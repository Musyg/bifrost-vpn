//! Transport: socket Unix cote Linux, named pipe cote Windows.
//!
//! Les deux cotes appliquent la meme regle: le canal n'est joignable que par
//! les identites autorisees, et la verification se fait a l'acceptation, avant
//! de lire le moindre octet du client.

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

use crate::auth::{AuthPolicy, PeerIdentity};
use crate::protocol::{MAX_FRAME_BYTES, PROTOCOL_VERSION, Request, Response};

#[derive(Debug, thiserror::Error)]
pub enum IpcError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Auth(#[from] crate::auth::AuthError),
    #[error("trame de plus de {MAX_FRAME_BYTES} octets sans fin de ligne")]
    FrameTooLarge,
    #[error("le pair a ferme la connexion")]
    Closed,
    #[error(
        "version de protocole {got} incompatible avec {PROTOCOL_VERSION}: \
         le client et le daemon ne sont pas de la meme version"
    )]
    VersionMismatch { got: u32 },
}

pub type Result<T> = std::result::Result<T, IpcError>;

/// Chemin par defaut du canal.
pub fn default_endpoint() -> String {
    #[cfg(unix)]
    {
        "/run/bifrost/daemon.sock".to_owned()
    }
    #[cfg(windows)]
    {
        r"\\.\pipe\bifrost-daemon".to_owned()
    }
}

// --------------------------------------------------------------------------
// Cadrage commun
// --------------------------------------------------------------------------

/// Lit une ligne JSON, en refusant les trames sans fin.
async fn read_frame<R>(reader: &mut BufReader<R>) -> Result<Vec<u8>>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut buf = Vec::new();
    let mut limited = reader.take(MAX_FRAME_BYTES as u64);
    let n = limited.read_until(b'\n', &mut buf).await?;
    if n == 0 {
        return Err(IpcError::Closed);
    }
    if buf.last() != Some(&b'\n') {
        return Err(IpcError::FrameTooLarge);
    }
    buf.pop();
    Ok(buf)
}

async fn write_frame<W>(writer: &mut W, bytes: &[u8]) -> Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    writer.write_all(bytes).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;
    Ok(())
}

// --------------------------------------------------------------------------
// Linux: socket Unix + SO_PEERCRED
// --------------------------------------------------------------------------

#[cfg(unix)]
mod imp {
    use super::*;
    use crate::auth::authorize;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use tokio::net::{UnixListener, UnixStream};

    pub struct IpcServer {
        listener: UnixListener,
        policy: AuthPolicy,
        path: PathBuf,
    }

    impl IpcServer {
        /// Cree le socket, restreint ses permissions, puis ecoute.
        ///
        /// L'ordre compte: le socket est cree avec un umask restrictif AVANT
        /// d'etre expose, sinon il existe un instant ou n'importe qui peut s'y
        /// connecter.
        pub async fn bind(
            path: impl AsRef<Path>,
            policy: AuthPolicy,
            group: Option<u32>,
        ) -> Result<Self> {
            let path = path.as_ref().to_path_buf();
            // On ne cree et ne durcit le repertoire que s'il n'existe pas
            // encore. Changer les permissions d'un repertoire deja la, c'est
            // au mieux modifier /run sans raison, au pire echouer sur /tmp
            // parce qu'il ne nous appartient pas.
            if let Some(parent) = path.parent()
                && !parent.as_os_str().is_empty()
                && !parent.exists()
            {
                std::fs::create_dir_all(parent)?;
                std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o755))?;
            }
            // Un socket residuel d'un daemon precedent empeche le bind.
            if path.exists() {
                std::fs::remove_file(&path)?;
            }

            // umask le temps du bind: le socket nait en 0o660 au lieu de 0o777.
            // SAFETY: umask ne prend qu'un masque entier et ne touche aucune memoire; la
            // valeur precedente est restauree juste apres le bind.
            let previous = unsafe { libc::umask(0o117) };
            let listener = UnixListener::bind(&path);
            // SAFETY: umask ne prend qu'un masque entier et ne touche aucune memoire;
            // restaure la valeur precedente relevee ci-dessus.
            unsafe { libc::umask(previous) };
            let listener = listener?;

            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660))?;
            if let Some(gid) = group {
                chown_group(&path, gid)?;
            }

            tracing::info!(path = %path.display(), gid = ?group, "IPC en ecoute");
            Ok(Self {
                listener,
                policy,
                path,
            })
        }

        /// Accepte une connexion et refuse immediatement un pair non autorise.
        ///
        /// `&mut self` par symetrie avec la version Windows, qui doit preparer
        /// l'instance suivante du named pipe a chaque acceptation.
        pub async fn accept(&mut self) -> Result<Connection> {
            loop {
                let (stream, _) = self.listener.accept().await?;
                let peer = peer_identity(&stream)?;
                match authorize(&peer, &self.policy) {
                    Ok(()) => {
                        tracing::debug!(%peer, "client accepte");
                        return Ok(Connection::new(stream, peer));
                    }
                    Err(e) => {
                        // On refuse sans rien lire du client, et on continue a
                        // servir: un refus ne doit pas arreter le daemon.
                        tracing::warn!(%peer, "connexion refusee");
                        let mut conn = Connection::new(stream, peer);
                        let _ = conn.send(&Response::error(e.to_string())).await;
                    }
                }
            }
        }

        pub fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for IpcServer {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    fn chown_group(path: &Path, gid: u32) -> Result<()> {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let c = CString::new(path.as_os_str().as_bytes())
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        // uid -1 laisse le proprietaire inchange.
        // SAFETY: `c` est une CString NUL-terminee vivante pendant l'appel; uid -1
        // (u32::MAX) laisse le proprietaire inchange, seul le groupe passe.
        let rc = unsafe { libc::chown(c.as_ptr(), u32::MAX, gid) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }

    fn peer_identity(stream: &UnixStream) -> Result<PeerIdentity> {
        let cred = stream.peer_cred()?;
        let pid = cred.pid();
        Ok(PeerIdentity {
            uid: cred.uid(),
            gid: cred.gid(),
            pid,
            supplementary_groups: pid
                .map(crate::auth::supplementary_groups)
                .unwrap_or_default(),
        })
    }

    pub struct Connection {
        reader: BufReader<tokio::io::ReadHalf<UnixStream>>,
        writer: tokio::io::WriteHalf<UnixStream>,
        peer: PeerIdentity,
    }

    impl Connection {
        fn new(stream: UnixStream, peer: PeerIdentity) -> Self {
            let (r, w) = tokio::io::split(stream);
            Self {
                reader: BufReader::new(r),
                writer: w,
                peer,
            }
        }

        pub fn peer(&self) -> &PeerIdentity {
            &self.peer
        }

        pub async fn recv(&mut self) -> Result<Request> {
            let bytes = read_frame(&mut self.reader).await?;
            let req: Request = serde_json::from_slice(&bytes)?;
            if req.version != PROTOCOL_VERSION {
                return Err(IpcError::VersionMismatch { got: req.version });
            }
            Ok(req)
        }

        pub async fn send(&mut self, response: &Response) -> Result<()> {
            let bytes = serde_json::to_vec(response)?;
            write_frame(&mut self.writer, &bytes).await
        }
    }

    /// Cote client.
    pub struct IpcClient {
        reader: BufReader<tokio::io::ReadHalf<UnixStream>>,
        writer: tokio::io::WriteHalf<UnixStream>,
    }

    impl IpcClient {
        pub async fn connect(path: impl AsRef<Path>) -> Result<Self> {
            let stream = UnixStream::connect(path.as_ref()).await?;
            let (r, w) = tokio::io::split(stream);
            Ok(Self {
                reader: BufReader::new(r),
                writer: w,
            })
        }

        pub async fn request(&mut self, request: &Request) -> Result<Response> {
            let bytes = serde_json::to_vec(request)?;
            write_frame(&mut self.writer, &bytes).await?;
            let bytes = read_frame(&mut self.reader).await?;
            Ok(serde_json::from_slice(&bytes)?)
        }
    }
}

// --------------------------------------------------------------------------
// Windows: named pipe + DACL restrictive
// --------------------------------------------------------------------------

#[cfg(windows)]
mod imp {
    use super::*;
    use std::ffi::c_void;
    use std::path::Path;
    use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeServer, ServerOptions};
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;

    /// SDDL du named pipe.
    ///
    /// `D:P` protege le descripteur de tout heritage, puis on n'accorde
    /// GENERIC_ALL qu'a SYSTEM (SY) et aux Administrateurs (BA). Aucune ACE
    /// pour Everyone: un processus non privilegie ne peut meme pas ouvrir le
    /// pipe, l'autorisation applicative n'a donc jamais a le refuser.
    const PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)";

    pub struct IpcServer {
        path: String,
        policy: AuthPolicy,
        next: Option<NamedPipeServer>,
    }

    impl IpcServer {
        pub async fn bind(
            path: impl AsRef<Path>,
            policy: AuthPolicy,
            _group: Option<u32>,
        ) -> Result<Self> {
            let path = path.as_ref().to_string_lossy().into_owned();
            let mut server = Self {
                path,
                policy,
                next: None,
            };
            // La premiere instance est creee avec first_pipe_instance pour
            // garantir qu'aucun autre processus n'a deja squatte le nom.
            server.next = Some(server.create_instance(true)?);
            tracing::info!(path = %server.path, "IPC en ecoute");
            Ok(server)
        }

        fn create_instance(&self, first: bool) -> Result<NamedPipeServer> {
            let mut wide: Vec<u16> = PIPE_SDDL.encode_utf16().collect();
            wide.push(0);

            let mut psd: *mut c_void = std::ptr::null_mut();
            // SAFETY: `wide` est une chaine UTF-16 terminee par un zero, et
            // `psd` recoit un descripteur alloue par le systeme qu'on libere
            // avec LocalFree avant de sortir de la fonction.
            let ok = unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    wide.as_ptr(),
                    SDDL_REVISION_1,
                    &mut psd,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                return Err(std::io::Error::last_os_error().into());
            }

            let mut sa = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: psd,
                bInheritHandle: 0,
            };

            let mut opts = ServerOptions::new();
            opts.first_pipe_instance(first)
                // Un client distant ne doit jamais pouvoir piloter le daemon.
                .reject_remote_clients(true);

            // SAFETY: `sa` reste vivant pendant tout l'appel, et son
            // lpSecurityDescriptor pointe sur un descripteur valide.
            let result = unsafe {
                opts.create_with_security_attributes_raw(
                    &self.path,
                    &mut sa as *mut _ as *mut c_void,
                )
            };

            // SAFETY: psd a ete alloue par ConvertStringSecurityDescriptor... .
            unsafe { LocalFree(psd) };

            Ok(result?)
        }

        pub async fn accept(&mut self) -> Result<Connection> {
            let server = match self.next.take() {
                Some(s) => s,
                None => self.create_instance(false)?,
            };
            server.connect().await?;
            // On prepare tout de suite l'instance suivante: sans cela, entre
            // deux clients, le nom du pipe n'existe plus et un processus tiers
            // pourrait le creer a notre place.
            self.next = Some(self.create_instance(false)?);

            let peer = peer_identity(&server);
            tracing::debug!(%peer, "client accepte");
            Ok(Connection::new(server, peer))
        }

        pub fn path(&self) -> &Path {
            Path::new(&self.path)
        }

        pub fn policy(&self) -> &AuthPolicy {
            &self.policy
        }
    }

    /// Sur Windows, l'autorisation est portee par la DACL du pipe: seuls SYSTEM
    /// et les Administrateurs peuvent l'ouvrir. L'identite retournee sert a la
    /// journalisation, pas a la decision.
    fn peer_identity(_server: &NamedPipeServer) -> PeerIdentity {
        PeerIdentity {
            uid: 0,
            gid: 0,
            pid: None,
            supplementary_groups: Vec::new(),
        }
    }

    pub struct Connection {
        reader: BufReader<tokio::io::ReadHalf<NamedPipeServer>>,
        writer: tokio::io::WriteHalf<NamedPipeServer>,
        peer: PeerIdentity,
    }

    impl Connection {
        fn new(pipe: NamedPipeServer, peer: PeerIdentity) -> Self {
            let (r, w) = tokio::io::split(pipe);
            Self {
                reader: BufReader::new(r),
                writer: w,
                peer,
            }
        }

        pub fn peer(&self) -> &PeerIdentity {
            &self.peer
        }

        pub async fn recv(&mut self) -> Result<Request> {
            let bytes = read_frame(&mut self.reader).await?;
            let req: Request = serde_json::from_slice(&bytes)?;
            if req.version != PROTOCOL_VERSION {
                return Err(IpcError::VersionMismatch { got: req.version });
            }
            Ok(req)
        }

        pub async fn send(&mut self, response: &Response) -> Result<()> {
            let bytes = serde_json::to_vec(response)?;
            write_frame(&mut self.writer, &bytes).await
        }
    }

    pub struct IpcClient {
        reader: BufReader<tokio::io::ReadHalf<tokio::net::windows::named_pipe::NamedPipeClient>>,
        writer: tokio::io::WriteHalf<tokio::net::windows::named_pipe::NamedPipeClient>,
    }

    impl IpcClient {
        pub async fn connect(path: impl AsRef<Path>) -> Result<Self> {
            let path = path.as_ref().to_string_lossy().into_owned();
            let pipe = ClientOptions::new().open(&path)?;
            let (r, w) = tokio::io::split(pipe);
            Ok(Self {
                reader: BufReader::new(r),
                writer: w,
            })
        }

        pub async fn request(&mut self, request: &Request) -> Result<Response> {
            let bytes = serde_json::to_vec(request)?;
            write_frame(&mut self.writer, &bytes).await?;
            let bytes = read_frame(&mut self.reader).await?;
            Ok(serde_json::from_slice(&bytes)?)
        }
    }

    /// La DACL du pipe est le SEUL controle d'acces sous Windows.
    ///
    /// [`peer_identity`] rend `uid: 0` en dur, et le dit: l'identite du pair ne
    /// sert qu'au journal, la decision appartient a la DACL. Sur Linux,
    /// `SO_PEERCRED` alimente [`crate::auth::authorize`], et cette fonction-la
    /// a sept recettes. Cote Windows, [`PIPE_SDDL`] n'en avait AUCUNE.
    ///
    /// Mesure du 23 aout 2026 sur dev-windows: en remplacant cette chaine par
    /// n'importe quoi d'autre, les treize recettes du binaire de bibliotheque
    /// de `bifrost-ipc` restaient vertes. Une DACL desserree en passant - un `(A;;GA;;;WD)` ajoute le
    /// temps d'un debogage, le `P` perdu - aurait donne a n'importe quel
    /// processus local le pilotage complet du daemon, sans qu'une seule recette
    /// du depot ne bronche.
    #[cfg(test)]
    mod tests_sddl {
        use super::*;

        /// Les ACE d'un SDDL: le type et le compte, une paire par ACE.
        ///
        /// Une ACE s'ecrit `(type;flags;droits;guid;guid_heritage;compte)`: le
        /// compte est le sixieme champ. Le TYPE est rendu lui aussi, parce
        /// qu'une ACE de refus se lit comme une autorisation quand on ne
        /// regarde que le compte.
        fn aces(sddl: &str) -> Vec<(String, String)> {
            let mut out = Vec::new();
            let mut reste = sddl;
            while let Some(debut) = reste.find('(') {
                let fin = reste[debut..]
                    .find(')')
                    .expect("une ACE ouverte doit se refermer")
                    + debut;
                let champs: Vec<&str> = reste[debut + 1..fin].split(';').collect();
                assert_eq!(champs.len(), 6, "ACE malformee: {}", &reste[debut..=fin]);
                out.push((champs[0].to_string(), champs[5].to_string()));
                reste = &reste[fin + 1..];
            }
            out
        }

        /// La DACL n'ouvre le pipe qu'a SYSTEM et aux Administrateurs, et elle
        /// est PROTEGEE.
        ///
        /// Le `P` n'est pas decoratif: sans lui la DACL herite de celle du
        /// conteneur des pipes nommes, qui accorde a Everyone de quoi ouvrir.
        /// Le retirer suffirait donc a rouvrir ce que les deux ACE ferment.
        #[test]
        fn la_dacl_du_pipe_n_ouvre_qu_a_system_et_aux_administrateurs() {
            assert!(
                PIPE_SDDL.starts_with("D:P"),
                "la DACL doit etre PROTEGEE (`D:P`), sinon elle herite d'un \
                 conteneur qui accorde a Everyone: {PIPE_SDDL}"
            );

            let aces = aces(PIPE_SDDL);
            let comptes: Vec<&str> = aces.iter().map(|(_, c)| c.as_str()).collect();
            assert_eq!(
                comptes,
                vec!["SY", "BA"],
                "la DACL du pipe doit nommer exactement SYSTEM puis les \
                 Administrateurs, et personne d'autre: {PIPE_SDDL}"
            );
            for (type_ace, compte) in &aces {
                assert_eq!(
                    type_ace, "A",
                    "ACE de type {type_ace} pour {compte}: seules des \
                     autorisations sont attendues ici"
                );
            }

            // Les comptes larges sont nommes plutot que deduits de l'egalite
            // ci-dessus: le jour ou la liste attendue s'allonge pour une bonne
            // raison, celle-ci continue de refuser les mauvaises.
            for large in [
                "WD",      // Everyone
                "AU",      // Authenticated Users
                "BU",      // Users
                "IU",      // Interactive
                "AN",      // Anonymous
                "S-1-1-0", // Everyone, en SID
            ] {
                assert!(
                    !comptes.contains(&large),
                    "{large} peut ouvrir le pipe de commande du daemon: {PIPE_SDDL}"
                );
            }
        }

        /// Et Windows accepte cette chaine.
        ///
        /// Une coquille dans le SDDL ne se voit aujourd'hui qu'au demarrage du
        /// daemon, sur une machine Windows, au moment ou le pipe se cree. La
        /// meme conversion que `create_instance` la reduit a une recette.
        #[test]
        fn windows_accepte_le_sddl_du_pipe() {
            let mut large: Vec<u16> = PIPE_SDDL.encode_utf16().collect();
            large.push(0);
            let mut psd: *mut c_void = std::ptr::null_mut();
            // SAFETY: meme appel que create_instance, sur une chaine UTF-16
            // terminee par un zero; le descripteur rendu est libere aussitot.
            let ok = unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    large.as_ptr(),
                    SDDL_REVISION_1,
                    &mut psd,
                    std::ptr::null_mut(),
                )
            };
            let erreur = std::io::Error::last_os_error();
            if ok != 0 {
                // SAFETY: psd vient d'etre alloue par l'appel ci-dessus.
                unsafe { LocalFree(psd as _) };
            }
            assert!(
                ok != 0,
                "Windows refuse le SDDL du pipe, donc le daemon ne demarrera \
                 pas: {PIPE_SDDL} ({erreur})"
            );
        }
    }
}

pub use imp::{Connection, IpcClient, IpcServer};
