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
    #[error(transparent)]
    ServerIdentity(#[from] ServerIdentityError),
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
// Identite du SERVEUR, verifiee par le client
// --------------------------------------------------------------------------
//
// Le serveur authentifie ses clients (SO_PEERCRED, DACL du pipe). L'inverse
// n'existait pas: le client parlait a quiconque servait le chemin qu'on lui
// donnait. Pour une PREUVE qui confronte le noyau a ce que le daemon declare,
// n'importe quel processus pouvait servir une declaration taillee pour un
// noyau altere, et la preuve disait MATCH. Pour piloter, c'etait pire: `connect
// --config` envoyait le profil, cle privee comprise, a qui tenait le socket, et
// sous Windows le nom du pipe par defaut est libre des que le service est
// arrete. Mesure du 30/09/2026, depuis un compte non eleve: le client de
// `5baf9f3` ecrit 506 octets, dont la cle privee, dans un pipe
// `bifrost-daemon` cree par ce compte.
//
// `IpcClient::connect_verified` est desormais la SEULE facon d'ouvrir un
// client: il n'existe plus de constructeur qui ecrive avant d'avoir etabli
// l'identite du serveur, et un site d'appel ne peut donc pas l'oublier.

/// Ce que le client exige du processus qui sert le canal.
///
/// Deux regles et non une, parce qu'elles ne repondent pas a la meme question.
/// La preuve (`Privileged`) exporte un constat sur ce que le DAEMON declare, et
/// ne l'admet que sous l'identite du service. Les commandes (`Elevated`)
/// confient un profil ou un ordre a un serveur, et n'exigent de lui que les
/// droits que le daemon exige de lui-meme pour demarrer (`ensure_privileged`):
/// ce qu'un compte non privilegie ne peut jamais avoir. Sous Linux les deux se
/// confondent (root); sous Windows la seconde admet aussi un pipe possede par
/// les Administrateurs, celui que cree un daemon lance en console elevee.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerRequirement {
    /// Un serveur privilegie, pour une PREUVE. Linux: l'uid EFFECTIF du
    /// processus qui a appele `listen(2)` sur le socket, tel que `SO_PEERCRED`
    /// le rend, vaut 0. Windows: le proprietaire du pipe nomme est LocalSystem
    /// (`S-1-5-18`).
    Privileged,
    /// Un serveur qui a les droits du daemon, pour une COMMANDE. Linux: comme
    /// `Privileged`, l'uid effectif vaut 0. Windows: le proprietaire du pipe
    /// est LocalSystem ou les Administrateurs (`S-1-5-32-544`).
    ///
    /// Un compte non eleve ne peut ni creer un pipe possede par l'un ou
    /// l'autre, ni le leur attribuer apres coup (`ERROR_INVALID_OWNER`): le
    /// noyau n'accepte comme proprietaire que l'utilisateur du jeton ou un
    /// groupe ACTIF marque `SE_GROUP_OWNER`, et les Administrateurs ne sont
    /// actifs que dans un jeton eleve. Garde par
    /// `un_compte_sans_administrateurs_actifs_ne_fabrique_aucun_pipe_admis`.
    Elevated,
    /// Linux: exactement cet uid effectif. Pour les recettes qui servent un
    /// faux daemon sous leur propre compte; une preuve ne s'en sert jamais.
    #[cfg(unix)]
    Uid(u32),
}

/// La regle selon laquelle l'identite du serveur a ete verifiee.
///
/// Son nom est ce qu'un rapport exporte: une REGLE, jamais une valeur. Ni uid,
/// ni pid, ni SID ne sortent de ce module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerRule {
    /// Linux, `ServerRequirement::Privileged` ou `Elevated`.
    RootPeerCredentials,
    /// Linux, `ServerRequirement::Uid`: recettes seulement.
    UidPeerCredentials,
    /// Windows, `ServerRequirement::Privileged` ou `Elevated`: pipe de
    /// LocalSystem.
    WindowsSystemPipeOwner,
    /// Windows, `ServerRequirement::Elevated` seulement: pipe des
    /// Administrateurs. Jamais rendue a une preuve.
    WindowsAdministratorsPipeOwner,
}

impl ServerRule {
    pub fn name(self) -> &'static str {
        match self {
            ServerRule::RootPeerCredentials => "root-peer-credentials",
            ServerRule::UidPeerCredentials => "uid-peer-credentials",
            ServerRule::WindowsSystemPipeOwner => "windows-system-pipe-owner",
            ServerRule::WindowsAdministratorsPipeOwner => "windows-administrators-pipe-owner",
        }
    }
}

/// Pourquoi l'identite du serveur n'a pas ete admise. Les messages ne
/// nomment aucune valeur: un rapport exporte peut les recopier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ServerIdentityError {
    /// Le systeme n'a pas rendu l'identite du serveur.
    #[error("identite du serveur illisible")]
    Unreadable,
    /// L'identite a ete lue, et ce n'est pas celle qu'exige la regle.
    #[error("le serveur n'a pas l'identite exigee")]
    Refused,
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
        /// Se connecte, puis exige du SERVEUR l'identite demandee, avant
        /// d'ecrire le moindre octet. Le seul constructeur du client.
        ///
        /// `SO_PEERCRED` sur le socket du client rend les identifiants que le
        /// noyau a copies depuis le socket d'ecoute au `connect(2)`, eux-memes
        /// releves au `listen(2)` du serveur (`unix_listen` puis
        /// `copy_peercred`, net/unix/af_unix.c). Ce sont l'uid et le gid
        /// EFFECTIFS de ce processus a cet instant (`cred_to_ucred`,
        /// net/core/sock.c: `cred->euid`, `cred->egid`), traduits dans
        /// l'espace de noms utilisateur du LECTEUR (un uid sans image y vaut
        /// l'uid de debordement, jamais 0), et un pid traduit dans son espace
        /// de noms de pid. Seul l'uid entre dans la decision.
        ///
        /// Ce que la regle ne dit pas: qu'un processus root qui ecoute EST le
        /// daemon. Un socket d'ecoute cree par root puis confie a un autre
        /// processus garde les identifiants de root.
        pub async fn connect_verified(
            path: impl AsRef<Path>,
            attendu: ServerRequirement,
        ) -> Result<(Self, ServerRule)> {
            let stream = UnixStream::connect(path.as_ref()).await?;
            let uid = stream
                .peer_cred()
                .map_err(|_| ServerIdentityError::Unreadable)?
                .uid();
            let regle = decide_server_uid(uid, attendu)?;
            Ok((Self::from_stream(stream), regle))
        }

        fn from_stream(stream: UnixStream) -> Self {
            let (r, w) = tokio::io::split(stream);
            Self {
                reader: BufReader::new(r),
                writer: w,
            }
        }

        pub async fn request(&mut self, request: &Request) -> Result<Response> {
            let bytes = self.request_raw(request).await?;
            Ok(serde_json::from_slice(&bytes)?)
        }

        /// La reponse telle qu'elle est arrivee, sans la desserialiser.
        ///
        /// Pour un lecteur qui doit refuser ce que serde accepte en silence
        /// (cle dupliquee, cle inconnue d'une variante): la preuve nft relit
        /// la declaration du daemon avec son propre analyseur strict. Le
        /// cadrage reste celui de `request`, borne a `MAX_FRAME_BYTES`, et une
        /// reponse sans fin de ligne est une erreur, jamais une trame.
        pub async fn request_raw(&mut self, request: &Request) -> Result<Vec<u8>> {
            let bytes = serde_json::to_vec(request)?;
            write_frame(&mut self.writer, &bytes).await?;
            read_frame(&mut self.reader).await
        }
    }

    /// La decision, fonction pure de l'uid releve et de l'exigence.
    ///
    /// `SO_PEERCRED` rend -1 quand le noyau n'a aucun identifiant a copier:
    /// ce n'est pas 0, donc refuse, comme tout le reste.
    pub(crate) fn decide_server_uid(
        uid: u32,
        attendu: ServerRequirement,
    ) -> std::result::Result<ServerRule, ServerIdentityError> {
        match attendu {
            // Une seule regle pour la preuve et les commandes: sous Linux, le
            // daemon n'a qu'une identite possible (`ensure_privileged`).
            ServerRequirement::Privileged | ServerRequirement::Elevated if uid == 0 => {
                Ok(ServerRule::RootPeerCredentials)
            }
            ServerRequirement::Uid(exige) if uid == exige => Ok(ServerRule::UidPeerCredentials),
            _ => Err(ServerIdentityError::Refused),
        }
    }

    #[cfg(test)]
    mod tests_identite_serveur {
        use super::*;

        fn euid() -> u32 {
            // SAFETY: geteuid ne prend aucun argument et ne touche aucune memoire.
            unsafe { libc::geteuid() }
        }

        fn chemin(nom: &str) -> PathBuf {
            std::env::temp_dir().join(format!(
                "bifrost-ipc-serveur-{}-{nom}.sock",
                std::process::id()
            ))
        }

        #[test]
        fn seul_l_uid_exige_passe() {
            use ServerIdentityError::Refused;
            use ServerRequirement::{Elevated, Privileged, Uid};
            for (uid, attendu, issue) in [
                (0, Privileged, Ok(ServerRule::RootPeerCredentials)),
                (1, Privileged, Err(Refused)),
                (1000, Privileged, Err(Refused)),
                // L'uid de debordement: un serveur d'un autre espace de noms
                // utilisateur, root chez lui, ne devient pas root ici.
                (65534, Privileged, Err(Refused)),
                // -1: aucun identifiant copie par le noyau.
                (u32::MAX, Privileged, Err(Refused)),
                // Les commandes: la meme regle, sans exception.
                (0, Elevated, Ok(ServerRule::RootPeerCredentials)),
                (1, Elevated, Err(Refused)),
                (1000, Elevated, Err(Refused)),
                (65534, Elevated, Err(Refused)),
                (u32::MAX, Elevated, Err(Refused)),
                (1000, Uid(1000), Ok(ServerRule::UidPeerCredentials)),
                (0, Uid(1000), Err(Refused)),
                (1001, Uid(1000), Err(Refused)),
            ] {
                assert_eq!(decide_server_uid(uid, attendu), issue, "{uid} {attendu:?}");
            }
        }

        /// Sur un vrai socket, servi par CE processus: refuse s'il n'est pas
        /// root, admis s'il l'est, pour la preuve comme pour les commandes.
        /// Les deux branches mesurent, aucune ne s'abstient; et l'exigence
        /// d'uid explicite passe dans les deux.
        #[tokio::test]
        async fn un_serveur_du_compte_courant_n_est_admis_que_s_il_est_root() {
            let path = chemin("courant");
            let _serveur = IpcServer::bind(&path, AuthPolicy::default(), None)
                .await
                .expect("bind");
            for attendu in [ServerRequirement::Privileged, ServerRequirement::Elevated] {
                let issue = IpcClient::connect_verified(&path, attendu)
                    .await
                    .map(|(_, regle)| regle);
                if euid() == 0 {
                    assert!(
                        matches!(issue, Ok(ServerRule::RootPeerCredentials)),
                        "{attendu:?}: {issue:?}"
                    );
                } else {
                    assert!(
                        matches!(
                            issue,
                            Err(IpcError::ServerIdentity(ServerIdentityError::Refused))
                        ),
                        "{attendu:?}: {issue:?}"
                    );
                }
            }
            let issue = IpcClient::connect_verified(&path, ServerRequirement::Uid(euid()))
                .await
                .map(|(_, regle)| regle);
            assert!(
                matches!(issue, Ok(ServerRule::UidPeerCredentials)),
                "{issue:?}"
            );
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
    use std::os::windows::io::{AsRawHandle, RawHandle};
    use std::path::Path;
    use tokio::net::windows::named_pipe::{
        ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions,
    };
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
        SE_KERNEL_OBJECT,
    };
    use windows_sys::Win32::Security::{
        IsWellKnownSid, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
        SECURITY_ATTRIBUTES, WinBuiltinAdministratorsSid, WinLocalSystemSid,
    };

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
            create_pipe(&self.path, PIPE_SDDL, first)
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

    /// Cree une instance du pipe `path` avec le descripteur `sddl`.
    ///
    /// Le chemin du daemon (`PIPE_SDDL`) et celui des recettes qui fabriquent
    /// un pipe d'un autre proprietaire: le meme appel, pour que ce qu'elles
    /// mesurent soit ce que le daemon fait.
    fn create_pipe(path: &str, sddl: &str, first: bool) -> Result<NamedPipeServer> {
        let mut wide: Vec<u16> = sddl.encode_utf16().collect();
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
            opts.create_with_security_attributes_raw(path, &mut sa as *mut _ as *mut c_void)
        };

        // SAFETY: psd a ete alloue par ConvertStringSecurityDescriptor... .
        unsafe { LocalFree(psd) };

        Ok(result?)
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
        reader: BufReader<tokio::io::ReadHalf<NamedPipeClient>>,
        writer: tokio::io::WriteHalf<NamedPipeClient>,
    }

    /// Le proprietaire d'un pipe, tel que la decision le lit: trois classes,
    /// et rien d'autre ne sort de ce module (ni SID, ni compte). Public avec
    /// [`decide_pipe_owner`], pour qu'une preuve montre sans privilege ce que
    /// son exigence admet; le client ne s'ouvre toujours que par
    /// `IpcClient::connect_verified`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum PipeOwner {
        /// LocalSystem, `S-1-5-18`: le daemon installe en service.
        LocalSystem,
        /// Les Administrateurs, `S-1-5-32-544`: proprietaire par defaut des
        /// objets crees par un jeton eleve, donc d'un daemon lance en console
        /// elevee.
        Administrators,
        /// Tout autre compte ou groupe.
        Other,
    }

    /// Le proprietaire de l'objet que designe `handle`.
    ///
    /// La comparaison est confiee au systeme (`IsWellKnownSid`), jamais a une
    /// chaine: une forme textuelle equivalente ne peut pas la tromper.
    fn pipe_owner(handle: RawHandle) -> std::result::Result<PipeOwner, ServerIdentityError> {
        let mut proprietaire: PSID = std::ptr::null_mut();
        let mut descripteur: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: `handle` est une poignee vivante tenue par l'appelant; les
        // pointeurs de sortie sont des variables locales; groupe, DACL et SACL
        // ne sont pas demandes, donc nuls. `proprietaire` pointe DANS
        // `descripteur`, alloue par le systeme et libere ci-dessous.
        let rc = unsafe {
            GetSecurityInfo(
                handle as _,
                SE_KERNEL_OBJECT,
                OWNER_SECURITY_INFORMATION,
                &mut proprietaire,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut descripteur,
            )
        };
        if rc != 0 || descripteur.is_null() {
            return Err(ServerIdentityError::Unreadable);
        }
        let classe = classify_owner(proprietaire);
        // SAFETY: `descripteur` a ete alloue par GetSecurityInfo pour nous;
        // `proprietaire`, qui pointe dedans, n'est plus lu apres.
        unsafe { LocalFree(descripteur as _) };
        Ok(classe)
    }

    fn classify_owner(sid: PSID) -> PipeOwner {
        if sid.is_null() {
            return PipeOwner::Other;
        }
        // SAFETY: IsWellKnownSid lit un SID valide; un pointeur nul est ecarte
        // avant l'appel.
        if unsafe { IsWellKnownSid(sid, WinLocalSystemSid) } != 0 {
            PipeOwner::LocalSystem
        // SAFETY: idem.
        } else if unsafe { IsWellKnownSid(sid, WinBuiltinAdministratorsSid) } != 0 {
            PipeOwner::Administrators
        } else {
            PipeOwner::Other
        }
    }

    /// La decision, fonction pure du proprietaire lu et de l'exigence: celle
    /// que `IpcClient::connect_verified` applique au proprietaire du pipe.
    pub fn decide_pipe_owner(
        proprietaire: PipeOwner,
        attendu: ServerRequirement,
    ) -> std::result::Result<ServerRule, ServerIdentityError> {
        match (proprietaire, attendu) {
            (PipeOwner::LocalSystem, _) => Ok(ServerRule::WindowsSystemPipeOwner),
            (PipeOwner::Administrators, ServerRequirement::Elevated) => {
                Ok(ServerRule::WindowsAdministratorsPipeOwner)
            }
            _ => Err(ServerIdentityError::Refused),
        }
    }

    impl IpcClient {
        /// Se connecte, puis exige du proprietaire du pipe l'identite
        /// demandee (LocalSystem pour une preuve, LocalSystem ou les
        /// Administrateurs pour une commande), avant d'ecrire le moindre
        /// octet. Le seul constructeur du client.
        ///
        /// # Pourquoi le proprietaire du pipe, et pas le jeton du serveur
        ///
        /// `GetNamedPipeServerProcessId` rend bien le pid du serveur, mais
        /// ouvrir ce processus pour lire son jeton echoue sans privilege.
        /// Mesure du 29/09/2026: depuis un client non eleve, `OpenProcess`
        /// (`PROCESS_QUERY_LIMITED_INFORMATION`) rend `ERROR_ACCESS_DENIED`
        /// sur les serveurs de neuf pipes du systeme; depuis un client eleve
        /// sans `SeDebugPrivilege` actif, sur un serveur SYSTEM aussi. Une
        /// regle qui ne se verifie qu'avec ce privilege-la ne sert pas.
        ///
        /// Le proprietaire, lui, se lit sur la poignee que le client tient
        /// deja (`GetSecurityInfo`, `READ_CONTROL` etant compris dans
        /// `GENERIC_READ`), et il ne se choisit pas: le noyau n'accepte comme
        /// proprietaire d'un objet cree que le compte du createur ou un groupe
        /// de son jeton marque `SE_GROUP_OWNER`, sauf privilege de
        /// restauration. Mesure le meme jour depuis un jeton non eleve: creer
        /// un pipe `O:SY` ou `O:BA` rend `ERROR_INVALID_OWNER` (1307), et un
        /// pipe cree sous SYSTEM avec le SDDL du daemon appartient a
        /// `S-1-5-18`. Remesure le 30/09/2026, et desormais gardee par une
        /// recette: sans Administrateurs actifs dans le jeton, ni la creation
        /// d'un pipe `O:BA` ou `O:SY`, ni l'attribution de son propre pipe aux
        /// Administrateurs n'aboutissent (1307 les trois fois).
        ///
        /// Ce que la regle ne dit pas: que le pipe est celui du daemon. Un
        /// pipe de LocalSystem dont la DACL laisse d'autres comptes creer des
        /// instances peut etre servi, instance par instance, par un tiers.
        /// Celui du daemon ne le permet pas a un compte ordinaire
        /// (`PIPE_SDDL`: SYSTEM et Administrateurs seulement), mais le permet
        /// a un processus eleve: la regle stricte de la preuve n'ecarte donc
        /// pas les Administrateurs pendant que le daemon tourne.
        pub async fn connect_verified(
            path: impl AsRef<Path>,
            attendu: ServerRequirement,
        ) -> Result<(Self, ServerRule)> {
            let path = path.as_ref().to_string_lossy().into_owned();
            let pipe = ClientOptions::new().open(&path)?;
            let regle = decide_pipe_owner(pipe_owner(pipe.as_raw_handle())?, attendu)?;
            Ok((Self::from_pipe(pipe), regle))
        }

        fn from_pipe(pipe: NamedPipeClient) -> Self {
            let (r, w) = tokio::io::split(pipe);
            Self {
                reader: BufReader::new(r),
                writer: w,
            }
        }

        pub async fn request(&mut self, request: &Request) -> Result<Response> {
            let bytes = self.request_raw(request).await?;
            Ok(serde_json::from_slice(&bytes)?)
        }

        /// Meme contrat que la version Unix: la reponse brute, cadrage borne.
        pub async fn request_raw(&mut self, request: &Request) -> Result<Vec<u8>> {
            let bytes = serde_json::to_vec(request)?;
            write_frame(&mut self.writer, &bytes).await?;
            read_frame(&mut self.reader).await
        }
    }

    #[cfg(test)]
    mod tests_identite_serveur {
        use super::*;
        use windows_sys::Win32::Security::Authorization::SetSecurityInfo;
        use windows_sys::Win32::Security::{
            CheckTokenMembership, CreateWellKnownSid, SECURITY_MAX_SID_SIZE, WELL_KNOWN_SID_TYPE,
            WinAuthenticatedUserSid, WinBuiltinUsersSid, WinLocalServiceSid, WinNetworkServiceSid,
            WinWorldSid,
        };

        /// `ERROR_INVALID_OWNER`: le proprietaire demande n'est ni
        /// l'utilisateur du jeton, ni un de ses groupes actifs marques
        /// `SE_GROUP_OWNER`.
        const PROPRIETAIRE_INVALIDE: u32 = 1307;

        fn nom(suffixe: &str) -> String {
            format!(
                r"\\.\pipe\bifrost-ipc-serveur-{}-{suffixe}",
                std::process::id()
            )
        }

        fn sid(genre: WELL_KNOWN_SID_TYPE) -> Vec<u8> {
            let mut tampon = vec![0u8; SECURITY_MAX_SID_SIZE as usize];
            let mut taille = tampon.len() as u32;
            // SAFETY: le tampon fait SECURITY_MAX_SID_SIZE octets, sa taille
            // est passee; aucun SID de domaine n'est requis pour ces comptes.
            let ok = unsafe {
                CreateWellKnownSid(
                    genre,
                    std::ptr::null_mut(),
                    tampon.as_mut_ptr() as PSID,
                    &mut taille,
                )
            };
            assert!(ok != 0, "CreateWellKnownSid({genre})");
            tampon.truncate(taille as usize);
            tampon
        }

        /// Les Administrateurs sont-ils ACTIFS dans le jeton de ce processus?
        ///
        /// Faux dans le jeton filtre d'un administrateur non eleve (le groupe y
        /// est en refus seulement) comme dans celui d'un compte ordinaire; vrai
        /// dans un jeton eleve et sous SYSTEM. C'est la ligne de partage de la
        /// regle des commandes, lue par le systeme et non devinee.
        fn administrateurs_actifs() -> bool {
            let mut ba = sid(WinBuiltinAdministratorsSid);
            let mut membre = 0;
            // SAFETY: jeton nul, donc celui du fil ou une copie du jeton
            // primaire; le SID est valide et vit jusqu'a la fin de l'appel;
            // `membre` est une variable locale.
            let ok = unsafe {
                CheckTokenMembership(std::ptr::null_mut(), ba.as_mut_ptr() as PSID, &mut membre)
            };
            assert!(
                ok != 0,
                "CheckTokenMembership: {}",
                std::io::Error::last_os_error()
            );
            membre != 0
        }

        /// Trois classes de proprietaire, et la decision de chaque exigence.
        /// Les comptes voisins sont nommes: les deux comptes de service (le
        /// resolveur chiffre tourne sous LocalService) et les groupes larges.
        #[test]
        fn chaque_proprietaire_a_sa_decision() {
            use PipeOwner::{Administrators, LocalSystem, Other};
            use ServerIdentityError::Refused;
            use ServerRequirement::{Elevated, Privileged};
            let mut systeme = sid(WinLocalSystemSid);
            assert_eq!(classify_owner(systeme.as_mut_ptr() as PSID), LocalSystem);
            let mut administrateurs = sid(WinBuiltinAdministratorsSid);
            assert_eq!(
                classify_owner(administrateurs.as_mut_ptr() as PSID),
                Administrators
            );
            for genre in [
                WinLocalServiceSid,
                WinNetworkServiceSid,
                WinWorldSid,
                WinAuthenticatedUserSid,
                WinBuiltinUsersSid,
            ] {
                let mut autre = sid(genre);
                assert_eq!(classify_owner(autre.as_mut_ptr() as PSID), Other, "{genre}");
            }
            assert_eq!(classify_owner(std::ptr::null_mut()), Other);
            for (proprietaire, attendu, issue) in [
                (
                    LocalSystem,
                    Privileged,
                    Ok(ServerRule::WindowsSystemPipeOwner),
                ),
                (
                    LocalSystem,
                    Elevated,
                    Ok(ServerRule::WindowsSystemPipeOwner),
                ),
                // La preuve n'admet jamais les Administrateurs.
                (Administrators, Privileged, Err(Refused)),
                (
                    Administrators,
                    Elevated,
                    Ok(ServerRule::WindowsAdministratorsPipeOwner),
                ),
                (Other, Privileged, Err(Refused)),
                (Other, Elevated, Err(Refused)),
            ] {
                assert_eq!(
                    decide_pipe_owner(proprietaire, attendu),
                    issue,
                    "{proprietaire:?} {attendu:?}"
                );
            }
        }

        /// Ce que le client rend, selon le proprietaire lu cote SERVEUR et
        /// l'exigence. Ecrit en clair plutot que recalcule par
        /// `decide_pipe_owner`: une recette qui demanderait a la decision ce
        /// qu'elle doit attendre de la decision ne mesurerait rien.
        fn attendu_du_client(
            proprietaire: PipeOwner,
            attendu: ServerRequirement,
        ) -> Option<ServerRule> {
            match (proprietaire, attendu) {
                (PipeOwner::LocalSystem, _) => Some(ServerRule::WindowsSystemPipeOwner),
                (PipeOwner::Administrators, ServerRequirement::Elevated) => {
                    Some(ServerRule::WindowsAdministratorsPipeOwner)
                }
                (PipeOwner::Administrators, ServerRequirement::Privileged) => None,
                (PipeOwner::Other, _) => None,
            }
        }

        /// Un pipe servi par CE processus, avec le descripteur par defaut:
        /// son proprietaire est le compte qui l'a cree (les Administrateurs si
        /// le jeton est eleve, LocalSystem sous SYSTEM). Refuse pour les deux
        /// exigences sauf proprietaire privilegie: chaque branche mesure,
        /// aucune ne s'abstient. Un pipe neuf par exigence: une instance ne
        /// sert qu'un client.
        #[tokio::test]
        async fn un_pipe_du_compte_courant_n_est_admis_que_selon_son_proprietaire() {
            let actifs = administrateurs_actifs();
            for attendu in [ServerRequirement::Privileged, ServerRequirement::Elevated] {
                let nom = nom(&format!("courant-{attendu:?}"));
                let serveur = ServerOptions::new()
                    .first_pipe_instance(true)
                    .reject_remote_clients(true)
                    .create(&nom)
                    .expect("creation du pipe");
                let proprietaire = pipe_owner(serveur.as_raw_handle()).expect("proprietaire");
                if !actifs {
                    // Sans Administrateurs actifs, le pipe ne peut appartenir
                    // qu'au compte courant: c'est le cas qui compte.
                    assert_eq!(proprietaire, PipeOwner::Other);
                }
                let issue = IpcClient::connect_verified(&nom, attendu)
                    .await
                    .map(|(_, regle)| regle);
                match attendu_du_client(proprietaire, attendu) {
                    Some(regle) => {
                        assert!(
                            matches!(issue, Ok(r) if r == regle),
                            "{attendu:?}: {issue:?}"
                        )
                    }
                    None => assert!(
                        matches!(
                            issue,
                            Err(IpcError::ServerIdentity(ServerIdentityError::Refused))
                        ),
                        "{attendu:?}: {issue:?}"
                    ),
                }
            }
        }

        /// Le pipe du VRAI serveur, avec `PIPE_SDDL`, servi par ce processus.
        /// Un client sans Administrateurs actifs ne l'ouvre meme pas (la DACL
        /// ne nomme que SYSTEM et les Administrateurs); un client eleve
        /// l'ouvre et trouve pour proprietaire les Administrateurs: refuse
        /// pour une preuve, admis pour une commande.
        #[tokio::test]
        async fn le_pipe_du_daemon_n_est_admis_que_selon_son_proprietaire() {
            for attendu in [ServerRequirement::Privileged, ServerRequirement::Elevated] {
                let nom = nom(&format!("daemon-{attendu:?}"));
                let serveur = IpcServer::bind(&nom, AuthPolicy::default(), None)
                    .await
                    .expect("bind");
                let proprietaire = pipe_owner(
                    serveur
                        .next
                        .as_ref()
                        .expect("instance prete")
                        .as_raw_handle(),
                )
                .expect("proprietaire");
                let issue = IpcClient::connect_verified(&nom, attendu)
                    .await
                    .map(|(_, regle)| regle);
                match issue {
                    Ok(regle) => assert_eq!(
                        Some(regle),
                        attendu_du_client(proprietaire, attendu),
                        "{attendu:?}"
                    ),
                    Err(IpcError::Io(e)) => {
                        assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied, "{e}");
                        assert!(!administrateurs_actifs(), "{attendu:?}: {e}");
                    }
                    Err(IpcError::ServerIdentity(ServerIdentityError::Refused)) => {
                        assert_eq!(
                            attendu_du_client(proprietaire, attendu),
                            None,
                            "{attendu:?}"
                        )
                    }
                    Err(autre) => panic!("{attendu:?}: {autre}"),
                }
            }
        }

        /// La premisse de la regle des commandes, gardee: sans
        /// Administrateurs actifs dans son jeton, un compte ne fabrique aucun
        /// pipe que `Elevated` admettrait. Ni en le creant `O:BA` ou `O:SY`,
        /// ni en attribuant apres coup son propre pipe aux Administrateurs:
        /// `ERROR_INVALID_OWNER` les trois fois. Les DACL sont grandes
        /// ouvertes: la seule barriere mesuree est le proprietaire.
        ///
        /// Avec les Administrateurs actifs (jeton eleve, SYSTEM), `O:BA` et
        /// l'attribution aboutissent, et le pipe est admis pour une commande:
        /// c'est la limite de la regle, mesuree elle aussi.
        #[tokio::test]
        async fn un_compte_sans_administrateurs_actifs_ne_fabrique_aucun_pipe_admis() {
            let actifs = administrateurs_actifs();
            for (etiquette, sddl) in [
                ("o-ba", "O:BAD:P(A;;GA;;;WD)"),
                ("o-sy", "O:SYD:P(A;;GA;;;WD)"),
            ] {
                let nom = nom(etiquette);
                match create_pipe(&nom, sddl, true) {
                    Err(IpcError::Io(e)) => assert_eq!(
                        e.raw_os_error(),
                        Some(PROPRIETAIRE_INVALIDE as i32),
                        "{sddl}: {e}"
                    ),
                    Err(autre) => panic!("{sddl}: {autre}"),
                    Ok(serveur) => {
                        assert!(
                            actifs,
                            "{sddl}: un jeton sans Administrateurs actifs a cree un pipe a ce proprietaire"
                        );
                        let proprietaire =
                            pipe_owner(serveur.as_raw_handle()).expect("proprietaire");
                        assert_ne!(proprietaire, PipeOwner::Other, "{sddl}");
                        let issue = IpcClient::connect_verified(&nom, ServerRequirement::Elevated)
                            .await
                            .map(|(_, regle)| regle);
                        assert_eq!(
                            issue.ok(),
                            attendu_du_client(proprietaire, ServerRequirement::Elevated),
                            "{sddl}"
                        );
                    }
                }
            }

            let nom = nom("attribue");
            let serveur = ServerOptions::new()
                .first_pipe_instance(true)
                .reject_remote_clients(true)
                .write_owner(true)
                .create(&nom)
                .expect("creation du pipe");
            let mut administrateurs = sid(WinBuiltinAdministratorsSid);
            // SAFETY: la poignee est vivante et ouverte avec WRITE_OWNER; seul
            // le proprietaire est pose, groupe, DACL et SACL sont nuls; le SID
            // vit jusqu'a la fin de l'appel.
            let rc = unsafe {
                SetSecurityInfo(
                    serveur.as_raw_handle() as _,
                    SE_KERNEL_OBJECT,
                    OWNER_SECURITY_INFORMATION,
                    administrateurs.as_mut_ptr() as PSID,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                )
            };
            let proprietaire = pipe_owner(serveur.as_raw_handle()).expect("proprietaire");
            if actifs {
                assert_eq!(rc, 0, "attribution aux Administrateurs sous jeton eleve");
                assert_eq!(proprietaire, PipeOwner::Administrators);
            } else {
                assert_eq!(
                    rc, PROPRIETAIRE_INVALIDE,
                    "un jeton sans Administrateurs actifs a attribue son pipe aux Administrateurs"
                );
                assert_eq!(proprietaire, PipeOwner::Other);
            }
        }

        /// Ce qui protege le pipe du daemon PENDANT qu'il tourne. Son
        /// proprietaire est LocalSystem, et une instance de plus, creee par un
        /// tiers, recevrait des clients qui liraient ce proprietaire-la. Or
        /// une instance de plus exige `FILE_CREATE_PIPE_INSTANCE` sur la DACL
        /// du pipe EXISTANT, et `PIPE_SDDL` ne l'accorde qu'a SYSTEM et aux
        /// Administrateurs: sans eux, ce compte ne s'intercale pas, meme en
        /// proposant son propre descripteur, grand ouvert. Avec eux il le
        /// peut: la limite de la regle stricte de la preuve, mesuree aussi.
        #[tokio::test]
        async fn sans_administrateurs_actifs_aucune_instance_ne_s_ajoute_au_pipe_du_daemon() {
            let nom = nom("instance");
            let _daemon = IpcServer::bind(&nom, AuthPolicy::default(), None)
                .await
                .expect("bind");
            let issue = create_pipe(&nom, "D:P(A;;GA;;;WD)", false).map(|_| ());
            if administrateurs_actifs() {
                assert!(issue.is_ok(), "{issue:?}");
            } else {
                match issue {
                    Err(IpcError::Io(e)) => {
                        assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied, "{e}")
                    }
                    autre => panic!("une instance s'est ajoutee au pipe du daemon: {autre:?}"),
                }
            }
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
#[cfg(windows)]
pub use imp::{PipeOwner, decide_pipe_owner};

#[cfg(test)]
mod tests_regles_serveur {
    use super::*;

    /// Les noms sont un contrat de rapport, et les messages d'erreur peuvent
    /// y etre recopies: ils ne nomment aucune valeur.
    #[test]
    fn les_noms_des_regles_sont_un_contrat_de_rapport() {
        assert_eq!(
            ServerRule::RootPeerCredentials.name(),
            "root-peer-credentials"
        );
        assert_eq!(
            ServerRule::UidPeerCredentials.name(),
            "uid-peer-credentials"
        );
        assert_eq!(
            ServerRule::WindowsSystemPipeOwner.name(),
            "windows-system-pipe-owner"
        );
        assert_eq!(
            ServerRule::WindowsAdministratorsPipeOwner.name(),
            "windows-administrators-pipe-owner"
        );
        for message in [
            ServerIdentityError::Unreadable.to_string(),
            ServerIdentityError::Refused.to_string(),
        ] {
            for interdit in ["uid", "pid", "S-1-"] {
                assert!(!message.contains(interdit), "{message}");
            }
        }
    }
}
