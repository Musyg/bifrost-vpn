//! Transport: socket Unix cote Linux, named pipe cote Windows.
//!
//! Les deux cotes appliquent la meme regle: le canal n'est joignable que par
//! les identites autorisees, et la verification se fait a l'acceptation, avant
//! de lire le moindre octet du client.

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

use crate::auth::{AuthPolicy, PeerIdentity, SupplementaryGroups};
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
    #[error("aucune requete complete dans le delai imparti")]
    RequestTimeout,
}

pub type Result<T> = std::result::Result<T, IpcError>;

impl IpcError {
    /// Le canal existe, et son serveur n'a pris aucune connexion de plus.
    ///
    /// A lire sur une erreur de `IpcClient::connect_verified`, la seule ou elle
    /// ait ce sens. Windows: aucune instance du pipe ne s'est liberee avant la
    /// fin de l'attente du client (`ERROR_PIPE_BUSY`, rendu passe
    /// `ATTENTE_PIPE_OCCUPE`). Linux: la file d'attente du socket d'ecoute est
    /// pleine, et `connect(2)` rend alors `EAGAIN` (`unix_stream_connect`, net/unix/af_unix.c).
    /// Dans les deux cas un serveur tient le canal: ce n'est pas un daemon
    /// absent.
    pub fn is_server_busy(&self) -> bool {
        matches!(self, IpcError::Io(e) if imp::canal_occupe(e))
    }
}

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

/// Borne de la lecture d'une requete par le serveur, a compter du moment ou il
/// l'attend: apres l'acceptation pour la premiere, apres sa reponse pour
/// chacune des suivantes.
///
/// Le protocole n'a ni abonnement ni message que le serveur enverrait sans
/// qu'on le lui demande: chaque echange part d'une requete, et chaque client
/// du depot ecrit la sienne des que l'identite du serveur est etablie. Une
/// connexion qui ne transmet aucune requete complete dans ce delai n'a donc
/// rien a attendre du daemon; sans cette borne, elle lui tiendrait une tache,
/// et sous Windows une instance du pipe, aussi longtemps que le client le
/// voudrait. Le temps de traiter une requete n'y entre pas: une commande
/// longue (`connect`, `check`) n'est jamais coupee par cette borne.
const DELAI_REQUETE: std::time::Duration = std::time::Duration::from_secs(10);

/// Lit la trame d'une requete, dans le delai imparti au client pour l'ecrire.
async fn read_request_frame<R>(
    reader: &mut BufReader<R>,
    delai: std::time::Duration,
) -> Result<Vec<u8>>
where
    R: tokio::io::AsyncRead + Unpin,
{
    tokio::time::timeout(delai, read_frame(reader))
        .await
        .map_err(|_| IpcError::RequestTimeout)?
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
// Acceptation: ce qui arrete le serveur, et ce qui ne l'arrete pas
// --------------------------------------------------------------------------
//
// Une erreur rencontree en acceptant n'est pas forcement une erreur de
// l'ecoute. Chaque plateforme la range, dans son `accept`, dans l'un de trois
// cas:
//
// - Elle ne touche qu'UNE connexion: celle-la est fermee sans que rien n'en
//   soit lu, et l'acceptation reprend aussitot.
// - Une ressource du systeme manque (descripteurs ou memoire sous Linux,
//   memoire ou quota du noyau sous Windows): l'acceptation attend
//   `PAUSE_EPUISEMENT`, puis reessaie, aussi longtemps qu'il le faut. Un
//   serveur a court de descripteurs en retrouve des que ses connexions se
//   ferment, et chacune est bornee dans le temps (`DELAI_REQUETE`).
// - Le reste touche l'ecoute elle-meme, et `accept` le rend.
//
// Les boucles d'acceptation de reference tranchent les deux premiers cas de la
// meme facon, lues le 01/10/2026: axum 0.8.9 (`serve/listener.rs`) reprend
// aussitot sur ConnectionRefused, ConnectionAborted et ConnectionReset, et
// attend une seconde sur toute autre erreur, comme le faisait hyper 0.14.27
// (`server/tcp.rs`), dont la documentation nomme le cas d'un processus arrive
// au maximum de ses fichiers ouverts (EMFILE). Elles n'ont pas le troisieme:
// ici, une ecoute perdue reste fatale.

/// Attente avant de reessayer une acceptation qui a echoue faute de ressource:
/// dix essais par seconde au plus, et rien entre deux.
const PAUSE_EPUISEMENT: std::time::Duration = std::time::Duration::from_millis(100);

/// Une ligne de journal au plus par intervalle pour les incidents
/// d'acceptation: un epuisement qui dure, ou des connexions qui echouent en
/// rafale, ne remplissent pas le journal.
const INTERVALLE_JOURNAL: std::time::Duration = std::time::Duration::from_secs(60);

/// Le message d'un epuisement de ressource pendant l'acceptation.
const ACCEPTATION_SUSPENDUE: &str =
    "acceptation suspendue: ressource epuisee, nouvel essai apres une pause";

/// Le debit du journal des incidents d'acceptation: la premiere ligne tout de
/// suite, puis une au plus par `INTERVALLE_JOURNAL`, qui dit combien
/// d'incidents ont ete tus depuis la precedente.
#[derive(Debug, Default)]
struct Journal {
    derniere: Option<std::time::Instant>,
    tus: u64,
    /// Lignes ecrites, que les recettes comptent.
    #[cfg(test)]
    lignes: u64,
}

impl Journal {
    /// Ecrit la ligne de l'incident `quoi` si le debit le permet; sinon le
    /// compte, pour la ligne suivante.
    fn incident(&mut self, quoi: &'static str, erreur: &dyn std::fmt::Display) {
        let maintenant = std::time::Instant::now();
        if self
            .derniere
            .is_some_and(|t| maintenant.duration_since(t) < INTERVALLE_JOURNAL)
        {
            self.tus += 1;
            return;
        }
        self.derniere = Some(maintenant);
        let tus = std::mem::take(&mut self.tus);
        tracing::warn!(error = %erreur, incidents_tus = tus, "{quoi}");
        #[cfg(test)]
        {
            self.lignes += 1;
        }
    }
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
        /// [`DELAI_REQUETE`]; les recettes le raccourcissent.
        pub(super) delai_requete: std::time::Duration,
        /// Le debit du journal des incidents d'acceptation.
        pub(super) journal: Journal,
        /// Recettes: une erreur substituee a celle d'une etape de `accept`.
        #[cfg(test)]
        pub(super) panne: Option<Panne>,
    }

    /// Les etapes de `accept` ou une recette substitue une erreur a l'issue
    /// du systeme. Le reste du chemin est celui du daemon.
    #[cfg(test)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(super) enum Etape {
        /// A la place de `accept(2)`: la connexion en attente reste dans la
        /// file d'ecoute.
        Acceptation,
        /// A la place de la lecture de l'identite d'un pair deja accepte.
        Identite,
        /// A la place de la lecture de `/proc/<pid>/status`, ou se lisent les
        /// groupes supplementaires d'un pair dont l'identite est lue.
        Groupes,
    }

    /// Ce qu'une recette rend a chaque etape: `Some` substitue l'erreur.
    #[cfg(test)]
    pub(super) type Panne = Box<dyn FnMut(Etape) -> Option<std::io::Error> + Send>;

    /// Le message d'une connexion abandonnee sur une erreur qui ne touche
    /// qu'elle.
    const CONNEXION_ABANDONNEE: &str = "connexion abandonnee sans rien en lire, l'ecoute continue";

    /// Ce qu'une erreur de `UnixListener::accept` dit de l'ecoute.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(super) enum Nature {
        /// Une seule connexion est perdue: on accepte aussitot la suivante.
        Connexion,
        /// Une ressource manque: on attend `PAUSE_EPUISEMENT`, puis on
        /// reessaie.
        Epuisement,
        /// L'ecoute elle-meme: rendue a l'appelant.
        Fatale,
    }

    /// tokio reunit sous `accept` l'appel `accept4(2)` et l'enregistrement
    /// aupres d'epoll de la connexion qu'il rend (`epoll_ctl(2)`). Sources lues
    /// le 01/10/2026: accept(2) et epoll_ctl(2) des man-pages 6.19, et
    /// `net/socket.c` de Linux 7.0 (`__sys_accept4_file`, `do_accept`).
    pub(super) fn nature(e: &std::io::Error) -> Nature {
        match e.raw_os_error() {
            // Plus de descripteur pour ce processus (EMFILE) ou pour le
            // systeme (ENFILE), plus de memoire (ENOMEM): Linux les rend avant
            // de retirer la connexion de la file d'ecoute
            // (`get_unused_fd_flags`, `sock_alloc`, `sock_alloc_file`), ou
            // elle attend l'essai suivant. ENOBUFS, qu'accept(2) range avec
            // ENOMEM, est traite comme lui. ENOMEM et ENOSPC (la limite
            // `max_user_watches`) viennent aussi d'epoll_ctl, apres
            // l'acceptation: cette connexion-la est alors fermee, et son
            // client lit une fin de flux.
            Some(libc::EMFILE | libc::ENFILE | libc::ENOMEM | libc::ENOBUFS | libc::ENOSPC) => {
                Nature::Epuisement
            }
            // Une connexion avortee (ECONNABORTED, que `do_accept` rend apres
            // l'avoir retiree de la file), une erreur de protocole propre a la
            // nouvelle connexion (EPROTO), un signal (EINTR): l'ecoute est
            // intacte.
            Some(libc::ECONNABORTED | libc::EPROTO | libc::EINTR) => Nature::Connexion,
            // L'ecoute elle-meme (EBADF, EINVAL, ENOTSOCK, EOPNOTSUPP), le
            // refus d'un module de securite (EPERM, EACCES: `do_accept` le rend
            // avant de retirer la connexion, il reviendrait a chaque essai), et
            // tout ce qui n'est pas nomme ci-dessus.
            _ => Nature::Fatale,
        }
    }

    /// `connect(2)` a trouve pleine la file d'attente du socket d'ecoute.
    pub(super) fn canal_occupe(e: &std::io::Error) -> bool {
        e.raw_os_error() == Some(libc::EAGAIN)
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
                delai_requete: DELAI_REQUETE,
                journal: Journal::default(),
                #[cfg(test)]
                panne: None,
            })
        }

        /// Accepte une connexion et refuse immediatement un pair non autorise.
        ///
        /// Ne rend que les erreurs de l'ecoute elle-meme (voir [`nature`]):
        /// une erreur propre a une connexion la ferme sans rien en lire et
        /// passe a la suivante, un epuisement de ressource attend
        /// `PAUSE_EPUISEMENT` puis reessaie. Les deux s'inscrivent au journal,
        /// a debit borne.
        ///
        /// `&mut self` par symetrie avec la version Windows, qui doit preparer
        /// l'instance suivante du named pipe a chaque acceptation.
        pub async fn accept(&mut self) -> Result<Connection> {
            loop {
                let stream = match self.accepter_une().await {
                    Ok(stream) => stream,
                    Err(e) => match nature(&e) {
                        Nature::Connexion => {
                            self.journal.incident(CONNEXION_ABANDONNEE, &e);
                            continue;
                        }
                        Nature::Epuisement => {
                            self.journal.incident(ACCEPTATION_SUSPENDUE, &e);
                            tokio::time::sleep(PAUSE_EPUISEMENT).await;
                            continue;
                        }
                        Nature::Fatale => return Err(e.into()),
                    },
                };
                // L'identite d'un pair deja accepte ne touche que lui:
                // illisible, sa connexion est fermee sans que rien n'en soit
                // lu ni ecrit.
                let peer = match self.identite(&stream) {
                    Ok(peer) => peer,
                    Err(e) => {
                        self.journal.incident(CONNEXION_ABANDONNEE, &e);
                        continue;
                    }
                };
                match authorize(&peer, &self.policy) {
                    Ok(()) => {
                        tracing::debug!(%peer, "client accepte");
                        return Ok(Connection::new(stream, peer, self.delai_requete));
                    }
                    Err(e) => {
                        // On refuse sans rien lire du client, et on continue a
                        // servir: un refus ne doit pas arreter le daemon. La
                        // cause va au journal comme au client: des groupes
                        // illisibles ne s'y lisent pas comme un non-membre.
                        tracing::warn!(%peer, error = %e, "connexion refusee");
                        let mut conn = Connection::new(stream, peer, self.delai_requete);
                        let _ = conn.send(&Response::error(e.to_string())).await;
                    }
                }
            }
        }

        /// Une connexion de la file d'ecoute.
        async fn accepter_une(&mut self) -> std::io::Result<UnixStream> {
            #[cfg(test)]
            if let Some(e) = self.panne(Etape::Acceptation) {
                return Err(e);
            }
            self.listener.accept().await.map(|(stream, _)| stream)
        }

        /// L'identite du pair d'une connexion acceptee.
        fn identite(&mut self, stream: &UnixStream) -> Result<PeerIdentity> {
            #[cfg(test)]
            if let Some(e) = self.panne(Etape::Identite) {
                return Err(e.into());
            }
            let cred = stream.peer_cred()?;
            let pid = cred.pid();
            Ok(PeerIdentity {
                uid: cred.uid(),
                gid: cred.gid(),
                pid,
                supplementary_groups: match pid {
                    Some(pid) => self.groupes(pid),
                    None => SupplementaryGroups::Known(Vec::new()),
                },
            })
        }

        /// Les groupes supplementaires du pair `pid`, ou pourquoi ils n'ont
        /// pas pu etre lus: `authorize` ne confond pas les deux.
        fn groupes(&mut self, pid: i32) -> SupplementaryGroups {
            #[cfg(test)]
            if let Some(e) = self.panne(Etape::Groupes) {
                return crate::auth::groups_from_status(Err(e));
            }
            crate::auth::supplementary_groups(pid)
        }

        /// L'erreur qu'une recette substitue a l'etape `etape`, s'il y en a
        /// une.
        #[cfg(test)]
        fn panne(&mut self, etape: Etape) -> Option<std::io::Error> {
            self.panne.as_mut().and_then(|p| p(etape))
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

    pub struct Connection {
        reader: BufReader<tokio::io::ReadHalf<UnixStream>>,
        writer: tokio::io::WriteHalf<UnixStream>,
        peer: PeerIdentity,
        delai: std::time::Duration,
    }

    impl Connection {
        fn new(stream: UnixStream, peer: PeerIdentity, delai: std::time::Duration) -> Self {
            let (r, w) = tokio::io::split(stream);
            Self {
                reader: BufReader::new(r),
                writer: w,
                peer,
                delai,
            }
        }

        pub fn peer(&self) -> &PeerIdentity {
            &self.peer
        }

        /// La requete suivante, lue dans `DELAI_REQUETE`. Au-dela, `recv`
        /// rend [`IpcError::RequestTimeout`] et la connexion est a abandonner:
        /// une trame entamee a pu y etre lue en partie.
        ///
        /// # Pilote de temps requis
        ///
        /// Le delai est un minuteur tokio: `recv` doit tourner dans un runtime
        /// dont le pilote de temps est actif (`enable_time`, ou `enable_all`
        /// comme le daemon). Sans lui, tokio panique des le premier appel.
        pub async fn recv(&mut self) -> Result<Request> {
            let bytes = read_request_frame(&mut self.reader, self.delai).await?;
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
    use std::time::{Duration, Instant};
    use tokio::net::windows::named_pipe::{
        ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions,
    };
    use windows_sys::Win32::Foundation::{
        ERROR_COMMITMENT_LIMIT, ERROR_NO_SYSTEM_RESOURCES, ERROR_NOT_ENOUGH_MEMORY,
        ERROR_NOT_ENOUGH_QUOTA, ERROR_OUTOFMEMORY, ERROR_PIPE_BUSY, LocalFree,
    };
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

    /// Le descripteur des serveurs de recette: celui du daemon, plus une ACE
    /// pour le proprietaire du pipe (`OW`), c'est-a-dire le compte qui le
    /// cree. Un compte non eleve joint ainsi le serveur qu'il mesure, par le
    /// meme `bind_avec_descripteur` et le meme `accept` que le daemon.
    #[cfg(test)]
    pub(super) const SDDL_RECETTE: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;OW)";

    /// `ERROR_PIPE_BUSY`, tel que `std::io::Error::raw_os_error` le rend: le
    /// pipe existe, et aucune de ses instances n'attend de client.
    const PIPE_OCCUPE: i32 = ERROR_PIPE_BUSY as i32;

    /// Borne de l'attente d'une instance libre, par le client.
    const ATTENTE_PIPE_OCCUPE: Duration = Duration::from_secs(2);

    /// Intervalle entre deux ouvertures pendant cette attente.
    const PAS_PIPE_OCCUPE: Duration = Duration::from_millis(50);

    /// Aucune instance du pipe n'etait libre a la fin de l'attente.
    pub(super) fn canal_occupe(e: &std::io::Error) -> bool {
        e.raw_os_error() == Some(PIPE_OCCUPE)
    }

    pub struct IpcServer {
        path: String,
        policy: AuthPolicy,
        /// Le descripteur de CHAQUE instance: [`PIPE_SDDL`], pose par `bind`.
        sddl: &'static str,
        /// [`DELAI_REQUETE`]; les recettes le raccourcissent.
        pub(super) delai_requete: std::time::Duration,
        /// L'instance qui attend le client suivant. Toujours presente: c'est
        /// elle qui tient le nom du pipe entre deux clients, et celle qui la
        /// remplace est creee AVANT qu'elle ne parte avec sa connexion.
        next: NamedPipeServer,
        /// Le debit du journal des incidents d'acceptation.
        pub(super) journal: Journal,
        /// Recettes: une erreur substituee a celle d'une etape de `accept`.
        #[cfg(test)]
        pub(super) panne: Option<Panne>,
    }

    /// Les etapes de `accept` ou une recette substitue une erreur a l'issue
    /// du systeme. Le reste du chemin est celui du daemon.
    #[cfg(test)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(super) enum Etape {
        /// A la place de la creation de l'instance suivante, un client etant
        /// connecte a l'instance en attente.
        InstanceSuivante,
    }

    /// Ce qu'une recette rend a chaque etape: `Some` substitue l'erreur.
    #[cfg(test)]
    pub(super) type Panne = Box<dyn FnMut(Etape) -> Option<std::io::Error> + Send>;

    /// La creation d'une instance a-t-elle echoue faute de ressource du noyau?
    ///
    /// Chaque instance prend ses tampons dans la reserve non paginee du noyau,
    /// et un pipe a instances illimitees, comme celui du daemon, n'a pas
    /// d'autre limite (CreateNamedPipeW, "nMaxInstances" et "Remarks", lu le
    /// 01/10/2026). Les codes Win32 de STATUS_NO_MEMORY (8),
    /// STATUS_INSUFFICIENT_RESOURCES (1450), STATUS_COMMITMENT_LIMIT (1455) et
    /// STATUS_QUOTA_EXCEEDED (1816), tels que `RtlNtStatusToDosError` les rend
    /// (releve le 01/10/2026), et ERROR_OUTOFMEMORY (14).
    pub(super) fn est_un_epuisement(e: &std::io::Error) -> bool {
        matches!(
            e.raw_os_error().map(|code| code as u32),
            Some(
                ERROR_NOT_ENOUGH_MEMORY
                    | ERROR_OUTOFMEMORY
                    | ERROR_NO_SYSTEM_RESOURCES
                    | ERROR_COMMITMENT_LIMIT
                    | ERROR_NOT_ENOUGH_QUOTA
            )
        )
    }

    impl IpcServer {
        pub async fn bind(
            path: impl AsRef<Path>,
            policy: AuthPolicy,
            _group: Option<u32>,
        ) -> Result<Self> {
            Self::bind_avec_descripteur(path.as_ref(), policy, PIPE_SDDL)
        }

        /// Le corps de `bind`, le descripteur en parametre. Le daemon n'en
        /// passe jamais d'autre que [`PIPE_SDDL`]; les recettes, si: un
        /// compte non eleve n'ouvre pas le pipe du daemon, et c'est pourtant
        /// sous ce compte qu'elles mesurent l'acceptation et le client.
        pub(super) fn bind_avec_descripteur(
            path: &Path,
            policy: AuthPolicy,
            sddl: &'static str,
        ) -> Result<Self> {
            let path = path.to_string_lossy().into_owned();
            // La premiere instance est creee avec first_pipe_instance pour
            // garantir qu'aucun autre processus n'a deja squatte le nom.
            let next = create_pipe(&path, sddl, true)?;
            tracing::info!(path = %path, "IPC en ecoute");
            Ok(Self {
                path,
                policy,
                sddl,
                delai_requete: DELAI_REQUETE,
                next,
                journal: Journal::default(),
                #[cfg(test)]
                panne: None,
            })
        }

        /// Attend un client sur l'instance en attente, et la rend avec sa
        /// connexion une fois l'instance suivante creee.
        ///
        /// Le nom du pipe ne cesse jamais d'exister: sans cela un processus
        /// tiers pourrait le creer a notre place, et le serveur rejoindrait
        /// son pipe en creant l'instance suivante (`first_pipe_instance` est
        /// faux pour elle). `connect` se fait donc sur l'instance que le
        /// serveur tient, sans la lui retirer, et la suivante est creee
        /// pendant qu'elle le tient encore.
        ///
        /// Si cette creation echoue faute de ressource du noyau (voir
        /// [`est_un_epuisement`]), le client deja connecte patiente:
        /// `PAUSE_EPUISEMENT`, puis un nouvel essai, aussi longtemps qu'il le
        /// faut, et son instance tient le nom pendant tout ce temps. Toute
        /// autre erreur est rendue, celles de `connect` comprises. Un client
        /// qui ferme avant ou pendant l'acceptation n'en produit pas: mio
        /// 1.2, sous tokio, prend `ERROR_NO_DATA` de `ConnectNamedPipe` pour
        /// une connexion etablie (`connect_overlapped`), que `accept` rend et
        /// dont la lecture rend `Closed`, mesure par
        /// `un_client_qui_ferme_tot_n_arrete_pas_le_serveur`.
        pub async fn accept(&mut self) -> Result<Connection> {
            self.next.connect().await?;
            let suivante = self.instance_suivante().await?;
            let connectee = std::mem::replace(&mut self.next, suivante);
            let peer = peer_identity(&connectee);
            tracing::debug!(%peer, "client accepte");
            Ok(Connection::new(connectee, peer, self.delai_requete))
        }

        /// L'instance qui attendra le client suivant, creee pendant que
        /// `next` tient le nom.
        async fn instance_suivante(&mut self) -> Result<NamedPipeServer> {
            loop {
                match self.creer_une_instance() {
                    Err(IpcError::Io(e)) if est_un_epuisement(&e) => {
                        self.journal.incident(ACCEPTATION_SUSPENDUE, &e);
                        tokio::time::sleep(PAUSE_EPUISEMENT).await;
                    }
                    issue => return issue,
                }
            }
        }

        /// Une instance de plus du pipe, jamais la premiere: appelee
        /// seulement pendant que `next` tient le nom.
        fn creer_une_instance(&mut self) -> Result<NamedPipeServer> {
            #[cfg(test)]
            if let Some(e) = self.panne.as_mut().and_then(|p| p(Etape::InstanceSuivante)) {
                return Err(e.into());
            }
            create_pipe(&self.path, self.sddl, false)
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
            supplementary_groups: SupplementaryGroups::Known(Vec::new()),
        }
    }

    pub struct Connection {
        reader: BufReader<tokio::io::ReadHalf<NamedPipeServer>>,
        writer: tokio::io::WriteHalf<NamedPipeServer>,
        peer: PeerIdentity,
        delai: std::time::Duration,
    }

    impl Connection {
        fn new(pipe: NamedPipeServer, peer: PeerIdentity, delai: std::time::Duration) -> Self {
            let (r, w) = tokio::io::split(pipe);
            Self {
                reader: BufReader::new(r),
                writer: w,
                peer,
                delai,
            }
        }

        pub fn peer(&self) -> &PeerIdentity {
            &self.peer
        }

        /// Meme contrat que la version Unix: la requete suivante, lue dans
        /// `DELAI_REQUETE`, dans un runtime dont le pilote de temps est actif
        /// (`enable_time`, ou `enable_all` comme le daemon).
        pub async fn recv(&mut self) -> Result<Request> {
            let bytes = read_request_frame(&mut self.reader, self.delai).await?;
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

    /// Ouvre le pipe `path` cote client, en attendant au plus `borne` qu'une
    /// de ses instances soit libre.
    ///
    /// `ERROR_PIPE_BUSY` dit que le pipe EXISTE et qu'aucune instance
    /// n'attend de client: le serveur prepare la suivante des qu'un client a
    /// pris la precedente, et deux clients simultanes se croisent dans cet
    /// intervalle. On rouvre donc toutes les `PAS_PIPE_OCCUPE`, la boucle que
    /// la documentation de tokio donne pour `NamedPipeClient`, jusqu'a la
    /// borne; passe la borne, l'erreur du systeme est rendue telle quelle.
    /// Toute autre erreur (pipe absent, acces refuse) est rendue a la
    /// premiere ouverture.
    ///
    /// Pas `WaitNamedPipeW`: il bloque le fil qui l'appelle (le runtime, ou
    /// un fil de `spawn_blocking` qu'une borne exterieure ne sait pas
    /// interrompre), et sa documentation ne promet qu'une instance "disponible"
    /// que le `CreateFile` suivant peut encore trouver prise par un autre
    /// client: il faudrait la meme boucle autour.
    async fn ouvrir_le_pipe(path: &str, borne: Duration) -> std::io::Result<NamedPipeClient> {
        let debut = Instant::now();
        loop {
            match ClientOptions::new().open(path) {
                Err(e) if e.raw_os_error() == Some(PIPE_OCCUPE) && debut.elapsed() < borne => {}
                issue => return issue,
            }
            tokio::time::sleep(PAS_PIPE_OCCUPE).await;
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
        ///
        /// # Un pipe occupe n'est pas un pipe absent
        ///
        /// Quand toutes les instances du pipe sont prises (`ERROR_PIPE_BUSY`),
        /// le client rouvre jusqu'a `ATTENTE_PIPE_OCCUPE` (2 s) au lieu de
        /// conclure a l'absence du daemon; toute autre erreur d'ouverture est
        /// rendue aussitot (voir `ouvrir_le_pipe`). L'identite est exigee de
        /// l'instance OBTENUE, quelle que soit l'ouverture qui l'a donnee: la
        /// decision suit l'ouverture, et n'a qu'un chemin.
        pub async fn connect_verified(
            path: impl AsRef<Path>,
            attendu: ServerRequirement,
        ) -> Result<(Self, ServerRule)> {
            let path = path.as_ref().to_string_lossy().into_owned();
            let pipe = ouvrir_le_pipe(&path, ATTENTE_PIPE_OCCUPE).await?;
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
        pub(super) fn attendu_du_client(
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
                let proprietaire = pipe_owner(serveur.next.as_raw_handle()).expect("proprietaire");
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

    /// Un pipe OCCUPE n'est pas un pipe absent.
    ///
    /// Le serveur ne tient qu'une instance en attente a la fois, et prepare la
    /// suivante des qu'un client a pris la precedente: entre les deux, un
    /// autre client trouve le pipe sans instance libre (`ERROR_PIPE_BUSY`).
    /// Ces recettes mesurent ce que le client en fait, par `connect_verified`
    /// et contre un serveur qui passe par `bind_avec_descripteur` et `accept`
    /// comme le daemon. Chaque client est un fil a lui, avec son runtime, et
    /// rend son issue par un canal lu avec une borne: une attente sans fin
    /// rougit en quelques secondes, elle ne pend pas.
    #[cfg(test)]
    mod tests_pipe_occupe {
        use super::tests_identite_serveur::attendu_du_client;
        use super::*;
        use std::sync::mpsc;
        use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND};

        fn nom(suffixe: &str) -> String {
            format!(
                r"\\.\pipe\bifrost-ipc-occupe-{}-{suffixe}",
                std::process::id()
            )
        }

        fn runtime_serveur() -> tokio::runtime::Runtime {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("runtime du serveur")
        }

        /// Ce que `connect_verified` a rendu, reduit a ce qui traverse un
        /// canal.
        #[derive(Debug, PartialEq, Eq)]
        enum Issue {
            Admis(ServerRule),
            Refuse(ServerIdentityError),
            Io(Option<i32>),
            Autre(String),
        }

        /// Un client dans un fil a lui: son issue, et le temps qu'il y a mis.
        fn client(nom: String, attendu: ServerRequirement) -> mpsc::Receiver<(Issue, Duration)> {
            client_parti(nom, attendu).1
        }

        /// `client`, et son heure de depart: celle d'ou le client compte sa
        /// duree, prise juste avant `connect_verified`. Un fil se lance quand
        /// le systeme le planifie, pas quand on le demande: une duree prise
        /// par le client ne se compare a l'horloge de la recette qu'a partir
        /// de cette heure.
        fn client_parti(
            nom: String,
            attendu: ServerRequirement,
        ) -> (mpsc::Receiver<Instant>, mpsc::Receiver<(Issue, Duration)>) {
            let (parti, depart) = mpsc::channel();
            let (tx, rx) = mpsc::channel();
            std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("runtime du client");
                let debut = Instant::now();
                let _ = parti.send(debut);
                let issue = match rt.block_on(IpcClient::connect_verified(&nom, attendu)) {
                    Ok((_, regle)) => Issue::Admis(regle),
                    Err(IpcError::ServerIdentity(e)) => Issue::Refuse(e),
                    Err(IpcError::Io(e)) => Issue::Io(e.raw_os_error()),
                    Err(autre) => Issue::Autre(autre.to_string()),
                };
                let _ = tx.send((issue, debut.elapsed()));
            });
            (depart, rx)
        }

        /// Le serveur de recette, dont l'unique instance est prise par un
        /// premier client que personne n'accepte: le pipe existe, et aucune
        /// de ses instances n'attend de client.
        fn serveur_occupe(nom: &str, rt: &tokio::runtime::Runtime) -> (IpcServer, NamedPipeClient) {
            let _dans = rt.enter();
            let serveur = IpcServer::bind_avec_descripteur(
                Path::new(nom),
                AuthPolicy::default(),
                SDDL_RECETTE,
            )
            .expect("serveur de recette");
            let premier = ClientOptions::new().open(nom).expect("premier client");
            (serveur, premier)
        }

        /// Occupe au-dela de la borne: le client a attendu au moins
        /// `ATTENTE_PIPE_OCCUPE`, puis rend l'erreur du systeme telle quelle,
        /// sans pendre.
        #[test]
        fn un_pipe_occupe_au_dela_de_la_borne_rend_son_erreur_sans_pendre() {
            let rt = runtime_serveur();
            let nom = nom("borne");
            let (_serveur, _premier) = serveur_occupe(&nom, &rt);
            let (issue, duree) = client(nom, ServerRequirement::Privileged)
                .recv_timeout(ATTENTE_PIPE_OCCUPE + Duration::from_secs(3))
                .expect("l'attente d'une instance libre doit etre bornee");
            assert_eq!(issue, Issue::Io(Some(PIPE_OCCUPE)), "{duree:?}");
            assert!(
                duree >= ATTENTE_PIPE_OCCUPE,
                "le client n'a pas attendu d'instance libre: {duree:?}"
            );
            assert!(
                duree < ATTENTE_PIPE_OCCUPE + Duration::from_secs(1),
                "l'attente a depasse sa borne: {duree:?}"
            );
        }

        /// Une instance se libere pendant l'attente: le client l'ouvre, et
        /// l'identite du serveur est exigee de CETTE instance comme de toute
        /// autre. Le pipe de recette appartient au compte courant, que la
        /// preuve refuse (sous SYSTEM il appartient a LocalSystem, qu'elle
        /// admet): `attendu_du_client` le dit en clair.
        #[test]
        fn l_identite_est_exigee_de_l_instance_obtenue_apres_l_attente() {
            let rt = runtime_serveur();
            let nom = nom("identite");
            let (mut serveur, _premier) = serveur_occupe(&nom, &rt);
            let proprietaire = pipe_owner(serveur.next.as_raw_handle()).expect("proprietaire");
            // Les 300 ms se comptent a partir du depart du client, que le
            // systeme peut planifier bien apres sa demande: comptees a partir
            // de la demande, une partie s'ecoulerait avant qu'il attende.
            let lancement = Instant::now();
            let (parti, issue) = client_parti(nom, ServerRequirement::Privileged);
            let depart = parti
                .recv_timeout(Duration::from_secs(5))
                .expect("le fil du client doit partir")
                - lancement;
            std::thread::sleep(Duration::from_millis(300));
            assert!(
                matches!(issue.try_recv(), Err(mpsc::TryRecvError::Empty)),
                "le client a rendu sans attendre d'instance libre"
            );
            // Le serveur accepte le premier client et prepare l'instance
            // suivante, que personne n'occupe.
            let _connexion = rt.block_on(serveur.accept()).expect("acceptation");
            let (issue, duree) = issue
                .recv_timeout(ATTENTE_PIPE_OCCUPE + Duration::from_secs(3))
                .expect("le client doit rendre son issue dans un temps borne");
            println!("mesure instance obtenue: depart du client {depart:?}, attente {duree:?}");
            assert!(duree >= Duration::from_millis(300), "{duree:?}");
            let attendu = match attendu_du_client(proprietaire, ServerRequirement::Privileged) {
                Some(regle) => Issue::Admis(regle),
                None => Issue::Refuse(ServerIdentityError::Refused),
            };
            assert_eq!(issue, attendu, "{proprietaire:?}, {duree:?}");
        }

        /// Toute autre erreur d'ouverture est rendue a la premiere: un pipe
        /// absent, et un pipe que sa DACL ferme a ce compte (SYSTEM seul).
        #[test]
        fn toute_autre_erreur_d_ouverture_est_rendue_sans_attendre() {
            let immediat = ATTENTE_PIPE_OCCUPE / 4;
            let (issue, duree) = client(nom("absent"), ServerRequirement::Elevated)
                .recv_timeout(ATTENTE_PIPE_OCCUPE + Duration::from_secs(3))
                .expect("un pipe absent doit rendre son erreur dans un temps borne");
            assert_eq!(issue, Issue::Io(Some(ERROR_FILE_NOT_FOUND as i32)));
            assert!(duree < immediat, "pipe absent: {duree:?}");

            let rt = runtime_serveur();
            let nom = nom("refuse");
            let _dans = rt.enter();
            let serveur = create_pipe(&nom, "D:P(A;;GA;;;SY)", true).expect("pipe de SYSTEM");
            let proprietaire = pipe_owner(serveur.as_raw_handle()).expect("proprietaire");
            let (issue, duree) = client(nom, ServerRequirement::Elevated)
                .recv_timeout(ATTENTE_PIPE_OCCUPE + Duration::from_secs(3))
                .expect("un acces refuse doit rendre son erreur dans un temps borne");
            if proprietaire == PipeOwner::LocalSystem {
                // Sous SYSTEM la DACL admet ce compte: le pipe s'ouvre.
                assert_eq!(issue, Issue::Admis(ServerRule::WindowsSystemPipeOwner));
            } else {
                assert_eq!(issue, Issue::Io(Some(ERROR_ACCESS_DENIED as i32)));
                assert!(duree < immediat, "acces refuse: {duree:?}");
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

        /// `bind` pose `PIPE_SDDL`, le descripteur en parametre de
        /// `bind_avec_descripteur` n'etant qu'une couture pour les recettes;
        /// et sa premiere instance exige `first_pipe_instance`: un nom deja
        /// tenu par un autre serveur, meme grand ouvert, fait echouer `bind`
        /// au lieu de lui ajouter une instance.
        #[tokio::test]
        async fn bind_pose_le_descripteur_du_daemon_et_exige_la_premiere_instance() {
            let nom = |suffixe: &str| {
                format!(
                    r"\\.\pipe\bifrost-ipc-sddl-{}-{suffixe}",
                    std::process::id()
                )
            };
            let serveur = IpcServer::bind(nom("libre"), AuthPolicy::default(), None)
                .await
                .expect("bind");
            assert_eq!(serveur.sddl, PIPE_SDDL);

            let tenu = nom("tenu");
            let _tiers = create_pipe(&tenu, "D:P(A;;GA;;;WD)", true).expect("pipe du tiers");
            match IpcServer::bind(&tenu, AuthPolicy::default(), None).await {
                Err(IpcError::Io(e)) => {
                    assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied, "{e}")
                }
                Ok(_) => panic!("bind a ajoute une instance a un pipe deja tenu"),
                Err(autre) => panic!("{autre}"),
            }
        }

        /// Et Windows accepte cette chaine.
        ///
        /// Une coquille dans le SDDL ne se voit aujourd'hui qu'au demarrage du
        /// daemon, sur une machine Windows, au moment ou le pipe se cree. La
        /// meme conversion que `create_pipe` la reduit a une recette.
        #[test]
        fn windows_accepte_le_sddl_du_pipe() {
            let mut large: Vec<u16> = PIPE_SDDL.encode_utf16().collect();
            large.push(0);
            let mut psd: *mut c_void = std::ptr::null_mut();
            // SAFETY: meme appel que create_pipe, sur une chaine UTF-16
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

/// Plusieurs clients a la fois, et un client qui se tait: ce qu'en font le
/// serveur et le client, par le chemin de production. Linux: `bind`, dans un
/// repertoire de la recette. Windows: `bind_avec_descripteur`, le corps de
/// `bind`, avec le descripteur de recette qui laisse ce compte ouvrir le pipe.
/// Puis `accept`, `recv` et `connect_verified`, tels quels.
#[cfg(test)]
mod tests_clients_concurrents {
    use super::*;
    use crate::protocol::Command;
    use std::sync::{Arc, Barrier, mpsc};
    use std::time::{Duration, Instant};

    #[cfg(unix)]
    fn euid() -> u32 {
        // SAFETY: geteuid ne prend aucun argument et ne touche aucune memoire.
        unsafe { libc::geteuid() }
    }

    /// Ce qu'exigent les clients de ces recettes, dont le serveur est CE
    /// processus. Linux: son uid. Windows: la regle des commandes, qui admet
    /// le pipe d'un jeton eleve et refuse celui d'un compte ordinaire. Dans
    /// les deux cas, une identite DECIDEE dit que le client a joint le
    /// serveur.
    fn exigence() -> ServerRequirement {
        #[cfg(unix)]
        {
            ServerRequirement::Uid(euid())
        }
        #[cfg(windows)]
        {
            ServerRequirement::Elevated
        }
    }

    #[cfg(unix)]
    async fn serveur(nom: &str) -> (IpcServer, String) {
        use std::os::unix::fs::PermissionsExt;
        let dossier = std::env::temp_dir().join(format!(
            "bifrost-ipc-concurrents-{}-{nom}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dossier);
        std::fs::create_dir_all(&dossier).expect("repertoire de la recette");
        // Mode pose explicitement: `bind` pose un `umask(0o117)`, valable pour
        // tout le processus, le temps de se lier; un repertoire cree pendant
        // le bind d'une recette voisine naitrait sans bit d'execution, donc
        // intraversable, et ce bind-ci echouerait en `EACCES`.
        std::fs::set_permissions(&dossier, std::fs::Permissions::from_mode(0o755))
            .expect("repertoire de la recette en 0755");
        let chemin = dossier.join("d.sock");
        let policy = AuthPolicy {
            allowed_uids: vec![0, euid()],
            allowed_gid: None,
        };
        let serveur = IpcServer::bind(&chemin, policy, None).await.expect("bind");
        (serveur, chemin.to_string_lossy().into_owned())
    }

    #[cfg(windows)]
    async fn serveur(nom: &str) -> (IpcServer, String) {
        let chemin = format!(
            r"\\.\pipe\bifrost-ipc-concurrents-{}-{nom}",
            std::process::id()
        );
        let serveur = IpcServer::bind_avec_descripteur(
            std::path::Path::new(&chemin),
            AuthPolicy::default(),
            imp::SDDL_RECETTE,
        )
        .expect("serveur de recette");
        (serveur, chemin)
    }

    /// Retire le repertoire de la recette (Linux); rien a retirer sous
    /// Windows, le pipe disparait avec sa derniere poignee.
    fn nettoyer(chemin: &str) {
        #[cfg(unix)]
        if let Some(dossier) = std::path::Path::new(chemin).parent() {
            let _ = std::fs::remove_dir_all(dossier);
        }
        #[cfg(windows)]
        let _ = chemin;
    }

    /// Un client qui ne passe pas par `IpcClient`: il ouvre le canal et
    /// n'ecrit que ce que la recette lui fait ecrire.
    #[cfg(unix)]
    async fn client_brut(chemin: &str) -> tokio::net::UnixStream {
        tokio::net::UnixStream::connect(chemin)
            .await
            .expect("connexion")
    }

    #[cfg(windows)]
    async fn client_brut(chemin: &str) -> tokio::net::windows::named_pipe::NamedPipeClient {
        tokio::net::windows::named_pipe::ClientOptions::new()
            .open(chemin)
            .expect("ouverture")
    }

    /// Ce qu'un client a obtenu.
    #[derive(Debug)]
    enum Issue {
        /// L'identite du serveur a ete decidee, et, admise, l'echange a
        /// abouti.
        Joint,
        /// L'ouverture a echoue: le code du systeme.
        Ouverture(Option<i32>),
        Autre(String),
    }

    fn lancer_un_client(chemin: String, depart: Arc<Barrier>, tx: mpsc::Sender<(Issue, Duration)>) {
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime du client");
            depart.wait();
            let debut = Instant::now();
            let issue = rt.block_on(async {
                match IpcClient::connect_verified(&chemin, exigence()).await {
                    Ok((mut client, _)) => {
                        match client.request(&Request::new(Command::Status)).await {
                            Ok(Response::Ok) => Issue::Joint,
                            autre => Issue::Autre(format!("{autre:?}")),
                        }
                    }
                    Err(IpcError::ServerIdentity(_)) => Issue::Joint,
                    Err(IpcError::Io(e)) => Issue::Ouverture(e.raw_os_error()),
                    Err(autre) => Issue::Autre(autre.to_string()),
                }
            });
            let _ = tx.send((issue, debut.elapsed()));
        });
    }

    /// K clients lances ensemble, chacun dans un fil a lui comme dans un
    /// processus a lui, contre un serveur qui sert comme le daemon: une tache
    /// par connexion, l'acceptation suivante aussitot. Chacun joint le
    /// serveur. Le nombre d'ouvertures refusees, leurs codes et le plus long
    /// des temps de connexion sont imprimes: c'est la mesure.
    #[test]
    fn k_clients_concurrents_joignent_tous_le_serveur() {
        let mut ecarts = Vec::new();
        for k in [2usize, 4, 16] {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("runtime du serveur");
            let (mut serveur, chemin) = rt.block_on(serveur(&format!("k{k}")));
            rt.spawn(async move {
                while let Ok(mut connexion) = serveur.accept().await {
                    tokio::spawn(async move {
                        while connexion.recv().await.is_ok() {
                            if connexion.send(&Response::Ok).await.is_err() {
                                break;
                            }
                        }
                    });
                }
            });
            let depart = Arc::new(Barrier::new(k));
            let (tx, rx) = mpsc::channel();
            for _ in 0..k {
                lancer_un_client(chemin.clone(), depart.clone(), tx.clone());
            }
            drop(tx);
            let issues: Vec<(Issue, Duration)> = (0..k)
                .map(|_| {
                    rx.recv_timeout(Duration::from_secs(10))
                        .expect("chaque client rend son issue dans un temps borne")
                })
                .collect();
            rt.shutdown_timeout(Duration::from_secs(1));
            nettoyer(&chemin);
            let joints = issues
                .iter()
                .filter(|(i, _)| matches!(i, Issue::Joint))
                .count();
            let refusees: Vec<Option<i32>> = issues
                .iter()
                .filter_map(|(i, _)| match i {
                    Issue::Ouverture(code) => Some(*code),
                    _ => None,
                })
                .collect();
            let autres: Vec<&String> = issues
                .iter()
                .filter_map(|(i, _)| match i {
                    Issue::Autre(raison) => Some(raison),
                    _ => None,
                })
                .collect();
            let plus_long = issues.iter().map(|(_, d)| *d).max().unwrap_or_default();
            println!(
                "mesure clients concurrents: K={k} joints={joints} ouvertures refusees={} codes={refusees:?} autres={autres:?} plus long={plus_long:?}",
                refusees.len()
            );
            if joints != k {
                ecarts.push(format!("K={k}: {joints} joints sur {k}: {issues:?}"));
            }
        }
        assert!(ecarts.is_empty(), "{ecarts:#?}");
    }

    const DELAI_COURT: Duration = Duration::from_millis(300);
    const AU_PLUS: Duration = Duration::from_secs(5);

    /// La lecture a rendu `RequestTimeout` dans le delai, ni avant ni bien
    /// apres; un `recv` qui attend encore apres `AU_PLUS` est une connexion
    /// tenue sans borne.
    fn rendue_dans_le_delai(
        issue: std::result::Result<Result<Request>, tokio::time::error::Elapsed>,
        duree: Duration,
    ) {
        match issue {
            Err(_) => panic!("aucune borne: la connexion est tenue depuis {duree:?}"),
            Ok(Err(IpcError::RequestTimeout)) => {}
            Ok(autre) => panic!("issue inattendue apres {duree:?}: {autre:?}"),
        }
        assert!(
            duree >= DELAI_COURT && duree < DELAI_COURT + Duration::from_secs(1),
            "{duree:?}"
        );
    }

    /// Un client qui se connecte et n'ecrit rien ne tient pas la connexion,
    /// donc la tache du daemon, au-dela du delai.
    #[tokio::test]
    async fn une_connexion_sans_requete_est_rendue_dans_le_delai() {
        let (mut serveur, chemin) = serveur("muet").await;
        serveur.delai_requete = DELAI_COURT;
        let _client = client_brut(&chemin).await;
        let mut connexion = serveur.accept().await.expect("acceptation");
        let debut = Instant::now();
        let issue = tokio::time::timeout(AU_PLUS, connexion.recv()).await;
        let duree = debut.elapsed();
        drop(connexion);
        drop(serveur);
        nettoyer(&chemin);
        rendue_dans_le_delai(issue, duree);
    }

    /// La borne vaut pour chaque requete, pas pour la premiere seulement: un
    /// client qui a obtenu une reponse puis se tait, connexion ouverte, ne la
    /// tient pas davantage.
    #[tokio::test]
    async fn la_borne_vaut_pour_chaque_requete() {
        use tokio::io::AsyncWriteExt;
        let (mut serveur, chemin) = serveur("apres").await;
        serveur.delai_requete = DELAI_COURT;
        let mut client = client_brut(&chemin).await;
        let mut connexion = serveur.accept().await.expect("acceptation");
        let mut requete = serde_json::to_vec(&Request::new(Command::Status)).expect("requete");
        requete.push(b'\n');
        client.write_all(&requete).await.expect("ecriture");
        let premiere = tokio::time::timeout(AU_PLUS, connexion.recv()).await;
        assert!(
            matches!(premiere, Ok(Ok(_))),
            "une requete ecrite aussitot est lue: {premiere:?}"
        );
        connexion.send(&Response::Ok).await.expect("reponse");
        let debut = Instant::now();
        let seconde = tokio::time::timeout(AU_PLUS, connexion.recv()).await;
        let duree = debut.elapsed();
        drop(connexion);
        drop(serveur);
        nettoyer(&chemin);
        rendue_dans_le_delai(seconde, duree);
    }

    /// La borne de temps ne remplace pas la borne de taille: une trame de plus
    /// de `MAX_FRAME_BYTES` sans fin de ligne est refusee comme telle, sans
    /// attendre le delai.
    #[tokio::test]
    async fn une_trame_trop_longue_reste_refusee_pour_sa_taille() {
        use tokio::io::AsyncWriteExt;
        let (mut serveur, chemin) = serveur("longue").await;
        // Large: la lecture de la trame ne doit pas l'approcher sous charge.
        serveur.delai_requete = Duration::from_secs(2);
        let mut client = client_brut(&chemin).await;
        let mut connexion = serveur.accept().await.expect("acceptation");
        let ecriture = tokio::spawn(async move {
            let _ = client.write_all(&vec![b'a'; MAX_FRAME_BYTES + 1]).await;
            client
        });
        let debut = Instant::now();
        let issue = tokio::time::timeout(AU_PLUS, connexion.recv()).await;
        let duree = debut.elapsed();
        drop(connexion);
        let _ = ecriture.await;
        drop(serveur);
        nettoyer(&chemin);
        // `FrameTooLarge` et non `RequestTimeout`: la taille a tranche avant
        // le delai.
        assert!(
            matches!(issue, Ok(Err(IpcError::FrameTooLarge))),
            "apres {duree:?}: {issue:?}"
        );
    }

    /// Une requete entamee puis suspendue n'echappe pas a la borne: elle
    /// porte sur la trame complete, pas sur son premier octet.
    #[tokio::test]
    async fn une_requete_entamee_puis_suspendue_est_bornee_aussi() {
        use tokio::io::AsyncWriteExt;
        let (mut serveur, chemin) = serveur("entamee").await;
        serveur.delai_requete = DELAI_COURT;
        let mut client = client_brut(&chemin).await;
        let mut connexion = serveur.accept().await.expect("acceptation");
        client.write_all(b"{\"version\":").await.expect("ecriture");
        let debut = Instant::now();
        let issue = tokio::time::timeout(AU_PLUS, connexion.recv()).await;
        let duree = debut.elapsed();
        drop(connexion);
        drop(serveur);
        nettoyer(&chemin);
        rendue_dans_le_delai(issue, duree);
    }

    /// Une requete ecrite goutte a goutte, un octet a la fois a intervalle
    /// plus court que le delai et sans jamais de fin de ligne, n'echappe pas
    /// davantage: le delai court sur la trame entiere, il ne repart pas a
    /// chaque octet recu.
    #[tokio::test]
    async fn une_requete_ecrite_goutte_a_goutte_est_bornee_au_total() {
        use tokio::io::AsyncWriteExt;
        let (mut serveur, chemin) = serveur("goutte").await;
        serveur.delai_requete = DELAI_COURT;
        let mut client = client_brut(&chemin).await;
        let mut connexion = serveur.accept().await.expect("acceptation");
        // Un octet par tiers de delai: aucun silence n'approche le delai,
        // meme si l'ordonnanceur tarde.
        let goutte = tokio::spawn(async move {
            while client.write_all(b" ").await.is_ok() {
                tokio::time::sleep(DELAI_COURT / 3).await;
            }
        });
        let debut = Instant::now();
        let issue = tokio::time::timeout(AU_PLUS, connexion.recv()).await;
        let duree = debut.elapsed();
        goutte.abort();
        let _ = goutte.await;
        drop(connexion);
        drop(serveur);
        nettoyer(&chemin);
        rendue_dans_le_delai(issue, duree);
    }
}

/// Ce que `accept` fait d'une erreur qui ne touche qu'une connexion, ou d'une
/// ressource qui manque: le serveur continue, ou il rend. Par `bind` (Linux)
/// ou `bind_avec_descripteur` (Windows, descripteur de recette), puis
/// `accept`, tels quels.
///
/// Ce que le systeme ne laisse pas provoquer sans abimer la machine (l'identite
/// illisible d'un pair, une acceptation avortee, la reserve du noyau epuisee)
/// passe par la couture `panne`: une erreur substituee a l'issue d'UNE etape
/// de `accept`, tout le reste du chemin etant celui du daemon. L'epuisement
/// reel des descripteurs, lui, est mesure par le daemon (`serve`), dans un
/// processus enfant.
#[cfg(test)]
mod tests_acceptation {
    use super::*;
    use crate::protocol::Command;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, Instant};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

    /// Au-dela, une acceptation ou une reponse attendue est une recette qui
    /// pend: elle rougit au lieu d'attendre.
    const AU_PLUS: Duration = Duration::from_secs(5);

    /// Duree d'un epuisement simule.
    const EPUISEMENT: Duration = Duration::from_secs(1);

    /// Essais au plus pendant `EPUISEMENT`: un par `PAUSE_EPUISEMENT`, plus
    /// le premier et une marge d'ordonnancement. Une boucle active en fait
    /// des milliers.
    const ESSAIS_AU_PLUS: u64 = 13;

    #[cfg(unix)]
    async fn serveur(nom: &str) -> (IpcServer, String) {
        // SAFETY: geteuid ne prend aucun argument et ne touche aucune memoire.
        let euid = unsafe { libc::geteuid() };
        let policy = AuthPolicy {
            allowed_uids: vec![0, euid],
            allowed_gid: None,
        };
        serveur_sous(nom, policy).await
    }

    /// Le serveur de recette, sous la politique `policy`.
    #[cfg(unix)]
    async fn serveur_sous(nom: &str, policy: AuthPolicy) -> (IpcServer, String) {
        use std::os::unix::fs::PermissionsExt;
        let dossier = std::env::temp_dir().join(format!(
            "bifrost-ipc-acceptation-{}-{nom}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dossier);
        std::fs::create_dir_all(&dossier).expect("repertoire de la recette");
        // Mode pose explicitement: le `umask` que `bind` pose le temps de se
        // lier vaut pour tout le processus (voir tests_clients_concurrents).
        std::fs::set_permissions(&dossier, std::fs::Permissions::from_mode(0o755))
            .expect("repertoire de la recette en 0755");
        let chemin = dossier.join("d.sock");
        let serveur = IpcServer::bind(&chemin, policy, None).await.expect("bind");
        (serveur, chemin.to_string_lossy().into_owned())
    }

    #[cfg(windows)]
    async fn serveur(nom: &str) -> (IpcServer, String) {
        let chemin = format!(
            r"\\.\pipe\bifrost-ipc-acceptation-{}-{nom}",
            std::process::id()
        );
        let serveur = IpcServer::bind_avec_descripteur(
            std::path::Path::new(&chemin),
            AuthPolicy::default(),
            imp::SDDL_RECETTE,
        )
        .expect("serveur de recette");
        (serveur, chemin)
    }

    /// Retire le repertoire de la recette (Linux); sous Windows le pipe
    /// disparait avec sa derniere poignee.
    fn nettoyer(chemin: &str) {
        #[cfg(unix)]
        if let Some(dossier) = std::path::Path::new(chemin).parent() {
            let _ = std::fs::remove_dir_all(dossier);
        }
        #[cfg(windows)]
        let _ = chemin;
    }

    /// Un client brut: il ouvre le canal et n'ecrit que ce que la recette lui
    /// fait ecrire.
    #[cfg(unix)]
    async fn ouvrir(chemin: &str) -> std::io::Result<tokio::net::UnixStream> {
        tokio::net::UnixStream::connect(chemin).await
    }

    #[cfg(windows)]
    async fn ouvrir(
        chemin: &str,
    ) -> std::io::Result<tokio::net::windows::named_pipe::NamedPipeClient> {
        tokio::net::windows::named_pipe::ClientOptions::new().open(chemin)
    }

    /// Le client ecrit une requete complete.
    async fn demander<C: tokio::io::AsyncWrite + Unpin>(client: &mut C) {
        let mut requete = serde_json::to_vec(&Request::new(Command::Status)).expect("requete");
        requete.push(b'\n');
        client
            .write_all(&requete)
            .await
            .expect("ecriture de la requete");
    }

    /// Le client a-t-il recu une reponse dans `AU_PLUS`?
    async fn repondu<C: tokio::io::AsyncRead + Unpin>(client: &mut C) -> bool {
        let mut ligne = String::new();
        tokio::time::timeout(
            AU_PLUS,
            tokio::io::BufReader::new(client).read_line(&mut ligne),
        )
        .await
        .is_ok_and(|n| n.is_ok_and(|n| n > 0))
    }

    /// Le serveur lit la requete d'une connexion acceptee et y repond.
    async fn servir(issue: std::result::Result<Result<Connection>, tokio::time::error::Elapsed>) {
        if let Ok(Ok(mut connexion)) = issue
            && connexion.recv().await.is_ok()
        {
            let _ = connexion.send(&Response::Ok).await;
        }
    }

    /// L'issue d'une acceptation, reduite a ce qui s'imprime.
    fn decrire(
        issue: &std::result::Result<Result<Connection>, tokio::time::error::Elapsed>,
    ) -> String {
        match issue {
            Err(_) => "aucune acceptation dans le delai de la recette".to_owned(),
            Ok(Ok(_)) => "acceptee".to_owned(),
            Ok(Err(IpcError::Io(e))) => format!("erreur {:?}: {e}", e.raw_os_error()),
            Ok(Err(e)) => format!("erreur: {e}"),
        }
    }

    /// Un client qui ouvre le pipe puis le ferme, avant que le serveur ne
    /// l'accepte ou pendant qu'il l'attend (`ConnectNamedPipe` en cours):
    /// ce que `accept` en rend, ce que la lecture de cette connexion rend,
    /// et le client suivant est servi par le meme serveur.
    #[cfg(windows)]
    #[tokio::test]
    async fn un_client_qui_ferme_tot_n_arrete_pas_le_serveur() {
        let (mut serveur, chemin) = serveur("ferme-tot").await;

        // Avant: ouvert puis ferme, `accept` pas encore appele.
        drop(ouvrir(&chemin).await.expect("ouverture"));
        let avant = tokio::time::timeout(AU_PLUS, serveur.accept()).await;
        let mesure_avant = decrire(&avant);
        let lecture_avant = match avant {
            Ok(Ok(mut c)) => format!("{:?}", c.recv().await.map(|_| ())),
            _ => "-".to_owned(),
        };

        // Pendant: `accept` attend deja quand le client ouvre puis ferme.
        let attente = tokio::spawn(async move {
            let issue = tokio::time::timeout(AU_PLUS, serveur.accept()).await;
            (serveur, issue)
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        drop(ouvrir(&chemin).await.expect("ouverture"));
        let (mut serveur, pendant) = attente.await.expect("tache d'acceptation");
        let mesure_pendant = decrire(&pendant);
        let lecture_pendant = match pendant {
            Ok(Ok(mut c)) => format!("{:?}", c.recv().await.map(|_| ())),
            _ => "-".to_owned(),
        };

        // Le suivant: une requete, une reponse.
        let mut client = ouvrir(&chemin).await.expect("ouverture");
        demander(&mut client).await;
        let suivant = tokio::time::timeout(AU_PLUS, serveur.accept()).await;
        let mesure_suivant = decrire(&suivant);
        servir(suivant).await;
        let servi = repondu(&mut client).await;
        println!(
            "mesure client ferme tot: avant={mesure_avant} lecture={lecture_avant}; pendant={mesure_pendant} lecture={lecture_pendant}; suivant={mesure_suivant} servi={servi}"
        );
        assert_eq!(mesure_avant, "acceptee", "avant");
        assert_eq!(mesure_pendant, "acceptee", "pendant");
        assert!(
            servi,
            "le client suivant n'a pas ete servi: {mesure_suivant}"
        );
    }

    /// Unix: une erreur qui ne touche qu'une connexion ne fait pas rendre
    /// `accept`. Trois acceptations en erreur (avortee, erreur de protocole,
    /// interrompue), puis l'identite illisible d'un pair deja accepte: ce
    /// pair-la est ferme sans reponse, et le pair suivant est servi.
    #[cfg(unix)]
    #[tokio::test]
    async fn une_erreur_propre_a_une_connexion_n_arrete_pas_l_acceptation() {
        let (mut serveur, chemin) = serveur("connexion").await;
        let acceptations = Arc::new(AtomicU64::new(0));
        let identites = Arc::new(AtomicU64::new(0));
        let (a, i) = (acceptations.clone(), identites.clone());
        serveur.panne = Some(Box::new(move |etape| {
            let code = match etape {
                imp::Etape::Acceptation => match a.fetch_add(1, Ordering::SeqCst) {
                    0 => libc::ECONNABORTED,
                    1 => libc::EPROTO,
                    2 => libc::EINTR,
                    _ => return None,
                },
                imp::Etape::Identite => match i.fetch_add(1, Ordering::SeqCst) {
                    0 => libc::ENOTCONN,
                    _ => return None,
                },
                imp::Etape::Groupes => return None,
            };
            Some(std::io::Error::from_raw_os_error(code))
        }));
        // Le premier pair, dont l'identite sera illisible, ecrit une requete
        // que personne ne doit lire; le second est servi.
        let mut abandonne = ouvrir(&chemin).await.expect("premier pair");
        demander(&mut abandonne).await;
        let mut suivant = ouvrir(&chemin).await.expect("second pair");
        demander(&mut suivant).await;

        let issue = tokio::time::timeout(AU_PLUS, serveur.accept()).await;
        let mesure = decrire(&issue);
        servir(issue).await;
        let servi = repondu(&mut suivant).await;
        // Une fin de flux, ou ECONNRESET: Linux le pose sur le pair d'un
        // socket ferme avec des donnees non lues (`unix_release_sock`).
        let mut lu = Vec::new();
        let ferme_sans_reponse = tokio::time::timeout(
            AU_PLUS,
            tokio::io::AsyncReadExt::read_to_end(&mut abandonne, &mut lu),
        )
        .await;
        let acceptations = acceptations.load(Ordering::SeqCst);
        let identites = identites.load(Ordering::SeqCst);
        let lignes = serveur.journal.lignes;
        drop(serveur);
        nettoyer(&chemin);
        println!(
            "mesure erreur propre a une connexion: accept={mesure} essais d'acceptation={acceptations} identites lues={identites} servi={servi} abandonne={ferme_sans_reponse:?} octets recus={} lignes={lignes}",
            lu.len()
        );
        assert_eq!(mesure, "acceptee");
        assert_eq!((acceptations, identites), (5, 2));
        assert!(servi, "le pair suivant n'a pas ete servi");
        assert!(
            ferme_sans_reponse.is_ok() && lu.is_empty(),
            "le pair abandonne doit etre ferme sans reponse: {ferme_sans_reponse:?}, {} octets",
            lu.len()
        );
        assert_eq!(lignes, 1, "quatre incidents, une ligne");
    }

    /// La reponse que le client a recue dans `AU_PLUS`, s'il en a recu une.
    #[cfg(unix)]
    async fn reponse_recue<C: tokio::io::AsyncRead + Unpin>(client: &mut C) -> Option<Response> {
        let mut ligne = String::new();
        tokio::time::timeout(
            AU_PLUS,
            tokio::io::BufReader::new(client).read_line(&mut ligne),
        )
        .await
        .ok()?
        .ok()?;
        serde_json::from_str(&ligne).ok()
    }

    /// Les evenements de journal emis sur le fil qui l'a pose par
    /// `tracing::subscriber::set_default`, chacun reduit a son niveau puis a
    /// ses champs: le journal de production filtre par niveau, une ligne
    /// emise sous ce filtre n'existe pas.
    #[cfg(unix)]
    #[derive(Clone, Default)]
    struct Capture(Arc<std::sync::Mutex<Vec<String>>>);

    #[cfg(unix)]
    impl tracing::Subscriber for Capture {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn event(&self, evenement: &tracing::Event<'_>) {
            struct Champs(String);
            impl tracing::field::Visit for Champs {
                fn record_debug(
                    &mut self,
                    champ: &tracing::field::Field,
                    valeur: &dyn std::fmt::Debug,
                ) {
                    self.0.push_str(&format!("{}={valeur:?} ", champ.name()));
                }
            }
            let mut champs = Champs(format!("{} ", evenement.metadata().level()));
            evenement.record(&mut champs);
            self.0.lock().unwrap().push(champs.0);
        }
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
    }

    /// Unix: des groupes supplementaires illisibles ne valent pas "membre
    /// d'aucun groupe".
    ///
    /// Par `bind` puis `accept`, tels quels; seule la lecture de
    /// `/proc/<pid>/status` est substituee (`Etape::Groupes`), par `EMFILE`,
    /// ce que rend un daemon a court de descripteurs. Le pair est la recette
    /// elle-meme, dont le gid primaire n'est pas celui de la politique: seul
    /// un groupe supplementaire pourrait l'admettre. Sous root, l'uid
    /// l'admet quels que soient ses groupes, et la recette le verifie aussi.
    /// Puis la politique nomme le gid primaire de la recette: le pair est
    /// admis sans que ses groupes supplementaires aient a etre connus.
    #[cfg(unix)]
    #[tokio::test]
    async fn des_groupes_illisibles_ne_se_confondent_pas_avec_aucun_groupe() {
        // SAFETY: geteuid et getegid ne prennent aucun argument et ne
        // touchent aucune memoire.
        let (euid, egid) = unsafe { (libc::geteuid(), libc::getegid()) };
        let capture = Capture::default();
        let _journal = tracing::subscriber::set_default(capture.clone());
        let lectures = Arc::new(AtomicU64::new(0));
        let illisibles = |serveur: &mut IpcServer| {
            let l = lectures.clone();
            serveur.panne = Some(Box::new(move |etape| {
                (etape == imp::Etape::Groupes).then(|| {
                    l.fetch_add(1, Ordering::SeqCst);
                    std::io::Error::from_raw_os_error(libc::EMFILE)
                })
            }));
        };

        // Seul un groupe supplementaire pourrait admettre ce pair.
        let politique = AuthPolicy {
            allowed_uids: vec![0],
            allowed_gid: Some(egid.wrapping_add(1)),
        };
        let (mut serveur, chemin) = serveur_sous("groupes-illisibles", politique).await;
        illisibles(&mut serveur);
        let mut client = ouvrir(&chemin).await.expect("client");
        demander(&mut client).await;
        let issue = tokio::time::timeout(Duration::from_millis(500), serveur.accept()).await;
        let mesure = decrire(&issue);
        drop(issue);
        let reponse = reponse_recue(&mut client).await;
        drop(serveur);
        nettoyer(&chemin);
        let lues = lectures.swap(0, Ordering::SeqCst);

        // Le gid primaire du pair suffit, ses groupes restant illisibles.
        let politique = AuthPolicy {
            allowed_uids: vec![0],
            allowed_gid: Some(egid),
        };
        let (mut serveur, chemin) = serveur_sous("groupe-primaire", politique).await;
        illisibles(&mut serveur);
        let mut client = ouvrir(&chemin).await.expect("client");
        demander(&mut client).await;
        let issue = tokio::time::timeout(AU_PLUS, serveur.accept()).await;
        let primaire = decrire(&issue);
        drop(issue);
        drop(client);
        drop(serveur);
        nettoyer(&chemin);

        let journal = capture.0.lock().unwrap().clone();
        let refus: Vec<&String> = journal
            .iter()
            .filter(|l| l.contains("connexion refusee"))
            .collect();
        println!(
            "mesure groupes illisibles: euid={euid} accept={mesure} lectures de groupes={lues} reponse={reponse:?} journal={refus:?}; gid primaire: accept={primaire}"
        );
        assert!(
            lues >= 1,
            "la couture n'a pas ete consultee: rien n'est mesure"
        );
        assert_eq!(primaire, "acceptee", "le gid primaire suffit");
        if euid == 0 {
            assert_eq!(
                mesure, "acceptee",
                "root est admis quels que soient ses groupes"
            );
            return;
        }
        assert_eq!(
            mesure, "aucune acceptation dans le delai de la recette",
            "le pair doit etre refuse"
        );
        let message = match reponse {
            Some(Response::Error { message }) => message,
            autre => panic!("refus attendu, recu {autre:?}"),
        };
        assert!(message.starts_with("acces refuse"), "{message}");
        assert!(
            message.contains("groupes supplementaires illisibles"),
            "le refus doit nommer la cause: {message}"
        );
        assert!(
            !message.contains("ni membre"),
            "un groupe illisible n'est pas une absence de groupe: {message}"
        );
        assert_eq!(refus.len(), 1, "une ligne de refus: {journal:?}");
        assert!(
            refus[0].contains("groupes supplementaires illisibles"),
            "le journal doit nommer la cause: {}",
            refus[0]
        );
        // Le daemon journalise `bifrost_ipc` au niveau info par defaut: un
        // refus emis plus bas n'y figurerait pas.
        assert!(
            refus[0].starts_with("WARN "),
            "le refus doit etre un avertissement: {}",
            refus[0]
        );
    }

    /// Un epuisement de ressource ne fait pas rendre `accept`: il attend,
    /// sans boucle active, puis reprend, et le client qui patientait est
    /// servi. Unix: `accept(2)` rend `EMFILE` pendant `EPUISEMENT`, la
    /// connexion restant dans la file d'ecoute comme sous Linux. Windows: la
    /// creation de l'instance suivante rend `ERROR_NO_SYSTEM_RESOURCES`,
    /// le client etant deja connecte; a chaque essai un tiers tente de creer
    /// le nom du pipe, ce qu'il ne doit jamais pouvoir faire.
    #[tokio::test]
    async fn un_epuisement_attend_sans_boucle_active_puis_reprend() {
        let (mut serveur, chemin) = serveur("epuisement").await;
        let essais = Arc::new(AtomicU64::new(0));
        let tiers = Arc::new(AtomicU64::new(0));
        let (e, t) = (essais.clone(), tiers.clone());
        #[cfg(windows)]
        let nom = chemin.clone();
        let mut fin: Option<Instant> = None;
        serveur.panne = Some(Box::new(move |etape| {
            #[cfg(unix)]
            let (pertinente, code) = (etape == imp::Etape::Acceptation, libc::EMFILE);
            #[cfg(windows)]
            let (pertinente, code) = {
                // Un tiers qui voudrait le nom: il y parvient s'il est libre.
                if tokio::net::windows::named_pipe::ServerOptions::new()
                    .first_pipe_instance(true)
                    .create(&nom)
                    .is_ok()
                {
                    t.fetch_add(1, Ordering::SeqCst);
                }
                (
                    etape == imp::Etape::InstanceSuivante,
                    windows_sys::Win32::Foundation::ERROR_NO_SYSTEM_RESOURCES as i32,
                )
            };
            let fin = *fin.get_or_insert_with(|| Instant::now() + EPUISEMENT);
            if !pertinente || Instant::now() >= fin {
                return None;
            }
            e.fetch_add(1, Ordering::SeqCst);
            Some(std::io::Error::from_raw_os_error(code))
        }));
        #[cfg(unix)]
        let _ = &t;

        let mut client = ouvrir(&chemin).await.expect("client");
        demander(&mut client).await;
        let debut = Instant::now();
        let issue = tokio::time::timeout(AU_PLUS, serveur.accept()).await;
        let duree = debut.elapsed();
        let mesure = decrire(&issue);
        servir(issue).await;
        let servi = repondu(&mut client).await;
        drop(client);

        // Le premier client parti, le serveur attend le suivant, qui vient
        // ensuite. Windows: le tiers n'a pas davantage le nom a cet instant,
        // ou plus aucune connexion ne le tient.
        let attente = tokio::spawn(async move {
            let issue = tokio::time::timeout(AU_PLUS, serveur.accept()).await;
            servir(issue).await;
            serveur
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        let second = match ouvrir(&chemin).await {
            Ok(mut second) => {
                demander(&mut second).await;
                repondu(&mut second).await
            }
            Err(e) => {
                println!("second client: {e}");
                false
            }
        };
        let serveur = attente.await.expect("tache d'acceptation");

        let essais = essais.load(Ordering::SeqCst);
        let tiers = tiers.load(Ordering::SeqCst);
        let lignes = serveur.journal.lignes;
        drop(serveur);
        nettoyer(&chemin);
        println!(
            "mesure epuisement simule: accept={mesure} apres {duree:?}, essais={essais}, lignes={lignes}, nom pris par un tiers={tiers}, servi={servi}, second servi={second}"
        );
        assert_eq!(mesure, "acceptee");
        assert_eq!(tiers, 0, "un tiers a pu creer le nom du pipe");
        assert!(
            (2..=ESSAIS_AU_PLUS).contains(&essais),
            "{essais} essais en {EPUISEMENT:?}: attente active, ou aucune attente"
        );
        assert!(
            duree >= EPUISEMENT * 9 / 10 && duree < EPUISEMENT + PAUSE_EPUISEMENT * 5,
            "reprise hors de sa borne: {duree:?}"
        );
        assert_eq!(lignes, 1, "un episode, une ligne");
        assert!(servi && second, "client servi: {servi}, second: {second}");
    }

    /// Une erreur de l'ecoute elle-meme reste fatale: `accept` la rend
    /// aussitot, sans pause ni nouvel essai.
    #[tokio::test]
    async fn une_erreur_de_l_ecoute_reste_fatale() {
        #[cfg(unix)]
        let codes = [libc::EBADF, libc::EINVAL, libc::EPERM];
        #[cfg(windows)]
        let codes = [
            windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED as i32,
            windows_sys::Win32::Foundation::ERROR_INVALID_PARAMETER as i32,
        ];
        for code in codes {
            let (mut serveur, chemin) = serveur(&format!("fatale-{code}")).await;
            serveur.panne = Some(Box::new(move |_| {
                Some(std::io::Error::from_raw_os_error(code))
            }));
            // Windows: l'erreur vient a la creation de l'instance suivante,
            // donc apres la connexion d'un client.
            let _client = ouvrir(&chemin).await.expect("client");
            let issue = tokio::time::timeout(Duration::from_secs(1), serveur.accept()).await;
            let mesure = decrire(&issue);
            drop(serveur);
            nettoyer(&chemin);
            assert_eq!(
                mesure,
                decrire(&Ok(Err(IpcError::Io(std::io::Error::from_raw_os_error(
                    code
                ))))),
                "{code}"
            );
        }
    }

    /// Unix: la nature de chaque erreur d'acceptation, nommee.
    #[cfg(unix)]
    #[test]
    fn chaque_erreur_d_acceptation_a_sa_nature() {
        use imp::Nature::{Connexion, Epuisement, Fatale};
        for (code, attendue) in [
            (libc::EMFILE, Epuisement),
            (libc::ENFILE, Epuisement),
            (libc::ENOMEM, Epuisement),
            (libc::ENOBUFS, Epuisement),
            (libc::ENOSPC, Epuisement),
            (libc::ECONNABORTED, Connexion),
            (libc::EPROTO, Connexion),
            (libc::EINTR, Connexion),
            (libc::EBADF, Fatale),
            (libc::EINVAL, Fatale),
            (libc::ENOTSOCK, Fatale),
            (libc::EOPNOTSUPP, Fatale),
            (libc::EPERM, Fatale),
            (libc::EACCES, Fatale),
        ] {
            assert_eq!(
                imp::nature(&std::io::Error::from_raw_os_error(code)),
                attendue,
                "errno {code}"
            );
        }
        assert_eq!(imp::nature(&std::io::Error::other("sans code")), Fatale);
    }

    /// Windows: les erreurs de creation d'instance qui disent un epuisement,
    /// nommees, et des voisines qui n'en sont pas.
    #[cfg(windows)]
    #[test]
    fn chaque_erreur_de_creation_a_sa_nature() {
        use windows_sys::Win32::Foundation::{
            ERROR_ACCESS_DENIED, ERROR_BROKEN_PIPE, ERROR_COMMITMENT_LIMIT, ERROR_FILE_NOT_FOUND,
            ERROR_NO_DATA, ERROR_NO_SYSTEM_RESOURCES, ERROR_NOT_ENOUGH_MEMORY,
            ERROR_NOT_ENOUGH_QUOTA, ERROR_OUTOFMEMORY, ERROR_PIPE_BUSY,
        };
        for (code, attendue) in [
            (ERROR_NOT_ENOUGH_MEMORY, true),
            (ERROR_OUTOFMEMORY, true),
            (ERROR_NO_SYSTEM_RESOURCES, true),
            (ERROR_COMMITMENT_LIMIT, true),
            (ERROR_NOT_ENOUGH_QUOTA, true),
            (ERROR_ACCESS_DENIED, false),
            (ERROR_PIPE_BUSY, false),
            (ERROR_NO_DATA, false),
            (ERROR_BROKEN_PIPE, false),
            (ERROR_FILE_NOT_FOUND, false),
        ] {
            assert_eq!(
                imp::est_un_epuisement(&std::io::Error::from_raw_os_error(code as i32)),
                attendue,
                "{code}"
            );
        }
        assert!(!imp::est_un_epuisement(&std::io::Error::other("sans code")));
    }
}

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

/// Ce que `IpcError::is_server_busy` dit d'une erreur: le canal occupe, et rien
/// d'autre. L'erreur reelle d'un canal occupe, par `connect_verified`, est
/// mesuree par les recettes de la CLI qui en dependent.
#[cfg(test)]
mod tests_classement {
    use super::*;

    #[test]
    fn seul_un_canal_sans_place_est_dit_occupe() {
        #[cfg(unix)]
        let (occupe, autres) = (
            libc::EAGAIN,
            [
                libc::ENOENT,
                libc::ECONNREFUSED,
                libc::EACCES,
                libc::ENOTSOCK,
            ],
        );
        #[cfg(windows)]
        let (occupe, autres) = {
            use windows_sys::Win32::Foundation::{
                ERROR_ACCESS_DENIED, ERROR_BAD_PIPE, ERROR_FILE_NOT_FOUND, ERROR_PIPE_BUSY,
                ERROR_PIPE_NOT_CONNECTED,
            };
            (
                ERROR_PIPE_BUSY as i32,
                [
                    ERROR_FILE_NOT_FOUND as i32,
                    ERROR_ACCESS_DENIED as i32,
                    ERROR_BAD_PIPE as i32,
                    ERROR_PIPE_NOT_CONNECTED as i32,
                ],
            )
        };
        assert!(IpcError::Io(std::io::Error::from_raw_os_error(occupe)).is_server_busy());
        for code in autres {
            assert!(
                !IpcError::Io(std::io::Error::from_raw_os_error(code)).is_server_busy(),
                "{code}"
            );
        }
        for autre in [
            IpcError::Io(std::io::Error::other("sans code")),
            IpcError::Closed,
            IpcError::RequestTimeout,
            IpcError::FrameTooLarge,
            IpcError::ServerIdentity(ServerIdentityError::Refused),
        ] {
            assert!(!autre.is_server_busy(), "{autre}");
        }
    }
}
