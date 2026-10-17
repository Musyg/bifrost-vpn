//! Le poste de commande: il parle au daemon par l'IPC, il ne modifie rien
//! lui-meme.
//!
//! Il n'expose que ce dont la coquille a besoin, et rien de plus: l'etat,
//! monter le tunnel a partir du profil que le DAEMON detient (`ConnectStored`,
//! jamais une cle lue par la coquille), et le demonter. `Connect` avec un
//! profil fourni par l'appelant, `Check` et le reste ne sont pas ici: la
//! coquille n'a aucune raison de les offrir, et une surface qu'on n'ouvre pas
//! est une surface qu'on n'a pas a defendre. Ce sont aussi les trois
//! commandes que le daemon ouvre, sous Windows, aux membres du groupe d'acces
//! (`bifrost_ipc::appelant`): un membre a tout ce que la coquille offre.
//!
//! # Le serveur du canal, verifie avant le premier octet
//!
//! Le canal ne s'ouvre que par `IpcClient::connect_verified`, avec l'exigence
//! des commandes de la CLI, [`ServerRequirement::Elevated`]: sous Linux un
//! serveur root, sous Windows un pipe possede par LocalSystem ou par les
//! Administrateurs. Ce qu'un compte ordinaire ne peut pas servir. Un processus
//! qui tiendrait le canal sans cette identite ne recoit rien, pas meme la
//! commande, et la coquille le dit ([`ErreurCommande::ServeurNonAdmis`]) au
//! lieu de lui faire confiance ou de le prendre pour un daemon absent.

use bifrost_core::state::TunnelStatus;
use bifrost_ipc::protocol::{Command, Request, Response};
use bifrost_ipc::transport::{
    IpcClient, IpcError, ServerIdentityError, ServerRequirement, default_endpoint,
};

/// L'exigence envers le serveur du canal, celle des commandes de la CLI. Le
/// seul constructeur public du poste de commande la pose, et rien ne la
/// remplace hors des recettes de ce module.
const EXIGENCE: ServerRequirement = ServerRequirement::Elevated;

/// L'erreur du poste de commande, typee: la coquille en tire une Vue distincte
/// pour chaque cas.
///
/// A l'ouverture du canal, quatre cas qui ne se confondent pas: personne ne
/// tient le canal ([`ErreurCommande::DaemonInjoignable`], l'etat NORMAL quand
/// la coquille tourne et que le service n'est pas la); le canal existe et le
/// systeme refuse a ce compte de l'ouvrir
/// ([`ErreurCommande::CompteNonAdmis`]: sous Windows un compte hors du groupe
/// d'acces du pipe, ou un pipe de ce nom tenu par un autre processus dont la
/// DACL refuse ce compte, sans rien pour les distinguer; sous Linux un compte
/// hors du groupe du socket); un
/// serveur tient le canal et n'a pris aucune connexion de plus dans le delai
/// du client
/// ([`ErreurCommande::DaemonSansReponse`]: rien ne dit qu'il soit arrete); un
/// serveur tient le canal et n'a pas l'identite du daemon
/// ([`ErreurCommande::ServeurNonAdmis`]: rien ne lui a ete envoye).
///
/// Une fois le serveur admis, `Response::Error { message }` du daemon devient
/// soit [`ErreurCommande::Refuse`] (l'IPC a refuse l'appelant), soit
/// [`ErreurCommande::Autre`]; une connexion coupee pendant l'echange reste
/// [`ErreurCommande::DaemonInjoignable`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ErreurCommande {
    #[error("daemon injoignable: {0}")]
    DaemonInjoignable(String),
    #[error("compte non admis par le canal: {0}")]
    CompteNonAdmis(String),
    #[error("daemon sans reponse dans le delai: {0}")]
    DaemonSansReponse(String),
    #[error("serveur du canal non admis, rien ne lui a ete envoye: {0}")]
    ServeurNonAdmis(ServerIdentityError),
    #[error("acces refuse par le daemon: {0}")]
    Refuse(String),
    #[error("erreur du daemon: {0}")]
    Autre(String),
}

/// Classe un `Response::Error { message }` du daemon.
///
/// Le seul discriminant disponible est le texte, car le protocole ne porte pas
/// de code. Le message de refus de l'IPC contient << refuse >> (voir
/// `bifrost_ipc::auth::AuthError::Denied`); tout le reste est une erreur
/// applicative que la coquille montre telle quelle.
fn classer(message: String) -> ErreurCommande {
    if message.to_lowercase().contains("refus") {
        ErreurCommande::Refuse(message)
    } else {
        ErreurCommande::Autre(message)
    }
}

/// Classe une erreur de `IpcClient::connect_verified`, la seule ou
/// `is_server_busy` ait un sens.
///
/// L'identite du serveur passe avant tout: c'est le seul cas ou un serveur a
/// ete joint et ecarte. Puis le refus d'ouverture pour droits insuffisants
/// (`ERROR_ACCESS_DENIED` sous Windows, `EACCES` sous Linux, tous deux
/// `PermissionDenied`): le canal existe, et refuse ce compte. Sous Linux le
/// repertoire du socket par defaut appartient a root: c'est le daemon qui
/// n'admet pas ce compte. Sous Windows le nom du pipe est libre quand le
/// service est arrete, et un autre processus peut le tenir avec une DACL qui
/// refuse ce compte: l'ouverture echoue avant toute verification d'identite,
/// et sans poignee ni le proprietaire ni le serveur ne se lisent. La Vue dit
/// alors les deux cas. Puis l'occupation, ou un serveur tient le canal sans
/// prendre de connexion de plus. Le reste (canal absent, erreur du systeme)
/// dit qu'aucun daemon n'a pu etre joint.
fn classer_ouverture(e: IpcError) -> ErreurCommande {
    match e {
        IpcError::ServerIdentity(cause) => ErreurCommande::ServeurNonAdmis(cause),
        IpcError::Io(io) if io.kind() == std::io::ErrorKind::PermissionDenied => {
            ErreurCommande::CompteNonAdmis(io.to_string())
        }
        e if e.is_server_busy() => ErreurCommande::DaemonSansReponse(e.to_string()),
        e => ErreurCommande::DaemonInjoignable(e.to_string()),
    }
}

/// Parle au daemon. Clonable et sans etat autre que l'adresse du canal et
/// l'exigence envers son serveur: chaque appel ouvre une connexion neuve, la
/// ferme, et rend la main. Une coquille qui interroge l'etat toutes les deux
/// secondes n'a pas besoin de tenir un canal ouvert. Le daemon sert chaque
/// connexion dans sa propre tache, mais il coupe celle qui ne lui transmet
/// aucune requete complete dans son delai; et tant qu'elle est ouverte, elle
/// lui tient une tache et, sous Windows, une instance du pipe.
#[derive(Debug, Clone)]
pub struct Commande {
    endpoint: String,
    exigence: ServerRequirement,
}

impl Default for Commande {
    fn default() -> Self {
        Self::new(default_endpoint())
    }
}

impl Commande {
    /// Vise le canal donne, et n'en admet le serveur que sous `EXIGENCE`.
    /// `Commande::default()` vise [`default_endpoint`].
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            exigence: EXIGENCE,
        }
    }

    /// La couture des recettes: un poste de commande qui admet un serveur de
    /// cet uid effectif, pour servir un faux daemon sous le compte de la
    /// recette. Elle n'existe que dans le binaire des recettes de ce crate:
    /// aucun autre code ne peut l'appeler, et le chemin de production n'a qu'un
    /// constructeur, [`Commande::new`].
    #[cfg(all(test, unix))]
    fn admettant_l_uid(endpoint: impl Into<String>, uid: u32) -> Self {
        Self {
            endpoint: endpoint.into(),
            exigence: ServerRequirement::Uid(uid),
        }
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Ouvre une connexion, exige l'identite du serveur, envoie une requete,
    /// rend la reponse brute.
    ///
    /// Le seul site d'ouverture du canal. L'identite du serveur est etablie
    /// avant que la requete ne soit ecrite; un echec d'ouverture est classe
    /// par [`classer_ouverture`]. Une erreur de transport pendant l'echange
    /// devient [`ErreurCommande::DaemonInjoignable`]: du point de vue de la
    /// coquille, un canal qui se ferme au milieu d'un echange est aussi
    /// injoignable qu'un canal absent, et le seul geste utile est de
    /// reessayer plus tard.
    async fn echanger(&self, command: Command) -> Result<Response, ErreurCommande> {
        let (mut client, _regle) = IpcClient::connect_verified(&self.endpoint, self.exigence)
            .await
            .map_err(classer_ouverture)?;
        client
            .request(&Request::new(command))
            .await
            .map_err(|e| ErreurCommande::DaemonInjoignable(e.to_string()))
    }

    /// L'etat courant du tunnel et du kill switch.
    pub async fn etat(&self) -> Result<TunnelStatus, ErreurCommande> {
        match self.echanger(Command::Status).await? {
            Response::Status(status) => Ok(*status),
            Response::Error { message } => Err(classer(message)),
            autre => Err(ErreurCommande::Autre(format!(
                "reponse inattendue a status: {autre:?}"
            ))),
        }
    }

    /// Monte le tunnel a partir du profil que le DAEMON detient.
    ///
    /// `ConnectStored` et non `Connect`: la coquille ne lit jamais une cle. Le
    /// daemon ouvre son propre profil, qui peut etre scelle et exiger le TPM
    /// donc root. La coquille, non privilegiee, gagne le droit de connecter
    /// sans gagner celui de lire le secret.
    pub async fn connecter(&self) -> Result<(), ErreurCommande> {
        match self.echanger(Command::ConnectStored).await? {
            Response::Ok => Ok(()),
            Response::Error { message } => Err(classer(message)),
            autre => Err(ErreurCommande::Autre(format!(
                "reponse inattendue a connect-stored: {autre:?}"
            ))),
        }
    }

    /// Demonte le tunnel et desarme le kill switch.
    pub async fn deconnecter(&self) -> Result<(), ErreurCommande> {
        match self.echanger(Command::Disconnect).await? {
            Response::Ok => Ok(()),
            Response::Error { message } => Err(classer(message)),
            autre => Err(ErreurCommande::Autre(format!(
                "reponse inattendue a disconnect: {autre:?}"
            ))),
        }
    }
}

// Le faux daemon des recettes, partage avec `tests/eleve_ipc.rs`.
#[cfg(all(test, unix))]
#[path = "../tests/commun/faux_daemon.rs"]
mod faux_daemon;

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use bifrost_ipc::{AuthPolicy, IpcServer};

    /// L'erreur que le systeme rend au client d'un canal qui existe et ne
    /// prend aucune connexion de plus: `EAGAIN` au `connect(2)` sous Linux,
    /// `ERROR_PIPE_BUSY` a l'ouverture sous Windows.
    #[cfg(unix)]
    const CANAL_OCCUPE: i32 = libc::EAGAIN;
    #[cfg(windows)]
    const CANAL_OCCUPE: i32 = windows_sys::Win32::Foundation::ERROR_PIPE_BUSY as i32;

    /// L'erreur que le systeme rend au client d'un canal qui existe et que
    /// ses droits ferment a ce compte: `EACCES` au `connect(2)` sous Linux,
    /// `ERROR_ACCESS_DENIED` a l'ouverture sous Windows.
    #[cfg(unix)]
    const ACCES_REFUSE: i32 = libc::EACCES;
    #[cfg(windows)]
    const ACCES_REFUSE: i32 = windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED as i32;

    #[test]
    fn la_commande_par_defaut_vise_le_canal_par_defaut() {
        assert_eq!(Commande::default().endpoint(), default_endpoint());
    }

    /// Le chemin de production exige `Elevated`, au caractere pres: la
    /// constante, et ce que posent le constructeur public et `Default`.
    #[test]
    fn le_chemin_de_production_exige_elevated() {
        assert_eq!(EXIGENCE, ServerRequirement::Elevated);
        assert_eq!(Commande::new("canal").exigence, ServerRequirement::Elevated);
        assert_eq!(Commande::default().exigence, ServerRequirement::Elevated);
    }

    /// La coquille n'envoie au daemon que `status`, `connect-stored` et
    /// `disconnect`, les trois commandes que le daemon ouvre, sous Windows,
    /// aux membres du groupe d'acces: le texte de production de ce module ne
    /// nomme aucune autre variante de `Command`, la page graphique
    /// (`gui/src/main.rs`) n'en nomme aucune, et la decision du daemon admet
    /// chacune des trois au niveau restreint.
    #[test]
    fn la_coquille_n_envoie_que_les_trois_commandes_ouvertes_aux_membres() {
        use bifrost_ipc::{NiveauDAppelant, decider};
        let source = include_str!("commande.rs");
        let production = &source[..source.find("\nmod tests {").expect("module des recettes")];
        let nommees: std::collections::BTreeSet<String> = production
            .match_indices("Command::")
            .map(|(rang, motif)| {
                production[rang + motif.len()..]
                    .chars()
                    .take_while(char::is_ascii_alphanumeric)
                    .collect()
            })
            .collect();
        let attendues: std::collections::BTreeSet<String> =
            ["ConnectStored", "Disconnect", "Status"]
                .map(String::from)
                .into_iter()
                .collect();
        assert_eq!(
            nommees, attendues,
            "commandes nommees par le poste de commande"
        );
        let page = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../gui/src/main.rs"
        ))
        .expect("gui/src/main.rs");
        assert!(
            !page.contains("Command::"),
            "la page graphique construit elle-meme une commande"
        );
        for commande in [Command::Status, Command::ConnectStored, Command::Disconnect] {
            assert_eq!(
                decider(NiveauDAppelant::Restreint, &commande),
                Ok(()),
                "{}",
                commande.name()
            );
        }
    }

    #[test]
    fn un_refus_du_daemon_devient_refuse_et_pas_autre() {
        // Le message de l'IPC quand il refuse un pair non autorise.
        let e = classer("acces refuse pour uid=1000: ni root, ni dans les uid autorises".into());
        assert!(matches!(e, ErreurCommande::Refuse(_)));
    }

    #[test]
    fn une_erreur_applicative_devient_autre_et_pas_refuse() {
        let e = classer("configuration invalide: endpoint manquant".into());
        assert!(matches!(e, ErreurCommande::Autre(_)));
    }

    /// Chaque echec d'ouverture du canal dans sa classe, et dans aucune
    /// autre: le serveur ecarte, quelle que soit la cause, n'est jamais pris
    /// pour un daemon absent; le compte que le canal refuse non plus, ni le
    /// canal occupe; le reste, si.
    #[test]
    fn chaque_echec_d_ouverture_a_sa_classe() {
        for cause in [
            ServerIdentityError::Refused,
            ServerIdentityError::Unreadable,
        ] {
            assert_eq!(
                classer_ouverture(IpcError::ServerIdentity(cause)),
                ErreurCommande::ServeurNonAdmis(cause)
            );
        }

        let occupe = IpcError::Io(std::io::Error::from_raw_os_error(CANAL_OCCUPE));
        assert!(
            occupe.is_server_busy(),
            "l'erreur de la recette doit etre celle d'un canal occupe: {occupe}"
        );
        let classe = classer_ouverture(occupe);
        assert!(
            matches!(classe, ErreurCommande::DaemonSansReponse(_)),
            "{classe:?}"
        );

        // Le refus du systeme a l'ouverture, sous la forme ou il arrive:
        // le code de la plateforme, et le genre seul.
        for refus in [
            std::io::Error::from_raw_os_error(ACCES_REFUSE),
            std::io::Error::from(std::io::ErrorKind::PermissionDenied),
        ] {
            let classe = classer_ouverture(IpcError::Io(refus));
            assert!(
                matches!(classe, ErreurCommande::CompteNonAdmis(_)),
                "{classe:?}"
            );
            assert!(!classe.to_string().contains("injoignable"), "{classe}");
        }

        for genre in [
            std::io::ErrorKind::NotFound,
            std::io::ErrorKind::ConnectionRefused,
        ] {
            let e = IpcError::Io(std::io::Error::from(genre));
            assert!(!e.is_server_busy(), "{genre:?}");
            let classe = classer_ouverture(e);
            assert!(
                matches!(classe, ErreurCommande::DaemonInjoignable(_)),
                "{genre:?}: {classe:?}"
            );
        }
    }

    /// La couture et le chemin de production face au MEME faux daemon: un
    /// vrai `IpcServer`, lie sous le compte de la recette, qui admet son uid
    /// effectif. Admis par la couture, il sert `status`, `connect-stored` et
    /// `disconnect`; le chemin de production, lui, le refuse sauf si la
    /// recette tourne en root, ou il est admis comme le daemon.
    #[cfg(unix)]
    #[tokio::test]
    async fn la_couture_admet_le_compte_de_la_recette_et_le_chemin_de_production_non() {
        // SAFETY: geteuid ne prend aucun argument, ne touche aucune memoire et
        // ne peut pas echouer.
        let euid = unsafe { libc::geteuid() };
        let path = std::env::temp_dir().join(format!(
            "bifrost-coquille-{}-couture.sock",
            std::process::id()
        ));
        let policy = AuthPolicy {
            allowed_uids: vec![0, euid],
            allowed_gid: None,
        };
        let server = IpcServer::bind(
            &path,
            policy,
            None,
            bifrost_ipc::ProprietaireDuPipe::ParDefaut,
        )
        .await
        .expect("bind");
        let tache = tokio::spawn(faux_daemon::servir(server, Default::default()));

        let couture = Commande::admettant_l_uid(path.to_string_lossy(), euid);
        assert_eq!(couture.etat().await, Ok(faux_daemon::status_de_reference()));
        couture.connecter().await.expect("connect-stored");
        couture.deconnecter().await.expect("disconnect");

        let production = Commande::new(path.to_string_lossy());
        let issue = production.etat().await;
        if euid == 0 {
            assert_eq!(issue, Ok(faux_daemon::status_de_reference()));
        } else {
            assert_eq!(
                issue,
                Err(ErreurCommande::ServeurNonAdmis(
                    ServerIdentityError::Refused
                ))
            );
        }

        tache.abort();
        let _ = std::fs::remove_file(&path);
    }
}
