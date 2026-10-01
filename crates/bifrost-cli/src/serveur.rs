//! Le serveur du socket, verifie AVANT le premier octet.
//!
//! Toute commande qui parle au daemon passe par ce module, et il n'y a pas
//! d'autre chemin: `bifrost_ipc` n'offre plus de client qui ecrive avant
//! d'avoir etabli l'identite du serveur. `prove nft --politique-daemon` garde
//! sa regle et son rapport (`preuve_nft_daemon`); ici, celle des commandes.
//!
//! # Ce qui partait, et vers qui
//!
//! Mesure du 30/09/2026 sur le client de `5baf9f3`, face a un faux serveur du
//! compte courant, non eleve: `connect --config` y ecrit 506 octets, dont la
//! cle privee du profil; `connect`, `disconnect`, `status` et `check` leur
//! commande; `inspection-tls --annoncer` son verdict. La sonde
//! d'`emergency-disarm` n'ecrit rien, mais annoncait "un daemon repond encore".
//! Sous Windows le nom par defaut du pipe est libre quand le service est
//! arrete: un compte non eleve l'a pris, et le profil lui est arrive sans
//! `--socket`.
//!
//! # La regle
//!
//! [`ServerRequirement::Elevated`]: sous Linux un serveur root, sous Windows
//! un pipe possede par LocalSystem ou par les Administrateurs. Ce qu'un compte
//! non privilegie ne peut jamais servir, et ce que le daemon exige de lui-meme
//! pour demarrer. `bifrost_ipc::ServerRequirement` dit pourquoi la preuve en
//! a une plus stricte.
//!
//! # Le refus
//!
//! Un message qui nomme le socket et la regle, jamais un uid, un pid ou un
//! SID, et le code de sortie [`CODE_SERVEUR_REFUSE`]. Aucun repli vers une
//! connexion non verifiee, aucune option pour s'en passer.

use anyhow::Context;
use bifrost_ipc::protocol::{Command, Request, Response};
use bifrost_ipc::{IpcClient, IpcError, ServerIdentityError, ServerRequirement};

/// Le code de sortie d'une commande qui a refuse le serveur de son socket.
///
/// Distinct de tous ceux que le client rend deja: `0` succes, `1` echec,
/// ecart ou interception, `2` non mesure ou invocation refusee (et erreur
/// d'usage de clap), `3` inspection non concluante; le hook de reprise ajoute
/// `124`, le depassement de `timeout`. Un script distingue ainsi "quelqu'un
/// d'autre tient le canal" de "le daemon est absent".
pub(crate) const CODE_SERVEUR_REFUSE: i32 = 4;

/// L'exigence des commandes. Une constante et non un parametre: il n'y a pas
/// de commande qui puisse s'en passer.
const EXIGENCE: ServerRequirement = ServerRequirement::Elevated;

#[cfg(unix)]
const REGLE: &str = "Seul un serveur root est admis: un processus d'un compte ordinaire \
                     qui tient ce canal n'est pas le daemon.";
#[cfg(windows)]
const REGLE: &str = "Seul un pipe possede par LocalSystem ou par les Administrateurs est \
                     admis: un processus d'un compte ordinaire qui tient ce canal n'est pas \
                     le daemon.";

/// Le serveur du socket n'a pas l'identite exigee: rien ne lui a ete envoye.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ServeurRefuse {
    socket: String,
    cause: ServerIdentityError,
}

impl std::fmt::Display for ServeurRefuse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let constat = match self.cause {
            ServerIdentityError::Refused => "n'a pas l'identite attendue du daemon",
            ServerIdentityError::Unreadable => "n'a pas pu etre identifie",
        };
        write!(
            f,
            "REFUS: le serveur de {} {constat}. Rien ne lui a ete envoye.\n{REGLE}",
            self.socket
        )
    }
}

impl std::error::Error for ServeurRefuse {}

/// Pourquoi le canal n'a pas ete ouvert.
#[derive(Debug)]
pub(crate) enum Echec {
    /// Le serveur a ete joint, et son identite n'est pas admise.
    Refuse(ServeurRefuse),
    /// Le canal n'a pas pu etre ouvert: absent, droits, occupe.
    Canal(IpcError),
}

/// Ouvre le canal, apres avoir etabli l'identite du serveur.
pub(crate) async fn joindre(socket: &str) -> Result<IpcClient, Echec> {
    match IpcClient::connect_verified(socket, EXIGENCE).await {
        Ok((client, _regle)) => Ok(client),
        Err(IpcError::ServerIdentity(cause)) => Err(Echec::Refuse(ServeurRefuse {
            socket: socket.to_owned(),
            cause,
        })),
        Err(e) => Err(Echec::Canal(e)),
    }
}

/// [`joindre`], pour le chemin commun: un refus reste un [`ServeurRefuse`],
/// que `main` reconnait et rend en [`CODE_SERVEUR_REFUSE`].
pub(crate) async fn ouvrir(socket: &str) -> anyhow::Result<IpcClient> {
    match joindre(socket).await {
        Ok(client) => Ok(client),
        Err(Echec::Refuse(refus)) => Err(refus.into()),
        // Un serveur tient le canal: rien ne dit qu'il soit arrete.
        Err(Echec::Canal(e)) if e.is_server_busy() => Err(anyhow::Error::new(e).context(format!(
            "daemon sans reponse dans le delai sur {socket}: le canal existe, mais \
             n'a pris aucune connexion de plus. Reessayer dans un instant."
        ))),
        Err(Echec::Canal(e)) => Err(anyhow::Error::new(e).context(format!(
            "connexion au daemon sur {socket}. Est-il demarre, et avez-vous le droit \
             de le piloter ?"
        ))),
    }
}

/// Le refus porte par une erreur, a quelque profondeur qu'il se trouve.
pub(crate) fn refus(e: &anyhow::Error) -> Option<&ServeurRefuse> {
    e.chain().find_map(|c| c.downcast_ref::<ServeurRefuse>())
}

/// Ce qui tient le canal, pour une commande qui ne fait que le dire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Presence {
    /// Un serveur a l'identite du daemon.
    Daemon,
    /// Un serveur, mais pas celui-la.
    Autre,
    /// Personne, ou personne que ce compte puisse joindre.
    Personne,
}

/// Qui tient le canal. N'ecrit rien, dans aucun cas.
pub(crate) async fn presence(socket: &str) -> Presence {
    match joindre(socket).await {
        Ok(_) => Presence::Daemon,
        Err(Echec::Refuse(_)) => Presence::Autre,
        Err(Echec::Canal(_)) => Presence::Personne,
    }
}

/// Porte le verdict d'inspection TLS au daemon.
pub(crate) async fn annoncer_le_verdict(socket: &str, intercepte: bool) -> anyhow::Result<()> {
    let mut client = ouvrir(socket).await?;
    let reponse = client
        .request(&Request::new(Command::VerdictInspectionTls { intercepte }))
        .await
        .context("dialogue avec le daemon")?;
    match reponse {
        Response::Ok => Ok(()),
        Response::Error { message } => anyhow::bail!("{message}"),
        autre => anyhow::bail!("reponse inattendue du daemon: {autre:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tokio::io::{AsyncRead, AsyncReadExt};

    /// Ce que la recette attend du faux serveur, selon le compte qui la lance.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Attendu {
        /// Compte ordinaire: le faux serveur n'est jamais admis.
        Refus,
        /// Linux, root: le faux serveur EST privilegie, et admis.
        #[cfg(unix)]
        Admis,
        /// Windows, jeton eleve: le proprietaire du pipe depend d'une
        /// strategie locale (les Administrateurs par defaut). Seul
        /// l'invariant est exige: refuse, rien recu; admis, requete recue.
        #[cfg(windows)]
        Selon,
    }

    #[cfg(unix)]
    fn attendu() -> Attendu {
        let euid = std::fs::read_to_string("/proc/self/status")
            .expect("/proc/self/status")
            .lines()
            .find_map(|l| l.strip_prefix("Uid:"))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|u| u.parse::<u32>().ok())
            .expect("uid effectif");
        if euid == 0 {
            Attendu::Admis
        } else {
            Attendu::Refus
        }
    }

    /// Le niveau d'integrite du jeton, par son SID, qui ne se traduit pas:
    /// `S-1-16-12288` (eleve) ou `S-1-16-16384` (systeme).
    #[cfg(windows)]
    fn attendu() -> Attendu {
        let sortie = std::process::Command::new("whoami")
            .arg("/groups")
            .output()
            .expect("whoami /groups");
        let texte = String::from_utf8_lossy(&sortie.stdout);
        if texte.contains("S-1-16-12288") || texte.contains("S-1-16-16384") {
            Attendu::Selon
        } else {
            assert!(
                texte.contains("S-1-16-"),
                "niveau d'integrite introuvable dans whoami /groups"
            );
            Attendu::Refus
        }
    }

    /// Un faux serveur du COMPTE COURANT: il accepte, lit jusqu'a la fin de
    /// ligne ou du flux, ne repond jamais, et compte connexions et octets.
    struct Faux {
        socket: String,
        connexions: Arc<AtomicUsize>,
        recus: Arc<Mutex<Vec<u8>>>,
        tache: tokio::task::JoinHandle<()>,
        #[cfg(unix)]
        dossier: std::path::PathBuf,
    }

    fn etiquette_unique(nom: &str) -> String {
        static SUIVANT: AtomicUsize = AtomicUsize::new(0);
        format!(
            "bfsrv-{}-{}-{nom}",
            std::process::id(),
            SUIVANT.fetch_add(1, Ordering::SeqCst)
        )
    }

    async fn lire<R: AsyncRead + Unpin>(
        mut flux: R,
        connexions: Arc<AtomicUsize>,
        recus: Arc<Mutex<Vec<u8>>>,
    ) {
        let mut lu = Vec::new();
        let mut tampon = [0u8; 4096];
        let _ = tokio::time::timeout(Duration::from_secs(5), async {
            while let Ok(n) = flux.read(&mut tampon).await {
                if n == 0 {
                    break;
                }
                lu.extend_from_slice(&tampon[..n]);
                if lu.ends_with(b"\n") {
                    break;
                }
            }
        })
        .await;
        recus.lock().unwrap().extend_from_slice(&lu);
        // Compte APRES la lecture: une connexion comptee est une connexion
        // dont tout ce qui est arrive a ete releve.
        connexions.fetch_add(1, Ordering::SeqCst);
    }

    impl Faux {
        #[cfg(unix)]
        fn demarrer(nom: &str) -> Self {
            let dossier = std::env::temp_dir().join(etiquette_unique(nom));
            std::fs::create_dir_all(&dossier).unwrap();
            let chemin = dossier.join("d.sock");
            let ecoute = tokio::net::UnixListener::bind(&chemin).unwrap();
            let (connexions, recus) = (Arc::default(), Arc::default());
            let (c, r) = (Arc::clone(&connexions), Arc::clone(&recus));
            let tache = tokio::spawn(async move {
                while let Ok((flux, _)) = ecoute.accept().await {
                    tokio::spawn(lire(flux, Arc::clone(&c), Arc::clone(&r)));
                }
            });
            Self {
                socket: chemin.to_string_lossy().into_owned(),
                connexions,
                recus,
                tache,
                dossier,
            }
        }

        #[cfg(windows)]
        fn demarrer(nom: &str) -> Self {
            use tokio::net::windows::named_pipe::ServerOptions;
            let socket = format!(r"\\.\pipe\{}", etiquette_unique(nom));
            // Le descripteur par defaut: le proprietaire est le compte courant.
            let premier = ServerOptions::new()
                .first_pipe_instance(true)
                .reject_remote_clients(true)
                .create(&socket)
                .unwrap();
            let (connexions, recus) = (Arc::default(), Arc::default());
            let (c, r) = (Arc::clone(&connexions), Arc::clone(&recus));
            let nom_pipe = socket.clone();
            let tache = tokio::spawn(async move {
                let mut courant = premier;
                while courant.connect().await.is_ok() {
                    let Ok(suivant) = ServerOptions::new()
                        .reject_remote_clients(true)
                        .create(&nom_pipe)
                    else {
                        return;
                    };
                    let servi = std::mem::replace(&mut courant, suivant);
                    tokio::spawn(lire(servi, Arc::clone(&c), Arc::clone(&r)));
                }
            });
            Self {
                socket,
                connexions,
                recus,
                tache,
            }
        }

        /// Attend que `n` connexions aient ete relevees, et rend les octets.
        async fn apres(&self, n: usize) -> Vec<u8> {
            for _ in 0..100 {
                if self.connexions.load(Ordering::SeqCst) >= n {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            assert_eq!(
                self.connexions.load(Ordering::SeqCst),
                n,
                "le client n'a pas joint le faux serveur: un zero octet ne prouverait rien"
            );
            self.recus.lock().unwrap().clone()
        }
    }

    impl Drop for Faux {
        fn drop(&mut self) {
            self.tache.abort();
            #[cfg(unix)]
            let _ = std::fs::remove_dir_all(&self.dossier);
        }
    }

    /// Le chemin commun (`connect`, `disconnect`, `status`, `check`): refuse
    /// sans rien ecrire, avec le refus que `main` rend en code 4.
    #[tokio::test(flavor = "multi_thread")]
    async fn le_chemin_commun_refuse_un_serveur_du_compte_courant_sans_rien_lui_ecrire() {
        let faux = Faux::demarrer("commun");
        match ouvrir(&faux.socket).await {
            Ok(mut client) => {
                assert_ne!(attendu(), Attendu::Refus, "serveur du compte courant admis");
                let _ = client.request(&Request::new(Command::Status)).await;
                let recus = faux.apres(1).await;
                assert!(
                    !recus.is_empty(),
                    "admis, et rien recu: le faux serveur ne voit rien"
                );
            }
            Err(e) => {
                #[cfg(unix)]
                assert_ne!(attendu(), Attendu::Admis, "{e:#}");
                let refus = refus(&e).unwrap_or_else(|| panic!("pas un refus d'identite: {e:#}"));
                assert_eq!(refus.cause, ServerIdentityError::Refused);
                let recus = faux.apres(1).await;
                assert!(
                    recus.is_empty(),
                    "{} octet(s) ecrit(s) a un serveur refuse",
                    recus.len()
                );
            }
        }
    }

    /// Le verdict d'inspection: meme regle, meme silence.
    #[tokio::test(flavor = "multi_thread")]
    async fn l_annonce_du_verdict_ne_part_pas_vers_un_serveur_refuse() {
        let faux = Faux::demarrer("annonce");
        let issue = annoncer_le_verdict(&faux.socket, true).await;
        let recus = faux.apres(1).await;
        match attendu() {
            Attendu::Refus => {
                let e = issue.expect_err("annonce acceptee par un serveur du compte courant");
                assert!(refus(&e).is_some(), "{e:#}");
                assert!(recus.is_empty(), "{} octet(s) annonce(s)", recus.len());
            }
            #[cfg(unix)]
            Attendu::Admis => {
                assert!(!recus.is_empty(), "admis, et rien recu");
            }
            #[cfg(windows)]
            Attendu::Selon => match issue {
                Err(e) if refus(&e).is_some() => assert!(recus.is_empty()),
                _ => assert!(!recus.is_empty()),
            },
        }
    }

    /// La sonde de presence d'`emergency-disarm` n'ecrit JAMAIS, et ne prend
    /// plus un serveur quelconque pour le daemon.
    #[tokio::test(flavor = "multi_thread")]
    async fn la_sonde_de_presence_distingue_le_daemon_d_un_autre_sans_rien_ecrire() {
        let faux = Faux::demarrer("presence");
        let vu = presence(&faux.socket).await;
        let recus = faux.apres(1).await;
        assert!(
            recus.is_empty(),
            "la sonde a ecrit {} octet(s)",
            recus.len()
        );
        match attendu() {
            Attendu::Refus => assert_eq!(vu, Presence::Autre),
            #[cfg(unix)]
            Attendu::Admis => assert_eq!(vu, Presence::Daemon),
            #[cfg(windows)]
            Attendu::Selon => assert_ne!(vu, Presence::Personne),
        }
        #[cfg(unix)]
        let absent = std::env::temp_dir()
            .join(etiquette_unique("absent"))
            .join("d.sock")
            .to_string_lossy()
            .into_owned();
        #[cfg(windows)]
        let absent = format!(r"\\.\pipe\{}", etiquette_unique("absent"));
        assert_eq!(presence(&absent).await, Presence::Personne);
    }

    /// Un canal qui existe, et dont la seule place est tenue par un premier
    /// client que personne n'accepte. Windows: un pipe a une seule instance,
    /// prise par ce client. Linux: un socket d'ecoute dont la file d'attente a
    /// une longueur de zero, remplie par ce client.
    struct Occupe {
        socket: String,
        #[cfg(windows)]
        _tenu: (
            tokio::net::windows::named_pipe::NamedPipeServer,
            tokio::net::windows::named_pipe::NamedPipeClient,
        ),
        #[cfg(unix)]
        _tenu: (tokio::net::UnixListener, std::os::unix::net::UnixStream),
        #[cfg(unix)]
        dossier: std::path::PathBuf,
    }

    #[cfg(windows)]
    fn occupe(nom: &str) -> Occupe {
        use tokio::net::windows::named_pipe::{ClientOptions, ServerOptions};
        let socket = format!(r"\\.\pipe\{}", etiquette_unique(nom));
        let serveur = ServerOptions::new()
            .first_pipe_instance(true)
            .reject_remote_clients(true)
            .create(&socket)
            .expect("pipe de recette");
        let premier = ClientOptions::new().open(&socket).expect("premier client");
        Occupe {
            socket,
            _tenu: (serveur, premier),
        }
    }

    #[cfg(unix)]
    fn occupe(nom: &str) -> Occupe {
        let dossier = std::env::temp_dir().join(etiquette_unique(nom));
        std::fs::create_dir_all(&dossier).expect("repertoire de la recette");
        let chemin = dossier.join("d.sock");
        let prise = tokio::net::UnixSocket::new_stream().expect("socket de recette");
        prise.bind(&chemin).expect("bind");
        let ecoute = prise.listen(0).expect("listen");
        let premier = std::os::unix::net::UnixStream::connect(&chemin).expect("premier client");
        Occupe {
            socket: chemin.to_string_lossy().into_owned(),
            _tenu: (ecoute, premier),
            dossier,
        }
    }

    #[cfg(unix)]
    impl Drop for Occupe {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dossier);
        }
    }

    /// Le chemin commun des commandes: un canal qui existe et ne prend
    /// aucune connexion de plus se dit "daemon sans reponse dans le delai",
    /// sans le conseil qui suppose un daemon arrete; un canal absent garde ce
    /// conseil. Windows: apres l'attente d'une instance libre (2 s). Linux:
    /// `connect(2)` sur une file d'attente pleine rend `EAGAIN`.
    #[tokio::test(flavor = "multi_thread")]
    async fn un_canal_occupe_n_est_pas_dit_arrete() {
        let canal = occupe("occupe");
        let pris = ouvrir(&canal.socket).await.err().map(|e| format!("{e:#}"));
        drop(canal);
        #[cfg(unix)]
        let absent = std::env::temp_dir()
            .join(etiquette_unique("absent"))
            .join("d.sock")
            .to_string_lossy()
            .into_owned();
        #[cfg(windows)]
        let absent = format!(r"\\.\pipe\{}", etiquette_unique("absent"));
        let absent = ouvrir(&absent).await.err().map(|e| format!("{e:#}"));
        println!("mesure canal occupe: {pris:?}; canal absent: {absent:?}");
        let pris = pris.expect("un canal occupe ne s'ouvre pas");
        assert!(pris.contains("daemon sans reponse dans le delai"), "{pris}");
        assert!(!pris.contains("Est-il demarre"), "{pris}");
        let absent = absent.expect("un canal absent ne s'ouvre pas");
        assert!(absent.contains("Est-il demarre"), "{absent}");
        assert!(!absent.contains("sans reponse dans le delai"), "{absent}");
    }

    /// Le message nomme le socket et la regle, rien d'autre: ni uid, ni pid,
    /// ni SID. Ecrit en entier, pour que tout ajout se voie.
    #[test]
    fn le_refus_ne_nomme_ni_uid_ni_pid_ni_sid() {
        for (cause, constat) in [
            (
                ServerIdentityError::Refused,
                "n'a pas l'identite attendue du daemon",
            ),
            (ServerIdentityError::Unreadable, "n'a pas pu etre identifie"),
        ] {
            let refus = ServeurRefuse {
                socket: "CANAL".into(),
                cause,
            };
            let texte = refus.to_string();
            assert_eq!(
                texte,
                format!("REFUS: le serveur de CANAL {constat}. Rien ne lui a ete envoye.\n{REGLE}")
            );
            for interdit in ["uid", "pid", "S-1-", "gid"] {
                assert!(!texte.contains(interdit), "{interdit}: {texte}");
            }
            // Et `main` le retrouve sous un contexte ajoute par un appelant.
            let e = anyhow::Error::new(refus.clone()).context("contexte d'un appelant");
            assert_eq!(super::refus(&e), Some(&refus));
        }
        assert!(super::refus(&anyhow::anyhow!("autre chose")).is_none());
    }

    /// Le code du refus ne se confond avec aucun de ceux que le client rend
    /// deja, ni avec celui du `timeout` du hook.
    #[test]
    fn le_code_du_refus_est_distinct() {
        for deja in [0, 1, 2, 3, 124] {
            assert_ne!(CODE_SERVEUR_REFUSE, deja);
        }
    }
}
