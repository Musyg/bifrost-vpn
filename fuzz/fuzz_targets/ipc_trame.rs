//! La trame d'un client du daemon, lue par le vrai serveur IPC:
//! `bifrost_ipc::IpcServer::accept` puis `bifrost_ipc::Connection::recv`.
//!
//! Frontiere: n'importe quel processus admis sur le socket (root, ou un membre
//! du groupe `bifrost`) ecrit ces octets; le daemon les lit en root sous Linux
//! (LocalSystem sous Windows, par le pipe nomme, non couvert ici). C'est le
//! chemin de production complet: cadrage borne (`read_frame`, prive),
//! deserialisation, controle de version.
//!
//! La cible ouvre UNE fois, par processus, un vrai serveur sur un socket Unix
//! du repertoire temporaire (aucun reseau), admet son propre uid, puis a
//! chaque execution se connecte, ecrit l'entree, ferme son cote ecriture et
//! laisse le serveur accepter et lire. L'entree est bornee a 64 Kio pour tenir
//! d'un bloc dans le tampon du socket avant l'acceptation; la borne de 256 Kio
//! de `MAX_FRAME_BYTES` n'est donc pas atteinte ici.
//!
//! Au-dela de l'absence de panique, la cible verifie l'issue exacte du cadrage:
//! - rien d'ecrit: `Closed`;
//! - aucune fin de ligne: la trame est refusee (`FrameTooLarge`);
//! - sinon la premiere ligne decide seule: `Json` si elle ne se lit pas,
//!   `VersionMismatch` si sa version n'est pas `PROTOCOL_VERSION`, et la
//!   requete rendue est exactement celle que serde_json lit de cette ligne.
#![no_main]

use std::io::Write;
use std::net::Shutdown;
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

use bifrost_ipc::protocol::{PROTOCOL_VERSION, Request};
use bifrost_ipc::{AuthPolicy, IpcError, IpcServer};
use libfuzzer_sys::fuzz_target;

/// Ce qui tient d'un bloc dans le tampon d'un socket Unix avant l'acceptation.
const ENTREE_MAX: usize = 64 * 1024;

struct Banc {
    runtime: tokio::runtime::Runtime,
    serveur: Mutex<IpcServer>,
    chemin: PathBuf,
}

fn banc() -> &'static Banc {
    static BANC: OnceLock<Banc> = OnceLock::new();
    BANC.get_or_init(|| {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .expect("le runtime du banc doit demarrer");
        let dossier = std::env::temp_dir().join(format!("bifrost-fuzz-ipc-{}", std::process::id()));
        std::fs::create_dir_all(&dossier).expect("le repertoire du banc doit se creer");
        let moi = std::fs::metadata(&dossier)
            .expect("le repertoire du banc doit se lire")
            .uid();
        let politique = AuthPolicy {
            allowed_uids: vec![moi],
            allowed_gid: None,
        };
        let chemin = dossier.join("daemon.sock");
        let serveur = runtime
            .block_on(IpcServer::bind(&chemin, politique, None))
            .expect("le serveur du banc doit ecouter");
        Banc {
            runtime,
            serveur: Mutex::new(serveur),
            chemin,
        }
    })
}

fuzz_target!(|octets: &[u8]| {
    let entree = &octets[..octets.len().min(ENTREE_MAX)];
    let banc = banc();

    let mut client = UnixStream::connect(&banc.chemin).expect("le client doit se connecter");
    client
        .write_all(entree)
        .expect("l'entree doit tenir dans le tampon du socket");
    client
        .shutdown(Shutdown::Write)
        .expect("le client doit fermer son cote ecriture");

    let mut serveur = banc.serveur.lock().expect("verrou du serveur");
    let issue = banc.runtime.block_on(async {
        let mut connexion = serveur
            .accept()
            .await
            .expect("le client admis doit etre accepte");
        connexion.recv().await
    });
    drop(client);

    let ligne = entree
        .iter()
        .position(|o| *o == b'\n')
        .map(|fin| &entree[..fin]);
    match issue {
        Ok(requete) => {
            assert_eq!(requete.version, PROTOCOL_VERSION, "version non controlee");
            let ligne = ligne.expect("une requete rendue sans fin de ligne");
            let lue: Request =
                serde_json::from_slice(ligne).expect("une requete rendue que serde ne lit pas");
            assert_eq!(
                serde_json::to_value(&requete).expect("requete serialisable"),
                serde_json::to_value(&lue).expect("requete serialisable"),
                "la requete rendue n'est pas celle de la premiere ligne"
            );
        }
        Err(IpcError::Closed) => assert!(entree.is_empty(), "Closed sur une entree non vide"),
        Err(IpcError::FrameTooLarge) => {
            assert!(
                !entree.is_empty() && ligne.is_none(),
                "trame refusee a tort"
            )
        }
        Err(IpcError::Json(_)) => {
            let ligne = ligne.expect("erreur JSON sans fin de ligne");
            assert!(
                serde_json::from_slice::<Request>(ligne).is_err(),
                "erreur JSON sur une ligne que serde lit"
            );
        }
        Err(IpcError::VersionMismatch { got }) => {
            let ligne = ligne.expect("version refusee sans fin de ligne");
            let lue: Request =
                serde_json::from_slice(ligne).expect("version refusee sur une ligne illisible");
            assert_eq!(lue.version, got, "version rapportee differente de la lue");
            assert_ne!(got, PROTOCOL_VERSION, "la bonne version a ete refusee");
        }
        Err(autre) => panic!("issue inattendue du cadrage: {autre}"),
    }
});
