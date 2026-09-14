//! Le hook `systemd-sleep` fait-il arriver la reprise AU SUPERVISEUR.
//!
//! La question de la tranche, en une seule mesure et sans joint: le script que
//! l'installateur depose, invoque exactement comme systemd l'invoque, jusqu'au
//! canal que le superviseur ecoute. Entre les deux, le vrai client, le vrai
//! serveur IPC, le vrai `dispatch`. Aucune doublure.
//!
//! # Ce qui reste hors de portee, et pourquoi ce n'est pas contournable
//!
//! Que systemd lance REELLEMENT ce script au reveil ne peut pas etre mesure
//! ici. Il faudrait endormir la machine, et la seule machine d'essai Linux
//! heberge des services qui ne doivent pas s'interrompre. Ce chemin-la est donc
//! declare non mesure, jamais suppose acquis: c'est le contrat d'appel de
//! `man systemd-sleep` qui le porte, et rien d'autre.
//!
//! Le pendant Windows de cette mesure existe et va plus loin - il ENDORT la
//! machine: `bifrost_daemon::reprise::selftest`, derriere
//! `--reprise-selftest`. Il n'a pas d'equivalent ici pour la raison ci-dessus.

#![cfg(target_os = "linux")]

use std::path::PathBuf;
use std::time::Duration;

use bifrost_daemon::supervisor::Cmd;
use bifrost_ipc::AuthPolicy;
use bifrost_ipc::transport::IpcServer;

/// De quoi couvrir le lancement d'un processus et un aller-retour local.
const PATIENCE: Duration = Duration::from_secs(10);

fn euid() -> u32 {
    std::fs::read_to_string("/proc/self/status")
        .expect("/proc/self/status doit etre lisible")
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))
        .and_then(|l| l.split_whitespace().nth(1).and_then(|u| u.parse().ok()))
        .expect("la ligne Uid: doit porter un uid effectif")
}

/// Le client, cherche a cote du binaire de test puis un cran au-dessus.
///
/// `cargo test -p bifrost-daemon` ne construit PAS `bifrost-cli`: le trouver
/// absent est une situation normale, et cette recette se declare alors sautee
/// plutot que verte. Un `cargo build --workspace` prealable la fait tourner.
fn client() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let deps = exe.parent()?;
    [deps.join("bifrost-cli"), deps.join("../bifrost-cli")]
        .into_iter()
        .find(|c| c.is_file())
}

#[tokio::test(flavor = "multi_thread")]
async fn le_hook_de_veille_fait_arriver_la_reprise_au_superviseur() {
    use std::os::unix::fs::PermissionsExt;

    let Some(cli) = client() else {
        println!(
            "SKIPPED: bifrost-cli absent a cote du binaire de test. `cargo test -p \
             bifrost-daemon` ne le construit pas; lancer `cargo build --workspace` \
             avant. Le chemin du hook n'a donc PAS ete mesure."
        );
        return;
    };

    // Mode pose explicitement: `IpcServer::bind` applique un `umask(0o117)`
    // processus-wide le temps de se lier, et un repertoire cree pendant ce
    // temps-la naitrait sans bit d'execution, donc intraversable.
    let rep = std::env::temp_dir().join(format!("bifrost-reprise-sup-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&rep);
    std::fs::create_dir_all(&rep).expect("atelier");
    std::fs::set_permissions(&rep, std::fs::Permissions::from_mode(0o755)).expect("atelier 0755");

    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../packaging/systemd/system-sleep/bifrost-reprise");
    let hook = rep.join("bifrost-reprise");
    std::fs::copy(&source, &hook).unwrap_or_else(|e| panic!("copie de {}: {e}", source.display()));
    std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).expect("hook 0755");

    // Le canal du superviseur. C'est SON extremite qui est le point d'arrivee
    // de la mesure: tout ce qui est en amont peut mentir, pas ce qui sort ici.
    let (tx, rx) = std::sync::mpsc::channel::<Cmd>();

    let chemin = rep.join("daemon.sock");
    let policy = AuthPolicy {
        allowed_uids: vec![0, euid()],
        allowed_gid: None,
    };
    let ipc = IpcServer::bind(&chemin, policy, None)
        .await
        .expect("le serveur d'essai doit se lier");
    // Le VRAI serveur du daemon, avec son `dispatch`. Un serveur d'essai qui
    // se contenterait de lire la trame prouverait que le client parle, pas que
    // le daemon transmet.
    tokio::spawn(bifrost_daemon::server::serve(
        ipc,
        tx,
        PathBuf::from("/inexistant"),
    ));

    let sortie = tokio::task::spawn_blocking({
        let (hook, chemin) = (hook.clone(), chemin.clone());
        move || {
            std::process::Command::new(&hook)
                // Les deux arguments de `man systemd-sleep`, dans cet ordre.
                .arg("post")
                .arg("suspend")
                .env("BIFROST_CLI", &cli)
                .env("BIFROST_SOCKET", &chemin)
                .output()
                .expect("le hook doit s'executer")
        }
    })
    .await
    .expect("le hook doit rendre la main");

    let erreur = String::from_utf8_lossy(&sortie.stderr).trim().to_owned();
    let recu = rx.recv_timeout(PATIENCE);
    let _ = std::fs::remove_dir_all(&rep);

    assert_eq!(sortie.status.code(), Some(0), "le hook a echoue: {erreur}");
    // `Cmd` ne derive pas `Debug` et ne doit pas le deriver: `Cmd::Connect`
    // porte une cle privee, qu'un `{:?}` egare suffirait a mettre au journal.
    assert!(
        matches!(recu, Ok(Cmd::Reprise)),
        "aucune Cmd::Reprise n'est arrivee au superviseur. Au reveil, la \
         politique ne serait pas reposee. stderr du hook: {erreur}"
    );
}
