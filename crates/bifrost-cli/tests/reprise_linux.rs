//! Le hook `systemd-sleep` porte-t-il la reprise jusqu'au daemon.
//!
//! Ce qui est mesure ici: le SCRIPT reellement depose par l'installateur, le
//! binaire du client reellement construit, un vrai socket, un vrai serveur IPC.
//! Aucune doublure entre les deux bouts, et le script n'est pas reecrit pour
//! l'occasion - il est copie tel quel, avec le mode que `install -m 0755` lui
//! donnera.
//!
//! Ce qui n'est PAS mesure ici, et ne peut pas l'etre: que systemd lance bien
//! ce script au reveil. Cela demanderait d'endormir la machine d'essai, qui
//! heberge des services et ne doit pas dormir. Le present fichier s'arrete donc
//! a l'invocation manuelle, avec exactement les arguments que
//! `man systemd-sleep` decrit. La suite - trame sur le fil puis canal du
//! superviseur - est mesuree par `le_hook_...` cote daemon, dans les recettes
//! de `bifrost_daemon::server`.

#![cfg(target_os = "linux")]

use std::path::PathBuf;
use std::time::Duration;

use bifrost_ipc::AuthPolicy;
use bifrost_ipc::protocol::{Command, Response};
use bifrost_ipc::transport::IpcServer;

/// Combien de temps on attend une trame avant de conclure qu'il n'en vient pas.
///
/// Court, et ce n'est pas une imprudence: la trame n'est attendue qu'APRES la
/// sortie du processus. Le client attend la reponse du daemon avant de rendre
/// la main, donc s'il avait parle, le serveur d'essai a deja recu. Ce delai ne
/// couvre que le trajet entre les deux fils du test, jamais la decision du
/// hook. Allonger n'ajouterait rien, sinon de la duree aux cas negatifs.
const PATIENCE: Duration = Duration::from_secs(2);

/// L'uid effectif, lu dans `/proc`.
///
/// Plutot que `geteuid`: `libc` n'est pas une dependance de ce crate et cette
/// tranche n'en ajoute aucune. Champ 2 de la ligne `Uid:`, comme ailleurs dans
/// le depot.
fn euid() -> u32 {
    std::fs::read_to_string("/proc/self/status")
        .expect("/proc/self/status doit etre lisible")
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))
        .and_then(|l| l.split_whitespace().nth(1).and_then(|u| u.parse().ok()))
        .expect("la ligne Uid: doit porter un uid effectif")
}

/// Un repertoire a nous, TRAVERSABLE quoi qu'il arrive.
///
/// Le mode est pose explicitement, et ce n'est pas une precaution de style:
/// `IpcServer::bind` pose un `umask(0o117)` le temps de se lier, et l'umask est
/// PROCESSUS-WIDE. Ces recettes tournent en parallele dans un seul binaire,
/// donc un `create_dir_all` d'ici peut tomber pendant le bind d'a cote et
/// naitre en 0o660 - sans bit d'execution, c'est-a-dire non traversable, et le
/// bind suivant echoue en `EACCES`. Constate le 23/08/2026 sur essai-linux: une
/// recette sur cinq en echec, au hasard de l'ordonnancement.
fn atelier(nom: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let rep = std::env::temp_dir().join(format!("bifrost-reprise-{}-{nom}", std::process::id()));
    let _ = std::fs::remove_dir_all(&rep);
    std::fs::create_dir_all(&rep).expect("atelier");
    std::fs::set_permissions(&rep, std::fs::Permissions::from_mode(0o755)).expect("atelier 0755");
    rep
}

/// Le hook, copie UNE SEULE FOIS avec le mode que l'installateur lui donnera.
///
/// Copie et non lu: systemd ne lance que les fichiers executables de son
/// repertoire, et un depot clone depuis Windows ne porte aucun bit d'execution.
/// L'executer ici par son shebang mesure donc la meme chose que ce qui sera
/// installe, y compris la premiere ligne.
///
/// Une seule fois, et c'est la moitie qui a coute quelque chose. Avec une copie
/// par recette, une recette sur cinq environ tombait en `ETXTBSY` - "Text file
/// busy" - au moment d'executer SA copie. Le mecanisme n'a rien d'evident:
/// `execve` refuse un fichier ouvert en ECRITURE par n'importe quel processus,
/// et ces recettes tournent en parallele dans un seul binaire. Quand l'une
/// forke pour lancer son hook, l'enfant herite de toute la table de
/// descripteurs (`O_CLOEXEC` ne referme qu'a l'`execve`, pas au `fork`), donc
/// pendant la fenetre entre les deux, cet enfant tient une copie du descripteur
/// d'ecriture qu'une AUTRE recette a ouvert sur SA copie. Celle-la echoue alors
/// a executer un fichier que plus personne ne croit ecrire. Constate le
/// 23/08/2026 sur essai-linux, au 5e passage d'une boucle de 12.
///
/// Le `OnceLock` supprime la concurrence plutot que de la rattraper: la seule
/// ecriture a lieu avant que la premiere recette n'ait pu forker, puisque
/// toutes passent par ici avant de lancer quoi que ce soit.
fn hook() -> &'static PathBuf {
    static HOOK: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    HOOK.get_or_init(|| {
        use std::os::unix::fs::PermissionsExt;
        let source = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../packaging/systemd/system-sleep/bifrost-reprise");
        // Un repertoire a lui: les ateliers des recettes sont effaces a la fin
        // de chacune, et le hook partage n'y survivrait pas.
        let rep = std::env::temp_dir().join(format!("bifrost-reprise-hook-{}", std::process::id()));
        std::fs::create_dir_all(&rep).expect("repertoire du hook");
        std::fs::set_permissions(&rep, std::fs::Permissions::from_mode(0o755)).expect("hook 0755");
        let copie = rep.join("bifrost-reprise");
        std::fs::copy(&source, &copie)
            .unwrap_or_else(|e| panic!("copie de {}: {e}", source.display()));
        std::fs::set_permissions(&copie, std::fs::Permissions::from_mode(0o755))
            .expect("mode 0755");
        copie
    })
}

/// Ce qu'une invocation du hook a produit.
struct Passage {
    code: Option<i32>,
    erreur: String,
    /// La commande arrivee sur le fil, ou `None` si rien n'est venu pendant
    /// [`PATIENCE`].
    recue: Option<Command>,
}

/// Lance le hook contre un vrai serveur IPC et rend ce qui s'est passe.
///
/// `socket` decide de ce que le hook trouvera au bout: `Canal::Ouvert` monte un
/// serveur, les deux autres fabriquent les situations ou il n'y en a pas.
async fn passer(nom: &str, phase: &str, operation: &str, canal: Canal) -> Passage {
    let rep = atelier(nom);
    let chemin = rep.join("daemon.sock");
    let (tx, rx) = std::sync::mpsc::channel();

    let _serveur = match canal {
        Canal::Ouvert => {
            // La politique par defaut n'autorise que root, et ces recettes
            // tournent sous un compte ordinaire.
            let policy = AuthPolicy {
                allowed_uids: vec![0, euid()],
                allowed_gid: None,
            };
            let serveur = IpcServer::bind(&chemin, policy, None)
                .await
                .expect("le serveur d'essai doit se lier");
            Some(tokio::spawn(recevoir_une_fois(serveur, tx)))
        }
        Canal::Mort => {
            // Un `UnixListener` de la bibliotheque standard et surtout pas un
            // `IpcServer`: celui-ci RETIRE son fichier en tombant, ce qui
            // rendrait ce cas indiscernable d'une machine sans daemon - donc
            // exactement la confusion que cette recette existe pour eprouver.
            // Le listener standard, lui, laisse l'entree derriere lui, comme un
            // daemon tue.
            let ecoute = std::os::unix::net::UnixListener::bind(&chemin)
                .expect("le socket d'essai doit se lier");
            drop(ecoute);
            assert!(
                chemin.exists(),
                "le canal mort doit laisser son fichier, sinon la recette mesure \
                 une machine sans daemon"
            );
            None
        }
        Canal::Absent => None,
    };

    let script = hook().clone();
    let cli = env!("CARGO_BIN_EXE_bifrost-cli");
    // Tout est possede avant d'entrer dans la tache: `spawn_blocking` exige
    // `'static`, et les arguments arrivent ici par reference.
    let (phase, operation) = (phase.to_owned(), operation.to_owned());
    let sortie = tokio::task::spawn_blocking({
        let chemin = chemin.clone();
        move || {
            std::process::Command::new(&script)
                .arg(&phase)
                .arg(&operation)
                .env("BIFROST_CLI", cli)
                .env("BIFROST_SOCKET", &chemin)
                .output()
                .expect("le hook doit s'executer")
        }
    })
    .await
    .expect("le hook doit rendre la main");

    let recue = rx.recv_timeout(PATIENCE).ok();
    let _ = std::fs::remove_dir_all(&rep);
    Passage {
        code: sortie.status.code(),
        erreur: String::from_utf8_lossy(&sortie.stderr).trim().to_owned(),
        recue,
    }
}

#[derive(Clone, Copy)]
enum Canal {
    /// Un daemon ecoute et repond.
    Ouvert,
    /// Le fichier de socket existe, personne n'accepte.
    Mort,
    /// Rien du tout, comme sur une machine ou le daemon n'a jamais demarre.
    Absent,
}

/// Accepte une connexion, transmet la commande recue, repond, et sort.
async fn recevoir_une_fois(mut serveur: IpcServer, tx: std::sync::mpsc::Sender<Command>) {
    if let Ok(mut conn) = serveur.accept().await
        && let Ok(requete) = conn.recv().await
    {
        let _ = tx.send(requete.command);
        let _ = conn.send(&Response::Ok).await;
    }
}

/// Ce que la tranche existe pour etablir: `post suspend`, invoque a la main,
/// fait arriver `Command::Reprise` au daemon.
#[tokio::test(flavor = "multi_thread")]
async fn le_hook_au_reveil_porte_la_reprise_jusqu_au_daemon() {
    let p = passer("reveil", "post", "suspend", Canal::Ouvert).await;
    assert!(
        matches!(p.recue, Some(Command::Reprise)),
        "le daemon n'a pas recu de reprise (recu: {:?}, stderr: {})",
        p.recue.as_ref().map(Command::name),
        p.erreur
    );
    assert_eq!(p.code, Some(0), "stderr: {}", p.erreur);
}

/// Les quatre operations que systemd nomme passent toutes par le meme chemin.
///
/// Une seule d'entre elles mesuree laisserait croire que le hook marche alors
/// qu'il ne reconnaitrait qu'un mot.
#[tokio::test(flavor = "multi_thread")]
async fn les_quatre_operations_de_systemd_portent_la_reprise() {
    for operation in [
        "suspend",
        "hibernate",
        "hybrid-sleep",
        "suspend-then-hibernate",
    ] {
        let p = passer(operation, "post", operation, Canal::Ouvert).await;
        assert!(
            matches!(p.recue, Some(Command::Reprise)),
            "{operation}: rien recu (stderr: {})",
            p.erreur
        );
    }
}

/// La garde qui compte: systemd appelle le MEME script avant d'endormir.
///
/// Sans elle, le daemon recevrait une reprise a l'aller comme au retour, et une
/// reprise recue cesserait de vouloir dire qu'une veille s'est terminee.
#[tokio::test(flavor = "multi_thread")]
async fn le_hook_a_l_endormissement_ne_parle_a_personne() {
    let p = passer("endormissement", "pre", "suspend", Canal::Ouvert).await;
    assert!(
        p.recue.is_none(),
        "la phase pre a parle au daemon: {:?}",
        p.recue.map(|c| c.name())
    );
    // Et sans se plaindre: c'est un appel normal, pas un incident.
    assert_eq!(p.code, Some(0), "stderr: {}", p.erreur);
    assert!(
        !p.erreur.is_empty(),
        "le passage doit laisser une trace: un hook absent et un hook muet se \
         ressemblent trop"
    );
}

/// Une invocation hors du contrat de systemd ne fait rien, et le dit.
#[tokio::test(flavor = "multi_thread")]
async fn une_invocation_hors_contrat_ne_parle_a_personne() {
    for (nom, phase, operation) in [
        ("operation", "post", "sieste"),
        ("phase", "resume", "suspend"),
        ("vide", "", ""),
    ] {
        let p = passer(nom, phase, operation, Canal::Ouvert).await;
        assert!(
            p.recue.is_none(),
            "{nom}: une invocation hors contrat a parle au daemon"
        );
        assert_eq!(p.code, Some(2), "{nom}: stderr: {}", p.erreur);
        assert!(
            p.erreur.contains("refusee"),
            "{nom}: le refus doit se lire dans le journal: {}",
            p.erreur
        );
    }
}

/// Un canal mort n'est pas une machine sans daemon.
///
/// Les deux se ressembleraient si le hook rendait 0 dans les deux cas, et c'est
/// justement dans le premier que la politique n'a PAS ete reposee.
#[tokio::test(flavor = "multi_thread")]
async fn un_canal_mort_et_une_machine_sans_daemon_ne_se_ressemblent_pas() {
    let mort = passer("mort", "post", "suspend", Canal::Mort).await;
    assert_eq!(
        mort.code,
        Some(1),
        "un socket que plus personne n'ecoute doit echouer: {}",
        mort.erreur
    );
    assert!(
        mort.erreur.contains("n'a PAS ete reposee"),
        "le journal doit dire ce qui n'a pas eu lieu: {}",
        mort.erreur
    );

    let absent = passer("absent", "post", "suspend", Canal::Absent).await;
    assert_eq!(
        absent.code,
        Some(0),
        "une machine sans daemon n'a rien a reposer: {}",
        absent.erreur
    );
}
