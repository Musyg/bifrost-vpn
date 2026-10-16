//! Le poste de commande face a un vrai `IpcServer`, sous Windows: par son
//! seul chemin public, `Commande::new`, il lui fait servir `status`,
//! `connect-stored` et `disconnect`.
//!
//! La regle des commandes n'admet qu'un pipe de LocalSystem ou des
//! Administrateurs, et un objet cree sans proprietaire explicite recoit le
//! proprietaire par defaut du jeton de son createur, `TokenOwner`
//! ([MS-DTYP] 2.5.3.4.1). La recette ne suppose rien de ce proprietaire par
//! defaut: elle le lit, puis pose les Administrateurs comme proprietaire par
//! defaut de son jeton, ce que fait l'elevation par UAC, le relit, et
//! seulement alors lie le serveur. Le systeme refuse la pose
//! (`ERROR_INVALID_OWNER`) quand les Administrateurs ne sont pas eligibles
//! comme proprietaire dans ce jeton: la recette s'abstient alors, et le dit.
//!
//! Un binaire a part: la pose modifie le jeton du PROCESSUS, et aucune autre
//! recette ne tourne dans ce processus. Ni jeton de fil, ni impersonation.
//!
//! Ce qu'elle lit s'imprime par classes, jamais par SID:
//! `RELEVE eleve_ipc: integrite=..., proprietaire par defaut avant=...`, puis,
//! apres la pose, `RELEVE eleve_ipc: proprietaire par defaut apres=...`.

#![cfg(windows)]

#[path = "commun/faux_daemon.rs"]
mod faux_daemon;

use bifrost_coquille::Commande;
use bifrost_ipc::{AuthPolicy, IpcServer};
use jeton::{Integrite, Proprietaire};
use windows_sys::Win32::Foundation::ERROR_INVALID_OWNER;

/// L'issue de la pose des Administrateurs comme proprietaire par defaut.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pose {
    /// Deja proprietaire par defaut: rien n'est pose.
    Deja,
    /// Posee par `SetTokenInformation`.
    Posee,
    /// Refusee par `ERROR_INVALID_OWNER`: les Administrateurs ne sont pas
    /// eligibles comme proprietaire dans ce jeton.
    NonEligible,
}

/// Le dialogue avec un vrai serveur IPC, une fois les Administrateurs poses
/// comme proprietaire par defaut du jeton et relus. Le niveau d'integrite
/// sert de controle croise de la pose: un jeton eleve ou systeme qui la
/// refuse, ou un jeton moyen dont les Administrateurs sont ou deviennent le
/// proprietaire par defaut, se contredisent, et la recette rougit en
/// imprimant les deux. Toute erreur de la pose autre que
/// `ERROR_INVALID_OWNER` est un rouge.
#[tokio::test(flavor = "multi_thread")]
async fn eleve_la_commande_dialogue_avec_un_vrai_serveur_ipc() {
    let integrite = jeton::integrite();
    let avant = jeton::proprietaire_par_defaut();
    println!(
        "RELEVE eleve_ipc: integrite={}, proprietaire par defaut avant={}",
        integrite.nom(),
        avant.nom()
    );

    let pose = if avant == Proprietaire::Administrateurs {
        Pose::Deja
    } else {
        match jeton::poser_les_administrateurs() {
            Ok(()) => Pose::Posee,
            Err(e) if e.raw_os_error() == Some(ERROR_INVALID_OWNER as i32) => Pose::NonEligible,
            Err(e) => panic!("pose des Administrateurs comme proprietaire par defaut: {e}"),
        }
    };
    match (integrite, pose) {
        (Integrite::Eleve | Integrite::Systeme, Pose::Deja | Pose::Posee) => {}
        (Integrite::Moyen, Pose::NonEligible) => {
            println!(
                "SKIPPED eleve_la_commande_dialogue_avec_un_vrai_serveur_ipc: les \
                 Administrateurs ne sont pas eligibles comme proprietaire dans le jeton de ce \
                 processus (ERROR_INVALID_OWNER), et la regle des commandes n'admet qu'un pipe \
                 de LocalSystem ou des Administrateurs"
            );
            return;
        }
        (Integrite::Eleve | Integrite::Systeme, Pose::NonEligible)
        | (Integrite::Moyen, Pose::Deja | Pose::Posee) => panic!(
            "contradiction: integrite={}, pose des Administrateurs comme proprietaire par \
             defaut: {pose:?}",
            integrite.nom()
        ),
    }

    let apres = jeton::proprietaire_par_defaut();
    println!(
        "RELEVE eleve_ipc: proprietaire par defaut apres={}",
        apres.nom()
    );
    assert_eq!(
        apres,
        Proprietaire::Administrateurs,
        "le proprietaire par defaut relu apres la pose ({pose:?})"
    );

    let path = format!(r"\\.\pipe\bifrost-coquille-{}-eleve", std::process::id());
    let server = IpcServer::bind(&path, AuthPolicy::default(), None)
        .await
        .expect("bind du vrai serveur IPC");
    let tache = tokio::spawn(faux_daemon::servir(server, Default::default()));

    let poste = Commande::new(path);
    assert_eq!(poste.etat().await, Ok(faux_daemon::status_de_reference()));
    poste.connecter().await.expect("connect-stored");
    poste.deconnecter().await.expect("disconnect");
    tache.abort();
}

#[path = "commun/jeton.rs"]
mod jeton;
