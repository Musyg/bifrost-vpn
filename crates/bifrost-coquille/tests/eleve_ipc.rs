//! Le poste de commande face a un vrai `IpcServer`, sous Windows: par son
//! seul chemin public, `Commande::new`, il lui fait servir `status`,
//! `connect-stored` et `disconnect`.
//!
//! La regle des commandes n'admet qu'un pipe de LocalSystem ou des
//! Administrateurs. Le daemon lance en console attribue son pipe aux
//! Administrateurs (`O:BA`), sans dependre du proprietaire par defaut du
//! jeton: la recette lie donc le serveur en mode console
//! (`ProprietaireDuPipe::Administrateurs`) et verifie que le poste de commande
//! dialogue avec lui.
//!
//! Le noyau n'accepte `O:BA` que si les Administrateurs sont actifs dans le
//! jeton, ce que la recette lit par `CheckTokenMembership`
//! (`jeton::administrateurs_actifs`). Sans eux, elle s'abstient, et le dit.
//! Elle ne modifie plus le jeton du processus (aucune pose de proprietaire
//! par defaut, plus de binaire a part necessaire pour cela); l'integrite et
//! le proprietaire par defaut ne sont plus lus que pour son releve.
//!
//! Ce qu'elle lit s'imprime par classes, jamais par SID:
//! `RELEVE eleve_ipc: integrite=..., proprietaire par defaut=...`.

#![cfg(windows)]

#[path = "commun/faux_daemon.rs"]
mod faux_daemon;

use bifrost_coquille::Commande;
use bifrost_ipc::{AuthPolicy, IpcServer, ProprietaireDuPipe};

/// Le dialogue avec un vrai serveur IPC lie en mode console. Le proprietaire
/// par defaut du jeton n'entre pas en jeu: le mode console attribue le pipe
/// aux Administrateurs. La recette ne tourne que la ou ce groupe est actif
/// dans le jeton, lu par `CheckTokenMembership`; ailleurs elle s'abstient.
#[tokio::test(flavor = "multi_thread")]
async fn eleve_la_commande_dialogue_avec_un_vrai_serveur_ipc() {
    let integrite = jeton::integrite();
    let proprietaire = jeton::proprietaire_par_defaut();
    println!(
        "RELEVE eleve_ipc: integrite={}, proprietaire par defaut={}",
        integrite.nom(),
        proprietaire.nom()
    );

    if !jeton::administrateurs_actifs() {
        println!(
            "SKIPPED eleve_la_commande_dialogue_avec_un_vrai_serveur_ipc: les Administrateurs ne \
             sont pas actifs dans le jeton de ce processus, et le noyau refuse alors d'attribuer \
             un pipe a ce groupe"
        );
        return;
    }

    let path = format!(r"\\.\pipe\bifrost-coquille-{}-eleve", std::process::id());
    let server = IpcServer::bind(
        &path,
        AuthPolicy::default(),
        None,
        ProprietaireDuPipe::Administrateurs,
    )
    .await
    .expect("bind du vrai serveur IPC en mode console");
    let tache = tokio::spawn(faux_daemon::servir(server, Default::default()));

    let poste = Commande::new(path);
    assert_eq!(poste.etat().await, Ok(faux_daemon::status_de_reference()));
    poste.connecter().await.expect("connect-stored");
    poste.deconnecter().await.expect("disconnect");
    tache.abort();
}

#[path = "commun/jeton.rs"]
mod jeton;
