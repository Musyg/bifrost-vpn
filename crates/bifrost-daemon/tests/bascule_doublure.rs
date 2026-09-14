//! La bascule menee de bout en bout contre une doublure de coeur, par socket.
//!
//! # Ce que cette recette ajoute aux deux autres
//!
//! Trois recettes couvrent la bascule, et aucune ne remplace les autres.
//!
//! - Les recettes unitaires de `coeurs::bascule` posent une API MENTEUSE - elle
//!   repond 204 et ne change jamais de sortie - pour prouver que la relecture
//!   mord. Elles ne parlent a aucun coeur.
//! - `tests/vitalite.rs::la_bascule_change_vraiment_de_sortie_et_le_dit` parle a
//!   un VRAI sing-box, quand `BIFROST_COEURS` en designe un. Elle mesure le
//!   protocole, et elle est `SKIPPED` partout ailleurs.
//! - Celle-ci fait dialoguer notre CLIENT avec notre SERVEUR, par une vraie
//!   socket, sans binaire tiers. Elle tourne donc sur les deux plateformes et
//!   en CI, et elle attrape la classe de defaut que les deux autres laissent
//!   passer: un desaccord entre `coeurs::clash` et `coeurs::doublure` sur ce qui
//!   circule sur le fil - chemin encode, corps JSON, statut attendu.
//!
//! Le desaccord n'est pas theorique: jusqu'au 20 aout 2026 la doublure rendait
//! 404 a `GET /proxies/<nom>`, donc toute bascule menee contre elle concluait
//! `Refusee` avec la raison "bascule inverifiable". Personne ne s'en apercevait
//! parce que personne ne menait de bascule contre elle.

#![cfg(debug_assertions)]

use std::net::SocketAddr;

use bifrost_daemon::coeurs::bascule::{Issue, basculer};
use bifrost_daemon::coeurs::doublure::{Configuration, servir_sur};
use bifrost_daemon::coeurs::vitalite::Adresse;
use tokio::net::TcpListener;

const SECRET: &str = "secret-de-recette-bascule";
const SELECTEUR: &str = "select";

/// Lance la doublure sur un port choisi par le systeme et rend son adresse.
///
/// L'ecoute est liee AVANT que la tache ne demarre: demander un port libre puis
/// esperer qu'il le soit encore a la seconde suivante est la course que
/// `tests/coeurs.rs` traine encore, et il n'y a aucune raison de la reproduire.
async fn doublure(sorties: &[&str]) -> SocketAddr {
    let ecoute = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("un port libre sur la boucle locale");
    let adresse = ecoute.local_addr().expect("l'adresse liee");
    let config = Configuration {
        port: adresse.port(),
        secret: SECRET.to_owned(),
        selecteur: SELECTEUR.to_owned(),
        sorties: sorties.iter().map(|s| (*s).to_owned()).collect(),
    };
    tokio::spawn(async move {
        let _ = servir_sur(ecoute, config).await;
    });
    adresse
}

fn adresse_de(api: SocketAddr) -> Adresse {
    Adresse {
        api,
        secret: SECRET.to_owned(),
        selecteur: SELECTEUR.to_owned(),
    }
}

/// Le cas nominal: on demande la sortie suivante, elle est servie, et on le sait.
#[tokio::test]
async fn une_bascule_vers_une_sortie_connue_est_faite_et_verifiee() {
    let api = doublure(&["sortie-a", "sortie-b"]).await;
    assert_eq!(
        basculer(&adresse_de(api), "sortie-b").await,
        Issue::Faite {
            sortie: "sortie-b".to_owned()
        }
    );
}

/// Et la bascule TIENT: la sortie servie reste celle qu'on a demandee.
///
/// Sans etat partage entre connexions, chaque requete repartirait de la
/// selection initiale: le PUT dirait oui, le GET qui le verifie repondrait
/// "sortie-a", et la bascule se declarerait refusee sans que rien ne soit en
/// cause chez le client. C'est le defaut que cette recette garde.
#[tokio::test]
async fn la_sortie_choisie_survit_a_la_connexion_qui_l_a_choisie() {
    let adresse = adresse_de(doublure(&["sortie-a", "sortie-b"]).await);
    assert!(matches!(
        basculer(&adresse, "sortie-b").await,
        Issue::Faite { .. }
    ));
    // Une troisieme connexion, plus tard: la selection est toujours la.
    assert_eq!(
        bifrost_daemon::coeurs::clash::lire_selection(adresse.api, &adresse.secret, SELECTEUR)
            .await
            .expect("le selecteur se lit"),
        "sortie-b"
    );
}

/// Une sortie que le coeur ne connait pas est refusee, et le trafic ne bouge pas.
///
/// C'est le comportement mesure sur sing-box 1.13.18: une etiquette absente du
/// groupe rend un statut non-204. La consequence qui compte est la seconde
/// assertion - apres un refus, la sortie servie est toujours l'ancienne.
#[tokio::test]
async fn une_sortie_inconnue_laisse_le_trafic_ou_il_etait() {
    let adresse = adresse_de(doublure(&["sortie-a", "sortie-b"]).await);
    let issue = basculer(&adresse, "sortie-fantome").await;
    assert!(
        matches!(issue, Issue::Refusee { .. }),
        "une sortie inconnue doit etre refusee: {issue:?}"
    );
    assert_eq!(
        bifrost_daemon::coeurs::clash::lire_selection(adresse.api, &adresse.secret, SELECTEUR)
            .await
            .expect("le selecteur se lit"),
        "sortie-a"
    );
}

/// Un mauvais secret ne bascule rien.
///
/// L'API de controle choisit par ou sort le trafic. Un programme du poste qui
/// n'a pas le secret ne doit pas pouvoir la piloter, et le refus doit se lire
/// comme un refus et non comme une bascule silencieuse.
#[tokio::test]
async fn un_mauvais_secret_ne_bascule_rien() {
    let api = doublure(&["sortie-a", "sortie-b"]).await;
    let menteur = Adresse {
        api,
        secret: "pas le bon".to_owned(),
        selecteur: SELECTEUR.to_owned(),
    };
    assert!(matches!(
        basculer(&menteur, "sortie-b").await,
        Issue::Refusee { .. }
    ));
    assert_eq!(
        bifrost_daemon::coeurs::clash::lire_selection(api, SECRET, SELECTEUR)
            .await
            .expect("le selecteur se lit avec le bon secret"),
        "sortie-a"
    );
}

/// Un nom de selecteur qui doit etre encode traverse le fil intact.
///
/// Le client encode, la doublure decode. Les deux moities sont ecrites ici, et
/// rien avant cette recette ne les faisait se rencontrer: une erreur
/// d'encodage d'un cote se serait vue en exploitation, contre un vrai coeur, et
/// nulle part avant.
#[tokio::test]
async fn un_selecteur_dont_le_nom_doit_etre_encode_bascule_quand_meme() {
    const NOM: &str = "mon selecteur/2";
    let ecoute = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("un port libre");
    let api = ecoute.local_addr().expect("l'adresse liee");
    let config = Configuration {
        port: api.port(),
        secret: SECRET.to_owned(),
        selecteur: NOM.to_owned(),
        sorties: vec!["sortie-a".to_owned(), "sortie-b".to_owned()],
    };
    tokio::spawn(async move {
        let _ = servir_sur(ecoute, config).await;
    });

    let adresse = Adresse {
        api,
        secret: SECRET.to_owned(),
        selecteur: NOM.to_owned(),
    };
    assert_eq!(
        basculer(&adresse, "sortie-b").await,
        Issue::Faite {
            sortie: "sortie-b".to_owned()
        }
    );
}
