//! Le repli classique de `Toile` et de `tirer_une_fois`, sur la boucle locale.
//!
//! Ces deux clients vivent dans `bifrost-amorce`; leurs recettes vivent ici
//! pour une raison mesuree. Le serveur rustls local a besoin d'un certificat
//! engendre, et `rcgen` n'est une dependance de developpement que de ce
//! paquet: l'ajouter a `bifrost-amorce` ajoute une ligne a `Cargo.lock`
//! (mesure du 12/10/2026 sur dev-windows), ce que cette tranche s'interdit.
//! `bifrost-amorce` est une dependance de ce paquet, donc ses recettes
//! d'integration atteignent `Toile` par son chemin de production.
//!
//! Toile valide la chaine contre les racines de Mozilla embarquees: aucun
//! serveur local ne peut la satisfaire sans une couture de test dans le code
//! de production, et il n'y en a pas. Le second essai se juge donc a ce qu'il
//! atteint: un vrai serveur rustls qui repond jusqu'a son certificat, que le
//! client refuse (`UnknownIssuer`). C'est une erreur de certificat, qui
//! n'appelle aucun troisieme essai.
//!
//! Le comportement mesure ici est celui retenu pour Toile (B): ureq rend la
//! meme erreur pour une coupure avant toute reponse du serveur et pour une
//! coupure apres un ServerHello, donc les deux rejouent. La sonde
//! d'inspection, qui compte ses octets, ne rejoue que la premiere: voir ses
//! recettes dans `src/inspection.rs`.

#[allow(dead_code)]
#[path = "commun/banc_tls.rs"]
mod banc_tls;

use banc_tls::{Banc, Conduite, Hello, SECP256R1, SECP384R1, X25519, X25519MLKEM768};
use bifrost_amorce::Canal;
use bifrost_amorce::toile::{Toile, tirer_une_fois};
use std::net::SocketAddr;
use std::time::Duration;

/// Pour les recettes ou aucun delai ne doit jouer.
const LARGE: Duration = Duration::from_secs(5);

/// Pour la recette ou le delai est l'objet.
const COURT: Duration = Duration::from_secs(1);

/// Les marques que l'echec final porte quand le second essai a eu lieu.
const PREMIER: &str = "premier essai";
const SECOND: &str = "second essai";

/// Lance le client sur un fil et attend sa reponse au plus trente secondes:
/// un client qui rejouerait sans borne ne fait pas pendre la recette, il la
/// fait rougir.
fn borne(client: impl FnOnce() -> Result<(), String> + Send + 'static) -> String {
    let (envoi, reception) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = envoi.send(client());
    });
    reception
        .recv_timeout(Duration::from_secs(30))
        .expect("le client n'a pas rendu la main: il rejoue sans borne")
        .expect_err("aucune conduite du banc ne laisse passer une reponse")
}

fn par_toile(adresse: String, delai: Duration) -> String {
    borne(move || Toile::avec_delai(adresse, delai).chercher().map(|_| ()))
}

fn par_tirer_une_fois(adresse: String, delai: Duration) -> String {
    borne(move || tirer_une_fois(&adresse, 1024, delai).map(|_| ()))
}

fn https(banc: &Banc) -> String {
    format!("https://{}/tunnel.toml", banc.adresse)
}

/// Les ClientHello vus par le banc, chacun complet.
fn hellos(banc: &Banc) -> Vec<Hello> {
    banc.vus()
        .into_iter()
        .map(|h| h.expect("chaque connexion doit porter un ClientHello complet"))
        .collect()
}

fn hybride_en_tete(h: &Hello) {
    assert_eq!(
        h.groupes.first(),
        Some(&X25519MLKEM768),
        "le premier ClientHello doit mettre X25519MLKEM768 en tete: {h:?}"
    );
    assert_eq!(
        h.parts.first().map(|p| p.0),
        Some(X25519MLKEM768),
        "le premier ClientHello doit porter la part hybride: {h:?}"
    );
}

fn rien_que_du_classique(h: &Hello) {
    assert!(
        !h.offre_du_post_quantique(),
        "le second essai ne doit offrir ni groupe ni part hybride: {h:?}"
    );
    assert_eq!(
        h.groupes,
        [X25519, SECP256R1, SECP384R1],
        "le second essai offre X25519, P-256, P-384: {h:?}"
    );
}

/// Le boitier intolerant: il coupe tout ClientHello qui offre l'hybride. Le
/// second essai, classique, atteint le vrai serveur jusqu'a son certificat.
#[test]
fn toile_rejoue_une_fois_en_classique_jusqu_au_certificat() {
    let banc = Banc::monter(Conduite::CoupeSiPostQuantique);
    let e = par_toile(https(&banc), LARGE);
    let vus = hellos(&banc);
    assert_eq!(vus.len(), 2, "deux connexions exactement: {vus:?} ({e})");
    hybride_en_tete(&vus[0]);
    rien_que_du_classique(&vus[1]);
    assert!(e.contains(PREMIER) && e.contains(SECOND), "{e}");
    assert!(
        e.contains("UnknownIssuer"),
        "le second essai doit atteindre le certificat du serveur: {e}"
    );
}

#[test]
fn tirer_une_fois_rejoue_une_fois_en_classique_jusqu_au_certificat() {
    let banc = Banc::monter(Conduite::CoupeSiPostQuantique);
    let e = par_tirer_une_fois(https(&banc), LARGE);
    let vus = hellos(&banc);
    assert_eq!(vus.len(), 2, "deux connexions exactement: {vus:?} ({e})");
    hybride_en_tete(&vus[0]);
    rien_que_du_classique(&vus[1]);
    assert!(e.contains(PREMIER) && e.contains(SECOND), "{e}");
    assert!(e.contains("UnknownIssuer"), "{e}");
}

/// Deux essais exactement, jamais trois, et l'echec nomme les deux.
fn coupe_toujours(client: &str, par: fn(String, Duration) -> String) {
    let banc = Banc::monter(Conduite::CoupeToujours);
    let e = par(https(&banc), LARGE);
    let vus = hellos(&banc);
    assert_eq!(
        vus.len(),
        2,
        "{client}: deux essais, jamais trois: {vus:?} ({e})"
    );
    hybride_en_tete(&vus[0]);
    rien_que_du_classique(&vus[1]);
    assert!(e.contains(PREMIER) && e.contains(SECOND), "{client}: {e}");
    assert_eq!(
        e.matches("unexpected end of file").count(),
        2,
        "{client}: l'echec doit nommer l'erreur de chacun des deux essais: {e}"
    );
}

#[test]
fn un_ecouteur_qui_coupe_toujours_voit_deux_essais_de_toile_et_jamais_trois() {
    coupe_toujours("toile", par_toile);
}

#[test]
fn un_ecouteur_qui_coupe_toujours_voit_deux_essais_de_tirer_une_fois_et_jamais_trois() {
    coupe_toujours("tirer_une_fois", par_tirer_une_fois);
}

/// Le repli sur delai: une adresse muette coute deux delais.
#[test]
fn un_serveur_muet_est_rejoue_une_fois() {
    let banc = Banc::monter(Conduite::Silence);
    let e = par_toile(https(&banc), COURT);
    let vus = hellos(&banc);
    assert_eq!(
        vus.len(),
        2,
        "le silence appelle le second essai: {vus:?} ({e})"
    );
    rien_que_du_classique(&vus[1]);
    assert_eq!(e.matches("timeout").count(), 2, "{e}");
}

/// Une alerte est une reponse du serveur: aucun second essai.
#[test]
fn une_alerte_n_appelle_aucun_second_essai() {
    let banc = Banc::monter(Conduite::Alerte);
    let e = par_toile(https(&banc), LARGE);
    let vus = hellos(&banc);
    assert_eq!(vus.len(), 1, "une alerte ne se rejoue pas: {vus:?} ({e})");
    assert!(e.contains("HandshakeFailure") && !e.contains(SECOND), "{e}");
}

/// Un certificat refuse: aucun second essai, quel que soit l'echange.
#[test]
fn un_certificat_refuse_n_appelle_aucun_second_essai() {
    let banc = Banc::monter(Conduite::Sert);
    let e = par_toile(https(&banc), LARGE);
    let vus = hellos(&banc);
    assert_eq!(
        vus.len(),
        1,
        "un certificat refuse ne se rejoue pas: {vus:?} ({e})"
    );
    hybride_en_tete(&vus[0]);
    assert!(e.contains("UnknownIssuer") && !e.contains(SECOND), "{e}");
}

/// Comportement B, retenu pour Toile: une coupure APRES un ServerHello rejoue
/// aussi, ureq ne la distinguant pas d'une coupure avant toute reponse. La
/// sonde d'inspection, elle, ne la rejoue pas.
#[test]
fn comportement_b_une_coupure_apres_un_server_hello_rejoue_aussi() {
    let banc = Banc::monter(Conduite::ServerHelloPuisCoupe);
    let e = par_toile(https(&banc), LARGE);
    let vus = hellos(&banc);
    assert_eq!(vus.len(), 2, "B rejoue apres un ServerHello: {vus:?} ({e})");
    rien_que_du_classique(&vus[1]);
    assert!(e.contains(PREMIER) && e.contains(SECOND), "{e}");
}

/// Une connexion refusee n'a porte aucun ClientHello: aucun second essai.
///
/// Le delai est large expres: sous Windows, une connexion vers un port ferme
/// de la boucle locale insiste environ deux secondes avant d'etre refusee, et
/// un delai plus court la ferait rendre comme un delai depasse, qui rejoue
/// (mesure du 12/10/2026 sur dev-windows).
#[test]
fn une_connexion_refusee_n_appelle_aucun_second_essai() {
    // Un port lie et tenu sans ecoute: personne ne peut le prendre pendant la
    // recette, et toute connexion y est refusee.
    let tenu = tokio::net::TcpSocket::new_v4().expect("socket");
    tenu.bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .expect("liaison sur la boucle locale");
    let port = tenu.local_addr().expect("adresse liee").port();
    let e = par_toile(format!("https://127.0.0.1:{port}/tunnel.toml"), LARGE);
    assert!(
        e.contains("Connection refused") && !e.contains(SECOND),
        "une connexion refusee ne se rejoue pas: {e}"
    );
}

/// Sans TLS, pas de ClientHello: le repli ne changerait rien au second essai,
/// et il n'a pas lieu.
#[test]
fn une_adresse_en_clair_n_appelle_aucun_second_essai() {
    let banc = Banc::monter(Conduite::CoupeToujours);
    let e = par_toile(format!("http://{}/tunnel.toml", banc.adresse), LARGE);
    let vus = banc.vus();
    assert_eq!(vus.len(), 1, "en clair, une seule connexion: {vus:?} ({e})");
    assert!(!e.contains(SECOND), "{e}");
}
