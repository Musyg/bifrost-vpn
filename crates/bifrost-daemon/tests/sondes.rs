//! Sonde de largeur de chemin, eprouvee sur de vrais sockets.
//!
//! Les tests unitaires du module ne couvrent que l'interpretation, qui est
//! pure. Ils ne prouvent donc rien de ce qui compte ici: que le bit DF est
//! reellement pose et que le noyau refuse reellement. Une sonde dont le
//! `setsockopt` echouerait en silence rendrait `Vu(true)` partout, y compris
//! sur un chemin etroit, et son seul effet serait de rendre une panne muette
//! encore plus difficile a lire.

use std::net::{SocketAddr, UdpSocket};

use bifrost_daemon::sondes::{paquet_ip_quic, sonder_chemin_quic};
use bifrost_evasion::environnement::Mesure;

/// Cible qui CONSOMME les datagrammes.
///
/// Viser un port ou personne n'ecoute ferait remonter un ICMP port
/// unreachable, que le noyau sert au `send` SUIVANT sur un socket connecte:
/// le temoin echouerait alors pour une raison qui n'a rien a voir avec la
/// taille.
fn cible_qui_ecoute() -> (UdpSocket, SocketAddr) {
    let s = UdpSocket::bind("127.0.0.1:0").expect("liaison de la cible");
    let a = s.local_addr().expect("adresse de la cible");
    (s, a)
}

#[test]
fn la_boucle_locale_porte_un_datagramme_quic_de_pleine_taille() {
    let (_garde, cible) = cible_qui_ecoute();
    // La boucle locale a un MTU de 65536: 1316 octets y passent forcement.
    // Si ce test echoue, ce n'est pas le chemin qui est etroit, c'est la sonde
    // qui est cassee.
    assert_eq!(
        sonder_chemin_quic(cible, true),
        Mesure::Vu(true),
        "un chemin a 65536 refuserait {} octets",
        paquet_ip_quic(true)
    );
}

#[test]
fn un_chemin_etroit_est_vu_comme_tel() {
    // Il n'existe aucun moyen portable de fabriquer un chemin a 1280 depuis un
    // test: cela demande une interface reelle. La mesure se fait donc sur une
    // machine qui en a une, en nommant la cible par l'environnement. Sans
    // elle, le test ne s'execute pas et le dit, plutot que de passer sans rien
    // avoir mesure.
    let Ok(cible) = std::env::var("BIFROST_CHEMIN_ETROIT") else {
        eprintln!(
            "SKIPPED un_chemin_etroit_est_vu_comme_tel: \
             BIFROST_CHEMIN_ETROIT absent, aucune interface a MTU reduit a viser"
        );
        return;
    };
    let cible: SocketAddr = cible
        .parse()
        .expect("BIFROST_CHEMIN_ETROIT doit etre ip:port");
    assert_eq!(
        sonder_chemin_quic(cible, true),
        Mesure::Vu(false),
        "{cible} devait refuser {} octets sans fragmenter",
        paquet_ip_quic(true)
    );
}
