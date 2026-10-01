//! Ce que le daemon lit du reseau et du coeur, en analyseurs ecrits a la main:
//! `quic::lire_reponse`, `tls::decouper`, `coeurs::socks` et `coeurs::clash`.
//!
//! Frontiere: les deux premiers lisent la reponse d'un serveur distant
//! quelconque (sonde QUIC, mesure de la volee TLS d'un site emprunte); les deux
//! suivants lisent ce que rend le coeur tiers (relais UDP du SOCKS5, API Clash
//! sur la boucle locale), lui-meme expose au reseau. Tous tournent dans le
//! binaire du daemon, root sous Linux, LocalSystem sous Windows.
//!
//! Le premier octet choisit l'analyseur, le reste est la donnee recue.
//!
//! Au-dela de l'absence de panique, la cible verifie:
//! - une volee TLS non tronquee couvre exactement le flux lu, et une volee
//!   tronquee ne le couvre pas;
//! - la charge d'un datagramme SOCKS5 est la fin de la trame, et un datagramme
//!   a adresse IP se reecrit par `entete_datagramme`, l'encodeur de production,
//!   puis se relit a l'identique;
//! - le corps d'une reponse HTTP de l'API Clash est la fin de la reponse.
#![no_main]

use bifrost_daemon::coeurs::{clash, socks};
use bifrost_daemon::{quic, tls};
use libfuzzer_sys::fuzz_target;

fn quic(donnee: &[u8]) {
    let reponse = quic::lire_reponse(donnee);
    assert_eq!(
        reponse.is_none(),
        donnee.is_empty(),
        "rien lu d'un datagramme"
    );
}

fn tls(donnee: &[u8]) {
    let volee = tls::decouper(donnee);
    assert_eq!(
        volee.tronquee,
        volee.total() != donnee.len(),
        "une volee tronquee si et seulement si elle ne couvre pas le flux"
    );
    let vue = tls::Observation::Vue(volee);
    let _ = tls::taille_exploitable(&vue);
    let _ = tls::conclure_site_emprunte(&vue, &vue);
}

fn socks(donnee: &[u8]) {
    let _ = socks::code_de_reponse(donnee);
    let _ = socks::salutation_acceptee(donnee);
    let _ = socks::sous_negociation_acceptee(donnee);
    let Ok((source, charge)) = socks::lire_datagramme(donnee) else {
        return;
    };
    assert!(
        donnee.ends_with(charge),
        "la charge n'est pas la fin de la trame"
    );
    // Les deux types d'adresse que `entete_datagramme` sait ecrire.
    if matches!(
        donnee.get(3),
        Some(&socks::TYPE_IPV4) | Some(&socks::TYPE_IPV6)
    ) {
        let mut refaite = socks::entete_datagramme(source);
        refaite.extend_from_slice(charge);
        let (source_relue, charge_relue) =
            socks::lire_datagramme(&refaite).expect("un datagramme reecrit doit se relire");
        assert_eq!(source_relue, source, "l'aller-retour change la source");
        assert_eq!(charge_relue, charge, "l'aller-retour change la charge");
    }
}

fn clash(donnee: &[u8]) {
    let Ok(texte) = std::str::from_utf8(donnee) else {
        return;
    };
    if let Some((_, corps)) = clash::depouiller(texte) {
        assert!(
            texte.ends_with(corps),
            "le corps n'est pas la fin de la reponse"
        );
        let _ = clash::version_annoncee(corps);
        let _ = clash::selection_courante(corps);
    }
    let _ = clash::version_annoncee(texte);
    let _ = clash::selection_courante(texte);
}

fuzz_target!(|octets: &[u8]| {
    let Some((&choix, donnee)) = octets.split_first() else {
        return;
    };
    match choix % 4 {
        0 => quic(donnee),
        1 => tls(donnee),
        2 => socks(donnee),
        _ => clash(donnee),
    }
});
