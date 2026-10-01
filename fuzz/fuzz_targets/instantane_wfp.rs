//! Ce que la preuve WFP lit du moteur: `bifrost_firewall::instantane_wfp`,
//! `Sid::lire_texte`, `Sid::lire_octets` et `lire_dacl`.
//!
//! Frontiere: les octets viennent du moteur de filtrage de Windows (descripteur
//! de securite d'une condition `ALE_USER_ID`, SID binaire) et le texte d'une
//! declaration du daemon; la CLI les lit sous le compte de l'utilisateur. Les
//! analyseurs sont purs et compiles sur les deux plateformes.
//!
//! Le premier octet choisit l'analyseur, le reste est la donnee lue.
//!
//! Au-dela de l'absence de panique, la cible verifie les allers-retours avec
//! les encodeurs purs du meme module:
//! - un SID textuel lu se reecrit (`Sid::texte`) a l'identique, sa forme
//!   binaire (`Sid::octets`) se relit en lui-meme et sur toute sa longueur;
//! - un SID binaire lu est exactement la forme binaire qu'il reecrit, et le
//!   descripteur que `descripteur_autorisant` construit pour lui se relit en
//!   une liste qui l'autorise, lui seul.
#![no_main]

use bifrost_firewall::instantane_wfp::{Ace, Dacl, Sid, descripteur_autorisant, lire_dacl};
use libfuzzer_sys::fuzz_target;

fn binaire_se_relit(sid: &Sid) {
    let octets = sid.octets();
    assert_eq!(
        Sid::lire_octets(&octets),
        Some((sid.clone(), octets.len())),
        "la forme binaire ne se relit pas"
    );
}

fn texte(donnee: &[u8]) {
    let Ok(texte) = std::str::from_utf8(donnee) else {
        return;
    };
    let Some(sid) = Sid::lire_texte(texte) else {
        return;
    };
    assert_eq!(
        sid.texte(),
        texte,
        "un SID textuel lu ne se reecrit pas a l'identique"
    );
    binaire_se_relit(&sid);
}

fn binaire(donnee: &[u8]) {
    let Some((sid, longueur)) = Sid::lire_octets(donnee) else {
        return;
    };
    assert_eq!(
        sid.octets(),
        &donnee[..longueur],
        "un SID binaire lu n'est pas sa propre forme"
    );
    let masque = 0x0001_0000;
    assert_eq!(
        lire_dacl(&descripteur_autorisant(&sid, masque)),
        Some(Dacl::Liste(vec![Ace::Acces {
            genre: bifrost_firewall::instantane_wfp::ACE_AUTORISATION,
            drapeaux: 0,
            masque,
            sid,
        }])),
        "le descripteur construit ne se relit pas"
    );
}

fn descripteur(donnee: &[u8]) {
    let premiere = lire_dacl(donnee);
    assert_eq!(
        premiere,
        lire_dacl(donnee),
        "deux lectures du meme descripteur"
    );
    if let Some(Dacl::Liste(entrees)) = premiere {
        for entree in entrees {
            if let Ace::Acces { sid, .. } = entree {
                binaire_se_relit(&sid);
            }
        }
    }
}

fuzz_target!(|octets: &[u8]| {
    let Some((&choix, donnee)) = octets.split_first() else {
        return;
    };
    match choix % 3 {
        0 => texte(donnee),
        1 => binaire(donnee),
        _ => descripteur(donnee),
    }
});
