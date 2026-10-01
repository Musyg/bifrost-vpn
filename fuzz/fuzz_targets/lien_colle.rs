//! Le lien colle par une personne: `bifrost_amorce::colle::lire`, sans phrase.
//!
//! Frontiere: le lien arrive d'une messagerie, d'un QR code ou d'un courriel,
//! donc d'un inconnu. La CLI le decode sous le compte de l'utilisateur, AVANT
//! toute verification de signature: c'est la premiere chose qu'un tiers fait
//! lire au produit.
//!
//! Au-dela de l'absence de panique, la cible verifie:
//! - la lecture est deterministe: meme lien, meme issue, meme message;
//! - un lien lu n'est jamais un lien que `est_chiffre` reconnait;
//! - un lien nu se lit a l'identique avec ou sans phrase de passe (la phrase ne
//!   sert qu'au lien chiffre, elle ne doit rien changer ici);
//! - aller-retour: ce qui a ete lu se reecrit par `colle::ecrire`, l'encodeur
//!   de production, et se relit a l'identique.
#![no_main]

use bifrost_amorce::colle;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|octets: &[u8]| {
    let Ok(lien) = std::str::from_utf8(octets) else {
        return;
    };
    let premiere = colle::lire(lien, None);
    let seconde = colle::lire(lien, None);
    match (&premiere, &seconde) {
        (Ok(a), Ok(b)) => {
            assert_eq!(a.profil, b.profil, "deux lectures, deux profils");
            assert_eq!(a.signature, b.signature, "deux lectures, deux signatures");
        }
        (Err(a), Err(b)) => assert_eq!(a, b, "deux lectures, deux refus differents"),
        _ => panic!("deux lectures du meme lien ne rendent pas la meme issue"),
    }
    let Ok(recu) = premiere else {
        return;
    };

    assert!(
        !colle::est_chiffre(lien),
        "un lien que est_chiffre reconnait a ete lu sans phrase"
    );

    let avec_phrase = colle::lire(lien, Some("phrase-sans-objet"))
        .expect("un lien nu lu sans phrase doit se lire aussi avec une phrase");
    assert_eq!(avec_phrase.profil, recu.profil);
    assert_eq!(avec_phrase.signature, recu.signature);

    let reecrit = colle::ecrire(&recu.profil, &recu.signature);
    let relu = colle::lire(&reecrit, None).expect("un lien ecrit par colle::ecrire doit se relire");
    assert_eq!(relu.profil, recu.profil, "l'aller-retour change le profil");
    assert_eq!(
        relu.signature, recu.signature,
        "l'aller-retour change la signature"
    );
});
