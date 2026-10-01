//! Le lien chiffre: `bifrost_amorce::colle::lire` avec une phrase de passe.
//!
//! Frontiere: celle de `lien_colle`, un cran plus loin. Le lien vient d'un
//! inconnu, la phrase d'un autre chemin; ce qui est lu avant toute signature
//! est l'en-tete age, son destinataire scrypt et son facteur de travail, puis
//! le clair, qui doit etre un lien nu et rien d'autre.
//!
//! Les graines sont des liens rendus par `colle::ecrire_chiffre`, l'encodeur de
//! production, avec la phrase ci-dessous (une phrase de recette, jamais une
//! phrase reelle). Un lien qui garde son en-tete valide paie un scrypt a chaque
//! execution: cette cible est lente par construction, et sa campagne le dit.
//!
//! Au-dela de l'absence de panique et de depassement memoire, la cible verifie
//! qu'un lien ouvert rend un profil qui se reecrit en lien nu et se relit a
//! l'identique.
#![no_main]

use bifrost_amorce::colle;
use libfuzzer_sys::fuzz_target;

/// La phrase des graines. Forme de `colle::engendrer_phrase`, valeur de recette.
const PHRASE: &str = "0123-4567-89AB-CDEF-GHJK-MNPQ";

fuzz_target!(|octets: &[u8]| {
    let Ok(lien) = std::str::from_utf8(octets) else {
        return;
    };
    let Ok(recu) = colle::lire(lien, Some(PHRASE)) else {
        return;
    };
    let reecrit = colle::ecrire(&recu.profil, &recu.signature);
    let relu = colle::lire(&reecrit, None).expect("le clair d'un lien chiffre doit se reecrire");
    assert_eq!(relu.profil, recu.profil, "l'aller-retour change le profil");
    assert_eq!(
        relu.signature, recu.signature,
        "l'aller-retour change la signature"
    );
});
