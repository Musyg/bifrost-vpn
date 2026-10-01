//! La projection WFP declaree par le daemon:
//! `bifrost_firewall::politique_wfp::PolitiqueWfp::lire`, puis la reference
//! qu'en tire `prove wfp --politique-daemon`.
//!
//! Frontiere: le daemon (LocalSystem) serialise sa projection dans la reponse
//! `declaration-pare-feu`; la CLI la lit sous le compte de l'utilisateur, apres
//! le lecteur strict de la declaration (dans le binaire `bifrost-cli`, hors
//! d'atteinte d'ici). La reference est calculee par le plan WFP pur, sur les
//! deux plateformes.
//!
//! Au-dela de l'absence de panique, la cible verifie pour une projection lue:
//! - aller-retour: serialisee comme le daemon la declare, elle se relit a
//!   l'identique;
//! - son identite se relit en SID;
//! - le calcul de sa reference est deterministe.
#![no_main]

use bifrost_firewall::politique_wfp::PolitiqueWfp;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|octets: &[u8]| {
    let Ok(valeur) = serde_json::from_slice::<serde_json::Value>(octets) else {
        return;
    };
    let Ok(projection) = PolitiqueWfp::lire(valeur) else {
        return;
    };

    let declaree = serde_json::to_value(&projection).expect("une projection lue se serialise");
    assert_eq!(
        PolitiqueWfp::lire(declaree).as_ref(),
        Ok(&projection),
        "la projection change a l'aller-retour"
    );
    projection
        .identite_courante()
        .expect("l'identite d'une projection lue doit se relire");

    assert_eq!(
        projection.reference(),
        projection.reference(),
        "deux calculs de reference divergent"
    );
});
