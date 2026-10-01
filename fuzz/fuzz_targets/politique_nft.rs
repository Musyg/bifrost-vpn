//! L'intention nft: `bifrost_firewall::politique_nft::Politique::lire`, puis
//! la reference qu'en tire `prove nft --politique`.
//!
//! Frontiere: le fichier d'intention est designe a la CLI par l'utilisateur,
//! qui le lit sous son propre compte; la meme forme arrive aussi du daemon,
//! dans la declaration de `prove nft --politique-daemon`. La CLI le passe
//! d'abord par un lecteur JSON strict (`Unique`, cles dupliquees refusees) qui
//! vit dans le binaire `bifrost-cli` et n'est pas atteignable d'ici: la cible
//! lit le JSON par serde_json, un sur-ensemble de ce que `Unique` laisse passer.
//!
//! Au-dela de l'absence de panique, la cible verifie pour une politique lue:
//! - aller-retour par le daemon: serialisee comme il la declare, elle se relit
//!   a l'identique; projetee depuis sa politique de pare-feu, elle aussi;
//! - sa reference existe, est stable, et porte l'enveloppe `nftables` que
//!   l'analyseur de la CLI exige.
#![no_main]

use bifrost_firewall::politique_nft::Politique;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|octets: &[u8]| {
    let Ok(valeur) = serde_json::from_slice::<serde_json::Value>(octets) else {
        return;
    };
    let Ok(politique) = Politique::lire(valeur) else {
        return;
    };

    let declaree = serde_json::to_value(&politique).expect("une politique lue se serialise");
    assert_eq!(
        Politique::lire(declaree).as_ref(),
        Ok(&politique),
        "la politique change a l'aller-retour"
    );
    let pare_feu = politique
        .firewall_policy()
        .expect("une politique lue se convertit en politique de pare-feu");
    assert_eq!(
        Politique::projeter(&pare_feu),
        politique,
        "la projection ne rend pas la politique lue"
    );

    let reference = politique
        .reference()
        .expect("une politique lue doit avoir une reference");
    assert_eq!(
        politique.reference().as_ref(),
        Ok(&reference),
        "deux references differentes pour la meme politique"
    );
    assert!(
        reference
            .get("nftables")
            .and_then(|v| v.as_array())
            .is_some(),
        "reference sans enveloppe nftables"
    );
});
