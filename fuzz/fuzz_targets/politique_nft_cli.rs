//! L'intention de `prove nft --politique`, lue comme la CLI la lit: le lecteur
//! JSON strict `bifrost_cli::preuve_nft::Unique`, puis
//! `bifrost_firewall::politique_nft::Politique::lire`, puis la reference
//! qu'elle en tire, rendue au comparateur de la CLI
//! (`bifrost_cli::preuve_nft::verifier_avec`).
//!
//! Frontiere: le fichier d'intention est designe a la CLI par l'utilisateur,
//! qui le lit sous son propre compte. La cible `politique_nft` lit la meme
//! forme par serde_json, sans le lecteur strict ni l'analyseur de la CLI.
//!
//! Au-dela de l'absence de panique, la cible verifie:
//! - le lecteur strict ne lit jamais autrement que serde_json: ce qu'il
//!   accepte, serde_json le lit a l'identique (il refuse seulement davantage:
//!   cles dupliquees, nombres non entiers);
//! - la reference d'une intention acceptee est une capture que le comparateur
//!   de la CLI accepte comme reference et qui, comparee a elle-meme,
//!   correspond: sans quoi `prove nft --politique` ne rendrait jamais de
//!   correspondance pour cette intention.
#![no_main]

use bifrost_cli::preuve_nft::{Unique, verifier_avec};
use bifrost_firewall::politique_nft::Politique;
use libfuzzer_sys::fuzz_target;
use serde_json::Value;

fuzz_target!(|octets: &[u8]| {
    let Ok(Unique(valeur)) = serde_json::from_slice::<Unique>(octets) else {
        return;
    };
    assert_eq!(
        serde_json::from_slice::<Value>(octets).ok().as_ref(),
        Some(&valeur),
        "le lecteur strict lit autrement que serde_json"
    );
    let Ok(politique) = Politique::lire(valeur) else {
        return;
    };
    let reference = politique
        .reference()
        .expect("une politique lue doit avoir une reference");
    let capture = serde_json::to_vec(&reference).expect("une reference se serialise");
    let rapport = verifier_avec(|| Ok(capture.clone()), || Ok(capture.clone()));
    let r = serde_json::to_value(&rapport).expect("un rapport se serialise");
    assert_eq!(
        r["verdict"], "MATCH",
        "la reference d'une politique lue ne se compare pas a elle-meme: {}",
        r["reason"]
    );
});
