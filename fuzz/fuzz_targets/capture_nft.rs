//! Le comparateur nft hors ligne de la CLI (`prove nft --attendu A --observe
//! B`): `bifrost_cli::preuve_nft::verifier_avec`, le chemin de `verifier` sans
//! ses deux lectures de fichier. Il passe chaque capture par le lecteur JSON
//! strict, l'analyseur de capture et ses objets nommes, puis les compare.
//!
//! Frontiere: les deux fichiers sont designes a la CLI par l'utilisateur et
//! lus sous son compte; l'observe peut venir d'un autre poste. Le meme
//! analyseur lit la sortie de `nft -j list ruleset` (`--actif`) et la reference
//! que `--politique` tire d'une intention.
//!
//! L'entree se coupe au premier octet nul, qu'aucun JSON valide ne porte:
//! l'attendu avant, l'observe apres. Sans octet nul, l'entree est comparee a
//! elle-meme.
//!
//! Au-dela de l'absence de panique, la cible verifie:
//! - le code de sortie suit le verdict; un verdict rendu porte ses deux
//!   comptes, un NON MESURE nomme l'entree en cause et aucun ecart;
//! - une capture acceptee comme reference, comparee a elle-meme, correspond
//!   sans ecart et avec des comptes egaux; refusee, c'est l'attendu qui est
//!   nomme;
//! - deux captures acceptees chacune comme reference se comparent de la meme
//!   facon dans les deux sens: meme verdict, memes ecarts, dans le meme ordre.
#![no_main]

use bifrost_cli::preuve_nft::verifier_avec;
use libfuzzer_sys::fuzz_target;
use serde_json::{Value, json};

/// Le rapport de la comparaison, serialise comme `--json` l'ecrit, apres les
/// controles valables pour toute paire.
fn comparer(attendu: &[u8], observe: &[u8]) -> Value {
    let rapport = verifier_avec(|| Ok(attendu.to_vec()), || Ok(observe.to_vec()));
    let code = rapport.code();
    let r = serde_json::to_value(&rapport).expect("un rapport se serialise");
    let selon_le_verdict = match r["verdict"].as_str() {
        Some("MATCH") => 0,
        Some("MISMATCH") => 1,
        Some("UNMEASURED") => 2,
        autre => panic!("verdict inconnu: {autre:?}"),
    };
    assert_eq!(
        code, selon_le_verdict,
        "code de sortie et verdict divergent"
    );
    if code < 2 {
        assert!(
            r["failed_input"].is_null(),
            "verdict rendu avec une entree en cause"
        );
        assert!(
            r["expected_counts"].is_object() && r["observed_counts"].is_object(),
            "verdict rendu sans ses comptes"
        );
        assert_eq!(
            code == 0,
            r["differences"] == json!([]),
            "verdict et ecarts divergent"
        );
    } else {
        assert!(
            matches!(r["failed_input"].as_str(), Some("expected" | "observed")),
            "NON MESURE sans l'entree en cause"
        );
        assert_eq!(r["differences"], json!([]), "NON MESURE avec des ecarts");
    }
    r
}

fuzz_target!(|octets: &[u8]| {
    let (attendu, observe) = match octets.iter().position(|o| *o == 0) {
        Some(i) => (&octets[..i], &octets[i + 1..]),
        None => (octets, octets),
    };
    let aller = comparer(attendu, observe);
    if attendu == observe {
        if aller["failed_input"].is_null() {
            assert_eq!(
                aller["verdict"], "MATCH",
                "une capture ne se compare pas a elle-meme"
            );
            assert_eq!(
                aller["expected_counts"], aller["observed_counts"],
                "une capture comparee a elle-meme change de comptes"
            );
        } else {
            assert_eq!(
                aller["failed_input"], "expected",
                "une capture lue comme reference est refusee comme observee"
            );
        }
        return;
    }
    let retour = comparer(observe, attendu);
    if aller["failed_input"].is_null() && retour["failed_input"].is_null() {
        assert_eq!(
            (&aller["verdict"], &aller["differences"]),
            (&retour["verdict"], &retour["differences"]),
            "la comparaison depend du sens"
        );
    }
});
