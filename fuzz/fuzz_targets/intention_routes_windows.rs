//! L'intention de `prove routes --intention` sous Windows, lue comme la CLI la
//! lit: le lecteur JSON strict `bifrost_cli::preuve_nft::Unique`, puis
//! `bifrost_cli::preuve_routes_windows::plan_de_l_intention`, qui rend le plan
//! du produit (`bifrost_core::routage_windows::PlanWindows`). Le lecteur est
//! pur et compile sur les deux plateformes; seule la collecte est Windows.
//!
//! Frontiere: le fichier est designe a la CLI par l'utilisateur et lu sous son
//! compte, avant toute lecture du systeme.
//!
//! Au-dela de l'absence de panique, la cible verifie pour une intention lue:
//! le plan porte l'interface, la MTU et les familles ecrites.
//!
//! Et pour toute entree que le lecteur strict accepte: les memes valeurs,
//! declarees par le daemon dans une trame `declaration-routage-windows`,
//! designent le meme plan par
//! `bifrost_cli::declaration::analyser_routage_windows` puis
//! `bifrost_cli::preuve_routes_windows::plan_de_la_declaration`, ou sont
//! refusees par les deux chemins.
#![no_main]

use bifrost_cli::declaration::analyser_routage_windows;
use bifrost_cli::preuve_nft::Unique;
use bifrost_cli::preuve_routes_windows::{plan_de_l_intention, plan_de_la_declaration};
use bifrost_core::routage::Famille;
use bifrost_core::routage_windows::PlanWindows;
use libfuzzer_sys::fuzz_target;
use serde_json::{Map, Value, json};

/// La trame que le daemon ecrirait pour les valeurs de cette intention: son
/// objet sans `schema_version` ni `plateforme`, en `plan` d'une declaration
/// posee. Rien si l'entree n'est pas un objet de sept cles, en version 1, pour
/// Windows.
fn declaree(objet: &Map<String, Value>) -> Option<Vec<u8>> {
    if objet.len() != 7
        || objet.get("schema_version") != Some(&json!(1))
        || objet.get("plateforme") != Some(&json!("windows"))
    {
        return None;
    }
    let mut plan = objet.clone();
    plan.remove("schema_version");
    plan.remove("plateforme");
    let trame = json!({
        "result": "declaration-routage-windows",
        "schema_version": 1,
        "instance": "0".repeat(48),
        "application": 1,
        "issue": "pose",
        "plan": plan,
    });
    Some(serde_json::to_vec(&trame).expect("une trame se serialise"))
}

fn controler(plan: &PlanWindows, objet: &Map<String, Value>) {
    assert_eq!(
        Some(plan.interface.as_str()),
        objet["interface"].as_str(),
        "le plan ne porte pas l'interface ecrite"
    );
    assert_eq!(
        Some(u64::from(plan.mtu)),
        objet["mtu"].as_u64(),
        "le plan ne porte pas la MTU ecrite"
    );
    let ecrites: Vec<Famille> = objet["familles"]
        .as_array()
        .expect("des familles lues sont une liste")
        .iter()
        .map(|f| match f.as_str() {
            Some("ipv4") => Famille::Ipv4,
            Some("ipv6") => Famille::Ipv6,
            autre => panic!("famille lue inconnue: {autre:?}"),
        })
        .collect();
    assert_eq!(
        plan.familles(),
        ecrites,
        "le plan ne porte pas les familles ecrites"
    );
}

fuzz_target!(|octets: &[u8]| {
    let Ok(Unique(valeur)) = serde_json::from_slice::<Unique>(octets) else {
        return;
    };
    let objet = valeur.as_object().cloned();
    let lue = plan_de_l_intention(valeur);
    if let (Ok(plan), Some(objet)) = (&lue, &objet) {
        controler(plan, objet);
    }
    let Some(trame) = objet.as_ref().and_then(declaree) else {
        assert!(
            lue.is_err(),
            "intention lue sans etre un objet Windows de version 1"
        );
        return;
    };
    let par_la_declaration = analyser_routage_windows(&trame).map(|d| plan_de_la_declaration(&d));
    match (lue, par_la_declaration) {
        (Ok(plan), Ok(Ok(declare))) => {
            assert_eq!(plan, declare, "les deux chemins designent deux plans")
        }
        (Ok(_), autre) => panic!("intention lue, declaration refusee: {autre:?}"),
        (Err(raison), Ok(Ok(_))) => panic!("intention refusee ({raison}), declaration lue"),
        (Err(_), _) => {}
    }
});
