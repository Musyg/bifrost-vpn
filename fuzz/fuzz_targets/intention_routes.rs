//! L'intention de `prove routes --intention` sous Linux, lue comme la CLI la
//! lit: le lecteur JSON strict `bifrost_cli::preuve_nft::Unique`, puis
//! `bifrost_cli::preuve_routes::plan_de_l_intention`, qui rend le plan du
//! produit (`bifrost_core::routage::Plan`).
//!
//! Frontiere: le fichier est designe a la CLI par l'utilisateur et lu sous son
//! compte, avant toute lecture du noyau.
//!
//! Au-dela de l'absence de panique, la cible verifie pour une intention lue:
//! - le plan porte le chemin, l'interface, la marque, la table et le compte
//!   ecrits;
//! - dans chaque famille, il a un ordre d'evaluation, une seule regle vers la
//!   table du tunnel et une seule route, dans cette table, sur l'interface:
//!   sans quoi la comparaison au noyau ne pourrait rien rendre.
//!
//! Et pour toute entree que le lecteur strict accepte: les memes valeurs,
//! declarees par le daemon dans une trame `declaration-routage`, designent le
//! meme plan par `bifrost_cli::declaration::analyser_routage` puis
//! `bifrost_cli::preuve_routes::plan_de_la_declaration`, ou sont refusees par
//! les deux chemins. Le meme plan ne se juge pas autrement selon qui le
//! declare.
#![no_main]

use bifrost_cli::declaration::analyser_routage;
use bifrost_cli::preuve_nft::Unique;
use bifrost_cli::preuve_routes::{plan_de_l_intention, plan_de_la_declaration};
use bifrost_core::routage::{Chemin, Consultation, Famille, Plan};
use libfuzzer_sys::fuzz_target;
use serde_json::{Map, Value, json};

/// La trame que le daemon ecrirait pour les valeurs de cette intention: son
/// objet sans `schema_version`, en `plan` d'une declaration posee. Rien si
/// l'entree n'est pas un objet de six cles en version 1.
fn declaree(objet: &Map<String, Value>) -> Option<Vec<u8>> {
    if objet.len() != 6 || objet.get("schema_version") != Some(&json!(1)) {
        return None;
    }
    let mut plan = objet.clone();
    plan.remove("schema_version");
    let trame = json!({
        "result": "declaration-routage",
        "schema_version": 1,
        "instance": "0".repeat(48),
        "application": 1,
        "issue": "pose",
        "plan": plan,
    });
    Some(serde_json::to_vec(&trame).expect("une trame se serialise"))
}

fn controler(plan: &Plan, objet: &Map<String, Value>) {
    assert_eq!(
        Some(plan.interface.as_str()),
        objet["interface"].as_str(),
        "le plan ne porte pas l'interface ecrite"
    );
    let entier = |cle: &str| objet[cle].as_u64();
    match plan.chemin {
        Chemin::WireGuard { marque, table } => {
            assert_eq!(objet["chemin"], "wireguard", "chemin change");
            assert_eq!(
                (Some(u64::from(marque)), Some(u64::from(table))),
                (entier("fwmark"), entier("table")),
                "marque ou table changee"
            );
        }
        Chemin::Coeur { compte } => {
            assert_eq!(objet["chemin"], "coeur", "chemin change");
            assert_eq!(compte.map(u64::from), entier("coeur_uid"), "compte change");
        }
    }
    let tunnel = plan.table_du_tunnel();
    for famille in Famille::TOUTES {
        let ordre = plan
            .ordre_d_evaluation(famille)
            .expect("un plan lu sans ordre d'evaluation");
        assert_eq!(
            ordre
                .iter()
                .filter(|r| r.consultation == Consultation::Table(tunnel))
                .count(),
            1,
            "un plan lu sans exactement une regle vers le tunnel"
        );
        let routes = plan.routes(famille);
        assert!(
            routes.len() == 1 && routes[0].table == tunnel && routes[0].interface == plan.interface,
            "un plan lu sans exactement sa route du tunnel"
        );
    }
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
            "intention lue sans etre un objet de version 1"
        );
        return;
    };
    let par_la_declaration = analyser_routage(&trame).map(|d| plan_de_la_declaration(&d));
    match (lue, par_la_declaration) {
        (Ok(plan), Ok(Ok(declare))) => {
            assert_eq!(plan, declare, "les deux chemins designent deux plans")
        }
        (Ok(_), autre) => panic!("intention lue, declaration refusee: {autre:?}"),
        (Err(raison), Ok(Ok(_))) => panic!("intention refusee ({raison}), declaration lue"),
        (Err(_), _) => {}
    }
});
