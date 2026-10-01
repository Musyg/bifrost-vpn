//! Les reponses du daemon que les preuves prennent pour attendu, lues par les
//! trois lecteurs de `bifrost_cli::declaration`: `analyser`
//! (`declaration-pare-feu`, pour `prove nft` et `prove wfp`),
//! `analyser_routage` (`declaration-routage`, `prove routes` sous Linux) et
//! `analyser_routage_windows` (`declaration-routage-windows`, `prove routes`
//! sous Windows, pur et compile sur les deux plateformes).
//!
//! Frontiere: le daemon (root, LocalSystem) ecrit la trame; la CLI la lit sous
//! le compte de l'utilisateur, une fois l'identite du serveur admise. Un
//! daemon d'une autre version, ou defaillant, ecrit ce qu'il veut. Les trois
//! lecteurs lisent la meme enveloppe, une reponse IPC: chaque entree est
//! donnee aux trois.
//!
//! Au-dela de l'absence de panique, la cible verifie:
//! - un lecteur au plus accepte une trame;
//! - aller-retour: une declaration lue, ecrite comme le daemon l'ecrit
//!   (`Response` par serde_json), se relit a l'identique;
//! - une declaration de routage posee designe le meme plan
//!   (`plan_de_la_declaration`) que l'intention qui porte les memes valeurs
//!   (`plan_de_l_intention`), sous Linux comme sous Windows, ou les deux
//!   chemins la refusent.
#![no_main]

use bifrost_cli::declaration::{analyser, analyser_routage, analyser_routage_windows};
use bifrost_cli::{preuve_routes, preuve_routes_windows};
use bifrost_ipc::protocol::Response;
use libfuzzer_sys::fuzz_target;
use serde_json::{Value, json};

/// L'intention qui porte les valeurs d'un plan declare: le plan tel que le
/// daemon l'ecrit, plus les cles propres a l'intention.
fn intention(mut plan: Value, propres: Value) -> Value {
    let objet = plan.as_object_mut().expect("un plan s'ecrit en objet");
    for (cle, valeur) in propres.as_object().expect("des cles").clone() {
        objet.insert(cle, valeur);
    }
    plan
}

fn ecrite(reponse: Response) -> Vec<u8> {
    serde_json::to_vec(&reponse).expect("une reponse se serialise")
}

fuzz_target!(|octets: &[u8]| {
    let pare_feu = analyser(octets);
    let routage = analyser_routage(octets);
    let windows = analyser_routage_windows(octets);
    assert!(
        [pare_feu.is_ok(), routage.is_ok(), windows.is_ok()]
            .iter()
            .filter(|lue| **lue)
            .count()
            <= 1,
        "une trame lue par deux lecteurs"
    );

    if let Ok(d) = pare_feu {
        let relue = analyser(&ecrite(Response::DeclarationPareFeu(Box::new(d.clone()))));
        assert_eq!(
            relue,
            Ok(d),
            "la declaration du pare-feu change a l'aller-retour"
        );
    }

    if let Ok(d) = routage {
        let relue = analyser_routage(&ecrite(Response::DeclarationRoutage(Box::new(d.clone()))));
        assert_eq!(
            relue.as_ref(),
            Ok(&d),
            "la declaration de routage change a l'aller-retour"
        );
        if let Some(plan) = &d.plan {
            let ecrit = serde_json::to_value(plan).expect("un plan se serialise");
            let par_l_intention =
                preuve_routes::plan_de_l_intention(intention(ecrit, json!({"schema_version": 1})));
            match (preuve_routes::plan_de_la_declaration(&d), par_l_intention) {
                (Ok(a), Ok(b)) => assert_eq!(a, b, "les deux chemins designent deux plans"),
                (Err(_), Err(_)) => {}
                autre => panic!("un seul des deux chemins accepte le plan: {autre:?}"),
            }
        }
    }

    if let Ok(d) = windows {
        let relue = analyser_routage_windows(&ecrite(Response::DeclarationRoutageWindows(
            Box::new(d.clone()),
        )));
        assert_eq!(
            relue.as_ref(),
            Ok(&d),
            "la declaration de routage Windows change a l'aller-retour"
        );
        if let Some(plan) = &d.plan {
            let ecrit = serde_json::to_value(plan).expect("un plan se serialise");
            let par_l_intention = preuve_routes_windows::plan_de_l_intention(intention(
                ecrit,
                json!({"schema_version": 1, "plateforme": "windows"}),
            ));
            match (
                preuve_routes_windows::plan_de_la_declaration(&d),
                par_l_intention,
            ) {
                (Ok(a), Ok(b)) => assert_eq!(a, b, "les deux chemins designent deux plans"),
                (Err(_), Err(_)) => {}
                autre => panic!("un seul des deux chemins accepte le plan: {autre:?}"),
            }
        }
    }
});
