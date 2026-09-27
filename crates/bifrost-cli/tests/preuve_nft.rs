//! Captures synthetiques au format nft JSON: aucun pare-feu n'est touche.

use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::{Value, json};

static NUMERO: AtomicU64 = AtomicU64::new(0);

struct Bac(PathBuf);
impl Bac {
    fn nouveau() -> Self {
        let p = std::env::temp_dir().join(format!(
            "bifrost-nft-{}-{}",
            std::process::id(),
            NUMERO.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&p).unwrap();
        Self(p)
    }
    fn lancer(&self, attendu: &[u8], observe: &[u8], json: bool) -> Output {
        std::fs::write(self.0.join("reference-privee.json"), attendu).unwrap();
        std::fs::write(self.0.join("capture-privee.json"), observe).unwrap();
        let mut c = Command::new(env!("CARGO_BIN_EXE_bifrost-cli"));
        if json {
            c.arg("--json");
        }
        c.args(["--socket", "daemon-inexistant", "prove", "nft", "--attendu"])
            .arg(self.0.join("reference-privee.json"))
            .arg("--observe")
            .arg(self.0.join("capture-privee.json"))
            .output()
            .unwrap()
    }
}
impl Drop for Bac {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

fn reference() -> Value {
    json!({"nftables": [
        {"metainfo": {"version": "1.0.9", "release_name": "fixture", "json_schema_version": 1}},
        {"table": {"family": "inet", "name": "nom-prive", "handle": 1}},
        {"chain": {"family": "inet", "table": "nom-prive", "name": "output", "handle": 2,
            "type": "filter", "hook": "output", "prio": 0, "policy": "drop"}},
        {"rule": {"family": "inet", "table": "nom-prive", "chain": "output", "handle": 3,
            "expr": [{"match": {"op": "==", "left": {"payload": {"protocol": "udp", "field": "dport"}}, "right": 53}}, {"drop": null}]}},
        {"rule": {"family": "inet", "table": "nom-prive", "chain": "output", "handle": 4,
            "expr": [{"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": "wg-prive"}},
                     {"counter": {"packets": 2, "bytes": 100}}, {"accept": null}]}},
        {"rule": {"family": "inet", "table": "nom-prive", "chain": "output", "handle": 5,
            "expr": [{"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "daddr"}}, "right": "192.0.2.9"}}, {"accept": null}]}}
    ]})
}

fn rapport(sortie: Output, code: i32, verdict: &str) -> Value {
    assert_eq!(sortie.status.code(), Some(code), "{sortie:?}");
    assert!(sortie.stderr.is_empty());
    let r: Value = serde_json::from_slice(&sortie.stdout).unwrap();
    assert_eq!(r["scope"], "nft-json-comparison");
    assert_eq!(r["schema_version"], 1);
    assert_eq!(r["verdict"], verdict);
    assert_eq!(r["source"], "user-supplied-snapshots");
    assert_eq!(r["live_kernel"], false);
    assert_eq!(r["generation_verified"], false);
    assert_eq!(r["network_security"], "not-evaluated");
    assert!(r["started_at_unix_ms"].as_u64().is_some());
    assert!(r["completed_at_unix_ms"].as_u64().is_some());
    r
}

fn comparer(observe: &Value, code: i32, verdict: &str) -> Value {
    let b = Bac::nouveau();
    rapport(
        b.lancer(
            &serde_json::to_vec(&reference()).unwrap(),
            &serde_json::to_vec(observe).unwrap(),
            true,
        ),
        code,
        verdict,
    )
}

#[test]
fn seuls_handles_et_compteurs_volatils_peuvent_changer() {
    let mut o = reference();
    o["nftables"][0]["metainfo"]["version"] = "autre-version".into();
    o["nftables"][1]["table"]["handle"] = 500.into();
    o["nftables"][4]["rule"]["handle"] = 900.into();
    o["nftables"][4]["rule"]["expr"][1]["counter"]["packets"] = 6000.into();
    o["nftables"][4]["rule"]["expr"][1]["counter"]["bytes"] = 7000.into();
    let r = comparer(&o, 0, "MATCH");
    assert!(r["failed_input"].is_null());
    assert_eq!(
        r["expected_counts"],
        json!({"tables":1,"chains":1,"rules":3})
    );
    let texte = r.to_string();
    for secret in [
        "nom-prive",
        "wg-prive",
        "192.0.2.9",
        "reference-privee",
        "capture-privee",
        "bifrost-nft-",
    ] {
        assert!(!texte.contains(secret));
    }
}

#[test]
fn les_alterations_de_politique_ne_passent_pas() {
    let mut mutations = Vec::new();
    for (chemin, valeur) in [
        ("/nftables/2/chain/policy", json!("accept")),
        ("/nftables/2/chain/prio", json!(-100)),
        ("/nftables/2/chain/hook", json!("input")),
        ("/nftables/4/rule/expr/0/match/right", json!("eth0")),
        ("/nftables/5/rule/expr/0/match/right", json!("0.0.0.0")),
        ("/nftables/3/rule/expr/0/match/op", json!("!=")),
    ] {
        let mut o = reference();
        *o.pointer_mut(chemin).unwrap() = valeur;
        mutations.push(o);
    }
    let mut o = reference();
    o["nftables"].as_array_mut().unwrap().remove(3);
    mutations.push(o);
    let mut o = reference();
    o["nftables"].as_array_mut().unwrap().swap(3, 4);
    mutations.push(o);
    let mut o = reference();
    o["nftables"][1]["table"]["flags"] = json!(["dormant"]);
    mutations.push(o);
    let mut o = reference();
    for entree in o["nftables"].as_array_mut().unwrap().iter_mut().skip(1) {
        let contenu = entree.as_object_mut().unwrap().values_mut().next().unwrap();
        contenu["family"] = "ip".into();
    }
    mutations.push(o);
    let mut o = reference();
    o["nftables"][4]["rule"]["expr"]
        .as_array_mut()
        .unwrap()
        .remove(1);
    mutations.push(o);
    for o in mutations {
        let r = comparer(&o, 1, "MISMATCH");
        assert!(!r["differences"].as_array().unwrap().is_empty());
    }
}

#[test]
fn le_vide_observe_est_un_ecart_pas_une_mesure_manquante() {
    let mut o = reference();
    o["nftables"].as_array_mut().unwrap().truncate(1);
    let r = comparer(&o, 1, "MISMATCH");
    assert_eq!(r["observed_counts"]["tables"], 0);
    let b = Bac::nouveau();
    let vide = serde_json::to_vec(&o).unwrap();
    rapport(b.lancer(&vide, &vide, true), 2, "UNMEASURED");
}

#[test]
fn ordre_des_declarations_et_regle_tierce_restent_visibles() {
    let mut a = reference();
    a["nftables"].as_array_mut().unwrap().push(json!({"chain": {
        "family":"inet", "table":"nom-prive", "name":"tiers", "type":"filter",
        "hook":"output", "prio":0, "policy":"accept"
    }}));
    let mut o = a.clone();
    o["nftables"].as_array_mut().unwrap().swap(2, 6);
    let b = Bac::nouveau();
    let r = rapport(
        b.lancer(
            &serde_json::to_vec(&a).unwrap(),
            &serde_json::to_vec(&o).unwrap(),
            true,
        ),
        1,
        "MISMATCH",
    );
    assert_eq!(r["differences"], json!(["object-order"]));
    comparer(&a, 1, "MISMATCH");
}

#[test]
fn schema_inconnu_objets_non_geres_et_parents_absents_sont_non_mesures() {
    let mut mutations = Vec::new();
    let mut o = reference();
    o["nftables"][0]["metainfo"]["json_schema_version"] = 2.into();
    mutations.push(o);
    let mut o = reference();
    o["nftables"]
        .as_array_mut()
        .unwrap()
        .push(json!({"set":{"name":"cache"}}));
    mutations.push(o);
    let mut o = reference();
    o["nftables"].as_array_mut().unwrap().remove(1);
    mutations.push(o);
    let mut o = reference();
    let clone = o["nftables"][2].clone();
    o["nftables"].as_array_mut().unwrap().push(clone);
    mutations.push(o);
    for o in mutations {
        comparer(&o, 2, "UNMEASURED");
    }
}

#[test]
fn json_tronque_duplique_et_entree_trop_grande_ne_passent_pas() {
    let b = Bac::nouveau();
    let a = serde_json::to_vec(&reference()).unwrap();
    for o in [
        br#"{"nftables":["#.to_vec(),
        br#"{"nftables":[],"nftables":[]}"#.to_vec(),
        vec![b' '; 2 * 1024 * 1024 + 1],
    ] {
        let r = rapport(b.lancer(&a, &o, true), 2, "UNMEASURED");
        assert!(r["observed_counts"].is_null());
        assert!(r["differences"].as_array().unwrap().is_empty());
        assert_eq!(r["failed_input"], "observed");
    }
}

#[test]
fn comparaison_hors_ligne_laissant_les_fichiers_intacts() {
    let b = Bac::nouveau();
    let a = serde_json::to_vec(&reference()).unwrap();
    let sortie = b.lancer(&a, &a, false);
    assert_eq!(sortie.status.code(), Some(0));
    let texte = String::from_utf8(sortie.stdout).unwrap();
    assert!(texte.contains("pas une preuve du pare-feu actif"));
    assert_eq!(std::fs::read(b.0.join("reference-privee.json")).unwrap(), a);
    assert_eq!(std::fs::read(b.0.join("capture-privee.json")).unwrap(), a);
    assert_eq!(std::fs::read_dir(&b.0).unwrap().count(), 2);
}

#[test]
fn capture_absente_ou_non_reguliere_reste_non_mesuree() {
    let b = Bac::nouveau();
    let attendu = b.0.join("reference-privee.json");
    std::fs::write(&attendu, serde_json::to_vec(&reference()).unwrap()).unwrap();
    let chemins = vec![b.0.join("absent"), b.0.clone()];
    #[cfg(unix)]
    let chemins = {
        let mut chemins = chemins;
        let lien = b.0.join("lien");
        std::os::unix::fs::symlink(&attendu, &lien).unwrap();
        chemins.push(lien);
        chemins
    };
    for chemin in chemins {
        let sortie = Command::new(env!("CARGO_BIN_EXE_bifrost-cli"))
            .args(["--json", "prove", "nft", "--attendu"])
            .arg(&attendu)
            .arg("--observe")
            .arg(chemin)
            .output()
            .unwrap();
        let r = rapport(sortie, 2, "UNMEASURED");
        assert!(r["observed_counts"].is_null());
    }
}
