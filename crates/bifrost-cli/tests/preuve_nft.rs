//! Captures synthetiques au format nft JSON: aucun pare-feu n'est touche.

use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::{Value, json};

static NUMERO: AtomicU64 = AtomicU64::new(0);

#[cfg(target_os = "linux")]
fn politique() -> Value {
    json!({"schema_version":1,"tunnel_interface":"wg-prive","fwmark":51820,
        "dns_resolver":"127.0.0.1","allow_lan":false,"coeur_uid":1001,"resolveur_uid":1002})
}

#[cfg(target_os = "linux")]
fn lancer_politique(b: &Bac, p: &[u8], observation: Option<&Value>) -> Output {
    std::fs::write(b.0.join("politique-privee.json"), p).unwrap();
    let mut c = Command::new(env!("CARGO_BIN_EXE_bifrost-cli"));
    c.args([
        "--json",
        "--socket",
        "absent",
        "prove",
        "nft",
        "--politique",
    ])
    .arg(b.0.join("politique-privee.json"));
    if let Some(o) = observation {
        std::fs::write(b.0.join("observe.json"), o.to_string()).unwrap();
        c.arg("--observe").arg(b.0.join("observe.json"));
    } else {
        c.arg("--actif");
    }
    c.output().unwrap()
}

#[cfg(target_os = "linux")]
#[test]
fn politique_produit_comparee_sans_daemon_et_sans_exporter_ses_parametres() {
    let b = Bac::nouveau();
    let p = politique();
    let attendu = bifrost_firewall::politique_nft::Politique::lire(p.clone())
        .unwrap()
        .reference()
        .unwrap();
    let sortie = lancer_politique(&b, p.to_string().as_bytes(), Some(&attendu));
    assert_eq!(sortie.status.code(), Some(0), "{sortie:?}");
    let r: Value = serde_json::from_slice(&sortie.stdout).unwrap();
    assert_eq!(r["verdict"], "MATCH");
    assert_eq!(r["expected_source"], "bifrost-policy-v1-user-declared");
    assert_eq!(r["policy_schema_version"], 1);
    assert_eq!(r["live_kernel"], false);
    assert_eq!(r["network_security"], "not-evaluated");
    for secret in ["wg-prive", "127.0.0.1", "politique-privee", "51820"] {
        assert!(!String::from_utf8_lossy(&sortie.stdout).contains(secret));
    }
    // Changer l'intention sans toucher l'observation doit produire un ecart.
    for (cle, valeur) in [
        ("allow_lan", json!(true)),
        ("fwmark", json!(42)),
        ("tunnel_interface", json!("wg-autre")),
        ("coeur_uid", json!(1003)),
        ("resolveur_uid", json!(1004)),
        ("dns_resolver", json!("::1")),
    ] {
        let mut autre = p.clone();
        autre[cle] = valeur;
        let sortie = lancer_politique(&b, autre.to_string().as_bytes(), Some(&attendu));
        assert_eq!(
            sortie.status.code(),
            Some(1),
            "ecart ignore: {cle}, {sortie:?}"
        );
    }
    assert_eq!(
        std::fs::read(b.0.join("observe.json")).unwrap(),
        attendu.to_string().as_bytes()
    );
}

#[cfg(target_os = "linux")]
#[test]
fn politique_invalide_refusee_avant_toute_collecte() {
    let b = Bac::nouveau();
    let p = politique().to_string();
    for invalide in [
        "{}".to_owned(),
        format!("{{\"schema_version\":1,{}", &p[1..]),
        p.replace("51820", "0"),
        p.replace("\"schema_version\":1", "\"schema_version\":99"),
    ] {
        let sortie = lancer_politique(&b, invalide.as_bytes(), None);
        assert_eq!(sortie.status.code(), Some(2), "{sortie:?}");
        let r: Value = serde_json::from_slice(&sortie.stdout).unwrap();
        assert_eq!(r["verdict"], "UNMEASURED");
        assert_eq!(r["failed_input"], "policy");
        assert_eq!(r["live_kernel"], false);
        assert_eq!(r["generation_verified"], false);
    }
    let sortie = Command::new(env!("CARGO_BIN_EXE_bifrost-cli"))
        .args([
            "prove",
            "nft",
            "--politique",
            "absent",
            "--attendu",
            "absent",
            "--actif",
        ])
        .output()
        .unwrap();
    assert_eq!(sortie.status.code(), Some(2));
    assert!(sortie.stdout.is_empty());
}

#[cfg(target_os = "linux")]
#[test]
fn reference_confrontee_a_la_capture_reelle_nft_1_0_9() {
    let b = Bac::nouveau();
    let mut p = politique();
    for cle in ["tunnel_interface", "fwmark", "coeur_uid", "resolveur_uid"] {
        p[cle] = Value::Null;
    }
    let capture: Value =
        serde_json::from_slice(include_bytes!("fixtures/nft-1.0.9-minimal.json")).unwrap();
    let sortie = lancer_politique(&b, p.to_string().as_bytes(), Some(&capture));
    assert_eq!(sortie.status.code(), Some(0), "{sortie:?}");
}

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
        json!({"tables":1,"chains":1,"rules":3,"objects":0})
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
    // Un set sans identite, et un type que le comparateur ne sait pas lire.
    let mut o = reference();
    o["nftables"]
        .as_array_mut()
        .unwrap()
        .push(json!({"set":{"name":"cache"}}));
    mutations.push(o);
    let mut o = reference();
    o["nftables"]
        .as_array_mut()
        .unwrap()
        .push(json!({"secmark":{"family":"inet","table":"nom-prive","name":"s","context":"x"}}));
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

/// La reference avec, dans une table tierce, un set a delai, une map, un
/// flowtable et un counter nomme, dans la forme que nft 1.0.9 leur donne.
fn reference_avec_objets() -> Value {
    let mut r = reference();
    let tiers = |genre: &str, mut corps: Value| {
        corps["family"] = "inet".into();
        corps["table"] = "table-tierce".into();
        json!({ genre: corps })
    };
    r["nftables"].as_array_mut().unwrap().extend([
        json!({"table": {"family": "inet", "name": "table-tierce", "handle": 7}}),
        tiers(
            "counter",
            json!({"name": "compteur-prive", "handle": 1, "packets": 3, "bytes": 180}),
        ),
        tiers(
            "set",
            json!({"name": "set-prive", "handle": 2, "type": "ipv4_addr",
            "flags": ["timeout"], "timeout": 3600,
            "elem": [{"elem": {"val": "198.51.100.7", "expires": 3500}}, "198.51.100.8"]}),
        ),
        tiers(
            "map",
            json!({"name": "map-privee", "handle": 3, "type": "ipv4_addr", "map": "verdict",
            "elem": [["198.51.100.9", {"accept": null}]]}),
        ),
        tiers(
            "flowtable",
            json!({"name": "flux-prive", "handle": 4, "hook": "ingress", "prio": 0,
            "dev": "if-privee"}),
        ),
    ]);
    r
}

#[test]
fn objets_nommes_compares_sans_exporter_ce_qu_ils_portent() {
    let a = reference_avec_objets();
    let b = Bac::nouveau();
    let lancer = |o: &Value| {
        b.lancer(
            &serde_json::to_vec(&a).unwrap(),
            &serde_json::to_vec(o).unwrap(),
            true,
        )
    };
    // L'etat change seul: valeurs du counter, expiration, ordre des elements.
    let mut o = a.clone();
    o["nftables"][7]["counter"]["packets"] = 9000.into();
    o["nftables"][8]["set"]["elem"] =
        json!(["198.51.100.8", {"elem": {"val": "198.51.100.7", "expires": 12}}]);
    let r = rapport(lancer(&o), 0, "MATCH");
    assert_eq!(
        r["expected_counts"],
        json!({"tables":2,"chains":1,"rules":3,"objects":4})
    );
    let mut ecarts = Vec::new();
    let mut o = a.clone();
    o["nftables"][8]["set"]["elem"]
        .as_array_mut()
        .unwrap()
        .push("198.51.100.99".into());
    ecarts.push((o, json!(["set-elements"])));
    let mut o = a.clone();
    o["nftables"][9]["map"]["elem"][0][1] = json!({"drop": null});
    ecarts.push((o, json!(["map-elements"])));
    let mut o = a.clone();
    o["nftables"][10]["flowtable"]["dev"] = json!(["if-privee", "if-autre"]);
    ecarts.push((o, json!(["flowtables"])));
    let mut o = a.clone();
    o["nftables"].as_array_mut().unwrap().remove(7);
    ecarts.push((o, json!(["counters"])));
    for (o, categories) in ecarts {
        let r = rapport(lancer(&o), 1, "MISMATCH");
        assert_eq!(r["differences"], categories);
        let texte = r.to_string();
        for secret in [
            "table-tierce",
            "compteur-prive",
            "set-prive",
            "map-privee",
            "flux-prive",
            "if-privee",
            "if-autre",
            "198.51.100",
        ] {
            assert!(!texte.contains(secret), "{secret} exporte: {texte}");
        }
    }
    // Un type que le comparateur ne sait pas lire: jamais omis.
    let mut o = a.clone();
    o["nftables"].as_array_mut().unwrap().push(
        json!({"tunnel": {"family": "inet", "table": "table-tierce", "name": "tunnel-prive"}}),
    );
    let r = rapport(lancer(&o), 2, "UNMEASURED");
    assert_eq!(r["reason"], "type d'objet nft non pris en charge");
    assert!(!r.to_string().contains("tunnel-prive"));
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

#[test]
fn mode_actif_explicite_et_exclusif_sans_collecte_sur_reference_invalide() {
    let b = Bac::nouveau();
    let absent = b.0.join("absent");
    for arguments in [vec![], vec!["--observe", "capture", "--actif"]] {
        let sortie = Command::new(env!("CARGO_BIN_EXE_bifrost-cli"))
            .args(["--json", "prove", "nft", "--attendu"])
            .arg(&absent)
            .args(arguments)
            .output()
            .unwrap();
        assert_eq!(sortie.status.code(), Some(2));
        assert!(sortie.stdout.is_empty());
    }
    let sortie = Command::new(env!("CARGO_BIN_EXE_bifrost-cli"))
        .args(["--json", "prove", "nft", "--actif", "--attendu"])
        .arg(absent)
        .output()
        .unwrap();
    assert_eq!(sortie.status.code(), Some(2));
    let r: Value = serde_json::from_slice(&sortie.stdout).unwrap();
    assert_eq!(r["scope"], "nft-kernel-comparison");
    assert_eq!(r["verdict"], "UNMEASURED");
    assert_eq!(r["failed_input"], "expected");
    assert_eq!(r["live_kernel"], false);
    assert_eq!(r["generation_verified"], false);
}

/// `--politique-daemon`: l'attendu vient du daemon, le noyau courant l'observe.
///
/// Toute autre source d'attendu, et toute capture fournie, est refusee par
/// clap avant la moindre lecture. Sans `--actif` aussi: la declaration est
/// relue avant et apres la collecte, et cet encadrement ne veut rien dire
/// autour d'un fichier capture a un autre moment.
#[test]
fn politique_daemon_exclusive_et_liee_au_noyau_courant() {
    let b = Bac::nouveau();
    let fichier = b.0.join("fichier-prive.json");
    std::fs::write(&fichier, "{}").unwrap();
    let f = fichier.to_str().unwrap();
    for arguments in [
        vec!["--politique-daemon"],
        vec!["--politique-daemon", "--observe", f],
        vec!["--politique-daemon", "--actif", "--attendu", f],
        vec!["--politique-daemon", "--actif", "--politique", f],
        vec!["--politique-daemon", "--actif", "--observe", f],
        vec!["--politique-daemon", "--attendu", f, "--observe", f],
        vec!["--politique-daemon", "--politique", f, "--observe", f],
    ] {
        let sortie = Command::new(env!("CARGO_BIN_EXE_bifrost-cli"))
            .args(["--json", "--socket", "absent", "prove", "nft"])
            .args(&arguments)
            .output()
            .unwrap();
        assert_eq!(sortie.status.code(), Some(2), "{arguments:?}");
        assert!(sortie.stdout.is_empty(), "{arguments:?}");
    }
    let socket = b.0.join("daemon-prive.sock");
    let sortie = Command::new(env!("CARGO_BIN_EXE_bifrost-cli"))
        .args(["--json", "--socket"])
        .arg(&socket)
        .args(["prove", "nft", "--politique-daemon", "--actif"])
        .output()
        .unwrap();
    assert_eq!(sortie.status.code(), Some(2), "{sortie:?}");
    let r: Value = serde_json::from_slice(&sortie.stdout).unwrap();
    assert_eq!(r["schema_version"], 1);
    assert_eq!(r["scope"], "nft-kernel-comparison");
    assert_eq!(r["verdict"], "UNMEASURED");
    assert_eq!(r["expected_source"], "daemon-declared-active-policy");
    assert_eq!(r["failed_input"], "daemon-declaration");
    assert_eq!(r["live_kernel"], false);
    assert_eq!(r["generation_verified"], false);
    assert_eq!(r["network_security"], "not-evaluated");
    #[cfg(target_os = "linux")]
    assert_eq!(r["reason"], "daemon injoignable");
    #[cfg(not(target_os = "linux"))]
    assert_eq!(
        r["reason"],
        "preuve par declaration du daemon disponible uniquement sous Linux"
    );
    assert!(!String::from_utf8_lossy(&sortie.stdout).contains("daemon-prive"));
}
