//! Recettes hors ligne des objets nft nommes, sur captures synthetiques.
//!
//! Les formes sont celles que nft 1.0.9 rend pour chaque type (releve du
//! 30/09/2026, namespace jetable); les valeurs sont des adresses de
//! documentation et des noms inventes. Ces recettes ne prouvent pas une
//! observation du noyau: le banc `scripts/preuve-nft-linux.sh` le fait.

use std::time::Instant;

use serde_json::{Value, json};

use super::*;

/// Une capture avec la table du produit et une table tierce qui porte un
/// objet de chaque type pris en charge, dans l'ordre ou nft les liste:
/// objets a etat, sets et maps, flowtables, chaines, regles.
fn base() -> Value {
    let t = |genre: &str, mut corps: Value| {
        corps["family"] = "inet".into();
        corps["table"] = "tiers".into();
        json!({ genre: corps })
    };
    let regle = |expr: Value| t("rule", json!({"chain": "c", "expr": expr}));
    json!({"nftables": [
        {"metainfo": {"version": "1.0.9", "release_name": "fixture", "json_schema_version": 1}},
        {"table": {"family": "inet", "name": "produit", "handle": 1}},
        {"chain": {"family": "inet", "table": "produit", "name": "output", "handle": 2,
            "type": "filter", "hook": "output", "prio": 0, "policy": "drop"}},
        {"rule": {"family": "inet", "table": "produit", "chain": "output", "handle": 3,
            "expr": [{"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": "lo"}},
                     {"accept": null}]}},
        {"table": {"family": "inet", "name": "tiers", "handle": 2}},
        t("counter", json!({"name": "cnom", "handle": 11, "packets": 5, "bytes": 100})),
        t("counter", json!({"name": "cseul", "handle": 12, "packets": 0, "bytes": 0})),
        t("limit", json!({"name": "lnom", "handle": 13, "rate": 10, "per": "second", "burst": 5})),
        t("ct timeout", json!({"name": "tnom", "handle": 14, "protocol": "tcp", "l3proto": "ip",
            "policy": {"established": 100}})),
        t("ct expectation", json!({"name": "enom", "handle": 15, "protocol": "tcp", "dport": 21,
            "timeout": 60000, "size": 10, "l3proto": "ip"})),
        t("quota", json!({"name": "qnom", "handle": 16, "bytes": 10485760, "used": 1000, "inv": true})),
        t("ct helper", json!({"name": "hnom", "handle": 17, "type": "ftp", "protocol": "tcp",
            "l3proto": "ip"})),
        t("synproxy", json!({"name": "pnom", "handle": 18, "mss": 1460, "wscale": 7,
            "flags": ["timestamp", "sack-perm"]})),
        t("set", json!({"name": "s4", "type": "ipv4_addr", "handle": 1,
            "elem": ["192.0.2.1", "192.0.2.2", "192.0.2.3"]})),
        t("set", json!({"name": "sint", "type": "ipv4_addr", "handle": 2, "flags": ["interval"],
            "elem": [{"prefix": {"addr": "192.0.2.0", "len": 24}},
                     {"range": ["198.51.100.10", "198.51.100.20"]}]})),
        t("set", json!({"name": "sto", "type": "ipv4_addr", "handle": 3, "flags": ["timeout"],
            "timeout": 3600, "elem": [{"elem": {"val": "192.0.2.3", "expires": 3599}},
                {"elem": {"val": "192.0.2.4", "timeout": 1800, "expires": 1799}}]})),
        t("set", json!({"name": "sdyn", "type": "ipv4_addr", "handle": 4, "size": 65535,
            "flags": ["timeout", "dynamic"], "timeout": 3600,
            "elem": [{"elem": {"val": "127.0.0.1", "expires": 3599,
                "counter": {"packets": 4, "bytes": 336}}}]})),
        t("set", json!({"name": "sq", "type": "ipv4_addr", "handle": 5,
            "elem": [{"elem": {"val": "192.0.2.5", "quota": {"val": 10, "val_unit": "mbytes"}}}],
            "stmt": [{"quota": {"val": 10, "val_unit": "mbytes"}}]})),
        t("set", json!({"name": "sla", "type": "ipv4_addr", "handle": 6,
            "elem": [{"elem": {"val": "192.0.2.6", "last": null}}], "stmt": [{"last": null}]})),
        t("set", json!({"name": "scat", "type": ["ipv4_addr", "inet_service"], "handle": 7,
            "comment": "commentaire", "elem": [{"concat": ["192.0.2.6", 53]}]})),
        t("map", json!({"name": "mv", "type": "ipv4_addr", "handle": 8, "map": "verdict",
            "elem": [["192.0.2.8", {"accept": null}], ["192.0.2.9", {"drop": null}]]})),
        t("map", json!({"name": "mto", "type": "ipv4_addr", "handle": 9, "map": "ipv4_addr",
            "flags": ["timeout"], "elem": [[{"elem": {"val": "192.0.2.10", "timeout": 600,
                "expires": 599}}, "198.51.100.2"]]})),
        t("flowtable", json!({"name": "fnom", "handle": 19, "hook": "ingress", "prio": 0,
            "dev": ["veth-a", "veth-b"]})),
        t("flowtable", json!({"name": "fun", "handle": 20, "hook": "ingress", "prio": 10,
            "dev": "veth-c"})),
        t("chain", json!({"name": "c", "handle": 21, "type": "filter", "hook": "output",
            "prio": 10, "policy": "accept"})),
        regle(json!([{"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "daddr"}},
            "right": "@s4"}}, {"counter": "cnom"}, {"accept": null}])),
        regle(json!([{"quota": "qnom"}, {"drop": null}])),
        regle(json!([{"quota": {"val": 5, "val_unit": "mbytes", "inv": true, "used": 10,
            "used_unit": "bytes"}}, {"drop": null}])),
        regle(json!([{"last": {"used": 3}}])),
        regle(json!([{"limit": "lnom"}, {"accept": null}])),
        regle(json!([{"vmap": {"key": {"payload": {"protocol": "ip", "field": "daddr"}},
            "data": "@mv"}}])),
        regle(json!([{"flow": {"op": "add", "flowtable": "@fnom"}}])),
    ]})
}

/// L'entree de `capture` dont le type est `genre` et le nom `nom`.
fn objet<'a>(capture: &'a mut Value, genre: &str, nom: &str) -> &'a mut Value {
    capture["nftables"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find_map(|e| e.get_mut(genre).filter(|c| c["name"] == nom))
        .unwrap_or_else(|| panic!("{genre} {nom} absent de la fixture"))
}

fn entrees(capture: &mut Value) -> &mut Vec<Value> {
    capture["nftables"].as_array_mut().unwrap()
}

/// La position de l'entree `genre`/`nom` dans la capture.
fn position(capture: &Value, genre: &str, nom: &str) -> usize {
    capture["nftables"]
        .as_array()
        .unwrap()
        .iter()
        .position(|e| e.get(genre).is_some_and(|c| c["name"] == nom))
        .unwrap()
}

fn comparer(attendu: &Value, observe: &Value) -> Value {
    let debut = Instant::now();
    let mut r = commencer();
    let resultat = (|| {
        let a = analyser(&serde_json::to_vec(attendu).unwrap())?;
        r.expected_counts = Some(a.compte());
        r.failed_input = Some("observed");
        confronter(&mut r, a, &serde_json::to_vec(observe).unwrap())
    })();
    let r = terminer(r, debut, resultat);
    let code = r.code();
    let v = serde_json::to_value(&r).unwrap();
    assert_eq!(
        code,
        match v["verdict"].as_str().unwrap() {
            "MATCH" => 0,
            "MISMATCH" => 1,
            _ => 2,
        }
    );
    v
}

/// Rien de ce que portent les objets ne sort: ni nom, ni element, ni
/// peripherique, ni valeur. Seuls comptes et categories.
fn muet(r: &Value) {
    let mut sans_horloge = r.clone();
    for cle in ["started_at_unix_ms", "completed_at_unix_ms", "duration_ms"] {
        sans_horloge.as_object_mut().unwrap().remove(cle);
    }
    let texte = sans_horloge.to_string();
    for interdit in [
        "tiers",
        "produit",
        "cnom",
        "cseul",
        "s4",
        "sint",
        "sdyn",
        "mv",
        "fnom",
        "veth",
        "192.0.2",
        "198.51.100",
        "127.0.0.1",
        "ftp",
        "1460",
        "10485760",
        "commentaire",
    ] {
        assert!(
            !texte.contains(interdit),
            "le rapport exporte {interdit}: {texte}"
        );
    }
}

#[test]
fn la_base_se_lit_et_compte_ses_objets() {
    let r = comparer(&base(), &base());
    assert_eq!(r["verdict"], "MATCH", "{r}");
    assert_eq!(
        r["expected_counts"],
        json!({"tables": 2, "chains": 2, "rules": 8, "objects": 19})
    );
    assert_eq!(r["observed_counts"], r["expected_counts"]);
    muet(&r);
}

/// Les valeurs d'etat que le noyau change seul, toutes a la fois: compteurs
/// (nomme, d'element), consommation d'un quota (nomme, anonyme), dernier
/// passage, expiration des elements, plus handles, ordre des elements et des
/// peripheriques, et la forme chaine ou liste d'un peripherique seul.
#[test]
fn les_objets_identiques_correspondent_malgre_leur_etat() {
    let a = base();
    let mut o = base();
    *objet(&mut o, "counter", "cnom") = json!({"family": "inet", "table": "tiers", "name": "cnom", "handle": 90,
            "packets": 9000, "bytes": 900000});
    objet(&mut o, "quota", "qnom")["used"] = 5_000_000.into();
    objet(&mut o, "set", "sto")["elem"][0]["elem"]["expires"] = 12.into();
    objet(&mut o, "set", "sto")["elem"][1]["elem"]["expires"] = 3.into();
    objet(&mut o, "set", "sdyn")["elem"][0]["elem"]["counter"] =
        json!({"packets": 70, "bytes": 7000});
    objet(&mut o, "set", "sdyn")["elem"][0]["elem"]["expires"] = 1.into();
    objet(&mut o, "set", "sq")["elem"][0]["elem"]["quota"] =
        json!({"val": 10, "val_unit": "mbytes", "used": 3, "used_unit": "kbytes"});
    objet(&mut o, "set", "sla")["elem"][0]["elem"]["last"] = json!({"used": 40});
    objet(&mut o, "map", "mto")["elem"][0][0]["elem"]["expires"] = 2.into();
    objet(&mut o, "set", "s4")["elem"] = json!(["192.0.2.3", "192.0.2.1", "192.0.2.2"]);
    objet(&mut o, "map", "mv")["elem"] =
        json!([["192.0.2.9", {"drop": null}], ["192.0.2.8", {"accept": null}]]);
    objet(&mut o, "flowtable", "fnom")["dev"] = json!(["veth-b", "veth-a"]);
    objet(&mut o, "flowtable", "fun")["dev"] = json!(["veth-c"]);
    let n = entrees(&mut o).len();
    // Consommation d'un quota anonyme: ecrite une fois non nulle, dans une
    // unite qui suit sa grandeur; et le dernier passage d'une regle.
    let quota = &mut entrees(&mut o)[n - 5]["rule"]["expr"][0]["quota"];
    quota["used"] = 2.into();
    quota["used_unit"] = "mbytes".into();
    entrees(&mut o)[n - 4]["rule"]["expr"][0]["last"] = json!({"used": 99});
    let r = comparer(&a, &o);
    assert_eq!(r["verdict"], "MATCH", "{r}");
    assert!(r["failed_input"].is_null());
    // Et dans l'autre sens: l'etat neuf (quota anonyme jamais consomme, sans
    // `used`; regle jamais passee, `last` nul).
    let mut neuf = base();
    let n = entrees(&mut neuf).len();
    let quota = entrees(&mut neuf)[n - 5]["rule"]["expr"][0]["quota"]
        .as_object_mut()
        .unwrap();
    quota.remove("used");
    quota.remove("used_unit");
    entrees(&mut neuf)[n - 4]["rule"]["expr"][0]["last"] = Value::Null;
    assert_eq!(comparer(&neuf, &o)["verdict"], "MATCH");
    assert_eq!(comparer(&o, &neuf)["verdict"], "MATCH");
}

type Alteration = fn(&mut Value);

/// Chaque alteration, seule, face a la base: un ecart, et exactement la
/// categorie de l'objet qu'elle touche.
#[test]
fn chaque_alteration_est_un_ecart_de_sa_categorie() {
    let cas: Vec<(&str, Alteration, Value)> = vec![
        (
            "element ajoute a un set",
            |o| {
                objet(o, "set", "s4")["elem"]
                    .as_array_mut()
                    .unwrap()
                    .push("192.0.2.200".into())
            },
            json!(["set-elements"]),
        ),
        (
            "element retire d'un set",
            |o| {
                objet(o, "set", "s4")["elem"]
                    .as_array_mut()
                    .unwrap()
                    .remove(1);
            },
            json!(["set-elements"]),
        ),
        (
            "intervalle elargi",
            |o| objet(o, "set", "sint")["elem"][0]["prefix"]["len"] = 16.into(),
            json!(["set-elements"]),
        ),
        (
            "delai d'un element change",
            |o| objet(o, "set", "sto")["elem"][1]["elem"]["timeout"] = 60.into(),
            json!(["set-elements"]),
        ),
        (
            "element d'un set dynamique gagne par le trafic",
            |o| {
                objet(o, "set", "sdyn")["elem"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!({"elem": {"val": "127.0.0.2", "expires": 3599,
                    "counter": {"packets": 1, "bytes": 84}}}))
            },
            json!(["set-elements"]),
        ),
        (
            "limite du quota d'un element changee",
            |o| objet(o, "set", "sq")["elem"][0]["elem"]["quota"]["val"] = 20.into(),
            json!(["set-elements"]),
        ),
        (
            "flag de set change",
            |o| objet(o, "set", "sto")["flags"] = json!(["timeout", "dynamic"]),
            json!(["sets"]),
        ),
        (
            "delai d'un set change",
            |o| objet(o, "set", "sto")["timeout"] = 60.into(),
            json!(["sets"]),
        ),
        (
            "type de set change",
            |o| objet(o, "set", "s4")["type"] = "ipv6_addr".into(),
            json!(["sets"]),
        ),
        (
            "instruction d'un set retiree",
            |o| {
                objet(o, "set", "sq")
                    .as_object_mut()
                    .unwrap()
                    .remove("stmt");
            },
            json!(["sets"]),
        ),
        (
            "commentaire de set change",
            |o| objet(o, "set", "scat")["comment"] = "autre".into(),
            json!(["sets"]),
        ),
        (
            "set tiers ajoute",
            |o| {
                let i = position(o, "set", "s4");
                entrees(o).insert(
                    i,
                    json!({"set": {"family": "inet", "table": "tiers",
                "name": "nouveau", "type": "ipv4_addr", "elem": ["192.0.2.77"]}}),
                )
            },
            json!(["sets"]),
        ),
        (
            "set retire",
            |o| {
                let i = position(o, "set", "sla");
                entrees(o).remove(i);
            },
            json!(["sets"]),
        ),
        (
            "valeur de map changee",
            |o| objet(o, "map", "mv")["elem"][0][1] = json!({"drop": null}),
            json!(["map-elements"]),
        ),
        (
            "element de map ajoute",
            |o| {
                objet(o, "map", "mv")["elem"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!(["192.0.2.99", {"accept": null}]))
            },
            json!(["map-elements"]),
        ),
        (
            "adresse d'une map changee",
            |o| objet(o, "map", "mto")["elem"][0][1] = "198.51.100.3".into(),
            json!(["map-elements"]),
        ),
        (
            "type de valeur de map change",
            |o| objet(o, "map", "mto")["map"] = "mark".into(),
            json!(["maps"]),
        ),
        (
            "hook de flowtable change",
            |o| objet(o, "flowtable", "fnom")["hook"] = "egress".into(),
            json!(["flowtables"]),
        ),
        (
            "priorite de flowtable changee",
            |o| objet(o, "flowtable", "fnom")["prio"] = (-5).into(),
            json!(["flowtables"]),
        ),
        (
            "peripherique de flowtable ajoute",
            |o| objet(o, "flowtable", "fun")["dev"] = json!(["veth-c", "veth-d"]),
            json!(["flowtables"]),
        ),
        (
            "peripherique de flowtable remplace",
            |o| objet(o, "flowtable", "fun")["dev"] = "veth-d".into(),
            json!(["flowtables"]),
        ),
        (
            "peripheriques de flowtable retires",
            |o| {
                objet(o, "flowtable", "fnom")
                    .as_object_mut()
                    .unwrap()
                    .remove("dev");
            },
            json!(["flowtables"]),
        ),
        (
            "counter nomme retire",
            |o| {
                let i = position(o, "counter", "cseul");
                entrees(o).remove(i);
            },
            json!(["counters"]),
        ),
        (
            "counter nomme renomme",
            |o| objet(o, "counter", "cseul")["name"] = "autre".into(),
            json!(["counters"]),
        ),
        (
            "limite du quota changee",
            |o| objet(o, "quota", "qnom")["bytes"] = 20971520.into(),
            json!(["quotas"]),
        ),
        (
            "sens du quota change",
            |o| objet(o, "quota", "qnom")["inv"] = false.into(),
            json!(["quotas"]),
        ),
        (
            "debit de limit change",
            |o| objet(o, "limit", "lnom")["rate"] = 1000.into(),
            json!(["limits"]),
        ),
        (
            "rafale de limit retiree",
            |o| {
                objet(o, "limit", "lnom")
                    .as_object_mut()
                    .unwrap()
                    .remove("burst");
            },
            json!(["limits"]),
        ),
        (
            "assistant ct change",
            |o| objet(o, "ct helper", "hnom")["type"] = "tftp".into(),
            json!(["ct-helpers"]),
        ),
        (
            "delai ct change",
            |o| objet(o, "ct timeout", "tnom")["policy"]["established"] = 7200.into(),
            json!(["ct-timeouts"]),
        ),
        (
            "attente ct changee",
            |o| objet(o, "ct expectation", "enom")["dport"] = 2121.into(),
            json!(["ct-expectations"]),
        ),
        (
            "synproxy change",
            |o| objet(o, "synproxy", "pnom")["mss"] = 536.into(),
            json!(["synproxies"]),
        ),
        (
            "objet tiers dans une nouvelle table",
            |o| {
                entrees(o).push(json!({"table": {"family": "ip", "name": "autre"}}));
                entrees(o).push(
                    json!({"counter": {"family": "ip", "table": "autre", "name": "c",
                "packets": 0, "bytes": 0}}),
                );
            },
            json!(["tables", "counters"]),
        ),
        (
            "objet tiers dans la table du produit",
            |o| {
                entrees(o).insert(
                    2,
                    json!({"quota": {"family": "inet", "table": "produit",
                "name": "q", "bytes": 1, "used": 0, "inv": false}}),
                )
            },
            json!(["quotas"]),
        ),
        (
            "meme nom, autre famille",
            |o| {
                entrees(o).push(json!({"table": {"family": "ip", "name": "tiers"}}));
                entrees(o).push(
                    json!({"limit": {"family": "ip", "table": "tiers", "name": "lnom",
                "rate": 10, "per": "second", "burst": 5}}),
                );
            },
            json!(["tables", "limits"]),
        ),
        (
            "limite d'un quota anonyme changee",
            |o| {
                let n = entrees(o).len();
                entrees(o)[n - 5]["rule"]["expr"][0]["quota"]["val"] = 6.into()
            },
            json!(["rules"]),
        ),
        (
            "reference a un counter nomme changee",
            |o| {
                let n = entrees(o).len();
                entrees(o)[n - 7]["rule"]["expr"][1]["counter"] = "cseul".into()
            },
            json!(["rules"]),
        ),
        (
            "quota anonyme retire de sa regle",
            |o| {
                let n = entrees(o).len();
                entrees(o)[n - 5]["rule"]["expr"]
                    .as_array_mut()
                    .unwrap()
                    .remove(0);
            },
            json!(["rules"]),
        ),
        (
            "dernier passage retire",
            |o| {
                let n = entrees(o).len();
                entrees(o)[n - 4]["rule"]["expr"] = json!([{"counter": {"packets": 0, "bytes": 0}}])
            },
            json!(["rules"]),
        ),
    ];
    let a = base();
    for (nom, alterer, attendu) in cas {
        let mut o = base();
        alterer(&mut o);
        let r = comparer(&a, &o);
        assert_eq!(r["verdict"], "MISMATCH", "{nom}: {r}");
        assert_eq!(r["differences"], attendu, "{nom}");
        muet(&r);
        // Symetrique: l'objet en trop d'un cote est l'objet en moins de l'autre.
        let r = comparer(&o, &a);
        assert_eq!(r["verdict"], "MISMATCH", "{nom}, sens inverse: {r}");
        assert_eq!(r["differences"], attendu, "{nom}, sens inverse");
    }
}

/// L'ordre des declarations reste compare, comme pour les chaines: deux sets
/// intervertis sont un ecart d'ordre, pas une correspondance.
#[test]
fn l_ordre_des_objets_reste_compare() {
    let a = base();
    let mut o = base();
    let (i, j) = (position(&o, "set", "s4"), position(&o, "set", "sint"));
    entrees(&mut o).swap(i, j);
    let r = comparer(&a, &o);
    assert_eq!(r["verdict"], "MISMATCH", "{r}");
    assert_eq!(r["differences"], json!(["object-order"]));
}

/// Un type inconnu du comparateur ou un objet malforme, d'un cote comme de
/// l'autre: NON MESURE, jamais omis.
#[test]
fn inconnus_et_malformes_restent_non_mesures() {
    type Cas = (&'static str, Alteration, &'static str);
    let inconnu = "type d'objet nft non pris en charge";
    let malforme = "objet nft nomme malforme";
    let cas: Vec<Cas> = vec![
        (
            "secmark",
            |o| {
                entrees(o).push(json!({"secmark": {"family": "inet", "table": "tiers",
                "name": "x", "context": "system_u:object_r:x_t:s0"}}))
            },
            inconnu,
        ),
        (
            "tunnel",
            |o| {
                entrees(o)
                    .push(json!({"tunnel": {"family": "inet", "table": "tiers", "name": "x"}}))
            },
            inconnu,
        ),
        (
            "element hors d'un set",
            |o| {
                entrees(o).push(json!({"element": {"family": "inet", "table": "tiers",
                "name": "s4", "elem": ["192.0.2.9"]}}))
            },
            inconnu,
        ),
        (
            "set sans nom",
            |o| {
                objet(o, "set", "s4")
                    .as_object_mut()
                    .unwrap()
                    .remove("name");
            },
            "identite d'objet incomplete",
        ),
        (
            "set sans table",
            |o| {
                objet(o, "set", "s4")
                    .as_object_mut()
                    .unwrap()
                    .remove("table");
            },
            "identite d'objet incomplete",
        ),
        (
            "counter dans une table absente",
            |o| objet(o, "counter", "cseul")["table"] = "absente".into(),
            "table ou chaine parente absente",
        ),
        (
            "set duplique",
            |o| {
                let i = position(o, "set", "s4");
                let doublon = entrees(o)[i].clone();
                entrees(o).push(doublon)
            },
            "objet nomme duplique",
        ),
        (
            "set et map de meme nom",
            |o| objet(o, "map", "mv")["name"] = "s4".into(),
            "objet nomme duplique",
        ),
        (
            "handle non entier",
            |o| objet(o, "quota", "qnom")["handle"] = "16".into(),
            "handle nft invalide",
        ),
        (
            "element duplique",
            |o| {
                objet(o, "set", "s4")["elem"]
                    .as_array_mut()
                    .unwrap()
                    .push("192.0.2.1".into())
            },
            "element de set duplique",
        ),
        (
            "element duplique sous deux formes",
            |o| {
                objet(o, "set", "sto")["elem"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!({"elem": {"val": "192.0.2.3", "timeout": 5}}))
            },
            "element de set duplique",
        ),
        (
            "deux valeurs pour une cle de map",
            |o| {
                objet(o, "map", "mv")["elem"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!(["192.0.2.8", {"drop": null}]))
            },
            "element de set duplique",
        ),
        (
            "element de map sans valeur",
            |o| objet(o, "map", "mv")["elem"][0] = json!(["192.0.2.8"]),
            malforme,
        ),
        (
            "element de map hors paire",
            |o| objet(o, "map", "mv")["elem"][0] = "192.0.2.8".into(),
            malforme,
        ),
        (
            "element de map a trois termes",
            |o| {
                objet(o, "map", "mv")["elem"][0] = json!(["192.0.2.7", "192.0.2.8", {"drop": null}])
            },
            malforme,
        ),
        (
            "type de valeur de map invalide",
            |o| objet(o, "map", "mv")["map"] = 3.into(),
            malforme,
        ),
        (
            "set portant un type de valeur",
            |o| objet(o, "set", "s4")["map"] = "mark".into(),
            malforme,
        ),
        (
            "map sans type de valeur",
            |o| {
                objet(o, "map", "mv").as_object_mut().unwrap().remove("map");
            },
            malforme,
        ),
        (
            "set sans type",
            |o| {
                objet(o, "set", "s4")
                    .as_object_mut()
                    .unwrap()
                    .remove("type");
            },
            malforme,
        ),
        (
            "type de concatenation vide",
            |o| objet(o, "set", "scat")["type"] = json!([]),
            malforme,
        ),
        (
            "elements hors liste",
            |o| objet(o, "set", "s4")["elem"] = "192.0.2.1".into(),
            malforme,
        ),
        (
            "element sans valeur",
            |o| objet(o, "set", "sto")["elem"][0] = json!({"elem": {"expires": 3}}),
            malforme,
        ),
        (
            "expiration non entiere",
            |o| objet(o, "set", "sto")["elem"][0]["elem"]["expires"] = "3599".into(),
            malforme,
        ),
        (
            "compteur d'element sans valeurs",
            |o| objet(o, "set", "sdyn")["elem"][0]["elem"]["counter"] = Value::Null,
            "compteur non pris en charge",
        ),
        (
            "consommation sans unite",
            |o| objet(o, "set", "sq")["elem"][0]["elem"]["quota"]["used"] = 3.into(),
            "quota non pris en charge",
        ),
        (
            "dernier passage mal forme",
            |o| objet(o, "set", "sla")["elem"][0]["elem"]["last"] = json!({"used": "3"}),
            "dernier passage non pris en charge",
        ),
        (
            "counter nomme sans octets",
            |o| {
                objet(o, "counter", "cnom")
                    .as_object_mut()
                    .unwrap()
                    .remove("bytes");
            },
            malforme,
        ),
        (
            "counter nomme a valeur non entiere",
            |o| objet(o, "counter", "cnom")["packets"] = "5".into(),
            malforme,
        ),
        (
            "quota nomme sans consommation",
            |o| {
                objet(o, "quota", "qnom")
                    .as_object_mut()
                    .unwrap()
                    .remove("used");
            },
            malforme,
        ),
        (
            "quota nomme sans limite",
            |o| {
                objet(o, "quota", "qnom")
                    .as_object_mut()
                    .unwrap()
                    .remove("bytes");
            },
            malforme,
        ),
        (
            "limit sans debit",
            |o| {
                objet(o, "limit", "lnom")
                    .as_object_mut()
                    .unwrap()
                    .remove("rate");
            },
            malforme,
        ),
        (
            "limit sans periode",
            |o| {
                objet(o, "limit", "lnom")
                    .as_object_mut()
                    .unwrap()
                    .remove("per");
            },
            malforme,
        ),
        (
            "assistant ct sans type",
            |o| {
                objet(o, "ct helper", "hnom")
                    .as_object_mut()
                    .unwrap()
                    .remove("type");
            },
            malforme,
        ),
        (
            "assistant ct sans protocole",
            |o| {
                objet(o, "ct helper", "hnom")
                    .as_object_mut()
                    .unwrap()
                    .remove("protocol");
            },
            malforme,
        ),
        (
            "delai ct sans protocole",
            |o| {
                objet(o, "ct timeout", "tnom")
                    .as_object_mut()
                    .unwrap()
                    .remove("protocol");
            },
            malforme,
        ),
        (
            "attente ct sans protocole",
            |o| {
                objet(o, "ct expectation", "enom")
                    .as_object_mut()
                    .unwrap()
                    .remove("protocol");
            },
            malforme,
        ),
        (
            "synproxy sans mss",
            |o| {
                objet(o, "synproxy", "pnom")
                    .as_object_mut()
                    .unwrap()
                    .remove("mss");
            },
            malforme,
        ),
        (
            "synproxy sans wscale",
            |o| {
                objet(o, "synproxy", "pnom")
                    .as_object_mut()
                    .unwrap()
                    .remove("wscale");
            },
            malforme,
        ),
        (
            "flowtable sans hook",
            |o| {
                objet(o, "flowtable", "fnom")
                    .as_object_mut()
                    .unwrap()
                    .remove("hook");
            },
            malforme,
        ),
        (
            "flowtable a priorite non entiere",
            |o| objet(o, "flowtable", "fnom")["prio"] = "0".into(),
            malforme,
        ),
        (
            "peripherique duplique",
            |o| objet(o, "flowtable", "fnom")["dev"] = json!(["veth-a", "veth-a"]),
            malforme,
        ),
        (
            "peripherique non textuel",
            |o| objet(o, "flowtable", "fnom")["dev"] = json!(["veth-a", 3]),
            malforme,
        ),
        (
            "peripherique vide",
            |o| objet(o, "flowtable", "fun")["dev"] = "".into(),
            malforme,
        ),
        (
            "peripheriques d'un autre type",
            |o| objet(o, "flowtable", "fun")["dev"] = 3.into(),
            malforme,
        ),
        (
            "compteur anonyme a trois cles",
            |o| {
                let n = entrees(o).len();
                entrees(o)[n - 4]["rule"]["expr"] =
                    json!([{"counter": {"packets": 0, "bytes": 0, "autre": 0}}])
            },
            "compteur non pris en charge",
        ),
        (
            "reference nommee vide",
            |o| {
                let n = entrees(o).len();
                entrees(o)[n - 7]["rule"]["expr"][1]["counter"] = "".into()
            },
            "compteur non pris en charge",
        ),
        (
            "quota anonyme consomme sans unite",
            |o| {
                let n = entrees(o).len();
                entrees(o)[n - 5]["rule"]["expr"][0]["quota"]
                    .as_object_mut()
                    .unwrap()
                    .remove("used_unit");
            },
            "quota non pris en charge",
        ),
        (
            "dernier passage de regle mal forme",
            |o| {
                let n = entrees(o).len();
                entrees(o)[n - 4]["rule"]["expr"][0]["last"] = json!({"used": 1, "autre": 2})
            },
            "dernier passage non pris en charge",
        ),
    ];
    let a = base();
    for (nom, alterer, raison) in cas {
        let mut o = base();
        alterer(&mut o);
        let r = comparer(&a, &o);
        assert_eq!(r["verdict"], "UNMEASURED", "{nom}: {r}");
        assert_eq!(r["reason"], raison, "{nom}");
        assert_eq!(r["failed_input"], "observed", "{nom}");
        assert!(r["observed_counts"].is_null(), "{nom}");
        let r = comparer(&o, &a);
        assert_eq!(r["verdict"], "UNMEASURED", "{nom}, en reference: {r}");
        assert_eq!(r["reason"], raison, "{nom}, en reference");
        assert!(r["expected_counts"].is_null(), "{nom}, en reference");
    }
}

/// Un counter et un quota peuvent porter le meme nom dans une table: le noyau
/// separe leurs espaces, le comparateur aussi.
#[test]
fn deux_genres_d_objets_a_etat_peuvent_partager_un_nom() {
    let mut a = base();
    objet(&mut a, "quota", "qnom")["name"] = "cnom".into();
    let n = entrees(&mut a).len();
    entrees(&mut a)[n - 6]["rule"]["expr"][0]["quota"] = "cnom".into();
    assert_eq!(comparer(&a, &a)["verdict"], "MATCH");
}
