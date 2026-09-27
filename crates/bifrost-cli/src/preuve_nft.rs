//! Comparaison structurelle nft JSON: fichiers, ou collecte passive Linux.
//! La reference fournie reste non authentifiee, meme pour une collecte noyau.

use std::collections::BTreeMap;
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};

const MAX_OCTETS: u64 = 2 * 1024 * 1024;
const LIMITE: &str =
    "Comparaison de fichiers fournis, pas une preuve du pare-feu actif ni de son etancheite.";
type Table = (String, String);
type Chaine = (String, String, String);

#[derive(Default, Debug, PartialEq)]
struct Capture {
    ordre: Vec<Value>,
    tables: BTreeMap<Table, Value>,
    chaines: BTreeMap<Chaine, Value>,
    regles: BTreeMap<Chaine, Vec<Value>>,
}

#[derive(Serialize)]
struct Compte {
    tables: usize,
    chains: usize,
    rules: usize,
}

impl Capture {
    fn compte(&self) -> Compte {
        Compte {
            tables: self.tables.len(),
            chains: self.chaines.len(),
            rules: self.regles.values().map(Vec::len).sum(),
        }
    }
}

#[derive(Serialize)]
pub struct Rapport {
    schema_version: u32,
    scope: &'static str,
    verdict: &'static str,
    started_at_unix_ms: Option<u128>,
    completed_at_unix_ms: Option<u128>,
    duration_ms: u128,
    source: &'static str,
    expected_source: &'static str,
    policy_schema_version: Option<u32>,
    live_kernel: bool,
    generation_verified: bool,
    network_security: &'static str,
    expected_counts: Option<Compte>,
    observed_counts: Option<Compte>,
    differences: Vec<&'static str>,
    failed_input: Option<&'static str>,
    reason: &'static str,
    limitation: &'static str,
}

impl Rapport {
    pub fn code(&self) -> i32 {
        match self.verdict {
            "MATCH" => 0,
            "MISMATCH" => 1,
            _ => 2,
        }
    }

    pub fn texte(&self) -> String {
        format!(
            "{}  {}\n{}\nentree non mesuree: {}\necarts: {}\n\n{}\n",
            self.verdict,
            self.scope,
            self.reason,
            self.failed_input.unwrap_or("aucune"),
            self.differences.join(", "),
            self.limitation
        )
    }
}

fn heure() -> Option<u128> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_millis())
}

// Value accepte normalement deux cles identiques en gardant la derniere.
// Une capture ambigue n'est jamais une observation acceptable, meme si les
// doublons ont la meme valeur. Le refus vaut aussi au fond d'une expression.
struct Unique(Value);

impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Strict;
        impl<'de> Visitor<'de> for Strict {
            type Value = Unique;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("JSON sans cle dupliquee")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<Unique, A::Error> {
                let mut m = Map::new();
                while let Some((k, Unique(v))) = a.next_entry::<String, Unique>()? {
                    if m.insert(k, v).is_some() {
                        return Err(de::Error::custom("cle dupliquee"));
                    }
                }
                Ok(Unique(Value::Object(m)))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Unique, A::Error> {
                let mut v = Vec::new();
                while let Some(Unique(e)) = a.next_element()? {
                    v.push(e);
                }
                Ok(Unique(Value::Array(v)))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_f64<E: de::Error>(self, _: f64) -> Result<Unique, E> {
                Err(de::Error::custom("nombre non entier hors perimetre"))
            }
            fn visit_unit<E: de::Error>(self) -> Result<Unique, E> {
                Ok(Unique(Value::Null))
            }
        }
        d.deserialize_any(Strict)
    }
}

fn texte(v: &Value, cle: &str) -> Result<String, &'static str> {
    v.get(cle)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .ok_or("identite d'objet incomplete")
}

fn analyser(octets: &[u8]) -> Result<Capture, &'static str> {
    if octets.len() as u64 > MAX_OCTETS {
        return Err("capture trop grande");
    }
    let Unique(racine) = serde_json::from_slice(octets).map_err(|_| "JSON invalide ou ambigu")?;
    let objets = racine
        .as_object()
        .filter(|m| m.len() == 1)
        .and_then(|m| m.get("nftables"))
        .and_then(Value::as_array)
        .ok_or("enveloppe nftables absente ou inconnue")?;
    let mut capture = Capture::default();
    let mut schema_vu = false;
    for (index, entree) in objets.iter().enumerate() {
        let objet = entree
            .as_object()
            .filter(|m| m.len() == 1)
            .ok_or("objet nft invalide")?;
        let (genre, contenu) = objet.iter().next().ok_or("objet nft vide")?;
        if genre == "metainfo" {
            if index != 0 || contenu.get("json_schema_version").and_then(Value::as_u64) != Some(1) {
                return Err("version de schema nft inconnue ou metainfo deplacee");
            }
            schema_vu = true;
            continue;
        }
        if !schema_vu {
            return Err("version de schema nft absente");
        }
        if !matches!(genre.as_str(), "table" | "chain" | "rule") {
            return Err("type d'objet nft non pris en charge");
        }
        let mut v = contenu.clone();
        let famille = texte(&v, "family")?;
        if !matches!(
            famille.as_str(),
            "inet" | "ip" | "ip6" | "arp" | "bridge" | "netdev"
        ) {
            return Err("famille nft inconnue");
        }
        let m = v.as_object_mut().ok_or("contenu nft invalide")?;
        if let Some(handle) = m.remove("handle")
            && handle.as_u64().is_none()
        {
            return Err("handle nft invalide");
        }
        match genre.as_str() {
            "table" => {
                let cle = (famille, texte(&v, "name")?);
                if capture.tables.insert(cle, v.clone()).is_some() {
                    return Err("table dupliquee");
                }
            }
            "chain" => {
                let cle = (famille, texte(&v, "table")?, texte(&v, "name")?);
                if v.get("hook").is_some() {
                    texte(&v, "type")?;
                    texte(&v, "hook")?;
                    if v.get("prio").and_then(Value::as_i64).is_none()
                        || !matches!(
                            v.get("policy").and_then(Value::as_str),
                            Some("accept" | "drop")
                        )
                    {
                        return Err("chaine de base incomplete");
                    }
                }
                if capture.chaines.insert(cle, v.clone()).is_some() {
                    return Err("chaine dupliquee");
                }
            }
            "rule" => {
                let cle = (famille, texte(&v, "table")?, texte(&v, "chain")?);
                let expressions = v
                    .get_mut("expr")
                    .and_then(Value::as_array_mut)
                    .filter(|v| !v.is_empty())
                    .ok_or("expressions de regle absentes")?;
                for expression in expressions {
                    let instruction = expression
                        .as_object_mut()
                        .filter(|m| m.len() == 1)
                        .ok_or("instruction nft invalide")?;
                    if let Some(compteur) = instruction.get_mut("counter") {
                        let chiffres = compteur
                            .as_object_mut()
                            .filter(|m| {
                                m.len() == 2
                                    && m.get("packets").and_then(Value::as_u64).is_some()
                                    && m.get("bytes").and_then(Value::as_u64).is_some()
                            })
                            .ok_or("compteur non pris en charge")?;
                        // Seuls ces deux nombres sont volatils. Conserver le
                        // compteur lui-meme et sa position dans les expressions.
                        chiffres.insert("packets".into(), 0.into());
                        chiffres.insert("bytes".into(), 0.into());
                    }
                }
                capture.regles.entry(cle).or_default().push(v.clone());
            }
            _ => unreachable!(),
        }
        // Conserver aussi l'ordre global: deux chaines de meme priorite ne
        // doivent pas devenir egales parce qu'un tri a efface leur ordre.
        capture.ordre.push(serde_json::json!({genre: v}));
    }
    if !schema_vu {
        return Err("version de schema nft absente");
    }
    if capture
        .chaines
        .keys()
        .any(|(f, t, _)| !capture.tables.contains_key(&(f.clone(), t.clone())))
        || capture
            .regles
            .keys()
            .any(|c| !capture.chaines.contains_key(c))
    {
        return Err("table ou chaine parente absente");
    }
    Ok(capture)
}

fn lire(chemin: &Path) -> Result<Vec<u8>, &'static str> {
    let initial = std::fs::symlink_metadata(chemin).map_err(|_| "fichier inaccessible")?;
    if !initial.is_file() || initial.len() > MAX_OCTETS {
        return Err("fichier non regulier ou trop grand");
    }
    let mut f = File::open(chemin).map_err(|_| "ouverture impossible")?;
    let avant = f.metadata().map_err(|_| "metadonnees illisibles")?;
    if !avant.is_file() || avant.len() > MAX_OCTETS {
        return Err("fichier non regulier ou trop grand");
    }
    let mut octets = Vec::new();
    (&mut f)
        .take(MAX_OCTETS + 1)
        .read_to_end(&mut octets)
        .map_err(|_| "lecture incomplete")?;
    let apres = f.metadata().map_err(|_| "metadonnees finales illisibles")?;
    if octets.len() as u64 > MAX_OCTETS
        || avant.len() != apres.len()
        || apres.len() != octets.len() as u64
        || !matches!((avant.modified(), apres.modified()), (Ok(a), Ok(b)) if a == b)
    {
        return Err("capture modifiee ou trop grande");
    }
    Ok(octets)
}

fn commencer() -> Rapport {
    Rapport {
        schema_version: 1,
        scope: "nft-json-comparison",
        verdict: "UNMEASURED",
        started_at_unix_ms: heure(),
        completed_at_unix_ms: None,
        duration_ms: 0,
        source: "user-supplied-snapshots",
        expected_source: "user-supplied-snapshot",
        policy_schema_version: None,
        live_kernel: false,
        generation_verified: false,
        network_security: "not-evaluated",
        expected_counts: None,
        observed_counts: None,
        differences: Vec::new(),
        failed_input: Some("expected"),
        reason: "reference illisible ou non prise en charge",
        limitation: LIMITE,
    }
}

fn reference(r: &mut Rapport, attendu: &Path) -> Result<Capture, &'static str> {
    let a = analyser(&lire(attendu)?)?;
    if !a.chaines.values().any(|v| v.get("hook").is_some()) {
        return Err("reference sans chaine de base");
    }
    r.expected_counts = Some(a.compte());
    r.failed_input = Some("observed");
    Ok(a)
}

fn confronter(r: &mut Rapport, a: Capture, octets: &[u8]) -> Result<(), &'static str> {
    let b = analyser(octets)?;
    r.observed_counts = Some(b.compte());
    r.failed_input = None;
    if a.tables != b.tables {
        r.differences.push("tables");
    }
    if a.chaines != b.chaines {
        r.differences.push("chains");
    }
    if a.regles != b.regles {
        r.differences.push("rules");
    }
    if r.differences.is_empty() && a.ordre != b.ordre {
        r.differences.push("object-order");
    }
    r.verdict = if r.differences.is_empty() {
        "MATCH"
    } else {
        "MISMATCH"
    };
    Ok(())
}

fn terminer(mut r: Rapport, debut: Instant, resultat: Result<(), &'static str>) -> Rapport {
    r.reason = match resultat {
        Ok(()) => {
            "comparaison structurelle; seuls handles et valeurs des compteurs anonymes sont ignores"
        }
        Err(raison) => raison,
    };
    r.completed_at_unix_ms = heure();
    r.duration_ms = debut.elapsed().as_millis();
    r
}

pub fn verifier(attendu: &Path, observe: &Path) -> Rapport {
    let debut = Instant::now();
    let mut r = commencer();
    let resultat = (|| {
        let a = reference(&mut r, attendu)?;
        confronter(&mut r, a, &lire(observe)?)
    })();
    terminer(r, debut, resultat)
}

pub async fn verifier_actif(attendu: &Path) -> Rapport {
    let debut = Instant::now();
    let mut r = commencer();
    r.scope = "nft-kernel-comparison";
    r.source = "kernel-netlink-and-system-nft";
    r.limitation = "Reference utilisateur non authentifiee; nftables du namespace courant uniquement, pas une preuve d'etancheite du VPN.";
    let resultat = async {
        let a = reference(&mut r, attendu)?;
        #[cfg(target_os = "linux")]
        {
            let octets = crate::preuve_nft_linux::collecter().await?;
            r.live_kernel = true;
            r.generation_verified = true;
            confronter(&mut r, a, &octets)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = a;
            Err("collecte nft active disponible uniquement sous Linux")
        }
    }
    .await;
    terminer(r, debut, resultat)
}

pub async fn verifier_politique(politique: &Path, observe: Option<&Path>, actif: bool) -> Rapport {
    let debut = Instant::now();
    let mut r = commencer();
    r.expected_source = "bifrost-policy-v1-user-declared";
    r.source = "user-supplied-snapshot";
    r.failed_input = Some("policy");
    r.limitation = "Intention declaree, pas le profil actif atteste; comparaison nft uniquement, pas une preuve d'etancheite du VPN.";
    if actif {
        r.scope = "nft-kernel-comparison";
        r.source = "kernel-netlink-and-system-nft";
    }
    let resultat = async {
        let Unique(v) = serde_json::from_slice(&lire(politique)?)
            .map_err(|_| "politique JSON invalide ou ambigue")?;
        #[cfg(target_os = "linux")]
        {
            let p = bifrost_firewall::politique_nft::Politique::lire(v)?;
            let octets = serde_json::to_vec(&p.reference()?).map_err(|_| "reference impossible")?;
            let a = analyser(&octets)?;
            r.policy_schema_version = Some(1);
            r.expected_counts = Some(a.compte());
            r.failed_input = Some("observed");
            let b = if actif {
                let b = crate::preuve_nft_linux::collecter().await?;
                r.live_kernel = true;
                r.generation_verified = true;
                b
            } else {
                lire(observe.ok_or("capture observee absente")?)?
            };
            confronter(&mut r, a, &b)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (v, observe);
            Err("reference de politique nft disponible uniquement sous Linux")
        }
    }
    .await;
    terminer(r, debut, resultat)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn les_doublons_json_sont_refuses_meme_en_profondeur() {
        for texte in [
            r#"{"nftables":[],"nftables":[]}"#,
            r#"{"a":[{"b":1,"b":1}]}"#,
        ] {
            assert!(serde_json::from_str::<Unique>(texte).is_err());
        }
    }

    #[test]
    fn les_entiers_ne_sont_pas_arrondis_et_les_flottants_sont_refuses() {
        assert!(serde_json::from_str::<Unique>("18446744073709551615").is_ok());
        for texte in ["18446744073709551616", "1.5", "1e3"] {
            assert!(serde_json::from_str::<Unique>(texte).is_err());
        }
    }
}
