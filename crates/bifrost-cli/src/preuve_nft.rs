//! Comparaison structurelle nft JSON: fichiers, ou collecte passive Linux.
//! La reference fournie reste non authentifiee, meme pour une collecte noyau.
//! Avec `--politique-daemon`, l'attendu est la declaration du daemon: elle est
//! relue avant et apres la collecte, et reste un attendu, jamais une mesure.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};

use crate::declaration::IdentiteDaemon;

mod nommes;
#[cfg(test)]
mod recettes_objets;

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
    /// Objets nommes (`nommes`), declaration sans elements.
    objets: BTreeMap<nommes::Objet, Value>,
    /// Elements des sets et des maps, dans l'ordre canonique.
    elements: BTreeMap<nommes::Objet, Vec<Value>>,
}

#[derive(Serialize)]
struct Compte {
    tables: usize,
    chains: usize,
    rules: usize,
    objects: usize,
}

impl Capture {
    fn compte(&self) -> Compte {
        Compte {
            tables: self.tables.len(),
            chains: self.chaines.len(),
            rules: self.regles.values().map(Vec::len).sum(),
            objects: self.objets.len(),
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
    #[serde(skip_serializing_if = "IdentiteDaemon::hors_perimetre")]
    daemon_identity: IdentiteDaemon,
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
        let identite = self.daemon_identity.ligne();
        format!(
            "{}  {}\n{}\n{identite}entree non mesuree: {}\necarts: {}\n\n{}\n",
            self.verdict,
            self.scope,
            self.reason,
            self.failed_input.unwrap_or("aucune"),
            self.differences.join(", "),
            self.limitation
        )
    }
}

/// Horodatage d'un rapport de preuve, partage avec `prove routes`.
pub(crate) fn heure() -> Option<u128> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_millis())
}

// Value accepte normalement deux cles identiques en gardant la derniere.
// Une capture ambigue n'est jamais une observation acceptable, meme si les
// doublons ont la meme valeur. Le refus vaut aussi au fond d'une expression.
// Partage avec le lecteur de la declaration du daemon, pour la meme raison.
pub(crate) struct Unique(pub(crate) Value);

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
    let mut espaces = BTreeSet::new();
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
        // Un type que le comparateur ne sait pas lire n'est jamais omis: la
        // capture entiere reste non mesuree.
        let nomme = nommes::lisible(genre);
        if nomme.is_none() && !matches!(genre.as_str(), "table" | "chain" | "rule") {
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
        if let Some(g) = nomme {
            let table = texte(&v, "table")?;
            let nom = texte(&v, "name")?;
            if !espaces.insert((g.espace(), famille.clone(), table.clone(), nom.clone())) {
                return Err("objet nomme duplique");
            }
            let lu = nommes::lire(g, v)?;
            capture.ordre.push(serde_json::json!({genre: lu.complet()}));
            let cle = (g.nom.to_owned(), famille, table, nom);
            if let Some(elements) = lu.elements {
                capture.elements.insert(cle.clone(), elements);
            }
            capture.objets.insert(cle, lu.declaration);
            continue;
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
                    // Seules les valeurs d'etat sont neutralisees (voir
                    // `nommes`): l'instruction elle-meme et sa position dans
                    // les expressions restent comparees.
                    nommes::instruction(instruction)?;
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
    let table_absente =
        |f: &String, t: &String| !capture.tables.contains_key(&(f.clone(), t.clone()));
    if capture.chaines.keys().any(|(f, t, _)| table_absente(f, t))
        || capture
            .objets
            .keys()
            .any(|(_, f, t, _)| table_absente(f, t))
        || capture
            .regles
            .keys()
            .any(|c| !capture.chaines.contains_key(c))
    {
        return Err("table ou chaine parente absente");
    }
    Ok(capture)
}

/// Lecture bornee d'un fichier regulier, stable pendant la lecture. Partagee
/// avec `prove routes`, qui lit son intention par le meme chemin.
pub(crate) fn lire(chemin: &Path) -> Result<Vec<u8>, &'static str> {
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
        daemon_identity: IdentiteDaemon::HorsPerimetre,
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
    nommes::ecarts(
        (&a.objets, &a.elements),
        (&b.objets, &b.elements),
        &mut r.differences,
    );
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
            "comparaison structurelle; seuls handles et valeurs d'etat (compteurs, consommation des quotas, dernier passage, expiration des elements) sont ignores"
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

/// L'attendu est la declaration du daemon joint par `socket`, le noyau
/// l'observe. Linux seulement: la reference et la collecte n'existent que la.
pub async fn verifier_declaration(socket: &str) -> Rapport {
    #[cfg(target_os = "linux")]
    {
        verifier_declaration_avec(
            move || crate::declaration::lire(socket),
            crate::preuve_nft_linux::collecter,
        )
        .await
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = socket;
        let debut = Instant::now();
        let r = commencer_declaration();
        terminer(
            r,
            debut,
            Err("preuve par declaration du daemon disponible uniquement sous Linux"),
        )
    }
}

fn commencer_declaration() -> Rapport {
    let mut r = commencer();
    r.scope = "nft-kernel-comparison";
    r.source = "kernel-netlink-and-system-nft";
    r.expected_source = "daemon-declared-active-policy";
    r.daemon_identity = IdentiteDaemon::NonVerifiee;
    r.failed_input = Some("daemon-declaration");
    r.reason = "declaration du daemon non lue";
    r.limitation = "Attendu declare par le daemon, pas observe: une correspondance dit que le noyau porte ce que le daemon dit avoir pose; nftables du namespace courant uniquement, pas une preuve d'etancheite du VPN.";
    r
}

impl crate::declaration::Suivi for Rapport {
    fn entree_manquante(&mut self, entree: &'static str) {
        self.failed_input = Some(entree);
    }
    fn identite(&mut self, identite: IdentiteDaemon) {
        self.daemon_identity = identite;
    }
}

/// Le moteur dont cette preuve lit la projection: les six champs projetes
/// sont ceux que lit le rendu nft; pour un autre moteur ils ne decrivent pas
/// ce qui a ete pose, et une correspondance serait fortuite.
#[cfg(target_os = "linux")]
const PERIMETRE: crate::declaration::Perimetre = crate::declaration::Perimetre {
    moteur: "nftables",
    autre_moteur: "moteur de pare-feu du daemon hors perimetre de la reference nft",
    echec: "derniere application du daemon en echec: etat du noyau inconnu du daemon",
};

/// Le protocole, separe de ses deux sources pour que les recettes sans
/// privilege le jouent avec un faux daemon et une fausse capture.
///
/// N1, collecte encadree par deux GETGEN, N2: le protocole commun des preuves
/// par declaration (`declaration::encadrer`), avec son exigence d'identite et
/// ce qu'il en dit au rapport. Seule la mesure est propre a nft.
#[cfg(target_os = "linux")]
pub(crate) async fn verifier_declaration_avec<L, FL, C, FC>(
    lire_declaration: L,
    collecter: C,
) -> Rapport
where
    L: FnMut() -> FL,
    FL: std::future::Future<Output = Result<crate::declaration::Lue, crate::declaration::Refus>>,
    C: FnOnce() -> FC,
    FC: std::future::Future<Output = Result<Vec<u8>, &'static str>>,
{
    let debut = Instant::now();
    let mut r = commencer_declaration();
    let resultat = async {
        let (a, b) = crate::declaration::encadrer(
            &mut r,
            lire_declaration,
            |d| crate::declaration::politique_posee(d, &PERIMETRE).cloned(),
            async move |r: &mut Rapport, politique: Value| {
                // Le meme lecteur strict que `--politique`: la declaration ne
                // passe pas par un chemin plus indulgent que celui d'un
                // fichier. Ce qu'il refuse (interface `lo`, UID root ou
                // partage, DNS hors boucle locale avec un resolveur) est hors
                // du perimetre de la reference: NON MESURE.
                let p = bifrost_firewall::politique_nft::Politique::lire(politique)
                    .map_err(|_| "politique declaree hors du perimetre de la reference nft v1")?;
                let octets =
                    serde_json::to_vec(&p.reference()?).map_err(|_| "reference impossible")?;
                let a = analyser(&octets)?;
                r.policy_schema_version = Some(1);
                r.expected_counts = Some(a.compte());
                r.failed_input = Some("observed");
                let b = collecter().await?;
                r.live_kernel = true;
                r.generation_verified = true;
                Ok((a, b))
            },
        )
        .await?;
        confronter(&mut r, a, &b)
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
