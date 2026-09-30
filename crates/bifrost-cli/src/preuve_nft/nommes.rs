//! Objets nft nommes et autonomes: sets, maps, flowtables et objets a etat.
//!
//! Chaque type de `GENRES` est COMPARE, pas refuse: identite (famille, table,
//! nom), declaration complete, et pour les sets et les maps leurs elements.
//! Un type absent de `GENRES` n'est jamais omis: `analyser` le refuse et la
//! comparaison reste NON MESUREE.
//!
//! Les formes lues sont celles que `nft -j list ruleset` rend, relevees le
//! 30/09/2026 avec nft 1.0.9 sur un noyau 7.0, dans un namespace jetable.
//!
//! Les valeurs d'etat que le noyau change seul sont neutralisees ICI, et
//! nulle part ailleurs, chacune nommee avec sa raison. Ce sont les memes que
//! les deux nombres des compteurs anonymes: l'objet ou l'instruction qui les
//! porte reste compare, sa presence et sa position aussi, seule la valeur est
//! ignoree.
//!
//! - `packets`/`bytes` d'un compteur, nomme, anonyme ou d'element: le trafic.
//! - `used` d'un quota nomme: la consommation. nft l'ecrit toujours; la limite
//!   (`bytes`) et le sens (`inv`) restent compares.
//! - `used`/`used_unit` d'un quota anonyme ou d'element: la consommation, que
//!   nft n'ecrit qu'une fois non nulle, dans une unite qui suit sa grandeur.
//!   Leur presence est donc elle-meme de l'etat; la limite reste comparee.
//! - `last`: `null` tant que rien n'est passe, puis le temps ecoule depuis le
//!   dernier passage. Les deux formes valent `null`.
//! - `expires` d'un element: le temps restant, decompte par le noyau. Son
//!   delai (`timeout` de l'element ou du set) reste compare.
//!
//! La consommation d'un quota ou la valeur d'un compteur peuvent aussi avoir
//! ete posees a la creation: elles ne sont pas comparees davantage. Un element
//! qu'un set dynamique gagne ou perd avec le trafic, lui, change l'appartenance:
//! c'est un ecart.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value};

const MALFORME: &str = "objet nft nomme malforme";

/// Un type d'objet nomme lisible: son nom dans le JSON de nft, la categorie
/// d'ecart de sa declaration et, pour un set ou une map, celle de ses elements.
pub(super) struct Genre {
    pub(super) nom: &'static str,
    categorie: &'static str,
    elements: Option<&'static str>,
}

const fn genre(nom: &'static str, categorie: &'static str) -> Genre {
    Genre {
        nom,
        categorie,
        elements: None,
    }
}

/// Dans l'ordre ou les categories d'ecart sont rapportees. `secmark` n'y est
/// pas: le noyau de mesure le refuse sans module de securite a contextes, et
/// sa forme JSON n'a donc pas ete observee. Ni `tunnel`, que nft 1.0.9 ne
/// connait pas, ni `element`, une commande qu'une liste ne rend jamais. Tous
/// trois restent NON MESURES.
const GENRES: [Genre; 10] = [
    Genre {
        nom: "set",
        categorie: "sets",
        elements: Some("set-elements"),
    },
    Genre {
        nom: "map",
        categorie: "maps",
        elements: Some("map-elements"),
    },
    genre("flowtable", "flowtables"),
    genre("counter", "counters"),
    genre("quota", "quotas"),
    genre("limit", "limits"),
    genre("ct helper", "ct-helpers"),
    genre("ct timeout", "ct-timeouts"),
    genre("ct expectation", "ct-expectations"),
    genre("synproxy", "synproxies"),
];

/// Le genre d'un objet nomme que ce comparateur sait lire, s'il en est un.
pub(super) fn lisible(nom: &str) -> Option<&'static Genre> {
    GENRES.iter().find(|g| g.nom == nom)
}

impl Genre {
    /// Sets et maps partagent un espace de noms dans une table: le noyau ne
    /// laisse pas un set et une map porter le meme nom.
    pub(super) fn espace(&self) -> &'static str {
        if self.nom == "map" { "set" } else { self.nom }
    }
}

/// Un objet lu: sa declaration sans ses elements, et pour un set ou une map
/// ses elements dans l'ordre canonique.
pub(super) struct Lu {
    pub(super) declaration: Value,
    pub(super) elements: Option<Vec<Value>>,
}

impl Lu {
    /// La forme complete, pour l'ordre global des declarations.
    pub(super) fn complet(&self) -> Value {
        let mut v = self.declaration.clone();
        if let (Some(m), Some(e)) = (v.as_object_mut(), &self.elements) {
            m.insert("elem".into(), Value::Array(e.clone()));
        }
        v
    }
}

fn entier(m: &Map<String, Value>, cle: &str) -> Result<(), &'static str> {
    m.get(cle)
        .and_then(Value::as_u64)
        .map(|_| ())
        .ok_or(MALFORME)
}

fn chaine(m: &Map<String, Value>, cle: &str) -> Result<(), &'static str> {
    m.get(cle)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(|_| ())
        .ok_or(MALFORME)
}

/// Un type de donnees de set: un nom, ou la liste des noms d'une concatenation.
fn type_de_donnees(v: Option<&Value>) -> Result<(), &'static str> {
    let nom = |t: &Value| t.as_str().is_some_and(|s| !s.is_empty());
    match v {
        Some(t @ Value::String(_)) if nom(t) => Ok(()),
        Some(Value::Array(a)) if !a.is_empty() && a.iter().all(nom) => Ok(()),
        _ => Err(MALFORME),
    }
}

/// Remet a zero des valeurs d'etat entieres, qui doivent etre presentes.
fn neutraliser(m: &mut Map<String, Value>, cles: &[&str]) -> Result<(), &'static str> {
    for cle in cles {
        entier(m, cle)?;
        m.insert((*cle).into(), 0.into());
    }
    Ok(())
}

/// Lit un objet nomme, handle deja retire et famille deja validee.
pub(super) fn lire(genre: &Genre, mut v: Value) -> Result<Lu, &'static str> {
    let m = v.as_object_mut().ok_or(MALFORME)?;
    let mut elements = None;
    match genre.nom {
        "set" | "map" => {
            type_de_donnees(m.get("type"))?;
            // Une map porte le type de ses valeurs, un set n'en porte pas.
            let map = genre.nom == "map";
            if map != m.contains_key("map") {
                return Err(MALFORME);
            }
            if map {
                type_de_donnees(m.get("map"))?;
            }
            // nft n'ecrit `elem` que pour un set non vide.
            let liste = match m.remove("elem") {
                None => Vec::new(),
                Some(Value::Array(a)) => a,
                Some(_) => return Err(MALFORME),
            };
            elements = Some(canonique(map, liste)?);
        }
        "flowtable" => {
            chaine(m, "hook")?;
            m.get("prio").and_then(Value::as_i64).ok_or(MALFORME)?;
            // nft ecrit un peripherique seul en chaine, plusieurs en liste,
            // aucun pas du tout. Les peripheriques d'un flowtable sont un
            // ensemble: ni leur ordre ni cette forme n'ont de sens. Un doublon
            // n'est pas une sortie de nft.
            let mut peripheriques = match m.remove("dev") {
                None => Vec::new(),
                Some(Value::String(s)) => vec![s],
                Some(Value::Array(a)) => a
                    .into_iter()
                    .map(|d| match d {
                        Value::String(s) => Ok(s),
                        _ => Err(MALFORME),
                    })
                    .collect::<Result<_, _>>()?,
                Some(_) => return Err(MALFORME),
            };
            if peripheriques.iter().any(String::is_empty) {
                return Err(MALFORME);
            }
            peripheriques.sort();
            let avant = peripheriques.len();
            peripheriques.dedup();
            if peripheriques.len() != avant {
                return Err(MALFORME);
            }
            m.insert("dev".into(), peripheriques.into());
        }
        "counter" => neutraliser(m, &["packets", "bytes"])?,
        "quota" => {
            entier(m, "bytes")?;
            neutraliser(m, &["used"])?;
        }
        "limit" => {
            entier(m, "rate")?;
            chaine(m, "per")?;
        }
        "ct helper" => {
            chaine(m, "type")?;
            chaine(m, "protocol")?;
        }
        "ct timeout" | "ct expectation" => chaine(m, "protocol")?,
        "synproxy" => {
            entier(m, "mss")?;
            entier(m, "wscale")?;
        }
        _ => return Err("type d'objet nft non pris en charge"),
    }
    Ok(Lu {
        declaration: v,
        elements,
    })
}

/// Les elements d'un set ou d'une map, dans un ordre canonique.
///
/// Ordre: le noyau ne donne aucun sens a l'ordre des elements d'un set (une
/// appartenance, pas une liste), et l'ordre rendu depend du tri de nft ou de
/// la structure du noyau. Le comparer ferait un ecart de ce qui n'en est pas
/// un; trier par cle ne peut masquer aucun changement d'appartenance, ni une
/// valeur de map changee, qui reste attachee a sa cle.
///
/// Doublons: un set du noyau ne contient jamais deux fois la meme cle, ni une
/// map deux valeurs pour une cle. Une capture qui en porte n'est pas la sortie
/// de nft: NON MESUREE, jamais fusionnee.
fn canonique(map: bool, liste: Vec<Value>) -> Result<Vec<Value>, &'static str> {
    let mut vues = BTreeSet::new();
    let mut elements = Vec::with_capacity(liste.len());
    for e in liste {
        let e = if map {
            let Value::Array(mut paire) = e else {
                return Err(MALFORME);
            };
            if paire.len() != 2 {
                return Err(MALFORME);
            }
            let valeur = paire.pop().ok_or(MALFORME)?;
            let cle = element(paire.pop().ok_or(MALFORME)?)?;
            Value::Array(vec![cle, valeur])
        } else {
            element(e)?
        };
        let cle = cle_de(if map { &e[0] } else { &e });
        if !vues.insert(cle.clone()) {
            return Err("element de set duplique");
        }
        elements.push((cle, e));
    }
    elements.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(elements.into_iter().map(|(_, e)| e).collect())
}

/// La cle d'un element: sa valeur, sans ses attributs (delai, commentaire,
/// instructions). Serialisee: les cles d'objet JSON y sont triees.
fn cle_de(e: &Value) -> String {
    let valeur = e
        .as_object()
        .filter(|m| m.len() == 1)
        .and_then(|m| m.get("elem"))
        .and_then(|corps| corps.get("val"))
        .unwrap_or(e);
    valeur.to_string()
}

/// Un element: une valeur nue, ou `{"elem": {"val": ..., ...}}` quand il porte
/// un delai, une expiration, un commentaire ou des instructions.
fn element(mut e: Value) -> Result<Value, &'static str> {
    let Some(corps) = e
        .as_object_mut()
        .filter(|m| m.len() == 1)
        .and_then(|m| m.get_mut("elem"))
    else {
        return Ok(e);
    };
    let corps = corps
        .as_object_mut()
        .filter(|m| m.contains_key("val"))
        .ok_or(MALFORME)?;
    if let Some(reste) = corps.remove("expires")
        && reste.as_u64().is_none()
    {
        return Err(MALFORME);
    }
    if let Some(c) = corps.get_mut("counter") {
        compteur(c)?;
    }
    if let Some(q) = corps.get_mut("quota") {
        quota(q)?;
    }
    if let Some(l) = corps.get_mut("last") {
        dernier(l)?;
    }
    Ok(e)
}

/// Un compteur anonyme: exactement ses deux nombres, remis a zero.
fn compteur(c: &mut Value) -> Result<(), &'static str> {
    let chiffres = c
        .as_object_mut()
        .filter(|m| m.len() == 2)
        .ok_or("compteur non pris en charge")?;
    neutraliser(chiffres, &["packets", "bytes"]).map_err(|_| "compteur non pris en charge")
}

/// Un quota anonyme: la limite reste, la consommation part, entiere et
/// unite ensemble ou pas du tout.
fn quota(q: &mut Value) -> Result<(), &'static str> {
    let m = q.as_object_mut().ok_or("quota non pris en charge")?;
    match (m.remove("used"), m.remove("used_unit")) {
        (None, None) => Ok(()),
        (Some(u), Some(Value::String(unite))) if u.as_u64().is_some() && !unite.is_empty() => {
            Ok(())
        }
        _ => Err("quota non pris en charge"),
    }
}

/// `last`: jamais passe (`null`) ou le temps depuis le dernier passage.
fn dernier(l: &mut Value) -> Result<(), &'static str> {
    let valide = match &*l {
        Value::Null => true,
        Value::Object(m) => m.len() == 1 && m.get("used").and_then(Value::as_u64).is_some(),
        _ => false,
    };
    if !valide {
        return Err("dernier passage non pris en charge");
    }
    *l = Value::Null;
    Ok(())
}

/// Une instruction de regle a etat: compteur, quota ou dernier passage.
/// Une reference a un objet nomme (`{"counter": "nom"}`) est comparee telle
/// quelle: c'est l'objet nomme qui porte l'etat, et il est compare a part.
pub(super) fn instruction(i: &mut Map<String, Value>) -> Result<(), &'static str> {
    let reference = |v: &Value| v.as_str().is_some_and(|s| !s.is_empty());
    if let Some(c) = i.get_mut("counter")
        && !reference(c)
    {
        compteur(c)?;
    }
    if let Some(q) = i.get_mut("quota")
        && !reference(q)
    {
        quota(q)?;
    }
    if let Some(l) = i.get_mut("last") {
        dernier(l)?;
    }
    Ok(())
}

/// Identite d'un objet: genre, famille, table, nom.
pub(super) type Objet = (String, String, String, String);

/// Les categories d'ecart des objets nommes, dans l'ordre de `GENRES`.
///
/// Un objet present d'un seul cote, ou dont la declaration differe, est un
/// ecart de sa categorie (`sets`, `counters`...). Les elements ne sont
/// confrontes qu'entre deux sets ou deux maps de meme identite: un set ajoute
/// ou retire est un ecart `sets`, pas `set-elements`.
pub(super) fn ecarts(
    a: (&BTreeMap<Objet, Value>, &BTreeMap<Objet, Vec<Value>>),
    b: (&BTreeMap<Objet, Value>, &BTreeMap<Objet, Vec<Value>>),
    differences: &mut Vec<&'static str>,
) {
    fn du_genre<'a, V>(
        c: &'a BTreeMap<Objet, V>,
        genre: &'static str,
    ) -> impl Iterator<Item = (&'a Objet, &'a V)> {
        c.iter().filter(move |(k, _)| k.0 == genre)
    }
    for g in &GENRES {
        if !du_genre(a.0, g.nom).eq(du_genre(b.0, g.nom)) {
            differences.push(g.categorie);
        }
        if let Some(categorie) = g.elements
            && du_genre(a.1, g.nom).any(|(k, e)| b.1.get(k).is_some_and(|f| f != e))
        {
            differences.push(categorie);
        }
    }
}
