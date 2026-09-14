//! Le daemon n'apprend pas a parler au reseau ouvert.
//!
//! # Ce que cette frontiere protege
//!
//! Le daemon tourne en root, en permanence, avec un socket que d'autres
//! peuvent joindre. La recuperation d'un profil, elle, parle a des serveurs qui
//! ne sont pas les notres - c'est meme l'hypothese de depart du multi-canal.
//! Mettre les deux dans le meme processus ferait qu'un defaut dans un analyseur
//! HTTP ou TLS deviendrait une compromission racine permanente.
//!
//! C'est le raisonnement que ce depot applique deja au compte `bifrost-coeur`,
//! dont le README dit qu'il fait tourner "du code tiers qui analyse du trafic
//! reseau hostile pendant que le daemon tourne en root". La meme phrase vaut
//! pour un client HTTP.
//!
//! Et c'est la signature qui rend la separation tenable: le profil recupere est
//! authentifie par une cle, donc son transport n'a besoin d'aucun privilege.
//! Sans elle, il aurait fallu que le processus de confiance aille le chercher
//! lui-meme.
//!
//! # Pourquoi une recette plutot qu'un paragraphe
//!
//! Un `bifrost-amorce.workspace = true` ajoute par distraction au manifeste du
//! daemon ne se verrait nulle part: rien ne casserait, tout compilerait, et la
//! frontiere serait franchie en silence. Ici, elle tombe avant la revue.

use std::collections::{BTreeSet, VecDeque};
use std::process::Command;

/// Ce qu'un daemon privilegie n'a pas a savoir faire.
///
/// Nommes un par un plutot que par motif: une liste explicite se relit et se
/// discute, la ou un motif sur "http" attraperait un jour un paquet sans rapport
/// et se ferait relacher pour cette raison.
const INTERDITS: &[&str] = &[
    "ureq",
    "reqwest",
    "hyper",
    "rustls",
    "aws-lc-rs",
    "aws-lc-sys",
    "ring",
    "native-tls",
    "openssl",
    "openssl-sys",
    "curl",
    "curl-sys",
    "wreq",
    "boring",
    "bifrost-amorce",
];

fn metadata() -> serde_json::Value {
    let sortie = Command::new(option_env!("CARGO").unwrap_or("cargo"))
        .args(["metadata", "--format-version", "1"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("cargo metadata doit pouvoir tourner");
    assert!(
        sortie.status.success(),
        "cargo metadata a echoue: {}",
        String::from_utf8_lossy(&sortie.stderr)
    );
    serde_json::from_slice(&sortie.stdout).expect("metadata illisible")
}

/// Tout ce dont un paquet depend, transitivement, hors dependances de recette.
///
/// Les `dev-dependencies` sont exclues parce qu'elles n'entrent dans aucun
/// binaire livre. Les inclure ferait tomber la recette sur les doublures des
/// recettes elles-memes, et l'on serait tente de relacher la regle entiere.
///
/// # Ce que cette ferme est, exactement
///
/// Le graphe RESOLU, toutes cibles et toutes features confondues - et non le
/// graphe reellement compile. La difference se mesure: `bifrost-amorce` a une
/// arete vers `ring` ici, alors que `cargo tree -i ring` n'imprime rien, parce
/// que la feature qui l'activerait n'est pas prise.
///
/// C'est volontairement le plus large des deux. Une frontiere qui n'interdirait
/// que ce qui est compile AUJOURD'HUI laisserait passer l'ajout d'une feature,
/// c'est-a-dire un caractere dans un manifeste, et c'est precisement la classe
/// de changement qui echappe a une revue. Le prix a payer est qu'un jour un
/// paquet interdit apparaitra sans etre compile: ce sera alors une decision a
/// prendre, pas une regle a relacher.
fn ferme_transitive(meta: &serde_json::Value, racine: &str) -> BTreeSet<String> {
    let noeuds = meta["resolve"]["nodes"]
        .as_array()
        .expect("champ resolve.nodes absent");

    let par_id: std::collections::HashMap<&str, &serde_json::Value> = noeuds
        .iter()
        .map(|n| (n["id"].as_str().unwrap_or_default(), n))
        .collect();

    let nom_de = |id: &str| -> String {
        meta["packages"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|p| p["id"].as_str() == Some(id))
            .and_then(|p| p["name"].as_str())
            .unwrap_or_default()
            .to_string()
    };

    let depart = noeuds
        .iter()
        .find(|n| nom_de(n["id"].as_str().unwrap_or_default()) == racine)
        .unwrap_or_else(|| panic!("paquet {racine} introuvable dans le graphe"));

    let mut vus = BTreeSet::new();
    let mut a_voir = VecDeque::new();
    a_voir.push_back(depart["id"].as_str().unwrap_or_default().to_string());

    while let Some(id) = a_voir.pop_front() {
        let Some(noeud) = par_id.get(id.as_str()) else {
            continue;
        };
        for dep in noeud["deps"].as_array().into_iter().flatten() {
            // Seules les aretes normales et de construction comptent: une arete
            // "dev" ne suit pas le code jusqu'au binaire installe.
            let vivante = dep["dep_kinds"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|k| !matches!(k["kind"].as_str(), Some("dev")));
            if !vivante {
                continue;
            }
            let Some(pkg) = dep["pkg"].as_str() else {
                continue;
            };
            let nom = nom_de(pkg);
            if vus.insert(nom) {
                a_voir.push_back(pkg.to_string());
            }
        }
    }
    vus
}

#[test]
fn le_daemon_ne_parle_pas_au_reseau_ouvert() {
    let meta = metadata();
    let ferme = ferme_transitive(&meta, "bifrost-daemon");

    // Controle positif: une ferme vide passerait sans rien avoir verifie.
    assert!(
        ferme.contains("tokio"),
        "graphe suspect, le daemon devrait au moins dependre de tokio: {ferme:?}"
    );

    let trouves: Vec<&String> = ferme
        .iter()
        .filter(|d| INTERDITS.contains(&d.as_str()))
        .collect();
    assert!(
        trouves.is_empty(),
        "le daemon tourne en root: un analyseur de protocole hostile n'a rien a \
         y faire. Trouve: {trouves:?}. La recuperation vit dans bifrost-amorce, \
         dont seul le client depend."
    );
}

/// Le temoin negatif de la recette precedente.
///
/// Sans lui, `le_daemon_ne_parle_pas_au_reseau_ouvert` passerait tout aussi bien
/// si la liste des interdits ne correspondait a rien, ou si la ferme transitive
/// etait mal calculee. Ici, la meme mecanique doit TROUVER ce qu'elle cherche.
#[test]
fn le_client_lui_en_depend_bien() {
    let meta = metadata();
    let ferme = ferme_transitive(&meta, "bifrost-cli");

    assert!(
        ferme.contains("bifrost-amorce"),
        "le client doit dependre de l'amorce, sinon la recette jumelle ne \
         prouve rien: {ferme:?}"
    );
    assert!(
        ferme.contains("ureq"),
        "et donc d'un client HTTP, transitivement: {ferme:?}"
    );
}
