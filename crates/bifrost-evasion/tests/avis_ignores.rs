//! Les deux listes d'avis ignores doivent dire la meme chose.
//!
//! # Pourquoi cette recette existe
//!
//! `cargo audit` et `cargo deny check advisories` lisent la MEME base RustSec,
//! et chacun sa liste d'exceptions: `deny.toml` d'un cote, `.cargo/audit.toml`
//! de l'autre, sous deux formes differentes - une table `{ id, reason }` ici,
//! une simple chaine la. Un seul reglage, deux endroits, deux syntaxes.
//!
//! C'est exactement la forme du defaut trouve trois fois en aout 2026 en
//! portant le produit sur Windows: un reglage porte par une plateforme et pas
//! par l'autre, qui ne se voit qu'a l'execution et seulement dans un cas. Ici
//! la divergence serait pire que muette, elle serait rassurante: la CI
//! resterait verte pendant qu'un des deux outils tairait un avis que l'autre
//! signale, et personne ne saurait lequel des deux a raison.
//!
//! # Ce qu'elle ne fait pas
//!
//! Elle ne juge aucun avis. Elle ne dit pas qu'ignorer RUSTSEC-2024-0436 est
//! une bonne idee - ce raisonnement-la vit dans `deny.toml`, a cote de
//! l'entree, et il est date. Elle dit seulement que les deux fichiers portent
//! le meme ensemble d'identifiants.

use std::collections::BTreeSet;
use std::path::PathBuf;

fn racine() -> PathBuf {
    // `CARGO_MANIFEST_DIR` pointe sur crates/bifrost-evasion; la racine de
    // l'espace de travail est deux crans au-dessus. Meme idiome que
    // `frontiere_licence.rs`, qui y lance `cargo metadata`.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("la racine de l'espace de travail doit exister")
        .to_path_buf()
}

fn lire(relatif: &str) -> String {
    let chemin = racine().join(relatif);
    std::fs::read_to_string(&chemin)
        .unwrap_or_else(|e| panic!("{} illisible: {e}", chemin.display()))
}

/// Les identifiants RUSTSEC portes par les lignes ACTIVES d'un fichier.
///
/// Les lignes de commentaire sont ecartees, et c'est indispensable ici:
/// `deny.toml` explique longuement pourquoi il ignore l'avis, en le nommant
/// plusieurs fois en prose. Les compter donnerait une egalite fausse dans un
/// sens comme dans l'autre.
///
/// Pas de parseur TOML: `bifrost-evasion` ne depend que de `serde`, et son
/// manifeste le dit. Le format d'un identifiant RUSTSEC est fixe, la
/// reconnaitre a la main coute moins qu'une dependance de plus.
fn avis_actifs(texte: &str) -> BTreeSet<String> {
    let mut vus = BTreeSet::new();
    for ligne in texte.lines() {
        if ligne.trim_start().starts_with('#') {
            continue;
        }
        vus.extend(identifiants(ligne));
    }
    vus
}

fn identifiants(ligne: &str) -> Vec<String> {
    let mut trouves = Vec::new();
    let mut i = 0;
    while let Some(pos) = ligne[i..].find("RUSTSEC-") {
        let debut = i + pos;
        // RUSTSEC-AAAA-NNNN: huit caracteres de prefixe, quatre chiffres, un
        // tiret, quatre chiffres.
        let fin = debut + 8 + 4 + 1 + 4;
        // `get` et non l'indexation directe: la fin tombe a une longueur fixe
        // en OCTETS, et une ligne peut porter un caractere multi-octets juste
        // apres l'identifiant. Indexer au milieu d'un caractere panique.
        if let Some(candidat) = ligne.get(debut..fin) {
            let corps: Vec<char> = candidat.chars().skip(8).collect();
            let bien_forme = corps.len() == 9
                && corps[..4].iter().all(|c| c.is_ascii_digit())
                && corps[4] == '-'
                && corps[5..].iter().all(|c| c.is_ascii_digit());
            if bien_forme {
                trouves.push(candidat.to_owned());
            }
        }
        i = debut + 8;
    }
    trouves
}

#[test]
fn les_deux_listes_d_avis_ignores_concordent() {
    let deny = lire("deny.toml");
    let audit = lire(".cargo/audit.toml");

    let cote_deny = avis_actifs(&deny);
    let cote_audit = avis_actifs(&audit);

    assert_eq!(
        cote_deny, cote_audit,
        "deny.toml et .cargo/audit.toml n'ignorent pas les memes avis.\n\
         cargo-deny: {cote_deny:?}\n\
         cargo-audit: {cote_audit:?}\n\
         Un avis ignore d'un seul cote laisse la CI verte pendant qu'un des \
         deux outils le signale et que l'autre le tait."
    );
}

/// Le controle positif. Sans lui, une extraction qui rendrait toujours
/// l'ensemble vide ferait passer la recette precedente sans rien comparer -
/// deux ensembles vides sont egaux.
#[test]
fn l_extraction_trouve_reellement_quelque_chose() {
    for fichier in ["deny.toml", ".cargo/audit.toml"] {
        let texte = lire(fichier);
        if !texte.contains("RUSTSEC-") {
            // Legitime: le jour ou plus aucun avis n'est ignore, les deux
            // fichiers seront muets et la recette d'egalite suffira.
            continue;
        }
        assert!(
            !avis_actifs(&texte).is_empty(),
            "{fichier} nomme un avis RUSTSEC mais l'extraction n'en trouve \
             aucun sur ses lignes actives"
        );
    }
}

/// Et le temoin que les commentaires sont bien ecartes. `deny.toml` nomme son
/// avis en prose plusieurs fois avant de l'ignorer une seule; si les
/// commentaires comptaient, l'egalite ci-dessus tomberait pour une raison qui
/// n'a rien a voir avec une divergence reelle.
#[test]
fn les_commentaires_ne_comptent_pas() {
    let deny = lire("deny.toml");
    let en_commentaire: usize = deny
        .lines()
        .filter(|l| l.trim_start().starts_with('#'))
        .map(|l| identifiants(l).len())
        .sum();
    assert!(
        en_commentaire > 0,
        "ce temoin suppose que deny.toml nomme l'avis en prose; il ne le fait \
         plus, donc il ne prouve plus rien"
    );
    assert_eq!(
        avis_actifs(&deny).len(),
        1,
        "un seul avis est ignore aujourd'hui, et il l'est sur une ligne active"
    );
}
