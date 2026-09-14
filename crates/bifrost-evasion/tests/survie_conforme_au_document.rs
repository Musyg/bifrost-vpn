//! Le code du tableau de survie et le document 04 partie 1 disent la meme chose.
//!
//! `survie.rs` porte le tableau operatoire comme donnee; `docs/04-anti-censure-dpi.md`
//! partie 1 le porte comme prose datee. Les deux se rafraichissent a la main,
//! et rien jusqu'ici ne les obligeait a concorder: une source pouvait entrer
//! dans le document et manquer le code, ou l'inverse. Cette garde lie les deux.
//!
//! Elle lit le document par `env!("CARGO_MANIFEST_DIR")` remonte a la racine de
//! l'espace de travail, comme les gardes de source de `suivi_a_jour.rs` et de
//! `bifrost-daemon`, puis compare, pour les cinq techniques candidates du
//! produit et pour chacun des quatre pays censeurs, le statut ET la date que
//! chaque cote porte.
//!
//! # La legende, codee explicitement
//!
//! Le document ecrit quatre statuts en toutes lettres - Fonctionne, Degrade,
//! Incertain, Mort - et ecrit AUSSI "Mort/Degrade" ou "Degrade/Mort" pour les
//! cellules ou la technique tient ou tombe selon un declencheur cote censeur.
//! `survie.rs` aplatit ces deux ecritures composites vers `Incertain` (voir la
//! doc de module de `survie.rs` et l'enum `Statut`). La garde code donc la MEME
//! equivalence; sans elle, elle comparerait deux vocabulaires et rougirait a
//! tort.

use std::path::PathBuf;

use bifrost_evasion::survie::{Pays, statut};
use bifrost_evasion::{Date, Statut, Technique};

fn racine() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("la racine de l'espace de travail doit exister")
        .to_path_buf()
}

fn lire_doc() -> String {
    let chemin = racine().join("docs/04-anti-censure-dpi.md");
    std::fs::read_to_string(&chemin)
        .unwrap_or_else(|e| panic!("{} illisible: {e}", chemin.display()))
}

/// La legende du document 04 partie 1, telle que `survie.rs` l'aplatit.
///
/// Casser cette equivalence - par exemple faire lire "Incertain" comme
/// `Fonctionne` - doit rendre une garde rouge: c'est le sens de la falsification
/// (c) de la tranche.
fn statut_du_document(jeton: &str) -> Statut {
    match jeton {
        "Fonctionne" => Statut::Fonctionne,
        "Degrade" => Statut::Degrade,
        "Incertain" | "Degrade/Mort" | "Mort/Degrade" => Statut::Incertain,
        "Mort" => Statut::Mort,
        autre => panic!(
            "statut inconnu dans le document 04: {autre:?}. La legende ne connait \
             que Fonctionne, Degrade, Incertain, Mort, Degrade/Mort, Mort/Degrade."
        ),
    }
}

/// Le statut en tete d'une cellule, avant toute parenthese ou precision.
///
/// "Incertain (CIDR; ...)" rend "Incertain"; "Mort (IP ban)" rend "Mort";
/// "Mort/Degrade" rend "Mort/Degrade" - aucun espace, aucune parenthese.
fn jeton_de_statut(cellule: &str) -> &str {
    cellule
        .trim()
        .split(|c: char| c == '(' || c.is_whitespace())
        .next()
        .unwrap_or("")
}

/// "2026-07" rend (2026, 7); "2026-Q2" rend (2026, 4). `None` sinon.
///
/// Un trimestre est ramene a son premier mois, comme le fait `survie.rs`
/// ("2026-Q2, ramene au 1er avril"), pour que les deux cotes parlent du meme
/// jour.
fn parser_annee_mois(brut: &str) -> Option<(i32, u8)> {
    let (annee, reste) = brut.trim().split_once('-')?;
    let annee: i32 = annee.trim().parse().ok()?;
    let reste = reste.trim();
    let mois = if let Some(q) = reste.strip_prefix('Q') {
        let trimestre: u8 = q.parse().ok()?;
        if !(1..=4).contains(&trimestre) {
            return None;
        }
        (trimestre - 1) * 3 + 1
    } else {
        let m: u8 = reste.parse().ok()?;
        if !(1..=12).contains(&m) {
            return None;
        }
        m
    };
    Some((annee, mois))
}

/// (annee, mois) attendus pour un pays, lus dans la cellule "Derniere mesure".
///
/// Format du document: une date de base "AAAA-MM" ou "AAAA-Qn", suivie
/// eventuellement d'un remplacement "(Russie: AAAA-MM)" qui ne vaut que pour la
/// Russie.
fn date_du_document(cellule: &str, pays: Pays) -> (i32, u8) {
    let cellule = cellule.trim();
    let base = cellule.split('(').next().unwrap_or("").trim();
    let base = parser_annee_mois(base)
        .unwrap_or_else(|| panic!("date de base illisible dans la cellule {cellule:?}"));

    if pays == Pays::Russie
        && let Some(debut) = cellule.find("Russie:")
    {
        let reste = &cellule[debut + "Russie:".len()..];
        let brut = reste.split(')').next().unwrap_or("").trim();
        if let Some(rus) = parser_annee_mois(brut) {
            return rus;
        }
    }
    base
}

/// La ligne du tableau dont la premiere cellule est EXACTEMENT ce libelle.
///
/// L'egalite exacte, et non un `contains`: "VLESS+REALITY(+Vision)" ne doit pas
/// se confondre avec "VLESS+XTLS-Vision (sans REALITY)", qui porte aussi le mot
/// REALITY.
fn ligne_du_tableau<'a>(doc: &'a str, libelle: &str) -> Option<Vec<&'a str>> {
    for ligne in doc.lines() {
        let ligne = ligne.trim();
        if !ligne.starts_with('|') {
            continue;
        }
        let cellules: Vec<&str> = ligne.split('|').collect();
        // cellules[0] et le dernier sont vides (barres de bord). Il faut au
        // moins la cellule "Derniere mesure" (indice 6).
        if cellules.len() < 7 {
            continue;
        }
        if cellules[1].trim() == libelle {
            return Some(cellules);
        }
    }
    None
}

/// Les cinq techniques candidates du produit et leur libelle EXACT dans le
/// tableau du document 04 partie 1.
const CANDIDATES: [(Technique, &str); 5] = [
    (Technique::RealityVision, "VLESS+REALITY(+Vision)"),
    (Technique::XhttpCdn, "XHTTP (SplitHTTP)"),
    (Technique::Hysteria2, "Hysteria2"),
    (Technique::AmneziaWg, "AmneziaWG"),
    (Technique::WireGuardNu, "WireGuard nu"),
];

/// Chaque pays censeur et l'indice de sa colonne dans une ligne decoupee sur
/// "|". 2 = Chine, 3 = Russie, 4 = Iran, 5 = Turkmenistan.
const PAYS_COLONNE: [(Pays, usize); 4] = [
    (Pays::Chine, 2),
    (Pays::Russie, 3),
    (Pays::Iran, 4),
    (Pays::Turkmenistan, 5),
];

#[test]
fn la_legende_du_document_se_lit_comme_le_code() {
    assert_eq!(statut_du_document("Fonctionne"), Statut::Fonctionne);
    assert_eq!(statut_du_document("Degrade"), Statut::Degrade);
    assert_eq!(statut_du_document("Mort"), Statut::Mort);
    // Les deux ecritures composites du document valent Incertain dans le code.
    assert_eq!(statut_du_document("Incertain"), Statut::Incertain);
    assert_eq!(statut_du_document("Degrade/Mort"), Statut::Incertain);
    assert_eq!(statut_du_document("Mort/Degrade"), Statut::Incertain);
}

#[test]
fn chaque_technique_candidate_a_le_meme_statut_et_la_meme_date_que_le_document() {
    let doc = lire_doc();
    let mut ecarts: Vec<String> = Vec::new();
    let mut comparaisons = 0usize;

    for (technique, libelle) in CANDIDATES {
        let ligne = ligne_du_tableau(&doc, libelle).unwrap_or_else(|| {
            panic!(
                "aucune ligne du tableau du document 04 ne porte le libelle {libelle:?}: \
                 le tableau a bouge, la garde ne verifie plus rien"
            )
        });

        for (pays, colonne) in PAYS_COLONNE {
            comparaisons += 1;
            let statut_doc = statut_du_document(jeton_de_statut(ligne[colonne]));
            let (annee_doc, mois_doc) = date_du_document(ligne[6], pays);

            let o = statut(technique, pays)
                .unwrap_or_else(|| panic!("{} en {pays:?}: absente de survie.rs", technique.nom()));

            if o.statut != statut_doc {
                ecarts.push(format!(
                    "{} en {pays:?}: statut code {:?}, document {:?}",
                    technique.nom(),
                    o.statut,
                    statut_doc
                ));
            }
            let attendu = Date::new(annee_doc, mois_doc, 1);
            if o.mesure_le != attendu {
                ecarts.push(format!(
                    "{} en {pays:?}: date code {}-{:02}, document {}-{:02}",
                    technique.nom(),
                    o.mesure_le.annee,
                    o.mesure_le.mois,
                    annee_doc,
                    mois_doc
                ));
            }
        }
    }

    assert_eq!(
        comparaisons, 20,
        "cinq techniques par quatre pays font vingt comparaisons; {comparaisons} faites: \
         la garde ne balaie pas ce qu'elle croit"
    );
    assert!(
        ecarts.is_empty(),
        "survie.rs et le tableau du document 04 partie 1 divergent:\n  {}",
        ecarts.join("\n  ")
    );
}
