//! La frontiere de licence, verifiee mecaniquement.
//!
//! Le client est sous MPL-2.0 et les coeurs anti-censure sont sous GPL. La
//! parade est une frontiere de processus, decrite dans `src/coeur.rs` et dans
//! le document 04 partie 6. Un paragraphe ne se verifie pas: ce test lit le
//! graphe de dependances reel et refuse toute dependance Rust sous copyleft
//! fort. Le jour ou quelqu'un ajoutera une liaison, la recette tombera avant
//! la revue.
//!
//! Il refuse aussi les paquets sans licence declaree. Aucun ne pose probleme
//! aujourd'hui, mais un paquet sans licence n'est pas un paquet permissif: il
//! est un paquet dont on ne sait rien, et c'est pire.

use std::process::Command;

/// La seule exception, tranchee le 16 aout 2026 et documentee au chapitre 8.
///
/// `wireguard-control` est sous LGPL-2.1-or-later, uniquement compile sous
/// Linux. L'article 6 autorise la liaison statique a condition de fournir de
/// quoi relier; le client restant ouvert, la condition est remplie. Toute
/// autre exception doit passer par la meme discussion, d'ou la liste nommee
/// plutot qu'un motif generique sur "LGPL".
const EXCEPTIONS_LGPL: &[&str] = &["wireguard-control"];

/// Ce que vaut UN terme de licence, sans operateur.
#[derive(Debug, PartialEq, Eq)]
enum Terme {
    Permissive,
    Lgpl,
    CopyleftFort,
}

fn juger_terme(terme: &str) -> Terme {
    let l = terme.trim().to_ascii_uppercase();
    if l.contains("LGPL") {
        return Terme::Lgpl;
    }
    // Le "-" est volontaire: il attrape GPL-2.0, GPL-3.0-only,
    // AGPL-3.0-or-later, sans attraper LGPL, dont le nom contient GPL mais
    // qui est traitee juste au-dessus.
    let contient_gpl = l
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '-')
        .any(|mot| mot.starts_with("GPL-") || mot == "GPL" || mot.starts_with("AGPL"));
    if contient_gpl {
        Terme::CopyleftFort
    } else {
        Terme::Permissive
    }
}

/// Ce que vaut une expression SPDX entiere.
#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    /// Au moins une branche convient sans reserve.
    Acceptable,
    /// Aucune branche permissive, mais une branche LGPL: a trancher a la main.
    LgplSeulement,
    /// Aucune branche acceptable.
    CopyleftFort,
    /// L'expression n'est pas analysable ici. Voir plus bas.
    Illisible,
}

/// Juge une expression SPDX.
///
/// `OR` offre un CHOIX: il suffit qu'une branche convienne, et c'est celle-la
/// qu'on retient. `AND` impose tout: une branche ne vaut que si chacun de ses
/// termes convient.
///
/// La distinction n'est pas theorique. `MIT OR Apache-2.0 OR LGPL-2.1-or-later`
/// est une licence qu'on prend sous MIT; la lire comme "LGPL" ferait refuser
/// une dependance parfaitement permissive, et la version precedente de ce
/// fichier le faisait, par simple recherche de sous-chaine sur l'expression
/// entiere.
///
/// Les PARENTHESES ne sont analysees que dans le cas ou elles ne peuvent rien
/// changer: quand TOUS les termes sont permissifs, aucune priorite d'operateur
/// ne rend l'ensemble contraignant, et `(Apache-2.0 OR MIT) AND BSD-3-Clause`
/// se juge sans hesitation. Sinon l'expression rend [`Verdict::Illisible`] et
/// fait echouer la recette: deviner la priorite donnerait un verdict faux dans
/// un sens ou dans l'autre, et le sens ou l'on se trompe en sa propre faveur
/// est celui qui coute cher. Une telle expression se tranche a la main, comme
/// les LGPL.
fn juger_expression(licence: &str) -> Verdict {
    // Raccourci sur: si TOUS les termes sont permissifs, aucune priorite
    // d'operateur ne peut rendre l'ensemble contraignant. Cela couvre les
    // expressions a parentheses du genre `(Apache-2.0 OR MIT) AND BSD-3-Clause`,
    // qui sont courantes et qu'il serait absurde de faire trancher a la main.
    let termes: Vec<Terme> = licence
        .replace(['(', ')'], " ")
        .split(" OR ")
        .flat_map(|b| b.split(" AND "))
        .map(juger_terme)
        .collect();
    if termes.iter().all(|t| *t == Terme::Permissive) {
        return Verdict::Acceptable;
    }
    // Au-dela, la priorite des operateurs decide, et on ne la devine pas.
    if licence.contains('(') || licence.contains(')') {
        return Verdict::Illisible;
    }
    let mut lgpl_vue = false;
    for branche in licence.split(" OR ") {
        // Dans une branche, `AND` impose tout: le pire terme decide.
        let pire =
            branche
                .split(" AND ")
                .map(juger_terme)
                .fold(Terme::Permissive, |acc, t| match (acc, t) {
                    (Terme::CopyleftFort, _) | (_, Terme::CopyleftFort) => Terme::CopyleftFort,
                    (Terme::Lgpl, _) | (_, Terme::Lgpl) => Terme::Lgpl,
                    _ => Terme::Permissive,
                });
        match pire {
            Terme::Permissive => return Verdict::Acceptable,
            Terme::Lgpl => lgpl_vue = true,
            Terme::CopyleftFort => {}
        }
    }
    if lgpl_vue {
        Verdict::LgplSeulement
    } else {
        Verdict::CopyleftFort
    }
}

#[test]
fn aucune_dependance_rust_sous_copyleft_fort() {
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

    let meta: serde_json::Value =
        serde_json::from_slice(&sortie.stdout).expect("metadata illisible");
    let paquets = meta["packages"].as_array().expect("champ packages absent");

    // Controle positif: sans lui, une requete qui rendrait zero paquet
    // passerait la recette sans rien avoir verifie.
    assert!(
        paquets.len() > 20,
        "graphe de dependances suspect: {} paquets",
        paquets.len()
    );

    let mut interdits = Vec::new();
    let mut sans_licence = Vec::new();
    let mut lgpl_hors_liste = Vec::new();
    let mut illisibles = Vec::new();

    for p in paquets {
        let nom = p["name"].as_str().unwrap_or("(anonyme)");
        match p["license"].as_str() {
            None => sans_licence.push(nom.to_string()),
            Some(l) => match juger_expression(l) {
                Verdict::Acceptable => {}
                Verdict::CopyleftFort => interdits.push(format!("{nom} ({l})")),
                Verdict::Illisible => illisibles.push(format!("{nom} ({l})")),
                Verdict::LgplSeulement if !EXCEPTIONS_LGPL.contains(&nom) => {
                    lgpl_hors_liste.push(format!("{nom} ({l})"))
                }
                Verdict::LgplSeulement => {}
            },
        }
    }

    assert!(
        interdits.is_empty(),
        "dependance sous copyleft fort, la frontiere de processus est percee: {interdits:?}"
    );
    assert!(
        sans_licence.is_empty(),
        "paquet sans licence declaree, donc de statut inconnu: {sans_licence:?}"
    );
    assert!(
        lgpl_hors_liste.is_empty(),
        "LGPL non tranchee, voir le chapitre 8 avant d'ajouter a EXCEPTIONS_LGPL: {lgpl_hors_liste:?}"
    );
    assert!(
        illisibles.is_empty(),
        "expression de licence a parentheses, non analysee ici: a trancher a la main plutot qu'a deviner: {illisibles:?}"
    );
}

#[test]
fn l_exception_lgpl_declaree_existe_encore() {
    // Une exception qui ne correspond plus a rien est une permission qui
    // trainerait pour le prochain paquet du meme nom.
    let sortie = Command::new(option_env!("CARGO").unwrap_or("cargo"))
        .args(["metadata", "--format-version", "1"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("cargo metadata doit pouvoir tourner");
    let meta: serde_json::Value = serde_json::from_slice(&sortie.stdout).unwrap();
    let noms: Vec<&str> = meta["packages"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|p| p["name"].as_str())
        .collect();
    for e in EXCEPTIONS_LGPL {
        assert!(
            noms.contains(e),
            "exception LGPL '{e}' inutile: le paquet n'est plus dans le graphe"
        );
    }
}

#[test]
fn le_detecteur_distingue_gpl_de_lgpl() {
    // Sans cette distinction, l'exception deja tranchee ferait tomber la
    // recette, et on serait tente de relacher le motif entier.
    assert_eq!(juger_terme("GPL-3.0"), Terme::CopyleftFort);
    assert_eq!(juger_terme("GPL-2.0-only"), Terme::CopyleftFort);
    assert_eq!(juger_terme("AGPL-3.0-or-later"), Terme::CopyleftFort);

    assert_eq!(juger_terme("LGPL-2.1-or-later"), Terme::Lgpl);
    for permissive in ["MIT", "MPL-2.0", "BSD-3-Clause", "Apache-2.0", "Unlicense"] {
        assert_eq!(juger_terme(permissive), Terme::Permissive, "{permissive}");
    }
}

/// Le `OR` de SPDX est un CHOIX offert au licencie, pas une contrainte
/// cumulee. Une expression qui propose MIT se prend sous MIT, quoi qu'elle
/// propose d'autre.
///
/// Ce test corrige une regle qui etait FAUSSE et qui a ete vue a l'oeuvre le
/// 19 aout 2026: la version precedente cherchait "GPL" dans l'expression
/// entiere et refusait donc `MIT OR Apache-2.0 OR LGPL-2.1-or-later`, qui est
/// la licence de `r-efi`, dependance transitive parfaitement permissive.
///
/// C'est un ASSOUPLISSEMENT d'un garde-fou, donc il se justifie: le
/// double-licenciement est le mode normal de l'ecosysteme Rust, ou
/// `MIT OR Apache-2.0` est la norme, et refuser une branche permissive parce
/// qu'une autre branche ne l'est pas reviendrait a s'interdire une licence
/// qu'on nous accorde. La contrainte reelle est inchangee: il faut qu'AU MOINS
/// une branche convienne.
#[test]
fn le_ou_de_spdx_est_un_choix_et_le_et_une_contrainte() {
    // Une branche permissive suffit, ou qu'elle soit dans l'expression.
    assert_eq!(juger_expression("MIT OR GPL-3.0"), Verdict::Acceptable);
    assert_eq!(juger_expression("GPL-3.0 OR MIT"), Verdict::Acceptable);
    assert_eq!(
        juger_expression("MIT OR Apache-2.0 OR LGPL-2.1-or-later"),
        Verdict::Acceptable
    );

    // Sans branche permissive, le verdict tient.
    assert_eq!(juger_expression("GPL-3.0"), Verdict::CopyleftFort);
    assert_eq!(
        juger_expression("GPL-2.0-only OR AGPL-3.0-or-later"),
        Verdict::CopyleftFort
    );
    assert_eq!(
        juger_expression("LGPL-2.1-or-later"),
        Verdict::LgplSeulement
    );
    assert_eq!(
        juger_expression("GPL-3.0 OR LGPL-2.1-or-later"),
        Verdict::LgplSeulement,
        "la branche LGPL est la moins mauvaise: a trancher a la main, pas a refuser d'office"
    );

    // `AND` impose tout: le pire terme de la branche decide.
    assert_eq!(juger_expression("MIT AND GPL-3.0"), Verdict::CopyleftFort);
    assert_eq!(
        juger_expression("MIT AND GPL-3.0 OR BSD-3-Clause"),
        Verdict::Acceptable,
        "la seconde branche est permissive a elle seule"
    );

    // Des parentheses dont tous les termes sont permissifs ne posent aucune
    // question: aucune priorite d'operateur ne peut rendre l'ensemble
    // contraignant. Ces deux expressions sont celles de dependances reelles.
    assert_eq!(
        juger_expression("(Apache-2.0 OR MIT) AND BSD-3-Clause"),
        Verdict::Acceptable
    );
    assert_eq!(
        juger_expression("(MIT OR Apache-2.0) AND Unicode-3.0"),
        Verdict::Acceptable
    );

    // Melangees a du copyleft, elles ne se devinent pas.
    assert_eq!(
        juger_expression("(MIT OR Apache-2.0) AND GPL-3.0"),
        Verdict::Illisible
    );
}
