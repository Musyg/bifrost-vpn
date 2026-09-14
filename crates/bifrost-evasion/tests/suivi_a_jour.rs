//! `ETAT.md` doit rester vrai, et pas seulement le jour ou on l'ecrit.
//!
//! # Pourquoi cette recette existe
//!
//! Le depot a deja eu un document d'etat qui a peri en silence: un bloc "Ou en
//! est le depot" qui se datait encore de trois jours plus tot et annoncait des
//! comptes de recettes faux de plusieurs centaines, dans le meme document ou le
//! tableau des criteres portait un compte de vecteurs perime. `ETAT.md` est ne
//! de la: une page, tenue a jour dans le meme commit que le code.
//!
//! Une page tenue a la main perit de la meme facon. Cette recette garde les
//! proprietes qui se verifient sans jugement:
//!
//! 1. chaque document du plan figure dans le tableau des documents;
//! 2. chaque script du depot est nomme quelque part qu'un lecteur ouvre;
//! 3. les comptes de recettes sont coherents A L'INTERIEUR de la page: pour
//!    chaque hote, annoncees moins abstentions moins rouges egale reelles, et
//!    les deux lignes d'hote sont presentes;
//! 4. aucun chantier ouvert n'a de "prochaine action" vide;
//! 5. aucun document n'ecrit un nombre de vecteurs different de celui que
//!    `CheckVector::ALL` declare.
//!
//! La propriete 3 comparait autrefois `ETAT.md` a un recit de banc separe. Ce
//! recit ne fait plus partie de l'arbre public; la concordance externe est donc
//! remplacee par un controle interne a la page, qui ne depend d'aucun autre
//! fichier: une recette annoncee est soit abstenue, soit rouge, soit reelle.
//!
//! # Ce qu'elle ne fait pas
//!
//! Elle ne juge aucune affirmation. Elle ne sait pas si "livre et mesure" est
//! vrai, ni si la date est fraiche - un test n'a pas d'horloge fiable pour ca
//! et une date qui se perime toute seule ferait rougir le depot un matin sans
//! qu'aucun defaut n'existe. Elle garde la STRUCTURE, qui est ce qui se perd
//! par distraction.

use std::path::PathBuf;

fn racine() -> PathBuf {
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

const ETAT: &str = "ETAT.md";
const LISEZ_MOI: &str = "README.md";

/// Les documents du plan, tels qu'ils existent sur le disque.
///
/// Releves et non recopies: c'est tout l'interet. Le jour ou un document 08
/// apparait, cette recette le remarque avant qu'un lecteur ne se demande
/// pourquoi la page d'etat n'en parle pas.
fn documents_du_plan() -> Vec<String> {
    let mut trouves = Vec::new();
    let entrees = std::fs::read_dir(racine().join("docs")).expect("docs/ doit exister");
    for entree in entrees.flatten() {
        let nom = entree.file_name().to_string_lossy().into_owned();
        // `01-architecture-technique.md` et ses freres: deux chiffres, un
        // tiret. `SOTA-...` et `FILTRE-...` n'en sont pas.
        let numero: String = nom.chars().take(2).collect();
        if numero.len() == 2
            && numero.chars().all(|c| c.is_ascii_digit())
            && nom.chars().nth(2) == Some('-')
            && nom.ends_with(".md")
        {
            trouves.push(numero);
        }
    }
    trouves.sort();
    trouves
}

#[test]
fn chaque_document_du_plan_figure_dans_la_page_d_etat() {
    let etat = lire(ETAT);
    let documents = documents_du_plan();

    assert!(
        documents.len() >= 7,
        "seuls {} document(s) du plan trouves dans docs/: le releve est casse, \
         donc la recette ne verifie rien",
        documents.len()
    );

    for numero in &documents {
        // La ligne du tableau commence par le numero entre barres.
        let ligne = format!("| {numero} |");
        assert!(
            etat.contains(&ligne),
            "docs/{numero}-*.md existe mais aucune ligne `{ligne}` dans {ETAT}: \
             un document du plan dont la page d'etat ne dit rien"
        );
    }
}

#[test]
fn chaque_script_est_nomme_quelque_part_qu_on_ouvre() {
    let documents: Vec<String> = [ETAT, LISEZ_MOI].iter().map(|f| lire(f)).collect();

    let entrees = std::fs::read_dir(racine().join("scripts")).expect("scripts/ doit exister");
    let mut examines = 0usize;
    let mut muets = Vec::new();
    for entree in entrees.flatten() {
        if entree.path().is_dir() {
            continue;
        }
        let nom = entree.file_name().to_string_lossy().into_owned();
        examines += 1;
        if !documents.iter().any(|d| d.contains(&nom)) {
            muets.push(nom);
        }
    }

    assert!(
        examines > 5,
        "seuls {examines} script(s) examines: le parcours est casse"
    );
    assert!(
        muets.is_empty(),
        "{} script(s) que ni {ETAT} ni {LISEZ_MOI} ne nomment. Un banc que \
         personne ne sait lancer n'est pas un banc:\n  {}",
        muets.len(),
        muets.join("\n  ")
    );
}

/// Les nombres d'une ligne de tableau: `| dev-windows | 1015 | 22 | 0 | **993** |`.
fn nombres_de(ligne: &str) -> Vec<String> {
    ligne
        .split('|')
        .filter_map(|cellule| {
            let brut: String = cellule.chars().filter(|c| c.is_ascii_digit()).collect();
            if brut.is_empty() { None } else { Some(brut) }
        })
        .collect()
}

#[test]
fn les_comptes_de_recettes_sont_coherents_dans_la_page() {
    let etat = lire(ETAT);

    let mut hotes = 0usize;
    for ligne in etat.lines() {
        if !ligne.starts_with("| dev-windows |") && !ligne.starts_with("| essai-linux |") {
            continue;
        }
        hotes += 1;
        let nombres = nombres_de(ligne);
        assert_eq!(
            nombres.len(),
            4,
            "ligne de comptes mal formee dans {ETAT} (attendu quatre nombres: \
             annoncees, abstentions, rouges, reelles):\n  {ligne}"
        );
        let n: Vec<i64> = nombres
            .iter()
            .map(|s| {
                s.parse()
                    .unwrap_or_else(|e| panic!("nombre {s:?} illisible dans {ETAT}: {e}"))
            })
            .collect();
        let (annoncees, abstentions, rouges, reelles) = (n[0], n[1], n[2], n[3]);
        assert_eq!(
            annoncees - abstentions - rouges,
            reelles,
            "les comptes de cette ligne ne se tiennent pas:\n  {ligne}\n{annoncees} \
             annoncees - {abstentions} abstentions - {rouges} rouges = {}, mais la \
             page ecrit {reelles} reelles. Les deux documents d'etat avaient \
             diverge deux fois le 22/08/2026; depuis, la page porte son propre \
             controle: une recette annoncee est soit abstenue, soit rouge, soit \
             reelle.",
            annoncees - abstentions - rouges
        );
    }
    assert_eq!(
        hotes, 2,
        "{ETAT} devrait porter une ligne de comptes par hote, dev-windows et \
         essai-linux; {hotes} trouvee(s)"
    );
}

#[test]
fn aucun_chantier_ouvert_n_a_de_prochaine_action_vide() {
    let etat = lire(ETAT);
    let section = etat
        .split("## ")
        .find(|s| s.starts_with("Ce qui est ouvert"))
        .expect("la section des chantiers doit exister dans ETAT.md");

    let mut chantiers = 0usize;
    for ligne in section.lines() {
        // Les lignes de donnees d'un tableau a trois colonnes, separateur
        // exclu.
        if !ligne.starts_with('|') || ligne.contains("---") || ligne.starts_with("| Chantier |") {
            continue;
        }
        let cellules: Vec<&str> = ligne.trim_matches('|').split('|').collect();
        if cellules.len() != 3 {
            continue;
        }
        chantiers += 1;
        for (rang, cellule) in cellules.iter().enumerate() {
            assert!(
                !cellule.trim().is_empty(),
                "colonne {} vide dans la ligne de chantier:\n  {ligne}\nLa regle \
                 que ce fichier se donne a lui-meme: si la prochaine action ne \
                 peut pas etre nommee, la tranche n'est pas finie.",
                rang + 1
            );
        }
    }
    assert!(
        chantiers >= 3,
        "seuls {chantiers} chantier(s) lus dans {ETAT}: le decoupage du tableau \
         est casse, donc la recette ne verifie rien"
    );
}

/// Les numeraux francais qu'un document est susceptible d'ecrire en toutes
/// lettres devant "vecteurs". Toujours compares en minuscules: un debut de
/// cellule de tableau porte une majuscule.
const NUMERAUX: &[(&str, usize)] = &[
    ("quatre", 4),
    ("cinq", 5),
    ("six", 6),
    ("sept", 7),
    ("huit", 8),
    ("neuf", 9),
    ("dix", 10),
    ("onze", 11),
    ("douze", 12),
];

/// Ce que `CheckVector::ALL` declare, lu dans la source et non recopie.
fn vecteurs_declares() -> usize {
    let source = lire("crates/bifrost-core/src/checks.rs");
    let apres = source
        .split("[CheckVector; ")
        .nth(1)
        .expect("`CheckVector::ALL` doit etre declare `[CheckVector; N]`");
    let chiffres: String = apres.chars().take_while(|c| c.is_ascii_digit()).collect();
    chiffres
        .parse()
        .unwrap_or_else(|e| panic!("longueur de `CheckVector::ALL` illisible ({chiffres:?}): {e}"))
}

/// Vrai si ce qui suit "vecteurs" en fait un compte PARTIEL, du genre
/// "cinq vecteurs sur six".
///
/// Un compte partiel porte son denominateur; un total ne le porte pas. Sans
/// cette distinction la garde forcerait a effacer une mesure vraie ("cinq
/// vecteurs sur six passent en FAILED" rapporte un test de mutation, ou six
/// vecteurs s'executent).
fn est_un_compte_partiel(suite: &str) -> bool {
    let reste = match suite.trim_start().strip_prefix("sur ") {
        Some(reste) => reste,
        None => return false,
    };
    let mot: String = reste
        .chars()
        .take_while(|c| c.is_alphanumeric())
        .collect::<String>()
        .to_lowercase();
    NUMERAUX.iter().any(|(n, _)| *n == mot) || mot.parse::<usize>().is_ok()
}

#[test]
fn aucun_document_ne_recopie_un_mauvais_compte_de_vecteurs() {
    let attendu = vecteurs_declares();
    assert!(
        (2..=64).contains(&attendu),
        "{attendu} vecteurs declares: la lecture de `CheckVector::ALL` est cassee, \
         donc la recette ne verifie rien"
    );

    let mut lus = 0usize;
    let mut faux = Vec::new();
    for fichier in [ETAT, LISEZ_MOI] {
        let texte = lire(fichier);
        for (numero, ligne) in texte.lines().enumerate() {
            // Le mot qui precede "vecteurs", quand il y en a un.
            for (avant, motif) in ligne.match_indices("vecteurs") {
                if est_un_compte_partiel(&ligne[avant + motif.len()..]) {
                    continue;
                }
                // En minuscules. "Sept vecteurs" en tete de cellule de
                // tableau passait au travers tant que la comparaison etait
                // sensible a la casse, et le README en portait justement un:
                // la garde etait verte parce qu'elle ne le regardait pas.
                let mot = ligne[..avant]
                    .trim_end()
                    .rsplit(|c: char| !c.is_alphanumeric())
                    .next()
                    .unwrap_or("")
                    .to_lowercase();
                let valeur = NUMERAUX
                    .iter()
                    .find(|(n, _)| *n == mot.as_str())
                    .map(|(_, v)| *v)
                    .or_else(|| mot.parse::<usize>().ok());
                if let Some(valeur) = valeur {
                    lus += 1;
                    if valeur != attendu {
                        faux.push(format!("{fichier}:{}: {}", numero + 1, ligne.trim()));
                    }
                }
            }
        }
    }

    assert!(
        lus > 0,
        "aucun compte de vecteurs lu dans les deux documents: soit le reperage \
         est casse, soit plus personne n'ecrit ce nombre, auquel cas cette \
         recette peut disparaitre"
    );
    assert!(
        faux.is_empty(),
        "{} endroit(s) annoncent un nombre de vecteurs different des {attendu} \
         que `CheckVector::ALL` declare. Le recit dit de ce nombre precis qu'il \
         'a ete faux quatre fois'; il n'y a pas de raison qu'il cesse tout \
         seul:\n  {}",
        faux.len(),
        faux.join("\n  ")
    );
}
