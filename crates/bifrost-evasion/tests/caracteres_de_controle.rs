//! Aucun caractere de controle egare dans les fichiers texte du depot.
//!
//! # Pourquoi cette recette existe
//!
//! Deux fois le 22 aout 2026, un antislash a ete mange en cours de route entre
//! l'editeur et le fichier, et la sequence qui le suivait a ete interpretee au
//! lieu d'etre ecrite. Le resultat n'est pas une erreur: c'est un octet de
//! controle depose au milieu d'un fichier texte, qui ne se voit pas.
//!
//! 1. Un document d'etat documentait le journal du banc Windows sous un chemin
//!    dont un segment commencait par `b`. Les deux antislashs
//!    avaient disparu et `\b` etait devenu un vrai retour arriere (0x08). Le
//!    chemin etait inutilisable, et pire: affiche dans un terminal, le retour
//!    arriere deplace le curseur, donc la ligne se lit presque normalement.
//! 2. `scripts/recettes-strict.sh` s'est retrouve avec un `\1` transforme en
//!    0x01 dans un programme `sed`. Le script a continue de tourner, de rendre
//!    0, et d'annoncer **zero abstention** sur une suite qui en comptait
//!    vingt-deux. Un caractere invisible qui fait mentir une mesure.
//!
//! Le deuxieme cas est le motif de cette recette. Un octet de controle ne
//! provoque pas d'erreur; il change le sens de ce qui l'entoure et laisse tout
//! le reste vert.
//!
//! # Ce qu'elle ne fait pas
//!
//! Elle ne juge ni l'encodage, ni les fins de ligne. `\t`, `\n` et `\r` sont
//! des caracteres de controle legitimes et sont exclus: l'arbre de travail est
//! en CRLF sous Windows, et `.gitattributes` s'occupe de la normalisation.
//!
//! Elle ne demande pas git. Le parcours se fait sur le disque, et c'est
//! delibere: sur essai-linux le depot est copie par `tar` et n'a pas de `.git`,
//! donc une recette qui appellerait `git ls-files` s'y abstiendrait a chaque
//! passage. Une recette qui ne s'execute que sur une machine sur deux ne garde
//! rien. En contrepartie, le perimetre est une liste d'extensions declaree ici,
//! qu'il faut etendre le jour ou le depot accueille un autre format texte.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

fn racine() -> PathBuf {
    // Meme idiome que `avis_ignores.rs` et `frontiere_licence.rs`:
    // `CARGO_MANIFEST_DIR` pointe sur crates/bifrost-evasion, la racine de
    // l'espace de travail est deux crans au-dessus.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("la racine de l'espace de travail doit exister")
        .to_path_buf()
}

/// Les octets qui n'ont rien a faire dans un fichier texte de ce depot.
///
/// Sont exclus `\t` (0x09), `\n` (0x0A) et `\r` (0x0D), seuls caracteres de
/// controle qu'un fichier texte porte legitimement. 0x7F (DEL) est inclus: il
/// ne s'ecrit pas au clavier et n'a aucune raison d'apparaitre.
fn est_de_controle(octet: u8) -> bool {
    matches!(octet, 0x00..=0x08 | 0x0B | 0x0C | 0x0E..=0x1F | 0x7F)
}

/// Les repertoires que le parcours ne descend pas, a n'importe quelle
/// profondeur.
///
/// `.git` porte des objets compresses et `target` des binaires: les deux sont
/// pleins d'octets de controle, et aucun des deux n'est du texte qu'on ecrit.
/// Tout le reste est descendu, `.github`, `.cargo` et `packaging/systemd/system-sleep`
/// compris, ou vivent des fichiers ecrits a la main.
const DOSSIERS_IGNORES: [&str; 2] = [".git", "target"];

/// Les extensions considerees comme du texte ecrit a la main.
///
/// Relevee sur les fichiers suivis le 22 aout 2026: rs, sh, md, toml, ps1, yml,
/// py, lock, conf, service, plus `.gitignore` et `.gitattributes` qui n'ont pas
/// d'extension. `json` et `txt` sont ajoutes par anticipation, `yaml` parce que
/// les deux orthographes cohabitent partout.
const EXTENSIONS: [&str; 13] = [
    "rs", "sh", "md", "toml", "ps1", "yml", "yaml", "py", "lock", "conf", "service", "json", "txt",
];

/// Un fichier sans extension est du texte: `.gitignore`, `.gitattributes`,
/// `packaging/systemd/system-sleep/bifrost-reprise`. Un binaire depose a la
/// main sans extension serait
/// signale a tort, et ce serait une plainte legitime: il n'a rien a faire dans
/// l'arbre.
fn est_du_texte(chemin: &Path) -> bool {
    match chemin.extension().and_then(OsStr::to_str) {
        Some(ext) => EXTENSIONS.contains(&ext),
        None => true,
    }
}

fn parcourir(dossier: &Path, examines: &mut usize, defauts: &mut Vec<String>) {
    let Ok(entrees) = std::fs::read_dir(dossier) else {
        return;
    };
    for entree in entrees.flatten() {
        let chemin = entree.path();
        let nom = entree.file_name();
        let nom = nom.to_string_lossy().into_owned();
        if chemin.is_dir() {
            if !DOSSIERS_IGNORES.contains(&nom.as_str()) {
                parcourir(&chemin, examines, defauts);
            }
        } else if est_du_texte(&chemin)
            && let Ok(octets) = std::fs::read(&chemin)
        {
            *examines += 1;
            if let Some((ligne, octet)) = premier_defaut(&octets) {
                let relatif = chemin
                    .strip_prefix(racine())
                    .unwrap_or(&chemin)
                    .display()
                    .to_string();
                defauts.push(format!("{relatif}:{ligne}: octet 0x{octet:02x}"));
            }
        }
    }
}

/// Le premier octet de controle d'un fichier, avec son numero de ligne.
///
/// Un seul signalement par fichier: un fichier abime l'est generalement
/// plusieurs fois, et la liste doit rester lisible.
fn premier_defaut(octets: &[u8]) -> Option<(usize, u8)> {
    let mut ligne = 1usize;
    for octet in octets {
        if *octet == b'\n' {
            ligne += 1;
        } else if est_de_controle(*octet) {
            return Some((ligne, *octet));
        }
    }
    None
}

#[test]
fn aucun_fichier_texte_du_depot_ne_porte_de_caractere_de_controle() {
    let mut examines = 0usize;
    let mut defauts = Vec::new();
    parcourir(&racine(), &mut examines, &mut defauts);

    // Le controle positif, sans lequel un parcours casse - mauvaise racine,
    // lecture qui echoue en silence - rendrait une liste vide, donc un succes,
    // sans avoir rien lu. Le depot porte environ 187 fichiers suivis.
    assert!(
        examines > 100,
        "le parcours n'a examine que {examines} fichier(s): il ne verifie rien"
    );

    assert!(
        defauts.is_empty(),
        "{} fichier(s) portent un octet de controle. Il ne provoque aucune \
         erreur, il change le sens de ce qui l'entoure:\n  {}",
        defauts.len(),
        defauts.join("\n  ")
    );
}

/// Les fichiers Rust ou une tabulation est legitime, et pourquoi.
///
/// `rustfmt` n'emet jamais de tabulation. Dans un `.rs` de ce depot, une
/// tabulation ne peut donc etre que deux choses: une sortie d'outil recopiee
/// telle quelle dans une fixture, ou - et c'est le cas qui a coute - un
/// antislash mange dont le `\t` qui suivait a ete interprete.
///
/// Mesure du 23 aout 2026: `crates/bifrost-daemon/src/main.rs` portait
/// `r"C:\ProgramData\Bifrost<TAB>elemetrie-journal.json"`. Le chemin par defaut
/// du journal de retour en arriere de la couche 1 designait donc un fichier
/// dont le nom contient une tabulation, et `create_dir_all` reussissait sur un
/// parent qui existe. Rien n'a jamais rougi: `telemetrie-windows.ps1` passe
/// toujours `--telemetrie-journal` explicitement, donc aucun aller-retour ne
/// pouvait l'attraper. La recette voisine ne le voyait pas non plus, la
/// tabulation etant exclue de `est_de_controle` a juste titre - elle est
/// legitime dans un `.md` ou un `.sh`.
const TABULATIONS_ADMISES: [&str; 1] = ["crates/bifrost-daemon/src/exit_ip.rs"];

/// Les fichiers `.rs` du depot, chemin relatif a la racine.
fn sources_rust(dossier: &Path, trouves: &mut Vec<(String, usize)>) {
    let Ok(entrees) = std::fs::read_dir(dossier) else {
        return;
    };
    for entree in entrees.flatten() {
        let chemin = entree.path();
        let nom = entree.file_name();
        let nom = nom.to_string_lossy().into_owned();
        if chemin.is_dir() {
            if !DOSSIERS_IGNORES.contains(&nom.as_str()) {
                sources_rust(&chemin, trouves);
            }
        } else if chemin.extension().and_then(OsStr::to_str) == Some("rs")
            && let Ok(octets) = std::fs::read(&chemin)
        {
            let relatif = chemin
                .strip_prefix(racine())
                .unwrap_or(&chemin)
                .display()
                .to_string()
                .replace('\\', "/");
            let tabulations = octets.iter().filter(|o| **o == b'\t').count();
            trouves.push((relatif, tabulations));
        }
    }
}

#[test]
fn aucune_tabulation_dans_le_rust_hors_fixture_declaree() {
    let mut sources = Vec::new();
    sources_rust(&racine(), &mut sources);

    // Controle positif: un parcours casse rendrait une liste vide, donc un
    // succes, sans avoir rien lu.
    assert!(
        sources.len() > 50,
        "le parcours n'a trouve que {} source(s) Rust: il ne verifie rien",
        sources.len()
    );

    let egares: Vec<&(String, usize)> = sources
        .iter()
        .filter(|(chemin, tabulations)| {
            *tabulations > 0 && !TABULATIONS_ADMISES.contains(&chemin.as_str())
        })
        .collect();
    assert!(
        egares.is_empty(),
        "tabulation(s) dans du Rust, la ou rustfmt n'en met jamais. C'est \
         presque toujours un antislash mange dont la sequence suivante a ete \
         interpretee:\n  {}",
        egares
            .iter()
            .map(|(chemin, n)| format!("{chemin}: {n}"))
            .collect::<Vec<_>>()
            .join("\n  ")
    );

    // Une derogation qui ne sert plus est une derogation qui elargit la regle
    // en silence. Chaque entree doit encore designer un fichier qui existe ET
    // qui porte vraiment une tabulation.
    for admis in TABULATIONS_ADMISES {
        let trouve = sources.iter().find(|(chemin, _)| chemin == admis);
        match trouve {
            None => panic!("{admis} est admis mais n'existe plus: derogation a retirer"),
            Some((_, 0)) => {
                panic!("{admis} est admis mais ne porte plus de tabulation: derogation a retirer")
            }
            Some(_) => {}
        }
    }
}

#[test]
fn le_detecteur_reconnait_ce_qu_il_doit_reconnaitre() {
    // Les deux octets reellement rencontres le 22 aout 2026.
    assert!(est_de_controle(0x08), "retour arriere, ne d'un antislash-b");
    assert!(est_de_controle(0x01), "SOH, ne d'un antislash-1");
    assert!(est_de_controle(0x00));
    assert!(est_de_controle(0x1b), "echappement ANSI");
    assert!(est_de_controle(0x7f));

    // Ce qu'un fichier texte porte legitimement.
    assert!(!est_de_controle(b'\t'));
    assert!(!est_de_controle(b'\n'));
    assert!(!est_de_controle(b'\r'));
    assert!(!est_de_controle(b'A'));
    assert!(!est_de_controle(b' '));

    // Un caractere accentue en UTF-8 tient sur deux octets hauts, aucun des
    // deux ne doit etre pris pour un caractere de controle. Le depot est ecrit
    // en francais, la question n'est pas theorique.
    for octet in "e\u{0301}crit".as_bytes() {
        assert!(!est_de_controle(*octet), "octet 0x{octet:02x} de l'UTF-8");
    }
}

#[test]
fn le_reperage_donne_la_bonne_ligne() {
    // La forme exacte du defaut trouve dans la documentation: le mot est coupe
    // par un retour arriere au milieu de la troisieme ligne.
    let texte = b"premiere\nseconde\nC:\x08ifrost-test\n";
    assert_eq!(premier_defaut(texte), Some((3, 0x08)));

    // Et un texte sain, avec tabulation et CRLF, ne declenche rien.
    let sain = b"une\tligne\r\nune autre\r\n";
    assert_eq!(premier_defaut(sain), None);
}

#[test]
fn le_perimetre_couvre_ce_que_le_depot_contient() {
    // Sans ce temoin, restreindre la liste d'extensions ferait passer la
    // recette principale en n'examinant plus rien d'interessant.
    for exemple in [
        "scripts/recettes-strict.sh",
        "docs/01-architecture-technique.md",
        "Cargo.toml",
        "Cargo.lock",
        "deny.toml",
        ".gitignore",
        "packaging/systemd/system-sleep/bifrost-reprise",
        ".github/workflows/ci.yml",
        "packaging/install-windows.ps1",
        "crates/bifrost-evasion/tests/caracteres_de_controle.rs",
    ] {
        assert!(
            est_du_texte(Path::new(exemple)),
            "{exemple} sort du perimetre alors qu'il est suivi par le depot"
        );
    }

    // Et ce qui doit en sortir: le pilote depose a cote des binaires.
    assert!(!est_du_texte(Path::new("target/debug/wireguard.dll")));
}
