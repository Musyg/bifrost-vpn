//! Les sources du depot restent en ASCII, sauf une liste nommee d'exceptions.
//!
//! # Pourquoi cette recette existe
//!
//! Le depot se donne une regle: ASCII strict dans le code, les commentaires,
//! la documentation et les messages de commit; zero tiret cadratin, zero
//! emoji. Les identifiants sont en francais sans accents. La regle est
//! anterieure a une partie du code, et `HEAD` portait encore, le jour ou cette
//! recette est nee, huit octets non-ASCII dans cinq fichiers: des accents
//! oublies dans des commentaires (`ports.rs`, `anti_orphelin.rs`,
//! `resolveur.rs`, un commentaire de `coeurs/superviseur.rs`) et un accent
//! oublie dans un commentaire de script (`service-systemd-linux.sh`).
//!
//! Un commentaire accentue ne provoque aucune erreur; il erode en silence une
//! regle que plus rien ne fait respecter. Cette recette la fait respecter.
//!
//! # Ce qu'elle admet
//!
//! - Les guillemets francais `<<` et `>>` (U+00AB et U+00BB), partout: ce sont
//!   les seuls signes non-ASCII que la regle du depot autorise.
//! - Une liste NOMMEE d'exceptions, chacune designant un fichier et le litteral
//!   exact admis, avec la raison. Aujourd'hui deux, et deux seulement: les deux
//!   chaines de test volontairement multi-octets qui verifient qu'une coupe
//!   tombant sur une frontiere UTF-8 ne panique pas. Les reecrire en ASCII
//!   effacerait ce que ces tests mesurent.
//!
//! # Son perimetre
//!
//! `crates/**/*.rs`, tous les fichiers de `scripts/`, tous ceux de
//! `packaging/`. Les documents `.md` ne sont PAS gardes ici: c'est une
//! decision de la tranche qui a ecrit cette recette, `docs/` portant du
//! non-ASCII anterieur qu'une autre passe traitera.
//!
//! Le parcours se fait sur le disque, sans git: sur essai-linux le depot est
//! copie par `tar` et n'a pas de `.git`. Une recette qui appellerait
//! `git ls-files` s'y abstiendrait a chaque passage, et une recette qui ne
//! s'execute que sur une machine sur deux ne garde rien.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

fn racine() -> PathBuf {
    // Meme idiome que `caracteres_de_controle.rs` et ses voisines:
    // `CARGO_MANIFEST_DIR` pointe sur crates/bifrost-evasion, la racine de
    // l'espace de travail est deux crans au-dessus.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("la racine de l'espace de travail doit exister")
        .to_path_buf()
}

/// Les seuls signes non-ASCII admis partout: les guillemets francais.
const GUILLEMETS_ADMIS: [u32; 2] = [0x00AB, 0x00BB];

/// Vrai si le point de code n'a rien a faire dans une source du depot.
///
/// Tout ce qui depasse l'ASCII de 7 bits, sauf les deux guillemets francais.
fn est_interdit(point_de_code: u32) -> bool {
    point_de_code > 0x7F && !GUILLEMETS_ADMIS.contains(&point_de_code)
}

/// Une derogation nommee: un fichier, le litteral exact admis, et pourquoi.
///
/// Le litteral est ecrit en echappements `\u{..}` pour que CETTE source reste
/// elle-meme en ASCII: elle est balayee comme les autres, elle ne peut pas
/// s'auto-exempter en portant les octets qu'elle tolere ailleurs.
struct Exception {
    fichier: &'static str,
    litteral: &'static str,
    raison: &'static str,
}

/// La liste NOMMEE des exceptions. Deux, et deux seulement.
///
/// Les deux sont des chaines de test volontairement multi-octets. Elles ont la
/// meme raison d'etre: un accent tient sur deux octets en UTF-8, donc une coupe
/// a un rang donne peut tomber entre les deux, et c'est precisement ce cas que
/// le test doit couvrir. Un accent efface au profit d'un caractere d'un seul
/// octet rendrait chaque rang une frontiere valide et le test ne mesurerait
/// plus rien: un vert qui ne garde rien.
const EXCEPTIONS: &[Exception] = &[
    Exception {
        // La source de superviseur.rs porte `j.pousser("\u{e9}\u{e0}\u{fc}");`;
        // le litteral admis est la chaine entre guillemets doubles.
        fichier: "crates/bifrost-daemon/src/coeurs/superviseur.rs",
        litteral: "\"\u{e9}\u{e0}\u{fc}\"",
        raison: "Chaine de test volontairement multi-octets. Le test \
                 couper_au_milieu_d_un_caractere_ne_panique_pas pousse 2000 fois \
                 trois caracteres accentues dans un journal borne, pour que la \
                 coupe tombe fatalement entre les deux octets d'un accent. La \
                 reecrire en ASCII effacerait ce que le test mesure.",
    },
    Exception {
        // La source d'e2e.rs porte `let accents = "\u{e9}".repeat(200);`; le
        // litteral admis est cette expression, guillemets doubles compris.
        fichier: "crates/bifrost-daemon/src/coeurs/e2e.rs",
        litteral: "\"\u{e9}\".repeat(200)",
        raison: "Chaine de test volontairement multi-octets. Le test \
                 abreger_ne_coupe_pas_un_caractere_en_deux force `abreger` a \
                 chercher une frontiere de caractere par is_char_boundary sur \
                 400 octets. En ASCII chaque octet serait une frontiere et le \
                 test ne mesurerait plus rien.",
    },
];

/// Vrai si le caractere non-ASCII a l'octet `idx` de `ligne` tombe dans une
/// occurrence d'un litteral admis pour ce fichier.
///
/// L'exception est scopee au litteral: un accent ailleurs sur la ligne, hors
/// du litteral admis, reste un ecart. C'est ce qui rend la falsification (b)
/// possible: retirer l'exception decouvre les octets qu'elle protegeait.
fn admis_par_exception(fichier_rel: &str, ligne: &str, idx: usize) -> bool {
    EXCEPTIONS
        .iter()
        .filter(|e| e.fichier == fichier_rel)
        .any(|e| {
            ligne
                .match_indices(e.litteral)
                .any(|(debut, m)| (debut..debut + m.len()).contains(&idx))
        })
}

/// Un lot de fichiers ramasses: chemin relatif et octets bruts.
type Lot = Vec<(String, Vec<u8>)>;

/// Les repertoires que le parcours ne descend jamais.
const DOSSIERS_IGNORES: [&str; 2] = [".git", "target"];

/// Parcourt `dossier` et ramasse les fichiers, en octets bruts.
///
/// `extension` filtre par extension quand elle est fournie (`Some("rs")` pour
/// les sources Rust), ou prend tout quand elle vaut `None` (scripts et
/// packaging, ou cohabitent `.sh`, `.ps1`, `.py`, `.service`, `.conf` et des
/// fichiers sans extension).
fn ramasser(dossier: &Path, extension: Option<&str>, trouves: &mut Lot) {
    let Ok(entrees) = std::fs::read_dir(dossier) else {
        return;
    };
    for entree in entrees.flatten() {
        let chemin = entree.path();
        let nom = entree.file_name().to_string_lossy().into_owned();
        if chemin.is_dir() {
            if !DOSSIERS_IGNORES.contains(&nom.as_str()) {
                ramasser(&chemin, extension, trouves);
            }
        } else {
            let garder = match extension {
                Some(ext) => chemin.extension().and_then(OsStr::to_str) == Some(ext),
                None => true,
            };
            if garder && let Ok(octets) = std::fs::read(&chemin) {
                let relatif = chemin
                    .strip_prefix(racine())
                    .unwrap_or(&chemin)
                    .display()
                    .to_string()
                    .replace('\\', "/");
                trouves.push((relatif, octets));
            }
        }
    }
}

/// Les trois racines du perimetre, chacune dans son propre lot pour que le
/// controle positif verifie qu'AUCUNE des trois n'est restee vide.
fn collecter() -> (Lot, Lot, Lot) {
    let mut rust = Vec::new();
    ramasser(&racine().join("crates"), Some("rs"), &mut rust);
    let mut scripts = Vec::new();
    ramasser(&racine().join("scripts"), None, &mut scripts);
    let mut packaging = Vec::new();
    ramasser(&racine().join("packaging"), None, &mut packaging);
    (rust, scripts, packaging)
}

/// Un ecart, forme lisible: `chemin:ligne:colonne: U+XXXX`.
fn ecarts_de(rel: &str, bytes: &[u8]) -> Vec<String> {
    let texte = match std::str::from_utf8(bytes) {
        Ok(t) => t,
        Err(e) => return vec![format!("{rel}: fichier non-UTF-8 ({e})")],
    };
    let mut ecarts = Vec::new();
    for (numero, ligne) in texte.lines().enumerate() {
        for (idx, ch) in ligne.char_indices() {
            let point_de_code = ch as u32;
            if !est_interdit(point_de_code) {
                continue;
            }
            if admis_par_exception(rel, ligne, idx) {
                continue;
            }
            let colonne = ligne[..idx].chars().count() + 1;
            ecarts.push(format!(
                "{rel}:{}:{colonne}: U+{point_de_code:04X}",
                numero + 1
            ));
        }
    }
    ecarts
}

#[test]
fn aucun_octet_non_ascii_hors_admis_et_exceptions() {
    let (rust, scripts, packaging) = collecter();

    // Controle positif par racine: un parcours casse - mauvaise racine, lecture
    // qui echoue en silence - rendrait un lot vide, donc un succes, sans avoir
    // rien lu. Les trois racines doivent chacune avoir ete descendues.
    assert!(
        rust.len() > 100,
        "seules {} source(s) Rust trouvees: le parcours de crates/ est casse",
        rust.len()
    );
    assert!(
        scripts.len() > 5,
        "seuls {} fichier(s) trouves dans scripts/: le parcours est casse",
        scripts.len()
    );
    assert!(
        packaging.len() >= 3,
        "seuls {} fichier(s) trouves dans packaging/: le parcours est casse",
        packaging.len()
    );

    let mut ecarts = Vec::new();
    for (rel, bytes) in rust.iter().chain(&scripts).chain(&packaging) {
        ecarts.extend(ecarts_de(rel, bytes));
    }

    assert!(
        ecarts.is_empty(),
        "{} octet(s) non-ASCII hors des admis (<< >>) et de la liste d'exceptions \
         nommees. Un accent egare erode en silence la regle ASCII du depot:\n  {}",
        ecarts.len(),
        ecarts.join("\n  ")
    );
}

#[test]
fn chaque_exception_designe_encore_du_non_ascii_reel() {
    // Une derogation qui ne sert plus elargit la regle en silence. Chaque
    // exception doit encore designer un fichier scanne, dont le litteral admis
    // est present ET porte vraiment du non-ASCII.
    let (rust, scripts, packaging) = collecter();
    let tous: Lot = rust.into_iter().chain(scripts).chain(packaging).collect();

    for ex in EXCEPTIONS {
        let Some((_, bytes)) = tous.iter().find(|(rel, _)| rel == ex.fichier) else {
            panic!(
                "{}: exception qui ne designe aucun fichier scanne: a retirer",
                ex.fichier
            );
        };
        let texte = std::str::from_utf8(bytes)
            .unwrap_or_else(|_| panic!("{}: fichier non-UTF-8", ex.fichier));
        assert!(
            texte.contains(ex.litteral),
            "{}: le litteral admis n'apparait plus dans le fichier: exception a \
             retirer",
            ex.fichier
        );
        assert!(
            ex.litteral.chars().any(|c| est_interdit(c as u32)),
            "{}: le litteral admis ne porte aucun caractere non-ASCII: exception \
             inutile",
            ex.fichier
        );
        assert!(
            !ex.raison.trim().is_empty(),
            "{}: exception sans raison ecrite",
            ex.fichier
        );
    }
}

#[test]
fn l_admission_reconnait_les_guillemets_et_rougit_sur_le_reste() {
    // Les deux guillemets francais sont admis; l'accent et le tiret cadratin
    // ne le sont pas.
    assert!(!est_interdit(0x00AB), "<< doit etre admis");
    assert!(!est_interdit(0x00BB), ">> doit etre admis");
    assert!(!est_interdit(u32::from(b'A')));
    assert!(est_interdit(0x00E9), "e accent aigu doit etre interdit");
    assert!(est_interdit(0x2014), "tiret cadratin doit etre interdit");

    // L'exception est scopee a son litteral. Dans superviseur.rs, la chaine
    // multi-octets est admise...
    let ligne_chaine = "        j.pousser(\"\u{e9}\u{e0}\u{fc}\");";
    let idx = ligne_chaine
        .char_indices()
        .find(|(_, c)| *c == '\u{e9}')
        .unwrap()
        .0;
    assert!(admis_par_exception(
        "crates/bifrost-daemon/src/coeurs/superviseur.rs",
        ligne_chaine,
        idx
    ));

    // ...mais un accent AILLEURS dans ce meme fichier, hors de la chaine, ne
    // l'est pas: sans quoi l'exception serait un blanc-seing sur tout le
    // fichier.
    let ligne_hors = "        // un \u{e9} egare dans un commentaire";
    let idx_hors = ligne_hors
        .char_indices()
        .find(|(_, c)| *c == '\u{e9}')
        .unwrap()
        .0;
    assert!(!admis_par_exception(
        "crates/bifrost-daemon/src/coeurs/superviseur.rs",
        ligne_hors,
        idx_hors
    ));

    // Et un fichier sans exception ne beneficie de rien.
    assert!(!admis_par_exception(
        "fichier/sans/exception.rs",
        ligne_chaine,
        idx
    ));
}
