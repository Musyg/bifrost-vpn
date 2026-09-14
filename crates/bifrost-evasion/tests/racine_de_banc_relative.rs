//! La racine de banc absolue ne se versionne plus: les scripts la derivent.
//!
//! # Pourquoi cette recette existe
//!
//! Treize scripts PowerShell portaient une racine de banc absolue en dur, en
//! valeur par defaut d'un parametre ou dans un commentaire d'usage. C'est une
//! identite de banc, et le depot est prive: rien de tel ne doit y rester avant
//! son ouverture. L'arbitrage 8 (option B), rendu le 06/09/2026, tranche: chaque
//! script prend en tete de son bloc `param()` un parametre `$Banc` derive de
//! `$env:BIFROST_BANC` et de `$PSScriptRoot`, et toutes ses valeurs par defaut de
//! chemin en descendent. Cette recette garde trois proprietes qui se verifient
//! sans jugement:
//!
//! 1. aucun fichier versionne de `scripts/`, `packaging/` ou `crates/` ne porte
//!    la racine de banc absolue (le chemin d'un banc d'essai), sous aucune de
//!    ses formes;
//! 2. chacun des treize scripts declare `$Banc` en PREMIER parametre, derive de
//!    l'environnement et du repertoire du script, et aucune valeur par defaut de
//!    son bloc `param()` n'est un chemin absolu;
//! 3. chacun refuse un `$Banc` vide, par un `throw` juste apres `param()`.
//!
//! # Ce qu'elle ne fait pas
//!
//! Elle ne demande pas git: le parcours se fait sur le disque. Sur essai-linux le
//! depot est copie par `tar` et n'a pas de `.git`, donc une recette qui
//! appellerait `git ls-files` s'y abstiendrait a chaque passage, et une recette
//! qui ne s'execute que sur une machine sur deux ne garde rien.
//!
//! Le segment de banc est ecrit ici en fragments (jamais colle a une lettre de
//! lecteur et a un separateur) pour que le balayage ne se signale pas lui-meme:
//! une recette qui rougit sur sa propre source ne garde rien non plus.

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

/// Le segment qui suit la lettre de lecteur dans la racine de banc historique.
/// Ecrit seul, jamais precede de la lettre et du separateur, pour ne pas se
/// faire reperer par le balayage ci-dessous.
const SEGMENT_BANC: &[u8] = b"bifrost-test";

/// Les repertoires que le parcours ne descend pas, a n'importe quelle
/// profondeur: objets compresses et binaires, pleins d'octets qui ne sont pas
/// du texte qu'on ecrit.
const DOSSIERS_IGNORES: [&str; 2] = [".git", "target"];

/// Les racines balayees et les extensions considerees comme du texte versionne.
const RACINES: [&str; 3] = ["scripts", "packaging", "crates"];
const EXTENSIONS: [&str; 8] = ["ps1", "sh", "cmd", "rs", "toml", "md", "txt", "in"];

/// Les treize scripts que l'arbitrage 8B derive de `$Banc`.
const SCRIPTS: [&str; 13] = [
    "scripts/banc-coeur-windows.ps1",
    "scripts/banc-jeton-filtre-windows.ps1",
    "scripts/jetons-compare-windows.ps1",
    "scripts/service-windows.ps1",
    "scripts/telemetrie-cause-binaire-windows.ps1",
    "scripts/telemetrie-cause-windows.ps1",
    "scripts/telemetrie-cibles-windows.ps1",
    "scripts/telemetrie-conditions-windows.ps1",
    "scripts/telemetrie-effet-windows.ps1",
    "scripts/telemetrie-reseau-windows.ps1",
    "scripts/telemetrie-svchost-windows.ps1",
    "scripts/telemetrie-w32time-windows.ps1",
    "scripts/telemetrie-windows.ps1",
];

// ------------------------------------------------------------------ balayage

/// Vrai si la ligne (deja en minuscules, en octets) porte la racine de banc
/// absolue: une lettre `c`, deux points, AU MOINS un separateur (`\` ou `/`),
/// puis le segment de banc.
///
/// Le nombre de separateurs est libre: un litteral PowerShell ecrit un seul
/// antislash sur le disque, un litteral Rust en ecrit deux (`\\` a la source),
/// et la forme a barre oblique en a un. Un seul motif couvre les trois, sans
/// quoi la forme Rust echapperait au balayage.
fn porte_identite_de_banc(ligne_bas: &[u8]) -> bool {
    let n = ligne_bas.len();
    let mut i = 0;
    while i + 1 < n {
        if ligne_bas[i] == b'c' && ligne_bas[i + 1] == b':' {
            let mut j = i + 2;
            let mut separateurs = 0usize;
            while j < n && (ligne_bas[j] == b'\\' || ligne_bas[j] == b'/') {
                j += 1;
                separateurs += 1;
            }
            if separateurs >= 1 && ligne_bas[j..].starts_with(SEGMENT_BANC) {
                return true;
            }
        }
        i += 1;
    }
    false
}

fn est_du_texte(chemin: &Path) -> bool {
    match chemin.extension().and_then(OsStr::to_str) {
        Some(ext) => EXTENSIONS.contains(&ext),
        None => false,
    }
}

fn parcourir(dossier: &Path, base: &Path, examines: &mut usize, defauts: &mut Vec<String>) {
    let Ok(entrees) = std::fs::read_dir(dossier) else {
        return;
    };
    for entree in entrees.flatten() {
        let chemin = entree.path();
        let nom = entree.file_name().to_string_lossy().into_owned();
        if chemin.is_dir() {
            if !DOSSIERS_IGNORES.contains(&nom.as_str()) {
                parcourir(&chemin, base, examines, defauts);
            }
        } else if est_du_texte(&chemin)
            && let Ok(octets) = std::fs::read(&chemin)
        {
            *examines += 1;
            let relatif = chemin
                .strip_prefix(base)
                .unwrap_or(&chemin)
                .display()
                .to_string()
                .replace('\\', "/");
            for (rang, ligne) in octets.split(|o| *o == b'\n').enumerate() {
                let bas: Vec<u8> = ligne.iter().map(|o| o.to_ascii_lowercase()).collect();
                if porte_identite_de_banc(&bas) {
                    defauts.push(format!("{relatif}:{}", rang + 1));
                }
            }
        }
    }
}

#[test]
fn aucune_identite_de_banc_dans_scripts_packaging_crates() {
    let base = racine();
    let mut examines = 0usize;
    let mut defauts = Vec::new();
    for r in RACINES {
        parcourir(&base.join(r), &base, &mut examines, &mut defauts);
    }

    // Controle positif: un parcours casse - mauvaise racine, lecture qui echoue
    // en silence - rendrait une liste vide, donc un succes, sans avoir rien lu.
    assert!(
        examines > 100,
        "le parcours n'a examine que {examines} fichier(s): il ne verifie rien"
    );

    assert!(
        defauts.is_empty(),
        "{} occurrence(s) de la racine de banc absolue dans le depot versionne. \
         C'est une identite de banc, elle ne se versionne pas: la deriver de \
         $Banc:\n  {}",
        defauts.len(),
        defauts.join("\n  ")
    );
}

// ------------------------------------------------------- lecture des scripts

fn lire_script(relatif: &str) -> String {
    let chemin = racine().join(relatif);
    std::fs::read_to_string(&chemin)
        .unwrap_or_else(|e| panic!("{} illisible: {e}", chemin.display()))
}

/// Sans espaces, pour comparer une declaration quel que soit l'espacement.
fn sans_espaces(ligne: &str) -> String {
    ligne.chars().filter(|c| !c.is_whitespace()).collect()
}

/// Une ligne de declaration de parametre: ni commentaire, ni vide, elle porte
/// une variable et ouvre sur un type entre crochets ou sur le `$` directement.
/// Un attribut comme `[ValidateSet(...)]` ne porte pas de `$` et n'en est pas un.
fn est_declaration(trim: &str) -> bool {
    !trim.is_empty()
        && !trim.starts_with('#')
        && trim.contains('$')
        && (trim.starts_with('[') || trim.starts_with('$'))
}

/// Rend (index de la ligne `param(`, index de la ligne de fermeture `)`).
fn bloc_param(lignes: &[&str]) -> Option<(usize, usize)> {
    let debut = lignes.iter().position(|l| l.contains("param("))?;
    for (k, ligne) in lignes.iter().enumerate().skip(debut + 1) {
        if ligne.trim() == ")" {
            return Some((debut, k));
        }
    }
    None
}

/// Vrai si la ligne porte un chemin absolu a la Windows: une lettre, deux
/// points, puis un separateur. `$env:BIFROST_BANC` (lettre, deux points, lettre)
/// et `1.1.1.1:443` (chiffre avant les deux points) n'en sont pas.
fn contient_chemin_absolu(ligne: &str) -> bool {
    let b = ligne.as_bytes();
    if b.len() < 3 {
        return false;
    }
    for i in 0..(b.len() - 2) {
        if b[i].is_ascii_alphabetic() && b[i + 1] == b':' && (b[i + 2] == b'\\' || b[i + 2] == b'/')
        {
            return true;
        }
    }
    false
}

#[test]
fn chaque_script_derive_sa_racine_du_banc() {
    for relatif in SCRIPTS {
        let texte = lire_script(relatif);
        let lignes: Vec<&str> = texte.lines().collect();

        // Controle positif: le fichier existe (lire_script paniquerait sinon) et
        // porte un bloc param(). Sans lui, la recette ne verifierait rien.
        let (debut, fin) = bloc_param(&lignes)
            .unwrap_or_else(|| panic!("{relatif} ne porte pas de bloc param() lisible"));

        // Le PREMIER parametre doit etre $Banc, derive de l'environnement et du
        // repertoire du script.
        let premier = ((debut + 1)..fin)
            .find(|&k| est_declaration(lignes[k].trim()))
            .unwrap_or_else(|| panic!("{relatif}: aucun parametre dans le bloc param()"));
        let ligne_banc = lignes[premier];
        assert!(
            sans_espaces(ligne_banc).starts_with("[string]$Banc"),
            "{relatif}: le premier parametre n'est pas $Banc mais:\n  {}",
            ligne_banc.trim()
        );
        assert!(
            ligne_banc.contains("$env:BIFROST_BANC") && ligne_banc.contains("$PSScriptRoot"),
            "{relatif}: $Banc ne derive pas de $env:BIFROST_BANC et de $PSScriptRoot:\n  {}",
            ligne_banc.trim()
        );

        // Aucune valeur par defaut du bloc param() n'est un chemin absolu.
        let mut absolus = Vec::new();
        for (k, ligne) in lignes.iter().enumerate().take(fin).skip(debut + 1) {
            let trim = ligne.trim();
            if est_declaration(trim) && contient_chemin_absolu(ligne) {
                absolus.push(format!("{relatif}:{}: {}", k + 1, trim));
            }
        }
        assert!(
            absolus.is_empty(),
            "valeur(s) par defaut absolue(s) dans le bloc param(). Un chemin \
             absolu est une identite de machine: le deriver de $Banc:\n  {}",
            absolus.join("\n  ")
        );
    }
}

#[test]
fn chaque_script_refuse_un_banc_vide() {
    for relatif in SCRIPTS {
        let texte = lire_script(relatif);
        let lignes: Vec<&str> = texte.lines().collect();
        let (_, fin) = bloc_param(&lignes)
            .unwrap_or_else(|| panic!("{relatif} ne porte pas de bloc param() lisible"));

        // La garde vit juste apres param(). On la cherche dans une fenetre
        // courte: un test de vacuite de $Banc, puis un throw.
        let borne = (fin + 15).min(lignes.len());
        let test = ((fin + 1)..borne)
            .find(|&k| lignes[k].contains("$Banc") && lignes[k].contains("IsNullOrEmpty"));
        let idx = test
            .unwrap_or_else(|| panic!("{relatif}: pas de test de vacuite de $Banc apres param()"));
        let a_throw = (idx..(idx + 4).min(lignes.len())).any(|k| lignes[k].contains("throw"));
        assert!(
            a_throw,
            "{relatif}: $Banc est teste vide mais aucun throw ne suit: un banc \
             inconnu doit arreter le script, pas produire des chemins faux"
        );
    }
}
