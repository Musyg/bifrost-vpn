//! Tout script du depot porte le bit d'execution dans l'index git, et lui seul.
//!
//! # Pourquoi cette recette existe
//!
//! Un fichier cree sous Windows entre dans l'index en mode `100644`: le systeme
//! de fichiers n'a pas de bit d'execution et git (`core.filemode` faux) n'en
//! invente pas. Rien ne le signale, et le script tourne tres bien sur la
//! machine qui l'a ecrit, puisque Git Bash ignore le bit. Il ne tourne plus
//! des qu'un Linux le recoit tel quel par `git clone`, `git archive` ou
//! `git checkout`: `./scripts/x.sh` rend `exit 126`, << Permission denied >>.
//!
//! Le piege a ete paye deux fois. Le 04/09/2026 sur essai-linux, apres un
//! `git archive` (regle depuis: `chmod +x` apres extraction, et lire le code de
//! sortie avant le nombre). Puis, sans que personne ne le voie pendant neuf
//! jours, sur la CI: du 05/09 (`b8df9a5`, qui a fait entrer
//! `recettes-strict.sh` et `abstentions-budget.sh` dans le job Linux) au 13/09
//! (`4826229`), huit runs rouges a << Permission denied >>, parce que ces
//! deux scripts etaient en `100644` avec sept autres. Le `chmod` de la regle du
//! 04/09 vivait dans la procedure de synchronisation, pas dans le depot: il
//! reparait la copie et laissait la cause.
//!
//! # Ce qu'elle exige
//!
//! Sous `scripts/` et `packaging/`, un fichier `.sh` ou `.py`, ou un fichier
//! sans extension sous `packaging/systemd/system-sleep/` (un crochet que
//! systemd lance directement), est en `100755` dans l'index ET commence par
//! `#!`. Reciproquement, un fichier en `100755` de ces deux arbres commence par
//! `#!`: un executable sans interprete declare serait lance par le shell de
//! l'appelant, quel qu'il soit. Les `.ps1` ne sont pas concernes, PowerShell
//! ne regarde pas le bit.
//!
//! # Ce qu'elle suppose
//!
//! Elle lit l'INDEX, pas le disque: sous Windows le disque ne sait rien du bit,
//! et sur essai-linux l'arbre est copie par `tar`, sans `.git`. Elle demande
//! donc `git` et un depot. Sans l'un ou l'autre elle s'abstient, en le disant:
//! c'est la seule recette de ce dossier qui appelle git, et c'est parce que
//! l'information n'existe nulle part ailleurs. La copie par `tar` d'essai-linux
//! s'y abstiendra a chaque passage; les worktrees de dev-windows, la copie du
//! verificateur (un worktree) et le runner de la CI (un clone) la font tourner.
//!
//! Reparation: `git update-index --chmod=+x <fichier>` (ou `--chmod=-x`), puis
//! commit. C'est ce qu'a fait la tranche `5w'` pour les neuf fichiers trouves.

use std::path::{Path, PathBuf};
use std::process::Command;

fn racine() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("la racine de l'espace de travail doit exister")
        .to_path_buf()
}

/// Les arbres examines, relatifs a la racine.
const ARBRES: [&str; 2] = ["scripts", "packaging"];

/// Un chemin de l'index (en avant-slash, comme git l'ecrit) qui doit etre
/// executable.
fn doit_etre_executable(chemin: &str) -> bool {
    let p = Path::new(chemin);
    match p.extension().and_then(|e| e.to_str()) {
        Some("sh") | Some("py") => true,
        Some(_) => false,
        None => chemin.starts_with("packaging/systemd/system-sleep/"),
    }
}

/// Une entree de l'index: mode et chemin.
struct Entree {
    mode: String,
    chemin: String,
}

/// Lit `git ls-files -s` sur les deux arbres. `None` quand git ne peut pas
/// tourner ou que l'arbre n'est pas un depot: la recette s'abstient alors.
fn index() -> Option<Vec<Entree>> {
    let sortie = Command::new("git")
        .arg("-C")
        .arg(racine())
        .args(["ls-files", "-s", "-z", "--"])
        .args(ARBRES)
        .output()
        .ok()?;
    if !sortie.status.success() {
        return None;
    }
    let texte = String::from_utf8_lossy(&sortie.stdout);
    let mut entrees = Vec::new();
    for ligne in texte.split('\0').filter(|l| !l.is_empty()) {
        // `<mode> <objet> <etape>\t<chemin>`
        let (meta, chemin) = ligne.split_once('\t')?;
        let mode = meta.split_whitespace().next()?.to_string();
        entrees.push(Entree {
            mode,
            chemin: chemin.to_string(),
        });
    }
    Some(entrees)
}

fn commence_par_shebang(chemin: &str) -> bool {
    std::fs::read(racine().join(chemin))
        .map(|octets| octets.starts_with(b"#!"))
        .unwrap_or(false)
}

#[test]
fn chaque_script_de_l_index_porte_le_bit_d_execution_et_lui_seul() {
    let Some(entrees) = index() else {
        println!(
            "SKIPPED: pas de depot git lisible sous {}: le bit d'execution ne se lit que dans l'index",
            racine().display()
        );
        return;
    };
    assert!(
        entrees
            .iter()
            .any(|e| e.chemin == "scripts/recettes-strict.sh"),
        "l'index doit lister scripts/recettes-strict.sh: la lecture de git ls-files a rate"
    );

    let mut ecarts = Vec::new();
    for e in &entrees {
        let attendu = doit_etre_executable(&e.chemin);
        let executable = e.mode == "100755";
        let shebang = commence_par_shebang(&e.chemin);
        if attendu && !executable {
            ecarts.push(format!(
                "{} est en {} dans l'index: git update-index --chmod=+x {}",
                e.chemin, e.mode, e.chemin
            ));
        }
        if attendu && !shebang {
            ecarts.push(format!("{} ne commence pas par #!", e.chemin));
        }
        if executable && !shebang {
            ecarts.push(format!(
                "{} est executable sans commencer par #!: git update-index --chmod=-x {} ou un interprete declare",
                e.chemin, e.chemin
            ));
        }
    }
    assert!(
        ecarts.is_empty(),
        "{} ecart(s) de mode dans l'index:\n  {}",
        ecarts.len(),
        ecarts.join("\n  ")
    );
}

#[test]
fn la_regle_nomme_les_bons_fichiers() {
    assert!(doit_etre_executable("scripts/recettes-strict.sh"));
    assert!(doit_etre_executable("scripts/quic-chronologie.py"));
    assert!(doit_etre_executable("packaging/comptes.sh"));
    assert!(doit_etre_executable(
        "packaging/systemd/system-sleep/bifrost-reprise"
    ));
    assert!(!doit_etre_executable("scripts/service-windows.ps1"));
    assert!(!doit_etre_executable("packaging/security.txt"));
    assert!(!doit_etre_executable(
        "packaging/systemd/bifrost-daemon.service"
    ));
    assert!(!doit_etre_executable("packaging/SECURITY-TXT.md"));
}
