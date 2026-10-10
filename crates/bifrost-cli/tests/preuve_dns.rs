//! `prove dns` par le vrai client: les deux sources de l'attendu et ce que la
//! ligne de commande en admet. Aucun daemon, reseau ou privilege requis.

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::Value;

static NUMERO: AtomicU64 = AtomicU64::new(0);

/// Un repertoire de recette au nom unique, retire meme sur une recette rouge.
struct Bac(PathBuf);

impl Bac {
    fn nouveau() -> Self {
        let p = std::env::temp_dir().join(format!(
            "bifrost-preuve-dns-{}-{}",
            std::process::id(),
            NUMERO.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&p).unwrap();
        Self(p)
    }
}

impl Drop for Bac {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// `--politique-daemon`: l'attendu vient du daemon, le systeme courant
/// l'observe.
///
/// Exclusive de `--intention`, et `--actif` exige: toute autre combinaison est
/// refusee par clap avant la moindre lecture. Sans daemon sur le socket
/// nomme, la preuve rend son NON MESURE nomme, sans exporter le chemin du
/// socket. Le mode intention garde son rapport, sans identite de daemon.
#[test]
fn par_declaration_exclusive_de_l_intention_et_liee_au_systeme_courant() {
    let b = Bac::nouveau();
    let intention = b.0.join("intention-privee.json");
    std::fs::write(&intention, "{}").unwrap();
    let f = intention.to_str().unwrap();
    for arguments in [
        vec!["--politique-daemon"],
        vec!["--actif"],
        vec!["--politique-daemon", "--actif", "--intention", f],
        vec!["--politique-daemon", "--intention", f],
        vec!["--intention", f],
    ] {
        let sortie = Command::new(env!("CARGO_BIN_EXE_bifrost-cli"))
            .args(["--json", "--socket", "absent", "prove", "dns"])
            .args(&arguments)
            .output()
            .unwrap();
        assert_eq!(sortie.status.code(), Some(2), "{arguments:?}");
        assert!(sortie.stdout.is_empty(), "{arguments:?}");
    }

    let socket = b.0.join("daemon-prive.sock");
    let sortie = Command::new(env!("CARGO_BIN_EXE_bifrost-cli"))
        .args(["--json", "--socket"])
        .arg(&socket)
        .args(["prove", "dns", "--politique-daemon", "--actif"])
        .output()
        .unwrap();
    assert_eq!(sortie.status.code(), Some(2), "{sortie:?}");
    let r: Value = serde_json::from_slice(&sortie.stdout).unwrap();
    assert_eq!(r["schema_version"], 1);
    assert_eq!(r["scope"], "linux-dns-comparison");
    assert_eq!(r["verdict"], "UNMEASURED");
    assert_eq!(r["expected_source"], "daemon-declared-active-dns-plan");
    assert_eq!(r["failed_input"], "daemon-declaration");
    assert!(r["daemon_identity"].is_null(), "{r}");
    assert!(r["intention_schema_version"].is_null());
    assert_eq!(r["live_system"], false);
    assert_eq!(r["network_security"], "not-evaluated");
    #[cfg(target_os = "linux")]
    assert_eq!(r["reason"], "daemon injoignable");
    #[cfg(not(target_os = "linux"))]
    assert_eq!(
        r["reason"],
        "declaration DNS non applicable sur cette plateforme: la preuve DNS par declaration ne lit que Linux"
    );
    assert!(!String::from_utf8_lossy(&sortie.stdout).contains("daemon-prive"));

    let sortie = Command::new(env!("CARGO_BIN_EXE_bifrost-cli"))
        .args([
            "--json",
            "--socket",
            "absent",
            "prove",
            "dns",
            "--intention",
        ])
        .arg(&intention)
        .arg("--actif")
        .output()
        .unwrap();
    assert_eq!(sortie.status.code(), Some(2), "{sortie:?}");
    let r: Value = serde_json::from_slice(&sortie.stdout).unwrap();
    assert_eq!(r["expected_source"], "bifrost-dns-plan-v1-user-declared");
    assert_eq!(r["failed_input"], "intention");
    assert!(r.get("daemon_identity").is_none(), "{r}");
    assert!(!String::from_utf8_lossy(&sortie.stdout).contains("intention-privee"));
}
