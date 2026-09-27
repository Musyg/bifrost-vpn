//! Exercices du vrai client: aucun daemon, reseau ou privilege requis.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

const ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
static NUMERO: AtomicU64 = AtomicU64::new(0);

struct Bac(PathBuf);

impl Bac {
    fn nouveau() -> Self {
        let p = std::env::temp_dir().join(format!(
            "bifrost-preuve-{}-{}",
            std::process::id(),
            NUMERO.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&p).unwrap();
        Self(p)
    }

    fn fichier(&self) -> PathBuf {
        let p = self.0.join("nom-confidentiel.bin");
        std::fs::write(&p, b"abc").unwrap();
        p
    }
}

impl Drop for Bac {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

fn lancer(fichier: &Path, hash: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_bifrost-cli"))
        .args([
            "--json",
            "--socket",
            "daemon-inexistant",
            "prove",
            "binaire",
            "--fichier",
        ])
        .arg(fichier)
        .args(["--sha256", hash])
        .output()
        .unwrap()
}

fn rapport(sortie: &Output, code: i32, verdict: &str) -> serde_json::Value {
    assert_eq!(sortie.status.code(), Some(code), "{sortie:?}");
    let r: serde_json::Value = serde_json::from_slice(&sortie.stdout).unwrap();
    assert_eq!(r["schema_version"], 1);
    assert_eq!(r["scope"], "file-sha256");
    assert_eq!(r["verdict"], verdict);
    assert_eq!(r["reference_source"], "user-supplied");
    assert_eq!(r["provenance"], "not-verified");
    assert_eq!(r["network_security"], "not-evaluated");
    assert!(r["started_at_unix_ms"].as_u64().is_some());
    assert!(r["completed_at_unix_ms"].as_u64().is_some());
    assert!(r["duration_ms"].as_u64().is_some());
    r
}

#[test]
fn mesure_sans_daemon_sans_chemin_exporte_et_sans_ecriture() {
    let bac = Bac::nouveau();
    let p = bac.fichier();
    let sortie = lancer(&p, &ABC.to_ascii_uppercase());
    let r = rapport(&sortie, 0, "MATCH");
    assert_eq!(r["expected_sha256"], ABC);
    assert_eq!(r["observed_sha256"], ABC);
    assert_eq!(r["bytes_read"], 3);
    let texte = String::from_utf8(sortie.stdout).unwrap();
    assert!(!texte.contains("nom-confidentiel"));
    assert!(!texte.contains("bifrost-preuve-"));
    assert!(sortie.stderr.is_empty());
    assert_eq!(std::fs::read(&p).unwrap(), b"abc");
    assert_eq!(std::fs::read_dir(&bac.0).unwrap().count(), 1);
}

#[test]
fn un_octet_altere_rougit_et_conserve_les_deux_empreintes() {
    let bac = Bac::nouveau();
    let p = bac.fichier();
    std::fs::write(&p, b"abd").unwrap();
    let r = rapport(&lancer(&p, ABC), 1, "MISMATCH");
    assert_ne!(r["observed_sha256"], ABC);
    assert_eq!(r["expected_sha256"], ABC);
}

#[test]
fn absent_repertoire_et_fichier_trop_grand_ne_passent_jamais() {
    let bac = Bac::nouveau();
    for p in [bac.0.join("absent"), bac.0.clone()] {
        let r = rapport(&lancer(&p, ABC), 2, "UNMEASURED");
        assert!(r["observed_sha256"].is_null());
        assert!(r["bytes_read"].is_null());
    }
    let p = bac.0.join("grand");
    std::fs::File::create(&p)
        .unwrap()
        .set_len(512 * 1024 * 1024 + 1)
        .unwrap();
    let r = rapport(&lancer(&p, ABC), 2, "UNMEASURED");
    assert!(r["observed_sha256"].is_null());
}

#[test]
fn empreinte_invalide_refusee_par_la_cli() {
    let bac = Bac::nouveau();
    let sortie = lancer(&bac.0.join("absent"), "abc");
    assert_eq!(sortie.status.code(), Some(2));
    assert!(sortie.stdout.is_empty());
    assert!(
        String::from_utf8(sortie.stderr)
            .unwrap()
            .contains("64 caracteres")
    );
}

#[cfg(unix)]
#[test]
fn lien_symbolique_refuse_meme_si_la_cible_correspond() {
    let bac = Bac::nouveau();
    let p = bac.fichier();
    let lien = bac.0.join("lien");
    std::os::unix::fs::symlink(p, &lien).unwrap();
    rapport(&lancer(&lien, ABC), 2, "UNMEASURED");
}
