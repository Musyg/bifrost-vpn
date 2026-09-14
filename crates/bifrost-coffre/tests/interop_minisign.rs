//! Ce que produit le VRAI minisign est-il accepte ici.
//!
//! Les recettes du module de signature signent avec la crate Rust de Frank
//! Denis. L'utilisateur, lui, signera avec le binaire `minisign` - un autre
//! programme, dans un autre langage, avec son propre encodage. Une
//! incompatibilite entre les deux ne se verrait nulle part ailleurs qu'ici, et
//! elle se verrait au pire moment: le jour ou quelqu'un installe un profil.
//!
//! Cette recette couvre aussi ce que la crate Rust ne sait plus produire: le
//! FORMAT HERITE, que le binaire emet encore avec `-l`. C'est le seul endroit du
//! depot ou `allow_legacy = false` est mesure plutot que lu.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Le binaire, s'il est la.
///
/// Absent sur dev-windows, present sur essai-linux. Une recette qui ne peut pas
/// s'executer le DIT: la faire passer par defaut reviendrait a annoncer une
/// interoperabilite que rien n'a verifiee.
fn minisign_present() -> bool {
    Command::new("minisign")
        .arg("-v")
        .output()
        .map(|s| s.status.success())
        .unwrap_or(false)
}

struct Atelier {
    rep: PathBuf,
}

impl Atelier {
    fn nouveau(nom: &str) -> Self {
        let rep =
            std::env::temp_dir().join(format!("bifrost-interop-{}-{nom}", std::process::id()));
        let _ = std::fs::remove_dir_all(&rep);
        std::fs::create_dir_all(&rep).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&rep, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        Self { rep }
    }

    fn chemin(&self, nom: &str) -> PathBuf {
        self.rep.join(nom)
    }

    /// Une paire sans mot de passe: `-W`. Rend la ligne base64 de la publique.
    fn engendrer(&self, nom: &str) -> String {
        let pk = self.chemin(&format!("{nom}.pub"));
        let sk = self.chemin(&format!("{nom}.key"));
        self.lancer(&["-G", "-W", "-f", "-p", &s(&pk), "-s", &s(&sk)]);
        bifrost_coffre::signature::lire_cle_de_confiance(&pk).unwrap()
    }

    fn signer(&self, nom: &str, fichier: &Path, commentaire: &str, herite: bool) {
        let sk = s(&self.chemin(&format!("{nom}.key")));
        let f = s(fichier);
        let mut args = vec!["-S", "-s", &sk, "-t", commentaire, "-m", &f];
        if herite {
            args.insert(1, "-l");
        }
        self.lancer(&args);
    }

    fn lancer(&self, args: &[&str]) {
        let sortie = Command::new("minisign")
            .args(args)
            .current_dir(&self.rep)
            .output()
            .expect("minisign doit pouvoir tourner");
        assert!(
            sortie.status.success(),
            "minisign {args:?} a echoue: {}",
            String::from_utf8_lossy(&sortie.stderr)
        );
    }
}

impl Drop for Atelier {
    fn drop(&mut self) {
        // La cle privee engendree ici ne survit pas a la recette.
        let _ = std::fs::remove_dir_all(&self.rep);
    }
}

fn s(p: &Path) -> String {
    p.display().to_string()
}

fn lire_signature(fichier: &Path) -> String {
    std::fs::read_to_string(bifrost_coffre::signature::chemin_signature(fichier)).unwrap()
}

#[test]
fn ce_que_signe_le_vrai_minisign_est_accepte() {
    if !minisign_present() {
        println!("SKIPPED: le binaire minisign n'est pas installe sur cette machine");
        return;
    }

    let a = Atelier::nouveau("accepte");
    let cle = a.engendrer("bonne");
    let profil = a.chemin("tunnel.toml");
    std::fs::write(&profil, b"interface = \"wg0\"\n").unwrap();
    a.signer("bonne", &profil, "serie=42 profil de recette", false);

    let contenu = std::fs::read(&profil).unwrap();
    let origine = bifrost_coffre::signature::verifier(&contenu, &lire_signature(&profil), &cle)
        .expect("une signature du vrai minisign doit etre acceptee");
    assert_eq!(origine.serie, Some(42));
    assert!(origine.commentaire.contains("profil de recette"));
}

/// Le format herite est refuse, et c'est mesure.
///
/// `minisign -l` signe le fichier entier au lieu de son empreinte. La
/// specification demande aux nouvelles implementations de ne pas l'accepter par
/// defaut, et `verifier` passe donc `allow_legacy = false`. Sans cette recette,
/// ce drapeau ne serait qu'une ligne que personne ne relit.
#[test]
fn le_format_herite_est_refuse() {
    if !minisign_present() {
        println!("SKIPPED: le binaire minisign n'est pas installe sur cette machine");
        return;
    }

    let a = Atelier::nouveau("herite");
    let cle = a.engendrer("bonne");
    let profil = a.chemin("tunnel.toml");
    std::fs::write(&profil, b"interface = \"wg0\"\n").unwrap();
    a.signer("bonne", &profil, "serie=1", true);

    let contenu = std::fs::read(&profil).unwrap();
    bifrost_coffre::signature::verifier(&contenu, &lire_signature(&profil), &cle)
        .expect_err("le format herite ne doit pas passer");

    // Le temoin negatif: la MEME paire, le MEME profil, le MEME commentaire, en
    // format moderne. Sans lui, la recette passerait aussi si quelque chose
    // d'entierement different avait casse.
    a.signer("bonne", &profil, "serie=1", false);
    bifrost_coffre::signature::verifier(&contenu, &lire_signature(&profil), &cle)
        .expect("seul le format doit faire la difference");
}

#[test]
fn une_cle_etrangere_du_vrai_minisign_est_refusee() {
    if !minisign_present() {
        println!("SKIPPED: le binaire minisign n'est pas installe sur cette machine");
        return;
    }

    let a = Atelier::nouveau("etrangere");
    let attendue = a.engendrer("attendue");
    let _autre = a.engendrer("autre");
    let profil = a.chemin("tunnel.toml");
    std::fs::write(&profil, b"a = 1\n").unwrap();
    a.signer("autre", &profil, "serie=1", false);

    let contenu = std::fs::read(&profil).unwrap();
    bifrost_coffre::signature::verifier(&contenu, &lire_signature(&profil), &attendue)
        .expect_err("une signature d'une autre cle ne doit pas passer");
}

/// Le chemin entier, avec l'outil que l'utilisateur emploiera.
#[test]
fn un_profil_signe_par_le_vrai_minisign_s_installe() {
    if !minisign_present() {
        println!("SKIPPED: le binaire minisign n'est pas installe sur cette machine");
        return;
    }

    let a = Atelier::nouveau("installe");
    let cle = a.engendrer("bonne");
    std::fs::write(
        a.chemin(bifrost_coffre::signature::NOM_CLE_DE_CONFIANCE),
        &cle,
    )
    .unwrap();

    let source = a.chemin("arrive.toml");
    std::fs::write(&source, b"interface = \"wg0\"\n").unwrap();
    a.signer("bonne", &source, "serie=9", false);

    let dest = a.chemin("tunnel.toml");
    let origine = bifrost_coffre::signature::installer(&source, &dest)
        .expect("un profil signe par le vrai outil doit s'installer");
    assert_eq!(origine.serie, Some(9));
    assert_eq!(std::fs::read(&dest).unwrap(), b"interface = \"wg0\"\n");

    // Et le rejeu de ce meme profil, une fois installe, ne passe plus.
    bifrost_coffre::signature::installer(&source, &dest)
        .expect_err("la meme serie ne remplace pas");
}
