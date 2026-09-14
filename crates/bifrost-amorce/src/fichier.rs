//! Le canal le plus resistant a la censure: un fichier.
//!
//! Une cle USB, un fichier recu par messagerie, un partage monte. Aucun reseau,
//! donc rien a bloquer - c'est le seul canal qui repond encore quand tous les
//! autres se taisent, et c'est la raison d'etre du trait [`Canal`]: la politique
//! de selection ne sait pas si un profil est arrive par HTTPS ou a pied.

use crate::{Canal, Recu};
use bifrost_coffre::signature::chemin_signature;
use std::path::{Path, PathBuf};

/// Un profil et sa signature, quelque part sur le disque.
pub struct Fichier {
    chemin: PathBuf,
}

impl Fichier {
    pub fn nouveau(chemin: impl Into<PathBuf>) -> Self {
        Self {
            chemin: chemin.into(),
        }
    }
}

impl Canal for Fichier {
    fn nom(&self) -> String {
        self.chemin.display().to_string()
    }

    fn chercher(&self) -> Result<Recu, String> {
        let profil = lire(&self.chemin)?;
        let signature = lire(&chemin_signature(&self.chemin))?;
        let signature = String::from_utf8(signature)
            .map_err(|_| "la signature n'est pas du texte".to_string())?;
        Ok(Recu { profil, signature })
    }
}

fn lire(chemin: &Path) -> Result<Vec<u8>, String> {
    std::fs::read(chemin).map_err(|e| format!("{}: {e}", chemin.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn atelier(nom: &str) -> PathBuf {
        let rep = std::env::temp_dir().join(format!("bifrost-amorce-{}-{nom}", std::process::id()));
        let _ = std::fs::remove_dir_all(&rep);
        std::fs::create_dir_all(&rep).unwrap();
        rep
    }

    #[test]
    fn un_fichier_et_sa_signature_se_lisent() {
        let rep = atelier("lit");
        let p = rep.join("profil.toml");
        std::fs::write(&p, b"a = 1").unwrap();
        std::fs::write(chemin_signature(&p), "untrusted comment: x\nAAAA\n").unwrap();

        let recu = Fichier::nouveau(&p).chercher().expect("doit lire");
        assert_eq!(recu.profil, b"a = 1");
        assert!(recu.signature.contains("AAAA"));
        let _ = std::fs::remove_dir_all(&rep);
    }

    /// Un profil sans signature est un canal muet, pas un demi-succes.
    #[test]
    fn un_profil_sans_signature_est_un_echec_qui_nomme_le_fichier_manquant() {
        let rep = atelier("nue");
        let p = rep.join("profil.toml");
        std::fs::write(&p, b"a = 1").unwrap();

        let e = Fichier::nouveau(&p).chercher().expect_err("doit echouer");
        assert!(
            e.contains(".minisig"),
            "le message doit nommer ce qui manque: {e}"
        );
        let _ = std::fs::remove_dir_all(&rep);
    }

    #[test]
    fn un_fichier_absent_se_plaint_de_son_chemin() {
        let e = Fichier::nouveau("/nulle/part/profil.toml")
            .chercher()
            .expect_err("doit echouer");
        assert!(e.contains("profil.toml"), "{e}");
    }
}
