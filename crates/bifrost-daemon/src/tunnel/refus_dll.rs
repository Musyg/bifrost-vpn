//! Le message d'un chargement de DLL refuse.
//!
//! `LoadLibraryExW` rend un module nul et laisse sa raison a `GetLastError`.
//! Pour qui lit le journal, ce code est le seul diagnostic: un indice qui ne
//! lui correspond pas l'envoie chercher ailleurs. L'indice d'architecture n'est
//! donc donne que pour `ERROR_BAD_EXE_FORMAT`; tout autre code est rendu tel
//! quel, nomme quand il figure dans la table ci-dessous, avec le texte que le
//! systeme lui associe.
//!
//! Les deux chargeurs du depot passent par ici: `wintun.dll` pour le chemin
//! par coeur ([`super::brut`]) et `wireguard.dll` pour WireGuardNT
//! ([`super::wgnt`]). Ce module est pur: il est compile et teste partout, ses
//! deux appelants n'existent que sous Windows.
//!
//! # Sources et mesures
//!
//! Noms et valeurs: learn.microsoft.com, << System Error Codes (0-499) >> et
//! << System Error Codes (500-999) >>, ms.date du 14/07/2025, lues le
//! 02/10/2026. Une recette Windows les compare aux constantes de `windows-sys`.
//!
//! Mesure du 02/10/2026 sur dev-windows, processus 64 bits,
//! `LOAD_LIBRARY_SEARCH_SYSTEM32`: une DLL 32 bits de `SysWOW64` rend 193, un
//! fichier texte nomme `.dll` rend aussi 193, un chemin absent rend 126, et un
//! fichier tenu ouvert sans partage rend 32. D'ou l'indice de 193, qui nomme
//! les deux causes observees, et lui seul.

use std::path::Path;

/// `%1 is not a valid Win32 application.`
pub const ERROR_BAD_EXE_FORMAT: u32 = 193;
/// `The specified module could not be found.`
pub const ERROR_MOD_NOT_FOUND: u32 = 126;
/// `Windows cannot verify the digital signature for this file.` Ce que rend
/// un chargement refuse par une politique de signature du code.
pub const ERROR_INVALID_IMAGE_HASH: u32 = 577;

/// Les codes nommes. Ceux qu'un chargement par chemin absolu peut rendre, et
/// rien de plus: un code absent de la table reste rendu, par son numero et le
/// texte du systeme.
const NOMS: [(u32, &str); 10] = [
    (2, "ERROR_FILE_NOT_FOUND"),
    (3, "ERROR_PATH_NOT_FOUND"),
    (5, "ERROR_ACCESS_DENIED"),
    (32, "ERROR_SHARING_VIOLATION"),
    (ERROR_MOD_NOT_FOUND, "ERROR_MOD_NOT_FOUND"),
    (127, "ERROR_PROC_NOT_FOUND"),
    (ERROR_BAD_EXE_FORMAT, "ERROR_BAD_EXE_FORMAT"),
    (216, "ERROR_EXE_MACHINE_TYPE_MISMATCH"),
    (225, "ERROR_VIRUS_INFECTED"),
    (ERROR_INVALID_IMAGE_HASH, "ERROR_INVALID_IMAGE_HASH"),
];

/// L'indice, pour le seul code qui le justifie.
const INDICE_FORMAT: &str =
    "architecture du binaire et de la DLL differentes, ou fichier qui n'est pas une DLL?";

/// Le nom symbolique d'un code, s'il figure dans la table.
pub fn nom(code: u32) -> Option<&'static str> {
    NOMS.iter().find(|(c, _)| *c == code).map(|(_, n)| *n)
}

/// Le message rendu quand `LoadLibraryExW` refuse `chemin`.
///
/// `code` est ce que `GetLastError` a rendu juste apres l'appel, et
/// `texte_du_systeme` ce que le systeme dit de ce code (`std::io::Error`
/// l'obtient de `FormatMessageW`). Le texte est passe et non calcule ici: ce
/// module ne fait aucun appel au systeme, pour etre teste partout.
pub fn message(chemin: &Path, code: u32, texte_du_systeme: &str) -> String {
    let designation = match nom(code) {
        Some(n) => format!("{n} ({code})"),
        None => format!("erreur Win32 {code}"),
    };
    let indice = if code == ERROR_BAD_EXE_FORMAT {
        format!(", {INDICE_FORMAT}")
    } else {
        String::new()
    };
    format!(
        "chargement de {} refuse ({texte_du_systeme}): {designation}{indice}",
        chemin.display()
    )
}

/// Pour les recettes des deux chargeurs: un fichier `.dll` qui n'est pas une
/// image, que `LoadLibraryExW` refuse par son format (193), et qu'il refuse
/// pour une autre raison (32) tant qu'il est tenu ouvert sans partage.
#[cfg(all(test, windows))]
pub(crate) mod essai {
    use std::path::{Path, PathBuf};

    /// Le fichier, retire a la fin de la recette, rouge comprise.
    pub(crate) struct PasUneImage(PathBuf);

    impl PasUneImage {
        /// Un nom par processus et par recette: deux recettes ou deux
        /// executions concurrentes ne se partagent pas le fichier.
        pub(crate) fn nouveau(recette: &str) -> Self {
            let chemin = std::env::temp_dir().join(format!(
                "bifrost-refus-dll-{}-{recette}.dll",
                std::process::id()
            ));
            std::fs::write(&chemin, b"ce fichier n'est pas une image PE").expect("fichier jetable");
            Self(chemin)
        }

        pub(crate) fn chemin(&self) -> &Path {
            &self.0
        }

        /// Le fichier ouvert SANS partage: tant que la poignee vit, tout
        /// autre ouverture, celle du chargeur comprise, est refusee.
        pub(crate) fn tenir(&self) -> std::fs::File {
            use std::os::windows::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .read(true)
                .share_mode(0)
                .open(&self.0)
                .expect("ouverture sans partage")
        }
    }

    impl Drop for PasUneImage {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pour(code: u32) -> String {
        message(Path::new("bin/wintun.dll"), code, "texte du systeme")
    }

    /// Le format refuse, et lui seul, porte l'indice d'architecture.
    #[test]
    fn l_indice_d_architecture_ne_vaut_que_pour_le_format() {
        let m = pour(ERROR_BAD_EXE_FORMAT);
        assert!(m.contains("ERROR_BAD_EXE_FORMAT (193)"), "{m}");
        assert!(m.contains("architecture"), "{m}");
        for code in [ERROR_INVALID_IMAGE_HASH, ERROR_MOD_NOT_FOUND] {
            let m = pour(code);
            assert!(
                !m.contains("architecture"),
                "le code {code} ne dit rien de l'architecture: {m}"
            );
        }
    }

    /// Une signature refusee et un module introuvable sont nommes, numero
    /// compris: c'est tout ce que le message peut dire de vrai sur eux.
    #[test]
    fn la_signature_refusee_et_le_module_introuvable_sont_nommes() {
        let m = pour(ERROR_INVALID_IMAGE_HASH);
        assert!(m.contains("ERROR_INVALID_IMAGE_HASH (577)"), "{m}");
        let m = pour(ERROR_MOD_NOT_FOUND);
        assert!(m.contains("ERROR_MOD_NOT_FOUND (126)"), "{m}");
    }

    /// Un code hors de la table reste rendu tel quel, sans nom invente ni
    /// indice, et le chemin comme le texte du systeme figurent toujours.
    #[test]
    fn un_code_inconnu_est_rendu_tel_quel() {
        let m = pour(4242);
        assert!(m.contains("erreur Win32 4242"), "{m}");
        assert!(!m.contains("architecture"), "{m}");
        assert!(!m.contains("ERROR_"), "{m}");
        for code in [ERROR_BAD_EXE_FORMAT, ERROR_INVALID_IMAGE_HASH, 4242] {
            let m = pour(code);
            assert!(m.contains("bin/wintun.dll"), "{m}");
            assert!(m.contains("texte du systeme"), "{m}");
        }
    }

    /// Chaque nom de la table est celui que le SDK donne a ce numero.
    #[cfg(windows)]
    #[test]
    fn les_noms_de_la_table_sont_ceux_du_sdk() {
        use windows_sys::Win32::Foundation as f;
        let sdk: [(u32, &str); 10] = [
            (f::ERROR_FILE_NOT_FOUND, "ERROR_FILE_NOT_FOUND"),
            (f::ERROR_PATH_NOT_FOUND, "ERROR_PATH_NOT_FOUND"),
            (f::ERROR_ACCESS_DENIED, "ERROR_ACCESS_DENIED"),
            (f::ERROR_SHARING_VIOLATION, "ERROR_SHARING_VIOLATION"),
            (f::ERROR_MOD_NOT_FOUND, "ERROR_MOD_NOT_FOUND"),
            (f::ERROR_PROC_NOT_FOUND, "ERROR_PROC_NOT_FOUND"),
            (f::ERROR_BAD_EXE_FORMAT, "ERROR_BAD_EXE_FORMAT"),
            (
                f::ERROR_EXE_MACHINE_TYPE_MISMATCH,
                "ERROR_EXE_MACHINE_TYPE_MISMATCH",
            ),
            (f::ERROR_VIRUS_INFECTED, "ERROR_VIRUS_INFECTED"),
            (f::ERROR_INVALID_IMAGE_HASH, "ERROR_INVALID_IMAGE_HASH"),
        ];
        assert_eq!(NOMS, sdk);
    }
}
