//! Le coffre sous Windows: DPAPI, dans le contexte du compte qui appelle.
//!
//! # Le plan disait "portee machine", et c'est exactement ce qu'il ne faut pas
//!
//! Le document 06 partie 137 demande "DPAPI (machine scope) sur Windows". Or la
//! documentation de `CryptProtectData` est explicite sur ce que fait ce
//! drapeau: avec `CRYPTPROTECT_LOCAL_MACHINE`, **n'importe quel utilisateur de
//! la machine peut dechiffrer**. Ce n'est pas un effet de bord, c'est sa raison
//! d'etre.
//!
//! Cela viderait le coffre de sa moitie utile. Sous Linux, `systemd-creds` lie
//! la cle au TPM ET a un fichier de `/var/` que seul root lit: il faut etre root
//! pour ouvrir un profil scelle. La portee machine rendrait le meme fichier
//! ouvrable par le premier compte venu - une protection contre le vol du disque,
//! oui, mais plus rien contre qui est deja sur la machine, alors que c'est
//! precisement la ou le profil vit.
//!
//! # Ce que fait la reference que le plan cite lui-meme
//!
//! WireGuard pour Windows, que le document 02 partie 152 donne en exemple,
//! n'utilise PAS la portee machine. Son service chiffre chaque configuration
//! avec `CryptProtectData` dans son propre contexte - celui de Local System -
//! puis rend le fichier illisible aux autres comptes et supprime le clair. Le
//! resultat est le bon: seul Local System rouvre la configuration.
//!
//! C'est ce qui est fait ici. Le chiffrement herite du compte qui appelle, donc
//! du daemon, donc de SYSTEM en exploitation - et l'equivalence avec Linux est
//! alors exacte: root la-bas, SYSTEM ici.
//!
//! # DPAPI-NG a ete envisage, et ecarte
//!
//! `NCryptProtectSecret` avec un descripteur `SID=S-1-5-18` restreindrait le
//! dechiffrement a SYSTEM de facon explicite plutot que par heritage du
//! contexte. C'est plus lisible, mais cela repose sur le service de
//! distribution de cles, pense pour un domaine, et n'apporterait rien de plus
//! sur une machine autonome - qui est le cas d'un poste client VPN. La voie de
//! WireGuard fait la meme chose avec une seule fonction et sans dependance.
//!
//! # Le nom est verifie, comme sous Linux
//!
//! `systemd-creds` authentifie le nom du credential, ce qui empeche de glisser
//! le chiffre d'autre chose dans le creneau du profil. DPAPI offre la meme
//! chose autrement: la description accompagne le chiffre, est couverte par son
//! integrite, et se relit au dechiffrement. Elle est comparee, et un chiffre qui
//! porte un autre nom est refuse. WireGuard procede exactement ainsi.

use anyhow::{Context, Result, bail};
use windows_sys::Win32::Foundation::{HLOCAL, LocalFree};
use windows_sys::Win32::Security::Cryptography::{
    CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
};

use crate::texte::{large, lire_et_liberer};

/// Recopie un blob rendu par l'API, puis efface et libere l'original.
///
/// L'effacement compte pour le dechiffrement: ce que l'API vient de rendre est
/// le profil en clair, donc une cle privee, et `LocalFree` rend la page au tas
/// sans la nettoyer. La recopie a lieu de toute facon; effacer avant de rendre
/// ne coute qu'une boucle et retire une copie du secret de la memoire.
///
/// # Securite
///
/// `blob` doit avoir ete rempli par `CryptProtectData` ou `CryptUnprotectData`,
/// qui alloue avec `LocalAlloc`.
unsafe fn recuperer(blob: &CRYPT_INTEGER_BLOB) -> Vec<u8> {
    // SAFETY: `blob` a ete rempli par CryptProtectData/CryptUnprotectData, donc
    // `pbData` pointe `cbData` octets valides et lisibles le temps de la copie.
    let vu = unsafe { std::slice::from_raw_parts(blob.pbData, blob.cbData as usize) };
    let copie = vu.to_vec();
    // SAFETY: `pbData` designe `cbData` octets qu'on peut ecrire a zero; le blob a
    // ete alloue par LocalAlloc et est libere une seule fois par LocalFree.
    unsafe {
        std::ptr::write_bytes(blob.pbData, 0, blob.cbData as usize);
        LocalFree(blob.pbData as HLOCAL);
    }
    copie
}

/// Chiffre pour le compte qui appelle.
pub fn chiffrer(clair: &[u8], nom: &str) -> Result<Vec<u8>> {
    let entree = CRYPT_INTEGER_BLOB {
        cbData: clair.len() as u32,
        pbData: clair.as_ptr() as *mut u8,
    };
    let mut sortie = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    let nom = large(nom);

    // CRYPTPROTECT_UI_FORBIDDEN et rien d'autre: pas de portee machine, pour la
    // raison ecrite en tete de module. Le drapeau interdit toute invite, ce qui
    // vaut mieux qu'un service qui attendrait une fenetre que personne ne verra.
    // SAFETY: `entree` decrit `clair` (pointeur et longueur coherents), `nom` est
    // une chaine large NUL-terminee vivante pendant l'appel, les null_mut sont les
    // parametres optionnels omis, et `sortie` recoit un blob alloue par LocalAlloc.
    let ok = unsafe {
        CryptProtectData(
            &entree,
            nom.as_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut sortie,
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error()).context("DPAPI a refuse de chiffrer");
    }
    // SAFETY: `sortie` a ete rempli par CryptProtectData (ok != 0); recuperer
    // copie ses `cbData` octets puis les efface et libere le blob une fois.
    Ok(unsafe { recuperer(&sortie) })
}

/// Dechiffre, et refuse un chiffre qui ne porte pas le nom attendu.
pub fn dechiffrer(chiffre: &[u8], nom_attendu: &str) -> Result<Vec<u8>> {
    let entree = CRYPT_INTEGER_BLOB {
        cbData: chiffre.len() as u32,
        pbData: chiffre.as_ptr() as *mut u8,
    };
    let mut sortie = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    let mut nom_lu: *mut u16 = std::ptr::null_mut();

    // SAFETY: `entree` decrit `chiffre` (pointeur et longueur coherents), `nom_lu`
    // et `sortie` sont des sorties initialisees a null, les null_mut sont les
    // parametres optionnels omis; a la reussite l'API alloue les deux par LocalAlloc.
    let ok = unsafe {
        CryptUnprotectData(
            &entree,
            &mut nom_lu,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut sortie,
        )
    };
    if ok == 0 {
        let brut = std::io::Error::last_os_error();
        bail!(
            "DPAPI a refuse d'ouvrir ce profil ({brut}).\n    \
             Un profil scelle ne s'ouvre que sur la machine et sous le compte qui \n    \
             l'ont scelle. Si le daemon l'a scelle, il faut etre SYSTEM pour le lire, \n    \
             ce qui est voulu: c'est la meme regle que sous Linux, ou seul root ouvre \n    \
             le coffre."
        );
    }

    // SAFETY: `nom_lu` a ete alloue par CryptUnprotectData (ok != 0) et pointe une
    // chaine large NUL-terminee; lire_et_liberer la lit puis la libere une fois.
    let lu = unsafe { lire_et_liberer(nom_lu) };
    // SAFETY: `sortie` a ete rempli par CryptUnprotectData; recuperer copie ses
    // `cbData` octets puis les efface et libere le blob une fois.
    let clair = unsafe { recuperer(&sortie) };

    // Apres le dechiffrement, comme WireGuard: le nom voyage avec le chiffre et
    // son integrite est couverte par DPAPI, donc le comparer ici a un sens. Ce
    // qui est refuse est le glissement - presenter le chiffre d'autre chose dans
    // le creneau du profil.
    if lu != nom_attendu {
        bail!(
            "ce chiffre porte le nom \"{lu}\" et non \"{nom_attendu}\": ce n'est pas \
             un profil Bifrost, ou il a ete mis a la place d'un autre fichier"
        );
    }
    Ok(clair)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOM: &str = "bifrost.tunnel";

    #[test]
    fn un_profil_chiffre_se_rouvre_sur_cette_machine() {
        let clair = b"private_key = \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaA=\"";
        let chiffre = chiffrer(clair, NOM).expect("DPAPI doit chiffrer");
        assert_ne!(chiffre, clair, "le chiffre ne doit pas etre le clair");

        let rouvert = dechiffrer(&chiffre, NOM).expect("DPAPI doit rouvrir");
        assert_eq!(rouvert, clair);
    }

    /// Ce que le chiffrement doit reellement cacher.
    #[test]
    fn le_chiffre_ne_laisse_rien_voir_du_clair() {
        const SECRET: &[u8] = b"private_key = \"NE-DOIT-PAS-APPARAITRE\"";
        let chiffre = chiffrer(SECRET, NOM).unwrap();
        assert!(
            !chiffre.windows(SECRET.len()).any(|f| f == SECRET),
            "le clair apparait dans le chiffre"
        );
    }

    /// Le glissement d'un chiffre etranger dans le creneau du profil.
    ///
    /// C'est la propriete que `systemd-creds` donne sous Linux en authentifiant
    /// le nom du credential. Sans elle, un chiffre parfaitement valide produit
    /// pour autre chose serait accepte comme profil.
    #[test]
    fn un_chiffre_sous_un_autre_nom_est_refuse() {
        let chiffre = chiffrer(b"autre chose", "bifrost.autre").unwrap();
        let e = dechiffrer(&chiffre, NOM).expect_err("le nom doit etre verifie");
        let dit = format!("{e:#}");
        assert!(dit.contains("bifrost.autre"), "{dit}");
        assert!(dit.contains(NOM), "{dit}");
    }

    #[test]
    fn un_chiffre_abime_est_refuse_en_disant_quoi_faire() {
        let mut chiffre = chiffrer(b"un profil", NOM).unwrap();
        let dernier = chiffre.len() - 1;
        chiffre[dernier] ^= 0xff;

        let e = dechiffrer(&chiffre, NOM).expect_err("un chiffre abime doit etre refuse");
        let dit = format!("{e:#}");
        assert!(
            dit.contains("machine") && dit.contains("compte"),
            "le message doit nommer les deux conditions: {dit}"
        );
    }
}
