//! Un secret tire du generateur du systeme.
//!
//! Le secret de l'API Clash protege une interface qui decide par ou sort le
//! trafic. Le tirer d'une source faible, ou d'un `RandomState` prevu pour
//! ensemencer des tables de hachage, ne conviendrait pas: ces sources visent
//! l'imprevisibilite face aux collisions, pas face a un attaquant local.
//!
//! On appelle donc directement le generateur du systeme, sans dependance
//! supplementaire: `/dev/urandom` sous Unix, `BCryptGenRandom` sous Windows.

/// Longueur du secret en octets avant encodage. 24 octets font 192 bits, bien
/// au-dela de ce qu'un secret de boucle locale exige, et 48 caracteres une fois
/// encode, ce qui reste lisible dans un fichier de configuration.
pub const OCTETS_DU_SECRET: usize = 24;

/// Tire un secret et le rend en hexadecimal.
pub fn secret() -> anyhow::Result<String> {
    let mut octets = [0u8; OCTETS_DU_SECRET];
    remplir(&mut octets)?;
    // Un tirage entierement nul est astronomiquement improbable, donc s'il
    // arrive c'est que le generateur n'a rien ecrit. Mieux vaut refuser que
    // poser un secret constant sur une interface de controle.
    if octets.iter().all(|o| *o == 0) {
        anyhow::bail!("le generateur du systeme a rendu un tirage nul");
    }
    Ok(octets.iter().map(|o| format!("{o:02x}")).collect())
}

/// Remplit un tampon depuis le generateur du systeme.
///
/// Expose pour les usages qui veulent des octets bruts plutot qu'une chaine:
/// l'alea d'une poignee de main TLS, par exemple, dont le `Random` et la part
/// publique de l'echange de clefs doivent etre imprevisibles pour la meme
/// raison que le secret ci-dessus.
pub fn octets(tampon: &mut [u8]) -> anyhow::Result<()> {
    remplir(tampon)
}

#[cfg(unix)]
fn remplir(tampon: &mut [u8]) -> anyhow::Result<()> {
    use std::io::Read;
    let mut f = std::fs::File::open("/dev/urandom")
        .map_err(|e| anyhow::anyhow!("ouverture de /dev/urandom: {e}"))?;
    f.read_exact(tampon)
        .map_err(|e| anyhow::anyhow!("lecture de /dev/urandom: {e}"))?;
    Ok(())
}

#[cfg(windows)]
fn remplir(tampon: &mut [u8]) -> anyhow::Result<()> {
    use windows_sys::Win32::Security::Cryptography::{
        BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom,
    };
    // Le premier argument nul, combine au drapeau, demande le generateur par
    // defaut du systeme sans avoir a ouvrir d'algorithme.
    // SAFETY: le premier argument nul avec BCRYPT_USE_SYSTEM_PREFERRED_RNG demande
    // le generateur par defaut du systeme; `tampon` recoit `tampon.len()` octets,
    // exactement la longueur passee.
    let statut = unsafe {
        BCryptGenRandom(
            std::ptr::null_mut(),
            tampon.as_mut_ptr(),
            tampon.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if statut != 0 {
        anyhow::bail!("BCryptGenRandom a echoue: NTSTATUS {statut:#x}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn le_secret_a_la_longueur_attendue_et_est_hexadecimal() {
        let s = secret().unwrap();
        assert_eq!(s.len(), OCTETS_DU_SECRET * 2);
        assert!(s.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn deux_secrets_successifs_different() {
        // Le controle le plus grossier possible, et le seul qui attraperait un
        // generateur qui n'ecrit rien dans le tampon.
        assert_ne!(secret().unwrap(), secret().unwrap());
    }

    #[test]
    fn cent_tirages_ne_produisent_aucun_doublon() {
        let mut vus: Vec<String> = (0..100).map(|_| secret().unwrap()).collect();
        vus.sort();
        let avant = vus.len();
        vus.dedup();
        assert_eq!(avant, vus.len());
    }
}
