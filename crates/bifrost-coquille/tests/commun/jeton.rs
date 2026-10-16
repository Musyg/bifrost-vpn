//! Le jeton du processus, lu et modifie par les appels du systeme. Les SID
//! se comparent par `IsWellKnownSid` et `EqualSid`, jamais en chaines, et
//! aucun ne sort de ce module.
//!
//! Inclus par `#[path = "commun/jeton.rs"]` dans `tests/eleve_ipc.rs` et
//! `tests/groupe_d_acces.rs`: deux binaires a part, parce que la pose des
//! Administrateurs comme proprietaire par defaut modifie le jeton du
//! PROCESSUS.

use std::ffi::c_void;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::Security::{
    CreateWellKnownSid, EqualSid, GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation,
    IsWellKnownSid, SECURITY_MAX_SID_SIZE, SetTokenInformation, TOKEN_ACCESS_MASK,
    TOKEN_ADJUST_DEFAULT, TOKEN_INFORMATION_CLASS, TOKEN_MANDATORY_LABEL, TOKEN_OWNER, TOKEN_QUERY,
    TOKEN_USER, TokenIntegrityLevel, TokenOwner, TokenUser, WinBuiltinAdministratorsSid,
    WinLocalSystemSid,
};
use windows_sys::Win32::System::SystemServices::{
    SECURITY_MANDATORY_HIGH_RID, SECURITY_MANDATORY_MEDIUM_RID, SECURITY_MANDATORY_SYSTEM_RID,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// Le niveau d'integrite du jeton, lu par le dernier RID de son etiquette.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Integrite {
    Moyen,
    Eleve,
    Systeme,
}

impl Integrite {
    pub fn nom(self) -> &'static str {
        match self {
            Self::Moyen => "moyen",
            Self::Eleve => "eleve",
            Self::Systeme => "systeme",
        }
    }
}

/// Le proprietaire par defaut du jeton, classe dans cet ordre.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proprietaire {
    /// Les Administrateurs, `S-1-5-32-544`.
    Administrateurs,
    /// LocalSystem, `S-1-5-18`.
    Systeme,
    /// Le compte qui execute la recette, `TokenUser`.
    Compte,
    /// Tout autre SID.
    Autre,
}

impl Proprietaire {
    pub fn nom(self) -> &'static str {
        match self {
            Self::Administrateurs => "administrateurs",
            Self::Systeme => "systeme",
            Self::Compte => "compte",
            Self::Autre => "autre",
        }
    }
}

/// Le jeton du processus, ouvert avec un acces donne, ferme quand il sort
/// de portee.
struct Jeton(HANDLE);

impl Jeton {
    fn ouvrir(acces: TOKEN_ACCESS_MASK) -> Self {
        let mut poignee: HANDLE = std::ptr::null_mut();
        // SAFETY: GetCurrentProcess rend une pseudo-poignee qui n'a pas a
        // etre fermee; `poignee` est une variable locale qui recoit, a la
        // reussite, une poignee de jeton que Drop ferme une fois.
        let ok = unsafe { OpenProcessToken(GetCurrentProcess(), acces, &mut poignee) };
        assert!(
            ok != 0,
            "OpenProcessToken: {}",
            std::io::Error::last_os_error()
        );
        Self(poignee)
    }

    /// Une classe d'information du jeton, dans un tampon dimensionne par
    /// un premier appel et aligne sur 8 octets, comme les pointeurs des
    /// structures qu'il porte.
    fn lire(&self, classe: TOKEN_INFORMATION_CLASS) -> Vec<u64> {
        lire_le_jeton(self.0, classe)
    }
}

impl Drop for Jeton {
    fn drop(&mut self) {
        // SAFETY: la poignee a ete ouverte par OpenProcessToken et n'est
        // fermee qu'ici, une fois.
        unsafe { CloseHandle(self.0) };
    }
}

/// Une classe d'information du jeton `poignee`, ouvert avec `TOKEN_QUERY`,
/// dans un tampon dimensionne par un premier appel et aligne sur 8 octets.
pub fn lire_le_jeton(poignee: HANDLE, classe: TOKEN_INFORMATION_CLASS) -> Vec<u64> {
    let mut taille = 0u32;
    // SAFETY: la poignee est un jeton ouvert avec TOKEN_QUERY; un tampon nul
    // de taille zero ne demande que la taille requise, ecrite dans `taille`,
    // une variable locale.
    unsafe { GetTokenInformation(poignee, classe, std::ptr::null_mut(), 0, &mut taille) };
    assert!(
        taille > 0,
        "GetTokenInformation({classe}), taille: {}",
        std::io::Error::last_os_error()
    );
    let mut tampon = vec![0u64; (taille as usize).div_ceil(8)];
    // SAFETY: `tampon` fait au moins `taille` octets, la taille rendue par
    // l'appel precedent, et `taille` decrit sa capacite.
    let ok = unsafe {
        GetTokenInformation(
            poignee,
            classe,
            tampon.as_mut_ptr().cast::<c_void>(),
            taille,
            &mut taille,
        )
    };
    assert!(
        ok != 0,
        "GetTokenInformation({classe}): {}",
        std::io::Error::last_os_error()
    );
    tampon
}

/// Le niveau d'integrite du jeton du processus. Un RID hors des trois
/// classes est un rouge: la recette ne sait pas en tirer de controle.
pub fn integrite() -> Integrite {
    let etiquette = Jeton::ouvrir(TOKEN_QUERY).lire(TokenIntegrityLevel);
    // SAFETY: `etiquette`, aligne sur 8 octets, a ete rempli par
    // GetTokenInformation(TokenIntegrityLevel): il commence par un
    // TOKEN_MANDATORY_LABEL, dont le SID pointe dans ce meme tampon.
    let sid = unsafe {
        (*etiquette.as_ptr().cast::<TOKEN_MANDATORY_LABEL>())
            .Label
            .Sid
    };
    // SAFETY: `sid` est un SID valide, vivant tant que `etiquette` l'est;
    // le pointeur rendu designe son compte de sous-autorites, lu aussitot.
    let sous_autorites = unsafe { *GetSidSubAuthorityCount(sid) };
    assert!(
        sous_autorites > 0,
        "etiquette d'integrite sans sous-autorite"
    );
    // SAFETY: meme SID, toujours vivant; l'indice est le dernier,
    // inferieur au compte lu, et le pointeur rendu est lu aussitot.
    let rid = unsafe { *GetSidSubAuthority(sid, u32::from(sous_autorites) - 1) };
    match i32::try_from(rid) {
        Ok(SECURITY_MANDATORY_MEDIUM_RID) => Integrite::Moyen,
        Ok(SECURITY_MANDATORY_HIGH_RID) => Integrite::Eleve,
        Ok(SECURITY_MANDATORY_SYSTEM_RID) => Integrite::Systeme,
        _ => panic!("niveau d'integrite que la recette ne sait pas classer: {rid:#x}"),
    }
}

/// Le proprietaire par defaut du jeton du processus, classe par le
/// systeme: Administrateurs, puis LocalSystem, puis le compte, sinon
/// autre.
pub fn proprietaire_par_defaut() -> Proprietaire {
    let jeton = Jeton::ouvrir(TOKEN_QUERY);
    let proprietaire = jeton.lire(TokenOwner);
    let utilisateur = jeton.lire(TokenUser);
    // SAFETY: `proprietaire`, aligne sur 8 octets, a ete rempli par
    // GetTokenInformation(TokenOwner): il commence par un TOKEN_OWNER,
    // dont le SID pointe dans ce meme tampon.
    let sid = unsafe { (*proprietaire.as_ptr().cast::<TOKEN_OWNER>()).Owner };
    // SAFETY: de meme pour `utilisateur`, rempli pour TokenUser: un
    // TOKEN_USER en tete, dont le SID pointe dans ce meme tampon.
    let compte = unsafe { (*utilisateur.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    // SAFETY: `sid` et `compte` sont des SID valides, qui vivent dans les
    // deux tampons jusqu'a la fin de la fonction; les trois appels ne
    // font que les lire.
    unsafe {
        if IsWellKnownSid(sid, WinBuiltinAdministratorsSid) != 0 {
            Proprietaire::Administrateurs
        } else if IsWellKnownSid(sid, WinLocalSystemSid) != 0 {
            Proprietaire::Systeme
        } else if EqualSid(sid, compte) != 0 {
            Proprietaire::Compte
        } else {
            Proprietaire::Autre
        }
    }
}

/// Pose les Administrateurs comme proprietaire par defaut du jeton du
/// processus, et rend l'erreur du systeme telle quelle.
pub fn poser_les_administrateurs() -> std::io::Result<()> {
    let jeton = Jeton::ouvrir(TOKEN_QUERY | TOKEN_ADJUST_DEFAULT);
    let mut administrateurs = vec![0u64; (SECURITY_MAX_SID_SIZE as usize).div_ceil(8)];
    let mut taille = SECURITY_MAX_SID_SIZE;
    // SAFETY: le tampon fait au moins SECURITY_MAX_SID_SIZE octets, et
    // `taille` le dit; le SID des Administrateurs ne demande aucun SID de
    // domaine.
    let ok = unsafe {
        CreateWellKnownSid(
            WinBuiltinAdministratorsSid,
            std::ptr::null_mut(),
            administrateurs.as_mut_ptr().cast::<c_void>(),
            &mut taille,
        )
    };
    assert!(
        ok != 0,
        "CreateWellKnownSid: {}",
        std::io::Error::last_os_error()
    );
    let proprietaire = TOKEN_OWNER {
        Owner: administrateurs.as_mut_ptr().cast::<c_void>(),
    };
    // SAFETY: la poignee est ouverte avec TOKEN_ADJUST_DEFAULT;
    // `proprietaire` est un TOKEN_OWNER de la taille passee, et le SID
    // qu'il designe, `administrateurs`, vit jusqu'a la fin de l'appel.
    let ok = unsafe {
        SetTokenInformation(
            jeton.0,
            TokenOwner,
            (&proprietaire as *const TOKEN_OWNER).cast::<c_void>(),
            std::mem::size_of::<TOKEN_OWNER>() as u32,
        )
    };
    if ok != 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}
