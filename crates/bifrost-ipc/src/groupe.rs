//! Le groupe d'acces du canal, sous Windows.
//!
//! Le pipe du daemon n'admet que SYSTEM et les Administrateurs. Un groupe
//! d'acces y ajoute UNE ACE: ses membres, sans elevation, ouvrent le canal en
//! lecture et en ecriture, et n'y peuvent rien d'autre (le masque et sa
//! mesure sont dans `transport`, `MASQUE_DU_GROUPE`). C'est le pendant du
//! groupe `bifrost` du socket Linux, avec la meme regle: un membre n'a que
//! trois commandes, `status`, `connect-stored` et `disconnect`
//! (`crate::appelant`).
//!
//! # Qui peut etre groupe d'acces
//!
//! Un seul genre de compte: un groupe LOCAL de cette machine, cree par un
//! administrateur. Le systeme le dit en trois faits, tous lus sur ce qu'il
//! rend, jamais sur la chaine tapee par l'administrateur:
//!
//! - la forme CANONIQUE du SID, telle que `ConvertSidToStringSidW` la rend,
//!   est `S-1-5-21-a-b-c-RID` avec `RID >= PREMIER_RID_CREE`: les comptes et
//!   groupes predefinis (`S-1-1-0` Everyone, `S-1-5-11` Authenticated Users,
//!   `S-1-5-32-545` Users, les identites d'ouverture de session, les paquets
//!   d'application, les RID predefinis d'un domaine) n'ont pas cette forme;
//! - le domaine de ce SID est celui des comptes de cette machine, que rend la
//!   LSA, compare par `EqualSid`: un groupe d'un domaine ne s'administre pas
//!   ici;
//! - le type de compte que rend le systeme est `SidTypeAlias`, celui d'un
//!   groupe local: un utilisateur n'est pas un groupe.
//!
//! Une liste blanche de forme et non une liste noire de valeurs: une liste
//! noire compare des chaines que le systeme ne compare pas, et ne connait
//! jamais tous les comptes qui mettent << tout le monde >> dans le public du
//! pipe. Le jugement porte sur la forme rendue, parce que le systeme lit
//! `S-1-1-00`, `s-1-1-0` ou `S-1-0x1-0` comme `S-1-1-0` (mesure du
//! 16/10/2026 sur dev-windows).
//!
//! Un [`GroupeDAcces`] ne se construit que par ce jugement: un groupe refuse
//! ne peut pas atteindre le descripteur du pipe.

use std::ffi::c_void;
use std::fmt;

use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, GetLastError, LocalFree};
use windows_sys::Win32::Security::Authentication::Identity::{
    LSA_HANDLE, LSA_OBJECT_ATTRIBUTES, LsaClose, LsaFreeMemory, LsaNtStatusToWinError,
    LsaOpenPolicy, LsaQueryInformationPolicy, POLICY_ACCOUNT_DOMAIN_INFO,
    POLICY_VIEW_LOCAL_INFORMATION, PolicyAccountDomainInformation,
};
use windows_sys::Win32::Security::Authorization::{ConvertSidToStringSidW, ConvertStringSidToSidW};
use windows_sys::Win32::Security::{
    CopySid, EqualSid, GetLengthSid, GetWindowsAccountDomainSid, IsValidSid, LookupAccountNameW,
    LookupAccountSidW, PSID, SECURITY_MAX_SID_SIZE, SID_NAME_USE, SidTypeAlias,
};

/// Le RID a partir duquel Windows numerote les comptes et groupes crees par
/// un administrateur; en dessous, les comptes predefinis d'un domaine ou
/// d'une machine (Administrator 500, Guest 501, Domain Users 513...).
pub const PREMIER_RID_CREE: u32 = 1000;

/// Pourquoi un groupe d'acces n'a pas ete retenu. Chaque message nomme la
/// designation recue et, des qu'il est lu, le SID sous sa forme canonique.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ErreurGroupe {
    /// Le systeme ne connait aucun compte sous cette designation.
    #[error("groupe d'acces {nom:?} introuvable sur cette machine ({cause})")]
    Introuvable { nom: String, cause: String },
    /// Le SID n'est pas celui d'un groupe cree localement par un
    /// administrateur.
    #[error(
        "groupe d'acces {nom:?} refuse: il designe {sid}, qui n'est pas un groupe cree \
         localement par un administrateur (S-1-5-21-a-b-c-RID, RID >= 1000, dans le \
         domaine des comptes de cette machine); un compte ou un groupe predefini ne \
         recoit jamais l'acces au canal"
    )]
    NonAdmissible { nom: String, sid: String },
    /// Le SID a la forme admise, et ce n'est pas un groupe local.
    #[error(
        "groupe d'acces {nom:?} refuse: {sid} n'est pas un groupe local (type de compte \
         {type_de_compte}); seul un groupe local recoit l'acces au canal"
    )]
    PasUnGroupeLocal {
        nom: String,
        sid: String,
        type_de_compte: i32,
    },
    /// Un appel du systeme a echoue.
    #[error("groupe d'acces {nom:?}: {appel} a echoue (erreur Win32 {code})")]
    Systeme {
        nom: String,
        appel: &'static str,
        code: u32,
    },
}

/// Un groupe d'acces retenu: le SID que le systeme a rendu, et sa forme
/// textuelle canonique, la seule qui entre dans le descripteur du pipe.
#[derive(Clone, PartialEq, Eq)]
pub struct GroupeDAcces {
    sid: Vec<u8>,
    canonique: String,
}

impl fmt::Debug for GroupeDAcces {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("GroupeDAcces")
            .field(&self.canonique)
            .finish()
    }
}

impl GroupeDAcces {
    /// Resout la designation d'un groupe local et le juge.
    ///
    /// La designation est un nom de groupe (`Bifrost`), resolu par
    /// `LookupAccountNameW`, sans egard a la casse comme tout nom de compte
    /// Windows; ou un SID textuel (`S-1-...`, `s-1-...`), converti par
    /// `ConvertStringSidToSidW` puis cherche par `LookupAccountSidW`, qui
    /// rend son type et dit s'il existe. Dans les deux cas, ce qui est juge
    /// puis retenu est ce que le systeme a rendu, jamais la chaine recue.
    pub fn resoudre(designation: &str) -> Result<Self, ErreurGroupe> {
        let (sid, type_de_compte) = sid_de_la_designation(designation)?;
        let groupe = juger_le_sid(designation, sid)?;
        if type_de_compte != SidTypeAlias {
            return Err(ErreurGroupe::PasUnGroupeLocal {
                nom: designation.to_owned(),
                sid: groupe.canonique,
                type_de_compte,
            });
        }
        Ok(groupe)
    }

    /// La forme textuelle canonique du SID, telle que le systeme la rend.
    pub fn sid(&self) -> &str {
        &self.canonique
    }

    /// Le SID en binaire, tel que le systeme l'a rendu: pour `EqualSid`.
    #[cfg(test)]
    pub(crate) fn sid_binaire(&self) -> &[u8] {
        &self.sid
    }

    /// Le compte qui execute la recette, pour une recette MIROIR: juge par
    /// la meme regle de forme et de domaine, sans la regle du type de compte
    /// (c'est un utilisateur). C'est le seul SID qu'un compte non eleve
    /// porte et dont il peut mesurer l'ACE, sans creer de groupe sur la
    /// machine: une mesure de poste de developpement.
    ///
    /// Rend `None` apres avoir imprime `SKIPPED <recette>: <raison>` quand
    /// la premisse du miroir manque, c'est-a-dire quand ce compte est un
    /// compte predefini de la machine (le compte du runner de la CI en est
    /// un); la, c'est la recette du runner jetable (`bifrost-coquille`,
    /// `groupe_d_acces`) qui mesure, sur un vrai groupe. Toute autre issue
    /// (erreur du systeme, compte hors du domaine de la machine, compte de
    /// la classe d'un compte cree que le jugement refuse) PANIQUE: sur par
    /// defaut, jamais une abstention large.
    #[cfg(test)]
    pub(crate) fn compte_pour_le_miroir(recette: &str) -> Option<Self> {
        let lu = classe_du_compte_courant();
        let premisse = juger_la_premisse(lu.as_ref().map(|(_, classe)| *classe));
        match premisse {
            Premisse::Abstention(raison) => {
                println!("SKIPPED {recette}: {raison}");
                None
            }
            Premisse::Tenue => {
                let (sid, _) = lu.expect("une premisse tenue vient d'une classe lue");
                Some(juger_le_sid("compte courant", sid).unwrap_or_else(|e| {
                    panic!("compte des recettes de la classe d'un compte cree, refuse: {e}")
                }))
            }
        }
    }
}

/// La regle de forme, sur la forme CANONIQUE rendue par le systeme:
/// `S-1-5-21-a-b-c-RID`, exactement quatre champs decimaux apres le prefixe,
/// et `RID >= PREMIER_RID_CREE`. Appelee sur une chaine tapee, elle jugerait
/// une forme que le systeme ne compare pas.
pub(crate) fn forme_admissible(canonique: &str) -> bool {
    let Some(reste) = canonique.strip_prefix("S-1-5-21-") else {
        return false;
    };
    let champs: Vec<&str> = reste.split('-').collect();
    champs.len() == 4
        && champs
            .iter()
            .all(|c| !c.is_empty() && c.bytes().all(|b| b.is_ascii_digit()))
        && champs[3]
            .parse::<u32>()
            .is_ok_and(|rid| rid >= PREMIER_RID_CREE)
}

/// Le jugement de forme et de domaine d'un SID rendu par le systeme. Rend le
/// groupe, sous la forme canonique de ce SID.
fn juger_le_sid(designation: &str, sid: Vec<u8>) -> Result<GroupeDAcces, ErreurGroupe> {
    let canonique = texte_du_sid(designation, &sid)?;
    if !forme_admissible(&canonique)
        || !du_domaine_de_la_machine(&sid, &domaine_de_la_machine(designation)?)
    {
        return Err(ErreurGroupe::NonAdmissible {
            nom: designation.to_owned(),
            sid: canonique,
        });
    }
    Ok(GroupeDAcces { sid, canonique })
}

/// Le dernier code d'erreur du fil.
fn derniere_erreur() -> u32 {
    // SAFETY: GetLastError ne lit que l'etat du fil courant.
    unsafe { GetLastError() }
}

fn erreur_systeme(designation: &str, appel: &'static str, code: u32) -> ErreurGroupe {
    ErreurGroupe::Systeme {
        nom: designation.to_owned(),
        appel,
        code,
    }
}

/// Une chaine UTF-16 du systeme, terminee par un zero, copiee.
///
/// # Safety
///
/// `texte` pointe sur une chaine UTF-16 terminee par un zero, vivante pendant
/// l'appel.
unsafe fn copier_texte(texte: *const u16) -> String {
    let mut longueur = 0usize;
    // SAFETY: la chaine est terminee par un zero (contrat de l'appelant): la
    // lecture s'arrete sur lui.
    while unsafe { *texte.add(longueur) } != 0 {
        longueur += 1;
    }
    // SAFETY: les `longueur` unites qui precedent le zero sont lisibles.
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(texte, longueur) })
}

/// La forme textuelle canonique d'un SID binaire, rendue par le systeme.
fn texte_du_sid(designation: &str, sid: &[u8]) -> Result<String, ErreurGroupe> {
    // SAFETY: `sid` est un SID valide (rendu par le systeme et verifie par
    // IsValidSid a sa copie), vivant pendant l'appel.
    unsafe { forme_canonique(sid.as_ptr() as PSID) }
        .map_err(|code| erreur_systeme(designation, "ConvertSidToStringSidW", code))
}

/// La forme textuelle canonique d'un SID, telle que `ConvertSidToStringSidW`
/// la rend, ou le code d'erreur du systeme. Une seule conversion pour le
/// jugement du groupe d'acces et pour le journal du transport, qui nomme le
/// client d'une requete par le SID de son jeton (`appelant::identifier`).
///
/// # Safety
///
/// `sid` pointe sur un SID valide, vivant pendant l'appel.
pub(crate) unsafe fn forme_canonique(sid: PSID) -> Result<String, u32> {
    let mut texte: windows_sys::core::PWSTR = std::ptr::null_mut();
    // SAFETY: `sid` est un SID valide (contrat de l'appelant); `texte` recoit
    // une allocation du systeme, liberee par LocalFree apres copie.
    let ok = unsafe { ConvertSidToStringSidW(sid, &mut texte) };
    if ok == 0 || texte.is_null() {
        return Err(derniere_erreur());
    }
    // SAFETY: le systeme a rendu une chaine terminee par un zero, libree
    // juste apres la copie et plus jamais lue.
    let canonique = unsafe { copier_texte(texte) };
    // SAFETY: `texte` a ete alloue par ConvertSidToStringSidW.
    unsafe { LocalFree(texte.cast()) };
    Ok(canonique)
}

/// Copie un SID que le systeme a rendu, apres avoir verifie qu'il est valide.
///
/// # Safety
///
/// `sid` pointe sur une zone lisible rendue par le systeme comme SID.
unsafe fn copier_sid(designation: &str, sid: PSID) -> Result<Vec<u8>, ErreurGroupe> {
    // SAFETY: IsValidSid lit le SID; le contrat de l'appelant garantit la
    // zone.
    if unsafe { IsValidSid(sid) } == 0 {
        return Err(erreur_systeme(designation, "IsValidSid", derniere_erreur()));
    }
    // SAFETY: le SID est valide, sa longueur se lit dans son en-tete.
    let longueur = unsafe { GetLengthSid(sid) };
    let mut copie = vec![0u8; longueur as usize];
    // SAFETY: la copie fait exactement la longueur du SID source, valide.
    if unsafe { CopySid(longueur, copie.as_mut_ptr() as PSID, sid) } == 0 {
        return Err(erreur_systeme(designation, "CopySid", derniere_erreur()));
    }
    Ok(copie)
}

/// Le SID et le type de compte que le systeme rend pour la designation.
fn sid_de_la_designation(designation: &str) -> Result<(Vec<u8>, SID_NAME_USE), ErreurGroupe> {
    // `get` et non un indice direct: un nom de groupe peut porter un
    // caractere de plusieurs octets a cet endroit.
    if designation
        .get(..4)
        .is_some_and(|p| p.eq_ignore_ascii_case("S-1-"))
    {
        return sid_textuel(designation);
    }
    sid_du_nom(designation)
}

/// Une designation `S-1-...`: convertie, puis cherchee pour son type.
fn sid_textuel(designation: &str) -> Result<(Vec<u8>, SID_NAME_USE), ErreurGroupe> {
    let large: Vec<u16> = designation.encode_utf16().chain(Some(0)).collect();
    let mut brut: PSID = std::ptr::null_mut();
    // SAFETY: `large` est une chaine UTF-16 terminee par un zero; `brut`
    // recoit une allocation du systeme, liberee par LocalFree ci-dessous.
    let ok = unsafe { ConvertStringSidToSidW(large.as_ptr(), &mut brut) };
    if ok == 0 || brut.is_null() {
        return Err(ErreurGroupe::Introuvable {
            nom: designation.to_owned(),
            cause: format!(
                "SID mal forme, ConvertStringSidToSidW: erreur Win32 {}",
                derniere_erreur()
            ),
        });
    }
    // SAFETY: `brut` est le SID que le systeme vient de rendre.
    let copie = unsafe { copier_sid(designation, brut) };
    // SAFETY: `brut` a ete alloue par ConvertStringSidToSidW et n'est plus
    // lu: la copie est faite.
    unsafe { LocalFree(brut) };
    let sid = copie?;

    let mut taille_nom = 0u32;
    let mut taille_domaine = 0u32;
    let mut type_de_compte: SID_NAME_USE = 0;
    // SAFETY: sonde de taille: tampons nuls de longueur zero, comme l'API le
    // prevoit; `sid` est valide.
    let ok = unsafe {
        LookupAccountSidW(
            std::ptr::null(),
            sid.as_ptr() as PSID,
            std::ptr::null_mut(),
            &mut taille_nom,
            std::ptr::null_mut(),
            &mut taille_domaine,
            &mut type_de_compte,
        )
    };
    let code = derniere_erreur();
    if ok == 0 && code != ERROR_INSUFFICIENT_BUFFER {
        return Err(ErreurGroupe::Introuvable {
            nom: designation.to_owned(),
            cause: format!("LookupAccountSidW: erreur Win32 {code}"),
        });
    }
    let mut nom = vec![0u16; taille_nom.max(1) as usize];
    let mut domaine = vec![0u16; taille_domaine.max(1) as usize];
    // SAFETY: les tampons sont dimensionnes par la sonde et vivent pendant
    // l'appel; `sid` est valide.
    let ok = unsafe {
        LookupAccountSidW(
            std::ptr::null(),
            sid.as_ptr() as PSID,
            nom.as_mut_ptr(),
            &mut taille_nom,
            domaine.as_mut_ptr(),
            &mut taille_domaine,
            &mut type_de_compte,
        )
    };
    if ok == 0 {
        return Err(ErreurGroupe::Introuvable {
            nom: designation.to_owned(),
            cause: format!("LookupAccountSidW: erreur Win32 {}", derniere_erreur()),
        });
    }
    Ok((sid, type_de_compte))
}

/// Un nom de compte: resolu par `LookupAccountNameW`.
fn sid_du_nom(designation: &str) -> Result<(Vec<u8>, SID_NAME_USE), ErreurGroupe> {
    // Un nom vide designe pour `LookupAccountNameW` le domaine BUILTIN
    // (mesure du 16/10/2026): ce n'est le nom d'aucun groupe.
    if designation.trim().is_empty() {
        return Err(ErreurGroupe::Introuvable {
            nom: designation.to_owned(),
            cause: "nom vide".to_owned(),
        });
    }
    let large: Vec<u16> = designation.encode_utf16().chain(Some(0)).collect();
    let mut taille_sid = 0u32;
    let mut taille_domaine = 0u32;
    let mut type_de_compte: SID_NAME_USE = 0;
    // SAFETY: sonde de taille: tampons nuls de longueur zero, comme l'API le
    // prevoit; `large` est une chaine UTF-16 terminee par un zero.
    let ok = unsafe {
        LookupAccountNameW(
            std::ptr::null(),
            large.as_ptr(),
            std::ptr::null_mut(),
            &mut taille_sid,
            std::ptr::null_mut(),
            &mut taille_domaine,
            &mut type_de_compte,
        )
    };
    let code = derniere_erreur();
    if ok == 0 && (code != ERROR_INSUFFICIENT_BUFFER || taille_sid == 0) {
        return Err(ErreurGroupe::Introuvable {
            nom: designation.to_owned(),
            cause: format!("LookupAccountNameW: erreur Win32 {code}"),
        });
    }
    let mut tampon = vec![0u8; (taille_sid as usize).max(SECURITY_MAX_SID_SIZE as usize)];
    let mut taille_sid = tampon.len() as u32;
    let mut domaine = vec![0u16; taille_domaine.max(1) as usize];
    // SAFETY: les tampons sont dimensionnes par la sonde (le SID au moins a
    // SECURITY_MAX_SID_SIZE) et vivent pendant l'appel.
    let ok = unsafe {
        LookupAccountNameW(
            std::ptr::null(),
            large.as_ptr(),
            tampon.as_mut_ptr() as PSID,
            &mut taille_sid,
            domaine.as_mut_ptr(),
            &mut taille_domaine,
            &mut type_de_compte,
        )
    };
    if ok == 0 {
        return Err(ErreurGroupe::Introuvable {
            nom: designation.to_owned(),
            cause: format!("LookupAccountNameW: erreur Win32 {}", derniere_erreur()),
        });
    }
    // SAFETY: le systeme vient d'ecrire un SID dans `tampon`.
    let sid = unsafe { copier_sid(designation, tampon.as_mut_ptr() as PSID) }?;
    Ok((sid, type_de_compte))
}

/// Le SID du domaine des comptes de cette machine, tel que la LSA le rend
/// (`PolicyAccountDomainInformation`): celui des comptes et groupes locaux.
fn domaine_de_la_machine(designation: &str) -> Result<Vec<u8>, ErreurGroupe> {
    let attributs = LSA_OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<LSA_OBJECT_ATTRIBUTES>() as u32,
        ..Default::default()
    };
    let mut politique: LSA_HANDLE = 0;
    // SAFETY: systeme local (nom nul), attributs mis a zero hors de leur
    // longueur comme l'API l'exige; `politique` recoit une poignee fermee par
    // LsaClose ci-dessous.
    let statut = unsafe {
        LsaOpenPolicy(
            std::ptr::null(),
            &attributs,
            POLICY_VIEW_LOCAL_INFORMATION as u32,
            &mut politique,
        )
    };
    if statut != 0 {
        // SAFETY: conversion pure d'un code de statut.
        let code = unsafe { LsaNtStatusToWinError(statut) };
        return Err(erreur_systeme(designation, "LsaOpenPolicy", code));
    }
    let mut info: *mut c_void = std::ptr::null_mut();
    // SAFETY: la poignee est ouverte avec POLICY_VIEW_LOCAL_INFORMATION;
    // `info` recoit une allocation de la LSA, liberee par LsaFreeMemory.
    let statut =
        unsafe { LsaQueryInformationPolicy(politique, PolicyAccountDomainInformation, &mut info) };
    let resultat = if statut != 0 || info.is_null() {
        // SAFETY: conversion pure d'un code de statut.
        let code = unsafe { LsaNtStatusToWinError(statut) };
        Err(erreur_systeme(
            designation,
            "LsaQueryInformationPolicy",
            code,
        ))
    } else {
        // SAFETY: la LSA a rendu un POLICY_ACCOUNT_DOMAIN_INFO dont le SID
        // pointe dans la meme allocation, encore vivante.
        let domaine = unsafe { (*(info as *const POLICY_ACCOUNT_DOMAIN_INFO)).DomainSid };
        // SAFETY: le SID du domaine vit dans l'allocation de la LSA.
        let copie = unsafe { copier_sid(designation, domaine) };
        // SAFETY: `info` a ete alloue par LsaQueryInformationPolicy et n'est
        // plus lu apres la copie.
        unsafe { LsaFreeMemory(info) };
        copie
    };
    // SAFETY: la poignee vient d'un LsaOpenPolicy reussi, fermee une fois.
    unsafe { LsaClose(politique) };
    resultat
}

/// Le domaine de `sid` est-il celui des comptes de cette machine? Compare par
/// `EqualSid`, sur le domaine que `GetWindowsAccountDomainSid` tire du SID.
/// Un SID qui n'est pas celui d'un compte (un groupe integre, une identite
/// d'ouverture de session) n'a pas de domaine de comptes: faux.
fn du_domaine_de_la_machine(sid: &[u8], machine: &[u8]) -> bool {
    let mut domaine = vec![0u8; SECURITY_MAX_SID_SIZE as usize];
    let mut taille = domaine.len() as u32;
    // SAFETY: `sid` est valide; le tampon fait SECURITY_MAX_SID_SIZE octets,
    // sa taille est passee.
    let ok = unsafe {
        GetWindowsAccountDomainSid(
            sid.as_ptr() as PSID,
            domaine.as_mut_ptr() as PSID,
            &mut taille,
        )
    };
    if ok == 0 {
        return false;
    }
    // SAFETY: deux SID valides, lus seulement.
    unsafe { EqualSid(domaine.as_ptr() as PSID, machine.as_ptr() as PSID) != 0 }
}

/// Le SID du compte qui execute ce processus, en binaire.
#[cfg(test)]
pub(crate) fn sid_du_compte_courant() -> Result<Vec<u8>, ErreurGroupe> {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let designation = "compte courant";
    let mut jeton: HANDLE = std::ptr::null_mut();
    // SAFETY: GetCurrentProcess rend une pseudo-poignee toujours valide;
    // `jeton` recoit une poignee fermee ci-dessous.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut jeton) } == 0 {
        return Err(erreur_systeme(
            designation,
            "OpenProcessToken",
            derniere_erreur(),
        ));
    }
    let mut taille = 0u32;
    // SAFETY: sonde de taille, tampon nul de longueur zero.
    unsafe { GetTokenInformation(jeton, TokenUser, std::ptr::null_mut(), 0, &mut taille) };
    let mut tampon = vec![0u64; (taille as usize).div_ceil(8)];
    // SAFETY: le tampon, aligne sur 8 octets, fait au moins `taille` octets.
    let ok = unsafe {
        GetTokenInformation(
            jeton,
            TokenUser,
            tampon.as_mut_ptr().cast(),
            taille,
            &mut taille,
        )
    };
    let resultat = if ok == 0 {
        Err(erreur_systeme(
            designation,
            "GetTokenInformation",
            derniere_erreur(),
        ))
    } else {
        // SAFETY: le tampon commence par un TOKEN_USER dont le SID pointe dans
        // ce meme tampon, vivant jusqu'a la copie.
        let sid = unsafe { (*tampon.as_ptr().cast::<TOKEN_USER>()).User.Sid };
        // SAFETY: SID rendu par le systeme, dans le tampon.
        unsafe { copier_sid(designation, sid) }
    };
    // SAFETY: la poignee vient d'un OpenProcessToken reussi, fermee une fois.
    unsafe { CloseHandle(jeton) };
    resultat
}

/// La classe d'un SID pour la premisse des recettes miroir, lue sur la forme
/// CANONIQUE que le systeme rend, contre le domaine des comptes de la machine
/// sous sa forme canonique aussi.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClasseDeCompte {
    /// Du domaine de la machine, RID sous `PREMIER_RID_CREE`: un compte ou un
    /// groupe predefini (l'administrateur integre, 500; l'invite, 501).
    Predefini,
    /// Du domaine de la machine, RID a partir de `PREMIER_RID_CREE`: un
    /// compte ou un groupe cree par un administrateur.
    Cree,
    /// Ni l'un ni l'autre: un autre domaine, une autorite predefinie, une
    /// forme qui n'est pas canonique.
    Autre,
}

/// Classe une forme canonique: `<domaine>-<RID>`, le RID decimal sans zero de
/// tete, et rien d'autre; le domaine, de la forme `S-1-5-21-a-b-c`, compare en
/// entier.
#[cfg(test)]
pub(crate) fn classer_la_forme(canonique: &str, domaine: &str) -> ClasseDeCompte {
    if !domaine.starts_with("S-1-5-21-") {
        return ClasseDeCompte::Autre;
    }
    let Some(rid) = canonique
        .strip_prefix(domaine)
        .and_then(|reste| reste.strip_prefix('-'))
    else {
        return ClasseDeCompte::Autre;
    };
    if rid.is_empty()
        || !rid.bytes().all(|b| b.is_ascii_digit())
        || (rid.len() > 1 && rid.starts_with('0'))
    {
        return ClasseDeCompte::Autre;
    }
    match rid.parse::<u32>() {
        Ok(rid) if rid >= PREMIER_RID_CREE => ClasseDeCompte::Cree,
        Ok(_) => ClasseDeCompte::Predefini,
        Err(_) => ClasseDeCompte::Autre,
    }
}

/// La raison d'abstention des recettes miroir quand le compte des recettes
/// est un compte predefini de la machine (sur le runner de la CI, le compte
/// qui lance les recettes est l'administrateur integre). Une seule, partagee
/// par les sept, sans chiffre ni chemin: `ci/abstentions-attendues-windows.txt`
/// la porte sous cette forme exacte, et une garde des recettes le verifie.
#[cfg(test)]
pub(crate) const RAISON_COMPTE_PREDEFINI: &str = "le compte des recettes est un compte \
    predefini de la machine, pas un compte cree par un administrateur: la recette \
    miroir ne le mesure pas";

/// La raison des deux miroirs qui mesurent l'ouverture du pipe par l'ACE du
/// groupe seule, quand les Administrateurs sont actifs dans le jeton des
/// recettes: leur ACE `(A;;GA;;;BA)` du descripteur ouvre tout, l'ACE du
/// groupe ne s'isole pas. Jugee APRES la premiere: sur le runner, c'est la
/// premiere qui parle.
#[cfg(test)]
pub(crate) const RAISON_ADMINISTRATEURS_ACTIFS: &str = "les Administrateurs sont actifs \
    dans le jeton des recettes et leur ACE ouvre tout le pipe: la recette miroir n'y \
    isole pas l'ACE du groupe";

/// Ce que la premisse du miroir donne: la mesure, ou une abstention nommee.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Premisse {
    Tenue,
    Abstention(&'static str),
}

/// Juge la premisse du miroir d'apres la classe du compte des recettes: un
/// compte cree la tient; un compte predefini vaut l'abstention nommee; une
/// classe illisible (erreur du systeme) et toute autre forme PANIQUENT. Une
/// fonction a part, sans appel au systeme, pour que la regle << sur par
/// defaut >> se mesure seule.
#[cfg(test)]
pub(crate) fn juger_la_premisse(classe: Result<ClasseDeCompte, &ErreurGroupe>) -> Premisse {
    match classe {
        Ok(ClasseDeCompte::Cree) => Premisse::Tenue,
        Ok(ClasseDeCompte::Predefini) => Premisse::Abstention(RAISON_COMPTE_PREDEFINI),
        Ok(ClasseDeCompte::Autre) => panic!(
            "le compte des recettes n'est ni un compte cree ni un compte predefini de la \
             machine: la recette miroir ne sait pas le mesurer"
        ),
        Err(e) => panic!("la classe du compte des recettes ne se lit pas: {e}"),
    }
}

/// Le SID du compte des recettes et sa classe, l'un et l'autre lus sur ce que
/// le systeme rend: la forme canonique du compte et celle du domaine de la
/// machine.
#[cfg(test)]
fn classe_du_compte_courant() -> Result<(Vec<u8>, ClasseDeCompte), ErreurGroupe> {
    let designation = "compte courant";
    let sid = sid_du_compte_courant()?;
    let canonique = texte_du_sid(designation, &sid)?;
    let domaine = texte_du_sid(designation, &domaine_de_la_machine(designation)?)?;
    let classe = classer_la_forme(&canonique, &domaine);
    Ok((sid, classe))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// La regle de forme, sur des formes canoniques: seul un compte de
    /// domaine ou de machine cree par un administrateur passe.
    #[test]
    fn seule_la_forme_d_un_compte_cree_passe() {
        for admis in [
            "S-1-5-21-1-2-3-1000",
            "S-1-5-21-1-2-3-1001",
            "S-1-5-21-1111111111-2222222222-3333333333-4294967295",
        ] {
            assert!(forme_admissible(admis), "{admis} doit passer");
        }
        for refuse in [
            // Les comptes et groupes predefinis, et des identites larges.
            "S-1-1-0",
            "S-1-2-0",
            "S-1-2-1",
            "S-1-5-2",
            "S-1-5-4",
            "S-1-5-7",
            "S-1-5-11",
            "S-1-5-15",
            "S-1-5-18",
            "S-1-5-32-544",
            "S-1-5-32-545",
            "S-1-5-32-555",
            "S-1-5-64-10",
            "S-1-5-113",
            "S-1-15-2-1",
            "S-1-18-1",
            // Les RID predefinis d'un domaine ou d'une machine.
            "S-1-5-21-1-2-3-500",
            "S-1-5-21-1-2-3-501",
            "S-1-5-21-1-2-3-513",
            "S-1-5-21-1-2-3-999",
            // Autant de champs qu'il faut, pas un de plus ni de moins.
            "S-1-5-21-1-2-1001",
            "S-1-5-21-1-2-3-4-1001",
            "S-1-5-21-1-2-3-",
            "S-1-5-21-1-2-3-1001)(A;;GA;;;WD)",
            "S-1-5-21-1-2-3-+1001",
            "S-1-5-21-1-2-3-4294967296",
            "",
        ] {
            assert!(!forme_admissible(refuse), "{refuse} doit etre refuse");
        }
    }

    /// La classe d'un compte pour la premisse des miroirs, sur des formes
    /// synthetiques: les RID 500 et 501 (et tout RID sous 1000) predefinis,
    /// 1000 et au-dela crees, un autre domaine ni l'un ni l'autre, comme
    /// toute forme qui n'est pas `<domaine>-<RID decimal canonique>`. Sur le
    /// domaine, la classe << cree >> coincide avec la regle de forme du
    /// jugement.
    #[test]
    fn la_classe_du_compte_se_lit_sur_la_forme_canonique() {
        use ClasseDeCompte::{Autre, Cree, Predefini};
        let domaine = "S-1-5-21-1-2-3";
        for (forme, classe) in [
            ("S-1-5-21-1-2-3-500", Predefini),
            ("S-1-5-21-1-2-3-501", Predefini),
            ("S-1-5-21-1-2-3-513", Predefini),
            ("S-1-5-21-1-2-3-999", Predefini),
            ("S-1-5-21-1-2-3-0", Predefini),
            ("S-1-5-21-1-2-3-1000", Cree),
            ("S-1-5-21-1-2-3-1001", Cree),
            ("S-1-5-21-1-2-3-4294967295", Cree),
            // Un autre domaine, meme avec un RID cree; le domaine seul.
            ("S-1-5-21-4-5-6-1000", Autre),
            ("S-1-5-21-1-2-30-1000", Autre),
            ("S-1-5-21-1-2-3", Autre),
            // Les autorites et groupes predefinis hors domaine.
            ("S-1-5-32-544", Autre),
            ("S-1-5-18", Autre),
            ("S-1-1-0", Autre),
            // Des formes qui ne sont pas canoniques, ou pas un RID.
            ("S-1-5-21-1-2-3-0500", Autre),
            ("S-1-5-21-1-2-3-", Autre),
            ("S-1-5-21-1-2-3-1000-7", Autre),
            ("S-1-5-21-1-2-3-+1000", Autre),
            ("S-1-5-21-1-2-3-4294967296", Autre),
            ("s-1-5-21-1-2-3-1000", Autre),
            ("", Autre),
        ] {
            assert_eq!(classer_la_forme(forme, domaine), classe, "{forme}");
            assert_eq!(
                classer_la_forme(forme, domaine) == Cree,
                forme_admissible(forme) && forme.starts_with("S-1-5-21-1-2-3-"),
                "{forme}: la classe cree et la regle de forme doivent coincider"
            );
        }
        // Un domaine qui n'a pas la forme d'un domaine de comptes ne classe
        // rien.
        assert_eq!(classer_la_forme("S-1-5-32-544", "S-1-5-32"), Autre);
    }

    /// Le texte d'une panique attrapee; sans panique, vide.
    fn message(issue: &Result<Premisse, Box<dyn std::any::Any + Send>>) -> String {
        match issue {
            Ok(_) => String::new(),
            Err(p) => p
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| p.downcast_ref::<&str>().map(|s| (*s).to_owned()))
                .unwrap_or_default(),
        }
    }

    /// La premisse du miroir, jugee seule: un compte cree la tient, un compte
    /// predefini vaut l'abstention, sous sa raison exacte; toute autre forme
    /// et toute erreur du systeme sont un rouge (panique nommee), jamais une
    /// abstention. Les deux raisons n'ont ni chiffre ni chemin, pour que la
    /// garde de forme de la liste des abstentions les prenne telles quelles.
    #[test]
    fn la_premisse_du_miroir_n_abstient_que_le_compte_predefini() {
        use std::panic::catch_unwind;
        assert_eq!(juger_la_premisse(Ok(ClasseDeCompte::Cree)), Premisse::Tenue);
        assert_eq!(
            juger_la_premisse(Ok(ClasseDeCompte::Predefini)),
            Premisse::Abstention(RAISON_COMPTE_PREDEFINI)
        );
        let autre = catch_unwind(|| juger_la_premisse(Ok(ClasseDeCompte::Autre)));
        assert!(
            message(&autre).contains("ne sait pas le mesurer"),
            "une autre forme doit paniquer, pas s'abstenir: {autre:?}"
        );
        let erreur = ErreurGroupe::Systeme {
            nom: "compte courant".to_owned(),
            appel: "OpenProcessToken",
            code: 5,
        };
        let systeme = catch_unwind(|| juger_la_premisse(Err(&erreur)));
        assert!(
            message(&systeme).contains("ne se lit pas"),
            "une erreur du systeme doit paniquer, pas s'abstenir: {systeme:?}"
        );
        for raison in [RAISON_COMPTE_PREDEFINI, RAISON_ADMINISTRATEURS_ACTIFS] {
            assert!(!raison.chars().any(|c| c.is_ascii_digit()), "{raison}");
            assert!(!raison.contains(['/', '\\']), "{raison}");
            assert!(raison.is_ascii() && !raison.contains('\n'), "{raison}");
        }
        assert_ne!(RAISON_COMPTE_PREDEFINI, RAISON_ADMINISTRATEURS_ACTIFS);
    }

    /// Les sept recettes miroir avouent leur abstention, et l'avouent la ou
    /// la CI la lit: chacune existe sous son nom dans le source, passe son
    /// nom a l'abstention du miroir (`compte_pour_le_miroir`, directement ou
    /// par les deux aides de `transport.rs`), et
    /// `ci/abstentions-attendues-windows.txt` porte sa ligne
    /// `SKIPPED <nom>: <raison>` avec la raison du compte predefini, mot pour
    /// mot. Une recette qui cesserait de passer son nom a l'abstention, ou
    /// une liste qui ne porterait pas sa ligne sous la forme exacte, rougit
    /// ici, avant le runner. La garde lit le texte, pas l'appel: une recette
    /// qui garderait son nom entre guillemets ailleurs sans appeler
    /// l'abstention passerait ici, et seul le runner la verrait (un rouge au
    /// lieu d'un SKIPPED). La raison des Administrateurs actifs n'y est pas:
    /// sur le runner, c'est la premiere premisse qui parle.
    #[test]
    fn les_sept_miroirs_avouent_leur_abstention_dans_la_liste_windows() {
        const MIROIRS: [&str; 7] = [
            "le_compte_courant_passe_la_forme_et_le_domaine",
            "un_rid_predefini_de_la_machine_est_refuse",
            "une_forme_equivalente_est_jugee_et_rendue_sous_sa_forme_canonique",
            "le_client_s_ouvre_par_les_droits_que_le_groupe_accorde",
            "le_descripteur_ajoute_une_seule_ace_pour_le_groupe",
            "le_pipe_lie_porte_l_ace_du_groupe_et_rien_de_plus",
            "miroir_le_compte_du_groupe_echange_sans_pouvoir_ajouter_d_instance",
        ];
        let sources = [include_str!("groupe.rs"), include_str!("transport.rs")].concat();
        let liste = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../ci/abstentions-attendues-windows.txt"
        ))
        .expect("la liste des abstentions attendues du job Windows");
        let lignes: Vec<&str> = liste.lines().collect();
        for nom in MIROIRS {
            assert_eq!(
                sources.matches(&format!("fn {nom}(")).count(),
                1,
                "{nom}: une recette de ce nom, une seule"
            );
            // Le nom entre guillemets: une fois dans cette garde, et au moins
            // une fois dans la recette, passe a l'abstention du miroir.
            assert!(
                sources.matches(&format!("\"{nom}\"")).count() >= 2,
                "{nom}: la recette ne passe pas son nom a l'abstention du miroir"
            );
            let attendue = format!("SKIPPED {nom}: {RAISON_COMPTE_PREDEFINI}");
            assert_eq!(
                lignes.iter().filter(|l| **l == attendue).count(),
                1,
                "{nom}: la liste Windows doit porter sa ligne exacte, une fois"
            );
        }
        let avec_raison = lignes
            .iter()
            .filter(|l| l.contains(RAISON_COMPTE_PREDEFINI))
            .count();
        assert_eq!(avec_raison, 7, "la raison du compte predefini: sept lignes");
        assert!(
            !liste.contains(RAISON_ADMINISTRATEURS_ACTIFS),
            "la raison des Administrateurs actifs n'est pas attendue sur le runner"
        );
    }

    /// Une designation textuelle d'un compte predefini, ecrite sous une forme
    /// que le systeme canonise (zeros de tete, casse, autorite en
    /// hexadecimal), est refusee, et le refus nomme la forme CANONIQUE.
    #[test]
    fn une_forme_equivalente_d_un_compte_predefini_est_refusee_sous_sa_forme_canonique() {
        for (designation, canonique) in [
            ("S-1-1-00", "S-1-1-0"),
            ("S-1-01-0", "S-1-1-0"),
            ("s-1-1-0", "S-1-1-0"),
            ("S-1-0x1-0", "S-1-1-0"),
            ("S-1-5-011", "S-1-5-11"),
            ("S-1-5-32-0545", "S-1-5-32-545"),
            ("S-1-5-32-0544", "S-1-5-32-544"),
        ] {
            match GroupeDAcces::resoudre(designation) {
                Err(ErreurGroupe::NonAdmissible { nom, sid }) => {
                    assert_eq!(nom, designation);
                    assert_eq!(sid, canonique, "{designation}");
                }
                autre => panic!("{designation}: {autre:?}"),
            }
        }
    }

    /// Le compte courant, designe par son SID ecrit avec des zeros de tete et
    /// en minuscules: le systeme le canonise, et c'est la forme canonique
    /// qui est jugee puis rendue. Un utilisateur n'est pas un groupe local:
    /// refuse par le type, sous sa forme canonique. Miroir: s'abstient, en le
    /// nommant, si le compte des recettes n'est pas un compte cree.
    #[test]
    fn une_forme_equivalente_est_jugee_et_rendue_sous_sa_forme_canonique() {
        let Some(compte) = GroupeDAcces::compte_pour_le_miroir(
            "une_forme_equivalente_est_jugee_et_rendue_sous_sa_forme_canonique",
        ) else {
            return;
        };
        let canonique = compte.sid().to_owned();
        let (domaine, rid) = canonique
            .rsplit_once('-')
            .expect("forme S-1-5-21-a-b-c-RID");
        for designation in [
            format!("{domaine}-0{rid}"),
            format!("{domaine}-00{rid}").to_lowercase(),
        ] {
            match GroupeDAcces::resoudre(&designation) {
                Err(ErreurGroupe::PasUnGroupeLocal { sid, .. }) => {
                    assert_eq!(sid, canonique, "{designation}")
                }
                autre => panic!("{designation}: {autre:?}"),
            }
        }
    }

    /// Un SID de la machine sous le RID 1000 (le compte predefini
    /// Administrator, 500, et Guest, 501) est refuse par la forme, avant
    /// toute question de type. Miroir: le domaine est celui du compte des
    /// recettes; s'abstient, en le nommant, si ce compte n'est pas un compte
    /// cree.
    #[test]
    fn un_rid_predefini_de_la_machine_est_refuse() {
        let Some(compte) =
            GroupeDAcces::compte_pour_le_miroir("un_rid_predefini_de_la_machine_est_refuse")
        else {
            return;
        };
        let (domaine, _) = compte.sid().rsplit_once('-').expect("forme");
        for rid in [500, 501, 999] {
            let designation = format!("{domaine}-{rid}");
            match GroupeDAcces::resoudre(&designation) {
                Err(ErreurGroupe::NonAdmissible { sid, .. }) => assert_eq!(sid, designation),
                // Un RID que la machine ne porte pas: introuvable, refuse aussi.
                Err(ErreurGroupe::Introuvable { .. }) => {}
                autre => panic!("{designation}: {autre:?}"),
            }
        }
    }

    /// Un compte d'un autre domaine que celui de la machine, de forme admise,
    /// n'est pas un groupe cree localement: refuse. Le domaine `1-2-3` n'est
    /// celui d'aucune machine, et la regle de domaine se juge sans lui
    /// demander s'il existe.
    #[test]
    fn un_sid_d_un_autre_domaine_n_est_pas_du_domaine_de_la_machine() {
        let machine = domaine_de_la_machine("recette").expect("domaine de la machine");
        let etranger = "S-1-5-21-1-2-3-1001";
        let large: Vec<u16> = etranger.encode_utf16().chain(Some(0)).collect();
        let mut brut: PSID = std::ptr::null_mut();
        // SAFETY: chaine UTF-16 terminee par un zero; allocation liberee
        // ci-dessous.
        assert!(unsafe { ConvertStringSidToSidW(large.as_ptr(), &mut brut) } != 0);
        // SAFETY: SID rendu par le systeme.
        let sid = unsafe { copier_sid("recette", brut) }.expect("copie");
        // SAFETY: allocation de ConvertStringSidToSidW, plus lue apres.
        unsafe { LocalFree(brut) };
        assert!(forme_admissible(etranger));
        assert!(!du_domaine_de_la_machine(&sid, &machine));
        // Et le jugement l'applique: de forme admise, le SID est refuse par
        // son domaine. `resoudre` ne le montre pas ici, faute de pouvoir
        // trouver un compte d'un autre domaine depuis cette machine.
        match juger_le_sid("recette", sid) {
            Err(ErreurGroupe::NonAdmissible { sid, .. }) => assert_eq!(sid, etranger),
            autre => panic!("{etranger}: {autre:?}"),
        }
        let compte = sid_du_compte_courant().expect("compte des recettes");
        assert!(
            du_domaine_de_la_machine(&compte, &machine),
            "le compte des recettes est un compte de cette machine"
        );
    }

    /// Les groupes et comptes predefinis designes par leur nom: le nom de
    /// Everyone et de Users depend de la langue de la machine, leur SID non.
    /// Designes par SID, ils sont refuses; un nom inconnu et un nom vide sont
    /// introuvables, jamais admis.
    #[test]
    fn un_nom_inconnu_ou_vide_est_introuvable() {
        let absent = format!("bifrost-groupe-absent-{}", std::process::id());
        for designation in [absent.as_str(), "", "   "] {
            assert!(
                matches!(
                    GroupeDAcces::resoudre(designation),
                    Err(ErreurGroupe::Introuvable { .. })
                ),
                "{designation:?}"
            );
        }
        // Une injection SDDL dans une designation textuelle n'est pas un SID.
        assert!(matches!(
            GroupeDAcces::resoudre("S-1-5-21-1-2-3-1001)(A;;GA;;;WD"),
            Err(ErreurGroupe::Introuvable { .. })
        ));
    }

    /// Le compte courant passe la regle de forme et de domaine, et son
    /// `Debug` ne montre que la forme canonique. Miroir: s'abstient, en le
    /// nommant, si le compte des recettes n'est pas un compte cree.
    #[test]
    fn le_compte_courant_passe_la_forme_et_le_domaine() {
        let Some(compte) =
            GroupeDAcces::compte_pour_le_miroir("le_compte_courant_passe_la_forme_et_le_domaine")
        else {
            return;
        };
        assert!(forme_admissible(compte.sid()), "{}", compte.sid());
        assert_eq!(
            format!("{compte:?}"),
            format!("GroupeDAcces({:?})", compte.sid())
        );
        assert_eq!(
            texte_du_sid("recette", compte.sid_binaire()).as_deref(),
            Ok(compte.sid())
        );
    }
}
