//! Lecture seule du moteur WFP, pour `prove wfp`.
//!
//! # Un instantane coherent
//!
//! Tout se lit dans UNE transaction ouverte en lecture seule. BFE garantit a
//! ses transactions une semantique ACID (Microsoft Learn, "Object
//! Management"): les sous-couches et les filtres recopies ici appartiennent au
//! meme etat du moteur, aucune ecriture ne s'intercale entre deux lots d'une
//! enumeration. C'est ce qui tient le role du GETGEN de nftables: WFP ne publie
//! ni numero de generation ni identifiant de changement, mais une lecture
//! transactionnelle n'en a pas besoin. Qu'un autre processus tienne le verrou
//! au-dela du delai, et la lecture echoue (`Refus::Verrou`) plutot que de
//! rendre un etat a moitie ecrit.
//!
//! # Aucune elevation, aucune ecriture
//!
//! Tout le monde recoit `FWPM_ACTRL_OPEN` sur le moteur; ouvrir une
//! transaction de lecture exige `FWPM_ACTRL_BEGIN_READ_TXN`, et enumerer
//! `FWPM_ACTRL_ENUM` (Microsoft Learn, "Access control"). Un appelant sans ces
//! droits est donc refuse, et ce refus remonte en [`Refus::AccesRefuse`],
//! jamais en moteur vide. Ce module n'appelle aucune fonction qui ajoute,
//! supprime ou change la securite d'un objet: la recette
//! `la_lecture_n_appelle_rien_qui_ecrive` le verifie sur son propre source.
//!
//! # Ce que cette lecture ne voit pas
//!
//! "L'enumerateur ne rend que les objets sur lesquels l'appelant a
//! `FWPM_ACTRL_READ`": un filtre dont le descripteur refuse la lecture aux
//! administrateurs est omis sans que rien ne le signale, et les appelants en
//! mode noyau echappent a tout controle. C'est une limite de la plateforme,
//! dite dans le rapport de la preuve.

use std::ffi::c_void;

use windows_sys::Win32::Foundation::{
    E_ACCESSDENIED, ERROR_ACCESS_DENIED, ERROR_SUCCESS, FWP_E_PROVIDER_NOT_FOUND, FWP_E_TIMEOUT,
    HANDLE,
};
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::*;
use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_DEFAULT;
use windows_sys::core::GUID;

use crate::instantane_wfp::{ConditionVue, FiltreVu, Instantane, SousCoucheVue, ValeurVue};
use crate::wfp_plan::{self, Layer};

/// Pourquoi il n'y a pas d'instantane. Aucun de ces cas n'est un moteur vide.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refus {
    /// Un droit a ete refuse: a l'ouverture, a la transaction ou a une
    /// enumeration.
    AccesRefuse,
    /// Le verrou de transaction n'a pas ete obtenu dans le delai: un autre
    /// processus ecrivait.
    Verrou,
    /// Le moteur ne repond pas (BFE arrete, RPC), avec son code.
    MoteurInjoignable(u32),
    /// Une enumeration s'est interrompue, avec son code.
    Interrompue(u32),
    /// Des donnees incoherentes ou hors bornes: pointeur nul sous un compte
    /// non nul, taille aberrante, trop d'objets. Rien de partiel n'est rendu.
    Tronquee,
    /// La transaction n'a pas pu etre refermee: rien ne dit que la lecture
    /// etait isolee.
    NonConfirmee(u32),
}

/// Delai d'attente du verrou. Le meme que la pose: au-dela, un autre processus
/// ecrit, et attendre davantage ne rendrait pas la lecture plus sure.
const DELAI_VERROU_MS: u32 = 5_000;
const LOT: u32 = 256;
/// Bornes au-dela desquelles la lecture refuse plutot que de tronquer. Un
/// moteur ordinaire porte quelques milliers de filtres.
const MAX_FILTRES: usize = 500_000;
const MAX_SOUS_COUCHES: usize = 100_000;
const MAX_CONDITIONS: u32 = 4_096;
const MAX_OCTETS: u32 = 1 << 20;

fn refus(code: u32) -> bool {
    code == ERROR_ACCESS_DENIED || code == E_ACCESSDENIED as u32
}

fn classer(code: u32, sinon: fn(u32) -> Refus) -> Refus {
    if refus(code) {
        Refus::AccesRefuse
    } else if code == FWP_E_TIMEOUT as u32 {
        Refus::Verrou
    } else {
        sinon(code)
    }
}

fn en_u128(g: &GUID) -> u128 {
    (u128::from(g.data1) << 96)
        | (u128::from(g.data2) << 80)
        | (u128::from(g.data3) << 64)
        | u128::from(u64::from_be_bytes(g.data4))
}

struct Session(HANDLE);

impl Drop for Session {
    fn drop(&mut self) {
        // SAFETY: le handle provient d'un FwpmEngineOpen0 reussi et n'est
        // ferme qu'ici. Fermer une session abandonne sa transaction eventuelle.
        unsafe { FwpmEngineClose0(self.0) };
    }
}

/// L'instantane du moteur: sous-couches et filtres des quatre couches du plan,
/// lus dans une seule transaction en lecture seule.
pub fn instantane() -> Result<Instantane, Refus> {
    let mut handle: HANDLE = std::ptr::null_mut();
    let session = FWPM_SESSION0 {
        txnWaitTimeoutInMSec: DELAI_VERROU_MS,
        ..Default::default()
    };
    // SAFETY: `session` vit jusqu'a la fin de l'appel et `handle` pointe sur
    // une variable locale; le code de retour est verifie.
    let code = unsafe {
        FwpmEngineOpen0(
            std::ptr::null(),
            RPC_C_AUTHN_DEFAULT as u32,
            std::ptr::null(),
            &session,
            &mut handle,
        )
    };
    if code != ERROR_SUCCESS {
        return Err(classer(code, Refus::MoteurInjoignable));
    }
    let session = Session(handle);
    let h = session.0;

    // SAFETY: session ouverte ci-dessus, aucune transaction en cours.
    let code = unsafe { FwpmTransactionBegin0(h, FWPM_TXN_READ_ONLY) };
    if code != ERROR_SUCCESS {
        return Err(classer(code, Refus::MoteurInjoignable));
    }
    let lu = lire(h);
    if lu.is_err() {
        // SAFETY: transaction ouverte ci-dessus.
        unsafe { FwpmTransactionAbort0(h) };
        return lu;
    }
    // Une transaction en lecture seule n'a rien a valider. La clore par un
    // commit plutot qu'un abandon fait remonter le cas ou BFE l'aurait
    // interrompue entre-temps.
    // SAFETY: transaction ouverte ci-dessus.
    let fin = unsafe { FwpmTransactionCommit0(h) };
    if fin != ERROR_SUCCESS {
        // SAFETY: idem; l'abandon d'une transaction deja close est sans effet.
        unsafe { FwpmTransactionAbort0(h) };
        return Err(Refus::NonConfirmee(fin));
    }
    lu
}

/// L'identifiant d'application que la pose calcule pour `chemin`, en octets:
/// la valeur que le moteur compare, pour que l'attendu d'une condition
/// `ALE_APP_ID` se calcule par la meme fonction que la pose. `None` si le
/// fichier n'existe pas ou si la plateforme refuse le chemin. N'ouvre pas le
/// moteur.
pub fn identifiant_application(chemin: &std::path::Path) -> Option<Vec<u8>> {
    let id = super::ffi::AppId::from_path(chemin).ok()?;
    octets(id.as_ptr()).ok()
}

fn lire(h: HANDLE) -> Result<Instantane, Refus> {
    let fournisseur_bifrost = fournisseur_present(h)?;
    let sous_couches = sous_couches(h)?;
    let mut filtres = Vec::new();
    for couche in Layer::ALL {
        filtres_de(h, couche, &mut filtres)?;
    }
    Ok(Instantane {
        fournisseur_bifrost,
        sous_couches,
        filtres,
    })
}

fn fournisseur_present(h: HANDLE) -> Result<bool, Refus> {
    let cle = GUID::from_u128(wfp_plan::FOURNISSEUR);
    let mut sortie: *mut FWPM_PROVIDER0 = std::ptr::null_mut();
    // SAFETY: `cle` et `sortie` sont locales; l'allocation rendue est liberee
    // juste apres.
    let code = unsafe { FwpmProviderGetByKey0(h, &cle, &mut sortie) };
    if code == ERROR_SUCCESS {
        if !sortie.is_null() {
            // SAFETY: allocation de FwpmProviderGetByKey0.
            unsafe { FwpmFreeMemory0(&mut (sortie as *mut c_void)) };
        }
        return Ok(true);
    }
    if code == FWP_E_PROVIDER_NOT_FOUND as u32 {
        return Ok(false);
    }
    Err(classer(code, Refus::Interrompue))
}

fn sous_couches(h: HANDLE) -> Result<Vec<SousCoucheVue>, Refus> {
    let mut poignee: HANDLE = std::ptr::null_mut();
    // SAFETY: gabarit nul (toutes les sous-couches), `poignee` est une sortie.
    let code = unsafe { FwpmSubLayerCreateEnumHandle0(h, std::ptr::null(), &mut poignee) };
    if code != ERROR_SUCCESS {
        return Err(classer(code, Refus::Interrompue));
    }
    let mut vues = Vec::new();
    let resultat = loop {
        let mut lot: *mut *mut FWPM_SUBLAYER0 = std::ptr::null_mut();
        let mut rendus: u32 = 0;
        // SAFETY: poignee valide; `lot` recoit un tableau alloue par WFP,
        // libere plus bas sur tous les chemins.
        let code = unsafe { FwpmSubLayerEnum0(h, poignee, LOT, &mut lot, &mut rendus) };
        if code != ERROR_SUCCESS {
            break Err(classer(code, Refus::Interrompue));
        }
        let copie = copier_sous_couches(lot, rendus, &mut vues);
        if !lot.is_null() {
            // SAFETY: tableau alloue par FwpmSubLayerEnum0.
            unsafe { FwpmFreeMemory0(&mut (lot as *mut c_void)) };
        }
        if let Err(e) = copie {
            break Err(e);
        }
        if vues.len() > MAX_SOUS_COUCHES {
            break Err(Refus::Tronquee);
        }
        if rendus < LOT {
            break Ok(());
        }
    };
    // SAFETY: poignee creee ci-dessus, detruite une seule fois.
    unsafe { FwpmSubLayerDestroyEnumHandle0(h, poignee) };
    resultat.map(|()| vues)
}

fn copier_sous_couches(
    lot: *mut *mut FWPM_SUBLAYER0,
    rendus: u32,
    vues: &mut Vec<SousCoucheVue>,
) -> Result<(), Refus> {
    if rendus > LOT || (rendus > 0 && lot.is_null()) {
        return Err(Refus::Tronquee);
    }
    for i in 0..rendus as usize {
        // SAFETY: WFP garantit `rendus` pointeurs dans le tableau.
        let s = unsafe { *lot.add(i) };
        if s.is_null() {
            return Err(Refus::Tronquee);
        }
        // SAFETY: pointeur non nul rendu par l'enumeration.
        let s = unsafe { &*s };
        vues.push(SousCoucheVue {
            cle: en_u128(&s.subLayerKey),
            poids: s.weight,
            fournisseur: if s.providerKey.is_null() {
                None
            } else {
                // SAFETY: pointeur non nul dans l'allocation du lot.
                Some(en_u128(unsafe { &*s.providerKey }))
            },
        });
    }
    Ok(())
}

fn filtres_de(h: HANDLE, couche: Layer, vus: &mut Vec<FiltreVu>) -> Result<(), Refus> {
    let gabarit = FWPM_FILTER_ENUM_TEMPLATE0 {
        providerKey: std::ptr::null_mut(),
        layerKey: GUID::from_u128(couche.cle()),
        // Sans condition dans le gabarit, "overlapping" rend tous les filtres
        // de la couche, de tous les fournisseurs.
        enumType: FWP_FILTER_ENUM_OVERLAPPING,
        // Les desactives aussi: un filtre de Bifrost desactive doit se lire
        // comme tel, et non comme un filtre absent.
        flags: FWP_FILTER_ENUM_FLAG_INCLUDE_DISABLED,
        actionMask: u32::MAX,
        ..Default::default()
    };
    let mut poignee: HANDLE = std::ptr::null_mut();
    // SAFETY: le gabarit vit jusqu'a la fin de l'appel; `poignee` est une
    // sortie.
    let code = unsafe { FwpmFilterCreateEnumHandle0(h, &gabarit, &mut poignee) };
    if code != ERROR_SUCCESS {
        return Err(classer(code, Refus::Interrompue));
    }
    let resultat = loop {
        let mut lot: *mut *mut FWPM_FILTER0 = std::ptr::null_mut();
        let mut rendus: u32 = 0;
        // SAFETY: poignee valide; `lot` recoit un tableau alloue par WFP,
        // libere plus bas sur tous les chemins.
        let code = unsafe { FwpmFilterEnum0(h, poignee, LOT, &mut lot, &mut rendus) };
        if code != ERROR_SUCCESS {
            break Err(classer(code, Refus::Interrompue));
        }
        let copie = copier_filtres(couche, lot, rendus, vus);
        if !lot.is_null() {
            // SAFETY: tableau alloue par FwpmFilterEnum0.
            unsafe { FwpmFreeMemory0(&mut (lot as *mut c_void)) };
        }
        if let Err(e) = copie {
            break Err(e);
        }
        if vus.len() > MAX_FILTRES {
            break Err(Refus::Tronquee);
        }
        if rendus < LOT {
            break Ok(());
        }
    };
    // SAFETY: poignee creee ci-dessus, detruite une seule fois.
    unsafe { FwpmFilterDestroyEnumHandle0(h, poignee) };
    resultat
}

fn copier_filtres(
    couche: Layer,
    lot: *mut *mut FWPM_FILTER0,
    rendus: u32,
    vus: &mut Vec<FiltreVu>,
) -> Result<(), Refus> {
    if rendus > LOT || (rendus > 0 && lot.is_null()) {
        return Err(Refus::Tronquee);
    }
    for i in 0..rendus as usize {
        // SAFETY: WFP garantit `rendus` pointeurs dans le tableau.
        let f = unsafe { *lot.add(i) };
        if f.is_null() {
            return Err(Refus::Tronquee);
        }
        // SAFETY: pointeur non nul rendu par l'enumeration; tout ce qu'il
        // pointe vit dans l'allocation du lot, liberee apres la copie.
        let f = unsafe { &*f };
        // Le gabarit demandait CETTE couche: un filtre d'une autre couche dans
        // la reponse est une incoherence, pas un filtre a ranger ailleurs.
        if en_u128(&f.layerKey) != couche.cle() {
            return Err(Refus::Tronquee);
        }
        if f.numFilterConditions > MAX_CONDITIONS
            || (f.numFilterConditions > 0 && f.filterCondition.is_null())
        {
            return Err(Refus::Tronquee);
        }
        let mut conditions = Vec::with_capacity(f.numFilterConditions as usize);
        for j in 0..f.numFilterConditions as usize {
            // SAFETY: `numFilterConditions` conditions contigues, verifie non
            // nul ci-dessus.
            let c = unsafe { &*f.filterCondition.add(j) };
            conditions.push(ConditionVue {
                champ: en_u128(&c.fieldKey),
                correspondance: c.matchType as u32,
                valeur: valeur_condition(&c.conditionValue)?,
            });
        }
        vus.push(FiltreVu {
            couche,
            sous_couche: en_u128(&f.subLayerKey),
            fournisseur: if f.providerKey.is_null() {
                None
            } else {
                // SAFETY: pointeur non nul dans l'allocation du lot.
                Some(en_u128(unsafe { &*f.providerKey }))
            },
            poids: valeur(&f.weight)?,
            poids_effectif: valeur(&f.effectiveWeight)?,
            action: f.action.r#type,
            drapeaux: f.flags,
            conditions,
        });
    }
    Ok(())
}

fn octets(blob: *const FWP_BYTE_BLOB) -> Result<Vec<u8>, Refus> {
    if blob.is_null() {
        return Err(Refus::Tronquee);
    }
    // SAFETY: pointeur non nul rendu par WFP.
    let b = unsafe { &*blob };
    if b.size > MAX_OCTETS || (b.size > 0 && b.data.is_null()) {
        return Err(Refus::Tronquee);
    }
    if b.size == 0 {
        return Ok(Vec::new());
    }
    // SAFETY: `size` octets a `data`, verifies non nuls et bornes ci-dessus.
    Ok(unsafe { std::slice::from_raw_parts(b.data, b.size as usize) }.to_vec())
}

fn valeur(v: &FWP_VALUE0) -> Result<ValeurVue, Refus> {
    // SAFETY: chaque bras ne lit que le membre de l'union que le type designe,
    // et verifie les pointeurs avant de les suivre.
    unsafe {
        Ok(match v.r#type {
            FWP_EMPTY => ValeurVue::Vide,
            FWP_UINT8 => ValeurVue::U8(v.Anonymous.uint8),
            FWP_UINT16 => ValeurVue::U16(v.Anonymous.uint16),
            FWP_UINT32 => ValeurVue::U32(v.Anonymous.uint32),
            FWP_UINT64 => {
                let p = v.Anonymous.uint64;
                if p.is_null() {
                    return Err(Refus::Tronquee);
                }
                ValeurVue::U64(*p)
            }
            autre => ValeurVue::Autre(autre),
        })
    }
}

fn valeur_condition(v: &FWP_CONDITION_VALUE0) -> Result<ValeurVue, Refus> {
    // SAFETY: chaque bras ne lit que le membre de l'union que le type designe,
    // et verifie les pointeurs avant de les suivre.
    unsafe {
        Ok(match v.r#type {
            FWP_EMPTY => ValeurVue::Vide,
            FWP_UINT8 => ValeurVue::U8(v.Anonymous.uint8),
            FWP_UINT16 => ValeurVue::U16(v.Anonymous.uint16),
            FWP_UINT32 => ValeurVue::U32(v.Anonymous.uint32),
            FWP_UINT64 => {
                let p = v.Anonymous.uint64;
                if p.is_null() {
                    return Err(Refus::Tronquee);
                }
                ValeurVue::U64(*p)
            }
            FWP_V4_ADDR_MASK => {
                let p = v.Anonymous.v4AddrMask;
                if p.is_null() {
                    return Err(Refus::Tronquee);
                }
                ValeurVue::V4 {
                    adresse: (*p).addr,
                    masque: (*p).mask,
                }
            }
            FWP_V6_ADDR_MASK => {
                let p = v.Anonymous.v6AddrMask;
                if p.is_null() {
                    return Err(Refus::Tronquee);
                }
                ValeurVue::V6 {
                    adresse: (*p).addr,
                    prefixe: (*p).prefixLength,
                }
            }
            FWP_BYTE_BLOB_TYPE => ValeurVue::Octets(octets(v.Anonymous.byteBlob)?),
            FWP_SECURITY_DESCRIPTOR_TYPE => ValeurVue::Descripteur(octets(v.Anonymous.sd)?),
            autre => ValeurVue::Autre(autre),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Le processus qui execute la recette est-il eleve. Lu dans son jeton,
    /// independamment de WFP: c'est ce qui permet de dire quelle reponse le
    /// moteur DOIT donner, au lieu d'accepter les deux.
    fn est_eleve() -> bool {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::Security::{
            GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
        };
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
        // SAFETY: jeton ouvert et referme ici; tampon local de la taille
        // exacte de la structure demandee.
        unsafe {
            let mut jeton: HANDLE = std::ptr::null_mut();
            assert_ne!(
                OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut jeton),
                0,
                "jeton du processus illisible"
            );
            let mut e = TOKEN_ELEVATION::default();
            let mut n = 0u32;
            let ok = GetTokenInformation(
                jeton,
                TokenElevation,
                &mut e as *mut TOKEN_ELEVATION as *mut c_void,
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut n,
            );
            CloseHandle(jeton);
            assert_ne!(ok, 0, "elevation illisible");
            e.TokenIsElevated != 0
        }
    }

    /// LA recette de la distinction entre absence et refus, sur le vrai
    /// moteur. Sans elevation, la lecture doit etre REFUSEE, jamais rendue
    /// vide: un instantane vide dirait "aucun filtre" sur une machine qui en
    /// porte des milliers. Elevee, elle doit rendre un moteur habite: BFE a
    /// toujours ses sous-couches integrees.
    #[test]
    fn sans_elevation_la_lecture_est_refusee_et_jamais_vide() {
        match (est_eleve(), instantane()) {
            (false, r) => assert_eq!(r, Err(Refus::AccesRefuse)),
            (true, Ok(i)) => {
                assert!(!i.sous_couches.is_empty(), "moteur sans sous-couche");
                assert!(!i.filtres.is_empty(), "moteur sans filtre ALE");
            }
            (true, Err(e)) => panic!("lecture elevee refusee: {e:?}"),
        }
    }

    /// Le collecteur est PASSIF: aucune fonction qui ajoute, supprime, change
    /// une option ou une securite, et toute transaction est en lecture seule.
    /// Lu sur le source meme, hors de ce bloc de recettes.
    #[test]
    fn la_lecture_n_appelle_rien_qui_ecrive() {
        let source = include_str!("lecture.rs");
        let produit = source
            .split("#[cfg(test)]")
            .next()
            .expect("le source a un corps");
        for interdit in [
            "Add0",
            "Delete",
            "SetSecurityInfo",
            "SetOption",
            "SubscribeChanges",
        ] {
            assert!(
                !produit.contains(interdit),
                "le collecteur appelle {interdit}"
            );
        }
        let ouvertures = produit.matches("FwpmTransactionBegin0(").count();
        let lecture_seule = produit
            .matches("FwpmTransactionBegin0(h, FWPM_TXN_READ_ONLY)")
            .count();
        assert!(ouvertures >= 1);
        assert_eq!(
            ouvertures, lecture_seule,
            "une transaction n'est pas en lecture seule"
        );
    }

    /// L'attendu d'une condition `ALE_APP_ID` se calcule par la fonction de la
    /// pose; un fichier absent ne rend rien, pas un identifiant vide.
    #[test]
    fn l_identifiant_d_application_est_celui_de_la_pose() {
        let exe = std::env::current_exe().expect("chemin de la recette");
        let id = identifiant_application(&exe).expect("un fichier qui existe");
        assert!(!id.is_empty());
        let pose = super::super::ffi::AppId::from_path(&exe).expect("idem");
        assert_eq!(octets(pose.as_ptr()), Ok(id));
        assert_eq!(identifiant_application(&exe.with_extension("absent")), None);
    }

    #[test]
    fn un_guid_se_relit_en_sa_valeur_pure() {
        for v in [
            wfp_plan::FOURNISSEUR,
            wfp_plan::cles::COUCHE_CONNECT_V6,
            0x0011_2233_4455_6677_8899_aabb_ccdd_eeff,
        ] {
            assert_eq!(en_u128(&GUID::from_u128(v)), v);
        }
    }
}
