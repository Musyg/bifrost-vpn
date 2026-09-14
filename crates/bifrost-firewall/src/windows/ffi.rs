//! Enrobage des appels WFP user-mode de `fwpuclnt.dll`.
//!
//! Trois responsabilites: convertir les codes de retour `u32` en `Result`,
//! garantir la liberation des handles et des allocations WFP, et maintenir en
//! vie les tampons pointes par les conditions le temps de l'appel.
//!
//! Toutes les fonctions `Fwpm*` renvoient un `WIN32_ERROR` et non un `HRESULT`:
//! elles ne signalent rien par une valeur de retour nulle et une erreur non
//! testee passerait inapercue. C'est verifie systematiquement ici.

use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use bifrost_core::{Error, Result};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_SUCCESS, GetLastError, HANDLE, HLOCAL, LocalFree,
};
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::*;
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    GetSidIdentifierAuthority, GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation,
    PSECURITY_DESCRIPTOR, PSID, TOKEN_GROUPS, TOKEN_QUERY, TOKEN_USER, TokenGroups, TokenUser,
};
use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_DEFAULT;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows_sys::core::{GUID, PWSTR};

use crate::wfp_plan::Identity;

/// Convertit une chaine en UTF-16 terminee par zero, prete pour l'API Win32.
pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Lit une chaine large terminee par zero, rendue par une API Win32.
///
/// # Safety
///
/// `p` doit etre nul, ou pointer sur une sequence UTF-16 terminee par zero.
unsafe fn depuis_large(p: PWSTR) -> String {
    if p.is_null() {
        return String::new();
    }
    // SAFETY: le contrat de la fonction garantit la terminaison par zero.
    unsafe {
        let mut len = 0usize;
        while *p.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
    }
}

/// Ce qu'une enumeration rend d'un filtre pose.
///
/// Le NOM est ce qui compte apres un redemarrage: les identifiants
/// d'execution sont reattribues par BFE quand il rejoue les filtres
/// persistants, donc celui note avant le reboot ne designe plus rien apres.
/// Seul le nom traverse.
#[derive(Debug, Clone)]
pub struct FiltreVu {
    pub id: u64,
    pub flags: u32,
    pub nom: String,
}

fn check(code: u32, what: &str) -> Result<()> {
    if code == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(Error::Firewall(format!(
            "{what}: erreur Win32 {code} ({code:#x})"
        )))
    }
}

/// Session WFP. Ferme le moteur a la liberation.
pub struct Engine {
    handle: HANDLE,
}

/// Delai maximal d'attente du verrou de transaction WFP.
///
/// Sans borne, `FwpmTransactionBegin0` attend indefiniment que le verrou se
/// libere. Un antivirus, un autre VPN ou simplement `netsh wfp show filters`
/// peuvent le detenir, et le daemon se retrouve alors bloque avec un kill
/// switch a moitie pose. C'est un piege documente cote Mullvad. Mieux vaut
/// echouer avec un message clair et reessayer.
const TXN_WAIT_TIMEOUT_MS: u32 = 5_000;

impl Engine {
    /// Ouvre une session NON dynamique.
    ///
    /// Une session dynamique verrait ses objets supprimes a la fermeture du
    /// processus. Pour un kill switch c'est exactement le contraire de ce qu'on
    /// veut: si le daemon meurt, les filtres doivent rester et le trafic rester
    /// bloque. Fail-closed.
    pub fn open() -> Result<Self> {
        let mut handle: HANDLE = std::ptr::null_mut();
        let session = FWPM_SESSION0 {
            txnWaitTimeoutInMSec: TXN_WAIT_TIMEOUT_MS,
            ..Default::default()
        };
        // SAFETY: `session` vit jusqu'a la fin de l'appel, `handle` pointe sur
        // une variable locale valide, et le code de retour est verifie.
        let code = unsafe {
            FwpmEngineOpen0(
                std::ptr::null(),
                RPC_C_AUTHN_DEFAULT as u32,
                std::ptr::null(),
                &session,
                &mut handle,
            )
        };
        check(code, "FwpmEngineOpen0")?;
        Ok(Self { handle })
    }

    /// Execute `body` dans une transaction WFP.
    ///
    /// C'est ce qui garantit l'absence de fenetre de fuite: les filtres
    /// apparaissent ou disparaissent tous ensemble. Toute erreur declenche un
    /// abandon, jamais une application partielle.
    pub fn transaction<T>(&self, body: impl FnOnce() -> Result<T>) -> Result<T> {
        check(
            // SAFETY: le handle provient d'un FwpmEngineOpen0 reussi.
            unsafe { FwpmTransactionBegin0(self.handle, 0) },
            "FwpmTransactionBegin0",
        )?;

        match body() {
            Ok(value) => {
                match check(
                    // SAFETY: le handle provient d'un FwpmEngineOpen0 reussi et la
                    // transaction est ouverte.
                    unsafe { FwpmTransactionCommit0(self.handle) },
                    "FwpmTransactionCommit0",
                ) {
                    Ok(()) => Ok(value),
                    Err(e) => {
                        // SAFETY: le handle provient d'un FwpmEngineOpen0 reussi et la
                        // transaction est ouverte; l'abandon la referme.
                        unsafe { FwpmTransactionAbort0(self.handle) };
                        Err(e)
                    }
                }
            }
            Err(e) => {
                // SAFETY: idem. L'echec de l'abandon ne doit pas masquer la
                // cause initiale, on se contente de le journaliser.
                let abort = unsafe { FwpmTransactionAbort0(self.handle) };
                if abort != ERROR_SUCCESS {
                    tracing::error!(code = abort, "abandon de transaction WFP en echec");
                }
                Err(e)
            }
        }
    }

    pub fn add_provider(&self, key: &GUID, name: &mut Vec<u16>, desc: &mut Vec<u16>) -> Result<()> {
        let provider = FWPM_PROVIDER0 {
            providerKey: *key,
            displayData: FWPM_DISPLAY_DATA0 {
                name: name.as_mut_ptr(),
                description: desc.as_mut_ptr(),
            },
            flags: 0,
            providerData: FWP_BYTE_BLOB {
                size: 0,
                data: std::ptr::null_mut(),
            },
            serviceName: std::ptr::null_mut(),
        };
        // SAFETY: `provider` reference `name` et `desc`, qui vivent plus
        // longtemps que l'appel.
        let code = unsafe { FwpmProviderAdd0(self.handle, &provider, std::ptr::null_mut()) };
        check(code, "FwpmProviderAdd0")
    }

    /// Provider persistant, avec un nom de service optionnel.
    ///
    /// Le nom de service n'est pas decoratif. La documentation de
    /// `FWPM_FILTER_FLAG_DISABLED` dit que "les filtres d'un provider sont
    /// DESACTIVES au demarrage de BFE si le provider n'a pas de nom de service
    /// associe, ou si ce service n'est pas en demarrage automatique". Un
    /// provider persistant sans nom de service risque donc de voir ses filtres
    /// revenir au reboot mais desactives, c'est-a-dire de ne rien bloquer tout
    /// en etant bien la. C'est precisement ce que cette recette mesure.
    pub fn add_provider_persistent(
        &self,
        key: &GUID,
        name: &mut Vec<u16>,
        desc: &mut Vec<u16>,
        service: Option<&mut Vec<u16>>,
    ) -> Result<()> {
        let provider = FWPM_PROVIDER0 {
            providerKey: *key,
            displayData: FWPM_DISPLAY_DATA0 {
                name: name.as_mut_ptr(),
                description: desc.as_mut_ptr(),
            },
            flags: FWPM_PROVIDER_FLAG_PERSISTENT,
            providerData: FWP_BYTE_BLOB {
                size: 0,
                data: std::ptr::null_mut(),
            },
            serviceName: match service {
                Some(s) => s.as_mut_ptr(),
                None => std::ptr::null_mut(),
            },
        };
        // SAFETY: tous les tampons pointes vivent plus longtemps que l'appel.
        let code = unsafe { FwpmProviderAdd0(self.handle, &provider, std::ptr::null_mut()) };
        check(code, "FwpmProviderAdd0")
    }

    pub fn add_sublayer(
        &self,
        key: &GUID,
        provider: &mut GUID,
        name: &mut Vec<u16>,
        desc: &mut Vec<u16>,
        weight: u16,
    ) -> Result<()> {
        self.add_sublayer_flags(key, provider, name, desc, weight, 0)
    }

    /// Le meme, avec `FWPM_SUBLAYER_FLAG_PERSISTENT` quand il le faut: un
    /// sublayer non persistant ne pourrait pas porter de filtres persistants.
    pub fn add_sublayer_persistent(
        &self,
        key: &GUID,
        provider: &mut GUID,
        name: &mut Vec<u16>,
        desc: &mut Vec<u16>,
        weight: u16,
    ) -> Result<()> {
        self.add_sublayer_flags(
            key,
            provider,
            name,
            desc,
            weight,
            FWPM_SUBLAYER_FLAG_PERSISTENT,
        )
    }

    fn add_sublayer_flags(
        &self,
        key: &GUID,
        provider: &mut GUID,
        name: &mut Vec<u16>,
        desc: &mut Vec<u16>,
        weight: u16,
        flags: u32,
    ) -> Result<()> {
        let sublayer = FWPM_SUBLAYER0 {
            subLayerKey: *key,
            displayData: FWPM_DISPLAY_DATA0 {
                name: name.as_mut_ptr(),
                description: desc.as_mut_ptr(),
            },
            flags,
            providerKey: provider,
            providerData: FWP_BYTE_BLOB {
                size: 0,
                data: std::ptr::null_mut(),
            },
            weight,
        };
        // SAFETY: tous les pointeurs du descripteur vivent plus longtemps que
        // l'appel.
        let code = unsafe { FwpmSubLayerAdd0(self.handle, &sublayer, std::ptr::null_mut()) };
        check(code, "FwpmSubLayerAdd0")
    }

    /// Supprime les objets de Bifrost. Les codes "objet introuvable" sont
    /// tolerated: le but est qu'il ne reste rien, pas qu'il y ait eu quelque
    /// chose a retirer.
    pub fn delete_sublayer(&self, key: &GUID) -> Result<()> {
        // SAFETY: `key` pointe sur un GUID valide.
        tolerate_not_found(
            unsafe { FwpmSubLayerDeleteByKey0(self.handle, key) },
            "FwpmSubLayerDeleteByKey0",
        )
    }

    /// Supprime un filtre par sa CLE et non par son identifiant.
    ///
    /// Seul moyen de retirer un filtre boot-time: celui-ci n'apparait pas dans
    /// l'enumeration du moteur en marche, puisqu'il est desactive des que BFE
    /// demarre. Un filtre boot-time dont on a laisse BFE engendrer la cle est
    /// donc irretirable par les voies normales, et il retient le sublayer qui
    /// le porte. C'est la raison pour laquelle ces filtres doivent porter des
    /// GUID fixes, choisis par nous.
    pub fn delete_filter_by_key(&self, key: &GUID) -> Result<()> {
        // SAFETY: `key` pointe sur un GUID valide.
        tolerate_not_found(
            unsafe { FwpmFilterDeleteByKey0(self.handle, key) },
            "FwpmFilterDeleteByKey0",
        )
    }

    pub fn delete_provider(&self, key: &GUID) -> Result<()> {
        // SAFETY: `key` pointe sur un GUID valide.
        tolerate_not_found(
            unsafe { FwpmProviderDeleteByKey0(self.handle, key) },
            "FwpmProviderDeleteByKey0",
        )
    }

    /// Vrai si le provider de Bifrost existe dans le moteur.
    pub fn provider_exists(&self, key: &GUID) -> Result<bool> {
        let mut out: *mut FWPM_PROVIDER0 = std::ptr::null_mut();
        // SAFETY: `out` recoit une allocation WFP qu'on libere juste apres.
        let code = unsafe { FwpmProviderGetByKey0(self.handle, key, &mut out) };
        if code == ERROR_SUCCESS {
            if !out.is_null() {
                // SAFETY: `out` a ete alloue par WFP.
                unsafe { FwpmFreeMemory0(&mut (out as *mut c_void)) };
            }
            return Ok(true);
        }
        if code == codes::PROVIDER_NOT_FOUND || code == codes::NOT_FOUND {
            return Ok(false);
        }
        Err(Error::Firewall(format!(
            "FwpmProviderGetByKey0: erreur Win32 {code} ({code:#x})"
        )))
    }

    /// Supprime tous les filtres d'un provider dans les layers indiques, et
    /// renvoie leur nombre.
    ///
    /// Indispensable avant de supprimer le sublayer: WFP ne fait AUCUNE
    /// suppression en cascade. Tant qu'un filtre reference le sublayer,
    /// `FwpmSubLayerDeleteByKey0` echoue avec `FWP_E_IN_USE` et le kill switch
    /// devient inamovible. C'est le chemin qu'emprunte aussi
    /// `--cleanup-firewall`, qui tourne dans un processus neuf et ne connait
    /// aucun identifiant de filtre: l'enumeration est le seul moyen de les
    /// retrouver.
    ///
    /// Les layers doivent etre enumeres un par un. Un `layerKey` nul dans le
    /// gabarit n'est pas compris comme "tous les layers": WFP le traite comme un
    /// layer inexistant et repond `FWP_E_LAYER_NOT_FOUND`.
    pub fn delete_filters_by_provider(&self, provider: &GUID, layers: &[GUID]) -> Result<usize> {
        let mut ids = Vec::new();
        for layer in layers {
            ids.extend(self.enumerate_filter_ids(provider, layer)?);
        }

        // On supprime apres avoir tout collecte: supprimer en cours
        // d'enumeration invaliderait le curseur.
        for id in &ids {
            tolerate_not_found(
                // SAFETY: le handle est valide et `id` provient de l'enumeration.
                unsafe { FwpmFilterDeleteById0(self.handle, *id) },
                "FwpmFilterDeleteById0",
            )?;
        }
        Ok(ids.len())
    }

    /// Ce que le moteur dit des filtres d'un provider: identifiant, drapeaux et
    /// nom. Les drapeaux sont l'objet de la mesure, pas un detail: BFE peut
    /// rendre un filtre AVEC `FWPM_FILTER_FLAG_DISABLED`, auquel cas il est bien
    /// present, bien enumerable, et ne bloque rien. Compter les filtres ne dit
    /// donc pas s'ils protegent.
    pub fn describe_filters(&self, provider: &GUID, layers: &[GUID]) -> Result<Vec<(u64, u32)>> {
        Ok(self
            .enumerate_named(provider, layers)?
            .into_iter()
            .map(|f| (f.id, f.flags))
            .collect())
    }

    /// Les filtres d'un provider, avec leur NOM, sur les couches donnees.
    ///
    /// Sert a retrouver un filtre pose par une AUTRE execution - typiquement un
    /// filtre persistant rejoue par BFE apres un redemarrage, dont l'identifiant
    /// d'execution a change.
    pub fn enumerate_named(&self, provider: &GUID, layers: &[GUID]) -> Result<Vec<FiltreVu>> {
        let mut out = Vec::new();
        for layer in layers {
            out.extend(self.enumerate_filters(provider, layer)?);
        }
        Ok(out)
    }

    fn enumerate_filter_ids(&self, provider: &GUID, layer: &GUID) -> Result<Vec<u64>> {
        Ok(self
            .enumerate_filters(provider, layer)?
            .into_iter()
            .map(|f| f.id)
            .collect())
    }

    fn enumerate_filters(&self, provider: &GUID, layer: &GUID) -> Result<Vec<FiltreVu>> {
        const BATCH: u32 = 64;

        let mut provider_key = *provider;
        let template = FWPM_FILTER_ENUM_TEMPLATE0 {
            providerKey: &mut provider_key,
            layerKey: *layer,
            // Sans condition dans le gabarit, "overlapping" retient tous les
            // filtres du layer qui appartiennent au provider.
            enumType: FWP_FILTER_ENUM_OVERLAPPING,
            actionMask: u32::MAX,
            ..Default::default()
        };

        let mut enum_handle: HANDLE = std::ptr::null_mut();
        check(
            // SAFETY: `template` vit jusqu'a la fin de l'appel et pointe sur
            // `provider_key`, local lui aussi; `enum_handle` est une sortie.
            unsafe { FwpmFilterCreateEnumHandle0(self.handle, &template, &mut enum_handle) },
            "FwpmFilterCreateEnumHandle0",
        )?;

        let mut ids: Vec<FiltreVu> = Vec::new();
        let mut erreur = None;
        loop {
            let mut entries: *mut *mut FWPM_FILTER0 = std::ptr::null_mut();
            let mut returned: u32 = 0;
            // SAFETY: `enum_handle` provient d'une creation reussie; `entries`
            // recoit un tableau alloue par WFP, libere ci-dessous.
            let code = unsafe {
                FwpmFilterEnum0(self.handle, enum_handle, BATCH, &mut entries, &mut returned)
            };
            if code != ERROR_SUCCESS {
                erreur = Some(format!("FwpmFilterEnum0: erreur Win32 {code} ({code:#x})"));
                break;
            }
            if returned > 0 && !entries.is_null() {
                for i in 0..returned as usize {
                    // SAFETY: WFP garantit `returned` pointeurs valides.
                    let filter = unsafe { *entries.add(i) };
                    if !filter.is_null() {
                        // SAFETY: pointeur non nul rendu par l'enumeration, dont
                        // le champ `displayData.name` est une chaine large
                        // terminee par zero ou un pointeur nul.
                        ids.push(unsafe {
                            FiltreVu {
                                id: (*filter).filterId,
                                flags: (*filter).flags,
                                nom: depuis_large((*filter).displayData.name),
                            }
                        });
                    }
                }
            }
            if !entries.is_null() {
                // SAFETY: tableau alloue par FwpmFilterEnum0.
                unsafe { FwpmFreeMemory0(&mut (entries as *mut c_void)) };
            }
            if returned < BATCH {
                break;
            }
        }

        // SAFETY: le handle est referme quel que soit le chemin de sortie.
        unsafe { FwpmFilterDestroyEnumHandle0(self.handle, enum_handle) };

        match erreur {
            Some(e) => Err(Error::Firewall(e)),
            None => Ok(ids),
        }
    }

    pub fn add_filter(&self, filter: &FWPM_FILTER0) -> Result<u64> {
        let mut id: u64 = 0;
        // SAFETY: `filter` et tout ce qu'il pointe restent vivants pendant
        // l'appel, cf. FilterBuilder.
        let code = unsafe { FwpmFilterAdd0(self.handle, filter, std::ptr::null_mut(), &mut id) };
        check(code, "FwpmFilterAdd0")?;
        Ok(id)
    }
}

/// Les codes WFP viennent de `Win32::Foundation`, ou windows-sys les expose en
/// `HRESULT` signes, alors que les fonctions `Fwpm*` renvoient un `u32`. Les
/// redeclarer a la main a deja produit un bug: les valeurs devinees decalaient
/// provider et sublayer d'un cran, et un desarmement normal remontait comme une
/// erreur fatale.
mod codes {
    use windows_sys::Win32::Foundation::{
        FWP_E_FILTER_NOT_FOUND, FWP_E_IN_USE, FWP_E_NOT_FOUND, FWP_E_PROVIDER_NOT_FOUND,
        FWP_E_SUBLAYER_NOT_FOUND,
    };

    /// Distinct de `NOT_FOUND`, que WFP reserve a d'autres objets. Retirer un
    /// filtre deja absent n'est pas un echec: l'objectif est qu'il n'en reste
    /// aucun, pas qu'il y en ait eu un a retirer.
    pub const FILTER_NOT_FOUND: u32 = FWP_E_FILTER_NOT_FOUND as u32;
    pub const PROVIDER_NOT_FOUND: u32 = FWP_E_PROVIDER_NOT_FOUND as u32;
    pub const SUBLAYER_NOT_FOUND: u32 = FWP_E_SUBLAYER_NOT_FOUND as u32;
    pub const NOT_FOUND: u32 = FWP_E_NOT_FOUND as u32;
    pub const IN_USE: u32 = FWP_E_IN_USE as u32;
}

fn tolerate_not_found(code: u32, what: &str) -> Result<()> {
    match code {
        ERROR_SUCCESS
        | codes::FILTER_NOT_FOUND
        | codes::PROVIDER_NOT_FOUND
        | codes::SUBLAYER_NOT_FOUND
        | codes::NOT_FOUND => Ok(()),
        codes::IN_USE => Err(Error::Firewall(format!(
            "{what}: objet encore reference. Les filtres n'ont pas tous ete \
             supprimes avant le sublayer."
        ))),
        _ => Err(Error::Firewall(format!(
            "{what}: erreur Win32 {code} ({code:#x})"
        ))),
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            // SAFETY: le handle provient d'un FwpmEngineOpen0 reussi et n'est
            // ferme qu'une fois.
            unsafe { FwpmEngineClose0(self.handle) };
        }
    }
}

/// Identifiant d'application obtenu par `FwpmGetAppIdFromFileName0`.
///
/// WFP attend un chemin NT (`\device\harddiskvolume...`), pas un chemin DOS.
/// Un filtre construit avec un chemin DOS ne matche jamais: c'est un piege
/// documente qui produit un kill switch qui bloque tout, y compris le daemon.
pub struct AppId {
    blob: *mut FWP_BYTE_BLOB,
}

impl AppId {
    pub fn from_path(path: &Path) -> Result<Self> {
        let wide: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let mut blob: *mut FWP_BYTE_BLOB = std::ptr::null_mut();
        // SAFETY: `wide` est une chaine UTF-16 terminee par zero; `blob` recoit
        // une allocation WFP liberee dans Drop.
        let code = unsafe { FwpmGetAppIdFromFileName0(wide.as_ptr(), &mut blob) };
        check(
            code,
            &format!("FwpmGetAppIdFromFileName0({})", path.display()),
        )?;
        if blob.is_null() {
            return Err(Error::Firewall(format!(
                "FwpmGetAppIdFromFileName0 a reussi sans renvoyer d'identifiant \
                 pour {}",
                path.display()
            )));
        }
        Ok(Self { blob })
    }

    pub fn as_ptr(&self) -> *mut FWP_BYTE_BLOB {
        self.blob
    }
}

impl Drop for AppId {
    fn drop(&mut self) {
        if !self.blob.is_null() {
            // SAFETY: `blob` a ete alloue par FwpmGetAppIdFromFileName0.
            unsafe { FwpmFreeMemory0(&mut (self.blob as *mut c_void)) };
        }
    }
}

/// Descripteur de securite designant l'identite autorisee a matcher un filtre.
///
/// WFP ne compare pas un SID: il fait un controle d'acces du token du processus
/// qui ouvre la connexion contre le DACL de ce descripteur, en demandant le
/// droit `FWP_ACTRL_MATCH_FILTER`. Seul un processus dont le token porte le SID
/// autorise passe le controle.
///
/// L'identite retenue est le SID de SERVICE du token quand il y en a un, et
/// celui de l'utilisateur sinon. C'est le choix de WireGuard for Windows, et il
/// est plus fin qu'il n'y parait: sous LocalSystem, tous les services de la
/// machine partagent `S-1-5-18`, donc retenir le SID d'utilisateur reviendrait a
/// laisser n'importe quel service franchir le kill switch. Le SID de service,
/// lui, designe CE service et lui seul.
///
/// Le repli sur l'utilisateur n'est pas une tolerance mais le mode console: le
/// daemon lance a la main pour un autotest n'a pas de SID de service, et doit
/// quand meme pouvoir poser ses filtres.
pub struct SecurityDescriptor {
    /// Allocation de `ConvertStringSecurityDescriptorToSecurityDescriptorW`,
    /// liberee par `LocalFree`.
    sd: PSECURITY_DESCRIPTOR,
    /// WFP veut un pointeur vers un blob qui pointe vers le descripteur, pas
    /// vers le descripteur lui-meme.
    blob: Box<FWP_BYTE_BLOB>,
}

impl SecurityDescriptor {
    /// Descripteur correspondant a l'identite demandee par le plan.
    pub fn for_identity(identity: &Identity) -> Result<Self> {
        let sid = match identity {
            Identity::Current => identite_courante()?.0,
            Identity::Sid(sid) => sid.clone(),
        };
        let sd = Self::from_sddl(&matching_sddl(&sid))?;
        tracing::debug!(%sid, "identite retenue pour la condition ALE_USER_ID");
        Ok(sd)
    }

    fn from_sddl(sddl: &str) -> Result<Self> {
        let text = wide(sddl);
        let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        let mut size: u32 = 0;
        // SAFETY: `text` est une chaine UTF-16 terminee par zero; `sd` et `size`
        // pointent sur des variables locales valides.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                &mut size,
            )
        };
        if ok == 0 || sd.is_null() {
            return Err(Error::Firewall(format!(
                "ConvertStringSecurityDescriptorToSecurityDescriptorW({sddl}): \
                 erreur Win32 {} ({:#x})",
                last_error(),
                last_error()
            )));
        }
        // Le descripteur rendu est auto-relatif, c'est ce que WFP attend: il le
        // copie tel quel, sans suivre de pointeur interne.
        let blob = Box::new(FWP_BYTE_BLOB {
            size,
            data: sd as *mut u8,
        });
        Ok(Self { sd, blob })
    }

    pub fn as_ptr(&mut self) -> *mut FWP_BYTE_BLOB {
        &mut *self.blob
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        if !self.sd.is_null() {
            // SAFETY: allocation de ConvertStringSecurityDescriptorToSecurityDescriptorW.
            unsafe { LocalFree(self.sd as HLOCAL) };
        }
    }
}

/// SDDL d'un descripteur dont le DACL n'accorde qu'a `sid` le seul droit que
/// WFP demande lors du controle d'acces.
///
/// Ni proprietaire ni groupe: le controle d'acces de WFP ne consulte que le
/// DACL, et un `O:`/`G:` inutile masquerait ce que la chaine exprime vraiment.
fn matching_sddl(sid: &str) -> String {
    format!("D:(A;;0x{FWP_ACTRL_MATCH_FILTER:x};;;{sid})")
}

/// Identite que le plan doit retenir, et si elle vient d'un SID de service.
///
/// Publique pour que le daemon puisse l'annoncer au demarrage: c'est la seule
/// facon de constater, sur une machine reelle, que le passage en service a bien
/// change l'identite du filtre. Un changement invisible dans un journal est un
/// changement qu'on croit sur parole.
pub fn identite_courante() -> Result<(String, bool)> {
    match service_sid()? {
        Some(sid) => Ok((sid, true)),
        None => Ok((current_user_sid()?, false)),
    }
}

/// SID de service porte par le token du processus, s'il y en a un.
///
/// Un processus lance par le gestionnaire de services porte dans ses GROUPES un
/// SID `S-1-5-80-<hachage du nom>`. Un processus lance a la main, meme
/// administrateur, n'en a aucun: `None` est donc le cas normal en console, pas
/// une erreur.
fn service_sid() -> Result<Option<String>> {
    // SAFETY: le handle et le tampon sont liberes sur tous les chemins de
    // sortie, et les tailles viennent de l'API elle-meme.
    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return Err(Error::Firewall(format!(
                "OpenProcessToken: erreur Win32 {}",
                last_error()
            )));
        }

        let mut needed: u32 = 0;
        GetTokenInformation(token, TokenGroups, std::ptr::null_mut(), 0, &mut needed);
        // Tampon aligne sur u64: TOKEN_GROUPS contient des pointeurs.
        let mut buffer = vec![0u64; (needed as usize).div_ceil(8).max(1)];
        let ok = GetTokenInformation(
            token,
            TokenGroups,
            buffer.as_mut_ptr() as *mut c_void,
            needed,
            &mut needed,
        );
        let err = last_error();
        CloseHandle(token);
        if ok == 0 {
            return Err(Error::Firewall(format!(
                "GetTokenInformation(TokenGroups): erreur Win32 {err}"
            )));
        }

        let groupes = &*(buffer.as_ptr() as *const TOKEN_GROUPS);
        let entrees =
            std::slice::from_raw_parts(groupes.Groups.as_ptr(), groupes.GroupCount as usize);
        for entree in entrees {
            if entree.Sid.is_null() {
                continue;
            }
            let autorite = (*GetSidIdentifierAuthority(entree.Sid)).Value;
            let n = *GetSidSubAuthorityCount(entree.Sid) as u32;
            let sous: Vec<u32> = (0..n).map(|i| *GetSidSubAuthority(entree.Sid, i)).collect();
            if crate::wfp_plan::est_sid_de_service(autorite, &sous) {
                return Ok(Some(sid_en_texte(entree.Sid)?));
            }
        }
        Ok(None)
    }
}

/// Forme textuelle d'un SID.
///
/// # Safety
///
/// `psid` doit pointer sur un SID valide.
unsafe fn sid_en_texte(psid: PSID) -> Result<String> {
    let mut text: PWSTR = std::ptr::null_mut();
    // SAFETY: le contrat de la fonction garantit la validite de `psid`, et
    // l'allocation rendue est liberee avant de sortir.
    unsafe {
        if ConvertSidToStringSidW(psid, &mut text) == 0 || text.is_null() {
            return Err(Error::Firewall(format!(
                "ConvertSidToStringSidW: erreur Win32 {}",
                last_error()
            )));
        }
        let mut len = 0usize;
        while *text.add(len) != 0 {
            len += 1;
        }
        let sid = String::from_utf16_lossy(std::slice::from_raw_parts(text, len));
        LocalFree(text as HLOCAL);
        Ok(sid)
    }
}

/// SID de l'utilisateur du processus courant, sous sa forme textuelle.
fn current_user_sid() -> Result<String> {
    // SAFETY: chaque handle et chaque allocation est liberee sur tous les
    // chemins de sortie; les tailles de tampon viennent de l'API elle-meme.
    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return Err(Error::Firewall(format!(
                "OpenProcessToken: erreur Win32 {}",
                last_error()
            )));
        }

        // Premier appel a vide pour connaitre la taille: un TOKEN_USER contient
        // un pointeur vers un SID de longueur variable place a sa suite.
        let mut needed: u32 = 0;
        GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut needed);
        // Tampon de u64 et non de u8: TOKEN_USER contient un pointeur, le
        // relire depuis un tampon mal aligne serait un comportement indefini.
        let mut buffer = vec![0u64; (needed as usize).div_ceil(8).max(1)];
        let ok = GetTokenInformation(
            token,
            TokenUser,
            buffer.as_mut_ptr() as *mut c_void,
            needed,
            &mut needed,
        );
        let err = last_error();
        CloseHandle(token);
        if ok == 0 {
            return Err(Error::Firewall(format!(
                "GetTokenInformation(TokenUser): erreur Win32 {err}"
            )));
        }

        let user = &*(buffer.as_ptr() as *const TOKEN_USER);
        sid_en_texte(user.User.Sid)
    }
}

fn last_error() -> u32 {
    // SAFETY: lecture d'une valeur par thread, sans effet de bord.
    unsafe { GetLastError() }
}

/// Tampons references par les conditions d'un filtre.
///
/// Les unions WFP stockent des POINTEURS pour les valeurs larges (u64,
/// adresses, blobs). Les cibles doivent rester valides jusqu'a la fin de
/// `FwpmFilterAdd0`. Chaque valeur est donc placee dans un `Box`, dont l'adresse
/// ne bouge plus meme si le vecteur qui le contient est reallocue.
// clippy::vec_box est une bonne regle en general et un contresens ici. Sans le
// Box, ajouter une valeur peut reallouer le vecteur et DEPLACER les valeurs
// precedentes, alors que des pointeurs vers elles ont deja ete remis a WFP. Le
// Box garantit que la cible ne bouge plus, seul le pointeur du Box se deplace.
#[allow(clippy::vec_box)]
#[derive(Default)]
pub struct Storage {
    u64s: Vec<Box<u64>>,
    v4: Vec<Box<FWP_V4_ADDR_AND_MASK>>,
    v6: Vec<Box<FWP_V6_ADDR_AND_MASK>>,
    app_ids: Vec<AppId>,
    sds: Vec<SecurityDescriptor>,
    pub names: Vec<Vec<u16>>,
}

impl Storage {
    pub fn u64(&mut self, value: u64) -> *mut u64 {
        self.u64s.push(Box::new(value));
        &mut **self.u64s.last_mut().expect("vient d'etre insere")
    }

    pub fn v4(&mut self, addr: u32, mask: u32) -> *mut FWP_V4_ADDR_AND_MASK {
        self.v4.push(Box::new(FWP_V4_ADDR_AND_MASK { addr, mask }));
        &mut **self.v4.last_mut().expect("vient d'etre insere")
    }

    pub fn v6(&mut self, addr: [u8; 16], prefix_length: u8) -> *mut FWP_V6_ADDR_AND_MASK {
        self.v6.push(Box::new(FWP_V6_ADDR_AND_MASK {
            addr,
            prefixLength: prefix_length,
        }));
        &mut **self.v6.last_mut().expect("vient d'etre insere")
    }

    pub fn app_id(&mut self, path: &Path) -> Result<*mut FWP_BYTE_BLOB> {
        let id = AppId::from_path(path)?;
        let ptr = id.as_ptr();
        self.app_ids.push(id);
        Ok(ptr)
    }

    pub fn user_id(&mut self, identity: &Identity) -> Result<*mut FWP_BYTE_BLOB> {
        self.sds.push(SecurityDescriptor::for_identity(identity)?);
        Ok(self.sds.last_mut().expect("vient d'etre insere").as_ptr())
    }

    pub fn name(&mut self, s: &str) -> *mut u16 {
        self.names.push(wide(s));
        self.names
            .last_mut()
            .expect("vient d'etre insere")
            .as_mut_ptr()
    }
}

/// Construit une valeur de condition typee.
pub fn cond_u8(value: u8) -> FWP_CONDITION_VALUE0 {
    FWP_CONDITION_VALUE0 {
        r#type: FWP_UINT8,
        Anonymous: FWP_CONDITION_VALUE0_0 { uint8: value },
    }
}

pub fn cond_u16(value: u16) -> FWP_CONDITION_VALUE0 {
    FWP_CONDITION_VALUE0 {
        r#type: FWP_UINT16,
        Anonymous: FWP_CONDITION_VALUE0_0 { uint16: value },
    }
}

pub fn cond_u32(value: u32) -> FWP_CONDITION_VALUE0 {
    FWP_CONDITION_VALUE0 {
        r#type: FWP_UINT32,
        Anonymous: FWP_CONDITION_VALUE0_0 { uint32: value },
    }
}

pub fn cond_u64(ptr: *mut u64) -> FWP_CONDITION_VALUE0 {
    FWP_CONDITION_VALUE0 {
        r#type: FWP_UINT64,
        Anonymous: FWP_CONDITION_VALUE0_0 { uint64: ptr },
    }
}

pub fn cond_v4(ptr: *mut FWP_V4_ADDR_AND_MASK) -> FWP_CONDITION_VALUE0 {
    FWP_CONDITION_VALUE0 {
        r#type: FWP_V4_ADDR_MASK,
        Anonymous: FWP_CONDITION_VALUE0_0 { v4AddrMask: ptr },
    }
}

pub fn cond_v6(ptr: *mut FWP_V6_ADDR_AND_MASK) -> FWP_CONDITION_VALUE0 {
    FWP_CONDITION_VALUE0 {
        r#type: FWP_V6_ADDR_MASK,
        Anonymous: FWP_CONDITION_VALUE0_0 { v6AddrMask: ptr },
    }
}

pub fn cond_blob(ptr: *mut FWP_BYTE_BLOB) -> FWP_CONDITION_VALUE0 {
    FWP_CONDITION_VALUE0 {
        r#type: FWP_BYTE_BLOB_TYPE,
        Anonymous: FWP_CONDITION_VALUE0_0 { byteBlob: ptr },
    }
}

/// Condition portant un descripteur de securite, pour `ALE_USER_ID`.
///
/// Le membre d'union est `sd`, distinct de `byteBlob` bien que les deux soient
/// des `FWP_BYTE_BLOB*`: c'est le type declare qui indique a WFP de faire un
/// controle d'acces au lieu d'une comparaison d'octets.
pub fn cond_sd(ptr: *mut FWP_BYTE_BLOB) -> FWP_CONDITION_VALUE0 {
    FWP_CONDITION_VALUE0 {
        r#type: FWP_SECURITY_DESCRIPTOR_TYPE,
        Anonymous: FWP_CONDITION_VALUE0_0 { sd: ptr },
    }
}

/// Poids d'un filtre, au format `FWP_UINT8` comme WireGuard for Windows.
pub fn filter_weight(weight: u8) -> FWP_VALUE0 {
    FWP_VALUE0 {
        r#type: FWP_UINT8,
        Anonymous: FWP_VALUE0_0 { uint8: weight },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Le droit demande par WFP lors du controle d'acces vaut 1. Si la valeur
    /// changeait de forme dans le SDDL, le DACL n'accorderait plus le bon droit
    /// et le filtre ne matcherait jamais, sans que rien n'echoue a la pose.
    #[test]
    fn le_sddl_n_accorde_que_le_droit_de_matcher() {
        let sddl = matching_sddl("S-1-5-21-1-2-3-1001");
        assert_eq!(sddl, "D:(A;;0x1;;;S-1-5-21-1-2-3-1001)");
    }

    /// Le chemin complet, du token jusqu'au descripteur auto-relatif. Ne demande
    /// aucun privilege: il tourne en integration continue.
    #[test]
    fn le_descripteur_de_l_utilisateur_courant_se_construit() {
        let sid = current_user_sid().expect("SID de l'utilisateur courant");
        assert!(sid.starts_with("S-1-"), "SID inattendu: {sid}");

        let mut sd = SecurityDescriptor::for_identity(&Identity::Current).expect("descripteur");
        // SAFETY: le blob vient d'etre construit et vit dans `sd`.
        let blob = unsafe { *sd.as_ptr() };
        assert!(blob.size > 0, "descripteur de taille nulle");
        assert!(!blob.data.is_null());
    }

    /// Ce que `FwpmGetAppIdFromFileName0` rend REELLEMENT, mesure sur l'hote
    /// qui execute la recette et non recopie d'une page de documentation.
    ///
    /// Deux affirmations en dependent ailleurs dans le depot et aucune n'etait
    /// mesuree. La premiere: la condition `ALE_APP_ID` porte un chemin NT en
    /// minuscules, ce que le banc de mesure cherche dans le dump `netsh`. La
    /// seconde: l'appel OUVRE le fichier, donc refuse un chemin qui ne designe
    /// rien, ce sur quoi `plan_telemetrie::plan_sonde_binaire` fonde son refus
    /// d'existence. La seconde est dans la recette suivante.
    #[test]
    fn l_identifiant_d_application_est_un_chemin_nt_en_minuscules() {
        let exe = std::env::current_exe().expect("le binaire de la recette existe");
        let id = AppId::from_path(&exe).expect("un fichier qui existe");
        // SAFETY: le blob vient d'un appel reussi et vit dans `id`.
        let blob = unsafe { *id.as_ptr() };
        assert!(blob.size > 0 && !blob.data.is_null(), "identifiant vide");
        // SAFETY: WFP rend `size` octets, soit une chaine UTF-16 terminee par
        // zero. On la relit telle quelle.
        let mots: &[u16] = unsafe {
            std::slice::from_raw_parts(blob.data as *const u16, (blob.size / 2) as usize)
        };
        let texte = String::from_utf16_lossy(mots);
        let texte = texte.trim_end_matches('\0');

        assert!(
            texte.starts_with("\\device\\"),
            "attendu un chemin NT, obtenu {texte:?}. Tout le reste du chantier \
             cherche cette forme dans les dumps netsh"
        );
        assert_eq!(
            texte,
            texte.to_lowercase(),
            "attendu un chemin en minuscules, obtenu {texte:?}: une comparaison \
             sensible a la casse dans un banc rendrait un faux negatif"
        );
        let feuille = exe
            .file_name()
            .expect("un binaire a un nom")
            .to_string_lossy()
            .to_lowercase();
        assert!(
            texte.ends_with(&feuille),
            "{texte:?} ne finit pas par {feuille:?}: l'identifiant ne designe pas \
             le fichier demande"
        );
    }

    /// Le refus sur lequel `plan_sonde_binaire` s'appuie pour dire ce qu'il
    /// attendait au lieu de laisser remonter un code WFP.
    #[test]
    fn l_identifiant_d_application_refuse_un_fichier_absent() {
        let absent = std::env::temp_dir().join("bifrost-appid-qui-n-existe-pas.exe");
        assert!(!absent.is_file(), "le temoin doit etre absent");
        let erreur = match AppId::from_path(&absent) {
            Ok(_) => panic!(
                "FwpmGetAppIdFromFileName0 a accepte un fichier absent: le refus \
                 d'existence de plan_sonde_binaire repose sur le contraire"
            ),
            Err(e) => e.to_string(),
        };
        assert!(
            erreur.contains("FwpmGetAppIdFromFileName0"),
            "le message doit nommer l'appel qui a refuse: {erreur}"
        );
    }

    /// Sans ce test, une erreur de construction du SDDL passerait pour un
    /// descripteur valide et produirait un filtre qui n'autorise personne.
    #[test]
    fn un_sddl_invalide_remonte_une_erreur() {
        let err = match SecurityDescriptor::from_sddl("ceci n'est pas un SDDL") {
            Ok(_) => panic!("un SDDL invalide doit echouer"),
            Err(e) => e.to_string(),
        };
        assert!(err.contains("ConvertStringSecurityDescriptor"), "{err}");
    }
}
