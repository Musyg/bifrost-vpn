//! Chargement dynamique de `wireguard.dll`.
//!
//! WireGuardNT s'utilise ainsi et pas autrement: l'amont demande explicitement
//! un `LoadLibraryEx` suivi de `GetProcAddress` sur chaque fonction, en
//! reprenant les typedefs de `api/wireguard.h`. Il n'existe pas de bibliotheque
//! d'import a lier. Le crate `wireguard-nt` 0.5.0 existe mais est fige depuis
//! 2024, d'ou cette liaison ecrite ici (cf. `docs/SOTA-2026-07.md`).
//!
//! La DLL est chargee par CHEMIN ABSOLU, a cote du binaire. Charger par nom
//! laisserait jouer l'ordre de recherche de Windows, qui inclut des
//! repertoires qu'un utilisateur non privilegie peut parfois ecrire: un
//! processus qui tourne en administrateur et qui charge une DLL par nom est un
//! detournement de DLL en puissance.
//!
//! Le pilote lui-meme n'est installe qu'au premier `WireGuardCreateAdapter`.
//! Tant qu'on se contente de charger la DLL, rien n'est modifie sur la machine.

use std::ffi::{OsStr, c_void};
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use bifrost_core::{Error, Result};
use windows_sys::Win32::Foundation::{FreeLibrary, GetLastError, HMODULE};
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW,
};
use windows_sys::core::GUID;

/// Nom du fichier attendu a cote du binaire.
pub const DLL_NAME: &str = "wireguard.dll";

/// Handle opaque d'adaptateur rendu par le driver.
pub type AdapterHandle = *mut c_void;

/// `WIREGUARD_ADAPTER_STATE`.
pub const ADAPTER_STATE_DOWN: i32 = 0;
pub const ADAPTER_STATE_UP: i32 = 1;

type CreateAdapterFn =
    unsafe extern "system" fn(*const u16, *const u16, *const GUID) -> AdapterHandle;
type OpenAdapterFn = unsafe extern "system" fn(*const u16) -> AdapterHandle;
type CloseAdapterFn = unsafe extern "system" fn(AdapterHandle);
type GetAdapterLuidFn = unsafe extern "system" fn(AdapterHandle, *mut NET_LUID_LH);
type SetAdapterStateFn = unsafe extern "system" fn(AdapterHandle, i32) -> i32;
type SetConfigurationFn = unsafe extern "system" fn(AdapterHandle, *const u8, u32) -> i32;
/// Rend faux et pose `ERROR_MORE_DATA` quand le tampon est trop petit, en
/// ecrivant la taille requise dans `Bytes`.
type GetConfigurationFn = unsafe extern "system" fn(AdapterHandle, *mut u8, *mut u32) -> i32;
type GetRunningDriverVersionFn = unsafe extern "system" fn() -> u32;

/// `wireguard.dll` chargee, avec ses points d'entree resolus.
///
/// Tous les symboles sont resolus a la construction. Un chargement partiel
/// laisserait le daemon decouvrir un symbole manquant au milieu d'une montee de
/// tunnel, kill switch deja arme.
pub struct WireGuardNt {
    module: HMODULE,
    pub create_adapter: CreateAdapterFn,
    pub open_adapter: OpenAdapterFn,
    pub close_adapter: CloseAdapterFn,
    pub get_adapter_luid: GetAdapterLuidFn,
    pub set_adapter_state: SetAdapterStateFn,
    pub set_configuration: SetConfigurationFn,
    pub get_configuration: GetConfigurationFn,
    pub get_running_driver_version: GetRunningDriverVersionFn,
}

// SAFETY: le module reste charge tant que la structure vit, et les pointeurs de
// fonction sont sans etat. Le driver serialise lui-meme les acces par
// adaptateur.
unsafe impl Send for WireGuardNt {}

impl WireGuardNt {
    /// Chemin attendu de la DLL: a cote du binaire du daemon.
    pub fn expected_path() -> Result<PathBuf> {
        let exe = std::env::current_exe()
            .map_err(|e| Error::Tunnel(format!("chemin du binaire introuvable: {e}")))?;
        let dir = exe.parent().ok_or_else(|| {
            Error::Tunnel(format!("binaire sans repertoire parent: {}", exe.display()))
        })?;
        Ok(dir.join(DLL_NAME))
    }

    pub fn load() -> Result<Self> {
        Self::load_from(&Self::expected_path()?)
    }

    pub fn load_from(path: &Path) -> Result<Self> {
        if !path.is_file() {
            return Err(Error::Tunnel(format!(
                "{} introuvable. Le transport Windows a besoin de la DLL \
                 WireGuardNT: la recuperer depuis \
                 https://download.wireguard.com/wireguard-nt/ et deposer \
                 bin/amd64/wireguard.dll a cote du binaire, ici {}",
                DLL_NAME,
                path.display()
            )));
        }

        let wide: Vec<u16> = OsStr::new(path)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        // Chemin absolu, donc les drapeaux de recherche ne servent qu'aux
        // dependances de la DLL. SYSTEM32 seul: elles sont toutes systeme.
        // SAFETY: `wide` est une chaine UTF-16 terminee par zero.
        let module = unsafe {
            LoadLibraryExW(
                wide.as_ptr(),
                std::ptr::null_mut(),
                LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
        };
        if module.is_null() {
            return Err(Error::Tunnel(format!(
                "chargement de {} en echec: erreur Win32 {}",
                path.display(),
                last_error()
            )));
        }

        // Toute sortie en erreur a partir d'ici doit relacher le module.
        let charge = |nom: &str| -> Result<*const c_void> {
            let mut c: Vec<u8> = nom.bytes().collect();
            c.push(0);
            // SAFETY: `module` provient d'un chargement reussi, `c` est
            // terminee par zero.
            let p = unsafe { GetProcAddress(module, c.as_ptr()) };
            match p {
                Some(p) => Ok(p as *const c_void),
                None => Err(Error::Tunnel(format!(
                    "symbole {nom} absent de {}: erreur Win32 {}. La DLL n'est \
                     probablement pas celle de WireGuardNT.",
                    path.display(),
                    last_error()
                ))),
            }
        };

        let resolus = (|| -> Result<Self> {
            // SAFETY: chaque symbole est transmute vers la signature declaree
            // par api/wireguard.h, verifiee une par une contre l'en-tete amont.
            unsafe {
                Ok(Self {
                    module,
                    create_adapter: std::mem::transmute::<*const c_void, CreateAdapterFn>(charge(
                        "WireGuardCreateAdapter",
                    )?),
                    open_adapter: std::mem::transmute::<*const c_void, OpenAdapterFn>(charge(
                        "WireGuardOpenAdapter",
                    )?),
                    close_adapter: std::mem::transmute::<*const c_void, CloseAdapterFn>(charge(
                        "WireGuardCloseAdapter",
                    )?),
                    get_adapter_luid: std::mem::transmute::<*const c_void, GetAdapterLuidFn>(
                        charge("WireGuardGetAdapterLUID")?,
                    ),
                    set_adapter_state: std::mem::transmute::<*const c_void, SetAdapterStateFn>(
                        charge("WireGuardSetAdapterState")?,
                    ),
                    set_configuration: std::mem::transmute::<*const c_void, SetConfigurationFn>(
                        charge("WireGuardSetConfiguration")?,
                    ),
                    get_configuration: std::mem::transmute::<*const c_void, GetConfigurationFn>(
                        charge("WireGuardGetConfiguration")?,
                    ),
                    get_running_driver_version: std::mem::transmute::<
                        *const c_void,
                        GetRunningDriverVersionFn,
                    >(charge(
                        "WireGuardGetRunningDriverVersion",
                    )?),
                })
            }
        })();

        match resolus {
            Ok(nt) => Ok(nt),
            Err(e) => {
                // SAFETY: module charge et non encore relache.
                unsafe { FreeLibrary(module) };
                Err(e)
            }
        }
    }
}

impl Drop for WireGuardNt {
    fn drop(&mut self) {
        if !self.module.is_null() {
            // SAFETY: le module provient d'un LoadLibraryExW reussi et n'est
            // relache qu'une fois.
            unsafe { FreeLibrary(self.module) };
        }
    }
}

fn last_error() -> u32 {
    // SAFETY: lecture d'une valeur par thread, sans effet de bord.
    unsafe { GetLastError() }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Une DLL absente doit donner un message qui dit quoi faire. C'est l'etat
    /// normal d'une machine ou WireGuardNT n'a pas ete depose, et le daemon y
    /// tourne quand meme pour le kill switch.
    #[test]
    fn une_dll_absente_donne_un_message_actionnable() {
        let err = match WireGuardNt::load_from(Path::new(r"C:\bifrost-inexistant\wireguard.dll")) {
            Ok(_) => panic!("une DLL absente doit echouer"),
            Err(e) => e.to_string(),
        };
        assert!(err.contains("download.wireguard.com"), "{err}");
        assert!(err.contains("wireguard.dll"), "{err}");
    }

    /// Charger une DLL systeme qui existe mais n'exporte pas les symboles doit
    /// echouer en le disant, et surtout relacher le module. Sans cela, chaque
    /// tentative de connexion fuirait un handle.
    #[test]
    fn une_dll_sans_les_symboles_est_refusee() {
        let systeme = Path::new(r"C:\Windows\System32\kernel32.dll");
        if !systeme.is_file() {
            // Jamais PASSED par defaut: si la machine n'a pas ce fichier, le
            // test n'a rien mesure et doit le dire.
            eprintln!("SKIPPED: {} absent", systeme.display());
            return;
        }
        let err = match WireGuardNt::load_from(systeme) {
            Ok(_) => panic!("kernel32 n'exporte pas les symboles WireGuard"),
            Err(e) => e.to_string(),
        };
        assert!(err.contains("WireGuardCreateAdapter"), "{err}");
    }

    #[test]
    fn le_chemin_attendu_est_a_cote_du_binaire() {
        let attendu = WireGuardNt::expected_path().unwrap();
        // Le litteral, pas la constante: comparer `DLL_NAME` a lui-meme
        // laissait cette recette verte quel que soit son contenu.
        assert_eq!(attendu.file_name().unwrap(), "wireguard.dll");
        assert_eq!(
            attendu.parent().unwrap(),
            std::env::current_exe().unwrap().parent().unwrap()
        );
    }

    /// Les deux etats d'adaptateur, epingles sur l'enumeration amont.
    ///
    /// `WIREGUARD_ADAPTER_STATE` de `api/wireguard.h` numerote implicitement:
    /// `_DOWN` d'abord, donc 0, `_UP` ensuite, donc 1. Rien dans le code ne
    /// permet de les deduire, et rien ne les regardait: `SetAdapterState` les
    /// passe au driver sans que personne relise la valeur.
    ///
    /// L'egalite des deux serait le cas grave, et c'est celui qu'une faute de
    /// recopie produit le plus facilement. Demander la descente en passant la
    /// valeur de la montee laisse l'adaptateur EN PLACE a l'arret du tunnel:
    /// une interface vivante apres qu'on a cru la retirer, ce qui est
    /// exactement ce que le kill switch existe pour empecher.
    #[test]
    fn les_etats_d_adaptateur_sont_ceux_de_l_enumeration_amont() {
        assert_eq!(ADAPTER_STATE_DOWN, 0);
        assert_eq!(ADAPTER_STATE_UP, 1);
        assert_ne!(
            ADAPTER_STATE_DOWN, ADAPTER_STATE_UP,
            "demander la descente avec la valeur de la montee laisserait \
             l'adaptateur en place"
        );
    }
}
