//! Cycle de vie d'un adaptateur WireGuardNT.
//!
//! Creer un adaptateur installe le driver noyau au premier appel. C'est la
//! seule operation de ce module qui modifie la machine, et elle est
//! reversible: fermer l'adaptateur le retire.
//!
//! L'adaptateur ne porte ni adresse ni route: WireGuardNT ne fait que le
//! transport chiffre. La configuration IP se pose separement, comme cote Linux
//! ou le module noyau ignore aussi le routage.

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

use bifrost_core::{Error, Result};
use windows_sys::Win32::Foundation::{ERROR_MORE_DATA, GetLastError};
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::core::GUID;

use super::dll::{ADAPTER_STATE_DOWN, ADAPTER_STATE_UP, AdapterHandle, WireGuardNt};

/// Identifiant stable de l'adaptateur de Bifrost.
///
/// Fixe et non tire au hasard: le meme tunnel doit retrouver le meme
/// adaptateur d'une connexion a l'autre. Un GUID different a chaque montee
/// accumulerait les adaptateurs fantomes dans la configuration reseau de
/// Windows, et ferait perdre au kill switch le LUID qu'il vient d'autoriser.
/// Le MVP ne monte qu'un tunnel a la fois, un seul identifiant suffit donc.
pub const ADAPTER_GUID: GUID = GUID::from_u128(0x0bd4f5a1_6c1e_4f8d_9a3e_2f7b41c9e520);

/// Identifiants reserves a l'autotest. Distincts de celui du tunnel reel: deux
/// adaptateurs ne peuvent pas partager un GUID, et un autotest ne doit surtout
/// pas reprendre l'identite d'une connexion en cours.
pub const SELFTEST_GUID: GUID = GUID::from_u128(0x0bd4f5a1_6c1e_4f8d_9a3e_2f7b41c9e521);
pub const SELFTEST_PEER_GUID: GUID = GUID::from_u128(0x0bd4f5a1_6c1e_4f8d_9a3e_2f7b41c9e522);

/// Identifiants reserves aux vecteurs `kill-switch-on-drop` et
/// `reconnect-window`. Il en faut DEUX: la reconnexion cree le nouvel
/// adaptateur avant de detruire l'ancien, comme le produit, et deux
/// adaptateurs ne peuvent pas partager un GUID. Ils alternent donc.
pub const CHUTE_GUID: [GUID; 2] = [
    GUID::from_u128(0x0bd4f5a1_6c1e_4f8d_9a3e_2f7b41c9e523),
    GUID::from_u128(0x0bd4f5a1_6c1e_4f8d_9a3e_2f7b41c9e524),
];

/// Categorie affichee par Windows a cote de l'adaptateur.
const TUNNEL_TYPE: &str = "Bifrost";

/// Taille du premier tampon de relecture. Une interface avec un pair et
/// quelques prefixes tient largement dedans; au-dela le driver dit combien il
/// lui faut.
const READ_BUFFER: usize = 1024;

/// Nombre maximal de reprises de la relecture.
const MAX_RELECTURES: usize = 8;

/// Un adaptateur ouvert. Le referme a la liberation.
pub struct Adapter {
    nt: WireGuardNt,
    handle: AdapterHandle,
}

// SAFETY: le handle designe un objet noyau attache au PROCESSUS, pas au thread
// qui l'a cree: l'amont precise que les sockets d'un adaptateur appartiennent
// au processus qui l'active. La liaison Go officielle s'appuie sur cette
// propriete, ses goroutines changeant librement de thread systeme. Dans le
// daemon, l'adaptateur ne vit de toute facon que sur le thread du superviseur;
// ce `Send` sert a l'y deplacer une fois, pas a le partager.
unsafe impl Send for Adapter {}

impl Adapter {
    /// Cree l'adaptateur du tunnel, en installant le driver si besoin.
    pub fn create(nt: WireGuardNt, name: &str) -> Result<Self> {
        Self::create_with_guid(nt, name, &ADAPTER_GUID)
    }

    /// Comme [`Self::create`], mais sous un identifiant choisi. Sert a monter
    /// plusieurs adaptateurs en meme temps, ce que fait l'autotest.
    pub fn create_with_guid(nt: WireGuardNt, name: &str, guid: &GUID) -> Result<Self> {
        let nom = wide(name);
        let categorie = wide(TUNNEL_TYPE);
        // SAFETY: les deux chaines sont terminees par zero et vivent jusqu'a la
        // fin de l'appel; `guid` pointe sur un GUID valide.
        let handle = unsafe { (nt.create_adapter)(nom.as_ptr(), categorie.as_ptr(), guid) };
        if handle.is_null() {
            return Err(Error::Tunnel(format!(
                "creation de l'adaptateur '{name}' en echec: erreur Win32 {}. \
                 Le driver WireGuardNT s'installe au premier appel et demande \
                 les privileges administrateur.",
                last_error()
            )));
        }
        Ok(Self { nt, handle })
    }

    /// Version du driver reellement charge, au format majeur.mineur.
    pub fn driver_version(&self) -> Option<(u16, u16)> {
        // SAFETY: sans etat, ne touche pas a l'adaptateur.
        let v = unsafe { (self.nt.get_running_driver_version)() };
        if v == 0 {
            None
        } else {
            Some(((v >> 16) as u16, v as u16))
        }
    }

    pub fn luid(&self) -> u64 {
        let mut luid = NET_LUID_LH::default();
        // SAFETY: handle valide, `luid` pointe sur une union locale.
        unsafe { (self.nt.get_adapter_luid)(self.handle, &mut luid) };
        // SAFETY: `Value` est la vue u64 de l'union, valide quoi qu'on y ait
        // ecrit.
        unsafe { luid.Value }
    }

    pub fn set_configuration(&self, blob: &[u8]) -> Result<()> {
        // SAFETY: `blob` vit jusqu'a la fin de l'appel et sa taille est celle
        // annoncee.
        let ok =
            unsafe { (self.nt.set_configuration)(self.handle, blob.as_ptr(), blob.len() as u32) };
        if ok == 0 {
            return Err(Error::Tunnel(format!(
                "configuration refusee par le driver: erreur Win32 {}. Un code \
                 87 (parametre invalide) designe la disposition du blob.",
                last_error()
            )));
        }
        Ok(())
    }

    /// Relit la configuration telle que le driver la voit.
    ///
    /// L'amont precise que la taille requise peut CHANGER d'un appel a l'autre,
    /// un pair pouvant apparaitre ou disparaitre entre deux, et demande de
    /// boucler jusqu'au succes. On ne conclut donc rien d'une taille plus petite
    /// que la precedente: on garde le maximum et on reessaie. La boucle reste
    /// bornee, un pilote qui redemanderait indefiniment ne doit pas figer le
    /// daemon en silence.
    pub fn get_configuration(&self) -> Result<Vec<u8>> {
        let mut buffer = vec![0u8; READ_BUFFER];
        for _ in 0..MAX_RELECTURES {
            let mut taille = buffer.len() as u32;
            // SAFETY: `buffer` a bien `taille` octets accessibles en ecriture.
            let ok = unsafe {
                (self.nt.get_configuration)(self.handle, buffer.as_mut_ptr(), &mut taille)
            };
            if ok != 0 {
                buffer.truncate(taille as usize);
                return Ok(buffer);
            }
            let err = last_error();
            if err != ERROR_MORE_DATA {
                return Err(Error::Tunnel(format!(
                    "relecture de la configuration en echec: erreur Win32 {err}"
                )));
            }
            // `+ 1` au minimum: sans cela, un driver qui redemande la taille
            // qu'il a deja bouclerait sans jamais agrandir le tampon.
            buffer.resize((taille as usize).max(buffer.len() + 1), 0);
        }
        Err(Error::Tunnel(format!(
            "le driver redemande un tampon plus grand apres {MAX_RELECTURES} \
             tentatives: relecture abandonnee"
        )))
    }

    pub fn set_state(&self, up: bool) -> Result<()> {
        let etat = if up {
            ADAPTER_STATE_UP
        } else {
            ADAPTER_STATE_DOWN
        };
        // SAFETY: handle valide.
        let ok = unsafe { (self.nt.set_adapter_state)(self.handle, etat) };
        if ok == 0 {
            return Err(Error::Tunnel(format!(
                "passage de l'adaptateur a l'etat {} en echec: erreur Win32 {}",
                if up { "actif" } else { "inactif" },
                last_error()
            )));
        }
        Ok(())
    }
}

impl Drop for Adapter {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            // SAFETY: handle issu d'une creation reussie, ferme une seule fois.
            unsafe { (self.nt.close_adapter)(self.handle) };
        }
    }
}

fn wide(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn last_error() -> u32 {
    // SAFETY: lecture d'une valeur par thread, sans effet de bord.
    unsafe { GetLastError() }
}
