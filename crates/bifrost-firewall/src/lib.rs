//! Kill switch multi-plateforme.
//!
//! Un trait commun ([`bifrost_core::ports::KillSwitch`]) et deux
//! implementations derriere `#[cfg]`:
//!
//! - Linux: nftables famille `inet`, policy drop, couple au fwmark de
//!   WireGuard. Voir [`linux`].
//! - Windows: WFP user-mode via la Base Filtering Engine, sublayer dedie de
//!   poids `0xFFFF` et block-all de poids 0. Voir [`windows`].
//!
//! Les deux appliquent leurs changements de facon atomique (un seul `nft -f`,
//! une transaction WFP), pour qu'il n'existe aucun instant ou une politique
//! partielle laisse passer du trafic.

use bifrost_core::Result;
use bifrost_core::ports::KillSwitch;

/// Le plan des filtres WFP, volontairement hors de `#[cfg(windows)]`: c'est de
/// la donnee pure, donc la politique de blocage Windows est testee aussi en CI
/// Linux, ou personne ne peut l'executer mais tout le monde peut la verifier.
pub mod wfp_plan;

/// Le plan de la couche 2 du document 03, pur pour la meme raison que
/// [`wfp_plan`]: bloquer la telemetrie par SID de service se verifie sur les
/// deux hotes, meme si ca ne s'applique que sur un seul.
pub mod plan_telemetrie;

/// La reconnaissance des regles nft par identite, pure et volontairement hors
/// de `#[cfg]` comme [`wfp_plan`]: ses recettes comptent sur les deux hotes.
pub mod regles_nft;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(windows)]
pub mod windows;

/// Construit le kill switch de la plateforme courante.
pub fn new() -> Result<Box<dyn KillSwitch>> {
    #[cfg(target_os = "linux")]
    {
        Ok(Box::new(linux::NftablesKillSwitch::new()))
    }
    #[cfg(windows)]
    {
        Ok(Box::new(windows::WfpKillSwitch::new()?))
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        Err(bifrost_core::Error::Unsupported(format!(
            "aucun kill switch pour {}",
            std::env::consts::OS
        )))
    }
}
