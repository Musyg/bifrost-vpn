//! Le device WireGuard et son routage.

pub mod netcfg;

/// Les regles et les routes que le noyau porte deja, lues avant la premiere
/// commande et autour de chaque retrait. Sa lecture des trames est pure et
/// compilee partout; le canal netlink n'existe que sous Linux.
mod occupation;

/// Les sessions de routage du produit sous Linux: le journal de ce que
/// chacune a pose, et ce qu'un montage ou un demontage en retire. Le
/// jugement est pur et compile partout; le journal et le noyau n'existent
/// que sous Linux.
pub mod session;

/// Qui entre dans le TUN et qui en sort, pour le chemin par coeur. Pur, comme
/// `netcfg`: il rend des commandes, il n'execute rien.
#[cfg(target_os = "linux")]
pub mod aiguillage;

/// Le chemin par coeur, vu comme un tunnel: la deuxieme implementation du port
/// que la machine a etats connait deja.
#[cfg(any(target_os = "linux", windows))]
pub mod coeur;

/// Interface TUN nue, pour le chemin par coeur. Sa moitie pure - la validation
/// du nom - est compilee partout pour etre testee partout; l'ouverture est
/// reservee aux plateformes qui savent le faire.
pub mod brut;

/// Liaison WireGuardNT. Sa moitie pure est compilee partout, pour etre testee
/// partout; seul le chargement de la DLL est reserve a Windows.
pub mod wgnt;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(windows)]
pub mod windows;

use bifrost_core::Result;
use bifrost_core::ports::TunnelDevice;

/// Construit le device de la plateforme courante.
pub fn new() -> Result<Box<dyn TunnelDevice>> {
    #[cfg(target_os = "linux")]
    {
        Ok(Box::new(linux::LinuxTunnel::new()))
    }
    #[cfg(windows)]
    {
        Ok(Box::new(windows::WindowsTunnel::new()?))
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        Err(bifrost_core::Error::Unsupported(format!(
            "aucun device tunnel pour {}",
            std::env::consts::OS
        )))
    }
}
