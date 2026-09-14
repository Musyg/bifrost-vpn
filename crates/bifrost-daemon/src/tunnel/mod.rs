//! Le device WireGuard et son routage.

pub mod netcfg;

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
