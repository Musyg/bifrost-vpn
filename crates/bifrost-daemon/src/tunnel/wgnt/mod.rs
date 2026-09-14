//! Liaison WireGuardNT: le transport WireGuard sous Windows.
//!
//! Deux moities, separees expres.
//!
//! [`config`] produit le blob de configuration attendu par le driver. C'est de
//! la donnee pure, sans un seul appel Windows, donc c'est teste partout, y
//! compris en integration continue Linux. C'est voulu: la disposition
//! d'octets est la partie ou une erreur ne se voit pas. Un champ decale d'un
//! octet donne un tunnel qui monte et ne transporte rien, sans message.
//!
//! [`dll`] charge `wireguard.dll` et resout ses points d'entree. Cette moitie
//! ne peut pas etre eprouvee sans la DLL: ce qui l'est, c'est son comportement
//! quand elle est absente ou quand ce n'est pas la bonne.

pub mod config;
pub mod routes;

#[cfg(windows)]
pub mod adapter;
#[cfg(windows)]
pub mod dll;
#[cfg(windows)]
pub mod e2e;
#[cfg(windows)]
pub mod ipcfg;
#[cfg(windows)]
pub mod selftest;
