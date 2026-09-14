//! Types du domaine et machine a etats du tunnel.
//!
//! Ce crate ne touche ni au reseau ni au systeme. Il decrit ce qu'il faut faire
//! (`Action`) et laisse le daemon l'executer via les traits de [`ports`]. La
//! machine a etats est donc entierement testable sans privileges.

#![forbid(unsafe_code)]

pub mod checks;
pub mod config;
/// Ce que le filtre de demarrage laisse passer. Portable a dessein: les
/// decisions qui comptent doivent etre eprouvees partout, pas seulement sous
/// Windows.
pub mod demarrage;
pub mod ports;
/// Le profil de coeur: un serveur, une technique, et de quoi s'y authentifier.
/// Pur, comme le reste du crate: il lit un lien de partage, il ne joint rien.
pub mod profil;
pub mod state;

pub use checks::{CheckOutcome, CheckReport, CheckVector, Verdict};
pub use config::{DnsPolicy, Endpoint, PeerConfig, TunnelConfig};
pub use profil::{Profil, Transport};
pub use state::{Action, Event, State, StateMachine, TunnelStatus};

/// Erreurs remontees par les implementations des traits de [`ports`].
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("kill switch: {0}")]
    Firewall(String),
    #[error("tunnel: {0}")]
    Tunnel(String),
    #[error("dns: {0}")]
    Dns(String),
    #[error("configuration invalide: {0}")]
    Config(String),
    #[error("plateforme non supportee: {0}")]
    Unsupported(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
