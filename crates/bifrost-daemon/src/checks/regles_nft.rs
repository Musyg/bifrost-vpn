//! Reconnaissance des regles nft par identite: le module a demenage (5u).
//!
//! Son contenu vit desormais dans `bifrost_firewall::regles_nft`, au niveau
//! superieur du crate et hors de tout `cfg`. Le crate qui REND les regles est
//! celui qui sait quelle forme elles ont, et `bifrost-daemon` depend de
//! `bifrost-firewall`, jamais l'inverse. Cette pelure garde le chemin
//! `checks::regles_nft::...` valide pour `checks/mod.rs`.
//!
//! Le module est pur et disponible partout, donc la re-exportation n'est plus
//! gardee par `#[cfg]`: elle compile sur les deux hotes, comme le module
//! qu'elle re-exporte. Ses usages dans `checks/mod.rs` restent, eux, sous
//! `#[cfg(target_os = "linux")]`.
pub use bifrost_firewall::regles_nft::*;
