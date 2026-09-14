//! Lancement et pilotage des coeurs anti-censure tiers.
//!
//! La frontiere de licence est decrite dans `bifrost_evasion::coeur` et
//! verifiee par `crates/bifrost-evasion/tests/frontiere_licence.rs`. Ici, on
//! s'en tient a la consequence: un coeur est un EXECUTABLE, lance par ce
//! module et pilote par une socket. Aucun de ces modules ne charge de
//! bibliotheque tierce, ne fait de `dlopen`, et il n'existe aucun chemin de
//! code qui le permettrait.

pub mod alea;
/// Le pont entre le superviseur de tunnel, synchrone, et les coeurs,
/// asynchrones. Un canal, pas une poignee de runtime.
pub mod atelier;
/// La bascule a chaud du selecteur, qui met en service le candidat suivant
/// sans rien relancer.
pub mod bascule;
pub mod clash;
pub mod configuration;
/// Uniquement dans les binaires de debogage: un serveur de controle embarque
/// dans un produit livre serait une surface de plus sans contrepartie.
#[cfg(debug_assertions)]
pub mod doublure;
pub mod e2e;
/// L'adresse locale stable derriere laquelle les coeurs se remplacent.
pub mod facade;
pub mod identite;
pub mod lancement;

/// Le pont entre le superviseur synchrone et le passeur asynchrone.
#[cfg(any(target_os = "linux", windows))]
pub mod passage;

/// Ce qui mene le systeme du TUN a la facade.
#[cfg(any(target_os = "linux", windows))]
pub mod passeur;
pub mod port;
pub mod selftest;
pub mod socks;
pub mod superviseur;

/// La sonde aller-retour de vitalite du tunnel par coeur.
pub mod vitalite;
