//! Les preuves de la CLI et leurs lecteurs de fichiers et de declarations.
//!
//! Bibliotheque du paquet `bifrost-cli`, pour une seule raison: que le harnais
//! de fuzzing (`fuzz/`) atteigne ces lecteurs par leur chemin de PRODUCTION,
//! sans copie ni module compile deux fois. Le binaire (`src/main.rs`) en
//! appelle les preuves, comme avant; rien d'autre ne la lit.
//!
//! Les modules des preuves y sont tous, et seulement eux: chacun nomme les
//! autres par `crate::` (le lecteur JSON strict, la declaration du daemon, son
//! protocole), et aucun ne nomme un module du binaire. Les deplacer ensemble
//! laisse chaque detail partage en `pub(crate)`.
//!
//! Ce qui est public:
//! - pour le binaire, ce qu'il appelait deja: les `verifier*` de chaque preuve
//!   et leurs rapports;
//! - pour le harnais, les lecteurs et rien de plus: `preuve_nft::Unique`, le
//!   lecteur JSON strict de toutes ces entrees; `preuve_nft::verifier_avec`, le
//!   comparateur nft hors ligne sans ses deux lectures de fichier;
//!   `declaration::analyser`, `declaration::analyser_routage` (Linux) et
//!   `declaration::analyser_routage_windows`, les lecteurs de la declaration
//!   du daemon; `plan_de_l_intention` et `plan_de_la_declaration` de
//!   `preuve_routes` (Linux pour le second) et de `preuve_routes_windows`;
//!   `preuve_dns::dbus::lire_reponse`, le lecteur des trames D-Bus de
//!   `prove dns`.

#![forbid(unsafe_code)]

/// Le lecteur de la declaration du daemon, commun a `prove nft`, `prove wfp`
/// et `prove routes`: identite du serveur, N1, mesure, N2.
pub mod declaration;
/// DNS: le plan du produit confronte au resolveur systeme. Pur et compile
/// partout, sauf la collecte, qui est Linux.
pub mod preuve_dns;
#[cfg(target_os = "linux")]
mod preuve_dns_linux;
pub mod preuve_nft;
#[cfg(target_os = "linux")]
mod preuve_nft_daemon;
#[cfg(target_os = "linux")]
mod preuve_nft_linux;
/// Regles de routage et routes: le plan du produit confronte au noyau. Pur,
/// sauf la collecte, qui est Linux.
pub mod preuve_routes;
#[cfg(target_os = "linux")]
mod preuve_routes_linux;
/// Routes et lignes d'interface: le plan du produit confronte a la table IP
/// Helper. Pur et compile partout, sauf la collecte, qui est Windows.
pub mod preuve_routes_windows;
pub mod preuve_wfp;
