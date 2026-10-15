//! La logique de la coquille graphique de Bifrost, celle qui se teste SANS
//! fenetre: l'etat du daemon, les commandes qu'elle lui envoie, et ce qu'elle
//! en affiche.
//!
//! # Pourquoi une bibliotheque sans fenetre
//!
//! Une bibliotheque de fenetres ne se lie pas sur chaque hote (sous Linux, il
//! lui faut les paquets de developpement de la WebView). Ici, dans un membre
//! ordinaire de l'espace de travail, sans aucune dependance graphique,
//! `recettes-strict.sh` compte cette logique sur chaque hote et dans chaque job
//! de la CI, y compris la ou une fenetre ne pourrait pas se construire.
//!
//! Trois morceaux, tous purs ou presque:
//!
//! - [`commande`]: parle au daemon par l'IPC, apres avoir exige du serveur du
//!   canal l'identite du daemon. Une seule dependance au monde (le canal),
//!   isolee derriere [`commande::Commande`].
//! - [`vue`]: fonction pure `TunnelStatus | erreur -> Vue`. Aucun effet.
//! - [`elevation`]: la DECISION de refuser une coquille elevee est pure; seule
//!   la MESURE du booleen touche a l'OS, et elle est minuscule.

pub mod commande;
pub mod elevation;
pub mod vue;

pub use commande::{Commande, ErreurCommande};
pub use vue::{CouleurTray, EtatKillSwitch, EtatVue, Vue};
