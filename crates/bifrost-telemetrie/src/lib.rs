//! Couche 1 de l'anti-telemetrie: registre, services, taches planifiees.
//!
//! Le document 03 decrit quatre couches. La DNS est livree depuis le 22 aout
//! 2026 et vit dans [`bifrost_dns::telemetrie`]. Celle-ci est la premiere des
//! trois autres, celle que le plan veut poser en premier parce qu'elle agit
//! **a la source**: on ne filtre pas un flux, on eteint ce qui le produit.
//!
//! Elle est aussi la plus fragile, et le plan le dit: une mise a jour de
//! fonctionnalite reactive DiagTrack et remet `AllowTelemetry` a sa valeur par
//! defaut. D'ou la contrainte que ce crate existe pour tenir: **tout est
//! journalise et tout se defait**.
//!
//! # Le partage pur / impur
//!
//! Ici, rien ne touche la machine. [`catalogue`] dit ce qu'il faut poser et
//! pourquoi; [`journal`] dit comment le defaire. La pose vit dans
//! `bifrost_daemon::telemetrie`, qui est Windows seulement. C'est le meme
//! partage que `bifrost_evasion::carnet` et `bifrost_daemon::carnet`, et il a
//! la meme consequence utile: les recettes du catalogue et de la reversibilite
//! tournent sur les DEUX hotes, donc elles ne s'abstiennent jamais.
//!
//! # Trois regles que ce crate impose au code qui l'emploie
//!
//! 1. **Une cible absente n'est jamais un succes.** Un service inconnu, une
//!    tache qui n'existe pas sous ce nom: [`Issue::SansObjet`], jamais
//!    "applique". Le releve du 22/08/2026 montre pourquoi ce n'est pas
//!    theorique: sur la build 26200, deux des neuf taches que le document 03
//!    nomme n'existent pas sous ce nom-la. Un moteur qui les compterait comme
//!    posees annoncerait neuf reglages pour sept reels.
//!
//! 2. **On relit apres avoir ecrit.** Poser une valeur et croire l'avoir posee
//!    sont deux choses. Winhance, defaut 281 du 29 decembre 2025, en est
//!    l'illustration: un interrupteur "Disable" qui ECRIVAIT 1. Le verdict
//!    [`Issue::Echoue`] existe pour ce cas precis - ecrit, puis relu different.
//!
//! 3. **Le journal distingue une valeur absente d'une cle absente.** Poser
//!    `AllowRecallEnablement` sur une machine ou la cle `WindowsAI` n'existe
//!    pas - le cas mesure sur essai-windows le 22/08/2026 - CREE la cle. Un
//!    retour en arriere qui se contenterait de supprimer la valeur laisserait
//!    derriere lui une cle de politique vide, donc une trace de passage. Voir
//!    [`journal::Avant`].

#![forbid(unsafe_code)]

pub mod catalogue;
pub mod journal;
pub mod taches;

pub use catalogue::{Cible, Profil, Reglage, Ruche, profil_depuis_nom, reglages};
pub use journal::{Avant, Entree, Issue, Journal};
pub use taches::{decoder_sortie, tache_activee};
