//! Choix du protocole de contournement (objectif 2 du README).
//!
//! Ce crate ne touche ni au reseau, ni au systeme, ni a un processus tiers. Il
//! repond a une seule question, en fonction pure: **au vu de ce qu'on a
//! reellement mesure de ce reseau, dans quel ordre essayer les protocoles.**
//!
//! C'est le meme partage que pour le kill switch, ou `wfp_plan` decrit les
//! filtres sans appeler Windows. Le document 04 chiffre le superviseur a 20-30
//! jours-homme et le designe comme la piece a ecrire soi-meme, sing-box et
//! Xray etant reutilises tels quels. La politique de ce superviseur est ici,
//! testable en CI Linux sans binaire tiers, sans privileges et sans reseau.
//!
//! Ce que ce crate ne fait pas, PAR CONSTRUCTION, parce qu'il faut un socket ou
//! un processus pour cela: lancer les sondes qui remplissent
//! [`environnement::Environnement`] (le daemon le fait, voir
//! `bifrost_daemon::sondes`), lancer sing-box ou Xray, observer un flux vivant.
//!
//! Ce qui reste a faire, et qui n'est fait NULLE PART: rien, a la date de la
//! derniere relecture. Cette liste a ete VIDE une fois sans que personne ne
//! l'ecrive, et une entree de plan perime se lit comme une consigne de
//! construire ce qui existe deja - c'est pour cela qu'elle est nommee plutot
//! que supprimee.
//!
//! Ce qui a cesse d'etre a faire:
//!
//! - conduire la [`course`]. Le flux de connexion la conduit depuis le
//!   21/08/2026 au plus tard: `Supervisor::course_pour` en ouvre une par
//!   connexion par coeur et lui fait consommer le premier pas, celui que la
//!   connexion lance elle-meme; `Supervisor::encaisser` verse chaque perte
//!   qualifiee dans la course, et `Supervisor::avancer_la_course` bascule le
//!   selecteur du coeur vers le candidat suivant, paie la gigue que le plan
//!   reclame, et rend un echec GARDE quand les candidats sont epuises. Cette
//!   entree a annonce le contraire pendant plusieurs jours;
//!
//! - OBSERVER les criteres d'echec en cours de session. [`observation`] les
//!   mesure, et le superviseur du daemon lui verse les compteurs du tunnel a
//!   chaque sondage;
//! - EMETTRE la sonde aller-retour que [`observation`] reclamait. Le daemon la
//!   pose a travers le coeur, et le critere de gel conclut donc lui aussi;
//! - lancer sing-box ou Xray depuis le flux de connexion. `Connect` y mene
//!   desormais: la demarche se calcule a partir du profil recu, au lieu d'etre
//!   epinglee au demarrage du daemon sur un tunnel direct qui refusait tout
//!   profil de coeur.
//!
//! Il n'a par ailleurs aucun verbe pour armer ou desarmer le kill switch. Le
//! document 04 partie 3.2 exige qu'il ne soit jamais leve pendant une bascule;
//! l'absence du verbe rend l'exigence structurelle plutot que disciplinaire.

#![forbid(unsafe_code)]

pub mod carnet;
pub mod coeur;
pub mod course;
pub mod date;
pub mod demarche;
pub mod environnement;
pub mod memoire;
pub mod observation;
pub mod selection;
pub mod survie;
pub mod technique;

pub use carnet::{Carnet, Sondage, sondage};
pub use coeur::{Coeur, Contrainte, coeur_de, coeurs_requis};
pub use course::{Course, Echec, Pas};
pub use date::Date;
pub use demarche::{Demarche, demarche, demarche_parmi};
pub use environnement::{Environnement, Mesure};
pub use memoire::{CleReseau, MemoireReseau};
pub use observation::{Echantillon, Observateur, Perte, Verdict};
pub use selection::{Candidat, Contexte, Mode, Plan, Refus, planifier};
pub use survie::{Pays, Statut};
pub use technique::{Camouflage, Technique, Transport};
