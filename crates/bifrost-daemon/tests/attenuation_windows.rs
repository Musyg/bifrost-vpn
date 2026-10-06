//! Les politiques d'attenuation du daemon Windows sont EFFECTIVES dans le
//! processus qui les pose: relues par `GetProcessMitigationPolicy` apres
//! `attenuation::poser`.
//!
//! Binaire de recette a part, et seul de son espece: une politique posee ne se
//! retire plus, et celles que cette recette pose vaudraient pour toute autre
//! recette du meme processus. La politique de chargement d'images passe meme
//! aux processus qu'il cree ensuite (mesure le 02/10/2026 sur dev-windows):
//! la recette du daemon lance vit donc dans un autre binaire,
//! `attenuation_daemon_windows.rs`.
#![cfg(windows)]

#[path = "commun/attenuation.rs"]
mod attenuation_commun;

use attenuation_commun::{ATTENDUES, manquantes};
use bifrost_daemon::attenuation;

/// Apres `poser`, chaque politique se relit dans le processus qui l'a posee.
#[test]
fn les_politiques_posees_se_relisent_dans_ce_processus() {
    let moi = std::process::id();

    // Le temoin, AVANT la pose: aucune n'y est. Sans lui, une lecture qui
    // rendrait toujours les bits attendus ferait passer la recette.
    let avant = manquantes(moi).expect("lecture de ce processus");
    assert_eq!(
        avant.len(),
        ATTENDUES.len(),
        "des politiques etaient deja la avant la pose: seules manquaient {avant:?}"
    );

    let bilan = attenuation::poser();
    assert!(
        bilan.refusees.is_empty(),
        "poses refusees: {:?}",
        bilan.refus_en_clair()
    );

    let apres = manquantes(moi).expect("lecture de ce processus");
    assert!(
        apres.is_empty(),
        "politiques absentes apres la pose: {apres:?}"
    );
}
