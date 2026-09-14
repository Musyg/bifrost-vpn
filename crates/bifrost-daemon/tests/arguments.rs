//! Ce que le daemon refuse sur sa seule ligne de commande.
//!
//! Ces recettes lancent le VRAI binaire, ce qu'aucun test unitaire ne peut
//! faire: la fonction qui juge peut etre juste et n'etre appelee nulle part.
//! C'est precisement ce qui s'est passe ici - le conflit d'ecoute etait
//! calculable des la ligne de commande, et personne ne le calculait.
//!
//! Elles ne demandent aucun privilege et n'ouvrent rien: le refus doit tomber
//! avant que le daemon touche a quoi que ce soit.

use std::path::PathBuf;
use std::process::Command;

fn binaire_du_daemon() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_bifrost-daemon"))
}

/// La ligne de commande exacte qui a produit la panne tardive du 20 aout 2026.
#[test]
fn une_facade_sur_le_port_socks_du_coeur_est_refusee_avant_tout() {
    let sortie = Command::new(binaire_du_daemon())
        .args(["--facade", "127.0.0.1:1080", "--coeur-socks-port", "1080"])
        .output()
        .expect("le binaire du daemon doit se lancer");
    assert!(
        !sortie.status.success(),
        "le daemon a accepte deux ecoutes sur le meme port"
    );
    let dit = String::from_utf8_lossy(&sortie.stderr);
    assert!(dit.contains("--facade"), "{dit}");
    assert!(dit.contains("--coeur-socks-port"), "{dit}");
    assert!(dit.contains("1080"), "{dit}");
}

/// Le temoin negatif: sans conflit, ce refus-la ne doit pas tomber. Sans lui,
/// un daemon qui refuserait TOUT passerait la recette precedente.
#[test]
fn sans_conflit_ce_refus_ne_tombe_pas() {
    let sortie = Command::new(binaire_du_daemon())
        .args([
            "--facade",
            "127.0.0.1:1081",
            "--coeur-socks-port",
            "1080",
            "--probe",
            "dns",
        ])
        .output()
        .expect("le binaire du daemon doit se lancer");
    let dit = String::from_utf8_lossy(&sortie.stderr);
    assert!(
        !dit.contains("demandent le meme port"),
        "refus de conflit sur une ligne de commande saine: {dit}"
    );
}
