//! Ecrit sur la sortie standard le fichier des noms refuses d'un profil.
//!
//! Pendant de `config-resolveur`, et pour la meme raison: les recettes du
//! module ne prouvent que sa coherence avec lui-meme. Seul dnscrypt-proxy dit
//! s'il accepte ce fichier, et seule une resolution reelle dit s'il le fait
//! mordre. Ce programme produit ce qu'on lui soumet.
//!
//! Usage: cargo run -p bifrost-dns --example liste-telemetrie [PROFIL]
//!   PROFIL  aucun | equilibre | strict, defaut equilibre
//!
//! Avec `--raisons`, ecrit sur la sortie d'ERREUR la raison de chaque entree,
//! pour relire une liste sans ouvrir le code.

use bifrost_core::config::ProfilTelemetrie;
use bifrost_dns::telemetrie::{blocked_names, regles};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut profil = ProfilTelemetrie::Equilibre;
    let mut raisons = false;

    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "--raisons" => raisons = true,
            "aucun" => profil = ProfilTelemetrie::Aucun,
            "equilibre" => profil = ProfilTelemetrie::Equilibre,
            "strict" => profil = ProfilTelemetrie::Strict,
            autre => return Err(format!("profil inconnu: {autre}").into()),
        }
    }

    print!("{}", blocked_names(profil));

    if raisons {
        for regle in regles(profil) {
            eprintln!("{}\n    {}\n", regle.motif, regle.pourquoi);
        }
    }
    Ok(())
}
