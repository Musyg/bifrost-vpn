//! Construction de la coquille Tauri.
//!
//! # Pourquoi ce build.rs n'est pas un simple `tauri_build::build()`
//!
//! Tauri exige des icones que la regle du depot interdit de versionner (aucun
//! binaire). On les ENGENDRE au build, hors de l'arbre versionne, et on ne
//! stocke jamais un octet d'icone dans le depot.
//!
//! Deux exigences de tauri-build et de `generate_context!`:
//!
//! 1. `generate_context!` embarque une icone de fenetre par defaut. Sous
//!    Windows il prend un `.ico` s'il en trouve un dans `bundle.icon`, sinon un
//!    `.png`; sous Unix il exige un `.png` RGBA. On ne met donc QU'UN `.png`
//!    dans `bundle.icon` (chemin `target/gen-icons/icon.png`), pris par les deux
//!    plateformes, engendre ici avant que le macro ne le lise.
//! 2. Sur Windows, `tauri-build` compile une ressource Windows et exige un
//!    `.ico` EXISTANT, sans moyen de sauter l'etape. On l'engendre dans
//!    `OUT_DIR` et on le pointe par `WindowsAttributes::window_icon_path`.
//!
//! # D'ou vient l'icone
//!
//! Le dessin n'est pas dans ce fichier: il vient du crate `bifrost-icone`,
//! source unique partagee par la coquille (fenetre et tray) et par le binaire
//! `bifrost-icone`. `bifrost_icone::png` et `bifrost_icone::ico` engendrent le
//! PNG et le `.ico` a la main (aucune dependance ajoutee au lock des binaires
//! privilegies). Le PNG de fenetre est engendre en 32x32 (et non 16):
//! `generate_context!` en fait l'icone de fenetre par defaut, que l'OS agrandit
//! pour la barre des taches et Alt-Tab; 32 rend mieux que 16 a ces tailles, et
//! le tray garde son propre 16 via `bifrost_icone::rgba_tray`.
//!
//! `gui/target/` n'est pas versionne (.gitignore) et la garde
//! `la_coquille_n_embarque_aucun_binaire` (`bifrost-coquille`, recette
//! `gui_conf.rs`) ignore `target`: rien de tout cela n'entre dans le depot.

use std::path::PathBuf;

/// Cote du PNG de fenetre engendre pour `generate_context!`.
const COTE_FENETRE: u32 = 32;

fn main() {
    let manifeste =
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR fourni"));
    // Chemin resolu de la meme facon que `generate_context!` (relatif au dossier
    // de tauri.conf.json, ici la racine de la coquille), pour que le macro
    // retrouve exactement ce que l'on ecrit.
    let dossier_icones = manifeste.join("target").join("gen-icons");
    std::fs::create_dir_all(&dossier_icones)
        .unwrap_or_else(|e| panic!("creation de {}: {e}", dossier_icones.display()));
    let png = dossier_icones.join("icon.png");
    std::fs::write(&png, bifrost_icone::png(COTE_FENETRE))
        .unwrap_or_else(|e| panic!("ecriture de {}: {e}", png.display()));

    let cible_windows = std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows");
    if cible_windows {
        let out = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR fourni par cargo"));
        let ico = out.join("bifrost.ico");
        std::fs::write(&ico, bifrost_icone::ico(bifrost_icone::COTES_ICO))
            .unwrap_or_else(|e| panic!("ecriture de l'icone de ressource {}: {e}", ico.display()));

        let attributs = tauri_build::Attributes::new()
            .windows_attributes(tauri_build::WindowsAttributes::new().window_icon_path(&ico));
        tauri_build::try_build(attributs)
            .expect("tauri_build::try_build a echoue (coquille Windows)");
    } else {
        tauri_build::build();
    }
}
