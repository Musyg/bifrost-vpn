//! L'icone du tray, construite EN MEMOIRE depuis la MEME source que l'icone de
//! Bifrost.
//!
//! Aucun fichier binaire n'entre dans le depot: `bifrost_icone::rgba_tray`
//! engendre les octets RGBA du tray (le meme pont que l'icone de Bifrost, dans
//! la couleur d'etat), et `Image::new_owned` les possede. Une seule source de
//! dessin sert la fenetre (`build.rs`), le tray (ici) et les fichiers d'icone
//! du binaire `bifrost-icone`. La garde `la_coquille_n_embarque_aucun_binaire`
//! (`bifrost-coquille`, recette `gui_conf.rs`) rougit si un .png ou un .ico
//! apparaissait dans `gui/`.

use bifrost_coquille::vue::CouleurTray;
use bifrost_icone::Teinte;
use tauri::image::Image;

/// Cote de l'icone, en pixels. 16 est la taille d'un tray sous Windows.
const COTE: u32 = 16;

/// La teinte d'etat de l'icone pour une couleur de Vue donnee.
fn teinte_de(couleur: CouleurTray) -> Teinte {
    match couleur {
        CouleurTray::Vert => Teinte::Vert,
        CouleurTray::Gris => Teinte::Gris,
        CouleurTray::Rouge => Teinte::Rouge,
    }
}

/// L'image du tray pour une couleur donnee, allouee et possedee (`'static`).
pub fn image_pour(couleur: CouleurTray) -> Image<'static> {
    let pixels = bifrost_icone::rgba_tray(COTE, teinte_de(couleur));
    Image::new_owned(pixels, COTE, COTE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bifrost_coquille::vue::Vue;

    #[test]
    fn chaque_couleur_donne_une_image_de_la_bonne_taille() {
        for couleur in [CouleurTray::Vert, CouleurTray::Gris, CouleurTray::Rouge] {
            let image = image_pour(couleur);
            assert_eq!(image.width(), COTE);
            assert_eq!(image.height(), COTE);
            assert_eq!(image.rgba().len(), (COTE * COTE * 4) as usize);
        }
    }

    /// Les trois couleurs sont distinctes: sans quoi le tray ne dirait rien.
    #[test]
    fn les_trois_couleurs_different() {
        let v = bifrost_icone::rgba_tray(COTE, Teinte::Vert);
        let g = bifrost_icone::rgba_tray(COTE, Teinte::Gris);
        let r = bifrost_icone::rgba_tray(COTE, Teinte::Rouge);
        assert_ne!(v, g);
        assert_ne!(v, r);
        assert_ne!(g, r);
    }

    /// Chaque couleur de Vue a SA teinte, et aucune autre: une erreur rendue
    /// grise par la Vue doit l'etre aussi dans le tray. Une table qui
    /// confondrait gris et vert peindrait en vert un daemon injoignable, un
    /// serveur du canal non admis ou un refus.
    #[test]
    fn chaque_couleur_a_sa_teinte_et_aucune_autre() {
        for (couleur, attendue) in [
            (CouleurTray::Vert, Teinte::Vert),
            (CouleurTray::Gris, Teinte::Gris),
            (CouleurTray::Rouge, Teinte::Rouge),
        ] {
            assert_eq!(teinte_de(couleur), attendue, "{couleur:?}");
            assert_eq!(
                image_pour(couleur).rgba(),
                bifrost_icone::rgba_tray(COTE, attendue).as_slice(),
                "{couleur:?}"
            );
        }
    }

    /// Le tray d'une erreur du poste de commande, de chaque sorte, est gris et
    /// jamais vert: le pendant, dans la coquille, de l'invariant de la Vue.
    #[test]
    fn le_tray_d_une_erreur_n_est_jamais_vert() {
        let vert = bifrost_icone::rgba_tray(COTE, Teinte::Vert);
        let gris = bifrost_icone::rgba_tray(COTE, Teinte::Gris);
        for e in crate::une_erreur_de_chaque_sorte() {
            let vue = Vue::depuis_erreur(&e);
            let image = image_pour(vue.couleur);
            assert_ne!(image.rgba(), vert.as_slice(), "erreur {e:?} peinte en vert");
            assert_eq!(image.rgba(), gris.as_slice(), "erreur {e:?}");
        }
    }

    /// Le tray et l'icone de Bifrost partagent le meme pont: leur canal alpha
    /// (la silhouette: carre arrondi et arc opaque) est identique.
    #[test]
    fn le_tray_partage_le_pont_de_l_icone() {
        let logiciel = bifrost_icone::rgba(COTE);
        let tray = bifrost_icone::rgba_tray(COTE, Teinte::Gris);
        let alpha = |v: &[u8]| {
            v.as_chunks::<4>()
                .0
                .iter()
                .map(|px| px[3])
                .collect::<Vec<u8>>()
        };
        assert_eq!(alpha(&logiciel), alpha(&tray));
    }

    /// Le PNG de fenetre que `build.rs` depose sous `target/gen-icons/icon.png`
    /// vient bien de `bifrost_icone::png(32)`, la source unique. Sans cette
    /// garde, `build.rs` pourrait reecrire une autre image (un carre gris, par
    /// exemple) sans que rien ne le remarque: la fenetre porterait alors une
    /// icone divergente du reste du logiciel. Cote 32 = `COTE_FENETRE` de
    /// `build.rs`. La recette ne tourne que la ou `gui/` compile (dev-windows /
    /// runner), apres que `build.rs` a engendre le fichier.
    #[test]
    fn le_png_de_fenetre_vient_de_la_source_unique() {
        let chemin = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("gen-icons")
            .join("icon.png");
        let sur_disque = std::fs::read(&chemin).unwrap_or_else(|e| {
            panic!(
                "{} illisible (build.rs doit l'engendrer avant les recettes): {e}",
                chemin.display()
            )
        });
        assert_eq!(
            sur_disque,
            bifrost_icone::png(32),
            "le PNG de fenetre engendre par build.rs diverge de bifrost_icone::png(32)"
        );
    }
}
