//! Icone de Bifrost, ENGENDREE et deterministe, depuis une source unique en
//! Rust.
//!
//! # Pourquoi ce crate existe
//!
//! La regle du depot interdit tout binaire versionne (gardes
//! `la_coquille_n_embarque_aucun_binaire` et `sources_ascii`). L'icone doit donc
//! etre produite a la construction, jamais stockee. Plusieurs consommateurs en
//! ont besoin: la coquille (son `build.rs` pour la fenetre et la ressource
//! Windows, son tray en memoire) et le binaire `bifrost-icone`, qui ecrit les
//! icones hicolor PNG et le `.ico` multi-tailles dans un repertoire hors du
//! depot, sur une machine qui n'a pas a compiler `gui/`. Une seule source evite
//! des dessins qui divergeraient.
//!
//! # Pourquoi aucune dependance
//!
//! `png` n'est PAS dans le lock de la racine (les binaires privilegies: daemon,
//! CLI). L'y faire entrer tirerait png + crc32fast + fdeflate + flate2 +
//! miniz_oxide. On prefere ecrire le PNG a la main (zlib << stored >> non
//! compresse, CRC32 et Adler32) et assembler l'ICO a la main: quelques centaines
//! de lignes gardees ici contre cinq crates de plus dans le lock privilegie. Le
//! determinisme est alors total et ne depend d'aucune version d'encodeur.
//!
//! # Le motif
//!
//! Bifrost est le pont arc-en-ciel. Fond sombre arrondi, un arc de cinq bandes de
//! couleurs franches, aucun texte. Le dessin est procedural: il ne depend
//! d'aucune police, d'aucun fichier, d'aucune bibliotheque systeme, et n'emploie
//! que des operations IEEE-754 deterministes (addition, soustraction,
//! multiplication, comparaison; jamais de sinus, cosinus ni racine, dont la
//! precision varie d'une plateforme a l'autre). Anticrenelage par
//! sur-echantillonnage 4x4 par pixel, pour que l'arc soit propre a 16 comme a
//! 256 px.

#![forbid(unsafe_code)]

use std::io;
use std::path::{Component, Path, PathBuf};

/// La teinte d'etat du tray: meme pont que l'icone de Bifrost, mais l'arc porte
/// une seule couleur d'etat au lieu de l'arc-en-ciel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Teinte {
    /// Connecte.
    Vert,
    /// Deconnecte ou inconnu.
    Gris,
    /// Kill switch arme sans tunnel etabli.
    Rouge,
}

/// Tailles hicolor ecrites par le binaire (theme d'icones Linux, PNG 16 a 256).
pub const COTES_HICOLOR: &[u32] = &[16, 24, 32, 48, 64, 128, 256];

/// Tailles embarquees dans le `.ico` Windows: ce que l'explorateur et
/// Ajouter/Supprimer des programmes lisent. 256 y est stocke comme largeur 0.
pub const COTES_ICO: &[u32] = &[16, 24, 32, 48, 256];

// --- Palette -----------------------------------------------------------------

/// Fond sombre du carre arrondi (RGB, opaque).
const FOND: [u8; 3] = [0x12, 0x16, 0x22];

/// Les cinq bandes de l'arc, de l'INTERIEUR (bas de l'arche) vers l'EXTERIEUR
/// (haut de l'arche). Rouge en haut, violet en bas, comme un arc-en-ciel.
const BANDES: [[u8; 3]; 5] = [
    [0x8e, 0x5a, 0xd8], // violet
    [0x2f, 0x74, 0xe6], // bleu
    [0x34, 0xb2, 0x54], // vert
    [0xf2, 0xa0, 0x2a], // ambre
    [0xe5, 0x3a, 0x2e], // rouge
];

/// La couleur d'etat du tray. Memes teintes que la pastille de la page de la
/// coquille (`gui/ui/style.css`): le tray et la fenetre disent la meme couleur.
fn couleur_de_teinte(teinte: Teinte) -> [u8; 3] {
    match teinte {
        Teinte::Vert => [0x2e, 0x7d, 0x32],
        Teinte::Gris => [0x9e, 0x9e, 0x9e],
        Teinte::Rouge => [0xc6, 0x28, 0x28],
    }
}

// --- Geometrie du dessin -----------------------------------------------------

/// Rayon des coins arrondis, en fraction du cote. Assez grand pour que le coin
/// (0,0) soit transparent a toute taille (garde du fond arrondi).
const RAYON_COIN: f64 = 0.30;

/// Centre des anneaux de l'arc, sous l'image pour que l'arc s'ouvre en arche.
const ARC_CY: f64 = 1.10;
/// Rayon exterieur (haut de l'arche) et interieur (bas), en fraction du cote.
const ARC_R_EXT: f64 = 0.86;
const ARC_R_INT: f64 = 0.52;

/// Ce qu'on dessine: l'arc-en-ciel (logiciel) ou un arc d'une seule couleur
/// (tray). Le fond seul s'obtient avec `Etat(FOND)`: l'arc peint de la couleur
/// du fond est invisible; les recettes s'en servent pour prouver que le tray
/// porte le meme pont.
#[derive(Clone, Copy)]
pub(crate) enum Motif {
    Logiciel,
    Etat([u8; 3]),
}

/// Sur-echantillonnage: 4x4 sous-pixels par pixel.
const SS: u32 = 4;

/// Vrai si le sous-pixel (dx = x - 0.5, y) tombe dans le carre arrondi.
/// Symetrique en x: n'emploie que |dx|. Comme le rendu appelle cette fonction
/// avec, pour les deux colonnes miroir, des `dx` exactement opposes, deux
/// colonnes symetriques donnent le meme dedans/dehors.
fn dans_le_fond(dx: f64, y: f64) -> bool {
    let ax = dx.abs();
    let ay = (y - 0.5).abs();
    // Distance au bord du rectangle interieur (hors coins).
    let ex = ax - (0.5 - RAYON_COIN);
    let ey = ay - (0.5 - RAYON_COIN);
    if ex <= 0.0 || ey <= 0.0 {
        true
    } else {
        // Dans le quart de coin: dedans si sous le rayon. On compare les carres
        // pour eviter une racine (non deterministe entre plateformes).
        ex * ex + ey * ey <= RAYON_COIN * RAYON_COIN
    }
}

/// L'indice de bande de l'arc au sous-pixel (dx = x - 0.5, y), ou None hors de
/// l'arc. Les anneaux sont centres en (0.5, ARC_CY): le dessin ne depend de x
/// que par `dx * dx`, donc il est symetrique. Aucune racine: on compare des
/// distances au carre a des rayons au carre.
fn bande_arc(dx: f64, y: f64) -> Option<usize> {
    let dy = y - ARC_CY;
    let d2 = dx * dx + dy * dy;
    if d2 < ARC_R_INT * ARC_R_INT || d2 > ARC_R_EXT * ARC_R_EXT {
        return None;
    }
    let nb = BANDES.len();
    let pas = (ARC_R_EXT - ARC_R_INT) / nb as f64;
    let mut k = 0;
    while k < nb {
        let rin = ARC_R_INT + pas * k as f64;
        let rout = ARC_R_INT + pas * (k as f64 + 1.0);
        if d2 >= rin * rin && d2 <= rout * rout {
            return Some(k);
        }
        k += 1;
    }
    None
}

/// La couleur RGB d'un sous-pixel opaque, ou None s'il est transparent (hors du
/// fond arrondi).
fn echantillon(dx: f64, y: f64, motif: Motif) -> Option<[u8; 3]> {
    if !dans_le_fond(dx, y) {
        return None;
    }
    Some(match bande_arc(dx, y) {
        Some(k) => match motif {
            Motif::Logiciel => BANDES[k],
            Motif::Etat(couleur) => couleur,
        },
        None => FOND,
    })
}

/// Arrondi au plus proche de `somme / nombre` (entiers), en arithmetique
/// entiere: `(2*somme + nombre) / (2*nombre)`, division plancher.
fn arrondi_div(somme: u32, nombre: u32) -> u8 {
    ((2 * somme + nombre) / (2 * nombre)) as u8
}

/// Rend l'image RGBA (cote*cote*4 octets) du motif, avec sur-echantillonnage
/// 4x4 par pixel. La couleur d'un pixel est la MOYENNE ENTIERE des sous-pixels
/// opaques (equivalent a un compositing premultiplie sur transparent), et
/// l'alpha vaut la couverture. L'accumulation est entiere: elle ne depend ni de
/// l'ordre de sommation ni de la plateforme, ce qui rend l'image exactement
/// symetrique gauche/droite et identique octet pour octet d'un hote a l'autre.
pub(crate) fn rendre(cote: u32, motif: Motif) -> Vec<u8> {
    assert!(cote > 0, "le cote doit etre non nul");
    let cote_us = cote as usize;
    let mut sortie = vec![0u8; cote_us * cote_us * 4];
    // Grille de sous-pixels: N par cote. Position d'un sous-pixel d'indice n:
    // (2n+1)/(2N). Le numerateur entier de `dx = x - 0.5` est donc 2n+1-N, et
    // la colonne miroir (n' = N-1-n) a pour numerateur -(2n+1-N): dx exactement
    // oppose, symetrie garantie.
    let grille = cote * SS;
    let deux_n = f64::from(2 * grille);
    for py in 0..cote {
        for px in 0..cote {
            let mut somme_r = 0u32;
            let mut somme_g = 0u32;
            let mut somme_b = 0u32;
            let mut nombre = 0u32;
            for sj in 0..SS {
                let ny = py * SS + sj;
                let y = f64::from(2 * ny + 1) / deux_n;
                for si in 0..SS {
                    let nx = px * SS + si;
                    let dx = (f64::from(2 * nx + 1) - f64::from(grille)) / deux_n;
                    if let Some([r, g, b]) = echantillon(dx, y, motif) {
                        somme_r += u32::from(r);
                        somme_g += u32::from(g);
                        somme_b += u32::from(b);
                        nombre += 1;
                    }
                }
            }
            let idx = (py as usize * cote_us + px as usize) * 4;
            if nombre > 0 {
                sortie[idx] = arrondi_div(somme_r, nombre);
                sortie[idx + 1] = arrondi_div(somme_g, nombre);
                sortie[idx + 2] = arrondi_div(somme_b, nombre);
                // Alpha = couverture: nombre / (SS*SS), arrondi sur 0..255.
                sortie[idx + 3] = arrondi_div(nombre * 255, SS * SS);
            }
            // Sinon: entierement transparent, laisse a [0,0,0,0].
        }
    }
    sortie
}

// --- API publique ------------------------------------------------------------

/// L'icone de Bifrost en RGBA 8 bits (cote*cote*4 octets): fond arrondi et arc
/// arc-en-ciel.
#[must_use]
pub fn rgba(cote: u32) -> Vec<u8> {
    rendre(cote, Motif::Logiciel)
}

/// La variante du tray: meme pont, l'arc porte la couleur d'etat.
#[must_use]
pub fn rgba_tray(cote: u32, teinte: Teinte) -> Vec<u8> {
    rendre(cote, Motif::Etat(couleur_de_teinte(teinte)))
}

/// Le PNG (RGBA 8 bits) de l'icone de Bifrost.
#[must_use]
pub fn png(cote: u32) -> Vec<u8> {
    encoder_png(&rgba(cote), cote)
}

/// Le PNG (RGBA 8 bits) d'une teinte de tray.
#[must_use]
pub fn png_tray(cote: u32, teinte: Teinte) -> Vec<u8> {
    encoder_png(&rgba_tray(cote, teinte), cote)
}

/// Le `.ico` multi-images (32 bits par pixel, masque AND) de l'icone de Bifrost,
/// une image par cote donne, dans l'ordre. Assemble a la main.
#[must_use]
pub fn ico(cotes: &[u32]) -> Vec<u8> {
    let images: Vec<Vec<u8>> = cotes.iter().map(|&c| image_dib(c)).collect();
    let n = cotes.len();
    let mut sortie = Vec::new();
    // ICONDIR.
    sortie.extend_from_slice(&0u16.to_le_bytes()); // reserve
    sortie.extend_from_slice(&1u16.to_le_bytes()); // type: icone
    sortie.extend_from_slice(&(n as u16).to_le_bytes()); // nombre d'images
    // Les images suivent les 6 octets d'ICONDIR et les 16 octets par ICONDIRENTRY.
    let mut decalage = 6u32 + 16u32 * n as u32;
    for (idx, &c) in cotes.iter().enumerate() {
        let taille = images[idx].len() as u32;
        let dim = dim_ico(c);
        sortie.push(dim); // largeur (0 = 256)
        sortie.push(dim); // hauteur (0 = 256)
        sortie.push(0); // couleurs de palette
        sortie.push(0); // reserve
        sortie.extend_from_slice(&1u16.to_le_bytes()); // plans
        sortie.extend_from_slice(&32u16.to_le_bytes()); // bits par pixel
        sortie.extend_from_slice(&taille.to_le_bytes()); // taille de l'image
        sortie.extend_from_slice(&decalage.to_le_bytes()); // decalage
        decalage += taille;
    }
    for img in &images {
        sortie.extend_from_slice(img);
    }
    sortie
}

/// L'octet de dimension d'une ICONDIRENTRY: 0 code 256 (Windows).
fn dim_ico(cote: u32) -> u8 {
    if cote >= 256 { 0 } else { cote as u8 }
}

/// Une image DIB pour l'ICO: BITMAPINFOHEADER a hauteur double (XOR + AND),
/// pixels XOR en BGRA de bas en haut, masque AND a 1 bit par pixel (1 =
/// transparent, la ou l'alpha vaut 0), lignes alignees sur 4 octets.
fn image_dib(cote: u32) -> Vec<u8> {
    let rgba = rgba(cote);
    let cote_us = cote as usize;
    let ligne = cote_us * 4;

    let mut dib = Vec::new();
    dib.extend_from_slice(&40u32.to_le_bytes()); // biSize
    dib.extend_from_slice(&(cote as i32).to_le_bytes()); // biWidth
    dib.extend_from_slice(&((cote * 2) as i32).to_le_bytes()); // biHeight (XOR + AND)
    dib.extend_from_slice(&1u16.to_le_bytes()); // biPlanes
    dib.extend_from_slice(&32u16.to_le_bytes()); // biBitCount
    dib.extend_from_slice(&0u32.to_le_bytes()); // biCompression (BI_RGB)
    dib.extend_from_slice(&0u32.to_le_bytes()); // biSizeImage
    dib.extend_from_slice(&0i32.to_le_bytes()); // biXPelsPerMeter
    dib.extend_from_slice(&0i32.to_le_bytes()); // biYPelsPerMeter
    dib.extend_from_slice(&0u32.to_le_bytes()); // biClrUsed
    dib.extend_from_slice(&0u32.to_le_bytes()); // biClrImportant

    // XOR: BGRA, de bas en haut.
    for y in (0..cote_us).rev() {
        for x in 0..cote_us {
            let i = y * ligne + x * 4;
            dib.push(rgba[i + 2]); // B
            dib.push(rgba[i + 1]); // G
            dib.push(rgba[i]); // R
            dib.push(rgba[i + 3]); // A
        }
    }

    // Masque AND: 1 bit par pixel, ligne alignee sur 4 octets, de bas en haut.
    let octets_ligne = cote_us.div_ceil(32) * 4;
    for y in (0..cote_us).rev() {
        let mut bits = vec![0u8; octets_ligne];
        for x in 0..cote_us {
            let i = y * ligne + x * 4;
            if rgba[i + 3] == 0 {
                bits[x / 8] |= 0x80u8 >> (x % 8);
            }
        }
        dib.extend_from_slice(&bits);
    }
    dib
}

// --- Encodage PNG a la main --------------------------------------------------

/// Encode un buffer RGBA 8 bits en PNG. Le flux zlib est en blocs << stored >>
/// (non compresses): plus gros mais trivialement deterministe, et le crate `png`
/// de tauri-codegen les decode sans peine.
fn encoder_png(rgba: &[u8], cote: u32) -> Vec<u8> {
    assert_eq!(
        rgba.len(),
        cote as usize * cote as usize * 4,
        "le buffer RGBA doit faire cote*cote*4 octets"
    );
    let mut png = Vec::new();
    png.extend_from_slice(&[137, 80, 78, 71, 13, 10, 26, 10]); // signature

    let mut ihdr = Vec::with_capacity(13);
    ihdr.extend_from_slice(&cote.to_be_bytes()); // largeur
    ihdr.extend_from_slice(&cote.to_be_bytes()); // hauteur
    ihdr.push(8); // profondeur de bit
    ihdr.push(6); // type couleur: RGBA (couleur + alpha)
    ihdr.push(0); // compression (deflate)
    ihdr.push(0); // filtre
    ihdr.push(0); // entrelacement
    ecrire_bloc(&mut png, b"IHDR", &ihdr);

    let idat = zlib_stored(&filtrer(rgba, cote));
    ecrire_bloc(&mut png, b"IDAT", &idat);

    ecrire_bloc(&mut png, b"IEND", &[]);
    png
}

/// Prefixe chaque ligne d'un octet de filtre 0 (aucun filtre): c'est ce que le
/// flux deflate transporte.
fn filtrer(rgba: &[u8], cote: u32) -> Vec<u8> {
    let ligne = cote as usize * 4;
    let mut raw = Vec::with_capacity(cote as usize * (1 + ligne));
    for y in 0..cote as usize {
        raw.push(0); // filtre None
        raw.extend_from_slice(&rgba[y * ligne..y * ligne + ligne]);
    }
    raw
}

/// Enveloppe zlib d'un flux deflate en blocs << stored >>: en-tete 0x78 0x01,
/// blocs non compresses de 65535 octets au plus, puis Adler32 en gros-boutiste.
fn zlib_stored(raw: &[u8]) -> Vec<u8> {
    let mut z = Vec::with_capacity(raw.len() + raw.len() / 65535 * 5 + 8);
    z.push(0x78);
    z.push(0x01);
    let mut i = 0usize;
    // raw n'est jamais vide (cote >= 1), mais on reste correct si un jour il l'est.
    if raw.is_empty() {
        z.push(1); // BFINAL, BTYPE = stored
        z.extend_from_slice(&0u16.to_le_bytes());
        z.extend_from_slice(&(!0u16).to_le_bytes());
    } else {
        while i < raw.len() {
            let bloc = std::cmp::min(65535usize, raw.len() - i);
            let dernier = i + bloc >= raw.len();
            z.push(u8::from(dernier)); // BFINAL sur le dernier, BTYPE = stored
            let len = bloc as u16;
            z.extend_from_slice(&len.to_le_bytes());
            z.extend_from_slice(&(!len).to_le_bytes());
            z.extend_from_slice(&raw[i..i + bloc]);
            i += bloc;
        }
    }
    z.extend_from_slice(&adler32(raw).to_be_bytes());
    z
}

/// Ecrit un bloc PNG: longueur (gros-boutiste), type, donnees, CRC32 du type et
/// des donnees.
fn ecrire_bloc(sortie: &mut Vec<u8>, typ: &[u8; 4], donnees: &[u8]) {
    sortie.extend_from_slice(&(donnees.len() as u32).to_be_bytes());
    sortie.extend_from_slice(typ);
    sortie.extend_from_slice(donnees);
    let crc = crc32(&[typ, donnees]);
    sortie.extend_from_slice(&crc.to_be_bytes());
}

/// CRC32 de PNG/zlib (polynome 0xEDB88320), sur une suite de tranches.
fn crc32(parties: &[&[u8]]) -> u32 {
    let mut c: u32 = 0xFFFF_FFFF;
    for partie in parties {
        for &octet in *partie {
            c ^= u32::from(octet);
            for _ in 0..8 {
                let masque = (c & 1).wrapping_neg(); // 0xFFFFFFFF si bit pose, sinon 0
                c = (c >> 1) ^ (0xEDB8_8320 & masque);
            }
        }
    }
    c ^ 0xFFFF_FFFF
}

/// Adler32 (modulo 65521).
fn adler32(donnees: &[u8]) -> u32 {
    const MODULO: u32 = 65521;
    let mut a: u32 = 1;
    let mut b: u32 = 0;
    for &octet in donnees {
        a = (a + u32::from(octet)) % MODULO;
        b = (b + a) % MODULO;
    }
    (b << 16) | a
}

// --- Ecriture des fichiers (binaire) -----------------------------------------

/// Ecrit dans `repertoire` toutes les icones (PNG hicolor, `.ico`, PNG de tray)
/// et rend la liste des chemins ecrits. Refuse un chemin sous `gui/` ou
/// `crates/`: aucun binaire d'icone ne doit entrer dans l'arbre du depot (ce que
/// gardent `la_coquille_n_embarque_aucun_binaire` et `sources_ascii`).
///
/// # Errors
///
/// Rend une erreur si le chemin vise l'arbre du depot, ou si une ecriture echoue.
pub fn ecrire_icones(repertoire: &Path) -> io::Result<Vec<PathBuf>> {
    refuser_si_dans_le_depot(repertoire)?;
    std::fs::create_dir_all(repertoire)?;
    let mut ecrits = Vec::new();
    for &c in COTES_HICOLOR {
        let chemin = repertoire.join(format!("bifrost-{c}.png"));
        std::fs::write(&chemin, png(c))?;
        ecrits.push(chemin);
    }
    let ico_chemin = repertoire.join("bifrost.ico");
    std::fs::write(&ico_chemin, ico(COTES_ICO))?;
    ecrits.push(ico_chemin);
    for (teinte, nom) in [
        (Teinte::Vert, "vert"),
        (Teinte::Gris, "gris"),
        (Teinte::Rouge, "rouge"),
    ] {
        let chemin = repertoire.join(format!("bifrost-tray-{nom}-16.png"));
        std::fs::write(&chemin, png_tray(16, teinte))?;
        ecrits.push(chemin);
    }
    Ok(ecrits)
}

/// Refuse tout chemin dont un composant est `gui` ou `crates`: ce sont les
/// arbres versionnes ou aucun binaire ne doit apparaitre.
fn refuser_si_dans_le_depot(repertoire: &Path) -> io::Result<()> {
    for composant in repertoire.components() {
        if let Component::Normal(nom) = composant
            && let Some(s) = nom.to_str()
            && (s == "crates" || s == "gui")
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "refus d'ecrire sous '{}': le composant '{s}' place les icones dans \
                     l'arbre versionne; aucun binaire d'icone ne doit y entrer",
                    repertoire.display(),
                ),
            ));
        }
    }
    Ok(())
}

/// Lit la largeur et la hauteur d'un PNG dans son IHDR (aux decalages fixes 16 et
/// 20). Sert aux recettes: le PNG etant ecrit a la main, on n'a pas de decodeur.
#[cfg(test)]
fn dimensions_ihdr(png: &[u8]) -> (u32, u32) {
    let largeur = u32::from_be_bytes([png[16], png[17], png[18], png[19]]);
    let hauteur = u32::from_be_bytes([png[20], png[21], png[22], png[23]]);
    (largeur, hauteur)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    const SIGNATURE_PNG: [u8; 8] = [137, 80, 78, 71, 13, 10, 26, 10];

    /// Deux appels rendent les memes octets, pour rgba, png et ico. Une graine de
    /// bruit dans le rendu ferait rougir cette garde.
    #[test]
    fn le_rendu_est_deterministe() {
        assert_eq!(rgba(16), rgba(16));
        assert_eq!(rgba(64), rgba(64));
        assert_eq!(png(32), png(32));
        assert_eq!(png_tray(16, Teinte::Vert), png_tray(16, Teinte::Vert));
        assert_eq!(ico(COTES_ICO), ico(COTES_ICO));
    }

    /// Chaque PNG decode a la taille demandee, en RGBA 8 bits (IHDR lu a la main).
    #[test]
    fn les_png_ont_la_taille_demandee_en_rgba() {
        for &c in COTES_HICOLOR {
            let p = png(c);
            assert_eq!(&p[0..8], &SIGNATURE_PNG, "signature PNG pour cote {c}");
            let (largeur, hauteur) = dimensions_ihdr(&p);
            assert_eq!(largeur, c, "largeur IHDR pour cote {c}");
            assert_eq!(hauteur, c, "hauteur IHDR pour cote {c}");
            assert_eq!(p[24], 8, "profondeur 8 bits pour cote {c}");
            assert_eq!(p[25], 6, "type couleur RGBA pour cote {c}");
        }
    }

    /// L'icone n'est pas unie: au moins deux couleurs OPAQUES distinctes (le fond
    /// et l'arc). Un coin transparent et un centre opaque prouvent le fond
    /// arrondi. Retirer l'arc ne laisse qu'une couleur opaque: la garde rougit.
    #[test]
    fn l_icone_n_est_pas_unie_et_le_fond_est_arrondi() {
        let img = rgba(16);
        let mut opaques = BTreeSet::new();
        for px in img.as_chunks::<4>().0 {
            if px[3] == 255 {
                opaques.insert([px[0], px[1], px[2]]);
            }
        }
        assert!(
            opaques.len() >= 2,
            "une seule couleur opaque ({}): le fond sans arc",
            opaques.len()
        );
        // Coin (0,0) transparent, centre opaque.
        assert_eq!(img[3], 0, "le coin (0,0) doit etre transparent");
        let centre = (16u32 / 2 * 16 + 16 / 2) as usize * 4;
        assert_eq!(img[centre + 3], 255, "le centre doit etre opaque");
    }

    /// Les trois teintes du tray donnent trois images distinctes.
    #[test]
    fn les_trois_teintes_du_tray_different() {
        let v = rgba_tray(16, Teinte::Vert);
        let g = rgba_tray(16, Teinte::Gris);
        let r = rgba_tray(16, Teinte::Rouge);
        assert_ne!(v, g);
        assert_ne!(v, r);
        assert_ne!(g, r);
    }

    /// L'ICO porte exactement COTES_ICO.len() entrees, dans l'ordre, chaque
    /// ICONDIRENTRY coherente (largeur 0 = 256, plans 1, 32 bpp), les decalages
    /// strictement croissants et contenus dans le fichier.
    #[test]
    fn l_ico_porte_les_bonnes_entrees() {
        let fichier = ico(COTES_ICO);
        assert_eq!(&fichier[0..2], &[0, 0], "champ reserve d'ICONDIR");
        assert_eq!(
            u16::from_le_bytes([fichier[2], fichier[3]]),
            1,
            "type ICONDIR (1 = icone)"
        );
        let n = u16::from_le_bytes([fichier[4], fichier[5]]) as usize;
        assert_eq!(n, COTES_ICO.len(), "nombre d'entrees");

        let mut attendu_decalage = 6u32 + 16u32 * n as u32;
        let mut precedent = 0u32;
        for (idx, &c) in COTES_ICO.iter().enumerate() {
            let base = 6 + 16 * idx;
            let dim = if c >= 256 { 0u8 } else { c as u8 };
            assert_eq!(fichier[base], dim, "largeur de l'entree {idx} (cote {c})");
            assert_eq!(
                fichier[base + 1],
                dim,
                "hauteur de l'entree {idx} (cote {c})"
            );
            let plans = u16::from_le_bytes([fichier[base + 4], fichier[base + 5]]);
            let bpp = u16::from_le_bytes([fichier[base + 6], fichier[base + 7]]);
            assert_eq!(plans, 1, "plans de l'entree {idx}");
            assert_eq!(bpp, 32, "bits par pixel de l'entree {idx}");
            let taille = u32::from_le_bytes([
                fichier[base + 8],
                fichier[base + 9],
                fichier[base + 10],
                fichier[base + 11],
            ]);
            let decalage = u32::from_le_bytes([
                fichier[base + 12],
                fichier[base + 13],
                fichier[base + 14],
                fichier[base + 15],
            ]);
            assert_eq!(decalage, attendu_decalage, "decalage de l'entree {idx}");
            assert!(decalage > precedent, "decalages strictement croissants");
            assert!(
                decalage as usize + taille as usize <= fichier.len(),
                "l'image de l'entree {idx} deborde du fichier"
            );
            precedent = decalage;
            attendu_decalage += taille;
        }
        // Les images remplissent exactement le reste du fichier.
        assert_eq!(
            attendu_decalage as usize,
            fichier.len(),
            "taille totale de l'ICO"
        );
    }

    /// L'arc est symetrique gauche/droite: (x, y) et (cote-1-x, y) ont la meme
    /// couleur. C'est ce qui prouve un pont, et pas du bruit.
    #[test]
    fn l_arc_est_symetrique_gauche_droite() {
        for &cote in &[16u32, 64] {
            let img = rgba(cote);
            let ligne = cote as usize * 4;
            for y in 0..cote as usize {
                for x in 0..cote as usize {
                    let miroir = cote as usize - 1 - x;
                    let gauche = &img[y * ligne + x * 4..y * ligne + x * 4 + 4];
                    let droite = &img[y * ligne + miroir * 4..y * ligne + miroir * 4 + 4];
                    assert_eq!(gauche, droite, "asymetrie en ({x}, {y}), cote {cote}");
                }
            }
        }
    }

    /// Le tray et l'icone de Bifrost partagent le meme pont: aux pixels ou
    /// l'icone de Bifrost differe du fond seul, le tray en differe aussi, et
    /// nulle part ailleurs. Dessiner le tray sans le pont fait rougir la garde.
    #[test]
    fn le_tray_porte_le_meme_pont() {
        let cote = 16usize;
        let fond = rendre(cote as u32, Motif::Etat(FOND));
        let logiciel = rgba(cote as u32);
        let tray = rgba_tray(cote as u32, Teinte::Gris);
        let mut pixels_logiciel = 0usize;
        for i in 0..cote * cote {
            let plage = i * 4..i * 4 + 4;
            let diff_logiciel = logiciel[plage.clone()] != fond[plage.clone()];
            let diff_tray = tray[plage.clone()] != fond[plage];
            if diff_logiciel {
                pixels_logiciel += 1;
            }
            assert_eq!(
                diff_logiciel, diff_tray,
                "le pixel {i} n'est pas couvert identiquement par l'arc du tray et du logiciel"
            );
        }
        assert!(pixels_logiciel > 0, "l'icone de Bifrost ne porte aucun arc");
    }

    /// Le tray et l'icone de Bifrost ont EXACTEMENT le meme canal alpha (meme
    /// silhouette): l'arc est opaque sur un fond opaque, seul le bord arrondi
    /// module l'alpha, et les deux partagent ce bord.
    #[test]
    fn le_tray_et_l_icone_partagent_l_alpha() {
        let logiciel = rgba(16);
        let tray = rgba_tray(16, Teinte::Gris);
        let alpha_logiciel: Vec<u8> = logiciel.as_chunks::<4>().0.iter().map(|px| px[3]).collect();
        let alpha_tray: Vec<u8> = tray.as_chunks::<4>().0.iter().map(|px| px[3]).collect();
        assert_eq!(alpha_logiciel, alpha_tray);
    }

    /// Le binaire refuse d'ecrire sous `gui/` ou `crates/` et n'y touche rien;
    /// hors depot, il ecrit bien tous les fichiers annonces.
    #[test]
    fn ecrire_refuse_l_arbre_du_depot() {
        let base = std::env::temp_dir().join(format!(
            "bifrost-icone-recette-refus-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&base);
        let sous_crates = base.join("crates");
        let sous_gui = base.join("gui").join("target");
        assert!(
            ecrire_icones(&sous_crates).is_err(),
            "doit refuser un chemin sous crates/"
        );
        assert!(
            ecrire_icones(&sous_gui).is_err(),
            "doit refuser un chemin sous gui/"
        );
        assert!(
            !sous_crates.exists(),
            "rien ne doit etre ecrit sous crates/"
        );
        assert!(
            !base.join("gui").exists(),
            "rien ne doit etre ecrit sous gui/"
        );
        // Controle positif: hors depot, tout est ecrit.
        let hors = base.join("hors-depot");
        let chemins = ecrire_icones(&hors).expect("doit ecrire hors depot");
        assert_eq!(chemins.len(), COTES_HICOLOR.len() + 1 + 3);
        assert!(
            chemins.iter().all(|c| c.exists()),
            "les fichiers doivent exister"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    // --- Conformite du PNG ecrit a la main, verifiee INDEPENDAMMENT --------------
    //
    // Le CRC32 et l'Adler32 du PNG sont calcules a la main. Un CRC faux ne casse
    // que la construction de gui/ (dev-windows, runner), un Adler32 faux ne casse
    // RIEN (png 0.17 l'ignore par defaut): sans les recettes qui suivent, une
    // regression passerait toutes les autres. On decode donc le PNG a la main et
    // on RECALCULE CRC et Adler avec des implementations SEPAREES (jamais celles
    // du crate), sanite sur les vecteurs standards.

    /// CRC32 (polynome 0xEDB88320) recalcule bit a bit, code SEPARE de `super::crc32`:
    /// une mutation du CRC du crate ne se propage pas ici. Verifie sur "123456789".
    fn crc32_recette(donnees: &[u8]) -> u32 {
        let mut c: u32 = 0xFFFF_FFFF;
        for &octet in donnees {
            c ^= u32::from(octet);
            for _ in 0..8 {
                c = if c & 1 == 1 {
                    (c >> 1) ^ 0xEDB8_8320
                } else {
                    c >> 1
                };
            }
        }
        c ^ 0xFFFF_FFFF
    }

    /// Adler32 recalcule, code SEPARE de `super::adler32`. Verifie sur "Wikipedia".
    fn adler32_recette(donnees: &[u8]) -> u32 {
        const MODULO: u32 = 65521;
        let mut a: u32 = 1;
        let mut b: u32 = 0;
        for &octet in donnees {
            a = (a + u32::from(octet)) % MODULO;
            b = (b + a) % MODULO;
        }
        (b << 16) | a
    }

    /// Decode le PNG a la main et exige: CRC de chaque bloc juste (recalcule),
    /// flux zlib << stored >> (en-tete, LEN/NLEN, blocs) dont les octets valent
    /// exactement les scanlines filtre 0 de `raw`, et Adler32 juste (recalcule).
    fn verifier_png_conforme(bytes: &[u8], raw: &[u8], cote: u32) {
        assert_eq!(&bytes[0..8], &SIGNATURE_PNG, "signature PNG (cote {cote})");
        let lire_be = |b: &[u8], p: usize| u32::from_be_bytes([b[p], b[p + 1], b[p + 2], b[p + 3]]);

        let mut i = 8usize;
        let mut idat: Vec<u8> = Vec::new();
        let mut vu_ihdr = false;
        loop {
            assert!(i + 8 <= bytes.len(), "bloc tronque (cote {cote})");
            let len = lire_be(bytes, i) as usize;
            let typ = &bytes[i + 4..i + 8];
            let d0 = i + 8;
            assert!(
                d0 + len + 4 <= bytes.len(),
                "donnees/CRC tronques (cote {cote})"
            );
            let donnees = &bytes[d0..d0 + len];
            let crc_lu = lire_be(bytes, d0 + len);
            let mut type_et_donnees = Vec::with_capacity(4 + len);
            type_et_donnees.extend_from_slice(typ);
            type_et_donnees.extend_from_slice(donnees);
            assert_eq!(
                crc32_recette(&type_et_donnees),
                crc_lu,
                "CRC32 du bloc {} (cote {cote})",
                std::str::from_utf8(typ).unwrap_or("?")
            );
            match typ {
                b"IHDR" => {
                    vu_ihdr = true;
                    assert_eq!(lire_be(donnees, 0), cote, "largeur IHDR (cote {cote})");
                    assert_eq!(lire_be(donnees, 4), cote, "hauteur IHDR (cote {cote})");
                    assert_eq!(donnees[8], 8, "profondeur 8 bits (cote {cote})");
                    assert_eq!(donnees[9], 6, "type couleur RGBA (cote {cote})");
                }
                b"IDAT" => idat.extend_from_slice(donnees),
                b"IEND" => {
                    i = d0 + len + 4;
                    break;
                }
                _ => {}
            }
            i = d0 + len + 4;
        }
        assert!(vu_ihdr, "IHDR absent (cote {cote})");
        assert_eq!(i, bytes.len(), "octets apres IEND (cote {cote})");

        // Flux zlib: en-tete 0x78 0x01, blocs << stored >>, Adler32 gros-boutiste.
        assert!(idat.len() >= 6, "IDAT trop court (cote {cote})");
        assert_eq!(idat[0], 0x78, "CMF zlib (cote {cote})");
        assert_eq!(idat[1], 0x01, "FLG zlib (cote {cote})");
        let mut p = 2usize;
        let mut decode: Vec<u8> = Vec::new();
        loop {
            let entete = idat[p];
            p += 1;
            let bfinal = entete & 1;
            let btype = (entete >> 1) & 0b11;
            assert_eq!(btype, 0, "bloc deflate non << stored >> (cote {cote})");
            let len = u16::from_le_bytes([idat[p], idat[p + 1]]) as usize;
            let nlen = u16::from_le_bytes([idat[p + 2], idat[p + 3]]);
            assert_eq!(
                nlen,
                !(len as u16),
                "NLEN != complement de LEN (cote {cote})"
            );
            p += 4;
            decode.extend_from_slice(&idat[p..p + len]);
            p += len;
            if bfinal == 1 {
                break;
            }
        }
        assert_eq!(
            p + 4,
            idat.len(),
            "octets zlib superflus/manquants (cote {cote})"
        );
        let adler_lu = u32::from_be_bytes([idat[p], idat[p + 1], idat[p + 2], idat[p + 3]]);
        assert_eq!(
            adler32_recette(&decode),
            adler_lu,
            "Adler32 du flux (cote {cote})"
        );

        // Les octets decodes valent exactement les scanlines filtre 0 de raw.
        let ligne = cote as usize * 4;
        let mut attendu = Vec::with_capacity(cote as usize * (1 + ligne));
        for y in 0..cote as usize {
            attendu.push(0);
            attendu.extend_from_slice(&raw[y * ligne..y * ligne + ligne]);
        }
        assert_eq!(
            decode, attendu,
            "scanlines decodees != rendu filtre 0 (cote {cote})"
        );
    }

    #[test]
    fn le_png_est_conforme_crc_et_adler_independants() {
        // Sanite des implementations separees sur les vecteurs standards.
        assert_eq!(
            crc32_recette(b"123456789"),
            0xCBF4_3926,
            "CRC32 de reference"
        );
        assert_eq!(
            adler32_recette(b"Wikipedia"),
            0x11E6_0398,
            "Adler32 de reference"
        );
        // png(32), une teinte de tray, et une cote de COTES_HICOLOR (256: plusieurs
        // blocs << stored >>, ce qui eprouve les LEN/NLEN successifs).
        verifier_png_conforme(&png(32), &rgba(32), 32);
        verifier_png_conforme(
            &png_tray(16, Teinte::Vert),
            &rgba_tray(16, Teinte::Vert),
            16,
        );
        verifier_png_conforme(&png(256), &rgba(256), 256);
    }

    /// Les deux tables de cotes sont STRICTEMENT croissantes: pas de doublon
    /// ([16,24,24,48,256] passerait la garde de l'ICO, qui se compare a COTES_ICO
    /// lui-meme) et pas de desordre.
    #[test]
    fn les_cotes_sont_strictement_croissantes() {
        for (nom, cotes) in [("COTES_ICO", COTES_ICO), ("COTES_HICOLOR", COTES_HICOLOR)] {
            for fenetre in cotes.windows(2) {
                assert!(
                    fenetre[0] < fenetre[1],
                    "{nom} n'est pas strictement croissante: {cotes:?}"
                );
            }
        }
    }
}
