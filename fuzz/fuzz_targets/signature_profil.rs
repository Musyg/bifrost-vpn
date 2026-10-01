//! La signature d'un profil: `bifrost_coffre::signature::lire_cle_de_confiance`
//! puis `bifrost_coffre::signature::verifier`.
//!
//! Frontiere: le profil et sa signature `.minisig` arrivent d'un canal
//! quelconque (miroir, fichier, lien colle), donc d'un inconnu; la cle de
//! confiance est un fichier local. La CLI lit les trois sous le compte de
//! l'utilisateur, `bifrost profil installer` aussi, et c'est cette
//! verification qui decide si le profil s'installe.
//!
//! Forme de l'entree, coupee aux deux premiers octets nuls: le fichier de cle
//! (ecrit tel quel dans un fichier temporaire du processus, puis relu par la
//! fonction de production), le profil, la signature.
//!
//! Au-dela de l'absence de panique, la cible verifie:
//! - une cle lue tient sur une ligne, sans blanc autour, et n'est pas un
//!   commentaire;
//! - la verification est deterministe;
//! - une signature acceptee n'accepte plus le profil des qu'un octet lui est
//!   ajoute: la signature couvre le contenu;
//! - une serie rendue vient d'un marqueur `serie=` du commentaire de confiance.
#![no_main]

use std::path::PathBuf;
use std::sync::OnceLock;

use bifrost_coffre::signature::{lire_cle_de_confiance, verifier};
use libfuzzer_sys::fuzz_target;

/// Un fichier par processus, sous le repertoire temporaire: deux campagnes
/// simultanees n'ecrivent jamais le meme.
fn fichier_de_cle() -> &'static PathBuf {
    static CHEMIN: OnceLock<PathBuf> = OnceLock::new();
    CHEMIN.get_or_init(|| {
        std::env::temp_dir().join(format!("bifrost-fuzz-cle-{}.pub", std::process::id()))
    })
}

fn eprouver(contenu: &[u8], signature: &str, cle: &str) {
    let premiere = verifier(contenu, signature, cle);
    let seconde = verifier(contenu, signature, cle);
    assert_eq!(
        premiere.as_ref().ok(),
        seconde.as_ref().ok(),
        "deux verifications de la meme signature divergent"
    );
    let Ok(origine) = premiere else {
        return;
    };
    let mut altere = contenu.to_vec();
    altere.push(b'\n');
    assert!(
        verifier(&altere, signature, cle).is_err(),
        "une signature acceptee couvre aussi un profil allonge d'un octet"
    );
    if origine.serie.is_some() {
        assert!(
            origine.commentaire.contains("serie="),
            "une serie sans marqueur dans le commentaire de confiance"
        );
    }
}

fuzz_target!(|octets: &[u8]| {
    let mut morceaux = octets.splitn(3, |o| *o == 0);
    let (Some(fichier), Some(contenu), Some(signature)) =
        (morceaux.next(), morceaux.next(), morceaux.next())
    else {
        return;
    };
    let Ok(signature) = std::str::from_utf8(signature) else {
        return;
    };

    let chemin = fichier_de_cle();
    std::fs::write(chemin, fichier).expect("le fichier de cle temporaire doit s'ecrire");
    if let Ok(cle) = lire_cle_de_confiance(chemin) {
        assert!(!cle.is_empty(), "cle vide rendue");
        assert_eq!(cle, cle.trim(), "cle rendue avec des blancs autour");
        assert!(!cle.contains('\n'), "cle rendue sur plusieurs lignes");
        assert!(
            !cle.starts_with("untrusted comment:"),
            "un commentaire rendu comme cle"
        );
        eprouver(contenu, signature, &cle);
    }
    // Le texte brut aussi: `verifier` est publique et ebarbe elle-meme la cle
    // qu'on lui passe, elle est donc eprouvee hors du lecteur de fichier.
    if let Ok(brute) = std::str::from_utf8(fichier) {
        eprouver(contenu, signature, brute);
    }
});
