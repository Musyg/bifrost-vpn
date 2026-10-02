//! Le lecteur D-Bus de `prove dns`, tel que la CLI le joue sur ce que le bus
//! systeme lui envoie: `bifrost_cli::preuve_dns::dbus::lire_reponse`, apres
//! `lire_accord` pour l'authentification.
//!
//! Frontiere: les octets viennent du bus systeme, donc de tout pair que le bus
//! relaie, et sont lus sous le compte de l'utilisateur, sans elevation.
//!
//! L'entree porte l'attente puis le flux: un octet de forme (modulo 10), le
//! numero de l'appel attendu (32 bits, petit-boutiste), la longueur puis les
//! octets du nom de l'emetteur attendu, puis les octets recus.
//!
//! Au-dela de l'absence de panique, la cible verifie pour une reponse lue:
//! - la longueur consommee est dans le flux, et le flux coupe un octet avant
//!   est incomplet: ni une erreur, ni une autre reponse;
//! - la valeur rendue a la forme attendue;
//! - reecrite par l'encodeur des recettes, elle se relit a l'identique.
#![no_main]

use bifrost_cli::preuve_dns::dbus::{
    Attente, BUS, Forme, Issue, ORDRE_NATIF, Propriete, Valeur, encoder_reponse, lire_accord,
    lire_reponse,
};
use libfuzzer_sys::fuzz_target;

const FORMES: [Forme; 10] = [
    Forme::Chaine,
    Forme::Entier32NonSigne,
    Forme::Chemin,
    Forme::ListeDeDelegues,
    Forme::Variante(Propriete::Serveurs),
    Forme::Variante(Propriete::Domaines),
    Forme::Variante(Propriete::Chaine),
    Forme::Variante(Propriete::Booleen),
    Forme::Variante(Propriete::Entier64),
    Forme::Variante(Propriete::ServeursDuLien),
];

fn de_la_forme(forme: Forme, v: &Valeur) -> bool {
    matches!(
        (forme, v),
        (Forme::Chaine, Valeur::Chaine(_))
            | (Forme::Entier32NonSigne, Valeur::Entier32NonSigne(_))
            | (Forme::Chemin, Valeur::Chemin(_))
            | (Forme::ListeDeDelegues, Valeur::Delegues(_))
            | (Forme::Variante(Propriete::Serveurs), Valeur::Serveurs(_))
            | (Forme::Variante(Propriete::Domaines), Valeur::Domaines(_))
            | (Forme::Variante(Propriete::Chaine), Valeur::Chaine(_))
            | (Forme::Variante(Propriete::Booleen), Valeur::Booleen(_))
            | (Forme::Variante(Propriete::Entier64), Valeur::Entier64(_))
            | (
                Forme::Variante(Propriete::ServeursDuLien),
                Valeur::ServeursDuLien(_)
            )
    )
}

fuzz_target!(|octets: &[u8]| {
    if let Ok(Some(n)) = lire_accord(octets) {
        assert!(octets[..n].starts_with(b"OK ") && octets[..n].ends_with(b"\r\n"));
    }
    let [f, s0, s1, s2, s3, n, reste @ ..] = octets else {
        return;
    };
    let n = usize::from(*n);
    if reste.len() < n {
        return;
    }
    let Ok(emetteur) = std::str::from_utf8(&reste[..n]) else {
        return;
    };
    let flux = &reste[n..];
    let forme = FORMES[usize::from(*f) % FORMES.len()];
    let attente = Attente {
        serie: u32::from_le_bytes([*s0, *s1, *s2, *s3]),
        emetteur,
        forme,
        ordre: ORDRE_NATIF,
    };
    let Ok(Some((issue, lus))) = lire_reponse(flux, &attente) else {
        return;
    };
    assert!(
        lus > 0 && lus <= flux.len(),
        "longueur consommee hors du flux"
    );
    assert_eq!(
        lire_reponse(&flux[..lus - 1], &attente),
        Ok(None),
        "un flux coupe avant la fin de la reponse n'est pas incomplet"
    );
    assert_eq!(
        lire_reponse(&flux[..lus], &attente),
        Ok(Some((issue.clone(), lus))),
        "la reponse depend des octets qui la suivent"
    );
    let reecrite = match &issue {
        Issue::Retour(v) => {
            assert!(de_la_forme(forme, v), "valeur d'une autre forme: {v:?}");
            encoder_reponse(
                1,
                attente.serie,
                emetteur,
                None,
                Some((forme, v)),
                ORDRE_NATIF,
            )
        }
        Issue::Erreur(nom) => {
            encoder_reponse(1, attente.serie, emetteur, Some(nom), None, ORDRE_NATIF)
        }
        Issue::RefusDuBus(nom) => {
            encoder_reponse(1, attente.serie, BUS, Some(nom), None, ORDRE_NATIF)
        }
    };
    assert_eq!(
        lire_reponse(&reecrite, &attente),
        Ok(Some((issue, reecrite.len()))),
        "une reponse reecrite ne se relit pas a l'identique"
    );
});
