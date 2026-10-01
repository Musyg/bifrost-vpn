//! La moisson multi-canal: `bifrost_amorce::recuperer`.
//!
//! Frontiere: chaque canal (miroir HTTP, fichier, lien colle) est suppose
//! hostile; ce qu'il rend (nom, profil, signature) est lu par la CLI sous le
//! compte de l'utilisateur, et seule la cle de confiance locale tranche. La
//! cible fait jouer les canaux par des doublures qui rendent les octets de
//! l'entree, exactement comme `Canal::chercher` les rendrait.
//!
//! Forme de l'entree, coupee aux octets nuls: la cle publique, puis par canal
//! un nom, un profil et une signature. Une signature qui n'est pas de l'UTF-8,
//! ou un canal incomplet, fait un canal muet. Huit canaux au plus.
//!
//! Au-dela de l'absence de panique, la cible verifie la politique documentee
//! dans `bifrost-amorce/src/lib.rs`:
//! - un passage par canal, dans l'ordre, et un canal muet reste muet;
//! - un nom de canal tient en cent caracteres, ou bien il est abrege et le dit;
//! - rien n'est retenu sans un canal authentique;
//! - le retenu est le premier canal a la serie la plus haute, un profil sans
//!   serie ne delogeant jamais un profil qui en a une;
//! - le retenu se verifie, de nouveau, avec la meme cle.
#![no_main]

use bifrost_amorce::{Canal, Issue, Recu, recuperer};
use libfuzzer_sys::fuzz_target;

/// La largeur au-dela de laquelle `abreger` coupe un nom de canal.
const LARGEUR: usize = 100;

struct Doublure {
    nom: String,
    reponse: Result<(Vec<u8>, String), String>,
}

impl Canal for Doublure {
    fn nom(&self) -> String {
        self.nom.clone()
    }

    fn chercher(&self) -> Result<Recu, String> {
        match &self.reponse {
            Ok((profil, signature)) => Ok(Recu {
                profil: profil.clone(),
                signature: signature.clone(),
            }),
            Err(pourquoi) => Err(pourquoi.clone()),
        }
    }
}

fn doublure(morceaux: &[&[u8]]) -> Doublure {
    let nom = String::from_utf8_lossy(morceaux[0]).into_owned();
    let reponse = match morceaux {
        [_, profil, signature] => match std::str::from_utf8(signature) {
            Ok(s) => Ok((profil.to_vec(), s.to_owned())),
            Err(_) => Err(String::from_utf8_lossy(signature).into_owned()),
        },
        [_, muet] => Err(String::from_utf8_lossy(muet).into_owned()),
        _ => Err(String::new()),
    };
    Doublure { nom, reponse }
}

fuzz_target!(|octets: &[u8]| {
    let mut morceaux = octets.split(|o| *o == 0);
    let Some(cle) = morceaux.next() else {
        return;
    };
    let cle = String::from_utf8_lossy(cle).into_owned();
    let reste: Vec<&[u8]> = morceaux.collect();
    let doublures: Vec<Doublure> = reste.chunks(3).take(8).map(doublure).collect();
    let attendus: Vec<(String, bool)> = doublures
        .iter()
        .map(|d| (d.nom.clone(), d.reponse.is_err()))
        .collect();
    let canaux: Vec<Box<dyn Canal>> = doublures
        .into_iter()
        .map(|d| Box::new(d) as Box<dyn Canal>)
        .collect();

    let moisson = recuperer(&canaux, &cle);

    assert_eq!(moisson.journal.len(), canaux.len(), "un passage par canal");
    for (passage, (nom, muet)) in moisson.journal.iter().zip(&attendus) {
        if nom.chars().count() <= LARGEUR {
            assert_eq!(&passage.canal, nom, "un nom court se rapporte tel quel");
        } else {
            let debut: String = nom.chars().take(LARGEUR).collect();
            assert!(
                passage.canal.starts_with(&debut),
                "l'abregement garde le debut"
            );
            assert!(
                passage.canal.chars().count() < LARGEUR + 40,
                "nom de canal abrege a {} caracteres",
                passage.canal.chars().count()
            );
        }
        assert_eq!(
            matches!(passage.issue, Issue::Muet(_)),
            *muet,
            "un canal muet doit etre rapporte muet, et lui seul"
        );
    }

    let authentiques: Vec<(usize, Option<u64>)> = moisson
        .journal
        .iter()
        .enumerate()
        .filter_map(|(i, p)| match p.issue {
            Issue::Authentique(serie) => Some((i, serie)),
            _ => None,
        })
        .collect();
    match &moisson.retenu {
        None => assert!(
            authentiques.is_empty(),
            "un canal authentique et rien de retenu"
        ),
        Some(retenu) => {
            // `None < Some(_)`: la plus haute est une serie des qu'un canal en
            // declare une, et le premier canal qui la porte l'emporte.
            let meilleure = authentiques
                .iter()
                .map(|(_, s)| *s)
                .max()
                .expect("un profil retenu sans canal authentique");
            let premier = authentiques
                .iter()
                .find(|(_, s)| *s == meilleure)
                .map(|(i, _)| *i)
                .expect("la meilleure serie vient d'un canal");
            assert_eq!(retenu.origine.serie, meilleure, "serie retenue");
            assert_eq!(retenu.canal, moisson.journal[premier].canal, "canal retenu");
            bifrost_coffre::signature::verifier(&retenu.profil, &retenu.signature, &cle)
                .expect("le profil retenu doit se verifier avec la cle de confiance");
        }
    }
});
