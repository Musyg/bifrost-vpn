//! `TABLEAU_INERTE_A_PARTIR_DU` dit-il le jour que la SELECTION applique.
//!
//! # Pourquoi cette garde existe, et ce que l'ancienne ne pouvait pas voir
//!
//! La constante annonce le jour ou le tableau de survie ne peut plus eliminer
//! aucun candidat. Elle etait epinglee, depuis le 20/08/2026, par une recette
//! unitaire qui la comparait a `survie::mord_encore`. Les deux portaient la
//! meme definition trop large - "une observation fraiche, quel que soit son
//! statut" - alors que `selection::refuser` exige une observation fraiche ET
//! `Statut::Mort`. Une garde qui recalcule la formule du code ne peut pas voir
//! que la formule est fausse: elle est restee verte du 04/09/2026 au
//! 20/09/2026 pendant que la constante annoncait 62 jours de morsure que le
//! code ne pouvait pas produire.
//!
//! Celle-ci ne recalcule rien. Elle fait tourner `selection::planifier`, la
//! seule fonction qui elimine reellement, et lui demande ce qu'elle ecarte.
//! Elle rougirait donc meme si `mord_encore` et la constante se trompaient
//! ENSEMBLE, ce qui est exactement le cas qui s'est produit.

use bifrost_evasion::selection::{Contexte, Mode, Refus, planifier};
use bifrost_evasion::survie::{Pays, TABLEAU_INERTE_A_PARTIR_DU};
use bifrost_evasion::{Date, Environnement, MemoireReseau, Technique};

const CENSEURS: [Pays; 4] = [Pays::Chine, Pays::Russie, Pays::Iran, Pays::Turkmenistan];

fn decale(jour: Date, jours: i64) -> Date {
    Date::depuis_numero_de_jour(jour.numero_de_jour() + jours)
}

/// Les techniques que le tableau de survie ecarte ce jour-la dans ce pays.
///
/// Rien d'autre ne doit pouvoir les ecarter: l'environnement est vierge (aucune
/// sonde n'a tourne, donc aucun refus de transport), le mode est `Auto` (donc
/// aucun refus de camouflage) et la memoire est vide. Ce qui reste dans
/// `ecartes` avec ce motif vient du tableau et de lui seul.
fn ecartees_par_le_tableau(pays: Pays, jour: Date) -> Vec<Technique> {
    let memoire = MemoireReseau::vierge();
    let plan = planifier(&Contexte {
        pays,
        environnement: Environnement::rien_sonde(),
        mode: Mode::Auto,
        memoire: &memoire,
        aujourd_hui: jour,
    });
    plan.ecartes
        .iter()
        .filter(|(_, refus)| *refus == Refus::MorteEtObservationFraiche)
        .map(|(t, _)| *t)
        .collect()
}

/// La veille du jour annonce, la selection ecarte encore quelqu'un, quelque
/// part.
#[test]
fn la_veille_du_jour_annonce_la_selection_ecarte_encore() {
    let veille = decale(TABLEAU_INERTE_A_PARTIR_DU, -1);
    let total: Vec<(Pays, Technique)> = CENSEURS
        .into_iter()
        .flat_map(|p| {
            ecartees_par_le_tableau(p, veille)
                .into_iter()
                .map(move |t| (p, t))
        })
        .collect();
    assert!(
        !total.is_empty(),
        "la veille de {TABLEAU_INERTE_A_PARTIR_DU:?} la selection devait encore ecarter au moins une technique; \
         si elle n'ecarte plus rien, la constante est trop TARDIVE"
    );
}

/// Le jour annonce, et pour toujours ensuite, plus personne n'est ecarte par le
/// tableau, dans aucun des quatre pays.
///
/// Le balayage sur une annee n'est pas decoratif: il mesure la promesse de la
/// constante ("PLUS AUCUNE ligne ne pourra eliminer") plutot que le seul jour
/// de la frontiere. Il tient parce que la fraicheur ne fait que decroitre.
#[test]
fn a_partir_du_jour_annonce_la_selection_n_ecarte_plus_personne() {
    for n in 0..365 {
        let jour = decale(TABLEAU_INERTE_A_PARTIR_DU, n);
        for pays in CENSEURS {
            let ecartees = ecartees_par_le_tableau(pays, jour);
            assert!(
                ecartees.is_empty(),
                "a {jour:?} en {pays:?}, la selection ecarte encore {ecartees:?} sur le tableau de survie: \
                 la constante est trop PRECOCE"
            );
        }
    }
}

/// Le tableau n'a plus la meme portee dans les quatre pays, et c'est ce qu'une
/// constante unique cache.
///
/// Releve du 20/09/2026: la Chine et la Russie n'ont qu'une cellule `Mort`,
/// WireGuard nu (2026-04), et l'Iran en a DEUX, Hysteria2 (2026-01) et
/// WireGuard nu (2026-04). C'est la plus TARDIVE des peremptions qui gouverne,
/// Hysteria2 ayant expire des le 02/04/2026: les trois pays cessent donc
/// d'eliminer le meme jour, le 01/07/2026, et le tableau n'y ecarte plus rien
/// depuis onze semaines. Seul le Turkmenistan garde une elimination, REALITY,
/// mesuree en 2026-07.
///
/// Cette recette existe pour que la prochaine lecture de `TABLEAU_INERTE_A_PARTIR_DU`
/// ne se lise pas comme "le tableau mord partout jusque-la".
#[test]
fn au_20_septembre_2026_seul_le_turkmenistan_voit_encore_une_elimination() {
    let jour = Date::new(2026, 9, 20);
    for pays in [Pays::Chine, Pays::Russie, Pays::Iran] {
        assert_eq!(
            ecartees_par_le_tableau(pays, jour),
            Vec::<Technique>::new(),
            "en {pays:?} le tableau n'elimine plus rien au 20/09/2026"
        );
    }
    assert_eq!(
        ecartees_par_le_tableau(Pays::Turkmenistan, jour),
        vec![Technique::RealityVision],
        "au Turkmenistan REALITY est la derniere elimination du tableau"
    );
}

/// Depuis QUAND la Chine, la Russie et l'Iran n'ont plus d'elimination.
///
/// `docs/04-anti-censure-dpi.md` partie 1 ecrit: "en Chine, en Russie et en
/// Iran, plus aucune cellule n'elimine depuis le 1er juillet 2026". C'est une
/// affirmation sur une date, posee en prose dans un document que rien
/// n'obligerait a suivre le code - exactement la forme qui s'est demodee en
/// silence dans quatre documents a la fois et qui a fait naitre
/// `TABLEAU_INERTE_A_PARTIR_DU`. Elle est donc mesuree ici, de part et d'autre
/// du jour cite, plutot que laissee a la prose.
#[test]
fn la_chine_la_russie_et_l_iran_n_eliminent_plus_rien_depuis_le_1er_juillet_2026() {
    for pays in [Pays::Chine, Pays::Russie, Pays::Iran] {
        assert_eq!(
            ecartees_par_le_tableau(pays, Date::new(2026, 6, 30)),
            vec![Technique::WireGuardNu],
            "au 2026-06-30 en {pays:?}, WireGuard nu (mesure en 2026-04) devait encore etre ecarte"
        );
        assert_eq!(
            ecartees_par_le_tableau(pays, Date::new(2026, 7, 1)),
            Vec::<Technique>::new(),
            "au 2026-07-01 en {pays:?}, plus aucune elimination: c'est la date que le document annonce"
        );
    }
}
