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
//!
//! # Ce que "inerte" veut dire, mesure le 30/09/2026
//!
//! Le jour annonce, la selection n'ecarte plus rien; c'est ce que la constante
//! promet. Mais le releve du 30/09/2026 montre davantage, et deux recettes le
//! fixent: le plan de chaque pays, dans chaque mode, ne change PLUS du tout a
//! partir de ce jour. Le classement ne lit que le statut d'une cellule, jamais
//! sa fraicheur; une fois la derniere cellule `Mort` perimee, plus rien dans le
//! tableau ne depend du calendrier. "Il classe encore" est exact, mais son
//! classement est fige jusqu'au prochain changement de STATUT ou jusqu'a une
//! nouvelle date sur une cellule `Mort` - redater une cellule qui n'est pas
//! `Mort` ne change aucun plan.

use bifrost_evasion::selection::{Contexte, Mode, Plan, Refus, planifier};
use bifrost_evasion::survie::{Pays, TABLEAU_INERTE_A_PARTIR_DU};
use bifrost_evasion::{Date, Demarche, Environnement, MemoireReseau, Technique, demarche_parmi};

const CENSEURS: [Pays; 4] = [Pays::Chine, Pays::Russie, Pays::Iran, Pays::Turkmenistan];

/// Les quatre pays censeurs et le cas sans censure, qui ne doit jamais bouger.
const TOUS_LES_PAYS: [Pays; 5] = [
    Pays::NonCensure,
    Pays::Chine,
    Pays::Russie,
    Pays::Iran,
    Pays::Turkmenistan,
];

const MODES: [Mode; 3] = [Mode::Auto, Mode::Discret, Mode::Rapide];

fn decale(jour: Date, jours: i64) -> Date {
    Date::depuis_numero_de_jour(jour.numero_de_jour() + jours)
}

/// Le plan complet, dans les memes conditions que [`ecartees_par_le_tableau`]:
/// rien de sonde, memoire vide. Seuls le pays, le mode et le jour varient.
fn plan(pays: Pays, mode: Mode, jour: Date) -> Plan {
    let memoire = MemoireReseau::vierge();
    planifier(&Contexte {
        pays,
        environnement: Environnement::rien_sonde(),
        mode,
        memoire: &memoire,
        aujourd_hui: jour,
    })
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

/// Ce que le passage du 29 au 30 septembre 2026 change, mesure et non deduit.
///
/// Releve du 30/09/2026, par `planifier` et `demarche_parmi` - la fonction que
/// le daemon appelle pour arbitrer le profil de l'utilisateur. Des quinze plans
/// (cinq pays, trois modes), seuls les trois plans turkmenes changent, et ils
/// changent d'une seule facon: REALITY cesse d'etre ecartee et rentre dans le
/// plan, sans en deloger la tete. Pour le produit, cela veut dire qu'un profil
/// REALITY au Turkmenistan, refuse le 29 avec le motif "donnee morte dans ce
/// pays, observation fraiche", est accepte le 30. C'est le dernier veto que le
/// tableau de survie exercait; aucun autre couple pays et technique ne change
/// de demarche ce jour-la.
///
/// Recette figee sur deux dates du calendrier, comme celles du 20/08 et du
/// 20/09: le prochain rafraichissement qui redaterait REALITY/Turkmenistan la
/// fera rougir, et c'est voulu - il devra dire ce que le 30/09 est devenu.
#[test]
fn le_30_septembre_2026_seul_le_turkmenistan_change_et_perd_son_dernier_veto() {
    let veille = Date::new(2026, 9, 29);
    let jour = Date::new(2026, 9, 30);

    for pays in TOUS_LES_PAYS {
        for mode in MODES {
            let avant = plan(pays, mode, veille);
            let apres = plan(pays, mode, jour);
            if pays != Pays::Turkmenistan {
                assert_eq!(
                    avant, apres,
                    "en {pays:?}/{mode:?}, le plan ne devait pas changer entre le 29 et le 30/09/2026"
                );
                continue;
            }
            assert_ne!(
                avant, apres,
                "au Turkmenistan/{mode:?}, le 30/09/2026 devait changer le plan"
            );
            assert!(
                avant
                    .ecartes
                    .contains(&(Technique::RealityVision, Refus::MorteEtObservationFraiche)),
                "au Turkmenistan/{mode:?}, REALITY devait encore etre ecartee le 29/09: {:?}",
                avant.ecartes
            );
            assert!(
                !apres
                    .ecartes
                    .iter()
                    .any(|(_, r)| *r == Refus::MorteEtObservationFraiche),
                "au Turkmenistan/{mode:?}, plus rien ne devait etre ecarte par le tableau le 30/09: {:?}",
                apres.ecartes
            );
            assert!(
                apres
                    .candidats
                    .iter()
                    .any(|c| c.technique == Technique::RealityVision),
                "au Turkmenistan/{mode:?}, REALITY devait rentrer dans le plan le 30/09"
            );
            assert_eq!(
                avant.premier(),
                apres.premier(),
                "au Turkmenistan/{mode:?}, la tete du plan ne devait pas bouger: REALITY rentre par la queue"
            );
        }
    }

    // Le produit: le veto par profil, pour chaque couple pays et technique.
    for pays in TOUS_LES_PAYS {
        for t in Technique::TOUTES {
            let avant = demarche_parmi(&plan(pays, Mode::Auto, veille), &[t]);
            let apres = demarche_parmi(&plan(pays, Mode::Auto, jour), &[t]);
            if (pays, t) == (Pays::Turkmenistan, Technique::RealityVision) {
                assert_eq!(
                    avant,
                    Demarche::Ecartee {
                        motifs: vec![(Technique::RealityVision, Refus::MorteEtObservationFraiche)]
                    },
                    "le 29/09/2026, un profil REALITY au Turkmenistan devait etre refuse par le tableau"
                );
                assert!(
                    !matches!(apres, Demarche::Ecartee { .. }),
                    "le 30/09/2026, un profil REALITY au Turkmenistan ne devait plus etre refuse: {apres:?}"
                );
            } else {
                assert_eq!(
                    avant,
                    apres,
                    "{pays:?}/{}: la demarche ne devait pas changer entre le 29 et le 30/09/2026",
                    t.nom()
                );
            }
        }
    }
}

/// A partir du jour annonce, plus aucun plan ne change, dans aucun pays ni aucun
/// mode, pendant un an.
///
/// Plus fort que "plus rien n'est ecarte", et c'est ce que "inerte" doit
/// vouloir dire pour qui lit `ETAT.md`: le tableau classe encore, mais d'un
/// classement FIGE. Cela tient parce que `rang_de_survie` ne lit que le statut
/// d'une cellule; le jour ou le classement lirait aussi sa fraicheur (par
/// exemple pour departager des ex aequo), cette recette rougira, et il faudra
/// redire ce que la constante annonce.
#[test]
fn a_partir_du_jour_annonce_aucun_plan_ne_bouge_plus() {
    for pays in TOUS_LES_PAYS {
        for mode in MODES {
            let reference = plan(pays, mode, TABLEAU_INERTE_A_PARTIR_DU);
            for n in 1..365 {
                let jour = decale(TABLEAU_INERTE_A_PARTIR_DU, n);
                assert_eq!(
                    plan(pays, mode, jour),
                    reference,
                    "en {pays:?}/{mode:?}, le plan change encore le {jour:?}, apres le jour annonce: \
                     le tableau n'est pas inerte au sens ou la constante le dit"
                );
            }
        }
    }
}
