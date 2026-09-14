//! Du plan a ce que le flux de connexion doit FAIRE.
//!
//! [`crate::planifier`] rend un ordre de preference. Ce module dit ce que cet
//! ordre implique pour le premier candidat, et la distinction n'est pas
//! cosmetique: un plan est une politique, une demarche est un engagement
//! d'execution. Les deux ne coutent pas la meme chose quand ils se trompent.
//!
//! C'est la piece qui manquait entre les deux objectifs du README. La selection
//! savait choisir, le superviseur savait lancer un coeur sous un compte dedie,
//! le kill switch savait l'exempter - et rien ne reliait le choix au lancement.
//!
//! Comme le reste du module de selection, il n'a aucun vocabulaire pour toucher
//! au kill switch. Il DECRIT ce qu'il faut faire; c'est l'appelant qui agit, et
//! l'appelant n'a jamais a baisser la garde pour suivre cette description.

use crate::coeur::{Coeur, coeur_de};
use crate::selection::{Plan, Refus};
use crate::technique::Technique;

/// Ce que le flux de connexion doit entreprendre, au vu du plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Demarche {
    /// Franchir un portail captif AVANT toute tentative.
    ///
    /// Passe devant tout le reste, y compris devant un plan sans candidat: le
    /// portail change l'environnement, donc un plan calcule derriere lui n'est
    /// pas celui qu'on a sous les yeux. Enchainer les protocoles devant un
    /// portail n'emettrait qu'une rafale, et une rafale est elle-meme une
    /// signature.
    PortailDAbord,
    /// Bifrost monte le tunnel lui-meme, sans coeur tiers.
    ///
    /// Aucune identite a exempter: un paquet chiffre par le noyau n'a pas de
    /// socket, donc pas de `skuid`. Il s'exempte par la marque que le
    /// chiffrement laisse.
    TunnelDirect(Technique),
    /// La technique retenue passe par un coeur tiers.
    ///
    /// Le coeur est a lancer sous le compte dedie, et son exemption doit
    /// figurer dans le kill switch AVANT qu'il ne tourne: l'ordre inverse
    /// obligerait soit a le lancer etrangle, soit a baisser la garde pour lui
    /// ouvrir la sortie.
    ParCoeur { technique: Technique, coeur: Coeur },
    /// Le plan a ECARTE toutes les techniques dont on dispose, et dit
    /// pourquoi chacune.
    ///
    /// Distincte de [`Demarche::SansIssue`], qui est l'absence de candidat.
    /// Ici il en reste peut-etre trois: ils ne sont simplement pas ce que
    /// l'utilisateur a sous la main. Confondre les deux rendrait "aucune
    /// technique candidate" a quelqu'un dont le plan en propose plusieurs, et
    /// le seul reproche qu'on puisse lui faire est de n'avoir pas les bons
    /// profils.
    ///
    /// **Tous les motifs, et pas seulement le premier.** Un profil qui propose
    /// trois techniques et se voit tout refuser doit apprendre les trois
    /// raisons: n'en montrer qu'une ferait corriger un point pour se heurter
    /// au suivant, et ainsi de suite. La liste n'est jamais vide - elle n'est
    /// construite que lorsqu'au moins une technique a ete ecartee.
    Ecartee { motifs: Vec<(Technique, Refus)> },
    /// Aucun candidat. Le kill switch reste arme et la connexion echoue.
    ///
    /// Echouer garde est le bon echec: c'est exactement l'etat ou l'on veut
    /// etre quand rien ne passe.
    SansIssue,
}

impl Demarche {
    /// Ce qu'UNE technique implique, sans rien savoir d'un plan.
    ///
    /// C'est par ici que [`crate::course`] passe: la course distribue les
    /// candidats un par un, et chacun appelle sa propre demarche. Sans cette
    /// fonction, il faudrait refaire ailleurs la correspondance entre technique
    /// et coeur, donc l'avoir a deux endroits et la voir diverger.
    pub fn pour(technique: Technique) -> Self {
        match coeur_de(technique) {
            Some(coeur) => Demarche::ParCoeur { technique, coeur },
            None => Demarche::TunnelDirect(technique),
        }
    }

    /// La technique que cette demarche engage a monter, s'il y en a une.
    ///
    /// C'est ce que le carnet doit noter. Sans cet accesseur, la notation se
    /// faisait par un filtrage sur `TunnelDirect` seul, et une connexion par
    /// coeur ne laissait AUCUNE trace: la moitie de la memoire dont la
    /// selection se sert n'etait jamais ecrite, et rien ne le disait.
    ///
    /// `None` pour les trois demarches qui ne montent rien. Noter un portail a
    /// franchir ou un refus comme un echec de technique salirait le carnet
    /// d'une ligne qui ne parle pas du reseau.
    pub fn technique(&self) -> Option<Technique> {
        match self {
            Demarche::TunnelDirect(t) | Demarche::ParCoeur { technique: t, .. } => Some(*t),
            Demarche::PortailDAbord | Demarche::Ecartee { .. } | Demarche::SansIssue => None,
        }
    }
}

/// Traduit un plan en la demarche a suivre pour son premier candidat.
///
/// Vue d'ensemble, pour annoncer ce qui va se passer. Le parcours reel de la
/// liste appartient a [`crate::course`], qui appelle [`Demarche::pour`] sur
/// chaque candidat qu'elle distribue.
pub fn demarche(plan: &Plan) -> Demarche {
    // 1. Le portail, avant meme de regarder s'il reste un candidat.
    if plan.portail_a_franchir {
        return Demarche::PortailDAbord;
    }
    // 2. Rien a essayer: echouer garde, ce qui est le bon echec.
    let Some(premier) = plan.candidats.first() else {
        return Demarche::SansIssue;
    };
    // 3. Seul le premier decide. Les suivants sont des replis, et les lire ici
    //    melangerait la demarche en cours avec celle d'apres.
    Demarche::pour(premier.technique)
}

/// La demarche pour les techniques QUE L'ON A, arbitrees par le plan.
///
/// [`demarche`] repond a "que faire du meilleur candidat du plan". Celle-ci
/// repond a "que faire de ceux qu'on possede", et c'est l'autre question -
/// celle du flux de connexion. L'utilisateur arrive avec un profil, qui decrit
/// un ensemble de techniques, souvent reduit a une. Lui opposer le premier
/// candidat du plan refuserait un profil WireGuard parfaitement utilisable
/// chaque fois que le plan prefere REALITY, c'est-a-dire presque toujours: le
/// daemon aurait l'air de selectionner alors qu'il ne ferait que refuser.
///
/// La selection garde donc tout son role, mais comme CLASSEMENT ET VETO plutot
/// que comme choix absolu. Elle ne dit pas quoi posseder - le profil le dit -
/// elle dit lequel de ce qu'on possede vient en premier ici, et ce qu'il ne
/// faut pas monter du tout, avec le motif. C'est la regle du document 04, "un
/// candidat ecarte dit pourquoi", portee jusqu'au refus que l'utilisateur lit.
///
/// **L'ordre du plan, pas celui de l'appelant.** Le premier candidat du plan
/// qui figure dans `techniques` gagne. Prendre le premier de `techniques`
/// laisserait l'ordre d'ecriture d'un fichier de profil decider a la place de
/// la selection, ce qui reviendrait a ne pas selectionner.
///
/// La distribution du RESTE de la liste, quand la premiere echoue, appartient
/// a [`crate::course`]. Cette fonction dit par ou commencer.
pub fn demarche_parmi(plan: &Plan, techniques: &[Technique]) -> Demarche {
    // Le portail d'abord, pour la meme raison que dans `demarche`: il change
    // l'environnement, donc le plan calcule derriere lui n'est pas celui qu'on
    // a sous les yeux.
    if plan.portail_a_franchir {
        return Demarche::PortailDAbord;
    }
    // `planifier` partitionne `Technique::TOUTES`: une technique absente des
    // ecartes est retenue. Parcourir les candidats DANS L'ORDRE DU PLAN et
    // garder le premier qu'on possede donne donc a la fois le classement et le
    // veto, et une recette de `selection` garde cette partition.
    if let Some(c) = plan
        .candidats
        .iter()
        .find(|c| techniques.contains(&c.technique))
    {
        return Demarche::pour(c.technique);
    }
    // Rien de ce qu'on a n'est retenu. Rendre TOUS les motifs, dans l'ordre ou
    // l'appelant a presente ses techniques: c'est le sien, donc celui de son
    // fichier, donc celui ou il relira ses lignes.
    let motifs: Vec<(Technique, Refus)> = techniques
        .iter()
        .filter_map(|t| {
            plan.ecartes
                .iter()
                .find(|(e, _)| e == t)
                .map(|(_, r)| (*t, *r))
        })
        .collect();
    if motifs.is_empty() {
        // Ni retenue ni ecartee: l'appelant n'a presente aucune technique. Un
        // portage vide ne devrait pas exister - `Profils` l'interdit - mais le
        // dire vaut mieux que de rendre une liste vide qu'un affichage
        // presenterait comme "aucun motif".
        return Demarche::SansIssue;
    }
    Demarche::Ecartee { motifs }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::selection::{Candidat, JITTER_MAX, JITTER_MIN, PARALLELISME_MAX};

    fn plan_de(techniques: &[Technique], portail: bool) -> Plan {
        Plan {
            candidats: techniques
                .iter()
                .map(|t| Candidat {
                    technique: *t,
                    pourquoi: "fixture",
                })
                .collect(),
            ecartes: Vec::new(),
            portail_a_franchir: portail,
            parallelisme_max: PARALLELISME_MAX,
            jitter: (JITTER_MIN, JITTER_MAX),
        }
    }

    #[test]
    fn wireguard_nu_se_monte_sans_coeur() {
        assert_eq!(
            demarche(&plan_de(&[Technique::WireGuardNu], false)),
            Demarche::TunnelDirect(Technique::WireGuardNu)
        );
    }

    #[test]
    fn les_techniques_a_coeur_nomment_le_leur() {
        assert_eq!(
            demarche(&plan_de(&[Technique::XhttpCdn], false)),
            Demarche::ParCoeur {
                technique: Technique::XhttpCdn,
                coeur: Coeur::XrayCore
            }
        );
        assert_eq!(
            demarche(&plan_de(&[Technique::RealityVision], false)),
            Demarche::ParCoeur {
                technique: Technique::RealityVision,
                coeur: Coeur::SingBox
            }
        );
        assert_eq!(
            demarche(&plan_de(&[Technique::Hysteria2], false)),
            Demarche::ParCoeur {
                technique: Technique::Hysteria2,
                coeur: Coeur::SingBox
            }
        );
    }

    /// Seul le PREMIER candidat decide. Les suivants sont des replis, et les
    /// lire ici melangerait la demarche en cours avec celle d'apres.
    #[test]
    fn seul_le_premier_candidat_decide() {
        assert_eq!(
            demarche(&plan_de(
                &[Technique::WireGuardNu, Technique::RealityVision],
                false
            )),
            Demarche::TunnelDirect(Technique::WireGuardNu)
        );
    }

    /// Les deux chemins doivent dire la meme chose du meme candidat, sans quoi
    /// la vue d'ensemble annoncerait autre chose que ce que la course fera.
    #[test]
    fn la_vue_d_ensemble_et_le_cas_par_cas_s_accordent() {
        for t in Technique::TOUTES {
            let plan = plan_de(&[t], false);
            assert_eq!(
                demarche(&plan),
                Demarche::pour(t),
                "{} vu differemment selon le chemin",
                t.nom()
            );
        }
    }

    #[test]
    fn un_plan_sans_candidat_est_sans_issue() {
        assert_eq!(demarche(&plan_de(&[], false)), Demarche::SansIssue);
    }

    /// Le portail passe devant TOUT, y compris devant un plan sans candidat:
    /// il change l'environnement, donc le plan calcule derriere lui n'est pas
    /// celui qu'on a sous les yeux. Conclure "sans issue" avant de l'avoir
    /// franchi condamnerait une connexion qui n'a pas encore ete tentee.
    #[test]
    fn le_portail_passe_avant_tout() {
        assert_eq!(
            demarche(&plan_de(&[Technique::WireGuardNu], true)),
            Demarche::PortailDAbord
        );
        assert_eq!(demarche(&plan_de(&[], true)), Demarche::PortailDAbord);
    }

    // -----------------------------------------------------------------------
    // L'arbitrage d'une technique imposee par le profil
    // -----------------------------------------------------------------------

    fn plan_avec_ecart(retenues: &[Technique], ecartee: Technique, refus: Refus) -> Plan {
        let mut plan = plan_de(retenues, false);
        plan.ecartes.push((ecartee, refus));
        plan
    }

    /// LE defaut que cette fonction existe pour corriger. Opposer le premier
    /// candidat du plan a un profil refuserait presque toujours, puisque le
    /// plan prefere REALITY et que la plupart des profils ne sont pas cela.
    #[test]
    fn une_technique_retenue_passe_meme_si_le_plan_prefere_une_autre() {
        let plan = plan_de(&[Technique::RealityVision, Technique::WireGuardNu], false);
        assert_eq!(
            demarche(&plan),
            Demarche::ParCoeur {
                technique: Technique::RealityVision,
                coeur: Coeur::SingBox
            },
            "le plan doit bien preferer REALITY, sinon la recette ne prouve rien"
        );
        assert_eq!(
            demarche_parmi(&plan, &[Technique::WireGuardNu]),
            Demarche::TunnelDirect(Technique::WireGuardNu)
        );
    }

    /// Un veto se lit. Rendre `SansIssue` ici dirait "aucune technique
    /// candidate" a quelqu'un dont le plan en propose une autre.
    #[test]
    fn une_technique_ecartee_l_est_avec_son_motif() {
        let plan = plan_avec_ecart(
            &[Technique::RealityVision],
            Technique::Hysteria2,
            Refus::UdpMesureBloque,
        );
        assert_eq!(
            demarche_parmi(&plan, &[Technique::Hysteria2]),
            Demarche::Ecartee {
                motifs: vec![(Technique::Hysteria2, Refus::UdpMesureBloque)]
            }
        );
    }

    /// Le portail change l'environnement: le plan calcule derriere lui n'est
    /// pas celui qu'on a sous les yeux, donc son ecart ne vaut rien encore.
    #[test]
    fn le_portail_passe_avant_l_ecart() {
        let mut plan = plan_avec_ecart(&[], Technique::Hysteria2, Refus::UdpMesureBloque);
        plan.portail_a_franchir = true;
        assert_eq!(
            demarche_parmi(&plan, &[Technique::Hysteria2]),
            Demarche::PortailDAbord
        );
    }

    /// C'est le plan qui classe, pas l'ordre d'ecriture du fichier de profil.
    ///
    /// Sans cela, la selection serait un decor: celui qui ecrit ses profils
    /// dans un ordre quelconque deciderait a sa place.
    #[test]
    fn l_ordre_du_plan_l_emporte_sur_celui_de_l_appelant() {
        let plan = plan_de(&[Technique::RealityVision, Technique::Hysteria2], false);
        // Presentes dans l'ordre INVERSE de la preference du plan.
        assert_eq!(
            demarche_parmi(&plan, &[Technique::Hysteria2, Technique::RealityVision]),
            Demarche::pour(Technique::RealityVision)
        );
    }

    /// Tous les motifs, pas seulement le premier: corriger un point pour se
    /// heurter au suivant est le pire des diagnostics.
    #[test]
    fn tout_ecarter_rend_tous_les_motifs() {
        let mut plan = plan_de(&[Technique::RealityVision], false);
        plan.ecartes
            .push((Technique::Hysteria2, Refus::UdpMesureBloque));
        plan.ecartes
            .push((Technique::WireGuardNu, Refus::PortHautMesureFerme));
        assert_eq!(
            demarche_parmi(&plan, &[Technique::Hysteria2, Technique::WireGuardNu]),
            Demarche::Ecartee {
                motifs: vec![
                    (Technique::Hysteria2, Refus::UdpMesureBloque),
                    (Technique::WireGuardNu, Refus::PortHautMesureFerme),
                ]
            }
        );
    }

    /// Une seule technique retenue suffit: les ecartes qui l'accompagnent ne
    /// doivent pas condamner la connexion.
    #[test]
    fn une_seule_technique_debout_suffit() {
        let mut plan = plan_de(&[Technique::Hysteria2], false);
        plan.ecartes
            .push((Technique::RealityVision, Refus::MitmTlsMesure));
        assert_eq!(
            demarche_parmi(&plan, &[Technique::RealityVision, Technique::Hysteria2]),
            Demarche::pour(Technique::Hysteria2)
        );
    }

    /// Un plan sans candidat n'ecarte pas pour autant ce qu'il n'a pas examine.
    /// La seule facon d'etre ecarte est de figurer dans les ecartes, et
    /// `planifier` garantit que l'un ou l'autre est vrai de chaque technique.
    #[test]
    fn l_arbitrage_ne_lit_que_les_ecartes() {
        for t in Technique::TOUTES {
            assert_eq!(
                demarche_parmi(&plan_de(&[t], false), &[t]),
                Demarche::pour(t),
                "{} ecartee sans figurer dans les ecartes",
                t.nom()
            );
        }
    }

    /// Aucune technique presentee: `SansIssue`, et surtout pas une liste de
    /// motifs vide qu'un affichage rendrait comme "ecartee, sans raison".
    #[test]
    fn un_appelant_sans_technique_est_sans_issue() {
        assert_eq!(
            demarche_parmi(&plan_de(&[Technique::RealityVision], false), &[]),
            Demarche::SansIssue
        );
    }

    /// Ce que le carnet notera. Les demarches qui ne montent rien ne doivent
    /// rien y inscrire: une ligne de carnet parle du RESEAU, et un portail a
    /// franchir ou un veto de selection n'en parlent pas.
    #[test]
    fn seules_les_demarches_qui_montent_quelque_chose_nomment_leur_technique() {
        for t in Technique::TOUTES {
            assert_eq!(
                Demarche::pour(t).technique(),
                Some(t),
                "{} montee sans etre notable",
                t.nom()
            );
        }
        assert_eq!(Demarche::PortailDAbord.technique(), None);
        assert_eq!(Demarche::SansIssue.technique(), None);
        assert_eq!(
            Demarche::Ecartee {
                motifs: vec![(Technique::Hysteria2, Refus::UdpMesureBloque)]
            }
            .technique(),
            None
        );
    }
}
