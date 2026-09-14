//! Choix du protocole: une fonction pure, du contexte vers un plan d'essai.
//!
//! Deux regles gouvernent tout le module, et elles ne sont pas symetriques.
//!
//! **Seule une mesure elimine.** Une sonde qui n'a pas tourne ne retire jamais
//! un candidat. C'est la meme discipline que le harnais de fuite, ou un vecteur
//! qui ne peut pas s'executer rend `SKIPPED` et jamais `PASSED`: l'ignorance ne
//! se transforme pas en conclusion.
//!
//! **Un candidat ecarte dit pourquoi.** Le plan porte ses refus avec leur
//! motif. Un choix de protocole qui ne s'explique pas est indebogable sur le
//! terrain, ou l'on ne dispose ni du reseau du censeur ni d'une deuxieme
//! chance.
//!
//! Ce module n'a aucun vocabulaire pour toucher au kill switch, et c'est
//! delibere: le document 04 exige qu'il ne soit jamais leve pendant une
//! bascule. La garantie ne repose pas sur la prudence de l'appelant mais sur
//! l'absence du verbe.

use std::time::Duration;

use crate::date::Date;
use crate::environnement::Environnement;
use crate::memoire::MemoireReseau;
use crate::survie::{Pays, Statut, statut};
use crate::technique::{Camouflage, Technique, Transport};

/// L'intention de l'utilisateur, jamais un nom de protocole.
///
/// Document 04 partie 6: "L'utilisateur ne choisit jamais VLESS contre
/// Hysteria2; il choisit une intention."
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    /// Machine a etats complete. Defaut.
    #[default]
    Auto,
    /// Le chemin le plus furtif, quel qu'en soit le cout.
    Discret,
    /// Le chemin le plus efficace que le reseau tolere.
    Rapide,
}

/// Au-dela de cette perte, le mode Rapide prefere un protocole qui la tient
/// plutot que le moins couteux. Seuil du document 04 partie 5.
pub const PERTE_QUI_CHANGE_LA_DONNE: u8 = 5;

/// Pourquoi un candidat a ete ecarte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refus {
    /// L'UDP sortant a ete mesure bloque.
    UdpMesureBloque,
    /// QUIC a ete mesure bloque, sans que l'UDP le soit.
    QuicMesureBloque,
    /// Seuls 80 et 443 repondent, la technique demande un autre port.
    PortHautMesureFerme,
    /// Le TLS est intercepte et la technique n'y survit pas.
    MitmTlsMesure,
    /// Le tableau de survie la dit morte ici, et l'observation est fraiche.
    MorteEtObservationFraiche,
    /// Le mode choisi ne l'autorise pas.
    ModeIncompatible,
}

impl Refus {
    pub fn motif(self) -> &'static str {
        match self {
            Refus::UdpMesureBloque => "UDP sortant mesure bloque",
            Refus::QuicMesureBloque => "QUIC mesure bloque",
            Refus::PortHautMesureFerme => "seuls 80 et 443 repondent",
            Refus::MitmTlsMesure => "TLS intercepte, technique non compatible",
            Refus::MorteEtObservationFraiche => "donnee morte dans ce pays, observation fraiche",
            Refus::ModeIncompatible => "ecartee par le mode choisi",
        }
    }
}

/// Tout ce dont la selection a besoin. Rien d'autre ne l'influence.
#[derive(Debug, Clone)]
pub struct Contexte<'a> {
    pub pays: Pays,
    pub environnement: Environnement,
    pub mode: Mode,
    pub memoire: &'a MemoireReseau,
    /// Fourni par l'appelant, jamais lu d'une horloge ici.
    pub aujourd_hui: Date,
}

/// Un candidat retenu, avec ce qui l'a place la.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidat {
    pub technique: Technique,
    /// Ce qui a decide de son rang. Destine au journal, pas a l'utilisateur.
    pub pourquoi: &'static str,
}

/// Le resultat: quoi essayer, dans quel ordre, a quel rythme, et ce qui a ete
/// ecarte.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub candidats: Vec<Candidat>,
    pub ecartes: Vec<(Technique, Refus)>,
    /// Un portail captif doit etre franchi avant toute tentative: sinon rien
    /// ne passera, et enchainer les protocoles n'emettra qu'une rafale.
    pub portail_a_franchir: bool,
    /// Jamais plus de deux essais concurrents: six protocoles en rafale sont
    /// eux-memes une signature (document 04 partie 3.2).
    pub parallelisme_max: usize,
    /// Bornes du delai entre deux tentatives. Le tirage est laisse a
    /// l'appelant: du hasard ici rendrait la fonction impure et le plan
    /// intestable.
    pub jitter: (Duration, Duration),
}

pub const PARALLELISME_MAX: usize = 2;
pub const JITTER_MIN: Duration = Duration::from_millis(400);
pub const JITTER_MAX: Duration = Duration::from_millis(2_500);

impl Plan {
    /// Aucun candidat ne subsiste. L'appelant ne doit surtout pas en conclure
    /// qu'il peut sortir en clair: le kill switch reste arme, c'est la
    /// connexion qui echoue.
    pub fn est_sans_issue(&self) -> bool {
        self.candidats.is_empty()
    }

    pub fn premier(&self) -> Option<Technique> {
        self.candidats.first().map(|c| c.technique)
    }
}

/// Rang du statut de survie, du meilleur au pire.
///
/// L'absence d'observation vaut moins qu'un `Degrade` observe et mieux qu'un
/// `Incertain`: savoir qu'une technique marche a moitie vaut mieux que ne rien
/// savoir, et ne rien savoir vaut mieux que savoir qu'elle tient ou tombe selon
/// l'humeur du censeur.
fn rang_de_survie(t: Technique, ctx: &Contexte) -> u8 {
    match statut(t, ctx.pays) {
        Some(o) => match o.statut {
            Statut::Fonctionne => 0,
            Statut::Degrade => 1,
            Statut::Incertain => 3,
            // Non eliminee, donc l'observation est perimee: derniere.
            Statut::Mort => 4,
        },
        None => 2,
    }
}

/// Les preconditions de la technique sont-elles MESUREES satisfaites.
///
/// Distinct de "non contredites". Une technique dont on a verifie que le
/// transport passe doit devancer une technique dont on n'a rien verifie, sans
/// que cette derniere soit ecartee pour autant.
fn preconditions_confirmees(t: Technique, env: &Environnement) -> bool {
    let transport_confirme = match t.transport() {
        Transport::Tcp443 => env.tcp443_passe.vu_vrai(),
        Transport::Udp443 => env.udp_passe.vu_vrai() && env.quic_passe.vu_vrai(),
        Transport::UdpPortLibre => env.udp_passe.vu_vrai() && env.ports_hauts_ouverts.vu_vrai(),
    };
    // Un TLS intercepte ne retire pas la confirmation aux techniques qui y
    // survivent, mais il l'interdit a celles qui n'y survivent pas. Celles-la
    // sont deja eliminees par `refuser`; la condition reste pour que la
    // fonction se tienne seule.
    transport_confirme && (!env.mitm_tls.vu_vrai() || t.survit_au_mitm_tls())
}

/// Rang impose par le mode. Plus petit vaut mieux.
fn rang_de_mode(t: Technique, ctx: &Contexte) -> u8 {
    match ctx.mode {
        Mode::Auto => 0,
        Mode::Discret => match t.camouflage() {
            Camouflage::SiteEmprunte => 0,
            Camouflage::TraficWebOrdinaire => 1,
            // Ecartees en amont; la valeur n'est la que pour la totalite.
            Camouflage::BruitDeHandshake | Camouflage::Aucun => 2,
        },
        Mode::Rapide => {
            let perte_forte = match ctx.environnement.perte_pourcent {
                crate::environnement::Mesure::Vu(p) => p > PERTE_QUI_CHANGE_LA_DONNE,
                crate::environnement::Mesure::NonMesure => false,
            };
            if perte_forte && t.tient_la_perte() {
                0
            } else {
                // Le cout machine, decale pour rester derriere le cas ci-dessus.
                1 + t.cout_machine()
            }
        }
    }
}

/// Ce qui elimine la technique, s'il y a lieu.
fn refuser(t: Technique, ctx: &Contexte) -> Option<Refus> {
    let env = &ctx.environnement;

    if ctx.mode == Mode::Discret
        && matches!(
            t.camouflage(),
            Camouflage::BruitDeHandshake | Camouflage::Aucun
        )
    {
        return Some(Refus::ModeIncompatible);
    }

    if t.transport().est_udp() && env.udp_passe.vu_faux() {
        return Some(Refus::UdpMesureBloque);
    }
    if t.transport() == Transport::Udp443 && env.quic_passe.vu_faux() {
        return Some(Refus::QuicMesureBloque);
    }
    if !t.transport().tient_sur_80_443() && env.ports_hauts_ouverts.vu_faux() {
        return Some(Refus::PortHautMesureFerme);
    }
    if env.mitm_tls.vu_vrai() && !t.survit_au_mitm_tls() {
        return Some(Refus::MitmTlsMesure);
    }

    if let Some(o) = statut(t, ctx.pays)
        && o.statut == Statut::Mort
        && o.assez_fraiche_pour_eliminer(ctx.aujourd_hui)
    {
        return Some(Refus::MorteEtObservationFraiche);
    }

    None
}

/// Construit le plan d'essai.
pub fn planifier(ctx: &Contexte) -> Plan {
    let memorisee = ctx.memoire.reussite_utilisable(ctx.aujourd_hui);

    let mut retenus: Vec<(Cle, Candidat)> = Vec::new();
    let mut ecartes: Vec<(Technique, Refus)> = Vec::new();

    for (position, t) in Technique::TOUTES.into_iter().enumerate() {
        if let Some(refus) = refuser(t, ctx) {
            ecartes.push((t, refus));
            continue;
        }

        // Une reussite memorisee ne survit pas a un refus: si le reseau a
        // change au point d'eliminer la technique, le souvenir est caduc. Le
        // `continue` ci-dessus s'en charge, et c'est voulu.
        let memorisee_ici = memorisee == Some(t);
        let echec_recent = ctx.memoire.echec_recent(t, ctx.aujourd_hui);

        let pourquoi = if memorisee_ici {
            "a deja marche sur ce reseau"
        } else if echec_recent {
            "vient d'echouer ici, gardee en dernier recours"
        } else if preconditions_confirmees(t, &ctx.environnement) {
            "preconditions mesurees satisfaites"
        } else {
            "non contredite par les mesures"
        };

        retenus.push((
            Cle {
                echec_recent: echec_recent as u8,
                memorisee: !memorisee_ici as u8,
                survie: rang_de_survie(t, ctx),
                preconditions: !preconditions_confirmees(t, &ctx.environnement) as u8,
                mode: rang_de_mode(t, ctx),
                position: position as u8,
            },
            Candidat {
                technique: t,
                pourquoi,
            },
        ));
    }

    retenus.sort_by_key(|(cle, _)| *cle);

    Plan {
        candidats: retenus.into_iter().map(|(_, c)| c).collect(),
        ecartes,
        portail_a_franchir: ctx.environnement.portail_a_franchir(),
        parallelisme_max: PARALLELISME_MAX,
        jitter: (JITTER_MIN, JITTER_MAX),
    }
}

/// Cle de tri, lue de gauche a droite.
///
/// L'ordre des champs EST la politique, et c'est pour cela qu'il est declare
/// une fois ici plutot qu'enfoui dans un comparateur. Un echec tout frais passe
/// avant tout le reste parce qu'il vient d'etre observe sur ce reseau precis;
/// un souvenir de reussite ensuite, pour eviter de re-sonder; puis ce que le
/// tableau de survie sait du pays; puis les mesures locales; puis l'intention
/// de l'utilisateur; et la position de declaration pour que deux executions
/// identiques rendent le meme ordre.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Cle {
    echec_recent: u8,
    memorisee: u8,
    survie: u8,
    preconditions: u8,
    mode: u8,
    position: u8,
}

#[cfg(test)]
mod tests {
    /// Chaque technique est SOIT retenue SOIT ecartee, jamais ni l'un ni
    /// l'autre.
    ///
    /// [`crate::demarche::demarche_arbitree`] en depend directement: elle
    /// conclut "retenue" de l'absence dans les ecartes. Le jour ou un candidat
    /// serait filtre sans passer par `refuser`, il disparaitrait des deux
    /// listes et se monterait quand meme, en silence. C'est le seul mode
    /// d'echec de cette fonction, et il se garde ici plutot que la-bas: c'est
    /// ici qu'il naitrait.
    #[test]
    fn chaque_technique_est_retenue_ou_ecartee_jamais_perdue() {
        let vierge = crate::memoire::MemoireReseau::vierge();
        for pays in [
            crate::survie::Pays::NonCensure,
            crate::survie::Pays::Chine,
            crate::survie::Pays::Russie,
            crate::survie::Pays::Iran,
            crate::survie::Pays::Turkmenistan,
        ] {
            for mode in [super::Mode::Auto, super::Mode::Discret, super::Mode::Rapide] {
                let plan = super::planifier(&super::Contexte {
                    pays,
                    environnement: crate::environnement::Environnement::default(),
                    mode,
                    memoire: &vierge,
                    aujourd_hui: crate::date::Date::new(2026, 8, 20),
                });
                let mut vues: Vec<crate::technique::Technique> = plan
                    .candidats
                    .iter()
                    .map(|c| c.technique)
                    .chain(plan.ecartes.iter().map(|(t, _)| *t))
                    .collect();
                vues.sort_unstable();
                vues.dedup();
                assert_eq!(
                    vues.len(),
                    crate::technique::Technique::TOUTES.len(),
                    "{pays:?}/{mode:?}: une technique n'est ni retenue ni ecartee"
                );
            }
        }
    }

    use super::*;
    use crate::environnement::Mesure;

    const AOUT: Date = Date::new(2026, 8, 16);

    fn ctx<'a>(pays: Pays, env: Environnement, mode: Mode, m: &'a MemoireReseau) -> Contexte<'a> {
        Contexte {
            pays,
            environnement: env,
            mode,
            memoire: m,
            aujourd_hui: AOUT,
        }
    }

    fn vierge() -> MemoireReseau {
        MemoireReseau::vierge()
    }

    #[test]
    fn sans_aucune_sonde_rien_n_est_ecarte_par_l_environnement() {
        // La regle centrale du module. Si elle tombait, un client qui n'a pas
        // eu le temps de sonder se retrouverait sans candidat.
        let m = vierge();
        let p = planifier(&ctx(
            Pays::NonCensure,
            Environnement::rien_sonde(),
            Mode::Auto,
            &m,
        ));
        assert_eq!(p.candidats.len(), Technique::TOUTES.len());
        assert!(p.ecartes.is_empty());
    }

    #[test]
    fn un_udp_mesure_bloque_ecarte_toutes_les_techniques_udp() {
        let m = vierge();
        let env = Environnement {
            udp_passe: Mesure::Vu(false),
            ..Environnement::rien_sonde()
        };
        let p = planifier(&ctx(Pays::NonCensure, env, Mode::Auto, &m));
        for c in &p.candidats {
            assert!(
                !c.technique.transport().est_udp(),
                "{} a survecu a un UDP bloque",
                c.technique.nom()
            );
        }
        assert_eq!(p.ecartes.len(), 3);
        assert!(p.ecartes.iter().all(|(_, r)| *r == Refus::UdpMesureBloque));
    }

    #[test]
    fn un_udp_non_mesure_n_ecarte_rien() {
        // Le pendant du test precedent, et le vrai piege: un `bool` a false par
        // defaut aurait le meme effet qu'un UDP mesure bloque.
        let m = vierge();
        let p = planifier(&ctx(
            Pays::NonCensure,
            Environnement::rien_sonde(),
            Mode::Auto,
            &m,
        ));
        assert!(
            p.candidats
                .iter()
                .any(|c| c.technique.transport().est_udp())
        );
    }

    #[test]
    fn quic_bloque_seul_n_emporte_pas_amneziawg() {
        // Le GFW dechiffre l'Initial QUIC sans couper l'UDP. Confondre les deux
        // couterait AmneziaWG, qui est precisement le repli prevu la.
        let m = vierge();
        let env = Environnement {
            udp_passe: Mesure::Vu(true),
            quic_passe: Mesure::Vu(false),
            ..Environnement::rien_sonde()
        };
        let p = planifier(&ctx(Pays::NonCensure, env, Mode::Auto, &m));
        let noms: Vec<_> = p.candidats.iter().map(|c| c.technique).collect();
        assert!(!noms.contains(&Technique::Hysteria2));
        assert!(noms.contains(&Technique::AmneziaWg));
        assert_eq!(
            p.ecartes,
            vec![(Technique::Hysteria2, Refus::QuicMesureBloque)]
        );
    }

    #[test]
    fn un_reseau_qui_n_ouvre_que_80_et_443_ecarte_les_ports_libres() {
        let m = vierge();
        let env = Environnement {
            udp_passe: Mesure::Vu(true),
            ports_hauts_ouverts: Mesure::Vu(false),
            ..Environnement::rien_sonde()
        };
        let p = planifier(&ctx(Pays::NonCensure, env, Mode::Auto, &m));
        let noms: Vec<_> = p.candidats.iter().map(|c| c.technique).collect();
        assert!(!noms.contains(&Technique::AmneziaWg));
        assert!(!noms.contains(&Technique::WireGuardNu));
        assert!(
            noms.contains(&Technique::Hysteria2),
            "UDP/443 tient sur ce reseau"
        );
    }

    #[test]
    fn un_mitm_tls_ecarte_reality_et_garde_xhttp() {
        // Le cas du reseau d'entreprise. La technique la plus furtive face a un
        // etat est ici la seule a tomber.
        let m = vierge();
        let env = Environnement {
            mitm_tls: Mesure::Vu(true),
            ..Environnement::rien_sonde()
        };
        let p = planifier(&ctx(Pays::NonCensure, env, Mode::Auto, &m));
        let noms: Vec<_> = p.candidats.iter().map(|c| c.technique).collect();
        assert!(!noms.contains(&Technique::RealityVision));
        assert!(noms.contains(&Technique::XhttpCdn));
        assert_eq!(
            p.ecartes,
            vec![(Technique::RealityVision, Refus::MitmTlsMesure)]
        );
    }

    #[test]
    fn le_mode_discret_ne_garde_que_les_camouflages_qui_imitent_du_web() {
        let m = vierge();
        let p = planifier(&ctx(
            Pays::NonCensure,
            Environnement::rien_sonde(),
            Mode::Discret,
            &m,
        ));
        let noms: Vec<_> = p.candidats.iter().map(|c| c.technique).collect();
        assert_eq!(
            noms,
            vec![
                Technique::RealityVision,
                Technique::XhttpCdn,
                Technique::WebsocketCdn,
                Technique::HttpUpgradeFront
            ]
        );
        assert!(p.ecartes.iter().all(|(_, r)| *r == Refus::ModeIncompatible));
    }

    /// Le cas qui a motive l'ajout de HTTPUpgrade, et qu'aucune recette ne
    /// couvrait: le mode Discret DERRIERE une interception TLS.
    ///
    /// Mesure du 21 aout 2026, avant le correctif: le plan rendait
    /// `[XhttpCdn]` et rien d'autre. Discret ecarte les trois camouflages qui
    /// ne ressemblent pas a du web, l'interception ecarte REALITY, et le seul
    /// survivant etait une technique que RIEN dans ce depot ne sait monter -
    /// aucune forme de `Profil` ne la decrit et aucun generateur Xray n'existe.
    /// Le plan disait "vas-y" et rien ne demarrait.
    ///
    /// Ce que cette recette exige n'est donc pas "il reste un candidat" mais
    /// "il reste un candidat MONTABLE", ce qui se lit ici a son coeur: un
    /// candidat servi par sing-box est engendrable par le generateur existant.
    #[test]
    fn discret_derriere_un_mitm_garde_un_candidat_montable() {
        let m = vierge();
        let env = Environnement {
            mitm_tls: Mesure::Vu(true),
            ..Environnement::rien_sonde()
        };
        let p = planifier(&ctx(Pays::NonCensure, env, Mode::Discret, &m));
        let noms: Vec<_> = p.candidats.iter().map(|c| c.technique).collect();

        assert!(
            noms.contains(&Technique::WebsocketCdn),
            "sans lui, Discret sous MITM n'a que XhttpCdn, qui ne se monte pas: {noms:?}"
        );
        assert!(
            !noms.contains(&Technique::RealityVision),
            "REALITY ne survit pas a une terminaison TLS"
        );

        // La condition qui compte vraiment: au moins un candidat dont le coeur
        // est celui que le generateur sait configurer.
        let montables: Vec<_> = noms
            .iter()
            .filter(|t| crate::coeur::coeur_de(**t) == Some(crate::coeur::Coeur::SingBox))
            .collect();
        assert!(
            !montables.is_empty(),
            "aucun candidat servi par sing-box: le plan promettrait ce que rien ne tient ({noms:?})"
        );
    }

    #[test]
    fn le_mode_rapide_prefere_le_moins_couteux_quand_le_reseau_est_propre() {
        let m = vierge();
        let env = Environnement {
            perte_pourcent: Mesure::Vu(0),
            ..Environnement::rien_sonde()
        };
        let p = planifier(&ctx(Pays::NonCensure, env, Mode::Rapide, &m));
        assert_eq!(p.premier(), Some(Technique::WireGuardNu));
    }

    #[test]
    fn le_mode_rapide_bascule_sur_hysteria2_quand_le_reseau_perd() {
        let m = vierge();
        let env = Environnement {
            udp_passe: Mesure::Vu(true),
            quic_passe: Mesure::Vu(true),
            perte_pourcent: Mesure::Vu(12),
            ..Environnement::rien_sonde()
        };
        let p = planifier(&ctx(Pays::NonCensure, env, Mode::Rapide, &m));
        assert_eq!(p.premier(), Some(Technique::Hysteria2));
    }

    #[test]
    fn une_perte_non_mesuree_ne_declenche_pas_la_bascule() {
        let m = vierge();
        let p = planifier(&ctx(
            Pays::NonCensure,
            Environnement::rien_sonde(),
            Mode::Rapide,
            &m,
        ));
        assert_eq!(p.premier(), Some(Technique::WireGuardNu));
    }

    #[test]
    fn en_chine_wireguard_nu_est_ecarte_si_l_observation_est_fraiche() {
        let m = vierge();
        let mut c = ctx(Pays::Chine, Environnement::rien_sonde(), Mode::Auto, &m);
        // Observation du 1er avril 2026: fraiche au 1er juin.
        c.aujourd_hui = Date::new(2026, 6, 1);
        let p = planifier(&c);
        assert!(
            p.ecartes
                .contains(&(Technique::WireGuardNu, Refus::MorteEtObservationFraiche))
        );
        assert_eq!(p.premier(), Some(Technique::RealityVision));
    }

    #[test]
    fn la_meme_observation_perimee_ne_l_ecarte_plus_mais_le_classe_dernier() {
        // La nuance qui compte: un censeur qui leve un blocage sans qu'on le
        // sache ne doit pas nous priver du protocole a jamais.
        let m = vierge();
        let p = planifier(&ctx(
            Pays::Chine,
            Environnement::rien_sonde(),
            Mode::Auto,
            &m,
        ));
        let noms: Vec<_> = p.candidats.iter().map(|c| c.technique).collect();
        assert!(noms.contains(&Technique::WireGuardNu));
        assert_eq!(noms.last(), Some(&Technique::WireGuardNu));
    }

    /// En Russie, c'est desormais XHTTP qui passe devant - et pourquoi.
    ///
    /// Cette recette exigeait AmneziaWG jusqu'au 20 aout 2026, parce que le
    /// tableau l'y donnait seule `Fonctionne`. La documentation amont d'Amnezia
    /// rattache sa version 3.0 au "blocage generalise en Russie en juin et
    /// juillet 2026": la cellule est passee a `Degrade`, et la recette est
    /// tombee. C'est le comportement attendu d'une politique qui est de la
    /// donnee - le tableau change, le plan change avec lui.
    ///
    /// Ce que la recette verifie maintenant n'est donc pas un nom mais une
    /// MECANIQUE: quand trois candidats partagent le meme rang de survie, c'est
    /// l'ordre de declaration qui departage, et il est stable. Le nom est
    /// verifie ensuite pour que le changement se voie, pas pour lui-meme.
    #[test]
    fn en_russie_les_degrades_passent_devant_et_l_ordre_de_declaration_departage() {
        let m = vierge();
        let p = planifier(&ctx(
            Pays::Russie,
            Environnement::rien_sonde(),
            Mode::Auto,
            &m,
        ));
        // Aucune valeur sure sur ce reseau: le mieux disponible est `Degrade`.
        let tete: Vec<Technique> = p.candidats.iter().take(3).map(|c| c.technique).collect();
        for t in &tete {
            assert_eq!(
                crate::survie::statut(*t, Pays::Russie).map(|o| o.statut),
                Some(crate::survie::Statut::Degrade),
                "{} n'est pas Degrade: la tete du plan russe a change de nature",
                t.nom()
            );
        }
        // Et entre egaux, l'ordre de declaration. XHTTP est declare avant
        // HTTPUpgrade, lui-meme avant Hysteria2. La boucle ci-dessus vaut plus
        // que cette liste: elle exige que la tete soit faite de `Degrade`
        // SOURCES, ce qui a tenu quand une quatrieme technique est arrivee.
        assert_eq!(
            tete,
            vec![
                Technique::XhttpCdn,
                Technique::HttpUpgradeFront,
                Technique::Hysteria2
            ]
        );
    }

    /// Un souvenir de reussite passe devant ce que le tableau dit du pays.
    ///
    /// La technique memorisee est choisie a dessein: REALITY est `Incertain` en
    /// Russie, donc le tableau la met DERRIERE les trois `Degrade`. Sans le
    /// souvenir, elle n'a aucune chance d'etre en tete - c'est ce qui fait de
    /// cette recette une mesure et non un echo.
    ///
    /// Elle nommait XHTTP jusqu'au 20 aout 2026. La correction du tableau a
    /// fait de XHTTP la tete du plan russe par ailleurs: la recette serait
    /// restee VERTE en supprimant la memoire, donc elle ne prouvait plus rien.
    #[test]
    fn une_reussite_memorisee_passe_devant_le_tableau_de_survie() {
        let sans_souvenir = planifier(&ctx(
            Pays::Russie,
            Environnement::rien_sonde(),
            Mode::Auto,
            &vierge(),
        ));
        assert_ne!(
            sans_souvenir.premier(),
            Some(Technique::RealityVision),
            "le tableau doit mettre REALITY en retrait en Russie, sinon la recette ne mesure rien"
        );

        let mut m = MemoireReseau::vierge();
        m.noter_reussite(Technique::RealityVision, Date::new(2026, 8, 15));
        let p = planifier(&ctx(
            Pays::Russie,
            Environnement::rien_sonde(),
            Mode::Auto,
            &m,
        ));
        assert_eq!(p.premier(), Some(Technique::RealityVision));
        assert_eq!(p.candidats[0].pourquoi, "a deja marche sur ce reseau");
    }

    #[test]
    fn une_reussite_memorisee_ne_ressuscite_pas_une_technique_ecartee() {
        // Le piege du souvenir: le reseau a change, l'UDP est desormais bloque,
        // et le protocole qui marchait hier ne peut plus rien.
        let mut m = MemoireReseau::vierge();
        m.noter_reussite(Technique::AmneziaWg, Date::new(2026, 8, 15));
        let env = Environnement {
            udp_passe: Mesure::Vu(false),
            ..Environnement::rien_sonde()
        };
        let p = planifier(&ctx(Pays::NonCensure, env, Mode::Auto, &m));
        assert_ne!(p.premier(), Some(Technique::AmneziaWg));
        assert!(
            p.ecartes
                .contains(&(Technique::AmneziaWg, Refus::UdpMesureBloque))
        );
    }

    #[test]
    fn un_echec_tout_frais_relegue_sans_eliminer() {
        let mut m = MemoireReseau::vierge();
        m.noter_echec(Technique::RealityVision, Date::new(2026, 8, 16));
        let p = planifier(&ctx(
            Pays::Chine,
            Environnement::rien_sonde(),
            Mode::Auto,
            &m,
        ));
        let noms: Vec<_> = p.candidats.iter().map(|c| c.technique).collect();
        assert!(noms.contains(&Technique::RealityVision));
        assert_ne!(p.premier(), Some(Technique::RealityVision));
        assert_eq!(
            noms.last(),
            Some(&Technique::RealityVision),
            "l'echec le plus recent doit etre le dernier essaye"
        );
    }

    #[test]
    fn une_precondition_confirmee_devance_une_precondition_inconnue() {
        // Deux techniques au meme rang de survie sous Pays::NonCensure: seule
        // la mesure les departage.
        let m = vierge();
        let env = Environnement {
            udp_passe: Mesure::Vu(true),
            ports_hauts_ouverts: Mesure::Vu(true),
            ..Environnement::rien_sonde()
        };
        let p = planifier(&ctx(Pays::NonCensure, env, Mode::Auto, &m));
        let pos = |t: Technique| p.candidats.iter().position(|c| c.technique == t).unwrap();
        assert!(
            pos(Technique::AmneziaWg) < pos(Technique::RealityVision),
            "la technique dont on a verifie le transport doit devancer celle dont on n'a rien verifie"
        );
        assert_eq!(
            p.candidats[pos(Technique::AmneziaWg)].pourquoi,
            "preconditions mesurees satisfaites"
        );
        assert_eq!(
            p.candidats[pos(Technique::RealityVision)].pourquoi,
            "non contredite par les mesures"
        );
    }

    #[test]
    fn tcp_443_non_sonde_ne_vaut_pas_tcp_443_verifie() {
        // Le defaut que ce champ existe pour empecher: sans lui, "TCP/443 n'a
        // pas ete contredit" comptait comme une confirmation, et les techniques
        // TCP passaient systematiquement devant, y compris en mode Rapide ou
        // l'intention est exactement inverse.
        let m = vierge();
        let sans = planifier(&ctx(
            Pays::NonCensure,
            Environnement::rien_sonde(),
            Mode::Auto,
            &m,
        ));
        let avec = planifier(&ctx(
            Pays::NonCensure,
            Environnement {
                tcp443_passe: Mesure::Vu(true),
                ..Environnement::rien_sonde()
            },
            Mode::Auto,
            &m,
        ));
        let pos =
            |p: &Plan, t: Technique| p.candidats.iter().position(|c| c.technique == t).unwrap();
        assert_eq!(
            sans.candidats[pos(&sans, Technique::RealityVision)].pourquoi,
            "non contredite par les mesures"
        );
        assert_eq!(
            avec.candidats[pos(&avec, Technique::RealityVision)].pourquoi,
            "preconditions mesurees satisfaites"
        );
        assert_eq!(avec.premier(), Some(Technique::RealityVision));
    }

    #[test]
    fn une_precondition_mesuree_l_emporte_sur_la_preference_du_mode() {
        // L'arbitrage de fond, et le seul endroit ou les deux criteres se
        // contredisent franchement. Le mode Rapide veut WireGuard, le moins
        // couteux; mais son transport n'a pas ete sonde, alors que celui de
        // REALITY l'a ete. Ce qu'on sait pouvoir marcher passe devant ce qui
        // serait plus agreable si ca marchait: une tentative ratee coute un
        // aller-retour ET une signature de plus sur le reseau.
        let m = vierge();
        let env = Environnement {
            tcp443_passe: Mesure::Vu(true),
            ..Environnement::rien_sonde()
        };
        let p = planifier(&ctx(Pays::NonCensure, env, Mode::Rapide, &m));
        assert_eq!(
            p.premier(),
            Some(Technique::RealityVision),
            "le mode a pris le pas sur une mesure"
        );
        // Et le controle qui donne son sens au precedent: des que le transport
        // de WireGuard est confirme lui aussi, les preconditions s'egalisent et
        // le mode retrouve la main.
        let env = Environnement {
            tcp443_passe: Mesure::Vu(true),
            udp_passe: Mesure::Vu(true),
            ports_hauts_ouverts: Mesure::Vu(true),
            ..Environnement::rien_sonde()
        };
        let p = planifier(&ctx(Pays::NonCensure, env, Mode::Rapide, &m));
        assert_eq!(p.premier(), Some(Technique::WireGuardNu));
    }

    /// Le dernier recours est la technique NON OBSERVEE, et c'est voulu.
    ///
    /// Cette recette exigeait auparavant un plan vide: Turkmenistan au 15
    /// juillet, REALITY et XHTTP morts et frais, UDP mesure bloque, il ne
    /// restait rien. L'arrivee de HTTPUpgrade change la reponse, et le
    /// changement est le bon.
    ///
    /// La regle d'elimination est "morte ET observation fraiche". HTTPUpgrade
    /// n'a AUCUNE observation au Turkmenistan - la cellule est declaree dans
    /// `survie::SANS_SOURCE` faute de source primaire - donc rien ne
    /// l'elimine. Le planificateur propose une option non testee au lieu de
    /// declarer forfait, ce qui est preferable: on ignore qu'elle echoue.
    ///
    /// **Consequence a connaitre**: tant qu'une technique reste non observee
    /// partout, `est_sans_issue()` est INATTEIGNABLE par `planifier`. Verifie
    /// ici sur la combinaison la plus eliminatrice qui existe - Discret ecarte
    /// les trois camouflages non-web, l'interception TLS ecarte REALITY, le
    /// pays frais ecarte XHTTP - et il reste encore un candidat.
    #[test]
    fn le_dernier_recours_est_la_technique_non_observee() {
        let m = vierge();
        let env = Environnement {
            udp_passe: Mesure::Vu(false),
            ..Environnement::rien_sonde()
        };
        let mut c = ctx(Pays::Turkmenistan, env, Mode::Auto, &m);
        c.aujourd_hui = Date::new(2026, 7, 15);
        let p = planifier(&c);
        assert_eq!(p.premier(), Some(Technique::WebsocketCdn));

        // La combinaison la plus eliminatrice possible, et elle ne vide pas.
        let env = Environnement {
            udp_passe: Mesure::Vu(false),
            mitm_tls: Mesure::Vu(true),
            ..Environnement::rien_sonde()
        };
        let mut c = ctx(Pays::Turkmenistan, env, Mode::Discret, &m);
        c.aujourd_hui = Date::new(2026, 7, 15);
        let p = planifier(&c);
        let noms: Vec<_> = p.candidats.iter().map(|c| c.technique).collect();
        assert_eq!(
            noms,
            vec![Technique::WebsocketCdn, Technique::HttpUpgradeFront],
            "seules les techniques non observees doivent rester"
        );
        assert!(!p.est_sans_issue());
    }

    /// La predicat de plan vide, garde a part.
    ///
    /// `planifier` ne peut plus l'atteindre, cf. la recette ci-dessus. Le
    /// laisser sans recette au motif qu'il est inatteignable serait un pari sur
    /// le tableau de survie, qui change en semaines: une seule observation
    /// "Morte" fraiche pour HTTPUpgrade le rendrait de nouveau joignable.
    #[test]
    fn un_plan_vide_se_declare_sans_issue() {
        let p = Plan {
            candidats: Vec::new(),
            ecartes: Technique::TOUTES
                .iter()
                .map(|t| (*t, Refus::ModeIncompatible))
                .collect(),
            portail_a_franchir: false,
            parallelisme_max: 2,
            jitter: (JITTER_MIN, JITTER_MAX),
        };
        assert!(p.est_sans_issue());
        assert_eq!(p.premier(), None);
        assert_eq!(p.ecartes.len(), Technique::TOUTES.len());
    }

    #[test]
    fn le_portail_captif_est_signale_sans_vider_le_plan() {
        let m = vierge();
        let env = Environnement {
            portail_captif: Mesure::Vu(true),
            ..Environnement::rien_sonde()
        };
        let p = planifier(&ctx(Pays::NonCensure, env, Mode::Auto, &m));
        assert!(p.portail_a_franchir);
        assert!(!p.est_sans_issue());
    }

    #[test]
    fn le_plan_borne_toujours_le_parallelisme_et_le_jitter() {
        let m = vierge();
        let p = planifier(&ctx(
            Pays::NonCensure,
            Environnement::rien_sonde(),
            Mode::Auto,
            &m,
        ));
        assert_eq!(p.parallelisme_max, 2);
        assert!(p.jitter.0 < p.jitter.1);
        assert!(
            p.jitter.0 > Duration::ZERO,
            "un jitter nul n'est pas un jitter"
        );
    }

    #[test]
    fn le_plan_est_stable_a_contexte_egal() {
        // Un ordre qui varierait d'une execution a l'autre rendrait tout
        // diagnostic de terrain impossible.
        let m = vierge();
        let c = ctx(Pays::Iran, Environnement::rien_sonde(), Mode::Auto, &m);
        assert_eq!(planifier(&c), planifier(&c));
    }

    #[test]
    fn aucun_candidat_ne_figure_deux_fois_ni_ne_figure_aussi_en_ecarte() {
        for pays in [
            Pays::NonCensure,
            Pays::Chine,
            Pays::Russie,
            Pays::Iran,
            Pays::Turkmenistan,
        ] {
            for mode in [Mode::Auto, Mode::Discret, Mode::Rapide] {
                let m = vierge();
                let p = planifier(&ctx(pays, Environnement::rien_sonde(), mode, &m));
                let mut vus: Vec<Technique> = p.candidats.iter().map(|c| c.technique).collect();
                let avant = vus.len();
                vus.sort_unstable();
                vus.dedup();
                assert_eq!(avant, vus.len(), "doublon dans les candidats");
                for (t, _) in &p.ecartes {
                    assert!(
                        !vus.contains(t),
                        "{} est a la fois retenu et ecarte",
                        t.nom()
                    );
                }
                assert_eq!(
                    p.candidats.len() + p.ecartes.len(),
                    Technique::TOUTES.len(),
                    "une technique s'est perdue en route"
                );
            }
        }
    }
}
