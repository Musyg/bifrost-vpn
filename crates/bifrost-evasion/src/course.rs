//! L'ordre des tentatives: quoi lancer, quand, et quand passer au suivant.
//!
//! [`crate::selection`] rend un ordre de preference, [`crate::demarche`] dit ce
//! que le PREMIER candidat implique. Il manquait la piece qui parcourt la liste:
//! celle qui lance, attend, constate, et passe au suivant.
//!
//! # Pourquoi une course de tentatives et pas une salve de sondes
//!
//! Le plan le dit deja, document 04 partie 3.2: "Ordre d'essai (du plus
//! furtif/leger au plus lourd), memorise par reseau", avec pour criteres de
//! passage au candidat suivant "echec de handshake < 3s, ou gel apres 16-20KB,
//! ou debit < seuil sur 10s". Ce sont des criteres de TENTATIVE, pas de sonde.
//! La tentative est la mesure.
//!
//! L'etat de l'art d'aout 2026 dit la meme chose, et par trois voix
//! independantes: Psiphon lance des connexions concurrentes sous differentes
//! obfuscations et garde la premiere qui tient; le Smart Dialer d'Outline
//! cherche une strategie qui debloque DNS et TLS en les essayant; le Connection
//! Assist de Tor ne sonde pas le reseau du tout. Le seul systeme documente qui
//! sonde avant de choisir, DPYProxy-DNS, met 13,8 s en moyenne en Chine pour
//! une reponse qu'une tentative reussie aurait donnee en meme temps que la
//! connexion.
//!
//! Il y a une raison de fond, et elle est plus forte que le cout: une sonde
//! mesure une propriete de transport ("l'UDP passe"), alors que la question est
//! "cette technique se connecte-t-elle". Un censeur peut laisser passer l'UDP
//! et couper la poignee de main hysteria2. La sonde repond a cote.
//!
//! # Ce que ce module ne fait pas
//!
//! Il ne lance rien. Comme le reste du crate, il DECRIT: l'appelant lance,
//! observe, et rapporte. Le tirage de la gigue lui-meme est laisse dehors, pour
//! que la course reste une fonction du temps qu'on lui donne et non de
//! l'horloge, donc testable a un rythme choisi.

use std::collections::VecDeque;
use std::time::Duration;

use crate::selection::Plan;
use crate::technique::Technique;

/// Budget d'une poignee de main. Document 04 partie 3.2: "echec de handshake
/// < 3s" comme critere de passage au candidat suivant.
pub const BUDGET_POIGNEE: Duration = Duration::from_secs(3);

/// Le flux gele apres 16-20 Ko: signature TSPU (document 04 partie 3.2).
///
/// La borne BASSE est retenue a dessein. Attendre 20 Ko pour conclure laisserait
/// passer les coupures qui tombent a 17, et le prix d'une conclusion trop tot
/// est une tentative de plus, pas une fuite.
///
/// # Le critere est CONFIRME, mais il n'est plus le seul, et il est vieux
///
/// Recherche approfondie du 20 aout 2026, sources lues et non resumees. Une
/// premiere version de ce commentaire datait tout cela de "mai 2026" et fondait
/// deux mecanismes distincts en un seul. Les dates reelles, relevees sur les
/// fils eux-memes:
///
/// - **net4people/bbs#490, ouvert le 27 juin 2025.** C'est LUI qui porte le
///   seuil d'octets, et il est precis: gel quand, TCP + HTTPS/TLS, IP serveur
///   hors de Russie ou de centre de donnees etranger, "plus de ~15-20 Ko recus
///   du serveur vers le client DANS UNE MEME CONNEXION TCP (et non dans une
///   meme requete HTTP)". Une mise a jour ajoute: gel "apres environ 25 paquets
///   dans un sens ou l'autre, soit en moyenne 16 Ko de charge utile".
/// - **net4people/bbs#546, ouvert le 14 novembre 2025.** Autre mecanisme:
///   comptage de connexions simultanees, sur le port 443 EXCLUSIVEMENT -
///   changer de port suffisait a y echapper.
/// - **XTLS/Xray-core#6293, ouvert le 8 juin 2026.** Le plus recent, et il
///   n'est PAS volumetrique: sous-reseau suspect + empreinte uTLS suspecte +
///   **plus de trois connexions TLS concurrentes en 20-50 ms sur le meme SNI**
///   dans une fenetre de 60 s. Des sous-reseaux et des AS entiers sont vises,
///   y compris russes (Selectel, Yandex.Cloud, Cloud.ru).
///
/// Ce que cela veut dire pour ce seuil. Il est CONFIRME - la bande 16-20 Ko est
/// exactement celle de #490 - et `crate::observation` compte `recus`, donc le
/// sens serveur vers client, qui est le bon. Mais #490 date de JUIN 2025: il ne
/// rafraichit rien, c'est la source que le plan avait deja.
///
/// # Ce que nous ne detectons PAS, et le piege qui va avec
///
/// La GRANULARITE d'abord: le censeur gele une connexion TCP a la fois, nous
/// lisons les compteurs agreges du TUN. Un tunnel dont chaque connexion gele a
/// 16 Ko continue d'accumuler des octets tant que l'application en ouvre de
/// nouvelles - cela se lira comme un DEBIT effondre, pas comme un gel. Les deux
/// criteres se couvrent, mais il faut savoir lequel a repondu.
///
/// Le mecanisme de #6293 ensuite, et c'est plus serieux: il ne se declenche sur
/// AUCUN volume. Il compte des connexions concurrentes. Rien ici ne le mesure.
/// Pire, il porte une sanction que notre bascule risque de declencher: le gel
/// dure 120 s, et **passe a 600 s si l'empreinte change apres coup**. Or
/// changer de candidat, c'est changer d'empreinte. Sous ce mecanisme-la, notre
/// reponse quintuple la punition.
///
/// Ce n'est pas corrige ici parce qu'aucune mesure a nous ne le distingue
/// encore d'un gel ordinaire, et qu'on ne code pas contre un mecanisme qu'on ne
/// sait pas reconnaitre. C'est nomme pour que la prochaine personne qui
/// instrumente la couche d'observation sache quoi chercher: un compteur de
/// connexions concurrentes par SNI, et un gel qui dure exactement 120 ou
/// 600 secondes.
pub const SEUIL_GEL: u64 = 16 * 1024;

/// Duree d'observation du debit. Document 04 partie 3.2: "debit < seuil sur
/// 10s". Un effondrement progressif est du throttling, un echec immediat est un
/// blocage franc, et les deux ne se corrigent pas de la meme facon.
pub const FENETRE_DEBIT: Duration = Duration::from_secs(10);

/// Pourquoi une tentative n'a pas abouti.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Echec {
    /// Aucune poignee de main dans le budget.
    Poignee,
    /// Le flux a gele apres avoir passe des octets. Signature TSPU.
    Gel { octets: u64 },
    /// Le debit s'est effondre sur la fenetre d'observation.
    Debit,
    /// La tentative n'a jamais quitte la machine: coeur absent, configuration
    /// illisible, compte dedie manquant.
    NonLancable(String),
}

impl Echec {
    /// Cet echec dit-il quelque chose du RESEAU.
    ///
    /// Non pour [`Echec::NonLancable`], et la distinction n'est pas theorique:
    /// noter au carnet qu'une technique a echoue ici alors que le binaire de
    /// son coeur manque l'ecarterait du prochain essai sur ce reseau, pour une
    /// raison qui n'a rien a voir avec lui. Pire, la panne etant locale, elle
    /// suivrait la machine sur tous les reseaux qu'elle visite, en salissant
    /// le carnet a chaque fois.
    ///
    /// C'est la meme regle que partout dans ce depot: une mesure qui n'a pas pu
    /// se faire n'est pas une mesure negative.
    pub fn accuse_le_reseau(&self) -> bool {
        !matches!(self, Echec::NonLancable(_))
    }

    pub fn motif(&self) -> String {
        match self {
            Echec::Poignee => format!("aucune poignee de main en {} s", BUDGET_POIGNEE.as_secs()),
            Echec::Gel { octets } => {
                format!(
                    "flux gele apres {octets} octets, signature d'une coupure en cours de session"
                )
            }
            Echec::Debit => format!(
                "debit effondre sur {} s: throttling plutot que blocage franc",
                FENETRE_DEBIT.as_secs()
            ),
            Echec::NonLancable(raison) => {
                format!(
                    "n'a pas pu etre lancee ({raison}): panne locale, le reseau n'y est pour rien"
                )
            }
        }
    }
}

/// Ce que l'appelant doit faire maintenant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pas {
    /// Lancer cette technique.
    Lancer(Technique),
    /// Ne rien lancer avant ce delai. Soit une tentative est en vol et il faut
    /// la laisser conclure, soit c'est la gigue qui separe deux tentatives.
    Patienter(Duration),
    /// Une technique a etabli. La course est finie, meme s'il restait des
    /// candidats: le plus furtif qui marche est celui qu'on garde.
    Etabli(Technique),
    /// Tous les candidats ont echoue. Le kill switch reste arme et la connexion
    /// echoue: echouer garde est le bon echec.
    Epuisee,
}

/// Le parcours de la liste de candidats.
#[derive(Debug, Clone)]
pub struct Course {
    restants: VecDeque<Technique>,
    en_vol: Vec<Technique>,
    parallelisme_max: usize,
    etabli: Option<Technique>,
    echoues: Vec<(Technique, Echec)>,
    /// Combien ont deja ete lancees. La premiere ne paie pas de gigue: espacer
    /// une tentative qui n'a rien avant elle n'espace rien, et retarderait
    /// chaque connexion sans rien cacher.
    lances: usize,
    /// La gigue due avant la prochaine tentative a-t-elle ete rendue.
    gigue_payee: bool,
}

impl Course {
    /// Prepare la course a partir du plan.
    ///
    /// REFUSE un plan qui demande de franchir un portail: derriere un portail
    /// rien ne passera, et enchainer les protocoles n'emettrait qu'une rafale,
    /// laquelle est elle-meme une signature. Le portail se franchit d'abord,
    /// et le plan se recalcule apres, parce qu'il aura change.
    pub fn nouvelle(plan: &Plan) -> Result<Self, String> {
        if plan.portail_a_franchir {
            return Err(
                "un portail captif est a franchir avant toute tentative: une course lancee derriere lui n'emettrait qu'une rafale, et une rafale est elle-meme une signature".to_owned(),
            );
        }
        Ok(Self {
            restants: plan.candidats.iter().map(|c| c.technique).collect(),
            en_vol: Vec::new(),
            // Un parallelisme nul ne lancerait jamais rien et la course
            // attendrait pour toujours. Le plancher n'est pas une politesse.
            parallelisme_max: plan.parallelisme_max.max(1),
            etabli: None,
            echoues: Vec::new(),
            lances: 0,
            gigue_payee: false,
        })
    }

    /// La meme course, restreinte aux techniques dont l'appelant DISPOSE.
    ///
    /// Meme asymetrie que [`crate::demarche_parmi`], et pour la meme raison: le
    /// plan CLASSE, l'appelant fournit. Courir sur les candidats du plan tels
    /// quels ferait tenter des techniques qu'aucun profil ne decrit - il n'y
    /// aurait rien a mettre derriere le selecteur - et la course attendrait un
    /// etablissement qui ne peut pas venir.
    ///
    /// L'ordre est celui du PLAN, filtre. C'est ce qui fait que la tete de
    /// cette course est exactement la technique que `demarche_parmi` retient
    /// sur le meme plan: les deux prennent le premier candidat du plan present
    /// chez l'appelant. Un tri different ici ouvrirait un second endroit ou la
    /// preference se decide, et les deux divergeraient un jour.
    ///
    /// Rend une erreur plutot qu'une course vide: une course sans candidat
    /// rendrait `Epuisee` au premier pas, ce qui se lirait comme "tout a ete
    /// tente" alors que rien ne l'a ete.
    pub fn parmi(plan: &Plan, techniques: &[Technique]) -> Result<Self, String> {
        let mut course = Self::nouvelle(plan)?;
        course.restants.retain(|t| techniques.contains(t));
        if course.restants.is_empty() {
            return Err(
                "aucune des techniques proposees n'est un candidat de ce plan: il n'y a rien a parcourir".to_owned(),
            );
        }
        Ok(course)
    }

    /// Ce qu'il faut faire maintenant.
    ///
    /// `gigue` est tiree par l'appelant, entre [`crate::selection::JITTER_MIN`]
    /// et [`crate::selection::JITTER_MAX`]. Elle est prise en argument et non
    /// tiree ici pour que la course reste pure: du hasard dedans la rendrait
    /// intestable, et c'est exactement ce que le meme choix a deja evite dans
    /// `Plan`.
    ///
    /// L'appelant DOIT honorer ce que ce pas dit. Un `Lancer` qui n'est pas
    /// suivi d'un lancement laisse une technique comptee en vol qui ne
    /// conclura jamais, et la course attendra.
    pub fn prochain_pas(&mut self, gigue: Duration) -> Pas {
        if let Some(t) = self.etabli {
            return Pas::Etabli(t);
        }
        if self.restants.is_empty() && self.en_vol.is_empty() {
            return Pas::Epuisee;
        }
        // Le parallelisme est plein, ou il ne reste rien a lancer: dans les deux
        // cas on laisse conclure ce qui est en vol. Le budget de poignee est la
        // bonne attente, puisque c'est le delai au bout duquel une tentative qui
        // n'a pas abouti est declaree perdue.
        if self.en_vol.len() >= self.parallelisme_max || self.restants.is_empty() {
            return Pas::Patienter(BUDGET_POIGNEE);
        }
        // Toute tentative sauf la premiere est precedee d'une attente. Le plan
        // le demande deux fois: "espacer les tentatives (jitter)" et "ne pas
        // emettre de motif de bascule regulier".
        if self.lances > 0 && !self.gigue_payee {
            self.gigue_payee = true;
            return Pas::Patienter(gigue);
        }
        let t = self.restants.pop_front().expect("restants n'est pas vide");
        self.en_vol.push(t);
        self.lances += 1;
        self.gigue_payee = false;
        Pas::Lancer(t)
    }

    /// Cette technique a etabli. La course s'arrete.
    pub fn noter_reussite(&mut self, technique: Technique) {
        self.en_vol.retain(|t| *t != technique);
        self.etabli = Some(technique);
    }

    /// Cette technique a echoue. La course passe a la suivante.
    pub fn noter_echec(&mut self, technique: Technique, echec: Echec) {
        self.en_vol.retain(|t| *t != technique);
        self.echoues.push((technique, echec));
    }

    pub fn etabli(&self) -> Option<Technique> {
        self.etabli
    }

    pub fn echoues(&self) -> &[(Technique, Echec)] {
        &self.echoues
    }

    /// Ce que la course a appris du RESEAU, a retenir au carnet.
    ///
    /// Les echecs qui n'accusent pas le reseau sont ecartes: voir
    /// [`Echec::accuse_le_reseau`]. Le booleen dit si c'est une reussite.
    pub fn a_retenir(&self) -> Vec<(Technique, bool)> {
        let mut retenu: Vec<(Technique, bool)> = self
            .echoues
            .iter()
            .filter(|(_, e)| e.accuse_le_reseau())
            .map(|(t, _)| (*t, false))
            .collect();
        if let Some(t) = self.etabli {
            retenu.push((t, true));
        }
        retenu
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::selection::{Candidat, JITTER_MIN, PARALLELISME_MAX};

    const GIGUE: Duration = JITTER_MIN;

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
            jitter: (JITTER_MIN, crate::selection::JITTER_MAX),
        }
    }

    fn course_de(techniques: &[Technique]) -> Course {
        Course::nouvelle(&plan_de(techniques, false)).expect("plan sans portail")
    }

    /// La course restreinte garde l'ORDRE DU PLAN, pas celui de l'appelant.
    ///
    /// Le plan classe par furtivite et par survie mesuree; la liste de
    /// l'appelant est l'ordre d'un fichier de profil, qui ne veut rien dire.
    /// Suivre le second ferait basculer vers un candidat plus voyant alors
    /// qu'un plus discret attendait.
    #[test]
    fn une_course_restreinte_garde_l_ordre_du_plan() {
        let plan = plan_de(
            &[
                Technique::RealityVision,
                Technique::Hysteria2,
                Technique::AmneziaWg,
            ],
            false,
        );
        // A REBOURS du plan, et avec une technique que le plan ne propose pas.
        let mut c = Course::parmi(&plan, &[Technique::AmneziaWg, Technique::RealityVision])
            .expect("deux techniques du plan sont proposees");
        assert_eq!(c.prochain_pas(GIGUE), Pas::Lancer(Technique::RealityVision));
        assert_eq!(c.prochain_pas(GIGUE), Pas::Patienter(GIGUE));
        assert_eq!(c.prochain_pas(GIGUE), Pas::Lancer(Technique::AmneziaWg));
    }

    /// Et la tete de cette course est exactement ce que `demarche_parmi`
    /// retient sur le meme plan.
    ///
    /// C'est la propriete qui evite un second endroit ou la preference se
    /// deciderait: le selecteur sert la tete que la demarche designe, et la
    /// course continue a partir de la meme.
    #[test]
    fn la_tete_de_la_course_est_ce_que_la_demarche_retient() {
        let plan = plan_de(&[Technique::RealityVision, Technique::Hysteria2], false);
        let proposees = [Technique::Hysteria2, Technique::RealityVision];
        let mut c = Course::parmi(&plan, &proposees).expect("plan et proposees se croisent");
        let tete = match c.prochain_pas(GIGUE) {
            Pas::Lancer(t) => t,
            autre => panic!("une course neuve lance: {autre:?}"),
        };
        assert_eq!(
            Some(tete),
            crate::demarche_parmi(&plan, &proposees).technique()
        );
    }

    /// Aucune technique commune: une erreur, pas une course vide.
    ///
    /// Une course vide rendrait `Epuisee` au premier pas, ce qui se lirait
    /// comme "tout a ete tente" alors que rien ne l'a ete.
    #[test]
    fn une_course_sans_candidat_commun_est_refusee() {
        let plan = plan_de(&[Technique::RealityVision], false);
        assert!(Course::parmi(&plan, &[Technique::Hysteria2]).is_err());
    }

    /// Un portail captif refuse la course restreinte comme la course entiere.
    #[test]
    fn une_course_restreinte_refuse_aussi_derriere_un_portail() {
        let plan = plan_de(&[Technique::RealityVision], true);
        assert!(Course::parmi(&plan, &[Technique::RealityVision]).is_err());
    }

    /// La premiere tentative part tout de suite: espacer une tentative qui n'a
    /// rien avant elle n'espace rien et retarderait chaque connexion.
    #[test]
    fn la_premiere_tentative_ne_paie_pas_de_gigue() {
        let mut c = course_de(&[Technique::RealityVision]);
        assert_eq!(c.prochain_pas(GIGUE), Pas::Lancer(Technique::RealityVision));
    }

    /// "Espacer les tentatives (jitter)", document 04 partie 3.2. Une deuxieme
    /// tentative qui suivrait la premiere sans delai produirait le motif
    /// regulier que le meme paragraphe interdit.
    #[test]
    fn la_deuxieme_tentative_est_precedee_d_une_attente() {
        let mut c = course_de(&[Technique::RealityVision, Technique::Hysteria2]);
        assert_eq!(c.prochain_pas(GIGUE), Pas::Lancer(Technique::RealityVision));
        c.noter_echec(Technique::RealityVision, Echec::Poignee);
        assert_eq!(c.prochain_pas(GIGUE), Pas::Patienter(GIGUE));
        assert_eq!(c.prochain_pas(GIGUE), Pas::Lancer(Technique::Hysteria2));
    }

    /// "Jamais 6 d'affilee - un client qui tente 6 protocoles en rafale est
    /// lui-meme une signature detectable."
    #[test]
    fn jamais_plus_de_candidats_en_vol_que_le_plan_ne_permet() {
        let mut c = course_de(&[
            Technique::RealityVision,
            Technique::Hysteria2,
            Technique::AmneziaWg,
            Technique::WireGuardNu,
        ]);
        let mut en_vol = 0;
        // Personne ne conclut: la course ne doit pas pouvoir depasser la borne.
        for _ in 0..20 {
            match c.prochain_pas(GIGUE) {
                Pas::Lancer(_) => en_vol += 1,
                Pas::Patienter(_) => {}
                autre => panic!("ni etabli ni epuisee ici: {autre:?}"),
            }
            assert!(
                en_vol <= PARALLELISME_MAX,
                "{en_vol} tentatives en vol pour un maximum de {PARALLELISME_MAX}"
            );
        }
        assert_eq!(en_vol, PARALLELISME_MAX);
    }

    /// Le plus furtif qui marche est celui qu'on garde: une reussite arrete la
    /// course meme s'il restait des candidats a essayer.
    #[test]
    fn une_reussite_arrete_la_course() {
        let mut c = course_de(&[Technique::RealityVision, Technique::Hysteria2]);
        assert_eq!(c.prochain_pas(GIGUE), Pas::Lancer(Technique::RealityVision));
        c.noter_reussite(Technique::RealityVision);
        assert_eq!(c.prochain_pas(GIGUE), Pas::Etabli(Technique::RealityVision));
        assert_eq!(c.etabli(), Some(Technique::RealityVision));
    }

    #[test]
    fn tous_les_echecs_epuisent_la_course() {
        let mut c = course_de(&[Technique::RealityVision, Technique::Hysteria2]);
        for t in [Technique::RealityVision, Technique::Hysteria2] {
            // La gigue precede toutes les tentatives sauf la premiere.
            loop {
                match c.prochain_pas(GIGUE) {
                    Pas::Lancer(lance) => {
                        assert_eq!(lance, t);
                        break;
                    }
                    Pas::Patienter(_) => {}
                    autre => panic!("il restait des candidats: {autre:?}"),
                }
            }
            c.noter_echec(t, Echec::Poignee);
        }
        assert_eq!(c.prochain_pas(GIGUE), Pas::Epuisee);
        assert_eq!(c.etabli(), None);
    }

    /// Echouer garde est le bon echec: un plan sans candidat ne doit surtout
    /// pas se lire comme une autorisation de sortir en clair.
    #[test]
    fn un_plan_sans_candidat_est_epuise_d_emblee() {
        let mut c = course_de(&[]);
        assert_eq!(c.prochain_pas(GIGUE), Pas::Epuisee);
    }

    /// Derriere un portail rien ne passera. Lancer la course la-dedans
    /// n'emettrait qu'une rafale, et le plan calcule avant le portail n'est de
    /// toute facon pas celui qu'on aura apres.
    #[test]
    fn un_plan_a_portail_refuse_la_course() {
        let e = Course::nouvelle(&plan_de(&[Technique::RealityVision], true))
            .expect_err("un plan a portail doit refuser la course");
        assert!(e.contains("portail"), "{e}");
        assert!(e.contains("rafale"), "{e}");
    }

    /// Une technique qui n'a pas pu etre lancee n'a rien mesure du reseau. La
    /// noter au carnet l'ecarterait du prochain essai ICI pour une panne qui,
    /// etant locale, suivrait la machine partout.
    #[test]
    fn un_echec_local_n_accuse_pas_le_reseau() {
        assert!(!Echec::NonLancable("binaire xray absent".to_owned()).accuse_le_reseau());
        assert!(Echec::Poignee.accuse_le_reseau());
        assert!(Echec::Gel { octets: 17_000 }.accuse_le_reseau());
        assert!(Echec::Debit.accuse_le_reseau());
    }

    /// Le carnet ne retient que ce qui parle du reseau.
    #[test]
    fn le_carnet_ne_retient_pas_les_pannes_locales() {
        let mut c = course_de(&[
            Technique::RealityVision,
            Technique::Hysteria2,
            Technique::WireGuardNu,
        ]);
        c.noter_echec(
            Technique::RealityVision,
            Echec::NonLancable("binaire xray absent".to_owned()),
        );
        c.noter_echec(Technique::Hysteria2, Echec::Gel { octets: 17_000 });
        c.noter_reussite(Technique::WireGuardNu);

        let retenu = c.a_retenir();
        assert_eq!(
            retenu,
            vec![
                (Technique::Hysteria2, false),
                (Technique::WireGuardNu, true)
            ],
            "la panne locale ne doit pas figurer au carnet"
        );
    }

    /// Une course qui relancerait une technique deja essayee emettrait deux
    /// fois la meme poignee, ce qui est precisement le motif regulier que la
    /// gigue existe pour casser.
    #[test]
    fn une_technique_n_est_jamais_lancee_deux_fois() {
        let mut c = course_de(&[Technique::RealityVision, Technique::Hysteria2]);
        let mut lancees = Vec::new();
        for _ in 0..30 {
            match c.prochain_pas(GIGUE) {
                Pas::Lancer(t) => {
                    assert!(!lancees.contains(&t), "{t:?} lancee deux fois");
                    lancees.push(t);
                    c.noter_echec(t, Echec::Poignee);
                }
                Pas::Patienter(_) => {}
                Pas::Epuisee => break,
                autre => panic!("inattendu: {autre:?}"),
            }
        }
        assert_eq!(lancees.len(), 2);
    }

    /// Un parallelisme nul ne lancerait jamais rien et la course attendrait
    /// pour toujours. Le plancher est ce qui l'empeche.
    #[test]
    fn un_parallelisme_nul_ne_bloque_pas_la_course() {
        let mut plan = plan_de(&[Technique::RealityVision], false);
        plan.parallelisme_max = 0;
        let mut c = Course::nouvelle(&plan).expect("plan sans portail");
        assert_eq!(
            c.prochain_pas(GIGUE),
            Pas::Lancer(Technique::RealityVision),
            "une course qui n'attendrait que Patienter ne connecterait jamais"
        );
    }

    /// Les motifs partent dans le journal et dans le carnet: ils doivent dire
    /// ce qui s'est passe, pas seulement qu'il s'est passe quelque chose.
    #[test]
    fn chaque_echec_dit_ce_qui_s_est_passe() {
        assert!(Echec::Poignee.motif().contains("poignee"));
        assert!(Echec::Gel { octets: 17_000 }.motif().contains("17000"));
        assert!(Echec::Debit.motif().contains("throttling"));
        let local = Echec::NonLancable("xray absent".to_owned()).motif();
        assert!(local.contains("xray absent"), "{local}");
        assert!(
            local.contains("le reseau n'y est pour rien"),
            "un echec local doit se lire comme tel: {local}"
        );
    }
}
