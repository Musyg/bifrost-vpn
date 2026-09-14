//! Ce qui a marche, et rate, sur un reseau donne.
//!
//! Le document 04 partie 3.2 en fait une exigence de discretion autant que de
//! confort: re-sonder a chaque reconnexion emet un motif regulier, et un client
//! qui essaie six protocoles en rafale est lui-meme une signature. Se souvenir
//! evite les deux.

use serde::{Deserialize, Serialize};

use crate::date::Date;
use crate::technique::Technique;

/// Au-dela de ce delai, une reussite memorisee ne dispense plus de sonder.
///
/// Un reseau garde rarement les memes regles un mois entier, et se fier a un
/// souvenir perime coute une tentative vouee a l'echec, donc une signature de
/// plus. Trente jours est un compromis: assez long pour couvrir un usage
/// quotidien au bureau ou a la maison, assez court pour ne pas traverser un
/// changement de politique.
pub const REUSSITE_VALIDE_JOURS: i64 = 30;

/// En dessous de ce delai, un echec ecarte la technique du prochain essai.
///
/// Assez court pour ne pas condamner une technique sur un incident passager,
/// assez long pour ne pas la reproposer dans la foulee.
pub const ECHEC_RECENT_JOURS: i64 = 1;

/// Identifie un reseau, au sens du document: le BSSID Wi-Fi ou l'identifiant
/// d'interface, la passerelle par defaut, et l'ASN de sortie observe.
///
/// Les trois parties sont jointes par un separateur qui ne peut pas apparaitre
/// dans un BSSID, une adresse ni un numero d'ASN. Sans cela, deux reseaux
/// differents pourraient produire la meme cle par simple concatenation et
/// heriter l'un des souvenirs de l'autre.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CleReseau(String);

/// Separateur de la cle. L'espace est absent des BSSID, des adresses IP et des
/// numeros d'ASN.
const SEPARATEUR: char = ' ';

impl CleReseau {
    /// `lien` est le BSSID sur Wi-Fi, l'identifiant d'interface sinon.
    /// `asn` est absent tant que la sortie n'a pas ete observee.
    pub fn nouvelle(lien: &str, passerelle: &str, asn: Option<u32>) -> Self {
        let asn = match asn {
            Some(n) => n.to_string(),
            None => "?".to_string(),
        };
        Self(format!(
            "{}{SEPARATEUR}{}{SEPARATEUR}{}",
            assainir(lien),
            assainir(passerelle),
            asn
        ))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Remplace le separateur s'il apparait dans une partie, pour qu'une valeur
/// inattendue ne puisse pas fabriquer une collision.
fn assainir(partie: &str) -> String {
    let nettoye: String = partie
        .chars()
        .map(|c| if c == SEPARATEUR { '_' } else { c })
        .collect();
    if nettoye.is_empty() {
        "?".to_string()
    } else {
        nettoye
    }
}

/// Souvenirs attaches a un reseau.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoireReseau {
    /// La derniere technique qui a etabli un tunnel ici, et quand.
    pub a_marche: Option<(Technique, Date)>,
    /// Les echecs recents, les plus recents en premier n'etant pas garanti:
    /// la lecture se fait par date, pas par position.
    pub a_echoue: Vec<(Technique, Date)>,
}

impl MemoireReseau {
    pub fn vierge() -> Self {
        Self::default()
    }

    /// La reussite memorisee, si elle est encore exploitable.
    ///
    /// Une date future rend `None`: un souvenir date de demain est une donnee
    /// fausse, et lui obeir ferait sauter le sondage sur la foi d'une erreur.
    pub fn reussite_utilisable(&self, aujourd_hui: Date) -> Option<Technique> {
        let (technique, quand) = self.a_marche?;
        let age = quand.jours_jusqu_a(aujourd_hui);
        (0..=REUSSITE_VALIDE_JOURS)
            .contains(&age)
            .then_some(technique)
    }

    /// Cette technique a-t-elle echoue ici assez recemment pour etre ecartee.
    pub fn echec_recent(&self, technique: Technique, aujourd_hui: Date) -> bool {
        self.a_echoue.iter().any(|(t, quand)| {
            *t == technique && (0..=ECHEC_RECENT_JOURS).contains(&quand.jours_jusqu_a(aujourd_hui))
        })
    }

    /// Enregistre une reussite. Elle efface l'echec memorise de la meme
    /// technique: garder les deux ferait qu'une technique qui vient de marcher
    /// resterait ecartee du prochain essai.
    pub fn noter_reussite(&mut self, technique: Technique, quand: Date) {
        self.a_echoue.retain(|(t, _)| *t != technique);
        self.a_marche = Some((technique, quand));
    }

    /// Enregistre un echec. Il efface la reussite memorisee si elle portait sur
    /// la meme technique, pour la meme raison, en sens inverse.
    pub fn noter_echec(&mut self, technique: Technique, quand: Date) {
        if let Some((t, _)) = self.a_marche
            && t == technique
        {
            self.a_marche = None;
        }
        self.a_echoue.retain(|(t, _)| *t != technique);
        self.a_echoue.push((technique, quand));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const AOUT: Date = Date::new(2026, 8, 16);

    #[test]
    fn deux_reseaux_differents_ne_partagent_pas_de_cle() {
        let a = CleReseau::nouvelle("aa:bb", "192.168.1.1", Some(13335));
        let b = CleReseau::nouvelle("aa:bb", "192.168.1.2", Some(13335));
        assert_ne!(a, b);
    }

    #[test]
    fn le_separateur_ne_peut_pas_fabriquer_une_collision() {
        // Sans assainissement, ces deux appels produiraient la meme chaine.
        let a = CleReseau::nouvelle("aa bb", "192.168.1.1", None);
        let b = CleReseau::nouvelle("aa", "bb 192.168.1.1", None);
        assert_ne!(a, b, "collision par injection du separateur");
    }

    #[test]
    fn une_partie_vide_reste_distincte() {
        let a = CleReseau::nouvelle("", "192.168.1.1", None);
        let b = CleReseau::nouvelle("eth0", "192.168.1.1", None);
        assert_ne!(a, b);
        assert!(a.as_str().starts_with('?'));
    }

    #[test]
    fn un_asn_absent_ne_se_confond_pas_avec_l_asn_zero() {
        let a = CleReseau::nouvelle("eth0", "10.0.0.1", None);
        let b = CleReseau::nouvelle("eth0", "10.0.0.1", Some(0));
        assert_ne!(a, b);
    }

    #[test]
    fn une_reussite_fraiche_est_utilisable() {
        let mut m = MemoireReseau::vierge();
        m.noter_reussite(Technique::RealityVision, Date::new(2026, 8, 10));
        assert_eq!(m.reussite_utilisable(AOUT), Some(Technique::RealityVision));
    }

    #[test]
    fn une_reussite_perimee_ne_l_est_plus() {
        let mut m = MemoireReseau::vierge();
        m.noter_reussite(Technique::RealityVision, Date::new(2026, 6, 1));
        assert_eq!(m.reussite_utilisable(AOUT), None);
    }

    #[test]
    fn une_reussite_datee_du_futur_est_ignoree() {
        let mut m = MemoireReseau::vierge();
        m.noter_reussite(Technique::RealityVision, Date::new(2027, 1, 1));
        assert_eq!(m.reussite_utilisable(AOUT), None);
    }

    #[test]
    fn un_echec_de_la_veille_ecarte_la_technique() {
        let mut m = MemoireReseau::vierge();
        m.noter_echec(Technique::Hysteria2, Date::new(2026, 8, 15));
        assert!(m.echec_recent(Technique::Hysteria2, AOUT));
        assert!(!m.echec_recent(Technique::RealityVision, AOUT));
    }

    #[test]
    fn un_echec_ancien_ne_l_ecarte_plus() {
        let mut m = MemoireReseau::vierge();
        m.noter_echec(Technique::Hysteria2, Date::new(2026, 8, 1));
        assert!(!m.echec_recent(Technique::Hysteria2, AOUT));
    }

    #[test]
    fn une_reussite_efface_l_echec_de_la_meme_technique() {
        let mut m = MemoireReseau::vierge();
        m.noter_echec(Technique::Hysteria2, Date::new(2026, 8, 15));
        m.noter_reussite(Technique::Hysteria2, Date::new(2026, 8, 16));
        assert!(
            !m.echec_recent(Technique::Hysteria2, AOUT),
            "la technique qui vient de marcher reste ecartee"
        );
        assert_eq!(m.reussite_utilisable(AOUT), Some(Technique::Hysteria2));
    }

    #[test]
    fn un_echec_efface_la_reussite_de_la_meme_technique() {
        let mut m = MemoireReseau::vierge();
        m.noter_reussite(Technique::Hysteria2, Date::new(2026, 8, 15));
        m.noter_echec(Technique::Hysteria2, Date::new(2026, 8, 16));
        assert_eq!(
            m.reussite_utilisable(AOUT),
            None,
            "on se souvient d'une reussite que le reseau vient de dementir"
        );
    }

    #[test]
    fn un_echec_repete_ne_s_accumule_pas() {
        let mut m = MemoireReseau::vierge();
        m.noter_echec(Technique::Hysteria2, Date::new(2026, 8, 14));
        m.noter_echec(Technique::Hysteria2, Date::new(2026, 8, 16));
        assert_eq!(m.a_echoue.len(), 1);
        assert!(m.echec_recent(Technique::Hysteria2, AOUT));
    }

    #[test]
    fn un_echec_n_efface_pas_la_reussite_d_une_autre_technique() {
        let mut m = MemoireReseau::vierge();
        m.noter_reussite(Technique::RealityVision, Date::new(2026, 8, 15));
        m.noter_echec(Technique::Hysteria2, Date::new(2026, 8, 16));
        assert_eq!(m.reussite_utilisable(AOUT), Some(Technique::RealityVision));
    }
}
