//! Ce que les sondes ont observe du reseau courant.
//!
//! Le type central est [`Mesure`], et il n'est pas un `Option` deguise par
//! coquetterie. Le produit applique deja la regle "un test qui ne peut pas
//! s'executer rend SKIPPED, jamais PASSED par defaut"; la selection du
//! protocole a besoin de la meme rigueur, pour la meme raison. Une sonde UDP
//! qui n'a pas tourne ne dit pas que l'UDP passe. Un `bool` a `false` par
//! defaut confondrait les deux, et le seul symptome serait un client qui
//! choisit un protocole condamne sur ce reseau, sans jamais dire pourquoi.

use serde::{Deserialize, Serialize};

/// Une observation, ou l'aveu qu'il n'y en a pas.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Mesure<T> {
    /// La sonde a tourne et a conclu.
    Vu(T),
    /// La sonde n'a pas tourne, a expire, ou son resultat n'est pas
    /// interpretable. Aucune conclusion n'en sera tiree.
    NonMesure,
}

impl<T> Mesure<T> {
    pub fn est_mesure(&self) -> bool {
        matches!(self, Mesure::Vu(_))
    }
}

impl Mesure<bool> {
    /// Vrai seulement si la sonde a tourne ET a conclu positivement.
    ///
    /// Le nom dit l'asymetrie: il n'existe pas de `est_faux()` symetrique,
    /// parce qu'appeler la negation de celui-ci sur une valeur `NonMesure`
    /// serait exactement l'erreur qu'on cherche a rendre impossible.
    pub fn vu_vrai(self) -> bool {
        matches!(self, Mesure::Vu(true))
    }

    /// Vrai seulement si la sonde a tourne ET a conclu negativement.
    pub fn vu_faux(self) -> bool {
        matches!(self, Mesure::Vu(false))
    }
}

/// Etat du reseau tel que les sondes du document 04 partie 3.1 le rendent.
///
/// Tous les champs partent a `NonMesure`: un environnement construit sans
/// sonder n'autorise et n'interdit rien.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Environnement {
    /// Une connexion TCP sortante sur 443 aboutit-elle.
    ///
    /// Sonde la plus banale, et pourtant indispensable comme champ a part
    /// entiere: sans elle, "TCP/443 n'a pas ete contredit" et "TCP/443 a ete
    /// verifie" seraient indistinguables, et le classement mettrait devant les
    /// techniques sur lesquelles on ne sait rien.
    pub tcp443_passe: Mesure<bool>,
    /// L'UDP sortant passe-t-il, quel que soit le port.
    pub udp_passe: Mesure<bool>,
    /// QUIC specifiquement passe-t-il. Distinct du precedent: la Chine
    /// dechiffre l'Initial QUIC et bloque cible, sans couper l'UDP.
    pub quic_passe: Mesure<bool>,
    /// Des ports autres que 80 et 443 sont-ils joignables.
    pub ports_hauts_ouverts: Mesure<bool>,
    /// La chaine de certificats vue differe-t-elle du pin, donc TLS intercepte.
    pub mitm_tls: Mesure<bool>,
    /// Un portail captif repond a la place du reseau.
    pub portail_captif: Mesure<bool>,
    /// Taux de perte observe, en pourcentage entier. Decide du mode Rapide.
    pub perte_pourcent: Mesure<u8>,
}

impl Default for Environnement {
    fn default() -> Self {
        Self::rien_sonde()
    }
}

impl Environnement {
    /// Aucune sonde n'a tourne. C'est l'etat au demarrage, et c'est aussi
    /// l'etat de repli si le budget de sondage est epuise.
    pub const fn rien_sonde() -> Self {
        Self {
            tcp443_passe: Mesure::NonMesure,
            udp_passe: Mesure::NonMesure,
            quic_passe: Mesure::NonMesure,
            ports_hauts_ouverts: Mesure::NonMesure,
            mitm_tls: Mesure::NonMesure,
            portail_captif: Mesure::NonMesure,
            perte_pourcent: Mesure::NonMesure,
        }
    }

    /// Combien de champs cet environnement compte.
    ///
    /// Publie pour que l'affichage n'ait pas a le recopier: il annoncait "sur
    /// 6" alors que le compte en parcourait deja sept, et rien ne l'a signale.
    pub const SONDES: usize = 7;

    /// Combien de sondes ont conclu. Sert a decider si l'on a assez pour
    /// choisir, ou s'il faut sonder davantage avant de s'engager.
    pub fn sondes_abouties(&self) -> usize {
        [
            self.tcp443_passe.est_mesure(),
            self.udp_passe.est_mesure(),
            self.quic_passe.est_mesure(),
            self.ports_hauts_ouverts.est_mesure(),
            self.mitm_tls.est_mesure(),
            self.portail_captif.est_mesure(),
            self.perte_pourcent.est_mesure(),
        ]
        .iter()
        .filter(|b| **b)
        .count()
    }

    /// Le compte annonce et le compte reel ne peuvent pas diverger.
    #[cfg(test)]
    fn tous_mesures() -> Self {
        Self {
            tcp443_passe: Mesure::Vu(true),
            udp_passe: Mesure::Vu(true),
            quic_passe: Mesure::Vu(true),
            ports_hauts_ouverts: Mesure::Vu(true),
            mitm_tls: Mesure::Vu(false),
            portail_captif: Mesure::Vu(false),
            perte_pourcent: Mesure::Vu(0),
        }
    }

    /// Un portail captif doit etre franchi avant toute tentative: rien ne
    /// passera tant qu'il est la, et enchainer les protocoles ne ferait
    /// qu'emettre une rafale de tentatives, ce qui est en soi une signature.
    pub fn portail_a_franchir(&self) -> bool {
        self.portail_captif.vu_vrai()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn un_environnement_vierge_n_a_rien_mesure() {
        let e = Environnement::rien_sonde();
        assert_eq!(e.sondes_abouties(), 0);
        assert_eq!(e, Environnement::default());
    }

    /// Ajouter un champ sans toucher a `SONDES` ferait mentir tous les
    /// rapports, en silence.
    #[test]
    fn le_nombre_annonce_de_sondes_est_celui_qui_est_compte() {
        assert_eq!(
            Environnement::tous_mesures().sondes_abouties(),
            Environnement::SONDES
        );
    }

    #[test]
    fn non_mesure_ne_vaut_ni_vrai_ni_faux() {
        // Le coeur du type. Si cette assertion tombait, `NonMesure` se
        // comporterait comme un `false` et la selection prendrait des
        // decisions sur une sonde qui n'a pas tourne.
        let m: Mesure<bool> = Mesure::NonMesure;
        assert!(!m.vu_vrai());
        assert!(!m.vu_faux());
    }

    #[test]
    fn une_mesure_conclut_dans_un_seul_sens() {
        assert!(Mesure::Vu(true).vu_vrai());
        assert!(!Mesure::Vu(true).vu_faux());
        assert!(Mesure::Vu(false).vu_faux());
        assert!(!Mesure::Vu(false).vu_vrai());
    }

    #[test]
    fn le_portail_captif_non_sonde_n_est_pas_un_portail_absent() {
        let e = Environnement::rien_sonde();
        assert!(!e.portail_a_franchir());
        // Et il ne compte pas non plus comme une sonde aboutie.
        assert_eq!(e.sondes_abouties(), 0);
    }

    #[test]
    fn les_sondes_abouties_se_comptent_une_a_une() {
        let mut e = Environnement::rien_sonde();
        assert_eq!(e.sondes_abouties(), 0);
        e.udp_passe = Mesure::Vu(false);
        assert_eq!(e.sondes_abouties(), 1);
        e.perte_pourcent = Mesure::Vu(0);
        assert_eq!(e.sondes_abouties(), 2);
    }
}
