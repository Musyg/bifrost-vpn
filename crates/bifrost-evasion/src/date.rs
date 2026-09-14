//! Une date civile, et la seule operation qu'on lui demande: leur ecart.
//!
//! Pas de dependance sur une bibliotheque de temps, et surtout pas d'horloge:
//! la fraicheur d'une observation se calcule contre un "aujourd'hui" fourni par
//! l'appelant. La politique reste ainsi une fonction pure, testable a une date
//! choisie, et l'impurete de la lecture de l'heure reste au bord du programme.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Date {
    pub annee: i32,
    pub mois: u8,
    pub jour: u8,
}

impl Date {
    pub const fn new(annee: i32, mois: u8, jour: u8) -> Self {
        Self { annee, mois, jour }
    }

    /// Numero de jour depuis le 1er janvier 1970, algorithme `days_from_civil`
    /// de Howard Hinnant. Il vaut pour le calendrier gregorien proleptique et
    /// gere les annees bissextiles seculaires, ce qu'une soustraction naive de
    /// `annee * 365 + mois * 30` ne fait pas.
    pub const fn numero_de_jour(self) -> i64 {
        let a = self.annee as i64 - if self.mois <= 2 { 1 } else { 0 };
        let ere = if a >= 0 { a } else { a - 399 } / 400;
        let annee_dans_ere = a - ere * 400;
        let m = self.mois as i64;
        let jour_dans_annee =
            (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + self.jour as i64 - 1;
        let jour_dans_ere =
            annee_dans_ere * 365 + annee_dans_ere / 4 - annee_dans_ere / 100 + jour_dans_annee;
        ere * 146097 + jour_dans_ere - 719468
    }

    /// Inverse de [`Date::numero_de_jour`], algorithme `civil_from_days` du
    /// meme auteur. Sert au bord du programme, la ou l'horloge du systeme est
    /// lue une fois puis passee a la politique.
    pub const fn depuis_numero_de_jour(numero: i64) -> Self {
        let z = numero + 719468;
        let ere = if z >= 0 { z } else { z - 146096 } / 146097;
        let jour_dans_ere = z - ere * 146097;
        let annee_dans_ere = (jour_dans_ere - jour_dans_ere / 1460 + jour_dans_ere / 36524
            - jour_dans_ere / 146096)
            / 365;
        let annee = annee_dans_ere + ere * 400;
        let jour_dans_annee =
            jour_dans_ere - (365 * annee_dans_ere + annee_dans_ere / 4 - annee_dans_ere / 100);
        let mois_decale = (5 * jour_dans_annee + 2) / 153;
        let jour = jour_dans_annee - (153 * mois_decale + 2) / 5 + 1;
        let mois = mois_decale + if mois_decale < 10 { 3 } else { -9 };
        Self {
            annee: (annee + if mois <= 2 { 1 } else { 0 }) as i32,
            mois: mois as u8,
            jour: jour as u8,
        }
    }

    /// Nombre de jours ecoules entre `self` et `aujourd_hui`.
    ///
    /// Negatif si `self` est dans le futur, ce que l'appelant doit traiter:
    /// une observation datee de demain est une donnee fausse, pas une donnee
    /// tres fraiche.
    pub const fn jours_jusqu_a(self, aujourd_hui: Date) -> i64 {
        aujourd_hui.numero_de_jour() - self.numero_de_jour()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn l_epoque_unix_est_le_jour_zero() {
        assert_eq!(Date::new(1970, 1, 1).numero_de_jour(), 0);
    }

    #[test]
    fn les_reperes_connus_de_l_algorithme_tombent_juste() {
        // Valeurs de reference de days_from_civil.
        assert_eq!(Date::new(1969, 12, 31).numero_de_jour(), -1);
        assert_eq!(Date::new(2000, 3, 1).numero_de_jour(), 11017);
    }

    #[test]
    fn fevrier_bissextile_est_compte() {
        // 2024 est bissextile, 2100 ne l'est pas malgre le multiple de 4.
        assert_eq!(
            Date::new(2024, 2, 28).jours_jusqu_a(Date::new(2024, 3, 1)),
            2
        );
        assert_eq!(
            Date::new(2100, 2, 28).jours_jusqu_a(Date::new(2100, 3, 1)),
            1
        );
    }

    #[test]
    fn un_semestre_fait_bien_181_jours_en_2026() {
        assert_eq!(
            Date::new(2026, 1, 1).jours_jusqu_a(Date::new(2026, 7, 1)),
            181
        );
    }

    #[test]
    fn l_aller_retour_par_le_numero_de_jour_est_l_identite() {
        // Sur quinze ans, jour par jour. Une erreur d'un jour sur une frontiere
        // de mois ou d'annee bissextile ne se verrait pas autrement, et
        // decalerait silencieusement toutes les fraicheurs du tableau de survie.
        let debut = Date::new(2020, 1, 1).numero_de_jour();
        let fin = Date::new(2035, 12, 31).numero_de_jour();
        for n in debut..=fin {
            let d = Date::depuis_numero_de_jour(n);
            assert_eq!(d.numero_de_jour(), n, "aller-retour casse sur {d:?}");
            assert!((1..=12).contains(&d.mois), "mois hors bornes: {d:?}");
            assert!((1..=31).contains(&d.jour), "jour hors bornes: {d:?}");
        }
    }

    #[test]
    fn le_jour_zero_redonne_l_epoque_unix() {
        assert_eq!(Date::depuis_numero_de_jour(0), Date::new(1970, 1, 1));
        assert_eq!(Date::depuis_numero_de_jour(-1), Date::new(1969, 12, 31));
    }

    #[test]
    fn le_29_fevrier_2024_existe_et_pas_celui_de_2100() {
        let bissextile = Date::new(2024, 2, 29);
        assert_eq!(
            Date::depuis_numero_de_jour(bissextile.numero_de_jour()),
            bissextile
        );
        // 2100 n'est pas bissextile: le 29 fevrier y retombe sur le 1er mars.
        assert_eq!(
            Date::depuis_numero_de_jour(Date::new(2100, 2, 29).numero_de_jour()),
            Date::new(2100, 3, 1)
        );
    }

    #[test]
    fn une_date_future_rend_un_ecart_negatif() {
        assert!(Date::new(2026, 12, 1).jours_jusqu_a(Date::new(2026, 8, 16)) < 0);
    }

    #[test]
    fn l_ordre_naturel_suit_la_chronologie() {
        assert!(Date::new(2026, 1, 31) < Date::new(2026, 2, 1));
        assert!(Date::new(2025, 12, 31) < Date::new(2026, 1, 1));
    }
}
