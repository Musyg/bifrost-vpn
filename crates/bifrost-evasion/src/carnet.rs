//! Les souvenirs de TOUS les reseaux, et la regle qui dispense de sonder.
//!
//! [`crate::memoire`] sait ce qui a marche sur UN reseau. Il lui manquait deux
//! choses pour servir: de quoi ranger un souvenir par reseau, et quelqu'un pour
//! dire ce qu'on en fait. Sans elles, `MemoireReseau::vierge()` etait la seule
//! memoire que le daemon ait jamais eue, et le module entier ne changeait rien
//! au comportement.
//!
//! # Pourquoi ceci repond a la question des sondes
//!
//! Sonder emet. Les sept mesures de [`crate::environnement`] demandent toutes
//! un paquet sortant, sans exception: aucune ne se deduit d'un etat local. Les
//! emettre avant qu'un tunnel soit monte, c'est ouvrir exactement la fenetre
//! que le vecteur `startup-window` existe pour mesurer.
//!
//! L'etat de l'art d'aout 2026 sur ce point precis est celui de Mullvad, pour
//! sa detection de portail captif: plutot que percer le pare-feu arme, un
//! resolveur local repond des reponses fabriquees, et rien ne sort. Le procede
//! ne se transpose pas tel quel ici, parce que les six autres sondes doivent
//! apprendre des faits sur le VRAI chemin (l'UDP passe-t-il, y a-t-il un
//! interception TLS) qu'une reponse fabriquee localement n'enseigne pas. Mais
//! le principe se transpose entierement: **ne pas emettre pour apprendre ce
//! qu'on sait deja.**
//!
//! D'ou ce module. Reconnaitre un reseau par son lien et sa passerelle est de
//! la lecture d'etat local, donc gratuite. Sur un reseau deja connu et encore
//! frais, la bonne quantite de sondes est zero.
//!
//! # Pourquoi les souvenirs perimes s'effacent
//!
//! Un carnet qui n'oublie jamais devient l'historique des reseaux frequentes,
//! c'est-a-dire des lieux traverses. Une entree qui ne peut plus peser sur
//! aucune decision n'a donc pas seulement cesse d'etre utile: elle est devenue
//! une donnee a ne pas garder. [`Carnet::oublier_les_perimes`] la retire.
//!
//! # Pourquoi l'encodage n'est pas ici
//!
//! Le carnet derive `Serialize`, mais ne sait ni lire ni ecrire un fichier, et
//! ne connait meme pas JSON: ce crate ne depend que de `serde`, et l'ajout de
//! `serde_json` pour deux methodes ferait entrer un format dans une couche qui
//! n'a que des regles. Le daemon encode, range et relit. Les tests ci-dessous
//! verifient tout de meme que la FORME s'y prete, parce que c'est une propriete
//! du type et non du fichier.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::date::Date;
use crate::memoire::{CleReseau, MemoireReseau};
use crate::technique::Technique;

/// Faut-il sonder ce reseau, et si non, pourquoi.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sondage {
    /// Reseau connu, souvenir encore valable: **ne rien emettre**.
    Inutile { technique: Technique, quand: Date },
    /// Sonder emettra. La raison dit ce qui manque, pour que la decision se
    /// lise dans le journal au lieu de se deviner.
    Necessaire(String),
}

/// Ce que le souvenir de ce reseau permet de faire sans emettre.
pub fn sondage(memoire: &MemoireReseau, aujourd_hui: Date) -> Sondage {
    match memoire.a_marche {
        None => Sondage::Necessaire(
            "aucune reussite memorisee sur ce reseau: rien ne dit ce qui y passe".to_owned(),
        ),
        Some((technique, quand)) => match memoire.reussite_utilisable(aujourd_hui) {
            Some(_) => Sondage::Inutile { technique, quand },
            // Le souvenir existe mais ne vaut plus. Le dire avec sa date: un
            // "il faut sonder" muet ne se distingue pas d'un carnet vide, et
            // les deux ne se corrigent pas de la meme facon.
            None => Sondage::Necessaire(format!(
                "la reussite memorisee ({} le {quand:?}) n'est plus exploitable: perimee ou datee du futur",
                technique.nom()
            )),
        },
    }
}

/// Les souvenirs, ranges par reseau.
///
/// `BTreeMap` et non `HashMap`: l'ordre de serialisation doit etre stable, sans
/// quoi deux ecritures du meme contenu produisent deux fichiers differents et
/// toute comparaison devient impossible.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Carnet {
    reseaux: BTreeMap<CleReseau, MemoireReseau>,
}

impl Carnet {
    pub fn vide() -> Self {
        Self::default()
    }

    /// Le souvenir de ce reseau, s'il y en a un.
    pub fn souvenir(&self, cle: &CleReseau) -> Option<&MemoireReseau> {
        self.reseaux.get(cle)
    }

    pub fn est_vide(&self) -> bool {
        self.reseaux.is_empty()
    }

    pub fn combien(&self) -> usize {
        self.reseaux.len()
    }

    pub fn noter_reussite(&mut self, cle: CleReseau, technique: Technique, quand: Date) {
        self.reseaux
            .entry(cle)
            .or_default()
            .noter_reussite(technique, quand);
    }

    pub fn noter_echec(&mut self, cle: CleReseau, technique: Technique, quand: Date) {
        self.reseaux
            .entry(cle)
            .or_default()
            .noter_echec(technique, quand);
    }

    /// Retire les souvenirs qui ne peuvent plus peser sur aucune decision.
    ///
    /// Rend le nombre d'entrees oubliees. Un souvenir garde est un souvenir qui
    /// sert: sans reussite exploitable NI echec assez recent pour ecarter quoi
    /// que ce soit, l'entree ne fait plus que dire que ce reseau a ete
    /// frequente, ce qui n'est pas une chose a conserver.
    pub fn oublier_les_perimes(&mut self, aujourd_hui: Date) -> usize {
        let avant = self.reseaux.len();
        self.reseaux.retain(|_, m| {
            m.reussite_utilisable(aujourd_hui).is_some()
                || m.a_echoue
                    .iter()
                    .any(|(t, _)| m.echec_recent(*t, aujourd_hui))
        });
        avant - self.reseaux.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const AOUT: Date = Date::new(2026, 8, 19);

    fn cle(n: &str) -> CleReseau {
        CleReseau::nouvelle(n, "192.168.1.1", None)
    }

    /// Le point du module: sur un reseau connu, on n'emet rien.
    #[test]
    fn un_reseau_connu_dispense_de_sonder() {
        let mut c = Carnet::vide();
        c.noter_reussite(
            cle("bureau"),
            Technique::RealityVision,
            Date::new(2026, 8, 15),
        );
        let m = c.souvenir(&cle("bureau")).expect("le souvenir est la");
        assert_eq!(
            sondage(m, AOUT),
            Sondage::Inutile {
                technique: Technique::RealityVision,
                quand: Date::new(2026, 8, 15)
            }
        );
    }

    #[test]
    fn un_reseau_inconnu_oblige_a_sonder() {
        let c = Carnet::vide();
        assert!(c.souvenir(&cle("hotel")).is_none());
        let raison = match sondage(&MemoireReseau::vierge(), AOUT) {
            Sondage::Necessaire(r) => r,
            autre => panic!("un reseau inconnu doit obliger a sonder: {autre:?}"),
        };
        assert!(raison.contains("aucune reussite"), "{raison}");
    }

    /// Un souvenir perime ne doit pas se confondre avec un carnet vide: les
    /// deux obligent a sonder, mais ne se corrigent pas de la meme facon.
    #[test]
    fn un_souvenir_perime_dit_qu_il_a_existe() {
        let mut c = Carnet::vide();
        c.noter_reussite(cle("bureau"), Technique::Hysteria2, Date::new(2026, 1, 1));
        let m = c.souvenir(&cle("bureau")).expect("le souvenir est la");
        let raison = match sondage(m, AOUT) {
            Sondage::Necessaire(r) => r,
            autre => panic!("un souvenir perime ne dispense pas de sonder: {autre:?}"),
        };
        assert!(raison.contains("hysteria2"), "{raison}");
        assert!(raison.contains("2026"), "la date doit figurer: {raison}");
    }

    /// Une date future est une donnee fausse. Lui obeir ferait sauter le
    /// sondage sur la foi d'une erreur, ce qui est le seul cas ou ne pas
    /// emettre est le mauvais choix.
    #[test]
    fn un_souvenir_date_du_futur_ne_dispense_pas() {
        let mut c = Carnet::vide();
        c.noter_reussite(cle("bureau"), Technique::Hysteria2, Date::new(2027, 5, 1));
        let m = c.souvenir(&cle("bureau")).expect("le souvenir est la");
        assert!(matches!(sondage(m, AOUT), Sondage::Necessaire(_)));
    }

    #[test]
    fn deux_reseaux_ne_melangent_pas_leurs_souvenirs() {
        let mut c = Carnet::vide();
        c.noter_reussite(cle("bureau"), Technique::RealityVision, AOUT);
        c.noter_echec(cle("hotel"), Technique::RealityVision, AOUT);
        assert_eq!(
            c.souvenir(&cle("bureau"))
                .unwrap()
                .reussite_utilisable(AOUT),
            Some(Technique::RealityVision)
        );
        assert_eq!(
            c.souvenir(&cle("hotel")).unwrap().reussite_utilisable(AOUT),
            None,
            "l'echec d'un reseau a contamine la reussite de l'autre"
        );
    }

    #[test]
    fn un_carnet_survit_a_l_aller_retour() {
        let mut c = Carnet::vide();
        c.noter_reussite(cle("bureau"), Technique::RealityVision, AOUT);
        c.noter_echec(cle("hotel"), Technique::Hysteria2, AOUT);
        let texte = serde_json::to_string(&c).expect("un carnet est serialisable");
        let relu: Carnet = serde_json::from_str(&texte).expect("le carnet doit se relire");
        assert_eq!(relu, c);
    }

    /// L'ordre de serialisation doit etre stable: sans cela, deux ecritures du
    /// meme contenu produisent deux fichiers differents et toute comparaison
    /// devient impossible.
    #[test]
    fn deux_ecritures_du_meme_carnet_sont_identiques() {
        let mut a = Carnet::vide();
        let mut b = Carnet::vide();
        for n in ["zzz", "aaa", "mmm"] {
            a.noter_reussite(cle(n), Technique::RealityVision, AOUT);
        }
        // Le meme contenu, insere dans un autre ordre.
        for n in ["mmm", "zzz", "aaa"] {
            b.noter_reussite(cle(n), Technique::RealityVision, AOUT);
        }
        assert_eq!(
            serde_json::to_string(&a).unwrap(),
            serde_json::to_string(&b).unwrap()
        );
    }

    /// Un fichier abime ne doit pas pouvoir passer pour un carnet vide: le
    /// daemon s'appuie dessus pour refuser de se rabattre en silence sur
    /// "aucun souvenir", ce qui ferait sonder alors qu'on avait de quoi ne pas
    /// le faire.
    #[test]
    fn un_carnet_abime_ne_passe_pas_pour_un_carnet_vide() {
        assert!(serde_json::from_str::<Carnet>("{ ceci n'est pas du json").is_err());
        assert!(
            serde_json::from_str::<Carnet>("").is_err(),
            "un fichier vide n'est pas un carnet vide"
        );
    }

    #[test]
    fn un_carnet_vide_se_relit() {
        let texte = serde_json::to_string(&Carnet::vide()).unwrap();
        let c: Carnet = serde_json::from_str(&texte).expect("doit se relire");
        assert!(c.est_vide());
    }

    /// Une entree qui ne peut plus peser sur aucune decision n'est plus qu'une
    /// trace des reseaux frequentes.
    #[test]
    fn les_souvenirs_perimes_s_oublient() {
        let mut c = Carnet::vide();
        c.noter_reussite(
            cle("vieux"),
            Technique::RealityVision,
            Date::new(2026, 1, 1),
        );
        c.noter_reussite(
            cle("frais"),
            Technique::RealityVision,
            Date::new(2026, 8, 18),
        );
        assert_eq!(c.combien(), 2);
        assert_eq!(c.oublier_les_perimes(AOUT), 1);
        assert!(c.souvenir(&cle("vieux")).is_none());
        assert!(c.souvenir(&cle("frais")).is_some());
    }

    /// Un echec recent SEUL vaut d'etre garde: il ecarte une technique du
    /// prochain essai, donc il pese encore.
    #[test]
    fn un_echec_recent_seul_merite_d_etre_garde() {
        let mut c = Carnet::vide();
        c.noter_echec(cle("hotel"), Technique::Hysteria2, Date::new(2026, 8, 18));
        assert_eq!(c.oublier_les_perimes(AOUT), 0);
        assert!(c.souvenir(&cle("hotel")).is_some());
    }

    /// Un echec ANCIEN seul n'ecarte plus rien: l'entree ne dit plus que
    /// "ce reseau a ete frequente".
    #[test]
    fn un_echec_ancien_seul_s_oublie() {
        let mut c = Carnet::vide();
        c.noter_echec(cle("hotel"), Technique::Hysteria2, Date::new(2026, 1, 1));
        assert_eq!(c.oublier_les_perimes(AOUT), 1);
        assert!(c.est_vide());
    }

    #[test]
    fn oublier_dans_un_carnet_vide_ne_fait_rien() {
        assert_eq!(Carnet::vide().oublier_les_perimes(AOUT), 0);
    }
}
