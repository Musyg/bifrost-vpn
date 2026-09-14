//! Ce qu'il faut avoir garde pour pouvoir tout defaire.
//!
//! Le document 03 pose la reversibilite comme obligatoire, et la couche 1 est
//! celle qui en a le plus besoin: elle touche des services et des politiques,
//! c'est-a-dire des choses dont l'utilisateur ne se souviendra pas de l'etat
//! d'origine.
//!
//! # Trois etats d'origine, pas un
//!
//! La difference entre [`Avant::ValeurAbsente`] et [`Avant::CleEtValeurAbsentes`]
//! n'est pas une subtilite. Sur essai-windows, build 26200, mesure du
//! 22/08/2026: la cle `DataCollection` EXISTE et ses valeurs non, tandis que
//! `WindowsAI`, `CloudContent`, `AdvertisingInfo` et `InputPersonalization`
//! n'existent pas du tout sous `Policies`. Poser un reglage dans le second cas
//! CREE une cle. Un retour en arriere qui se contenterait de supprimer la
//! valeur laisserait une cle de politique vide derriere lui - une trace de
//! passage, et un chemin que le prochain outil trouvera deja la.
//!
//! # Poser deux fois ne doit pas effacer l'origine
//!
//! Si l'on applique un profil, puis un autre, un journal naif noterait comme
//! "avant" ce que la premiere pose a ecrit. L'etat d'origine serait perdu, et
//! le retour en arriere ramenerait la machine a un etat ou elle n'a jamais ete.
//! [`Journal::noter`] garde donc la PREMIERE observation pour un identifiant
//! donne, et une recette le verifie.

use serde::{Deserialize, Serialize};

use crate::catalogue::Profil;

/// L'etat d'une cible avant qu'on y touche.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "etait", rename_all = "snake_case")]
pub enum Avant {
    /// Ni la cle ni la valeur n'existaient. Defaire = supprimer la valeur, puis
    /// la cle si elle est restee vide.
    CleEtValeurAbsentes,
    /// La cle existait, la valeur non. Defaire = supprimer la valeur.
    ValeurAbsente,
    /// La valeur existait. Defaire = la reecrire telle quelle.
    Dword { valeur: u32 },
    /// Une tache planifiee, avec son etat.
    Tache { activee: bool },
}

/// Ce qu'une tentative de pose a donne.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Issue {
    /// Etait different, a ete pose, et la relecture le confirme.
    Applique,
    /// Etait deja a la valeur voulue. Rien ecrit, rien a defaire.
    DejaConforme,
    /// La cible n'existe pas sur cette machine. **Jamais compte comme pose.**
    SansObjet(String),
    /// La cible existe mais ce moteur ne doit pas y toucher ici: ruche
    /// utilisateur alors qu'on tourne sous SYSTEM, droit manquant.
    Refuse(String),
    /// Rendu par la lecture d'etat seulement: la cible est atteignable et
    /// differente de ce qu'on veut.
    ///
    /// Distinct de `Refuse`, et la distinction n'est pas cosmetique: un lecteur
    /// qui voit REFUSE en face de vingt lignes croit que l'outil a refuse de
    /// travailler, alors que la machine attend simplement qu'on pose.
    APoser(String),
    /// Ecrit, puis relu different. Le cas Winhance 281.
    Echoue(String),
}

impl Issue {
    /// Le mot que le rapport imprime. Les memes que partout ailleurs dans le
    /// depot, pour qu'un lecteur n'ait pas deux vocabulaires a tenir.
    pub fn mot(&self) -> &'static str {
        match self {
            Issue::Applique => "POSE",
            Issue::DejaConforme => "DEJA",
            Issue::SansObjet(_) => "SANS OBJET",
            Issue::Refuse(_) => "REFUSE",
            Issue::APoser(_) => "A POSER",
            Issue::Echoue(_) => "ECHEC",
        }
    }

    /// Vrai si la tentative a laisse la machine dans un etat qui n'est pas
    /// celui qu'on voulait ET qui n'a pas ete explique.
    pub fn est_un_echec(&self) -> bool {
        matches!(self, Issue::Echoue(_))
    }

    /// La raison, quand il y en a une.
    pub fn raison(&self) -> Option<&str> {
        match self {
            Issue::SansObjet(r) | Issue::Refuse(r) | Issue::Echoue(r) | Issue::APoser(r) => Some(r),
            Issue::Applique | Issue::DejaConforme => None,
        }
    }
}

/// Une ligne du journal: ce qui a ete touche, et dans quel etat on l'a trouve.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entree {
    /// L'identifiant du reglage, stable dans le catalogue.
    pub id: String,
    /// La cible en clair, pour qu'un humain puisse defaire a la main le jour ou
    /// le binaire n'est plus la. Redondant avec `id` par construction, et c'est
    /// exactement pour cela qu'elle est ecrite.
    pub cible: String,
    pub avant: Avant,
}

/// La version du format. Un journal d'une version inconnue n'est pas devine.
pub const VERSION: u32 = 1;

/// Tout ce qu'il faut pour rendre la machine a son etat d'avant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Journal {
    pub version: u32,
    /// Le profil demande lors de la premiere pose.
    pub profil: Profil,
    /// Quand, en toutes lettres. Fourni par l'appelant: un journal doit se
    /// relire dans une recette sans dependre de l'horloge.
    pub pose_le: String,
    /// La build du systeme au moment de la pose. Sert au moteur de derive: une
    /// mise a jour de fonctionnalite change ce numero ET reactive DiagTrack.
    pub build: String,
    pub entrees: Vec<Entree>,
}

impl Journal {
    pub fn neuf(profil: Profil, pose_le: impl Into<String>, build: impl Into<String>) -> Self {
        Self {
            version: VERSION,
            profil,
            pose_le: pose_le.into(),
            build: build.into(),
            entrees: Vec::new(),
        }
    }

    /// Note l'etat d'origine d'une cible, **sans jamais ecraser une
    /// observation plus ancienne**.
    ///
    /// Rend `true` si l'observation a ete retenue, `false` si une plus ancienne
    /// existait deja. Le `false` n'est pas une erreur: c'est le cas normal
    /// d'une deuxieme pose, et c'est ce qui protege l'etat d'origine.
    pub fn noter(&mut self, id: &str, cible: &str, avant: Avant) -> bool {
        if self.entrees.iter().any(|e| e.id == id) {
            return false;
        }
        self.entrees.push(Entree {
            id: id.to_owned(),
            cible: cible.to_owned(),
            avant,
        });
        true
    }

    /// Les entrees dans l'ordre ou il faut les defaire: l'inverse de la pose.
    ///
    /// Aucune entree du catalogue ne depend d'une autre aujourd'hui - une
    /// recette le verifie - mais defaire dans l'ordre inverse est la seule
    /// discipline qui reste juste quand ce ne sera plus vrai.
    pub fn a_defaire(&self) -> Vec<&Entree> {
        self.entrees.iter().rev().collect()
    }

    pub fn est_vide(&self) -> bool {
        self.entrees.is_empty()
    }

    /// Serialise pour le disque.
    pub fn en_texte(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self).map_err(|e| format!("journal non serialisable: {e}"))
    }

    /// Relit un journal, en refusant une version inconnue plutot qu'en la
    /// devinant.
    ///
    /// Un journal d'une version future decrirait peut-etre des cibles que ce
    /// binaire ne sait pas defaire. Le defaire a moitie serait pire que de
    /// refuser: l'utilisateur croirait la machine rendue.
    pub fn depuis_texte(texte: &str) -> Result<Self, String> {
        let journal: Journal =
            serde_json::from_str(texte).map_err(|e| format!("journal illisible: {e}"))?;
        if journal.version != VERSION {
            return Err(format!(
                "journal en version {}, ce binaire ne connait que la {VERSION}. \
                 Le defaire a moitie laisserait la machine dans un etat que \
                 personne n'a voulu, et qu'on croirait rendu",
                journal.version
            ));
        }
        Ok(journal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn journal() -> Journal {
        Journal::neuf(Profil::Equilibre, "2026-08-22T18:00:00Z", "10.0.26200.9168")
    }

    #[test]
    fn une_deuxieme_pose_n_efface_pas_l_origine() {
        let mut j = journal();
        assert!(j.noter(
            "collecte-niveau",
            "HKLM\\... :: AllowTelemetry = 0",
            Avant::ValeurAbsente
        ));
        // Deuxieme passage: la machine porte desormais 0, mais l'origine est
        // "la valeur n'existait pas". C'est celle-la qu'il faut rendre.
        assert!(!j.noter(
            "collecte-niveau",
            "HKLM\\... :: AllowTelemetry = 0",
            Avant::Dword { valeur: 0 }
        ));
        assert_eq!(j.entrees.len(), 1);
        assert_eq!(
            j.entrees[0].avant,
            Avant::ValeurAbsente,
            "la deuxieme observation a ecrase la premiere: le retour en arriere \
             ramenerait la machine a un etat ou elle n'a jamais ete"
        );
    }

    #[test]
    fn on_defait_dans_l_ordre_inverse() {
        let mut j = journal();
        j.noter("un", "a", Avant::ValeurAbsente);
        j.noter("deux", "b", Avant::CleEtValeurAbsentes);
        j.noter("trois", "c", Avant::Dword { valeur: 3 });
        let ordre: Vec<&str> = j.a_defaire().iter().map(|e| e.id.as_str()).collect();
        assert_eq!(ordre, vec!["trois", "deux", "un"]);
    }

    #[test]
    fn le_journal_fait_l_aller_retour() {
        let mut j = journal();
        j.noter(
            "service-diagtrack",
            "service DiagTrack :: Start = 4",
            Avant::Dword { valeur: 2 },
        );
        j.noter(
            "tache-consolidator",
            "tache \\A\\B :: desactivee",
            Avant::Tache { activee: true },
        );
        j.noter(
            "recall-composant",
            "HKLM\\...WindowsAI :: AllowRecallEnablement = 0",
            Avant::CleEtValeurAbsentes,
        );
        let texte = j.en_texte().expect("serialisable");
        let relu = Journal::depuis_texte(&texte).expect("relisible");
        assert_eq!(relu, j);
    }

    /// Les trois etats d'origine doivent rester DISTINCTS a la relecture. Les
    /// confondre est precisement ce qui laisse une cle de politique vide
    /// derriere soi.
    #[test]
    fn les_trois_etats_d_origine_ne_se_confondent_pas() {
        let mut j = journal();
        j.noter("a", "a", Avant::CleEtValeurAbsentes);
        j.noter("b", "b", Avant::ValeurAbsente);
        j.noter("c", "c", Avant::Dword { valeur: 0 });
        let relu = Journal::depuis_texte(&j.en_texte().unwrap()).unwrap();
        assert_eq!(relu.entrees[0].avant, Avant::CleEtValeurAbsentes);
        assert_eq!(relu.entrees[1].avant, Avant::ValeurAbsente);
        assert_eq!(relu.entrees[2].avant, Avant::Dword { valeur: 0 });
        assert_ne!(relu.entrees[0].avant, relu.entrees[1].avant);
        // Et le texte doit les distinguer, pas seulement le type.
        let texte = j.en_texte().unwrap();
        assert!(texte.contains("cle_et_valeur_absentes"), "{texte}");
        assert!(texte.contains("valeur_absente"), "{texte}");
    }

    #[test]
    fn une_version_inconnue_est_refusee_et_non_devinee() {
        let mut j = journal();
        j.noter("a", "a", Avant::ValeurAbsente);
        let texte = j
            .en_texte()
            .unwrap()
            .replace("\"version\": 1", "\"version\": 99");
        let e = Journal::depuis_texte(&texte).expect_err("une version 99 doit etre refusee");
        assert!(e.contains("version 99"), "{e}");
        assert!(
            e.contains("croirait rendu"),
            "le message doit dire POURQUOI on refuse plutot que de constater: {e}"
        );
    }

    #[test]
    fn un_texte_qui_n_est_pas_un_journal_est_refuse() {
        let e = Journal::depuis_texte("ceci n'est pas du json").expect_err("doit echouer");
        assert!(e.contains("illisible"), "{e}");
    }

    #[test]
    fn les_mots_du_rapport_sont_ceux_du_depot() {
        assert_eq!(Issue::Applique.mot(), "POSE");
        assert_eq!(Issue::DejaConforme.mot(), "DEJA");
        assert_eq!(Issue::SansObjet("absent".into()).mot(), "SANS OBJET");
        assert_eq!(Issue::Refuse("sous SYSTEM".into()).mot(), "REFUSE");
        assert_eq!(Issue::APoser("valeur absente".into()).mot(), "A POSER");
        assert_eq!(Issue::Echoue("relu 1".into()).mot(), "ECHEC");
    }

    /// Seul `Echoue` est un echec. `SansObjet` et `Refuse` disent une mesure
    /// qui n'a pas eu lieu, ce qui est honnete; les confondre avec un echec
    /// ferait rougir une machine saine, et les confondre avec un succes ferait
    /// exactement l'inverse.
    #[test]
    fn seul_un_ecart_apres_ecriture_est_un_echec() {
        assert!(Issue::Echoue("relu 1 au lieu de 0".into()).est_un_echec());
        assert!(!Issue::SansObjet("service inconnu".into()).est_un_echec());
        assert!(!Issue::Refuse("ruche utilisateur sous SYSTEM".into()).est_un_echec());
        assert!(!Issue::APoser("valeur absente".into()).est_un_echec());
        assert!(!Issue::Applique.est_un_echec());
        assert!(!Issue::DejaConforme.est_un_echec());
    }

    #[test]
    fn les_issues_qui_expliquent_portent_leur_raison() {
        assert_eq!(
            Issue::SansObjet("service inconnu".into()).raison(),
            Some("service inconnu")
        );
        assert_eq!(Issue::Applique.raison(), None);
        assert_eq!(Issue::DejaConforme.raison(), None);
    }

    #[test]
    fn un_journal_neuf_est_vide() {
        assert!(journal().est_vide());
        assert!(journal().a_defaire().is_empty());
    }

    /// La build est gardee parce que le moteur de derive en aura besoin: une
    /// mise a jour de fonctionnalite change ce numero et remet DiagTrack en
    /// automatique.
    #[test]
    fn le_journal_garde_la_build_et_la_date() {
        let j = journal();
        let relu = Journal::depuis_texte(&j.en_texte().unwrap()).unwrap();
        assert_eq!(relu.build, "10.0.26200.9168");
        assert_eq!(relu.pose_le, "2026-08-22T18:00:00Z");
        assert_eq!(relu.profil, Profil::Equilibre);
    }
}
