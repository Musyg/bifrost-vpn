//! Le tableau de survie du document 04 partie 1, comme donnee.
//!
//! Meme principe que le plan WFP: la politique est de la donnee, pas du code.
//! Le tableau change en semaines, il doit pouvoir etre remplace sans toucher a
//! la selection, et etre lisible a cote de sa source.
//!
//! Deux precautions que la source impose. D'abord ces lignes sont des
//! observations communautaires datees, pas des mesures controlees: chacune
//! porte sa date et sa fraicheur decide de ce qu'on s'autorise a en conclure.
//! Ensuite plusieurs cellules du document disent litteralement "Degrade/Mort",
//! parce que le sort de la technique depend d'un declencheur cote censeur. Ces
//! cellules ont leur propre statut plutot que d'etre aplaties vers le pire ou
//! vers le meilleur, qui seraient deux facons differentes de mentir.

use serde::{Deserialize, Serialize};

use crate::date::Date;
use crate::technique::Technique;

/// Juridiction sous laquelle le client se trouve.
///
/// `NonCensure` n'est pas un defaut commode: c'est le cas du FAI europeen et du
/// reseau d'entreprise, ou aucune censure etatique n'agit et ou les contraintes
/// viennent des seules sondes d'environnement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Pays {
    NonCensure,
    Chine,
    Russie,
    Iran,
    Turkmenistan,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Statut {
    Fonctionne,
    Degrade,
    /// La source dit "Degrade/Mort": la technique tient ou tombe selon un
    /// declencheur cote censeur, typiquement le passage en liste blanche CIDR.
    /// On ne l'elimine donc pas, mais on ne la met pas devant non plus.
    Incertain,
    Mort,
}

/// Une ligne du tableau, pour une technique et un pays.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Observation {
    pub technique: Technique,
    pub pays: Pays,
    pub statut: Statut,
    /// Date de la derniere mesure fiable connue. Les cellules du document qui
    /// ne donnent qu'une annee ou un trimestre sont ramenees a son premier
    /// jour: une observation vaguement datee doit vieillir vite, pas lentement.
    pub mesure_le: Date,
}

/// Les cellules pour lesquelles AUCUNE source datee n'est connue.
///
/// Une absence DELIBEREE, et c'est toute la difference que cette liste sert a
/// garder. Sans elle, un trou par oubli et un trou par honnetete se
/// ressemblent, et la recette de completude ne pourrait plus attraper que le
/// premier en interdisant le second.
///
/// Ce que produit une cellule absente: `statut` rend `None`, que
/// `selection::rang_de_survie` traite comme "ne rien savoir" - ni eliminee, ni
/// mise devant, entre `Degrade` et `Incertain`. C'est exactement ce qu'on veut
/// dire. Ecrire un statut invente serait pire que le trou: un statut se lit
/// comme une mesure, et il vieillirait ensuite comme si quelqu'un l'avait
/// faite.
///
/// Retirer une paire d'ici demande une source primaire datee, pas un
/// raisonnement. Il est tentant d'en tenir un - un CDN place le serveur dans
/// des plages que les listes blanches CIDR epargnent - mais un raisonnement
/// n'est pas une observation, et ce tableau ne contient que des observations.
pub const SANS_SOURCE: [(Technique, Pays); 6] = [
    (Technique::WebsocketCdn, Pays::Chine),
    (Technique::WebsocketCdn, Pays::Russie),
    (Technique::WebsocketCdn, Pays::Turkmenistan),
    (Technique::HttpUpgradeFront, Pays::Chine),
    (Technique::HttpUpgradeFront, Pays::Iran),
    (Technique::HttpUpgradeFront, Pays::Turkmenistan),
];

/// Au-dela de ce delai, une observation ne justifie plus d'ELIMINER une
/// technique.
///
/// Le document previent que la situation change en semaines. Un trimestre est
/// donc deja long pour ce tableau; l'observation garde son poids dans le
/// classement, elle perd seulement le droit de supprimer un candidat. Un
/// censeur qui leve un blocage sans qu'on le sache ne doit pas nous priver
/// definitivement du protocole qui remarche.
pub const FRAICHEUR_POUR_ELIMINER_JOURS: i64 = 90;

/// Le tableau, restreint aux techniques que la selection sait proposer.
///
/// Les techniques du document 04 qui ne sont pas des candidats de la machine a
/// etats (OpenVPN, Trojan, obfs4, Snowflake, etc.) ne sont pas reprises ici:
/// elles y figurent comme etat de l'art, pas comme options du produit.
pub const TABLEAU: &[Observation] = &[
    // VLESS + REALITY + Vision. Document: 2026-07.
    obs(
        Technique::RealityVision,
        Pays::Chine,
        Statut::Fonctionne,
        2026,
        7,
    ),
    // # Rafraichie le 4 septembre 2026: date 2026-07 -> 2026-09, statut inchange.
    //
    // net4people/bbs #663 (2026-09-02, REALITY degrade toute la connexion du
    // foyer en mode TUN sur Beeline mobile apres 5 a 15 min, intact en mode
    // proxy); #650 et son commentaire (2026-08-22, MTS: passe chez un
    // utilisateur hors liste blanche, jamais chez un autre; a Ijevsk sur MTS et
    // Megafon, REALITY+VLESS vu et bloque); empreintes TLS Chrome visees par la
    // TSPU (#662 commentaire, 2026-09-02). Reste Incertain: tient ou tombe selon
    // l'operateur, le mode et le SNI.
    obs(
        Technique::RealityVision,
        Pays::Russie,
        Statut::Incertain,
        2026,
        9,
    ),
    obs(
        Technique::RealityVision,
        Pays::Iran,
        Statut::Incertain,
        2026,
        7,
    ),
    obs(
        Technique::RealityVision,
        Pays::Turkmenistan,
        Statut::Mort,
        2026,
        7,
    ),
    // XHTTP derriere CDN. Document: 2026-06.
    obs(
        Technique::XhttpCdn,
        Pays::Chine,
        Statut::Fonctionne,
        2026,
        6,
    ),
    // Rafraichie le 4 septembre 2026: date 2026-06 -> 2026-09, statut inchange.
    // net4people/bbs #662 et son commentaire (2026-09-02): les sites Cloudflare
    // gelent apres 16 a 20 Ko hors petite liste blanche; l'attribution au
    // prefixe IP retiree par l'auteur le 2026-09-02. Reste Degrade, porte par le
    // gel a 16-20 Ko - le mecanisme de net4people/bbs #490 applique au CDN.
    obs(Technique::XhttpCdn, Pays::Russie, Statut::Degrade, 2026, 9),
    obs(Technique::XhttpCdn, Pays::Iran, Statut::Degrade, 2026, 6),
    obs(
        Technique::XhttpCdn,
        Pays::Turkmenistan,
        Statut::Mort,
        2026,
        6,
    ),
    // WebSocket derriere CDN.
    //
    // UNE seule cellule. net4people #628, "[Iran] Advanced DPI is reassembling
    // TCP fragments to extract SNI on VLESS/WS + CDN", ouverte le 2026-06-10 et
    // toujours ouverte au 2026-08-21 (dates relevees par l'API GitHub, pas
    // lues dans un resume). Le rapport decrit un VLESS/WS derriere Cloudflare
    // dont le domaine tombe en moins de 24 h MALGRE une fragmentation TCP
    // lourde. `Degrade` et non `Mort`: la technique etablit bien la connexion,
    // c'est sa duree de vie qui s'effondre. Date retenue: 2026-06, celle de
    // l'observation et non de la derniere activite du fil, pour qu'elle
    // vieillisse vite.
    obs(
        Technique::WebsocketCdn,
        Pays::Iran,
        Statut::Degrade,
        2026,
        6,
    ),
    // HTTPUpgrade derriere un front auto-heberge.
    //
    // UNE seule cellule aussi. Le document 04 partie 1 nomme `httpupgrade`
    // explicitement dans la cellule Russie de la ligne XHTTP - "Degrade
    // (httpupgrade/xhttp OK Extreme-Orient)", net4people #490, 2026-06. Cette
    // observation porte sur `httpupgrade`, donc elle reste ICI et ne suit pas
    // WebSocket: ce sont deux techniques distinctes, ce que la mesure du meme
    // jour a etabli de la facon la plus nette qui soit.
    obs(
        Technique::HttpUpgradeFront,
        Pays::Russie,
        Statut::Degrade,
        2026,
        6,
    ),
    // Hysteria2. Document: 2026, sans mois.
    obs(Technique::Hysteria2, Pays::Chine, Statut::Degrade, 2026, 1),
    // Rafraichie le 4 septembre 2026: date 2026-01 -> 2026-09, statut inchange.
    // XTLS/Xray-core #6717 (2026-09-03, Hysteria2 par sing-box passe a ~36,6
    // Mbit/s quand l'implementation Xray echoue apres la poignee de main);
    // net4people/bbs #654 (2026-08-25, la TSPU filtre le QUIC v1 par SNI sur
    // tous les ports UDP, v2 non touche); #650 commentaire (2026-08-22, Ijevsk,
    // Hysteria passe). Reste Degrade: deux temoignages positifs sur deux
    // reseaux ne valent pas "tient partout", et le SNI en liste reste vise.
    obs(Technique::Hysteria2, Pays::Russie, Statut::Degrade, 2026, 9),
    obs(Technique::Hysteria2, Pays::Iran, Statut::Mort, 2026, 1),
    obs(
        Technique::Hysteria2,
        Pays::Turkmenistan,
        Statut::Mort,
        2026,
        1,
    ),
    // AmneziaWG. Document: 2026-07.
    obs(Technique::AmneziaWg, Pays::Chine, Statut::Degrade, 2026, 7),
    // # Corrige le 20 aout 2026: Fonctionne -> Degrade
    //
    // Le document 04 donnait "Fonctionne (bas volume)" en Russie, sur
    // net4people/bbs#523. La documentation AMONT du projet Amnezia, lue le
    // 20 aout 2026, dit le contraire pour la periode qui suit: AmneziaWG 3.0
    // "a ete developpee en reponse au blocage generalise en Russie en juin et
    // juillet 2026", parce que "masquer les caracteristiques individuelles du
    // trafic ne suffisait plus".
    //
    // C'est le mainteneur du protocole qui constate que son propre protocole
    // est tombe: un temoignage contre son interet, donc du meilleur poids
    // qu'une observation d'exploitant. Et il porte sur les versions 1.5 et
    // 2.0 - exactement celles qu'on pourrait heberger soi-meme. La 3.0, qui
    // repond au blocage, n'est PAS encore auto-hebergeable selon la meme
    // page: elle n'existe que dans l'application Amnezia.
    //
    // Degrade et non Mort: le blocage est dit generalise, pas total, et une
    // parade existe meme si elle n'est pas a notre portee. La date reste
    // juillet 2026, le dernier mois nomme par la source.
    obs(Technique::AmneziaWg, Pays::Russie, Statut::Degrade, 2026, 7),
    obs(Technique::AmneziaWg, Pays::Iran, Statut::Degrade, 2026, 7),
    obs(
        Technique::AmneziaWg,
        Pays::Turkmenistan,
        Statut::Fonctionne,
        2026,
        7,
    ),
    // WireGuard nu. Document: 2026-Q2, ramene au 1er avril.
    obs(Technique::WireGuardNu, Pays::Chine, Statut::Mort, 2026, 4),
    obs(Technique::WireGuardNu, Pays::Russie, Statut::Mort, 2026, 4),
    obs(Technique::WireGuardNu, Pays::Iran, Statut::Mort, 2026, 4),
    obs(
        Technique::WireGuardNu,
        Pays::Turkmenistan,
        Statut::Degrade,
        2026,
        4,
    ),
];

const fn obs(
    technique: Technique,
    pays: Pays,
    statut: Statut,
    annee: i32,
    mois: u8,
) -> Observation {
    Observation {
        technique,
        pays,
        statut,
        mesure_le: Date::new(annee, mois, 1),
    }
}

/// Ce que le tableau dit d'une technique dans un pays.
///
/// `None` signifie qu'aucune ligne n'existe, pas que tout va bien. Sous
/// `Pays::NonCensure`, il n'y a par construction aucune ligne: le tableau
/// decrit des censures etatiques, et l'absence de censure ne s'y observe pas.
pub fn statut(technique: Technique, pays: Pays) -> Option<Observation> {
    let mut i = 0;
    while i < TABLEAU.len() {
        let o = TABLEAU[i];
        if o.technique as u8 == technique as u8 && o.pays as u8 == pays as u8 {
            return Some(o);
        }
        i += 1;
    }
    None
}

impl Observation {
    /// L'observation est-elle assez recente pour justifier une elimination.
    ///
    /// Une date future rend `false`: c'est une donnee fausse, et une donnee
    /// fausse ne doit pas donner le droit de supprimer un candidat.
    pub fn assez_fraiche_pour_eliminer(&self, aujourd_hui: Date) -> bool {
        let age = self.mesure_le.jours_jusqu_a(aujourd_hui);
        (0..=FRAICHEUR_POUR_ELIMINER_JOURS).contains(&age)
    }
}

/// Le jour ou PLUS AUCUNE ligne du tableau ne pourra eliminer un candidat.
///
/// # Pourquoi cette constante existe, et ce qu'elle repare
///
/// Parce que la meme information a ete AFFIRMEE dans quatre documents et
/// qu'elle y etait fausse. On y lisait que le tableau etait inerte "depuis
/// debut juillet 2026, observations d'avril": en realite ses lignes les plus
/// recentes datent de juillet 2026 et gardaient donc le droit d'eliminer
/// pendant tout l'ete. Une phrase de prose sur une date se demode en silence;
/// une constante verifiee par [`la_peremption_du_tableau_est_celle_qu_on_annonce`]
/// ne le peut pas - le jour ou quelqu'un rafraichit une ligne, la recette
/// devient rouge et le force a corriger ici, donc dans les documents.
///
/// La regle est simple: c'est la ligne la PLUS RECENTE plus
/// [`FRAICHEUR_POUR_ELIMINER_JOURS`], puisqu'il suffit d'une ligne vivante
/// pour que le tableau puisse encore mordre.
pub const TABLEAU_INERTE_A_PARTIR_DU: Date = Date::new(2026, 12, 1);

/// Le tableau peut-il encore eliminer QUOI QUE CE SOIT a cette date.
///
/// Rend faux quand toutes les observations sont perimees. Le tableau continue
/// alors de peser sur le CLASSEMENT - une technique morte reste derriere une
/// technique vivante - il perd seulement le droit de supprimer un candidat.
pub fn mord_encore(aujourd_hui: Date) -> bool {
    TABLEAU
        .iter()
        .any(|o| o.assez_fraiche_pour_eliminer(aujourd_hui))
}

#[cfg(test)]
mod tests {
    use super::*;

    const AOUT: Date = Date::new(2026, 8, 16);

    /// La peremption annoncee est celle que le tableau applique.
    ///
    /// La veille, au moins une ligne mord encore; le jour dit, plus aucune.
    /// C'est ce qui empeche la prose de rejouer le meme mensonge: rafraichir
    /// une observation sans corriger [`TABLEAU_INERTE_A_PARTIR_DU`] rend cette
    /// recette rouge.
    #[test]
    fn la_peremption_du_tableau_est_celle_qu_on_annonce() {
        assert!(
            !mord_encore(TABLEAU_INERTE_A_PARTIR_DU),
            "le jour annonce, plus aucune ligne ne doit pouvoir eliminer"
        );
        // Et c'est le PREMIER tel jour. Une premiere version comparait a une
        // veille ECRITE EN DUR: repousser la constante plus loin laissait la
        // recette verte, donc elle ne pincait la date que d'un cote. La
        // falsification l'a montre. On l'exprime maintenant exactement, sans
        // arithmetique de date: ce jour-la, l'observation la plus recente doit
        // avoir tout juste franchi la fenetre.
        let plus_jeune = TABLEAU
            .iter()
            .map(|o| o.mesure_le.jours_jusqu_a(TABLEAU_INERTE_A_PARTIR_DU))
            .min()
            .expect("le tableau n'est pas vide");
        assert_eq!(
            plus_jeune,
            FRAICHEUR_POUR_ELIMINER_JOURS + 1,
            "TABLEAU_INERTE_A_PARTIR_DU doit etre le lendemain du dernier jour ou l'observation la plus recente mordait encore"
        );
    }

    /// Et au 20 aout 2026, le tableau mord encore - contrairement a ce que
    /// quatre documents ont affirme.
    ///
    /// Les lignes de juillet ont 50 jours, celles de juin 80: toutes trois dans
    /// la fenetre de 90. Seules Hysteria2 (janvier) et WireGuard nu (avril)
    /// sont perimees.
    #[test]
    fn au_20_aout_2026_le_tableau_mord_encore() {
        let jour = Date::new(2026, 8, 20);
        assert!(mord_encore(jour));
        let fraiches: Vec<Technique> = TABLEAU
            .iter()
            .filter(|o| o.assez_fraiche_pour_eliminer(jour))
            .map(|o| o.technique)
            .collect();
        for attendue in [
            Technique::RealityVision,
            Technique::XhttpCdn,
            Technique::AmneziaWg,
        ] {
            assert!(
                fraiches.contains(&attendue),
                "{} devait encore pouvoir eliminer",
                attendue.nom()
            );
        }
        for perimee in [Technique::Hysteria2, Technique::WireGuardNu] {
            assert!(
                !fraiches.contains(&perimee),
                "{} est mesuree en janvier ou avril: elle ne peut plus eliminer",
                perimee.nom()
            );
        }
    }

    /// En Russie, plus AUCUNE technique n'est donnee pour fonctionnelle.
    ///
    /// C'est le seul changement que la recherche du 20 aout 2026 a fait bouger,
    /// et il est ecrit ici comme propriete de COLONNE plutot que comme echo de
    /// la cellule: une recette qui relirait `AmneziaWg + Russie == Degrade` ne
    /// dirait rien de plus que la ligne elle-meme. Celle-ci dit ce que la ligne
    /// SIGNIFIE - il n'y a plus de valeur sure sur ce reseau - et elle etait
    /// rouge avant la correction, puisque AmneziaWG y valait `Fonctionne`.
    ///
    /// Source: la documentation amont d'Amnezia, qui rattache la version 3.0 au
    /// "blocage generalise en Russie en juin et juillet 2026". Le jour ou une
    /// technique y repasse a `Fonctionne`, cette recette devient rouge et force
    /// a citer la source qui l'autorise.
    #[test]
    fn en_russie_plus_rien_n_est_donne_pour_fonctionnel() {
        for o in TABLEAU.iter().filter(|o| o.pays == Pays::Russie) {
            assert_ne!(
                o.statut,
                Statut::Fonctionne,
                "{} est donnee fonctionnelle en Russie: quelle source datee l'etablit ?",
                o.technique.nom()
            );
        }
    }

    #[test]
    fn chaque_technique_a_une_ligne_pour_chaque_pays_censeur() {
        // Un trou par OUBLI ne se voit pas: la technique passerait simplement
        // en "inconnu" au lieu d'etre jugee. Un trou par honnetete, lui, est
        // declare dans `SANS_SOURCE` et se lit. La recette exige donc l'un ou
        // l'autre, jamais rien.
        for t in Technique::TOUTES {
            for p in [Pays::Chine, Pays::Russie, Pays::Iran, Pays::Turkmenistan] {
                let declaree = SANS_SOURCE.contains(&(t, p));
                assert!(
                    statut(t, p).is_some() != declaree,
                    "{} en {:?}: soit une ligne, soit une entree dans SANS_SOURCE, jamais les deux ni aucune",
                    t.nom(),
                    p
                );
            }
        }
    }

    #[test]
    fn le_tableau_ne_contient_pas_de_doublon() {
        for (i, a) in TABLEAU.iter().enumerate() {
            for b in TABLEAU.iter().skip(i + 1) {
                assert!(
                    !(a.technique == b.technique && a.pays == b.pays),
                    "doublon: {} en {:?}",
                    a.technique.nom(),
                    a.pays
                );
            }
        }
    }

    #[test]
    fn aucune_ligne_ne_decrit_un_pays_non_censure() {
        // Y mettre une ligne serait affirmer une observation de censure la ou
        // il n'y en a pas.
        for o in TABLEAU {
            assert_ne!(o.pays, Pays::NonCensure);
        }
        assert!(statut(Technique::RealityVision, Pays::NonCensure).is_none());
    }

    #[test]
    fn une_observation_du_mois_dernier_permet_d_eliminer() {
        let o = statut(Technique::WireGuardNu, Pays::Chine).unwrap();
        assert_eq!(o.statut, Statut::Mort);
        // 2026-04-01 a 2026-06-01: 61 jours, sous le seuil.
        assert!(o.assez_fraiche_pour_eliminer(Date::new(2026, 6, 1)));
    }

    #[test]
    fn la_meme_observation_perime_et_perd_ce_droit() {
        let o = statut(Technique::WireGuardNu, Pays::Chine).unwrap();
        // 2026-04-01 a 2026-08-16: 137 jours, au-dela du trimestre.
        assert!(!o.assez_fraiche_pour_eliminer(AOUT));
    }

    #[test]
    fn une_observation_datee_du_futur_ne_permet_pas_d_eliminer() {
        let o = Observation {
            technique: Technique::Hysteria2,
            pays: Pays::Iran,
            statut: Statut::Mort,
            mesure_le: Date::new(2027, 1, 1),
        };
        assert!(!o.assez_fraiche_pour_eliminer(AOUT));
    }

    #[test]
    fn le_seuil_de_fraicheur_est_inclusif_et_borne_des_le_lendemain() {
        let o = Observation {
            technique: Technique::Hysteria2,
            pays: Pays::Iran,
            statut: Statut::Mort,
            mesure_le: Date::new(2026, 1, 1),
        };
        // Exactement 90 jours: encore valable.
        assert!(o.assez_fraiche_pour_eliminer(Date::new(2026, 4, 1)));
        // 91 jours: plus valable.
        assert!(!o.assez_fraiche_pour_eliminer(Date::new(2026, 4, 2)));
    }

    #[test]
    fn l_ordre_des_statuts_va_du_meilleur_au_pire() {
        // La selection s'appuie sur cet ordre pour classer. S'il s'inversait,
        // elle proposerait les techniques mortes en premier.
        assert!(Statut::Fonctionne < Statut::Degrade);
        assert!(Statut::Degrade < Statut::Incertain);
        assert!(Statut::Incertain < Statut::Mort);
    }
}
