//! Mesure d'etancheite du kill switch Windows.
//!
//! Le cycle de vie des objets WFP est verifie ailleurs, et la sonde d'identite
//! etablit qu'un blocage WFP refuse effectivement une connexion. Il manquait la
//! question la plus simple, et la seule qui interesse un utilisateur: quand le
//! kill switch est arme, le trafic est-il retenu?
//!
//! Sous Linux elle est repondue par la suite de vecteurs de fuite, qui repose sur
//! les namespaces reseau. Windows n'en a pas, et la suite s'y declare `Skipped`.
//! Cette mesure comble ce trou sans Npcap ni machine virtuelle dediee.
//!
//! # Le piege a eviter
//!
//! Le processus qui execute l'autotest EST le daemon, que le plan autorise
//! nommement par `ALE_APP_ID` et `ALE_USER_ID`. Une connexion tentee depuis lui
//! aboutit donc meme kill switch arme, et c'est le comportement voulu. Sonder
//! depuis ce processus ne mesurerait rien du tout, tout en produisant une belle
//! ligne verte. La sonde doit venir d'un processus que le plan n'autorise pas:
//! on reutilise la copie du binaire de [`crate::wfp_identity::via_copie`], dont
//! seul le chemin change, ce qui suffit a la faire tomber hors du permit.
//!
//! # Trois mesures, parce qu'aucune ne suffit seule
//!
//! 1. **Temoin negatif**, kill switch au repos: la connexion doit REELLEMENT
//!    aboutir. Pas expirer, aboutir. Une cible injoignable donnerait ensuite un
//!    echec de connexion sous armement qu'on prendrait pour un blocage reussi,
//!    et la mesure certifierait une etancheite qu'elle n'a jamais observee.
//!    C'est la raison d'etre de [`Verdict::Connecte`], distinct de `Passe`.
//! 2. **Sous armement**: la meme connexion, depuis le meme binaire copie, doit
//!    etre refusee par un filtre. Seul `WSAEACCES` vaut refus; une echeance ou
//!    une absence de route ne prouvent rien et ne sont pas comptees comme un
//!    succes.
//! 3. **Apres desarmement**: la connexion doit revenir. Sans cette troisieme
//!    mesure, un refus constate en 2 pourrait aussi bien venir de la cible
//!    tombee entre-temps que du kill switch, et un filtre qui survit au retrait
//!    passerait inapercu.
//!
//! Conformement a la regle du module `checks`, une mesure qui ne peut pas
//! conclure renvoie `Ignore` avec sa raison, jamais un succes par defaut.

use std::net::SocketAddr;

use anyhow::anyhow;
use bifrost_core::ports::{FirewallPolicy, KillSwitch};
use bifrost_firewall::windows::WfpKillSwitch;

use crate::wfp_identity::{Issue, Verdict, via_copie};

/// Execute les trois mesures.
///
/// **Coupe tout le reseau de la machine** entre l'armement et le desarmement,
/// puisque c'est precisement ce qu'on cherche a constater. Le desarmement a
/// lieu quel que soit le resultat de la sonde et avant toute analyse: rendre le
/// reseau prime sur la lecture du resultat, et l'inverse a deja coute un
/// redemarrage.
pub fn run(
    firewall: &mut WfpKillSwitch,
    policy: &FirewallPolicy,
    cible: SocketAddr,
) -> anyhow::Result<Issue> {
    println!("  temoin negatif vers {cible}, kill switch au repos...");
    let controle = via_copie(cible)?;
    println!("    au repos:           {controle:?}");
    if controle != Verdict::Connecte {
        // Rien n'est arme, donc rien a retirer. Surtout: on ne coupe pas le
        // reseau de la machine pour une mesure dont on sait deja qu'elle ne
        // conclura rien.
        return Ok(conclure(cible, controle, None, None));
    }

    println!("  armement du vrai plan de blocage, le reseau tombe...");
    firewall
        .engage(policy)
        .map_err(|e| anyhow!("armement de la mesure d'etancheite: {e}"))?;

    let arme = via_copie(cible);
    let desarmement = firewall
        .disengage()
        .map_err(|e| anyhow!("desarmement de la mesure d'etancheite: {e}"));
    println!("  desarme, le reseau revient");

    let arme = arme?;
    desarmement?;
    println!("    sous armement:      {arme:?}");

    let restaure = via_copie(cible)?;
    println!("    apres desarmement:  {restaure:?}");

    Ok(conclure(cible, controle, Some(arme), Some(restaure)))
}

/// Conclut a partir des trois mesures.
///
/// Pure et sans effet de bord, donc verifiable sans machine Windows ni
/// privileges. Cette fonction porte a elle seule la question "qu'est-ce qui
/// compte comme une preuve d'etancheite", et c'est la que ca doit se discuter.
///
/// `arme` et `restaure` valent `None` quand la mesure a ete abandonnee avant
/// d'armer, ce qui n'arrive que si le temoin negatif est deja muet: il n'y a
/// alors aucune raison de couper le reseau de la machine.
pub fn conclure(
    cible: SocketAddr,
    controle: Verdict,
    arme: Option<Verdict>,
    restaure: Option<Verdict>,
) -> Issue {
    if controle == Verdict::SansRoute {
        return Issue::Ignore(format!(
            "aucune route vers {cible} au repos: la sonde ne mesure rien"
        ));
    }
    if controle != Verdict::Connecte {
        return Issue::Ignore(format!(
            "le temoin negatif n'a pas abouti ({controle:?}) vers {cible} alors \
             que rien n'est arme. Une cible qui ne repond deja pas au repos ne \
             peut pas attester d'un blocage: sous armement elle echouerait de \
             toute facon. Choisir une cible qui accepte une connexion TCP."
        ));
    }
    let (Some(arme), Some(restaure)) = (arme, restaure) else {
        return Issue::Ignore(format!("mesure abandonnee avant l'armement, cible {cible}"));
    };
    if arme != Verdict::Bloque {
        return Issue::Echec(format!(
            "FUITE: la connexion vers {cible} est passee ({arme:?}) alors que le \
             kill switch etait arme, et depuis un binaire que le plan n'autorise \
             pas. Le block-all ne retient pas le trafic."
        ));
    }
    if restaure == Verdict::Bloque {
        return Issue::Echec(format!(
            "la connexion vers {cible} est encore refusee apres le desarmement: \
             des filtres survivent au retrait, la machine reste coupee"
        ));
    }
    if restaure != Verdict::Connecte {
        return Issue::Ignore(format!(
            "la cible {cible} ne repond plus apres le desarmement ({restaure:?}): \
             le refus observe sous armement ne peut plus etre attribue au kill \
             switch plutot qu'a la disparition de la cible"
        ));
    }
    Issue::Reussi
}

/// Vrai si la mesure a effectivement arme et constate un refus a imputer.
///
/// L'attribution nominative interroge `filtres_nommes`, qui ne connait que les
/// filtres du dernier armement. Apres un `Ignore`, il n'y a pas eu d'armement:
/// la liste est vide, et le vecteur en conclut que le plan a change. C'est
/// faux, et c'est la pire des deux erreurs possibles - un banc mal dispose
/// devient une fuite a chercher. Apres un `Echec`, les filtres existent mais la
/// connexion est PASSEE: le journal n'a aucun blocage a montrer, et exiger une
/// attribution masquerait la fuite derriere une erreur d'outillage.
///
/// La regle du depot veut qu'une mesure qui ne peut pas conclure le dise. Elle
/// vaut dans les deux sens: ne pas transformer un SKIPPED en FAILED non plus.
pub fn attribuable(issue: &Issue) -> bool {
    matches!(issue, Issue::Reussi)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cible() -> SocketAddr {
        "203.0.113.7:443".parse().unwrap()
    }

    fn nom(issue: &Issue) -> &'static str {
        match issue {
            Issue::Reussi => "Reussi",
            Issue::Ignore(_) => "Ignore",
            Issue::Echec(_) => "Echec",
        }
    }

    fn juge(controle: Verdict, arme: Verdict, restaure: Verdict) -> Issue {
        conclure(cible(), controle, Some(arme), Some(restaure))
    }

    /// La seule sequence qui vaut une preuve: ca passe, ca ne passe plus, ca
    /// repasse. Les deux extremites encadrent le blocage et l'attribuent a
    /// l'armement.
    #[test]
    fn la_sequence_encadree_vaut_preuve() {
        let i = juge(Verdict::Connecte, Verdict::Bloque, Verdict::Connecte);
        assert_eq!(nom(&i), "Reussi");
    }

    /// Le point le plus important du fichier. Une cible injoignable produit un
    /// echec de connexion sous armement, qu'on prendrait pour un blocage. Si le
    /// temoin negatif n'aboutit pas VRAIMENT, la mesure ne prouve rien et doit
    /// se declarer ignoree plutot que reussie.
    #[test]
    fn un_temoin_negatif_muet_ne_prouve_rien() {
        for controle in [Verdict::Passe, Verdict::SansRoute, Verdict::Bloque] {
            let i = juge(controle, Verdict::Bloque, Verdict::Connecte);
            assert_eq!(
                nom(&i),
                "Ignore",
                "un temoin negatif {controle:?} ne devrait rien conclure"
            );
        }
    }

    /// Une echeance atteinte n'est pas un refus. La confondre avec un blocage
    /// ferait passer la mesure sur une machine dont le kill switch ne retient
    /// rien mais dont la cible est simplement lente.
    #[test]
    fn seul_un_refus_atteste_du_blocage() {
        for arme in [Verdict::Connecte, Verdict::Passe] {
            let i = juge(Verdict::Connecte, arme, Verdict::Connecte);
            assert_eq!(nom(&i), "Echec", "un armement {arme:?} est une fuite");
        }
    }

    /// C'est le defaut qui a deja coute un redemarrage: des filtres qui
    /// survivent au desarmement laissent la machine coupee.
    #[test]
    fn des_filtres_qui_survivent_au_desarmement_sont_un_echec() {
        let i = juge(Verdict::Connecte, Verdict::Bloque, Verdict::Bloque);
        assert_eq!(nom(&i), "Echec");
    }

    /// Si la cible disparait pendant la mesure, le refus constate sous
    /// armement n'est plus attribuable au kill switch. Ni succes ni echec.
    #[test]
    fn une_cible_disparue_en_cours_de_mesure_ne_conclut_pas() {
        for restaure in [Verdict::Passe, Verdict::SansRoute] {
            let i = juge(Verdict::Connecte, Verdict::Bloque, restaure);
            assert_eq!(nom(&i), "Ignore", "restauration {restaure:?}");
        }
    }

    /// Abandon avant armement: le reseau n'a pas ete coupe, il n'y a rien a
    /// conclure et surtout rien a declarer reussi.
    #[test]
    fn l_abandon_avant_armement_ne_conclut_pas() {
        let i = conclure(cible(), Verdict::Passe, None, None);
        assert_eq!(nom(&i), "Ignore");
    }

    /// Une fuite doit se lire comme une fuite. Ce test verrouille le mot, parce
    /// qu'un echec formule mollement se relit six mois plus tard comme un
    /// detail d'outillage.
    #[test]
    fn une_fuite_est_nommee_fuite() {
        let Issue::Echec(message) = juge(Verdict::Connecte, Verdict::Connecte, Verdict::Connecte)
        else {
            panic!("une connexion qui passe sous armement doit etre un echec");
        };
        assert!(message.contains("FUITE"), "message: {message}");
    }

    #[test]
    fn une_mesure_qui_s_est_abstenue_n_autorise_aucune_attribution() {
        // Le defaut que ce test verrouille, observe sur `ipv6-leak` en portee
        // globale: le temoin negatif n'aboutit pas, `run` rend `Ignore` sans
        // jamais armer, donc AUCUN filtre n'a ete pose. Chercher l'attribution
        // la-dessus trouve une liste vide et fait accuser le plan d'avoir
        // change. Un SKIPPED legitime devient alors un FAILED a la cause
        // fausse, ce qui est la pire des deux erreurs: on cherche une fuite la
        // ou il n'y a qu'un banc mal dispose.
        assert!(!attribuable(&Issue::Ignore("temoin muet".into())));
        // Un echec a bien arme, mais il n'a rien a imputer a personne: la
        // connexion est PASSEE. Le journal n'a aucun blocage a montrer.
        assert!(!attribuable(&Issue::Echec("fuite".into())));
        // Seul le succes a pose des filtres ET constate un refus qu'on peut
        // leur imputer nommement.
        assert!(attribuable(&Issue::Reussi));
    }
}
