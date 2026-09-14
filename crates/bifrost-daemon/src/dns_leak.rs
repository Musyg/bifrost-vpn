//! Le vecteur `dns-leak` sous Windows: aucune requete DNS ne sort en clair.
//!
//! # Ce qui rend ce vecteur mesurable ici
//!
//! Il ne demande ni tunnel monte, ni coeur, ni IPv6: le plan porte deja un
//! `block-dns` sous le permit du resolveur local, et il s'applique des que le
//! kill switch est arme. Plusieurs vecteurs attendent un tunnel monte;
//! celui-ci n'attendait que d'etre cable.
//!
//! # Pourquoi une commande dediee et non `bifrost-cli check`
//!
//! Ce vecteur ARME le kill switch, donc il coupe le reseau de la machine qui
//! l'execute. Sous Linux le harnais travaille dans des namespaces et ne touche
//! pas a l'hote; sous Windows il n'y a pas d'equivalent, et la mesure se paie
//! en vrai. Couper le reseau de quelqu'un au detour d'un `check` serait une
//! mauvaise surprise, donc `check` continue de rendre `Skipped` en renvoyant
//! ici, et c'est cette commande-la qui coupe, quand on la demande.
//!
//! # Ce que la mesure etablit, et ce qu'elle n'etablit pas
//!
//! Elle etablit qu'une requete DNS vers un resolveur EXTERNE, emise par un
//! processus que le plan n'autorise pas, est refusee par le filtre `block-dns`
//! nommement. Elle n'etablit pas que toutes les formes de DNS sont couvertes:
//! un resolveur DoH parle du 443 et ne ressemble a rien de particulier sur le
//! fil. Le document 02 le dit deja, et aucun filtre de port n'y changera rien.
//!
//! # Le detail qui decide de tout: d'ou part la sonde
//!
//! Le daemon porte un permit de poids 15, au-dessus du `block-dns` de poids 14.
//! Une requete DNS emise depuis LUI aboutit donc, kill switch arme, et c'est le
//! comportement voulu. Sonder depuis ce processus ne mesurerait rien tout en
//! produisant une ligne verte. La sonde part d'une COPIE du binaire, dont seul
//! le chemin change, ce qui suffit a la faire tomber hors du permit.
//!
//! On sonde en TCP et non en UDP: `block-dns` porte ses deux conditions de
//! protocole sur le meme champ, donc combinees en OU, et le port 53 en TCP
//! traverse exactement le meme filtre. Cela evite d'ecrire une sonde UDP dont
//! le silence serait ambigu.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use anyhow::anyhow;
use bifrost_core::ports::FirewallPolicy;
use bifrost_firewall::windows::WfpKillSwitch;

use crate::temoin_wfp;
use crate::wfp_identity::Issue;
use crate::wfp_leaktest;

/// Le journal d'audit n'est pas ecrit dans la foulee de la connexion.
const FENETRE: Duration = Duration::from_secs(60);
/// Nom du filtre dont on attend qu'il refuse. C'est celui du plan.
const FILTRE_ATTENDU: &str = "block-dns";

/// Construit la politique du vecteur.
///
/// `resolveur_local` est la SEULE destination :53 autorisee. En pointant la
/// boucle locale, toute requete vers un resolveur externe tombe sous
/// `block-dns`, ce qui est exactement la situation du produit quand le
/// resolveur chiffre embarque tourne.
fn politique(lan: bool) -> FirewallPolicy {
    FirewallPolicy {
        tunnel_interface: None,
        tunnel_luid: None,
        fwmark: None,
        dns_resolver: IpAddr::V4(Ipv4Addr::LOCALHOST),
        // Ouvrir le reseau local ne desarme pas `block-dns`: le blocage DNS
        // pese 14 et le permit du LAN 11. Une requete :53 vers le LAN reste
        // donc refusee, et la session d'administration survit quand meme.
        allow_lan: lan,
        coeur_uid: None,
        coeur_executable: None,
        resolveur_uid: None,
        resolveur_executable: None,
        resolveur_sid: None,
        resolveur_embarque: false,
    }
}

/// Mesure le vecteur. Coupe le reseau entre l'armement et le desarmement.
pub fn selftest(resolveur: SocketAddr, lan: bool) -> anyhow::Result<()> {
    if resolveur.port() != 53 {
        anyhow::bail!(
            "le resolveur doit etre sur le port 53: c'est le port que \
             `{FILTRE_ATTENDU}` filtre, et sonder ailleurs mesurerait le \
             catch-all sans rien dire du DNS"
        );
    }

    let mut firewall = WfpKillSwitch::new().map_err(|e| anyhow!("ouverture du moteur WFP: {e}"))?;
    let politique = politique(lan);

    println!("vecteur dns-leak, resolveur externe {resolveur}");
    let issue = wfp_leaktest::run(&mut firewall, &politique, resolveur)?;

    // L'attribution vient APRES le desarmement, a dessein: le journal persiste,
    // alors que le reseau coupe, non. Rendre la machine prime sur la lecture du
    // resultat. Elle ne vaut que si la mesure a arme ET constate un refus:
    // apres un `Ignore`, aucun filtre n'a ete pose, et l'exiger ferait accuser
    // le plan d'avoir change alors que la mesure s'est abstenue.
    if wfp_leaktest::attribuable(&issue) {
        attribuer(&firewall, resolveur)?;
    }

    match issue {
        Issue::Reussi => {
            println!(
                "
dns-leak: PASSED - aucune requete DNS ne sort en clair"
            );
            Ok(())
        }
        // Un vecteur qui n'a pas pu mesurer n'est PAS un echec d'etancheite, et
        // les confondre ferait chercher une fuite la ou il n'y a qu'un banc mal
        // dispose. C'est la regle non negociable du depot.
        Issue::Ignore(raison) => {
            println!(
                "
dns-leak: SKIPPED - {raison}"
            );
            Ok(())
        }
        Issue::Echec(raison) => Err(anyhow!("dns-leak: FAILED - {raison}")),
    }
}

/// Impute le refus a la regle DNS, nommement.
///
/// Appelee seulement quand la mesure a conclu: voir
/// [`wfp_leaktest::attribuable`].
fn attribuer(firewall: &WfpKillSwitch, resolveur: SocketAddr) -> anyhow::Result<()> {
    let attendus = firewall.filtres_nommes(FILTRE_ATTENDU);
    if attendus.is_empty() {
        anyhow::bail!(
            "aucun filtre nomme `{FILTRE_ATTENDU}` n'a ete pose: le plan a \
             change, et cette mesure ne porte plus sur ce qu'elle annonce"
        );
    }
    println!("  filtres `{FILTRE_ATTENDU}` poses: {attendus:?}");

    let constat = attendre(&attendus, resolveur)?;
    println!(
        "  journal d'audit: {} blocages WFP dans la fenetre, dont {} imputables \
         a `{FILTRE_ATTENDU}`",
        constat.total,
        constat.notres.len()
    );

    if constat.audit_muet() {
        anyhow::bail!(
            "SKIPPED: aucun blocage WFP dans le journal, pas meme ceux du \
             pare-feu Windows: l'audit n'enregistre rien, donc l'attribution \
             est impossible. Ce n'est pas un echec d'etancheite. A activer \
             avec:\n{}",
            temoin_wfp::COMMANDE_ACTIVATION
        );
    }
    match constat.notres.first() {
        Some(b) => println!(
            "  filtre {} a la couche {}, application {}",
            b.filtre,
            b.couche,
            b.application.rsplit('\\').next().unwrap_or("?")
        ),
        None => anyhow::bail!(
            "la requete a bien ete refusee, mais AUCUN blocage n'est imputable \
             a `{FILTRE_ATTENDU}` (filtres {attendus:?}) vers {resolveur}. \
             Elle a donc ete arretee par autre chose - le catch-all, ou un \
             produit tiers - et conclure que la regle DNS fonctionne serait \
             une erreur"
        ),
    }
    Ok(())
}

/// Attend que le journal rende le blocage.
///
/// Le journal de securite n'est pas ecrit dans la foulee de la connexion; une
/// lecture unique transformerait ce delai en echec d'etancheite. Mesure sur le
/// banc: 1,2 s.
fn attendre(filtres: &[u64], resolveur: SocketAddr) -> anyhow::Result<temoin_wfp::Constat> {
    const PATIENCE: Duration = Duration::from_secs(20);
    const PAS: Duration = Duration::from_millis(500);

    let debut = std::time::Instant::now();
    let mut constat = temoin_wfp::constater(FENETRE, filtres, resolveur.ip(), resolveur.port())?;
    while constat.notres.is_empty() && debut.elapsed() < PATIENCE {
        std::thread::sleep(PAS);
        constat = temoin_wfp::constater(FENETRE, filtres, resolveur.ip(), resolveur.port())?;
    }
    Ok(constat)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn un_resolveur_hors_port_53_est_refuse_avant_toute_coupure() {
        // Sonder ailleurs qu'au 53 mesurerait le catch-all sans rien dire du
        // DNS, et couperait le reseau de la machine pour rien.
        let e = selftest("9.9.9.9:443".parse().unwrap(), true).unwrap_err();
        assert!(format!("{e}").contains("port 53"), "{e}");
    }

    #[test]
    fn la_politique_n_autorise_le_53_que_vers_la_boucle_locale() {
        let p = politique(true);
        assert_eq!(p.dns_resolver, IpAddr::V4(Ipv4Addr::LOCALHOST));
        // Le LAN ouvert ne doit pas desarmer le blocage DNS: si un jour les
        // poids changeaient, ce vecteur mesurerait le contraire de ce qu'il
        // annonce.
        assert!(p.allow_lan);
    }

    /// Le nom attendu designe un filtre que le plan pose VRAIMENT.
    ///
    /// L'imputation par le nom est tout ce qui distingue << notre blocage a
    /// mordu >> de << quelque chose a bloque >>: sans elle, un pare-feu tiers
    /// ou le catch-all suffiraient a faire passer le vecteur. Or le nom est
    /// ecrit en dur ici et le plan vit dans `bifrost-firewall`: rien ne les
    /// reliait.
    ///
    /// Mesure du 23 aout 2026 sur dev-windows: en remplacant ce nom par
    /// n'importe quelle autre chaine, toute la suite du crate restait verte.
    /// Le defaut ne serait apparu qu'a l'execution, sur une machine Windows
    /// elevee avec l'audit WFP actif - donc jamais en integration continue.
    /// Il est fail-closed, ce qui limite le degat a une mesure impossible et
    /// non a une fuite silencieuse, mais une mesure impossible qu'on decouvre
    /// sur le banc coute une journee.
    ///
    /// La comparaison est un `contains`, exactement celle que
    /// `WfpKillSwitch::filtres_nommes` fait a l'execution. Une lecture voisine
    /// mais differente ne dirait rien de la lecture reelle.
    #[test]
    fn le_filtre_attendu_est_un_filtre_que_le_plan_pose() {
        let plan = bifrost_firewall::wfp_plan::plan(
            &politique(true),
            std::path::PathBuf::from("bifrost-daemon.exe"),
            Some(1),
        );
        let noms: Vec<&str> = plan.iter().map(|f| f.name.as_str()).collect();
        assert!(
            noms.iter().any(|n| n.contains(FILTRE_ATTENDU)),
            "aucun filtre du plan ne s'appelle `{}`: ce vecteur ne pourra imputer son refus a rien. Poses: {:?}",
            FILTRE_ATTENDU,
            noms
        );
    }
}
