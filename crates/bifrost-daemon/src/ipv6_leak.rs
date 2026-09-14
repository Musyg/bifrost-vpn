//! Le vecteur `ipv6-leak` sous Windows: rien ne sort par IPv6 non plus.
//!
//! # Le piege propre a ce vecteur
//!
//! Un plan qui aurait oublie les couches V6 bloquerait parfaitement l'IPv4 et
//! laisserait l'IPv6 sortir. Toutes les autres mesures resteraient vertes: elles
//! sondent en IPv4. C'est la definition meme d'une panne silencieuse, et c'est
//! pour ca que ce vecteur existe.
//!
//! Le sonder demande un temoin negatif qui ABOUTIT en IPv6 avant l'armement.
//! Sans lui, un refus constate sous armement ne distingue pas un filtre qui
//! retient d'une machine qui n'a tout simplement pas d'IPv6 - et la seconde
//! lecture est la bonne sur la plupart des postes.
//!
//! # Deux portees de preuve, et elles ne valent pas la meme chose
//!
//! - **Globale**: la destination est une adresse unicast globale (`2000::/3`).
//!   La machine a une vraie route IPv6 vers l'exterieur, et ce qui est mesure
//!   est exactement la fuite que l'utilisateur pourrait subir.
//! - **Locale**: la destination est unique-locale ou lien-local. Les paquets
//!   sont de l'IPv6 authentique, evalues par les memes couches
//!   `ALE_AUTH_CONNECT_V6` et le meme plan, donc l'oubli des couches V6 est
//!   attrape aussi surement. Ce qui n'est PAS couvert: le chemin de sortie
//!   global, que cette machine n'a pas. Dire que les deux se valent serait
//!   faux, et ne rien mesurer en attendant mieux le serait aussi.
//!
//! La portee est deduite de l'adresse, jamais declaree par l'appelant: un
//! drapeau se met a mentir des qu'on change de cible.
//!
//! # Pourquoi ce vecteur ne peut pas ouvrir le reseau local
//!
//! Le plan permet `fc00::/7` et `fe80::/10` quand `allow_lan` est vrai - donc
//! exactement les adresses d'un temoin LOCAL. L'ouvrir rendrait la mesure verte
//! pour la mauvaise raison: la connexion passerait, et on lirait un permit
//! comme une fuite. La politique force donc `allow_lan` a faux des que la
//! portee est locale, et le dit: la machine perd son reseau local le temps de
//! la mesure, ce que les autres vecteurs evitaient.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use anyhow::anyhow;
use bifrost_core::ports::FirewallPolicy;
use bifrost_firewall::windows::WfpKillSwitch;

use crate::temoin_wfp;
use crate::wfp_identity::Issue;
use crate::wfp_leaktest;

/// Le journal d'audit n'est pas ecrit dans la foulee de la connexion.
const FENETRE: Duration = Duration::from_secs(60);
/// Le filtre dont on attend qu'il refuse.
const FILTRE_ATTENDU: &str = "block-all";

/// Ce que la destination permet d'etablir.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Portee {
    /// Unicast global: la fuite mesuree est celle que l'utilisateur subirait.
    Globale,
    /// Unique-locale ou lien-local: memes couches, meme plan, pas la route.
    Locale,
}

/// Deduit la portee d'une adresse IPv6.
///
/// `2000::/3` est le seul bloc unicast global attribue. Tout le reste - ULA,
/// lien-local, multicast, boucle locale - ne quitte pas le site, et une mesure
/// faite dessus ne peut pas parler d'une fuite vers l'exterieur.
pub fn portee(ip: Ipv6Addr) -> Portee {
    if (ip.segments()[0] & 0xe000) == 0x2000 {
        Portee::Globale
    } else {
        Portee::Locale
    }
}

/// Construit la politique du vecteur.
///
/// `lan` n'est honore que pour une portee globale: pour une portee locale, le
/// permit du reseau local couvrirait la destination meme, et la mesure dirait
/// le contraire de ce qu'elle annonce.
fn politique(portee: Portee, lan: bool) -> FirewallPolicy {
    FirewallPolicy {
        tunnel_interface: None,
        tunnel_luid: None,
        fwmark: None,
        dns_resolver: IpAddr::V4(Ipv4Addr::LOCALHOST),
        allow_lan: lan && portee == Portee::Globale,
        coeur_uid: None,
        coeur_executable: None,
        resolveur_uid: None,
        resolveur_executable: None,
        resolveur_sid: None,
        resolveur_embarque: false,
    }
}

/// Mesure le vecteur. Coupe le reseau entre l'armement et le desarmement.
pub fn selftest(cible: SocketAddr, lan: bool) -> anyhow::Result<()> {
    let ip = match cible.ip() {
        IpAddr::V6(v6) => v6,
        IpAddr::V4(_) => anyhow::bail!(
            "la cible doit etre une adresse IPv6: sonder en IPv4 mesurerait le \
             catch-all deja couvert par les autres vecteurs, et ne dirait rien \
             des couches V6"
        ),
    };
    let portee = portee(ip);
    let politique = politique(portee, lan);

    println!("vecteur ipv6-leak, cible {cible}");
    match portee {
        Portee::Globale => println!("  portee GLOBALE: la cible est une unicast globale"),
        Portee::Locale => println!(
            "  portee LOCALE: la cible ne quitte pas le site. Les couches V6 et \
             le plan sont eprouves a l'identique, le chemin de sortie global ne \
             l'est pas"
        ),
    }
    if lan && !politique.allow_lan {
        println!(
            "  reseau local FERME malgre --wfp-selftest-lan: son permit couvre \
             `fc00::/7` et `fe80::/10`, donc la cible elle-meme. L'ouvrir \
             rendrait la mesure verte pour la mauvaise raison"
        );
    }

    let mut firewall = WfpKillSwitch::new().map_err(|e| anyhow!("ouverture du moteur WFP: {e}"))?;
    let issue = wfp_leaktest::run(&mut firewall, &politique, cible)?;

    // L'attribution ne vaut que si la mesure a arme ET constate un refus.
    // Apres un `Ignore`, `run` a rendu la main avant d'armer: aucun filtre n'a
    // ete pose, et la chercher ferait accuser le plan d'avoir change alors que
    // la mesure s'est simplement abstenue. Observe en portee globale, ou le
    // temoin depend d'un tunnel instable.
    if wfp_leaktest::attribuable(&issue) {
        attribuer(&firewall, cible)?;
    }

    let mention = match portee {
        Portee::Globale => "aucune connexion IPv6 ne sort",
        Portee::Locale => {
            "aucune connexion IPv6 ne sort, portee LOCALE: les couches V6 \
             retiennent, le chemin de sortie global reste a eprouver sur une \
             machine qui en a un"
        }
    };
    match issue {
        Issue::Reussi => {
            println!("\nipv6-leak: PASSED - {mention}");
            Ok(())
        }
        Issue::Ignore(raison) => {
            println!("\nipv6-leak: SKIPPED - {raison}");
            Ok(())
        }
        Issue::Echec(raison) => Err(anyhow!("ipv6-leak: FAILED - {raison}")),
    }
}

/// Impute le refus au catch-all, nommement.
///
/// Appelee seulement quand la mesure a conclu: voir
/// [`wfp_leaktest::attribuable`].
fn attribuer(firewall: &WfpKillSwitch, cible: SocketAddr) -> anyhow::Result<()> {
    let attendus = firewall.filtres_nommes(FILTRE_ATTENDU);
    if attendus.is_empty() {
        anyhow::bail!("aucun filtre nomme `{FILTRE_ATTENDU}` n'a ete pose: le plan a change");
    }
    let constat = attendre(&attendus, cible)?;
    println!(
        "  journal d'audit: {} blocages WFP dans la fenetre, dont {} imputables a `{FILTRE_ATTENDU}`",
        constat.total,
        constat.notres.len()
    );

    if constat.audit_muet() {
        println!(
            "  attribution impossible: aucun blocage WFP dans le journal, pas \
             meme ceux du pare-feu Windows. A activer avec:\n{}",
            temoin_wfp::COMMANDE_ACTIVATION
        );
    } else {
        match constat.notres.first() {
            // La destination du blocage est l'adresse IPv6 sondee: c'est ce qui
            // etablit que le refus vient du chemin V6 et non d'un filtre IPv4
            // qui aurait coupe autre chose au meme moment.
            Some(b) => println!(
                "    filtre {} a la couche {}, destination IPv6 {:?}, application {}",
                b.filtre,
                b.couche,
                b.destination,
                b.application.rsplit('\\').next().unwrap_or("?")
            ),
            None => anyhow::bail!(
                "le refus vers {cible} n'est imputable a AUCUN filtre \
                 `{FILTRE_ATTENDU}` (filtres {attendus:?}). Il vient donc \
                 d'autre chose, et conclure que l'IPv6 est retenu serait une \
                 erreur"
            ),
        }
    }
    Ok(())
}

fn attendre(filtres: &[u64], cible: SocketAddr) -> anyhow::Result<temoin_wfp::Constat> {
    const PATIENCE: Duration = Duration::from_secs(20);
    const PAS: Duration = Duration::from_millis(500);

    let debut = std::time::Instant::now();
    let mut constat = temoin_wfp::constater(FENETRE, filtres, cible.ip(), cible.port())?;
    while constat.notres.is_empty() && debut.elapsed() < PATIENCE {
        std::thread::sleep(PAS);
        constat = temoin_wfp::constater(FENETRE, filtres, cible.ip(), cible.port())?;
    }
    Ok(constat)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v6(s: &str) -> Ipv6Addr {
        s.parse().unwrap()
    }

    #[test]
    fn seul_le_bloc_unicast_global_vaut_une_portee_globale() {
        assert_eq!(portee(v6("2606:4700:4700::1111")), Portee::Globale);
        assert_eq!(portee(v6("2001:db8::1")), Portee::Globale);
        // Tout ce qui suit ne quitte pas le site: une mesure faite dessus ne
        // peut pas parler d'une fuite vers l'exterieur.
        assert_eq!(portee(v6("fd00::1")), Portee::Locale);
        assert_eq!(portee(v6("fe80::1")), Portee::Locale);
        assert_eq!(portee(v6("ff02::1")), Portee::Locale);
        assert_eq!(portee(v6("::1")), Portee::Locale);
    }

    #[test]
    fn une_portee_locale_ferme_le_reseau_local_meme_si_on_le_demande() {
        // LE garde-fou de ce vecteur. Le permit du LAN couvre `fc00::/7` et
        // `fe80::/10`: laisser `allow_lan` a vrai avec une cible locale ferait
        // passer la connexion, et on lirait un permit comme une etancheite.
        assert!(!politique(Portee::Locale, true).allow_lan);
        assert!(politique(Portee::Globale, true).allow_lan);
        assert!(!politique(Portee::Globale, false).allow_lan);
    }

    #[test]
    fn une_cible_ipv4_est_refusee_avant_toute_coupure() {
        let e = selftest("1.1.1.1:443".parse().unwrap(), true).unwrap_err();
        assert!(format!("{e}").contains("IPv6"), "{e}");
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
            &politique(Portee::Globale, true),
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
