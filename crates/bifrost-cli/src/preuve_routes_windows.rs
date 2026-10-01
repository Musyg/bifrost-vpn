//! Routes et lignes d'interface: le plan du produit confronte a la table IP
//! Helper de Windows.
//!
//! `prove routes --intention F --actif` lit une intention de routage Windows
//! (chemin, interface, MTU, familles adressees, destinations), en tire le plan
//! que le produit pose (`bifrost_core::routage_windows::PlanWindows`, la meme
//! source que `wgnt::ipcfg::apply`), puis lit les tables IP Helper en passif
//! (`bifrost_firewall::windows::lecture_routes`), deux fois, et compare.
//! `prove routes --politique-daemon --actif` prend pour attendu le plan que le
//! peripherique du tunnel declare avoir pose (`declaration-routage-windows`),
//! lu par le lecteur commun des declarations. Aucune route, aucune adresse,
//! aucune interface n'est posee, retiree ou changee.
//!
//! # L'intention Windows v1
//!
//! Une intention distincte de celle de Linux, dont `fwmark` et `table` n'ont
//! pas de sens ici: exactement `schema_version` (1), `plateforme`
//! (`windows`), `chemin` (`wireguard` ou `coeur`), `interface` (la regle de
//! nom du produit), `mtu` (la plage du produit), `familles` (`ipv4`, `ipv6`,
//! dans cet ordre, sans doublon, au moins une) et `destinations` (WireGuard:
//! au moins un prefixe, chacun masque, ecrit sous sa forme canonique, sans
//! doublon; coeur: `null`). Lue avec les plafonds et le refus des cles
//! dupliquees de D1b.1, refusee avant toute lecture du systeme.
//!
//! # Comment Windows choisit
//!
//! Le prefixe le plus long gagne; a longueur egale, la metrique la plus
//! faible, qui est la SOMME de la metrique de la route et de celle de son
//! interface; a metrique egale, l'ordre de liaison en IPv4, un choix de la
//! pile en IPv6 (Microsoft Learn, "Chapter 10 - TCP/IP End-to-End Delivery" et
//! "MIB_IPFORWARD_ROW2", lus le 01/10/2026). Une egalite ne se decide donc pas
//! sur ce que la preuve lit: elle ne la compte ni pour le tunnel ni contre lui
//! (voir plus bas).
//!
//! # Ce qui est compare, famille par famille
//!
//! - `tunnel-interface-missing`: l'alias du tunnel ne designe aucune
//!   interface. Rien d'autre n'est alors compare.
//! - `<famille>-plan-route-missing`: une route du plan n'est pas sur
//!   l'interface du tunnel, a sa destination exacte, sur le lien.
//! - `<famille>-route-metric`: elle y est, avec une autre metrique.
//! - `<famille>-interface-metric`: le plan capture la famille (route par
//!   defaut), et la ligne d'interface du tunnel est absente, en metrique
//!   automatique, ou d'une autre metrique que zero.
//! - `<famille>-tunnel-extra-route`: une route du tunnel hors du plan, hors des
//!   classes admises ci-dessous, et qui n'est pas la diffusion dirigee d'une
//!   route IPv4 du plan (`plan_directed_broadcast`): avec une route IPv4 sur
//!   le lien, Windows cree la route hote de sa derniere adresse, sur la meme
//!   interface, et la retire avec elle. Mesure pour un `/24` seulement; la
//!   classe admet un prefixe de 1 a 30 bits, ceux qui ont une diffusion
//!   dirigee, sans que les autres longueurs aient ete posees.
//! - `<famille>-competing-route`: une route d'une AUTRE interface qui gagne,
//!   pour une destination du plan, contre la route du tunnel: prefixe plus
//!   long contenu dans celui du plan, ou meme prefixe a metrique effective
//!   inferieure, ou dont la metrique effective ne se lit pas. Hors des classes
//!   admises.
//!
//! Meme prefixe a metrique effective EGALE (`tied_routes_elsewhere`): ni
//! victoire ni defaite, la preuve ne lit pas ce qui departage. Hors des
//! classes admises et sans autre ecart, le verdict est UNMEASURED.
//!
//! La legitimite d'une route se decide par une regle de forme, pas par une
//! liste d'adresses, comme sous Linux. Admises:
//! - `local_delivery`: une route de l'interface de bouclage, ou la route hote
//!   d'une adresse portee par son interface;
//! - `connected`: une route sur le lien vers le reseau exact (adresse masquee et
//!   longueur, non nulle) d'une adresse portee par son interface;
//! - `own_network_host`: une route hote sur le lien vers une adresse du reseau
//!   d'une adresse de son interface (la diffusion du reseau, par exemple);
//! - `multicast_on_link`: une route sur le lien vers une destination de
//!   multidiffusion, LIMITE NOMMEE;
//! - `limited_broadcast`: `255.255.255.255/32` sur le lien, LIMITE NOMMEE.
//!
//! Tout le reste est un ecart (`other`): une route par une passerelle, un
//! `0.0.0.0/1`, un prefixe sur le lien hors du reseau de l'interface.
//!
//! Un ecart prime: s'il y en a un, MISMATCH. Une collecte impossible ou
//! instable, ou une egalite indecise, rend UNMEASURED, jamais une
//! correspondance. Le rapport ne porte que
//! des categories et des comptes: ni adresse, ni prefixe, ni interface, ni LUID.
#![cfg_attr(not(windows), allow(dead_code))]

use std::path::Path;
use std::time::Instant;

use bifrost_core::config::IpNet;
use bifrost_core::routage::Famille;
use bifrost_core::routage_windows::{
    AdresseLue, PlanWindows, RouteLue, TableIpHelper, contient, est_boucle_locale, masquer,
};
use bifrost_ipc::protocol::{
    CheminRoutage, DeclarationRoutageWindows, EtatRoutage, FamilleRoutage,
};
use serde::Serialize;
use serde_json::Value;

use crate::declaration::IdentiteDaemon;
use crate::preuve_nft::{Unique, heure};

#[cfg(test)]
mod recettes;

const LIMITE: &str = "Intention declaree, pas le profil actif atteste. Tables IP Helper (routes, lignes d'interface, adresses) des deux familles, lues deux fois de suite: un changement qui s'annule entre deux lectures echappe, et ce qui est pose apres la collecte n'est pas vu. Une route identique a celle du plan, posee par un tiers, passe pour celle du produit: Windows ne porte aucune etiquette de proprietaire sur une route. Deux limites de la regle de legitimite: une route connectee est admise quelle que soit la largeur du reseau de son adresse, et la multidiffusion et la diffusion limitee partent sur le lien. L'ordre de liaison qui departage deux metriques effectives egales n'est pas lu: une egalite rend UNMEASURED. Ne sont pas compares: la MTU et la detection d'adresse dupliquee des lignes, l'etat de connexion de l'interface, la duree de vie des routes, les adresses du tunnel. Ni les routes deja en cache, ni les connexions ouvertes, ni une source liee a une interface (modele d'hote fort), ni le pare-feu, ni le DNS ne sont prouves ici. Pas une preuve d'etancheite du VPN.";

const LIMITE_DAEMON: &str = "Plan declare par le peripherique du tunnel, relu avant et apres la collecte, pas observe: une correspondance dit que la table IP Helper porte le plan que le peripherique dit avoir pose. Tables lues deux fois de suite: un changement qui s'annule entre deux lectures echappe, et ce qui est pose apres la collecte n'est pas vu. Une route identique a celle du plan, posee par un tiers, passe pour celle du produit: Windows ne porte aucune etiquette de proprietaire sur une route. Deux limites de la regle de legitimite: une route connectee est admise quelle que soit la largeur du reseau de son adresse, et la multidiffusion et la diffusion limitee partent sur le lien. L'ordre de liaison qui departage deux metriques effectives egales n'est pas lu: une egalite rend UNMEASURED. Ne sont pas compares: la MTU et la detection d'adresse dupliquee des lignes, l'etat de connexion de l'interface, la duree de vie des routes, les adresses du tunnel. Ni les routes deja en cache, ni les connexions ouvertes, ni une source liee a une interface, ni le pare-feu, ni le DNS ne sont prouves ici. Pas une preuve d'etancheite du VPN.";

pub(crate) const INSTABLE: &str =
    "collecte instable: deux lectures consecutives des tables IP Helper different";

pub(crate) const EGALITE: &str = "egalite de metrique effective entre une route du plan et la route d'une autre interface: Windows departage par l'ordre de liaison en IPv4, par un choix de la pile en IPv6, que la preuve ne lit pas";

/// L'encadrement de la collecte: deux lectures completes, qui doivent etre
/// identiques. IP Helper n'a ni transaction ni numero de generation: c'est la
/// comparaison qui tient lieu de garde. Elle ne prouve pas qu'un instant a
/// porte exactement cet etat, seulement que deux lectures successives l'ont
/// rendu.
pub(crate) fn encadrer<L>(mut lire: L) -> Result<TableIpHelper, &'static str>
where
    L: FnMut() -> Result<TableIpHelper, &'static str>,
{
    let premiere = lire()?;
    let seconde = lire()?;
    if premiere != seconde {
        return Err(INSTABLE);
    }
    Ok(premiere)
}

// ---------------------------------------------------------------------------
// L'intention, la declaration, et le plan qu'elles designent.
// ---------------------------------------------------------------------------

const CLES: [&str; 7] = [
    "schema_version",
    "plateforme",
    "chemin",
    "interface",
    "mtu",
    "familles",
    "destinations",
];

const TYPES: &str = "types d'intention de routage invalides";

fn entier(v: &Value) -> Result<u32, &'static str> {
    v.as_u64().and_then(|n| u32::try_from(n).ok()).ok_or(TYPES)
}

/// Le chemin, tel que l'intention et la declaration le nomment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Chemin {
    WireGuard,
    Coeur,
}

/// Le plan Windows que designent un chemin, une interface, une MTU, des
/// familles et des destinations, rendu par le MEME constructeur que la pose
/// (`PlanWindows::wireguard`, `PlanWindows::coeur`). Commun a l'intention et a
/// la declaration: chacune n'a qu'a dire ces cinq valeurs.
///
/// Rejette ce que le produit ne pose pas: un nom d'interface hors de sa regle
/// (1 a 15 caracteres, alphanumeriques, `-` et `_`), une MTU hors de sa plage
/// (576 a 9000), des familles vides, dupliquees ou hors de l'ordre IPv4 puis
/// IPv6, des destinations absentes pour WireGuard ou presentes pour le coeur,
/// une destination non masquee ou en double.
pub(crate) fn plan_windows(
    chemin: Chemin,
    interface: &str,
    mtu: u32,
    familles: &[Famille],
    destinations: Option<&[IpNet]>,
) -> Result<PlanWindows, &'static str> {
    if interface.is_empty()
        || interface.len() > 15
        || !interface
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err("interface du plan de routage invalide");
    }
    if !(576..=9000).contains(&mtu) {
        return Err("MTU du plan de routage hors de la plage du produit");
    }
    if familles.is_empty() || !familles.windows(2).all(|p| p[0] < p[1]) {
        return Err("familles du plan de routage vides, en double ou hors d'ordre");
    }
    match (chemin, destinations) {
        (Chemin::WireGuard, Some(d)) if !d.is_empty() => {
            if d.iter().any(|n| masquer(n) != *n) {
                return Err("destination du plan de routage non masquee");
            }
            if d.iter().enumerate().any(|(i, n)| d[..i].contains(n)) {
                return Err("destination du plan de routage en double");
            }
            Ok(PlanWindows::wireguard(interface, familles, d, mtu))
        }
        (Chemin::WireGuard, _) => Err("chemin WireGuard: au moins une destination exigee"),
        (Chemin::Coeur, None) => Ok(PlanWindows::coeur(interface, familles, mtu)),
        (Chemin::Coeur, Some(_)) => Err("chemin par coeur: aucune destination dans le plan"),
    }
}

/// L'intention de routage Windows v1, lue strictement (voir l'en-tete).
pub fn plan_de_l_intention(v: Value) -> Result<PlanWindows, &'static str> {
    let objet = v.as_object().ok_or("intention de routage invalide")?;
    if objet.len() != CLES.len() || CLES.iter().any(|c| !objet.contains_key(*c)) {
        return Err("champs d'intention de routage manquants ou inconnus");
    }
    if entier(&objet["schema_version"])? != 1 {
        return Err("version d'intention de routage inconnue");
    }
    if objet["plateforme"].as_str().ok_or(TYPES)? != "windows" {
        return Err("intention de routage d'une autre plateforme");
    }
    let chemin = match objet["chemin"].as_str().ok_or(TYPES)? {
        "wireguard" => Chemin::WireGuard,
        "coeur" => Chemin::Coeur,
        _ => return Err("chemin d'intention de routage inconnu"),
    };
    let interface = objet["interface"].as_str().ok_or(TYPES)?;
    let mtu = entier(&objet["mtu"])?;
    let familles = objet["familles"]
        .as_array()
        .ok_or(TYPES)?
        .iter()
        .map(|f| match f.as_str() {
            Some("ipv4") => Ok(Famille::Ipv4),
            Some("ipv6") => Ok(Famille::Ipv6),
            _ => Err(TYPES),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let destinations = match &objet["destinations"] {
        Value::Null => None,
        Value::Array(liste) => Some(
            liste
                .iter()
                .map(|d| {
                    let texte = d.as_str().ok_or(TYPES)?;
                    let net: IpNet = texte
                        .parse()
                        .map_err(|_| "destination d'intention de routage illisible")?;
                    if net.to_string() != texte {
                        return Err(
                            "destination d'intention de routage hors de sa forme canonique",
                        );
                    }
                    Ok(net)
                })
                .collect::<Result<Vec<_>, _>>()?,
        ),
        _ => return Err(TYPES),
    };
    plan_windows(chemin, interface, mtu, &familles, destinations.as_deref())
}

/// Le plan que la declaration du peripherique designe, reconstruit par le meme
/// constructeur que la pose. La declaration a deja ete lue strictement (cles,
/// types, graphie, coherence) par `analyser_routage_windows`; il reste a juger
/// son contenu, comme celui d'une intention.
pub fn plan_de_la_declaration(d: &DeclarationRoutageWindows) -> Result<PlanWindows, &'static str> {
    match d.issue {
        EtatRoutage::NonApplicable => Err("le daemon ne declare pas de plan de routage"),
        EtatRoutage::Aucun => Err("aucun plan de routage pose par ce daemon: rien a comparer"),
        EtatRoutage::Pose => {
            let p = d
                .plan
                .as_ref()
                .ok_or("declaration de routage posee sans plan")?;
            let familles: Vec<Famille> = p
                .familles
                .iter()
                .map(|f| match f {
                    FamilleRoutage::Ipv4 => Famille::Ipv4,
                    FamilleRoutage::Ipv6 => Famille::Ipv6,
                })
                .collect();
            let chemin = match p.chemin {
                CheminRoutage::Wireguard => Chemin::WireGuard,
                CheminRoutage::Coeur => Chemin::Coeur,
            };
            plan_windows(
                chemin,
                &p.interface,
                p.mtu,
                &familles,
                p.destinations.as_deref(),
            )
        }
    }
}

// ---------------------------------------------------------------------------
// La comparaison.
// ---------------------------------------------------------------------------

/// Les categories d'ecart d'une famille, dans l'ordre ou le rapport les ecrit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Categorie {
    RouteDuPlanAbsente,
    MetriqueDeRoute,
    MetriqueDInterface,
    RouteEnTropSurLeTunnel,
    RouteConcurrente,
}

fn nom(f: Famille, c: Categorie) -> &'static str {
    match (f, c) {
        (Famille::Ipv4, Categorie::RouteDuPlanAbsente) => "ipv4-plan-route-missing",
        (Famille::Ipv4, Categorie::MetriqueDeRoute) => "ipv4-route-metric",
        (Famille::Ipv4, Categorie::MetriqueDInterface) => "ipv4-interface-metric",
        (Famille::Ipv4, Categorie::RouteEnTropSurLeTunnel) => "ipv4-tunnel-extra-route",
        (Famille::Ipv4, Categorie::RouteConcurrente) => "ipv4-competing-route",
        (Famille::Ipv6, Categorie::RouteDuPlanAbsente) => "ipv6-plan-route-missing",
        (Famille::Ipv6, Categorie::MetriqueDeRoute) => "ipv6-route-metric",
        (Famille::Ipv6, Categorie::MetriqueDInterface) => "ipv6-interface-metric",
        (Famille::Ipv6, Categorie::RouteEnTropSurLeTunnel) => "ipv6-tunnel-extra-route",
        (Famille::Ipv6, Categorie::RouteConcurrente) => "ipv6-competing-route",
    }
}

const INTERFACE_ABSENTE: &str = "tunnel-interface-missing";

/// Comptes attendus d'une famille.
#[derive(Debug, Default, Serialize, PartialEq, Eq)]
pub(crate) struct Attendus {
    plan_routes: usize,
    /// Le plan capture la famille: metrique d'interface a zero, automatique
    /// coupee.
    interface_metric_forced: bool,
}

/// Ce que la regle de legitimite dit d'un ensemble de routes, classe par
/// classe (voir l'en-tete du module).
#[derive(Debug, Default, Serialize, PartialEq, Eq)]
pub(crate) struct Jugees {
    local_delivery: usize,
    connected: usize,
    own_network_host: usize,
    /// Limite nommee: comptee, admise.
    multicast_on_link: usize,
    /// Limite nommee: comptee, admise.
    limited_broadcast: usize,
    /// La diffusion dirigee d'une route IPv4 du plan, sur le tunnel seulement:
    /// toujours nulle pour les routes des autres interfaces.
    plan_directed_broadcast: usize,
    /// Aucune des classes admises: chacune est un ecart.
    other: usize,
}

/// Comptes observes d'une famille. `null` pour ce qui n'a pas pu etre juge
/// faute d'interface du tunnel.
#[derive(Debug, Default, Serialize, PartialEq, Eq)]
pub(crate) struct Observes {
    routes: usize,
    interfaces: usize,
    tunnel_routes: Option<usize>,
    plan_routes_found: Option<usize>,
    /// Les routes du tunnel hors du plan, jugees.
    tunnel_other_routes: Option<Jugees>,
    /// Les routes d'autres interfaces qui gagnent pour une destination du
    /// plan, jugees.
    winning_routes_elsewhere: Option<Jugees>,
    /// Les routes d'autres interfaces a egalite de metrique effective avec la
    /// route du plan de meme prefixe, jugees.
    tied_routes_elsewhere: Option<Jugees>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub(crate) struct ParFamille<T> {
    ipv4: T,
    ipv6: T,
}

enum Classe {
    LivraisonLocale,
    Connectee,
    HoteDuReseau,
    MultidiffusionSurLeLien,
    DiffusionLimitee,
    Autre,
}

fn multidiffusion(n: &IpNet) -> bool {
    match n.addr {
        std::net::IpAddr::V4(a) => n.prefix_len >= 4 && a.octets()[0] & 0xf0 == 0xe0,
        std::net::IpAddr::V6(a) => n.prefix_len >= 8 && a.octets()[0] == 0xff,
    }
}

fn pleine(n: &IpNet) -> u8 {
    if n.is_ipv4() { 32 } else { 128 }
}

/// La diffusion dirigee d'un prefixe IPv4 de 1 a 30 bits: sa derniere adresse,
/// en route hote. Ni le `/0`, dont la derniere adresse est la diffusion
/// limitee, ni les `/31` et `/32`, qui n'en ont pas; rien en IPv6. Ces bornes
/// sont celles de la definition: la route que Windows cree n'est mesuree que
/// pour un `/24`.
fn diffusion_dirigee(n: &IpNet) -> Option<IpNet> {
    match n.addr {
        std::net::IpAddr::V4(a) if (1..=30).contains(&n.prefix_len) => Some(IpNet {
            addr: std::net::IpAddr::V4((u32::from(a) | (u32::MAX >> n.prefix_len)).into()),
            prefix_len: 32,
        }),
        _ => None,
    }
}

/// La regle de legitimite, appliquee a une route (voir l'en-tete du module).
fn classer(r: &RouteLue, adresses: &[AdresseLue]) -> Classe {
    if est_boucle_locale(r.interface) {
        return Classe::LivraisonLocale;
    }
    // Par une passerelle: emise hors du lien, vers un tiers.
    if r.prochain_saut.is_some() {
        return Classe::Autre;
    }
    let d = &r.destination;
    // Les adresses portees par l'interface de la route. Une adresse de l'autre
    // famille ne satisfait aucune des comparaisons qui suivent: egalite,
    // reseau masque et contenance distinguent deja les familles.
    let du_lien = || adresses.iter().filter(|a| a.interface == r.interface);
    if d.prefix_len == pleine(d) && du_lien().any(|a| a.adresse.addr == d.addr) {
        return Classe::LivraisonLocale;
    }
    // Le reseau d'une adresse de longueur nulle couvrirait toute la famille:
    // il ne rend rien legitime.
    if d.prefix_len > 0
        && du_lien()
            .any(|a| a.adresse.prefix_len == d.prefix_len && masquer(&a.adresse) == masquer(d))
    {
        return Classe::Connectee;
    }
    if d.prefix_len == pleine(d)
        && du_lien().any(|a| a.adresse.prefix_len > 0 && contient(&masquer(&a.adresse), d))
    {
        return Classe::HoteDuReseau;
    }
    if multidiffusion(d) {
        return Classe::MultidiffusionSurLeLien;
    }
    if d.is_ipv4() && d.prefix_len == 32 && d.addr == std::net::IpAddr::from([255u8; 4]) {
        return Classe::DiffusionLimitee;
    }
    Classe::Autre
}

fn juger(classe: Classe, j: &mut Jugees) {
    match classe {
        Classe::LivraisonLocale => j.local_delivery += 1,
        Classe::Connectee => j.connected += 1,
        Classe::HoteDuReseau => j.own_network_host += 1,
        Classe::MultidiffusionSurLeLien => j.multicast_on_link += 1,
        Classe::DiffusionLimitee => j.limited_broadcast += 1,
        Classe::Autre => j.other += 1,
    }
}

/// La comparaison d'une famille, l'interface du tunnel etant presente. Les
/// ecarts sont ajoutes a `ecarts`.
fn comparer_famille(
    plan: &PlanWindows,
    f: Famille,
    t: &TableIpHelper,
    tunnel: u64,
    ecarts: &mut Vec<&'static str>,
) -> (Attendus, Observes) {
    let attendues = plan.routes(f);
    let ligne_du_plan = plan.ligne(f);
    let routes: Vec<&RouteLue> = t.routes.iter().filter(|r| r.famille() == f).collect();
    let du_tunnel: Vec<&RouteLue> = routes
        .iter()
        .copied()
        .filter(|r| r.interface == tunnel)
        .collect();
    let ligne_du_tunnel = t
        .lignes
        .iter()
        .find(|l| l.interface == tunnel && l.famille == f);
    // La route du tunnel qui porte une destination du plan: a sa destination
    // exacte, sur le lien, comme la pose la cree.
    let route_du_plan = |destination: &IpNet| {
        du_tunnel
            .iter()
            .copied()
            .find(|r| r.destination == *destination && r.prochain_saut.is_none())
    };

    let attendus = Attendus {
        plan_routes: attendues.len(),
        interface_metric_forced: ligne_du_plan.is_some_and(|l| l.metrique_imposee().is_some()),
    };
    let mut o = Observes {
        routes: routes.len(),
        interfaces: t.lignes.iter().filter(|l| l.famille == f).count(),
        tunnel_routes: Some(du_tunnel.len()),
        ..Observes::default()
    };

    // 1. Les routes du plan, et leur metrique.
    let mut absente = false;
    let mut metrique = false;
    let mut trouvees = 0;
    for a in &attendues {
        match route_du_plan(&a.destination) {
            None => absente = true,
            Some(r) => {
                trouvees += 1;
                if r.metrique != a.metrique {
                    metrique = true;
                }
            }
        }
    }
    o.plan_routes_found = Some(trouvees);
    if absente {
        ecarts.push(nom(f, Categorie::RouteDuPlanAbsente));
    }
    if metrique {
        ecarts.push(nom(f, Categorie::MetriqueDeRoute));
    }

    // 2. La ligne d'une famille capturee: metrique imposee, automatique coupee.
    if let Some(imposee) = ligne_du_plan.and_then(|l| l.metrique_imposee())
        && !ligne_du_tunnel.is_some_and(|l| !l.metrique_automatique && l.metrique == imposee)
    {
        ecarts.push(nom(f, Categorie::MetriqueDInterface));
    }

    // 3. Ce que le tunnel porte en plus du plan. La diffusion dirigee d'une
    // route du plan est celle que Windows cree avec elle: sur le lien, sur le
    // tunnel, a la derniere adresse d'une destination du plan.
    let mut en_trop = Jugees::default();
    for r in &du_tunnel {
        let sur_le_lien = r.prochain_saut.is_none();
        if sur_le_lien && attendues.iter().any(|a| a.destination == r.destination) {
            continue;
        }
        if sur_le_lien
            && attendues
                .iter()
                .any(|a| diffusion_dirigee(&a.destination) == Some(r.destination))
        {
            en_trop.plan_directed_broadcast += 1;
        } else {
            juger(classer(r, &t.adresses), &mut en_trop);
        }
    }
    if en_trop.other > 0 {
        ecarts.push(nom(f, Categorie::RouteEnTropSurLeTunnel));
    }
    o.tunnel_other_routes = Some(en_trop);

    // 4. Les routes des autres interfaces qui gagnent pour une destination du
    // plan. Contre la route du plan la plus specifique qui les contient: plus
    // long, l'autre gagne toujours; meme prefixe, la metrique effective
    // (route + interface) departage. Une metrique qui ne se lit pas est une
    // victoire de l'autre; une egalite n'est ni une victoire ni une defaite.
    let metrique_du_tunnel = ligne_du_tunnel.map(|l| u64::from(l.metrique));
    let mut gagnantes = Jugees::default();
    let mut egales = Jugees::default();
    for r in routes.iter().filter(|r| r.interface != tunnel) {
        let Some(p) = attendues
            .iter()
            .filter(|a| contient(&a.destination, &r.destination))
            .max_by_key(|a| a.destination.prefix_len)
        else {
            continue;
        };
        let issue = if r.destination.prefix_len > p.destination.prefix_len {
            Some(true)
        } else {
            let effective_du_tunnel = route_du_plan(&p.destination)
                .map(|rt| u64::from(rt.metrique))
                .zip(metrique_du_tunnel)
                .map(|(a, b)| a + b);
            let effective_de_l_autre = t
                .lignes
                .iter()
                .find(|l| l.interface == r.interface && l.famille == f)
                .map(|l| u64::from(r.metrique) + u64::from(l.metrique));
            match (effective_de_l_autre, effective_du_tunnel) {
                (Some(autre), Some(tunnel)) if autre == tunnel => None,
                (Some(autre), Some(tunnel)) => Some(autre < tunnel),
                _ => Some(true),
            }
        };
        match issue {
            Some(true) => juger(classer(r, &t.adresses), &mut gagnantes),
            None => juger(classer(r, &t.adresses), &mut egales),
            Some(false) => {}
        }
    }
    if gagnantes.other > 0 {
        ecarts.push(nom(f, Categorie::RouteConcurrente));
    }
    o.winning_routes_elsewhere = Some(gagnantes);
    o.tied_routes_elsewhere = Some(egales);
    (attendus, o)
}

/// Ce que la comparaison rend: comptes attendus, comptes observes, ecarts.
pub(crate) type Comparaison = (
    ParFamille<Attendus>,
    ParFamille<Observes>,
    Vec<&'static str>,
);

/// La comparaison entiere: les deux familles, les ecarts dans un ordre fixe.
/// Sans interface du tunnel, un seul ecart, et seuls les comptes de la table.
pub(crate) fn comparer(plan: &PlanWindows, t: &TableIpHelper) -> Comparaison {
    let mut ecarts = Vec::new();
    let Some(tunnel) = t.tunnel else {
        let attendus = |f| Attendus {
            plan_routes: plan.routes(f).len(),
            interface_metric_forced: plan
                .ligne(f)
                .is_some_and(|l| l.metrique_imposee().is_some()),
        };
        let observes = |f| Observes {
            routes: t.routes.iter().filter(|r| r.famille() == f).count(),
            interfaces: t.lignes.iter().filter(|l| l.famille == f).count(),
            ..Observes::default()
        };
        return (
            ParFamille {
                ipv4: attendus(Famille::Ipv4),
                ipv6: attendus(Famille::Ipv6),
            },
            ParFamille {
                ipv4: observes(Famille::Ipv4),
                ipv6: observes(Famille::Ipv6),
            },
            vec![INTERFACE_ABSENTE],
        );
    };
    let (a4, o4) = comparer_famille(plan, Famille::Ipv4, t, tunnel, &mut ecarts);
    let (a6, o6) = comparer_famille(plan, Famille::Ipv6, t, tunnel, &mut ecarts);
    (
        ParFamille { ipv4: a4, ipv6: a6 },
        ParFamille { ipv4: o4, ipv6: o6 },
        ecarts,
    )
}

// ---------------------------------------------------------------------------
// Le rapport.
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct Rapport {
    schema_version: u32,
    scope: &'static str,
    verdict: &'static str,
    started_at_unix_ms: Option<u128>,
    completed_at_unix_ms: Option<u128>,
    duration_ms: u128,
    /// La collecte de cet hote: `iphelper-tables-read-twice`.
    source: Option<&'static str>,
    expected_source: &'static str,
    intention_schema_version: Option<u32>,
    live_kernel: bool,
    collection_verified: bool,
    network_security: &'static str,
    /// Le nom de la regle qui a admis le serveur de la declaration, en mode
    /// daemon; absent en mode intention. Jamais un SID ni un pid.
    #[serde(skip_serializing_if = "IdentiteDaemon::hors_perimetre")]
    daemon_identity: IdentiteDaemon,
    tunnel_interface_present: Option<bool>,
    expected_counts: Option<ParFamille<Attendus>>,
    observed_counts: Option<ParFamille<Observes>>,
    differences: Vec<&'static str>,
    failed_input: Option<&'static str>,
    reason: &'static str,
    limitation: &'static str,
}

impl Rapport {
    pub fn code(&self) -> i32 {
        match self.verdict {
            "MATCH" => 0,
            "MISMATCH" => 1,
            _ => 2,
        }
    }

    pub fn texte(&self) -> String {
        format!(
            "{}  {}\n{}\n{}entree non mesuree: {}\necarts: {}\n\n{}\n",
            self.verdict,
            self.scope,
            self.reason,
            self.daemon_identity.ligne(),
            self.failed_input.unwrap_or("aucune"),
            self.differences.join(", "),
            self.limitation
        )
    }
}

fn commencer() -> Rapport {
    Rapport {
        schema_version: 1,
        scope: "windows-routing-comparison",
        verdict: "UNMEASURED",
        started_at_unix_ms: heure(),
        completed_at_unix_ms: None,
        duration_ms: 0,
        source: Some("iphelper-tables-read-twice"),
        expected_source: "bifrost-windows-routing-plan-v1-user-declared",
        intention_schema_version: None,
        live_kernel: false,
        collection_verified: false,
        network_security: "not-evaluated",
        daemon_identity: IdentiteDaemon::HorsPerimetre,
        tunnel_interface_present: None,
        expected_counts: None,
        observed_counts: None,
        differences: Vec::new(),
        failed_input: Some("intention"),
        reason: "intention de routage illisible ou non prise en charge",
        limitation: LIMITE,
    }
}

/// Inscrit la comparaison au rapport. Sans ecart, une egalite hors des classes
/// admises laisse le verdict non mesure, et sa raison est rendue.
fn conclure(r: &mut Rapport, plan: &PlanWindows, t: &TableIpHelper) -> Result<(), &'static str> {
    r.live_kernel = true;
    r.collection_verified = true;
    r.tunnel_interface_present = Some(t.tunnel.is_some());
    let (attendus, observes, ecarts) = comparer(plan, t);
    let indecise = [&observes.ipv4, &observes.ipv6].iter().any(|o| {
        o.tied_routes_elsewhere
            .as_ref()
            .is_some_and(|j| j.other > 0)
    });
    r.expected_counts = Some(attendus);
    r.observed_counts = Some(observes);
    if ecarts.is_empty() && indecise {
        return Err(EGALITE);
    }
    r.failed_input = None;
    r.verdict = if ecarts.is_empty() {
        "MATCH"
    } else {
        "MISMATCH"
    };
    r.differences = ecarts;
    Ok(())
}

/// La preuve, separee de sa collecte pour que les recettes la jouent avec une
/// fausse lecture des tables. `lire` recoit l'alias de l'interface du tunnel et
/// rend UNE lecture complete; l'encadrement (deux lectures identiques) est
/// fait ici, apres que l'intention a ete lue et validee.
pub(crate) fn verifier_avec<L>(intention: &Path, mut lire: L) -> Rapport
where
    L: FnMut(&str) -> Result<TableIpHelper, &'static str>,
{
    let debut = Instant::now();
    let mut r = commencer();
    let resultat = (|| {
        let Unique(v) = serde_json::from_slice(&crate::preuve_nft::lire(intention)?)
            .map_err(|_| "intention de routage JSON invalide ou ambigue")?;
        let plan = plan_de_l_intention(v)?;
        r.intention_schema_version = Some(1);
        r.failed_input = Some("observed");
        let table = encadrer(|| lire(&plan.interface))?;
        conclure(&mut r, &plan, &table)
    })();
    r.reason = match resultat {
        Ok(()) => {
            "routes et lignes d'interface des deux familles comparees au plan du produit; seules les valeurs d'etat des routes sont ignorees"
        }
        Err(raison) => raison,
    };
    r.completed_at_unix_ms = heure();
    r.duration_ms = debut.elapsed().as_millis();
    r
}

/// Une lecture des tables de cet hote, ses refus nommes sans code.
#[cfg(windows)]
fn lire_hote(alias: &str) -> Result<TableIpHelper, &'static str> {
    use bifrost_firewall::windows::lecture_routes::{Refus, lire_une_fois};
    lire_une_fois(alias).map_err(|e| match e {
        Refus::Alias(_) => "interface du tunnel non resolue par IP Helper",
        Refus::Routes(_) => "table des routes IP Helper refusee",
        Refus::Interfaces(_) => "table des lignes d'interface IP Helper refusee",
        Refus::Adresses(_) => "table des adresses IP Helper refusee",
        Refus::Tronquee => "donnees IP Helper tronquees ou hors bornes",
    })
}

/// `prove routes --intention F --actif`, sous Windows.
#[cfg(windows)]
pub fn verifier(intention: &Path) -> Rapport {
    verifier_avec(intention, lire_hote)
}

// ---------------------------------------------------------------------------
// Mode face au daemon.
// ---------------------------------------------------------------------------

impl crate::declaration::Suivi for Rapport {
    fn entree_manquante(&mut self, entree: &'static str) {
        self.failed_input = Some(entree);
    }
    fn identite(&mut self, identite: IdentiteDaemon) {
        self.daemon_identity = identite;
    }
}

/// Le rapport de depart du mode daemon, avant toute lecture.
fn commencer_declaration() -> Rapport {
    let mut r = commencer();
    r.expected_source = "daemon-declared-active-routing-plan";
    r.daemon_identity = IdentiteDaemon::NonVerifiee;
    r.failed_input = Some("daemon-declaration");
    r.reason = "declaration de routage du daemon non lue";
    r.limitation = LIMITE_DAEMON;
    r
}

/// Le protocole, separe de ses deux sources pour que les recettes le jouent
/// avec un faux daemon et une fausse lecture des tables: N1, la mesure
/// encadree (deux lectures identiques), N2, par le protocole commun des
/// preuves par declaration (`declaration::encadrer`), avec son exigence
/// d'identite et ce qu'il en dit au rapport.
pub(crate) async fn verifier_declaration_avec<L, FL, C>(
    lire_declaration: L,
    lire_table: C,
) -> Rapport
where
    L: FnMut() -> FL,
    FL: std::future::Future<
            Output = Result<crate::declaration::LueRoutageWindows, crate::declaration::Refus>,
        >,
    C: Fn(&str) -> Result<TableIpHelper, &'static str> + Copy,
{
    let debut = Instant::now();
    let mut r = commencer_declaration();
    let resultat = async {
        let (plan, table) = crate::declaration::encadrer(
            &mut r,
            lire_declaration,
            plan_de_la_declaration,
            async move |r: &mut Rapport, plan: PlanWindows| {
                r.failed_input = Some("observed");
                let table = encadrer(|| lire_table(&plan.interface))?;
                Ok((plan, table))
            },
        )
        .await?;
        conclure(&mut r, &plan, &table)
    }
    .await;
    r.reason = match resultat {
        Ok(()) => {
            "routes et lignes d'interface des deux familles comparees au plan declare par le peripherique"
        }
        Err(raison) => raison,
    };
    r.completed_at_unix_ms = heure();
    r.duration_ms = debut.elapsed().as_millis();
    r
}

/// `prove routes --politique-daemon --actif`, sous Windows: l'attendu est le
/// plan que le peripherique du tunnel joint par `socket` declare avoir pose,
/// lu aupres d'un serveur admis par la regle des preuves (le pipe de
/// LocalSystem), relu avant et apres la collecte.
#[cfg(windows)]
pub async fn verifier_declaration(socket: &str) -> Rapport {
    verifier_declaration_avec(
        move || crate::declaration::lire_routage_windows(socket),
        lire_hote,
    )
    .await
}
