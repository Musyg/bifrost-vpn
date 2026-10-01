//! Recettes de `prove routes` sous Windows, sans privilege et sur les deux
//! hotes. Le plan vient du constructeur meme de la pose (`PlanWindows`, par
//! l'intention), les tables IP Helper sont fabriquees comme le lecteur les
//! rend, puis alterees comme un tiers ou une panne les altererait. Le daemon
//! est une suite de trames lues par le vrai lecteur strict
//! (`analyser_routage_windows`), servie par un serveur admis. Deux recettes,
//! Windows seulement, tiennent les occurrences reelles: la lecture de
//! production face a un pipe qui n'est pas celui de LocalSystem, et la lecture
//! reelle des tables de l'hote.

use super::*;
use crate::declaration::{
    CLES_ROUTAGE, HORS_SCHEMA, LueRoutageWindows, PLAN_WINDOWS_CLES, Refus,
    analyser_routage_windows,
};
use bifrost_core::routage_windows::LigneLue;
use bifrost_ipc::ServerRule;
use bifrost_ipc::protocol::{
    DECLARATION_ROUTAGE_VERSION, DECLARATION_ROUTAGE_WINDOWS_VERSION, DeclarationRoutage,
    PlanRoutage, PlanRoutageWindows, Response,
};
use serde_json::json;
use std::cell::Cell;
use std::io::Write;
use std::path::PathBuf;

const V4: Famille = Famille::Ipv4;
const V6: Famille = Famille::Ipv6;

/// Les LUID des recettes. Le type d'interface est dans les bits 48 a 63: 53
/// (virtuelle, celui de Wintun), 6 (Ethernet), 71 (Wi-Fi), 24 (bouclage).
const TUNNEL: u64 = 0x0035_0000_0000_1000;
const LAN: u64 = 0x0006_0000_0000_2000;
const AUTRE: u64 = 0x0047_0000_0000_3000;
const BOUCLE: u64 = 0x0018_0000_0000_0001;

/// La metrique que Windows donne aux routes qu'il cree pour une adresse.
const METRIQUE_SYSTEME: u32 = 256;

fn net(texte: &str) -> IpNet {
    texte.parse().unwrap()
}

/// Une route sur le lien, comme Windows la cree pour une adresse.
fn route(interface: u64, destination: &str) -> RouteLue {
    RouteLue {
        interface,
        destination: net(destination),
        prochain_saut: None,
        metrique: METRIQUE_SYSTEME,
    }
}

fn par(mut r: RouteLue, saut: &str) -> RouteLue {
    r.prochain_saut = Some(saut.parse().unwrap());
    r
}

fn a_metrique(mut r: RouteLue, metrique: u32) -> RouteLue {
    r.metrique = metrique;
    r
}

fn ligne(interface: u64, famille: Famille, metrique: u32, automatique: bool) -> LigneLue {
    LigneLue {
        interface,
        famille,
        metrique,
        metrique_automatique: automatique,
    }
}

fn adresse(interface: u64, a: &str) -> AdresseLue {
    AdresseLue {
        interface,
        adresse: net(a),
    }
}

/// L'hote sans tunnel: un lien physique (passerelle par defaut, reseau
/// connecte, adresse, diffusion, multidiffusion), une seconde interface sans
/// route, et le bouclage, dans les deux familles.
fn hote() -> TableIpHelper {
    TableIpHelper {
        tunnel: None,
        adresses: vec![
            adresse(LAN, "203.0.113.10/24"),
            adresse(LAN, "fe80::abcd/64"),
            adresse(LAN, "2001:db8:aaaa::10/64"),
            adresse(BOUCLE, "127.0.0.1/8"),
            adresse(BOUCLE, "::1/128"),
        ],
        routes: vec![
            a_metrique(par(route(LAN, "0.0.0.0/0"), "203.0.113.1"), 0),
            route(LAN, "203.0.113.0/24"),
            route(LAN, "203.0.113.10/32"),
            route(LAN, "203.0.113.255/32"),
            route(LAN, "224.0.0.0/4"),
            route(LAN, "255.255.255.255/32"),
            a_metrique(par(route(LAN, "::/0"), "fe80::1"), 0),
            route(LAN, "fe80::/64"),
            route(LAN, "fe80::abcd/128"),
            route(LAN, "2001:db8:aaaa::/64"),
            route(LAN, "2001:db8:aaaa::10/128"),
            route(LAN, "ff00::/8"),
            route(BOUCLE, "127.0.0.0/8"),
            route(BOUCLE, "127.0.0.1/32"),
            route(BOUCLE, "127.255.255.255/32"),
            route(BOUCLE, "224.0.0.0/4"),
            route(BOUCLE, "255.255.255.255/32"),
            route(BOUCLE, "::1/128"),
            route(BOUCLE, "ff00::/8"),
        ],
        lignes: vec![
            ligne(LAN, V4, 25, true),
            ligne(LAN, V6, 25, true),
            ligne(AUTRE, V4, 35, true),
            ligne(AUTRE, V6, 35, true),
            ligne(BOUCLE, V4, 75, true),
            ligne(BOUCLE, V6, 75, true),
        ],
    }
}

/// La derniere adresse d'un prefixe IPv4 de 1 a 30 bits, calculee bit a bit,
/// independamment de la preuve.
fn derniere_adresse(n: &IpNet) -> Option<IpNet> {
    let std::net::IpAddr::V4(a) = n.addr else {
        return None;
    };
    if !(1..=30).contains(&n.prefix_len) {
        return None;
    }
    let mut octets = a.octets();
    for bit in usize::from(n.prefix_len)..32 {
        octets[bit / 8] |= 0x80 >> (bit % 8);
    }
    Some(IpNet {
        addr: octets.into(),
        prefix_len: 32,
    })
}

/// Ce que la pose du plan laisse sur l'hote: l'interface du tunnel, ses routes
/// a leur metrique et la diffusion dirigee que Windows cree avec chaque route
/// IPv4 (mesure sur un `/24`), sa ligne par famille adressee (imposee si la
/// famille est capturee, automatique sinon), ses adresses et les routes que
/// Windows cree pour elles.
fn pose(t: &mut TableIpHelper, plan: &PlanWindows) {
    t.tunnel = Some(TUNNEL);
    for r in &plan.routes {
        t.routes.push(RouteLue {
            interface: TUNNEL,
            destination: r.destination,
            prochain_saut: None,
            metrique: r.metrique,
        });
        if let Some(diffusion) = derniere_adresse(&r.destination) {
            t.routes.push(RouteLue {
                interface: TUNNEL,
                destination: diffusion,
                prochain_saut: None,
                metrique: METRIQUE_SYSTEME,
            });
        }
    }
    for l in &plan.lignes {
        t.lignes.push(match l.metrique_imposee() {
            Some(m) => ligne(TUNNEL, l.famille, m, false),
            None => ligne(TUNNEL, l.famille, 5, true),
        });
    }
    if plan.ligne(V4).is_some() {
        t.adresses.push(adresse(TUNNEL, "192.0.2.2/32"));
        t.routes.extend([
            route(TUNNEL, "192.0.2.2/32"),
            route(TUNNEL, "224.0.0.0/4"),
            route(TUNNEL, "255.255.255.255/32"),
        ]);
    }
    if plan.ligne(V6).is_some() {
        t.adresses.extend([
            adresse(TUNNEL, "2001:db8:ffff::2/128"),
            adresse(TUNNEL, "fe80::d1c/64"),
        ]);
        t.routes.extend([
            route(TUNNEL, "2001:db8:ffff::2/128"),
            route(TUNNEL, "fe80::/64"),
            route(TUNNEL, "fe80::d1c/128"),
            route(TUNNEL, "ff00::/8"),
        ]);
    }
}

const WG: &str = r#"{"schema_version":1,"plateforme":"windows","chemin":"wireguard","interface":"bfwg0","mtu":1420,"familles":["ipv4","ipv6"],"destinations":["198.51.100.0/24","2001:db8:d1c::/48"]}"#;
const COEUR: &str = r#"{"schema_version":1,"plateforme":"windows","chemin":"coeur","interface":"bftun0","mtu":1280,"familles":["ipv4","ipv6"],"destinations":null}"#;

fn plan(texte: &str) -> PlanWindows {
    plan_de_l_intention(serde_json::from_str(texte).unwrap()).unwrap()
}

fn plan_wg() -> PlanWindows {
    plan(WG)
}

fn plan_coeur() -> PlanWindows {
    plan(COEUR)
}

fn posee(p: &PlanWindows) -> TableIpHelper {
    let mut t = hote();
    pose(&mut t, p);
    t
}

fn ecarts(p: &PlanWindows, t: &TableIpHelper) -> Vec<&'static str> {
    comparer(p, t).2
}

fn retirer(t: &mut TableIpHelper, interface: u64, destination: &str) {
    let d = net(destination);
    let avant = t.routes.len();
    t.routes
        .retain(|r| !(r.interface == interface && r.destination == d));
    assert_eq!(
        avant,
        t.routes.len() + 1,
        "{destination} absente de la table"
    );
}

fn ligne_de(t: &mut TableIpHelper, interface: u64, f: Famille) -> &mut LigneLue {
    t.lignes
        .iter_mut()
        .find(|l| l.interface == interface && l.famille == f)
        .unwrap()
}

fn route_de<'t>(t: &'t mut TableIpHelper, interface: u64, destination: &str) -> &'t mut RouteLue {
    let d = net(destination);
    t.routes
        .iter_mut()
        .find(|r| r.interface == interface && r.destination == d)
        .unwrap()
}

// --- la comparaison ------------------------------------------------------------

/// Des comptes juges, dans l'ordre des champs: livraison locale, connectee,
/// hote du reseau, multidiffusion, diffusion limitee, diffusion dirigee d'une
/// route du plan, autre.
fn jugees(n: [usize; 7]) -> Value {
    json!({"local_delivery": n[0], "connected": n[1], "own_network_host": n[2],
           "multicast_on_link": n[3], "limited_broadcast": n[4],
           "plan_directed_broadcast": n[5], "other": n[6]})
}

/// Le plan pose, dans chaque chemin: correspondance. Les comptes juges sont
/// exacts: chaque classe admise a son occurrence, et rien d'autre ne passe.
#[test]
fn le_plan_pose_correspond_dans_les_deux_chemins() {
    let rien = jugees([0; 7]);
    let p = plan_wg();
    let (attendus, observes, e) = comparer(&p, &posee(&p));
    assert!(e.is_empty(), "{e:?}");
    assert_eq!(
        serde_json::to_value(&attendus).unwrap(),
        json!({
            "ipv4": {"plan_routes": 1, "interface_metric_forced": false},
            "ipv6": {"plan_routes": 1, "interface_metric_forced": false}
        })
    );
    // La diffusion dirigee de la route IPv4 du plan est sur le tunnel, et
    // rien d'une autre interface n'est dans les destinations du plan.
    assert_eq!(
        serde_json::to_value(&observes).unwrap(),
        json!({
            "ipv4": {
                "routes": 16, "interfaces": 4, "tunnel_routes": 5, "plan_routes_found": 1,
                "tunnel_other_routes": jugees([1, 0, 0, 1, 1, 1, 0]),
                "winning_routes_elsewhere": rien,
                "tied_routes_elsewhere": rien
            },
            "ipv6": {
                "routes": 13, "interfaces": 4, "tunnel_routes": 5, "plan_routes_found": 1,
                "tunnel_other_routes": jugees([2, 1, 0, 1, 0, 0, 0]),
                "winning_routes_elsewhere": rien,
                "tied_routes_elsewhere": rien
            }
        })
    );

    let p = plan_coeur();
    let (attendus, observes, e) = comparer(&p, &posee(&p));
    assert!(e.is_empty(), "{e:?}");
    assert_eq!(
        serde_json::to_value(&attendus).unwrap(),
        json!({
            "ipv4": {"plan_routes": 1, "interface_metric_forced": true},
            "ipv6": {"plan_routes": 1, "interface_metric_forced": true}
        })
    );
    // Le `/0` n'a pas de diffusion dirigee: sa derniere adresse est la
    // diffusion limitee, deja sur chaque interface.
    assert_eq!(
        serde_json::to_value(&observes).unwrap(),
        json!({
            "ipv4": {
                "routes": 15, "interfaces": 4, "tunnel_routes": 4, "plan_routes_found": 1,
                "tunnel_other_routes": jugees([1, 0, 0, 1, 1, 0, 0]),
                "winning_routes_elsewhere": jugees([6, 1, 1, 1, 1, 0, 0]),
                "tied_routes_elsewhere": rien
            },
            "ipv6": {
                "routes": 13, "interfaces": 4, "tunnel_routes": 5, "plan_routes_found": 1,
                "tunnel_other_routes": jugees([2, 1, 0, 1, 0, 0, 0]),
                "winning_routes_elsewhere": jugees([4, 2, 0, 1, 0, 0, 0]),
                "tied_routes_elsewhere": rien
            }
        })
    );
}

/// La diffusion dirigee admise est celle d'une route IPv4 du plan, sur le
/// lien du tunnel, a la derniere adresse exacte d'un prefixe de 1 a 30 bits.
/// Chaque cas ajoute (ou deplace) UNE route.
#[test]
fn la_diffusion_dirigee_d_une_route_du_plan_est_admise_sur_le_tunnel() {
    let p = plan_wg();
    // La pose porte la sienne; sans elle, rien ne manque: elle est admise,
    // pas exigee.
    let mut t = posee(&p);
    retirer(&mut t, TUNNEL, "198.51.100.255/32");
    assert!(ecarts(&p, &t).is_empty());

    type Changer = fn(&mut TableIpHelper);
    let cas: Vec<(&str, Changer, &[&str])> = vec![
        (
            "par une passerelle",
            |t| {
                route_de(t, TUNNEL, "198.51.100.255/32").prochain_saut =
                    Some("192.0.2.1".parse().unwrap())
            },
            &["ipv4-tunnel-extra-route"],
        ),
        (
            "une autre adresse du prefixe",
            |t| t.routes.push(route(TUNNEL, "198.51.100.254/32")),
            &["ipv4-tunnel-extra-route"],
        ),
        (
            "la derniere adresse d'un prefixe hors du plan",
            |t| t.routes.push(route(TUNNEL, "198.51.101.255/32")),
            &["ipv4-tunnel-extra-route"],
        ),
        (
            "la derniere adresse du prefixe IPv6 du plan",
            |t| {
                t.routes
                    .push(route(TUNNEL, "2001:db8:d1c:ffff:ffff:ffff:ffff:ffff/128"))
            },
            &["ipv6-tunnel-extra-route"],
        ),
        (
            "sur une autre interface",
            |t| t.routes.push(route(LAN, "198.51.100.255/32")),
            &["ipv4-competing-route"],
        ),
    ];
    for (nom, changer, attendus) in cas {
        let mut t = posee(&p);
        changer(&mut t);
        assert_eq!(ecarts(&p, &t), attendus, "{nom}");
    }

    // Les bornes: un `/30` en a une, un `/31` n'en a pas.
    let wg = |destination: &str| {
        plan(&format!(
            r#"{{"schema_version":1,"plateforme":"windows","chemin":"wireguard","interface":"bfwg0","mtu":1420,"familles":["ipv4"],"destinations":["{destination}"]}}"#
        ))
    };
    let p = wg("198.51.100.4/30");
    let t = posee(&p);
    assert!(
        t.routes
            .iter()
            .any(|r| r.destination == net("198.51.100.7/32")),
        "la pose porte la diffusion du /30"
    );
    assert!(ecarts(&p, &t).is_empty());
    let p = wg("198.51.100.4/31");
    let mut t = posee(&p);
    assert_eq!(t.routes.len(), hote().routes.len() + 4);
    t.routes.push(route(TUNNEL, "198.51.100.5/32"));
    assert_eq!(ecarts(&p, &t), ["ipv4-tunnel-extra-route"]);
}

/// Une route du plan absente du tunnel est l'ecart de sa seule famille. Pour
/// le coeur, sans sa route par defaut, celle du lien physique gagne: l'ecart
/// de la route concurrente s'y ajoute, et c'est la verite.
#[test]
fn une_route_du_plan_absente_est_un_ecart_de_sa_famille() {
    let p = plan_wg();
    let mut t = posee(&p);
    retirer(&mut t, TUNNEL, "198.51.100.0/24");
    assert_eq!(ecarts(&p, &t), ["ipv4-plan-route-missing"]);
    let mut t = posee(&p);
    retirer(&mut t, TUNNEL, "2001:db8:d1c::/48");
    assert_eq!(ecarts(&p, &t), ["ipv6-plan-route-missing"]);

    let p = plan_coeur();
    let mut t = posee(&p);
    retirer(&mut t, TUNNEL, "0.0.0.0/0");
    assert_eq!(
        ecarts(&p, &t),
        ["ipv4-plan-route-missing", "ipv4-competing-route"]
    );
    let mut t = posee(&p);
    retirer(&mut t, TUNNEL, "::/0");
    assert_eq!(
        ecarts(&p, &t),
        ["ipv6-plan-route-missing", "ipv6-competing-route"]
    );
}

/// La route du plan doit etre sur le lien, comme la pose la cree: par une
/// passerelle, elle n'est pas celle du plan, et elle est en trop.
#[test]
fn une_route_du_plan_par_une_passerelle_n_est_pas_celle_du_plan() {
    let p = plan_wg();
    let mut t = posee(&p);
    route_de(&mut t, TUNNEL, "198.51.100.0/24").prochain_saut = Some("192.0.2.1".parse().unwrap());
    assert_eq!(
        ecarts(&p, &t),
        ["ipv4-plan-route-missing", "ipv4-tunnel-extra-route"]
    );
}

/// Une metrique de route autre que celle du plan est un ecart. Pour le coeur,
/// une metrique qui egale la metrique effective du lien physique en fait une
/// egalite, comptee, et qui depasse la sienne le fait gagner.
#[test]
fn une_metrique_de_route_autre_est_un_ecart() {
    let p = plan_wg();
    let mut t = posee(&p);
    route_de(&mut t, TUNNEL, "2001:db8:d1c::/48").metrique = 7;
    assert_eq!(ecarts(&p, &t), ["ipv6-route-metric"]);

    let p = plan_coeur();
    let mut t = posee(&p);
    route_de(&mut t, TUNNEL, "0.0.0.0/0").metrique = 7;
    assert_eq!(ecarts(&p, &t), ["ipv4-route-metric"]);
    // 25 + 0 contre 0 + 25: egalite.
    route_de(&mut t, TUNNEL, "0.0.0.0/0").metrique = 25;
    let (_, o, e) = comparer(&p, &t);
    assert_eq!(e, ["ipv4-route-metric"]);
    assert_eq!(o.ipv4.tied_routes_elsewhere.unwrap().other, 1);
    // 26 + 0 contre 0 + 25: le lien physique gagne.
    route_de(&mut t, TUNNEL, "0.0.0.0/0").metrique = 26;
    assert_eq!(
        ecarts(&p, &t),
        ["ipv4-route-metric", "ipv4-competing-route"]
    );
}

/// La ligne d'une famille capturee porte la metrique imposee, automatique
/// coupee. Absente, automatique ou d'une autre metrique: un ecart. Pour une
/// famille non capturee (WireGuard sans route par defaut), la ligne n'est pas
/// jugee.
#[test]
fn la_ligne_d_une_famille_capturee_est_imposee() {
    let p = plan_coeur();
    let mut t = posee(&p);
    ligne_de(&mut t, TUNNEL, V4).metrique = 1;
    assert_eq!(ecarts(&p, &t), ["ipv4-interface-metric"]);

    let mut t = posee(&p);
    ligne_de(&mut t, TUNNEL, V6).metrique_automatique = true;
    assert_eq!(ecarts(&p, &t), ["ipv6-interface-metric"]);

    // Sans ligne, la metrique effective du tunnel ne se lit pas: la route
    // par defaut du lien physique gagne.
    let mut t = posee(&p);
    t.lignes
        .retain(|l| !(l.interface == TUNNEL && l.famille == V4));
    assert_eq!(
        ecarts(&p, &t),
        ["ipv4-interface-metric", "ipv4-competing-route"]
    );

    // A 25, le tunnel egale le lien physique; a 26, il perd.
    let mut t = posee(&p);
    ligne_de(&mut t, TUNNEL, V6).metrique = 25;
    assert_eq!(ecarts(&p, &t), ["ipv6-interface-metric"]);
    ligne_de(&mut t, TUNNEL, V6).metrique = 26;
    assert_eq!(
        ecarts(&p, &t),
        ["ipv6-interface-metric", "ipv6-competing-route"]
    );

    let p = plan_wg();
    let mut t = posee(&p);
    ligne_de(&mut t, TUNNEL, V4).metrique = 1;
    ligne_de(&mut t, TUNNEL, V6).metrique_automatique = false;
    assert!(ecarts(&p, &t).is_empty());
}

/// Ce que le tunnel porte hors du plan et hors des classes admises est un
/// ecart: une moitie de l'espace, un prefixe sur le lien hors du reseau de ses
/// adresses, une route par une passerelle.
#[test]
fn une_route_en_trop_sur_le_tunnel_est_un_ecart() {
    let p = plan_wg();
    for (famille, r) in [
        ("ipv4", a_metrique(route(TUNNEL, "0.0.0.0/1"), 0)),
        ("ipv4", route(TUNNEL, "10.0.0.0/8")),
        ("ipv4", par(route(TUNNEL, "192.0.2.77/32"), "192.0.2.1")),
        ("ipv6", route(TUNNEL, "2000::/3")),
        (
            "ipv6",
            par(route(TUNNEL, "2001:db8:ffff::7/128"), "fe80::1"),
        ),
    ] {
        let mut t = posee(&p);
        t.routes.push(r);
        assert_eq!(
            ecarts(&p, &t),
            [format!("{famille}-tunnel-extra-route")],
            "{r:?}"
        );
    }
}

/// Une route d'une autre interface qui gagne pour une destination du plan:
/// plus longue, ou de meme longueur a metrique effective inferieure, ou dont
/// la metrique ne se lit pas. Plus chere, elle perd, et n'est rien; a egalite,
/// elle n'est pas un ecart, elle est comptee a part.
#[test]
fn une_route_d_une_autre_interface_qui_gagne_est_un_ecart() {
    let p = plan_wg();
    let concurrente = |t: &mut TableIpHelper| {
        t.routes.push(a_metrique(
            par(route(LAN, "198.51.100.0/24"), "203.0.113.1"),
            0,
        ));
    };

    // Plus longue, par une passerelle.
    let mut t = posee(&p);
    t.routes
        .push(par(route(AUTRE, "198.51.100.128/25"), "198.18.0.1"));
    assert_eq!(ecarts(&p, &t), ["ipv4-competing-route"]);

    // Plus longue, sur le lien, hors du reseau de toute adresse.
    let mut t = posee(&p);
    t.routes.push(route(AUTRE, "2001:db8:d1c:8000::/49"));
    assert_eq!(ecarts(&p, &t), ["ipv6-competing-route"]);

    // Meme prefixe: 0 + 25 contre 0 + 5, le tunnel gagne.
    let mut t = posee(&p);
    concurrente(&mut t);
    assert!(ecarts(&p, &t).is_empty());
    // 0 + 6 contre 0 + 5: le tunnel gagne encore.
    ligne_de(&mut t, LAN, V4).metrique = 6;
    let (_, o, e) = comparer(&p, &t);
    assert!(e.is_empty());
    assert_eq!(o.ipv4.tied_routes_elsewhere.unwrap().other, 0);
    // 0 + 5 contre 0 + 5: egalite, ni l'un ni l'autre.
    ligne_de(&mut t, LAN, V4).metrique = 5;
    let (_, o, e) = comparer(&p, &t);
    assert!(e.is_empty());
    assert_eq!(
        serde_json::to_value(&o.ipv4.tied_routes_elsewhere).unwrap(),
        jugees([0, 0, 0, 0, 0, 0, 1])
    );
    assert_eq!(o.ipv4.winning_routes_elsewhere.unwrap().other, 0);
    // 0 + 4 contre 0 + 5.
    ligne_de(&mut t, LAN, V4).metrique = 4;
    assert_eq!(ecarts(&p, &t), ["ipv4-competing-route"]);

    // La metrique de l'autre interface ne se lit pas: elle gagne.
    let mut t = posee(&p);
    concurrente(&mut t);
    t.lignes
        .retain(|l| !(l.interface == LAN && l.famille == V4));
    assert_eq!(ecarts(&p, &t), ["ipv4-competing-route"]);
}

/// La route du plan qui compte est la plus specifique de celles qui contiennent
/// la concurrente: contre un `/16` du plan, un `/24` d'ailleurs serait plus
/// long; contre le `/24` du plan, il est de meme longueur, et plus cher.
#[test]
fn la_concurrente_se_juge_contre_la_route_du_plan_la_plus_specifique() {
    let p = plan(
        r#"{"schema_version":1,"plateforme":"windows","chemin":"wireguard","interface":"bfwg0","mtu":1420,"familles":["ipv4"],"destinations":["198.51.0.0/16","198.51.100.0/24"]}"#,
    );
    let mut t = posee(&p);
    assert!(ecarts(&p, &t).is_empty());
    t.routes.push(a_metrique(
        par(route(LAN, "198.51.100.0/24"), "203.0.113.1"),
        0,
    ));
    assert!(ecarts(&p, &t).is_empty());
    t.routes.push(a_metrique(
        par(route(LAN, "198.51.7.0/24"), "203.0.113.1"),
        0,
    ));
    assert_eq!(ecarts(&p, &t), ["ipv4-competing-route"]);
}

/// La regle de legitimite, classe par classe, sur l'occurrence ou elle decide:
/// le coeur prend tout, toute route d'une autre interface est donc jugee.
/// Chaque cas ajoute UNE route (ou adresse) a la pose conforme.
#[test]
fn la_regle_de_legitimite_decide_par_la_forme() {
    let p = plan_coeur();
    type Changer = fn(&mut TableIpHelper);
    let cas: Vec<(&str, Changer, &[&str])> = vec![
        // Admises.
        (
            "hote du reseau du lien",
            |t| t.routes.push(route(LAN, "203.0.113.77/32")),
            &[],
        ),
        (
            "bouclage sans adresse lue",
            |t| {
                t.adresses.retain(|a| a.interface != BOUCLE);
                t.routes.push(route(BOUCLE, "127.0.0.0/9"));
            },
            &[],
        ),
        (
            "adresse a prefixe nul, sa route hote",
            |t| {
                t.adresses.push(adresse(LAN, "198.18.0.1/0"));
                t.routes.push(route(LAN, "198.18.0.1/32"));
            },
            &[],
        ),
        // Ecarts.
        (
            "hote du reseau du lien par une passerelle",
            |t| {
                t.routes
                    .push(par(route(LAN, "203.0.113.77/32"), "203.0.113.1"))
            },
            &["ipv4-competing-route"],
        ),
        (
            "prefixe sur le lien hors du reseau du lien",
            |t| t.routes.push(route(LAN, "198.51.100.0/24")),
            &["ipv4-competing-route"],
        ),
        (
            "hote dans le reseau d'une adresse a prefixe nul",
            |t| {
                t.adresses.push(adresse(LAN, "198.18.0.1/0"));
                t.routes.push(route(LAN, "198.51.100.7/32"));
            },
            &["ipv4-competing-route"],
        ),
        (
            "multidiffusion trop large",
            |t| t.routes.push(route(LAN, "224.0.0.0/3")),
            &["ipv4-competing-route"],
        ),
        (
            "multidiffusion IPv6 trop large, non masquee",
            |t| t.routes.push(route(LAN, "ff00::/7")),
            &["ipv6-competing-route"],
        ),
        (
            "diffusion d'un autre reseau",
            |t| t.routes.push(route(LAN, "198.51.100.255/32")),
            &["ipv4-competing-route"],
        ),
        (
            "reseau d'une adresse d'une autre interface",
            |t| t.routes.push(route(AUTRE, "203.0.113.0/24")),
            &["ipv4-competing-route"],
        ),
    ];
    for (nom, changer, attendus) in cas {
        let mut t = posee(&p);
        changer(&mut t);
        assert_eq!(ecarts(&p, &t), attendus, "{nom}");
    }

    // Le reseau d'une adresse a prefixe nul: une route `/0` sur le lien, a
    // 0 + 0 comme celle du tunnel. La metrique effective ne descend pas
    // au-dessous: l'occurrence est une egalite, jugee hors des classes
    // admises, jamais connectee.
    let mut t = posee(&p);
    t.adresses.push(adresse(LAN, "198.18.0.1/0"));
    retirer(&mut t, LAN, "0.0.0.0/0");
    t.routes.push(a_metrique(route(LAN, "0.0.0.0/0"), 0));
    ligne_de(&mut t, LAN, V4).metrique = 0;
    let (_, o, e) = comparer(&p, &t);
    assert!(e.is_empty(), "{e:?}");
    assert_eq!(
        serde_json::to_value(&o.ipv4.tied_routes_elsewhere).unwrap(),
        jugees([0, 0, 0, 0, 0, 0, 1])
    );
}

/// Sans interface du tunnel, un seul ecart, et seuls les comptes de la table:
/// rien n'est juge contre une interface qui n'existe pas, meme quand ses routes
/// restent sous un autre LUID.
#[test]
fn sans_interface_du_tunnel_un_seul_ecart() {
    for p in [plan_wg(), plan_coeur()] {
        let mut t = posee(&p);
        t.tunnel = None;
        let (attendus, observes, e) = comparer(&p, &t);
        assert_eq!(e, [INTERFACE_ABSENTE]);
        assert_eq!(attendus.ipv4.plan_routes, 1);
        let o = serde_json::to_value(&observes).unwrap();
        for f in ["ipv4", "ipv6"] {
            assert!(o[f]["routes"].as_u64().unwrap() > 0);
            for cle in [
                "tunnel_routes",
                "plan_routes_found",
                "tunnel_other_routes",
                "winning_routes_elsewhere",
                "tied_routes_elsewhere",
            ] {
                assert!(o[f][cle].is_null(), "{f} {cle}: {o}");
            }
        }
    }
}

/// L'ordre des ecarts est fixe: IPv4 puis IPv6, et dans chaque famille l'ordre
/// des categories.
#[test]
fn les_ecarts_ont_un_ordre_fixe() {
    let p = plan_wg();
    let mut t = posee(&p);
    t.routes.push(route(AUTRE, "2001:db8:d1c::/64"));
    route_de(&mut t, TUNNEL, "2001:db8:d1c::/48").metrique = 9;
    t.routes.push(route(TUNNEL, "10.0.0.0/8"));
    retirer(&mut t, TUNNEL, "198.51.100.0/24");
    assert_eq!(
        ecarts(&p, &t),
        [
            "ipv4-plan-route-missing",
            "ipv4-tunnel-extra-route",
            "ipv6-route-metric",
            "ipv6-competing-route"
        ]
    );
}

// --- l'intention, l'encadrement et le rapport ------------------------------------

struct Fichier(PathBuf);

impl Fichier {
    fn nouveau(contenu: &str) -> Self {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static N: AtomicUsize = AtomicUsize::new(0);
        let p = std::env::temp_dir().join(format!(
            "bifrost-routes-windows-{}-{}.json",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(contenu.as_bytes()).unwrap();
        Self(p)
    }
}

impl Drop for Fichier {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// La preuve jouee avec une fausse lecture des tables; rend le rapport et le
/// nombre de lectures.
fn rapport(lectures: Vec<Result<TableIpHelper, &'static str>>, texte: &str) -> (Rapport, usize) {
    let f = Fichier::nouveau(texte);
    let mut lectures = lectures.into_iter();
    let mut appels = 0;
    let r = verifier_avec(&f.0, |_alias| {
        appels += 1;
        lectures.next().expect("lecture de trop")
    });
    (r, appels)
}

#[test]
fn deux_lectures_identiques_font_une_mesure() {
    let t = posee(&plan_wg());
    let f = Fichier::nouveau(WG);
    let mut alias = Vec::new();
    let r = verifier_avec(&f.0, |a| {
        alias.push(a.to_owned());
        Ok(t.clone())
    });
    assert_eq!(
        alias,
        ["bfwg0", "bfwg0"],
        "l'alias lu est celui de l'intention"
    );
    assert_eq!(r.verdict, "MATCH");
    assert_eq!(r.code(), 0);
    assert!(r.live_kernel && r.collection_verified);
    assert_eq!(r.failed_input, None);
    assert_eq!(r.tunnel_interface_present, Some(true));
    assert_eq!(r.intention_schema_version, Some(1));
    assert_eq!(r.scope, "windows-routing-comparison");
    assert_eq!(r.source, Some("iphelper-tables-read-twice"));
    assert_eq!(
        r.expected_source,
        "bifrost-windows-routing-plan-v1-user-declared"
    );

    // L'alias vient de l'intention, pas d'une valeur par defaut.
    let t = posee(&plan_coeur());
    let f = Fichier::nouveau(COEUR);
    let mut alias = Vec::new();
    let r = verifier_avec(&f.0, |a| {
        alias.push(a.to_owned());
        Ok(t.clone())
    });
    assert_eq!(alias, ["bftun0", "bftun0"]);
    assert_eq!(r.verdict, "MATCH");

    let mut t = posee(&plan_coeur());
    t.tunnel = None;
    let (r, _) = rapport(vec![Ok(t.clone()), Ok(t)], COEUR);
    assert_eq!(r.verdict, "MISMATCH");
    assert_eq!(r.code(), 1);
    assert_eq!(r.differences, [INTERFACE_ABSENTE]);
    assert_eq!(r.tunnel_interface_present, Some(false));
}

/// Deux lectures differentes ne sont jamais une mesure, meme quand chacune
/// correspondrait; une lecture refusee non plus.
#[test]
fn deux_lectures_differentes_ne_sont_jamais_une_mesure() {
    let p = plan_wg();
    let une = posee(&p);
    let mut autre = une.clone();
    autre.routes.push(route(LAN, "203.0.113.78/32"));
    assert!(ecarts(&p, &autre).is_empty(), "chacune correspondrait");
    let (r, appels) = rapport(vec![Ok(une), Ok(autre)], WG);
    assert_eq!((r.verdict, appels), ("UNMEASURED", 2));
    assert_eq!(r.code(), 2);
    assert_eq!(r.reason, INSTABLE);
    assert_eq!(r.failed_input, Some("observed"));
    assert!(!r.live_kernel && !r.collection_verified);
    assert!(r.expected_counts.is_none() && r.observed_counts.is_none());

    let (r, appels) = rapport(vec![Err("table des routes IP Helper refusee")], WG);
    assert_eq!((r.verdict, appels), ("UNMEASURED", 1));
    assert_eq!(r.reason, "table des routes IP Helper refusee");
    assert_eq!(r.failed_input, Some("observed"));
}

/// La route du lien physique a egalite de metrique effective avec la route
/// IPv4 du plan WireGuard: 0 + 5 contre 0 + 5.
fn a_egalite() -> TableIpHelper {
    let mut t = posee(&plan_wg());
    t.routes.push(a_metrique(
        par(route(LAN, "198.51.100.0/24"), "203.0.113.1"),
        0,
    ));
    ligne_de(&mut t, LAN, V4).metrique = 5;
    t
}

/// Une egalite hors des classes admises, sans autre ecart, n'est pas une
/// mesure: Windows la departage par ce que la preuve ne lit pas. Un ecart
/// prime; une egalite admise (la route connectee d'une adresse du lien) ne
/// suspend rien.
#[test]
fn une_egalite_indecise_n_est_pas_mesuree() {
    let t = a_egalite();
    let (r, appels) = rapport(vec![Ok(t.clone()), Ok(t.clone())], WG);
    assert_eq!((r.verdict, appels), ("UNMEASURED", 2));
    assert_eq!(r.code(), 2);
    assert_eq!(r.reason, EGALITE);
    assert_eq!(r.failed_input, Some("observed"));
    assert!(r.differences.is_empty());
    assert!(r.live_kernel && r.collection_verified);
    let o = serde_json::to_value(&r.observed_counts).unwrap();
    assert_eq!(o["ipv4"]["tied_routes_elsewhere"]["other"], 1);
    assert_eq!(o["ipv6"]["tied_routes_elsewhere"]["other"], 0);

    let mut avec_ecart = t;
    avec_ecart.routes.push(route(TUNNEL, "10.0.0.0/8"));
    let (r, _) = rapport(vec![Ok(avec_ecart.clone()), Ok(avec_ecart)], WG);
    assert_eq!(r.verdict, "MISMATCH");
    assert_eq!(r.differences, ["ipv4-tunnel-extra-route"]);
    assert_eq!(r.failed_input, None);

    let mut admise = posee(&plan_wg());
    admise.adresses.push(adresse(LAN, "198.51.100.9/24"));
    admise
        .routes
        .push(a_metrique(route(LAN, "198.51.100.0/24"), 0));
    ligne_de(&mut admise, LAN, V4).metrique = 5;
    let (r, _) = rapport(vec![Ok(admise.clone()), Ok(admise)], WG);
    assert_eq!(r.verdict, "MATCH", "{}", r.reason);
    let o = serde_json::to_value(&r.observed_counts).unwrap();
    assert_eq!(
        o["ipv4"]["tied_routes_elsewhere"],
        jugees([0, 1, 0, 0, 0, 0, 0])
    );
}

fn variante(cle: &str, valeur: Value) -> String {
    let mut v: Value = serde_json::from_str(WG).unwrap();
    v[cle] = valeur;
    v.to_string()
}

/// L'intention est lue et validee AVANT toute lecture des tables.
#[test]
fn une_intention_invalide_ne_lit_pas_les_tables() {
    let mut textes: Vec<String> = vec![
        String::new(),
        "[]".into(),
        "{}".into(),
        // La forme de Linux.
        r#"{"schema_version":1,"chemin":"wireguard","interface":"bfwg0","fwmark":777001,"table":30303,"coeur_uid":null}"#.into(),
        // Cle dupliquee.
        WG.replacen("\"mtu\":1420", "\"mtu\":1420,\"mtu\":1420", 1),
        // Au-dela du plafond de taille.
        format!("{}{WG}", " ".repeat(2 * 1024 * 1024)),
    ];
    for cle in CLES {
        let mut v: Value = serde_json::from_str(WG).unwrap();
        v.as_object_mut().unwrap().remove(cle);
        textes.push(v.to_string());
    }
    let mut v: Value = serde_json::from_str(WG).unwrap();
    v.as_object_mut().unwrap().insert("x".into(), json!(1));
    textes.push(v.to_string());
    for (cle, valeur) in [
        ("schema_version", json!(2)),
        ("schema_version", json!("1")),
        ("schema_version", json!(1.0)),
        ("plateforme", json!("linux")),
        ("plateforme", Value::Null),
        ("chemin", json!("autre")),
        ("interface", json!("")),
        ("interface", json!("a b")),
        ("interface", json!("bf.wg0")),
        ("interface", json!("bfwg0bfwg0bfwg0x")),
        ("interface", json!(7)),
        ("mtu", json!(575)),
        ("mtu", json!(9001)),
        ("mtu", json!(1420.5)),
        ("mtu", json!("1420")),
        ("mtu", json!(4_294_968_716u64)),
        ("familles", json!([])),
        ("familles", json!(["ipv6", "ipv4"])),
        ("familles", json!(["ipv4", "ipv4"])),
        ("familles", json!(["ipv5"])),
        ("familles", json!([4])),
        ("familles", json!("ipv4")),
        ("destinations", Value::Null),
        ("destinations", json!([])),
        ("destinations", json!("198.51.100.0/24")),
        ("destinations", json!(["198.51.100.1/24"])),
        (
            "destinations",
            json!(["198.51.100.0/24", "198.51.100.0/24"]),
        ),
        (
            "destinations",
            json!(["198.51.100.0/24", "198.51.100.7/24"]),
        ),
        ("destinations", json!(["198.51.100.0/024"])),
        ("destinations", json!(["198.51.100.0/+24"])),
        ("destinations", json!(["2001:0db8:d1c::/48"])),
        ("destinations", json!(["198.51.100.0"])),
        ("destinations", json!(["198.51.100.0/33"])),
        ("destinations", json!([5])),
    ] {
        textes.push(variante(cle, valeur));
    }
    let mut coeur: Value = serde_json::from_str(COEUR).unwrap();
    for valeur in [json!(["0.0.0.0/0"]), json!([])] {
        coeur["destinations"] = valeur;
        textes.push(coeur.to_string());
    }
    for texte in &textes {
        let (r, appels) = rapport(vec![], texte);
        let court = &texte[texte.len().saturating_sub(200)..];
        assert_eq!((r.verdict, appels), ("UNMEASURED", 0), "{court}");
        assert_eq!(r.failed_input, Some("intention"), "{court}");
        assert!(!r.live_kernel && r.intention_schema_version.is_none());
    }
}

/// Les formes admises d'une intention: l'ordre des cles est libre, une seule
/// famille fait un plan, et les bornes du produit sont incluses.
#[test]
fn une_intention_valide_se_lit_dans_ses_formes_admises() {
    let texte = r#"{"destinations":["198.51.100.0/24"],"familles":["ipv4"],"mtu":576,"interface":"bf-wg_0","chemin":"wireguard","plateforme":"windows","schema_version":1}"#;
    let p = plan(texte);
    let (r, appels) = rapport(vec![Ok(posee(&p)); 2], texte);
    assert_eq!((r.verdict, appels), ("MATCH", 2), "{}", r.reason);
    let p = plan(
        &COEUR
            .replace(r#"["ipv4","ipv6"]"#, r#"["ipv6"]"#)
            .replace("1280", "9000"),
    );
    assert_eq!(p.familles(), [V6]);
    assert_eq!(p.routes.len(), 1);
    assert_eq!(p.mtu, 9000);
}

/// Le rapport ne dit que des categories et des comptes: ni interface, ni
/// adresse, ni prefixe, ni LUID; et ses cles sont celles-ci, pas une de plus.
#[test]
fn le_rapport_n_exporte_ni_adresse_ni_interface_ni_luid() {
    let p = plan_wg();
    let mut t = posee(&p);
    t.routes
        .push(par(route(AUTRE, "198.51.100.128/25"), "198.18.0.1"));
    t.routes.push(route(TUNNEL, "10.0.0.0/8"));
    route_de(&mut t, TUNNEL, "2001:db8:d1c::/48").metrique = 9;
    let (r, _) = rapport(vec![Ok(t.clone()), Ok(t)], WG);
    assert_eq!(r.verdict, "MISMATCH");
    let mut v = serde_json::to_value(&r).unwrap();
    let cles: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
    let mut attendues = vec![
        "schema_version",
        "scope",
        "verdict",
        "started_at_unix_ms",
        "completed_at_unix_ms",
        "duration_ms",
        "source",
        "expected_source",
        "intention_schema_version",
        "live_kernel",
        "collection_verified",
        "network_security",
        "tunnel_interface_present",
        "expected_counts",
        "observed_counts",
        "differences",
        "failed_input",
        "reason",
        "limitation",
    ];
    let mut cles = cles;
    cles.sort_unstable();
    attendues.sort_unstable();
    assert_eq!(cles, attendues);
    for cle in ["started_at_unix_ms", "completed_at_unix_ms", "duration_ms"] {
        v.as_object_mut().unwrap().remove(cle);
    }
    let texte = format!("{v}{}", r.texte());
    for interdit in [
        "bfwg0",
        "198.51",
        "198.18",
        "2001:db8",
        "203.0.113",
        "192.0.2",
        "10.0.0",
        "fe80",
        "1420",
    ]
    .into_iter()
    .map(str::to_owned)
    .chain(
        [TUNNEL, LAN, AUTRE, BOUCLE]
            .into_iter()
            .flat_map(|l| [l.to_string(), format!("{l:x}")]),
    ) {
        assert!(!texte.contains(&interdit), "le rapport exporte {interdit}");
    }
}

// --- mode daemon: le protocole et la reconstruction du plan ---------------------
//
// Le lecteur de production (`declaration::lire_routage_windows`) et le
// protocole (`declaration::encadrer`) sont communs a `prove nft/wfp`, qui en
// tiennent le tronc. Ce qui est propre au routage Windows - l'analyse stricte
// de sa reponse (`analyser_routage_windows`), la reconstruction du plan
// (`plan_de_la_declaration`) et son cablage dans `verifier_declaration_avec` -
// est tenu ici, sur les tables FABRIQUEES ci-dessus. L'identite exigee du pipe,
// sur son occurrence reelle, a sa recette Windows plus bas.

const INSTANCE: &str = "0123456789abcdef0123456789abcdef0123456789abcdef";

/// La regle que le lecteur de production rend pour le pipe du service.
fn regle() -> &'static str {
    ServerRule::WindowsSystemPipeOwner.name()
}

/// Une trame lue par le VRAI lecteur strict, servie par un serveur admis.
fn lue(trame: &[u8]) -> Result<LueRoutageWindows, Refus> {
    analyser_routage_windows(trame)
        .map(|d| (d, regle()))
        .map_err(Refus::Declaration)
}

fn decl_wg() -> PlanRoutageWindows {
    PlanRoutageWindows {
        chemin: CheminRoutage::Wireguard,
        interface: "bfwg0".into(),
        mtu: 1420,
        familles: vec![FamilleRoutage::Ipv4, FamilleRoutage::Ipv6],
        destinations: Some(vec![net("198.51.100.0/24"), net("2001:db8:d1c::/48")]),
    }
}

fn decl_coeur() -> PlanRoutageWindows {
    PlanRoutageWindows {
        chemin: CheminRoutage::Coeur,
        interface: "bftun0".into(),
        mtu: 1280,
        familles: vec![FamilleRoutage::Ipv4, FamilleRoutage::Ipv6],
        destinations: None,
    }
}

/// La reponse telle que le VRAI daemon l'ecrit: le type du protocole, pas un
/// JSON tape a la main.
fn trame(application: u64, issue: EtatRoutage, plan: Option<PlanRoutageWindows>) -> Vec<u8> {
    let d = DeclarationRoutageWindows {
        schema_version: DECLARATION_ROUTAGE_WINDOWS_VERSION,
        instance: INSTANCE.into(),
        application,
        issue,
        plan,
    };
    let mut v = serde_json::to_vec(&Response::DeclarationRoutageWindows(Box::new(d))).unwrap();
    v.push(b'\n');
    v
}

fn posee_wg() -> Vec<u8> {
    trame(4, EtatRoutage::Pose, Some(decl_wg()))
}

fn modifier(trame: &[u8], cle: &str, valeur: Value) -> Vec<u8> {
    let mut v: Value = serde_json::from_slice(trame).unwrap();
    v[cle] = valeur;
    let mut t = serde_json::to_vec(&v).unwrap();
    t.push(b'\n');
    t
}

fn modifier_plan(trame: &[u8], cle: &str, valeur: Value) -> Vec<u8> {
    let mut v: Value = serde_json::from_slice(trame).unwrap();
    v["plan"][cle] = valeur;
    let mut t = serde_json::to_vec(&v).unwrap();
    t.push(b'\n');
    t
}

/// Ce que la lecture rend pour un alias: les tables, l'interface du tunnel
/// resolue seulement pour l'alias sous lequel le plan a ete pose.
fn vue(t: &TableIpHelper, alias: &str, alias_pose: &str) -> TableIpHelper {
    let mut v = t.clone();
    if alias != alias_pose {
        v.tunnel = None;
    }
    v
}

/// Le protocole joue sur une suite de lectures de la declaration et une table;
/// rend le rapport, le nombre de lectures de la declaration et celui des
/// tables.
async fn prouver(
    lectures: Vec<Result<LueRoutageWindows, Refus>>,
    table: &TableIpHelper,
    alias_pose: &str,
) -> (Value, usize, usize) {
    let mut lectures = lectures.into_iter();
    let declarations = Cell::new(0);
    let collectes = Cell::new(0);
    let (d, c) = (&declarations, &collectes);
    let r = verifier_declaration_avec(
        || {
            d.set(d.get() + 1);
            std::future::ready(lectures.next().expect("lecture de trop"))
        },
        |alias: &str| -> Result<TableIpHelper, &'static str> {
            c.set(c.get() + 1);
            Ok(vue(table, alias, alias_pose))
        },
    )
    .await;
    let code = r.code();
    let v = serde_json::to_value(&r).unwrap();
    assert_eq!(
        code,
        match v["verdict"].as_str().unwrap() {
            "MATCH" => 0,
            "MISMATCH" => 1,
            _ => 2,
        }
    );
    (v, declarations.get(), collectes.get())
}

/// Rien de la declaration ne sort dans le rapport.
fn rien_de_la_declaration(rapport: &Value) {
    let mut sans_horloge = rapport.clone();
    for cle in ["started_at_unix_ms", "completed_at_unix_ms", "duration_ms"] {
        sans_horloge.as_object_mut().unwrap().remove(cle);
    }
    let texte = sans_horloge.to_string().to_lowercase();
    for interdit in [
        "bfwg0", "bftun0", "198.51", "2001:db8", "1420", "1280", "s-1-5", INSTANCE,
    ] {
        assert!(
            !texte.contains(interdit),
            "le rapport exporte {interdit}: {texte}"
        );
    }
    for cle in ["application", "instance", "issue", "plan"] {
        assert!(rapport.get(cle).is_none(), "cle exportee: {cle}");
    }
}

/// Un plan declare, conforme aux tables: correspondance, dans les deux
/// chemins. Le rapport dit d'ou vient l'attendu et le nom de la regle qui a
/// admis le serveur; deux lectures de la declaration encadrent deux lectures
/// des tables.
#[tokio::test]
async fn un_plan_declare_conforme_aux_tables_correspond() {
    let (r, n, c) = prouver(
        vec![lue(&posee_wg()), lue(&posee_wg())],
        &posee(&plan_wg()),
        "bfwg0",
    )
    .await;
    assert_eq!(r["verdict"], "MATCH", "{r}");
    assert_eq!(r["scope"], "windows-routing-comparison");
    assert_eq!(r["expected_source"], "daemon-declared-active-routing-plan");
    assert_eq!(r["source"], "iphelper-tables-read-twice");
    assert_eq!(r["live_kernel"], true);
    assert_eq!(r["collection_verified"], true);
    assert!(r["failed_input"].is_null());
    assert!(r["intention_schema_version"].is_null());
    assert_eq!(r["daemon_identity"], "windows-system-pipe-owner");
    assert_eq!((n, c), (2, 2));
    rien_de_la_declaration(&r);

    let coeur = trame(4, EtatRoutage::Pose, Some(decl_coeur()));
    let (r, n, c) = prouver(
        vec![lue(&coeur), lue(&coeur)],
        &posee(&plan_coeur()),
        "bftun0",
    )
    .await;
    assert_eq!(r["verdict"], "MATCH", "{r}");
    assert_eq!((n, c), (2, 2));
    rien_de_la_declaration(&r);
}

/// L'attendu est reconstruit du plan DECLARE, pas des tables: un plan declare
/// different de ce que l'hote porte est un ecart, jamais une correspondance.
#[tokio::test]
async fn un_plan_declare_different_des_tables_est_un_ecart() {
    type Changer = fn(&mut PlanRoutageWindows);
    let variantes: [(&str, Changer, &[&str]); 4] = [
        (
            "autre interface",
            |p| p.interface = "bfwg1".into(),
            &["tunnel-interface-missing"],
        ),
        (
            "autre destination",
            |p| p.destinations = Some(vec![net("198.51.101.0/24"), net("2001:db8:d1c::/48")]),
            &["ipv4-plan-route-missing", "ipv4-tunnel-extra-route"],
        ),
        (
            "une destination de moins",
            |p| p.destinations = Some(vec![net("198.51.100.0/24")]),
            &["ipv6-tunnel-extra-route"],
        ),
        // Le coeur declare face a une pose WireGuard: ses routes par defaut
        // manquent, ses lignes ne sont pas imposees, les routes de WireGuard
        // sont en trop, et le lien physique gagne.
        (
            "autre chemin",
            |p| {
                p.chemin = CheminRoutage::Coeur;
                p.destinations = None;
            },
            &[
                "ipv4-plan-route-missing",
                "ipv4-interface-metric",
                "ipv4-tunnel-extra-route",
                "ipv4-competing-route",
                "ipv6-plan-route-missing",
                "ipv6-interface-metric",
                "ipv6-tunnel-extra-route",
                "ipv6-competing-route",
            ],
        ),
    ];
    for (nom, changer, attendus) in variantes {
        let mut plan = decl_wg();
        changer(&mut plan);
        let t = trame(4, EtatRoutage::Pose, Some(plan));
        let (r, n, _) = prouver(vec![lue(&t), lue(&t)], &posee(&plan_wg()), "bfwg0").await;
        assert_eq!(r["verdict"], "MISMATCH", "{nom}: {r}");
        assert_eq!(r["differences"], json!(attendus), "{nom}");
        assert_eq!(n, 2, "{nom}");
        rien_de_la_declaration(&r);
    }
}

/// La moindre difference entre N1 et N2 rend la collecte non attribuable,
/// meme quand les tables sont conformes a N1.
#[tokio::test]
async fn une_declaration_changee_pendant_la_collecte_n_est_pas_mesuree() {
    let n1 = posee_wg();
    for (nom, n2) in [
        (
            "numero suivant",
            trame(5, EtatRoutage::Pose, Some(decl_wg())),
        ),
        (
            "autre instance",
            modifier(&n1, "instance", json!("f".repeat(48))),
        ),
        ("autre mtu", modifier_plan(&n1, "mtu", json!(1421))),
        (
            "autres destinations",
            modifier_plan(&n1, "destinations", json!(["198.51.100.0/24"])),
        ),
        ("retrait", trame(5, EtatRoutage::Aucun, None)),
    ] {
        let (r, n, c) = prouver(vec![lue(&n1), lue(&n2)], &posee(&plan_wg()), "bfwg0").await;
        assert_eq!(r["verdict"], "UNMEASURED", "{nom}: {r}");
        assert_eq!(
            r["reason"], "declaration du daemon modifiee pendant la collecte",
            "{nom}"
        );
        assert_eq!(r["failed_input"], "daemon-declaration", "{nom}");
        assert_eq!((n, c), (2, 2), "{nom}");
        rien_de_la_declaration(&r);
    }
    let (r, _, _) = prouver(
        vec![lue(&n1), lue(b"{\"result\"")],
        &posee(&plan_wg()),
        "bfwg0",
    )
    .await;
    assert_eq!(r["verdict"], "UNMEASURED");
    assert_eq!(
        r["reason"],
        "declaration du daemon illisible ou injoignable apres la collecte"
    );
}

/// Des tables instables pendant le mode daemon: non mesure, comme en mode
/// intention.
#[tokio::test]
async fn des_tables_instables_ne_sont_pas_mesurees_face_au_daemon() {
    let une = posee(&plan_wg());
    let mut autre = une.clone();
    autre.routes.push(route(LAN, "203.0.113.78/32"));
    let bascule = Cell::new(false);
    let (b, u, a) = (&bascule, &une, &autre);
    let mut lectures = vec![lue(&posee_wg()), lue(&posee_wg())].into_iter();
    let r = verifier_declaration_avec(
        || std::future::ready(lectures.next().expect("lecture de trop")),
        |_alias: &str| -> Result<TableIpHelper, &'static str> {
            b.set(!b.get());
            Ok(if b.get() { u.clone() } else { a.clone() })
        },
    )
    .await;
    let r = serde_json::to_value(&r).unwrap();
    assert_eq!(r["verdict"], "UNMEASURED", "{r}");
    assert_eq!(r["reason"], INSTABLE);
    assert_eq!(r["failed_input"], "observed");
    assert_eq!(r["live_kernel"], false);
}

/// Une egalite indecise face au daemon: non mesuree, comme en mode intention,
/// et la regle qui a admis le serveur reste dite.
#[tokio::test]
async fn une_egalite_indecise_face_au_daemon_n_est_pas_mesuree() {
    let (r, n, c) = prouver(
        vec![lue(&posee_wg()), lue(&posee_wg())],
        &a_egalite(),
        "bfwg0",
    )
    .await;
    assert_eq!(r["verdict"], "UNMEASURED", "{r}");
    assert_eq!(r["reason"], EGALITE);
    assert_eq!(r["failed_input"], "observed");
    assert_eq!(r["differences"], json!([]));
    assert_eq!(r["daemon_identity"], "windows-system-pipe-owner");
    assert_eq!((n, c), (2, 2));
    rien_de_la_declaration(&r);
}

/// Un serveur refuse a N1: rien n'est lu des tables. Refuse a N2: le rapport
/// ne garde pas la regle de N1.
#[tokio::test]
async fn une_identite_refusee_n_est_jamais_mesuree() {
    let refus = Refus::Identite("serveur de la declaration non privilegie");
    let (r, n, c) = prouver(vec![Err(refus)], &posee(&plan_wg()), "bfwg0").await;
    assert_eq!(r["verdict"], "UNMEASURED", "{r}");
    assert_eq!(r["reason"], "serveur de la declaration non privilegie");
    assert_eq!(r["failed_input"], "daemon-identity");
    assert!(r["daemon_identity"].is_null(), "{r}");
    assert_eq!(r["live_kernel"], false);
    assert_eq!((n, c), (1, 0));

    let illisible = Refus::Identite("identite du serveur de la declaration illisible");
    let (r, n, c) = prouver(
        vec![lue(&posee_wg()), Err(illisible)],
        &posee(&plan_wg()),
        "bfwg0",
    )
    .await;
    assert_eq!(r["verdict"], "UNMEASURED", "{r}");
    assert_eq!(
        r["reason"],
        "identite du serveur de la declaration illisible"
    );
    assert_eq!(r["failed_input"], "daemon-identity");
    assert!(r["daemon_identity"].is_null(), "{r}");
    assert_eq!((n, c), (2, 2));
}

/// Une declaration valide qui ne pose aucun plan, ou n'en declare pas: rien
/// n'est compare, les tables ne sont pas lues, et il n'y a pas de N2.
#[tokio::test]
async fn sans_plan_pose_rien_n_est_compare() {
    for (issue, raison) in [
        (
            EtatRoutage::Aucun,
            "aucun plan de routage pose par ce daemon: rien a comparer",
        ),
        (
            EtatRoutage::NonApplicable,
            "le daemon ne declare pas de plan de routage",
        ),
    ] {
        let (r, n, c) = prouver(
            vec![lue(&trame(0, issue, None))],
            &posee(&plan_wg()),
            "bfwg0",
        )
        .await;
        assert_eq!(r["verdict"], "UNMEASURED", "{issue:?}");
        assert_eq!(r["reason"], raison);
        assert_eq!(r["failed_input"], "daemon-declaration");
        assert_eq!(r["live_kernel"], false);
        assert_eq!((n, c), (1, 0), "{issue:?}");
    }
}

/// L'analyse stricte de la reponse Windows: forme, cles exactes au niveau
/// superieur et dans `plan`, doublons, version, instance, coherence entre
/// l'etat, le numero et le plan, entre le chemin et les destinations, graphie
/// canonique des destinations, et la forme de Linux. Rien ne se mesure, et
/// rien de la declaration ne sort.
#[tokio::test]
async fn une_reponse_hors_schema_n_est_pas_mesuree() {
    let bonne = posee_wg();
    let coeur = trame(4, EtatRoutage::Pose, Some(decl_coeur()));
    let mut cas: Vec<(String, Vec<u8>)> = vec![
        ("coupee".into(), bonne[..bonne.len() / 2].to_vec()),
        ("vide".into(), Vec::new()),
        ("tableau".into(), b"[]\n".to_vec()),
        (
            "erreur sans message".into(),
            b"{\"result\":\"error\"}\n".to_vec(),
        ),
    ];
    let mut v: Value = serde_json::from_slice(&bonne).unwrap();
    v.as_object_mut()
        .unwrap()
        .insert("en_trop".into(), json!(1));
    cas.push(("cle en trop".into(), serde_json::to_vec(&v).unwrap()));
    for cle in CLES_ROUTAGE {
        let mut v: Value = serde_json::from_slice(&bonne).unwrap();
        v.as_object_mut().unwrap().remove(cle);
        cas.push((format!("sans {cle}"), serde_json::to_vec(&v).unwrap()));
    }
    let mut doublon = bonne[..bonne.len() - 2].to_vec();
    doublon.extend_from_slice(b",\"issue\":\"pose\"}\n");
    cas.push(("cle superieure dupliquee".into(), doublon));
    let doublon_plan = String::from_utf8(bonne.clone())
        .unwrap()
        .replacen("\"mtu\":1420", "\"mtu\":1420,\"mtu\":1420", 1)
        .into_bytes();
    cas.push(("cle du plan dupliquee".into(), doublon_plan));
    let mut v: Value = serde_json::from_slice(&bonne).unwrap();
    v["plan"]
        .as_object_mut()
        .unwrap()
        .insert("x".into(), json!(1));
    cas.push((
        "cle en trop dans le plan".into(),
        serde_json::to_vec(&v).unwrap(),
    ));
    for cle in PLAN_WINDOWS_CLES {
        let mut v: Value = serde_json::from_slice(&bonne).unwrap();
        v["plan"].as_object_mut().unwrap().remove(cle);
        cas.push((format!("plan sans {cle}"), serde_json::to_vec(&v).unwrap()));
    }
    for (nom, cle, valeur) in [
        ("version", "schema_version", json!(2)),
        ("instance vide", "instance", json!("")),
        (
            "instance majuscule",
            "instance",
            json!(INSTANCE.to_uppercase()),
        ),
        ("instance courte", "instance", json!(&INSTANCE[..31])),
        ("numero negatif", "application", json!(-1)),
        ("issue inconnue", "issue", json!("inconnue")),
        ("pose sans plan", "plan", Value::Null),
        ("plan tableau", "plan", json!([])),
    ] {
        cas.push((nom.into(), modifier(&bonne, cle, valeur)));
    }
    let flottant = String::from_utf8(bonne.clone())
        .unwrap()
        .replace("\"application\":4", "\"application\":4.0")
        .into_bytes();
    cas.push(("numero flottant".into(), flottant));
    for (nom, cle, valeur) in [
        ("wireguard sans destinations", "destinations", Value::Null),
        ("wireguard destinations vides", "destinations", json!([])),
        (
            "destination non canonique v4",
            "destinations",
            json!(["198.51.100.0/024"]),
        ),
        (
            "destination non canonique v6",
            "destinations",
            json!(["2001:0db8:d1c::/48"]),
        ),
        (
            "destination signee",
            "destinations",
            json!(["198.51.100.0/+24"]),
        ),
        ("destination illisible", "destinations", json!(["x/24"])),
        ("destination nombre", "destinations", json!([5])),
        (
            "destinations texte",
            "destinations",
            json!("198.51.100.0/24"),
        ),
        ("famille inconnue", "familles", json!(["ipv5"])),
        ("familles texte", "familles", json!("ipv4")),
        ("mtu negative", "mtu", json!(-1)),
        ("mtu flottante", "mtu", json!(1420.0)),
        ("mtu hors u32", "mtu", json!(4_294_968_716u64)),
        ("chemin inconnu", "chemin", json!("autre")),
        ("interface nombre", "interface", json!(7)),
    ] {
        cas.push((nom.into(), modifier_plan(&bonne, cle, valeur)));
    }
    cas.push((
        "coeur avec destinations".into(),
        modifier_plan(&coeur, "destinations", json!(["0.0.0.0/0"])),
    ));
    cas.push((
        "coeur avec destinations vides".into(),
        modifier_plan(&coeur, "destinations", json!([])),
    ));
    cas.push((
        "aucun avec plan".into(),
        modifier(
            &trame(0, EtatRoutage::Aucun, None),
            "plan",
            serde_json::to_value(decl_wg()).unwrap(),
        ),
    ));
    cas.push((
        "non applicable avec plan".into(),
        modifier(
            &trame(0, EtatRoutage::NonApplicable, None),
            "plan",
            serde_json::to_value(decl_wg()).unwrap(),
        ),
    ));
    cas.push((
        "pose au numero zero".into(),
        trame(0, EtatRoutage::Pose, Some(decl_wg())),
    ));
    // La forme de Linux, avec et sans plan: un autre schema.
    let linux = |issue, plan| {
        let d = DeclarationRoutage {
            schema_version: DECLARATION_ROUTAGE_VERSION,
            instance: INSTANCE.into(),
            application: 4,
            issue,
            plan,
        };
        serde_json::to_vec(&Response::DeclarationRoutage(Box::new(d))).unwrap()
    };
    cas.push((
        "forme linux sans plan".into(),
        linux(EtatRoutage::Aucun, None),
    ));
    cas.push((
        "forme linux posee".into(),
        linux(
            EtatRoutage::Pose,
            Some(PlanRoutage {
                chemin: CheminRoutage::Wireguard,
                interface: "bfwg0".into(),
                fwmark: Some(777_001),
                table: Some(30303),
                coeur_uid: None,
            }),
        ),
    ));
    for (nom, t) in cas {
        let lu = lue(&t);
        assert!(
            matches!(lu, Err(Refus::Declaration(_))),
            "{nom}: {:?}",
            lu.as_ref().map(|_| ())
        );
        let (r, n, c) = prouver(vec![lu], &posee(&plan_wg()), "bfwg0").await;
        assert_eq!(r["verdict"], "UNMEASURED", "{nom}: {r}");
        assert!(
            [
                HORS_SCHEMA,
                "reponse du daemon tronquee ou illisible",
                "le daemon a refuse la demande",
            ]
            .contains(&r["reason"].as_str().unwrap()),
            "{nom}: {r}"
        );
        assert_eq!(r["failed_input"], "daemon-declaration", "{nom}");
        assert_eq!((n, c), (1, 0), "{nom}");
        rien_de_la_declaration(&r);
    }
}

/// Le refus d'acces du daemon nomme l'appelant dans son message: jamais recopie
/// dans une raison.
#[tokio::test]
async fn un_acces_refuse_ne_nomme_personne() {
    let refus = b"{\"result\":\"error\",\"message\":\"acces refuse pour S-1-5-21-1-2-3-1001: ni SYSTEM ni administrateur\"}\n";
    let (r, _, c) = prouver(vec![lue(refus)], &posee(&plan_wg()), "bfwg0").await;
    assert_eq!(r["verdict"], "UNMEASURED");
    assert_eq!(r["reason"], "acces au daemon refuse");
    assert_eq!(c, 0);
    rien_de_la_declaration(&r);
}

/// Un plan declare que le produit ne pose pas ne se compare jamais: la
/// declaration passe l'analyse de schema, c'est la reconstruction du plan qui
/// refuse, avant toute lecture des tables, et sans N2.
#[tokio::test]
async fn un_plan_declare_hors_perimetre_n_est_jamais_compare() {
    type Changer = fn(&mut PlanRoutageWindows);
    let variantes: [(&str, Changer); 9] = [
        ("interface vide", |p| p.interface = String::new()),
        ("interface espace", |p| p.interface = "bf wg0".into()),
        ("interface longue", |p| {
            p.interface = "bfwg0bfwg0bfwg0x".into()
        }),
        ("mtu basse", |p| p.mtu = 575),
        ("mtu haute", |p| p.mtu = 9001),
        ("familles vides", |p| p.familles.clear()),
        ("familles inversees", |p| p.familles.reverse()),
        ("destination non masquee", |p| {
            p.destinations = Some(vec![net("198.51.100.1/24")])
        }),
        ("destination en double", |p| {
            p.destinations = Some(vec![net("198.51.100.0/24"), net("198.51.100.0/24")])
        }),
    ];
    for (nom, changer) in variantes {
        let mut plan = decl_wg();
        changer(&mut plan);
        let t = trame(4, EtatRoutage::Pose, Some(plan));
        let (r, n, c) = prouver(vec![lue(&t)], &posee(&plan_wg()), "bfwg0").await;
        assert_eq!(r["verdict"], "UNMEASURED", "{nom}: {r}");
        assert_eq!(r["failed_input"], "daemon-declaration", "{nom}");
        assert_eq!(r["live_kernel"], false, "{nom}");
        assert_eq!((n, c), (1, 0), "{nom}");
        rien_de_la_declaration(&r);
    }
}

// --- les occurrences reelles, sous Windows -----------------------------------------

/// LA garde de l'identite sur son occurrence reelle: la lecture de production
/// (`declaration::lire_routage_windows`, regle des preuves) face a un pipe
/// servi par CE processus. Son proprietaire est le compte de la recette, ou les
/// Administrateurs sous un jeton eleve: jamais LocalSystem hors d'un processus
/// SYSTEM. Refuse, il ne recoit RIEN. Sous SYSTEM, il est admis: c'est la
/// limite de la regle, et la branche le mesure aussi.
#[cfg(windows)]
#[tokio::test]
async fn la_preuve_des_routes_exige_le_pipe_de_localsystem() {
    use tokio::io::AsyncReadExt;
    use tokio::net::windows::named_pipe::ServerOptions;

    let nom = format!(
        r"\\.\pipe\bifrost-preuve-routes-identite-{}",
        std::process::id()
    );
    let mut serveur = ServerOptions::new()
        .first_pipe_instance(true)
        .reject_remote_clients(true)
        .create(&nom)
        .expect("creation du pipe");
    let ecoute = tokio::spawn(async move {
        let mut recus = Vec::new();
        if serveur.connect().await.is_ok() {
            let _ = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                serveur.read_to_end(&mut recus),
            )
            .await;
        }
        recus
    });
    let r = verifier_declaration_avec(
        || crate::declaration::lire_routage_windows(&nom),
        |_alias: &str| -> Result<TableIpHelper, &'static str> {
            panic!("collecte interdite sans declaration")
        },
    )
    .await;
    let recus = ecoute.await.expect("le faux serveur rend la main");
    let r = serde_json::to_value(&r).unwrap();
    assert_eq!(r["verdict"], "UNMEASURED", "{r}");
    let groupes = std::process::Command::new("whoami")
        .arg("/groups")
        .output()
        .expect("whoami /groups");
    let sous_system = String::from_utf8_lossy(&groupes.stdout).contains("S-1-16-16384");
    if !sous_system {
        assert!(
            recus.is_empty(),
            "{} octet(s) ecrit(s) a un serveur refuse",
            recus.len()
        );
        assert_eq!(
            r["reason"], "serveur de la declaration non privilegie",
            "{r}"
        );
        assert_eq!(r["failed_input"], "daemon-identity", "{r}");
        assert!(r["daemon_identity"].is_null(), "{r}");
    } else {
        assert_eq!(
            String::from_utf8_lossy(&recus),
            "{\"version\":1,\"command\":\"declaration-routage\"}\n"
        );
        assert_eq!(r["failed_input"], "daemon-declaration", "{r}");
    }
    rien_de_la_declaration(&r);
}

/// La preuve de production lit les VRAIES tables de l'hote, sans privilege:
/// un alias que rien ne porte est l'ecart `tunnel-interface-missing`, apres une
/// collecte verifiee des deux familles, jamais un refus ni une correspondance.
/// Une table qui bouge entre deux lectures rend la mesure instable: la recette
/// la rejoue, au plus trois fois.
#[cfg(windows)]
#[test]
fn la_preuve_lit_les_tables_reelles_de_l_hote() {
    let f = Fichier::nouveau(&WG.replace("bfwg0", "bfabsent0"));
    let mut r = verifier(&f.0);
    for _ in 0..2 {
        if r.reason != INSTABLE {
            break;
        }
        r = verifier(&f.0);
    }
    assert_eq!(r.verdict, "MISMATCH", "{}", r.reason);
    assert_eq!(r.differences, [INTERFACE_ABSENTE]);
    assert!(r.live_kernel && r.collection_verified);
    assert_eq!(r.tunnel_interface_present, Some(false));
    let o = serde_json::to_value(&r.observed_counts).unwrap();
    for famille in ["ipv4", "ipv6"] {
        assert!(o[famille]["routes"].as_u64().unwrap() > 0, "{o}");
        assert!(o[famille]["interfaces"].as_u64().unwrap() > 0, "{o}");
    }
}
