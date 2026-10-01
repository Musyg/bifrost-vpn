//! Recettes hors ligne de `prove routes`: le comparateur sur des lectures
//! fabriquees, et le lecteur de trames sur des trames fabriquees.
//!
//! Les lectures fabriquees reprennent la forme que le noyau rend (priorites
//! qu'il choisit, marque completee de son masque, regles du noyau a leur
//! protocole): elles ne prouvent aucune observation du noyau, c'est le banc
//! `preuve-routes-linux.sh` et la recette de `preuve_routes_linux` qui le font.

use std::io::Write;
use std::path::PathBuf;

use super::trames::{self, Attente, Suite};
use super::*;

// --- lectures fabriquees ---------------------------------------------------

const LO: u32 = 1;
const PHYS: u32 = 2;
const TUN: u32 = 3;
const MARQUE: u32 = 777_001;
const TABLE_WG: u32 = 30_303;
const COMPTE: u32 = 4242;

fn v4(a: [u8; 4]) -> Vec<u8> {
    a.to_vec()
}

fn v6(prefixe: &[u16]) -> Vec<u8> {
    let mut o = [0_u16; 8];
    o[..prefixe.len()].copy_from_slice(prefixe);
    o.iter().flat_map(|m| m.to_be_bytes()).collect()
}

fn regle(pref: u32, table: u32) -> Regle {
    Regle {
        pref,
        action: Action::VersTable,
        table,
        inverse: false,
        drapeaux: 0,
        selecteurs: Selecteurs::default(),
        suppression_prefixe: None,
        suppression_groupe: None,
        cible_saut: None,
        protocole: 3,
    }
}

fn du_noyau(pref: u32, table: u32) -> Regle {
    Regle {
        protocole: 2,
        ..regle(pref, table)
    }
}

fn sans_defaut(pref: u32) -> Regle {
    Regle {
        suppression_prefixe: Some(0),
        ..regle(pref, 254)
    }
}

fn hors_marque(pref: u32) -> Regle {
    let mut r = regle(pref, TABLE_WG);
    r.inverse = true;
    r.selecteurs.marque = Some((MARQUE, u32::MAX));
    r
}

fn route(table: u32, genre: u8, dst: Vec<u8>, dst_len: u8, oif: u32) -> Route {
    Route {
        table,
        genre,
        dst: if dst_len == 0 { Vec::new() } else { dst },
        dst_len,
        src: Vec::new(),
        src_len: 0,
        tos: 0,
        protocole: 2,
        portee: 0,
        drapeaux: 0,
        oif: Some(oif),
        iif: None,
        passerelle: None,
        via: None,
        multichemin: None,
        prochain_saut: None,
        encapsulation: None,
        metrique: None,
        source_preferee: None,
        metriques: None,
        flux: None,
        preference: None,
        expire: false,
    }
}

fn par(mut r: Route, passerelle: Vec<u8>) -> Route {
    r.passerelle = Some(passerelle);
    r
}

fn adresse(index: u32, prefixe: u8, adresse: Vec<u8>) -> Adresse {
    Adresse {
        index,
        prefixe,
        adresse,
    }
}

/// Un namespace comme celui du banc: une fausse interface physique
/// (192.0.2.2/24 et 2001:db8:1::2/64, route par defaut par .1 et ::1),
/// l'interface du tunnel, et ce que le noyau pose de lui-meme dans `local` et
/// `main`.
fn systeme() -> Observation {
    let ipv4 = Vue {
        regles: vec![du_noyau(0, 255), du_noyau(32766, 254), du_noyau(32767, 253)],
        routes: vec![
            par(route(254, 1, vec![], 0, PHYS), v4([192, 0, 2, 1])),
            route(254, 1, v4([192, 0, 2, 0]), 24, PHYS),
            route(255, 2, v4([127, 0, 0, 0]), 8, LO),
            route(255, 2, v4([127, 0, 0, 1]), 32, LO),
            route(255, 3, v4([127, 255, 255, 255]), 32, LO),
            route(255, 2, v4([192, 0, 2, 2]), 32, PHYS),
            route(255, 3, v4([192, 0, 2, 255]), 32, PHYS),
            route(255, 2, v4([198, 51, 100, 2]), 32, TUN),
        ],
        adresses: vec![
            adresse(LO, 8, v4([127, 0, 0, 1])),
            adresse(PHYS, 24, v4([192, 0, 2, 2])),
            adresse(TUN, 32, v4([198, 51, 100, 2])),
        ],
    };
    let ipv6 = Vue {
        regles: vec![du_noyau(0, 255), du_noyau(32766, 254)],
        routes: vec![
            route(254, 1, v6(&[0, 0, 0, 0, 0, 0, 0, 1]), 128, LO),
            route(254, 1, v6(&[0x2001, 0xdb8, 1]), 64, PHYS),
            route(254, 1, v6(&[0xfe80]), 64, PHYS),
            route(254, 1, v6(&[0xfe80]), 64, TUN),
            par(
                route(254, 1, vec![], 0, PHYS),
                v6(&[0x2001, 0xdb8, 1, 0, 0, 0, 0, 1]),
            ),
            route(255, 2, v6(&[0, 0, 0, 0, 0, 0, 0, 1]), 128, LO),
            route(255, 2, v6(&[0x2001, 0xdb8, 1, 0, 0, 0, 0, 2]), 128, PHYS),
            route(255, 2, v6(&[0xfe80, 0, 0, 0, 0, 0, 0, 2]), 128, PHYS),
            route(255, 5, v6(&[0xff00]), 8, PHYS),
            route(255, 5, v6(&[0xff00]), 8, TUN),
        ],
        adresses: vec![
            adresse(LO, 128, v6(&[0, 0, 0, 0, 0, 0, 0, 1])),
            adresse(PHYS, 64, v6(&[0x2001, 0xdb8, 1, 0, 0, 0, 0, 2])),
            adresse(PHYS, 64, v6(&[0xfe80, 0, 0, 0, 0, 0, 0, 2])),
            adresse(TUN, 64, v6(&[0xfe80, 0, 0, 0, 0, 0, 0, 3])),
        ],
    };
    Observation {
        tunnel: Some(TUN),
        ipv4,
        ipv6,
    }
}

fn vue(o: &mut Observation, f: Famille) -> &mut Vue {
    match f {
        Famille::Ipv4 => &mut o.ipv4,
        Famille::Ipv6 => &mut o.ipv6,
    }
}

/// Ce que le chemin WireGuard pose, comme le noyau le rend: priorites choisies
/// par le noyau (32765 pour `not fwmark`, posee la premiere, puis 32764 pour
/// `suppress_prefixlength 0`), route par defaut dans la table du tunnel.
fn wireguard_pose() -> Observation {
    let mut o = systeme();
    for f in Famille::TOUTES {
        let v = vue(&mut o, f);
        v.regles.insert(1, hors_marque(32765));
        v.regles.insert(1, sans_defaut(32764));
        v.routes.push(route(TABLE_WG, 1, vec![], 0, TUN));
    }
    o
}

/// Le chemin par coeur, a priorites fixes, avec ou sans compte.
fn coeur_pose(compte: Option<u32>) -> Observation {
    let mut o = systeme();
    for f in Famille::TOUTES {
        let v = vue(&mut o, f);
        let mut regles = vec![sans_defaut(9110), regle(9120, 2847)];
        if let Some(u) = compte {
            let mut r = regle(9100, 254);
            r.selecteurs.compte = Some((u, u));
            regles.insert(0, r);
        }
        for (i, r) in regles.into_iter().enumerate() {
            v.regles.insert(1 + i, r);
        }
        v.routes.push(route(2847, 1, vec![], 0, TUN));
    }
    o
}

fn plan_wg() -> Plan {
    Plan::wireguard("bfwg0", MARQUE, TABLE_WG)
}

fn plan_coeur() -> Plan {
    Plan::coeur("bftun0", Some(COMPTE))
}

fn ecarts(plan: &Plan, o: &Observation) -> Vec<&'static str> {
    comparer(plan, o).unwrap().2
}

/// La meme pose, ses regles et la route de sa table de tunnel posees a
/// l'originateur `protocole`. Les regles du produit sont posees au protocole 3
/// par les fabriques ci-dessus (comme un tiers); cette fonction les fait
/// passer a `protocole`, avec la route du tunnel.
fn posee_a(mut o: Observation, table: u32, protocole: u8) -> Observation {
    for f in Famille::TOUTES {
        let v = vue(&mut o, f);
        for r in v.regles.iter_mut().filter(|r| r.protocole == 3) {
            r.protocole = protocole;
        }
        for r in v.routes.iter_mut().filter(|r| r.table == table) {
            r.protocole = protocole;
        }
    }
    o
}

/// La meme pose avec l'etiquette du produit ([`PROTOCOLE_PRODUIT`]) sur ses
/// regles et sur la route de sa table de tunnel: ce que le peripherique du
/// tunnel pose vraiment, et ce que le mode daemon exige.
fn etiquete(o: Observation, table: u32) -> Observation {
    posee_a(o, table, PROTOCOLE_PRODUIT)
}

/// Les originateurs que les recettes du mode daemon opposent a l'etiquette du
/// produit: 0 (`RTPROT_UNSPEC`), 2 (`RTPROT_KERNEL`), 3 (`RTPROT_BOOT`), 4
/// (`RTPROT_STATIC`), les deux voisins de 177, et la derniere valeur. Une garde
/// qui ne refuserait que l'un d'eux (`!= 3`, `!= 2`, `>= 177`...) en laisserait
/// passer un autre: chaque recette les essaie tous.
const PROTOCOLES_TIERS: [u8; 7] = [0, 2, 3, 4, 176, 178, 255];

/// Les ecarts en mode daemon: l'etiquette du produit exigee sur les objets du
/// plan (voir [`super::comparer_avec`]).
fn ecarts_daemon(plan: &Plan, o: &Observation) -> Vec<&'static str> {
    comparer_avec(plan, o, true).unwrap().2
}

const AUCUN: [&str; 0] = [];

// --- correspondance ------------------------------------------------------

#[test]
fn le_plan_pose_correspond() {
    let (attendus, observes, e) = comparer(&plan_wg(), &wireguard_pose()).unwrap();
    assert_eq!(e, AUCUN);
    assert_eq!(
        (attendus.ipv4.product_rules, attendus.ipv4.tunnel_routes),
        (2, 1)
    );
    assert_eq!(observes.ipv4.product_rules_found, 2);
    assert_eq!(observes.ipv4.rules_before_tunnel, Some(2));
    assert_eq!(observes.ipv4.third_party_rules_before_tunnel, Some(0));
    // `local` en entier, `main` au-dela de sa route par defaut. IPv4: les
    // adresses locales, la route connectee du lien, et les diffusions du
    // reseau de chaque adresse (lien et boucle locale).
    assert_eq!(
        observes.ipv4.routes_before_tunnel,
        Some(Jugees {
            local_delivery: 4,
            connected: 1,
            own_network_host: 2,
            ..Jugees::default()
        })
    );
    // IPv6: la multidiffusion que le noyau pose sur le lien physique est
    // comptee a part (limite nommee); celle du tunnel va au tunnel.
    assert_eq!(
        observes.ipv6.routes_before_tunnel,
        Some(Jugees {
            tunnel_interface: 2,
            local_delivery: 3,
            connected: 3,
            multicast_on_link: 1,
            ..Jugees::default()
        })
    );
    for compte in [Some(COMPTE), None] {
        let plan = Plan::coeur("bftun0", compte);
        assert_eq!(ecarts(&plan, &coeur_pose(compte)), AUCUN);
    }
}

/// Le produit pose ses regles et ses routes avec son etiquette
/// (`bifrost_core::routage::PROTOCOLE_PRODUIT`), pour que son demontage ne
/// retire que ce qu'il a pose. Elle ne change aucune decision de routage, et
/// la preuve ne la compare pas: la pose etiquetee correspond, dans les deux
/// chemins, comme la pose d'un autre originateur.
#[test]
fn l_etiquette_du_produit_ne_change_pas_le_verdict() {
    let etiqueter = |mut o: Observation, table: u32| {
        for f in Famille::TOUTES {
            let v = vue(&mut o, f);
            for r in v.regles.iter_mut().filter(|r| r.protocole == 3) {
                r.protocole = bifrost_core::routage::PROTOCOLE_PRODUIT;
            }
            for r in v.routes.iter_mut().filter(|r| r.table == table) {
                r.protocole = bifrost_core::routage::PROTOCOLE_PRODUIT;
            }
        }
        o
    };
    let o = etiqueter(wireguard_pose(), TABLE_WG);
    assert_eq!(
        o.ipv6
            .regles
            .iter()
            .filter(|r| r.protocole == bifrost_core::routage::PROTOCOLE_PRODUIT)
            .count(),
        2
    );
    assert_eq!(ecarts(&plan_wg(), &o), AUCUN);
    let o = etiqueter(coeur_pose(Some(COMPTE)), 2847);
    assert_eq!(ecarts(&plan_coeur(), &o), AUCUN);
}

/// Sans rien de pose, c'est un ecart, jamais une correspondance.
#[test]
fn rien_de_pose_est_un_ecart() {
    for plan in [plan_wg(), plan_coeur()] {
        assert_eq!(
            ecarts(&plan, &systeme()),
            [
                "ipv4-product-rules",
                "ipv4-tunnel-table",
                "ipv6-product-rules",
                "ipv6-tunnel-table"
            ]
        );
    }
}

// --- mode daemon: l'etiquette du produit exigee ----------------------------
//
// Le mode intention ne dit rien de qui a pose: il ne compare pas l'etiquette.
// Le mode daemon, lui, tient l'attendu du peripherique du tunnel, qui pose avec
// l'etiquette du produit; une regle ou une route du plan sans etiquette n'est
// donc pas la sienne. La decision de la voie: en mode daemon, l'etiquette est
// exigee sur les regles du produit ET sur la route de la table du tunnel. Le
// produit pose avec `protocol 177` et `proto 177` (`netcfg`, `aiguillage`), et
// le banc `e2e-linux.sh` mesure la correspondance en mode daemon face a la pose
// d'un vrai daemon; ces recettes tiennent le comparateur, sur chacun des
// originateurs de [`PROTOCOLES_TIERS`].

/// La pose etiquetee correspond en mode daemon, dans les deux chemins.
#[test]
fn en_mode_daemon_la_pose_etiquetee_correspond() {
    assert_eq!(
        ecarts_daemon(&plan_wg(), &etiquete(wireguard_pose(), TABLE_WG)),
        AUCUN
    );
    assert_eq!(
        ecarts_daemon(&plan_coeur(), &etiquete(coeur_pose(Some(COMPTE)), 2847)),
        AUCUN
    );
}

/// La MEME pose, a tout autre originateur que l'etiquette, n'est pas celle du
/// daemon: ni ses regles ni sa route de tunnel ne correspondent, dans les deux
/// familles. C'est ce qui distingue le mode daemon du mode intention, ou la
/// meme pose correspond.
#[test]
fn en_mode_daemon_une_pose_sans_etiquette_est_un_ecart() {
    assert!(!PROTOCOLES_TIERS.contains(&PROTOCOLE_PRODUIT));
    for p in PROTOCOLES_TIERS {
        for (plan, o) in [
            (plan_wg(), posee_a(wireguard_pose(), TABLE_WG, p)),
            (plan_coeur(), posee_a(coeur_pose(Some(COMPTE)), 2847, p)),
        ] {
            assert_eq!(
                ecarts_daemon(&plan, &o),
                [
                    "ipv4-product-rules",
                    "ipv4-tunnel-table",
                    "ipv6-product-rules",
                    "ipv6-tunnel-table"
                ],
                "protocole {p}"
            );
            // La meme pose, en mode intention, correspond: l'etiquette n'y est
            // pas exigee.
            assert_eq!(ecarts(&plan, &o), AUCUN, "protocole {p}");
        }
    }
}

/// L'etiquette otee de la SEULE regle qui aiguille vers le tunnel: elle n'est
/// plus reconnue comme celle du produit, et comme elle est l'ancre, l'analyse
/// d'avant-tunnel ne s'ouvre pas. Un seul ecart, celui des regles du produit,
/// quel que soit l'originateur qui remplace l'etiquette.
#[test]
fn en_mode_daemon_l_etiquette_otee_de_la_regle_du_tunnel_est_un_ecart_de_sa_categorie() {
    for p in PROTOCOLES_TIERS {
        // WireGuard: la regle `not fwmark` consulte la table du tunnel.
        let mut o = etiquete(wireguard_pose(), TABLE_WG);
        for r in o.ipv4.regles.iter_mut().filter(|r| r.inverse) {
            r.protocole = p;
        }
        assert_eq!(
            ecarts_daemon(&plan_wg(), &o),
            ["ipv4-product-rules"],
            "protocole {p}"
        );

        // Coeur: la regle de priorite 9120 consulte la table du coeur (2847).
        let mut o = etiquete(coeur_pose(Some(COMPTE)), 2847);
        for r in o.ipv6.regles.iter_mut().filter(|r| r.table == 2847) {
            r.protocole = p;
        }
        assert_eq!(
            ecarts_daemon(&plan_coeur(), &o),
            ["ipv6-product-rules"],
            "protocole {p}"
        );
    }
}

/// L'etiquette otee de la route de la table du tunnel: la route par defaut
/// existe et va au tunnel, mais sans l'etiquette du produit ce n'est pas celle
/// que le daemon declare avoir posee. Les regles gardent la leur, donc l'ancre
/// est trouvee et l'avant-tunnel s'analyse: un seul ecart, celui de la table du
/// tunnel, quel que soit l'originateur qui remplace l'etiquette.
#[test]
fn en_mode_daemon_l_etiquette_otee_de_la_route_du_tunnel_est_un_ecart_de_sa_categorie() {
    for p in PROTOCOLES_TIERS {
        let mut o = etiquete(wireguard_pose(), TABLE_WG);
        for r in o.ipv4.routes.iter_mut().filter(|r| r.table == TABLE_WG) {
            r.protocole = p;
        }
        assert_eq!(
            ecarts_daemon(&plan_wg(), &o),
            ["ipv4-tunnel-table"],
            "protocole {p}"
        );

        let mut o = etiquete(coeur_pose(Some(COMPTE)), 2847);
        for r in o.ipv6.routes.iter_mut().filter(|r| r.table == 2847) {
            r.protocole = p;
        }
        assert_eq!(
            ecarts_daemon(&plan_coeur(), &o),
            ["ipv6-tunnel-table"],
            "protocole {p}"
        );
    }
}

// --- regles du produit ---------------------------------------------------

#[test]
fn une_regle_du_produit_retiree_est_un_ecart_de_sa_seule_categorie() {
    let mut o = wireguard_pose();
    o.ipv4.regles.retain(|r| !r.inverse);
    assert_eq!(ecarts(&plan_wg(), &o), ["ipv4-product-rules"]);

    let mut o = wireguard_pose();
    o.ipv6.regles.retain(|r| r.suppression_prefixe.is_none());
    assert_eq!(ecarts(&plan_wg(), &o), ["ipv6-product-rules"]);

    let mut o = coeur_pose(Some(COMPTE));
    o.ipv4.regles.retain(|r| r.selecteurs.compte.is_none());
    assert_eq!(ecarts(&plan_coeur(), &o), ["ipv4-product-rules"]);

    // En double: la meme regle deux fois n'est plus "une seule fois".
    let mut o = wireguard_pose();
    let double = o.ipv4.regles[1].clone();
    o.ipv4.regles.insert(1, double);
    assert_eq!(ecarts(&plan_wg(), &o), ["ipv4-product-rules"]);
}

#[test]
fn une_regle_du_produit_changee_est_un_ecart() {
    // La regle du tunnel changee: plus rien n'aiguille vers le tunnel.
    let mut o = wireguard_pose();
    o.ipv4.regles[2].selecteurs.marque = Some((MARQUE + 1, u32::MAX));
    assert_eq!(ecarts(&plan_wg(), &o), ["ipv4-product-rules"]);

    let mut o = coeur_pose(Some(COMPTE));
    o.ipv6.regles[3].pref = 9121;
    assert_eq!(ecarts(&plan_coeur(), &o), ["ipv6-product-rules"]);

    // Une regle changee AVANT celle du tunnel, et qui consulte encore une
    // autre table, est aussi une regle tierce avant le tunnel: deux
    // categories, et les deux sont vraies.
    let mut o = wireguard_pose();
    o.ipv6.regles[1].suppression_prefixe = Some(1);
    assert_eq!(
        ecarts(&plan_wg(), &o),
        ["ipv6-product-rules", "ipv6-rules-before-tunnel"]
    );
    let mut o = coeur_pose(Some(COMPTE));
    o.ipv4.regles[1].pref = 9101;
    assert_eq!(
        ecarts(&plan_coeur(), &o),
        ["ipv4-product-rules", "ipv4-rules-before-tunnel"]
    );
}

/// L'ordre EST la politique: `suppress_prefixlength 0` evalue apres `not
/// fwmark` ne garde plus le LAN hors du tunnel. Le meme ensemble de regles,
/// dans l'autre ordre, est un ecart.
#[test]
fn l_ordre_des_regles_compte() {
    // Les deux regles de WireGuard, priorites echangees.
    let mut o = wireguard_pose();
    o.ipv4.regles.swap(1, 2);
    o.ipv4.regles[1].pref = 32764;
    o.ipv4.regles[2].pref = 32765;
    assert_eq!(ecarts(&plan_wg(), &o), ["ipv4-product-rules"]);

    // A priorites fixes le noyau trie par priorite et ne rend jamais cet
    // ordre; il est joue ici pour le comparateur seul.
    let mut o = coeur_pose(None);
    o.ipv6.regles.swap(1, 2);
    assert_eq!(
        ecarts(&Plan::coeur("bftun0", None), &o),
        ["ipv6-product-rules"]
    );
}

/// Les deux familles sont comparees: IPv6 oubliee n'est pas une
/// correspondance, et ses ecarts sont les siens seuls.
#[test]
fn une_famille_oubliee_est_un_ecart_de_cette_famille() {
    for (plan, mut o, table) in [
        (plan_wg(), wireguard_pose(), TABLE_WG),
        (plan_coeur(), coeur_pose(Some(COMPTE)), 2847),
    ] {
        o.ipv6.regles.retain(|r| r.protocole == 2);
        o.ipv6.routes.retain(|r| r.table != table);
        assert_eq!(
            ecarts(&plan, &o),
            ["ipv6-product-rules", "ipv6-tunnel-table"]
        );
    }
}

// --- regles tierces --------------------------------------------------------

#[test]
fn une_regle_tierce_avant_le_tunnel_est_un_ecart() {
    let mut vers_203 = regle(100, 254);
    vers_203.selecteurs.dst = Some((v4([203, 0, 113, 0]), 24));
    for tierce in [
        regle(100, 254),
        regle(100, 100),
        Regle {
            action: Action::Saut,
            cible_saut: Some(32766),
            ..regle(100, 0)
        },
        vers_203,
    ] {
        let mut o = wireguard_pose();
        o.ipv4.regles.insert(1, tierce);
        assert_eq!(ecarts(&plan_wg(), &o), ["ipv4-rules-before-tunnel"]);
    }
    // Entre la regle du LAN et celle du tunnel du coeur.
    let mut o = coeur_pose(Some(COMPTE));
    o.ipv6.regles.insert(3, regle(9115, 100));
    assert_eq!(ecarts(&plan_coeur(), &o), ["ipv6-rules-before-tunnel"]);
}

/// Ce qui n'aiguille rien ailleurs n'est pas un ecart: une regle apres celle
/// du tunnel, une consultation de la table du tunnel, une regle neutre ou qui
/// rejette.
#[test]
fn une_regle_tierce_qui_n_aiguille_rien_ailleurs_n_est_pas_un_ecart() {
    for (position, tierce) in [
        (4, regle(32766, 100)),
        (1, regle(100, TABLE_WG)),
        (
            1,
            Regle {
                action: Action::Neutre,
                ..regle(100, 0)
            },
        ),
        (
            1,
            Regle {
                action: Action::TrouNoir,
                ..regle(100, 0)
            },
        ),
    ] {
        let mut o = wireguard_pose();
        o.ipv4.regles.insert(position, tierce);
        assert_eq!(ecarts(&plan_wg(), &o), AUCUN);
    }
}

// --- table du tunnel -------------------------------------------------------

#[test]
fn la_table_du_tunnel_porte_exactement_la_route_du_plan() {
    let mut o = wireguard_pose();
    o.ipv6.routes.retain(|r| r.table != TABLE_WG);
    assert_eq!(ecarts(&plan_wg(), &o), ["ipv6-tunnel-table"]);

    let mut o = wireguard_pose();
    let r = o
        .ipv4
        .routes
        .iter_mut()
        .find(|r| r.table == TABLE_WG)
        .unwrap();
    r.oif = Some(PHYS);
    assert_eq!(ecarts(&plan_wg(), &o), ["ipv4-tunnel-table"]);

    let mut o = wireguard_pose();
    let r = o
        .ipv4
        .routes
        .iter_mut()
        .find(|r| r.table == TABLE_WG)
        .unwrap();
    r.passerelle = Some(v4([192, 0, 2, 1]));
    assert_eq!(ecarts(&plan_wg(), &o), ["ipv4-tunnel-table"]);

    let mut o = wireguard_pose();
    o.ipv4.routes.push(par(
        route(TABLE_WG, 1, v4([203, 0, 113, 0]), 24, PHYS),
        v4([192, 0, 2, 1]),
    ));
    assert_eq!(ecarts(&plan_wg(), &o), ["ipv4-tunnel-table"]);

    // Le noyau ignore une route au prochain saut mort (RTNH_F_DEAD), ou sans
    // porteuse (RTNH_F_LINKDOWN) des que `ignore_routes_with_linkdown` vaut 1,
    // sysctl lu a chaque recherche: le trafic passe alors a la regle
    // suivante, hors du tunnel (mesure sur essai-linux). Une route qui expire
    // cesse d'etre consultee a son echeance, alors que le dump la montre
    // encore (mesure). Chacune est un ecart; `onlink`, qui ne change pas
    // l'emission (mesure en IPv6, refuse sans passerelle en IPv4), non.
    for (drapeaux, expire, ecart) in [
        (1, false, true),
        (16, false, true),
        (17, false, true),
        (0, true, true),
        (4, false, false),
    ] {
        for (plan, mut o, table) in [
            (plan_wg(), wireguard_pose(), TABLE_WG),
            (plan_coeur(), coeur_pose(Some(COMPTE)), 2847),
        ] {
            let r = o.ipv6.routes.iter_mut().find(|r| r.table == table).unwrap();
            r.drapeaux = drapeaux;
            r.expire = expire;
            let attendu: &[&str] = if ecart { &["ipv6-tunnel-table"] } else { &[] };
            assert_eq!(ecarts(&plan, &o), attendu, "{drapeaux} {expire}");
        }
    }

    // L'interface du tunnel a disparu, et ses routes avec elle.
    let mut o = wireguard_pose();
    o.tunnel = None;
    for f in Famille::TOUTES {
        vue(&mut o, f).routes.retain(|r| r.oif != Some(TUN));
    }
    assert_eq!(
        ecarts(&plan_wg(), &o),
        ["ipv4-tunnel-table", "ipv6-tunnel-table"]
    );
}

// --- ce que suppress_prefixlength 0 laisse passer --------------------------

#[test]
fn une_route_plus_specifique_hors_du_lien_passe_avant_le_tunnel() {
    let passerelle = v4([192, 0, 2, 1]);
    for r in [
        // Une route par une passerelle.
        par(
            route(254, 1, v4([203, 0, 113, 0]), 24, PHYS),
            passerelle.clone(),
        ),
        // La moitie d'Internet: le tour de `def1`.
        par(route(254, 1, v4([0, 0, 0, 0]), 1, PHYS), passerelle.clone()),
        // Sur le lien, mais plus large que le reseau de son adresse.
        route(254, 1, v4([192, 0, 0, 0]), 16, PHYS),
        // Sur le lien, sans aucune adresse dans ce reseau.
        route(254, 1, v4([128, 0, 0, 0]), 1, PHYS),
        // Dans `local`, que la regle de priorite 0 consulte sans suppression.
        par(
            route(255, 1, v4([203, 0, 113, 7]), 32, PHYS),
            passerelle.clone(),
        ),
    ] {
        let mut o = wireguard_pose();
        o.ipv4.routes.push(r);
        assert_eq!(ecarts(&plan_wg(), &o), ["ipv4-routes-before-tunnel"]);
    }
    let mut o = coeur_pose(Some(COMPTE));
    o.ipv6.routes.push(par(
        route(254, 1, v6(&[0x2001, 0xdb8, 5]), 48, PHYS),
        v6(&[0x2001, 0xdb8, 1, 0, 0, 0, 0, 1]),
    ));
    assert_eq!(ecarts(&plan_coeur(), &o), ["ipv6-routes-before-tunnel"]);
}

/// `broadcast` et `anycast` ne livrent pas a l'hote: une route de ces types
/// posee par un tiers emet sur le lien, vers toute sa destination (mesure sur
/// essai-linux, dans `main` comme dans `local`, dans les deux familles). Ils
/// ne sont admis qu'en route hote vers une adresse du reseau exact d'une
/// adresse de la meme interface, et `broadcast` en IPv4 seulement: IPv6 n'a
/// pas de diffusion, et le noyau y traite une telle route en unicast.
#[test]
fn une_diffusion_hors_du_reseau_du_lien_est_un_ecart() {
    for r in [
        route(254, 3, v4([203, 0, 113, 0]), 24, PHYS),
        route(255, 3, v4([203, 0, 113, 0]), 24, PHYS),
        route(255, 3, v4([203, 0, 113, 5]), 32, PHYS),
        route(255, 4, v4([203, 0, 113, 6]), 32, PHYS),
        route(254, 4, v4([203, 0, 113, 0]), 24, PHYS),
        // Le reseau du lien entier en diffusion, pas une route hote.
        route(255, 3, v4([192, 0, 2, 0]), 24, PHYS),
        // Une route hote du reseau du lien, mais par une passerelle.
        par(
            route(255, 3, v4([192, 0, 2, 255]), 32, PHYS),
            v4([192, 0, 2, 1]),
        ),
    ] {
        let mut o = wireguard_pose();
        o.ipv4.routes.push(r.clone());
        assert_eq!(
            ecarts(&plan_wg(), &o),
            ["ipv4-routes-before-tunnel"],
            "{r:?}"
        );
    }
    for r in [
        route(254, 3, v6(&[0x2001, 0xdb8, 9]), 64, PHYS),
        route(255, 3, v6(&[0x2001, 0xdb8, 1, 0, 0, 0, 0, 7]), 128, PHYS),
        route(254, 4, v6(&[0x2001, 0xdb8, 9]), 64, PHYS),
        route(255, 4, v6(&[0x2001, 0xdb8, 9, 0, 0, 0, 0, 5]), 128, PHYS),
    ] {
        let mut o = coeur_pose(Some(COMPTE));
        o.ipv6.routes.push(r.clone());
        assert_eq!(
            ecarts(&plan_coeur(), &o),
            ["ipv6-routes-before-tunnel"],
            "{r:?}"
        );
    }
}

/// La regle de legitimite admet ce qui mene au tunnel, au lien, a l'hote, ou
/// ce qui rejette, et rien d'autre.
#[test]
fn ce_qui_reste_sur_le_lien_ou_rejette_passe_la_regle() {
    let mut o = wireguard_pose();
    o.ipv4.routes.extend([
        route(254, 6, v4([203, 0, 113, 99]), 32, LO),
        route(254, 9, v4([203, 0, 113, 0]), 24, LO),
        route(254, 1, v4([203, 0, 113, 0]), 24, TUN),
    ]);
    // Une route PAR DEFAUT tierce dans `main`: `suppress_prefixlength 0` la
    // rejette, elle ne passe pas avant le tunnel.
    o.ipv6.routes.push(par(
        route(254, 1, vec![], 0, PHYS),
        v6(&[0x2001, 0xdb8, 1, 0, 0, 0, 0, 9]),
    ));
    let (_, observes, e) = comparer(&plan_wg(), &o).unwrap();
    assert_eq!(e, AUCUN);
    let j = observes.ipv4.routes_before_tunnel.unwrap();
    assert_eq!(
        (j.rejecting, j.next_rule, j.tunnel_interface, j.other),
        (1, 1, 1, 0)
    );
    // `local` vers une destination hors de tout reseau du lien: livree a
    // l'hote, rien n'est emis (mesure). Les rejets et `throw` dans `local`.
    let mut o = wireguard_pose();
    o.ipv4.routes.extend([
        route(254, 2, v4([203, 0, 113, 0]), 24, PHYS),
        route(255, 7, v4([203, 0, 113, 0]), 25, LO),
        route(255, 9, v4([203, 0, 113, 128]), 25, LO),
    ]);
    o.ipv6
        .routes
        .push(route(254, 2, v6(&[0x2001, 0xdb8, 9]), 64, PHYS));
    let (_, observes, e) = comparer(&plan_wg(), &o).unwrap();
    assert_eq!(e, AUCUN);
    let j = observes.ipv4.routes_before_tunnel.unwrap();
    assert_eq!(
        (j.local_delivery, j.rejecting, j.next_rule, j.other),
        (5, 1, 1, 0)
    );
    assert_eq!(
        observes.ipv6.routes_before_tunnel.unwrap().local_delivery,
        4
    );
    // Une multidiffusion vers une adresse qui n'en est pas une, non.
    let mut o = wireguard_pose();
    o.ipv4
        .routes
        .push(route(254, 5, v4([203, 0, 113, 0]), 24, PHYS));
    assert_eq!(ecarts(&plan_wg(), &o), ["ipv4-routes-before-tunnel"]);
}

/// Une route hote `broadcast` (IPv4) ou `anycast` vers une adresse du reseau
/// exact d'une adresse de son interface emet sur le lien, vers son propre
/// reseau, comme la route connectee (mesure): admise. Le noyau en pose de
/// lui-meme: la diffusion de chaque reseau IPv4, et l'anycast de routeur de
/// sous-reseau IPv6 quand l'hote route.
#[test]
fn une_route_hote_du_reseau_du_lien_passe_la_regle() {
    let mut o = wireguard_pose();
    o.ipv6.routes.extend([
        route(255, 4, v6(&[0x2001, 0xdb8, 1]), 128, PHYS),
        route(255, 4, v6(&[0x2001, 0xdb8, 1, 0, 0, 0, 0, 7]), 128, PHYS),
        route(255, 4, v6(&[0xfe80]), 128, PHYS),
    ]);
    o.ipv4
        .routes
        .push(route(255, 4, v4([192, 0, 2, 9]), 32, PHYS));
    let (_, observes, e) = comparer(&plan_wg(), &o).unwrap();
    assert_eq!(e, AUCUN);
    assert_eq!(
        observes.ipv4.routes_before_tunnel.unwrap().own_network_host,
        3
    );
    assert_eq!(
        observes.ipv6.routes_before_tunnel.unwrap().own_network_host,
        3
    );
}

/// Les drapeaux d'une route consultee avant le tunnel ne changent pas son
/// jugement: un prochain saut mort la rend inerte (le trafic de son reseau
/// passe alors au tunnel, mesure), et elle peut revivre a tout instant. Une
/// route admise le reste, un ecart le reste.
#[test]
fn un_drapeau_ne_change_pas_le_jugement_d_une_route_avant_le_tunnel() {
    for drapeaux in [1, 16, 17, 4] {
        let mut o = wireguard_pose();
        for r in o.ipv4.routes.iter_mut().filter(|r| r.table == 254) {
            r.drapeaux = drapeaux;
        }
        assert_eq!(ecarts(&plan_wg(), &o), AUCUN, "{drapeaux}");
        let mut mort = par(
            route(254, 1, v4([203, 0, 113, 0]), 24, PHYS),
            v4([192, 0, 2, 1]),
        );
        mort.drapeaux = drapeaux;
        o.ipv4.routes.push(mort);
        assert_eq!(
            ecarts(&plan_wg(), &o),
            ["ipv4-routes-before-tunnel"],
            "{drapeaux}"
        );
    }
}

/// LIMITE NOMMEE: une route connectee est admise quelle que soit la largeur
/// du reseau de son adresse. Une adresse a masque large (bail a masque large,
/// prefixe annonce sur le lien) met sur le lien tout ce qu'elle couvre, et la
/// preuve rend MATCH: le banc le mesure, et le rapport le dit.
#[test]
fn une_adresse_a_masque_large_est_une_limite_nommee() {
    let mut o = wireguard_pose();
    o.ipv4.adresses.push(adresse(PHYS, 1, v4([192, 0, 2, 3])));
    o.ipv4
        .routes
        .push(route(254, 1, v4([128, 0, 0, 0]), 1, PHYS));
    o.ipv6
        .adresses
        .push(adresse(PHYS, 3, v6(&[0x2001, 0xdb8, 1, 0, 0, 0, 0, 3])));
    o.ipv6.routes.push(route(254, 1, v6(&[0x2000]), 3, PHYS));
    let (_, observes, e) = comparer(&plan_wg(), &o).unwrap();
    assert_eq!(e, AUCUN);
    assert_eq!(observes.ipv4.routes_before_tunnel.unwrap().connected, 2);
    assert_eq!(observes.ipv6.routes_before_tunnel.unwrap().connected, 4);
    assert!(LIMITE.contains("quelle que soit la largeur du reseau de son adresse"));
}

/// LIMITE NOMMEE: la multidiffusion part sur le lien. Le noyau pose
/// `ff00::/8` sur chaque interface IPv6, dans `local`, consultee avant le
/// tunnel: une destination de multidiffusion, de toute portee, sort sur le
/// lien physique avec la seule pose du produit (mesure). Comptee a part,
/// admise, dite par le rapport.
#[test]
fn la_multidiffusion_sur_le_lien_est_une_limite_nommee() {
    let mut o = wireguard_pose();
    o.ipv4
        .routes
        .push(route(254, 5, v4([224, 0, 0, 0]), 4, PHYS));
    o.ipv6.routes.push(route(254, 5, v6(&[0xff0e]), 16, PHYS));
    let (_, observes, e) = comparer(&plan_wg(), &o).unwrap();
    assert_eq!(e, AUCUN);
    assert_eq!(
        observes
            .ipv4
            .routes_before_tunnel
            .unwrap()
            .multicast_on_link,
        1
    );
    assert_eq!(
        observes
            .ipv6
            .routes_before_tunnel
            .unwrap()
            .multicast_on_link,
        2
    );
    assert!(LIMITE.contains("la multidiffusion part sur le lien"));
}

// --- encadrement et entrees -------------------------------------------------

/// Un fichier temporaire sans dependance: ecrit, puis efface a la fin.
struct Fichier(PathBuf);

impl Fichier {
    fn nouveau(contenu: &str) -> Self {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static N: AtomicUsize = AtomicUsize::new(0);
        let p = std::env::temp_dir().join(format!(
            "bifrost-routes-{}-{}.json",
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

const WG: &str = r#"{"schema_version":1,"chemin":"wireguard","interface":"bfwg0","fwmark":777001,"table":30303,"coeur_uid":null}"#;

/// La preuve jouee avec une fausse lecture du noyau; rend le rapport et le
/// nombre de lectures demandees.
fn rapport(lectures: Vec<Result<Observation, &'static str>>, texte: &str) -> (Rapport, usize) {
    let f = Fichier::nouveau(texte);
    let mut lectures = lectures.into_iter();
    let mut appels = 0;
    let r = verifier_avec(&f.0, |i| {
        assert_eq!(i, "bfwg0");
        appels += 1;
        lectures.next().expect("lecture de trop")
    });
    (r, appels)
}

#[test]
fn deux_lectures_identiques_font_une_mesure() {
    let (r, appels) = rapport(vec![Ok(wireguard_pose()), Ok(wireguard_pose())], WG);
    assert_eq!((r.verdict, r.code(), appels), ("MATCH", 0, 2));
    assert!(r.live_kernel && r.collection_verified);
    assert_eq!(
        serde_json::to_value(&r).unwrap()["source"],
        "kernel-rtnetlink-read-twice"
    );
    assert_eq!(r.failed_input, None);
    assert_eq!(r.tunnel_interface_present, Some(true));
    let (r, _) = rapport(vec![Ok(systeme()), Ok(systeme())], WG);
    assert_eq!((r.verdict, r.code()), ("MISMATCH", 1));
}

/// Une lecture qui change entre les deux passages n'est ni une correspondance
/// ni un ecart: l'etat n'est pas attribuable. Une lecture refusee ou
/// interrompue non plus.
#[test]
fn deux_lectures_differentes_ne_sont_jamais_une_mesure() {
    let mut autre = wireguard_pose();
    autre.ipv4.regles.insert(1, regle(100, 254));
    for (premiere, seconde) in [
        (wireguard_pose(), autre.clone()),
        (autre.clone(), wireguard_pose()),
    ] {
        let (r, _) = rapport(vec![Ok(premiere), Ok(seconde)], WG);
        assert_eq!((r.verdict, r.code(), r.reason), ("UNMEASURED", 2, INSTABLE));
        assert!(!r.collection_verified && r.differences.is_empty());
        assert_eq!(r.failed_input, Some("observed"));
    }
    for (lectures, attendu) in [
        (vec![Err(trames::ACCES)], trames::ACCES),
        (
            vec![Ok(wireguard_pose()), Err(trames::INTERROMPUE)],
            trames::INTERROMPUE,
        ),
        (vec![Err(trames::FAMILLE_ABSENTE)], trames::FAMILLE_ABSENTE),
    ] {
        let (r, _) = rapport(lectures, WG);
        assert_eq!((r.verdict, r.code(), r.reason), ("UNMEASURED", 2, attendu));
        assert!(r.observed_counts.is_none() && r.differences.is_empty());
    }
}

/// L'intention est lue et validee AVANT tout acces au noyau.
#[test]
fn une_intention_invalide_ne_lit_pas_le_noyau() {
    for texte in [
        "",
        "[]",
        r#"{"schema_version":1,"chemin":"wireguard","interface":"bfwg0","fwmark":777001,"table":30303}"#,
        r#"{"schema_version":1,"chemin":"wireguard","interface":"bfwg0","fwmark":777001,"table":30303,"coeur_uid":null,"x":1}"#,
        r#"{"schema_version":1,"schema_version":1,"chemin":"wireguard","interface":"bfwg0","fwmark":777001,"table":30303,"coeur_uid":null}"#,
        r#"{"schema_version":2,"chemin":"wireguard","interface":"bfwg0","fwmark":777001,"table":30303,"coeur_uid":null}"#,
        r#"{"schema_version":1,"chemin":"autre","interface":"bfwg0","fwmark":777001,"table":30303,"coeur_uid":null}"#,
        r#"{"schema_version":1,"chemin":"wireguard","interface":"lo","fwmark":777001,"table":30303,"coeur_uid":null}"#,
        r#"{"schema_version":1,"chemin":"wireguard","interface":"a b","fwmark":777001,"table":30303,"coeur_uid":null}"#,
        r#"{"schema_version":1,"chemin":"wireguard","interface":"bfwg0bfwg0bfwg0x","fwmark":777001,"table":30303,"coeur_uid":null}"#,
        r#"{"schema_version":1,"chemin":"wireguard","interface":"bfwg0","fwmark":0,"table":30303,"coeur_uid":null}"#,
        r#"{"schema_version":1,"chemin":"wireguard","interface":"bfwg0","fwmark":777001,"table":254,"coeur_uid":null}"#,
        r#"{"schema_version":1,"chemin":"wireguard","interface":"bfwg0","fwmark":777001,"table":null,"coeur_uid":null}"#,
        r#"{"schema_version":1,"chemin":"wireguard","interface":"bfwg0","fwmark":777001,"table":30303,"coeur_uid":1000}"#,
        r#"{"schema_version":1,"chemin":"wireguard","interface":"bfwg0","fwmark":4294967296,"table":30303,"coeur_uid":null}"#,
        r#"{"schema_version":1,"chemin":"wireguard","interface":"bfwg0","fwmark":1.5,"table":30303,"coeur_uid":null}"#,
        r#"{"schema_version":1,"chemin":"wireguard","interface":"bfwg0","fwmark":"1","table":30303,"coeur_uid":null}"#,
        r#"{"schema_version":1,"chemin":"coeur","interface":"bftun0","fwmark":null,"table":null,"coeur_uid":0}"#,
        r#"{"schema_version":1,"chemin":"coeur","interface":"bftun0","fwmark":1,"table":null,"coeur_uid":null}"#,
        r#"{"schema_version":1,"chemin":"coeur","interface":"bftun0","fwmark":null,"table":2847,"coeur_uid":null}"#,
    ] {
        let (r, appels) = rapport(vec![], texte);
        assert_eq!((r.verdict, appels), ("UNMEASURED", 0), "{texte}");
        assert_eq!(r.failed_input, Some("intention"), "{texte}");
        assert!(!r.live_kernel && r.intention_schema_version.is_none());
    }
    let f = Fichier::nouveau(
        r#"{"schema_version":1,"chemin":"coeur","interface":"bftun0","fwmark":null,"table":null,"coeur_uid":4242}"#,
    );
    let r = verifier_avec(&f.0, |i| {
        assert_eq!(i, "bftun0");
        Ok(coeur_pose(Some(COMPTE)))
    });
    assert_eq!(r.verdict, "MATCH");
}

/// Le rapport ne dit que des categories et des comptes: ni interface, ni
/// adresse, ni table, ni marque, ni compte; et ses cles sont celles-ci, pas
/// une de plus.
#[test]
fn le_rapport_n_exporte_ni_adresse_ni_interface_ni_parametre() {
    let mut o = wireguard_pose();
    o.ipv4.routes.push(par(
        route(254, 1, v4([203, 0, 113, 0]), 24, PHYS),
        v4([192, 0, 2, 1]),
    ));
    o.ipv4.regles.insert(1, regle(100, 30_404));
    let (r, _) = rapport(vec![Ok(o.clone()), Ok(o)], WG);
    assert_eq!(r.verdict, "MISMATCH");
    assert_eq!(
        r.differences,
        ["ipv4-rules-before-tunnel", "ipv4-routes-before-tunnel"]
    );
    let v = serde_json::to_value(&r).unwrap();
    let mut cles: Vec<_> = v.as_object().unwrap().keys().cloned().collect();
    cles.sort();
    assert_eq!(
        cles,
        [
            "collection_verified",
            "completed_at_unix_ms",
            "differences",
            "duration_ms",
            "expected_counts",
            "expected_source",
            "failed_input",
            "intention_schema_version",
            "limitation",
            "live_kernel",
            "network_security",
            "observed_counts",
            "reason",
            "schema_version",
            "scope",
            "source",
            "started_at_unix_ms",
            "tunnel_interface_present",
            "verdict",
        ]
    );
    let mut sans_heure = v.clone();
    for c in ["started_at_unix_ms", "completed_at_unix_ms", "duration_ms"] {
        sans_heure.as_object_mut().unwrap().remove(c);
    }
    let texte = sans_heure.to_string() + &r.texte();
    for secret in [
        "bfwg0",
        "30303",
        "30404",
        "777001",
        "203.0.113",
        "192.0.2",
        "4242",
    ] {
        assert!(
            !texte.contains(secret),
            "le rapport exporte {secret}: {texte}"
        );
    }
}

// --- trames ------------------------------------------------------------------

fn attr(genre: u16, valeur: &[u8]) -> Vec<u8> {
    let mut v = ((4 + valeur.len()) as u16).to_ne_bytes().to_vec();
    v.extend(genre.to_ne_bytes());
    v.extend(valeur);
    while !v.len().is_multiple_of(4) {
        v.push(0);
    }
    v
}

fn message(genre: u16, drapeaux: u16, sequence: u32, port: u32, charge: &[u8]) -> Vec<u8> {
    let mut v = trames::entete(16 + charge.len(), genre, drapeaux, sequence, port);
    v.extend(charge);
    v
}

fn attente(genre: u16, dump: bool) -> Attente {
    Attente {
        sequence: 7,
        port: 42,
        genre,
        dump,
        filtre_admis: genre == trames::RTM_NEWROUTE,
    }
}

fn charge_regle(famille: u8, action: u8, drapeaux: u32, attributs: &[Vec<u8>]) -> Vec<u8> {
    let mut v = vec![famille, 0, 0, 0, 254, 0, 0, action];
    v.extend(drapeaux.to_ne_bytes());
    for a in attributs {
        v.extend(a);
    }
    v
}

fn charge_route(famille: u8, dst_len: u8, genre: u8, attributs: &[Vec<u8>]) -> Vec<u8> {
    let mut v = vec![famille, dst_len, 0, 0, 254, 3, 0, genre];
    v.extend(0_u32.to_ne_bytes());
    for a in attributs {
        v.extend(a);
    }
    v
}

fn fin(drapeaux: u16, code: i32) -> Vec<u8> {
    message(trames::NLMSG_DONE, drapeaux, 7, 42, &code.to_ne_bytes())
}

/// Table, suppression et protocole: ce que le noyau ecrit toujours.
fn obligatoires() -> Vec<Vec<u8>> {
    vec![
        attr(15, &254_u32.to_ne_bytes()),
        attr(14, &u32::MAX.to_ne_bytes()),
        attr(21, &[2]),
    ]
}

/// `not fwmark 777001 table 30303` a la priorite 32765, comme le noyau
/// l'ecrit.
fn regle_marque() -> Vec<u8> {
    charge_regle(
        trames::AF_INET,
        1,
        0x2,
        &[
            attr(15, &TABLE_WG.to_ne_bytes()),
            attr(14, &u32::MAX.to_ne_bytes()),
            attr(21, &[3]),
            attr(6, &32765_u32.to_ne_bytes()),
            attr(10, &MARQUE.to_ne_bytes()),
            attr(16, &u32::MAX.to_ne_bytes()),
        ],
    )
}

#[test]
fn une_regle_se_lit_entierement() {
    let r = trames::regle(trames::AF_INET, &regle_marque()).unwrap();
    assert_eq!(r, hors_marque(32765));
    // Plage de comptes, suppression 0, priorite nulle (que le noyau omet).
    let mut a = obligatoires();
    a[1] = attr(14, &0_u32.to_ne_bytes());
    a.push(attr(
        20,
        &[COMPTE.to_ne_bytes(), COMPTE.to_ne_bytes()].concat(),
    ));
    let r = trames::regle(trames::AF_INET6, &charge_regle(trames::AF_INET6, 1, 0, &a)).unwrap();
    assert_eq!(r.pref, 0);
    assert_eq!(r.suppression_prefixe, Some(0));
    assert_eq!(r.selecteurs.compte, Some((COMPTE, COMPTE)));
}

#[test]
fn une_regle_hors_forme_est_refusee() {
    // Coupee a chaque octet: seules les coupures entre deux attributs, une
    // fois table, suppression et protocole lus, rendent une regle (plus
    // courte); un dernier attribut sans son bourrage est admis, comme le
    // noyau l'admet.
    let bonne = regle_marque();
    assert_eq!(bonne.len(), 60);
    for n in 0..bonne.len() {
        let lue = trames::regle(trames::AF_INET, &bonne[..n]);
        assert_eq!(lue.is_ok(), [33, 34, 35, 36, 44, 52].contains(&n), "{n}");
    }
    let mut autre_famille = bonne.clone();
    autre_famille[0] = trames::AF_INET6;
    assert!(trames::regle(trames::AF_INET, &autre_famille).is_err());

    let avec = |extra: Vec<Vec<u8>>| [obligatoires(), extra].concat();
    let mut table_courte = obligatoires();
    table_courte[0] = attr(15, &[0; 2]);
    for (action, drapeaux, attributs) in [
        // FR_ACT_RES3, FR_ACT_UNSPEC, drapeau inconnu.
        (4, 0, obligatoires()),
        (0, 0, obligatoires()),
        (1, 0x40, obligatoires()),
        // Attribut inconnu, FRA_UNUSED2, table de mauvaise taille, doublon.
        (1, 0, avec(vec![attr(31, &[0])])),
        (1, 0, avec(vec![attr(5, &[0; 4])])),
        (1, 0, table_courte),
        (1, 0, avec(vec![attr(6, &[0; 4]), attr(6, &[0; 4])])),
        // Destination sans longueur, attribut niche, attribut en ordre reseau.
        (1, 0, avec(vec![attr(1, &[0; 4])])),
        (1, 0, avec(vec![attr(6 | 0x8000, &[0; 4])])),
        (1, 0, avec(vec![attr(6 | 0x4000, &[0; 4])])),
    ] {
        let c = charge_regle(trames::AF_INET, action, drapeaux, &attributs);
        assert!(
            trames::regle(trames::AF_INET, &c).is_err(),
            "{action} {drapeaux} {attributs:?}"
        );
    }
    // Sans table, sans suppression ou sans protocole: incomplete.
    for sans in 0..3 {
        let mut a = obligatoires();
        a.remove(sans);
        let c = charge_regle(trames::AF_INET, 1, 0, &a);
        assert!(trames::regle(trames::AF_INET, &c).is_err(), "{sans}");
    }
}

#[test]
fn une_route_se_lit_sans_ses_valeurs_d_etat() {
    let base = [
        attr(15, &TABLE_WG.to_ne_bytes()),
        attr(4, &TUN.to_ne_bytes()),
        attr(6, &1024_u32.to_ne_bytes()),
    ];
    let r = trames::route(
        trames::AF_INET6,
        &charge_route(trames::AF_INET6, 0, 1, &base),
    )
    .unwrap();
    assert_eq!(
        (r.table, r.oif, r.genre, r.dst_len),
        (TABLE_WG, Some(TUN), 1, 0)
    );
    assert!(!r.expire);
    // Les compteurs et les temps de RTA_CACHEINFO changent seuls: lus, pas
    // compares. Son echeance (`rta_expires`, a l'octet 8), si: elle dit que
    // la route cessera d'etre consultee.
    let cache = |expire: i32| {
        let mut c = [7_u8; 32];
        c[8..12].copy_from_slice(&expire.to_ne_bytes());
        attr(12, &c)
    };
    let lire = |extra: Vec<u8>| {
        let mut a = base.to_vec();
        a.push(extra);
        trames::route(trames::AF_INET6, &charge_route(trames::AF_INET6, 0, 1, &a)).unwrap()
    };
    assert_eq!(lire(cache(0)), r);
    for echeance in [cache(300), cache(-3), attr(23, &[9; 8])] {
        let s = lire(echeance);
        assert!(s.expire);
        assert_eq!(Route { expire: false, ..s }, r);
    }
    // Une destination, une passerelle.
    let r = trames::route(
        trames::AF_INET,
        &charge_route(
            trames::AF_INET,
            24,
            1,
            &[
                attr(15, &254_u32.to_ne_bytes()),
                attr(1, &[203, 0, 113, 0]),
                attr(5, &[192, 0, 2, 1]),
                attr(4, &PHYS.to_ne_bytes()),
            ],
        ),
    )
    .unwrap();
    assert_eq!(r.dst, [203, 0, 113, 0]);
    assert_eq!(r.passerelle.as_deref(), Some(&[192_u8, 0, 2, 1][..]));
}

#[test]
fn une_route_hors_forme_est_refusee() {
    let table = attr(15, &254_u32.to_ne_bytes());
    let avec = |extra: Vec<u8>| vec![table.clone(), extra];
    for (dst_len, genre, attributs, drapeaux) in [
        // RTN_UNSPEC, RTN_NAT, sans table.
        (0, 0, vec![table.clone()], 0_u32),
        (0, 10, vec![table.clone()], 0),
        (0, 1, vec![], 0),
        // RTA_MARK et RTA_PROTOINFO, qu'un dump ne porte pas.
        (0, 1, avec(attr(16, &[0; 4])), 0),
        (0, 1, avec(attr(10, &[0; 4])), 0),
        // Destination sans longueur, longueur sans destination.
        (0, 1, avec(attr(1, &[0; 4])), 0),
        (24, 1, vec![table.clone()], 0),
        // Passerelle d'une autre taille, RTM_F_CLONED, doublon, niche.
        (0, 1, avec(attr(5, &[0; 16])), 0),
        (0, 1, vec![table.clone()], 0x200),
        (0, 1, avec(table.clone()), 0),
        (0, 1, avec(attr(4 | 0x8000, &[0; 4])), 0),
        // Information de cache d'une autre taille que `rta_cacheinfo`.
        (0, 1, avec(attr(12, &[0; 16])), 0),
    ] {
        let mut c = charge_route(trames::AF_INET, dst_len, genre, &attributs);
        c[8..12].copy_from_slice(&drapeaux.to_ne_bytes());
        assert!(
            trames::route(trames::AF_INET, &c).is_err(),
            "{genre} {attributs:?}"
        );
    }
}

/// Les drapeaux de route que le lecteur admet sont ceux dont l'effet sur
/// l'emission a ete mesure: RTNH_F_DEAD, RTNH_F_ONLINK, RTNH_F_LINKDOWN. Les
/// autres (delestage materiel, piegeage, drapeaux de requete, bits que l'UAPI
/// ne definit pas) rendent la collecte non mesuree.
#[test]
fn un_drapeau_de_route_non_mesure_rend_la_collecte_non_mesuree() {
    let lire = |drapeaux: u32| {
        let mut c = charge_route(
            trames::AF_INET6,
            0,
            1,
            &[
                attr(15, &TABLE_WG.to_ne_bytes()),
                attr(4, &TUN.to_ne_bytes()),
            ],
        );
        c[8..12].copy_from_slice(&drapeaux.to_ne_bytes());
        trames::route(trames::AF_INET6, &c)
    };
    for admis in [0, 1, 4, 16, 1 | 16, 4 | 16, 1 | 4 | 16] {
        assert_eq!(lire(admis).map(|r| r.drapeaux), Ok(admis), "{admis:#x}");
    }
    for refuse in [
        2,
        8,
        32,
        64,
        0x80,
        0x100,
        0x400,
        0x800,
        0x1000,
        0x2000,
        0x4000,
        0x8000,
        0x2000_0000,
        0x8000_0000,
    ] {
        assert!(lire(refuse).is_err(), "{refuse:#x}");
        assert!(lire(refuse | 1).is_err(), "{refuse:#x}");
    }
}

/// Un dump: chaque message a la bonne sequence, le bon port, le drapeau
/// multi-parties; il se termine par NLMSG_DONE sans erreur, et rien ne suit.
#[test]
fn un_dump_se_lit_jusqu_a_sa_fin_et_pas_au_dela() {
    let a = attente(trames::RTM_NEWRULE, true);
    let donnee = message(trames::RTM_NEWRULE, 0x2, 7, 42, &regle_marque());
    let lire = |d: &[u8]| {
        let mut charges = Vec::new();
        let mut total = 0;
        trames::lire_datagramme(d, &a, &mut charges, &mut total, 1 << 20)
            .map(|s| (s, charges.len()))
    };
    assert_eq!(lire(&donnee), Ok((Suite::Encore, 1)));
    assert_eq!(
        lire(&[donnee.clone(), fin(0x2, 0)].concat()),
        Ok((Suite::Fini, 1))
    );
    let interrompue = message(trames::RTM_NEWRULE, 0x12, 7, 42, &regle_marque());
    for (mauvais, raison) in [
        // NLM_F_DUMP_INTR, sur un message ou sur la fin.
        (
            [interrompue, fin(0x2, 0)].concat(),
            Some(trames::INTERROMPUE),
        ),
        (
            [donnee.clone(), fin(0x12, 0)].concat(),
            Some(trames::INTERROMPUE),
        ),
        // Fin sur une erreur du noyau; un message apres la fin.
        ([donnee.clone(), fin(0x2, -4)].concat(), None),
        ([donnee.clone(), fin(0x2, 0), donnee.clone()].concat(), None),
        // Autre sequence, autre port, sans NLM_F_MULTI, drapeau non admis.
        (
            message(trames::RTM_NEWRULE, 0x2, 8, 42, &regle_marque()),
            None,
        ),
        (
            message(trames::RTM_NEWRULE, 0x2, 7, 43, &regle_marque()),
            None,
        ),
        (
            message(trames::RTM_NEWRULE, 0, 7, 42, &regle_marque()),
            None,
        ),
        (
            message(trames::RTM_NEWRULE, 0x22, 7, 42, &regle_marque()),
            None,
        ),
        // Autre type, accuse de reception, vide, tronque.
        (
            message(trames::RTM_NEWROUTE, 0x2, 7, 42, &regle_marque()),
            None,
        ),
        (
            message(trames::NLMSG_ERROR, 0, 7, 42, &0_i32.to_ne_bytes()),
            None,
        ),
        (Vec::new(), None),
        (donnee[..donnee.len() - 1].to_vec(), None),
    ] {
        let lu = lire(&mauvais);
        assert!(lu.is_err(), "{mauvais:?}");
        if let Some(raison) = raison {
            assert_eq!(lu, Err(raison));
        }
    }
    // Seules les routes admettent NLM_F_DUMP_FILTERED: elles sont demandees
    // sans leurs exceptions.
    let r = attente(trames::RTM_NEWROUTE, true);
    let route = charge_route(trames::AF_INET, 0, 1, &[attr(15, &254_u32.to_ne_bytes())]);
    let mut charges = Vec::new();
    let mut total = 0;
    assert_eq!(
        trames::lire_datagramme(
            &message(trames::RTM_NEWROUTE, 0x22, 7, 42, &route),
            &r,
            &mut charges,
            &mut total,
            1 << 20
        ),
        Ok(Suite::Encore)
    );
    // La memoire est bornee.
    let mut charges = Vec::new();
    let mut total = 0;
    assert!(trames::lire_datagramme(&donnee, &a, &mut charges, &mut total, 10).is_err());
}

#[test]
fn un_refus_du_noyau_n_est_jamais_une_absence() {
    for (code, dump, attendu) in [
        (-1_i32, true, Err(trames::ACCES)),
        (-13, true, Err(trames::ACCES)),
        (-97, true, Err(trames::FAMILLE_ABSENTE)),
        (-19, false, Ok(Suite::Absent)),
        (-19, true, Err("requete netlink refusee par le noyau")),
        (-22, false, Err("requete netlink refusee par le noyau")),
    ] {
        let a = attente(trames::RTM_NEWLINK, dump);
        let mut charges = Vec::new();
        let mut total = 0;
        let d = message(trames::NLMSG_ERROR, 0, 7, 42, &code.to_ne_bytes());
        assert_eq!(
            trames::lire_datagramme(&d, &a, &mut charges, &mut total, 1 << 20),
            attendu,
            "{code}"
        );
    }
}

#[test]
fn le_lien_du_tunnel_se_reconnait_a_son_nom() {
    let lien = |index: i32, attributs: &[Vec<u8>]| {
        let mut c = vec![0_u8; 16];
        c[4..8].copy_from_slice(&index.to_ne_bytes());
        for a in attributs {
            c.extend(a);
        }
        c
    };
    let nom = attr(3, b"bfwg0\0");
    // Les autres attributs d'un lien ne sont pas lus, doublons compris.
    let mtu = attr(4, &1420_u32.to_ne_bytes());
    let c = lien(3, &[mtu.clone(), nom.clone(), mtu.clone()]);
    assert_eq!(trames::lien(&c, "bfwg0"), Ok(3));
    assert!(trames::lien(&c, "bfwg1").is_err());
    for mauvais in [
        lien(0, std::slice::from_ref(&nom)),
        lien(-1, std::slice::from_ref(&nom)),
        lien(3, std::slice::from_ref(&mtu)),
        lien(3, &[nom.clone(), nom.clone()]),
        lien(3, &[attr(3, b"bfwg0")]),
        lien(3, &[nom.clone(), vec![8, 0, 4, 0]]),
    ] {
        assert!(trames::lien(&mauvais, "bfwg0").is_err(), "{mauvais:?}");
    }
    // La requete porte le nom, termine par un octet nul, et rien d'autre.
    let q = trames::requete_lien("bfwg0", 7, 42);
    assert_eq!(q.len(), 16 + 16 + 12);
    assert_eq!(&q[36..42], b"bfwg0\0");
    // Une requete de dump n'a aucun filtre: tout est nul hors la famille.
    let d = trames::requete_dump(trames::RTM_GETROUTE, trames::AF_INET6, 7, 42);
    assert_eq!(d.len(), 28);
    assert_eq!(d[16], trames::AF_INET6);
    assert!(d[17..].iter().all(|o| *o == 0));
    let d = trames::requete_dump(trames::RTM_GETADDR, trames::AF_INET, 7, 42);
    assert_eq!(d.len(), 24);
}

/// Les categories qui ne dependent pas de l'etiquette (regles tierces et routes
/// avant le tunnel) sont vues en mode daemon exactement comme en mode intention:
/// `exiger_etiquette` ne touche qu'aux regles du produit et a la route du
/// tunnel.
#[test]
fn en_mode_daemon_les_categories_sans_etiquette_restent_vues() {
    let mut o = etiquete(wireguard_pose(), TABLE_WG);
    o.ipv4.regles.insert(1, regle(100, 254));
    assert_eq!(ecarts_daemon(&plan_wg(), &o), ["ipv4-rules-before-tunnel"]);

    let mut o = etiquete(wireguard_pose(), TABLE_WG);
    o.ipv4.routes.push(par(
        route(254, 1, v4([203, 0, 113, 0]), 24, PHYS),
        v4([192, 0, 2, 1]),
    ));
    assert_eq!(ecarts_daemon(&plan_wg(), &o), ["ipv4-routes-before-tunnel"]);
}

// --- mode daemon: le protocole et la reconstruction du plan -----------------
//
// Linux seulement: un faux daemon ecoute sur un vrai socket Unix, sert des
// trames `declaration-routage`, et le client y lit l'identite du serveur par
// SO_PEERCRED. Le lecteur (`declaration::lire_routage`) et le protocole
// (`declaration::encadrer`) sont communs a `prove nft/wfp` et ont leurs recettes
// dans `preuve_nft_daemon`; ce qui est propre au routage - l'analyse stricte de
// la reponse (`analyser_routage`) et la reconstruction du plan
// (`plan_de_la_declaration`) - est ce que ces recettes-ci tiennent, sur le noyau
// FABRIQUE des recettes ci-dessus. Le noyau REEL face a un vrai daemon est au
// banc `e2e-linux.sh`, qui mesure la correspondance tunnel monte, encore apres
// reprise, et l'absence de plan apres deconnexion.
#[cfg(target_os = "linux")]
mod protocole_daemon {
    use super::{
        COMPTE, MARQUE, PROTOCOLES_TIERS, TABLE_WG, coeur_pose, etiquete, posee_a, wireguard_pose,
    };
    use crate::declaration::{CLES_ROUTAGE, HORS_SCHEMA, Refus, lire_routage, lire_routage_avec};
    use crate::preuve_routes::{Observation, verifier_declaration_avec};
    use bifrost_ipc::ServerRequirement;
    use bifrost_ipc::protocol::{
        CheminRoutage, DECLARATION_ROUTAGE_VERSION, DeclarationRoutage, EtatRoutage, PlanRoutage,
        Response,
    };
    use serde_json::{Value, json};
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    const INSTANCE: &str = "0123456789abcdef0123456789abcdef0123456789abcdef";

    /// L'uid effectif de ce processus, comme `preuve_nft_daemon`: le faux daemon
    /// tourne sous lui, et SO_PEERCRED rend precisement cet uid.
    fn mon_uid() -> u32 {
        std::fs::read_to_string("/proc/self/status")
            .unwrap()
            .lines()
            .find_map(|l| l.strip_prefix("Uid:"))
            .and_then(|champs| champs.split_whitespace().nth(1))
            .and_then(|u| u.parse().ok())
            .expect("uid effectif lisible dans /proc/self/status")
    }

    /// L'exigence des recettes de PROTOCOLE: le faux daemon a l'uid de la
    /// recette. La regle de PRODUCTION (`lire_routage`, root) a sa propre recette
    /// plus bas.
    fn recette() -> ServerRequirement {
        ServerRequirement::Uid(mon_uid())
    }

    /// Le plan que le peripherique declare, accorde aux fabriques du noyau:
    /// interface `bfwg0`, marque et table de WireGuard, sans compte.
    fn decl_wg() -> PlanRoutage {
        PlanRoutage {
            chemin: CheminRoutage::Wireguard,
            interface: "bfwg0".into(),
            fwmark: Some(MARQUE),
            table: Some(TABLE_WG),
            coeur_uid: None,
        }
    }

    /// Le plan du coeur declare: interface `bftun0`, ni marque ni table, avec ou
    /// sans compte.
    fn decl_coeur(compte: Option<u32>) -> PlanRoutage {
        PlanRoutage {
            chemin: CheminRoutage::Coeur,
            interface: "bftun0".into(),
            fwmark: None,
            table: None,
            coeur_uid: compte,
        }
    }

    /// La reponse telle que le VRAI daemon l'ecrit: le type du protocole et la
    /// projection du plan, pas un JSON tape a la main. Si l'un des deux derive,
    /// le lecteur strict le voit ici avant de le voir en production.
    fn trame(application: u64, issue: EtatRoutage, plan: Option<PlanRoutage>) -> Vec<u8> {
        let d = DeclarationRoutage {
            schema_version: DECLARATION_ROUTAGE_VERSION,
            instance: INSTANCE.into(),
            application,
            issue,
            plan,
        };
        let mut v = serde_json::to_vec(&Response::DeclarationRoutage(Box::new(d))).unwrap();
        v.push(b'\n');
        v
    }

    fn posee_wg() -> Vec<u8> {
        trame(4, EtatRoutage::Pose, Some(decl_wg()))
    }

    fn noyau_wg() -> Observation {
        etiquete(wireguard_pose(), TABLE_WG)
    }

    fn modifier(trame: &[u8], cle: &str, valeur: Value) -> Vec<u8> {
        let mut v: Value = serde_json::from_slice(trame).unwrap();
        v[cle] = valeur;
        let mut t = serde_json::to_vec(&v).unwrap();
        t.push(b'\n');
        t
    }

    /// Change un champ du sous-objet `plan`.
    fn modifier_plan(trame: &[u8], cle: &str, valeur: Value) -> Vec<u8> {
        let mut v: Value = serde_json::from_slice(trame).unwrap();
        v["plan"][cle] = valeur;
        let mut t = serde_json::to_vec(&v).unwrap();
        t.push(b'\n');
        t
    }

    /// Un faux daemon sur un vrai socket Unix: il sert ses trames dans l'ordre
    /// (la derniere se repete), verifie que la requete est exactement celle du
    /// protocole du routage, et compte les requetes.
    struct FauxDaemon {
        dossier: PathBuf,
        socket: String,
        requetes: Arc<AtomicUsize>,
        tache: tokio::task::JoinHandle<()>,
    }

    impl FauxDaemon {
        fn dossier() -> PathBuf {
            static SUIVANT: AtomicUsize = AtomicUsize::new(0);
            let n = SUIVANT.fetch_add(1, Ordering::SeqCst);
            let d = std::env::temp_dir().join(format!("bfroute-{}-{n}", std::process::id()));
            let _ = std::fs::remove_dir_all(&d);
            std::fs::create_dir(&d).unwrap();
            d
        }

        fn demarrer(trames: Vec<Vec<u8>>) -> Self {
            let dossier = Self::dossier();
            let chemin = dossier.join("d.sock");
            let ecoute = tokio::net::UnixListener::bind(&chemin).unwrap();
            let requetes = Arc::new(AtomicUsize::new(0));
            let compte = requetes.clone();
            let tache = tokio::spawn(async move {
                loop {
                    let Ok((flux, _)) = ecoute.accept().await else {
                        return;
                    };
                    let (lecture, mut ecriture) = tokio::io::split(flux);
                    let mut ligne = String::new();
                    if BufReader::new(lecture).read_line(&mut ligne).await.is_err() {
                        continue;
                    }
                    assert_eq!(
                        ligne, "{\"version\":1,\"command\":\"declaration-routage\"}\n",
                        "requete inattendue"
                    );
                    let n = compte.fetch_add(1, Ordering::SeqCst);
                    let t = &trames[n.min(trames.len() - 1)];
                    let _ = ecriture.write_all(t).await;
                    let _ = ecriture.shutdown().await;
                }
            });
            Self {
                socket: chemin.to_string_lossy().into_owned(),
                dossier,
                requetes,
                tache,
            }
        }

        fn requetes(&self) -> usize {
            self.requetes.load(Ordering::SeqCst)
        }
    }

    impl Drop for FauxDaemon {
        fn drop(&mut self) {
            self.tache.abort();
            let _ = std::fs::remove_dir_all(&self.dossier);
        }
    }

    async fn prouver(daemon: &FauxDaemon, noyau: &Observation) -> Value {
        let socket = daemon.socket.clone();
        let noyau = noyau.clone();
        let noyau_ref = &noyau;
        let r = verifier_declaration_avec(
            || lire_routage_avec(&socket, Duration::from_secs(2), recette()),
            |_i: &str| -> Result<Observation, &'static str> { Ok(noyau_ref.clone()) },
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
        v
    }

    async fn sans_collecte(daemon: &FauxDaemon) -> Value {
        let socket = daemon.socket.clone();
        let r = verifier_declaration_avec(
            || lire_routage_avec(&socket, Duration::from_secs(2), recette()),
            |_i: &str| -> Result<Observation, &'static str> {
                panic!("collecte interdite sans plan a comparer")
            },
        )
        .await;
        serde_json::to_value(&r).unwrap()
    }

    /// Rien de la declaration ne sort dans le rapport. Les horodatages sont
    /// retires avant la recherche: un instant en millisecondes contient tot ou
    /// tard `30303` ou `4242`, et la recette rougirait sur une coincidence.
    fn rien_de_la_declaration(rapport: &Value) {
        let mut sans_horloge = rapport.clone();
        for cle in ["started_at_unix_ms", "completed_at_unix_ms", "duration_ms"] {
            sans_horloge.as_object_mut().unwrap().remove(cle);
        }
        let texte = sans_horloge.to_string();
        for interdit in ["bfwg0", "bftun0", "777001", "30303", "4242", INSTANCE] {
            assert!(
                !texte.contains(interdit),
                "le rapport exporte {interdit}: {texte}"
            );
        }
        for cle in ["application", "instance", "issue", "plan"] {
            assert!(rapport.get(cle).is_none(), "cle exportee: {cle}");
        }
    }

    /// Un plan declare, conforme au noyau etiquete du produit: correspondance,
    /// dans les deux chemins. Le rapport dit d'ou vient l'attendu, et deux
    /// requetes encadrent la collecte.
    #[tokio::test]
    async fn un_plan_declare_conforme_au_noyau_correspond() {
        let daemon = FauxDaemon::demarrer(vec![posee_wg()]);
        let r = prouver(&daemon, &noyau_wg()).await;
        assert_eq!(r["verdict"], "MATCH", "{r}");
        assert_eq!(r["schema_version"], 1);
        assert_eq!(r["scope"], "linux-routing-comparison");
        assert_eq!(r["expected_source"], "daemon-declared-active-routing-plan");
        assert_eq!(r["source"], "kernel-rtnetlink-read-twice");
        assert_eq!(r["live_kernel"], true);
        assert_eq!(r["collection_verified"], true);
        assert!(r["failed_input"].is_null());
        assert_eq!(r["tunnel_interface_present"], true);
        // Pas d'intention en mode daemon.
        assert!(r["intention_schema_version"].is_null());
        // Le nom de la regle, jamais sa valeur.
        assert_eq!(r["daemon_identity"], "uid-peer-credentials");
        assert_eq!(daemon.requetes(), 2, "N1 puis N2");
        rien_de_la_declaration(&r);

        // Le chemin du coeur, avec compte.
        let daemon = FauxDaemon::demarrer(vec![trame(
            4,
            EtatRoutage::Pose,
            Some(decl_coeur(Some(COMPTE))),
        )]);
        let r = prouver(&daemon, &etiquete(coeur_pose(Some(COMPTE)), 2847)).await;
        assert_eq!(r["verdict"], "MATCH", "{r}");
    }

    /// Un plan declare different de ce que le noyau porte est un ecart, jamais
    /// une correspondance: l'attendu est reconstruit du plan declare, pas du
    /// noyau. Marque et table alterees seulement: le noyau fabrique de ces
    /// recettes ignore le nom de l'interface, que seul un vrai noyau resout en
    /// index. Le nom declare different a ete mesure hors depot, par un faux
    /// daemon face a un vrai noyau: `bfwg1`/`bfwg9` et `bftun1`/`bftun9`
    /// declares contre une pose de `bfwg0`/`bftun0` rendent l'ecart de la table
    /// du tunnel dans les deux familles, jamais une correspondance.
    #[tokio::test]
    async fn un_plan_declare_different_du_noyau_est_un_ecart() {
        let variantes: [fn(&mut PlanRoutage); 2] = [
            |p: &mut PlanRoutage| p.fwmark = Some(MARQUE + 1),
            |p: &mut PlanRoutage| p.table = Some(TABLE_WG + 1),
        ];
        for changer in variantes {
            let mut plan = decl_wg();
            changer(&mut plan);
            let daemon = FauxDaemon::demarrer(vec![trame(4, EtatRoutage::Pose, Some(plan))]);
            let r = prouver(&daemon, &noyau_wg()).await;
            assert_eq!(r["verdict"], "MISMATCH", "{r}");
            assert!(!r["differences"].as_array().unwrap().is_empty());
            assert_eq!(daemon.requetes(), 2);
            rien_de_la_declaration(&r);
        }
    }

    /// Le cablage de l'exigence d'etiquette, par le chemin de PRODUCTION
    /// (`verifier_declaration_avec`): un noyau qui porte le plan declare a
    /// l'identique, mais a un autre originateur que l'etiquette du produit,
    /// n'est pas la pose du daemon. Ecart des regles du produit et de la table
    /// du tunnel, dans les deux familles et les deux chemins, jamais une
    /// correspondance. Le comparateur seul a ses recettes plus haut; celle-ci
    /// tient l'appel que le mode daemon en fait.
    #[tokio::test]
    async fn un_noyau_sans_l_etiquette_du_produit_n_est_pas_la_pose_du_daemon() {
        let quatre = json!([
            "ipv4-product-rules",
            "ipv4-tunnel-table",
            "ipv6-product-rules",
            "ipv6-tunnel-table"
        ]);
        for p in PROTOCOLES_TIERS {
            let daemon = FauxDaemon::demarrer(vec![posee_wg()]);
            let r = prouver(&daemon, &posee_a(wireguard_pose(), TABLE_WG, p)).await;
            assert_eq!(r["verdict"], "MISMATCH", "protocole {p}: {r}");
            assert_eq!(r["differences"], quatre, "protocole {p}");
            assert_eq!(r["collection_verified"], true, "protocole {p}");
            assert_eq!(daemon.requetes(), 2, "protocole {p}");
            rien_de_la_declaration(&r);

            let daemon = FauxDaemon::demarrer(vec![trame(
                4,
                EtatRoutage::Pose,
                Some(decl_coeur(Some(COMPTE))),
            )]);
            let r = prouver(&daemon, &posee_a(coeur_pose(Some(COMPTE)), 2847, p)).await;
            assert_eq!(r["verdict"], "MISMATCH", "coeur, protocole {p}: {r}");
            assert_eq!(r["differences"], quatre, "coeur, protocole {p}");
            rien_de_la_declaration(&r);
        }
    }

    /// La moindre difference entre N1 et N2 rend la collecte non attribuable,
    /// meme quand le noyau est conforme a N1.
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
            (
                "autre plan",
                modifier_plan(&n1, "table", json!(TABLE_WG + 1)),
            ),
            ("retrait", trame(5, EtatRoutage::Aucun, None)),
        ] {
            let daemon = FauxDaemon::demarrer(vec![n1.clone(), n2]);
            let r = prouver(&daemon, &noyau_wg()).await;
            assert_eq!(r["verdict"], "UNMEASURED", "{nom}: {r}");
            assert_eq!(
                r["reason"], "declaration du daemon modifiee pendant la collecte",
                "{nom}"
            );
            assert_eq!(r["failed_input"], "daemon-declaration", "{nom}");
            assert_eq!(daemon.requetes(), 2, "{nom}");
            rien_de_la_declaration(&r);
        }
        // Illisible a N2: la raison le distingue d'un changement.
        let daemon = FauxDaemon::demarrer(vec![n1, b"{\"result\"".to_vec()]);
        let r = prouver(&daemon, &noyau_wg()).await;
        assert_eq!(r["verdict"], "UNMEASURED");
        assert_eq!(
            r["reason"],
            "declaration du daemon illisible ou injoignable apres la collecte"
        );
    }

    #[tokio::test]
    async fn un_daemon_absent_n_est_pas_mesure() {
        let daemon = FauxDaemon::demarrer(vec![posee_wg()]);
        let socket = format!("{}.absent", daemon.socket);
        let r = verifier_declaration_avec(
            || lire_routage_avec(&socket, Duration::from_secs(2), recette()),
            |_i: &str| -> Result<Observation, &'static str> {
                panic!("collecte interdite sans declaration")
            },
        )
        .await;
        let r = serde_json::to_value(&r).unwrap();
        assert_eq!(r["verdict"], "UNMEASURED");
        assert_eq!(r["reason"], "daemon injoignable");
        assert_eq!(r["failed_input"], "daemon-declaration");
        assert_eq!(r["live_kernel"], false);
    }

    /// Le refus du daemon (SO_PEERCRED) nomme l'appelant dans son message: jamais
    /// recopie dans une raison.
    #[tokio::test]
    async fn un_acces_refuse_n_est_pas_mesure_et_ne_nomme_personne() {
        let refus = b"{\"result\":\"error\",\"message\":\"acces refuse pour uid=1000 gid=1000 pid=42: ni root\"}\n";
        let daemon = FauxDaemon::demarrer(vec![refus.to_vec()]);
        let r = sans_collecte(&daemon).await;
        assert_eq!(r["verdict"], "UNMEASURED");
        assert_eq!(r["reason"], "acces au daemon refuse");
        rien_de_la_declaration(&r);
    }

    /// L'analyse stricte de la reponse de routage: cle en trop, cle manquante,
    /// doublon, sous-objet `plan` mal forme, incoherence entre l'etat et le plan.
    /// Rien ne se mesure, et rien de la declaration ne sort.
    #[tokio::test]
    async fn une_reponse_hors_schema_n_est_pas_mesuree() {
        let bonne = posee_wg();
        let mut cas: Vec<(&str, Vec<u8>)> = vec![
            ("sans fin de ligne", bonne[..bonne.len() - 1].to_vec()),
            ("coupee", bonne[..bonne.len() / 2].to_vec()),
            ("vide", Vec::new()),
            ("tableau", b"[]\n".to_vec()),
            ("erreur sans message", b"{\"result\":\"error\"}\n".to_vec()),
        ];
        // Cle en trop au niveau superieur.
        let mut v: Value = serde_json::from_slice(&bonne).unwrap();
        v.as_object_mut()
            .unwrap()
            .insert("en_trop".into(), json!(1));
        let mut t = serde_json::to_vec(&v).unwrap();
        t.push(b'\n');
        cas.push(("cle en trop", t));
        // Chaque cle superieure retiree.
        for cle in CLES_ROUTAGE {
            let mut v: Value = serde_json::from_slice(&bonne).unwrap();
            v.as_object_mut().unwrap().remove(cle);
            let mut t = serde_json::to_vec(&v).unwrap();
            t.push(b'\n');
            cas.push((cle, t));
        }
        // Doublon d'une cle superieure: `Unique` le refuse en profondeur.
        let mut doublon = bonne[..bonne.len() - 2].to_vec();
        doublon.extend_from_slice(b",\"issue\":\"pose\"}\n");
        cas.push(("cle superieure dupliquee", doublon));
        // Sous-objet plan: cle en trop, cle manquante.
        let mut v: Value = serde_json::from_slice(&bonne).unwrap();
        v["plan"]
            .as_object_mut()
            .unwrap()
            .insert("x".into(), json!(1));
        let mut t = serde_json::to_vec(&v).unwrap();
        t.push(b'\n');
        cas.push(("cle en trop dans le plan", t));
        let mut v: Value = serde_json::from_slice(&bonne).unwrap();
        v["plan"].as_object_mut().unwrap().remove("interface");
        let mut t = serde_json::to_vec(&v).unwrap();
        t.push(b'\n');
        cas.push(("cle manquante dans le plan", t));
        // Valeurs invalides et incoherences.
        for (nom, cle, valeur) in [
            ("version", "schema_version", json!(2)),
            ("instance vide", "instance", json!("")),
            (
                "instance majuscule",
                "instance",
                json!(INSTANCE.to_uppercase()),
            ),
            ("numero negatif", "application", json!(-1)),
            ("issue inconnue", "issue", json!("inconnue")),
            ("pose sans plan", "plan", Value::Null),
        ] {
            cas.push((nom, modifier(&bonne, cle, valeur)));
        }
        // Numero flottant.
        let flottant = String::from_utf8(bonne.clone())
            .unwrap()
            .replace("\"application\":4", "\"application\":4.0")
            .into_bytes();
        cas.push(("numero flottant", flottant));
        // Plan incoherent avec son chemin: WireGuard sans marque, coeur avec
        // marque.
        cas.push((
            "wireguard sans marque",
            modifier_plan(&bonne, "fwmark", Value::Null),
        ));
        let coeur = trame(4, EtatRoutage::Pose, Some(decl_coeur(Some(COMPTE))));
        cas.push((
            "coeur avec marque",
            modifier_plan(&coeur, "fwmark", json!(1)),
        ));
        // Etat sans plan portant un plan, et l'inverse.
        cas.push((
            "aucun avec plan",
            modifier(
                &trame(0, EtatRoutage::Aucun, None),
                "plan",
                serde_json::to_value(decl_wg()).unwrap(),
            ),
        ));
        cas.push((
            "pose au numero zero",
            trame(0, EtatRoutage::Pose, Some(decl_wg())),
        ));
        for (nom, t) in cas {
            let daemon = FauxDaemon::demarrer(vec![t]);
            let r = sans_collecte(&daemon).await;
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
            rien_de_la_declaration(&r);
        }
    }

    /// La forme Windows de la declaration, bien formee, offerte au lecteur
    /// Linux: jamais lue comme un plan Linux, ni comme "rien de pose". Chaque
    /// etat (pose par WireGuard, pose par le coeur, aucun, non applicable) est
    /// refuse hors schema par l'analyse, et la preuve ne collecte rien.
    #[tokio::test]
    async fn une_declaration_de_la_forme_windows_n_est_pas_mesuree() {
        use bifrost_ipc::protocol::{
            DECLARATION_ROUTAGE_WINDOWS_VERSION, DeclarationRoutageWindows, FamilleRoutage,
            PlanRoutageWindows,
        };
        let windows = |application: u64, issue: EtatRoutage, plan: Option<PlanRoutageWindows>| {
            let d = DeclarationRoutageWindows {
                schema_version: DECLARATION_ROUTAGE_WINDOWS_VERSION,
                instance: INSTANCE.into(),
                application,
                issue,
                plan,
            };
            let mut v =
                serde_json::to_vec(&Response::DeclarationRoutageWindows(Box::new(d))).unwrap();
            v.push(b'\n');
            v
        };
        let wg = PlanRoutageWindows {
            chemin: CheminRoutage::Wireguard,
            interface: "bfwg0".into(),
            mtu: 1420,
            familles: vec![FamilleRoutage::Ipv4, FamilleRoutage::Ipv6],
            destinations: Some(vec!["198.51.100.0/24".parse().unwrap()]),
        };
        let coeur = PlanRoutageWindows {
            chemin: CheminRoutage::Coeur,
            interface: "bftun0".into(),
            mtu: 1420,
            familles: vec![FamilleRoutage::Ipv4],
            destinations: None,
        };
        for (nom, t) in [
            ("pose wireguard", windows(4, EtatRoutage::Pose, Some(wg))),
            ("pose coeur", windows(4, EtatRoutage::Pose, Some(coeur))),
            ("aucun", windows(0, EtatRoutage::Aucun, None)),
            (
                "non applicable",
                windows(0, EtatRoutage::NonApplicable, None),
            ),
        ] {
            assert_eq!(
                crate::declaration::analyser_routage(&t).map(|_| ()),
                Err(HORS_SCHEMA),
                "{nom}"
            );
            let daemon = FauxDaemon::demarrer(vec![t]);
            let r = sans_collecte(&daemon).await;
            assert_eq!(r["verdict"], "UNMEASURED", "{nom}: {r}");
            assert_eq!(r["reason"], HORS_SCHEMA, "{nom}: {r}");
            assert_eq!(r["failed_input"], "daemon-declaration", "{nom}");
            rien_de_la_declaration(&r);
        }
    }

    /// Une declaration valide qui ne pose aucun plan (ou n'en declare pas):
    /// rien n'est compare, la collecte n'a pas lieu.
    #[tokio::test]
    async fn sans_plan_pose_rien_n_est_compare() {
        for (issue, application, raison) in [
            (
                EtatRoutage::Aucun,
                0,
                "aucun plan de routage pose par ce daemon: rien a comparer",
            ),
            (
                EtatRoutage::NonApplicable,
                0,
                "le daemon ne declare pas de plan de routage",
            ),
        ] {
            let daemon = FauxDaemon::demarrer(vec![trame(application, issue, None)]);
            let r = sans_collecte(&daemon).await;
            assert_eq!(r["verdict"], "UNMEASURED", "{issue:?}");
            assert_eq!(r["reason"], raison);
            assert_eq!(r["live_kernel"], false);
            assert_eq!(daemon.requetes(), 1, "pas de N2 sans plan");
        }
    }

    /// Un plan hors du perimetre de la reference (interface `lo`, marque nulle,
    /// table reservee au noyau, compte root) ne se compare jamais: la collecte
    /// n'a meme pas lieu. La declaration passe l'analyse de schema, c'est la
    /// reconstruction du plan qui refuse.
    #[tokio::test]
    async fn un_plan_hors_perimetre_n_est_jamais_une_correspondance() {
        let mut lo = decl_wg();
        lo.interface = "lo".into();
        let mut marque_nulle = decl_wg();
        marque_nulle.fwmark = Some(0);
        let mut table_reservee = decl_wg();
        table_reservee.table = Some(255);
        let mut coeur_root = decl_coeur(Some(0));
        coeur_root.interface = "bftun0".into();
        for plan in [lo, marque_nulle, table_reservee, coeur_root] {
            let daemon = FauxDaemon::demarrer(vec![trame(4, EtatRoutage::Pose, Some(plan))]);
            let r = sans_collecte(&daemon).await;
            assert_eq!(r["verdict"], "UNMEASURED", "{r}");
            assert!(
                r["reason"].as_str().unwrap().contains("hors perimetre"),
                "{r}"
            );
            assert_eq!(r["live_kernel"], false);
            assert_eq!(daemon.requetes(), 1);
            rien_de_la_declaration(&r);
        }
    }

    /// La lecture de PRODUCTION (`lire_routage`) exige un serveur root, comme
    /// `prove nft/wfp`. Non root, il n'est pas admis et ne recoit rien; root, il
    /// est admis (la regle dit qui ecoute, pas que c'est le daemon).
    #[tokio::test]
    async fn la_preuve_exige_un_serveur_root() {
        let daemon = FauxDaemon::demarrer(vec![posee_wg()]);
        let socket = daemon.socket.clone();
        let noyau = noyau_wg();
        let noyau_ref = &noyau;
        let root = mon_uid() == 0;
        let r = verifier_declaration_avec(
            || lire_routage(&socket),
            |_i: &str| -> Result<Observation, &'static str> {
                assert!(root, "collecte interdite sans identite admise");
                Ok(noyau_ref.clone())
            },
        )
        .await;
        let code = r.code();
        let r = serde_json::to_value(&r).unwrap();
        if root {
            assert_eq!(r["verdict"], "MATCH", "{r}");
            assert_eq!(r["daemon_identity"], "root-peer-credentials");
            assert_eq!(daemon.requetes(), 2);
        } else {
            assert_eq!(code, 2);
            assert_eq!(r["verdict"], "UNMEASURED", "{r}");
            assert_eq!(r["reason"], "serveur de la declaration non privilegie");
            assert_eq!(r["failed_input"], "daemon-identity");
            assert!(r["daemon_identity"].is_null(), "{r}");
            assert_eq!(r["live_kernel"], false);
            assert_eq!(
                daemon.requetes(),
                0,
                "rien n'est envoye a un serveur refuse"
            );
        }
        rien_de_la_declaration(&r);
    }

    /// L'identite se reverifie a N2: un serveur admis pour N1 et refuse pour N2
    /// ne laisse rien comparer, et le rapport ne garde pas la regle de N1.
    #[tokio::test]
    async fn une_identite_refusee_apres_la_collecte_n_est_pas_mesuree() {
        let d = DeclarationRoutage {
            schema_version: DECLARATION_ROUTAGE_VERSION,
            instance: INSTANCE.into(),
            application: 4,
            issue: EtatRoutage::Pose,
            plan: Some(decl_wg()),
        };
        let noyau = noyau_wg();
        let noyau_ref = &noyau;
        let mut lectures = vec![
            Err(Refus::Identite(
                "identite du serveur de la declaration illisible",
            )),
            Ok((d, "root-peer-credentials")),
        ];
        let r = verifier_declaration_avec(
            || std::future::ready(lectures.pop().unwrap()),
            |_i: &str| -> Result<Observation, &'static str> { Ok(noyau_ref.clone()) },
        )
        .await;
        let r = serde_json::to_value(&r).unwrap();
        assert_eq!(r["verdict"], "UNMEASURED", "{r}");
        assert_eq!(
            r["reason"],
            "identite du serveur de la declaration illisible"
        );
        assert_eq!(r["failed_input"], "daemon-identity");
        assert!(r["daemon_identity"].is_null(), "{r}");
        assert_eq!(r["live_kernel"], true);
    }
}
