//! Regles de routage et routes: le plan du produit confronte au noyau Linux.
//!
//! `prove routes --intention F --actif` lit une intention de routage (chemin
//! WireGuard ou coeur, marque, table, compte du coeur), en tire le plan que le
//! produit pose (`bifrost_core::routage::Plan`, la meme source que
//! `netcfg::add_routing` et `aiguillage::poser`), puis lit le noyau en passif
//! (`preuve_routes_linux`) et compare. Aucune regle, aucune route, aucune
//! interface n'est posee, retiree ou changee.
//!
//! # Ce qui est compare, famille par famille
//!
//! - Les regles du produit (`<famille>-product-rules`): chacune presente une
//!   seule fois, avec son contenu exact (selecteur, table, suppression) et sa
//!   priorite quand le produit en fixe une, et dans l'ordre ou le plan veut que
//!   le noyau les evalue.
//! - Les regles TIERCES evaluees avant la regle qui envoie au tunnel
//!   (`<famille>-rules-before-tunnel`): une consultation d'une autre table que
//!   celle du tunnel, ou un saut (`goto`), peut aiguiller du trafic hors du
//!   tunnel. Exception ecrite: une consultation de la table `local`, dont le
//!   noyau se sert pour ce qui est destine a l'hote lui-meme; c'est son
//!   contenu qui est juge, route par route. Une regle neutre (`nop`) ou qui
//!   rejette (`blackhole`, `unreachable`, `prohibit`) n'aiguille rien ailleurs.
//! - La table du tunnel (`<famille>-tunnel-table`): exactement la route par
//!   defaut du plan, vers l'interface du tunnel, sans passerelle, utilisable
//!   (ni prochain saut mort, ni lien sans porteuse, ni echeance); rien
//!   d'autre.
//! - Les routes que les tables consultees AVANT la regle du tunnel laissent
//!   passer (`<famille>-routes-before-tunnel`): `local` en entier, `main` au
//!   travers de `suppress_prefixlength 0` (seules les routes plus specifiques
//!   que la route par defaut). Regle de legitimite ecrite, sans liste
//!   d'adresses, chaque classe mesuree au banc par un temoin d'emission:
//!   - `tunnel_interface`: une route simple vers l'interface du tunnel;
//!   - `local_delivery`: une route `local`, livree a l'hote sans rien emettre;
//!   - `connected`: la route CONNECTEE d'une adresse de l'interface: unicast,
//!     sans passerelle ni multichemin, sans prefixe source, vers exactement le
//!     reseau (adresse et longueur) d'une adresse portee par la meme
//!     interface;
//!   - `own_network_host`: une route hote `broadcast` (IPv4 seulement) ou
//!     `anycast`, vers une adresse de ce meme reseau exact: elle emet sur le
//!     lien, vers son propre reseau, comme la route connectee;
//!   - `multicast_on_link`: `multicast` vers une destination de
//!     multidiffusion, emise sur le lien: LIMITE NOMMEE;
//!   - `rejecting`: `blackhole`, `unreachable`, `prohibit`;
//!   - `next_rule`: `throw`, qui renvoie a la regle suivante.
//!
//!   Tout le reste est un ecart (`other`): une route plus specifique par une
//!   passerelle, un `0.0.0.0/1`, un prefixe plus large que le lien, une
//!   diffusion ou un anycast hors du reseau du lien, `broadcast` en IPv6.
//!   Les drapeaux d'une route admise ne changent pas son jugement: un prochain
//!   saut mort la rend inerte, et elle peut revivre a tout instant.
//!
//! Deux limites nommees, mesurees: une route connectee est admise quelle que
//! soit la largeur du reseau de son adresse (un masque large met sur le lien
//! tout ce qu'il couvre), et la multidiffusion part sur le lien (le noyau pose
//! `ff00::/8` sur chaque interface IPv6, dans `local`).
//!
//! Un ecart prime: s'il y en a un, MISMATCH. Une collecte impossible,
//! interrompue ou instable rend UNMEASURED, jamais une correspondance.
//!
//! Le rapport ne porte que des categories et des comptes: ni adresse, ni nom
//! d'interface, ni table, ni marque, ni compte.
//!
//! Sous Windows, la commande passe par `preuve_routes_windows`, le jumeau IP
//! Helper: ce module n'y est compile que pour ses recettes, qui comptent sur
//! les deux hotes.
#![cfg_attr(windows, allow(dead_code))]

use std::path::Path;
use std::time::Instant;

use bifrost_core::routage::{
    Consultation, Famille, PROTOCOLE_PRODUIT, Plan, Selecteur, TABLE_LOCAL, TABLE_MAIN,
    TABLES_RESERVEES,
};
use serde::Serialize;
use serde_json::Value;

use crate::declaration::IdentiteDaemon;
use crate::preuve_nft::{Unique, heure};

pub(crate) mod trames;

#[cfg(test)]
mod recettes;

const LIMITE: &str = "Intention declaree, pas le profil actif atteste. Regles et routes du namespace reseau courant, lues deux fois de suite: un changement qui s'annule entre deux lectures echappe, et ce qui est pose apres la collecte n'est pas vu. Deux limites de la regle de legitimite: une route connectee est admise quelle que soit la largeur du reseau de son adresse, et un masque large met sur le lien tout ce qu'il couvre; la multidiffusion part sur le lien, car le noyau pose ff00::/8 sur chaque interface IPv6, dans une table consultee avant le tunnel. Ni les routes deja en cache dans les sockets, ni les connexions ouvertes, ni les exceptions de route (PMTU, redirections), ni le pare-feu, ni le DNS ne sont prouves ici. Pas une preuve d'etancheite du VPN.";

pub(crate) const INSTABLE: &str =
    "collecte instable: deux lectures consecutives du noyau different";

// ---------------------------------------------------------------------------
// Ce que le noyau rend, normalise.
// ---------------------------------------------------------------------------

/// Action d'une regle (`FR_ACT_*`). Hors Linux, seules les recettes en
/// construisent: la lecture des trames n'y sert qu'a elles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) enum Action {
    VersTable,
    Saut,
    Neutre,
    TrouNoir,
    Injoignable,
    Interdit,
}

/// Selecteurs d'une regle. Une regle sans aucun selecteur prend tout.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Selecteurs {
    pub(crate) src: Option<(Vec<u8>, u8)>,
    pub(crate) dst: Option<(Vec<u8>, u8)>,
    pub(crate) tos: u8,
    pub(crate) dscp: Option<(u8, u8)>,
    pub(crate) iif: Option<Vec<u8>>,
    pub(crate) oif: Option<Vec<u8>>,
    /// (marque, masque)
    pub(crate) marque: Option<(u32, u32)>,
    /// (premier, dernier)
    pub(crate) compte: Option<(u32, u32)>,
    pub(crate) protocole_ip: Option<u8>,
    pub(crate) port_source: Option<(u16, u16)>,
    pub(crate) port_destination: Option<(u16, u16)>,
    pub(crate) masque_port_source: Option<u16>,
    pub(crate) masque_port_destination: Option<u16>,
    pub(crate) tunnel_id: Option<u64>,
    pub(crate) l3mdev: Option<u8>,
    pub(crate) flux: Option<u32>,
    pub(crate) etiquette_flux: Option<(u32, u32)>,
}

/// Une regle de politique de routage lue du noyau.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Regle {
    pub(crate) pref: u32,
    pub(crate) action: Action,
    pub(crate) table: u32,
    /// `not` (FIB_RULE_INVERT).
    pub(crate) inverse: bool,
    /// Les autres drapeaux de la regle.
    pub(crate) drapeaux: u32,
    pub(crate) selecteurs: Selecteurs,
    pub(crate) suppression_prefixe: Option<u32>,
    pub(crate) suppression_groupe: Option<u32>,
    pub(crate) cible_saut: Option<u32>,
    /// Qui l'a posee (FRA_PROTOCOL). Lu, jamais compare: il ne change pas la
    /// decision de routage.
    pub(crate) protocole: u8,
}

/// Une route lue du noyau, sans ses valeurs d'etat.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Route {
    pub(crate) table: u32,
    /// `RTN_*`.
    pub(crate) genre: u8,
    pub(crate) dst: Vec<u8>,
    pub(crate) dst_len: u8,
    pub(crate) src: Vec<u8>,
    pub(crate) src_len: u8,
    pub(crate) tos: u8,
    pub(crate) protocole: u8,
    pub(crate) portee: u8,
    pub(crate) drapeaux: u32,
    pub(crate) oif: Option<u32>,
    pub(crate) iif: Option<u32>,
    pub(crate) passerelle: Option<Vec<u8>>,
    pub(crate) via: Option<Vec<u8>>,
    pub(crate) multichemin: Option<Vec<u8>>,
    pub(crate) prochain_saut: Option<u32>,
    pub(crate) encapsulation: Option<Vec<u8>>,
    pub(crate) metrique: Option<u32>,
    pub(crate) source_preferee: Option<Vec<u8>>,
    pub(crate) metriques: Option<Vec<u8>>,
    pub(crate) flux: Option<u32>,
    pub(crate) preference: Option<u8>,
    /// La route porte une echeance (`RTF_EXPIRES`, IPv6). Seule sa presence
    /// est gardee: le compte a rebours change seul entre deux lectures. Une
    /// route echue n'est plus consultee par le noyau alors que le dump la
    /// montre encore (mesure sur essai-linux, noyau 7.0).
    pub(crate) expire: bool,
}

/// Une adresse portee par une interface: ce qu'il faut pour reconnaitre sa
/// route connectee.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Adresse {
    pub(crate) index: u32,
    pub(crate) prefixe: u8,
    pub(crate) adresse: Vec<u8>,
}

/// Une famille, telle que le noyau la rend.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Vue {
    /// Dans l'ordre du dump, qui est l'ordre d'evaluation du noyau.
    pub(crate) regles: Vec<Regle>,
    pub(crate) routes: Vec<Route>,
    pub(crate) adresses: Vec<Adresse>,
}

/// Une lecture complete du noyau.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Observation {
    /// L'index de l'interface du tunnel, `None` si elle n'existe pas.
    pub(crate) tunnel: Option<u32>,
    pub(crate) ipv4: Vue,
    pub(crate) ipv6: Vue,
}

impl Observation {
    fn vue(&self, f: Famille) -> &Vue {
        match f {
            Famille::Ipv4 => &self.ipv4,
            Famille::Ipv6 => &self.ipv6,
        }
    }
}

/// L'encadrement de la collecte: deux lectures completes, qui doivent etre
/// identiques. Le noyau n'a pas de numero de generation pour les regles et les
/// routes, et ne pose NLM_F_DUMP_INTR ni sur l'un ni sur l'autre de ces dumps
/// (voir `preuve_routes_linux`): c'est la comparaison qui tient lieu de
/// garde. Elle ne prouve pas qu'il a existe un instant ou le noyau portait
/// exactement cet etat, seulement que deux lectures successives l'ont rendu.
pub(crate) fn encadrer<L>(mut lire: L) -> Result<Observation, &'static str>
where
    L: FnMut() -> Result<Observation, &'static str>,
{
    let premiere = lire()?;
    let seconde = lire()?;
    if premiere != seconde {
        return Err(INSTABLE);
    }
    Ok(premiere)
}

// ---------------------------------------------------------------------------
// L'intention, et le plan qu'elle designe.
// ---------------------------------------------------------------------------

const CLES: [&str; 6] = [
    "schema_version",
    "chemin",
    "interface",
    "fwmark",
    "table",
    "coeur_uid",
];

fn entier(v: &Value) -> Result<Option<u32>, &'static str> {
    match v {
        Value::Null => Ok(None),
        Value::Number(n) => n
            .as_u64()
            .and_then(|n| u32::try_from(n).ok())
            .map(Some)
            .ok_or("types d'intention de routage invalides"),
        _ => Err("types d'intention de routage invalides"),
    }
}

/// L'intention de routage v1, lue strictement: les six cles, toutes
/// presentes; `chemin` vaut `wireguard` ou `coeur`. WireGuard exige une marque
/// non nulle et une table qui n'est pas reservee au noyau, sans compte de
/// coeur; le coeur n'a ni marque ni table (la sienne est fixee par le
/// produit), et un compte non nul ou null. Le nom d'interface suit la regle
/// du produit (1 a 15 caracteres, alphanumeriques, `-` et `_`), sans `lo`.
pub fn plan_de_l_intention(v: Value) -> Result<Plan, &'static str> {
    let objet = v.as_object().ok_or("intention de routage invalide")?;
    if objet.len() != CLES.len() || CLES.iter().any(|c| !objet.contains_key(*c)) {
        return Err("champs d'intention de routage manquants ou inconnus");
    }
    if entier(&objet["schema_version"])? != Some(1) {
        return Err("version d'intention de routage inconnue");
    }
    let interface = objet["interface"]
        .as_str()
        .ok_or("types d'intention de routage invalides")?;
    if interface.is_empty()
        || interface.len() > 15
        || interface == "lo"
        || !interface
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err("interface d'intention de routage invalide");
    }
    let marque = entier(&objet["fwmark"])?;
    let table = entier(&objet["table"])?;
    let compte = entier(&objet["coeur_uid"])?;
    match objet["chemin"].as_str() {
        Some("wireguard") => {
            let (Some(marque), Some(table), None) = (marque, table, compte) else {
                return Err("chemin WireGuard: marque et table exigees, pas de compte de coeur");
            };
            if marque == 0 {
                return Err("marque nulle interdite");
            }
            if TABLES_RESERVEES.contains(&table) {
                return Err("table reservee du noyau: hors perimetre de la reference");
            }
            Ok(Plan::wireguard(interface, marque, table))
        }
        Some("coeur") => {
            if marque.is_some() || table.is_some() {
                return Err("chemin par coeur: ni marque ni table dans l'intention");
            }
            if compte == Some(0) {
                return Err("compte de coeur root interdit");
            }
            Ok(Plan::coeur(interface, compte))
        }
        _ => Err("chemin d'intention de routage inconnu"),
    }
}

// ---------------------------------------------------------------------------
// La comparaison.
// ---------------------------------------------------------------------------

/// Une regle du plan, sous la forme ou le noyau la rend.
#[derive(Debug, Clone, Copy)]
struct Attendue {
    pref: Option<u32>,
    consultation: Consultation,
    selecteur: Selecteur,
}

impl Attendue {
    /// Le contenu exact que `ip rule add` fait porter au noyau pour cette
    /// regle: `not fwmark M` devient la marque M, le masque que le noyau
    /// complete a 0xffffffff quand aucun n'est donne, et le drapeau
    /// d'inversion; `uidrange U-U` la plage (U, U); `suppress_prefixlength 0`
    /// la suppression 0. Aucun autre selecteur, aucun autre drapeau.
    ///
    /// `exiger_etiquette` (mode daemon): la regle doit AUSSI porter l'etiquette
    /// du produit ([`PROTOCOLE_PRODUIT`]). En mode intention elle est ignoree,
    /// car l'intention ne dit rien de qui a pose; en mode daemon, on sait que le
    /// daemon pose avec elle, donc une regle identique sans etiquette n'est pas
    /// la sienne.
    fn correspond(&self, r: &Regle, exiger_etiquette: bool) -> bool {
        let mut selecteurs = Selecteurs::default();
        let mut inverse = false;
        match self.selecteur {
            Selecteur::Tout => {}
            Selecteur::HorsMarque(m) => {
                selecteurs.marque = Some((m, u32::MAX));
                inverse = true;
            }
            Selecteur::Compte(u) => selecteurs.compte = Some((u, u)),
        }
        r.action == Action::VersTable
            && r.table == self.consultation.table()
            && r.inverse == inverse
            && r.drapeaux == 0
            && r.selecteurs == selecteurs
            && r.suppression_prefixe == self.consultation.suppression()
            && r.suppression_groupe.is_none()
            && r.cible_saut.is_none()
            && self.pref.is_none_or(|p| p == r.pref)
            && (!exiger_etiquette || r.protocole == PROTOCOLE_PRODUIT)
    }
}

/// Les categories d'ecart, dans l'ordre ou le rapport les ecrit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Categorie {
    ReglesProduit,
    ReglesAvantTunnel,
    TableTunnel,
    RoutesAvantTunnel,
}

fn nom(f: Famille, c: Categorie) -> &'static str {
    match (f, c) {
        (Famille::Ipv4, Categorie::ReglesProduit) => "ipv4-product-rules",
        (Famille::Ipv4, Categorie::ReglesAvantTunnel) => "ipv4-rules-before-tunnel",
        (Famille::Ipv4, Categorie::TableTunnel) => "ipv4-tunnel-table",
        (Famille::Ipv4, Categorie::RoutesAvantTunnel) => "ipv4-routes-before-tunnel",
        (Famille::Ipv6, Categorie::ReglesProduit) => "ipv6-product-rules",
        (Famille::Ipv6, Categorie::ReglesAvantTunnel) => "ipv6-rules-before-tunnel",
        (Famille::Ipv6, Categorie::TableTunnel) => "ipv6-tunnel-table",
        (Famille::Ipv6, Categorie::RoutesAvantTunnel) => "ipv6-routes-before-tunnel",
    }
}

/// Comptes attendus d'une famille.
#[derive(Debug, Default, Serialize, PartialEq, Eq)]
pub(crate) struct Attendus {
    product_rules: usize,
    tunnel_routes: usize,
}

/// Ce que la regle de legitimite a dit des routes consultees avant le tunnel,
/// classe par classe (voir l'en-tete du module).
#[derive(Debug, Default, Serialize, PartialEq, Eq)]
pub(crate) struct Jugees {
    tunnel_interface: usize,
    local_delivery: usize,
    connected: usize,
    own_network_host: usize,
    /// Limite nommee: comptee, admise.
    multicast_on_link: usize,
    rejecting: usize,
    next_rule: usize,
    /// Aucune des classes admises: chacune est un ecart.
    other: usize,
}

/// Comptes observes d'une famille. `null` pour ce qui n'a pas pu etre juge
/// faute de regle du tunnel.
#[derive(Debug, Default, Serialize, PartialEq, Eq)]
pub(crate) struct Observes {
    rules: usize,
    routes: usize,
    addresses: usize,
    product_rules_found: usize,
    tunnel_table_routes: usize,
    rules_before_tunnel: Option<usize>,
    third_party_rules_before_tunnel: Option<usize>,
    routes_before_tunnel: Option<Jugees>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub(crate) struct ParFamille<T> {
    ipv4: T,
    ipv6: T,
}

enum Classe {
    Tunnel,
    LivraisonLocale,
    Connectee,
    HoteDuReseau,
    MultidiffusionSurLeLien,
    Rejet,
    RegleSuivante,
    Autre,
}

fn masquer(adresse: &[u8], longueur: u8) -> Vec<u8> {
    adresse
        .iter()
        .enumerate()
        .map(|(i, octet)| {
            let bits = (longueur as usize).saturating_sub(i * 8).min(8);
            if bits == 0 {
                0
            } else {
                octet & (0xffu8 << (8 - bits))
            }
        })
        .collect()
}

fn multidiffusion(f: Famille, r: &Route) -> bool {
    match f {
        Famille::Ipv4 => r.dst_len >= 4 && r.dst.first().is_some_and(|o| o & 0xf0 == 0xe0),
        Famille::Ipv6 => r.dst_len >= 8 && r.dst.first() == Some(&0xff),
    }
}

/// Chaque classe admise a ete mesuree par un temoin d'emission (compteurs
/// d'emission de l'interface physique et de celle du tunnel), dans `main` et
/// dans `local`, dans les deux familles: voir le banc.
fn classer(f: Famille, r: &Route, tunnel: Option<u32>, adresses: &[Adresse]) -> Classe {
    let simple = r.multichemin.is_none() && r.prochain_saut.is_none() && r.encapsulation.is_none();
    let directe = r.passerelle.is_none() && r.via.is_none();
    // Sur le lien, sans passerelle ni prefixe source ni interface d'entree:
    // ce que la route emet va a sa destination, sur son interface.
    let sur_le_lien = simple && directe && r.src_len == 0 && r.iif.is_none();
    // Le reseau exact (adresse masquee et longueur) d'une adresse portee par
    // l'interface de la route.
    let adresse_du_lien = |a: &&Adresse| r.oif == Some(a.index);
    let pleine = (r.dst.len() * 8) as u8;
    match r.genre {
        // RTN_BLACKHOLE, RTN_UNREACHABLE, RTN_PROHIBIT: rejet, rien n'est emis.
        6..=8 => Classe::Rejet,
        // RTN_THROW: la recherche passe a la regle suivante.
        9 => Classe::RegleSuivante,
        // RTN_LOCAL: livre a l'hote, par la boucle locale, rien n'est emis.
        2 if simple && directe => Classe::LivraisonLocale,
        // Unicast, diffusion, anycast ou multidiffusion vers le tunnel.
        1 | 3..=5 if simple && tunnel.is_some() && r.oif == tunnel => Classe::Tunnel,
        // RTN_UNICAST: la route connectee d'une adresse de l'interface.
        1 if sur_le_lien
            && r.dst_len > 0
            && adresses
                .iter()
                .filter(adresse_du_lien)
                .any(|a| a.prefixe == r.dst_len && masquer(&a.adresse, a.prefixe) == r.dst) =>
        {
            Classe::Connectee
        }
        // RTN_BROADCAST (IPv4 seulement) et RTN_ANYCAST: une route hote vers
        // une adresse du reseau exact d'une adresse de l'interface. Le noyau
        // pose ainsi l'adresse de diffusion d'un reseau IPv4 et l'anycast de
        // routeur de sous-reseau IPv6.
        3 | 4
            if (r.genre == 4 || f == Famille::Ipv4)
                && sur_le_lien
                && r.dst_len > 0
                && r.dst_len == pleine
                && adresses
                    .iter()
                    .filter(adresse_du_lien)
                    .any(|a| masquer(&r.dst, a.prefixe) == masquer(&a.adresse, a.prefixe)) =>
        {
            Classe::HoteDuReseau
        }
        // RTN_MULTICAST vers une destination de multidiffusion: emise sur le
        // lien. Limite nommee.
        5 if simple && directe && multidiffusion(f, r) => Classe::MultidiffusionSurLeLien,
        _ => Classe::Autre,
    }
}

fn juger(
    f: Famille,
    vue: &Vue,
    table: u32,
    suppression: Option<u32>,
    tunnel: Option<u32>,
    jugees: &mut Jugees,
) {
    for r in vue.routes.iter().filter(|r| r.table == table) {
        // `suppress_prefixlength N` rejette une decision dont le prefixe a une
        // longueur de N ou moins: ces routes ne passent pas avant le tunnel.
        if suppression.is_some_and(|s| u32::from(r.dst_len) <= s) {
            continue;
        }
        match classer(f, r, tunnel, &vue.adresses) {
            Classe::Tunnel => jugees.tunnel_interface += 1,
            Classe::LivraisonLocale => jugees.local_delivery += 1,
            Classe::Connectee => jugees.connected += 1,
            Classe::HoteDuReseau => jugees.own_network_host += 1,
            Classe::MultidiffusionSurLeLien => jugees.multicast_on_link += 1,
            Classe::Rejet => jugees.rejecting += 1,
            Classe::RegleSuivante => jugees.next_rule += 1,
            Classe::Autre => jugees.other += 1,
        }
    }
}

/// La comparaison d'une famille. Les ecarts sont ajoutes a `ecarts`.
fn comparer_famille(
    plan: &Plan,
    f: Famille,
    obs: &Observation,
    ecarts: &mut Vec<&'static str>,
    exiger_etiquette: bool,
) -> Result<(Attendus, Observes), &'static str> {
    let vue = obs.vue(f);
    let t = plan.table_du_tunnel();
    let attendues: Vec<Attendue> = plan
        .ordre_d_evaluation(f)
        .ok_or("plan de routage sans ordre d'evaluation defini")?
        .iter()
        .map(|r| Attendue {
            pref: r.priorite,
            consultation: r.consultation,
            selecteur: r.selecteur,
        })
        .collect();
    let routes_attendues = plan.routes(f);
    let attendus = Attendus {
        product_rules: attendues.len(),
        tunnel_routes: routes_attendues.len(),
    };
    let mut o = Observes {
        rules: vue.regles.len(),
        routes: vue.routes.len(),
        addresses: vue.adresses.len(),
        ..Observes::default()
    };

    // 1. Les regles du produit: chacune une seule fois, a sa place.
    let du_produit: Vec<Option<usize>> = vue
        .regles
        .iter()
        .map(|r| {
            attendues
                .iter()
                .position(|a| a.correspond(r, exiger_etiquette))
        })
        .collect();
    let mut positions = Vec::new();
    let mut ecart = false;
    for (j, _) in attendues.iter().enumerate() {
        let trouvees: Vec<usize> = (0..vue.regles.len())
            .filter(|&i| du_produit[i] == Some(j))
            .collect();
        if let [i] = trouvees.as_slice() {
            positions.push(*i);
        } else {
            ecart = true;
        }
    }
    o.product_rules_found = positions.len();
    if ecart || !positions.windows(2).all(|p| p[0] < p[1]) {
        ecarts.push(nom(f, Categorie::ReglesProduit));
    }

    // 2. La table du tunnel: exactement la route du plan, utilisable, rien
    // d'autre. Le noyau ignore une route au prochain saut mort, ou sans
    // porteuse des que `ignore_routes_with_linkdown` vaut 1 (sysctl lu a
    // chaque recherche), et une route echue: le trafic passe alors a la
    // regle suivante, hors du tunnel (mesure). `onlink` est admis: il ne
    // change pas l'emission (mesure).
    let dans_t: Vec<&Route> = vue.routes.iter().filter(|r| r.table == t).collect();
    o.tunnel_table_routes = dans_t.len();
    let conforme = |r: &Route| {
        r.drapeaux & (trames::RTNH_F_DEAD | trames::RTNH_F_LINKDOWN) == 0
            && !r.expire
            && r.genre == 1
            && r.dst_len == 0
            && r.src_len == 0
            && r.tos == 0
            && obs.tunnel.is_some()
            && r.oif == obs.tunnel
            && r.iif.is_none()
            && r.passerelle.is_none()
            && r.via.is_none()
            && r.multichemin.is_none()
            && r.prochain_saut.is_none()
            && r.encapsulation.is_none()
            // Mode daemon: la route du tunnel doit porter l'etiquette du produit.
            // Une route par defaut identique posee par un tiers, sans etiquette,
            // n'est pas celle que le daemon declare avoir posee.
            && (!exiger_etiquette || r.protocole == PROTOCOLE_PRODUIT)
    };
    if dans_t.len() != routes_attendues.len() || !dans_t.iter().all(|r| conforme(r)) {
        ecarts.push(nom(f, Categorie::TableTunnel));
    }

    // 3. Ce qui est evalue avant la regle qui envoie au tunnel. Sans cette
    // regle, rien n'aiguille vers le tunnel et l'avant n'a pas de sens:
    // l'ecart est deja dit par la categorie des regles du produit.
    let tunnel_j = attendues
        .iter()
        .position(|a| a.consultation == Consultation::Table(t))
        .ok_or("plan de routage sans regle vers le tunnel")?;
    let ancre = (0..vue.regles.len()).find(|&i| du_produit[i] == Some(tunnel_j));
    if let Some(ancre) = ancre {
        let mut tiers = 0;
        let mut consultees: Vec<(u32, Option<u32>)> = Vec::new();
        for (i, r) in vue.regles[..ancre].iter().enumerate() {
            match du_produit[i] {
                Some(j) => match attendues[j].consultation {
                    Consultation::MainSansDefaut => consultees.push((TABLE_MAIN, Some(0))),
                    // Le compte du coeur sort par `main`: c'est la sortie voulue.
                    Consultation::Main | Consultation::Table(_) => {}
                },
                None => match r.action {
                    Action::VersTable if r.table == TABLE_LOCAL => {
                        consultees.push((TABLE_LOCAL, r.suppression_prefixe));
                    }
                    Action::VersTable if r.table == t => {}
                    Action::VersTable | Action::Saut => tiers += 1,
                    Action::Neutre | Action::TrouNoir | Action::Injoignable | Action::Interdit => {}
                },
            }
        }
        consultees.sort();
        consultees.dedup();
        let mut jugees = Jugees::default();
        for (table, suppression) in consultees {
            juger(f, vue, table, suppression, obs.tunnel, &mut jugees);
        }
        o.rules_before_tunnel = Some(ancre);
        o.third_party_rules_before_tunnel = Some(tiers);
        if tiers > 0 {
            ecarts.push(nom(f, Categorie::ReglesAvantTunnel));
        }
        if jugees.other > 0 {
            ecarts.push(nom(f, Categorie::RoutesAvantTunnel));
        }
        o.routes_before_tunnel = Some(jugees);
    }
    Ok((attendus, o))
}

/// Ce que la comparaison rend: comptes attendus, comptes observes, ecarts.
pub(crate) type Comparaison = (
    ParFamille<Attendus>,
    ParFamille<Observes>,
    Vec<&'static str>,
);

/// La comparaison entiere en mode intention: l'etiquette du produit n'est pas
/// exigee (l'intention ne dit rien de qui a pose).
pub(crate) fn comparer(plan: &Plan, obs: &Observation) -> Result<Comparaison, &'static str> {
    comparer_avec(plan, obs, false)
}

/// La comparaison entiere: les deux familles, les ecarts dans un ordre fixe.
/// `exiger_etiquette` vaut vrai en mode daemon: le plan vient de ce qui l'a
/// pose, qui met l'etiquette du produit, donc une regle ou une route du plan
/// sans etiquette est un ecart de sa categorie.
pub(crate) fn comparer_avec(
    plan: &Plan,
    obs: &Observation,
    exiger_etiquette: bool,
) -> Result<Comparaison, &'static str> {
    let mut ecarts = Vec::new();
    let (a4, o4) = comparer_famille(plan, Famille::Ipv4, obs, &mut ecarts, exiger_etiquette)?;
    let (a6, o6) = comparer_famille(plan, Famille::Ipv6, obs, &mut ecarts, exiger_etiquette)?;
    Ok((
        ParFamille { ipv4: a4, ipv6: a6 },
        ParFamille { ipv4: o4, ipv6: o6 },
        ecarts,
    ))
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
    /// La collecte de cet hote: `kernel-rtnetlink-read-twice` sous Linux;
    /// `null` ailleurs, ou rien du noyau n'est lu.
    source: Option<&'static str>,
    expected_source: &'static str,
    intention_schema_version: Option<u32>,
    live_kernel: bool,
    collection_verified: bool,
    network_security: &'static str,
    /// Le nom de la regle qui a admis le serveur de la declaration, en mode
    /// daemon; `null` en mode intention (pas de serveur), ou tant qu'elle n'est
    /// pas etablie. Jamais un uid, un pid ou un SID.
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
        scope: "linux-routing-comparison",
        verdict: "UNMEASURED",
        started_at_unix_ms: heure(),
        completed_at_unix_ms: None,
        duration_ms: 0,
        source: Some("kernel-rtnetlink-read-twice"),
        expected_source: "bifrost-routing-plan-v1-user-declared",
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

/// La preuve, separee de sa collecte pour que les recettes la jouent avec une
/// fausse lecture du noyau. `lire` recoit le nom de l'interface du tunnel et
/// rend UNE lecture complete; l'encadrement (deux lectures identiques) est
/// fait ici.
pub(crate) fn verifier_avec<L>(intention: &Path, mut lire: L) -> Rapport
where
    L: FnMut(&str) -> Result<Observation, &'static str>,
{
    let debut = Instant::now();
    let mut r = commencer();
    let resultat = (|| {
        let Unique(v) = serde_json::from_slice(&crate::preuve_nft::lire(intention)?)
            .map_err(|_| "intention de routage JSON invalide ou ambigue")?;
        let plan = plan_de_l_intention(v)?;
        r.intention_schema_version = Some(1);
        r.failed_input = Some("observed");
        // Lire et valider l'intention AVANT tout acces au noyau.
        let interface = plan.interface.clone();
        let obs = encadrer(|| lire(&interface))?;
        r.live_kernel = true;
        r.collection_verified = true;
        r.tunnel_interface_present = Some(obs.tunnel.is_some());
        let (attendus, observes, ecarts) = comparer(&plan, &obs)?;
        r.expected_counts = Some(attendus);
        r.observed_counts = Some(observes);
        r.failed_input = None;
        r.verdict = if ecarts.is_empty() {
            "MATCH"
        } else {
            "MISMATCH"
        };
        r.differences = ecarts;
        Ok(())
    })();
    r.reason = match resultat {
        Ok(()) => {
            "regles et routes des deux familles comparees au plan du produit; seuls l'originateur des regles et les valeurs d'etat des routes sont ignores"
        }
        Err(raison) => raison,
    };
    r.completed_at_unix_ms = heure();
    r.duration_ms = debut.elapsed().as_millis();
    r
}

/// `prove routes --intention F --actif`, hors Windows (voir
/// `preuve_routes_windows`).
#[cfg(not(windows))]
pub fn verifier(intention: &Path) -> Rapport {
    #[cfg(target_os = "linux")]
    {
        verifier_avec(intention, crate::preuve_routes_linux::lire_une_fois)
    }
    #[cfg(not(target_os = "linux"))]
    {
        // Rien du noyau n'est lu ici: le rapport ne nomme aucune source.
        let mut r = verifier_avec(intention, |_| {
            Err("collecte des routes disponible uniquement sous Linux et Windows")
        });
        r.source = None;
        r
    }
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

/// La limite propre au mode daemon: l'attendu est declare par le peripherique,
/// pas par l'appelant, et une declaration n'est jamais une observation.
const LIMITE_DAEMON: &str = "Plan declare par le peripherique du tunnel, relu avant et apres la collecte, pas observe: une correspondance dit que le noyau porte le plan que le peripherique dit avoir pose. Regles et routes du namespace reseau courant, lues deux fois de suite: un changement qui s'annule entre deux lectures echappe, et ce qui est pose apres la collecte n'est pas vu. Deux limites de la regle de legitimite: une route connectee est admise quelle que soit la largeur du reseau de son adresse, et un masque large met sur le lien tout ce qu'il couvre; la multidiffusion part sur le lien, car le noyau pose ff00::/8 sur chaque interface IPv6. Ni les routes deja en cache, ni les connexions ouvertes, ni les exceptions de route, ni le pare-feu, ni le DNS ne sont prouves ici. Pas une preuve d'etancheite du VPN.";

/// Le plan que la declaration du peripherique designe, reconstruit par le MEME
/// constructeur que le produit (`Plan::wireguard`, `Plan::coeur`): une seule
/// source pour la pose et pour l'attendu. La declaration a deja ete lue
/// strictement (cles, coherence chemin/champs) par `analyser_routage`; il reste
/// a rejeter ce qui sort du perimetre de la reference (interface `lo`, marque
/// nulle, table reservee au noyau, compte root ou partage), comme le fait le
/// lecteur d'intention.
#[cfg(target_os = "linux")]
pub fn plan_de_la_declaration(
    d: &bifrost_ipc::protocol::DeclarationRoutage,
) -> Result<Plan, &'static str> {
    use bifrost_ipc::protocol::{CheminRoutage, EtatRoutage};
    match d.issue {
        EtatRoutage::NonApplicable => Err("le daemon ne declare pas de plan de routage"),
        EtatRoutage::Aucun => Err("aucun plan de routage pose par ce daemon: rien a comparer"),
        EtatRoutage::Pose => {
            let plan = d
                .plan
                .as_ref()
                .ok_or("declaration de routage posee sans plan")?;
            let interface = &plan.interface;
            if interface.is_empty()
                || interface.len() > 15
                || interface == "lo"
                || !interface
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            {
                return Err("interface du plan declare hors perimetre de la reference");
            }
            match plan.chemin {
                CheminRoutage::Wireguard => {
                    let (Some(marque), Some(table)) = (plan.fwmark, plan.table) else {
                        return Err("plan WireGuard declare sans marque ni table");
                    };
                    if marque == 0 {
                        return Err("marque nulle: plan declare hors perimetre de la reference");
                    }
                    if TABLES_RESERVEES.contains(&table) {
                        return Err("table reservee du noyau: plan declare hors perimetre");
                    }
                    Ok(Plan::wireguard(interface, marque, table))
                }
                CheminRoutage::Coeur => {
                    if plan.coeur_uid == Some(0) {
                        return Err("compte de coeur root: plan declare hors perimetre");
                    }
                    Ok(Plan::coeur(interface, plan.coeur_uid))
                }
            }
        }
    }
}

/// `prove routes --politique-daemon --actif`: l'attendu est le plan que le
/// peripherique du tunnel joint par `socket` declare avoir pose, relu avant et
/// apres la collecte du noyau, par le lecteur COMMUN de `declaration`. Hors
/// Windows (voir `preuve_routes_windows`).
#[cfg(not(windows))]
pub async fn verifier_declaration(socket: &str) -> Rapport {
    #[cfg(target_os = "linux")]
    {
        verifier_declaration_avec(
            move || crate::declaration::lire_routage(socket),
            crate::preuve_routes_linux::lire_une_fois,
        )
        .await
    }
    #[cfg(not(target_os = "linux"))]
    {
        // Ni Linux ni Windows: aucune lecture, et le rapport ne nomme aucune
        // source.
        let _ = socket;
        let debut = Instant::now();
        let mut r = commencer_declaration();
        r.source = None;
        r.reason = "plan de routage par declaration disponible uniquement sous Linux et Windows";
        r.completed_at_unix_ms = heure();
        r.duration_ms = debut.elapsed().as_millis();
        r
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
/// avec un faux daemon et une fausse lecture du noyau. N1, la mesure encadree
/// (deux lectures rtnetlink identiques), N2: le protocole commun des preuves
/// par declaration (`declaration::encadrer`), avec son exigence d'identite et
/// ce qu'il en dit au rapport. En mode daemon, l'etiquette du produit est
/// exigee sur les objets du plan.
#[cfg(target_os = "linux")]
pub(crate) async fn verifier_declaration_avec<L, FL, C>(
    lire_declaration: L,
    lire_noyau: C,
) -> Rapport
where
    L: FnMut() -> FL,
    FL: std::future::Future<
            Output = Result<crate::declaration::LueRoutage, crate::declaration::Refus>,
        >,
    C: Fn(&str) -> Result<Observation, &'static str> + Copy,
{
    let debut = Instant::now();
    let mut r = commencer_declaration();
    let resultat = async {
        let (plan, obs) = crate::declaration::encadrer(
            &mut r,
            lire_declaration,
            plan_de_la_declaration,
            async move |r: &mut Rapport, plan: Plan| {
                // Pas d'`intention_schema_version`: en mode daemon il n'y a pas
                // d'intention lue; la source de l'attendu est dite par
                // `expected_source` et `daemon_identity`.
                r.failed_input = Some("observed");
                let interface = plan.interface.clone();
                let obs = encadrer(|| lire_noyau(&interface))?;
                r.live_kernel = true;
                r.collection_verified = true;
                r.tunnel_interface_present = Some(obs.tunnel.is_some());
                Ok((plan, obs))
            },
        )
        .await?;
        let (attendus, observes, ecarts) = comparer_avec(&plan, &obs, true)?;
        r.expected_counts = Some(attendus);
        r.observed_counts = Some(observes);
        r.failed_input = None;
        r.differences = ecarts;
        Ok(())
    }
    .await;
    r.verdict = match &resultat {
        Ok(()) if r.differences.is_empty() => "MATCH",
        Ok(()) => "MISMATCH",
        Err(_) => "UNMEASURED",
    };
    r.reason = match resultat {
        Ok(()) => {
            "regles et routes des deux familles comparees au plan declare par le peripherique; l'etiquette du produit exigee sur les objets du plan"
        }
        Err(raison) => raison,
    };
    r.completed_at_unix_ms = heure();
    r.duration_ms = debut.elapsed().as_millis();
    r
}
