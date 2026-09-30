//! Lecture stricte des trames rtnetlink: regles, routes, adresses, lien.
//!
//! Pur: aucune entree-sortie ici, pour que les recettes le jouent partout sur
//! des trames fabriquees. Les constantes viennent de l'UAPI Linux 7.0
//! (`include/uapi/linux/netlink.h`, `rtnetlink.h`, `fib_rules.h`,
//! `if_addr.h`, `if_link.h`), relue le 30/09/2026.
//!
//! Tout ce qui n'est pas reconnu est refuse, jamais ignore: un attribut de
//! regle ou de route inconnu, un type de route ou une action de regle inconnus,
//! un drapeau netlink inattendu, un drapeau de route dont l'effet n'a pas ete
//! mesure, une longueur fausse, un attribut duplique. La collecte entiere
//! devient alors NON MESUREE. Seules les valeurs d'etat que le noyau change
//! seul (compteurs et temps de `RTA_CACHEINFO`) et le bourrage (`RTA_PAD`,
//! `FRA_PAD`) sont lus puis ecartes de la comparaison des deux lectures; de
//! l'echeance d'une route, seule la presence est gardee.

// Hors Linux, seules les recettes lisent ces trames: la collecte n'existe que
// sous Linux (`preuve_routes_linux`).
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use super::{Action, Adresse, Regle, Route, Selecteurs};

// netlink.h
pub(crate) const NLMSG_ERROR: u16 = 2;
pub(crate) const NLMSG_DONE: u16 = 3;
pub(crate) const NLM_F_REQUEST: u16 = 0x1;
pub(crate) const NLM_F_MULTI: u16 = 0x2;
pub(crate) const NLM_F_DUMP: u16 = 0x300;
pub(crate) const NLM_F_DUMP_INTR: u16 = 0x10;
pub(crate) const NLM_F_DUMP_FILTERED: u16 = 0x20;
// Portes par un NLMSG_ERROR ou un NLMSG_DONE (NLM_F_CAPPED, NLM_F_ACK_TLVS).
const NLM_F_CAPPED_OU_TLVS: u16 = 0x300;
// rtnetlink.h
pub(crate) const RTM_NEWLINK: u16 = 16;
pub(crate) const RTM_GETLINK: u16 = 18;
pub(crate) const RTM_NEWADDR: u16 = 20;
pub(crate) const RTM_GETADDR: u16 = 22;
pub(crate) const RTM_NEWROUTE: u16 = 24;
pub(crate) const RTM_GETROUTE: u16 = 26;
pub(crate) const RTM_NEWRULE: u16 = 32;
pub(crate) const RTM_GETRULE: u16 = 34;
pub(crate) const AF_INET: u8 = 2;
pub(crate) const AF_INET6: u8 = 10;
const RTM_F_CLONED: u32 = 0x200;
/// Le prochain saut est mort: le noyau ignore la route.
pub(crate) const RTNH_F_DEAD: u32 = 1;
/// Passerelle forcee sur le lien: sans effet sur une route sans passerelle.
pub(crate) const RTNH_F_ONLINK: u32 = 4;
/// Le lien du prochain saut n'a pas de porteuse.
pub(crate) const RTNH_F_LINKDOWN: u32 = 16;
/// `sizeof(struct rta_cacheinfo)`.
const TAILLE_CACHEINFO: usize = 32;
const IFLA_IFNAME: u16 = 3;
const IFNAMSIZ: usize = 16;

pub(crate) const ACCES: &str = "acces noyau refuse; aucune elevation automatique";
pub(crate) const INTERROMPUE: &str =
    "lecture netlink interrompue par le noyau (NLM_F_DUMP_INTR): etat incoherent";
/// EAFNOSUPPORT: le noyau n'a pas cette famille (IPv6 desactive, par exemple).
/// La famille n'est alors pas mesuree, et la preuve ne l'est pas non plus.
pub(crate) const FAMILLE_ABSENTE: &str =
    "famille d'adresses absente de ce noyau: collecte incomplete";

/// Ce qu'une requete attend en retour.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Attente {
    pub(crate) sequence: u32,
    pub(crate) port: u32,
    /// Le type de message de donnees attendu (`RTM_NEW*`).
    pub(crate) genre: u16,
    /// Vrai pour un dump (reponse en plusieurs messages close par
    /// `NLMSG_DONE`), faux pour une requete simple (un seul message).
    pub(crate) dump: bool,
    /// Vrai si le noyau marque legitimement ces messages NLM_F_DUMP_FILTERED
    /// (routes demandees sans leurs exceptions, voir la collecte).
    pub(crate) filtre_admis: bool,
}

/// Ou en est la lecture d'une reponse.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Suite {
    /// D'autres datagrammes doivent suivre.
    Encore,
    /// La reponse est complete.
    Fini,
    /// Le noyau dit que l'objet demande n'existe pas (`ENODEV`), pour une
    /// requete simple.
    Absent,
}

fn u16_ne(b: &[u8]) -> u16 {
    u16::from_ne_bytes([b[0], b[1]])
}

fn u32_ne(b: &[u8]) -> u32 {
    u32::from_ne_bytes([b[0], b[1], b[2], b[3]])
}

fn i32_ne(b: &[u8]) -> i32 {
    i32::from_ne_bytes([b[0], b[1], b[2], b[3]])
}

/// Aligne sur 4 octets (`NLMSG_ALIGN`, `RTA_ALIGN`).
fn aligner(n: usize) -> usize {
    (n + 3) & !3
}

/// En-tete netlink d'une requete de `taille` octets au total.
pub(crate) fn entete(
    taille: usize,
    genre: u16,
    drapeaux: u16,
    sequence: u32,
    port: u32,
) -> Vec<u8> {
    let mut v = Vec::with_capacity(taille);
    v.extend_from_slice(&(taille as u32).to_ne_bytes());
    v.extend_from_slice(&genre.to_ne_bytes());
    v.extend_from_slice(&drapeaux.to_ne_bytes());
    v.extend_from_slice(&sequence.to_ne_bytes());
    v.extend_from_slice(&port.to_ne_bytes());
    v
}

/// Requete de dump: l'en-tete de famille est entierement nul sauf la
/// famille, ce que le controle strict du noyau exige (aucun filtre).
pub(crate) fn requete_dump(genre: u16, famille: u8, sequence: u32, port: u32) -> Vec<u8> {
    // ifaddrmsg fait 8 octets; rtmsg et fib_rule_hdr en font 12.
    let corps = if genre == RTM_GETADDR { 8 } else { 12 };
    let mut v = entete(
        16 + corps,
        genre,
        NLM_F_REQUEST | NLM_F_DUMP,
        sequence,
        port,
    );
    v.push(famille);
    v.resize(16 + corps, 0);
    v
}

/// Requete simple d'un lien par son nom (`RTM_GETLINK` + `IFLA_IFNAME`).
pub(crate) fn requete_lien(nom: &str, sequence: u32, port: u32) -> Vec<u8> {
    let attribut = 4 + nom.len() + 1;
    let taille = 16 + 16 + aligner(attribut);
    let mut v = entete(taille, RTM_GETLINK, NLM_F_REQUEST, sequence, port);
    v.resize(32, 0); // ifinfomsg entierement nul: famille AF_UNSPEC, index 0
    v.extend_from_slice(&(attribut as u16).to_ne_bytes());
    v.extend_from_slice(&IFLA_IFNAME.to_ne_bytes());
    v.extend_from_slice(nom.as_bytes());
    v.resize(taille, 0);
    v
}

/// Lit un datagramme de la reponse attendue et range la charge de chaque
/// message de donnees dans `charges`. `total` borne la memoire.
pub(crate) fn lire_datagramme(
    d: &[u8],
    attente: &Attente,
    charges: &mut Vec<Vec<u8>>,
    total: &mut usize,
    plafond: usize,
) -> Result<Suite, &'static str> {
    let mut offset = 0;
    if d.is_empty() {
        return Err("datagramme netlink vide");
    }
    while offset < d.len() {
        if d.len() - offset < 16 {
            return Err("en-tete netlink tronque");
        }
        let h = &d[offset..];
        let taille = u32_ne(&h[0..4]) as usize;
        let genre = u16_ne(&h[4..6]);
        let drapeaux = u16_ne(&h[6..8]);
        let sequence = u32_ne(&h[8..12]);
        let port = u32_ne(&h[12..16]);
        if taille < 16 || taille > d.len() - offset {
            return Err("longueur de message netlink invalide");
        }
        if sequence != attente.sequence || port != attente.port {
            return Err("enveloppe netlink inattendue");
        }
        let charge = &h[16..taille];
        let suivant = offset + aligner(taille);
        match genre {
            NLMSG_ERROR => {
                if drapeaux & !NLM_F_CAPPED_OU_TLVS != 0 || charge.len() < 4 {
                    return Err("erreur netlink mal formee");
                }
                let code = i32_ne(&charge[0..4]);
                return match code {
                    -1 | -13 => Err(ACCES),
                    -19 if !attente.dump => Ok(Suite::Absent),
                    -97 => Err(FAMILLE_ABSENTE),
                    0 => Err("accuse de reception netlink inattendu"),
                    _ => Err("requete netlink refusee par le noyau"),
                };
            }
            NLMSG_DONE => {
                if !attente.dump {
                    return Err("fin de dump inattendue");
                }
                if drapeaux & NLM_F_DUMP_INTR != 0 {
                    return Err(INTERROMPUE);
                }
                if drapeaux & !(NLM_F_MULTI | NLM_F_CAPPED_OU_TLVS) != 0 || charge.len() < 4 {
                    return Err("fin de dump netlink mal formee");
                }
                if i32_ne(&charge[0..4]) != 0 {
                    return Err("dump netlink clos sur une erreur du noyau");
                }
                if suivant < d.len() {
                    return Err("message netlink apres la fin du dump");
                }
                return Ok(Suite::Fini);
            }
            g if g == attente.genre => {
                if drapeaux & NLM_F_DUMP_INTR != 0 {
                    return Err(INTERROMPUE);
                }
                let admis = if attente.dump {
                    NLM_F_MULTI
                        | if attente.filtre_admis {
                            NLM_F_DUMP_FILTERED
                        } else {
                            0
                        }
                } else {
                    0
                };
                if drapeaux & !admis != 0 || (attente.dump && drapeaux & NLM_F_MULTI == 0) {
                    return Err("drapeaux netlink inattendus");
                }
                *total += charge.len();
                if *total > plafond || charges.len() >= 1_000_000 {
                    return Err("etat de routage trop grand pour la collecte bornee");
                }
                charges.push(charge.to_vec());
                if !attente.dump {
                    if suivant < d.len() {
                        return Err("message netlink en trop");
                    }
                    return Ok(Suite::Fini);
                }
            }
            _ => return Err("type de message netlink inattendu"),
        }
        offset = suivant;
        if offset > d.len() {
            return Err("alignement netlink invalide");
        }
    }
    Ok(Suite::Encore)
}

/// Les attributs d'une charge, sans autre controle que leurs longueurs:
/// `(type avec ses drapeaux, valeur)`.
fn balayer(b: &[u8]) -> Result<Vec<(u16, &[u8])>, &'static str> {
    let mut v = Vec::new();
    let mut offset = 0;
    while offset < b.len() {
        if b.len() - offset < 4 {
            return Err("attribut netlink tronque");
        }
        let n = u16_ne(&b[offset..offset + 2]) as usize;
        let t = u16_ne(&b[offset + 2..offset + 4]);
        if n < 4 || n > b.len() - offset {
            return Err("longueur d'attribut netlink invalide");
        }
        v.push((t, &b[offset + 4..offset + n]));
        offset += aligner(n);
    }
    Ok(v)
}

/// Un attribut lu: `(type sans drapeaux, niche, valeur)`.
type Attribut<'a> = (u16, bool, &'a [u8]);

/// Les attributs d'une charge. Un attribut en double est refuse.
fn attributs(b: &[u8]) -> Result<Vec<Attribut<'_>>, &'static str> {
    let mut v: Vec<Attribut<'_>> = Vec::new();
    for (t, valeur) in balayer(b)? {
        // NLA_F_NET_BYTEORDER n'est jamais pose sur ces messages.
        if t & 0x4000 != 0 {
            return Err("attribut netlink de forme inattendue");
        }
        let genre = t & 0x3fff;
        if v.iter().any(|(g, _, _)| *g == genre) {
            return Err("attribut netlink duplique");
        }
        v.push((genre, t & 0x8000 != 0, valeur));
    }
    Ok(v)
}

fn longueur_adresse(famille: u8) -> usize {
    if famille == AF_INET { 4 } else { 16 }
}

fn valeur_u8(v: &[u8]) -> Result<u8, &'static str> {
    if v.len() == 1 {
        Ok(v[0])
    } else {
        Err("attribut netlink de taille inattendue")
    }
}

fn valeur_u16(v: &[u8]) -> Result<u16, &'static str> {
    if v.len() == 2 {
        Ok(u16_ne(v))
    } else {
        Err("attribut netlink de taille inattendue")
    }
}

fn valeur_u32(v: &[u8]) -> Result<u32, &'static str> {
    if v.len() == 4 {
        Ok(u32_ne(v))
    } else {
        Err("attribut netlink de taille inattendue")
    }
}

fn valeur_be32(v: &[u8]) -> Result<u32, &'static str> {
    if v.len() == 4 {
        Ok(u32::from_be_bytes([v[0], v[1], v[2], v[3]]))
    } else {
        Err("attribut netlink de taille inattendue")
    }
}

fn adresse(famille: u8, v: &[u8]) -> Result<Vec<u8>, &'static str> {
    if v.len() == longueur_adresse(famille) {
        Ok(v.to_vec())
    } else {
        Err("adresse netlink de taille inattendue")
    }
}

/// Un nom d'interface termine par un octet nul, au plus IFNAMSIZ octets.
fn nom(v: &[u8]) -> Result<Vec<u8>, &'static str> {
    match v.split_last() {
        Some((0, n)) if !n.is_empty() && v.len() <= IFNAMSIZ && !n.contains(&0) => Ok(n.to_vec()),
        _ => Err("nom d'interface netlink invalide"),
    }
}

fn plage_u32(v: &[u8]) -> Result<(u32, u32), &'static str> {
    if v.len() == 8 {
        Ok((u32_ne(&v[0..4]), u32_ne(&v[4..8])))
    } else {
        Err("plage netlink de taille inattendue")
    }
}

fn plage_u16(v: &[u8]) -> Result<(u16, u16), &'static str> {
    if v.len() == 4 {
        Ok((u16_ne(&v[0..2]), u16_ne(&v[2..4])))
    } else {
        Err("plage netlink de taille inattendue")
    }
}

/// Une regle (`RTM_NEWRULE`, charge `fib_rule_hdr` puis attributs `FRA_*`).
pub(crate) fn regle(famille: u8, charge: &[u8]) -> Result<Regle, &'static str> {
    if charge.len() < 12 || charge[0] != famille {
        return Err("regle netlink tronquee ou d'une autre famille");
    }
    let (dst_len, src_len, tos, action, drapeaux) = (
        charge[1],
        charge[2],
        charge[3],
        charge[7],
        u32_ne(&charge[8..12]),
    );
    let max = (longueur_adresse(famille) * 8) as u8;
    if dst_len > max || src_len > max {
        return Err("longueur de prefixe de regle invalide");
    }
    let action = match action {
        1 => Action::VersTable,
        2 => Action::Saut,
        3 => Action::Neutre,
        6 => Action::TrouNoir,
        7 => Action::Injoignable,
        8 => Action::Interdit,
        _ => return Err("action de regle non prise en charge"),
    };
    // FIB_RULE_PERMANENT, INVERT, UNRESOLVED, IIF_DETACHED, OIF_DETACHED et
    // FIND_SADDR: les seuls drapeaux que l'UAPI definit.
    if drapeaux & !(0x1f | 0x10000) != 0 {
        return Err("drapeau de regle non pris en charge");
    }
    let mut r = Regle {
        pref: 0,
        action,
        table: 0,
        inverse: drapeaux & 0x2 != 0,
        drapeaux: drapeaux & !0x2,
        selecteurs: Selecteurs {
            tos,
            ..Selecteurs::default()
        },
        suppression_prefixe: None,
        suppression_groupe: None,
        cible_saut: None,
        protocole: 0,
    };
    let (mut table, mut suppression, mut protocole) = (None, None, None);
    let (mut marque, mut masque) = (None, None);
    let (mut dscp, mut dscp_masque) = (None, None);
    let (mut etiquette, mut etiquette_masque) = (None, None);
    for (genre, niche, v) in attributs(&charge[12..])? {
        if niche {
            return Err("attribut de regle de forme inattendue");
        }
        match genre {
            1 => r.selecteurs.dst = Some((adresse(famille, v)?, dst_len)),
            2 => r.selecteurs.src = Some((adresse(famille, v)?, src_len)),
            3 => r.selecteurs.iif = Some(nom(v)?),
            4 => r.cible_saut = Some(valeur_u32(v)?),
            6 => r.pref = valeur_u32(v)?,
            10 => marque = Some(valeur_u32(v)?),
            11 => r.selecteurs.flux = Some(valeur_u32(v)?),
            12 => {
                if v.len() != 8 {
                    return Err("attribut netlink de taille inattendue");
                }
                r.selecteurs.tunnel_id = Some(u64::from_be_bytes(v.try_into().unwrap()));
            }
            13 => r.suppression_groupe = Some(valeur_u32(v)?),
            14 => suppression = Some(valeur_u32(v)?),
            15 => table = Some(valeur_u32(v)?),
            16 => masque = Some(valeur_u32(v)?),
            17 => r.selecteurs.oif = Some(nom(v)?),
            18 => {} // FRA_PAD
            19 => r.selecteurs.l3mdev = Some(valeur_u8(v)?),
            20 => r.selecteurs.compte = Some(plage_u32(v)?),
            21 => protocole = Some(valeur_u8(v)?),
            22 => r.selecteurs.protocole_ip = Some(valeur_u8(v)?),
            23 => r.selecteurs.port_source = Some(plage_u16(v)?),
            24 => r.selecteurs.port_destination = Some(plage_u16(v)?),
            25 => dscp = Some(valeur_u8(v)?),
            26 => etiquette = Some(valeur_be32(v)?),
            27 => etiquette_masque = Some(valeur_be32(v)?),
            28 => r.selecteurs.masque_port_source = Some(valeur_u16(v)?),
            29 => r.selecteurs.masque_port_destination = Some(valeur_u16(v)?),
            30 => dscp_masque = Some(valeur_u8(v)?),
            _ => return Err("attribut de regle non pris en charge"),
        }
    }
    // Presence et longueur de prefixe vont ensemble, dans les deux sens.
    if (dst_len > 0) != r.selecteurs.dst.is_some() || (src_len > 0) != r.selecteurs.src.is_some() {
        return Err("prefixe de regle incoherent");
    }
    // Le noyau ecrit toujours la table, la suppression et le protocole.
    r.table = table.ok_or("regle sans table")?;
    r.suppression_prefixe = match suppression.ok_or("regle sans suppression declaree")? {
        u32::MAX => None,
        n => Some(n),
    };
    r.protocole = protocole.ok_or("regle sans protocole")?;
    if marque.is_some() || masque.is_some() {
        r.selecteurs.marque = Some((marque.unwrap_or(0), masque.unwrap_or(0)));
    }
    if dscp.is_some() || dscp_masque.is_some() {
        r.selecteurs.dscp = Some((dscp.unwrap_or(0), dscp_masque.unwrap_or(0)));
    }
    if etiquette.is_some() || etiquette_masque.is_some() {
        r.selecteurs.etiquette_flux = Some((etiquette.unwrap_or(0), etiquette_masque.unwrap_or(0)));
    }
    Ok(r)
}

/// Une route (`RTM_NEWROUTE`, charge `rtmsg` puis attributs `RTA_*`).
pub(crate) fn route(famille: u8, charge: &[u8]) -> Result<Route, &'static str> {
    if charge.len() < 12 || charge[0] != famille {
        return Err("route netlink tronquee ou d'une autre famille");
    }
    let max = (longueur_adresse(famille) * 8) as u8;
    let mut r = Route {
        table: 0,
        genre: charge[7],
        dst: Vec::new(),
        dst_len: charge[1],
        src: Vec::new(),
        src_len: charge[2],
        tos: charge[3],
        protocole: charge[5],
        portee: charge[6],
        drapeaux: u32_ne(&charge[8..12]),
        oif: None,
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
    };
    if r.dst_len > max || r.src_len > max {
        return Err("longueur de prefixe de route invalide");
    }
    // RTN_UNICAST (1) a RTN_THROW (9). RTN_NAT et RTN_XRESOLVE ne sont plus
    // poses par le noyau; RTN_UNSPEC n'est pas une route.
    if !(1..=9).contains(&r.genre) {
        return Err("type de route non pris en charge");
    }
    // La collecte demande les routes SANS leurs exceptions (strict, sans
    // RTM_F_CLONED): une route clonee ici n'est pas ce qui a ete demande.
    if r.drapeaux & RTM_F_CLONED != 0 {
        return Err("exception de route inattendue dans le dump");
    }
    // Les seuls drapeaux dont l'effet sur l'emission a ete mesure au banc
    // (voir la comparaison). Delestage et piegeage materiels (RTNH_F_OFFLOAD,
    // RTNH_F_TRAP, RTM_F_OFFLOAD, RTM_F_TRAP, RTM_F_OFFLOAD_FAILED) ne se
    // produisent pas sans materiel ni module dedie; les autres bits ne
    // figurent pas dans un dump de routes du noyau 7.0. Tous rendent la
    // collecte non mesuree.
    if r.drapeaux & !(RTNH_F_DEAD | RTNH_F_ONLINK | RTNH_F_LINKDOWN) != 0 {
        return Err("drapeau de route non mesure");
    }
    let mut table = None;
    for (genre, niche, v) in attributs(&charge[12..])? {
        // RTA_METRICS, RTA_MULTIPATH et RTA_ENCAP sont des attributs niches.
        if niche && !matches!(genre, 8 | 9 | 22) {
            return Err("attribut de route de forme inattendue");
        }
        match genre {
            1 => r.dst = adresse(famille, v)?,
            2 => r.src = adresse(famille, v)?,
            3 => r.iif = Some(valeur_u32(v)?),
            4 => r.oif = Some(valeur_u32(v)?),
            5 => r.passerelle = Some(adresse(famille, v)?),
            6 => r.metrique = Some(valeur_u32(v)?),
            7 => r.source_preferee = Some(adresse(famille, v)?),
            8 => r.metriques = Some(v.to_vec()),
            9 => {
                if v.is_empty() {
                    return Err("route multichemin vide");
                }
                r.multichemin = Some(v.to_vec());
            }
            11 => r.flux = Some(valeur_u32(v)?),
            // RTA_CACHEINFO (`struct rta_cacheinfo`, huit champs de 32 bits):
            // compteurs et temps changent seuls, seule la presence d'une
            // echeance (`rta_expires`, non nul) est gardee.
            12 => {
                if v.len() != TAILLE_CACHEINFO {
                    return Err("information de cache de route de taille inattendue");
                }
                r.expire |= i32_ne(&v[8..12]) != 0;
            }
            // RTA_EXPIRES: une echeance, quelle que soit sa valeur.
            23 => r.expire = true,
            24 => {} // RTA_PAD
            15 => table = Some(valeur_u32(v)?),
            18 => {
                if v.len() < 2 {
                    return Err("passerelle d'une autre famille tronquee");
                }
                r.via = Some(v.to_vec());
            }
            20 => r.preference = Some(valeur_u8(v)?),
            21 => {
                let t = valeur_u16(v)?;
                r.encapsulation
                    .get_or_insert_with(Vec::new)
                    .extend(t.to_ne_bytes());
            }
            22 => r
                .encapsulation
                .get_or_insert_with(Vec::new)
                .extend_from_slice(v),
            30 => r.prochain_saut = Some(valeur_u32(v)?),
            _ => return Err("attribut de route non pris en charge"),
        }
    }
    if (r.dst_len > 0) != !r.dst.is_empty() || (r.src_len > 0) != !r.src.is_empty() {
        return Err("prefixe de route incoherent");
    }
    r.table = table.ok_or("route sans table")?;
    Ok(r)
}

/// Une adresse (`RTM_NEWADDR`, charge `ifaddrmsg` puis attributs `IFA_*`).
///
/// Seuls l'interface, la longueur de prefixe et `IFA_ADDRESS` servent (a
/// reconnaitre une route connectee); les autres attributs sont lus pour leur
/// forme et ecartes. Sans `IFA_ADDRESS`, l'adresse ne sert a rien: `None`.
pub(crate) fn adresse_interface(
    famille: u8,
    charge: &[u8],
) -> Result<Option<Adresse>, &'static str> {
    if charge.len() < 8 || charge[0] != famille {
        return Err("adresse netlink tronquee ou d'une autre famille");
    }
    let prefixe = charge[1];
    if prefixe as usize > longueur_adresse(famille) * 8 {
        return Err("longueur de prefixe d'adresse invalide");
    }
    let index = u32_ne(&charge[4..8]);
    let mut valeur = None;
    for (genre, _, v) in attributs(&charge[8..])? {
        if genre == 1 {
            valeur = Some(adresse(famille, v)?);
        }
    }
    Ok(valeur.map(|adresse| Adresse {
        index,
        prefixe,
        adresse,
    }))
}

/// L'index du lien rendu pour le nom demande.
///
/// Un message de lien porte des dizaines d'attributs qui ne servent pas ici et
/// dont la liste change d'un noyau a l'autre: seules leurs longueurs sont
/// controlees, et `IFLA_IFNAME` doit y figurer une seule fois, egal au nom
/// demande.
pub(crate) fn lien(charge: &[u8], demande: &str) -> Result<u32, &'static str> {
    if charge.len() < 16 {
        return Err("lien netlink tronque");
    }
    let index = i32_ne(&charge[4..8]);
    let noms: Vec<&[u8]> = balayer(&charge[16..])?
        .into_iter()
        .filter(|(t, _)| t & 0x3fff == IFLA_IFNAME)
        .map(|(_, v)| v)
        .collect();
    let [un] = noms.as_slice() else {
        return Err("lien netlink sans nom unique");
    };
    if index <= 0 || nom(un)? != demande.as_bytes() {
        return Err("lien netlink rendu pour un autre nom");
    }
    Ok(index as u32)
}
