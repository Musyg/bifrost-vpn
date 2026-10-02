//! Les regles et les routes que le noyau porte deja, lues avant la premiere
//! commande du montage et autour de chaque retrait.
//!
//! # Pourquoi ce module existe
//!
//! Les valeurs par defaut du produit (table 51820, marque 51820) sont celles
//! de wg-quick. Mesure du 30/09/2026 sur essai-linux, en namespace jetable, par
//! `LinuxTunnel::up` et `down` de la base `91d614f`: un tiers pose dans la
//! meme table faisait echouer la pose (la route par defaut y etait deja), puis
//! le nettoyage vidait sa table et retirait ses regles. Le retrait est
//! desormais exact (voir `bifrost_core::routage`), et cette lecture sert le
//! reste: avant de poser, le journal des sessions (`super::session`) y
//! reconnait ce qu'une session du produit a pose, et `Plan::occupation` ce
//! qu'un tiers occupe deja; apres un retrait, elle dit ce qui reste.
//!
//! # Ce qui borne la course entre la lecture et la pose
//!
//! Un tiers peut s'installer entre la lecture et la derniere commande de pose.
//! Deux cas, et aucun ne fait retirer au produit ce qui n'est pas a lui: une
//! route par defaut posee dans la table avant la notre fait echouer la pose
//! (EEXIST), et le nettoyage qui suit ne retire que ce que la session a pose;
//! toute autre installation (une route plus specifique, une regle) cohabite,
//! et le demontage la laisse en place pour la meme raison. La lecture est un
//! refus nomme, pas la garantie: la garantie est le retrait exact. La fenetre
//! elle-meme dure le temps de creer l'interface et de lancer les commandes de
//! pose.
//!
//! # Pourquoi pas la collecte de `prove routes`
//!
//! Elle vit dans la CLI, que le daemon ne peut pas importer, et sa politique
//! est l'inverse de celle qu'il faut ici: elle REFUSE tout attribut qu'elle ne
//! reconnait pas (la preuve devient alors non mesuree), ce qui, avant une
//! pose, empecherait le tunnel de monter sur un noyau qui ajoute un attribut
//! de regle. Ici seuls la table, la priorite, la marque, l'action,
//! l'etiquette et la forme comptent; un attribut inconnu est ignore, mais il
//! retire a la regle sa forme du produit (`RegleLue::forme`): ce n'est plus
//! une regle que le produit pose. Une trame mal formee ou un dump interrompu
//! est une erreur. Sans shell ni programme externe: rtnetlink en lecture, que
//! le noyau accorde sans privilege (`rtnetlink_rcv_msg`, v7.0).
//!
//! La lecture des trames est pure et compilee partout, pour que ses recettes
//! tournent aussi sous Windows; le canal netlink n'existe que sous Linux.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

#[cfg(target_os = "linux")]
use bifrost_core::Result;
use bifrost_core::routage::{Consultation, Famille, RegleLue, RouteLue, Selecteur, TABLE_MAIN};

// UAPI Linux v7.0: netlink.h, rtnetlink.h, fib_rules.h.
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_DUMP: u16 = 0x300;
const NLM_F_DUMP_INTR: u16 = 0x10;
pub(crate) const RTM_NEWROUTE: u16 = 24;
pub(crate) const RTM_GETROUTE: u16 = 26;
pub(crate) const RTM_NEWRULE: u16 = 32;
pub(crate) const RTM_GETRULE: u16 = 34;
pub(crate) const AF_INET: u8 = 2;
pub(crate) const AF_INET6: u8 = 10;
const FR_ACT_TO_TBL: u8 = 1;
const FIB_RULE_INVERT: u32 = 0x2;
const FRA_PRIORITY: u16 = 6;
const FRA_FWMARK: u16 = 10;
const FRA_SUPPRESS_IFGROUP: u16 = 13;
const FRA_SUPPRESS_PREFIXLEN: u16 = 14;
const FRA_TABLE: u16 = 15;
const FRA_FWMASK: u16 = 16;
const FRA_PAD: u16 = 18;
const FRA_UID_RANGE: u16 = 20;
const FRA_PROTOCOL: u16 = 21;
const RTA_SRC: u16 = 2;
const RTA_IIF: u16 = 3;
const RTA_OIF: u16 = 4;
const RTA_GATEWAY: u16 = 5;
const RTA_MULTIPATH: u16 = 9;
const RTA_TABLE: u16 = 15;
const RTA_VIA: u16 = 18;
const RTA_ENCAP: u16 = 22;
const RTN_UNICAST: u8 = 1;
/// EAFNOSUPPORT: le noyau n'a pas cette famille (IPv6 desactive au
/// demarrage). Rien ne peut alors l'occuper; la pose de cette famille
/// echouera d'elle-meme, avec son propre message.
const EAFNOSUPPORT: i32 = 97;

fn u16_ne(b: &[u8]) -> u16 {
    u16::from_ne_bytes([b[0], b[1]])
}

fn u32_ne(b: &[u8]) -> u32 {
    u32::from_ne_bytes([b[0], b[1], b[2], b[3]])
}

fn aligner(n: usize) -> usize {
    (n + 3) & !3
}

fn famille(f: u8) -> std::result::Result<Famille, String> {
    match f {
        AF_INET => Ok(Famille::Ipv4),
        AF_INET6 => Ok(Famille::Ipv6),
        _ => Err(format!("famille netlink inattendue: {f}")),
    }
}

/// La requete de dump d'une famille: en-tete netlink, puis l'en-tete de
/// famille (`rtmsg` ou `fib_rule_hdr`, 12 octets tous deux) nul hors la
/// famille. Aucun filtre: tout est rendu, et trie ici.
pub(crate) fn requete(genre: u16, f: u8, sequence: u32) -> Vec<u8> {
    let taille: u32 = 16 + 12;
    let mut v = Vec::with_capacity(taille as usize);
    v.extend_from_slice(&taille.to_ne_bytes());
    v.extend_from_slice(&genre.to_ne_bytes());
    v.extend_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
    v.extend_from_slice(&sequence.to_ne_bytes());
    v.extend_from_slice(&0u32.to_ne_bytes());
    v.push(f);
    v.resize(taille as usize, 0);
    v
}

/// Ou en est la lecture d'un dump.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Suite {
    /// D'autres datagrammes doivent suivre.
    Encore,
    /// Le dump est complet.
    Fini,
    /// Le noyau n'a pas cette famille.
    FamilleAbsente,
}

/// Lit un datagramme d'un dump et range la charge de chaque message du type
/// attendu. Une longueur fausse, une sequence etrangere, un type inattendu,
/// un dump interrompu (`NLM_F_DUMP_INTR`) ou une erreur du noyau sont des
/// erreurs: l'etat lu serait incomplet.
pub(crate) fn lire_datagramme(
    d: &[u8],
    sequence: u32,
    genre: u16,
    charges: &mut Vec<Vec<u8>>,
) -> std::result::Result<Suite, String> {
    if d.is_empty() {
        return Err("datagramme netlink vide".into());
    }
    let mut offset = 0;
    while offset < d.len() {
        if d.len() - offset < 16 {
            return Err("en-tete netlink tronque".into());
        }
        let h = &d[offset..];
        let taille = u32_ne(&h[0..4]) as usize;
        let type_ = u16_ne(&h[4..6]);
        let drapeaux = u16_ne(&h[6..8]);
        if taille < 16 || taille > d.len() - offset {
            return Err("longueur de message netlink invalide".into());
        }
        if u32_ne(&h[8..12]) != sequence {
            return Err("message netlink d'une autre requete".into());
        }
        if drapeaux & NLM_F_DUMP_INTR != 0 {
            return Err("dump netlink interrompu par le noyau (NLM_F_DUMP_INTR)".into());
        }
        let charge = &h[16..taille];
        match type_ {
            NLMSG_ERROR => {
                if charge.len() < 4 {
                    return Err("erreur netlink tronquee".into());
                }
                let code = i32::from_ne_bytes([charge[0], charge[1], charge[2], charge[3]]);
                return match code {
                    c if c == -EAFNOSUPPORT => Ok(Suite::FamilleAbsente),
                    0 => Err("accuse de reception netlink inattendu".into()),
                    c => Err(format!(
                        "lecture netlink refusee par le noyau (errno {})",
                        -c
                    )),
                };
            }
            NLMSG_DONE => {
                if charge.len() >= 4 && u32_ne(&charge[0..4]) != 0 {
                    return Err("dump netlink clos sur une erreur du noyau".into());
                }
                return Ok(Suite::Fini);
            }
            t if t == genre => charges.push(charge.to_vec()),
            _ => return Err(format!("type de message netlink inattendu: {type_}")),
        }
        offset += aligner(taille);
    }
    Ok(Suite::Encore)
}

/// Les attributs d'une charge, `(type sans drapeaux, valeur)`. Les longueurs
/// sont controlees; un attribut inconnu est rendu, et l'appelant l'ignore.
fn attributs(b: &[u8]) -> std::result::Result<Vec<(u16, &[u8])>, String> {
    let mut v = Vec::new();
    let mut offset = 0;
    while offset < b.len() {
        if b.len() - offset < 4 {
            return Err("attribut netlink tronque".into());
        }
        let n = u16_ne(&b[offset..offset + 2]) as usize;
        let t = u16_ne(&b[offset + 2..offset + 4]) & 0x3fff;
        if n < 4 || n > b.len() - offset {
            return Err("longueur d'attribut netlink invalide".into());
        }
        v.push((t, &b[offset + 4..offset + n]));
        offset += aligner(n);
    }
    Ok(v)
}

fn valeur_u32(v: &[u8]) -> std::result::Result<u32, String> {
    if v.len() == 4 {
        Ok(u32_ne(v))
    } else {
        Err("attribut netlink de taille inattendue".into())
    }
}

/// Une regle (`RTM_NEWRULE`: `fib_rule_hdr`, puis attributs `FRA_*`).
///
/// Sa forme (`RegleLue::forme`) n'est rendue que si la regle n'est faite QUE
/// de ce qu'une forme du produit contient: ni prefixe, ni TOS, ni drapeau
/// hors l'inversion, une action vers une table, et aucun attribut hors la
/// priorite, la marque et son masque, la plage de comptes, la table, la
/// suppression de prefixe, l'etiquette et le bourrage; `FRA_SUPPRESS_IFGROUP`
/// seulement a sa valeur neutre. Le noyau ecrit toujours la table, la
/// suppression de prefixe (`u32::MAX` sans suppression) et l'etiquette
/// (`fib_nl_fill_rule`, `net/core/fib_rules.c`, v7.0).
pub(crate) fn regle(charge: &[u8]) -> std::result::Result<RegleLue, String> {
    if charge.len() < 12 {
        return Err("regle netlink tronquee".into());
    }
    let f = famille(charge[0])?;
    let (prefixes_ou_tos, action) = (charge[1] | charge[2] | charge[3], charge[7]);
    let drapeaux = u32_ne(&charge[8..12]);
    let mut table = u32::from(charge[4]);
    let (mut priorite, mut protocole) = (0, 0);
    let (mut marque, mut masque) = (None, None);
    let (mut comptes, mut suppression) = (None, u32::MAX);
    // Un attribut qu'aucune forme du produit ne porte.
    let mut etranger = false;
    for (t, v) in attributs(&charge[12..])? {
        match t {
            FRA_PRIORITY => priorite = valeur_u32(v)?,
            FRA_TABLE => table = valeur_u32(v)?,
            FRA_FWMARK => marque = Some(valeur_u32(v)?),
            FRA_FWMASK => masque = Some(valeur_u32(v)?),
            FRA_PROTOCOL => {
                let [p] = v else {
                    return Err("attribut netlink de taille inattendue".into());
                };
                protocole = *p;
            }
            FRA_SUPPRESS_PREFIXLEN => suppression = valeur_u32(v)?,
            FRA_UID_RANGE => {
                if v.len() != 8 {
                    return Err("attribut netlink de taille inattendue".into());
                }
                comptes = Some((u32_ne(&v[0..4]), u32_ne(&v[4..8])));
            }
            FRA_SUPPRESS_IFGROUP => etranger |= valeur_u32(v)? != u32::MAX,
            FRA_PAD => {}
            _ => etranger = true,
        }
    }
    let marque = (marque.is_some() || masque.is_some())
        .then(|| (marque.unwrap_or(0), masque.unwrap_or(u32::MAX)));
    let inverse = drapeaux & FIB_RULE_INVERT != 0;
    let forme = if etranger
        || prefixes_ou_tos != 0
        || action != FR_ACT_TO_TBL
        || drapeaux & !FIB_RULE_INVERT != 0
    {
        None
    } else {
        let selecteur = match (marque, comptes, inverse) {
            (None, None, false) => Some(Selecteur::Tout),
            (Some((m, u32::MAX)), None, true) => Some(Selecteur::HorsMarque(m)),
            (None, Some((debut, fin)), false) if debut == fin => Some(Selecteur::Compte(debut)),
            _ => None,
        };
        let consultation = match (table, suppression) {
            (TABLE_MAIN, 0) => Some(Consultation::MainSansDefaut),
            (TABLE_MAIN, u32::MAX) => Some(Consultation::Main),
            (t, u32::MAX) => Some(Consultation::Table(t)),
            _ => None,
        };
        selecteur.zip(consultation)
    };
    Ok(RegleLue {
        famille: f,
        priorite,
        table: (action == FR_ACT_TO_TBL).then_some(table),
        marque,
        protocole,
        forme,
    })
}

/// Une route (`RTM_NEWROUTE`: `rtmsg`, puis attributs `RTA_*`). La table est
/// `RTA_TABLE` quand elle y est: le champ de huit bits de `rtmsg` ne tient pas
/// une table au-dela de 255.
///
/// `RouteLue::par_defaut_vers` n'est rendu que pour la forme que le produit
/// pose: route par defaut (aucun prefixe, ni de destination ni de source, TOS
/// nul) de type `unicast`, vers une interface (`RTA_OIF`), sans passerelle, ni
/// chemins multiples, ni encapsulation, ni interface d'entree.
pub(crate) fn route(charge: &[u8]) -> std::result::Result<RouteLue, String> {
    if charge.len() < 12 {
        return Err("route netlink tronquee".into());
    }
    let f = famille(charge[0])?;
    let par_defaut = (charge[1] | charge[2] | charge[3]) == 0 && charge[7] == RTN_UNICAST;
    let mut table = u32::from(charge[4]);
    let (mut sortie, mut ailleurs) = (None, false);
    for (t, v) in attributs(&charge[12..])? {
        match t {
            RTA_TABLE => table = valeur_u32(v)?,
            RTA_OIF => sortie = Some(valeur_u32(v)?),
            RTA_SRC | RTA_IIF | RTA_GATEWAY | RTA_MULTIPATH | RTA_VIA | RTA_ENCAP => {
                ailleurs = true;
            }
            _ => {}
        }
    }
    Ok(RouteLue {
        famille: f,
        table,
        protocole: charge[5],
        par_defaut_vers: if par_defaut && !ailleurs {
            sortie
        } else {
            None
        },
    })
}

/// Ce que la lecture rend: les regles et les routes des deux familles.
pub(crate) type Etat = (Vec<RegleLue>, Vec<RouteLue>);

/// Les regles et les routes des deux familles, lues dans le noyau, dans le
/// namespace reseau courant.
#[cfg(target_os = "linux")]
pub(crate) fn lire() -> Result<Etat> {
    canal::lire()
}

#[cfg(target_os = "linux")]
mod canal {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::time::{Duration, Instant};

    use bifrost_core::{Error, Result};

    use super::{Etat, Suite};

    /// Borne d'une lecture entiere.
    const DELAI: Duration = Duration::from_secs(2);
    /// Un datagramme de dump fait au plus 32 Kio (`netlink_dump`); un
    /// datagramme plus grand que ce tampon est refuse, jamais lu en partie.
    const TAMPON: usize = 64 * 1024;
    /// Borne de la memoire d'une reponse.
    const PLAFOND: usize = 16 * 1024 * 1024;

    fn erreur(quoi: &str, e: std::io::Error) -> Error {
        Error::Tunnel(format!(
            "lecture des regles et des routes impossible avant la pose ({quoi}): {e}"
        ))
    }

    fn ouvrir() -> Result<OwnedFd> {
        // SAFETY: appel systeme sans pointeur; le descripteur rendu, s'il est
        // valide, est aussitot confie a un `OwnedFd` qui le fermera.
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_ROUTE,
            )
        };
        if fd < 0 {
            return Err(erreur("socket", std::io::Error::last_os_error()));
        }
        // SAFETY: `fd` vient d'etre ouvert et n'appartient a personne d'autre.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let delai = libc::timeval {
            tv_sec: 0,
            tv_usec: 200_000,
        };
        // SAFETY: `delai` vit jusqu'a la fin de l'appel, et sa taille est
        // celle que le noyau attend pour SO_RCVTIMEO.
        let r = unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                (&raw const delai).cast(),
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            )
        };
        if r != 0 {
            return Err(erreur("SO_RCVTIMEO", std::io::Error::last_os_error()));
        }
        Ok(fd)
    }

    /// Un dump entier d'une famille, ou `None` si le noyau n'a pas la famille.
    fn dump(
        fd: &OwnedFd,
        get: u16,
        new: u16,
        famille: u8,
        sequence: u32,
    ) -> Result<Option<Vec<Vec<u8>>>> {
        let requete = super::requete(get, famille, sequence);
        // SAFETY: une adresse netlink nulle hors sa famille designe le noyau.
        let mut noyau: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        noyau.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        // SAFETY: `requete` et `noyau` vivent jusqu'a la fin de l'appel; les
        // longueurs passees sont les leurs.
        let envoye = unsafe {
            libc::sendto(
                fd.as_raw_fd(),
                requete.as_ptr().cast(),
                requete.len(),
                0,
                (&raw const noyau).cast(),
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if envoye != requete.len() as isize {
            return Err(erreur("envoi", std::io::Error::last_os_error()));
        }
        let debut = Instant::now();
        let mut tampon = vec![0u8; TAMPON];
        let mut charges = Vec::new();
        loop {
            if debut.elapsed() >= DELAI {
                return Err(Error::Tunnel(
                    "lecture des regles et des routes: delai depasse".into(),
                ));
            }
            // SAFETY: une adresse netlink nulle, que le noyau remplit.
            let mut source: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
            let mut longueur = std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t;
            // SAFETY: `tampon` est valide et long de `tampon.len()`; `source`
            // et `longueur` vivent jusqu'a la fin de l'appel. MSG_TRUNC fait
            // rendre la taille reelle d'un datagramme plus grand que le tampon.
            let n = unsafe {
                libc::recvfrom(
                    fd.as_raw_fd(),
                    tampon.as_mut_ptr().cast(),
                    tampon.len(),
                    libc::MSG_TRUNC,
                    (&raw mut source).cast(),
                    &raw mut longueur,
                )
            };
            if n < 0 {
                let e = std::io::Error::last_os_error();
                match e.kind() {
                    std::io::ErrorKind::WouldBlock
                    | std::io::ErrorKind::TimedOut
                    | std::io::ErrorKind::Interrupted => continue,
                    _ => return Err(erreur("reception", e)),
                }
            }
            let n = n as usize;
            if n > tampon.len() {
                return Err(Error::Tunnel(
                    "lecture des regles et des routes: datagramme tronque".into(),
                ));
            }
            if source.nl_pid != 0 {
                return Err(Error::Tunnel(
                    "lecture des regles et des routes: reponse qui ne vient pas du noyau".into(),
                ));
            }
            let suite = super::lire_datagramme(&tampon[..n], sequence, new, &mut charges)
                .map_err(|e| Error::Tunnel(format!("lecture des regles et des routes: {e}")))?;
            if charges.iter().map(Vec::len).sum::<usize>() > PLAFOND {
                return Err(Error::Tunnel(
                    "lecture des regles et des routes: etat trop grand".into(),
                ));
            }
            match suite {
                Suite::Encore => {}
                Suite::Fini => return Ok(Some(charges)),
                Suite::FamilleAbsente => return Ok(None),
            }
        }
    }

    /// Les regles et les routes des deux familles, dans le namespace courant.
    pub(super) fn lire() -> Result<Etat> {
        let fd = ouvrir()?;
        let mut regles = Vec::new();
        let mut routes = Vec::new();
        let mut sequence = 0;
        for famille in [super::AF_INET, super::AF_INET6] {
            sequence += 1;
            for c in dump(
                &fd,
                super::RTM_GETRULE,
                super::RTM_NEWRULE,
                famille,
                sequence,
            )?
            .unwrap_or_default()
            {
                regles.push(super::regle(&c).map_err(Error::Tunnel)?);
            }
            sequence += 1;
            for c in dump(
                &fd,
                super::RTM_GETROUTE,
                super::RTM_NEWROUTE,
                famille,
                sequence,
            )?
            .unwrap_or_default()
            {
                routes.push(super::route(&c).map_err(Error::Tunnel)?);
            }
        }
        Ok((regles, routes))
    }

    #[cfg(test)]
    mod tests {
        use bifrost_core::routage::Famille;

        /// Face au noyau, sans privilege: le namespace courant se lit, et on y
        /// retrouve ce que le noyau pose toujours, les regles `local` (table
        /// 255, priorite 0) et `main` (table 254, priorite 32766) dans les deux
        /// familles, a son protocole (`kernel`, 2), et la boucle locale dans
        /// `local`. Passif: rien n'est pose.
        #[test]
        fn le_namespace_courant_se_lit_sans_privilege() {
            let (regles, routes) = super::lire().expect("lecture rtnetlink");
            for f in Famille::TOUTES {
                assert!(
                    regles.iter().any(|r| r.famille == f
                        && r.priorite == 0
                        && r.table == Some(255)
                        && r.protocole == 2),
                    "{f:?}: regle local du noyau absente: {regles:?}"
                );
                assert!(
                    regles.iter().any(|r| r.famille == f
                        && r.priorite == 32766
                        && r.table == Some(254)
                        && r.protocole == 2),
                    "{f:?}: regle main du noyau absente: {regles:?}"
                );
            }
            assert!(
                routes
                    .iter()
                    .any(|r| r.famille == Famille::Ipv4 && r.table == 255),
                "la boucle locale doit porter une route dans local"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bifrost_core::routage::PROTOCOLE_PRODUIT;

    /// Un message netlink: en-tete puis charge, aligne.
    fn message(type_: u16, drapeaux: u16, sequence: u32, charge: &[u8]) -> Vec<u8> {
        let taille = 16 + charge.len();
        let mut v = Vec::new();
        v.extend_from_slice(&(taille as u32).to_ne_bytes());
        v.extend_from_slice(&type_.to_ne_bytes());
        v.extend_from_slice(&drapeaux.to_ne_bytes());
        v.extend_from_slice(&sequence.to_ne_bytes());
        v.extend_from_slice(&0u32.to_ne_bytes());
        v.extend_from_slice(charge);
        v.resize(aligner(v.len()), 0);
        v
    }

    fn attribut(t: u16, valeur: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&((4 + valeur.len()) as u16).to_ne_bytes());
        v.extend_from_slice(&t.to_ne_bytes());
        v.extend_from_slice(valeur);
        v.resize(aligner(v.len()), 0);
        v
    }

    /// `fib_rule_hdr` puis les attributs, comme le noyau les ecrit.
    fn charge_regle(f: u8, action: u8, attributs: &[Vec<u8>]) -> Vec<u8> {
        let mut v = vec![f, 0, 0, 0, 0, 0, 0, action];
        v.extend_from_slice(&0u32.to_ne_bytes());
        for a in attributs {
            v.extend_from_slice(a);
        }
        v
    }

    fn charge_route(f: u8, table8: u8, protocole: u8, table: Option<u32>) -> Vec<u8> {
        let mut v = vec![f, 0, 0, 0, table8, protocole, 0, 1];
        v.extend_from_slice(&0u32.to_ne_bytes());
        if let Some(t) = table {
            v.extend_from_slice(&attribut(RTA_TABLE, &t.to_ne_bytes()));
        }
        v
    }

    #[test]
    fn la_requete_est_un_dump_sans_filtre() {
        let r = requete(RTM_GETRULE, AF_INET6, 7);
        assert_eq!(r.len(), 28);
        assert_eq!(u32_ne(&r[0..4]), 28);
        assert_eq!(u16_ne(&r[4..6]), RTM_GETRULE);
        assert_eq!(u16_ne(&r[6..8]), NLM_F_REQUEST | NLM_F_DUMP);
        assert_eq!(u32_ne(&r[8..12]), 7);
        assert_eq!(r[16], AF_INET6);
        assert!(r[17..].iter().all(|o| *o == 0));
    }

    /// `fib_rule_hdr` complet: prefixes et TOS, action, drapeaux.
    fn charge_regle_entiere(
        f: u8,
        prefixes_et_tos: [u8; 3],
        action: u8,
        drapeaux: u32,
        attributs: &[Vec<u8>],
    ) -> Vec<u8> {
        let [d, s, t] = prefixes_et_tos;
        let mut v = vec![f, d, s, t, 0, 0, 0, action];
        v.extend_from_slice(&drapeaux.to_ne_bytes());
        for a in attributs {
            v.extend_from_slice(a);
        }
        v
    }

    fn u32_attr(t: u16, x: u32) -> Vec<u8> {
        attribut(t, &x.to_ne_bytes())
    }

    /// Les attributs que le noyau ecrit pour toute regle: la table, la
    /// suppression de prefixe (aucune: `u32::MAX`) et l'etiquette.
    fn toujours(table: u32, suppression: u32, etiquette: u8) -> Vec<Vec<u8>> {
        vec![
            u32_attr(FRA_TABLE, table),
            u32_attr(FRA_SUPPRESS_PREFIXLEN, suppression),
            attribut(FRA_PROTOCOL, &[etiquette]),
        ]
    }

    /// Une regle du produit telle que le noyau la rend (`not fwmark 51820
    /// table 51820 protocol 177`, priorite choisie par le noyau), et une
    /// regle sans table. Un attribut inconnu est ignore pour la table, la
    /// marque et l'etiquette, mais la regle qui le porte n'a plus de forme.
    #[test]
    fn une_regle_se_lit_table_marque_priorite_etiquette_et_forme() {
        let mut attrs = vec![
            u32_attr(FRA_PRIORITY, 32765),
            u32_attr(FRA_FWMARK, 51820),
            u32_attr(FRA_FWMASK, u32::MAX),
            attribut(FRA_PAD, &[]),
        ];
        attrs.extend(toujours(51820, u32::MAX, PROTOCOLE_PRODUIT));
        let c = charge_regle_entiere(AF_INET, [0; 3], FR_ACT_TO_TBL, FIB_RULE_INVERT, &attrs);
        assert_eq!(
            regle(&c).unwrap(),
            RegleLue {
                famille: Famille::Ipv4,
                priorite: 32765,
                table: Some(51820),
                marque: Some((51820, u32::MAX)),
                protocole: PROTOCOLE_PRODUIT,
                forme: Some((Selecteur::HorsMarque(51820), Consultation::Table(51820))),
            }
        );
        attrs.push(attribut(29, &[1, 2]));
        let c = charge_regle_entiere(AF_INET, [0; 3], FR_ACT_TO_TBL, FIB_RULE_INVERT, &attrs);
        let r = regle(&c).unwrap();
        assert_eq!(
            (r.table, r.marque, r.protocole, r.forme),
            (
                Some(51820),
                Some((51820, u32::MAX)),
                PROTOCOLE_PRODUIT,
                None
            )
        );
        // Un rejet (`unreachable`, action 7) ne consulte aucune table.
        let c = charge_regle(
            AF_INET6,
            7,
            &[attribut(FRA_PRIORITY, &5250u32.to_ne_bytes())],
        );
        let r = regle(&c).unwrap();
        assert_eq!(
            (r.famille, r.table, r.marque, r.forme),
            (Famille::Ipv6, None, None, None)
        );
    }

    /// Les formes que le produit pose se lisent comme telles, chacune dans
    /// ses deux variantes de consultation de `main`.
    #[test]
    fn chaque_forme_du_produit_se_lit() {
        let forme = |drapeaux: u32, attrs: Vec<Vec<u8>>| {
            regle(&charge_regle_entiere(
                AF_INET6,
                [0; 3],
                FR_ACT_TO_TBL,
                drapeaux,
                &attrs,
            ))
            .unwrap()
            .forme
        };
        assert_eq!(
            forme(0, toujours(TABLE_MAIN, 0, PROTOCOLE_PRODUIT)),
            Some((Selecteur::Tout, Consultation::MainSansDefaut))
        );
        assert_eq!(
            forme(0, toujours(2847, u32::MAX, PROTOCOLE_PRODUIT)),
            Some((Selecteur::Tout, Consultation::Table(2847)))
        );
        let mut compte = toujours(TABLE_MAIN, u32::MAX, PROTOCOLE_PRODUIT);
        let mut plage = 4242u32.to_ne_bytes().to_vec();
        plage.extend_from_slice(&4242u32.to_ne_bytes());
        compte.push(attribut(FRA_UID_RANGE, &plage));
        assert_eq!(
            forme(0, compte),
            Some((Selecteur::Compte(4242), Consultation::Main))
        );
        // Le groupe de suppression a sa valeur neutre ne change rien.
        let mut neutre = toujours(TABLE_MAIN, 0, PROTOCOLE_PRODUIT);
        neutre.push(u32_attr(FRA_SUPPRESS_IFGROUP, u32::MAX));
        assert_eq!(
            forme(0, neutre),
            Some((Selecteur::Tout, Consultation::MainSansDefaut))
        );
    }

    /// Tout ce qu'une forme du produit ne porte pas lui retire sa forme: une
    /// source, un TOS, un drapeau, un saut, une marque non inversee ou a
    /// masque partiel, une inversion sans marque, une plage de comptes, une
    /// suppression autre que 0, un groupe de suppression, une interface.
    #[test]
    fn ce_qui_n_est_pas_une_forme_du_produit_n_en_a_pas() {
        let base = toujours(TABLE_MAIN, 0, PROTOCOLE_PRODUIT);
        let avec = |extra: Vec<Vec<u8>>| {
            let mut v = base.clone();
            v.extend(extra);
            v
        };
        let mut plage = 1000u32.to_ne_bytes().to_vec();
        plage.extend_from_slice(&2000u32.to_ne_bytes());
        for (nom, prefixes, action, drapeaux, attrs) in [
            ("source", [0, 24, 0], FR_ACT_TO_TBL, 0, avec(vec![])),
            ("tos", [0, 0, 16], FR_ACT_TO_TBL, 0, avec(vec![])),
            ("saut", [0; 3], 2, 0, avec(vec![])),
            ("drapeau", [0; 3], FR_ACT_TO_TBL, 0x10000, avec(vec![])),
            (
                "inversion sans marque",
                [0; 3],
                FR_ACT_TO_TBL,
                FIB_RULE_INVERT,
                avec(vec![]),
            ),
            (
                "marque non inversee",
                [0; 3],
                FR_ACT_TO_TBL,
                0,
                avec(vec![
                    u32_attr(FRA_FWMARK, 7),
                    u32_attr(FRA_FWMASK, u32::MAX),
                ]),
            ),
            (
                "masque partiel",
                [0; 3],
                FR_ACT_TO_TBL,
                FIB_RULE_INVERT,
                avec(vec![u32_attr(FRA_FWMARK, 7), u32_attr(FRA_FWMASK, 0xff)]),
            ),
            (
                "plage de comptes",
                [0; 3],
                FR_ACT_TO_TBL,
                0,
                avec(vec![attribut(FRA_UID_RANGE, &plage)]),
            ),
            (
                "groupe de suppression",
                [0; 3],
                FR_ACT_TO_TBL,
                0,
                avec(vec![u32_attr(FRA_SUPPRESS_IFGROUP, 3)]),
            ),
            (
                "interface d'entree",
                [0; 3],
                FR_ACT_TO_TBL,
                0,
                avec(vec![attribut(3, b"eth0\0")]),
            ),
            (
                "suppression de 8",
                [0; 3],
                FR_ACT_TO_TBL,
                0,
                toujours(TABLE_MAIN, 8, PROTOCOLE_PRODUIT),
            ),
            (
                "suppression hors main",
                [0; 3],
                FR_ACT_TO_TBL,
                0,
                toujours(100, 0, PROTOCOLE_PRODUIT),
            ),
        ] {
            let r = regle(&charge_regle_entiere(
                AF_INET, prefixes, action, drapeaux, &attrs,
            ))
            .unwrap_or_else(|e| panic!("{nom}: {e}"));
            assert_eq!(r.forme, None, "{nom}: {r:?}");
            assert_eq!(r.protocole, PROTOCOLE_PRODUIT, "{nom}");
        }
    }

    /// `rtmsg` complet: prefixes, TOS, type, puis les attributs.
    fn charge_route_entiere(
        f: u8,
        prefixes_et_tos: [u8; 3],
        genre: u8,
        attrs: &[Vec<u8>],
    ) -> Vec<u8> {
        let [d, s, t] = prefixes_et_tos;
        let mut v = vec![f, d, s, t, 252, PROTOCOLE_PRODUIT, 0, genre];
        v.extend_from_slice(&0u32.to_ne_bytes());
        for a in attrs {
            v.extend_from_slice(a);
        }
        v
    }

    #[test]
    fn une_route_prend_sa_table_dans_rta_table() {
        assert_eq!(
            route(&charge_route(AF_INET, 252, PROTOCOLE_PRODUIT, Some(51820))).unwrap(),
            RouteLue {
                famille: Famille::Ipv4,
                table: 51820,
                protocole: PROTOCOLE_PRODUIT,
                par_defaut_vers: None,
            }
        );
        assert_eq!(
            route(&charge_route(AF_INET6, 254, 3, None)).unwrap().table,
            254
        );
    }

    /// La route par defaut directe vers une interface, la forme que le
    /// produit pose, rend l'interface; une passerelle, des chemins multiples,
    /// une source, un prefixe ou un autre type n'en rendent aucune.
    #[test]
    fn seule_la_route_par_defaut_directe_rend_son_interface() {
        let oif = u32_attr(RTA_OIF, 7);
        let table = u32_attr(RTA_TABLE, 51820);
        let r = route(&charge_route_entiere(
            AF_INET6,
            [0; 3],
            RTN_UNICAST,
            &[table.clone(), oif.clone(), u32_attr(6, 1024)],
        ))
        .unwrap();
        assert_eq!((r.table, r.par_defaut_vers), (51820, Some(7)));
        for (nom, prefixes, genre, extra) in [
            (
                "passerelle",
                [0; 3],
                RTN_UNICAST,
                vec![attribut(RTA_GATEWAY, &[192, 0, 2, 1])],
            ),
            (
                "multichemin",
                [0; 3],
                RTN_UNICAST,
                vec![attribut(RTA_MULTIPATH, &[0; 8])],
            ),
            (
                "via",
                [0; 3],
                RTN_UNICAST,
                vec![attribut(RTA_VIA, &[2, 0, 192, 0, 2, 1])],
            ),
            (
                "source",
                [0, 24, 0],
                RTN_UNICAST,
                vec![attribut(RTA_SRC, &[192, 0, 2, 0])],
            ),
            (
                "encapsulation",
                [0; 3],
                RTN_UNICAST,
                vec![attribut(RTA_ENCAP, &[0; 4])],
            ),
            ("entree", [0; 3], RTN_UNICAST, vec![u32_attr(RTA_IIF, 3)]),
            ("prefixe", [24, 0, 0], RTN_UNICAST, vec![]),
            ("tos", [0, 0, 16], RTN_UNICAST, vec![]),
            ("trou noir", [0; 3], 6, vec![]),
        ] {
            let mut attrs = vec![table.clone(), oif.clone()];
            attrs.extend(extra);
            let r = route(&charge_route_entiere(AF_INET, prefixes, genre, &attrs))
                .unwrap_or_else(|e| panic!("{nom}: {e}"));
            assert_eq!(r.par_defaut_vers, None, "{nom}");
        }
        let sans_interface = route(&charge_route_entiere(
            AF_INET,
            [0; 3],
            RTN_UNICAST,
            &[table],
        ))
        .unwrap();
        assert_eq!(sans_interface.par_defaut_vers, None);
    }

    #[test]
    fn un_dump_se_lit_jusqu_a_sa_fin() {
        let mut charges = Vec::new();
        let mut d = message(RTM_NEWRULE, 2, 3, &charge_regle(AF_INET, 1, &[]));
        d.extend(message(RTM_NEWRULE, 2, 3, &charge_regle(AF_INET, 1, &[])));
        assert_eq!(
            lire_datagramme(&d, 3, RTM_NEWRULE, &mut charges),
            Ok(Suite::Encore)
        );
        let fin = message(NLMSG_DONE, 2, 3, &0u32.to_ne_bytes());
        assert_eq!(
            lire_datagramme(&fin, 3, RTM_NEWRULE, &mut charges),
            Ok(Suite::Fini)
        );
        assert_eq!(charges.len(), 2);
        // IPv6 absent du noyau: la famille est vide, pas une erreur.
        let absente = message(NLMSG_ERROR, 0, 4, &(-EAFNOSUPPORT).to_ne_bytes());
        assert_eq!(
            lire_datagramme(&absente, 4, RTM_NEWRULE, &mut Vec::new()),
            Ok(Suite::FamilleAbsente)
        );
    }

    /// Ce qui rendrait l'etat incomplet ou etranger est une erreur, pas un
    /// etat vide: une voie lue a moitie paraitrait libre.
    #[test]
    fn un_dump_incomplet_ou_etranger_est_une_erreur() {
        let bon = message(RTM_NEWRULE, 2, 3, &charge_regle(AF_INET, 1, &[]));
        let interrompu = message(
            RTM_NEWRULE,
            2 | NLM_F_DUMP_INTR,
            3,
            &charge_regle(AF_INET, 1, &[]),
        );
        let fin_interrompue = message(NLMSG_DONE, 2 | NLM_F_DUMP_INTR, 3, &0u32.to_ne_bytes());
        let refus = message(NLMSG_ERROR, 0, 3, &(-1i32).to_ne_bytes());
        let fin_en_erreur = message(NLMSG_DONE, 2, 3, &(-16i32).to_ne_bytes());
        let autre_type = message(RTM_NEWROUTE, 2, 3, &charge_route(AF_INET, 254, 3, None));
        let mut tronque = bon.clone();
        tronque.truncate(20);
        let mut trop_long = bon.clone();
        trop_long[0] = 200;
        for (nom, d, seq) in [
            ("interrompu", interrompu, 3),
            ("fin interrompue", fin_interrompue, 3),
            ("refus du noyau", refus, 3),
            ("fin en erreur", fin_en_erreur, 3),
            ("autre type", autre_type, 3),
            ("autre sequence", bon.clone(), 4),
            ("tronque", tronque, 3),
            ("longueur fausse", trop_long, 3),
            ("vide", Vec::new(), 3),
        ] {
            assert!(
                lire_datagramme(&d, seq, RTM_NEWRULE, &mut Vec::new()).is_err(),
                "{nom}: accepte"
            );
        }
        let mut attribut_faux = charge_regle(AF_INET, 1, &[attribut(FRA_TABLE, &[1, 2])]);
        assert!(regle(&attribut_faux).is_err(), "table de deux octets");
        attribut_faux.truncate(14);
        assert!(regle(&attribut_faux).is_err(), "attribut tronque");
        assert!(regle(&[2, 0, 0]).is_err(), "en-tete tronque");
        assert!(regle(&charge_regle(7, 1, &[])).is_err(), "famille inconnue");
        assert!(route(&[10; 5]).is_err(), "route tronquee");
        let mut plage_courte = charge_regle(AF_INET, 1, &[attribut(FRA_UID_RANGE, &[0; 4])]);
        assert!(
            regle(&plage_courte).is_err(),
            "plage de comptes de quatre octets"
        );
        plage_courte.truncate(12);
        assert!(regle(&plage_courte).is_ok(), "temoin: sans l'attribut");
    }
}
