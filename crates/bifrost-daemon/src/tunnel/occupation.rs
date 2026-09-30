//! Ce qu'un tiers occupe deja de ce que le produit va poser, lu dans le noyau
//! avant la premiere commande du montage.
//!
//! # Pourquoi ce module existe
//!
//! Les valeurs par defaut du produit (table 51820, marque 51820) sont celles
//! de wg-quick. Mesure du 30/09/2026 sur essai-linux, en namespace jetable, par
//! `LinuxTunnel::up` et `down` de la base `91d614f`: un tiers pose dans la
//! meme table faisait echouer la pose (la route par defaut y etait deja), puis
//! le nettoyage vidait sa table et retirait ses regles. Le retrait est
//! desormais exact (voir `bifrost_core::routage`), et ce module fait le reste:
//! avant de poser, il lit les regles et les routes des deux familles et refuse
//! de monter dans une table ou sur une marque qu'un tiers emploie deja, en le
//! nommant (`Plan::occupation`, `Plan::refus_d_occupation`). Rien n'est pose.
//!
//! # Ce qui borne la course entre la lecture et la pose
//!
//! Un tiers peut s'installer entre la lecture et la derniere commande de pose.
//! Deux cas, et aucun ne fait retirer au produit ce qui n'est pas a lui: une
//! route par defaut posee dans la table avant la notre fait echouer la pose
//! (EEXIST), et le nettoyage qui suit ne retire que ce qui porte l'etiquette
//! du produit; toute autre installation (une route plus specifique, une regle)
//! cohabite, et le demontage la laisse en place pour la meme raison. La
//! lecture est un refus nomme, pas la garantie: la garantie est le retrait
//! exact. La fenetre elle-meme dure le temps de creer l'interface et de lancer
//! les commandes de pose.
//!
//! # Pourquoi pas la collecte de `prove routes`
//!
//! Elle vit dans la CLI, que le daemon ne peut pas importer, et sa politique
//! est l'inverse de celle qu'il faut ici: elle REFUSE tout attribut qu'elle ne
//! reconnait pas (la preuve devient alors non mesuree), ce qui, avant une
//! pose, empecherait le tunnel de monter sur un noyau qui ajoute un attribut
//! de regle. Ici seuls la table, la priorite, la marque, l'action et
//! l'etiquette comptent; un attribut inconnu est ignore, une trame mal formee
//! ou un dump interrompu est une erreur. Sans shell ni programme externe:
//! rtnetlink en lecture, que le noyau accorde sans privilege
//! (`rtnetlink_rcv_msg`, v7.0).
//!
//! La lecture des trames est pure et compilee partout, pour que ses recettes
//! tournent aussi sous Windows; le canal netlink n'existe que sous Linux.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use bifrost_core::routage::{Famille, PROTOCOLE_PRODUIT, Plan, RegleLue, RouteLue};
use bifrost_core::{Error, Result};

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
const FRA_PRIORITY: u16 = 6;
const FRA_FWMARK: u16 = 10;
const FRA_TABLE: u16 = 15;
const FRA_FWMASK: u16 = 16;
const FRA_PROTOCOL: u16 = 21;
const RTA_TABLE: u16 = 15;
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
pub(crate) fn regle(charge: &[u8]) -> std::result::Result<RegleLue, String> {
    if charge.len() < 12 {
        return Err("regle netlink tronquee".into());
    }
    let f = famille(charge[0])?;
    let action = charge[7];
    let mut table = u32::from(charge[4]);
    let (mut priorite, mut protocole) = (0, 0);
    let (mut marque, mut masque) = (None, None);
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
            _ => {}
        }
    }
    Ok(RegleLue {
        famille: f,
        priorite,
        table: (action == FR_ACT_TO_TBL).then_some(table),
        marque: (marque.is_some() || masque.is_some())
            .then(|| (marque.unwrap_or(0), masque.unwrap_or(u32::MAX))),
        protocole,
    })
}

/// Une route (`RTM_NEWROUTE`: `rtmsg`, puis attributs `RTA_*`). La table est
/// `RTA_TABLE` quand elle y est: le champ de huit bits de `rtmsg` ne tient pas
/// une table au-dela de 255.
pub(crate) fn route(charge: &[u8]) -> std::result::Result<RouteLue, String> {
    if charge.len() < 12 {
        return Err("route netlink tronquee".into());
    }
    let f = famille(charge[0])?;
    let mut table = u32::from(charge[4]);
    for (t, v) in attributs(&charge[12..])? {
        if t == RTA_TABLE {
            table = valeur_u32(v)?;
        }
    }
    Ok(RouteLue {
        famille: f,
        table,
        protocole: charge[5],
    })
}

/// Ce que la lecture rend: les regles et les routes des deux familles.
pub(crate) type Etat = (Vec<RegleLue>, Vec<RouteLue>);

/// Un reste d'une session precedente du produit: une regle ou une route qui
/// porte son etiquette.
pub(crate) fn restes_du_produit((regles, routes): &Etat) -> bool {
    regles.iter().any(|r| r.protocole == PROTOCOLE_PRODUIT)
        || routes.iter().any(|r| r.protocole == PROTOCOLE_PRODUIT)
}

/// Avant la premiere commande du montage: lire, retirer les restes du produit
/// s'il y en a (par `retirer_restes`, qui ne designe que ce qui porte son
/// etiquette), relire, puis refuser une voie occupee.
///
/// Separee de la lecture reelle pour que les recettes la jouent avec une
/// fausse lecture, sur toutes les plateformes.
pub(crate) fn preparer_avec(
    plan: &Plan,
    mut lire: impl FnMut() -> Result<Etat>,
    retirer_restes: impl FnOnce(),
) -> Result<()> {
    let mut etat = lire()?;
    if restes_du_produit(&etat) {
        tracing::warn!(
            "regles ou routes laissees par une session precedente du produit: \
             retrait exact avant la pose"
        );
        retirer_restes();
        etat = lire()?;
    }
    let occupations = plan.occupation(&etat.0, &etat.1);
    if occupations.is_empty() {
        return Ok(());
    }
    Err(Error::Tunnel(plan.refus_d_occupation(&occupations)))
}

/// La lecture reelle, puis [`preparer_avec`].
#[cfg(target_os = "linux")]
pub(crate) fn preparer(plan: &Plan, retirer_restes: impl FnOnce()) -> Result<()> {
    preparer_avec(plan, canal::lire, retirer_restes)
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

    /// Une regle du produit telle que le noyau la rend (`not fwmark 51820
    /// table 51820 protocol 177`, priorite choisie par le noyau), et une
    /// regle sans table: un attribut inconnu est ignore.
    #[test]
    fn une_regle_se_lit_table_marque_priorite_et_etiquette() {
        let c = charge_regle(
            AF_INET,
            FR_ACT_TO_TBL,
            &[
                attribut(FRA_PRIORITY, &32765u32.to_ne_bytes()),
                attribut(FRA_FWMARK, &51820u32.to_ne_bytes()),
                attribut(FRA_FWMASK, &u32::MAX.to_ne_bytes()),
                attribut(FRA_TABLE, &51820u32.to_ne_bytes()),
                attribut(FRA_PROTOCOL, &[PROTOCOLE_PRODUIT]),
                attribut(29, &[1, 2]),
            ],
        );
        assert_eq!(
            regle(&c).unwrap(),
            RegleLue {
                famille: Famille::Ipv4,
                priorite: 32765,
                table: Some(51820),
                marque: Some((51820, u32::MAX)),
                protocole: PROTOCOLE_PRODUIT,
            }
        );
        // Un rejet (`unreachable`, action 7) ne consulte aucune table.
        let c = charge_regle(
            AF_INET6,
            7,
            &[attribut(FRA_PRIORITY, &5250u32.to_ne_bytes())],
        );
        let r = regle(&c).unwrap();
        assert_eq!((r.famille, r.table, r.marque), (Famille::Ipv6, None, None));
    }

    #[test]
    fn une_route_prend_sa_table_dans_rta_table() {
        assert_eq!(
            route(&charge_route(AF_INET, 252, PROTOCOLE_PRODUIT, Some(51820))).unwrap(),
            RouteLue {
                famille: Famille::Ipv4,
                table: 51820,
                protocole: PROTOCOLE_PRODUIT
            }
        );
        assert_eq!(
            route(&charge_route(AF_INET6, 254, 3, None)).unwrap().table,
            254
        );
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
    }

    fn plan() -> Plan {
        Plan::wireguard("wg0", 51820, 51820)
    }

    fn noyau() -> Vec<RegleLue> {
        Famille::TOUTES
            .iter()
            .map(|f| RegleLue {
                famille: *f,
                priorite: 0,
                table: Some(255),
                marque: None,
                protocole: 2,
            })
            .collect()
    }

    /// Une voie libre: une seule lecture, rien de retire, pas de refus.
    #[test]
    fn une_voie_libre_se_prepare_sans_rien_retirer() {
        let mut lectures = 0;
        let mut retire = false;
        preparer_avec(
            &plan(),
            || {
                lectures += 1;
                Ok((noyau(), Vec::new()))
            },
            || retire = true,
        )
        .unwrap();
        assert_eq!((lectures, retire), (1, false));
    }

    /// Un tiers dans la table: refus nomme, et rien n'est retire.
    #[test]
    fn une_voie_occupee_est_refusee_sans_rien_retirer() {
        let mut retire = false;
        let e = preparer_avec(
            &plan(),
            || {
                Ok((
                    noyau(),
                    vec![RouteLue {
                        famille: Famille::Ipv6,
                        table: 51820,
                        protocole: 3,
                    }],
                ))
            },
            || retire = true,
        )
        .expect_err("voie occupee acceptee")
        .to_string();
        assert!(!retire);
        assert!(
            e.contains("ipv6: 1 route(s) dans la table 51820") && e.contains("montage refuse"),
            "{e}"
        );
    }

    /// Un reste du produit: il est retire, la voie relue, et c'est la seconde
    /// lecture qui decide. Un tiers reste un tiers apres le retrait.
    #[test]
    fn un_reste_du_produit_est_retire_puis_la_voie_relue() {
        let reste = RouteLue {
            famille: Famille::Ipv4,
            table: 51820,
            protocole: PROTOCOLE_PRODUIT,
        };
        let tiers = RegleLue {
            famille: Famille::Ipv4,
            priorite: 32000,
            table: Some(51820),
            marque: None,
            protocole: 0,
        };
        for (apres, libre) in [(Vec::new(), true), (vec![tiers], false)] {
            let mut lectures = 0;
            let mut retraits = 0;
            let r = preparer_avec(
                &plan(),
                || {
                    lectures += 1;
                    Ok(if lectures == 1 {
                        (noyau(), vec![reste])
                    } else {
                        let mut regles = noyau();
                        regles.extend(apres.iter().copied());
                        (regles, Vec::new())
                    })
                },
                || retraits += 1,
            );
            assert_eq!((lectures, retraits), (2, 1));
            assert_eq!(r.is_ok(), libre, "{r:?}");
        }
    }

    /// Une lecture impossible n'est pas une voie libre.
    #[test]
    fn une_lecture_impossible_empeche_le_montage() {
        let r = preparer_avec(
            &plan(),
            || Err(Error::Tunnel("lecture impossible".into())),
            || {},
        );
        assert!(r.is_err());
    }
}
