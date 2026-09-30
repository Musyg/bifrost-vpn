//! Collecte Linux strictement passive des regles et des routes: rtnetlink en
//! lecture, sans elevation, sans shell, sans programme externe.
//!
//! # Pourquoi netlink directement, et pas `ip -j`
//!
//! iproute2 6.1.0 (la version de la machine d'essai), `lib/libnetlink.c`, relu
//! le 30/09/2026: sur un message marque NLM_F_DUMP_INTR, `rtnl_dump_filter_l`
//! ecrit << Dump was interrupted and may be inconsistent. >> sur la sortie
//! d'erreur et rend 0; sur MSG_TRUNC il ecrit << Message truncated >> et
//! continue. `ip -j` rendrait donc un dump incoherent ou tronque avec un code
//! de sortie 0, et sa forme JSON change d'une version a l'autre. Lire les
//! messages nous-memes donne chaque drapeau, chaque longueur et chaque
//! attribut, et laisse refuser ce qui n'est pas reconnu.
//!
//! # Sans privilege
//!
//! `rtnetlink_rcv_msg` (`net/core/rtnetlink.c`, v7.0) n'exige CAP_NET_ADMIN que
//! pour ce qui n'est pas une lecture (`kind != RTNL_KIND_GET`). Les dumps de
//! liens, d'adresses, de regles et de routes du namespace courant sont donc
//! lisibles par un compte ordinaire. Mesure sur la machine d'essai: voir le
//! banc `preuve-routes-linux.sh` et la recette de ce module.
//!
//! # L'encadrement, et ce qu'il ne prouve pas
//!
//! Les regles et les routes n'ont pas de numero de generation que l'on puisse
//! lire, a la difference de nftables (`getgen`). Et le noyau v7.0 ne pose
//! NLM_F_DUMP_INTR que sur les dumps qui fixent `cb->seq`: liens
//! (`rtnl_dump_ifinfo`) et adresses (`inet_dump_ifaddr`, `inet6_dump_addr`),
//! PAS sur les regles (`dump_rules`, `net/core/fib_rules.c`) ni sur les routes
//! (`inet_dump_fib`, `inet6_dump_fib`). Pire: un dump de routes IPv6 dont
//! l'arbre change entre deux lots repart de la racine en sautant le nombre
//! d'entrees deja rendues (`fib6_dump_table`), sans rien signaler. Le drapeau
//! est donc refuse partout ou il apparait, mais l'encadrement reel est ailleurs:
//! la collecte entiere est faite DEUX fois et les deux lectures doivent etre
//! identiques (`preuve_routes::encadrer`). Cela ne prouve pas qu'il a existe un
//! instant ou le noyau portait exactement cet etat: un changement qui s'annule
//! entre deux lectures echappe, et ce qui change apres la collecte n'est pas vu.
//!
//! # Ce qui est demande au noyau
//!
//! Le controle strict des requetes (`NETLINK_GET_STRICT_CHK`) est active, et
//! chaque en-tete de requete est nul hors la famille: aucun filtre. Les routes
//! sont demandees SANS leurs exceptions (pas de RTM_F_CLONED): les caches de
//! PMTU et de redirection ne sont pas lus, et le noyau marque alors chaque
//! message NLM_F_DUMP_FILTERED (`fn_trie_dump_leaf`), seul drapeau admis en
//! plus de NLM_F_MULTI.

use std::time::{Duration, Instant};

use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_ROUTE};

use crate::preuve_routes::trames::{self, Attente, Suite};
use crate::preuve_routes::{Observation, Vue};

/// Borne de chaque echange avec le noyau.
const DELAI: Duration = Duration::from_secs(2);
/// Borne de la memoire d'une reponse.
const PLAFOND: usize = 16 * 1024 * 1024;
/// Un datagramme de dump fait au plus 32 Kio (`netlink_dump`); une reponse
/// plus grande que ce tampon est refusee, jamais lue en partie.
const TAMPON: usize = 64 * 1024;
/// MSG_TRUNC (UAPI Linux): connaitre la taille reelle d'un datagramme.
const MSG_TRUNC: i32 = 0x20;

fn erreur_io(e: std::io::Error) -> &'static str {
    if e.kind() == std::io::ErrorKind::PermissionDenied {
        trames::ACCES
    } else {
        "lecture netlink impossible"
    }
}

struct Canal {
    socket: Socket,
    port: u32,
    sequence: u32,
}

impl Canal {
    fn ouvrir() -> Result<Self, &'static str> {
        let mut socket = Socket::new(NETLINK_ROUTE).map_err(erreur_io)?;
        let adresse = socket.bind_auto().map_err(erreur_io)?;
        socket.connect(&SocketAddr::new(0, 0)).map_err(erreur_io)?;
        socket.set_netlink_get_strict_chk(true).map_err(erreur_io)?;
        socket.set_non_blocking(true).map_err(erreur_io)?;
        Ok(Self {
            socket,
            port: adresse.port_number(),
            sequence: 0,
        })
    }

    /// Envoie une requete et lit sa reponse entiere, ou refuse.
    fn echanger(
        &mut self,
        fabriquer: impl FnOnce(u32, u32) -> Vec<u8>,
        genre: u16,
        dump: bool,
        filtre_admis: bool,
    ) -> Result<(Vec<Vec<u8>>, Suite), &'static str> {
        self.sequence += 1;
        let attente = Attente {
            sequence: self.sequence,
            port: self.port,
            genre,
            dump,
            filtre_admis,
        };
        let requete = fabriquer(self.sequence, self.port);
        if self.socket.send(&requete, 0).map_err(erreur_io)? != requete.len() {
            return Err("requete netlink incomplete");
        }
        let debut = Instant::now();
        let mut charges = Vec::new();
        let mut total = 0;
        let mut tampon = vec![0_u8; TAMPON];
        loop {
            if debut.elapsed() >= DELAI {
                return Err("delai netlink depasse");
            }
            match self.socket.recv_from(&mut &mut tampon[..], MSG_TRUNC) {
                Ok((n, source)) => {
                    if n > tampon.len() {
                        return Err("reponse netlink trop grande pour le tampon");
                    }
                    if source.port_number() != 0 {
                        return Err("reponse netlink non authentifiee");
                    }
                    match trames::lire_datagramme(
                        &tampon[..n],
                        &attente,
                        &mut charges,
                        &mut total,
                        PLAFOND,
                    )? {
                        Suite::Encore => {}
                        fin => return Ok((charges, fin)),
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(erreur_io(e)),
            }
        }
    }

    fn dump(&mut self, get: u16, new: u16, famille: u8) -> Result<Vec<Vec<u8>>, &'static str> {
        let (charges, _) = self.echanger(
            |s, p| trames::requete_dump(get, famille, s, p),
            new,
            true,
            new == trames::RTM_NEWROUTE,
        )?;
        Ok(charges)
    }
}

/// Une lecture complete: le lien du tunnel par son nom, puis, pour chaque
/// famille, adresses, regles et routes de toutes les tables.
pub(crate) fn lire_une_fois(interface: &str) -> Result<Observation, &'static str> {
    let mut canal = Canal::ouvrir()?;
    let (charges, suite) = canal.echanger(
        |s, p| trames::requete_lien(interface, s, p),
        trames::RTM_NEWLINK,
        false,
        false,
    )?;
    let tunnel = match suite {
        Suite::Absent => None,
        Suite::Fini => Some(trames::lien(
            charges.first().ok_or("lien netlink absent de la reponse")?,
            interface,
        )?),
        Suite::Encore => return Err("reponse netlink inachevee"),
    };
    let mut vues = [Vue::default(), Vue::default()];
    for (vue, famille) in vues.iter_mut().zip([trames::AF_INET, trames::AF_INET6]) {
        for c in canal.dump(trames::RTM_GETADDR, trames::RTM_NEWADDR, famille)? {
            if let Some(a) = trames::adresse_interface(famille, &c)? {
                vue.adresses.push(a);
            }
        }
        for c in canal.dump(trames::RTM_GETRULE, trames::RTM_NEWRULE, famille)? {
            vue.regles.push(trames::regle(famille, &c)?);
        }
        for c in canal.dump(trames::RTM_GETROUTE, trames::RTM_NEWROUTE, famille)? {
            vue.routes.push(trames::route(famille, &c)?);
        }
    }
    let [ipv4, ipv6] = vues;
    Ok(Observation { tunnel, ipv4, ipv6 })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Face au noyau, sans privilege: le namespace courant se lit, et on y
    /// retrouve ce que le noyau pose toujours (regles `local` a la priorite 0
    /// et `main` dans les deux familles, et la boucle locale). Passif: rien
    /// n'est pose. Ne tourne que sous Linux, sans aucune abstention.
    #[test]
    fn le_namespace_courant_se_lit_sans_privilege() {
        let o = lire_une_fois("lo").expect("lecture rtnetlink du namespace courant");
        assert!(o.tunnel.is_some_and(|i| i > 0), "lo doit exister");
        for (nom, vue) in [("ipv4", &o.ipv4), ("ipv6", &o.ipv6)] {
            assert!(
                vue.regles
                    .iter()
                    .any(|r| r.pref == 0 && r.table == 255 && r.protocole == 2),
                "{nom}: regle local du noyau absente"
            );
            assert!(
                vue.regles
                    .iter()
                    .any(|r| r.table == 254 && r.protocole == 2),
                "{nom}: regle main du noyau absente"
            );
            assert!(
                vue.regles.windows(2).all(|p| p[0].pref <= p[1].pref),
                "{nom}: le dump rend les regles dans l'ordre d'evaluation"
            );
        }
        assert!(
            o.ipv4
                .routes
                .iter()
                .any(|r| r.table == 255 && r.genre == 2 && r.oif == o.tunnel),
            "ipv4: la boucle locale doit porter une route local"
        );
    }

    /// Une interface qui n'existe pas n'est pas une erreur de collecte: le
    /// noyau le dit (ENODEV), et la preuve le lira comme une table du tunnel
    /// sans sa route.
    #[test]
    fn une_interface_absente_est_rendue_absente() {
        let o = lire_une_fois("bfabsent9z").expect("lecture rtnetlink");
        assert_eq!(o.tunnel, None);
    }
}
