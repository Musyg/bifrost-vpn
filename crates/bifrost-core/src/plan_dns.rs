//! Le plan DNS que le produit pose, en donnees pures.
//!
//! # Pourquoi ce module existe
//!
//! Sous Linux, le produit pose son DNS par l'un de deux rendus: les commandes
//! `resolvectl` quand systemd-resolved tourne, ou le contenu de
//! `/etc/resolv.conf` sinon (`bifrost_dns::linux`). La preuve `prove dns` doit
//! comparer l'etat du systeme a ce que le produit pose; si elle recopiait ces
//! rendus a la main, sa reference pourrait diverger de la pose sans que rien ne
//! le dise. Le plan et ses deux rendus vivent donc ICI, une seule fois: le
//! gestionnaire DNS en tire ses commandes et son fichier, la preuve son
//! attendu. Ce crate ne touche ni au reseau ni au systeme, et il est compile
//! partout: les recettes du plan tournent aussi sous Windows.
//!
//! # Ce que le plan ne dit pas
//!
//! Le backend. Le daemon le choisit a l'execution (`bifrost_dns::linux::
//! detect`), selon que systemd-resolved repond ou non, et ce choix n'est ecrit
//! nulle part ailleurs. La preuve le prend donc de son intention, declaree, et
//! ne le devine pas.

use std::net::IpAddr;

use crate::config::DnsPolicy;

/// Ce qui, dans `/etc/resolv.conf`, dit que le fichier est celui du produit.
/// Le gestionnaire DNS Linux s'en sert aussi pour reconnaitre son propre
/// fichier: une seule definition pour les deux usages.
pub const MARQUEUR_RESOLV_CONF: &str = "genere par bifrost";

/// Qui le systeme doit interroger, selon qu'un resolveur chiffre est embarque.
///
/// Un seul serveur, sur la boucle locale, quand un resolveur est embarque: y
/// ajouter les amonts en secours annulerait tout, car au premier hoquet du
/// resolveur chiffre le systeme basculerait sur une resolution en clair, sans
/// rien dire. Sinon, les amonts, dans l'ordre du profil.
pub fn serveurs_a_interroger(policy: &DnsPolicy) -> Vec<IpAddr> {
    if policy.embarque {
        vec![policy.local_resolver]
    } else {
        policy.upstream.clone()
    }
}

/// Les arguments `resolvectl` qui basculent le DNS sur le lien du tunnel:
/// les serveurs, puis le domaine `~.`, qui fait de ce lien la route de TOUTES
/// les requetes. Sans lui, systemd-resolved fait du split DNS et interroge en
/// parallele les resolveurs des autres liens, dont celui pousse par DHCP.
pub fn commandes_resolved(interface: &str, serveurs: &[IpAddr]) -> Vec<Vec<String>> {
    let mut dns = vec!["dns".to_owned(), interface.to_owned()];
    dns.extend(serveurs.iter().map(|a| a.to_string()));
    vec![
        dns,
        vec!["domain".to_owned(), interface.to_owned(), "~.".to_owned()],
    ]
}

/// Le contenu de `/etc/resolv.conf` pose pendant la duree du tunnel: une
/// ligne de marqueur, une ligne `nameserver` par serveur, dans l'ordre, puis
/// les options.
pub fn contenu_resolv_conf(serveurs: &[IpAddr]) -> String {
    let mut contenu = format!("# {MARQUEUR_RESOLV_CONF}, restaure a la deconnexion\n");
    for s in serveurs {
        contenu.push_str(&format!("nameserver {s}\n"));
    }
    contenu.push_str("options edns0 trust-ad\n");
    contenu
}

/// Le plan DNS du produit: le lien du tunnel et les serveurs qu'il designe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanDns {
    /// L'interface du tunnel, ou le backend systemd-resolved pose.
    pub interface: String,
    /// Les serveurs a interroger, dans l'ordre ([`serveurs_a_interroger`]).
    pub serveurs: Vec<IpAddr>,
}

impl PlanDns {
    /// Le plan que le produit pose pour ce tunnel et cette politique.
    pub fn nouveau(interface: &str, policy: &DnsPolicy) -> Self {
        Self {
            interface: interface.to_owned(),
            serveurs: serveurs_a_interroger(policy),
        }
    }

    /// Les commandes du backend systemd-resolved, telles que le produit les
    /// execute.
    pub fn commandes_resolved(&self) -> Vec<Vec<String>> {
        commandes_resolved(&self.interface, &self.serveurs)
    }

    /// Le fichier du backend resolv.conf, tel que le produit l'ecrit.
    pub fn contenu_resolv_conf(&self) -> String {
        contenu_resolv_conf(&self.serveurs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ProfilTelemetrie;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn politique(embarque: bool) -> DnsPolicy {
        DnsPolicy {
            local_resolver: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 53)),
            upstream: vec![
                IpAddr::V4(Ipv4Addr::new(10, 2, 0, 1)),
                IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)),
            ],
            embarque,
            anti_telemetrie: ProfilTelemetrie::Aucun,
        }
    }

    fn lignes(cmds: &[Vec<String>]) -> Vec<String> {
        cmds.iter().map(|c| c.join(" ")).collect()
    }

    /// Les rendus du plan, au caractere pres, tels que le gestionnaire DNS les
    /// rendait avant que le plan existe (memes textes que les recettes de
    /// `bifrost_dns::linux`, qui ne tournent que sous Linux).
    #[test]
    fn les_rendus_du_plan_sont_ceux_de_la_pose_au_caractere_pres() {
        let amont = PlanDns::nouveau("wg0", &politique(false));
        assert_eq!(
            lignes(&amont.commandes_resolved()),
            ["dns wg0 10.2.0.1 fd00::1", "domain wg0 ~."]
        );
        assert_eq!(
            amont.contenu_resolv_conf(),
            "# genere par bifrost, restaure a la deconnexion\n\
             nameserver 10.2.0.1\n\
             nameserver fd00::1\n\
             options edns0 trust-ad\n"
        );
        let embarque = PlanDns::nouveau("bifrost0", &politique(true));
        assert_eq!(
            lignes(&embarque.commandes_resolved()),
            ["dns bifrost0 127.0.0.53", "domain bifrost0 ~."]
        );
        assert_eq!(
            embarque.contenu_resolv_conf(),
            "# genere par bifrost, restaure a la deconnexion\n\
             nameserver 127.0.0.53\n\
             options edns0 trust-ad\n"
        );
    }

    /// Le plan et les fonctions libres sont la meme source: les rendus du plan
    /// sont ceux des fonctions appelees sur ses champs.
    #[test]
    fn le_plan_rend_par_les_fonctions_libres() {
        for embarque in [false, true] {
            let p = PlanDns::nouveau("wg0", &politique(embarque));
            assert_eq!(p.serveurs, serveurs_a_interroger(&politique(embarque)));
            assert_eq!(
                p.commandes_resolved(),
                commandes_resolved("wg0", &serveurs_a_interroger(&politique(embarque)))
            );
            assert_eq!(
                p.contenu_resolv_conf(),
                contenu_resolv_conf(&serveurs_a_interroger(&politique(embarque)))
            );
        }
    }
}
