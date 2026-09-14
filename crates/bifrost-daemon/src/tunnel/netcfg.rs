//! Construction des commandes `ip` qui montent et demontent le routage.
//!
//! Fonctions pures: elles renvoient des listes d'arguments, sans rien executer.
//! C'est ce qui permet de tester la politique de routage (celle qui evite les
//! fuites) sans avoir besoin de root ni d'une interface reelle.
//!
//! Le mecanisme est celui de wg-quick, decrit au document 02 partie 2.1.

use bifrost_core::TunnelConfig;

/// Une commande a executer: le programme et ses arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cmd {
    pub program: &'static str,
    pub args: Vec<String>,
    /// Si vrai, un code de retour non nul est journalise mais n'interrompt pas
    /// la sequence. Sert au demontage, ou une regle deja absente est normale.
    pub tolerate_failure: bool,
}

impl Cmd {
    pub(crate) fn ip(args: &[&str]) -> Self {
        Self {
            program: "ip",
            args: args.iter().map(|s| (*s).to_owned()).collect(),
            tolerate_failure: false,
        }
    }

    pub(crate) fn ip_lenient(args: &[&str]) -> Self {
        Self {
            tolerate_failure: true,
            ..Self::ip(args)
        }
    }

    pub fn display(&self) -> String {
        format!("{} {}", self.program, self.args.join(" "))
    }
}

/// Cree l'interface WireGuard.
///
/// `ip link add type wireguard` est prefere a une creation par netlink maison:
/// c'est la meme operation, deja correcte partout, et elle echoue proprement si
/// le module noyau est absent.
pub fn create_link(cfg: &TunnelConfig) -> Cmd {
    Cmd::ip(&["link", "add", "dev", &cfg.interface, "type", "wireguard"])
}

/// Adresses, MTU et mise en service de l'interface.
pub fn configure_link(cfg: &TunnelConfig) -> Vec<Cmd> {
    let mut cmds = Vec::new();
    for addr in &cfg.addresses {
        let family = if addr.is_ipv4() { "-4" } else { "-6" };
        cmds.push(Cmd::ip(&[
            family,
            "address",
            "add",
            &addr.to_string(),
            "dev",
            &cfg.interface,
        ]));
    }
    cmds.push(Cmd::ip(&[
        "link",
        "set",
        "mtu",
        &cfg.mtu.to_string(),
        "up",
        "dev",
        &cfg.interface,
    ]));
    cmds
}

/// Routes et regles de politique de routage.
///
/// Le couple `not fwmark X table Y` plus `suppress_prefixlength 0` est le coeur
/// du montage: le trafic non encore chiffre part dans la table Y dont la route
/// par defaut est le tunnel, tandis que le trafic deja chiffre par WireGuard,
/// qui porte la marque, echappe a cette regle et sort par l'interface physique.
/// `suppress_prefixlength 0` fait ignorer la seule route par defaut de la table
/// main, ce qui preserve les routes LAN specifiques.
pub fn add_routing(cfg: &TunnelConfig) -> Vec<Cmd> {
    // Ces commandes n'existent que pour WireGuard: c'est sa marque qui echappe
    // a la regle, et sa table dediee qui porte la route par defaut. Le chemin
    // par coeur a son propre aiguillage, avec sa table. Rendre une liste vide
    // plutot qu'echouer, parce que le seul appelant est le peripherique
    // WireGuard, qui sait deja dans quel cas il est.
    let Some(wg) = cfg.portage.wireguard() else {
        return Vec::new();
    };
    let table = wg.routing_table.to_string();
    let mark = wg.fwmark.to_string();
    let mut cmds = Vec::new();

    // Les deux familles sont traitees meme si le tunnel n'a pas d'adresse IPv6:
    // sans route par defaut IPv6 dans le tunnel, l'IPv6 sortirait par
    // l'interface physique. C'est le vecteur de fuite IPv6 classique.
    for (family, default_route) in [("-4", "0.0.0.0/0"), ("-6", "::/0")] {
        cmds.push(Cmd::ip(&[
            family,
            "route",
            "add",
            default_route,
            "dev",
            &cfg.interface,
            "table",
            &table,
        ]));
        cmds.push(Cmd::ip(&[
            family, "rule", "add", "not", "fwmark", &mark, "table", &table,
        ]));
        cmds.push(Cmd::ip(&[
            family,
            "rule",
            "add",
            "table",
            "main",
            "suppress_prefixlength",
            "0",
        ]));
    }
    cmds
}

/// Retrait des regles et de l'interface.
///
/// Toutes les commandes tolerent l'echec: le demontage doit aboutir a un
/// systeme propre meme s'il est appele apres un demontage partiel ou un crash.
/// Supprimer le lien supprime aussi les routes de la table dediee.
pub fn teardown(cfg: &TunnelConfig) -> Vec<Cmd> {
    // Ces commandes n'existent que pour WireGuard: c'est sa marque qui echappe
    // a la regle, et sa table dediee qui porte la route par defaut. Le chemin
    // par coeur a son propre aiguillage, avec sa table. Rendre une liste vide
    // plutot qu'echouer, parce que le seul appelant est le peripherique
    // WireGuard, qui sait deja dans quel cas il est.
    let Some(wg) = cfg.portage.wireguard() else {
        return Vec::new();
    };
    let table = wg.routing_table.to_string();
    let mark = wg.fwmark.to_string();
    let mut cmds = Vec::new();

    for family in ["-4", "-6"] {
        cmds.push(Cmd::ip_lenient(&[
            family, "rule", "del", "not", "fwmark", &mark, "table", &table,
        ]));
        cmds.push(Cmd::ip_lenient(&[
            family,
            "rule",
            "del",
            "table",
            "main",
            "suppress_prefixlength",
            "0",
        ]));
        cmds.push(Cmd::ip_lenient(&[
            family, "route", "flush", "table", &table,
        ]));
    }
    cmds.push(Cmd::ip_lenient(&["link", "del", "dev", &cfg.interface]));
    cmds
}

#[cfg(test)]
mod tests {
    use super::*;
    use bifrost_core::config::{DnsPolicy, Endpoint, PeerConfig, WgKey};
    use std::net::{IpAddr, Ipv4Addr};

    /// Le 43e caractere d'une cle ne porte que quatre bits utiles, donc tous
    /// ne conviennent pas. 'A' vaut zero: il termine n'importe quelle cle.
    fn key(c: char) -> WgKey {
        let mut s: String = std::iter::repeat_n(c, 42).collect();
        s.push('A');
        s.push('=');
        s.parse().unwrap()
    }

    fn cfg() -> TunnelConfig {
        TunnelConfig {
            interface: "wg0".into(),
            addresses: vec!["10.2.0.2/32".parse().unwrap()],
            mtu: 1420,
            portage: bifrost_core::config::Portage::Wireguard(Box::new(
                bifrost_core::config::WireguardParams {
                    private_key: key('a'),
                    fwmark: 0xca6c,
                    routing_table: 51820,
                    listen_port: None,
                    peer: PeerConfig {
                        public_key: key('b'),
                        preshared_key: None,
                        endpoint: Endpoint {
                            addr: "203.0.113.7:51820".parse().unwrap(),
                        },
                        allowed_ips: vec!["0.0.0.0/0".parse().unwrap(), "::/0".parse().unwrap()],
                        persistent_keepalive: 25,
                    },
                },
            )),
            dns: DnsPolicy {
                local_resolver: IpAddr::V4(Ipv4Addr::LOCALHOST),
                upstream: vec![IpAddr::V4(Ipv4Addr::new(10, 2, 0, 1))],
                embarque: false,
                anti_telemetrie: bifrost_core::config::ProfilTelemetrie::Aucun,
            },
            allow_lan: false,
        }
    }

    /// Les parametres WireGuard d'une configuration de test, modifiables.
    /// Panique si le portage n'est pas WireGuard: seul un test mal ecrit peut
    /// y arriver.
    fn wg(c: &mut TunnelConfig) -> &mut bifrost_core::config::WireguardParams {
        match &mut c.portage {
            bifrost_core::config::Portage::Wireguard(w) => w,
            bifrost_core::config::Portage::Coeur(_) => {
                panic!("ce test suppose un portage WireGuard")
            }
        }
    }

    fn lignes(cmds: &[Cmd]) -> Vec<String> {
        cmds.iter().map(Cmd::display).collect()
    }

    #[test]
    fn creation_de_l_interface_wireguard() {
        assert_eq!(
            create_link(&cfg()).display(),
            "ip link add dev wg0 type wireguard"
        );
    }

    #[test]
    fn les_adresses_et_le_mtu_sont_poses() {
        let l = lignes(&configure_link(&cfg()));
        assert!(l.contains(&"ip -4 address add 10.2.0.2/32 dev wg0".to_owned()));
        assert!(l.contains(&"ip link set mtu 1420 up dev wg0".to_owned()));
    }

    #[test]
    fn une_adresse_ipv6_utilise_la_bonne_famille() {
        let mut c = cfg();
        c.addresses = vec!["fd00::2/128".parse().unwrap()];
        let l = lignes(&configure_link(&c));
        assert!(l.contains(&"ip -6 address add fd00::2/128 dev wg0".to_owned()));
    }

    /// Le coeur du mecanisme wg-quick.
    #[test]
    fn la_regle_fwmark_et_la_suppression_de_prefixe_sont_posees() {
        let l = lignes(&add_routing(&cfg()));
        assert!(l.contains(&"ip -4 rule add not fwmark 51820 table 51820".to_owned()));
        assert!(l.contains(&"ip -4 rule add table main suppress_prefixlength 0".to_owned()));
        assert!(l.contains(&"ip -4 route add 0.0.0.0/0 dev wg0 table 51820".to_owned()));
    }

    /// Sans route par defaut IPv6 dans le tunnel, l'IPv6 fuit par l'interface
    /// physique meme quand IPv4 est correctement route.
    #[test]
    fn l_ipv6_est_route_dans_le_tunnel_meme_sans_adresse_ipv6() {
        let mut c = cfg();
        c.addresses = vec!["10.2.0.2/32".parse().unwrap()];
        let l = lignes(&add_routing(&c));
        assert!(l.contains(&"ip -6 route add ::/0 dev wg0 table 51820".to_owned()));
        assert!(l.contains(&"ip -6 rule add not fwmark 51820 table 51820".to_owned()));
    }

    #[test]
    fn le_fwmark_de_la_config_est_utilise_partout() {
        let mut c = cfg();
        wg(&mut c).fwmark = 0x1234;
        wg(&mut c).routing_table = 4660;
        let l = lignes(&add_routing(&c)).join("\n");
        assert!(l.contains("not fwmark 4660 table 4660") || l.contains("not fwmark 4660"));
        assert!(!l.contains("51820"));
    }

    #[test]
    fn le_demontage_tolere_l_absence_des_regles() {
        let cmds = teardown(&cfg());
        assert!(
            cmds.iter().all(|c| c.tolerate_failure),
            "le demontage doit aboutir meme partiellement applique"
        );
    }

    #[test]
    fn le_demontage_retire_regles_routes_et_interface() {
        let l = lignes(&teardown(&cfg())).join("\n");
        assert!(l.contains("rule del not fwmark 51820"));
        assert!(l.contains("rule del table main suppress_prefixlength 0"));
        assert!(l.contains("link del dev wg0"));
        // v4 et v6 pour les regles.
        assert_eq!(l.matches("rule del not fwmark").count(), 2);
    }

    /// Le demontage doit annuler exactement ce que le montage a pose.
    #[test]
    fn montage_et_demontage_sont_symetriques() {
        let c = cfg();
        let up = lignes(&add_routing(&c));
        let down = lignes(&teardown(&c));
        for cmd in &up {
            let inverse = cmd.replacen(" add ", " del ", 1);
            let couvert = down.contains(&inverse)
                // les routes de la table dediee partent avec `route flush`
                || (cmd.contains("route add") && down.iter().any(|d| d.contains("route flush")));
            assert!(couvert, "aucun inverse pour: {cmd}");
        }
    }

    /// Le nom d'interface vient de la config, deja validee, mais on verifie
    /// qu'il est passe comme argument distinct et jamais concatene dans un
    /// shell: aucune commande ne doit passer par un interpreteur.
    #[test]
    fn les_arguments_ne_sont_jamais_concatenes() {
        for cmd in add_routing(&cfg()) {
            assert!(
                cmd.args.iter().all(|a| !a.contains(' ')),
                "argument contenant un espace: {cmd:?}"
            );
        }
    }
}
