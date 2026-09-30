//! Outil du banc jetable `preuve-routes-linux.sh`: rend, une par ligne, les
//! arguments des commandes `ip` que le produit execute pour poser son routage,
//! sans en executer une seule. Ce sont les fonctions de la pose elles-memes
//! (`netcfg::add_routing`, `aiguillage::poser`), pas une copie: le banc pose
//! exactement ce que le daemon poserait.
//!
//! `routage_produit wireguard <interface> <fwmark> <table>`
//! `routage_produit coeur <interface> [<uid>]`

#[cfg(target_os = "linux")]
fn main() {
    use bifrost_daemon::tunnel::{aiguillage, netcfg};

    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let cmds = match args.as_slice() {
        ["wireguard", interface, marque, table] => netcfg::add_routing(&configuration(
            interface,
            marque.parse().expect("fwmark entier"),
            table.parse().expect("table entiere"),
        )),
        ["coeur", interface] => aiguillage::poser(&aiguillage::Aiguillage {
            interface: (*interface).to_owned(),
            coeur_uid: None,
        }),
        ["coeur", interface, uid] => aiguillage::poser(&aiguillage::Aiguillage {
            interface: (*interface).to_owned(),
            coeur_uid: Some(uid.parse().expect("uid entier")),
        }),
        _ => {
            eprintln!("usage: wireguard <interface> <fwmark> <table> | coeur <interface> [<uid>]");
            std::process::exit(2);
        }
    };
    for c in cmds {
        // La pose n'a que des commandes `ip`, aucune toleree en echec: le banc
        // s'arrete a la premiere qui echoue, comme le daemon.
        assert!(c.program == "ip" && !c.tolerate_failure, "{}", c.display());
        println!("{}", c.args.join(" "));
    }
}

/// Une configuration WireGuard dont seuls l'interface, la marque et la table
/// comptent pour `add_routing`; le reste est une valeur de documentation.
#[cfg(target_os = "linux")]
fn configuration(interface: &str, fwmark: u32, routing_table: u32) -> bifrost_core::TunnelConfig {
    use bifrost_core::config::{
        DnsPolicy, Endpoint, PeerConfig, Portage, ProfilTelemetrie, WgKey, WireguardParams,
    };
    use std::net::{IpAddr, Ipv4Addr};

    // Le 43e caractere d'une cle ne porte que quatre bits utiles: 'A' (zero)
    // termine n'importe quelle cle.
    let cle = |c: char| -> WgKey {
        let mut s: String = std::iter::repeat_n(c, 42).collect();
        s.push_str("A=");
        s.parse().expect("cle de documentation")
    };
    bifrost_core::TunnelConfig {
        interface: interface.to_owned(),
        addresses: vec!["198.51.100.2/32".parse().expect("adresse de documentation")],
        mtu: 1420,
        portage: Portage::Wireguard(Box::new(WireguardParams {
            private_key: cle('a'),
            fwmark,
            routing_table,
            listen_port: None,
            peer: PeerConfig {
                public_key: cle('b'),
                preshared_key: None,
                endpoint: Endpoint {
                    addr: "203.0.113.7:51820".parse().expect("point de documentation"),
                },
                allowed_ips: vec![
                    "0.0.0.0/0".parse().expect("route IPv4"),
                    "::/0".parse().expect("route IPv6"),
                ],
                persistent_keepalive: 25,
            },
        })),
        dns: DnsPolicy {
            local_resolver: IpAddr::V4(Ipv4Addr::LOCALHOST),
            upstream: vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53))],
            embarque: false,
            anti_telemetrie: ProfilTelemetrie::Aucun,
        },
        allow_lan: false,
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("Banc de routage Linux uniquement");
    std::process::exit(2);
}
