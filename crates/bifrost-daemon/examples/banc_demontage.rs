//! Outil du banc jetable `banc-demontage-routage-linux.sh`: monte et demonte
//! le routage du produit par ses fonctions a lui, dans le namespace reseau ou
//! il est lance.
//!
//! `banc_demontage wireguard monter|demonter <interface> <fwmark> <table>`
//! appelle `LinuxTunnel::up` et `down`, le vrai peripherique: interface
//! WireGuard, cles, adresses, routes et regles (le module noyau `wireguard`
//! est necessaire).
//!
//! `banc_demontage coeur monter|demonter <interface> [<uid>]` fait ce que
//! `CoeurTunnel::monter_ici` et `demonter_ici` font du routage: au montage
//! `coeur::preparer_aiguillage`, puis chaque commande d'`aiguillage::poser`,
//! et au premier echec toutes celles d'`aiguillage::retirer`; au demontage
//! toutes celles d'`aiguillage::retirer`, echecs toleres. Le TUN et le
//! passage n'en font pas partie: le banc pose a leur place une interface
//! factice du meme nom.
//!
//! Code 0: fait. Code 1: refuse ou echoue, la raison sur la sortie d'erreur.
//! Code 2: usage.

#[cfg(target_os = "linux")]
fn main() {
    use bifrost_core::ports::TunnelDevice;
    use bifrost_daemon::tunnel::{aiguillage, coeur, linux::LinuxTunnel, netcfg::Cmd};

    // Comme `CoeurTunnel::run`: un echec tolere n'en est pas un.
    fn run(cmd: &Cmd) -> bifrost_core::Result<()> {
        let out = std::process::Command::new(cmd.program)
            .args(&cmd.args)
            .output()
            .map_err(|e| bifrost_core::Error::Tunnel(format!("{}: {e}", cmd.display())))?;
        if out.status.success() || cmd.tolerate_failure {
            return Ok(());
        }
        Err(bifrost_core::Error::Tunnel(format!(
            "{}: {}",
            cmd.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        )))
    }

    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let resultat = match args.as_slice() {
        ["wireguard", sens, interface, marque, table] => {
            let cfg = configuration(
                interface,
                marque.parse().expect("fwmark entier"),
                table.parse().expect("table entiere"),
            );
            match *sens {
                "monter" => LinuxTunnel::new().up(&cfg),
                "demonter" => LinuxTunnel::new().down(&cfg),
                _ => usage(),
            }
        }
        ["coeur", sens, interface, reste @ ..] if reste.len() <= 1 => {
            let a = aiguillage::Aiguillage {
                interface: (*interface).to_owned(),
                coeur_uid: reste.first().map(|u| u.parse().expect("uid entier")),
            };
            match *sens {
                "monter" => coeur::preparer_aiguillage(&a).and_then(|()| {
                    for cmd in aiguillage::poser(&a) {
                        if let Err(e) = run(&cmd) {
                            for retour in aiguillage::retirer(&a) {
                                let _ = run(&retour);
                            }
                            return Err(e);
                        }
                    }
                    Ok(())
                }),
                "demonter" => {
                    for cmd in aiguillage::retirer(&a) {
                        let _ = run(&cmd);
                    }
                    Ok(())
                }
                _ => usage(),
            }
        }
        _ => usage(),
    };
    if let Err(e) = resultat {
        eprintln!("{e}");
        std::process::exit(1);
    }
}

#[cfg(target_os = "linux")]
fn usage() -> ! {
    eprintln!(
        "usage: wireguard monter|demonter <interface> <fwmark> <table> \
         | coeur monter|demonter <interface> [<uid>]"
    );
    std::process::exit(2);
}

/// Une configuration WireGuard de documentation: seules l'interface, la
/// marque et la table comptent pour le routage. Aucun maintien de session:
/// l'interface n'emet rien d'elle-meme.
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
                persistent_keepalive: 0,
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
