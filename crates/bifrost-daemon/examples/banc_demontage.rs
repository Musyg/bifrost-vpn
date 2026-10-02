//! Outil du banc jetable `banc-demontage-routage-linux.sh`: tient une session
//! de routage du produit comme le daemon la tient, par ses fonctions a lui,
//! dans le namespace reseau ou il est lance.
//!
//! `banc_demontage tenir wireguard <interface> <fwmark> <table>` monte par
//! `LinuxTunnel::up`, le vrai peripherique: interface WireGuard, cles,
//! adresses, routes et regles (le module noyau `wireguard` est necessaire).
//!
//! `banc_demontage tenir coeur <interface> [<uid>]` fait ce que
//! `CoeurTunnel::monter_ici` fait du routage: `coeur::preparer_aiguillage`,
//! puis `coeur::poser_aiguillage`. Le TUN et le passage n'en font pas partie:
//! le banc pose a leur place une interface factice du meme nom.
//!
//! Le montage fait, l'outil ecrit `monte` ou `refuse <raison>` sur sa sortie,
//! puis lit des ordres sur son entree: `demonter` demonte le MEME objet, comme
//! le daemon (`LinuxTunnel::down`, ou le retrait de la session de
//! l'aiguillage), et ecrit `demonte` ou `echec <raison>`; `fin`, ou la fin de
//! l'entree, le fait sortir sans rien demonter, comme un daemon arrete. Tue,
//! il ne demonte rien non plus: sa session reste au journal, morte.
//!
//! `banc_demontage porter` ne monte rien au depart: il ecrit `pret`, puis lit
//! des ordres qui visent chacun le MEME objet d'un ordre a l'autre, comme le
//! superviseur garde ses peripheriques d'une connexion a la suivante:
//! `wireguard monter <interface> <fwmark> <table>` et `wireguard demonter`
//! (`LinuxTunnel::up` et `down`), `coeur monter <interface> [<uid>]` et
//! `coeur demonter` (ce que `CoeurTunnel` fait du routage: au montage, la
//! session qu'il tient encore retiree d'abord, puis `preparer_aiguillage` et
//! `poser_aiguillage`; au demontage, le retrait de la session tenue). Chaque
//! ordre rend `monte`, `demonte`, `refuse <raison>` ou `echec <raison>`;
//! `fin` le fait sortir sans rien demonter.
//!
//! Code 2: usage.

#[cfg(target_os = "linux")]
fn main() {
    use std::io::BufRead;

    use bifrost_core::ports::TunnelDevice;
    use bifrost_daemon::tunnel::{aiguillage, coeur, linux::LinuxTunnel, session::Session};

    fn ligne(e: &bifrost_core::Error) -> String {
        e.to_string().replace('\n', " ")
    }

    enum Porteur {
        Wg(LinuxTunnel, bifrost_core::TunnelConfig),
        Coeur(Option<Session>),
    }

    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    if args.as_slice() == ["porter"] {
        porter();
        return;
    }
    let (mut porteur, montage) = match args.as_slice() {
        ["tenir", "wireguard", interface, marque, table] => {
            let cfg = configuration(
                interface,
                marque.parse().expect("fwmark entier"),
                table.parse().expect("table entiere"),
            );
            let mut t = LinuxTunnel::new();
            let r = t.up(&cfg);
            (Porteur::Wg(t, cfg), r)
        }
        ["tenir", "coeur", interface, reste @ ..] if reste.len() <= 1 => {
            let a = aiguillage::Aiguillage {
                interface: (*interface).to_owned(),
                coeur_uid: reste.first().map(|u| u.parse().expect("uid entier")),
            };
            match coeur::preparer_aiguillage(&a).and_then(|()| coeur::poser_aiguillage(&a)) {
                Ok(s) => (Porteur::Coeur(Some(s)), Ok(())),
                Err(e) => (Porteur::Coeur(None), Err(e)),
            }
        }
        _ => usage(),
    };
    match &montage {
        Ok(()) => println!("monte"),
        Err(e) => println!("refuse {}", ligne(e)),
    }
    for l in std::io::stdin().lock().lines() {
        let Ok(l) = l else { break };
        match l.trim() {
            "demonter" => {
                let r = match &mut porteur {
                    Porteur::Wg(t, cfg) => t.down(cfg),
                    Porteur::Coeur(session) => match session.take() {
                        None => Ok(()),
                        Some(s) => match s.retirer() {
                            Ok(()) => Ok(()),
                            Err(e) => {
                                *session = Some(s);
                                Err(e)
                            }
                        },
                    },
                };
                match r {
                    Ok(()) => println!("demonte"),
                    Err(e) => println!("echec {}", ligne(&e)),
                }
            }
            "fin" => break,
            autre => println!("ordre inconnu {autre}"),
        }
    }
    // Sortir sans demonter: la session reste au journal, et ses objets dans
    // le noyau, comme ceux d'un daemon arrete.
}

/// Le porteur a ordres: voir l'en-tete.
#[cfg(target_os = "linux")]
fn porter() {
    use std::io::BufRead;

    use bifrost_core::ports::TunnelDevice;
    use bifrost_daemon::tunnel::{aiguillage, coeur, linux::LinuxTunnel, session::Session};

    // Comme `CoeurTunnel`: la session tenue est retiree, et en erreur elle
    // reste tenue.
    fn retirer_la_tenue(tenue: &mut Option<Session>) -> bifrost_core::Result<()> {
        if let Some(s) = tenue.take()
            && let Err(e) = s.retirer()
        {
            *tenue = Some(s);
            return Err(e);
        }
        Ok(())
    }

    let mut wg = LinuxTunnel::new();
    let mut wg_cfg: Option<bifrost_core::TunnelConfig> = None;
    let mut tenue: Option<Session> = None;
    println!("pret");
    for l in std::io::stdin().lock().lines() {
        let Ok(l) = l else { break };
        let mots: Vec<&str> = l.split_whitespace().collect();
        let (r, fait) = match mots.as_slice() {
            ["wireguard", "monter", interface, marque, table] => {
                let cfg = configuration(
                    interface,
                    marque.parse().expect("fwmark entier"),
                    table.parse().expect("table entiere"),
                );
                let r = wg.up(&cfg);
                wg_cfg = Some(cfg);
                (r, "monte")
            }
            ["wireguard", "demonter"] => match &wg_cfg {
                Some(cfg) => (wg.down(cfg), "demonte"),
                None => (Ok(()), "demonte"),
            },
            ["coeur", "monter", interface, reste @ ..] if reste.len() <= 1 => {
                let a = aiguillage::Aiguillage {
                    interface: (*interface).to_owned(),
                    coeur_uid: reste.first().map(|u| u.parse().expect("uid entier")),
                };
                let r = retirer_la_tenue(&mut tenue)
                    .and_then(|()| coeur::preparer_aiguillage(&a))
                    .and_then(|()| coeur::poser_aiguillage(&a))
                    .map(|s| tenue = Some(s));
                (r, "monte")
            }
            ["coeur", "demonter"] => (retirer_la_tenue(&mut tenue), "demonte"),
            ["fin"] => break,
            _ => {
                println!("ordre inconnu {l}");
                continue;
            }
        };
        match r {
            Ok(()) => println!("{fait}"),
            Err(e) if fait == "monte" => println!("refuse {}", e.to_string().replace('\n', " ")),
            Err(e) => println!("echec {}", e.to_string().replace('\n', " ")),
        }
    }
    // Sortir sans demonter, comme un daemon arrete.
}

#[cfg(target_os = "linux")]
fn usage() -> ! {
    eprintln!(
        "usage: tenir wireguard <interface> <fwmark> <table> | tenir coeur <interface> [<uid>] \
         | porter"
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
    // termine n'importe quelle cle. La cle depend de l'interface, pour que
    // deux profils du banc n'aient pas la meme.
    let lettre = if interface.ends_with('1') { 'c' } else { 'a' };
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
            private_key: cle(lettre),
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
