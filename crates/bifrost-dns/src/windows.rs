//! DNS Windows: configuration des serveurs de l'interface du tunnel.
//!
//! L'enforcement reel vient des filtres WFP `blockDNS` (permit vers le
//! resolveur au poids 15, block de tout :53 au poids 14). Ce module se contente
//! de pointer le resolveur de l'interface du tunnel au bon endroit, pour que la
//! resolution fonctionne au lieu d'etre simplement bloquee.

use std::process::{Command, Stdio};

use bifrost_core::config::DnsPolicy;
use bifrost_core::ports::DnsManager;
use bifrost_core::{Error, Result};

#[derive(Default)]
pub struct NetshDns {
    applied_on: Option<String>,
}

impl NetshDns {
    pub fn new() -> Self {
        Self::default()
    }
}

impl DnsManager for NetshDns {
    fn apply(&mut self, interface: &str, policy: &DnsPolicy) -> Result<()> {
        policy.validate()?;

        // `serveurs_a_interroger` et non `policy.upstream`: c'est elle qui
        // sait qu'un resolveur EMBARQUE se designe par la boucle locale. Le
        // defaut corrige ici pointait l'interface du tunnel sur l'amont, donc
        // sur une destination que `block-dns` refuse.
        let serveurs = crate::serveurs_a_interroger(policy);
        let mut first = true;
        for server in &serveurs {
            let family = if server.is_ipv4() { "ipv4" } else { "ipv6" };
            let args: Vec<String> = if first {
                vec![
                    "interface".into(),
                    family.into(),
                    "set".into(),
                    "dnsservers".into(),
                    format!("name={interface}"),
                    "source=static".into(),
                    format!("address={server}"),
                    "register=none".into(),
                    "validate=no".into(),
                ]
            } else {
                vec![
                    "interface".into(),
                    family.into(),
                    "add".into(),
                    "dnsservers".into(),
                    format!("name={interface}"),
                    format!("address={server}"),
                    "validate=no".into(),
                ]
            };
            run("netsh", &args)?;
            first = false;
        }

        // Le cache Dnscache contient les reponses obtenues hors tunnel.
        let _ = run("ipconfig", &["/flushdns".to_owned()]);

        self.applied_on = Some(interface.to_owned());
        tracing::info!(interface, servers = ?serveurs, embarque = policy.embarque, "DNS du tunnel configure");
        Ok(())
    }

    fn restore(&mut self) -> Result<()> {
        if let Some(iface) = self.applied_on.take() {
            for family in ["ipv4", "ipv6"] {
                let args = [
                    "interface".to_owned(),
                    family.to_owned(),
                    "set".to_owned(),
                    "dnsservers".to_owned(),
                    format!("name={iface}"),
                    "source=dhcp".to_owned(),
                ];
                // L'interface a pu disparaitre avec le tunnel: ce n'est pas une
                // erreur, il n'y a alors plus rien a restaurer.
                if let Err(e) = run("netsh", &args) {
                    tracing::debug!(interface = %iface, family, error = %e, "restauration DNS ignoree");
                }
            }
            let _ = run("ipconfig", &["/flushdns".to_owned()]);
            tracing::info!(interface = %iface, "DNS restaure");
        }
        Ok(())
    }

    fn backend(&self) -> &'static str {
        "netsh"
    }
}

fn run(program: &str, args: &[String]) -> Result<()> {
    let out = Command::new(program)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| Error::Dns(format!("{program}: {e}")))?;
    if !out.status.success() {
        return Err(Error::Dns(format!(
            "{program} {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stdout).trim()
        )));
    }
    Ok(())
}
