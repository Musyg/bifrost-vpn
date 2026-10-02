//! Ecrit sur la sortie standard ce que le produit pose pour son DNS sous
//! Linux: les arguments `resolvectl` du backend systemd-resolved, une commande
//! par ligne, ou le fichier du backend resolv.conf.
//!
//! Pour le banc de `prove dns` (`scripts/preuve-dns-linux.sh`): la pose du
//! banc est celle du produit, rendue par les fonctions du gestionnaire DNS
//! (`resolved_apply_commands`, `resolv_conf_contents`), pas recopiee a la main.
//! La preuve, elle, tire son attendu de la meme intention par le plan DNS.
//!
//! Usage: cargo run -p bifrost-dns --example pose-dns -- MODE INTERFACE EMBARQUE LOCAL AMONT...
//!   MODE      resolved | resolv-conf
//!   EMBARQUE  oui | non

#[cfg(target_os = "linux")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use bifrost_core::config::{DnsPolicy, ProfilTelemetrie};
    use std::net::IpAddr;

    let args: Vec<String> = std::env::args().skip(1).collect();
    let [mode, interface, embarque, local, amonts @ ..] = args.as_slice() else {
        return Err("usage: pose-dns MODE INTERFACE EMBARQUE LOCAL AMONT...".into());
    };
    let embarque = match embarque.as_str() {
        "oui" => true,
        "non" => false,
        autre => return Err(format!("EMBARQUE inconnu: {autre}").into()),
    };
    let politique = DnsPolicy {
        local_resolver: local.parse::<IpAddr>()?,
        upstream: amonts
            .iter()
            .map(|a| a.parse::<IpAddr>())
            .collect::<Result<_, _>>()?,
        embarque,
        anti_telemetrie: ProfilTelemetrie::Aucun,
    };
    politique.validate()?;
    match mode.as_str() {
        "resolved" => {
            for commande in bifrost_dns::linux::resolved_apply_commands(interface, &politique) {
                println!("{}", commande.join(" "));
            }
        }
        "resolv-conf" => print!("{}", bifrost_dns::linux::resolv_conf_contents(&politique)),
        autre => return Err(format!("MODE inconnu: {autre}").into()),
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("pose-dns: la pose rendue ici est celle du gestionnaire DNS Linux");
    std::process::exit(2);
}
