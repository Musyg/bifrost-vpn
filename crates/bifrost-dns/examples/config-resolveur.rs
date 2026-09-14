//! Ecrit sur la sortie standard la configuration dnscrypt-proxy engendree.
//!
//! Sert a confronter le generateur au VRAI binaire: `dnscrypt-proxy -check`
//! lit ce que ce programme produit et dit s'il l'accepte. Sans cela, les tests
//! du generateur ne prouvent que sa coherence avec lui-meme, ce qui est
//! exactement le genre de recette qui reste verte pendant que le produit
//! refuse de demarrer.
//!
//! Usage: cargo run -p bifrost-dns --example config-resolveur [ECOUTE] [SERVEURS] [BOOTSTRAP] [BLOCAGE]
//!   ECOUTE    adresse:port, defaut 127.0.0.1:53
//!   SERVEURS  noms separes par des virgules
//!   BOOTSTRAP adresses separees par des virgules
//!   BLOCAGE   chemin ABSOLU du fichier des noms refuses. Absent ou vide, la
//!             section `[blocked_names]` n'est pas ecrite. Le fichier lui-meme
//!             se produit avec l'exemple `liste-telemetrie`.

use std::net::{IpAddr, SocketAddr};

use bifrost_dns::resolveur::{ResolveurChiffre, dnscrypt_proxy_toml};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let ecoute: SocketAddr = args
        .next()
        .unwrap_or_else(|| "127.0.0.1:53".to_owned())
        .parse()?;
    let serveurs: Vec<String> = args
        .next()
        .unwrap_or_else(|| "quad9-dnscrypt-ip4-filter-pri,cloudflare".to_owned())
        .split(',')
        .map(str::to_owned)
        .collect();
    let bootstrap: Vec<IpAddr> = args
        .next()
        .unwrap_or_else(|| "9.9.9.9,1.1.1.1".to_owned())
        .split(',')
        .map(str::parse)
        .collect::<Result<_, _>>()?;

    let blocage = args
        .next()
        .filter(|s| !s.is_empty())
        .map(std::path::PathBuf::from);

    print!(
        "{}",
        dnscrypt_proxy_toml(&ResolveurChiffre {
            ecoute,
            serveurs,
            bootstrap,
            cache: std::path::PathBuf::from("/var/lib/bifrost/resolveur/public-resolvers.md"),
            blocage,
        })?
    );
    Ok(())
}
