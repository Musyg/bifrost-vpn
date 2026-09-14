//! Configuration d'un device WireGuard depuis un namespace reseau.
//!
//! Le harnais doit configurer deux devices WireGuard, chacun dans son
//! namespace. Un processus ne peut configurer que le namespace dans lequel il
//! tourne: on relance donc le binaire du daemon via `ip netns exec` avec la
//! sous-commande cachee `--wg-apply`, qui reutilise exactement le meme chemin
//! netlink que le tunnel de production.

use serde::{Deserialize, Serialize};

/// Description d'un device, cote client comme cote serveur.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WgSpec {
    pub interface: String,
    pub private_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fwmark: Option<u32>,
    pub peers: Vec<WgPeerSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WgPeerSpec {
    pub public_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    pub allowed_ips: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keepalive: Option<u16>,
}

#[cfg(target_os = "linux")]
mod imp {
    use super::*;
    use crate::checks::transport::Compteurs;
    use bifrost_core::{Error, Result};
    use wireguard_control::{
        AllowedIp, Backend, Device, DeviceUpdate, InterfaceName, Key, PeerConfigBuilder,
    };

    /// Applique la specification au device. Suppose que l'interface existe.
    pub fn apply(spec: &WgSpec) -> Result<()> {
        let iface: InterfaceName = spec
            .interface
            .parse()
            .map_err(|e| Error::Tunnel(format!("interface '{}': {e:?}", spec.interface)))?;

        let private = Key::from_base64(&spec.private_key)
            .map_err(|e| Error::Tunnel(format!("cle privee: {e:?}")))?;

        let mut update = DeviceUpdate::new().set_private_key(private).replace_peers();
        if let Some(port) = spec.listen_port {
            update = update.set_listen_port(port);
        }
        if let Some(mark) = spec.fwmark {
            update = update.set_fwmark(mark);
        }

        for peer in &spec.peers {
            let public = Key::from_base64(&peer.public_key)
                .map_err(|e| Error::Tunnel(format!("cle publique: {e:?}")))?;
            let allowed: Vec<AllowedIp> = peer
                .allowed_ips
                .iter()
                .map(|s| {
                    s.parse::<AllowedIp>()
                        .map_err(|e| Error::Tunnel(format!("allowed-ip '{s}': {e:?}")))
                })
                .collect::<Result<_>>()?;

            let mut builder = PeerConfigBuilder::new(&public)
                .replace_allowed_ips()
                .add_allowed_ips(&allowed);
            if let Some(ep) = &peer.endpoint {
                let addr = ep
                    .parse()
                    .map_err(|e| Error::Tunnel(format!("endpoint '{ep}': {e}")))?;
                builder = builder.set_endpoint(addr);
            }
            if let Some(k) = peer.keepalive {
                builder = builder.set_persistent_keepalive_interval(k);
            }
            update = update.add_peer(builder);
        }

        update
            .apply(&iface, Backend::Kernel)
            .map_err(|e| Error::Tunnel(format!("application sur {iface}: {e}")))
    }

    /// Relit le driver: poignee de main aboutie, octets emis et RECUS.
    ///
    /// Les octets recus sont ce qui distingue un pair vivant d'un endpoint
    /// mort. Le lien physique ne le dit pas: un pair mort provoque exactement
    /// les memes paquets chiffres, ce sont les poignees de main reemises. Seul
    /// le driver sait que personne n'a jamais repondu.
    pub fn peer_stats(interface: &str) -> Result<Compteurs> {
        let iface: InterfaceName = interface
            .parse()
            .map_err(|e| Error::Tunnel(format!("interface '{interface}': {e:?}")))?;
        let device = Device::get(&iface, Backend::Kernel)
            .map_err(|e| Error::Tunnel(format!("lecture de {iface}: {e}")))?;

        let mut compteurs = Compteurs::default();
        for peer in &device.peers {
            compteurs.tx_bytes += peer.stats.tx_bytes;
            compteurs.rx_bytes += peer.stats.rx_bytes;
            // L'epoque Unix est ce que rend le noyau quand il n'y a jamais eu
            // de poignee de main: la lire comme une date la ferait passer pour
            // une poignee de main tres ancienne, donc pour une poignee de main.
            if matches!(peer.stats.last_handshake_time, Some(t) if t != std::time::SystemTime::UNIX_EPOCH)
            {
                compteurs.handshake = true;
            }
        }
        Ok(compteurs)
    }

    /// Genere une paire de cles au format base64.
    pub fn generate_keypair() -> (String, String) {
        let pair = wireguard_control::KeyPair::generate();
        (pair.private.to_base64(), pair.public.to_base64())
    }
}

#[cfg(target_os = "linux")]
pub use imp::{apply, generate_keypair, peer_stats};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn la_specification_fait_l_aller_retour_json() {
        let spec = WgSpec {
            interface: "wgc".into(),
            private_key: "a".repeat(43) + "=",
            listen_port: None,
            fwmark: Some(0xca6c),
            peers: vec![WgPeerSpec {
                public_key: "b".repeat(43) + "=",
                endpoint: Some("10.77.0.1:51820".into()),
                allowed_ips: vec!["0.0.0.0/0".into()],
                keepalive: Some(5),
            }],
        };
        let json = serde_json::to_string(&spec).unwrap();
        let back: WgSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(back.interface, "wgc");
        assert_eq!(back.fwmark, Some(0xca6c));
        assert_eq!(back.peers[0].allowed_ips, vec!["0.0.0.0/0".to_owned()]);
    }

    /// Le cote serveur n'a ni endpoint ni fwmark: la specification doit
    /// accepter ces absences sans champ obligatoire manquant.
    #[test]
    fn une_specification_de_serveur_est_valide_sans_endpoint() {
        let json = r#"{"interface":"wgs","private_key":"k","listen_port":51820,
                       "peers":[{"public_key":"p","allowed_ips":["10.88.0.2/32"]}]}"#;
        let spec: WgSpec = serde_json::from_str(json).unwrap();
        assert_eq!(spec.listen_port, Some(51820));
        assert!(spec.fwmark.is_none());
        assert!(spec.peers[0].endpoint.is_none());
    }
}
