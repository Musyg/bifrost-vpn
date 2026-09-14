//! Device WireGuard sous Linux.
//!
//! Deux couches distinctes:
//!
//! - la configuration cryptographique du device (cles, pair, fwmark) passe par
//!   netlink avec `wireguard-control`;
//! - les adresses, routes et regles de politique passent par `ip`, via les
//!   commandes construites dans [`super::netcfg`].
//!
//! `wg-quick` est volontairement ecarte: il gere lui-meme routes, fwmark et
//! DNS, et entrerait en conflit avec le kill switch et la machine a etats.

use std::process::{Command, Stdio};
use std::time::SystemTime;

use bifrost_core::ports::{HandshakeInfo, TunnelDevice};
use bifrost_core::{Error, Result, TunnelConfig};
use wireguard_control::{
    AllowedIp, Backend, Device, DeviceUpdate, InterfaceName, Key, PeerConfigBuilder,
};

use super::netcfg::{self, Cmd};

#[derive(Default)]
pub struct LinuxTunnel;

impl LinuxTunnel {
    pub fn new() -> Self {
        Self
    }

    fn iface(cfg: &TunnelConfig) -> Result<InterfaceName> {
        cfg.interface
            .parse()
            .map_err(|e| Error::Tunnel(format!("nom d'interface '{}': {e:?}", cfg.interface)))
    }

    fn link_exists(name: &str) -> bool {
        std::path::Path::new(&format!("/sys/class/net/{name}")).exists()
    }

    /// Applique cles, fwmark et pair au device par netlink.
    fn apply_device(cfg: &TunnelConfig) -> Result<()> {
        // Ce peripherique ne monte que du WireGuard. Le dire ici plutot que le
        // supposer: depuis que `portage` existe, une configuration peut
        // decrire un coeur, et c'est alors `CoeurTunnel` qu'il fallait appeler.
        let wg = cfg.wireguard()?;
        let iface = Self::iface(cfg)?;

        let private = Key::from_base64(wg.private_key.as_str())
            .map_err(|e| Error::Tunnel(format!("cle privee invalide: {e:?}")))?;
        let public = Key::from_base64(wg.peer.public_key.as_str())
            .map_err(|e| Error::Tunnel(format!("cle publique du pair invalide: {e:?}")))?;

        let allowed: Vec<AllowedIp> = wg
            .peer
            .allowed_ips
            .iter()
            .map(|n| AllowedIp {
                address: n.addr,
                cidr: n.prefix_len,
            })
            .collect();

        let mut peer = PeerConfigBuilder::new(&public)
            .set_endpoint(wg.peer.endpoint.addr)
            .replace_allowed_ips()
            .add_allowed_ips(&allowed);
        if wg.peer.persistent_keepalive > 0 {
            peer = peer.set_persistent_keepalive_interval(wg.peer.persistent_keepalive);
        }
        if let Some(psk) = &wg.peer.preshared_key {
            let psk = Key::from_base64(psk.as_str())
                .map_err(|e| Error::Tunnel(format!("cle pre-partagee invalide: {e:?}")))?;
            peer = peer.set_preshared_key(psk);
        }

        let mut update = DeviceUpdate::new()
            .set_private_key(private)
            // Le fwmark est ce qui permet au kill switch de reconnaitre le
            // trafic deja chiffre. Sans lui, rien ne sort.
            .set_fwmark(wg.fwmark)
            .replace_peers()
            .add_peer(peer);
        if let Some(port) = wg.listen_port {
            update = update.set_listen_port(port);
        }

        update
            .apply(&iface, Backend::Kernel)
            .map_err(|e| Error::Tunnel(format!("configuration du device {iface}: {e}")))?;
        Ok(())
    }

    fn run(cmd: &Cmd) -> Result<()> {
        let out = Command::new(cmd.program)
            .args(&cmd.args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .map_err(|e| Error::Tunnel(format!("{}: {e}", cmd.display())))?;

        if out.status.success() {
            return Ok(());
        }
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_owned();
        if cmd.tolerate_failure {
            tracing::debug!(cmd = %cmd.display(), stderr = %stderr, "echec tolere");
            return Ok(());
        }
        Err(Error::Tunnel(format!("{}: {stderr}", cmd.display())))
    }
}

impl TunnelDevice for LinuxTunnel {
    fn up(&mut self, cfg: &TunnelConfig) -> Result<()> {
        cfg.validate()?;

        if !std::path::Path::new("/sys/module/wireguard").exists()
            && !Self::link_exists(&cfg.interface)
        {
            // Le module se charge a la creation de la premiere interface: son
            // absence ici n'est pas fatale, mais elle explique l'erreur si la
            // creation echoue juste apres.
            tracing::debug!("module wireguard pas encore charge");
        }

        // Une interface residuelle d'une session precedente porterait des
        // routes obsoletes: on repart d'un etat connu.
        if Self::link_exists(&cfg.interface) {
            tracing::warn!(
                interface = %cfg.interface,
                "interface residuelle detectee, demontage prealable"
            );
            for cmd in netcfg::teardown(cfg) {
                Self::run(&cmd)?;
            }
        }

        Self::run(&netcfg::create_link(cfg)).map_err(|e| {
            Error::Tunnel(format!(
                "{e}. Le module noyau wireguard est-il disponible \
                 (modprobe wireguard) ?"
            ))
        })?;

        // Si la suite echoue, l'interface reste orpheline: on nettoie avant de
        // remonter l'erreur, sinon la tentative suivante repart d'un etat sale.
        let result = (|| -> Result<()> {
            Self::apply_device(cfg)?;
            for cmd in netcfg::configure_link(cfg) {
                Self::run(&cmd)?;
            }
            for cmd in netcfg::add_routing(cfg) {
                Self::run(&cmd)?;
            }
            Ok(())
        })();

        if let Err(e) = result {
            tracing::error!(error = %e, "montage incomplet, nettoyage");
            for cmd in netcfg::teardown(cfg) {
                let _ = Self::run(&cmd);
            }
            return Err(e);
        }

        let wg = cfg.wireguard()?;
        tracing::info!(
            interface = %cfg.interface,
            endpoint = %wg.peer.endpoint,
            fwmark = format!("{:#x}", wg.fwmark),
            "tunnel monte"
        );
        Ok(())
    }

    fn down(&mut self, cfg: &TunnelConfig) -> Result<()> {
        for cmd in netcfg::teardown(cfg) {
            Self::run(&cmd)?;
        }
        tracing::info!(interface = %cfg.interface, "tunnel demonte");
        Ok(())
    }

    fn handshake(&self, cfg: &TunnelConfig) -> Result<Option<HandshakeInfo>> {
        if !Self::link_exists(&cfg.interface) {
            return Ok(None);
        }
        let iface = Self::iface(cfg)?;
        let device = match Device::get(&iface, Backend::Kernel) {
            Ok(d) => d,
            Err(e) => {
                tracing::debug!(error = %e, "lecture du device impossible");
                return Ok(None);
            }
        };

        let mut info = HandshakeInfo {
            last_handshake: None,
            rx_bytes: 0,
            tx_bytes: 0,
        };
        for peer in &device.peers {
            info.rx_bytes += peer.stats.rx_bytes;
            info.tx_bytes += peer.stats.tx_bytes;
            if let Some(t) = peer.stats.last_handshake_time {
                // Le noyau renvoie l'epoch zero tant qu'aucun handshake n'a eu
                // lieu: ce n'est pas un handshake de 1970, c'est une absence.
                if t != SystemTime::UNIX_EPOCH
                    && info.last_handshake.map(|prev| t > prev).unwrap_or(true)
                {
                    info.last_handshake = Some(t);
                }
            }
        }
        Ok(Some(info))
    }
}
