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

/// Ce qui porte deja le nom d'interface du profil.
///
/// Le nom seul ne dit pas a qui est l'interface: `wg0` est celui de
/// l'exemple de profil ET celui que wg-quick donne a la sienne d'apres son
/// fichier. Avant, une interface de ce nom etait prise pour le reste d'une
/// session precedente et supprimee, celle d'un tiers comprise (mesure en
/// namespace jetable sur essai-linux, 30/09/2026).
#[derive(Debug, PartialEq, Eq)]
enum Occupant {
    /// Aucune interface de ce nom.
    Aucun,
    /// Une interface WireGuard qui porte la cle du profil: le reste d'une
    /// session du produit, a retirer avant de reposer.
    Produit,
    /// Autre chose, que le produit ne retire pas; le texte dit quoi.
    Tiers(&'static str),
}

/// `DEVTYPE=wireguard` est la ligne que le module noyau inscrit dans
/// `/sys/class/net/<nom>/uevent` (lisible sans privilege; mesure le
/// 30/09/2026 sur essai-linux, noyau 7.0, contre une interface factice qui
/// n'en porte aucune).
fn est_wireguard(uevent: &str) -> bool {
    uevent.lines().any(|l| l == "DEVTYPE=wireguard")
}

/// Une interface WireGuard est celle du produit quand sa cle publique est
/// celle que la cle privee du profil donne. Sans cle, elle n'est a personne
/// que l'on puisse nommer: le produit ne la retire pas.
fn occupant_wireguard(lue: Option<&Key>, du_profil: &Key) -> Occupant {
    match lue {
        Some(k) if k == du_profil => Occupant::Produit,
        Some(_) => Occupant::Tiers("interface WireGuard d'une autre cle"),
        None => Occupant::Tiers("interface WireGuard sans cle"),
    }
}

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

    /// A qui est l'interface qui porte le nom du profil. Une lecture qui
    /// echoue est une erreur, jamais un classement: rien n'est alors retire.
    fn occupant(cfg: &TunnelConfig) -> Result<Occupant> {
        if !Self::link_exists(&cfg.interface) {
            return Ok(Occupant::Aucun);
        }
        let chemin = format!("/sys/class/net/{}/uevent", cfg.interface);
        let uevent = std::fs::read_to_string(&chemin)
            .map_err(|e| Error::Tunnel(format!("lecture de {chemin}: {e}; rien n'est retire")))?;
        if !est_wireguard(&uevent) {
            return Ok(Occupant::Tiers("interface d'un autre type que WireGuard"));
        }
        let wg = cfg.wireguard()?;
        let du_profil = Key::from_base64(wg.private_key.as_str())
            .map_err(|e| Error::Tunnel(format!("cle privee invalide: {e:?}")))?
            .get_public();
        let device = Device::get(&Self::iface(cfg)?, Backend::Kernel).map_err(|e| {
            Error::Tunnel(format!(
                "lecture de l'interface {}: {e}; rien n'est retire",
                cfg.interface
            ))
        })?;
        Ok(occupant_wireguard(device.public_key.as_ref(), &du_profil))
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
        // Les deux listes de routage sont rendues ICI, avant la premiere
        // commande. `netcfg` refuse une table que le noyau se reserve, meme si
        // la validation l'a laissee passer; refuse ici, rien n'a encore ete
        // cree ni retire. Rendues plus bas, un refus de la pose laisserait une
        // interface creee sans demontage possible.
        let pose = netcfg::add_routing(cfg)?;
        let demontage = netcfg::teardown(cfg)?;
        let retrait_routage = netcfg::retrait_routage(cfg)?;

        if !std::path::Path::new("/sys/module/wireguard").exists()
            && !Self::link_exists(&cfg.interface)
        {
            // Le module se charge a la creation de la premiere interface: son
            // absence ici n'est pas fatale, mais elle explique l'erreur si la
            // creation echoue juste apres.
            tracing::debug!("module wireguard pas encore charge");
        }

        // Une interface residuelle d'une session precedente porterait des
        // routes obsoletes: on repart d'un etat connu. Mais seulement si elle
        // est au produit; celle d'un tiers qui porte le meme nom n'est ni
        // retiree ni reprise.
        match Self::occupant(cfg)? {
            Occupant::Aucun => {}
            Occupant::Produit => {
                tracing::warn!(
                    interface = %cfg.interface,
                    "interface residuelle detectee, demontage prealable"
                );
                for cmd in &demontage {
                    Self::run(cmd)?;
                }
            }
            Occupant::Tiers(quoi) => {
                return Err(Error::Tunnel(format!(
                    "montage refuse: l'interface {nom} existe deja et n'est pas \
                     celle du produit ({quoi}). Rien n'est retire ni pose. \
                     Choisir dans le profil un autre nom d'interface: wg-quick \
                     nomme la sienne d'apres son fichier de configuration, wg0 \
                     le plus souvent",
                    nom = cfg.interface,
                )));
            }
        }

        // Avant la premiere commande qui pose: lire les regles et les routes,
        // retirer ce qu'une session precedente du produit a laisse (seulement
        // ce qui porte son etiquette), puis refuser une table ou une marque
        // qu'un tiers emploie deja. Refuse ici, rien n'a ete pose.
        if let Some(plan) = netcfg::plan(cfg, "pose du routage")? {
            super::occupation::preparer(&plan, || {
                for cmd in &retrait_routage {
                    let _ = Self::run(cmd);
                }
            })?;
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
            for cmd in &pose {
                Self::run(cmd)?;
            }
            Ok(())
        })();

        if let Err(e) = result {
            tracing::error!(error = %e, "montage incomplet, nettoyage");
            for cmd in &demontage {
                let _ = Self::run(cmd);
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
        // Une table reservee est refusee sans qu'aucune commande parte: voir
        // `netcfg::teardown`. Les regles et les routes retirees sont celles
        // que le produit pose, et elles seules (`netcfg::retrait_routage`).
        for cmd in netcfg::retrait_routage(cfg)? {
            Self::run(&cmd)?;
        }
        // L'interface, seulement si elle est au produit: apres un montage
        // refuse, celle qui porte le nom du profil peut etre d'un tiers.
        if cfg.portage.wireguard().is_some() {
            match Self::occupant(cfg)? {
                Occupant::Aucun => {}
                Occupant::Produit => Self::run(&netcfg::retrait_lien(cfg))?,
                Occupant::Tiers(quoi) => {
                    tracing::warn!(
                        interface = %cfg.interface,
                        quoi,
                        "interface d'un tiers laissee en place"
                    );
                }
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use bifrost_core::config::{
        DnsPolicy, Endpoint, PeerConfig, Portage, ProfilTelemetrie, WgKey, WireguardParams,
    };
    use std::net::{IpAddr, Ipv4Addr};

    /// Une configuration WireGuard dont la table est donnee, SANS passer par
    /// la validation: c'est le cas que `down` doit tenir seul.
    fn configuration(routing_table: u32) -> TunnelConfig {
        let cle = |c: char| -> WgKey {
            let mut s: String = std::iter::repeat_n(c, 42).collect();
            s.push_str("A=");
            s.parse().expect("cle de documentation")
        };
        TunnelConfig {
            interface: "bfwgdown0".into(),
            addresses: vec!["198.51.100.2/32".parse().unwrap()],
            mtu: 1420,
            portage: Portage::Wireguard(Box::new(WireguardParams {
                private_key: cle('a'),
                fwmark: 51820,
                routing_table,
                listen_port: None,
                peer: PeerConfig {
                    public_key: cle('b'),
                    preshared_key: None,
                    endpoint: Endpoint {
                        addr: "203.0.113.7:51820".parse().unwrap(),
                    },
                    allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
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

    /// `down` rend le refus du demontage, pour chaque table que le noyau se
    /// reserve, au lieu de l'avaler: un demontage refuse n'est pas un
    /// demontage reussi. Aucune commande n'est lancee avant le refus, d'ou
    /// une recette sans privilege: rien ne peut rien toucher. Avant elle, la
    /// mutation `netcfg::teardown(cfg).unwrap_or_default()` passait toutes
    /// les recettes du depot.
    #[test]
    fn down_rend_le_refus_du_demontage_sans_rien_lancer() {
        for (table, nom) in [
            (0u32, "unspec"),
            (253, "default"),
            (254, "main"),
            (255, "local"),
        ] {
            let e = LinuxTunnel::new()
                .down(&configuration(table))
                .expect_err(&format!("demontage en table {table} rendu comme reussi"))
                .to_string();
            assert!(
                e.contains(&format!("table {table} ('{nom}')"))
                    && e.contains("aucune commande n'est emise"),
                "{e}"
            );
        }
    }

    /// La ligne que le module ecrit, et elle seule: ni l'absence de ligne
    /// (interface factice, mesure), ni un autre type, ni un prefixe.
    #[test]
    fn seule_la_ligne_du_module_designe_une_interface_wireguard() {
        assert!(est_wireguard(
            "DEVTYPE=wireguard\nINTERFACE=wg0\nIFINDEX=2\n"
        ));
        assert!(!est_wireguard("INTERFACE=wg0\nIFINDEX=3\n"));
        assert!(!est_wireguard("DEVTYPE=bridge\nINTERFACE=wg0\n"));
        assert!(!est_wireguard("DEVTYPE=wireguard0\nINTERFACE=wg0\n"));
        assert!(!est_wireguard("INTERFACE=DEVTYPE=wireguard\n"));
    }

    /// Seule la cle du profil fait d'une interface WireGuard celle du produit.
    #[test]
    fn seule_la_cle_du_profil_designe_l_interface_du_produit() {
        let cle = |c: char| {
            let mut s: String = std::iter::repeat_n(c, 42).collect();
            s.push_str("A=");
            Key::from_base64(&s)
                .expect("cle de documentation")
                .get_public()
        };
        let (du_profil, autre) = (cle('a'), cle('b'));
        assert_ne!(du_profil, autre);
        assert_eq!(
            occupant_wireguard(Some(&du_profil), &du_profil),
            Occupant::Produit
        );
        assert!(matches!(
            occupant_wireguard(Some(&autre), &du_profil),
            Occupant::Tiers(_)
        ));
        assert!(matches!(
            occupant_wireguard(None, &du_profil),
            Occupant::Tiers(_)
        ));
    }

    /// Sur le vrai sysfs, en lecture seule et sans privilege: un nom absent
    /// n'est a personne, et `lo`, qui n'est pas WireGuard, est a un tiers.
    #[test]
    fn l_occupant_se_lit_dans_sysfs_sans_privilege() {
        let mut c = configuration(51820);
        assert_eq!(LinuxTunnel::occupant(&c).unwrap(), Occupant::Aucun);
        c.interface = "lo".into();
        assert_eq!(
            LinuxTunnel::occupant(&c).unwrap(),
            Occupant::Tiers("interface d'un autre type que WireGuard")
        );
    }
}
