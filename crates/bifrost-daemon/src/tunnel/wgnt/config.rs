//! Serialisation du blob de configuration de WireGuardNT.
//!
//! `WireGuardSetConfiguration` prend un unique tampon d'octets: une structure
//! `WIREGUARD_INTERFACE`, suivie de `PeersCount` structures `WIREGUARD_PEER`,
//! chacune suivie de ses `AllowedIPsCount` structures `WIREGUARD_ALLOWED_IP`.
//! Ce module produit ce tampon, et rien d'autre. Aucun appel Windows, donc la
//! partie ou une erreur d'un octet suffit a tout casser est testable partout,
//! y compris en integration continue Linux.
//!
//! Les tailles et les positions viennent de `api/wireguard.h` de wireguard-nt,
//! ou les trois structures portent `ALIGNED(8)`. Elles ont ete recoupees avec
//! l'implementation Go de WireGuard for Windows
//! (`driver/configuration_windows.go`), qui declare explicitement ses octets de
//! bourrage et est celle qui tourne en production.
//!
//! Attention en lisant d'autres sources: l'exemple C# du meme depot
//! (`embeddable-dll-service/csharp/TunnelDll/Driver.cs`) place `Cidr` a
//! l'offset 20 et ne declare pas `Flags`. L'en-tete C et le code Go s'accordent
//! sur `Cidr` a 18 et `Flags` a 20. C'est l'en-tete qui fait foi.

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, SystemTime};

use bifrost_core::config::{IpNet, TunnelConfig, WG_KEY_BYTES};
use bifrost_core::{Error, Result};

/// Taille de `WIREGUARD_INTERFACE`. Les champs s'arretent a 76, l'alignement
/// sur 8 de la structure porte le total a 80.
pub const INTERFACE_SIZE: usize = 80;
/// Taille de `WIREGUARD_PEER`.
pub const PEER_SIZE: usize = 136;
/// Taille de `WIREGUARD_ALLOWED_IP`.
pub const ALLOWED_IP_SIZE: usize = 24;

/// Positions dans `WIREGUARD_INTERFACE`.
mod itf {
    pub const FLAGS: usize = 0;
    pub const LISTEN_PORT: usize = 4;
    pub const PRIVATE_KEY: usize = 6;
    pub const PUBLIC_KEY: usize = 38;
    /// 70 apres la cle publique, mais `DWORD` s'aligne sur 4: deux octets de
    /// bourrage s'intercalent.
    pub const PEERS_COUNT: usize = 72;
}

/// Positions dans `WIREGUARD_PEER`.
mod peer {
    pub const FLAGS: usize = 0;
    pub const RESERVED: usize = 4;
    pub const PUBLIC_KEY: usize = 8;
    pub const PRESHARED_KEY: usize = 40;
    pub const PERSISTENT_KEEPALIVE: usize = 72;
    /// 74 apres le keepalive, aligne sur 4 pour `SOCKADDR_INET`.
    pub const ENDPOINT: usize = 76;
    pub const TX_BYTES: usize = 104;
    pub const RX_BYTES: usize = 112;
    pub const LAST_HANDSHAKE: usize = 120;
    pub const ALLOWED_IPS_COUNT: usize = 128;
}

/// Positions dans `WIREGUARD_ALLOWED_IP`.
mod aip {
    pub const ADDRESS: usize = 0;
    pub const ADDRESS_FAMILY: usize = 16;
    pub const CIDR: usize = 18;
    pub const FLAGS: usize = 20;
}

/// `WIREGUARD_INTERFACE_FLAG`.
mod interface_flag {
    pub const HAS_PRIVATE_KEY: u32 = 1 << 1;
    pub const HAS_LISTEN_PORT: u32 = 1 << 2;
    pub const REPLACE_PEERS: u32 = 1 << 3;
}

/// `WIREGUARD_PEER_FLAG`.
mod peer_flag {
    pub const HAS_PUBLIC_KEY: u32 = 1 << 0;
    pub const HAS_PRESHARED_KEY: u32 = 1 << 1;
    pub const HAS_PERSISTENT_KEEPALIVE: u32 = 1 << 2;
    pub const HAS_ENDPOINT: u32 = 1 << 3;
    pub const REPLACE_ALLOWED_IPS: u32 = 1 << 5;
}

const AF_INET: u16 = 2;
const AF_INET6: u16 = 23;

/// Taille de `SOCKADDR_INET`: celle de `SOCKADDR_IN6`, la plus grande des deux.
const SOCKADDR_INET_SIZE: usize = 28;

/// Coherence de la disposition, verifiee a la compilation.
///
/// Les offsets ci-dessus sont recopies d'un en-tete C. Une faute de frappe y
/// produirait un blob accepte par le compilateur et mal lu par un driver
/// noyau. Ces egalites disent que les champs se suivent sans trou inattendu et
/// tiennent dans la taille annoncee: elles ne peuvent pas etre fausses a
/// l'execution seulement.
const _: () = {
    assert!(
        itf::PUBLIC_KEY + WG_KEY_BYTES == 70,
        "cle publique jusqu'a 70"
    );
    assert!(itf::PEERS_COUNT + 4 <= INTERFACE_SIZE);
    assert!(peer::PRESHARED_KEY + WG_KEY_BYTES == peer::PERSISTENT_KEEPALIVE);
    assert!(peer::ENDPOINT + SOCKADDR_INET_SIZE == peer::TX_BYTES);
    assert!(peer::TX_BYTES + 8 == peer::RX_BYTES);
    assert!(peer::RX_BYTES + 8 == peer::LAST_HANDSHAKE);
    assert!(peer::LAST_HANDSHAKE + 8 == peer::ALLOWED_IPS_COUNT);
    assert!(peer::ALLOWED_IPS_COUNT + 4 <= PEER_SIZE);
    assert!(aip::FLAGS + 4 == ALLOWED_IP_SIZE);
};

/// Produit le blob a passer a `WireGuardSetConfiguration`.
///
/// La configuration est posee en remplacement: `REPLACE_PEERS` sur l'interface
/// et `REPLACE_ALLOWED_IPS` sur le pair. Une reconfiguration ne laisse donc
/// jamais survivre un pair ou un prefixe d'une session precedente, ce qui
/// serait une route residuelle hors de la politique voulue.
///
/// La cle publique de l'interface n'est pas transmise: le driver la derive de
/// la cle privee. La transmettre demanderait de refaire ce calcul ici, donc
/// d'embarquer Curve25519 pour rien.
pub fn encode(cfg: &TunnelConfig) -> Result<Vec<u8>> {
    // WireGuardNT ne sait monter que du WireGuard: si un coeur porte le
    // trafic, ce n'est pas ce peripherique qui doit etre appele, et le dire
    // vaut mieux que de fabriquer un blob a partir de rien.
    let wg = cfg.wireguard()?;
    let allowed = &wg.peer.allowed_ips;
    if allowed.is_empty() {
        // `TunnelConfig::validate` l'interdit deja. Ici c'est le blob qui est
        // en jeu: un pair sans prefixe autorise ne recevrait aucun trafic, et
        // le tunnel monterait sans rien transporter.
        return Err(Error::Config(
            "aucun prefixe autorise: le pair ne recevrait aucun trafic".into(),
        ));
    }

    let mut blob = vec![0u8; INTERFACE_SIZE + PEER_SIZE + allowed.len() * ALLOWED_IP_SIZE];

    let mut flags = interface_flag::HAS_PRIVATE_KEY | interface_flag::REPLACE_PEERS;
    if wg.listen_port.is_some() {
        flags |= interface_flag::HAS_LISTEN_PORT;
    }
    put_u32(&mut blob, itf::FLAGS, flags);
    put_u16(&mut blob, itf::LISTEN_PORT, wg.listen_port.unwrap_or(0));
    put_bytes(&mut blob, itf::PRIVATE_KEY, &wg.private_key.to_bytes()?[..]);
    // itf::PUBLIC_KEY reste a zero, faute de flag HAS_PUBLIC_KEY.
    put_u32(&mut blob, itf::PEERS_COUNT, 1);

    let base = INTERFACE_SIZE;
    let mut flags =
        peer_flag::HAS_PUBLIC_KEY | peer_flag::HAS_ENDPOINT | peer_flag::REPLACE_ALLOWED_IPS;
    if wg.peer.preshared_key.is_some() {
        flags |= peer_flag::HAS_PRESHARED_KEY;
    }
    if wg.peer.persistent_keepalive != 0 {
        flags |= peer_flag::HAS_PERSISTENT_KEEPALIVE;
    }
    put_u32(&mut blob, base + peer::FLAGS, flags);
    put_u32(&mut blob, base + peer::RESERVED, 0);
    put_bytes(
        &mut blob,
        base + peer::PUBLIC_KEY,
        &wg.peer.public_key.to_bytes()?[..],
    );
    if let Some(psk) = &wg.peer.preshared_key {
        put_bytes(&mut blob, base + peer::PRESHARED_KEY, &psk.to_bytes()?[..]);
    }
    put_u16(
        &mut blob,
        base + peer::PERSISTENT_KEEPALIVE,
        wg.peer.persistent_keepalive,
    );
    put_sockaddr_inet(&mut blob, base + peer::ENDPOINT, wg.peer.endpoint.addr);
    // TX_BYTES, RX_BYTES et LAST_HANDSHAKE sont des compteurs que le driver
    // remplit en lecture. On les laisse a zero.
    put_u32(
        &mut blob,
        base + peer::ALLOWED_IPS_COUNT,
        allowed.len() as u32,
    );

    for (i, net) in allowed.iter().enumerate() {
        let at = base + PEER_SIZE + i * ALLOWED_IP_SIZE;
        put_allowed_ip(&mut blob, at, net);
    }

    Ok(blob)
}

/// Ce qu'on relit d'une configuration rendue par le driver.
///
/// Volontairement partiel: seuls les champs qui prouvent que la disposition
/// d'octets est la bonne. Si un offset etait faux a l'ecriture, le driver
/// rendrait autre chose ici.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadBack {
    /// Cle publique de l'INTERFACE, derivee par le driver a partir de la cle
    /// privee. Nulle dans un blob qu'on vient d'ecrire, puisqu'on ne la
    /// transmet pas: c'est justement le driver qui la calcule.
    pub interface_public_key: [u8; WG_KEY_BYTES],
    pub peers_count: u32,
    /// Le premier pair, s'il y en a un.
    ///
    /// Une interface sans pair est un blob parfaitement valide de 80 octets:
    /// c'est l'etat d'un adaptateur cree mais pas encore configure. Traiter ce
    /// cas comme une erreur de decodage confondrait "blob illisible" et
    /// "adaptateur vide", deux diagnostics tres differents pour qui lit le
    /// message.
    pub peer: Option<PeerReadBack>,
}

/// Ce qu'on relit d'un pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerReadBack {
    pub public_key: [u8; WG_KEY_BYTES],
    pub endpoint: Option<SocketAddr>,
    pub persistent_keepalive: u16,
    pub allowed_ips: Vec<IpNet>,
    /// `None` tant qu'aucun handshake n'a eu lieu.
    pub last_handshake: Option<SystemTime>,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
}

/// Relit un blob de configuration.
///
/// Le driver rend la meme disposition que celle qu'il accepte, donc cette
/// fonction est l'inverse de [`encode`] pour les champs qu'elle couvre. C'est
/// ce qui permet de confronter la disposition au vrai driver: on ecrit, on
/// relit, on compare. Un offset faux ne survit pas a cet aller-retour.
pub fn decode(blob: &[u8]) -> Result<ReadBack> {
    if blob.len() < INTERFACE_SIZE {
        return Err(Error::Tunnel(format!(
            "configuration de {} octets, au moins {INTERFACE_SIZE} attendus",
            blob.len()
        )));
    }
    let peers_count = get_u32(blob, itf::PEERS_COUNT);
    let mut interface_public_key = [0u8; WG_KEY_BYTES];
    interface_public_key.copy_from_slice(&blob[itf::PUBLIC_KEY..][..WG_KEY_BYTES]);

    if peers_count == 0 {
        return Ok(ReadBack {
            interface_public_key,
            peers_count,
            peer: None,
        });
    }

    let base = INTERFACE_SIZE;
    if blob.len() < base + PEER_SIZE {
        return Err(Error::Tunnel(format!(
            "l'interface annonce {peers_count} pair(s) mais la configuration \
             ne fait que {} octets, {} attendus pour en porter un",
            blob.len(),
            base + PEER_SIZE
        )));
    }

    let mut peer_public_key = [0u8; WG_KEY_BYTES];
    peer_public_key.copy_from_slice(&blob[base + peer::PUBLIC_KEY..][..WG_KEY_BYTES]);

    let flags = get_u32(blob, base + peer::FLAGS);
    let endpoint = if flags & peer_flag::HAS_ENDPOINT != 0 {
        get_sockaddr_inet(blob, base + peer::ENDPOINT)
    } else {
        None
    };

    let count = get_u32(blob, base + peer::ALLOWED_IPS_COUNT) as usize;
    let attendu = base + PEER_SIZE + count * ALLOWED_IP_SIZE;
    if blob.len() < attendu {
        return Err(Error::Tunnel(format!(
            "le pair annonce {count} prefixes, soit {attendu} octets, mais la \
             configuration n'en fait que {}",
            blob.len()
        )));
    }
    let mut allowed_ips = Vec::with_capacity(count);
    for i in 0..count {
        let at = base + PEER_SIZE + i * ALLOWED_IP_SIZE;
        allowed_ips.push(get_allowed_ip(blob, at)?);
    }

    Ok(ReadBack {
        interface_public_key,
        peers_count,
        peer: Some(PeerReadBack {
            public_key: peer_public_key,
            endpoint,
            persistent_keepalive: get_u16(blob, base + peer::PERSISTENT_KEEPALIVE),
            allowed_ips,
            last_handshake: filetime_to_system_time(get_u64(blob, base + peer::LAST_HANDSHAKE)),
            tx_bytes: get_u64(blob, base + peer::TX_BYTES),
            rx_bytes: get_u64(blob, base + peer::RX_BYTES),
        }),
    })
}

/// Nombre d'intervalles de 100 ns entre le 1er janvier 1601 et l'epoque Unix.
///
/// Un FILETIME compte des intervalles de 100 ns depuis le 1er janvier 1601
/// UTC; cet ecart, 116444736000000000, le ramene a l'epoque Unix. C'est la
/// SEULE copie du nombre dans le crate: `wfp_veille` l'importe pour poser
/// l'echeance absolue de son minuteur de reveil, la ou il portait sa propre
/// copie non gardee. La recette
/// `l_ecart_entre_1601_et_l_epoque_unix_se_recalcule` le rederive du
/// calendrier gregorien et couvre donc les deux usages.
pub(crate) const FILETIME_TO_UNIX: u64 = 116_444_736_000_000_000;

/// Convertit l'horodatage du driver, compte en intervalles de 100 ns depuis
/// 1601-01-01 UTC, en temps systeme.
///
/// Zero veut dire "aucun handshake", pas "1601": le rendre tel quel ferait
/// croire a un pair vivant depuis quatre siecles. Une valeur anterieure a
/// l'epoque Unix est tout aussi absurde et traitee pareil.
pub fn filetime_to_system_time(ticks: u64) -> Option<SystemTime> {
    if ticks < FILETIME_TO_UNIX {
        return None;
    }
    let depuis_epoque = ticks - FILETIME_TO_UNIX;
    Some(
        SystemTime::UNIX_EPOCH
            + Duration::from_secs(depuis_epoque / 10_000_000)
            + Duration::from_nanos((depuis_epoque % 10_000_000) * 100),
    )
}

fn get_u64(blob: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(blob[at..at + 8].try_into().expect("huit octets"))
}

fn get_sockaddr_inet(blob: &[u8], at: usize) -> Option<SocketAddr> {
    let port = u16::from_be_bytes([blob[at + 2], blob[at + 3]]);
    match get_u16(blob, at) {
        AF_INET => {
            let mut o = [0u8; 4];
            o.copy_from_slice(&blob[at + 4..at + 8]);
            Some(SocketAddr::from((o, port)))
        }
        AF_INET6 => {
            let mut o = [0u8; 16];
            o.copy_from_slice(&blob[at + 8..at + 24]);
            Some(SocketAddr::from((o, port)))
        }
        _ => None,
    }
}

fn get_allowed_ip(blob: &[u8], at: usize) -> Result<IpNet> {
    let cidr = blob[at + aip::CIDR];
    let addr = match get_u16(blob, at + aip::ADDRESS_FAMILY) {
        AF_INET => {
            let mut o = [0u8; 4];
            o.copy_from_slice(&blob[at + aip::ADDRESS..at + aip::ADDRESS + 4]);
            IpAddr::from(o)
        }
        AF_INET6 => {
            let mut o = [0u8; 16];
            o.copy_from_slice(&blob[at + aip::ADDRESS..at + aip::ADDRESS + 16]);
            IpAddr::from(o)
        }
        autre => {
            return Err(Error::Tunnel(format!(
                "famille d'adresse inconnue dans un prefixe autorise: {autre}"
            )));
        }
    };
    IpNet::new(addr, cidr)
}

fn get_u16(blob: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([blob[at], blob[at + 1]])
}

fn get_u32(blob: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([blob[at], blob[at + 1], blob[at + 2], blob[at + 3]])
}

/// Ecrit un `SOCKADDR_INET`.
///
/// Le port est en ordre reseau, contrairement a tout le reste de la structure
/// qui est en ordre hote. C'est la convention de `SOCKADDR_IN`, pas une
/// particularite de WireGuard.
fn put_sockaddr_inet(blob: &mut [u8], at: usize, addr: SocketAddr) {
    match addr {
        SocketAddr::V4(v4) => {
            put_u16(blob, at, AF_INET);
            put_bytes(blob, at + 2, &v4.port().to_be_bytes());
            put_bytes(blob, at + 4, &v4.ip().octets());
            // sin_zero[8] reste a zero.
        }
        SocketAddr::V6(v6) => {
            put_u16(blob, at, AF_INET6);
            put_bytes(blob, at + 2, &v6.port().to_be_bytes());
            put_u32(blob, at + 4, v6.flowinfo());
            put_bytes(blob, at + 8, &v6.ip().octets());
            put_u32(blob, at + 24, v6.scope_id());
        }
    }
    debug_assert!(at + SOCKADDR_INET_SIZE <= blob.len());
}

fn put_allowed_ip(blob: &mut [u8], at: usize, net: &IpNet) {
    match net.addr {
        IpAddr::V4(v4) => {
            put_bytes(blob, at + aip::ADDRESS, &v4.octets());
            put_u16(blob, at + aip::ADDRESS_FAMILY, AF_INET);
        }
        IpAddr::V6(v6) => {
            put_bytes(blob, at + aip::ADDRESS, &v6.octets());
            put_u16(blob, at + aip::ADDRESS_FAMILY, AF_INET6);
        }
    }
    blob[at + aip::CIDR] = net.prefix_len;
    put_u32(blob, at + aip::FLAGS, 0);
}

fn put_u16(blob: &mut [u8], at: usize, value: u16) {
    blob[at..at + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(blob: &mut [u8], at: usize, value: u32) {
    blob[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_bytes(blob: &mut [u8], at: usize, value: &[u8]) {
    blob[at..at + value.len()].copy_from_slice(value);
}

#[cfg(test)]
mod tests {

    use bifrost_core::config::{Portage as P, WireguardParams as WP};

    /// Les parametres WireGuard d'une configuration de test.
    ///
    /// Panique si le portage n'est pas WireGuard: seul un test mal ecrit peut
    /// y arriver, et le type interdit desormais l'inverse.
    fn wg(c: &TunnelConfig) -> &WP {
        c.portage.wireguard().expect("ce test suppose du WireGuard")
    }

    fn wg_mut(c: &mut TunnelConfig) -> &mut WP {
        match &mut c.portage {
            P::Wireguard(w) => w,
            P::Coeur(_) => panic!("ce test suppose du WireGuard"),
        }
    }
    use super::*;
    use bifrost_core::config::{DnsPolicy, Endpoint, PeerConfig, WgKey};
    use std::net::{Ipv4Addr, Ipv6Addr};

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
            portage: P::Wireguard(Box::new(WP {
                private_key: key('A'),
                fwmark: 0xca6c,
                routing_table: 51820,
                listen_port: None,
                peer: PeerConfig {
                    public_key: key('B'),
                    preshared_key: None,
                    endpoint: Endpoint {
                        addr: "203.0.113.7:51820".parse().unwrap(),
                    },
                    allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
                    persistent_keepalive: 25,
                },
            })),
            dns: DnsPolicy {
                local_resolver: IpAddr::V4(Ipv4Addr::LOCALHOST),
                upstream: vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))],
                embarque: false,
                anti_telemetrie: bifrost_core::config::ProfilTelemetrie::Aucun,
            },
            allow_lan: false,
        }
    }

    fn u16_at(blob: &[u8], at: usize) -> u16 {
        u16::from_le_bytes(blob[at..at + 2].try_into().unwrap())
    }

    fn u32_at(blob: &[u8], at: usize) -> u32 {
        u32::from_le_bytes(blob[at..at + 4].try_into().unwrap())
    }

    /// Les trois tailles viennent de l'en-tete et sont confirmees par le code
    /// Go. Si l'une d'elles bougeait, le driver lirait n'importe quoi a partir
    /// du deuxieme element.
    #[test]
    fn les_tailles_de_structures_sont_celles_de_l_entete() {
        assert_eq!(INTERFACE_SIZE, 80);
        assert_eq!(PEER_SIZE, 136);
        assert_eq!(ALLOWED_IP_SIZE, 24);
    }

    /// Les positions, confrontees a une transcription des structures C.
    ///
    /// Toutes les autres recettes de ce module ecrivent a l'offset `N` et
    /// relisent au MEME offset `N`: elles restent vertes quelle que soit la
    /// valeur de `N`. Le bloc `const _` en tete de module ne fait guere mieux,
    /// il recoupe nos positions les unes contre les autres. Une position
    /// epinglee sur une autre de nos positions ne dit rien de la disposition
    /// que le pilote attend.
    ///
    /// Mesure du 23/08/2026 sur dev-windows, mutation `+1` appliquee a chaque
    /// position seule: `itf::FLAGS`, `itf::LISTEN_PORT` et `itf::PRIVATE_KEY`
    /// ne faisaient rougir aucune recette.
    ///
    /// Ici les trois structures de `api/wireguard.h` sont redeclarees avec
    /// leurs vrais types, et c'est le compilateur qui calcule les positions:
    /// le bourrage et l'alignement cessent d'etre affirmes par un humain. Le
    /// `ALIGNED(8)` de l'en-tete devient `align(8)`, et il compte: sans lui,
    /// `WIREGUARD_INTERFACE` mesurerait 76 octets au lieu de 80.
    ///
    /// Ce que cette recette ne prouve PAS: que la transcription corresponde au
    /// pilote installe. Elle attrape une desynchronisation INTERNE - une
    /// position corrigee seule, par exemple d'apres l'exemple C# amont qui
    /// place `Cidr` a 20 - et rien de plus. Seul un aller-retour contre le vrai
    /// driver irait plus loin, et il demande les droits d'administrateur.
    ///
    /// Les types viennent de l'en-tete et non de `windows-sys`: ce module se
    /// construit sans dependance Windows, c'est ce qui lui permet d'etre
    /// eprouve en integration continue Linux (cf. `wgnt::mod`).
    #[test]
    fn les_positions_declarees_sont_celles_que_le_compilateur_calcule() {
        use std::mem::{offset_of, size_of};

        // Aucun champ n'est jamais lu: ces structures n'existent que pour que
        // le compilateur leur donne une disposition et que `offset_of!`
        // l'interroge.
        #[allow(dead_code)]
        #[repr(C, align(8))]
        struct InterfaceC {
            /// `WIREGUARD_INTERFACE_FLAG Flags`: une enumeration C, donc un int.
            flags: u32,
            /// `WORD ListenPort`.
            listen_port: u16,
            /// `BYTE PrivateKey[WIREGUARD_KEY_LENGTH]`.
            private_key: [u8; WG_KEY_BYTES],
            /// `BYTE PublicKey[WIREGUARD_KEY_LENGTH]`.
            public_key: [u8; WG_KEY_BYTES],
            /// `DWORD PeersCount`: c'est son alignement sur 4 qui intercale
            /// les deux octets de bourrage apres la cle publique.
            peers_count: u32,
        }

        /// `SOCKADDR_INET`, une union dont `SOCKADDR_IN6` est le plus grand
        /// membre: c'est donc lui qui donne la taille et l'alignement.
        #[allow(dead_code)]
        #[repr(C)]
        struct SockaddrInetC {
            family: u16,
            /// En ordre RESEAU, seule exception du blob.
            port: u16,
            flowinfo: u32,
            addr: [u8; 16],
            scope_id: u32,
        }

        #[allow(dead_code)]
        #[repr(C, align(8))]
        struct PeerC {
            flags: u32,
            reserved: u32,
            public_key: [u8; WG_KEY_BYTES],
            preshared_key: [u8; WG_KEY_BYTES],
            persistent_keepalive: u16,
            /// Aligne sur 4: deux octets de bourrage apres le keepalive.
            endpoint: SockaddrInetC,
            tx_bytes: u64,
            rx_bytes: u64,
            last_handshake: u64,
            allowed_ips_count: u32,
        }

        #[allow(dead_code)]
        #[repr(C, align(8))]
        struct AllowedIpC {
            /// L'union `{ IN_ADDR V4; IN6_ADDR V6; }`: seize octets, alignes
            /// sur quatre par `IN_ADDR`.
            address: [u32; 4],
            /// `ADDRESS_FAMILY`, c'est-a-dire `USHORT`.
            address_family: u16,
            /// `BYTE Cidr`.
            cidr: u8,
            /// `WIREGUARD_ALLOWED_IP_FLAG Flags`: un int, donc aligne sur 4,
            /// donc un octet de bourrage apres `Cidr`.
            flags: u32,
        }

        assert_eq!(size_of::<InterfaceC>(), INTERFACE_SIZE);
        assert_eq!(offset_of!(InterfaceC, flags), itf::FLAGS);
        assert_eq!(offset_of!(InterfaceC, listen_port), itf::LISTEN_PORT);
        assert_eq!(offset_of!(InterfaceC, private_key), itf::PRIVATE_KEY);
        assert_eq!(offset_of!(InterfaceC, public_key), itf::PUBLIC_KEY);
        assert_eq!(offset_of!(InterfaceC, peers_count), itf::PEERS_COUNT);

        assert_eq!(size_of::<SockaddrInetC>(), SOCKADDR_INET_SIZE);

        assert_eq!(size_of::<PeerC>(), PEER_SIZE);
        assert_eq!(offset_of!(PeerC, flags), peer::FLAGS);
        assert_eq!(offset_of!(PeerC, reserved), peer::RESERVED);
        assert_eq!(offset_of!(PeerC, public_key), peer::PUBLIC_KEY);
        assert_eq!(offset_of!(PeerC, preshared_key), peer::PRESHARED_KEY);
        assert_eq!(
            offset_of!(PeerC, persistent_keepalive),
            peer::PERSISTENT_KEEPALIVE
        );
        assert_eq!(offset_of!(PeerC, endpoint), peer::ENDPOINT);
        assert_eq!(offset_of!(PeerC, tx_bytes), peer::TX_BYTES);
        assert_eq!(offset_of!(PeerC, rx_bytes), peer::RX_BYTES);
        assert_eq!(offset_of!(PeerC, last_handshake), peer::LAST_HANDSHAKE);
        assert_eq!(
            offset_of!(PeerC, allowed_ips_count),
            peer::ALLOWED_IPS_COUNT
        );

        assert_eq!(size_of::<AllowedIpC>(), ALLOWED_IP_SIZE);
        assert_eq!(offset_of!(AllowedIpC, address), aip::ADDRESS);
        assert_eq!(offset_of!(AllowedIpC, address_family), aip::ADDRESS_FAMILY);
        assert_eq!(offset_of!(AllowedIpC, cidr), aip::CIDR);
        assert_eq!(offset_of!(AllowedIpC, flags), aip::FLAGS);
    }

    /// Les bits de drapeau, epingles sur l'enumeration amont.
    ///
    /// Rien ne permet de les DEDUIRE: ce sont des valeurs d'enumeration, et la
    /// seule source est `api/wireguard.h`. La recette les recopie donc, rang
    /// par rang, et c'est tout ce qu'elle peut faire. Elle vaut quand meme
    /// mieux que rien: partout ailleurs le module manipule ces drapeaux par
    /// leur NOM, si bien qu'un bit decale d'un cran ne faisait rougir aucune
    /// recette - mesure du 23/08/2026 sur dev-windows, quatre des huit
    /// muettes, les quatre autres n'etant vues que par ricochet.
    ///
    /// La panne serait silencieuse. Le pilote lirait un drapeau qu'on n'a pas
    /// voulu poser et ignorerait le champ qu'on croyait annoncer: un
    /// `HAS_ENDPOINT` devenu `1 << 4` donne un tunnel qui monte, avec un pair
    /// sans adresse.
    ///
    /// Le rang 4 de `WIREGUARD_PEER_FLAG` est vacant dans l'en-tete, entre
    /// `HAS_ENDPOINT` et `REPLACE_ALLOWED_IPS`. Ne pas le lire comme une faute
    /// de recopie.
    #[test]
    fn les_bits_de_drapeau_sont_ceux_de_l_enumeration_amont() {
        // WIREGUARD_INTERFACE_FLAG. Le rang 0, HAS_PUBLIC_KEY, n'est pas
        // declare ici: on ne transmet pas la cle publique de l'interface.
        assert_eq!(interface_flag::HAS_PRIVATE_KEY, 1 << 1);
        assert_eq!(interface_flag::HAS_LISTEN_PORT, 1 << 2);
        assert_eq!(interface_flag::REPLACE_PEERS, 1 << 3);

        // WIREGUARD_PEER_FLAG. Les rangs 6 et 7, REMOVE et UPDATE_ONLY, ne
        // sont pas declares: ce module ne fait jamais de mise a jour
        // incrementale, il remplace.
        assert_eq!(peer_flag::HAS_PUBLIC_KEY, 1 << 0);
        assert_eq!(peer_flag::HAS_PRESHARED_KEY, 1 << 1);
        assert_eq!(peer_flag::HAS_PERSISTENT_KEEPALIVE, 1 << 2);
        assert_eq!(peer_flag::HAS_ENDPOINT, 1 << 3);
        assert_eq!(peer_flag::REPLACE_ALLOWED_IPS, 1 << 5);

        // Deux drapeaux ne peuvent pas partager un rang. C'est la faute que la
        // recopie ci-dessus laisserait passer si deux lignes bougeaient
        // ensemble, et celle qui fait poser un drapeau pour un autre.
        let tous = [
            peer_flag::HAS_PUBLIC_KEY,
            peer_flag::HAS_PRESHARED_KEY,
            peer_flag::HAS_PERSISTENT_KEEPALIVE,
            peer_flag::HAS_ENDPOINT,
            peer_flag::REPLACE_ALLOWED_IPS,
        ];
        assert_eq!(
            tous.iter().fold(0u32, |a, b| a | b),
            tous.iter().sum::<u32>(),
            "deux drapeaux de pair se recouvrent"
        );
    }

    /// `AF_INET` et `AF_INET6` sont ceux de Windows, pas ceux de l'hote.
    ///
    /// Le blob part vers un pilote Windows: la famille d'adresse doit etre
    /// celle de `ws2def.h`, ou `AF_INET6` vaut 23. Sous Linux elle vaut 10, et
    /// ces recettes tournent aussi sous Linux. Un jour quelqu'un lira 23 comme
    /// une faute de frappe et voudra la corriger: le blob porterait alors une
    /// famille que le driver ne connait pas, et `get_allowed_ip` refuserait
    /// chaque prefixe v6 en relecture.
    ///
    /// La valeur n'est pas prise chez `windows-sys`, pour la meme raison que
    /// plus haut: pas de dependance Windows dans ce module.
    #[test]
    fn les_familles_d_adresse_sont_celles_de_winsock() {
        assert_eq!(AF_INET, 2);
        assert_eq!(AF_INET6, 23, "valeur Windows; 10 est celle de Linux");
    }

    /// L'ecart 1601-1970, recalcule plutot que recopie.
    ///
    /// 116444736000000000 est un nombre qu'on recopie sans jamais le verifier,
    /// et aucune recette ne le regardait: celles qui le citent l'emploient des
    /// deux cotes de l'egalite. Il se derive pourtant, par le calendrier
    /// gregorien proleptique: une annee est bissextile si elle est divisible
    /// par 4, sauf les seculaires qui ne le sont pas par 400; on additionne
    /// les jours de chaque annee de 1601 a 1969 incluse. Soit 134774 jours de
    /// 86400 secondes, comptes en intervalles de 100 ns. Les 89 annees
    /// bissextiles que la version precedente recopiait (1604 a 1968, moins
    /// 1700, 1800 et 1900) ne sont plus un nombre ecrit: la regle les produit.
    ///
    /// La constante est la seule du crate depuis que `wfp_veille` l'importe:
    /// cette recette garde aussi l'echeance du minuteur de reveil.
    ///
    /// Un ecart faux ne fait rien planter: il decale tous les horodatages de
    /// poignee de main rendus par le pilote, et c'est le jugement porte sur la
    /// sante du tunnel qui devient faux; cote veille, il decalerait d'autant
    /// l'heure du reveil.
    #[test]
    fn l_ecart_entre_1601_et_l_epoque_unix_se_recalcule() {
        fn bissextile(annee: u64) -> bool {
            annee.is_multiple_of(4) && (!annee.is_multiple_of(100) || annee.is_multiple_of(400))
        }
        let jours: u64 = (1601..1970)
            .map(|annee| if bissextile(annee) { 366 } else { 365 })
            .sum();
        assert_eq!(jours, 134_774);
        assert_eq!(FILETIME_TO_UNIX, jours * 86_400 * 10_000_000);
    }

    #[test]
    fn la_taille_du_blob_suit_le_nombre_de_prefixes() {
        let mut c = cfg();
        assert_eq!(encode(&c).unwrap().len(), 80 + 136 + 24);

        wg_mut(&mut c).peer.allowed_ips = vec![
            "0.0.0.0/0".parse().unwrap(),
            "::/0".parse().unwrap(),
            "10.0.0.0/8".parse().unwrap(),
        ];
        assert_eq!(encode(&c).unwrap().len(), 80 + 136 + 3 * 24);
    }

    /// Le decompte annonce doit correspondre a ce qui suit reellement, sinon
    /// le driver lit au-dela du tampon ou ignore des prefixes.
    #[test]
    fn les_decomptes_annonces_correspondent_au_contenu() {
        let mut c = cfg();
        wg_mut(&mut c).peer.allowed_ips =
            vec!["0.0.0.0/0".parse().unwrap(), "::/0".parse().unwrap()];
        let blob = encode(&c).unwrap();

        assert_eq!(u32_at(&blob, itf::PEERS_COUNT), 1);
        assert_eq!(u32_at(&blob, INTERFACE_SIZE + peer::ALLOWED_IPS_COUNT), 2);
        assert_eq!(
            blob.len(),
            INTERFACE_SIZE + PEER_SIZE + 2 * ALLOWED_IP_SIZE,
            "le tampon doit contenir exactement ce que les decomptes annoncent"
        );
    }

    /// La cle privee doit atterrir a l'offset 6, pas ailleurs. Une cle decalee
    /// donne un tunnel qui monte et ne fait jamais de handshake.
    #[test]
    fn la_cle_privee_est_a_sa_place_et_la_publique_reste_nulle() {
        let mut c = cfg();
        wg_mut(&mut c).private_key = format!("AQ{}=", "A".repeat(41)).parse().unwrap();
        let blob = encode(&c).unwrap();

        assert_eq!(blob[itf::PRIVATE_KEY], 1);
        assert_eq!(
            &blob[itf::PRIVATE_KEY + 1..itf::PRIVATE_KEY + WG_KEY_BYTES],
            &[0u8; WG_KEY_BYTES - 1][..]
        );
        // Sans le flag HAS_PUBLIC_KEY, le driver derive la cle publique. Le
        // champ doit rester nul, sinon on lui ferait croire le contraire.
        assert_eq!(
            &blob[itf::PUBLIC_KEY..itf::PUBLIC_KEY + WG_KEY_BYTES],
            &[0u8; WG_KEY_BYTES][..]
        );
        assert_eq!(
            u32_at(&blob, itf::FLAGS) & interface_flag::HAS_PRIVATE_KEY,
            interface_flag::HAS_PRIVATE_KEY
        );
    }

    /// Le port d'un SOCKADDR est en ordre RESEAU. Tout le reste du blob est en
    /// ordre hote: c'est la seule exception, et l'oublier donne un endpoint
    /// dont le port est celui des octets inverses, donc injoignable.
    #[test]
    fn le_port_de_l_endpoint_est_en_ordre_reseau() {
        let blob = encode(&cfg()).unwrap();
        let at = INTERFACE_SIZE + peer::ENDPOINT;

        assert_eq!(u16_at(&blob, at), AF_INET);
        assert_eq!(
            &blob[at + 2..at + 4],
            &51820u16.to_be_bytes()[..],
            "port en ordre reseau attendu"
        );
        assert_ne!(
            &blob[at + 2..at + 4],
            &51820u16.to_le_bytes()[..],
            "51820 doit rester asymetrique, sinon ce test ne prouve rien"
        );
        assert_eq!(&blob[at + 4..at + 8], &[203, 0, 113, 7][..]);
    }

    #[test]
    fn un_endpoint_ipv6_utilise_la_disposition_sockaddr_in6() {
        let mut c = cfg();
        wg_mut(&mut c).peer.endpoint.addr = "[2001:db8::1]:51820".parse().unwrap();
        let blob = encode(&c).unwrap();
        let at = INTERFACE_SIZE + peer::ENDPOINT;

        assert_eq!(u16_at(&blob, at), AF_INET6);
        assert_eq!(&blob[at + 2..at + 4], &51820u16.to_be_bytes()[..]);
        assert_eq!(u32_at(&blob, at + 4), 0, "flowinfo");
        assert_eq!(
            &blob[at + 8..at + 24],
            &"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets()[..]
        );
        assert_eq!(u32_at(&blob, at + 24), 0, "scope_id");
    }

    /// `Cidr` est a 18 et `Flags` a 20. L'exemple C# du depot amont place
    /// `Cidr` a 20: le suivre ferait ecrire le prefixe dans le champ de flags,
    /// et le driver verrait un prefixe /0 sur chaque entree.
    #[test]
    fn le_prefixe_autorise_respecte_la_disposition_de_l_entete() {
        let mut c = cfg();
        wg_mut(&mut c).peer.allowed_ips = vec!["10.0.0.0/8".parse().unwrap()];
        let blob = encode(&c).unwrap();
        let at = INTERFACE_SIZE + PEER_SIZE;

        assert_eq!(&blob[at..at + 4], &[10, 0, 0, 0][..]);
        // Une adresse v4 n'occupe que 4 des 16 octets du champ.
        assert_eq!(&blob[at + 4..at + 16], &[0u8; 12][..]);
        assert_eq!(u16_at(&blob, at + aip::ADDRESS_FAMILY), AF_INET);
        assert_eq!(blob[at + aip::CIDR], 8);
        assert_eq!(u32_at(&blob, at + aip::FLAGS), 0);
    }

    #[test]
    fn un_prefixe_ipv6_occupe_les_seize_octets() {
        let mut c = cfg();
        wg_mut(&mut c).peer.allowed_ips = vec!["2001:db8::/32".parse().unwrap()];
        let blob = encode(&c).unwrap();
        let at = INTERFACE_SIZE + PEER_SIZE;

        assert_eq!(
            &blob[at..at + 16],
            &"2001:db8::".parse::<Ipv6Addr>().unwrap().octets()[..]
        );
        assert_eq!(u16_at(&blob, at + aip::ADDRESS_FAMILY), AF_INET6);
        assert_eq!(blob[at + aip::CIDR], 32);
    }

    /// Une reconfiguration ne doit jamais laisser survivre un pair ou un
    /// prefixe de la session precedente: ce serait une route hors politique.
    #[test]
    fn la_configuration_remplace_toujours_l_existant() {
        let blob = encode(&cfg()).unwrap();
        assert_ne!(u32_at(&blob, itf::FLAGS) & interface_flag::REPLACE_PEERS, 0);
        assert_ne!(
            u32_at(&blob, INTERFACE_SIZE + peer::FLAGS) & peer_flag::REPLACE_ALLOWED_IPS,
            0
        );
    }

    /// Un flag annonce un champ rempli. Annoncer une cle partagee absente
    /// ferait lire 32 octets nuls au driver et casserait le handshake.
    #[test]
    fn les_flags_optionnels_suivent_la_presence_des_champs() {
        let mut c = cfg();
        wg_mut(&mut c).peer.preshared_key = None;
        wg_mut(&mut c).peer.persistent_keepalive = 0;
        wg_mut(&mut c).listen_port = None;
        let sans = encode(&c).unwrap();
        assert_eq!(
            u32_at(&sans, INTERFACE_SIZE + peer::FLAGS) & peer_flag::HAS_PRESHARED_KEY,
            0
        );
        assert_eq!(
            u32_at(&sans, INTERFACE_SIZE + peer::FLAGS) & peer_flag::HAS_PERSISTENT_KEEPALIVE,
            0
        );
        assert_eq!(
            u32_at(&sans, itf::FLAGS) & interface_flag::HAS_LISTEN_PORT,
            0
        );
        assert_eq!(
            &sans[INTERFACE_SIZE + peer::PRESHARED_KEY
                ..INTERFACE_SIZE + peer::PRESHARED_KEY + WG_KEY_BYTES],
            &[0u8; WG_KEY_BYTES][..]
        );

        wg_mut(&mut c).peer.preshared_key = Some(key('C'));
        wg_mut(&mut c).peer.persistent_keepalive = 25;
        wg_mut(&mut c).listen_port = Some(51820);
        let avec = encode(&c).unwrap();
        assert_ne!(
            u32_at(&avec, INTERFACE_SIZE + peer::FLAGS) & peer_flag::HAS_PRESHARED_KEY,
            0
        );
        assert_ne!(
            u32_at(&avec, INTERFACE_SIZE + peer::FLAGS) & peer_flag::HAS_PERSISTENT_KEEPALIVE,
            0
        );
        assert_ne!(
            u32_at(&avec, itf::FLAGS) & interface_flag::HAS_LISTEN_PORT,
            0
        );
        assert_eq!(u16_at(&avec, itf::LISTEN_PORT), 51820);
        assert_eq!(
            u16_at(&avec, INTERFACE_SIZE + peer::PERSISTENT_KEEPALIVE),
            25
        );
    }

    /// Le champ `Reserved` et les compteurs de statistiques sont a la charge du
    /// driver. Les remplir serait au mieux ignore, au pire refuse.
    #[test]
    fn les_champs_reserves_au_driver_restent_nuls() {
        let blob = encode(&cfg()).unwrap();
        let base = INTERFACE_SIZE;
        assert_eq!(u32_at(&blob, base + peer::RESERVED), 0);
        for at in [peer::TX_BYTES, peer::RX_BYTES, peer::LAST_HANDSHAKE] {
            assert_eq!(&blob[base + at..base + at + 8], &[0u8; 8][..]);
        }
    }

    /// Les octets de bourrage imposes par l'alignement sur 8 doivent rester
    /// nuls: le driver les lit comme faisant partie de la structure.
    #[test]
    fn le_bourrage_d_alignement_reste_nul() {
        let blob = encode(&cfg()).unwrap();
        // Entre la cle publique de l'interface (fin a 70) et PeersCount (72).
        assert_eq!(&blob[70..72], &[0u8; 2][..]);
        // Queue de WIREGUARD_INTERFACE: 76 a 80.
        assert_eq!(&blob[76..80], &[0u8; 4][..]);
        // Entre le keepalive (fin a 74) et l'endpoint (76).
        assert_eq!(
            &blob[INTERFACE_SIZE + 74..INTERFACE_SIZE + 76],
            &[0u8; 2][..]
        );
        // Queue de WIREGUARD_PEER: 132 a 136.
        assert_eq!(
            &blob[INTERFACE_SIZE + 132..INTERFACE_SIZE + PEER_SIZE],
            &[0u8; 4][..]
        );
    }

    /// L'aller-retour est ce qui sera confronte au vrai driver: on ecrit, il
    /// relit, on compare. Ici il ne teste que la coherence interne, mais c'est
    /// deja lui qui attrape une lecture et une ecriture qui ne parlent pas du
    /// meme champ.
    #[test]
    fn l_aller_retour_conserve_ce_qui_compte() {
        let mut c = cfg();
        wg_mut(&mut c).peer.allowed_ips = vec![
            "0.0.0.0/0".parse().unwrap(),
            "2001:db8::/32".parse().unwrap(),
            "10.0.0.0/8".parse().unwrap(),
        ];
        let relu = decode(&encode(&c).unwrap()).unwrap();

        assert_eq!(relu.peers_count, 1);
        let pair = relu.peer.expect("un pair a ete ecrit");
        assert_eq!(pair.public_key, wg(&c).peer.public_key.to_bytes().unwrap());
        assert_eq!(pair.endpoint, Some(wg(&c).peer.endpoint.addr));
        assert_eq!(pair.persistent_keepalive, 25);
        assert_eq!(pair.allowed_ips, wg(&c).peer.allowed_ips);
    }

    /// Une interface sans pair fait exactement 80 octets et c'est un blob
    /// valide: c'est l'etat d'un adaptateur cree mais pas encore configure. Le
    /// refuser confondrait "adaptateur vide" et "blob illisible".
    #[test]
    fn une_interface_sans_pair_se_decode() {
        let mut blob = encode(&cfg()).unwrap();
        blob.truncate(INTERFACE_SIZE);
        // PeersCount a zero, comme le rendrait le driver.
        blob[itf::PEERS_COUNT..itf::PEERS_COUNT + 4].copy_from_slice(&0u32.to_le_bytes());

        let relu = decode(&blob).unwrap();
        assert_eq!(relu.peers_count, 0);
        assert!(relu.peer.is_none());
    }

    /// En revanche, annoncer un pair sans fournir ses octets reste une erreur,
    /// et le message doit dire laquelle.
    #[test]
    fn un_pair_annonce_mais_absent_est_refuse() {
        let mut blob = encode(&cfg()).unwrap();
        blob.truncate(INTERFACE_SIZE);
        let err = match decode(&blob) {
            Ok(_) => panic!("un pair annonce et absent doit etre refuse"),
            Err(e) => e.to_string(),
        };
        assert!(err.contains("annonce"), "{err}");
    }

    /// Un blob qu'on vient d'ecrire n'a jamais eu de handshake. Rendre 1601
    /// plutot que rien ferait passer un pair muet pour un pair vivant, ce que
    /// `HandshakeInfo::is_alive` interpreterait comme un tunnel sain.
    #[test]
    fn l_absence_de_handshake_ne_devient_pas_une_date() {
        let pair = decode(&encode(&cfg()).unwrap()).unwrap().peer.unwrap();
        assert_eq!(pair.last_handshake, None);
        assert_eq!(pair.tx_bytes, 0);
        assert_eq!(pair.rx_bytes, 0);
    }

    /// Point de repere verifiable: 116444736000000000 intervalles de 100 ns
    /// separent 1601-01-01 de l'epoque Unix.
    #[test]
    fn l_horodatage_du_driver_se_convertit() {
        assert_eq!(filetime_to_system_time(0), None);
        assert_eq!(filetime_to_system_time(FILETIME_TO_UNIX - 1), None);
        assert_eq!(
            filetime_to_system_time(FILETIME_TO_UNIX),
            Some(SystemTime::UNIX_EPOCH)
        );
        // Une seconde apres l'epoque.
        assert_eq!(
            filetime_to_system_time(FILETIME_TO_UNIX + 10_000_000),
            Some(SystemTime::UNIX_EPOCH + Duration::from_secs(1))
        );
    }

    #[test]
    fn l_aller_retour_conserve_un_endpoint_ipv6() {
        let mut c = cfg();
        wg_mut(&mut c).peer.endpoint.addr = "[2001:db8::1]:51820".parse().unwrap();
        let relu = decode(&encode(&c).unwrap()).unwrap();
        assert_eq!(relu.peer.unwrap().endpoint, Some(wg(&c).peer.endpoint.addr));
    }

    /// Un blob tronque ne doit pas produire une lecture hors bornes. Ce blob
    /// vient d'un driver noyau: le traiter comme sur serait deplacer la
    /// confiance au mauvais endroit.
    #[test]
    fn un_blob_tronque_est_refuse_sans_paniquer() {
        let blob = encode(&cfg()).unwrap();
        for taille in [0, 1, INTERFACE_SIZE, INTERFACE_SIZE + PEER_SIZE - 1] {
            assert!(decode(&blob[..taille]).is_err(), "taille {taille}");
        }
        // Decompte coherent mais prefixes absents: le cas ou seule la
        // verification du decompte protege.
        let ampute = &blob[..INTERFACE_SIZE + PEER_SIZE];
        assert!(decode(ampute).is_err());
    }

    #[test]
    fn un_pair_sans_prefixe_autorise_est_refuse() {
        let mut c = cfg();
        wg_mut(&mut c).peer.allowed_ips.clear();
        let err = match encode(&c) {
            Ok(_) => panic!("un pair sans prefixe doit etre refuse"),
            Err(e) => e.to_string(),
        };
        assert!(err.contains("prefixe"), "{err}");
    }
}
