//! Emetteurs de trafic utilises par le harnais de fuite.
//!
//! Le harnais a besoin d'un processus qui tente activement de fuir: envoyer une
//! requete DNS a un resolveur public, joindre une IP hors tunnel, emettre de
//! l'IPv6. Plutot que de dependre de `dig`, `curl` ou du `/dev/udp` de bash, le
//! daemon sait le faire lui-meme via le sous-commande cachee `--probe`.
//!
//! Aucune sonde n'echoue: quand le kill switch fonctionne, l'echec d'emission
//! est precisement le resultat attendu. Ce qui est mesure, c'est ce qui
//! apparait dans la capture, pas ce que la sonde croit avoir fait.
//!
//! Elles ne se TAISENT pas pour autant. Chaque echec part sur la sortie
//! d'erreur, que le harnais rattache a l'observation. Sans cela, une capture
//! vide a deux lectures indiscernables: le trafic a ete bloque, ou il n'a
//! jamais ete emis. La premiere est un succes, la seconde un test qui ne
//! prouve rien, et le verdict n'a pas le droit de les confondre.

use std::io::Write;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, UdpSocket};
use std::str::FromStr;
use std::time::Duration;

/// Delai laisse a chaque tentative. Court: on veut que le paquet parte (ou
/// soit bloque), pas attendre une reponse.
const TIMEOUT: Duration = Duration::from_millis(300);

/// Destinations utilisees par les sondes. Ce sont des adresses de
/// documentation (RFC 5737 et RFC 3849): elles ne sont routees nulle part, donc
/// une sonde qui s'echappe reellement ne derange personne.
pub const PROBE_V4: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 9);
pub const PROBE_V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
/// Resolveur public: cible realiste d'une fuite DNS.
pub const PROBE_DNS: Ipv4Addr = Ipv4Addr::new(8, 8, 8, 8);
/// Port vise par la sonde du lien.
///
/// Sans service en face, et c'est sans importance: ce qui est mesure est le
/// paquet qui QUITTE la machine, pas ce qu'on en fait a l'arrivee. Un port haut
/// et improbable plutot qu'un port connu, pour qu'un voisin qui ecouterait par
/// hasard ne recoive rien qu'il puisse interpreter.
const PORT_LAN: u16 = 9999;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Probe {
    /// Requete DNS en UDP et en TCP vers un resolveur public.
    Dns,
    /// Trafic IPv4 quelconque vers une destination hors tunnel.
    Ipv4,
    /// Trafic IPv6 vers une destination hors tunnel.
    Ipv6,
    /// Les trois ci-dessus.
    All,
}

impl FromStr for Probe {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "dns" => Ok(Probe::Dns),
            "ipv4" => Ok(Probe::Ipv4),
            "ipv6" => Ok(Probe::Ipv6),
            "all" => Ok(Probe::All),
            other => Err(format!("sonde inconnue: {other}")),
        }
    }
}

impl Probe {
    pub fn as_str(&self) -> &'static str {
        match self {
            Probe::Dns => "dns",
            Probe::Ipv4 => "ipv4",
            Probe::Ipv6 => "ipv6",
            Probe::All => "all",
        }
    }
}

/// Emet la sonde. Ne renvoie jamais d'erreur: seul le pcap fait foi.
pub fn emit(probe: Probe) {
    match probe {
        Probe::Dns => emit_dns(),
        Probe::Ipv4 => emit_ipv4(),
        Probe::Ipv6 => emit_ipv6(),
        Probe::All => {
            emit_dns();
            emit_ipv4();
            emit_ipv6();
        }
    }
}

/// Une requete DNS minimale mais bien formee pour `example.com` de type A.
///
/// Un paquet bien forme plutot que des octets arbitraires: un analyseur de
/// capture qui filtre sur le port 53 verra la meme chose, mais une trace lue
/// par un humain reste interpretable.
fn dns_query() -> Vec<u8> {
    let mut q = vec![
        0x12, 0x34, // transaction id
        0x01, 0x00, // recursion desiree
        0x00, 0x01, // 1 question
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    for label in ["example", "com"] {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0x00);
    q.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // type A, classe IN
    q
}

fn emit_dns() {
    let dst = SocketAddr::from((PROBE_DNS, 53));
    if let Ok(sock) = UdpSocket::bind("0.0.0.0:0") {
        let _ = sock.set_write_timeout(Some(TIMEOUT));
        let _ = sock.send_to(&dns_query(), dst);
    }
    // Le DNS sur TCP est un vecteur de fuite a part entiere: un resolveur qui
    // bascule en TCP sur reponse tronquee contourne un filtre UDP seul.
    if let Ok(mut stream) = TcpStream::connect_timeout(&dst, TIMEOUT) {
        let query = dns_query();
        let mut framed = (query.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(&query);
        let _ = stream.set_write_timeout(Some(TIMEOUT));
        let _ = stream.write_all(&framed);
    }
}

/// Signale un echec d'emission sans faire echouer la sonde.
fn signaler(quoi: &str, e: &std::io::Error) {
    eprintln!("sonde {quoi}: {e}");
}

fn emit_ipv4() {
    match UdpSocket::bind("0.0.0.0:0") {
        Ok(sock) => {
            let _ = sock.set_write_timeout(Some(TIMEOUT));
            if let Err(e) = sock.send_to(b"bifrost-probe", SocketAddr::from((PROBE_V4, 1234))) {
                signaler("udp v4", &e);
            }
        }
        Err(e) => signaler("bind udp v4", &e),
    }
    if let Err(e) = TcpStream::connect_timeout(&SocketAddr::from((PROBE_V4, 80)), TIMEOUT) {
        signaler("tcp v4", &e);
    }
}

fn emit_ipv6() {
    if let Ok(sock) = UdpSocket::bind("[::]:0") {
        let _ = sock.set_write_timeout(Some(TIMEOUT));
        let _ = sock.send_to(b"bifrost-probe", SocketAddr::from((PROBE_V6, 1234)));
    }
    let _ = TcpStream::connect_timeout(&SocketAddr::from((PROBE_V6, 80)), TIMEOUT);
}

/// Emet du trafic vers un VOISIN DU LIEN, hors tunnel.
///
/// Le contraire de [`emit_through_tunnel`] par sa destination: celle-ci est
/// on-link, donc sa route ne passe PAS par le tunnel meme quand l'aiguillage du
/// produit est en place. `suppress_prefixlength 0` ne supprime que le prefixe
/// par defaut de la table principale et laisse vivre les routes de lien: le
/// voisin reste joignable par la carte physique.
///
/// C'est ce qui en fait la sonde qui DISCRIMINE quand un kill switch tombe. Un
/// plan pose `allow_lan = false`: ce trafic doit etre refuse tant que les
/// filtres tiennent, et il repart en clair des qu'ils ne tiennent plus. Les
/// sondes de [`Probe::All`], elles, visent des destinations hors lien, dont la
/// route reste celle du tunnel: elles ne fuient pas en clair meme sans filtres,
/// et un vecteur qui n'aurait qu'elles ne verrait rien.
///
/// Mesure du 23/08/2026 sur la machine d'essai, unite systemd REELLE et
/// SIGKILL du daemon: 16 paquets sortants en clair sur l'interface physique,
/// tous vers le lien, zero vers Internet.
///
/// Comme les autres sondes, elle signale ses echecs d'emission au lieu de les
/// avaler: une capture vide dont on ne sait pas si la sonde a emis ne mesure
/// rien.
pub fn emit_lan(dst: Ipv4Addr) {
    match UdpSocket::bind("0.0.0.0:0") {
        Ok(sock) => {
            let _ = sock.set_write_timeout(Some(TIMEOUT));
            if let Err(e) = sock.send_to(b"bifrost-lan-probe", SocketAddr::from((dst, PORT_LAN))) {
                signaler("udp lan", &e);
            }
        }
        Err(e) => signaler("bind udp lan", &e),
    }
    if let Err(e) = TcpStream::connect_timeout(&SocketAddr::from((dst, PORT_LAN)), TIMEOUT) {
        signaler("tcp lan", &e);
    }
}

/// Emet du trafic vers une adresse joignable uniquement par le tunnel.
///
/// **Cette sonde ne prouve aucun transport, et rien ne doit le conclure d'elle.**
/// Elle emet en aveugle, sans destinataire qui accuse reception: un tunnel
/// dont l'endpoint est mort avale ces datagrammes exactement comme un tunnel
/// vivant les transporte. Son emploi est de PROVOQUER du trafic, pas de le
/// constater: reveiller une poignee de main, ou tenter de fuir pendant que le
/// tunnel est coupe, ou l'absence de reponse est precisement l'attendu.
///
/// Ce qui etablit qu'un tunnel transporte est la banniere de
/// [`super::transport`], lue a travers lui depuis une adresse qu'il est seul a
/// joindre, avec les compteurs du driver a l'appui.
///
/// Comme les autres sondes, elle signale ses echecs d'emission au lieu de les
/// avaler: une capture vide dont on ne sait pas si la sonde a emis ne mesure
/// rien.
pub fn emit_through_tunnel(dst: Ipv4Addr) {
    match UdpSocket::bind("0.0.0.0:0") {
        Ok(sock) => {
            let _ = sock.set_write_timeout(Some(TIMEOUT));
            for _ in 0..3 {
                if let Err(e) = sock.send_to(b"bifrost-tunnel-probe", SocketAddr::from((dst, 1234)))
                {
                    signaler("udp tunnel", &e);
                }
            }
        }
        Err(e) => signaler("bind udp tunnel", &e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn la_requete_dns_est_bien_formee() {
        let q = dns_query();
        // En-tete de 12 octets, puis 7example3com0, puis qtype et qclass.
        assert_eq!(q.len(), 12 + 1 + 7 + 1 + 3 + 1 + 4);
        assert_eq!(&q[0..2], &[0x12, 0x34]);
        assert_eq!(q[4..6], [0x00, 0x01], "une seule question");
        assert_eq!(&q[13..20], b"example");
        assert_eq!(q[q.len() - 4..], [0x00, 0x01, 0x00, 0x01]);
    }

    #[test]
    fn les_sondes_se_parsent_depuis_la_ligne_de_commande() {
        for name in ["dns", "ipv4", "ipv6", "all"] {
            assert_eq!(name.parse::<Probe>().unwrap().as_str(), name);
        }
        assert!("inconnue".parse::<Probe>().is_err());
    }

    /// Les destinations doivent rester des adresses de documentation: une
    /// sonde qui s'echappe ne doit atteindre aucun tiers reel.
    #[test]
    fn les_destinations_de_sonde_sont_non_routables() {
        assert_eq!(PROBE_V4.octets()[0..3], [203, 0, 113]); // RFC 5737 TEST-NET-3
        assert_eq!(PROBE_V6.segments()[0..2], [0x2001, 0x0db8]); // RFC 3849
    }
}
