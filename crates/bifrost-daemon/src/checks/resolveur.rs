//! Le versant manquant du vecteur `dns-leak`.
//!
//! `dns-leak` prouve qu'aucune requete DNS ne sort hors du tunnel. C'est une
//! moitie de propriete, et prise seule elle est trompeuse: un Bifrost dont la
//! resolution serait entierement CASSEE passerait ce vecteur avec les memes
//! zero paquet. Le harnais mesurait donc l'etancheite du DNS sans jamais
//! verifier qu'il restait du DNS.
//!
//! Deux doublures comblent l'ecart. `servir` repond aux requetes depuis le
//! bout du tunnel, `resoudre` en emet une en passant par la configuration
//! systeme que Bifrost vient de poser. Ensemble elles repondent a la question
//! que `dns-leak` ne pose pas: le tunnel monte et le kill switch arme, la
//! machine sait-elle encore traduire un nom.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::Duration;

/// Taille maximale d'une requete DNS sur UDP sans EDNS0.
const TAMPON: usize = 512;

/// Delai laisse a l'amont en mode relais. Court: sur le banc il est a deux
/// sauts, et une recette qui attend cache un blocage au lieu de le montrer.
const DELAI_AMONT: Duration = Duration::from_secs(3);

/// Duree de vie annoncee. Courte: aucune recette ne doit dependre d'un cache.
const TTL: u32 = 60;

/// Sert des reponses DNS jusqu'a ce qu'on la tue.
///
/// Un resolveur reel n'est pas necessaire ici et serait meme nuisible: le banc
/// n'a pas d'acces a Internet, et dependre de `dnsmasq` ou `unbound`
/// transformerait un vecteur de fuite en test de la distribution qui l'execute.
pub fn servir(
    ecoute: SocketAddr,
    adresse: Ipv4Addr,
    amont: Option<SocketAddr>,
) -> std::io::Result<()> {
    let socket = UdpSocket::bind(ecoute)?;
    match amont {
        Some(a) => eprintln!("faux resolveur sur {ecoute}, relaie vers {a}"),
        None => eprintln!("faux resolveur sur {ecoute}, repond {adresse} a tout nom"),
    }

    let mut tampon = [0u8; TAMPON];
    loop {
        let (recus, source) = socket.recv_from(&mut tampon)?;
        let sortie = match amont {
            // Mode relais: la forme de dnscrypt-proxy, moins le chiffrement.
            // Ce que le banc a besoin d'eprouver n'est pas DoH, dont les
            // auteurs de dnscrypt-proxy repondent, mais la PLOMBERIE autour:
            // les applications interrogent la boucle locale, le resolveur seul
            // a le droit d'emettre du :53, et sa requete part par le tunnel.
            Some(a) => relayer(&tampon[..recus], a).ok(),
            None => reponse(&tampon[..recus], adresse),
        };
        match sortie {
            Some(r) => {
                let _ = socket.send_to(&r, source);
            }
            // Se taire ici rendrait une requete mal formee indiscernable d'une
            // requete jamais arrivee, et le harnais conclurait a une fuite
            // bloquee la ou il y a un bogue de doublure.
            None => eprintln!("requete sans reponse, source {source}, {recus} octet(s)"),
        }
    }
}

/// Transmet la requete a l'amont et rend sa reponse.
///
/// C'est cette socket-la que le kill switch regarde: elle emet un :53 depuis
/// le compte du resolveur, et elle est la seule de la machine qui en ait le
/// droit une fois la restriction posee.
fn relayer(requete: &[u8], amont: SocketAddr) -> std::io::Result<Vec<u8>> {
    let liaison = if amont.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(liaison)?;
    socket.set_read_timeout(Some(DELAI_AMONT))?;
    socket.send_to(requete, amont)?;
    let mut tampon = [0u8; TAMPON];
    let recus = socket.recv(&mut tampon)?;
    Ok(tampon[..recus].to_vec())
}

/// Fabrique une requete A pour `nom`.
///
/// Publique parce que le harnais interroge un serveur PRECIS avec, sans passer
/// par la configuration systeme: c'est la seule facon de mesurer si le kill
/// switch laisse un processus donne emettre un :53 vers une destination
/// donnee.
pub fn requete_a(nom: &str, identifiant: u16) -> Vec<u8> {
    let mut q = Vec::new();
    q.extend_from_slice(&identifiant.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00]); // recursion demandee
    q.extend_from_slice(&[0x00, 0x01, 0, 0, 0, 0, 0, 0]);
    for etiquette in nom.split('.').filter(|e| !e.is_empty()) {
        q.push(etiquette.len() as u8);
        q.extend_from_slice(etiquette.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&1u16.to_be_bytes()); // type A
    q.extend_from_slice(&1u16.to_be_bytes()); // classe IN
    q
}

/// Interroge un serveur DNS PRECIS, en contournant la configuration systeme.
///
/// Le pendant negatif de [`resoudre`]. Celui-la demande "la machine sait-elle
/// resoudre"; celui-ci demande "ce processus-ci peut-il joindre ce
/// serveur-la", qui est la question que pose le kill switch.
pub fn interroger(serveur: SocketAddr, nom: &str) -> std::io::Result<Vec<u8>> {
    relayer(&requete_a(nom, 0x4242), serveur)
}

/// Resout un nom par la configuration systeme, et rend les adresses obtenues.
///
/// `to_socket_addrs` passe par `getaddrinfo`, donc par `/etc/resolv.conf` ou
/// par systemd-resolved selon ce que la machine utilise. C'est exactement le
/// point: la question n'est pas "un resolveur choisi par le harnais
/// repond-il", mais "la machine, telle que Bifrost l'a laissee, sait-elle
/// encore resoudre un nom".
pub fn resoudre(nom: &str) -> std::io::Result<Vec<IpAddr>> {
    Ok((nom, 0u16).to_socket_addrs()?.map(|s| s.ip()).collect())
}

/// Fin de la section question, ou `None` si la requete est illisible.
fn fin_de_la_question(requete: &[u8]) -> Option<usize> {
    let mut i = 12; // juste apres l'entete
    loop {
        let longueur = *requete.get(i)? as usize;
        if longueur == 0 {
            i += 1;
            break;
        }
        // Un pointeur de compression dans une QUESTION ne se rencontre pas en
        // pratique. On refuse plutot que de deviner: une doublure qui accepte
        // ce qu'elle ne comprend pas repond n'importe quoi.
        if longueur & 0xC0 != 0 {
            return None;
        }
        i += 1 + longueur;
    }
    // qtype et qclass suivent le nom.
    if requete.len() < i + 4 {
        return None;
    }
    Some(i + 4)
}

/// Fabrique la reponse a `requete`, ou `None` si elle est illisible.
///
/// Fonction pure, comme le ruleset nftables et les commandes resolvectl: ce
/// que la doublure repond se verifie en test, sans socket ni banc.
pub fn reponse(requete: &[u8], adresse: Ipv4Addr) -> Option<Vec<u8>> {
    if requete.len() < 12 {
        return None;
    }
    let fin = fin_de_la_question(requete)?;
    let qtype = u16::from_be_bytes([requete[fin - 4], requete[fin - 3]]);

    // Seul le type A recoit un enregistrement. Un AAAA repondu NOERROR avec
    // zero reponse fait retomber getaddrinfo sur l'IPv4, ce qui est le
    // comportement voulu sur un banc dont le tunnel ne porte pas d'IPv6.
    // Repondre une erreur, au contraire, ferait echouer toute la resolution.
    let repond = qtype == 1;

    let mut r = Vec::with_capacity(fin + 16);
    r.extend_from_slice(&requete[..2]); // meme identifiant que la requete
    r.extend_from_slice(&[0x81, 0x80]); // reponse, recursion demandee et offerte
    r.extend_from_slice(&[0x00, 0x01]); // une question
    r.extend_from_slice(&[0x00, u8::from(repond)]); // zero ou une reponse
    r.extend_from_slice(&[0, 0, 0, 0]); // ni autorite ni additionnel
    r.extend_from_slice(&requete[12..fin]); // la question, recopiee telle quelle

    if repond {
        r.extend_from_slice(&[0xC0, 0x0C]); // pointeur vers le nom de la question
        r.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // type A, classe IN
        r.extend_from_slice(&TTL.to_be_bytes());
        r.extend_from_slice(&4u16.to_be_bytes()); // longueur de l'adresse
        r.extend_from_slice(&adresse.octets());
    }
    Some(r)
}

/// Ce qu'une reponse DNS porte reellement: son code de retour, et les adresses
/// v4 utilisables qu'elle contient.
///
/// Ecrit pour une question a laquelle nslookup ne sait pas repondre: un nom
/// a-t-il ete REFUSE, ou simplement pas resolu? Et surtout, ecrit pour ne pas
/// avoir a lire la sortie d'un outil systeme. Mesure du 22/08/2026 sur
/// essai-windows: le meme `nslookup` qui rend des chaines anglaises sous le
/// compte SYSTEME rend "Reponse ne faisant pas autorite" sous une session
/// ordinaire. Une recette qui cherche un mot dans cette sortie mesure la
/// langue de la machine.
///
/// `0.0.0.0` est ECARTEE des adresses rendues: c'est une des reponses qu'un
/// resolveur filtrant sert pour un nom refuse, et la compter comme une
/// resolution reussie ferait passer un blocage pour un echec de blocage.
pub fn verdict(reponse: &[u8]) -> Option<(u8, Vec<Ipv4Addr>)> {
    if reponse.len() < 12 {
        return None;
    }
    let rcode = reponse[3] & 0x0F;
    let reponses = u16::from_be_bytes([reponse[6], reponse[7]]);
    let mut i = fin_de_la_question(reponse)?;

    let mut adresses = Vec::new();
    for _ in 0..reponses {
        // Le nom d'un enregistrement est soit un pointeur de compression sur
        // deux octets, soit une suite d'etiquettes. Les deux se rencontrent.
        if *reponse.get(i)? & 0xC0 == 0xC0 {
            i += 2;
        } else {
            loop {
                let longueur = *reponse.get(i)? as usize;
                i += 1 + longueur;
                if longueur == 0 {
                    break;
                }
            }
        }
        let rtype = u16::from_be_bytes([*reponse.get(i)?, *reponse.get(i + 1)?]);
        let longueur = u16::from_be_bytes([*reponse.get(i + 8)?, *reponse.get(i + 9)?]) as usize;
        i += 10;
        if rtype == 1 && longueur == 4 {
            let o = reponse.get(i..i + 4)?;
            let adresse = Ipv4Addr::new(o[0], o[1], o[2], o[3]);
            if !adresse.is_unspecified() {
                adresses.push(adresse);
            }
        }
        i += longueur;
    }
    Some((rcode, adresses))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SERVIE: Ipv4Addr = Ipv4Addr::new(10, 99, 9, 42);

    /// Requete pour `bifrost.test`, avec l'identifiant et le type donnes.
    fn requete(identifiant: u16, qtype: u16) -> Vec<u8> {
        let mut q = requete_a("bifrost.test", identifiant);
        let fin = q.len();
        q[fin - 4..fin - 2].copy_from_slice(&qtype.to_be_bytes());
        q
    }

    fn nombre_de_reponses(r: &[u8]) -> u16 {
        u16::from_be_bytes([r[6], r[7]])
    }

    /// Aller-retour: ce que la doublure ecrit, le lecteur le relit. Sans ce
    /// couple, `verdict` ne serait juge par rien, et il sert a decider si un
    /// nom de telemetrie est reellement refuse.
    #[test]
    fn le_verdict_relit_ce_que_la_doublure_a_ecrit() {
        let r = reponse(&requete(0x1234, 1), SERVIE).unwrap();
        assert_eq!(verdict(&r), Some((0, vec![SERVIE])));
    }

    /// Une reponse sans enregistrement: le cas d'un nom refuse.
    #[test]
    fn une_reponse_vide_ne_rend_aucune_adresse() {
        let r = reponse(&requete(1, 28), SERVIE).unwrap();
        assert_eq!(verdict(&r), Some((0, Vec::new())));
    }

    /// `0.0.0.0` est une facon de dire non, pas une adresse joignable. La
    /// compter ferait passer un blocage reussi pour un blocage rate.
    #[test]
    fn l_adresse_nulle_ne_compte_pas_comme_une_resolution() {
        let r = reponse(&requete(1, 1), Ipv4Addr::UNSPECIFIED).unwrap();
        let (rcode, adresses) = verdict(&r).unwrap();
        assert_eq!(rcode, 0);
        assert!(adresses.is_empty(), "0.0.0.0 comptee comme resolution");
    }

    #[test]
    fn une_reponse_tronquee_ne_fait_pas_paniquer_le_lecteur() {
        let r = reponse(&requete(1, 1), SERVIE).unwrap();
        for coupe in 0..r.len() {
            let _ = verdict(&r[..coupe]);
        }
    }

    #[test]
    fn une_requete_a_recoit_l_adresse_servie() {
        let r = reponse(&requete(0x1234, 1), SERVIE).expect("requete lisible");
        assert_eq!(nombre_de_reponses(&r), 1);
        assert_eq!(
            &r[r.len() - 4..],
            &SERVIE.octets(),
            "l'adresse servie n'est pas en fin de reponse"
        );
    }

    /// Un client qui ne retrouve pas son identifiant jette la reponse et
    /// attend jusqu'a expiration. Le symptome serait une resolution qui
    /// echoue lentement, sans que rien ne signale la doublure.
    #[test]
    fn l_identifiant_de_la_requete_est_repris() {
        let r = reponse(&requete(0xBEEF, 1), SERVIE).unwrap();
        assert_eq!(&r[..2], &[0xBE, 0xEF]);
    }

    /// La question doit revenir a l'identique: un client qui ne s'y retrouve
    /// pas traite la reponse comme sans rapport avec sa requete.
    #[test]
    fn la_question_est_recopiee_telle_quelle() {
        let q = requete(1, 1);
        let r = reponse(&q, SERVIE).unwrap();
        assert_eq!(&r[12..q.len()], &q[12..]);
    }

    /// Repondre NXDOMAIN a un AAAA ferait echouer toute la resolution, y
    /// compris la partie IPv4 que le banc sait servir.
    #[test]
    fn une_requete_aaaa_recoit_une_reponse_vide_et_non_une_erreur() {
        let r = reponse(&requete(1, 28), SERVIE).unwrap();
        assert_eq!(nombre_de_reponses(&r), 0, "un AAAA ne doit rien renvoyer");
        assert_eq!(r[3] & 0x0F, 0, "le code de retour doit rester NOERROR");
    }

    #[test]
    fn une_requete_tronquee_ne_produit_pas_de_reponse() {
        let q = requete(1, 1);
        assert!(reponse(&q[..8], SERVIE).is_none(), "entete incomplet");
        assert!(reponse(&q[..15], SERVIE).is_none(), "nom incomplet");
        assert!(
            reponse(&q[..q.len() - 2], SERVIE).is_none(),
            "qclass absent"
        );
    }

    /// Une etiquette dont le premier octet a les bits de poids fort a 1 est un
    /// pointeur de compression. Accepte tel quel, il serait lu comme une
    /// longueur et la doublure repondrait sur un nom qui n'existe pas.
    #[test]
    fn un_pointeur_de_compression_est_refuse() {
        let mut q = requete(1, 1);
        q[12] = 0xC0;
        assert!(reponse(&q, SERVIE).is_none());
    }
}
