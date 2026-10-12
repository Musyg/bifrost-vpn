//! Banc TLS de la boucle locale, partage par les recettes du repli classique.
//!
//! Inclus par `#[path = "commun/banc_tls.rs"]` dans `tests/repli_toile.rs`, et
//! par `#[path = "../tests/commun/banc_tls.rs"]` dans les recettes de
//! `src/inspection.rs`: un fichier sous `tests/commun/` n'est pas une cible de
//! test a lui seul.
//!
//! Un ecouteur TCP BRUT lit, sur chaque connexion, la charge utile TCP que le
//! client envoie jusqu'a un ClientHello complet, et le decode sans
//! bibliotheque TLS: groupes de `supported_groups` dans l'ordre, groupes
//! portes par `key_share`. C'est ce que le client a reellement emis. Ensuite
//! seulement, l'ecouteur suit sa [`Conduite`]: couper, se taire, envoyer une
//! alerte, ou servir une vraie poignee de main rustls avec un certificat
//! engendre pour la recette.
//!
//! Rien ne sort de la boucle locale: l'ecouteur est lie a `127.0.0.1`, port
//! choisi par le systeme et TENU par le banc jusqu'a la fin du processus.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Les groupes que les recettes nomment (IANA, TLS Supported Groups).
pub const X25519: u16 = 0x001d;
pub const SECP256R1: u16 = 0x0017;
pub const SECP384R1: u16 = 0x0018;
pub const X25519MLKEM768: u16 = 0x11ec;

/// Les groupes post-quantiques, purs ou hybrides, que rustls sait offrir.
pub fn est_post_quantique(groupe: u16) -> bool {
    matches!(groupe, 0x11eb | 0x11ec | 0x0200 | 0x0201 | 0x0202)
}

/// Ce qu'un ClientHello a annonce.
#[derive(Debug, Clone, Default)]
pub struct Hello {
    /// `supported_groups`, dans l'ordre.
    pub groupes: Vec<u16>,
    /// `key_share`: groupe et longueur de chaque part, dans l'ordre.
    pub parts: Vec<(u16, usize)>,
    /// Octets de charge utile TCP lus jusqu'au ClientHello complet.
    pub octets: usize,
}

impl Hello {
    /// Vrai si un groupe ou une part post-quantique y figure.
    pub fn offre_du_post_quantique(&self) -> bool {
        self.groupes.iter().any(|g| est_post_quantique(*g))
            || self.parts.iter().any(|(g, _)| est_post_quantique(*g))
    }
}

fn u16be(b: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(i)?, *b.get(i + 1)?]))
}

/// Decode un ClientHello a partir des enregistrements recus.
///
/// `Ok(None)` tant qu'il manque des octets, `Err` si ce n'est pas un
/// ClientHello TLS (une requete HTTP en clair, par exemple).
pub fn decoder(recu: &[u8]) -> Result<Option<Hello>, String> {
    let mut poignee: Vec<u8> = Vec::new();
    let mut i = 0;
    loop {
        if poignee.len() >= 4 {
            let l = (usize::from(poignee[1]) << 16)
                | (usize::from(poignee[2]) << 8)
                | usize::from(poignee[3]);
            if poignee.len() >= 4 + l {
                break;
            }
        }
        if recu.len() < i + 5 {
            return Ok(None);
        }
        if recu[i] != 22 {
            return Err(format!("enregistrement de type {} et non 22", recu[i]));
        }
        let l = usize::from(u16be(recu, i + 3).ok_or("en-tete")?);
        if recu.len() < i + 5 + l {
            return Ok(None);
        }
        poignee.extend_from_slice(&recu[i + 5..i + 5 + l]);
        i += 5 + l;
    }
    if poignee[0] != 1 {
        return Err(format!(
            "message de poignee {} et non ClientHello",
            poignee[0]
        ));
    }
    let l =
        (usize::from(poignee[1]) << 16) | (usize::from(poignee[2]) << 8) | usize::from(poignee[3]);
    let corps = &poignee[4..4 + l];
    let tronque = || "ClientHello tronque".to_string();
    let mut h = Hello {
        octets: recu.len(),
        ..Hello::default()
    };
    // legacy_version, random, session_id, cipher_suites, compression.
    let mut p = 2 + 32;
    p += 1 + usize::from(*corps.get(p).ok_or_else(tronque)?);
    p += 2 + usize::from(u16be(corps, p).ok_or_else(tronque)?);
    p += 1 + usize::from(*corps.get(p).ok_or_else(tronque)?);
    let total = usize::from(u16be(corps, p).ok_or_else(tronque)?);
    p += 2;
    let fin = p + total;
    while p < fin {
        let genre = u16be(corps, p).ok_or_else(tronque)?;
        let long = usize::from(u16be(corps, p + 2).ok_or_else(tronque)?);
        let donnees = corps.get(p + 4..p + 4 + long).ok_or_else(tronque)?;
        match genre {
            0x000a => {
                let liste = usize::from(u16be(donnees, 0).ok_or_else(tronque)?);
                let mut q = 2;
                while q < 2 + liste {
                    h.groupes.push(u16be(donnees, q).ok_or_else(tronque)?);
                    q += 2;
                }
            }
            0x0033 => {
                let liste = usize::from(u16be(donnees, 0).ok_or_else(tronque)?);
                let mut q = 2;
                while q < 2 + liste {
                    let groupe = u16be(donnees, q).ok_or_else(tronque)?;
                    let part = usize::from(u16be(donnees, q + 2).ok_or_else(tronque)?);
                    h.parts.push((groupe, part));
                    q += 4 + part;
                }
            }
            _ => {}
        }
        p += 4 + long;
    }
    Ok(Some(h))
}

/// Ce que l'ecouteur fait d'une connexion, une fois son ClientHello lu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Conduite {
    /// Ferme (FIN) si le ClientHello offre du post-quantique, sert une vraie
    /// poignee rustls sinon: le boitier intolerant que le repli contourne.
    CoupeSiPostQuantique,
    /// Ferme (FIN) a chaque ClientHello.
    CoupeToujours,
    /// Garde la connexion ouverte sans rien envoyer.
    Silence,
    /// Envoie une alerte fatale `handshake_failure`.
    Alerte,
    /// Sert une vraie poignee rustls, quel que soit le ClientHello.
    Sert,
    /// Envoie le seul ServerHello d'une vraie poignee rustls, puis ferme (FIN).
    ServerHelloPuisCoupe,
}

/// Le nom que porte le certificat engendre du banc.
pub const NOM: &str = "essai.repli.test";

/// Un serveur rustls de recette, a certificat auto-signe engendre ici.
///
/// Le fournisseur est celui que les features du depot donnent a rustls.
pub fn configuration_serveur() -> Arc<rustls::ServerConfig> {
    let engendre = rcgen::generate_simple_self_signed(vec![NOM.to_owned()]).expect("rcgen");
    let certificat = rustls::pki_types::CertificateDer::from(engendre.cert.der().to_vec());
    let clef = rustls::pki_types::PrivateKeyDer::try_from(engendre.signing_key.serialize_der())
        .expect("clef du banc");
    let fournisseur = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    Arc::new(
        rustls::ServerConfig::builder_with_provider(fournisseur)
            .with_safe_default_protocol_versions()
            .expect("versions")
            .with_no_client_auth()
            .with_single_cert(vec![certificat], clef)
            .expect("certificat du banc"),
    )
}

/// Un ecouteur de la boucle locale et ce qu'il a vu, connexion par connexion.
pub struct Banc {
    pub adresse: SocketAddr,
    vus: Arc<Mutex<Vec<Option<Hello>>>>,
}

impl Banc {
    /// Monte l'ecouteur. Il vit jusqu'a la fin du processus: le fil est
    /// detache, et un client qui ne rendrait pas la main ne fait pas pendre
    /// les autres recettes.
    pub fn monter(conduite: Conduite) -> Banc {
        let ecoute = TcpListener::bind("127.0.0.1:0").expect("la boucle locale doit etre libre");
        let adresse = ecoute.local_addr().expect("adresse de l'ecouteur");
        let vus: Arc<Mutex<Vec<Option<Hello>>>> = Arc::default();
        let partage = vus.clone();
        let configuration = configuration_serveur();
        std::thread::spawn(move || {
            for flux in ecoute.incoming() {
                let Ok(flux) = flux else { break };
                // La connexion est comptee a l'acceptation, avant toute
                // lecture: un client qui ne parlerait pas compte quand meme.
                let rang = {
                    let mut v = partage.lock().expect("verrou du banc");
                    v.push(None);
                    v.len() - 1
                };
                let partage = partage.clone();
                let configuration = configuration.clone();
                std::thread::spawn(move || {
                    conduire(flux, conduite, &configuration, &partage, rang);
                });
            }
        });
        Banc { adresse, vus }
    }

    /// Les ClientHello vus, dans l'ordre des connexions, apres un temps de
    /// grace qui laisse aux fils de l'ecouteur le temps de noter une connexion
    /// tardive: un troisieme essai ne doit pas passer inapercu.
    pub fn vus(&self) -> Vec<Option<Hello>> {
        std::thread::sleep(Duration::from_millis(400));
        self.vus.lock().expect("verrou du banc").clone()
    }
}

/// Lit jusqu'a un ClientHello complet. Rend aussi les octets bruts.
fn lire_hello(flux: &mut TcpStream) -> Option<(Hello, Vec<u8>)> {
    let _ = flux.set_read_timeout(Some(Duration::from_secs(10)));
    let mut recu = Vec::new();
    let mut tampon = [0u8; 4096];
    loop {
        match decoder(&recu) {
            Ok(Some(h)) => return Some((h, recu)),
            Ok(None) => {}
            Err(_) => return None,
        }
        match flux.read(&mut tampon) {
            Ok(0) | Err(_) => return None,
            Ok(n) => recu.extend_from_slice(&tampon[..n]),
        }
    }
}

/// Lit ce que le client envoie encore, peu de temps, pour fermer par un FIN et
/// non par un RST (des octets non lus a la fermeture font repondre un RST).
fn vider(flux: &mut TcpStream) {
    let _ = flux.set_read_timeout(Some(Duration::from_millis(300)));
    let mut tampon = [0u8; 4096];
    while let Ok(n) = flux.read(&mut tampon) {
        if n == 0 {
            break;
        }
    }
}

/// Un serveur rustls qui a deja lu ce ClientHello.
fn serveur(
    configuration: &Arc<rustls::ServerConfig>,
    hello: &[u8],
) -> Option<rustls::ServerConnection> {
    let mut serveur = rustls::ServerConnection::new(configuration.clone()).ok()?;
    let mut entree = hello;
    while !entree.is_empty() {
        serveur.read_tls(&mut entree).ok()?;
    }
    serveur.process_new_packets().ok()?;
    Some(serveur)
}

fn conduire(
    mut flux: TcpStream,
    conduite: Conduite,
    configuration: &Arc<rustls::ServerConfig>,
    vus: &Arc<Mutex<Vec<Option<Hello>>>>,
    rang: usize,
) {
    let Some((hello, brut)) = lire_hello(&mut flux) else {
        return;
    };
    let post_quantique = hello.offre_du_post_quantique();
    vus.lock().expect("verrou du banc")[rang] = Some(hello);
    match conduite {
        Conduite::CoupeToujours => {}
        Conduite::CoupeSiPostQuantique if post_quantique => {}
        Conduite::Silence => std::thread::sleep(Duration::from_secs(10)),
        Conduite::Alerte => {
            let _ = flux.write_all(&[21, 3, 3, 0, 2, 2, 40]);
            vider(&mut flux);
        }
        Conduite::Sert | Conduite::CoupeSiPostQuantique => {
            if let Some(mut serveur) = serveur(configuration, &brut) {
                let _ = flux.set_read_timeout(Some(Duration::from_secs(10)));
                // Jusqu'au bout de la poignee, ou jusqu'a l'alerte du client
                // qui refuse le certificat.
                let _ = serveur.complete_io(&mut flux);
                vider(&mut flux);
            }
        }
        Conduite::ServerHelloPuisCoupe => {
            if let Some(mut serveur) = serveur(configuration, &brut) {
                let mut volee = Vec::new();
                while serveur.wants_write() {
                    if serveur.write_tls(&mut volee).is_err() {
                        break;
                    }
                }
                let longueur = usize::from(u16::from_be_bytes([volee[3], volee[4]]));
                let _ = flux.write_all(&volee[..5 + longueur]);
                vider(&mut flux);
            }
        }
    }
    drop(flux);
}
