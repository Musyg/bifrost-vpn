//! Collecte Linux strictement passive: GETGEN, nft list ruleset, GETGEN.
//! Ni elevation, ni shell, ni recherche de programme dans le PATH.

use std::future::Future;
use std::path::Path;
use std::process::Stdio;
use std::time::{Duration, Instant};

use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_NETFILTER};
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tokio::time::timeout;

const MAX_OCTETS: u64 = 2 * 1024 * 1024;
const NFT_ARGS: &[&str] = &["--json", "--numeric", "list", "ruleset"];
// UAPI Linux: sous-systeme NFTABLES 10, GETGEN 16 et NEWGEN 15.
const GETGEN: u16 = 0x0a10;
const NEWGEN: u16 = 0x0a0f;
const SEQUENCE: u32 = 1;
const ACCES: &str = "acces noyau refuse; aucune elevation automatique";

fn erreur_io(e: std::io::Error) -> &'static str {
    if e.kind() == std::io::ErrorKind::PermissionDenied {
        ACCES
    } else {
        "lecture netlink impossible"
    }
}

fn requete(port: u32) -> [u8; 20] {
    let mut v = [0_u8; 20];
    v[..4].copy_from_slice(&20_u32.to_ne_bytes());
    v[4..6].copy_from_slice(&GETGEN.to_ne_bytes());
    v[6..8].copy_from_slice(&1_u16.to_ne_bytes()); // NLM_F_REQUEST, sans mutation ni dump
    v[8..12].copy_from_slice(&SEQUENCE.to_ne_bytes());
    v[12..16].copy_from_slice(&port.to_ne_bytes());
    // nfgenmsg: AF_UNSPEC, version 0, res_id 0.
    v
}

fn generation_recue(data: &[u8], expediteur: u32, port: u32) -> Result<u32, &'static str> {
    if expediteur != 0 || data.len() < 20 {
        return Err("reponse netlink non authentifiee ou tronquee");
    }
    let taille = u32::from_ne_bytes(data[..4].try_into().unwrap()) as usize;
    let genre = u16::from_ne_bytes(data[4..6].try_into().unwrap());
    let flags = u16::from_ne_bytes(data[6..8].try_into().unwrap());
    let sequence = u32::from_ne_bytes(data[8..12].try_into().unwrap());
    let destination = u32::from_ne_bytes(data[12..16].try_into().unwrap());
    if taille != data.len() || sequence != SEQUENCE || destination != port {
        return Err("enveloppe netlink inattendue");
    }
    if genre == 2 {
        // NLMSG_ERROR; un ACK sans generation ne suffit pas.
        // Les noyaux peuvent signaler CAPPED / ACK_TLVS sur une erreur.
        if flags & !0x300 != 0 {
            return Err("flags netlink inconnus");
        }
        let code = i32::from_ne_bytes(data[16..20].try_into().unwrap());
        return Err(if code == -1 || code == -13 {
            ACCES
        } else {
            "generation noyau indisponible"
        });
    }
    if genre != NEWGEN || flags != 0 || data[16] != 0 || data[17] != 0 {
        return Err("type de reponse netlink inconnu");
    }
    let mut id = None;
    let mut offset = 20;
    while offset < data.len() {
        if data.len() - offset < 4 {
            return Err("attribut netlink tronque");
        }
        let n = u16::from_ne_bytes(data[offset..offset + 2].try_into().unwrap()) as usize;
        let genre = u16::from_ne_bytes(data[offset + 2..offset + 4].try_into().unwrap());
        if n < 4 || n > data.len() - offset {
            return Err("longueur netlink invalide");
        }
        if genre & 0x3fff == 1 {
            // NFTA_GEN_ID, entier big-endian (UAPI).
            if n != 8 || id.is_some() || genre & 0x8000 != 0 {
                return Err("generation dupliquee ou mal formee");
            }
            id = Some(u32::from_be_bytes(
                data[offset + 4..offset + 8].try_into().unwrap(),
            ));
        }
        offset += (n + 3) & !3;
        if offset > data.len() {
            return Err("alignement netlink invalide");
        }
    }
    id.ok_or("generation absente")
}

fn generation() -> Result<u32, &'static str> {
    let mut socket = Socket::new(NETLINK_NETFILTER).map_err(erreur_io)?;
    let adresse = socket.bind_auto().map_err(erreur_io)?;
    socket.connect(&SocketAddr::new(0, 0)).map_err(erreur_io)?;
    socket.set_non_blocking(true).map_err(erreur_io)?;
    let demande = requete(adresse.port_number());
    if socket.send(&demande, 0).map_err(erreur_io)? != demande.len() {
        return Err("requete netlink incomplete");
    }
    let debut = Instant::now();
    loop {
        if debut.elapsed() >= Duration::from_secs(1) {
            return Err("delai netlink depasse");
        }
        let mut tampon = [0_u8; 4096];
        // MSG_TRUNC (UAPI Linux 0x20): connaitre la taille reelle sans allouer
        // selon une longueur recue. Refuser plutot qu'accepter un prefixe.
        match socket.recv_from(&mut &mut tampon[..], 0x20) {
            Ok((n, source)) => {
                if n > tampon.len() {
                    return Err("reponse netlink trop grande");
                }
                return generation_recue(&tampon[..n], source.port_number(), adresse.port_number());
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5))
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(erreur_io(e)),
        }
    }
}

async fn lire_commande(
    programme: &Path,
    args: &[&str],
    delai: Duration,
    limite: u64,
) -> Result<Vec<u8>, &'static str> {
    let mut enfant = Command::new(programme)
        .args(args)
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| "nft absent ou impossible a lancer")?;
    let sortie = enfant.stdout.take().ok_or("sortie nft indisponible")?;
    let resultat = timeout(delai, async {
        let mut octets = Vec::new();
        sortie
            .take(limite + 1)
            .read_to_end(&mut octets)
            .await
            .map_err(|_| "lecture nft incomplete")?;
        if octets.len() as u64 > limite {
            return Err("capture nft trop grande");
        }
        let code = enfant.wait().await.map_err(|_| "attente nft impossible")?;
        if !code.success() {
            return Err("nft a refuse ou echoue; aucune regle appliquee");
        }
        Ok(octets)
    })
    .await
    .unwrap_or(Err("delai nft depasse"));
    if resultat.is_err() {
        // Ne tuer que NOTRE enfant, jamais nft par nom ni un service tiers.
        let _ = enfant.start_kill();
        let _ = timeout(Duration::from_secs(1), enfant.wait()).await;
    }
    resultat
}

async fn encadrer<G, F, Fut>(mut lire_generation: G, dump: F) -> Result<Vec<u8>, &'static str>
where
    G: FnMut() -> Result<u32, &'static str>,
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<Vec<u8>, &'static str>>,
{
    let avant = lire_generation()?;
    let octets = dump().await?;
    let apres = lire_generation()?;
    if avant != apres {
        return Err("generation nft modifiee pendant la collecte");
    }
    Ok(octets)
}

pub async fn collecter() -> Result<Vec<u8>, &'static str> {
    let nft = ["/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft", "/bin/nft"]
        .into_iter()
        .map(Path::new)
        .find(|p| p.is_file())
        .ok_or("nft absent des emplacements systeme")?;
    encadrer(generation, || {
        lire_commande(nft, NFT_ARGS, Duration::from_secs(5), MAX_OCTETS)
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reponse(id: u32) -> Vec<u8> {
        let mut v = requete(42).to_vec();
        v[..4].copy_from_slice(&28_u32.to_ne_bytes());
        v[4..6].copy_from_slice(&NEWGEN.to_ne_bytes());
        v[6..8].copy_from_slice(&0_u16.to_ne_bytes());
        v.extend_from_slice(&8_u16.to_ne_bytes());
        v.extend_from_slice(&1_u16.to_ne_bytes());
        v.extend_from_slice(&id.to_be_bytes());
        v
    }

    #[test]
    fn generation_big_endian_et_enveloppe_stricte() {
        let v = reponse(0x12345678);
        assert_eq!(generation_recue(&v, 0, 42), Ok(0x12345678));
        assert!(generation_recue(&v, 9, 42).is_err());
        assert!(generation_recue(&v, 0, 41).is_err());
        for n in 0..v.len() {
            assert!(generation_recue(&v[..n], 0, 42).is_err());
        }
        for offset in [4, 6, 8, 17, 20, 22] {
            let mut casse = v.clone();
            casse[offset] ^= 1;
            assert!(generation_recue(&casse, 0, 42).is_err());
        }
        let mut double = v.clone();
        double.extend_from_slice(&v[20..]);
        double[..4].copy_from_slice(&36_u32.to_ne_bytes());
        assert!(generation_recue(&double, 0, 42).is_err());
    }

    #[test]
    fn acces_refuse_et_ack_ne_deviennent_pas_une_generation() {
        for code in [-1_i32, -13, 0, -95] {
            let mut v = requete(42).to_vec();
            v[4..6].copy_from_slice(&2_u16.to_ne_bytes());
            v[6..8].copy_from_slice(&0_u16.to_ne_bytes());
            v[16..20].copy_from_slice(&code.to_ne_bytes());
            assert!(generation_recue(&v, 0, 42).is_err());
        }
    }

    #[tokio::test]
    async fn changement_et_echec_de_generation_invalident_la_capture() {
        for fin in [Ok(8), Err("refus")] {
            let mut g = [Ok(7), fin].into_iter();
            assert!(
                encadrer(|| g.next().unwrap(), || async { Ok(b"capture".to_vec()) })
                    .await
                    .is_err()
            );
        }
        assert_eq!(
            encadrer(|| Ok(7), || async { Ok(b"capture".to_vec()) })
                .await
                .unwrap(),
            b"capture"
        );
        assert!(
            encadrer(
                || Err("refus"),
                || async { panic!("dump interdit apres un refus") }
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn sortie_processus_bornee_et_erreurs_sans_donnees_partielles() {
        let sh = Path::new("/bin/sh");
        assert_eq!(
            lire_commande(sh, &["-c", "printf abc"], Duration::from_secs(1), 3)
                .await
                .unwrap(),
            b"abc"
        );
        assert!(
            lire_commande(sh, &["-c", "printf abcd"], Duration::from_secs(1), 3)
                .await
                .is_err()
        );
        assert!(
            lire_commande(sh, &["-c", "printf abc; exit 7"], Duration::from_secs(1), 3)
                .await
                .is_err()
        );
        assert!(
            lire_commande(
                sh,
                &["-c", "while :; do :; done"],
                Duration::from_millis(50),
                3
            )
            .await
            .is_err()
        );
    }
}
