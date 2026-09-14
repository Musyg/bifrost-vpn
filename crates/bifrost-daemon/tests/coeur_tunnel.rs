//! Le chemin par coeur monte, porte le trafic, et ne laisse rien derriere lui.
//!
//! # Pourquoi ce fichier se relance lui-meme
//!
//! Ce que le device pose n'est pas anodin: une route par defaut pour TOUT le
//! systeme. Sur la machine d'essai, cela couperait la session par laquelle on y
//! travaille. Contrairement a `tunnel::aiguillage`, dont le test peut prefixer
//! chaque commande par `ip netns exec`, ce device execute les siennes lui-meme,
//! et lui donner un prefixe configurable serait ajouter de la surface de
//! production pour les besoins d'une recette.
//!
//! Le test cree donc un espace de noms et **s'y relance**: le travail reel se
//! fait dans un processus fils dont TOUT le reseau est isole. L'hote ne voit
//! rien passer.

#![cfg(target_os = "linux")]

use std::io::{Read, Write};
use std::net::SocketAddr;
use std::time::Duration;

use bifrost_core::config::Portage;
use bifrost_core::ports::TunnelDevice;
use bifrost_core::profil::Profil;
use bifrost_core::{DnsPolicy, TunnelConfig};
use bifrost_daemon::coeurs::passage;
use bifrost_daemon::tunnel::coeur::CoeurTunnel;

/// L'interface montee par le test. Un espace de noms neuf, donc aucun conflit.
const INTERFACE: &str = "bfcoeur0";
/// L'adresse que l'application vise. N'importe laquelle: l'aiguillage envoie
/// tout dans le TUN.
const CIBLE: &str = "93.184.216.34:443";
/// Le compte suppose du coeur. Aucun processus ne le porte ici; ce qui est
/// verifie est que la regle est posee et retiree.
const UID_COEUR: u32 = 4242;

fn est_root() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .unwrap_or_default()
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))
        .and_then(|l| l.split_whitespace().nth(1).map(str::to_owned))
        .as_deref()
        == Some("0")
}

fn ip(args: &[&str]) -> Result<String, String> {
    let sortie = std::process::Command::new("ip")
        .args(args)
        .output()
        .map_err(|e| format!("ip {args:?} non lancable: {e}"))?;
    if !sortie.status.success() {
        return Err(format!(
            "ip {args:?}: {}",
            String::from_utf8_lossy(&sortie.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&sortie.stdout).into_owned())
}

fn cfg() -> TunnelConfig {
    // Un VRAI profil de coeur, et non plus une configuration de forme
    // WireGuard servant de vehicule. C'est ce que la lacune nommee ici
    // jusqu'au 19 aout 2026 empechait: le type porte desormais ce que le
    // peripherique utilise, et rien d'autre.
    let profil = Profil::depuis_lien(
        "hysteria2://mot-de-passe-de-documentation@203.0.113.8:8443/?sni=exemple.test#Essai",
    )
    .expect("le lien de documentation doit se lire");
    TunnelConfig {
        interface: INTERFACE.into(),
        addresses: vec!["10.99.0.1/24".parse().unwrap()],
        mtu: 1500,
        dns: DnsPolicy {
            local_resolver: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            upstream: vec![std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)],
            embarque: false,
            anti_telemetrie: bifrost_core::config::ProfilTelemetrie::Aucun,
        },
        allow_lan: false,
        portage: Portage::Coeur(Box::new(profil.into())),
    }
}

/// Le compte de recette, exige par le faux coeur et presente par le passeur.
fn compte() -> bifrost_daemon::coeurs::socks::Identifiants {
    bifrost_daemon::coeurs::socks::Identifiants::nouveaux("bifrost", "recette").unwrap()
}

/// Un faux coeur derriere la facade: il parle SOCKS5, dit ou on l'a envoye,
/// puis renvoie ce qu'on lui donne prefixe de son etiquette.
///
/// Il EXIGE le compte, comme le fera un vrai: un faux coeur complaisant
/// laisserait passer un passeur qui aurait cesse de se presenter, et ce test
/// continuerait de reussir en ne mesurant plus rien.
async fn coeur_fictif(vues: std::sync::mpsc::Sender<SocketAddr>) -> SocketAddr {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let ecoute = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let adresse = ecoute.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut flux, _)) = ecoute.accept().await {
            let vues = vues.clone();
            tokio::spawn(async move {
                let mut debut = [0u8; 2];
                if flux.read_exact(&mut debut).await.is_err() {
                    return;
                }
                let mut methodes = vec![0u8; debut[1] as usize];
                if flux.read_exact(&mut methodes).await.is_err() || !methodes.contains(&0x02) {
                    return;
                }
                let _ = flux.write_all(&[0x05, 0x02]).await;

                // RFC 1929: `VER | ULEN | UNAME | PLEN | PASSWD`, VER = 0x01.
                let mut tete = [0u8; 2];
                if flux.read_exact(&mut tete).await.is_err() || tete[0] != 0x01 {
                    return;
                }
                let mut nom = vec![0u8; tete[1] as usize];
                let mut taille = [0u8; 1];
                if flux.read_exact(&mut nom).await.is_err()
                    || flux.read_exact(&mut taille).await.is_err()
                {
                    return;
                }
                let mut passe = vec![0u8; taille[0] as usize];
                if flux.read_exact(&mut passe).await.is_err() {
                    return;
                }
                let attendu = compte();
                if nom != attendu.utilisateur().as_bytes()
                    || passe != attendu.mot_de_passe().as_bytes()
                {
                    let _ = flux.write_all(&[0x01, 0x01]).await;
                    return;
                }
                let _ = flux.write_all(&[0x01, 0x00]).await;

                let mut entete = [0u8; 4];
                if flux.read_exact(&mut entete).await.is_err() {
                    return;
                }
                let mut a = [0u8; 6];
                if entete[3] != 0x01 || flux.read_exact(&mut a).await.is_err() {
                    return;
                }
                let _ = vues.send(SocketAddr::from((
                    [a[0], a[1], a[2], a[3]],
                    u16::from_be_bytes([a[4], a[5]]),
                )));
                let _ = flux
                    .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await;

                let mut tampon = [0u8; 64];
                while let Ok(n) = flux.read(&mut tampon).await {
                    if n == 0 {
                        return;
                    }
                    let _ = flux.write_all(b"C:").await;
                    let _ = flux.write_all(&tampon[..n]).await;
                    let _ = flux.flush().await;
                }
            });
        }
    });
    adresse
}

/// Le travail reel. Ne tourne QUE dans l'espace de noms cree par le test
/// ci-dessous, d'ou `#[ignore]`: lance a la main sur une vraie machine, il
/// couperait son reseau.
#[test]
#[ignore = "pose une route par defaut: ne doit tourner que dans un espace de noms"]
fn dans_l_espace_de_noms_le_chemin_par_coeur_porte_le_trafic() {
    // Un espace de noms neuf a sa boucle locale eteinte, et la facade y ecoute.
    ip(&["link", "set", "lo", "up"]).expect("la boucle locale doit monter");

    // Une fausse interface physique, avec la route par defaut du monde
    // ordinaire. Elle n'est pas decorative: la regle qui fait sortir le coeur
    // l'envoie vers la table `main`, et sans route par defaut la-bas il n'a
    // nulle part ou aller - il retombe dans le TUN. Le premier jet de ce test
    // l'a montre, dans un espace de noms qui n'avait que sa boucle locale.
    //
    // Ce n'est donc pas seulement un decor de recette: sur une machine qui
    // perd son lien physique, le coeur serait route dans son propre TUN. Le
    // kill switch tient a ce moment-la, mais il faut le savoir.
    ip(&["link", "add", "dummy0", "type", "dummy"]).expect("interface physique factice");
    ip(&["addr", "add", "192.0.2.2/24", "dev", "dummy0"]).unwrap();
    ip(&["link", "set", "dummy0", "up"]).unwrap();
    ip(&[
        "route",
        "add",
        "default",
        "via",
        "192.0.2.1",
        "dev",
        "dummy0",
    ])
    .unwrap();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");

    let (dire, vues) = std::sync::mpsc::channel();
    let facade = rt.block_on(coeur_fictif(dire));

    let (poignee, tenir) = passage::ouvrir();
    rt.spawn(tenir);

    let cfg = cfg();
    // Le canal que l'atelier publie en exploitation. Tenu ici par la recette,
    // pour pouvoir faire disparaitre le coeur sans en tuer un vrai.
    let (publier, suivre) = tokio::sync::watch::channel(Some(facade));
    let mut device = CoeurTunnel::new(
        poignee,
        bifrost_daemon::coeurs::socks::Mandataire::nouveau(facade, compte()),
        Some(UID_COEUR),
        suivre,
    );
    device.up(&cfg).expect("le chemin par coeur doit monter");

    // L'interface existe, et le noyau y envoie le trafic ordinaire.
    assert!(
        std::path::Path::new(&format!("/sys/class/net/{INTERFACE}")).exists(),
        "l'interface doit exister une fois montee"
    );
    let route = ip(&["route", "get", "93.184.216.34"]).unwrap();
    assert!(
        route.contains(&format!("dev {INTERFACE}")),
        "le trafic ordinaire doit entrer dans le TUN: {route}"
    );
    // Et le coeur, lui, ne doit pas y entrer, sinon il boucle sur lui-meme.
    let sortie_coeur = ip(&["route", "get", "93.184.216.34", "uid", "4242"]).unwrap();
    assert!(
        !sortie_coeur.contains(&format!("dev {INTERFACE}")),
        "le coeur ne doit pas etre route dans le TUN: {sortie_coeur}"
    );

    // Le trajet complet: une connexion ordinaire ressort en CONNECT SOCKS5.
    let cible: SocketAddr = CIBLE.parse().unwrap();
    let mut flux = std::net::TcpStream::connect_timeout(&cible, Duration::from_secs(5))
        .expect("la connexion doit aboutir a travers le TUN");
    flux.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    flux.write_all(b"salut").unwrap();
    let mut recu = [0u8; 7];
    flux.read_exact(&mut recu).expect("la reponse doit revenir");
    assert_eq!(
        &recu, b"C:salut",
        "les octets doivent traverser les deux sens"
    );

    let demandee = vues
        .recv_timeout(Duration::from_secs(5))
        .expect("le coeur devait voir un CONNECT");
    assert_eq!(
        demandee, cible,
        "le CONNECT doit viser la destination d'origine"
    );

    // --- La vitalite ------------------------------------------------------
    //
    // Le point mesure ici, et qui ne se mesure qu'avec un VRAI peripherique
    // devant une VRAIE interface: l'interface, a elle seule, ne prouve rien.
    // Elle tient debout meme quand le coeur est mort, et ce tunnel paraissait
    // alors vivant alors que plus rien ne passait.
    let vivant = device
        .handshake(&cfg)
        .expect("un coeur publie et une interface debout font un tunnel vivant");
    assert!(
        vivant.is_some(),
        "tant que le coeur est publie, ce tunnel est vivant"
    );

    // Le coeur disparait, l'interface ne bouge pas.
    publier.send(None).expect("le canal doit rester ouvert");
    assert!(
        std::path::Path::new(&format!("/sys/class/net/{INTERFACE}")).exists(),
        "l'interface est toujours la: c'est bien ce qui rendait la panne invisible"
    );
    let e = device
        .handshake(&cfg)
        .expect_err("un coeur disparu doit se voir");
    let e = e.to_string();
    assert!(e.contains("coeur"), "l'erreur doit nommer le coeur: {e}");
    assert!(
        e.contains(INTERFACE),
        "et l'interface encore debout, pour ne pas la faire chercher: {e}"
    );

    // Et le demontage ne doit rien laisser.
    device.down(&cfg).expect("le demontage doit reussir");
    assert!(
        !std::path::Path::new(&format!("/sys/class/net/{INTERFACE}")).exists(),
        "l'interface doit disparaitre avec le passage"
    );
    let regles = ip(&["rule", "show"]).unwrap();
    for pref in [
        bifrost_daemon::tunnel::aiguillage::PREF_COEUR,
        bifrost_daemon::tunnel::aiguillage::PREF_LAN,
        bifrost_daemon::tunnel::aiguillage::PREF_TUNNEL,
    ] {
        assert!(
            !regles.contains(&format!("{pref}:")),
            "la regle {pref} survit au demontage: {regles}"
        );
    }
}

/// Cree l'espace de noms et s'y relance.
#[test]
fn le_chemin_par_coeur_se_verifie_dans_un_espace_de_noms() {
    if !est_root() {
        println!("SKIPPED: creer un espace de noms reseau demande CAP_NET_ADMIN");
        return;
    }
    let ns = format!("bfcoeur{}", std::process::id());
    let _ = ip(&["netns", "del", &ns]);
    ip(&["netns", "add", &ns]).expect("l'espace de noms doit se creer");

    let exe = std::env::current_exe().expect("le binaire de test doit etre localisable");
    let sortie = std::process::Command::new("ip")
        .args(["netns", "exec", &ns])
        .arg(&exe)
        .args([
            "--exact",
            "dans_l_espace_de_noms_le_chemin_par_coeur_porte_le_trafic",
            "--ignored",
            "--nocapture",
            "--test-threads",
            "1",
        ])
        .output()
        .expect("le test interne doit se lancer");

    let _ = ip(&["netns", "del", &ns]);

    assert!(
        sortie.status.success(),
        "le chemin par coeur a echoue dans l'espace de noms.\n--- sortie ---\n{}\n--- erreurs ---\n{}",
        String::from_utf8_lossy(&sortie.stdout),
        String::from_utf8_lossy(&sortie.stderr)
    );
}
