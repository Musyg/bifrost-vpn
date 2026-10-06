//! Un daemon Windows lance porte les politiques d'attenuation, relues de
//! l'exterieur par `GetProcessMitigationPolicy` pendant qu'il sert.
//!
//! Binaire de recette a part: le processus de cette recette ne pose rien.
//! Une politique posee par le lanceur peut passer a l'enfant (celle du
//! chargement d'images le fait); un lanceur qui en porterait ferait passer la
//! recette sans que le daemon ait rien pose. Le temoin le verifie avant le
//! lancement.
#![cfg(windows)]

#[path = "commun/attenuation.rs"]
mod attenuation_commun;

use std::io::Read;
use std::net::{SocketAddr, TcpListener};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use attenuation_commun::{ATTENDUES, manquantes};
use bifrost_daemon::checks::transport;

fn port_libre() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .expect("un port libre sur la boucle locale")
}

/// Attend que le daemon serve sa banniere. Rend une erreur s'il sort avant,
/// avec ce qu'il a ecrit sur sa sortie d'erreur.
fn attendre_banniere(enfant: &mut Child, ecoute: SocketAddr) -> Result<(), String> {
    let echeance = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(statut) = enfant.try_wait().map_err(|e| e.to_string())? {
            let mut dit = String::new();
            if let Some(mut erreur) = enfant.stderr.take() {
                let _ = erreur.read_to_string(&mut dit);
            }
            return Err(format!(
                "le daemon est sorti avant de servir ({statut}): {}",
                dit.trim()
            ));
        }
        match transport::lire(ecoute, Duration::ZERO) {
            Ok(lue) if lue == transport::BANNIERE => return Ok(()),
            Ok(lue) => return Err(format!("banniere inattendue sur {ecoute}: {lue}")),
            Err(e) if Instant::now() >= echeance => {
                return Err(format!("aucune banniere sur {ecoute} en 20 s: {e}"));
            }
            Err(_) => std::thread::sleep(Duration::from_millis(50)),
        }
    }
}

/// Un daemon lance porte les politiques, lues de l'exterieur pendant qu'il
/// sert.
///
/// `--servir-banniere` rend la main avant l'ouverture du journal et tout le
/// reste du demarrage. La banniere lue prouve que le processus a passe le
/// debut de `main`: la lecture qui suit ne peut pas devancer la pose. Une pose
/// deplacee apres cette sous-commande fait rougir la recette.
#[test]
fn un_daemon_lance_porte_les_politiques_vues_de_l_exterieur() {
    // Le temoin: le lanceur n'en porte aucune. Sans lui, une politique que
    // l'enfant herite passerait pour posee par le daemon, et une lecture qui
    // rendrait toujours les bits attendus ferait passer la recette.
    let lanceur = manquantes(std::process::id()).expect("lecture de ce processus");
    assert_eq!(
        lanceur.len(),
        ATTENDUES.len(),
        "le processus de la recette porte deja des politiques: seules manquaient {lanceur:?}"
    );

    let mut daemon = None;
    let mut derniere = String::new();
    // Le port est libere avant que le daemon s'y lie: un autre processus peut
    // le prendre entre-temps. Trois ports au plus, et la raison du dernier
    // echec si aucun ne sert.
    for _ in 0..3 {
        let ecoute = port_libre();
        let mut enfant = Command::new(env!("CARGO_BIN_EXE_bifrost-daemon"))
            .args(["--servir-banniere", &ecoute.to_string()])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("lancement du daemon");
        match attendre_banniere(&mut enfant, ecoute) {
            Ok(()) => {
                daemon = Some(enfant);
                break;
            }
            Err(e) => {
                derniere = e;
                let _ = enfant.kill();
                let _ = enfant.wait();
            }
        }
    }
    let mut daemon = daemon.unwrap_or_else(|| panic!("le daemon n'a jamais servi: {derniere}"));

    let lu = manquantes(daemon.id());
    let _ = daemon.kill();
    let _ = daemon.wait();

    let manque = lu.unwrap_or_else(|code| {
        panic!("ouverture du daemon lance en lecture refusee, code systeme {code}")
    });
    assert!(
        manque.is_empty(),
        "le daemon lance sert sans ces politiques: {manque:?}"
    );
}
