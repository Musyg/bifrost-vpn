//! Le canal HTTP contre un serveur qui n'est pas complaisant.
//!
//! Les recettes du module jugent la POLITIQUE avec des canaux de doublure. Ici
//! c'est le TRANSPORT qui est mesure, et contre les comportements qu'un canal
//! hostile peut avoir sans jamais fabriquer de signature: repondre 404, servir
//! un corps sans fin, accepter la connexion et se taire.
//!
//! En clair et sur la boucle locale, deliberement: monter une autorite de
//! certification pour la recette mesurerait notre capacite a fabriquer un
//! certificat, pas les plafonds. Que la pile TLS fonctionne a ete verifie
//! autrement - une requete reelle vers un depot public, sur les deux
//! plateformes, le 19 aout 2026.

use bifrost_amorce::Canal;
use bifrost_amorce::toile::Toile;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

/// Ce qu'un serveur de recette fait d'une requete.
#[derive(Clone, Copy)]
enum Conduite {
    /// Repond normalement au profil et a sa signature.
    Correcte,
    /// Sert un corps enorme sur toute demande.
    Deluge,
    /// Accepte la connexion et ne repond jamais.
    Mutisme,
    /// Repond 404 a tout.
    Absent,
}

/// Monte un serveur sur la boucle locale et rend son adresse.
///
/// Il vit le temps de la recette et meurt avec elle: le thread est detache et
/// la recette ne l'attend pas, ce qui evite qu'un serveur muet fasse pendre la
/// suite du fichier.
fn servir(conduite: Conduite) -> String {
    let ecoute = TcpListener::bind("127.0.0.1:0").expect("la boucle locale doit etre libre");
    let adresse = format!("http://{}", ecoute.local_addr().unwrap());

    std::thread::spawn(move || {
        for flux in ecoute.incoming() {
            let Ok(flux) = flux else { break };
            std::thread::spawn(move || repondre(flux, conduite));
        }
    });

    adresse
}

fn repondre(mut flux: TcpStream, conduite: Conduite) {
    let mut tampon = [0u8; 2048];
    let lu = flux.read(&mut tampon).unwrap_or(0);
    let requete = String::from_utf8_lossy(&tampon[..lu]).to_string();

    match conduite {
        Conduite::Mutisme => {
            // Ni reponse ni fermeture: c'est au delai de trancher.
            std::thread::sleep(Duration::from_secs(120));
        }
        Conduite::Absent => {
            let _ = flux.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
        }
        Conduite::Deluge => {
            let corps = vec![b'x'; 1024 * 1024];
            let _ = flux.write_all(
                format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", corps.len()).as_bytes(),
            );
            let _ = flux.write_all(&corps);
        }
        Conduite::Correcte => {
            let corps: &[u8] = if requete.contains(".minisig") {
                b"untrusted comment: recette\nSIGNATURE\ntrusted comment: serie=1\nGLOBALE\n"
            } else {
                b"interface = \"wg0\"\n"
            };
            let _ = flux.write_all(
                format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", corps.len()).as_bytes(),
            );
            let _ = flux.write_all(corps);
        }
    }
}

#[test]
fn un_serveur_correct_rend_le_profil_et_sa_signature() {
    let base = servir(Conduite::Correcte);
    let recu = Toile::nouvelle(format!("{base}/tunnel.toml"))
        .chercher()
        .expect("un serveur correct doit repondre");

    assert_eq!(recu.profil, b"interface = \"wg0\"\n");
    // La signature est allee chercher l'autre adresse, celle en .minisig: c'est
    // la convention, et c'est ce qui distingue les deux reponses du serveur.
    assert!(
        recu.signature.contains("GLOBALE"),
        "la signature doit venir de l'adresse .minisig: {}",
        recu.signature
    );
}

/// Le plafond de taille, qui est le point entier.
///
/// Un canal hostile n'a pas besoin de fabriquer une signature pour nuire: un
/// corps sans fin suffit a faire grossir le processus jusqu'a sa mort. Ce n'est
/// pas une precaution theorique - c'est le defaut qu'un `telecharger l'adresse`
/// naif laisse ouvert.
#[test]
fn un_corps_demesure_est_refuse_avant_d_etre_avale() {
    let base = servir(Conduite::Deluge);
    let e = Toile::nouvelle(format!("{base}/tunnel.toml"))
        .chercher()
        .expect_err("un mega-octet ne doit pas passer pour un profil");
    assert!(
        e.to_lowercase().contains("limit"),
        "l'echec doit nommer le plafond: {e}"
    );
}

#[test]
fn un_404_est_un_canal_muet_qui_se_nomme() {
    let base = servir(Conduite::Absent);
    let adresse = format!("{base}/tunnel.toml");
    let e = Toile::nouvelle(&adresse)
        .chercher()
        .expect_err("un 404 n'est pas un profil");
    assert!(e.contains(&adresse), "{e}");
}

/// Un serveur qui accepte puis se tait ne fait pas pendre la commande.
///
/// Avec un delai d'une seconde plutot que les quinze du defaut: c'est le
/// mecanisme qui est mesure, pas sa valeur. Sans cette recette, un canal
/// silencieux gelerait la recuperation entiere et rien ne le dirait.
#[test]
fn un_serveur_muet_rend_la_main() {
    let base = servir(Conduite::Mutisme);
    let debut = std::time::Instant::now();
    let e = Toile::avec_delai(format!("{base}/tunnel.toml"), Duration::from_secs(1))
        .chercher()
        .expect_err("un serveur muet doit finir par etre abandonne");

    let mis = debut.elapsed();
    assert!(
        mis < Duration::from_secs(10),
        "le delai n'a pas joue: {mis:?} ({e})"
    );
}
