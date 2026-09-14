//! Le chemin entier, du systeme jusqu'au coeur, sur un vrai TUN.
//!
//! Ce que ce fichier mesure ne peut pas l'etre par morceaux: qu'une
//! application qui ouvre une connexion ordinaire vers une adresse routee par le
//! TUN ressorte en CONNECT SOCKS5 vers la BONNE destination, et que les octets
//! fassent l'aller-retour.
//!
//! Le pare-feu de l'hote ne s'y oppose pas, et c'est du conntrack qu'on le
//! tient et non de la chance: la connexion part de l'interieur, donc les
//! reponses que la pile ecrit sur le TUN sont vues comme etablies. C'est la
//! difference avec un paquet injecte sans flux prealable, qu'une politique
//! INPUT en DROP arrete - ce qui avait fait echouer un test de `tunnel::brut`.

#![cfg(target_os = "linux")]

use std::net::SocketAddr;
use std::time::Duration;

use bifrost_daemon::coeurs::passeur::{self, Tun};
use bifrost_daemon::coeurs::socks::{Identifiants, Mandataire};
use bifrost_daemon::tunnel::brut;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

/// Le compte que les faux coeurs de ce fichier exigent.
///
/// Valeurs de recette et non de production: elles n'ouvrent rien ailleurs que
/// dans ce processus, ou le faux coeur les compare a ce que le passeur envoie.
fn compte() -> Identifiants {
    Identifiants::nouveaux("bifrost", "MOT-DE-PASSE-DE-RECETTE").unwrap()
}

/// La poignee de main de la RFC 1929, du cote du coeur.
///
/// Rend `false` si le passeur ne s'est pas presente ou s'est mal presente, et
/// dans ce cas le lien se ferme comme la RFC l'exige. C'est ce qui fait de ces
/// faux coeurs des juges et non des complices: un passeur qui aurait cesse de
/// presenter ses identifiants ferait tomber les tests principaux du fichier.
async fn authentifier(flux: &mut TcpStream, attendu: &Identifiants) -> bool {
    let mut debut = [0u8; 2];
    if flux.read_exact(&mut debut).await.is_err() {
        return false;
    }
    let mut methodes = vec![0u8; debut[1] as usize];
    if flux.read_exact(&mut methodes).await.is_err() {
        return false;
    }
    assert!(
        methodes.contains(&0x02),
        "le passeur doit proposer l'authentification par mot de passe"
    );
    assert!(
        !methodes.contains(&0x00),
        "le passeur ne doit pas proposer 'sans authentification': le coeur la choisirait"
    );
    if flux.write_all(&[0x05, 0x02]).await.is_err() {
        return false;
    }

    // `VER | ULEN | UNAME | PLEN | PASSWD`, ou VER vaut 0x01 et non 0x05.
    let mut entete = [0u8; 2];
    if flux.read_exact(&mut entete).await.is_err() || entete[0] != 0x01 {
        return false;
    }
    let mut nom = vec![0u8; entete[1] as usize];
    if flux.read_exact(&mut nom).await.is_err() {
        return false;
    }
    let mut taille = [0u8; 1];
    if flux.read_exact(&mut taille).await.is_err() {
        return false;
    }
    let mut passe = vec![0u8; taille[0] as usize];
    if flux.read_exact(&mut passe).await.is_err() {
        return false;
    }

    let bon = nom == attendu.utilisateur().as_bytes() && passe == attendu.mot_de_passe().as_bytes();
    let _ = flux.write_all(&[0x01, u8::from(!bon)]).await;
    bon
}

/// Pourquoi ce qui suit ne peut pas tourner ici, s'il y a une raison.
fn raison_de_sauter() -> Option<&'static str> {
    if !std::path::Path::new("/dev/net/tun").exists() {
        return Some("/dev/net/tun absent, le module tun n'est pas charge");
    }
    // Lu dans /proc plutot qu'appele: une recette d'integration n'a pas a
    // dependre de `libc`, et le depot lit deja /proc ailleurs.
    let statut = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let effectif = statut
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))
        .and_then(|l| l.split_whitespace().nth(1).map(str::to_owned));
    if effectif.as_deref() != Some("0") {
        return Some("ouvrir un TUN demande CAP_NET_ADMIN, ce test tourne sans");
    }
    None
}

fn ip(args: &[&str]) -> Result<(), String> {
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
    Ok(())
}

/// Un TUN adresse et en service, et une adresse joignable a travers lui.
///
/// `rang` distingue les tests: ils tournent en parallele dans le meme
/// processus, et sans lui le second demanderait une interface deja prise et un
/// sous-reseau deja route.
fn tun_monte(rang: u8) -> (brut::TunBrut, SocketAddr) {
    let octet = (std::process::id() % 100) as u8 * 2 + rang;
    let nom = format!("bfp{octet}");
    let tun = brut::ouvrir(&nom).expect("le TUN doit s'ouvrir");
    ip(&["addr", "add", &format!("10.78.{octet}.1/24"), "dev", &nom]).unwrap();
    ip(&["link", "set", &nom, "up"]).unwrap();
    // Une adresse du sous-reseau connecte: le noyau la route par le TUN sans
    // qu'on ait a poser quoi que ce soit de plus.
    (tun, format!("10.78.{octet}.5:80").parse().unwrap())
}

/// Un faux coeur: il parle SOCKS5, dit ou on lui a demande d'aller, puis
/// renvoie ce qu'on lui envoie prefixe de son etiquette.
///
/// Ecrit ici plutot que reutilise: ce test doit pouvoir dire vers QUELLE
/// destination le CONNECT a ete emis, ce qu'un vrai coeur ne raconte pas.
async fn coeur_fictif(
    etiquette: &'static str,
    attendu: Identifiants,
) -> (SocketAddr, mpsc::UnboundedReceiver<SocketAddr>) {
    let ecoute = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let adresse = ecoute.local_addr().unwrap();
    let (dire, entendre) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok((mut flux, _)) = ecoute.accept().await {
            let dire = dire.clone();
            let attendu = attendu.clone();
            tokio::spawn(async move {
                if !authentifier(&mut flux, &attendu).await {
                    return;
                }

                // Requete: version, commande, reserve, type d'adresse.
                let mut entete = [0u8; 4];
                if flux.read_exact(&mut entete).await.is_err() {
                    return;
                }
                let cible = match entete[3] {
                    0x01 => {
                        let mut a = [0u8; 6];
                        if flux.read_exact(&mut a).await.is_err() {
                            return;
                        }
                        SocketAddr::from((
                            [a[0], a[1], a[2], a[3]],
                            u16::from_be_bytes([a[4], a[5]]),
                        ))
                    }
                    autre => panic!("le passeur doit annoncer une adresse, pas un type {autre}"),
                };
                let _ = dire.send(cible);

                // Reponse: succes, adresse liee sans interet.
                let _ = flux
                    .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await;

                let mut tampon = [0u8; 64];
                while let Ok(n) = flux.read(&mut tampon).await {
                    if n == 0 {
                        return;
                    }
                    let _ = flux.write_all(etiquette.as_bytes()).await;
                    let _ = flux.write_all(&tampon[..n]).await;
                    let _ = flux.flush().await;
                }
            });
        }
    });
    (adresse, entendre)
}

/// Le test qui vaut pour tous les autres: une connexion ordinaire, emise par
/// le systeme vers une adresse routee par le TUN, ressort en CONNECT SOCKS5
/// vers cette meme adresse, et les octets font l'aller-retour.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn une_connexion_du_systeme_ressort_en_connect_vers_la_bonne_cible() {
    if let Some(raison) = raison_de_sauter() {
        println!("SKIPPED: {raison}");
        return;
    }
    let (tun, cible) = tun_monte(0);
    let (coeur, mut vues) = coeur_fictif("C:", compte()).await;

    let passage = Tun::nouveau(tun).expect("le TUN doit devenir asynchrone");
    tokio::spawn(passeur::servir(
        passage,
        Mandataire::nouveau(coeur, compte()),
        passeur::MTU,
    ));

    let echange = async {
        let mut flux = TcpStream::connect(cible).await?;
        flux.write_all(b"salut").await?;
        flux.flush().await?;
        // `read_exact` et non `read`: TCP rend des morceaux, pas des
        // messages, et le faux coeur ecrit son etiquette puis la charge. Une
        // seule lecture rendait "C:" et faisait echouer le test sur une
        // propriete de TCP plutot que sur ce qu'il mesure.
        let mut recu = [0u8; 7];
        flux.read_exact(&mut recu).await?;
        std::io::Result::Ok(String::from_utf8_lossy(&recu).into_owned())
    };
    let recu = tokio::time::timeout(Duration::from_secs(10), echange)
        .await
        .expect("le chemin complet ne doit pas faire attendre")
        .expect("la connexion doit aboutir");

    assert_eq!(
        recu, "C:salut",
        "les octets doivent traverser dans les deux sens"
    );

    let demandee = vues.try_recv().expect("le coeur devait voir un CONNECT");
    assert_eq!(
        demandee, cible,
        "le CONNECT doit viser la destination D'ORIGINE, celle que l'application avait choisie"
    );
}

/// Le temoin negatif du test precedent, et la seule chose qui le rende
/// lisible: si un passeur mal identifie traversait quand meme, le succes
/// ci-dessus ne prouverait pas que les identifiants ont servi a quoi que ce
/// soit.
///
/// Ce que cela reproduit est un trou mesure sur le banc le 20 aout 2026, ou un
/// processus tiers de la machine - ni le passeur ni le coeur - s'est connecte a
/// l'entree SOCKS sans rien presenter et est ressorti par le tunnel.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn un_passeur_mal_identifie_ne_traverse_pas() {
    if let Some(raison) = raison_de_sauter() {
        println!("SKIPPED: {raison}");
        return;
    }
    let (tun, cible) = tun_monte(2);
    // Le coeur attend le bon compte; le passeur en presentera un autre.
    let (coeur, mut vues) = coeur_fictif("C:", compte()).await;
    let faux = Identifiants::nouveaux("bifrost", "CE-N-EST-PAS-LE-BON").unwrap();

    let passage = Tun::nouveau(tun).expect("le TUN doit devenir asynchrone");
    tokio::spawn(passeur::servir(
        passage,
        Mandataire::nouveau(coeur, faux),
        passeur::MTU,
    ));

    let echange = async {
        let mut flux = TcpStream::connect(cible).await?;
        flux.write_all(b"salut").await?;
        flux.flush().await?;
        let mut recu = [0u8; 32];
        let n = flux.read(&mut recu).await?;
        std::io::Result::Ok(n)
    };
    match tokio::time::timeout(Duration::from_secs(15), echange).await {
        Err(_) => panic!("la connexion s'est eternisee au lieu de tomber"),
        Ok(Ok(n)) => assert_eq!(n, 0, "des octets sont revenus d'un coeur qui a refuse"),
        Ok(Err(_)) => {}
    }
    assert!(
        vues.try_recv().is_err(),
        "un CONNECT a ete emis alors que l'authentification avait echoue"
    );
}

/// Sans coeur joignable, la connexion doit tomber, pas s'eterniser. Une
/// application suspendue finit par decider elle-meme, souvent en reessayant
/// hors du tunnel - le contraire de ce qu'un kill switch cherche a obtenir.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sans_coeur_joignable_la_connexion_ne_s_eternise_pas() {
    if let Some(raison) = raison_de_sauter() {
        println!("SKIPPED: {raison}");
        return;
    }
    let (tun, cible) = tun_monte(1);

    // Un port qu'on vient de liberer: personne n'ecoute derriere.
    let mort = {
        let ecoute = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a = ecoute.local_addr().unwrap();
        drop(ecoute);
        a
    };

    let passage = Tun::nouveau(tun).expect("le TUN doit devenir asynchrone");
    tokio::spawn(passeur::servir(
        passage,
        Mandataire::nouveau(mort, compte()),
        passeur::MTU,
    ));

    let echange = async {
        let mut flux = TcpStream::connect(cible).await?;
        flux.write_all(b"salut").await?;
        let mut recu = [0u8; 32];
        let n = flux.read(&mut recu).await?;
        std::io::Result::Ok(n)
    };
    let issue = tokio::time::timeout(Duration::from_secs(15), echange).await;
    match issue {
        Err(_) => panic!("la connexion s'est eternisee au lieu de tomber"),
        Ok(Ok(n)) => assert_eq!(n, 0, "rien ne doit revenir quand aucun coeur ne repond"),
        Ok(Err(_)) => {}
    }
}

/// Un faux coeur qui parle SOCKS5 UDP: il accepte l'association, ouvre un
/// relais, et renvoie chaque datagramme prefixe de son etiquette.
///
/// Le relais est annonce sur `0.0.0.0`, DELIBEREMENT: c'est ce que fait un
/// mandataire qui ecoute sur toutes les interfaces, et c'est le piege
/// d'interoperabilite que le client doit savoir defaire. L'annoncer en
/// `127.0.0.1` rendrait ce test complaisant.
async fn coeur_udp_fictif() -> (SocketAddr, mpsc::UnboundedReceiver<SocketAddr>) {
    let ecoute = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let adresse = ecoute.local_addr().unwrap();
    let (dire, entendre) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok((mut controle, _)) = ecoute.accept().await {
            let dire = dire.clone();
            tokio::spawn(async move {
                if !authentifier(&mut controle, &compte()).await {
                    return;
                }

                let mut entete = [0u8; 4];
                if controle.read_exact(&mut entete).await.is_err() {
                    return;
                }
                assert_eq!(entete[1], 0x03, "le passeur doit demander UDP ASSOCIATE");
                let mut reste = [0u8; 6];
                if controle.read_exact(&mut reste).await.is_err() {
                    return;
                }

                let relais = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
                let port = relais.local_addr().unwrap().port();
                // Adresse nulle, port reel: la forme qui piege les clients.
                let mut reponse = vec![0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0];
                reponse.extend_from_slice(&port.to_be_bytes());
                let _ = controle.write_all(&reponse).await;

                let dire2 = dire.clone();
                tokio::spawn(async move {
                    let mut tampon = vec![0u8; 65535];
                    while let Ok((n, de)) = relais.recv_from(&mut tampon).await {
                        // L'en-tete: RSV(2) FRAG(1) ATYP(1) puis l'adresse.
                        if n < 10 || tampon[3] != 0x01 {
                            continue;
                        }
                        let cible = SocketAddr::from((
                            [tampon[4], tampon[5], tampon[6], tampon[7]],
                            u16::from_be_bytes([tampon[8], tampon[9]]),
                        ));
                        let _ = dire2.send(cible);
                        let mut retour = tampon[..10].to_vec();
                        retour.extend_from_slice(b"U:");
                        retour.extend_from_slice(&tampon[10..n]);
                        let _ = relais.send_to(&retour, de).await;
                    }
                });

                // Le lien de controle tient l'association: le garder ouvert.
                let mut muet = [0u8; 1];
                let _ = controle.read(&mut muet).await;
            });
        }
    });
    (adresse, entendre)
}

/// Le pendant UDP du test principal: un datagramme ordinaire ressort en
/// datagramme encapsule vers la bonne destination, et la reponse revient.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn un_datagramme_du_systeme_ressort_par_l_association_udp() {
    if let Some(raison) = raison_de_sauter() {
        println!("SKIPPED: {raison}");
        return;
    }
    let (tun, cible_tcp) = tun_monte(3);
    let cible = SocketAddr::new(cible_tcp.ip(), 5353);
    let (coeur, mut vues) = coeur_udp_fictif().await;

    let passage = passeur::Tun::nouveau(tun).expect("la pile doit prendre le TUN");
    tokio::spawn(passeur::servir(
        passage,
        Mandataire::nouveau(coeur, compte()),
        passeur::MTU,
    ));

    let local = tokio::net::UdpSocket::bind("0.0.0.0:0").await.unwrap();
    local.connect(cible).await.unwrap();
    local.send(b"salut").await.unwrap();

    let mut recu = vec![0u8; 1500];
    let n = tokio::time::timeout(std::time::Duration::from_secs(5), local.recv(&mut recu))
        .await
        .expect("la reponse doit revenir avant l'echeance")
        .expect("la reception doit reussir");
    assert_eq!(
        &recu[..n],
        b"U:salut",
        "les octets doivent faire l'aller-retour a travers l'association"
    );

    let demandee = tokio::time::timeout(std::time::Duration::from_secs(5), vues.recv())
        .await
        .expect("le coeur devait voir un datagramme")
        .expect("le canal doit rendre l'adresse");
    assert_eq!(
        demandee, cible,
        "le datagramme encapsule doit viser la destination d'origine"
    );
}

/// Un faux coeur qui repond une fois puis RACCROCHE.
///
/// C'est le comportement de tout serveur qui delimite sa reponse par la
/// fermeture: HTTP/1.0 sans `Content-Length`, et la moitie des protocoles de
/// requete-reponse. Le faux coeur des autres recettes, lui, ne raccroche
/// jamais - il ne pouvait donc pas voir ce que celle-ci mesure.
async fn coeur_qui_raccroche(attendu: Identifiants) -> SocketAddr {
    let ecoute = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let adresse = ecoute.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut flux, _)) = ecoute.accept().await {
            let attendu = attendu.clone();
            tokio::spawn(async move {
                if !authentifier(&mut flux, &attendu).await {
                    return;
                }
                // Requete: en-tete puis adresse. Ni l'une ni l'autre ne sert
                // ici, mais il faut les consommer pour rester en phase.
                let mut entete = [0u8; 4];
                if flux.read_exact(&mut entete).await.is_err() {
                    return;
                }
                let mut adresse = [0u8; 6];
                if flux.read_exact(&mut adresse).await.is_err() {
                    return;
                }
                let _ = flux
                    .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await;

                let mut tampon = [0u8; 64];
                if flux.read(&mut tampon).await.is_err() {
                    return;
                }
                let _ = flux.write_all(b"raccroche").await;
                let _ = flux.flush().await;
                // Et voila le point de la recette: le lien se ferme.
            });
        }
    });
    adresse
}

/// Quand le coeur raccroche, l'application doit voir la FIN du flux.
///
/// # Ce que cette recette a attrape
///
/// Un tunnel qui livre les octets et jamais la fermeture. Mesure sur
/// essai-windows le 21 aout 2026, sur un vrai sing-box: les 208 octets de la
/// reponse arrivent, l'application les acquitte, et puis plus rien - la
/// connexion reste ouverte jusqu'a ce que le CLIENT se lasse, huit secondes
/// plus tard. Une lecture jusqu'a la fin du flux, qui est ce que fait tout
/// client HTTP/1.0, rendait donc une chaine VIDE apres un long silence, alors
/// que les octets etaient bel et bien arrives.
///
/// La cause est en amont et elle est nette: `ipstack` 1.0.1 differe le FIN tant
/// qu'il reste des paquets en vol - `poll_shutdown`, `is_ready == false` - puis
/// enregistre son reveil dans `self.shutdown`. Or l'acquittement qui vide la
/// file ne reveille que `write_notify` et `read_notify`; `shutdown.ready()` ne
/// se dit qu'aux chemins de fermeture. Personne ne repasse donc, et le FIN
/// n'est jamais emis. Aucun correctif en amont au 21 aout 2026 (dernier commit
/// touchant la fermeture: `0f95edc`, 18 aout, qui traite un autre cas).
/// Remonte le meme jour: <https://github.com/narrowlink/ipstack/issues/89>.
///
/// La recette est ecrite ici plutot que dans un test unitaire parce que la
/// propriete ne s'observe qu'au bout de la chaine: une pile TCP en espace
/// utilisateur, un vrai TUN, et une application qui lit jusqu'a la fin.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quand_le_coeur_raccroche_l_application_voit_la_fin_du_flux() {
    if let Some(raison) = raison_de_sauter() {
        println!("SKIPPED: {raison}");
        return;
    }
    let (tun, cible) = tun_monte(4);
    let coeur = coeur_qui_raccroche(compte()).await;

    let passage = Tun::nouveau(tun).expect("le TUN doit devenir asynchrone");
    tokio::spawn(passeur::servir(
        passage,
        Mandataire::nouveau(coeur, compte()),
        passeur::MTU,
    ));

    let echange = async {
        let mut flux = TcpStream::connect(cible).await?;
        flux.write_all(b"salut").await?;
        flux.flush().await?;
        // `read_to_end` et non `read_exact`: c'est la FIN qu'on mesure, et elle
        // ne s'observe qu'en demandant a lire jusqu'a elle.
        let mut tout = Vec::new();
        flux.read_to_end(&mut tout).await?;
        std::io::Result::Ok(tout)
    };
    let tout = tokio::time::timeout(Duration::from_secs(5), echange)
        .await
        .expect(
            "l'application n'a jamais vu la fin du flux: les octets peuvent \
             etre arrives, la fermeture n'a pas suivi",
        )
        .expect("la connexion doit aboutir");

    assert_eq!(
        String::from_utf8_lossy(&tout),
        "raccroche",
        "l'application doit recevoir la reponse ENTIERE, terminee par la fermeture"
    );
}
