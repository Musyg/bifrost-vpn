//! L'enveloppe asynchrone du TUN sous Windows, sur une vraie interface.
//!
//! Ce que ce fichier mesure n'est PAS le meme chemin que son homologue Linux, et
//! il vaut mieux le dire que le laisser croire. La-bas, la recette ouvre une
//! connexion ordinaire vers une adresse routee par le TUN et verifie qu'elle
//! ressort en CONNECT SOCKS5: cela demande d'adresser l'interface et de la
//! router, ce qui appartient sous Windows au lot suivant - celui qui cablera
//! `CoeurTunnel`.
//!
//! Ce qui est mesure ici est d'abord la moitie qui n'existe que sous Windows, et
//! qui est aussi la plus risquee: le fil de veille, le canal qui le relie a la
//! tache, et surtout l'ARRET. Une enveloppe qui terminerait la session pendant
//! que le fil est dans `WintunReceivePacket` ne planterait pas tout de suite -
//! elle planterait un jour, en production, a la deconnexion.
//!
//! # L'aller-retour, ajoute le 21 aout 2026
//!
//! Le lot qui cable `CoeurTunnel` est arrive, donc l'excuse ci-dessus a expire:
//! adresser l'interface et la router se fait desormais par
//! [`bifrost_daemon::tunnel::wgnt::ipcfg`], et la derniere recette de ce fichier
//! est enfin l'homologue de celle de la moitie Linux.
//!
//! Elle a ete ecrite pour une raison precise: le banc du 21 aout 2026 a montre
//! un chemin par coeur qui porte l'ALLER et perd le RETOUR sous Windows, la ou
//! il fait l'aller-retour sous Linux. Un banc qui coupe le reseau ne dit pas OU,
//! parce qu'il mesure tout a la fois - le kill switch, la route par defaut, le
//! vrai coeur, le passeur. Cette recette ne prend QUE le passeur: pas de kill
//! switch, pas de route par defaut, un faux coeur dans le processus. Verte, elle
//! innocente le passeur et renvoie la recherche au montage; rouge, elle tient le
//! defaut dans un fichier qu'on peut relancer en trente secondes.
//!
//! Elle ne coupe donc rien et peut tourner sur une machine de travail: la seule
//! route posee mene un `/24` prive a une interface qui disparait avec le test.

#![cfg(windows)]

use std::time::Duration;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use bifrost_core::config::{
    DEFAULT_FWMARK, DEFAULT_ROUTING_TABLE, DnsPolicy, Endpoint, PeerConfig, Portage, TunnelConfig,
    WgKey, WireguardParams,
};
use bifrost_daemon::coeurs::passeur::{self, Tun};
use bifrost_daemon::coeurs::socks::{Identifiants, Mandataire};
use bifrost_daemon::tunnel::brut;
use bifrost_daemon::tunnel::wgnt::ipcfg;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use windows_sys::core::GUID;

/// Les GUID de ce fichier, distincts de ceux des recettes unitaires de
/// `tunnel::brut`: deux adaptateurs ne peuvent pas partager un GUID, et les deux
/// jeux de recettes peuvent tourner dans la meme minute.
const GUID_PASSEUR: [GUID; 5] = [
    GUID::from_u128(0x0bd4f5a1_6c1e_4f8d_9a3e_2f7b41c9e540),
    GUID::from_u128(0x0bd4f5a1_6c1e_4f8d_9a3e_2f7b41c9e541),
    GUID::from_u128(0x0bd4f5a1_6c1e_4f8d_9a3e_2f7b41c9e542),
    GUID::from_u128(0x0bd4f5a1_6c1e_4f8d_9a3e_2f7b41c9e543),
    GUID::from_u128(0x0bd4f5a1_6c1e_4f8d_9a3e_2f7b41c9e544),
];

/// Pourquoi ce qui suit ne peut pas tourner ici, s'il y a une raison.
fn raison_de_sauter() -> Option<String> {
    let a_cote = std::env::current_exe()
        .ok()
        .and_then(|e| e.parent().map(|d| d.join("wintun.dll")));
    match a_cote {
        Some(c) if c.is_file() => {}
        _ => {
            return Some(
                "wintun.dll absente a cote du binaire: le depot ne distribue aucun \
                 binaire tiers, la recuperer avec 'bifrost pilote recuperer'"
                    .to_owned(),
            );
        }
    }
    if !est_eleve() {
        return Some(
            "creer une interface Wintun installe le pilote, ce qui demande les droits \
             d'administrateur"
                .to_owned(),
        );
    }
    None
}

fn est_eleve() -> bool {
    use std::mem::size_of;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{
        GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    // SAFETY: jeton du processus courant, champ de taille connue, handle
    // referme sur tous les chemins.
    unsafe {
        let mut jeton: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut jeton) == 0 {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut taille = 0u32;
        let ok = GetTokenInformation(
            jeton,
            TokenElevation,
            &raw mut elevation as *mut std::ffi::c_void,
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut taille,
        );
        CloseHandle(jeton);
        ok != 0 && elevation.TokenIsElevated != 0
    }
}

/// Le compteur d'entree de l'interface, tel que le systeme l'expose.
fn paquets_entrants(luid: u64) -> u64 {
    use windows_sys::Win32::NetworkManagement::IpHelper::{GetIfEntry2, MIB_IF_ROW2};
    use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;

    // SAFETY: structure mise a zero, seul le LUID renseigne avant l'appel,
    // comme la documentation l'exige.
    unsafe {
        let mut ligne: MIB_IF_ROW2 = std::mem::zeroed();
        ligne.InterfaceLuid = NET_LUID_LH { Value: luid };
        let code = GetIfEntry2(&raw mut ligne);
        assert_eq!(code, 0, "GetIfEntry2 a refuse (code {code})");
        ligne.InUcastPkts
    }
}

/// La somme de controle d'Internet, RFC 1071.
fn somme_internet(octets: &[u8]) -> u16 {
    let mut somme = 0u32;
    for morceau in octets.chunks(2) {
        let mot = if morceau.len() == 2 {
            u16::from_be_bytes([morceau[0], morceau[1]])
        } else {
            u16::from_be_bytes([morceau[0], 0])
        };
        somme += u32::from(mot);
    }
    while somme >> 16 != 0 {
        somme = (somme & 0xffff) + (somme >> 16);
    }
    !(somme as u16)
}

/// Un datagramme UDP complet, en-tete IPv4 comprise.
fn datagramme(charge: &[u8]) -> Vec<u8> {
    let total = (20 + 8 + charge.len()) as u16;
    let mut p = Vec::with_capacity(total as usize);
    p.extend_from_slice(&[0x45, 0x00]);
    p.extend_from_slice(&total.to_be_bytes());
    p.extend_from_slice(&[0, 0, 0x40, 0x00, 64, 17, 0, 0]);
    p.extend_from_slice(&std::net::Ipv4Addr::new(10, 79, 0, 2).octets());
    p.extend_from_slice(&std::net::Ipv4Addr::new(10, 79, 0, 1).octets());
    let somme = somme_internet(&p[..20]);
    p[10..12].copy_from_slice(&somme.to_be_bytes());
    p.extend_from_slice(&4242u16.to_be_bytes());
    p.extend_from_slice(&9u16.to_be_bytes());
    p.extend_from_slice(&((8 + charge.len()) as u16).to_be_bytes());
    // Somme UDP a zero: permise en IPv4, et ce qui est mesure ici est le
    // passage a la pile, pas la validation d'un en-tete de transport.
    p.extend_from_slice(&[0, 0]);
    p.extend_from_slice(charge);
    p
}

/// L'enveloppe se construit sur une vraie interface et en garde le nom.
#[tokio::test]
async fn l_enveloppe_prend_le_tun_et_garde_son_nom() {
    if let Some(raison) = raison_de_sauter() {
        println!("SKIPPED: {raison}");
        return;
    }
    let brut = brut::ouvrir_avec("bfp-win0", &GUID_PASSEUR[0], brut::ANNEAU)
        .expect("l'interface doit s'ouvrir");
    let tun = Tun::nouveau(brut).expect("l'enveloppe doit se construire");
    assert_eq!(tun.nom(), "bfp-win0");
}

/// Attendre un paquet n'arrete pas l'ordonnanceur.
///
/// C'est la propriete qui porte tout le reste: si l'attente du fil de veille
/// remontait jusqu'a l'ordonnanceur, ce n'est pas une tache qui s'arreterait
/// mais le daemon entier, kill switch compris.
///
/// # Une premiere version supposait le silence, et la mesure l'a dementie
///
/// Elle ouvrait l'interface et attendait que la lecture expire. Rouge sur
/// dev-windows le 19 aout 2026: `Ok(Ok(64))`, un paquet de 64 octets rendu tout
/// de suite. Une interface Wintun neuve n'est donc pas forcement silencieuse -
/// Windows peut y emettre des qu'elle apparait. Et ce n'est pas regulier: la
/// mesure suivante, sur la meme machine, n'a rien vu venir du tout.
///
/// D'ou cette forme: purger ce que le systeme a a dire, s'il a quelque chose,
/// puis ne mesurer l'attente que sur un anneau reellement vide. Une recette qui
/// depend de l'humeur de Windows ne dit rien sur ce code.
#[tokio::test]
async fn attendre_un_paquet_n_arrete_pas_l_ordonnanceur() {
    if let Some(raison) = raison_de_sauter() {
        println!("SKIPPED: {raison}");
        return;
    }
    let brut = brut::ouvrir_avec("bfp-win1", &GUID_PASSEUR[1], brut::ANNEAU)
        .expect("l'interface doit s'ouvrir");
    let mut tun = Tun::nouveau(brut).expect("l'enveloppe doit se construire");
    let mut tampon = vec![0u8; 2048];

    // Purge: lire ce que Windows dit de lui-meme, jusqu'a ce que l'anneau se
    // taise. La borne evite qu'une interface bavarde fasse tourner sans fin.
    let mut vus = 0u32;
    let mut silence = false;
    for _ in 0..50 {
        match tokio::time::timeout(Duration::from_millis(100), tun.read(&mut tampon)).await {
            Err(_) => {
                silence = true;
                break;
            }
            Ok(Ok(n)) => {
                if vus == 0 {
                    // Pour la trace: savoir CE QUE Windows emet sur une
                    // interface neuve vaut mieux que de le supposer.
                    println!(
                        "premier paquet emis par le systeme: {n} octets, version IP {}",
                        tampon[0] >> 4
                    );
                }
                vus += 1;
            }
            Ok(Err(e)) => panic!("la lecture ne doit pas echouer: {e}"),
        }
    }
    assert!(
        silence,
        "l'interface n'a jamais cesse d'emettre en 50 lectures: l'attente ne peut \
         pas etre mesuree ici"
    );
    println!("{vus} paquets emis par le systeme avant le silence");

    // L'anneau est vide: c'est maintenant que l'attente se mesure.
    let temoin = tokio::spawn(async {
        // Si l'ordonnanceur etait arrete, ce compteur ne bougerait pas.
        let mut tours = 0u32;
        for _ in 0..20 {
            tokio::time::sleep(Duration::from_millis(10)).await;
            tours += 1;
        }
        tours
    });

    let issue = tokio::time::timeout(Duration::from_millis(150), tun.read(&mut tampon)).await;
    assert!(
        issue.is_err(),
        "sur un anneau vide, la lecture doit faire attendre et non rendre la main: {issue:?}"
    );
    assert_eq!(
        temoin.await.expect("le temoin doit avoir tourne"),
        20,
        "l'ordonnanceur a continue de servir les autres taches pendant l'attente"
    );
}

/// Ce qu'on ecrit par l'enveloppe entre dans la pile.
///
/// Le compteur d'entree de l'interface plutot qu'une socket, pour la raison que
/// la moitie Linux a deja mesuree: une socket mesurerait le pare-feu de l'hote.
#[tokio::test]
async fn un_paquet_ecrit_par_l_enveloppe_entre_dans_la_pile() {
    if let Some(raison) = raison_de_sauter() {
        println!("SKIPPED: {raison}");
        return;
    }
    let brut = brut::ouvrir_avec("bfp-win2", &GUID_PASSEUR[2], brut::ANNEAU)
        .expect("l'interface doit s'ouvrir");
    let luid = brut.luid();
    let mut tun = Tun::nouveau(brut).expect("l'enveloppe doit se construire");

    let paquet = datagramme(b"bifrost");
    let avant = paquets_entrants(luid);
    tun.write_all(&paquet)
        .await
        .expect("l'enveloppe doit accepter le paquet");

    // Le compteur est mis a jour par le pilote de facon asynchrone: on lui
    // laisse un instant plutot que de mesurer la vitesse de Windows.
    let mut apres = avant;
    for _ in 0..50 {
        apres = paquets_entrants(luid);
        if apres > avant {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        apres > avant,
        "le systeme devait compter un paquet entrant sur cette interface \
         ({avant} puis {apres})"
    );
}

/// L'arret rend la main, et il la rend vite.
///
/// La propriete la plus importante de ce fichier. Le fil de veille attend un
/// evenement sans delai; s'il n'etait reveille que par l'arrivee d'un paquet, la
/// deconnexion resterait suspendue jusqu'a ce que le reseau veuille bien parler
/// - c'est-a-dire indefiniment sur une interface silencieuse. Et si la session
/// etait terminee AVANT que le fil soit sorti, ce ne serait pas une attente mais
/// un fil a l'interieur d'une session detruite.
///
/// La recette monte et demonte plusieurs fois: une seule fois passerait aussi
/// pour une liberation qui n'a pas lieu.
#[tokio::test]
async fn l_arret_reveille_le_fil_de_veille_et_ne_traine_pas() {
    if let Some(raison) = raison_de_sauter() {
        println!("SKIPPED: {raison}");
        return;
    }
    // Sur un fil bloquant: `Drop` joint le fil de veille, ce qu'une tache
    // asynchrone ne doit pas faire directement.
    let issue = tokio::time::timeout(
        Duration::from_secs(10),
        tokio::task::spawn_blocking(|| {
            for tour in 0..5u8 {
                let nom = format!("bfp-win-a{tour}");
                let guid =
                    GUID::from_u128(0x0bd4f5a1_6c1e_4f8d_9a3e_2f7b41c9e550 + u128::from(tour));
                let brut = brut::ouvrir_avec(&nom, &guid, brut::ANNEAU)
                    .expect("l'interface doit s'ouvrir");
                let tun = Tun::nouveau(brut).expect("l'enveloppe doit se construire");
                // C'est la chute de `tun` qui doit reveiller le fil, l'attendre,
                // et seulement ensuite laisser la session se terminer.
                drop(tun);
            }
        }),
    )
    .await;

    match issue {
        Ok(Ok(())) => {}
        Ok(Err(e)) => panic!("le montage-demontage a echoue: {e}"),
        Err(_) => panic!(
            "cinq montages-demontages n'ont pas tenu en dix secondes: l'arret \
             n'atteint pas le fil de veille"
        ),
    }
}

/// Le compte que le faux coeur de ce fichier exige.
///
/// Valeurs de recette et non de production: elles n'ouvrent rien ailleurs que
/// dans ce processus, ou le faux coeur les compare a ce que le passeur envoie.
fn compte() -> Identifiants {
    Identifiants::nouveaux("passeur-windows", "mot-de-recette")
        .expect("des identifiants de recette doivent tenir dans la RFC 1929")
}

/// Une cle acceptable par le format, et rien de plus.
///
/// Le portage de ce tunnel est declare WireGuard parce que c'est le seul qui
/// laisse choisir les prefixes routes: [`bifrost_daemon::tunnel::wgnt::routes`]
/// donne au chemin par coeur `0.0.0.0/0`, sans exception. Une recette qui
/// prendrait toute la famille couperait le reseau de la machine qui la lance -
/// ce que ce fichier promet en en-tete de ne pas faire. Aucun WireGuard n'est
/// monte ici: la cle ne sert qu'a satisfaire le type.
fn cle_de_forme() -> WgKey {
    let mut s: String = std::iter::repeat_n('a', 42).collect();
    s.push('A');
    s.push('=');
    s.parse().expect("cle de forme canonique")
}

/// La poignee de main de la RFC 1929, du cote du coeur.
///
/// Rend `false` si le passeur ne s'est pas presente ou s'est mal presente, et
/// dans ce cas le lien se ferme comme la RFC l'exige. C'est ce qui fait du faux
/// coeur un juge et non un complice: un passeur qui cesserait de se presenter
/// ferait rougir la recette.
async fn authentifier(flux: &mut TcpStream, attendu: &Identifiants) -> bool {
    // Salutation: version, nombre de methodes, puis les methodes.
    let mut debut = [0u8; 2];
    if flux.read_exact(&mut debut).await.is_err() {
        return false;
    }
    let mut methodes = vec![0u8; debut[1] as usize];
    if flux.read_exact(&mut methodes).await.is_err() {
        return false;
    }
    if !methodes.contains(&0x02) {
        // Pas de methode commune: la RFC 1928 veut 0xFF puis la fermeture.
        let _ = flux.write_all(&[0x05, 0xFF]).await;
        return false;
    }
    if flux.write_all(&[0x05, 0x02]).await.is_err() {
        return false;
    }

    // Sous-negociation: version, longueur du nom, nom, longueur du mot, mot.
    let mut version = [0u8; 1];
    if flux.read_exact(&mut version).await.is_err() || version[0] != 0x01 {
        return false;
    }
    let Some(nom) = champ_precede_de_sa_longueur(flux).await else {
        return false;
    };
    let Some(mot) = champ_precede_de_sa_longueur(flux).await else {
        return false;
    };

    let bon = nom == attendu.utilisateur() && mot == attendu.mot_de_passe();
    let _ = flux.write_all(&[0x01, u8::from(!bon)]).await;
    bon
}

/// Un octet de longueur, puis autant d'octets.
async fn champ_precede_de_sa_longueur(flux: &mut TcpStream) -> Option<String> {
    let mut n = [0u8; 1];
    flux.read_exact(&mut n).await.ok()?;
    let mut champ = vec![0u8; n[0] as usize];
    flux.read_exact(&mut champ).await.ok()?;
    String::from_utf8(champ).ok()
}

/// Un faux coeur: il parle SOCKS5, dit ou on lui a demande d'aller, puis
/// renvoie ce qu'on lui envoie prefixe de son etiquette.
///
/// Ecrit ici plutot qu'emprunte a la moitie Linux: deux fichiers de `tests/`
/// sont deux binaires, ils ne partagent rien. Ce qu'il fait est le meme, et
/// pour la meme raison - un vrai coeur ne raconte pas vers QUELLE destination
/// il a recu un CONNECT.
async fn coeur_fictif(attendu: Identifiants) -> (SocketAddr, mpsc::UnboundedReceiver<SocketAddr>) {
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
                    let _ = flux.write_all(b"C:").await;
                    let _ = flux.write_all(&tampon[..n]).await;
                    let _ = flux.flush().await;
                }
            });
        }
    });
    (adresse, entendre)
}

/// Le tunnel de recette: un `/24` prive, et rien d'autre.
///
/// `mtu` vaut celle que le passeur recevra: en production les deux viennent du
/// meme profil, et les laisser diverger ici mesurerait un desaccord que le
/// produit n'a pas.
///
/// `octet` distingue les recettes: elles tournent en parallele dans le meme
/// processus, et sans lui la seconde demanderait un sous-reseau deja route.
fn tunnel_de_recette_dans(nom: &str, mtu: u32, octet: u8) -> TunnelConfig {
    TunnelConfig {
        interface: nom.to_owned(),
        addresses: vec![format!("10.78.{octet}.1/24").parse().unwrap()],
        mtu,
        dns: DnsPolicy {
            local_resolver: IpAddr::V4(Ipv4Addr::LOCALHOST),
            upstream: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
            embarque: false,
            anti_telemetrie: bifrost_core::config::ProfilTelemetrie::Aucun,
        },
        allow_lan: false,
        portage: Portage::Wireguard(Box::new(WireguardParams {
            private_key: cle_de_forme(),
            fwmark: DEFAULT_FWMARK,
            routing_table: DEFAULT_ROUTING_TABLE,
            listen_port: None,
            peer: PeerConfig {
                public_key: cle_de_forme(),
                preshared_key: None,
                endpoint: Endpoint {
                    addr: "203.0.113.7:51820".parse().unwrap(),
                },
                // LE point de cette configuration: ce prefixe-la, et pas la
                // famille entiere.
                allowed_ips: vec![format!("10.78.{octet}.0/24").parse().unwrap()],
                persistent_keepalive: 25,
            },
        })),
    }
}

/// L'homologue Windows du test qui vaut pour tous les autres: une connexion
/// ordinaire, emise par le systeme vers une adresse routee par le TUN, ressort
/// en CONNECT SOCKS5 vers cette meme adresse, et les octets font
/// L'ALLER-RETOUR.
///
/// Le retour est ce qui est vraiment en jeu, et il merite d'etre nomme: le banc
/// du 21 aout 2026 a vu l'aller aboutir - la poignee de main TCP se fait, la
/// requete arrive au serveur, qui repond - sans que la reponse revienne jamais
/// a l'application. Une recette qui ne verifierait que le CONNECT serait verte
/// sur ce defaut-la.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn une_connexion_du_systeme_fait_l_aller_retour_par_le_coeur() {
    if let Some(raison) = raison_de_sauter() {
        println!("SKIPPED: {raison}");
        return;
    }
    const NOM: &str = "bfp-win3";
    let cible: SocketAddr = "10.78.90.5:80".parse().unwrap();

    let brut =
        brut::ouvrir_avec(NOM, &GUID_PASSEUR[3], brut::ANNEAU).expect("l'interface doit s'ouvrir");
    let luid = brut.luid();
    let cfg = tunnel_de_recette_dans(NOM, u32::from(passeur::MTU), 90);
    ipcfg::apply(luid, &cfg).expect("l'interface doit s'adresser et se router");

    let (coeur, mut vues) = coeur_fictif(compte()).await;
    let passage = Tun::nouveau(brut).expect("le TUN doit devenir asynchrone");
    tokio::spawn(passeur::servir(
        passage,
        Mandataire::nouveau(coeur, compte()),
        passeur::MTU,
    ));

    let echange = async {
        let mut flux = TcpStream::connect(cible).await?;
        flux.write_all(b"salut").await?;
        flux.flush().await?;
        // `read_exact` et non `read`: TCP rend des morceaux, pas des messages,
        // et le faux coeur ecrit son etiquette puis la charge.
        let mut recu = [0u8; 7];
        flux.read_exact(&mut recu).await?;
        std::io::Result::Ok(String::from_utf8_lossy(&recu).into_owned())
    };
    let issue = tokio::time::timeout(Duration::from_secs(10), echange).await;

    // Le CONNECT est lu AVANT de juger l'echange: c'est lui qui distingue un
    // aller qui n'est jamais parti d'un retour qui n'est jamais revenu, et sans
    // cette lecture le message d'echec ne saurait pas dire lequel des deux.
    let vu = vues.try_recv().ok();
    let recu = match issue {
        Ok(Ok(recu)) => recu,
        Ok(Err(e)) => panic!("la connexion a echoue ({e}), CONNECT vu: {vu:?}"),
        Err(_) => panic!(
            "rien n'est revenu en dix secondes. CONNECT vu par le coeur: {vu:?} - \
             s'il y en a un, l'aller est parti et c'est le RETOUR qui manque"
        ),
    };

    assert_eq!(
        recu, "C:salut",
        "les octets doivent traverser dans les deux sens"
    );
    assert_eq!(
        vu,
        Some(cible),
        "le CONNECT doit viser la destination D'ORIGINE, celle que l'application avait choisie"
    );
}

/// Un faux coeur qui repond une fois puis RACCROCHE.
///
/// C'est le comportement de tout serveur qui delimite sa reponse par la
/// fermeture: HTTP/1.0 sans `Content-Length`, et la moitie des protocoles de
/// requete-reponse. Celui de [`coeur_fictif`] ne raccroche jamais, il ne
/// pouvait donc pas voir ce que la recette suivante mesure.
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
                // En-tete puis adresse: ni l'une ni l'autre ne sert ici, mais
                // il faut les consommer pour rester en phase.
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
/// La propriete est la meme que celle de la moitie Linux, et le defaut qu'elle
/// a attrape ne devait rien a la plateforme - il est dans la pile en espace
/// utilisateur, commune aux deux. Elle est refaite ici parce que le CHEMIN,
/// lui, differe: sous Windows le paquet de fermeture traverse le fil de veille
/// et le canal de [`bifrost_daemon::coeurs::passeur`], et un FIN est le plus
/// petit paquet qui existe. Ce qui vaut pour 208 octets ne vaut pas de soi pour
/// zero.
///
/// C'est aussi la recette qui rejoue, en trente secondes et sans couper le
/// reseau, ce que le banc a mis un quart d'heure a mesurer le 21 aout 2026.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn quand_le_coeur_raccroche_l_application_voit_la_fin_du_flux() {
    if let Some(raison) = raison_de_sauter() {
        println!("SKIPPED: {raison}");
        return;
    }
    const NOM: &str = "bfp-win4";
    let cible: SocketAddr = "10.78.91.5:80".parse().unwrap();

    let brut =
        brut::ouvrir_avec(NOM, &GUID_PASSEUR[4], brut::ANNEAU).expect("l'interface doit s'ouvrir");
    let luid = brut.luid();
    let cfg = tunnel_de_recette_dans(NOM, u32::from(passeur::MTU), 91);
    ipcfg::apply(luid, &cfg).expect("l'interface doit s'adresser et se router");

    let coeur = coeur_qui_raccroche(compte()).await;
    let passage = Tun::nouveau(brut).expect("le TUN doit devenir asynchrone");
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
    let tout = tokio::time::timeout(Duration::from_secs(10), echange)
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
