//! Sondes qui remplissent l'`Environnement` que `bifrost-evasion` consomme.
//!
//! Le crate de selection ne conclut rien d'une sonde qui n'a pas tourne. Toute
//! la valeur de ce module tient donc dans sa capacite a distinguer trois
//! choses que le reseau presente souvent de la meme facon: "ca passe", "c'est
//! filtre", et "je n'ai pas pu savoir".
//!
//! Le moyen de les distinguer est un temoin. Un echec de connexion sur 443 ne
//! prouve rien tout seul: une machine debranchee produit exactement le meme
//! symptome qu'un port filtre. Le document 04 partie 3.1 le dit en passant en
//! prescrivant d'essayer "443, 80, puis un port haut"; c'est le port 80 qui
//! sert d'arbitre. Sans lui, un cable debranche se lirait comme une censure, et
//! la selection eliminerait des protocoles sur la foi d'un incident materiel.
//!
//! Le partage habituel de ce depot est reconduit: l'interpretation est pure et
//! testee partout, les sockets sont a cote.

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::net::SocketAddr;
use std::time::Duration;

use bifrost_evasion::environnement::{Environnement, Mesure};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

/// Budget total du sondage. Document 04 partie 3.1: moins de cinq secondes.
/// Les sondes tournent en parallele, donc ce budget est aussi celui de la plus
/// lente d'entre elles.
pub const BUDGET: Duration = Duration::from_secs(5);

/// Delai au-dela duquel une tentative est declaree expiree.
pub const DELAI_TENTATIVE: Duration = Duration::from_millis(1_500);

/// Ce qu'une tentative a donne, avant toute interpretation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tentative {
    /// La cible a repondu.
    Aboutie,
    /// La cible a refuse franchement: RST, ICMP port unreachable.
    Refusee,
    /// Rien n'est revenu avant l'echeance.
    Expiree,
    /// La tentative n'a pas pu etre faite: pas de cible fournie, adresse
    /// invalide, pile reseau indisponible. Ce n'est PAS un echec du reseau.
    Impossible,
}

impl Tentative {
    /// La tentative a-t-elle vraiment eu lieu.
    ///
    /// Publique parce que la sonde QUIC arbitre ses deux paquets de la meme
    /// facon: un silence n'apprend rien tant qu'on ne sait pas si le paquet est
    /// seulement parti.
    pub fn a_pu_etre_faite(self) -> bool {
        !matches!(self, Tentative::Impossible)
    }
}

/// Reponse HTTP de la sonde de portail captif.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReponseHttp {
    /// Le 204 attendu, sans corps: aucun portail ne s'interpose.
    Vide204,
    /// Autre chose: une redirection ou une page, donc quelqu'un repond a la
    /// place de la cible.
    Autre,
}

/// Le reseau donne-t-il signe de vie.
///
/// Sans cette reponse, aucune autre sonde ne conclut. C'est le temoin negatif
/// du module, et il joue exactement le role du temoin de la sonde d'identite
/// WFP: prouver que l'absence de reponse veut dire quelque chose.
pub fn conclure_temoin(tentatives: &[Tentative]) -> Mesure<bool> {
    if tentatives.contains(&Tentative::Aboutie) {
        return Mesure::Vu(true);
    }
    if tentatives.iter().any(|t| t.a_pu_etre_faite()) {
        return Mesure::Vu(false);
    }
    Mesure::NonMesure
}

/// Interprete une serie de tentatives a la lumiere du temoin.
///
/// Une seule reussite suffit a conclure positivement: une cible peut etre en
/// panne, le reseau ne l'est pas pour autant. A l'inverse, il faut que TOUTES
/// aient echoue ET que le reseau soit vivant pour conclure a un filtrage.
pub fn conclure_avec_temoin(tentatives: &[Tentative], temoin: Mesure<bool>) -> Mesure<bool> {
    if tentatives.contains(&Tentative::Aboutie) {
        return Mesure::Vu(true);
    }
    if !tentatives.iter().any(|t| t.a_pu_etre_faite()) {
        return Mesure::NonMesure;
    }
    // Le coeur du module: sans reseau vivant, un echec n'apprend rien.
    match temoin {
        Mesure::Vu(true) => Mesure::Vu(false),
        Mesure::Vu(false) | Mesure::NonMesure => Mesure::NonMesure,
    }
}

/// Un portail captif se detecte a ce qu'il REPOND, pas a ce qu'il bloque.
///
/// L'absence de reponse ne le designe donc pas: c'est le seul cas du module ou
/// le temoin n'a rien a arbitrer.
pub fn conclure_portail(reponse: Option<ReponseHttp>) -> Mesure<bool> {
    match reponse {
        Some(ReponseHttp::Vide204) => Mesure::Vu(false),
        Some(ReponseHttp::Autre) => Mesure::Vu(true),
        None => Mesure::NonMesure,
    }
}

/// Taille du paquet QUIC que quic-go emet tant que rien ne la reduit, cote
/// client comme cote serveur.
pub const PAQUET_QUIC: usize = 1280;

/// Sel prefixe a chaque datagramme par l'obfuscation Salamander de Hysteria2.
pub const SEL_SALAMANDER: usize = 8;

/// En-tetes IPv4 et UDP, sans option.
pub const ENTETES_IP_UDP: usize = 28;

/// Datagramme temoin: assez court pour tenir sur n'importe quel chemin.
const TEMOIN_COURT: usize = 64;

/// Charge UDP d'un datagramme QUIC de pleine taille.
pub fn charge_utile_quic(obfusque: bool) -> usize {
    PAQUET_QUIC + if obfusque { SEL_SALAMANDER } else { 0 }
}

/// Paquet IP correspondant, en-tetes compris.
pub fn paquet_ip_quic(obfusque: bool) -> usize {
    charge_utile_quic(obfusque) + ENTETES_IP_UDP
}

/// Le chemin porte-t-il un datagramme QUIC de pleine taille sans le fragmenter.
///
/// Cette sonde ne mesure pas si QUIC est FILTRE, ce dont `quic_passe` se
/// charge, mais si le chemin est assez large pour lui. Les deux echouent de la
/// meme facon vues de loin, et se soignent de facons opposees.
///
/// Ce qu'elle mesure exactement: le lien local accepte-t-il de faire partir un
/// paquet de cette taille avec le bit DF pose. Elle ne dit rien d'un
/// retrecissement plus loin sur le chemin, qui se manifesterait par une perte
/// silencieuse. C'est deliberement la question la plus etroite, parce que
/// c'est celle qui a mordu: le 16 aout 2026, sur un chemin a 1280 de MTU, le
/// serveur Linux s'est vu REFUSER PAR SON PROPRE NOYAU l'`Initial` portant le
/// ServerHello.
///
/// | Charge UDP | Paquet IP | DF pose | DF absent |
/// |---|---|---|---|
/// | 1250 | 1278 | envoye | envoye |
/// | 1258 | 1286 | `EMSGSIZE` | envoye, fragmente |
/// | 1288 | 1316 | `EMSGSIZE` | envoye, fragmente |
///
/// L'asymetrie qui rend la panne muette: Windows ne pose pas DF, fragmente et
/// passe; Linux pose DF et n'emet rien. Le client reemet son `Initial`
/// indefiniment, n'obtient jamais les clefs de niveau Handshake, et la
/// connexion expire sans qu'aucune des deux extremites ne dise pourquoi.
///
/// Le temoin est indispensable: un envoi qui echoue pour cause de pile reseau
/// indisponible ressemble trait pour trait a un envoi refuse pour cause de
/// taille. Sans lui, une machine debranchee se lirait comme un chemin etroit.
pub fn sonder_chemin_quic(cible: SocketAddr, obfusque: bool) -> Mesure<bool> {
    let pleine_taille = tenter_datagramme_df(cible, charge_utile_quic(obfusque));
    let temoin = tenter_datagramme_df(cible, TEMOIN_COURT);
    conclure_chemin_quic(pleine_taille, temoin)
}

/// Interprete les deux envois. Pur, donc testable partout.
///
/// `Expiree` n'apparait pas: rien n'est attendu en retour, la sonde ne juge
/// que le depart.
pub fn conclure_chemin_quic(pleine_taille: Tentative, temoin: Tentative) -> Mesure<bool> {
    match (pleine_taille, temoin) {
        // Le gros est parti: la question est tranchee, le temoin n'a rien a
        // arbitrer.
        (Tentative::Aboutie, _) => Mesure::Vu(true),
        // Le gros a ete refuse ET le petit est parti: c'est bien la taille.
        (Tentative::Refusee, Tentative::Aboutie) => Mesure::Vu(false),
        // Tout le reste: le refus ne parle pas de taille, ou la sonde n'a pas
        // pu tourner. On n'en conclut rien, et le transport sera essaye.
        _ => Mesure::NonMesure,
    }
}

/// Envoie un datagramme de `taille` octets avec le bit DF pose.
///
/// La charge est nulle et la cible la jettera: ce qui est mesure est le
/// DEPART, pas l'arrivee. Synchrone a dessein, un `send` UDP ne dialogue avec
/// personne.
fn tenter_datagramme_df(cible: SocketAddr, taille: usize) -> Tentative {
    let liaison = if cible.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let Ok(socket) = std::net::UdpSocket::bind(liaison) else {
        return Tentative::Impossible;
    };
    if socket.connect(cible).is_err() {
        return Tentative::Impossible;
    }
    if !poser_df(&socket, cible.is_ipv4()) {
        return Tentative::Impossible;
    }
    match socket.send(&vec![0u8; taille]) {
        Ok(_) => Tentative::Aboutie,
        // Le noyau refuse, sans qu'on ait a nommer son code d'erreur: c'est le
        // temoin qui dira si ce refus parle de taille. Un `EMSGSIZE` et un
        // `ENETUNREACH` se distinguent par lui, pas par leur numero, qui n'est
        // le meme sur aucun systeme.
        Err(_) => Tentative::Refusee,
    }
}

/// Demande au noyau de ne PAS fragmenter, donc de refuser plutot que de
/// decouper. C'est ce que fait quic-go sur ses propres sockets, et c'est ce
/// qui doit etre reproduit ici pour mesurer la meme chose que lui.
#[cfg(target_os = "linux")]
fn poser_df(socket: &std::net::UdpSocket, v4: bool) -> bool {
    use std::os::fd::AsRawFd;

    let (niveau, option, valeur) = if v4 {
        (
            libc::IPPROTO_IP,
            libc::IP_MTU_DISCOVER,
            libc::IP_PMTUDISC_DO,
        )
    } else {
        (
            libc::IPPROTO_IPV6,
            libc::IPV6_MTU_DISCOVER,
            libc::IPV6_PMTUDISC_DO,
        )
    };
    let v: libc::c_int = valeur;
    // SAFETY: le descripteur appartient au socket vivant tenu par l'appelant,
    // et le pointeur designe un `c_int` de la taille annoncee.
    let r = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            niveau,
            option,
            std::ptr::from_ref(&v).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    r == 0
}

#[cfg(windows)]
fn poser_df(socket: &std::net::UdpSocket, v4: bool) -> bool {
    use std::os::windows::io::AsRawSocket;

    use windows_sys::Win32::Networking::WinSock::{
        IP_DONTFRAGMENT, IPPROTO_IP, IPPROTO_IPV6, IPV6_DONTFRAG, SOCKET, setsockopt,
    };

    let (niveau, option) = if v4 {
        (IPPROTO_IP, IP_DONTFRAGMENT)
    } else {
        (IPPROTO_IPV6, IPV6_DONTFRAG)
    };
    let actif: i32 = 1;
    // SAFETY: le handle appartient au socket vivant tenu par l'appelant, et le
    // pointeur designe un `i32` de la taille annoncee.
    let r = unsafe {
        setsockopt(
            socket.as_raw_socket() as SOCKET,
            niveau,
            option,
            std::ptr::from_ref(&actif).cast::<u8>(),
            std::mem::size_of::<i32>() as i32,
        )
    };
    r == 0
}

/// Ailleurs, la sonde s'abstient plutot que de mesurer autre chose: sans DF,
/// le noyau fragmenterait et l'envoi reussirait toujours, ce qui donnerait un
/// `Vu(true)` faux a tous les coups.
#[cfg(not(any(target_os = "linux", windows)))]
fn poser_df(_socket: &std::net::UdpSocket, _v4: bool) -> bool {
    false
}

/// Cibles du sondage. Aucune n'est codee en dur dans la logique: elles doivent
/// pouvoir changer sans nouvelle version du client, comme les profils.
#[derive(Debug, Clone)]
pub struct Cibles {
    /// Hotes a joindre en TCP/80. Temoin de vie du reseau.
    pub temoin_tcp80: Vec<SocketAddr>,
    /// Hotes a joindre en TCP/443.
    pub tcp443: Vec<SocketAddr>,
    /// Serveurs STUN. Ils repondent a deux questions a la fois: l'UDP sort-il,
    /// et sort-il sur un port autre que 80 ou 443. Il n'y a donc PAS de sonde
    /// de port haut separee, et ce n'est pas une simplification.
    ///
    /// Une premiere version en avait une, en TCP, et elle repondait a cote:
    /// les seules techniques que `ports_hauts_ouverts` conditionne parlent UDP,
    /// donc un port TCP haut joignable ne prouve rien pour elles. Pire, une
    /// cible ou personne n'ecoute rendait "ports hauts fermes" alors que le
    /// reseau ne filtrait rien. Le defaut ne se voyait pas en test unitaire,
    /// seulement en lancant la sonde sur une vraie machine.
    ///
    /// Reste hors de portee: l'endpoint du tunnel lui-meme. WireGuard ne
    /// repond rien a un datagramme invalide, donc son silence ne distingue pas
    /// un port filtre d'un serveur qui nous ignore. Le sonder demanderait une
    /// vraie initiation de handshake.
    pub stun: Vec<SocketAddr>,
    /// Point de detection de portail captif, en HTTP clair.
    pub portail: Option<(SocketAddr, String)>,
    /// Cibles QUIC, chacune avec le nom de serveur a annoncer.
    ///
    /// Le nom compte autant que l'adresse: le pare-feu chinois DECHIFFRE
    /// l'Initial et filtre sur lui. Un nom anodin mesure "QUIC passe-t-il"; un
    /// nom sensible mesurerait "ce nom-la est-il bloque" et declencherait, sur
    /// un reseau censeur, trois minutes de blocage residuel sur le triplet -
    /// voir l'en-tete de `crate::quic`.
    pub quic: Vec<(SocketAddr, String)>,
}

/// Nombre de sondes emises vers CHAQUE cible pour estimer la perte.
///
/// Le chiffre sort de la question posee, pas d'un gout. Le document 04 partie
/// 5 place la bascule a 5 % et decrit les regimes qui comptent: 5 %, puis
/// 20-30 %. Distinguer un reseau propre d'un reseau a 20 % demande une poignee
/// de tirs; distinguer 4 % de 6 % en demanderait des centaines, ne changerait
/// aucune decision, et ferait de cette sonde un scanner. Vingt-cinq tirs par
/// cible donnent une granularite de 4 %, et cinquante mis en commun de 2 %.
pub const TIRS_PAR_CIBLE: usize = 25;

/// Espacement entre deux tirs.
///
/// Une salve serree se ferait limiter par le serveur - les serveurs STUN
/// publics le font, sans jamais publier leurs seuils - et la limitation se
/// lirait comme de la perte. Soixante millisecondes est aussi l'ordre de
/// grandeur qu'un vrai client emploie entre deux retransmissions, donc la
/// salve reste dans l'enveloppe du trafic ordinaire.
pub const ESPACEMENT_DES_TIRS: Duration = Duration::from_millis(60);

/// En dessous de tant de tirs retenus, aucun chiffre n'est soutenable.
pub const TIRS_MINIMUM: usize = 20;

/// Une serie a-t-elle ete ECOURTEE par le serveur plutot que par le reseau.
///
/// La limitation de debit a une forme: elle laisse passer un debut puis coupe,
/// donc les pertes sont groupees en QUEUE. La perte reseau, elle, est
/// dispersee. Le test porte sur la queue seule et non sur la forme entiere: un
/// limiteur peut aussi laisser filtrer quelques reponses.
///
/// Il faut au moins une reponse: une serie entierement muette n'est pas une
/// limitation, c'est un silence, et il appartient a `udp_passe` de le dire.
///
/// Le cout de ce garde est assume: une perte reelle catastrophique peut finir
/// par une queue de sept echecs et se faire ecarter. On rend alors NonMesure
/// plutot qu'un chiffre, ce qui est le bon sens de ce depot - une mesure dont
/// on doute ne conclut pas.
pub fn serie_ecourtee(reponses: &[bool]) -> bool {
    if reponses.is_empty() || !reponses.contains(&true) {
        return false;
    }
    let queue = reponses.iter().rev().take_while(|r| !**r).count();
    queue * 4 >= reponses.len()
}

/// Le taux de perte que ces series soutiennent, ou rien.
///
/// Les series ecourtees sont ECARTEES et non moyennees: une cible qui limite
/// son debit ne dit rien du chemin, exactement comme une cible en panne ne dit
/// rien du reseau. Ce qui reste est mis en commun.
///
/// Une cible MUETTE est ecartee, et ce garde-la a ete pose apres coup, sur une
/// mesure. La liste des cibles contenait `1.1.1.1:3478` sous le commentaire
/// "stun.cloudflare.com"; cette adresse ne parle pas STUN, et personne ne s'en
/// etait apercu parce que `udp_passe` se contente d'UNE reussite dans la liste.
/// La sonde de perte est la premiere a interroger chaque cible SEPAREMENT: elle
/// a mis en commun vingt-cinq reponses et vingt-cinq silences, et annonce 50 %
/// de perte sur un lien filaire parfaitement sain. C'est la meme asymetrie que
/// partout ailleurs ici - une cible en panne ne dit rien du reseau - et elle
/// manquait.
///
/// Si toutes les cibles se taisent, la mise en commun tombe sous
/// [`TIRS_MINIMUM`] et rien n'est conclu. Cent pour cent de perte n'existe pas
/// comme regime de reseau: c'est un UDP coupe, et `udp_passe` porte deja cette
/// question. Le rendre ferait franchir le seuil de bascule et promouvoir
/// Hysteria2 - un protocole UDP - sur un reseau ou l'UDP ne passe pas du tout.
pub fn conclure_perte(series: &[Vec<bool>]) -> Mesure<u8> {
    let retenues: Vec<&Vec<bool>> = series
        .iter()
        .filter(|s| s.contains(&true) && !serie_ecourtee(s))
        .collect();
    let total: usize = retenues.iter().map(|s| s.len()).sum();
    if total < TIRS_MINIMUM {
        return Mesure::NonMesure;
    }
    // Chaque serie retenue porte au moins une reponse, donc `recus` ne peut
    // pas etre nul ici. Le filtre au-dessus est le seul garde, et il n'y en a
    // pas de second qui donnerait l'illusion d'une ceinture.
    let recus: usize = retenues
        .iter()
        .map(|s| s.iter().filter(|r| **r).count())
        .sum();
    let perdus = total - recus;
    // Arrondi au plus proche, et non par defaut: a 5 % pres du seuil, tronquer
    // deciderait systematiquement dans le meme sens.
    Mesure::Vu(((perdus * 100 + total / 2) / total) as u8)
}

/// Un port compte comme haut des lors qu'il n'est ni 80 ni 443, ce qui est
/// exactement la frontiere que `Transport::tient_sur_80_443` trace de l'autre
/// cote. Les deux definitions doivent rester les memes, sinon la selection
/// eliminerait des techniques sur une mesure qui parle d'autre chose.
pub fn est_port_haut(port: u16) -> bool {
    port != 80 && port != 443
}

impl Cibles {
    /// Cibles par defaut. Publiques, stables, et deliberement banales: une
    /// adresse exotique serait elle-meme un signal pour un observateur.
    pub fn par_defaut() -> Self {
        Self {
            temoin_tcp80: vec!["1.1.1.1:80".parse().unwrap(), "8.8.8.8:80".parse().unwrap()],
            tcp443: vec![
                "1.1.1.1:443".parse().unwrap(),
                "8.8.8.8:443".parse().unwrap(),
            ],
            stun: vec![
                "74.125.250.129:19302".parse().unwrap(), // stun.l.google.com
                // Corrige le 20 aout 2026. La liste portait `1.1.1.1:3478`
                // sous ce meme commentaire; cette adresse-la ne parle pas
                // STUN, et `stun.cloudflare.com` resout sur celle-ci. Le
                // defaut a survecu parce que `udp_passe` se contente d'une
                // reussite dans la liste: la moitie des preuves d'UDP etait
                // fabriquee. La sonde de perte l'a rendu visible en
                // interrogeant chaque cible separement.
                "162.159.207.0:3478".parse().unwrap(), // stun.cloudflare.com
            ],
            portail: Some((
                "1.1.1.1:80".parse().unwrap(),
                "http://cp.cloudflare.com/generate_204".to_string(),
            )),
            // Les deux resolveurs publics deja vises plus haut, qui servent
            // aussi DoH sur HTTP-3. Les noms sont les leurs, et sont d'une
            // banalite recherchee: ce sont ceux que des millions de machines
            // annoncent chaque jour.
            quic: vec![
                (
                    "1.1.1.1:443".parse().unwrap(),
                    "cloudflare-dns.com".to_string(),
                ),
                ("8.8.8.8:443".parse().unwrap(), "dns.google".to_string()),
            ],
        }
    }
}

/// Ce que le sondage a mesure, et ce qu'il n'a pas pu mesurer.
#[derive(Debug, Clone)]
pub struct Rapport {
    pub environnement: Environnement,
    /// Pour chaque champ laisse a `NonMesure`, la raison. Le journal doit
    /// pouvoir dire pourquoi une sonde n'a rien rendu, sinon un sondage muet
    /// est indistinguable d'un sondage reussi qui n'a rien trouve.
    pub non_mesures: Vec<(&'static str, &'static str)>,
    /// Ce qu'une mesure dit EN PLUS de sa valeur.
    ///
    /// Un booleen ne porte qu'une conclusion, et deux causes tres differentes
    /// peuvent y mener. `quic_passe = false` parce que l'UDP est coupe et
    /// `quic_passe = false` parce qu'un censeur lit le SNI appellent la meme
    /// decision - ne pas compter sur QUIC - et un diagnostic tout autre. Sans
    /// cet endroit, la distinction serait mesuree puis jetee.
    pub remarques: Vec<(&'static str, String)>,
}

/// Lance toutes les sondes en parallele et rend l'environnement.
pub async fn sonder(cibles: &Cibles) -> Rapport {
    let (t80, t443, stun, portail, quic, series) = tokio::join!(
        essayer_tcp(&cibles.temoin_tcp80),
        essayer_tcp(&cibles.tcp443),
        essayer_stun(&cibles.stun),
        async {
            match &cibles.portail {
                Some((a, url)) => tenter_portail(*a, url).await,
                None => None,
            }
        },
        essayer_quic(&cibles.quic),
        mesurer_la_perte(&cibles.stun)
    );

    let temoin = conclure_temoin(&t80);
    let mut non_mesures = Vec::new();

    let toutes_stun: Vec<Tentative> = stun.iter().map(|(_, t)| *t).collect();
    let stun_port_haut: Vec<Tentative> = stun
        .iter()
        .filter(|(p, _)| est_port_haut(*p))
        .map(|(_, t)| *t)
        .collect();

    let (quic_negociation, quic_initial) = quic;
    let tcp443_passe = conclure_avec_temoin(&t443, temoin);
    let udp_passe = conclure_avec_temoin(&toutes_stun, temoin);
    let ports_hauts_ouverts = conclure_avec_temoin(&stun_port_haut, temoin);
    let portail_captif = conclure_portail(portail);

    if !temoin.est_mesure() {
        non_mesures.push(("temoin", "aucune tentative TCP/80 n'a pu etre faite"));
    } else if temoin.vu_faux() {
        non_mesures.push((
            "temoin",
            "le reseau ne repond pas du tout: aucune autre sonde ne conclut",
        ));
    }
    if !tcp443_passe.est_mesure() {
        non_mesures.push(("tcp443_passe", "echecs non arbitres par le temoin"));
    }
    if !udp_passe.est_mesure() {
        non_mesures.push(("udp_passe", "echecs STUN non arbitres par le temoin"));
    }
    if !ports_hauts_ouverts.est_mesure() {
        non_mesures.push((
            "ports_hauts_ouverts",
            "aucun serveur STUN sur un port autre que 80 ou 443, ou echec non arbitre",
        ));
    }
    if !portail_captif.est_mesure() {
        non_mesures.push(("portail_captif", "aucune reponse HTTP exploitable"));
    }

    let quic_passe = crate::quic::conclure(quic_negociation, quic_initial, temoin);
    if !quic_passe.est_mesure() {
        non_mesures.push((
            "quic_passe",
            "aucun paquet QUIC n'a pu partir, ou leur silence n'est pas arbitre par le temoin",
        ));
    }
    let mut remarques: Vec<(&'static str, String)> = Vec::new();
    if crate::quic::contenu_filtre(quic_negociation, quic_initial) {
        remarques.push((
            "quic_passe",
            "la negociation de version repond mais l'Initial version 1 reste muet: \
             le CONTENU est filtre, donc un observateur dechiffre le paquet et lit le \
             nom de serveur. La version 2 de QUIC passerait, elle"
                .to_owned(),
        ));
    }

    // Cette sonde-la EXISTE, et elle ne tourne pas ici. Une poignee de main
    // TLS parse des donnees choisies par le pair dans un processus qui tourne
    // en root, ce que `tests/frontiere_reseau.rs` interdit avec ses raisons.
    // Elle vit donc du cote non privilegie, dans le client. Ce rapport-ci
    // reste muet parce qu'il ne mesure QUE ce que ce processus mesure; le
    // verdict, lui, rejoint la `Decision` du superviseur par l'IPC.
    non_mesures.push((
        "mitm_tls",
        "mesuree hors du processus privilegie - une pile TLS n'a rien a faire \
         dans un daemon qui tourne en root - et annoncee au daemon par \
         `bifrost-cli inspection-tls --annoncer`",
    ));

    let perte_pourcent = conclure_perte(&series);
    if !perte_pourcent.est_mesure() {
        non_mesures.push((
            "perte_pourcent",
            "pas assez de tirs retenus: cibles muettes, ou series ecourtees par une \
             limitation de debit du serveur plutot que par le reseau",
        ));
    }

    Rapport {
        environnement: Environnement {
            tcp443_passe,
            udp_passe,
            quic_passe,
            ports_hauts_ouverts,
            mitm_tls: Mesure::NonMesure,
            portail_captif,
            perte_pourcent,
        },
        non_mesures,
        remarques,
    }
}

/// Sonde chaque cible QUIC et retient la MEILLEURE reponse de chaque sorte.
///
/// Une cible peut etre en panne sans que le reseau filtre quoi que ce soit,
/// exactement comme pour TCP: une seule reussite suffit a conclure
/// positivement. C'est la meme asymetrie que `conclure_avec_temoin`.
async fn essayer_quic(cibles: &[(SocketAddr, String)]) -> (Tentative, Tentative) {
    if cibles.is_empty() {
        return (Tentative::Impossible, Tentative::Impossible);
    }
    let mut negociation = Tentative::Impossible;
    let mut initial = Tentative::Impossible;
    for (adresse, nom) in cibles {
        let mut alea = [0u8; crate::quic::OCTETS_D_ALEA];
        if crate::coeurs::alea::octets(&mut alea).is_err() {
            continue;
        }
        let (n, i) = crate::quic::sonder(*adresse, nom, &alea).await;
        negociation = meilleure(negociation, n);
        initial = meilleure(initial, i);
        if initial == Tentative::Aboutie {
            // Inutile d'insister: une reussite tranche, et chaque paquet de
            // plus est un paquet de plus dans la trace de ce client.
            break;
        }
    }
    (negociation, initial)
}

/// Entre deux tentatives, celle qui en apprend le plus.
///
/// Une reussite l'emporte sur tout; un silence l'emporte sur "je n'ai pas pu
/// essayer", parce qu'un silence est au moins une observation.
fn meilleure(a: Tentative, b: Tentative) -> Tentative {
    let rang = |t: Tentative| match t {
        Tentative::Aboutie => 3,
        Tentative::Refusee => 2,
        Tentative::Expiree => 1,
        Tentative::Impossible => 0,
    };
    if rang(b) > rang(a) { b } else { a }
}

async fn essayer_tcp(cibles: &[SocketAddr]) -> Vec<Tentative> {
    if cibles.is_empty() {
        return vec![Tentative::Impossible];
    }
    let mut sorties = Vec::with_capacity(cibles.len());
    for c in cibles {
        sorties.push(tenter_tcp(*c).await);
    }
    sorties
}

async fn tenter_tcp(cible: SocketAddr) -> Tentative {
    match tokio::time::timeout(DELAI_TENTATIVE, TcpStream::connect(cible)).await {
        Ok(Ok(_)) => Tentative::Aboutie,
        // Un refus franc distingue "quelqu'un a repondu non" de "rien n'est
        // revenu". Les deux comptent comme un echec ici, mais la difference est
        // conservee pour le journal.
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => Tentative::Refusee,
        Ok(Err(_)) => Tentative::Expiree,
        Err(_) => Tentative::Expiree,
    }
}

/// Envoie une requete STUN Binding et attend une reponse qui lui corresponde.
///
/// La correspondance n'est pas un detail: sur un reseau bavard, un datagramme
/// quelconque arrivant sur le socket compterait comme une reponse et ferait
/// conclure a tort que l'UDP sort.
/// Rend le port de chaque cible avec son resultat: le meme essai sert a la
/// fois a l'UDP en general et aux ports hauts en particulier.
async fn essayer_stun(cibles: &[SocketAddr]) -> Vec<(u16, Tentative)> {
    if cibles.is_empty() {
        return vec![(0, Tentative::Impossible)];
    }
    let mut sorties = Vec::with_capacity(cibles.len());
    for c in cibles {
        sorties.push((c.port(), tenter_stun(*c).await));
    }
    sorties
}

/// Mesure la perte vers chaque cible, en parallele.
///
/// Les memes serveurs STUN que la sonde d'UDP: aucune destination de plus dans
/// la trace de ce client, et le bon transport - la decision que ce chiffre
/// alimente est de promouvoir ou non un protocole UDP.
async fn mesurer_la_perte(cibles: &[SocketAddr]) -> Vec<Vec<bool>> {
    // Les salves tournent EN MEME TEMPS, et le premier jet les enchainait.
    // Le garde de budget a fait tomber la recette: deux salves de trois
    // secondes debordent des cinq du document 04 partie 3.1. La raison qui les
    // enchainait - deux salves melangees se perdraient l'une l'autre - ne
    // resiste pas au calcul: deux tirs toutes les soixante millisecondes font
    // trente-trois paquets par seconde de quarante-huit octets, soit un peu
    // plus d'un kilo-octet par seconde. Meme le lien faible que cette sonde
    // cherche a reconnaitre en porte mille fois plus.
    let travaux: Vec<_> = cibles.iter().map(|c| tokio::spawn(salve(*c))).collect();
    let mut sorties = Vec::with_capacity(travaux.len());
    for t in travaux {
        // Un fil qui panique ne dit rien du reseau: la serie vide sera ecartee
        // par `conclure_perte`, qui refuse de conclure sur trop peu.
        sorties.push(t.await.unwrap_or_default());
    }
    sorties
}

/// Une salve vers une cible: on emet a cadence fixe et on ramasse ce qui
/// revient, sans jamais attendre tir par tir.
///
/// Attendre chaque reponse avant d'emettre la suivante ferait couter
/// [`DELAI_TENTATIVE`] a CHAQUE paquet perdu, donc trente-sept secondes sur une
/// serie a moitie perdue. La salve emet et ecoute en meme temps, et sa duree ne
/// depend pas de la perte: c'est ce qui la fait tenir dans le budget.
async fn salve(cible: SocketAddr) -> Vec<bool> {
    let liaison = if cible.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let Ok(socket) = UdpSocket::bind(liaison).await else {
        return Vec::new();
    };

    // Un identifiant par tir, tires d'un coup. Ils doivent etre imprevisibles
    // (RFC 5389 section 6) et surtout DISTINCTS, sans quoi deux tirs se
    // confondraient et une reponse en crediterait deux.
    let mut brut = vec![0u8; 12 * TIRS_PAR_CIBLE];
    if crate::coeurs::alea::octets(&mut brut).is_err() {
        return Vec::new();
    }
    let mut identifiants = Vec::with_capacity(TIRS_PAR_CIBLE);
    for (i, bloc) in brut.as_chunks::<12>().0.iter().enumerate() {
        let mut t = *bloc;
        // Le dernier octet porte le rang: la distinction ne repose pas sur la
        // chance, et il reste quatre-vingt-huit bits imprevisibles.
        t[11] = i as u8;
        identifiants.push(t);
    }

    let fin =
        tokio::time::Instant::now() + ESPACEMENT_DES_TIRS * TIRS_PAR_CIBLE as u32 + DELAI_TENTATIVE;

    let emission = async {
        for t in &identifiants {
            // Un envoi qui echoue est un tir perdu, pas une salve perdue: on
            // continue, et l'absence de reponse le comptera.
            let _ = socket.send_to(&requete_stun(*t), cible).await;
            tokio::time::sleep(ESPACEMENT_DES_TIRS).await;
        }
    };

    let reception = async {
        let mut vus = std::collections::HashSet::new();
        let mut tampon = [0u8; 512];
        loop {
            let maintenant = tokio::time::Instant::now();
            if maintenant >= fin {
                break;
            }
            match tokio::time::timeout(fin - maintenant, socket.recv_from(&mut tampon)).await {
                Ok(Ok((n, _))) => {
                    for (i, t) in identifiants.iter().enumerate() {
                        if reponse_stun_valide(&tampon[..n], *t) {
                            vus.insert(i);
                            break;
                        }
                    }
                }
                // Une erreur de lecture - ICMP port unreachable remonte ici -
                // ne termine pas la salve: le reste peut encore repondre.
                Ok(Err(_)) => continue,
                Err(_) => break,
            }
        }
        vus
    };

    let (_, vus) = tokio::join!(emission, reception);
    (0..TIRS_PAR_CIBLE).map(|i| vus.contains(&i)).collect()
}

/// En-tete STUN: type Binding Request, longueur nulle, cookie magique, puis
/// l'identifiant de transaction. RFC 5389 section 6.
const STUN_BINDING_REQUEST: u16 = 0x0001;
const STUN_BINDING_RESPONSE: u16 = 0x0101;
const STUN_COOKIE: u32 = 0x2112_A442;

fn requete_stun(transaction: [u8; 12]) -> [u8; 20] {
    let mut m = [0u8; 20];
    m[0..2].copy_from_slice(&STUN_BINDING_REQUEST.to_be_bytes());
    m[2..4].copy_from_slice(&0u16.to_be_bytes());
    m[4..8].copy_from_slice(&STUN_COOKIE.to_be_bytes());
    m[8..20].copy_from_slice(&transaction);
    m
}

/// La reponse correspond-elle a la requete envoyee.
pub fn reponse_stun_valide(reponse: &[u8], transaction: [u8; 12]) -> bool {
    reponse.len() >= 20
        && u16::from_be_bytes([reponse[0], reponse[1]]) == STUN_BINDING_RESPONSE
        && u32::from_be_bytes([reponse[4], reponse[5], reponse[6], reponse[7]]) == STUN_COOKIE
        && reponse[8..20] == transaction
}

/// Identifiant de transaction imprevisible, sans dependance de tirage
/// aleatoire: `RandomState` est ensemence par le systeme a chaque processus.
fn transaction_stun() -> [u8; 12] {
    let etat = RandomState::new();
    let mut t = [0u8; 12];
    for (i, bloc) in t.chunks_mut(8).enumerate() {
        let mut h = etat.build_hasher();
        h.write_usize(i);
        h.write_u64(bloc.len() as u64);
        let v = h.finish().to_le_bytes();
        bloc.copy_from_slice(&v[..bloc.len()]);
    }
    t
}

async fn tenter_stun(cible: SocketAddr) -> Tentative {
    let liaison = if cible.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let Ok(socket) = UdpSocket::bind(liaison).await else {
        return Tentative::Impossible;
    };
    let transaction = transaction_stun();
    if socket
        .send_to(&requete_stun(transaction), cible)
        .await
        .is_err()
    {
        return Tentative::Expiree;
    }
    let mut tampon = [0u8; 512];
    match tokio::time::timeout(DELAI_TENTATIVE, socket.recv_from(&mut tampon)).await {
        Ok(Ok((n, _))) if reponse_stun_valide(&tampon[..n], transaction) => Tentative::Aboutie,
        // Un datagramme qui ne correspond pas ne prouve rien: on ne le compte
        // pas comme une reussite.
        Ok(Ok(_)) => Tentative::Expiree,
        Ok(Err(_)) | Err(_) => Tentative::Expiree,
    }
}

/// Lit le statut d'une reponse HTTP en clair.
pub fn statut_http(entete: &str) -> Option<u16> {
    let ligne = entete.lines().next()?;
    let mut morceaux = ligne.split(' ');
    let version = morceaux.next()?;
    if !version.starts_with("HTTP/") {
        return None;
    }
    morceaux.next()?.parse().ok()
}

async fn tenter_portail(cible: SocketAddr, url: &str) -> Option<ReponseHttp> {
    let hote = url
        .strip_prefix("http://")
        .and_then(|r| r.split('/').next())
        .unwrap_or("");
    let chemin = url
        .strip_prefix("http://")
        .and_then(|r| r.find('/').map(|i| &r[i..]))
        .unwrap_or("/");
    let requete = format!("GET {chemin} HTTP/1.1\r\nHost: {hote}\r\nConnection: close\r\n\r\n");

    let travail = async {
        let mut flux = TcpStream::connect(cible).await.ok()?;
        flux.write_all(requete.as_bytes()).await.ok()?;
        let mut tampon = vec![0u8; 1024];
        let n = flux.read(&mut tampon).await.ok()?;
        let texte = String::from_utf8_lossy(&tampon[..n]).into_owned();
        match statut_http(&texte) {
            Some(204) => Some(ReponseHttp::Vide204),
            Some(_) => Some(ReponseHttp::Autre),
            None => None,
        }
    };
    tokio::time::timeout(DELAI_TENTATIVE, travail).await.ok()?
}

#[cfg(test)]
mod tests {
    use super::*;

    const ABOUTIE: Tentative = Tentative::Aboutie;
    const EXPIREE: Tentative = Tentative::Expiree;
    const REFUSEE: Tentative = Tentative::Refusee;
    const IMPOSSIBLE: Tentative = Tentative::Impossible;

    #[test]
    fn le_temoin_conclut_positivement_des_la_premiere_reussite() {
        assert!(conclure_temoin(&[EXPIREE, ABOUTIE]).vu_vrai());
    }

    #[test]
    fn le_temoin_declare_le_reseau_mort_si_tout_a_ete_essaye_sans_succes() {
        assert!(conclure_temoin(&[EXPIREE, REFUSEE]).vu_faux());
    }

    #[test]
    fn le_temoin_ne_conclut_rien_si_rien_n_a_pu_etre_essaye() {
        assert!(!conclure_temoin(&[IMPOSSIBLE]).est_mesure());
        assert!(!conclure_temoin(&[]).est_mesure());
    }

    #[test]
    fn un_echec_sur_un_reseau_vivant_vaut_filtrage() {
        let temoin = Mesure::Vu(true);
        assert!(conclure_avec_temoin(&[EXPIREE, EXPIREE], temoin).vu_faux());
    }

    #[test]
    fn le_meme_echec_sur_un_reseau_mort_ne_conclut_rien() {
        // Le test qui justifie tout le module. Un cable debranche produit
        // exactement les memes tentatives expirees qu'un port filtre; seul le
        // temoin les separe, et sans lui la selection eliminerait des
        // protocoles sur la foi d'un incident materiel.
        let temoin = Mesure::Vu(false);
        assert!(!conclure_avec_temoin(&[EXPIREE, EXPIREE], temoin).est_mesure());
    }

    #[test]
    fn un_temoin_non_mesure_ne_permet_pas_davantage_de_conclure() {
        assert!(!conclure_avec_temoin(&[EXPIREE], Mesure::NonMesure).est_mesure());
    }

    #[test]
    fn une_seule_reussite_conclut_meme_sans_temoin() {
        // Une cible qui repond prouve que le transport sort, quel que soit
        // l'etat du temoin: c'est une observation directe, pas une deduction.
        assert!(conclure_avec_temoin(&[EXPIREE, ABOUTIE], Mesure::NonMesure).vu_vrai());
        assert!(conclure_avec_temoin(&[ABOUTIE], Mesure::Vu(false)).vu_vrai());
    }

    #[test]
    fn une_sonde_qui_n_a_pas_pu_tourner_ne_conclut_pas_meme_reseau_vivant() {
        // Cas de la cible sur port haut non fournie. Sans ce cas, l'absence de
        // cible se lirait comme un port haut ferme.
        assert!(!conclure_avec_temoin(&[IMPOSSIBLE], Mesure::Vu(true)).est_mesure());
    }

    #[test]
    fn le_portail_se_detecte_a_sa_reponse_pas_a_son_silence() {
        assert!(conclure_portail(Some(ReponseHttp::Autre)).vu_vrai());
        assert!(conclure_portail(Some(ReponseHttp::Vide204)).vu_faux());
        assert!(!conclure_portail(None).est_mesure());
    }

    #[test]
    fn un_datagramme_quic_de_pleine_taille_ne_tient_pas_dans_un_chemin_a_1280() {
        // Le fait central, et il tient sans l'obfuscation: meme nu, un paquet
        // QUIC par defaut deborde d'un chemin a 1280. Salamander aggrave, il
        // n'est pas la cause. Un correctif qui se contenterait de couper
        // l'obfuscation ne reglerait donc rien, et ce test le dit.
        assert_eq!(paquet_ip_quic(false), 1308);
        assert_eq!(paquet_ip_quic(true), 1316);
        assert!(paquet_ip_quic(false) > 1280);
        assert_eq!(
            paquet_ip_quic(true) - paquet_ip_quic(false),
            SEL_SALAMANDER,
            "le sel Salamander est le seul ecart entre les deux"
        );
    }

    #[test]
    fn un_gros_datagramme_qui_part_tranche_la_question() {
        for temoin in [
            Tentative::Aboutie,
            Tentative::Refusee,
            Tentative::Impossible,
        ] {
            assert!(conclure_chemin_quic(Tentative::Aboutie, temoin).vu_vrai());
        }
    }

    #[test]
    fn le_gros_refuse_et_le_petit_parti_designe_la_taille() {
        assert!(conclure_chemin_quic(Tentative::Refusee, Tentative::Aboutie).vu_faux());
    }

    #[test]
    fn deux_refus_ne_designent_pas_la_taille() {
        // Machine debranchee, route absente, pare-feu local: le gros comme le
        // petit sont refuses. Conclure a un chemin etroit ferait sauter un
        // transport parfaitement viable des que le reseau tousse.
        assert!(!conclure_chemin_quic(Tentative::Refusee, Tentative::Refusee).est_mesure());
        assert!(!conclure_chemin_quic(Tentative::Refusee, Tentative::Impossible).est_mesure());
        assert!(!conclure_chemin_quic(Tentative::Impossible, Tentative::Aboutie).est_mesure());
    }

    #[test]
    fn la_requete_stun_porte_le_cookie_et_la_transaction() {
        let t = [7u8; 12];
        let m = requete_stun(t);
        assert_eq!(u16::from_be_bytes([m[0], m[1]]), STUN_BINDING_REQUEST);
        assert_eq!(u16::from_be_bytes([m[2], m[3]]), 0);
        assert_eq!(u32::from_be_bytes([m[4], m[5], m[6], m[7]]), STUN_COOKIE);
        assert_eq!(m[8..20], t);
    }

    #[test]
    fn une_reponse_stun_correspondante_est_acceptee() {
        let t = [3u8; 12];
        let mut r = requete_stun(t);
        r[0..2].copy_from_slice(&STUN_BINDING_RESPONSE.to_be_bytes());
        assert!(reponse_stun_valide(&r, t));
    }

    #[test]
    fn un_datagramme_quelconque_ne_passe_pas_pour_une_reponse() {
        // Sur un reseau bavard, compter n'importe quel datagramme ferait
        // conclure a tort que l'UDP sort.
        let t = [3u8; 12];
        assert!(!reponse_stun_valide(&[0u8; 20], t), "tout a zero accepte");
        assert!(!reponse_stun_valide(b"bonjour", t), "trop court accepte");

        let mut mauvaise_transaction = requete_stun([9u8; 12]);
        mauvaise_transaction[0..2].copy_from_slice(&STUN_BINDING_RESPONSE.to_be_bytes());
        assert!(
            !reponse_stun_valide(&mauvaise_transaction, t),
            "transaction etrangere acceptee"
        );

        let requete_renvoyee = requete_stun(t);
        assert!(
            !reponse_stun_valide(&requete_renvoyee, t),
            "notre propre requete, renvoyee en echo, acceptee comme reponse"
        );
    }

    #[test]
    fn deux_transactions_successives_different() {
        assert_ne!(transaction_stun(), transaction_stun());
    }

    #[test]
    fn le_statut_http_se_lit_sur_la_premiere_ligne() {
        assert_eq!(statut_http("HTTP/1.1 204 No Content\r\n\r\n"), Some(204));
        assert_eq!(
            statut_http("HTTP/1.0 302 Found\r\nLocation: /x\r\n"),
            Some(302)
        );
    }

    #[test]
    fn une_reponse_qui_n_est_pas_du_http_ne_rend_pas_de_statut() {
        // Un portail captif maladroit peut repondre n'importe quoi. Le lire
        // comme un 200 ferait conclure a un portail alors qu'on n'a rien
        // compris; rendre None fait tomber la sonde en NonMesure.
        assert_eq!(statut_http("bonjour"), None);
        assert_eq!(statut_http(""), None);
        assert_eq!(statut_http("HTTP/1.1 abc"), None);
        assert_eq!(statut_http("ICY 200 OK"), None);
    }

    /// Le controle negatif du module, sur la vraie chaine et pas seulement sur
    /// les fonctions pures. Toutes les cibles sont dans TEST-NET-1 (RFC 5737),
    /// qui n'est routee nulle part: le temoin meurt, donc AUCUNE sonde ne doit
    /// conclure. Un module qui rendrait ici "UDP bloque, TCP/443 bloque" aurait
    /// l'air de fonctionner et ferait eliminer tous les protocoles a la
    /// selection, sur une machine dont le reseau va peut-etre tres bien.
    #[tokio::test]
    async fn sans_reseau_vivant_aucune_sonde_ne_conclut() {
        let cibles = Cibles {
            temoin_tcp80: vec!["192.0.2.1:80".parse().unwrap()],
            tcp443: vec!["192.0.2.2:443".parse().unwrap()],
            stun: vec!["192.0.2.3:19302".parse().unwrap()],
            portail: Some((
                "192.0.2.4:80".parse().unwrap(),
                "http://192.0.2.4/generate_204".to_string(),
            )),
            quic: vec![("192.0.2.5:443".parse().unwrap(), "exemple.test".to_string())],
        };
        let r = sonder(&cibles).await;
        assert_eq!(
            r.environnement.sondes_abouties(),
            0,
            "une sonde a conclu alors que le reseau ne repondait pas: {:?}",
            r.environnement
        );
        assert!(
            r.non_mesures.iter().any(|(champ, _)| *champ == "temoin"),
            "le rapport ne dit pas que le temoin est mort"
        );
    }

    /// Une serie coupee net a la fin est une limitation, pas de la perte.
    #[test]
    fn une_serie_coupee_en_queue_est_reconnue_comme_ecourtee() {
        let mut s = vec![true; 25];
        for r in s.iter_mut().skip(18) {
            *r = false;
        }
        assert!(
            serie_ecourtee(&s),
            "sept echecs de suite en queue sur vingt-cinq"
        );
        assert_eq!(
            conclure_perte(&[s]),
            Mesure::NonMesure,
            "une serie ecourtee doit etre ecartee, pas moyennee"
        );
    }

    /// Une perte DISPERSEE, meme du meme volume, n'est pas une limitation.
    #[test]
    fn une_perte_dispersee_n_est_pas_prise_pour_une_limitation() {
        let s: Vec<bool> = (0..25).map(|i| i % 4 != 0).collect();
        assert!(!serie_ecourtee(&s));
        // Sept tirs sur vingt-cinq perdus: 28 %.
        assert_eq!(conclure_perte(&[s]), Mesure::Vu(28));
    }

    /// Le garde qui compte le plus: cent pour cent de perte n'est pas un
    /// regime de reseau, c'est un UDP coupe. Le rendre franchirait le seuil de
    /// bascule et promouvrait Hysteria2 - un protocole UDP - sur un reseau ou
    /// l'UDP ne passe pas du tout.
    #[test]
    fn une_serie_entierement_muette_ne_rend_pas_cent_pour_cent() {
        let muette = vec![false; 25];
        assert!(
            !serie_ecourtee(&muette),
            "un silence complet n'est pas une limitation de debit"
        );
        assert_eq!(conclure_perte(&[muette]), Mesure::NonMesure);
    }

    /// La recette du defaut trouve sur le reseau: une cible morte melangee a
    /// une cible saine annoncait 50 % de perte sur un lien impeccable.
    #[test]
    fn une_cible_muette_est_ecartee_et_ne_fabrique_pas_de_perte() {
        let saine = vec![true; 25];
        let muette = vec![false; 25];
        assert_eq!(
            conclure_perte(&[saine, muette]),
            Mesure::Vu(0),
            "une cible qui ne repond a rien n'est pas un chemin a 100 % de perte"
        );
    }

    /// Et si TOUTES se taisent, on ne conclut pas: c'est `udp_passe` qui porte
    /// cette question-la.
    #[test]
    fn toutes_les_cibles_muettes_ne_concluent_rien() {
        assert_eq!(
            conclure_perte(&[vec![false; 25], vec![false; 25]]),
            Mesure::NonMesure
        );
    }

    /// L'arrondi va au plus proche, pas par defaut.
    ///
    /// Tronquer deciderait toujours dans le meme sens, et la bascule se joue
    /// justement a quelques points du seuil.
    #[test]
    fn le_taux_est_arrondi_au_plus_proche() {
        let a: Vec<bool> = (0..20).map(|i| i != 0).collect();
        let b = vec![true; 20];
        // Un perdu sur quarante: 2,5 %, donc 3 au plus proche et 2 par defaut.
        assert_eq!(conclure_perte(&[a, b]), Mesure::Vu(3));
    }

    #[test]
    fn un_echantillon_trop_maigre_ne_soutient_aucun_chiffre() {
        let courte = vec![true; TIRS_MINIMUM - 1];
        assert_eq!(conclure_perte(&[courte]), Mesure::NonMesure);
        assert_eq!(conclure_perte(&[]), Mesure::NonMesure);
    }

    /// Deux cibles sont mises en commun, ce qui affine la granularite.
    #[test]
    fn deux_series_saines_sont_mises_en_commun() {
        let a: Vec<bool> = (0..25).map(|i| i != 0).collect();
        let b: Vec<bool> = (0..25).map(|i| i != 0).collect();
        // Deux perdus sur cinquante: 4 %.
        assert_eq!(conclure_perte(&[a, b]), Mesure::Vu(4));
    }

    /// Une cible qui limite ne doit pas contaminer celle qui mesure.
    #[test]
    fn une_cible_qui_limite_est_ecartee_et_l_autre_conclut() {
        let saine: Vec<bool> = (0..25).map(|i| i != 0).collect();
        let mut limitee = vec![true; 25];
        for r in limitee.iter_mut().skip(10) {
            *r = false;
        }
        assert_eq!(
            conclure_perte(&[saine, limitee]),
            Mesure::Vu(4),
            "la serie limitee a tire la moyenne vers le haut"
        );
    }

    /// La salve tient dans le budget de sondage, quelle que soit la perte.
    ///
    /// Deux proprietes en une. La duree ne depend PAS de la perte, parce que la
    /// salve emet et ecoute en meme temps: attendre tir par tir aurait coute
    /// une echeance entiere par paquet perdu, et c'est ce qui faisait croire
    /// que cette sonde ne tenait pas dans cinq secondes. Et les salves tournent
    /// en parallele, ce que cette recette a impose - elle est tombee sur le
    /// premier jet, qui les enchainait.
    #[test]
    fn la_salve_tient_dans_le_budget_de_sondage() {
        let duree = ESPACEMENT_DES_TIRS * TIRS_PAR_CIBLE as u32 + DELAI_TENTATIVE;
        assert!(
            duree <= BUDGET,
            "une salve ({duree:?}) depasse le budget de {BUDGET:?}"
        );
        // Et il reste de quoi absorber la mise en route: le budget n'est pas
        // consomme a l'octet pres.
        assert!(
            duree + Duration::from_secs(1) <= BUDGET,
            "une salve ({duree:?}) ne laisse pas une seconde de marge sur {BUDGET:?}"
        );
    }

    #[test]
    fn les_cibles_par_defaut_sont_analysables() {
        let c = Cibles::par_defaut();
        assert!(!c.temoin_tcp80.is_empty());
        assert!(!c.tcp443.is_empty());
        assert!(!c.stun.is_empty());
        assert!(!c.quic.is_empty());
        for (adresse, nom) in &c.quic {
            assert_eq!(adresse.port(), 443, "QUIC se sonde la ou il vit");
            assert!(
                !nom.is_empty(),
                "un Initial sans nom de serveur n'est pas inspecte"
            );
        }
    }

    #[test]
    fn au_moins_un_serveur_stun_par_defaut_est_sur_un_port_haut() {
        // Sans cela, `ports_hauts_ouverts` resterait NonMesure a jamais et la
        // sonde n'aurait aucun moyen de le dire.
        let c = Cibles::par_defaut();
        assert!(c.stun.iter().any(|a| est_port_haut(a.port())));
    }

    #[test]
    fn la_definition_du_port_haut_est_celle_de_la_selection() {
        use bifrost_evasion::Transport;
        // Les deux cotes doivent tracer la meme frontiere: la sonde mesure ce
        // que la selection consomme. Si l'une derivait, la selection
        // eliminerait des techniques sur une mesure qui parle d'autre chose.
        assert!(!est_port_haut(443));
        assert!(Transport::Tcp443.tient_sur_80_443());
        assert!(!est_port_haut(80));
        assert!(est_port_haut(19302));
        assert!(est_port_haut(51820));
        assert!(!Transport::UdpPortLibre.tient_sur_80_443());
    }

    /// Les trois entiers de l'en-tete STUN sont ceux de la RFC 5389.
    ///
    /// `la_requete_stun_porte_le_cookie_et_la_transaction` relit le message que
    /// `requete_stun` vient d'ecrire et compare chaque champ a la constante qui
    /// l'a ecrit. Les deux cotes bougent ensemble: la recette reste verte quelle
    /// que soit la valeur. Le round-trip `requete_stun` /
    /// `reponse_stun_valide` a le meme defaut, les deux fonctions lisant les
    /// memes constantes.
    ///
    /// Mesure du 23 aout 2026 sur dev-windows: avec le cookie a `0xDEADBEEF`,
    /// puis avec les deux types de message decales, les 524 recettes du
    /// binaire de bibliotheque restaient vertes. Un cookie faux fait jeter la
    /// requete par TOUT serveur STUN, donc `reponse_stun_valide` ne verrait
    /// jamais rien et la sonde conclurait que l'UDP ne sort pas - sur un
    /// reseau ou il sort.
    ///
    /// Valeurs relevees dans la RFC 5389: section 6 pour le cookie magique
    /// `0x2112A442`, section 18.1 pour les types de message.
    #[test]
    fn l_entete_stun_porte_les_valeurs_de_la_rfc_5389() {
        assert_eq!(STUN_COOKIE, 0x2112_A442, "cookie magique, RFC 5389 6");
        assert_eq!(STUN_BINDING_REQUEST, 0x0001, "Binding Request");
        assert_eq!(STUN_BINDING_RESPONSE, 0x0101, "Binding Success Response");
        // Et les deux types different, sans quoi notre propre requete renvoyee
        // en echo passerait pour une reponse.
        assert_ne!(STUN_BINDING_REQUEST, STUN_BINDING_RESPONSE);
    }
}
