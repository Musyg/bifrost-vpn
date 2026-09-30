//! Reserver un port pour un processus qu'on va lancer.
//!
//! # Ce que la version d'avant promettait sans le tenir
//!
//! Cinq copies de la meme fonction disaient "reserve un port libre" et
//! rendaient un NUMERO: elles liaient `127.0.0.1:0`, lisaient le port attribue,
//! puis relachaient l'ecoute avant meme de rendre la main. Entre ce numero et
//! le moment ou l'enfant le relie, l'appelant ecrit une configuration, la donne
//! parfois a un autre compte, et lance un processus. Toute la machine vit
//! pendant ce temps, et chaque connexion sortante y pioche un port ephemere de
//! la MEME plage. Une recette le montre en une ligne: le port rendu se relie
//! immediatement par n'importe qui.
//!
//! Le commentaire de ces copies assumait la course - "la fenetre est etroite".
//! Elle ne l'etait pas: elle couvrait toute la preparation.
//!
//! # Ce que tenir l'ecoute change
//!
//! Le port reste PRIS jusqu'a [`Reservation::liberer`], appele juste avant le
//! lancement. La fenetre passe de toute la preparation a l'intervalle entre
//! cette liberation et le `bind` de l'enfant. Et deux appelants du meme
//! processus ne peuvent plus recevoir le meme numero, quoi qu'en decide
//! l'attribueur du systeme: le premier tient encore le sien.
//!
//! # Ce qui reste, et pourquoi
//!
//! Cet intervalle-la ne se ferme pas d'ici. Il faudrait passer le descripteur
//! deja lie a l'enfant, ce qu'aucun coeur tiers n'accepte: sing-box et Xray
//! lisent un numero de port dans leur configuration, pas un descripteur herite.
//! La reduire de plusieurs millisemes a quelques microsecondes est tout ce
//! qu'on peut faire sans changer de coeur.

use std::io;
use std::net::{SocketAddr, TcpListener};

/// Un port tenu ouvert, et donc reellement reserve.
pub struct Reservation {
    /// Tenu jusqu'a la liberation: c'est CE descripteur qui garde le port, et
    /// rien d'autre. Meme raison que la poignee de Job du superviseur.
    _ecoute: TcpListener,
    port: u16,
}

impl Reservation {
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Rend le port, juste avant que l'enfant ne le relie.
    ///
    /// Une methode et non un `drop` implicite: l'endroit ou la fenetre s'ouvre
    /// doit se voir a la lecture. Un appelant qui laisse la reservation vivre
    /// jusqu'a la fin de sa portee empecherait son propre enfant de lier.
    pub fn liberer(self) {}
}

/// Reserve un port libre et le TIENT jusqu'a [`Reservation::liberer`].
pub fn reserver() -> io::Result<Reservation> {
    let ecoute = TcpListener::bind("127.0.0.1:0")?;
    let port = ecoute.local_addr()?.port();
    Ok(Reservation {
        _ecoute: ecoute,
        port,
    })
}

/// Un port de la boucle locale derriere lequel PERSONNE n'ecoute, et que
/// personne ne peut prendre tant qu'il est tenu.
///
/// # Pourquoi ce n'est pas une [`Reservation`]
///
/// C'est l'usage exactement inverse, et les cinq copies d'avant le cachaient
/// derriere un seul nom. Certaines recettes veulent une adresse qui REFUSE:
/// une API de coeur qui n'ecoute pas encore, un mandataire annonce mais sans
/// relais derriere, un serveur de sortie mort. Tenir une ECOUTE la-dessus
/// ferait accepter la connexion, c'est-a-dire transformerait "refuse" en
/// "accepte puis se tait" - deux etats que ces recettes existent justement pour
/// distinguer.
///
/// # Lie, sans ecoute
///
/// Le port est tenu par un socket LIE et jamais mis en ecoute. Une connexion
/// vers lui est refusee, puisque personne n'ecoute; et aucun autre socket ne
/// peut le lier tant que celui-ci vit, puisqu'il ne demande pas
/// `SO_REUSEADDR` - sous Linux le partage exige que les DEUX le demandent, et
/// les ecoutes de la bibliotheque standard comme de tokio, qui le demandent,
/// se voient donc refuser le numero. Sous Windows, un tiers qui demanderait
/// `SO_REUSEADDR` pourrait encore le lier: aucun lanceur de ce depot ne le
/// fait.
///
/// # Ce que la version d'avant supposait, et ce que la mesure a montre
///
/// Jusqu'au 30/09/2026 cette fonction rendait un NUMERO, lie puis relache
/// aussitot, avec pour seule promesse "libre a l'instant de l'appel". Le
/// commentaire jugeait la course negligeable: pour qu'une adresse sans
/// personne cesse de refuser, il faudrait qu'un autre processus se mette a
/// ecouter dessus. Mesure du 30/09/2026 sur dev-windows, ou c'est arrive:
///
/// - l'attribueur de Windows redonne un numero qu'on vient de relacher: 19
///   numeros rendus deux fois en moins de 2 s sur 48000 liaisons `:0` de
///   quatre processus concurrents; sur les 10 releves en detail, 7 l'avaient
///   ete a un AUTRE processus, tous moins d'une milliseconde apres le premier;
/// - il le redonne aussi comme port SOURCE de la connexion suivante du meme
///   processus, qui aboutit alors sur elle-meme, Windows acceptant
///   l'auto-connexion (5 fois sur 98507 connexions, l'attribueur presse par
///   quatre processus);
/// - un refus sur la boucle locale de Windows prend 2,0 s, le temps de ses
///   reemissions de SYN: une ecoute qui apparait dans cet intervalle ACCEPTE.
///
/// La forme exacte de la recette ci-dessous, sous cette pression: 7
/// connexions abouties sur 80000 vers le port "sans personne" (4
/// auto-connexions, 3 ecoutes d'un autre processus), 0 sur 80000 avec le port
/// tenu. La recette elle-meme est devenue rouge une fois sur 80 passages
/// pendant qu'une autre suite de ce crate tournait sur la machine
/// (<< quelqu'un a repondu sur le port 27054 >>, passage entier en 97 ms au
/// lieu de 2,1 s). Tenir le port ferme cette course-la au lieu de la reduire.
pub struct PortSansPersonne {
    /// Lie, jamais en ecoute: c'est CE socket qui garde le numero.
    _tenu: tokio::net::TcpSocket,
    port: u16,
}

impl PortSansPersonne {
    pub fn port(&self) -> u16 {
        self.port
    }

    /// L'adresse complete, sur la boucle locale.
    pub fn adresse(&self) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], self.port))
    }
}

/// Tient un port de la boucle locale sans y ecouter. Voir [`PortSansPersonne`].
///
/// L'appelant garde la valeur rendue aussi longtemps qu'il se sert de
/// l'adresse: la laisser tomber rend le numero a l'attribueur, et la course
/// d'avant avec lui.
pub fn port_sans_personne() -> io::Result<PortSansPersonne> {
    // `TcpSocket` et non `TcpListener`: la bibliotheque standard ne sait pas
    // lier un socket TCP sans l'ecouter. `new_v4` ne pose pas `SO_REUSEADDR`
    // (seul `TcpListener::bind` de tokio le fait), et ne demande pas de
    // runtime: rien n'est enregistre tant qu'on ne connecte ni n'ecoute.
    let tenu = tokio::net::TcpSocket::new_v4()?;
    tenu.bind(SocketAddr::from(([127, 0, 0, 1], 0)))?;
    let port = tenu.local_addr()?.port();
    Ok(PortSansPersonne { _tenu: tenu, port })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// # Le defaut que cette recette tient
    ///
    /// Les cinq copies d'avant rendaient un numero deja relache. Cette recette
    /// etait ROUGE contre elles, en une ligne et sans course a provoquer: le
    /// port "reserve" se reliait immediatement.
    #[test]
    fn un_port_reserve_ne_peut_pas_etre_pris_par_un_autre() {
        let r = reserver().unwrap();
        let voleur = TcpListener::bind(("127.0.0.1", r.port()));
        assert!(
            voleur.is_err(),
            "le port {} etait a prendre alors qu'il venait d'etre reserve",
            r.port()
        );
    }

    /// Et l'autre versant: une reservation qu'on ne peut pas rendre serait
    /// pire que pas de reservation du tout - l'enfant ne pourrait jamais lier.
    #[test]
    fn un_port_libere_redevient_prenable() {
        let r = reserver().unwrap();
        let p = r.port();
        r.liberer();
        TcpListener::bind(("127.0.0.1", p)).expect("apres liberation, le port doit etre prenable");
    }

    /// Borne de l'attente d'un refus. Ce n'est pas une attente: la recette
    /// s'arrete au refus, la borne ne sert que s'il ne vient pas.
    ///
    /// Un refus sur la boucle locale est immediat sous Linux et prend 2,0 s
    /// sous Windows, le temps de ses reemissions de SYN (mesure du 30/09/2026
    /// sur dev-windows: de 2,000 a 2,024 s au calme). La borne d'avant, 2 s,
    /// tombait donc AVANT le refus: sous Windows la recette concluait sur une
    /// echeance et n'avait jamais vu un seul refus.
    const BORNE_DU_REFUS: std::time::Duration = std::time::Duration::from_secs(10);

    /// Un port "sans personne" doit REFUSER: ni accepter, ni se taire.
    ///
    /// La recette existe pour empecher la confusion que le nom unique d'avant
    /// rendait facile: rendre une [`Reservation`] ici ferait accepter la
    /// connexion, et les recettes qui distinguent "refuse" de "accepte puis se
    /// tait" passeraient au vert sans rien mesurer. Elle exige le REFUS lui-meme:
    /// une echeance n'est pas un refus, c'est ce que rendrait aussi un paquet
    /// jete en route.
    #[test]
    fn un_port_sans_personne_refuse_la_connexion() {
        let mort = port_sans_personne().unwrap();
        match std::net::TcpStream::connect_timeout(&mort.adresse(), BORNE_DU_REFUS) {
            Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => {}
            Ok(_) => panic!("quelqu'un a repondu sur le port {}", mort.port()),
            Err(e) => panic!(
                "le port {} devait refuser la connexion, il a rendu: {e}",
                mort.port()
            ),
        }
    }

    /// # Le defaut que cette recette tient
    ///
    /// La version d'avant rendait un numero deja relache: n'importe quel
    /// processus pouvait s'y mettre a l'ecoute, et l'adresse "sans personne"
    /// acceptait alors. Contre elle, cette recette etait rouge en une ligne et
    /// sans course a provoquer. La liaison est tentee comme la font la
    /// bibliotheque standard et tokio, c'est-a-dire avec `SO_REUSEADDR` sous
    /// Linux: c'est le cas qui compte.
    #[test]
    fn un_port_sans_personne_ne_peut_pas_etre_pris_par_un_autre() {
        let mort = port_sans_personne().unwrap();
        let voleur = TcpListener::bind(mort.adresse());
        assert!(
            voleur.is_err(),
            "le port {} etait a prendre alors qu'il est tenu",
            mort.port()
        );
    }

    /// Deux reservations vivantes ne partagent jamais un numero.
    ///
    /// Ce n'est pas une redite de la premiere: celle-la dit qu'un port tenu ne
    /// se prend pas, celle-ci que l'attribueur ne rend pas deux fois le meme a
    /// deux appelants qui vont TOUS LES DEUX s'en servir. Contre la version
    /// d'avant, la question ne se posait meme pas - rien n'etait tenu.
    #[test]
    fn deux_reservations_vivantes_ne_partagent_pas_un_port() {
        let miennes: Vec<Reservation> = (0..64).map(|_| reserver().unwrap()).collect();
        let mut ports: Vec<u16> = miennes.iter().map(Reservation::port).collect();
        ports.sort_unstable();
        let avant = ports.len();
        ports.dedup();
        assert_eq!(avant, ports.len(), "un numero a ete rendu deux fois");
    }
}
