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
use std::net::TcpListener;

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

/// Un port de la boucle locale derriere lequel PERSONNE n'ecoute.
///
/// # Pourquoi ce n'est pas une [`Reservation`]
///
/// C'est l'usage exactement inverse, et les cinq copies d'avant le cachaient
/// derriere un seul nom. Certaines recettes veulent une adresse qui REFUSE:
/// une API de coeur qui n'ecoute pas encore, un mandataire annonce mais sans
/// relais derriere, un serveur de sortie mort. Tenir une ecoute la-dessus
/// ferait accepter la connexion, c'est-a-dire transformerait "refuse" en
/// "accepte puis se tait" - deux etats que ces recettes existent justement pour
/// distinguer.
///
/// # Ce qu'il promet, et ce qu'il ne promet pas
///
/// Le numero etait libre a l'instant de l'appel. Pour qu'il cesse de refuser,
/// il faudrait qu'un autre processus se mette a ECOUTER dessus, ce qui n'a rien
/// a voir avec la pression ordinaire sur la plage ephemere: une connexion
/// sortante qui prendrait ce numero comme port source ne rend pas l'adresse
/// joignable pour autant, un socket connecte n'etant pas un socket en ecoute.
/// C'est une course d'un autre ordre de grandeur que celle que
/// [`reserver`] ferme, et elle ne se ferme pas d'ici.
pub fn port_sans_personne() -> io::Result<u16> {
    Ok(TcpListener::bind("127.0.0.1:0")?.local_addr()?.port())
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

    /// Un port "sans personne" doit refuser, pas accepter.
    ///
    /// La recette existe pour empecher la confusion que le nom unique d'avant
    /// rendait facile: rendre une [`Reservation`] ici ferait accepter la
    /// connexion, et les recettes qui distinguent "refuse" de "accepte puis se
    /// tait" passeraient au vert sans rien mesurer.
    #[test]
    fn un_port_sans_personne_refuse_la_connexion() {
        let p = port_sans_personne().unwrap();
        let issue = std::net::TcpStream::connect_timeout(
            &std::net::SocketAddr::from(([127, 0, 0, 1], p)),
            std::time::Duration::from_secs(2),
        );
        assert!(issue.is_err(), "quelqu'un a repondu sur le port {p}");
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
