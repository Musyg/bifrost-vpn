//! Les techniques de contournement et leurs proprietes.
//!
//! Une propriete par question que la selection a besoin de poser. Elles sont
//! declarees une fois ici plutot que devinees ailleurs par un `match` disperse:
//! ajouter une technique doit obliger le compilateur a reclamer ses reponses.

use serde::{Deserialize, Serialize};

/// Ce que la technique demande au reseau pour fonctionner.
///
/// C'est la propriete qui decide des eliminations dures: un transport que le
/// reseau bloque de facon MESUREE elimine la technique, sans discussion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Transport {
    /// TCP sur 443. Passe partout ou quelque chose passe.
    Tcp443,
    /// UDP sur 443, donc QUIC ou assimile.
    Udp443,
    /// UDP sur un port quelconque, souvent haut.
    UdpPortLibre,
}

impl Transport {
    pub fn est_udp(self) -> bool {
        matches!(self, Transport::Udp443 | Transport::UdpPortLibre)
    }

    /// Vrai si le transport survit a un reseau qui n'ouvre que 80 et 443.
    pub fn tient_sur_80_443(self) -> bool {
        matches!(self, Transport::Tcp443 | Transport::Udp443)
    }
}

/// A quoi ressemble la technique pour un DPI.
///
/// Distinct du transport: deux techniques peuvent parler TCP/443 et n'avoir
/// aucune ressemblance vue d'un inspecteur.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Camouflage {
    /// Emprunte un vrai site: une sonde non authentifiee recoit le vrai
    /// certificat du site cible. C'est le cas de REALITY.
    SiteEmprunte,
    /// Ressemble a du trafic HTTP ou TLS ordinaire vers un CDN.
    TraficWebOrdinaire,
    /// Bruit ajoute au handshake pour ne pas matcher une signature connue,
    /// sans imiter quoi que ce soit. C'est le cas d'AmneziaWG.
    BruitDeHandshake,
    /// Aucun. Le premier paquet est a haute entropie et ne ressemble a rien,
    /// ce que les seuils d'entropie du GFW attrapent.
    Aucun,
}

/// Les techniques retenues par le document 04.
///
/// La liste est volontairement courte: ce sont les candidats de la machine a
/// etats de la partie 3.2, pas le tableau de survie complet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Technique {
    /// VLESS + REALITY + XTLS-Vision, TCP/443.
    RealityVision,
    /// XHTTP (SplitHTTP) derriere un CDN.
    XhttpCdn,
    /// VLESS + TLS + WebSocket derriere un CDN.
    ///
    /// Le repli du mode Discret, et la reponse au seul cas ou ce mode n'avait
    /// plus rien de montable: derriere une interception TLS d'entreprise,
    /// REALITY tombe et Discret ecarte tout ce qui ne ressemble pas a du web.
    ///
    /// **Pourquoi WebSocket et non HTTPUpgrade, alors que le second est plus
    /// leger.** Mesure du 21 aout 2026 a travers un vrai edge Cloudflare:
    /// `httpupgrade` n'y passe PAS, et c'est structurel. Le client sing-box
    /// annonce `Upgrade: websocket` sans emettre `Sec-WebSocket-Key` ni
    /// `Sec-WebSocket-Version`; l'edge refuse cette poignee incomplete par un
    /// 400 qui n'atteint jamais l'origine, tandis que le serveur `httpupgrade`
    /// de sing-box refuse a l'inverse une poignee COMPLETE - "real websocket
    /// request received". Les deux exigences s'excluent. Voir
    /// [`Technique::HttpUpgradeFront`] pour ce que `httpupgrade` sert encore.
    ///
    /// Servi par sing-box, donc dans le MEME processus que REALITY et
    /// Hysteria2, derriere le meme selecteur. XHTTP demanderait un second
    /// coeur, une seconde mecanique de course faute d'API Clash chez Xray, et
    /// un echange de coeur a chaque bascule. Voir `coeur::coeur_de`.
    WebsocketCdn,
    /// VLESS + TLS + HTTPUpgrade derriere un front que l'on heberge.
    ///
    /// Le meme camouflage que ci-dessus, sans CDN. Un proxy inverse ordinaire -
    /// nginx, Caddy - RELAIE l'upgrade sans le valider, la ou un CDN le valide:
    /// mesure du 21 aout 2026, `101 Switching Protocols` dans le journal
    /// d'acces de nginx pour la requete meme que Cloudflare rejette.
    ///
    /// **Pourquoi la garder alors que le CDN est le cas qui nous interessait.**
    /// Bifrost est un CLIENT: ce n'est pas lui qui choisit le transport, c'est
    /// l'operateur du serveur. Un utilisateur qui colle un lien
    /// `type=httpupgrade` fourni par son fournisseur doit pouvoir s'en servir,
    /// et une bonne partie de l'ecosysteme deploie exactement cela derriere un
    /// front auto-heberge. La refuser rendrait le client inutilisable pour eux.
    HttpUpgradeFront,
    /// Hysteria2 + Salamander, UDP/443.
    Hysteria2,
    /// AmneziaWG en profil bas volume.
    AmneziaWg,
    /// WireGuard nu. Presque partout mort, garde comme candidat sur un reseau
    /// non censure ou il est le plus efficace.
    WireGuardNu,
}

impl Technique {
    /// Toutes les techniques, dans un ordre stable qui n'est PAS un ordre de
    /// preference: la preference se calcule, elle ne se declare pas ici.
    pub const TOUTES: [Technique; 7] = [
        Technique::RealityVision,
        Technique::XhttpCdn,
        Technique::WebsocketCdn,
        Technique::HttpUpgradeFront,
        Technique::Hysteria2,
        Technique::AmneziaWg,
        Technique::WireGuardNu,
    ];

    pub fn nom(self) -> &'static str {
        match self {
            Technique::RealityVision => "vless-reality-vision",
            Technique::XhttpCdn => "xhttp-cdn",
            Technique::WebsocketCdn => "websocket-cdn",
            Technique::HttpUpgradeFront => "httpupgrade-front",
            Technique::Hysteria2 => "hysteria2",
            Technique::AmneziaWg => "amneziawg",
            Technique::WireGuardNu => "wireguard-nu",
        }
    }

    pub fn transport(self) -> Transport {
        match self {
            Technique::RealityVision
            | Technique::XhttpCdn
            | Technique::WebsocketCdn
            | Technique::HttpUpgradeFront => Transport::Tcp443,
            Technique::Hysteria2 => Transport::Udp443,
            Technique::AmneziaWg | Technique::WireGuardNu => Transport::UdpPortLibre,
        }
    }

    pub fn camouflage(self) -> Camouflage {
        match self {
            Technique::RealityVision => Camouflage::SiteEmprunte,
            Technique::XhttpCdn | Technique::WebsocketCdn | Technique::HttpUpgradeFront => {
                Camouflage::TraficWebOrdinaire
            }
            Technique::Hysteria2 | Technique::AmneziaWg => Camouflage::BruitDeHandshake,
            Technique::WireGuardNu => Camouflage::Aucun,
        }
    }

    /// Survit-elle a une interception TLS d'entreprise.
    ///
    /// REALITY ne survit PAS a un MITM: le proxy termine le TLS, donc le
    /// ClientHello camoufle n'atteint jamais le serveur et l'echange X25519
    /// cache dans le SessionID est perdu. C'est le cas ou la technique la plus
    /// furtive face a un etat est la moins utile face a un employeur.
    pub fn survit_au_mitm_tls(self) -> bool {
        match self {
            Technique::RealityVision => false,
            // Le CDN termine deja le TLS: une terminaison de plus ne change
            // rien tant que le contenu transporte reste du HTTP quelconque.
            Technique::XhttpCdn | Technique::WebsocketCdn | Technique::HttpUpgradeFront => true,
            // Ne parlent pas TLS, donc rien a intercepter. Encore faut-il que
            // leur transport passe, ce que la selection verifie par ailleurs.
            Technique::Hysteria2 | Technique::AmneziaWg | Technique::WireGuardNu => true,
        }
    }

    /// Cout approximatif pour la machine, du plus leger au plus lourd.
    ///
    /// Sert au mode Rapide. Les valeurs viennent du classement du document 04
    /// partie 5 (WireGuard noyau < REALITY < QUIC en espace utilisateur), pas
    /// d'une mesure faite ici: c'est un ordre, pas une metrique.
    pub fn cout_machine(self) -> u8 {
        match self {
            Technique::WireGuardNu => 0,
            Technique::AmneziaWg => 1,
            Technique::RealityVision => 2,
            // Meme rang que XHTTP: les deux sont du VLESS en TLS encadre par du
            // HTTP, et rien de mesure ici ne les separe. Une egalite honnete
            // vaut mieux qu'un ordre invente pour eviter l'egalite.
            Technique::XhttpCdn | Technique::WebsocketCdn | Technique::HttpUpgradeFront => 3,
            Technique::Hysteria2 => 4,
        }
    }

    /// Resiste-t-elle bien a un reseau qui perd des paquets.
    ///
    /// Seul Hysteria2 le fait vraiment: son controle de congestion evite le
    /// probleme du TCP dans le tunnel, ou le TCP interne voit la perte du
    /// reseau et ralentit deux fois.
    pub fn tient_la_perte(self) -> bool {
        matches!(self, Technique::Hysteria2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chaque_technique_a_un_nom_unique() {
        let mut noms: Vec<&str> = Technique::TOUTES.iter().map(|t| t.nom()).collect();
        noms.sort_unstable();
        let avant = noms.len();
        noms.dedup();
        assert_eq!(avant, noms.len(), "deux techniques partagent un nom");
    }

    #[test]
    fn la_liste_toutes_est_complete() {
        // Si une variante est ajoutee sans etre mise dans TOUTES, elle serait
        // invisible de la selection: elle ne serait jamais choisie et rien ne
        // le signalerait. Le match exhaustif ci-dessous casse la compilation
        // dans ce cas.
        for t in Technique::TOUTES {
            match t {
                Technique::RealityVision
                | Technique::XhttpCdn
                | Technique::WebsocketCdn
                | Technique::HttpUpgradeFront
                | Technique::Hysteria2
                | Technique::AmneziaWg
                | Technique::WireGuardNu => {}
            }
        }
        assert_eq!(Technique::TOUTES.len(), 7);
    }

    #[test]
    fn le_cout_machine_ordonne_bien_wireguard_devant_quic() {
        assert!(Technique::WireGuardNu.cout_machine() < Technique::RealityVision.cout_machine());
        assert!(Technique::RealityVision.cout_machine() < Technique::Hysteria2.cout_machine());
    }

    #[test]
    fn reality_ne_survit_pas_au_mitm_alors_qu_il_parle_tcp_443() {
        // Le piege que ce couple de proprietes existe pour eviter: juger de la
        // survie a un MITM sur le seul transport conduirait a choisir REALITY
        // sur un reseau d'entreprise, ou il est precisement casse.
        assert_eq!(Technique::RealityVision.transport(), Transport::Tcp443);
        assert!(!Technique::RealityVision.survit_au_mitm_tls());
        assert!(Technique::XhttpCdn.survit_au_mitm_tls());
    }

    #[test]
    fn seul_hysteria2_est_annonce_resistant_a_la_perte() {
        let resistants: Vec<_> = Technique::TOUTES
            .iter()
            .filter(|t| t.tient_la_perte())
            .collect();
        assert_eq!(resistants, vec![&Technique::Hysteria2]);
    }

    #[test]
    fn tient_sur_80_443_exclut_le_port_libre() {
        assert!(Transport::Tcp443.tient_sur_80_443());
        assert!(Transport::Udp443.tient_sur_80_443());
        assert!(!Transport::UdpPortLibre.tient_sur_80_443());
    }
}
