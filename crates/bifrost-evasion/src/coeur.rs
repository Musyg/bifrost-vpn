//! Les coeurs tiers qui portent les protocoles, et la frontiere de licence.
//!
//! Aucune technique de ce crate n'est implementee par Bifrost, sauf WireGuard
//! nu que le produit sait deja monter lui-meme. Les autres sont servies par des
//! programmes ecrits en Go, et le document 04 partie 6 pose la contrainte qui
//! decide de toute l'architecture: sing-box est sous GPL-3.0, donc le lier au
//! client en ferait une oeuvre derivee et imposerait la GPLv3 a tout Bifrost,
//! qui est sous MPL-2.0.
//!
//! La parade est une frontiere de processus. Un executable lance et pilote par
//! une socket n'est pas une oeuvre derivee, et le client reste sous sa propre
//! licence. Cette frontiere n'est pas une intention: elle est verifiee par
//! `tests/frontiere_licence.rs`, qui refuse toute dependance Rust sous GPL ou
//! AGPL, et par le fait qu'aucun coeur n'expose ici de variante "bibliotheque".

use serde::{Deserialize, Serialize};

use crate::technique::Technique;

/// Ce que la licence d'un coeur autorise vis-a-vis d'un client MPL-2.0.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Contrainte {
    /// Copyleft fort: lier contaminerait le client. Processus separe
    /// obligatoire, et le code source doit etre fourni ou offert.
    CopyleftFort,
    /// Copyleft par fichier ou permissive: la liaison ne contaminerait pas.
    /// Le processus separe reste choisi, pour une raison qui n'est plus
    /// juridique mais pratique, ces programmes etant ecrits en Go.
    SansContamination,
}

/// Un coeur tiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Coeur {
    SingBox,
    XrayCore,
    AmneziaWg,
}

impl Coeur {
    pub const TOUS: [Coeur; 3] = [Coeur::SingBox, Coeur::XrayCore, Coeur::AmneziaWg];

    /// Nom de l'executable, sans extension. Le chemin complet vient de la
    /// configuration: coder un chemin en dur reviendrait a decider a la place
    /// de l'empaqueteur.
    pub fn executable(self) -> &'static str {
        match self {
            Coeur::SingBox => "sing-box",
            Coeur::XrayCore => "xray",
            Coeur::AmneziaWg => "amneziawg-go",
        }
    }

    /// Licence declaree en amont, telle que le document 04 partie 6 la releve.
    pub fn licence(self) -> &'static str {
        match self {
            Coeur::SingBox => "GPL-3.0",
            Coeur::XrayCore => "MPL-2.0",
            Coeur::AmneziaWg => "GPL-2.0",
        }
    }

    pub fn contrainte(self) -> Contrainte {
        match self {
            Coeur::SingBox | Coeur::AmneziaWg => Contrainte::CopyleftFort,
            Coeur::XrayCore => Contrainte::SansContamination,
        }
    }

    /// Le coeur expose-t-il une API Clash pour etre pilote a chaud.
    ///
    /// sing-box l'expose et c'est par elle que passent le selecteur et l'etat.
    /// Xray a son propre mecanisme, `observatory` et `balancers`, qui n'est pas
    /// la meme API; AmneziaWG n'a rien de tel et se pilote par sa
    /// configuration au lancement.
    pub fn a_une_api_clash(self) -> bool {
        matches!(self, Coeur::SingBox)
    }
}

/// Qui porte quelle technique.
///
/// `None` veut dire que Bifrost s'en charge lui-meme, sans aucun tiers. C'est
/// le cas de WireGuard nu, qu'il monte deja par netlink sous Linux et par
/// WireGuardNT sous Windows.
///
/// # Ce que cette table est, et ce qu'elle n'est pas
///
/// Un DEFAUT DE DEPLOIEMENT, pas une propriete des protocoles. Xray et
/// sing-box implementent tous deux REALITY; quel executable porte un serveur
/// donne est un choix, et il se revise. Lire cette table comme un fait sur les
/// techniques est ce qui a rendu la question confuse une premiere fois.
pub fn coeur_de(technique: Technique) -> Option<Coeur> {
    match technique {
        // # REALITY est servie par sing-box, et le plan est corrige ici
        //
        // Le document 04 partie 6 designe Xray, "en complement", pour
        // REALITY+Vision+XHTTP: ce sont les fonctionnalites que ce projet porte
        // en premier et le plus abouti. C'est vrai en amont, et ce n'est pas ce
        // qui decide ici.
        //
        // Ce qui decide est la partie 3.3 du MEME document: le choix se pilote
        // "via la Clash API" par un superviseur maison, parce qu'urltest ne
        // detecte ni le gel a 16 Ko ni l'accessibilite reelle. Or
        // `Coeur::a_une_api_clash` dit que seul sing-box expose cette API. Une
        // technique routee vers Xray ne peut donc PAS etre pilotee par le
        // mecanisme que le plan prescrit: il faudrait `observatory` et
        // `balancers`, un autre mecanisme, que ce depot n'a pas ecrit.
        //
        // Et sing-box porte bel et bien la technique, ENTIERE: verifie le 20
        // aout 2026 sur la documentation amont, la sortie `vless` accepte
        // `flow: xtls-rprx-vision` et sa configuration TLS de sortie porte
        // `reality { enabled, public_key, short_id }`, cote client. Mieux: son
        // client REALITY EXIGE uTLS et refuse de demarrer sans lui - "uTLS is
        // required by reality client" - parce que REALITY a besoin d'un champ
        // de session que la bibliotheque TLS standard de Go ne sait pas ecrire.
        // C'est exactement ce que
        // `bifrost_daemon::coeurs::configuration::Sortie` engendre deja,
        // empreinte `chrome` comprise: ce chemin-la n'a rien d'improvise.
        //
        // Aucune objection d'interoperabilite non plus. Le seul rapport qui
        // pretendait le contraire (SagerNet/sing-box#4023, "Reality
        // verification fails when both client and server are sing-box") est
        // clos "not planned", etiquete spam, et son propre auteur y constate
        // qu'un client Xray joint sans peine le meme serveur.
        //
        // Consequence, et c'est elle qui compte: REALITY et Hysteria2 vivent
        // dans le MEME processus, donc derriere le meme selecteur. Basculer de
        // l'une a l'autre ne relance rien, ne bouge pas le SOCKS local et ne
        // demande jamais de lever le kill switch - les trois conditions que la
        // partie 3.2 pose pour une bascule en cours de session. Les separer
        // couterait un echange de coeur a chaque bascule.
        //
        // Rien ne change du cote des licences: sing-box etait deja requis pour
        // Hysteria2, la frontiere reste celle du PROCESSUS, et
        // `tests/frontiere_licence.rs` la garde.
        //
        // # Ce que ce choix coute, parce qu'il coute quelque chose
        //
        // La partie 6 n'est PAS perimee: Xray est bien la ou REALITY se
        // developpe, et il a une longueur d'avance qui porte un nom. **VLESS
        // Encryption** - `mlkem768x25519plus`, confidentialite persistante
        // post-quantique, 1-RTT ou 0-RTT anti-rejeu - est fusionnee dans
        // Xray-core (PR XTLS/Xray-core#5067), avec choix d'authentification
        // post-quantique depuis juillet 2026. sing-box amont ne l'a pas:
        // SagerNet/sing-box#4179 la demande, et elle n'existe que dans un fork
        // (`sing-box-lx`). Passer REALITY a sing-box, c'est renoncer a cela
        // pour l'instant, et il faut le savoir plutot que le decouvrir.
        //
        // # Pourquoi ce renoncement ne coute rien AUJOURD'HUI
        //
        // VLESS Encryption n'est pas exprimable par un lien de partage: sa
        // configuration est une chaine composite - methode de poignee,
        // apparence du trafic, reprise de session, remplissage, parametre
        // d'authentification serveur - et rien ne documente sa forme dans un
        // `vless://`. Or `Profil::depuis_lien` lit des liens et REFUSE les
        // parametres qu'il ne connait pas. La technique serait donc hors de
        // portee meme en restant chez Xray.
        //
        // # Ce qui rouvrira la question, et quand
        //
        // Le jour ou VLESS Encryption comptera, il faudra de toute facon
        // etendre le format de profil pour la porter. C'est CE moment-la qu'il
        // faut saisir pour reexaminer cette ligne - pas avant, et surtout pas
        // en la decouvrant par hasard. Trois choses seront alors a peser
        // ensemble: le generateur Xray qui manque, l'absence d'API Clash de ce
        // cote (donc une seconde mecanique de course, `observatory` et
        // `balancers`), et l'echange de coeur par la facade a chaque bascule
        // entre une technique Xray et une technique sing-box.
        Technique::RealityVision => Some(Coeur::SingBox),
        // XHTTP reste a Xray, lui: c'est une invention de ce projet, et aucune
        // forme de `Profil` ne la decrit encore. Le jour ou elle deviendra un
        // candidat, il faudra soit un generateur Xray, soit l'equivalent en
        // transport sing-box - et la question se reposera entiere.
        Technique::XhttpCdn => Some(Coeur::XrayCore),
        // # Pourquoi HTTPUpgrade va a sing-box, et ce que ce choix repond
        //
        // La ligne au-dessus posait un fork: pour porter un repli CDN, "soit un
        // generateur Xray, soit l'equivalent en transport sing-box". La seconde
        // branche a ete cherchee a la source amont le 21 aout 2026 et elle est
        // FERMEE pour XHTTP: sing-box v1.13.18, celle que ce depot execute,
        // connait cinq transports - `http`, `ws`, `quic`, `grpc`,
        // `httpupgrade` (`constant/v2ray.go`) - et aucun XHTTP. Le changelog
        // n'en porte aucune trace et la demande #3550 a ete supprimee.
        //
        // Mais la question posee n'etait pas "comment avoir XHTTP", c'etait
        // "comment donner un repli au mode Discret". Or `httpupgrade` existe
        // deja dans le coeur qu'on lance: meme processus que REALITY et
        // Hysteria2, meme selecteur, meme generateur. Aucun second coeur,
        // aucune seconde mecanique de course faute d'API Clash chez Xray,
        // aucun echange de coeur par la facade en cours de session - les trois
        // couts que la ligne XhttpCdn ci-dessus nomme et n'a jamais payes.
        //
        // Ce que ce choix NE fait pas: remplacer XHTTP. XHTTP decoupe l'envoi
        // et sait parler `packet-up` a un middlebox qui refuse un flux long;
        // HTTPUpgrade ne sait rien de tout ca. Le jour ou une mesure montrera
        // qu'un CDN ou un censeur coupe HTTPUpgrade la ou XHTTP passe, la
        // ligne au-dessus reprendra tout son sens - et le format de profil,
        // etendu ici, aura deja fait la moitie du chemin.
        //
        // # Le transport a ete corrige par la MESURE, le 21 aout 2026
        //
        // Ce fut d'abord `httpupgrade`, plus leger. A travers un vrai edge
        // Cloudflare il ne passe pas, et aucun reglage ne l'y aidera: le client
        // sing-box annonce `Upgrade: websocket` sans `Sec-WebSocket-Key` ni
        // `Sec-WebSocket-Version`, l'edge refuse par un 400 qui n'atteint jamais
        // l'origine, et le serveur `httpupgrade` refuse a l'inverse une poignee
        // complete. Les deux exigences s'excluent.
        //
        // `ws` passe, mesure de bout en bout: banniere lue a travers le CDN,
        // `101 Switching Protocols` dans le journal du front. Rien de l'analyse
        // ci-dessus ne change - meme coeur, meme processus, meme selecteur -
        // seul le nom du transport bougeait, et seule la mesure pouvait le dire:
        // la documentation amont liste `httpupgrade` comme un transport valide
        // et n'annonce nulle part qu'un CDN le rejettera.
        Technique::WebsocketCdn => Some(Coeur::SingBox),
        // Le meme camouflage sans CDN, garde parce que Bifrost est un CLIENT et
        // que l'operateur du serveur choisit le transport, pas nous.
        Technique::HttpUpgradeFront => Some(Coeur::SingBox),
        Technique::Hysteria2 => Some(Coeur::SingBox),
        Technique::AmneziaWg => Some(Coeur::AmneziaWg),
        Technique::WireGuardNu => None,
    }
}

/// Les coeurs qu'il faut avoir installes pour pouvoir essayer ce plan.
///
/// Sert a refuser tot: proposer un candidat dont le binaire est absent
/// gaspille une tentative et, sur un reseau surveille, une signature.
pub fn coeurs_requis(candidats: &[Technique]) -> Vec<Coeur> {
    let mut v: Vec<Coeur> = candidats.iter().filter_map(|t| coeur_de(*t)).collect();
    v.sort_unstable();
    v.dedup();
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aucun_coeur_a_copyleft_fort_n_est_propose_en_bibliotheque() {
        // L'invariant de licence, exprime la ou il se decide. Ce crate n'a
        // aucune variante "liee": si quelqu'un en ajoutait une, il devrait
        // aussi modifier ce test, ce qui est le point.
        for c in Coeur::TOUS {
            let _ = c.executable();
        }
        assert!(
            Coeur::TOUS
                .iter()
                .any(|c| c.contrainte() == Contrainte::CopyleftFort),
            "si plus aucun coeur n'est copyleft fort, la frontiere merite d'etre rediscutee"
        );
    }

    #[test]
    fn sing_box_est_bien_le_coeur_sous_gpl3() {
        assert_eq!(Coeur::SingBox.licence(), "GPL-3.0");
        assert_eq!(Coeur::SingBox.contrainte(), Contrainte::CopyleftFort);
        assert_eq!(Coeur::XrayCore.contrainte(), Contrainte::SansContamination);
    }

    #[test]
    fn wireguard_nu_ne_demande_aucun_tiers() {
        assert_eq!(coeur_de(Technique::WireGuardNu), None);
    }

    #[test]
    fn chaque_autre_technique_designe_un_coeur() {
        for t in Technique::TOUTES {
            if t == Technique::WireGuardNu {
                continue;
            }
            assert!(coeur_de(t).is_some(), "{} sans coeur", t.nom());
        }
    }

    #[test]
    fn les_coeurs_requis_sont_dedupliques_et_ignorent_le_natif() {
        let requis = coeurs_requis(&[
            Technique::XhttpCdn,
            Technique::XhttpCdn,
            Technique::WireGuardNu,
        ]);
        assert_eq!(requis, vec![Coeur::XrayCore]);
    }

    /// Les deux techniques qu'un profil sait decrire vivent dans le MEME coeur.
    ///
    /// C'est la condition d'une bascule sans relance: un selecteur est interne
    /// a un processus. Si REALITY et Hysteria2 se separaient, passer de l'une a
    /// l'autre demanderait d'echanger le coeur, donc de relancer un processus
    /// pendant que le tunnel est monte - ce que le document 04 partie 3.2
    /// cherche precisement a eviter.
    #[test]
    fn les_deux_techniques_qu_un_profil_decrit_partagent_leur_coeur() {
        assert_eq!(coeur_de(Technique::RealityVision), Some(Coeur::SingBox));
        assert_eq!(coeur_de(Technique::Hysteria2), Some(Coeur::SingBox));
    }

    /// Et ce coeur est pilotable a chaud. Sans cela, le selecteur ne serait
    /// qu'un champ dans un fichier: rien ne pourrait le faire changer d'avis.
    #[test]
    fn le_coeur_qui_porte_les_candidats_se_pilote_a_chaud() {
        for t in [Technique::RealityVision, Technique::Hysteria2] {
            let c = coeur_de(t).expect("ces deux-la passent par un coeur");
            assert!(
                c.a_une_api_clash(),
                "{} est portee par {}, qui ne se pilote pas a chaud",
                t.nom(),
                c.executable()
            );
        }
    }

    #[test]
    fn un_plan_entierement_natif_ne_requiert_rien() {
        assert!(coeurs_requis(&[Technique::WireGuardNu]).is_empty());
        assert!(coeurs_requis(&[]).is_empty());
    }

    #[test]
    fn seul_sing_box_se_pilote_par_l_api_clash() {
        // Supposer que Xray parle Clash ferait attendre indefiniment une API
        // qui n'existe pas de ce cote.
        assert!(Coeur::SingBox.a_une_api_clash());
        assert!(!Coeur::XrayCore.a_une_api_clash());
        assert!(!Coeur::AmneziaWg.a_une_api_clash());
    }
}
