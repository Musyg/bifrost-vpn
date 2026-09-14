//! Traits que le daemon branche sur les implementations systeme.
//!
//! Les methodes sont synchrones: ce sont des appels netlink, WFP ou des
//! sous-processus courts. Le daemon les execute sur un thread dedie plutot que
//! de contaminer tout le code d'une couche async.

use std::net::IpAddr;
use std::path::PathBuf;
use std::time::SystemTime;

use crate::Result;
use crate::config::{DnsPolicy, Portage, TunnelConfig};

/// Ce que le kill switch doit laisser passer. Tout le reste est bloque.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirewallPolicy {
    /// Interface du tunnel. `None` tant qu'elle n'existe pas: le kill switch
    /// est arme avant, avec un block-all qui ne connait pas encore le tunnel.
    pub tunnel_interface: Option<String>,
    /// Identifiant systeme de cette interface, quand la plateforme en fournit
    /// un plus sur que le nom.
    ///
    /// Sous Windows, WFP designe une interface par son LUID, et le deduire du
    /// nom est une resolution qui peut echouer ou arriver avant que Windows ait
    /// enregistre l'alias. WireGuardNT, lui, rend le LUID directement: c'est
    /// celui-la qui fait foi. Sous Linux, `None`: nftables designe l'interface
    /// par son nom, sans lookup.
    ///
    /// La machine a etats ne le connait pas, elle ne fait que decider. C'est le
    /// superviseur qui le complete au moment d'executer l'action, une fois
    /// l'interface montee.
    pub tunnel_luid: Option<u64>,
    /// Marque portee par le trafic deja chiffre par WireGuard.
    ///
    /// `None` quand RIEN ne sort marque, c'est-a-dire quand un coeur porte le
    /// trafic: il tourne en espace utilisateur, ses paquets n'ont pas de
    /// marque, et il s'exempte par son identite. Le ruleset n'emet alors aucun
    /// permit de marque du tout.
    ///
    /// `None` et `Some(0)` sont deux choses opposees, et c'est pour les
    /// distinguer que ce champ est devenu optionnel. `Some(0)` rendrait
    /// `meta mark 0x0 accept`, qui matche tout paquet NON marque, donc tout le
    /// trafic: le kill switch deviendrait un laissez-passer tout en
    /// journalisant qu'il est arme. Avant ce changement, "pas de marque" ne
    /// pouvait s'ecrire que `0`, et le seul recours etait de refuser d'armer.
    pub fwmark: Option<u32>,
    /// Seule destination :53 autorisee hors tunnel.
    pub dns_resolver: IpAddr,
    /// Autorise les prefixes RFC1918 hors tunnel.
    pub allow_lan: bool,
    /// UID dedie sous lequel tourne le coeur anti-censure, quand il y en a un.
    ///
    /// Un coeur est par construction ce qui sort HORS du tunnel, puisque c'est
    /// LUI le transport: ses paquets ne portent pas le `fwmark` et ne passent
    /// pas par l'interface du tunnel. Sans cette exemption, la `policy drop`
    /// les jette, et le kill switch etrangle le composant meme qui devait
    /// porter le trafic.
    ///
    /// L'exemption designe une IDENTITE, jamais une destination. Autoriser
    /// l'IP du serveur ouvrirait un canal de sortie en clair utilisable par
    /// n'importe quel programme de la machine, ce que ce depot refuse deja
    /// pour l'endpoint WireGuard.
    ///
    /// UID plutot que `cgroup v2`, alors que le document 02 propose les deux:
    /// l'identifiant de cgroup que nftables matche est un NUMERO qui change a
    /// chaque redemarrage du service, ce que le document signale lui-meme, et
    /// son matching en namespace n'est fiable qu'a partir du noyau 6.12 quand
    /// Ubuntu 24.04 est livre en 6.8. Un UID n'a aucun des deux defauts, il se
    /// teste dans les namespaces du harnais de fuite, et il est le pendant
    /// exact de ce que Windows fait deja en combinant `ALE_APP_ID` et
    /// `ALE_USER_ID`.
    pub coeur_uid: Option<u32>,
    /// Executable du coeur anti-censure, pour les plateformes qui designent un
    /// processus par son binaire plutot que par son utilisateur.
    ///
    /// Sous Windows, c'est `ALE_APP_ID`. Piege documente par le document 02 et
    /// par le crate `windows-wfp`: la condition attend un chemin NT
    /// (`\device\harddiskvolume...`) et non un chemin DOS, faute de quoi le
    /// filtre ne matche JAMAIS, sans erreur a la pose.
    pub coeur_executable: Option<PathBuf>,
    /// UID du resolveur chiffre embarque, quand il y en a un.
    ///
    /// Le contraire exact de `coeur_uid`, et il faut le lire ainsi pour ne pas
    /// confondre les deux. Le coeur est exempte pour sortir HORS du tunnel,
    /// parce qu'il EST le transport. Le resolveur, lui, n'est exempte de rien:
    /// son trafic doit passer par le tunnel comme celui de tout le monde. Son
    /// UID sert a RESTREINDRE, pas a ouvrir.
    ///
    /// Ce qu'il restreint: sans resolveur embarque, `oifname <tunnel> accept`
    /// laisse n'importe quelle application interroger le resolveur public de
    /// son choix A TRAVERS le tunnel. Rien ne fuit sur le fil local, mais la
    /// requete ressort en clair a la sortie du tunnel, et l'utilisateur croit
    /// interroger le resolveur annonce. Declarer cet UID pose un `drop` du
    /// :53 AVANT l'acceptation du tunnel, avec pour seule exception le
    /// resolveur lui-meme, qui a besoin du :53 en clair pour son bootstrap.
    ///
    /// `None` conserve le comportement anterieur: le :53 circule librement
    /// dans le tunnel. C'est le seul choix correct tant qu'aucun resolveur
    /// local n'ecoute, sans quoi le kill switch etranglerait la resolution au
    /// lieu de la rerouter.
    pub resolveur_uid: Option<u32>,
    /// Executable du resolveur chiffre embarque, pour les plateformes qui
    /// designent un processus par son binaire plutot que par son utilisateur.
    ///
    /// Le pendant Windows de `resolveur_uid`, exactement comme
    /// `coeur_executable` l'est de `coeur_uid`. Sous Windows, WFP compare
    /// `ALE_APP_ID`, et le meme piege du chemin NT s'y applique.
    ///
    /// Le SENS reste celui de `resolveur_uid`, et c'est ce qu'il ne faut pas
    /// confondre: le blocage du :53 existe deja sans ce champ, pose au-dessus
    /// du permit du tunnel. Ce que ce champ ajoute est l'EXCEPTION qui rend le
    /// resolveur possible - sans elle il ne peut pas resoudre le nom de son
    /// propre serveur chiffre, et rien ne demarre. L'exception est bornee au
    /// :53: la donner large ferait du resolveur un second coeur, c'est-a-dire
    /// une sortie en clair hors tunnel.
    pub resolveur_executable: Option<std::path::PathBuf>,
    /// SID du compte de service Windows sous lequel tourne le resolveur, quand
    /// l'exploitation en declare un.
    ///
    /// Le pendant exact de `resolveur_executable`, un cran plus loin. Windows
    /// combine `ALE_APP_ID` (le chemin, porte par `resolveur_executable`) et
    /// `ALE_USER_ID` (l'identite, portee par ce champ): sans compte declare,
    /// l'identite reste celle du daemon (`Identity::Current`, le comportement
    /// d'aujourd'hui); avec un compte, le filtre `permit-resolveur-dns` nomme
    /// ce SID, si bien qu'une copie du binaire lancee sous une autre identite
    /// ne matcherait plus. Il est renseigne par `IdentiteResolveur::restreindre`
    /// avec la meme discipline que `resolveur_uid` et `resolveur_executable`:
    /// pose quand le profil embarque un resolveur, efface sinon.
    ///
    /// Toujours `None` hors Windows: Linux nomme le resolveur par l'UID
    /// proprietaire du socket (`resolveur_uid`), jamais par un SID. Le champ
    /// existe quand meme sur les deux plateformes, comme `resolveur_executable`,
    /// pour que `wfp_plan` - qui compile partout - le lise sans `cfg`.
    pub resolveur_sid: Option<String>,

    /// Le profil actif fait-il passer le DNS par un resolveur local.
    ///
    /// Recopie de `dns.embarque`, et c'est ce qui autorise la restriction
    /// ci-dessus a exister. Les deux ne sont pas redondants: l'UID vient de
    /// l'EXPLOITATION, qui nomme un compte une fois pour toutes au demarrage
    /// du daemon; ce drapeau vient du PROFIL, qui change a chaque connexion.
    /// Fermer le :53 parce qu'un compte est declare, sur un profil qui ne
    /// route pas le DNS par la boucle locale, retirerait la resolution de
    /// noms a la machine au lieu de la durcir.
    pub resolveur_embarque: bool,
}

impl FirewallPolicy {
    pub fn from_config(cfg: &TunnelConfig) -> Self {
        // Tout ce que le pare-feu a besoin de savoir du portage: par ou le
        // trafic sort en clair. WireGuard sort chiffre et marque, donc la
        // marque ouvre la sortie. Un coeur ne sort pas marque du tout.
        //
        // Il n'y a rien a dire de l'ENDPOINT, et c'est delibere: ce depot
        // n'autorise jamais une destination par son IP, ce qui ouvrirait un
        // canal de sortie en clair a n'importe quel programme du poste. Un
        // champ `endpoints` a existe ici, ecrit par tous les appelants et lu
        // par aucun moteur de rendu; il a ete retire plutot que garde, parce
        // qu'une politique qui NOMME des endpoints laisse croire qu'elle les
        // autorise.
        let fwmark = match &cfg.portage {
            Portage::Wireguard(w) => Some(w.fwmark),
            Portage::Coeur(_) => None,
        };
        Self {
            tunnel_interface: None,
            tunnel_luid: None,
            fwmark,
            dns_resolver: cfg.dns.local_resolver,
            allow_lan: cfg.allow_lan,
            // Aucun coeur par defaut: le tunnel WireGuard nu n'en lance pas.
            // C'est le superviseur qui renseigne ces champs au moment ou il en
            // demarre un, comme il complete deja `tunnel_luid`.
            coeur_uid: None,
            coeur_executable: None,
            // Meme raison, et meme moment: le superviseur le renseigne quand
            // il demarre reellement un resolveur embarque. Le poser d'avance
            // fermerait le :53 du tunnel sans que rien n'ecoute en face.
            resolveur_uid: None,
            resolveur_executable: None,
            // Aucun compte de service par defaut, comme les champs ci-dessus:
            // c'est le superviseur qui pose le SID quand il arme, via
            // `IdentiteResolveur::restreindre`, et seulement sous Windows.
            resolveur_sid: None,
            resolveur_embarque: cfg.dns.embarque,
        }
    }
}

/// Le kill switch. Fail-closed: une fois engage il reste en place jusqu'a un
/// `disengage` explicite, y compris si le daemon redemarre.
pub trait KillSwitch: Send {
    /// Pose la politique de blocage. Idempotent: un second appel remplace la
    /// politique de facon atomique, sans fenetre ou rien ne bloque.
    fn engage(&mut self, policy: &FirewallPolicy) -> Result<()>;

    /// Retire tous les filtres. C'est la seule operation qui rouvre le trafic.
    fn disengage(&mut self) -> Result<()>;

    /// Interroge l'etat reel du systeme, pas un booleen memorise.
    fn is_engaged(&self) -> Result<bool>;

    /// Nom de la plateforme, pour les diagnostics.
    fn backend(&self) -> &'static str;
}

/// Etat du handshake WireGuard, lu depuis le device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeInfo {
    pub last_handshake: Option<SystemTime>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

impl HandshakeInfo {
    /// Un handshake WireGuard est renouvele toutes les 120 s. Au-dela de 180 s
    /// sans handshake, le pair est considere injoignable.
    pub const STALE_AFTER: std::time::Duration = std::time::Duration::from_secs(180);

    pub fn is_alive(&self, now: SystemTime) -> bool {
        match self.last_handshake {
            Some(t) => now
                .duration_since(t)
                .map(|d| d < Self::STALE_AFTER)
                .unwrap_or(true),
            None => false,
        }
    }
}

/// Le device WireGuard et son routage.
pub trait TunnelDevice: Send {
    /// Cree l'interface, applique cles et pair, pose adresses, routes et regles.
    fn up(&mut self, cfg: &TunnelConfig) -> Result<()>;

    /// Detruit l'interface et nettoie routes et regles. Idempotent.
    fn down(&mut self, cfg: &TunnelConfig) -> Result<()>;

    /// `None` si l'interface n'existe pas.
    fn handshake(&self, cfg: &TunnelConfig) -> Result<Option<HandshakeInfo>>;

    /// Identifiant systeme de l'interface montee, quand il en existe un plus
    /// sur que son nom. Voir [`FirewallPolicy::tunnel_luid`].
    ///
    /// La valeur par defaut convient a toute plateforme ou le kill switch
    /// designe l'interface par son nom, ce qui est le cas de nftables.
    fn interface_handle(&self) -> Option<u64> {
        None
    }
}

/// La configuration du resolveur systeme pendant la duree du tunnel.
pub trait DnsManager: Send {
    fn apply(&mut self, interface: &str, policy: &DnsPolicy) -> Result<()>;
    fn restore(&mut self) -> Result<()>;
    fn backend(&self) -> &'static str;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn handshake_absent_signifie_mort() {
        let h = HandshakeInfo {
            last_handshake: None,
            rx_bytes: 0,
            tx_bytes: 0,
        };
        assert!(!h.is_alive(SystemTime::now()));
    }

    #[test]
    fn handshake_recent_signifie_vivant() {
        let now = SystemTime::now();
        let h = HandshakeInfo {
            last_handshake: Some(now - Duration::from_secs(30)),
            rx_bytes: 1,
            tx_bytes: 1,
        };
        assert!(h.is_alive(now));
    }

    #[test]
    fn handshake_perime_signifie_mort() {
        let now = SystemTime::now();
        let h = HandshakeInfo {
            last_handshake: Some(now - Duration::from_secs(200)),
            rx_bytes: 1,
            tx_bytes: 1,
        };
        assert!(!h.is_alive(now));
    }

    /// Une configuration de forme WireGuard, telle que le reste du depot en
    /// construit. Le profil de coeur s'y greffe en changeant le seul champ qui
    /// interesse le pare-feu.
    fn config() -> TunnelConfig {
        let cle = |c: char| -> crate::config::WgKey {
            let mut s: String = std::iter::repeat_n(c, 42).collect();
            s.push('A');
            s.push('=');
            s.parse().unwrap()
        };
        TunnelConfig {
            interface: "wg0".into(),
            addresses: vec!["10.2.0.2/32".parse().unwrap()],
            mtu: 1420,
            portage: Portage::Wireguard(Box::new(crate::config::WireguardParams {
                private_key: cle('a'),
                fwmark: 0xca6c,
                routing_table: 51820,
                listen_port: None,
                peer: crate::config::PeerConfig {
                    public_key: cle('b'),
                    preshared_key: None,
                    endpoint: crate::config::Endpoint {
                        addr: "203.0.113.7:51820".parse().unwrap(),
                    },
                    allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
                    persistent_keepalive: 25,
                },
            })),
            dns: DnsPolicy {
                local_resolver: IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                upstream: vec![IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)],
                embarque: false,
                anti_telemetrie: crate::config::ProfilTelemetrie::Aucun,
            },
            allow_lan: false,
        }
    }

    #[test]
    fn un_portage_wireguard_ouvre_la_sortie_par_la_marque() {
        let p = FirewallPolicy::from_config(&config());
        assert_eq!(p.fwmark, Some(0xca6c));
    }

    /// Le coeur de ce changement.
    ///
    /// Un coeur porte le trafic lui-meme: rien ne sort marque, et il n'y a pas
    /// d'endpoint WireGuard a nommer. Recopier `cfg.fwmark` ici ouvrirait une
    /// sortie que rien n'emprunte; le mettre a `Some(0)` les ouvrirait toutes.
    #[test]
    fn un_portage_par_coeur_n_ouvre_rien_par_la_marque() {
        let profil = crate::profil::Profil::depuis_lien(
            "hysteria2://mot-de-passe@203.0.113.8:8443/?sni=exemple.test#Essai",
        )
        .expect("le lien doit se lire");
        let cfg = TunnelConfig {
            portage: Portage::Coeur(Box::new(profil.into())),
            ..config()
        };
        let p = FirewallPolicy::from_config(&cfg);
        assert_eq!(
            p.fwmark, None,
            "un coeur ne produit aucun paquet marque: aucune marque ne doit ouvrir la sortie"
        );
    }

    /// Le champ `fwmark` de la configuration reste renseigne pour un coeur -
    /// c'est le remplissage que `TunnelConfig` impose encore - et il ne doit
    /// PAS remonter dans la politique. Le test le dit explicitement pour qu'un
    /// futur refactor qui le recopierait echoue ici.
    #[test]
    fn le_fwmark_de_remplissage_ne_remonte_pas_dans_la_politique() {
        let profil =
            crate::profil::Profil::depuis_lien("hy2://mot-de-passe@203.0.113.8:8443").unwrap();
        // Le remplissage n'existe plus dans le type: un portage par coeur ne
        // PEUT plus porter de marque. Le test garde sa raison d'etre - verifier
        // que la politique n'en fabrique pas une - et gagne la garantie que le
        // compilateur interdit desormais l'etat qu'il surveillait.
        let cfg = TunnelConfig {
            portage: Portage::Coeur(Box::new(profil.into())),
            ..config()
        };
        assert_eq!(FirewallPolicy::from_config(&cfg).fwmark, None);
    }
}
