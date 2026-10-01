//! Le plan de routage que le produit pose sous Windows, en donnees pures.
//!
//! # Pourquoi ce module existe
//!
//! Sous Windows, les deux chemins (WireGuardNT et coeur sur un TUN Wintun)
//! posent la meme sorte d'objets par les memes appels IP Helper, sur le LUID
//! de l'interface du tunnel: les adresses, une ligne d'interface par famille
//! adressee (MTU, detection d'adresse dupliquee, et metrique quand le plan
//! capture la famille), puis les routes. Le daemon les execute
//! (`wgnt::ipcfg`); la preuve `prove routes` en tire son attendu. Si la preuve
//! recopiait la pose, sa reference pourrait diverger sans que rien ne le dise:
//! le plan vit donc ICI, une seule fois, comme
//! [`crate::routage::Plan`] pour les commandes `ip` de Linux. La pose execute
//! [`PlanWindows::pose`] et [`PlanWindows::retrait`], la preuve reconstruit le
//! plan au meme constructeur. Ce crate ne touche ni au reseau ni au systeme, et
//! il est compile partout: les recettes du plan tournent aussi sous Linux.
//!
//! # Ce que le plan contient, et ce qu'il laisse
//!
//! Le PLAN DE ROUTAGE est ce qui decide du choix de route: les routes (une par
//! prefixe, metrique nulle, prochain saut non specifie) et, par famille
//! adressee, la ligne d'interface. Les adresses du tunnel ne sont pas dans le
//! plan: la pose les recoit a part ([`PlanWindows::pose`]), parce qu'elles
//! viennent du profil et qu'aucune decision de routage du plan n'en depend,
//! hors la liste des familles adressees, qui y est.
//!
//! # Comment Windows choisit une route
//!
//! La route dont le prefixe est le plus LONG gagne; a longueur egale, la
//! metrique la plus faible; a metrique egale, l'interface la premiere dans
//! l'ordre de liaison en IPv4, et une route choisie par la pile en IPv6
//! (Microsoft Learn, "Chapter 10 - TCP/IP End-to-End Delivery", etapes 4 de
//! l'hote source IPv4 et IPv6, lu le 01/10/2026). La metrique comparee est la
//! SOMME de la metrique de la route (`MIB_IPFORWARD_ROW2.Metric`, un decalage)
//! et de la metrique de l'interface (`MIB_IPINTERFACE_ROW.Metric`)
//! (Microsoft Learn, "MIB_IPFORWARD_ROW2", lu le 01/10/2026). C'est pourquoi
//! la pose force a zero la metrique d'une interface qui prend la route par
//! defaut d'une famille: voir [`LigneInterface::capture`].

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::config::{IpNet, Portage, TunnelConfig};
use crate::routage::Famille;

/// Metrique (decalage) de chaque route du tunnel: zero, comme WireGuard for
/// Windows. La route la plus specifique gagne de toute facon, et une metrique
/// nulle evite que Windows en calcule une qui varierait d'une machine a
/// l'autre.
pub const METRIQUE_ROUTE: u32 = 0;

/// Metrique imposee a la ligne d'interface d'une famille capturee, metrique
/// automatique coupee.
pub const METRIQUE_INTERFACE_CAPTURE: u32 = 0;

/// Sondes de detection d'adresse dupliquee posees sur chaque ligne: aucune.
/// Une adresse restee `Tentative` ne peut pas servir de source, et personne
/// d'autre sur l'interface du tunnel ne peut repondre a la sonde.
pub const SONDES_DAD: u32 = 0;

/// `IF_TYPE_SOFTWARE_LOOPBACK`, le type d'interface que porte le champ `IfType`
/// d'un LUID (bits 48 a 63) pour l'interface de bouclage.
pub const TYPE_BOUCLE_LOCALE: u64 = 24;

/// Le chemin qui pose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheminWindows {
    /// L'adaptateur WireGuardNT: une route par prefixe autorise.
    WireGuard,
    /// Le TUN Wintun du coeur: la route par defaut de chaque famille adressee.
    Coeur,
}

/// Une route du plan, posee sur l'interface du tunnel, prochain saut non
/// specifie.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteWindows {
    /// Destination, deja masquee a son prefixe.
    pub destination: IpNet,
    pub metrique: u32,
}

impl RouteWindows {
    pub fn famille(&self) -> Famille {
        famille_de(&self.destination)
    }
}

/// La ligne d'interface que la pose regle pour une famille adressee, en un
/// seul `GetIpInterfaceEntry` suivi d'un `SetIpInterfaceEntry`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LigneInterface {
    pub famille: Famille,
    pub mtu: u32,
    pub sondes_dad: u32,
    /// Le plan prend la route par defaut de cette famille. Alors, et alors
    /// seulement, la metrique automatique de l'interface est coupee et sa
    /// metrique mise a [`METRIQUE_INTERFACE_CAPTURE`]: sans cela deux routes
    /// `/0` coexistent, celle du lien physique et celle du tunnel, et c'est la
    /// somme des metriques qui departage. WireGuard for Windows fait de meme
    /// (`if foundDefault4 { UseAutomaticMetric = false; Metric = 0 }`), et
    /// sing-tun sous `if AutoRoute`.
    pub capture: bool,
}

impl LigneInterface {
    /// La metrique que la pose impose a la ligne, ou `None` quand elle la
    /// laisse telle que Windows ou un tiers l'a reglee.
    pub fn metrique_imposee(&self) -> Option<u32> {
        self.capture.then_some(METRIQUE_INTERFACE_CAPTURE)
    }
}

/// Le plan: ce que le produit pose sur l'interface du tunnel pour router.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanWindows {
    pub chemin: CheminWindows,
    /// L'alias de l'interface, celui que le peripherique donne a l'adaptateur.
    pub interface: String,
    pub mtu: u32,
    /// Une ligne par famille adressee, IPv4 puis IPv6.
    pub lignes: Vec<LigneInterface>,
    /// Dans l'ordre de pose.
    pub routes: Vec<RouteWindows>,
}

/// Un appel IP Helper de la pose ou du retrait, dans l'ordre ou le daemon
/// l'execute. `wgnt::ipcfg` traduit chacun en un appel, champ pour champ.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationIpHelper {
    /// `CreateUnicastIpAddressEntry`.
    AjouterAdresse(IpNet),
    /// `GetIpInterfaceEntry` puis `SetIpInterfaceEntry`.
    ReglerInterface(LigneInterface),
    /// `CreateIpForwardEntry2`.
    AjouterRoute(RouteWindows),
    /// `DeleteIpForwardEntry2`.
    RetirerRoute(RouteWindows),
    /// `DeleteUnicastIpAddressEntry`.
    RetirerAdresse(IpNet),
}

impl PlanWindows {
    /// Le chemin WireGuard: une route par prefixe autorise, masquee et
    /// dedoublonnee dans l'ordre. Windows refuse une route dont l'adresse
    /// porte des bits hors du prefixe, et `10.1.2.3/8` est une facon legitime
    /// d'ecrire `10.0.0.0/8` dans un profil; deux prefixes qui se ramenent au
    /// meme n'en font qu'une, la seconde serait refusee comme deja presente.
    /// La route par defaut est posee telle quelle, pas decoupee en deux `/1`,
    /// comme WireGuard for Windows (`tunnel/addressconfig.go`).
    pub fn wireguard(interface: &str, familles: &[Famille], autorises: &[IpNet], mtu: u32) -> Self {
        let mut routes: Vec<RouteWindows> = Vec::new();
        for net in autorises {
            let route = RouteWindows {
                destination: masquer(net),
                metrique: METRIQUE_ROUTE,
            };
            if !routes.contains(&route) {
                routes.push(route);
            }
        }
        Self::assembler(CheminWindows::WireGuard, interface, familles, routes, mtu)
    }

    /// Le chemin par coeur: la route par defaut de chaque famille adressee, et
    /// d'elle seule. Un coeur ne dit pas ce qu'il transporte, il porte
    /// n'importe quelle destination: le plan se decide, et la decision est
    /// "tout". Une route IPv6 sur une interface sans adresse IPv6 serait
    /// refusee par Windows. Le `/0` est sur parce que le coeur ne s'echappe pas
    /// par la table de routage mais par sa SOCKET, liee a l'interface physique;
    /// et il ne mange pas le reseau local, dont les routes connectees sont plus
    /// specifiques. sing-tun pose aussi `0.0.0.0/0` hors de macOS.
    pub fn coeur(interface: &str, familles: &[Famille], mtu: u32) -> Self {
        let routes = Famille::TOUTES
            .iter()
            .filter(|f| familles.contains(f))
            .map(|f| RouteWindows {
                destination: IpNet {
                    addr: match f {
                        Famille::Ipv4 => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                        Famille::Ipv6 => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                    },
                    prefix_len: 0,
                },
                metrique: METRIQUE_ROUTE,
            })
            .collect();
        Self::assembler(CheminWindows::Coeur, interface, familles, routes, mtu)
    }

    /// Le plan d'une configuration de tunnel: le chemin vient du portage, les
    /// familles des adresses, les routes des prefixes autorises (WireGuard) ou
    /// des familles (coeur). C'est le seul constructeur que la pose appelle.
    pub fn de_la_configuration(cfg: &TunnelConfig) -> Self {
        let familles = familles_adressees(&cfg.addresses);
        match &cfg.portage {
            Portage::Wireguard(wg) => {
                Self::wireguard(&cfg.interface, &familles, &wg.peer.allowed_ips, cfg.mtu)
            }
            Portage::Coeur(_) => Self::coeur(&cfg.interface, &familles, cfg.mtu),
        }
    }

    fn assembler(
        chemin: CheminWindows,
        interface: &str,
        familles: &[Famille],
        routes: Vec<RouteWindows>,
        mtu: u32,
    ) -> Self {
        let lignes = Famille::TOUTES
            .iter()
            .filter(|f| familles.contains(f))
            .map(|&famille| LigneInterface {
                famille,
                mtu,
                sondes_dad: SONDES_DAD,
                capture: routes
                    .iter()
                    .any(|r| r.destination.prefix_len == 0 && r.famille() == famille),
            })
            .collect();
        Self {
            chemin,
            interface: interface.to_owned(),
            mtu,
            lignes,
            routes,
        }
    }

    /// Les familles adressees, IPv4 puis IPv6: celles qui ont une ligne.
    pub fn familles(&self) -> Vec<Famille> {
        self.lignes.iter().map(|l| l.famille).collect()
    }

    /// La ligne d'une famille, si elle est adressee.
    pub fn ligne(&self, famille: Famille) -> Option<&LigneInterface> {
        self.lignes.iter().find(|l| l.famille == famille)
    }

    /// Les routes d'une famille, dans l'ordre de pose.
    pub fn routes(&self, famille: Famille) -> Vec<RouteWindows> {
        self.routes
            .iter()
            .filter(|r| r.famille() == famille)
            .copied()
            .collect()
    }

    /// Vrai si le plan prend la route par defaut d'au moins une famille: la
    /// garde des bancs, qu'une machine de travail ne doit pas subir.
    pub fn contient_route_par_defaut(&self) -> bool {
        self.routes.iter().any(|r| r.destination.prefix_len == 0)
    }

    /// Les appels de la pose, dans l'ordre: les adresses d'abord (une route vers
    /// une interface sans adresse est refusee par Windows), puis une ligne par
    /// famille adressee, puis les routes. `adresses` est celle du profil, dans
    /// son ordre.
    pub fn pose(&self, adresses: &[IpNet]) -> Vec<OperationIpHelper> {
        adresses
            .iter()
            .map(|a| OperationIpHelper::AjouterAdresse(*a))
            .chain(
                self.lignes
                    .iter()
                    .map(|l| OperationIpHelper::ReglerInterface(*l)),
            )
            .chain(
                self.routes
                    .iter()
                    .map(|r| OperationIpHelper::AjouterRoute(*r)),
            )
            .collect()
    }

    /// Les appels du retrait, dans l'ordre: les routes, puis les adresses. La
    /// ligne d'interface n'est pas restauree: elle disparait avec l'adaptateur.
    pub fn retrait(&self, adresses: &[IpNet]) -> Vec<OperationIpHelper> {
        self.routes
            .iter()
            .map(|r| OperationIpHelper::RetirerRoute(*r))
            .chain(
                adresses
                    .iter()
                    .map(|a| OperationIpHelper::RetirerAdresse(*a)),
            )
            .collect()
    }
}

/// Les familles d'une liste d'adresses, IPv4 puis IPv6, sans doublon.
pub fn familles_adressees(adresses: &[IpNet]) -> Vec<Famille> {
    Famille::TOUTES
        .iter()
        .copied()
        .filter(|f| adresses.iter().any(|a| famille_de(a) == *f))
        .collect()
}

/// La famille d'un prefixe.
pub fn famille_de(net: &IpNet) -> Famille {
    if net.is_ipv4() {
        Famille::Ipv4
    } else {
        Famille::Ipv6
    }
}

/// Remet a zero les bits situes hors du prefixe.
pub fn masquer(net: &IpNet) -> IpNet {
    let addr = match net.addr {
        IpAddr::V4(v4) => {
            let bits = u32::from(v4);
            let masque = if net.prefix_len == 0 {
                0
            } else {
                u32::MAX << (32 - u32::from(net.prefix_len.min(32)))
            };
            IpAddr::V4(Ipv4Addr::from(bits & masque))
        }
        IpAddr::V6(v6) => {
            let bits = u128::from(v6);
            let masque = if net.prefix_len == 0 {
                0
            } else {
                u128::MAX << (128 - u32::from(net.prefix_len.min(128)))
            };
            IpAddr::V6(Ipv6Addr::from(bits & masque))
        }
    };
    IpNet {
        addr,
        prefix_len: net.prefix_len,
    }
}

/// Vrai si `interieur` est contenu dans `exterieur`: meme famille, prefixe au
/// moins aussi long, et memes bits sur la longueur de `exterieur`.
pub fn contient(exterieur: &IpNet, interieur: &IpNet) -> bool {
    famille_de(exterieur) == famille_de(interieur)
        && interieur.prefix_len >= exterieur.prefix_len
        && masquer(&IpNet {
            addr: interieur.addr,
            prefix_len: exterieur.prefix_len,
        }) == masquer(exterieur)
}

/// Vrai si le LUID designe l'interface de bouclage: son champ `IfType` (bits 48
/// a 63 du LUID, `NET_LUID_LH.Info`) vaut `IF_TYPE_SOFTWARE_LOOPBACK`.
pub fn est_boucle_locale(luid: u64) -> bool {
    luid >> 48 == TYPE_BOUCLE_LOCALE
}

// ---------------------------------------------------------------------------
// Ce que la lecture des tables IP Helper rend, en donnees pures: pour que la
// preuve et ses recettes a lecture factice compilent et comptent partout.
// ---------------------------------------------------------------------------

/// Une route de `GetIpForwardTable2`, sans ses valeurs d'etat (age, durees de
/// vie restantes), qui changent seules entre deux lectures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteLue {
    /// Le LUID de l'interface.
    pub interface: u64,
    /// Le prefixe de destination, tel que la table le rend.
    pub destination: IpNet,
    /// `None` quand le prochain saut est non specifie: la route est sur le
    /// lien (ou de bouclage).
    pub prochain_saut: Option<IpAddr>,
    /// Le decalage de la route, a ajouter a la metrique de l'interface.
    pub metrique: u32,
}

impl RouteLue {
    pub fn famille(&self) -> Famille {
        famille_de(&self.destination)
    }
}

/// Une ligne de `GetIpInterfaceTable`: ce qui entre dans le choix de route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LigneLue {
    pub interface: u64,
    pub famille: Famille,
    pub metrique: u32,
    pub metrique_automatique: bool,
}

/// Une adresse de `GetUnicastIpAddressTable`: l'adresse et la longueur de son
/// prefixe sur le lien, ce qui suffit a reconnaitre ses routes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdresseLue {
    pub interface: u64,
    pub adresse: IpNet,
}

/// Une lecture complete: l'interface du tunnel, et les trois tables de toutes
/// les interfaces, dans les deux familles.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TableIpHelper {
    /// Le LUID que porte l'alias du tunnel, `None` s'il n'existe pas.
    pub tunnel: Option<u64>,
    pub routes: Vec<RouteLue>,
    pub lignes: Vec<LigneLue>,
    pub adresses: Vec<AdresseLue>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{DnsPolicy, Endpoint, PeerConfig, WgKey};

    fn net(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    fn cle(c: char) -> WgKey {
        let mut s: String = std::iter::repeat_n(c, 42).collect();
        s.push('A');
        s.push('=');
        s.parse().unwrap()
    }

    fn cfg(adresses: &[&str], autorises: &[&str]) -> TunnelConfig {
        TunnelConfig {
            interface: "wg0".into(),
            addresses: adresses.iter().map(|s| net(s)).collect(),
            mtu: 1420,
            portage: Portage::Wireguard(Box::new(crate::config::WireguardParams {
                private_key: cle('A'),
                fwmark: 0xca6c,
                routing_table: 51820,
                listen_port: None,
                peer: PeerConfig {
                    public_key: cle('B'),
                    preshared_key: None,
                    endpoint: Endpoint {
                        addr: "203.0.113.7:51820".parse().unwrap(),
                    },
                    allowed_ips: autorises.iter().map(|s| net(s)).collect(),
                    persistent_keepalive: 25,
                },
            })),
            dns: DnsPolicy {
                local_resolver: IpAddr::V4(Ipv4Addr::LOCALHOST),
                upstream: vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))],
                embarque: false,
                anti_telemetrie: crate::config::ProfilTelemetrie::Aucun,
            },
            allow_lan: false,
        }
    }

    fn cfg_coeur(adresses: &[&str]) -> TunnelConfig {
        let profil = crate::profil::Profil::depuis_lien("hy2://mdp@192.0.2.11:8443")
            .expect("le lien de documentation doit se lire");
        TunnelConfig {
            portage: Portage::Coeur(Box::new(profil.into())),
            ..cfg(adresses, &["0.0.0.0/0"])
        }
    }

    fn rendu(ops: &[OperationIpHelper]) -> Vec<String> {
        ops.iter()
            .map(|op| match op {
                OperationIpHelper::AjouterAdresse(a) => format!("adresse+ {a}"),
                OperationIpHelper::ReglerInterface(l) => format!(
                    "ligne {} mtu {} dad {} metrique {:?}",
                    l.famille.nom(),
                    l.mtu,
                    l.sondes_dad,
                    l.metrique_imposee()
                ),
                OperationIpHelper::AjouterRoute(r) => {
                    format!("route+ {} metrique {}", r.destination, r.metrique)
                }
                OperationIpHelper::RetirerRoute(r) => {
                    format!("route- {} metrique {}", r.destination, r.metrique)
                }
                OperationIpHelper::RetirerAdresse(a) => format!("adresse- {a}"),
            })
            .collect()
    }

    /// La pose de chaque chemin, appel par appel et dans l'ordre: celle que
    /// `ipcfg::apply` et `ipcfg::remove` executaient avant que le plan vive
    /// ici, relue dans leur code d'alors: les adresses du profil dans leur ordre, une
    /// ligne par famille adressee (IPv4 puis IPv6) avec la MTU du profil,
    /// aucune sonde DAD et la metrique a zero seulement pour une famille
    /// capturee, puis les routes masquees et dedoublonnees, metrique zero.
    #[test]
    fn la_pose_de_chaque_chemin_est_celle_de_la_base_appel_pour_appel() {
        let c = cfg(
            &["10.2.0.2/32", "fd00::2/128"],
            &["10.1.2.3/8", "0.0.0.0/0", "10.0.0.0/8", "2001:db8::5/32"],
        );
        let p = PlanWindows::de_la_configuration(&c);
        assert_eq!(
            rendu(&p.pose(&c.addresses)),
            [
                "adresse+ 10.2.0.2/32",
                "adresse+ fd00::2/128",
                "ligne ipv4 mtu 1420 dad 0 metrique Some(0)",
                "ligne ipv6 mtu 1420 dad 0 metrique None",
                "route+ 10.0.0.0/8 metrique 0",
                "route+ 0.0.0.0/0 metrique 0",
                "route+ 2001:db8::/32 metrique 0",
            ]
        );
        assert_eq!(
            rendu(&p.retrait(&c.addresses)),
            [
                "route- 10.0.0.0/8 metrique 0",
                "route- 0.0.0.0/0 metrique 0",
                "route- 2001:db8::/32 metrique 0",
                "adresse- 10.2.0.2/32",
                "adresse- fd00::2/128",
            ]
        );

        let c = cfg_coeur(&["10.7.0.2/32", "fd00::2/128"]);
        let p = PlanWindows::de_la_configuration(&c);
        assert_eq!(p.chemin, CheminWindows::Coeur);
        assert_eq!(
            rendu(&p.pose(&c.addresses)),
            [
                "adresse+ 10.7.0.2/32",
                "adresse+ fd00::2/128",
                "ligne ipv4 mtu 1420 dad 0 metrique Some(0)",
                "ligne ipv6 mtu 1420 dad 0 metrique Some(0)",
                "route+ 0.0.0.0/0 metrique 0",
                "route+ ::/0 metrique 0",
            ]
        );
        assert_eq!(
            rendu(&p.retrait(&c.addresses)),
            [
                "route- 0.0.0.0/0 metrique 0",
                "route- ::/0 metrique 0",
                "adresse- 10.7.0.2/32",
                "adresse- fd00::2/128",
            ]
        );
    }

    /// Une famille non adressee n'a pas de ligne, et le coeur ne lui invente
    /// pas de route; un plan WireGuard etroit ne capture rien.
    #[test]
    fn une_famille_non_adressee_n_a_ni_ligne_ni_route_du_coeur() {
        let p = PlanWindows::de_la_configuration(&cfg_coeur(&["fd00::2/128"]));
        assert_eq!(p.familles(), [Famille::Ipv6]);
        assert_eq!(p.routes.len(), 1);
        assert_eq!(p.routes[0].destination.to_string(), "::/0");

        let p = PlanWindows::de_la_configuration(&cfg(&["10.2.0.2/32"], &["198.51.100.0/24"]));
        assert_eq!(p.familles(), [Famille::Ipv4]);
        assert!(!p.lignes[0].capture);
        assert_eq!(p.lignes[0].metrique_imposee(), None);
        assert!(!p.contient_route_par_defaut());
    }

    /// Le plan reconstruit depuis ce qu'il declare (chemin, interface, MTU,
    /// familles et, pour WireGuard, les destinations posees) est le plan pose:
    /// masquer et dedoublonner sont idempotents.
    #[test]
    fn le_plan_se_reconstruit_depuis_ce_qu_il_declare() {
        let c = cfg(
            &["10.2.0.2/32", "fd00::2/128"],
            &["10.1.2.3/8", "10.0.0.0/8", "::/0"],
        );
        let p = PlanWindows::de_la_configuration(&c);
        let destinations: Vec<IpNet> = p.routes.iter().map(|r| r.destination).collect();
        assert_eq!(
            PlanWindows::wireguard(&p.interface, &p.familles(), &destinations, p.mtu),
            p
        );
        let c = cfg_coeur(&["10.7.0.2/32"]);
        let p = PlanWindows::de_la_configuration(&c);
        assert_eq!(PlanWindows::coeur(&p.interface, &p.familles(), p.mtu), p);
    }

    #[test]
    fn la_destination_est_masquee_et_la_contenance_suit_les_bits() {
        for (brut, attendu) in [
            ("10.1.2.3/8", "10.0.0.0/8"),
            ("203.0.113.7/32", "203.0.113.7/32"),
            ("1.2.3.4/0", "0.0.0.0/0"),
            ("2001:db8:1234::5/32", "2001:db8::/32"),
            ("2001:db8::5/0", "::/0"),
        ] {
            assert_eq!(masquer(&net(brut)).to_string(), attendu, "{brut}");
        }
        assert!(contient(&net("0.0.0.0/0"), &net("198.51.100.0/25")));
        assert!(contient(&net("198.51.100.0/24"), &net("198.51.100.128/25")));
        assert!(contient(&net("198.51.100.0/24"), &net("198.51.100.0/24")));
        assert!(!contient(&net("198.51.100.0/24"), &net("198.51.0.0/16")));
        assert!(!contient(&net("198.51.100.0/24"), &net("203.0.113.0/25")));
        assert!(!contient(&net("::/0"), &net("198.51.100.0/24")));
        assert!(contient(&net("::/0"), &net("2001:db8::/48")));
    }

    #[test]
    fn le_type_du_luid_designe_la_boucle_locale() {
        assert!(est_boucle_locale(24 << 48 | 1));
        assert!(!est_boucle_locale(6 << 48 | 1));
        assert!(!est_boucle_locale(53 << 48 | 1));
    }
}
