//! Ce qu'il faut poser sur l'interface du tunnel: adresses et routes.
//!
//! WireGuardNT ne fait que le transport chiffre. Il ignore les adresses IP, les
//! routes et le MTU, exactement comme le module noyau sous Linux. Ce module
//! decide quoi poser; il ne pose rien lui-meme, donc il se teste partout.
//!
//! Depuis le 20 aout 2026 il decide AUSSI pour le chemin par coeur, dont
//! l'interface est un TUN Wintun et non un adaptateur WireGuardNT. Les deux
//! posent la meme sorte d'objets par les memes appels; seul le PLAN differe, et
//! c'est ce que [`routes_for`] distingue.
//!
//! Le plan reproduit celui de WireGuard for Windows
//! (`tunnel/addressconfig.go`): une route par prefixe autorise, metrique nulle,
//! prochain saut non specifie. En particulier `0.0.0.0/0` est pose tel quel et
//! **pas** decoupe en deux moities `/1`, contrairement a ce que font certains
//! clients pour laisser l'endpoint joignable hors tunnel.
//!
//! Cette derniere difference merite d'etre comprise avant de la reproduire.
//! Sous Linux, Bifrost evite la boucle par le fwmark: le trafic deja chiffre
//! porte une marque et echappe a la table du tunnel. Sous Windows il n'y a pas
//! de fwmark. **WireGuardNT exclut lui-meme ses paquets de transport du routage
//! du tunnel**, et ce n'est plus une deduction: c'est mesure.
//!
//! L'epreuve, faite le 1er aout 2026 avec `--wgnt-e2e`: on route l'adresse de
//! l'endpoint ELLE-MEME dans le tunnel, ce qui reproduit exactement la
//! condition de bouclage avec une portee d'une seule adresse au lieu de toute
//! la machine. `GetBestRoute2` confirme que Windows choisit alors le tunnel
//! pour joindre l'endpoint, et le handshake aboutit quand meme, donnees
//! comprises. Le driver ne suit donc pas la table de routage pour son propre
//! transport.
//!
//! Ce que l'epreuve ne couvre pas: un vrai `0.0.0.0/0`, qui touche aussi le
//! DNS, le MTU des gros paquets et tout le reste du trafic de la machine. La
//! question du bouclage, elle, est tranchee.

use std::net::{IpAddr, Ipv6Addr};

use bifrost_core::config::{IpNet, TunnelConfig};

/// Metrique des routes du tunnel. Zero, comme WireGuard for Windows: la route
/// la plus specifique gagne de toute facon, et une metrique nulle evite que
/// Windows en calcule une automatiquement qui varierait d'une machine a l'autre.
pub const ROUTE_METRIC: u32 = 0;

/// Une route a poser sur l'interface du tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Route {
    /// Destination, deja masquee a son prefixe.
    pub dest: IpNet,
    pub metric: u32,
}

/// Les routes a poser pour cette configuration.
///
/// Sous WireGuard: une par prefixe autorise, dedupliquee. La destination est
/// masquee, Windows refusant une route dont l'adresse porte des bits hors du
/// prefixe, et `10.1.2.3/8` etant une facon parfaitement legitime d'ecrire
/// `10.0.0.0/8` dans un fichier de configuration.
///
/// Sous coeur: voir [`routes_du_coeur`], qui n'a pas de prefixes autorises a
/// lire et prend tout.
pub fn routes_for(cfg: &TunnelConfig) -> Vec<Route> {
    let mut routes: Vec<Route> = Vec::new();
    let Some(wg) = cfg.portage.wireguard() else {
        return routes_du_coeur(cfg);
    };
    for net in &wg.peer.allowed_ips {
        let route = Route {
            dest: masked(net),
            metric: ROUTE_METRIC,
        };
        if !routes.contains(&route) {
            routes.push(route);
        }
    }
    routes
}

/// Route hote vers l'endpoint, posee SUR LE TUNNEL.
///
/// Elle sert a PROVOQUER la condition de bouclage, que le banc ne rencontre
/// jamais autrement: quand le pair est sur le meme lien que la machine, il est
/// joint par une route on-link plus specifique que la route par defaut, et la
/// question ne se pose pas. Avec une route hote sur le tunnel, la table de
/// routage affirme que l'endpoint se joint PAR LE TUNNEL LUI-MEME. Un handshake
/// obtenu malgre ca etablit que le driver exclut ses propres paquets chiffres
/// du routage; sans cette exclusion, ils y retourneraient indefiniment.
///
/// Le prefixe hote n'est pas un detail: c'est la route la plus specifique qui
/// gagne, et une `/24` on-link battrait aussi bien une `/0` qu'une `/25`.
pub fn route_bouclage(endpoint: IpAddr) -> Route {
    let prefix_len = match endpoint {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    Route {
        dest: IpNet {
            addr: endpoint,
            prefix_len,
        },
        metric: ROUTE_METRIC,
    }
}

/// Le plan du chemin par coeur: tout entre dans le TUN.
///
/// # Ce qui remplace les prefixes autorises
///
/// WireGuard sait ce qu'il transporte, et le dit: `AllowedIPs` est a la fois
/// une politique de chiffrement et un plan de routage. Un coeur ne dit rien de
/// tel - il porte n'importe quelle destination vers son serveur - donc le plan
/// ne se lit nulle part: il se decide, et la decision est "tout".
///
/// Une route par famille effectivement adressee. Une route IPv6 sur une
/// interface qui n'a pas d'adresse IPv6 serait refusee par Windows, et une
/// famille laissee dehors sortirait EN CLAIR par le lien physique - c'est
/// exactement le cas que `--ipv6-leak` mesure.
///
/// # Pourquoi `/0` et non deux moities `/1`
///
/// Le decoupage en `0.0.0.0/1` et `128.0.0.0/1` est courant chez les clients
/// VPN parce qu'il bat la route par defaut existante sans la remplacer, ce qui
/// laisse l'endpoint joignable hors tunnel. On n'en a pas besoin, et les deux
/// references le confirment: WireGuard pour Windows pose `0.0.0.0/0` tel quel
/// (`tunnel/addressconfig.go`), et sing-tun - la bibliotheque TUN de sing-box,
/// c'est-a-dire le cas exactement identique au notre - reserve les sous-plages
/// a macOS, `autoRouteUseSubRanges = runtime.GOOS == "darwin"`, et pose
/// `0.0.0.0/0` partout ailleurs.
///
/// Ce qui rend le `/0` sur: le coeur ne s'echappe pas par la table de routage
/// mais par sa SOCKET, liee a l'interface physique. La table peut donc dire
/// "tout passe par le tunnel" sans l'enfermer. Voir
/// [`crate::coeurs::configuration::Parametres::lier_a`].
///
/// # Ce que le `/0` ne mange pas
///
/// Le reseau local. Les routes on-link du lien physique sont des `/24`, `/64`
/// et autres prefixes plus SPECIFIQUES qu'un `/0`, et la route la plus
/// specifique gagne: l'imprimante du bureau reste joignable sans qu'on ait rien
/// a poser. C'est ce que Linux obtient explicitement par
/// `suppress_prefixlength 0`, parce que la-bas la question se pose dans une
/// autre table.
pub fn routes_du_coeur(cfg: &TunnelConfig) -> Vec<Route> {
    let mut routes = Vec::new();
    if cfg.addresses.iter().any(IpNet::is_ipv4) {
        routes.push(Route {
            dest: IpNet {
                addr: IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                prefix_len: 0,
            },
            metric: ROUTE_METRIC,
        });
    }
    if cfg.addresses.iter().any(|a| !a.is_ipv4()) {
        routes.push(Route {
            dest: IpNet {
                addr: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                prefix_len: 0,
            },
            metric: ROUTE_METRIC,
        });
    }
    routes
}

/// Vrai si le plan capture tout le trafic d'au moins une famille.
///
/// Sert de garde-fou: poser une route par defaut sur une machine de travail la
/// coupe du reseau si le tunnel ne transporte rien.
pub fn contient_route_par_defaut(routes: &[Route]) -> bool {
    routes.iter().any(|r| r.dest.prefix_len == 0)
}

/// Vrai si le plan capture TOUT le trafic d'une famille donnee.
///
/// Sert a une decision et une seule, cote Windows: quand le tunnel prend la
/// route par defaut d'une famille, la metrique automatique de son interface
/// doit etre remplacee par zero. Sans cela, deux routes `/0` coexistent - celle
/// du lien physique et la notre - et c'est la SOMME metrique d'interface plus
/// metrique de route qui departage. Une interface fraiche recoit une metrique
/// calculee sur la vitesse du lien, que rien ne garantit inferieure a celle du
/// lien physique: le tunnel monterait, et le trafic continuerait de sortir en
/// clair a cote.
///
/// Les deux references font exactement cela, et seulement dans ce cas:
/// WireGuard pour Windows sous `if foundDefault4 { UseAutomaticMetric = false;
/// Metric = 0 }`, et sing-tun sous `if AutoRoute`.
pub fn capture_toute_la_famille(routes: &[Route], v4: bool) -> bool {
    routes
        .iter()
        .any(|r| r.dest.prefix_len == 0 && r.dest.addr.is_ipv4() == v4)
}

/// Remet a zero les bits situes hors du prefixe.
pub fn masked(net: &IpNet) -> IpNet {
    let addr = match net.addr {
        IpAddr::V4(v4) => {
            let bits = u32::from(v4);
            let masque = if net.prefix_len == 0 {
                0
            } else {
                u32::MAX << (32 - net.prefix_len.min(32))
            };
            IpAddr::from((bits & masque).to_be_bytes())
        }
        IpAddr::V6(v6) => {
            let bits = u128::from(v6);
            let masque = if net.prefix_len == 0 {
                0
            } else {
                u128::MAX << (128 - net.prefix_len.min(128))
            };
            IpAddr::V6(Ipv6Addr::from(bits & masque))
        }
    };
    IpNet {
        addr,
        prefix_len: net.prefix_len,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bifrost_core::config::{DnsPolicy, Endpoint, PeerConfig, WgKey};
    use std::net::Ipv4Addr;

    fn key(c: char) -> WgKey {
        let mut s: String = std::iter::repeat_n(c, 42).collect();
        s.push('A');
        s.push('=');
        s.parse().unwrap()
    }

    /// La meme configuration, portee par un coeur au lieu de WireGuard.
    ///
    /// `adresses` decide des familles, ce qui est precisement la variable que
    /// [`routes_du_coeur`] lit.
    fn cfg_coeur(adresses: &[&str]) -> TunnelConfig {
        let profil = bifrost_core::profil::Profil::depuis_lien("hy2://mdp@192.0.2.11:8443")
            .expect("le lien de documentation doit se lire");
        TunnelConfig {
            addresses: adresses.iter().map(|s| s.parse().unwrap()).collect(),
            portage: bifrost_core::config::Portage::Coeur(Box::new(profil.into())),
            ..cfg(&["0.0.0.0/0"])
        }
    }

    #[test]
    fn un_portage_par_coeur_prend_tout_le_trafic_de_la_famille_adressee() {
        // Un coeur n'a pas de prefixes autorises a lire: il porte n'importe
        // quelle destination. Le plan ne se lit donc nulle part, il se decide,
        // et la decision est "tout". Une famille laissee dehors sortirait en
        // clair par le lien physique.
        let plan = routes_for(&cfg_coeur(&["10.7.0.2/32"]));
        assert_eq!(plan.len(), 1, "une seule famille adressee: {plan:?}");
        assert_eq!(plan[0].dest.prefix_len, 0);
        assert!(plan[0].dest.addr.is_ipv4());
        assert_eq!(plan[0].metric, ROUTE_METRIC);
    }

    #[test]
    fn un_portage_par_coeur_n_invente_pas_une_famille_non_adressee() {
        // Une route IPv6 sur une interface sans adresse IPv6 est refusee par
        // Windows, et un refus a cet endroit avorte le montage entier.
        let v6 = routes_for(&cfg_coeur(&["fd00::2/128"]));
        assert_eq!(v6.len(), 1, "{v6:?}");
        assert!(!v6[0].dest.addr.is_ipv4());

        let deux = routes_for(&cfg_coeur(&["10.7.0.2/32", "fd00::2/128"]));
        assert_eq!(deux.len(), 2, "{deux:?}");
        assert!(deux.iter().all(|r| r.dest.prefix_len == 0));
    }

    #[test]
    fn la_metrique_ne_se_force_que_pour_la_famille_reellement_capturee() {
        // C'est la question exacte que pose `ipcfg::apply`, famille par
        // famille. Forcer la metrique d'une famille qui n'est pas capturee
        // avantagerait le tunnel pour un trafic qu'il ne transporte pas.
        let v4_seule = routes_for(&cfg_coeur(&["10.7.0.2/32"]));
        assert!(capture_toute_la_famille(&v4_seule, true));
        assert!(!capture_toute_la_famille(&v4_seule, false));

        // Et un plan WireGuard qui ne prend qu'un prefixe ne capture rien.
        let etroit = routes_for(&cfg(&["10.0.0.0/8"]));
        assert!(!capture_toute_la_famille(&etroit, true));
        assert!(!capture_toute_la_famille(&etroit, false));
    }

    fn cfg(allowed: &[&str]) -> TunnelConfig {
        TunnelConfig {
            interface: "wg0".into(),
            addresses: vec!["10.2.0.2/32".parse().unwrap()],
            mtu: 1420,
            portage: bifrost_core::config::Portage::Wireguard(Box::new(
                bifrost_core::config::WireguardParams {
                    private_key: key('A'),
                    fwmark: 0xca6c,
                    routing_table: 51820,
                    listen_port: None,
                    peer: PeerConfig {
                        public_key: key('B'),
                        preshared_key: None,
                        endpoint: Endpoint {
                            addr: "203.0.113.7:51820".parse().unwrap(),
                        },
                        allowed_ips: allowed.iter().map(|s| s.parse().unwrap()).collect(),
                        persistent_keepalive: 25,
                    },
                },
            )),
            dns: DnsPolicy {
                local_resolver: IpAddr::V4(Ipv4Addr::LOCALHOST),
                upstream: vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))],
                embarque: false,
                anti_telemetrie: bifrost_core::config::ProfilTelemetrie::Aucun,
            },
            allow_lan: false,
        }
    }

    /// Windows refuse une route dont la destination porte des bits hors du
    /// prefixe. Ecrire `10.1.2.3/8` dans une configuration est pourtant
    /// legitime: c'est au plan de normaliser, pas a l'utilisateur.
    #[test]
    fn la_destination_est_masquee_a_son_prefixe() {
        let cas = [
            ("10.1.2.3/8", "10.0.0.0/8"),
            ("192.168.7.9/16", "192.168.0.0/16"),
            ("203.0.113.7/24", "203.0.113.0/24"),
            ("203.0.113.7/32", "203.0.113.7/32"),
            ("1.2.3.4/0", "0.0.0.0/0"),
            ("2001:db8:1234::5/32", "2001:db8::/32"),
            ("2001:db8::5/128", "2001:db8::5/128"),
            ("2001:db8::5/0", "::/0"),
        ];
        for (brut, attendu) in cas {
            let net: IpNet = brut.parse().unwrap();
            assert_eq!(masked(&net).to_string(), attendu, "en masquant {brut}");
        }
    }

    #[test]
    fn une_route_par_prefixe_autorise() {
        let r = routes_for(&cfg(&["0.0.0.0/0", "::/0", "10.0.0.0/8"]));
        assert_eq!(r.len(), 3);
        assert!(r.iter().all(|r| r.metric == ROUTE_METRIC));
    }

    /// Deux prefixes qui se ramenent au meme apres masquage ne doivent produire
    /// qu'une route: Windows refuse la seconde comme deja existante, et le
    /// tunnel echouerait a monter pour une raison purement cosmetique.
    #[test]
    fn les_doublons_apres_masquage_sont_ecartes() {
        let r = routes_for(&cfg(&["10.1.2.3/8", "10.4.5.6/8", "10.0.0.0/8"]));
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].dest.to_string(), "10.0.0.0/8");
    }

    #[test]
    fn la_route_par_defaut_est_detectee_dans_les_deux_familles() {
        assert!(contient_route_par_defaut(&routes_for(&cfg(&["0.0.0.0/0"]))));
        assert!(contient_route_par_defaut(&routes_for(&cfg(&["::/0"]))));
        assert!(!contient_route_par_defaut(&routes_for(&cfg(&[
            "10.0.0.0/8",
            "2001:db8::/32"
        ]))));
    }

    /// Le plan reproduit celui de WireGuard for Windows: la route par defaut
    /// est posee telle quelle, pas decoupee en deux `/1`. Si quelqu'un
    /// introduisait ce decoupage, ce serait un changement de strategie a
    /// assumer explicitement, pas un detail d'implementation.
    #[test]
    fn la_route_par_defaut_n_est_pas_decoupee() {
        let r = routes_for(&cfg(&["0.0.0.0/0"]));
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].dest.to_string(), "0.0.0.0/0");
    }

    #[test]
    fn la_route_de_bouclage_est_une_route_hote_plus_specifique_que_le_lan() {
        let r = route_bouclage("198.51.100.94".parse().unwrap());
        assert_eq!(r.dest.addr, "198.51.100.94".parse::<IpAddr>().unwrap());
        // LE point de cette route. La condition de bouclage ne se produit que si
        // Windows choisit le tunnel pour joindre l'endpoint, et c'est la route
        // la PLUS SPECIFIQUE qui gagne. Un pair sur le meme lien est joint par
        // une route on-link en /24, qui battrait une /0 comme une /25. Seule une
        // route hote passe devant.
        assert_eq!(r.dest.prefix_len, 32);
        assert_eq!(
            route_bouclage("2001:db8::1".parse().unwrap())
                .dest
                .prefix_len,
            128
        );
    }
}
