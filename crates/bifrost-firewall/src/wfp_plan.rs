//! Plan des filtres WFP.
//!
//! Ce module ne contient aucun appel Windows: il decrit quels filtres poser,
//! avec quel poids, quelle action et quelles conditions. Le resultat est une
//! donnee pure, donc la politique de blocage la plus critique du produit est
//! testable sur n'importe quelle plateforme, y compris en CI Linux.
//!
//! Le plan reproduit celui de WireGuard for Windows (document 02 partie 1.3):
//! sublayer dedie de poids `0xFFFF`, filtres permit aux poids 11 a 15, filtre
//! block-all au poids 0, et flag `FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT` sur les
//! blocages pour qu'un hard permit d'un sublayer concurrent ne puisse pas les
//! ecraser (faille simplewall #689).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

use bifrost_core::demarrage::{Exemption, Famille, PolitiqueDemarrage, Protocole, Sens};
use bifrost_core::ports::FirewallPolicy;

/// Poids du sublayer: le maximum, pour etre evalue avant tout le monde.
pub const SUBLAYER_WEIGHT: u16 = u16::MAX;

pub const IPPROTO_ICMPV6: u8 = 58;
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;

/// Types ICMPv6 de la decouverte de voisins.
const NDP_TYPES: [u16; 5] = [133, 134, 135, 136, 137];

/// Les quatre layers ALE utilises. Ce sont ceux de WireGuard for Windows: le
/// filtrage par interface au niveau ALE suffit, les layers de couche paquet ne
/// sont pas necessaires.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Layer {
    AuthConnectV4,
    AuthConnectV6,
    AuthRecvAcceptV4,
    AuthRecvAcceptV6,
}

impl Layer {
    pub const ALL: [Layer; 4] = [
        Layer::AuthConnectV4,
        Layer::AuthConnectV6,
        Layer::AuthRecvAcceptV4,
        Layer::AuthRecvAcceptV6,
    ];
    pub const OUTBOUND: [Layer; 2] = [Layer::AuthConnectV4, Layer::AuthConnectV6];
    pub const V4: [Layer; 2] = [Layer::AuthConnectV4, Layer::AuthRecvAcceptV4];
    pub const V6: [Layer; 2] = [Layer::AuthConnectV6, Layer::AuthRecvAcceptV6];

    pub fn is_v4(&self) -> bool {
        matches!(self, Layer::AuthConnectV4 | Layer::AuthRecvAcceptV4)
    }

    pub fn name(&self) -> &'static str {
        match self {
            Layer::AuthConnectV4 => "ALE_AUTH_CONNECT_V4",
            Layer::AuthConnectV6 => "ALE_AUTH_CONNECT_V6",
            Layer::AuthRecvAcceptV4 => "ALE_AUTH_RECV_ACCEPT_V4",
            Layer::AuthRecvAcceptV6 => "ALE_AUTH_RECV_ACCEPT_V6",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Permit,
    Block,
}

/// Une condition de filtre.
///
/// Rappel WFP determinant pour la lecture des plans ci-dessous: deux conditions
/// portant le MEME champ sont combinees en OU, deux champs differents en ET.
/// C'est ainsi qu'on exprime "port 53 ET (UDP OU TCP)".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Condition {
    /// Identite du binaire autorise, par son chemin.
    AppId(PathBuf),
    /// Identite de l'utilisateur autorise.
    ///
    /// Se combine en ET avec [`Condition::AppId`]: il ne suffit plus de lancer
    /// le binaire au bon chemin, il faut aussi le lancer sous la bonne identite.
    /// C'est la deuxieme condition que WireGuard for Windows met sur le filtre
    /// de son service (document 02 partie 1.3).
    UserId(Identity),
    Protocol(u8),
    LocalPort(u16),
    RemotePort(u16),
    RemoteAddrV4 {
        addr: Ipv4Addr,
        prefix: u8,
    },
    RemoteAddrV6 {
        addr: Ipv6Addr,
        prefix: u8,
    },
    /// LUID de l'interface du tunnel.
    LocalInterface(u64),
    /// Type ICMPv6. WFP fait porter ce champ par le meme identifiant que le
    /// port local: pour ICMP, le port local EST le type.
    IcmpType(u16),
    /// Trafic de boucle locale.
    Loopback,
}

/// Quelle identite d'utilisateur un filtre autorise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Identity {
    /// Celle du processus qui pose le filtre, lue dans son token au moment de
    /// la pose. C'est la seule valeur qu'emploie le plan reel: on n'autorise
    /// jamais une identite autre que la sienne.
    Current,
    /// Un SID nomme, sous sa forme textuelle.
    ///
    /// N'existe que pour la sonde de [`identity_probe`]: poser sciemment une
    /// identite que le daemon n'a pas est le seul moyen de verifier que WFP
    /// applique reellement la condition, au lieu de l'ignorer. Sans cette
    /// mutation, une condition d'utilisateur inoperante donnerait exactement
    /// les memes mesures qu'une condition correcte.
    Sid(String),
}

/// Autorite NT, celle que portent tous les SID de la forme `S-1-5-...`.
pub const AUTORITE_NT: [u8; 6] = [0, 0, 0, 0, 0, 5];
/// Premiere sous-autorite des SID de service: `S-1-5-80-...`.
pub const SOUS_AUTORITE_SERVICE: u32 = 80;
/// Un SID de service complet porte six sous-autorites: le 80, puis les cinq
/// mots du hachage SHA-1 du nom du service.
const SOUS_AUTORITES_ATTENDUES: usize = 6;

/// Ce SID designe-t-il un service?
///
/// Un SID de service (`S-1-5-80-<hachage du nom>`) est bien plus etroit qu'un
/// SID d'utilisateur: il ne designe pas un compte mais UN service precis, meme
/// quand dix services tournent sous LocalSystem. C'est pour ca qu'il vaut mieux
/// que `S-1-5-18`, lequel autoriserait n'importe quel service de la machine a
/// passer le kill switch.
///
/// Les trois criteres reproduisent ceux de `getCurrentProcessSecurityDescriptor`
/// dans WireGuard for Windows: autorite NT, au moins six sous-autorites, et 80
/// en premiere position. Le critere de longueur n'est pas decoratif: sans lui,
/// un SID tronque a `S-1-5-80` matcherait, et il designe la FAMILLE des services
/// plutot qu'un service.
pub fn est_sid_de_service(autorite: [u8; 6], sous_autorites: &[u32]) -> bool {
    autorite == AUTORITE_NT
        && sous_autorites.len() >= SOUS_AUTORITES_ATTENDUES
        && sous_autorites[0] == SOUS_AUTORITE_SERVICE
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterSpec {
    pub name: String,
    pub layers: Vec<Layer>,
    /// 0 a 15. WFP recoit un `FWP_UINT8`, comme WireGuard for Windows.
    pub weight: u8,
    pub action: Action,
    /// Pose `FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT`: le filtre devient un veto
    /// qu'un hard permit concurrent ne peut plus ecraser.
    pub hard: bool,
    pub conditions: Vec<Condition>,
}

/// Poids, du plus prioritaire au moins prioritaire.
mod weight {
    pub const DAEMON: u8 = 15;
    pub const DNS_PERMIT: u8 = 15;
    /// Doit rester strictement inferieur a [`DNS_PERMIT`], sinon le blocage
    /// couvrirait aussi le resolveur autorise et casserait toute resolution.
    pub const DNS_BLOCK: u8 = 14;
    pub const LOOPBACK: u8 = 13;
    pub const TUNNEL: u8 = 12;
    /// Doit rester strictement inferieur a [`DNS_BLOCK`].
    ///
    /// Dans un sublayer, c'est le filtre de plus fort poids qui l'emporte. Un
    /// coeur autorise AU-DESSUS du blocage DNS pourrait interroger n'importe
    /// quel resolveur en clair, ce qui rouvrirait exactement la fuite que ce
    /// plan interdit partout ailleurs. En dessous, le blocage DNS continue de
    /// s'appliquer a lui comme a tout le monde, et il resout par le resolveur
    /// local, dont le permit est plus haut encore.
    pub const COEUR: u8 = 12;
    pub const LAN: u8 = 11;
    pub const BLOCK_ALL: u8 = 0;
}

/// Construit le plan complet.
///
/// `daemon_exe` est le binaire autorise a sortir vers l'endpoint: c'est la
/// resolution du probleme oeuf-poule. On autorise une IDENTITE de processus, et
/// jamais l'IP de l'endpoint, qui serait un canal de sortie en clair ouvert a
/// n'importe quel programme.
///
/// `tunnel_luid` est `None` tant que l'interface n'existe pas. Le block-all est
/// alors deja pose: c'est l'etat voulu avant la premiere tentative.
pub fn plan(
    policy: &FirewallPolicy,
    daemon_exe: PathBuf,
    tunnel_luid: Option<u64>,
) -> Vec<FilterSpec> {
    let mut filters = Vec::new();

    filters.push(FilterSpec {
        name: "permit-daemon".into(),
        layers: Layer::ALL.to_vec(),
        weight: weight::DAEMON,
        action: Action::Permit,
        hard: false,
        conditions: vec![
            Condition::AppId(daemon_exe),
            Condition::UserId(Identity::Current),
        ],
    });

    filters.extend(dns_filters(policy.dns_resolver));

    // L'exception du resolveur chiffre embarque, quand il y en a un. Elle
    // passe AU-DESSUS du blocage DNS, a l'inverse exact du coeur qui doit
    // rester dessous: pour joindre son serveur chiffre, le resolveur doit
    // d'abord en resoudre le NOM, et cette premiere requete-la ne peut pas
    // etre chiffree par le service qu'elle sert a atteindre. Sans cette
    // exception, le resolveur embarque ne demarre jamais.
    //
    // Bornee au :53, et c'est ce qui la distingue de l'exemption du coeur.
    // Large, elle ferait du resolveur un second transport, c'est-a-dire une
    // sortie en clair hors tunnel accordee au composant qui existe justement
    // pour qu'il n'y en ait plus. Le reste de son trafic - le DoH sur 443 -
    // passe par le tunnel comme celui de tout le monde.
    //
    // Les DEUX conditions, comme partout ailleurs: le drapeau vient du PROFIL
    // et change a chaque connexion, le binaire vient de l'EXPLOITATION et ne
    // change pas. Ouvrir sur le seul binaire poserait l'exception sur un
    // profil ou aucun resolveur n'ecoute.
    if policy.resolveur_embarque
        && let Some(exe) = &policy.resolveur_executable
    {
        // L'identite du permit. Sans compte de service declare, celle du
        // daemon (`Identity::Current`), a l'octet pres comme avant 11b-1: le
        // resolveur est alors un enfant du daemon et porte son jeton. Avec un
        // compte declare (11b-1, forme alpha `NT AUTHORITY\LocalService`), le
        // SID de ce compte, si bien qu'une copie du binaire lancee sous une
        // autre identite ne matcherait plus. Le SID vient de
        // `IdentiteResolveur::restreindre`, qui l'a resolu une fois au
        // demarrage; ce champ est toujours `None` hors Windows.
        let identite = match &policy.resolveur_sid {
            Some(sid) => Identity::Sid(sid.clone()),
            None => Identity::Current,
        };
        filters.push(FilterSpec {
            name: "permit-resolveur-dns".into(),
            layers: Layer::OUTBOUND.to_vec(),
            weight: weight::DNS_PERMIT,
            action: Action::Permit,
            hard: false,
            conditions: vec![
                Condition::AppId(exe.clone()),
                Condition::UserId(identite),
                Condition::RemotePort(53),
                Condition::Protocol(IPPROTO_UDP),
                Condition::Protocol(IPPROTO_TCP),
            ],
        });
    }

    filters.push(FilterSpec {
        name: "permit-loopback".into(),
        layers: Layer::ALL.to_vec(),
        weight: weight::LOOPBACK,
        action: Action::Permit,
        hard: false,
        conditions: vec![Condition::Loopback],
    });

    if let Some(luid) = tunnel_luid {
        filters.push(FilterSpec {
            name: "permit-tunnel-interface".into(),
            layers: Layer::ALL.to_vec(),
            weight: weight::TUNNEL,
            action: Action::Permit,
            hard: false,
            conditions: vec![Condition::LocalInterface(luid)],
        });
    }

    // Le coeur anti-censure, quand il y en a un. Il est designe par son
    // BINAIRE et non par une destination: autoriser l'IP du serveur ouvrirait
    // un canal de sortie en clair a tout programme de la machine.
    if let Some(exe) = &policy.coeur_executable {
        filters.push(FilterSpec {
            name: "permit-coeur".into(),
            layers: Layer::ALL.to_vec(),
            weight: weight::COEUR,
            action: Action::Permit,
            hard: false,
            // Chemin ET identite, combines en ET par WFP, comme pour le
            // daemon: sans `UserId`, une copie du meme binaire lancee sous une
            // autre identite matcherait. Le coeur etant un enfant du daemon, il
            // porte l'identite de celui-ci. A revoir le jour ou il tournerait
            // sous un compte propre, comme il le fera sous Linux.
            conditions: vec![
                Condition::AppId(exe.clone()),
                Condition::UserId(Identity::Current),
            ],
        });
    }

    filters.push(dhcp_v4());
    filters.push(dhcp_v6());
    filters.push(ndp());

    if policy.allow_lan {
        filters.extend(lan_filters());
    }

    // Le catch-all. Poids 0 pour etre evalue en dernier dans le sublayer, et
    // veto pour qu'aucun autre produit ne puisse le contourner.
    filters.push(FilterSpec {
        name: "block-all".into(),
        layers: Layer::ALL.to_vec(),
        weight: weight::BLOCK_ALL,
        action: Action::Block,
        hard: true,
        conditions: Vec::new(),
    });

    filters
}

/// Poids du plan de demarrage. Ce plan vit dans son PROPRE sublayer, donc ces
/// poids ne se comparent a aucun de ceux ci-dessus: seul leur ordre relatif
/// compte.
mod poids_demarrage {
    pub const BOUCLE: u8 = 13;
    /// DHCP et NDP au-dessus des options: une machine doit pouvoir obtenir une
    /// adresse meme si l'utilisateur n'a ouvert aucune option.
    pub const AMORCAGE: u8 = 12;
    pub const OPTION: u8 = 11;
    pub const BLOCAGE: u8 = 0;
}

/// Traduit une politique de demarrage en filtres.
///
/// Le plan est volontairement pauvre par rapport a [`plan`]: aucune condition
/// d'identite de processus, aucune interface de tunnel. C'est structurel et non
/// un raccourci - au moment ou ces filtres s'appliquent, AUCUN processus
/// Bifrost n'existe et AUCUN tunnel n'est monte. Un filtre conditionne au
/// binaire du daemon n'autoriserait donc rien, et une exemption vers l'endpoint
/// serait un canal de sortie en clair ouvert a n'importe quel programme, ce que
/// ce depot refuse partout ailleurs. Le daemon remplace ce plan par le sien des
/// qu'il demarre.
pub fn plan_demarrage(politique: &PolitiqueDemarrage) -> Vec<FilterSpec> {
    let mut filters: Vec<FilterSpec> = politique
        .exemptions()
        .into_iter()
        .filter_map(exemption_en_filtre)
        .collect();

    // Le catch-all, dans les deux familles et les deux sens. Poids 0 pour etre
    // evalue en dernier, veto pour qu'aucun autre produit ne le contourne.
    filters.push(FilterSpec {
        name: "demarrage block-all".into(),
        layers: Layer::ALL.to_vec(),
        weight: poids_demarrage::BLOCAGE,
        action: Action::Block,
        hard: true,
        conditions: Vec::new(),
    });

    filters
}

fn couches(exemption: &Exemption) -> Vec<Layer> {
    let (v4, v6) = match exemption.sens {
        Sens::Sortant => (Layer::AuthConnectV4, Layer::AuthConnectV6),
        Sens::Entrant => (Layer::AuthRecvAcceptV4, Layer::AuthRecvAcceptV6),
    };
    match exemption.famille {
        Famille::V4 => vec![v4],
        Famille::V6 => vec![v6],
        Famille::Toutes => vec![v4, v6],
    }
}

fn exemption_en_filtre(exemption: Exemption) -> Option<FilterSpec> {
    let mut conditions = Vec::new();

    match exemption.protocole {
        Protocole::Udp => conditions.push(Condition::Protocol(IPPROTO_UDP)),
        Protocole::IcmpV6 => conditions.push(Condition::Protocol(IPPROTO_ICMPV6)),
        Protocole::Tout => {}
    }

    match exemption.icmpv6_type {
        // Pour ICMP, WFP fait porter le TYPE par le champ du port local. Poser
        // les deux serait poser deux fois le meme champ, donc un OU, et le
        // filtre s'ouvrirait a tous les types.
        Some(t) => conditions.push(Condition::IcmpType(u16::from(t))),
        None => {
            if let Some(p) = exemption.port_local {
                conditions.push(Condition::LocalPort(p));
            }
            if let Some(p) = exemption.port_distant {
                conditions.push(Condition::RemotePort(p));
            }
        }
    }

    if let Some(r) = exemption.distant {
        conditions.push(match r.adresse {
            IpAddr::V4(addr) => Condition::RemoteAddrV4 {
                addr,
                prefix: r.prefixe,
            },
            IpAddr::V6(addr) => Condition::RemoteAddrV6 {
                addr,
                prefix: r.prefixe,
            },
        });
    }

    let poids = if exemption.etiquette == "boucle locale" {
        conditions.push(Condition::Loopback);
        poids_demarrage::BOUCLE
    } else if exemption.etiquette.starts_with("DHCP") || exemption.etiquette.starts_with("NDP") {
        poids_demarrage::AMORCAGE
    } else {
        poids_demarrage::OPTION
    };

    Some(FilterSpec {
        name: format!(
            "demarrage {} {}",
            exemption.etiquette,
            match exemption.sens {
                Sens::Sortant => "sortant",
                Sens::Entrant => "entrant",
            }
        ),
        layers: couches(&exemption),
        weight: poids,
        action: Action::Permit,
        hard: false,
        conditions,
    })
}

/// Le meme plan, tous les blocages convertis en autorisations.
///
/// Sert a eprouver le cycle de vie des objets WFP sans couper le reseau de la
/// machine. Le nombre de filtres, leurs layers, leurs poids, leurs conditions
/// et leur appartenance au provider et au sublayer sont identiques: c'est
/// exactement le meme chemin de creation et de suppression. Seule l'action
/// change, donc rien n'est bloque.
///
/// Ce n'est PAS un test du kill switch. Ca ne prouve rien sur l'etancheite,
/// seulement que les objets se posent et se retirent proprement.
pub fn without_blocking(plan: Vec<FilterSpec>) -> Vec<FilterSpec> {
    plan.into_iter()
        .map(|mut f| {
            if f.action == Action::Block {
                f.action = Action::Permit;
                // Un veto n'a pas de sens sur une autorisation.
                f.hard = false;
            }
            f
        })
        .collect()
}

/// Plan minimal permettant d'observer si le permit du daemon matche vraiment.
///
/// Le probleme: la variante [`without_blocking`] eprouve le cycle de vie des
/// objets, mais comme elle ne bloque rien, elle ne dit pas si les conditions
/// d'identite designent bien le daemon. Or c'est exactement ce qu'une erreur
/// sur `AppId` ou `UserId` casserait, et le symptome serait un daemon incapable
/// de joindre son endpoint une fois le kill switch arme.
///
/// Le plan ci-dessous a la meme structure que le vrai (un permit d'identite de
/// poids fort, un blocage veto de poids nul) mais les deux filtres sont
/// restreints a UNE adresse de destination. Une tentative de connexion vers
/// cette adresse repond alors par un refus d'acces si le blocage a gagne, et
/// par autre chose si le permit a matche. Le reste du trafic de la machine
/// n'est jamais concerne: c'est ce qui rend l'observation possible sans couper
/// le reseau.
///
/// `target` doit etre une adresse sans trafic reel, typiquement un prefixe de
/// documentation RFC 5737.
///
/// `user` permet de rejouer la meme mesure avec une identite que le daemon n'a
/// pas: c'est la mutation qui prouve que la condition d'utilisateur est
/// appliquee et non ignoree.
pub fn identity_probe(daemon_exe: PathBuf, target: Ipv4Addr, user: Identity) -> Vec<FilterSpec> {
    let scope = Condition::RemoteAddrV4 {
        addr: target,
        prefix: 32,
    };
    vec![
        FilterSpec {
            name: "probe-permit-daemon".into(),
            layers: vec![Layer::AuthConnectV4],
            weight: weight::DAEMON,
            action: Action::Permit,
            hard: false,
            // Les memes conditions d'identite que `permit-daemon`, plus la
            // restriction de portee: la sonde ne doit rien autoriser au-dela de
            // ce qu'elle mesure.
            conditions: vec![
                Condition::AppId(daemon_exe),
                Condition::UserId(user),
                scope.clone(),
            ],
        },
        FilterSpec {
            name: "probe-block-target".into(),
            layers: vec![Layer::AuthConnectV4],
            weight: weight::BLOCK_ALL,
            action: Action::Block,
            hard: true,
            conditions: vec![scope],
        },
    ]
}

fn dns_filters(resolver: IpAddr) -> Vec<FilterSpec> {
    let addr = match resolver {
        IpAddr::V4(a) => Condition::RemoteAddrV4 {
            addr: a,
            prefix: 32,
        },
        IpAddr::V6(a) => Condition::RemoteAddrV6 {
            addr: a,
            prefix: 128,
        },
    };
    vec![
        FilterSpec {
            name: "permit-dns-to-local-resolver".into(),
            layers: Layer::OUTBOUND.to_vec(),
            weight: weight::DNS_PERMIT,
            action: Action::Permit,
            hard: false,
            conditions: vec![
                addr,
                Condition::RemotePort(53),
                Condition::Protocol(IPPROTO_UDP),
                Condition::Protocol(IPPROTO_TCP),
            ],
        },
        FilterSpec {
            name: "block-dns".into(),
            layers: Layer::OUTBOUND.to_vec(),
            weight: weight::DNS_BLOCK,
            action: Action::Block,
            hard: true,
            conditions: vec![
                Condition::RemotePort(53),
                Condition::Protocol(IPPROTO_UDP),
                Condition::Protocol(IPPROTO_TCP),
            ],
        },
    ]
}

fn dhcp_v4() -> FilterSpec {
    FilterSpec {
        name: "permit-dhcp-v4".into(),
        layers: Layer::V4.to_vec(),
        weight: weight::TUNNEL,
        action: Action::Permit,
        hard: false,
        conditions: vec![
            Condition::Protocol(IPPROTO_UDP),
            Condition::LocalPort(68),
            Condition::RemotePort(67),
            Condition::RemoteAddrV4 {
                addr: Ipv4Addr::BROADCAST,
                prefix: 32,
            },
        ],
    }
}

fn dhcp_v6() -> FilterSpec {
    FilterSpec {
        name: "permit-dhcp-v6".into(),
        layers: Layer::V6.to_vec(),
        weight: weight::TUNNEL,
        action: Action::Permit,
        hard: false,
        conditions: vec![
            Condition::Protocol(IPPROTO_UDP),
            Condition::LocalPort(546),
            Condition::RemotePort(547),
            // Multicast link-local puis site-local: deux conditions du meme
            // champ, donc combinees en OU.
            Condition::RemoteAddrV6 {
                addr: Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0x1, 0x2),
                prefix: 128,
            },
            Condition::RemoteAddrV6 {
                addr: Ipv6Addr::new(0xff05, 0, 0, 0, 0, 0, 0x1, 0x3),
                prefix: 128,
            },
        ],
    }
}

fn ndp() -> FilterSpec {
    let mut conditions = vec![Condition::Protocol(IPPROTO_ICMPV6)];
    conditions.extend(NDP_TYPES.iter().map(|t| Condition::IcmpType(*t)));
    // Restreint aux adresses ou NDP a un sens: link-local et multicast
    // link-local. Sans cela, le filtre ouvrirait ICMPv6 vers Internet.
    conditions.push(Condition::RemoteAddrV6 {
        addr: Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0),
        prefix: 10,
    });
    conditions.push(Condition::RemoteAddrV6 {
        addr: Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0),
        prefix: 16,
    });
    FilterSpec {
        name: "permit-ndp".into(),
        layers: Layer::V6.to_vec(),
        weight: weight::TUNNEL,
        action: Action::Permit,
        hard: false,
        conditions,
    }
}

fn lan_filters() -> Vec<FilterSpec> {
    let v4 = [
        (Ipv4Addr::new(10, 0, 0, 0), 8),
        (Ipv4Addr::new(172, 16, 0, 0), 12),
        (Ipv4Addr::new(192, 168, 0, 0), 16),
        (Ipv4Addr::new(169, 254, 0, 0), 16),
    ];
    vec![
        FilterSpec {
            name: "permit-lan-v4".into(),
            layers: Layer::V4.to_vec(),
            weight: weight::LAN,
            action: Action::Permit,
            hard: false,
            conditions: v4
                .iter()
                .map(|(addr, prefix)| Condition::RemoteAddrV4 {
                    addr: *addr,
                    prefix: *prefix,
                })
                .collect(),
        },
        FilterSpec {
            name: "permit-lan-v6".into(),
            layers: Layer::V6.to_vec(),
            weight: weight::LAN,
            action: Action::Permit,
            hard: false,
            conditions: vec![
                Condition::RemoteAddrV6 {
                    addr: Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0),
                    prefix: 7,
                },
                Condition::RemoteAddrV6 {
                    addr: Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0),
                    prefix: 10,
                },
            ],
        },
    ]
}

#[cfg(test)]
mod tests {

    fn plan_boot(politique: PolitiqueDemarrage) -> Vec<FilterSpec> {
        plan_demarrage(&politique)
    }

    fn tout_ouvert() -> PolitiqueDemarrage {
        PolitiqueDemarrage {
            reseau_local: true,
            overlay_cgnat: true,
            ipv6: true,
        }
    }

    #[test]
    fn aucune_autorisation_de_demarrage_n_est_sans_condition() {
        // LE test de ce plan. Un permit sans condition, a un poids superieur au
        // catch-all, serait un permit-all: le filtre de demarrage aurait l'air
        // pose, compterait ses filtres, et ne bloquerait rien du tout.
        for politique in [PolitiqueDemarrage::default(), tout_ouvert()] {
            for f in plan_boot(politique) {
                if f.action == Action::Permit {
                    assert!(
                        !f.conditions.is_empty(),
                        "autorisation sans condition, donc permit-all: {}",
                        f.name
                    );
                }
            }
        }
    }

    #[test]
    fn le_catch_all_de_demarrage_couvre_les_quatre_couches_et_reste_le_moins_prioritaire() {
        let plan = plan_boot(tout_ouvert());
        let bloc: Vec<_> = plan.iter().filter(|f| f.action == Action::Block).collect();
        assert_eq!(bloc.len(), 1, "un seul blocage attendu");
        assert_eq!(
            bloc[0].layers.len(),
            4,
            "les quatre couches doivent etre couvertes"
        );
        assert!(bloc[0].hard, "le blocage doit etre un veto");
        assert!(
            bloc[0].conditions.is_empty(),
            "le blocage doit tout prendre"
        );
        for f in plan.iter().filter(|f| f.action == Action::Permit) {
            assert!(
                f.weight > bloc[0].weight,
                "{} ne passerait pas devant le blocage",
                f.name
            );
        }
    }

    #[test]
    fn ipv6_bloque_ne_laisse_aucune_autorisation_sur_une_couche_v6() {
        // Le blocage, lui, doit rester sur les quatre couches: bloquer IPv6
        // veut dire le bloquer, pas l'ignorer.
        let plan = plan_boot(PolitiqueDemarrage {
            reseau_local: true,
            overlay_cgnat: true,
            ipv6: false,
        });
        for f in plan
            .iter()
            .filter(|f| f.action == Action::Permit && !f.name.contains("boucle locale"))
        {
            for l in &f.layers {
                assert!(
                    l.is_v4(),
                    "{} autorise du trafic IPv6 alors qu'IPv6 est bloque",
                    f.name
                );
            }
        }

        // La boucle locale est la seule exception, et elle est deliberee:
        // `::1` ne quitte jamais la machine, donc la bloquer ne protege de
        // rien et casse les logiciels locaux qui s'y lient. "Bloquer IPv6"
        // veut dire bloquer le RESEAU IPv6, pas la boucle locale.
        let boucle_v6 = plan.iter().any(|f| {
            f.action == Action::Permit
                && f.name.contains("boucle locale")
                && f.layers.iter().any(|l| !l.is_v4())
        });
        assert!(boucle_v6, "la boucle locale IPv6 doit rester autorisee");
    }

    #[test]
    fn les_filtres_ndp_portent_un_type_icmp_et_jamais_un_port_local() {
        // Sous WFP le type ICMP et le port local partagent le meme champ.
        // Poser les deux les combinerait en OU, et le filtre s'ouvrirait a tous
        // les types ICMPv6 au lieu du seul sous-ensemble NDP.
        let ndp: Vec<_> = plan_boot(tout_ouvert())
            .into_iter()
            .filter(|f| f.name.contains("NDP"))
            .collect();
        assert!(!ndp.is_empty(), "aucun filtre NDP");
        for f in ndp {
            assert!(
                f.conditions
                    .iter()
                    .any(|c| matches!(c, Condition::IcmpType(_))),
                "{} n'a pas de type ICMP",
                f.name
            );
            assert!(
                !f.conditions
                    .iter()
                    .any(|c| matches!(c, Condition::LocalPort(_))),
                "{} melange type ICMP et port local",
                f.name
            );
        }
    }

    #[test]
    fn la_boucle_locale_est_conditionnee_au_trafic_de_boucle() {
        // Sans la condition, ce filtre autoriserait tout le trafic, dans les
        // deux familles, au poids le plus fort du plan.
        for f in plan_boot(PolitiqueDemarrage::default())
            .iter()
            .filter(|f| f.name.contains("boucle locale"))
        {
            assert!(
                f.conditions.contains(&Condition::Loopback),
                "{} n'est pas restreint a la boucle locale",
                f.name
            );
        }
    }

    #[test]
    fn le_plan_de_demarrage_ne_conditionne_rien_a_un_processus_ni_a_un_tunnel() {
        // Au moment ou ces filtres s'appliquent, aucun processus Bifrost
        // n'existe et aucun tunnel n'est monte: une telle condition
        // n'autoriserait rien, et masquerait le fait que l'exemption est morte.
        for f in plan_boot(tout_ouvert()) {
            for c in &f.conditions {
                assert!(
                    !matches!(
                        c,
                        Condition::AppId(_) | Condition::UserId(_) | Condition::LocalInterface(_)
                    ),
                    "{} depend de quelque chose qui n'existe pas encore au demarrage",
                    f.name
                );
            }
        }
    }

    use super::*;

    fn policy(allow_lan: bool) -> FirewallPolicy {
        FirewallPolicy {
            tunnel_interface: Some("Bifrost".into()),
            tunnel_luid: None,
            fwmark: Some(0xca6c),
            dns_resolver: IpAddr::V4(Ipv4Addr::LOCALHOST),
            allow_lan,
            coeur_uid: None,
            coeur_executable: None,
            resolveur_uid: None,
            resolveur_executable: None,
            resolveur_sid: None,
            resolveur_embarque: false,
        }
    }

    fn policy_avec_coeur() -> FirewallPolicy {
        FirewallPolicy {
            coeur_executable: Some(PathBuf::from(r"C:\Bifrost\coeurs\sing-box.exe")),
            ..policy(false)
        }
    }

    /// Un resolveur chiffre embarque, declare comme le superviseur le declare:
    /// le binaire ET le drapeau du profil. L'un sans l'autre ne doit rien
    /// produire, et une recette plus bas le verifie.
    fn policy_avec_resolveur() -> FirewallPolicy {
        FirewallPolicy {
            resolveur_executable: Some(PathBuf::from(r"C:\Bifrost\dnscrypt-proxy.exe")),
            resolveur_embarque: true,
            ..policy(false)
        }
    }

    /// Le meme resolveur, mais un compte de service dedie est declare (11b-1,
    /// forme alpha `NT AUTHORITY\LocalService`, SID `S-1-5-19`). C'est ce que
    /// `IdentiteResolveur::restreindre` pose quand l'exploitation nomme un
    /// compte: le SID resolu une fois au demarrage.
    fn policy_avec_resolveur_et_compte() -> FirewallPolicy {
        FirewallPolicy {
            resolveur_sid: Some("S-1-5-19".to_owned()),
            ..policy_avec_resolveur()
        }
    }

    fn full_plan() -> Vec<FilterSpec> {
        plan(
            &policy(false),
            PathBuf::from(r"C:\Bifrost\bifrost-daemon.exe"),
            Some(42),
        )
    }

    fn find<'a>(plan: &'a [FilterSpec], name: &str) -> &'a FilterSpec {
        plan.iter()
            .find(|f| f.name == name)
            .unwrap_or_else(|| panic!("filtre absent: {name}"))
    }

    /// Le filtre qui fait le kill switch. Poids 0, veto, tous les layers,
    /// aucune condition: il capture ce que rien d'autre n'a autorise.
    #[test]
    fn le_block_all_est_un_veto_de_poids_zero_sur_les_quatre_layers() {
        let p = full_plan();
        let f = find(&p, "block-all");
        assert_eq!(f.weight, 0);
        assert_eq!(f.action, Action::Block);
        assert!(
            f.hard,
            "sans CLEAR_ACTION_RIGHT un hard permit concurrent l'ecrase"
        );
        assert!(f.conditions.is_empty());
        for layer in Layer::ALL {
            assert!(
                f.layers.contains(&layer),
                "layer manquant: {}",
                layer.name()
            );
        }
    }

    /// Tout blocage doit etre un veto, sinon il est contournable.
    #[test]
    fn tous_les_filtres_de_blocage_sont_des_vetos() {
        for f in full_plan().iter().filter(|f| f.action == Action::Block) {
            assert!(f.hard, "blocage sans veto: {}", f.name);
        }
    }

    /// Contrainte de WireGuard for Windows: le permit DNS doit primer sur le
    /// blocage DNS, sinon plus aucune resolution ne fonctionne.
    #[test]
    fn le_permit_dns_prime_strictement_sur_le_blocage_dns() {
        let p = full_plan();
        let permit = find(&p, "permit-dns-to-local-resolver");
        let block = find(&p, "block-dns");
        assert!(
            permit.weight > block.weight,
            "permit {} doit etre > block {}",
            permit.weight,
            block.weight
        );
    }

    #[test]
    fn le_blocage_dns_couvre_udp_et_tcp_sur_le_port_53() {
        let p = full_plan();
        let f = find(&p, "block-dns");
        assert!(f.conditions.contains(&Condition::RemotePort(53)));
        assert!(f.conditions.contains(&Condition::Protocol(IPPROTO_UDP)));
        assert!(f.conditions.contains(&Condition::Protocol(IPPROTO_TCP)));
    }

    #[test]
    fn le_permit_dns_est_limite_au_resolveur_de_la_politique() {
        let p = full_plan();
        let f = find(&p, "permit-dns-to-local-resolver");
        assert!(f.conditions.contains(&Condition::RemoteAddrV4 {
            addr: Ipv4Addr::LOCALHOST,
            prefix: 32
        }));
    }

    #[test]
    fn un_resolveur_ipv6_produit_une_condition_ipv6() {
        let mut p = policy(false);
        p.dns_resolver = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let plan = plan(&p, PathBuf::from("x.exe"), None);
        let f = find(&plan, "permit-dns-to-local-resolver");
        assert!(f.conditions.contains(&Condition::RemoteAddrV6 {
            addr: Ipv6Addr::LOCALHOST,
            prefix: 128
        }));
    }

    /// La meme garantie que cote Linux: l'endpoint est autorise par l'identite
    /// du daemon, jamais par son adresse.
    #[test]
    fn l_endpoint_n_apparait_dans_aucune_condition() {
        let p = full_plan();
        for f in &p {
            for c in &f.conditions {
                if let Condition::RemoteAddrV4 { addr, .. } = c {
                    assert_ne!(
                        *addr,
                        Ipv4Addr::new(203, 0, 113, 7),
                        "l'IP de l'endpoint est devenue une condition dans {}",
                        f.name
                    );
                }
                assert_ne!(*c, Condition::RemotePort(51820));
            }
        }
    }

    #[test]
    fn le_daemon_est_autorise_par_identite_de_binaire_et_d_utilisateur() {
        let p = full_plan();
        let f = find(&p, "permit-daemon");
        assert_eq!(f.weight, 15);
        assert_eq!(
            f.conditions,
            vec![
                Condition::AppId(PathBuf::from(r"C:\Bifrost\bifrost-daemon.exe")),
                Condition::UserId(Identity::Current)
            ]
        );
    }

    /// Le plan reel n'autorise que l'identite du processus qui le pose.
    /// `Identity::Sid` n'existe que pour la mutation de la sonde; s'il
    /// apparaissait ici, le kill switch autoriserait un tiers.
    #[test]
    fn le_plan_reel_n_autorise_aucune_identite_nommee() {
        for f in plan(&policy(true), PathBuf::from("x.exe"), Some(1)) {
            for c in &f.conditions {
                if let Condition::UserId(id) = c {
                    assert_eq!(*id, Identity::Current, "identite nommee dans {}", f.name);
                }
            }
        }
    }

    /// Champs differents, donc combines en ET par WFP. Si `UserId` disparaissait,
    /// un processus lance sous une autre identite mais au bon chemin matcherait.
    ///
    /// "Le seul" vaut pour le plan NU: sans coeur ni resolveur declare, aucun
    /// autre filtre ne designe un processus. Les deux qui peuvent s'y ajouter
    /// portent chacun leurs propres recettes.
    #[test]
    fn le_permit_du_daemon_est_le_seul_a_porter_une_identite() {
        let p = plan(&policy(true), PathBuf::from("x.exe"), Some(1));
        let porteurs: Vec<&str> = p
            .iter()
            .filter(|f| {
                f.conditions
                    .iter()
                    .any(|c| matches!(c, Condition::AppId(_) | Condition::UserId(_)))
            })
            .map(|f| f.name.as_str())
            .collect();
        assert_eq!(porteurs, vec!["permit-daemon"]);
    }

    /// Recette transverse, et la plus utile des trois. Un permit qui designe
    /// un processus et ne borne RIEN d'autre est une sortie en clair pour ce
    /// processus. Deux seulement ont le droit de l'etre, et pour la meme
    /// raison: ils SONT le transport.
    #[test]
    fn seuls_le_daemon_et_le_coeur_ont_un_permit_large() {
        let politique = FirewallPolicy {
            coeur_executable: Some(PathBuf::from(r"C:\Bifrost\coeurs\sing-box.exe")),
            ..policy_avec_resolveur()
        };
        for f in plan(&politique, PathBuf::from("x.exe"), Some(1)) {
            let designe_un_processus = f
                .conditions
                .iter()
                .any(|c| matches!(c, Condition::AppId(_)));
            let borne_autre_chose = f
                .conditions
                .iter()
                .any(|c| !matches!(c, Condition::AppId(_) | Condition::UserId(_)));
            if designe_un_processus && !borne_autre_chose {
                assert!(
                    f.name == "permit-daemon" || f.name == "permit-coeur",
                    "{} ouvre une sortie en clair a un processus",
                    f.name
                );
            }
        }
    }

    #[test]
    fn sans_coeur_declare_aucun_filtre_ne_le_mentionne() {
        // Le tunnel nu ne lance aucun coeur: l'exemption ne doit pas exister
        // par defaut, un permit pose "au cas ou" etant un trou permanent.
        let p = plan(&policy(false), PathBuf::from("x.exe"), Some(1));
        assert!(p.iter().all(|f| f.name != "permit-coeur"));
    }

    #[test]
    fn le_coeur_declare_est_autorise_par_son_binaire_et_son_identite() {
        let p = plan(&policy_avec_coeur(), PathBuf::from("x.exe"), Some(1));
        let f = find(&p, "permit-coeur");
        assert_eq!(
            f.conditions,
            vec![
                Condition::AppId(PathBuf::from(r"C:\Bifrost\coeurs\sing-box.exe")),
                Condition::UserId(Identity::Current)
            ]
        );
        assert_eq!(f.action, Action::Permit);
    }

    #[test]
    fn sans_resolveur_declare_aucun_filtre_ne_le_mentionne() {
        // Meme discipline que pour le coeur: un permit pose "au cas ou" est un
        // trou permanent, et ici il autoriserait du :53 en clair.
        let p = plan(&policy(false), PathBuf::from("x.exe"), Some(1));
        assert!(p.iter().all(|f| f.name != "permit-resolveur-dns"));
    }

    /// Le binaire declare sans le drapeau du profil ne doit rien ouvrir.
    ///
    /// L'asymetrie est la meme que sous Linux: le binaire vient de
    /// l'EXPLOITATION, qui le nomme une fois pour toutes, le drapeau vient du
    /// PROFIL, qui change a chaque connexion. Un profil qui ne route pas le DNS
    /// par la boucle locale n'a aucun resolveur embarque a exempter.
    #[test]
    fn le_binaire_seul_n_ouvre_rien_sans_le_drapeau_du_profil() {
        let politique = FirewallPolicy {
            resolveur_executable: Some(PathBuf::from(r"C:\Bifrost\dnscrypt-proxy.exe")),
            resolveur_embarque: false,
            ..policy(false)
        };
        let p = plan(&politique, PathBuf::from("x.exe"), Some(1));
        assert!(p.iter().all(|f| f.name != "permit-resolveur-dns"));
    }

    #[test]
    fn le_resolveur_declare_est_autorise_par_son_binaire_et_son_identite() {
        let p = plan(&policy_avec_resolveur(), PathBuf::from("x.exe"), Some(1));
        let f = find(&p, "permit-resolveur-dns");
        assert_eq!(f.action, Action::Permit);
        assert_eq!(f.layers, Layer::OUTBOUND.to_vec());
        assert_eq!(
            f.conditions,
            vec![
                Condition::AppId(PathBuf::from(r"C:\Bifrost\dnscrypt-proxy.exe")),
                Condition::UserId(Identity::Current),
                Condition::RemotePort(53),
                Condition::Protocol(IPPROTO_UDP),
                Condition::Protocol(IPPROTO_TCP),
            ]
        );
    }

    /// 11b-1, valeur preservee a l'octet pres. Sans compte de service declare,
    /// le permit doit porter EXACTEMENT ce qu'il portait avant 11b-1:
    /// `Identity::Current`, et rien d'autre. Falsification: si le nouveau code
    /// posait un SID par defaut (`Identity::Sid(..)` alors qu'aucun compte
    /// n'est declare), cette egalite rougit. C'est le pendant de la recette
    /// ci-dessus, isole pour nommer la propriete de non-regression.
    #[test]
    fn sans_compte_declare_le_permit_du_resolveur_garde_identity_current() {
        let p = plan(&policy_avec_resolveur(), PathBuf::from("x.exe"), Some(1));
        let f = find(&p, "permit-resolveur-dns");
        assert!(
            f.conditions.contains(&Condition::UserId(Identity::Current)),
            "sans compte declare, l'identite doit rester celle du daemon"
        );
        assert!(
            !f.conditions
                .iter()
                .any(|c| matches!(c, Condition::UserId(Identity::Sid(_)))),
            "aucun SID ne doit etre pose par defaut: le comportement d'avant \
             11b-1 est preserve a l'octet pres"
        );
    }

    /// 11b-1, l'effet du compte. Avec un compte de service declare (temoin
    /// `LocalService`, SID `S-1-5-19`), le permit doit NOMMER ce SID dans sa
    /// condition d'identite, tout en gardant AppId, le port 53 et les deux
    /// protocoles. Falsification: retirer la condition de port de ce permit
    /// (ce que garde deja `le_permit_du_resolveur_ne_vaut_que_pour_le_53`) le
    /// rendrait large, et l'egalite ci-dessous rougit.
    #[test]
    fn avec_un_compte_declare_le_permit_du_resolveur_nomme_le_sid() {
        let p = plan(
            &policy_avec_resolveur_et_compte(),
            PathBuf::from("x.exe"),
            Some(1),
        );
        let f = find(&p, "permit-resolveur-dns");
        assert_eq!(f.action, Action::Permit);
        assert_eq!(f.layers, Layer::OUTBOUND.to_vec());
        assert_eq!(
            f.conditions,
            vec![
                Condition::AppId(PathBuf::from(r"C:\Bifrost\dnscrypt-proxy.exe")),
                Condition::UserId(Identity::Sid("S-1-5-19".to_owned())),
                Condition::RemotePort(53),
                Condition::Protocol(IPPROTO_UDP),
                Condition::Protocol(IPPROTO_TCP),
            ]
        );
    }

    /// L'exact CONTRAIRE de la recette du coeur, et il faut lire les deux
    /// ensemble. Le coeur doit rester SOUS le blocage DNS, sans quoi il
    /// interrogerait n'importe quel resolveur en clair. Le resolveur, lui, doit
    /// passer AU-DESSUS: sans cela il ne peut pas resoudre le NOM de son propre
    /// serveur chiffre, et le resolveur embarque ne demarre jamais.
    #[test]
    fn le_permit_du_resolveur_passe_au_dessus_du_blocage_dns() {
        let p = plan(&policy_avec_resolveur(), PathBuf::from("x.exe"), Some(1));
        let resolveur = find(&p, "permit-resolveur-dns").weight;
        let bloc_dns = p
            .iter()
            .filter(|f| f.action == Action::Block && f.name.contains("dns"))
            .map(|f| f.weight)
            .max()
            .expect("le plan doit bloquer le DNS");
        assert!(
            resolveur > bloc_dns,
            "permit-resolveur-dns a {resolveur}, blocage DNS a {bloc_dns}: \
             le resolveur ne pourrait pas amorcer"
        );
    }

    /// La falsification qui compte. Ce permit passe au-dessus du blocage DNS;
    /// s'il perdait sa condition de port, il autoriserait le resolveur a sortir
    /// vers N'IMPORTE QUOI hors tunnel, c'est-a-dire exactement l'exemption du
    /// coeur, donnee au composant qui ne doit jamais l'avoir.
    #[test]
    fn le_permit_du_resolveur_ne_vaut_que_pour_le_53() {
        let p = plan(&policy_avec_resolveur(), PathBuf::from("x.exe"), Some(1));
        let f = find(&p, "permit-resolveur-dns");
        assert!(
            f.conditions.contains(&Condition::RemotePort(53)),
            "sans la condition de port, ce permit est une sortie en clair"
        );
    }

    /// La regression qui rouvrirait une fuite DNS.
    ///
    /// Dans un sublayer, c'est le plus fort poids qui l'emporte. Un coeur
    /// autorise AU-DESSUS du blocage DNS pourrait interroger n'importe quel
    /// resolveur en clair. Il doit rester dessous, et resoudre par le
    /// resolveur local comme tout le monde.
    #[test]
    fn le_permit_du_coeur_reste_sous_le_blocage_dns() {
        let p = plan(&policy_avec_coeur(), PathBuf::from("x.exe"), Some(1));
        let coeur = find(&p, "permit-coeur").weight;
        let bloc_dns = p
            .iter()
            .filter(|f| f.action == Action::Block && f.name.contains("dns"))
            .map(|f| f.weight)
            .max()
            .expect("le plan doit bloquer le DNS");
        assert!(
            coeur < bloc_dns,
            "permit-coeur a {coeur}, blocage DNS a {bloc_dns}: le coeur passerait au-dessus"
        );
    }

    /// L'exemption designe une identite, jamais une destination.
    #[test]
    fn l_exemption_du_coeur_n_ouvre_aucune_destination() {
        let p = plan(&policy_avec_coeur(), PathBuf::from("x.exe"), Some(1));
        let f = find(&p, "permit-coeur");
        assert!(
            !f.conditions
                .iter()
                .any(|c| matches!(c, Condition::RemoteAddrV4 { .. })),
            "le coeur est autorise par une adresse: {:?}",
            f.conditions
        );
    }

    /// Avant que l'interface du tunnel existe, le block-all est deja pose et
    /// aucun filtre ne reference d'interface.
    #[test]
    fn sans_luid_aucun_filtre_ne_reference_l_interface() {
        let p = plan(&policy(false), PathBuf::from("x.exe"), None);
        assert!(p.iter().all(|f| f.name != "permit-tunnel-interface"));
        assert!(p.iter().all(|f| {
            !f.conditions
                .iter()
                .any(|c| matches!(c, Condition::LocalInterface(_)))
        }));
        // Mais le blocage est complet.
        find(&p, "block-all");
    }

    #[test]
    fn le_luid_du_tunnel_est_repris_tel_quel() {
        let p = full_plan();
        let f = find(&p, "permit-tunnel-interface");
        assert_eq!(f.conditions, vec![Condition::LocalInterface(42)]);
    }

    #[test]
    fn ndp_est_limite_aux_types_de_decouverte_et_aux_adresses_locales() {
        let p = full_plan();
        let f = find(&p, "permit-ndp");
        for t in NDP_TYPES {
            assert!(
                f.conditions.contains(&Condition::IcmpType(t)),
                "type {t} absent"
            );
        }
        assert!(f.conditions.contains(&Condition::Protocol(IPPROTO_ICMPV6)));
        // Aucune ouverture ICMPv6 vers Internet.
        assert!(
            f.conditions
                .iter()
                .any(|c| matches!(c, Condition::RemoteAddrV6 { prefix: 10, .. }))
        );
        assert_eq!(f.layers, Layer::V6.to_vec());
    }

    #[test]
    fn dhcp_est_cible_precisement() {
        let p = full_plan();
        let v4 = find(&p, "permit-dhcp-v4");
        assert!(v4.conditions.contains(&Condition::LocalPort(68)));
        assert!(v4.conditions.contains(&Condition::RemotePort(67)));
        assert!(v4.conditions.contains(&Condition::RemoteAddrV4 {
            addr: Ipv4Addr::BROADCAST,
            prefix: 32
        }));
        let v6 = find(&p, "permit-dhcp-v6");
        assert!(v6.conditions.contains(&Condition::LocalPort(546)));
        assert!(v6.conditions.contains(&Condition::RemotePort(547)));
    }

    #[test]
    fn allow_lan_desactive_n_ouvre_aucun_prefixe_prive() {
        let p = full_plan();
        assert!(p.iter().all(|f| !f.name.starts_with("permit-lan")));
    }

    #[test]
    fn allow_lan_active_ouvre_les_prefixes_prives_a_poids_moindre() {
        let p = plan(&policy(true), PathBuf::from("x.exe"), Some(1));
        let v4 = find(&p, "permit-lan-v4");
        assert_eq!(v4.weight, 11);
        assert!(v4.conditions.contains(&Condition::RemoteAddrV4 {
            addr: Ipv4Addr::new(192, 168, 0, 0),
            prefix: 16
        }));
        // Le LAN ne doit jamais primer sur la politique DNS.
        let dns = find(&p, "block-dns");
        assert!(v4.weight < dns.weight);
    }

    #[test]
    fn tous_les_permits_ont_un_poids_superieur_au_block_all() {
        let p = full_plan();
        let block_all = find(&p, "block-all").weight;
        for f in p.iter().filter(|f| f.action == Action::Permit) {
            assert!(f.weight > block_all, "{} au poids du block-all", f.name);
        }
    }

    #[test]
    fn les_noms_de_filtres_sont_uniques() {
        let p = plan(&policy(true), PathBuf::from("x.exe"), Some(1));
        let mut noms: Vec<_> = p.iter().map(|f| f.name.as_str()).collect();
        noms.sort_unstable();
        let avant = noms.len();
        noms.dedup();
        assert_eq!(noms.len(), avant, "noms de filtres dupliques");
    }

    #[test]
    fn aucun_filtre_n_est_sans_layer() {
        for f in plan(&policy(true), PathBuf::from("x.exe"), Some(1)) {
            assert!(!f.layers.is_empty(), "filtre sans layer: {}", f.name);
        }
    }

    /// Le poids WFP est un FWP_UINT8 sur la plage 0-15 chez WireGuard.
    #[test]
    fn les_poids_tiennent_dans_la_plage_utilisee_par_wireguard() {
        for f in plan(&policy(true), PathBuf::from("x.exe"), Some(1)) {
            assert!(f.weight <= 15, "poids hors plage pour {}", f.name);
        }
    }
    /// La variante sans blocage doit conserver la STRUCTURE du plan: memes
    /// filtres, memes layers, memes poids, memes conditions. Sinon elle
    /// n'eprouve plus le meme chemin de creation et de suppression et ne dit
    /// plus rien du cycle de vie reel.
    #[test]
    fn la_variante_sans_blocage_conserve_la_structure() {
        let reel = full_plan();
        let sonde = without_blocking(reel.clone());

        assert_eq!(sonde.len(), reel.len());
        for (a, b) in reel.iter().zip(sonde.iter()) {
            assert_eq!(a.name, b.name);
            assert_eq!(a.layers, b.layers);
            assert_eq!(a.weight, b.weight);
            assert_eq!(a.conditions, b.conditions);
        }
    }

    #[test]
    fn la_variante_sans_blocage_ne_bloque_rien() {
        let sonde = without_blocking(full_plan());
        assert!(
            sonde.iter().all(|f| f.action == Action::Permit),
            "un blocage a survecu: le reseau serait coupe"
        );
        assert!(
            sonde.iter().all(|f| !f.hard),
            "un veto a survecu sur une autorisation"
        );
    }

    /// Garde-fou: la variante sans blocage ne doit jamais servir de plan reel.
    /// Le plan reel, lui, contient bien des blocages.
    #[test]
    fn le_plan_reel_bloque_toujours() {
        let reel = full_plan();
        assert!(reel.iter().any(|f| f.action == Action::Block && f.hard));
    }

    const CIBLE: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 9);

    fn sonde() -> Vec<FilterSpec> {
        identity_probe(
            PathBuf::from(r"C:\Bifrost\bifrost-daemon.exe"),
            CIBLE,
            Identity::Current,
        )
    }

    /// La propriete qui rend la sonde utilisable sur une machine de travail: le
    /// blocage ne peut pas deborder de l'adresse mesuree. Sans cette garantie,
    /// la sonde serait un kill switch deguise.
    #[test]
    fn la_sonde_ne_bloque_que_son_adresse_cible() {
        for f in sonde().iter().filter(|f| f.action == Action::Block) {
            assert!(
                f.conditions.contains(&Condition::RemoteAddrV4 {
                    addr: CIBLE,
                    prefix: 32
                }),
                "blocage sans portee dans la sonde: {}",
                f.name
            );
            assert_eq!(
                f.layers,
                vec![Layer::AuthConnectV4],
                "la sonde ne doit toucher que les connexions sortantes IPv4"
            );
        }
    }

    /// La sonde ne vaut que si elle mesure les MEMES conditions d'identite que
    /// le plan reel. Si l'une des deux evoluait sans l'autre, elle continuerait
    /// a passer en ne prouvant plus rien.
    #[test]
    fn la_sonde_reprend_les_conditions_d_identite_du_plan_reel() {
        let reel = find(&full_plan(), "permit-daemon").conditions.clone();
        let s = sonde();
        let permit = find(&s, "probe-permit-daemon");
        for c in &reel {
            assert!(
                permit.conditions.contains(c),
                "condition d'identite absente de la sonde: {c:?}"
            );
        }
    }

    /// Meme arbitrage que le vrai plan: le permit d'identite l'emporte sur le
    /// blocage. Si les poids etaient inverses, la sonde declarerait le daemon
    /// bloque alors que le kill switch reel le laisserait passer.
    #[test]
    fn dans_la_sonde_le_permit_prime_sur_le_blocage() {
        let s = sonde();
        assert!(find(&s, "probe-permit-daemon").weight > find(&s, "probe-block-target").weight);
        assert!(find(&s, "probe-block-target").hard);
    }

    /// La mutation ne doit changer QUE l'identite. Si elle changeait aussi la
    /// portee ou les poids, le blocage observe pourrait venir d'autre chose que
    /// de la condition d'utilisateur, et ne prouverait plus rien sur elle.
    #[test]
    fn la_mutation_ne_change_que_l_identite() {
        let exe = PathBuf::from(r"C:\Bifrost\bifrost-daemon.exe");
        let normale = identity_probe(exe.clone(), CIBLE, Identity::Current);
        let mutee = identity_probe(exe, CIBLE, Identity::Sid("S-1-0-0".into()));

        assert_eq!(normale.len(), mutee.len());
        for (a, b) in normale.iter().zip(mutee.iter()) {
            assert_eq!(a.name, b.name);
            assert_eq!(a.layers, b.layers);
            assert_eq!(a.weight, b.weight);
            assert_eq!(a.action, b.action);
            let sans_identite = |f: &FilterSpec| -> Vec<Condition> {
                f.conditions
                    .iter()
                    .filter(|c| !matches!(c, Condition::UserId(_)))
                    .cloned()
                    .collect()
            };
            assert_eq!(sans_identite(a), sans_identite(b));
        }
        assert!(
            mutee[0]
                .conditions
                .contains(&Condition::UserId(Identity::Sid("S-1-0-0".into())))
        );
    }

    /// Un SID de service reel: autorite NT, 80, puis les cinq mots du hachage
    /// du nom du service.
    #[test]
    fn un_sid_de_service_est_reconnu() {
        assert!(est_sid_de_service(
            AUTORITE_NT,
            &[
                80,
                3_262_478_231,
                3_923_453_534,
                1_469_004_531,
                56_507_889,
                2_197_805_297
            ]
        ));
    }

    /// `S-1-5-18`, LocalSystem, n'est PAS un SID de service. C'est la
    /// distinction qui justifie tout le reste: sous LocalSystem, tous les
    /// services de la machine partagent ce SID, donc l'autoriser reviendrait a
    /// autoriser n'importe lequel d'entre eux a franchir le kill switch.
    #[test]
    fn local_system_n_est_pas_un_sid_de_service() {
        assert!(!est_sid_de_service(AUTORITE_NT, &[18]));
    }

    /// Un SID d'utilisateur de domaine, `S-1-5-21-A-B-C-RID`, porte cinq
    /// sous-autorites. Il passe a une unite du critere de longueur, ce qui en
    /// fait le meilleur cas limite disponible.
    #[test]
    fn un_sid_d_utilisateur_n_est_pas_un_sid_de_service() {
        assert!(!est_sid_de_service(
            AUTORITE_NT,
            &[21, 1_111_111_111, 2_222_222_222, 3_333_333_333, 1001]
        ));
    }

    /// `S-1-5-80` tout court designe la FAMILLE des services, pas un service.
    /// L'accepter reviendrait a autoriser tout service de la machine, ce qui
    /// vide la condition de son sens.
    #[test]
    fn un_sid_de_service_tronque_est_refuse() {
        assert!(!est_sid_de_service(AUTORITE_NT, &[80]));
        assert!(!est_sid_de_service(AUTORITE_NT, &[80, 1, 2, 3, 4]));
    }

    /// Le 80 ne veut rien dire hors de l'autorite NT. Une autre autorite qui
    /// porterait la meme premiere sous-autorite ne designe aucun service.
    #[test]
    fn le_80_ne_suffit_pas_sous_une_autre_autorite() {
        let autorite_monde = [0, 0, 0, 0, 0, 1];
        assert!(!est_sid_de_service(autorite_monde, &[80, 1, 2, 3, 4, 5]));
    }

    /// Les numeros de protocole et les types NDP viennent de l'exterieur.
    ///
    /// Toutes les recettes qui les mentionnent comparent
    /// `Condition::Protocol(IPPROTO_UDP)` a la condition que le plan a ecrite
    /// DEPUIS `IPPROTO_UDP`. Elles eprouvent la FORME du plan - tel filtre
    /// porte-t-il une condition de protocole - et jamais la VALEUR, alors que
    /// c'est la valeur que WFP compare au paquet.
    ///
    /// Mesure du 23 aout 2026 sur dev-windows: en decalant les trois numeros,
    /// la suite du crate restait entierement verte. Un `block-dns` conditionne
    /// a un numero de protocole inexistant ne matche aucun paquet: le :53
    /// serait sorti en clair et le plan aurait continue de se lire comme
    /// correct.
    ///
    /// Les valeurs sont celles du registre IANA des numeros de protocole
    /// (6 TCP, 17 UDP, 58 ICMPv6) et de la RFC 4861 section 4 pour les cinq
    /// messages de la decouverte de voisins.
    #[test]
    fn les_numeros_de_protocole_sont_ceux_du_registre_et_pas_les_notres() {
        assert_eq!(IPPROTO_TCP, 6);
        assert_eq!(IPPROTO_UDP, 17);
        assert_eq!(IPPROTO_ICMPV6, 58);
        assert_eq!(
            NDP_TYPES,
            [133, 134, 135, 136, 137],
            "sollicitation et annonce de routeur, sollicitation et annonce de              voisin, redirection"
        );
    }
}
