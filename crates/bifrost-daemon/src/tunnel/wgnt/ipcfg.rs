//! Pose adresses, routes et MTU sur l'interface du tunnel, via IP Helper.
//!
//! WireGuardNT ne fait que le transport: tout ce qui suit est du ressort de la
//! pile IP de Windows, et se fait par LUID d'interface. Le plan de ce qu'il
//! faut poser vit dans [`super::routes`], qui est pur; ici il n'y a que les
//! appels systeme.
//!
//! Le retrait est fait pour ne jamais echouer a mi-chemin: chaque suppression
//! est tentee, les objets deja absents sont tolores, et l'ensemble des erreurs
//! est rendu a la fin. Un demontage qui s'arrete a la premiere erreur
//! laisserait des routes derriere lui, donc du trafic dirige vers une interface
//! morte.

use std::net::IpAddr;

use bifrost_core::config::{IpNet, TunnelConfig};
use bifrost_core::{Error, Result};
use windows_sys::Win32::Foundation::{ERROR_NOT_FOUND, ERROR_OBJECT_ALREADY_EXISTS, ERROR_SUCCESS};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    CreateIpForwardEntry2, CreateUnicastIpAddressEntry, DeleteIpForwardEntry2,
    DeleteUnicastIpAddressEntry, GetBestRoute2, GetIpForwardEntry2, GetIpInterfaceEntry,
    GetUnicastIpAddressEntry, IP_ADDRESS_PREFIX, InitializeIpForwardEntry,
    InitializeUnicastIpAddressEntry, MIB_IPFORWARD_ROW2, MIB_IPINTERFACE_ROW,
    MIB_UNICASTIPADDRESS_ROW, SetIpInterfaceEntry,
};
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, IN_ADDR, IN_ADDR_0, IN6_ADDR, IN6_ADDR_0, IpDadStatePreferred, SOCKADDR_IN,
    SOCKADDR_IN6, SOCKADDR_IN6_0, SOCKADDR_INET,
};

use super::routes::{self, Route};

/// Duree de vie d'une adresse posee a la main: infinie.
const INFINITE_LIFETIME: u32 = 0xffff_ffff;

/// Applique adresses, MTU, metrique puis routes.
///
/// Les routes viennent en dernier: une route vers une interface qui n'a pas
/// encore d'adresse est refusee par Windows.
///
/// Le plan est calcule EN PREMIER bien qu'il soit pose en dernier, parce que
/// la ligne d'interface a besoin de savoir s'il contient une route par defaut:
/// voir [`routes::capture_toute_la_famille`].
pub fn apply(luid: u64, cfg: &TunnelConfig) -> Result<()> {
    let plan = routes::routes_for(cfg);
    for net in &cfg.addresses {
        add_address(luid, net)?;
    }
    for famille in familles(cfg) {
        let capture = routes::capture_toute_la_famille(&plan, famille == AF_INET);
        configurer_interface(luid, famille, cfg.mtu, capture)?;
    }
    for route in &plan {
        add_route(luid, route)?;
    }
    Ok(())
}

/// Retire tout ce qu'[`apply`] a pose. Idempotent.
///
/// Ne s'arrete pas a la premiere erreur: ce qui peut etre retire l'est, et les
/// erreurs sont rassemblees. Le MTU n'est pas restaure, l'interface disparait
/// avec l'adaptateur.
pub fn remove(luid: u64, cfg: &TunnelConfig) -> Result<()> {
    let mut erreurs = Vec::new();
    for route in &routes::routes_for(cfg) {
        if let Err(e) = del_route(luid, route) {
            erreurs.push(e.to_string());
        }
    }
    for net in &cfg.addresses {
        if let Err(e) = del_address(luid, net) {
            erreurs.push(e.to_string());
        }
    }
    if erreurs.is_empty() {
        Ok(())
    } else {
        Err(Error::Tunnel(format!(
            "retrait incomplet de la configuration IP: {}",
            erreurs.join("; ")
        )))
    }
}

fn familles(cfg: &TunnelConfig) -> Vec<u16> {
    let mut f = Vec::new();
    if cfg.addresses.iter().any(IpNet::is_ipv4) {
        f.push(AF_INET);
    }
    if cfg.addresses.iter().any(|a| !a.is_ipv4()) {
        f.push(AF_INET6);
    }
    f
}

fn add_address(luid: u64, net: &IpNet) -> Result<()> {
    let mut row = MIB_UNICASTIPADDRESS_ROW::default();
    // SAFETY: `row` est une structure locale valide; l'API la remplit de ses
    // valeurs par defaut, ce qui est obligatoire avant de la completer.
    unsafe { InitializeUnicastIpAddressEntry(&mut row) };
    row.InterfaceLuid = net_luid(luid);
    row.Address = sockaddr_inet(net.addr, 0);
    row.OnLinkPrefixLength = net.prefix_len;
    // Sans cela Windows traite l'adresse comme temporaire et peut la retirer.
    row.ValidLifetime = INFINITE_LIFETIME;
    row.PreferredLifetime = INFINITE_LIFETIME;
    // Sans cette ligne, l'adresse reste a l'etat `Tentative` et ne peut PAS
    // servir d'adresse source: la table la montre, mais tout envoi depuis
    // l'interface echoue en "hote injoignable". Une interface de tunnel est
    // point a point, il n'y a personne pour repondre a une detection d'adresse
    // dupliquee, donc elle ne se conclut jamais d'elle-meme. WireGuard for
    // Windows pose la meme valeur (winipcfg, `AddIPAddress`).
    row.DadState = IpDadStatePreferred;

    // SAFETY: `row` est initialisee et vit jusqu'a la fin de l'appel.
    let code = unsafe { CreateUnicastIpAddressEntry(&row) };
    tolerer_deja_present(code, &format!("adresse {net}"))
}

fn del_address(luid: u64, net: &IpNet) -> Result<()> {
    let mut row = MIB_UNICASTIPADDRESS_ROW::default();
    // SAFETY: idem add_address.
    unsafe { InitializeUnicastIpAddressEntry(&mut row) };
    row.InterfaceLuid = net_luid(luid);
    row.Address = sockaddr_inet(net.addr, 0);
    row.OnLinkPrefixLength = net.prefix_len;

    // SAFETY: idem.
    let code = unsafe { DeleteUnicastIpAddressEntry(&row) };
    tolerer_absent(code, &format!("adresse {net}"))
}

fn forward_row(luid: u64, route: &Route) -> MIB_IPFORWARD_ROW2 {
    let mut row = MIB_IPFORWARD_ROW2::default();
    // SAFETY: `row` est locale et valide.
    unsafe { InitializeIpForwardEntry(&mut row) };
    row.InterfaceLuid = net_luid(luid);
    row.DestinationPrefix = IP_ADDRESS_PREFIX {
        Prefix: sockaddr_inet(route.dest.addr, 0),
        PrefixLength: route.dest.prefix_len,
    };
    // Prochain saut non specifie: la route pointe vers l'interface, pas vers
    // une passerelle. C'est ce que fait WireGuard for Windows.
    row.NextHop = sockaddr_inet(unspecified_like(route.dest.addr), 0);
    row.Metric = route.metric;
    row
}

pub(crate) fn add_route(luid: u64, route: &Route) -> Result<()> {
    let row = forward_row(luid, route);
    // SAFETY: `row` est initialisee et vit jusqu'a la fin de l'appel.
    let code = unsafe { CreateIpForwardEntry2(&row) };
    tolerer_deja_present(code, &format!("route {}", route.dest))
}

fn del_route(luid: u64, route: &Route) -> Result<()> {
    let row = forward_row(luid, route);
    // SAFETY: idem.
    let code = unsafe { DeleteIpForwardEntry2(&row) };
    tolerer_absent(code, &format!("route {}", route.dest))
}

/// Regle la ligne d'interface pour une famille: MTU, detection d'adresse
/// dupliquee, et metrique quand le tunnel prend la route par defaut.
///
/// Il faut relire la ligne avant de l'ecrire: `SetIpInterfaceEntry` refuse une
/// structure qui ne vient pas d'un `GetIpInterfaceEntry`. Les trois reglages
/// tiennent donc dans un seul aller-retour, ce qui est aussi ce que fait
/// WireGuard pour Windows.
///
/// # `capture`
///
/// Vrai quand le plan prend `::/0` ou `0.0.0.0/0` pour cette famille. Alors, et
/// alors seulement, la metrique automatique de l'interface est remplacee par
/// zero: sans cela la route par defaut du lien physique peut gagner la
/// comparaison et le trafic sort en clair a cote d'un tunnel qui a l'air monte.
/// Le detail du calcul est dans [`routes::capture_toute_la_famille`].
fn configurer_interface(luid: u64, family: u16, mtu: u32, capture: bool) -> Result<()> {
    let mut row = MIB_IPINTERFACE_ROW {
        Family: family,
        InterfaceLuid: net_luid(luid),
        ..Default::default()
    };

    // SAFETY: `row` porte la famille et le LUID, les deux cles de la recherche.
    let code = unsafe { GetIpInterfaceEntry(&mut row) };
    if code != ERROR_SUCCESS {
        return Err(Error::Tunnel(format!(
            "lecture de l'interface (famille {family}) en echec: erreur Win32 {code}"
        )));
    }

    row.NlMtu = mtu;
    if family == AF_INET {
        // Champ obligatoire en IPv4 sous peine de ERROR_INVALID_PARAMETER, et
        // qui n'existe pas en IPv6. Piege connu de SetIpInterfaceEntry.
        row.SitePrefixLength = 0;
    }

    // Aucune sonde de detection d'adresse dupliquee. Une adresse restee
    // `Tentative` figure dans la table sans pouvoir servir de source, et tout
    // envoi echoue alors en "hote injoignable" alors que la pose a reussi -
    // c'est le defaut qui a fait rougir la premiere recette de bout en bout.
    // Il n'y a personne d'autre sur cette interface pour se disputer une
    // adresse: la sonde ne peut rien trouver, elle ne peut que retarder.
    // WireGuard pour Windows fait de meme.
    row.DadTransmits = 0;

    if capture {
        row.UseAutomaticMetric = false;
        row.Metric = 0;
    }

    // SAFETY: `row` provient d'un GetIpInterfaceEntry reussi, comme exige.
    let code = unsafe { SetIpInterfaceEntry(&mut row) };
    if code != ERROR_SUCCESS {
        return Err(Error::Tunnel(format!(
            "reglage de l'interface (MTU {mtu}, famille {family}) refuse: \
             erreur Win32 {code}"
        )));
    }
    Ok(())
}

/// Octets entres et sortis par l'interface, ou `None` si elle a disparu.
///
/// C'est le pendant Windows de `/sys/class/net/<if>/statistics/rx_bytes`, et il
/// sert au meme endroit: le chemin par coeur n'a pas de poignee de main
/// periodique, donc ce qui prouve qu'il est vivant est que l'interface existe
/// encore et que des octets la traversent.
///
/// `None` veut dire "l'interface n'est plus la", et rien d'autre: c'est
/// exactement ce que le superviseur lit comme un tunnel perdu.
pub fn compteurs(luid: u64) -> Option<(u64, u64)> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{GetIfEntry2, MIB_IF_ROW2};

    // SAFETY: structure mise a zero, seul le LUID renseigne avant l'appel,
    // comme la documentation de GetIfEntry2 l'exige.
    unsafe {
        let mut ligne: MIB_IF_ROW2 = std::mem::zeroed();
        ligne.InterfaceLuid = net_luid(luid);
        (GetIfEntry2(&raw mut ligne) == ERROR_SUCCESS).then_some((ligne.InOctets, ligne.OutOctets))
    }
}

/// La metrique effective de l'interface pour une famille, et si elle est
/// automatique.
///
/// Relue au systeme plutot que deduite du code de retour, comme [`mtu`]: c'est
/// la difference entre "l'appel a reussi" et "l'etat voulu est en place".
pub fn metrique(luid: u64, family: u16) -> Option<(u32, bool)> {
    let mut row = MIB_IPINTERFACE_ROW {
        Family: family,
        InterfaceLuid: net_luid(luid),
        ..Default::default()
    };
    // SAFETY: `row` porte la famille et le LUID, les deux cles de la recherche.
    let code = unsafe { GetIpInterfaceEntry(&mut row) };
    (code == ERROR_SUCCESS).then_some((row.Metric, row.UseAutomaticMetric))
}

/// Vrai si l'adresse est effectivement portee par l'interface.
///
/// On redemande au systeme plutot que de croire un code de retour: c'est la
/// difference entre "l'appel a reussi" et "l'etat voulu est en place".
pub fn address_exists(luid: u64, net: &IpNet) -> bool {
    let mut row = MIB_UNICASTIPADDRESS_ROW::default();
    // SAFETY: `row` est locale et valide.
    unsafe { InitializeUnicastIpAddressEntry(&mut row) };
    row.InterfaceLuid = net_luid(luid);
    row.Address = sockaddr_inet(net.addr, 0);
    // SAFETY: la famille, le LUID et l'adresse sont les cles de la recherche.
    unsafe { GetUnicastIpAddressEntry(&mut row) == ERROR_SUCCESS }
}

/// Vrai si la route est effectivement dans la table.
pub fn route_exists(luid: u64, route: &Route) -> bool {
    let mut row = forward_row(luid, route);
    // SAFETY: `row` porte le LUID, la destination et le prochain saut.
    unsafe { GetIpForwardEntry2(&mut row) == ERROR_SUCCESS }
}

/// LUID de l'interface que Windows choisirait pour joindre `dest`.
///
/// Sert a lever une ambiguite quand plusieurs routes visent la meme
/// destination: savoir qu'une route existe ne dit pas qu'elle est celle qui
/// gagne. C'est la difference entre une mesure et une supposition.
pub fn best_route_interface(dest: IpAddr) -> Option<u64> {
    let destination = sockaddr_inet(dest, 0);
    let mut route = MIB_IPFORWARD_ROW2::default();
    let mut source = SOCKADDR_INET::default();
    // SAFETY: les trois structures sont locales et valides; un LUID nul et un
    // index nul demandent a l'API de choisir elle-meme l'interface.
    let code = unsafe {
        GetBestRoute2(
            std::ptr::null(),
            0,
            std::ptr::null(),
            &destination,
            0,
            &mut route,
            &mut source,
        )
    };
    if code == ERROR_SUCCESS {
        // SAFETY: `Value` est la vue u64 de l'union, valide quoi qu'on y ait
        // ecrit.
        Some(unsafe { route.InterfaceLuid.Value })
    } else {
        None
    }
}

/// Le nom convivial d'une interface, celui que voient les programmes.
///
/// `ConvertInterfaceLuidToAlias` rend l'ALIAS - "Ethernet", "Wi-Fi" - et non le
/// GUID. C'est ce nom-la qu'attendent les coeurs quand on leur demande de lier
/// leur sortie a une interface: la bibliotheque standard de Go, dont les deux
/// sont ecrits, expose sous `Interface.Name` le nom convivial de Windows.
pub fn alias(luid: u64) -> Option<String> {
    use windows_sys::Win32::NetworkManagement::IpHelper::ConvertInterfaceLuidToAlias;

    // `IF_MAX_STRING_SIZE + 1`, ce que la documentation exige au minimum.
    let mut tampon = [0u16; 257];
    let entree = NET_LUID_LH { Value: luid };
    // SAFETY: le LUID et le tampon sont locaux et vivent le temps de l'appel;
    // la longueur annoncee est celle du tampon, en caracteres.
    let code = unsafe { ConvertInterfaceLuidToAlias(&entree, tampon.as_mut_ptr(), tampon.len()) };
    if code != ERROR_SUCCESS {
        return None;
    }
    let fin = tampon.iter().position(|c| *c == 0).unwrap_or(tampon.len());
    Some(String::from_utf16_lossy(&tampon[..fin]))
}

/// L'interface par laquelle la machine sort AUJOURD'HUI vers `dest`.
///
/// A appeler AVANT de poser la route par defaut du tunnel: apres, elle
/// repondrait le tunnel lui-meme, ce qui est exactement la boucle qu'on cherche
/// a eviter. Le moment de l'appel fait partie de la reponse.
pub fn interface_de_sortie(dest: IpAddr) -> Option<String> {
    alias(best_route_interface(dest)?)
}

/// Etat de detection d'adresse dupliquee (DAD) d'une adresse posee.
///
/// Une adresse restee `Tentative` (valeur 2) figure dans la table mais ne peut
/// pas servir d'adresse source: tout envoi depuis l'interface echoue en "hote
/// injoignable", alors que la pose a bien reussi. `Preferred` vaut 4.
pub fn address_dad_state(luid: u64, net: &IpNet) -> Option<i32> {
    let mut row = MIB_UNICASTIPADDRESS_ROW::default();
    // SAFETY: `row` est locale et valide.
    unsafe { InitializeUnicastIpAddressEntry(&mut row) };
    row.InterfaceLuid = net_luid(luid);
    row.Address = sockaddr_inet(net.addr, 0);
    // SAFETY: la famille, le LUID et l'adresse sont les cles de la recherche.
    if unsafe { GetUnicastIpAddressEntry(&mut row) } == ERROR_SUCCESS {
        Some(row.DadState)
    } else {
        None
    }
}

/// MTU courant de l'interface pour une famille.
pub fn mtu(luid: u64, family: u16) -> Option<u32> {
    let mut row = MIB_IPINTERFACE_ROW {
        Family: family,
        InterfaceLuid: net_luid(luid),
        ..Default::default()
    };
    // SAFETY: `row` porte les deux cles de la recherche.
    if unsafe { GetIpInterfaceEntry(&mut row) } == ERROR_SUCCESS {
        Some(row.NlMtu)
    } else {
        None
    }
}

fn net_luid(value: u64) -> NET_LUID_LH {
    NET_LUID_LH { Value: value }
}

fn unspecified_like(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V4(_) => IpAddr::from([0u8; 4]),
        IpAddr::V6(_) => IpAddr::from([0u8; 16]),
    }
}

/// Construit un `SOCKADDR_INET`. Le port est en ordre reseau.
fn sockaddr_inet(addr: IpAddr, port: u16) -> SOCKADDR_INET {
    let mut sa = SOCKADDR_INET::default();
    match addr {
        IpAddr::V4(v4) => {
            sa.Ipv4 = SOCKADDR_IN {
                sin_family: AF_INET,
                sin_port: port.to_be(),
                sin_addr: IN_ADDR {
                    S_un: IN_ADDR_0 {
                        S_addr: u32::from_ne_bytes(v4.octets()),
                    },
                },
                sin_zero: [0; 8],
            };
        }
        IpAddr::V6(v6) => {
            sa.Ipv6 = SOCKADDR_IN6 {
                sin6_family: AF_INET6,
                sin6_port: port.to_be(),
                sin6_flowinfo: 0,
                sin6_addr: IN6_ADDR {
                    u: IN6_ADDR_0 { Byte: v6.octets() },
                },
                Anonymous: SOCKADDR_IN6_0 { sin6_scope_id: 0 },
            };
        }
    }
    sa
}

/// Reposer une configuration deja en place n'est pas une erreur: `up` doit
/// pouvoir etre rejoue apres une reconnexion partielle.
fn tolerer_deja_present(code: u32, quoi: &str) -> Result<()> {
    match code {
        ERROR_SUCCESS | ERROR_OBJECT_ALREADY_EXISTS => Ok(()),
        _ => Err(Error::Tunnel(format!(
            "pose de {quoi} en echec: erreur Win32 {code}"
        ))),
    }
}

/// Le but du retrait est qu'il ne reste rien, pas qu'il y ait eu quelque chose
/// a retirer.
fn tolerer_absent(code: u32, quoi: &str) -> Result<()> {
    match code {
        ERROR_SUCCESS | ERROR_NOT_FOUND => Ok(()),
        _ => Err(Error::Tunnel(format!(
            "retrait de {quoi} en echec: erreur Win32 {code}"
        ))),
    }
}
