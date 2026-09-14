//! La configuration IP du chemin par coeur, sur une vraie interface Wintun.
//!
//! # Ce que ce fichier NE fait PAS, et pourquoi
//!
//! Il ne monte pas le chemin par coeur en entier. Le faire poserait une route
//! par defaut vers un TUN qui ne mene nulle part, c'est-a-dire couperait le
//! reseau de la machine qui execute la recette. Son homologue Linux,
//! `tests/coeur_tunnel.rs`, s'en sort en creant un espace de noms reseau et en
//! s'y relancant; Windows n'a pas d'equivalent, et la seule facon honnete de
//! mesurer ce montage-la est de le faire sur une machine dont on accepte de
//! perdre le reseau. Ce n'est pas celle-ci.
//!
//! Reste ce qui se mesure sans rien couper, et qui est l'essentiel du nouveau
//! code: `ipcfg::apply` sur un TUN Wintun - il ne servait jusqu'ici qu'a un
//! adaptateur WireGuardNT - avec un plan qui ne prend qu'une route HOTE. La
//! portee est alors d'une seule adresse au lieu de tout le trafic, et c'est
//! exactement le tour que `wgnt::routes::route_bouclage` employait deja pour
//! provoquer une condition de bouclage sans consequence.
//!
//! Cette route hote sert deux fois: elle mesure que la configuration IP prend,
//! et elle etablit que [`ipcfg::interface_de_sortie`] SUIT la table de routage.
//! C'est ce qui rend load-bearing la regle "l'appeler avant de monter le
//! tunnel": la meme question posee apres repondrait le tunnel lui-meme, et le
//! coeur serait lie a l'interface dont on voulait le faire sortir.
//!
//! # Ce que la premiere execution privilegiee a appris
//!
//! Deux faits qui vont ensemble, et dont le couple justifie que `demonter_ici`
//! ne nettoie rien sous Windows.
//!
//! La destruction de l'adaptateur n'est PAS synchrone: `alias` rendait encore
//! le nom de l'interface juste apres le `drop`, et elle a mis 127 ms a
//! disparaitre (mesure du 20 aout 2026 sur dev-windows). La recette attend donc,
//! avec une borne, et imprime le delai.
//!
//! Mais la table de routage, elle, cesse IMMEDIATEMENT de designer l'interface -
//! c'est la seconde recette qui l'etablit, dont la derniere assertion suit le
//! `drop` sans rien entre les deux. C'est la propriete qui compte: pendant ces
//! 127 ms, l'interface existe encore mais plus rien n'y est envoye.

#![cfg(windows)]

use bifrost_core::config::{
    DnsPolicy, Endpoint, IpNet, PeerConfig, Portage, TunnelConfig, WgKey, WireguardParams,
};
use bifrost_daemon::tunnel::brut;
use bifrost_daemon::tunnel::wgnt::{ipcfg, routes};
use std::net::{IpAddr, Ipv4Addr};
use windows_sys::Win32::Networking::WinSock::AF_INET;
use windows_sys::core::GUID;

/// Les GUID de ce fichier, distincts de ceux des autres recettes: deux
/// adaptateurs ne peuvent pas partager un GUID, et rien n'empeche deux jeux de
/// recettes de tourner dans la meme minute.
const GUID_COEUR: [GUID; 2] = [
    GUID::from_u128(0x0bd4f5a1_6c1e_4f8d_9a3e_2f7b41c9e560),
    GUID::from_u128(0x0bd4f5a1_6c1e_4f8d_9a3e_2f7b41c9e561),
];

/// Anneau minimal: ces recettes ne lisent aucun paquet.
const ANNEAU: u32 = 0x2_0000;

/// L'adresse posee sur le TUN. TEST-NET-2, RFC 5737.
const ADRESSE: &str = "198.51.100.2/32";

/// Le temoin qu'on fera passer par le TUN. Une seule adresse, et de
/// documentation: aucune machine reelle n'est derriere.
const TEMOIN: IpAddr = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 77));

/// MTU distinct du defaut, pour qu'une valeur relue prouve quelque chose.
const MTU: u32 = 1380;

/// Attente maximale pour que l'interface disparaisse apres la fermeture du TUN.
/// Genereuse a dessein: ce qui est mesure est qu'elle finit par partir, et le
/// delai reel est imprime a cote.
const BORNE: std::time::Duration = std::time::Duration::from_secs(10);

/// Pourquoi ce qui suit ne peut pas tourner ici, s'il y a une raison.
fn raison_de_sauter() -> Option<String> {
    let a_cote = std::env::current_exe()
        .ok()
        .and_then(|e| e.parent().map(|d| d.join("wintun.dll")));
    match a_cote {
        Some(c) if c.is_file() => {}
        _ => {
            return Some(
                "wintun.dll absente a cote du binaire: le depot ne distribue aucun \
                 binaire tiers, la recuperer avec 'bifrost pilote recuperer'"
                    .to_owned(),
            );
        }
    }
    if !est_eleve() {
        return Some(
            "creer une interface Wintun installe le pilote, et poser une adresse ou une \
             route demande les droits d'administrateur"
                .to_owned(),
        );
    }
    None
}

fn est_eleve() -> bool {
    use std::mem::size_of;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{
        GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    // SAFETY: jeton du processus courant, champ de taille connue, handle
    // referme sur tous les chemins.
    unsafe {
        let mut jeton: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut jeton) == 0 {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION::default();
        let mut taille = 0u32;
        let ok = GetTokenInformation(
            jeton,
            TokenElevation,
            &raw mut elevation as *mut std::ffi::c_void,
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut taille,
        );
        CloseHandle(jeton);
        ok != 0 && elevation.TokenIsElevated != 0
    }
}

fn cle(c: char) -> WgKey {
    let mut s: String = std::iter::repeat_n(c, 42).collect();
    s.push('A');
    s.push('=');
    s.parse().unwrap()
}

/// Une configuration dont le plan est une SEULE route hote.
///
/// Portee par WireGuard et non par un coeur, et c'est le point: un portage par
/// coeur prendrait `0.0.0.0/0`, ce que cette recette refuse de poser. Le code
/// mesure est le meme - `ipcfg::apply` ne sait pas qui a decide du plan.
fn cfg(interface: &str) -> TunnelConfig {
    TunnelConfig {
        interface: interface.to_owned(),
        addresses: vec![ADRESSE.parse().unwrap()],
        mtu: MTU,
        allow_lan: false,
        dns: DnsPolicy {
            local_resolver: IpAddr::V4(Ipv4Addr::LOCALHOST),
            upstream: vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))],
            embarque: false,
            anti_telemetrie: bifrost_core::config::ProfilTelemetrie::Aucun,
        },
        portage: Portage::Wireguard(Box::new(WireguardParams {
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
                allowed_ips: vec![IpNet {
                    addr: TEMOIN,
                    prefix_len: 32,
                }],
                persistent_keepalive: 25,
            },
        })),
    }
}

#[test]
fn la_configuration_ip_prend_sur_un_tun_wintun() {
    let Some(raison) = raison_de_sauter() else {
        let cfg = cfg("bfc-win-a0");
        let plan = routes::routes_for(&cfg);
        assert!(
            !routes::contient_route_par_defaut(&plan),
            "garde-fou: cette recette ne pose JAMAIS de route par defaut, elle couperait \
             le reseau de la machine. Plan: {plan:?}"
        );

        let tun = brut::ouvrir_avec(&cfg.interface, &GUID_COEUR[0], ANNEAU)
            .expect("l'interface doit s'ouvrir");
        let luid = tun.luid();

        ipcfg::apply(luid, &cfg).expect("la configuration IP doit prendre");

        let net = &cfg.addresses[0];
        assert!(
            ipcfg::address_exists(luid, net),
            "l'adresse {net} n'est pas sur l'interface"
        );

        // Presente ne suffit pas: une adresse restee Tentative figure dans la
        // table sans pouvoir servir de source. `DadTransmits = 0` doit la faire
        // naitre Preferred, qui vaut 4.
        let dad = ipcfg::address_dad_state(luid, net);
        assert_eq!(
            dad,
            Some(4),
            "etat DAD {dad:?}: l'adresse ne pourra pas servir d'adresse source"
        );

        assert_eq!(ipcfg::mtu(luid, AF_INET), Some(MTU));

        for r in &plan {
            assert!(
                ipcfg::route_exists(luid, r),
                "la route {} n'est pas dans la table",
                r.dest
            );
        }

        // La metrique reste automatique: le plan ne capture pas la famille.
        // C'est le versant negatif de la regle, et le seul mesurable ici - le
        // versant positif demande une route par defaut.
        let (_, automatique) =
            ipcfg::metrique(luid, AF_INET).expect("la ligne d'interface doit se relire");
        assert!(
            automatique,
            "metrique forcee alors que le plan ne prend pas la route par defaut"
        );

        drop(tun);

        // L'adaptateur disparait avec la structure, et Windows emporte avec lui
        // ce qui le designait: c'est ce qui autorise `demonter_ici` a ne rien
        // nettoyer. Mais la destruction n'est PAS synchrone, et la premiere
        // version de cette recette l'a appris en rougissant - `alias` rendait
        // encore `bfc-win-a0` juste apres le `drop`. On attend donc, avec une
        // borne, et on imprime le delai observe pour que la prochaine execution
        // dise si l'ordre de grandeur bouge.
        //
        // Ce que le delai ne remet pas en cause: la table de routage, elle,
        // cesse immediatement de designer l'interface - c'est l'autre recette de
        // ce fichier qui le mesure, et c'est la propriete qui compte, puisque
        // c'est elle qui enverrait du trafic vers une interface morte.
        let debut = std::time::Instant::now();
        while ipcfg::alias(luid).is_some() && debut.elapsed() < BORNE {
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let delai = debut.elapsed();
        println!("  l'interface a disparu en {delai:?}");

        assert!(
            ipcfg::alias(luid).is_none(),
            "le LUID designe encore une interface {BORNE:?} apres la fermeture du TUN"
        );
        assert!(
            !ipcfg::address_exists(luid, net),
            "l'adresse {net} a survecu a l'interface"
        );
        for r in &plan {
            assert!(
                !ipcfg::route_exists(luid, r),
                "la route {} a survecu a l'interface",
                r.dest
            );
        }
        return;
    };
    println!("SKIPPED: {raison}");
}

#[test]
fn interface_de_sortie_suit_la_table_et_repondrait_le_tunnel_si_on_l_appelait_trop_tard() {
    let Some(raison) = raison_de_sauter() else {
        let cfg = cfg("bfc-win-a1");

        // Avant: le temoin sort par ou la machine sort. Quelle interface, on ne
        // le sait pas et on n'a pas a le savoir; ce qui compte est qu'il y en
        // ait une, et qu'elle ne soit pas celle qu'on va creer.
        let avant = ipcfg::interface_de_sortie(TEMOIN);
        assert!(
            avant.is_some(),
            "aucune route vers {TEMOIN}: cette machine n'a pas de route par defaut, la \
             recette ne peut rien comparer"
        );

        let tun = brut::ouvrir_avec(&cfg.interface, &GUID_COEUR[1], ANNEAU)
            .expect("l'interface doit s'ouvrir");
        let luid = tun.luid();
        ipcfg::apply(luid, &cfg).expect("la configuration IP doit prendre");

        let nom_du_tun = ipcfg::alias(luid).expect("le TUN doit avoir un alias");
        assert_ne!(
            avant.as_deref(),
            Some(nom_du_tun.as_str()),
            "le temoin sortait deja par le TUN avant qu'il existe"
        );

        // Apres: la meme question, la meme fonction, une autre reponse - parce
        // que la table a change. Une route hote bat toutes les autres, ce qui
        // reproduit en une seule adresse ce qu'une route par defaut ferait pour
        // tout le trafic.
        let apres = ipcfg::interface_de_sortie(TEMOIN);
        assert_eq!(
            apres.as_deref(),
            Some(nom_du_tun.as_str()),
            "la table designe {nom_du_tun} pour {TEMOIN}, la fonction dit {apres:?}"
        );

        drop(tun);

        // Et la table revient d'elle-meme a ce qu'elle etait. C'est aussi la
        // verification d'hygiene: rien de ce que la recette a pose ne survit.
        assert_eq!(
            ipcfg::interface_de_sortie(TEMOIN),
            avant,
            "la route hote a survecu a la disparition de l'interface"
        );
        return;
    };
    println!("SKIPPED: {raison}");
}
