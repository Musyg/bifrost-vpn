//! Autotest du transport WireGuardNT, confronte au vrai driver.
//!
//! Ce que le driver valide et que rien d'autre ne peut valider: la disposition
//! du blob de configuration. `--wgnt-selftest` ecrit une configuration, la
//! relit telle que le driver la voit, et compare. Un offset faux ne survit pas
//! a cet aller-retour: soit le driver refuse le blob, soit il rend autre chose
//! que ce qu'on a ecrit.
//!
//! Quatre phases, de la moins engageante a la plus.
//!
//! 1. **Aller-retour du blob**: un adaptateur, une configuration ecrite puis
//!    relue et comparee. Aucun trafic.
//! 2. **Configuration IP**: adresses, routes et MTU poses, redemandes au
//!    systeme, retires, puis on verifie qu'il ne reste rien. Les prefixes
//!    viennent de RFC 5737, et un garde-fou refuse toute route par defaut: en
//!    poser une vers un tunnel qui ne transporte rien couperait le reseau de la
//!    machine.
//! 3. **LUID dans le kill switch**: le plan WFP est pose en portant le LUID que
//!    WireGuardNT vient de donner, pour verifier que WFP accepte cette
//!    condition d'interface. C'est le maillon qui autorise le trafic du tunnel.
//! 4. **Handshake**: deux adaptateurs montes sur cette machine se parlent par
//!    la boucle locale. Du vrai trafic WireGuard circule, mais il ne quitte pas
//!    la machine: l'endpoint est `127.0.0.1` et les adresses viennent de
//!    TEST-NET-2.
//!
//! Le seul plan WFP pose est la variante SANS BLOCAGE, en phase 3: memes
//! objets et memes conditions que le vrai kill switch, mais rien n'est coupe.
//! La seule trace durable est l'installation du driver au premier appel; les
//! adaptateurs et les filtres sont retires a la fin.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use anyhow::{Context, bail};
use bifrost_core::config::{DnsPolicy, Endpoint, PeerConfig, TunnelConfig, WgKey};
use bifrost_core::ports::{FirewallPolicy, KillSwitch};

use windows_sys::Win32::Networking::WinSock::AF_INET;

use super::adapter::{self, Adapter};
use super::config as blob;
use super::dll::WireGuardNt;
use super::{ipcfg, routes};

/// Nom de l'adaptateur de l'autotest. Distinct de celui d'un vrai tunnel, pour
/// qu'un autotest ne puisse pas demonter une connexion en cours. Quinze
/// caracteres au plus: `TunnelConfig` impose la limite d'`IFNAMSIZ`, qui vient
/// de Linux mais s'applique a toute la configuration.
const ADAPTER_NAME: &str = "Bifrost-test";

/// Cles factices. Elles ne protegent rien: aucun trafic n'est echange, et
/// l'endpoint est une adresse de documentation vers laquelle rien ne part.
/// Elles sont ecrites en clair a dessein, pour que l'autotest soit
/// deterministe et qu'aucune cle reelle n'ait a exister pour le lancer.
const CLE_PRIVEE_FACTICE: &str = "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const CLE_PUBLIQUE_FACTICE: &str = "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

/// Les deux cotes de l'epreuve de handshake. Memes remarques que ci-dessus:
/// factices, deterministes, jamais utilisees pour du vrai trafic.
///
/// Elles different par le PREMIER octet, valant 8 et 16, et ce n'est pas un
/// detail. WireGuard clampe toute cle privee avant usage: `k[0] &= 248`,
/// `k[31] &= 127`, `k[31] |= 64`. Deux cles qui ne different que par les trois
/// bits de poids faible du premier octet deviennent donc la MEME cle apres
/// clampage, et derivent la meme cle publique: l'epreuve aurait alors deux
/// adaptateurs a l'identite identique, ce qui n'est pas deux pairs. C'est
/// exactement ce qui s'est produit avec un premier jeu de cles valant 3 et 4.
const SRV: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const CLI: &str = "EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const SRV_NAME: &str = "Bifrost-srv";
const CLI_NAME: &str = "Bifrost-cli";
/// TEST-NET-2 (RFC 5737): reservee a la documentation, donc garantie hors
/// usage. Des `/32` sur des interfaces de tunnel, aucune route par defaut.
const SRV_ADDR: &str = "198.51.100.1/32";
const CLI_ADDR: &str = "198.51.100.2/32";
/// Ports d'ecoute. Explicites et distincts des deux cotes: laisser l'un des
/// deux au hasard rendrait l'epreuve dependante de ce que le driver fait d'un
/// `HAS_LISTEN_PORT` absent, et deux adaptateurs qui reclament le meme port
/// echouent a s'activer avec un partage refuse.
const LISTEN_PORT: u16 = 51821;
const CLIENT_PORT: u16 = 51822;

/// Un handshake WireGuard se fait en un aller-retour. Cette marge couvre le
/// demarrage des deux adaptateurs, pas une lenteur reseau: tout est local.
const DELAI_HANDSHAKE: Duration = Duration::from_secs(15);
const PAS: Duration = Duration::from_millis(250);

/// `IpDadStatePreferred`. Le seul etat dans lequel une adresse peut servir de
/// source.
const PREFERRED: i32 = 4;

pub fn run() -> anyhow::Result<()> {
    // Tout ce qui peut echouer sans toucher a la machine est fait d'abord.
    // Creer l'adaptateur installe le driver: le faire pour decouvrir ensuite
    // que la configuration est invalide serait modifier la machine pour rien.
    let cfg = configuration_d_essai()?;
    let ecrit = blob::encode(&cfg).map_err(anyhow::Error::msg)?;

    let chemin = WireGuardNt::expected_path().map_err(anyhow::Error::msg)?;
    println!("chargement de {}", chemin.display());
    let nt = WireGuardNt::load().map_err(anyhow::Error::msg)?;
    println!("  symboles resolus");

    println!("creation de l'adaptateur '{ADAPTER_NAME}'...");
    let adapter = Adapter::create(nt, ADAPTER_NAME)
        .map_err(anyhow::Error::msg)
        .context("creation de l'adaptateur")?;
    match adapter.driver_version() {
        Some((maj, min)) => println!("  driver WireGuardNT {maj}.{min}"),
        None => println!("  version du driver indisponible"),
    }
    println!("  LUID {:#x}", adapter.luid());

    println!("configuration de {} octets...", ecrit.len());
    adapter
        .set_configuration(&ecrit)
        .map_err(anyhow::Error::msg)
        .context("le driver a refuse le blob")?;
    println!("  acceptee");

    let relu = adapter
        .get_configuration()
        .map_err(anyhow::Error::msg)
        .context("relecture")?;
    println!("relecture de {} octets", relu.len());
    let vu = blob::decode(&relu).map_err(anyhow::Error::msg)?;
    let attendu = blob::decode(&ecrit).map_err(anyhow::Error::msg)?;

    let mut echecs = Vec::new();
    if vu.peers_count != 1 {
        echecs.push(format!("{} pairs relus, 1 attendu", vu.peers_count));
    }
    let (Some(pair_vu), Some(pair_ecrit)) = (&vu.peer, &attendu.peer) else {
        bail!("le driver a rendu une interface sans pair alors qu'un pair a ete ecrit");
    };
    if pair_vu.public_key != pair_ecrit.public_key {
        echecs.push("la cle publique du pair relue differe de celle ecrite".to_owned());
    }
    if pair_vu.endpoint != pair_ecrit.endpoint {
        echecs.push(format!(
            "endpoint relu {:?}, {:?} ecrit",
            pair_vu.endpoint, pair_ecrit.endpoint
        ));
    }
    if pair_vu.allowed_ips != pair_ecrit.allowed_ips {
        echecs.push(format!(
            "prefixes relus {:?}, {:?} ecrits",
            pair_vu.allowed_ips, pair_ecrit.allowed_ips
        ));
    }
    if pair_vu.persistent_keepalive != pair_ecrit.persistent_keepalive {
        echecs.push(format!(
            "keepalive relu {}, {} ecrit",
            pair_vu.persistent_keepalive, pair_ecrit.persistent_keepalive
        ));
    }
    println!(
        "  cle publique du pair: {}",
        verdict(pair_vu.public_key == pair_ecrit.public_key)
    );
    println!(
        "  endpoint:             {} {:?}",
        verdict(pair_vu.endpoint == pair_ecrit.endpoint),
        pair_vu.endpoint
    );
    println!(
        "  prefixes autorises:   {} {:?}",
        verdict(pair_vu.allowed_ips == pair_ecrit.allowed_ips),
        pair_vu.allowed_ips
    );
    println!(
        "  keepalive:            {} {}",
        verdict(pair_vu.persistent_keepalive == pair_ecrit.persistent_keepalive),
        pair_vu.persistent_keepalive
    );

    println!("activation de l'adaptateur...");
    adapter.set_state(true).map_err(anyhow::Error::msg)?;

    echecs.extend(eprouver_config_ip(adapter.luid(), &cfg)?);
    echecs.extend(eprouver_luid_dans_le_kill_switch(adapter.luid(), &cfg)?);

    adapter.set_state(false).map_err(anyhow::Error::msg)?;
    println!("adaptateur desactive");

    // La fermeture retire l'adaptateur. Le driver, lui, reste installe: c'est
    // le comportement de WireGuardNT, et c'est ce que fait aussi le client
    // officiel.
    drop(adapter);
    println!("adaptateur retire");

    println!("\n--- handshake entre deux adaptateurs, en boucle locale ---");
    match eprouver_handshake() {
        Ok(None) => println!("  handshake etabli des deux cotes"),
        Ok(Some(raison)) => {
            println!("  SKIPPED: {raison}");
        }
        Err(e) => echecs.push(format!("epreuve de handshake: {e:#}")),
    }

    if echecs.is_empty() {
        println!(
            "\nautotest WireGuardNT: blob accepte et rendu identique, \
             configuration IP posee puis retiree sans residu, LUID du tunnel \
             accepte par le kill switch. Voir la ligne de handshake ci-dessus: \
             un SKIPPED n'est pas une preuve de transport."
        );
        Ok(())
    } else {
        for e in &echecs {
            eprintln!("ECHEC: {e}");
        }
        bail!("{} verification(s) en echec", echecs.len())
    }
}

fn verdict(ok: bool) -> &'static str {
    if ok { "OK  " } else { "ECHEC" }
}

/// Pose la configuration IP, verifie qu'elle est bien la, la retire, verifie
/// qu'il ne reste rien.
///
/// Chaque verification redemande au systeme au lieu de se fier au code de
/// retour de la pose: "l'appel a reussi" et "l'etat voulu est en place" sont
/// deux affirmations differentes.
fn eprouver_config_ip(luid: u64, cfg: &TunnelConfig) -> anyhow::Result<Vec<String>> {
    let plan = routes::routes_for(cfg);

    // Garde-fou. L'autotest tourne sur une machine de travail: poser une route
    // par defaut vers un tunnel qui ne transporte rien la couperait du reseau.
    // C'est exactement la faute qui a deja coute un redemarrage cote WFP.
    if routes::contient_route_par_defaut(&plan) {
        bail!(
            "la configuration d'essai contient une route par defaut. Refus: \
             l'autotest la poserait reellement et couperait le reseau de cette \
             machine."
        );
    }

    println!(
        "pose de la configuration IP ({} adresse(s), {} route(s), MTU {})...",
        cfg.addresses.len(),
        plan.len(),
        cfg.mtu
    );
    ipcfg::apply(luid, cfg).map_err(anyhow::Error::msg)?;

    let mut echecs = Vec::new();
    for net in &cfg.addresses {
        let ok = ipcfg::address_exists(luid, net);
        println!("  adresse {net}: {}", verdict(ok));
        if !ok {
            echecs.push(format!("l'adresse {net} n'est pas sur l'interface"));
        }
        // Presente ne suffit pas: une adresse restee Tentative ne peut pas
        // servir de source, et tout envoi echoue en "hote injoignable" alors
        // que la table la montre bien. C'est exactement le defaut qui a fait
        // echouer la premiere recette de bout en bout.
        let dad = ipcfg::address_dad_state(luid, net);
        println!(
            "  etat DAD de {net}: {} {dad:?}",
            verdict(dad == Some(PREFERRED))
        );
        if dad != Some(PREFERRED) {
            echecs.push(format!(
                "l'adresse {net} est a l'etat DAD {dad:?}, {PREFERRED} \
                 (Preferred) attendu: elle ne pourra pas servir d'adresse source"
            ));
        }
    }
    for r in &plan {
        let ok = ipcfg::route_exists(luid, r);
        println!("  route {}: {}", r.dest, verdict(ok));
        if !ok {
            echecs.push(format!("la route {} n'est pas dans la table", r.dest));
        }
    }
    let vu = ipcfg::mtu(luid, AF_INET);
    println!("  MTU IPv4: {} {vu:?}", verdict(vu == Some(cfg.mtu)));
    if vu != Some(cfg.mtu) {
        echecs.push(format!("MTU IPv4 {vu:?}, {} attendu", cfg.mtu));
    }

    println!("retrait de la configuration IP...");
    ipcfg::remove(luid, cfg).map_err(anyhow::Error::msg)?;

    let restants: Vec<String> = cfg
        .addresses
        .iter()
        .filter(|n| ipcfg::address_exists(luid, n))
        .map(|n| n.to_string())
        .chain(
            plan.iter()
                .filter(|r| ipcfg::route_exists(luid, r))
                .map(|r| r.dest.to_string()),
        )
        .collect();
    println!("  residus apres retrait: {}", verdict(restants.is_empty()));
    if !restants.is_empty() {
        echecs.push(format!(
            "{} objet(s) survivent au retrait: {}",
            restants.len(),
            restants.join(", ")
        ));
    }

    Ok(echecs)
}

/// Le kill switch accepte-t-il le LUID que WireGuardNT vient de donner?
///
/// C'est le maillon qui autorise le trafic du tunnel. Un LUID que WFP refuse
/// ferait echouer `FwpmFilterAdd0`, donc l'armement, donc la connexion; un LUID
/// simplement absent produirait un kill switch qui bloque aussi le tunnel, sans
/// rien signaler. Les deux se voient ici et nulle part ailleurs.
///
/// Le plan pose est la variante SANS BLOCAGE: memes objets, memes conditions,
/// mais rien n'est coupe. Ce qu'on mesure est que WFP accepte la condition
/// d'interface, pas qu'il bloque.
///
/// On en profite pour confronter la resolution par NOM a ce que le driver a
/// donne. Le produit ne s'en sert qu'en dernier recours, mais savoir si elle
/// fonctionne sur un adaptateur WireGuardNT, et si elle rend le meme
/// identifiant, evite d'avoir a le supposer.
fn eprouver_luid_dans_le_kill_switch(luid: u64, cfg: &TunnelConfig) -> anyhow::Result<Vec<String>> {
    let mut echecs = Vec::new();
    println!("le kill switch accepte-t-il le LUID {luid:#x}...");

    match bifrost_firewall::windows::interface_luid(&cfg.interface) {
        Ok(par_nom) if par_nom == luid => {
            println!("  resolution par nom '{}': meme LUID", cfg.interface)
        }
        Ok(par_nom) => echecs.push(format!(
            "la resolution par nom rend {par_nom:#x}, le driver {luid:#x}: deux \
             interfaces differentes portent le meme nom, ou l'une des deux \
             sources ment"
        )),
        // Pas un echec: le produit n'en depend pas. Mais c'est bon a savoir, et
        // ca justifie de ne pas s'y fier.
        Err(e) => println!(
            "  resolution par nom '{}': indisponible ({e})",
            cfg.interface
        ),
    }

    let mut policy = FirewallPolicy::from_config(cfg);
    policy.tunnel_interface = Some(cfg.interface.clone());
    policy.tunnel_luid = Some(luid);

    let mut firewall =
        bifrost_firewall::windows::WfpKillSwitch::new().map_err(anyhow::Error::msg)?;
    let poses = firewall
        .engage_without_blocking(&policy)
        .map_err(anyhow::Error::msg)
        .context("le kill switch a refuse le plan portant le LUID du tunnel")?;

    // Le plan sans tunnel compte huit specifications; avec, neuf. Si le permit
    // du tunnel manquait, le compte le dirait avant que le trafic ne le dise.
    let sans_tunnel = {
        let mut p = policy.clone();
        p.tunnel_luid = None;
        p.tunnel_interface = None;
        bifrost_firewall::wfp_plan::plan(&p, std::env::current_exe()?, None).len()
    };
    println!("  specifications posees: {poses} (contre {sans_tunnel} sans tunnel)");
    if poses != sans_tunnel + 1 {
        echecs.push(format!(
            "{poses} specifications posees, {} attendues: le permit du tunnel \
             n'est pas dans le plan",
            sans_tunnel + 1
        ));
    }

    firewall
        .disengage()
        .map_err(anyhow::Error::msg)
        .context("retrait des filtres de l'epreuve")?;
    println!("  filtres retires");

    Ok(echecs)
}

/// Monte deux adaptateurs WireGuardNT sur cette machine et les fait se parler
/// par la boucle locale, pour obtenir un vrai handshake.
///
/// C'est le seul moyen d'eprouver le transport sans serveur distant. Ce que ca
/// etablit et que le reste de l'autotest ne peut pas etablir:
///
/// - les cles privees ecrites dans le blob sont bien celles que le driver
///   utilise, puisque deux pairs qui ne partagent pas les bonnes cles ne font
///   jamais de handshake;
/// - la cle publique de l'interface est bien derivee par le driver et relue au
///   bon endroit, puisqu'elle sert de cle de pair a l'autre cote;
/// - l'endpoint est ecrit au bon offset et son port dans le bon ordre, sans
///   quoi les paquets ne trouvent pas le pair;
/// - `handshake()` rend une date et des compteurs qui bougent.
///
/// Rien ne sort de la machine: l'endpoint est `127.0.0.1`, et les adresses
/// viennent de TEST-NET-2 (RFC 5737), reservee a la documentation. Aucune route
/// par defaut n'est posee.
///
/// Rend `Ok(None)` si le handshake a eu lieu, `Ok(Some(raison))` s'il n'a pas
/// pu etre mesure, `Err` si quelque chose a casse. Jamais un succes par defaut.
fn eprouver_handshake() -> anyhow::Result<Option<String>> {
    let nt_a = WireGuardNt::load().map_err(anyhow::Error::msg)?;
    let nt_b = WireGuardNt::load().map_err(anyhow::Error::msg)?;

    let serveur = Adapter::create_with_guid(nt_a, SRV_NAME, &adapter::SELFTEST_GUID)
        .map_err(anyhow::Error::msg)
        .context("adaptateur serveur")?;
    let client = Adapter::create_with_guid(nt_b, CLI_NAME, &adapter::SELFTEST_PEER_GUID)
        .map_err(anyhow::Error::msg)
        .context("adaptateur client")?;

    // Premiere passe: on pose les cles privees avec un pair factice, puis on
    // relit les cles publiques que le driver en a derivees. C'est lui qui fait
    // le Curve25519, pas nous.
    let pub_srv = cle_publique_derivee(&serveur, &paire(SRV)?)?;
    let pub_cli = cle_publique_derivee(&client, &paire(CLI)?)?;
    // Des cles publiques: rien de secret a les afficher, et elles disent tout
    // de suite si les deux adaptateurs ont bien des identites distinctes.
    println!("  cle publique serveur: {}", pub_srv.as_str());
    println!("  cle publique client:  {}", pub_cli.as_str());
    if pub_srv == pub_cli {
        bail!("les deux adaptateurs derivent la meme cle publique: ce n'est pas deux pairs");
    }

    // Seconde passe: chacun prend l'autre pour pair. REPLACE_PEERS remplace le
    // pair factice de la premiere passe.
    let cfg_srv = duo(SRV, &pub_cli, None, SRV_ADDR, CLI_ADDR)?;
    let cfg_cli = duo(
        CLI,
        &pub_srv,
        Some(format!("127.0.0.1:{LISTEN_PORT}").parse()?),
        CLI_ADDR,
        SRV_ADDR,
    )?;
    serveur
        .set_configuration(&blob::encode(&cfg_srv).map_err(anyhow::Error::msg)?)
        .map_err(anyhow::Error::msg)?;
    client
        .set_configuration(&blob::encode(&cfg_cli).map_err(anyhow::Error::msg)?)
        .map_err(anyhow::Error::msg)?;

    // Le pair est-il en place AVANT l'activation? Sans cette mesure, un pair
    // absent plus loin ne dit pas s'il a ete refuse a la configuration ou perdu
    // a l'activation. Ce sont deux causes tres differentes.
    for (nom, adapter) in [("serveur", &serveur), ("client", &client)] {
        match etat_pair(adapter)? {
            Some(p) => println!(
                "  {nom} avant activation: 1 pair, endpoint {:?}",
                p.endpoint
            ),
            None => bail!(
                "le {nom} n'a aucun pair juste apres sa configuration: le driver \
                 l'a refuse sans le dire"
            ),
        }
    }

    serveur
        .set_state(true)
        .map_err(anyhow::Error::msg)
        .with_context(|| format!("activation du serveur, port {LISTEN_PORT}"))?;
    client
        .set_state(true)
        .map_err(anyhow::Error::msg)
        .with_context(|| format!("activation du client, port {CLIENT_PORT}"))?;
    ipcfg::apply(serveur.luid(), &cfg_srv).map_err(anyhow::Error::msg)?;
    ipcfg::apply(client.luid(), &cfg_cli).map_err(anyhow::Error::msg)?;
    println!("  les deux adaptateurs sont actifs, endpoint 127.0.0.1:{LISTEN_PORT}");

    // Le keepalive du client declenche l'initiation. On attend qu'un handshake
    // apparaisse des DEUX cotes: un seul cote pourrait n'etre qu'une tentative.
    let mut atteint = None;
    let mut dernier = (None, None);
    for _ in 0..(DELAI_HANDSHAKE.as_millis() / PAS.as_millis()) {
        let c = etat_pair(&client)?;
        let s = etat_pair(&serveur)?;
        if let (Some(pc), Some(ps)) = (&c, &s)
            && pc.last_handshake.is_some()
            && ps.last_handshake.is_some()
        {
            atteint = Some((pc.clone(), ps.clone()));
            break;
        }
        dernier = (c, s);
        std::thread::sleep(PAS);
    }

    let resultat = match atteint {
        Some((pc, ps)) => {
            println!(
                "  client:  {} octets emis, {} recus",
                pc.tx_bytes, pc.rx_bytes
            );
            println!(
                "  serveur: {} octets emis, {} recus",
                ps.tx_bytes, ps.rx_bytes
            );
            if pc.tx_bytes == 0 || ps.rx_bytes == 0 {
                Some(
                    "handshake date mais aucun octet compte: les compteurs ne \
                     sont pas lus au bon endroit"
                        .to_owned(),
                )
            } else {
                None
            }
        }
        // Distinguer les deux causes possibles: un adaptateur qui a perdu son
        // pair est un tout autre probleme qu'un handshake qui n'aboutit pas.
        None => match dernier {
            (None, _) => Some("le client ne porte aucun pair apres activation".to_owned()),
            (_, None) => Some("le serveur ne porte aucun pair apres activation".to_owned()),
            (Some(pc), Some(ps)) => Some(format!(
                "aucun handshake des deux cotes en {DELAI_HANDSHAKE:?} \
                 (client: {:?}, serveur: {:?}, {} octets emis par le client). \
                 WireGuardNT refuse peut-etre un endpoint en boucle locale; \
                 l'epreuve ne conclut alors rien sur le transport",
                pc.last_handshake, ps.last_handshake, pc.tx_bytes
            )),
        },
    };

    // Demontage complet, quel que soit le resultat.
    let _ = ipcfg::remove(client.luid(), &cfg_cli);
    let _ = ipcfg::remove(serveur.luid(), &cfg_srv);
    let _ = client.set_state(false);
    let _ = serveur.set_state(false);
    drop(client);
    drop(serveur);
    println!("  les deux adaptateurs sont retires");

    Ok(resultat)
}

/// Pose une configuration minimale et relit la cle publique que le driver a
/// derivee de la cle privee.
fn cle_publique_derivee(adapter: &Adapter, cfg: &TunnelConfig) -> anyhow::Result<WgKey> {
    adapter
        .set_configuration(&blob::encode(cfg).map_err(anyhow::Error::msg)?)
        .map_err(anyhow::Error::msg)?;
    let relu = adapter
        .get_configuration()
        .map_err(anyhow::Error::msg)
        .context("relecture pour la cle publique")?;
    let vu = blob::decode(&relu).map_err(anyhow::Error::msg)?;
    if vu.interface_public_key == [0u8; 32] {
        bail!(
            "le driver n'a pas derive de cle publique, ou elle n'est pas relue \
             au bon offset"
        );
    }
    Ok(WgKey::from_bytes(&vu.interface_public_key))
}

/// Etat du pair d'un adaptateur.
///
/// `None` veut dire que l'adaptateur ne porte aucun pair, ce qui est un
/// diagnostic en soi et non une erreur de lecture.
fn etat_pair(adapter: &Adapter) -> anyhow::Result<Option<blob::PeerReadBack>> {
    let relu = adapter.get_configuration().map_err(anyhow::Error::msg)?;
    Ok(blob::decode(&relu).map_err(anyhow::Error::msg)?.peer)
}

/// Configuration a un pair factice, juste pour poser la cle privee.
fn paire(privee: &str) -> anyhow::Result<TunnelConfig> {
    duo(
        privee,
        &parse(CLE_PUBLIQUE_FACTICE)?,
        None,
        SRV_ADDR,
        CLI_ADDR,
    )
}

/// Configuration d'un des deux cotes de l'epreuve.
///
/// Le port d'ecoute est choisi d'apres le COTE, jamais d'apres la presence
/// d'un endpoint. Les deux configurations du premier passage n'en ont pas: le
/// deduire de la aurait fait reclamer le meme port aux deux adaptateurs, et
/// le second refuse alors de s'activer avec un partage refuse.
fn duo(
    privee: &str,
    pair: &WgKey,
    endpoint: Option<std::net::SocketAddr>,
    adresse: &str,
    autorise: &str,
) -> anyhow::Result<TunnelConfig> {
    let serveur = privee == SRV;
    let cfg = TunnelConfig {
        interface: if serveur { SRV_NAME } else { CLI_NAME }.into(),
        addresses: vec![adresse.parse().map_err(anyhow::Error::msg)?],
        mtu: 1420,
        dns: DnsPolicy {
            local_resolver: IpAddr::V4(Ipv4Addr::LOCALHOST),
            upstream: vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))],
            embarque: false,
            anti_telemetrie: bifrost_core::config::ProfilTelemetrie::Aucun,
        },
        allow_lan: false,
        portage: bifrost_core::config::Portage::Wireguard(Box::new(
            bifrost_core::config::WireguardParams {
                private_key: parse(privee)?,
                fwmark: 0xca6c,
                routing_table: 51820,
                listen_port: Some(if serveur { LISTEN_PORT } else { CLIENT_PORT }),
                peer: PeerConfig {
                    public_key: pair.clone(),
                    preshared_key: None,
                    endpoint: Endpoint {
                        // Le cote serveur n'a pas d'endpoint a joindre: il attend. Le
                        // champ est obligatoire dans `TunnelConfig`, on y met une
                        // adresse de documentation qui ne sera jamais contactee, le
                        // client venant a lui.
                        addr: endpoint.unwrap_or("203.0.113.7:51820".parse()?),
                    },
                    allowed_ips: vec![autorise.parse().map_err(anyhow::Error::msg)?],
                    persistent_keepalive: 5,
                },
            },
        )),
    };
    cfg.validate().map_err(anyhow::Error::msg)?;
    Ok(cfg)
}

fn configuration_d_essai() -> anyhow::Result<TunnelConfig> {
    let cfg = TunnelConfig {
        interface: ADAPTER_NAME.into(),
        addresses: vec!["10.2.0.2/32".parse().map_err(anyhow::Error::msg)?],
        mtu: 1420,
        dns: DnsPolicy {
            local_resolver: IpAddr::V4(Ipv4Addr::LOCALHOST),
            upstream: vec![IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))],
            embarque: false,
            anti_telemetrie: bifrost_core::config::ProfilTelemetrie::Aucun,
        },
        allow_lan: false,
        portage: bifrost_core::config::Portage::Wireguard(Box::new(
            bifrost_core::config::WireguardParams {
                private_key: parse(CLE_PRIVEE_FACTICE)?,
                fwmark: 0xca6c,
                routing_table: 51820,
                listen_port: None,
                peer: PeerConfig {
                    public_key: parse(CLE_PUBLIQUE_FACTICE)?,
                    preshared_key: None,
                    // RFC 5737: rien ne s'y trouve, donc aucun paquet ne part vers un
                    // hote reel meme si l'adaptateur etait active plus longtemps.
                    endpoint: Endpoint {
                        addr: "203.0.113.7:51820".parse()?,
                    },
                    // Plusieurs prefixes, des deux familles: c'est la ou une erreur de
                    // pas entre deux structures se verrait.
                    //
                    // AUCUNE route par defaut, et ce n'est pas negociable: l'autotest
                    // pose ces prefixes comme vraies routes. Un `0.0.0.0/0` ici
                    // detournerait tout le trafic de la machine vers un tunnel qui ne
                    // transporte rien. Le cas `/0` est couvert par les tests purs de
                    // `routes`, qui n'appellent pas le systeme. Un garde-fou le
                    // reverifie avant la pose.
                    allowed_ips: vec![
                        "203.0.113.0/24".parse().map_err(anyhow::Error::msg)?,
                        "2001:db8::/32".parse().map_err(anyhow::Error::msg)?,
                        "10.0.0.0/8".parse().map_err(anyhow::Error::msg)?,
                    ],
                    persistent_keepalive: 25,
                },
            },
        )),
    };
    cfg.validate().map_err(anyhow::Error::msg)?;
    Ok(cfg)
}

fn parse(s: &str) -> anyhow::Result<WgKey> {
    s.parse::<WgKey>().map_err(anyhow::Error::msg)
}
