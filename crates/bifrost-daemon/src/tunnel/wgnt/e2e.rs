//! Recette de bout en bout du transport Windows, contre un serveur distant.
//!
//! L'autotest local etablit qu'un handshake se produit entre deux adaptateurs
//! de la meme machine. Il ne peut rien dire du CHEMIN DE DONNEES: les deux
//! adresses etant locales, Windows n'a aucune raison de faire passer le trafic
//! par le tunnel. Seul un pair distant permet de le verifier.
//!
//! La recette monte le tunnel par le vrai chemin du produit,
//! [`crate::tunnel::windows::WindowsTunnel::up`], attend un handshake, puis
//! ouvre une connexion TCP vers une adresse qui n'est joignable QUE par le
//! tunnel et compare la banniere recue. Une banniere identique ne peut venir
//! que de l'autre bout, donc le trafic a traverse.
//!
//! **Ce qu'elle n'arme pas: le kill switch.** Le kill switch pose un block-all
//! qui coupe tout ce qui ne sort pas par le tunnel. Sur une machine de travail,
//! l'armer reviendrait a la couper du reseau, ce qui est le comportement voulu
//! du produit mais pas ce qu'on mesure ici. La recette se limite au transport
//! et au routage.
//!
//! **Elle refuse une configuration a route par defaut**, pour la meme raison:
//! detourner tout le trafic de la machine vers un tunnel qu'on est en train
//! d'eprouver n'est pas une mesure, c'est un pari.

use std::io::Read;
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Context, bail};
use bifrost_core::TunnelConfig;
use bifrost_core::ports::TunnelDevice;

use crate::tunnel::windows::WindowsTunnel;

use super::{ipcfg, routes};

/// Ce que le pair distant doit renvoyer. Une chaine choisie plutot qu'un simple
/// "la connexion s'ouvre": un port ouvert par hasard sur un autre chemin
/// donnerait une connexion, pas cette banniere.
pub const BANNIERE: &str = "BIFROST-E2E-OK";

/// Marge d'attente du handshake. Un aller-retour WireGuard sur un reseau local
/// est immediat; cette marge couvre la creation de l'interface.
const DELAI_HANDSHAKE: Duration = Duration::from_secs(20);
const PAS: Duration = Duration::from_millis(500);
/// La sonde ne doit pas pendre si le chemin de donnees ne passe pas.
const DELAI_SONDE: Duration = Duration::from_secs(5);

/// Les parametres WireGuard d'un profil, ou une erreur qui dit ce qui porte a
/// la place. Cette recette ne monte que du WireGuard: le dire vaut mieux que
/// de le supposer, maintenant qu'un profil peut decrire un coeur.
fn parametres(cfg: &TunnelConfig) -> anyhow::Result<&bifrost_core::config::WireguardParams> {
    cfg.wireguard().map_err(|e| anyhow::anyhow!("{e}"))
}

pub fn run(
    profil: &Path,
    cible: SocketAddr,
    accepte_par_defaut: bool,
    temoin_public: Option<SocketAddr>,
    bouclage: bool,
) -> anyhow::Result<()> {
    let cfg = charger(profil, accepte_par_defaut)?;
    println!("profil {} charge", profil.display());
    println!("  interface {}", cfg.interface);
    println!("  endpoint  {}", parametres(&cfg)?.peer.endpoint);
    println!("  cible de la sonde {cible}");
    if routes::contient_route_par_defaut(&routes::routes_for(&cfg)) {
        // Annonce AVANT la montee: l'operateur doit pouvoir interrompre tant
        // que la machine a encore son reseau.
        println!(
            "  ROUTE PAR DEFAUT: cette machine perd son acces reseau pendant la mesure. Tuer le processus la retablit, l'adaptateur lui appartient."
        );
    }

    let mut tunnel = WindowsTunnel::new().map_err(anyhow::Error::msg)?;

    println!("montee du tunnel...");
    tunnel
        .up(&cfg)
        .map_err(anyhow::Error::msg)
        .context("montee du tunnel")?;
    println!("  LUID {:#x}", tunnel.luid().unwrap_or(0));

    // La route de bouclage est posee APRES la montee, sur l'interface deja
    // adressee: Windows refuse une route vers une interface sans adresse. Elle
    // disparait avec l'adaptateur, comme les autres.
    if bouclage {
        let luid = tunnel.luid().unwrap_or(0);
        let route = routes::route_bouclage(parametres(&cfg)?.peer.endpoint.addr.ip());
        if let Err(e) = ipcfg::add_route(luid, &route) {
            let _ = tunnel.down(&cfg);
            return Err(anyhow::Error::msg(e)).context("pose de la route de bouclage");
        }
        println!(
            "  route de bouclage {} posee SUR LE TUNNEL: la table affirme desormais que l'endpoint se joint par le tunnel lui-meme",
            route.dest
        );
    }

    // Tout ce qui suit doit s'executer meme en cas d'echec: un tunnel laisse
    // monte detournerait le trafic vers sa cible bien apres la fin du test.
    let resultat = mesurer(&tunnel, &cfg, cible, temoin_public, bouclage);

    println!("demontage du tunnel...");
    let demontage = tunnel.down(&cfg).map_err(anyhow::Error::msg);
    println!("  interface retiree");

    let echecs = resultat?;
    demontage.context("demontage du tunnel")?;

    if echecs.is_empty() {
        println!("\nrecette de bout en bout: handshake obtenu et chemin de donnees confirme.");
        Ok(())
    } else {
        for e in &echecs {
            eprintln!("ECHEC: {e}");
        }
        bail!("{} verification(s) en echec", echecs.len())
    }
}

fn mesurer(
    tunnel: &WindowsTunnel,
    cfg: &TunnelConfig,
    cible: SocketAddr,
    temoin_public: Option<SocketAddr>,
    bouclage: bool,
) -> anyhow::Result<Vec<String>> {
    let mut echecs = Vec::new();

    // Etat reel de la configuration IP. "L'appel a reussi" et "l'adresse est
    // utilisable" sont deux choses differentes: une adresse restee Tentative
    // figure dans la table sans pouvoir servir de source.
    let luid = tunnel.luid().unwrap_or(0);
    for net in &cfg.addresses {
        println!(
            "  adresse {net}: presente={} dad={:?}",
            ipcfg::address_exists(luid, net),
            ipcfg::address_dad_state(luid, net)
        );
    }
    for r in routes::routes_for(cfg) {
        println!(
            "  route {}: presente={}",
            r.dest,
            ipcfg::route_exists(luid, &r)
        );
    }

    // Quelle interface Windows choisit-il pour joindre l'endpoint? Si c'est le
    // tunnel lui-meme, alors la table de routage renvoie le transport de
    // WireGuardNT dans son propre tunnel: un handshake obtenu malgre ca etablit
    // que le driver exclut ses propres paquets du routage. Si c'est une autre
    // interface, la question n'est pas posee et le resultat ne prouve rien.
    let vers_endpoint = ipcfg::best_route_interface(parametres(cfg)?.peer.endpoint.addr.ip());
    let dans_le_tunnel = vers_endpoint == Some(luid);
    println!(
        "  route choisie vers l'endpoint: LUID {:?} ({})",
        vers_endpoint.map(|l| format!("{l:#x}")),
        if dans_le_tunnel {
            "LE TUNNEL, condition de bouclage reunie"
        } else {
            "hors tunnel, pas de bouclage a eprouver"
        }
    );

    // Une condition demandee mais non reunie rendrait le resultat muet: le
    // handshake reussirait pour la raison ordinaire, et on lirait cette
    // reussite comme une preuve d'exclusion. Mieux vaut echouer bruyamment.
    if bouclage && !dans_le_tunnel {
        echecs.push(format!(
            "la route de bouclage est posee, mais Windows ne choisit PAS le tunnel pour joindre {}: la condition n'est pas reunie, et un handshake reussi ne prouverait rien",
            parametres(cfg)?.peer.endpoint
        ));
    }

    // Ce que la route par defaut ajoute, et qu'aucun profil restreint ne
    // pouvait eprouver: une destination publique QUELCONQUE sort desormais
    // par le tunnel. Sans elle, la recette dirait seulement que la route est
    // dans la table, pas que Windows la choisit.
    if routes::contient_route_par_defaut(&routes::routes_for(cfg)) {
        let temoin = IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1));
        let via = ipcfg::best_route_interface(temoin);
        println!(
            "  route choisie vers {temoin}: LUID {:?}",
            via.map(|l| format!("{l:#x}"))
        );
        if via != Some(luid) {
            echecs.push(format!(
                "la route par defaut est posee, mais {temoin} ne sort PAS par le tunnel: Windows a choisi {via:?} au lieu de {luid:#x}. Le trafic continuerait de partir en clair"
            ));
        }
    }

    let debut = Instant::now();
    let mut vu = None;
    while debut.elapsed() < DELAI_HANDSHAKE {
        match tunnel.handshake(cfg).map_err(anyhow::Error::msg)? {
            Some(h) if h.last_handshake.is_some() => {
                vu = Some(h);
                break;
            }
            _ => std::thread::sleep(PAS),
        }
    }
    let Some(h) = vu else {
        echecs.push(format!(
            "aucun handshake en {DELAI_HANDSHAKE:?}. Le pair distant est-il \
             joignable a {}, et sa cle publique est-elle la bonne?",
            parametres(cfg)?.peer.endpoint
        ));
        return Ok(echecs);
    };
    println!(
        "  handshake obtenu apres {:?} ({} octets emis, {} recus)",
        debut.elapsed(),
        h.tx_bytes,
        h.rx_bytes
    );

    println!("sonde du chemin de donnees vers {cible}...");
    match sonder(cible) {
        Ok(recu) if recu == BANNIERE => println!("  banniere '{recu}' recue"),
        Ok(recu) => echecs.push(format!(
            "banniere inattendue '{recu}': quelque chose repond a {cible}, mais \
             ce n'est pas le pair du tunnel"
        )),
        Err(e) => echecs.push(format!("le chemin de donnees ne passe pas: {e:#}")),
    }

    // Temoin du vecteur `exit-ip`: une destination PUBLIQUE tentee pendant que
    // le tunnel porte la route par defaut. Son resultat n'est pas juge ici, et
    // c'est voulu - le pair d'essai ne route pas vers l'exterieur, donc elle
    // n'aboutira pas. Ce qui compte est ce que la capture voit sur le fil: si
    // le routage etait faux, un SYN en CLAIR vers cette adresse y apparaitrait.
    // C'est la promesse d'un VPN, et aucune sonde vers une adresse du tunnel ne
    // peut l'etablir.
    if let Some(t) = temoin_public {
        println!("  temoin public {t}, tente sans etre juge: la capture tranche");
        let _ = TcpStream::connect_timeout(&t, DELAI_SONDE);
    }

    // Les compteurs doivent avoir bouge entre le handshake et maintenant. Un
    // handshake seul prouve le transport, pas le passage des donnees.
    if let Some(apres) = tunnel.handshake(cfg).map_err(anyhow::Error::msg)? {
        println!(
            "  compteurs apres la sonde: {} octets emis, {} recus",
            apres.tx_bytes, apres.rx_bytes
        );
        if apres.tx_bytes <= h.tx_bytes || apres.rx_bytes <= h.rx_bytes {
            echecs.push(format!(
                "les compteurs n'ont pas bouge pendant la sonde ({} puis {} \
                 emis): si la banniere est arrivee, elle n'est pas passee par \
                 le tunnel",
                h.tx_bytes, apres.tx_bytes
            ));
        }
    }

    Ok(echecs)
}

fn sonder(cible: SocketAddr) -> anyhow::Result<String> {
    let mut flux = TcpStream::connect_timeout(&cible, DELAI_SONDE)
        .with_context(|| format!("connexion a {cible}"))?;
    flux.set_read_timeout(Some(DELAI_SONDE))?;
    let mut recu = String::new();
    flux.read_to_string(&mut recu).context("lecture")?;
    Ok(recu.trim().to_owned())
}

/// Motif de refus d'un profil a route par defaut, s'il y a lieu.
///
/// Le refus n'est pas une precaution de style: un `/0` pose REELLEMENT la route
/// par defaut de la machine vers le tunnel, et la recette tourne souvent sur un
/// poste de travail.
///
/// **Ce qui rend l'accord tenable**, et pourquoi aucune tache planifiee de
/// retrait n'est exigee ici contrairement au vecteur `startup-window`:
/// l'adaptateur WireGuardNT appartient au PROCESSUS. Sa fermeture le retire, et
/// avec lui toutes les routes qui le designent - y compris si le processus
/// panique, est tue, ou disparait. La machine revient a son etat d'origine sans
/// intervention, ce qui est une garantie plus forte qu'un filet planifie: ce
/// dernier suppose que le planificateur, lui, va bien. Le filtre de demarrage,
/// a l'inverse, SURVIT au redemarrage; d'ou deux exigences differentes.
pub(crate) fn refus_route_par_defaut(par_defaut: bool, accepte: bool) -> Option<String> {
    if !par_defaut || accepte {
        return None;
    }
    Some(
        "le profil contient une route par defaut. Refus: la recette detournerait tout le trafic de cette machine vers le pair, et lui ferait perdre son acces reseau le temps de la mesure. C'est pourtant la configuration du produit en usage reel. Sur une machine dediee, l'accepter avec `--wgnt-e2e-route-par-defaut`; sinon restreindre `allowed_ips`."
            .to_owned(),
    )
}

pub(crate) fn charger(profil: &Path, accepte_par_defaut: bool) -> anyhow::Result<TunnelConfig> {
    let brut = std::fs::read_to_string(profil)
        .with_context(|| format!("lecture de {}", profil.display()))?;
    let cfg: TunnelConfig =
        toml::from_str(&brut).with_context(|| format!("profil {} invalide", profil.display()))?;
    cfg.validate().map_err(anyhow::Error::msg)?;

    let par_defaut = routes::contient_route_par_defaut(&routes::routes_for(&cfg));
    if let Some(motif) = refus_route_par_defaut(par_defaut, accepte_par_defaut) {
        bail!(motif);
    }
    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn un_profil_a_route_par_defaut_est_refuse_sans_accord_explicite() {
        // Un `/0` pose REELLEMENT la route par defaut de la machine vers le
        // tunnel. La recette tourne souvent sur un poste de travail, ou ca se
        // paye par une perte de reseau immediate.
        let motif = refus_route_par_defaut(true, false).expect("doit refuser");
        assert!(motif.contains("route par defaut"), "{motif}");
        // Le message doit dire comment passer outre, sinon il envoie l'operateur
        // modifier son profil alors que c'est justement la configuration du
        // produit qu'on veut eprouver.
        assert!(motif.contains("--wgnt-e2e-route-par-defaut"), "{motif}");
    }

    #[test]
    fn l_accord_explicite_leve_le_refus_et_lui_seul() {
        assert!(refus_route_par_defaut(true, true).is_none());
        // Sans route par defaut, l'accord ne change rien: il n'autorise pas
        // autre chose au passage.
        assert!(refus_route_par_defaut(false, false).is_none());
        assert!(refus_route_par_defaut(false, true).is_none());
    }
}
