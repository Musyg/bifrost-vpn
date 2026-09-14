//! Autotest du cycle de vie des objets WFP.
//!
//! Il pose le jeu de filtres, verifie qu'ils apparaissent dans
//! `netsh wfp show filters`, refait un armement par-dessus (ce que la machine a
//! etats fait a chaque connexion), puis retire tout et verifie qu'il ne reste
//! rien. Il finit par la sonde d'identite de [`crate::wfp_identity`], seule
//! mesure du fait que le permit du daemon le designe reellement.
//!
//! Deux modes, et la difference n'est pas cosmetique.
//!
//! - **Par defaut**, tous les blocages du kill switch sont convertis en
//!   autorisations. Le nombre d'objets, leurs layers, leurs poids et leurs
//!   conditions sont identiques au plan reel, donc le chemin de creation et de
//!   suppression est le meme, mais **aucun trafic de la machine n'est coupe**.
//!   Le seul blocage pose au cours de l'autotest est celui de la sonde
//!   d'identite, restreint a une adresse de documentation RFC 5737 vers
//!   laquelle rien ne circule. C'est sans danger sur une machine de travail.
//!   Ca ne dit rien de l'etancheite generale.
//! - **Avec `--wfp-selftest-blocking`**, le vrai plan est pose. La machine perd
//!   tout reseau pendant l'operation: le block-all n'autorise que ce binaire.
//!   A reserver a une machine dediee dont on ne depend pas a distance.
//!
//! L'existence du mode par defaut vient d'un incident: le mode bloquant a
//! laisse un poste de travail sans reseau jusqu'au redemarrage, parce que le
//! desarmement echouait. Eprouver le cycle de vie ne demande pas de couper le
//! reseau, et le faire quand meme etait une erreur de conception du test.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, bail};
use bifrost_core::ports::{FirewallPolicy, KillSwitch};

use crate::wfp_identity::Issue;

/// Au-dela de ce delai, le chien de garde reprend la main.
const WATCHDOG: Duration = Duration::from_secs(30);
/// Echeance de chaque appel a netsh.
const NETSH_DEADLINE: Duration = Duration::from_secs(15);

pub fn run(blocking: bool, cible_fuite: Option<SocketAddr>) -> anyhow::Result<()> {
    run_avec_lan(blocking, cible_fuite, false)
}

/// Le meme, en choisissant si le reseau local reste ouvert.
///
/// `lan` a une raison d'etre precise, et elle vaut d'etre ecrite. Le mode
/// bloquant coupe TOUT le reseau de la machine qui l'execute, ce qui interdit
/// de le lancer sur une machine pilotee a distance: un essai a deja coute un
/// redemarrage. Avec `lan`, la politique ouvre les prefixes prives, donc une
/// session d'administration passant par le RESEAU LOCAL survit a l'armement,
/// alors que tout le reste - Internet, et notamment un reseau overlay dont le
/// transport sort vers des endpoints publics - reste coupe.
///
/// Ce que cela affaiblit, et qu'il ne faut pas se cacher: le block-all n'est
/// plus total, le trafic local passe. Ce n'est pas un contournement de la
/// mesure, c'est la politique reelle du produit quand l'utilisateur demande le
/// partage local. Pour eprouver le blocage TOTAL, il faut une machine avec un
/// acces console.
pub fn run_avec_lan(
    blocking: bool,
    cible_fuite: Option<SocketAddr>,
    lan: bool,
) -> anyhow::Result<()> {
    if blocking {
        eprintln!(
            "AVERTISSEMENT: mode bloquant. Cet autotest coupe tout le reseau de \
             cette machine pendant l'operation. Ne pas le lancer sur une machine \
             pilotee a distance, ni sur un poste de travail."
        );
        // Le chien de garde n'a de sens que dans ce mode: c'est le seul ou un
        // blocage laisserait la machine coupee.
        std::thread::spawn(watchdog);
    } else {
        eprintln!(
            "mode sans blocage: les objets WFP sont poses puis retires sans \
             couper le reseau. Seule la sonde d'identite pose un blocage, \
             restreint a une adresse de documentation. Utiliser \
             --wfp-selftest-blocking sur une machine dediee pour eprouver \
             l'etancheite generale."
        );
    }

    let mut firewall = bifrost_firewall::windows::WfpKillSwitch::new()
        .map_err(|e| anyhow::anyhow!("ouverture du moteur WFP: {e}"))?;
    let policy = FirewallPolicy {
        tunnel_interface: None,
        tunnel_luid: None,
        fwmark: None,
        dns_resolver: IpAddr::V4(Ipv4Addr::LOCALHOST),
        allow_lan: lan,
        // L'autotest n'eprouve que le cycle de vie des objets WFP: aucun coeur
        // ne tourne, donc aucune exemption a poser, et aucun resolveur
        // embarque, donc aucune restriction du :53 a mesurer ici.
        coeur_uid: None,
        coeur_executable: None,
        resolveur_uid: None,
        resolveur_executable: None,
        resolveur_sid: None,
        resolveur_embarque: false,
    };

    let avant = inventaire("avant")?;
    println!("filtres Bifrost avant armement: {}", avant.total);

    println!("armement...");
    let poses = engage(&mut firewall, &policy, blocking).context("armement")?;
    let arme = inventaire("arme");

    // Reengagement. La machine a etats appelle `engage` deux fois par
    // connexion: une fois avant de monter le tunnel, une fois quand l'interface
    // existe. Le second passage commence par remettre le moteur a plat, et
    // c'est exactement la que le bug de suppression frappait.
    println!("reengagement par-dessus...");
    let reengage = engage(&mut firewall, &policy, blocking);
    let apres_reengage = inventaire("reengage");

    let engage_confirme = firewall.is_engaged();

    println!("desarmement...");
    let desarmement = firewall.disengage();
    let apres = inventaire("apres");

    // Analyse seulement une fois le reseau rendu.
    reengage.context("reengagement")?;
    desarmement.context("desarmement")?;
    let arme = arme.context("inventaire pendant l'armement")?;
    let apres_reengage = apres_reengage.context("inventaire apres reengagement")?;
    let apres = apres.context("inventaire apres desarmement")?;

    match poses {
        Some(n) => println!("filtres au plan:         {n}"),
        None => println!("filtres au plan:         non rapporte par le chemin bloquant"),
    }
    println!("filtres vus armes:       {}", arme.total);
    println!("catch-all present:       {}", arme.block_all);
    println!("filtres apres reengage:  {}", apres_reengage.total);
    println!("is_engaged pendant:      {engage_confirme:?}");
    println!("filtres apres desarmement: {}", apres.total);

    let mut echecs = Vec::new();
    if arme.total == 0 {
        echecs.push("aucun filtre Bifrost visible dans netsh pendant l'armement".to_owned());
    }
    if !arme.block_all {
        echecs.push("le filtre catch-all n'apparait pas dans netsh".to_owned());
    }
    if apres_reengage.total != arme.total {
        echecs.push(format!(
            "le reengagement a change le nombre de filtres: {} puis {}",
            arme.total, apres_reengage.total
        ));
    }
    if !engage_confirme.as_ref().copied().unwrap_or(false) {
        echecs.push("is_engaged n'a pas confirme l'armement".to_owned());
    }
    if apres.total != 0 {
        echecs.push(format!(
            "{} filtre(s) Bifrost survivent au desarmement",
            apres.total
        ));
    }

    // Le cycle de vie ne dit rien du matching. La sonde d'identite, elle, pose
    // un vrai blocage, mais restreint a une adresse sans trafic reel.
    println!("\nsonde d'identite du filtre du daemon...");
    match crate::wfp_identity::run(&mut firewall)? {
        Issue::Reussi => {
            println!("  le daemon matche son permit, le temoin est bloque")
        }
        Issue::Ignore(raison) => println!("  SKIPPED: {raison}"),
        Issue::Echec(raison) => echecs.push(raison),
    }

    // Et le cycle de vie ne dit rien non plus du blocage. Poser les objets, les
    // reposer et les retirer proprement ne repond pas a la seule question qui
    // interesse un utilisateur: le trafic est-il retenu? Cette mesure y repond,
    // ou declare pourquoi elle n'a pas pu.
    println!("\nmesure d'etancheite...");
    let etancheite = match (blocking, cible_fuite) {
        (true, Some(cible)) => crate::wfp_leaktest::run(&mut firewall, &policy, cible)?,
        (true, None) => Issue::Ignore(
            "aucune cible fournie. Ajouter --leak-target <ADDR:PORT>, vers une \
             adresse qui accepte une connexion TCP depuis cette machine. Sans \
             elle, cet autotest pose les filtres sans jamais verifier qu'ils \
             retiennent quoi que ce soit."
                .to_owned(),
        ),
        (false, _) => Issue::Ignore(
            "le mode sans blocage convertit tous les blocages en autorisations: \
             il n'y a rien a retenir, donc rien a mesurer. Passer par \
             --wfp-selftest-blocking sur une machine dediee."
                .to_owned(),
        ),
    };
    let etancheite_mesuree = matches!(etancheite, Issue::Reussi);
    match etancheite {
        Issue::Reussi => println!(
            "  le trafic passe au repos, est refuse sous armement, et repasse \
             apres desarmement"
        ),
        Issue::Ignore(raison) => println!("  SKIPPED: {raison}"),
        Issue::Echec(raison) => echecs.push(raison),
    }

    if echecs.is_empty() {
        // L'etancheite figure dans le resume meme quand elle n'a pas eu lieu.
        // Un autotest qui se conclut par une ligne de succes sans dire ce qu'il
        // n'a pas mesure se relit comme une garantie qu'il n'apporte pas.
        println!(
            "\nautotest WFP ({}): objets poses, reengagement idempotent, \
             retrait complet, identite du daemon verifiee, etancheite {}",
            if blocking { "bloquant" } else { "sans blocage" },
            if etancheite_mesuree {
                "mesuree"
            } else {
                "NON mesuree"
            }
        );
        Ok(())
    } else {
        for e in &echecs {
            eprintln!("ECHEC: {e}");
        }
        bail!("{} verification(s) en echec", echecs.len())
    }
}

/// `None` en mode bloquant: ce chemin ne rend aucun compte de filtres. Rendre
/// zero, ce qu'il faisait, affichait "filtres au plan: 0" a cote de vingt-deux
/// filtres bien reels. Un zero se relit un jour comme un filtre manquant, et
/// aucune assertion ne portait dessus pour dementir.
fn engage(
    firewall: &mut bifrost_firewall::windows::WfpKillSwitch,
    policy: &FirewallPolicy,
    blocking: bool,
) -> anyhow::Result<Option<usize>> {
    if blocking {
        firewall
            .engage(policy)
            .map_err(|e| anyhow::anyhow!("{e}"))
            .map(|()| None)
    } else {
        firewall
            .engage_without_blocking(policy)
            .map_err(|e| anyhow::anyhow!("{e}"))
            .map(Some)
    }
}

/// Dernier recours du mode bloquant: si le corps de l'autotest fige alors que
/// les filtres sont poses, la machine reste sans reseau.
fn watchdog() {
    std::thread::sleep(WATCHDOG);
    eprintln!("chien de garde: reprise apres {WATCHDOG:?}");
    for tentative in 1..=3 {
        match bifrost_firewall::new().and_then(|mut fw| fw.disengage()) {
            Ok(()) => {
                eprintln!("chien de garde: kill switch desarme");
                std::process::exit(2);
            }
            Err(e) => eprintln!("chien de garde: tentative {tentative} en echec: {e}"),
        }
        std::thread::sleep(Duration::from_secs(2));
    }
    eprintln!(
        "chien de garde: desarmement impossible. Le trafic reste bloque. \
         Lancer 'bifrost-daemon --cleanup-firewall', ou redemarrer: les filtres \
         ne sont pas persistants."
    );
    std::process::exit(3);
}

struct Inventaire {
    total: usize,
    block_all: bool,
}

/// Interroge `netsh wfp show filters` et compte les filtres de Bifrost.
///
/// Les filtres sont reconnus a leur description, que le kill switch prefixe
/// systematiquement par "Bifrost: ". Passer par le GUID du provider
/// demanderait de le resoudre dans un XML de plusieurs megaoctets.
fn inventaire(etiquette: &str) -> anyhow::Result<Inventaire> {
    let chemin: PathBuf = std::env::temp_dir().join(format!(
        "bifrost-wfp-{etiquette}-{}.xml",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&chemin);

    run_with_deadline(
        Command::new("netsh").args([
            "wfp",
            "show",
            "filters",
            &format!("file={}", chemin.display()),
        ]),
        NETSH_DEADLINE,
    )
    .context("netsh wfp show filters")?;

    let brut =
        std::fs::read(&chemin).with_context(|| format!("lecture de {}", chemin.display()))?;
    let xml = String::from_utf8_lossy(&brut);
    let inv = Inventaire {
        total: xml.matches("Bifrost: ").count(),
        block_all: xml.contains("block-all ("),
    };
    let _ = std::fs::remove_file(&chemin);
    Ok(inv)
}

/// Lance une commande et la tue si elle depasse l'echeance.
///
/// `std::process` n'offre pas d'attente bornee. Sans cette boucle, un outil qui
/// detient le verrou WFP fige l'autotest, le reseau coupe en mode bloquant.
fn run_with_deadline(command: &mut Command, deadline: Duration) -> anyhow::Result<()> {
    let mut child = command
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .context("lancement")?;

    let debut = Instant::now();
    loop {
        match child.try_wait().context("attente")? {
            Some(status) if status.success() => return Ok(()),
            Some(status) => bail!("code de sortie {status}"),
            None => {}
        }
        if debut.elapsed() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            bail!("depassement de l'echeance de {deadline:?}");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}
