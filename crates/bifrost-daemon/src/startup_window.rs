//! Le vecteur `startup-window` sous Windows: la fenetre de fuite au demarrage.
//!
//! # Pourquoi ce vecteur est le seul en deux temps
//!
//! Les autres vecteurs arment, mesurent et desarment dans un seul processus. Ce
//! qui se mesure ici est ce qui vaut AVANT que le daemon existe: il faut donc
//! poser, redemarrer la machine, et constater depuis un processus qui n'a rien
//! arme. D'ou deux phases, `armer` et `constater`, separees par un reboot.
//!
//! # Ce que la phase `constater` etablit, et ce qu'elle n'etablit pas
//!
//! Elle etablit qu'apres un redemarrage, AVANT qu'aucun daemon Bifrost ne soit
//! lance, une connexion vers l'exterieur est refusee, que le refus est
//! imputable au filtre `demarrage block-all` nommement, et que le retrait
//! rouvre le trafic.
//!
//! Elle n'etablit PAS que la fenetre pre-BFE est couverte. Un processus en
//! espace utilisateur ne peut pas s'executer avant BFE: quand la sonde tourne,
//! c'est le filtre PERSISTANT qui bloque, pas le boot-time. Que le boot-time
//! soit bien enregistre la ou `tcpip.sys` le lit se mesure autrement, par
//! mutation dans le magasin `BFE\\Parameters\\Policy\\BootTime\\Filter`, et
//! c'est fait ailleurs. Les deux mesures se completent; aucune ne remplace
//! l'autre, et les confondre ferait croire la fenetre entiere couverte par une
//! seule.
//!
//! # Le danger propre a ce vecteur, et ce qui le contient
//!
//! Une erreur ici ne se repare pas par un redemarrage: le filtre SURVIT au
//! redemarrage, c'est tout son objet. Trois garde-fous, dont aucun n'est
//! optionnel:
//!
//! 1. `armer` REFUSE une politique sans reseau local. Sans elle, la machine
//!    revient injoignable et seule une console la recupere. Qui a une console
//!    peut toujours passer par `--demarrage poser`, qui ne pretend pas etre une
//!    mesure;
//! 2. `armer` refuse tant qu'une tache planifiee de retrait n'est pas
//!    enregistree. Elle doit se declencher AU DEMARRAGE, la seule condition qui
//!    se produise encore quand tout le reste a echoue;
//! 3. `armer` refuse si la cible ne repond deja pas: redemarrer une machine
//!    pour une mesure dont on sait qu'elle ne conclura rien est une coupure
//!    pour rien.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use anyhow::{Context, anyhow};
use bifrost_core::demarrage::PolitiqueDemarrage;
use bifrost_firewall::windows::WfpKillSwitch;

use crate::temoin_wfp;
use crate::wfp_identity::{Verdict, via_copie};

/// Le journal d'audit n'est pas ecrit dans la foulee de la connexion.
const FENETRE: Duration = Duration::from_secs(180);
/// Le filtre dont on attend qu'il refuse. C'est le catch-all du plan de
/// demarrage, seul blocage que ce plan comporte.
const FILTRE_ATTENDU: &str = "block-all";
/// Nom de la tache planifiee de retrait, exigee avant tout armement.
pub const TACHE_FILET: &str = "BifrostFiletDemarrage";

/// De quoi creer le filet. Un declencheur AU DEMARRAGE, pas une echeance:
/// c'est la seule condition qui se produise encore quand la machine est
/// injoignable et qu'il ne reste plus qu'a la redemarrer.
const HINT_FILET: &str = r#"  $t = New-ScheduledTaskTrigger -AtStartup
  $t.Delay = 'PT6M'
  Register-ScheduledTask -TaskName BifrostFiletDemarrage -Trigger $t `
    -Action (New-ScheduledTaskAction -Execute '<chemin>\bifrost-daemon.exe' `
      -Argument '--demarrage retirer') `
    -Principal (New-ScheduledTaskPrincipal -UserId SYSTEM `
      -LogonType ServiceAccount -RunLevel Highest)"#;

/// Ce que la mesure a conclu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Issue {
    Reussi,
    /// La mesure n'a pas pu conclure. Jamais un succes par defaut.
    Ignore(String),
    Echec(String),
}

/// Les trois mesures d'apres redemarrage, sans interpretation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mesures {
    /// Les filtres de demarrage vus dans le moteur, par leur nom.
    pub presents: Vec<String>,
    /// Vers la cible, avant tout retrait.
    pub arme: Verdict,
    /// Vers la cible, apres le retrait.
    pub apres: Verdict,
}

/// Pose le filtre et prepare la mesure. A lancer AVANT le redemarrage.
pub fn armer(cible: SocketAddr, politique: PolitiqueDemarrage) -> anyhow::Result<()> {
    if !politique.reseau_local {
        anyhow::bail!(
            "ce vecteur refuse une politique sans reseau local. Le filtre \
             SURVIT au redemarrage: sans exemption du reseau local, la machine \
             revient injoignable et aucun redemarrage ne la recupere. Ajouter \
             `--demarrage-reseau-local`, ou passer par `--demarrage poser` si \
             la machine a un acces console"
        );
    }
    filet_present()?;

    // Temoin negatif AVANT le redemarrage: une cible deja muette rendrait la
    // mesure d'apres reboot ininterpretable, et on aurait redemarre pour rien.
    let controle = via_copie(cible)?;
    println!("temoin negatif vers {cible}: {controle:?}");
    if controle != Verdict::Connecte {
        anyhow::bail!(
            "la cible {cible} n'aboutit pas ({controle:?}) alors que rien n'est \
             pose. Apres redemarrage son refus ne pourrait pas etre attribue au \
             filtre de demarrage. Choisir une cible qui accepte une connexion TCP"
        );
    }

    let ks = WfpKillSwitch::new().map_err(|e| anyhow!("ouverture du moteur WFP: {e}"))?;
    let n = ks
        .poser_demarrage(&politique)
        .map_err(|e| anyhow!("pose du filtre de demarrage: {e}"))?;
    marqueur_ecrire(cible)?;

    println!("filtre de demarrage pose: {n} filtres, reseau local ouvert");
    println!("filet `{TACHE_FILET}` en place, il retire au demarrage suivant");
    println!(
        "\nRedemarrer la machine, puis lancer:\n  \
         bifrost-daemon --startup-window constater"
    );
    Ok(())
}

/// Constate ce que le filtre retient. A lancer APRES le redemarrage.
pub fn constater() -> anyhow::Result<()> {
    let cible = marqueur_lire()?;
    println!("vecteur startup-window, cible {cible}");
    println!(
        "  la session qui lance cette commande est elle-meme le temoin du \
         reseau local: sans son exemption, elle n'aurait pas pu l'atteindre"
    );

    let ks = WfpKillSwitch::new().map_err(|e| anyhow!("ouverture du moteur WFP: {e}"))?;
    let vus = ks
        .filtres_demarrage_vus()
        .map_err(|e| anyhow!("enumeration des filtres de demarrage: {e}"))?;
    let attendus: Vec<u64> = vus
        .iter()
        .filter(|(nom, _)| nom.contains(FILTRE_ATTENDU))
        .map(|(_, id)| *id)
        .collect();
    println!(
        "  filtres de demarrage survivants: {}, dont {} nommes `{FILTRE_ATTENDU}`",
        vus.len(),
        attendus.len()
    );

    let arme = via_copie(cible)?;
    println!("  avant retrait: {arme:?}");

    // L'attribution se lit AVANT le retrait: le journal persiste, mais autant
    // interroger pendant que les identifiants designent encore quelque chose.
    let constat = if attendus.is_empty() {
        None
    } else {
        Some(attendre(&attendus, cible)?)
    };

    ks.retirer_demarrage()
        .map_err(|e| anyhow!("retrait du filtre de demarrage: {e}"))?;
    println!("  filtre de demarrage retire");

    let apres = via_copie(cible)?;
    println!("  apres retrait: {apres:?}");
    marqueur_effacer();

    let mesures = Mesures {
        presents: vus.into_iter().map(|(nom, _)| nom).collect(),
        arme,
        apres,
    };
    let issue = juger(&mesures, cible);

    if issue == Issue::Reussi {
        match constat {
            Some(c) if c.audit_muet() => println!(
                "  attribution impossible: aucun blocage WFP dans le journal, pas \
                 meme ceux du pare-feu Windows. A activer avec:\n{}",
                temoin_wfp::COMMANDE_ACTIVATION
            ),
            Some(c) => {
                println!(
                    "  journal d'audit: {} blocages WFP dans la fenetre, dont {} \
                     imputables a `{FILTRE_ATTENDU}`",
                    c.total,
                    c.notres.len()
                );
                match c.notres.first() {
                    Some(b) => println!(
                        "    filtre {} a la couche {}, application {}",
                        b.filtre,
                        b.couche,
                        b.application.rsplit('\\').next().unwrap_or("?")
                    ),
                    None => {
                        return Err(anyhow!(
                            "le refus vers {cible} n'est imputable a AUCUN filtre \
                             `{FILTRE_ATTENDU}` de demarrage ({attendus:?}). Il vient \
                             donc d'autre chose, et conclure que le filtre de \
                             demarrage retient serait une erreur"
                        ));
                    }
                }
            }
            None => println!("  attribution impossible: aucun filtre a interroger"),
        }
    }

    match issue {
        Issue::Reussi => {
            println!(
                "\nstartup-window: PASSED - rien ne sort avant que le daemon existe\n\
                 (ne dit rien de la fenetre pre-BFE, qui se mesure par le magasin BootTime)"
            );
            Ok(())
        }
        Issue::Ignore(raison) => {
            println!("\nstartup-window: SKIPPED - {raison}");
            Ok(())
        }
        Issue::Echec(raison) => Err(anyhow!("startup-window: FAILED - {raison}")),
    }
}

/// Conclut a partir des mesures d'apres redemarrage.
///
/// Pure et sans effet de bord, donc verifiable sans machine Windows ni
/// redemarrage.
pub fn juger(m: &Mesures, cible: SocketAddr) -> Issue {
    if m.presents.is_empty() {
        return Issue::Echec(format!(
            "aucun filtre de demarrage n'a survecu au redemarrage: le drapeau \
             persistant n'a pas tenu, et la fenetre que ce filtre existe pour \
             fermer reste ouverte. La cible {cible} a d'ailleurs repondu {:?}",
            m.arme
        ));
    }
    if !m.presents.iter().any(|n| n.contains(FILTRE_ATTENDU)) {
        return Issue::Echec(format!(
            "{} filtres de demarrage ont survecu, mais aucun ne s'appelle \
             `{FILTRE_ATTENDU}`: seules les AUTORISATIONS ont survecu, donc \
             rien ne bloque. Une politique reduite a ses exemptions ne retient \
             rien du tout",
            m.presents.len()
        ));
    }
    if m.arme == Verdict::SansRoute {
        return Issue::Ignore(format!(
            "aucune route vers {cible} apres le redemarrage: la machine n'a \
             peut-etre pas fini de remonter son reseau, et un refus ne pourrait \
             pas etre attribue au filtre"
        ));
    }
    if m.arme != Verdict::Bloque {
        return Issue::Echec(format!(
            "FUITE: la connexion vers {cible} est passee ({:?}) apres le \
             redemarrage, alors que le filtre de demarrage etait en place et \
             qu'aucun daemon n'avait encore demarre. C'est exactement la \
             fenetre que ce filtre existe pour fermer",
            m.arme
        ));
    }
    if m.apres == Verdict::Bloque {
        return Issue::Echec(format!(
            "la connexion vers {cible} est encore refusee apres le retrait: des \
             filtres survivent au retrait, et la machine reste coupee au \
             prochain redemarrage"
        ));
    }
    if m.apres != Verdict::Connecte {
        return Issue::Ignore(format!(
            "la cible {cible} ne repond plus apres le retrait ({:?}): le refus \
             observe ne peut plus etre attribue au filtre plutot qu'a la \
             disparition de la cible",
            m.apres
        ));
    }
    Issue::Reussi
}

/// Exige la tache planifiee de retrait.
///
/// Seul le CODE DE SORTIE est lu: la sortie de `schtasks` est traduite dans la
/// langue du systeme, et en dependre rendrait le garde-fou muet sur une machine
/// dont la locale n'est pas celle du developpeur.
fn filet_present() -> anyhow::Result<()> {
    let ok = Command::new("schtasks")
        .args(["/query", "/tn", TACHE_FILET])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .context("interrogation de schtasks")?
        .success();
    if ok {
        return Ok(());
    }
    Err(anyhow!(
        "la tache planifiee `{TACHE_FILET}` n'existe pas. Ce filtre SURVIT au \
         redemarrage: sans retrait declenche AU DEMARRAGE, une erreur laisse la \
         machine coupee sans moyen de la recuperer a distance. La creer en \
         PowerShell administrateur, puis relancer:\n\n{HINT_FILET}"
    ))
}

/// Ou la phase `armer` laisse ce que la phase `constater` doit savoir.
///
/// A cote du binaire et non dans le repertoire temporaire: la phase suivante
/// s'execute apres un redemarrage, et Windows nettoie les temporaires.
fn marqueur() -> anyhow::Result<PathBuf> {
    let exe = std::env::current_exe().context("chemin du binaire courant")?;
    Ok(exe.with_file_name("bifrost-startup-window.txt"))
}

fn marqueur_ecrire(cible: SocketAddr) -> anyhow::Result<()> {
    let p = marqueur()?;
    std::fs::write(&p, format!("cible={cible}\n"))
        .with_context(|| format!("ecriture de {}", p.display()))
}

fn marqueur_lire() -> anyhow::Result<SocketAddr> {
    let p = marqueur()?;
    let texte = std::fs::read_to_string(&p).map_err(|e| {
        anyhow!(
            "lecture de {}: {e}. Cette phase suit un `--startup-window armer`, \
             qui y note la cible mesuree. Sans elle, on ne sait pas quelle \
             adresse devrait etre refusee",
            p.display()
        )
    })?;
    let cible = texte
        .lines()
        .find_map(|l| l.strip_prefix("cible="))
        .ok_or_else(|| anyhow!("{} ne porte pas de cible", p.display()))?;
    cible
        .trim()
        .parse()
        .with_context(|| format!("cible illisible dans {}", p.display()))
}

fn marqueur_effacer() {
    if let Ok(p) = marqueur() {
        let _ = std::fs::remove_file(p);
    }
}

/// Attend que le journal rende le blocage. Borne a vingt secondes.
fn attendre(filtres: &[u64], cible: SocketAddr) -> anyhow::Result<temoin_wfp::Constat> {
    const PATIENCE: Duration = Duration::from_secs(20);
    const PAS: Duration = Duration::from_millis(500);

    let debut = std::time::Instant::now();
    let mut constat = temoin_wfp::constater(FENETRE, filtres, cible.ip(), cible.port())?;
    while constat.notres.is_empty() && debut.elapsed() < PATIENCE {
        std::thread::sleep(PAS);
        constat = temoin_wfp::constater(FENETRE, filtres, cible.ip(), cible.port())?;
    }
    Ok(constat)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cible() -> SocketAddr {
        "1.1.1.1:443".parse().unwrap()
    }

    fn mesures(presents: &[&str], arme: Verdict, apres: Verdict) -> Mesures {
        Mesures {
            presents: presents.iter().map(|s| (*s).to_owned()).collect(),
            arme,
            apres,
        }
    }

    #[test]
    fn la_combinaison_attendue_vaut_reussite() {
        let m = mesures(
            &["demarrage block-all", "reseau local"],
            Verdict::Bloque,
            Verdict::Connecte,
        );
        assert_eq!(juger(&m, cible()), Issue::Reussi);
    }

    #[test]
    fn un_filtre_qui_ne_survit_pas_au_redemarrage_est_un_echec_et_pas_un_ignore() {
        // La tentation serait de rendre Skipped: rien a mesurer, donc rien a
        // dire. Ce serait faux. Un filtre pose puis disparu au redemarrage est
        // precisement la panne que ce vecteur existe pour attraper.
        let m = mesures(&[], Verdict::Connecte, Verdict::Connecte);
        match juger(&m, cible()) {
            Issue::Echec(r) => assert!(r.contains("persistant"), "{r}"),
            autre => panic!("attendu un echec, obtenu {autre:?}"),
        }
    }

    #[test]
    fn seules_les_autorisations_survivantes_ne_retiennent_rien() {
        // Le cas vicieux: des filtres ont survecu, le compte n'est pas nul, et
        // pourtant aucun ne bloque. Compter les filtres suffirait a verdir.
        let m = mesures(
            &["reseau local", "DHCPv4"],
            Verdict::Bloque,
            Verdict::Connecte,
        );
        match juger(&m, cible()) {
            Issue::Echec(r) => assert!(r.contains("aucun ne s'appelle"), "{r}"),
            autre => panic!("attendu un echec, obtenu {autre:?}"),
        }
    }

    #[test]
    fn une_connexion_qui_passe_apres_redemarrage_est_la_fuite_cherchee() {
        let m = mesures(
            &["demarrage block-all"],
            Verdict::Connecte,
            Verdict::Connecte,
        );
        match juger(&m, cible()) {
            Issue::Echec(r) => assert!(r.contains("FUITE"), "{r}"),
            autre => panic!("attendu un echec, obtenu {autre:?}"),
        }
    }

    #[test]
    fn un_retrait_qui_ne_rouvre_pas_est_un_echec() {
        let m = mesures(&["demarrage block-all"], Verdict::Bloque, Verdict::Bloque);
        match juger(&m, cible()) {
            Issue::Echec(r) => assert!(r.contains("survivent au retrait"), "{r}"),
            autre => panic!("attendu un echec, obtenu {autre:?}"),
        }
    }

    #[test]
    fn un_reseau_pas_encore_remonte_ne_conclut_pas() {
        let m = mesures(
            &["demarrage block-all"],
            Verdict::SansRoute,
            Verdict::Connecte,
        );
        assert!(matches!(juger(&m, cible()), Issue::Ignore(_)));
    }

    #[test]
    fn armer_refuse_une_politique_sans_reseau_local() {
        // Le garde-fou qui evite de rendre la machine irrecuperable. Il est
        // verifie AVANT toute interrogation de schtasks et avant tout acces au
        // moteur WFP, donc ce test ne demande ni privileges ni tache planifiee.
        let e = armer(cible(), PolitiqueDemarrage::default()).unwrap_err();
        assert!(format!("{e}").contains("reseau local"), "{e}");
    }
}
