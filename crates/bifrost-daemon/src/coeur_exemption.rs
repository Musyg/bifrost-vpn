//! Le vecteur `coeur-exemption` sous Windows: la LARGEUR de l'exemption.
//!
//! # Ce qui se mesure ici, et pourquoi ce n'est pas "le coeur passe"
//!
//! Qu'un coeur anti-censure exempte puisse sortir est la partie facile, et
//! celle qui ne peut pas mal tourner sans se voir: si elle casse, le produit ne
//! se connecte plus. Ce qui peut mal tourner SILENCIEUSEMENT, c'est l'exemption
//! trop LARGE - un permit qui laisse passer plus que le coeur, ou qui laisse
//! passer le coeur plus loin que prevu. Personne ne s'en plaint, et l'etancheite
//! est percee.
//!
//! D'ou trois mesures sous armement, dont deux attendent un BLOCAGE:
//!
//! 1. depuis le chemin du coeur, vers une destination ordinaire: doit passer.
//!    Sans elle, les deux suivantes seraient satisfaites par un plan qui bloque
//!    tout, exemption comprise;
//! 2. depuis le chemin du coeur, vers le port 53 d'un resolveur externe: doit
//!    etre REFUSE. Le coeur est exempte pour joindre son serveur, pas pour
//!    devenir un contournement du blocage DNS. C'est la mesure de largeur;
//! 3. depuis une copie du meme binaire a un AUTRE chemin: doit etre refuse.
//!    Sans elle, une exemption qui matcherait tout le monde rendrait la mesure 1
//!    verte a l'identique.
//!
//! # Le motif "demande un coeur en cours d'execution" etait faux
//!
//! Ce vecteur a porte cette raison de `Skipped` jusqu'au 18 aout 2026. Elle
//! vient de Linux, ou l'exemption designe un UID: sans processus tournant sous
//! cet UID, il n'y a effectivement rien a mesurer.
//!
//! Sous Windows l'exemption est faite de `ALE_APP_ID` ET `ALE_USER_ID`, soit un
//! CHEMIN et une identite. Un binaire pose a ce chemin et lance sous cette
//! identite matche le filtre, qu'il s'agisse d'un vrai coeur ou d'une sonde.
//! Aucun coeur n'a donc besoin de tourner, et c'est meme preferable: la mesure
//! porte alors sur le pare-feu seul, sans dependre de ce qu'un sing-box aurait
//! decide d'emettre. Ce qui se mesure est le MECANISME, pas ce binaire-la.
//!
//! # Ce que la mesure n'etablit pas
//!
//! Qu'un AUTRE utilisateur lancant le binaire au chemin du coeur serait refuse:
//! le verifier demanderait un second compte. La sonde d'identite de
//! `--wfp-selftest` en est le plus proche substitut, par sa mutation sur un SID
//! que personne ne porte.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, anyhow};
use bifrost_core::ports::{FirewallPolicy, KillSwitch};
use bifrost_firewall::windows::WfpKillSwitch;

use crate::temoin_wfp;
use crate::wfp_identity::{Verdict, sonder_depuis, via_copie};

/// Le journal d'audit n'est pas ecrit dans la foulee de la connexion.
const FENETRE: Duration = Duration::from_secs(60);
/// Le filtre dont on attend qu'il refuse la sonde DNS du coeur.
const FILTRE_DNS: &str = "block-dns";
/// Le filtre dont on attend qu'il refuse la sonde venue d'ailleurs.
const FILTRE_TOUT: &str = "block-all";

/// Les cinq mesures, sans interpretation.
///
/// Les separer de la conclusion permet d'eprouver le raisonnement sans machine
/// Windows ni privileges, et c'est la que se discute ce qui compte comme une
/// exemption correctement bornee.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mesures {
    /// Au repos, depuis le chemin du coeur, vers la destination ordinaire.
    pub repos: Verdict,
    /// Au repos, depuis le chemin du coeur, vers le resolveur externe.
    pub repos_dns: Verdict,
    /// Sous armement, depuis le chemin du coeur, vers la destination ordinaire.
    pub coeur: Verdict,
    /// Sous armement, depuis le chemin du coeur, vers le resolveur externe.
    pub coeur_dns: Verdict,
    /// Sous armement, depuis une copie a un autre chemin.
    pub etranger: Verdict,
}

/// Ce que la mesure a conclu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Issue {
    Reussi,
    /// La mesure n'a pas pu conclure. Jamais un succes par defaut.
    Ignore(String),
    Echec(String),
}

/// Construit la politique du vecteur.
///
/// `coeur` est le chemin du binaire exempte. Le resolveur declare pointe la
/// boucle locale, comme dans le produit quand le resolveur chiffre embarque
/// tourne: toute requete :53 vers l'exterieur tombe donc sous `block-dns`, y
/// compris celles du coeur - c'est precisement ce qu'on veut verifier.
fn politique(coeur: &Path, lan: bool) -> FirewallPolicy {
    FirewallPolicy {
        tunnel_interface: None,
        tunnel_luid: None,
        fwmark: None,
        dns_resolver: IpAddr::V4(Ipv4Addr::LOCALHOST),
        allow_lan: lan,
        coeur_uid: None,
        coeur_executable: Some(coeur.to_path_buf()),
        resolveur_uid: None,
        resolveur_executable: None,
        resolveur_sid: None,
        resolveur_embarque: false,
    }
}

/// Mesure le vecteur. Coupe le reseau entre l'armement et le desarmement.
pub fn selftest(cible: SocketAddr, resolveur: SocketAddr, lan: bool) -> anyhow::Result<()> {
    if resolveur.port() != 53 {
        anyhow::bail!(
            "le resolveur doit etre sur le port 53: c'est le port que \
             `{FILTRE_DNS}` filtre, et sonder ailleurs ne dirait rien de la \
             largeur de l'exemption"
        );
    }
    if cible.port() == 53 {
        anyhow::bail!(
            "la destination ordinaire ne peut pas etre sur le port 53: elle \
             sert de temoin POSITIF sous armement, et le plan la bloquerait"
        );
    }

    let faux_coeur = FauxCoeur::poser()?;
    println!("vecteur coeur-exemption, coeur declare {}", faux_coeur);
    println!("  destination ordinaire {cible}, resolveur externe {resolveur}");

    let mut firewall = WfpKillSwitch::new().map_err(|e| anyhow!("ouverture du moteur WFP: {e}"))?;
    let politique = politique(faux_coeur.chemin(), lan);

    let mesures = mesurer(&mut firewall, &faux_coeur, cible, resolveur, &politique)?;
    println!("    au repos, ordinaire:   {:?}", mesures.repos);
    println!("    au repos, :53:         {:?}", mesures.repos_dns);
    println!("    arme, coeur ordinaire: {:?}", mesures.coeur);
    println!("    arme, coeur :53:       {:?}", mesures.coeur_dns);
    println!("    arme, autre chemin:    {:?}", mesures.etranger);

    let issue = juger(mesures, cible, resolveur);

    // L'attribution ne vaut que si la mesure a effectivement arme et conclu.
    // La chercher apres un Ignore ferait parler un journal qui n'a rien vu.
    if issue == Issue::Reussi {
        attribuer(&firewall, resolveur, FILTRE_DNS, "la sonde DNS du coeur")?;
        attribuer(&firewall, cible, FILTRE_TOUT, "la sonde d'un autre chemin")?;
    }

    match issue {
        Issue::Reussi => {
            println!("\ncoeur-exemption: PASSED - l'exemption borne le coeur a ce qu'il lui faut");
            Ok(())
        }
        Issue::Ignore(raison) => {
            println!("\ncoeur-exemption: SKIPPED - {raison}");
            Ok(())
        }
        Issue::Echec(raison) => Err(anyhow!("coeur-exemption: FAILED - {raison}")),
    }
}

/// Enchaine les cinq mesures. Desarme quoi qu'il arrive.
fn mesurer(
    firewall: &mut WfpKillSwitch,
    faux_coeur: &FauxCoeur,
    cible: SocketAddr,
    resolveur: SocketAddr,
    politique: &FirewallPolicy,
) -> anyhow::Result<Mesures> {
    println!("  temoins negatifs, kill switch au repos...");
    let repos = faux_coeur.sonder(cible)?;
    let repos_dns = faux_coeur.sonder(resolveur)?;
    if repos != Verdict::Connecte || repos_dns != Verdict::Connecte {
        // Rien n'est arme, donc rien a retirer, et surtout: on ne coupe pas le
        // reseau de la machine pour une mesure dont on sait qu'elle ne
        // conclura rien.
        return Ok(Mesures {
            repos,
            repos_dns,
            coeur: Verdict::SansRoute,
            coeur_dns: Verdict::SansRoute,
            etranger: Verdict::SansRoute,
        });
    }

    println!("  armement avec l'exemption du coeur, le reseau tombe...");
    firewall
        .engage(politique)
        .map_err(|e| anyhow!("armement de la mesure d'exemption: {e}"))?;

    let sous_armement = (|| -> anyhow::Result<(Verdict, Verdict, Verdict)> {
        Ok((
            faux_coeur.sonder(cible)?,
            faux_coeur.sonder(resolveur)?,
            via_copie(cible)?,
        ))
    })();

    let desarmement = firewall
        .disengage()
        .map_err(|e| anyhow!("desarmement de la mesure d'exemption: {e}"));
    println!("  desarme, le reseau revient");

    let (coeur, coeur_dns, etranger) = sous_armement?;
    desarmement?;

    Ok(Mesures {
        repos,
        repos_dns,
        coeur,
        coeur_dns,
        etranger,
    })
}

/// Conclut a partir des cinq mesures.
///
/// Pure et sans effet de bord, donc verifiable sans machine Windows ni
/// privileges.
pub fn juger(m: Mesures, cible: SocketAddr, resolveur: SocketAddr) -> Issue {
    if m.repos == Verdict::SansRoute || m.repos_dns == Verdict::SansRoute {
        return Issue::Ignore(format!(
            "aucune route vers {cible} ou {resolveur} au repos: les sondes ne \
             mesurent rien"
        ));
    }
    if m.repos != Verdict::Connecte {
        return Issue::Ignore(format!(
            "le temoin negatif vers {cible} n'a pas abouti ({:?}) alors que \
             rien n'est arme: sous armement il echouerait de toute facon, et \
             son echec ne pourrait pas etre attribue au kill switch",
            m.repos
        ));
    }
    if m.repos_dns != Verdict::Connecte {
        return Issue::Ignore(format!(
            "le port 53 de {resolveur} est deja refuse ({:?}) alors que rien \
             n'est arme - resolveur injoignable, ou un tiers filtre deja le \
             DNS. Un refus sous armement ne pourrait pas etre impute a \
             `{FILTRE_DNS}`, donc la largeur de l'exemption reste inconnue",
            m.repos_dns
        ));
    }

    // L'ordre compte: la fuite se dit avant la panne. Une exemption trop large
    // est un defaut d'etancheite, une exemption morte n'est qu'un produit qui
    // ne se connecte plus - visible au premier usage, et sans consequence sur
    // ce que le kill switch retient.
    if m.etranger != Verdict::Bloque {
        return Issue::Echec(format!(
            "FUITE: un binaire a un chemin QUELCONQUE a joint {cible} ({:?}) \
             sous armement. L'exemption ne discrimine pas le chemin du coeur, \
             elle exempte tout le monde",
            m.etranger
        ));
    }
    if m.coeur_dns != Verdict::Bloque {
        return Issue::Echec(format!(
            "FUITE: le coeur a joint le port 53 de {resolveur} ({:?}) sous \
             armement. Son exemption passe AU-DESSUS de `{FILTRE_DNS}`, elle \
             en fait donc un contournement du blocage DNS",
            m.coeur_dns
        ));
    }
    if m.coeur == Verdict::Bloque {
        return Issue::Echec(format!(
            "l'exemption ne matche pas: le coeur declare a ete refuse vers \
             {cible} sous armement. Le produit ne pourrait pas se connecter. \
             Les deux blocages constates ne prouvent alors rien de la largeur \
             de l'exemption, puisqu'ils s'expliquent par un plan qui bloque tout"
        ));
    }
    if m.coeur != Verdict::Connecte {
        return Issue::Ignore(format!(
            "le coeur n'a ni ete refuse ni abouti vers {cible} sous armement \
             ({:?}): sans succes franc, on ne peut pas distinguer une exemption \
             qui matche d'une destination devenue muette",
            m.coeur
        ));
    }
    Issue::Reussi
}

/// Exige qu'un blocage vers `destination` soit impute au filtre nomme `nom`.
///
/// Un blocage impute au catch-all ne dit rien de `block-dns`, et un blocage
/// impute a n'importe lequel de nos filtres ne dit rien du tout: c'est vrai
/// meme quand seul le catch-all fonctionne.
fn attribuer(
    firewall: &WfpKillSwitch,
    destination: SocketAddr,
    nom: &str,
    quoi: &str,
) -> anyhow::Result<()> {
    let attendus = firewall.filtres_nommes(nom);
    if attendus.is_empty() {
        anyhow::bail!(
            "aucun filtre nomme `{nom}` n'a ete pose: le plan a change, et \
             cette mesure ne porte plus sur ce qu'elle annonce"
        );
    }

    let constat = attendre(&attendus, destination)?;
    println!(
        "  {quoi}: {} blocages WFP dans la fenetre, dont {} imputables a `{nom}`",
        constat.total,
        constat.notres.len()
    );
    if constat.audit_muet() {
        println!(
            "    attribution impossible: aucun blocage WFP dans le journal, pas \
             meme ceux du pare-feu Windows. L'audit n'enregistre rien. A activer \
             avec:\n{}",
            temoin_wfp::COMMANDE_ACTIVATION
        );
        return Ok(());
    }
    match constat.notres.first() {
        Some(b) => {
            println!(
                "    filtre {} a la couche {}, application {}",
                b.filtre,
                b.couche,
                b.application.rsplit('\\').next().unwrap_or("?")
            );
            Ok(())
        }
        None => Err(anyhow!(
            "le refus vers {destination} n'est imputable a AUCUN filtre `{nom}` \
             (filtres {attendus:?}). Il vient donc d'autre chose, et conclure \
             sur la largeur de l'exemption serait une erreur"
        )),
    }
}

/// Attend que le journal rende le blocage. Borne a vingt secondes.
fn attendre(filtres: &[u64], destination: SocketAddr) -> anyhow::Result<temoin_wfp::Constat> {
    const PATIENCE: Duration = Duration::from_secs(20);
    const PAS: Duration = Duration::from_millis(500);

    let debut = std::time::Instant::now();
    let mut constat =
        temoin_wfp::constater(FENETRE, filtres, destination.ip(), destination.port())?;
    while constat.notres.is_empty() && debut.elapsed() < PATIENCE {
        std::thread::sleep(PAS);
        constat = temoin_wfp::constater(FENETRE, filtres, destination.ip(), destination.port())?;
    }
    Ok(constat)
}

/// Copie du binaire courant, tenant lieu de coeur declare.
///
/// Un vrai coeur n'apporterait rien: ce qui se mesure est le filtre, et le
/// filtre ne regarde que le chemin et l'identite. Un vrai coeur ajouterait en
/// revanche ses propres connexions au journal, donc du bruit a trier.
struct FauxCoeur {
    chemin: PathBuf,
}

impl FauxCoeur {
    fn poser() -> anyhow::Result<Self> {
        let source = std::env::current_exe().context("chemin du binaire courant")?;
        // Nom distinct de celui de la sonde d'identite: les deux coexistent
        // pendant la mesure sous armement, et se marcher dessus ferait sonder
        // deux fois le meme chemin sans que rien ne le signale.
        let chemin =
            std::env::temp_dir().join(format!("bifrost-faux-coeur-{}.exe", std::process::id()));
        std::fs::copy(&source, &chemin)
            .with_context(|| format!("copie de {} vers {}", source.display(), chemin.display()))?;
        Ok(Self { chemin })
    }

    fn chemin(&self) -> &Path {
        &self.chemin
    }

    fn sonder(&self, addr: SocketAddr) -> anyhow::Result<Verdict> {
        sonder_depuis(&self.chemin, addr)
    }
}

impl std::fmt::Display for FauxCoeur {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.chemin.display())
    }
}

impl Drop for FauxCoeur {
    fn drop(&mut self) {
        // Windows garde l'image mappee un court instant apres la sortie du
        // processus. On reessaie plutot que de laisser un exe derriere soi.
        for _ in 0..5 {
            if std::fs::remove_file(&self.chemin).is_ok() {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        eprintln!(
            "faux coeur non efface: {} (a supprimer a la main)",
            self.chemin.display()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cible() -> SocketAddr {
        "1.1.1.1:443".parse().unwrap()
    }
    fn resolveur() -> SocketAddr {
        "9.9.9.9:53".parse().unwrap()
    }

    fn mesures(coeur: Verdict, coeur_dns: Verdict, etranger: Verdict) -> Mesures {
        Mesures {
            repos: Verdict::Connecte,
            repos_dns: Verdict::Connecte,
            coeur,
            coeur_dns,
            etranger,
        }
    }

    #[test]
    fn la_combinaison_attendue_vaut_reussite() {
        let m = mesures(Verdict::Connecte, Verdict::Bloque, Verdict::Bloque);
        assert_eq!(juger(m, cible(), resolveur()), Issue::Reussi);
    }

    #[test]
    fn un_coeur_qui_joint_le_53_est_une_fuite_et_pas_un_succes() {
        // LE test de ce vecteur. Le coeur sort, aucun etranger ne sort: tout
        // semble en ordre, et pourtant l'exemption vient de faire du coeur un
        // contournement du blocage DNS.
        let m = mesures(Verdict::Connecte, Verdict::Connecte, Verdict::Bloque);
        match juger(m, cible(), resolveur()) {
            Issue::Echec(r) => assert!(r.contains("block-dns"), "{r}"),
            autre => panic!("attendu un echec, obtenu {autre:?}"),
        }
    }

    #[test]
    fn une_exemption_qui_matche_tout_le_monde_est_une_fuite() {
        let m = mesures(Verdict::Connecte, Verdict::Bloque, Verdict::Connecte);
        match juger(m, cible(), resolveur()) {
            Issue::Echec(r) => assert!(r.contains("chemin"), "{r}"),
            autre => panic!("attendu un echec, obtenu {autre:?}"),
        }
    }

    #[test]
    fn un_plan_qui_bloque_tout_ne_passe_pas_pour_une_exemption_bornee() {
        // Les deux blocages attendus sont la, mais le coeur aussi est bloque:
        // sans le succes du coeur, ils s'expliquent par un plan qui coupe tout
        // et ne disent rien de la largeur de l'exemption.
        let m = mesures(Verdict::Bloque, Verdict::Bloque, Verdict::Bloque);
        match juger(m, cible(), resolveur()) {
            Issue::Echec(r) => assert!(r.contains("ne matche pas"), "{r}"),
            autre => panic!("attendu un echec, obtenu {autre:?}"),
        }
    }

    #[test]
    fn un_succes_du_coeur_qui_n_est_pas_franc_ne_conclut_pas() {
        // `Passe` couvre l'echeance atteinte: la connexion est partie sans etre
        // refusee, mais n'a rien joint. Le lire comme un succes rendrait la
        // mesure verte sur une destination devenue muette.
        let m = mesures(Verdict::Passe, Verdict::Bloque, Verdict::Bloque);
        assert!(matches!(juger(m, cible(), resolveur()), Issue::Ignore(_)));
    }

    #[test]
    fn un_53_deja_refuse_au_repos_ne_permet_aucune_conclusion() {
        let m = Mesures {
            repos: Verdict::Connecte,
            repos_dns: Verdict::Bloque,
            coeur: Verdict::SansRoute,
            coeur_dns: Verdict::SansRoute,
            etranger: Verdict::SansRoute,
        };
        match juger(m, cible(), resolveur()) {
            Issue::Ignore(r) => assert!(r.contains("deja refuse"), "{r}"),
            autre => panic!("attendu un Ignore, obtenu {autre:?}"),
        }
    }

    #[test]
    fn la_politique_declare_le_coeur_et_garde_le_dns_en_local() {
        let p = politique(Path::new(r"C:\faux\coeur.exe"), true);
        assert_eq!(
            p.coeur_executable.as_deref(),
            Some(Path::new(r"C:\faux\coeur.exe"))
        );
        assert_eq!(p.dns_resolver, IpAddr::V4(Ipv4Addr::LOCALHOST));
    }

    #[test]
    fn une_destination_ordinaire_sur_le_53_est_refusee_avant_toute_coupure() {
        // Elle sert de temoin POSITIF sous armement. La placer sur le port que
        // le plan bloque rendrait la mesure impossible tout en coupant le
        // reseau de la machine pour rien.
        let e = selftest("1.1.1.1:53".parse().unwrap(), resolveur(), true).unwrap_err();
        assert!(format!("{e}").contains("port 53"), "{e}");
    }

    /// Le nom attendu designe un filtre que le plan pose VRAIMENT.
    ///
    /// L'imputation par le nom est tout ce qui distingue << notre blocage a
    /// mordu >> de << quelque chose a bloque >>: sans elle, un pare-feu tiers
    /// ou le catch-all suffiraient a faire passer le vecteur. Or le nom est
    /// ecrit en dur ici et le plan vit dans `bifrost-firewall`: rien ne les
    /// reliait.
    ///
    /// Mesure du 23 aout 2026 sur dev-windows: en remplacant ce nom par
    /// n'importe quelle autre chaine, toute la suite du crate restait verte.
    /// Le defaut ne serait apparu qu'a l'execution, sur une machine Windows
    /// elevee avec l'audit WFP actif - donc jamais en integration continue.
    /// Il est fail-closed, ce qui limite le degat a une mesure impossible et
    /// non a une fuite silencieuse, mais une mesure impossible qu'on decouvre
    /// sur le banc coute une journee.
    ///
    /// La comparaison est un `contains`, exactement celle que
    /// `WfpKillSwitch::filtres_nommes` fait a l'execution. Une lecture voisine
    /// mais differente ne dirait rien de la lecture reelle.
    #[test]
    fn les_filtres_attendus_sont_des_filtres_que_le_plan_pose() {
        let plan = bifrost_firewall::wfp_plan::plan(
            &politique(std::path::Path::new("coeur.exe"), true),
            std::path::PathBuf::from("bifrost-daemon.exe"),
            Some(1),
        );
        let noms: Vec<&str> = plan.iter().map(|f| f.name.as_str()).collect();
        assert!(
            noms.iter().any(|n| n.contains(FILTRE_DNS)),
            "aucun filtre du plan ne s'appelle `{}`: ce vecteur ne pourra imputer son refus a rien. Poses: {:?}",
            FILTRE_DNS,
            noms
        );
        assert!(
            noms.iter().any(|n| n.contains(FILTRE_TOUT)),
            "aucun filtre du plan ne s'appelle `{}`: ce vecteur ne pourra imputer son refus a rien. Poses: {:?}",
            FILTRE_TOUT,
            noms
        );
    }
}
