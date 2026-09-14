//! Le vecteur `resolveur-exemption` sous Windows: la BORNE de l'exception.
//!
//! # Le miroir de `coeur-exemption`, et son exact contraire
//!
//! Les deux vecteurs mesurent la meme chose - la largeur d'un permit accorde a
//! un binaire - mais dans des sens opposes, et c'est ce qui rend utile de les
//! lire ensemble.
//!
//! Le coeur EST le transport: son permit est large et doit rester SOUS le
//! blocage DNS, sans quoi il deviendrait un contournement de ce blocage. Le
//! resolveur chiffre est l'inverse: son permit passe AU-DESSUS du blocage DNS,
//! parce que sans cela il ne peut pas resoudre le nom de son propre serveur
//! chiffre et ne demarre jamais - mais il ne doit pouvoir sortir QUE sur le
//! :53. Large, il ferait du resolveur un second transport, c'est-a-dire une
//! sortie en clair hors tunnel accordee au composant qui existe justement pour
//! qu'il n'y en ait plus.
//!
//! # Ce qui se mesure, et pourquoi ce n'est pas "le resolveur amorce"
//!
//! Qu'un resolveur exempte puisse joindre son bootstrap est la partie facile,
//! et celle qui ne peut pas mal tourner sans se voir: si elle casse, aucun nom
//! ne se resout. Ce qui peut mal tourner SILENCIEUSEMENT est l'exception trop
//! large. D'ou cinq mesures, dont deux attendent un BLOCAGE:
//!
//! 1. au repos, depuis le chemin du resolveur, vers une destination ordinaire
//!    et vers le :53 externe: les deux doivent aboutir. Sans ces temoins, les
//!    blocages sous armement ne seraient imputables a rien;
//! 2. sous armement, depuis le chemin du resolveur, vers le :53 externe: doit
//!    PASSER. C'est l'exception elle-meme;
//! 3. sous armement, depuis le chemin du resolveur, vers la destination
//!    ordinaire: doit etre REFUSE. C'est la mesure de borne, la seule qui
//!    distingue une exception etroite d'une exemption de transport;
//! 4. sous armement, depuis une copie du meme binaire a un AUTRE chemin, vers
//!    le :53: doit etre refuse. Sans elle, une exception qui matcherait tout le
//!    monde rendrait la mesure 2 verte a l'identique.
//!
//! # Ce que la mesure n'etablit pas
//!
//! Qu'un AUTRE utilisateur lancant le binaire au chemin du resolveur serait
//! refuse: le verifier demanderait un second compte. Windows ne fait pas encore
//! tourner le resolveur sous un compte a lui, ce que `--resolveur-selftest`
//! annonce SKIPPED avec sa raison. La sonde d'identite de `--wfp-selftest` en
//! est le plus proche substitut, par sa mutation sur un SID que personne ne
//! porte.

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
/// Le filtre dont on attend qu'il refuse la sonde venue d'un autre chemin.
const FILTRE_DNS: &str = "block-dns";
/// Le filtre dont on attend qu'il refuse le resolveur hors du :53.
const FILTRE_TOUT: &str = "block-all";

/// Les cinq mesures, sans interpretation.
///
/// Les separer de la conclusion permet d'eprouver le raisonnement sans machine
/// Windows ni privileges, et c'est la que se discute ce qui compte comme une
/// exception correctement bornee.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mesures {
    /// Au repos, depuis le chemin du resolveur, vers la destination ordinaire.
    pub repos: Verdict,
    /// Au repos, depuis le chemin du resolveur, vers le :53 externe.
    pub repos_dns: Verdict,
    /// Sous armement, depuis le chemin du resolveur, vers le :53 externe.
    pub resolveur_dns: Verdict,
    /// Sous armement, depuis le chemin du resolveur, vers la destination
    /// ordinaire.
    pub resolveur_hors_53: Verdict,
    /// Sous armement, depuis une copie a un autre chemin, vers le :53 externe.
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
/// `resolveur` est le chemin du binaire exempte. Le resolveur DECLARE pointe la
/// boucle locale, comme dans le produit: c'est ce qui fait tomber toute requete
/// :53 vers l'exterieur sous `block-dns`, y compris celles du resolveur -
/// l'exception etant precisement ce qui doit l'en tirer, et rien de plus.
///
/// `resolveur_embarque` a `true`: le drapeau vient du profil, et sans lui
/// l'exception ne serait pas posee du tout. La mesure porterait alors sur un
/// plan sans exception, ce qui ne dirait rien de sa borne.
fn politique(resolveur: &Path, lan: bool) -> FirewallPolicy {
    FirewallPolicy {
        tunnel_interface: None,
        tunnel_luid: None,
        fwmark: None,
        dns_resolver: IpAddr::V4(Ipv4Addr::LOCALHOST),
        allow_lan: lan,
        coeur_uid: None,
        coeur_executable: None,
        resolveur_uid: None,
        resolveur_executable: Some(resolveur.to_path_buf()),
        // Aucun compte de service declare: ce vecteur mesure la BORNE de
        // l'exception (elle ne vaut que pour le :53), pas l'identite qui la
        // porte. Sans SID, `permit-resolveur-dns` garde `Identity::Current`,
        // le comportement d'aujourd'hui.
        resolveur_sid: None,
        resolveur_embarque: true,
    }
}

/// Mesure le vecteur. Coupe le reseau entre l'armement et le desarmement.
pub fn selftest(cible: SocketAddr, resolveur: SocketAddr, lan: bool) -> anyhow::Result<()> {
    if resolveur.port() != 53 {
        anyhow::bail!(
            "le resolveur doit etre sur le port 53: c'est le port que \
             l'exception ouvre, et sonder ailleurs ne dirait rien d'elle"
        );
    }
    if cible.port() == 53 {
        anyhow::bail!(
            "la destination ordinaire ne peut pas etre sur le port 53: elle \
             sert de temoin NEGATIF sous armement, et l'exception qu'on mesure \
             la laisserait justement passer"
        );
    }

    let faux = FauxResolveur::poser()?;
    println!("vecteur resolveur-exemption, resolveur declare {faux}");
    println!("  destination ordinaire {cible}, resolveur externe {resolveur}");

    let mut firewall = WfpKillSwitch::new().map_err(|e| anyhow!("ouverture du moteur WFP: {e}"))?;
    let politique = politique(faux.chemin(), lan);

    let mesures = mesurer(&mut firewall, &faux, cible, resolveur, &politique)?;
    println!("    au repos, ordinaire:       {:?}", mesures.repos);
    println!("    au repos, :53:             {:?}", mesures.repos_dns);
    println!("    arme, resolveur :53:       {:?}", mesures.resolveur_dns);
    println!(
        "    arme, resolveur ordinaire: {:?}",
        mesures.resolveur_hors_53
    );
    println!("    arme, autre chemin :53:    {:?}", mesures.etranger);

    let issue = juger(mesures, cible, resolveur);

    // L'attribution ne vaut que si la mesure a effectivement arme et conclu.
    // La chercher apres un Ignore ferait parler un journal qui n'a rien vu.
    if issue == Issue::Reussi {
        attribuer(
            &firewall,
            cible,
            FILTRE_TOUT,
            "la sonde du resolveur hors du :53",
        )?;
        attribuer(
            &firewall,
            resolveur,
            FILTRE_DNS,
            "la sonde d'un autre chemin vers le :53",
        )?;
    }

    match issue {
        Issue::Reussi => {
            println!(
                "\nresolveur-exemption: PASSED - l'exception ouvre le :53 au resolveur, \
                 et rien d'autre"
            );
            Ok(())
        }
        Issue::Ignore(raison) => {
            println!("\nresolveur-exemption: SKIPPED - {raison}");
            Ok(())
        }
        Issue::Echec(raison) => Err(anyhow!("resolveur-exemption: FAILED - {raison}")),
    }
}

/// Enchaine les cinq mesures. Desarme quoi qu'il arrive.
fn mesurer(
    firewall: &mut WfpKillSwitch,
    faux: &FauxResolveur,
    cible: SocketAddr,
    resolveur: SocketAddr,
    politique: &FirewallPolicy,
) -> anyhow::Result<Mesures> {
    println!("  temoins, kill switch au repos...");
    let repos = faux.sonder(cible)?;
    let repos_dns = faux.sonder(resolveur)?;
    if repos != Verdict::Connecte || repos_dns != Verdict::Connecte {
        // Rien n'est arme, donc rien a retirer, et surtout: on ne coupe pas le
        // reseau de la machine pour une mesure dont on sait qu'elle ne
        // conclura rien.
        return Ok(Mesures {
            repos,
            repos_dns,
            resolveur_dns: Verdict::SansRoute,
            resolveur_hors_53: Verdict::SansRoute,
            etranger: Verdict::SansRoute,
        });
    }

    println!("  armement avec l'exception du resolveur, le reseau tombe...");
    firewall
        .engage(politique)
        .map_err(|e| anyhow!("armement de la mesure d'exception: {e}"))?;

    let sous_armement = (|| -> anyhow::Result<(Verdict, Verdict, Verdict)> {
        Ok((
            faux.sonder(resolveur)?,
            faux.sonder(cible)?,
            // La copie sonde le :53 et non la destination ordinaire: c'est le
            // port que l'exception ouvre, donc le seul ou un defaut de
            // discrimination du chemin se verrait.
            via_copie(resolveur)?,
        ))
    })();

    let desarmement = firewall
        .disengage()
        .map_err(|e| anyhow!("desarmement de la mesure d'exception: {e}"));
    println!("  desarme, le reseau revient");

    let (resolveur_dns, resolveur_hors_53, etranger) = sous_armement?;
    desarmement?;

    Ok(Mesures {
        repos,
        repos_dns,
        resolveur_dns,
        resolveur_hors_53,
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
    if m.repos_dns != Verdict::Connecte {
        return Issue::Ignore(format!(
            "le port 53 de {resolveur} est deja refuse ({:?}) alors que rien \
             n'est arme - resolveur injoignable, ou un tiers filtre deja le \
             DNS. Un succes sous armement serait alors impossible, et \
             l'exception resterait inconnue",
            m.repos_dns
        ));
    }
    if m.repos != Verdict::Connecte {
        return Issue::Ignore(format!(
            "le temoin vers {cible} n'a pas abouti ({:?}) alors que rien n'est \
             arme: son refus sous armement s'expliquerait aussi bien par une \
             destination muette que par le kill switch, et la borne de \
             l'exception resterait inconnue",
            m.repos
        ));
    }

    // L'ordre compte: la fuite se dit avant la panne. Une exception trop large
    // est un defaut d'etancheite, une exception morte n'est qu'un resolveur qui
    // ne demarre pas - visible au premier usage, et sans consequence sur ce que
    // le kill switch retient.
    if m.etranger != Verdict::Bloque {
        return Issue::Echec(format!(
            "FUITE: un binaire a un chemin QUELCONQUE a joint le port 53 de \
             {resolveur} ({:?}) sous armement. L'exception ne discrimine pas le \
             chemin du resolveur, elle rouvre le :53 a tout le monde",
            m.etranger
        ));
    }
    if m.resolveur_hors_53 != Verdict::Bloque {
        return Issue::Echec(format!(
            "FUITE: le resolveur a joint {cible} ({:?}) sous armement, hors du \
             :53. Son exception n'est pas bornee au port: elle en fait un \
             second transport, c'est-a-dire une sortie en clair hors tunnel",
            m.resolveur_hors_53
        ));
    }
    if m.resolveur_dns == Verdict::Bloque {
        return Issue::Echec(format!(
            "l'exception ne matche pas: le resolveur declare a ete refuse vers \
             le port 53 de {resolveur} sous armement. Il ne pourrait pas \
             resoudre le nom de son propre serveur chiffre, donc pas demarrer. \
             Les deux blocages constates ne prouvent alors rien de la borne de \
             l'exception, puisqu'ils s'expliquent par un plan qui bloque tout"
        ));
    }
    if m.resolveur_dns != Verdict::Connecte {
        return Issue::Ignore(format!(
            "le resolveur n'a ni ete refuse ni abouti vers le port 53 de \
             {resolveur} sous armement ({:?}): sans succes franc, on ne peut \
             pas distinguer une exception qui matche d'un bootstrap devenu muet",
            m.resolveur_dns
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
             sur la borne de l'exception serait une erreur"
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

/// Copie du binaire courant, tenant lieu de resolveur declare.
///
/// Un vrai dnscrypt-proxy n'apporterait rien: ce qui se mesure est le filtre, et
/// le filtre ne regarde que le chemin et l'identite. Un vrai resolveur
/// ajouterait en revanche ses propres connexions au journal, donc du bruit a
/// trier - et son bootstrap partirait vers des serveurs que la mesure n'a pas
/// choisis.
struct FauxResolveur {
    chemin: PathBuf,
}

impl FauxResolveur {
    fn poser() -> anyhow::Result<Self> {
        let source = std::env::current_exe().context("chemin du binaire courant")?;
        // Nom distinct de celui du faux coeur et de celui de la sonde
        // d'identite: se marcher dessus ferait sonder deux fois le meme chemin
        // sans que rien ne le signale.
        let chemin =
            std::env::temp_dir().join(format!("bifrost-faux-resolveur-{}.exe", std::process::id()));
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

impl std::fmt::Display for FauxResolveur {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.chemin.display())
    }
}

impl Drop for FauxResolveur {
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
            "faux resolveur non efface: {} (a supprimer a la main)",
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

    fn mesures(resolveur_dns: Verdict, resolveur_hors_53: Verdict, etranger: Verdict) -> Mesures {
        Mesures {
            repos: Verdict::Connecte,
            repos_dns: Verdict::Connecte,
            resolveur_dns,
            resolveur_hors_53,
            etranger,
        }
    }

    #[test]
    fn la_combinaison_attendue_vaut_reussite() {
        let m = mesures(Verdict::Connecte, Verdict::Bloque, Verdict::Bloque);
        assert_eq!(juger(m, cible(), resolveur()), Issue::Reussi);
    }

    /// LE test de ce vecteur, et le miroir exact de celui du coeur. Le
    /// resolveur amorce, aucun etranger ne sort: tout semble en ordre, et
    /// pourtant l'exception vient d'en faire un second transport, capable de
    /// sortir en clair hors tunnel vers n'importe quoi.
    #[test]
    fn un_resolveur_qui_sort_hors_du_53_est_une_fuite_et_pas_un_succes() {
        let m = mesures(Verdict::Connecte, Verdict::Connecte, Verdict::Bloque);
        match juger(m, cible(), resolveur()) {
            Issue::Echec(r) => assert!(r.contains("transport"), "{r}"),
            autre => panic!("attendu un echec, obtenu {autre:?}"),
        }
    }

    #[test]
    fn une_exception_qui_matche_tout_le_monde_est_une_fuite() {
        let m = mesures(Verdict::Connecte, Verdict::Bloque, Verdict::Connecte);
        match juger(m, cible(), resolveur()) {
            Issue::Echec(r) => assert!(r.contains("chemin"), "{r}"),
            autre => panic!("attendu un echec, obtenu {autre:?}"),
        }
    }

    /// Les deux blocages attendus sont la, mais le resolveur aussi est bloque:
    /// sans son succes, ils s'expliquent par un plan qui coupe tout et ne
    /// disent rien de la borne de l'exception.
    #[test]
    fn un_plan_qui_bloque_tout_ne_passe_pas_pour_une_exception_bornee() {
        let m = mesures(Verdict::Bloque, Verdict::Bloque, Verdict::Bloque);
        match juger(m, cible(), resolveur()) {
            Issue::Echec(r) => assert!(r.contains("ne matche pas"), "{r}"),
            autre => panic!("attendu un echec, obtenu {autre:?}"),
        }
    }

    /// `Passe` couvre l'echeance atteinte: la connexion est partie sans etre
    /// refusee, mais n'a rien joint. La lire comme un succes rendrait la mesure
    /// verte sur un bootstrap devenu muet.
    #[test]
    fn un_amorcage_qui_n_est_pas_franc_ne_conclut_pas() {
        let m = mesures(Verdict::Passe, Verdict::Bloque, Verdict::Bloque);
        assert!(matches!(juger(m, cible(), resolveur()), Issue::Ignore(_)));
    }

    #[test]
    fn un_53_deja_refuse_au_repos_ne_permet_aucune_conclusion() {
        let m = Mesures {
            repos: Verdict::Connecte,
            repos_dns: Verdict::Bloque,
            resolveur_dns: Verdict::SansRoute,
            resolveur_hors_53: Verdict::SansRoute,
            etranger: Verdict::SansRoute,
        };
        match juger(m, cible(), resolveur()) {
            Issue::Ignore(r) => assert!(r.contains("deja refuse"), "{r}"),
            autre => panic!("attendu un Ignore, obtenu {autre:?}"),
        }
    }

    /// Le temoin NEGATIF sous armement doit avoir abouti au repos. Sans cela,
    /// son refus sous armement s'expliquerait par une destination injoignable
    /// aussi bien que par le kill switch.
    #[test]
    fn une_destination_ordinaire_deja_muette_au_repos_ne_permet_aucune_conclusion() {
        let m = Mesures {
            repos: Verdict::Passe,
            repos_dns: Verdict::Connecte,
            resolveur_dns: Verdict::SansRoute,
            resolveur_hors_53: Verdict::SansRoute,
            etranger: Verdict::SansRoute,
        };
        assert!(matches!(juger(m, cible(), resolveur()), Issue::Ignore(_)));
    }

    /// Elle sert de temoin NEGATIF sous armement. La placer sur le port que
    /// l'exception ouvre rendrait la mesure vide tout en coupant le reseau de
    /// la machine pour rien.
    #[test]
    fn une_destination_ordinaire_sur_le_53_est_refusee_avant_toute_coupure() {
        let e = selftest("1.1.1.1:53".parse().unwrap(), resolveur(), true).unwrap_err();
        assert!(format!("{e}").contains("port 53"), "{e}");
    }

    /// Symetrique: sonder l'exception ailleurs que sur le port qu'elle ouvre ne
    /// dirait rien d'elle.
    #[test]
    fn un_resolveur_externe_hors_du_53_est_refuse_avant_toute_coupure() {
        let e = selftest(cible(), "9.9.9.9:853".parse().unwrap(), true).unwrap_err();
        assert!(format!("{e}").contains("port 53"), "{e}");
    }

    #[test]
    fn la_politique_declare_le_resolveur_et_garde_le_dns_en_local() {
        let p = politique(Path::new(r"C:\faux\dnscrypt-proxy.exe"), true);
        assert_eq!(
            p.resolveur_executable.as_deref(),
            Some(Path::new(r"C:\faux\dnscrypt-proxy.exe"))
        );
        assert!(
            p.resolveur_embarque,
            "sans le drapeau du profil, le plan ne poserait aucune exception"
        );
        assert_eq!(p.dns_resolver, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(
            p.coeur_executable, None,
            "declarer un coeur donnerait un permit large qui masquerait la borne"
        );
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
            &politique(std::path::Path::new("resolveur.exe"), true),
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
