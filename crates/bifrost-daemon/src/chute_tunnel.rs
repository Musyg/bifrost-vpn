//! Les vecteurs `kill-switch-on-drop` et `reconnect-window` sous Windows.
//!
//! # Ce que le tunnel apporte, et ce qu'il n'apporte pas
//!
//! Ces deux vecteurs portaient la meme raison de `Skipped`: "demande un tunnel
//! monte". C'est vrai, et cette fois le motif tient - mais pas pour la raison
//! qu'on croirait. Il ne faut pas un tunnel qui TRANSPORTE, il faut une
//! interface qui EXISTE puis qui n'existe plus: le plan WFP conditionne le
//! permit du tunnel sur un LUID, et ce qui se mesure ici est ce que ce permit
//! devient quand le LUID ne designe plus rien.
//!
//! WireGuardNT donne exactement ca sans serveur distant: un adaptateur reel,
//! son LUID, et un `Drop` qui le fait disparaitre. Aucun pair, aucun handshake,
//! aucun paquet - rien de tout cela n'entre dans ce qui est mesure.
//!
//! # `kill-switch-on-drop`: le permit d'une interface morte
//!
//! Sous Linux, `ip link del` pendant le trafic, puis on regarde la capture. Ici
//! l'adaptateur est detruit sous armement, et on redemande a sortir. Le risque
//! precis: un `Condition::Interface(luid)` dont le LUID a disparu pourrait
//! cesser de discriminer et laisser passer, ou WFP pourrait defaire les filtres
//! qui s'y referent. Les deux rouvriraient le trafic en clair au pire moment,
//! celui ou l'utilisateur croit encore etre protege.
//!
//! # `reconnect-window`: la fenetre entre deux armements
//!
//! Sous Linux, un DPI coupe le port WireGuard et le handshake echoue en boucle.
//! Sous Windows, une reconnexion signifie un NOUVEL adaptateur, donc un nouveau
//! LUID, donc un `engage()` de plus. La fenetre de fuite, s'il y en a une, est
//! entre le retrait de l'ancien plan et la pose du nouveau. `engage()` affirme
//! faire les deux dans une transaction; ce vecteur le met a l'epreuve.
//!
//! La mesure est un ECHANTILLONNAGE, et ca doit se dire: la sonde boucle dans
//! un processus unique pendant que les reengagements s'enchainent. Une fenetre
//! plus courte que l'intervalle entre deux tentatives lui echapperait. C'est
//! pour ca que la sonde est une rafale et non une tentative par processus - le
//! lancement d'un processus dure plus longtemps que la fenetre cherchee.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, anyhow};
use bifrost_core::ports::{FirewallPolicy, KillSwitch};
use bifrost_firewall::windows::WfpKillSwitch;

use crate::temoin_wfp;
use crate::tunnel::wgnt::adapter::{self, Adapter};
use crate::tunnel::wgnt::dll::WireGuardNt;
use crate::wfp_identity::{Verdict, sonder_depuis, sonder_depuis_pendant};

/// Le journal d'audit n'est pas ecrit dans la foulee de la connexion.
const FENETRE: Duration = Duration::from_secs(60);
/// Le filtre dont on attend qu'il refuse une fois le tunnel tombe.
const FILTRE_ATTENDU: &str = "block-all";
/// Nom des adaptateurs de la mesure. Distinct de celui d'un vrai tunnel et de
/// celui de l'autotest de transport: une mesure ne doit pas pouvoir demonter
/// une connexion en cours, ni un autre essai.
const NOM_ADAPTATEUR: &str = "Bifrost-chute";
/// Nombre de reengagements enchaines pendant la rafale.
const REENGAGEMENTS: usize = 6;
/// Duree de la rafale de `reconnect-window`.
const RAFALE: Duration = Duration::from_secs(4);

/// Ce que chaque vecteur a conclu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Issue {
    Reussi,
    /// La mesure n'a pas pu conclure. Jamais un succes par defaut.
    Ignore(String),
    Echec(String),
}

/// Les mesures de `kill-switch-on-drop`, sans interpretation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Chute {
    /// Au repos, avant tout armement.
    pub repos: Verdict,
    /// Sous armement, l'adaptateur du tunnel existant encore.
    pub avant: Verdict,
    /// Sous armement, l'adaptateur detruit.
    pub apres: Verdict,
    /// Apres desarmement.
    pub restaure: Verdict,
}

fn politique(interface: &str, luid: u64, lan: bool) -> FirewallPolicy {
    FirewallPolicy {
        tunnel_interface: Some(interface.to_owned()),
        tunnel_luid: Some(luid),
        fwmark: None,
        dns_resolver: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        allow_lan: lan,
        coeur_uid: None,
        coeur_executable: None,
        resolveur_uid: None,
        resolveur_executable: None,
        resolveur_sid: None,
        resolveur_embarque: false,
    }
}

/// Cree un adaptateur sous le `i`-eme identifiant reserve au vecteur.
///
/// La DLL est rechargee a chaque appel: `Adapter::create` en prend la
/// propriete, et `LoadLibrary` sur un module deja charge ne fait
/// qu'incrementer son compteur. Deux adaptateurs coexistent le temps d'une
/// reconnexion, d'ou l'alternance des identifiants.
fn adaptateur(i: usize) -> anyhow::Result<Adapter> {
    let nt = WireGuardNt::load().map_err(|e| {
        anyhow!(
            "chargement de wireguard.dll: {e}. Ces deux vecteurs demandent              WireGuardNT, dont l'adaptateur fournit le LUID que le plan WFP              conditionne"
        )
    })?;
    Adapter::create_with_guid(nt, NOM_ADAPTATEUR, &adapter::CHUTE_GUID[i % 2])
        .map_err(|e| anyhow!("creation de l'adaptateur {NOM_ADAPTATEUR}: {e}"))
}

/// Mesure les deux vecteurs. Coupe le reseau pendant les armements.
pub fn selftest(cible: SocketAddr, lan: bool) -> anyhow::Result<()> {
    let sonde = Sonde::poser()?;
    // La DLL est chargee ici une premiere fois pour echouer TOT: sans elle, la
    // mesure ne peut pas avoir lieu, et le decouvrir apres le premier armement
    // aurait coupe le reseau de la machine pour rien.
    WireGuardNt::load().map_err(|e| {
        anyhow!(
            "chargement de wireguard.dll: {e}. Ces deux vecteurs demandent \
             WireGuardNT, dont l'adaptateur fournit le LUID que le plan WFP \
             conditionne"
        )
    })?;

    println!("vecteur kill-switch-on-drop, cible {cible}");
    let chute = mesurer_chute(&sonde, cible, lan)?;
    println!("    au repos:          {:?}", chute.repos);
    println!("    tunnel present:    {:?}", chute.avant);
    println!("    tunnel DETRUIT:    {:?}", chute.apres);
    println!("    apres desarmement: {:?}", chute.restaure);
    let issue_chute = juger_chute(chute, cible);

    println!("\nvecteur reconnect-window, cible {cible}");
    let (pire, tours) = mesurer_reconnexion(&sonde, cible, lan)?;
    println!(
        "    {tours} reengagements pendant une rafale de {:?}: {pire:?}",
        RAFALE
    );
    let issue_reco = juger_reconnexion(pire, tours, cible);

    rendre("kill-switch-on-drop", issue_chute)?;
    rendre("reconnect-window", issue_reco)
}

/// Detruit l'adaptateur sous armement et redemande a sortir.
fn mesurer_chute(sonde: &Sonde, cible: SocketAddr, lan: bool) -> anyhow::Result<Chute> {
    let repos = sonde.une_fois(cible)?;
    if repos != Verdict::Connecte {
        // Rien n'est arme, donc rien a retirer, et surtout: on ne coupe pas le
        // reseau de la machine pour une mesure qui ne conclura rien.
        return Ok(Chute {
            repos,
            avant: Verdict::SansRoute,
            apres: Verdict::SansRoute,
            restaure: Verdict::SansRoute,
        });
    }

    let adaptateur = adaptateur(0)?;
    let luid = adaptateur.luid();
    println!("  adaptateur {NOM_ADAPTATEUR} cree, LUID {luid:#x}");

    let mut firewall = WfpKillSwitch::new().map_err(|e| anyhow!("ouverture du moteur WFP: {e}"))?;
    firewall
        .engage(&politique(NOM_ADAPTATEUR, luid, lan))
        .map_err(|e| anyhow!("armement avec le LUID du tunnel: {e}"))?;

    let mesure = (|| -> anyhow::Result<(Verdict, Verdict)> {
        let avant = sonde.une_fois(cible)?;
        // La panne exacte du critere de recette, transposee: l'equivalent
        // Windows d'`ip link del` pendant le trafic.
        drop(adaptateur);
        println!("  adaptateur detruit, le kill switch reste arme");
        Ok((avant, sonde.une_fois(cible)?))
    })();

    let desarmement = firewall
        .disengage()
        .map_err(|e| anyhow!("desarmement apres la chute: {e}"));
    let (avant, apres) = mesure?;
    desarmement?;

    let restaure = sonde.une_fois(cible)?;

    if apres == Verdict::Bloque {
        attribuer(&firewall, cible)?;
    }

    Ok(Chute {
        repos,
        avant,
        apres,
        restaure,
    })
}

/// Enchaine les reengagements pendant qu'une rafale tente de sortir.
///
/// La rafale part AVANT le premier reengagement et court pendant toute la
/// serie: c'est la fenetre entre deux plans qu'on cherche, pas l'etat stable de
/// part et d'autre.
fn mesurer_reconnexion(
    sonde: &Sonde,
    cible: SocketAddr,
    lan: bool,
) -> anyhow::Result<(Verdict, usize)> {
    let premier = adaptateur(0)?;
    let mut firewall = WfpKillSwitch::new().map_err(|e| anyhow!("ouverture du moteur WFP: {e}"))?;
    firewall
        .engage(&politique(NOM_ADAPTATEUR, premier.luid(), lan))
        .map_err(|e| anyhow!("armement initial: {e}"))?;

    let chemin = sonde.chemin().to_path_buf();
    let rafale = std::thread::spawn(move || sonder_depuis_pendant(&chemin, cible, Some(RAFALE)));

    // Chaque tour est une reconnexion: un nouvel adaptateur nait, l'ancien
    // meurt, et le plan est repose avec le nouveau LUID.
    //
    // La boucle est ecrite a plat et non dans une fermeture: `courant` doit
    // rester detruisible apres la boucle quoi qu'il arrive, y compris sur
    // erreur. Une fermeture le capturerait et laisserait un adaptateur
    // derriere elle sur le chemin d'echec.
    let mut courant = premier;
    let mut tours = 0usize;
    let mut serie: anyhow::Result<()> = Ok(());
    for tour in 0..REENGAGEMENTS {
        // Le nouvel adaptateur nait AVANT que l'ancien meure, comme dans le
        // produit: c'est justement la sequence ou une fenetre pourrait
        // s'ouvrir. D'ou l'alternance des identifiants.
        let suivant = match adaptateur(tour + 1) {
            Ok(a) => a,
            Err(e) => {
                serie = Err(e);
                break;
            }
        };
        courant = suivant;
        if let Err(e) = firewall.engage(&politique(NOM_ADAPTATEUR, courant.luid(), lan)) {
            serie = Err(anyhow!("reengagement: {e}"));
            break;
        }
        tours += 1;
    }

    let pire = rafale
        .join()
        .map_err(|_| anyhow!("la rafale de sondage a panique"))?;

    let desarmement = firewall
        .disengage()
        .map_err(|e| anyhow!("desarmement apres les reengagements: {e}"));
    drop(courant);
    serie?;
    desarmement?;

    Ok((pire?, tours))
}

/// Conclut sur `kill-switch-on-drop`.
pub fn juger_chute(m: Chute, cible: SocketAddr) -> Issue {
    if m.repos == Verdict::SansRoute {
        return Issue::Ignore(format!("aucune route vers {cible} au repos"));
    }
    if m.repos != Verdict::Connecte {
        return Issue::Ignore(format!(
            "le temoin negatif vers {cible} n'a pas abouti ({:?}) alors que \
             rien n'est arme: un refus sous armement ne pourrait pas etre \
             attribue au kill switch",
            m.repos
        ));
    }
    // L'ordre compte: la fuite APRES la chute est ce que ce vecteur existe pour
    // trouver, et elle se dit avant tout le reste.
    if m.apres != Verdict::Bloque {
        return Issue::Echec(format!(
            "FUITE: la connexion vers {cible} est passee ({:?}) apres la \
             destruction de l'interface du tunnel, kill switch toujours arme. \
             C'est le moment exact ou l'utilisateur croit encore etre protege",
            m.apres
        ));
    }
    if m.avant != Verdict::Bloque {
        return Issue::Echec(format!(
            "la connexion vers {cible} passait deja ({:?}) AVANT la chute, \
             tunnel present: le plan ne retenait rien, et le blocage constate \
             apres la chute ne dit donc rien de la chute",
            m.avant
        ));
    }
    if m.restaure == Verdict::Bloque {
        return Issue::Echec(format!(
            "la connexion vers {cible} est encore refusee apres le \
             desarmement: des filtres survivent au retrait, la machine reste \
             coupee"
        ));
    }
    if m.restaure != Verdict::Connecte {
        return Issue::Ignore(format!(
            "la cible {cible} ne repond plus apres le desarmement ({:?}): le \
             refus observe ne peut plus lui etre attribue",
            m.restaure
        ));
    }
    Issue::Reussi
}

/// Conclut sur `reconnect-window`.
pub fn juger_reconnexion(pire: Verdict, tours: usize, cible: SocketAddr) -> Issue {
    if tours == 0 {
        return Issue::Ignore(
            "aucun reengagement n'a eu lieu: sans reconnexion, il n'y a pas de \
             fenetre a mesurer"
                .to_owned(),
        );
    }
    match pire {
        Verdict::Bloque => Issue::Reussi,
        Verdict::SansRoute => Issue::Ignore(format!(
            "aucune route vers {cible} pendant la rafale: la pile n'a pas \
             essaye, et l'absence de fuite ne prouve rien"
        )),
        autre => Issue::Echec(format!(
            "FUITE: au moins une tentative vers {cible} n'a pas ete refusee \
             ({autre:?}) pendant {tours} reengagements. Le retrait et la repose \
             du plan ne sont donc pas atomiques, et chaque reconnexion ouvre \
             une fenetre en clair"
        )),
    }
}

fn rendre(vecteur: &str, issue: Issue) -> anyhow::Result<()> {
    match issue {
        Issue::Reussi => {
            println!("\n{vecteur}: PASSED");
            Ok(())
        }
        Issue::Ignore(raison) => {
            println!("\n{vecteur}: SKIPPED - {raison}");
            Ok(())
        }
        Issue::Echec(raison) => Err(anyhow!("{vecteur}: FAILED - {raison}")),
    }
}

/// Impute le refus d'apres chute au catch-all, nommement.
fn attribuer(firewall: &WfpKillSwitch, cible: SocketAddr) -> anyhow::Result<()> {
    let attendus = firewall.filtres_nommes(FILTRE_ATTENDU);
    if attendus.is_empty() {
        anyhow::bail!("aucun filtre nomme `{FILTRE_ATTENDU}` n'a ete pose: le plan a change");
    }
    let constat = attendre(&attendus, cible)?;
    println!(
        "  journal d'audit: {} blocages WFP dans la fenetre, dont {} imputables a `{FILTRE_ATTENDU}`",
        constat.total,
        constat.notres.len()
    );
    if constat.audit_muet() {
        println!(
            "    attribution impossible: aucun blocage WFP dans le journal, pas \
             meme ceux du pare-feu Windows. A activer avec:\n{}",
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
            "le refus vers {cible} apres la chute n'est imputable a AUCUN \
             filtre `{FILTRE_ATTENDU}` (filtres {attendus:?}): il vient donc \
             d'autre chose, et l'attribuer au kill switch serait une erreur"
        )),
    }
}

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

/// Copie du binaire, d'ou partent toutes les tentatives.
///
/// Jamais depuis le daemon: le plan l'autorise nommement, il passerait donc
/// meme kill switch arme, et chaque mesure serait verte sans rien mesurer.
struct Sonde {
    chemin: PathBuf,
}

impl Sonde {
    fn poser() -> anyhow::Result<Self> {
        let source = std::env::current_exe().context("chemin du binaire courant")?;
        let chemin = std::env::temp_dir().join(format!("bifrost-chute-{}.exe", std::process::id()));
        std::fs::copy(&source, &chemin)
            .with_context(|| format!("copie de {} vers {}", source.display(), chemin.display()))?;
        Ok(Self { chemin })
    }

    fn chemin(&self) -> &Path {
        &self.chemin
    }

    fn une_fois(&self, addr: SocketAddr) -> anyhow::Result<Verdict> {
        sonder_depuis(&self.chemin, addr)
    }
}

impl Drop for Sonde {
    fn drop(&mut self) {
        for _ in 0..5 {
            if std::fs::remove_file(&self.chemin).is_ok() {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        eprintln!(
            "copie de sonde non effacee: {} (a supprimer a la main)",
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

    fn chute(avant: Verdict, apres: Verdict, restaure: Verdict) -> Chute {
        Chute {
            repos: Verdict::Connecte,
            avant,
            apres,
            restaure,
        }
    }

    #[test]
    fn la_combinaison_attendue_vaut_reussite() {
        let m = chute(Verdict::Bloque, Verdict::Bloque, Verdict::Connecte);
        assert_eq!(juger_chute(m, cible()), Issue::Reussi);
    }

    #[test]
    fn une_sortie_apres_la_chute_est_la_fuite_cherchee() {
        // LE test de ce vecteur: tout tenait tant que l'interface existait, et
        // sa disparition a rouvert le trafic.
        let m = chute(Verdict::Bloque, Verdict::Connecte, Verdict::Connecte);
        match juger_chute(m, cible()) {
            Issue::Echec(r) => assert!(r.contains("FUITE"), "{r}"),
            autre => panic!("attendu un echec, obtenu {autre:?}"),
        }
    }

    #[test]
    fn un_plan_qui_ne_retenait_deja_rien_ne_dit_rien_de_la_chute() {
        // Le piege: le blocage d'apres chute est bien la, donc tout semble en
        // ordre. Mais si rien n'etait retenu AVANT, ce blocage vient d'ailleurs
        // et la chute n'y est pour rien.
        let m = chute(Verdict::Connecte, Verdict::Bloque, Verdict::Connecte);
        match juger_chute(m, cible()) {
            Issue::Echec(r) => assert!(r.contains("AVANT la chute"), "{r}"),
            autre => panic!("attendu un echec, obtenu {autre:?}"),
        }
    }

    #[test]
    fn un_desarmement_qui_ne_rouvre_pas_est_un_echec() {
        let m = chute(Verdict::Bloque, Verdict::Bloque, Verdict::Bloque);
        match juger_chute(m, cible()) {
            Issue::Echec(r) => assert!(r.contains("survivent au retrait"), "{r}"),
            autre => panic!("attendu un echec, obtenu {autre:?}"),
        }
    }

    #[test]
    fn une_seule_tentative_passee_suffit_a_faire_tomber_la_reconnexion() {
        // La rafale rend la plus PERMISSIVE de ses tentatives, precisement
        // pour qu'une fuite breve ne soit pas noyee par les refus voisins.
        match juger_reconnexion(Verdict::Connecte, 6, cible()) {
            Issue::Echec(r) => assert!(r.contains("atomiques"), "{r}"),
            autre => panic!("attendu un echec, obtenu {autre:?}"),
        }
        assert_eq!(
            juger_reconnexion(Verdict::Bloque, 6, cible()),
            Issue::Reussi
        );
    }

    #[test]
    fn sans_reengagement_il_n_y_a_pas_de_fenetre_a_mesurer() {
        assert!(matches!(
            juger_reconnexion(Verdict::Bloque, 0, cible()),
            Issue::Ignore(_)
        ));
    }

    #[test]
    fn une_rafale_sans_route_ne_conclut_pas() {
        assert!(matches!(
            juger_reconnexion(Verdict::SansRoute, 6, cible()),
            Issue::Ignore(_)
        ));
    }

    #[test]
    fn la_politique_porte_le_luid_du_tunnel() {
        let p = politique("Bifrost-chute", 0xdead_beef, true);
        assert_eq!(p.tunnel_luid, Some(0xdead_beef));
        assert_eq!(p.tunnel_interface.as_deref(), Some("Bifrost-chute"));
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
    fn le_filtre_attendu_est_un_filtre_que_le_plan_pose() {
        let plan = bifrost_firewall::wfp_plan::plan(
            &politique("bifrost0", 1, true),
            std::path::PathBuf::from("bifrost-daemon.exe"),
            Some(1),
        );
        let noms: Vec<&str> = plan.iter().map(|f| f.name.as_str()).collect();
        assert!(
            noms.iter().any(|n| n.contains(FILTRE_ATTENDU)),
            "aucun filtre du plan ne s'appelle `{}`: ce vecteur ne pourra imputer son refus a rien. Poses: {:?}",
            FILTRE_ATTENDU,
            noms
        );
    }
}
