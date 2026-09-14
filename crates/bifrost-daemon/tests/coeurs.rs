//! Cycle de vie d'un coeur tiers, sur un vrai processus.
//!
//! Le coeur est ici une doublure qui parle le minimum de l'API Clash, parce
//! que ni sing-box ni Xray ne sont installes sur les machines de recette et que
//! les telecharger depuis un test serait pire que le mal. Ce qui est verifie
//! est donc le SUPERVISEUR: qu'un vrai processus est lance, qu'on attend
//! vraiment sa reponse, qu'un mauvais secret echoue tot au lieu d'attendre
//! l'echeance, qu'un binaire absent est refuse avant tout lancement, et qu'un
//! coeur arrete est bien mort.
//!
//! Ce qui n'est PAS verifie ici, et qui reste a la charge d'une recette sur
//! machine equipee: que sing-box et Xray se comportent comme la doublure. Une
//! premiere part de cette dette est payee par `tests/vitalite.rs`, qui lance un
//! VRAI sing-box quand `BIFROST_COEURS` le designe et confronte a lui les
//! statuts de l'API Clash - lesquels ne sont ecrits nulle part en amont.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use bifrost_daemon::coeurs::doublure::Configuration;
use bifrost_daemon::coeurs::lancement::Lancement;
use bifrost_daemon::coeurs::{alea, clash, port, superviseur};
use bifrost_evasion::Coeur;

fn binaire_du_daemon() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_bifrost-daemon"))
}

/// Prepare une doublure prete a lancer.
///
/// Rend AUSSI la reservation de son port, que l'appelant doit liberer juste
/// avant le lancement: la garder jusqu'a la fin de sa portee empecherait la
/// doublure de lier, et la relacher trop tot rouvrirait la course que
/// [`port`] existe pour fermer.
fn doublure(repertoire: &std::path::Path) -> (Lancement, String, port::Reservation) {
    let reserve = port::reserver().unwrap();
    let port = reserve.port();
    let secret = alea::secret().unwrap();
    let config = repertoire.join("doublure.json");
    std::fs::write(
        &config,
        serde_json::to_string(&Configuration {
            port,
            secret: secret.clone(),
            // Le selecteur que `un_coeur_demarre_repond_bascule_puis_meurt`
            // pilote, avec la sortie qu'il demande.
            //
            // Il a fallu l'ecrire le 20 aout 2026, et le motif vaut d'etre
            // garde: jusque-la la doublure repondait 204 a tout `PUT
            // /proxies/`, sans selecteur ni sortie. L'assertion "la bascule
            // doit aboutir" de cette recette passait donc contre un serveur
            // qui n'avait rien a basculer - elle ne mesurait que la politesse
            // du client. Des que la doublure a commence a refuser ce qu'un
            // vrai coeur refuse, la recette est devenue rouge, ce qui est le
            // bon sens de la marche.
            selecteur: "select".to_owned(),
            sorties: vec!["reality".to_owned(), "hy2".to_owned()],
        })
        .unwrap(),
    )
    .unwrap();
    let lancement = Lancement {
        programme: binaire_du_daemon(),
        arguments: vec!["--faux-coeur".into(), config.clone().into()],
        configuration: config,
        api_clash: Some(port),
        utilisateur: None,
    };
    (lancement, secret, reserve)
}

/// Une adresse SOCKS plausible pour un coeur. Personne n'ecoute derriere: ce
/// qui est eprouve ici est la PUBLICATION de l'adresse, pas le relais.
fn socks_fictif() -> SocketAddr {
    format!("127.0.0.1:{}", port::port_sans_personne().unwrap())
        .parse()
        .unwrap()
}

/// Un repertoire de travail propre a CETTE execution de la recette.
///
/// Le nom porte le pid du processus de recette, comme `tests/vitalite.rs` et
/// `tests/reprise_linux.rs` le font deja. Un nom fixe etait partage par toutes
/// les executions de la meme recette sur la machine, et le pipeline en fait
/// tourner deux en meme temps, chacune dans sa copie: l'une effacait la
/// configuration que le petit-enfant de l'autre allait lire, et le temoin
/// d'orphelin en concluait que son petit-enfant etait "mort sans garde".
/// Mesure sur essai-linux le 05/09/2026, avec une execution jumelle de la
/// meme recette, qui reproduisait ce conflit entre deux copies concurrentes.
fn repertoire_temporaire(nom: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("bifrost-coeurs-{}-{nom}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn vivant(pid: u32) -> bool {
    #[cfg(unix)]
    {
        // SAFETY: kill avec le signal 0 ne fait que tester l'existence du
        // processus; aucun pointeur, aucune memoire partagee.
        unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
    }
    #[cfg(windows)]
    {
        // `tasklist` plutot qu'OpenProcess: la recette n'a pas a ouvrir de
        // poignee pour repondre a une question aussi simple.
        let sortie = std::process::Command::new("tasklist")
            .args(["/FI", &format!("PID eq {pid}"), "/NH"])
            .output()
            .unwrap();
        String::from_utf8_lossy(&sortie.stdout).contains(&pid.to_string())
    }
}

#[tokio::test]
async fn un_coeur_demarre_repond_bascule_puis_meurt() {
    let rep = repertoire_temporaire("cycle");
    let (lancement, secret, reserve) = doublure(&rep);
    let port = reserve.port();

    // Rendu a l'instant ou la doublure va le prendre.
    reserve.liberer();
    let en_cours = superviseur::demarrer(Coeur::SingBox, &lancement, &secret)
        .await
        .expect("la doublure doit demarrer");

    let pid = en_cours.pid().expect("le coeur doit avoir un pid");
    assert!(vivant(pid), "le coeur n'est pas la apres demarrage");
    assert_eq!(
        en_cours.api(),
        Some(SocketAddr::from(([127, 0, 0, 1], port)))
    );

    en_cours
        .choisir("select", "reality")
        .await
        .expect("la bascule doit aboutir");

    en_cours.arreter().await.expect("l'arret doit aboutir");

    // Laisse au systeme le temps de faire disparaitre le processus.
    let echeance = Instant::now() + Duration::from_secs(5);
    while vivant(pid) && Instant::now() < echeance {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(!vivant(pid), "le coeur a survecu a son arret");

    let _ = std::fs::remove_dir_all(&rep);
}

#[tokio::test]
async fn un_mauvais_secret_echoue_tot_et_ne_fait_pas_attendre_l_echeance() {
    // Le mode d'echec qui compte: sonder pendant dix secondes un coeur qui
    // repond deja, mais refuse notre secret, ferait passer une erreur de
    // configuration pour une lenteur de demarrage.
    let rep = repertoire_temporaire("secret");
    let (lancement, _bon, reserve) = doublure(&rep);
    // Rendu a l'instant ou la doublure va le prendre.
    reserve.liberer();

    let debut = Instant::now();
    let erreur = superviseur::demarrer(Coeur::SingBox, &lancement, "mauvais-secret")
        .await
        .expect_err("un secret errone doit echouer");
    let ecoule = debut.elapsed();

    assert!(
        format!("{erreur}").contains("refuse le secret"),
        "message inattendu: {erreur}"
    );
    assert!(
        ecoule < superviseur::BUDGET_DEMARRAGE,
        "l'echec a pris {ecoule:?}, soit l'echeance entiere"
    );

    let _ = std::fs::remove_dir_all(&rep);
}

#[tokio::test]
async fn un_binaire_absent_est_refuse_avant_tout_lancement() {
    let lancement = Lancement {
        programme: PathBuf::from("/opt/bifrost/coeurs/sing-box-qui-n-existe-pas"),
        arguments: vec![],
        configuration: PathBuf::from("/dev/null"),
        api_clash: Some(1),
        utilisateur: None,
    };
    let erreur = superviseur::demarrer(Coeur::SingBox, &lancement, "x")
        .await
        .expect_err("un binaire absent doit etre refuse");
    let texte = format!("{erreur}");
    assert!(texte.contains("introuvable"), "message inattendu: {texte}");
}

#[tokio::test]
async fn un_coeur_qui_sort_aussitot_est_signale_sans_attendre() {
    // Un coeur mal configure sort en une fraction de seconde. Continuer a
    // sonder son port pendant dix secondes perdrait la seule information
    // utile, qui est qu'il est mort.
    let lancement = Lancement {
        programme: binaire_du_daemon(),
        // --version fait sortir immediatement avec succes.
        arguments: vec!["--version".into()],
        configuration: PathBuf::from("."),
        api_clash: Some(port::port_sans_personne().unwrap()),
        utilisateur: None,
    };
    let debut = Instant::now();
    let erreur = superviseur::demarrer(Coeur::SingBox, &lancement, "x")
        .await
        .expect_err("un coeur qui sort doit etre signale");
    let ecoule = debut.elapsed();

    assert!(
        format!("{erreur}").contains("s'est arrete avant de repondre"),
        "message inattendu: {erreur}"
    );
    assert!(
        ecoule < superviseur::BUDGET_DEMARRAGE,
        "l'echec a pris {ecoule:?}, soit l'echeance entiere"
    );
}

/// Un faux parent lance, et ce qu'il faut pour observer son petit-enfant.
struct FauxParent {
    processus: std::process::Child,
    petit_enfant: u32,
    /// L'API du petit-enfant, pour lui demander s'il est toujours en service.
    api: SocketAddr,
    secret: String,
}

/// Lance un faux parent; le pid rendu est celui d'un petit-enfant EN SERVICE.
///
/// C'est le parent qui le garantit, dans ses deux branches (voir
/// `doublure::parent`): il n'annonce un pid qu'une fois l'API du petit-enfant
/// interrogee avec succes. Un parent qui n'annonce rien a echoue avant, et son
/// statut de sortie et sa sortie d'erreur sont rendus dans la panique: une
/// panne de demarrage doit se lire comme telle, jamais comme une propriete de
/// la garde.
fn lancer_parent(rep: &std::path::Path, avec_garde: bool) -> FauxParent {
    lancer_parent_sous(rep, avec_garde, None)
}

/// Combien de fois retenter une mise en place ratee par une course
/// d'environnement.
///
/// Le port reserve est LIBERE juste avant que le petit-enfant ne le relie, et
/// `coeurs/port.rs` documente cette fenetre comme non fermable sans passer le
/// descripteur deja lie, ce qu'aucun coeur tiers n'accepte. Sous une forte
/// pression sur la plage ephemere, le bind du petit-enfant peut perdre son port
/// et il sort a la naissance: ce n'est pas la propriete d'anti-orphelin que la
/// recette mesure, c'est un echec de MISE EN PLACE. On la retente donc, avec
/// une reservation fraiche, un nombre borne de fois. Un echec PERSISTANT (un
/// vrai defaut, ou une falsification de la borne) epuise les essais et rougit
/// en nommant la cause. Une tempete artificielle sur la plage ephemere,
/// mesuree sur essai-linux le 05/09/2026, reproduisait cet echec 1 fois sur
/// 60 sans cette reprise, 0 avec.
const ESSAIS_DEMARRAGE: u32 = 5;

fn lancer_parent_sous(
    rep: &std::path::Path,
    avec_garde: bool,
    utilisateur: Option<(u32, u32)>,
) -> FauxParent {
    use std::io::{BufRead, BufReader, Read};

    let mut derniere_plainte = String::from("aucun essai");
    for essai in 1..=ESSAIS_DEMARRAGE {
        // Une reservation FRAICHE a chaque essai: si le port precedent a ete
        // vole, celui-ci en obtient un autre.
        let (lancement, secret, reserve) = doublure(rep);
        let api = SocketAddr::from(([127, 0, 0, 1], reserve.port()));
        let config = lancement.configuration;
        // Rendu a l'instant ou la doublure va le prendre.
        reserve.liberer();

        let mut commande = std::process::Command::new(binaire_du_daemon());
        commande
            .arg("--faux-parent")
            .arg(&config)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        if !avec_garde {
            commande.arg("--faux-parent-sans-garde");
        }
        if let Some((uid, gid)) = utilisateur {
            commande
                .arg("--faux-parent-utilisateur")
                .arg(format!("{uid}:{gid}"));
        }
        let mut parent = commande.spawn().unwrap();

        let mut ligne = String::new();
        BufReader::new(parent.stdout.take().unwrap())
            .read_line(&mut ligne)
            .unwrap();
        if let Ok(petit_enfant) = ligne.trim().parse::<u32>() {
            return FauxParent {
                processus: parent,
                petit_enfant,
                api,
                secret,
            };
        }
        // Pas de pid: le parent a echoue AVANT d'annoncer, et a deja tue son
        // petit-enfant rate (voir `doublure::parent`). On note pourquoi et on
        // retente.
        let statut = parent
            .wait()
            .map(|s| s.to_string())
            .unwrap_or_else(|e| e.to_string());
        let mut plainte = String::new();
        if let Some(mut flux) = parent.stderr.take() {
            let _ = flux.read_to_string(&mut plainte);
        }
        derniere_plainte = format!(
            "essai {essai}/{ESSAIS_DEMARRAGE}, statut {statut}: {}",
            plainte.trim()
        );
    }
    panic!(
        "le parent n'a annonce aucun pid en {ESSAIS_DEMARRAGE} essais: echec de demarrage du \
         petit-enfant, la garde n'est pas en cause. Derniere plainte: {derniere_plainte}"
    );
}

fn tuer_brutalement(parent: &mut std::process::Child) {
    #[cfg(unix)]
    // SAFETY: parent.id() est le pid positif d'un enfant encore possede;
    // kill ne touche aucune memoire.
    unsafe {
        libc::kill(parent.id() as libc::pid_t, libc::SIGKILL);
    }
    #[cfg(windows)]
    {
        let _ = std::process::Command::new("taskkill")
            .args(["/F", "/PID", &parent.id().to_string()])
            .output();
    }
    let _ = parent.wait();
}

fn attendre_mort(pid: u32, delai: Duration) -> bool {
    let echeance = Instant::now() + delai;
    while Instant::now() < echeance {
        if !vivant(pid) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    !vivant(pid)
}

#[test]
fn un_coeur_ne_survit_pas_a_la_mort_brutale_du_daemon() {
    // La propriete que rien d'autre ne peut prouver. Un coeur orphelin garde
    // son ecoute locale ouverte, donc une sortie que plus personne ne
    // supervise. Le code d'arret ne protege pas de ce cas: quand le daemon est
    // tue net, il ne tourne pas.
    let rep = repertoire_temporaire("orphelin");
    let mut parent = lancer_parent(&rep, true);
    let petit_enfant = parent.petit_enfant;
    assert!(vivant(petit_enfant), "le coeur n'a pas demarre");

    tuer_brutalement(&mut parent.processus);

    assert!(
        attendre_mort(petit_enfant, Duration::from_secs(10)),
        "le coeur a survecu a la mort brutale du daemon: PR_SET_PDEATHSIG ou l'objet Job ne fait pas son office"
    );
    let _ = std::fs::remove_dir_all(&rep);
}

/// La garde anti-orphelin survit-elle a la baisse de privilege?
///
/// La question n'est pas rhetorique. `PR_SET_PDEATHSIG` est efface quand les
/// credentials d'un processus changent de facon a le rendre non "dumpable".
/// Notre garde est posee dans une closure `pre_exec`, et l'UID est baisse par
/// la bibliotheque standard: si elle appliquait l'UID APRES nos closures, la
/// garde serait posee puis effacee, et un coeur survivrait au daemon sans que
/// rien ne le signale. Le mode d'echec est silencieux, donc il se mesure.
///
/// `nobody` plutot qu'un compte cree pour l'occasion: il existe partout, et un
/// test qui fabrique des comptes systeme laisse des traces sur la machine.
#[cfg(target_os = "linux")]
#[test]
fn la_garde_anti_orphelin_survit_a_la_baisse_de_privilege() {
    use std::os::unix::fs::PermissionsExt;

    const NOBODY: (u32, u32) = (65534, 65534);

    // SAFETY: geteuid ne prend aucun argument et ne peut pas echouer.
    if unsafe { libc::geteuid() } != 0 {
        println!(
            "SKIPPED la_garde_anti_orphelin_survit_a_la_baisse_de_privilege: \
             baisser l'UID demande root, or ce test tourne sous l'uid {}",
            // SAFETY: geteuid ne prend aucun argument et ne peut pas echouer.
            unsafe { libc::geteuid() }
        );
        return;
    }

    let rep = repertoire_temporaire("orphelin-privilege");
    // Le compte cible doit pouvoir traverser jusqu'au binaire et lire sa
    // configuration; le chown de celle-ci est fait par le superviseur.
    let _ = std::fs::set_permissions(&rep, std::fs::Permissions::from_mode(0o755));

    let mut parent = lancer_parent_sous(&rep, true, Some(NOBODY));
    let petit_enfant = parent.petit_enfant;
    assert!(vivant(petit_enfant), "le coeur n'a pas demarre sous nobody");

    // Il tourne bien sous le compte demande, sinon on mesurerait la garde d'un
    // processus qui n'a jamais change de credentials.
    let statut = std::fs::read_to_string(format!("/proc/{petit_enfant}/status")).unwrap();
    let ligne = statut
        .lines()
        .find(|l| l.starts_with("Uid:"))
        .expect("champ Uid absent");
    assert!(
        ligne.split_whitespace().skip(1).all(|v| v == "65534"),
        "le coeur ne tourne pas sous nobody: {ligne}"
    );

    tuer_brutalement(&mut parent.processus);

    let mort = attendre_mort(petit_enfant, Duration::from_secs(10));
    let _ = std::fs::remove_dir_all(&rep);
    assert!(
        mort,
        "la baisse de privilege a efface PR_SET_PDEATHSIG: le coeur survit au daemon"
    );
}

/// Combien de temps le temoin laisse a l'orphelin pour REPONDRE.
///
/// Le budget du demarrage, et non trois secondes de survie: ce qui est attendu
/// est une reponse, pas l'ecoulement d'un delai. Un processus qui ne se fait
/// pas ordonnancer en dix secondes n'est plus une mesure de la garde, et
/// l'echeance est alors nommee.
const BUDGET_REPONSE_ORPHELIN: Duration = superviseur::BUDGET_DEMARRAGE;

/// L'orphelin repond-il ENCORE, son parent mort et reape.
///
/// # Pourquoi une reponse, et non "encore vivant apres trois secondes"
///
/// Jusqu'au 05/09/2026 le temoin exigeait que le petit-enfant soit encore la
/// trois secondes apres la mort du parent. C'est une hypothese de temps dans
/// les deux sens: un petit-enfant mort de son DEMARRAGE dans ces trois
/// secondes signait un rouge sans rapport avec la garde (c'est le faux rouge
/// du 04/09/2026 sur essai-linux), et un petit-enfant que la garde aurait tue
/// plus tard aurait signe un vert.
///
/// Une reponse de l'API recue APRES que `wait()` a rendu le parent prouve que
/// le petit-enfant a execute du code apres son reparentage. Or c'est au
/// reparentage que `PR_SET_PDEATHSIG` fait signaler l'enfant, et un signal
/// fatal pendant se consomme avant tout retour en espace utilisateur: le meme
/// processus, avec la garde, ne peut pas repondre. Sous Windows l'objet Job
/// termine ses membres a la fermeture de sa derniere poignee, que la mort du
/// parent emporte, et un processus termine ne repond pas davantage. La mesure
/// ne depend donc plus de la vitesse de la machine: elle attend un fait,
/// bornee par [`BUDGET_REPONSE_ORPHELIN`], et nomme ce qui manque quand il
/// manque.
fn repond_orphelin(pid: u32, api: SocketAddr, secret: &str) -> Result<(), String> {
    let executeur = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let debut = Instant::now();
    let mut derniere = String::from("aucune tentative");
    loop {
        if !vivant(pid) {
            return Err(format!(
                "mort apres la mort de son parent (derniere reponse de l'API: {derniere})"
            ));
        }
        if debut.elapsed() >= BUDGET_REPONSE_ORPHELIN {
            return Err(format!(
                "n'a pas repondu sur {api} en {BUDGET_REPONSE_ORPHELIN:?} apres la mort de \
                 son parent, {}; derniere reponse de l'API: {derniere}",
                etat_du_processus(pid)
            ));
        }
        match executeur.block_on(clash::interroger_version(api, secret)) {
            Ok(_) => return Ok(()),
            Err(e) => derniere = e.to_string(),
        }
        std::thread::sleep(clash::PAS_DE_SONDAGE);
    }
}

/// La ligne `State:` du processus, pour distinguer un zombie d'un vivant qui
/// ne se fait pas ordonnancer. Une chaine, jamais une panique: c'est un
/// diagnostic de chemin d'echec.
fn etat_du_processus(pid: u32) -> String {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string(format!("/proc/{pid}/status"))
            .ok()
            .and_then(|s| {
                s.lines()
                    .find(|l| l.starts_with("State:"))
                    .map(str::to_owned)
            })
            .unwrap_or_else(|| "etat illisible dans /proc".to_owned())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        "etat non lu sur cette plateforme".to_owned()
    }
}

#[test]
fn sans_la_garde_le_coeur_survit_bel_et_bien() {
    // Temoin negatif. Sans lui, la recette precedente passerait aussi bien si
    // le systeme tuait les orphelins de lui-meme, et ne prouverait rien de la
    // garde qu'on croit avoir posee.
    //
    // Le pid lu est celui d'un petit-enfant qui a REPONDU avant d'etre annonce
    // (voir `lancer_parent`), et sa survie se mesure par une reponse APRES la
    // mort du parent (voir `repond_orphelin`): ni l'une ni l'autre ne depend
    // de la vitesse de la machine.
    let rep = repertoire_temporaire("orphelin-temoin");
    let mut parent = lancer_parent(&rep, false);
    let petit_enfant = parent.petit_enfant;
    assert!(vivant(petit_enfant), "le coeur n'a pas demarre");

    tuer_brutalement(&mut parent.processus);

    let issue = repond_orphelin(petit_enfant, parent.api, &parent.secret);

    // Nettoyage AVANT l'assertion: un echec ne doit pas laisser trainer un
    // processus sur la machine de recette.
    #[cfg(unix)]
    // SAFETY: petit_enfant est le pid positif du processus lance; kill ne
    // touche aucune memoire.
    unsafe {
        libc::kill(petit_enfant as libc::pid_t, libc::SIGKILL);
    }
    #[cfg(windows)]
    {
        let _ = std::process::Command::new("taskkill")
            .args(["/F", "/PID", &petit_enfant.to_string()])
            .output();
    }
    let _ = std::fs::remove_dir_all(&rep);

    if let Err(raison) = issue {
        panic!(
            "le petit-enfant ne repond plus sans garde: {raison}. La recette d'orphelin ne \
             prouve donc rien"
        );
    }
}

#[tokio::test]
async fn un_coeur_sans_api_clash_demarre_sans_rien_attendre() {
    // AmneziaWG n'expose pas d'API Clash. Attendre une reponse de sa part
    // bloquerait jusqu'a l'echeance sur un coeur pourtant sain.
    let rep = repertoire_temporaire("sans-api");
    let (mut lancement, secret, reserve) = doublure(&rep);
    lancement.api_clash = None;
    // Rendu a l'instant ou la doublure va le prendre.
    reserve.liberer();

    let debut = Instant::now();
    let en_cours = superviseur::demarrer(Coeur::AmneziaWg, &lancement, &secret)
        .await
        .expect("un coeur sans API doit demarrer");
    // Comparer a l'echeance que l'on refuse d'attendre, comme les deux autres
    // recettes de ce fichier, et NON a une constante en dur.
    //
    // Le seuil precedent, deux secondes, encodait la vitesse de la machine et
    // non la propriete: un demarrage de processus sous charge le depassait
    // alors que le sursis sans API reste de SURSIS_SANS_API. C'est ce qui a
    // rendu cette recette instable pendant trois passes de `--workspace`, avec
    // toujours la meme signature "6 passed; 1 failed", sans qu'aucune
    // regression existe. Mesure du 17 aout 2026: echec a plus de deux
    // secondes, dans une cible entiere bouclee en 5,3 s, donc tres loin des
    // dix secondes qu'une vraie attente de l'API aurait coutees.
    let ecoule = debut.elapsed();
    assert!(
        ecoule < superviseur::BUDGET_DEMARRAGE,
        "le demarrage a pris {ecoule:?}, soit l'echeance entiere: le coeur \
         sans API a attendu une reponse qui ne viendra jamais, alors que le \
         sursis prevu est de {:?}",
        superviseur::SURSIS_SANS_API
    );
    assert!(en_cours.api().is_none());

    // Et le piloter doit etre refuse explicitement plutot que d'echouer sur
    // une adresse fabriquee.
    let erreur = en_cours
        .choisir("select", "x")
        .await
        .expect_err("piloter un coeur sans API doit etre refuse");
    assert!(format!("{erreur}").contains("n'expose pas d'API Clash"));

    en_cours.arreter().await.unwrap();
    let _ = std::fs::remove_dir_all(&rep);
}

/// Le pont synchrone vers l'atelier, dans sa forme de PRODUCTION: un fil
/// systeme ordinaire, hors du runtime, qui bloque sur la reponse.
///
/// Ce que ce test verifie et qu'aucun test unitaire ne peut donner: qu'un vrai
/// processus est lance depuis l'autre cote de la frontiere, que le fil
/// appelant recupere de quoi le decrire, et que l'arret le tue vraiment.
#[test]
fn l_atelier_lance_un_vrai_coeur_depuis_un_fil_synchrone() {
    let rep = repertoire_temporaire("atelier-cycle");
    let (lancement, secret, reserve) = doublure(&rep);
    // Rendu a l'instant ou la doublure va le prendre.
    reserve.liberer();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let (poignee, _coeur_actif, tache) = bifrost_daemon::coeurs::atelier::ouvrir();
    runtime.spawn(tache);

    // Le fil du superviseur de tunnel: pas de runtime, il bloque.
    let fil = std::thread::spawn(move || {
        let lance = poignee
            .lancer(Coeur::SingBox, lancement, &secret, socks_fictif())
            .expect("la doublure doit se lancer par l'atelier");
        let pid = lance.pid.expect("un coeur lance a un pid");
        assert!(vivant(pid), "le processus doit tourner");
        poignee.arreter().expect("l'arret doit aboutir");
        pid
    });
    let pid = fil.join().expect("le fil ne doit pas paniquer");

    assert!(
        attendre_mort(pid, Duration::from_secs(5)),
        "le coeur doit etre mort apres l'arret"
    );
    let _ = std::fs::remove_dir_all(&rep);
}

/// Tue un processus par son PID, jamais par un motif de nom.
///
/// Un `pkill` par motif a deja coupe des services sans rapport sur une machine
/// de la flotte. Le PID ne vise que ce qu'on a lance.
fn tuer(pid: u32) {
    #[cfg(unix)]
    // SAFETY: pid est le pid positif du processus qu'on a lance; kill ne
    // touche aucune memoire.
    unsafe {
        libc::kill(pid as libc::pid_t, libc::SIGKILL);
    }
    #[cfg(windows)]
    {
        let _ = std::process::Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/F"])
            .output();
    }
}

/// Un coeur qui meurt de LUI-MEME est depublie.
///
/// La propriete que cette recette garde est celle qui manquait: l'atelier ne
/// se reveillait qu'a la demande suivante, donc un coeur sorti tout seul -
/// binaire qui panique, serveur qui coupe, OOM killer - restait publie. La
/// facade continuait de mener vers un port mort, et le tunnel par coeur se
/// croyait vivant puisque son interface tenait toujours debout.
///
/// Le coeur est tue par SIGKILL, donc sans le moindre arret propre: c'est le
/// cas le plus defavorable, et celui qu'aucune fermeture ordonnee ne signale.
#[test]
fn un_coeur_qui_meurt_tout_seul_est_depublie() {
    let rep = repertoire_temporaire("mort-solitaire");
    let (lancement, secret, reserve) = doublure(&rep);
    let socks = socks_fictif();
    // Rendu a l'instant ou la doublure va le prendre.
    reserve.liberer();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let (poignee, mut suivre, tache) = bifrost_daemon::coeurs::atelier::ouvrir();
    runtime.spawn(tache);

    // La poignee est CLONEE pour le fil, et l'originale reste ici: la deposer
    // fermerait le canal de l'atelier, qui arreterait le coeur en partant. La
    // recette mesurerait alors sa propre sortie plutot qu'une mort subie.
    let pour_le_fil = poignee.clone();
    let fil = std::thread::spawn(move || {
        pour_le_fil
            .lancer(Coeur::SingBox, lancement, &secret, socks)
            .expect("la doublure doit se lancer")
            .pid
            .expect("un coeur lance a un pid")
    });
    let pid = fil.join().expect("le fil ne doit pas paniquer");

    // Publie tant qu'il vit: sans ce temoin, la recette passerait aussi si
    // l'atelier ne publiait jamais rien.
    assert_eq!(
        *suivre.borrow_and_update(),
        Some(socks),
        "un coeur vivant doit etre publie"
    );

    tuer(pid);

    runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(10), async {
            while suivre.borrow_and_update().is_some() {
                suivre.changed().await.expect("le canal doit rester ouvert");
            }
        })
        .await
        .expect("l'atelier devait depublier le coeur mort");
    });

    assert!(
        attendre_mort(pid, Duration::from_secs(5)),
        "le processus doit bien avoir disparu"
    );
    drop(poignee);
    let _ = std::fs::remove_dir_all(&rep);
}

/// L'atelier n'en detient jamais deux. Un coeur oublie garderait son ecoute
/// SOCKS ouverte, donc une sortie que plus personne ne supervise et que le kill
/// switch ne connait pas: le danger que l'en-tete du superviseur designe.
#[test]
fn un_second_lancement_arrete_le_premier() {
    let rep = repertoire_temporaire("atelier-un-seul");
    let (premier, secret_a, reserve_a) = doublure(&rep);
    let rep_b = repertoire_temporaire("atelier-un-seul-b");
    let (second, secret_b, reserve_b) = doublure(&rep_b);
    // Rendus a l'instant ou les doublures vont les prendre.
    reserve_a.liberer();
    reserve_b.liberer();
    let (socks_a, socks_b) = (socks_fictif(), socks_fictif());
    assert_ne!(socks_a, socks_b, "deux coeurs, deux adresses");

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let (poignee, _coeur_actif, tache) = bifrost_daemon::coeurs::atelier::ouvrir();
    runtime.spawn(tache);

    let fil = std::thread::spawn(move || {
        let a = poignee
            .lancer(Coeur::SingBox, premier, &secret_a, socks_a)
            .expect("le premier coeur doit se lancer");
        let b = poignee
            .lancer(Coeur::SingBox, second, &secret_b, socks_b)
            .expect("le second coeur doit se lancer");
        poignee.arreter().expect("l'arret doit aboutir");
        (a.pid.unwrap(), b.pid.unwrap())
    });
    let (pid_a, pid_b) = fil.join().expect("le fil ne doit pas paniquer");

    assert_ne!(pid_a, pid_b, "deux lancements, deux processus");
    assert!(
        attendre_mort(pid_a, Duration::from_secs(5)),
        "le premier coeur devait etre arrete par le second lancement"
    );
    assert!(
        attendre_mort(pid_b, Duration::from_secs(5)),
        "le second coeur devait etre arrete par l'arret"
    );
    let _ = std::fs::remove_dir_all(&rep);
    let _ = std::fs::remove_dir_all(&rep_b);
}

/// Arreter quand rien ne tourne n'est pas une panne: une deconnexion qui
/// echouerait pour cette raison ferait passer un etat propre pour un incident.
#[test]
fn arreter_sans_coeur_en_cours_reussit() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let (poignee, _coeur_actif, tache) = bifrost_daemon::coeurs::atelier::ouvrir();
    runtime.spawn(tache);
    std::thread::spawn(move || poignee.arreter())
        .join()
        .expect("le fil ne doit pas paniquer")
        .expect("arreter sans coeur doit reussir");
}

/// L'atelier publie l'adresse du coeur actif, et la RETIRE des qu'il s'arrete.
///
/// L'ordre compte: publier avant que le coeur soit vivant enverrait la facade
/// vers un port que personne n'ecoute; la retirer apres l'arret laisserait la
/// facade mener des octets vers un processus qui meurt, et le client verrait
/// une coupure au lieu d'un refus franc.
#[test]
fn l_atelier_publie_le_coeur_actif_et_le_retire_a_l_arret() {
    let rep = repertoire_temporaire("atelier-publication");
    let (lancement, secret, reserve) = doublure(&rep);
    let socks = socks_fictif();
    // Rendu a l'instant ou la doublure va le prendre.
    reserve.liberer();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let (poignee, coeur_actif, tache) = bifrost_daemon::coeurs::atelier::ouvrir();
    runtime.spawn(tache);

    assert_eq!(
        *coeur_actif.borrow(),
        None,
        "rien ne doit etre publie avant qu'un coeur tourne"
    );

    let apres = std::thread::spawn(move || {
        poignee
            .lancer(Coeur::SingBox, lancement, &secret, socks)
            .expect("la doublure doit se lancer");
        let pendant = *coeur_actif.borrow();
        poignee.arreter().expect("l'arret doit aboutir");
        (pendant, *coeur_actif.borrow())
    })
    .join()
    .expect("le fil ne doit pas paniquer");

    assert_eq!(
        apres.0,
        Some(socks),
        "l'adresse du coeur devait etre publiee"
    );
    assert_eq!(apres.1, None, "l'arret devait retirer l'adresse");
    let _ = std::fs::remove_dir_all(&rep);
}
