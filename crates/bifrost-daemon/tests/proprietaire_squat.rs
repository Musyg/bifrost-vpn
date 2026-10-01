//! Un squatteur de la boucle locale ne recoit ni le secret de l'API, ni le
//! trafic: le daemon n'ecrit qu'au coeur qu'il a lance.
//!
//! # Le defaut que ces recettes tiennent
//!
//! `superviseur::demarrer` sondait `127.0.0.1:<api>` sans savoir qui l'ecoutait.
//! Le port par defaut est fixe (9090). Un compte ordinaire qui liait ce port
//! AVANT le coeur recevait `Authorization: Bearer <secret>`, et pouvait repondre
//! a la place du coeur - version, vitalite, selection - un coeur imposteur que
//! le daemon croyait sien. Sur l'entree SOCKS, le squatteur recevrait le trafic
//! de l'utilisateur en clair, avant chiffrement.
//!
//! # La classe entiere, pas seulement le lancement
//!
//! Fermer le seul lancement designerait le chemin qui reste: un coeur qui MEURT
//! en cours de session relache ses ports, et un squatteur qui les reprend
//! recevrait alors ce que la sonde de vitalite, la bascule et la facade lui
//! envoient au prochain usage. C'est pourquoi ces trois-la reverifient le
//! proprietaire de l'ecoute AVANT chaque envoi du secret et avant chaque
//! nouvelle connexion qui porte du trafic. Les recettes `..._en_session`
//! mesurent ce cas: le port publie n'est plus tenu par le coeur, et le squatteur
//! n'obtient rien.
//!
//! Ces recettes MESURENT ce qu'un squatteur obtient (rien, apres correction) et
//! ce que le daemon fait (il refuse en nommant l'erreur). L'ecouteur de test ne
//! fait qu'enregistrer ce qu'il recoit; ce n'est pas un outil d'attaque.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bifrost_daemon::coeurs::doublure::{self, Configuration, Essai, Gabarit, Liaison};
use bifrost_daemon::coeurs::lancement::Lancement;
use bifrost_daemon::coeurs::proprietaire::{self, Proprietaire};
use bifrost_daemon::coeurs::{alea, atelier, bascule, clash, facade, superviseur, vitalite};
use bifrost_evasion::Coeur;

/// Budget confie a la sonde et a la bascule dans les recettes en session.
const BUDGET: Duration = Duration::from_secs(5);

/// Un enfant VIVANT qui ne tient pas le port sonde: il joue le coeur qu'on a
/// lance et qui a relache son port (mort en session), pendant qu'un squatteur le
/// tient. La sonde verifie que le port est tenu par CE pid et constate que non.
///
/// Vivant plutot que deja mort pour rendre le verdict deterministe sur les deux
/// plateformes: l'ecoute existe (le squatteur), elle appartient a un tiers, donc
/// `Autre` des deux cotes. Un pid deja mort donnerait `Illisible` sous Linux et
/// `Autre` sous Windows: meme refus, mais deux chemins. Tue par PID juste apres.
fn coeur_qui_a_relache_son_port() -> std::process::Child {
    let mut commande = if cfg!(windows) {
        let mut c = std::process::Command::new("ping");
        c.args(["-n", "31", "127.0.0.1"]);
        c
    } else {
        let mut c = std::process::Command::new("sleep");
        c.arg("30");
        c
    };
    commande
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("un enfant vivant de test doit se lancer")
}

fn binaire_du_daemon() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_bifrost-daemon"))
}

/// Une doublure sans selecteur, montee et lancee par
/// [`doublure::lancer_sauf_vol`] ou [`doublure::demarrer_sauf_vol`]: un nouvel
/// essai seulement si elle a PROUVE que son port lui a ete pris avant son
/// `bind`. Un refus de reconnaissance d'une doublure qui tient son port rougit
/// au premier essai.
fn gabarit() -> Gabarit {
    Gabarit {
        programme: binaire_du_daemon(),
        selecteur: String::new(),
        sorties: vec![],
    }
}

/// Un repertoire de travail propre a CETTE execution, comme les autres recettes
/// de coeur: le pid dans le nom evite que deux executions concurrentes se
/// marchent dessus.
fn repertoire_temporaire(nom: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("bifrost-squat-{}-{nom}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

/// Ce que le squatteur a vu passer.
#[derive(Default)]
struct CeQuIlAVu {
    /// Le secret lu dans un en-tete `Authorization: Bearer ...`, si le daemon
    /// a fini par lui parler.
    secret_recu: Option<String>,
    /// Nombre de connexions acceptees, pour distinguer << rien recu >> de
    /// << jamais contacte >>.
    connexions: u32,
}

/// Un ecouteur de test qui prend un port de la boucle locale et NOTE ce que le
/// daemon lui envoie, en repondant comme le ferait une API Clash pour ne pas se
/// trahir. Il n'agit pas: il observe.
struct Squatteur {
    port: u16,
    vu: Arc<Mutex<CeQuIlAVu>>,
    stop: Arc<AtomicBool>,
    fil: Option<std::thread::JoinHandle<()>>,
}

impl Squatteur {
    /// Prend un port libre de la boucle et se met a l'ecoute AVANT que le coeur
    /// ne demarre. C'est la premiere moitie du defaut: qui arrive d'abord tient
    /// le port.
    fn prendre_le_port() -> Squatteur {
        Squatteur::sur(TcpListener::bind("127.0.0.1:0").expect("un port libre sur la boucle"))
    }

    /// Le meme observateur sur une ecoute deja liee, a l'adresse et avec les
    /// options que la recette a choisies.
    fn sur(ecoute: TcpListener) -> Squatteur {
        let port = ecoute.local_addr().unwrap().port();
        ecoute
            .set_nonblocking(true)
            .expect("l'ecoute doit passer en non bloquant");
        let vu = Arc::new(Mutex::new(CeQuIlAVu::default()));
        let stop = Arc::new(AtomicBool::new(false));
        let vu_fil = Arc::clone(&vu);
        let stop_fil = Arc::clone(&stop);
        let fil = std::thread::spawn(move || servir(ecoute, &vu_fil, &stop_fil));
        Squatteur {
            port,
            vu,
            stop,
            fil: Some(fil),
        }
    }

    fn adresse(&self) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], self.port))
    }

    /// Arrete le fil et rend ce qu'il a vu. Appele une fois le daemon revenu:
    /// s'il n'a rien envoye, le squatteur n'a rien vu.
    fn recolter(mut self) -> CeQuIlAVu {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(fil) = self.fil.take() {
            let _ = fil.join();
        }
        std::mem::take(&mut *self.vu.lock().unwrap())
    }
}

impl Drop for Squatteur {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(fil) = self.fil.take() {
            let _ = fil.join();
        }
    }
}

/// La boucle du squatteur: accepte, lit la requete, note le secret s'il y est,
/// repond une version plausible, recommence jusqu'au signal d'arret.
fn servir(ecoute: TcpListener, vu: &Mutex<CeQuIlAVu>, stop: &AtomicBool) {
    while !stop.load(Ordering::SeqCst) {
        match ecoute.accept() {
            Ok((mut flux, _)) => {
                flux.set_read_timeout(Some(Duration::from_millis(500))).ok();
                let mut tampon = [0u8; 4096];
                let n = flux.read(&mut tampon).unwrap_or(0);
                let requete = String::from_utf8_lossy(&tampon[..n]).into_owned();
                {
                    let mut vu = vu.lock().unwrap();
                    vu.connexions += 1;
                    if let Some(secret) = secret_du_bearer(&requete) {
                        vu.secret_recu = Some(secret);
                    }
                }
                // Repondre une version, comme une vraie API: c'est ce qui
                // ferait croire au daemon non corrige que le coeur est pret.
                let corps = "{\"version\":\"squatteur\"}";
                let reponse = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{corps}",
                    corps.len()
                );
                let _ = flux.write_all(reponse.as_bytes());
                let _ = flux.flush();
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(_) => break,
        }
    }
}

/// Le secret porte par un en-tete `Authorization: Bearer <secret>`.
fn secret_du_bearer(requete: &str) -> Option<String> {
    for ligne in requete.lines() {
        if let Some(reste) = ligne.strip_prefix("Authorization: Bearer ") {
            return Some(reste.trim().to_owned());
        }
    }
    None
}

/// # Le defaut, mesure
///
/// Un squatteur tient le port de l'API AVANT le coeur. Apres correction,
/// `demarrer` refuse en nommant l'erreur, et le squatteur n'a JAMAIS recu le
/// secret. Contre le code d'avant la correction, cette recette est rouge: le
/// squatteur recoit le secret (`secret_recu` est renseigne).
#[tokio::test]
async fn un_squatteur_de_l_api_ne_recoit_jamais_le_secret() {
    let squatteur = Squatteur::prendre_le_port();
    let port = squatteur.port;

    // Une doublure configuree sur le MEME port, que le squatteur tient deja:
    // le coeur echouerait a lier, mais le point n'est pas la - c'est que le
    // daemon ne doit pas parler a l'ecouteur en place, qui n'est pas son
    // enfant.
    let rep = repertoire_temporaire("api");
    let secret = alea::secret().unwrap();
    let config = rep.join("doublure.json");
    std::fs::write(
        &config,
        serde_json::to_string(&Configuration {
            port,
            secret: secret.clone(),
            selecteur: String::new(),
            sorties: vec![],
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

    let issue = superviseur::demarrer(Coeur::SingBox, &lancement, &secret).await;

    let vu = squatteur.recolter();

    assert!(
        vu.secret_recu.is_none(),
        "le secret a fui vers le squatteur: {:?}",
        vu.secret_recu
    );
    let erreur = issue.expect_err("demarrer doit refuser un port tenu par un autre processus");
    let texte = format!("{erreur}");
    // Deux chemins de refus, et les deux sont fail-closed. Quand le port est
    // tenu par un tiers, le vrai coeur ne peut pas lier et meurt: selon la
    // plateforme, la verification voit soit un proprietaire ETRANGER (`Autre`),
    // soit un enfant deja mort dont on ne peut plus lire les descripteurs
    // (`Illisible`, sur Linux ou l'on n'est pas root dans la recette). Les deux
    // messages disent que le secret ne sera pas envoye: c'est la propriete qui
    // compte, et elle est mesuree juste au-dessus par `secret_recu.is_none()`.
    assert!(
        texte.contains("sera pas envoye"),
        "l'erreur doit dire que le secret ne part pas, pas un simple echec de demarrage: {texte}"
    );

    let _ = std::fs::remove_dir_all(&rep);
}

/// # Le versant positif
///
/// Le coeur qu'on a REELLEMENT lance est accepte. Sans cette recette, refuser
/// tout le monde passerait la precedente sans rien prouver d'utile. La doublure
/// prend un port a elle, le daemon la reconnait comme son enfant, et
/// l'interroge.
#[tokio::test]
async fn le_coeur_qu_on_a_lance_est_bien_reconnu() {
    let rep = repertoire_temporaire("legitime");
    // La duree du SEUL demarrage qui a abouti: un essai qu'un vol de port a
    // coute ne compte pas dans ce que la reconnaissance coute.
    let mut duree = Duration::ZERO;
    let (en_cours, essai) = doublure::demarrer_sauf_vol(&rep, &gabarit(), async |e: &Essai| {
        let debut = Instant::now();
        let r = superviseur::demarrer(Coeur::SingBox, &e.lancement, &e.secret).await;
        duree = debut.elapsed();
        r.map_err(|x| format!("{x:#}"))
    })
    .await
    .expect("un coeur lance par nous doit etre reconnu et interroge");
    assert!(
        duree < superviseur::BUDGET_DEMARRAGE,
        "la reconnaissance ne doit pas couter l'echeance entiere"
    );
    assert_eq!(
        en_cours.api(),
        Some(SocketAddr::from(([127, 0, 0, 1], essai.port)))
    );
    en_cours.arreter().await.expect("l'arret doit aboutir");
    let _ = std::fs::remove_dir_all(&rep);
}

/// # L'autre bout du chemin par coeur: l'entree SOCKS
///
/// Le trafic de l'utilisateur passe par l'entree SOCKS du coeur, en clair avant
/// chiffrement. L'atelier PUBLIE l'adresse de cette entree, et la facade y mene
/// le trafic. Si un squatteur tient deja ce port, publier son adresse
/// reviendrait a lui livrer le trafic. Apres correction, l'atelier REFUSE de
/// publier une entree qu'un tiers detient: `coeur_actif` reste vide et le
/// lancement echoue en le disant. Contre le code d'avant la correction, cette
/// recette est rouge - l'adresse squattee etait publiee.
///
/// La doublure prend un port d'API a elle (donc reconnue comme notre enfant sur
/// le canal du secret); le squatteur, lui, tient le port SOCKS, un autre port.
/// C'est le cas ou le coeur est vivant ET un tiers tient l'entree, celui que la
/// verification du proprietaire tranche par `Autre`.
#[test]
fn un_squatteur_de_l_entree_socks_n_est_pas_publie() {
    let squatteur = Squatteur::prendre_le_port();
    let socks = squatteur.adresse();

    let rep = repertoire_temporaire("socks");

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let (poignee, coeur_actif, tache) = atelier::ouvrir();
    runtime.spawn(tache);

    // Le refus attendu vient d'une doublure qui TIENT son port d'API: il est
    // rendu au premier essai, jamais retente. Seul un port d'API pris avant
    // le `bind` de la doublure en fait monter une autre.
    let rep_du_fil = rep.clone();
    let issue = std::thread::spawn(move || {
        doublure::lancer_sauf_vol(&rep_du_fil, &gabarit(), |e| {
            poignee.lancer(Coeur::SingBox, e.lancement.clone(), &e.secret, socks)
        })
        .map(|(vivant, _)| vivant)
    })
    .join()
    .expect("le fil ne doit pas paniquer");

    // Rien ne doit avoir ete publie: la facade ne pointera jamais sur le
    // squatteur.
    assert_eq!(
        *coeur_actif.borrow(),
        None,
        "l'entree SOCKS squattee a ete publiee: la facade y menerait le trafic en clair"
    );
    let erreur = issue.expect_err("l'atelier doit refuser de publier une entree SOCKS squattee");
    assert!(
        erreur.contains("entree SOCKS") && erreur.contains("autre que le coeur"),
        "le refus doit nommer l'entree squattee: {erreur}"
    );

    let vu = squatteur.recolter();
    assert_eq!(
        vu.connexions, 0,
        "aucune connexion ne doit avoir atteint le squatteur"
    );
    let _ = std::fs::remove_dir_all(&rep);
}

/// # En cours de session: la sonde de vitalite
///
/// Le coeur qu'on a lance meurt et relache son API; un squatteur reprend le
/// port. Au prochain reveil de la sonde, elle verifie que l'API est tenue par le
/// PID publie, constate que non, et rend [`vitalite::Sonde::Impossible`] sans
/// envoyer le secret. Le squatteur ne voit aucune connexion.
///
/// Falsification: retirer la verification de proprietaire dans `vitalite::tenir`
/// (appeler `sonder` sans condition) rend cette recette rouge - la sonde se
/// connecte au squatteur et lui livre `Authorization: Bearer <secret>`, donc
/// `connexions >= 1` et `secret_recu` est renseigne. Mesure a la livraison.
#[tokio::test]
async fn la_sonde_ne_livre_pas_le_secret_a_un_squatteur_en_session() {
    let squatteur = Squatteur::prendre_le_port();
    let api = squatteur.adresse();
    let mut coeur_mort = coeur_qui_a_relache_son_port();
    let pid_coeur = coeur_mort.id();
    let secret = alea::secret().unwrap();

    let publie = atelier::CoeurPublie {
        socks: api,
        api: Some(api),
        pid: pid_coeur,
        uid: None,
    };
    let (_publier, coeur_rx) = tokio::sync::watch::channel(Some(publie));
    let adresse = vitalite::Adresse {
        api,
        secret: secret.clone(),
        selecteur: "select".to_owned(),
    };
    let (mut poignee, veille) = vitalite::ouvrir(adresse, coeur_rx);
    let tache = tokio::spawn(veille);

    assert!(poignee.demander(BUDGET), "la demande de sonde doit partir");
    let echeance = Instant::now();
    let verdict = loop {
        if let Some(v) = poignee.ramasser() {
            break v;
        }
        assert!(
            echeance.elapsed() < BUDGET + Duration::from_secs(3),
            "la sonde n'a jamais rendu de verdict"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    tache.abort();
    // Tuer et reaper l'enfant AVANT d'asserter: par PID, jamais par motif.
    let _ = coeur_mort.kill();
    let _ = coeur_mort.wait();

    assert_eq!(
        verdict,
        vitalite::Sonde::Impossible,
        "un port que le coeur publie ne tient plus doit rendre Impossible, pas un verdict de pair"
    );
    let vu = squatteur.recolter();
    assert_eq!(
        vu.connexions, 0,
        "aucune connexion ne doit avoir atteint le squatteur"
    );
    assert!(
        vu.secret_recu.is_none(),
        "le secret a fui vers le squatteur pendant la session: {:?}",
        vu.secret_recu
    );
}

/// # En cours de session: la bascule a chaud
///
/// Meme scenario, cote bascule: la sortie qui echoue declenche un passage a la
/// suivante, qui envoie `Authorization: Bearer <secret>` a l'API. Elle verifie
/// d'abord le proprietaire et rend [`bascule::Issue::Refusee`] plutot que de
/// parler au squatteur.
///
/// Falsification: retirer la verification dans `bascule::tenir` rend la recette
/// rouge - le secret part vers le squatteur. Mesure a la livraison.
#[tokio::test]
async fn la_bascule_ne_livre_pas_le_secret_a_un_squatteur_en_session() {
    let squatteur = Squatteur::prendre_le_port();
    let api = squatteur.adresse();
    let mut coeur_mort = coeur_qui_a_relache_son_port();
    let pid_coeur = coeur_mort.id();
    let secret = alea::secret().unwrap();

    let publie = atelier::CoeurPublie {
        socks: api,
        api: Some(api),
        pid: pid_coeur,
        uid: None,
    };
    let (_publier, coeur_rx) = tokio::sync::watch::channel(Some(publie));
    let adresse = vitalite::Adresse {
        api,
        secret: secret.clone(),
        selecteur: "select".to_owned(),
    };
    let (mut poignee, conduite) = bascule::ouvrir(adresse, coeur_rx);
    let tache = tokio::spawn(conduite);

    assert!(
        poignee.demander("second"),
        "la demande de bascule doit partir"
    );
    let echeance = Instant::now();
    let verdict = loop {
        if let Some(v) = poignee.ramasser() {
            break v;
        }
        assert!(
            echeance.elapsed() < BUDGET + Duration::from_secs(3),
            "la bascule n'a jamais rendu de verdict"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    tache.abort();
    let _ = coeur_mort.kill();
    let _ = coeur_mort.wait();

    assert!(
        matches!(verdict, bascule::Issue::Refusee { .. }),
        "une bascule vers un port squatte doit etre refusee: {verdict:?}"
    );
    let vu = squatteur.recolter();
    assert_eq!(
        vu.connexions, 0,
        "aucune connexion ne doit avoir atteint le squatteur"
    );
    assert!(
        vu.secret_recu.is_none(),
        "le secret a fui vers le squatteur a la bascule: {:?}",
        vu.secret_recu
    );
}

/// # En cours de session: le trafic de l'utilisateur par la facade
///
/// Le coeur meurt, un squatteur reprend l'entree SOCKS. La facade, avant de
/// relayer, verifie que l'entree est tenue par le PID publie; elle constate que
/// non et FERME la connexion sans verser un octet. En clair: le trafic de
/// l'utilisateur n'atteint jamais le squatteur.
///
/// Falsification: retirer la verification dans `facade::relayer` rend la recette
/// rouge - la facade se connecte au squatteur, qui voit `connexions >= 1`.
#[tokio::test]
async fn la_facade_ne_mene_pas_le_trafic_a_un_squatteur_en_session() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let squatteur = Squatteur::prendre_le_port();
    let entree = squatteur.adresse();
    let mut coeur_mort = coeur_qui_a_relache_son_port();
    let pid_coeur = coeur_mort.id();

    let publie = atelier::CoeurPublie {
        socks: entree,
        api: None,
        pid: pid_coeur,
        uid: None,
    };
    let (_publier, arriere) = tokio::sync::watch::channel(Some(publie));
    let (adresse, la_facade) = facade::ouvrir("127.0.0.1:0".parse().unwrap(), arriere)
        .await
        .expect("la facade doit ouvrir sur un port libre");
    let tache = tokio::spawn(la_facade.servir());

    let recu = tokio::time::timeout(Duration::from_secs(3), async {
        let mut flux = tokio::net::TcpStream::connect(adresse)
            .await
            .expect("le client doit joindre la facade");
        flux.write_all(b"trafic-en-clair").await.ok();
        flux.flush().await.ok();
        let mut tampon = Vec::new();
        let _ = flux.read_to_end(&mut tampon).await;
        tampon
    })
    .await
    .expect("la facade ne doit pas faire attendre");
    tache.abort();
    let _ = coeur_mort.kill();
    let _ = coeur_mort.wait();

    assert!(
        recu.is_empty(),
        "rien ne doit revenir: la facade a refuse de relayer vers le squatteur"
    );
    let vu = squatteur.recolter();
    assert_eq!(
        vu.connexions, 0,
        "aucun octet de trafic ne doit avoir atteint le squatteur"
    );
}

/// Lance une doublure sur `127.0.0.1:<port>`, a cote d'une ecoute que la
/// recette tient deja sur ce port, et attend qu'elle REPONDE.
///
/// Qu'elle reponde etablit deux faits a la fois: elle a pu se lier a cote de
/// l'ecoute tierce, et c'est ELLE qui recoit les connexions vers `127.0.0.1`
/// (l'ecoute de la recette n'accepte jamais: une connexion qui lui arriverait
/// resterait sans reponse).
///
/// Elle n'est interrogee qu'une fois son temoin a [`Liaison::Liee`]. Avant le
/// 30/09/2026 on l'interrogeait des le lancement, et toute reponse 200 comptait:
/// si `127.0.0.1:<port>` etait deja ecoute ailleurs - l'ecoute d'une AUTRE
/// recette de ce binaire, par exemple, qui repond une version -, la doublure
/// mourait de son `bind`, cette ecoute-la repondait a sa place avec le secret
/// de la doublure en main, et la recette jugeait le proprietaire d'un pid
/// mort. `Err` seulement si la doublure a ecrit que son port etait pris
/// ([`Liaison::PortPris`]), pour que la recette en essaie un autre; toute
/// autre issue panique en la nommant.
async fn doublure_a_cote(port: u16, nom: &str) -> Result<(std::process::Child, PathBuf), String> {
    let rep = repertoire_temporaire(nom);
    let secret = alea::secret().unwrap();
    let config = rep.join("doublure.json");
    std::fs::write(
        &config,
        serde_json::to_string(&Configuration {
            port,
            secret: secret.clone(),
            selecteur: String::new(),
            sorties: vec![],
        })
        .unwrap(),
    )
    .unwrap();
    let mut enfant = std::process::Command::new(binaire_du_daemon())
        .arg("--faux-coeur")
        .arg(&config)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("la doublure doit se lancer");
    let adresse = SocketAddr::from(([127, 0, 0, 1], port));
    let debut = Instant::now();
    loop {
        match doublure::liaison(&config) {
            Liaison::Liee => {
                let reponse = tokio::time::timeout(
                    Duration::from_millis(500),
                    clash::interroger_version(adresse, &secret),
                )
                .await;
                if let Ok(Ok(_)) = reponse {
                    return Ok((enfant, rep));
                }
            }
            Liaison::PortPris { code } => {
                // Par PID, jamais par motif.
                let _ = enfant.kill();
                let _ = enfant.wait();
                let _ = std::fs::remove_dir_all(&rep);
                return Err(format!(
                    "le port de la doublure {adresse} etait pris avant son bind (code {code:?})"
                ));
            }
            Liaison::Echec(raison) => {
                let _ = enfant.kill();
                let _ = enfant.wait();
                let _ = std::fs::remove_dir_all(&rep);
                panic!(
                    "la doublure n'a pas pu se lier sur {adresse}, et pas faute de port: {raison}"
                );
            }
            Liaison::Inconnue => {
                if let Ok(Some(statut)) = enfant.try_wait() {
                    let _ = std::fs::remove_dir_all(&rep);
                    panic!(
                        "la doublure s'est arretee ({statut}) sans dire ce qu'elle a fait de {adresse}"
                    );
                }
            }
        }
        if debut.elapsed() > Duration::from_secs(10) {
            // Par PID, jamais par motif.
            let _ = enfant.kill();
            let _ = enfant.wait();
            let temoin = doublure::liaison(&config);
            let _ = std::fs::remove_dir_all(&rep);
            panic!("la doublure ne repond pas sur {adresse} (temoin: {temoin:?})");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Tient `ecoute_tierce` (rendue par `lier`) a cote d'une doublure sur le meme
/// port, et rend le verdict de la verification pour la doublure. Quelques
/// essais, un port neuf a chaque fois, SEULEMENT si la doublure a ecrit que la
/// moitie v4 du port etait deja prise (voir [`doublure_a_cote`]).
async fn verdict_a_cote_de(lier: fn() -> std::io::Result<TcpListener>, nom: &str) -> Proprietaire {
    let mut raisons = Vec::new();
    for _ in 0..5 {
        let tierce = lier().expect("l'ecoute tierce de la recette doit se lier");
        let port = tierce.local_addr().unwrap().port();
        match doublure_a_cote(port, nom).await {
            Ok((mut doublure, rep)) => {
                let verdict = proprietaire::verifier_ecoute(
                    port,
                    proprietaire::Attendu {
                        pid: doublure.id(),
                        uid: None,
                    },
                );
                let _ = doublure.kill();
                let _ = doublure.wait();
                drop(tierce);
                let _ = std::fs::remove_dir_all(&rep);
                return verdict;
            }
            Err(raison) => raisons.push(raison),
        }
    }
    panic!("aucune doublure n'a pu se lier a cote de l'ecoute tierce: {raisons:?}");
}

/// # Une ecoute sur la boucle v6 ne disqualifie pas le coeur
///
/// `[::1]:<port>` se lie a cote de `127.0.0.1:<port>` sur les deux plateformes,
/// et ne recoit AUCUNE connexion vers `127.0.0.1`: la doublure repond, c'est ce
/// que [`doublure_a_cote`] attend. La compter faisait refuser a tort un coeur
/// sain (le verificateur l'a mesure des deux cotes). Elle est ignoree: le
/// verdict est `Confirme`.
///
/// Falsification: remettre `::1` parmi les adresses comptees
/// (`linux::V6_QUI_RECOIVENT`, `windows_impl::recoit_la_boucle_v6`) rend cette
/// recette rouge, `Autre`.
#[tokio::test]
async fn une_ecoute_sur_la_boucle_v6_ne_disqualifie_pas_le_coeur() {
    let verdict = verdict_a_cote_de(|| TcpListener::bind("[::1]:0"), "boucle-v6").await;
    assert_eq!(
        verdict,
        Proprietaire::Confirme,
        "une ecoute sur [::1] ne recoit rien de 127.0.0.1 et ne doit pas faire refuser le coeur"
    );
}

/// # Sous Windows: une ecoute large a cote du coeur est un tiers
///
/// Sous Windows, `0.0.0.0:<port>` et `127.0.0.1:<port>` se lient ensemble, et
/// la plus precise recoit: tant que le coeur vit, la connexion vers `127.0.0.1`
/// va a lui (la doublure repond). Le jour ou il meurt, l'ecoute large recoit la
/// suivante sans delai. La verification doit donc la compter, et nommer qui la
/// tient: `Autre`, avec le PID de la recette.
///
/// Falsification: ne plus compter `0.0.0.0` dans
/// `windows_impl::recoit_la_boucle_v4` rend cette recette rouge: la
/// verification ne voit plus que la doublure et rend `Confirme`. C'est la
/// garde que le verificateur avait trouvee aveugle (M8w).
#[cfg(windows)]
#[tokio::test]
async fn sous_windows_une_ecoute_large_a_cote_du_coeur_est_un_tiers() {
    let verdict = verdict_a_cote_de(|| TcpListener::bind("0.0.0.0:0"), "large").await;
    match verdict {
        Proprietaire::Autre { details } => assert!(
            details.contains(&std::process::id().to_string()),
            "le refus doit nommer le processus qui tient l'ecoute large: {details}"
        ),
        autre => panic!("une ecoute large d'un tiers a cote du coeur doit rendre Autre: {autre:?}"),
    }
}

/// # Canal C: qui peut partager le port de la facade
///
/// La facade est l'ECOUTEUR de son port stable, et son seul client est le
/// passeur du meme processus, qui frappe l'adresse exacte qu'[`facade::ouvrir`]
/// a rendue. Ce qu'un tiers peut faire de ce port depend de la plateforme, et
/// les recettes qui suivent le mesurent:
///
/// - la MEME adresse, tenue d'abord par un tiers: la facade ne s'ouvre pas,
///   sur les deux plateformes (ici);
/// - une ecoute LARGE (`0.0.0.0`), avant ou apres la facade: refusee par Linux,
///   qui ne laisse pas deux ecoutes se recouvrir sans `SO_REUSEPORT` des deux
///   cotes; acceptee par Windows, ou c'est alors la facade, plus precise, qui
///   recoit les connexions vers `127.0.0.1`. Elle les recoit tant qu'elle
///   ecoute, c'est-a-dire tant que le daemon - donc le passeur, son seul
///   client - vit;
/// - `SO_REUSEPORT` sous Linux: la facade ne le pose pas (tokio, par mio, ne
///   pose que `SO_REUSEADDR`), donc aucun tiers ne peut rejoindre son ecoute,
///   ni elle la sienne.
#[tokio::test]
async fn un_squatteur_du_port_de_la_facade_empeche_son_ouverture() {
    let squatteur = Squatteur::prendre_le_port();
    let port_facade = squatteur.adresse();
    let (_publier, arriere) = tokio::sync::watch::channel(None);
    let issue = facade::ouvrir(port_facade, arriere).await;
    assert!(
        issue.is_err(),
        "la facade ne doit pas s'ouvrir sur une adresse deja tenue par un tiers"
    );
}

/// Un client frappe la facade (aucun coeur publie: elle ferme sans rien
/// rendre) et dit ce qui est revenu.
async fn frapper(adresse: SocketAddr) -> Vec<u8> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    tokio::time::timeout(Duration::from_secs(3), async {
        let mut flux = tokio::net::TcpStream::connect(adresse)
            .await
            .expect("le client doit joindre le port");
        flux.write_all(b"trafic-en-clair").await.ok();
        flux.flush().await.ok();
        let mut tampon = Vec::new();
        let _ = flux.read_to_end(&mut tampon).await;
        tampon
    })
    .await
    .expect("la connexion ne doit pas rester en attente")
}

/// # Canal C: une ecoute large posee AVANT la facade
///
/// Linux refuse d'ouvrir la facade. Windows l'ouvre, et la connexion vers
/// `127.0.0.1` va a la facade, pas a l'ecoute large: le squatteur ne voit
/// aucune connexion, et le client ne recoit rien (la facade ferme, faute de
/// coeur) - la ou le squatteur, lui, aurait repondu.
#[tokio::test]
async fn une_ecoute_large_avant_la_facade_ne_recoit_rien() {
    let squatteur =
        Squatteur::sur(TcpListener::bind("0.0.0.0:0").expect("une ecoute sur toutes les adresses"));
    let adresse = squatteur.adresse();
    let (_publier, arriere) = tokio::sync::watch::channel(None);
    let issue = facade::ouvrir(adresse, arriere).await;

    if cfg!(target_os = "linux") {
        assert!(
            issue.is_err(),
            "Linux ne doit pas laisser la facade recouvrir une ecoute large"
        );
        return;
    }
    let (ouverte, la_facade) = issue.expect("Windows ouvre la facade a cote d'une ecoute large");
    assert_eq!(ouverte, adresse);
    let tache = tokio::spawn(la_facade.servir());
    let recu = frapper(adresse).await;
    tache.abort();
    let vu = squatteur.recolter();
    assert_eq!(
        vu.connexions, 0,
        "la connexion vers 127.0.0.1 doit aller a la facade, pas a l'ecoute large"
    );
    assert!(
        recu.is_empty(),
        "la facade ferme sans rien rendre: {recu:?}"
    );
}

/// # Canal C: une ecoute large posee APRES la facade
///
/// Le squatteur pose meme `SO_REUSEADDR`. Linux refuse son `bind`. Windows
/// l'accepte, et la facade, plus precise, garde les connexions.
#[tokio::test]
async fn une_ecoute_large_apres_la_facade_ne_recoit_rien() {
    let (_publier, arriere) = tokio::sync::watch::channel(None);
    let (adresse, la_facade) = facade::ouvrir("127.0.0.1:0".parse().unwrap(), arriere)
        .await
        .expect("la facade doit ouvrir sur un port libre");
    let large = tokio::net::TcpSocket::new_v4().unwrap();
    large.set_reuseaddr(true).unwrap();
    let liee = large.bind(SocketAddr::from(([0, 0, 0, 0], adresse.port())));

    if cfg!(target_os = "linux") {
        assert!(
            liee.is_err(),
            "Linux ne doit pas laisser une ecoute large recouvrir la facade"
        );
        return;
    }
    liee.expect("Windows lie une ecoute large a cote de la facade");
    let squatteur = Squatteur::sur(
        large
            .listen(16)
            .expect("l'ecoute large doit ecouter")
            .into_std()
            .unwrap(),
    );
    let tache = tokio::spawn(la_facade.servir());
    let recu = frapper(adresse).await;
    tache.abort();
    let vu = squatteur.recolter();
    assert_eq!(
        vu.connexions, 0,
        "la connexion vers 127.0.0.1 doit aller a la facade, pas a l'ecoute large"
    );
    assert!(
        recu.is_empty(),
        "la facade ferme sans rien rendre: {recu:?}"
    );
}

/// # Canal C, Linux: `SO_REUSEPORT` ne rejoint pas la facade
///
/// `SO_REUSEPORT` met plusieurs ecoutes sur la meme adresse et leur partage les
/// connexions, a condition que TOUTES le posent, sous le meme UID. La facade ne
/// le pose pas: un tiers qui le pose ne peut ni la rejoindre, ni etre rejoint
/// par elle.
///
/// Falsification: poser `SO_REUSEPORT` sur l'ecoute de la facade rend cette
/// recette rouge - le tiers, du meme UID ici, se lie, et le noyau lui
/// distribue une part des connexions.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn sous_linux_so_reuseport_ne_rejoint_pas_la_facade() {
    fn tiers_reuseport() -> tokio::net::TcpSocket {
        let s = tokio::net::TcpSocket::new_v4().unwrap();
        s.set_reuseaddr(true).unwrap();
        s.set_reuseport(true).unwrap();
        s
    }

    // La facade d'abord.
    let (_publier, arriere) = tokio::sync::watch::channel(None);
    let (adresse, _la_facade) = facade::ouvrir("127.0.0.1:0".parse().unwrap(), arriere)
        .await
        .expect("la facade doit ouvrir sur un port libre");
    assert!(
        tiers_reuseport().bind(adresse).is_err(),
        "un tiers en SO_REUSEPORT ne doit pas rejoindre l'ecoute de la facade"
    );

    // Le tiers d'abord.
    let tiers = tiers_reuseport();
    tiers.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let tenu = tiers.local_addr().unwrap();
    let _ecoute_tierce = tiers.listen(16).unwrap();
    let (_publier2, arriere2) = tokio::sync::watch::channel(None);
    assert!(
        facade::ouvrir(tenu, arriere2).await.is_err(),
        "la facade ne doit pas rejoindre une ecoute SO_REUSEPORT d'un tiers"
    );
}
