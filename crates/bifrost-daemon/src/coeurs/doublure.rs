//! Doublure de coeur, pour eprouver le superviseur sans binaire tiers.
//!
//! Le superviseur ne se teste pas en unitaire: ce qu'il faut verifier, c'est
//! qu'un vrai processus est lance, qu'on attend vraiment qu'il reponde, qu'un
//! mauvais secret echoue tot, et qu'il meurt bien a l'arret. Aucune doublure
//! en memoire ne prouve ca.
//!
//! Cette doublure sert donc de coeur: elle parle le minimum de l'API Clash,
//! par la meme socket et le meme protocole. Ce qu'elle NE prouve pas, et il
//! faut le dire: que sing-box ou Xray se comportent comme elle.
//!
//! # Elle tient une SELECTION, et refuse ce qu'un vrai coeur refuse
//!
//! Ajoute le 20 aout 2026. Jusque-la elle repondait 204 a tout `PUT /proxies/`
//! sans rien retenir, et ne servait pas le `GET` correspondant. C'etait
//! exactement l'API menteuse contre laquelle [`super::bascule`] se garde: elle
//! acceptait sans rien faire, et ne savait meme pas le dire. Une bascule menee
//! contre elle rendait donc toujours `Refusee`, et toute la chaine construite
//! au-dessus - perte observee, course qui avance, selecteur qui bascule -
//! restait inatteignable sans binaire tiers.
//!
//! Elle retient maintenant la sortie choisie et la rapporte. Deux refus sont
//! MESURES sur sing-box 1.13.18 le 20 aout 2026, pas devines: un selecteur
//! inconnu et une sortie inconnue rendent tous deux un statut non-204. Les
//! reproduire ici est ce qui distingue une doublure d'un complice - une
//! doublure qui dit oui a tout ne mesure que la politesse de l'appelant.
//!
//! Elle n'existe QUE dans les binaires de debogage. Embarquer un serveur de
//! controle dans un produit de securite livre, meme derriere un drapeau cache,
//! serait une surface de plus sans contrepartie.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::lancement::Lancement;

/// Configuration de la doublure, lue depuis un fichier comme le ferait un vrai
/// coeur: le secret ne transite jamais par la ligne de commande.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct Configuration {
    pub port: u16,
    pub secret: String,
    /// Nom du selecteur servi. Vide: la doublure n'en sert aucun et rend 404 a
    /// toute requete de selecteur, ce qui etait son comportement avant le
    /// 20 aout 2026.
    #[serde(default)]
    pub selecteur: String,
    /// Les sorties que le selecteur accepte, dans l'ordre. La premiere est la
    /// selection initiale, comme chez sing-box.
    #[serde(default)]
    pub sorties: Vec<String>,
}

impl Configuration {
    /// L'etat initial que cette configuration decrit.
    pub fn etat(&self) -> Etat {
        Etat::nouvel(&self.selecteur, &self.sorties)
    }
}

/// La selection que la doublure tient, separee des sockets pour etre testable.
///
/// `courante` est toujours l'une des `sorties`, ou vide quand il n'y en a
/// aucune: c'est l'invariant que [`Etat::choisir`] preserve, et la raison pour
/// laquelle il n'existe pas de constructeur qui prenne une selection arbitraire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Etat {
    selecteur: String,
    sorties: Vec<String>,
    courante: String,
}

impl Etat {
    pub fn nouvel(selecteur: &str, sorties: &[String]) -> Self {
        Self {
            selecteur: selecteur.to_owned(),
            sorties: sorties.to_vec(),
            courante: sorties.first().cloned().unwrap_or_default(),
        }
    }

    /// La sortie actuellement servie.
    pub fn courante(&self) -> &str {
        &self.courante
    }

    /// Change de sortie. Rend faux si la sortie est inconnue, auquel cas RIEN
    /// ne change - un coeur qui accepterait une etiquette inconnue laisserait
    /// le trafic sur l'ancienne sortie tout en disant oui.
    pub fn choisir(&mut self, sortie: &str) -> bool {
        if !self.sorties.iter().any(|s| s == sortie) {
            return false;
        }
        self.courante = sortie.to_owned();
        true
    }

    /// Le JSON qu'un selecteur Clash rend sur `GET /proxies/<nom>`.
    fn json(&self) -> String {
        serde_json::json!({
            "name": self.selecteur,
            "type": "Selector",
            "now": self.courante,
            "all": self.sorties,
        })
        .to_string()
    }

    /// Ce selecteur est-il celui que la doublure sert.
    fn sert(&self, nom: &str) -> bool {
        !self.selecteur.is_empty() && nom == self.selecteur
    }
}

/// Sert l'API jusqu'a ce que le processus soit tue.
///
/// Laisse a cote de sa configuration un temoin de ce qu'elle a fait de son
/// port (voir [`Liaison`]): c'est la seule preuve, pour qui l'a lancee, que
/// son port lui a ete pris avant qu'elle ne le lie.
pub async fn servir(chemin: &Path) -> anyhow::Result<()> {
    let brut = std::fs::read_to_string(chemin)?;
    let config: Configuration = serde_json::from_str(&brut)?;
    let adresse = SocketAddr::from(([127, 0, 0, 1], config.port));
    let temoin = temoin_de_liaison(chemin);
    let ecoute = match TcpListener::bind(adresse).await {
        Ok(e) => e,
        Err(e) => {
            noter(&temoin, &Liaison::depuis_l_erreur(&e));
            return Err(e.into());
        }
    };
    noter(&temoin, &Liaison::Liee);
    servir_sur(ecoute, config).await
}

/// Ce que la doublure a fait de son port, d'apres le temoin qu'elle ecrit a
/// cote de sa configuration juste apres son `bind`.
///
/// # Pourquoi un temoin, et pourquoi de la doublure elle-meme
///
/// Une doublure qui n'a pas demarre peut avoir deux histoires tres
/// differentes. Ou son port lui a ete pris avant qu'elle ne le lie: son
/// lanceur n'y est pour rien, et un nouvel essai sur un port neuf est
/// legitime. Ou elle a lie son port, et c'est son lanceur - la reconnaissance
/// du proprietaire, par exemple - qui a refuse: retenter masquerait un defaut
/// qui ne se montre qu'une fois sur deux. Le message d'erreur du lanceur ne
/// les distingue pas toujours: la verification peut refuser AVANT le `bind`
/// de l'enfant, qui lie ensuite sans encombre. Seule la doublure sait ce que
/// son `bind` a rendu; elle l'ecrit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Liaison {
    /// Son `bind` a abouti: elle a tenu son port.
    Liee,
    /// Son `bind` a ete refuse parce que le port etait deja pris
    /// (`EADDRINUSE`, `WSAEADDRINUSE`): elle n'a jamais tenu son port.
    PortPris { code: Option<i32> },
    /// Son `bind` a echoue pour une autre raison.
    Echec(String),
    /// Aucun temoin: elle n'est pas arrivee jusqu'a son `bind`.
    Inconnue,
}

impl Liaison {
    /// Seul un port deja pris est un vol: `EADDRINUSE` (98 sous Linux),
    /// `WSAEADDRINUSE` (10048 sous Windows).
    ///
    /// Sous Windows, un voleur qui pose `SO_EXCLUSIVEADDRUSE` rend lui aussi
    /// 10048 a la doublure, parce qu'elle ne pose pas `SO_REUSEADDR` (tokio,
    /// par mio, ne la pose pas sous Windows). `WSAEACCES` (10013) ne vient
    /// contre un tel voleur qu'a un socket qui la pose; mesure du 30/09/2026
    /// sur dev-windows. Sinon il dit une plage de ports exclue ou un droit
    /// refuse: aucun vol, donc un echec.
    fn depuis_l_erreur(e: &std::io::Error) -> Self {
        if e.kind() == std::io::ErrorKind::AddrInUse {
            Liaison::PortPris {
                code: e.raw_os_error(),
            }
        } else {
            Liaison::Echec(e.to_string())
        }
    }

    fn en_texte(&self) -> String {
        match self {
            Liaison::Liee => "liee".to_owned(),
            Liaison::PortPris { code } => match code {
                Some(c) => format!("port-pris {c}"),
                None => "port-pris".to_owned(),
            },
            Liaison::Echec(raison) => format!("echec {raison}"),
            Liaison::Inconnue => "inconnue".to_owned(),
        }
    }

    fn depuis_le_texte(t: &str) -> Self {
        let t = t.trim();
        if t == "liee" {
            Liaison::Liee
        } else if let Some(reste) = t.strip_prefix("port-pris") {
            Liaison::PortPris {
                code: reste.trim().parse().ok(),
            }
        } else if let Some(raison) = t.strip_prefix("echec ") {
            Liaison::Echec(raison.to_owned())
        } else {
            Liaison::Inconnue
        }
    }
}

/// Ou la doublure lancee sur `configuration` ecrit son temoin de liaison.
pub fn temoin_de_liaison(configuration: &Path) -> PathBuf {
    configuration.with_extension("liaison")
}

/// Le temoin de la doublure lancee sur `configuration`.
pub fn liaison(configuration: &Path) -> Liaison {
    match std::fs::read_to_string(temoin_de_liaison(configuration)) {
        Ok(t) => Liaison::depuis_le_texte(&t),
        Err(_) => Liaison::Inconnue,
    }
}

/// Ecrit le temoin. Un temoin qui ne s'ecrit pas n'arrete pas la doublure:
/// son lanceur lira `Inconnue`, et ne retentera pas. C'est voulu: sans
/// preuve de vol, pas de nouvel essai, et l'erreur rendue nomme `inconnue`.
/// La raison part sur la sortie d'erreur, que le superviseur garde dans son
/// journal: un temoin absent ne doit pas etre un silence.
fn noter(temoin: &Path, l: &Liaison) {
    if let Err(e) = std::fs::write(temoin, l.en_texte()) {
        eprintln!(
            "doublure: temoin de liaison {} non ecrit ({e}); son lanceur lira `inconnue`",
            temoin.display()
        );
    }
}

/// Combien de montages au plus quand chacun se fait prendre son port.
pub const ESSAIS_SUR_VOL: u32 = 5;

/// Ce qu'une recette demande a la doublure qu'elle monte.
#[derive(Debug, Clone)]
pub struct Gabarit {
    /// Le binaire du daemon, qui joue la doublure par `--faux-coeur`.
    pub programme: PathBuf,
    /// Voir [`Configuration::selecteur`].
    pub selecteur: String,
    /// Voir [`Configuration::sorties`].
    pub sorties: Vec<String>,
}

/// Un montage: le port tout juste rendu, la configuration ecrite.
#[derive(Debug, Clone)]
pub struct Essai {
    /// Le lancement par `--faux-coeur`, API sur `port`.
    pub lancement: Lancement,
    pub secret: String,
    pub port: u16,
}

/// Monte l'essai `n` dans `repertoire`: port reserve et tenu, configuration
/// ecrite sous un nom propre a l'essai, pour qu'un temoin d'un essai
/// precedent ne soit jamais relu.
fn monter(
    repertoire: &Path,
    gabarit: &Gabarit,
    n: u32,
) -> anyhow::Result<(super::port::Reservation, Essai)> {
    let reserve = super::port::reserver()?;
    let port = reserve.port();
    let secret = super::alea::secret()?;
    let configuration = repertoire.join(format!("doublure-{n}.json"));
    std::fs::write(
        &configuration,
        serde_json::to_string(&Configuration {
            port,
            secret: secret.clone(),
            selecteur: gabarit.selecteur.clone(),
            sorties: gabarit.sorties.clone(),
        })?,
    )?;
    let lancement = Lancement {
        programme: gabarit.programme.clone(),
        arguments: vec!["--faux-coeur".into(), configuration.clone().into()],
        configuration,
        api_clash: Some(port),
        utilisateur: None,
    };
    Ok((
        reserve,
        Essai {
            lancement,
            secret,
            port,
        },
    ))
}

/// La regle, unique: un nouvel essai seulement si la doublure a PROUVE que
/// son port lui a ete pris avant qu'elle ne le lie. Rend `None` pour retenter
/// (le vol est note), ou l'erreur a rendre telle quelle, completee de ce que
/// la doublure a dit.
fn juger(essai: &Essai, n: u32, erreur: String, vols: &mut Vec<String>) -> Option<String> {
    match liaison(&essai.lancement.configuration) {
        Liaison::PortPris { .. } => {
            vols.push(format!(
                "essai {n}, port {} pris avant le bind de la doublure: {erreur}",
                essai.port
            ));
            None
        }
        autre => Some(format!(
            "{erreur} [temoin de la doublure: {}; aucun vol de port prouve, pas de nouvel essai]",
            autre.en_texte()
        )),
    }
}

fn epuise(vols: &[String]) -> String {
    format!(
        "la doublure s'est fait prendre son port a chacun des {ESSAIS_SUR_VOL} essais: {vols:?}"
    )
}

/// Monte une doublure dans `repertoire` et la fait lancer par `lancer`, sur
/// un fil sans runtime (l'atelier, un faux parent). Un nouvel essai, sur un
/// port neuf, SEULEMENT quand la doublure a prouve que son port lui a ete pris
/// ([`Liaison::PortPris`]); toute autre erreur est rendue au premier essai.
///
/// Un repertoire par doublure: les noms de configuration y sont numerotes par
/// essai, pas par doublure.
pub fn lancer_sauf_vol<T>(
    repertoire: &Path,
    gabarit: &Gabarit,
    mut lancer: impl FnMut(&Essai) -> Result<T, String>,
) -> Result<(T, Essai), String> {
    let mut vols = Vec::new();
    for n in 1..=ESSAIS_SUR_VOL {
        let (reserve, essai) =
            monter(repertoire, gabarit, n).map_err(|e| format!("montage de la doublure: {e}"))?;
        reserve.liberer();
        match lancer(&essai) {
            Ok(v) => return Ok((v, essai)),
            Err(e) => {
                if let Some(fin) = juger(&essai, n, e, &mut vols) {
                    return Err(fin);
                }
            }
        }
    }
    Err(epuise(&vols))
}

/// [`lancer_sauf_vol`], pour un lanceur asynchrone (`superviseur::demarrer`).
/// Meme regle, meme juge.
pub async fn demarrer_sauf_vol<T>(
    repertoire: &Path,
    gabarit: &Gabarit,
    mut lancer: impl AsyncFnMut(&Essai) -> Result<T, String>,
) -> Result<(T, Essai), String> {
    let mut vols = Vec::new();
    for n in 1..=ESSAIS_SUR_VOL {
        let (reserve, essai) =
            monter(repertoire, gabarit, n).map_err(|e| format!("montage de la doublure: {e}"))?;
        reserve.liberer();
        match lancer(&essai).await {
            Ok(v) => return Ok((v, essai)),
            Err(e) => {
                if let Some(fin) = juger(&essai, n, e, &mut vols) {
                    return Err(fin);
                }
            }
        }
    }
    Err(epuise(&vols))
}

/// La meme, sur une ecoute deja liee.
///
/// Sert aux recettes qui veulent l'API dans leur propre processus: lier
/// soi-meme est plus fort que reserver, puisqu'il n'y a plus d'intervalle du
/// tout entre le choix du numero et son usage. C'est la borne superieure de ce
/// que [`super::port`] approche pour un enfant, a qui l'on ne peut pas passer
/// un descripteur deja lie.
pub async fn servir_sur(ecoute: TcpListener, config: Configuration) -> anyhow::Result<()> {
    // L'etat est PARTAGE entre connexions: le client de l'API Clash ouvre une
    // connexion par requete (`Connection: close`), donc un etat par connexion
    // oublierait la bascule entre le PUT et le GET qui la verifie.
    let etat = std::sync::Arc::new(std::sync::Mutex::new(config.etat()));
    loop {
        let (flux, _) = ecoute.accept().await?;
        let secret = config.secret.clone();
        let etat = std::sync::Arc::clone(&etat);
        tokio::spawn(async move {
            let _ = repondre(flux, &secret, &etat).await;
        });
    }
}

/// Joue le role du daemon: lance une doublure, annonce son PID, puis attend
/// d'etre tue. Sert a eprouver qu'un coeur ne survit pas a la mort brutale de
/// son parent, ce qu'aucun code d'arret ne peut prouver, puisque justement il
/// ne tourne pas dans ce cas.
///
/// Le pid annonce est TOUJOURS celui d'une doublure qui a repondu sur son API,
/// dans les deux branches. Un parent qui n'annonce rien a echoue avant, et le
/// dit par son statut de sortie et sa sortie d'erreur.
///
/// `avec_garde` a faux court-circuite le superviseur et lance le processus
/// sans aucune protection. C'est le temoin negatif: sans lui, une recette qui
/// verrait le petit-enfant mourir ne saurait pas si c'est grace a la garde ou
/// parce que le systeme le fait de toute facon.
/// `utilisateur` fait lancer la doublure sous un compte dedie, comme un vrai
/// coeur. C'est le seul moyen d'eprouver que la garde anti-orphelin SURVIT a
/// la baisse de privilege: `PR_SET_PDEATHSIG` est efface quand les credentials
/// d'un processus changent, donc l'ordre dans lequel la bibliotheque standard
/// applique l'UID et nos closures `pre_exec` decide si la garde tient ou
/// disparait en silence.
pub async fn parent(
    chemin: &Path,
    avec_garde: bool,
    utilisateur: Option<super::lancement::Utilisateur>,
) -> anyhow::Result<()> {
    let brut = std::fs::read_to_string(chemin)?;
    let config: Configuration = serde_json::from_str(&brut)?;
    let moi = std::env::current_exe()?;

    let pid = if avec_garde {
        let lancement = Lancement {
            programme: moi,
            arguments: vec!["--faux-coeur".into(), chemin.to_path_buf().into()],
            configuration: chemin.to_path_buf(),
            api_clash: Some(config.port),
            utilisateur,
        };
        let en_cours = super::superviseur::demarrer(
            bifrost_evasion::Coeur::SingBox,
            &lancement,
            &config.secret,
        )
        .await?;
        let pid = en_cours.pid().unwrap_or(0);
        // Volontairement fuite: on veut que le processus reste en vie apres la
        // mort de ce parent, pour que la recette observe qui le tue.
        std::mem::forget(en_cours);
        pid
    } else {
        let mut enfant = std::process::Command::new(&moi)
            .arg("--faux-coeur")
            .arg(chemin)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()?;
        let pid = enfant.id();
        if let Err(e) = attendre_en_service(
            &mut enfant,
            SocketAddr::from(([127, 0, 0, 1], config.port)),
            &config.secret,
            chemin,
        )
        .await
        {
            // Le petit-enfant n'est pas entre en service: on ne le laisse pas
            // en orphelin. Un `std::process::Child` ne tue rien a sa chute,
            // contrairement au chemin avec garde qui, lui, VEUT que le
            // petit-enfant survive.
            let _ = enfant.kill();
            let _ = enfant.wait();
            return Err(e);
        }
        std::mem::forget(enfant);
        pid
    };

    println!("{pid}");
    use std::io::Write;
    std::io::stdout().flush()?;

    // Attend d'etre tue. Aucun code d'arret ne tournera.
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
    }
}

/// Budget laisse a la doublure sans garde pour repondre avant d'etre annoncee.
///
/// Le meme que celui du superviseur, pour que les deux branches de [`parent`]
/// annoncent leur pid aux memes conditions.
const BUDGET_SANS_GARDE: std::time::Duration = super::superviseur::BUDGET_DEMARRAGE;

/// Attend que la doublure lancee SANS superviseur reponde sur son API, ou dit
/// pourquoi elle ne repondra jamais.
///
/// # Pourquoi le pid annonce attend une reponse, depuis le 05/09/2026
///
/// La branche avec garde de [`parent`] passe par `superviseur::demarrer`, qui
/// ne rend la main qu'une fois l'API interrogee avec succes: le pid qu'elle
/// annonce est celui d'un coeur EN SERVICE. Cette branche-ci annoncait le sien
/// aussitot le `spawn`, avant l'exec, avant la lecture de la configuration,
/// avant le `bind`. La recette qui lit ce pid tue le parent dans la foulee et
/// exige que le petit-enfant survive: un petit-enfant mort de son DEMARRAGE,
/// port repris entre la liberation et le bind, ou configuration effacee sous
/// lui par une autre execution de la meme recette, se lisait alors comme
/// "mort sans garde". C'est une conclusion sur la garde tiree d'une panne qui
/// n'a rien a voir avec elle, et elle a signe un faux rouge le 04/09/2026 sur
/// essai-linux, pendant une ronde de falsifications. Reproduit le 05/09/2026
/// sur essai-linux avec une execution jumelle de la meme recette: voir
/// `tests/coeurs.rs`, `repertoire_temporaire`.
///
/// Sans superviseur, donc sans `PR_SET_PDEATHSIG` ni objet Job: c'est tout le
/// point de cette branche, et la raison pour laquelle elle ne peut pas
/// simplement appeler `demarrer`. Elle en reprend seulement l'ordre: un
/// processus deja sorti est dit tel quel, un secret refuse n'attend pas, et
/// l'echeance est nommee quand elle tombe.
///
/// Une reponse ne compte que si la doublure a ecrit qu'elle tient son port
/// ([`Liaison::Liee`]). Sans cette condition, n'importe quelle ecoute du port
/// qui repond 200 - un autre processus qui l'aurait pris avant elle - pouvait
/// faire annoncer le pid d'une doublure morte de son `bind`.
async fn attendre_en_service(
    enfant: &mut std::process::Child,
    api: SocketAddr,
    secret: &str,
    configuration: &Path,
) -> anyhow::Result<()> {
    let debut = tokio::time::Instant::now();
    loop {
        if let Some(statut) = enfant.try_wait()? {
            anyhow::bail!(
                "la doublure sans garde s'est arretee avant de repondre (statut {statut}, temoin: {})",
                liaison(configuration).en_texte()
            );
        }
        if debut.elapsed() >= BUDGET_SANS_GARDE {
            anyhow::bail!(
                "la doublure sans garde n'a pas repondu sur {api} en {BUDGET_SANS_GARDE:?}"
            );
        }
        match super::clash::interroger_version(api, secret).await {
            Ok(_) if liaison(configuration) == Liaison::Liee => return Ok(()),
            Ok(_) => tokio::time::sleep(super::clash::PAS_DE_SONDAGE).await,
            Err(e) if format!("{e}").contains("refuse le secret") => return Err(e),
            Err(_) => tokio::time::sleep(super::clash::PAS_DE_SONDAGE).await,
        }
    }
}

async fn repondre(
    mut flux: TcpStream,
    secret: &str,
    etat: &std::sync::Mutex<Etat>,
) -> anyhow::Result<()> {
    let mut tampon = vec![0u8; 4096];
    let n = flux.read(&mut tampon).await?;
    let requete = String::from_utf8_lossy(&tampon[..n]).into_owned();
    let reponse = {
        let mut etat = etat
            .lock()
            .expect("l'etat de la doublure n'est jamais empoisonne");
        router(&requete, secret, &mut etat)
    };
    flux.write_all(reponse.as_bytes()).await?;
    flux.flush().await?;
    Ok(())
}

/// Le routage, separe des sockets pour etre testable directement.
pub fn router(requete: &str, secret: &str, etat: &mut Etat) -> String {
    let ligne = requete.lines().next().unwrap_or("");
    let mut morceaux = ligne.split(' ');
    let methode = morceaux.next().unwrap_or("");
    let chemin = morceaux.next().unwrap_or("");

    if !requete.contains(&format!("Authorization: Bearer {secret}\r\n")) {
        return reponse(401, "");
    }
    match (methode, chemin) {
        ("GET", "/version") => reponse(200, "{\"version\":\"doublure\"}"),
        ("GET", c) => match nom_du_selecteur(c) {
            Some(nom) if etat.sert(&nom) => reponse(200, &etat.json()),
            _ => reponse(404, ""),
        },
        ("PUT", c) => {
            let Some(nom) = nom_du_selecteur(c) else {
                return reponse(404, "");
            };
            if !etat.sert(&nom) {
                return reponse(404, "");
            }
            // Une sortie inconnue est refusee, comme sing-box 1.13.18 le fait.
            // C'est le refus qui rend la doublure utile: sans lui, elle
            // repondrait oui a une bascule vers une sortie qui n'existe pas.
            match corps_demande(requete) {
                Some(sortie) if etat.choisir(&sortie) => reponse(204, ""),
                _ => reponse(404, ""),
            }
        }
        _ => reponse(404, ""),
    }
}

/// Le nom du selecteur vise par un chemin `/proxies/<nom>`, decode.
///
/// Rend `None` pour tout autre chemin, y compris `/proxies/<nom>/delay` - la
/// sonde de vitalite est une AUTRE ressource, et la confondre avec le selecteur
/// ferait rendre 204 a une sonde.
fn nom_du_selecteur(chemin: &str) -> Option<String> {
    let reste = chemin.strip_prefix("/proxies/")?;
    if reste.is_empty() || reste.contains('/') || reste.contains('?') {
        return None;
    }
    Some(decoder_segment(reste))
}

/// L'inverse de l'encodage que fait [`super::clash`].
fn decoder_segment(s: &str) -> String {
    let octets = s.as_bytes();
    let mut sortie = Vec::with_capacity(octets.len());
    let mut i = 0;
    while i < octets.len() {
        if octets[i] == b'%' && i + 2 < octets.len() {
            let paire = std::str::from_utf8(&octets[i + 1..i + 3]).unwrap_or("");
            if let Ok(o) = u8::from_str_radix(paire, 16) {
                sortie.push(o);
                i += 3;
                continue;
            }
        }
        sortie.push(octets[i]);
        i += 1;
    }
    String::from_utf8_lossy(&sortie).into_owned()
}

/// La sortie demandee, lue dans le corps `{"name":"..."}`.
fn corps_demande(requete: &str) -> Option<String> {
    let corps = requete.split("\r\n\r\n").nth(1)?;
    let v: serde_json::Value = serde_json::from_str(corps).ok()?;
    v.get("name")?.as_str().map(str::to_owned)
}

fn reponse(statut: u16, corps: &str) -> String {
    let texte = match statut {
        200 => "OK",
        204 => "No Content",
        401 => "Unauthorized",
        _ => "Not Found",
    };
    format!(
        "HTTP/1.1 {statut} {texte}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{corps}",
        corps.len()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Une doublure qui ne sert aucun selecteur: l'etat d'avant le 20 aout 2026.
    fn muette() -> Etat {
        Etat::nouvel("", &[])
    }

    /// Une doublure qui sert `select` avec deux sorties, la premiere active.
    fn a_deux_sorties() -> Etat {
        Etat::nouvel("select", &["sortie-a".to_owned(), "sortie-b".to_owned()])
    }

    fn get(chemin: &str, etat: &mut Etat) -> String {
        router(
            &super::super::clash::requete("GET", chemin, "bon", None),
            "bon",
            etat,
        )
    }

    fn put(chemin: &str, sortie: &str, etat: &mut Etat) -> String {
        let corps = super::super::clash::corps_de_selection(sortie);
        router(
            &super::super::clash::requete("PUT", chemin, "bon", Some(&corps)),
            "bon",
            etat,
        )
    }

    #[test]
    fn la_version_est_servie_avec_le_bon_secret() {
        let r = router(
            "GET /version HTTP/1.1\r\nAuthorization: Bearer bon\r\n\r\n",
            "bon",
            &mut muette(),
        );
        assert!(r.starts_with("HTTP/1.1 200 "));
        assert!(r.ends_with("{\"version\":\"doublure\"}"));
    }

    #[test]
    fn un_mauvais_secret_rend_401_et_pas_un_silence() {
        // Le superviseur distingue les deux: un 401 arrete l'attente tout de
        // suite, un silence la fait durer jusqu'a l'echeance.
        let r = router(
            "GET /version HTTP/1.1\r\nAuthorization: Bearer mauvais\r\n\r\n",
            "bon",
            &mut muette(),
        );
        assert!(r.starts_with("HTTP/1.1 401 "));
    }

    #[test]
    fn un_secret_absent_rend_401() {
        let r = router("GET /version HTTP/1.1\r\n\r\n", "bon", &mut muette());
        assert!(r.starts_with("HTTP/1.1 401 "));
    }

    /// Ce qui manquait: une bascule se LIT apres avoir ete demandee.
    ///
    /// Avant le 20 aout 2026 le `PUT` rendait 204 sans rien retenir et le `GET`
    /// rendait 404. [`super::super::bascule::basculer`] concluait donc toujours
    /// `Refusee`, et rien de la chaine construite au-dessus n'etait
    /// atteignable sans binaire tiers.
    #[test]
    fn un_put_change_ce_que_le_get_rapporte() {
        let mut etat = a_deux_sorties();
        let avant = get("/proxies/select", &mut etat);
        assert!(avant.starts_with("HTTP/1.1 200 "), "{avant}");
        assert!(avant.contains("\"now\":\"sortie-a\""), "{avant}");

        let bascule = put("/proxies/select", "sortie-b", &mut etat);
        assert!(bascule.starts_with("HTTP/1.1 204 "), "{bascule}");

        let apres = get("/proxies/select", &mut etat);
        assert!(apres.contains("\"now\":\"sortie-b\""), "{apres}");
    }

    /// Une sortie inconnue est REFUSEE, et rien ne bouge.
    ///
    /// Mesure sur sing-box 1.13.18 le 20 aout 2026: une etiquette absente du
    /// groupe rend un statut non-204. Une doublure qui dirait oui ferait croire
    /// la course avancee pendant que le trafic resterait sur la sortie gelee.
    #[test]
    fn une_sortie_inconnue_est_refusee_et_ne_change_rien() {
        let mut etat = a_deux_sorties();
        let r = put("/proxies/select", "sortie-inexistante", &mut etat);
        assert!(!r.starts_with("HTTP/1.1 204 "), "{r}");
        assert_eq!(etat.courante(), "sortie-a");
    }

    /// Un selecteur qui n'est pas celui servi est introuvable, dans les deux
    /// sens. Sans ce refus, une faute de frappe dans le nom du selecteur
    /// passerait pour une bascule reussie.
    #[test]
    fn un_selecteur_inconnu_est_introuvable() {
        let mut etat = a_deux_sorties();
        assert!(get("/proxies/autre", &mut etat).starts_with("HTTP/1.1 404 "));
        let r = put("/proxies/autre", "sortie-b", &mut etat);
        assert!(r.starts_with("HTTP/1.1 404 "), "{r}");
        assert_eq!(etat.courante(), "sortie-a");
    }

    /// La ressource visee est UN SEGMENT, decode, et rien d'autre.
    ///
    /// Deux cas, et le second seul mesure quelque chose - la falsification l'a
    /// montre. Une premiere version de cette recette n'exigeait que le premier:
    /// que `/proxies/select/delay?...` ne soit pas servi. Mais ce chemin-la est
    /// deja refuse par la comparaison de nom, `select/delay?...` n'etant pas
    /// `select`: retirer la garde laissait la recette verte. Elle ne gardait
    /// rien.
    ///
    /// Le second cas la rend mesurable. Un selecteur nomme `a/b` s'atteint par
    /// `/proxies/a%2Fb`, forme que le client produit. Le chemin BRUT
    /// `/proxies/a/b` est un chemin a deux segments, pas la forme encodee de ce
    /// nom, et doit rester introuvable - sans quoi la doublure servirait une
    /// ressource par un chemin que le client n'emet jamais.
    #[test]
    fn la_ressource_visee_est_un_seul_segment_decode() {
        let mut etat = a_deux_sorties();
        let sonde = super::super::clash::chemin_du_delai(
            "select",
            "https://exemple.test/204",
            std::time::Duration::from_secs(1),
        );
        assert!(
            get(&sonde, &mut etat).starts_with("HTTP/1.1 404 "),
            "{sonde}"
        );

        let mut biscornu = Etat::nouvel("a/b", &["sortie-a".to_owned(), "sortie-b".to_owned()]);
        // La forme encodee, celle que le client emet: servie.
        let encode = super::super::clash::chemin_du_selecteur("a/b");
        assert_eq!(encode, "/proxies/a%2Fb");
        assert!(get(&encode, &mut biscornu).starts_with("HTTP/1.1 200 "));
        // La forme brute, a deux segments: introuvable.
        assert!(
            get("/proxies/a/b", &mut biscornu).starts_with("HTTP/1.1 404 "),
            "un chemin a deux segments ne designe pas un selecteur"
        );
        let r = put("/proxies/a/b", "sortie-b", &mut biscornu);
        assert!(r.starts_with("HTTP/1.1 404 "), "{r}");
        assert_eq!(biscornu.courante(), "sortie-a");
    }

    /// Un nom de selecteur qui a du etre encode se retrouve tel quel.
    ///
    /// Le client encode `mon selecteur` en `mon%20selecteur`. Sans decodage
    /// symetrique ici, la doublure ne reconnaitrait jamais son propre selecteur
    /// des qu'il porte un espace, et le defaut ne se verrait qu'en exploitation.
    #[test]
    fn un_nom_encode_par_le_client_est_reconnu() {
        let mut etat = Etat::nouvel("mon selecteur", &["a".to_owned(), "b".to_owned()]);
        let chemin = super::super::clash::chemin_du_selecteur("mon selecteur");
        assert_eq!(chemin, "/proxies/mon%20selecteur");
        assert!(get(&chemin, &mut etat).starts_with("HTTP/1.1 200 "));
        assert!(put(&chemin, "b", &mut etat).starts_with("HTTP/1.1 204 "));
        assert_eq!(etat.courante(), "b");
    }

    /// Une doublure sans selecteur declare rend 404, comme avant.
    ///
    /// Les configurations ecrites par les recettes anterieures n'ont ni
    /// `selecteur` ni `sorties`: elles doivent continuer de fonctionner, et
    /// surtout ne pas se mettre a servir un selecteur nomme par la chaine vide.
    #[test]
    fn une_doublure_sans_selecteur_ne_sert_aucun_selecteur() {
        let mut etat = muette();
        assert!(get("/proxies/", &mut etat).starts_with("HTTP/1.1 404 "));
        assert!(get("/proxies/select", &mut etat).starts_with("HTTP/1.1 404 "));
        // Le cas piege: le chemin du selecteur NOMME par la chaine vide.
        let chemin = super::super::clash::chemin_du_selecteur("");
        assert!(
            get(&chemin, &mut etat).starts_with("HTTP/1.1 404 "),
            "{chemin}"
        );
    }

    /// Une configuration ancienne se relit sans ses nouveaux champs.
    #[test]
    fn une_configuration_sans_selecteur_se_relit() {
        let c: Configuration =
            serde_json::from_str(r#"{"port":1234,"secret":"s"}"#).expect("relecture");
        assert_eq!(c.port, 1234);
        assert!(c.selecteur.is_empty());
        assert!(c.sorties.is_empty());
        assert_eq!(c.etat(), muette());
    }

    /// La selection initiale est la PREMIERE sortie, comme chez sing-box.
    #[test]
    fn la_selection_initiale_est_la_premiere_sortie() {
        let etat = Etat::nouvel("select", &["a".to_owned(), "b".to_owned()]);
        assert_eq!(etat.courante(), "a");
    }

    #[test]
    fn un_secret_prefixe_ne_passe_pas_pour_le_bon() {
        // "bo" ne doit pas ouvrir la porte de "bon".
        let r = router(
            "GET /version HTTP/1.1\r\nAuthorization: Bearer bo\r\n\r\n",
            "bon",
            &mut muette(),
        );
        assert!(r.starts_with("HTTP/1.1 401 "));
    }

    /// Un corps qui ne NOMME aucune sortie est refuse.
    ///
    /// Cette recette s'appelait `la_bascule_rend_204` et posait exactement ce
    /// corps-la, `{}`, pour en exiger un 204. Elle encodait donc la
    /// complaisance qu'on vient de retirer: la doublure disait oui a une
    /// bascule qui ne demandait rien. Elle exige maintenant le contraire.
    #[test]
    fn un_corps_sans_nom_de_sortie_est_refuse() {
        let mut etat = a_deux_sorties();
        let r = router(
            "PUT /proxies/select HTTP/1.1\r\nAuthorization: Bearer bon\r\n\r\n{}",
            "bon",
            &mut etat,
        );
        assert!(!r.starts_with("HTTP/1.1 204 "), "{r}");
        assert_eq!(etat.courante(), "sortie-a");
    }

    /// Chaque etat du temoin se relit tel qu'il a ete ecrit, et un temoin
    /// illisible ne passe jamais pour un vol.
    #[test]
    fn le_temoin_de_liaison_se_relit_tel_quel() {
        for l in [
            Liaison::Liee,
            Liaison::PortPris { code: Some(98) },
            Liaison::PortPris { code: Some(10048) },
            Liaison::PortPris { code: None },
            Liaison::Echec("Permission denied (os error 13)".to_owned()),
        ] {
            assert_eq!(Liaison::depuis_le_texte(&l.en_texte()), l);
        }
        assert_eq!(Liaison::depuis_le_texte(""), Liaison::Inconnue);
        assert_eq!(
            Liaison::depuis_le_texte("n'importe quoi"),
            Liaison::Inconnue
        );
    }

    /// Un repertoire propre a cette execution et a cette recette.
    fn repertoire(nom: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("bifrost-doublure-{}-{nom}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn configuration_sur(rep: &Path, port: u16) -> PathBuf {
        let chemin = rep.join("doublure.json");
        std::fs::write(
            &chemin,
            serde_json::to_string(&Configuration {
                port,
                secret: "s".to_owned(),
                selecteur: String::new(),
                sorties: vec![],
            })
            .unwrap(),
        )
        .unwrap();
        chemin
    }

    /// Le port deja ecoute par un autre: la doublure echoue ET l'ecrit, avec
    /// le code du systeme. C'est la seule preuve de vol qu'un lanceur admet.
    #[tokio::test]
    async fn une_doublure_dont_le_port_est_pris_l_ecrit() {
        let rep = repertoire("port-pris");
        let tenu = super::super::port::reserver().unwrap();
        let chemin = configuration_sur(&rep, tenu.port());
        assert!(servir(&chemin).await.is_err(), "le port etait tenu");
        let temoin = liaison(&chemin);
        let _ = std::fs::remove_dir_all(&rep);
        assert!(
            matches!(temoin, Liaison::PortPris { code: Some(_) }),
            "{temoin:?}"
        );
    }

    /// Le port libre: la doublure le lie et l'ecrit avant de servir.
    #[tokio::test]
    async fn une_doublure_qui_lie_son_port_l_ecrit() {
        let rep = repertoire("liee");
        let reserve = super::super::port::reserver().unwrap();
        let chemin = configuration_sur(&rep, reserve.port());
        reserve.liberer();
        let c = chemin.clone();
        let tache = tokio::spawn(async move { servir(&c).await });
        let debut = std::time::Instant::now();
        let mut vu = liaison(&chemin);
        while vu == Liaison::Inconnue && debut.elapsed() < std::time::Duration::from_secs(5) {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            vu = liaison(&chemin);
        }
        tache.abort();
        let _ = std::fs::remove_dir_all(&rep);
        assert_eq!(vu, Liaison::Liee);
    }

    /// Seul un port deja pris se lit comme un vol. Un droit refuse, une
    /// adresse absente ou une erreur quelconque ne prouvent rien, et une doublure
    /// qui en meurt ne doit pas etre remontee sur un port neuf.
    #[cfg(any(target_os = "linux", windows))]
    #[test]
    fn seul_un_port_deja_pris_se_lit_comme_un_vol() {
        // EADDRINUSE; EACCES, EADDRNOTAVAIL.
        #[cfg(target_os = "linux")]
        let (pris, autres) = (98, [13, 99]);
        // WSAEADDRINUSE; WSAEACCES, WSAEADDRNOTAVAIL.
        #[cfg(windows)]
        let (pris, autres) = (10048, [10013, 10049]);
        assert_eq!(
            Liaison::depuis_l_erreur(&std::io::Error::from_raw_os_error(pris)),
            Liaison::PortPris { code: Some(pris) }
        );
        for code in autres {
            let l = Liaison::depuis_l_erreur(&std::io::Error::from_raw_os_error(code));
            assert!(matches!(l, Liaison::Echec(_)), "code {code}: {l:?}");
        }
        let l = Liaison::depuis_l_erreur(&std::io::Error::other("quelconque"));
        assert!(matches!(l, Liaison::Echec(_)), "{l:?}");
    }

    /// Un appel du lanceur factice: ce que la doublure aurait ecrit dans son
    /// temoin (rien pour `None`), et si le lanceur reussit.
    type Appel = (Option<Liaison>, bool);

    /// Un gabarit qui ne lance rien: le lanceur factice ne lit pas le programme.
    fn gabarit_factice() -> Gabarit {
        Gabarit {
            programme: PathBuf::from("lanceur-factice"),
            selecteur: String::new(),
            sorties: vec![],
        }
    }

    /// Le lanceur factice des recettes du juge. Il ne lance rien: il ecrit au
    /// temoin de l'essai ce que le script prevoit pour cet appel, comme la
    /// doublure l'aurait fait, et reussit ou echoue selon le script. Un appel
    /// que le script ne prevoit pas est un nouvel essai de trop, et le dit.
    fn factice(essai: &Essai, fait: &mut usize, script: &[Appel]) -> Result<usize, String> {
        let Some((temoin, reussit)) = script.get(*fait).cloned() else {
            panic!("appel {} du lanceur: un nouvel essai de trop", *fait + 1);
        };
        *fait += 1;
        if let Some(l) = temoin {
            noter(&temoin_de_liaison(&essai.lancement.configuration), &l);
        }
        if reussit {
            Ok(*fait)
        } else {
            Err(format!("refus du lanceur factice a l'appel {}", *fait))
        }
    }

    /// Joue `script` par [`lancer_sauf_vol`]; rend l'issue et le nombre
    /// d'appels du lanceur.
    fn par_lancer(nom: &str, script: &[Appel]) -> (Result<(usize, Essai), String>, usize) {
        let rep = repertoire(nom);
        let mut fait = 0;
        let issue = lancer_sauf_vol(&rep, &gabarit_factice(), |e| factice(e, &mut fait, script));
        let _ = std::fs::remove_dir_all(&rep);
        (issue, fait)
    }

    /// Joue `script` par [`demarrer_sauf_vol`], qui a sa propre boucle.
    async fn par_demarrer(nom: &str, script: &[Appel]) -> (Result<(usize, Essai), String>, usize) {
        let rep = repertoire(nom);
        let mut fait = 0;
        let issue = demarrer_sauf_vol(&rep, &gabarit_factice(), async |e: &Essai| {
            factice(e, &mut fait, script)
        })
        .await;
        let _ = std::fs::remove_dir_all(&rep);
        (issue, fait)
    }

    const VOL: Appel = (Some(Liaison::PortPris { code: Some(98) }), false);

    /// Un vol prouve au premier essai, la doublure liee au second: le second
    /// aboutit, sur sa propre configuration.
    fn vol_puis_liee(chemin: &str, (issue, fait): (Result<(usize, Essai), String>, usize)) {
        let (appel, essai) = issue.unwrap_or_else(|e| {
            panic!("{chemin}: un vol prouve au premier essai doit etre retente: {e}")
        });
        assert_eq!((appel, fait), (2, 2), "{chemin}");
        assert!(
            essai.lancement.configuration.ends_with("doublure-2.json"),
            "{chemin}: {:?}",
            essai.lancement.configuration
        );
    }

    #[test]
    fn lancer_sauf_vol_retente_un_vol_prouve_et_aboutit_au_second_essai() {
        vol_puis_liee(
            "lancer_sauf_vol",
            par_lancer("vol-puis-liee-l", &[VOL, (Some(Liaison::Liee), true)]),
        );
    }

    #[tokio::test]
    async fn demarrer_sauf_vol_retente_un_vol_prouve_et_aboutit_au_second_essai() {
        vol_puis_liee(
            "demarrer_sauf_vol",
            par_demarrer("vol-puis-liee-d", &[VOL, (Some(Liaison::Liee), true)]).await,
        );
    }

    /// Ce que le lanceur refuse sans vol prouve: la doublure a echoue a lier
    /// pour une autre raison, elle a lie son port et le lanceur l'a refusee
    /// quand meme (la reconnaissance du proprietaire, par exemple), ou elle
    /// n'a rien ecrit.
    fn sans_vol_prouve() -> [(&'static str, Appel, &'static str); 3] {
        [
            (
                "echec",
                (Some(Liaison::Echec("Permission denied".to_owned())), false),
                "echec Permission denied",
            ),
            ("liee", (Some(Liaison::Liee), false), "liee"),
            ("inconnue", (None, false), "inconnue"),
        ]
    }

    /// Rouge au premier essai, sans nouvel essai, et l'erreur dit pourquoi.
    fn un_seul_essai(
        chemin: &str,
        cas: &str,
        attendu: &str,
        (issue, fait): (Result<(usize, Essai), String>, usize),
    ) {
        let Err(e) = issue else {
            panic!("{chemin}, {cas}: un refus du lanceur ne peut pas aboutir");
        };
        assert_eq!(fait, 1, "{chemin}, {cas}: retente sans vol prouve: {e}");
        assert!(
            e.starts_with("refus du lanceur factice a l'appel 1"),
            "{chemin}, {cas}: l'erreur du lanceur doit etre rendue telle quelle: {e}"
        );
        assert!(
            e.contains(&format!("temoin de la doublure: {attendu};"))
                && e.contains("aucun vol de port prouve"),
            "{chemin}, {cas}: {e}"
        );
    }

    #[test]
    fn lancer_sauf_vol_ne_retente_pas_sans_vol_prouve() {
        for (cas, appel, attendu) in sans_vol_prouve() {
            let issue = par_lancer(&format!("sans-vol-l-{cas}"), &[appel]);
            un_seul_essai("lancer_sauf_vol", cas, attendu, issue);
        }
    }

    #[tokio::test]
    async fn demarrer_sauf_vol_ne_retente_pas_sans_vol_prouve() {
        for (cas, appel, attendu) in sans_vol_prouve() {
            let issue = par_demarrer(&format!("sans-vol-d-{cas}"), &[appel]).await;
            un_seul_essai("demarrer_sauf_vol", cas, attendu, issue);
        }
    }

    /// Un vol a chaque essai: exactement [`ESSAIS_SUR_VOL`] essais, puis un
    /// rouge qui nomme chacun des vols.
    fn epuisement(chemin: &str, (issue, fait): (Result<(usize, Essai), String>, usize)) {
        let Err(e) = issue else {
            panic!("{chemin}: un vol a chaque essai ne peut pas aboutir");
        };
        assert_eq!(fait, ESSAIS_SUR_VOL as usize, "{chemin}: {e}");
        assert!(
            e.contains(&format!("a chacun des {ESSAIS_SUR_VOL} essais")),
            "{chemin}: {e}"
        );
        assert_eq!(
            e.matches("pris avant le bind de la doublure").count(),
            ESSAIS_SUR_VOL as usize,
            "{chemin}: {e}"
        );
    }

    #[test]
    fn lancer_sauf_vol_s_arrete_apres_le_dernier_vol_et_le_nomme() {
        let script = vec![VOL; ESSAIS_SUR_VOL as usize];
        epuisement("lancer_sauf_vol", par_lancer("epuise-l", &script));
    }

    #[tokio::test]
    async fn demarrer_sauf_vol_s_arrete_apres_le_dernier_vol_et_le_nomme() {
        let script = vec![VOL; ESSAIS_SUR_VOL as usize];
        epuisement("demarrer_sauf_vol", par_demarrer("epuise-d", &script).await);
    }

    /// Un processus qui vit environ une seconde, sans rien ecouter.
    fn enfant_qui_vit_une_seconde() -> std::process::Child {
        #[cfg(unix)]
        let mut c = {
            let mut c = std::process::Command::new("sleep");
            c.arg("1");
            c
        };
        #[cfg(windows)]
        let mut c = {
            let mut c = std::process::Command::new("ping");
            c.args(["-n", "2", "127.0.0.1"]);
            c
        };
        c.stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("lancement de l'enfant temoin")
    }

    /// Une API qui repond ne suffit pas a annoncer la doublure sans garde: il
    /// faut qu'elle ait ecrit qu'elle tient son port. Ici l'API repond, mais
    /// c'est un autre qui ecoute (la recette elle-meme) et le temoin dit que
    /// le port a ete pris: aucune annonce, et l'erreur nomme le temoin quand
    /// l'enfant s'arrete. Le temoin de controle, `liee`, sur la meme API et un
    /// enfant du meme genre, est annonce: c'est donc bien le temoin qui decide.
    #[tokio::test]
    async fn une_api_qui_repond_sans_temoin_liee_n_annonce_pas_la_doublure() {
        let rep = repertoire("en-service");
        let ecoute = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let api = ecoute.local_addr().unwrap();
        let chemin = configuration_sur(&rep, api.port());
        let serveur = tokio::spawn(servir_sur(
            ecoute,
            Configuration {
                port: api.port(),
                secret: "s".to_owned(),
                selecteur: String::new(),
                sorties: vec![],
            },
        ));

        noter(&temoin_de_liaison(&chemin), &Liaison::Liee);
        let mut enfant = enfant_qui_vit_une_seconde();
        let controle = attendre_en_service(&mut enfant, api, "s", &chemin).await;
        let _ = enfant.kill();
        let _ = enfant.wait();

        noter(
            &temoin_de_liaison(&chemin),
            &Liaison::PortPris { code: Some(98) },
        );
        let mut enfant = enfant_qui_vit_une_seconde();
        let garde = attendre_en_service(&mut enfant, api, "s", &chemin).await;
        let _ = enfant.kill();
        let _ = enfant.wait();

        serveur.abort();
        let _ = std::fs::remove_dir_all(&rep);
        assert!(controle.is_ok(), "temoin `liee`: {controle:?}");
        let Err(e) = garde else {
            panic!("une API qui repond sans temoin `liee` a fait annoncer la doublure");
        };
        assert!(format!("{e}").contains("temoin: port-pris 98"), "{e}");
    }

    #[test]
    fn un_chemin_inconnu_rend_404() {
        let r = router(
            "GET /autre HTTP/1.1\r\nAuthorization: Bearer bon\r\n\r\n",
            "bon",
            &mut muette(),
        );
        assert!(r.starts_with("HTTP/1.1 404 "));
    }
}
