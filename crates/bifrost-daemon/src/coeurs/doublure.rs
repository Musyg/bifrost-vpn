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
use std::path::Path;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

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
pub async fn servir(chemin: &Path) -> anyhow::Result<()> {
    let brut = std::fs::read_to_string(chemin)?;
    let config: Configuration = serde_json::from_str(&brut)?;
    let adresse = SocketAddr::from(([127, 0, 0, 1], config.port));
    let ecoute = TcpListener::bind(adresse).await?;
    servir_sur(ecoute, config).await
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
    use super::lancement::Lancement;

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
async fn attendre_en_service(
    enfant: &mut std::process::Child,
    api: SocketAddr,
    secret: &str,
) -> anyhow::Result<()> {
    let debut = tokio::time::Instant::now();
    loop {
        if let Some(statut) = enfant.try_wait()? {
            anyhow::bail!(
                "la doublure sans garde s'est arretee avant de repondre (statut {statut})"
            );
        }
        if debut.elapsed() >= BUDGET_SANS_GARDE {
            anyhow::bail!(
                "la doublure sans garde n'a pas repondu sur {api} en {BUDGET_SANS_GARDE:?}"
            );
        }
        match super::clash::interroger_version(api, secret).await {
            Ok(_) => return Ok(()),
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
