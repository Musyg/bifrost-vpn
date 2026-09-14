//! La sonde de vitalite, confrontee a un VRAI sing-box.
//!
//! # Ce que cette recette apporte, et que les recettes pures ne peuvent pas
//!
//! Les trois issues de la sonde - le pair repond, le pair ne repond pas, je
//! n'ai pas pu demander - sont lues d'un statut HTTP. Ces statuts ne sont
//! ecrits NULLE PART en amont: ils ont ete obtenus en interrogeant le binaire
//! epingle. Une recette pure qui les recopie ne verifie que ma transcription;
//! elle resterait verte le jour ou une montee de version les changerait, et le
//! daemon lirait alors "le pair est mort" sur une simple faute de
//! configuration.
//!
//! # Ce que la sonde prouve exactement, mesure sur la source amont
//!
//! `common/urltest/urltest.go` de sing-box 1.13.18, lu le 20 aout 2026: la
//! requete est un `HEAD`, et le statut de la reponse n'est PAS regarde - la
//! fonction rend le temps ecoule des qu'une reponse HTTP arrive. `Aboutie` dit
//! donc "le transport a porte un aller-retour", et non "l'internet est
//! joignable": un portail captif qui repondrait une page de connexion
//! compterait comme un succes. C'est la bonne question pour ce qu'on cherche -
//! un tunnel gele ne repond RIEN - et la mauvaise pour juger d'un acces.
//!
//! # Pourquoi elle ne demande ni internet, ni privileges
//!
//! La cible est un serveur HTTP local monte par la recette. Le coeur la joint
//! par une sortie `direct`, donc sans quitter la machine, et l'aller-retour est
//! aussi reel qu'un autre: c'est la sortie du coeur qui compose, ce qui est
//! exactement ce que la sonde mesure en production.
//!
//! Le pair MUET est obtenu sans rien couper: une sortie SOCKS qui pointe sur un
//! port ou personne n'ecoute. Tout ce que le coeur tente d'y faire passer
//! echoue, ce qui est un transport mort par construction, et sans toucher au
//! reseau de la machine qui execute la recette.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use bifrost_daemon::coeurs::lancement::{self, Emplacements};
use bifrost_daemon::coeurs::vitalite::{self, Sonde};
use bifrost_evasion::Coeur;

/// Budget confie au coeur pour son aller-retour.
const BUDGET: Duration = Duration::from_secs(5);

/// Attente maximale du demarrage de l'API du coeur.
const DEMARRAGE: Duration = Duration::from_secs(10);

/// Ou trouver sing-box, ou pourquoi on ne peut pas.
///
/// Le depot ne distribue aucun binaire tiers et n'en telecharge pas depuis une
/// recette. L'exploitation designe le repertoire par `BIFROST_COEURS`, et le
/// chemin est ensuite construit par les MEMES fonctions que le daemon:
/// chercher le binaire autrement laisserait la recette verte sur un chemin que
/// la production ne prendrait jamais.
///
/// Sans repertoire, SKIPPED avec la raison. Jamais PASSED par defaut.
fn binaire_du_coeur() -> Result<PathBuf, String> {
    let Ok(repertoire) = std::env::var("BIFROST_COEURS") else {
        return Err(
            "BIFROST_COEURS ne designe aucun repertoire: cette recette veut un vrai \
                    sing-box, que le depot ne distribue pas"
                .to_owned(),
        );
    };
    let emplacements = Emplacements {
        binaires: PathBuf::from(&repertoire),
        configurations: PathBuf::from(&repertoire),
    };
    let chemin = lancement::chemin_binaire(&emplacements, Coeur::SingBox);
    if chemin.metadata().map(|m| m.is_file()).unwrap_or(false) {
        Ok(chemin)
    } else {
        Err(format!("{} n'existe pas", chemin.display()))
    }
}

fn port_mort() -> u16 {
    bifrost_daemon::coeurs::port::port_sans_personne().unwrap()
}

/// Un repertoire par RECETTE, et non par processus.
///
/// La premiere version le nommait sur le seul identifiant de processus. Les
/// deux recettes partageaient donc le meme, et cargo les fait tourner en
/// parallele: la premiere arrivee effacait le repertoire sous les pieds de
/// l'autre, qui echouait a ecrire sa configuration. Trouve en lancant la suite
/// entiere, pas la recette seule.
fn repertoire_de_travail(recette: &str) -> PathBuf {
    let r = std::env::temp_dir().join(format!("bifrost-vitalite-{}-{recette}", std::process::id()));
    std::fs::create_dir_all(&r).expect("le repertoire de travail doit exister");
    r
}

/// Un serveur qui repond 204 a tout, et rien d'autre.
///
/// Le pendant local de `generate_204`. La sonde emet un `HEAD`, donc la reponse
/// n'a pas de corps et n'en veut pas. `Connection: close` evite d'avoir a tenir
/// une connexion persistante pour un echange qui ne sert qu'une fois.
///
/// Le fil n'est jamais joint: il meurt avec le processus de la recette. Le
/// joindre demanderait de reveiller l'ecoute pour la faire sortir de sa boucle,
/// ce qui coute plus de code que ce que cela protege ici.
fn temoin_http() -> SocketAddr {
    let ecoute = TcpListener::bind("127.0.0.1:0").expect("le temoin doit ecouter");
    let adresse = ecoute.local_addr().unwrap();
    std::thread::spawn(move || {
        for flux in ecoute.incoming() {
            let Ok(mut flux) = flux else { return };
            let mut poubelle = [0u8; 1024];
            let _ = flux.read(&mut poubelle);
            let _ = flux.write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n");
        }
    });
    adresse
}

/// Un coeur lance, tue par son IDENTIFIANT quoi qu'il arrive.
///
/// Le `Drop` compte: une recette qui echoue au milieu laisserait sinon un
/// sing-box vivant sur la machine, et la suivante trouverait un port occupe
/// sans comprendre pourquoi.
struct CoeurVivant {
    enfant: Child,
    api: SocketAddr,
}

impl Drop for CoeurVivant {
    fn drop(&mut self) {
        let _ = self.enfant.kill();
        let _ = self.enfant.wait();
    }
}

/// Ecrit une configuration dont la sortie est vivante ou morte, et la lance.
fn lancer(binaire: &Path, repertoire: &Path, secret: &str, vivante: bool) -> CoeurVivant {
    // Vivante: `direct`, qui joint le temoin local sans quitter la machine.
    // Morte: un mandataire SOCKS sur un port ou personne n'ecoute. Le coeur ne
    // resout meme pas le nom de la cible - il le passe au mandataire - donc
    // l'echec vient bien du transport, et non d'une resolution absente.
    let sortie = if vivante {
        serde_json::json!({ "type": "direct", "tag": "profil" })
    } else {
        serde_json::json!({
            "type": "socks",
            "tag": "profil",
            "server": "127.0.0.1",
            "server_port": port_mort(),
        })
    };
    lancer_avec(binaire, repertoire, secret, vec![sortie])
}

/// Le meme, avec les sorties qu'on veut derriere le selecteur.
///
/// Sert a la bascule: elle a besoin d'AU MOINS DEUX sorties pour qu'il y ait
/// quelque chose a changer, et la recette de vitalite n'en demandait qu'une.
/// Le defaut du selecteur est la premiere de la liste, comme le fait notre
/// generateur.
fn lancer_avec(
    binaire: &Path,
    repertoire: &Path,
    secret: &str,
    sorties: Vec<serde_json::Value>,
) -> CoeurVivant {
    // Les deux ports que le sing-box va lier, tenus jusqu'a son lancement.
    let reserve_api = bifrost_daemon::coeurs::port::reserver().unwrap();
    let reserve_entree = bifrost_daemon::coeurs::port::reserver().unwrap();
    let port_api = reserve_api.port();
    let etiquettes: Vec<String> = sorties
        .iter()
        .map(|s| {
            s["tag"]
                .as_str()
                .expect("chaque sortie a une etiquette")
                .to_owned()
        })
        .collect();
    let mut outbounds = sorties;
    outbounds.push(serde_json::json!({
        "type": "selector",
        "tag": "select",
        "outbounds": etiquettes,
        "default": etiquettes.first(),
    }));
    let configuration = serde_json::json!({
        "log": { "level": "warn", "timestamp": false },
        "inbounds": [{
            "type": "socks",
            "tag": "entree",
            "listen": "127.0.0.1",
            "listen_port": reserve_entree.port(),
        }],
        "outbounds": outbounds,
        "route": { "final": "select" },
        "experimental": {
            "clash_api": {
                "external_controller": format!("127.0.0.1:{port_api}"),
                "secret": secret,
            }
        }
    });
    let fichier = repertoire.join(format!("sing-box-{port_api}.json"));
    std::fs::write(
        &fichier,
        serde_json::to_string_pretty(&configuration).unwrap(),
    )
    .expect("la configuration doit s'ecrire");

    // Rendus a l'instant ou le coeur va les prendre, et pas avant.
    reserve_api.liberer();
    reserve_entree.liberer();
    let enfant = Command::new(binaire)
        .arg("run")
        .arg("-c")
        .arg(&fichier)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("le coeur doit se lancer");

    let coeur = CoeurVivant {
        enfant,
        api: format!("127.0.0.1:{port_api}").parse().unwrap(),
    };
    let debut = Instant::now();
    while debut.elapsed() < DEMARRAGE {
        if std::net::TcpStream::connect_timeout(&coeur.api, Duration::from_millis(200)).is_ok() {
            return coeur;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("l'API de controle du coeur n'a pas repondu en {DEMARRAGE:?}");
}

fn executeur() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("le runtime doit se construire")
}

fn adresse(api: SocketAddr, secret: &str) -> vitalite::Adresse {
    vitalite::Adresse {
        api,
        secret: secret.to_owned(),
        selecteur: "select".to_owned(),
    }
}

#[test]
fn les_quatre_issues_de_la_sonde_tiennent_face_a_un_vrai_coeur() {
    let binaire = match binaire_du_coeur() {
        Ok(b) => b,
        Err(raison) => {
            println!(
                "SKIPPED les_quatre_issues_de_la_sonde_tiennent_face_a_un_vrai_coeur: {raison}"
            );
            return;
        }
    };
    let repertoire = repertoire_de_travail("issues");
    let secret = bifrost_daemon::coeurs::alea::secret().expect("un secret");
    // La cible de production vise l'internet; ici elle vise le temoin local.
    // Le CHEMIN mesure est le meme: c'est la sortie du coeur qui compose.
    let cible = format!("http://{}/generate_204", temoin_http());
    let ex = executeur();

    // --- Le pair repond ---------------------------------------------------
    let vivant = lancer(&binaire, &repertoire, &secret, true);
    assert_eq!(
        ex.block_on(vitalite::sonder(
            &adresse(vivant.api, &secret),
            &cible,
            BUDGET
        )),
        Sonde::Aboutie,
        "un transport vivant doit rendre Aboutie"
    );
    drop(vivant);

    // --- Le pair ne repond pas -------------------------------------------
    let mort = lancer(&binaire, &repertoire, &secret, false);
    assert_eq!(
        ex.block_on(vitalite::sonder(
            &adresse(mort.api, &secret),
            &cible,
            BUDGET
        )),
        Sonde::Echouee,
        "un transport mort doit rendre Echouee, et non Impossible: c'est bien le RESEAU qui \
         a dit non, et c'est la seule issue qui autorise a demonter le tunnel"
    );

    // --- Un secret refuse est une panne CHEZ NOUS -------------------------
    assert_eq!(
        ex.block_on(vitalite::sonder(
            &adresse(mort.api, "pas-le-bon-secret"),
            &cible,
            BUDGET
        )),
        Sonde::Impossible,
        "un secret refuse doit rendre Impossible: le confondre avec un pair muet demonterait \
         un tunnel sain sur une faute de configuration"
    );

    // --- Une sortie inconnue aussi ----------------------------------------
    let mut inconnue = adresse(mort.api, &secret);
    inconnue.selecteur = "selecteur-qui-n-existe-pas".to_owned();
    assert_eq!(
        ex.block_on(vitalite::sonder(&inconnue, &cible, BUDGET)),
        Sonde::Impossible,
        "une sortie inconnue ne dit rien du pair"
    );
    drop(mort);

    // --- Et une API absente non plus --------------------------------------
    // L'etat que le superviseur traverse a chaque bascule de technique: le
    // coeur precedent est mort, le suivant n'ecoute pas encore.
    let injoignable: SocketAddr = format!("127.0.0.1:{}", port_mort()).parse().unwrap();
    assert_eq!(
        ex.block_on(vitalite::sonder(
            &adresse(injoignable, &secret),
            &cible,
            BUDGET
        )),
        Sonde::Impossible,
        "une API injoignable ne dit rien du pair"
    );

    let _ = std::fs::remove_dir_all(&repertoire);
}

/// La poignee est le seul chemin que le superviseur emprunte, et sa propriete
/// n'est pas le verdict: c'est de ne JAMAIS le faire attendre.
///
/// Le fil du superviseur tient le kill switch. L'y faire patienter cinq
/// secondes sur une reponse reseau suspendrait tout le daemon a chaque silence
/// de tunnel. La recette le constate en vrai: `demander` rend la main tout de
/// suite, `ramasser` rend `None` tant que la reponse n'est pas la, et le
/// verdict finit par arriver.
///
/// Le coeur est celui dont le transport est MORT, pour que la recette n'ait
/// besoin d'aucun acces a internet: la sortie SOCKS pointe sur un port ferme,
/// donc l'echec ne depend pas de la cible visee - et c'est bien la vraie qui
/// est visee ici, celle de production, puisque c'est `ouvrir` qui la choisit.
/// La bascule a chaud, face a un VRAI coeur.
///
/// Trois proprietes, et aucune ne se lit dans la documentation amont:
///
/// 1. une bascule vers une sortie existante est FAITE, et le coeur le confirme
///    quand on le relit;
/// 2. une bascule vers une etiquette inconnue est REFUSEE - c'est le cas qui
///    arriverait si le vocabulaire de la course et celui des etiquettes
///    divergeaient un jour;
/// 3. la sortie servie change vraiment, ce qui est la seule chose qui compte:
///    un 204 dit que le coeur a compris, pas qu'il a change.
///
/// La troisieme est celle qui a motive la relecture. Sans elle, une bascule
/// refusee en silence laisserait le trafic sur la sortie gelee, et la course se
/// croirait avancee.
#[test]
fn la_bascule_change_vraiment_de_sortie_et_le_dit() {
    let binaire = match binaire_du_coeur() {
        Ok(b) => b,
        Err(raison) => {
            println!("SKIPPED la_bascule_change_vraiment_de_sortie_et_le_dit: {raison}");
            return;
        }
    };
    let repertoire = repertoire_de_travail("bascule");
    let secret = "secret-de-recette-bascule";
    // Deux sorties directes: ce qu'on mesure est le PILOTAGE du selecteur, pas
    // le transport. Deux `direct` suffisent et ne quittent pas la machine.
    let coeur = lancer_avec(
        &binaire,
        &repertoire,
        secret,
        vec![
            serde_json::json!({ "type": "direct", "tag": "premier" }),
            serde_json::json!({ "type": "direct", "tag": "second" }),
        ],
    );
    let adresse = adresse(coeur.api, secret);
    let rt = executeur();

    let servie = rt
        .block_on(bifrost_daemon::coeurs::clash::lire_selection(
            adresse.api,
            &adresse.secret,
            &adresse.selecteur,
        ))
        .expect("le selecteur doit declarer une sortie active");
    assert_eq!(servie, "premier", "le defaut est la premiere de la liste");

    let issue = rt.block_on(bifrost_daemon::coeurs::bascule::basculer(
        &adresse, "second",
    ));
    assert_eq!(
        issue,
        bifrost_daemon::coeurs::bascule::Issue::Faite {
            sortie: "second".to_owned()
        },
        "une sortie qui existe doit etre servie apres la bascule"
    );

    let servie = rt
        .block_on(bifrost_daemon::coeurs::clash::lire_selection(
            adresse.api,
            &adresse.secret,
            &adresse.selecteur,
        ))
        .expect("le selecteur doit declarer une sortie active");
    assert_eq!(
        servie, "second",
        "la bascule doit avoir change la sortie servie, pas seulement rendu 204"
    );

    let issue = rt.block_on(bifrost_daemon::coeurs::bascule::basculer(
        &adresse,
        "cette-etiquette-n-existe-pas",
    ));
    assert!(
        matches!(
            issue,
            bifrost_daemon::coeurs::bascule::Issue::Refusee { .. }
        ),
        "une etiquette inconnue doit etre refusee, pas silencieusement ignoree: {issue:?}"
    );

    let servie = rt
        .block_on(bifrost_daemon::coeurs::clash::lire_selection(
            adresse.api,
            &adresse.secret,
            &adresse.selecteur,
        ))
        .expect("le selecteur doit declarer une sortie active");
    assert_eq!(
        servie, "second",
        "un refus ne doit rien avoir change: {servie}"
    );

    drop(coeur);
}

#[test]
fn la_poignee_rend_un_verdict_sans_jamais_faire_attendre_le_superviseur() {
    let binaire = match binaire_du_coeur() {
        Ok(b) => b,
        Err(raison) => {
            println!(
                "SKIPPED la_poignee_rend_un_verdict_sans_jamais_faire_attendre_le_superviseur: \
                 {raison}"
            );
            return;
        }
    };
    let repertoire = repertoire_de_travail("poignee");
    let secret = bifrost_daemon::coeurs::alea::secret().expect("un secret");
    let mort = lancer(&binaire, &repertoire, &secret, false);

    let (mut poignee, veille) = vitalite::ouvrir(adresse(mort.api, &secret));
    let ex = executeur();
    let issue = ex.block_on(async move {
        let tache = tokio::spawn(veille);

        let avant = Instant::now();
        assert!(poignee.demander(BUDGET), "la demande doit partir");
        assert!(
            avant.elapsed() < Duration::from_millis(50),
            "demander a fait attendre le superviseur {:?}",
            avant.elapsed()
        );

        let avant = Instant::now();
        assert!(
            poignee.ramasser().is_none(),
            "un verdict est arrive avant meme que la sonde soit partie"
        );
        assert!(
            avant.elapsed() < Duration::from_millis(50),
            "ramasser a fait attendre le superviseur {:?}",
            avant.elapsed()
        );

        let echeance = Instant::now();
        loop {
            if let Some(issue) = poignee.ramasser() {
                tache.abort();
                return issue;
            }
            assert!(
                echeance.elapsed() < BUDGET + vitalite::MARGE + Duration::from_secs(3),
                "la sonde n'a jamais rendu de verdict"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    });

    assert_eq!(
        issue,
        Sonde::Echouee,
        "le verdict d'un transport mort doit traverser la poignee inchange"
    );
    drop(mort);
    let _ = std::fs::remove_dir_all(&repertoire);
}
