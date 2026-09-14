//! Cycle de vie du resolveur chiffre embarque.
//!
//! Ce module ne reutilise pas `coeurs::superviseur`, et c'est delibere: celui-la
//! est asynchrone et porte l'API Clash, deux choses qu'un resolveur DNS n'a pas.
//! Ce qu'il en REPREND est nomme ici a chaque fois, parce que ce sont des
//! proprietes de securite et non des commodites: la garde anti-orphelin par
//! `PR_SET_PDEATHSIG`, le drainage continu de la sortie d'erreur, et l'arret
//! poli avant l'arret ferme.
//!
//! Le point qui domine, le meme que pour les coeurs: **le resolveur ne doit
//! jamais survivre au daemon**. Un dnscrypt-proxy orphelin garde son ecoute sur
//! le :53 de la boucle locale. Le systeme continuerait de l'interroger alors
//! que plus personne ne le supervise, que le tunnel est tombe et que le kill
//! switch ne connait plus son compte: la resolution s'arreterait sans que rien
//! n'explique pourquoi, ou pire, reprendrait par un chemin que personne n'a
//! choisi.
//!
//! Cette garde-la a failli n'etre qu'une affirmation. Le noyau efface
//! `pdeath_signal` des que les identifiants d'un processus changent
//! (`commit_creds`), et la premiere version confiait la baisse de privilege a
//! dnscrypt-proxy par son `user_name`: le `setuid` desarmait la garde en
//! silence. Mesure sur essai-linux le 17/08/2026, daemon tue par SIGKILL: avec
//! `user_name`, le resolveur survivait, reparente a init, ecoute intacte sur
//! le :53; sans lui, il mourait avec. Les deux proprietes de securite etaient
//! en conflit direct et rien ne le disait, parce que tous les controles
//! passaient par un arret propre, qui ne prouve rien sur ce qui arrive quand
//! l'arret propre est impossible.
//!
//! D'ou l'ordre actuel, et il n'est pas negociable: le daemon prend les
//! identifiants LUI-MEME entre le fork et l'exec, puis arme la garde APRES.
//! Le resolveur ne passe plus une seule instruction en root, et ce qu'il lui
//! reste pour se lier au :53 est une capacite ambiante et rien d'autre. Le
//! controle `--resolveur-selftest` mesure les deux.

use std::io::Read;
use std::net::{SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bifrost_core::{Error, Result};

/// Budget d'attente avant de declarer que le resolveur ne repondra pas.
///
/// Mesure et non devine. Un demarrage a FROID, sans liste de serveurs en
/// cache, enchaine trois choses qui traversent toutes le tunnel: resoudre le
/// nom de l'hebergeur de la source par les bootstrap, telecharger la liste,
/// verifier sa signature, puis negocier avec le serveur chiffre. Mesure du
/// 17/08/2026 sur essai-linux: 20 s n'y suffisaient pas, et l'echec relancait tout
/// depuis zero. A CHAUD, la liste etant en cache, la reponse vient en
/// quelques secondes; ce budget ne sert donc qu'au premier demarrage.
const BUDGET_DEMARRAGE: Duration = Duration::from_secs(45);

/// Periode entre deux interrogations pendant l'attente.
const PAS: Duration = Duration::from_millis(250);

/// Delai laisse au resolveur pour s'arreter de lui-meme avant d'etre tue.
///
/// `cfg(unix)`: l'arret doux passe par SIGTERM, qui n'existe pas ailleurs.
#[cfg(unix)]
const DELAI_ARRET_DOUX: Duration = Duration::from_secs(3);

/// Delai laisse a la garde du systeme pour tuer un membre du job.
///
/// Distinct de `DELAI_ARRET_DOUX`, qui est `cfg(unix)` et mesure la politesse
/// d'un arret demande. Celui-ci mesure la reaction du systeme a une mort
/// brutale, ce qui n'est pas la meme question.
#[cfg(windows)]
const DELAI_ARRET_DOUX_WINDOWS: Duration = Duration::from_secs(5);

/// Delai d'une interrogation de disponibilite.
const DELAI_SONDE: Duration = Duration::from_millis(800);

/// Taille du journal d'erreur conserve.
///
/// La sortie d'erreur est drainee EN CONTINU et non a la demande: un tuyau que
/// personne ne lit finit par se remplir, et le resolveur se bloquerait en
/// ecrivant dedans. On garde la fin, parce que la derniere ligne porte la cause.
const TAILLE_JOURNAL: usize = 8 * 1024;

/// Nom qu'on demande au resolveur pendant l'attente de disponibilite.
///
/// Un nom du domaine reserve aux essais: aucune chance qu'il existe, et ce
/// n'est pas grave. Ce qui est mesure est que le resolveur REPONDE, pas ce
/// qu'il repond. Demander un vrai nom ferait dependre le demarrage du daemon
/// de l'etat d'Internet.
const NOM_DE_SONDE: &str = "disponibilite.invalid";

/// Ce que le resolveur a ecrit sur sa sortie d'erreur, borne et partageable.
#[derive(Clone, Default)]
pub struct JournalErreur(Arc<Mutex<String>>);

impl JournalErreur {
    fn pousser(&self, morceau: &str) {
        // `into_inner` sur un verrou empoisonne: un journal de diagnostic ne
        // doit jamais etre la raison pour laquelle le daemon panique.
        let mut j = self.0.lock().unwrap_or_else(|e| e.into_inner());
        j.push_str(morceau);
        if j.len() > TAILLE_JOURNAL {
            let debut = j.len() - TAILLE_JOURNAL;
            *j = j[debut..].to_owned();
        }
    }

    /// Les dernieres lignes, pretes a etre collees a un message d'erreur.
    pub fn dernieres_lignes(&self, n: usize) -> String {
        let j = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let lignes: Vec<&str> = j.lines().filter(|l| !l.trim().is_empty()).collect();
        lignes[lignes.len().saturating_sub(n)..].join(" | ")
    }
}

/// Ce que l'exploitation fournit pour qu'un resolveur puisse etre embarque.
///
/// Distinct de l'IDENTITE (le compte que le kill switch laisse emettre du
/// :53), qui est declaree separement et sert a restreindre. Ici il s'agit du
/// materiel: ou est le binaire, ou ecrire sa configuration, et quoi mettre
/// dedans.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Atelier {
    pub programme: PathBuf,
    pub configuration: PathBuf,
    /// Repertoire PERSISTANT du resolveur, distinct de celui de sa
    /// configuration. Il y garde la liste des serveurs chiffres; la perdre a
    /// chaque arret force un telechargement au demarrage suivant, dont
    /// l'echec empeche toute connexion.
    pub etat: PathBuf,
    pub serveurs: Vec<String>,
    pub bootstrap: Vec<std::net::IpAddr>,
    /// Compte sous lequel le daemon fait tourner le resolveur.
    ///
    /// Le daemon prend ces identifiants LUI-MEME avant l'exec: le laisser
    /// faire a dnscrypt-proxy par son `user_name` desarmait la garde
    /// anti-orphelin, mesure a l'appui.
    pub compte: Option<String>,
    /// Chemin du profil que le daemon detient (11b-2, ecart 3): son
    /// repertoire est REFUSE comme repertoire du resolveur, voir
    /// `repertoire_du_resolveur`. `#[cfg(windows)]` comme `Lancement::profil`.
    #[cfg(windows)]
    pub profil: PathBuf,
}

/// Identifiants que le daemon prend LUI-MEME avant d'exec le resolveur.
///
/// Resolus avant le `fork`, parce que `getpwnam` alloue et prend des verrous:
/// entre le fork et l'exec, l'appeler peut bloquer pour toujours.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bascule {
    pub uid: u32,
    pub gid: u32,
}

#[cfg(unix)]
impl Bascule {
    /// Resout un compte nomme, ou une paire `uid:gid`.
    pub fn pour(specification: &str) -> Result<Self> {
        let u = crate::coeurs::identite::lire_compte(specification)
            .map_err(|e| Error::Dns(format!("compte du resolveur {specification}: {e}")))?;
        if u.uid == 0 {
            return Err(Error::Dns(
                "le compte du resolveur ne peut pas etre root: la restriction du \
                 :53 nommerait alors l'uid 0, c'est-a-dire tout le systeme"
                    .to_owned(),
            ));
        }
        Ok(Self {
            uid: u.uid,
            gid: u.gid,
        })
    }
}

/// Tout ce qu'il faut pour demarrer le resolveur.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lancement {
    /// Executable dnscrypt-proxy. Fourni par l'empaquetage, jamais cherche
    /// dans le PATH: un tiers qui y placerait le sien serait exactement ce
    /// qu'un resolveur chiffre existe pour eviter.
    pub programme: PathBuf,
    /// Configuration engendree, deja ecrite sur le disque.
    pub configuration: PathBuf,
    /// Adresse d'ecoute, interrogee pour savoir s'il est pret.
    pub ecoute: SocketAddr,
    /// Identifiants pris avant l'exec, quand un compte est declare.
    pub bascule: Option<Bascule>,
    /// Compte de service Windows sous lequel lancer le resolveur (11b-1).
    ///
    /// Le pendant Windows de `bascule`, et son contraire de mecanisme. Sous
    /// Unix, le daemon prend les identifiants LUI-MEME entre fork et exec (voir
    /// `Bascule`). Sous Windows il n'y a pas de fork: le daemon ouvre un jeton
    /// pour le compte par `LogonUserW`, puis lance l'enfant sous ce jeton par
    /// `CreateProcessAsUserW`. `None` = le comportement d'avant 11b-1, le
    /// resolveur tourne sous le compte du daemon (LocalSystem en service). La
    /// forme recommandee est `LocalService` (arbitrage 11b, forme alpha,
    /// tranchee le 06/09/2026).
    #[cfg(windows)]
    pub compte: Option<String>,
    /// Repertoire d'etat du resolveur, ce qu'il ECRIT (11b-2).
    ///
    /// Sur le chemin sous compte, `demarrer_sous_compte` accorde au compte, a
    /// CHAQUE lancement, l'ecriture heritable de ce repertoire et la lecture
    /// heritable du repertoire de `configuration` (voir `ouvrir_au_compte`;
    /// ecart 2 du 13/09/2026: dnscrypt-proxy change lui-meme de repertoire
    /// courant vers celui de sa configuration, il lui faut le droit de
    /// l'OUVRIR, et la configuration comme la liste anti-telemetrie, qui y
    /// vivent, heritent de la lecture). En production ce repertoire est
    /// `%ProgramData%\Bifrost\resolveur` et l'etat son sous-repertoire `etat`.
    /// `#[cfg(windows)]` comme `compte`: ces champs forment le lot du
    /// lancement sous compte, que seul Windows connait; sous Unix la bascule
    /// d'identifiants et `partager_repertoire` font ce travail avant l'exec.
    #[cfg(windows)]
    pub etat: PathBuf,
    /// Chemin du profil que le daemon detient (11b-2, ecart 3 du 13/09/2026).
    ///
    /// Ouvrir au compte le repertoire de la configuration (ecart 2) ouvrirait
    /// aussi, cle privee comprise, un repertoire qui serait celui du profil:
    /// `repertoire_du_resolveur` REFUSE ce repertoire avant toute pose d'ACE,
    /// et il lui faut savoir ou vit le profil. L'argument `--profil` du
    /// daemon, qui vaut `bifrost_coffre::CHEMIN_PAR_DEFAUT` faute d'indication.
    #[cfg(windows)]
    pub profil: PathBuf,
}

/// Le processus du resolveur, quel que soit son mode de lancement.
///
/// Deux formes, parce que 11b-1 ajoute une seconde facon de lancer l'enfant.
/// `Ordinaire` est le seul chemin sous Unix - ou la bascule d'identifiants se
/// fait entre fork et exec sans changer d'API de lancement - et le chemin
/// Windows quand aucun compte de service n'est declare: `std::process::Command`,
/// le comportement d'avant 11b-1, a l'octet pres. `SousCompte` est le chemin
/// Windows de 11b-1: `CreateProcessAsUserW` sous un jeton ouvert par
/// `LogonUserW`, qui ne rend pas un `std::process::Child` mais une poignee de
/// processus brute. Les deux restent ENFANTS du daemon dans le job
/// anti-orphelin: `SousCompte` ne pose jamais `CREATE_BREAKAWAY_FROM_JOB`.
enum Processus {
    Ordinaire(Child),
    #[cfg(windows)]
    SousCompte(ProcessusSousCompte),
}

impl Processus {
    fn pid(&self) -> u32 {
        match self {
            Processus::Ordinaire(c) => c.id(),
            #[cfg(windows)]
            Processus::SousCompte(p) => p.pid,
        }
    }

    /// `Some(<code lisible>)` s'il est mort, `None` s'il tourne encore.
    fn terminaison(&mut self) -> std::io::Result<Option<String>> {
        match self {
            Processus::Ordinaire(c) => Ok(c.try_wait()?.map(|s| s.to_string())),
            #[cfg(windows)]
            Processus::SousCompte(p) => p.terminaison(),
        }
    }

    fn tuer(&mut self) -> std::io::Result<()> {
        match self {
            Processus::Ordinaire(c) => c.kill(),
            #[cfg(windows)]
            Processus::SousCompte(p) => p.tuer(),
        }
    }

    fn attendre(&mut self) {
        match self {
            Processus::Ordinaire(c) => {
                let _ = c.wait();
            }
            #[cfg(windows)]
            Processus::SousCompte(p) => p.attendre(),
        }
    }
}

/// Le resolveur en cours d'execution.
pub struct ResolveurEnCours {
    processus: Processus,
    journal: JournalErreur,
    ecoute: SocketAddr,
}

impl std::fmt::Debug for ResolveurEnCours {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolveurEnCours")
            .field("pid", &self.processus.pid())
            .field("ecoute", &self.ecoute)
            .finish()
    }
}

impl ResolveurEnCours {
    pub fn pid(&self) -> u32 {
        self.processus.pid()
    }

    /// Ce que le resolveur a dit sur sa sortie d'erreur.
    pub fn diagnostic(&self) -> String {
        self.journal.dernieres_lignes(3)
    }

    /// Interroge le resolveur jusqu'a ce qu'il reponde, ou jusqu'a l'echeance.
    fn attendre_disponible(&mut self) -> Result<()> {
        let echeance = Instant::now() + BUDGET_DEMARRAGE;
        let mut derniere = String::new();
        while Instant::now() < echeance {
            // Mort avant d'etre pret: inutile d'attendre l'echeance entiere, et
            // le message doit dire qu'il est MORT, pas qu'il est lent.
            if let Ok(Some(code)) = self.processus.terminaison() {
                return Err(Error::Dns(format!(
                    "le resolveur s'est arrete avant de repondre ({code})"
                )));
            }
            match interroger(self.ecoute) {
                Ok(()) => return Ok(()),
                Err(e) => derniere = e.to_string(),
            }
            std::thread::sleep(PAS);
        }
        Err(Error::Dns(format!(
            "le resolveur n'a pas repondu sur {} en {} s. Derniere tentative: {derniere}",
            self.ecoute,
            BUDGET_DEMARRAGE.as_secs()
        )))
    }

    /// Arrete le resolveur: poliment d'abord, fermement ensuite.
    pub fn arreter(mut self) -> Result<()> {
        #[cfg(unix)]
        {
            let pid = self.processus.pid();
            // SIGTERM laisse a dnscrypt-proxy le temps de fermer son ecoute.
            // Une erreur sur un PID deja disparu s'ignore: la course est
            // normale, l'enfant a pu sortir tout seul.
            // SAFETY: kill(pid, SIGTERM) ne touche aucune memoire; une erreur sur un PID
            // deja disparu est ignoree, la course est normale.
            unsafe {
                libc::kill(pid as libc::pid_t, libc::SIGTERM);
            }
            let echeance = Instant::now() + DELAI_ARRET_DOUX;
            while Instant::now() < echeance {
                match self.processus.terminaison() {
                    Ok(Some(_)) => return Ok(()),
                    Ok(None) => std::thread::sleep(PAS),
                    Err(e) => return Err(Error::Dns(format!("attente du resolveur: {e}"))),
                }
            }
        }
        // L'echec du kill ne s'ignore PAS, et `wait` ne doit surtout pas venir
        // apres sans l'avoir regarde: attendre un processus qu'on n'a pas le
        // droit de tuer, c'est attendre pour toujours. Cas reel, mesure sous
        // l'unite systemd le 17/08/2026: root ne peut pas signaler un
        // processus d'un autre UID sans CAP_KILL, le daemon restait bloque ici
        // et le resolveur gardait le :53. Un blocage silencieux est le pire
        // des deux resultats: il ne dit rien et il ne rend jamais la main.
        //
        // Sous Windows, le meme risque a une autre cause: un enfant lance sous
        // un compte de service (11b-1) tourne sous une identite differente de
        // celle du daemon. `TerminateProcess` reste possible parce que la
        // poignee possedee vient de `CreateProcessAsUserW`, qui la rend avec le
        // droit `PROCESS_TERMINATE`; c'est pour cela qu'on garde la poignee et
        // qu'on ne rouvre pas le processus par son seul PID.
        let pid = self.processus.pid();
        if let Err(e) = self.processus.tuer() {
            return Err(Error::Dns(format!(
                "le resolveur (pid {pid}) survit et ne peut pas etre tue: {e}. \
                 Le daemon a-t-il CAP_KILL? Signaler un processus d'un autre \
                 UID l'exige, meme en root"
            )));
        }
        self.processus.attendre();
        Ok(())
    }
}

/// Lance le resolveur et attend qu'il reponde a une requete.
///
/// Attendre une REPONSE et non la simple existence du processus: dnscrypt-proxy
/// demarre, ouvre son ecoute, puis passe plusieurs secondes a joindre sa source
/// et a negocier avec son serveur chiffre. Rendre la main entre les deux
/// laisserait le daemon pointer `resolv.conf` sur un port qui accepte les
/// paquets et n'y repond pas encore: la machine perdrait la resolution de noms
/// pendant quelques secondes, au moment precis de la connexion.
pub fn demarrer(lancement: &Lancement) -> Result<ResolveurEnCours> {
    if !lancement.programme.is_file() {
        return Err(Error::Dns(format!(
            "resolveur chiffre introuvable a {}: l'empaquetage doit l'installer \
             avant que le daemon puisse l'embarquer",
            lancement.programme.display()
        )));
    }

    // 11b-1: sous Windows, quand un compte de service est declare, le daemon
    // lance le resolveur SOUS ce compte, et non sous le sien (LocalSystem en
    // service). Le chemin ordinaire ci-dessous reste celui d'avant 11b-1 quand
    // aucun compte n'est declare, a l'octet pres. Voir `demarrer_sous_compte`.
    #[cfg(windows)]
    if let Some(compte) = &lancement.compte {
        return demarrer_sous_compte(lancement, compte);
    }

    let mut commande = Command::new(&lancement.programme);
    commande
        .arg("-config")
        .arg(&lancement.configuration)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());

    // Le repertoire courant, et non un heritage du daemon: dnscrypt-proxy y
    // ecrit le cache de sa liste de resolveurs. Sans cela il tenterait
    // d'ecrire dans le repertoire de travail du daemon, qui est `/`.
    if let Some(rep) = lancement.configuration.parent() {
        commande.current_dir(rep);
    }

    // SAFETY: pre_exec exige une fermeture async-signal-safe, executee dans
    // l'enfant entre fork et exec. Celle-ci n'appelle que basculer (set*id, prctl,
    // capset), prctl et getppid, toutes async-signal-safe, et n'alloue pas.
    #[cfg(target_os = "linux")]
    unsafe {
        use std::io::Error as IoError;
        use std::os::unix::process::CommandExt;
        let bascule = lancement.bascule;
        commande.pre_exec(move || {
            // L'ORDRE de ces deux etapes est la propriete, pas un detail. Le
            // noyau efface `pdeath_signal` des que les identifiants d'un
            // processus changent (`commit_creds`). Armer la garde AVANT la
            // bascule la desarmerait donc en silence -- c'est exactement ce
            // que faisait le `user_name` de dnscrypt-proxy, mesure sur essai-linux le
            // 17/08/2026: avec lui, le resolveur survivait a un daemon tue par
            // SIGKILL et gardait le :53; sans lui, il mourait avec.
            if let Some(b) = bascule {
                basculer(b)?;
            }
            // Le noyau tue l'enfant quand son parent meurt. Un dnscrypt-proxy
            // orphelin garderait l'ecoute sur le :53 de la boucle locale.
            // SIGKILL et non SIGTERM: le point de cette garde est justement de
            // couvrir le cas ou plus personne ne peut demander poliment.
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                return Err(IoError::last_os_error());
            }
            // La course connue de PR_SET_PDEATHSIG: si le parent est mort
            // ENTRE le fork et le prctl, le signal ne partira jamais et
            // l'enfant serait orphelin des sa naissance.
            if libc::getppid() == 1 {
                return Err(IoError::other(
                    "parent disparu avant l'armement de PR_SET_PDEATHSIG",
                ));
            }
            Ok(())
        });
    }

    let mut enfant = commande.spawn().map_err(|e| {
        Error::Dns(format!(
            "lancement de {}: {e}",
            lancement.programme.display()
        ))
    })?;

    // Pris tout de suite: le drain doit tourner avant l'attente, sinon un
    // resolveur bavard remplit le tuyau et se bloque avant d'etre pret.
    let journal = enfant.stderr.take().map(drainer).unwrap_or_default();

    let mut en_cours = ResolveurEnCours {
        processus: Processus::Ordinaire(enfant),
        journal,
        ecoute: lancement.ecoute,
    };

    match en_cours.attendre_disponible() {
        Ok(()) => Ok(en_cours),
        Err(e) => {
            let diagnostic = en_cours.diagnostic();
            let _ = en_cours.arreter();
            if diagnostic.is_empty() {
                Err(e)
            } else {
                Err(Error::Dns(format!("{e}. Sortie d'erreur: {diagnostic}")))
            }
        }
    }
}

/// Envoie une requete DNS et attend n'importe quelle reponse bien formee.
fn interroger(serveur: SocketAddr) -> std::io::Result<()> {
    let liaison = if serveur.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(liaison)?;
    socket.set_read_timeout(Some(DELAI_SONDE))?;
    let requete = requete_a(NOM_DE_SONDE);
    socket.send_to(&requete, serveur)?;

    let mut tampon = [0u8; 512];
    let recus = socket.recv(&mut tampon)?;
    // L'identifiant doit revenir. Sans ce controle, n'importe quel datagramme
    // arrivant sur ce port passerait pour une reponse.
    if recus >= 2 && tampon[..2] == requete[..2] {
        Ok(())
    } else {
        Err(std::io::Error::other(
            "reponse sans rapport avec la requete",
        ))
    }
}

/// Requete A minimale, avec un identifiant fixe.
fn requete_a(nom: &str) -> Vec<u8> {
    let mut q = vec![0xB1, 0xF0, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    for etiquette in nom.split('.').filter(|e| !e.is_empty()) {
        q.push(etiquette.len() as u8);
        q.extend_from_slice(etiquette.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&1u16.to_be_bytes()); // type A
    q.extend_from_slice(&1u16.to_be_bytes()); // classe IN
    q
}

/// Draine la sortie d'erreur en continu, sur un thread dedie.
fn drainer(mut flux: std::process::ChildStderr) -> JournalErreur {
    let journal = JournalErreur::default();
    let copie = journal.clone();
    std::thread::spawn(move || {
        let mut tampon = [0u8; 1024];
        loop {
            match flux.read(&mut tampon) {
                Ok(0) | Err(_) => break,
                Ok(n) => copie.pousser(&String::from_utf8_lossy(&tampon[..n])),
            }
        }
    });
    journal
}

/// Convertit une chaine en UTF-16 terminee par zero, prete pour l'API Win32.
#[cfg(windows)]
fn en_utf16(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Poignee de processus lancee sous un compte de service (11b-1).
///
/// `CreateProcessAsUserW` ne rend pas un `std::process::Child` mais une poignee
/// brute, qu'on possede et qu'on referme a la destruction. Le cycle de vie
/// (mort? tuer, attendre) est refait a la main, la ou le chemin ordinaire le
/// delegue a `std::process`.
#[cfg(windows)]
struct ProcessusSousCompte {
    processus: std::os::windows::io::OwnedHandle,
    pid: u32,
}

#[cfg(windows)]
impl ProcessusSousCompte {
    /// `Some(<code>)` s'il est mort, `None` s'il tourne encore.
    ///
    /// `WaitForSingleObject` et non `GetExitCodeProcess` seul, qui rend
    /// `STILL_ACTIVE` (259) pour un processus vivant et confondrait un code de
    /// sortie 259 avec la vie. L'attente a delai nul, elle, ne confond rien.
    fn terminaison(&mut self) -> std::io::Result<Option<String>> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Foundation::WAIT_TIMEOUT;
        use windows_sys::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject};

        let h = self.processus.as_raw_handle();
        // SAFETY: `h` est la poignee de processus possedee par self, valide tant
        // que self vit; l'attente a delai nul ne fait que lire l'etat.
        let attente = unsafe { WaitForSingleObject(h, 0) };
        if attente == WAIT_TIMEOUT {
            return Ok(None);
        }
        let mut code: u32 = 0;
        // SAFETY: `h` est valide; GetExitCodeProcess ecrit dans `code`, dont
        // l'adresse est locale et vivante.
        unsafe { GetExitCodeProcess(h, &mut code) };
        Ok(Some(format!("code de sortie {code}")))
    }

    fn tuer(&mut self) -> std::io::Result<()> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::System::Threading::TerminateProcess;
        // SAFETY: la poignee possedee par self a ete ouverte par
        // CreateProcessAsUserW avec le droit PROCESS_TERMINATE.
        if unsafe { TerminateProcess(self.processus.as_raw_handle(), 137) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    fn attendre(&mut self) {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::System::Threading::WaitForSingleObject;
        // SAFETY: `h` est valide; l'attente infinie rend la main a la mort du
        // processus, qui vient d'etre demandee par `tuer`. u32::MAX == INFINITE.
        unsafe { WaitForSingleObject(self.processus.as_raw_handle(), u32::MAX) };
    }
}

/// Separe un compte en `(domaine, nom)` pour `LogonUserW`.
///
/// `NT AUTHORITY\LocalService` -> `(Some("NT AUTHORITY"), "LocalService")`.
/// `LocalService` seul -> le meme, parce que ce compte bien connu vit sous
/// `NT AUTHORITY`. Tout autre nom nu part avec un domaine `None` (NULL), que
/// LogonUser resout dans le domaine local puis les domaines de confiance.
#[cfg(windows)]
fn separer_compte(compte: &str) -> (Option<String>, String) {
    if let Some((domaine, nom)) = compte.split_once('\\') {
        return (Some(domaine.to_owned()), nom.to_owned());
    }
    match compte.trim().to_ascii_lowercase().as_str() {
        "localservice" | "networkservice" => (Some("NT AUTHORITY".to_owned()), compte.to_owned()),
        _ => (None, compte.to_owned()),
    }
}

/// Ligne de commande de dnscrypt-proxy, prete pour `CreateProcessAsUserW`.
///
/// Chemins entre guillemets: un espace dans `%ProgramData%` couperait sinon
/// l'argument en deux.
#[cfg(windows)]
fn ligne_de_commande(programme: &Path, configuration: &Path) -> Vec<u16> {
    en_utf16(&format!(
        "\"{}\" -config \"{}\"",
        programme.display(),
        configuration.display()
    ))
}

/// SID binaire d'un compte, pour les ACE de poste de travail.
///
/// `LookupAccountNameW` a taille croissante, comme dans `coeurs::identite`,
/// mais rend ici les OCTETS du SID et non sa forme textuelle: une ACE se
/// construit avec le SID binaire.
#[cfg(windows)]
fn sid_binaire(nom: &str) -> Result<Vec<u8>> {
    use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, GetLastError};
    use windows_sys::Win32::Security::LookupAccountNameW;

    let nom_w = en_utf16(nom);
    let mut taille_sid: u32 = 0;
    let mut taille_domaine: u32 = 0;
    let mut usage = 0i32;
    // SAFETY: `nom_w` est terminee par zero; les pointeurs de sortie sont nuls
    // pour la sonde de taille, les compteurs vivent ici.
    unsafe {
        LookupAccountNameW(
            std::ptr::null(),
            nom_w.as_ptr(),
            std::ptr::null_mut(),
            &mut taille_sid,
            std::ptr::null_mut(),
            &mut taille_domaine,
            &mut usage,
        );
    }
    // SAFETY: lecture d'une valeur par thread, sans effet de bord.
    let err = unsafe { GetLastError() };
    if err != ERROR_INSUFFICIENT_BUFFER || taille_sid == 0 {
        return Err(Error::Dns(format!(
            "LookupAccountNameW({nom:?}) sonde de taille: erreur Win32 {err}"
        )));
    }
    let mut sid = vec![0u8; taille_sid as usize];
    let mut domaine = vec![0u16; taille_domaine.max(1) as usize];
    // SAFETY: les tampons sont dimensionnes par la sonde et vivent pendant
    // l'appel; `nom_w` reste terminee par zero.
    let ok = unsafe {
        LookupAccountNameW(
            std::ptr::null(),
            nom_w.as_ptr(),
            sid.as_mut_ptr() as *mut core::ffi::c_void,
            &mut taille_sid,
            domaine.as_mut_ptr(),
            &mut taille_domaine,
            &mut usage,
        )
    };
    if ok == 0 {
        return Err(Error::Dns(format!(
            "LookupAccountNameW({nom:?}): erreur Win32 {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(sid)
}

/// Accorde au SID l'acces a la window-station et au desktop de la session 0.
///
/// Mesure du 06/09/2026: sans cette ACE, `CreateProcessAsUserW` reussit mais
/// l'enfant sort en 0xC0000142 (STATUS_DLL_INIT_FAILED) - un compte de service
/// lancant un enfant en session 0 doit d'abord pouvoir ouvrir sa
/// window-station et son desktop. Le patron des deux ACE de window-station (une
/// heritable pour les objets crees dedans, une directe) et de l'ACE de desktop
/// est celui de la page MSDN "Starting an Interactive Client Process".
#[cfg(windows)]
fn accorder_acces_poste_de_travail(sid: *mut core::ffi::c_void) -> Result<()> {
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::System::StationsAndDesktops::{
        GetProcessWindowStation, GetThreadDesktop,
    };
    use windows_sys::Win32::System::Threading::GetCurrentThreadId;

    // Masques d'acces, valeurs stables de l'ABI Win32.
    const GENERIC_ALL: u32 = 0x1000_0000;
    /// WINSTA_ALL_ACCESS | STANDARD_RIGHTS_REQUIRED.
    const WINSTA_ACCES_COMPLET: u32 = 0x0000_037F | 0x000F_0000;
    /// Union des droits de desktop | STANDARD_RIGHTS_REQUIRED.
    const DESKTOP_ACCES_COMPLET: u32 = 0x0000_01FF | 0x000F_0000;
    /// OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE.
    const HERITAGE_ENFANTS: u8 = 0x01 | 0x02 | 0x08;

    // SAFETY: GetProcessWindowStation/GetThreadDesktop rendent des poignees de
    // session possedees par le systeme, valides pour la duree de l'appel; on ne
    // les referme pas, elles ne sont pas a nous.
    let (hwinsta, hdesk) = unsafe {
        (
            GetProcessWindowStation(),
            GetThreadDesktop(GetCurrentThreadId()),
        )
    };
    let hwinsta = hwinsta as HANDLE;
    let hdesk = hdesk as HANDLE;
    if hwinsta.is_null() || hdesk.is_null() {
        return Err(Error::Dns(
            "window-station ou desktop de la session introuvable".to_owned(),
        ));
    }
    ajouter_ace_objet(hwinsta, sid, GENERIC_ALL, HERITAGE_ENFANTS)?;
    ajouter_ace_objet(hwinsta, sid, WINSTA_ACCES_COMPLET, 0)?;
    ajouter_ace_objet(hdesk, sid, DESKTOP_ACCES_COMPLET, 0)?;
    Ok(())
}

/// Vrai si le DACL porte DEJA une `ACCESS_ALLOWED_ACE` de meme SID, meme masque
/// et memes drapeaux d'heritage.
///
/// C'est le coeur de l'idempotence (ecart 2, relance du 06/09/2026): `ajouter_ace_objet`
/// et `accorder_acces_chemin` sont rappeles a CHAQUE (re)lancement du resolveur
/// par le superviseur, sur une window-station, un desktop et des repertoires qui
/// vivent aussi longtemps que le service. Sans ce controle, chaque relance
/// empilerait une ACE de plus; un DACL est borne a 64 Ko, donc c'est une fuite
/// lente et silencieuse sur le chemin de production. Les deux fonctions partagent
/// cette decision pour qu'elle soit unique et testable sans objet noyau. Pour
/// `accorder_acces_chemin` cette phrase n'est vraie que depuis 11b-2
/// (13/09/2026): en 11b-1 seul l'autotest l'appelait, la production non;
/// `demarrer_sous_compte` la rappelle desormais a chaque lancement.
///
/// Deux formes d'equivalence, parce que l'OS ne stocke pas partout ce qu'on
/// ecrit (ecart releve par l'orchestrateur le 13/09/2026, classe "pose n'est
/// pas effet"):
///  - VERBATIM: meme masque, memes drapeaux que demandes. C'est ce que
///    `SetUserObjectSecurity` stocke sur une window-station ou un desktop
///    (mesure essai-windows du 06/09/2026: 2 puis 2, 1 puis 1).
///  - PROJETEE: `projete` est le masque generique projete par l'OS en droits
///    specifiques de l'objet (pour un objet fichier, `MapGenericMask` avec la
///    table FILE_GENERIC_*), avec les drapeaux d'heritage a ZERO: c'est l'ACE
///    EFFECTIVE que `SetNamedSecurityInfoW` stocke sur un fichier (releve
///    dev-windows du 13/09/2026: GENERIC_READ|WRITE|EXECUTE relu 0x001201BF,
///    AceFlags 0x00 que l'on ait demande 0 ou OBJECT|CONTAINER_INHERIT) et sur
///    un repertoire (releve dev-windows du 13/09/2026, recette repertoire:
///    GENERIC_READ|WRITE|EXECUTE|DELETE heritable relu comme une ACE
///    effective (0x001301BF = Modify, 0x00) plus une ACE inherit-only
///    (0xE0010000, 0x0B), dont on n'a pas besoin pour reconnaitre la pose). Sans cette forme, le predicat ne
///    reconnaissait JAMAIS son ACE sur un chemin et `accorder_acces_chemin`
///    reecrivait le DACL a chaque lancement, l'OS fusionnant en silence.
///    `None` pour un objet USER, stocke verbatim.
///
/// Fonction sure: elle ne DEReference aucun de ses parametres pointeurs cote Rust
/// (elle les passe a `GetAce`/`EqualSid`); les seuls dereferences portent sur les
/// ACE que `GetAce` rend DANS le DACL.
#[cfg(windows)]
fn ace_allow_equivalente_presente(
    dacl: *mut windows_sys::Win32::Security::ACL,
    nb: u32,
    sid: *mut core::ffi::c_void,
    masque: u32,
    drapeaux: u8,
    projete: Option<u32>,
) -> bool {
    use windows_sys::Win32::Security::{ACCESS_ALLOWED_ACE, ACE_HEADER, EqualSid, GetAce};

    const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
    /// Drapeaux de l'ACE effective stockee par l'OS sur un objet fichier.
    const DRAPEAUX_EFFECTIFS: u8 = 0;
    if dacl.is_null() {
        return false;
    }
    // SAFETY: `dacl` pointe un ACL valide portant au moins `nb` ACE (compte rendu
    // par GetAclInformation par l'appelant); GetAce rend, pour i < nb, un pointeur
    // aligne DANS ce DACL, valide le temps du parcours; `sid` est un SID valide
    // (rendu par LookupAccountNameW). Lecture seule, aucune ecriture.
    unsafe {
        for i in 0..nb {
            let mut ace: *mut core::ffi::c_void = std::ptr::null_mut();
            if GetAce(dacl, i, &mut ace) == 0 {
                continue;
            }
            let entete = &*(ace as *const ACE_HEADER);
            if entete.AceType != ACCESS_ALLOWED_ACE_TYPE {
                continue;
            }
            let allow = ace as *const ACCESS_ALLOWED_ACE;
            let stocke = ((*allow).Mask, entete.AceFlags);
            let verbatim = stocke == (masque, drapeaux);
            let projetee = projete.is_some_and(|p| stocke == (p, DRAPEAUX_EFFECTIFS));
            if !verbatim && !projetee {
                continue;
            }
            let sid_existant = std::ptr::addr_of!((*allow).SidStart) as *mut core::ffi::c_void;
            if EqualSid(sid, sid_existant) != 0 {
                return true;
            }
        }
    }
    false
}

/// Projette un masque generique en droits specifiques d'un objet FICHIER,
/// comme l'OS le fait quand il stocke une ACE effective sur un fichier ou un
/// repertoire (`MapGenericMask`, table FILE_GENERIC_*).
///
/// Les quatre valeurs sont stables dans l'ABI Win32 (winnt.h) et definies ici,
/// comme SYNCHRONIZE dans `vivant`: activer Win32_Storage_FileSystem pour
/// quatre noms serait payer cher. Elles sont MESUREES: sur dev-windows le
/// 13/09/2026, GENERIC_READ|WRITE|EXECUTE ecrit sur un fichier a ete relu
/// 0x001201BF, exactement FILE_GENERIC_READ|WRITE|EXECUTE.
#[cfg(windows)]
fn projeter_droits_fichier(masque: u32) -> u32 {
    use windows_sys::Win32::Security::{GENERIC_MAPPING, MapGenericMask};

    const FILE_GENERIC_READ: u32 = 0x0012_0089;
    const FILE_GENERIC_WRITE: u32 = 0x0012_0116;
    const FILE_GENERIC_EXECUTE: u32 = 0x0012_00A0;
    const FILE_ALL_ACCESS: u32 = 0x001F_01FF;
    let table = GENERIC_MAPPING {
        GenericRead: FILE_GENERIC_READ,
        GenericWrite: FILE_GENERIC_WRITE,
        GenericExecute: FILE_GENERIC_EXECUTE,
        GenericAll: FILE_ALL_ACCESS,
    };
    let mut projete = masque;
    // SAFETY: `projete` et `table` vivent sur la pile pendant l'appel;
    // MapGenericMask ne fait que reecrire l'entier pointe.
    unsafe { MapGenericMask(&mut projete, &table) };
    projete
}

/// Ajoute une ACE d'acces autorise pour `sid` au DACL d'un objet utilisateur.
///
/// Lit le descripteur courant par `GetUserObjectSecurity`, recopie ses ACE dans
/// un DACL agrandi d'une entree, ajoute l'ACE, puis reecrit par
/// `SetUserObjectSecurity`. `heritage` porte les drapeaux `*_INHERIT_ACE` a
/// poser sur la nouvelle ACE, ou 0.
#[cfg(windows)]
fn ajouter_ace_objet(
    objet: windows_sys::Win32::Foundation::HANDLE,
    sid: *mut core::ffi::c_void,
    masque: u32,
    heritage: u8,
) -> Result<()> {
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION, AclSizeInformation,
        AddAccessAllowedAce, AddAce, GetAce, GetAclInformation, GetLengthSid,
        GetSecurityDescriptorDacl, GetUserObjectSecurity, InitializeAcl,
        InitializeSecurityDescriptor, PSECURITY_DESCRIPTOR, SECURITY_DESCRIPTOR,
        SetSecurityDescriptorDacl, SetUserObjectSecurity,
    };

    const DACL_SECURITY_INFORMATION: u32 = 0x0000_0004;
    const ACL_REVISION: u32 = 2;
    const SECURITY_DESCRIPTOR_REVISION: u32 = 1;
    const MAXDWORD: u32 = 0xFFFF_FFFF;

    // SAFETY: enchainement d'appels Win32 de securite. Chaque tampon est
    // possede et dimensionne par l'API (double appel a taille croissante), et
    // chaque pointeur reste vivant pendant l'appel qui le lit. Le SID est
    // valide (rendu par LookupAccountNameW). `dacl_ancien` pointe dans `ancien`,
    // qui vit jusqu'a la fin du bloc; `dacl` pointe dans `tampon`, de meme.
    unsafe {
        let info = DACL_SECURITY_INFORMATION;
        let mut besoin: u32 = 0;
        GetUserObjectSecurity(objet, &info, std::ptr::null_mut(), 0, &mut besoin);
        if besoin == 0 {
            return Err(Error::Dns(format!(
                "GetUserObjectSecurity sonde: erreur Win32 {}",
                std::io::Error::last_os_error()
            )));
        }
        let mut ancien = vec![0u8; besoin as usize];
        let psd_ancien = ancien.as_mut_ptr() as PSECURITY_DESCRIPTOR;
        if GetUserObjectSecurity(objet, &info, psd_ancien, besoin, &mut besoin) == 0 {
            return Err(Error::Dns(format!(
                "GetUserObjectSecurity: erreur Win32 {}",
                std::io::Error::last_os_error()
            )));
        }

        let mut present: i32 = 0;
        let mut dacl_ancien: *mut ACL = std::ptr::null_mut();
        let mut defaut: i32 = 0;
        if GetSecurityDescriptorDacl(psd_ancien, &mut present, &mut dacl_ancien, &mut defaut) == 0 {
            return Err(Error::Dns(format!(
                "GetSecurityDescriptorDacl: erreur Win32 {}",
                std::io::Error::last_os_error()
            )));
        }

        let mut octets = size_of::<ACL>() as u32;
        let mut nb = 0u32;
        if present != 0 && !dacl_ancien.is_null() {
            let mut taille: ACL_SIZE_INFORMATION = std::mem::zeroed();
            if GetAclInformation(
                dacl_ancien,
                (&mut taille as *mut ACL_SIZE_INFORMATION).cast(),
                size_of::<ACL_SIZE_INFORMATION>() as u32,
                AclSizeInformation,
            ) == 0
            {
                return Err(Error::Dns(format!(
                    "GetAclInformation: erreur Win32 {}",
                    std::io::Error::last_os_error()
                )));
            }
            octets = taille.AclBytesInUse;
            nb = taille.AceCount;
        }

        // Idempotence (ecart 2): `demarrer_sous_compte` rappelle ce chemin a
        // CHAQUE (re)lancement du resolveur, sur une window-station et un desktop
        // qui vivent aussi longtemps que le service. Si l'ACE voulue existe deja,
        // ne rien reecrire - sinon le DACL grossit d'une ACE par relance. Un
        // objet USER stocke l'ACE verbatim: aucune forme projetee a chercher.
        if ace_allow_equivalente_presente(dacl_ancien, nb, sid, masque, heritage, None) {
            return Ok(());
        }

        // Taille du nouveau DACL: l'ancien plus une ACE. L'en-tete
        // ACCESS_ALLOWED_ACE compte deja un DWORD de SidStart, remplace par le
        // SID complet: on le retranche avant d'ajouter la longueur du SID.
        let taille_sid = GetLengthSid(sid);
        let taille_nouveau =
            octets + size_of::<ACCESS_ALLOWED_ACE>() as u32 - size_of::<u32>() as u32 + taille_sid;
        let mut tampon = vec![0u8; taille_nouveau as usize];
        let dacl = tampon.as_mut_ptr() as *mut ACL;
        if InitializeAcl(dacl, taille_nouveau, ACL_REVISION) == 0 {
            return Err(Error::Dns(format!(
                "InitializeAcl: erreur Win32 {}",
                std::io::Error::last_os_error()
            )));
        }

        for i in 0..nb {
            let mut ace: *mut core::ffi::c_void = std::ptr::null_mut();
            if GetAce(dacl_ancien, i, &mut ace) == 0 {
                return Err(Error::Dns(format!(
                    "GetAce({i}): erreur Win32 {}",
                    std::io::Error::last_os_error()
                )));
            }
            let entete = &*(ace as *const ACE_HEADER);
            if AddAce(dacl, ACL_REVISION, MAXDWORD, ace, u32::from(entete.AceSize)) == 0 {
                return Err(Error::Dns(format!(
                    "AddAce({i}): erreur Win32 {}",
                    std::io::Error::last_os_error()
                )));
            }
        }

        if AddAccessAllowedAce(dacl, ACL_REVISION, masque, sid) == 0 {
            return Err(Error::Dns(format!(
                "AddAccessAllowedAce: erreur Win32 {}",
                std::io::Error::last_os_error()
            )));
        }

        // AddAccessAllowedAce pose une ACE sans heritage: quand il en faut, on
        // relit l'ACE qu'on vient d'ajouter (la derniere, indice `nb`) et on y
        // ecrit les drapeaux.
        if heritage != 0 {
            let mut ace: *mut core::ffi::c_void = std::ptr::null_mut();
            if GetAce(dacl, nb, &mut ace) == 0 {
                return Err(Error::Dns(format!(
                    "GetAce(nouvelle ACE): erreur Win32 {}",
                    std::io::Error::last_os_error()
                )));
            }
            (*(ace as *mut ACE_HEADER)).AceFlags = heritage;
        }

        let mut sd: SECURITY_DESCRIPTOR = std::mem::zeroed();
        let psd = (&mut sd as *mut SECURITY_DESCRIPTOR).cast();
        if InitializeSecurityDescriptor(psd, SECURITY_DESCRIPTOR_REVISION) == 0 {
            return Err(Error::Dns(format!(
                "InitializeSecurityDescriptor: erreur Win32 {}",
                std::io::Error::last_os_error()
            )));
        }
        if SetSecurityDescriptorDacl(psd, 1, dacl, 0) == 0 {
            return Err(Error::Dns(format!(
                "SetSecurityDescriptorDacl: erreur Win32 {}",
                std::io::Error::last_os_error()
            )));
        }
        if SetUserObjectSecurity(objet, &info, psd) == 0 {
            return Err(Error::Dns(format!(
                "SetUserObjectSecurity: erreur Win32 {}",
                std::io::Error::last_os_error()
            )));
        }
    }
    Ok(())
}

/// Accorde au SID l'acces a un chemin: un repertoire (et, par heritage, son
/// contenu) ou un fichier.
///
/// Le pendant fichier de `ajouter_ace_objet`: `GetNamedSecurityInfoW` lit le
/// DACL courant, on l'augmente d'une ACE, `SetNamedSecurityInfoW` le reecrit.
/// Depuis 11b-2 (13/09/2026) c'est le chemin de PRODUCTION qui l'appelle:
/// `demarrer_sous_compte` ouvre au compte, a chaque lancement, la lecture de
/// sa configuration et de sa liste anti-telemetrie (des fichiers) et
/// l'ecriture de son repertoire d'etat. L'installateur ne le peut pas: ces
/// fichiers n'existent pas encore quand il tourne (le daemon les ecrit en
/// place a la premiere connexion), et `%ProgramData%\Bifrost` lui-meme ne doit
/// rien accorder au compte, il porte le profil et sa cle privee.
///
/// Ce qui est ECRIT: un masque generique (GENERIC_READ|EXECUTE, plus
/// GENERIC_WRITE et DELETE au besoin: l'ecriture d'un cache par fichier
/// temporaire puis renommage exige DELETE, ecart 4), heritable
/// (OBJECT|CONTAINER_INHERIT) sur un repertoire, sans heritage sur un fichier
/// (un fichier n'a pas d'enfant).
///
/// Ce que l'OS STOCKE n'est pas ce qui est ecrit, et le predicat de doublon
/// doit reconnaitre ce qui est stocke, sinon il ne reconnait rien et cette
/// fonction reecrit le DACL a chaque lancement (ecart releve par
/// l'orchestrateur le 13/09/2026, l'OS fusionnant alors en silence). Releves
/// dev-windows, par les recettes qui dumpent `(Mask, AceFlags)` des ACE du SID:
///  - FICHIER (13/09/2026): UNE ACE, masque generique projete en droits
///    fichier (GENERIC_READ|EXECUTE relu 0x001200A9; avec GENERIC_WRITE en
///    plus, 0x001201BF), AceFlags 0x00, que l'on ait demande l'heritage ou
///    non.
///  - REPERTOIRE (13/09/2026, ecriture = GENERIC_READ|WRITE|EXECUTE|DELETE):
///    l'ACE heritable est eclatee en une ACE EFFECTIVE (masque projete
///    0x001301BF = Modify, DELETE conserve tel quel, AceFlags 0x00) et une
///    ACE INHERIT_ONLY (masque generique conserve 0xE0010000, AceFlags 0x0B),
///    et `SetNamedSecurityInfoW` refusionne une ACE identique reposee (compte
///    total 4 -> 6 -> 6, releve du 06/09/2026).
///
/// Le predicat cherche donc l'une OU l'autre forme: verbatim (objets USER) ou
/// projetee a drapeaux nuls (`projeter_droits_fichier`), et c'est la seconde
/// qui mord sur un chemin. Garde par
/// `accorder_acces_chemin_accorde_le_sid_sur_un_vrai_fichier`,
/// `accorder_acces_chemin_accorde_le_sid_sur_un_vrai_repertoire` (vrais
/// objets, dev-windows) et `ace_allow_equivalente_reconnait_le_doublon` (en
/// memoire, forme projetee comprise).
///
/// Rend `true` si une ACE a ete ECRITE, `false` si une ACE equivalente etait
/// deja la et que rien n'a ete reecrit. Ce n'est pas une commodite: l'OS
/// fusionne de lui-meme une ACE identique reposee, donc le compte d'ACE ne
/// dit pas si NOTRE predicat a reconnu la sienne. Le retour le dit, et c'est
/// lui que les deux recettes chemin assertent a la relance.
#[cfg(windows)]
fn accorder_acces_chemin(
    chemin: &Path,
    sid: *mut core::ffi::c_void,
    ecriture: bool,
) -> Result<bool> {
    use windows_sys::Win32::Foundation::{ERROR_SUCCESS, HLOCAL, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        GetNamedSecurityInfoW, SE_FILE_OBJECT, SetNamedSecurityInfoW,
    };
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION, AclSizeInformation,
        AddAccessAllowedAce, AddAce, GetAce, GetAclInformation, GetLengthSid, InitializeAcl,
        PSECURITY_DESCRIPTOR, PSID,
    };

    const DACL_SECURITY_INFORMATION: u32 = 0x0000_0004;
    const ACL_REVISION: u32 = 2;
    const MAXDWORD: u32 = 0xFFFF_FFFF;
    // Droits generiques: le systeme les projette sur les droits fichier
    // specifiques a l'application. Lecture + traversee, plus l'ecriture au
    // besoin (le resolveur ecrit le cache de sa liste dans son repertoire
    // d'etat).
    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const GENERIC_EXECUTE: u32 = 0x2000_0000;
    // DELETE (droit standard, 0x0001_0000, que MapGenericMask laisse tel quel)
    // avec l'ecriture, et seulement avec elle: dnscrypt-proxy ecrit son cache
    // par fichier temporaire puis `rename`, qui exige DELETE sur la source.
    // Sans lui, ecart 4 releve sur essai-windows le 13/09/2026 sous SYSTEM:
    // `Couldn't write cache file [...]: rename ...: Access is denied.`, le
    // cache n'est jamais ecrit (chaque demarrage retelecharge la liste, le
    // probleme du 17/08 que l'etat existe pour eviter) et des `sf-*.tmp`
    // s'accumulent dans l'etat, un WARNING que personne ne lit. Avec lui,
    // l'ACE effective stockee vaut exactement Modify (0x001301BF), celle que
    // pose l'installateur.
    const DELETE: u32 = 0x0001_0000;
    // OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE: fichiers et sous-repertoires
    // heritent de l'acces. Sur un fichier, aucun: un fichier n'a pas d'enfant
    // (et l'OS retire de toute facon ces drapeaux d'une ACE de fichier, releve
    // du 13/09/2026).
    const HERITAGE_CONTENU: u8 = 0x01 | 0x02;

    let masque = if ecriture {
        GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | DELETE
    } else {
        GENERIC_READ | GENERIC_EXECUTE
    };
    let heritage: u8 = if chemin.is_file() {
        0
    } else {
        HERITAGE_CONTENU
    };
    // La forme que l'OS stocke, pour que le predicat reconnaisse sa propre
    // ACE (cf. le commentaire de la fonction).
    let projete = projeter_droits_fichier(masque);
    let chemin_w = en_utf16(&chemin.to_string_lossy());

    // SAFETY: enchainement d'appels Win32 de securite fichier. `chemin_w` est
    // une chaine UTF-16 terminee par zero, mutable comme SetNamedSecurityInfoW
    // l'exige; `sd` est une allocation rendue par GetNamedSecurityInfoW, liberee
    // par LocalFree sur tous les chemins de sortie; `dacl_ancien` pointe dans
    // `sd`; `tampon` porte le nouveau DACL et vit jusqu'a SetNamedSecurityInfoW.
    unsafe {
        let mut dacl_ancien: *mut ACL = std::ptr::null_mut();
        let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        let code = GetNamedSecurityInfoW(
            chemin_w.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut dacl_ancien,
            std::ptr::null_mut(),
            &mut sd,
        );
        if code != ERROR_SUCCESS {
            return Err(Error::Dns(format!(
                "GetNamedSecurityInfoW({}): erreur Win32 {code}",
                chemin.display()
            )));
        }

        let mut octets = size_of::<ACL>() as u32;
        let mut nb = 0u32;
        if !dacl_ancien.is_null() {
            let mut taille: ACL_SIZE_INFORMATION = std::mem::zeroed();
            if GetAclInformation(
                dacl_ancien,
                (&mut taille as *mut ACL_SIZE_INFORMATION).cast(),
                size_of::<ACL_SIZE_INFORMATION>() as u32,
                AclSizeInformation,
            ) == 0
            {
                LocalFree(sd as HLOCAL);
                return Err(Error::Dns(format!(
                    "GetAclInformation({}): erreur Win32 {}",
                    chemin.display(),
                    std::io::Error::last_os_error()
                )));
            }
            octets = taille.AclBytesInUse;
            nb = taille.AceCount;
        }

        // Idempotence (ecart 2), meme raison qu'`ajouter_ace_objet`: ce chemin
        // est reouvert au compte a chaque relance du resolveur. Si notre ACE
        // (meme SID, meme masque, memes drapeaux d'heritage) est deja posee, ne
        // rien reecrire - sinon le DACL grossit d'une ACE par relance.
        if ace_allow_equivalente_presente(dacl_ancien, nb, sid, masque, heritage, Some(projete)) {
            LocalFree(sd as HLOCAL);
            return Ok(false);
        }

        let taille_sid = GetLengthSid(sid as PSID);
        let taille_nouveau =
            octets + size_of::<ACCESS_ALLOWED_ACE>() as u32 - size_of::<u32>() as u32 + taille_sid;
        let mut tampon = vec![0u8; taille_nouveau as usize];
        let dacl = tampon.as_mut_ptr() as *mut ACL;
        let mut echec: Option<String> = None;
        if InitializeAcl(dacl, taille_nouveau, ACL_REVISION) == 0 {
            echec = Some(format!(
                "InitializeAcl: {}",
                std::io::Error::last_os_error()
            ));
        }
        if echec.is_none() {
            for i in 0..nb {
                let mut ace: *mut core::ffi::c_void = std::ptr::null_mut();
                if GetAce(dacl_ancien, i, &mut ace) == 0 {
                    echec = Some(format!("GetAce({i}): {}", std::io::Error::last_os_error()));
                    break;
                }
                let entete = &*(ace as *const ACE_HEADER);
                if AddAce(dacl, ACL_REVISION, MAXDWORD, ace, u32::from(entete.AceSize)) == 0 {
                    echec = Some(format!("AddAce({i}): {}", std::io::Error::last_os_error()));
                    break;
                }
            }
        }
        if echec.is_none() && AddAccessAllowedAce(dacl, ACL_REVISION, masque, sid as PSID) == 0 {
            echec = Some(format!(
                "AddAccessAllowedAce: {}",
                std::io::Error::last_os_error()
            ));
        }
        if echec.is_none() {
            let mut ace: *mut core::ffi::c_void = std::ptr::null_mut();
            if GetAce(dacl, nb, &mut ace) == 0 {
                echec = Some(format!(
                    "GetAce(nouvelle ACE): {}",
                    std::io::Error::last_os_error()
                ));
            } else {
                (*(ace as *mut ACE_HEADER)).AceFlags = heritage;
            }
        }
        if let Some(message) = echec {
            LocalFree(sd as HLOCAL);
            return Err(Error::Dns(format!("{}: {message}", chemin.display())));
        }

        let code = SetNamedSecurityInfoW(
            chemin_w.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            dacl,
            std::ptr::null_mut(),
        );
        LocalFree(sd as HLOCAL);
        if code != ERROR_SUCCESS {
            return Err(Error::Dns(format!(
                "SetNamedSecurityInfoW({}): erreur Win32 {code}",
                chemin.display()
            )));
        }
    }
    Ok(true)
}

/// Lit le SID effectif d'un processus par son PID, sous sa forme textuelle.
///
/// Sert au selftest a constater que l'enfant tourne bien SOUS le compte
/// annonce: on compare ce SID a celui du compte demande. `PROCESS_QUERY_LIMITED_INFORMATION`
/// suffit a ouvrir le jeton d'un processus d'un autre compte.
#[cfg(windows)]
fn sid_effectif_du_processus(pid: u32) -> Result<String> {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, HLOCAL, LocalFree};
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser};
    use windows_sys::Win32::System::Threading::{
        OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    // SAFETY: chaque poignee et allocation est fermee/liberee sur tous les
    // chemins; les tailles de tampon viennent de l'API elle-meme; le tampon
    // aligne sur u64 evite de relire un pointeur mal aligne dans TOKEN_USER.
    unsafe {
        let processus = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if processus.is_null() {
            return Err(Error::Dns(format!(
                "OpenProcess(pid {pid}): erreur Win32 {}",
                std::io::Error::last_os_error()
            )));
        }
        let mut jeton: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(processus, TOKEN_QUERY, &mut jeton) == 0 {
            let err = std::io::Error::last_os_error();
            CloseHandle(processus);
            return Err(Error::Dns(format!("OpenProcessToken: erreur Win32 {err}")));
        }
        let mut besoin: u32 = 0;
        GetTokenInformation(jeton, TokenUser, std::ptr::null_mut(), 0, &mut besoin);
        let mut tampon = vec![0u64; (besoin as usize).div_ceil(8).max(1)];
        let ok = GetTokenInformation(
            jeton,
            TokenUser,
            tampon.as_mut_ptr() as *mut core::ffi::c_void,
            besoin,
            &mut besoin,
        );
        let err = std::io::Error::last_os_error();
        CloseHandle(jeton);
        CloseHandle(processus);
        if ok == 0 {
            return Err(Error::Dns(format!(
                "GetTokenInformation(TokenUser): erreur Win32 {err}"
            )));
        }

        let user = &*(tampon.as_ptr() as *const TOKEN_USER);
        let mut texte: windows_sys::core::PWSTR = std::ptr::null_mut();
        if ConvertSidToStringSidW(user.User.Sid, &mut texte) == 0 || texte.is_null() {
            return Err(Error::Dns(format!(
                "ConvertSidToStringSidW: erreur Win32 {}",
                std::io::Error::last_os_error()
            )));
        }
        let mut len = 0usize;
        while *texte.add(len) != 0 {
            len += 1;
        }
        let sid = String::from_utf16_lossy(std::slice::from_raw_parts(texte, len));
        LocalFree(texte as HLOCAL);
        Ok(sid)
    }
}

/// Le repertoire du resolveur: celui de sa configuration, s'il est admissible.
///
/// C'est le repertoire que dnscrypt-proxy prend comme repertoire courant au
/// chargement (releve essai-windows du 13/09/2026) et que le compte doit donc
/// pouvoir ouvrir, en lecture heritable. Deux refus, par une erreur claire:
///  - une configuration sans repertoire parent: on n'ouvre pas "." au compte;
///  - le repertoire du PROFIL (ecart 3 du 13/09/2026): l'ouvrir en lecture au
///    compte du resolveur exposerait le profil et sa cle privee, sans un mot.
///    C'etait l'effet silencieux d'une `--resolveur-configuration` posee a
///    l'ancien defaut, la racine de `%ProgramData%\Bifrost`. Critere, l'un OU
///    l'autre: le repertoire contient un fichier du nom du profil par defaut
///    (`tunnel.toml`, nom pris dans `bifrost_coffre::CHEMIN_PAR_DEFAUT`, pas
///    recopie), ou il est egal, chemins canonicalises quand ils existent, au
///    parent du chemin de profil que le daemon connait (`profil`).
///
/// La decision est ICI, et unique: `ouvrir_au_compte` l'appelle AVANT toute
/// pose d'ACE (sinon la garde arriverait apres l'effet), `demarrer_sous_compte`
/// la rappelle pour le repertoire courant. Garde par
/// `ouvrir_au_compte_refuse_le_repertoire_du_profil` (dev-windows).
#[cfg(windows)]
fn repertoire_du_resolveur(configuration: &Path, profil: &Path) -> Result<PathBuf> {
    let repertoire = match configuration.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_owned(),
        _ => {
            return Err(Error::Dns(format!(
                "la configuration du resolveur doit avoir un repertoire parent (recu {})",
                configuration.display()
            )));
        }
    };
    let nom_du_profil = Path::new(bifrost_coffre::CHEMIN_PAR_DEFAUT)
        .file_name()
        .expect("le chemin par defaut du profil nomme un fichier");
    let porte_un_profil = repertoire.join(nom_du_profil).is_file();
    let est_celui_du_profil = profil
        .parent()
        .is_some_and(|parent_du_profil| meme_repertoire(&repertoire, parent_du_profil));
    if porte_un_profil || est_celui_du_profil {
        return Err(Error::Dns(format!(
            "le repertoire de la configuration du resolveur ({}) ne peut pas etre \
             celui du profil: il serait ouvert en lecture au compte du resolveur, \
             cle privee comprise; utiliser un sous-repertoire, par defaut \
             %ProgramData%\\Bifrost\\resolveur",
            repertoire.display()
        )));
    }
    Ok(repertoire)
}

/// Deux chemins designent-ils le meme repertoire. Canonicalises quand les deux
/// existent (casse, liens, forme `\\?\`), compares tels quels sinon: un
/// repertoire qui n'existe pas ne porte aucun profil a exposer, et la
/// comparaison textuelle reste un garde-fou.
#[cfg(windows)]
fn meme_repertoire(a: &Path, b: &Path) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(x), Ok(y)) => x == y,
        _ => a == b,
    }
}

/// Ouvre au compte, a chaque lancement, ce que le resolveur doit LIRE et
/// ECRIRE, et rien d'autre (11b-2, ecart 2 du 13/09/2026).
///
/// Deux ACE heritables, dans cet ordre:
///  - LECTURE + TRAVERSEE (GENERIC_READ|EXECUTE, OI|CI) sur le repertoire de
///    la configuration. dnscrypt-proxy change lui-meme de repertoire courant
///    vers ce repertoire au chargement (`os.Chdir`; releve essai-windows du
///    13/09/2026 sous SYSTEM: `chdir ...: Access is denied.`, sortie 255), et
///    `SetCurrentDirectory` exige un acces explicite a l'objet, que
///    `SeChangeNotifyPrivilege` ne remplace pas. `SetNamedSecurityInfoW`
///    propage l'ACE heritable aux enfants existants: la configuration et la
///    liste anti-telemetrie, deja ecrites la par le daemon, en heritent, ce
///    qui remplace les ACE par fichier de la premiere version de 11b-2
///    (retirees avec le champ `liste` de `Lancement`).
///  - ECRITURE heritable (GENERIC_READ|WRITE|EXECUTE|DELETE, OI|CI, soit
///    Modify une fois stockee, ecart 4) sur le repertoire d'etat, ce que le
///    resolveur ecrit (cache de la liste des serveurs, par fichier temporaire
///    puis renommage, d'ou DELETE). En production c'est un sous-repertoire du
///    precedent: il en herite la lecture, plus son ecriture explicite, cumul
///    voulu.
///
/// JAMAIS d'ecriture pour le compte sur le repertoire de la configuration: la
/// configuration et la liste doivent rester non modifiables par le resolveur,
/// meme but que "il ne peut pas reecrire son binaire". Et jamais rien sur le
/// parent de ce repertoire (`%ProgramData%\Bifrost`: profil, cle privee,
/// coeurs): c'est pour cela que les defauts Windows placent la configuration
/// dans `%ProgramData%\Bifrost\resolveur`, et non a la racine. Garde par
/// `ouvrir_au_compte_lit_le_repertoire_et_n_ecrit_que_l_etat` (dev-windows,
/// vrai repertoire, vrai fichier, vrai sous-repertoire).
///
/// Le repertoire du PROFIL est refuse avant toute pose (ecart 3, voir
/// `repertoire_du_resolveur`): un refus ne laisse AUCUNE ACE derriere lui.
///
/// Rend `(repertoire_ecrit, etat_ecrit)`: `true` quand une ACE a ete ECRITE,
/// `false` quand le doublon a ete reconnu (voir `accorder_acces_chemin`).
#[cfg(windows)]
fn ouvrir_au_compte(
    configuration: &Path,
    etat: &Path,
    profil: &Path,
    sid: *mut core::ffi::c_void,
) -> Result<(bool, bool)> {
    // AVANT toute ACE: la garde de l'ecart 3 vit dans repertoire_du_resolveur.
    let repertoire = repertoire_du_resolveur(configuration, profil)?;
    let repertoire_ecrit = accorder_acces_chemin(&repertoire, sid, false)?;
    let etat_ecrit = accorder_acces_chemin(etat, sid, true)?;
    Ok((repertoire_ecrit, etat_ecrit))
}

/// Lance le resolveur sous un compte de service Windows (11b-1, forme alpha).
///
/// Mecanisme mesure sur essai-windows le 06/09/2026, reproduit ici pas a pas
/// (ces effets ne sont PAS reproductibles sur dev-windows: dnscrypt-proxy y est
/// absent, et `LogonUserW` en service exige `SeTcbPrivilege`, que seule une
/// session SYSTEM porte; l'orchestrateur les mesure sur essai-windows):
///
/// - `LogonUserW(nom, domaine, NULL, LOGON32_LOGON_SERVICE, LOGON32_PROVIDER_DEFAULT)`
///   rend un jeton PRIMAIRE sans mot de passe pour un compte de service
///   ordinaire (`LocalService` -> `S-1-5-19`). La forme VIRTUELLE `NT SERVICE\...`
///   est EXCLUE: elle rend err 1326 a LogonUser et obligerait le resolveur a
///   devenir son propre service, hors du job anti-orphelin (fork tranche alpha).
/// - AVANT l'exec, `accorder_acces_poste_de_travail` ouvre la window-station et
///   le desktop de la session 0 au SID, sans quoi l'enfant sort en 0xC0000142.
/// - `lpDesktop` reste NUL, jamais un nom code en dur: la doc de
///   `CreateProcessAsUserW` (learn.microsoft.com, ms.date 2018-12-05) pose que
///   « If the lpDesktop member is NULL, the new process inherits the desktop and
///   window station of its parent process ». L'enfant herite donc EXACTEMENT des
///   deux objets sur lesquels l'ACE vient d'etre posee, quel que soit le contexte
///   du daemon (coherence PAR CONSTRUCTION). Un litteral aurait diverge des que
///   le daemon n'est pas sur la window-station interactive: un service non
///   interactif recoit sa PROPRE window-station (`Service-0x0-3e7$` pour
///   LocalSystem, `Service-0x<SID de session>$` pour un compte de service), cf.
///   « Window Station and Desktop Creation » (learn.microsoft.com, ms.date
///   2018-05-31). L'ACE serait alors posee sur un objet et l'enfant envoye sur
///   un autre, et le 0xC0000142 reviendrait.
/// - Ce que le compte doit LIRE et ECRIRE lui est ouvert ICI, a chaque
///   lancement (11b-2, 13/09/2026), par `ouvrir_au_compte`: le REPERTOIRE de sa
///   configuration (qui porte aussi la liste) en lecture et traversee
///   heritables, son repertoire d'etat en ecriture heritable avec DELETE (le
///   cache s'ecrit par `sf-*.tmp` puis `rename`). Jamais `%ProgramData%\Bifrost`
///   lui-meme, qui porte le profil et sa cle privee: un repertoire de
///   configuration qui est celui du profil est refuse AVANT toute ACE, celle du
///   poste de travail comprise. Le repertoire de travail donne a l'enfant est
///   celui de la configuration, comme sur `demarrer`; il n'a aucun role, car
///   dnscrypt-proxy fait LUI-MEME `chdir` vers le repertoire de sa configuration
///   au chargement (releve essai-windows du 13/09/2026: `chdir <repertoire>:
///   Access is denied.` quand seul le fichier etait ouvert au compte), et c'est
///   ce droit d'ouverture qui compte.
/// - AUCUN drapeau de creation, donc PAS de `CREATE_BREAKAWAY_FROM_JOB`:
///   l'enfant reste dans le job du daemon et meurt avec lui. C'est l'invariant
///   anti-orphelin, conserve par la forme alpha.
#[cfg(windows)]
fn demarrer_sous_compte(lancement: &Lancement, compte: &str) -> Result<ResolveurEnCours> {
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::Security::LogonUserW;
    use windows_sys::Win32::System::Threading::{
        CreateProcessAsUserW, PROCESS_INFORMATION, STARTUPINFOW,
    };

    // Valeurs stables de l'ABI Win32.
    const LOGON32_LOGON_SERVICE: u32 = 5;
    const LOGON32_PROVIDER_DEFAULT: u32 = 0;

    let (domaine, nom) = separer_compte(compte);
    let nom_w = en_utf16(&nom);
    let domaine_w = domaine.as_deref().map(en_utf16);

    // 1. Jeton primaire du compte, sans mot de passe.
    let mut jeton: HANDLE = std::ptr::null_mut();
    // SAFETY: `nom_w`/`domaine_w` sont des chaines UTF-16 terminees par zero
    // vivantes pendant l'appel; le mot de passe NULL est autorise pour un
    // compte de service; `jeton` recoit une poignee ou reste nul.
    let ok = unsafe {
        LogonUserW(
            nom_w.as_ptr(),
            domaine_w.as_ref().map_or(std::ptr::null(), |d| d.as_ptr()),
            std::ptr::null(),
            LOGON32_LOGON_SERVICE,
            LOGON32_PROVIDER_DEFAULT,
            &mut jeton,
        )
    };
    if ok == 0 || jeton.is_null() {
        return Err(Error::Dns(format!(
            "LogonUserW({compte:?}): erreur Win32 {}. Un compte de service \
             ordinaire (LocalService) se connecte sans mot de passe; la forme \
             virtuelle NT SERVICE rend err 1326 et n'est pas supportee",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: `jeton` est une poignee neuve rendue par LogonUserW, non nulle,
    // dont personne d'autre n'est proprietaire; refermee a la fin de la fonction.
    let jeton = unsafe { OwnedHandle::from_raw_handle(jeton as _) };

    // 2. SID binaire du compte, pour les ACE de poste de travail.
    let sid = sid_binaire(compte)?;

    // 2bis (11b-2, ecart 3 du 13/09/2026). Le repertoire de la configuration
    // est refuse s'il est celui du profil, AVANT toute ACE, celle du poste de
    // travail comprise: `ouvrir_au_compte` refait le meme controle, mais sans
    // ce point d'arret l'ACE de station aurait deja ete posee au moment du
    // refus.
    let repertoire = repertoire_du_resolveur(&lancement.configuration, &lancement.profil)?;

    // 3. Ouvrir la window-station et le desktop de la session 0 au compte.
    let psid = sid.as_ptr() as *mut core::ffi::c_void;
    accorder_acces_poste_de_travail(psid)?;

    // 3bis (11b-2, ecart 2 du 13/09/2026). Ouvrir au compte, a CHAQUE
    // lancement, ce qu'il doit LIRE et ECRIRE, et rien d'autre: voir
    // `ouvrir_au_compte`. Idempotent (`ace_allow_equivalente_presente`):
    // relancer ne reecrit rien.
    ouvrir_au_compte(
        &lancement.configuration,
        &lancement.etat,
        &lancement.profil,
        psid,
    )?;

    // 4. Ligne de commande et repertoire de travail: le repertoire de la
    // configuration, comme sur le chemin ordinaire `demarrer`. Le brief 11b-2
    // faisait du repertoire d'ETAT le CWD de l'enfant, en inferant que le CWD
    // n'avait aucun role (tout ce que la configuration nomme est absolu).
    // Releve essai-windows du 13/09/2026, sous SYSTEM: dnscrypt-proxy change
    // LUI-MEME de repertoire courant vers celui de sa configuration au
    // chargement (`chdir <repertoire>: Access is denied.`, sortie 255), donc
    // le CWD choisi ici n'a aucun role, et c'est le droit d'OUVRIR ce
    // repertoire qui compte (pose par `ouvrir_au_compte`). Le donner comme CWD
    // est une divergence de moins avec `demarrer`. Le repertoire vient du
    // point 2bis, deja controle.
    let mut ligne = ligne_de_commande(&lancement.programme, &lancement.configuration);
    let repertoire = Some(en_utf16(&repertoire.to_string_lossy()));

    // SAFETY: STARTUPINFOW est POD, tout-a-zero est un etat initial valide.
    let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
    si.cb = size_of::<STARTUPINFOW>() as u32;
    // lpDesktop reste NUL (l'etat tout-a-zero de STARTUPINFOW): l'enfant herite
    // alors de la window-station ET du desktop du parent (doc CreateProcessAsUserW,
    // ms.date 2018-12-05), c'est-a-dire exactement les objets que
    // `accorder_acces_poste_de_travail` vient d'ouvrir au compte. Aucun nom code
    // en dur, donc aucune divergence possible entre l'objet ou l'acces est
    // accorde et l'objet ou l'enfant arrive, quel que soit le contexte du daemon
    // (service SCM, tache SYSTEM, session interactive).

    // SAFETY: PROCESS_INFORMATION est POD.
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    // 5. Creer le processus sous le jeton, SANS CREATE_BREAKAWAY_FROM_JOB.
    // SAFETY: le jeton est valide; `ligne` est une chaine UTF-16 mutable
    // terminee par zero, que l'API exige mutable; attributs et environnement
    // NULL; `repertoire` pointe sur un tampon vivant; `si.lpDesktop` est nul
    // (l'enfant herite de la window-station et du desktop du parent); `pi` recoit
    // les poignees a la reussite. dwCreationFlags = 0: aucun
    // CREATE_BREAKAWAY_FROM_JOB, l'enfant reste dans le job du daemon.
    let cree = unsafe {
        CreateProcessAsUserW(
            jeton.as_raw_handle(),
            std::ptr::null(),
            ligne.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            0,
            0,
            std::ptr::null(),
            repertoire.as_ref().map_or(std::ptr::null(), |r| r.as_ptr()),
            &si,
            &mut pi,
        )
    };
    if cree == 0 {
        return Err(Error::Dns(format!(
            "CreateProcessAsUserW({}) sous {compte:?}: erreur Win32 {}",
            lancement.programme.display(),
            std::io::Error::last_os_error()
        )));
    }

    // La poignee de thread ne sert a rien: la refermer tout de suite.
    // SAFETY: pi.hThread est une poignee neuve rendue par CreateProcessAsUserW.
    let _ = unsafe { OwnedHandle::from_raw_handle(pi.hThread as _) };
    // SAFETY: pi.hProcess est une poignee neuve rendue par CreateProcessAsUserW,
    // avec les droits d'attente et de terminaison; on la possede.
    let processus = unsafe { OwnedHandle::from_raw_handle(pi.hProcess as _) };

    let mut en_cours = ResolveurEnCours {
        // Pas de capture de la sortie d'erreur sur ce chemin: rediriger les
        // poignees standard d'un enfant lance sous un autre jeton demande de
        // les rendre heritables et accessibles au compte, ce que 11b-1 ne fait
        // pas. Le journal reste vide; c'est l'identite effective du processus
        // que l'orchestrateur mesure, pas sa sortie d'erreur.
        processus: Processus::SousCompte(ProcessusSousCompte {
            processus,
            pid: pi.dwProcessId,
        }),
        journal: JournalErreur::default(),
        ecoute: lancement.ecoute,
    };

    match en_cours.attendre_disponible() {
        Ok(()) => Ok(en_cours),
        Err(e) => {
            let _ = en_cours.arreter();
            Err(e)
        }
    }
}

/// Ecrit la configuration la ou le resolveur la lira.
///
/// En 0644 et non 0600: dnscrypt-proxy la relit APRES avoir bascule sous son
/// compte non privilegie, et une configuration qu'il ne peut plus lire le fait
/// echouer a un endroit ou le message ne dit rien d'utile. Elle ne contient
/// aucun secret, contrairement a celle d'un coeur anti-censure.
pub fn ecrire_configuration(chemin: &Path, contenu: &str, bascule: Option<Bascule>) -> Result<()> {
    if let Some(rep) = chemin.parent() {
        std::fs::create_dir_all(rep)?;
    }
    // L'ecriture PUIS le partage, jamais l'inverse: ceder le repertoire avant
    // d'y ecrire retire au daemon le droit de creer le fichier qu'il ecrit.
    std::fs::write(chemin, contenu)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(chemin, std::fs::Permissions::from_mode(0o644))?;
    }

    // Le repertoire revient au GROUPE du resolveur, en 0770, et le daemon en
    // reste PROPRIETAIRE. Trois raisons, toutes mesurees:
    //
    // - Le resolveur doit pouvoir ecrire dedans: il y depose le cache de sa
    //   liste de serveurs, et il n'a plus une seule instruction en root.
    // - Le daemon doit pouvoir y reecrire a chaque reconnexion. Le donner
    //   entierement au resolveur le lui interdirait: l'unite systemd ne
    //   contient pas CAP_DAC_OVERRIDE, donc root n'y passe pas outre. Mesure
    //   sous le durcissement de l'unite: la version qui chownait le
    //   repertoire echouait ensuite en `Permission denied`, alors qu'elle
    //   passait sous `sudo`, ou root garde toutes ses capacites.
    // - Le mode est pose explicitement et non laisse a l'umask, que l'unite
    //   fixe a 0077.
    //
    // Et le chown vient APRES l'ecriture, pas avant: l'ordre inverse retire au
    // daemon le droit d'ecrire le fichier qu'il est en train de creer.
    if let Some(rep) = chemin.parent() {
        partager_repertoire(rep, bascule)?;
    }
    Ok(())
}

/// Cree un repertoire que le daemon ET le resolveur peuvent ecrire.
///
/// Le daemon en reste PROPRIETAIRE, le groupe passe au resolveur, mode 0770.
/// Trois raisons, toutes mesurees:
///
/// - Le resolveur doit pouvoir y ecrire: il y depose la liste des serveurs
///   chiffres, et il n'a plus une seule instruction en root.
/// - Le daemon doit pouvoir y revenir a chaque reconnexion. Le donner
///   entierement au resolveur le lui interdirait: l'unite systemd ne contient
///   pas `CAP_DAC_OVERRIDE`, donc root n'y passe pas outre. Mesure sous le
///   durcissement de l'unite le 17/08/2026: la version qui chownait le
///   repertoire echouait ensuite en `Permission denied`, alors qu'elle passait
///   sous `sudo`, ou root garde toutes ses capacites.
/// - Le mode est pose explicitement et non laisse a l'umask, que l'unite fixe
///   a 0077.
///
/// `bascule` n'est lue que sous Unix: ailleurs il n'y a ni setuid ni chown a
/// faire, et le repertoire est simplement cree.
#[cfg_attr(not(unix), allow(unused_variables))]
pub fn partager_repertoire(rep: &Path, bascule: Option<Bascule>) -> Result<()> {
    std::fs::create_dir_all(rep)?;
    #[cfg(unix)]
    if let Some(b) = bascule {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(rep, std::fs::Permissions::from_mode(0o770))?;
        let brut = std::ffi::CString::new(rep.as_os_str().as_encoded_bytes())
            .map_err(|e| Error::Dns(format!("chemin du repertoire de travail: {e}")))?;
        // uid inchange (-1): le daemon reste proprietaire, seul le groupe passe.
        // SAFETY: `brut` est une CString NUL-terminee vivante pendant l'appel; uid -1
        // (u32::MAX) laisse le proprietaire inchange, seul le groupe passe.
        if unsafe { libc::chown(brut.as_ptr(), u32::MAX, b.gid) } != 0 {
            return Err(Error::Dns(format!(
                "le repertoire {} ne peut pas etre partage avec le resolveur: {}",
                rep.display(),
                std::io::Error::last_os_error()
            )));
        }
    }
    Ok(())
}

/// Les `sf-*.tmp` d'un repertoire, tries: les fichiers temporaires que
/// dnscrypt-proxy cree pour ecrire son cache puis renomme. Un reste signe un
/// renommage refuse (ecart 4 du 13/09/2026: sans DELETE sur l'etat, `rename
/// ...: Access is denied.` et le cache n'etait jamais ecrit).
fn temporaires_dans(rep: &Path) -> Vec<String> {
    let mut noms: Vec<String> = match std::fs::read_dir(rep) {
        Ok(entrees) => entrees
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with("sf-") && n.ends_with(".tmp"))
            .collect(),
        Err(_) => Vec::new(),
    };
    noms.sort();
    noms
}

/// Retire les `sf-*.tmp` d'un passage precedent, pour que l'etape "Il ecrit
/// son cache" ne juge que le passage en cours. Rend combien ont ete retires.
fn balayer_temporaires(rep: &Path) -> usize {
    temporaires_dans(rep)
        .into_iter()
        .filter(|n| std::fs::remove_file(rep.join(n)).is_ok())
        .count()
}

/// Etape "Il ecrit son cache" des deux selftests (ecart 4): une fois la liste
/// chargee (le resolveur vient de repondre), `public-resolvers.md` doit
/// exister dans l'etat, non vide. Rend 1 en echec, 0 sinon.
fn etape_cache_ecrit(etat: &Path) -> u32 {
    println!("== Il ecrit son cache");
    let cache = etat.join("public-resolvers.md");
    match std::fs::metadata(&cache) {
        Ok(m) if m.len() > 0 => {
            println!("  OK    {} ecrit ({} octets)", cache.display(), m.len());
            0
        }
        Ok(_) => {
            println!("  ECHEC {} existe mais est vide", cache.display());
            1
        }
        Err(e) => {
            println!(
                "  ECHEC {} absent: {e} (le cache n'a pas pu etre ecrit ou renomme dans l'etat)",
                cache.display()
            );
            1
        }
    }
}

/// Fin des deux selftests (ecart 4): apres TOUS les lancements, aucun
/// `sf-*.tmp` ne doit rester dans l'etat. Rend 1 en echec, 0 sinon.
fn etape_sans_reste_temporaire(etat: &Path) -> u32 {
    println!("== Il ecrit son cache, sans reste temporaire");
    let restes = temporaires_dans(etat);
    if restes.is_empty() {
        println!("  OK    aucun sf-*.tmp dans {}", etat.display());
        0
    } else {
        println!(
            "  ECHEC {} fichier(s) temporaire(s) restent dans l'etat (renommage du cache refuse): {}",
            restes.len(),
            restes.join(", ")
        );
        1
    }
}

/// Avant le premier lancement des deux selftests: les restes d'un passage
/// precedent sont balayes et dits, pour que la fin ne juge que ce passage.
fn balayer_et_dire(etat: &Path) {
    let balayes = balayer_temporaires(etat);
    if balayes > 0 {
        println!(
            "INFO  {balayes} fichier(s) temporaire(s) d'un passage precedent retire(s) de l'etat"
        );
    }
}

/// Eprouve la supervision d'un VRAI dnscrypt-proxy, de bout en bout.
///
/// Le banc en namespaces ne peut pas le faire: il n'a pas d'Internet, et un
/// resolveur chiffre a besoin de joindre sa source puis son serveur. Ce qui se
/// mesure ici est donc l'autre moitie, celle que la doublure du banc ne peut
/// pas prouver: que le binaire demarre, qu'il repond, qu'il tourne bien SOUS
/// LE COMPTE annonce, et qu'il ne survit pas a son arret.
///
/// L'ecoute se fait sur une adresse de boucle locale ecartee, et non
/// 127.0.0.1: le :53 de la machine appartient souvent deja a systemd-resolved,
/// et une recette qui le lui prendrait couperait la resolution de la machine
/// le temps de son execution. Le port reste 53, parce que c'est justement le
/// port privilegie dont la baisse de privilege est le sujet.
///
/// Rend 3 quand le binaire est absent: SKIPPED, jamais PASSED par defaut.
#[cfg(unix)]
pub fn selftest(
    programme: &Path,
    ou: &Path,
    etat: &Path,
    serveurs: &[String],
    bootstrap: &[std::net::IpAddr],
    compte: Option<&str>,
) -> anyhow::Result<()> {
    const ECOUTE: &str = "127.0.0.9:53";

    // Meme convention que --coeur-selftest: 3 pour SKIPPED, jamais un succes
    // par defaut quand rien n a pu etre mesure.
    if !programme.is_file() {
        println!("SKIPPED: {} introuvable", programme.display());
        std::process::exit(3);
    }
    // SAFETY: geteuid ne prend pas d'argument et ne touche aucune memoire.
    if unsafe { libc::geteuid() } != 0 {
        println!("SKIPPED: se lier au :53 exige root");
        std::process::exit(3);
    }

    // Le repertoire de l'exploitation lui-meme, et non /tmp ni un sous-niveau
    // a nous. Deux mesures ont conduit la:
    //
    // - Sous l'unite systemd, `ProtectSystem=strict` rend /tmp en lecture
    //   seule. Une recette qui n'y survit pas ne peut pas eprouver le
    //   durcissement qu'elle existe pour valider.
    // - Un sous-repertoire ajoutait un niveau que le produit n'a pas, cree par
    //   `create_dir_all` sous l'`UMask=0077` de l'unite, donc en 0700
    //   root:root: le resolveur ne pouvait plus le TRAVERSER pour atteindre sa
    //   configuration. Le defaut appartenait a la recette, pas au produit, et
    //   une recette qui echoue la ou le produit reussit ne mesure plus rien.
    //
    // Le fichier porte le PID pour ne pas ecraser celui d'un resolveur en
    // service, et il est efface en partant. Le cache de la liste des serveurs,
    // lui, reste: c'est celui du produit, dans le repertoire du produit.
    let travail = ou.parent().unwrap_or(Path::new("/run/bifrost")).to_owned();
    let configuration = travail.join(format!("selftest-{}.toml", std::process::id()));
    balayer_et_dire(etat);
    let ecoute: SocketAddr = ECOUTE.parse().expect("adresse constante");

    // Le profil Equilibre, comme dans le pendant Windows. Les deux plateformes
    // doivent mesurer la MEME propriete: une couche portee d'un cote et pas de
    // l'autre est la forme de defaut la plus chere de ce depot.
    const PROFIL: bifrost_core::config::ProfilTelemetrie =
        bifrost_core::config::ProfilTelemetrie::Equilibre;
    let blocage = travail.join(format!("selftest-blocage-{}.txt", std::process::id()));

    let contenu = match bifrost_dns::resolveur::dnscrypt_proxy_toml(
        &bifrost_dns::resolveur::ResolveurChiffre {
            ecoute,
            serveurs: serveurs.to_vec(),
            bootstrap: bootstrap.to_vec(),
            cache: etat.join("public-resolvers.md"),
            blocage: Some(blocage.clone()),
        },
    ) {
        Ok(c) => c,
        Err(e) => anyhow::bail!("configuration refusee par notre propre validation: {e}"),
    };
    let bascule = match compte {
        Some(nom) => Some(Bascule::pour(nom)?),
        None => None,
    };
    // La liste AVANT la configuration qui la designe: l'ordre inverse laisse
    // une fenetre ou le resolveur, s'il demarrait entre les deux, lirait une
    // configuration pointant un fichier absent. Ecrite par le meme chemin que
    // la configuration, donc avec les memes droits: le resolveur doit pouvoir
    // la LIRE apres sa bascule d'identifiants.
    ecrire_configuration(
        &blocage,
        &bifrost_dns::telemetrie::blocked_names(PROFIL),
        bascule,
    )?;
    ecrire_configuration(&configuration, &contenu, bascule)?;
    partager_repertoire(etat, bascule)?;
    // Deux fois, et ce n'est pas une redite. Une reconnexion repasse par la
    // meme ecriture, dans un repertoire que le premier passage vient de
    // partager avec le resolveur. Sous l'unite systemd, qui ne donne pas
    // CAP_DAC_OVERRIDE au daemon, une mauvaise repartition des droits ne se
    // voit qu'au SECOND passage: le premier cree le repertoire et reussit, le
    // second se heurte a ce qu'il vient de poser.
    ecrire_configuration(&configuration, &contenu, bascule)
        .map_err(|e| Error::Dns(format!("la configuration n'est pas reecrivable: {e}")))?;

    let mut echecs = 0;
    println!("== Demarrage");
    let en_cours = match demarrer(&Lancement {
        programme: programme.to_owned(),
        configuration: configuration.clone(),
        ecoute,
        bascule,
    }) {
        Ok(r) => {
            println!("  OK    demarre et repond sur {ecoute} (pid {})", r.pid());
            r
        }
        Err(e) => {
            let _ = std::fs::remove_file(&configuration);
            anyhow::bail!("{e}");
        }
    };
    let pid = en_cours.pid();

    println!("== Il refuse les noms de telemetrie et resout le reste");
    // L'ordre compte, et le pendant Windows tient le meme raisonnement. Le
    // PLANCHER d'abord: si le resolveur ne resout rien - pas de reseau, amont
    // injoignable - le nom de telemetrie ne resoudra pas non plus, et le lire
    // comme un blocage reussi serait un vert gratuit. Un resolveur casse et un
    // resolveur qui bloque bien rendent la MEME reponse vide.
    {
        const PLANCHER: &str = "www.msftconnecttest.com";
        const REFUSE: &str = "v10.events.data.microsoft.com";
        match crate::checks::resolveur::interroger(ecoute, PLANCHER)
            .ok()
            .and_then(|r| crate::checks::resolveur::verdict(&r))
        {
            Some((rcode, adresses)) if !adresses.is_empty() => {
                println!(
                    "  OK    {PLANCHER} resout ({} adresse(s), rcode {rcode})",
                    adresses.len()
                );
                match crate::checks::resolveur::interroger(ecoute, REFUSE)
                    .ok()
                    .and_then(|r| crate::checks::resolveur::verdict(&r))
                {
                    Some((rcode, adresses)) if adresses.is_empty() => {
                        println!("  OK    {REFUSE} ne rend aucune adresse (rcode {rcode})")
                    }
                    Some((rcode, adresses)) => {
                        println!(
                            "  ECHEC {REFUSE} resout vers {adresses:?} (rcode {rcode}): la \
                             liste anti-telemetrie ne mord pas"
                        );
                        echecs += 1;
                    }
                    None => {
                        println!("  ECHEC aucune reponse lisible pour {REFUSE}");
                        echecs += 1;
                    }
                }
            }
            autre => println!(
                "  SKIPPED le resolveur ne resout pas {PLANCHER} ({autre:?}): sans question \
                 de controle, une reponse vide sur {REFUSE} ne prouverait pas un blocage"
            ),
        }
    }

    // Ecart 4: le cache est ecrit au meme endroit sur les deux plateformes
    // (`etat.join("public-resolvers.md")`), l'etape est la meme.
    echecs += etape_cache_ecrit(etat);

    println!("== Il tourne sous le compte annonce");
    // La propriete dont depend TOUTE la restriction du :53. Si le processus
    // restait root, ses requetes sortantes porteraient le skuid de root, que
    // la regle ne laisse pas passer: le resolveur serait etrangle par le kill
    // switch cense le proteger. Mesure sur /proc, pas sur la configuration:
    // ce qui compte est ce que le noyau voit, pas ce qu'on a demande.
    match (compte, bascule) {
        (Some(nom), Some(b)) => match uid_effectif(pid) {
            Some(uid) if uid == b.uid => {
                println!("  OK    pid {pid} tourne sous {nom} (uid {uid})")
            }
            Some(uid) => {
                println!(
                    "  ECHEC pid {pid} tourne sous l'uid {uid}, pas sous {nom} \
                     (uid {}): ses requetes seraient bloquees par la regle censee \
                     les laisser passer",
                    b.uid
                );
                echecs += 1;
            }
            None => {
                println!("  ECHEC uid du pid {pid} illisible");
                echecs += 1;
            }
        },
        _ => println!("  SKIP  aucun compte declare, rien a verifier"),
    }

    println!("== Il ne garde que de quoi se lier au :53");
    // L'unite systemd donne au daemon CAP_NET_ADMIN, CAP_NET_RAW et
    // CAP_SYS_ADMIN en ambiant, donc a tous ses enfants par defaut. Un
    // resolveur DNS qui heriterait de quoi reprogrammer nftables serait un
    // elargissement silencieux de la surface, et rien dans le code ne le
    // dirait: seule la lecture de /proc le montre.
    if bascule.is_none() {
        println!("  SKIP  sans bascule le resolveur reste root, rien a mesurer");
    } else {
        // Les TROIS ensembles, pas seulement l'effectif. Le permis est ce que
        // le processus peut reactiver quand il veut; l'ambiant est ce qu'il
        // transmettrait a son tour. Ne lire que l'effectif laisserait passer un
        // resolveur qui a garde CAP_SYS_ADMIN en reserve, ce qui est
        // exactement ce que l'heritage ambiant de l'unite systemd produirait
        // si on ne le vidait pas.
        let attendu = format!("{:016x}", 1u64 << CAP_NET_BIND_SERVICE);
        for ensemble in ["CapEff:", "CapPrm:", "CapAmb:"] {
            match champ_de_status(pid, ensemble) {
                Some(v) if v == attendu => {
                    println!("  OK    {ensemble} reduit a CAP_NET_BIND_SERVICE")
                }
                Some(v) => {
                    println!("  ECHEC {ensemble} {v}, attendu {attendu}");
                    echecs += 1;
                }
                None => {
                    println!("  ECHEC {ensemble} du pid {pid} illisible");
                    echecs += 1;
                }
            }
        }
        match champ_de_status(pid, "Groups:") {
            Some(v) if v.is_empty() => println!("  OK    aucun groupe supplementaire"),
            Some(v) => {
                println!("  ECHEC groupes supplementaires herites de root: {v}");
                echecs += 1;
            }
            None => {
                println!("  ECHEC groupes du pid {pid} illisibles");
                echecs += 1;
            }
        }
    }

    println!("== Arret");
    match en_cours.arreter() {
        Ok(()) => println!("  OK    arret accepte"),
        Err(e) => {
            println!("  ECHEC {e}");
            echecs += 1;
        }
    }
    // Un resolveur orphelin garderait le :53 de la boucle locale, et le
    // systeme continuerait de l'interroger sans que personne ne le supervise.
    if std::path::Path::new(&format!("/proc/{pid}")).exists() {
        println!("  ECHEC le pid {pid} survit a l'arret");
        echecs += 1;
    } else {
        println!("  OK    le processus a disparu");
    }
    if interroger(ecoute).is_ok() {
        println!("  ECHEC quelque chose repond encore sur {ecoute}");
        echecs += 1;
    } else {
        println!("  OK    plus rien ne repond sur {ecoute}");
    }

    println!("== Il ne survit pas a la mort brutale du daemon");
    // Le seul controle qui eprouve la garde du noyau au lieu de la supposer.
    // Tout ce qui precede passe par `arreter`, donc reste vert meme si la garde
    // est desarmee. Un resolveur orphelin garde le :53 de la boucle locale
    // pendant que plus personne ne le supervise.
    match orphelin_apres_mort_brutale(programme, &configuration, etat, ecoute, compte) {
        Ok(None) => println!("  OK    le resolveur meurt avec le daemon"),
        Ok(Some(pid)) => {
            println!(
                "  ECHEC le pid {pid} survit au daemon et garde {ecoute}: la garde \
                 anti-orphelin ne tient pas"
            );
            echecs += 1;
        }
        Err(e) => {
            println!("  ECHEC mesure impossible: {e}");
            echecs += 1;
        }
    }

    echecs += etape_sans_reste_temporaire(etat);

    let _ = std::fs::remove_file(&configuration);
    let _ = std::fs::remove_file(&blocage);
    if echecs == 0 {
        println!("\nresolveur chiffre supervise: tout est passe");
        Ok(())
    } else {
        anyhow::bail!("resolveur chiffre supervise: {echecs} controle(s) en echec")
    }
}

/// Budget d'attente pour un resolveur que Bifrost n'a pas lance lui-meme.
///
/// Bien plus court que `BUDGET_DEMARRAGE`: celui-la est cense etre deja en
/// place et servir. On lui laisse de quoi absorber une liaison en cours, pas
/// de quoi demarrer.
const BUDGET_ADOPTION: Duration = Duration::from_secs(3);

/// Verifie qu'un resolveur repond deja a cette adresse.
///
/// Sert quand le profil demande `embarque` sans que Bifrost n'ait de binaire a
/// lancer. La propriete est la meme que pour un resolveur qu'on demarre
/// soi-meme et elle merite la meme exigence: rien ne doit pointer sur cette
/// adresse tant qu'elle n'a pas repondu.
pub fn verifier_repond(ecoute: SocketAddr) -> Result<()> {
    let echeance = Instant::now() + BUDGET_ADOPTION;
    loop {
        let derniere = match interroger(ecoute) {
            Ok(()) => return Ok(()),
            Err(e) => e.to_string(),
        };
        if Instant::now() >= echeance {
            return Err(Error::Dns(format!(
                "le profil demande un resolveur sur {ecoute}, et rien n'y repond \
                 ({derniere}). Designer un binaire au daemon avec \
                 --resolveur-binaire, ou retirer `embarque` du profil: y pointer \
                 resolv.conf priverait la machine de resolution de noms sans \
                 qu'aucune erreur ne le dise"
            )));
        }
        std::thread::sleep(PAS);
    }
}

/// Version des structures de capacites, celle a trois ensembles de 64 bits.
#[cfg(target_os = "linux")]
const VERSION_CAPACITES: u32 = 0x2008_0522;

/// Numero de CAP_NET_BIND_SERVICE, la seule capacite que garde le resolveur.
#[cfg(target_os = "linux")]
const CAP_NET_BIND_SERVICE: u32 = 10;

/// Structures de `capset`, declarees ici parce que `libc` ne les expose pas.
///
/// Leur disposition est celle de `linux/capability.h` et fait partie de l'ABI
/// du noyau: elle ne peut pas changer sans casser tous les binaires existants.
/// Une version 3 attend DEUX blocs de donnees, jamais un seul.
#[cfg(target_os = "linux")]
#[repr(C)]
struct EnteteCapacites {
    version: u32,
    pid: libc::c_int,
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct BlocCapacites {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

/// Prend les identifiants du resolveur en gardant de quoi se lier au :53.
///
/// Appelee entre `fork` et `exec`, donc uniquement des appels systeme bruts:
/// tout ce qui alloue ou prend un verrou peut bloquer definitivement dans cet
/// intervalle.
///
/// Le detour par les capacites remplace le `user_name` de dnscrypt-proxy, dont
/// la mesure a montre qu'il desarmait la garde anti-orphelin. Il a deux autres
/// vertus: le resolveur ne passe plus une seule instruction en root, et la
/// bascule cesse de dependre de CAP_SETUID, que l'unite systemd durcie ne
/// donne pas.
#[cfg(target_os = "linux")]
fn basculer(b: Bascule) -> std::io::Result<()> {
    use std::io::Error as IoError;

    // Sans KEEPCAPS, passer a un uid non nul vide l'ensemble permis et il ne
    // resterait rien a promouvoir en ambiant.
    // SAFETY: prctl(PR_SET_KEEPCAPS, 1) ne prend que des arguments entiers, aucun
    // pointeur a dereferencer.
    if unsafe { libc::prctl(libc::PR_SET_KEEPCAPS, 1) } != 0 {
        return Err(IoError::last_os_error());
    }
    // Avant setuid, tant qu'on en a encore le droit: sinon le resolveur
    // garderait les groupes supplementaires de root.
    // SAFETY: setgroups(0, null) vide la liste des groupes supplementaires; une
    // longueur nulle rend le pointeur inutilise.
    if unsafe { libc::setgroups(0, std::ptr::null()) } != 0 {
        return Err(IoError::last_os_error());
    }
    // SAFETY: setgid ne prend qu'un gid, aucun pointeur.
    if unsafe { libc::setgid(b.gid) } != 0 {
        return Err(IoError::last_os_error());
    }
    // SAFETY: setuid ne prend qu'un uid, aucun pointeur.
    if unsafe { libc::setuid(b.uid) } != 0 {
        return Err(IoError::last_os_error());
    }

    // setuid a vide l'ensemble effectif; KEEPCAPS n'a garde que le permis. On
    // remonte CAP_NET_BIND_SERVICE dans les trois ensembles, seul etat depuis
    // lequel il peut ensuite etre promu en ambiant. Tout le reste tombe: le
    // resolveur n'a aucun besoin des capacites reseau du daemon, et l'unite
    // systemd les lui transmettrait sans cela.
    let masque = 1u32 << CAP_NET_BIND_SERVICE;
    let entete = EnteteCapacites {
        version: VERSION_CAPACITES,
        pid: 0,
    };
    let donnees = [
        BlocCapacites {
            effective: masque,
            permitted: masque,
            inheritable: masque,
        },
        BlocCapacites {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
    ];
    // SAFETY: `entete` et `donnees` vivent pendant l'appel; capset lit une entete
    // et deux `__user_cap_data_struct`, et `donnees` en contient exactement deux.
    if unsafe { libc::syscall(libc::SYS_capset, &entete, donnees.as_ptr()) } != 0 {
        return Err(IoError::last_os_error());
    }

    // Vider l'ambiant AVANT d'y remettre ce qu'on veut, et ce n'est pas une
    // precaution de style. L'unite systemd donne au daemon CAP_NET_ADMIN,
    // CAP_SYS_ADMIN et CAP_SETUID en ambiant, et l'ambiant est HERITE: sans ce
    // vidage, le resolveur les recevrait toutes. `PR_CAP_AMBIENT_RAISE` ajoute,
    // il ne remplace pas.
    // SAFETY: prctl(PR_CAP_AMBIENT, ...) ne prend que des arguments entiers, aucun
    // pointeur a dereferencer.
    if unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        )
    } != 0
    {
        return Err(IoError::last_os_error());
    }

    // L'ambiant est le seul ensemble qui SURVIT a l'exec d'un binaire sans
    // capacites de fichier. Sans cette derniere etape, le resolveur perdrait
    // tout en devenant dnscrypt-proxy et echouerait a se lier au :53.
    // SAFETY: prctl(PR_CAP_AMBIENT, ...) ne prend que des arguments entiers, aucun
    // pointeur a dereferencer.
    if unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_RAISE,
            CAP_NET_BIND_SERVICE as libc::c_ulong,
            0,
            0,
        )
    } != 0
    {
        return Err(IoError::last_os_error());
    }
    Ok(())
}

/// Demarre le resolveur, annonce son PID, puis se fait tuer sans rien ranger.
///
/// Instrument de mesure, pas un mode d'exploitation. C'est la seule facon
/// d'eprouver la garde anti-orphelin pour de vrai: un daemon qui s'arrete
/// proprement appelle `arreter`, ce qui ne prouve rien sur ce qui arrive quand
/// il ne le peut pas. SIGKILL parce que c'est le seul signal qu'aucun
/// gestionnaire n'intercepte, donc le seul cas ou il ne reste que la garde du
/// noyau.
///
/// Ecrit `PID=<n>` sur la sortie standard avant de mourir, pour que l'appelant
/// sache quoi observer.
#[cfg(unix)]
pub fn abandon(lancement: &Lancement) -> Result<std::convert::Infallible> {
    use std::io::Write;

    let en_cours = demarrer(lancement)?;
    println!("PID={}", en_cours.pid());
    let _ = std::io::stdout().flush();
    // Ni `arreter` ni destructeur: on part en laissant tout en plan, ce qui est
    // precisement la situation a mesurer.
    std::mem::forget(en_cours);
    // SAFETY: raise(SIGKILL) ne touche aucune memoire et ne rend pas la main, ce
    // qui est precisement la situation a mesurer.
    unsafe { libc::raise(libc::SIGKILL) };
    unreachable!("SIGKILL ne rend pas la main")
}

/// Se relance en mode `--resolveur-abandon` et regarde ce qui reste apres.
///
/// Rend `Some(pid)` si le resolveur a survecu, apres l'avoir tue: une recette
/// qui laisse derriere elle exactement ce qu'elle denonce ne vaut rien.
#[cfg(target_os = "linux")]
fn orphelin_apres_mort_brutale(
    programme: &Path,
    configuration: &Path,
    etat: &Path,
    ecoute: SocketAddr,
    compte: Option<&str>,
) -> Result<Option<u32>> {
    let moi = std::env::current_exe()
        .map_err(|e| Error::Dns(format!("chemin de l'executable courant: {e}")))?;
    let mut commande = Command::new(moi);
    commande
        .arg("--resolveur-abandon")
        .arg(ecoute.to_string())
        .arg("--resolveur-binaire")
        .arg(programme)
        .arg("--resolveur-configuration")
        .arg(configuration)
        .arg("--resolveur-etat")
        .arg(etat)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(nom) = compte {
        commande.arg("--resolveur-utilisateur").arg(nom);
    }
    let issue = commande
        .output()
        .map_err(|e| Error::Dns(format!("relance en mode abandon: {e}")))?;

    let texte = String::from_utf8_lossy(&issue.stdout);
    let Some(pid) = texte
        .lines()
        .find_map(|l| l.strip_prefix("PID="))
        .and_then(|n| n.trim().parse::<u32>().ok())
    else {
        return Err(Error::Dns(format!(
            "le mode abandon n'a annonce aucun PID. Sortie: {}",
            String::from_utf8_lossy(&issue.stderr).trim()
        )));
    };

    // Le noyau delivre le signal de mort du parent de facon asynchrone: lire
    // /proc dans la foulee mesurerait la latence de delivrance, pas la garde.
    let echeance = Instant::now() + DELAI_ARRET_DOUX;
    while Instant::now() < echeance {
        if !Path::new(&format!("/proc/{pid}")).exists() {
            return Ok(None);
        }
        std::thread::sleep(PAS);
    }
    // SAFETY: kill(pid, SIGKILL) ne touche aucune memoire.
    unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
    Ok(Some(pid))
}

#[cfg(all(unix, not(target_os = "linux")))]
fn orphelin_apres_mort_brutale(
    _programme: &Path,
    _configuration: &Path,
    _etat: &Path,
    _ecoute: SocketAddr,
    _compte: Option<&str>,
) -> Result<Option<u32>> {
    Err(Error::Dns(
        "observation d'un survivant non portee hors de Linux".to_owned(),
    ))
}

/// Le versant Windows de [`selftest`], borne a ce que le CYCLE DE VIE garantit.
///
/// Il ne mesure pas la separation d'identifiants, qui n'est pas portee: la
/// taire donnerait un vert plus large que ce qui a ete verifie, donc elle est
/// annoncee SKIPPED avec sa raison.
///
/// Adresse d'ecoute: la meme que sous Unix, et ce n'est pas evident. Windows
/// n'a pas de notion de port privilegie: mesure du 21 aout 2026 sur
/// dev-windows ET sur essai-windows, `127.0.0.9:53` se lie sans le moindre
/// privilege, la ou Unix exige root. L'intuition est exactement inversee.
///
/// Le port qu'on croit libre par habitude, `127.0.0.9:5353`, est lui refuse sur
/// les deux machines. La cause n'est PAS une plage exclue, contrairement a ce
/// qui a d'abord ete note ici: `netsh int ipv4 show excludedportrange
/// protocol=udp` rend une table VIDE sur essai-windows, et n'annonce que
/// 50000-50059 sur dev-windows. C'est le repondeur mDNS qui tient deja
/// `0.0.0.0:5353` - le service client DNS, plus tout navigateur ouvert. Le
/// tableau "Bind Behavior with Various Options Set" de Microsoft
/// (SO_EXCLUSIVEADDRUSE, ms.date 2018-05-31) donne la suite: un premier lien
/// joker exclusif fait echouer tout lien ulterieur sur le meme port, en 10048
/// ou en 10013 selon les options posees par le SECOND. D'ou le `AccessDenied`
/// vu par la sonde .NET, qui pose SO_REUSEADDR; `std::net::UdpSocket`, qui ne
/// le pose pas, verrait 10048. Refuse dans les deux cas.
///
/// Rend 3 quand le binaire est absent: SKIPPED, jamais PASSED par defaut.
///
/// `profil`: le chemin du profil que le daemon detient (`--profil`), dont le
/// repertoire est refuse comme repertoire du resolveur (ecart 3): le selftest
/// passe par `demarrer_sous_compte` comme la production, donc par la garde.
#[cfg(windows)]
pub fn selftest(
    programme: &Path,
    ou: &Path,
    etat: &Path,
    serveurs: &[String],
    bootstrap: &[std::net::IpAddr],
    compte: Option<&str>,
    profil: &Path,
) -> anyhow::Result<()> {
    const ECOUTE: &str = "127.0.0.9:53";

    if !programme.is_file() {
        println!("SKIPPED: {} introuvable", programme.display());
        std::process::exit(3);
    }

    // Armee AVANT tout lancement: c'est ce qui fait entrer le resolveur dans le
    // job a sa naissance, et donc ce que l'etape d'appartenance mesure.
    let garde = crate::anti_orphelin::armer_pour_le_processus()?;

    let travail = ou.parent().unwrap_or(Path::new(".")).to_owned();
    std::fs::create_dir_all(&travail)?;
    std::fs::create_dir_all(etat)?;
    balayer_et_dire(etat);
    let configuration = travail.join(format!("selftest-{}.toml", std::process::id()));
    let ecoute: SocketAddr = ECOUTE.parse().expect("adresse constante");

    // Le profil Equilibre, et non `Aucun`: c'est le seul endroit du depot ou un
    // VRAI dnscrypt-proxy lit notre liste. Sans cela, la couche anti-telemetrie
    // ne serait jugee que par des recettes qui comparent des chaines aux
    // chaines qu'elles viennent d'ecrire.
    const PROFIL: bifrost_core::config::ProfilTelemetrie =
        bifrost_core::config::ProfilTelemetrie::Equilibre;
    let blocage = travail.join(format!("selftest-blocage-{}.txt", std::process::id()));
    std::fs::write(&blocage, bifrost_dns::telemetrie::blocked_names(PROFIL))?;

    let contenu =
        bifrost_dns::resolveur::dnscrypt_proxy_toml(&bifrost_dns::resolveur::ResolveurChiffre {
            ecoute,
            serveurs: serveurs.to_vec(),
            bootstrap: bootstrap.to_vec(),
            cache: etat.join("public-resolvers.md"),
            blocage: Some(blocage.clone()),
        })
        .map_err(|e| anyhow::anyhow!("configuration refusee par notre propre validation: {e}"))?;
    ecrire_configuration(&configuration, &contenu, None)?;

    // 11b-1: quand un compte de service est demande, le selftest lance le
    // resolveur SOUS ce compte (ce que fait le daemon en production). On garde
    // le SID resolu pour verifier plus bas que l'enfant tourne bien sous lui.
    //
    // 11b-2: plus AUCUNE ACE posee ici. En 11b-1 le selftest ouvrait lui-meme
    // au compte le repertoire de travail et le repertoire d'etat, doublant un
    // mecanisme que la production n'avait pas. Desormais `demarrer_sous_compte`
    // ouvre au compte, a chaque lancement, la lecture heritable du repertoire
    // de sa configuration (`travail` ici, ou vivent le toml et la liste) et
    // l'ecriture heritable de son etat: le selftest EXERCE le chemin de
    // production au lieu de le masquer. La premiere version de 11b-2
    // n'ouvrait que les deux FICHIERS, pas `travail`: releve essai-windows du
    // 13/09/2026 sous SYSTEM, dnscrypt-proxy change lui-meme de repertoire
    // courant vers celui de sa configuration et sortait en 255 (`chdir ...:
    // Access is denied.`). L'ouverture du repertoire est necessaire.
    let sid_attendu = match compte {
        Some(nom) => {
            let sid = crate::coeurs::identite::resoudre_sid_compte(nom)
                .map_err(|e| anyhow::anyhow!("resolution du compte {nom:?}: {e}"))?;
            Some(sid)
        }
        None => None,
    };

    let mut echecs = 0;
    let lancement = Lancement {
        programme: programme.to_owned(),
        configuration: configuration.clone(),
        ecoute,
        bascule: None,
        // Sous ce compte quand il est demande: c'est ce que 11b-1 ajoute au
        // selftest, et ce que l'etape "Il tourne sous un compte distinct"
        // verifie ensuite.
        compte: compte.map(str::to_owned),
        // 11b-2: l'etat, ce que le resolveur ECRIT. `demarrer_sous_compte`
        // l'ouvre au compte en ecriture, et ouvre en lecture le repertoire de
        // la configuration (`travail`), dont le toml et la liste heritent.
        etat: etat.to_owned(),
        // Ecart 3: `travail` ne doit pas etre le repertoire du profil; la
        // garde le refuserait avant toute ACE.
        profil: profil.to_owned(),
    };

    println!("== Demarrage");
    let en_cours = match demarrer(&lancement) {
        Ok(r) => {
            println!("  OK    demarre et repond sur {ecoute} (pid {})", r.pid());
            r
        }
        Err(e) => {
            let _ = std::fs::remove_file(&configuration);
            let _ = std::fs::remove_file(&blocage);
            anyhow::bail!("{e}");
        }
    };
    let pid = en_cours.pid();

    println!("== Il est ne dans le job, sans fenetre de course");
    use std::os::windows::io::AsHandle;
    match poignee_de(pid).map(|p| garde.contient(p.as_handle())) {
        Some(Ok(true)) => println!("  OK    pid {pid} est membre du job du daemon"),
        Some(Ok(false)) => {
            println!(
                "  ECHEC pid {pid} n'est PAS dans le job: rien ne le tuera si le \
                 daemon meurt brutalement"
            );
            echecs += 1;
        }
        Some(Err(e)) => {
            println!("  ECHEC appartenance au job illisible: {e}");
            echecs += 1;
        }
        None => {
            println!("  ECHEC pid {pid} deja introuvable, l'appartenance n'a pas pu etre lue");
            echecs += 1;
        }
    }

    println!("== Il refuse les noms de telemetrie et resout le reste");
    // L'ordre compte. Le PLANCHER d'abord: si le resolveur ne resout rien -
    // pas de reseau, amont injoignable - alors le nom de telemetrie ne
    // resoudra pas non plus, et le lire comme un blocage reussi serait un vert
    // gratuit. Un resolveur casse et un resolveur qui bloque bien rendent la
    // MEME reponse vide; seule la question de controle les distingue.
    const PLANCHER: &str = "www.msftconnecttest.com";
    const REFUSE: &str = "v10.events.data.microsoft.com";
    match crate::checks::resolveur::interroger(ecoute, PLANCHER)
        .ok()
        .and_then(|r| crate::checks::resolveur::verdict(&r))
    {
        Some((rcode, adresses)) if !adresses.is_empty() => {
            println!(
                "  OK    {PLANCHER} resout ({} adresse(s), rcode {rcode})",
                adresses.len()
            );
            match crate::checks::resolveur::interroger(ecoute, REFUSE)
                .ok()
                .and_then(|r| crate::checks::resolveur::verdict(&r))
            {
                Some((rcode, adresses)) if adresses.is_empty() => {
                    println!("  OK    {REFUSE} ne rend aucune adresse (rcode {rcode})")
                }
                Some((rcode, adresses)) => {
                    println!(
                        "  ECHEC {REFUSE} resout vers {adresses:?} (rcode {rcode}): la liste \
                         anti-telemetrie ne mord pas"
                    );
                    echecs += 1;
                }
                None => {
                    println!("  ECHEC aucune reponse lisible pour {REFUSE}");
                    echecs += 1;
                }
            }
        }
        autre => println!(
            "  SKIPPED le resolveur ne resout pas {PLANCHER} ({autre:?}): sans question de \
             controle, une reponse vide sur {REFUSE} ne prouverait pas un blocage"
        ),
    }

    // Ecart 4 (13/09/2026, essai-windows sous SYSTEM): sans DELETE sur l'etat,
    // le renommage du cache temporaire echouait et le cache n'etait jamais
    // ecrit, un WARNING que personne ne lisait. C'est l'etape qui l'aurait
    // attrape. Les restes `sf-*.tmp` sont juges a la fin, apres tous les
    // lancements (celui du mode abandon compris).
    echecs += etape_cache_ecrit(etat);

    println!("== Il tourne sous un compte distinct");
    // 11b-1: ce que cette etape verifie est le SID EFFECTIF du processus
    // enfant. Il a ete lance sous le compte demande par `CreateProcessAsUserW`
    // (voir `demarrer_sous_compte`); on lit son jeton et on compare son SID a
    // celui du compte. Un binaire absent a deja fait sortir tout le selftest en
    // SKIPPED (exit 3) plus haut: quand on arrive ici, un vrai dnscrypt-proxy
    // tourne, et la mesure est donc opposable.
    match (compte, &sid_attendu) {
        (Some(nom), Some(attendu)) => match sid_effectif_du_processus(pid) {
            Ok(effectif) if &effectif == attendu => {
                println!("  OK    pid {pid} tourne sous {nom} (SID effectif {effectif})")
            }
            Ok(effectif) => {
                println!(
                    "  ECHEC pid {pid} tourne sous {effectif}, attendu {attendu} ({nom}): \
                     le resolveur ne s'est pas lance sous le compte demande"
                );
                echecs += 1;
            }
            Err(e) => {
                println!("  ECHEC SID effectif de pid {pid} illisible: {e}");
                echecs += 1;
            }
        },
        (Some(nom), None) => {
            println!("  ECHEC compte {nom} demande mais SID non resolu avant le lancement");
            echecs += 1;
        }
        (None, _) => println!(
            "  SKIPPED aucun compte demande: le resolveur tourne sous le compte \
             du daemon (--resolveur-utilisateur pour en imposer un, LocalService \
             recommande)"
        ),
    }

    println!("== L'arret rend le port");
    // La question que l'arret dur pose: dnscrypt-proxy ne reagit qu'aux
    // evenements de console, et un service n'a pas de console - la
    // documentation est nette, "Only those processes in the group that share
    // the same console as the calling process receive the signal". Il n'y a
    // donc pas d'arret poli a lui demander, seulement `TerminateProcess`. Ce
    // qu'il faut prouver est que cela ne coute rien d'observable: le port doit
    // redevenir liable tout de suite.
    match en_cours.arreter() {
        Ok(()) => match std::net::UdpSocket::bind(ecoute) {
            Ok(_) => println!("  OK    {ecoute} est de nouveau liable apres l'arret dur"),
            Err(e) => {
                println!("  ECHEC {ecoute} reste pris apres l'arret: {e}");
                echecs += 1;
            }
        },
        Err(e) => {
            println!("  ECHEC arret: {e}");
            echecs += 1;
        }
    }

    println!("== Il ne survit pas a un daemon tue brutalement");
    match orphelin_apres_mort_brutale(programme, &configuration, etat, ecoute, compte) {
        Ok(None) => println!("  OK    aucun survivant apres TerminateProcess sur le daemon"),
        Ok(Some(p)) => {
            println!(
                "  ECHEC le resolveur (pid {p}) a survecu au daemon et gardait {ecoute}. \
                 Il vient d'etre tue."
            );
            echecs += 1;
        }
        Err(e) => {
            println!("  ECHEC observation impossible: {e}");
            echecs += 1;
        }
    }

    echecs += etape_sans_reste_temporaire(etat);

    let _ = std::fs::remove_file(&configuration);
    let _ = std::fs::remove_file(&blocage);
    if echecs > 0 {
        anyhow::bail!("{echecs} propriete(s) du cycle de vie non tenue(s)");
    }
    println!("cycle de vie du resolveur: complet");
    Ok(())
}

/// Poignee sur un processus vivant, refermee a la destruction.
///
/// `OwnedHandle` et non un entier nu: la fermeture vient avec le type, et
/// `as_handle` la prete sans qu'un pointeur brut traverse une signature.
#[cfg(windows)]
fn poignee_de(pid: u32) -> Option<std::os::windows::io::OwnedHandle> {
    use std::os::windows::io::{FromRawHandle, OwnedHandle};
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

    // SAFETY: OpenProcess prend des drapeaux d'acces et un PID, sans pointeur;
    // rend une poignee ou null (teste ensuite).
    let p = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if p.is_null() {
        return None;
    }
    // `OpenProcess` vient de rendre une poignee neuve dont personne d'autre
    // n'est proprietaire: la posseder est exactement ce qu'on veut.
    // SAFETY: `p` est une poignee neuve rendue par OpenProcess (non nulle), dont
    // personne d'autre n'est proprietaire; from_raw_handle en prend la propriete.
    Some(unsafe { OwnedHandle::from_raw_handle(p) })
}

/// Le versant Windows de [`abandon`].
///
/// Meme role, mais la mort brutale n'y est pas un signal: `TerminateProcess`
/// sur soi-meme est ce qui s'en approche le plus, puisqu'il ne laisse tourner
/// ni destructeur ni gestionnaire. C'est exactement la situation que la garde
/// doit couvrir, et c'est aussi celle ou Windows ferme les poignees du
/// processus disparu - donc celle ou l'objet Job tire.
#[cfg(windows)]
pub fn abandon(lancement: &Lancement) -> Result<std::convert::Infallible> {
    use std::io::Write;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, TerminateProcess};

    // La garde AVANT le lancement: le resolveur doit naitre dans le job, sinon
    // la mesure ne mesurerait qu'une fenetre de course.
    crate::anti_orphelin::armer_pour_le_processus()?;

    let en_cours = demarrer(lancement)?;
    println!("PID={}", en_cours.pid());
    let _ = std::io::stdout().flush();

    // Ni `arreter` ni destructeur: on part en laissant tout en plan, ce qui est
    // precisement la situation a mesurer. La garde, elle, n'a pas besoin qu'on
    // la ferme: la mort du processus s'en charge, et c'est le sujet.
    std::mem::forget(en_cours);
    // SAFETY: GetCurrentProcess rend une pseudo-poignee toujours valide;
    // TerminateProcess sur soi-meme ne rend pas la main (comportement voulu).
    unsafe { TerminateProcess(GetCurrentProcess(), 137) };
    unreachable!("TerminateProcess ne rend pas la main")
}

/// Le versant Windows de l'observation d'un survivant.
///
/// `compte` est PROPAGE au mode abandon depuis 11b-1: pour mesurer que la garde
/// anti-orphelin tient AUSSI quand le resolveur a ete lance sous un compte de
/// service (par `CreateProcessAsUserW`, sans `CREATE_BREAKAWAY_FROM_JOB`), il
/// faut que le sous-processus abandonne le lance de la meme facon que la
/// production. Le taire mesurerait le seul chemin ordinaire.
#[cfg(windows)]
fn orphelin_apres_mort_brutale(
    programme: &Path,
    configuration: &Path,
    etat: &Path,
    ecoute: SocketAddr,
    compte: Option<&str>,
) -> Result<Option<u32>> {
    let moi = std::env::current_exe()
        .map_err(|e| Error::Dns(format!("chemin de l'executable courant: {e}")))?;
    let mut commande = Command::new(moi);
    commande
        .arg("--resolveur-abandon")
        .arg(ecoute.to_string())
        .arg("--resolveur-binaire")
        .arg(programme)
        .arg("--resolveur-configuration")
        .arg(configuration)
        .arg("--resolveur-etat")
        .arg(etat);
    if let Some(nom) = compte {
        commande.arg("--resolveur-utilisateur").arg(nom);
    }
    let issue = commande
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| Error::Dns(format!("relance en mode abandon: {e}")))?;

    let texte = String::from_utf8_lossy(&issue.stdout);
    let Some(pid) = texte
        .lines()
        .find_map(|l| l.strip_prefix("PID="))
        .and_then(|n| n.trim().parse::<u32>().ok())
    else {
        return Err(Error::Dns(format!(
            "le mode abandon n'a annonce aucun PID. Sortie: {}",
            String::from_utf8_lossy(&issue.stderr).trim()
        )));
    };

    // La garde tire de facon asynchrone: interroger dans la foulee mesurerait
    // la latence du systeme, pas la garde.
    let echeance = Instant::now() + DELAI_ARRET_DOUX_WINDOWS;
    while Instant::now() < echeance {
        match vivant(pid) {
            Some(false) | None => return Ok(None),
            Some(true) => std::thread::sleep(PAS),
        }
    }
    tuer(pid);
    Ok(Some(pid))
}

/// Ce processus tourne-t-il encore? `None` quand la question n'a plus de sens.
///
/// `WaitForSingleObject` et non `GetExitCodeProcess`: celui-ci rend
/// `STILL_ACTIVE`, qui vaut 259, et un processus sorti avec le code 259 serait
/// declare vivant pour toujours. L'attente, elle, ne confond rien.
///
/// Limite connue et non refermable ici: Windows recycle les identifiants de
/// processus. Entre la mort du resolveur et cet appel, un autre processus a pu
/// prendre le meme numero, et il serait alors compte comme un survivant. La
/// mesure penche donc du cote severe, ce qui est le bon sens pour une garde.
#[cfg(windows)]
fn vivant(pid: u32) -> Option<bool> {
    use windows_sys::Win32::Foundation::{CloseHandle, WAIT_TIMEOUT};
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, WaitForSingleObject,
    };

    // `SYNCHRONIZE`, le droit d'acces standard qu'exige `WaitForSingleObject`,
    // vit chez windows-sys dans `Win32::Storage::FileSystem`, type
    // `FILE_ACCESS_RIGHTS`. Activer toute cette famille pour un droit
    // GENERIQUE serait payer cher un simple nom. La valeur est figee depuis
    // Windows NT et documentee comme droit d'acces standard.
    const SYNCHRONIZE: u32 = 0x0010_0000;

    // SAFETY: OpenProcess prend des drapeaux d'acces et un PID, sans pointeur;
    // rend une poignee ou null (teste ensuite).
    let poignee = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, 0, pid) };
    if poignee.is_null() {
        // Plus ouvrable: disparu, ou hors de portee. Dans les deux cas il n'y a
        // pas de survivant a montrer.
        return None;
    }
    // SAFETY: `poignee` est une poignee de processus valide (non nulle);
    // WaitForSingleObject l'attend avec un delai nul.
    let attente = unsafe { WaitForSingleObject(poignee, 0) };
    // SAFETY: `poignee` a ete ouverte par OpenProcess et n'est plus utilisee apres
    // l'attente; fermee une seule fois.
    unsafe { CloseHandle(poignee) };
    Some(attente == WAIT_TIMEOUT)
}

/// Tue un processus par son identifiant. Une recette qui laisse derriere elle
/// exactement ce qu'elle denonce ne vaut rien.
#[cfg(windows)]
fn tuer(pid: u32) {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_TERMINATE, TerminateProcess};

    // SAFETY: OpenProcess prend PROCESS_TERMINATE et un PID, sans pointeur; rend
    // une poignee ou null (teste ensuite).
    let poignee = unsafe { OpenProcess(PROCESS_TERMINATE, 0, pid) };
    if poignee.is_null() {
        return;
    }
    // SAFETY: `poignee` est valide (non nulle); TerminateProcess puis CloseHandle,
    // chacune une fois, la poignee n'etant plus utilisee apres.
    unsafe {
        TerminateProcess(poignee, 137);
        CloseHandle(poignee);
    }
}

/// UID effectif d'un processus, lu dans `/proc`.
#[cfg(target_os = "linux")]
fn uid_effectif(pid: u32) -> Option<u32> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    // Ligne "Uid:\treel\teffectif\tsauve\tsysteme". C'est l'effectif qui
    // determine le `skuid` des sockets creees ensuite.
    status
        .lines()
        .find(|l| l.starts_with("Uid:"))?
        .split_whitespace()
        .nth(2)?
        .parse()
        .ok()
}

#[cfg(all(unix, not(target_os = "linux")))]
fn uid_effectif(_pid: u32) -> Option<u32> {
    None
}

/// Valeur d'un champ de `/proc/<pid>/status`, sans son etiquette.
#[cfg(target_os = "linux")]
fn champ_de_status(pid: u32, etiquette: &str) -> Option<String> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    status
        .lines()
        .find(|l| l.starts_with(etiquette))
        .map(|l| l[etiquette.len()..].trim().to_owned())
}

#[cfg(all(unix, not(target_os = "linux")))]
fn champ_de_status(_pid: u32, _etiquette: &str) -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn la_requete_de_sonde_est_bien_formee() {
        let q = requete_a("disponibilite.invalid");
        assert_eq!(&q[..2], &[0xB1, 0xF0], "identifiant fixe");
        assert_eq!(u16::from_be_bytes([q[4], q[5]]), 1, "une question");
        assert_eq!(&q[q.len() - 4..], &[0, 1, 0, 1], "type A, classe IN");
        // Chaque etiquette est precedee de sa longueur: 13 pour
        // "disponibilite", 7 pour "invalid", puis l'octet nul de fin.
        assert!(
            q.windows(14).any(|f| f == b"\x0ddisponibilite"),
            "l'etiquette du nom n'est pas encodee: {q:?}"
        );
        assert!(
            q.windows(8).any(|f| f == b"\x07invalid"),
            "la seconde etiquette manque: {q:?}"
        );
    }

    /// La restriction du :53 nomme un uid. Le laisser valoir 0 la transformerait
    /// en son contraire: au lieu de n'ouvrir qu'au resolveur, elle ouvrirait a
    /// tout ce qui tourne en root, et le kill switch resterait vert.
    #[cfg(unix)]
    #[test]
    fn le_resolveur_ne_peut_pas_tourner_en_root() {
        let e = Bascule::pour("0:0").unwrap_err();
        assert!(
            e.to_string().contains("root"),
            "message peu utile pour un refus qui protege le kill switch: {e}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn un_compte_ordinaire_donne_ses_deux_identifiants() {
        assert_eq!(
            Bascule::pour("982:983").unwrap(),
            Bascule { uid: 982, gid: 983 }
        );
    }

    /// Le cas du banc, et celui d'une machine ou dnscrypt-proxy est deja
    /// installe: Bifrost ne lance rien mais doit constater que ca repond.
    #[test]
    fn un_resolveur_deja_en_place_est_reconnu() {
        let serveur = UdpSocket::bind("127.0.0.1:0").unwrap();
        let adresse = serveur.local_addr().unwrap();
        let fil = std::thread::spawn(move || {
            let mut tampon = [0u8; 512];
            let (n, source) = serveur.recv_from(&mut tampon).unwrap();
            // Renvoyer l'identifiant recu: c'est ce que la sonde verifie.
            serveur.send_to(&tampon[..n], source).unwrap();
        });
        assert!(verifier_repond(adresse).is_ok());
        fil.join().unwrap();
    }

    /// Le controle qui empeche le pire silence: `resolv.conf` pointe sur une
    /// adresse muette et la machine perd la resolution de noms sans un mot.
    #[test]
    fn une_adresse_muette_est_refusee_avec_de_quoi_agir() {
        // Un port lie mais qui ne repond jamais: plus proche du cas reel qu'un
        // port ferme, qui provoquerait un ICMP et donc une autre erreur.
        let muet = UdpSocket::bind("127.0.0.1:0").unwrap();
        let adresse = muet.local_addr().unwrap();
        let e = verifier_repond(adresse).unwrap_err();
        let m = e.to_string();
        assert!(
            m.contains("--resolveur-binaire") && m.contains("embarque"),
            "message sans issue praticable: {m}"
        );
    }

    #[test]
    fn un_programme_absent_est_signale_avant_tout_lancement() {
        let e = demarrer(&Lancement {
            programme: PathBuf::from("/inexistant/dnscrypt-proxy"),
            configuration: PathBuf::from("/inexistant/dnscrypt-proxy.toml"),
            ecoute: "127.0.0.1:53".parse().unwrap(),
            bascule: None,
            #[cfg(windows)]
            compte: None,
            // Jamais lus: le programme absent fait sortir avant tout lancement.
            #[cfg(windows)]
            etat: PathBuf::from("/inexistant/etat"),
            #[cfg(windows)]
            profil: PathBuf::from("/inexistant/tunnel.toml"),
        })
        .unwrap_err();
        assert!(
            e.to_string().contains("introuvable"),
            "message peu utile: {e}"
        );
    }

    #[test]
    fn le_journal_garde_la_fin_et_non_le_debut() {
        let j = JournalErreur::default();
        j.pousser("premiere ligne\n");
        j.pousser(&"x".repeat(TAILLE_JOURNAL));
        j.pousser("\nderniere ligne\n");
        let fin = j.dernieres_lignes(1);
        assert_eq!(fin, "derniere ligne", "la cause est dans la DERNIERE ligne");
    }

    #[test]
    fn le_journal_rend_les_dernieres_lignes_dans_l_ordre() {
        let j = JournalErreur::default();
        j.pousser("une\ndeux\ntrois\n");
        assert_eq!(j.dernieres_lignes(2), "deux | trois");
    }

    /// Compte les ACE du DACL d'un repertoire.
    #[cfg(windows)]
    fn compter_ace_chemin(chemin: &Path) -> u32 {
        use windows_sys::Win32::Foundation::{ERROR_SUCCESS, HLOCAL, LocalFree};
        use windows_sys::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
        use windows_sys::Win32::Security::{
            ACL, ACL_SIZE_INFORMATION, AclSizeInformation, GetAclInformation, PSECURITY_DESCRIPTOR,
        };
        const DACL_SECURITY_INFORMATION: u32 = 0x0000_0004;
        let chemin_w = en_utf16(&chemin.to_string_lossy());
        // SAFETY: GetNamedSecurityInfoW alloue `sd`, libere par LocalFree avant
        // le retour; `dacl` pointe dans `sd`; `chemin_w` est terminee par zero.
        unsafe {
            let mut dacl: *mut ACL = std::ptr::null_mut();
            let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
            let code = GetNamedSecurityInfoW(
                chemin_w.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut dacl,
                std::ptr::null_mut(),
                &mut sd,
            );
            assert_eq!(code, ERROR_SUCCESS, "GetNamedSecurityInfoW (comptage)");
            let mut nb = 0u32;
            if !dacl.is_null() {
                let mut taille: ACL_SIZE_INFORMATION = std::mem::zeroed();
                if GetAclInformation(
                    dacl,
                    (&mut taille as *mut ACL_SIZE_INFORMATION).cast(),
                    size_of::<ACL_SIZE_INFORMATION>() as u32,
                    AclSizeInformation,
                ) != 0
                {
                    nb = taille.AceCount;
                }
            }
            LocalFree(sd as HLOCAL);
            nb
        }
    }

    /// Ecart 2, versant window-station/desktop: la decision de doublon que pose
    /// `ajouter_ace_objet` (via `ace_allow_equivalente_presente`) reconnait une
    /// ACE identique et distingue un SID, un masque ou des drapeaux differents.
    ///
    /// La recette s'exerce sur un DACL construit EN MEMOIRE, pas sur un vrai
    /// objet noyau: sur dev-windows le processus de test est bien sur la
    /// window-station interactive, mais `CreateWindowStationW` y rend
    /// ERROR_ACCESS_DENIED (privilege) et
    /// `CreateDesktopExW` ERROR_NOT_ENOUGH_MEMORY (reserve partagee de la station
    /// interactive saturee); aucun objet USER jetable n'est creable ici. La
    /// decision de doublon est justement partagee entre `ajouter_ace_objet` et
    /// `accorder_acces_chemin` pour etre verifiable sans objet noyau; le versant
    /// bout-en-bout sur un vrai objet est mesure par les recettes chemin
    /// (`accorder_acces_chemin_accorde_le_sid_sur_un_vrai_repertoire` et
    /// `..._sur_un_vrai_fichier`) et, pour la window-station reelle, reste a
    /// l'orchestrateur sur un hote a la reserve de desktop disponible.
    ///
    /// 11b-2 (13/09/2026): la forme PROJETEE est couverte aussi. Une ACE
    /// construite avec le masque specifique que l'OS stocke sur un fichier
    /// (drapeaux 0) doit etre reconnue quand on lui presente le masque generique
    /// ecrit et sa projection, et ne pas l'etre sans la projection ni pour une
    /// autre projection. Sans cela le predicat corrige ne serait garde par
    /// rien en memoire.
    #[cfg(windows)]
    #[test]
    fn ace_allow_equivalente_reconnait_le_doublon() {
        use windows_sys::Win32::Security::{ACL, AddAccessAllowedAce, InitializeAcl};

        const ACL_REVISION: u32 = 2;
        // DESKTOP_ACCES_COMPLET, le masque que pose accorder_acces_poste_de_travail.
        const MASQUE: u32 = 0x0000_01FF | 0x000F_0000;
        const AUTRE_MASQUE: u32 = 0x0000_0001;
        // Ce qu'ecrit accorder_acces_chemin en lecture (GENERIC_READ|EXECUTE),
        // ce que l'OS stocke pour ce masque sur un fichier
        // (FILE_GENERIC_READ|EXECUTE, releve du 13/09/2026), et une autre
        // projection (celle de l'ecriture, GENERIC_READ|WRITE|EXECUTE|DELETE,
        // relue 0x001301BF le 13/09/2026: Modify).
        const GENERIQUE_LECTURE: u32 = 0x8000_0000 | 0x2000_0000;
        const PROJETE_LECTURE: u32 = 0x0012_0089 | 0x0012_00A0;
        const PROJETE_ECRITURE: u32 = 0x0013_01BF;
        const HERITAGE_CONTENU: u8 = 0x01 | 0x02;

        let ls = sid_binaire("LocalService").expect("SID de LocalService sur dev-windows");
        let systeme = sid_binaire("SYSTEM").expect("SID de SYSTEM sur dev-windows");
        let psid_ls = ls.as_ptr() as *mut core::ffi::c_void;
        let psid_sys = systeme.as_ptr() as *mut core::ffi::c_void;

        let mut tampon = vec![0u8; 512];
        let dacl = tampon.as_mut_ptr() as *mut ACL;
        // SAFETY: `dacl` pointe un tampon de 512 octets vivant jusqu'a la fin de
        // la recette; InitializeAcl puis AddAccessAllowedAce ecrivent dedans;
        // `psid_ls` est un SID valide rendu par LookupAccountNameW.
        unsafe {
            assert!(InitializeAcl(dacl, 512, ACL_REVISION) != 0, "InitializeAcl");
            // DACL vide: aucune ACE ne peut correspondre.
            assert!(
                !ace_allow_equivalente_presente(dacl, 0, psid_ls, MASQUE, 0, None),
                "DACL vide: aucune equivalence possible"
            );
            assert!(
                AddAccessAllowedAce(dacl, ACL_REVISION, MASQUE, psid_ls) != 0,
                "AddAccessAllowedAce"
            );
        }

        // Meme SID, meme masque, memes drapeaux (0): reconnu comme doublon - c'est
        // ce qui evite qu'ajouter_ace_objet ne rempile une ACE a chaque relance.
        assert!(
            ace_allow_equivalente_presente(dacl, 1, psid_ls, MASQUE, 0, None),
            "une ACE identique doit etre reconnue (sinon le DACL grossit a chaque relance)"
        );
        // Masque different: pas un doublon.
        assert!(
            !ace_allow_equivalente_presente(dacl, 1, psid_ls, AUTRE_MASQUE, 0, None),
            "un masque different ne doit pas passer pour un doublon"
        );
        // Drapeaux d'heritage differents: pas un doublon.
        assert!(
            !ace_allow_equivalente_presente(dacl, 1, psid_ls, MASQUE, 0x02, None),
            "des drapeaux differents ne doivent pas passer pour un doublon"
        );
        // SID different: pas un doublon.
        assert!(
            !ace_allow_equivalente_presente(dacl, 1, psid_sys, MASQUE, 0, None),
            "un SID different ne doit pas passer pour un doublon"
        );

        // Forme PROJETEE (11b-2): une ACE telle que l'OS la stocke sur un fichier
        // pour une ecriture generique heritable de lecture.
        // SAFETY: memes conditions que ci-dessus, le tampon a la place.
        unsafe {
            assert!(
                AddAccessAllowedAce(dacl, ACL_REVISION, PROJETE_LECTURE, psid_ls) != 0,
                "AddAccessAllowedAce (projetee)"
            );
        }
        assert_eq!(
            projeter_droits_fichier(GENERIQUE_LECTURE),
            PROJETE_LECTURE,
            "MapGenericMask doit projeter GENERIC_READ|EXECUTE en FILE_GENERIC_READ|EXECUTE"
        );
        assert!(
            ace_allow_equivalente_presente(
                dacl,
                2,
                psid_ls,
                GENERIQUE_LECTURE,
                HERITAGE_CONTENU,
                Some(PROJETE_LECTURE)
            ),
            "l'ACE projetee stockee par l'OS doit etre reconnue comme la notre"
        );
        assert!(
            !ace_allow_equivalente_presente(
                dacl,
                2,
                psid_ls,
                GENERIQUE_LECTURE,
                HERITAGE_CONTENU,
                None
            ),
            "sans la projection, la forme stockee par l'OS ne ressemble a rien de ce qu'on ecrit"
        );
        assert!(
            !ace_allow_equivalente_presente(
                dacl,
                2,
                psid_ls,
                GENERIQUE_LECTURE,
                HERITAGE_CONTENU,
                Some(PROJETE_ECRITURE)
            ),
            "une autre projection (lecture+ecriture) ne doit pas passer pour la lecture seule"
        );
    }

    /// Compte les ACCESS_ALLOWED_ACE d'un repertoire qui portent `sid` (masque et
    /// drapeaux ignores: sur un fichier l'OS transforme l'ACE ecrite, cf. le
    /// commentaire de la recette chemin ci-dessous).
    #[cfg(windows)]
    fn compte_ace_pour_sid_chemin(chemin: &Path, sid: *mut core::ffi::c_void) -> u32 {
        use windows_sys::Win32::Foundation::{ERROR_SUCCESS, HLOCAL, LocalFree};
        use windows_sys::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
        use windows_sys::Win32::Security::{
            ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION, AclSizeInformation,
            EqualSid, GetAce, GetAclInformation, PSECURITY_DESCRIPTOR,
        };
        const DACL_SECURITY_INFORMATION: u32 = 0x0000_0004;
        let chemin_w = en_utf16(&chemin.to_string_lossy());
        // SAFETY: GetNamedSecurityInfoW alloue `sd`, libere par LocalFree; `dacl`
        // pointe dedans; GetAce rend des ACE valides DANS ce DACL; `sid` est un
        // SID valide. Lecture seule.
        unsafe {
            let mut dacl: *mut ACL = std::ptr::null_mut();
            let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
            let code = GetNamedSecurityInfoW(
                chemin_w.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut dacl,
                std::ptr::null_mut(),
                &mut sd,
            );
            assert_eq!(code, ERROR_SUCCESS, "GetNamedSecurityInfoW (comptage SID)");
            let mut compte = 0u32;
            if !dacl.is_null() {
                let mut taille: ACL_SIZE_INFORMATION = std::mem::zeroed();
                if GetAclInformation(
                    dacl,
                    (&mut taille as *mut ACL_SIZE_INFORMATION).cast(),
                    size_of::<ACL_SIZE_INFORMATION>() as u32,
                    AclSizeInformation,
                ) != 0
                {
                    for i in 0..taille.AceCount {
                        let mut ace: *mut core::ffi::c_void = std::ptr::null_mut();
                        if GetAce(dacl, i, &mut ace) == 0 {
                            continue;
                        }
                        let entete = &*(ace as *const ACE_HEADER);
                        if entete.AceType != 0 {
                            continue;
                        }
                        let allow = ace as *const ACCESS_ALLOWED_ACE;
                        let ps = std::ptr::addr_of!((*allow).SidStart) as *mut core::ffi::c_void;
                        if EqualSid(sid, ps) != 0 {
                            compte += 1;
                        }
                    }
                }
            }
            LocalFree(sd as HLOCAL);
            compte
        }
    }

    /// Ecart 2, versant chemin (round-trip sur un vrai objet noyau): `accorder_acces_chemin`
    /// accorde bien le compte de service sur un repertoire, et la relance ne fait
    /// pas grossir le DACL.
    ///
    /// RELEVE (dev-windows): sur un objet FICHIER, l'OS ne stocke PAS l'ACE telle
    /// qu'on l'ecrit. Une ACE heritable a masque generique (ce qu'ecrit
    /// `accorder_acces_chemin`: GENERIC_* + OBJECT/CONTAINER_INHERIT) est eclatee
    /// par le systeme en deux: une ACE EFFECTIVE sur le repertoire lui-meme
    /// (masque mappe en droits fichier specifiques, drapeaux 0x00) et une ACE
    /// INHERIT_ONLY pour les enfants (masque generique conserve, drapeaux 0x0B).
    /// De plus SetNamedSecurityInfoW (ecrit sans SE_DACL_PROTECTED) re-fusionne
    /// l'heritage et STABILISE le compte total: mesure 4 -> 6 -> 6 -> 6, avec ET
    /// sans la detection de doublon. Consequences honnetes:
    ///  - sur un repertoire, le compte total d'ACE ne peut PAS falsifier le dedup
    ///    (il ne bouge pas de toute facon), et le predicat (SID+masque+drapeaux)
    ///    ne reconnait pas ses propres ACE apres transformation: le dedup y est
    ///    donc inoperant, mais SANS consequence (le repertoire ne fuit pas);
    ///  - la fuite reelle que l'ecart 2 vise est sur les objets USER
    ///    (window-station/desktop), ou SetUserObjectSecurity stocke les ACE
    ///    VERBATIM (masques deja specifiques, pas d'heritage sur nos deux ACE
    ///    directes): la, le dedup (SID+masque+drapeaux) matche et court-circuite.
    ///    Cet effet n'est PAS mesurable ici (aucun objet USER jetable creable sur
    ///    dev-windows, cf. `ace_allow_equivalente_reconnait_le_doublon`); il reste
    ///    a l'orchestrateur sur essai-windows.
    ///
    /// Ce que cette recette garde donc, falsifiable ici: `accorder_acces_chemin`
    /// pose reellement au moins une ACE pour le compte (et aucune pour un compte
    /// tiers), deux appels laissent le compte total inchange, et depuis 11b-2
    /// (13/09/2026) la relance est RECONNUE par le predicat de doublon (elle
    /// n'ecrit rien: retour `false`), ce que le compte seul ne pouvait pas dire
    /// puisque l'OS refusionne. Elle imprime les `(Mask, AceFlags)` stockes
    /// pour le SID: c'est le releve dont le predicat est ecrit.
    #[cfg(windows)]
    #[test]
    fn accorder_acces_chemin_accorde_le_sid_sur_un_vrai_repertoire() {
        let base =
            std::env::temp_dir().join(format!("bifrost_dedup_chemin_{}", std::process::id()));
        std::fs::create_dir_all(&base).expect("repertoire jetable");

        let ls = sid_binaire("LocalService").expect("SID de LocalService sur dev-windows");
        let psid_ls = ls.as_ptr() as *mut core::ffi::c_void;

        // Avant: aucune ACE LocalService (controle que le compteur sait rendre 0
        // sur un SID absent - un compteur bloque a >=1 serait sans valeur).
        assert_eq!(
            compte_ace_pour_sid_chemin(&base, psid_ls),
            0,
            "aucune ACE LocalService ne devrait exister avant la pose"
        );

        let ecrite = accorder_acces_chemin(&base, psid_ls, true).expect("pose de l'ACE");
        assert!(
            ecrite,
            "la premiere pose doit ECRIRE une ACE (rien n'etait la)"
        );

        // Apres: au moins une ACE LocalService. Falsifiable: si accorder n'ajoute
        // rien (ou pour le mauvais compte), ce compte reste 0 et la recette rougit.
        assert!(
            compte_ace_pour_sid_chemin(&base, psid_ls) >= 1,
            "accorder_acces_chemin doit avoir pose au moins une ACE pour le compte"
        );
        println!(
            "RELEVE repertoire, ACE du SID apres la pose (Mask, AceFlags): {:?}",
            aces_pour_sid_chemin(&base, psid_ls)
                .iter()
                .map(|(m, f)| format!("(0x{m:08x}, 0x{f:02x})"))
                .collect::<Vec<_>>()
        );

        // Ecart 4 (13/09/2026): l'ecriture emporte DELETE (0x00010000), sans
        // quoi dnscrypt-proxy ne peut pas renommer son cache temporaire.
        // Falsifiable: retirer DELETE du masque d'ecriture.
        const DELETE: u32 = 0x0001_0000;
        let masque = aces_pour_sid_chemin(&base, psid_ls)
            .iter()
            .fold(0u32, |acc, (m, _)| acc | m);
        assert_ne!(
            masque & DELETE,
            0,
            "ecriture = true doit accorder DELETE (renommage du cache): masque cumule 0x{masque:08x}"
        );

        // Relance: sans erreur, le compte total ne grossit pas (sur un
        // repertoire, l'OS re-fusionne l'heritage; cf. RELEVE ci-dessus), ET
        // la relance est reconnue: rien n'est reecrit. Falsifiable: aveugler le
        // predicat, ou lui retirer la forme projetee, rend `true` ici.
        let total_un = compter_ace_chemin(&base);
        let reecrite = accorder_acces_chemin(&base, psid_ls, true).expect("relance");
        let total_deux = compter_ace_chemin(&base);

        let _ = std::fs::remove_dir_all(&base);

        assert_eq!(
            total_un, total_deux,
            "la relance ne doit pas faire grossir le DACL du repertoire"
        );
        assert!(
            !reecrite,
            "la relance doit etre reconnue par le predicat de doublon et ne rien reecrire"
        );
    }

    /// Les `(Mask, AceFlags)` de chaque ACCESS_ALLOWED_ACE d'un chemin qui porte
    /// `sid`, dans l'ordre du DACL: ce que l'OS a STOCKE, tel quel.
    ///
    /// Sert aux releves (imprimes par les recettes chemin) et a constater qu'une
    /// pose en lecture seule ne donne AUCUN droit d'ecriture, sous quelque forme
    /// que l'OS ait stocke le masque: generique tel qu'ecrit, ou projete en
    /// droits fichier specifiques.
    #[cfg(windows)]
    fn aces_pour_sid_chemin(chemin: &Path, sid: *mut core::ffi::c_void) -> Vec<(u32, u8)> {
        use windows_sys::Win32::Foundation::{ERROR_SUCCESS, HLOCAL, LocalFree};
        use windows_sys::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
        use windows_sys::Win32::Security::{
            ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION, AclSizeInformation,
            EqualSid, GetAce, GetAclInformation, PSECURITY_DESCRIPTOR,
        };
        const DACL_SECURITY_INFORMATION: u32 = 0x0000_0004;
        let chemin_w = en_utf16(&chemin.to_string_lossy());
        // SAFETY: GetNamedSecurityInfoW alloue `sd`, libere par LocalFree; `dacl`
        // pointe dedans; GetAce rend des ACE valides DANS ce DACL; `sid` est un
        // SID valide. Lecture seule.
        unsafe {
            let mut dacl: *mut ACL = std::ptr::null_mut();
            let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
            let code = GetNamedSecurityInfoW(
                chemin_w.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut dacl,
                std::ptr::null_mut(),
                &mut sd,
            );
            assert_eq!(code, ERROR_SUCCESS, "GetNamedSecurityInfoW (masque SID)");
            let mut aces = Vec::new();
            if !dacl.is_null() {
                let mut taille: ACL_SIZE_INFORMATION = std::mem::zeroed();
                if GetAclInformation(
                    dacl,
                    (&mut taille as *mut ACL_SIZE_INFORMATION).cast(),
                    size_of::<ACL_SIZE_INFORMATION>() as u32,
                    AclSizeInformation,
                ) != 0
                {
                    for i in 0..taille.AceCount {
                        let mut ace: *mut core::ffi::c_void = std::ptr::null_mut();
                        if GetAce(dacl, i, &mut ace) == 0 {
                            continue;
                        }
                        let entete = &*(ace as *const ACE_HEADER);
                        if entete.AceType != 0 {
                            continue;
                        }
                        let allow = ace as *const ACCESS_ALLOWED_ACE;
                        let ps = std::ptr::addr_of!((*allow).SidStart) as *mut core::ffi::c_void;
                        if EqualSid(sid, ps) != 0 {
                            aces.push(((*allow).Mask, entete.AceFlags));
                        }
                    }
                }
            }
            LocalFree(sd as HLOCAL);
            aces
        }
    }

    /// 11b-2, versant FICHIER de `accorder_acces_chemin`, sur un vrai fichier
    /// temporaire (poser une ACE sur un fichier qu'on vient de creer ne demande
    /// aucun privilege). C'est le cas de production: la configuration et la
    /// liste anti-telemetrie sont des FICHIERS, ouverts en lecture au compte par
    /// `demarrer_sous_compte` a chaque lancement. Quatre proprietes assertees,
    /// chacune falsifiee le 13/09/2026 sur dev-windows:
    ///  - la premiere pose ECRIT une ACE (retour `true`), et l'ACE du SID est
    ///    presente apres, absente avant;
    ///  - `ecriture = false` ne donne pas l'ecriture: aucun bit d'ecriture,
    ///    generique ou specifique, dans les ACE du SID (GENERIC_WRITE ajoute
    ///    au masque de lecture rougit);
    ///  - relancer ne fait pas croitre le compte d'ACE PORTANT LE SID. Jamais
    ///    le compte total: mesure du 06/09/2026, l'OS eclate une ACE heritable
    ///    a masque generique en deux sur un objet fichier; on compte par SID
    ///    pour rester opposable quoi que l'OS ait stocke;
    ///  - la relance est RECONNUE par le predicat de doublon (retour `false`),
    ///    et pas seulement absorbee par l'OS: aveugler le predicat, ou lui
    ///    retirer la forme projetee, rougit ici.
    ///
    /// Elle imprime les `(Mask, AceFlags)` stockes pour le SID: c'est le releve
    /// dont le predicat est ecrit (fichier: une ACE, masque projete, 0x00).
    #[cfg(windows)]
    #[test]
    fn accorder_acces_chemin_accorde_le_sid_sur_un_vrai_fichier() {
        let fichier =
            std::env::temp_dir().join(format!("bifrost_ace_fichier_{}.txt", std::process::id()));
        std::fs::write(&fichier, b"temoin").expect("fichier jetable");
        assert!(fichier.is_file(), "le temoin doit etre un FICHIER");

        let ls = sid_binaire("LocalService").expect("SID de LocalService sur dev-windows");
        let psid_ls = ls.as_ptr() as *mut core::ffi::c_void;

        // Avant: aucune ACE LocalService (le compteur sait rendre 0).
        assert_eq!(
            compte_ace_pour_sid_chemin(&fichier, psid_ls),
            0,
            "aucune ACE LocalService ne devrait exister avant la pose"
        );

        let ecrite =
            accorder_acces_chemin(&fichier, psid_ls, false).expect("pose en lecture seule");
        assert!(
            ecrite,
            "la premiere pose doit ECRIRE une ACE (rien n'etait la)"
        );

        // Apres: au moins une ACE LocalService. Falsifiable: si accorder n'ajoute
        // rien, ou pour le mauvais compte, ce compte reste 0.
        let apres_un = compte_ace_pour_sid_chemin(&fichier, psid_ls);
        assert!(
            apres_un >= 1,
            "accorder_acces_chemin doit avoir pose au moins une ACE pour le compte sur un fichier"
        );

        // ecriture = false ne donne pas l'ecriture, sous les deux formes de
        // masque que l'OS peut stocker. Falsifiable: passer `true` a la pose, ou
        // ajouter GENERIC_WRITE au masque de lecture, fait apparaitre un bit.
        const GENERIC_WRITE: u32 = 0x4000_0000;
        const GENERIC_ALL: u32 = 0x1000_0000;
        const FILE_WRITE_DATA: u32 = 0x0000_0002;
        const FILE_APPEND_DATA: u32 = 0x0000_0004;
        const DELETE: u32 = 0x0001_0000;
        const BITS_ECRITURE: u32 =
            GENERIC_WRITE | GENERIC_ALL | FILE_WRITE_DATA | FILE_APPEND_DATA | DELETE;
        let aces = aces_pour_sid_chemin(&fichier, psid_ls);
        println!(
            "RELEVE fichier, ACE du SID apres la pose (Mask, AceFlags): {:?}",
            aces.iter()
                .map(|(m, f)| format!("(0x{m:08x}, 0x{f:02x})"))
                .collect::<Vec<_>>()
        );
        let masque = aces.iter().fold(0u32, |acc, (m, _)| acc | m);
        assert_eq!(
            masque & BITS_ECRITURE,
            0,
            "ecriture = false ne doit donner aucun droit d'ecriture: masque cumule 0x{masque:08x}"
        );

        // Relance: sans erreur, le compte d'ACE PORTANT LE SID ne grossit pas,
        // ET la relance est reconnue par le predicat (rien reecrit). Le compte
        // seul ne suffit pas a falsifier: SetNamedSecurityInfoW fusionne de
        // lui-meme une ACE identique reposee (releve du 13/09/2026); c'est le
        // retour `false` qui dit que le predicat a mordu. Falsifiable: aveugler
        // `ace_allow_equivalente_presente`, ou lui retirer la forme projetee,
        // rend `true` ici.
        let reecrite = accorder_acces_chemin(&fichier, psid_ls, false).expect("relance");
        let apres_deux = compte_ace_pour_sid_chemin(&fichier, psid_ls);

        let _ = std::fs::remove_file(&fichier);

        assert_eq!(
            apres_un, apres_deux,
            "la relance ne doit pas faire grossir le compte d'ACE portant le SID sur un fichier"
        );
        assert!(
            !reecrite,
            "la relance doit etre reconnue par le predicat de doublon et ne rien reecrire"
        );
    }

    /// `ouvrir_au_compte` est le mecanisme de production (11b-2, ecart 2 du
    /// 13/09/2026): lecture heritable du repertoire du resolveur, ecriture
    /// heritable de son sous-repertoire d'etat. Sur un vrai repertoire
    /// temporaire, avec un vrai fichier dedans et un vrai sous-repertoire, elle
    /// asserte, chaque point falsifie sur dev-windows:
    ///  - le fichier (la configuration) HERITE de la lecture: au moins une ACE
    ///    du SID apres la pose, aucune avant, et le cumul de leurs masques n'a
    ///    aucun bit d'ecriture, generique ou specifique;
    ///  - le repertoire lui-meme n'accorde aucun bit d'ecriture au SID;
    ///  - le sous-repertoire d'etat, lui, porte l'ecriture (FILE_WRITE_DATA
    ///    dans le cumul);
    ///  - la premiere pose ECRIT sur les deux repertoires (`(true, true)`), la
    ///    relance ne reecrit rien (`(false, false)`) et laisse les comptes
    ///    d'ACE du SID inchanges sur les trois objets.
    ///
    /// Elle imprime les `(Mask, AceFlags)` des trois objets: c'est le releve de
    /// la propagation (une ACE heritee porte INHERITED_ACE, 0x10).
    #[cfg(windows)]
    #[test]
    fn ouvrir_au_compte_lit_le_repertoire_et_n_ecrit_que_l_etat() {
        // Le profil la ou la production le met: ailleurs que dans ce
        // repertoire temporaire, la garde de l'ecart 3 n'a rien a refuser.
        const PROFIL: &str = bifrost_coffre::CHEMIN_PAR_DEFAUT;
        let base = std::env::temp_dir().join(format!("bifrost_resolveur_{}", std::process::id()));
        let etat = base.join("etat");
        let configuration = base.join("dnscrypt-proxy.toml");
        std::fs::create_dir_all(&etat).expect("repertoires jetables");
        std::fs::write(&configuration, b"# temoin").expect("fichier jetable");

        let ls = sid_binaire("LocalService").expect("SID de LocalService sur dev-windows");
        let psid_ls = ls.as_ptr() as *mut core::ffi::c_void;
        let objets = [&base, &configuration, &etat];
        let comptes = |psid: *mut core::ffi::c_void| {
            objets.map(|chemin| compte_ace_pour_sid_chemin(chemin, psid))
        };

        // Avant: aucune ACE LocalService sur les trois objets.
        assert_eq!(
            comptes(psid_ls),
            [0, 0, 0],
            "aucune ACE LocalService ne devrait exister avant la pose (repertoire, configuration, etat)"
        );

        let (rep_ecrit, etat_ecrit) =
            ouvrir_au_compte(&configuration, &etat, Path::new(PROFIL), psid_ls).expect("pose");
        assert!(
            rep_ecrit && etat_ecrit,
            "la premiere pose doit ECRIRE sur le repertoire et sur l'etat: ({rep_ecrit}, {etat_ecrit})"
        );

        const GENERIC_WRITE: u32 = 0x4000_0000;
        const GENERIC_ALL: u32 = 0x1000_0000;
        const FILE_WRITE_DATA: u32 = 0x0000_0002;
        const FILE_APPEND_DATA: u32 = 0x0000_0004;
        const DELETE: u32 = 0x0001_0000;
        const BITS_ECRITURE: u32 =
            GENERIC_WRITE | GENERIC_ALL | FILE_WRITE_DATA | FILE_APPEND_DATA | DELETE;
        let releve = |nom: &str, chemin: &Path| {
            let aces = aces_pour_sid_chemin(chemin, psid_ls);
            println!(
                "RELEVE {nom}, ACE du SID apres la pose (Mask, AceFlags): {:?}",
                aces.iter()
                    .map(|(m, f)| format!("(0x{m:08x}, 0x{f:02x})"))
                    .collect::<Vec<_>>()
            );
            aces
        };
        let cumul = |aces: &[(u32, u8)]| aces.iter().fold(0u32, |acc, (m, _)| acc | m);
        let aces_base = releve("repertoire", &base);
        let aces_conf = releve("configuration", &configuration);
        let aces_etat = releve("etat", &etat);
        let (masque_base, masque_conf, masque_etat) =
            (cumul(&aces_base), cumul(&aces_conf), cumul(&aces_etat));

        // Le repertoire lui-meme porte l'ACE du SID: c'est lui que dnscrypt-proxy
        // ouvre en le prenant comme repertoire courant. Falsifiable: ouvrir le
        // fichier de configuration au lieu de son repertoire laisse 0 ici.
        assert!(
            !aces_base.is_empty(),
            "le repertoire du resolveur doit porter une ACE du SID (dnscrypt-proxy en fait son repertoire courant)"
        );
        // La configuration HERITE de la lecture (INHERITED_ACE, 0x10, sur au
        // moins une ACE: propagee par l'OS, pas posee fichier par fichier),
        // sans aucun bit d'ecriture. Falsifiable: ouvrir le repertoire en
        // ecriture fait apparaitre un bit ici et sur le repertoire.
        const INHERITED_ACE: u8 = 0x10;
        assert!(
            aces_conf.iter().any(|(_, f)| f & INHERITED_ACE != 0),
            "la configuration doit HERITER d'une ACE du SID (drapeaux relus: {:?})",
            aces_conf
                .iter()
                .map(|(_, f)| format!("0x{f:02x}"))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            masque_conf & BITS_ECRITURE,
            0,
            "la configuration ne doit pas etre modifiable par le compte: masque cumule 0x{masque_conf:08x}"
        );
        assert_eq!(
            masque_base & BITS_ECRITURE,
            0,
            "le repertoire du resolveur ne doit pas etre modifiable par le compte: masque cumule 0x{masque_base:08x}"
        );
        // L'etat, lui, est inscriptible. Falsifiable: l'ouvrir en lecture
        // seule retire ce bit.
        assert_ne!(
            masque_etat & FILE_WRITE_DATA,
            0,
            "l'etat doit etre inscriptible par le compte: masque cumule 0x{masque_etat:08x}"
        );
        // Ecart 4: l'etat porte DELETE (renommage du cache temporaire de
        // dnscrypt-proxy); le repertoire de configuration et ses fichiers,
        // non (BITS_ECRITURE, qui comprend DELETE, l'a deja garanti).
        assert_ne!(
            masque_etat & DELETE,
            0,
            "l'etat doit accorder DELETE au compte (renommage du cache): masque cumule 0x{masque_etat:08x}"
        );

        // Relance: reconnue sur les deux repertoires, comptes par SID stables.
        let comptes_un = comptes(psid_ls);
        let (rep_re, etat_re) =
            ouvrir_au_compte(&configuration, &etat, Path::new(PROFIL), psid_ls).expect("relance");
        let comptes_deux = comptes(psid_ls);

        let _ = std::fs::remove_dir_all(&base);

        assert_eq!(
            comptes_un, comptes_deux,
            "la relance ne doit pas faire grossir les ACE du SID (repertoire, configuration, etat)"
        );
        assert!(
            !rep_re && !etat_re,
            "la relance doit etre reconnue sur les deux repertoires: ({rep_re}, {etat_re})"
        );
    }

    /// Ecart 3 (13/09/2026): `ouvrir_au_compte` REFUSE le repertoire du profil
    /// et ne pose alors AUCUNE ACE. Sur un vrai repertoire temporaire, avec
    /// une configuration et un sous-repertoire d'etat dedans:
    ///  - avec un `tunnel.toml` a cote de la configuration (critere 1), refus
    ///    par une erreur qui nomme le profil, et compte d'ACE du SID a zero
    ///    sur les trois objets apres coup;
    ///  - sans `tunnel.toml` mais avec un chemin de profil dont le parent est
    ///    ce repertoire (critere 2), meme refus, memes zeros;
    ///  - sans `tunnel.toml` et avec un profil ailleurs, la pose est acceptee
    ///    (`(true, true)`).
    ///
    /// Falsifiable: retirer la verification de `repertoire_du_resolveur` rend
    /// `Ok` au premier cas et pose des ACE.
    #[cfg(windows)]
    #[test]
    fn ouvrir_au_compte_refuse_le_repertoire_du_profil() {
        let base = std::env::temp_dir().join(format!("bifrost_profil_{}", std::process::id()));
        let etat = base.join("etat");
        let configuration = base.join("dnscrypt-proxy.toml");
        let profil_ici = base.join("tunnel.toml");
        std::fs::create_dir_all(&etat).expect("repertoires jetables");
        std::fs::write(&configuration, b"# temoin").expect("fichier jetable");
        std::fs::write(&profil_ici, b"# faux profil").expect("faux profil jetable");
        let ailleurs = std::env::temp_dir().join(format!(
            "bifrost_profil_ailleurs_{}/tunnel.toml",
            std::process::id()
        ));

        let ls = sid_binaire("LocalService").expect("SID de LocalService sur dev-windows");
        let psid_ls = ls.as_ptr() as *mut core::ffi::c_void;
        let objets = [&base, &configuration, &etat];
        let comptes = || objets.map(|chemin| compte_ace_pour_sid_chemin(chemin, psid_ls));

        // Critere 1: un tunnel.toml dans le repertoire, profil declare ailleurs.
        let refus = ouvrir_au_compte(&configuration, &etat, &ailleurs, psid_ls);
        let message = match refus {
            Err(e) => e.to_string(),
            Ok(pose) => panic!("un repertoire portant tunnel.toml doit etre refuse, pose {pose:?}"),
        };
        assert!(
            message.contains("profil") && message.contains("cle privee"),
            "le refus doit dire ce qui est refuse et pourquoi: {message}"
        );
        assert_eq!(
            comptes(),
            [0, 0, 0],
            "un refus ne doit laisser AUCUNE ACE du SID (repertoire, configuration, etat)"
        );

        // Critere 2: plus de tunnel.toml, mais le profil declare vit ICI.
        std::fs::remove_file(&profil_ici).expect("retrait du faux profil");
        let refus = ouvrir_au_compte(&configuration, &etat, &base.join("autre-nom.toml"), psid_ls);
        assert!(
            refus.is_err(),
            "le parent du chemin de profil connu doit etre refuse meme sans tunnel.toml"
        );
        assert_eq!(
            comptes(),
            [0, 0, 0],
            "un refus (critere 2) ne doit laisser AUCUNE ACE du SID"
        );

        // Sans profil ici ni declare ici: accepte, et les ACE sont posees.
        let pose = ouvrir_au_compte(&configuration, &etat, &ailleurs, psid_ls);
        let apres = comptes();
        let _ = std::fs::remove_dir_all(&base);
        assert_eq!(
            pose.expect("sans profil, la pose doit etre acceptee"),
            (true, true),
            "la premiere pose acceptee doit ecrire sur le repertoire et sur l'etat"
        );
        assert!(
            apres.iter().all(|n| *n >= 1),
            "apres une pose acceptee, les trois objets portent le SID: {apres:?}"
        );
    }
}
