//! Cycle de vie d'un coeur tiers: le lancer, attendre qu'il reponde, l'arreter.
//!
//! Un point domine tout le module: **le coeur ne doit jamais survivre au
//! daemon**. Un sing-box orphelin garde son ecoute SOCKS locale ouverte, donc
//! une sortie que plus personne ne supervise et que le kill switch ne connait
//! pas. Le tuer depuis le code d'arret ne suffit pas: si le daemon est tue par
//! SIGKILL, ou s'effondre, ce code ne tourne pas.
//!
//! La garantie est donc demandee au systeme, avant tout code de nettoyage.
//! Sous Linux, `PR_SET_PDEATHSIG` fait envoyer un signal a l'enfant quand son
//! parent meurt. Sous Windows, un objet Job portant
//! `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` tue ses membres des que la derniere
//! poignee du Job se ferme, ce que la mort du processus fait toujours.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bifrost_evasion::Coeur;
use tokio::io::AsyncReadExt;
use tokio::process::{Child, Command};

use super::clash;
use super::lancement::{Lancement, binaire_present};

/// Budget d'attente de la disponibilite de l'API.
pub const BUDGET_DEMARRAGE: Duration = Duration::from_secs(10);

/// Delai laisse a un coeur pour s'arreter de lui-meme avant d'etre tue.
pub const DELAI_ARRET_DOUX: Duration = Duration::from_secs(3);

/// Taille du journal d'erreur conserve par coeur.
///
/// La sortie d'erreur est drainee en CONTINU et non a la demande: un tuyau que
/// personne ne lit finit par se remplir, et le coeur se bloquerait alors en
/// ecrivant dedans. La borne evite qu'un coeur bavard fasse enfler la memoire
/// du daemon; on garde la fin, parce que la derniere ligne porte la cause.
pub const TAILLE_JOURNAL_ERREUR: usize = 8 * 1024;

/// Delai laisse au drain pour rattraper les derniers octets apres la mort du
/// coeur. Sans lui, on lirait un journal vide sur le chemin d'echec, ce qui est
/// exactement le moment ou il sert.
const RATTRAPAGE_DRAIN: Duration = Duration::from_millis(150);

/// Ce que le coeur a ecrit sur sa sortie d'erreur, borne et partageable.
///
/// Sans ce journal, un coeur qui refuse sa configuration ne laisse qu'un
/// "s'est arrete avant de repondre": le diagnostic reel est dans son stderr, et
/// le perdre oblige a rejouer la panne a la main.
#[derive(Clone, Default)]
pub struct JournalErreur(Arc<Mutex<String>>);

impl JournalErreur {
    fn pousser(&self, morceau: &str) {
        // `into_inner` sur un verrou empoisonne: un journal de diagnostic ne
        // doit jamais etre la raison pour laquelle le daemon panique.
        let mut j = self.0.lock().unwrap_or_else(|e| e.into_inner());
        j.push_str(morceau);
        if j.len() > TAILLE_JOURNAL_ERREUR {
            let cible = j.len() - TAILLE_JOURNAL_ERREUR;
            // Couper au milieu d'un caractere multi-octet ferait paniquer
            // `String`: on avance jusqu'a la premiere frontiere valide.
            let coupe = (cible..j.len())
                .find(|i| j.is_char_boundary(*i))
                .unwrap_or_else(|| j.len());
            j.drain(..coupe);
        }
    }

    /// Les `n` dernieres lignes non vides, sur une seule ligne.
    ///
    /// Sans couleur: ce texte part dans un message d'erreur que quelqu'un lit,
    /// et un coeur colore sans jamais regarder ou il ecrit. Voir
    /// [`sans_couleur`] pour ce que la mesure a etabli.
    pub fn dernieres_lignes(&self, n: usize) -> String {
        let j = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let lignes: Vec<&str> = j.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
        lignes[lignes.len().saturating_sub(n)..]
            .iter()
            .map(|l| sans_couleur(l).into_owned())
            .collect::<Vec<_>>()
            .join(" | ")
    }

    pub fn est_vide(&self) -> bool {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .trim()
            .is_empty()
    }
}

/// Taille au-dela de laquelle un morceau sans fin de ligne est dit quand meme.
///
/// Un coeur qui ecrirait sans jamais retourner a la ligne serait autrement a la
/// fois muet et sans borne dans ce tampon.
const LIGNE_MAX: usize = 2 * 1024;

/// Recompose des lignes entieres a partir de lectures de taille arbitraire.
///
/// Une lecture de 4096 octets coupe ou elle tombe: elle peut porter trois
/// lignes et le debut d'une quatrieme. Dire les morceaux tels quels donnerait
/// un journal ou une cause se lit en deux fois, a deux endroits.
#[derive(Default)]
struct Decoupeur {
    residu: String,
}

impl Decoupeur {
    /// Les lignes ENTIERES que ce morceau vient de completer.
    fn avaler(&mut self, morceau: &str) -> Vec<String> {
        self.residu.push_str(morceau);
        let mut lignes = Vec::new();
        while let Some(i) = self.residu.find('\n') {
            let ligne: String = self.residu.drain(..=i).collect();
            let ligne = ligne.trim().to_string();
            if !ligne.is_empty() {
                lignes.push(ligne);
            }
        }
        if self.residu.len() >= LIGNE_MAX {
            let ligne = std::mem::take(&mut self.residu).trim().to_string();
            if !ligne.is_empty() {
                lignes.push(ligne);
            }
        }
        lignes
    }

    /// Ce qui reste quand le flux se ferme.
    ///
    /// La derniere ligne d'un coeur qui meurt n'a souvent pas eu le temps de
    /// porter son retour a la ligne, et c'est justement celle qui dit pourquoi.
    fn reste(&mut self) -> Option<String> {
        let ligne = std::mem::take(&mut self.residu).trim().to_string();
        (!ligne.is_empty()).then_some(ligne)
    }
}

/// Retire le secret de l'API de controle d'une ligne avant de la dire.
///
/// Le `Debug` de [`CoeurEnCours`] est ecrit a la main pour cette raison exacte:
/// le secret ne doit pas atterrir dans un journal. Faire parler la sortie
/// d'erreur du coeur rouvre la meme porte par l'autre cote - le coeur connait
/// ce secret, il l'a dans sa configuration, et rien ne garantit qu'il ne le
/// recopiera pas dans un message d'erreur sur son propre ecouteur d'API.
///
/// Le remplacement est fait sur la ligne SORTANTE seulement. Le journal borne
/// que lit [`CoeurEnCours::diagnostic`] garde le texte brut: il ne quitte le
/// processus que dans un message d'erreur que l'appelant a demande, et le
/// caviarder la aussi couterait une copie a chaque lecture pour la meme
/// propriete.
fn caviarder(ligne: &str, secret: &str) -> String {
    if secret.is_empty() {
        return ligne.to_string();
    }
    ligne.replace(secret, "(masque)")
}

/// Draine la sortie d'erreur d'un coeur dans un journal borne, ET LA DIT.
///
/// # Pourquoi elle se dit, depuis le 21 aout 2026
///
/// Le journal borne ne sert qu'a `diagnostic()`, qui n'est appele que sur le
/// chemin d'echec au DEMARRAGE. Un coeur qui demarre bien puis refuse chaque
/// relais se plaignait donc dans le vide: la seule facon de l'entendre etait de
/// relancer la panne sous `--coeur-e2e`, qui affiche ce flux. Les deux usages
/// ne s'excluent pas, et le drain est le seul endroit qui voit tout passer.
///
/// # Pourquoi `warn` et pas `debug`
///
/// Ce n'est pas un reglage de gout: c'est NOUS qui ecrivons la configuration du
/// coeur, et nous l'ecrivons a `warn` (sing-box) et `warning` (xray) - voir
/// [`super::configuration`]. Tout ce qui sort de ce tuyau est donc deja, par
/// construction, un avertissement ou pire. Le mettre a `debug` le rendrait
/// invisible sous le filtre par defaut du daemon, `bifrost_daemon=info`,
/// c'est-a-dire ne corrigerait rien.
///
/// Le couplage est reel et vaut d'etre nomme: quiconque monte le niveau du
/// coeur dans `configuration.rs` transforme ce `warn` en deluge.
fn drainer<F>(flux: F, coeur: Coeur, secret: &str) -> JournalErreur
where
    F: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    let journal = JournalErreur::default();
    tokio::spawn(drainer_dans(
        flux,
        journal.clone(),
        coeur,
        secret.to_string(),
    ));
    journal
}

/// La boucle de [`drainer`], sans le `spawn`, pour qu'une recette la conduise.
async fn drainer_dans<F>(mut flux: F, journal: JournalErreur, coeur: Coeur, secret: String)
where
    F: tokio::io::AsyncRead + Unpin,
{
    let mut tampon = [0u8; 4096];
    let mut decoupeur = Decoupeur::default();
    loop {
        let n = match flux.read(&mut tampon).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        // `from_utf8_lossy` peut abimer un caractere a cheval sur deux
        // lectures. C'est acceptable pour un journal de diagnostic, et c'est le
        // seul choix qui ne peut pas paniquer.
        let morceau = String::from_utf8_lossy(&tampon[..n]);
        journal.pousser(&morceau);
        for ligne in decoupeur.avaler(&morceau) {
            dire(coeur, &ligne, &secret);
        }
    }
    if let Some(ligne) = decoupeur.reste() {
        dire(coeur, &ligne, &secret);
    }
}

/// Retire les sequences de couleur d'un texte.
///
/// # Pourquoi ce n'est pas au coeur de s'en abstenir
///
/// Mesure du 21 aout 2026 contre sing-box 1.13.18, celui du banc:
///
/// - `log.disable_color` n'existe pas. La cle est REFUSEE - `json: unknown
///   field "disable_color"` - et la configuration entiere avec elle, donc
///   l'ajouter empecherait tout coeur de demarrer;
/// - `NO_COLOR=1` et `TERM=dumb` ne changent rien: quatre sequences dans les
///   deux cas, comme sans rien.
///
/// Il colore meme en ecrivant dans un fichier redirige, et meme un FATAL. La
/// seule place ou cela se corrige est donc ici. Le depot tient deja la meme
/// propriete pour sa propre sortie - voir `init_tracing`, "un journal dont
/// chaque ligne porte des sequences d'echappement qu'aucun `grep` ne veut" -
/// et ce serait la rouvrir que d'y verser celles d'un tiers.
///
/// # Toujours sur une ligne ENTIERE
///
/// Une sequence coupee entre deux lectures n'a pas d'octet final, et serait
/// alors jetee a moitie. Les deux appelants ne passent que des lignes
/// recomposees, ou une sequence est forcement complete.
fn sans_couleur(texte: &str) -> std::borrow::Cow<'_, str> {
    if !texte.contains('\u{1b}') {
        return std::borrow::Cow::Borrowed(texte);
    }
    let mut propre = String::with_capacity(texte.len());
    let mut restant = texte;
    while let Some(i) = restant.find('\u{1b}') {
        propre.push_str(&restant[..i]);
        let suite = &restant[i..];
        let mut octets = suite.char_indices().skip(1);
        // CSI: ESC, crochet, parametres, puis un octet final de 0x40 a 0x7E.
        if let Some((_, '[')) = octets.next() {
            match octets.find(|(_, c)| ('\u{40}'..='\u{7e}').contains(c)) {
                Some((j, c)) => restant = &suite[j + c.len_utf8()..],
                None => restant = "",
            }
        } else {
            // Un ESC isole, ou une sequence d'une autre famille: on jette le
            // seul octet invisible et on garde le reste tel quel.
            restant = &suite[1..];
        }
    }
    propre.push_str(restant);
    std::borrow::Cow::Owned(propre)
}

fn dire(coeur: Coeur, ligne: &str, secret: &str) {
    tracing::warn!(
        coeur = coeur.executable(),
        ligne = %caviarder(&sans_couleur(ligne), secret),
        "le coeur se plaint"
    );
}

/// Un coeur en cours d'execution.
///
/// Le `Debug` est ecrit a la main plus bas: le derive afficherait le secret de
/// l'API de controle des qu'une erreur serait journalisee.
pub struct CoeurEnCours {
    pub coeur: Coeur,
    enfant: Child,
    api: Option<SocketAddr>,
    secret: String,
    journal: JournalErreur,
    /// Sous Windows, la poignee du Job doit vivre aussi longtemps que le
    /// superviseur: c'est sa fermeture qui tue le coeur.
    #[cfg(windows)]
    _job: job::Job,
}

impl std::fmt::Debug for CoeurEnCours {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CoeurEnCours")
            .field("coeur", &self.coeur)
            .field("pid", &self.enfant.id())
            .field("api", &self.api)
            .field("secret", &"(masque)")
            .finish()
    }
}

impl CoeurEnCours {
    pub fn pid(&self) -> Option<u32> {
        self.enfant.id()
    }

    pub fn api(&self) -> Option<SocketAddr> {
        self.api
    }

    /// Ce que le coeur a dit sur sa sortie d'erreur, pret a etre affiche.
    ///
    /// Chaine vide s'il n'a rien dit: mieux vaut ne rien ajouter au message
    /// d'erreur que d'y coller un diagnostic creux.
    pub async fn diagnostic(&self) -> String {
        tokio::time::sleep(RATTRAPAGE_DRAIN).await;
        if self.journal.est_vide() {
            return String::new();
        }
        format!(
            "sortie d'erreur de {}: {}",
            self.coeur.executable(),
            self.journal.dernieres_lignes(3)
        )
    }

    /// Bascule le selecteur du coeur vers une sortie.
    pub async fn choisir(&self, selecteur: &str, sortie: &str) -> anyhow::Result<()> {
        let api = self
            .api
            .ok_or_else(|| anyhow::anyhow!("{:?} n'expose pas d'API Clash", self.coeur))?;
        clash::choisir(api, &self.secret, selecteur, sortie).await
    }

    /// Bascule le selecteur ET VERIFIE que la sortie a change.
    ///
    /// La difference avec [`Self::choisir`] est toute la difference: un 204 dit
    /// que le coeur a accepte la requete, pas qu'il sert autre chose.
    ///
    /// C'est le MEME code que celui du superviseur de tunnel en production -
    /// [`crate::coeurs::bascule::basculer`] - et c'est le point. La sequence
    /// "demander, relire, comparer" etait ecrite ici et la-bas; deux copies
    /// d'une meme politique divergent un jour, et celle-la decide si un tunnel
    /// gele change vraiment de sortie. En la partageant, ce que
    /// `--coeur-selftest` mesure contre un vrai binaire est exactement ce qui
    /// tourne quand un candidat lache en cours de session.
    pub async fn basculer(
        &self,
        selecteur: &str,
        sortie: &str,
    ) -> anyhow::Result<crate::coeurs::bascule::Issue> {
        let api = self
            .api
            .ok_or_else(|| anyhow::anyhow!("{:?} n'expose pas d'API Clash", self.coeur))?;
        Ok(crate::coeurs::bascule::basculer(
            &crate::coeurs::vitalite::Adresse {
                api,
                secret: self.secret.clone(),
                selecteur: selecteur.to_owned(),
            },
            sortie,
        )
        .await)
    }

    /// Lit la sortie active d'un selecteur.
    pub async fn selection(&self, selecteur: &str) -> anyhow::Result<String> {
        let api = self
            .api
            .ok_or_else(|| anyhow::anyhow!("{:?} n'expose pas d'API Clash", self.coeur))?;
        clash::lire_selection(api, &self.secret, selecteur).await
    }

    /// Attend que ce coeur meure de lui-meme, et decrit sa mort.
    ///
    /// # Pourquoi attendre plutot qu'interroger
    ///
    /// La question "ce coeur est-il vivant" n'a pas d'autre reponse fiable. Le
    /// scruter periodiquement laisserait une fenetre ou il est mort et ou le
    /// tunnel se croit vivant, exactement le defaut que cette fonction existe
    /// pour fermer. Et l'API Clash n'aide pas: sing-box n'expose aucun point
    /// de vitalite - `/proxies/<tag>/delay` mesure la latence d'une SORTIE, pas
    /// la sante du coeur, et la demande d'un vrai healthcheck est encore
    /// ouverte a l'amont (SagerNet/sing-box#1494, verifie le 19/08/2026). La
    /// mort du processus est donc le seul signal qui ne ment pas, et c'est
    /// aussi celui que les lanceurs en circulation surveillent.
    ///
    /// Emprunte `&mut self` sans consommer: l'appelant garde le coeur pour
    /// pouvoir l'arreter proprement, meme si le processus est deja parti - il
    /// reste a reaper, et sous Windows le Job reste a fermer.
    pub async fn attendre_la_fin(&mut self) -> String {
        let issue = self.enfant.wait().await;
        let mort = match issue {
            Ok(statut) => match statut.code() {
                Some(code) => format!("{} s'est arrete (code {code})", self.coeur.executable()),
                None => format!("{} a ete tue par un signal", self.coeur.executable()),
            },
            Err(e) => format!(
                "{} a disparu et son sort est illisible: {e}",
                self.coeur.executable()
            ),
        };
        // Ce que le coeur a dit en mourant vaut plus que le code de sortie: un
        // `exit 1` muet enverrait chercher la panne partout.
        let dit = self.diagnostic().await;
        if dit.is_empty() {
            mort
        } else {
            format!("{mort}. {dit}")
        }
    }

    /// Arrete le coeur: poliment d'abord, fermement ensuite.
    ///
    /// Consomme le superviseur, parce qu'un coeur arrete ne doit pas pouvoir
    /// etre repilote: les appels suivants viseraient un port que quelqu'un
    /// d'autre a pu reprendre entre-temps.
    pub async fn arreter(mut self) -> anyhow::Result<()> {
        #[cfg(unix)]
        if let Some(pid) = self.enfant.id() {
            // SIGTERM laisse au coeur le temps de fermer ses ecoutes. `kill`
            // sur un PID deja disparu rend une erreur qu'on ignore: la course
            // est normale, l'enfant a pu sortir tout seul.
            // SAFETY: kill(pid, SIGTERM) ne touche aucune memoire; une erreur sur un PID
            // deja disparu est ignoree, la course est normale.
            unsafe {
                libc::kill(pid as libc::pid_t, libc::SIGTERM);
            }
            if tokio::time::timeout(DELAI_ARRET_DOUX, self.enfant.wait())
                .await
                .is_ok()
            {
                return Ok(());
            }
        }
        self.enfant.kill().await?;
        self.enfant.wait().await?;
        Ok(())
    }
}

/// Lance un coeur et attend qu'il reponde.
///
/// Le secret est passe par la configuration deja ecrite, pas par la ligne de
/// commande: les arguments d'un processus sont lisibles par tout le monde dans
/// `/proc` comme dans le gestionnaire de taches.
pub async fn demarrer(
    coeur: Coeur,
    lancement: &Lancement,
    secret: &str,
) -> anyhow::Result<CoeurEnCours> {
    if !binaire_present(lancement) {
        anyhow::bail!(
            "{} introuvable a {}: installer le coeur ou corriger le repertoire",
            coeur.executable(),
            lancement.programme.display()
        );
    }

    let mut commande = Command::new(&lancement.programme);
    commande
        .args(&lancement.arguments)
        .kill_on_drop(true)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped());

    // Baisse de privilege, quand un compte dedie est prevu.
    //
    // L'ordre compte: le groupe AVANT l'utilisateur, faute de quoi le
    // `setgid` se ferait apres la perte de root et echouerait. La
    // bibliotheque standard s'en charge, mais le fait de le savoir explique
    // pourquoi les deux valeurs voyagent ensemble.
    //
    // La configuration porte des secrets et vit en 0600. Un coeur qui tourne
    // sous un autre compte ne peut donc plus la lire: on lui en donne la
    // PROPRIETE plutot que d'elargir le mode, ce qui la rendrait lisible par
    // toute la machine. C'est fait ici, et pas au moment de l'ecriture, pour
    // qu'aucun appelant ne puisse l'oublier: qui pose un compte donne l'acces.
    #[cfg(unix)]
    if let Some(u) = lancement.utilisateur {
        std::os::unix::fs::chown(&lancement.configuration, Some(u.uid), Some(u.gid)).map_err(
            |e| {
                anyhow::anyhow!(
                    "donner {} au compte {}:{}: {e}",
                    lancement.configuration.display(),
                    u.uid,
                    u.gid
                )
            },
        )?;
        commande.gid(u.gid).uid(u.uid);
    }

    // SAFETY: pre_exec exige une fermeture async-signal-safe, executee dans
    // l'enfant entre fork et exec. Celle-ci n'appelle que prctl et getppid, toutes
    // deux async-signal-safe, et n'alloue rien.
    #[cfg(target_os = "linux")]
    unsafe {
        use std::io::Error;
        commande.pre_exec(|| {
            // Demande au noyau de signaler l'enfant quand son parent meurt.
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) != 0 {
                return Err(Error::last_os_error());
            }
            // La course connue de PR_SET_PDEATHSIG: si le parent est mort
            // ENTRE le fork et le prctl, le signal ne partira jamais et
            // l'enfant serait orphelin des sa naissance. On verifie donc
            // apres coup qu'on a toujours un vrai parent.
            if libc::getppid() == 1 {
                return Err(Error::other(
                    "parent disparu avant l'armement de PR_SET_PDEATHSIG",
                ));
            }
            Ok(())
        });
    }

    let mut enfant = commande
        .spawn()
        .map_err(|e| anyhow::anyhow!("lancement de {}: {e}", lancement.programme.display()))?;

    #[cfg(windows)]
    let _job = job::attacher(&enfant)?;

    // Pris tout de suite: le drain doit tourner avant meme l'attente de l'API,
    // sinon un coeur qui se plaint abondamment remplit le tuyau et se bloque.
    let journal = enfant
        .stderr
        .take()
        .map(|flux| drainer(flux, coeur, secret))
        .unwrap_or_default();

    let mut en_cours = CoeurEnCours {
        coeur,
        enfant,
        api: lancement
            .api_clash
            .map(|p| SocketAddr::from(([127, 0, 0, 1], p))),
        secret: secret.to_string(),
        journal,
        #[cfg(windows)]
        _job,
    };

    let resultat = match en_cours.api {
        Some(api) => attendre_api(&mut en_cours, api).await,
        None => sursis_sans_api(&mut en_cours).await,
    };
    match resultat {
        Ok(()) => Ok(en_cours),
        Err(e) => match en_cours.diagnostic().await {
            d if d.is_empty() => Err(e),
            d => Err(anyhow::anyhow!("{e}; {d}")),
        },
    }
}

/// Delai pendant lequel un coeur sans API doit rester en vie pour etre
/// considere demarre.
pub const SURSIS_SANS_API: Duration = Duration::from_millis(750);

/// Verifie qu'un coeur sans API Clash n'est pas simplement mort a la naissance.
///
/// Faute de signal de disponibilite, la garantie est plus faible que sur le
/// chemin API et il faut le dire: on sait seulement que le processus a survecu
/// un instant, pas qu'il est fonctionnel. Sans cette verification, `demarrer`
/// rendrait un succes pour un coeur dont la configuration est refusee, et
/// l'erreur ne remonterait qu'a la premiere tentative de trafic.
async fn sursis_sans_api(en_cours: &mut CoeurEnCours) -> anyhow::Result<()> {
    let coeur = en_cours.coeur;
    match tokio::time::timeout(SURSIS_SANS_API, en_cours.enfant.wait()).await {
        // Il est sorti pendant le sursis: c'est un echec de demarrage.
        Ok(statut) => {
            let statut = statut?;
            anyhow::bail!(
                "{} s'est arrete {SURSIS_SANS_API:?} apres son lancement (statut {statut})",
                coeur.executable()
            )
        }
        // Toujours la au bout du sursis: c'est tout ce qu'on peut affirmer.
        Err(_) => Ok(()),
    }
}

/// Attend que l'API reponde, sans jamais attendre un processus deja mort.
///
/// Sonder pendant dix secondes un port que plus personne n'ecoute est le
/// mauvais mode d'echec: le vrai diagnostic est la sortie d'erreur du coeur, et
/// elle est perdue si on attend l'echeance.
async fn attendre_api(en_cours: &mut CoeurEnCours, api: SocketAddr) -> anyhow::Result<()> {
    let secret = en_cours.secret.clone();
    let coeur = en_cours.coeur;

    let sondage = async {
        loop {
            match clash::interroger_version(api, &secret).await {
                Ok(v) => return Ok(v),
                // Un refus d'autorisation ne se resorbera pas avec le temps.
                Err(e) if format!("{e}").contains("refuse le secret") => return Err(e),
                Err(_) => tokio::time::sleep(clash::PAS_DE_SONDAGE).await,
            }
        }
    };

    let resultat = tokio::select! {
        statut = en_cours.enfant.wait() => {
            let statut = statut?;
            anyhow::bail!("{} s'est arrete avant de repondre (statut {statut})", coeur.executable());
        }
        v = tokio::time::timeout(BUDGET_DEMARRAGE, sondage) => v,
    };

    match resultat {
        Ok(Ok(version)) => {
            tracing::info!(coeur = coeur.executable(), version, "coeur pret");
            Ok(())
        }
        Ok(Err(e)) => Err(e),
        Err(_) => anyhow::bail!(
            "{} n'a pas repondu sur son API Clash en {BUDGET_DEMARRAGE:?}",
            coeur.executable()
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn un_journal_vide_ne_dit_rien() {
        let j = JournalErreur::default();
        assert!(j.est_vide());
        assert_eq!(j.dernieres_lignes(3), "");
        j.pousser("   \n\n");
        assert!(j.est_vide(), "des blancs ne sont pas un diagnostic");
    }

    #[test]
    fn on_garde_la_fin_et_non_le_debut() {
        // La cause d'un echec est dans la derniere ligne, pas la premiere.
        let j = JournalErreur::default();
        for i in 0..500 {
            j.pousser(&format!("ligne de remplissage numero {i}\n"));
        }
        j.pousser("FATAL: configuration refusee\n");
        assert_eq!(j.dernieres_lignes(1), "FATAL: configuration refusee");
    }

    #[test]
    fn le_journal_reste_borne() {
        let j = JournalErreur::default();
        for _ in 0..1000 {
            j.pousser(&"x".repeat(100));
        }
        let taille = j.0.lock().unwrap().len();
        assert!(
            taille <= TAILLE_JOURNAL_ERREUR,
            "journal non borne: {taille} octets"
        );
    }

    #[test]
    fn couper_au_milieu_d_un_caractere_ne_panique_pas() {
        // Le point du test: un caractere accentue tient sur deux octets,
        // donc la coupe tombe fatalement entre les deux a un moment ou un
        // autre. La chaine ci-dessous est volontairement multi-octets:
        // c'est l'une des deux exceptions nommees de la garde de source
        // tests/sources_ascii.rs, et elle doit rester telle quelle.
        let j = JournalErreur::default();
        for _ in 0..2000 {
            j.pousser("éàü");
        }
        assert!(!j.est_vide());
        assert!(j.0.lock().unwrap().len() <= TAILLE_JOURNAL_ERREUR);
    }

    /// Un carnet qui retient ce que `tracing` ecrit, pour lire ce qu'un
    /// journal de service aurait recu.
    #[derive(Clone, Default)]
    struct Carnet(Arc<Mutex<Vec<u8>>>);

    impl Carnet {
        fn texte(&self) -> String {
            String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
        }
    }

    impl std::io::Write for Carnet {
        fn write(&mut self, tampon: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(tampon);
            Ok(tampon.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl tracing_subscriber::fmt::MakeWriter<'_> for Carnet {
        type Writer = Carnet;
        fn make_writer(&self) -> Carnet {
            self.clone()
        }
    }

    /// Installe le carnet POUR CE FIL.
    ///
    /// `set_default` est thread-local, et `#[tokio::test]` tourne sur un
    /// runtime mono-fil: le futur du drain reste donc sur ce fil et voit
    /// l'abonne. C'est aussi pourquoi la recette conduit `drainer_dans`
    /// elle-meme au lieu de passer par `drainer`, qui `spawn`.
    fn ecouter() -> (Carnet, tracing::subscriber::DefaultGuard) {
        let carnet = Carnet::default();
        let abonne = tracing_subscriber::fmt()
            .with_writer(carnet.clone())
            .with_max_level(tracing::Level::WARN)
            .with_ansi(false)
            .finish();
        (carnet.clone(), tracing::subscriber::set_default(abonne))
    }

    /// # Le defaut que cette recette tient
    ///
    /// Jusqu'au 21 aout 2026, un coeur qui demarrait bien puis refusait chaque
    /// relais se plaignait dans le vide: sa sortie d'erreur allait dans un
    /// tampon borne que seul le chemin d'echec au DEMARRAGE relisait. La seule
    /// facon de l'entendre etait de rejouer la panne sous `--coeur-e2e`.
    #[tokio::test]
    async fn ce_que_le_coeur_dit_apres_son_demarrage_arrive_dans_le_journal() {
        let (carnet, _garde) = ecouter();
        let (mut ecrivain, lecteur) = tokio::io::duplex(256);
        let journal = JournalErreur::default();
        let drain = drainer_dans(lecteur, journal.clone(), Coeur::SingBox, "s3cr3t".into());

        tokio::io::AsyncWriteExt::write_all(&mut ecrivain, b"FATAL: relais refuse\n")
            .await
            .unwrap();
        drop(ecrivain);
        drain.await;

        let vu = carnet.texte();
        assert!(
            vu.contains("FATAL: relais refuse"),
            "rien n'est sorti: {vu}"
        );
        assert!(
            vu.contains("sing-box"),
            "la ligne ne dit pas de qui elle vient: {vu}"
        );
        assert!(
            !journal.est_vide(),
            "le tampon que relit diagnostic() doit rester rempli"
        );
    }

    /// Le secret de l'API ne sort jamais, meme si le coeur le recopie.
    ///
    /// Le `Debug` de `CoeurEnCours` est masque a la main pour cette raison; y
    /// brancher la sortie d'erreur du coeur rouvrirait la porte par l'autre
    /// cote, le coeur ayant ce secret dans sa configuration.
    #[tokio::test]
    async fn le_secret_de_l_api_ne_sort_jamais_dans_le_journal() {
        let (carnet, _garde) = ecouter();
        let (mut ecrivain, lecteur) = tokio::io::duplex(256);
        let drain = drainer_dans(
            lecteur,
            JournalErreur::default(),
            Coeur::SingBox,
            "abracadabra".into(),
        );

        tokio::io::AsyncWriteExt::write_all(
            &mut ecrivain,
            b"erreur: ecoute API refusee, secret=abracadabra\n",
        )
        .await
        .unwrap();
        drop(ecrivain);
        drain.await;

        let vu = carnet.texte();
        assert!(
            !vu.contains("abracadabra"),
            "le secret est sorti en clair: {vu}"
        );
        assert!(
            vu.contains("(masque)"),
            "la ligne devait sortir, caviardee: {vu}"
        );
    }

    /// La derniere ligne d'un coeur qui meurt n'a pas de retour a la ligne.
    ///
    /// Et c'est justement celle qui dit pourquoi il est mort.
    #[tokio::test]
    async fn la_derniere_ligne_sort_meme_sans_retour_a_la_ligne() {
        let (carnet, _garde) = ecouter();
        let (mut ecrivain, lecteur) = tokio::io::duplex(256);
        let drain = drainer_dans(
            lecteur,
            JournalErreur::default(),
            Coeur::XrayCore,
            String::new(),
        );

        tokio::io::AsyncWriteExt::write_all(&mut ecrivain, b"panic: adresse deja prise")
            .await
            .unwrap();
        drop(ecrivain);
        drain.await;

        assert!(
            carnet.texte().contains("panic: adresse deja prise"),
            "la derniere ligne a ete perdue: {}",
            carnet.texte()
        );
    }

    /// Une plainte de sing-box, telle qu'elle sort vraiment.
    ///
    /// Relevee le 21 aout 2026 sur essai-windows, sing-box 1.13.18 configure a
    /// `warn`, sortie redirigee dans un fichier: la couleur est la quand meme.
    const PLAINTE_REELLE: &str = concat!(
        "\u{1b}",
        "[31mERROR",
        "\u{1b}",
        "[0m[0002] [",
        "\u{1b}",
        "[38;5;194m2181161906",
        "\u{1b}",
        "[0m 1ms] connection: open connection to example.com:80 using outbound/socks[sortie]",
    );

    #[test]
    fn les_couleurs_d_un_coeur_ne_survivent_pas_au_journal() {
        let propre = sans_couleur(PLAINTE_REELLE);
        assert!(
            !propre.contains('\u{1b}'),
            "il reste des sequences: {propre}"
        );
        assert!(
            propre.starts_with("ERROR[0002] [2181161906 1ms] connection: open connection"),
            "le texte a ete abime: {propre}"
        );
        // Un texte sans couleur ne paie pas de copie.
        assert!(matches!(
            sans_couleur("rien a retirer"),
            std::borrow::Cow::Borrowed(_)
        ));
    }

    #[test]
    fn une_sequence_tronquee_ne_mange_pas_la_suite_du_texte() {
        // Le cas est theorique - les appelants ne passent que des lignes
        // entieres - mais un ESC isole ne doit pas faire disparaitre une ligne.
        assert_eq!(
            sans_couleur(concat!("avant", "\u{1b}", "apres")).as_ref(),
            "avantapres"
        );
        assert_eq!(
            sans_couleur(concat!("avant", "\u{1b}", "[31")).as_ref(),
            "avant"
        );
    }

    /// La sortie du coeur arrive dans le journal du daemon SANS couleur.
    #[tokio::test]
    async fn le_journal_du_daemon_ne_recoit_pas_les_couleurs_du_coeur() {
        let (carnet, _garde) = ecouter();
        let (mut ecrivain, lecteur) = tokio::io::duplex(1024);
        let drain = drainer_dans(
            lecteur,
            JournalErreur::default(),
            Coeur::SingBox,
            String::new(),
        );

        let mut ligne = PLAINTE_REELLE.as_bytes().to_vec();
        ligne.push(b'\n');
        tokio::io::AsyncWriteExt::write_all(&mut ecrivain, &ligne)
            .await
            .unwrap();
        drop(ecrivain);
        drain.await;

        let vu = carnet.texte();
        assert!(
            vu.contains("connection: open connection to example.com:80"),
            "la plainte n'est pas sortie: {vu}"
        );
        assert!(
            !vu.contains('\u{1b}'),
            "des sequences d'echappement ont atteint le journal: {vu:?}"
        );
    }

    /// Et le diagnostic non plus: c'est un message que quelqu'un lit.
    #[test]
    fn un_diagnostic_ne_porte_pas_de_sequences_d_echappement() {
        let j = JournalErreur::default();
        j.pousser(PLAINTE_REELLE);
        j.pousser(
            "
",
        );
        let dit = j.dernieres_lignes(1);
        assert!(!dit.contains('\u{1b}'), "diagnostic colore: {dit:?}");
        assert!(
            dit.contains("outbound/socks[sortie]"),
            "diagnostic abime: {dit}"
        );
    }

    #[test]
    fn une_ligne_coupee_entre_deux_lectures_ne_sort_qu_une_fois_entiere() {
        let mut d = Decoupeur::default();
        assert!(
            d.avaler("FATAL: configu").is_empty(),
            "une demi-ligne n'est pas une ligne"
        );
        assert_eq!(
            d.avaler("ration refusee\n"),
            vec!["FATAL: configuration refusee"]
        );
    }

    #[test]
    fn une_lecture_peut_porter_plusieurs_lignes_et_un_debut() {
        let mut d = Decoupeur::default();
        assert_eq!(d.avaler("une\ndeux\ntro"), vec!["une", "deux"]);
        assert_eq!(d.reste().as_deref(), Some("tro"));
        assert_eq!(d.reste(), None, "le reste ne se dit qu'une fois");
    }

    #[test]
    fn une_ligne_interminable_finit_par_sortir() {
        // Sans cette borne, un coeur qui n'ecrit jamais de fin de ligne serait
        // a la fois muet et sans limite de memoire.
        let mut d = Decoupeur::default();
        let long = "x".repeat(LIGNE_MAX + 1);
        assert_eq!(d.avaler(&long), vec![long.clone()]);
        assert_eq!(d.reste(), None);
    }

    #[test]
    fn les_dernieres_lignes_ignorent_les_lignes_vides() {
        let j = JournalErreur::default();
        j.pousser("premiere\n\n  \ndeuxieme\ntroisieme\n");
        assert_eq!(j.dernieres_lignes(2), "deuxieme | troisieme");
        // Demander plus de lignes qu'il n'en existe rend tout, sans paniquer.
        assert_eq!(j.dernieres_lignes(99), "premiere | deuxieme | troisieme");
    }
}

#[cfg(windows)]
mod job {
    //! Objet Job Windows: l'equivalent de PR_SET_PDEATHSIG.
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
        SetInformationJobObject,
    };

    /// Poignee de Job, fermee a la destruction. Cette fermeture est ce qui tue
    /// les processus membres, y compris quand le daemon meurt brutalement:
    /// Windows ferme les poignees d'un processus disparu.
    pub struct Job(HANDLE);

    // SAFETY: `Job` ne detient qu'un HANDLE de job Windows. Les appels qui le
    // manipulent (CloseHandle, AssignProcessToJobObject) sont surs vis-a-vis des
    // threads, donc l'envoyer entre fils est licite.
    unsafe impl Send for Job {}
    // SAFETY: memes raisons; l'acces partage ne fait que passer le HANDLE a ces
    // appels Windows, sans etat interne mutable non protege.
    unsafe impl Sync for Job {}

    impl Drop for Job {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: `self.0` est un HANDLE de job non nul (teste au-dessus); ferme une
                // seule fois a la destruction.
                unsafe { CloseHandle(self.0) };
            }
        }
    }

    pub fn attacher(enfant: &tokio::process::Child) -> anyhow::Result<Job> {
        let poignee_enfant = enfant
            .raw_handle()
            .ok_or_else(|| anyhow::anyhow!("l'enfant n'a plus de poignee"))?;

        // SAFETY: les deux null sont les attributs de securite et le nom, optionnels;
        // CreateJobObjectW rend un HANDLE ou null (teste ensuite).
        let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if job.is_null() {
            anyhow::bail!(
                "CreateJobObject a echoue: {}",
                std::io::Error::last_os_error()
            );
        }
        let job = Job(job);

        // SAFETY: JOBOBJECT_EXTENDED_LIMIT_INFORMATION n'est fait que d'entiers et de
        // structures POD pour lesquels tout-a-zero est une valeur initiale valide.
        let mut limites: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        limites.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        // SAFETY: `job.0` est un HANDLE de job valide; `limites` vit pendant l'appel et
        // la taille passee est exactement celle de la structure pointee.
        let pose = unsafe {
            SetInformationJobObject(
                job.0,
                JobObjectExtendedLimitInformation,
                (&raw const limites).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if pose == 0 {
            anyhow::bail!(
                "SetInformationJobObject a echoue: {}",
                std::io::Error::last_os_error()
            );
        }

        // `raw_handle` rend deja la poignee brute du processus: tokio la tient
        // ouverte tant que le `Child` vit, donc elle est valide ici.
        // SAFETY: `job.0` est un HANDLE de job valide et `poignee_enfant` la poignee
        // brute du processus, tenue ouverte par tokio tant que l'enfant vit.
        let attache = unsafe { AssignProcessToJobObject(job.0, poignee_enfant) };
        if attache == 0 {
            anyhow::bail!(
                "AssignProcessToJobObject a echoue: {}",
                std::io::Error::last_os_error()
            );
        }
        Ok(job)
    }
}
