//! Capture pcap et assertion d'absence de fuite.
//!
//! La capture se fait cote `phys`, sur le veth qui joue la carte reseau. Ce qui
//! y apparait est ce qu'un observateur sur le LAN verrait. L'assertion est
//! ensuite faite en relisant le pcap avec un filtre BPF: tcpdump sait deja
//! decoder, filtrer et afficher, et il est present partout ou ces tests ont un
//! sens.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bifrost_core::{Error, Result};

use super::netns::{Bench, PHYS_ADDR, VETH_PHYS, WG_PORT};

/// Temps maximal accorde a tcpdump pour ouvrir son fichier de sortie.
const ATTACHE_MAX: Duration = Duration::from_secs(5);

/// Taille de l'en-tete d'un fichier pcap.
///
/// Son apparition dit que le processus tcpdump vit et a ouvert sa sortie. Elle
/// ne dit PAS que le filtre est pose: mesure du 16/08/2026, remplacer le delai
/// ci-dessous par cette seule attente rend muets des vecteurs qui passaient,
/// donc tcpdump ecrit cet en-tete avant d'etre reellement a l'ecoute. C'est un
/// signal de vie, pas un signal de disponibilite, et les deux sont necessaires.
const ENTETE_PCAP: u64 = 24;

/// Pas de scrutation de l'en-tete.
const PAS: Duration = Duration::from_millis(20);

/// Delai laisse a tcpdump, une fois son fichier ouvert, pour etre a l'ecoute.
///
/// Il ne remplace pas l'attente ci-dessus, il la complete. Seul, il supposait
/// que le processus demarre en moins de 500 ms; sur une machine occupee cette
/// supposition tombe, la sonde part avant la capture, et le pcap vide se lit
/// comme une absence de fuite. Attendre d'abord la preuve que tcpdump vit
/// enleve du delai la partie qu'il ne pouvait pas garantir.
const WARMUP: Duration = Duration::from_millis(500);

/// Pas de scrutation du vidage.
const VIDAGE_PAS: Duration = Duration::from_millis(25);

/// Duree minimale du vidage, avant meme de regarder si le pcap grossit encore.
///
/// Le dernier paquet d'une sonde peut n'avoir pas encore atteint le veth quand
/// la sonde rend la main; sans ce plancher, un pcap deja calme parce qu'il n'a
/// rien recu serait declare calme aussitot.
const VIDAGE_PLANCHER: Duration = Duration::from_millis(250);

/// Duree pendant laquelle le pcap doit cesser de grossir pour etre dit calme.
const VIDAGE_CALME: Duration = Duration::from_millis(250);

/// Echeance de securite du vidage.
///
/// Dimensionnee pour couvrir un retrait de bloc complet plus une fenetre de
/// calme, de sorte que la perte du mode immediat allonge le vidage au lieu de
/// rendre la mesure fausse. La garde `l_echeance_de_vidage_couvre_un_retrait_de_bloc`
/// tient ce rapport, en le reliant au delai de lecture par defaut de tcpdump.
const VIDAGE_PLAFOND: Duration = Duration::from_millis(3000);

/// Nombre de paquets de preuve rapportes en cas d'echec.
const MAX_EVIDENCE: usize = 20;

pub struct Capture {
    /// `None` une fois la capture arretee. Le `Drop` s'appuie dessus pour ne
    /// pas tuer deux fois, et surtout pour tuer quand personne n'a appele
    /// [`Capture::stop`].
    child: Option<Child>,
    path: PathBuf,
    /// Le nom du vecteur, pour que le refus d'une capture incomplete dise
    /// laquelle.
    tag: String,
}

/// Ce que tcpdump a compte, a chaque etage de la chaine.
///
/// Les trois nombres viennent de la meme ligne d'erreur standard, ecrite par
/// `info()` dans `tcpdump.c`, et ne mesurent pas la meme chose:
///
/// - `remis` est le compteur interne de tcpdump, incremente une fois par paquet
///   effectivement remis a la fonction d'ecriture. C'est ce qui se retrouve
///   dans le pcap.
/// - `vus_par_le_filtre` est `ps_recv`, que `pcap_stats_linux` lit par
///   `getsockopt(PACKET_STATISTICS)`. La source de libpcap le commente ainsi:
///   << "ps_recv" counts only packets that *passed* the filter, not packets
///   that didn't pass the filter. This includes packets later dropped because
///   we ran out of buffer space. >> Le noyau le compte a l'entree de l'anneau,
///   sans savoir si l'application lira un jour.
/// - `jetes_par_le_noyau` est `ps_drop`, deja compris dans le precedent.
///
/// L'ecart entre les deux premiers est donc exactement ce que le noyau a
/// accepte et que personne n'a jamais lu. La page de manuel de `pcap_stats`
/// previent qu'on ne peut pas demander mieux a l'API: << Both ps_recv and
/// ps_drop might, or might not, count packets not yet read from the operating
/// system and thus not yet seen by the application. >> C'est pour cela que
/// l'ecart se mesure par soustraction et non par un compteur dedie.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Comptes {
    pub remis: u64,
    pub vus_par_le_filtre: u64,
    pub jetes_par_le_noyau: u64,
}

impl Comptes {
    /// Lit les trois compteurs dans le compte rendu de tcpdump.
    ///
    /// `None` quand ils n'y sont pas, et ce cas n'est pas theorique: tcpdump
    /// n'ecrit cette ligne que sur le chemin normal de sortie, apres que
    /// `cleanup()` a appele `pcap_breakloop()`. Un tcpdump acheve par SIGKILL
    /// n'imprime rien du tout. Rendre alors des comptes a zero laisserait une
    /// capture jamais lue passer pour une capture vide, ce qui est precisement
    /// la confusion que ce module existe pour empecher.
    pub fn depuis_tcpdump(rapport: &str) -> Option<Self> {
        Some(Self {
            remis: compteur(rapport, "captured")?,
            vus_par_le_filtre: compteur(rapport, "received by filter")?,
            jetes_par_le_noyau: compteur(rapport, "dropped by kernel")?,
        })
    }

    /// Paquets acceptes par le noyau et jamais remis a l'application.
    ///
    /// `jetes_par_le_noyau` n'est pas ajoute: la source de libpcap dit qu'il
    /// est deja compris dans `vus_par_le_filtre`, et l'additionner compterait
    /// deux fois les memes paquets.
    pub fn perdus(&self) -> u64 {
        self.vus_par_le_filtre.saturating_sub(self.remis)
    }
}

/// Extrait le nombre qui precede une etiquette de fin de ligne de tcpdump.
///
/// La comparaison porte sur la FIN du fragment et non sur son contenu: la ligne
/// << 4 packets captured >> et la ligne << 10 packets received by filter >> se
/// distinguent par leur terminaison, et un nom d'interface malheureux ne peut
/// pas se faire passer pour un compteur.
fn compteur(rapport: &str, etiquette: &str) -> Option<u64> {
    rapport
        .split(';')
        .map(str::trim)
        .find(|m| m.ends_with(etiquette))
        .and_then(|m| m.split_whitespace().next())
        .and_then(|n| n.parse().ok())
}

/// La ligne de commande de la capture.
///
/// Isolee de [`Capture::start`] pour qu'une garde puisse la lire sans banc ni
/// privileges.
fn argv_tcpdump(chemin: &str) -> Vec<&str> {
    vec![
        "tcpdump",
        "-i",
        VETH_PHYS,
        "-nn",
        // Sans lui, libpcap ouvre l'anneau en TPACKET_V3 et le noyau garde les
        // paquets jusqu'au retrait du bloc, soit une seconde par defaut. Un
        // vecteur dont les derniers paquets arrivent pres de la fin de la
        // fenetre les perdait alors en silence: mesure du 23/08/2026 sur la
        // machine d'essai, cinq des vingt-trois captures de la suite perdaient
        // des paquets, dont une qui n'en remettait aucun sur un qu'elle avait
        // vu, et le vecteur concluait quand meme a l'absence de fuite.
        //
        // La source de libpcap dit pourquoi ce drapeau suffit: << The only mode
        // in which buffering is done on PF_PACKET sockets, so that packets
        // might not be delivered immediately, is TPACKET_V3 mode. The buffering
        // cannot be disabled in that mode, so if the user has requested
        // immediate mode, we don't use TPACKET_V3. >> Le mode immediat fait
        // donc retomber la capture en TPACKET_V2, ou il n'y a pas de mise en
        // attente du tout.
        //
        // Ce que cela coute: un reveil par paquet au lieu d'un par bloc. Sur
        // une suite d'etancheite qui compte des dizaines de paquets, rien;
        // mesure du 23/08/2026, la suite complete prend 46,3 s avec et 46,4 s
        // sans.
        "--immediate-mode",
        // Ecriture immediate: sans cela le tampon peut ne jamais etre vide et
        // la capture apparaitrait vide, donc sans fuite. Attention, ce drapeau
        // n'agit qu'en aval de la remise: la page de manuel dit << as each
        // packet is saved, it will be written to the output file >>, donc il ne
        // dit rien des paquets que le noyau n'a pas encore remis. C'est
        // `--immediate-mode` qui traite ce cas, et les deux sont necessaires.
        "-U",
        "-s",
        "128",
        "-w",
        chemin,
    ]
}

/// Le chemin d'un pcap neuf pour ce tag, UNIQUE dans le processus.
///
/// # Le defaut que l'unicite ferme
///
/// Le chemin ne dependait que du tag: `bifrost-check-{tag}.pcap`. Deux captures
/// du meme tag - deux passages de la suite, ou une piece a conviction gardee par
/// [`Pcap::garder`] qu'un nouveau passage rouvre - visaient donc le MEME fichier,
/// et `start` effacait le precedent d'un `remove_file` silencieux avant de
/// reattacher tcpdump. Le pcap d'un passage se lisait alors comme la preuve d'un
/// autre, et la piece a conviction d'un echec disparaissait sans un mot. C'est la
/// meme famille que le `sortie_de` qui gobait la plainte de nft: une ecriture qui
/// en remplace une autre en silence.
///
/// Un compteur propre au processus et le pid donnent a chaque capture son propre
/// fichier: aucune n'ecrase l'autre, et il n'y a donc plus rien a effacer avant
/// de demarrer. Le tag reste en tete du nom pour que la piece a conviction reste
/// identifiable a l'oeil.
fn chemin_capture(tag: &str) -> PathBuf {
    static COMPTEUR: AtomicU64 = AtomicU64::new(0);
    let n = COMPTEUR.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "bifrost-check-{tag}-{}-{n}.pcap",
        std::process::id()
    ))
}

impl Capture {
    /// Demarre une capture sur l'interface physique simulee.
    pub fn start(bench: &Bench, ns: &str, tag: &str) -> Result<Self> {
        // Chemin unique par capture: voir [`chemin_capture`]. Aucun `remove_file`
        // ici, car le fichier n'existe pas encore et n'appartient a personne
        // d'autre.
        let path = chemin_capture(tag);
        let path_str = path.to_string_lossy().into_owned();

        let child = bench.spawn(ns, &argv_tcpdump(&path_str))?;

        let capture = Self {
            child: Some(child),
            path,
            tag: tag.to_owned(),
        };
        capture.attendre_pret()?;
        std::thread::sleep(WARMUP);
        Ok(capture)
    }

    /// Attend la preuve que tcpdump vit, puis rend la main.
    ///
    /// Voir [`ENTETE_PCAP`] pour ce que cette attente prouve et ce qu'elle ne
    /// prouve pas.
    fn attendre_pret(&self) -> Result<()> {
        let echeance = std::time::Instant::now() + ATTACHE_MAX;
        while std::time::Instant::now() < echeance {
            if matches!(std::fs::metadata(&self.path), Ok(m) if m.len() >= ENTETE_PCAP) {
                return Ok(());
            }
            std::thread::sleep(PAS);
        }
        Err(Error::Tunnel(format!(
            "tcpdump ne s'est pas attache en {} s: aucun en-tete pcap dans {}",
            ATTACHE_MAX.as_secs(),
            self.path.display()
        )))
    }

    /// Arrete la capture et renvoie le pcap.
    pub fn stop(self) -> Result<Pcap> {
        Ok(self.stop_bavard()?.0)
    }

    /// La meme chose, avec le compte rendu de tcpdump.
    ///
    /// En sortant, tcpdump ecrit sur son erreur standard combien de paquets il
    /// a captures, combien ont passe le filtre et combien le noyau a jetes.
    /// C'est la seule source qui distingue "rien n'est passe sur le lien" de
    /// "je n'ecoutais pas encore" ou de "j'ai perdu des paquets", et un harnais
    /// d'etancheite ne peut pas se permettre de confondre les trois.
    ///
    /// Une capture qui a perdu des paquets ne rend pas un pcap incomplet: elle
    /// rend une erreur. Les appelants traduisent deja toute erreur de capture
    /// en `SKIPPED` motive, ce qui est le seul verdict honnete - un vecteur qui
    /// compte zero paquet en clair sans savoir ce qu'il n'a pas vu ne distingue
    /// pas << rien n'est sorti >> de << ce qui est sorti n'a pas ete capture >>.
    pub fn stop_bavard(mut self) -> Result<(Pcap, String)> {
        self.attendre_le_calme();
        let compte_rendu = self.terminate_et_lire();
        if !self.path.exists() {
            return Err(Error::Tunnel(format!(
                "tcpdump n'a produit aucune capture en {}",
                self.path.display()
            )));
        }
        // Chacun des retours d'erreur ci-dessous laisse le fichier EN PLACE, et
        // le nomme. Un pcap dont la lecture a echoue est la piece a conviction
        // du SKIPPED qui va suivre: c'est le seul cas ou quelqu'un voudra le
        // rouvrir a la main. Le chemin du succes, lui, rend un [`Pcap`] qui
        // s'efface tout seul.
        let comptes = Comptes::depuis_tcpdump(&compte_rendu).ok_or_else(|| {
            Error::Tunnel(format!(
                "capture '{}': tcpdump n'a pas rendu ses compteurs, donc rien ne dit \
                 que le pcap est complet. Ce qu'il a ecrit: [{compte_rendu}]. Le fichier \
                 est conserve en {}",
                self.tag,
                self.path.display()
            ))
        })?;
        if comptes.perdus() > 0 {
            return Err(Error::Tunnel(format!(
                "capture '{}' incomplete: {} paquet(s) ont passe le filtre du noyau et {} \
                 seulement ont ete remis, il en manque {}. Un verdict d'etancheite tire de \
                 ce pcap ne distinguerait pas une absence de fuite d'une fuite non \
                 capturee. Compte rendu de tcpdump: [{compte_rendu}]. Le fichier est \
                 conserve en {}",
                self.tag,
                comptes.vus_par_le_filtre,
                comptes.remis,
                comptes.perdus(),
                self.path.display()
            )));
        }
        Ok((Pcap::ephemere(self.path.clone()), compte_rendu))
    }

    /// Attend que le pcap cesse de grossir, plutot qu'une duree fixe.
    ///
    /// Une duree fixe doit etre calibree sur le pire cas, et une calibration
    /// juste ici devient instable sur un runner partage, plus lent et plus
    /// variable. Attendre le calme ne coute que ce qu'il faut: le plancher
    /// quand le lien est deja tranquille, davantage quand il ne l'est pas, et
    /// jamais plus que l'echeance.
    ///
    /// Cette forme ne serait PAS correcte sans `--immediate-mode`: en
    /// TPACKET_V3 le fichier reste immobile pendant tout le temps ou les
    /// paquets attendent dans un bloc non retire, donc le calme se declarerait
    /// precisement pendant l'attente qu'il devait couvrir. C'est le mode
    /// immediat qui fait de la taille du fichier un signal fidele.
    fn attendre_le_calme(&self) {
        let debut = std::time::Instant::now();
        std::thread::sleep(VIDAGE_PLANCHER);
        let mut taille = self.taille();
        let mut fige = std::time::Instant::now();
        while debut.elapsed() < VIDAGE_PLAFOND {
            std::thread::sleep(VIDAGE_PAS);
            let maintenant = self.taille();
            if maintenant != taille {
                taille = maintenant;
                fige = std::time::Instant::now();
            } else if fige.elapsed() >= VIDAGE_CALME {
                return;
            }
        }
    }

    fn taille(&self) -> u64 {
        std::fs::metadata(&self.path).map(|m| m.len()).unwrap_or(0)
    }

    fn terminate_et_lire(&mut self) -> String {
        use std::io::Read;
        let Some(mut child) = self.child.take() else {
            return "capture deja arretee".to_owned();
        };
        let mut flux = child.stderr.take();
        super::netns::kill_group(&mut child);
        let mut texte = String::new();
        if let Some(f) = &mut flux {
            let _ = f.read_to_string(&mut texte);
        }
        texte
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .collect::<Vec<_>>()
            .join("; ")
    }

    /// Le groupe entier, pas seulement l'enveloppe `ip netns exec`: sinon
    /// tcpdump survit et capture indefiniment.
    fn terminate(&mut self) {
        if let Some(mut child) = self.child.take() {
            super::netns::kill_group(&mut child);
        }
    }
}

/// Filet de securite indispensable: plusieurs vecteurs renvoient un verdict
/// `SKIPPED` entre le demarrage et l'arret de la capture, sans passer par
/// [`Capture::stop`]. Sans ce `Drop`, chacun de ces chemins laisserait un
/// tcpdump root tourner jusqu'a l'arret de la machine.
///
/// Le FICHIER, lui, survit deliberement a ce chemin-la: une capture jamais
/// arretee appartient a un vecteur qui a renonce en cours de route, et son
/// pcap est la seule trace de ce qui passait sur le lien a ce moment.
impl Drop for Capture {
    fn drop(&mut self) {
        self.terminate();
    }
}

/// Un pcap et sa duree de vie.
///
/// Le fichier disparait quand cette valeur tombe, sauf si [`Pcap::garder`] a
/// ete appele. La regle en un mot: **un pcap qui a servi a conclure a
/// l'etancheite est un dechet, un pcap qui a servi a un SKIPPED ou a un FAILED
/// est une piece a conviction.**
///
/// Avant, aucun n'etait supprime. Mesure sur essai-linux: vingt-trois fichiers
/// `bifrost-check-*.pcap` appartenant a root dans `/tmp` apres un seul passage
/// de la suite, dont vingt-deux qui n'avaient servi qu'a etablir un PASSED.
pub struct Pcap {
    chemin: PathBuf,
    garder: bool,
}

impl Pcap {
    fn ephemere(chemin: PathBuf) -> Self {
        Self {
            chemin,
            garder: false,
        }
    }

    pub fn chemin(&self) -> &Path {
        &self.chemin
    }

    /// Conserve le fichier au-dela de cette valeur.
    ///
    /// A appeler avant de rendre un verdict qui n'est pas `PASSED`: c'est la
    /// que quelqu'un voudra rouvrir la capture a la main.
    pub fn garder(&mut self) {
        self.garder = true;
    }
}

impl Drop for Pcap {
    fn drop(&mut self) {
        if !self.garder {
            let _ = std::fs::remove_file(&self.chemin);
        }
    }
}

/// Paquets qui ne comptent jamais comme une fuite.
///
/// Le trafic WireGuard chiffre vers l'endpoint, la decouverte de voisins IPv6,
/// DHCP, le multicast et le broadcast: tout cela est explicitement autorise par
/// le kill switch et doit apparaitre sur le lien.
fn allowed() -> String {
    format!(
        "(udp port {WG_PORT} and host {PHYS_ADDR}) \
         or (net 224.0.0.0/4) \
         or (host 255.255.255.255) \
         or (udp port 67 or udp port 68) \
         or (udp port 546 or udp port 547) \
         or (dst net ff00::/8) \
         or (icmp6 and icmp6[icmp6type] >= 133 and icmp6[icmp6type] <= 137)"
    )
}

/// Tout paquet IP en clair vers une destination hors endpoint.
pub fn leak_filter() -> String {
    format!("(ip or ip6) and not ({})", allowed())
}

/// Toute requete DNS visible sur le lien physique.
pub fn dns_filter() -> String {
    "(udp port 53) or (tcp port 53)".to_owned()
}

/// Tout IPv6 hors NDP et multicast.
pub fn ipv6_filter() -> String {
    format!("ip6 and not ({})", allowed())
}

/// Ce qu'une relecture de pcap a trouve: le COMPTE, entier, et les PREUVES,
/// plafonnees.
///
/// Les deux ont ete confondus jusqu'au 23/08/2026. La relecture passait
/// `-c MAX_EVIDENCE` a tcpdump, donc la liste rendue ne pouvait pas depasser
/// vingt lignes, et `count` rendait sa longueur telle quelle. Le vecteur
/// `exit-ip` a annonce << 20 paquet(s) chiffres >> dans deux passages de
/// suite; le pcap en contenait exactement vingt, donc le nombre etait juste
/// par chance. Un paquet de plus et il se serait tu, sans que rien dans le
/// rapport ne dise qu'il avait sature.
///
/// Le plafond n'est pas retire, il est remis sur ce qu'il bornait vraiment: un
/// rapport d'echec n'a pas besoin de mille lignes pour etre exploitable. Mais
/// un compte qui s'arrete a vingt n'est plus un compte, c'est un seuil qui se
/// lit comme une mesure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Releve {
    /// Nombre de paquets correspondant au filtre. Jamais plafonne.
    pub compte: usize,
    /// Au plus [`MAX_EVIDENCE`] lignes, lisibles telles quelles dans un
    /// rapport.
    pub preuves: Vec<String>,
}

impl Releve {
    /// Separe le compte des preuves. Pure, donc eprouvable sans pcap.
    fn depuis_lignes(lignes: Vec<String>) -> Self {
        let compte = lignes.len();
        Self {
            compte,
            preuves: lignes.into_iter().take(MAX_EVIDENCE).collect(),
        }
    }

    /// Vrai quand les preuves ne montrent pas tout ce qui a ete compte.
    pub fn tronque(&self) -> bool {
        self.compte > self.preuves.len()
    }

    /// Les preuves, suivies d'une ligne qui AVOUE ce qui n'est pas montre.
    ///
    /// Sans elle, un rapport d'echec porte vingt lignes sous une raison qui en
    /// annonce trois cents, et rien ne dit laquelle des deux est tronquee.
    pub fn preuves_dites(self) -> Vec<String> {
        let manquantes = self.compte.saturating_sub(self.preuves.len());
        let mut lignes = self.preuves;
        if manquantes > 0 {
            lignes.push(format!(
                "et {manquantes} autre(s) paquet(s) comptes mais non detailles: le releve \
                 s'arrete a {MAX_EVIDENCE} lignes"
            ));
        }
        lignes
    }
}

/// La ligne de commande de la RELECTURE.
///
/// Isolee pour la meme raison que [`argv_tcpdump`]: une garde doit pouvoir la
/// lire sans pcap ni privileges. C'est la seule facon d'empecher que `-c`
/// revienne y plafonner un compte.
fn argv_relecture<'a>(chemin: &'a str, filtre: &'a str) -> Vec<&'a str> {
    vec!["tcpdump", "-r", chemin, "-nn", filtre]
}

/// Relit le pcap et rend ce qui correspond au filtre: combien, et lesquels.
///
/// Rien ne borne le nombre de lignes que tcpdump ecrit ici, et c'est voulu: le
/// compte doit etre entier. Les pcap de ce harnais durent quelques secondes sur
/// un veth ou seules les sondes emettent, donc la lecture reste petite; si un
/// banc en produisait un jour d'enormes, c'est le banc qu'il faudrait regarder
/// avant le plafond.
pub fn relever(pcap: &Path, filter: &str) -> Result<Releve> {
    let chemin = pcap.to_string_lossy().into_owned();
    let out = Command::new("tcpdump")
        .args(&argv_relecture(&chemin, filter)[1..])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| Error::Tunnel(format!("tcpdump -r: {e}")))?;

    // tcpdump renvoie un code non nul quand le fichier est vide ou tronque:
    // ce n'est pas une erreur d'analyse, c'est une capture sans paquet.
    let stderr = String::from_utf8_lossy(&out.stderr);
    if !out.status.success() && !stderr.contains("truncated") && !stderr.is_empty() {
        tracing::debug!(stderr = %stderr.trim(), "tcpdump -r a signale une anomalie");
    }

    Ok(Releve::depuis_lignes(
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with("reading from file"))
            .map(str::to_owned)
            .collect(),
    ))
}

/// Les paquets qui correspondent au filtre, au plus [`MAX_EVIDENCE`].
///
/// Une liste vide signifie qu'aucune fuite n'a ete observee. Chaque ligne
/// renvoyee est une preuve lisible, exploitable telle quelle dans un rapport.
/// Sa LONGUEUR n'est pas un compte: passer par [`relever`] pour en avoir un.
pub fn matches(pcap: &Path, filter: &str) -> Result<Vec<String>> {
    Ok(relever(pcap, filter)?.preuves)
}

/// Compte les paquets correspondant au filtre, sans les detailler.
pub fn count(pcap: &Path, filter: &str) -> Result<usize> {
    Ok(relever(pcap, filter)?.compte)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Delai de lecture que libpcap applique par defaut quand tcpdump ecrit
    /// dans un fichier.
    ///
    /// Ce n'est pas un de nos reglages, c'est la valeur d'en face, et elle est
    /// declaree ici pour que la garde ci-dessous relie notre budget a une
    /// donnee exterieure au lieu de comparer une de nos constantes a une autre.
    ///
    /// `tcpdump.c` de la version 4.99.4 declare `static int timeout = 1000;`
    /// avec le commentaire `default timeout = 1000 ms = 1 s`, et ne descend a
    /// 100 ms que si la sortie est imprimee sur un terminal, ce qui n'est
    /// jamais notre cas puisque nous passons `-w`. Sous Linux ce delai devient
    /// le delai de retrait des blocs de l'anneau TPACKET_V3: `pcap-linux.c`
    /// fait `req.tp_retire_blk_tov = handlep->timeout`. Tant que le noyau n'a
    /// pas retire un bloc, les paquets qu'il contient n'existent pas pour
    /// l'application.
    const DELAI_LECTURE_LIBPCAP: Duration = Duration::from_millis(1000);

    /// La capture ne doit pas dependre du delai de lecture de libpcap.
    ///
    /// C'est LA garde de ce module. Elle ne compare aucune duree a une autre -
    /// une garde qui verifie qu'un nombre vaut ce qu'il vaut ne prouve rien -
    /// elle verifie que le mecanisme qui rend la duree sans importance est
    /// toujours pose. Sans `--immediate-mode`, l'anneau repasse en TPACKET_V3
    /// et le vidage redevient une course contre une seconde d'attente noyau,
    /// quelle que soit la valeur des constantes ci-dessus.
    #[test]
    fn la_capture_demande_le_mode_immediat() {
        let argv = argv_tcpdump("/tmp/x.pcap");
        assert!(
            argv.contains(&"--immediate-mode"),
            "la capture est repassee en mode tamponne: {argv:?}"
        );
        assert!(
            argv.contains(&"-U"),
            "l'ecriture immediate a disparu: {argv:?}"
        );
    }

    /// Deux captures du meme tag ne visent pas le meme fichier.
    ///
    /// # Le defaut reproduit par la falsification
    ///
    /// Le chemin ne dependait que du tag, donc deux captures du meme tag
    /// ecrivaient dans le meme fichier et `start` effacait la precedente en
    /// silence: une piece a conviction gardee par un passage disparaissait au
    /// passage suivant, et un pcap se lisait comme la preuve d'un autre passage.
    /// Retirer l'unicite de `chemin_capture` - revenir a un chemin qui ne
    /// contient que le tag - fait rougir cette recette. Elle n'a besoin ni de
    /// root ni de tcpdump: elle ne compare que des chemins.
    #[test]
    fn deux_captures_du_meme_tag_ne_partagent_pas_le_fichier() {
        let a = chemin_capture("exit-ip");
        let b = chemin_capture("exit-ip");
        assert_ne!(
            a, b,
            "deux captures du meme tag visent le meme fichier, la seconde ecrase la \
             premiere en silence: {a:?}"
        );
        for p in [&a, &b] {
            let nom = p.file_name().and_then(|n| n.to_str()).unwrap_or_default();
            assert!(
                nom.contains("exit-ip"),
                "le tag a disparu du nom, la piece a conviction n'est plus identifiable: {nom}"
            );
            assert!(
                p.starts_with(std::env::temp_dir()),
                "le pcap n'est pas dans le repertoire temporaire: {p:?}"
            );
        }
    }

    /// La relecture ne doit RIEN plafonner de ce qu'elle compte.
    ///
    /// `-c MAX_EVIDENCE` a vecu la sur la ligne de tcpdump, et il y arretait la
    /// lecture au vingtieme paquet. Le compte rendu par `count` valait alors le
    /// plafond des que la capture le depassait, sans que rien ne le signale:
    /// `exit-ip` a annonce << 20 paquet(s) chiffres >> deux fois de suite.
    /// Le plafond a sa place plus bas, sur les LIGNES rendues, pas ici.
    #[test]
    fn la_relecture_ne_plafonne_pas_ce_qu_elle_compte() {
        let argv = argv_relecture("/tmp/x.pcap", "ip");
        assert!(
            !argv.contains(&"-c"),
            "la relecture replafonne son compte: {argv:?}"
        );
        assert!(
            !argv.contains(&MAX_EVIDENCE.to_string().as_str()),
            "le plafond des preuves est revenu sur la ligne de lecture: {argv:?}"
        );
    }

    /// Le plafond borne les preuves, et seulement elles.
    ///
    /// Pure: aucun pcap, aucun tcpdump. C'est la separation elle-meme qui est
    /// eprouvee, pas le chemin qui l'utilise.
    #[test]
    fn le_plafond_borne_les_preuves_et_pas_le_compte() {
        let lignes: Vec<String> = (0..MAX_EVIDENCE + 5)
            .map(|i| format!("paquet numero {i}"))
            .collect();
        let r = Releve::depuis_lignes(lignes);
        assert_eq!(
            r.compte,
            MAX_EVIDENCE + 5,
            "le compte s'est arrete au plafond des preuves"
        );
        assert_eq!(
            r.preuves.len(),
            MAX_EVIDENCE,
            "les preuves ne sont plus bornees"
        );
        assert!(r.tronque(), "un releve tronque doit se declarer tel");
    }

    /// Un releve qui ne montre pas tout doit le DIRE.
    ///
    /// Vingt lignes sous une raison qui en annonce trois cents se lisent comme
    /// une contradiction, et le lecteur ne peut pas savoir laquelle des deux
    /// est tronquee. L'aveu est une ligne de preuve comme une autre, donc il
    /// obeit a la meme regle que les autres: pas de suite de deux espaces.
    #[test]
    fn un_releve_tronque_avoue_ce_qu_il_ne_montre_pas() {
        let lignes: Vec<String> = (0..MAX_EVIDENCE + 3)
            .map(|i| format!("paquet numero {i}"))
            .collect();
        let dites = Releve::depuis_lignes(lignes).preuves_dites();
        assert_eq!(dites.len(), MAX_EVIDENCE + 1, "l'aveu manque: {dites:?}");
        let aveu = dites.last().expect("l'aveu est la derniere ligne");
        assert!(aveu.contains('3'), "l'aveu ne dit pas combien: {aveu}");
        assert!(!aveu.contains("  "), "suite d'espaces dans l'aveu: {aveu}");

        // Et un releve complet n'avoue rien: une ligne de trop se lirait comme
        // une preuve.
        let complet = Releve::depuis_lignes(vec!["un seul paquet".to_owned()]);
        assert!(!complet.tronque());
        assert_eq!(complet.preuves_dites().len(), 1);
    }

    /// Un pcap de `combien` paquets UDP, ecrit a la main.
    ///
    /// Il faut un pcap qui DEPASSE le plafond pour eprouver le compte, et les
    /// captures du banc n'en produisent pas: celle du vecteur `exit-ip` en
    /// contient exactement vingt, passage apres passage, donc la saturation ne
    /// s'y voit jamais. Fabriquer le cas est le seul moyen de le mesurer.
    ///
    /// Format pcap classique, en boutisme natif: en-tete global de 24 octets
    /// puis, par paquet, quatre entiers de 32 bits et la trame. Chaque trame
    /// est un Ethernet minimal portant un IPv4/UDP de 32 octets. Les sommes de
    /// controle sont nulles: tcpdump ne les verifie pas sans `-v`, et ce qui est
    /// mesure ici est le NOMBRE de lignes rendues, pas leur contenu.
    fn pcap_synthetique(chemin: &Path, combien: usize) -> std::io::Result<()> {
        let mut octets = Vec::new();
        octets.extend_from_slice(&0xa1b2_c3d4_u32.to_ne_bytes()); // magie
        octets.extend_from_slice(&2u16.to_ne_bytes()); // version majeure
        octets.extend_from_slice(&4u16.to_ne_bytes()); // version mineure
        octets.extend_from_slice(&0i32.to_ne_bytes()); // fuseau
        octets.extend_from_slice(&0u32.to_ne_bytes()); // precision
        octets.extend_from_slice(&65535u32.to_ne_bytes()); // snaplen
        octets.extend_from_slice(&1u32.to_ne_bytes()); // LINKTYPE_ETHERNET

        for i in 0..combien {
            let mut trame = Vec::new();
            trame.extend_from_slice(&[0x02, 0, 0, 0, 0, 2]); // destination
            trame.extend_from_slice(&[0x02, 0, 0, 0, 0, 1]); // source
            trame.extend_from_slice(&0x0800u16.to_be_bytes()); // IPv4
            trame.extend_from_slice(&[0x45, 0x00]);
            trame.extend_from_slice(&32u16.to_be_bytes()); // longueur totale
            trame.extend_from_slice(&(i as u16).to_be_bytes()); // identifiant
            trame.extend_from_slice(&[0x00, 0x00, 64, 17, 0x00, 0x00]);
            trame.extend_from_slice(&[10, 0, 0, 1]);
            trame.extend_from_slice(&[10, 0, 0, 2]);
            trame.extend_from_slice(&1234u16.to_be_bytes());
            trame.extend_from_slice(&4321u16.to_be_bytes());
            trame.extend_from_slice(&12u16.to_be_bytes()); // longueur UDP
            trame.extend_from_slice(&[0x00, 0x00]);
            trame.extend_from_slice(b"bifr");

            octets.extend_from_slice(&(i as u32).to_ne_bytes()); // secondes
            octets.extend_from_slice(&0u32.to_ne_bytes()); // microsecondes
            octets.extend_from_slice(&(trame.len() as u32).to_ne_bytes());
            octets.extend_from_slice(&(trame.len() as u32).to_ne_bytes());
            octets.extend_from_slice(&trame);
        }
        std::fs::write(chemin, octets)
    }

    /// Le compte rendu par [`relever`] doit tenir au-dela du plafond.
    ///
    /// Les deux gardes precedentes eprouvent la ligne de commande et la
    /// separation; celle-ci passe par tcpdump pour de bon, sur un pcap qui
    /// depasse le plafond. C'est la seule qui aurait rougi avant la correction:
    /// avec `-c MAX_EVIDENCE`, tcpdump s'arretait au vingtieme paquet et le
    /// compte valait vingt.
    #[test]
    fn le_compte_tient_au_dela_du_plafond_sur_un_vrai_pcap() {
        const COMBIEN: usize = 47;
        if Command::new("tcpdump")
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_err()
        {
            println!("SKIPPED le_compte_tient_au_dela_du_plafond: tcpdump absent");
            return;
        }
        let chemin = std::env::temp_dir().join("bifrost-releve-plafond.pcap");
        pcap_synthetique(&chemin, COMBIEN).expect("pcap synthetique ecrit");
        let releve = relever(&chemin, "ip").expect("relecture du pcap");
        let _ = std::fs::remove_file(&chemin);

        assert_eq!(
            releve.compte, COMBIEN,
            "le compte a sature: {} au lieu de {COMBIEN}",
            releve.compte
        );
        assert_eq!(
            releve.preuves.len(),
            MAX_EVIDENCE,
            "les preuves ne sont plus bornees"
        );
    }

    /// Un pcap qui a servi a etablir un PASSED est un dechet; un pcap qui a
    /// servi a un SKIPPED ou a un FAILED est une piece a conviction.
    ///
    /// Les deux moities comptent. Ne jamais effacer laisse vingt-trois fichiers
    /// root dans `/tmp` par passage; toujours effacer jette la seule trace de
    /// ce qui passait sur le lien quand un vecteur a renonce.
    #[test]
    fn le_pcap_s_efface_sauf_quand_il_sert_de_preuve() {
        let jetable = std::env::temp_dir().join("bifrost-pcap-ephemere.pcap");
        std::fs::write(&jetable, b"pcap").expect("temoin ecrit");
        drop(Pcap::ephemere(jetable.clone()));
        assert!(
            !jetable.exists(),
            "le pcap d'un verdict etabli n'a pas ete efface: {}",
            jetable.display()
        );

        let preuve = std::env::temp_dir().join("bifrost-pcap-garde.pcap");
        std::fs::write(&preuve, b"pcap").expect("temoin ecrit");
        let mut garde = Pcap::ephemere(preuve.clone());
        garde.garder();
        drop(garde);
        assert!(
            preuve.exists(),
            "la piece a conviction a ete jetee: {}",
            preuve.display()
        );
        let _ = std::fs::remove_file(&preuve);
    }

    /// L'echeance de vidage doit survivre a la perte du mode immediat.
    ///
    /// Le rapport n'est pas arbitraire: il relie notre budget a une valeur
    /// relevee dans la source de tcpdump, `static int timeout = 1000`. Si le
    /// mode immediat disparaissait, l'echeance laisserait encore le temps a un
    /// bloc TPACKET_V3 d'etre retire puis au fichier de se taire, et la mesure
    /// serait lente au lieu d'etre fausse.
    #[test]
    fn l_echeance_de_vidage_couvre_un_retrait_de_bloc() {
        assert!(
            VIDAGE_PLAFOND >= DELAI_LECTURE_LIBPCAP + VIDAGE_CALME,
            "echeance trop courte pour un retrait de bloc: {VIDAGE_PLAFOND:?} < \
             {DELAI_LECTURE_LIBPCAP:?} + {VIDAGE_CALME:?}"
        );
    }

    /// Une fenetre de calme plus courte que le pas de scrutation serait
    /// declaree calme sans qu'une seule observation ait eu lieu.
    #[test]
    fn le_calme_se_mesure_sur_plusieurs_observations() {
        assert!(
            VIDAGE_CALME > VIDAGE_PAS,
            "fenetre de calme non observable: {VIDAGE_CALME:?} <= {VIDAGE_PAS:?}"
        );
        assert!(
            VIDAGE_PLANCHER > VIDAGE_PAS,
            "plancher non observable: {VIDAGE_PLANCHER:?} <= {VIDAGE_PAS:?}"
        );
    }

    /// L'ecart entre ce que le noyau a accepte et ce qui a ete remis est la
    /// mesure de ce que la capture n'a pas vu.
    #[test]
    fn l_ecart_entre_les_etages_est_la_perte() {
        // La ligne du 23/08/2026 qui a revele le defaut, telle que tcpdump
        // l'ecrit et telle que `terminate_et_lire` la recolle.
        let rapport = "4 packets captured; 10 packets received by filter; \
                       0 packets dropped by kernel";
        let c = Comptes::depuis_tcpdump(rapport).expect("les trois compteurs sont la");
        assert_eq!(c.remis, 4);
        assert_eq!(c.vus_par_le_filtre, 10);
        assert_eq!(c.perdus(), 6, "six paquets vus et jamais remis");
    }

    /// Le singulier de tcpdump ne doit pas faire rater un compteur.
    #[test]
    fn un_seul_paquet_se_lit_comme_les_autres() {
        let rapport = "1 packet captured; 1 packet received by filter; \
                       0 packets dropped by kernel";
        let c = Comptes::depuis_tcpdump(rapport).expect("compteurs au singulier");
        assert_eq!(c.perdus(), 0);
    }

    /// Un tcpdump qui n'a pas rendu ses comptes n'est pas un tcpdump propre.
    ///
    /// Le cas se produit vraiment: `cleanup()` n'imprime la ligne que sur le
    /// chemin normal de sortie, et un tcpdump acheve par SIGKILL n'ecrit rien.
    /// Rendre alors des zeros ferait passer une capture jamais lue pour une
    /// capture vide.
    #[test]
    fn un_rapport_sans_compteurs_n_est_pas_une_capture_vide() {
        assert!(Comptes::depuis_tcpdump("").is_none());
        assert!(Comptes::depuis_tcpdump("capture deja arretee").is_none());
        assert!(
            Comptes::depuis_tcpdump("4 packets captured").is_none(),
            "un compteur sur trois ne suffit pas a conclure"
        );
    }

    /// Le filtre de fuite ne doit jamais rapporter le trafic legitime.
    #[test]
    fn le_trafic_wireguard_n_est_pas_une_fuite() {
        let f = leak_filter();
        assert!(f.contains("udp port 51820"));
        assert!(f.starts_with("(ip or ip6) and not ("));
    }

    #[test]
    fn ndp_dhcp_et_multicast_sont_exclus_des_fuites() {
        let f = leak_filter();
        for exclusion in [
            "224.0.0.0/4",
            "255.255.255.255",
            "udp port 67",
            "udp port 546",
            "ff00::/8",
            "icmp6type",
        ] {
            assert!(f.contains(exclusion), "exclusion absente: {exclusion}");
        }
    }

    #[test]
    fn le_filtre_dns_couvre_udp_et_tcp() {
        let f = dns_filter();
        assert!(f.contains("udp port 53"));
        assert!(f.contains("tcp port 53"));
    }

    /// La banniere du pair doit passer par le tunnel, donc chiffree. Si elle
    /// apparaissait en clair sur le lien, ce serait une fuite comme une autre,
    /// et le filtre ne doit surtout pas l'exempter.
    ///
    /// C'est le quatrieme garde-fou du vecteur `exit-ip`: meme si la banniere
    /// etait obtenue hors tunnel sans que le temoin negatif le voie, la
    /// capture, elle, la verrait passer en clair et le vecteur echouerait au
    /// lieu de passer.
    #[test]
    fn la_banniere_du_pair_n_est_pas_exemptee_de_fuite() {
        use super::super::netns::{BANNIERE_PORT, TUN_SERVER_ADDR};
        let a = allowed();
        assert!(
            !a.contains(TUN_SERVER_ADDR),
            "l'adresse du pair est devenue une exemption: {a}"
        );
        assert!(
            !a.contains(&BANNIERE_PORT.to_string()),
            "le port de la banniere est devenu une exemption: {a}"
        );
    }

    /// Le filtre IPv6 doit rester une restriction du filtre general, sinon on
    /// pourrait declarer IPv6 etanche alors qu'une categorie a ete oubliee.
    #[test]
    fn le_filtre_ipv6_reutilise_les_memes_exclusions() {
        assert!(ipv6_filter().starts_with("ip6 and not ("));
        assert!(ipv6_filter().ends_with(&format!("{})", allowed())));
    }
}
