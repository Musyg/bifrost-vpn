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

use super::netns::{Bench, CLIENT_MAC, PHYS_ADDR, VETH_PHYS, WG_PORT};

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

/// Les trames que le client emet sur le lien, et elles seules.
///
/// La capture se fait cote `phys` et voit les deux sens du lien. Une fuite est
/// une trame que le client emet; ce que la passerelle emet de son cote (ses
/// reponses aux sondes, son NDP, ses rapports MLD) n'en est jamais une. Le
/// pcap ne porte pas le sens d'une trame, sa source Ethernet si: le banc pose
/// [`CLIENT_MAC`] sur `veth-bfc` a la creation du lien (`netns.rs`).
///
/// Mesure du 11/10/2026 sur essai-linux, suite de fuite dans un namespace
/// jetable, deux series: apres la remontee de `veth-bfp` (phase
/// `coupure-lien` de `reconnect-window`, kill switch arme), la passerelle a
/// emis des rapports MLDv2 vers `ff02::16`, et la capture armee de la phase en
/// a pris un dans chaque serie; ceux du client, le kill switch les a jetes.
fn emises_par_le_client() -> String {
    format!("ether src {CLIENT_MAC}")
}

/// Ce que la sortie du kill switch du banc admet sur le lien, en miroir: les
/// seules trames du client qui ne comptent jamais comme une fuite.
///
/// Les phases qui relisent un pcap par [`leak_filter`] ou [`ipv6_filter`] et
/// y attendent zero arment `bench_policy` (`checks/mod.rs`): marque
/// WireGuard, resolveur sur la boucle locale, LAN ferme, aucun coeur. La
/// sortie (`ruleset.rs`) n'admet alors sur le lien que ceci, et chaque clause
/// est bornee comme sa regle nft:
///
/// - `meta mark`, ce que le module WireGuard chiffre: dans le banc, l'UDP du
///   client vers l'endpoint, 10.77.0.1 port 51820. Le pcap ne porte pas la
///   marque: la clause exempte tout UDP du client vers ce port de l'endpoint;
/// - `ip daddr 255.255.255.255 udp sport 68 udp dport 67`, le client DHCPv4;
/// - `ip6 daddr { ff02::1:2, ff05::1:3 } udp sport 546 udp dport 547`, le
///   client DHCPv6;
/// - `icmpv6 type` 133 a 137, le NDP.
///
/// Le reste de ce que la sortie admet ne parait pas sur le lien: la boucle
/// locale, l'interface du tunnel, le DNS vers le resolveur declare
/// (127.0.0.1). Aucune exemption de plus: ni multicast, ni diffusion, ni
/// groupe IPv6 hors des deux du DHCPv6. Une seule capture relue par ces
/// filtres tourne LAN ouvert: le temoin `dns-leak-lien-ouvert`, qui y attend
/// un compte non nul. Le miroir, celui de la sortie LAN ferme, y compte la
/// sonde de lien que l'acceptation du LAN admet, et c'est ce que ce temoin
/// mesure.
///
/// Un ecart de forme, du cote qui compte: les primitives `udp` et `icmp6` de
/// libpcap ne franchissent pas un en-tete Hop-by-Hop. Une forme de cette liste
/// portee derriere lui serait comptee, quoi qu'en dise le kill switch. Le banc
/// n'en emet aucune (mesure du 11/10/2026: les seules trames du lien a en-tete
/// Hop-by-Hop etaient des rapports MLDv2).
fn allowed() -> String {
    format!(
        "(ip and dst host {PHYS_ADDR} and udp dst port {WG_PORT}) \
         or (ip and dst host 255.255.255.255 and udp src port 68 and udp dst port 67) \
         or (ip6 and (dst host ff02::1:2 or dst host ff05::1:3) \
         and udp src port 546 and udp dst port 547) \
         or (icmp6 and icmp6[icmp6type] >= 133 and icmp6[icmp6type] <= 137)"
    )
}

/// Toute trame IP que le client emet en clair sur le lien hors de ce que la
/// sortie du kill switch admet.
pub fn leak_filter() -> String {
    format!(
        "{} and (ip or ip6) and not ({})",
        emises_par_le_client(),
        allowed()
    )
}

/// Toute requete DNS visible sur le lien physique.
pub fn dns_filter() -> String {
    "(udp port 53) or (tcp port 53)".to_owned()
}

/// Tout IPv6 que le client emet sur le lien hors de ce que la sortie du kill
/// switch admet.
pub fn ipv6_filter() -> String {
    format!("{} and ip6 and not ({})", emises_par_le_client(), allowed())
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
    juger_la_relecture(
        out.status.success(),
        &String::from_utf8_lossy(&out.stdout),
        &String::from_utf8_lossy(&out.stderr),
    )
}

/// Ce que rend une relecture, jugee: un releve, ou une erreur qui dit pourquoi.
///
/// Pure, pour qu'une garde l'eprouve sans pcap, sans tcpdump et sans root.
///
/// # Le defaut que ce jugement ferme
///
/// Tout code non nul de `tcpdump -r` se lisait comme une capture sans paquet,
/// et la plainte ne partait qu'au journal de debogage. Mesure du 30/09/2026 sur
/// la machine d'essai, sous les capacites de l'unite systemd d'alors (root sans
/// CAP_DAC_OVERRIDE ni CAP_DAC_READ_SEARCH) et son `UMask=0077`: tcpdump quitte
/// root pour son propre compte avant d'ouvrir sa sortie, laisse donc un pcap en
/// 0600 a ce compte, et la relecture echoue sur `Permission denied`. La suite
/// entiere lisait alors des captures vides. Seuls les temoins negatifs ont
/// empeche un PASSED: tous muets, donc tous SKIPPED, sous une raison qui
/// accusait les sondes au lieu de la lecture. Un filtre que tcpdump ne sait pas
/// analyser se lisait de meme comme une absence de fuite.
///
/// Seule la troncature reste une relecture: tcpdump rend alors ce qu'il a lu
/// avant la coupure, et un fichier sans en-tete, capture arretee avant son
/// premier octet, est un fichier sans paquet. Tout autre echec est une
/// relecture qui n'a pas eu lieu, et un pcap qu'on n'a pas lu ne vaut pas un
/// pcap vide.
fn juger_la_relecture(reussie: bool, stdout: &str, stderr: &str) -> Result<Releve> {
    if !reussie && !stderr.contains("truncated") {
        let plainte = stderr
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .collect::<Vec<_>>()
            .join("; ");
        return Err(Error::Tunnel(format!(
            "relecture du pcap refusee par tcpdump, donc rien n'y a ete lu, pas meme \
             une absence de paquet: [{plainte}]"
        )));
    }
    Ok(Releve::depuis_lignes(
        stdout
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
        let chemin = std::env::temp_dir().join(format!(
            "bifrost-releve-plafond-{}.pcap",
            std::process::id()
        ));
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

    /// Un pcap d'UNE trame, ecrit a la main comme [`pcap_synthetique`]:
    /// en-tete global de 24 octets en boutisme natif, puis l'enregistrement.
    fn pcap_d_une_trame(chemin: &Path, trame: &[u8]) -> std::io::Result<()> {
        let mut octets = Vec::new();
        octets.extend_from_slice(&0xa1b2_c3d4_u32.to_ne_bytes()); // magie
        octets.extend_from_slice(&2u16.to_ne_bytes()); // version majeure
        octets.extend_from_slice(&4u16.to_ne_bytes()); // version mineure
        octets.extend_from_slice(&0i32.to_ne_bytes()); // fuseau
        octets.extend_from_slice(&0u32.to_ne_bytes()); // precision
        octets.extend_from_slice(&65535u32.to_ne_bytes()); // snaplen
        octets.extend_from_slice(&1u32.to_ne_bytes()); // LINKTYPE_ETHERNET
        octets.extend_from_slice(&0u32.to_ne_bytes()); // secondes
        octets.extend_from_slice(&0u32.to_ne_bytes()); // microsecondes
        octets.extend_from_slice(&(trame.len() as u32).to_ne_bytes());
        octets.extend_from_slice(&(trame.len() as u32).to_ne_bytes());
        octets.extend_from_slice(trame);
        std::fs::write(chemin, octets)
    }

    /// Les six octets d'une adresse MAC ecrite `aa:bb:cc:dd:ee:ff`.
    fn octets_mac(mac: &str) -> [u8; 6] {
        let octets: Vec<u8> = mac
            .split(':')
            .map(|o| u8::from_str_radix(o, 16).expect("adresse MAC hexadecimale"))
            .collect();
        octets
            .try_into()
            .unwrap_or_else(|o: Vec<u8>| panic!("adresse MAC de {} octets: {mac}", o.len()))
    }

    /// L'en-tete Ethernet d'une trame de temoin, emise par le client: sa
    /// source est [`CLIENT_MAC`], la seule que le filtre de fuite juge. La
    /// destination n'est lue par aucune clause. [`depuis`] change la source.
    fn ethernet(ethertype: u16) -> Vec<u8> {
        let mut t = vec![0x02, 0, 0, 0, 0, 1];
        t.extend_from_slice(&octets_mac(CLIENT_MAC));
        t.extend_from_slice(&ethertype.to_be_bytes());
        t
    }

    /// La meme trame, emise depuis l'adresse MAC `mac`.
    fn depuis(mac: &str, mut trame: Vec<u8>) -> Vec<u8> {
        trame[6..12].copy_from_slice(&octets_mac(mac));
        trame
    }

    /// Un en-tete UDP de 8 octets suivi d'une charge de 4. Sommes de controle
    /// nulles: tcpdump ne les verifie pas sans `-v`.
    fn udp(source: u16, destination: u16) -> Vec<u8> {
        let mut u = Vec::new();
        u.extend_from_slice(&source.to_be_bytes());
        u.extend_from_slice(&destination.to_be_bytes());
        u.extend_from_slice(&12u16.to_be_bytes());
        u.extend_from_slice(&[0x00, 0x00]);
        u.extend_from_slice(b"dhcp");
        u
    }

    /// Une trame IPv4 de protocole 17 (UDP) qui porte `charge`. `decalage`
    /// est le champ de fragment, en unites de huit octets: non nul, la trame
    /// est un fragment non premier et `charge` n'a pas d'en-tete UDP.
    fn trame_ipv4(
        source: std::net::Ipv4Addr,
        destination: std::net::Ipv4Addr,
        decalage: u16,
        charge: &[u8],
    ) -> Vec<u8> {
        trame_ipv4_de(source, destination, 17, &[], decalage, charge)
    }

    /// Une trame IPv4 du protocole `protocole`, `options` (un multiple de
    /// quatre octets) dans l'en-tete, qui porte `charge`.
    fn trame_ipv4_de(
        source: std::net::Ipv4Addr,
        destination: std::net::Ipv4Addr,
        protocole: u8,
        options: &[u8],
        decalage: u16,
        charge: &[u8],
    ) -> Vec<u8> {
        assert_eq!(options.len() % 4, 0, "options IPv4 hors de mots de 32 bits");
        let mut t = ethernet(0x0800);
        t.extend_from_slice(&[0x40 | (5 + options.len() / 4) as u8, 0x00]);
        t.extend_from_slice(&((20 + options.len() + charge.len()) as u16).to_be_bytes());
        t.extend_from_slice(&[0x00, 0x01]); // identifiant
        t.extend_from_slice(&(decalage & 0x1fff).to_be_bytes()); // drapeaux nuls
        t.extend_from_slice(&[64, protocole, 0x00, 0x00]); // duree de vie, protocole, somme
        t.extend_from_slice(&source.octets());
        t.extend_from_slice(&destination.octets());
        t.extend_from_slice(options);
        t.extend_from_slice(charge);
        t
    }

    /// Une trame IPv6 qui porte `charge` en UDP. Avec `saut_par_saut`, un
    /// en-tete Hop-by-Hop de huit octets (une option PadN) precede l'UDP.
    fn trame_ipv6(
        source: std::net::Ipv6Addr,
        destination: std::net::Ipv6Addr,
        saut_par_saut: bool,
        charge: &[u8],
    ) -> Vec<u8> {
        trame_ipv6_de(source, destination, saut_par_saut, 17, charge)
    }

    /// Une trame IPv6 qui porte `charge` sous l'en-tete suivant `protocole`
    /// (17 UDP, 6 TCP, 58 ICMPv6), derriere un en-tete Hop-by-Hop si
    /// `saut_par_saut`.
    fn trame_ipv6_de(
        source: std::net::Ipv6Addr,
        destination: std::net::Ipv6Addr,
        saut_par_saut: bool,
        protocole: u8,
        charge: &[u8],
    ) -> Vec<u8> {
        let mut suite = Vec::new();
        if saut_par_saut {
            // en-tete suivant, longueur 0 (8 octets), PadN de 4 octets
            suite.extend_from_slice(&[protocole, 0, 1, 4, 0, 0, 0, 0]);
        }
        suite.extend_from_slice(charge);
        let mut t = ethernet(0x86dd);
        t.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]);
        t.extend_from_slice(&(suite.len() as u16).to_be_bytes());
        t.push(if saut_par_saut { 0 } else { protocole });
        t.push(64);
        t.extend_from_slice(&source.octets());
        t.extend_from_slice(&destination.octets());
        t.extend_from_slice(&suite);
        t
    }

    /// Un message ICMP (IPv4 ou IPv6): type, code, somme nulle, puis `corps`.
    fn icmp(type_: u8, code: u8, corps: &[u8]) -> Vec<u8> {
        let mut m = vec![type_, code, 0x00, 0x00];
        m.extend_from_slice(corps);
        m
    }

    /// Un segment TCP de 20 octets portant `drapeaux` (0x02 SYN, 0x04 RST).
    fn tcp(source: u16, destination: u16, drapeaux: u8) -> Vec<u8> {
        let mut s = Vec::new();
        s.extend_from_slice(&source.to_be_bytes());
        s.extend_from_slice(&destination.to_be_bytes());
        s.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0]); // sequence, acquittement
        s.extend_from_slice(&[0x50, drapeaux, 0xff, 0xff, 0, 0, 0, 0]);
        s
    }

    /// Une requete ARP du client, de `source` vers `cible`.
    fn trame_arp(source: std::net::Ipv4Addr, cible: std::net::Ipv4Addr) -> Vec<u8> {
        let mut t = ethernet(0x0806);
        t.extend_from_slice(&[0, 1, 0x08, 0x00, 6, 4, 0, 1]);
        t.extend_from_slice(&octets_mac(CLIENT_MAC));
        t.extend_from_slice(&source.octets());
        t.extend_from_slice(&[0; 6]);
        t.extend_from_slice(&cible.octets());
        t
    }

    /// La clause d'adresse IPv6 d'un temoin, `sens` valant `src` ou `dst`.
    /// L'adresse non specifiee s'y ecrit par ses seize octets nuls plutot que
    /// par `::`.
    fn hote6(sens: &str, a: std::net::Ipv6Addr) -> String {
        if a.is_unspecified() {
            let o = if sens == "src" { 8 } else { 24 };
            format!(
                "ip6[{o}:4] == 0 and ip6[{}:4] == 0 and ip6[{}:4] == 0 and ip6[{}:4] == 0",
                o + 4,
                o + 8,
                o + 12
            )
        } else {
            format!("{sens} host {a}")
        }
    }

    /// Une forme de la table des temoins, et ce que le filtre de fuite doit en
    /// compter.
    struct Forme {
        id: &'static str,
        trame: Vec<u8>,
        /// Un filtre qui ne voit que cette forme. Il doit la compter une fois:
        /// sans lui, un compte de fuite nul ne distinguerait pas une forme
        /// exemptee d'une trame que tcpdump n'a pas lue comme prevu.
        temoin: String,
        /// Ce que `leak_filter()` doit en compter.
        fuite: usize,
    }

    /// Le filtre de fuite compte chaque forme de cette table que le kill
    /// switch Linux refuse, et aucune de celles qu'il admet.
    ///
    /// GARDE SANS ROOT: un pcap synthetique d'une trame par forme, relu par
    /// [`relever`] sous [`leak_filter`]. La table est celle des temoins,
    /// adaptee a la politique arbitree le 11/10/2026: DHCPv4 du client vers la
    /// diffusion seule, DHCPv6 vers `ff02::1:2` et `ff05::1:3` seuls. Adresses
    /// du banc (`netns.rs`): client 10.77.0.2 et fd00:77::2, endpoint
    /// 10.77.0.1; une adresse de lien par cote, fe80::c pour le client et
    /// fe80::1 pour le serveur; hors du lien, 203.0.113.9 et 2001:db8::9, en
    /// trou noir dans le banc.
    ///
    /// Comptees (1). Les douze formes T et N, la sortie du kill switch les
    /// refuse LAN ferme (mesure au banc le 11/10/2026; LAN ouvert,
    /// l'acceptation du LAN admet, comme tout trafic du LAN, celles qui visent
    /// une adresse du LAN: T7, N3, N7). F1 et F2, que le banc n'emet pas, ne
    /// sont jugees qu'ici:
    /// - T1 IPv4 10.77.0.2:40000 -> 203.0.113.9:67, mauvais port source;
    /// - T2 IPv4 10.77.0.2:68 -> 203.0.113.9:443, mauvaise destination;
    /// - T3 IPv4 10.77.0.2:1234 -> 203.0.113.9:68, port du client en
    ///   destination;
    /// - T4 IPv4 10.77.0.2:67 -> 203.0.113.9:68, forme du serveur emise par le
    ///   client: l'entree l'admet, la sortie non;
    /// - T5 IPv6 fd00:77::2:68 -> [2001:db8::9]:67, DHCPv4 en IPv6;
    /// - T6 IPv6 fd00:77::2:546 -> [2001:db8::9]:547, vers une globale;
    /// - T7 IPv6 [fe80::c]:40000 -> [fe80::1]:547, mauvais port source;
    /// - T8 IPv4 10.77.0.2:546 -> 203.0.113.9:547, ports du DHCPv6 en IPv4;
    /// - T9 IPv6 [fe80::c]:547 -> [2001:db8::9]:546, forme du serveur DHCPv6
    ///   emise par le client;
    /// - N3 IPv4 10.77.0.2:68 -> 10.77.0.1:67, renouvellement unicast vers le
    ///   serveur du lien (l'endpoint du banc: la clause WireGuard ne
    ///   l'exempte pas, elle exige le port 51820);
    /// - N4 IPv4 10.77.0.2:68 -> 203.0.113.9:67, renouvellement hors du lien
    ///   (relais);
    /// - N7 IPv6 [fe80::c]:546 -> [fe80::1]:547, unicast du client vers le
    ///   serveur du lien, que RFC 9915 retire;
    /// - F1 fragment IPv4 non premier d'un 68 -> 67 vers 10.77.0.1: sans
    ///   en-tete UDP, il n'est exempte par aucune adresse;
    /// - F2 IPv6 [fe80::c]:546 -> [fe80::1]:547 derriere un en-tete
    ///   Hop-by-Hop.
    ///
    /// Non comptees (0), le kill switch les admet, LAN ferme comme ouvert
    /// (mesure au banc le 11/10/2026):
    /// - N1 IPv4 0.0.0.0:68 -> 255.255.255.255:67, decouverte;
    /// - N2 IPv4 10.77.0.2:68 -> 255.255.255.255:67, redemande diffusee;
    /// - N5 IPv6 [fe80::c]:546 -> [ff02::1:2]:547, sollicitation;
    /// - N6 IPv6 [fe80::c]:546 -> [ff05::1:3]:547.
    ///
    /// Sans tcpdump, la garde s'abstient en le nommant, comme
    /// `le_compte_tient_au_dela_du_plafond_sur_un_vrai_pcap`.
    #[test]
    fn le_filtre_de_fuite_juge_chaque_forme_dhcp_de_sa_table() {
        use super::super::netns::{CLIENT_ADDR, CLIENT_ADDR6, PHYS_ADDR};
        use std::net::{Ipv4Addr, Ipv6Addr};
        if Command::new("tcpdump")
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_err()
        {
            println!(
                "SKIPPED le_filtre_de_fuite_juge_chaque_forme_dhcp_de_sa_table: \
                 tcpdump absent"
            );
            return;
        }
        let c4: Ipv4Addr = CLIENT_ADDR.parse().unwrap();
        let p4: Ipv4Addr = PHYS_ADDR.parse().unwrap();
        let c6: Ipv6Addr = CLIENT_ADDR6.parse().unwrap();
        let hors4 = Ipv4Addr::new(203, 0, 113, 9);
        let hors6: Ipv6Addr = "2001:db8::9".parse().unwrap();
        let lien_c: Ipv6Addr = "fe80::c".parse().unwrap();
        let lien_p: Ipv6Addr = "fe80::1".parse().unwrap();
        let diffusion = Ipv4Addr::BROADCAST;
        let tous_relais: Ipv6Addr = "ff02::1:2".parse().unwrap();
        let serveurs: Ipv6Addr = "ff05::1:3".parse().unwrap();

        let v4 = |id, s: Ipv4Addr, sp: u16, d: Ipv4Addr, dp: u16, fuite| Forme {
            id,
            trame: trame_ipv4(s, d, 0, &udp(sp, dp)),
            temoin: format!(
                "ip and src host {s} and dst host {d} and udp src port {sp} and udp dst port {dp}"
            ),
            fuite,
        };
        let v6 = |id, s: Ipv6Addr, sp: u16, d: Ipv6Addr, dp: u16, fuite| Forme {
            id,
            trame: trame_ipv6(s, d, false, &udp(sp, dp)),
            temoin: format!(
                "ip6 and src host {s} and dst host {d} and udp src port {sp} and udp dst port {dp}"
            ),
            fuite,
        };
        let formes = vec![
            v4("T1", c4, 40000, hors4, 67, 1),
            v4("T2", c4, 68, hors4, 443, 1),
            v4("T3", c4, 1234, hors4, 68, 1),
            v4("T4", c4, 67, hors4, 68, 1),
            v6("T5", c6, 68, hors6, 67, 1),
            v6("T6", c6, 546, hors6, 547, 1),
            v6("T7", lien_c, 40000, lien_p, 547, 1),
            v4("T8", c4, 546, hors4, 547, 1),
            v6("T9", lien_c, 547, hors6, 546, 1),
            v4("N1", Ipv4Addr::UNSPECIFIED, 68, diffusion, 67, 0),
            v4("N2", c4, 68, diffusion, 67, 0),
            v4("N3", c4, 68, p4, 67, 1),
            v4("N4", c4, 68, hors4, 67, 1),
            v6("N5", lien_c, 546, tous_relais, 547, 0),
            v6("N6", lien_c, 546, serveurs, 547, 0),
            v6("N7", lien_c, 546, lien_p, 547, 1),
            Forme {
                id: "F1",
                // 185 unites de huit octets: le second fragment d'un datagramme
                // de 1480 octets de donnees ou plus.
                trame: trame_ipv4(c4, p4, 185, b"suite du DHCP"),
                temoin: format!("ip and src host {c4} and dst host {p4} and ip[6:2] & 0x1fff != 0"),
                fuite: 1,
            },
            Forme {
                id: "F2",
                trame: trame_ipv6(lien_c, lien_p, true, &udp(546, 547)),
                temoin: format!("ip6 and src host {lien_c} and dst host {lien_p} and ip6[6] == 0"),
                fuite: 1,
            },
        ];

        let filtre = leak_filter();
        let mut ecarts = Vec::new();
        for f in &formes {
            let chemin = std::env::temp_dir().join(format!(
                "bifrost-dhcp-{}-{}.pcap",
                f.id,
                std::process::id()
            ));
            pcap_d_une_trame(&chemin, &f.trame).expect("pcap synthetique ecrit");
            let vue = relever(&chemin, &f.temoin).map(|r| r.compte);
            let comptee = relever(&chemin, &filtre).map(|r| r.compte);
            let _ = std::fs::remove_file(&chemin);
            match (vue, comptee) {
                (Ok(1), Ok(n)) if n == f.fuite => {}
                (vue, comptee) => ecarts.push(format!(
                    "{}: temoin {vue:?} (1 attendu), fuite {comptee:?} ({} attendu)",
                    f.id, f.fuite
                )),
            }
        }
        assert!(
            ecarts.is_empty(),
            "formes DHCP mal jugees par le filtre de fuite:\n{}\nfiltre: {filtre}",
            ecarts.join("\n")
        );
    }

    /// Une forme de la table de la garde par emetteur: sa trame, emise depuis
    /// `mac`, et son temoin, qui exige cette source Ethernet.
    fn forme_de(
        id: &'static str,
        mac: &str,
        (trame, temoin): (Vec<u8>, String),
        fuite: usize,
    ) -> Forme {
        Forme {
            id,
            trame: depuis(mac, trame),
            temoin: format!("ether src {mac} and {temoin}"),
            fuite,
        }
    }

    fn udp4(s: std::net::Ipv4Addr, sp: u16, d: std::net::Ipv4Addr, dp: u16) -> (Vec<u8>, String) {
        (
            trame_ipv4(s, d, 0, &udp(sp, dp)),
            format!(
                "ip and src host {s} and dst host {d} and udp src port {sp} and udp dst port {dp}"
            ),
        )
    }

    fn udp6(s: std::net::Ipv6Addr, sp: u16, d: std::net::Ipv6Addr, dp: u16) -> (Vec<u8>, String) {
        (
            trame_ipv6(s, d, false, &udp(sp, dp)),
            format!(
                "ip6 and {} and {} and udp src port {sp} and udp dst port {dp}",
                hote6("src", s),
                hote6("dst", d)
            ),
        )
    }

    fn tcp4(
        s: std::net::Ipv4Addr,
        sp: u16,
        d: std::net::Ipv4Addr,
        dp: u16,
        drapeaux: u8,
    ) -> (Vec<u8>, String) {
        let segment = tcp(sp, dp, drapeaux);
        (
            trame_ipv4_de(s, d, 6, &[], 0, &segment),
            format!(
                "ip and src host {s} and dst host {d} and tcp src port {sp} \
                 and tcp dst port {dp} and tcp[13] == {drapeaux}"
            ),
        )
    }

    fn icmp4(
        s: std::net::Ipv4Addr,
        d: std::net::Ipv4Addr,
        type_: u8,
        code: u8,
    ) -> (Vec<u8>, String) {
        (
            trame_ipv4_de(s, d, 1, &[], 0, &icmp(type_, code, &[0; 36])),
            format!(
                "ip and src host {s} and dst host {d} and icmp[0] == {type_} and icmp[1] == {code}"
            ),
        )
    }

    /// Un rapport IGMPv3 (protocole 2), sous l'option Router Alert.
    fn igmp3(s: std::net::Ipv4Addr, d: std::net::Ipv4Addr) -> (Vec<u8>, String) {
        let rapport = [0x22, 0, 0, 0, 0, 0, 0, 1, 4, 0, 0, 0, 224, 0, 0, 251];
        (
            trame_ipv4_de(s, d, 2, &[0x94, 0x04, 0x00, 0x00], 0, &rapport),
            format!("ip and src host {s} and dst host {d} and ip[9] == 2"),
        )
    }

    /// Un message ICMPv6 de type `type_`, directement sous l'en-tete IPv6.
    fn icmp6_de(s: std::net::Ipv6Addr, d: std::net::Ipv6Addr, type_: u8) -> (Vec<u8>, String) {
        (
            trame_ipv6_de(s, d, false, 58, &icmp(type_, 0, &[0; 36])),
            format!(
                "ip6 and {} and {} and ip6[6] == 58 and ip6[40] == {type_}",
                hote6("src", s),
                hote6("dst", d)
            ),
        )
    }

    /// Un rapport MLDv2 (ICMPv6 143) derriere un en-tete Hop-by-Hop, la forme
    /// que le noyau emet: un enregistrement, sans source, pour `ff02::1:ff00:c`.
    fn mld2(s: std::net::Ipv6Addr, d: std::net::Ipv6Addr) -> (Vec<u8>, String) {
        let mut corps = vec![0, 0, 0, 1, 4, 0, 0, 0];
        corps.extend_from_slice(
            &"ff02::1:ff00:c"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets(),
        );
        (
            trame_ipv6_de(s, d, true, 58, &icmp(143, 0, &corps)),
            format!(
                "ip6 and {} and {} and ip6[6] == 0 and ip6[40] == 58 and ip6[48] == 143",
                hote6("src", s),
                hote6("dst", d)
            ),
        )
    }

    /// Le filtre de fuite ne compte que ce que le CLIENT emet hors de la
    /// sortie du kill switch: chaque forme de sa table, jugee par son
    /// emetteur et par sa forme.
    ///
    /// GARDE SANS ROOT, comme la precedente: un pcap synthetique d'une trame
    /// par forme, relu par [`relever`] sous [`leak_filter`] et sous
    /// [`ipv6_filter`], qui doit compter les formes IPv6 comme le premier et
    /// aucune autre. Chaque forme a son temoin, qui exige sa source Ethernet.
    /// Adresses du banc (`netns.rs`): client 10.77.0.2, fd00:77::2 et
    /// [`CLIENT_MAC`], passerelle 10.77.0.1; une adresse de lien par cote,
    /// fe80::c pour le client et fe80::1 pour la passerelle. Le banc laisse le
    /// noyau tirer l'adresse MAC de la passerelle; la table lui donne
    /// 02:00:00:77:00:01.
    ///
    /// Emises par le client, comptees (1); la sortie du kill switch les
    /// refuse, LAN ferme:
    /// - V1 a V4, quatre formes relevees le 11/10/2026, que l'ancien filtre
    ///   exemptait par leur destination: 10.77.0.2:40000 ->
    ///   255.255.255.255:67; [fe80::c]:546 -> [ff02::1]:547; 10.77.0.2:68 ->
    ///   224.0.0.1:67; [fe80::c]:546 -> [ff02::1:3]:547;
    /// - M1, M2 mDNS vers 224.0.0.251:5353 et [ff02::fb]:5353;
    /// - S1 SSDP vers 239.255.255.250:1900;
    /// - L1, L2 LLMNR vers 224.0.0.252:5355 et [ff02::1:3]:5355;
    /// - G1 rapport IGMPv3 vers 224.0.0.22 (protocole 2, option Router Alert);
    /// - R1, R2 rapports MLDv2 vers ff02::16, derriere un en-tete Hop-by-Hop,
    ///   depuis fe80::c et depuis `::`: la forme que le client emet quand son
    ///   lien monte, et que le kill switch arme a jetee au retour de la
    ///   porteuse (mesure du 11/10/2026);
    /// - E1 ICMPv6 echo (type 128) vers ff02::1, hors NDP;
    /// - D1, D2 diffusion dirigee du sous-reseau du banc, 10.77.0.255: un
    ///   DHCPv4 68 -> 67 et un NetBIOS 137 -> 137;
    /// - P1 a P3, des sondes de la suite, vues sur le lien le 11/10/2026: UDP
    ///   et TCP SYN vers 10.77.0.1:9999 (la sonde de lien des temoins), UDP
    ///   vers [2001:db8::1]:1234.
    ///
    /// Emises par le client, non comptees (0); la sortie les admet:
    /// - A1, A2 DHCPv4 68 -> 67 vers la diffusion, depuis 0.0.0.0 et
    ///   10.77.0.2;
    /// - A3, A4 DHCPv6 546 -> 547 vers ff02::1:2 et ff05::1:3;
    /// - A5 a A9 ICMPv6 133 a 137 (NDP), A7 etant le NS de detection
    ///   d'adresse dupliquee, depuis `::`;
    /// - A10 WireGuard vers 10.77.0.1:51820;
    /// - A11 une requete ARP, qui n'est pas de l'IP.
    ///
    /// Emises par la passerelle, non comptees (0):
    /// - Q1, Q2 rapports MLDv2 vers ff02::16, depuis fe80::1 et depuis `::`
    ///   (la forme de la trame relevee le 11/10/2026 dans `coupure-lien`);
    /// - Q3 un NS de detection d'adresse dupliquee;
    /// - Q4 ICMP port injoignable et Q5 TCP RST vers 10.77.0.2, ses reponses
    ///   a la sonde de lien;
    /// - Q6 WireGuard de 10.77.0.1:51820 vers le client.
    ///
    /// Sans tcpdump, la garde s'abstient en le nommant, comme la precedente.
    #[test]
    fn le_filtre_de_fuite_juge_chaque_forme_par_son_emetteur() {
        use super::super::netns::{CLIENT_ADDR, CLIENT_ADDR6, PHYS_ADDR, PREFIX};
        use std::net::{Ipv4Addr, Ipv6Addr};
        if Command::new("tcpdump")
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_err()
        {
            println!(
                "SKIPPED le_filtre_de_fuite_juge_chaque_forme_par_son_emetteur: \
                 tcpdump absent"
            );
            return;
        }
        const PASSERELLE: &str = "02:00:00:77:00:01";
        let client = CLIENT_MAC;
        let v6 = |a: &str| -> Ipv6Addr { a.parse().unwrap() };
        let c4: Ipv4Addr = CLIENT_ADDR.parse().unwrap();
        let p4: Ipv4Addr = PHYS_ADDR.parse().unwrap();
        let c6: Ipv6Addr = CLIENT_ADDR6.parse().unwrap();
        let prefixe: u32 = PREFIX.parse().unwrap();
        let dirigee = Ipv4Addr::from(u32::from(c4) | (u32::MAX >> prefixe));
        let (lien_c, lien_p, nulle) = (v6("fe80::c"), v6("fe80::1"), Ipv6Addr::UNSPECIFIED);
        let rapports = v6("ff02::16");
        let groupe4 = |d: u8| Ipv4Addr::new(224, 0, 0, d);

        let formes = vec![
            forme_de("V1", client, udp4(c4, 40000, Ipv4Addr::BROADCAST, 67), 1),
            forme_de("V2", client, udp6(lien_c, 546, v6("ff02::1"), 547), 1),
            forme_de("V3", client, udp4(c4, 68, groupe4(1), 67), 1),
            forme_de("V4", client, udp6(lien_c, 546, v6("ff02::1:3"), 547), 1),
            forme_de("M1", client, udp4(c4, 5353, groupe4(251), 5353), 1),
            forme_de("M2", client, udp6(lien_c, 5353, v6("ff02::fb"), 5353), 1),
            forme_de(
                "S1",
                client,
                udp4(c4, 40001, Ipv4Addr::new(239, 255, 255, 250), 1900),
                1,
            ),
            forme_de("L1", client, udp4(c4, 40002, groupe4(252), 5355), 1),
            forme_de("L2", client, udp6(lien_c, 40002, v6("ff02::1:3"), 5355), 1),
            forme_de("G1", client, igmp3(c4, groupe4(22)), 1),
            forme_de("R1", client, mld2(lien_c, rapports), 1),
            forme_de("R2", client, mld2(nulle, rapports), 1),
            forme_de("E1", client, icmp6_de(lien_c, v6("ff02::1"), 128), 1),
            forme_de("D1", client, udp4(c4, 68, dirigee, 67), 1),
            forme_de("D2", client, udp4(c4, 137, dirigee, 137), 1),
            forme_de("P1", client, udp4(c4, 40004, p4, 9999), 1),
            forme_de("P2", client, tcp4(c4, 40005, p4, 9999, 0x02), 1),
            forme_de("P3", client, udp6(c6, 40006, v6("2001:db8::1"), 1234), 1),
            forme_de(
                "A1",
                client,
                udp4(Ipv4Addr::UNSPECIFIED, 68, Ipv4Addr::BROADCAST, 67),
                0,
            ),
            forme_de("A2", client, udp4(c4, 68, Ipv4Addr::BROADCAST, 67), 0),
            forme_de("A3", client, udp6(lien_c, 546, v6("ff02::1:2"), 547), 0),
            forme_de("A4", client, udp6(lien_c, 546, v6("ff05::1:3"), 547), 0),
            forme_de("A5", client, icmp6_de(lien_c, v6("ff02::2"), 133), 0),
            forme_de("A6", client, icmp6_de(lien_c, v6("ff02::1"), 134), 0),
            forme_de("A7", client, icmp6_de(nulle, v6("ff02::1:ff00:2"), 135), 0),
            forme_de("A8", client, icmp6_de(lien_c, lien_p, 136), 0),
            forme_de("A9", client, icmp6_de(lien_c, lien_p, 137), 0),
            forme_de("A10", client, udp4(c4, 40007, p4, WG_PORT), 0),
            forme_de("A11", client, (trame_arp(c4, p4), "arp".to_owned()), 0),
            forme_de("Q1", PASSERELLE, mld2(lien_p, rapports), 0),
            forme_de("Q2", PASSERELLE, mld2(nulle, rapports), 0),
            forme_de(
                "Q3",
                PASSERELLE,
                icmp6_de(nulle, v6("ff02::1:ff00:1"), 135),
                0,
            ),
            forme_de("Q4", PASSERELLE, icmp4(p4, c4, 3, 3), 0),
            forme_de("Q5", PASSERELLE, tcp4(p4, 9999, c4, 40005, 0x04), 0),
            forme_de("Q6", PASSERELLE, udp4(p4, WG_PORT, c4, 40007), 0),
        ];

        let (fuite, fuite6) = (leak_filter(), ipv6_filter());
        let mut ecarts = Vec::new();
        for f in &formes {
            let chemin = std::env::temp_dir().join(format!(
                "bifrost-emetteur-{}-{}.pcap",
                f.id,
                std::process::id()
            ));
            pcap_d_une_trame(&chemin, &f.trame).expect("pcap synthetique ecrit");
            let attendue6 = if f.trame[12..14] == [0x86, 0xdd] {
                f.fuite
            } else {
                0
            };
            let vue = relever(&chemin, &f.temoin).map(|r| r.compte);
            let comptee = relever(&chemin, &fuite).map(|r| r.compte);
            let comptee6 = relever(&chemin, &fuite6).map(|r| r.compte);
            let _ = std::fs::remove_file(&chemin);
            match (vue, comptee, comptee6) {
                (Ok(1), Ok(n), Ok(n6)) if n == f.fuite && n6 == attendue6 => {}
                (vue, comptee, comptee6) => ecarts.push(format!(
                    "{}: temoin {vue:?} (1 attendu), fuite {comptee:?} ({} attendu), \
                     ipv6 {comptee6:?} ({attendue6} attendu)",
                    f.id, f.fuite
                )),
            }
        }
        assert!(
            ecarts.is_empty(),
            "formes mal jugees par les filtres de fuite:\n{}\nfiltre: {fuite}\nfiltre ipv6: {fuite6}",
            ecarts.join("\n")
        );
    }

    /// Une relecture refusee n'est pas une capture vide.
    ///
    /// Les trois plaintes sont celles que tcpdump 4.99.4 a ecrites le
    /// 30/09/2026 sur la machine d'essai: un pcap du compte de tcpdump en 0600
    /// relu par root sans CAP_DAC_OVERRIDE, un fichier absent, un filtre
    /// casse. Toutes sortaient en code 1, et toutes se lisaient << zero
    /// paquet >>.
    #[test]
    fn une_relecture_refusee_n_est_pas_une_capture_vide() {
        let plaintes = [
            "tcpdump: /tmp/bifrost-check-exit-ip-1-5.pcap: Permission denied\n",
            "tcpdump: /tmp/bifrost-check-dns-1-2.pcap: No such file or directory\n",
            "reading from file /tmp/x.pcap, link-type EN10MB (Ethernet), snapshot length \
             128\ntcpdump: can't parse filter expression: syntax error\n",
        ];
        for plainte in plaintes {
            let dernier = plainte.trim_end().rsplit(": ").next().unwrap_or(plainte);
            match juger_la_relecture(false, "", plainte) {
                Ok(r) => panic!(
                    "relecture refusee lue comme {} paquet(s): {plainte}",
                    r.compte
                ),
                Err(e) => assert!(
                    e.to_string().contains(dernier),
                    "la raison ne rapporte pas la plainte '{dernier}': {e}"
                ),
            }
        }
    }

    /// La troncature, elle, reste une relecture: ce qui precede la coupure est
    /// compte, et un fichier sans en-tete est un fichier sans paquet. Les deux
    /// plaintes ont ete relevees le meme jour, sur un fichier vide et sur un
    /// pcap coupe a 200 octets.
    #[test]
    fn une_troncature_rend_ce_qui_a_ete_lu() {
        let vide = juger_la_relecture(
            false,
            "",
            "tcpdump: truncated dump file; tried to read 4 file header bytes, only got 0\n",
        )
        .expect("un fichier sans en-tete est une capture sans paquet");
        assert_eq!(vide.compte, 0);

        let coupe = juger_la_relecture(
            false,
            "05:20:13.080239 IP 10.77.0.2.52480 > 10.77.0.1.51820: UDP, length 80\n",
            "reading from file /tmp/x.pcap, link-type EN10MB (Ethernet), snapshot \
             length 128\ntcpdump: pcap_loop: truncated dump file; tried to read 122 \
             captured bytes, only got 22\n",
        )
        .expect("ce qui precede la coupure a ete lu");
        assert_eq!(coupe.compte, 1, "le paquet lu avant la coupure a disparu");

        let lue = juger_la_relecture(true, "reading from file /tmp/x.pcap\n", "")
            .expect("une relecture reussie");
        assert_eq!(lue.compte, 0, "l'en-tete de tcpdump compte comme un paquet");
    }

    /// Un pcap qui a servi a etablir un PASSED est un dechet; un pcap qui a
    /// servi a un SKIPPED ou a un FAILED est une piece a conviction.
    ///
    /// Les deux moities comptent. Ne jamais effacer laisse vingt-trois fichiers
    /// root dans `/tmp` par passage; toujours effacer jette la seule trace de
    /// ce qui passait sur le lien quand un vecteur a renonce.
    #[test]
    fn le_pcap_s_efface_sauf_quand_il_sert_de_preuve() {
        let jetable =
            std::env::temp_dir().join(format!("bifrost-pcap-ephemere-{}.pcap", std::process::id()));
        std::fs::write(&jetable, b"pcap").expect("temoin ecrit");
        drop(Pcap::ephemere(jetable.clone()));
        assert!(
            !jetable.exists(),
            "le pcap d'un verdict etabli n'a pas ete efface: {}",
            jetable.display()
        );

        let preuve =
            std::env::temp_dir().join(format!("bifrost-pcap-garde-{}.pcap", std::process::id()));
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

    /// Le filtre de fuite ne doit jamais rapporter le trafic legitime, et ne
    /// juge que ce que le client emet.
    #[test]
    fn le_trafic_wireguard_n_est_pas_une_fuite() {
        let f = leak_filter();
        assert!(f.contains(&format!("dst host {PHYS_ADDR} and udp dst port {WG_PORT}")));
        assert!(
            f.starts_with(&format!("ether src {CLIENT_MAC} and (ip or ip6) and not (")),
            "le filtre ne juge plus par l'emetteur: {f}"
        );
    }

    /// Le filtre n'exempte que les clauses de la sortie du kill switch du
    /// banc: aucune exemption par reseau (ni `224.0.0.0/4`, ni `ff00::/8`, ni
    /// aucun `net`), et un port du DHCP n'y est nomme que dans la clause qui
    /// nomme aussi la destination que la regle nft lui donne: la diffusion
    /// pour 68 -> 67, `ff02::1:2` et `ff05::1:3` pour 546 -> 547. Nomme seul,
    /// un port exempterait le meme port vers toute adresse, y compris vers une
    /// destination que la chaine `output` refuse; une destination nommee seule
    /// exempterait tout ce qui la vise. La garde sans root juge chaque forme
    /// sur un pcap.
    #[test]
    fn seules_les_sorties_du_kill_switch_sont_exclues_des_fuites() {
        let a = allowed();
        let clauses: Vec<&str> = a
            .strip_prefix('(')
            .and_then(|a| a.strip_suffix(')'))
            .expect("allowed() n'est pas une suite de clauses parenthesees")
            .split(") or (")
            .collect();
        assert_eq!(clauses.len(), 4, "une clause de plus ou de moins: {a}");
        for c in &clauses {
            let mots: Vec<&str> = c
                .split(|x: char| x.is_whitespace() || x == '(' || x == ')')
                .filter(|m| !m.is_empty())
                .collect();
            assert!(!mots.contains(&"net"), "exemption par reseau: ({c})");
            let nomme = |m: &str| mots.contains(&m);
            let dhcp4 = nomme("68") || nomme("67") || nomme("255.255.255.255");
            if dhcp4 {
                for exige in ["src", "dst", "68", "67", "255.255.255.255"] {
                    assert!(nomme(exige), "clause DHCPv4 sans `{exige}`: ({c})");
                }
                assert_eq!(c.matches("port 68").count(), 1, "({c})");
                assert!(c.contains("udp src port 68 and udp dst port 67"), "({c})");
                assert!(c.contains("dst host 255.255.255.255"), "({c})");
            }
            let dhcp6 = nomme("546") || nomme("547") || nomme("ff02::1:2") || nomme("ff05::1:3");
            if dhcp6 {
                assert!(c.contains("udp src port 546 and udp dst port 547"), "({c})");
                assert!(
                    c.contains("(dst host ff02::1:2 or dst host ff05::1:3)"),
                    "clause DHCPv6 sans ses deux groupes, et eux seuls: ({c})"
                );
                assert_eq!(c.matches("dst host").count(), 2, "({c})");
            }
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
    /// pourrait declarer IPv6 etanche alors qu'une categorie a ete oubliee; il
    /// juge le meme emetteur.
    #[test]
    fn le_filtre_ipv6_reutilise_les_memes_exclusions() {
        let f = ipv6_filter();
        assert!(
            f.starts_with(&format!("{} and ip6 and not (", emises_par_le_client())),
            "{f}"
        );
        assert!(f.ends_with(&format!("{})", allowed())), "{f}");
        assert!(leak_filter().starts_with(&emises_par_le_client()));
    }
}
