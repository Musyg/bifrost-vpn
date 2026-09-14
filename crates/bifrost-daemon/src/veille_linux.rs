//! Le kill switch tient-il a travers une mise en veille, cote Linux.
//!
//! Le pendant de [`crate::wfp_veille`]. Meme question, meme refus de tourner en
//! namespace - la veille est globale mais les veth et les netns sont de la
//! memoire noyau qui la traverse intacte - et trois differences qui ont chacune
//! demande une mesure avant d'ecrire une ligne.
//!
//! # 1. Un drop nftables ne dit rien, contrairement a un refus WFP
//!
//! Sous Windows, une connexion refusee par un filtre rend une erreur nette, et
//! la sonde sait donc dire "un filtre a refuse". Sous Linux la chaine `output`
//! est en `policy drop`: le paquet disparait sans un mot et le `connect()`
//! EXPIRE. Mesure du 17 aout 2026 sur essai-linux, avec une regle ne visant
//! qu'une cible pour ne pas couper la machine:
//!
//! - cible jetee par un `drop` en `output`: le connect expire, aucun errno;
//! - cible jetee par un `reject`: `ECONNREFUSED`;
//! - cible en trou noir en amont: le connect expire, aucun errno.
//!
//! Blocage et trou noir se ressemblent donc trait pour trait. Une sonde fondee
//! sur l'errno rendrait "bloque" pour une machine dont l'amont ne repond pas
//! encore, ce qui est exactement l'etat d'une reprise. Le faux vert serait
//! garanti.
//!
//! # 2. Le compteur du ruleset donne le temoin positif qui manque
//!
//! La chaine `output` se termine par un `counter` sans verdict, pose pour le
//! diagnostic, juste avant que la policy jette. Tout paquet qui parvient jusque
//! la l'incremente. Or un paquet sans route n'y parvient jamais: il est refuse
//! par la couche route, avant tout hook. Le compteur separe donc les deux cas
//! que l'errno confond. Mesure du meme jour:
//!
//! - cible jetee: sonde expiree, compteur 0 -> 2 (les retransmissions du SYN);
//! - cible joignable: sonde connectee, compteur inchange;
//! - machine sans route (namespace vide): `ENETUNREACH` en 0.000s, et le
//!   paquet n'atteint aucune chaine.
//!
//! C'est pourquoi la sonde d'ici lit le compteur de part et d'autre de chaque
//! tentative plutot que de croire ce que `connect()` raconte.
//!
//! # 3. `Instant` ne compte PAS le temps suspendu, a l'inverse de Windows
//!
//! `CLOCK_MONOTONIC` s'arrete pendant la veille, `CLOCK_BOOTTIME` non. Leur
//! ecart est donc le temps total passe suspendu depuis le demarrage, et sa
//! progression est le temoin le plus direct qu'une veille a eu lieu: mieux
//! qu'un horodatage de journal, mieux qu'un code de retour. Mesure du 17 aout
//! 2026: 52.4s d'ecart apres une veille dont le journal du noyau dit
//! `PM: suspend entry (deep)` a 21:46:13 et `PM: suspend exit` a 21:47:08.
//!
//! Deux consequences. Le chien de garde d'ici n'a PAS a englober la duree de
//! sommeil, au contraire de celui de Windows: son `thread::sleep` ne progresse
//! pas pendant la veille. Et `retry_at` du superviseur, qui s'appuie sur
//! `Instant`, se comporte donc differemment des deux cotes: sous Windows une
//! echeance posee avant la veille arrive a l'heure, sous Linux elle est
//! retardee de toute la duree du sommeil.
//!
//! # Endormir la machine sans court-circuiter systemd
//!
//! `rtcwake -m mem` ecrit directement dans `/sys/power/state` et saute la
//! sequence systemd, donc `nvidia-suspend.service` ne tourne jamais et le
//! pilote rend `-EIO` sur une machine dont la memoire video est preservee. On
//! arme donc l'alarme seule, `rtcwake -m no -s N`, et on laisse `systemctl
//! suspend` endormir. Verifie sur essai-linux: veille profonde obtenue, et les
//! 66 services et les processus GPU retrouves intacts au reveil.

use std::net::{SocketAddr, TcpStream};
use std::process::Command;
use std::time::{Duration, Instant, SystemTime};

use bifrost_core::ports::FirewallPolicy;

/// Duree pendant laquelle on sonde sans relache apres la reprise.
///
/// Meme raison qu'ailleurs: la fenetre interessante precede le retour de
/// l'amont, mais elle doit durer assez pour que la pile ait essaye au moins une
/// fois, sans quoi la mesure se conclut a vide.
const FENETRE_REPRISE: Duration = Duration::from_secs(45);

/// Temps EVEILLE au bout duquel le chien de garde desarme d'office.
///
/// Ici, et seulement ici, il n'englobe pas la duree de sommeil: `thread::sleep`
/// s'appuie sur `CLOCK_MONOTONIC`, qui ne progresse pas pendant la veille. La
/// remarque inverse figure dans le module Windows, ou l'echeance doit au
/// contraire couvrir le sommeil.
const GARDE: Duration = Duration::from_secs(300);

/// En dessous, on n'a pas dormi.
const VEILLE_MINIMALE: Duration = Duration::from_secs(15);

/// Chaque tentative est courte: on ne cherche pas a attendre une eventuelle
/// reponse, seulement a faire partir des paquets et a regarder ou ils vont.
const DELAI_SONDE: Duration = Duration::from_millis(1200);

/// Ce que la sonde a pu etablir. Quatre issues et non trois: sous Linux,
/// "expire sans que le compteur bouge" ne veut dire ni bloque ni passe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Le paquet a traverse la chaine et la policy l'a jete. Seule issue qui
    /// PROUVE que le kill switch tient.
    Bloque,
    /// La connexion a abouti. Fuite.
    Connecte,
    /// La pile n'a meme pas essaye: pas de route. Attendu juste apres une
    /// reprise, et sans valeur de preuve dans un sens comme dans l'autre.
    SansRoute,
    /// Ni abouti, ni compte, ni refuse par la couche route. Le paquet est parti
    /// quelque part et s'y est perdu. Ne prouve rien non plus.
    Muet,
}

/// Temps total passe suspendu depuis le demarrage.
///
/// L'ecart entre l'horloge qui compte le sommeil et celle qui ne le compte pas.
/// Sa progression est ce qui decide qu'une veille a eu lieu.
fn temps_suspendu() -> Duration {
    let mut boottime = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let mut monotone = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: deux structures vivantes, passees en ecriture a l'appel systeme.
    unsafe {
        libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut boottime);
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut monotone);
    }
    let en_nanos = |t: &libc::timespec| t.tv_sec as i128 * 1_000_000_000 + t.tv_nsec as i128;
    let ecart = en_nanos(&boottime) - en_nanos(&monotone);
    Duration::from_nanos(ecart.max(0) as u64)
}

/// Lit le compteur de la chaine `output`, en paquets.
///
/// Rend `None` quand la table n'existe pas ou que la sortie est illisible.
/// Distinguer ce cas de la valeur zero est indispensable: une table absente est
/// un kill switch disparu, ce qui n'a rien a voir avec un compteur a zero.
fn lire_compteur() -> Option<u64> {
    let sortie = Command::new("nft")
        .args([
            "-j",
            "list",
            "table",
            "inet",
            bifrost_firewall::linux::ruleset::TABLE,
        ])
        .output()
        .ok()?;
    if !sortie.status.success() {
        return None;
    }
    let texte = String::from_utf8_lossy(&sortie.stdout);
    let json: serde_json::Value = serde_json::from_str(&texte).ok()?;
    for objet in json.get("nftables")?.as_array()? {
        let Some(regle) = objet.get("rule") else {
            continue;
        };
        if regle.get("comment").and_then(|c| c.as_str()) != Some("bifrost-output-dropped") {
            continue;
        }
        for expr in regle.get("expr")?.as_array()? {
            if let Some(compteur) = expr.get("counter") {
                return compteur.get("packets")?.as_u64();
            }
        }
    }
    None
}

/// Une tentative, encadree par deux lectures du compteur.
///
/// L'ordre compte: le compteur est lu AVANT, la tentative faite, le compteur
/// relu APRES. Lire une seule fois et comparer a une valeur gardee de plus loin
/// attribuerait a cette sonde des paquets emis par n'importe quoi d'autre sur
/// la machine.
fn sonder(cible: SocketAddr) -> Verdict {
    let avant = lire_compteur();
    let issue = TcpStream::connect_timeout(&cible, DELAI_SONDE);
    let apres = lire_compteur();

    if issue.is_ok() {
        return Verdict::Connecte;
    }
    if let (Some(a), Some(b)) = (avant, apres)
        && b > a
    {
        return Verdict::Bloque;
    }
    // `ENETUNREACH` et `EHOSTUNREACH` viennent de la couche route, avant tout
    // hook: le paquet n'est jamais parti, et le compteur ne pouvait pas bouger.
    if let Err(e) = &issue
        && matches!(
            e.raw_os_error(),
            Some(libc::ENETUNREACH) | Some(libc::EHOSTUNREACH)
        )
    {
        return Verdict::SansRoute;
    }
    Verdict::Muet
}

/// Ce que la veille a traverse.
#[derive(Debug)]
pub struct Traversee {
    pub murale: Duration,
    pub monotone: Duration,
    pub suspendu: Duration,
    pub sondes: usize,
    pub bloquees: usize,
    pub sans_route: usize,
    pub muettes: usize,
    pub ifindex_avant: Option<u32>,
    pub ifindex_apres: Option<u32>,
}

/// L'index que le noyau donne a cette interface, ou `None` si elle n'existe
/// pas.
///
/// Le pendant du LUID de Windows, a ceci pres que le ruleset autorise le tunnel
/// par son NOM (`oifname`), qui survit par construction a une recreation. Cet
/// index n'est donc pas ce qui fait tenir la regle: il est releve parce qu'un
/// changement signalerait que l'interface a ete recreee pendant la veille, ce
/// qui est bon a savoir meme quand cela ne casse rien.
fn ifindex(nom: &str) -> Option<u32> {
    std::fs::read_to_string(format!("/sys/class/net/{nom}/ifindex"))
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// Point d'entree de `--veille-selftest` sous Linux.
///
/// **Coupe tout le reseau de la machine** entre l'armement et le desarmement,
/// puis l'endort. Machine dediee capable de revenir seule uniquement.
pub fn selftest(cible: SocketAddr, dormir: Duration, tunnel: Option<&str>) -> anyhow::Result<()> {
    eprintln!(
        "AVERTISSEMENT: cet autotest coupe tout le reseau de cette machine, PUIS \
         l'endort. Machine dediee capable de revenir seule uniquement."
    );

    // SAFETY: geteuid ne prend pas d'argument et ne touche aucune memoire.
    if unsafe { libc::geteuid() } != 0 {
        println!("SKIPPED: ce vecteur pose des regles nftables, il demande root.");
        std::process::exit(3);
    }

    // Le chien de garde avant tout armement: si le corps fige alors que les
    // filtres sont poses, une machine distante reste sans reseau et plus
    // personne ne peut y entrer pour la reparer.
    std::thread::spawn(chien_de_garde);

    let tunnel_interface = tunnel.map(str::to_owned);
    let ifindex_avant = tunnel.and_then(ifindex);
    match (tunnel, ifindex_avant) {
        (Some(nom), Some(i)) => println!("tunnel eprouve: {nom}, ifindex {i}"),
        (Some(nom), None) => anyhow::bail!("interface {nom} introuvable"),
        (None, _) => println!(
            "SKIPPED (partiel): aucune interface de tunnel donnee. La survie du \
             permit du tunnel ne sera pas mesuree."
        ),
    }

    // Temoin negatif, au repos. Sans lui, un blocage constate plus tard ne
    // prouverait rien: une cible deja muette donnerait le meme resultat.
    match sonder(cible) {
        Verdict::Connecte => {}
        autre => {
            println!(
                "SKIPPED: au repos, {cible} n'aboutit pas ({autre:?}). La mesure ne \
                 peut rien conclure d'un blocage sur une cible deja muette."
            );
            std::process::exit(3);
        }
    }

    let policy = FirewallPolicy {
        tunnel_interface,
        tunnel_luid: None,
        // Le fwmark reel et non zero. Zero rendrait `meta mark 0x0 accept`,
        // qui matche tout paquet non marque: le kill switch serait un
        // laissez-passer et la mesure un faux vert. C'est exactement ce qui
        // s'est produit au premier essai, avant que `engage` refuse ce cas.
        fwmark: Some(bifrost_core::config::DEFAULT_FWMARK),
        dns_resolver: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        allow_lan: false,
        coeur_uid: None,
        coeur_executable: None,
        resolveur_uid: None,
        resolveur_executable: None,
        resolveur_sid: None,
        resolveur_embarque: false,
    };

    // L'alarme est armee AVANT que le reseau ne soit coupe: si la plateforme ne
    // sait pas se reveiller, on l'apprend tant que la machine est joignable.
    if let Err(e) = armer_reveil(dormir) {
        println!("SKIPPED: {e}");
        std::process::exit(3);
    }

    let mut firewall = bifrost_firewall::new().map_err(|e| anyhow::anyhow!("{e}"))?;
    firewall
        .engage(&policy)
        .map_err(|e| anyhow::anyhow!("armement impossible: {e}"))?;

    println!("\nendormissement pour {dormir:?}, sondes vers {cible}...");
    let resultat = traverser(cible, dormir, tunnel);
    let desarme = firewall.disengage();

    // Le desarmement prime sur la lecture du resultat.
    desarme.map_err(|e| anyhow::anyhow!("desarmement impossible: {e}"))?;

    let (verdict, traversee) = resultat?;
    if let Some(t) = &traversee {
        println!("\nce que la veille a traverse:");
        println!("  horloge murale : {:?}", t.murale);
        println!("  Instant        : {:?}", t.monotone);
        println!(
            "  temps suspendu : {:?}  (BOOTTIME moins MONOTONIC)",
            t.suspendu
        );
        println!(
            "  sondes apres reprise : {} dont {} bloquees, {} sans route, {} muettes",
            t.sondes, t.bloquees, t.sans_route, t.muettes
        );
        match (t.ifindex_avant, t.ifindex_apres) {
            (Some(a), Some(b)) if a == b => println!("  ifindex du tunnel : {a}, inchange"),
            (Some(a), Some(b)) => println!("  ifindex du tunnel : {a} PUIS {b}"),
            (Some(a), None) => println!("  ifindex du tunnel : {a} PUIS interface disparue"),
            _ => println!("  ifindex du tunnel : non mesure"),
        }
    }

    match verdict {
        Issue::Reussi(bloquees) => {
            println!(
                "\nvecteur veille: le kill switch a tenu a travers la mise en veille \
                 ({bloquees} sonde(s) comptee(s) par le ruleset apres la reprise)"
            );
            Ok(())
        }
        Issue::Ignore(raison) => {
            println!("\nSKIPPED: {raison}");
            std::process::exit(3);
        }
        Issue::Echec(raison) => {
            eprintln!("\nECHEC: {raison}");
            anyhow::bail!("le vecteur veille a echoue")
        }
    }
}

enum Issue {
    Reussi(usize),
    Ignore(String),
    Echec(String),
}

/// Le corps, kill switch arme. Separe pour que l'appelant desarme sur tous les
/// chemins, y compris celui de l'erreur.
fn traverser(
    cible: SocketAddr,
    dormir: Duration,
    tunnel: Option<&str>,
) -> anyhow::Result<(Issue, Option<Traversee>)> {
    // Sous armement, avant de dormir: le blocage doit deja etre effectif, et
    // surtout COMPTE. Un simple silence ne suffirait pas a le dire.
    match sonder(cible) {
        Verdict::Bloque => {}
        autre => {
            return Ok((
                Issue::Echec(format!(
                    "le kill switch arme ne bloque pas AVANT la veille ({autre:?}): \
                     inutile de mesurer ce qu'il en reste apres"
                )),
                None,
            ));
        }
    }

    let ifindex_avant = tunnel.and_then(ifindex);
    let murale_avant = SystemTime::now();
    let monotone_avant = Instant::now();
    let suspendu_avant = temps_suspendu();

    // `systemctl suspend` rend la main aussitot: la veille arrive ensuite.
    let sortie = Command::new("systemctl").arg("suspend").output()?;
    if !sortie.status.success() {
        return Ok((
            Issue::Ignore(format!(
                "systemctl suspend a echoue: {}",
                String::from_utf8_lossy(&sortie.stderr).trim()
            )),
            None,
        ));
    }

    // On guette la reprise sur le seul temoin qui ne peut pas mentir: le temps
    // passe suspendu. Ni le code de retour ci-dessus, ni l'horodatage d'un
    // journal ne disent qu'une veille a eu lieu.
    // La duree de sommeil demandee s'ajoute a la marge: une machine qui met du
    // temps a revenir n'est pas une machine qui ne revient pas.
    let limite = Instant::now() + dormir + Duration::from_secs(180);
    while temps_suspendu().saturating_sub(suspendu_avant) < VEILLE_MINIMALE
        && Instant::now() < limite
    {
        std::thread::sleep(Duration::from_millis(100));
    }
    let suspendu = temps_suspendu().saturating_sub(suspendu_avant);
    let murale = SystemTime::now()
        .duration_since(murale_avant)
        .unwrap_or_default();
    let monotone = monotone_avant.elapsed();

    if suspendu < VEILLE_MINIMALE {
        return Ok((
            Issue::Ignore(format!(
                "la machine n'a pas dormi: l'ecart entre BOOTTIME et MONOTONIC n'a \
                 avance que de {suspendu:?} en {murale:?} d'horloge murale. Demande \
                 de veille acceptee mais jamais honoree."
            )),
            None,
        ));
    }

    // La fenetre qui compte. On sonde sans relache: c'est ici que des regles
    // disparues laisseraient passer, et l'amont ne repond pas encore.
    let mut sondes = 0usize;
    let (mut bloquees, mut sans_route, mut muettes) = (0usize, 0usize, 0usize);
    let fin = Instant::now() + FENETRE_REPRISE;
    let mut fuite = None;
    while Instant::now() < fin {
        sondes += 1;
        match sonder(cible) {
            Verdict::Bloque => bloquees += 1,
            Verdict::SansRoute => sans_route += 1,
            Verdict::Muet => muettes += 1,
            Verdict::Connecte => {
                fuite = Some(format!(
                    "a la sonde {sondes}, {suspendu:?} de veille traversee et dans la \
                     fenetre de reprise, {cible} aboutit: les regles n'ont pas tenu"
                ));
                break;
            }
        }
    }

    let traversee = Some(Traversee {
        murale,
        monotone,
        suspendu,
        sondes,
        bloquees,
        sans_route,
        muettes,
        ifindex_avant,
        ifindex_apres: tunnel.and_then(ifindex),
    });

    if let Some(raison) = fuite {
        return Ok((Issue::Echec(raison), traversee));
    }
    if bloquees == 0 {
        return Ok((
            Issue::Ignore(format!(
                "la fenetre de reprise s'est ecoulee sans qu'un seul paquet soit \
                 compte par le ruleset ({sondes} sondes: {sans_route} sans route, \
                 {muettes} muettes): rien n'a ete mesure. Un vert ici ne vaudrait \
                 rien."
            )),
            traversee,
        ));
    }
    Ok((Issue::Reussi(bloquees), traversee))
}

/// Arme l'alarme RTC sans endormir.
fn armer_reveil(dans: Duration) -> Result<(), String> {
    let secondes = dans.as_secs().max(1).to_string();
    let sortie = Command::new("rtcwake")
        .args(["-m", "no", "-s", &secondes])
        .output()
        .map_err(|e| format!("rtcwake introuvable: {e}"))?;
    if !sortie.status.success() {
        return Err(format!(
            "rtcwake n'a pas pu armer l'alarme: {}",
            String::from_utf8_lossy(&sortie.stderr).trim()
        ));
    }
    Ok(())
}

/// Dernier recours: si le corps fige alors que les regles sont posees, la
/// machine reste sans reseau, et sur une machine distante plus personne ne peut
/// y entrer pour la reparer.
fn chien_de_garde() {
    std::thread::sleep(GARDE);
    eprintln!("chien de garde: reprise apres {GARDE:?}");
    for tentative in 1..=3 {
        match bifrost_firewall::new().and_then(|mut fw| fw.disengage()) {
            Ok(()) => {
                eprintln!("chien de garde: kill switch desarme");
                std::process::exit(3);
            }
            Err(e) => eprintln!("chien de garde: tentative {tentative} echouee: {e}"),
        }
    }
    eprintln!("chien de garde: desarmement impossible, la machine reste coupee");
    std::process::exit(1);
}
