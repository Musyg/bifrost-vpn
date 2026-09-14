//! Le temoin de blocage sous Windows: quel filtre a jete quel paquet.
//!
//! # Pourquoi ce module existe
//!
//! Le harnais de fuite Linux s'appuie sur les namespaces reseau, que Windows
//! n'a pas, et la suite s'y declarait donc `Skipped`. La reponse
//! n'est pas d'imiter les namespaces: c'est de se passer d'isolation.
//!
//! Sur Linux on isole parce qu'il faut couper du trafic sans tuer la session en
//! cours, et parce que le seul temoin disponible - le compteur de la chaine
//! `output` - dit qu'UN paquet a ete jete, sans dire lequel ni par quelle
//! regle. Windows offre mieux: les audits WFP 5157 (connexion bloquee) et 5152
//! (paquet bloque) portent le `FilterRTID`, l'identifiant du filtre PRECIS qui
//! a bloque, avec le processus, la destination et la couche.
//!
//! Comme `FwpmFilterAdd0` rend cet identifiant a la pose, on peut affirmer
//! "NOTRE filtre numero N a refuse CETTE connexion" au lieu de constater qu'une
//! connexion a echoue. La difference n'est pas theorique: une connexion qui
//! echoue parce que la cible est injoignable, parce qu'une route manque ou
//! parce qu'un antivirus s'en mele produit exactement la meme observation. La
//! lecon du vecteur Linux, ou `SansRoute` ne mesurait rien, s'applique mot pour
//! mot.
//!
//! Consequence: il devient inutile d'isoler. On bloque UNE destination, on
//! prouve que c'est notre filtre qui l'a bloquee, et la machine reste jointe.
//!
//! # Ce module n'active pas l'audit, et c'est delibere
//!
//! Changer un reglage de securite de la machine sans le dire serait une
//! mauvaise surprise, et un harnais qui modifie l'environnement qu'il mesure
//! n'est plus un temoin. Quand l'audit est eteint, l'appelant rend `Skipped`
//! avec la commande exacte, conformement a la regle du depot: jamais `Passed`
//! par defaut.
//!
//! # Comment on sait que l'audit est eteint
//!
//! Pas en lisant `auditpol`, dont la sortie est TRADUITE dans la langue du
//! systeme: la mesure dependrait de la locale de la machine, et sur le banc
//! elle rend deja du francais. Le critere est empirique et ne depend d'aucune
//! langue: si la fenetre observee ne contient AUCUN blocage WFP, pas meme ceux
//! du pare-feu Windows - dont le journal est autrement plein - c'est que
//! l'audit n'enregistre rien. S'il y en a mais aucun a nous, alors le blocage
//! attendu n'a pas eu lieu, ce qui est un vrai echec et non un test impossible.

use std::net::IpAddr;
use std::process::Command;
use std::time::Duration;

/// La commande a donner quand l'audit est eteint. Deux sous-categories: la
/// 5157 vient de la premiere, la 5152 de la seconde.
pub const COMMANDE_ACTIVATION: &str = concat!(
    "auditpol /set /subcategory:\"Filtering Platform Connection\" /failure:enable\n",
    "auditpol /set /subcategory:\"Filtering Platform Packet Drop\" /failure:enable"
);

/// Un blocage constate par WFP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Blocage {
    /// `FilterRTID`: l'identifiant d'execution du filtre qui a bloque. C'est
    /// celui que rend `FwpmFilterAdd0`, donc celui qu'on confronte aux notres.
    pub filtre: u64,
    /// `LayerRTID`: la couche ou le blocage a eu lieu.
    pub couche: u64,
    /// Chemin NT du binaire, en minuscules.
    pub application: String,
    pub destination: Option<IpAddr>,
    pub port: Option<u16>,
    pub protocole: Option<u8>,
}

impl Blocage {
    /// Ce blocage vient-il d'un de nos filtres, vers la cible attendue?
    ///
    /// Les deux conditions comptent. L'identifiant seul suffirait en theorie,
    /// mais le confronter a la destination attrape le cas ou un identifiant
    /// aurait ete recycle entre la pose et la lecture.
    pub fn correspond(&self, filtres: &[u64], cible: IpAddr, port: u16) -> bool {
        filtres.contains(&self.filtre) && self.destination == Some(cible) && self.port == Some(port)
    }
}

/// Ce qu'une fenetre d'observation a rendu.
#[derive(Debug, Clone)]
pub struct Constat {
    /// TOUS les blocages WFP de la fenetre, les notres comme ceux des autres.
    /// Un total nul est le signe que l'audit n'enregistre pas.
    pub total: usize,
    /// Ceux qui viennent de nos filtres et visent la cible attendue.
    pub notres: Vec<Blocage>,
}

impl Constat {
    /// L'audit semble-t-il eteint?
    ///
    /// Sur une machine vivante, une fenetre de quelques secondes contient
    /// presque toujours un blocage du pare-feu Windows: sondes SSDP, mDNS,
    /// decouverte de voisinage. Zero blocage n'est donc pas "rien a signaler",
    /// c'est "personne n'ecoute".
    pub fn audit_muet(&self) -> bool {
        self.total == 0
    }
}

/// Observe les blocages des `fenetre` dernieres millisecondes.
///
/// Passe par `wevtutil` en sortie XML, et NON par le message rendu de
/// l'evenement: ce message est traduit dans la langue du systeme. Le XML porte
/// des noms de champs stables.
pub fn constater(
    fenetre: Duration,
    filtres: &[u64],
    cible: IpAddr,
    port: u16,
) -> anyhow::Result<Constat> {
    let blocages = lire(fenetre)?;
    let notres = blocages
        .iter()
        .filter(|b| b.correspond(filtres, cible, port))
        .cloned()
        .collect();
    Ok(Constat {
        total: blocages.len(),
        notres,
    })
}

fn lire(fenetre: Duration) -> anyhow::Result<Vec<Blocage>> {
    let ms = fenetre.as_millis().max(1);
    let requete = format!(
        "*[System[(EventID=5157 or EventID=5152) and TimeCreated[timediff(@SystemTime) <= {ms}]]]"
    );
    let sortie = Command::new("wevtutil")
        .arg("qe")
        .arg("Security")
        .arg(format!("/q:{requete}"))
        .args(["/f:xml", "/c:400", "/rd:true"])
        .output()
        .map_err(|e| anyhow::anyhow!("wevtutil introuvable: {e}"))?;

    if !sortie.status.success() {
        anyhow::bail!(
            "wevtutil a echoue: {}",
            String::from_utf8_lossy(&sortie.stderr).trim()
        );
    }

    let texte = String::from_utf8_lossy(&sortie.stdout);
    Ok(texte.split("<Event ").filter_map(analyser).collect())
}

/// Extrait la valeur d'un `<Data Name='...'>`.
///
/// Analyseur a la main plutot qu'une dependance XML: le format est fige par le
/// schema d'audit de Windows, les valeurs sont des nombres, des adresses et des
/// chemins, et aucune ne peut contenir de balise.
fn champ<'a>(bloc: &'a str, nom: &str) -> Option<&'a str> {
    let motif = format!("<Data Name='{nom}'>");
    let debut = bloc.find(&motif)? + motif.len();
    let reste = &bloc[debut..];
    let fin = reste.find("</Data>")?;
    Some(&reste[..fin])
}

fn analyser(bloc: &str) -> Option<Blocage> {
    // Sans identifiant de filtre l'evenement ne prouve rien: c'est le champ qui
    // distingue notre blocage de ceux du pare-feu Windows, dont le journal est
    // plein.
    let filtre = champ(bloc, "FilterRTID")?.parse().ok()?;
    let couche = champ(bloc, "LayerRTID")?.parse().ok()?;
    Some(Blocage {
        filtre,
        couche,
        application: champ(bloc, "Application")
            .unwrap_or_default()
            .to_lowercase(),
        destination: champ(bloc, "DestAddress").and_then(|v| v.parse().ok()),
        port: champ(bloc, "DestPort").and_then(|v| v.parse().ok()),
        protocole: champ(bloc, "Protocol").and_then(|v| v.parse().ok()),
    })
}

/// Eprouve le temoin de bout en bout, sans couper la machine.
///
/// Pose un blocage sur UNE adresse, tente la connexion, et verifie que le
/// journal d'audit nomme bien NOTRE filtre. La machine reste jointe: tout le
/// reste passe.
///
/// Trois mesures, parce qu'aucune ne suffit seule, exactement comme dans
/// `wfp_leaktest`:
///
/// 1. la connexion vers la cible doit etre REFUSEE par WFP, pas expirer;
/// 2. le journal doit porter un blocage a l'un de NOS identifiants vers cette
///    cible. C'est la mesure neuve, celle qui rend l'isolation inutile;
/// 3. la connexion vers le temoin doit ABOUTIR. Sans elle, une machine sans
///    reseau rendrait les deux premieres et on certifierait une etancheite
///    jamais observee.
pub fn selftest(cible: std::net::Ipv4Addr, temoin: std::net::Ipv4Addr) -> anyhow::Result<()> {
    const PORT: u16 = 443;
    const DELAI: Duration = Duration::from_millis(2500);
    /// Le journal d'audit n'est pas ecrit dans la foulee de la connexion.
    const FENETRE: Duration = Duration::from_secs(30);

    let ids = crate::boot_filtres::poser_et_rendre_ids(cible, None)?;
    println!("filtres poses, identifiants d'execution: {ids:?}");

    // Le retrait doit avoir lieu meme si une mesure echoue: des filtres
    // persistants laisses derriere survivraient au processus ET au redemarrage.
    let resultat = mesurer(cible, temoin, PORT, DELAI, FENETRE, &ids);
    let retrait = crate::boot_filtres::retirer(&[]);
    resultat?;
    retrait?;
    println!(
        "
temoin WFP valide: un blocage est attribuable au filtre qui l'a pose"
    );
    Ok(())
}

fn mesurer(
    cible: std::net::Ipv4Addr,
    temoin: std::net::Ipv4Addr,
    port: u16,
    delai: Duration,
    fenetre: Duration,
    ids: &[u64],
) -> anyhow::Result<()> {
    use std::net::{SocketAddr, TcpStream};

    use windows_sys::Win32::Networking::WinSock::WSAEACCES;

    let vers_cible = SocketAddr::from((cible, port));
    let erreur = TcpStream::connect_timeout(&vers_cible, delai).err();
    let refusee = matches!(
        erreur.as_ref().and_then(|e| e.raw_os_error()),
        Some(WSAEACCES)
    );
    println!(
        "1. connexion vers {cible}:{port} -> {}",
        match &erreur {
            None => "ABOUTIE (le filtre ne bloque pas)".to_owned(),
            Some(e) if refusee => format!("refusee par WFP ({e})"),
            Some(e) => format!("echec SANS refus WFP ({e})"),
        }
    );
    if !refusee {
        anyhow::bail!(
            "la connexion n'a pas ete refusee par WFP: le blocage n'est pas en place, et le reste de la mesure ne prouverait rien"
        );
    }

    // Le journal de securite n'est pas ecrit dans la foulee de la connexion:
    // une premiere lecture immediate a deja rendu "36 blocages, aucun a nous"
    // alors que le notre y figurait quelques secondes plus tard. Sonder une
    // seule fois transformerait donc ce delai d'ecriture en echec d'etancheite,
    // ce qui est exactement le genre de faux rouge qui fait perdre confiance
    // dans un harnais.
    const PATIENCE: Duration = Duration::from_secs(20);
    const PAS: Duration = Duration::from_millis(500);
    let debut = std::time::Instant::now();
    let mut constat = constater(fenetre, ids, cible.into(), port)?;
    while constat.notres.is_empty() && debut.elapsed() < PATIENCE {
        std::thread::sleep(PAS);
        constat = constater(fenetre, ids, cible.into(), port)?;
    }
    if !constat.notres.is_empty() {
        println!("   (blocage trouve apres {:?})", debut.elapsed());
    }
    println!(
        "2. journal d'audit: {} blocages WFP dans la fenetre, dont {} a nous",
        constat.total,
        constat.notres.len()
    );
    if constat.audit_muet() {
        anyhow::bail!(
            "aucun blocage WFP dans le journal, pas meme ceux du pare-feu Windows: l'audit n'enregistre rien. Ce n'est pas un echec d'etancheite, c'est une mesure impossible. A activer avec:
{COMMANDE_ACTIVATION}"
        );
    }
    match constat.notres.first() {
        Some(b) => println!(
            "   filtre {} a la couche {}, application {}",
            b.filtre,
            b.couche,
            b.application.rsplit('\\').next().unwrap_or("?")
        ),
        None => anyhow::bail!(
            "le journal porte {} blocages mais aucun a nos filtres {ids:?} vers {cible}:{port}. La connexion a donc ete refusee par quelqu'un d'autre, et l'attribuer a notre kill switch certifierait une etancheite qu'on n'a pas posee",
            constat.total
        ),
    }

    let vers_temoin = SocketAddr::from((temoin, port));
    match TcpStream::connect_timeout(&vers_temoin, delai) {
        Ok(_) => println!("3. temoin {temoin}:{port} -> aboutie, la machine a bien du reseau"),
        Err(e) => anyhow::bail!(
            "le temoin {temoin}:{port} n'aboutit pas ({e}): la machine n'a pas de reseau, donc le refus mesure plus haut ne prouve rien"
        ),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Un evenement reel du banc, ampute de tout ce qui identifierait une
    /// machine: le XML d'audit porte le nom de l'ordinateur, qui n'a rien a
    /// faire dans un depot.
    const EXEMPLE: &str = "<Event xmlns='x'><System><EventID>5157</EventID></System>\
<EventData><Data Name='ProcessID'>6508</Data>\
<Data Name='Application'>\\device\\harddiskvolume3\\essai\\bifrost-daemon.exe</Data>\
<Data Name='Direction'>%%14592</Data><Data Name='SourceAddress'>192.0.2.9</Data>\
<Data Name='SourcePort'>50682</Data><Data Name='DestAddress'>1.1.1.1</Data>\
<Data Name='DestPort'>443</Data><Data Name='Protocol'>6</Data>\
<Data Name='InterfaceIndex'>24</Data><Data Name='FilterOrigin'>Unknown</Data>\
<Data Name='FilterRTID'>299508</Data><Data Name='LayerName'>%%14610</Data>\
<Data Name='LayerRTID'>48</Data></EventData></Event>";

    fn cible() -> IpAddr {
        "1.1.1.1".parse().unwrap()
    }

    #[test]
    fn un_evenement_reel_est_analyse_champ_par_champ() {
        let b = analyser(EXEMPLE).expect("l'evenement doit etre analysable");
        assert_eq!(b.filtre, 299508);
        assert_eq!(b.couche, 48);
        assert_eq!(b.destination, Some(cible()));
        assert_eq!(b.port, Some(443));
        assert_eq!(b.protocole, Some(6));
        assert!(b.application.ends_with("bifrost-daemon.exe"));
    }

    #[test]
    fn un_evenement_sans_identifiant_de_filtre_est_rejete() {
        // Il ne prouverait rien: ce champ, et lui seul, distingue notre blocage
        // de ceux du pare-feu Windows.
        let sans = EXEMPLE.replace("<Data Name='FilterRTID'>299508</Data>", "");
        assert!(analyser(&sans).is_none());
    }

    #[test]
    fn la_correspondance_exige_le_filtre_et_la_destination() {
        let b = analyser(EXEMPLE).unwrap();
        let autre: IpAddr = "9.9.9.9".parse().unwrap();

        assert!(b.correspond(&[299508], cible(), 443));
        // Bon filtre, mauvaise destination: un blocage sans rapport.
        assert!(!b.correspond(&[299508], autre, 443));
        // Bonne destination, filtre etranger: quelqu'un d'autre a bloque, et le
        // compter pour nous certifierait une etancheite qu'on n'a pas posee.
        assert!(!b.correspond(&[12345], cible(), 443));
        assert!(!b.correspond(&[], cible(), 443));
    }

    #[test]
    fn un_blocage_du_pare_feu_windows_ne_compte_pas_pour_le_notre() {
        // Extrait vrai du banc: svchost bloque par un filtre par defaut, vers
        // du SSDP. Sans tri par identifiant il compterait comme une preuve
        // d'etancheite de NOTRE kill switch.
        let etranger = EXEMPLE
            .replace(
                "<Data Name='FilterRTID'>299508</Data>",
                "<Data Name='FilterRTID'>297391</Data>",
            )
            .replace(
                "<Data Name='DestAddress'>1.1.1.1</Data>",
                "<Data Name='DestAddress'>239.255.255.250</Data>",
            );
        let b = analyser(&etranger).unwrap();
        assert!(!b.correspond(&[299508], cible(), 443));
    }

    #[test]
    fn un_journal_muet_se_distingue_d_un_journal_sans_blocage_a_nous() {
        // Les deux rendent zero blocage a nous, et n'ont rien a voir: le
        // premier est un test impossible, le second un echec d'etancheite.
        let muet = Constat {
            total: 0,
            notres: Vec::new(),
        };
        let bruyant = Constat {
            total: 12,
            notres: Vec::new(),
        };
        assert!(muet.audit_muet());
        assert!(!bruyant.audit_muet());
    }
}
