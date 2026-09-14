//! Le vecteur `exit-ip` sous Windows: la sortie passe par le tunnel, et rien
//! ne part en clair vers les memes destinations.
//!
//! # Ce que ce vecteur mesure, et ce qu'il ne mesure pas
//!
//! Son nom laisse croire qu'il compare des adresses publiques. Ce n'est le cas
//! ni ici ni sous Linux: la version Linux capture sur le lien du namespace et
//! verifie que rien n'y apparait en clair. C'est la meme question ici, posee a
//! une vraie machine plutot qu'a un namespace.
//!
//! # Trois pieges, tous rencontres en montant ce vecteur
//!
//! 1. **`pktmon` capture a plusieurs endroits de la pile.** Sans cadrage, la
//!    capture contient les paquets TCP EN CLAIR tels qu'ils entrent dans
//!    l'adaptateur du tunnel, avant chiffrement. Les compter comme des fuites
//!    ferait echouer le vecteur a chaque execution, y compris parfaitement
//!    etanche. La capture est donc bornee aux composants qui existaient AVANT
//!    la montee: l'adaptateur du tunnel est hors champ par construction, pas
//!    par filtrage a la lecture.
//! 2. **`pktmon` reecrit ses propres filtres dans la trace.** Une ligne
//!    d'evenement porte `IP-1 10.88.0.1` sans qu'aucun paquet ne soit sorti.
//!    Chercher l'adresse dans le texte brut signalerait une fuite fantome a
//!    chaque fois. Seules les lignes de PAQUET comptent.
//! 3. **La sortie de `pktmon` est partiellement localisee.** `Composant` ici,
//!    `Component` ailleurs. Aucune decision ne repose dessus: le tri des lignes
//!    se fait sur `[Microsoft-Windows-PktMon]`, qui est un nom de fournisseur,
//!    et l'identifiant de composant ne sert qu'a rendre la preuve lisible.
//!
//! # Pourquoi la preuve du transport et celle de la capture sont la meme
//!
//! Une capture qui n'ecoute pas encore rend zero paquet, et zero paquet en
//! clair se lit comme une absence de fuite. Le vecteur exige donc des paquets
//! CHIFFRES vers l'endpoint: s'il n'y en a pas, la capture n'a rien vu et le
//! verdict est `Ignore`, jamais un succes. La meme evidence etablit que le
//! tunnel a transporte et que la capture etait vivante.

use std::net::{IpAddr, SocketAddr};

use crate::wfp_identity::Issue;

/// Un paquet decode par `pktmon etl2txt`, rattache a son composant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paquet {
    /// `None` quand l'en-tete precedent etait illisible. La correction du
    /// verdict n'en depend pas: ce champ ne sert qu'a la preuve ecrite.
    pub composant: Option<u32>,
    pub texte: String,
}

/// Nom du fournisseur ETW, present sur toute ligne d'EVENEMENT et sur aucune
/// ligne de paquet. Il n'est pas traduit, contrairement au reste de la sortie.
const FOURNISSEUR: &str = "[Microsoft-Windows-PktMon]";

/// Decode la sortie de `pktmon etl2txt`.
///
/// `pktmon` ecrit en UTF-16LE avec marque d'ordre des octets. Ni UTF-8, ni la
/// page de codes ANSI. Le piege n'est pas qu'un decodage UTF-8 echoue - c'est
/// qu'un decodage TOLERANT reussit: il rend une chaine ou chaque caractere est
/// suivi d'un octet nul. Les lignes restent lisibles a l'oeil, et toutes les
/// recherches de motif echouent en silence. Le vecteur concluait alors a une
/// capture muette sur une capture qui contenait tous ses paquets, donc a un
/// SKIPPED qu'aucun message ne permettait de comprendre.
pub fn decoder(octets: &[u8]) -> String {
    if let [0xFF, 0xFE, reste @ ..] = octets {
        let unites: Vec<u16> = reste
            .as_chunks::<2>()
            .0
            .iter()
            .map(|p| u16::from_le_bytes(*p))
            .collect();
        return String::from_utf16_lossy(&unites);
    }
    String::from_utf8_lossy(octets).into_owned()
}

/// Identifiants des composants listes par `pktmon list`.
///
/// Le tri se fait sur "la ligne commence par un entier", pas sur les colonnes:
/// les en-tetes sont traduits. Un composant sans adresse MAC est retenu comme
/// les autres - les adaptateurs virtuels n'en portent pas, et ce sont
/// precisement ceux par ou une fuite peut passer.
pub fn composants(sortie: &str) -> Vec<u32> {
    sortie
        .lines()
        .filter_map(|l| l.split_whitespace().next())
        .filter_map(|t| t.parse::<u32>().ok())
        .collect()
}

/// Identifiant de composant porte par une ligne d'en-tete, s'il est lisible.
///
/// `Composant` en francais, `Component` en anglais. Aucune decision du verdict
/// ne repose sur ce champ: il ne sert qu'a nommer la carte dans la preuve.
fn composant_de(ligne: &str) -> Option<u32> {
    let mots: Vec<&str> = ligne.split_whitespace().collect();
    mots.windows(2).find_map(|w| {
        let cle = w[0].trim_end_matches(',');
        (cle == "Composant" || cle == "Component")
            .then(|| w[1].trim_end_matches(',').parse().ok())
            .flatten()
    })
}

/// Vrai si `texte` mentionne l'adresse `ip` et non une adresse qui la prolonge.
///
/// `pktmon` ecrit `10.88.0.1.7000`, donc l'adresse est suivie d'un point. Une
/// recherche de sous-chaine nue confondrait `10.88.0.1` avec `10.88.0.12`, et
/// une fuite vers une machine voisine serait imputee a la mauvaise.
fn contient_adresse(texte: &str, ip: IpAddr) -> bool {
    let motif = ip.to_string();
    let mut reste = texte;
    while let Some(i) = reste.find(&motif) {
        let suite = &reste[i + motif.len()..];
        if !suite.starts_with(|c: char| c.is_ascii_digit()) {
            return true;
        }
        reste = &reste[i + motif.len()..];
    }
    false
}

/// Extrait les lignes de PAQUET, en ignorant les lignes d'evenement.
pub fn paquets(txt: &str) -> Vec<Paquet> {
    let mut courant = None;
    let mut out = Vec::new();
    for l in txt.lines() {
        if l.contains(FOURNISSEUR) {
            if let Some(id) = composant_de(l) {
                courant = Some(id);
            }
            continue;
        }
        let t = l.trim();
        // Un paquet decode porte toujours une direction. Ce qui n'en porte pas
        // est une ligne vide ou une continuation, jamais une preuve.
        if t.is_empty() || !t.contains('>') {
            continue;
        }
        out.push(Paquet {
            composant: courant,
            texte: t.to_owned(),
        });
    }
    out
}

/// Compte les paquets chiffres vers l'endpoint du tunnel.
pub fn chiffres(paquets: &[Paquet], endpoint: SocketAddr) -> usize {
    let motif = format!("{}.{}", endpoint.ip(), endpoint.port());
    paquets.iter().filter(|p| p.texte.contains(&motif)).count()
}

/// Paquets en clair vers l'une des destinations sondees.
pub fn fuites(paquets: &[Paquet], destinations: &[IpAddr]) -> Vec<String> {
    paquets
        .iter()
        .filter(|p| destinations.iter().any(|d| contient_adresse(&p.texte, *d)))
        .map(|p| match p.composant {
            Some(c) => format!("composant {c}: {}", p.texte),
            None => format!("composant inconnu: {}", p.texte),
        })
        .collect()
}

/// Conclut a partir des trois observations.
///
/// L'ordre compte. L'absence de paquet chiffre est examinee AVANT les fuites:
/// une capture qui n'a rien vu rend aussi zero fuite, et lire ce silence comme
/// une etancheite serait certifier ce qu'on n'a pas observe.
pub fn juger(chiffres: usize, fuites: &[String], transport: bool) -> Issue {
    if chiffres == 0 {
        return Issue::Ignore(
            "aucun paquet chiffre vers l'endpoint dans la capture: elle n'a rien vu, et zero paquet en clair ne vaut alors pas une absence de fuite"
                .to_owned(),
        );
    }
    if !transport {
        return Issue::Ignore(
            "le tunnel n'a pas transporte: la sortie pourrait etre etanche simplement parce que rien ne circulait"
                .to_owned(),
        );
    }
    if !fuites.is_empty() {
        return Issue::Echec(format!(
            "FUITE: {} paquet(s) en clair vers une destination que le tunnel devait porter",
            fuites.len()
        ));
    }
    Issue::Reussi
}

/// Mesure le vecteur. Monte un vrai tunnel vers un vrai pair.
///
/// Ne coupe PAS le reseau de la machine: le profil est refuse s'il porte une
/// route par defaut, et le kill switch n'est pas arme. Ce vecteur mesure le
/// routage, pas le pare-feu.
pub fn selftest(
    profil: &std::path::Path,
    cible: SocketAddr,
    accepte_par_defaut: bool,
    temoin_public: SocketAddr,
) -> anyhow::Result<()> {
    let cfg = crate::tunnel::wgnt::e2e::charger(profil, accepte_par_defaut)?;
    let endpoint = cfg
        .wireguard()
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .peer
        .endpoint
        .addr;

    println!("vecteur exit-ip, endpoint {endpoint}, cible {cible}");

    // Les composants sont releves AVANT la montee, a dessein: l'adaptateur du
    // tunnel n'existe pas encore, donc il ne peut pas entrer dans la capture.
    // C'est ce qui empeche ses paquets en clair d'AVANT chiffrement d'etre lus
    // comme des fuites, et ca ne repose sur aucun filtrage a la lecture.
    let liste = pktmon(&["list"])?;
    let ids = composants(&liste);
    if ids.is_empty() {
        anyhow::bail!("`pktmon list` ne rend aucun composant: capture impossible");
    }
    println!("  capture sur les composants {ids:?}, le tunnel exclu par construction");

    let etl = std::env::temp_dir().join("bifrost-exit-ip.etl");
    let txt = std::env::temp_dir().join("bifrost-exit-ip.txt");
    let _ = pktmon(&["stop"]);
    let _ = pktmon(&["filter", "remove"]);
    pktmon(&[
        "filter",
        "add",
        "BifrostEp",
        "-i",
        &endpoint.ip().to_string(),
    ])?;
    pktmon(&[
        "filter",
        "add",
        "BifrostCible",
        "-i",
        &cible.ip().to_string(),
    ])?;

    let mut demarrage = vec![
        "start".to_owned(),
        "--capture".to_owned(),
        "--pkt-size".to_owned(),
        "128".to_owned(),
        "-f".to_owned(),
        etl.to_string_lossy().into_owned(),
        "--comp".to_owned(),
    ];
    demarrage.extend(ids.iter().map(|i| i.to_string()));
    let args: Vec<&str> = demarrage.iter().map(String::as_str).collect();
    pktmon(&args)?;

    // La recette monte le tunnel, attend le handshake, lit la banniere et
    // demonte. Son echec n'interrompt pas la mesure: la capture doit etre
    // arretee de toute facon, et une capture laissee en cours consomme le
    // disque de la machine.
    let transport = crate::tunnel::wgnt::e2e::run(
        profil,
        cible,
        accepte_par_defaut,
        Some(temoin_public),
        false,
    );

    let _ = pktmon(&["stop"]);
    let conversion = pktmon(&[
        "etl2txt",
        &etl.to_string_lossy(),
        "-o",
        &txt.to_string_lossy(),
    ]);
    let _ = pktmon(&["filter", "remove"]);
    conversion?;

    let octets = std::fs::read(&txt)
        .map_err(|e| anyhow::anyhow!("lecture de la capture {}: {e}", txt.display()))?;
    let brut = decoder(&octets);
    let paquets = paquets(&brut);
    let chiffres = chiffres(&paquets, endpoint);
    let fuites = fuites(&paquets, &[cible.ip(), temoin_public.ip()]);

    println!(
        "  capture: {} paquet(s) decode(s), dont {chiffres} chiffre(s) vers {endpoint}",
        paquets.len()
    );
    if chiffres == 0 {
        // Sans cet extrait, "aucun paquet chiffre" ne dit pas SI la capture
        // etait muette ou si elle a vu autre chose. Les deux se corrigent
        // differemment, et la difference n'est pas devinable a posteriori.
        println!("  ce que la capture a vu, a defaut:");
        for q in paquets.iter().take(3) {
            println!("    composant {:?}: {}", q.composant, q.texte);
        }
        println!("  fichier de capture: {}", txt.display());
    }
    for f in &fuites {
        println!("    EN CLAIR: {f}");
    }

    match juger(chiffres, &fuites, transport.is_ok()) {
        Issue::Reussi => {
            println!(
                "
exit-ip: PASSED - la banniere est passee par le tunnel, et aucun paquet en clair vers {} ni vers le temoin public {} n'est apparu sur les {} composant(s) captures",
                cible.ip(),
                temoin_public.ip(),
                ids.len()
            );
            Ok(())
        }
        Issue::Ignore(raison) => {
            if let Err(e) = &transport {
                println!("  la recette de transport a echoue: {e:#}");
            }
            println!(
                "
exit-ip: SKIPPED - {raison}"
            );
            Ok(())
        }
        Issue::Echec(raison) => Err(anyhow::anyhow!("exit-ip: FAILED - {raison}")),
    }
}

/// Lance `pktmon` et rend sa sortie standard.
fn pktmon(args: &[&str]) -> anyhow::Result<String> {
    let sortie = std::process::Command::new("pktmon")
        .args(args)
        .output()
        .map_err(|e| anyhow::anyhow!("pktmon {}: {e}", args.join(" ")))?;
    if !sortie.status.success() {
        anyhow::bail!(
            "pktmon {} a echoue ({}): {}",
            args.join(" "),
            sortie.status,
            String::from_utf8_lossy(&sortie.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&sortie.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Format reel de `pktmon`, releve sur le banc le 18 aout 2026. Seules les
    /// adresses ont ete remplacees par des adresses de documentation: c'est la
    /// FORME de la sortie que ces tests verrouillent, pas le reseau d'essai.
    const LISTE: &str = "\r
Cartes reseau :\r
   ID Adresse MAC       Nom\r
   -- -----------       ---\r
    6                   Tailscale Tunnel\r
   16 02-00-00-00-00-03 Carte sans fil\r
   15 02-00-00-00-00-01 Carte ethernet\r
";

    const TRACE: &str = "[00]1264.1240::2026-08-18 16:45:38.288241000 [Microsoft-Windows-PktMon] PktGroupId 86, PktNumber 1, Apparence 0, Direction Rx , Type Ethernet , Composant 15, Edge 1, Filtre 1, OriginalSize 60, LoggedSize 60 
\t02-00-00-00-00-01 > 02-00-00-00-00-02, ethertype IPv4 (0x0800), length 190: 198.51.100.9.53702 > 198.51.100.94.51820: UDP, length 148
[03]3F60.374C::2026-08-18 16:45:38.294058500 [Microsoft-Windows-PktMon] Filtre de paquet 2, Nom TUN, MAC-1 0x000000000000, MAC-2 0x000000000000, EtherType 0, VlanId 0, IP-1 10.88.0.1, IP-2 0.0.0.0, Protocole 0, Port-1 0, Port-2 0, TCPFlags 0 
[00]1264.1240::2026-08-18 16:45:38.300000000 [Microsoft-Windows-PktMon] PktGroupId 87, PktNumber 1, Direction Tx , Type Ethernet , Composant 15, Edge 1
\t02-00-00-00-00-02 > 02-00-00-00-00-01, ethertype IPv4 (0x0800), length 134: 198.51.100.94.51820 > 198.51.100.9.53702: UDP, length 92
";

    fn endpoint() -> SocketAddr {
        "198.51.100.94:51820".parse().unwrap()
    }

    fn tunnel() -> IpAddr {
        "10.88.0.1".parse().unwrap()
    }

    #[test]
    fn les_identifiants_de_composants_se_lisent_sans_dependre_des_entetes() {
        // Les en-tetes sont traduits, les identifiants non. Le composant 6 n'a
        // aucune adresse MAC: l'exiger perdrait les adaptateurs virtuels, qui
        // sont precisement ceux par ou une fuite peut passer.
        assert_eq!(composants(LISTE), vec![6, 16, 15]);
    }

    #[test]
    fn la_declaration_de_filtre_de_pktmon_n_est_pas_une_fuite() {
        // LE piege de ce vecteur. `pktmon` reecrit ses filtres dans la trace,
        // donc l'adresse sondee apparait dans le texte sans qu'aucun paquet ne
        // soit sorti. Un analyseur naif signalerait une fuite a chaque
        // execution, y compris quand le tunnel est parfaitement etanche.
        let p = paquets(TRACE);
        assert_eq!(p.len(), 2, "seules les deux lignes de paquet comptent");
        assert!(fuites(&p, &[tunnel()]).is_empty());
    }

    #[test]
    fn les_paquets_sont_rattaches_a_leur_composant() {
        let p = paquets(TRACE);
        assert_eq!(p[0].composant, Some(15));
        assert_eq!(p[1].composant, Some(15));
    }

    #[test]
    fn seuls_les_paquets_vers_l_endpoint_comptent_comme_chiffres() {
        let p = paquets(TRACE);
        assert_eq!(chiffres(&p, endpoint()), 2);
        // Un autre port sur la meme machine n'est pas le tunnel.
        assert_eq!(chiffres(&p, "198.51.100.94:51821".parse().unwrap()), 0);
    }

    #[test]
    fn un_paquet_en_clair_vers_la_destination_sondee_est_une_fuite() {
        let trace = format!(
            "{TRACE}[00]1264.1240::2026-08-18 16:45:39.0 [Microsoft-Windows-PktMon] PktGroupId 90, Composant 16, Edge 1
\t02-00-00-00-00-03 > 02-00-00-00-00-02, ethertype IPv4 (0x0800), length 60: 198.51.100.9.64502 > 10.88.0.1.7000: Flags [S], length 0
"
        );
        let f = fuites(&paquets(&trace), &[tunnel()]);
        assert_eq!(f.len(), 1, "{f:?}");
        // La preuve nomme le composant: une fuite par le Wi-Fi et une fuite par
        // l'ethernet ne se corrigent pas de la meme facon.
        assert!(f[0].contains("16"), "{}", f[0]);
    }

    #[test]
    fn une_capture_muette_ne_vaut_pas_une_absence_de_fuite() {
        // Sans paquet chiffre, la capture n'a rien vu du tout. Conclure a
        // l'etancheite serait lire le silence de l'outil comme une preuve.
        assert!(matches!(juger(0, &[], true), Issue::Ignore(_)));
        // Le transport non etabli: la sortie pourrait etre etanche parce que
        // rien ne circulait.
        assert!(matches!(juger(11, &[], false), Issue::Ignore(_)));
        assert!(matches!(juger(11, &[], true), Issue::Reussi));
        assert!(matches!(
            juger(11, &["fuite".to_owned()], true),
            Issue::Echec(_)
        ));
    }

    #[test]
    fn une_adresse_voisine_n_est_pas_confondue_avec_la_cible() {
        // `10.88.0.1` ne doit pas matcher `10.88.0.12`: une fuite vers une
        // machine voisine serait imputee a la mauvaise, et une preuve fausse
        // est pire qu'une absence de preuve.
        let trace = "[00]1.1::x [Microsoft-Windows-PktMon] PktGroupId 1, Composant 15
	02-00-00-00-00-01 > 02-00-00-00-00-02, ethertype IPv4 (0x0800), length 60: 198.51.100.9.1 > 10.88.0.12.7000: Flags [S]
";
        assert!(fuites(&paquets(trace), &[tunnel()]).is_empty());
        assert_eq!(
            fuites(&paquets(trace), &["10.88.0.12".parse().unwrap()]).len(),
            1
        );
    }

    #[test]
    fn la_sortie_utf16_de_pktmon_est_decodee_avant_toute_recherche() {
        let ligne = "198.51.100.94.51820: UDP, length 148";
        let mut octets = vec![0xFF, 0xFE];
        for u in ligne.encode_utf16() {
            octets.extend_from_slice(&u.to_le_bytes());
        }
        assert_eq!(decoder(&octets), ligne);
        // LE piege, et la raison d'etre de ce test: le decodage tolerant en
        // UTF-8 ne signale rien. Il rend une chaine d'apparence correcte dans
        // laquelle la recherche echoue, donc une capture pleine se lit comme
        // une capture muette.
        assert!(!String::from_utf8_lossy(&octets).contains(ligne));
        // Une sortie deja en UTF-8 doit continuer de passer telle quelle.
        assert_eq!(decoder(ligne.as_bytes()), ligne);
    }
}
