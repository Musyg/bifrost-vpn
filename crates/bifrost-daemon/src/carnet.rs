//! Reconnaitre le reseau courant, et ranger ce qu'on a appris de lui.
//!
//! Le versant impur de [`bifrost_evasion::carnet`]: la lecture de l'etat de la
//! machine, et le fichier. La regle reste la-bas, ici il n'y a que des faits.
//!
//! # Ce que ce module n'emet pas
//!
//! Rien. C'est tout son interet. Les sept sondes de `bifrost-evasion` exigent
//! chacune un paquet sortant; identifier le reseau n'en exige aucun, parce que
//! la passerelle par defaut et le nom de l'interface sont deja dans la machine.
//! Sous Linux la source est `/proc/net/route`, un fichier; sous Windows c'est
//! `GetBestRoute2`, une consultation de la table de routage locale. Ni l'un ni
//! l'autre ne met un octet sur le fil.
//!
//! # Ce que la cle ne contient pas
//!
//! [`bifrost_evasion::CleReseau`] prevoit trois parties: le lien, la passerelle
//! et l'ASN de sortie. L'ASN est laisse absent ici, et ce n'est pas un oubli:
//! l'observer demande de sortir, donc d'emettre, ce qui reprendrait d'une main
//! ce que ce module donne de l'autre. `CleReseau` distingue deja un ASN absent
//! d'un ASN nul, et le couple lien + passerelle suffit a separer deux reseaux
//! que l'on frequente.
//!
//! Consequence assumee: deux reseaux differents qui presenteraient la meme
//! interface ET la meme adresse de passerelle partageraient un souvenir. Le cas
//! demande deux boitiers configures a l'identique sur la meme carte, et le prix
//! d'une confusion est une tentative ratee, pas une fuite.
//!
//! # Ce que le fichier revele
//!
//! A dire precisement, parce que le carnet est lisible sans privilege alors
//! qu'il s'ecrit avec: il contient des noms d'interface, des adresses de
//! passerelle (presque toujours privees, du type 192.168.x.1), des noms de
//! technique et des dates. Cela dit combien de reseaux distincts la machine a
//! traverses, pas lesquels ni ou. `CleReseau` prevoit le BSSID pour le lien, ce
//! qui SERAIT une donnee de localisation; tant que c'est le nom d'interface qui
//! est fourni, ce n'en est pas une. Le jour ou le BSSID sera lu, cette section
//! sera a reecrire et le fichier a proteger en lecture.

use std::path::{Path, PathBuf};

use bifrost_evasion::{Carnet, CleReseau, MemoireReseau};

/// Lit l'horloge du systeme et la ramene a une date civile.
///
/// Seul endroit du chemin de selection qui touche a l'heure. Tout ce qui suit
/// la recoit en argument, et reste donc testable a une date choisie.
pub fn aujourd_hui() -> Result<bifrost_evasion::Date, String> {
    const JOUR: u64 = 86_400;
    let depuis_epoque = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| format!("horloge systeme anterieure a 1970: {e}"))?;
    Ok(bifrost_evasion::Date::depuis_numero_de_jour(
        (depuis_epoque.as_secs() / JOUR) as i64,
    ))
}

/// Ce que le carnet retient de ce reseau, ou une memoire vierge.
///
/// Le pendant en lecture de `noter_au_carnet`, et la meme discipline: ouvrir,
/// lire, refermer. Garder le carnet en memoire entre deux connexions ferait
/// decider sur un souvenir peut-etre plus vieux que le fichier, que le daemon
/// n'est pas seul a pouvoir toucher.
///
/// Un reseau INCONNU rend une memoire vierge et non une erreur: c'est l'etat
/// ordinaire du premier passage, et la selection sait quoi en faire. Seul un
/// carnet illisible est une erreur, pour la meme raison que dans [`lire`].
pub fn souvenir_de(cle: &CleReseau) -> Result<MemoireReseau, String> {
    let carnet = lire(&chemin()?)?;
    Ok(carnet
        .souvenir(cle)
        .cloned()
        .unwrap_or_else(MemoireReseau::vierge))
}

/// Le nom du fichier, sous le repertoire d'etat du daemon.
pub const FICHIER: &str = "carnet.json";

/// Ou le carnet est range.
///
/// Sous Windows, `%ProgramData%\Bifrost`, comme le reste de ce que le service
/// ecrit: le service tourne en SYSTEM et n'a pas de profil utilisateur.
#[cfg(windows)]
pub fn chemin() -> Result<PathBuf, String> {
    let base = std::env::var_os("ProgramData")
        .ok_or_else(|| "%ProgramData% introuvable: ou ranger le carnet?".to_owned())?;
    Ok(Path::new(&base).join("Bifrost").join(FICHIER))
}

#[cfg(not(windows))]
pub fn chemin() -> Result<PathBuf, String> {
    Ok(Path::new("/var/lib/bifrost").join(FICHIER))
}

/// Lit le carnet. Un fichier ABSENT rend un carnet vide, un fichier ABIME rend
/// une erreur.
///
/// La distinction porte tout le module. "Pas encore de carnet" est un etat
/// normal au premier lancement. "Carnet illisible" ne l'est pas: se rabattre
/// dessus en silence ferait sonder, donc emettre, alors qu'on avait
/// peut-etre de quoi ne pas le faire, et le ferait sans que personne
/// l'apprenne.
pub fn lire(chemin: &Path) -> Result<Carnet, String> {
    match std::fs::read_to_string(chemin) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Carnet::vide()),
        Err(e) => Err(format!("{} illisible: {e}", chemin.display())),
        Ok(texte) => serde_json::from_str(&texte)
            .map_err(|e| format!("{} n'est pas un carnet valide: {e}", chemin.display())),
    }
}

/// Ecrit le carnet, par un fichier temporaire puis un renommage.
///
/// Une ecriture en place que le courant interrompt laisse un fichier tronque,
/// donc un carnet illisible, donc un sondage de plus a la prochaine connexion.
/// Le renommage est atomique sur les deux plateformes.
pub fn ecrire(chemin: &Path, carnet: &Carnet) -> Result<(), String> {
    let texte = serde_json::to_string_pretty(carnet)
        .map_err(|e| format!("carnet non serialisable: {e}"))?;
    if let Some(parent) = chemin.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("{} non creable: {e}", parent.display()))?;
    }
    let provisoire = chemin.with_extension("json.tmp");
    std::fs::write(&provisoire, texte)
        .map_err(|e| format!("{} non ecrivable: {e}", provisoire.display()))?;
    std::fs::rename(&provisoire, chemin).map_err(|e| {
        // Ne pas laisser le provisoire derriere: il porte les memes souvenirs
        // que le carnet, sans etre lu par personne.
        let _ = std::fs::remove_file(&provisoire);
        format!(
            "{} non renommable en {}: {e}",
            provisoire.display(),
            chemin.display()
        )
    })
}

/// Le nom de l'interface et l'adresse de la passerelle par defaut, tels que
/// `/proc/net/route` les presente.
///
/// Pur, donc teste partout et pas seulement sous Linux.
///
/// Le noyau imprime les adresses comme un entier 32 bits en boutisme HOTE,
/// alors que la valeur est en boutisme reseau: sur une machine petit-boutiste,
/// 192.168.1.1 ressort en "0101A8C0". L'inversion des octets remet l'adresse a
/// l'endroit. Toutes les cibles de ce depot sont petit-boutistes, y compris
/// l'ARM64 du terrain.
///
/// Quand plusieurs routes par defaut coexistent, celle de plus faible metrique
/// gagne, comme le noyau le ferait.
pub fn passerelle_depuis_proc(texte: &str) -> Option<(String, std::net::Ipv4Addr)> {
    let mut meilleure: Option<(u32, String, std::net::Ipv4Addr)> = None;
    for ligne in texte.lines().skip(1) {
        let champs: Vec<&str> = ligne.split_whitespace().collect();
        // Iface Destination Gateway Flags RefCnt Use Metric ...
        if champs.len() < 7 {
            continue;
        }
        // Seule la route par defaut identifie le reseau.
        if champs[1] != "00000000" {
            continue;
        }
        let Ok(brut) = u32::from_str_radix(champs[2], 16) else {
            continue;
        };
        // Une route par defaut sans passerelle (lien point a point) ne dit rien
        // du reseau: la retenir donnerait 0.0.0.0 pour cle.
        if brut == 0 {
            continue;
        }
        let Ok(metrique) = champs[6].parse::<u32>() else {
            continue;
        };
        let adresse = std::net::Ipv4Addr::from(brut.swap_bytes());
        if meilleure.as_ref().is_none_or(|(m, _, _)| metrique < *m) {
            meilleure = Some((metrique, champs[0].to_owned(), adresse));
        }
    }
    meilleure.map(|(_, iface, adresse)| (iface, adresse))
}

/// La cle du reseau courant, sans rien emettre.
#[cfg(not(windows))]
pub fn cle_courante() -> Result<CleReseau, String> {
    const ROUTE: &str = "/proc/net/route";
    let texte = std::fs::read_to_string(ROUTE).map_err(|e| format!("{ROUTE} illisible: {e}"))?;
    let (lien, passerelle) = passerelle_depuis_proc(&texte)
        .ok_or_else(|| format!("aucune route par defaut avec passerelle dans {ROUTE}"))?;
    Ok(CleReseau::nouvelle(&lien, &passerelle.to_string(), None))
}

/// La cle du reseau courant, sans rien emettre.
///
/// `GetBestRoute2` vers 0.0.0.0 rend la route que la pile emprunterait pour
/// sortir, c'est-a-dire la route par defaut effective. Consultation locale de
/// la table de routage: aucun paquet.
#[cfg(windows)]
pub fn cle_courante() -> Result<CleReseau, String> {
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        ConvertInterfaceLuidToNameW, GetBestRoute2, MIB_IPFORWARD_ROW2,
    };
    use windows_sys::Win32::Networking::WinSock::{AF_INET, SOCKADDR_INET};

    let mut destination = SOCKADDR_INET::default();
    // 0.0.0.0: "par ou sortirait-on".
    destination.si_family = AF_INET;
    let mut route = MIB_IPFORWARD_ROW2::default();
    let mut source = SOCKADDR_INET::default();
    // SAFETY: les trois structures sont locales et valides; un LUID nul et un
    // index nul demandent a l'API de choisir elle-meme l'interface.
    let code = unsafe {
        GetBestRoute2(
            std::ptr::null(),
            0,
            std::ptr::null(),
            &destination,
            0,
            &mut route,
            &mut source,
        )
    };
    if code != ERROR_SUCCESS {
        return Err(format!("aucune route par defaut lisible (code {code})"));
    }

    // SAFETY: la famille dit laquelle des vues de l'union est valide.
    let passerelle = unsafe {
        match route.NextHop.si_family {
            AF_INET => {
                std::net::Ipv4Addr::from(route.NextHop.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes())
                    .to_string()
            }
            autre => return Err(format!("passerelle de famille inattendue ({autre})")),
        }
    };

    // Le NOM de l'interface, pas son alias: l'alias est renommable par
    // l'utilisateur, et une cle qui change quand on renomme une carte perd le
    // souvenir du reseau sans que rien du reseau ait bouge.
    let mut nom = [0u16; 256];
    // SAFETY: `nom` fait la taille annoncee.
    let code =
        unsafe { ConvertInterfaceLuidToNameW(&route.InterfaceLuid, nom.as_mut_ptr(), nom.len()) };
    let lien = if code == ERROR_SUCCESS {
        let fin = nom.iter().position(|&c| c == 0).unwrap_or(nom.len());
        String::from_utf16_lossy(&nom[..fin])
    } else {
        // Le LUID lui-meme fait un identifiant de repli acceptable: stable
        // pour une carte donnee, ce qui est tout ce qu'on lui demande.
        // SAFETY: `Value` est la vue u64 de l'union, valide quoi qu'on y ait
        // ecrit.
        format!("luid:{}", unsafe { route.InterfaceLuid.Value })
    };

    Ok(CleReseau::nouvelle(&lien, &passerelle, None))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Un extrait reel: la passerelle 192.168.1.1 s'ecrit "0101A8C0" en
    /// boutisme hote sur une machine petit-boutiste.
    const PROC: &str = "\
Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
wlp2s0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0
wlp2s0\t0001A8C0\t00000000\t0001\t0\t0\t600\t00FFFFFF\t0\t0\t0
";

    #[test]
    fn la_passerelle_se_lit_a_l_endroit() {
        let (lien, adresse) = passerelle_depuis_proc(PROC).expect("il y a une route par defaut");
        assert_eq!(lien, "wlp2s0");
        assert_eq!(adresse, std::net::Ipv4Addr::new(192, 168, 1, 1));
    }

    /// La route de sous-reseau a une passerelle nulle et une destination non
    /// nulle: la retenir donnerait une cle qui ne designe aucun reseau.
    #[test]
    fn seule_la_route_par_defaut_compte() {
        let sans_defaut = "\
Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
wlp2s0\t0001A8C0\t00000000\t0001\t0\t0\t600\t00FFFFFF\t0\t0\t0
";
        assert_eq!(passerelle_depuis_proc(sans_defaut), None);
    }

    /// Une route par defaut sans passerelle existe sur les liens point a
    /// point. Elle ne dit rien du reseau, donc elle ne fait pas de cle.
    #[test]
    fn une_route_par_defaut_sans_passerelle_ne_fait_pas_de_cle() {
        let ppp = "\
Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
ppp0\t00000000\t00000000\t0001\t0\t0\t0\t00000000\t0\t0\t0
";
        assert_eq!(passerelle_depuis_proc(ppp), None);
    }

    /// Deux routes par defaut coexistent des qu'une machine a deux cartes. Le
    /// noyau suit la plus faible metrique; une cle qui suivrait l'ordre des
    /// lignes changerait au gre du fichier.
    #[test]
    fn la_plus_faible_metrique_gagne() {
        let deux = "\
Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
wlp2s0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0
eth0\t00000000\t0102A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0
";
        let (lien, adresse) = passerelle_depuis_proc(deux).expect("il y a des routes par defaut");
        assert_eq!(lien, "eth0");
        assert_eq!(adresse, std::net::Ipv4Addr::new(192, 168, 2, 1));
    }

    #[test]
    fn un_fichier_vide_ou_tronque_ne_fait_pas_de_cle() {
        assert_eq!(passerelle_depuis_proc(""), None);
        assert_eq!(passerelle_depuis_proc("Iface\tDestination\n"), None);
        // Une ligne amputee de ses derniers champs ne doit pas paniquer.
        assert_eq!(
            passerelle_depuis_proc("en-tete\nwlp2s0\t00000000\t0101A8C0\n"),
            None
        );
    }

    /// Un carnet absent est un etat normal au premier lancement; un carnet
    /// abime ne l'est pas, et les deux ne doivent pas se ressembler.
    #[test]
    fn un_carnet_absent_et_un_carnet_abime_ne_se_ressemblent_pas() {
        let repertoire =
            std::env::temp_dir().join(format!("bifrost-carnet-{}-{}", std::process::id(), line!()));
        std::fs::create_dir_all(&repertoire).expect("repertoire de test");
        let absent = repertoire.join("jamais-ecrit.json");
        assert_eq!(lire(&absent), Ok(Carnet::vide()));

        let abime = repertoire.join("abime.json");
        std::fs::write(&abime, "{ pas du json").expect("ecriture de test");
        let e = lire(&abime).expect_err("un carnet abime doit rendre une erreur");
        assert!(e.contains("n'est pas un carnet valide"), "{e}");

        std::fs::remove_dir_all(&repertoire).ok();
    }

    /// L'aller-retour par le disque, avec le renommage.
    #[test]
    fn un_carnet_ecrit_se_relit() {
        let repertoire =
            std::env::temp_dir().join(format!("bifrost-carnet-{}-{}", std::process::id(), line!()));
        let chemin = repertoire.join(FICHIER);
        let mut c = Carnet::vide();
        c.noter_reussite(
            CleReseau::nouvelle("eth0", "192.168.1.1", None),
            bifrost_evasion::Technique::RealityVision,
            bifrost_evasion::Date::new(2026, 8, 19),
        );
        ecrire(&chemin, &c).expect("le carnet doit s'ecrire");
        assert_eq!(lire(&chemin), Ok(c));
        assert!(
            !chemin.with_extension("json.tmp").exists(),
            "le fichier provisoire doit avoir ete renomme, pas laisse la"
        );
        std::fs::remove_dir_all(&repertoire).ok();
    }
}
