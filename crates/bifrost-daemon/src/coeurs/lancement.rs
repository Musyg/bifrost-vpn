//! Comment lancer un coeur: la ligne de commande, et rien d'autre.
//!
//! Pure, donc testee partout. C'est le genre de code ou une erreur ne se voit
//! qu'a l'execution, sur une machine ou le coeur est installe, c'est-a-dire
//! nulle part en integration continue.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use bifrost_evasion::Coeur;

/// Ou trouver les executables et ou ecrire leurs configurations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Emplacements {
    /// Repertoire des binaires des coeurs. Fourni par l'empaquetage, jamais
    /// devine: chercher dans le PATH laisserait un tiers placer un
    /// "sing-box" a lui devant le notre.
    pub binaires: PathBuf,
    /// Repertoire ou ecrire les configurations generees.
    pub configurations: PathBuf,
}

/// Tout ce qu'il faut pour demarrer un coeur.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lancement {
    pub programme: PathBuf,
    pub arguments: Vec<OsString>,
    pub configuration: PathBuf,
    /// Port local de l'API Clash, si le coeur en expose une.
    pub api_clash: Option<u16>,
    /// Compte sous lequel lancer le coeur, quand ce n'est pas celui du daemon.
    ///
    /// Deux raisons, et la seconde vaut a elle seule le detour. D'abord le kill
    /// switch: il exempte le coeur par son UID, donc il faut qu'il en ait un a
    /// lui. Ensuite le privilege: un coeur est du code TIERS qui analyse du
    /// trafic reseau hostile, et le daemon tourne en root. L'y laisser tourner
    /// donnerait la machine entiere au premier debordement dans un parseur que
    /// nous n'ecrivons pas.
    ///
    /// `None` sous Windows et dans les recettes qui ne posent pas de kill
    /// switch: le champ est ignore ailleurs que sous Unix.
    pub utilisateur: Option<Utilisateur>,
}

/// Compte systeme dedie a un coeur.
///
/// Le groupe accompagne l'utilisateur et n'est pas facultatif: ne baisser que
/// l'UID laisserait le processus avec le GID 0, donc l'acces a tout ce que root
/// partage par son groupe. Une baisse de privilege a moitie faite se lit comme
/// une baisse de privilege.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Utilisateur {
    pub uid: u32,
    pub gid: u32,
}

/// Extension de l'executable sur cette plateforme.
pub const fn extension_executable() -> &'static str {
    if cfg!(windows) { ".exe" } else { "" }
}

/// Le rang du prochain lancement de ce processus.
static LANCEMENTS: AtomicU64 = AtomicU64::new(0);

/// Ce qui, dans le nom d'une configuration, designe le processus qui l'ecrit:
/// son PID et sa date de debut, couple qu'un PID repris ne redonne pas (sous
/// Linux le `starttime` de `/proc`, qui nomme aussi les sessions du journal
/// de routage; sous Windows la date de creation du processus). Une date
/// illisible donne un nom que [`retirer_les_configurations_mortes`] ne juge
/// pas: il le laisse.
fn ce_processus() -> String {
    match processus::moi() {
        Ok((pid, debut)) => format!("{pid}-{debut}"),
        Err(_) => format!("{}-illisible", std::process::id()),
    }
}

/// Le processus qui ecrit une configuration, et s'il vit encore.
mod processus {
    /// Ce processus-ci: PID et date de debut.
    #[cfg(target_os = "linux")]
    pub(super) fn moi() -> std::io::Result<(u32, u64)> {
        crate::tunnel::session::ce_processus()
    }

    /// Le processus `pid` ne de `debut` vit-il encore? Non s'il est absent,
    /// repris a une autre date, ou zombie.
    #[cfg(target_os = "linux")]
    pub(super) fn vivant(pid: u32, debut: u64) -> std::io::Result<bool> {
        crate::tunnel::session::processus_vivant(pid, debut)
    }

    /// La date de creation d'un processus ouvert, en centaines de
    /// nanosecondes (`FILETIME`).
    #[cfg(windows)]
    fn creation(h: windows_sys::Win32::Foundation::HANDLE) -> std::io::Result<u64> {
        use windows_sys::Win32::Foundation::FILETIME;
        use windows_sys::Win32::System::Threading::GetProcessTimes;
        let vide = || FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let (mut c, mut x, mut k, mut u) = (vide(), vide(), vide(), vide());
        // SAFETY: `h` est une poignee de processus ouverte par l'appelant avec
        // au moins PROCESS_QUERY_LIMITED_INFORMATION; les quatre pointeurs
        // designent des FILETIME locaux et vivants.
        if unsafe { GetProcessTimes(h, &mut c, &mut x, &mut k, &mut u) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok((u64::from(c.dwHighDateTime) << 32) | u64::from(c.dwLowDateTime))
    }

    #[cfg(windows)]
    pub(super) fn moi() -> std::io::Result<(u32, u64)> {
        use windows_sys::Win32::System::Threading::GetCurrentProcess;
        // SAFETY: la pseudo-poignee du processus courant est toujours valide
        // et n'a pas a etre fermee.
        let h = unsafe { GetCurrentProcess() };
        Ok((std::process::id(), creation(h)?))
    }

    #[cfg(windows)]
    pub(super) fn vivant(pid: u32, debut: u64) -> std::io::Result<bool> {
        use windows_sys::Win32::Foundation::{CloseHandle, ERROR_INVALID_PARAMETER, WAIT_TIMEOUT};
        use windows_sys::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
            WaitForSingleObject,
        };
        // SAFETY: OpenProcess ne lit que ses arguments entiers; la poignee
        // rendue est fermee ci-dessous sur tous les chemins.
        let h = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                0,
                pid,
            )
        };
        if h.is_null() {
            let e = std::io::Error::last_os_error();
            // Aucun processus de ce numero.
            if e.raw_os_error() == Some(ERROR_INVALID_PARAMETER as i32) {
                return Ok(false);
            }
            return Err(e);
        }
        let date = creation(h);
        // SAFETY: `h` est valide et ouverte avec PROCESS_SYNCHRONIZE; l'attente
        // a delai nul ne fait que lire l'etat du processus.
        let attente = unsafe { WaitForSingleObject(h, 0) };
        // SAFETY: `h` a ete ouverte ici et n'est plus utilisee apres.
        unsafe { CloseHandle(h) };
        Ok(date? == debut && attente == WAIT_TIMEOUT)
    }

    #[cfg(not(any(target_os = "linux", windows)))]
    pub(super) fn moi() -> std::io::Result<(u32, u64)> {
        Err(std::io::ErrorKind::Unsupported.into())
    }
}

/// Chemin du fichier de configuration d'un lancement de coeur.
///
/// Un fichier par lancement, nomme par le coeur, le processus qui l'ecrit et
/// le rang du lancement dans ce processus (`sing-box-<pid>-<debut>-<n>.json`).
/// Le coeur qui s'arrete retire le sien ([`super::superviseur::demarrer`])
/// sans jamais toucher a celui du lancement qui le remplace, et le daemon qui
/// demarre retire ceux dont le processus est mort
/// ([`retirer_les_configurations_mortes`]).
pub fn chemin_configuration(emplacements: &Emplacements, coeur: Coeur) -> PathBuf {
    let rang = LANCEMENTS.fetch_add(1, Ordering::Relaxed);
    emplacements.configurations.join(format!(
        "{}-{}-{rang}.json",
        coeur.executable(),
        ce_processus()
    ))
}

/// Ce qu'un nom de fichier du repertoire des configurations dit de son
/// auteur.
#[cfg(any(target_os = "linux", windows))]
#[derive(Debug, PartialEq, Eq)]
enum Auteur {
    /// Un lancement de ce produit: le processus qui l'a ecrit.
    Processus { pid: u32, debut: u64 },
    /// Le nom fixe d'avant le 02/10/2026 (`sing-box.json`): aucun processus
    /// qui tourne avec ce code ne l'ecrit.
    NomFixe,
    /// Tout autre nom: rien que ce produit reconnaisse.
    Inconnu,
}

#[cfg(any(target_os = "linux", windows))]
fn auteur(nom: &str) -> Auteur {
    fn entier<T: std::str::FromStr>(s: &str) -> Option<T> {
        let canonique = !s.is_empty()
            && s.bytes().all(|b| b.is_ascii_digit())
            && (s == "0" || !s.starts_with('0'));
        if canonique { s.parse().ok() } else { None }
    }
    let Some(base) = nom.strip_suffix(".json") else {
        return Auteur::Inconnu;
    };
    for coeur in Coeur::TOUS {
        let exe = coeur.executable();
        if base == exe {
            return Auteur::NomFixe;
        }
        let Some(reste) = base.strip_prefix(exe).and_then(|r| r.strip_prefix('-')) else {
            continue;
        };
        let champs: Vec<&str> = reste.split('-').collect();
        if let [pid, debut, rang] = champs.as_slice()
            && let (Some(pid), Some(debut), Some(_)) = (
                entier::<u32>(pid),
                entier::<u64>(debut),
                entier::<u64>(rang),
            )
        {
            return Auteur::Processus { pid, debut };
        }
    }
    Auteur::Inconnu
}

/// Au demarrage du daemon: retire de `repertoire` les configurations de coeur
/// que plus aucun processus ne tient. Elles portent le secret de l'API de
/// controle et ceux du profil, et leur repertoire survit a l'arret du service
/// (sous Linux jusqu'au redemarrage de la machine, sous Windows au-dela).
///
/// - un fichier `<coeur>-<pid>-<debut>-<n>.json` dont le processus est mort
///   (PID absent, repris par un processus d'une autre date de debut, ou
///   termine; sous Linux, le meme jugement que pour les sessions du journal
///   de routage) est retire; celui d'un processus vivant est laisse;
/// - un fichier au nom fixe d'avant le 02/10/2026 (`<coeur>.json`) est
///   retire: le daemon d'aujourd'hui n'ecrit plus ce nom;
/// - tout le reste (autre nom, repertoire, lien) est laisse.
///
/// Rend ce qui a ete retire. Seule la lecture du repertoire est une erreur;
/// un fichier qui ne se juge pas ou ne se retire pas est laisse et dit.
#[cfg(any(target_os = "linux", windows))]
pub fn retirer_les_configurations_mortes(repertoire: &Path) -> std::io::Result<Vec<PathBuf>> {
    let lecture = match std::fs::read_dir(repertoire) {
        Ok(l) => l,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut retires = Vec::new();
    for entree in lecture {
        let entree = entree?;
        let chemin = entree.path();
        let Some(nom) = entree.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let a_retirer = match auteur(&nom) {
            Auteur::Inconnu => false,
            Auteur::NomFixe => true,
            Auteur::Processus { pid, debut } => match processus::vivant(pid, debut) {
                Ok(vivant) => !vivant,
                Err(e) => {
                    tracing::warn!(
                        erreur = %e,
                        configuration = %chemin.display(),
                        "configuration d'un coeur laissee: son processus ne se juge pas"
                    );
                    false
                }
            },
        };
        if !a_retirer {
            continue;
        }
        match std::fs::symlink_metadata(&chemin) {
            Ok(m) if m.file_type().is_file() => {}
            _ => continue,
        }
        match std::fs::remove_file(&chemin) {
            Ok(()) => retires.push(chemin),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => tracing::warn!(
                erreur = %e,
                configuration = %chemin.display(),
                "configuration d'un coeur mort non retiree"
            ),
        }
    }
    retires.sort();
    Ok(retires)
}

/// Chemin de l'executable d'un coeur.
pub fn chemin_binaire(emplacements: &Emplacements, coeur: Coeur) -> PathBuf {
    emplacements
        .binaires
        .join(format!("{}{}", coeur.executable(), extension_executable()))
}

/// Construit le lancement d'un coeur.
///
/// `port_api` n'est retenu que si le coeur expose reellement une API Clash.
/// Le passer a un coeur qui n'en a pas ferait attendre indefiniment une
/// reponse qui ne viendrait jamais.
pub fn preparer(emplacements: &Emplacements, coeur: Coeur, port_api: u16) -> Lancement {
    let configuration = chemin_configuration(emplacements, coeur);
    let arguments: Vec<OsString> = match coeur {
        // sing-box run -c <config>
        Coeur::SingBox => vec!["run".into(), "-c".into(), configuration.clone().into()],
        // xray run -config <config>
        Coeur::XrayCore => vec!["run".into(), "-config".into(), configuration.clone().into()],
        // amneziawg-go prend le nom de l'interface, sa configuration passe par
        // le protocole UAPI et non par un fichier au lancement.
        Coeur::AmneziaWg => vec!["awg0".into()],
    };
    Lancement {
        programme: chemin_binaire(emplacements, coeur),
        arguments,
        configuration,
        api_clash: coeur.a_une_api_clash().then_some(port_api),
        // Aucun compte dedie par defaut: les recettes qui ne posent pas de kill
        // switch tournent tres bien sous celui du daemon, et exiger un compte
        // qui n'existe pas les ferait echouer pour une raison sans rapport avec
        // ce qu'elles eprouvent.
        utilisateur: None,
    }
}

/// Le binaire du coeur est-il present et est-ce bien un fichier.
///
/// Verifie avant de lancer, pour que l'absence d'un coeur devienne un refus
/// explicite plutot qu'un echec de `spawn` au milieu d'une bascule.
pub fn binaire_present(lancement: &Lancement) -> bool {
    fichier_existe(&lancement.programme)
}

fn fichier_existe(p: &Path) -> bool {
    p.metadata().map(|m| m.is_file()).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn emplacements() -> Emplacements {
        Emplacements {
            binaires: PathBuf::from("/opt/bifrost/coeurs"),
            configurations: PathBuf::from("/var/lib/bifrost"),
        }
    }

    #[test]
    fn sing_box_recoit_son_fichier_de_configuration() {
        let l = preparer(&emplacements(), Coeur::SingBox, 9090);
        assert_eq!(l.arguments[0], OsString::from("run"));
        assert_eq!(l.arguments[1], OsString::from("-c"));
        assert_eq!(OsString::from(l.configuration.clone()), l.arguments[2]);
    }

    #[test]
    fn xray_utilise_son_propre_drapeau() {
        // -config chez Xray, -c chez sing-box. Les intervertir donne un coeur
        // qui refuse de demarrer avec un message qui ne dit pas pourquoi.
        let l = preparer(&emplacements(), Coeur::XrayCore, 9090);
        assert_eq!(l.arguments[1], OsString::from("-config"));
        assert_ne!(l.arguments[1], OsString::from("-c"));
    }

    #[test]
    fn seul_le_coeur_a_api_clash_recoit_un_port() {
        assert_eq!(
            preparer(&emplacements(), Coeur::SingBox, 9090).api_clash,
            Some(9090)
        );
        assert_eq!(
            preparer(&emplacements(), Coeur::XrayCore, 9090).api_clash,
            None
        );
        assert_eq!(
            preparer(&emplacements(), Coeur::AmneziaWg, 9090).api_clash,
            None
        );
    }

    #[test]
    fn chaque_coeur_a_sa_propre_configuration() {
        let e = emplacements();
        let mut vus: Vec<PathBuf> = Coeur::TOUS
            .iter()
            .map(|c| chemin_configuration(&e, *c))
            .collect();
        let avant = vus.len();
        vus.sort();
        vus.dedup();
        assert_eq!(
            avant,
            vus.len(),
            "deux coeurs ecriraient dans le meme fichier"
        );
    }

    /// Chaque lancement a son fichier: le coeur qui s'arrete retire le sien,
    /// jamais celui du lancement qui le remplace.
    #[test]
    fn deux_lancements_n_ecrivent_jamais_le_meme_fichier() {
        let e = emplacements();
        let a = chemin_configuration(&e, Coeur::SingBox);
        let b = chemin_configuration(&e, Coeur::SingBox);
        assert_ne!(a, b);
        for c in [&a, &b] {
            assert_eq!(c.parent(), Some(e.configurations.as_path()));
            let nom = c.file_name().unwrap().to_string_lossy().to_string();
            assert!(
                nom.starts_with("sing-box-") && nom.ends_with(".json"),
                "{nom}"
            );
        }
    }

    /// Le nom porte le processus qui l'ecrit, PID et date de debut: c'est ce
    /// que le demarrage suivant juge.
    #[cfg(any(target_os = "linux", windows))]
    #[test]
    fn le_nom_porte_ce_processus() {
        let (pid, debut) = processus::moi().unwrap();
        assert_eq!(pid, std::process::id());
        assert!(processus::vivant(pid, debut).unwrap(), "ce processus vit");
        let c = chemin_configuration(&emplacements(), Coeur::XrayCore);
        let nom = c.file_name().unwrap().to_string_lossy().to_string();
        assert_eq!(auteur(&nom), Auteur::Processus { pid, debut }, "{nom}");
    }

    #[cfg(any(target_os = "linux", windows))]
    #[test]
    fn un_nom_se_lit_strictement() {
        assert_eq!(
            auteur("sing-box-12-345-0.json"),
            Auteur::Processus {
                pid: 12,
                debut: 345
            }
        );
        assert_eq!(
            auteur("amneziawg-go-7-8-9.json"),
            Auteur::Processus { pid: 7, debut: 8 }
        );
        assert_eq!(auteur("sing-box.json"), Auteur::NomFixe);
        assert_eq!(auteur("xray.json"), Auteur::NomFixe);
        for autre in [
            "sing-box-12-345.json",
            "sing-box-12-345-0-1.json",
            "sing-box-012-345-0.json",
            "sing-box-12-x-0.json",
            "sing-box-12-345-0.toml",
            "sing-box-12--0.json",
            "singbox-12-345-0.json",
            "sing-box-4242-illisible-0.json",
            "autre.json",
            ".json",
        ] {
            assert_eq!(auteur(autre), Auteur::Inconnu, "{autre}");
        }
    }

    /// Le demarrage retire les configurations des processus morts et celles
    /// au nom fixe d'avant, et laisse celles d'un processus vivant et tout ce
    /// qu'il ne reconnait pas.
    #[cfg(any(target_os = "linux", windows))]
    #[test]
    fn au_demarrage_les_configurations_mortes_partent_et_les_vivantes_restent() {
        let rep =
            std::env::temp_dir().join(format!("bifrost-configurations-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&rep);
        std::fs::create_dir(&rep).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&rep, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let (pid, debut) = processus::moi().unwrap();
        // Le meme PID a une autre date de debut: un processus mort dont le
        // PID a ete repris.
        let repris = format!("sing-box-{pid}-{}-0.json", debut + 1);
        // Un processus termine, attendu et dont la poignee est fermee: son PID
        // ne designe plus rien, ou un processus d'une autre date.
        let fini = {
            let mut enfant = if cfg!(windows) {
                std::process::Command::new("cmd")
                    .args(["/C", "exit 0"])
                    .spawn()
            } else {
                std::process::Command::new("true").spawn()
            }
            .expect("un processus bref");
            enfant.wait().expect("attente du processus bref");
            enfant.id()
        };
        let termine = format!("sing-box-{fini}-1-0.json");
        // Un numero qu'aucun processus ne porte, bien au-dela de ceux que
        // l'un ou l'autre systeme attribue.
        let absent = format!("xray-{}-1-0.json", u32::MAX - 3);
        let vivant = format!("sing-box-{pid}-{debut}-3.json");
        let fichiers = [
            repris.as_str(),
            termine.as_str(),
            absent.as_str(),
            vivant.as_str(),
            "sing-box.json",
            "xray.json",
            "autre.json",
            "sing-box-1-x-0.json",
        ];
        for f in fichiers {
            std::fs::write(rep.join(f), "{}").unwrap();
        }
        std::fs::create_dir(rep.join(format!("xray-{pid}-{}-1.json", debut + 1))).unwrap();

        let retires = retirer_les_configurations_mortes(&rep).unwrap();

        let mut attendus = vec![
            rep.join(&repris),
            rep.join(&termine),
            rep.join(&absent),
            rep.join("sing-box.json"),
            rep.join("xray.json"),
        ];
        attendus.sort();
        assert_eq!(retires, attendus);
        for f in [vivant.as_str(), "autre.json", "sing-box-1-x-0.json"] {
            assert!(rep.join(f).exists(), "{f} doit rester");
        }
        for f in [
            repris.as_str(),
            termine.as_str(),
            absent.as_str(),
            "sing-box.json",
            "xray.json",
        ] {
            assert!(!rep.join(f).exists(), "{f} doit partir");
        }
        assert!(
            rep.join(format!("xray-{pid}-{}-1.json", debut + 1))
                .is_dir()
        );
        assert_eq!(
            retirer_les_configurations_mortes(&rep.join("absent")).unwrap(),
            Vec::<PathBuf>::new()
        );
        let _ = std::fs::remove_dir_all(&rep);
    }

    #[test]
    fn le_binaire_est_cherche_dans_le_repertoire_fourni_et_pas_dans_le_path() {
        // Laisser le PATH decider permettrait a un tiers de placer son propre
        // "sing-box" devant le notre. La propriete a verifier est donc que le
        // chemin PORTE un repertoire, pas qu'il soit absolu: `is_absolute` ne
        // veut pas dire la meme chose des deux cotes, un chemin a la Unix
        // n'etant pas absolu sous Windows faute de lettre de lecteur.
        let e = emplacements();
        let l = preparer(&e, Coeur::SingBox, 9090);
        assert_eq!(l.programme.parent(), Some(e.binaires.as_path()));
        assert_ne!(
            l.programme.as_os_str(),
            OsString::from(Coeur::SingBox.executable()),
            "un nom nu serait resolu par le PATH"
        );
    }

    #[test]
    fn l_extension_suit_la_plateforme() {
        let l = preparer(&emplacements(), Coeur::SingBox, 9090);
        let nom = l
            .programme
            .file_name()
            .unwrap()
            .to_string_lossy()
            .to_string();
        if cfg!(windows) {
            assert_eq!(nom, "sing-box.exe");
        } else {
            assert_eq!(nom, "sing-box");
        }
    }

    #[test]
    fn un_binaire_absent_est_vu_comme_absent() {
        let l = preparer(&emplacements(), Coeur::SingBox, 9090);
        assert!(!binaire_present(&l));
    }

    #[test]
    fn un_repertoire_portant_le_nom_du_binaire_ne_passe_pas_pour_un_binaire() {
        // `exists()` seul rendrait vrai sur un repertoire, et le lancement
        // echouerait plus tard avec une erreur de permission incomprehensible.
        let racine =
            std::env::temp_dir().join(format!("bifrost-essai-coeur-{}", std::process::id()));
        let faux = racine.join(format!("sing-box{}", extension_executable()));
        std::fs::create_dir_all(&faux).unwrap();
        let l = preparer(
            &Emplacements {
                binaires: racine.clone(),
                configurations: racine.clone(),
            },
            Coeur::SingBox,
            9090,
        );
        assert!(l.programme.exists(), "le repertoire piege n'a pas ete cree");
        assert!(!binaire_present(&l));
        let _ = std::fs::remove_dir_all(&racine);
    }
}
