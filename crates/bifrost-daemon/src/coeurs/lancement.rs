//! Comment lancer un coeur: la ligne de commande, et rien d'autre.
//!
//! Pure, donc testee partout. C'est le genre de code ou une erreur ne se voit
//! qu'a l'execution, sur une machine ou le coeur est installe, c'est-a-dire
//! nulle part en integration continue.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

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

/// Chemin du fichier de configuration d'un coeur.
pub fn chemin_configuration(emplacements: &Emplacements, coeur: Coeur) -> PathBuf {
    emplacements
        .configurations
        .join(format!("{}.json", coeur.executable()))
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
        let racine = std::env::temp_dir().join("bifrost-essai-coeur");
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
