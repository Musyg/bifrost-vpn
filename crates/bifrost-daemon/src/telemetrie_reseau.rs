//! La couche 2 anti-telemetrie, cote machine.
//!
//! Le PLAN vit dans [`bifrost_firewall::plan_telemetrie`], pur et verifie sur
//! les deux hotes. Ici vit ce qui touche la machine: decider si une cible peut
//! reellement etre bloquee, poser, retirer, rendre compte.
//!
//! La regle est celle de la couche 1: **une cible qui ne peut pas etre bloquee
//! est SANS OBJET, jamais posee et jamais comptee comme une protection.** Trois
//! facons de ne pas pouvoir l'etre:
//!
//! 1. le service n'existe pas sur cette machine;
//! 2. le binaire vise n'existe pas a l'emplacement attendu;
//! 3. le service existe mais son `SERVICE_SID_TYPE` vaut `NONE`, donc son jeton
//!    ne porte AUCUN SID de service et la condition `ALE_USER_ID` ne
//!    correspondrait jamais.
//!
//! Le troisieme cas est vicieux: le filtre se pose sans erreur, il est bien
//! present dans le moteur, il est enumerable, et il ne bloque rien. Sans cette verification, le produit annoncerait une protection
//! posee et verifiable qui n'existerait pas. Le depot connaissait deja ce piege
//! pour son PROPRE service - `service::spec::le_service_porte_son_propre_sid`,
//! ecrit le 16 aout 2026 - mais du cote de l'AUTORISATION; ici il touche le
//! blocage.
//!
//! **Et il en existe un quatrieme, decouvert le 22 aout 2026, que ce module ne
//! sait pas encore detecter.** Sur essai-windows, DiagTrack a `SERVICE_SID_TYPE
//! UNRESTRICTED`, son SID de service est verifie PRESENT dans le jeton du
//! processus, le filtre est verifie present dans le moteur par `netsh`, et la
//! connexion passe quand meme. Les trois verdicts ci-dessus disent donc
//! `Posable` pour une cible qui n'est pas protegee. C'est la limite actuelle de
//! la couche, que le document 03 decrit, et [`sonder_sid`] existe pour
//! l'isoler.

use std::path::PathBuf;

use bifrost_core::config::ProfilTelemetrie as Profil;
use bifrost_firewall::plan_telemetrie::{self, Cible};
use bifrost_firewall::windows::WfpKillSwitch;
use windows_sys::Win32::System::Services::SERVICE_SID_TYPE_NONE;

/// Ce qu'on peut faire d'une cible sur CETTE machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Le filtre peut etre pose et il mordra.
    Posable,
    /// Rien a poser, et la raison. Jamais un succes.
    SansObjet(String),
}

impl Verdict {
    pub fn mot(&self) -> &'static str {
        match self {
            Verdict::Posable => "POSABLE",
            Verdict::SansObjet(_) => "SANS OBJET",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Ligne {
    pub id: &'static str,
    pub cible: String,
    pub verdict: Verdict,
}

#[derive(Debug)]
pub struct Rapport {
    pub profil: Profil,
    pub lignes: Vec<Ligne>,
    /// Nombre de filtres REELLEMENT poses dans le moteur. Zero pour un simple
    /// etat des lieux.
    pub filtres_poses: usize,
}

impl Rapport {
    pub fn posables(&self) -> usize {
        self.lignes
            .iter()
            .filter(|l| l.verdict == Verdict::Posable)
            .count()
    }

    pub fn en_clair(&self) -> String {
        let mut s = String::new();
        for l in &self.lignes {
            s.push_str(&format!(
                "{:<11} {:<28} {}\n",
                l.verdict.mot(),
                l.id,
                l.cible
            ));
            if let Verdict::SansObjet(raison) = &l.verdict {
                s.push_str(&format!("            {raison}\n"));
            }
        }
        // Les deux nombres n'ont AUCUN rapport, et la premiere redaction les
        // mettait cote a cote separes d'une virgule: le premier compte les
        // cibles de CE profil, le second ce que le moteur porte a cet instant,
        // quel que soit le profil qui l'a pose. Sur une machine ou `strict`
        // rendait 8 posables et ou `equilibre` etait deja pose, la ligne
        // affichait "8 cible(s) posable(s) sur 10, 8 filtre(s) dans le moteur"
        // et les deux 8 se lisaient comme s'ils se confirmaient, alors
        // qu'ils ne portaient meme pas sur les memes cibles.
        s.push_str(&format!(
            "\n{} cible(s) posable(s) sur {} pour ce profil.\n",
            self.posables(),
            self.lignes.len()
        ));
        s.push_str(&format!(
            "Independamment: {} filtre(s) de la couche 2 dans le moteur en ce moment, quel que soit le profil qui les a poses.\n",
            self.filtres_poses
        ));
        s
    }
}

/// La racine systeme, jamais codee en dur: elle n'est pas toujours `C:\Windows`.
fn racine_systeme() -> PathBuf {
    PathBuf::from(std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string()))
}

/// Le verdict d'une cible, sans rien modifier.
fn juger(cible: &Cible) -> Verdict {
    match cible {
        Cible::Service(nom) => match crate::service::scm::type_de_sid_du_service(nom) {
            Err(e) => Verdict::SansObjet(format!("interrogation du service impossible: {e}")),
            Ok(None) => {
                Verdict::SansObjet(format!("le service {nom} n'existe pas sur cette machine"))
            }
            Ok(Some(t)) if t == SERVICE_SID_TYPE_NONE => Verdict::SansObjet(format!(
                "{nom} est configure en SERVICE_SID_TYPE NONE: son jeton ne porte \
                 aucun SID de service, et un filtre conditionne sur ALE_USER_ID se \
                 poserait sans jamais mordre"
            )),
            Ok(Some(_)) => Verdict::Posable,
        },
        Cible::Binaire(relatif) => {
            let chemin = plan_telemetrie::chemin(&racine_systeme(), relatif);
            if chemin.is_file() {
                Verdict::Posable
            } else {
                Verdict::SansObjet(format!("{} n'existe pas", chemin.display()))
            }
        }
    }
}

fn decrire(cible: &Cible) -> String {
    match cible {
        Cible::Service(nom) => format!("service {nom} ({})", plan_telemetrie::sid_de_service(nom)),
        Cible::Binaire(rel) => plan_telemetrie::chemin(&racine_systeme(), rel)
            .display()
            .to_string(),
    }
}

/// Etat des lieux. Ne modifie rien, et ne demande donc pas l'elevation pour la
/// partie fichiers; l'interrogation du SCM, elle, se contente de
/// `SC_MANAGER_CONNECT`.
pub fn etat(profil: Profil) -> Rapport {
    let lignes = plan_telemetrie::blocages(profil)
        .into_iter()
        .map(|b| Ligne {
            id: b.id,
            cible: decrire(&b.cible),
            verdict: juger(&b.cible),
        })
        .collect();
    let filtres_poses = WfpKillSwitch::new()
        .and_then(|k| k.filtres_telemetrie_vus())
        .map(|v| v.len())
        .unwrap_or(0);
    Rapport {
        profil,
        lignes,
        filtres_poses,
    }
}

/// Pose la couche 2, en n'y mettant que ce qui peut mordre.
///
/// Rend le rapport, avec le nombre de filtres que le moteur porte REELLEMENT
/// apres la pose - relu, pas suppose. C'est la meme regle qu'a la couche 1, et
/// pour la meme raison: un moteur qui accepte une transaction n'est pas la
/// preuve que la politique voulue s'y trouve.
pub fn appliquer(profil: Profil) -> anyhow::Result<Rapport> {
    let racine = racine_systeme();
    let blocages = plan_telemetrie::blocages(profil);

    let lignes: Vec<Ligne> = blocages
        .iter()
        .map(|b| Ligne {
            id: b.id,
            cible: decrire(&b.cible),
            verdict: juger(&b.cible),
        })
        .collect();

    let retenus: Vec<&str> = lignes
        .iter()
        .filter(|l| l.verdict == Verdict::Posable)
        .map(|l| l.id)
        .collect();

    let plan: Vec<_> = plan_telemetrie::plan(profil, &racine)
        .into_iter()
        .filter(|spec| retenus.iter().any(|id| spec.name.ends_with(id)))
        .collect();

    let kill = WfpKillSwitch::new()?;
    kill.poser_telemetrie(&plan)?;

    // Relire. Le nombre annonce est celui que le moteur porte, pas celui qu'on
    // a cru poser.
    let filtres_poses = kill.filtres_telemetrie_vus()?.len();
    Ok(Rapport {
        profil,
        lignes,
        filtres_poses,
    })
}

/// Retire la couche 2. Rend le nombre de filtres qui restent, qui doit etre nul.
/// Pose UNE sonde de diagnostic sur un SID choisi, et rend le nombre de
/// filtres que le moteur porte apres coup.
///
/// Elle vit dans les memes provider et sublayer que la couche 2, donc
/// `--telemetrie-reseau-retirer` la defait comme le reste: une sonde qui aurait
/// sa propre sortie de secours serait une sortie de secours de plus a oublier.
/// Le corollaire est qu'elle REMPLACE la couche si elle est posee, la pose
/// commencant par un balayage; c'est voulu, on ne mesure pas un filtre au
/// milieu de neuf autres.
pub fn sonder_sid(sid: &str) -> anyhow::Result<usize> {
    let plan = plan_telemetrie::plan_sonde(sid).map_err(|e| anyhow::anyhow!(e))?;
    let kill = WfpKillSwitch::new()?;
    kill.poser_telemetrie(&plan)?;
    Ok(kill.filtres_telemetrie_vus()?.len())
}

/// Pose UNE sonde de diagnostic sur un CHEMIN de binaire, et rend le nombre de
/// filtres que le moteur porte apres coup.
///
/// Meme vie et meme sortie de secours que [`sonder_sid`]: memes provider et
/// sublayer que la couche 2, donc `--telemetrie-reseau-retirer` la defait, et
/// la pose commence par un balayage, donc elle REMPLACE ce qui etait pose. On
/// ne mesure pas un filtre au milieu de neuf autres.
///
/// La racine systeme vient de la machine, comme partout ailleurs dans ce
/// module: c'est elle que [`plan_telemetrie::plan_sonde_binaire`] compare pour
/// refuser de viser un binaire du systeme, et la coder en dur ici ouvrirait ce
/// refus sur une machine installee ailleurs que sur `C:`.
pub fn sonder_binaire(binaire: &std::path::Path) -> anyhow::Result<usize> {
    let plan = plan_telemetrie::plan_sonde_binaire(binaire, &racine_systeme())
        .map_err(|e| anyhow::anyhow!(e))?;
    let kill = WfpKillSwitch::new()?;
    kill.poser_telemetrie(&plan)?;
    Ok(kill.filtres_telemetrie_vus()?.len())
}

pub fn retirer() -> anyhow::Result<usize> {
    let kill = WfpKillSwitch::new()?;
    kill.retirer_telemetrie()?;
    Ok(kill.filtres_telemetrie_vus().map(|v| v.len()).unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SANS OBJET n'est pas un succes deguise: il porte toujours sa raison, et
    /// une raison vide serait pire que pas de raison du tout.
    #[test]
    fn le_resume_ne_laisse_pas_confondre_les_deux_nombres() {
        // Un lecteur doit pouvoir dire, sans connaitre le code, lequel des
        // deux nombres parle du profil demande et lequel parle du moteur.
        // Les coller derriere une virgule les fait lire comme une
        // confirmation mutuelle alors qu'ils ne portent meme pas sur les
        // memes cibles.
        let rapport = Rapport {
            profil: Profil::Strict,
            lignes: vec![Ligne {
                id: "service-diagtrack",
                cible: "DiagTrack".into(),
                verdict: Verdict::Posable,
            }],
            filtres_poses: 8,
        };
        let texte = rapport.en_clair();
        assert!(
            texte.contains("pour ce profil"),
            "le compte des cibles doit dire qu'il parle du profil demande: {texte}"
        );
        assert!(
            texte.contains("quel que soit le profil qui les a poses"),
            "le compte du moteur doit dire qu'il ne parle PAS du profil: {texte}"
        );
        for ligne in texte.lines() {
            assert!(
                !(ligne.contains("posable(s)") && ligne.contains("dans le moteur")),
                "les deux comptes partagent une ligne, donc une lecture: {ligne}"
            );
        }
    }

    #[test]
    fn sans_objet_dit_toujours_pourquoi() {
        let v = Verdict::SansObjet("parce que".into());
        assert_eq!(v.mot(), "SANS OBJET");
        assert_ne!(v, Verdict::Posable);
    }

    /// Le rapport ne compte comme protection que ce qui est posable. Un
    /// SANS OBJET compte dans le total mais jamais dans les protections.
    #[test]
    fn le_rapport_ne_compte_pas_les_sans_objet_comme_des_protections() {
        let r = Rapport {
            profil: Profil::Strict,
            lignes: vec![
                Ligne {
                    id: "a",
                    cible: "x".into(),
                    verdict: Verdict::Posable,
                },
                Ligne {
                    id: "b",
                    cible: "y".into(),
                    verdict: Verdict::SansObjet("absent".into()),
                },
            ],
            filtres_poses: 2,
        };
        assert_eq!(r.posables(), 1);
        assert_eq!(r.lignes.len(), 2);
        assert!(r.en_clair().contains("1 cible(s) posable(s) sur 2"));
        assert!(r.en_clair().contains("absent"));
    }

    /// Le rapport en clair doit nommer la raison de chaque abstention, sinon il
    /// se lit comme une liste de succes.
    #[test]
    fn chaque_sans_objet_apparait_avec_sa_raison_dans_le_texte() {
        let r = Rapport {
            profil: Profil::Equilibre,
            lignes: vec![Ligne {
                id: "service-x",
                cible: "service X".into(),
                verdict: Verdict::SansObjet("SERVICE_SID_TYPE NONE".into()),
            }],
            filtres_poses: 0,
        };
        let t = r.en_clair();
        assert!(t.contains("SANS OBJET"));
        assert!(t.contains("SERVICE_SID_TYPE NONE"));
        assert!(t.contains("0 cible(s) posable(s) sur 1"));
    }
}
