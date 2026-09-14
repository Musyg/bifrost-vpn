//! Le versant Linux de [`super::doh_pose`]: l'ecriture sur le disque.
//!
//! Symetrique de [`super::doh_fichiers`], qui lit les memes emplacements. Ce
//! module ne decide rien: [`super::doh_pose`] dit quoi ecrire et quand refuser,
//! il se contente de le porter sur le disque et de rendre compte.
//!
//! # Ce que `retirer` enleve, et sa limite
//!
//! Les fichiers deposes dans les repertoires `managed` portent notre nom, donc
//! le retrait sait exactement lesquels sont a nous.
//!
//! Le `policies.json` de Firefox n'a pas cette chance: on n'en retire la clef
//! `DNSOverHTTPS` que si elle vaut EXACTEMENT ce que Bifrost ecrit. Limite
//! assumee: une politique identique a la notre, posee par quelqu'un d'autre
//! avant nous, serait retiree elle aussi, rien ne les distingue. Le cas est
//! benin et surtout VISIBLE, puisque le vecteur `doh-bypass` repasse alors au
//! rouge et le dit.

use std::path::{Path, PathBuf};

use super::doh_pose::{self, Fusion, Pose};

/// Une famille Chromium et ou vivent ses politiques.
struct Cible {
    nom: &'static str,
    binaires: &'static [&'static str],
    /// Par ordre de preference. `chromium` porte deux dispositions selon la
    /// distribution, et ce sont deux noms du MEME navigateur: en servir les
    /// deux creerait une arborescence que rien ne lit.
    repertoires: &'static [&'static str],
}

const CIBLES: &[Cible] = &[
    Cible {
        nom: "chrome",
        binaires: &["/usr/bin/google-chrome", "/usr/bin/google-chrome-stable"],
        repertoires: &["/etc/opt/chrome/policies/managed"],
    },
    Cible {
        nom: "chromium",
        binaires: &["/usr/bin/chromium", "/usr/bin/chromium-browser"],
        repertoires: &[
            "/etc/chromium/policies/managed",
            "/etc/chromium-browser/policies/managed",
        ],
    },
    Cible {
        nom: "edge",
        binaires: &["/usr/bin/microsoft-edge", "/usr/bin/microsoft-edge-stable"],
        repertoires: &["/etc/opt/edge/policies/managed"],
    },
];

const FIREFOX: &str = "/etc/firefox/policies/policies.json";

impl Cible {
    fn installe(&self) -> bool {
        self.binaires.iter().any(|b| Path::new(b).exists())
    }

    /// Celui dont la base existe deja, donc celui que la machine utilise. A
    /// defaut le premier, qui est la disposition moderne.
    fn repertoire(&self) -> &'static str {
        self.repertoires
            .iter()
            .copied()
            .find(|r| {
                Path::new(r)
                    .ancestors()
                    .nth(2)
                    .is_some_and(std::path::Path::exists)
            })
            .unwrap_or(self.repertoires[0])
    }
}

/// Enleve les repertoires devenus vides derriere un fichier retire.
///
/// `remove_dir` echoue sur un repertoire non vide, ce qui suffit a ne jamais
/// toucher a ce qui sert encore. La garde sur `/etc` est explicite: se reposer
/// sur cet echec pour proteger `/etc` marcherait, et c'est exactement le genre
/// de sauvegarde qu'on prefere ne pas devoir a un effet de bord.
fn nettoyer(chemin: &Path) {
    for repertoire in chemin.ancestors().skip(1).take(3) {
        if repertoire == Path::new("/etc") || std::fs::remove_dir(repertoire).is_err() {
            break;
        }
    }
}

fn fichier_de(repertoire: &str) -> PathBuf {
    Path::new(repertoire).join(doh_pose::FICHIER)
}

/// Ecrit les politiques. Ne touche a rien de ce qu'il n'a pas ecrit.
pub fn poser() -> Vec<(String, Pose)> {
    let mut resultats = Vec::new();

    for cible in CIBLES {
        // Un navigateur absent n'a pas besoin d'etre bride, et creer son
        // repertoire de politiques laisserait un residu sans objet.
        if !cible.installe() {
            resultats.push((
                cible.nom.to_owned(),
                Pose::HorsObjet("non installe".to_owned()),
            ));
            continue;
        }
        let repertoire = cible.repertoire();
        let chemin = fichier_de(repertoire);
        let voulu = doh_pose::chromium_json();
        if std::fs::read_to_string(&chemin).is_ok_and(|d| d == voulu) {
            resultats.push((
                cible.nom.to_owned(),
                Pose::DejaPose(chemin.display().to_string()),
            ));
            continue;
        }
        let pose = match std::fs::create_dir_all(repertoire) {
            Err(e) => Pose::Refus(format!("{repertoire} non creable: {e}")),
            Ok(()) => match std::fs::write(&chemin, &voulu) {
                Err(e) => Pose::Refus(format!("{} non ecrivable: {e}", chemin.display())),
                Ok(()) => Pose::Posee(chemin.display().to_string()),
            },
        };
        resultats.push((cible.nom.to_owned(), pose));
    }

    resultats.push(("firefox".to_owned(), poser_firefox()));
    resultats
}

fn poser_firefox() -> Pose {
    let chemin = Path::new(FIREFOX);
    let existant = match std::fs::read_to_string(chemin) {
        Ok(t) => Some(t),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Pose::Refus(format!("{FIREFOX} non lisible: {e}")),
    };
    match doh_pose::firefox_fusionner(existant.as_deref()) {
        Fusion::DejaPose => Pose::DejaPose(FIREFOX.to_owned()),
        Fusion::Conflit(r) | Fusion::Illisible(r) => Pose::Refus(format!("{FIREFOX}: {r}")),
        Fusion::Ecrire(contenu) => {
            if let Some(parent) = chemin.parent()
                && let Err(e) = std::fs::create_dir_all(parent)
            {
                return Pose::Refus(format!("{} non creable: {e}", parent.display()));
            }
            match std::fs::write(chemin, contenu) {
                Err(e) => Pose::Refus(format!("{FIREFOX} non ecrivable: {e}")),
                Ok(()) => Pose::Posee(FIREFOX.to_owned()),
            }
        }
    }
}

/// Retire ce que [`poser`] a ecrit, et rien d'autre.
///
/// Les DEUX dispositions de `chromium` sont visitees, pas seulement celle que
/// [`Cible::repertoire`] retiendrait aujourd'hui: une version anterieure
/// ecrivait dans les deux, et un retrait qui ne nettoie que le chemin courant
/// laisserait l'autre en place sans que personne le sache.
pub fn retirer() -> Vec<(String, Pose)> {
    let mut resultats = Vec::new();

    for cible in CIBLES {
        let mut retires = Vec::new();
        let mut refus = None;
        for repertoire in cible.repertoires {
            let chemin = fichier_de(repertoire);
            match std::fs::remove_file(&chemin) {
                Ok(()) => {
                    nettoyer(&chemin);
                    retires.push(chemin.display().to_string());
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => refus = Some(format!("{} non supprimable: {e}", chemin.display())),
            }
        }
        let pose = match (refus, retires.is_empty()) {
            (Some(r), _) => Pose::Refus(r),
            (None, true) => Pose::HorsObjet("rien a retirer".to_owned()),
            (None, false) => Pose::Retiree(retires.join(", ")),
        };
        resultats.push((cible.nom.to_owned(), pose));
    }

    resultats.push(("firefox".to_owned(), retirer_firefox()));
    resultats
}

fn retirer_firefox() -> Pose {
    let texte = match std::fs::read_to_string(FIREFOX) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Pose::HorsObjet("rien a retirer".to_owned());
        }
        Err(e) => return Pose::Refus(format!("{FIREFOX} non lisible: {e}")),
    };
    match doh_pose::firefox_defusionner(&texte) {
        Err(r) => Pose::Refus(format!("{FIREFOX}: {r}")),
        Ok(None) => Pose::HorsObjet("aucune politique de Bifrost dans ce fichier".to_owned()),
        // Le document ne porte plus rien: le laisser serait un residu.
        Ok(Some(reste)) if reste.trim() == doh_pose::VIDE => match std::fs::remove_file(FIREFOX) {
            Err(e) => Pose::Refus(format!("{FIREFOX} non supprimable: {e}")),
            Ok(()) => {
                nettoyer(Path::new(FIREFOX));
                Pose::Retiree(format!("{FIREFOX} (devenu vide, supprime)"))
            }
        },
        Ok(Some(reste)) => match std::fs::write(FIREFOX, reste) {
            Err(e) => Pose::Refus(format!("{FIREFOX} non ecrivable: {e}")),
            Ok(()) => Pose::Retiree(FIREFOX.to_owned()),
        },
    }
}
