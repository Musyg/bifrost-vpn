//! Politiques d'attenuation a l'execution du daemon Windows.
//!
//! Le document 07 (section 2.4) demande que le daemon se les applique par
//! `SetProcessMitigationPolicy`. Une politique posee ne se retire plus, et ne
//! vaut que pour ce qui arrive APRES sa pose: une image deja chargee, un
//! crochet deja installe lui echappent. D'ou sa place, la premiere instruction
//! de `main`, avant meme la lecture de la ligne de commande, pour le service
//! comme pour la console et les sous-commandes. La CLI n'en pose aucune.
//!
//! # Ce qui est pose
//!
//! [`POSEES`], dans cet ordre:
//! - `ProcessImageLoadPolicy`: aucune image chargee depuis un peripherique
//!   distant (partage UNC) ni portant l'etiquette d'integrite basse; une image
//!   chargee par son nom est cherchee dans System32 avant le repertoire de
//!   l'application. wintun.dll et wireguard.dll sont chargees par leur chemin
//!   absolu, a cote du binaire: rien n'est cherche pour elles.
//! - `ProcessExtensionPointDisablePolicy`: ni DLL AppInit, ni fournisseur
//!   Winsock en couche, ni crochet Windows global, ni ancien editeur de
//!   methode d'entree ne sont charges dans le daemon.
//! - `ProcessStrictHandleCheckPolicy`: une reference a une poignee invalide
//!   leve une exception au lieu de rendre une erreur, et le daemon tombe. Les
//!   deux bits sont exiges ensemble par le systeme. Ses filtres WFP lui
//!   survivent (session non dynamique) et le gestionnaire de services le
//!   relance, voir `service::scm`; aucune chute n'a ete provoquee pour le
//!   mesurer.
//! - `ProcessControlFlowGuardPolicy`, `StrictMode`: toute DLL chargee apres la
//!   pose doit porter Control Flow Guard, sinon son chargement echoue.
//!   wintun.dll et wireguard.dll le portent.
//! - `ProcessDynamicCodePolicy`, `ProhibitDynamicCode` (ACG): le processus ne
//!   peut plus rendre executable une memoire, ni modifier du code executable.
//!   Ni retrait par fil (`AllowThreadOptOut`), ni retrait par un autre
//!   processus (`AllowRemoteDowngrade`).
//!
//! # Ce qui est ecarte
//!
//! [`ECARTEES`], chacune avec sa raison: la signature, les appels systeme
//! Win32k, les processus enfants.
//!
//! # Une pose refusee
//!
//! Elle est journalisee et nommee, et le daemon continue: une politique
//! absente est un durcissement en moins, pas une raison de laisser la machine
//! sans kill switch. Le journal n'existe pas encore a la pose; [`poser`] rend
//! un [`Bilan`] que `main` confie a [`journaliser`] des que le journal est
//! ouvert. Les sous-commandes qui rendent la main avant ne journalisent rien.
//!
//! # Les enfants
//!
//! `ProcessImageLoadPolicy` passe aux processus que le daemon cree apres la
//! pose: les coeurs et le resolveur naissent avec elle. Les quatre autres ne
//! passent pas. Mesure le 02/10/2026 par `GetProcessMitigationPolicy` dans un
//! enfant cree apres la pose, sur dev-windows.
//!
//! # Gardes
//!
//! Les recettes de ce module tournent partout: la liste posee, l'ecart entre
//! posees et ecartees, le bilan qui nomme un refus, et la place de la pose dans
//! le seul `fn main` de `main.rs`. Deux binaires de recette Windows relisent les politiques
//! effectives par `GetProcessMitigationPolicy`, avec une table des bits
//! attendus ecrite a part (`tests/commun/attenuation.rs`):
//! `tests/attenuation_windows.rs` dans son propre processus apres [`poser`],
//! `tests/attenuation_daemon_windows.rs` de l'exterieur, dans un daemon lance
//! qui sert, depuis un processus qui n'en porte aucune.

/// Une politique, telle que `SetProcessMitigationPolicy` la recoit.
///
/// Chaque structure `PROCESS_MITIGATION_*_POLICY` posee ici est une union d'un
/// seul `DWORD`, `Flags`, et de ses champs de bits, le premier dans le bit de
/// poids faible: le mot `drapeaux` est donc la structure elle-meme.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Politique {
    /// Le nom de la valeur dans l'enumeration `PROCESS_MITIGATION_POLICY`.
    pub nom: &'static str,
    /// Sa valeur numerique dans cette enumeration (winnt.h).
    pub valeur: i32,
    /// Les bits poses dans `Flags`.
    pub drapeaux: u32,
    /// Les champs que ces bits designent, pour le journal.
    pub champs: &'static str,
}

/// Ce que le daemon Windows pose, dans cet ordre.
pub const POSEES: &[Politique] = &[
    Politique {
        nom: "ProcessImageLoadPolicy",
        valeur: 10,
        drapeaux: 0b111,
        champs: "NoRemoteImages, NoLowMandatoryLabelImages, PreferSystem32Images",
    },
    Politique {
        nom: "ProcessExtensionPointDisablePolicy",
        valeur: 6,
        drapeaux: 0b1,
        champs: "DisableExtensionPoints",
    },
    Politique {
        nom: "ProcessStrictHandleCheckPolicy",
        valeur: 3,
        drapeaux: 0b11,
        champs: "RaiseExceptionOnInvalidHandleReference, HandleExceptionsPermanentlyEnabled",
    },
    Politique {
        nom: "ProcessControlFlowGuardPolicy",
        valeur: 7,
        drapeaux: 0b100,
        champs: "StrictMode",
    },
    Politique {
        nom: "ProcessDynamicCodePolicy",
        valeur: 2,
        drapeaux: 0b1,
        champs: "ProhibitDynamicCode",
    },
];

/// Une politique ecartee, et ce qu'elle casserait.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ecartee {
    /// Le nom de la valeur dans l'enumeration `PROCESS_MITIGATION_POLICY`.
    pub nom: &'static str,
    /// Pourquoi elle n'est pas posee.
    pub raison: &'static str,
}

/// Ce que le daemon Windows ne pose pas, et pourquoi.
pub const ECARTEES: &[Ecartee] = &[
    Ecartee {
        nom: "ProcessSignaturePolicy",
        raison: "MicrosoftSignedOnly refuse le chargement de wintun.dll et de wireguard.dll, \
                 signees par leur editeur et non par Microsoft (mesure sous le service); \
                 StoreSignedOnly et MitigationOptIn exigent une signature du Store, de \
                 Microsoft ou WHQL, qu'elles ne portent pas non plus (documentation)",
    },
    Ecartee {
        nom: "ProcessSystemCallDisablePolicy",
        raison: "DisallowWin32kSystemCalls coupe les appels de user32, dont le lancement du \
                 resolveur sous son compte emploie quatre fonctions (window-station et bureau \
                 de la session 0); le daemon importe user32, et la pose est alors refusee",
    },
    Ecartee {
        nom: "ProcessChildProcessPolicy",
        raison: "NoChildProcessCreation interdit de creer un processus: le daemon lance les \
                 coeurs et le resolveur",
    },
];

/// Une pose que le systeme a refusee.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refus {
    /// La politique refusee.
    pub nom: &'static str,
    /// Les champs qu'elle devait poser.
    pub champs: &'static str,
    /// Le code systeme rendu par `GetLastError`.
    pub code: u32,
}

/// Ce que [`poser`] a obtenu, politique par politique.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Bilan {
    /// Les politiques posees, dans l'ordre de [`POSEES`].
    pub posees: Vec<&'static str>,
    /// Les politiques refusees, chacune avec son code.
    pub refusees: Vec<Refus>,
}

impl Bilan {
    /// Une ligne par refus, qui nomme la politique, ses champs et le code.
    pub fn refus_en_clair(&self) -> Vec<String> {
        self.refusees
            .iter()
            .map(|r| {
                format!(
                    "politique d'attenuation NON posee: {} ({}), code systeme {}; le daemon \
                     continue sans elle",
                    r.nom, r.champs, r.code
                )
            })
            .collect()
    }

    /// La ligne qui dit ce qui est pose.
    pub fn posees_en_clair(&self) -> String {
        if self.posees.is_empty() {
            "aucune politique d'attenuation posee".to_owned()
        } else {
            format!(
                "politiques d'attenuation posees: {}",
                self.posees.join(", ")
            )
        }
    }
}

/// Journalise un bilan: un avertissement par refus, une ligne pour le reste.
pub fn journaliser(bilan: &Bilan) {
    for ligne in bilan.refus_en_clair() {
        tracing::warn!("{ligne}");
    }
    tracing::info!("{}", bilan.posees_en_clair());
}

/// Pose [`POSEES`] dans le processus courant, dans l'ordre, et rend ce que le
/// systeme a accepte. Ne s'arrete pas au premier refus et ne panique pas.
#[cfg(windows)]
pub fn poser() -> Bilan {
    let mut bilan = Bilan::default();
    for p in POSEES {
        match poser_une(p) {
            Ok(()) => bilan.posees.push(p.nom),
            Err(code) => bilan.refusees.push(Refus {
                nom: p.nom,
                champs: p.champs,
                code,
            }),
        }
    }
    bilan
}

#[cfg(windows)]
fn poser_une(p: &Politique) -> Result<(), u32> {
    use windows_sys::Win32::Foundation::GetLastError;
    use windows_sys::Win32::System::Threading::SetProcessMitigationPolicy;

    let drapeaux: u32 = p.drapeaux;
    // SAFETY: `drapeaux` vit jusqu'a la fin de l'appel et la taille annoncee
    // est la sienne, celle de la structure (un DWORD, voir `Politique`).
    let ok = unsafe {
        SetProcessMitigationPolicy(
            p.valeur,
            (&raw const drapeaux).cast(),
            std::mem::size_of::<u32>(),
        )
    };
    if ok == 0 {
        // SAFETY: lecture de l'etat du fil courant.
        return Err(unsafe { GetLastError() });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// La liste posee, exactement: nom, valeur de l'enumeration, bits et
    /// ordre. Une politique omise, ajoutee ou mal parametree la fait rougir.
    #[test]
    fn la_liste_posee_est_exactement_celle_ci() {
        let lue: Vec<(&str, i32, u32)> = POSEES
            .iter()
            .map(|p| (p.nom, p.valeur, p.drapeaux))
            .collect();
        assert_eq!(
            lue,
            vec![
                ("ProcessImageLoadPolicy", 10, 0b111),
                ("ProcessExtensionPointDisablePolicy", 6, 0b1),
                ("ProcessStrictHandleCheckPolicy", 3, 0b11),
                ("ProcessControlFlowGuardPolicy", 7, 0b100),
                ("ProcessDynamicCodePolicy", 2, 0b1),
            ]
        );
    }

    /// Une politique ecartee ne se retrouve pas dans la liste posee, et dit
    /// pourquoi elle est ecartee.
    #[test]
    fn aucune_ecartee_n_est_posee() {
        assert_eq!(
            ECARTEES.iter().map(|e| e.nom).collect::<Vec<_>>(),
            vec![
                "ProcessSignaturePolicy",
                "ProcessSystemCallDisablePolicy",
                "ProcessChildProcessPolicy",
            ]
        );
        for e in ECARTEES {
            assert!(
                POSEES.iter().all(|p| p.nom != e.nom),
                "{} est a la fois posee et ecartee",
                e.nom
            );
            assert!(!e.raison.trim().is_empty(), "{} ecartee sans raison", e.nom);
        }
    }

    /// Un refus se journalise en nommant la politique, ses champs et le code
    /// systeme; ce qui est pose se dit sur une ligne.
    #[test]
    fn un_refus_est_journalise_et_nomme() {
        let bilan = Bilan {
            posees: vec!["ProcessImageLoadPolicy", "ProcessDynamicCodePolicy"],
            refusees: vec![Refus {
                nom: "ProcessControlFlowGuardPolicy",
                champs: "StrictMode",
                code: 87,
            }],
        };
        let refus = bilan.refus_en_clair();
        assert_eq!(refus.len(), 1, "{refus:?}");
        assert!(
            refus[0].contains("ProcessControlFlowGuardPolicy")
                && refus[0].contains("StrictMode")
                && refus[0].contains("code systeme 87")
                && refus[0].contains("continue"),
            "{}",
            refus[0]
        );
        assert_eq!(
            bilan.posees_en_clair(),
            "politiques d'attenuation posees: ProcessImageLoadPolicy, ProcessDynamicCodePolicy"
        );
        assert!(Bilan::default().refus_en_clair().is_empty());
        assert_eq!(
            Bilan::default().posees_en_clair(),
            "aucune politique d'attenuation posee"
        );
    }

    /// Un source sans ses commentaires, de ligne et de bloc (imbriques
    /// compris), fins de ligne gardees. Les litteraux ne sont pas interpretes.
    fn sans_commentaires(source: &str) -> String {
        let mut sortie = String::with_capacity(source.len());
        let mut caracteres = source.chars().peekable();
        let mut blocs = 0usize;
        let mut dans_ligne = false;
        while let Some(c) = caracteres.next() {
            if c == '\n' {
                dans_ligne = false;
                sortie.push(c);
                continue;
            }
            if dans_ligne {
                continue;
            }
            if c == '/' && caracteres.peek() == Some(&'*') {
                caracteres.next();
                blocs += 1;
            } else if blocs > 0 {
                if c == '*' && caracteres.peek() == Some(&'/') {
                    caracteres.next();
                    blocs -= 1;
                }
            } else if c == '/' && caracteres.peek() == Some(&'/') {
                dans_ligne = true;
            } else {
                sortie.push(c);
            }
        }
        sortie
    }

    /// Les definitions de `main` d'un source sans commentaires: le mot `fn`,
    /// le mot `main` et `(`, separes seulement par des blancs, fins de ligne
    /// comprises. Ce qui precede ne compte pas: `pub`, `async`, un attribut,
    /// `#[cfg(any())]` compris.
    fn definitions_de_main(code: &str) -> usize {
        let mut jetons: Vec<String> = Vec::new();
        let mut mot = String::new();
        for c in code.chars() {
            if c.is_alphanumeric() || c == '_' {
                mot.push(c);
                continue;
            }
            if !mot.is_empty() {
                jetons.push(std::mem::take(&mut mot));
            }
            if !c.is_whitespace() {
                jetons.push(c.to_string());
            }
        }
        if !mot.is_empty() {
            jetons.push(mot);
        }
        jetons
            .windows(3)
            .filter(|t| t[0] == "fn" && t[1] == "main" && t[2] == "(")
            .count()
    }

    /// Les lignes non vides de `main`, depuis sa signature, dans un source
    /// sans commentaires.
    fn code_de_main(code: &str) -> Vec<String> {
        let mut lignes = code.lines().map(str::trim);
        let signature = "fn main() -> anyhow::Result<()> {";
        assert!(
            lignes.any(|l| l == signature),
            "signature de main introuvable dans main.rs: {signature}"
        );
        lignes
            .filter(|l| !l.is_empty())
            .map(str::to_owned)
            .collect()
    }

    /// La pose est la PREMIERE instruction de `main`, et le bilan est
    /// journalise juste apres l'ouverture du journal.
    ///
    /// Une politique ne vaut que pour ce qui arrive apres sa pose: posee plus
    /// loin, elle laisserait passer ce qui la precede. La recette Windows du
    /// daemon lance le verifie de l'exterieur pour une sous-commande qui rend
    /// la main avant le journal; celle-ci tient la place exacte, et tourne
    /// aussi sous Linux.
    ///
    /// Elle juge le seul `main` qui compile: `main.rs` ne doit en definir
    /// qu'un, sans quoi un `main` ecarte par `#[cfg(...)]` pourrait porter la
    /// pose a la place du vrai. Le compte se fait sans les commentaires, et le
    /// compteur est d'abord eprouve sur des formes ecrites ici.
    #[test]
    fn la_pose_est_la_premiere_instruction_de_main() {
        for (forme, attendu) in [
            ("fn main() {}", 1),
            ("fn main () {}", 1),
            ("pub fn main() {}", 1),
            ("async fn main() {}", 1),
            ("#[cfg(any())]\nfn\nmain\n() {}", 1),
            ("fn /* x */ main() {}", 1),
            (
                "// fn main() {}\n/* fn main() {} /* x */ fn main() {} */",
                0,
            ),
            ("fn main_bis() {}\nfn principal() {}\nla main (1);", 0),
        ] {
            assert_eq!(
                definitions_de_main(&sans_commentaires(forme)),
                attendu,
                "compteur de definitions de main: {forme:?}"
            );
        }
        let chemin = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("main.rs");
        let source = std::fs::read_to_string(&chemin)
            .unwrap_or_else(|e| panic!("lecture de {}: {e}", chemin.display()));
        let source = sans_commentaires(&source);
        let definitions = definitions_de_main(&source);
        assert_eq!(
            definitions, 1,
            "main.rs definit `fn main` {definitions} fois: un seul compile, et la place de la \
             pose ne se juge que s'il est le seul"
        );
        let code = code_de_main(&source);
        assert_eq!(
            code.get(..2),
            Some(
                &[
                    "#[cfg(windows)]".to_owned(),
                    "let attenuations = bifrost_daemon::attenuation::poser();".to_owned(),
                ][..]
            ),
            "la pose des politiques d'attenuation n'est pas la premiere instruction de main: {:?}",
            code.get(..4)
        );
        let journal = [
            "#[cfg(windows)]",
            "init_tracing(args.service);",
            "#[cfg(not(windows))]",
            "init_tracing(false);",
            "#[cfg(windows)]",
            "bifrost_daemon::attenuation::journaliser(&attenuations);",
        ];
        let debuts: Vec<usize> = (0..code.len())
            .filter(|&i| {
                code[i..]
                    .iter()
                    .map(String::as_str)
                    .take(journal.len())
                    .eq(journal)
            })
            .collect();
        assert_eq!(
            debuts.len(),
            1,
            "le bilan doit etre journalise une fois, juste apres l'ouverture du journal"
        );
        let appels = code
            .iter()
            .filter(|l| l.contains("attenuation::journaliser") || l.contains("attenuation::poser"))
            .count();
        assert_eq!(appels, 2, "une pose et un journal, pas davantage");
    }
}
