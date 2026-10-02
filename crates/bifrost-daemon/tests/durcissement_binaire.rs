//! Le durcissement de compilation que le document 07 (section 2.4) demande est
//! dans les binaires, et cette recette rougit s'il disparait.
//!
//! # Ce qu'elle lit
//!
//! Les en-tetes de SON PROPRE executable (`std::env::current_exe`), sans outil
//! externe: PE sous Windows, ELF sous Linux. Ce binaire de recette est
//! construit par le meme cargo, depuis le meme depot, avec les memes drapeaux
//! de cible que `cargo build --release` (`.cargo/config.toml`).
//!
//! - Windows (MSVC): DYNAMIC_BASE, HIGH_ENTROPY_VA et NX_COMPAT dans
//!   DllCharacteristics (ASLR 64 bits et DEP, poses par l'editeur de liens
//!   sans qu'on le demande); GUARD_CF, et dans la Load Config la table des
//!   cibles CFG presente et non vide (Control Flow Guard, pose par
//!   `.cargo/config.toml`); enfin un appel par pointeur de fonction ecrit dans
//!   CE fichier passe par le pointeur de controle que la Load Config designe.
//!   Ce dernier point separe `control-flow-guard=checks` de `nochecks`, qui
//!   pose la table et GUARD_CF sans emettre un seul controle. Le code de
//!   toute l'image, lui, doit lire ces cases au moins
//!   `CONTROLES_CFG_MINIMUM` fois. Sous x86_64, enfin, l'image est marquee
//!   compatible CET (pile fantome): bit IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT
//!   dans l'entree de type 20 du repertoire de debogage, pose par
//!   `/CETCOMPAT`.
//! - Linux: executable PIE (ET_DYN avec interpreteur), RELRO complet
//!   (PT_GNU_RELRO et liaison immediate), pile non executable (PT_GNU_STACK
//!   sans PF_X). Ce sont des defauts de rustc: rien ne les pose dans le depot,
//!   la recette rougit si un drapeau les retire.
//! - Partout: `.cargo/config.toml` demande CFG pour la cible MSVC, et
//!   `/CETCOMPAT` pour la cible MSVC x86_64. C'est la seule partie que la CI
//!   automatique, qui tourne sous Linux, execute pour Windows.
//!
//! # Les binaires livres
//!
//! `les_binaires_livres_portent_le_durcissement` applique les memes lectures
//! aux binaires que les scripts d'installation copient (`LIVRES`, liste
//! confrontee a ces scripts par une recette), dans le repertoire que nomme
//! `BIFROST_REPERTOIRE_LIVRE` (relatif a la racine du depot, ou absolu). Elle
//! est ignoree dans la suite: une etape de la CI construit ces binaires en
//! `--release`, puis la lance par `--ignored`. Sans la variable, ou sans un
//! des binaires, elle rougit au lieu de lire autre chose. Elle refuse aussi
//! un repertoire qui n'est pas celui d'une construction `--release` (son
//! dernier composant doit etre `release`), et un fichier identique a son
//! propre executable: un binaire de recette ne passe pas pour un livre. Dans
//! la suite, la meme lecture (`controler`) s'applique a l'executable de la
//! recette et doit y nommer chaque propriete de `PROPRIETES`.
//!
//! # Pourquoi GuardFlags ne suffit pas
//!
//! Mesure du 01/10/2026 sur dev-windows, binaires `--release` construits SANS
//! CFG: GuardFlags vaut 0x100, << CF instrumented >>, alors que
//! DllCharacteristics ne porte pas GUARD_CF et que la table des cibles est
//! vide. La Load Config vient de la bibliotheque C de Microsoft, deja compilee
//! avec /guard:cf. Une garde qui ne lirait que ce drapeau serait verte sans
//! CFG; celle-ci ne le lit pas.
//!
//! # Ce qu'elle ne prouve pas
//!
//! - Le profil, dans la suite: les recettes qui y tournent lisent un binaire
//!   de recette (profil de test, sans LTO). Les binaires `--release` ne sont
//!   lus que par la recette ignoree, donc par l'etape de la CI qui la lance.
//! - La bibliotheque standard: livree precompilee sans CFG, ses appels
//!   indirects ne sont controles ni ici ni dans les binaires livres.
//! - L'execution: elle ne fait pas tomber un appel vers une cible invalide,
//!   ni un retour detourne; elle constate que le controle est emis et que
//!   l'image se declare. Le marquage CET n'a d'effet que sur un processeur qui
//!   porte la pile fantome, sous un Windows qui l'applique.
//! - Une construction faite ailleurs que dans la CI: lancee hors du depot, ou
//!   avec RUSTFLAGS defini, elle ne lit pas `.cargo/config.toml`, et rien ici
//!   ne la lit.

use std::path::PathBuf;

fn racine() -> PathBuf {
    // `CARGO_MANIFEST_DIR` pointe sur crates/bifrost-daemon, la racine de
    // l'espace de travail est deux crans au-dessus.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("la racine de l'espace de travail doit exister")
        .to_path_buf()
}

/// La cle de la table de `.cargo/config.toml` qui porte CFG, mot pour mot.
const CLE_CIBLE_MSVC: &str = r#"cfg(all(target_os = "windows", target_env = "msvc"))"#;

/// Le seul drapeau que cette table doit porter.
const DRAPEAUX_ATTENDUS: [&str; 2] = ["-C", "control-flow-guard=checks"];

/// La cle de la table qui porte CET, limitee a x86_64: la documentation de
/// `/CETCOMPAT` ne le donne que pour x64.
const CLE_CIBLE_MSVC_X64: &str =
    r#"cfg(all(target_os = "windows", target_env = "msvc", target_arch = "x86_64"))"#;

/// Le seul drapeau que la table x86_64 doit porter.
const DRAPEAUX_ATTENDUS_X64: [&str; 2] = ["-C", "link-arg=/CETCOMPAT"];

/// Les executables que les scripts d'installation copient, sans extension.
/// `la_liste_des_binaires_livres_est_celle_des_installeurs` la confronte a
/// `packaging/install-linux.sh` et `packaging/install-windows.ps1`.
const LIVRES: [&str; 2] = ["bifrost-daemon", "bifrost-cli"];

/// Le repertoire des binaires livres, pour la recette ignoree.
const VARIABLE_LIVRES: &str = "BIFROST_REPERTOIRE_LIVRE";

/// L'executable de la recette, tel que le systeme l'a charge.
#[cfg(any(target_os = "linux", all(windows, target_env = "msvc")))]
fn executable() -> (PathBuf, Vec<u8>) {
    let chemin = std::env::current_exe().expect("current_exe doit nommer la recette");
    let octets =
        std::fs::read(&chemin).unwrap_or_else(|e| panic!("{} illisible: {e}", chemin.display()));
    (chemin, octets)
}

#[cfg(any(target_os = "linux", all(windows, target_env = "msvc")))]
fn octets<const N: usize>(fichier: &[u8], position: usize) -> Result<[u8; N], String> {
    position
        .checked_add(N)
        .and_then(|fin| fichier.get(position..fin))
        .map(|tranche| {
            let mut lus = [0u8; N];
            lus.copy_from_slice(tranche);
            lus
        })
        .ok_or_else(|| {
            format!(
                "lecture de {N} octets a {position:#x} hors du fichier ({} octets)",
                fichier.len()
            )
        })
}

#[cfg(any(target_os = "linux", all(windows, target_env = "msvc")))]
fn u16_le(fichier: &[u8], position: usize) -> Result<u16, String> {
    octets::<2>(fichier, position).map(u16::from_le_bytes)
}

#[cfg(any(target_os = "linux", all(windows, target_env = "msvc")))]
fn u32_le(fichier: &[u8], position: usize) -> Result<u32, String> {
    octets::<4>(fichier, position).map(u32::from_le_bytes)
}

#[cfg(any(target_os = "linux", all(windows, target_env = "msvc")))]
fn u64_le(fichier: &[u8], position: usize) -> Result<u64, String> {
    octets::<8>(fichier, position).map(u64::from_le_bytes)
}

/// Les `rustflags` de la table `target.'<cle>'` de `.cargo/config.toml`.
fn drapeaux_de_la_table(cle: &str) -> (PathBuf, Vec<String>) {
    let chemin = racine().join(".cargo").join("config.toml");
    let texte = std::fs::read_to_string(&chemin)
        .unwrap_or_else(|e| panic!("{} illisible: {e}", chemin.display()));
    let config: toml::Table = toml::from_str(&texte)
        .unwrap_or_else(|e| panic!("{} n'est pas du TOML: {e}", chemin.display()));

    let drapeaux = config
        .get("target")
        .and_then(|t| t.get(cle))
        .and_then(|t| t.get("rustflags"))
        .and_then(|r| r.as_array())
        .map(|r| {
            r.iter()
                .filter_map(|d| d.as_str())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    (chemin, drapeaux)
}

#[test]
fn la_configuration_cargo_demande_cfg_pour_la_cible_msvc() {
    let (chemin, drapeaux) = drapeaux_de_la_table(CLE_CIBLE_MSVC);
    assert_eq!(
        drapeaux,
        DRAPEAUX_ATTENDUS,
        "{}: la table `target.'{CLE_CIBLE_MSVC}'` doit porter exactement \
         rustflags = {DRAPEAUX_ATTENDUS:?}. Sans elle, les binaires Windows \
         sortent sans Control Flow Guard et rien d'autre ne le dit: la CI \
         automatique ne construit pas pour Windows. Si la forme change \
         volontairement, changer aussi cette recette et le document 07.",
        chemin.display()
    );
}

#[test]
fn la_configuration_cargo_demande_cet_pour_la_cible_msvc_x64() {
    let (chemin, drapeaux) = drapeaux_de_la_table(CLE_CIBLE_MSVC_X64);
    assert_eq!(
        drapeaux,
        DRAPEAUX_ATTENDUS_X64,
        "{}: la table `target.'{CLE_CIBLE_MSVC_X64}'` doit porter exactement \
         rustflags = {DRAPEAUX_ATTENDUS_X64:?}. Sans elle, les binaires Windows \
         x64 sortent sans le marquage CET (pile fantome) et rien d'autre ne le \
         dit hors du job Windows de la CI, lance sur demande. Si la forme change \
         volontairement, changer aussi cette recette et le document 07.",
        chemin.display()
    );
}

/// Les noms que `texte` donne a `motif` suivi d'un nom de fichier: ce qui
/// suit le motif, jusqu'au premier caractere qui ne peut pas faire partie
/// d'un nom de binaire.
fn noms_apres(texte: &str, motif: &str) -> Vec<String> {
    texte
        .match_indices(motif)
        .map(|(i, _)| {
            texte[i + motif.len()..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_' || *c == '.')
                .collect::<String>()
        })
        .collect()
}

#[test]
fn la_liste_des_binaires_livres_est_celle_des_installeurs() {
    let mut attendus: Vec<String> = LIVRES.iter().map(|n| n.to_string()).collect();
    attendus.sort();

    // Linux: chaque `install ... "$BIN/<nom>"` copie un binaire, et la boucle
    // `for f in ...; do` verifie leur presence avant toute ecriture.
    let chemin = racine().join("packaging").join("install-linux.sh");
    let texte = std::fs::read_to_string(&chemin)
        .unwrap_or_else(|e| panic!("{} illisible: {e}", chemin.display()));
    let mut copies: Vec<String> = texte
        .lines()
        .filter(|l| l.trim_start().starts_with("install "))
        .flat_map(|l| noms_apres(l, "\"$BIN/"))
        .collect();
    copies.sort();
    assert_eq!(
        copies,
        attendus,
        "{}: les binaires copies depuis $BIN ne sont pas `LIVRES`. La recette \
         ignoree lirait un binaire non livre, ou laisserait un livre sans \
         lecture: mettre `LIVRES` a jour avec l'installeur.",
        chemin.display()
    );
    let verifies: Vec<Vec<String>> = texte
        .lines()
        .filter_map(|l| l.trim_start().strip_prefix("for f in "))
        .filter_map(|l| l.split_once(';'))
        .map(|(noms, _)| {
            let mut n: Vec<String> = noms.split_whitespace().map(str::to_string).collect();
            n.sort();
            n
        })
        .collect();
    assert_eq!(
        verifies,
        vec![attendus.clone()],
        "{}: la boucle qui verifie les binaires avant l'installation ne porte \
         pas `LIVRES`",
        chemin.display()
    );

    // Windows: chaque `foreach ($f in '<nom>.exe', ...)` porte la liste, a la
    // verification puis a la copie.
    let chemin = racine().join("packaging").join("install-windows.ps1");
    let texte = std::fs::read_to_string(&chemin)
        .unwrap_or_else(|e| panic!("{} illisible: {e}", chemin.display()));
    let boucles: Vec<Vec<String>> = texte
        .lines()
        .filter_map(|l| l.trim_start().strip_prefix("foreach ($f in "))
        .map(|l| {
            let mut n: Vec<String> = l
                .split('\'')
                .skip(1)
                .step_by(2)
                .map(|s| s.strip_suffix(".exe").unwrap_or(s).to_string())
                .collect();
            n.sort();
            n
        })
        .collect();
    assert!(
        !boucles.is_empty() && boucles.iter().all(|n| *n == attendus),
        "{}: les boucles `foreach ($f in ...)` portent {boucles:?}, pas `LIVRES` \
         ({attendus:?})",
        chemin.display()
    );
}

/// Le repertoire des binaires livres: `BIFROST_REPERTOIRE_LIVRE`, relatif a la
/// racine du depot s'il n'est pas absolu (cargo lance les recettes depuis le
/// repertoire du paquet, pas depuis la racine).
#[cfg(any(target_os = "linux", all(windows, target_env = "msvc")))]
fn repertoire_livre() -> PathBuf {
    let valeur = std::env::var_os(VARIABLE_LIVRES).unwrap_or_else(|| {
        panic!(
            "{VARIABLE_LIVRES} n'est pas defini: cette recette lit les binaires \
             livres construits en --release, elle ne se rabat sur rien d'autre. \
             Exemple: cargo build --release --locked, puis \
             {VARIABLE_LIVRES}=target/release cargo test --locked --workspace \
             --test durcissement_binaire -- --ignored"
        )
    });
    assert!(!valeur.is_empty(), "{VARIABLE_LIVRES} est defini mais vide");
    let chemin = PathBuf::from(valeur);
    let chemin = if chemin.is_absolute() {
        chemin
    } else {
        racine().join(chemin)
    };
    // `target/release` ou `target/<triple>/release`: pas `target/debug`, dont
    // les binaires portent les memes drapeaux de cible sans etre ceux que les
    // installeurs copient.
    assert!(
        chemin.file_name().is_some_and(|n| n == "release"),
        "{VARIABLE_LIVRES}={}: ce n'est pas le repertoire d'une construction \
         --release (`target/release` ou `target/<triple>/release`)",
        chemin.display()
    );
    chemin
}

/// Les proprietes de durcissement d'un binaire livre, chacune avec son
/// verdict: le constat si elle est la, le defaut sinon.
#[cfg(any(target_os = "linux", all(windows, target_env = "msvc")))]
type Verdicts = Vec<(&'static str, Result<String, String>)>;

#[cfg(any(target_os = "linux", all(windows, target_env = "msvc")))]
#[test]
#[ignore = "lit les binaires livres construits en --release: lancee par l'etape \
            de la CI qui les construit, avec BIFROST_REPERTOIRE_LIVRE et --ignored"]
fn les_binaires_livres_portent_le_durcissement() {
    use sha2::{Digest, Sha256};

    let repertoire = repertoire_livre();
    let (_, propre) = executable();
    let mut defauts = Vec::new();
    for nom in LIVRES {
        let chemin = repertoire.join(format!("{nom}{}", std::env::consts::EXE_SUFFIX));
        let fichier = match std::fs::read(&chemin) {
            Ok(f) => f,
            Err(e) => {
                defauts.push(format!("{}: illisible: {e}", chemin.display()));
                continue;
            }
        };
        // Le contenu, pas le chemin: une copie de la recette, ou une lecture
        // detournee vers elle, a un autre chemin que `current_exe`.
        if fichier == propre {
            defauts.push(format!(
                "{}: identique a l'executable de la recette, pas un binaire livre",
                chemin.display()
            ));
            continue;
        }
        let empreinte: String = Sha256::digest(&fichier)
            .iter()
            .map(|o| format!("{o:02x}"))
            .collect();
        println!(
            "lu: {} ({} octets, sha256 {empreinte})",
            chemin.display(),
            fichier.len()
        );
        for (propriete, verdict) in controler(&fichier) {
            match verdict {
                Ok(constat) => println!("  ok      {propriete}: {constat}"),
                Err(defaut) => {
                    println!("  DEFAUT  {propriete}: {defaut}");
                    defauts.push(format!("{}: {propriete}: {defaut}", chemin.display()));
                }
            }
        }
    }
    assert!(
        defauts.is_empty(),
        "binaires livres sous {} sans le durcissement attendu:\n{}",
        repertoire.display(),
        defauts.join("\n")
    );
}

/// `controler`, ce que la recette ignoree applique aux binaires livres, lit
/// chaque propriete attendue sur l'executable de cette recette, et la suite
/// le constate a chaque passage. Une propriete retiree de `controler` y
/// rougit, au lieu de laisser passer un binaire livre sans la lire.
#[cfg(any(target_os = "linux", all(windows, target_env = "msvc")))]
#[test]
fn le_controle_des_binaires_livres_lit_chaque_propriete() {
    let (chemin, fichier) = executable();
    let verdicts = controler(&fichier);
    let lues: Vec<&str> = verdicts.iter().map(|(propriete, _)| *propriete).collect();
    assert_eq!(
        lues, PROPRIETES,
        "les proprietes que `controler` lit ne sont pas `PROPRIETES`"
    );
    let defauts: Vec<String> = verdicts
        .into_iter()
        .filter_map(|(propriete, verdict)| verdict.err().map(|e| format!("{propriete}: {e}")))
        .collect();
    assert!(
        defauts.is_empty(),
        "{}:\n{}",
        chemin.display(),
        defauts.join("\n")
    );
}

#[cfg(all(windows, target_env = "msvc"))]
mod pe {
    use super::{u16_le, u32_le, u64_le};

    pub const HIGH_ENTROPY_VA: u16 = 0x0020;
    pub const DYNAMIC_BASE: u16 = 0x0040;
    pub const NX_COMPAT: u16 = 0x0100;
    pub const GUARD_CF: u16 = 0x4000;
    /// IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT, dans GuardFlags.
    pub const TABLE_DES_CIBLES_PRESENTE: u32 = 0x0000_0400;
    /// IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT, dans les caracteristiques
    /// etendues (specification PE de Microsoft, << Extended DLL
    /// Characteristics >>).
    pub const CET_COMPAT: u32 = 0x0001;

    const REPERTOIRE_EXCEPTIONS: usize = 3;
    const REPERTOIRE_DEBOGAGE: usize = 6;
    const REPERTOIRE_LOAD_CONFIG: usize = 10;
    /// IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS: l'entree du repertoire de
    /// debogage qui porte les caracteristiques etendues.
    const TYPE_CARACTERISTIQUES_ETENDUES: u32 = 20;
    /// IMAGE_SCN_MEM_EXECUTE, dans les caracteristiques d'une section.
    const SECTION_EXECUTABLE: u32 = 0x2000_0000;

    struct Section {
        adresse: u32,
        taille_virtuelle: u32,
        taille_brute: u32,
        position: u32,
        caracteristiques: u32,
    }

    /// Ce que la recette lit d'une image PE32+.
    pub struct Image {
        pub base: u64,
        pub caracteristiques: u16,
        sections: Vec<Section>,
        repertoires: Vec<(u32, u32)>,
    }

    /// Les champs CFG de IMAGE_LOAD_CONFIG_DIRECTORY64, en adresses virtuelles.
    pub struct Garde {
        pub pointeur_controle: u64,
        pub pointeur_dispatch: u64,
        pub table: u64,
        pub cibles: u64,
        pub drapeaux: u32,
    }

    impl Image {
        pub fn lire(fichier: &[u8]) -> Result<Image, String> {
            if fichier.get(0..2) != Some(b"MZ".as_slice()) {
                return Err("pas d'en-tete MZ".into());
            }
            let pe = u32_le(fichier, 0x3c)? as usize;
            if fichier.get(pe..pe + 4) != Some([b'P', b'E', 0, 0].as_slice()) {
                return Err(format!("pas de signature PE a {pe:#x}"));
            }
            let coff = pe + 4;
            let nombre_sections = usize::from(u16_le(fichier, coff + 2)?);
            let taille_optionnel = usize::from(u16_le(fichier, coff + 16)?);
            let optionnel = coff + 20;
            let magie = u16_le(fichier, optionnel)?;
            if magie != 0x20b {
                return Err(format!(
                    "en-tete optionnel {magie:#x}: seul PE32+ (0x20b) est lu ici"
                ));
            }
            let base = u64_le(fichier, optionnel + 24)?;
            let caracteristiques = u16_le(fichier, optionnel + 70)?;
            let nombre_repertoires = u32_le(fichier, optionnel + 108)? as usize;
            let mut repertoires = Vec::new();
            for i in 0..nombre_repertoires.min(16) {
                let p = optionnel + 112 + 8 * i;
                repertoires.push((u32_le(fichier, p)?, u32_le(fichier, p + 4)?));
            }
            let premiere = optionnel + taille_optionnel;
            let mut sections = Vec::new();
            for i in 0..nombre_sections {
                let s = premiere + 40 * i;
                sections.push(Section {
                    taille_virtuelle: u32_le(fichier, s + 8)?,
                    adresse: u32_le(fichier, s + 12)?,
                    taille_brute: u32_le(fichier, s + 16)?,
                    position: u32_le(fichier, s + 20)?,
                    caracteristiques: u32_le(fichier, s + 36)?,
                });
            }
            Ok(Image {
                base,
                caracteristiques,
                sections,
                repertoires,
            })
        }

        /// La position dans le fichier d'une adresse relative a l'image.
        pub fn position(&self, rva: u32) -> Result<usize, String> {
            for s in &self.sections {
                let decalage = rva.wrapping_sub(s.adresse);
                if rva >= s.adresse && decalage < s.taille_virtuelle.max(s.taille_brute) {
                    if decalage >= s.taille_brute {
                        return Err(format!("{rva:#x} hors des octets de sa section"));
                    }
                    return Ok(s.position as usize + decalage as usize);
                }
            }
            Err(format!("{rva:#x} dans aucune section"))
        }

        fn repertoire(&self, indice: usize) -> Result<(u32, u32), String> {
            match self.repertoires.get(indice) {
                Some(&(rva, taille)) if rva != 0 && taille != 0 => Ok((rva, taille)),
                _ => Err(format!("repertoire {indice} absent ou vide")),
            }
        }

        pub fn garde(&self, fichier: &[u8]) -> Result<Garde, String> {
            let (rva, _) = self.repertoire(REPERTOIRE_LOAD_CONFIG)?;
            let p = self.position(rva)?;
            // GuardFlags, le dernier champ lu, finit a l'octet 148.
            let taille = u32_le(fichier, p)?;
            if taille < 148 {
                return Err(format!(
                    "Load Config de {taille} octets, trop courte pour porter GuardFlags"
                ));
            }
            Ok(Garde {
                pointeur_controle: u64_le(fichier, p + 112)?,
                pointeur_dispatch: u64_le(fichier, p + 120)?,
                table: u64_le(fichier, p + 128)?,
                cibles: u64_le(fichier, p + 136)?,
                drapeaux: u32_le(fichier, p + 144)?,
            })
        }

        /// Debut et fin de la fonction qui commence a `rva`, lus dans sa
        /// RUNTIME_FUNCTION (.pdata). Toute fonction x64 qui en appelle une
        /// autre en a une.
        pub fn etendue(&self, fichier: &[u8], rva: u32) -> Result<(u32, u32), String> {
            let (table, taille) = self.repertoire(REPERTOIRE_EXCEPTIONS)?;
            let p = self.position(table)?;
            for i in 0..(taille as usize / 12) {
                if u32_le(fichier, p + 12 * i)? == rva {
                    return Ok((rva, u32_le(fichier, p + 12 * i + 4)?));
                }
            }
            Err(format!("aucune RUNTIME_FUNCTION ne commence a {rva:#x}"))
        }

        /// L'adresse relative d'une adresse virtuelle de la Load Config.
        pub fn relative(&self, va: u64) -> Option<u32> {
            va.checked_sub(self.base)
                .and_then(|r| u32::try_from(r).ok())
        }

        /// Les caracteristiques etendues: le mot de 32 bits de l'entree de
        /// type 20 du repertoire de debogage, ou `None` si l'image n'en porte
        /// pas. Une entree fait 28 octets; Type a l'octet 12, SizeOfData a 16,
        /// PointerToRawData (position dans le fichier) a 24.
        pub fn caracteristiques_etendues(&self, fichier: &[u8]) -> Result<Option<u32>, String> {
            let Ok((rva, taille)) = self.repertoire(REPERTOIRE_DEBOGAGE) else {
                return Ok(None);
            };
            let p = self.position(rva)?;
            for i in 0..(taille as usize / 28) {
                let entree = p + 28 * i;
                if u32_le(fichier, entree + 12)? != TYPE_CARACTERISTIQUES_ETENDUES {
                    continue;
                }
                let longueur = u32_le(fichier, entree + 16)?;
                if longueur < 4 {
                    return Err(format!(
                        "entree de type {TYPE_CARACTERISTIQUES_ETENDUES} de {longueur} octets"
                    ));
                }
                let donnees = u32_le(fichier, entree + 24)? as usize;
                return u32_le(fichier, donnees).map(Some);
            }
            Ok(None)
        }

        /// Le nombre de lectures, dans tout le code executable de l'image, des
        /// cases `cases` (adresses relatives) par un adressage relatif a RIP,
        /// au sens de `references`.
        pub fn lectures_dans_le_code(&self, fichier: &[u8], cases: &[u32]) -> usize {
            let mut total = 0;
            for s in &self.sections {
                if s.caracteristiques & SECTION_EXECUTABLE == 0 {
                    continue;
                }
                let longueur = s.taille_brute.min(s.taille_virtuelle) as usize;
                let debut = s.position as usize;
                let Some(code) = debut
                    .checked_add(longueur)
                    .and_then(|fin| fichier.get(debut..fin))
                else {
                    continue;
                };
                for &case in cases {
                    total += references(code, s.adresse, case);
                }
            }
            total
        }
    }

    /// Les instructions de `code` (qui commence a l'adresse relative `debut`)
    /// qui lisent la case `case` par un adressage relatif a RIP: appel ou saut
    /// indirect (`FF 15`, `FF 25`), ou chargement dans un registre 64 bits
    /// (`48 8B` / `4C 8B`, ModRM mod 00 rm 101). Le second est la forme que
    /// rustc emet pour le temoin en profil de test, mesure le 01/10/2026 sur
    /// dev-windows: `mov rdx,[__guard_dispatch_icall_fptr]` puis `call rdx`.
    pub fn references(code: &[u8], debut: u32, case: u32) -> usize {
        let vise = |i: usize, longueur: usize, d: &[u8]| {
            i64::from(debut)
                + i as i64
                + longueur as i64
                + i64::from(i32::from_le_bytes([d[0], d[1], d[2], d[3]]))
                == i64::from(case)
        };
        (0..code.len())
            .filter(|&i| {
                let appel = code.get(i..i + 6).is_some_and(|f| {
                    f[0] == 0xFF && (f[1] == 0x15 || f[1] == 0x25) && vise(i, 6, &f[2..6])
                });
                let chargement = code.get(i..i + 7).is_some_and(|f| {
                    (f[0] == 0x48 || f[0] == 0x4C)
                        && f[1] == 0x8B
                        && f[2] & 0xC7 == 0x05
                        && vise(i, 7, &f[3..7])
                });
                appel || chargement
            })
            .count()
    }
}

#[cfg(all(windows, target_env = "msvc"))]
fn image() -> (PathBuf, Vec<u8>, pe::Image) {
    let (chemin, fichier) = executable();
    let image = pe::Image::lire(&fichier)
        .unwrap_or_else(|e| panic!("{}: en-tetes PE illisibles: {e}", chemin.display()));
    (chemin, fichier, image)
}

/// Le nombre minimal de lectures des cases de controle CFG dans le code d'une
/// image (`pe::Image::lectures_dans_le_code`). Mesure du 02/10/2026 sur
/// dev-windows: sans aucun controle emis par rustc (drapeau absent, ou
/// `control-flow-guard=nochecks`), le code de la bibliotheque C de Microsoft
/// en porte a lui seul quelques-unes; avec `checks`, l'executable de cette
/// recette en porte quelques centaines et les binaires livres des milliers
/// (nombres dans le document 07, section 2.4). Le seuil se place entre les
/// deux, loin de chacun.
#[cfg(all(windows, target_env = "msvc", target_arch = "x86_64"))]
const CONTROLES_CFG_MINIMUM: usize = 100;

#[cfg(all(windows, target_env = "msvc"))]
fn verifier_aslr_dep(image: &pe::Image) -> Result<String, String> {
    for (bit, nom) in [
        (pe::DYNAMIC_BASE, "DYNAMIC_BASE (ASLR)"),
        (pe::HIGH_ENTROPY_VA, "HIGH_ENTROPY_VA (ASLR 64 bits)"),
        (pe::NX_COMPAT, "NX_COMPAT (DEP)"),
    ] {
        if image.caracteristiques & bit == 0 {
            return Err(format!(
                "DllCharacteristics {:#06x} sans {nom}",
                image.caracteristiques
            ));
        }
    }
    Ok(format!(
        "DllCharacteristics {:#06x}",
        image.caracteristiques
    ))
}

#[cfg(all(windows, target_env = "msvc"))]
fn verifier_cfg(image: &pe::Image, fichier: &[u8]) -> Result<String, String> {
    if image.caracteristiques & pe::GUARD_CF == 0 {
        return Err(format!(
            "DllCharacteristics {:#06x} sans GUARD_CF. `.cargo/config.toml` \
             n'a pas ete lu pour construire ce binaire (RUSTFLAGS ou \
             CARGO_ENCODED_RUSTFLAGS defini, cargo lance hors du depot) ou ne \
             demande plus `-C control-flow-guard`.",
            image.caracteristiques
        ));
    }
    let garde = image
        .garde(fichier)
        .map_err(|e| format!("Load Config illisible: {e}"))?;
    if garde.drapeaux & pe::TABLE_DES_CIBLES_PRESENTE == 0 || garde.table == 0 || garde.cibles == 0
    {
        return Err(format!(
            "GUARD_CF sans table des cibles (GuardFlags {:#x}, table {:#x}, {} cible(s))",
            garde.drapeaux, garde.table, garde.cibles
        ));
    }
    Ok(format!(
        "GUARD_CF, GuardFlags {:#x}, {} cible(s)",
        garde.drapeaux, garde.cibles
    ))
}

/// Le code de toute l'image lit les cases de controle et de dispatch CFG au
/// moins `CONTROLES_CFG_MINIMUM` fois. Separe `checks` de `nochecks` sur un
/// binaire dont on ne connait aucune fonction, comme le temoin le fait pour
/// le code de ce fichier.
#[cfg(all(windows, target_env = "msvc", target_arch = "x86_64"))]
fn verifier_controles_cfg(image: &pe::Image, fichier: &[u8]) -> Result<String, String> {
    let garde = image
        .garde(fichier)
        .map_err(|e| format!("Load Config illisible: {e}"))?;
    let cases: Vec<u32> = [garde.pointeur_dispatch, garde.pointeur_controle]
        .into_iter()
        .filter(|&va| va != 0)
        .filter_map(|va| image.relative(va))
        .collect();
    let lectures = image.lectures_dans_le_code(fichier, &cases);
    if lectures < CONTROLES_CFG_MINIMUM {
        return Err(format!(
            "le code lit {lectures} fois les cases de controle CFG (dispatch \
             {:#x}, controle {:#x}), moins que {CONTROLES_CFG_MINIMUM}: le code \
             Rust n'est pas instrumente. Drapeau absent, ou \
             `control-flow-guard=nochecks`, qui pose la table sans aucun controle.",
            garde.pointeur_dispatch, garde.pointeur_controle
        ));
    }
    Ok(format!("{lectures} lectures des cases de controle CFG"))
}

#[cfg(all(windows, target_env = "msvc", target_arch = "x86_64"))]
fn verifier_cet(image: &pe::Image, fichier: &[u8]) -> Result<String, String> {
    match image.caracteristiques_etendues(fichier) {
        Ok(Some(etendues)) if etendues & pe::CET_COMPAT != 0 => Ok(format!(
            "caracteristiques etendues {etendues:#x}, CET_COMPAT"
        )),
        Ok(Some(etendues)) => Err(format!(
            "caracteristiques etendues {etendues:#x} sans CET_COMPAT ({:#x})",
            pe::CET_COMPAT
        )),
        Ok(None) => Err(
            "aucune entree de caracteristiques etendues dans le repertoire de \
             debogage: l'image n'est pas marquee compatible CET. `.cargo/config.toml` \
             n'a pas ete lu, ou ne demande plus `/CETCOMPAT`."
                .to_string(),
        ),
        Err(e) => Err(format!("repertoire de debogage illisible: {e}")),
    }
}

/// Les proprietes que `controler` doit lire, dans l'ordre.
#[cfg(all(windows, target_env = "msvc", target_arch = "x86_64"))]
const PROPRIETES: [&str; 4] = [
    "ASLR 64 bits et DEP",
    "Control Flow Guard",
    "controles CFG dans le code",
    "CET (pile fantome)",
];
#[cfg(all(windows, target_env = "msvc", not(target_arch = "x86_64")))]
const PROPRIETES: [&str; 2] = ["ASLR 64 bits et DEP", "Control Flow Guard"];

/// Chaque propriete lue sur un binaire livre, avec son verdict.
#[cfg(all(windows, target_env = "msvc"))]
fn controler(fichier: &[u8]) -> Verdicts {
    let image = match pe::Image::lire(fichier) {
        Ok(i) => i,
        Err(e) => return vec![("en-tetes PE", Err(e))],
    };
    #[allow(unused_mut)]
    let mut verdicts: Verdicts = vec![
        ("ASLR 64 bits et DEP", verifier_aslr_dep(&image)),
        ("Control Flow Guard", verifier_cfg(&image, fichier)),
    ];
    #[cfg(target_arch = "x86_64")]
    {
        verdicts.push((
            "controles CFG dans le code",
            verifier_controles_cfg(&image, fichier),
        ));
        verdicts.push(("CET (pile fantome)", verifier_cet(&image, fichier)));
    }
    verdicts
}

#[cfg(all(windows, target_env = "msvc"))]
#[test]
fn l_executable_de_la_recette_porte_aslr_64_bits_et_dep() {
    let (chemin, _, image) = image();
    if let Err(e) = verifier_aslr_dep(&image) {
        panic!("{}: {e}", chemin.display());
    }
}

#[cfg(all(windows, target_env = "msvc"))]
#[test]
fn l_executable_de_la_recette_porte_control_flow_guard() {
    let (chemin, fichier, image) = image();
    if let Err(e) = verifier_cfg(&image, &fichier) {
        panic!("{}: {e}", chemin.display());
    }
}

#[cfg(all(windows, target_env = "msvc", target_arch = "x86_64"))]
#[test]
fn le_code_de_l_executable_de_la_recette_lit_les_cases_de_controle_cfg() {
    let (chemin, fichier, image) = image();
    match verifier_controles_cfg(&image, &fichier) {
        Ok(constat) => println!("{}: {constat}", chemin.display()),
        Err(e) => panic!("{}: {e}", chemin.display()),
    }
}

#[cfg(all(windows, target_env = "msvc", target_arch = "x86_64"))]
#[test]
fn l_executable_de_la_recette_est_marque_compatible_cet() {
    let (chemin, fichier, image) = image();
    if let Err(e) = verifier_cet(&image, &fichier) {
        panic!("{}: {e}", chemin.display());
    }
}

/// Le temoin: un appel par pointeur de fonction, que l'optimiseur ne peut pas
/// rendre direct (`black_box` a l'appel, pas d'inlining).
#[cfg(all(windows, target_env = "msvc", target_arch = "x86_64"))]
#[inline(never)]
fn appel_par_pointeur(f: fn(u64) -> u64, x: u64) -> u64 {
    f(x)
}

#[cfg(all(windows, target_env = "msvc", target_arch = "x86_64"))]
fn double(x: u64) -> u64 {
    x.wrapping_mul(2)
}

#[cfg(all(windows, target_env = "msvc", target_arch = "x86_64"))]
#[test]
fn un_appel_par_pointeur_de_ce_fichier_passe_par_le_controle_cfg() {
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;

    let f: fn(u64) -> u64 = std::hint::black_box(double);
    assert_eq!(appel_par_pointeur(f, 21), 42);

    let (chemin, fichier, image) = image();
    let garde = image
        .garde(&fichier)
        .unwrap_or_else(|e| panic!("{}: Load Config illisible: {e}", chemin.display()));

    // SAFETY: GetModuleHandleW(NULL) ne lit aucun argument et rend l'adresse
    // de chargement de l'executable du processus courant, sans en transferer
    // la propriete; la valeur n'est employee que comme nombre.
    let base_chargee = unsafe { GetModuleHandleW(std::ptr::null()) } as usize;
    assert_ne!(base_chargee, 0, "GetModuleHandleW(NULL) n'a rien rendu");
    let temoin = appel_par_pointeur as fn(fn(u64) -> u64, u64) -> u64 as usize;
    let rva = temoin
        .checked_sub(base_chargee)
        .and_then(|r| u32::try_from(r).ok())
        .unwrap_or_else(|| {
            panic!("le temoin {temoin:#x} n'est pas dans l'image {base_chargee:#x}")
        });
    let (debut, fin) = image
        .etendue(&fichier, rva)
        .unwrap_or_else(|e| panic!("{}: etendue du temoin: {e}", chemin.display()));
    let p = image
        .position(debut)
        .unwrap_or_else(|e| panic!("{}: code du temoin: {e}", chemin.display()));
    let code = fichier
        .get(p..p + (fin - debut) as usize)
        .expect("le code du temoin doit etre dans le fichier");

    let mut appels = 0;
    for case in [garde.pointeur_dispatch, garde.pointeur_controle] {
        if let Some(relative) = image.relative(case).filter(|_| case != 0) {
            appels += pe::references(code, debut, relative);
        }
    }
    assert!(
        appels > 0,
        "{}: l'appel par pointeur du temoin ({} octets a {debut:#x}) ne passe ni \
         par le pointeur de dispatch ({:#x}) ni par celui de controle ({:#x}) de \
         la Load Config: le code de ce crate n'est pas instrumente. Drapeau \
         absent, ou `control-flow-guard=nochecks`, qui pose la table sans \
         aucun controle.",
        chemin.display(),
        code.len(),
        garde.pointeur_dispatch,
        garde.pointeur_controle
    );
}

#[cfg(target_os = "linux")]
mod elf {
    use super::{u16_le, u32_le, u64_le};

    pub const ET_DYN: u16 = 3;
    pub const PT_DYNAMIC: u32 = 2;
    pub const PT_INTERP: u32 = 3;
    pub const PT_GNU_STACK: u32 = 0x6474_e551;
    pub const PT_GNU_RELRO: u32 = 0x6474_e552;
    pub const PF_X: u32 = 1;
    pub const DT_BIND_NOW: u64 = 24;
    pub const DT_FLAGS: u64 = 30;
    pub const DT_FLAGS_1: u64 = 0x6fff_fffb;
    pub const DF_BIND_NOW: u64 = 0x8;
    pub const DF_1_NOW: u64 = 0x1;

    pub struct Segment {
        pub genre: u32,
        pub drapeaux: u32,
        position: u64,
        taille: u64,
    }

    /// Ce que la recette lit d'un ELF64 petit-boutiste.
    pub struct Elf {
        pub genre: u16,
        pub segments: Vec<Segment>,
    }

    impl Elf {
        pub fn lire(fichier: &[u8]) -> Result<Elf, String> {
            if fichier.get(0..4) != Some([0x7f, b'E', b'L', b'F'].as_slice()) {
                return Err("pas de signature ELF".into());
            }
            if fichier.get(4) != Some(&2) || fichier.get(5) != Some(&1) {
                return Err("seul l'ELF64 petit-boutiste est lu ici".into());
            }
            let genre = u16_le(fichier, 16)?;
            let debut = usize::try_from(u64_le(fichier, 32)?).map_err(|e| e.to_string())?;
            let taille = usize::from(u16_le(fichier, 54)?);
            let nombre = usize::from(u16_le(fichier, 56)?);
            let mut segments = Vec::new();
            for i in 0..nombre {
                let p = debut + taille * i;
                segments.push(Segment {
                    genre: u32_le(fichier, p)?,
                    drapeaux: u32_le(fichier, p + 4)?,
                    position: u64_le(fichier, p + 8)?,
                    taille: u64_le(fichier, p + 32)?,
                });
            }
            Ok(Elf { genre, segments })
        }

        pub fn segment(&self, genre: u32) -> Option<&Segment> {
            self.segments.iter().find(|s| s.genre == genre)
        }

        /// Les entrees (etiquette, valeur) de PT_DYNAMIC, jusqu'a DT_NULL.
        pub fn dynamique(&self, fichier: &[u8]) -> Result<Vec<(u64, u64)>, String> {
            let s = self.segment(PT_DYNAMIC).ok_or("pas de PT_DYNAMIC")?;
            let debut = usize::try_from(s.position).map_err(|e| e.to_string())?;
            let nombre = usize::try_from(s.taille / 16).map_err(|e| e.to_string())?;
            let mut entrees = Vec::new();
            for i in 0..nombre {
                let etiquette = u64_le(fichier, debut + 16 * i)?;
                if etiquette == 0 {
                    break;
                }
                entrees.push((etiquette, u64_le(fichier, debut + 16 * i + 8)?));
            }
            Ok(entrees)
        }
    }
}

#[cfg(target_os = "linux")]
fn elf() -> (PathBuf, Vec<u8>, elf::Elf) {
    let (chemin, fichier) = executable();
    let lu = elf::Elf::lire(&fichier)
        .unwrap_or_else(|e| panic!("{}: en-tetes ELF illisibles: {e}", chemin.display()));
    (chemin, fichier, lu)
}

#[cfg(target_os = "linux")]
fn verifier_pie(lu: &elf::Elf) -> Result<String, String> {
    let interpreteur = lu.segment(elf::PT_INTERP).is_some();
    if lu.genre == elf::ET_DYN && interpreteur {
        return Ok("ET_DYN avec PT_INTERP".to_string());
    }
    Err(format!(
        "e_type {} (attendu {} = ET_DYN) avec PT_INTERP {}: pas un executable a \
         position independante",
        lu.genre,
        elf::ET_DYN,
        if interpreteur { "present" } else { "absent" }
    ))
}

#[cfg(target_os = "linux")]
fn verifier_relro(lu: &elf::Elf, fichier: &[u8]) -> Result<String, String> {
    if lu.segment(elf::PT_GNU_RELRO).is_none() {
        return Err("pas de PT_GNU_RELRO, aucun RELRO".to_string());
    }
    let dynamique = lu
        .dynamique(fichier)
        .map_err(|e| format!("section dynamique: {e}"))?;
    let immediate = dynamique.iter().any(|&(etiquette, valeur)| {
        etiquette == elf::DT_BIND_NOW
            || (etiquette == elf::DT_FLAGS && valeur & elf::DF_BIND_NOW != 0)
            || (etiquette == elf::DT_FLAGS_1 && valeur & elf::DF_1_NOW != 0)
    });
    if !immediate {
        return Err(
            "PT_GNU_RELRO sans liaison immediate (ni DT_BIND_NOW, ni DF_BIND_NOW, \
             ni DF_1_NOW): RELRO partiel, la GOT des fonctions reste inscriptible"
                .to_string(),
        );
    }
    Ok("PT_GNU_RELRO et liaison immediate".to_string())
}

#[cfg(target_os = "linux")]
fn verifier_pile(lu: &elf::Elf) -> Result<String, String> {
    let pile = lu
        .segment(elf::PT_GNU_STACK)
        .ok_or("pas de PT_GNU_STACK, la pile serait executable par defaut")?;
    if pile.drapeaux & elf::PF_X != 0 {
        return Err(format!(
            "PT_GNU_STACK porte PF_X (drapeaux {:#x}): pile executable",
            pile.drapeaux
        ));
    }
    Ok(format!("PT_GNU_STACK drapeaux {:#x}", pile.drapeaux))
}

/// Les proprietes que `controler` doit lire, dans l'ordre.
#[cfg(target_os = "linux")]
const PROPRIETES: [&str; 3] = ["PIE", "RELRO complet", "pile non executable"];

/// Chaque propriete lue sur un binaire livre, avec son verdict.
#[cfg(target_os = "linux")]
fn controler(fichier: &[u8]) -> Verdicts {
    let lu = match elf::Elf::lire(fichier) {
        Ok(l) => l,
        Err(e) => return vec![("en-tetes ELF", Err(e))],
    };
    vec![
        ("PIE", verifier_pie(&lu)),
        ("RELRO complet", verifier_relro(&lu, fichier)),
        ("pile non executable", verifier_pile(&lu)),
    ]
}

#[cfg(target_os = "linux")]
#[test]
fn l_executable_de_la_recette_est_un_pie() {
    let (chemin, _, lu) = elf();
    if let Err(e) = verifier_pie(&lu) {
        panic!("{}: {e}", chemin.display());
    }
}

#[cfg(target_os = "linux")]
#[test]
fn l_executable_de_la_recette_a_un_relro_complet() {
    let (chemin, fichier, lu) = elf();
    if let Err(e) = verifier_relro(&lu, &fichier) {
        panic!("{}: {e}", chemin.display());
    }
}

#[cfg(target_os = "linux")]
#[test]
fn la_pile_de_l_executable_de_la_recette_n_est_pas_executable() {
    let (chemin, _, lu) = elf();
    if let Err(e) = verifier_pile(&lu) {
        panic!("{}: {e}", chemin.display());
    }
}
