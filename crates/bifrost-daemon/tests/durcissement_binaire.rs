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
//!   pose la table et GUARD_CF sans emettre un seul controle.
//! - Linux: executable PIE (ET_DYN avec interpreteur), RELRO complet
//!   (PT_GNU_RELRO et liaison immediate), pile non executable (PT_GNU_STACK
//!   sans PF_X). Ce sont des defauts de rustc: rien ne les pose dans le depot,
//!   la recette rougit si un drapeau les retire.
//! - Partout: `.cargo/config.toml` demande CFG pour la cible MSVC. C'est la
//!   seule partie que la CI automatique, qui tourne sous Linux, execute pour
//!   Windows.
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
//! - Le profil: elle lit un binaire de recette (profil de test, sans LTO), pas
//!   les binaires `--release`. Les drapeaux de cible sont les memes pour les
//!   deux profils; l'effet de LTO sur CFG a ete mesure a part sur les binaires
//!   release (document 07, section 2.4).
//! - La bibliotheque standard: livree precompilee sans CFG, ses appels
//!   indirects ne sont controles ni ici ni dans les binaires livres.
//! - L'execution: elle ne fait pas tomber un appel vers une cible invalide;
//!   elle constate que le controle est emis et que l'image le declare.
//! - Le binaire livre lui-meme: une construction lancee hors du depot, ou avec
//!   RUSTFLAGS defini, ne lit pas `.cargo/config.toml`. La recette rougit si
//!   ELLE est construite ainsi, pas si seul le binaire livre l'est.

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

#[test]
fn la_configuration_cargo_demande_cfg_pour_la_cible_msvc() {
    let chemin = racine().join(".cargo").join("config.toml");
    let texte = std::fs::read_to_string(&chemin)
        .unwrap_or_else(|e| panic!("{} illisible: {e}", chemin.display()));
    let config: toml::Table = toml::from_str(&texte)
        .unwrap_or_else(|e| panic!("{} n'est pas du TOML: {e}", chemin.display()));

    let drapeaux: Vec<&str> = config
        .get("target")
        .and_then(|t| t.get(CLE_CIBLE_MSVC))
        .and_then(|t| t.get("rustflags"))
        .and_then(|r| r.as_array())
        .map(|r| r.iter().filter_map(|d| d.as_str()).collect())
        .unwrap_or_default();

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

#[cfg(all(windows, target_env = "msvc"))]
mod pe {
    use super::{u16_le, u32_le, u64_le};

    pub const HIGH_ENTROPY_VA: u16 = 0x0020;
    pub const DYNAMIC_BASE: u16 = 0x0040;
    pub const NX_COMPAT: u16 = 0x0100;
    pub const GUARD_CF: u16 = 0x4000;
    /// IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT, dans GuardFlags.
    pub const TABLE_DES_CIBLES_PRESENTE: u32 = 0x0000_0400;

    const REPERTOIRE_EXCEPTIONS: usize = 3;
    const REPERTOIRE_LOAD_CONFIG: usize = 10;

    struct Section {
        adresse: u32,
        taille_virtuelle: u32,
        taille_brute: u32,
        position: u32,
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

#[cfg(all(windows, target_env = "msvc"))]
#[test]
fn l_executable_de_la_recette_porte_aslr_64_bits_et_dep() {
    let (chemin, _, image) = image();
    for (bit, nom) in [
        (pe::DYNAMIC_BASE, "DYNAMIC_BASE (ASLR)"),
        (pe::HIGH_ENTROPY_VA, "HIGH_ENTROPY_VA (ASLR 64 bits)"),
        (pe::NX_COMPAT, "NX_COMPAT (DEP)"),
    ] {
        assert!(
            image.caracteristiques & bit != 0,
            "{}: DllCharacteristics {:#06x} sans {nom}",
            chemin.display(),
            image.caracteristiques
        );
    }
}

#[cfg(all(windows, target_env = "msvc"))]
#[test]
fn l_executable_de_la_recette_porte_control_flow_guard() {
    let (chemin, fichier, image) = image();
    assert!(
        image.caracteristiques & pe::GUARD_CF != 0,
        "{}: DllCharacteristics {:#06x} sans GUARD_CF. `.cargo/config.toml` \
         n'a pas ete lu pour construire cette recette (RUSTFLAGS ou \
         CARGO_ENCODED_RUSTFLAGS defini, cargo lance hors du depot) ou ne \
         demande plus `-C control-flow-guard`.",
        chemin.display(),
        image.caracteristiques
    );
    let garde = image
        .garde(&fichier)
        .unwrap_or_else(|e| panic!("{}: Load Config illisible: {e}", chemin.display()));
    assert!(
        garde.drapeaux & pe::TABLE_DES_CIBLES_PRESENTE != 0 && garde.table != 0 && garde.cibles > 0,
        "{}: GUARD_CF sans table des cibles (GuardFlags {:#x}, table {:#x}, {} cible(s))",
        chemin.display(),
        garde.drapeaux,
        garde.table,
        garde.cibles
    );
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
#[test]
fn l_executable_de_la_recette_est_un_pie() {
    let (chemin, _, lu) = elf();
    assert!(
        lu.genre == elf::ET_DYN && lu.segment(elf::PT_INTERP).is_some(),
        "{}: e_type {} (attendu {} = ET_DYN) avec PT_INTERP {}: pas un \
         executable a position independante",
        chemin.display(),
        lu.genre,
        elf::ET_DYN,
        if lu.segment(elf::PT_INTERP).is_some() {
            "present"
        } else {
            "absent"
        }
    );
}

#[cfg(target_os = "linux")]
#[test]
fn l_executable_de_la_recette_a_un_relro_complet() {
    let (chemin, fichier, lu) = elf();
    assert!(
        lu.segment(elf::PT_GNU_RELRO).is_some(),
        "{}: pas de PT_GNU_RELRO, aucun RELRO",
        chemin.display()
    );
    let dynamique = lu
        .dynamique(&fichier)
        .unwrap_or_else(|e| panic!("{}: section dynamique: {e}", chemin.display()));
    let immediate = dynamique.iter().any(|&(etiquette, valeur)| {
        etiquette == elf::DT_BIND_NOW
            || (etiquette == elf::DT_FLAGS && valeur & elf::DF_BIND_NOW != 0)
            || (etiquette == elf::DT_FLAGS_1 && valeur & elf::DF_1_NOW != 0)
    });
    assert!(
        immediate,
        "{}: PT_GNU_RELRO sans liaison immediate (ni DT_BIND_NOW, ni DF_BIND_NOW, \
         ni DF_1_NOW): RELRO partiel, la GOT des fonctions reste inscriptible",
        chemin.display()
    );
}

#[cfg(target_os = "linux")]
#[test]
fn la_pile_de_l_executable_de_la_recette_n_est_pas_executable() {
    let (chemin, _, lu) = elf();
    let pile = lu.segment(elf::PT_GNU_STACK).unwrap_or_else(|| {
        panic!(
            "{}: pas de PT_GNU_STACK, la pile serait executable par defaut",
            chemin.display()
        )
    });
    assert!(
        pile.drapeaux & elf::PF_X == 0,
        "{}: PT_GNU_STACK porte PF_X (drapeaux {:#x}): pile executable",
        chemin.display(),
        pile.drapeaux
    );
}
