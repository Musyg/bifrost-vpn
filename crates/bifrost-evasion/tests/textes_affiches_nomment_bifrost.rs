//! Les textes que l'utilisateur lit nomment Bifrost, jamais << le produit >>.
//!
//! # Pourquoi cette recette existe
//!
//! Decision du 18/10/2026: les textes publics disent << logiciel >> ou
//! << Bifrost >>, jamais << produit >> pour designer Bifrost, regle tenue dans
//! les documents depuis le 10/10/2026. Le code le disait encore dans les
//! textes qu'il affiche: raisons et limites des preuves (<< plan du produit >>,
//! << table du produit >>), messages d'erreur et de journal (<< fixee par le
//! produit >>, << session du produit >>), messages des bancs. Ils ont ete
//! remplaces par << Bifrost >>, ou << le logiciel >> quand la phrase le
//! demande. Les commentaires restent tels quels: ils ne s'affichent pas.
//!
//! # Ce qu'elle exige
//!
//! Le mot est lu entier, casse ignoree: `reproduit`, `produits`,
//! `PROTOCOLE_PRODUIT` ou `routage_produit` ne le portent pas.
//!
//! 1. Aucun litteral chaine des `.rs` de `crates/`, `gui/` et `fuzz/` ne le
//!    porte. Le lexeur commun (`commun/lexeur_rust.rs`) separe les litteraux
//!    du reste: un commentaire, doc-comment compris, n'est jamais lu. Le texte
//!    du litteral est lu tel que le programme l'affiche: continuations de
//!    ligne retirees (`du \` puis `produit` a la ligne suivante se lit
//!    `du produit`), echappements `\n`, `\t`, `\r` lus comme des blancs.
//!    Les doc-comments qu'affiche clap (`--help`) sont gardes a part, sur le
//!    texte RENDU, par une recette de chaque binaire
//!    (`l_aide_ne_nomme_pas_le_produit`, dans `bifrost-cli` et
//!    `bifrost-daemon`).
//! 2. Aucune page de manuel (`packaging/man/*.1`) ne le porte hors des
//!    commentaires roff (`.\"` en tete de ligne, `\"` jusqu'a la fin de la
//!    ligne). Les echappements roff sans largeur (`\&`, `\%`, `\:`) sont
//!    retires avant la lecture: `pro\&duit` se lit `produit`.
//! 3. Aucun script (`scripts/`, et les scripts de `packaging/`) ni texte de
//!    paquet (`packaging/`, hors pages de manuel, cle `.asc` et documents
//!    `.md`) ne le porte hors commentaire, en grammaire fermee: une ligne dont
//!    le premier caractere non blanc est `#` est un commentaire; dans un
//!    `.ps1`, les lignes d'un bloc `<# ... #>` aussi, et celles qui commencent
//!    par `//` (le C# embarque par `Add-Type`). Toute autre ligne est lue en
//!    entier: message, argument d'un aide (`ecart`, `passe`, `step`...),
//!    motif cherche par `grep`, valeur d'une table. Les textes de la coquille
//!    (`gui/ui/`, `gui/tauri.conf.json`) sont lus en entier, sans grammaire.
//! 4. Les exceptions sont nommees une par une, par fichier, par fragment du
//!    texte qui porte le mot, et par nombre: chacune doit couvrir EXACTEMENT
//!    le nombre d'occurrences declare. Une exception qui ne sert plus rougit,
//!    et une occurrence nouvelle du meme verbe dans le meme fichier aussi: le
//!    jugement << verbe ou nom >> se refait a chaque fois. Ce sont le verbe
//!    << produire >> (<< n'a produit aucun paquet >>), un participe
//!    (<< le fichier public produit >>), un produit TIERS (qui ne designe pas
//!    Bifrost), des noms de fichier de banc (`produit.json`), le nom d'une
//!    table de donnees de recette, le motif des deux recettes d'aide, et le
//!    nom du document `docs/07-programme-securite-produit.md`, admis partout.
//!
//! # Comptes de controle
//!
//! Un parcours casse rendrait vert sans rien lire. Les exceptions en sont le
//! premier temoin (un verbe que le parcours ne voit plus laisse son exception
//! sans emploi, donc rouge); les seuils de fichiers et de litteraux lus sont le
//! second.
//!
//! # Son perimetre et sa methode
//!
//! Sur le disque, sans git (sur l'hote Linux le depot peut etre copie par
//! `tar`). CE fichier est exclu du parcours: il porte le mot dans ses motifs
//! et ses exceptions.

#[allow(dead_code)]
#[path = "commun/lexeur_rust.rs"]
mod lexeur_rust;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Chemin relatif (avec des `/`) de cette recette: exclue du parcours.
const GUARD_REL: &str = "crates/bifrost-evasion/tests/textes_affiches_nomment_bifrost.rs";

/// Les repertoires que le parcours ne descend jamais.
const DOSSIERS_IGNORES: [&str; 3] = [".git", "target", "node_modules"];

/// Le mot, en minuscules.
const MOT: &str = "produit";

/// Seuils du compte de controle (le depot porte 262 fichiers `.rs` et pres de
/// 27 000 litteraux au 18/10/2026, 46 scripts, 3 pages de manuel).
const SEUIL_FICHIERS_RS: usize = 200;
const SEUIL_LITTERAUX: usize = 20_000;
const SEUIL_SCRIPTS: usize = 40;
const PAGES_DE_MANUEL: usize = 3;

/// Une exception nommee.
struct Exception {
    /// Chemin relatif du fichier, avec des `/`; `*` pour tout fichier.
    fichier: &'static str,
    /// Le fragment du texte qui porte le mot, tel qu'il se lit (litteral:
    /// apres continuations et echappements; ligne: telle qu'ecrite).
    fragment: &'static str,
    /// `true`: le litteral ENTIER vaut le fragment (une donnee, pas une
    /// phrase); `false`: le fragment est cherche dans le texte.
    entier: bool,
    /// Nombre exact d'occurrences du mot que l'exception couvre dans ce
    /// fichier; `None` pour une exception admise partout, sans compte.
    nombre: Option<usize>,
    /// Pourquoi le mot reste.
    raison: &'static str,
}

const fn ex(
    fichier: &'static str,
    fragment: &'static str,
    nombre: usize,
    raison: &'static str,
) -> Exception {
    Exception {
        fichier,
        fragment,
        entier: false,
        nombre: Some(nombre),
        raison,
    }
}

const VERBE: &str = "le verbe produire, pas un nom";

/// Le nom du document 07, cite par son fichier: admis partout.
const DOCUMENT_07: Exception = Exception {
    fichier: "*",
    fragment: "07-programme-securite-produit",
    entier: false,
    nombre: None,
    raison: "nom de fichier du document 07, cite tel quel",
};

/// Les exceptions des litteraux Rust.
const EXCEPTIONS_LITTERAUX: &[Exception] = &[
    Exception {
        fichier: "crates/bifrost-cli/src/preuve_nft/recettes_objets.rs",
        fragment: "produit",
        entier: true,
        nombre: Some(5),
        raison: "nom de la table nftables d'une donnee de recette; la recette `muet` \
                 exige justement qu'il ne sorte jamais du rapport",
    },
    Exception {
        fichier: "crates/bifrost-cli/src/main.rs",
        fragment: "produit",
        entier: true,
        nombre: Some(1),
        raison: "motif de la recette `l_aide_ne_nomme_pas_le_produit`",
    },
    Exception {
        fichier: "crates/bifrost-daemon/src/main.rs",
        fragment: "produit",
        entier: true,
        nombre: Some(1),
        raison: "motif de la recette `l_aide_ne_nomme_pas_le_produit`",
    },
    ex(
        "crates/bifrost-coffre/src/signature.rs",
        "le fichier public produit",
        1,
        "participe: le fichier que minisign -G a produit",
    ),
    ex(
        "crates/bifrost-core/src/ports.rs",
        "ne produit aucun",
        1,
        VERBE,
    ),
    ex(
        "crates/bifrost-daemon/src/dns_leak.rs",
        "un produit tiers",
        1,
        "un logiciel TIERS qui bloquerait la requete: ne designe pas Bifrost",
    ),
    ex(
        "crates/bifrost-daemon/src/checks/capture.rs",
        "n'a produit aucune",
        1,
        VERBE,
    ),
    ex(
        "crates/bifrost-daemon/src/checks/mod.rs",
        "n'a produit",
        7,
        VERBE,
    ),
    ex(
        "crates/bifrost-daemon/src/checks/mod.rs",
        "n'ont produit",
        1,
        VERBE,
    ),
    ex(
        "crates/bifrost-daemon/src/checks/transport.rs",
        "ce que produit un",
        1,
        VERBE,
    ),
    ex(
        "crates/bifrost-dns/src/telemetrie.rs",
        "a produit des motifs",
        1,
        VERBE,
    ),
];

const NOM_DE_FICHIER: &str = "nom de fichier de travail du banc, jamais affiche comme texte";

/// Les exceptions des scripts et des textes de paquet.
const EXCEPTIONS_LIGNES: &[Exception] = &[
    ex(
        "scripts/banc-cdn-linux.sh",
        "produit.log",
        2,
        NOM_DE_FICHIER,
    ),
    ex(
        "scripts/preuve-dns-linux.sh",
        "resolv-produit.conf",
        3,
        NOM_DE_FICHIER,
    ),
    ex(
        "scripts/preuve-nft-linux.sh",
        "produit.nft",
        2,
        NOM_DE_FICHIER,
    ),
    ex(
        "scripts/preuve-nft-linux.sh",
        "produit.json",
        4,
        NOM_DE_FICHIER,
    ),
    ex(
        "scripts/banc-jeton-filtre-windows.ps1",
        "ne se produit pas",
        1,
        VERBE,
    ),
    ex("scripts/e2e-linux.sh", "ne produit aucun", 1, VERBE),
    ex(
        "scripts/mort-daemon-systemd-linux.sh",
        "n'a produit aucun",
        1,
        VERBE,
    ),
    ex(
        "scripts/paquets-gui-linux.sh",
        "n'a produit aucun",
        1,
        VERBE,
    ),
    ex(
        "scripts/paquets-gui-windows.ps1",
        "n'a produit aucun",
        1,
        VERBE,
    ),
    ex("scripts/paquets-linux.sh", "n'a produit aucun", 1, VERBE),
    ex("scripts/paquets-windows.ps1", "n'a produit aucun", 1, VERBE),
    ex(
        "scripts/resolveur-linux.sh",
        "generateur produit une",
        1,
        VERBE,
    ),
    ex(
        "scripts/telemetrie-jeton-capture-windows.ps1",
        "n a produit aucun",
        1,
        VERBE,
    ),
    ex(
        "scripts/telemetrie-regle-microsoft-windows.ps1",
        "ne produit aucun",
        1,
        VERBE,
    ),
];

fn racine() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("la racine de l'espace de travail doit exister")
        .to_path_buf()
}

fn est_ident(o: u8) -> bool {
    o == b'_' || o.is_ascii_alphanumeric()
}

/// Les positions (octets) du mot entier dans `texte`, casse ignoree.
fn occurrences(texte: &str) -> Vec<usize> {
    let b = texte.as_bytes();
    let m = MOT.as_bytes();
    let mut sorties = Vec::new();
    if b.len() < m.len() {
        return sorties;
    }
    for p in 0..=b.len() - m.len() {
        if b[p..p + m.len()].eq_ignore_ascii_case(m)
            && (p == 0 || !est_ident(b[p - 1]))
            && (p + m.len() == b.len() || !est_ident(b[p + m.len()]))
        {
            sorties.push(p);
        }
    }
    sorties
}

/// Le texte d'un litteral tel que le programme l'affiche, a ce qui compte
/// ici pres: une continuation de ligne (`\` en fin de ligne) disparait avec
/// les blancs qui la suivent, comme en Rust; `\n`, `\t`, `\r`, `\0` et les
/// echappements numeriques deviennent un blanc (une frontiere de mot); `\\`,
/// `\"` et `\'` rendent leur caractere. Une chaine brute est lue telle quelle.
fn lisible(corps: &str, brut: bool) -> String {
    if brut {
        return corps.to_owned();
    }
    let c: Vec<char> = corps.chars().collect();
    let mut sortie = String::with_capacity(corps.len());
    let mut i = 0usize;
    while i < c.len() {
        if c[i] != '\\' || i + 1 >= c.len() {
            sortie.push(c[i]);
            i += 1;
            continue;
        }
        match c[i + 1] {
            '\n' | '\r' => {
                i += 2;
                while i < c.len() && c[i].is_whitespace() {
                    i += 1;
                }
            }
            'n' | 't' | 'r' | '0' => {
                sortie.push(' ');
                i += 2;
            }
            'x' => {
                sortie.push(' ');
                i = (i + 4).min(c.len());
            }
            'u' => {
                sortie.push(' ');
                i += 2;
                while i < c.len() && c[i] != '}' {
                    i += 1;
                }
                i += 1;
            }
            autre => {
                sortie.push(autre);
                i += 2;
            }
        }
    }
    sortie
}

/// Les lignes de code d'un script ou d'un texte de paquet, avec leur numero,
/// en grammaire fermee (voir l'en-tete): les lignes de commentaire sont
/// retirees, toutes les autres sont rendues entieres.
fn lignes_de_code(texte: &str, ps1: bool) -> Vec<(usize, &str)> {
    let mut sorties = Vec::new();
    let mut dans_un_bloc = false;
    for (k, ligne) in texte.lines().enumerate() {
        let t = ligne.trim_start();
        if ps1 && dans_un_bloc {
            if t.contains("#>") {
                dans_un_bloc = false;
            }
            continue;
        }
        if ps1 && t.starts_with("<#") {
            dans_un_bloc = !t[2..].contains("#>");
            continue;
        }
        if t.starts_with('#') || (ps1 && t.starts_with("//")) {
            continue;
        }
        sorties.push((k + 1, ligne));
    }
    sorties
}

/// Les lignes lues d'une page de manuel: commentaires roff retires, et
/// echappements sans largeur effaces.
fn lignes_de_page(texte: &str) -> Vec<(usize, String)> {
    let mut sorties = Vec::new();
    for (k, ligne) in texte.lines().enumerate() {
        if ligne.starts_with(".\\\"") || ligne.starts_with("'\\\"") {
            continue;
        }
        let utile = match ligne.find("\\\"") {
            Some(p) => &ligne[..p],
            None => ligne,
        };
        let lu = utile
            .replace("\\&", "")
            .replace("\\%", "")
            .replace("\\:", "");
        sorties.push((k + 1, lu));
    }
    sorties
}

/// Le juge: chaque occurrence du mot est couverte par une exception du
/// fichier, ou c'est une faute. Les emplois de chaque exception sont comptes.
struct Juge<'a> {
    exceptions: Vec<&'a Exception>,
    emplois: Vec<usize>,
    fautes: Vec<String>,
}

impl<'a> Juge<'a> {
    fn new(exceptions: &'a [Exception]) -> Self {
        let mut toutes: Vec<&Exception> = exceptions.iter().collect();
        toutes.push(&DOCUMENT_07);
        let n = toutes.len();
        Juge {
            exceptions: toutes,
            emplois: vec![0; n],
            fautes: Vec::new(),
        }
    }

    /// Juge un texte (un litteral, une ligne) du fichier `rel`, a la ligne
    /// `ligne`.
    fn juger(&mut self, rel: &str, ligne: usize, texte: &str) {
        for p in occurrences(texte) {
            let couverte = self.exceptions.iter().position(|e| {
                (e.fichier == "*" || e.fichier == rel)
                    && if e.entier {
                        texte == e.fragment
                    } else {
                        texte
                            .match_indices(e.fragment)
                            .any(|(s, f)| s <= p && p + MOT.len() <= s + f.len())
                    }
            });
            match couverte {
                Some(k) => self.emplois[k] += 1,
                None => {
                    let extrait: String = texte.chars().take(160).collect();
                    self.fautes.push(format!("{rel}:{ligne}: {extrait}"));
                }
            }
        }
    }

    /// Les fautes, plus chaque exception dont l'emploi differe du nombre
    /// declare.
    fn verdict(mut self) -> Vec<String> {
        for (e, n) in self.exceptions.iter().zip(&self.emplois) {
            if let Some(attendu) = e.nombre
                && attendu != *n
            {
                self.fautes.push(format!(
                    "exception {} << {} >> ({}): {attendu} declaree(s), {n} trouvee(s)",
                    e.fichier, e.fragment, e.raison
                ));
            }
        }
        self.fautes
    }
}

/// Les fichiers sous `dossier` (relatif a la racine), recursivement, hors
/// `DOSSIERS_IGNORES`, ranges par chemin; chemins relatifs avec des `/`.
fn fichiers_sous(racine: &Path, dossier: &str) -> Vec<(String, PathBuf)> {
    let mut sorties = Vec::new();
    let mut pile = vec![racine.join(dossier)];
    while let Some(rep) = pile.pop() {
        let Ok(entrees) = std::fs::read_dir(&rep) else {
            continue;
        };
        for entree in entrees.flatten() {
            let chemin = entree.path();
            let nom = entree.file_name().to_string_lossy().into_owned();
            if chemin.is_dir() {
                if !DOSSIERS_IGNORES.contains(&nom.as_str()) {
                    pile.push(chemin);
                }
                continue;
            }
            let rel = chemin
                .strip_prefix(racine)
                .expect("sous la racine")
                .to_string_lossy()
                .replace('\\', "/");
            sorties.push((rel, chemin));
        }
    }
    sorties.sort();
    sorties
}

fn lire(chemin: &Path) -> String {
    std::fs::read_to_string(chemin)
        .unwrap_or_else(|e| panic!("{} illisible: {e}", chemin.display()))
}

fn extension(rel: &str) -> &str {
    let nom = rel.rsplit('/').next().unwrap_or(rel);
    nom.rsplit_once('.').map_or("", |(_, e)| e)
}

#[test]
fn aucun_litteral_affiche_ne_nomme_le_produit() {
    let racine = racine();
    let mut juge = Juge::new(EXCEPTIONS_LITTERAUX);
    let (mut fichiers, mut litteraux) = (0usize, 0usize);
    for dossier in ["crates", "gui", "fuzz"] {
        for (rel, chemin) in fichiers_sous(&racine, dossier) {
            if extension(&rel) != "rs" || rel == GUARD_REL {
                continue;
            }
            let source = lire(&chemin);
            let decoupe = lexeur_rust::decouper(&source)
                .unwrap_or_else(|e| panic!("{rel}: le lexeur commun refuse le source: {e}"));
            fichiers += 1;
            litteraux += decoupe.litteraux.len();
            for l in &decoupe.litteraux {
                juge.juger(&rel, l.ligne, &lisible(&l.corps, l.brut));
            }
        }
    }
    assert!(
        fichiers >= SEUIL_FICHIERS_RS && litteraux >= SEUIL_LITTERAUX,
        "parcours casse: {fichiers} fichier(s) .rs, {litteraux} litteraux lus"
    );
    let fautes = juge.verdict();
    assert!(
        fautes.is_empty(),
        "litteral affiche qui nomme Bifrost << produit >> (dire << Bifrost >> ou \
         << le logiciel >>; un verbe se nomme dans EXCEPTIONS_LITTERAUX):\n{}",
        fautes.join("\n")
    );
}

#[test]
fn aucune_page_de_manuel_ne_nomme_le_produit() {
    let racine = racine();
    let mut juge = Juge::new(&[]);
    let mut pages = 0usize;
    for (rel, chemin) in fichiers_sous(&racine, "packaging/man") {
        if extension(&rel) != "1" {
            continue;
        }
        pages += 1;
        for (n, ligne) in lignes_de_page(&lire(&chemin)) {
            juge.juger(&rel, n, &ligne);
        }
    }
    assert_eq!(pages, PAGES_DE_MANUEL, "pages de manuel lues");
    let fautes = juge.verdict();
    assert!(
        fautes.is_empty(),
        "page de manuel qui nomme Bifrost << produit >>:\n{}",
        fautes.join("\n")
    );
}

#[test]
fn aucun_script_ni_texte_de_paquet_ne_nomme_le_produit() {
    let racine = racine();
    let mut juge = Juge::new(EXCEPTIONS_LIGNES);
    let mut scripts = 0usize;
    let mut lus: BTreeMap<String, usize> = BTreeMap::new();
    for dossier in ["scripts", "packaging"] {
        for (rel, chemin) in fichiers_sous(&racine, dossier) {
            let ext = extension(&rel);
            if matches!(ext, "1" | "asc" | "md") {
                continue;
            }
            let texte = lire(&chemin);
            if dossier == "scripts" {
                scripts += 1;
            }
            let lignes = lignes_de_code(&texte, ext == "ps1");
            *lus.entry(dossier.to_owned()).or_default() += lignes.len();
            for (n, ligne) in lignes {
                juge.juger(&rel, n, ligne);
            }
        }
    }
    // Les textes de la coquille: lus en entier.
    let mut coquille = fichiers_sous(&racine, "gui/ui");
    coquille.push((
        "gui/tauri.conf.json".to_owned(),
        racine.join("gui/tauri.conf.json"),
    ));
    for (rel, chemin) in coquille {
        let texte = lire(&chemin);
        *lus.entry("gui".to_owned()).or_default() += 1;
        for (k, ligne) in texte.lines().enumerate() {
            juge.juger(&rel, k + 1, ligne);
        }
    }
    assert!(
        scripts >= SEUIL_SCRIPTS && lus.len() == 3 && lus.values().all(|&n| n > 0),
        "parcours casse: {scripts} script(s) lus, lignes lues par dossier {lus:?}"
    );
    let fautes = juge.verdict();
    assert!(
        fautes.is_empty(),
        "script ou texte de paquet qui nomme Bifrost << produit >> (dire << Bifrost >>; \
         un verbe ou un nom de fichier se nomme dans EXCEPTIONS_LIGNES):\n{}",
        fautes.join("\n")
    );
}

// --- Recettes du juge et des grammaires --------------------------------------

#[test]
fn le_mot_n_est_lu_qu_entier() {
    for (texte, n) in [
        ("plan du produit", 1),
        ("Produit: --coeur-e2e", 1),
        ("PRODUIT", 1),
        ("fixee par le produit, produit.", 2),
        ("resolv-produit.conf", 1),
        ("reproduit", 0),
        ("produits", 0),
        ("produite", 0),
        ("{PROTOCOLE_PRODUIT}", 0),
        ("--example routage_produit", 0),
        ("produit2", 0),
    ] {
        assert_eq!(occurrences(texte).len(), n, "{texte}");
    }
}

#[test]
fn le_litteral_se_lit_comme_il_s_affiche() {
    assert_eq!(
        lisible("l'etiquette du \\\n         produit (protocole)", false),
        "l'etiquette du produit (protocole)"
    );
    assert_eq!(occurrences(&lisible("motifs:\\nproduit", false)).len(), 1);
    assert_eq!(occurrences(&lisible("a\\tproduit\\x41", false)).len(), 1);
    assert_eq!(lisible("\\\"produit\\\"", false), "\"produit\"");
    assert_eq!(lisible("du \\\n produit", true), "du \\\n produit");
}

#[test]
fn la_grammaire_des_scripts_ne_retire_que_les_commentaires() {
    let sh = "#!/bin/sh\n  # le produit\necho \"le produit\" # fin\n// produit\n";
    let lues: Vec<usize> = lignes_de_code(sh, false).iter().map(|l| l.0).collect();
    assert_eq!(lues, vec![3, 4], "sh: commentaires de tete seulement");
    let ps1 = "<#\n produit\n#>\n<# produit #>\nWrite-Host 'produit'\n    // produit\n";
    let lues: Vec<usize> = lignes_de_code(ps1, true).iter().map(|l| l.0).collect();
    assert_eq!(lues, vec![5], "ps1: blocs, en-tete et C# embarque retires");
}

#[test]
fn la_page_de_manuel_retire_ses_commentaires_et_lit_ses_echappements() {
    let page = ".\\\" le produit\n.TH X 1\nla table \\\" du produit\npro\\&duit\n";
    let lues: Vec<String> = lignes_de_page(page).into_iter().map(|l| l.1).collect();
    assert_eq!(lues, vec![".TH X 1", "la table ", "produit"]);
}

#[test]
fn le_juge_compte_chaque_exception_au_plus_juste() {
    const EX: &[Exception] = &[ex("a.sh", "n'a produit aucun", 1, VERBE)];
    let mut juge = Juge::new(EX);
    juge.juger("a.sh", 1, "echo \"rpmbuild n'a produit aucun .rpm\"");
    juge.juger("a.sh", 2, "voir docs/07-programme-securite-produit.md");
    assert!(juge.verdict().is_empty());

    // Le meme fragment dans un autre fichier n'est pas couvert.
    let mut juge = Juge::new(EX);
    juge.juger("a.sh", 1, "echo \"n'a produit aucun\"");
    juge.juger("b.sh", 1, "echo \"n'a produit aucun\"");
    assert_eq!(juge.verdict().len(), 1);

    // Une exception sans emploi, ou servie deux fois, rougit.
    assert_eq!(Juge::new(EX).verdict().len(), 1);
    let mut juge = Juge::new(EX);
    juge.juger("a.sh", 1, "n'a produit aucun");
    juge.juger("a.sh", 2, "n'a produit aucun");
    assert_eq!(juge.verdict().len(), 1);

    // Le fragment couvre le mot qu'il contient, pas un autre de la ligne.
    let mut juge = Juge::new(EX);
    juge.juger("a.sh", 1, "n'a produit aucun paquet du produit");
    let fautes = juge.verdict();
    assert_eq!(fautes.len(), 1, "{fautes:?}");

    // Une exception entiere ne couvre que le litteral exact.
    const ENTIER: &[Exception] = &[Exception {
        fichier: "r.rs",
        fragment: "produit",
        entier: true,
        nombre: Some(1),
        raison: "donnee",
    }];
    let mut juge = Juge::new(ENTIER);
    juge.juger("r.rs", 1, "produit");
    juge.juger("r.rs", 2, "la table du produit");
    assert_eq!(juge.verdict().len(), 1);
}
