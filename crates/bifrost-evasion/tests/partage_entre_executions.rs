//! Deux executions qui tournent en meme temps sur la meme machine ne se
//! partagent ni un chemin temporaire, ni un numero de port relache.
//!
//! # Pourquoi cette recette existe
//!
//! Le pipeline fait tourner plusieurs suites a la fois sur le meme hote, sous
//! le meme compte, chacune dans sa copie. Deux defauts de la meme famille y
//! ont signe des rouges qui disparaissaient seuls. Mesures du 30/09/2026:
//!
//! - `tests/tunnel_par_coeur.rs` travaillait dans un repertoire temporaire au
//!   nom FIXE. Deux executions decalees de 2 s sur essai-linux: 12 rouges sur
//!   12, la seconde effacant le repertoire de la premiere et y posant son
//!   propre enrobage de coeur, que la relance de la premiere executait. Le
//!   meme conflit avait deja ete trouve le 05/09/2026 dans `tests/coeurs.rs`,
//!   et corrige la seule.
//! - `coeurs::port::port_sans_personne` rendait un numero lie puis relache.
//!   Sur dev-windows, l'attribueur rend ce numero a une autre liaison, y
//!   compris a la connexion sortante qui suit dans le meme processus, laquelle
//!   aboutit alors sur elle-meme: 2 connexions abouties sur 16000 vers un
//!   port << sans personne >>, sous 4 processus qui lient `:0` en boucle.
//!
//! # Ce qu'elle refuse, dans le CODE de `crates/**/*.rs`
//!
//! Commentaires et litteraux exclus (lexeur partage `commun/lexeur_rust.rs`):
//!
//! 1. Un appel a `temp_dir()` dont l'instruction ne porte ni
//!    `process::id()` ni `etiquette_unique(`: un nom sous le repertoire
//!    temporaire que deux executions calculeraient a l'identique. Les
//!    exceptions sont nommees dans [`TEMP_ADMIS`], avec leur raison.
//! 2. Un numero de port tire d'une ecoute qu'on laisse tomber:
//!    `local_addr()` enchaine sur `TcpListener::bind(...)` ou
//!    `UdpSocket::bind(...)` (l'ecoute est un temporaire, relachee a la fin
//!    de l'instruction), ou une ecoute liee a un nom puis passee a `drop` dans
//!    les lignes qui suivent.
//! 3. Un `port_sans_personne()` consomme sur place, ou l'une des enveloppes
//!    des recettes qui le rendent ([`PORTS_TENUS`]): `.port()` ou
//!    `.adresse()` enchaine sur l'appel relache le port tenu a la fin de
//!    l'instruction, et rend la course que la fonction ferme.
//!
//! # Ce qu'elle ne voit pas
//!
//! - Un identifiant de processus range dans une variable puis place dans le
//!   nom: la regle 1 le prend pour un nom fixe (il faudrait l'admettre ou,
//!   mieux, ecrire `process::id()` dans l'instruction).
//! - Un chemin fixe ecrit en dur hors de `temp_dir()` (`"/tmp/..."`).
//! - Une ecoute relachee par une portee qui se ferme plutot que par `drop`,
//!   ou par un `drop` plus loin que [`FENETRE_DROP`] lignes.
//! - Un `PortSansPersonne` range dans une variable, puis relache avant que
//!   l'adresse ne serve: la duree de vie est l'affaire de l'appelant.
//! - Une enveloppe nouvelle de `port_sans_personne`, tant que son nom n'est
//!   pas ajoute a [`PORTS_TENUS`].
//!
//! Le parcours se fait sur le disque, sans git, comme ses voisines.

// Seul `decouper` sert ici; les lectures par position servent aux voisines.
#[allow(dead_code)]
#[path = "commun/lexeur_rust.rs"]
mod lexeur_rust;

use lexeur_rust::decouper;
use std::path::{Path, PathBuf};

/// Les repertoires que le parcours ne descend jamais.
const DOSSIERS_IGNORES: [&str; 2] = [".git", "target"];

/// Lignes, apres la liaison, ou un `drop` du meme nom est cherche.
const FENETRE_DROP: usize = 8;

/// Les appels qui rendent un port TENU (`coeurs::port::PortSansPersonne`):
/// la fonction, et les deux enveloppes des recettes qui la rendent telle
/// quelle (`tests/coeurs.rs`, `tests/vitalite.rs`).
const PORTS_TENUS: [&str; 3] = ["port_sans_personne(", "socks_fictif(", "port_mort("];

/// Les appels a `temp_dir()` admis sans identifiant de processus: le fichier,
/// un fragment de CODE de l'instruction (hors litteraux), et la raison.
const TEMP_ADMIS: [(&str, &str, &str); 8] = [
    (
        "crates/bifrost-coffre/src/lib.rs",
        "let f = std::env::temp_dir().join(",
        "chemin jamais cree: la recette n'inspecte que son repertoire parent",
    ),
    (
        "crates/bifrost-daemon/src/checks/capture.rs",
        "p.starts_with(std::env::temp_dir())",
        "comparaison avec le repertoire, aucun nom forme",
    ),
    (
        "crates/bifrost-daemon/src/exit_ip.rs",
        "let etl = std::env::temp_dir().join(",
        "Windows, hors recette: PktMon n'a qu'une session par machine et le \
         code l'arrete avant de la demarrer, deux executions concurrentes se \
         genent donc de toute facon",
    ),
    (
        "crates/bifrost-daemon/src/exit_ip.rs",
        "let txt = std::env::temp_dir().join(",
        "Windows, hors recette: la conversion de la meme capture",
    ),
    (
        "crates/bifrost-firewall/src/plan_telemetrie.rs",
        "let absent = std::env::temp_dir().join(",
        "chemin volontairement absent, jamais cree",
    ),
    (
        "crates/bifrost-firewall/src/plan_telemetrie.rs",
        "let repertoire = std::env::temp_dir()",
        "le repertoire lui-meme, aucun nom forme",
    ),
    (
        "crates/bifrost-firewall/src/windows/ffi.rs",
        "let absent = std::env::temp_dir().join(",
        "chemin volontairement absent, jamais cree",
    ),
    (
        "crates/bifrost-temoin-svchost/src/hote.rs",
        "std::env::temp_dir().join(NOM_JOURNAL)",
        "Windows, hors recette: repli du journal du temoin quand le nom de son \
         service manque; le cas normal est le chemin que le banc designe",
    ),
];

/// Comptes de controle: en dessous, soit le parcours ne lit plus le depot,
/// soit l'une des regles ne regarde plus rien, et le vert ne garderait rien.
const SEUIL_FICHIERS: usize = 100;
const SEUIL_TEMP_DIR: usize = 20;
const SEUIL_LIAISONS: usize = 30;

fn racine() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("la racine de l'espace de travail doit exister")
        .to_path_buf()
}

/// Parcourt `dossier` et ramasse les `.rs`, chemin relatif a `racine` (en `/`).
fn ramasser(dossier: &Path, racine: &Path, trouves: &mut Vec<(String, String)>) {
    let Ok(entrees) = std::fs::read_dir(dossier) else {
        return;
    };
    for entree in entrees.flatten() {
        let chemin = entree.path();
        let nom = entree.file_name().to_string_lossy().into_owned();
        if chemin.is_dir() {
            if !DOSSIERS_IGNORES.contains(&nom.as_str()) {
                ramasser(&chemin, racine, trouves);
            }
        } else if chemin.extension().and_then(|e| e.to_str()) == Some("rs")
            && let Ok(texte) = std::fs::read_to_string(&chemin)
        {
            let relatif = chemin
                .strip_prefix(racine)
                .unwrap_or(&chemin)
                .display()
                .to_string()
                .replace('\\', "/");
            trouves.push((relatif, texte));
        }
    }
}

/// Le source ou commentaires et litteraux sont remplaces par des espaces,
/// sauts de ligne gardes: memes positions, memes lignes, rien que du code.
fn code_seul(src: &str) -> Result<String, String> {
    let d = decouper(src)?;
    let mut o = src.as_bytes().to_vec();
    for (a, b) in d.neutres {
        for x in &mut o[a..b] {
            if *x != b'\n' {
                *x = b' ';
            }
        }
    }
    // Les octets remplaces sont ASCII; les autres sont ceux du source.
    Ok(String::from_utf8_lossy(&o).into_owned())
}

fn ligne_de(code: &str, pos: usize) -> usize {
    code[..pos].bytes().filter(|o| *o == b'\n').count() + 1
}

/// L'instruction qui contient `pos`: du `;`, `{` ou `}` precedent au `;`,
/// `{` ou `}` suivant.
fn instruction(code: &str, pos: usize) -> &str {
    let debut = code[..pos].rfind([';', '{', '}']).map_or(0, |k| k + 1);
    let fin = code[pos..]
        .find([';', '{', '}'])
        .map_or(code.len(), |k| pos + k);
    &code[debut..fin]
}

/// Fin (exclue) de la parenthese ouverte a `ouvrante`, ou `None`.
fn fin_de_parenthese(code: &str, ouvrante: usize) -> Option<usize> {
    let mut profondeur = 0usize;
    for (k, o) in code.bytes().enumerate().skip(ouvrante) {
        match o {
            b'(' => profondeur += 1,
            b')' => {
                profondeur -= 1;
                if profondeur == 0 {
                    return Some(k + 1);
                }
            }
            _ => {}
        }
    }
    None
}

/// Saute ce qui ne change pas la valeur d'un maillon de chaine: blancs,
/// `.await`, `?`, `.unwrap()`, `.expect(...)`. Rend la position suivante.
fn sauter_le_deballage(code: &str, mut k: usize) -> usize {
    loop {
        let reste = &code[k..];
        let blancs = reste.len() - reste.trim_start().len();
        if blancs > 0 {
            k += blancs;
            continue;
        }
        if let Some(r) = reste.strip_prefix('?') {
            k += reste.len() - r.len();
        } else if reste.starts_with(".await") {
            k += ".await".len();
        } else if reste.starts_with(".unwrap()") {
            k += ".unwrap()".len();
        } else if reste.starts_with(".expect(") {
            match fin_de_parenthese(code, k + ".expect".len()) {
                Some(f) => k = f,
                None => return k,
            }
        } else {
            return k;
        }
    }
}

/// Ce que la garde reproche a un source, ligne par ligne, et ce qu'elle a vu.
#[derive(Default)]
struct Releve {
    ecarts: Vec<(usize, String)>,
    temp_dir: usize,
    liaisons: usize,
}

fn examiner(chemin: &str, src: &str) -> Result<Releve, String> {
    let code = code_seul(src)?;
    let mut r = Releve::default();

    // Regle 1: les chemins temporaires.
    for (pos, _) in code.match_indices("temp_dir()") {
        r.temp_dir += 1;
        let instr = instruction(&code, pos);
        if instr.contains("process::id()") || instr.contains("etiquette_unique(") {
            continue;
        }
        let admis = TEMP_ADMIS
            .iter()
            .any(|(f, fragment, _)| *f == chemin && instr.contains(fragment));
        if !admis {
            r.ecarts.push((
                ligne_de(&code, pos),
                "`temp_dir()` sans `process::id()` ni `etiquette_unique(` dans \
                 l'instruction: deux executions concurrentes formeraient le meme \
                 chemin et s'effaceraient l'une l'autre"
                    .to_owned(),
            ));
        }
    }

    // Regle 2: les ecoutes relachees pour en tirer un numero.
    for motif in ["TcpListener::bind(", "UdpSocket::bind("] {
        for (pos, _) in code.match_indices(motif) {
            r.liaisons += 1;
            let ouvrante = pos + motif.len() - 1;
            let Some(fin) = fin_de_parenthese(&code, ouvrante) else {
                continue;
            };
            let suite = sauter_le_deballage(&code, fin);
            if code[suite..].starts_with(".local_addr()") {
                r.ecarts.push((
                    ligne_de(&code, pos),
                    format!(
                        "`local_addr()` enchaine sur `{motif}...)`: l'ecoute est un \
                         temporaire, relachee a la fin de l'instruction, et le numero \
                         rendu est a qui le demande. Tenir le port (`coeurs::port`)"
                    ),
                ));
                continue;
            }
            // `let [mut] nom = ...bind(` puis `drop(nom)` peu apres.
            let instr_debut = code[..pos].rfind([';', '{', '}']).map_or(0, |k| k + 1);
            let tete = code[instr_debut..pos].trim_start();
            let Some(apres_let) = tete.strip_prefix("let ") else {
                continue;
            };
            let apres_let = apres_let.trim_start();
            let apres_let = apres_let.strip_prefix("mut ").unwrap_or(apres_let);
            let nom: String = apres_let
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            if nom.is_empty() {
                continue;
            }
            let ligne = ligne_de(&code, pos);
            let voisinage: String = code
                .lines()
                .skip(ligne)
                .take(FENETRE_DROP)
                .collect::<Vec<_>>()
                .join("\n");
            let appel = format!("drop({nom})");
            if voisinage.contains(&appel) {
                r.ecarts.push((
                    ligne,
                    format!(
                        "`{nom}` est lie par `{motif}...)` puis passe a `{appel}` dans \
                         les {FENETRE_DROP} lignes: un numero de port relache, a qui le \
                         demande. Tenir le port (`coeurs::port`)"
                    ),
                ));
            }
        }
    }

    // Regle 3: un port tenu consomme sur place.
    for motif in PORTS_TENUS {
        for (pos, _) in code.match_indices(motif) {
            let colle = code[..pos]
                .chars()
                .next_back()
                .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_');
            if colle {
                continue;
            }
            let Some(fin) = fin_de_parenthese(&code, pos + motif.len() - 1) else {
                continue;
            };
            let suite = sauter_le_deballage(&code, fin);
            if code[suite..].starts_with(".port()") || code[suite..].starts_with(".adresse()") {
                r.ecarts.push((
                    ligne_de(&code, pos),
                    format!(
                        "`{motif})` consomme sur place: la valeur tombe a la fin de \
                         l'instruction, et avec elle le port qu'elle tenait. La garder \
                         dans une variable tant que l'adresse sert"
                    ),
                ));
            }
        }
    }
    Ok(r)
}

#[test]
fn aucune_execution_ne_partage_un_chemin_temporaire_ou_un_port_relache() {
    let racine = racine();
    let mut sources = Vec::new();
    ramasser(&racine.join("crates"), &racine, &mut sources);
    sources.sort();

    let mut ecarts = Vec::new();
    let (mut temp_dir, mut liaisons) = (0usize, 0usize);
    for (chemin, texte) in &sources {
        let r = examiner(chemin, texte).unwrap_or_else(|e| panic!("{chemin}: {e}"));
        temp_dir += r.temp_dir;
        liaisons += r.liaisons;
        for (ligne, motif) in r.ecarts {
            ecarts.push(format!("{chemin}:{ligne}: {motif}"));
        }
    }

    println!(
        "{} sources, {temp_dir} appels a temp_dir(), {liaisons} liaisons TCP/UDP vues",
        sources.len()
    );
    assert!(
        sources.len() > SEUIL_FICHIERS,
        "{} sources lues: le parcours ne lit plus le depot",
        sources.len()
    );
    assert!(
        temp_dir >= SEUIL_TEMP_DIR,
        "{temp_dir} appels a temp_dir() vus: la regle 1 ne regarde plus rien"
    );
    assert!(
        liaisons >= SEUIL_LIAISONS,
        "{liaisons} liaisons vues: la regle 2 ne regarde plus rien"
    );
    assert!(
        ecarts.is_empty(),
        "{} ecart(s):\n{}",
        ecarts.len(),
        ecarts.join("\n")
    );
}

/// Chaque exception nommee designe encore un site reel: une exception qui ne
/// couvre plus rien admettrait en silence le prochain site du meme fichier.
#[test]
fn chaque_exception_designe_un_site_reel() {
    let racine = racine();
    for (fichier, fragment, raison) in TEMP_ADMIS {
        let texte = std::fs::read_to_string(racine.join(fichier))
            .unwrap_or_else(|e| panic!("{fichier} illisible ({raison}): {e}"));
        let code = code_seul(&texte).unwrap();
        assert!(
            code.contains(fragment),
            "{fichier}: l'exception << {fragment} >> ne designe plus rien ({raison})"
        );
    }
}

/// Specification executable des trois regles, sur des sources ecrits ici.
#[test]
fn les_trois_regles_rougissent_sur_leur_forme_et_pas_a_cote() {
    fn lignes(src: &str) -> Vec<usize> {
        examiner("crates/essai/src/lib.rs", src)
            .unwrap()
            .ecarts
            .into_iter()
            .map(|(l, _)| l)
            .collect()
    }

    // Regle 1.
    assert_eq!(
        lignes("fn a() {\n    let p = std::env::temp_dir().join(\"fixe\");\n}\n"),
        vec![2],
        "un nom fixe sous temp_dir()"
    );
    assert_eq!(
        lignes(
            "fn a() {\n    let p = std::env::temp_dir().join(format!(\n        \"x-{}\",\n        std::process::id()\n    ));\n}\n"
        ),
        Vec::<usize>::new(),
        "le pid dans l'instruction, sur une autre ligne"
    );
    assert_eq!(
        lignes("fn a() {\n    let p = std::env::temp_dir().join(etiquette_unique(\"x\"));\n}\n"),
        Vec::<usize>::new()
    );
    assert_eq!(
        lignes("// let p = std::env::temp_dir().join(\"fixe\");\nfn a() {}\n"),
        Vec::<usize>::new(),
        "un commentaire n'est pas du code"
    );
    assert_eq!(
        lignes("fn a() {\n    let s = \"temp_dir()\";\n}\n"),
        Vec::<usize>::new(),
        "un litteral n'est pas du code"
    );
    assert_eq!(
        lignes(
            "fn a() {\n    let pid = std::process::id();\n    let p = std::env::temp_dir().join(format!(\"x-{pid}\"));\n}\n"
        ),
        vec![3],
        "angle mort nomme: le pid dans une variable n'est pas vu"
    );

    // Regle 2.
    assert_eq!(
        lignes(
            "fn a() -> u16 {\n    TcpListener::bind(\"127.0.0.1:0\").unwrap().local_addr().unwrap().port()\n}\n"
        ),
        vec![2],
        "l'ecoute temporaire"
    );
    assert_eq!(
        lignes(
            "fn a() -> io::Result<u16> {\n    Ok(TcpListener::bind(\"127.0.0.1:0\")?.local_addr()?.port())\n}\n"
        ),
        vec![2],
        "la forme exacte de port_sans_personne avant le 30/09/2026"
    );
    assert_eq!(
        lignes(
            "async fn a() {\n    let libre = TcpListener::bind(\"127.0.0.1:0\")\n        .await\n        .expect(\"un port (libre)\");\n    let api = libre.local_addr().unwrap();\n    drop(libre);\n}\n"
        ),
        vec![2],
        "liee, lue, puis relachee"
    );
    assert_eq!(
        lignes(
            "fn a() {\n    let ecoute = TcpListener::bind(\"127.0.0.1:0\").unwrap();\n    let adresse = ecoute.local_addr().unwrap();\n    servir(ecoute, adresse);\n}\n"
        ),
        Vec::<usize>::new(),
        "une ecoute gardee"
    );
    assert_eq!(
        lignes(
            "fn a() {\n    let s = UdpSocket::bind(\"127.0.0.1:0\").unwrap();\n    let p = s.local_addr().unwrap();\n    drop(s);\n}\n"
        ),
        vec![2],
        "la meme chose en UDP"
    );

    // Regle 3.
    assert_eq!(
        lignes("fn a() {\n    let p = port::port_sans_personne().unwrap().port();\n}\n"),
        vec![2],
        "un port tenu consomme sur place"
    );
    assert_eq!(
        lignes("fn a() {\n    let m = port_sans_personne()?.adresse();\n}\n"),
        vec![2]
    );
    assert_eq!(
        lignes(
            "fn a() {\n    let m = port::port_sans_personne().unwrap();\n    let p = m.port();\n}\n"
        ),
        Vec::<usize>::new(),
        "un port tenu garde dans une variable"
    );
    assert_eq!(
        lignes("fn a() {\n    let s = socks_fictif().adresse();\n}\n"),
        vec![2],
        "l'enveloppe de tests/coeurs.rs"
    );
    assert_eq!(
        lignes("fn a() {\n    let s = port_mort().port();\n}\n"),
        vec![2],
        "l'enveloppe de tests/vitalite.rs"
    );
    assert_eq!(
        lignes("fn a() {\n    let s = un_port_mort().port();\n}\n"),
        Vec::<usize>::new(),
        "un autre nom qui finit pareil n'est pas l'enveloppe"
    );
    assert_eq!(
        lignes(
            "fn socks_fictif() -> port::PortSansPersonne {\n    port::port_sans_personne().unwrap()\n}\n"
        ),
        Vec::<usize>::new(),
        "la definition de l'enveloppe"
    );
}
