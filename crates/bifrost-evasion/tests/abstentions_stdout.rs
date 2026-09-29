//! Une abstention ne s'ecrit JAMAIS sur stderr, et jamais avec un prefixe.
//!
//! # Pourquoi cette recette existe
//!
//! Le run 35278274527 (job Linux) a rougi a l'etape 8, le
//! budget d'abstention: une abstention attendue est sortie du journal sous la
//! forme `SKIPPED: nft --check exige des privileges (okkill switch: ...` au lieu
//! de `... (kill switch: ...)`. Le `ok\n` du harnais de `cargo test` (stdout)
//! s'etait glisse AU MILIEU du message, et la parenthese fermante etait perdue.
//!
//! La cause est de classe. Ce message passait par `eprintln!`, qui ecrit sur un
//! `Stderr` NON tamponne: chaque morceau du format part dans un `write` separe.
//! Sous `cargo test --workspace --no-fail-fast -- --nocapture > journal 2>&1`,
//! stdout et stderr atterrissent dans le MEME fichier; entre deux `write` de
//! stderr, le harnais a ecrit son `ok\n` sur stdout, et le message a ete
//! dechire. Le verrou de `Stderr` ne protege que des autres ecritures stderr.
//!
//! A l'inverse, `println!` ecrit sur un `Stdout` qui est un `LineWriter` sous
//! verrou reentrant: la ligne part au saut de ligne, en un seul morceau, et le
//! `ok` du harnais (stdout lui aussi, meme verrou) ne peut pas s'y intercaler.
//! La regle qui en sort, et que cette recette fait respecter: une abstention
//! s'imprime sur stdout, jamais sur stderr.
//!
//! Deja-vu: `5m'` (14/09/2026), classe alors ecrite comme << abstention stderr
//! instable >>, corrigee au coup par coup. Ici on ferme la classe entiere.
//!
//! # Ce qu'elle exige
//!
//! - Aucun `.rs` sous `crates/` n'emet une abstention `SKIPPED` par `eprint!`
//!   ou `eprintln!` (regle centrale, sur TOUT `crates/`, code de test comme code
//!   de production: le texte SKIPPED n'a rien a faire sur le stderr d'un binaire
//!   livre non plus).
//! - Dans le code de TEST (fichiers sous un repertoire `tests/`), une abstention
//!   imprimee par `print!`/`println!` COMMENCE la ligne: pas d'espace ni de
//!   prefixe avant `SKIPPED`, car `abstentions-budget.sh` lit des lignes qui
//!   commencent par `SKIPPED`. Ce controle est volontairement borne au code de
//!   test: le code de production (`src/`) affiche des sous-resultats indentes
//!   (`--wfp-selftest`, sondes de vecteurs) en `println!("  SKIPPED: ...")`, qui
//!   ne passent pas par le journal des recettes et restent legitimes; le
//!   perimetre de cette tranche ne les touche pas.
//! - Compte de controle: au moins 40 sites `println!("SKIPPED`/`print!("SKIPPED`.
//!   En dessous, le parcours est casse et le vert ne garderait rien.
//!
//! # Son perimetre et sa methode
//!
//! `crates/**/*.rs`, sur le disque (sans git: sur essai-linux le depot est copie
//! par `tar` et n'a pas de `.git`). CE fichier est exclu du parcours: il porte
//! les motifs interdits comme litteraux de sa propre logique et de son test de
//! classeur, il ne peut pas etre sa propre victime.

use std::path::{Path, PathBuf};

/// Chemin relatif (avec des `/`) de cette recette: exclue du parcours.
const GUARD_REL: &str = "crates/bifrost-evasion/tests/abstentions_stdout.rs";

/// Les repertoires que le parcours ne descend jamais.
const DOSSIERS_IGNORES: [&str; 2] = [".git", "target"];

/// Le seuil du compte de controle: le depot en porte une cinquantaine.
const SEUIL_CONTROLE: usize = 40;

fn racine() -> PathBuf {
    // Meme idiome que `sources_ascii.rs`: `CARGO_MANIFEST_DIR` pointe sur
    // crates/bifrost-evasion, la racine de l'espace de travail est deux crans
    // au-dessus.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("la racine de l'espace de travail doit exister")
        .to_path_buf()
}

/// Les quatre macros d'impression que l'on classe. L'ordre importe: on essaie
/// les noms les plus longs d'abord, mais le `!(` qui suit le nom suffit deja a
/// distinguer `print` de `println` et de `eprintln`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Genre {
    Print,
    Println,
    Eprint,
    Eprintln,
}

impl Genre {
    fn nom(self) -> &'static str {
        match self {
            Genre::Print => "print",
            Genre::Println => "println",
            Genre::Eprint => "eprint",
            Genre::Eprintln => "eprintln",
        }
    }

    /// Vrai pour les macros qui ecrivent sur stderr.
    fn sur_stderr(self) -> bool {
        matches!(self, Genre::Eprint | Genre::Eprintln)
    }
}

const NOMS: [(&str, Genre); 4] = [
    ("eprintln", Genre::Eprintln),
    ("eprint", Genre::Eprint),
    ("println", Genre::Println),
    ("print", Genre::Print),
];

/// Un appel de macro trouve sur une ligne: son genre, et le contenu du premier
/// litteral chaine s'il en porte un (les caracteres apres le `"` ouvrant,
/// jusqu'au `"` fermant sur la MEME ligne; les echappements sont gardes tels
/// quels, donc un `\n` source reste les deux caracteres `\` et `n`).
struct Appel {
    genre: Genre,
    contenu: Option<String>,
}

fn est_ident(octet: u8) -> bool {
    octet == b'_' || octet.is_ascii_alphanumeric()
}

/// Trouve les appels de macro d'impression sur une ligne.
///
/// Les sources du depot sont en ASCII (garde par `sources_ascii.rs`), donc un
/// parcours par octets est sur ici. Le nom doit etre precede d'une frontiere
/// (debut de ligne ou caractere non identifiant), sinon `eprintln!` serait lu
/// aussi comme `println!` (il le contient), et `sprint!` comme `print!`.
fn analyser_ligne(ligne: &str) -> Vec<Appel> {
    let b = ligne.as_bytes();
    let n = b.len();
    let mut appels = Vec::new();
    let mut i = 0usize;
    while i < n {
        let mut trouve: Option<(Genre, usize)> = None;
        for (nom, genre) in NOMS {
            let l = nom.len();
            if i + l < n && &b[i..i + l] == nom.as_bytes() && b[i + l] == b'!' {
                if i > 0 && est_ident(b[i - 1]) {
                    continue;
                }
                let mut j = i + l + 1;
                while j < n && (b[j] == b' ' || b[j] == b'\t') {
                    j += 1;
                }
                if j < n && b[j] == b'(' {
                    trouve = Some((genre, j + 1));
                    break;
                }
            }
        }
        if let Some((genre, apres_parenthese)) = trouve {
            let mut j = apres_parenthese;
            while j < n && (b[j] == b' ' || b[j] == b'\t') {
                j += 1;
            }
            let mut contenu = None;
            if j < n && b[j] == b'"' {
                let mut k = j + 1;
                let mut buf = String::new();
                while k < n {
                    let c = b[k];
                    if c == b'\\' && k + 1 < n {
                        buf.push(b[k] as char);
                        buf.push(b[k + 1] as char);
                        k += 2;
                        continue;
                    }
                    if c == b'"' {
                        break;
                    }
                    buf.push(c as char);
                    k += 1;
                }
                contenu = Some(buf);
            }
            appels.push(Appel { genre, contenu });
            i += genre.nom().len();
        } else {
            i += 1;
        }
    }
    appels
}

/// Le contenu prive d'un unique `\n` de tete (les deux caracteres `\` et `n`):
/// `println!("\nSKIPPED...")` imprime bien une ligne qui commence a SKIPPED.
fn tete_sans_saut(contenu: &str) -> &str {
    contenu.strip_prefix("\\n").unwrap_or(contenu)
}

/// La forme exacte comptee: le litteral commence par `SKIPPED` sans rien devant.
fn commence_par_skipped(contenu: &str) -> bool {
    contenu.starts_with("SKIPPED")
}

/// La ligne imprimee commencera par `SKIPPED` (apres un eventuel `\n` de tete).
fn debute_la_ligne(contenu: &str) -> bool {
    tete_sans_saut(contenu).starts_with("SKIPPED")
}

/// Un ou plusieurs espaces (ou tabulations) avant `SKIPPED`: le prefixe interdit
/// dans le code de test.
fn espace_puis_skipped(contenu: &str) -> bool {
    let tete = tete_sans_saut(contenu);
    let sans_espace = tete.trim_start_matches([' ', '\t']);
    sans_espace.len() != tete.len() && sans_espace.starts_with("SKIPPED")
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

#[test]
fn aucune_abstention_sur_stderr_ni_prefixee_dans_le_code_de_test() {
    // D'abord la specification du classeur: s'il ne distinguait plus les cas, le
    // parcours ci-dessous serait un vert qui ne garde rien.
    le_classeur_reconnait_les_formes_et_peut_rougir();

    let racine = racine();
    let mut fichiers = Vec::new();
    ramasser(&racine.join("crates"), &racine, &mut fichiers);

    // Controle positif du parcours: un lot vide passerait pour un succes sans
    // avoir rien lu.
    assert!(
        fichiers.len() > 100,
        "parcours casse: seulement {} source(s) Rust sous crates/",
        fichiers.len()
    );

    let mut violations = Vec::new();
    let mut compte = 0usize;

    for (rel, texte) in &fichiers {
        if rel == GUARD_REL {
            continue;
        }
        let dans_tests = rel.contains("/tests/");
        for (numero, ligne) in texte.lines().enumerate() {
            for appel in analyser_ligne(ligne) {
                let Some(contenu) = appel.contenu.as_deref() else {
                    continue;
                };
                if appel.genre.sur_stderr() {
                    if debute_la_ligne(contenu) || espace_puis_skipped(contenu) {
                        violations.push(format!(
                            "{rel}:{}: {}! ecrit une abstention SKIPPED sur stderr; une \
                             abstention s'imprime sur stdout (println!), que le journal \
                             merge sans la dechirer",
                            numero + 1,
                            appel.genre.nom()
                        ));
                    }
                } else if commence_par_skipped(contenu) {
                    compte += 1;
                } else if dans_tests && espace_puis_skipped(contenu) {
                    violations.push(format!(
                        "{rel}:{}: {}! imprime SKIPPED precede d'un espace/prefixe; le \
                         budget lit des lignes qui commencent par SKIPPED",
                        numero + 1,
                        appel.genre.nom()
                    ));
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "{} ecart(s) a la regle << une abstention s'ecrit sur stdout, d'un seul jet, \
         en tete de ligne >>:\n  {}",
        violations.len(),
        violations.join("\n  ")
    );
    assert!(
        compte >= SEUIL_CONTROLE,
        "compte de controle casse: {} site(s) println!(\"SKIPPED trouve(s), moins que \
         le seuil {}: le parcours ne lit plus le depot",
        compte,
        SEUIL_CONTROLE
    );
}

/// Specification executable du classeur, appelee par la recette principale (et
/// non un `#[test]` distinct, pour n'ajouter qu'UNE recette au compte). Elle
/// garantit que le classeur distingue reellement les cas, donc qu'il peut
/// rougir.
fn le_classeur_reconnait_les_formes_et_peut_rougir() {
    // Cette recette encode la frontiere entre ce qui est interdit et ce qui est
    // admis. Elle sert de specification executable et garantit que le classeur
    // n'est pas vide (il distingue reellement les cas).

    // eprint!/eprintln! qui portent une abstention: interdits.
    let a = analyser_ligne("        eprintln!(\"SKIPPED: motif\");");
    assert_eq!(a.len(), 1);
    assert_eq!(a[0].genre, Genre::Eprintln);
    assert!(debute_la_ligne(a[0].contenu.as_deref().unwrap()));

    let a = analyser_ligne("    eprint!(\"SKIPPED sans ln\");");
    assert_eq!(a[0].genre, Genre::Eprint);
    assert!(debute_la_ligne(a[0].contenu.as_deref().unwrap()));

    // println!("SKIPPED...): la forme normale, comptee, jamais un ecart.
    let a = analyser_ligne("    println!(\"SKIPPED: {raison}\");");
    assert_eq!(a[0].genre, Genre::Println);
    let c = a[0].contenu.as_deref().unwrap();
    assert!(commence_par_skipped(c));
    assert!(!espace_puis_skipped(c));

    // Un \n de tete puis SKIPPED: la ligne imprimee commence bien a SKIPPED.
    // Admise (cf. veille_linux.rs), et non comptee dans les 40 (c'est voulu).
    let c = analyser_ligne("    println!(\"\\nSKIPPED: {e}\");")[0]
        .contenu
        .clone()
        .unwrap();
    assert!(debute_la_ligne(&c));
    assert!(!espace_puis_skipped(&c));
    assert!(!commence_par_skipped(&c));

    // Un espace avant SKIPPED: le prefixe interdit dans le code de test.
    let c = analyser_ligne("    println!(\"  SKIPPED: x\");")[0]
        .contenu
        .clone()
        .unwrap();
    assert!(espace_puis_skipped(&c));
    assert!(!commence_par_skipped(&c));

    // Un prefixe textuel apres un \n (affichage de production, hors classe):
    // ni compte, ni prefixe d'espace.
    let c = analyser_ligne("    println!(\"\\n{v}: SKIPPED - {r}\");")[0]
        .contenu
        .clone()
        .unwrap();
    assert!(!debute_la_ligne(&c));
    assert!(!espace_puis_skipped(&c));

    // Frontiere: println! n'est PAS reconnu a l'interieur d'eprintln!.
    let a = analyser_ligne("    eprintln!(\"SKIPPED\");");
    assert_eq!(
        a.len(),
        1,
        "eprintln! ne doit pas compter aussi comme println!"
    );
    assert_eq!(a[0].genre, Genre::Eprintln);

    // Une mention de SKIPPED hors macro d'impression n'est pas un appel.
    assert!(analyser_ligne("        assert!(s.contains(\"SKIPPED\"));").is_empty());
}
