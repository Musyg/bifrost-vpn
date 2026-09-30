//! Aucun litteral chaine ne porte la trace d'un antislash mange en route.
//!
//! # Pourquoi cette recette existe
//!
//! Du 17/08 au 14/09/2026, des sources de ce depot ont ete ecrites par un outil
//! qui transportait le texte en interpretant ses antislashs: `\n` arrivait en
//! vrai saut de ligne, et une continuation `\` de fin de ligne disparaissait
//! avec son saut. Rust accepte un saut de ligne dans une chaine, donc tout a
//! compile, et rien n'a rougi. Releve du 30/09/2026 sur `inspecter_le_tls`
//! (`crates/bifrost-cli/src/main.rs`): la sortie humaine d'une interception
//! portait une vingtaine d'espaces au milieu d'une phrase, << du dernier
//! (22 espaces) certificat >>. Le meme releve, sur tout `crates/`, a trouve
//! neuf litteraux soudes de cette facon (onze soudures, sept fichiers), deux
//! litteraux dont les sauts de ligne avaient garde l'indentation du source
//! (huit sauts; l'un changeait le corps d'une fixture de recette), et
//! vingt-cinq litteraux ou trente et un `\n` etaient devenus de vrais sauts de
//! ligne.
//!
//! `caracteres_de_controle.rs` garde les echappements devenus octets de
//! controle (`\b`, `\1`, `\t`). Celle-ci garde ce que le meme transport fait
//! des sauts de ligne, et qui n'est fait que d'espaces.
//!
//! # La colonne de continuation, et pourquoi pas un seuil fixe
//!
//! C est la colonne du guillemet ouvrant plus un: la colonne sous laquelle le
//! depot aligne le texte de ses lignes de continuation. Mesure du 30/09/2026:
//! 1026 lignes de continuation sur 1046 y sont exactement; les autres sont des
//! fixtures qui repartent en colonne 0 et des lignes de tableau.
//!
//! Quand le transport mange `\` et son saut, ce qui reste de la ligne suivante
//! est son indentation, donc C blancs, plus un si un espace precedait `\`.
//! Toutes les soudures relevees font exactement C + 1. Un seuil fixe N ne
//! separe rien: les sauts de ligne reels legitimes du depot sont suivis de 2 a
//! 17 blancs (workflow YAML d'une fixture: 10; avertissement a retrait
//! suspendu: 15 et 17), les abimes de 9 et 13. La colonne C, elle, les separe
//! tous: aucun cas legitime ne tombe sur C ou C + 1.
//!
//! # Ce qu'elle refuse, dans un litteral NON brut de `crates/**/*.rs`
//!
//! 1. Une SOUDURE: une suite de C ou C + 1 espaces au milieu d'une ligne
//!    (precedee et suivie d'un autre caractere): `\` et son saut ont ete
//!    manges, l'indentation de la ligne suivante est entree dans la phrase.
//! 2. Un SAUT GARDE: un saut de ligne reel (non precede de `\`) suivi de C ou
//!    C + 1 espaces: `\n\` a perdu son `\`, et l'indentation du source est
//!    entree dans la valeur.
//! 3. Un litteral qui COMMENCE par un saut de ligne reel (guillemet ouvrant en
//!    fin de ligne): `"\n...` dont l'echappement a ete mange. Le depot ecrit
//!    `"\n` ou `"\` (continuation) pour cela, et une fixture multiligne
//!    commence par `"\`.
//!
//! # Ce qu'elle ne voit pas
//!
//! - Un `\n` mange au milieu ou en fin de texte, sans blanc derriere: la valeur
//!   est celle qui etait voulue, et la forme ne se distingue pas d'une fixture
//!   multiligne volontaire (certificat PEM, `/proc/net/route`, sortie netsh).
//! - Une continuation mangee dont la ligne suivante n'etait pas alignee en C.
//! - Un `\\` replie en `\` qui reste un echappement valide (`\\n` devenu
//!   `\n`): indecidable sans l'original.
//! - Les chaines brutes: elles n'ont ni echappement ni continuation, un saut
//!   de ligne y est toujours voulu.
//!
//! Le parcours se fait sur le disque, sans git, comme ses voisines: sur
//! l'hote Linux d'essai le depot peut etre une copie sans `.git`.

#[path = "commun/lexeur_rust.rs"]
mod lexeur_rust;

use lexeur_rust::{Litteral, decouper};
use std::path::{Path, PathBuf};

/// Les repertoires que le parcours ne descend jamais.
const DOSSIERS_IGNORES: [&str; 2] = [".git", "target"];

/// Compte de controle des lignes de continuation alignees en C. Le depot en
/// porte plus de mille; en dessous de ce seuil, soit le parcours ne lit plus
/// le depot, soit la convention sur laquelle repose la regle a change, et
/// dans les deux cas le vert ne garderait rien.
const SEUIL_CONTINUATIONS_EN_C: usize = 500;

fn racine() -> PathBuf {
    // Meme idiome que `caracteres_de_controle.rs` et ses voisines:
    // `CARGO_MANIFEST_DIR` pointe sur crates/bifrost-evasion, la racine de
    // l'espace de travail est deux crans au-dessus.
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

/// Espaces de tete d'une ligne physique.
fn espaces_de_tete(ligne: &str) -> usize {
    ligne.bytes().take_while(|o| *o == b' ').count()
}

/// Nombre d'antislashs consecutifs en fin de ligne. Impair: la ligne se
/// termine par une continuation; pair (zero compris): le saut qui suit est un
/// vrai saut de ligne du litteral.
fn antislashs_finaux(ligne: &str) -> usize {
    ligne.bytes().rev().take_while(|o| *o == b'\\').count()
}

/// Ce qu'un litteral porte de la forme d'un antislash mange: pour chaque
/// defaut, le decalage de ligne dans le litteral et le motif. Les chaines
/// brutes n'en portent jamais.
fn defauts(lit: &Litteral) -> Vec<(usize, String)> {
    let mut sortie = Vec::new();
    if lit.brut {
        return sortie;
    }
    let c = lit.colonne + 1;
    let lignes: Vec<&str> = lit
        .corps
        .split('\n')
        .map(|l| l.strip_suffix('\r').unwrap_or(l))
        .collect();
    for (k, ligne) in lignes.iter().enumerate() {
        let saut_reel = k > 0 && antislashs_finaux(lignes[k - 1]).is_multiple_of(2);
        if saut_reel {
            if k == 1 && lignes[0].is_empty() {
                // Signale a la ligne du guillemet ouvrant.
                sortie.push((
                    0,
                    "le litteral commence par un saut de ligne reel: un `\"\\n` \
                     dont l'antislash a ete mange (ecrire `\"\\n` ou `\"\\` en fin de ligne)"
                        .to_string(),
                ));
            }
            let tete = espaces_de_tete(ligne);
            if tete == c || tete == c + 1 {
                sortie.push((
                    k,
                    format!(
                        "saut de ligne reel suivi de {tete} espaces, la colonne de \
                         continuation (C = {c}): un `\\n\\` dont le `\\` a ete mange, \
                         l'indentation du source est entree dans la valeur"
                    ),
                ));
            }
        }
        // Apres une continuation, rustc saute les blancs de tete: ils ne font
        // pas partie de la valeur. Ailleurs, les blancs de tete sont l'affaire
        // de la regle du saut garde ci-dessus.
        let texte = if k > 0 && !saut_reel {
            ligne.trim_start_matches([' ', '\t'])
        } else {
            ligne
        };
        let o = texte.as_bytes();
        let mut j = 0usize;
        while j < o.len() {
            if o[j] != b' ' {
                j += 1;
                continue;
            }
            let a = j;
            while j < o.len() && o[j] == b' ' {
                j += 1;
            }
            let longueur = j - a;
            if a > 0 && j < o.len() && (longueur == c || longueur == c + 1) {
                sortie.push((
                    k,
                    format!(
                        "{longueur} espaces soudes au milieu d'une ligne, la colonne de \
                         continuation (C = {c}): un `\\` de fin de ligne a ete mange avec \
                         son saut, l'indentation de la ligne suivante est dans la phrase"
                    ),
                ));
            }
        }
    }
    sortie
}

/// Nombre de lignes de continuation d'un litteral non brut dont le texte
/// commence exactement en C: le compte de controle de la convention.
fn continuations_en_c(lit: &Litteral) -> usize {
    if lit.brut {
        return 0;
    }
    let c = lit.colonne + 1;
    let lignes: Vec<&str> = lit.corps.split('\n').collect();
    (1..lignes.len())
        .filter(|&k| {
            let prec = lignes[k - 1].strip_suffix('\r').unwrap_or(lignes[k - 1]);
            !antislashs_finaux(prec).is_multiple_of(2) && espaces_de_tete(lignes[k]) == c
        })
        .count()
}

/// Les defauts d'un source entier, en `(ligne, motif)`.
fn defauts_du_source(src: &str) -> Result<Vec<(usize, String)>, String> {
    let decoupe = decouper(src)?;
    let mut sortie = Vec::new();
    for lit in &decoupe.litteraux {
        for (k, motif) in defauts(lit) {
            sortie.push((lit.ligne + k, motif));
        }
    }
    Ok(sortie)
}

#[test]
fn aucun_litteral_ne_porte_un_antislash_mange() {
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
    let mut non_bruts = 0usize;
    let mut en_c = 0usize;
    for (rel, texte) in &fichiers {
        let decoupe = match decouper(texte) {
            Ok(d) => d,
            Err(e) => {
                violations.push(format!("{rel}: illisible pour le lexeur ({e})"));
                continue;
            }
        };
        for lit in &decoupe.litteraux {
            if !lit.brut {
                non_bruts += 1;
            }
            en_c += continuations_en_c(lit);
            for (k, motif) in defauts(lit) {
                violations.push(format!("{rel}:{}: {motif}", lit.ligne + k));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "{} trace(s) d'antislash mange dans des litteraux. Rust accepte un saut de \
         ligne dans une chaine, donc cela compile et ne rougit nulle part ailleurs:\n  {}",
        violations.len(),
        violations.join("\n  ")
    );
    assert!(
        non_bruts > 5000,
        "compte de controle casse: {non_bruts} litteral(aux) non brut(s), le lexeur ne \
         lit plus le depot"
    );
    assert!(
        en_c >= SEUIL_CONTINUATIONS_EN_C,
        "compte de controle casse: {en_c} ligne(s) de continuation alignee(s) en C, \
         moins que {SEUIL_CONTINUATIONS_EN_C}. La regle suppose cette convention: si \
         elle a change, la colonne C ne designe plus la trace d'une continuation"
    );
}

/// Le source d'une fonction qui passe `corps` a `println!`, le guillemet
/// ouvrant en colonne 8: la colonne de continuation y vaut donc 9.
fn source_println(corps: &str) -> String {
    let marge = " ".repeat(8);
    format!("fn f() {{\n    println!(\n{marge}\"{corps}\"\n    );\n}}\n")
}

/// C pour `source_println`.
const C: usize = 9;

/// Les motifs trouves dans un source, sans les lignes.
fn motifs(src: &str) -> Vec<String> {
    defauts_du_source(src)
        .expect("source lisible")
        .into_iter()
        .map(|(_, m)| m)
        .collect()
}

#[test]
fn le_detecteur_reconnait_chaque_forme_et_ses_voisines() {
    let blancs = |n: usize| " ".repeat(n);

    // 1. Soudure: C + 1 (un espace avant le `\` mange, la forme relevee) et C.
    let m = motifs(&source_println(&format!("debut{}suite", blancs(C + 1))));
    assert_eq!(m.len(), 1, "{m:?}");
    assert!(m[0].contains("soudes"), "{m:?}");
    let m = motifs(&source_println(&format!("debut{}suite", blancs(C))));
    assert_eq!(m.len(), 1, "{m:?}");
    // Hors de la signature: un tableau aligne, une suite d'une autre longueur.
    assert!(motifs(&source_println(&format!("debut{}suite", blancs(C + 2)))).is_empty());
    assert!(motifs(&source_println(&format!("cle{}: valeur", blancs(4)))).is_empty());

    // 2. La continuation correcte, qui DOIT rester verte: `\`, saut, C blancs.
    let correcte = source_println(&format!("debut \\\n{}suite", blancs(C)));
    assert!(motifs(&correcte).is_empty(), "{:?}", motifs(&correcte));
    // Et `\n\` correct: l'echappement, puis la continuation.
    let n_continue = source_println(&format!("ligne un\\n\\\n{}ligne deux", blancs(C)));
    assert!(motifs(&n_continue).is_empty());
    // Deux antislashs en fin de ligne: un antislash echappe, puis un VRAI saut.
    let echappe = source_println(&format!("a\\\\\n{}b", blancs(C)));
    assert_eq!(motifs(&echappe).len(), 1, "{:?}", motifs(&echappe));

    // 3. Saut garde: un saut reel suivi de C ou C + 1 espaces.
    let m = motifs(&source_println(&format!(
        "ligne un\n{}ligne deux",
        blancs(C)
    )));
    assert_eq!(m.len(), 1, "{m:?}");
    assert!(m[0].contains("saut de ligne reel suivi"), "{m:?}");
    assert_eq!(
        motifs(&source_println(&format!("un\n{}deux", blancs(C + 1)))).len(),
        1
    );
    // Un saut reel suivi d'un retrait voulu (fixture YAML, retrait suspendu).
    assert!(motifs(&source_println(&format!("un\n{}deux", blancs(4)))).is_empty());
    assert!(motifs(&source_println(&format!("un\n{}deux", blancs(15)))).is_empty());
    // Un saut reel en colonne 0, au milieu: hors de portee (voir l'en-tete).
    assert!(motifs(&source_println("un\ndeux")).is_empty());

    // 4. Un litteral qui commence par un saut reel.
    let m = motifs(&source_println("\nmitm_tls = false"));
    assert_eq!(m.len(), 1, "{m:?}");
    assert!(m[0].contains("commence par un saut"), "{m:?}");
    assert!(motifs(&source_println("\\nmitm_tls = false")).is_empty());
    assert!(motifs(&source_println("\\\nfixture en colonne zero\n")).is_empty());

    // 5. Les variantes syntaxiques ou la meme forme est LEGITIME.
    //    Chaine brute: ni echappement ni continuation, rien a manger. Le
    //    guillemet y est en colonne 13 (C = 14), comme celui du temoin non
    //    brut juste apres, qui porte les memes blancs et doit rougir deux fois.
    let corps = format!("un\n{}deux{}trois", blancs(14), blancs(15));
    let brute = format!("fn f() {{\n    let x = r\"{corps}\";\n}}\n");
    assert!(motifs(&brute).is_empty(), "{:?}", motifs(&brute));
    let temoin = format!("fn f() {{\n    let x =  \"{corps}\";\n}}\n");
    assert_eq!(motifs(&temoin).len(), 2, "{:?}", motifs(&temoin));
    let brute_dieses = format!(
        "fn f() {{\n    let x = r#\"un \"cite\"\n{}deux\"#;\n}}\n",
        blancs(15)
    );
    assert!(motifs(&brute_dieses).is_empty());
    assert_eq!(
        decouper(&brute_dieses).expect("lisible").litteraux.len(),
        1,
        "un guillemet dans une chaine brute a dieses ne la ferme pas"
    );
    //    Commentaires: un guillemet dans un commentaire n'ouvre rien.
    let commentaire = format!(
        "fn f() {{\n    // un guillemet \" ouvre ici{}rien\n    let x = 1;\n    /* et \"la\n{}non plus\" */\n}}\n",
        blancs(9),
        blancs(9)
    );
    let d = decouper(&commentaire).expect("lisible");
    assert!(d.litteraux.is_empty(), "{:?}", d.litteraux);
    for guillemet in commentaire.match_indices('"').map(|(p, _)| p) {
        assert!(
            d.zone_neutre(guillemet).is_some(),
            "le guillemet a l'octet {guillemet} est dans un commentaire"
        );
    }
    //    concat!: le saut et les blancs sont ENTRE deux litteraux.
    let concat = format!(
        "fn f() {{\n    let x = concat!(\n        \"a \",\n{}\"b\"\n    );\n}}\n",
        blancs(9)
    );
    assert!(motifs(&concat).is_empty());
    let d = decouper(&concat).expect("lisible");
    let second = concat.rfind("\"b\"").expect("le second litteral");
    assert_eq!(
        d.litteral_a(second).map(|l| l.corps.as_str()),
        Some("b"),
        "{:?}",
        d.litteraux
    );
    assert!(
        d.zone_neutre(second - 1).is_none(),
        "les blancs sont du code"
    );

    // 6. Le lexeur ne se desynchronise pas: un `'"'` n'ouvre pas de chaine, et
    //    la soudure qui suit est trouvee a SA ligne.
    let caractere = format!(
        "fn f() {{\n    let q = '\"';\n    let e = '\\'';\n    let s = \"a{}b\";\n}}\n",
        blancs(13)
    );
    let d = defauts_du_source(&caractere).expect("lisible");
    assert_eq!(d.len(), 1, "{d:?}");
    assert_eq!(d[0].0, 4, "la soudure est a la ligne 4: {d:?}");
    //    Lifetimes et etiquettes ne sont pas des caracteres.
    let vie = format!(
        "fn f<'a>(x: &'a str) {{\n    'boucle: loop {{ break 'boucle; }}\n    let s = \"a{}b\";\n}}\n",
        blancs(13)
    );
    assert_eq!(defauts_du_source(&vie).expect("lisible").len(), 1);
    //    Chaine d'octets et chaine C: non brutes, donc gardees.
    let octets = format!("fn f() {{\n    let s = b\"a{}b\";\n}}\n", blancs(14));
    assert_eq!(motifs(&octets).len(), 1);

    // 7. L'occurrence reelle, telle que `inspecter_le_tls` la portait.
    let d = defauts_du_source(OCCURRENCE_REELLE).expect("lisible");
    let lignes: Vec<usize> = d.iter().map(|(l, _)| *l).collect();
    assert_eq!(lignes, vec![2, 6, 7], "{d:?}");
}

/// Les lignes 605 a 607, 612 a 616 et 624 de `crates/bifrost-cli/src/main.rs`
/// au commit 852aff4, octet pour octet. Chaine brute: cette recette se lit
/// elle-meme sans s'y prendre.
const OCCURRENCE_REELLE: &str = r#"                Chaine::Etrangere { empreinte } => println!(
                    "{nom}: chaine ancree HORS du jeu public; empreinte SHA-256 du dernier                      certificat presente: {empreinte}"
                ),
        match verdict {
            Mesure::Vu(true) => println!(
                "
mitm_tls = true: quelqu'un dechiffre le TLS qui sort d'ici.                  Comparez l'empreinte ci-dessus a celle de votre autorite interne."
            ),
        }
"#;
