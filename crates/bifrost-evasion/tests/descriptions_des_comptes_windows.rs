//! Toute description qu'un script PowerShell du depot donne a un groupe ou a
//! un compte local tient dans la borne que Windows applique: 48 caracteres.
//!
//! # Pourquoi cette recette existe
//!
//! `packaging/install-windows.ps1` creait le groupe d'acces du canal par
//! `New-LocalGroup` avec une description de 100 caracteres. La commande refuse
//! une description de plus de 48 caracteres, quand sa documentation en annonce
//! 256: mesure le 18/10/2026 sur une machine virtuelle Windows Server 2025
//! jetable, PowerShell 7.6.6. Le script s'arretait donc avant de creer le
//! groupe et d'enregistrer le service, sur toute machine ou le groupe
//! n'existait pas encore. Il ne tourne qu'en administrateur, sur une machine
//! qu'on peut perdre: aucune recette ne l'execute, et rien ne l'avait vu.
//!
//! # Ce qu'elle exige
//!
//! Elle lit chaque `.ps1` de `packaging/` et de `scripts/`, sur le disque et
//! sans git: sur essai-linux le depot est copie par `tar` et n'a pas de
//! `.git`. Pour chaque appel a `New-LocalGroup` ou `New-LocalUser` qui porte
//! `-Description`, elle exige un litteral entre guillemets, sur la ligne de
//! l'appel, dont la longueur ne depasse pas 48 caracteres apres developpement
//! des seules variables affectees par un litteral simple dans le meme script:
//! la forme `$Nom = '<texte>'`, en colonne 0, une seule ecriture de la
//! variable dans tout le script, avant l'appel.
//!
//! # Une grammaire fermee
//!
//! Ce qui sort de cette forme rougit en se nommant, au lieu d'etre ignore:
//! une variable qui n'a pas d'affectation, ou plus d'une ecriture (une
//! seconde affectation, `+=`, un parametre, une boucle, `[ref]`, une commande
//! `*-Variable`), ou une affectation qui n'est pas un litteral simple; une
//! description qui n'est pas un litteral (variable nue, parentheses,
//! concatenation, `$(...)`, `$env:`, accent grave, guillemet double echappe);
//! un parametre abrege (`-Desc`) ou colle a sa valeur (`-Description:`); un
//! appel qui continue sur la ligne suivante (accent grave en fin de ligne,
//! parenthese ou chaine ouverte); un eclatement (`@params`) qui pourrait
//! porter la description; le nom de la commande dans une chaine, ou ailleurs
//! qu'en position de commande. Un script qui charge un autre fichier (`. x`,
//! `Import-Module`, `using module`) ne peut plus developper de variable: elle
//! viendrait d'ailleurs.
//!
//! # Ce qu'elle ne fait pas
//!
//! Elle n'execute aucun script: le seul juge de la borne est Windows, et la
//! valeur 48 vient de la mesure ci-dessus, pas d'une documentation. Son
//! lecteur de PowerShell ne connait que ce dont la garde a besoin: les
//! chaines simples et doubles, les here-strings, les commentaires de ligne et
//! de bloc. Une sous-expression `$(...)` qui contient elle-meme des
//! guillemets, dans une chaine double, n'y est pas suivie; un `#` qui
//! n'est precede ni d'un blanc ni d'un debut de ligne n'ouvre pas de
//! commentaire a ses yeux, de sorte qu'une lecture approximative rend du code
//! en plus a examiner, jamais du code en moins.

use std::path::{Path, PathBuf};

fn racine() -> PathBuf {
    // Meme idiome que `filet_service_parametre.rs` et ses voisines:
    // `CARGO_MANIFEST_DIR` pointe sur crates/bifrost-evasion, la racine de
    // l'espace de travail est deux crans au-dessus.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("la racine de l'espace de travail doit exister")
        .to_path_buf()
}

/// La plus longue description que `New-LocalGroup` accepte, mesuree.
const BORNE: usize = 48;

/// Les commandes qui creent un groupe ou un compte local avec une description.
const COMMANDES: [&str; 2] = ["New-LocalGroup", "New-LocalUser"];

/// Les dossiers lus, relatifs a la racine.
const DOSSIERS: [&str; 2] = ["packaging", "scripts"];

/// Les scripts PowerShell des dossiers lus, tries.
fn scripts() -> Vec<PathBuf> {
    let mut trouves = Vec::new();
    for dossier in DOSSIERS {
        let chemin = racine().join(dossier);
        let entrees = std::fs::read_dir(&chemin)
            .unwrap_or_else(|e| panic!("{} illisible: {e}", chemin.display()));
        for entree in entrees.flatten() {
            let p = entree.path();
            let ps1 = p
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| e.eq_ignore_ascii_case("ps1"));
            if ps1 && p.is_file() {
                trouves.push(p);
            }
        }
    }
    trouves.sort();
    trouves
}

// ---------------------------------------------------------------------------
// Lecture du PowerShell: chaque caractere recoit sa classe.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Classe {
    Code,
    Chaine,
    Commentaire,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Etat {
    Code,
    Simple,
    Double,
    IciSimple,
    IciDouble,
    Bloc,
}

struct Ligne {
    /// Numero de ligne, a partir de 1.
    numero: usize,
    car: Vec<char>,
    classes: Vec<Classe>,
    /// Une chaine reste ouverte a la fin de la ligne.
    chaine_ouverte: bool,
}

struct Script {
    nom: String,
    lignes: Vec<Ligne>,
}

fn blanc(c: char) -> bool {
    c == ' ' || c == '\t'
}

fn ident(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// Classe chaque caractere du texte. Les fins de ligne `\r` sont otees: un
/// arbre de travail en CRLF se lit comme le depot en LF.
fn lire_script(nom: &str, texte: &str) -> Script {
    let mut etat = Etat::Code;
    let mut lignes = Vec::new();
    for (rang, brute) in texte.split('\n').enumerate() {
        let car: Vec<char> = brute.strip_suffix('\r').unwrap_or(brute).chars().collect();
        let mut classes = vec![Classe::Code; car.len()];
        let mut i = 0;
        if matches!(etat, Etat::IciSimple | Etat::IciDouble) {
            let fin = if etat == Etat::IciSimple { '\'' } else { '"' };
            if car.first() == Some(&fin) && car.get(1) == Some(&'@') {
                classes[0] = Classe::Chaine;
                classes[1] = Classe::Chaine;
                i = 2;
                etat = Etat::Code;
            } else {
                classes.fill(Classe::Chaine);
                i = car.len();
            }
        }
        while i < car.len() {
            let c = car[i];
            match etat {
                Etat::Bloc => {
                    classes[i] = Classe::Commentaire;
                    if c == '#' && car.get(i + 1) == Some(&'>') {
                        classes[i + 1] = Classe::Commentaire;
                        i += 1;
                        etat = Etat::Code;
                    }
                }
                Etat::Simple => {
                    classes[i] = Classe::Chaine;
                    if c == '\'' {
                        if car.get(i + 1) == Some(&'\'') {
                            classes[i + 1] = Classe::Chaine;
                            i += 1;
                        } else {
                            etat = Etat::Code;
                        }
                    }
                }
                Etat::Double => {
                    classes[i] = Classe::Chaine;
                    if c == '`' && i + 1 < car.len() {
                        classes[i + 1] = Classe::Chaine;
                        i += 1;
                    } else if c == '"' {
                        if car.get(i + 1) == Some(&'"') {
                            classes[i + 1] = Classe::Chaine;
                            i += 1;
                        } else {
                            etat = Etat::Code;
                        }
                    }
                }
                Etat::IciSimple | Etat::IciDouble => unreachable!("traite en tete de ligne"),
                Etat::Code => {
                    let precedent = if i == 0 { None } else { Some(car[i - 1]) };
                    let debut_de_mot = precedent.is_none_or(|p| blanc(p) || ";|(){}".contains(p));
                    let reste_blanc = car[i + 1..].iter().skip(1).all(|&x| blanc(x));
                    if c == '<' && car.get(i + 1) == Some(&'#') {
                        classes[i] = Classe::Commentaire;
                        classes[i + 1] = Classe::Commentaire;
                        i += 1;
                        etat = Etat::Bloc;
                    } else if c == '#' && debut_de_mot {
                        classes[i..].fill(Classe::Commentaire);
                        i = car.len();
                        continue;
                    } else if c == '@' && matches!(car.get(i + 1), Some('\'' | '"')) && reste_blanc
                    {
                        classes[i] = Classe::Chaine;
                        classes[i + 1] = Classe::Chaine;
                        etat = if car[i + 1] == '\'' {
                            Etat::IciSimple
                        } else {
                            Etat::IciDouble
                        };
                        i = car.len();
                        continue;
                    } else if c == '\'' {
                        classes[i] = Classe::Chaine;
                        etat = Etat::Simple;
                    } else if c == '"' {
                        classes[i] = Classe::Chaine;
                        etat = Etat::Double;
                    } else if c == '`' && i + 1 < car.len() {
                        // L'accent grave echappe le caractere suivant, qui
                        // reste du code: `" n'ouvre pas de chaine.
                        i += 1;
                    }
                }
            }
            i += 1;
        }
        let chaine_ouverte = matches!(
            etat,
            Etat::Simple | Etat::Double | Etat::IciSimple | Etat::IciDouble
        );
        lignes.push(Ligne {
            numero: rang + 1,
            car,
            classes,
            chaine_ouverte,
        });
    }
    Script {
        nom: nom.to_string(),
        lignes,
    }
}

/// Les occurrences de `motif` dans `car`, sans egard a la casse.
fn occurrences(car: &[char], motif: &str) -> Vec<usize> {
    let m: Vec<char> = motif.chars().collect();
    if m.is_empty() || car.len() < m.len() {
        return Vec::new();
    }
    (0..=car.len() - m.len())
        .filter(|&i| {
            car[i..i + m.len()]
                .iter()
                .zip(&m)
                .all(|(a, b)| a.eq_ignore_ascii_case(b))
        })
        .collect()
}

fn texte(car: &[char]) -> String {
    car.iter().collect()
}

// ---------------------------------------------------------------------------
// Les ecritures d'une variable.
// ---------------------------------------------------------------------------

/// Les regions de parametres du script: le contenu de chaque `param(...)` et
/// de chaque `function Nom (...)`, en (ligne, colonne) de debut et de fin.
fn regions_de_parametres(s: &Script) -> Vec<((usize, usize), (usize, usize))> {
    // Le code seul, aplati, avec sa position.
    let mut code: Vec<(usize, usize, char)> = Vec::new();
    for (l, ligne) in s.lignes.iter().enumerate() {
        for (c, (&x, &k)) in ligne.car.iter().zip(&ligne.classes).enumerate() {
            if k == Classe::Code {
                code.push((l, c, x));
            }
        }
        code.push((l, ligne.car.len(), '\n'));
    }
    let bas: Vec<char> = code.iter().map(|t| t.2.to_ascii_lowercase()).collect();
    let mot_a = |i: usize, mot: &str| -> bool {
        let m: Vec<char> = mot.chars().collect();
        i + m.len() <= bas.len()
            && bas[i..i + m.len()] == m[..]
            && (i == 0 || !(ident(bas[i - 1]) || bas[i - 1] == '-' || bas[i - 1] == '$'))
            && bas.get(i + m.len()).is_none_or(|&c| !ident(c) && c != '-')
    };
    let mut regions = Vec::new();
    let mut i = 0;
    while i < bas.len() {
        let mut ouvrante = None;
        if mot_a(i, "param") {
            let mut j = i + 5;
            while j < bas.len() && (blanc(bas[j]) || bas[j] == '\n') {
                j += 1;
            }
            if bas.get(j) == Some(&'(') {
                ouvrante = Some(j);
            }
        } else if let Some(mot) = ["function", "filter"].into_iter().find(|m| mot_a(i, m)) {
            let mut j = i + mot.len();
            while j < bas.len() && blanc(bas[j]) {
                j += 1;
            }
            while j < bas.len() && (ident(bas[j]) || bas[j] == '-' || bas[j] == ':') {
                j += 1;
            }
            while j < bas.len() && blanc(bas[j]) {
                j += 1;
            }
            if bas.get(j) == Some(&'(') {
                ouvrante = Some(j);
            }
        }
        if let Some(o) = ouvrante {
            let mut profondeur = 0usize;
            let mut k = o;
            while k < bas.len() {
                match bas[k] {
                    '(' => profondeur += 1,
                    ')' => {
                        profondeur -= 1;
                        if profondeur == 0 {
                            break;
                        }
                    }
                    _ => {}
                }
                k += 1;
            }
            let fin = code.get(k).or(code.last()).expect("du code");
            regions.push(((code[o].0, code[o].1), (fin.0, fin.1)));
            i = k;
        }
        i += 1;
    }
    regions
}

/// Une ecriture d'une variable dans le script.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Ecriture {
    /// Numero de ligne, a partir de 1.
    ligne: usize,
    /// La valeur, quand l'ecriture est de la forme `$Nom = '<texte>'` en
    /// colonne 0; sinon ce qu'elle est.
    forme: Result<String, String>,
}

const OPERATEURS_D_AFFECTATION: [&str; 7] = ["+=", "-=", "*=", "/=", "%=", "??=", "="];
const PARAMETRES_DE_VARIABLE: [&str; 11] = [
    "-outvariable",
    "-errorvariable",
    "-warningvariable",
    "-informationvariable",
    "-pipelinevariable",
    "-ov",
    "-ev",
    "-wv",
    "-iv",
    "-pv",
    "-variable",
];
const COMMANDES_DE_VARIABLE: [&str; 4] = [
    "set-variable",
    "new-variable",
    "remove-variable",
    "clear-variable",
];

/// La valeur d'une affectation `$Nom = '<texte>'` en colonne 0, avec au plus
/// un commentaire apres; `None` pour toute autre forme.
fn affectation_litterale(ligne: &Ligne, nom: &str) -> Option<String> {
    let car = &ligne.car;
    if car.first() != Some(&'$') || ligne.classes.first() != Some(&Classe::Code) {
        return None;
    }
    let n: Vec<char> = nom.chars().collect();
    if car.len() < 1 + n.len()
        || !car[1..=n.len()]
            .iter()
            .zip(&n)
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
    {
        return None;
    }
    let mut i = 1 + n.len();
    while i < car.len() && blanc(car[i]) {
        i += 1;
    }
    if car.get(i) != Some(&'=') {
        return None;
    }
    i += 1;
    while i < car.len() && blanc(car[i]) {
        i += 1;
    }
    if car.get(i) != Some(&'\'') {
        return None;
    }
    let debut = i + 1;
    let fin = debut + car[debut..].iter().position(|&c| c == '\'')?;
    let mut j = fin + 1;
    while j < car.len() && blanc(car[j]) {
        j += 1;
    }
    let apres_ok = j == car.len() || ligne.classes[j] == Classe::Commentaire;
    apres_ok.then(|| texte(&car[debut..fin]))
}

/// Chaque ecriture de la variable `nom` dans le script, sous toutes les formes
/// que la garde reconnait. Le texte entier est lu, commentaires et chaines
/// compris: une mention de trop rend la garde plus stricte, jamais aveugle.
fn ecritures(s: &Script, nom: &str) -> Vec<Ecriture> {
    let regions = regions_de_parametres(s);
    let dans_une_region = |l: usize, c: usize| {
        regions
            .iter()
            .any(|&(debut, fin)| (l, c) >= debut && (l, c) <= fin)
    };
    let n = nom.to_ascii_lowercase();
    let mut trouvees = Vec::new();
    for (l, ligne) in s.lignes.iter().enumerate() {
        let bas: Vec<char> = ligne.car.iter().map(|c| c.to_ascii_lowercase()).collect();
        let mut causes: Vec<String> = Vec::new();
        for d in occurrences(&bas, "$") {
            // `$Nom`, `${Nom}`, `$script:Nom` et les autres portees.
            let mut i = d + 1;
            let accolade = bas.get(i) == Some(&'{');
            if accolade {
                i += 1;
            }
            for portee in ["script:", "global:", "local:", "private:", "using:"] {
                if occurrences(&bas[i..], portee).first() == Some(&0) {
                    i += portee.len();
                    break;
                }
            }
            let m: Vec<char> = n.chars().collect();
            if bas.len() < i + m.len() || bas[i..i + m.len()] != m[..] {
                continue;
            }
            let mut fin = i + m.len();
            if accolade {
                if bas.get(fin) != Some(&'}') {
                    continue;
                }
                fin += 1;
            } else if bas.get(fin).is_some_and(|&c| ident(c)) {
                continue;
            }
            let avant: String = texte(&bas[..d]).trim_end().to_string();
            let mut j = fin;
            if bas.get(j) == Some(&'+') && bas.get(j + 1) == Some(&'+')
                || bas.get(j) == Some(&'-') && bas.get(j + 1) == Some(&'-')
                || avant.ends_with("++")
                || avant.ends_with("--")
            {
                causes.push("increment".into());
                continue;
            }
            while j < bas.len() && blanc(bas[j]) {
                j += 1;
            }
            let reste = texte(&bas[j..]);
            if dans_une_region(l, d) {
                // Avant l'affectation: `param($N = 'a')` est un parametre,
                // dont l'appelant choisit la valeur.
                causes.push("parametre".into());
            } else if let Some(op) = OPERATEURS_D_AFFECTATION
                .iter()
                .find(|op| reste.starts_with(**op))
            {
                causes.push(format!("affectation `{op}`"));
            } else if reste.starts_with(',') && reste.contains('=') {
                causes.push("affectation multiple".into());
            } else if avant.ends_with("[ref]") {
                causes.push("`[ref]`".into());
            } else if avant.ends_with("foreach (") || avant.ends_with("foreach(") {
                causes.push("variable de boucle".into());
            }
        }
        // `Set-Variable Nom`, `-OutVariable Nom` et leurs voisins: le nom y
        // parait sans `$`.
        let mots: Vec<String> = texte(&bas)
            .split(|c: char| !(ident(c) || c == '-' || c == '+'))
            .filter(|m| !m.is_empty())
            .map(|m| m.trim_start_matches('+').to_string())
            .collect();
        let nomme = mots.contains(&n);
        if nomme
            && mots
                .iter()
                .any(|m| COMMANDES_DE_VARIABLE.contains(&m.as_str()))
        {
            causes.push("commande `*-Variable`".into());
        } else if nomme
            && mots
                .windows(2)
                .any(|w| w[1] == n && PARAMETRES_DE_VARIABLE.contains(&w[0].as_str()))
        {
            causes.push("parametre `-*Variable`".into());
        }
        for cause in causes {
            let forme = if cause == "affectation `=`" {
                affectation_litterale(ligne, nom).ok_or_else(|| {
                    format!(
                        "pas un litteral simple en colonne 0 (`${nom} = '<texte>'`): {}",
                        texte(&ligne.car).trim()
                    )
                })
            } else {
                Err(format!("{cause}: {}", texte(&ligne.car).trim()))
            };
            trouvees.push(Ecriture {
                ligne: ligne.numero,
                forme,
            });
        }
    }
    trouvees
}

/// Le script charge un autre fichier: ses variables peuvent venir d'ailleurs.
fn charge_un_autre_fichier(s: &Script) -> Option<usize> {
    s.lignes.iter().find_map(|ligne| {
        let code: String = ligne
            .car
            .iter()
            .zip(&ligne.classes)
            .map(|(&c, &k)| if k == Classe::Code { c } else { ' ' })
            .collect::<String>()
            .to_ascii_lowercase();
        let t = code.trim_start();
        let point = t.starts_with(". ") || t.starts_with(".\t");
        (point || code.contains("import-module") || code.contains("using module"))
            .then_some(ligne.numero)
    })
}

/// La valeur de `$nom` a la ligne `appel`: une seule ecriture dans tout le
/// script, de la forme `$Nom = '<texte>'`, avant l'appel.
fn valeur(s: &Script, nom: &str, appel: usize) -> Result<String, String> {
    if let Some(l) = charge_un_autre_fichier(s) {
        return Err(format!(
            "${nom}: le script charge un autre fichier (ligne {l}), la variable peut venir \
             d'ailleurs"
        ));
    }
    let toutes = ecritures(s, nom);
    match toutes.as_slice() {
        [] => Err(format!(
            "${nom}: variable inconnue, aucune affectation dans le script"
        )),
        [une] => match &une.forme {
            Ok(v) if une.ligne < appel => Ok(v.clone()),
            Ok(_) => Err(format!(
                "${nom}: affectee ligne {}, apres l'appel",
                une.ligne
            )),
            Err(e) => Err(format!("${nom}, ligne {}: {e}", une.ligne)),
        },
        plusieurs => Err(format!(
            "${nom}: {} ecritures (lignes {}), une seule affectation est admise",
            plusieurs.len(),
            plusieurs
                .iter()
                .map(|e| e.ligne.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

// ---------------------------------------------------------------------------
// Les appels.
// ---------------------------------------------------------------------------

/// La description litterale d'un appel: son delimiteur et son contenu brut.
#[derive(Debug)]
struct Litteral {
    double: bool,
    contenu: String,
}

/// Lit le litteral qui commence en `i` (un guillemet). Rend le litteral et
/// l'indice qui suit son guillemet fermant.
fn litteral(car: &[char], i: usize) -> Result<(Litteral, usize), String> {
    let double = car[i] == '"';
    let mut contenu = String::new();
    let mut j = i + 1;
    loop {
        let Some(&c) = car.get(j) else {
            return Err("description ouverte en fin de ligne: appel sur plusieurs lignes".into());
        };
        if double {
            if c == '`' {
                return Err("accent grave dans la description: echappement non prevu".into());
            }
            if c == '"' {
                if car.get(j + 1) == Some(&'"') {
                    return Err("guillemet double echappe dans la description: non prevu".into());
                }
                break;
            }
        } else if c == '\'' {
            if car.get(j + 1) == Some(&'\'') {
                contenu.push('\'');
                j += 2;
                continue;
            }
            break;
        }
        contenu.push(c);
        j += 1;
    }
    let suivant = j + 1;
    match car.get(suivant) {
        None => {}
        Some(&c) if blanc(c) || "|;)}".contains(c) => {}
        Some(&c) => {
            return Err(format!(
                "description calculee: `{c}` colle au litteral (concatenation ou expression)"
            ));
        }
    }
    Ok((Litteral { double, contenu }, suivant))
}

/// La description developpee: les seules variables `$Nom` ou `${Nom}`, par
/// leur affectation litterale.
fn developper(s: &Script, l: &Litteral, appel: usize) -> Result<String, String> {
    if !l.double {
        return Ok(l.contenu.clone());
    }
    let car: Vec<char> = l.contenu.chars().collect();
    let mut sortie = String::new();
    let mut i = 0;
    while i < car.len() {
        if car[i] != '$' {
            sortie.push(car[i]);
            i += 1;
            continue;
        }
        let (nom, fin) = if car.get(i + 1) == Some(&'{') {
            let Some(f) = car[i + 2..].iter().position(|&c| c == '}') else {
                return Err("`${` sans `}` dans la description".into());
            };
            (texte(&car[i + 2..i + 2 + f]), i + 3 + f)
        } else {
            let f = car[i + 1..].iter().take_while(|&&c| ident(c)).count();
            (texte(&car[i + 1..i + 1 + f]), i + 1 + f)
        };
        if nom.is_empty() || !nom.chars().all(ident) {
            return Err(format!(
                "description calculee: `{}` n'est pas une variable simple",
                texte(&car[i..fin.max(i + 2).min(car.len())])
            ));
        }
        if car.get(fin) == Some(&':') {
            return Err(format!(
                "description calculee: `${nom}:` (portee ou lecteur) non prevu"
            ));
        }
        sortie.push_str(&valeur(s, &nom, appel)?);
        i = fin;
    }
    Ok(sortie)
}

/// Un appel examine.
#[derive(Debug)]
struct Appel {
    ligne: usize,
    commande: &'static str,
    /// La description developpee, s'il en porte une.
    description: Option<String>,
}

/// Examine les arguments d'un appel, de l'indice `i` a la fin de
/// l'instruction. Rend la description developpee, s'il y en a une.
fn arguments(s: &Script, ligne: &Ligne, mut i: usize) -> Result<Option<String>, String> {
    let car = &ligne.car;
    let mut profondeur = 0usize;
    let mut description: Option<String> = None;
    loop {
        if i >= car.len() || ligne.classes[i] == Classe::Commentaire {
            if profondeur > 0 || (i >= car.len() && ligne.chaine_ouverte) {
                return Err("appel sur plusieurs lignes: parenthese ou chaine ouverte".into());
            }
            break;
        }
        let c = car[i];
        if ligne.classes[i] == Classe::Chaine {
            while i < car.len() && ligne.classes[i] == Classe::Chaine {
                i += 1;
            }
            continue;
        }
        match c {
            c if blanc(c) => {}
            '`' => {
                return Err(
                    "accent grave dans l'appel: echappement ou suite de ligne non prevu".into(),
                );
            }
            '@' => {
                return Err("`@` dans l'appel: eclatement ou tableau non prevu".into());
            }
            '(' | '{' => profondeur += 1,
            ')' | '}' if profondeur == 0 => break,
            ')' | '}' => profondeur -= 1,
            ';' | '|' if profondeur == 0 => break,
            '-' if i > 0
                && blanc(car[i - 1])
                && car.get(i + 1).is_some_and(|x| x.is_ascii_alphabetic()) =>
            {
                let longueur = car[i + 1..]
                    .iter()
                    .take_while(|x| x.is_ascii_alphabetic())
                    .count();
                let nom = texte(&car[i + 1..i + 1 + longueur]).to_ascii_lowercase();
                let fin = i + 1 + longueur;
                if nom.len() >= 3 && "description".starts_with(&nom) {
                    if nom != "description" {
                        return Err(format!("parametre abrege `-{nom}`: non prevu"));
                    }
                    if car.get(fin) == Some(&':') {
                        return Err("forme `-Description:` non prevue".into());
                    }
                    if description.is_some() {
                        return Err("deux `-Description` dans un appel".into());
                    }
                    let mut v = fin;
                    while v < car.len() && blanc(car[v]) {
                        v += 1;
                    }
                    match car.get(v) {
                        Some('\'' | '"') => {
                            let (l, apres) = litteral(car, v)?;
                            description = Some(developper(s, &l, ligne.numero)?);
                            i = apres;
                            continue;
                        }
                        Some(&x) => {
                            return Err(format!(
                                "description non litterale (commence par `{x}`): \
                                 un litteral entre guillemets est exige"
                            ));
                        }
                        None => {
                            return Err("description absente de la ligne de l'appel".into());
                        }
                    }
                }
                i = fin;
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    Ok(description)
}

/// Chaque appel des commandes du script, ou le premier defaut qui empeche de
/// le juger, nomme.
fn appels(s: &Script) -> (Vec<Appel>, Vec<String>) {
    let mut trouves = Vec::new();
    let mut defauts = Vec::new();
    for ligne in &s.lignes {
        for commande in COMMANDES {
            for d in occurrences(&ligne.car, commande) {
                let fin = d + commande.chars().count();
                let colle_avant = d > 0 && (ident(ligne.car[d - 1]) || ligne.car[d - 1] == '-');
                let colle_apres = ligne.car.get(fin).is_some_and(|&c| ident(c) || c == '-');
                if colle_avant || colle_apres {
                    continue;
                }
                let lieu = format!("{}:{}", s.nom, ligne.numero);
                match ligne.classes[d] {
                    Classe::Commentaire => continue,
                    Classe::Chaine => {
                        defauts.push(format!(
                            "{lieu}: {commande} dans une chaine: forme non prevue"
                        ));
                        continue;
                    }
                    Classe::Code => {}
                }
                // En position de commande: en tete d'instruction, apres un
                // `;`, un `|`, une accolade ou une parenthese ouvrante, `&`
                // ou `=`, eventuellement qualifiee par son module (`X\`).
                let mut avant = d;
                if avant > 0 && ligne.car[avant - 1] == '\\' {
                    avant -= 1;
                    while avant > 0 && (ident(ligne.car[avant - 1]) || ligne.car[avant - 1] == '.')
                    {
                        avant -= 1;
                    }
                }
                let prefixe = texte(&ligne.car[..avant]);
                let prefixe = prefixe.trim_end();
                if !(prefixe.is_empty() || prefixe.ends_with([';', '|', '{', '(', '&', '='])) {
                    defauts.push(format!(
                        "{lieu}: {commande} hors d'une position de commande: forme non prevue"
                    ));
                    continue;
                }
                match arguments(s, ligne, fin) {
                    Ok(description) => trouves.push(Appel {
                        ligne: ligne.numero,
                        commande,
                        description,
                    }),
                    Err(e) => defauts.push(format!("{lieu}: {commande}: {e}")),
                }
            }
        }
    }
    (trouves, defauts)
}

/// Le verdict d'un script: chaque appel juge, et chaque defaut nomme.
fn juger(nom: &str, contenu: &str) -> (Vec<Appel>, Vec<String>) {
    let s = lire_script(nom, contenu);
    let (trouves, mut defauts) = appels(&s);
    for a in &trouves {
        if let Some(d) = &a.description {
            let n = d.chars().count();
            if n > BORNE {
                defauts.push(format!(
                    "{}:{}: {}: description de {n} caracteres, au-dela de {BORNE}: \"{d}\"",
                    s.nom, a.ligne, a.commande
                ));
            }
        }
    }
    (trouves, defauts)
}

fn relatif(p: &Path) -> String {
    p.strip_prefix(racine())
        .unwrap_or(p)
        .to_string_lossy()
        .replace('\\', "/")
}

#[test]
fn chaque_description_de_compte_ou_de_groupe_tient_dans_la_borne() {
    let scripts = scripts();
    let mut examines = Vec::new();
    let mut defauts = Vec::new();
    let mut avec_description = Vec::new();
    for chemin in &scripts {
        let nom = relatif(chemin);
        let contenu =
            std::fs::read_to_string(chemin).unwrap_or_else(|e| panic!("{nom} illisible: {e}"));
        let (trouves, d) = juger(&nom, &contenu);
        for a in &trouves {
            if let Some(texte) = &a.description {
                println!(
                    "{nom}:{}: {} -Description de {} caracteres: \"{texte}\"",
                    a.ligne,
                    a.commande,
                    texte.chars().count()
                );
                avec_description.push(format!("{nom}:{}", a.ligne));
            }
        }
        examines.push(nom);
        defauts.extend(d);
    }

    // Controle positif: sans lui, un dossier mal lu ou un appel que la
    // lecture manquerait rendrait la recette verte sans avoir rien regarde.
    assert!(
        examines
            .iter()
            .any(|n| n == "packaging/install-windows.ps1")
            && examines.iter().any(|n| n == "scripts/service-windows.ps1"),
        "les scripts PowerShell du depot n'ont pas ete lus: {examines:?}"
    );

    // Les defauts AVANT le second controle positif: un appel que la garde
    // refuse de juger n'a pas de description retenue, et le controle le
    // dirait introuvable au lieu de nommer ce qui l'ecarte.
    assert!(
        defauts.is_empty(),
        "{} defaut(s) dans les descriptions de comptes et de groupes locaux des scripts \
         PowerShell (borne mesuree: {BORNE} caracteres):\n  {}",
        defauts.len(),
        defauts.join("\n  ")
    );

    // L'installeur cree le groupe d'acces avec une description.
    assert!(
        avec_description
            .iter()
            .any(|a| a.starts_with("packaging/install-windows.ps1:")),
        "l'appel de New-LocalGroup de l'installeur n'a pas ete trouve, ou sans sa \
         description: la recette ne regarde plus rien"
    );
}

/// La grammaire, sur des textes ecrits ici: ce qu'elle admet, et chaque forme
/// qu'elle refuse en la nommant. Les scripts du depot, eux, sont lus par la
/// recette precedente.
#[test]
fn la_grammaire_admet_la_forme_simple_et_nomme_chaque_ecart() {
    let admis = "$Nom = 'BifrostDaemon'\n\
                 # New-LocalGroup -Description \"un commentaire n'est pas un appel\"\n\
                 <# New-LocalUser -Description $inconnue #>\n\
                 if (-not $g) { New-LocalGroup -Name 'G' -Description \"Acces de ${Nom}\" | Out-Null }\n\
                 Microsoft.PowerShell.LocalAccounts\\New-LocalUser -Name 'u' -NoPassword -Description 'Compte ''x'''\n\
                 New-LocalGroup -Name 'Sans'\n";
    let (trouves, defauts) = juger("admis.ps1", admis);
    assert!(defauts.is_empty(), "{defauts:?}");
    let descriptions: Vec<_> = trouves.iter().map(|a| a.description.clone()).collect();
    assert_eq!(
        descriptions,
        vec![
            Some("Acces de BifrostDaemon".to_string()),
            Some("Compte 'x'".to_string()),
            None
        ]
    );

    let cas: [(&str, &str); 23] = [
        (
            "$N = 'x'\nNew-LocalGroup -Name G -Description \"0123456789012345678901234567890123456789012345678\"\n",
            "au-dela de 48",
        ),
        (
            "New-LocalGroup -Name G -Description \"service $Absente\"\n",
            "variable inconnue",
        ),
        (
            "$N = 'a'\n$N = 'b'\nNew-LocalGroup -Name G -Description \"$N\"\n",
            "2 ecritures",
        ),
        (
            "$N = 'a'\n$N += 'b'\nNew-LocalGroup -Name G -Description \"$N\"\n",
            "2 ecritures",
        ),
        (
            "$N = Get-Nom\nNew-LocalGroup -Name G -Description \"$N\"\n",
            "pas un litteral simple",
        ),
        (
            "if ($x) {\n    $N = 'a'\n}\nNew-LocalGroup -Name G -Description \"$N\"\n",
            "pas un litteral simple",
        ),
        (
            "param([string] $N = 'a')\nNew-LocalGroup -Name G -Description \"$N\"\n",
            "parametre",
        ),
        (
            "New-LocalGroup -Name G -Description \"$N\"\n$N = 'a'\n",
            "apres l'appel",
        ),
        (
            "New-LocalGroup -Name G -Description \"a $(Get-Date)\"\n",
            "description calculee",
        ),
        (
            "New-LocalGroup -Name G -Description \"a $env:COMPUTERNAME\"\n",
            "description calculee",
        ),
        (
            "New-LocalGroup -Name G -Description ('a' + 'b')\n",
            "description non litterale",
        ),
        (
            "New-LocalGroup -Name G -Description \"a\"+\"b\"\n",
            "description calculee",
        ),
        (
            "New-LocalGroup -Name G `\n    -Description \"a\"\n",
            "accent grave",
        ),
        ("New-LocalGroup @parametres\n", "eclatement"),
        ("New-LocalGroup -Name G -Desc \"a\"\n", "parametre abrege"),
        (
            "Invoke-Expression \"New-LocalGroup -Name G\"\n",
            "dans une chaine",
        ),
        (
            "$N = 'a'\nforeach ($N in 1..2) {}\nNew-LocalGroup -Name G -Description \"$N\"\n",
            "2 ecritures",
        ),
        (
            "$N = 'a'\nSet-Variable -Name N -Value b\nNew-LocalGroup -Name G -Description \"$N\"\n",
            "2 ecritures",
        ),
        (
            ". .\\autre.ps1\n$N = 'a'\nNew-LocalGroup -Name G -Description \"$N\"\n",
            "charge un autre fichier",
        ),
        (
            "New-LocalGroup -Name G -Description:\"a\"\n",
            "-Description:",
        ),
        (
            "Get-Command New-LocalGroup\n",
            "hors d'une position de commande",
        ),
        (
            "New-LocalGroup -Name G -Description \"a\" -Description \"b\"\n",
            "deux `-Description`",
        ),
        (
            "New-LocalGroup -Name (\n'G') -Description \"a\"\n",
            "plusieurs lignes",
        ),
    ];
    for (script, attendu) in cas {
        let (_, defauts) = juger("cas.ps1", script);
        assert!(
            defauts.iter().any(|d| d.contains(attendu)),
            "attendu `{attendu}` pour:\n{script}\nobtenu: {defauts:?}"
        );
    }

    // Le lecteur: un `#` dans une chaine n'ouvre pas de commentaire, une
    // here-string est une chaine, un bloc de commentaire se ferme.
    let s = lire_script(
        "lecteur.ps1",
        "Write-Host \"a # b\" # vrai\n$t = @'\nNew-LocalGroup\n'@\n<# x\ny #> z\n",
    );
    let classes = |l: usize| -> String {
        s.lignes[l]
            .classes
            .iter()
            .map(|k| match k {
                Classe::Code => 'c',
                Classe::Chaine => 's',
                Classe::Commentaire => '#',
            })
            .collect()
    };
    assert_eq!(classes(0), "cccccccccccsssssssc######");
    assert_eq!(classes(2), "ssssssssssssss");
    assert_eq!(classes(3), "ss");
    assert_eq!(classes(5), "####cc");
}
