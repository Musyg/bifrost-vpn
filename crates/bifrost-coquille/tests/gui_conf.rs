//! La configuration de la coquille Tauri reste stricte, et cette garde tombe si
//! elle se desserre.
//!
//! # Pourquoi cette recette vit ICI et pas dans `gui/`
//!
//! `gui/` ne compile que sur un hote qui porte les bibliotheques de
//! developpement de la WebView (sous Linux, webkit2gtk): une recette qui y
//! vivrait ne s'executerait pas partout. `bifrost-coquille` est un membre
//! ordinaire de l'espace de travail: cette garde compte sur chaque hote et dans
//! chaque job de la CI, exactement comme `suivi_a_jour.rs` garde des fichiers
//! qui ne sont pas du code compile.
//!
//! Elle lit `gui/tauri.conf.json`, `gui/capabilities/*.json` et
//! `gui/ui/main.js` sur le DISQUE et rougit sur:
//!   - un identifiant autre que `io.github.musyg.bifrost-vpn`: il nomme les
//!     repertoires de donnees de l'application, il ne change pas;
//!   - une CSP absente, non-chaine, sans `default-src 'self'`, laxiste
//!     (`unsafe-inline` / `unsafe-eval`), ou differente, au caractere pres, de
//!     celle du depot: toute source ajoutee est un elargissement;
//!   - `bundle.active` vrai ou absent (l'empaquetage ne passe pas par Tauri);
//!   - `withGlobalTauri` absent ou faux (le front en depend);
//!   - un fichier de capacites autre que `default.json`, une fenetre autre que
//!     `main`, une permission autre que `core:default` et `core:event:default`,
//!     et, avec un message a part, une permission shell / fs / http / updater /
//!     dialog;
//!   - un fichier binaire dans `gui/`;
//!   - une page qui ne rend pas chaque etat de la Vue, qui choisit elle-meme une
//!     couleur, ou dont la note d'un etat d'erreur se lit comme connecte.

use std::path::{Path, PathBuf};

use bifrost_coquille::vue::EtatVue;
use serde_json::Value;

/// La racine de l'espace de travail: `CARGO_MANIFEST_DIR` pointe sur
/// crates/bifrost-coquille, deux crans au-dessus.
fn racine() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("la racine de l'espace de travail doit exister")
        .to_path_buf()
}

fn lire_json(relatif: &str) -> Value {
    let chemin = racine().join(relatif);
    let texte = std::fs::read_to_string(&chemin)
        .unwrap_or_else(|e| panic!("{} illisible: {e}", chemin.display()));
    serde_json::from_str(&texte)
        .unwrap_or_else(|e| panic!("{} n'est pas un JSON valide: {e}", chemin.display()))
}

const CONF: &str = "gui/tauri.conf.json";

/// L'identifiant de l'application. Tauri en tire le nom des repertoires de
/// donnees de l'application: le changer les deplacerait.
const IDENTIFIANT: &str = "io.github.musyg.bifrost-vpn";

/// La CSP du depot, au caractere pres. La page ne charge que ses propres
/// fichiers et ne parle qu'au canal IPC de Tauri.
const CSP: &str = "default-src 'self'; img-src 'self' data:; style-src 'self'; \
                   script-src 'self'; connect-src 'self' ipc: http://ipc.localhost";

#[test]
fn l_identifiant_est_celui_du_depot() {
    let conf = lire_json(CONF);
    let identifiant = conf.get("identifier");
    assert_eq!(
        identifiant,
        Some(&Value::String(IDENTIFIANT.to_owned())),
        "identifier doit valoir `{IDENTIFIANT}` dans {CONF}: il nomme les \
         repertoires de donnees de l'application; trouve: {identifiant:?}"
    );
}

#[test]
fn la_csp_est_presente_et_stricte() {
    let conf = lire_json(CONF);
    let csp = conf
        .get("app")
        .and_then(|a| a.get("security"))
        .and_then(|s| s.get("csp"));

    let csp = csp.unwrap_or_else(|| {
        panic!("app.security.csp absente de {CONF}: une WebView sans CSP charge n'importe quoi")
    });
    let csp = csp.as_str().unwrap_or_else(|| {
        panic!("app.security.csp doit etre une chaine stricte dans {CONF}, pas {csp:?}")
    });

    assert!(
        csp.contains("default-src 'self'"),
        "la CSP doit poser default-src 'self': {csp}"
    );
    assert!(
        !csp.contains("unsafe-inline"),
        "CSP laxiste (unsafe-inline): {csp}"
    );
    assert!(
        !csp.contains("unsafe-eval"),
        "CSP laxiste (unsafe-eval): {csp}"
    );
    assert_eq!(
        csp, CSP,
        "la CSP de {CONF} n'est plus celle du depot: une source ajoutee a une \
         directive elargit ce que la WebView charge ou joint"
    );
}

#[test]
fn le_bundling_est_desactive() {
    let conf = lire_json(CONF);
    let active = conf.get("bundle").and_then(|b| b.get("active"));
    assert_eq!(
        active,
        Some(&Value::Bool(false)),
        "bundle.active doit etre present et faux dans {CONF}: l'empaquetage de \
         la coquille ne passe pas par Tauri; trouve: {active:?}"
    );
}

#[test]
fn le_global_tauri_est_actif() {
    let conf = lire_json(CONF);
    let wgt = conf.get("app").and_then(|a| a.get("withGlobalTauri"));
    assert_eq!(
        wgt,
        Some(&Value::Bool(true)),
        "app.withGlobalTauri doit etre vrai dans {CONF}: le front statique \
         appelle window.__TAURI__.core.invoke et .event.listen; trouve: {wgt:?}"
    );
}

/// Les fragments de permission interdits: aucun plugin qui ouvrirait une
/// surface que la coquille n'a aucune raison d'avoir.
const INTERDITS: &[&str] = &["shell", "fs", "http", "updater", "dialog"];

/// Les permissions de la coquille, toutes et seules: le coeur de Tauri et ses
/// evenements. Les commandes de l'application (etat, connecter, deconnecter)
/// sont autorisees par defaut et n'y figurent pas.
const PERMISSIONS: [&str; 2] = ["core:default", "core:event:default"];

/// Le seul fichier de capacites, et la seule fenetre qu'il vise.
const FICHIER_CAPACITES: &str = "default.json";
const FENETRE: &str = "main";

/// Les capacites sont celles du depot, ni plus ni moins: un seul fichier, la
/// seule fenetre `main`, et exactement les deux permissions de `PERMISSIONS`.
/// Une permission de plus, meme anodine, est une surface de plus pour la page.
#[test]
fn les_capacites_sont_exactement_celles_du_depot() {
    let fichiers = fichiers_capacites();
    let noms: Vec<String> = fichiers
        .iter()
        .filter_map(|f| f.file_name().map(|n| n.to_string_lossy().into_owned()))
        .collect();
    assert_eq!(
        noms,
        [FICHIER_CAPACITES],
        "gui/capabilities/ doit porter le seul fichier {FICHIER_CAPACITES}: un \
         fichier de plus accorde d'autres permissions"
    );

    let chemin = &fichiers[0];
    let texte = std::fs::read_to_string(chemin)
        .unwrap_or_else(|e| panic!("{} illisible: {e}", chemin.display()));
    let valeur: Value = serde_json::from_str(&texte)
        .unwrap_or_else(|e| panic!("{} JSON invalide: {e}", chemin.display()));

    let fenetres = valeur.get("windows");
    assert_eq!(
        fenetres,
        Some(&serde_json::json!([FENETRE])),
        "{}: la capacite ne vise que la fenetre `{FENETRE}`; trouve: {fenetres:?}",
        chemin.display()
    );

    let permissions = valeur.get("permissions");
    assert_eq!(
        permissions,
        Some(&serde_json::json!(PERMISSIONS)),
        "{}: les permissions doivent etre exactement {PERMISSIONS:?}, dans cet \
         ordre; trouve: {permissions:?}",
        chemin.display()
    );
}

fn fichiers_capacites() -> Vec<PathBuf> {
    let dossier = racine().join("gui/capabilities");
    let mut trouves = Vec::new();
    let entrees = std::fs::read_dir(&dossier)
        .unwrap_or_else(|e| panic!("{} illisible: {e}", dossier.display()));
    for entree in entrees.flatten() {
        let chemin = entree.path();
        if chemin.extension().and_then(|e| e.to_str()) == Some("json") {
            trouves.push(chemin);
        }
    }
    trouves.sort();
    trouves
}

#[test]
fn les_capacites_ne_demandent_aucune_permission_dangereuse() {
    let fichiers = fichiers_capacites();
    // Controle positif: au moins une capacite, sinon la recette ne lit rien.
    assert!(
        !fichiers.is_empty(),
        "aucun fichier de capacite dans gui/capabilities/: la recette ne verifie rien"
    );

    for fichier in &fichiers {
        let texte = std::fs::read_to_string(fichier)
            .unwrap_or_else(|e| panic!("{} illisible: {e}", fichier.display()));
        let valeur: Value = serde_json::from_str(&texte)
            .unwrap_or_else(|e| panic!("{} JSON invalide: {e}", fichier.display()));
        let permissions = valeur
            .get("permissions")
            .and_then(|p| p.as_array())
            .unwrap_or_else(|| panic!("{} sans tableau `permissions`", fichier.display()));

        for perm in permissions {
            // Une permission peut etre une chaine (<< core:default >>) ou un
            // objet ({ identifier, allow, ... }). On teste l'identifiant dans
            // les deux formes.
            let ident = perm
                .as_str()
                .map(str::to_owned)
                .or_else(|| {
                    perm.get("identifier")
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                })
                .unwrap_or_else(|| panic!("{}: permission illisible {perm:?}", fichier.display()));
            let bas = ident.to_lowercase();
            for interdit in INTERDITS {
                assert!(
                    !bas.contains(interdit),
                    "{}: la capacite demande une permission '{}', interdite ('{}'). \
                     La coquille commande le daemon par l'IPC, elle n'a besoin ni de \
                     shell, ni de fs, ni de http, ni d'updater, ni de dialog.",
                    fichier.display(),
                    ident,
                    interdit
                );
            }
        }
    }
}

/// La coquille n'embarque AUCUN binaire d'icone: l'image du tray est construite
/// en memoire. Cette garde tombe si un fichier binaire apparait dans `gui/`.
///
/// `sources_ascii` (bifrost-evasion) lit aussi chaque fichier de `gui/` et
/// rougirait sur les octets d'une image, mais elle ne dit pas que c'est un
/// binaire; `caracteres_de_controle` ne juge que des extensions texte connues
/// (un .png y echappe). Cette garde-ci nomme la regle << pas de binaire dans le
/// depot >> pour l'arbre de la coquille, par l'extension.
#[test]
fn la_coquille_n_embarque_aucun_binaire() {
    let extensions_binaires = [
        "png", "ico", "jpg", "jpeg", "gif", "bmp", "icns", "dll", "exe",
    ];
    let mut binaires = Vec::new();
    parcourir_gui(&racine().join("gui"), &extensions_binaires, &mut binaires);
    assert!(
        binaires.is_empty(),
        "gui/ porte {} fichier(s) binaire(s): l'icone du tray se construit en \
         memoire (Image::new_owned), aucun binaire ne doit entrer dans le depot:\n  {}",
        binaires.len(),
        binaires.join("\n  ")
    );
}

fn parcourir_gui(dossier: &Path, extensions: &[&str], trouves: &mut Vec<String>) {
    let Ok(entrees) = std::fs::read_dir(dossier) else {
        return;
    };
    for entree in entrees.flatten() {
        let chemin = entree.path();
        let nom = entree.file_name().to_string_lossy().into_owned();
        if chemin.is_dir() {
            // target/ n'est pas versionne; on ne le juge pas.
            if nom != "target" {
                parcourir_gui(&chemin, extensions, trouves);
            }
        } else if let Some(ext) = chemin.extension().and_then(|e| e.to_str())
            && extensions.contains(&ext.to_lowercase().as_str())
        {
            trouves.push(
                chemin
                    .strip_prefix(racine())
                    .unwrap_or(&chemin)
                    .display()
                    .to_string()
                    .replace('\\', "/"),
            );
        }
    }
}

// --- La page: chaque etat de la Vue a son rendu ---------------------------------

const PAGE: &str = "gui/ui/main.js";

/// Chaque etat de la Vue, et s'il est une erreur du poste de commande (vrai)
/// ou un etat rendu par le daemon (faux). Le `match` est exhaustif: un etat
/// ajoute a `EtatVue` ne compile plus ici tant qu'il n'est pas classe, donc
/// tant que la page n'a pas ete jugee pour lui.
fn etats_de_la_vue() -> Vec<(EtatVue, bool)> {
    let etats = [
        EtatVue::Connecte,
        EtatVue::ConnexionEnCours,
        EtatVue::Reprise,
        EtatVue::Echec,
        EtatVue::Deconnecte,
        EtatVue::DaemonInjoignable,
        EtatVue::DaemonSansReponse,
        EtatVue::ServeurNonAdmis,
        EtatVue::Refuse,
    ];
    etats
        .into_iter()
        .map(|etat| {
            let erreur = match etat {
                EtatVue::Connecte
                | EtatVue::ConnexionEnCours
                | EtatVue::Reprise
                | EtatVue::Echec
                | EtatVue::Deconnecte => false,
                EtatVue::DaemonInjoignable
                | EtatVue::DaemonSansReponse
                | EtatVue::ServeurNonAdmis
                | EtatVue::Refuse => true,
            };
            (etat, erreur)
        })
        .collect()
}

/// Le nom qu'un etat porte vers la page: sa serialisation.
fn nom_emis(etat: EtatVue) -> String {
    match serde_json::to_value(etat) {
        Ok(Value::String(nom)) => nom,
        autre => panic!("{etat:?} ne se serialise pas en chaine: {autre:?}"),
    }
}

/// Les entrees de la table `NOTES` de la page: (cle, note), dans l'ordre.
///
/// Pas d'interprete JavaScript: la table est un objet litteral fait de chaines
/// entre guillemets doubles, `"cle": "note"` ou la note sur la ligne suivante.
/// Une chaine est une cle si un `:` la suit; sa note est la chaine suivante.
/// Une table absente, ou une forme que cette lecture ne connait pas, rougit.
fn notes_de_la_page(page: &str) -> Result<Vec<(String, String)>, String> {
    const OUVERTURE: &str = "const NOTES = {";
    let debut = page
        .find(OUVERTURE)
        .ok_or("table `const NOTES = {` absente")?;
    let reste = &page[debut + OUVERTURE.len()..];
    let fin = reste
        .find("\n};")
        .ok_or("table NOTES jamais refermee par `};` en tete de ligne")?;
    let corps = &reste[..fin];

    // Les chaines entre guillemets doubles du corps, et le caractere qui suit
    // chacune (blancs sautes).
    let mut chaines: Vec<(String, Option<char>)> = Vec::new();
    let mut car = corps.chars().peekable();
    while let Some(c) = car.next() {
        match c {
            '"' => {
                let mut s = String::new();
                loop {
                    match car.next() {
                        Some('\\') => s.push(car.next().ok_or("echappement en fin de table")?),
                        Some('"') => break,
                        Some(x) => s.push(x),
                        None => return Err(format!("chaine `{s}` jamais refermee")),
                    }
                }
                while car.peek().is_some_and(|x| *x == ' ') {
                    car.next();
                }
                chaines.push((s, car.peek().copied()));
            }
            ' ' | '\n' | ',' | ':' => {}
            autre => {
                return Err(format!(
                    "caractere `{autre}` hors d'une chaine: forme que cette lecture ne \
                     connait pas"
                ));
            }
        }
    }
    let mut entrees = Vec::new();
    for paire in chaines.chunks(2) {
        let [(cle, apres_cle), (note, apres_note)] = paire else {
            return Err(format!("la cle `{}` n'a pas de note", paire[0].0));
        };
        if *apres_cle != Some(':') {
            return Err(format!("`\"{cle}\"` n'est pas suivie de `:`"));
        }
        if *apres_note == Some(':') {
            return Err(format!("la cle `{cle}` n'a pas de note avant `\"{note}\"`"));
        }
        entrees.push((cle.clone(), note.clone()));
    }
    Ok(entrees)
}

/// Vrai si `mot` apparait dans `texte` comme un mot entier (ni lettre, ni
/// chiffre, ni `_` ou `-` de part et d'autre).
fn contient_le_mot(texte: &str, mot: &str) -> bool {
    let colle = |c: char| c.is_ascii_alphanumeric() || c == '_' || c == '-';
    texte.match_indices(mot).any(|(i, _)| {
        let avant = texte[..i].chars().next_back();
        let apres = texte[i + mot.len()..].chars().next();
        !avant.is_some_and(colle) && !apres.is_some_and(colle)
    })
}

/// La page rend chaque etat de la Vue, et un etat d'erreur ne s'y lit jamais
/// comme connecte.
///
/// - la table `NOTES` porte une entree par etat de la Vue, et rien d'autre;
/// - la note d'un etat d'erreur n'est pas vide (la page dit ce que la coquille
///   sait) et ne dit pas << connecte >>;
/// - la couleur de la pastille est celle de la Vue, telle quelle: la page
///   l'ecrit une fois, depuis `vue.couleur`, et ne nomme jamais le vert.
#[test]
fn la_page_rend_chaque_etat_de_la_vue() {
    let page = std::fs::read_to_string(racine().join(PAGE))
        .unwrap_or_else(|e| panic!("{PAGE} illisible: {e}"));
    let notes = notes_de_la_page(&page).unwrap_or_else(|e| panic!("{PAGE}: {e}"));
    let etats = etats_de_la_vue();

    let cles: Vec<&str> = notes.iter().map(|(c, _)| c.as_str()).collect();
    let attendues: Vec<String> = etats.iter().map(|(e, _)| nom_emis(*e)).collect();
    let mut tri_cles = cles.clone();
    tri_cles.sort_unstable();
    let mut tri_attendues: Vec<&str> = attendues.iter().map(String::as_str).collect();
    tri_attendues.sort_unstable();
    assert_eq!(
        tri_cles, tri_attendues,
        "{PAGE}: la table NOTES doit porter une entree par etat de la Vue, et rien \
         d'autre"
    );

    for (etat, erreur) in etats {
        if !erreur {
            continue;
        }
        let nom = nom_emis(etat);
        let note = &notes
            .iter()
            .find(|(c, _)| *c == nom)
            .expect("cle verifiee ci-dessus")
            .1;
        assert!(
            !note.trim().is_empty(),
            "{PAGE}: l'etat d'erreur `{nom}` n'a pas de note: la page doit dire ce \
             que la coquille sait"
        );
        assert!(
            !note.to_lowercase().contains("connecte"),
            "{PAGE}: la note de l'etat d'erreur `{nom}` dit << connecte >>: `{note}`"
        );
    }

    assert_eq!(
        page.matches("className").count(),
        1,
        "{PAGE}: la page ne doit ecrire la classe d'un element qu'une fois, celle de \
         la pastille"
    );
    assert!(
        page.contains("pastille.className = \"pastille \" + vue.couleur;"),
        "{PAGE}: la couleur de la pastille doit etre celle de la Vue, telle quelle"
    );
    assert!(
        !contient_le_mot(&page, "vert"),
        "{PAGE}: la page nomme le vert; seule la Vue choisit la couleur"
    );
}

/// Le temoin de la lecture de la page: une table bien formee est lue, une cle
/// sans note, une table absente ou une forme inconnue font rougir la lecture
/// au lieu de rendre une table vide; et le mot entier `vert` se distingue de
/// `ouvert`.
#[test]
fn la_lecture_de_la_page_ne_devine_rien() {
    let saine =
        "const NOTES = {\n  \"a\": \"\",\n  \"b\":\n    \"une note, avec: deux points\",\n};\n";
    assert_eq!(
        notes_de_la_page(saine),
        Ok(vec![
            ("a".to_owned(), String::new()),
            ("b".to_owned(), "une note, avec: deux points".to_owned())
        ])
    );
    for cassee in [
        "const NOTES = {\n  \"a\":\n};\n",
        "const NOTES = {\n  \"a\": \"b\": \"c\",\n};\n",
        "const NOTES = {\n  \"a\": \"x\" + y,\n};\n",
        "var NOTES = {\n  \"a\": \"x\",\n};\n",
        "const NOTES = {\n  \"a\": \"x\",\n",
    ] {
        assert!(
            notes_de_la_page(cassee).is_err(),
            "{cassee:?} aurait du etre refusee"
        );
    }
    assert!(contient_le_mot("pastille vert", "vert"));
    assert!(contient_le_mot("\"vert\"", "vert"));
    assert!(!contient_le_mot("le canal est ouvert", "vert"));
    assert!(!contient_le_mot("--vert", "vert"));
}
