//! Les deux listes d'avis ignores doivent dire la meme chose.
//!
//! # Pourquoi cette recette existe
//!
//! `cargo audit` et `cargo deny check advisories` lisent la MEME base RustSec,
//! et chacun sa liste d'exceptions: `deny.toml` d'un cote, `.cargo/audit.toml`
//! de l'autre, sous deux formes differentes - une table `{ id, reason }` ici,
//! une simple chaine la. Un seul reglage, deux endroits, deux syntaxes.
//!
//! C'est exactement la forme du defaut trouve trois fois en aout 2026 en
//! portant le logiciel sur Windows: un reglage porte par une plateforme et pas
//! par l'autre, qui ne se voit qu'a l'execution et seulement dans un cas. Ici
//! la divergence serait pire que muette, elle serait rassurante: la CI
//! resterait verte pendant qu'un des deux outils tairait un avis que l'autre
//! signale, et personne ne saurait lequel des deux a raison.
//!
//! # Deux paires, pas une
//!
//! Le depot porte deux verrous, donc deux paires de listes: `deny.toml` et
//! `.cargo/audit.toml` pour la racine, `gui/deny.toml` et
//! `gui/.cargo/audit.toml` pour la coquille, espace de travail separe. Elles
//! sont separees parce que cargo-deny rend une erreur quand un ignore ne
//! matche aucun crate du verrou examine (`unused-ignored-advisory = "deny"`):
//! une liste unique ferait rougir l'un des deux controles a coup sur. Chaque
//! paire est gardee ici de la meme facon, et celle de la coquille exige en
//! plus une raison datee sur chaque entree: ses avis sont acceptes sur des
//! faits releves a une date, a relire quand la pile Tauri monte.
//!
//! # Ce qu'elle ne fait pas
//!
//! Elle ne juge aucun avis. Elle ne dit pas qu'ignorer RUSTSEC-2024-0436 est
//! une bonne idee - ce raisonnement-la vit dans `deny.toml`, a cote de
//! l'entree, et il est date. Elle dit seulement que les deux fichiers d'une
//! paire portent le meme ensemble d'identifiants, et que les deux `deny.toml`
//! portent les deux cles de reglage ci-dessous.
//!
//! # Deux cles de reglage, dans les deux `deny.toml`
//!
//! `unsound = "all"` et `unused-ignored-advisory = "deny"`, depuis le
//! 2026-09-15 a la racine. La premiere parce que le defaut `workspace`
//! n'examine les avis unsound que sur les dependances DIRECTES et laisse
//! passer un crate transitif unsound en silence, alors que le verrou de la
//! racine est celui des binaires PRIVILEGIES et que celui de la coquille porte
//! un avis unsound transitif (glib); la seconde parce qu'un ignore perime doit
//! rougir, pas avertir. Une ligne commentee ne compte pas, comme pour les
//! identifiants.

use std::collections::BTreeSet;
use std::path::PathBuf;

/// Les paires (cargo-deny, cargo-audit) gardees, chacune pour son verrou.
const PAIRES: [(&str, &str); 2] = [
    ("deny.toml", ".cargo/audit.toml"),
    ("gui/deny.toml", "gui/.cargo/audit.toml"),
];

fn racine() -> PathBuf {
    // `CARGO_MANIFEST_DIR` pointe sur crates/bifrost-evasion; la racine de
    // l'espace de travail est deux crans au-dessus. Meme idiome que
    // `frontiere_licence.rs`, qui y lance `cargo metadata`.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("la racine de l'espace de travail doit exister")
        .to_path_buf()
}

fn lire(relatif: &str) -> String {
    let chemin = racine().join(relatif);
    std::fs::read_to_string(&chemin)
        .unwrap_or_else(|e| panic!("{} illisible: {e}", chemin.display()))
}

/// Les identifiants RUSTSEC portes par les lignes ACTIVES d'un fichier.
///
/// Les lignes de commentaire sont ecartees, et c'est indispensable ici:
/// `deny.toml` explique longuement pourquoi il ignore l'avis, en le nommant
/// plusieurs fois en prose. Les compter donnerait une egalite fausse dans un
/// sens comme dans l'autre.
///
/// Pas de parseur TOML: `bifrost-evasion` ne depend que de `serde`, et son
/// manifeste le dit. Le format d'un identifiant RUSTSEC est fixe, la
/// reconnaitre a la main coute moins qu'une dependance de plus.
fn avis_actifs(texte: &str) -> BTreeSet<String> {
    let mut vus = BTreeSet::new();
    for ligne in texte.lines() {
        if ligne.trim_start().starts_with('#') {
            continue;
        }
        vus.extend(identifiants(ligne));
    }
    vus
}

fn identifiants(ligne: &str) -> Vec<String> {
    let mut trouves = Vec::new();
    let mut i = 0;
    while let Some(pos) = ligne[i..].find("RUSTSEC-") {
        let debut = i + pos;
        // RUSTSEC-AAAA-NNNN: huit caracteres de prefixe, quatre chiffres, un
        // tiret, quatre chiffres.
        let fin = debut + 8 + 4 + 1 + 4;
        // `get` et non l'indexation directe: la fin tombe a une longueur fixe
        // en OCTETS, et une ligne peut porter un caractere multi-octets juste
        // apres l'identifiant. Indexer au milieu d'un caractere panique.
        if let Some(candidat) = ligne.get(debut..fin) {
            let corps: Vec<char> = candidat.chars().skip(8).collect();
            let bien_forme = corps.len() == 9
                && corps[..4].iter().all(|c| c.is_ascii_digit())
                && corps[4] == '-'
                && corps[5..].iter().all(|c| c.is_ascii_digit());
            if bien_forme {
                trouves.push(candidat.to_owned());
            }
        }
        i = debut + 8;
    }
    trouves
}

/// La raison portee par une entree `{ id = "...", reason = "..." }` ecrite sur
/// une seule ligne, ou `None` si la ligne n'en porte pas.
///
/// Meme parti que `identifiants`: pas de parseur TOML. La forme est celle du
/// fichier, une entree par ligne; une entree eclatee sur plusieurs lignes
/// rendrait `None`, un rouge de trop plutot qu'un trou.
fn raison(ligne: &str) -> Option<String> {
    const CLE: &str = "reason = \"";
    let debut = ligne.find(CLE)? + CLE.len();
    let fin = ligne[debut..].find('"')?;
    Some(ligne[debut..debut + fin].to_owned())
}

/// Les entrees actives d'un `deny.toml`: chaque identifiant avec la raison
/// ecrite sur sa ligne, s'il y en a une.
fn entrees_ignore(texte: &str) -> Vec<(String, Option<String>)> {
    let mut entrees = Vec::new();
    for ligne in texte.lines() {
        if ligne.trim_start().starts_with('#') {
            continue;
        }
        for id in identifiants(ligne) {
            entrees.push((id, raison(ligne)));
        }
    }
    entrees
}

fn verifier_concordance(fichier_deny: &str, fichier_audit: &str) {
    let deny = lire(fichier_deny);
    let audit = lire(fichier_audit);

    let cote_deny = avis_actifs(&deny);
    let cote_audit = avis_actifs(&audit);

    assert_eq!(
        cote_deny, cote_audit,
        "{fichier_deny} et {fichier_audit} n'ignorent pas les memes avis.\n\
         cargo-deny: {cote_deny:?}\n\
         cargo-audit: {cote_audit:?}\n\
         Un avis ignore d'un seul cote laisse la CI verte pendant qu'un des \
         deux outils le signale et que l'autre le tait."
    );
}

#[test]
fn les_deux_listes_d_avis_ignores_concordent() {
    let (deny, audit) = PAIRES[0];
    verifier_concordance(deny, audit);
}

/// La meme garde pour la paire de la coquille. Une recette a part, et non une
/// boucle sur les deux paires: quand l'une tombe, son nom dit laquelle sans
/// lire le message.
#[test]
fn les_deux_listes_de_la_coquille_concordent() {
    let (deny, audit) = PAIRES[1];
    verifier_concordance(deny, audit);
}

/// Chaque entree ignoree de la coquille porte une raison NON VIDE et DATEE.
///
/// Les avis de `gui/Cargo.lock` sont acceptes sur des faits releves a une
/// date (qui tire le crate, proc-macro ou non, dans le binaire livre ou non,
/// plateforme, ce que la derniere version de Tauri exige). Une raison sans
/// date ne dit pas quand ces faits etaient vrais, donc quand les reverifier;
/// une raison vide ne dit rien. La date attendue commence par `2026-`: le jour
/// ou on la relit une autre annee, c'est ce prefixe qu'il faudra changer,
/// entree par entree, apres avoir remesure.
#[test]
fn chaque_ignore_de_la_coquille_porte_une_raison_datee() {
    let (fichier, _) = PAIRES[1];
    let entrees = entrees_ignore(&lire(fichier));

    // Controle positif: une liste vide passerait la boucle sans rien prouver.
    assert!(
        !entrees.is_empty(),
        "{fichier} ne porte aucune entree ignore active; cette recette suppose \
         qu'il en porte, sinon elle ne garde rien"
    );

    for (id, raison) in entrees {
        let raison = raison.unwrap_or_else(|| {
            panic!("{fichier}: l'entree {id} n'a pas de champ reason sur sa ligne")
        });
        assert!(
            !raison.trim().is_empty(),
            "{fichier}: l'entree {id} a une raison vide"
        );
        assert!(
            raison.contains("2026-"),
            "{fichier}: la raison de {id} ne porte pas de date 2026-: {raison:?}"
        );
    }
}

/// Le controle positif. Sans lui, une extraction qui rendrait toujours
/// l'ensemble vide ferait passer la recette precedente sans rien comparer -
/// deux ensembles vides sont egaux.
#[test]
fn l_extraction_trouve_reellement_quelque_chose() {
    for fichier in PAIRES.iter().flat_map(|(deny, audit)| [*deny, *audit]) {
        let texte = lire(fichier);
        if !texte.contains("RUSTSEC-") {
            // Legitime: le jour ou plus aucun avis n'est ignore, les deux
            // fichiers seront muets et la recette d'egalite suffira.
            continue;
        }
        assert!(
            !avis_actifs(&texte).is_empty(),
            "{fichier} nomme un avis RUSTSEC mais l'extraction n'en trouve \
             aucun sur ses lignes actives"
        );
    }
}

/// Et le temoin que les commentaires sont bien ecartes. `deny.toml` nomme son
/// avis en prose plusieurs fois avant de l'ignorer une seule; si les
/// commentaires comptaient, l'egalite ci-dessus tomberait pour une raison qui
/// n'a rien a voir avec une divergence reelle.
#[test]
fn les_commentaires_ne_comptent_pas() {
    let deny = lire("deny.toml");
    let en_commentaire: usize = deny
        .lines()
        .filter(|l| l.trim_start().starts_with('#'))
        .map(|l| identifiants(l).len())
        .sum();
    assert!(
        en_commentaire > 0,
        "ce temoin suppose que deny.toml nomme l'avis en prose; il ne le fait \
         plus, donc il ne prouve plus rien"
    );
    assert_eq!(
        avis_actifs(&deny).len(),
        1,
        "un seul avis est ignore aujourd'hui, et il l'est sur une ligne active"
    );
}

/// Le meme temoin pour la coquille, et plus tranchant: `gui/deny.toml` nomme
/// en prose l'avis de la RACINE (RUSTSEC-2024-0436, `paste`) pour dire
/// pourquoi il n'est pas dans sa liste. S'il comptait, la coquille ignorerait
/// un avis absent de son verrou, ce que cargo-deny refuse, et la concordance
/// avec `gui/.cargo/audit.toml` tomberait.
#[test]
fn les_commentaires_de_la_coquille_ne_comptent_pas() {
    let (fichier, _) = PAIRES[1];
    let deny = lire(fichier);
    let en_commentaire: BTreeSet<String> = deny
        .lines()
        .filter(|l| l.trim_start().starts_with('#'))
        .flat_map(identifiants)
        .collect();
    assert!(
        en_commentaire.contains("RUSTSEC-2024-0436"),
        "ce temoin suppose que {fichier} nomme l'avis de la racine en prose; \
         il ne le fait plus, donc il ne prouve plus rien"
    );
    assert!(
        !avis_actifs(&deny).contains("RUSTSEC-2024-0436"),
        "{fichier} ignore activement un avis qui n'existe que dans le verrou de \
         la racine"
    );
}

// --- Les deux cles de reglage, dans la section [advisories] ------------------

/// La ligne exigee, telle quelle, dans `deny.toml`.
const LIGNE_UNSOUND: &str = r#"unsound = "all""#;
const LIGNE_IGNORE_PERIME: &str = r#"unused-ignored-advisory = "deny""#;

/// La valeur d'une cle de la section `[advisories]` d'un `deny.toml`, lue sur
/// une ligne ACTIVE (les commentaires sont ecartes, comme dans `avis_actifs`:
/// `# unsound = "all"` n'est pas un reglage). `None` si la section ne la porte
/// pas. Un commentaire en fin de ligne (`unsound = "all" # ...`) est tolere,
/// c'est du TOML valide; la valeur s'arrete au premier `#`, ce qui suffit pour
/// des valeurs qui sont des mots entre guillemets.
///
/// Meme parti que `identifiants`: pas de parseur TOML. Une section commence a
/// une ligne `[...]`; une table imbriquee comme `[[licenses.exceptions]]` en
/// ouvre une autre, ce qui suffit ici.
fn valeur_dans_advisories(texte: &str, cle: &str) -> Option<String> {
    let mut dans_advisories = false;
    for ligne in texte.lines() {
        let net = ligne.trim();
        if net.is_empty() || net.starts_with('#') {
            continue;
        }
        if net.starts_with('[') {
            dans_advisories = net == "[advisories]";
            continue;
        }
        if !dans_advisories {
            continue;
        }
        let Some((gauche, droite)) = net.split_once('=') else {
            continue;
        };
        if gauche.trim() != cle {
            continue;
        }
        let valeur = match droite.split_once('#') {
            Some((avant, _)) => avant,
            None => droite,
        };
        return Some(valeur.trim().to_owned());
    }
    None
}

/// `unsound = "all"` dans `[advisories]` de `deny.toml`, sur une ligne active
/// et avec cette valeur exacte.
///
/// Depuis cargo-deny 0.19.0 la cle existe avec le defaut `workspace`: un avis
/// UNSOUND n'est examine que si le crate est une dependance DIRECTE d'un membre
/// de l'espace de travail, et un crate transitif unsound passe en silence. Le
/// lock de la racine est celui des binaires PRIVILEGIES: il n'a pas a etre
/// moins exigeant pour `unsound` qu'il ne l'est deja pour `unmaintained`.
/// Falsifiee le 15/09/2026 en retirant la ligne, puis en la mettant en
/// commentaire: rouge les deux fois.
#[test]
fn deny_examine_les_avis_unsound_sur_tout_l_arbre() {
    let valeur = valeur_dans_advisories(&lire("deny.toml"), "unsound");
    assert_eq!(
        valeur.as_deref(),
        Some(r#""all""#),
        "deny.toml: la section [advisories] doit porter la ligne active \
         `{LIGNE_UNSOUND}`; sans elle cargo-deny n'examine les avis unsound que \
         sur les dependances directes et un crate transitif unsound passe en silence"
    );
}

/// `unused-ignored-advisory = "deny"` aussi: un ignore qui ne matche plus aucun
/// crate de l'arbre est perime, et un avertissement que personne ne lit laisse
/// la liste vieillir en silence. Le jour ou la pile netlink cesse de tirer
/// `paste`, c'est cette cle qui le dit, en rouge.
#[test]
fn deny_refuse_un_ignore_perime() {
    let valeur = valeur_dans_advisories(&lire("deny.toml"), "unused-ignored-advisory");
    assert_eq!(
        valeur.as_deref(),
        Some(r#""deny""#),
        "deny.toml: la section [advisories] doit porter la ligne active \
         `{LIGNE_IGNORE_PERIME}`, sinon un ignore perime n'est qu'un avertissement"
    );
}

/// Les deux memes lignes dans `gui/deny.toml`. Pour la coquille, `unsound =
/// "all"` est aussi ce qui fait matcher son entree glib: glib est transitif
/// (sous atk et gtk, sous tauri), et avec le defaut `workspace` cargo-deny ne
/// l'examine pas; l'entree serait alors perimee et `unused-ignored-advisory`
/// la ferait rougir, ou, sans cette cle, seul cargo-audit garderait glib.
#[test]
fn la_coquille_examine_les_avis_unsound_sur_tout_l_arbre() {
    let (fichier, _) = PAIRES[1];
    let valeur = valeur_dans_advisories(&lire(fichier), "unsound");
    assert_eq!(
        valeur.as_deref(),
        Some(r#""all""#),
        "{fichier}: la section [advisories] doit porter la ligne active \
         `{LIGNE_UNSOUND}`; sans elle cargo-deny n'examine les avis unsound que \
         sur les dependances directes et un crate transitif unsound passe en silence"
    );
}

#[test]
fn la_coquille_refuse_un_ignore_perime() {
    let (fichier, _) = PAIRES[1];
    let valeur = valeur_dans_advisories(&lire(fichier), "unused-ignored-advisory");
    assert_eq!(
        valeur.as_deref(),
        Some(r#""deny""#),
        "{fichier}: la section [advisories] doit porter la ligne active \
         `{LIGNE_IGNORE_PERIME}`, sinon un ignore perime n'est qu'un avertissement"
    );
}

/// Le temoin du lecteur de cle: une ligne commentee n'est pas un reglage, une
/// cle hors de `[advisories]` n'est pas la bonne, un commentaire de fin de
/// ligne ne change pas la valeur, et la premiere occurrence active de la
/// section l'emporte. Sans lui, un lecteur qui rendrait `"all"` sur n'importe
/// quelle occurrence ferait passer les deux recettes ci-dessus sur un fichier
/// ou la cle n'est qu'en commentaire: une garde verte parce qu'elle ne regarde
/// pas.
#[test]
fn le_lecteur_de_cle_ne_lit_que_les_lignes_actives_de_la_section() {
    let texte = r##"# unsound = "all"
[licenses]
unsound = "all"
[advisories]
# unsound = "all"
unsound = "workspace" # pas all
unsound = "all"
"##;
    assert_eq!(
        valeur_dans_advisories(texte, "unsound").as_deref(),
        Some(r#""workspace""#)
    );

    let texte = r##"[advisories]
  unsound = "all"   # examine tout l'arbre
[[licenses.exceptions]]
unsound = "none"
"##;
    assert_eq!(
        valeur_dans_advisories(texte, "unsound").as_deref(),
        Some(r#""all""#)
    );

    let texte = r##"[advisories]
# unsound = "all"
unused-ignored-advisory = "deny"
"##;
    assert_eq!(valeur_dans_advisories(texte, "unsound"), None);
    assert_eq!(
        valeur_dans_advisories(texte, "unused-ignored-advisory").as_deref(),
        Some(r#""deny""#)
    );
}
