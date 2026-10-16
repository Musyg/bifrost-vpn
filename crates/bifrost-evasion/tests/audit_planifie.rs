//! Le run planifie quotidien de la CI ne lance que l'audit des dependances, et
//! sur une base d'avis telechargee a chaque run.
//!
//! # Pourquoi cette recette existe
//!
//! Le 14/10/2026, quatre avis RustSec contre `rustls` 0.23.45 ont ete publies
//! sans que rien ne change dans le depot. La CI ne partait que sur un push, une
//! PR ou un lancement manuel: on ne les a vus qu'au premier run suivant. Depuis,
//! `.github/workflows/ci.yml` porte un declencheur `schedule:` quotidien qui ne
//! lance que le job `dependances`.
//!
//! Ce run se perd sans qu'aucun job ne rougisse, de huit facons:
//!
//! - le declencheur retire: plus aucun run planifie, et rien ne le dit;
//! - le job des dependances saute sur `schedule` par sa condition: un run
//!   planifie vert qui n'a rien juge;
//! - le meme saut par un `needs:` vers un job qui n'y tourne pas: GitHub saute
//!   un job dont un besoin est saute;
//! - un autre job qui y tourne: chaque jour des minutes de runner, et un rouge
//!   de la suite de fuite ou du fuzzing qui couvrirait celui d'un avis;
//! - un juge qui ne juge plus ce qu'il doit: un drapeau qui empeche le
//!   telechargement de la base (le run juge chaque jour sur la meme base
//!   ancienne), un argument qui ecarte un avis ou un controle (`--ignore`,
//!   `cargo deny check licenses`), un juge lance hors de son repertoire, un
//!   `git diff` de `supply-chain/` retire ou place avant `cargo vet`, un
//!   reglage de `.cargo/audit.toml` (`fetch = false`, `severity_threshold`);
//! - un juge dont l'echec ne fait plus rougir le run: `continue-on-error` sur
//!   son etape ou sur le job, un `|| true` ou une autre commande dans son
//!   etape, un `shell:` ou des `defaults:` qui retirent le `-e` du shell;
//! - une cle du job qui le retient ou change ce qu'il juge: `environment` (un
//!   environnement protege le fait attendre une approbation), `container`,
//!   `services`, `env`, `strategy`;
//! - une variable de l'`env:` du workflow, ou un reglage de `[advisories]`
//!   dans `deny.toml`, `fuzz/deny.toml` ou `gui/deny.toml`, qui deplace ou
//!   fige la base de cargo-deny (`CARGO_HOME`, `db-urls`, `db-path`,
//!   `maximum-db-staleness`).
//!
//! Et la recette elle-meme serait aveuglee par une ligne qu'elle decoderait
//! autrement que GitHub: une valeur continuee sur la ligne suivante, dont elle
//! ne lirait que le debut, un style YAML qu'elle ne connait pas, ou une regle
//! de guillemets qu'elle appliquerait de travers (`''` vaut `'` entre
//! guillemets simples, pas entre guillemets doubles). D'ou sa grammaire
//! minimale, plus bas: les seules formes que le workflow emploie, decodees
//! comme YAML les decode, et toute autre refusee.
//!
//! # Ce qu'elle exige
//!
//! 1. `on.schedule` porte exactement une entree, quotidienne, qui ne porte
//!    que `cron`: minute et heure fixes, jour du mois, mois et jour de la
//!    semaine a `*`. La minute n'est pas 0: la documentation << Events that
//!    trigger workflows >>, section `schedule` (relevee le 15/10/2026), dit que
//!    le debut de chaque heure est une periode de forte charge ou le
//!    declenchement est retarde, et ou des jobs en file peuvent etre
//!    abandonnes. `cron` seule: la meme section admet un `timezone`, qui
//!    deplacerait l'heure UTC que la recette juge.
//! 2. Le routage, evalue pour l'evenement `schedule`, lance `dependances` et
//!    aucun autre job. Un job y est lance si sa condition `if:` est vraie et
//!    si chacun de ses `needs:` y est lance: << If a job fails or is skipped,
//!    all jobs that need it are skipped >> (<< Workflow syntax for GitHub
//!    Actions >>, `jobs.<job_id>.needs`, relevee le 15/10/2026).
//! 3. Le job `dependances` porte ses juges, et ils tournent sur `schedule`:
//!    `cargo audit` a la racine et dans `gui/` (`working-directory: gui`),
//!    `cargo deny check` a la racine, dans `fuzz/` (`working-directory:
//!    fuzz`) et dans `gui/`, `cargo vet` puis le `git diff` de
//!    `supply-chain/`. Chacun a la lettre (`cargo audit -D warnings`,
//!    `cargo deny check`, `cargo vet --locked`,
//!    `git diff --exit-code -- supply-chain/`) et a sa place: `cargo audit`
//!    a la racine et dans `gui/`, `cargo deny check` a la racine, dans
//!    `fuzz/` et dans `gui/`, les autres a la racine (`working-directory` lu
//!    sous forme canonique: `./fuzz`, `fuzz/` et `./fuzz/` valent `fuzz`,
//!    `./` la racine). `gui/` est la coquille, espace de travail separe avec
//!    son propre verrou: sans ses deux juges, un avis contre la pile de la
//!    WebView ne rougirait aucun run planifie. `cargo vet --locked` et le
//!    `git diff` sont seuls dans leur etape, et dans cet ordre: vet reecrit
//!    `supply-chain/` a sa forme canonique, le diff fait echouer l'etape des
//!    qu'un octet change; place avant vet, il ne verrait pas la reecriture.
//!    Un argument de plus (`--ignore`, `--file`, `--manifest-path`, une liste
//!    de controles) changerait ce qui est juge; une graphie equivalente
//!    (`--deny warnings` pour `-D warnings`) rougit aussi, choix assume.
//!    Aucune commande `cargo audit`
//!    ou `cargo deny` du job ne porte un drapeau qui empeche le telechargement
//!    de la base ou admet une base perimee: `--no-fetch`, `-n` et `--stale`
//!    pour cargo-audit, `--offline`, `--frozen` et `--disable-fetch` pour
//!    cargo-deny.
//! 4. Le groupe `concurrency` du workflow, evalue pour chaque evenement, n'est
//!    pas le meme pour `schedule` que pour un push, une PR ou un lancement
//!    manuel. Selon << Control the concurrency of workflows and jobs >>
//!    (relevee le 15/10/2026), un run qui entre dans un groupe annule celui qui
//!    y attendait deja: un run planifie qui partagerait le groupe des push sur
//!    `main` annulerait le run d'un commit.
//! 5. L'echec d'un juge fait echouer le run. Le job `dependances` ne porte
//!    pas `continue-on-error` (regle 6), et l'etape d'un juge (`cargo audit`,
//!    `cargo deny check`, `cargo vet` et le `git diff --exit-code` qui le
//!    suit) ne le porte qu'a `false`: << Set to true to allow a job to pass
//!    when this step fails >>, << to allow a workflow run to pass when this
//!    job fails >> (meme page). L'etape d'un juge ne porte que des juges, un
//!    par ligne, sans operateur `;`, `&` ou `|`, et aucune autre cle que
//!    `name`, `id`, `if`, `run` et `working-directory`: le shell par defaut,
//!    `bash -e {0}` (meme page, `steps[*].shell`), arrete l'etape au premier
//!    juge qui echoue. Ni le workflow ni le job ne portent `defaults:`.
//! 6. Le job `dependances` ne porte que les cles qu'il porte a `69d846f`:
//!    `name`, `if`, `runs-on`, `timeout-minutes`, `steps`. Toute autre cle
//!    rougit en se nommant: `environment` (<< All deployment protection
//!    rules must pass before a job referencing the environment is sent to a
//!    runner >>, << Workflow syntax for GitHub Actions >>,
//!    `jobs.<job_id>.environment`, relevee le 15/10/2026), `container`,
//!    `services`, `permissions`, `strategy`, `env`, `concurrency`, et
//!    `needs`, `defaults` ou `continue-on-error`, qui ont en plus leur defaut
//!    propre.
//! 7. `.cargo/audit.toml`, que cargo-audit 0.22.2 lit depuis la racine ou
//!    tourne son juge (`src/commands.rs`), ne porte que des lignes vides, des
//!    commentaires, `[advisories]` et, sous lui, une seule ligne
//!    `ignore = ["RUSTSEC-AAAA-NNNN", ...]`. Toute autre ligne rougit en se
//!    nommant: `[database]` et ses `fetch = false` ou `stale = true`, la cle
//!    pointee `database.fetch = false`, `severity_threshold`, une liste
//!    `ignore` sur plusieurs lignes. `gui/.cargo/audit.toml`, que le juge de
//!    la coquille lit depuis `gui/`, est ferme de la meme facon.
//! 8. L'`env:` du workflow est celui de `69d846f`, `CARGO_TERM_COLOR:
//!    always`, et rien d'autre: une variable ajoutee, retiree ou changee
//!    rougit en se nommant. Une variable de l'`env:` du workflow atteint
//!    chaque juge; cargo-deny 0.20.2 passe la sienne au binaire `git` qui
//!    telecharge la base (`src/git.rs`): `CARGO_HOME`, `GIT_CONFIG_GLOBAL`,
//!    `PATH`. Fige par decision du 15/10/2026.
//! 9. La section `[advisories]` de `deny.toml` et de `fuzz/deny.toml` est
//!    celle de `69d846f`, a la lettre: ses lignes actives (ni vides, ni
//!    commentaires) egales a `ADVISORIES_A_69D846F`, une seule section
//!    `[advisories]`, premier en-tete du fichier, une racine sans ligne
//!    active, aucun autre en-tete sous `advisories`, aucun en-tete hors de la
//!    forme nue `[a.b]`, aucune cle `advisories...` hors de la section. Elle
//!    choisit la base de cargo-deny et dit comment la prendre (`db-urls`,
//!    `db-path`, `git-fetch-with-cli`, `maximum-db-staleness`). Fige par
//!    decision du 15/10/2026; la recette lit ces deux fichiers, elle ne les
//!    change pas. La section `[advisories]` de `gui/deny.toml` est figee de
//!    la meme facon, sous les memes regles, a `ADVISORIES_DE_LA_COQUILLE`:
//!    les cinq reglages de la racine, puis la liste des avis que la coquille
//!    ignore. Changer cette liste, c'est changer cette constante dans le meme
//!    commit.
//! 10. Les deux jobs de la coquille suivent la politique de lancement du
//!     depot: `interface-linux` tourne sur un push, une PR et un lancement
//!     manuel sans la case `windows`; `interface-windows` seulement sur un
//!     lancement manuel avec elle; aucun des deux sur `schedule`, ce que la
//!     regle 2 exige deja de tout job autre que `dependances`.
//!
//! # La grammaire qu'elle lit
//!
//! Le workflow est lu EN ENTIER contre cette grammaire, faite des seules
//! formes qu'il emploie, chacune decodee comme YAML la decode; toute ligne
//! qui en sort fait ROUGIR la recette, qui nomme la ligne et la forme. Une
//! forme legitime que le workflow n'emploie pas encore rougit aussi: c'est le
//! prix d'une lecture qui ne devine rien.
//!
//! - le texte: ASCII imprimable, lignes finies par `\n`, la derniere comprise;
//! - ligne vide; commentaire, `#` en tete de ligne, a toute indentation;
//! - indentation par espaces; chaque ligne a celle d'un bloc ouvert;
//! - `cle: valeur` sur UNE ligne; `cle` en `[A-Za-z0-9_-]`, commencant par
//!   une lettre, unique dans son mapping, et pas un mot que YAML type (`on`
//!   seule admise, au premier niveau);
//! - `valeur`, l'une de: valeur nue qui commence par une lettre, `$` ou `./`,
//!   sans `: `, et pas un mot que YAML type; `true` ou `false`; un entier
//!   `[1-9][0-9]*`; une chaine entre guillemets simples fermee sur la ligne,
//!   sans `''`; une liste `[a, b]` de mots qui commencent par une lettre;
//! - apres une valeur, un commentaire de fin de ligne (un blanc, puis `#`);
//! - `cle:` seule, sans commentaire, suivie d'un bloc plus indente: mapping,
//!   ou sequence d'entrees `- cle: valeur`, les autres cles de l'entree deux
//!   colonnes plus loin;
//! - `run: |`, sans commentaire: bloc litteral, fait des lignes qui suivent,
//!   vides ou plus indentees que `run`, chacune au moins aussi indentee que
//!   la premiere non vide; decode sans cette indentation, ses lignes vides
//!   finales retirees, une fin de ligne a la fin.
//!
//! Hors de la grammaire, donc rouges et nommes: BOM, retour chariot,
//! tabulation, caractere hors de l'ASCII imprimable, espace en fin de ligne,
//! fin de fichier sans fin de ligne; guillemets doubles; `''` entre
//! guillemets simples; mot type (`yes`, `no`, `on`, `off`, `y`, `n`, `null`,
//! `True`...), `~`, nombre hors de `[1-9][0-9]*` (octal, flottant, date,
//! base 60); valeur nue qui commence par un autre caractere; valeur nulle;
//! commentaire apres une `cle:` seule ou apres `run: |`; une valeur continuee
//! sur la ligne suivante; tout indicateur de bloc autre que `run: |` (`>`,
//! `|-`, `|+`, `>-`, `|2`, `|` sous une autre cle), ancre `&`, alias `*`,
//! etiquette `!`, cle de fusion `<<`, cle complexe `?`, mapping en ligne `{`,
//! liste vide ou autrement ecrite; marqueur de document `---` ou `...`,
//! directive `%`; cle entre guillemets, en double, qui ne commence pas par une
//! lettre; entree `- ` sans cle, ou `- cle:` qui ouvre un bloc; sequence au
//! niveau de sa cle; indentation qui ne rouvre aucun bloc.
//!
//! # Ce qu'elle ne fait pas, et ce qu'elle ne lit pas
//!
//! Elle ne declenche rien, et ne dit pas que GitHub lance le run, ni a
//! l'heure: le premier run planifie se lit apres la fusion. Elle n'evalue que
//! le sous-ensemble des expressions de GitHub dont le workflow se sert:
//! chaines, `true`, `false`, `null`, `==`, `!=`, `!`, `&&`, `||`, parentheses,
//! les fonctions de statut sans argument (le scenario: rien n'a echoue, rien
//! n'est annule), et les contextes `github.event_name`, `github.workflow`,
//! `github.ref`, `github.event.pull_request.number` et `inputs.<nom>`. Un job
//! qui a des `needs:` et appelle une fonction de statut, un besoin inconnu ou
//! circulaire, et toute autre forme font ROUGIR la recette au lieu d'etre
//! devines.
//!
//! Du workflow, au-dela de sa grammaire, elle lit `name`, les evenements de
//! `on` et l'entree de `schedule`, le groupe de `concurrency`, la presence de
//! `defaults:`, `env:` (regle 8) et `jobs`; elle ne lit ni `permissions`, ni
//! `run-name`, ni le contenu des autres evenements, ni `cancel-in-progress`.
//! Des jobs autres que `dependances`, elle ne juge que l'identifiant, `if:`
//! et `needs:` (le routage): ni leurs etapes, ni leurs autres cles. Du job
//! `dependances`, elle ferme les cles (regle 6) mais ne lit pas la valeur de
//! `name`, `runs-on` et `timeout-minutes`.
//!
//! Elle ne lit pas les etapes sans juge du job `dependances` (checkout,
//! outillage, installation de cargo-vet, SBOM): ni leurs commandes, ni leurs
//! cles, ni leurs conditions. Le checkout et l'outillage tournent avant tous
//! les juges, l'installation de cargo-vet avant `cargo vet` (apres les
//! juges cargo-audit et cargo-deny), et les deux etapes du SBOM apres le
//! dernier juge; celles qui precedent un juge peuvent ecrire dans
//! `$GITHUB_ENV`, `$GITHUB_PATH`, `.cargo/audit.toml` ou la configuration
//! git de l'hote. Porte declaree, pas fermee, par decision du 15/10/2026: la
//! fermer toucherait la recette a chaque montee d'une action epinglee ou
//! d'un outil.
//!
//! De `deny.toml`, `fuzz/deny.toml` et `gui/deny.toml`, elle ne lit que ce
//! que dit la regle 9:
//! ni `[licenses]`, ni `[bans]`, ni `[sources]`, hors des en-tetes et des cles
//! `advisories...`. Elle ne lit ni l'environnement ni la configuration git de
//! l'hote, que cargo-deny 0.20.2 passe au binaire `git`
//! (`src/advisories/helpers/db.rs`, `src/git.rs`). Elle lit sur le disque,
//! sans git.

use std::path::PathBuf;

fn racine() -> PathBuf {
    // Meme idiome que `tubes_sous_pipefail.rs` et ses voisines:
    // `CARGO_MANIFEST_DIR` pointe sur crates/bifrost-evasion, la racine de
    // l'espace de travail est deux crans au-dessus.
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

const WORKFLOW: &str = ".github/workflows/ci.yml";
const CONFIG_AUDIT: &str = ".cargo/audit.toml";

/// Le job qui porte les juges des dependances: le seul du run planifie.
const JOB_AUDIT: &str = "dependances";

/// Le nom de l'evenement du run planifie.
const PLANIFIE: &str = "schedule";

/// Les juges du job `dependances`, a la lettre. `cargo deny check` sans liste
/// lance ses quatre controles, dont `advisories`.
/// Une graphie equivalente (`cargo audit --deny warnings`) rougit aussi:
/// choix assume le 15/10/2026, plutot qu'une liste de drapeaux interdits qui
/// laisserait passer ce qu'elle n'a pas prevu.
const FORMES_DES_JUGES: [&str; 4] = [
    "cargo audit -D warnings",
    "cargo deny check",
    "cargo vet --locked",
    "git diff --exit-code -- supply-chain/",
];

/// L'etape de `cargo vet`: ces deux commandes, seules et dans cet ordre.
const PAIRE_VET: [&str; 2] = [
    "cargo vet --locked",
    "git diff --exit-code -- supply-chain/",
];

/// Les cles du job `dependances` a `69d846f`, les seules admises.
const CLES_DU_JOB_AUDIT: [&str; 5] = ["name", "if", "runs-on", "timeout-minutes", "steps"];

/// L'`env:` du workflow a `69d846f`, fige (regle 8).
const ENV_A_69D846F: [(&str, &str); 1] = [("CARGO_TERM_COLOR", "always")];

const CONFIG_DENY: &str = "deny.toml";
const CONFIG_DENY_FUZZ: &str = "fuzz/deny.toml";

/// Les lignes actives (ni vides, ni commentaires) de `[advisories]` dans
/// `deny.toml` et dans `fuzz/deny.toml` a `69d846f`: les memes dans les deux,
/// figees (regle 9).
const ADVISORIES_A_69D846F: [&str; 8] = [
    "db-urls = [\"https://github.com/rustsec/advisory-db\"]",
    "yanked = \"deny\"",
    "unmaintained = \"all\"",
    "unsound = \"all\"",
    "unused-ignored-advisory = \"deny\"",
    "ignore = [",
    "    { id = \"RUSTSEC-2024-0436\", reason = \"paste archive, proc-macro donc absent du \
     binaire livre, transitif sous wireguard-control, aucune version corrigee\" },",
    "]",
];

/// La coquille (`gui/`): un espace de travail separe, son verrou, ses deux
/// fichiers de configuration des juges.
const CONFIG_AUDIT_GUI: &str = "gui/.cargo/audit.toml";
const CONFIG_DENY_GUI: &str = "gui/deny.toml";

/// Le repertoire ou tournent les juges de la coquille, sous forme canonique.
const REPERTOIRE_GUI: &str = "gui";

/// Les lignes actives de `[advisories]` dans `gui/deny.toml`, figees (regle
/// 9): les cinq reglages de la racine, puis la liste des avis que la coquille
/// ignore, entree par entree, raison comprise. Changer la liste, c'est changer
/// cette constante dans le meme commit.
const ADVISORIES_DE_LA_COQUILLE: [&str; 14] = [
    "db-urls = [\"https://github.com/rustsec/advisory-db\"]",
    "yanked = \"deny\"",
    "unmaintained = \"all\"",
    "unsound = \"all\"",
    "unused-ignored-advisory = \"deny\"",
    "ignore = [",
    "    { id = \"RUSTSEC-2024-0370\", reason = \"2026-10-16: proc-macro-error 1.0.4 non \
     maintenu, aucune version corrigee; tire seulement par deux proc-macros de gtk-rs 0.18 \
     (glib-macros, gtk3-macros), donc execute a la construction et absent du binaire livre; \
     Linux seulement\" },",
    "    { id = \"RUSTSEC-2025-0081\", reason = \"2026-10-16: unic-char-property 0.9.0 non \
     maintenu, aucune version corrigee; tables Unicode statiques tirees par urlpattern 0.3.0 \
     sous tauri-utils 2.9.3, dans le binaire livre sur les deux plateformes\" },",
    "    { id = \"RUSTSEC-2025-0075\", reason = \"2026-10-16: unic-char-range 0.9.0 non \
     maintenu, aucune version corrigee; tables Unicode statiques tirees par urlpattern 0.3.0 \
     sous tauri-utils 2.9.3, dans le binaire livre sur les deux plateformes\" },",
    "    { id = \"RUSTSEC-2025-0080\", reason = \"2026-10-16: unic-common 0.9.0 non maintenu, \
     aucune version corrigee; tables Unicode statiques tirees par urlpattern 0.3.0 sous \
     tauri-utils 2.9.3, dans le binaire livre sur les deux plateformes\" },",
    "    { id = \"RUSTSEC-2025-0100\", reason = \"2026-10-16: unic-ucd-ident 0.9.0 non \
     maintenu, aucune version corrigee; tables Unicode statiques tirees par urlpattern 0.3.0 \
     sous tauri-utils 2.9.3, dans le binaire livre sur les deux plateformes\" },",
    "    { id = \"RUSTSEC-2025-0098\", reason = \"2026-10-16: unic-ucd-version 0.9.0 non \
     maintenu, aucune version corrigee; tables Unicode statiques tirees par urlpattern 0.3.0 \
     sous tauri-utils 2.9.3, dans le binaire livre sur les deux plateformes\" },",
    "    { id = \"RUSTSEC-2024-0429\", reason = \"2026-10-16: glib 0.18.5 unsound \
     (VariantStrIter, corrige en 0.20.0); tauri 2.x epingle toujours gtk-rs 0.18 (tauri \
     2.12.4 exige gtk ^0.18); aucune occurrence de VariantStrIter dans notre code; Linux \
     seulement; processus non privilegie\" },",
    "]",
];

/// Une section `[advisories]` figee (regle 9): ses lignes actives, et ce que
/// les messages en disent.
struct SectionFigee {
    lignes: &'static [&'static str],
    /// D'ou viennent les lignes, dans les messages.
    origine: &'static str,
    /// Pourquoi la section est figee, ajoute a chaque defaut.
    pourquoi: &'static str,
}

/// `[advisories]` de `deny.toml` et de `fuzz/deny.toml`.
const SECTION_A_69D846F: SectionFigee = SectionFigee {
    lignes: &ADVISORIES_A_69D846F,
    origine: "a `69d846f`",
    pourquoi: "la section `[advisories]` est figee a son contenu de `69d846f` (decision du \
               15/10/2026): elle choisit la base d'avis de cargo-deny et dit comment la \
               prendre (`db-urls`, `db-path`, `git-fetch-with-cli`, `maximum-db-staleness`)",
};

/// `[advisories]` de `gui/deny.toml`.
const SECTION_DE_LA_COQUILLE: SectionFigee = SectionFigee {
    lignes: &ADVISORIES_DE_LA_COQUILLE,
    origine: "de `ADVISORIES_DE_LA_COQUILLE`",
    pourquoi: "la section `[advisories]` de la coquille est figee a \
               `ADVISORIES_DE_LA_COQUILLE`: elle choisit la base d'avis de cargo-deny et dit \
               comment la prendre (`db-urls`, `db-path`, `git-fetch-with-cli`, \
               `maximum-db-staleness`), et porte la liste des avis ignores, qui ne change \
               qu'avec cette constante, dans le meme commit",
};

/// Les deux jobs de la coquille, et ou chacun tourne (regle 10).
const JOB_COQUILLE_LINUX: &str = "interface-linux";
const JOB_COQUILLE_WINDOWS: &str = "interface-windows";

/// L'`env:` du workflow tel que lu: sa ligne, et ses entrees (ligne, cle,
/// valeur), ou `None` s'il n'est pas un mapping.
type EnvDuWorkflow = Option<(usize, Option<Vec<(usize, String, Noeud)>>)>;

// ================================================================ lecture YAML

fn indentation(l: &str) -> usize {
    l.len() - l.trim_start_matches(' ').len()
}

/// Indice qui suit le guillemet fermant d'une valeur qui commence par le
/// guillemet `q`, selon YAML: `''` vaut `'` entre guillemets simples, `\`
/// echappe le caractere suivant entre guillemets doubles. Sert a trouver ou
/// commence un commentaire de fin de ligne; le decodage, lui, refuse `''` et
/// les guillemets doubles (`decoder`).
fn fin_entre_guillemets(v: &str, q: u8) -> Option<usize> {
    let o = v.as_bytes();
    let mut i = 1;
    while i < o.len() {
        match o[i] {
            b'\\' if q == b'"' => i += 2,
            b'\'' if q == b'\'' && o.get(i + 1) == Some(&b'\'') => i += 2,
            c if c == q => return Some(i + 1),
            _ => i += 1,
        }
    }
    None
}

/// Une valeur en ligne sans son commentaire de fin. En YAML, `#` ouvre un
/// commentaire en tete de valeur ou apres un blanc, et jamais entre
/// guillemets: `'37 4 * * *' # 04:37 UTC` vaut `'37 4 * * *'`.
fn sans_commentaire(v: &str) -> &str {
    let v = v.trim();
    let libre = match v.as_bytes().first() {
        Some(&q @ (b'\'' | b'"')) => fin_entre_guillemets(v, q).unwrap_or(v.len()),
        _ => 0,
    };
    let o = v.as_bytes();
    (libre..o.len())
        .find(|&i| o[i] == b'#' && (i == 0 || matches!(o[i - 1], b' ' | b'\t')))
        .map_or(v, |i| v[..i].trim_end())
}

/// Une valeur sur une ligne, decodee comme YAML la decode, dans les seules
/// formes que la grammaire admet.
#[derive(Debug, Clone, PartialEq)]
enum Scalaire {
    /// Valeur nue, ou entre guillemets simples, ou corps d'un `run: |`.
    Texte(String),
    /// `true` ou `false`, en minuscules.
    Booleen(bool),
    /// `[1-9][0-9]*`.
    Entier(u64),
    /// `[a, b]`: des mots qui commencent par une lettre.
    Liste(Vec<String>),
}

/// Les mots nus que YAML lit comme un booleen ou un nul (YAML 1.1, que suit
/// PyYAML: `y`, `yes`, `n`, `no`, `on`, `off`; YAML 1.2: `true`, `false`,
/// `null`), en toute casse. La grammaire n'admet que `true` et `false` en
/// minuscules, comme booleens.
const MOTS_TYPES: [&str; 9] = ["y", "yes", "n", "no", "on", "off", "true", "false", "null"];

fn mot_type(m: &str) -> bool {
    MOTS_TYPES.iter().any(|t| t.eq_ignore_ascii_case(m))
}

/// Decode une valeur sur une ligne, deja sans son commentaire de fin, dans
/// les seules formes que le workflow emploie: valeur nue qui commence par une
/// lettre, `$` ou `./`; `true` ou `false`; entier `[1-9][0-9]*`; chaine entre
/// guillemets simples fermee sur la ligne, sans `''`; liste `[a, b]`. Toute
/// autre forme est refusee, et nommee.
fn decoder(v: &str, n: usize) -> Result<Scalaire, String> {
    let hors = |quoi: String| Err(format!("ligne {n}: {quoi}, hors de la grammaire"));
    let Some(c) = v.chars().next() else {
        return hors("valeur vide".into());
    };
    let indicateur = match c {
        '"' => Some("guillemets doubles"),
        '&' => Some("ancre `&`"),
        '*' => Some("alias `*`"),
        '!' => Some("etiquette `!`"),
        '{' => Some("mapping en ligne `{`"),
        '|' | '>' => Some("indicateur de bloc"),
        '%' | '@' | '`' => Some("indicateur reserve"),
        '?' | ':' | ',' | ']' | '}' | '#' => Some("indicateur YAML en tete de valeur"),
        '-' if v == "-" || v.starts_with("- ") => Some("sequence en ligne apres une cle"),
        _ => None,
    };
    if let Some(quoi) = indicateur {
        return hors(format!("{quoi} (`{v}`): forme absente du workflow"));
    }
    if c == '\'' {
        return chaine_simple(v, n);
    }
    if c == '[' {
        return liste_en_ligne(v, n);
    }
    if c.is_ascii_digit() {
        return match v.parse::<u64>() {
            Ok(x) if c != '0' && v.bytes().all(|b| b.is_ascii_digit()) => Ok(Scalaire::Entier(x)),
            _ => hors(format!(
                "nombre `{v}` hors de la forme entiere `[1-9][0-9]*`: forme absente du workflow \
                 (YAML y lirait un octal, un flottant, une date ou une base 60)"
            )),
        };
    }
    if !(c.is_ascii_alphabetic() || c == '$' || v.starts_with("./")) {
        return hors(format!(
            "valeur nue qui commence par `{c}` (`{v}`): forme absente du workflow, qui ne \
             commence une valeur nue que par une lettre, `$` ou `./`"
        ));
    }
    if v.contains(": ") || v.ends_with(':') {
        return hors(format!(
            "`: ` dans une valeur nue, ou YAML verrait une cle (`{v}`)"
        ));
    }
    match v {
        "true" => Ok(Scalaire::Booleen(true)),
        "false" => Ok(Scalaire::Booleen(false)),
        _ if mot_type(v) => hors(format!(
            "`{v}`: mot que YAML lit comme un booleen ou un nul: forme absente du workflow, qui \
             n'emploie que `true` et `false`"
        )),
        _ => Ok(Scalaire::Texte(v.to_string())),
    }
}

/// Une chaine entre guillemets simples, fermee sur sa ligne, sans `''`.
fn chaine_simple(v: &str, n: usize) -> Result<Scalaire, String> {
    let o = v.as_bytes();
    let Some(i) = (1..o.len()).find(|&i| o[i] == b'\'') else {
        return Err(format!(
            "ligne {n}: chaine entre guillemets simples non fermee sur sa ligne: valeur \
             continuee, la recette ne lit que la forme sur une ligne"
        ));
    };
    if o.get(i + 1) == Some(&b'\'') {
        return Err(format!(
            "ligne {n}: `''` entre guillemets simples (`{v}`): forme absente du workflow, hors \
             de la grammaire"
        ));
    }
    if i + 1 < o.len() {
        return Err(format!(
            "ligne {n}: texte apres la chaine entre guillemets (`{v}`), hors de la grammaire"
        ));
    }
    Ok(Scalaire::Texte(v[1..i].to_string()))
}

/// Une liste en ligne `[a, b]`: au moins un mot, chacun commencant par une
/// lettre, fait de `[A-Za-z0-9_.-]` et non type par YAML, separes par `, `.
fn liste_en_ligne(v: &str, n: usize) -> Result<Scalaire, String> {
    let mot = |m: &str| {
        m.bytes().next().is_some_and(|b| b.is_ascii_alphabetic())
            && m.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
            && !mot_type(m)
    };
    match v.strip_prefix('[').and_then(|r| r.strip_suffix(']')) {
        Some(l) if l.split(", ").all(mot) => {
            Ok(Scalaire::Liste(l.split(", ").map(str::to_string).collect()))
        }
        _ => Err(format!(
            "ligne {n}: liste en ligne hors de la forme `[a, b]` (au moins un mot, qui commence \
             par une lettre, separes par `, `, sur une ligne) (`{v}`): forme absente du \
             workflow, hors de la grammaire"
        )),
    }
}

// ======================================================= grammaire du workflow

#[derive(Clone, Copy, PartialEq)]
enum Genre {
    Mapping,
    Sequence,
}

/// Un pas de chemin dans le workflow: une cle de mapping, ou le rang d'une
/// entree `- ` de sequence.
#[derive(Debug, Clone, PartialEq)]
enum Pas {
    Cle(String),
    Rang(usize),
}

/// Ce que porte une cle: une valeur decodee, ou un bloc (mapping ou
/// sequence) sur les lignes suivantes. Une entree `- ` porte un bloc: le
/// mapping qu'elle ouvre.
#[derive(Debug, Clone, PartialEq)]
enum Noeud {
    Feuille(Scalaire),
    Bloc,
}

/// Une cle du workflow, ou une entree `- ` de sequence: sa ligne, son chemin
/// depuis la racine, ce qu'elle porte. La recette ne lit le workflow qu'a
/// travers ces entrees: une valeur est decodee une fois, par `decoder`, et
/// c'est ce decodage qu'elle juge.
#[derive(Debug, Clone)]
struct Entree {
    ligne: usize,
    chemin: Vec<Pas>,
    noeud: Noeud,
}

impl Entree {
    /// La derniere cle du chemin (vide pour une entree `- `).
    fn cle(&self) -> &str {
        match self.chemin.last() {
            Some(Pas::Cle(c)) => c,
            _ => "",
        }
    }
}

/// Un bloc ouvert: son indentation, son genre, son chemin, pour un mapping
/// les cles deja vues (cle, ligne), pour une sequence le nombre d'entrees.
struct Niveau {
    indent: usize,
    genre: Genre,
    chemin: Vec<Pas>,
    cles: Vec<(String, usize)>,
    rangs: usize,
}

/// Ce que porte une `cle:`, d'apres le texte qui suit le `:`.
enum Suite {
    Valeur(Scalaire),
    Bloc,
    Litteral,
}

/// Un bloc `run: |` en cours de lecture: colonne de `run`, indentation de sa
/// premiere ligne non vide, ligne de `run`, indice de son entree, ses lignes.
struct Litteral<'a> {
    col: usize,
    premiere: Option<usize>,
    ligne: usize,
    indice: usize,
    corps: Vec<&'a str>,
}

/// `cle:` en tete du contenu d'une ligne (apres l'indentation et un `- `):
/// la cle et le texte qui suit le `:`. `None`: pas une cle de la grammaire.
/// Une cle complexe, de fusion ou entre guillemets est nommee.
fn cle_de_ligne(c: &str, n: usize) -> Result<Option<(&str, &str)>, String> {
    if c == "?" || c.starts_with("? ") {
        return Err(format!("ligne {n}: cle complexe `?`, hors de la grammaire"));
    }
    if c.strip_prefix("<<")
        .is_some_and(|r| r.trim_start().starts_with(':'))
    {
        return Err(format!(
            "ligne {n}: cle de fusion `<<`, hors de la grammaire"
        ));
    }
    if let Some(&q @ (b'\'' | b'"')) = c.as_bytes().first() {
        if fin_entre_guillemets(c, q)
            .is_some_and(|e| c[e..].trim_start_matches([' ', '\t']).starts_with(':'))
        {
            return Err(format!(
                "ligne {n}: cle entre guillemets, hors de la grammaire"
            ));
        }
        return Ok(None);
    }
    let fin = c
        .bytes()
        .position(|b| !(b.is_ascii_alphanumeric() || b == b'_' || b == b'-'))
        .unwrap_or(c.len());
    let (cle, reste) = c.split_at(fin);
    Ok(match reste.strip_prefix(':') {
        Some(apres) if !cle.is_empty() && (apres.is_empty() || apres.starts_with([' ', '\t'])) => {
            Some((cle, apres))
        }
        _ => None,
    })
}

/// Ce que porte une `cle:`, d'apres le texte qui suit le `:`. Seul `run:`
/// ouvre un bloc litteral, et seulement par `|` sans commentaire; une `cle:`
/// seule, sans commentaire, ouvre un bloc; le reste est une valeur sur la
/// ligne, que `decoder` lit ou refuse.
fn valeur_de_cle(cle: &str, brute: &str, n: usize) -> Result<Suite, String> {
    let v = sans_commentaire(brute);
    let commentee = v.len() != brute.trim().len();
    if v.is_empty() {
        return if commentee {
            Err(format!(
                "ligne {n}: commentaire apres `{cle}:` seule: forme absente du workflow, hors \
                 de la grammaire"
            ))
        } else {
            Ok(Suite::Bloc)
        };
    }
    if v.starts_with(['|', '>']) {
        return if v == "|" && cle == "run" && !commentee {
            Ok(Suite::Litteral)
        } else if v == "|" && cle == "run" {
            Err(format!(
                "ligne {n}: commentaire apres `run: |`: forme absente du workflow, hors de la \
                 grammaire"
            ))
        } else if v == "|" {
            Err(format!(
                "ligne {n}: `{cle}: |`: la grammaire ne lit un bloc litteral que sous `run:`"
            ))
        } else {
            Err(format!(
                "ligne {n}: indicateur de bloc `{v}`: la grammaire ne lit que `run: |`"
            ))
        };
    }
    decoder(v, n).map(Suite::Valeur)
}

/// Le texte avant la grammaire: ASCII imprimable et fins de ligne `\n`, rien
/// d'autre, et une fin de ligne apres la derniere ligne. Rend les lignes.
fn controler_texte(texte: &str) -> Result<Vec<&str>, String> {
    let hors = |n: usize, quoi: &str| {
        Err(format!(
            "ligne {n}: {quoi}: forme absente du workflow, hors de la grammaire"
        ))
    };
    if texte.starts_with('\u{feff}') {
        return hors(1, "BOM (U+FEFF) en tete du fichier");
    }
    let Some(corps) = texte.strip_suffix('\n') else {
        return hors(
            texte.split('\n').count(),
            "fin de fichier sans fin de ligne apres cette ligne",
        );
    };
    let lignes: Vec<&str> = corps.split('\n').collect();
    for (k, l) in lignes.iter().enumerate() {
        let n = k + 1;
        for (j, c) in l.char_indices() {
            match c {
                ' '..='~' => {}
                '\t' if l[..j].bytes().all(|b| b == b' ') => {
                    return Err(format!(
                        "ligne {n}: tabulation dans l'indentation, hors de la grammaire"
                    ));
                }
                '\t' => return hors(n, "tabulation dans la ligne"),
                '\r' => return hors(n, "retour chariot (CR)"),
                autre => {
                    return hors(
                        n,
                        &format!(
                            "caractere U+{:04X} hors de l'ASCII imprimable",
                            u32::from(autre)
                        ),
                    );
                }
            }
        }
        if l.ends_with(' ') {
            return hors(n, "espace en fin de ligne");
        }
    }
    Ok(lignes)
}

/// Le corps d'un `run: |` comme YAML le lit (style litteral, fin << clip >>):
/// l'indentation de sa premiere ligne retiree de chaque ligne, les lignes
/// vides de la fin retirees, une seule fin de ligne a la fin.
fn fermer_litteral(b: Litteral, entrees: &mut [Entree]) -> Result<(), String> {
    let Some(p) = b.premiere else {
        return Err(format!(
            "ligne {}: bloc `run: |` vide: forme absente du workflow, hors de la grammaire",
            b.ligne
        ));
    };
    let mut lignes: Vec<&str> = b
        .corps
        .iter()
        .map(|l| if l.is_empty() { "" } else { &l[p..] })
        .collect();
    while lignes.last() == Some(&"") {
        lignes.pop();
    }
    entrees[b.indice].noeud = Noeud::Feuille(Scalaire::Texte(lignes.join("\n") + "\n"));
    Ok(())
}

/// Lit tout le workflow contre la grammaire de l'en-tete: une entree par cle
/// et par entree `- `, dans l'ordre du texte, chaque valeur decodee par
/// `decoder`. `Err` nomme la premiere ligne qui sort de la grammaire, et sa
/// forme.
fn lire_yaml(texte: &str) -> Result<Vec<Entree>, String> {
    let lignes = controler_texte(texte)?;
    let mut entrees: Vec<Entree> = Vec::new();
    let mut pile: Vec<Niveau> = Vec::new();
    // Apres une `cle:` seule: (colonne de la cle, sa ligne, son chemin).
    let mut ouverte: Option<(usize, usize, Vec<Pas>)> = None;
    let mut litteral: Option<Litteral> = None;
    let mut precedente = 0;
    for (k, l) in lignes.iter().enumerate() {
        let n = k + 1;
        if let Some(b) = litteral.as_mut() {
            if l.is_empty() {
                b.corps.push(l);
                continue;
            }
            let i = indentation(l);
            if i > b.col {
                match b.premiere {
                    None => b.premiere = Some(i),
                    Some(p) if i < p => {
                        return Err(format!(
                            "ligne {n}: moins indentee que la premiere ligne de son bloc \
                             `run: |`, hors de la grammaire"
                        ));
                    }
                    Some(_) => {}
                }
                b.corps.push(l);
                continue;
            }
            if let Some(fini) = litteral.take() {
                fermer_litteral(fini, &mut entrees)?;
            }
        }
        let i = indentation(l);
        let t = &l[i..];
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        if i == 0 {
            for marque in ["---", "..."] {
                if t == marque || t.starts_with(&format!("{marque} ")) {
                    return Err(format!(
                        "ligne {n}: marqueur de document `{marque}`, hors de la grammaire"
                    ));
                }
            }
            if t.starts_with('%') {
                return Err(format!("ligne {n}: directive `%`, hors de la grammaire"));
            }
        }
        let tiret = t == "-" || t.starts_with("- ");
        if let Some((col, de, chemin)) = ouverte.take() {
            if i > col {
                pile.push(Niveau {
                    indent: i,
                    genre: if tiret {
                        Genre::Sequence
                    } else {
                        Genre::Mapping
                    },
                    chemin,
                    cles: Vec::new(),
                    rangs: 0,
                });
            } else if i == col && tiret {
                return Err(format!(
                    "ligne {n}: sequence au niveau de sa cle (ligne {de}): la grammaire la \
                     veut plus indentee"
                ));
            } else {
                return Err(valeur_nulle(de));
            }
        }
        let avant = pile.len();
        while pile.last().is_some_and(|p| p.indent > i) {
            pile.pop();
        }
        if pile.is_empty() {
            if i > 0 {
                return Err(format!("ligne {n}: premiere ligne indentee"));
            }
            pile.push(Niveau {
                indent: 0,
                genre: Genre::Mapping,
                chemin: Vec::new(),
                cles: Vec::new(),
                rangs: 0,
            });
        }
        let (indent, genre) = pile
            .last()
            .map(|p| (p.indent, p.genre))
            .unwrap_or((0, Genre::Mapping));
        if indent < i {
            return Err(if pile.len() < avant {
                format!("ligne {n}: indentation {i} qui ne rouvre aucun bloc, hors de la grammaire")
            } else {
                format!(
                    "ligne {n}: valeur continuee de la ligne {precedente}: la recette ne lit \
                     que la forme sur une ligne"
                )
            });
        }
        precedente = n;
        let (contenu, col) = if tiret {
            if genre != Genre::Sequence {
                return Err(format!("ligne {n}: entree `- ` dans un mapping"));
            }
            let reste = t[1..].strip_prefix(' ').unwrap_or("");
            if reste.is_empty() || reste.starts_with(' ') {
                return Err(format!(
                    "ligne {n}: entree `-` vide ou suivie de plusieurs blancs, hors de la \
                     grammaire"
                ));
            }
            if reste == "-" || reste.starts_with("- ") {
                return Err(format!(
                    "ligne {n}: sequence dans une sequence sur une ligne, hors de la grammaire"
                ));
            }
            // L'entree ouvre le mapping de ses cles, deux colonnes plus loin.
            let sequence = pile.last_mut().expect("une sequence ouverte");
            let mut chemin = sequence.chemin.clone();
            chemin.push(Pas::Rang(sequence.rangs));
            sequence.rangs += 1;
            entrees.push(Entree {
                ligne: n,
                chemin: chemin.clone(),
                noeud: Noeud::Bloc,
            });
            pile.push(Niveau {
                indent: i + 2,
                genre: Genre::Mapping,
                chemin,
                cles: Vec::new(),
                rangs: 0,
            });
            (reste, i + 2)
        } else {
            if genre != Genre::Mapping {
                return Err(format!("ligne {n}: cle sans `- ` dans une sequence"));
            }
            (t, i)
        };
        let Some((cle, brute)) = cle_de_ligne(contenu, n)? else {
            return Err(if tiret {
                format!(
                    "ligne {n}: entree `- ` sans `cle:` (`{contenu}`): forme absente du \
                     workflow, hors de la grammaire"
                )
            } else {
                format!(
                    "ligne {n}: ni `cle: valeur`, ni `cle:`, ni `- `, ni commentaire: hors de \
                     la grammaire"
                )
            });
        };
        let mapping = pile.last_mut().expect("un mapping ouvert");
        if !cle.starts_with(|c: char| c.is_ascii_alphabetic()) {
            return Err(format!(
                "ligne {n}: cle `{cle}` qui ne commence pas par une lettre: forme absente du \
                 workflow, hors de la grammaire"
            ));
        }
        if mot_type(cle) && !(cle == "on" && mapping.chemin.is_empty()) {
            return Err(format!(
                "ligne {n}: cle `{cle}`: mot que YAML lit comme un booleen ou un nul; seule `on` \
                 est admise, au premier niveau, ou GitHub la lit comme son nom (<< Workflow \
                 syntax for GitHub Actions >>, section `on`), hors de la grammaire"
            ));
        }
        if let Some((_, deja)) = mapping.cles.iter().find(|(c, _)| c == cle) {
            return Err(format!(
                "ligne {n}: cle `{cle}` en double dans le meme mapping (deja ligne {deja})"
            ));
        }
        mapping.cles.push((cle.to_string(), n));
        let mut chemin = mapping.chemin.clone();
        chemin.push(Pas::Cle(cle.to_string()));
        match valeur_de_cle(cle, brute, n)? {
            Suite::Valeur(s) => entrees.push(Entree {
                ligne: n,
                chemin,
                noeud: Noeud::Feuille(s),
            }),
            Suite::Bloc if tiret => {
                return Err(format!(
                    "ligne {n}: entree `- {cle}:` qui ouvre un bloc: forme absente du \
                     workflow, hors de la grammaire"
                ));
            }
            Suite::Bloc => {
                entrees.push(Entree {
                    ligne: n,
                    chemin: chemin.clone(),
                    noeud: Noeud::Bloc,
                });
                ouverte = Some((col, n, chemin));
            }
            Suite::Litteral => {
                entrees.push(Entree {
                    ligne: n,
                    chemin,
                    noeud: Noeud::Feuille(Scalaire::Texte(String::new())),
                });
                litteral = Some(Litteral {
                    col,
                    premiere: None,
                    ligne: n,
                    indice: entrees.len() - 1,
                    corps: Vec::new(),
                });
            }
        }
    }
    if let Some(fini) = litteral.take() {
        fermer_litteral(fini, &mut entrees)?;
    }
    if let Some((_, de, _)) = ouverte {
        return Err(valeur_nulle(de));
    }
    Ok(entrees)
}

fn valeur_nulle(de: usize) -> String {
    format!(
        "ligne {de}: `cle:` seule, sans bloc plus indente apres elle (valeur nulle): forme \
         absente du workflow, hors de la grammaire"
    )
}

fn chemin(cles: &[&str]) -> Vec<Pas> {
    cles.iter().map(|c| Pas::Cle((*c).to_string())).collect()
}

/// L'entree d'un chemin, s'il existe.
fn trouver<'a>(arbre: &'a [Entree], chemin: &[Pas]) -> Option<&'a Entree> {
    arbre.iter().find(|e| e.chemin == chemin)
}

/// Les entrees directement sous un chemin, dans l'ordre du texte.
fn enfants<'a>(arbre: &'a [Entree], parent: &[Pas]) -> Vec<&'a Entree> {
    arbre
        .iter()
        .filter(|e| e.chemin.len() == parent.len() + 1 && e.chemin.starts_with(parent))
        .collect()
}

/// Ce que porte une entree, pour un message.
fn montrer(n: &Noeud) -> String {
    match n {
        Noeud::Feuille(Scalaire::Texte(s)) => s.clone(),
        Noeud::Feuille(Scalaire::Booleen(b)) => b.to_string(),
        Noeud::Feuille(Scalaire::Entier(x)) => x.to_string(),
        Noeud::Feuille(Scalaire::Liste(l)) => format!("[{}]", l.join(", ")),
        Noeud::Bloc => "un bloc".to_string(),
    }
}

/// Le texte d'une valeur: une chaine, ou un booleen ou un entier tels
/// qu'ecrits. Une liste ou un bloc la ou la recette attend une valeur la font
/// rougir.
fn texte(e: &Entree) -> Result<String, String> {
    match &e.noeud {
        Noeud::Feuille(Scalaire::Liste(_)) | Noeud::Bloc => Err(format!(
            "ligne {}: `{}:` porte {}, la ou la recette attend une valeur sur la ligne",
            e.ligne,
            e.cle(),
            montrer(&e.noeud)
        )),
        autre => Ok(montrer(autre)),
    }
}

#[derive(Debug, Default)]
struct Etape {
    ligne: usize,
    nom: String,
    si: Option<String>,
    run: Option<String>,
    repertoire: Option<String>,
    /// (ligne, cle, valeur) de chaque cle de l'etape.
    cles: Vec<(usize, String, Noeud)>,
}

#[derive(Debug, Default)]
struct Job {
    id: String,
    ligne: usize,
    si: Option<String>,
    /// Les jobs de `needs:`.
    besoins: Vec<String>,
    /// (ligne, valeur) de `continue-on-error:`.
    continuer: Option<(usize, Noeud)>,
    /// Ligne de `defaults:`.
    defaults: Option<usize>,
    /// (ligne, cle) de chaque cle du job.
    cles: Vec<(usize, String)>,
    etapes: Vec<Etape>,
}

#[derive(Debug, Default)]
struct Workflow {
    nom: String,
    evenements: Vec<String>,
    /// (ligne, expression) de chaque entree `cron` de `on.schedule`.
    crons: Vec<(usize, String)>,
    /// (ligne, cle) des cles d'une entree de `on.schedule` autres que `cron`.
    autres_cles_du_schedule: Vec<(usize, String)>,
    /// `concurrency.group` du workflow, ou `concurrency` sous forme de chaine.
    groupe: Option<String>,
    /// Ligne de `defaults:` au premier niveau.
    defaults: Option<usize>,
    env: EnvDuWorkflow,
    jobs: Vec<Job>,
}

/// Les entrees `cron` de `on.schedule`, et les autres cles de ses entrees.
type Schedule = (Vec<(usize, String)>, Vec<(usize, String)>);

fn lire_crons(arbre: &[Entree], schedule: &Entree) -> Result<Schedule, String> {
    let mut crons = Vec::new();
    let mut autres = Vec::new();
    for entree in enfants(arbre, &schedule.chemin) {
        if !matches!(entree.chemin.last(), Some(Pas::Rang(_))) {
            return Err(format!(
                "ligne {}: entree de `schedule` sans `- `",
                entree.ligne
            ));
        }
        let mut cron = None;
        for c in enfants(arbre, &entree.chemin) {
            if c.cle() == "cron" {
                cron = Some((c.ligne, texte(c)?));
            } else {
                autres.push((c.ligne, c.cle().to_string()));
            }
        }
        crons.push(
            cron.ok_or_else(|| {
                format!("ligne {}: entree de `schedule` sans `cron`", entree.ligne)
            })?,
        );
    }
    Ok((crons, autres))
}

fn lire_etapes(arbre: &[Entree], steps: &Entree) -> Result<Vec<Etape>, String> {
    if steps.noeud != Noeud::Bloc {
        return Err(format!(
            "ligne {}: `steps:` en ligne, la recette ne lit que la forme en blocs",
            steps.ligne
        ));
    }
    let mut etapes = Vec::new();
    for entree in enfants(arbre, &steps.chemin) {
        if !matches!(entree.chemin.last(), Some(Pas::Rang(_))) {
            return Err(format!("ligne {}: etape sans `- `", entree.ligne));
        }
        let mut etape = Etape {
            ligne: entree.ligne,
            ..Etape::default()
        };
        for c in enfants(arbre, &entree.chemin) {
            etape
                .cles
                .push((c.ligne, c.cle().to_string(), c.noeud.clone()));
            match c.cle() {
                "name" => etape.nom = texte(c)?,
                "if" => etape.si = Some(texte(c)?),
                "working-directory" => {
                    etape.repertoire = Some(normaliser_repertoire(&texte(c)?));
                }
                // Le corps d'un `run: |` finit deja par une fin de ligne; une
                // valeur sur la ligne en recoit une.
                "run" => {
                    let mut corps = texte(c)?;
                    if !corps.ends_with('\n') {
                        corps.push('\n');
                    }
                    etape.run = Some(corps);
                }
                _ => {}
            }
        }
        etapes.push(etape);
    }
    Ok(etapes)
}

/// `working-directory` sous sa forme canonique: une graphie de chemin n'est
/// pas un argument de juge. `./fuzz`, `fuzz/` et `./fuzz/` valent `fuzz`;
/// `./` et `.` valent la racine `.`. Un chemin absolu (`/`, `/x`) reste tel
/// quel, et n'est donc la place d'aucun juge.
fn normaliser_repertoire(r: &str) -> String {
    let mut r = r.trim();
    loop {
        let avant = r;
        r = r.strip_prefix("./").unwrap_or(r);
        if r.len() > 1 {
            r = r.strip_suffix('/').unwrap_or(r);
        }
        if r == avant {
            break;
        }
    }
    if r.is_empty() || r == "." {
        ".".to_string()
    } else {
        r.to_string()
    }
}

/// `needs:` d'un job: un nom, ou une liste `[a, b]` (une liste en blocs est
/// hors de la grammaire). Toute autre forme est refusee.
fn lire_besoins(e: &Entree) -> Result<Vec<String>, String> {
    let illisible = |quoi: &str| format!("ligne {}: `needs:` {quoi}", e.ligne);
    let noms: Vec<String> = match &e.noeud {
        Noeud::Feuille(Scalaire::Texte(s)) => vec![s.clone()],
        Noeud::Feuille(Scalaire::Liste(l)) => l.clone(),
        autre => return Err(illisible(&montrer(autre))),
    };
    let nom_de_job = |n: &String| {
        !n.is_empty()
            && n.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    };
    if !noms.iter().all(nom_de_job) {
        return Err(illisible(&format!(
            "{noms:?}: un nom de job attendu par entree"
        )));
    }
    Ok(noms)
}

/// Les cles du workflow que la recette juge, lues dans les entrees de
/// `lire_yaml`, donc une fois le workflow entier lu contre la grammaire.
fn lire_workflow(texte_du_workflow: &str) -> Result<Workflow, String> {
    let arbre = lire_yaml(texte_du_workflow)?;
    let mut wf = Workflow::default();
    if let Some(e) = trouver(&arbre, &chemin(&["name"])) {
        wf.nom = texte(e)?;
    }

    let on = trouver(&arbre, &chemin(&["on"])).ok_or("aucune cle `on:` au premier niveau")?;
    if on.noeud != Noeud::Bloc {
        return Err(format!(
            "ligne {}: `on:` en ligne, la recette ne lit que la forme en blocs",
            on.ligne
        ));
    }
    for evenement in enfants(&arbre, &on.chemin) {
        wf.evenements.push(evenement.cle().to_string());
        if evenement.cle() == PLANIFIE {
            if evenement.noeud != Noeud::Bloc {
                return Err(format!(
                    "ligne {}: `schedule:` en ligne, la recette ne lit que la forme en blocs",
                    evenement.ligne
                ));
            }
            (wf.crons, wf.autres_cles_du_schedule) = lire_crons(&arbre, evenement)?;
        }
    }

    if let Some(c) = trouver(&arbre, &chemin(&["concurrency"])) {
        wf.groupe = if c.noeud == Noeud::Bloc {
            trouver(&arbre, &chemin(&["concurrency", "group"]))
                .map(texte)
                .transpose()?
        } else {
            Some(texte(c)?)
        };
    }

    wf.defaults = trouver(&arbre, &chemin(&["defaults"])).map(|e| e.ligne);

    if let Some(e) = trouver(&arbre, &chemin(&["env"])) {
        let entrees = (e.noeud == Noeud::Bloc).then(|| {
            enfants(&arbre, &e.chemin)
                .into_iter()
                .map(|c| (c.ligne, c.cle().to_string(), c.noeud.clone()))
                .collect()
        });
        wf.env = Some((e.ligne, entrees));
    }

    let jobs = trouver(&arbre, &chemin(&["jobs"])).ok_or("aucune cle `jobs:` au premier niveau")?;
    for dj in enfants(&arbre, &jobs.chemin) {
        if dj.noeud != Noeud::Bloc {
            return Err(format!(
                "ligne {}: job `{}` en ligne, la recette ne lit que la forme en blocs",
                dj.ligne,
                dj.cle()
            ));
        }
        let mut job = Job {
            id: dj.cle().to_string(),
            ligne: dj.ligne,
            ..Job::default()
        };
        for c in enfants(&arbre, &dj.chemin) {
            job.cles.push((c.ligne, c.cle().to_string()));
            match c.cle() {
                "if" => job.si = Some(texte(c)?),
                "needs" => job.besoins = lire_besoins(c)?,
                "continue-on-error" => job.continuer = Some((c.ligne, c.noeud.clone())),
                "defaults" => job.defaults = Some(c.ligne),
                "steps" => job.etapes = lire_etapes(&arbre, c)?,
                _ => {}
            }
        }
        wf.jobs.push(job);
    }
    Ok(wf)
}

// ========================================================= expressions GitHub

#[derive(Debug, Clone, PartialEq)]
enum Valeur {
    Nul,
    Booleen(bool),
    Chaine(String),
}

/// Vrai au sens d'une condition: `null`, `false` et `''` sont faux
/// (<< Evaluate expressions in workflows and actions >>, relevee le
/// 15/10/2026). Les nombres ne sont pas admis par la recette.
fn vrai(v: &Valeur) -> bool {
    match v {
        Valeur::Nul => false,
        Valeur::Booleen(b) => *b,
        Valeur::Chaine(s) => !s.is_empty(),
    }
}

fn en_texte(v: &Valeur) -> String {
    match v {
        Valeur::Nul => String::new(),
        Valeur::Booleen(b) => b.to_string(),
        Valeur::Chaine(s) => s.clone(),
    }
}

#[derive(Debug, Clone, PartialEq)]
enum Jeton {
    Ouvrante,
    Fermante,
    Non,
    Et,
    Ou,
    Egal,
    Different,
    Chaine(String),
    Mot(String),
}

fn jetons(texte: &str) -> Result<Vec<Jeton>, String> {
    let s: Vec<char> = texte.chars().collect();
    let mut i = 0;
    let mut sortie = Vec::new();
    while let Some(&c) = s.get(i) {
        let suivant = s.get(i + 1).copied();
        match c {
            ' ' | '\t' => i += 1,
            '(' => {
                sortie.push(Jeton::Ouvrante);
                i += 1;
            }
            ')' => {
                sortie.push(Jeton::Fermante);
                i += 1;
            }
            '!' if suivant == Some('=') => {
                sortie.push(Jeton::Different);
                i += 2;
            }
            '!' => {
                sortie.push(Jeton::Non);
                i += 1;
            }
            '=' if suivant == Some('=') => {
                sortie.push(Jeton::Egal);
                i += 2;
            }
            '&' if suivant == Some('&') => {
                sortie.push(Jeton::Et);
                i += 2;
            }
            '|' if suivant == Some('|') => {
                sortie.push(Jeton::Ou);
                i += 2;
            }
            '\'' => {
                let mut chaine = String::new();
                i += 1;
                loop {
                    match s.get(i).copied() {
                        None => return Err("chaine jamais refermee".into()),
                        Some('\'') if s.get(i + 1) == Some(&'\'') => {
                            chaine.push('\'');
                            i += 2;
                        }
                        Some('\'') => {
                            i += 1;
                            break;
                        }
                        Some(x) => {
                            chaine.push(x);
                            i += 1;
                        }
                    }
                }
                sortie.push(Jeton::Chaine(chaine));
            }
            c if c.is_ascii_alphabetic() || c == '_' => {
                let d = i;
                while s
                    .get(i)
                    .is_some_and(|x| x.is_ascii_alphanumeric() || matches!(x, '_' | '.' | '-'))
                {
                    i += 1;
                }
                sortie.push(Jeton::Mot(s[d..i].iter().collect()));
            }
            autre => {
                return Err(format!(
                    "`{autre}`: operateur ou litteral que la recette ne sait pas evaluer"
                ));
            }
        }
    }
    Ok(sortie)
}

#[derive(Debug)]
enum Expr {
    Valeur(Valeur),
    Contexte(String),
    Non(Box<Expr>),
    Et(Box<Expr>, Box<Expr>),
    Ou(Box<Expr>, Box<Expr>),
    Compare(Box<Expr>, Box<Expr>, bool),
}

/// Descente recursive, avec les priorites de GitHub: `!`, puis `==` et `!=`,
/// puis `&&`, puis `||`.
struct Analyseur {
    jetons: Vec<Jeton>,
    i: usize,
}

impl Analyseur {
    fn suivant(&self) -> Option<&Jeton> {
        self.jetons.get(self.i)
    }

    fn ou(&mut self) -> Result<Expr, String> {
        let mut g = self.et()?;
        while self.suivant() == Some(&Jeton::Ou) {
            self.i += 1;
            g = Expr::Ou(Box::new(g), Box::new(self.et()?));
        }
        Ok(g)
    }

    fn et(&mut self) -> Result<Expr, String> {
        let mut g = self.egalite()?;
        while self.suivant() == Some(&Jeton::Et) {
            self.i += 1;
            g = Expr::Et(Box::new(g), Box::new(self.egalite()?));
        }
        Ok(g)
    }

    fn egalite(&mut self) -> Result<Expr, String> {
        let mut g = self.unaire()?;
        loop {
            let egal = match self.suivant() {
                Some(Jeton::Egal) => true,
                Some(Jeton::Different) => false,
                _ => return Ok(g),
            };
            self.i += 1;
            g = Expr::Compare(Box::new(g), Box::new(self.unaire()?), egal);
        }
    }

    fn unaire(&mut self) -> Result<Expr, String> {
        if self.suivant() == Some(&Jeton::Non) {
            self.i += 1;
            return Ok(Expr::Non(Box::new(self.unaire()?)));
        }
        self.primaire()
    }

    fn primaire(&mut self) -> Result<Expr, String> {
        let jeton = self.suivant().cloned().ok_or("expression incomplete")?;
        self.i += 1;
        match jeton {
            Jeton::Ouvrante => {
                let e = self.ou()?;
                if self.suivant() != Some(&Jeton::Fermante) {
                    return Err("parenthese jamais refermee".into());
                }
                self.i += 1;
                Ok(e)
            }
            Jeton::Chaine(c) => Ok(Expr::Valeur(Valeur::Chaine(c))),
            Jeton::Mot(m) if self.suivant() == Some(&Jeton::Ouvrante) => {
                self.i += 1;
                if self.suivant() != Some(&Jeton::Fermante) {
                    return Err(format!(
                        "`{m}(...)`: la recette n'evalue que les fonctions de statut, sans argument"
                    ));
                }
                self.i += 1;
                // Le scenario de la recette: rien n'a echoue, rien n'est annule.
                match m.as_str() {
                    "success" | "always" => Ok(Expr::Valeur(Valeur::Booleen(true))),
                    "failure" | "cancelled" => Ok(Expr::Valeur(Valeur::Booleen(false))),
                    _ => Err(format!(
                        "fonction `{m}()` que la recette ne sait pas evaluer"
                    )),
                }
            }
            Jeton::Mot(m) => match m.as_str() {
                "true" => Ok(Expr::Valeur(Valeur::Booleen(true))),
                "false" => Ok(Expr::Valeur(Valeur::Booleen(false))),
                "null" => Ok(Expr::Valeur(Valeur::Nul)),
                "github.event_name"
                | "github.workflow"
                | "github.ref"
                | "github.event.pull_request.number" => Ok(Expr::Contexte(m)),
                _ if m
                    .strip_prefix("inputs.")
                    .is_some_and(|n| !n.is_empty() && !n.contains('.')) =>
                {
                    Ok(Expr::Contexte(m))
                }
                _ => Err(format!("contexte `{m}` que la recette ne sait pas evaluer")),
            },
            autre => Err(format!("{autre:?} inattendu")),
        }
    }
}

fn analyser_expression(texte: &str) -> Result<Expr, String> {
    let mut a = Analyseur {
        jetons: jetons(texte)?,
        i: 0,
    };
    if a.jetons.is_empty() {
        return Err("expression vide".into());
    }
    let e = a.ou()?;
    if let Some(reste) = a.suivant() {
        return Err(format!("{reste:?} en trop apres l'expression"));
    }
    Ok(e)
}

/// Un evenement, et ce que GitHub met dans les contextes que la recette lit.
struct Scenario {
    nom: &'static str,
    evenement: &'static str,
    reference: &'static str,
    numero_pr: Option<&'static str>,
    windows: Option<bool>,
}

/// Les evenements du workflow, chacun sur `main` sauf la PR. Le run planifie
/// part sur le dernier commit de la branche par defaut (<< Events that
/// trigger workflows >>, section `schedule`).
static SCENARIOS: [Scenario; 5] = [
    Scenario {
        nom: "push",
        evenement: "push",
        reference: "refs/heads/main",
        numero_pr: None,
        windows: None,
    },
    Scenario {
        nom: "pull_request",
        evenement: "pull_request",
        reference: "refs/pull/1/merge",
        numero_pr: Some("1"),
        windows: None,
    },
    Scenario {
        nom: PLANIFIE,
        evenement: PLANIFIE,
        reference: "refs/heads/main",
        numero_pr: None,
        windows: None,
    },
    Scenario {
        nom: "workflow_dispatch windows=false",
        evenement: "workflow_dispatch",
        reference: "refs/heads/main",
        numero_pr: None,
        windows: Some(false),
    },
    Scenario {
        nom: "workflow_dispatch windows=true",
        evenement: "workflow_dispatch",
        reference: "refs/heads/main",
        numero_pr: None,
        windows: Some(true),
    },
];

fn scenario(nom: &str) -> &'static Scenario {
    SCENARIOS
        .iter()
        .find(|s| s.nom == nom)
        .unwrap_or_else(|| panic!("scenario `{nom}` inconnu"))
}

fn contexte(chemin: &str, s: &Scenario, workflow: &str) -> Valeur {
    match chemin {
        "github.event_name" => Valeur::Chaine(s.evenement.into()),
        "github.workflow" => Valeur::Chaine(workflow.into()),
        "github.ref" => Valeur::Chaine(s.reference.into()),
        "github.event.pull_request.number" => s
            .numero_pr
            .map_or(Valeur::Nul, |n| Valeur::Chaine(n.into())),
        // `inputs` n'existe que pour un lancement manuel; ailleurs, une
        // propriete absente vaut `null`.
        _ => match (chemin.strip_prefix("inputs."), s.windows) {
            (Some("windows"), Some(w)) => Valeur::Booleen(w),
            _ => Valeur::Nul,
        },
    }
}

fn evaluer(e: &Expr, s: &Scenario, workflow: &str) -> Result<Valeur, String> {
    Ok(match e {
        Expr::Valeur(v) => v.clone(),
        Expr::Contexte(c) => contexte(c, s, workflow),
        Expr::Non(x) => Valeur::Booleen(!vrai(&evaluer(x, s, workflow)?)),
        Expr::Et(a, b) => {
            let va = evaluer(a, s, workflow)?;
            if vrai(&va) {
                evaluer(b, s, workflow)?
            } else {
                va
            }
        }
        Expr::Ou(a, b) => {
            let va = evaluer(a, s, workflow)?;
            if vrai(&va) {
                va
            } else {
                evaluer(b, s, workflow)?
            }
        }
        Expr::Compare(a, b, egal) => {
            let (g, d) = (evaluer(a, s, workflow)?, evaluer(b, s, workflow)?);
            // GitHub ignore la casse en comparant des chaines (meme page).
            let pareil = match (&g, &d) {
                (Valeur::Chaine(x), Valeur::Chaine(y)) => x.eq_ignore_ascii_case(y),
                (Valeur::Booleen(x), Valeur::Booleen(y)) => x == y,
                (Valeur::Nul, Valeur::Nul) => true,
                _ => {
                    return Err(format!(
                        "comparaison de {g:?} a {d:?}: GitHub convertirait les deux en \
                         nombres, la recette ne le fait pas"
                    ));
                }
            };
            Valeur::Booleen(pareil == *egal)
        }
    })
}

/// Une condition `if:`, avec ou sans `${{ }}`. Sans fonction de statut, GitHub
/// la precede de `success() &&`; dans le scenario de la recette, `success()`
/// est vrai, donc rien ne change.
fn evaluer_condition(texte: &str, s: &Scenario, workflow: &str) -> Result<bool, String> {
    let t = texte.trim();
    let t = t
        .strip_prefix("${{")
        .and_then(|x| x.strip_suffix("}}"))
        .unwrap_or(t);
    Ok(vrai(&evaluer(&analyser_expression(t)?, s, workflow)?))
}

/// Une condition qui appelle une fonction (`success()`, `always()`...).
fn appelle_une_fonction(texte: &str) -> Result<bool, String> {
    let t = texte.trim();
    let t = t
        .strip_prefix("${{")
        .and_then(|x| x.strip_suffix("}}"))
        .unwrap_or(t);
    Ok(jetons(t)?
        .windows(2)
        .any(|w| matches!(w, [Jeton::Mot(_), Jeton::Ouvrante])))
}

fn resoudre(
    i: usize,
    jobs: &[Job],
    propre: &[bool],
    etat: &mut [u8],
    lance: &mut [bool],
) -> Result<bool, String> {
    match etat[i] {
        2 => return Ok(lance[i]),
        1 => return Err(format!("job `{}`: `needs:` circulaire", jobs[i].id)),
        _ => {}
    }
    etat[i] = 1;
    let mut oui = propre[i];
    for n in &jobs[i].besoins {
        let k = jobs.iter().position(|j| &j.id == n).ok_or_else(|| {
            format!(
                "job `{}` (ligne {}): `needs: {n}`, job inconnu",
                jobs[i].id, jobs[i].ligne
            )
        })?;
        oui &= resoudre(k, jobs, propre, etat, lance)?;
    }
    etat[i] = 2;
    lance[i] = oui;
    Ok(oui)
}

/// Pour un scenario, les jobs lances, `needs:` compris: << If a job fails or
/// is skipped, all jobs that need it are skipped unless the jobs use a
/// conditional expression that causes the job to continue >> (<< Workflow
/// syntax for GitHub Actions >>, `jobs.<job_id>.needs`, relevee le
/// 15/10/2026). Dans le scenario de la recette rien n'echoue: un besoin lance
/// reussit. Un job qui a des besoins et appelle une fonction de statut est
/// refuse: la recette ne modele pas l'etat de ses besoins.
fn routage(jobs: &[Job], s: &Scenario, nom: &str) -> Result<Vec<bool>, String> {
    let mut propre = Vec::new();
    for j in jobs {
        let si = j.si.as_deref().unwrap_or("success()");
        let erreur = |e: String| format!("job `{}` (ligne {}), `if: {si}`: {e}", j.id, j.ligne);
        if !j.besoins.is_empty() && j.si.is_some() && appelle_une_fonction(si).map_err(erreur)? {
            return Err(erreur(
                "fonction de statut et `needs:`: la recette ne modele pas l'etat des besoins"
                    .into(),
            ));
        }
        propre.push(evaluer_condition(si, s, nom).map_err(erreur)?);
    }
    let mut etat = vec![0u8; jobs.len()];
    let mut lance = vec![false; jobs.len()];
    for i in 0..jobs.len() {
        resoudre(i, jobs, &propre, &mut etat, &mut lance)?;
    }
    Ok(lance)
}

/// Une chaine qui porte des `${{ expression }}`, comme `concurrency.group`.
fn interpoler(modele: &str, s: &Scenario, workflow: &str) -> Result<String, String> {
    let mut sortie = String::new();
    let mut reste = modele;
    while let Some(d) = reste.find("${{") {
        sortie.push_str(&reste[..d]);
        let apres = &reste[d + 3..];
        let f = apres.find("}}").ok_or("`${{` jamais referme")?;
        let v = evaluer(&analyser_expression(&apres[..f])?, s, workflow)?;
        sortie.push_str(&en_texte(&v));
        reste = &apres[f + 2..];
    }
    sortie.push_str(reste);
    Ok(sortie)
}

// ==================================================================== jugement

/// `minute heure * * *`, minute et heure fixes, minute non nulle.
fn cron_quotidien(cron: &str) -> Result<(), String> {
    let champs: Vec<&str> = cron.split_whitespace().collect();
    let &[minute, heure, jour, mois, semaine] = champs.as_slice() else {
        return Err(format!("{} champ(s), cinq attendus", champs.len()));
    };
    let fixe = |c: &str, max: u32| {
        !c.is_empty()
            && c.bytes().all(|b| b.is_ascii_digit())
            && c.parse::<u32>().is_ok_and(|n| n <= max)
    };
    if !fixe(minute, 59) {
        return Err("la minute doit etre un nombre fixe, de 0 a 59".into());
    }
    if !fixe(heure, 23) {
        return Err("l'heure doit etre un nombre fixe, de 0 a 23: un run par jour".into());
    }
    if [jour, mois, semaine].iter().any(|c| *c != "*") {
        return Err(
            "jour du mois, mois et jour de la semaine doivent etre `*`: un run chaque jour".into(),
        );
    }
    if minute.parse::<u32>() == Ok(0) {
        return Err(
            "minute 0: le debut de chaque heure est une periode de forte charge, ou \
                    GitHub retarde le declenchement et peut abandonner des jobs en file"
                .into(),
        );
    }
    Ok(())
}

fn est_affectation(mot: &str) -> bool {
    let Some((nom, _)) = mot.split_once('=') else {
        return false;
    };
    let mut octets = nom.bytes();
    matches!(octets.next(), Some(b) if b.is_ascii_alphabetic() || b == b'_')
        && octets.all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// Les commandes simples d'un corps `run:`, en mots: continuations jointes,
/// commentaires retires, coupe aux sauts de ligne, `;`, `&` et `|`. Assez pour
/// reperer une commande `cargo` et ses drapeaux; ce n'est pas un lexeur shell
/// (celui du depot est dans `tubes_sous_pipefail.rs`).
fn commandes(corps: &str) -> Vec<Vec<String>> {
    let mut sortie = Vec::new();
    for ligne in lignes_actives(corps) {
        for morceau in ligne.split([';', '&', '|']) {
            let mots: Vec<String> = morceau.split_whitespace().map(str::to_string).collect();
            if !mots.is_empty() {
                sortie.push(mots);
            }
        }
    }
    sortie
}

/// Les lignes d'un corps `run:`, continuations jointes, sans lignes vides ni
/// commentaires.
fn lignes_actives(corps: &str) -> Vec<String> {
    corps
        .replace("\\\n", " ")
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.find(" #").map_or(l, |k| &l[..k]).trim_end().to_string())
        .collect()
}

/// `git diff ... --exit-code ...`: le juge qui suit `cargo vet`.
fn est_git_diff_juge(mots: &[String]) -> bool {
    let Some(k) = mots.iter().position(|m| !est_affectation(m)) else {
        return false;
    };
    mots[k] == "git"
        && mots.get(k + 1).map(String::as_str) == Some("diff")
        && mots.iter().any(|m| m == "--exit-code")
}

/// `cargo <sous-commande> ...`: la sous-commande et tous les autres mots,
/// drapeaux de cargo places avant elle compris.
fn commande_cargo(mots: &[String]) -> Option<(&str, Vec<&str>)> {
    let k = mots.iter().position(|m| !est_affectation(m))?;
    if mots[k].rsplit('/').next() != Some("cargo") {
        return None;
    }
    let reste = &mots[k + 1..];
    let pos = reste
        .iter()
        .position(|m| !m.starts_with('-') && !m.starts_with('+'))?;
    let autres = reste
        .iter()
        .enumerate()
        .filter(|(j, _)| *j != pos)
        .map(|(_, m)| m.as_str())
        .collect();
    Some((reste[pos].as_str(), autres))
}

/// Les drapeaux qui font juger sur une base non telechargee ou perimee.
/// cargo-audit 0.22.2: `-n`/`--no-fetch`, `--stale` (`src/commands/audit.rs`).
/// cargo-deny 0.20.2: `--offline`, et `--frozen`, qui le vaut
/// (`src/cargo-deny/main.rs`, lignes 151-152); `--disable-fetch`, que sa
/// documentation (`checks/advisories/cfg.md`) nomme encore.
fn drapeaux_qui_figent_la_base(sous_commande: &str, mots: &[&str]) -> Vec<String> {
    mots.iter()
        .filter(|m| match sous_commande {
            "audit" => {
                matches!(**m, "--no-fetch" | "--stale")
                    || (m.len() > 1
                        && m.starts_with('-')
                        && !m.starts_with("--")
                        && m[1..].bytes().all(|b| b.is_ascii_alphabetic())
                        && m.contains('n'))
            }
            "deny" => matches!(**m, "--offline" | "--frozen" | "--disable-fetch"),
            _ => false,
        })
        .map(|m| m.to_string())
        .collect()
}

/// `ignore = ["RUSTSEC-AAAA-NNNN", ...]` sur une ligne, sans commentaire.
fn est_liste_ignore(actif: &str) -> bool {
    let id = |m: &str| {
        let Some(m) = m
            .strip_prefix("\"RUSTSEC-")
            .and_then(|m| m.strip_suffix('"'))
        else {
            return false;
        };
        let o = m.as_bytes();
        o.len() == 9
            && o[4] == b'-'
            && o.iter()
                .enumerate()
                .all(|(i, b)| i == 4 || b.is_ascii_digit())
    };
    let Some(liste) = actif
        .strip_prefix("ignore")
        .map(str::trim_start)
        .and_then(|r| r.strip_prefix('='))
        .map(str::trim)
        .and_then(|r| r.strip_prefix('['))
        .and_then(|r| r.strip_suffix(']'))
    else {
        return false;
    };
    let mots: Vec<&str> = liste.split(',').map(str::trim).collect();
    // Une virgule finale laisse un dernier mot vide.
    let mots = match mots.split_last() {
        Some((&"", reste)) => reste,
        _ => &mots[..],
    };
    mots.iter().all(|m| id(m))
}

/// `.cargo/audit.toml` (ou celui de la coquille, `fichier`), ferme: lignes
/// vides, commentaires, `[advisories]` une fois et, sous lui, une ligne
/// `ignore = [...]` une fois. Toute autre ligne est un defaut qui la nomme.
fn defauts_de_la_config_audit(fichier: &str, config: &str) -> Vec<String> {
    let mut defauts = Vec::new();
    let mut dans_advisories = false;
    let (mut advisories_vue, mut ignore_vu) = (false, false);
    for (k, ligne) in config.lines().enumerate() {
        let t = ligne.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let actif = t.split('#').next().unwrap_or("").trim_end();
        let admise = if actif == "[advisories]" && !advisories_vue {
            advisories_vue = true;
            dans_advisories = true;
            true
        } else if dans_advisories && !ignore_vu && est_liste_ignore(actif) {
            ignore_vu = true;
            true
        } else {
            dans_advisories &= !actif.starts_with('[');
            false
        };
        if !admise {
            defauts.push(format!(
                "{fichier}, ligne {}: `{t}`: hors des formes admises (ligne vide, \
                 commentaire, `[advisories]`, puis `ignore = [\"RUSTSEC-AAAA-NNNN\", ...]` \
                 sur une ligne): la recette ne juge pas ce qu'elle regle a cargo-audit \
                 (`fetch = false` ou `stale = true` sous `[database]`, et \
                 `database.fetch = false`, figent la base)",
                k + 1
            ));
        }
    }
    defauts
}

/// Un en-tete de table TOML sous forme nue, `[a.b]` ou `[[a.b]]`, sans blanc,
/// guillemet ni commentaire: son chemin. `None`: une autre forme.
fn en_tete_nu(t: &str) -> Option<&str> {
    let c = t
        .strip_prefix("[[")
        .and_then(|r| r.strip_suffix("]]"))
        .or_else(|| t.strip_prefix('[').and_then(|r| r.strip_suffix(']')))?;
    c.split('.')
        .all(|p| {
            !p.is_empty()
                && p.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        })
        .then_some(c)
}

/// `[advisories]` d'un fichier de cargo-deny, fige (regle 9): a son contenu
/// de `69d846f` pour `deny.toml` et `fuzz/deny.toml`, a
/// `ADVISORIES_DE_LA_COQUILLE` pour `gui/deny.toml`. Ses lignes actives, ni
/// vides ni commentaires, sont comparees a la lettre a celles de `section`;
/// la racine du fichier, avant tout en-tete, n'a aucune ligne active;
/// `[advisories]` est le premier en-tete et le seul de son nom; aucun autre
/// en-tete ne commence par `advisories`; tout en-tete est sous forme nue;
/// aucune ligne active hors de la section ne commence par `advisories`,
/// entre guillemets ou non. Toute autre ligne est un defaut qui la nomme.
fn defauts_de_deny(fichier: &str, texte_du_fichier: &str, section: &SectionFigee) -> Vec<String> {
    let fige = section.pourquoi;
    let origine = section.origine;
    let attendues = section.lignes;
    let mut defauts = Vec::new();
    // None: avant tout en-tete; Some(true): dans `[advisories]`; Some(false):
    // dans une autre table.
    let mut dans: Option<bool> = None;
    let mut vue = false;
    let mut actives: Vec<(usize, &str)> = Vec::new();
    for (k, ligne) in texte_du_fichier.lines().enumerate() {
        let n = k + 1;
        let t = ligne.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        if t.starts_with('[') {
            if t == "[advisories]" && !vue && dans.is_none() {
                vue = true;
                dans = Some(true);
                continue;
            }
            dans = Some(false);
            match en_tete_nu(t) {
                None => defauts.push(format!(
                    "{fichier}, ligne {n}: en-tete `{t}` hors de la forme nue `[a.b]` ou \
                     `[[a.b]]` (blanc, guillemet ou commentaire): la recette ne lit pas ce qu'il \
                     designe; {fige}"
                )),
                Some(c) if c == "advisories" || c.starts_with("advisories.") => {
                    let quoi = if t != "[advisories]" {
                        "table sous `advisories` hors de la section"
                    } else if vue {
                        "seconde section `[advisories]`"
                    } else {
                        "`[advisories]` n'est pas le premier en-tete du fichier"
                    };
                    defauts.push(format!("{fichier}, ligne {n}: `{t}`: {quoi}; {fige}"));
                }
                Some(_) => {}
            }
            continue;
        }
        match dans {
            None => defauts.push(format!(
                "{fichier}, ligne {n}: `{t}`: ligne active avant `[advisories]`, dont la racine \
                 est vide {origine} (une cle pointee `advisories.<x>` ou une table en ligne y \
                 reglerait la base); {fige}"
            )),
            Some(true) => actives.push((n, ligne)),
            Some(false) => {
                if ["advisories", "\"advisories", "'advisories"]
                    .iter()
                    .any(|a| t.starts_with(a))
                {
                    defauts.push(format!(
                        "{fichier}, ligne {n}: `{t}`: cle `advisories` hors de sa section; {fige}"
                    ));
                }
            }
        }
    }
    if !vue {
        defauts.push(format!(
            "{fichier}: aucune section `[advisories]` en tete du fichier; {fige}"
        ));
        return defauts;
    }
    let vues: Vec<&str> = actives.iter().map(|(_, l)| *l).collect();
    if vues != attendues {
        let avant = defauts.len();
        for (n, l) in &actives {
            if !attendues.contains(l) {
                defauts.push(format!(
                    "{fichier}, ligne {n}: `{}` n'est pas une ligne de la section {origine}; \
                     {fige}",
                    l.trim()
                ));
            }
        }
        for attendue in attendues {
            if !vues.contains(attendue) {
                defauts.push(format!(
                    "{fichier}: `{}` retiree de la section `[advisories]`; {fige}",
                    attendue.trim()
                ));
            }
        }
        if defauts.len() == avant {
            defauts.push(format!(
                "{fichier}: lignes de la section `[advisories]` deplacees ou en double; {fige}"
            ));
        }
    }
    defauts
}

/// L'`env:` du workflow, fige a `CARGO_TERM_COLOR: always` (regle 8): une
/// variable y atteint chaque juge.
fn defauts_de_l_env(env: &EnvDuWorkflow) -> Vec<String> {
    let fige = "l'`env:` du workflow est fige a son contenu de `69d846f`, `CARGO_TERM_COLOR: \
                always` (decision du 15/10/2026): une variable y atteint chaque juge \
                (`CARGO_HOME`, `GIT_CONFIG_GLOBAL`, `PATH`...)";
    let Some((ligne, entrees)) = env else {
        return vec![format!("`env:` du workflow absent; {fige}")];
    };
    let Some(entrees) = entrees else {
        return vec![format!(
            "ligne {ligne}: `env:` du workflow n'est pas un mapping; {fige}"
        )];
    };
    let mut defauts = Vec::new();
    for (l, cle, v) in entrees {
        match ENV_A_69D846F.iter().find(|(c, _)| c == cle) {
            None => defauts.push(format!(
                "ligne {l}: `{cle}: {}` ajoutee a l'`env:` du workflow; {fige}",
                montrer(v)
            )),
            Some((_, attendue)) if *v != Noeud::Feuille(Scalaire::Texte((*attendue).into())) => {
                defauts.push(format!(
                    "ligne {l}: `{cle}: {}` dans l'`env:` du workflow, au lieu de `{cle}: \
                     {attendue}`; {fige}",
                    montrer(v)
                ));
            }
            Some(_) => {}
        }
    }
    for (cle, attendue) in ENV_A_69D846F {
        if !entrees.iter().any(|(_, c, _)| c == cle) {
            defauts.push(format!(
                "`{cle}: {attendue}` retiree de l'`env:` du workflow; {fige}"
            ));
        }
    }
    defauts
}

#[derive(Debug)]
struct Rapport {
    defauts: Vec<String>,
    /// Pour chaque scenario, les jobs dont la condition est vraie.
    table: Vec<(&'static str, Vec<String>)>,
}

/// Les fichiers de configuration que la recette lit, a cote du workflow.
struct Configs<'a> {
    audit: &'a str,
    deny: &'a str,
    deny_fuzz: &'a str,
    audit_gui: &'a str,
    deny_gui: &'a str,
}

/// Juge un workflow et les configurations des juges. `Err`: un texte que la
/// recette ne sait pas lire, ce qui la fait rougir aussi.
fn juger(texte: &str, configs: &Configs) -> Result<Rapport, String> {
    let wf = lire_workflow(texte)?;
    let nom = if wf.nom.is_empty() {
        WORKFLOW
    } else {
        wf.nom.as_str()
    };
    // Controle positif: un workflow mal lu rendrait zero job, donc zero
    // defaut de routage.
    if wf.jobs.len() < 2 {
        return Err(format!(
            "{} job(s) lu(s): la lecture du workflow est cassee",
            wf.jobs.len()
        ));
    }
    let mut defauts = Vec::new();

    // 1. Le declencheur.
    if !wf.evenements.iter().any(|e| e == PLANIFIE) {
        defauts.push("`on.schedule` absent: aucun run planifie, et rien ne le dit".to_string());
    } else if wf.crons.len() != 1 {
        defauts.push(format!(
            "`on.schedule` porte {} entree(s) `cron`; la recette en attend une, quotidienne",
            wf.crons.len()
        ));
    }
    for (ligne, cron) in &wf.crons {
        if let Err(e) = cron_quotidien(cron) {
            defauts.push(format!("ligne {ligne}: cron `{cron}`: {e}"));
        }
    }
    for (ligne, cle) in &wf.autres_cles_du_schedule {
        defauts.push(format!(
            "ligne {ligne}: `{cle}:` dans l'entree de `schedule`, qui ne porte que `cron`: \
             la recette ne juge que l'heure UTC du cron (un `timezone` la deplacerait)"
        ));
    }

    // 2. Le routage, pour chaque evenement, `needs:` compris.
    let mut table = Vec::new();
    for s in &SCENARIOS {
        let lance = routage(&wf.jobs, s, nom)?;
        let ids: Vec<String> = wf
            .jobs
            .iter()
            .zip(&lance)
            .filter(|(_, l)| **l)
            .map(|(j, _)| j.id.clone())
            .collect();
        table.push((s.nom, ids));
    }
    let planifies: Vec<String> = table
        .iter()
        .find(|(n, _)| *n == PLANIFIE)
        .map(|(_, l)| l.clone())
        .unwrap_or_default();
    let job_audit = wf.jobs.iter().find(|j| j.id == JOB_AUDIT);
    if !planifies.iter().any(|j| j == JOB_AUDIT) {
        // Saute par sa condition, ou par un besoin saute.
        let besoins_sautes: Vec<&str> = job_audit
            .map(|j| {
                j.besoins
                    .iter()
                    .filter(|n| !planifies.contains(n))
                    .map(String::as_str)
                    .collect()
            })
            .unwrap_or_default();
        let condition_vraie = job_audit.is_some_and(|j| {
            evaluer_condition(
                j.si.as_deref().unwrap_or("success()"),
                scenario(PLANIFIE),
                nom,
            ) == Ok(true)
        });
        if condition_vraie && !besoins_sautes.is_empty() {
            defauts.push(format!(
                "le job `{JOB_AUDIT}` est saute sur `schedule` par `needs:`: {} n'y tourne \
                 pas, et GitHub saute un job dont un besoin est saute",
                besoins_sautes.join(", ")
            ));
        } else {
            defauts.push(format!(
                "le job `{JOB_AUDIT}` est saute sur `schedule` (ou absent): le run planifie \
                 serait vert sans avoir rien juge"
            ));
        }
    }
    let intrus: Vec<&str> = planifies
        .iter()
        .map(String::as_str)
        .filter(|j| *j != JOB_AUDIT)
        .collect();
    if !intrus.is_empty() {
        defauts.push(format!(
            "job(s) qui tournent sur `schedule` en plus de `{JOB_AUDIT}`: {}. Leur condition \
             doit commencer par `github.event_name != 'schedule' &&`",
            intrus.join(", ")
        ));
    }

    // 3. Les juges du job des dependances, et la fraicheur de la base.
    // 5. Un juge qui echoue fait echouer le run.
    if let Some(job) = job_audit {
        let planifie = scenario(PLANIFIE);
        // 6. Le job ne porte que ses cles de 69d846f.
        for (l, cle) in &job.cles {
            if !CLES_DU_JOB_AUDIT.contains(&cle.as_str()) {
                defauts.push(format!(
                    "job `{JOB_AUDIT}`, ligne {l}: `{cle}:` n'est pas une cle du job a \
                     `69d846f` ({}): la recette ne juge pas ce qu'elle change au run \
                     planifie (un `environment` protege le fait attendre une approbation), \
                     refusee plutot que devinee",
                    CLES_DU_JOB_AUDIT.map(|c| format!("`{c}`")).join(", ")
                ));
            }
        }
        for (ou, ligne) in [("du workflow", wf.defaults), ("du job", job.defaults)] {
            if let Some(l) = ligne {
                defauts.push(format!(
                    "ligne {l}: `defaults:` {ou}: il peut changer le shell (`bash -e` par \
                     defaut) ou le repertoire des etapes des juges, que la recette ne juge \
                     que sans lui"
                ));
            }
        }
        if let Some((l, v)) = &job.continuer
            && *v != Noeud::Feuille(Scalaire::Booleen(false))
        {
            defauts.push(format!(
                "job `{JOB_AUDIT}`, ligne {l}: `continue-on-error: {}`: un echec du job ne \
                 ferait plus echouer le run",
                montrer(v)
            ));
        }
        let (mut audit, mut deny_racine, mut deny_fuzz, mut vet) = (false, false, false, false);
        let (mut audit_gui, mut deny_gui) = (false, false);
        let mut vet_puis_diff = false;
        for e in &job.etapes {
            let Some(corps) = &e.run else { continue };
            let si = e.si.as_deref().unwrap_or("success()");
            let tourne = evaluer_condition(si, planifie, nom)
                .map_err(|x| format!("etape `{}` (ligne {}), `if: {si}`: {x}", e.nom, e.ligne))?;
            let repertoire = e.repertoire.as_deref().unwrap_or(".");
            let racine = repertoire == ".";
            let mut juges = Vec::new();
            let mut etrangeres = Vec::new();
            // L'ordre des commandes de l'etape, et la place de `cargo vet` et
            // du `git diff` qui le juge.
            let mut ordre = Vec::new();
            let (mut i_vet, mut i_diff) = (None, None);
            for mots in commandes(corps) {
                let texte = mots.join(" ");
                ordre.push(texte.clone());
                if est_git_diff_juge(&mots) {
                    i_diff = i_diff.or(Some(ordre.len() - 1));
                    if !tourne {
                        defauts.push(format!(
                            "etape `{}` (ligne {}): `git diff --exit-code` y est saute sur \
                             `schedule`",
                            e.nom, e.ligne
                        ));
                    }
                    juges.push((texte, racine));
                    continue;
                }
                let Some((sous, autres)) = commande_cargo(&mots) else {
                    etrangeres.push(texte);
                    continue;
                };
                // Ou chaque juge a sa place: `cargo audit` a la racine et dans
                // `gui/`, `cargo deny check` a la racine, dans `fuzz/` et dans
                // `gui/`, les autres a la racine seulement.
                let gui = repertoire == REPERTOIRE_GUI;
                let juge = match sous {
                    "audit" => {
                        audit |= tourne && racine;
                        audit_gui |= tourne && gui;
                        Some(racine || gui)
                    }
                    "deny" if autres.contains(&"check") => {
                        deny_racine |= tourne && racine;
                        deny_fuzz |= tourne && repertoire == "fuzz";
                        deny_gui |= tourne && gui;
                        Some(racine || repertoire == "fuzz" || gui)
                    }
                    "vet" => {
                        vet |= tourne && racine;
                        i_vet = i_vet.or(Some(ordre.len() - 1));
                        Some(racine)
                    }
                    _ => None,
                };
                match juge {
                    Some(a_sa_place) => juges.push((texte, a_sa_place)),
                    None => etrangeres.push(texte),
                }
                if juge.is_some() && !tourne {
                    defauts.push(format!(
                        "etape `{}` (ligne {}): `cargo {sous}` y est saute sur `schedule`",
                        e.nom, e.ligne
                    ));
                }
                let figes = drapeaux_qui_figent_la_base(sous, &autres);
                if !figes.is_empty() {
                    defauts.push(format!(
                        "etape `{}` (ligne {}): `cargo {sous}` porte {}: la base d'avis n'est \
                         plus telechargee, ou une base perimee est admise",
                        e.nom,
                        e.ligne,
                        figes.join(" ")
                    ));
                }
            }
            if juges.is_empty() {
                continue;
            }
            // `cargo vet --locked` reecrit `supply-chain/` a sa forme
            // canonique; le `git diff` qui suit fait echouer l'etape des
            // qu'un octet change. Avant vet, il ne voit pas cette reecriture.
            if let Some(v) = i_vet {
                let attendu = format!("`{}` puis `{}`", PAIRE_VET[0], PAIRE_VET[1]);
                match i_diff {
                    None => defauts.push(format!(
                        "etape `{}` (ligne {}): aucun `{}` apres `cargo vet`: la reecriture \
                         canonique de `supply-chain/` par vet n'est plus jugee",
                        e.nom, e.ligne, PAIRE_VET[1]
                    )),
                    Some(d) if d < v => defauts.push(format!(
                        "etape `{}` (ligne {}): `{}` avant `cargo vet`: il ne voit pas la \
                         reecriture que vet fait ensuite",
                        e.nom, e.ligne, PAIRE_VET[1]
                    )),
                    Some(_) if ordre.len() != 2 => defauts.push(format!(
                        "etape `{}` (ligne {}): {} commandes; l'etape de `cargo vet` ne porte \
                         que {attendu}",
                        e.nom,
                        e.ligne,
                        ordre.len()
                    )),
                    Some(_) => {}
                }
                vet_puis_diff |= tourne && racine && ordre == PAIRE_VET;
            }
            for (j, a_sa_place) in &juges {
                if !a_sa_place {
                    defauts.push(format!(
                        "etape `{}` (ligne {}): `{j}` lance dans `{repertoire}`: il y jugerait \
                         un autre espace de travail que celui qu'il doit juger",
                        e.nom, e.ligne
                    ));
                }
                if !FORMES_DES_JUGES.contains(&j.as_str()) {
                    defauts.push(format!(
                        "etape `{}` (ligne {}): `{j}`: forme que la recette ne connait pas pour \
                         un juge (elle admet {}); un argument de plus peut changer ce qui est \
                         juge: `--ignore`, `--file`, `--manifest-path`, une liste de controles",
                        e.nom,
                        e.ligne,
                        FORMES_DES_JUGES.map(|f| format!("`{f}`")).join(", ")
                    ));
                }
            }
            // L'etape d'un juge: des juges seuls, un par ligne, sous le shell
            // par defaut `bash -e {0}`, qui arrete l'etape au premier echec
            // (<< Workflow syntax for GitHub Actions >>, `steps[*].shell`,
            // relevee le 15/10/2026).
            if let Some(l) = lignes_actives(corps)
                .iter()
                .find(|l| l.contains([';', '&', '|']))
            {
                defauts.push(format!(
                    "etape `{}` (ligne {}): `{l}`: un operateur shell dans l'etape d'un juge \
                     peut avaler son code de sortie (`|| true`, `; true`)",
                    e.nom, e.ligne
                ));
            }
            for c in &etrangeres {
                defauts.push(format!(
                    "etape `{}` (ligne {}): `{c}` n'est pas un juge: l'etape d'un juge ne porte \
                     que des juges, un par ligne",
                    e.nom, e.ligne
                ));
            }
            for (l, cle, v) in &e.cles {
                match cle.as_str() {
                    "name" | "id" | "if" | "run" | "working-directory" => {}
                    "continue-on-error" if *v == Noeud::Feuille(Scalaire::Booleen(false)) => {}
                    "continue-on-error" => defauts.push(format!(
                        "etape `{}`, ligne {l}: `continue-on-error: {}`: un echec du juge ne \
                         ferait plus echouer le job, ni le run",
                        e.nom,
                        montrer(v)
                    )),
                    _ => defauts.push(format!(
                        "etape `{}`, ligne {l}: `{cle}:` sur l'etape d'un juge: la recette ne \
                         juge pas ce que cette cle change a son verdict (`shell:` peut retirer \
                         `-e`), refusee plutot que devinee",
                        e.nom
                    )),
                }
            }
        }
        for (present, quoi) in [
            (audit, "`cargo audit`"),
            (deny_racine, "`cargo deny check` a la racine"),
            (
                deny_fuzz,
                "`cargo deny check` dans `fuzz/` (`working-directory: fuzz`)",
            ),
            (
                audit_gui,
                "`cargo audit` dans `gui/` (`working-directory: gui`)",
            ),
            (
                deny_gui,
                "`cargo deny check` dans `gui/` (`working-directory: gui`)",
            ),
            (vet, "`cargo vet`"),
            (
                vet_puis_diff,
                "`cargo vet --locked` puis `git diff --exit-code -- supply-chain/`, seuls et dans \
                 cet ordre dans une meme etape a la racine,",
            ),
        ] {
            if !present {
                defauts.push(format!(
                    "{quoi} ne tourne pas dans le job `{JOB_AUDIT}` sur `schedule`"
                ));
            }
        }
    }
    // 7. Les deux configurations de cargo-audit, fermees.
    defauts.extend(defauts_de_la_config_audit(CONFIG_AUDIT, configs.audit));
    defauts.extend(defauts_de_la_config_audit(
        CONFIG_AUDIT_GUI,
        configs.audit_gui,
    ));
    // 8. L'`env:` du workflow, fige.
    defauts.extend(defauts_de_l_env(&wf.env));
    // 9. `[advisories]` des trois fichiers de cargo-deny, figee.
    defauts.extend(defauts_de_deny(
        CONFIG_DENY,
        configs.deny,
        &SECTION_A_69D846F,
    ));
    defauts.extend(defauts_de_deny(
        CONFIG_DENY_FUZZ,
        configs.deny_fuzz,
        &SECTION_A_69D846F,
    ));
    defauts.extend(defauts_de_deny(
        CONFIG_DENY_GUI,
        configs.deny_gui,
        &SECTION_DE_LA_COQUILLE,
    ));

    // 4. Le groupe de concurrence du run planifie.
    if let Some(groupe) = &wf.groupe {
        let du_planifie = interpoler(groupe, scenario(PLANIFIE), nom)?;
        for s in SCENARIOS.iter().filter(|s| s.nom != PLANIFIE) {
            let autre = interpoler(groupe, s, nom)?;
            // Le nom d'un groupe ignore la casse (meme page).
            if autre.eq_ignore_ascii_case(&du_planifie) {
                defauts.push(format!(
                    "le run planifie et `{}` partagent le groupe de concurrence `{autre}`: \
                     l'un annulerait l'autre",
                    s.nom
                ));
            }
        }
    }

    Ok(Rapport { defauts, table })
}

// ==================================================================== recettes

#[test]
fn le_run_planifie_ne_lance_que_l_audit_sur_une_base_fraiche() {
    let (audit, deny, deny_fuzz, audit_gui, deny_gui) = (
        lire(CONFIG_AUDIT),
        lire(CONFIG_DENY),
        lire(CONFIG_DENY_FUZZ),
        lire(CONFIG_AUDIT_GUI),
        lire(CONFIG_DENY_GUI),
    );
    let configs = Configs {
        audit: &audit,
        deny: &deny,
        deny_fuzz: &deny_fuzz,
        audit_gui: &audit_gui,
        deny_gui: &deny_gui,
    };
    let rapport = juger(&lire(WORKFLOW), &configs)
        .unwrap_or_else(|e| panic!("{WORKFLOW} illisible pour la recette: {e}"));
    for (quoi, jobs) in &rapport.table {
        println!("audit_planifie: {quoi}: {}", jobs.join(", "));
    }
    assert!(
        rapport.defauts.is_empty(),
        "{} defaut(s) du run planifie de {WORKFLOW}:\n  {}",
        rapport.defauts.len(),
        rapport.defauts.join("\n  ")
    );
}

/// Ou tournent les deux jobs de la coquille, d'apres le routage du workflow
/// reel (regle 10): Linux a chaque push, PR et lancement manuel sans la case
/// `windows`; Windows seulement sur un lancement manuel avec elle; aucun des
/// deux sur `schedule`.
fn defauts_des_jobs_de_la_coquille(table: &[(&'static str, Vec<String>)]) -> Vec<String> {
    let mut defauts = Vec::new();
    for (job, ou) in [
        (
            JOB_COQUILLE_LINUX,
            ["push", "pull_request", "workflow_dispatch windows=false"].as_slice(),
        ),
        (
            JOB_COQUILLE_WINDOWS,
            ["workflow_dispatch windows=true"].as_slice(),
        ),
    ] {
        let vus: Vec<&str> = table
            .iter()
            .filter(|(_, jobs)| jobs.iter().any(|j| j == job))
            .map(|(s, _)| *s)
            .collect();
        if vus != ou {
            defauts.push(format!(
                "le job `{job}` tourne sur [{}], la politique de lancement du depot le veut \
                 sur [{}]",
                vus.join(", "),
                ou.join(", ")
            ));
        }
    }
    defauts
}

#[test]
fn les_jobs_de_la_coquille_suivent_la_politique_de_lancement() {
    let (audit, deny, deny_fuzz, audit_gui, deny_gui) = (
        lire(CONFIG_AUDIT),
        lire(CONFIG_DENY),
        lire(CONFIG_DENY_FUZZ),
        lire(CONFIG_AUDIT_GUI),
        lire(CONFIG_DENY_GUI),
    );
    let configs = Configs {
        audit: &audit,
        deny: &deny,
        deny_fuzz: &deny_fuzz,
        audit_gui: &audit_gui,
        deny_gui: &deny_gui,
    };
    let rapport = juger(&lire(WORKFLOW), &configs)
        .unwrap_or_else(|e| panic!("{WORKFLOW} illisible pour la recette: {e}"));
    let defauts = defauts_des_jobs_de_la_coquille(&rapport.table);
    assert!(
        defauts.is_empty(),
        "{} defaut(s) du routage de la coquille dans {WORKFLOW}:\n  {}",
        defauts.len(),
        defauts.join("\n  ")
    );
}

/// Un workflow de la forme de celui du depot, sain. Les falsifications plus
/// bas en partent.
const TEMOIN: &str = "\
name: ci
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  # un commentaire entre deux evenements
  schedule:
    - cron: '37 4 * * *'
  workflow_dispatch:
    inputs:
      windows:
        type: boolean
        default: false
concurrency:
  group: ${{ github.workflow }}-${{ github.event_name }}-${{ github.event.pull_request.number || github.ref }}
  cancel-in-progress: true
env:
  CARGO_TERM_COLOR: always
jobs:
  controles:
    if: github.event_name != 'schedule' && (github.event_name != 'workflow_dispatch' || !inputs.windows)
    runs-on: ubuntu-24.04
    steps:
      - run: cargo test
  windows:
    if: github.event_name == 'workflow_dispatch' && inputs.windows
    runs-on: windows-2025
    concurrency:
      group: ${{ github.workflow }}-windows
    steps:
      - run: cargo test
  interface-linux:
    if: github.event_name != 'schedule' && (github.event_name != 'workflow_dispatch' || !inputs.windows)
    runs-on: ubuntu-24.04
    steps:
      - run: cargo test --manifest-path gui/Cargo.toml --locked
  interface-windows:
    if: github.event_name == 'workflow_dispatch' && inputs.windows
    runs-on: windows-2025-vs2026
    steps:
      - run: cargo test --manifest-path gui/Cargo.toml --locked
  dependances:
    if: github.event_name != 'workflow_dispatch' || !inputs.windows
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@0 # v1
      - name: Avis
        run: cargo audit -D warnings
      - name: Licences
        run: cargo deny check
      - name: Licences du harnais
        working-directory: fuzz
        run: cargo deny check
      - name: Avis de la coquille
        working-directory: gui
        run: cargo audit -D warnings
      - name: Licences de la coquille
        working-directory: gui
        run: cargo deny check
      # commentaire entre deux etapes
      - name: Vet
        run: |
          cargo vet --locked
          git diff --exit-code -- supply-chain/
      - name: SBOM
        if: github.event_name != 'schedule'
        run: cargo cyclonedx
";

const CONFIG_TEMOIN: &str = "[advisories]\nignore = [\"RUSTSEC-2024-0436\"]\n";

/// Le `gui/.cargo/audit.toml` du temoin: la meme forme, une autre liste.
const CONFIG_TEMOIN_GUI: &str =
    "# la coquille\n[advisories]\nignore = [\"RUSTSEC-2024-0370\", \"RUSTSEC-2024-0429\"]\n";

/// Un `deny.toml` de la forme de ceux du depot: sa section `[advisories]` de
/// `69d846f`, commentee, puis une autre table.
fn deny_temoin() -> String {
    format!(
        "# politique\n\n[advisories]\n# la base\n{}\n\n[licenses]\nallow = [\"MIT\"]\n",
        ADVISORIES_A_69D846F.join("\n")
    )
}

/// Le `gui/deny.toml` du temoin: sa section `[advisories]` figee, commentee,
/// puis les autres tables.
fn deny_gui_temoin() -> String {
    format!(
        "# politique de la coquille\n\n[advisories]\n# la base\n{}\n\n[licenses]\nallow = \
         [\"MIT\"]\n\n[sources]\nunknown-git = \"deny\"\n",
        ADVISORIES_DE_LA_COQUILLE.join("\n")
    )
}

/// Juge un workflow avec les configurations du temoin.
fn juger_temoin(texte: &str) -> Result<Rapport, String> {
    let (deny, deny_gui) = (deny_temoin(), deny_gui_temoin());
    juger(
        texte,
        &Configs {
            audit: CONFIG_TEMOIN,
            deny: &deny,
            deny_fuzz: &deny,
            audit_gui: CONFIG_TEMOIN_GUI,
            deny_gui: &deny_gui,
        },
    )
}

#[test]
fn le_temoin_est_lu_et_juge_sain() {
    let wf = lire_workflow(TEMOIN).expect("temoin lisible");
    assert_eq!(wf.nom, "ci");
    assert_eq!(
        wf.evenements,
        ["push", "pull_request", "schedule", "workflow_dispatch"]
    );
    assert_eq!(wf.crons, [(9, "37 4 * * *".to_string())]);
    let ids: Vec<&str> = wf.jobs.iter().map(|j| j.id.as_str()).collect();
    assert_eq!(
        ids,
        [
            "controles",
            "windows",
            "interface-linux",
            "interface-windows",
            "dependances"
        ]
    );
    let dep = &wf.jobs[4];
    let noms: Vec<&str> = dep.etapes.iter().map(|e| e.nom.as_str()).collect();
    assert_eq!(
        noms,
        [
            "",
            "Avis",
            "Licences",
            "Licences du harnais",
            "Avis de la coquille",
            "Licences de la coquille",
            "Vet",
            "SBOM"
        ]
    );
    assert_eq!(dep.etapes[3].repertoire.as_deref(), Some("fuzz"));
    assert_eq!(dep.etapes[4].repertoire.as_deref(), Some("gui"));
    assert_eq!(dep.etapes[5].repertoire.as_deref(), Some("gui"));
    assert_eq!(
        dep.etapes[6].run.as_deref(),
        Some("cargo vet --locked\ngit diff --exit-code -- supply-chain/\n")
    );

    assert_eq!(
        dep.etapes[1].cles[1].2,
        Noeud::Feuille(Scalaire::Texte("cargo audit -D warnings".into()))
    );
    assert_eq!(
        wf.env,
        Some((
            18,
            Some(vec![(
                19,
                "CARGO_TERM_COLOR".to_string(),
                Noeud::Feuille(Scalaire::Texte("always".into()))
            )])
        ))
    );

    let rapport = juger_temoin(TEMOIN).expect("temoin lisible");
    assert!(rapport.defauts.is_empty(), "{:?}", rapport.defauts);
    let table: Vec<(&str, Vec<&str>)> = rapport
        .table
        .iter()
        .map(|(s, j)| (*s, j.iter().map(String::as_str).collect()))
        .collect();
    assert_eq!(
        table,
        [
            ("push", vec!["controles", "interface-linux", "dependances"]),
            (
                "pull_request",
                vec!["controles", "interface-linux", "dependances"]
            ),
            ("schedule", vec!["dependances"]),
            (
                "workflow_dispatch windows=false",
                vec!["controles", "interface-linux", "dependances"]
            ),
            (
                "workflow_dispatch windows=true",
                vec!["windows", "interface-windows"]
            ),
        ]
    );
    assert!(
        defauts_des_jobs_de_la_coquille(&rapport.table).is_empty(),
        "{:?}",
        defauts_des_jobs_de_la_coquille(&rapport.table)
    );
}

/// Chaque mutation du temoin doit faire rougir la recette, avec le defaut
/// attendu: sans cela, la recette principale pourrait etre verte sans rien
/// regarder.
#[test]
fn chaque_mutation_du_temoin_rougit() {
    let dep_si = "    if: github.event_name != 'workflow_dispatch' || !inputs.windows\n";
    let ctl_si = "    if: github.event_name != 'schedule' && (github.event_name != \
                  'workflow_dispatch' || !inputs.windows)\n";
    let cas: &[(&str, &str, &str, &str)] = &[
        (
            "declencheur retire",
            "  schedule:\n    - cron: '37 4 * * *'\n",
            "",
            "`on.schedule` absent",
        ),
        (
            "deux entrees cron",
            "    - cron: '37 4 * * *'\n",
            "    - cron: '37 4 * * *'\n    - cron: '11 16 * * *'\n",
            "2 entree(s)",
        ),
        ("heure pile", "'37 4 * * *'", "'0 4 * * *'", "minute 0"),
        (
            "hebdomadaire",
            "'37 4 * * *'",
            "'37 4 * * 1'",
            "un run chaque jour",
        ),
        (
            "toutes les heures",
            "'37 4 * * *'",
            "'37 * * * *'",
            "un run par jour",
        ),
        (
            "quatre champs",
            "'37 4 * * *'",
            "'37 4 * *'",
            "cinq attendus",
        ),
        (
            "dependances saute sur schedule",
            dep_si,
            ctl_si,
            "est saute sur `schedule`",
        ),
        (
            "controles tourne sur schedule",
            ctl_si,
            dep_si,
            "en plus de",
        ),
        (
            "controles sans condition",
            ctl_si,
            "",
            "en plus de `dependances`: controles",
        ),
        (
            "etape d'audit sautee sur schedule",
            "      - name: Avis\n",
            "      - name: Avis\n        if: github.event_name != 'schedule'\n",
            "y est saute sur `schedule`",
        ),
        (
            "cargo audit retire",
            "run: cargo audit -D warnings",
            "run: echo",
            "`cargo audit` ne tourne pas",
        ),
        (
            "cargo audit sans telechargement",
            "cargo audit -D warnings",
            "cargo audit --no-fetch -D warnings",
            "porte --no-fetch",
        ),
        (
            "cargo audit -n",
            "cargo audit -D warnings",
            "cargo audit -n -D warnings",
            "porte -n",
        ),
        (
            "cargo audit sur base perimee",
            "cargo audit -D warnings",
            "cargo audit --stale -D warnings",
            "porte --stale",
        ),
        (
            "cargo deny hors ligne",
            "run: cargo deny check\n",
            "run: cargo deny --offline check\n",
            "porte --offline",
        ),
        (
            "cargo deny fige",
            "run: cargo deny check\n",
            "run: cargo deny --frozen check\n",
            "porte --frozen",
        ),
        (
            "harnais sans son repertoire",
            "        working-directory: fuzz\n",
            "",
            "dans `fuzz/`",
        ),
        (
            "cargo vet retire",
            "          cargo vet --locked\n",
            "",
            "`cargo vet` ne tourne pas",
        ),
        (
            "groupe sans l'evenement",
            "${{ github.workflow }}-${{ github.event_name }}-",
            "${{ github.workflow }}-",
            "partagent le groupe",
        ),
        (
            "dependances attend controles",
            dep_si,
            &format!("{dep_si}    needs: controles\n"),
            "par `needs:`: controles",
        ),
        (
            "dependances attend windows, liste en ligne",
            dep_si,
            &format!("{dep_si}    needs: [windows]\n"),
            "par `needs:`: windows",
        ),
        (
            "continue-on-error sur l'etape d'audit",
            "      - name: Avis\n",
            "      - name: Avis\n        continue-on-error: true\n",
            "`continue-on-error: true`: un echec du juge",
        ),
        (
            "continue-on-error en expression sur l'etape de vet",
            "      - name: Vet\n",
            "      - name: Vet\n        continue-on-error: ${{ !inputs.windows }}\n",
            "un echec du juge",
        ),
        (
            "continue-on-error sur le job",
            dep_si,
            &format!("{dep_si}    continue-on-error: true\n"),
            "un echec du job",
        ),
        (
            "cargo audit || true",
            "cargo audit -D warnings",
            "cargo audit -D warnings || true",
            "operateur shell",
        ),
        (
            "set +e avant cargo vet",
            "          cargo vet --locked\n",
            "          set +e\n          cargo vet --locked\n",
            "`set +e` n'est pas un juge",
        ),
        (
            "shell sans -e sur l'etape de vet",
            "      - name: Vet\n",
            "      - name: Vet\n        shell: bash {0}\n",
            "`shell:` sur l'etape d'un juge",
        ),
        (
            "defaults du job",
            dep_si,
            &format!("{dep_si}    defaults:\n      run:\n        shell: bash {{0}}\n"),
            "`defaults:` du job",
        ),
        (
            "defaults du workflow",
            "\njobs:\n",
            "\ndefaults:\n  run:\n    working-directory: fuzz\njobs:\n",
            "`defaults:` du workflow",
        ),
        (
            "cargo audit dans fuzz",
            "      - name: Avis\n",
            "      - name: Avis\n        working-directory: fuzz\n",
            "lance dans `fuzz`",
        ),
        (
            "cargo deny d'un seul controle",
            "        working-directory: fuzz\n        run: cargo deny check\n",
            "        working-directory: fuzz\n        run: cargo deny check licenses\n",
            "`cargo deny check licenses`: forme que la recette ne connait pas",
        ),
        (
            "cargo audit --ignore",
            "cargo audit -D warnings",
            "cargo audit -D warnings --ignore RUSTSEC-2026-0001",
            "--ignore RUSTSEC-2026-0001`: forme",
        ),
        (
            "cargo audit sans -D warnings",
            "run: cargo audit -D warnings",
            "run: cargo audit",
            "`cargo audit`: forme",
        ),
        (
            "affectation devant cargo audit",
            "run: cargo audit -D warnings",
            "run: CARGO_HOME=/tmp/x cargo audit -D warnings",
            "`CARGO_HOME=/tmp/x cargo audit -D warnings`: forme",
        ),
        (
            "git diff de supply-chain/ retire",
            "          git diff --exit-code -- supply-chain/\n",
            "",
            "aucun `git diff --exit-code -- supply-chain/` apres `cargo vet`",
        ),
        (
            "git diff avant cargo vet",
            "          cargo vet --locked\n          git diff --exit-code -- supply-chain/\n",
            "          git diff --exit-code -- supply-chain/\n          cargo vet --locked\n",
            "`git diff --exit-code -- supply-chain/` avant `cargo vet`",
        ),
        (
            "git diff dans une etape a part",
            "          cargo vet --locked\n          git diff --exit-code -- supply-chain/\n",
            "          cargo vet --locked\n      - name: Diff\n        run: git diff \
             --exit-code -- supply-chain/\n",
            "aucun `git diff --exit-code -- supply-chain/` apres `cargo vet`",
        ),
        (
            "cargo audit --deny warnings (graphie equivalente, rouge assume)",
            "cargo audit -D warnings",
            "cargo audit --deny warnings",
            "`cargo audit --deny warnings`: forme",
        ),
        (
            "environment sur le job",
            dep_si,
            &format!("{dep_si}    environment: audit\n"),
            "`environment:` n'est pas une cle du job",
        ),
        (
            "container sur le job",
            dep_si,
            &format!("{dep_si}    container: rust\n"),
            "`container:` n'est pas une cle du job",
        ),
        (
            "services sur le job",
            dep_si,
            &format!("{dep_si}    services:\n      cache:\n        image: redis\n"),
            "`services:` n'est pas une cle du job",
        ),
        (
            "permissions sur le job",
            dep_si,
            &format!("{dep_si}    permissions: read-all\n"),
            "`permissions:` n'est pas une cle du job",
        ),
        (
            "strategy sur le job",
            dep_si,
            &format!("{dep_si}    strategy:\n      fail-fast: false\n"),
            "`strategy:` n'est pas une cle du job",
        ),
        (
            "env sur le job",
            dep_si,
            &format!("{dep_si}    env:\n      CARGO_HOME: ./ailleurs\n"),
            "`env:` n'est pas une cle du job",
        ),
        (
            "concurrency sur le job",
            dep_si,
            &format!("{dep_si}    concurrency:\n      group: audit\n"),
            "`concurrency:` n'est pas une cle du job",
        ),
        (
            "timezone dans l'entree de schedule",
            "    - cron: '37 4 * * *'\n",
            "    - cron: '37 4 * * *'\n      timezone: Asia/Kolkata\n",
            "`timezone:` dans l'entree de `schedule`",
        ),
        // dq1 du quatrieme verificateur, en valeur nue: `''''` est une chaine
        // qui vaut `'` pour GitHub, donc `!''''` est faux et le job saute.
        (
            "dependances saute par !'''' (valeur nue)",
            dep_si,
            "    if: github.event_name != 'workflow_dispatch' && !'''' || !inputs.windows && \
             !''''\n",
            "est saute sur `schedule`",
        ),
        (
            "variable ajoutee a l'env du workflow",
            "  CARGO_TERM_COLOR: always\n",
            "  CARGO_TERM_COLOR: always\n  CARGO_HOME: ./ailleurs\n",
            "`CARGO_HOME: ./ailleurs` ajoutee a l'`env:` du workflow",
        ),
        (
            "variable changee dans l'env du workflow",
            "  CARGO_TERM_COLOR: always\n",
            "  CARGO_TERM_COLOR: never\n",
            "au lieu de `CARGO_TERM_COLOR: always`",
        ),
        (
            "env du workflow retire",
            "env:\n  CARGO_TERM_COLOR: always\n",
            "",
            "`env:` du workflow absent",
        ),
        // Les juges de la coquille (`gui/`).
        (
            "audit de la coquille retire",
            "      - name: Avis de la coquille\n        working-directory: gui\n        run: cargo \
             audit -D warnings\n",
            "",
            "`cargo audit` dans `gui/` (`working-directory: gui`) ne tourne pas",
        ),
        (
            "deny de la coquille retire",
            "      - name: Licences de la coquille\n        working-directory: gui\n        run: \
             cargo deny check\n",
            "",
            "`cargo deny check` dans `gui/` (`working-directory: gui`) ne tourne pas",
        ),
        (
            "audit de la coquille sans son repertoire",
            "        working-directory: gui\n        run: cargo audit -D warnings\n",
            "        run: cargo audit -D warnings\n",
            "`cargo audit` dans `gui/` (`working-directory: gui`) ne tourne pas",
        ),
        (
            "audit de la coquille dans fuzz",
            "        working-directory: gui\n        run: cargo audit -D warnings\n",
            "        working-directory: fuzz\n        run: cargo audit -D warnings\n",
            "`cargo audit -D warnings` lance dans `fuzz`",
        ),
        (
            "deny de la coquille d'un seul controle",
            "        working-directory: gui\n        run: cargo deny check\n",
            "        working-directory: gui\n        run: cargo deny check advisories\n",
            "`cargo deny check advisories`: forme que la recette ne connait pas",
        ),
        (
            "audit de la coquille qui ecarte glib",
            "        working-directory: gui\n        run: cargo audit -D warnings\n",
            "        working-directory: gui\n        run: cargo audit -D warnings --ignore \
             RUSTSEC-2024-0429\n",
            "--ignore RUSTSEC-2024-0429`: forme",
        ),
        (
            "audit de la coquille sans telechargement",
            "        working-directory: gui\n        run: cargo audit -D warnings\n",
            "        working-directory: gui\n        run: cargo audit --no-fetch -D warnings\n",
            "porte --no-fetch",
        ),
        (
            "deny de la coquille saute sur schedule",
            "      - name: Licences de la coquille\n",
            "      - name: Licences de la coquille\n        if: github.event_name != 'schedule'\n",
            "`cargo deny` y est saute sur `schedule`",
        ),
        (
            "cargo vet dans gui",
            "        run: |\n          cargo vet --locked\n",
            "        working-directory: gui\n        run: |\n          cargo vet --locked\n",
            "`cargo vet --locked` lance dans `gui`",
        ),
        // Les jobs de la coquille, et tout job nouveau, sur `schedule`.
        (
            "coquille Linux sur schedule",
            "  interface-linux:\n    if: github.event_name != 'schedule' && (github.event_name != \
             'workflow_dispatch' || !inputs.windows)\n",
            "  interface-linux:\n    if: github.event_name != 'workflow_dispatch' || \
             !inputs.windows\n",
            "en plus de `dependances`: interface-linux",
        ),
        (
            "nouveau job sans condition de schedule",
            "  dependances:\n",
            "  paquets:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: cargo build\n  \
             dependances:\n",
            "en plus de `dependances`: paquets",
        ),
    ];
    let mut ecarts = Vec::new();
    for (quoi, de, vers, attendu) in cas {
        assert!(TEMOIN.contains(de), "{quoi}: `{de}` absent du temoin");
        let mute = TEMOIN.replacen(de, vers, 1);
        match juger_temoin(&mute) {
            Ok(r) if r.defauts.iter().any(|d| d.contains(attendu)) => {}
            Ok(r) => ecarts.push(format!("{quoi}: attendu `{attendu}`, vu {:?}", r.defauts)),
            Err(e) => ecarts.push(format!("{quoi}: illisible ({e}) au lieu d'un defaut")),
        }
    }
    // La politique de lancement des deux jobs de la coquille (regle 10).
    let linux_coquille = "  interface-linux:\n    if: github.event_name != 'schedule' && \
                          (github.event_name != 'workflow_dispatch' || !inputs.windows)\n";
    let windows_coquille = "  interface-windows:\n    if: github.event_name == 'workflow_dispatch' \
                            && inputs.windows\n";
    for (quoi, de, vers, attendu) in [
        (
            "coquille Windows sur chaque push",
            windows_coquille,
            "  interface-windows:\n    if: github.event_name != 'schedule'\n",
            "le job `interface-windows` tourne sur [push, pull_request",
        ),
        (
            "coquille Linux sur les seules PR",
            linux_coquille,
            "  interface-linux:\n    if: github.event_name == 'pull_request'\n",
            "le job `interface-linux` tourne sur [pull_request], la politique",
        ),
        (
            "coquille Linux retiree",
            "  interface-linux:\n",
            "  autre-linux:\n",
            "le job `interface-linux` tourne sur [], la politique",
        ),
    ] {
        assert!(TEMOIN.contains(de), "{quoi}: `{de}` absent du temoin");
        let mute = TEMOIN.replacen(de, vers, 1);
        match juger_temoin(&mute) {
            Ok(r) => {
                let d = defauts_des_jobs_de_la_coquille(&r.table);
                if !d.iter().any(|x| x.contains(attendu)) {
                    ecarts.push(format!("{quoi}: attendu `{attendu}`, vu {d:?}"));
                }
            }
            Err(e) => ecarts.push(format!("{quoi}: illisible ({e}) au lieu d'un defaut")),
        }
    }
    // Chaque ligne hors des formes admises de `.cargo/audit.toml` est nommee.
    let ignore = "ignore = [\"RUSTSEC-2024-0436\"]\n";
    for (quoi, config, attendus) in [
        (
            "[database] puis fetch = false",
            format!("[advisories]\n{ignore}[database]\nfetch = false\n"),
            vec!["`[database]`", "`fetch = false`"],
        ),
        (
            "stale = true",
            format!("[advisories]\n{ignore}[database]\nstale   =   true # commentaire\n"),
            vec!["`stale   =   true # commentaire`"],
        ),
        (
            "cle pointee database.fetch = false",
            format!("database.fetch = false\n[advisories]\n{ignore}"),
            vec!["`database.fetch = false`"],
        ),
        (
            "severity_threshold",
            format!("[advisories]\n{ignore}severity_threshold = \"critical\"\n"),
            vec!["`severity_threshold = \"critical\"`"],
        ),
        (
            "liste ignore sur plusieurs lignes",
            "[advisories]\nignore = [\n  \"RUSTSEC-2024-0436\",\n]\n".to_string(),
            vec!["`ignore = [`", "`\"RUSTSEC-2024-0436\",`", "`]`"],
        ),
        (
            "ignore hors de [advisories]",
            format!("{ignore}[advisories]\n"),
            vec!["`ignore = [\"RUSTSEC-2024-0436\"]`"],
        ),
    ] {
        let (deny, deny_gui) = (deny_temoin(), deny_gui_temoin());
        // La meme ligne, dans la configuration de la racine puis dans celle
        // de la coquille: chacune est nommee avec son fichier.
        for (fichier, configs) in [
            (
                CONFIG_AUDIT,
                Configs {
                    audit: &config,
                    deny: &deny,
                    deny_fuzz: &deny,
                    audit_gui: CONFIG_TEMOIN_GUI,
                    deny_gui: &deny_gui,
                },
            ),
            (
                CONFIG_AUDIT_GUI,
                Configs {
                    audit: CONFIG_TEMOIN,
                    deny: &deny,
                    deny_fuzz: &deny,
                    audit_gui: &config,
                    deny_gui: &deny_gui,
                },
            ),
        ] {
            match juger(TEMOIN, &configs) {
                Ok(r) => {
                    for a in &attendus {
                        if !r
                            .defauts
                            .iter()
                            .any(|d| d.starts_with(&format!("{fichier}, ")) && d.contains(a))
                        {
                            ecarts.push(format!(
                                "{quoi} ({fichier}): attendu {a} nomme, vu {:?}",
                                r.defauts
                            ));
                        }
                    }
                }
                Err(e) => ecarts.push(format!("{quoi} ({fichier}): illisible ({e})")),
            }
        }
    }
    // Chaque changement de `[advisories]` dans l'un des trois fichiers de
    // cargo-deny est nomme, avec son fichier.
    let sain = deny_temoin();
    let sain_gui = deny_gui_temoin();
    let urls = "db-urls = [\"https://github.com/rustsec/advisory-db\"]\n";
    let yanked = "yanked = \"deny\"\n";
    for (quoi, de, vers, attendus) in [
        (
            "db-urls change",
            urls,
            "db-urls = [\"https://example.org/advisory-db\"]\n",
            vec![
                "`db-urls = [\"https://example.org/advisory-db\"]` n'est pas une ligne",
                "`db-urls = [\"https://github.com/rustsec/advisory-db\"]` retiree",
            ],
        ),
        (
            "db-path ajoute",
            yanked,
            "yanked = \"deny\"\ndb-path = \"/tmp/advisory-dbs\"\n",
            vec!["`db-path = \"/tmp/advisory-dbs\"` n'est pas une ligne"],
        ),
        (
            "git-fetch-with-cli ajoute",
            yanked,
            "yanked = \"deny\"\ngit-fetch-with-cli = false\n",
            vec!["`git-fetch-with-cli = false` n'est pas une ligne"],
        ),
        (
            "maximum-db-staleness ajoute",
            yanked,
            "yanked = \"deny\"\nmaximum-db-staleness = \"P1000D\"\n",
            vec!["`maximum-db-staleness = \"P1000D\"` n'est pas une ligne"],
        ),
        (
            "commentaire de fin sur une ligne de la section",
            yanked,
            "yanked = \"deny\" # toujours\n",
            vec!["`yanked = \"deny\" # toujours` n'est pas une ligne"],
        ),
        (
            "cle pointee a la racine",
            "\n[advisories]\n",
            "\nadvisories.db-path = \"/tmp/x\"\n[advisories]\n",
            vec!["`advisories.db-path = \"/tmp/x\"`: ligne active avant `[advisories]`"],
        ),
        (
            "table en ligne a la racine",
            "\n[advisories]\n",
            "\nadvisories = { db-path = \"/tmp/x\" }\n[advisories]\n",
            vec!["ligne active avant `[advisories]`"],
        ),
        (
            "cle pointee dans une autre table",
            "allow = [\"MIT\"]\n",
            "allow = [\"MIT\"]\nadvisories.db-path = \"/tmp/x\"\n",
            vec!["`advisories.db-path = \"/tmp/x\"`: cle `advisories` hors de sa section"],
        ),
        (
            "seconde section",
            "[licenses]\n",
            "[advisories]\ndb-path = \"/tmp/x\"\n[licenses]\n",
            vec!["seconde section `[advisories]`"],
        ),
        (
            "sous-table d'advisories",
            "[licenses]\n",
            "[advisories.base]\nx = 1\n[licenses]\n",
            vec!["`[advisories.base]`: table sous `advisories`"],
        ),
        (
            "en-tete entre guillemets",
            "[licenses]\n",
            "[\"advisories\".base]\nx = 1\n[licenses]\n",
            vec!["en-tete `[\"advisories\".base]` hors de la forme nue"],
        ),
        (
            "advisories apres une autre table",
            "[advisories]\n",
            "[graph]\n[advisories]\n",
            vec!["`[advisories]` n'est pas le premier en-tete"],
        ),
    ] {
        assert!(
            sain.contains(de),
            "{quoi}: `{de}` absent du deny.toml temoin"
        );
        assert!(
            sain_gui.contains(de),
            "{quoi}: `{de}` absent du gui/deny.toml temoin"
        );
        let mute = sain.replacen(de, vers, 1);
        let mute_gui = sain_gui.replacen(de, vers, 1);
        for (fichier, configs) in [
            (
                CONFIG_DENY,
                Configs {
                    audit: CONFIG_TEMOIN,
                    deny: &mute,
                    deny_fuzz: &sain,
                    audit_gui: CONFIG_TEMOIN_GUI,
                    deny_gui: &sain_gui,
                },
            ),
            (
                CONFIG_DENY_FUZZ,
                Configs {
                    audit: CONFIG_TEMOIN,
                    deny: &sain,
                    deny_fuzz: &mute,
                    audit_gui: CONFIG_TEMOIN_GUI,
                    deny_gui: &sain_gui,
                },
            ),
            (
                CONFIG_DENY_GUI,
                Configs {
                    audit: CONFIG_TEMOIN,
                    deny: &sain,
                    deny_fuzz: &sain,
                    audit_gui: CONFIG_TEMOIN_GUI,
                    deny_gui: &mute_gui,
                },
            ),
        ] {
            match juger(TEMOIN, &configs) {
                Ok(r) => {
                    for a in &attendus {
                        if !r
                            .defauts
                            .iter()
                            .any(|d| d.starts_with(fichier) && d.contains(a))
                        {
                            ecarts.push(format!(
                                "{quoi} ({fichier}): attendu {a} nomme, vu {:?}",
                                r.defauts
                            ));
                        }
                    }
                }
                Err(e) => ecarts.push(format!("{quoi} ({fichier}): illisible ({e})")),
            }
        }
    }
    // La liste des avis de la coquille est figee avec le reste de sa
    // section: une entree retiree, ajoutee ou dont la raison change est
    // nommee dans `gui/deny.toml`, et la section de la racine ne l'admet pas.
    let glib = ADVISORIES_DE_LA_COQUILLE[ADVISORIES_DE_LA_COQUILLE.len() - 2];
    assert!(glib.contains("RUSTSEC-2024-0429"), "{glib}");
    let perime = "    { id = \"RUSTSEC-2099-0001\", reason = \"2026-10-16: perime\" },";
    for (quoi, de, vers, attendu) in [
        (
            "entree glib retiree de la coquille",
            format!("{glib}\n"),
            String::new(),
            "retiree de la section `[advisories]`".to_string(),
        ),
        (
            "entree ajoutee a la coquille",
            format!("{glib}\n"),
            format!("{glib}\n{perime}\n"),
            format!("`{}` n'est pas une ligne de la section", perime.trim()),
        ),
        (
            "raison de glib changee",
            "processus non privilegie\" },".to_string(),
            "processus non privilegie, a revoir\" },".to_string(),
            "n'est pas une ligne de la section de `ADVISORIES_DE_LA_COQUILLE`".to_string(),
        ),
    ] {
        assert!(sain_gui.contains(&de), "{quoi}: `{de}` absent du temoin");
        let mute_gui = sain_gui.replacen(&de, &vers, 1);
        let configs = Configs {
            audit: CONFIG_TEMOIN,
            deny: &sain,
            deny_fuzz: &sain,
            audit_gui: CONFIG_TEMOIN_GUI,
            deny_gui: &mute_gui,
        };
        match juger(TEMOIN, &configs) {
            Ok(r)
                if r.defauts
                    .iter()
                    .any(|d| d.starts_with(CONFIG_DENY_GUI) && d.contains(&attendu)) => {}
            Ok(r) => ecarts.push(format!("{quoi}: attendu `{attendu}`, vu {:?}", r.defauts)),
            Err(e) => ecarts.push(format!("{quoi}: illisible ({e})")),
        }
    }
    // Et la section de la coquille n'est pas admise a la racine: chaque
    // fichier a la sienne.
    let configs = Configs {
        audit: CONFIG_TEMOIN,
        deny: &sain_gui,
        deny_fuzz: &sain,
        audit_gui: CONFIG_TEMOIN_GUI,
        deny_gui: &sain_gui,
    };
    match juger(TEMOIN, &configs) {
        Ok(r)
            if r.defauts.iter().any(|d| {
                d.starts_with(&format!("{CONFIG_DENY}, ")) && d.contains("RUSTSEC-2024-0429")
            }) => {}
        autre => ecarts.push(format!(
            "section de la coquille dans deny.toml: attendu un defaut qui nomme glib, vu {autre:?}"
        )),
    }
    assert!(
        ecarts.is_empty(),
        "{} mutation(s) sans le rouge attendu:\n  {}",
        ecarts.len(),
        ecarts.join("\n  ")
    );
}

/// Une condition que la recette ne sait pas evaluer la fait rougir: elle ne
/// devine pas le routage.
#[test]
fn une_condition_illisible_fait_rougir() {
    let ctl_si = "    if: github.event_name != 'schedule' && (github.event_name != \
                  'workflow_dispatch' || !inputs.windows)\n";
    for vers in [
        "    if: contains(github.ref, 'main')\n",
        "    if: github.ref_name == 'main'\n",
        "    if: github.event_name == 1\n",
        "    if: >\n      github.event_name != 'schedule'\n",
    ] {
        let mute = TEMOIN.replacen(ctl_si, vers, 1);
        assert!(
            juger_temoin(&mute).is_err(),
            "{vers:?} aurait du etre refuse comme illisible"
        );
    }
    // Des `needs:` que la recette ne sait pas resoudre.
    let dep_si = "    if: github.event_name != 'workflow_dispatch' || !inputs.windows\n";
    for (de, vers) in [
        (dep_si, format!("{dep_si}    needs: inconnu\n")),
        (dep_si, format!("{dep_si}    needs: ${{{{ x }}}}\n")),
        (
            dep_si,
            "    needs: controles\n    if: ${{ always() }}\n".to_string(),
        ),
        (
            "    runs-on: ubuntu-24.04\n    steps:\n      - run: cargo test\n  windows:",
            "    needs: dependances\n    runs-on: ubuntu-24.04\n    steps:\n      - run: cargo \
             test\n  windows:"
                .to_string(),
        ),
    ] {
        assert!(TEMOIN.contains(de), "`{de}` absent du temoin");
        let mut mute = TEMOIN.replacen(de, &vers, 1);
        if vers.contains("needs: dependances") {
            // Et le cycle: dependances attend controles, qui l'attend.
            mute = mute.replacen(dep_si, &format!("{dep_si}    needs: controles\n"), 1);
        }
        assert!(
            juger_temoin(&mute).is_err(),
            "{vers:?} aurait du etre refuse comme illisible"
        );
    }
}

/// Chaque forme hors de la grammaire de l'en-tete, injectee dans le temoin,
/// fait rougir la recette, qui nomme la forme: la recette ne lit jamais une
/// ligne autrement que GitHub sans le dire.
#[test]
fn chaque_forme_hors_grammaire_rougit() {
    let dep_si = "    if: github.event_name != 'workflow_dispatch' || !inputs.windows\n";
    let audit = "        run: cargo audit -D warnings\n";
    let vet = "        run: |\n          cargo vet";
    let cas: &[(&str, &str, &str, &str)] = &[
        (
            "valeur continuee d'un juge (X1)",
            audit,
            "        run: cargo audit -D warnings\n          --ignore RUSTSEC-2026-0001\n",
            "valeur continuee de la ligne",
        ),
        (
            "condition coupee en deux lignes (X3)",
            dep_si,
            "    if: github.event_name != 'workflow_dispatch'\n      || !inputs.windows\n",
            "valeur continuee de la ligne",
        ),
        (
            "chaine entre guillemets simples continuee",
            "      - name: Avis\n",
            "      - name: 'Avis\n          RustSec'\n",
            "non fermee sur sa ligne",
        ),
        // dq1 du quatrieme verificateur: YAML garde `''''` entre guillemets
        // doubles, GitHub ne lancerait jamais le job.
        (
            "guillemets doubles (dq1)",
            dep_si,
            "    if: \"(github.event_name != 'workflow_dispatch' || !inputs.windows) && \
             !''''\"\n",
            "guillemets doubles",
        ),
        (
            "guillemets doubles sans ''",
            "      - name: Avis\n",
            "      - name: \"Avis\"\n",
            "guillemets doubles",
        ),
        // sq1: la meme valeur entre guillemets simples, ou `''` vaut `'`.
        (
            "'' entre guillemets simples (sq1)",
            dep_si,
            "    if: '(github.event_name != ''workflow_dispatch'' || !inputs.windows) && \
             !'''''''''\n",
            "`''` entre guillemets simples",
        ),
        (
            "BOM",
            "name: ci\n",
            "\u{feff}name: ci\n",
            "BOM (U+FEFF) en tete du fichier",
        ),
        (
            "retour chariot",
            "name: ci\n",
            "name: ci\r\n",
            "retour chariot (CR)",
        ),
        (
            "espace en fin de ligne",
            "name: ci\n",
            "name: ci \n",
            "espace en fin de ligne",
        ),
        (
            "tabulation dans une valeur",
            "name: ci\n",
            "name: c\ti\n",
            "tabulation dans la ligne",
        ),
        (
            "caractere hors de l'ASCII",
            "name: ci\n",
            "name: c\u{e9}\n",
            "U+00E9 hors de l'ASCII imprimable",
        ),
        (
            "fin de fichier sans fin de ligne",
            "        run: cargo cyclonedx\n",
            "        run: cargo cyclonedx",
            "fin de fichier sans fin de ligne",
        ),
        (
            "evenement a valeur nulle",
            "    - cron: '37 4 * * *'\n",
            "",
            "valeur nulle",
        ),
        (
            "commentaire apres une cle seule",
            "  schedule:\n",
            "  schedule: # quotidien\n",
            "commentaire apres `schedule:` seule",
        ),
        (
            "commentaire apres run: |",
            vet,
            "        run: | # deux juges\n          cargo vet",
            "commentaire apres `run: |`",
        ),
        (
            "liste en blocs de valeurs",
            dep_si,
            &format!("{dep_si}    needs:\n      - controles\n"),
            "entree `- ` sans `cle:`",
        ),
        (
            "entree de sequence qui ouvre un bloc",
            "      - name: Avis\n        run: cargo audit -D warnings\n",
            "      - with:\n          a: b\n        name: Avis\n        run: cargo audit -D \
             warnings\n",
            "entree `- with:` qui ouvre un bloc",
        ),
        (
            "liste en ligne vide",
            "    runs-on: windows-2025\n",
            "    runs-on: windows-2025\n    needs: []\n",
            "liste en ligne hors de la forme",
        ),
        (
            "mot que YAML type en booleen",
            "        default: false\n",
            "        default: no\n",
            "`no`: mot que YAML lit comme un booleen ou un nul",
        ),
        (
            "booleen en majuscules",
            "        default: false\n",
            "        default: False\n",
            "`False`: mot que YAML lit comme un booleen ou un nul",
        ),
        (
            "nul",
            "    runs-on: windows-2025\n",
            "    runs-on: null\n",
            "`null`: mot que YAML lit comme un booleen ou un nul",
        ),
        (
            "nul en tilde",
            "    runs-on: windows-2025\n",
            "    runs-on: ~\n",
            "valeur nue qui commence par `~`",
        ),
        (
            "octal YAML 1.1",
            "        default: false\n",
            "        default: 010\n",
            "nombre `010` hors de la forme entiere",
        ),
        (
            "flottant",
            "        default: false\n",
            "        default: 1.5\n",
            "nombre `1.5` hors de la forme entiere",
        ),
        (
            "valeur nue qui commence par un point",
            "    runs-on: windows-2025\n",
            "    runs-on: .windows\n",
            "valeur nue qui commence par `.`",
        ),
        (
            "cle qui commence par un chiffre",
            dep_si,
            &format!("{dep_si}    1x: y\n"),
            "cle `1x` qui ne commence pas par une lettre",
        ),
        (
            "cle on hors du premier niveau",
            dep_si,
            &format!("{dep_si}    on: push\n"),
            "cle `on`: mot que YAML lit comme un booleen ou un nul",
        ),
        (
            "style replie",
            vet,
            "        run: >\n          cargo vet",
            "indicateur de bloc `>`",
        ),
        (
            "litteral sans fin de ligne",
            vet,
            "        run: |-\n          cargo vet",
            "indicateur de bloc `|-`",
        ),
        (
            "litteral qui garde les fins",
            vet,
            "        run: |+\n          cargo vet",
            "indicateur de bloc `|+`",
        ),
        (
            "replie sans fin de ligne",
            vet,
            "        run: >-\n          cargo vet",
            "indicateur de bloc `>-`",
        ),
        (
            "indicateur d'indentation",
            vet,
            "        run: |2\n          cargo vet",
            "indicateur de bloc `|2`",
        ),
        (
            "bloc litteral sous une autre cle",
            "      - name: Avis\n",
            "      - name: |\n          Avis\n",
            "`name: |`",
        ),
        (
            "ancre",
            "      - name: Avis\n",
            "      - name: &avis Avis\n",
            "ancre `&`",
        ),
        (
            "alias",
            "      - name: Licences\n",
            "      - name: *avis\n",
            "alias `*`",
        ),
        (
            "cle de fusion",
            dep_si,
            &format!("{dep_si}    <<: *defaut\n"),
            "cle de fusion `<<`",
        ),
        (
            "etiquette",
            audit,
            "        run: !!str cargo audit -D warnings\n",
            "etiquette `!`",
        ),
        (
            "mapping en ligne",
            dep_si,
            &format!("{dep_si}    env: {{CARGO_HOME: /tmp/c}}\n"),
            "mapping en ligne `{`",
        ),
        (
            "cle complexe",
            dep_si,
            "    ? if\n    : github.event_name != 'workflow_dispatch' || !inputs.windows\n",
            "cle complexe `?`",
        ),
        (
            "marqueur de debut de document",
            "name: ci\n",
            "---\nname: ci\n",
            "marqueur de document `---`",
        ),
        (
            "marqueur de fin de document",
            "        run: cargo cyclonedx\n",
            "        run: cargo cyclonedx\n...\n",
            "marqueur de document `...`",
        ),
        (
            "directive",
            "name: ci\n",
            "%YAML 1.2\nname: ci\n",
            "directive `%`",
        ),
        (
            "tabulation dans l'indentation",
            dep_si,
            "  \tif: github.event_name != 'workflow_dispatch' || !inputs.windows\n",
            "tabulation dans l'indentation",
        ),
        (
            "cle entre guillemets",
            dep_si,
            "    'if': github.event_name != 'workflow_dispatch' || !inputs.windows\n",
            "cle entre guillemets",
        ),
        (
            "cle en double sur le job",
            dep_si,
            &format!("{dep_si}    if: always()\n"),
            "cle `if` en double",
        ),
        (
            "cle en double dans l'etape d'un juge",
            audit,
            "        run: echo\n        run: cargo audit -D warnings\n",
            "cle `run` en double",
        ),
        (
            "sequence au niveau de sa cle",
            "    steps:\n      - uses: actions/checkout@0 # v1\n",
            "    steps:\n    - uses: actions/checkout@0 # v1\n",
            "sequence au niveau de sa cle",
        ),
        (
            "echappement entre guillemets doubles",
            audit,
            "        run: \"cargo audit -D warnings\\t\"\n",
            "guillemets doubles",
        ),
        (
            "deux-points dans une valeur nue",
            "      - name: Avis\n",
            "      - name: Avis: RustSec\n",
            "`: ` dans une valeur nue",
        ),
        (
            "texte apres une chaine entre guillemets",
            audit,
            "        run: 'cargo audit' -D warnings\n",
            "texte apres la chaine",
        ),
        (
            "liste en ligne sur deux lignes",
            "  push:\n    branches: [main]\n",
            "  push:\n    branches: [main,\n      dev]\n",
            "liste en ligne hors de la forme",
        ),
        (
            "indentation qui ne rouvre aucun bloc",
            "      - name: Licences\n",
            "     - name: Licences\n",
            "qui ne rouvre aucun bloc",
        ),
        (
            "entree de sequence dans un mapping",
            dep_si,
            &format!("{dep_si}    - controles\n"),
            "entree `- ` dans un mapping",
        ),
        (
            "cle sans tiret dans une sequence",
            "      - name: Licences\n",
            "      name: Licences\n",
            "cle sans `- ` dans une sequence",
        ),
    ];
    let mut ecarts = Vec::new();
    for (quoi, de, vers, attendu) in cas {
        assert!(TEMOIN.contains(de), "{quoi}: `{de}` absent du temoin");
        let mute = TEMOIN.replacen(de, vers, 1);
        match juger_temoin(&mute) {
            Err(e) if e.contains(attendu) => {}
            autre => ecarts.push(format!(
                "{quoi}: attendu le refus `{attendu}`, vu {autre:?}"
            )),
        }
    }
    assert!(
        ecarts.is_empty(),
        "{} forme(s) sans le refus attendu:\n  {}",
        ecarts.len(),
        ecarts.join("\n  ")
    );
}

/// Les commentaires de fin de ligne et les formes admises ne changent ni le
/// verdict ni le routage: un faux rouge pousserait a affaiblir la recette.
#[test]
fn les_commentaires_et_les_formes_admises_ne_changent_rien() {
    let dep_si = "    if: github.event_name != 'workflow_dispatch' || !inputs.windows\n";
    let attendu = juger_temoin(TEMOIN).expect("temoin lisible").table;
    let delai = format!("{dep_si}    timeout-minutes: 30\n");
    for (de, vers) in [
        (
            "    - cron: '37 4 * * *'\n",
            "    - cron: '37 4 * * *' # 04:37 UTC\n",
        ),
        (
            dep_si,
            "    if: github.event_name != 'workflow_dispatch' || !inputs.windows # inchangee\n",
        ),
        (
            "      - name: Avis\n",
            "      - name: Avis\n        continue-on-error: false # explicite\n",
        ),
        (
            "      - name: Avis\n",
            "      - name: Avis\n        id: avis\n",
        ),
        ("      - name: Avis\n", "      - name: 'Avis'\n"),
        (dep_si, delai.as_str()),
        (
            "        working-directory: fuzz\n",
            "        working-directory: ./fuzz/\n",
        ),
        (
            "        working-directory: gui\n",
            "        working-directory: ./gui/\n",
        ),
        (
            "        working-directory: gui\n        run: cargo deny check\n",
            "        working-directory: gui/\n        run: cargo deny check\n",
        ),
        (
            "      - name: Avis\n",
            "      - name: Avis\n        working-directory: ./\n",
        ),
        // `''''` dans une valeur nue: une chaine qui vaut `'`, egale a
        // elle-meme; l'etape du SBOM reste sautee sur `schedule`.
        (
            "        if: github.event_name != 'schedule'\n",
            "        if: github.event_name != 'schedule' && '''' == ''''\n",
        ),
        (
            "  CARGO_TERM_COLOR: always\n",
            "  CARGO_TERM_COLOR: always # couleur\n",
        ),
        (
            "        run: |\n          cargo vet --locked\n",
            "        run: |\n\n          cargo vet --locked\n",
        ),
    ] {
        assert!(TEMOIN.contains(de), "`{de}` absent du temoin");
        let mute = TEMOIN.replacen(de, vers, 1);
        let r = juger_temoin(&mute).unwrap_or_else(|e| panic!("{vers:?}: illisible: {e}"));
        assert!(r.defauts.is_empty(), "{vers:?}: {:?}", r.defauts);
        assert_eq!(r.table, attendu, "{vers:?}: le routage a change");
        assert_eq!(
            lire_workflow(&mute).expect("lisible").crons[0].1,
            "37 4 * * *",
            "{vers:?}"
        );
    }
    // Les formes admises de `.cargo/audit.toml`, et de celui de la coquille.
    let (deny, deny_gui) = (deny_temoin(), deny_gui_temoin());
    for config in [
        "# un commentaire\n\n[advisories] # la seule table\nignore = []\n",
        "[advisories]\n  ignore = [ \"RUSTSEC-2024-0436\", \"RUSTSEC-2025-0001\", ] # deux\n",
    ] {
        for configs in [
            Configs {
                audit: config,
                deny: &deny,
                deny_fuzz: &deny,
                audit_gui: CONFIG_TEMOIN_GUI,
                deny_gui: &deny_gui,
            },
            Configs {
                audit: CONFIG_TEMOIN,
                deny: &deny,
                deny_fuzz: &deny,
                audit_gui: config,
                deny_gui: &deny_gui,
            },
        ] {
            let r =
                juger(TEMOIN, &configs).unwrap_or_else(|e| panic!("{config:?}: illisible: {e}"));
            assert!(r.defauts.is_empty(), "{config:?}: {:?}", r.defauts);
        }
    }
    // Les commentaires et les lignes vides des fichiers de cargo-deny, dans la
    // section comme ailleurs, ne changent rien.
    let commenter = |texte: &str| {
        texte
            .replacen("yanked", "\n# un mot\n\nyanked", 1)
            .replacen("[licenses]", "# avant les licences\n[licenses]", 1)
    };
    let (commente, commente_gui) = (commenter(&deny), commenter(&deny_gui));
    let configs = Configs {
        audit: CONFIG_TEMOIN,
        deny: &commente,
        deny_fuzz: &commente,
        audit_gui: CONFIG_TEMOIN_GUI,
        deny_gui: &commente_gui,
    };
    let r = juger(TEMOIN, &configs).expect("temoin lisible");
    assert!(r.defauts.is_empty(), "{:?}", r.defauts);
}

/// L'evaluateur, sur les formes du workflow: casse ignoree, `null` faux,
/// court-circuit, `${{ }}` facultatif, fonctions de statut.
#[test]
fn l_evaluateur_suit_les_regles_de_github() {
    let cas: &[(&str, &str, bool)] = &[
        ("github.event_name == 'SCHEDULE'", PLANIFIE, true),
        ("!inputs.windows", PLANIFIE, true),
        ("inputs.windows", "workflow_dispatch windows=true", true),
        ("!inputs.windows", "workflow_dispatch windows=true", false),
        (
            "github.event_name != 'workflow_dispatch' || !inputs.windows",
            "workflow_dispatch windows=true",
            false,
        ),
        (
            "github.event_name != 'workflow_dispatch' || !inputs.windows",
            PLANIFIE,
            true,
        ),
        (
            "github.event_name != 'schedule' && (github.event_name != 'workflow_dispatch' || !inputs.windows)",
            PLANIFIE,
            false,
        ),
        (
            "github.event_name != 'schedule' && (github.event_name != 'workflow_dispatch' || !inputs.windows)",
            "push",
            true,
        ),
        (
            "github.event_name != 'schedule' && (github.event_name != 'workflow_dispatch' || !inputs.windows)",
            "workflow_dispatch windows=false",
            true,
        ),
        ("${{ github.event_name == 'schedule' }}", PLANIFIE, true),
        ("${{ !cancelled() }}", PLANIFIE, true),
        ("failure()", PLANIFIE, false),
        ("always() && github.event_name == 'push'", PLANIFIE, false),
        ("!(github.event_name == 'schedule')", PLANIFIE, false),
        ("github.event.pull_request.number", "pull_request", true),
        ("github.event.pull_request.number", "push", false),
        ("'it''s' == 'IT''S'", "push", true),
    ];
    for (texte, nom, attendu) in cas {
        let vu = evaluer_condition(texte, scenario(nom), "ci")
            .unwrap_or_else(|e| panic!("{texte:?} sur {nom}: {e}"));
        assert_eq!(vu, *attendu, "{texte:?} sur {nom}");
    }
    for texte in [
        "",
        "github.event_name ==",
        "(github.event_name == 'push'",
        "'abc",
        "github.event_name < 'x'",
        "inputs.windows == 'true'",
        "success(1)",
        "toJSON()",
    ] {
        assert!(
            evaluer_condition(texte, scenario("workflow_dispatch windows=true"), "ci").is_err(),
            "{texte:?} aurait du etre refuse"
        );
    }
    assert_eq!(
        interpoler(
            "${{ github.workflow }}-${{ github.event_name }}-${{ github.event.pull_request.number || github.ref }}",
            scenario(PLANIFIE),
            "ci"
        ),
        Ok("ci-schedule-refs/heads/main".to_string())
    );
}
