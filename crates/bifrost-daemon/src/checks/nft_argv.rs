//! Grammaire UNIQUE de la ligne de commande de nft, partagee par les deux
//! gardes (5t, dixieme passage).
//!
//! # Pourquoi un module commun, derriere une porte d'OS
//!
//! Jusqu'au huitieme livre, le refus runtime (`netns::nft_en_lecture_seule`) et
//! la garde de source (`tests_source::nft_lecture_seule`) portaient CHACUN leur
//! propre lecture de l'argv nft, jumelles a la main. Le quatrieme FAIL a montre
//! le prix de deux copies: aucune des deux ne modelisait `getopt_long`. Trois
//! injections litterales passaient donc,
//!
//! - `nft -I list add table inet bfv6` : `-I` (includepath) CONSOMME le jeton
//!   suivant (`list`) comme son argument; le vrai verbe est `add`, mais les deux
//!   listes sautaient `-I` comme une option nue et lisaient `list` comme premier
//!   jeton hors option, donc << lecture >>;
//! - `nft -I -c add table inet bfv7` : `-c` est ici l'ARGUMENT de `-I`, pas
//!   l'option check; un `any(== "-c")` l'acceptait quand meme;
//! - `/usr/sbin/nft add table inet bfv5` : `argv[0]` compare a `"nft"` ENTIER
//!   ratait le chemin absolu.
//!
//! Une seule grammaire, un seul module, auquel les deux gardes DELEGUENT: la
//! garde ne peut plus diverger de ce qu'elle garde. Le module est garde par
//! `#[cfg(any(target_os = "linux", test))]` (voir sa declaration dans `mod.rs`):
//! ses deux utilisateurs sont `netns` (Linux) et `tests_source` (`cfg(test)`),
//! si bien qu'en bibliotheque Windows HORS test il n'aurait aucun utilisateur et
//! serait du `dead_code` sous `clippy -D warnings`. Ses recettes (`#[cfg(test)]`,
//! plus bas) tournent sur les deux hotes: le bras `test` de la porte les compile.
//!
//! # La ligne de commande de nft 1.0.9, telle que `nft --help` la donne
//!
//! Sortie de `nft --help` sur essai-linux (nftables v1.0.9, `Old Doc Yak #3`),
//! releve le 05/09/2026:
//!
//! ```text
//! Usage: nft [ options ] [ cmds... ]
//!
//! Options (general):
//!   -h, --help                      Show this help
//!   -v, --version                   Show version information
//!   -V                              Show extended version information
//!
//! Options (ruleset input handling):
//!   -f, --file <filename>           Read input from <filename>
//!   -D, --define <name=value>       Define variable, e.g. --define foo=1.2.3.4
//!   -i, --interactive               Read input from interactive CLI
//!   -I, --includepath <directory>   Add <directory> to the paths searched for include files. Default is: /etc
//!   -c, --check                     Check commands validity without actually applying the changes.
//!   -o, --optimize                  Optimize ruleset
//!
//! Options (ruleset list formatting):
//!   -a, --handle                    Output rule handle.
//!   -s, --stateless                 Omit stateful information of ruleset.
//!   -t, --terse                     Omit contents of sets.
//!   -S, --service                   Translate ports to service names as described in /etc/services.
//!   -N, --reversedns                Translate IP addresses to names.
//!   -u, --guid                      Print UID/GID as defined in /etc/passwd and /etc/group.
//!   -n, --numeric                   Print fully numerical output.
//!   -y, --numeric-priority          Print chain priority numerically.
//!   -p, --numeric-protocol          Print layer 4 protocols numerically.
//!   -T, --numeric-time              Print time values numerically.
//!
//! Options (command output formatting):
//!   -e, --echo                      Echo what has been added, inserted or replaced.
//!   -j, --json                      Format output in JSON
//!   -d, --debug <level [,level...]> Specify debugging level (scanner, parser, eval, netlink, mnl, proto-ctx, segtree, all)
//! ```
//!
//! nft appelle `getopt_long`: les options precedent la commande, une option
//! courte peut coller sa valeur (`-Ivaleur`) ou se grouper (`-nj` = `-n -j`),
//! une option longue peut coller sa valeur par `=` (`--includepath=x`). Le
//! PREMIER jeton hors option est le verbe; tout ce qui suit est concatene par
//! nft en un seul tampon (`nft_run_cmd_from_buffer`, src/main.c). D'ou la
//! grammaire retenue.

/// Options COURTES sans argument (ensemble FERME, de `nft --help` 1.0.9).
///
/// `-V` n'a pas de forme longue; les autres oui (voir [`LONGUES_SANS_ARG`]).
const COURTES_SANS_ARG: &[char] = &[
    'h', 'v', 'V', 'i', 'c', 'o', 'a', 's', 't', 'S', 'N', 'u', 'n', 'y', 'p', 'T', 'e', 'j',
];

/// Options COURTES avec argument (ensemble FERME, de `nft --help` 1.0.9):
/// `-f` fichier, `-D` define, `-I` includepath, `-d` debug. L'argument est le
/// reste de la grappe s'il y en a (`-Ivaleur`), sinon le jeton suivant (`-I x`).
const COURTES_AVEC_ARG: &[char] = &['f', 'D', 'I', 'd'];

/// Options LONGUES sans argument (ensemble FERME, de `nft --help` 1.0.9).
const LONGUES_SANS_ARG: &[&str] = &[
    "help",
    "version",
    "interactive",
    "check",
    "optimize",
    "handle",
    "stateless",
    "terse",
    "service",
    "reversedns",
    "guid",
    "numeric",
    "numeric-priority",
    "numeric-protocol",
    "numeric-time",
    "echo",
    "json",
];

/// Options LONGUES avec argument (ensemble FERME, de `nft --help` 1.0.9).
/// La valeur est collee par `=` (`--file=x`) ou le jeton suivant (`--file x`).
const LONGUES_AVEC_ARG: &[&str] = &["file", "define", "includepath", "debug"];

/// Un jeton porte-t-il un separateur de commande ou un antislash?
///
/// nft concatene ses arguments restants en un seul tampon separe d'espaces:
/// un `;`, un saut de ligne ou un retour chariot y OUVRE une seconde commande.
/// L'antislash, lui, n'apparait jamais dans un argv nft du banc (les jetons
/// sont `list`, `tables`, `-j`, `-f`, `-`, un nom de table); cote SOURCE il
/// signe une sequence d'echappement que le compilateur replierait en un
/// separateur reel (`"tables\nadd..."` -> `tables`, saut de ligne, `add...`),
/// invisible a une vue textuelle. On le refuse donc des DEUX cotes: cote source
/// il ferme cette porte, cote runtime il ne coute rien puisqu'un argv du banc
/// n'en porte jamais. Un tel jeton n'est PAS une lecture, quel que soit le
/// verbe de tete.
fn porte_un_separateur(jeton: &str) -> bool {
    jeton.contains(';') || jeton.contains('\n') || jeton.contains('\r') || jeton.contains('\\')
}

/// Les jetons `argv` (ceux qui SUIVENT le programme nft) sont-ils une LECTURE?
///
/// Liste BLANCHE, jamais une liste noire (une liste noire laisse passer le verbe
/// qu'on a oublie). L'argv est analyse comme `getopt_long` de nft 1.0.9
/// l'analyserait (voir l'en-tete du module pour la sortie de `nft --help`):
///
/// - aucun jeton ne porte `;`, `\n`, `\r` ni un antislash (cf.
///   [`porte_un_separateur`]);
/// - les options sont classees sur les ensembles FERMES ci-dessus: une option
///   AVEC argument CONSOMME sa valeur (le reste de la grappe pour `-Ivaleur`,
///   la partie apres `=` pour `--includepath=x`, sinon le jeton suivant), si
///   bien que ce jeton-la n'est jamais pris pour le verbe ni pour un `-c`;
/// - une option INCONNUE (courte ou longue) -> pas une lecture;
/// - `--` termine les options: le premier operande qui suit est le verbe;
/// - `-c` / `--check` ne compte que rencontre COMME OPTION (jamais comme
///   argument d'une autre): c'est tout le sens du FAIL `nft -I -c add`, ou `-c`
///   est l'includepath, pas la verification.
///
/// Une lecture est alors: `-c`/`--check` rencontre comme option, OU premier
/// jeton hors option egal a `list`. Aucun jeton APRES le verbe n'est examine,
/// sauf pour les separateurs (deja verifies sur tout l'argv en tete).
///
/// # Sur-acceptation connue, sans effet
///
/// La grammaire modelise `getopt_long`, pas la validation semantique de nft.
/// `-D x=1 list tables` est classe LECTURE ici -- l'option `-D`/`--define`
/// consomme son argument `x=1`, puis `list` est le premier operande -- alors que
/// nft 1.0.9 rend une erreur SANS rien poser (mesure du verificateur). C'est une
/// sur-acceptation sans effet: la garde peut classer LECTURE une ligne que nft
/// refusera de toute facon; l'inverse -- laisser passer une modification pour
/// une lecture -- est ce qu'elle interdit, et ne se produit pas ici.
///
/// # Verite unique
///
/// Le refus runtime `netns::nft_en_lecture_seule` et la garde de source
/// `tests_source::nft_lecture_seule` DELEGUENT tous deux ici, sans copie. Le
/// runtime voit des caracteres reels; la source voit le TEXTE d'un litteral,
/// antislashs conserves: le refus de l'antislash rend les deux vues identiques.
pub(crate) fn est_une_lecture(argv: &[&str]) -> bool {
    if argv.iter().any(|a| porte_un_separateur(a)) {
        return false;
    }
    let mut i = 0usize;
    let mut vu_check = false;
    let mut fin_des_options = false;
    while i < argv.len() {
        let tok = argv[i];
        if fin_des_options {
            return vu_check || tok == "list";
        }
        if tok == "--" {
            fin_des_options = true;
            i += 1;
            continue;
        }
        // Un operande (ne commence pas par `-`, ou `-` seul = stdin/`-f -`): le
        // verbe. On rend le verdict sans regarder plus loin.
        if !tok.starts_with('-') || tok == "-" {
            return vu_check || tok == "list";
        }
        // tok est une option (commence par `-`, longueur >= 2).
        if let Some(long) = tok.strip_prefix("--") {
            let (nom, valeur_collee) = match long.split_once('=') {
                Some((n, _)) => (n, true),
                None => (long, false),
            };
            if LONGUES_SANS_ARG.contains(&nom) {
                // Une option sans argument affublee d'une `=valeur` n'existe pas:
                // option inconnue de fait -> pas une lecture.
                if valeur_collee {
                    return false;
                }
                if nom == "check" {
                    vu_check = true;
                }
                i += 1;
            } else if LONGUES_AVEC_ARG.contains(&nom) {
                // `--file=x` colle sa valeur; `--file x` prend le jeton suivant.
                i += if valeur_collee { 1 } else { 2 };
            } else {
                return false; // option longue inconnue
            }
        } else {
            // Grappe d'options courtes: `-c`, `-nj`, `-Ivaleur`, `-f`.
            let corps: Vec<char> = tok[1..].chars().collect();
            let mut j = 0usize;
            let mut consomme_jeton_suivant = false;
            while j < corps.len() {
                let ch = corps[j];
                if COURTES_SANS_ARG.contains(&ch) {
                    if ch == 'c' {
                        vu_check = true;
                    }
                    j += 1;
                } else if COURTES_AVEC_ARG.contains(&ch) {
                    // Le reste de la grappe est la valeur collee (`-Ivaleur`); si
                    // la grappe s'arrete sur cette option, la valeur est le jeton
                    // suivant (`-I x`, `-f -`).
                    if j + 1 == corps.len() {
                        consomme_jeton_suivant = true;
                    }
                    break;
                } else {
                    return false; // option courte inconnue
                }
            }
            i += if consomme_jeton_suivant { 2 } else { 1 };
        }
    }
    // Aucun operande: lecture seulement si `-c`/`--check` a ete vu comme option.
    vu_check
}

/// Ce jeton designe-t-il le programme nft, par son NOM DE FICHIER?
///
/// `nft`, `/usr/sbin/nft`, `./nft` -> vrai; `env`, `nft add table` (un jeton qui
/// EMBARQUE une commande, cf. [`jeton_embarque_commande_nft`]) -> faux. C'est la
/// reconnaissance qui manquait au FAIL 3 (`/usr/sbin/nft` compare a `"nft"`
/// entier). Les deux gardes s'en servent pour trouver nft a TOUTE position de
/// l'argv (`env nft`, `nice nft`, `timeout 5 nft`, `ip netns exec <ns> nft`).
pub(crate) fn jeton_est_nft(jeton: &str) -> bool {
    std::path::Path::new(jeton)
        .file_name()
        .and_then(|n| n.to_str())
        == Some("nft")
}

/// Ce jeton EMBARQUE-t-il une commande shell nft (`sh -c "nft add ..."`)?
///
/// # La seule concession a la liste noire, et pourquoi
///
/// Toute la grammaire ci-dessus est une liste BLANCHE. Une invocation qui passe
/// nft dans le TEXTE d'un argument shell (`sh`, `bash -c`) ne l'expose pas comme
/// `argv[i]` reconnaissable par [`jeton_est_nft`]: elle le cache dans une chaine
/// que la grammaire ne parse pas. On ne peut pas modeliser la ligne de commande
/// d'un shell arbitraire; on refuse donc, par liste NOIRE assumee, tout jeton
/// (qui n'est pas deja un chemin nft) contenant le MOT `nft` -- borne a gauche
/// par un debut de jeton, un blanc ou un `/`, et a droite par un blanc ou la fin
/// du jeton. C'est la seule entorse a la liste blanche: un shell est un langage
/// qu'on ne veut pas re-implementer, et un argv nft du banc ne porte jamais un
/// tel jeton compose. Applique des DEUX cotes (runtime et texte).
pub(crate) fn jeton_embarque_commande_nft(jeton: &str) -> bool {
    // Un chemin nft nu est reconnu par [`jeton_est_nft`], pas ici.
    if jeton_est_nft(jeton) {
        return false;
    }
    let o = jeton.as_bytes();
    let n = o.len();
    let mut deb = 0usize;
    while deb + 3 <= n {
        if &o[deb..deb + 3] == b"nft" {
            let fin = deb + 3;
            let gauche_ok = deb == 0 || o[deb - 1].is_ascii_whitespace() || o[deb - 1] == b'/';
            let droite_ok = fin == n || o[fin].is_ascii_whitespace();
            if gauche_ok && droite_ok {
                return true;
            }
        }
        deb += 1;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    // Jeux d'essai migres depuis `tests_source::nft_lecture_seule_jeu_d_essai`
    // (mod.rs) et `netns::tests::nft_json_list_est_une_lecture` (netns.rs): la
    // grammaire est desormais UNE, et ses recettes tournent sur les deux hotes,
    // sans root.

    #[test]
    fn lectures_acceptees() {
        assert!(est_une_lecture(&["list", "tables"]));
        assert!(est_une_lecture(&["list", "table", "inet", "x"]));
        assert!(est_une_lecture(&["list", "ruleset"]));
        // `-j` (json) precede le verbe: lecture.
        assert!(est_une_lecture(&["-j", "list", "tables"]));
        // Groupe d'options courtes sans argument devant `list`.
        assert!(est_une_lecture(&["-nj", "list", "tables"]));
        // `-c`/`--check` comme option: verification SANS application = lecture.
        assert!(est_une_lecture(&["-c", "-f", "-"]));
        assert!(est_une_lecture(&["-c", "add", "table", "inet", "x"]));
        assert!(est_une_lecture(&["--check", "add", "table", "inet", "x"]));
        // `--` termine les options: le verbe `list` suit.
        assert!(est_une_lecture(&["--", "list", "tables"]));
    }

    #[test]
    fn modifications_refusees() {
        assert!(!est_une_lecture(&["add", "table", "inet", "x"]));
        assert!(!est_une_lecture(&["delete", "table", "inet", "x"]));
        assert!(!est_une_lecture(&["flush", "ruleset"]));
        assert!(!est_une_lecture(&["-j", "add", "table", "inet", "x"]));
        // `nft -f -`: applique l'entree standard, ce n'est pas une lecture.
        assert!(!est_une_lecture(&["-f", "-"]));
        // nft seul, ou apres `--`, un verbe qui modifie.
        assert!(!est_une_lecture(&[]));
        assert!(!est_une_lecture(&["--", "add", "table"]));
        // `--` termine les options: apres lui, `-c` n'est plus l'option check,
        // c'est le premier operande, et il n'est pas `list` -> pas une lecture.
        // Jumele au `["--", "list", "tables"]` de `lectures_acceptees`: si `--`
        // cessait de terminer les options (skip sans poser fin_des_options),
        // `-c` serait relu comme l'option check et ce cas serait sur-accepte.
        // Sans ce cas, rendre `--` inoperant ne faisait rougir aucune recette.
        assert!(!est_une_lecture(&["--", "-c", "add", "table", "inet", "x"]));
    }

    #[test]
    fn les_trois_lignes_du_fail() {
        // (1) `-I` (includepath) consomme `list`; le verbe est `add`.
        assert!(!est_une_lecture(&[
            "-I", "list", "add", "table", "inet", "bfv6"
        ]));
        // (2) `-c` est ici l'ARGUMENT de `-I`, pas l'option check.
        assert!(!est_une_lecture(&[
            "-I", "-c", "add", "table", "inet", "bfv7"
        ]));
        // (3) est une affaire de reconnaissance du programme, cf.
        // `reconnaissance_du_programme`; ici l'argv APRES nft.
        assert!(!est_une_lecture(&["add", "table", "inet", "bfv5"]));
    }

    #[test]
    fn formes_collees_de_l_includepath() {
        // `-Ilist`: `list` est la valeur collee de l'includepath, `add` le verbe.
        assert!(!est_une_lecture(&["-Ilist", "add", "table", "inet", "x"]));
        // `--includepath=x`: valeur collee, `add` le verbe.
        assert!(!est_une_lecture(&[
            "--includepath=x",
            "add",
            "table",
            "inet",
            "x"
        ]));
        // Forme separee: `--includepath x add` et `-I x add`.
        assert!(!est_une_lecture(&["--includepath", "x", "add", "table"]));
        assert!(!est_une_lecture(&["-I", "x", "add", "table"]));
        // Un includepath devant une VRAIE lecture reste une lecture.
        assert!(est_une_lecture(&["-I", "/etc", "list", "tables"]));
        assert!(est_une_lecture(&["-Ietc", "list", "tables"]));
    }

    #[test]
    fn options_inconnues_et_valeurs_illegitimes() {
        // Option courte inconnue.
        assert!(!est_une_lecture(&["-z", "list", "tables"]));
        // Option longue inconnue.
        assert!(!est_une_lecture(&["--zorglub", "list", "tables"]));
        // Une option sans argument ne prend pas de `=valeur`.
        assert!(!est_une_lecture(&["--json=x", "list", "tables"]));
    }

    #[test]
    fn separateurs_et_antislash() {
        assert!(!est_une_lecture(&["list", "tables;"]));
        assert!(!est_une_lecture(&["-j", "list", "tables;"]));
        // Antislash: cote source, une sequence d'echappement cachant un
        // separateur reel; refusee des deux cotes.
        assert!(!est_une_lecture(&["list", "tables\\nadd table inet x"]));
        assert!(!est_une_lecture(&["list", "tables\\x3badd table inet x"]));
        // Saut de ligne / retour chariot reels (ce que le runtime voit).
        assert!(!est_une_lecture(&["list", "tables\nadd table inet x"]));
        assert!(!est_une_lecture(&["list", "tables\radd table inet x"]));
    }

    #[test]
    fn reconnaissance_du_programme() {
        assert!(jeton_est_nft("nft"));
        assert!(jeton_est_nft("/usr/sbin/nft"));
        assert!(jeton_est_nft("./nft"));
        assert!(!jeton_est_nft("env"));
        assert!(!jeton_est_nft("nftables"));
        assert!(!jeton_est_nft(""));
        // Un jeton qui EMBARQUE une commande n'est pas un chemin nft.
        assert!(!jeton_est_nft("nft add table inet x"));
    }

    #[test]
    fn commande_nft_embarquee() {
        // Le corps d'un `sh -c "nft add ..."`.
        assert!(jeton_embarque_commande_nft("nft add table inet x"));
        assert!(jeton_embarque_commande_nft("echo hi; nft"));
        assert!(jeton_embarque_commande_nft("/usr/sbin/nft add table"));
        // Un chemin nft nu n'est PAS traite ici (reconnu par jeton_est_nft).
        assert!(!jeton_embarque_commande_nft("nft"));
        assert!(!jeton_embarque_commande_nft("/usr/sbin/nft"));
        // `nft` en sous-chaine d'un mot n'est pas une commande.
        assert!(!jeton_embarque_commande_nft("nftables"));
        assert!(!jeton_embarque_commande_nft("list"));
        assert!(!jeton_embarque_commande_nft("runft-machin"));
    }
}
