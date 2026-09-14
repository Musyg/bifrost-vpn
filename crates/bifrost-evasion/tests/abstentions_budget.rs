//! La garde de `scripts/abstentions-budget.sh` et des deux listes du depot.
//!
//! # Pourquoi cette recette existe
//!
//! La CI ne lance plus `cargo test --workspace` nu: elle passe par
//! `recettes-strict.sh` (qui rend les abstentions visibles avec --nocapture)
//! puis par `abstentions-budget.sh`, qui exige que chaque abstention du runner
//! soit ATTENDUE dans `ci/abstentions-attendues-<os>.txt`. Ce budget est un
//! palier vers `recettes-strict.sh --strict`, qui refusera toute abstention le
//! jour ou les deux listes seront vides.
//!
//! Un budget qui ne rougit pas ne garde rien. Cette recette EXERCE le script
//! sur des journaux fabriques et prouve qu'il rougit quand il le doit:
//!
//!   1. une abstention du journal absente de la liste (nouvelle) -> rouge;
//!   2. une ligne de liste de forme inconnue (chemin ou nombre brut) -> rouge;
//!   3. une liste a jour -> vert;
//!   4. une ligne de liste qui n'apparait plus (progres) -> vert, avec un
//!      avertissement.
//!
//! Elle controle aussi la FORME des deux listes reelles du depot: en-tete date
//! citant run et commit, corps trie (LC_ALL=C) et sans doublon, chaque ligne de
//! forme stable. C'est le pendant, cote listes, de ce que `sources_ascii.rs` et
//! `avis_ignores.rs` font pour d'autres fichiers.
//!
//! # Ce qu'elle suppose
//!
//! Un `bash` executable, comme tout ce qui exerce un script `.sh` dans ce
//! depot: la CI Windows lance ces etapes sous `shell: bash`, et dev-windows
//! passe par Git Bash. Si `bash` ne peut pas tourner, la recette panique plutot
//! que de rendre un faux vert - a l'image de `frontiere_licence.rs` qui exige
//! `cargo metadata`.
//!
//! # Lequel des deux `bash`, sous Windows
//!
//! Releve du 14/09/2026 sur les huit runs de la CI Windows du 05/09 (`b8df9a5`,
//! le commit qui a ajoute cette recette) au 13/09 (`4826229`): tous rouges a
//! l'etape des recettes, code 101, `recettes-strict.sh` comptant 207 vertes et
//! zero rouge avant de buter sur un journal devenu binaire (<< Binary file
//! matches >>). Le dernier run vert (`ed9366f`, le meme jour, sans cette
//! recette) comptait 1183 vertes sur ce runner. Sur dev-windows la meme suite
//! passe, et `C:\Windows\System32\bash.exe` n'y existe pas.
//!
//! Mecanisme infere, a confirmer au premier run: sous Windows, `Command::new`
//! avec un nom nu est resolu par `CreateProcess`, qui cherche dans le
//! repertoire systeme AVANT les repertoires du `PATH`. Sur le runner GitHub,
//! `System32\bash.exe` est le lanceur du sous-systeme Linux, sans
//! distribution: il ecrit son message en UTF-16, d'ou les octets nuls du
//! journal, et ne lance pas le script, d'ou les rouges. La resolution ci-dessous
//! parcourt donc le `PATH` elle-meme en ecartant tout repertoire sous
//! `SystemRoot`, et retombe sur l'emplacement usuel de Git Bash.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Le `bash` a lancer: sur les plateformes Unix, celui du `PATH`; sous Windows,
/// le premier `bash.exe` du `PATH` HORS du repertoire systeme, sinon Git Bash
/// a son emplacement d'installation par defaut, sinon le nom nu (et l'appel
/// echouera avec un message qui le dit).
fn bash() -> PathBuf {
    if !cfg!(windows) {
        return PathBuf::from("bash");
    }
    let racine_systeme = std::env::var_os("SystemRoot")
        .map(|s| s.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_else(|| "c:\\windows".to_string());
    let sous_le_systeme = |d: &Path| {
        d.to_string_lossy()
            .to_ascii_lowercase()
            .trim_end_matches(['\\', '/'])
            .starts_with(racine_systeme.trim_end_matches(['\\', '/']))
    };
    if let Some(chemin) = std::env::var_os("PATH") {
        for dossier in std::env::split_paths(&chemin) {
            if dossier.as_os_str().is_empty() || sous_le_systeme(&dossier) {
                continue;
            }
            let candidat = dossier.join("bash.exe");
            if candidat.is_file() {
                return candidat;
            }
        }
    }
    let usuel = PathBuf::from(r"C:\Program Files\Git\bin\bash.exe");
    if usuel.is_file() {
        return usuel;
    }
    PathBuf::from("bash")
}

fn racine() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("la racine de l'espace de travail doit exister")
        .to_path_buf()
}

/// Un chemin en avant-slash, que Git Bash accepte sur les deux plateformes.
fn pour_bash(p: &Path) -> String {
    p.display().to_string().replace('\\', "/")
}

fn script() -> String {
    pour_bash(&racine().join("scripts").join("abstentions-budget.sh"))
}

/// Lance le budget et rend (succes, sortie melangee). Panique si `bash` ne peut
/// pas tourner: cette garde exerce un script bash, son absence n'est pas un
/// resultat mesurable.
fn budget(args: &[&str]) -> (bool, String) {
    let interprete = bash();
    let sortie = Command::new(&interprete)
        .arg(script())
        .args(args)
        .output()
        .unwrap_or_else(|e| {
            panic!(
                "bash doit pouvoir tourner: cette garde exerce un script bash ({}: {e})",
                interprete.display()
            )
        });
    let mut texte = String::from_utf8_lossy(&sortie.stdout).into_owned();
    texte.push_str(&String::from_utf8_lossy(&sortie.stderr));
    (sortie.status.success(), texte)
}

/// Un dossier de travail propre a CE test, sous le repertoire temporaire que
/// cargo donne a la recette. Rien n'est ecrit dans le depot.
fn bac(nom: &str) -> PathBuf {
    let d = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(nom);
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("le bac de test doit pouvoir etre cree");
    d
}

fn ecrire(p: &Path, contenu: &str) -> String {
    std::fs::write(p, contenu).unwrap_or_else(|e| panic!("{} inecrivable: {e}", p.display()));
    pour_bash(p)
}

/// Un en-tete de liste bien forme: date, run, commit. Les tests qui eprouvent
/// le CORPS ont besoin d'un en-tete valide pour que l'hygiene ne masque pas ce
/// qu'ils mesurent.
const ENTETE: &str = "# Liste de test fabriquee.\n\
     # Releve fondateur 2026-09-05, run 33978299199, commit ed9366f.\n";

const LISTE_LINUX: &str = "ci/abstentions-attendues-linux.txt";
const LISTE_WINDOWS: &str = "ci/abstentions-attendues-windows.txt";

// --- La forme des deux listes reelles du depot -------------------------------

#[test]
fn les_deux_listes_du_depot_sont_bien_formees() {
    for rel in [LISTE_LINUX, LISTE_WINDOWS] {
        let chemin = pour_bash(&racine().join(rel));
        let (ok, sortie) = budget(&["--verifier-liste", &chemin]);
        assert!(ok, "{rel} n'est pas bien formee:\n{sortie}");
    }
}

/// Vrai si `texte` contient `mot` suivi d'espaces puis d'au moins `minimum`
/// caracteres acceptes par `accepte`: un run cite par son numero, un commit
/// par son SHA. Le mot seul ne suffit pas.
///
/// Le 14/09/2026, une falsification qui retirait les deux numeros de run de
/// l'en-tete de la liste Linux a laisse `contains("run")` vert: << runner >> et
/// << runs >> portaient encore le mot. Une garde qui accepte << runner >> pour un
/// numero de run ne garde rien (verificateur de `5l'`).
fn cite(texte: &str, mot: &str, minimum: usize, accepte: impl Fn(char) -> bool) -> bool {
    let bas = texte.to_lowercase();
    let mut depuis = 0;
    while let Some(pos) = bas[depuis..].find(mot) {
        let apres = &bas[depuis + pos + mot.len()..];
        let sans_espaces = apres.trim_start_matches([' ', '\t']);
        if sans_espaces.len() < apres.len()
            && sans_espaces.chars().take_while(|c| accepte(*c)).count() >= minimum
        {
            return true;
        }
        depuis += pos + mot.len();
    }
    false
}

fn cite_un_run(texte: &str) -> bool {
    cite(texte, "run", 6, |c| c.is_ascii_digit())
}

fn cite_un_commit(texte: &str) -> bool {
    cite(texte, "commit", 7, |c| c.is_ascii_hexdigit())
}

#[test]
fn la_citation_exige_un_numero_pas_seulement_le_mot() {
    assert!(cite_un_run("releve sur le run 34870873349, job Linux"));
    assert!(cite_un_run("Run\t33978299199"));
    assert!(!cite_un_run(
        "le runner a tcpdump, huit runs rouges, run a l'autre"
    ));
    assert!(!cite_un_run("run 12345"));
    assert!(!cite_un_run("run34870873349"));
    assert!(cite_un_commit("commit ed9366f, job Windows"));
    assert!(cite_un_commit("commit 7c687ab (5w')"));
    assert!(!cite_un_commit(
        "commite le 05/09, huit tranches commitees, commit ed"
    ));
    assert!(!cite_un_commit("commit ZZZZZZZ"));
}

#[test]
fn les_listes_du_depot_ont_un_entete_date_run_et_commit() {
    // Un controle direct, en plus de la delegation au script: si un jour le
    // script cessait de verifier l'en-tete, cette recette le remarquerait.
    for rel in [LISTE_LINUX, LISTE_WINDOWS] {
        let texte = std::fs::read_to_string(racine().join(rel))
            .unwrap_or_else(|e| panic!("{rel} illisible: {e}"));
        let entete: String = texte
            .lines()
            .take_while(|l| l.trim_start().starts_with('#') || l.trim().is_empty())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            entete.contains("2026-"),
            "{rel}: en-tete sans date de releve"
        );
        assert!(
            cite_un_run(&entete),
            "{rel}: en-tete qui ne cite aucun run de CI par son numero"
        );
        assert!(
            cite_un_commit(&entete),
            "{rel}: en-tete qui ne cite aucun commit par son SHA"
        );
    }
}

// --- Le script rougit quand il le doit --------------------------------------

#[test]
fn une_abstention_nouvelle_fait_rougir() {
    let d = bac("nouvelle");
    let liste = ecrire(
        &d.join("liste.txt"),
        &format!("{ENTETE}SKIPPED: wintun.dll absente a cote du binaire\n"),
    );
    let journal = ecrire(
        &d.join("journal.txt"),
        "        1 SKIPPED: wintun.dll absente a cote du binaire\n\
                 1 SKIPPED: un outil flambant neuf manque sur cette machine\n",
    );
    let (ok, sortie) = budget(&["--liste", &liste, "--journal", &journal]);
    assert!(
        !ok,
        "une abstention absente de la liste doit faire rougir:\n{sortie}"
    );
    assert!(
        sortie.contains("un outil flambant neuf"),
        "le rouge doit nommer l'abstention nouvelle:\n{sortie}"
    );
}

#[test]
fn une_raison_de_forme_inconnue_fait_rougir() {
    // Un chemin brut dans la liste: elle depend alors du runner, ce que la
    // garde de forme refuse.
    let d = bac("forme");
    let liste = ecrire(
        &d.join("liste.txt"),
        &format!("{ENTETE}SKIPPED: C:\\un\\chemin\\brut\\wintun.dll absente\n"),
    );
    let journal = ecrire(&d.join("journal.txt"), "rien ici\n");
    let (ok, sortie) = budget(&["--liste", &liste, "--journal", &journal]);
    assert!(
        !ok,
        "une ligne de liste non normalisee doit faire rougir:\n{sortie}"
    );
    assert!(
        sortie.contains("forme inconnue"),
        "le rouge doit dire que la forme est inconnue:\n{sortie}"
    );
}

#[test]
fn une_ligne_qui_ne_commence_pas_par_skipped_fait_rougir() {
    let d = bac("prefixe");
    let liste = ecrire(
        &d.join("liste.txt"),
        &format!("{ENTETE}ceci n'est pas une abstention\n"),
    );
    let journal = ecrire(&d.join("journal.txt"), "rien\n");
    let (ok, _sortie) = budget(&["--liste", &liste, "--journal", &journal]);
    assert!(!ok, "une ligne de corps hors SKIPPED doit faire rougir");
}

// --- Le script passe quand il le doit ---------------------------------------

#[test]
fn une_liste_a_jour_passe() {
    let d = bac("ajour");
    let corps = "SKIPPED: la cle du coffre est dans le TPM, qui n'est lisible que par root\n\
                 SKIPPED: ouvrir un TUN demande CAP_NET_ADMIN, ce test tourne sans\n";
    let liste = ecrire(&d.join("liste.txt"), &format!("{ENTETE}{corps}"));
    // Le journal contient EXACTEMENT ces abstentions (avec un compte, comme le
    // resume de recettes-strict.sh).
    let journal = ecrire(
        &d.join("journal.txt"),
        "        3 SKIPPED: la cle du coffre est dans le TPM, qui n'est lisible que par root\n\
                 9 SKIPPED: ouvrir un TUN demande CAP_NET_ADMIN, ce test tourne sans\n",
    );
    let (ok, sortie) = budget(&["--liste", &liste, "--journal", &journal]);
    assert!(ok, "une liste a jour doit passer:\n{sortie}");
    assert!(
        sortie.contains("budget tenu"),
        "un vert doit le dire:\n{sortie}"
    );
}

#[test]
fn une_ligne_en_trop_dans_la_liste_avertit_sans_rougir() {
    let d = bac("entrop");
    // La liste attend deux abstentions; le journal n'en porte qu'une. L'autre
    // est un progres: elle ne mesure plus rien, a retirer, sans rougir.
    let liste = ecrire(
        &d.join("liste.txt"),
        &format!(
            "{ENTETE}SKIPPED: creer un espace de noms reseau demande CAP_NET_ADMIN\n\
             SKIPPED: le binaire minisign n'est pas installe sur cette machine\n"
        ),
    );
    let journal = ecrire(
        &d.join("journal.txt"),
        "        2 SKIPPED: creer un espace de noms reseau demande CAP_NET_ADMIN\n",
    );
    let (ok, sortie) = budget(&["--liste", &liste, "--journal", &journal]);
    assert!(
        ok,
        "une abstention attendue mais absente est un progres, pas un rouge:\n{sortie}"
    );
    assert!(
        sortie.contains("progres") && sortie.contains("minisign"),
        "le vert doit signaler la ligne a retirer:\n{sortie}"
    );
}

#[test]
fn la_normalisation_recolle_chemin_et_nombre() {
    // Le meme chemin sous deux racines, ou le meme uid sous deux valeurs, ne
    // doit produire qu'UNE forme. On l'eprouve par le fait qu'une liste ecrite
    // avec les marqueurs <CHEMIN>/<N> accepte un journal aux valeurs concretes.
    let d = bac("normal");
    let liste = ecrire(
        &d.join("liste.txt"),
        &format!(
            "{ENTETE}SKIPPED la_garde: baisser l'UID demande root, or ce test tourne sous l'uid <N>\n\
             SKIPPED: <CHEMIN> absente: le depot ne distribue aucun binaire tiers\n"
        ),
    );
    let journal = ecrire(
        &d.join("journal.txt"),
        "        1 SKIPPED la_garde: baisser l'UID demande root, or ce test tourne sous l'uid 1001\n\
                 1 SKIPPED: D:\\a\\bifrost\\bifrost\\target\\debug\\deps\\wintun.dll absente: le depot ne distribue aucun binaire tiers\n",
    );
    let (ok, sortie) = budget(&["--liste", &liste, "--journal", &journal]);
    assert!(
        ok,
        "les valeurs concretes doivent se replier sur <CHEMIN>/<N>:\n{sortie}"
    );
}

#[test]
fn l_artefact_de_raison_perdue_ne_fait_pas_rougir() {
    // L'affichage parallele de recettes-strict.sh peut intercaler
    // << raison perdue a l affichage >>. Non deterministe: il ne doit ni
    // compter comme nouvelle abstention, ni etre exige.
    let d = bac("perdue");
    let liste = ecrire(
        &d.join("liste.txt"),
        &format!("{ENTETE}SKIPPED: creer un espace de noms reseau demande CAP_NET_ADMIN\n"),
    );
    let journal = ecrire(
        &d.join("journal.txt"),
        "        2 SKIPPED: creer un espace de noms reseau demande CAP_NET_ADMIN\n\
                 1 SKIPPED (raison perdue a l affichage: une autre recette s est intercalee. Rejouer avec --test-threads=1 pour la lire.)\n",
    );
    let (ok, sortie) = budget(&["--liste", &liste, "--journal", &journal]);
    assert!(
        ok,
        "l'artefact de raison perdue ne doit pas faire rougir:\n{sortie}"
    );
}

// --- L'hygiene de la liste: tri, doublon, en-tete ---------------------------

#[test]
fn verifier_liste_rougit_sur_corps_non_trie() {
    let d = bac("nontrie");
    let liste = ecrire(
        &d.join("liste.txt"),
        &format!(
            "{ENTETE}SKIPPED: ouvrir un TUN demande CAP_NET_ADMIN, ce test tourne sans\n\
             SKIPPED: creer un espace de noms reseau demande CAP_NET_ADMIN\n"
        ),
    );
    let (ok, sortie) = budget(&["--verifier-liste", &liste]);
    assert!(!ok, "un corps non trie doit faire rougir:\n{sortie}");
}

#[test]
fn verifier_liste_rougit_sur_doublon() {
    let d = bac("doublon");
    let liste = ecrire(
        &d.join("liste.txt"),
        &format!(
            "{ENTETE}SKIPPED: creer un espace de noms reseau demande CAP_NET_ADMIN\n\
             SKIPPED: creer un espace de noms reseau demande CAP_NET_ADMIN\n"
        ),
    );
    let (ok, sortie) = budget(&["--verifier-liste", &liste]);
    assert!(!ok, "un doublon doit faire rougir:\n{sortie}");
}

#[test]
fn verifier_liste_rougit_sur_entete_sans_date() {
    let d = bac("entete");
    let liste = ecrire(
        &d.join("liste.txt"),
        "# une liste sans date, sans run, sans commit\n\
         SKIPPED: creer un espace de noms reseau demande CAP_NET_ADMIN\n",
    );
    let (ok, sortie) = budget(&["--verifier-liste", &liste]);
    assert!(
        !ok,
        "un en-tete sans date/run/commit doit faire rougir:\n{sortie}"
    );
}

#[test]
fn verifier_liste_rougit_sur_entete_qui_porte_le_mot_run_sans_numero() {
    // Le cas qui a laisse la garde verte le 14/09/2026: << runner >> et
    // << runs >> dans l'en-tete, mais aucun numero de run. Le script doit
    // rougir sur le run ET sur le commit sans SHA.
    let d = bac("entete-mot-seul");
    let liste = ecrire(
        &d.join("liste.txt"),
        "# Releve 2026-09-14 sur le runner, huit runs rouges, commite le 05/09.
         SKIPPED: creer un espace de noms reseau demande CAP_NET_ADMIN
",
    );
    let (ok, sortie) = budget(&["--verifier-liste", &liste]);
    assert!(
        !ok,
        "un en-tete qui ne cite ni numero de run ni SHA de commit doit faire rougir:
{sortie}"
    );
    assert!(
        sortie.contains("par son numero") && sortie.contains("par son SHA"),
        "les deux manques doivent etre nommes:
{sortie}"
    );
}

#[test]
fn une_liste_vide_de_corps_reste_bien_formee() {
    // Le but final: une liste sans aucune abstention. Elle doit rester valide,
    // sinon on ne pourrait jamais atteindre le palier --strict.
    let d = bac("vide");
    let liste = ecrire(&d.join("liste.txt"), ENTETE);
    let (ok, sortie) = budget(&["--verifier-liste", &liste]);
    assert!(ok, "une liste au corps vide doit rester valide:\n{sortie}");
}
