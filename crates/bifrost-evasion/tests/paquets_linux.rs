//! Les paquets Linux font ce que fait `packaging/install-linux.sh`, et rien
//! de plus qui change la machine.
//!
//! # Pourquoi cette recette existe
//!
//! Le depot installe Bifrost sous Linux par deux chemins: l'installateur
//! (`packaging/install-linux.sh`) et les paquets (`packaging/deb/`, assemble
//! par `scripts/paquets-linux.sh`, et `packaging/rpm/bifrost.spec`). Deux
//! chemins ecrits a la main divergent en silence: un mode de fichier change
//! d'un cote, un compte renomme de l'autre, un `systemctl enable` ajoute dans
//! un script du mainteneur, et chaque chemin reste vert sur la machine qui
//! l'essaie. Le .deb ne s'installe que sur le runner jetable de la CI, le .rpm
//! nulle part: cette recette lit les textes, sur chaque hote.
//!
//! # Ce qu'elle exige
//!
//! 1. Les fichiers que pose l'installateur, les paquets les posent aux memes
//!    destinations, aux memes modes, depuis la meme source de `packaging/`.
//!    Une seule exception, nommee: l'unite, que l'installateur pose sous
//!    `/etc/systemd/system` et un paquet sous `/usr/lib/systemd/system`. Le
//!    .deb et le .rpm posent entre eux les memes fichiers aux memes modes, a
//!    leur fichier de copyright pres (`/usr/share/doc` contre
//!    `/usr/share/licenses`).
//! 2. Les comptes: la meme declaration (`packaging/sysusers.d/bifrost.conf`,
//!    un groupe `bifrost`, deux comptes `bifrost-coeur` et
//!    `bifrost-resolveur`), appliquee par `systemd-sysusers` dans
//!    l'installateur, le postinst et le `%post`, avec les memes refus: un
//!    compte de service membre du groupe de pilotage, deux comptes qui
//!    partagent un uid.
//! 3. Le demarrage: ni l'installateur, ni le postinst, ni le `%post`
//!    n'active, ne demarre ou ne relance le service. Le retrait (prerm,
//!    `%preun`) l'arrete, le desactive et retire les filtres.
//! 4. Une version (`@VERSION@`), un mainteneur sans donnee personnelle (le
//!    contact public du depot), la licence du depot, les memes dependances
//!    hors bibliotheques, et la regle des trois commandes du groupe dite par
//!    les textes des paquets et les pages de manuel.
//!
//! # Ce qu'elle ne fait pas
//!
//! Elle ne construit ni n'installe rien: `scripts/paquets-linux.sh` construit
//! et verifie le .deb, `scripts/paquets-linux-installer.sh` l'installe et le
//! retire sur le runner. Elle lit le shell ligne a ligne (commentaires de
//! ligne entiere et documents en ligne ecartes, continuations jointes,
//! variables simples resolues); une forme qu'elle ne sait pas lire fait
//! rougir une de ses exigences au lieu d'etre devinee. Elle lit sur le
//! disque, sans git.

use std::collections::BTreeMap;
use std::path::PathBuf;

fn racine() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("la racine de l'espace de travail doit exister")
        .to_path_buf()
}

fn lire(relatif: &str) -> String {
    std::fs::read_to_string(racine().join(relatif))
        .unwrap_or_else(|e| panic!("{relatif} illisible: {e}"))
}

const INSTALLATEUR: &str = "packaging/install-linux.sh";
const CONSTRUCTEUR: &str = "scripts/paquets-linux.sh";
const SPEC: &str = "packaging/rpm/bifrost.spec";
const CONTROL: &str = "packaging/deb/control";
const COPYRIGHT: &str = "packaging/deb/copyright";
const POSTINST: &str = "packaging/deb/postinst";
const PRERM: &str = "packaging/deb/prerm";
const POSTRM: &str = "packaging/deb/postrm";
const DECLARATION: &str = "packaging/sysusers.d/bifrost.conf";
const MAN_CLI: &str = "packaging/man/bifrost-cli.1";
const MAN_DAEMON: &str = "packaging/man/bifrost-daemon.1";
const CONTACT: &str = "Bifrost <security@inaricom.com>";

/// L'unite: l'installateur la pose ou l'administrateur range les siennes, un
/// paquet ou les paquets rangent les leurs. Meme fichier.
const UNITE_INSTALLATEUR: &str = "/etc/systemd/system/bifrost-daemon.service";
const UNITE_PAQUET: &str = "/usr/lib/systemd/system/bifrost-daemon.service";

/// Lignes actives d'un texte shell: continuations `\` jointes, commentaires
/// de ligne entiere et corps des documents en ligne (`<<MOT` jusqu'a `MOT`)
/// ecartes, chaque ligne sans ses blancs de tete et de fin.
fn lignes_shell(texte: &str) -> Vec<String> {
    let mut jointes: Vec<String> = Vec::new();
    let mut courante = String::new();
    for l in texte.lines() {
        if let Some(debut) = l.strip_suffix('\\') {
            courante.push_str(debut);
            courante.push(' ');
            continue;
        }
        courante.push_str(l);
        jointes.push(std::mem::take(&mut courante));
    }
    if !courante.is_empty() {
        jointes.push(courante);
    }
    let mut actives = Vec::new();
    let mut fin_document: Option<String> = None;
    for l in jointes {
        let t = l.trim();
        if let Some(mot) = &fin_document {
            if t == mot {
                fin_document = None;
            }
            continue;
        }
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        if let Some(mot) = document_en_ligne(t) {
            fin_document = Some(mot);
        }
        actives.push(t.to_string());
    }
    actives
}

/// Le delimiteur d'un document en ligne ouvert sur cette ligne (`<<MOT`,
/// `<<-MOT`, `<<'MOT'`), jamais une chaine en ligne (`<<<`).
fn document_en_ligne(ligne: &str) -> Option<String> {
    let mut reste = ligne;
    while let Some(p) = reste.find("<<") {
        let apres = &reste[p + 2..];
        if let Some(suite) = apres.strip_prefix('<') {
            reste = suite;
            continue;
        }
        let apres = apres.trim_start_matches('-').trim_start();
        let apres = apres.trim_start_matches(['\'', '"']);
        let mot: String = apres
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if !mot.is_empty() {
            return Some(mot);
        }
        reste = apres;
    }
    None
}

/// Les affectations simples `NOM=valeur` d'un script (guillemets doubles
/// retires), sans substitution de commande. `imposees` l'emportent: ce que la
/// recette ne peut pas evaluer (un `$(cd ...)`, un `${1:-...}`) y recoit sa
/// valeur relative a la racine du depot.
fn affectations(lignes: &[String], imposees: &[(&str, &str)]) -> BTreeMap<String, String> {
    let mut vars = BTreeMap::new();
    for l in lignes {
        let Some((nom, valeur)) = l.split_once('=') else {
            continue;
        };
        if nom.is_empty() || !nom.bytes().all(|b| b.is_ascii_uppercase() || b == b'_') {
            continue;
        }
        if valeur.contains("$(")
            || valeur.contains("${")
            || (valeur.contains(' ') && !valeur.starts_with('"'))
        {
            continue;
        }
        vars.insert(nom.to_string(), valeur.trim_matches('"').to_string());
    }
    for (nom, valeur) in imposees {
        vars.insert((*nom).to_string(), (*valeur).to_string());
    }
    vars
}

/// `texte` avec ses `$NOM` et `${NOM}` connus remplaces, guillemets doubles
/// retires. Les autres `$` restent tels quels.
fn resoudre(texte: &str, vars: &BTreeMap<String, String>) -> String {
    let mut s = texte.replace('"', "");
    for _ in 0..6 {
        let mut suivant = String::new();
        let o = s.as_bytes();
        let mut i = 0usize;
        while i < o.len() {
            if o[i] == b'$' {
                let (debut, accolade) = if o.get(i + 1) == Some(&b'{') {
                    (i + 2, true)
                } else {
                    (i + 1, false)
                };
                let mut j = debut;
                while j < o.len() && (o[j].is_ascii_uppercase() || o[j] == b'_') {
                    j += 1;
                }
                let nom = &s[debut..j];
                let ferme = !accolade || o.get(j) == Some(&b'}');
                if !nom.is_empty()
                    && ferme
                    && let Some(v) = vars.get(nom)
                {
                    suivant.push_str(v);
                    i = if accolade { j + 1 } else { j };
                    continue;
                }
            }
            suivant.push(o[i] as char);
            i += 1;
        }
        if suivant == s {
            break;
        }
        s = suivant;
    }
    s
}

/// Les poses `install ... -m MODE SOURCE DESTINATION` d'une liste de lignes
/// deja resolues: destination -> (mode, source). Une pose dont la source ou
/// la destination garde un `$` non resolu est ecartee (le resolveur chiffre,
/// que l'installateur ne pose que si on le lui donne).
fn poses(lignes: &[String]) -> BTreeMap<String, (String, String)> {
    let mut sortie = BTreeMap::new();
    for l in lignes {
        let mots: Vec<&str> = l.split_whitespace().collect();
        if mots.first() != Some(&"install") {
            continue;
        }
        let mut mode = String::new();
        let mut libres = Vec::new();
        let mut k = 1usize;
        while k < mots.len() {
            match mots[k] {
                "-m" => {
                    mode = mots.get(k + 1).copied().unwrap_or("").to_string();
                    k += 2;
                }
                "-o" | "-g" => k += 2,
                m if m.starts_with('-') => k += 1,
                m => {
                    libres.push(m);
                    k += 1;
                }
            }
        }
        // Une source relative a la racine du depot s'ecrit `./x` ou `x`.
        if let [source, destination] = libres.as_slice()
            && !source.contains('$')
            && !destination.contains('$')
        {
            let source = source.trim_start_matches("./");
            sortie.insert((*destination).to_string(), (mode, source.to_string()));
        }
    }
    sortie
}

/// Les poses de l'installateur, du .deb et du .rpm.
type Poses = BTreeMap<String, (String, String)>;

fn poses_de_l_installateur(texte: &str) -> Poses {
    let lignes = lignes_shell(texte);
    let vars = affectations(&lignes, &[("ICI", "packaging"), ("BIN", "BIN")]);
    poses(
        &lignes
            .iter()
            .map(|l| resoudre(l, &vars))
            .collect::<Vec<_>>(),
    )
}

fn poses_du_deb(texte: &str) -> Poses {
    let lignes = lignes_shell(texte);
    let vars = affectations(
        &lignes,
        &[("RACINE_DEPOT", "."), ("BIN", "BIN"), ("ARBRE", "")],
    );
    let mut p = poses(
        &lignes
            .iter()
            .map(|l| resoudre(l, &vars))
            .collect::<Vec<_>>(),
    );
    // Les scripts du mainteneur vont dans DEBIAN/, hors du systeme de fichiers.
    p.retain(|destination, _| !destination.starts_with("/DEBIAN/"));
    p
}

/// La section `%nom` d'un spec, jusqu'a la section suivante.
fn section<'a>(spec: &'a str, nom: &str) -> Vec<&'a str> {
    let mut dedans = false;
    let mut lignes = Vec::new();
    for l in spec.lines() {
        if l.starts_with('%')
            && !l.starts_with("%{")
            && !l.starts_with("%attr")
            && !l.starts_with("%license")
        {
            dedans = l.split_whitespace().next() == Some(nom);
            continue;
        }
        if dedans {
            lignes.push(l);
        }
    }
    lignes
}

fn poses_du_rpm(spec: &str) -> Poses {
    let lignes: Vec<String> = section(spec, "%install")
        .iter()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| {
            l.replace("%{bindir_source}", "BIN")
                .replace("%{pkg_source}", "packaging")
                .replace("%{buildroot}", "")
        })
        .collect();
    poses(&lignes)
}

fn ecarts_de_poses(installateur: &Poses, deb: &Poses, rpm: &Poses) -> Vec<String> {
    let mut ecarts = Vec::new();
    if installateur.len() < 5 {
        ecarts.push(format!(
            "{} pose(s) lue(s) dans {INSTALLATEUR}: la lecture est cassee",
            installateur.len()
        ));
    }
    for (destination, attendu) in installateur {
        let cible = if destination == UNITE_INSTALLATEUR {
            UNITE_PAQUET
        } else {
            destination.as_str()
        };
        for (nom, paquet) in [("le .deb", deb), ("le .rpm", rpm)] {
            match paquet.get(cible) {
                Some(lu) if lu == attendu => {}
                Some((mode, source)) => ecarts.push(format!(
                    "{nom} pose {cible} en {mode} depuis {source}, l'installateur en {} depuis {}",
                    attendu.0, attendu.1
                )),
                None => ecarts.push(format!(
                    "{nom} ne pose pas {cible}, que l'installateur pose ({destination})"
                )),
            }
        }
    }
    let sans_copyright = |p: &Poses| -> Poses {
        p.iter()
            .filter(|(d, _)| !d.ends_with("/bifrost/copyright"))
            .map(|(d, v)| (d.clone(), v.clone()))
            .collect()
    };
    if sans_copyright(deb) != sans_copyright(rpm) {
        ecarts.push(format!(
            "le .deb et le .rpm ne posent pas les memes fichiers aux memes modes:\n    deb {:?}\n    rpm {:?}",
            sans_copyright(deb),
            sans_copyright(rpm)
        ));
    }
    ecarts
}

#[test]
fn les_paquets_posent_les_fichiers_de_l_installateur_aux_memes_modes() {
    let ecarts = ecarts_de_poses(
        &poses_de_l_installateur(&lire(INSTALLATEUR)),
        &poses_du_deb(&lire(CONSTRUCTEUR)),
        &poses_du_rpm(&lire(SPEC)),
    );
    assert!(
        ecarts.is_empty(),
        "{} ecart(s):\n  {}",
        ecarts.len(),
        ecarts.join("\n  ")
    );
}

/// Ce que l'installateur, le postinst et le `%post` disent tous trois des
/// comptes, une fois leurs variables resolues: la meme declaration appliquee
/// par systemd-sysusers, les deux comptes passes en revue contre le groupe de
/// pilotage, leurs uid compares.
const CONTRAT_DES_COMPTES: [&str; 5] = [
    "systemd-sysusers /usr/lib/sysusers.d/bifrost.conf",
    "for compte in bifrost-coeur bifrost-resolveur",
    "grep -x bifrost",
    "id -u bifrost-coeur",
    "id -u bifrost-resolveur",
];

fn ecarts_des_comptes(
    installateur: &str,
    postinst: &str,
    spec: &str,
    declaration: &str,
) -> Vec<String> {
    let mut ecarts = Vec::new();
    let entrees: Vec<String> = declaration
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.split_whitespace().take(2).collect::<Vec<_>>().join(" "))
        .collect();
    if entrees != ["g bifrost", "u bifrost-coeur", "u bifrost-resolveur"] {
        ecarts.push(format!("{DECLARATION} declare {entrees:?}"));
    }
    let resolu = |texte: &str, imposees: &[(&str, &str)]| -> String {
        let lignes = lignes_shell(texte);
        let vars = affectations(&lignes, imposees);
        lignes
            .iter()
            .map(|l| resoudre(l, &vars))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let post: Vec<String> = section(spec, "%post")
        .iter()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    for (nom, texte) in [
        (INSTALLATEUR, resolu(installateur, &[("ICI", "packaging")])),
        (POSTINST, resolu(postinst, &[])),
        ("%post du spec", post.join("\n")),
    ] {
        for fragment in CONTRAT_DES_COMPTES {
            if !texte.contains(fragment) {
                ecarts.push(format!("{nom} ne porte pas `{fragment}`"));
            }
        }
    }
    ecarts
}

#[test]
fn les_comptes_sont_ceux_de_l_installateur() {
    let ecarts = ecarts_des_comptes(
        &lire(INSTALLATEUR),
        &lire(POSTINST),
        &lire(SPEC),
        &lire(DECLARATION),
    );
    assert!(
        ecarts.is_empty(),
        "{} ecart(s):\n  {}",
        ecarts.len(),
        ecarts.join("\n  ")
    );
}

/// Les verbes de systemctl qui activent, demarrent ou relancent.
const VERBES_QUI_DEMARRENT: [&str; 8] = [
    "enable",
    "start",
    "restart",
    "try-restart",
    "reload-or-restart",
    "try-reload-or-restart",
    "reenable",
    "preset",
];

/// Les commandes d'une ligne: decoupee aux `;`, `&&`, `||`, `|`, puis sans
/// les mots de controle de tete (`then`, `do`, `else`, `if`, `!`).
fn commandes_de(ligne: &str) -> Vec<Vec<String>> {
    let mut morceaux = vec![ligne.to_string()];
    for sep in ["&&", "||", ";", "|"] {
        morceaux = morceaux
            .iter()
            .flat_map(|m| m.split(sep).map(str::to_string).collect::<Vec<_>>())
            .collect();
    }
    morceaux
        .iter()
        .map(|m| {
            m.split_whitespace()
                .skip_while(|w| matches!(*w, "then" | "do" | "else" | "if" | "!" | "elif"))
                .map(str::to_string)
                .collect::<Vec<String>>()
        })
        .filter(|c| !c.is_empty())
        .collect()
}

/// Une commande qui active, demarre ou relance le service.
fn demarre(commande: &[String]) -> bool {
    match commande.first().map(String::as_str) {
        Some("systemctl") => {
            commande
                .iter()
                .skip(1)
                .find(|w| !w.starts_with('-'))
                .is_some_and(|v| VERBES_QUI_DEMARRENT.contains(&v.as_str()))
                || commande.iter().any(|w| w == "--now")
        }
        Some("deb-systemd-invoke") => commande
            .iter()
            .any(|w| VERBES_QUI_DEMARRENT.contains(&w.as_str())),
        _ => false,
    }
}

fn ecarts_du_demarrage(
    installateur: &str,
    postinst: &str,
    spec: &str,
    prerm: &str,
    postrm: &str,
) -> Vec<String> {
    let mut ecarts = Vec::new();
    let scriptlet = |nom: &str| -> Vec<String> {
        section(spec, nom)
            .iter()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect()
    };
    // Tous les scripts du mainteneur, retrait compris: un `enable` laisse par
    // le prerm ou le postrm ferait demarrer le service au boot suivant.
    for (nom, lignes) in [
        (INSTALLATEUR, lignes_shell(installateur)),
        (POSTINST, lignes_shell(postinst)),
        (PRERM, lignes_shell(prerm)),
        (POSTRM, lignes_shell(postrm)),
        ("%post du spec", scriptlet("%post")),
        ("%preun du spec", scriptlet("%preun")),
        ("%postun du spec", scriptlet("%postun")),
    ] {
        for l in &lignes {
            if commandes_de(l).iter().any(|c| demarre(c)) {
                ecarts.push(format!("{nom} active ou demarre le service: `{l}`"));
            }
        }
    }
    let preun: Vec<String> = section(spec, "%preun")
        .iter()
        .map(|l| l.trim().to_string())
        .collect();
    for (nom, texte) in [
        (PRERM, lignes_shell(prerm).join("\n")),
        ("%preun du spec", preun.join("\n")),
    ] {
        for attendu in [
            "systemctl stop bifrost-daemon.service",
            "systemctl disable bifrost-daemon.service",
            "bifrost-daemon --cleanup-firewall",
        ] {
            if !texte.contains(attendu) {
                ecarts.push(format!("{nom} ne porte pas `{attendu}`"));
            }
        }
    }
    ecarts
}

#[test]
fn rien_n_active_ni_ne_demarre_le_service() {
    let ecarts = ecarts_du_demarrage(
        &lire(INSTALLATEUR),
        &lire(POSTINST),
        &lire(SPEC),
        &lire(PRERM),
        &lire(POSTRM),
    );
    assert!(
        ecarts.is_empty(),
        "{} ecart(s):\n  {}",
        ecarts.len(),
        ecarts.join("\n  ")
    );
}

/// Les adresses de courriel d'un texte (`local@domaine.tld`).
fn courriels(texte: &str) -> Vec<String> {
    let o = texte.as_bytes();
    let local = |b: u8| b.is_ascii_alphanumeric() || b".-_+%".contains(&b);
    let mut sortie = Vec::new();
    for (i, &b) in o.iter().enumerate() {
        if b != b'@' {
            continue;
        }
        let mut d = i;
        while d > 0 && local(o[d - 1]) {
            d -= 1;
        }
        let mut f = i + 1;
        while f < o.len() && (o[f].is_ascii_alphanumeric() || o[f] == b'.' || o[f] == b'-') {
            f += 1;
        }
        let domaine = texte[i + 1..f].trim_end_matches('.');
        if d < i && domaine.contains('.') {
            sortie.push(format!("{}@{domaine}", &texte[d..i]));
        }
    }
    sortie
}

#[test]
fn version_mainteneur_licence_et_dependances_ont_une_seule_source() {
    let control = lire(CONTROL);
    let spec = lire(SPEC);
    let mut ecarts = Vec::new();
    let champ = |texte: &str, nom: &str| -> Vec<String> {
        texte
            .lines()
            .filter_map(|l| l.strip_prefix(nom))
            .map(|v| v.trim().to_string())
            .collect()
    };
    if champ(&control, "Version:") != ["@VERSION@"] || champ(&spec, "Version:") != ["@VERSION@"] {
        ecarts.push("Version: autre que @VERSION@ dans le control ou le spec".to_string());
    }
    let version = lire("Cargo.toml")
        .lines()
        .find_map(|l| l.strip_prefix("version = \""))
        .map(|v| v.trim_end_matches('"').to_string())
        .unwrap_or_default();
    for (nom, texte) in [(CONTROL, &control), (SPEC, &spec)] {
        if version.is_empty() || texte.contains(&version) {
            ecarts.push(format!(
                "{nom} ecrit la version du workspace ({version}) en dur"
            ));
        }
    }
    if champ(&control, "Maintainer:") != [CONTACT] || champ(&spec, "Packager:") != [CONTACT] {
        ecarts.push(format!(
            "Maintainer du control ou Packager du spec autre que {CONTACT}"
        ));
    }
    for fichier in [
        CONTROL,
        COPYRIGHT,
        SPEC,
        POSTINST,
        PRERM,
        POSTRM,
        CONSTRUCTEUR,
        MAN_CLI,
        MAN_DAEMON,
    ] {
        for c in courriels(&lire(fichier)) {
            if c != "security@inaricom.com" {
                ecarts.push(format!("{fichier} porte l'adresse {c}"));
            }
        }
    }
    let licence = lire("Cargo.toml")
        .lines()
        .find_map(|l| l.strip_prefix("license = \""))
        .map(|v| v.trim_end_matches('"').to_string())
        .unwrap_or_default();
    for (nom, texte) in [(SPEC, spec.clone()), (COPYRIGHT, lire(COPYRIGHT))] {
        let lues = champ(&texte, "License:");
        if licence.is_empty() || lues.is_empty() || lues.iter().any(|l| *l != licence) {
            ecarts.push(format!(
                "{nom}: License: {lues:?}, le depot declare {licence}"
            ));
        }
    }
    let depends: Vec<String> = champ(&control, "Depends:")
        .join(",")
        .split(',')
        .map(|d| d.trim().to_string())
        .filter(|d| !d.starts_with('@'))
        .collect();
    let requires: Vec<String> = champ(&spec, "Requires:")
        .into_iter()
        .filter(|r| r != "glibc" && r != "libgcc")
        .collect();
    if depends.is_empty() || depends != requires {
        ecarts.push(format!(
            "dependances hors bibliotheques: control {depends:?}, spec {requires:?}"
        ));
    }
    let blancs = |t: &str| t.split_whitespace().collect::<Vec<_>>().join(" ");
    for fichier in [CONTROL, SPEC, MAN_CLI, MAN_DAEMON] {
        if !blancs(&lire(fichier)).contains("trois commandes") {
            ecarts.push(format!(
                "{fichier} ne dit pas les trois commandes du groupe bifrost"
            ));
        }
    }
    assert!(
        ecarts.is_empty(),
        "{} ecart(s):\n  {}",
        ecarts.len(),
        ecarts.join("\n  ")
    );
}

/// Chaque exigence mord sur une mutation du texte reel, et le lecteur de shell
/// ne se laisse pas tromper par un document en ligne ou un commentaire.
#[test]
fn chaque_exigence_mord() {
    let installateur = lire(INSTALLATEUR);
    let constructeur = lire(CONSTRUCTEUR);
    let spec = lire(SPEC);
    let postinst = lire(POSTINST);
    let prerm = lire(PRERM);
    let postrm = lire(POSTRM);
    let declaration = lire(DECLARATION);
    let poses_temoin = ecarts_de_poses(
        &poses_de_l_installateur(&installateur),
        &poses_du_deb(&constructeur),
        &poses_du_rpm(&spec),
    );
    assert!(poses_temoin.is_empty(), "temoin: {poses_temoin:?}");

    let remplacer = |texte: &str, avant: &str, apres: &str| -> String {
        assert_eq!(
            texte.matches(avant).count(),
            1,
            "`{avant}` doit etre unique"
        );
        texte.replacen(avant, apres, 1)
    };

    // Un mode du hook change dans le spec.
    let spec_mute = remplacer(
        &spec,
        "install -D -m 0755 %{pkg_source}/systemd/system-sleep/bifrost-reprise",
        "install -D -m 0644 %{pkg_source}/systemd/system-sleep/bifrost-reprise",
    );
    let e = ecarts_de_poses(
        &poses_de_l_installateur(&installateur),
        &poses_du_deb(&constructeur),
        &poses_du_rpm(&spec_mute),
    );
    assert!(
        e.iter()
            .any(|x| x
                .contains("le .rpm pose /usr/lib/systemd/system-sleep/bifrost-reprise en 0644")),
        "{e:?}"
    );

    // L'unite du .deb tiree d'un autre fichier.
    let constructeur_mute = remplacer(
        &constructeur,
        "UNITE_SRC=\"$PKG/systemd/bifrost-daemon.service\"",
        "UNITE_SRC=\"$PKG/systemd/autre.service\"",
    );
    let e = ecarts_de_poses(
        &poses_de_l_installateur(&installateur),
        &poses_du_deb(&constructeur_mute),
        &poses_du_rpm(&spec),
    );
    assert!(
        e.iter()
            .any(|x| x.contains("le .deb pose /usr/lib/systemd/system/bifrost-daemon.service")),
        "{e:?}"
    );

    // Un compte renomme dans le postinst.
    let postinst_mute = remplacer(
        &postinst,
        "COMPTE_COEUR=bifrost-coeur",
        "COMPTE_COEUR=bifrost-noyau",
    );
    let e = ecarts_des_comptes(&installateur, &postinst_mute, &spec, &declaration);
    assert!(e.iter().any(|x| x.contains(POSTINST)), "{e:?}");

    // Le refus du membre retire du %post.
    let spec_mute = remplacer(
        &spec,
        "  if id -nG \"$compte\" | tr ' ' '\\n' | grep -x bifrost >/dev/null; then",
        "  if false; then",
    );
    let e = ecarts_des_comptes(&installateur, &postinst, &spec_mute, &declaration);
    assert!(
        e.iter()
            .any(|x| x.contains("%post du spec ne porte pas `grep -x bifrost`")),
        "{e:?}"
    );

    // Un demarrage ajoute au postinst, et sous une forme composee au %post.
    let postinst_mute = remplacer(
        &postinst,
        "      systemctl daemon-reload\n",
        "      systemctl daemon-reload\n      systemctl enable --now bifrost-daemon.service\n",
    );
    let e = ecarts_du_demarrage(&installateur, &postinst_mute, &spec, &prerm, &postrm);
    assert!(e.iter().any(|x| x.contains(POSTINST)), "{e:?}");
    let spec_mute = remplacer(
        &spec,
        "  systemctl daemon-reload\nfi\necho",
        "  systemctl daemon-reload && systemctl start bifrost-daemon\nfi\necho",
    );
    let e = ecarts_du_demarrage(&installateur, &postinst, &spec_mute, &prerm, &postrm);
    assert!(e.iter().any(|x| x.contains("%post du spec")), "{e:?}");

    // Une activation laissee par le postrm, et par le %postun.
    let postrm_mute = remplacer(
        &postrm,
        "  systemctl daemon-reload >/dev/null 2>&1 || true\n",
        "  systemctl daemon-reload >/dev/null 2>&1 || true\n  systemctl enable bifrost-daemon.service\n",
    );
    let e = ecarts_du_demarrage(&installateur, &postinst, &spec, &prerm, &postrm_mute);
    assert!(e.iter().any(|x| x.contains(POSTRM)), "{e:?}");
    let spec_mute = remplacer(
        &spec,
        "  systemctl daemon-reload >/dev/null 2>&1 || :\nfi\nif [ \"$1\" = 0 ]; then\n  if [ -d /var/lib/bifrost ]",
        "  systemctl daemon-reload >/dev/null 2>&1 || :\n  systemctl try-restart bifrost-daemon.service\nfi\nif [ \"$1\" = 0 ]; then\n  if [ -d /var/lib/bifrost ]",
    );
    let e = ecarts_du_demarrage(&installateur, &postinst, &spec_mute, &prerm, &postrm);
    assert!(e.iter().any(|x| x.contains("%postun du spec")), "{e:?}");

    // Le retrait des filtres retire du prerm.
    let prerm_mute = remplacer(
        &prerm,
        "      bifrost-daemon --cleanup-firewall \\\n        ||",
        "      true \\\n        ||",
    );
    let e = ecarts_du_demarrage(&installateur, &postinst, &spec, &prerm_mute, &postrm);
    assert!(
        e.iter()
            .any(|x| x.contains("bifrost-daemon --cleanup-firewall")),
        "{e:?}"
    );

    // Le texte de fin de l'installateur, un document en ligne, n'est pas une
    // commande; la meme ligne hors document en est une.
    assert!(ecarts_du_demarrage(&installateur, &postinst, &spec, &prerm, &postrm).is_empty());
    let hors_document = remplacer(
        &installateur,
        "cat <<TEXTE\n",
        "systemctl enable --now bifrost-daemon\ncat <<TEXTE\n",
    );
    let e = ecarts_du_demarrage(&hors_document, &postinst, &spec, &prerm, &postrm);
    assert!(e.iter().any(|x| x.contains(INSTALLATEUR)), "{e:?}");
    // Un commentaire n'en est pas une.
    let commentaire = remplacer(
        &installateur,
        "cat <<TEXTE\n",
        "# systemctl enable --now bifrost-daemon\ncat <<TEXTE\n",
    );
    assert!(ecarts_du_demarrage(&commentaire, &postinst, &spec, &prerm, &postrm).is_empty());

    // Une adresse personnelle dans un texte livre est vue.
    assert_eq!(
        courriels("Maintainer: Nom <nom.prenom@exemple.ch>"),
        ["nom.prenom@exemple.ch"]
    );
    assert!(courriels("Version: @VERSION@").is_empty());
}
