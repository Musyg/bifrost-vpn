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
//! # La coquille graphique
//!
//! Les paquets de la coquille (`bifrost-gui`: `packaging/deb-gui/`, assemble
//! par `scripts/paquets-gui-linux.sh`, et `packaging/rpm/bifrost-gui.spec`)
//! n'ont pas d'installateur en face: le .deb et le .rpm se comparent entre
//! eux. Ils ne se construisent que sur le runner (WebKitGTK), d'ou ces
//! exigences lues dans les textes:
//!
//! 5. Le .deb et le .rpm posent les memes fichiers aux memes modes depuis les
//!    memes sources, a leur copyright pres; une icone par cote de
//!    `COTES_HICOLOR` (lu dans le code de `bifrost-icone`), le .deb depuis ce
//!    que le binaire ecrit, le .rpm par une liste que `%files` declare a
//!    l'identique.
//! 6. L'identifiant de `gui/tauri.conf.json` nomme l'entree de bureau et
//!    l'icone, et l'ancien identifiant n'est dans aucun fichier du depot.
//! 7. Pas de demarrage automatique: aucune pose sous un repertoire autostart,
//!    aucune cle de demarrage dans l'entree de bureau, ni script du mainteneur
//!    ni scriptlet.
//! 8. Champs, version, licence et contact a une seule source; la bibliotheque
//!    chargee par dlopen nommee de la meme facon des deux cotes; les textes
//!    disent les trois commandes du groupe et l'absence de demarrage
//!    automatique. Les deux gabarits RPM n'ont ni macro nue dans un
//!    commentaire (rpm la developpe) ni date de changelog au mauvais jour.
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

// ================================================== la coquille graphique

// Seul `decouper` sert ici; les lectures par position servent aux voisines.
#[allow(dead_code)]
#[path = "commun/lexeur_rust.rs"]
mod lexeur_rust;

const CONSTRUCTEUR_GUI: &str = "scripts/paquets-gui-linux.sh";
const INSTALLATEUR_GUI: &str = "scripts/paquets-gui-linux-installer.sh";
const SPEC_GUI: &str = "packaging/rpm/bifrost-gui.spec";
const CONTROL_GUI: &str = "packaging/deb-gui/control";
const COPYRIGHT_GUI: &str = "packaging/deb-gui/copyright";
const MAN_GUI: &str = "packaging/man/bifrost-gui.1";
const BUREAU: &str = "packaging/desktop";
const CONF_TAURI: &str = "gui/tauri.conf.json";
const ICONES_SRC: &str = "crates/bifrost-icone/src/lib.rs";

/// L'identifiant de l'application, lu dans `gui/tauri.conf.json`: il nomme
/// l'entree de bureau et l'icone des paquets.
fn identifiant() -> String {
    let conf: serde_json::Value = serde_json::from_str(&lire(CONF_TAURI))
        .unwrap_or_else(|e| panic!("{CONF_TAURI} illisible: {e}"));
    conf["identifier"].as_str().unwrap_or_default().to_string()
}

/// L'identifiant que portaient les fichiers de la coquille avant celui du
/// depot, en deux morceaux: cette recette ne le contient pas elle-meme.
fn ancien_identifiant() -> String {
    ["com", "inaricom"].join(".")
}

/// Le source sans ses commentaires ni ses litteraux, remplaces par des
/// espaces (la lecture de `partage_entre_executions.rs`).
fn code_seul(src: &str) -> Result<String, String> {
    let d = lexeur_rust::decouper(src)?;
    let mut o = src.as_bytes().to_vec();
    for (a, b) in d.neutres {
        for x in &mut o[a..b] {
            if *x != b'\n' {
                *x = b' ';
            }
        }
    }
    Ok(String::from_utf8_lossy(&o).into_owned())
}

/// Les cotes de `COTES_HICOLOR`, lues dans le code de `bifrost-icone`.
fn cotes_hicolor(src: &str) -> Result<Vec<u32>, String> {
    let code = code_seul(src)?;
    let debut = code
        .find("const COTES_HICOLOR")
        .ok_or("const COTES_HICOLOR introuvable")?;
    let reste = &code[debut..];
    let egal = reste.find('=').ok_or("COTES_HICOLOR sans valeur")?;
    let valeur = &reste[egal..];
    let ouvrant = valeur.find('[').ok_or("COTES_HICOLOR sans tableau")? + 1;
    let fermant = valeur
        .find(']')
        .ok_or("tableau de COTES_HICOLOR non ferme")?;
    valeur[ouvrant..fermant]
        .split(',')
        .map(str::trim)
        .filter(|c| !c.is_empty())
        .map(|c| c.parse::<u32>().map_err(|e| format!("cote {c:?}: {e}")))
        .collect()
}

/// Les lignes actives du constructeur de la coquille, variables resolues.
fn lignes_du_constructeur_gui(texte: &str, id: &str) -> Vec<String> {
    let lignes = lignes_shell(texte);
    let vars = affectations(
        &lignes,
        &[
            ("RACINE_DEPOT", "."),
            ("GUI_BIN", "GUI"),
            ("BIN", "BIN"),
            ("SORTIE", "SORTIE"),
            ("ARBRE", ""),
            ("ID_APP", id),
        ],
    );
    lignes.iter().map(|l| resoudre(l, &vars)).collect()
}

fn poses_du_rpm_gui(spec: &str) -> Poses {
    let lignes: Vec<String> = section(spec, "%install")
        .iter()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| {
            l.replace("%{gui_bindir}", "GUI")
                .replace("%{pkg_source}", "packaging")
                .replace("%{icones_source}", "ICONES")
                .replace("%{buildroot}", "")
        })
        .collect();
    poses(&lignes)
}

/// Les poses d'icones du .deb: (mode, destination) de chaque ligne `install`
/// vers `/usr/share/icons/`, la destination telle qu'ecrite (le cote vient de
/// la boucle sur ce que bifrost-icone a ecrit, il reste `${cote}`).
fn poses_d_icones_du_deb(lignes: &[String]) -> Vec<(String, String)> {
    lignes
        .iter()
        .filter_map(|l| {
            let mots: Vec<&str> = l.split_whitespace().collect();
            if mots.first() != Some(&"install") {
                return None;
            }
            let destination = mots.last()?;
            if !destination.starts_with("/usr/share/icons/") {
                return None;
            }
            let mode = mots
                .iter()
                .position(|m| *m == "-m")
                .and_then(|i| mots.get(i + 1))
                .copied()
                .unwrap_or("");
            Some((mode.to_string(), (*destination).to_string()))
        })
        .collect()
}

fn ecarts_des_poses_gui(constructeur: &str, spec: &str, id: &str, cotes: &[u32]) -> Vec<String> {
    let mut ecarts = Vec::new();
    let lignes = lignes_du_constructeur_gui(constructeur, id);
    let deb: Poses = poses(&lignes)
        .into_iter()
        .filter(|(d, _)| !d.starts_with("/DEBIAN/"))
        .collect();
    let rpm = poses_du_rpm_gui(spec);
    if cotes.is_empty() {
        ecarts.push("COTES_HICOLOR lu vide: la lecture est cassee".to_string());
    }

    // Hors icones et copyright: les memes poses des deux cotes.
    let commun = |p: &Poses| -> Poses {
        p.iter()
            .filter(|(d, _)| {
                !d.starts_with("/usr/share/icons/") && !d.ends_with("/bifrost-gui/copyright")
            })
            .map(|(d, v)| (d.clone(), v.clone()))
            .collect()
    };
    if commun(&deb) != commun(&rpm) {
        ecarts.push(format!(
            "le .deb et le .rpm de la coquille ne posent pas les memes fichiers aux memes modes:\n    deb {:?}\n    rpm {:?}",
            commun(&deb),
            commun(&rpm)
        ));
    }

    // Ce que chacun pose, et d'ou.
    let bureau = format!("/usr/share/applications/{id}.desktop");
    let bureau_src = format!("packaging/desktop/{id}.desktop");
    let attendus: [(&str, &str, &str); 3] = [
        ("/usr/bin/bifrost-gui", "0755", "GUI/bifrost-gui"),
        (&bureau, "0644", &bureau_src),
        (
            "/usr/share/man/man1/bifrost-gui.1",
            "0644",
            "packaging/man/bifrost-gui.1",
        ),
    ];
    for (nom, p, copyright) in [
        ("le .deb", &deb, "/usr/share/doc/bifrost-gui/copyright"),
        ("le .rpm", &rpm, "/usr/share/licenses/bifrost-gui/copyright"),
    ] {
        for (destination, mode, source) in
            attendus
                .iter()
                .copied()
                .chain([(copyright, "0644", COPYRIGHT_GUI)])
        {
            match p.get(destination) {
                Some((m, s)) if m == mode && s == source => {}
                Some((m, s)) => ecarts.push(format!(
                    "{nom} de la coquille pose {destination} en {m} depuis {s}, attendu {mode} depuis {source}"
                )),
                None => ecarts.push(format!(
                    "{nom} de la coquille ne pose pas {destination}"
                )),
            }
        }
    }

    // Les icones: le .rpm une par cote de COTES_HICOLOR, le .deb par sa boucle.
    let icones_rpm: Poses = rpm
        .iter()
        .filter(|(d, _)| d.starts_with("/usr/share/icons/"))
        .map(|(d, v)| (d.clone(), v.clone()))
        .collect();
    let icones_attendues: Poses = cotes
        .iter()
        .map(|c| {
            (
                format!("/usr/share/icons/hicolor/{c}x{c}/apps/{id}.png"),
                ("0644".to_string(), format!("ICONES/bifrost-{c}.png")),
            )
        })
        .collect();
    if icones_rpm != icones_attendues {
        ecarts.push(format!(
            "le .rpm de la coquille pose les icones {:?}, COTES_HICOLOR {cotes:?} en demande {:?}",
            icones_rpm.keys().collect::<Vec<_>>(),
            icones_attendues.keys().collect::<Vec<_>>()
        ));
    }
    let gabarit = format!("/usr/share/icons/hicolor/${{cote}}x${{cote}}/apps/{id}.png");
    let icones_deb = poses_d_icones_du_deb(&lignes);
    if icones_deb != [("0644".to_string(), gabarit.clone())] {
        ecarts.push(format!(
            "le .deb de la coquille pose ses icones par {icones_deb:?}, attendu une pose 0644 vers {gabarit}"
        ));
    }

    // %files declare exactement ce que %install pose (la page recomprimee).
    let installes: std::collections::BTreeSet<String> = rpm
        .keys()
        .map(|d| {
            if d.starts_with("/usr/share/man/") {
                format!("{d}.gz")
            } else {
                d.clone()
            }
        })
        .collect();
    let declares: std::collections::BTreeSet<String> = section(spec, "%files")
        .iter()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.trim_start_matches("%license").trim().to_string())
        .collect();
    if installes != declares {
        ecarts.push(format!(
            "%files du spec de la coquille ne declare pas ce que %install pose:\n    pose {installes:?}\n    declare {declares:?}"
        ));
    }
    ecarts
}

#[test]
fn les_paquets_de_la_coquille_posent_les_memes_fichiers() {
    let cotes =
        cotes_hicolor(&lire(ICONES_SRC)).unwrap_or_else(|e| panic!("{ICONES_SRC} illisible: {e}"));
    let ecarts = ecarts_des_poses_gui(
        &lire(CONSTRUCTEUR_GUI),
        &lire(SPEC_GUI),
        &identifiant(),
        &cotes,
    );
    assert!(
        ecarts.is_empty(),
        "{} ecart(s):\n  {}",
        ecarts.len(),
        ecarts.join("\n  ")
    );
}

/// Ce que dit l'entree de bureau, et les fichiers du repertoire qui la porte.
fn ecarts_de_l_entree_de_bureau(desktop: &str, fichiers: &[String], id: &str) -> Vec<String> {
    let mut ecarts = Vec::new();
    let attendu = format!("{id}.desktop");
    if fichiers != [attendu.clone()] {
        ecarts.push(format!(
            "{BUREAU} porte {fichiers:?}, attendu la seule entree {attendu}"
        ));
    }
    for (cle, valeur) in [
        ("Type", "Application"),
        ("Exec", "bifrost-gui"),
        ("TryExec", "bifrost-gui"),
        ("Icon", id),
        ("Terminal", "false"),
    ] {
        let lues: Vec<&str> = desktop
            .lines()
            .filter_map(|l| l.strip_prefix(cle)?.strip_prefix('='))
            .collect();
        if lues != [valeur] {
            ecarts.push(format!(
                "entree de bureau: {cle}={lues:?}, attendu {valeur}"
            ));
        }
    }
    ecarts
}

/// Les fichiers d'un texte qui portent l'ancien identifiant: (chemin, texte).
fn porteurs_de_l_ancien_identifiant(fichiers: &[(String, String)]) -> Vec<String> {
    let ancien = ancien_identifiant();
    fichiers
        .iter()
        .filter(|(_, t)| t.contains(&ancien))
        .map(|(c, _)| c.clone())
        .collect()
}

/// Chaque fichier du depot hors `.git` et des repertoires de compilation:
/// (chemin relatif, texte).
fn fichiers_du_depot(dossier: &std::path::Path, trouves: &mut Vec<(String, String)>) {
    let Ok(entrees) = std::fs::read_dir(dossier) else {
        return;
    };
    for entree in entrees.flatten() {
        let chemin = entree.path();
        let nom = entree.file_name().to_string_lossy().into_owned();
        if chemin.is_dir() {
            if ![".git", "target", "node_modules"].contains(&nom.as_str()) {
                fichiers_du_depot(&chemin, trouves);
            }
        } else if let Ok(octets) = std::fs::read(&chemin) {
            let relatif = chemin
                .strip_prefix(racine())
                .unwrap_or(&chemin)
                .display()
                .to_string()
                .replace('\\', "/");
            trouves.push((relatif, String::from_utf8_lossy(&octets).into_owned()));
        }
    }
}

#[test]
fn la_coquille_porte_l_identifiant_du_depot_et_lui_seul() {
    let id = identifiant();
    let mut fichiers = Vec::new();
    fichiers_du_depot(&racine(), &mut fichiers);
    assert!(
        fichiers.len() > 100,
        "seuls {} fichier(s) lus: le parcours est casse",
        fichiers.len()
    );
    let mut ecarts: Vec<String> = porteurs_de_l_ancien_identifiant(&fichiers)
        .into_iter()
        .map(|c| format!("{c} porte l'ancien identifiant {}", ancien_identifiant()))
        .collect();
    if id.is_empty() {
        ecarts.push(format!("{CONF_TAURI}: identifier illisible"));
    }
    let mut noms: Vec<String> = std::fs::read_dir(racine().join(BUREAU))
        .unwrap_or_else(|e| panic!("{BUREAU} illisible: {e}"))
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    noms.sort();
    let desktop = noms
        .first()
        .map(|n| lire(&format!("{BUREAU}/{n}")))
        .unwrap_or_default();
    ecarts.extend(ecarts_de_l_entree_de_bureau(&desktop, &noms, &id));
    assert!(
        ecarts.is_empty(),
        "{} ecart(s):\n  {}",
        ecarts.len(),
        ecarts.join("\n  ")
    );
}

/// Les sections de scriptlet d'un spec.
const SCRIPTLETS: [&str; 7] = [
    "%pre",
    "%post",
    "%preun",
    "%postun",
    "%pretrans",
    "%posttrans",
    "%triggerin",
];

fn ecarts_du_demarrage_gui(
    constructeur: &str,
    spec: &str,
    desktop: &str,
    fichiers_deb_gui: &[String],
    id: &str,
) -> Vec<String> {
    let mut ecarts = Vec::new();
    let lignes = lignes_du_constructeur_gui(constructeur, id);
    for (nom, p) in [
        ("le .deb", poses(&lignes)),
        ("le .rpm", poses_du_rpm_gui(spec)),
    ] {
        for destination in p.keys() {
            let hors_de_usr =
                !destination.starts_with("/usr/") && !destination.starts_with("/DEBIAN/");
            if hors_de_usr || destination.to_ascii_lowercase().contains("autostart") {
                ecarts.push(format!(
                    "{nom} de la coquille pose {destination}: hors de /usr, ou une entree de demarrage de session"
                ));
            }
            if destination.starts_with("/DEBIAN/") {
                ecarts.push(format!(
                    "{nom} de la coquille pose un script du mainteneur: {destination}"
                ));
            }
        }
    }
    for l in &lignes {
        if l.contains("xdg/autostart") || l.contains("config/autostart") {
            ecarts.push(format!(
                "{CONSTRUCTEUR_GUI} ecrit sous un repertoire autostart: `{l}`"
            ));
        }
    }
    for l in spec.lines() {
        if l.split_whitespace()
            .next()
            .is_some_and(|m| SCRIPTLETS.contains(&m))
        {
            ecarts.push(format!("{SPEC_GUI} porte un scriptlet: `{l}`"));
        }
    }
    for l in desktop.lines() {
        if l.to_ascii_lowercase().contains("autostart") {
            ecarts.push(format!("l'entree de bureau porte `{l}`"));
        }
    }
    if fichiers_deb_gui != ["control", "copyright"] {
        ecarts.push(format!(
            "packaging/deb-gui porte {fichiers_deb_gui:?}, attendu control et copyright seuls"
        ));
    }
    ecarts
}

#[test]
fn aucun_paquet_de_la_coquille_ne_demarre_a_l_ouverture_de_session() {
    let id = identifiant();
    let mut fichiers: Vec<String> = std::fs::read_dir(racine().join("packaging/deb-gui"))
        .expect("packaging/deb-gui doit exister")
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    fichiers.sort();
    let ecarts = ecarts_du_demarrage_gui(
        &lire(CONSTRUCTEUR_GUI),
        &lire(SPEC_GUI),
        &lire(&format!("{BUREAU}/{id}.desktop")),
        &fichiers,
        &id,
    );
    assert!(
        ecarts.is_empty(),
        "{} ecart(s):\n  {}",
        ecarts.len(),
        ecarts.join("\n  ")
    );
}

/// Les valeurs d'un champ `Nom:` d'un texte, une par ligne qui le porte.
fn champ_de(texte: &str, nom: &str) -> Vec<String> {
    texte
        .lines()
        .filter_map(|l| l.strip_prefix(nom))
        .map(|v| v.trim().to_string())
        .collect()
}

/// La valeur `version = "..."` de la section `[section]` d'un Cargo.toml.
fn version_de_section(cargo: &str, section: &str) -> String {
    let mut dedans = false;
    for l in cargo.lines() {
        let t = l.trim();
        if t.starts_with('[') {
            dedans = t == section;
            continue;
        }
        if dedans && let Some(v) = t.strip_prefix("version = \"") {
            return v.trim_end_matches('"').to_string();
        }
    }
    String::new()
}

/// Les textes de la coquille que lit [`ecarts_des_champs_gui`].
struct TextesGui<'a> {
    control: &'a str,
    spec: &'a str,
    copyright: &'a str,
    man: &'a str,
    constructeur: &'a str,
    installateur: &'a str,
    desktop: &'a str,
}

fn ecarts_des_champs_gui(t: &TextesGui, id: &str) -> Vec<String> {
    let mut ecarts = Vec::new();
    let cargo = lire("Cargo.toml");
    let workspace = |cle: &str| -> String {
        cargo
            .lines()
            .find_map(|l| l.strip_prefix(&format!("{cle} = \"")))
            .map(|v| v.trim_end_matches('"').to_string())
            .unwrap_or_default()
    };
    let (version, licence, depot) = (
        workspace("version"),
        workspace("license"),
        workspace("repository"),
    );
    let conf: serde_json::Value = serde_json::from_str(&lire(CONF_TAURI)).unwrap_or_default();
    let version_gui = version_de_section(&lire("gui/Cargo.toml"), "[package]");
    if version.is_empty()
        || version_gui != version
        || conf["version"].as_str() != Some(version.as_str())
    {
        ecarts.push(format!(
            "versions: workspace {version:?}, gui/Cargo.toml {version_gui:?}, {CONF_TAURI} {:?}",
            conf["version"]
        ));
    }
    let lignes = lignes_du_constructeur_gui(t.constructeur, id);
    let vars = affectations(&lignes, &[]);
    let soname = vars.get("DLOPEN_SONAME").cloned().unwrap_or_default();
    let paquet_dlopen = vars.get("DLOPEN").cloned().unwrap_or_default();
    if soname.is_empty() || paquet_dlopen.is_empty() {
        ecarts.push(format!(
            "{CONSTRUCTEUR_GUI}: DLOPEN_SONAME {soname:?} ou DLOPEN {paquet_dlopen:?} illisible"
        ));
    }
    let requires = format!("{soname}()(64bit)");
    let attendus: [(&str, &str, &str, &str); 13] = [
        (CONTROL_GUI, t.control, "Package:", "bifrost-gui"),
        (CONTROL_GUI, t.control, "Version:", "@VERSION@"),
        (CONTROL_GUI, t.control, "Maintainer:", CONTACT),
        (
            CONTROL_GUI,
            t.control,
            "Depends:",
            "@SHLIBS@, @DLOPEN@, hicolor-icon-theme",
        ),
        (CONTROL_GUI, t.control, "Recommends:", "bifrost"),
        (CONTROL_GUI, t.control, "Homepage:", &depot),
        (SPEC_GUI, t.spec, "Name:", "bifrost-gui"),
        (SPEC_GUI, t.spec, "Version:", "@VERSION@"),
        (SPEC_GUI, t.spec, "Packager:", CONTACT),
        (SPEC_GUI, t.spec, "License:", &licence),
        (SPEC_GUI, t.spec, "URL:", &depot),
        (SPEC_GUI, t.spec, "Recommends:", "bifrost"),
        (COPYRIGHT_GUI, t.copyright, "Source:", &depot),
    ];
    for (fichier, texte, nom, valeur) in attendus {
        let lues = champ_de(texte, nom);
        if valeur.is_empty() || lues != [valeur] {
            ecarts.push(format!("{fichier}: {nom} {lues:?}, attendu {valeur:?}"));
        }
    }
    let requis = champ_de(t.spec, "Requires:");
    if requis != [requires.as_str(), "hicolor-icon-theme"] {
        ecarts.push(format!(
            "{SPEC_GUI}: Requires {requis:?}, attendu le soname que charge le .deb ({requires}) et hicolor-icon-theme"
        ));
    }
    let licences = champ_de(t.copyright, "License:");
    if licences.is_empty() || licences.iter().any(|l| *l != licence) {
        ecarts.push(format!(
            "{COPYRIGHT_GUI}: License {licences:?}, le depot declare {licence}"
        ));
    }
    for (fichier, texte) in [(CONTROL_GUI, t.control), (SPEC_GUI, t.spec)] {
        if texte.contains(&version) {
            ecarts.push(format!(
                "{fichier} ecrit la version du workspace ({version}) en dur"
            ));
        }
    }
    for (fichier, texte) in [
        (CONTROL_GUI, t.control),
        (COPYRIGHT_GUI, t.copyright),
        (SPEC_GUI, t.spec),
        (MAN_GUI, t.man),
        (CONSTRUCTEUR_GUI, t.constructeur),
        (INSTALLATEUR_GUI, t.installateur),
        (BUREAU, t.desktop),
    ] {
        for c in courriels(texte) {
            if c != "security@inaricom.com" {
                ecarts.push(format!("{fichier} porte l'adresse {c}"));
            }
        }
    }
    let blancs = |t: &str| t.split_whitespace().collect::<Vec<_>>().join(" ");
    for (fichier, texte) in [
        (CONTROL_GUI, t.control),
        (SPEC_GUI, t.spec),
        (MAN_GUI, t.man),
    ] {
        for phrase in ["trois commandes", "Pas de demarrage automatique"] {
            if !blancs(texte).contains(phrase) {
                ecarts.push(format!("{fichier} ne dit pas << {phrase} >>"));
            }
        }
    }
    ecarts
}

#[test]
fn champs_version_licence_et_textes_de_la_coquille_ont_une_seule_source() {
    let id = identifiant();
    let (control, spec, copyright, man, constructeur, installateur, desktop) = (
        lire(CONTROL_GUI),
        lire(SPEC_GUI),
        lire(COPYRIGHT_GUI),
        lire(MAN_GUI),
        lire(CONSTRUCTEUR_GUI),
        lire(INSTALLATEUR_GUI),
        lire(&format!("{BUREAU}/{id}.desktop")),
    );
    let ecarts = ecarts_des_champs_gui(
        &TextesGui {
            control: &control,
            spec: &spec,
            copyright: &copyright,
            man: &man,
            constructeur: &constructeur,
            installateur: &installateur,
            desktop: &desktop,
        },
        &id,
    );
    assert!(
        ecarts.is_empty(),
        "{} ecart(s):\n  {}",
        ecarts.len(),
        ecarts.join("\n  ")
    );
}

/// Le jour de la semaine d'une date du calendrier gregorien, 0 = dimanche
/// (methode de Sakamoto).
fn jour_de_semaine(annee: i32, mois: usize, jour: i32) -> usize {
    const DECALAGES: [i32; 12] = [0, 3, 2, 5, 0, 3, 5, 1, 4, 6, 2, 4];
    let a = if mois < 3 { annee - 1 } else { annee };
    (a + a / 4 - a / 100 + a / 400 + DECALAGES[mois - 1] + jour).rem_euclid(7) as usize
}

/// Un gabarit RPM: rpm developpe les macros jusque dans les commentaires (un
/// `%` s'y ecrit `%%`), et refuse une entree de changelog dont le jour de la
/// semaine ne tombe pas a sa date.
fn ecarts_du_gabarit_rpm(nom: &str, spec: &str) -> Vec<String> {
    const JOURS: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MOIS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let mut ecarts = Vec::new();
    for (i, l) in spec.lines().enumerate() {
        if !l.trim_start().starts_with('#') {
            continue;
        }
        let o = l.as_bytes();
        let mut k = 0usize;
        while k < o.len() {
            if o[k] == b'%' {
                if o.get(k + 1) == Some(&b'%') {
                    k += 2;
                    continue;
                }
                if o.get(k + 1)
                    .is_some_and(|c| c.is_ascii_alphabetic() || *c == b'{' || *c == b'(')
                {
                    ecarts.push(format!(
                        "{nom}, ligne {}: macro nue dans un commentaire: `{l}`",
                        i + 1
                    ));
                    break;
                }
            }
            k += 1;
        }
    }
    let mut entrees = 0usize;
    for l in section(spec, "%changelog") {
        let Some(reste) = l.strip_prefix("* ") else {
            continue;
        };
        entrees += 1;
        let mots: Vec<&str> = reste.split_whitespace().take(4).collect();
        let lue = match mots.as_slice() {
            [j, m, d, a] => MOIS
                .iter()
                .position(|x| x == m)
                .zip(d.parse::<i32>().ok())
                .zip(a.parse::<i32>().ok())
                .map(|((m, d), a)| (*j, JOURS[jour_de_semaine(a, m + 1, d)])),
            _ => None,
        };
        match lue {
            Some((ecrit, vrai)) if ecrit == vrai => {}
            Some((ecrit, vrai)) => {
                ecarts.push(format!("{nom}: changelog `{l}`: {ecrit} au lieu de {vrai}"))
            }
            None => ecarts.push(format!("{nom}: changelog illisible: `{l}`")),
        }
    }
    if entrees == 0 {
        ecarts.push(format!("{nom}: aucune entree de changelog"));
    }
    ecarts
}

#[test]
fn les_gabarits_rpm_n_ont_ni_macro_nue_en_commentaire_ni_date_fausse() {
    let mut ecarts = ecarts_du_gabarit_rpm(SPEC, &lire(SPEC));
    ecarts.extend(ecarts_du_gabarit_rpm(SPEC_GUI, &lire(SPEC_GUI)));
    assert!(
        ecarts.is_empty(),
        "{} ecart(s):\n  {}",
        ecarts.len(),
        ecarts.join("\n  ")
    );
}

/// Chaque exigence de la coquille mord sur une mutation du texte reel.
#[test]
fn chaque_exigence_de_la_coquille_mord() {
    let id = identifiant();
    let icones_src = lire(ICONES_SRC);
    let cotes = cotes_hicolor(&icones_src).expect("COTES_HICOLOR lisible");
    let (control, spec, copyright, man, constructeur, installateur, desktop) = (
        lire(CONTROL_GUI),
        lire(SPEC_GUI),
        lire(COPYRIGHT_GUI),
        lire(MAN_GUI),
        lire(CONSTRUCTEUR_GUI),
        lire(INSTALLATEUR_GUI),
        lire(&format!("{BUREAU}/{id}.desktop")),
    );
    let deb_gui = ["control".to_string(), "copyright".to_string()];
    let champs = |control: &str, spec: &str, desktop: &str| -> Vec<String> {
        ecarts_des_champs_gui(
            &TextesGui {
                control,
                spec,
                copyright: &copyright,
                man: &man,
                constructeur: &constructeur,
                installateur: &installateur,
                desktop,
            },
            &id,
        )
    };
    assert!(ecarts_des_poses_gui(&constructeur, &spec, &id, &cotes).is_empty());
    assert!(ecarts_du_demarrage_gui(&constructeur, &spec, &desktop, &deb_gui, &id).is_empty());
    assert!(champs(&control, &spec, &desktop).is_empty());
    assert!(ecarts_du_gabarit_rpm(SPEC_GUI, &spec).is_empty());

    let remplacer = |texte: &str, avant: &str, apres: &str| -> String {
        assert_eq!(
            texte.matches(avant).count(),
            1,
            "`{avant}` doit etre unique"
        );
        texte.replacen(avant, apres, 1)
    };
    let mord = |e: Vec<String>, motif: &str| {
        assert!(
            e.iter().any(|x| x.contains(motif)),
            "`{motif}` attendu dans {e:?}"
        );
    };

    // Une icone retiree du .rpm, puis une cote ajoutee au crate.
    let ligne_64 = format!(
        "install -D -m 0644 %{{icones_source}}/bifrost-64.png %{{buildroot}}/usr/share/icons/hicolor/64x64/apps/{id}.png\n"
    );
    let ligne_64_files = format!("/usr/share/icons/hicolor/64x64/apps/{id}.png\n");
    let spec_mute = remplacer(&remplacer(&spec, &ligne_64, ""), &ligne_64_files, "");
    mord(
        ecarts_des_poses_gui(&constructeur, &spec_mute, &id, &cotes),
        "le .rpm de la coquille pose les icones",
    );
    let cotes_mutees = cotes_hicolor(&remplacer(
        &icones_src,
        "&[16, 24, 32, 48, 64, 128, 256]",
        "&[16, 24, 32, 48, 64, 128, 256, 512]",
    ))
    .expect("source mutee lisible");
    mord(
        ecarts_des_poses_gui(&constructeur, &spec, &id, &cotes_mutees),
        "COTES_HICOLOR",
    );
    // Une declaration en commentaire n'est pas le code.
    let commentee = format!("// pub const COTES_HICOLOR: &[u32] = &[8];\n{icones_src}");
    assert_eq!(cotes_hicolor(&commentee), Ok(cotes.clone()));

    // L'entree de bureau du .deb posee sous un autre nom.
    let constructeur_mute = remplacer(
        &constructeur,
        "\"$ARBRE/usr/share/applications/$ID_APP.desktop\"",
        "\"$ARBRE/usr/share/applications/bifrost.desktop\"",
    );
    mord(
        ecarts_des_poses_gui(&constructeur_mute, &spec, &id, &cotes),
        "le .deb de la coquille ne pose pas /usr/share/applications/",
    );

    // Un %files qui oublie la page.
    let spec_mute = remplacer(&spec, "/usr/share/man/man1/bifrost-gui.1.gz\n", "");
    mord(
        ecarts_des_poses_gui(&constructeur, &spec_mute, &id, &cotes),
        "%files du spec de la coquille",
    );

    // Une entree de demarrage de session, dans le .deb, le .rpm ou l'entree.
    let constructeur_mute = remplacer(
        &constructeur,
        "gzip -9n \"$ARBRE/usr/share/man/man1/bifrost-gui.1\"\n",
        "gzip -9n \"$ARBRE/usr/share/man/man1/bifrost-gui.1\"\ninstall -D -m 0644 \"$DESKTOP_SRC\" \"$ARBRE/etc/xdg/autostart/$ID_APP.desktop\"\n",
    );
    mord(
        ecarts_du_demarrage_gui(&constructeur_mute, &spec, &desktop, &deb_gui, &id),
        "entree de demarrage de session",
    );
    let spec_mute = remplacer(
        &spec,
        "\n%files\n",
        &format!(
            "install -D -m 0644 %{{pkg_source}}/desktop/{id}.desktop %{{buildroot}}/etc/xdg/autostart/{id}.desktop\n\n%files\n"
        ),
    );
    mord(
        ecarts_du_demarrage_gui(&constructeur, &spec_mute, &desktop, &deb_gui, &id),
        "le .rpm de la coquille pose /etc/xdg/autostart/",
    );
    let desktop_mute = format!("{desktop}X-GNOME-Autostart-enabled=true\n");
    mord(
        ecarts_du_demarrage_gui(&constructeur, &spec, &desktop_mute, &deb_gui, &id),
        "l'entree de bureau porte",
    );
    let spec_mute = remplacer(
        &spec,
        "\n%changelog\n",
        "\n%post\nupdate-desktop-database\n\n%changelog\n",
    );
    mord(
        ecarts_du_demarrage_gui(&constructeur, &spec_mute, &desktop, &deb_gui, &id),
        "porte un scriptlet",
    );
    mord(
        ecarts_du_demarrage_gui(
            &constructeur,
            &spec,
            &desktop,
            &[
                "control".to_string(),
                "copyright".to_string(),
                "postinst".to_string(),
            ],
            &id,
        ),
        "packaging/deb-gui porte",
    );

    // L'ancien identifiant remis dans l'entree de bureau.
    let ancien = format!("Icon={}.bifrost", ancien_identifiant());
    let desktop_mute = remplacer(&desktop, &format!("Icon={id}"), &ancien);
    assert_eq!(
        porteurs_de_l_ancien_identifiant(&[(BUREAU.to_string(), desktop_mute.clone())]),
        [BUREAU]
    );
    mord(
        ecarts_de_l_entree_de_bureau(&desktop_mute, &[format!("{id}.desktop")], &id),
        "entree de bureau: Icon=",
    );

    // Les champs: la bibliotheque dlopen oubliee du Depends, un soname qui
    // diverge, une adresse personnelle, les trois commandes tues.
    let control_mute = remplacer(
        &control,
        "@SHLIBS@, @DLOPEN@, hicolor-icon-theme",
        "@SHLIBS@, hicolor-icon-theme",
    );
    mord(champs(&control_mute, &spec, &desktop), "Depends:");
    let spec_mute = remplacer(
        &spec,
        "libayatana-appindicator3.so.1()(64bit)",
        "libappindicator3.so.1()(64bit)",
    );
    mord(champs(&control, &spec_mute, &desktop), "Requires");
    let control_mute = remplacer(
        &control,
        "Maintainer: Bifrost <security@inaricom.com>",
        "Maintainer: Nom <nom.prenom@exemple.ch>",
    );
    mord(
        champs(&control_mute, &spec, &desktop),
        "nom.prenom@exemple.ch",
    );
    let control_mute = control.replace("trois commandes", "commandes");
    mord(champs(&control_mute, &spec, &desktop), "trois commandes");

    // Le gabarit: une macro nue en commentaire, un jour faux.
    let spec_mute = remplacer(&spec, "(voir %%files)", "(voir %files)");
    mord(
        ecarts_du_gabarit_rpm(SPEC_GUI, &spec_mute),
        "macro nue dans un commentaire",
    );
    let spec_mute = remplacer(&spec, "* Sun Oct 18 2026", "* Sat Oct 18 2026");
    mord(
        ecarts_du_gabarit_rpm(SPEC_GUI, &spec_mute),
        "Sat au lieu de Sun",
    );
}
