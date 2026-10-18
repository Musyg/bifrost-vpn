//! Le MSI fait ce que fait `packaging/install-windows.ps1`: memes
//! repertoires, memes droits, meme groupe d'acces, meme ligne de service, et
//! aucun demarrage.
//!
//! # Pourquoi cette recette existe
//!
//! Le depot installe Bifrost sous Windows par deux chemins: le script
//! (`packaging/install-windows.ps1`) et le MSI (`packaging/msi/bifrost.wxs`).
//! Le MSI ne se construit et ne s'installe que sur un lancement manuel de la
//! CI, sur un runner jetable: un ecart entre les deux chemins (un SID change
//! dans une ACL, le groupe d'acces renomme, un argument de plus dans la ligne
//! du service, un `Start="install"`) ne se verrait qu'a ce run-la, ou jamais.
//! Cette recette lit les deux textes, sur chaque hote.
//!
//! # Ce qu'elle exige
//!
//! 1. Les repertoires: `%ProgramFiles%\Bifrost` pour les binaires,
//!    `%ProgramData%\Bifrost`, son `resolveur` et l'`etat` de celui-ci, aux
//!    memes noms des deux cotes; le MSI ne pose que les deux binaires.
//! 2. Les droits: les quatre invocations d'icacls du script (proprietaire,
//!    heritage et controle total, lecture du resolveur, modification de
//!    l'etat), memes repertoires, memes SID, memes drapeaux, meme ordre.
//! 3. Le groupe d'acces: le meme nom, cree par `net.exe localgroup <nom>
//!    /add` avec le commentaire que `New-LocalGroup` lui donne dans le
//!    script, l'echec << existe deja >> ignore. Ce commentaire tient en 48
//!    caracteres: au-dela, `New-LocalGroup` refuse et le script s'arrete avant
//!    de creer le groupe (mesure du 18/10/2026, Windows Server 2025,
//!    PowerShell 7.6.6), quand `net.exe` l'accepte.
//! 4. La ligne du service: celle du script, argument pour argument, sans
//!    resolveur et avec le resolveur deja pose (le MSI le cherche au meme
//!    chemin que le script); le daemon y inscrit le SID du groupe.
//! 5. Le demarrage: ni `ServiceInstall`, ni `Start=` dans le MSI, ni
//!    `Start-Service` dans le script; le service s'arrete (`ServiceControl`),
//!    perd ses filtres (`--cleanup-firewall`) et part (`--uninstall-service`)
//!    a la desinstallation.
//! 6. Une seule version (`$(var.Version)`), le fabricant `Bifrost`, la page du
//!    depot.
//!
//! # La mise a niveau et le service
//!
//! Mesure du 18/10/2026 dans une VM Windows Server 2025: deux MSI de la meme
//! version etaient deux installations distinctes, la seconde butait sur le
//! service de la premiere et son retour arriere le retirait; une mise a
//! niveau retirait puis recreait
//! le service, et le type de demarrage choisi par l'administrateur (a la
//! demande, desactive) redevenait automatique; un echec de la nouvelle version
//! laissait la machine sans aucune des deux. En grammaire FERMEE (une forme
//! non prevue rougit):
//!
//! 10. `MajorUpgrade` porte exactement `AllowSameVersionUpgrades="yes"`,
//!     `Schedule="afterInstallInitialize"` et `DowngradeErrorMessage`.
//! 11. `BIFROSTSERVICEEXISTANT`: `Secure="yes"`, un seul `RegistrySearch`,
//!     la valeur `ImagePath` de la cle du service que le script nomme.
//! 12. La table `InstallExecuteSequence`, action par action (`Action`,
//!     `After`, `Condition`, rien d'autre): le retour arriere du service
//!     seulement si le service n'existait pas, son retrait et celui des
//!     filtres jamais pendant une mise a niveau. `BifrostServiceRollback` est
//!     une action de retour arriere, et rien de plus.
//! 13. `install-windows.ps1` n'invoque le daemon que par `& $Daemon
//!     @arguments` (plus de `--uninstall-service` avant de reinstaller).
//! 14. Le daemon (`service/scm.rs`, lu par le lexeur commun): un seul
//!     `ChangeServiceConfigW`, dans `mettre_a_jour`, type de demarrage
//!     `SERVICE_NO_CHANGE`, ligne reecrite; `install` y mene sur
//!     `ERROR_SERVICE_EXISTS`; `CreateServiceW` garde le demarrage de la
//!     specification; `DeleteService` n'est appele que par `uninstall`.
//!
//! # Le MSI de la coquille
//!
//! `packaging/msi/bifrost-gui.wxs` n'a pas de script en face: il se compare au
//! MSI du daemon, a cote duquel il s'installe.
//!
//! 7. Un paquet distinct: son nom, son UpgradeCode (le meme ferait prendre
//!    l'un pour une mise a niveau de l'autre, qui serait retire), ses
//!    composants; le meme dossier d'installation; le seul `bifrost-gui.exe`.
//! 8. Ni action personnalisee, ni service, ni `%ProgramData%`, ni demarrage
//!    automatique (valeur sous `CurrentVersion\Run`, dossier Demarrage),
//!    ni raccourci sur le Bureau. Un seul raccourci, non annonce, a la racine
//!    du Menu Demarrer, dans un composant sans fichier dont le KeyPath est une
//!    valeur HKCU (ICE43, ICE57). La WebView2 exigee a la premiere
//!    installation seulement. Des identifiants WiX legaux dans les deux
//!    sources (pas de tiret: WIX0014).
//! 15. La mise a niveau, dans la grammaire FERMEE de l'exigence 10: le meme
//!     `MajorUpgrade` que le daemon (`AllowSameVersionUpgrades="yes"`,
//!     `Schedule="afterInstallInitialize"`, `DowngradeErrorMessage`). Mesure
//!     du 18/10/2026 dans une VM Windows Server 2025: deux MSI de la coquille
//!     de la meme version etaient deux installations distinctes (deux
//!     entrees de programmes, composants a deux clients, executable du
//!     second non copie, dossier d'icone laisse apres les deux retraits), et
//!     un echec de la nouvelle version laissait la machine sans coquille.
//!     Les exigences 11 a 14 visent le service: sans objet ici.
//!
//! # L'editeur
//!
//! 9. `Bifrost`, dit en trois lieux qui restent d'accord: `bundle.publisher`
//!    de `gui/tauri.conf.json` (tauri-build l'ecrit dans le CompanyName de
//!    l'executable; absent, il y ecrit le deuxieme element de l'identifiant,
//!    `github`), le `Manufacturer` du Package des deux sources WiX, et
//!    `scripts/paquets-gui-windows.ps1`, qui lit l'editeur dans la
//!    configuration et l'exige dans l'executable et dans le MSI. Les lignes
//!    du script qui disent l'editeur ont une forme fermee: une autre fait
//!    rougir.
//!
//! # Ce qu'elle ne fait pas
//!
//! Elle ne construit ni n'installe rien (`scripts/paquets-windows.ps1`,
//! `scripts/paquets-windows-installer.ps1`). Elle lit le XML et le PowerShell
//! en texte: commentaires ecartes, elements reperes par leur balise et leur
//! `Id`, variables a valeur litterale ou `Join-Path` resolues. Une forme
//! qu'elle ne sait pas lire fait rougir une exigence au lieu d'etre devinee.

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

const SCRIPT: &str = "packaging/install-windows.ps1";
const WXS: &str = "packaging/msi/bifrost.wxs";

/// La plus longue description que `New-LocalGroup` accepte (validation du
/// parametre `-Description`, relevee dans son refus le 18/10/2026).
const DESCRIPTION_MAX: usize = 48;

// ------------------------------------------------------------------ XML

/// Le XML sans ses commentaires.
fn sans_commentaires_xml(xml: &str) -> String {
    let mut sortie = String::new();
    let mut reste = xml;
    while let Some(d) = reste.find("<!--") {
        sortie.push_str(&reste[..d]);
        match reste[d..].find("-->") {
            Some(f) => reste = &reste[d + f + 3..],
            None => return sortie,
        }
    }
    sortie.push_str(reste);
    sortie
}

/// Chaque balise ouvrante (ou vide) du XML, dans l'ordre: (nom, attributs
/// bruts, vide), et chaque fermante: ("/nom", "", false).
fn balises(xml: &str) -> Vec<(String, String, bool)> {
    let mut sortie = Vec::new();
    let mut reste = xml;
    while let Some(d) = reste.find('<') {
        let Some(f) = reste[d..].find('>') else { break };
        let corps = &reste[d + 1..d + f];
        reste = &reste[d + f + 1..];
        if corps.starts_with('?') || corps.starts_with('!') {
            continue;
        }
        let vide = corps.ends_with('/');
        let corps = corps.trim_end_matches('/');
        let (nom, attributs) = corps.split_once(char::is_whitespace).unwrap_or((corps, ""));
        sortie.push((nom.to_string(), attributs.to_string(), vide));
    }
    sortie
}

/// La valeur d'un attribut (`nom="..."`), entites `&quot;` et `&amp;`
/// rendues.
fn attribut(attributs: &str, nom: &str) -> Option<String> {
    let motif = format!("{nom}=\"");
    let mut depart = 0usize;
    while let Some(p) = attributs[depart..].find(&motif) {
        let p = depart + p;
        let precede = p == 0 || attributs.as_bytes()[p - 1].is_ascii_whitespace();
        let debut = p + motif.len();
        if precede {
            let fin = attributs[debut..].find('"')? + debut;
            return Some(
                attributs[debut..fin]
                    .replace("&quot;", "\"")
                    .replace("&amp;", "&"),
            );
        }
        depart = debut;
    }
    None
}

/// Les attributs de l'element `balise` dont l'`Id` vaut `id`.
fn element(xml: &str, balise: &str, id: &str) -> Option<String> {
    balises(xml)
        .into_iter()
        .find(|(n, a, _)| n == balise && attribut(a, "Id").as_deref() == Some(id))
        .map(|(_, a, _)| a)
}

/// Le chemin de chaque repertoire du MSI, par son `Id`: les deux repertoires
/// standard nommes comme le script les lit dans l'environnement, puis les
/// `Directory` imbriques par leur `Name`.
fn repertoires_du_msi(xml: &str) -> BTreeMap<String, String> {
    let mut chemins = BTreeMap::new();
    let mut pile: Vec<String> = Vec::new();
    for (nom, attributs, vide) in balises(xml) {
        match nom.as_str() {
            "StandardDirectory" | "Directory" => {
                let id = attribut(&attributs, "Id").unwrap_or_default();
                let chemin = if nom == "StandardDirectory" {
                    match id.as_str() {
                        "ProgramFiles64Folder" => "$env:ProgramFiles".to_string(),
                        "CommonAppDataFolder" => "$env:ProgramData".to_string(),
                        autre => format!("<{autre}>"),
                    }
                } else {
                    format!(
                        "{}\\{}",
                        pile.last().cloned().unwrap_or_default(),
                        attribut(&attributs, "Name").unwrap_or_default()
                    )
                };
                chemins.insert(id, chemin.clone());
                if !vide {
                    pile.push(chemin);
                }
            }
            "/StandardDirectory" | "/Directory" => {
                pile.pop();
            }
            _ => {}
        }
    }
    chemins
}

/// `[ID]` remplaces par le chemin du repertoire, sans sa contre-oblique
/// finale quand rien ne suit.
fn resoudre_msi(texte: &str, repertoires: &BTreeMap<String, String>) -> String {
    let mut s = texte.to_string();
    for (id, chemin) in repertoires {
        s = s.replace(&format!("[{id}]"), &format!("{chemin}\\"));
    }
    s.trim_end_matches('\\').to_string()
}

// ----------------------------------------------------------- PowerShell

/// Les lignes actives d'un script PowerShell: sans les blocs `<# #>` ni les
/// commentaires de ligne entiere, chaque ligne sans ses blancs.
fn lignes_ps(texte: &str) -> Vec<String> {
    let mut actives = Vec::new();
    let mut dans_bloc = false;
    for l in texte.lines() {
        let t = l.trim();
        if dans_bloc {
            if t.contains("#>") {
                dans_bloc = false;
            }
            continue;
        }
        if t.starts_with("<#") {
            dans_bloc = !t.contains("#>");
            continue;
        }
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        actives.push(t.to_string());
    }
    actives
}

/// Les variables d'un script: `$X = 'litteral'` et `$X = Join-Path $Y 'z'`.
fn variables_ps(lignes: &[String]) -> BTreeMap<String, String> {
    let mut vars: BTreeMap<String, String> = BTreeMap::new();
    for l in lignes {
        let Some(reste) = l.strip_prefix('$') else {
            continue;
        };
        let Some((nom, valeur)) = reste.split_once('=') else {
            continue;
        };
        let nom = nom.trim();
        if nom.is_empty() || !nom.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            continue;
        }
        let valeur = valeur.trim();
        if let Some(v) = valeur.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')) {
            vars.insert(nom.to_string(), v.to_string());
        } else if let Some(j) = valeur.strip_prefix("Join-Path ") {
            let mots = jetons_ps(j);
            if let [base, feuille] = mots.as_slice() {
                let base = remplacer_variables(base, &vars);
                vars.insert(nom.to_string(), format!("{base}\\{feuille}"));
            }
        }
    }
    vars
}

/// Les mots d'une ligne PowerShell: guillemets simples et doubles retires,
/// leurs blancs gardes dans le mot.
fn jetons_ps(ligne: &str) -> Vec<String> {
    let mut mots = Vec::new();
    let mut courant = String::new();
    let mut guillemet: Option<char> = None;
    let mut dans_mot = false;
    for c in ligne.chars() {
        match (guillemet, c) {
            (Some(q), c) if c == q => guillemet = None,
            (Some(_), c) => courant.push(c),
            (None, '\'' | '"') => {
                guillemet = Some(c);
                dans_mot = true;
            }
            (None, c) if c.is_whitespace() => {
                if dans_mot {
                    mots.push(std::mem::take(&mut courant));
                    dans_mot = false;
                }
            }
            (None, c) => {
                courant.push(c);
                dans_mot = true;
            }
        }
    }
    if dans_mot {
        mots.push(courant);
    }
    mots
}

/// `$X`, `${X}` et `$($X)` remplaces par leur valeur connue.
fn remplacer_variables(texte: &str, vars: &BTreeMap<String, String>) -> String {
    let mut s = texte.to_string();
    // Les plus longs d'abord: `$Etat` ne doit pas mordre dans `$EtatX`.
    let mut noms: Vec<&String> = vars.keys().collect();
    noms.sort_by_key(|n| std::cmp::Reverse(n.len()));
    for nom in noms {
        let v = &vars[nom];
        s = s
            .replace(&format!("$(${nom})"), v)
            .replace(&format!("${{{nom}}}"), v)
            .replace(&format!("${nom}"), v);
    }
    s
}

// --------------------------------------------------------------- lecture

/// Ce que chaque cote declare, sous une forme comparable.
#[derive(Debug, Default, PartialEq)]
struct Installation {
    /// Les invocations d'icacls, arguments resolus, dans l'ordre.
    icacls: Vec<Vec<String>>,
    /// Le nom du groupe d'acces et son commentaire.
    groupe: (String, String),
    /// La ligne du service sans resolveur, puis avec.
    ligne_sans: Vec<String>,
    ligne_avec: Vec<String>,
    /// Le chemin ou le resolveur deja pose est cherche.
    resolveur: String,
}

fn lire_script(texte: &str) -> Installation {
    let lignes = lignes_ps(texte);
    let mut vars = variables_ps(&lignes);
    let mut sortie = Installation::default();
    for l in &lignes {
        if let Some(p) = l.find("icacls.exe ") {
            let corps = l[p + "icacls.exe ".len()..].trim_end_matches('}').trim();
            let mots = jetons_ps(&remplacer_variables(corps, &vars));
            sortie.icacls.push(mots);
        }
    }
    let groupe = vars.get("GroupeAcces").cloned().unwrap_or_default();
    // `${X}` et `$X` dans un texte entre guillemets doubles.
    if let Some(l) = lignes.iter().find(|l| l.starts_with("New-LocalGroup ")) {
        let mots = jetons_ps(l);
        if let Some(i) = mots.iter().position(|m| m == "-Description") {
            let commentaire = mots.get(i + 1).cloned().unwrap_or_default();
            sortie.groupe = (groupe.clone(), remplacer_variables(&commentaire, &vars));
        }
    }
    // La ligne du service: les elements de `$arguments`, dans l'ordre.
    let mut parties: Vec<Vec<String>> = Vec::new();
    for l in &lignes {
        if l.starts_with("$arguments = @(") || l.starts_with("$arguments += @(") {
            let dedans = l
                .split_once("@(")
                .map(|(_, r)| r.trim_end_matches(')'))
                .unwrap_or("");
            let mots: Vec<String> = dedans
                .split(',')
                .map(|m| {
                    remplacer_variables(m.trim(), &vars)
                        .trim_matches('\'')
                        .to_string()
                })
                .collect();
            parties.push(mots);
        }
    }
    if let [base, resolveur, groupe_args] = parties.as_slice() {
        sortie.ligne_sans = base.iter().chain(groupe_args).cloned().collect();
        sortie.ligne_avec = base
            .iter()
            .chain(resolveur)
            .chain(groupe_args)
            .cloned()
            .collect();
    }
    vars.entry("ResolveurInstalle".to_string()).or_default();
    sortie.resolveur = vars["ResolveurInstalle"].clone();
    sortie
}

fn lire_wxs(texte: &str) -> Installation {
    let xml = sans_commentaires_xml(texte);
    let reps = repertoires_du_msi(&xml);
    let mut sortie = Installation::default();
    for (nom, attributs, _) in balises(&xml) {
        if nom != "SetProperty" {
            continue;
        }
        let valeur = attribut(&attributs, "Value").unwrap_or_default();
        let mots = jetons_ps(&valeur);
        let Some((programme, args)) = mots.split_first() else {
            continue;
        };
        let args: Vec<String> = args.iter().map(|a| resoudre_msi(a, &reps)).collect();
        if programme.ends_with("icacls.exe") {
            sortie.icacls.push(args);
        } else if programme.ends_with("net.exe")
            && let [verbe, groupe, ajout, commentaire] = args.as_slice()
            && verbe == "localgroup"
            && ajout == "/add"
        {
            let commentaire = commentaire.strip_prefix("/comment:").unwrap_or("");
            sortie.groupe = (groupe.clone(), commentaire.to_string());
        }
    }
    let exe = |id: &str| -> Vec<String> {
        element(&xml, "CustomAction", id)
            .and_then(|a| attribut(&a, "ExeCommand"))
            .map(|c| {
                jetons_ps(&c)
                    .iter()
                    .map(|m| resoudre_msi(m, &reps))
                    .collect()
            })
            .unwrap_or_default()
    };
    sortie.ligne_sans = exe("BifrostServiceInstall");
    sortie.ligne_avec = exe("BifrostServiceInstallResolveur");
    let recherche = balises(&xml)
        .into_iter()
        .find(|(n, _, _)| n == "DirectorySearch")
        .and_then(|(_, a, _)| attribut(&a, "Path"))
        .map(|p| resoudre_msi(&p, &reps))
        .unwrap_or_default();
    let fichier = balises(&xml)
        .into_iter()
        .find(|(n, _, _)| n == "FileSearch")
        .and_then(|(_, a, _)| attribut(&a, "Name"))
        .unwrap_or_default();
    sortie.resolveur = format!("{recherche}\\{fichier}");
    sortie
}

// -------------------------------------------------------------- recettes

fn ecarts_d_installation(script: &str, wxs: &str) -> Vec<String> {
    let s = lire_script(script);
    let m = lire_wxs(wxs);
    let mut ecarts = Vec::new();
    if s.icacls.len() != 4
        || s.ligne_sans.len() < 3
        || s.groupe.0.is_empty()
        || s.groupe.1.is_empty()
    {
        ecarts.push(format!("{SCRIPT} mal lu: {s:?}"));
    }
    // La limite de New-LocalGroup, mesuree: une description plus longue
    // arrete le script avant la creation du groupe.
    if s.groupe.1.chars().count() > DESCRIPTION_MAX {
        ecarts.push(format!(
            "description du groupe d'acces de {} caracteres: New-LocalGroup en refuse plus de {DESCRIPTION_MAX}",
            s.groupe.1.chars().count()
        ));
    }
    for (quoi, a, b) in [
        (
            "les invocations d'icacls",
            format!("{:?}", s.icacls),
            format!("{:?}", m.icacls),
        ),
        (
            "le groupe d'acces (nom, commentaire)",
            format!("{:?}", s.groupe),
            format!("{:?}", m.groupe),
        ),
        (
            "la ligne du service sans resolveur",
            format!("{:?}", s.ligne_sans),
            format!("{:?}", m.ligne_sans),
        ),
        (
            "la ligne du service avec le resolveur",
            format!("{:?}", s.ligne_avec),
            format!("{:?}", m.ligne_avec),
        ),
        (
            "le chemin du resolveur deja pose",
            s.resolveur.clone(),
            m.resolveur.clone(),
        ),
    ] {
        if a != b {
            ecarts.push(format!("{quoi}: script {a}, MSI {b}"));
        }
    }
    let xml = sans_commentaires_xml(wxs);
    // Le resolveur nomme dans la ligne est celui que le MSI cherche.
    if !m.ligne_avec.contains(&m.resolveur) {
        ecarts.push(format!(
            "la ligne avec resolveur ne nomme pas {} : {:?}",
            m.resolveur, m.ligne_avec
        ));
    }
    // Les conditions: l'une ou l'autre forme, jamais les deux.
    for (action, condition) in [
        (
            "BifrostServiceInstall",
            "NOT Installed AND NOT BIFROSTRESOLVEUR",
        ),
        (
            "BifrostServiceInstallResolveur",
            "NOT Installed AND BIFROSTRESOLVEUR",
        ),
    ] {
        let lue = balises(&xml)
            .into_iter()
            .find(|(n, a, _)| n == "Custom" && attribut(a, "Action").as_deref() == Some(action))
            .and_then(|(_, a, _)| attribut(&a, "Condition"));
        if lue.as_deref() != Some(condition) {
            ecarts.push(format!(
                "Custom {action}: condition {lue:?} au lieu de {condition:?}"
            ));
        }
    }
    for (id, retour) in [
        ("BifrostServiceInstall", "check"),
        ("BifrostServiceInstallResolveur", "check"),
        ("BifrostGroupe", "ignore"),
        ("BifrostServiceUninstall", "check"),
    ] {
        let a = element(&xml, "CustomAction", id).unwrap_or_default();
        if attribut(&a, "Return").as_deref() != Some(retour)
            || attribut(&a, "Impersonate").as_deref() != Some("no")
            || attribut(&a, "Execute").as_deref() != Some("deferred")
        {
            ecarts.push(format!(
                "CustomAction {id}: attendu deferred, Impersonate=no, Return={retour}"
            ));
        }
    }
    // Les repertoires portent les noms du script.
    let reps = repertoires_du_msi(&xml);
    let vars = variables_ps(&lignes_ps(script));
    for (id, var) in [
        ("INSTALLFOLDER", "Installation"),
        ("BIFROSTDATA", "Donnees"),
        ("BIFROSTRESOLVEURDIR", "RepResolveur"),
        ("BIFROSTETAT", "Etat"),
    ] {
        if reps.get(id) != vars.get(var) || !reps.contains_key(id) {
            ecarts.push(format!(
                "repertoire {id} {:?}, script ${var} {:?}",
                reps.get(id),
                vars.get(var)
            ));
        }
    }
    let fichiers: Vec<String> = balises(&xml)
        .into_iter()
        .filter(|(n, _, _)| n == "File")
        .filter_map(|(_, a, _)| attribut(&a, "Source"))
        .collect();
    if fichiers
        != [
            "$(var.Binaires)\\bifrost-daemon.exe",
            "$(var.Binaires)\\bifrost-cli.exe",
        ]
    {
        ecarts.push(format!(
            "le MSI pose {fichiers:?}, pas exactement les deux binaires"
        ));
    }
    ecarts
}

#[test]
fn le_msi_installe_comme_le_script() {
    let ecarts = ecarts_d_installation(&lire(SCRIPT), &lire(WXS));
    assert!(
        ecarts.is_empty(),
        "{} ecart(s):\n  {}",
        ecarts.len(),
        ecarts.join("\n  ")
    );
}

fn ecarts_du_demarrage(script: &str, wxs: &str) -> Vec<String> {
    let mut ecarts = Vec::new();
    let xml = sans_commentaires_xml(wxs);
    for (nom, attributs, _) in balises(&xml) {
        if nom == "ServiceInstall" {
            ecarts.push(
                "le MSI porte un ServiceInstall: le service est enregistre par le daemon"
                    .to_string(),
            );
        }
        if nom == "ServiceControl" {
            if attribut(&attributs, "Start").is_some() {
                ecarts.push(format!("ServiceControl avec Start=: {attributs}"));
            }
            if attribut(&attributs, "Stop").as_deref() != Some("uninstall")
                || attribut(&attributs, "Name").as_deref() != Some("BifrostDaemon")
            {
                ecarts.push(format!("ServiceControl inattendu: {attributs}"));
            }
        }
    }
    for (id, commande) in [
        ("BifrostCleanupFirewall", "--cleanup-firewall"),
        ("BifrostServiceUninstall", "--uninstall-service"),
        ("BifrostServiceRollback", "--uninstall-service"),
    ] {
        let lue = element(&xml, "CustomAction", id).and_then(|a| attribut(&a, "ExeCommand"));
        if lue.as_deref() != Some(commande) {
            ecarts.push(format!(
                "CustomAction {id}: {lue:?} au lieu de {commande:?}"
            ));
        }
    }
    for l in lignes_ps(script) {
        // Hors des chaines: un message qui cite la commande n'en est pas une.
        let mut code = String::new();
        let mut guillemet: Option<char> = None;
        for c in l.chars() {
            match guillemet {
                Some(q) if c == q => guillemet = None,
                Some(_) => {}
                None if c == '\'' || c == '"' => guillemet = Some(c),
                None => code.push(c),
            }
        }
        let code = code.to_ascii_lowercase();
        if code.contains("start-service")
            || code.contains("sc.exe start")
            || code.contains("net start")
        {
            ecarts.push(format!("{SCRIPT} demarre le service: `{l}`"));
        }
    }
    ecarts
}

#[test]
fn ni_le_msi_ni_le_script_ne_demarrent_le_service() {
    let ecarts = ecarts_du_demarrage(&lire(SCRIPT), &lire(WXS));
    assert!(
        ecarts.is_empty(),
        "{} ecart(s):\n  {}",
        ecarts.len(),
        ecarts.join("\n  ")
    );
}

#[test]
fn version_fabricant_et_page_ont_une_seule_source() {
    let xml = sans_commentaires_xml(&lire(WXS));
    let package = balises(&xml)
        .into_iter()
        .find(|(n, _, _)| n == "Package")
        .map(|(_, a, _)| a)
        .unwrap_or_default();
    let mut ecarts = Vec::new();
    for (nom, attendu) in [
        ("Version", "$(var.Version)"),
        ("Manufacturer", "Bifrost"),
        ("Name", "Bifrost"),
        ("Scope", "perMachine"),
    ] {
        if attribut(&package, nom).as_deref() != Some(attendu) {
            ecarts.push(format!(
                "Package {nom}: {:?} au lieu de {attendu}",
                attribut(&package, nom)
            ));
        }
    }
    let upgrade = attribut(&package, "UpgradeCode").unwrap_or_default();
    if upgrade.len() != 36 || !upgrade.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-') {
        ecarts.push(format!("UpgradeCode illisible: {upgrade:?}"));
    }
    let depot = lire("Cargo.toml")
        .lines()
        .find_map(|l| l.strip_prefix("repository = \""))
        .map(|v| v.trim_end_matches('"').to_string())
        .unwrap_or_default();
    let page = element(&xml, "Property", "ARPURLINFOABOUT").and_then(|a| attribut(&a, "Value"));
    if depot.is_empty() || page.as_deref() != Some(depot.as_str()) {
        ecarts.push(format!("ARPURLINFOABOUT {page:?}, depot {depot:?}"));
    }
    let version = lire("Cargo.toml")
        .lines()
        .find_map(|l| l.strip_prefix("version = \""))
        .map(|v| v.trim_end_matches('"').to_string())
        .unwrap_or_default();
    if version.is_empty() || lire(WXS).contains(&format!("\"{version}\"")) {
        ecarts.push(format!(
            "{WXS} ecrit la version du workspace ({version}) en dur"
        ));
    }
    assert!(
        ecarts.is_empty(),
        "{} ecart(s):\n  {}",
        ecarts.len(),
        ecarts.join("\n  ")
    );
}

/// Chaque exigence mord sur une mutation du texte reel.
#[test]
fn chaque_exigence_mord() {
    let script = lire(SCRIPT);
    let wxs = lire(WXS);
    assert!(ecarts_d_installation(&script, &wxs).is_empty());
    assert!(ecarts_du_demarrage(&script, &wxs).is_empty());
    let remplacer = |texte: &str, avant: &str, apres: &str| -> String {
        assert_eq!(
            texte.matches(avant).count(),
            1,
            "`{avant}` doit etre unique"
        );
        texte.replacen(avant, apres, 1)
    };
    let mord = |script: &str, wxs: &str, motif: &str| {
        let e = ecarts_d_installation(script, wxs);
        assert!(
            e.iter().any(|x| x.contains(motif)),
            "`{motif}` attendu dans {e:?}"
        );
    };
    // Cote MSI.
    mord(
        &script,
        &remplacer(
            &wxs,
            "ExeCommand=\"--install-service --group Bifrost\"",
            "ExeCommand=\"--install-service --group Utilisateurs\"",
        ),
        "la ligne du service sans resolveur",
    );
    mord(
        &script,
        &remplacer(
            &wxs,
            "--resolveur-utilisateur LocalService --group Bifrost",
            "--resolveur-utilisateur LocalSystem --group Bifrost",
        ),
        "la ligne du service avec le resolveur",
    );
    mord(
        &script,
        &remplacer(
            &wxs,
            "[BIFROSTETAT] /grant *S-1-5-19:(OI)(CI)M",
            "[BIFROSTETAT] /grant *S-1-5-19:(OI)(CI)F",
        ),
        "les invocations d'icacls",
    );
    mord(
        &script,
        &remplacer(&wxs, "au canal de BifrostDaemon&quot;", "au canal&quot;"),
        "le groupe d'acces",
    );
    mord(
        &script,
        &remplacer(
            &wxs,
            "<FileSearch Id=\"RechercheResolveur\" Name=\"dnscrypt-proxy.exe\" />",
            "<FileSearch Id=\"RechercheResolveur\" Name=\"resolveur.exe\" />",
        ),
        "le chemin du resolveur deja pose",
    );
    mord(
        &script,
        &remplacer(
            &wxs,
            "Condition=\"NOT Installed AND NOT BIFROSTRESOLVEUR\"",
            "Condition=\"NOT Installed\"",
        ),
        "Custom BifrostServiceInstall: condition",
    );
    mord(
        &script,
        &remplacer(
            &wxs,
            "<Directory Id=\"BIFROSTETAT\" Name=\"etat\" />",
            "<Directory Id=\"BIFROSTETAT\" Name=\"cache\" />",
        ),
        "repertoire BIFROSTETAT",
    );
    // Une description que New-LocalGroup refuserait, des deux cotes a la fois:
    // la parite tient, la limite rougit.
    mord(
        &remplacer(
            &script,
            "\"Acces sans elevation au canal de $NomService\"",
            "\"Acces sans elevation, a l'etat et a la connexion, au canal de $NomService\"",
        ),
        &remplacer(
            &wxs,
            "/comment:&quot;Acces sans elevation au canal de BifrostDaemon&quot;",
            "/comment:&quot;Acces sans elevation, a l'etat et a la connexion, au canal de BifrostDaemon&quot;",
        ),
        "New-LocalGroup en refuse plus de 48",
    );
    // Cote script: le groupe renomme, un SID d'ACL change.
    mord(
        &remplacer(
            &script,
            "$GroupeAcces = 'Bifrost'",
            "$GroupeAcces = 'BifrostAcces'",
        ),
        &wxs,
        "le groupe d'acces",
    );
    mord(
        &remplacer(
            &script,
            "$SID_LOCALSERVICE = '*S-1-5-19'",
            "$SID_LOCALSERVICE = '*S-1-5-20'",
        ),
        &wxs,
        "les invocations d'icacls",
    );
    // Le demarrage.
    let e = ecarts_du_demarrage(
        &script,
        &remplacer(
            &wxs,
            "Stop=\"uninstall\" Wait=\"yes\"",
            "Start=\"install\" Stop=\"uninstall\" Wait=\"yes\"",
        ),
    );
    assert!(e.iter().any(|x| x.contains("Start=")), "{e:?}");
    let e = ecarts_du_demarrage(
        &remplacer(
            &script,
            "Write-Host ''\nWrite-Host 'Installation terminee.",
            "Start-Service $NomService\nWrite-Host ''\nWrite-Host 'Installation terminee.",
        ),
        &wxs,
    );
    assert!(e.iter().any(|x| x.contains("demarre le service")), "{e:?}");
    let e = ecarts_du_demarrage(
        &script,
        &remplacer(
            &wxs,
            "ExeCommand=\"--cleanup-firewall\"",
            "ExeCommand=\"--version\"",
        ),
    );
    assert!(
        e.iter().any(|x| x.contains("BifrostCleanupFirewall")),
        "{e:?}"
    );
}

// ======================================== la mise a niveau et le service

const SCM: &str = "crates/bifrost-daemon/src/service/scm.rs";

/// Les attributs d'une balise, en grammaire fermee: une suite de
/// `nom="valeur"` separes par des blancs, rien d'autre. Une forme que la
/// lecture ne reconnait pas (guillemet simple, attribut sans valeur, nom en
/// double, texte colle) est une erreur, pas une absence.
fn attributs_stricts(brut: &str) -> Result<Vec<(String, String)>, String> {
    let mut sortie: Vec<(String, String)> = Vec::new();
    let mut reste = brut.trim_start();
    while !reste.is_empty() {
        let egal = reste
            .find('=')
            .ok_or_else(|| format!("attribut sans valeur: {reste:?}"))?;
        let nom = &reste[..egal];
        if nom.is_empty()
            || !nom
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b':' || b == b'_')
        {
            return Err(format!("nom d'attribut illisible: {nom:?}"));
        }
        let corps = reste[egal + 1..]
            .strip_prefix('"')
            .ok_or_else(|| format!("{nom}: valeur sans guillemet double"))?;
        let fin = corps
            .find('"')
            .ok_or_else(|| format!("{nom}: valeur non fermee"))?;
        if sortie.iter().any(|(n, _)| n == nom) {
            return Err(format!("{nom} deux fois"));
        }
        sortie.push((
            nom.to_string(),
            corps[..fin].replace("&quot;", "\"").replace("&amp;", "&"),
        ));
        let suite = &corps[fin + 1..];
        if !suite.is_empty() && !suite.starts_with(char::is_whitespace) {
            return Err(format!("{nom}: texte colle apres la valeur: {suite:?}"));
        }
        reste = suite.trim_start();
    }
    Ok(sortie)
}

/// Les attributs stricts, tries par nom: deux balises egales a l'ordre pres
/// se comparent egales.
fn attributs_tries(brut: &str) -> Result<Vec<(String, String)>, String> {
    let mut a = attributs_stricts(brut)?;
    a.sort();
    Ok(a)
}

fn paires(attendu: &[(&str, &str)]) -> Vec<(String, String)> {
    let mut v: Vec<(String, String)> = attendu
        .iter()
        .map(|(n, v)| (n.to_string(), v.to_string()))
        .collect();
    v.sort();
    v
}

/// La table InstallExecuteSequence du MSI du daemon, action par action:
/// (Action, After, Condition), dans l'ordre du texte.
const SEQUENCE: [(&str, &str, &str); 10] = [
    ("BifrostAclProprietaire", "InstallFiles", "NOT Installed"),
    (
        "BifrostAclDonnees",
        "BifrostAclProprietaire",
        "NOT Installed",
    ),
    ("BifrostAclResolveur", "BifrostAclDonnees", "NOT Installed"),
    ("BifrostAclEtat", "BifrostAclResolveur", "NOT Installed"),
    ("BifrostGroupe", "BifrostAclEtat", "NOT Installed"),
    (
        "BifrostServiceRollback",
        "BifrostGroupe",
        "NOT Installed AND NOT BIFROSTSERVICEEXISTANT",
    ),
    (
        "BifrostServiceInstall",
        "BifrostServiceRollback",
        "NOT Installed AND NOT BIFROSTRESOLVEUR",
    ),
    (
        "BifrostServiceInstallResolveur",
        "BifrostServiceInstall",
        "NOT Installed AND BIFROSTRESOLVEUR",
    ),
    (
        "BifrostCleanupFirewall",
        "StopServices",
        "REMOVE=\"ALL\" AND NOT UPGRADINGPRODUCTCODE",
    ),
    (
        "BifrostServiceUninstall",
        "BifrostCleanupFirewall",
        "REMOVE=\"ALL\" AND NOT UPGRADINGPRODUCTCODE",
    ),
];

/// 10 et 15. `MajorUpgrade`, en grammaire fermee: un seul element, vide,
/// qui porte exactement `AllowSameVersionUpgrades="yes"`,
/// `Schedule="afterInstallInitialize"` et un `DowngradeErrorMessage` non vide.
/// La meme grammaire pour les deux MSI: c'est leur parite.
fn ecarts_du_major_upgrade(tout: &[(String, String, bool)]) -> Vec<String> {
    let mut ecarts = Vec::new();
    let majeures: Vec<&(String, String, bool)> = tout
        .iter()
        .filter(|(n, _, _)| n == "MajorUpgrade")
        .collect();
    match majeures.as_slice() {
        [(_, a, true)] => match attributs_stricts(a) {
            Ok(lus) => {
                for (nom, valeur) in &lus {
                    match nom.as_str() {
                        "AllowSameVersionUpgrades" if valeur == "yes" => {}
                        "Schedule" if valeur == "afterInstallInitialize" => {}
                        "DowngradeErrorMessage" if !valeur.trim().is_empty() => {}
                        _ => ecarts.push(format!(
                            "MajorUpgrade {nom}=\"{valeur}\": hors de la grammaire (AllowSameVersionUpgrades=\"yes\", Schedule=\"afterInstallInitialize\", DowngradeErrorMessage)"
                        )),
                    }
                }
                for requis in [
                    "AllowSameVersionUpgrades",
                    "Schedule",
                    "DowngradeErrorMessage",
                ] {
                    if !lus.iter().any(|(n, _)| n == requis) {
                        ecarts.push(format!("MajorUpgrade sans {requis}"));
                    }
                }
            }
            Err(e) => ecarts.push(format!("MajorUpgrade illisible: {e}")),
        },
        autre => ecarts.push(format!(
            "{} element(s) MajorUpgrade vide(s) au lieu d'un",
            autre.len()
        )),
    }
    ecarts
}

fn ecarts_de_la_mise_a_niveau(wxs: &str, script: &str) -> Vec<String> {
    let xml = sans_commentaires_xml(wxs);
    let tout = balises(&xml);
    let mut ecarts = Vec::new();

    // 10. MajorUpgrade.
    ecarts.extend(ecarts_du_major_upgrade(&tout));

    // 11. La propriete qui dit si le service existait avant l'installation.
    let nom_service = variables_ps(&lignes_ps(script))
        .get("NomService")
        .cloned()
        .unwrap_or_default();
    let proprietes: Vec<usize> = tout
        .iter()
        .enumerate()
        .filter(|(_, (n, a, _))| {
            n == "Property" && attribut(a, "Id").as_deref() == Some("BIFROSTSERVICEEXISTANT")
        })
        .map(|(i, _)| i)
        .collect();
    match proprietes.as_slice() {
        [i] => {
            let (_, a, vide) = &tout[*i];
            if attributs_tries(a)
                != Ok(paires(&[
                    ("Id", "BIFROSTSERVICEEXISTANT"),
                    ("Secure", "yes"),
                ]))
            {
                ecarts.push(format!(
                    "Property BIFROSTSERVICEEXISTANT: {:?}, attendu Id et Secure=\"yes\" seuls",
                    attributs_stricts(a)
                ));
            }
            let enfants: Vec<&(String, String, bool)> = if *vide {
                Vec::new()
            } else {
                tout[i + 1..]
                    .iter()
                    .take_while(|(n, _, _)| n != "/Property")
                    .collect()
            };
            let cle = format!("SYSTEM\\CurrentControlSet\\Services\\{nom_service}");
            let attendu = paires(&[
                ("Id", "RechercheService"),
                ("Root", "HKLM"),
                ("Key", &cle),
                ("Name", "ImagePath"),
                ("Type", "raw"),
                ("Bitness", "always64"),
            ]);
            match enfants.as_slice() {
                [(n, a, true)] if n == "RegistrySearch" => {
                    if nom_service.is_empty() || attributs_tries(a) != Ok(attendu.clone()) {
                        ecarts.push(format!(
                            "RegistrySearch de BIFROSTSERVICEEXISTANT: {:?}, attendu {attendu:?}",
                            attributs_tries(a)
                        ));
                    }
                }
                autre => ecarts.push(format!(
                    "Property BIFROSTSERVICEEXISTANT: enfants {:?}, attendu un seul RegistrySearch",
                    autre.iter().map(|(n, _, _)| n.as_str()).collect::<Vec<_>>()
                )),
            }
        }
        autre => ecarts.push(format!(
            "{} propriete(s) BIFROSTSERVICEEXISTANT au lieu d'une",
            autre.len()
        )),
    }

    // 12. La sequence, action par action, et l'action de retour arriere.
    let debut = tout
        .iter()
        .position(|(n, _, _)| n == "InstallExecuteSequence");
    let fin = tout
        .iter()
        .position(|(n, _, _)| n == "/InstallExecuteSequence");
    match (debut, fin) {
        (Some(d), Some(f)) if d < f => {
            let mut lues: Vec<(String, String, String)> = Vec::new();
            for (n, a, vide) in &tout[d + 1..f] {
                let triple = attributs_stricts(a).ok().and_then(|at| {
                    let noms: Vec<&str> = at.iter().map(|(k, _)| k.as_str()).collect();
                    (noms == ["Action", "After", "Condition"])
                        .then(|| (at[0].1.clone(), at[1].1.clone(), at[2].1.clone()))
                });
                match (n.as_str(), vide, triple) {
                    ("Custom", true, Some(t)) => lues.push(t),
                    _ => ecarts.push(format!(
                        "sequence: balise hors de la grammaire (Custom Action After Condition): <{n} {a}>"
                    )),
                }
            }
            let attendues: Vec<(String, String, String)> = SEQUENCE
                .iter()
                .map(|(a, b, c)| (a.to_string(), b.to_string(), c.to_string()))
                .collect();
            for (i, (lue, attendue)) in lues.iter().zip(&attendues).enumerate() {
                if lue != attendue {
                    ecarts.push(format!(
                        "sequence, action {}: {} lue {lue:?}, attendue {attendue:?}",
                        i + 1,
                        attendue.0
                    ));
                }
            }
            if lues.len() != attendues.len() {
                ecarts.push(format!(
                    "sequence: {} action(s) lue(s), {} attendue(s)",
                    lues.len(),
                    attendues.len()
                ));
            }
        }
        _ => ecarts.push("InstallExecuteSequence introuvable".to_string()),
    }
    let rollback = element(&xml, "CustomAction", "BifrostServiceRollback").unwrap_or_default();
    let attendu_rollback = paires(&[
        ("Id", "BifrostServiceRollback"),
        ("FileRef", "bifrostdaemon.exe"),
        ("ExeCommand", "--uninstall-service"),
        ("Execute", "rollback"),
        ("Impersonate", "no"),
        ("Return", "ignore"),
    ]);
    if attributs_tries(&rollback) != Ok(attendu_rollback) {
        ecarts.push(format!(
            "CustomAction BifrostServiceRollback: {:?}, attendu une action de retour arriere qui lance --uninstall-service, et rien de plus",
            attributs_stricts(&rollback)
        ));
    }

    // 13. Le script n'invoque le daemon que pour l'installer (mise a jour en
    // place), et jamais --uninstall-service avant.
    let lignes = lignes_ps(script);
    let invocations: Vec<&String> = lignes.iter().filter(|l| l.contains("& $Daemon")).collect();
    if invocations != ["& $Daemon @arguments"] {
        ecarts.push(format!(
            "{SCRIPT}: invocations du daemon {invocations:?}, attendu la seule `& $Daemon @arguments`"
        ));
    }
    for l in &lignes {
        let mut code = String::new();
        let mut guillemet: Option<char> = None;
        for c in l.chars() {
            match guillemet {
                Some(q) if c == q => guillemet = None,
                Some(_) => {}
                None if c == '\'' || c == '"' => guillemet = Some(c),
                None => code.push(c),
            }
        }
        if code.contains("--uninstall-service") {
            ecarts.push(format!(
                "{SCRIPT} retire le service avant de reinstaller: `{l}`"
            ));
        }
    }
    ecarts
}

#[test]
fn la_meme_version_est_une_mise_a_niveau_qui_garde_le_service() {
    let ecarts = ecarts_de_la_mise_a_niveau(&lire(WXS), &lire(SCRIPT));
    assert!(
        ecarts.is_empty(),
        "{} ecart(s):\n  {}",
        ecarts.len(),
        ecarts.join("\n  ")
    );
}

// Seul `decouper` sert ici; les lectures par position servent aux voisines.
#[allow(dead_code)]
#[path = "commun/lexeur_rust.rs"]
mod lexeur_rust;

/// Le source sans ses commentaires ni ses litteraux, remplaces par des
/// espaces (meme lecture que `paquets_linux.rs`): les positions restent
/// celles du source.
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

fn est_ident(o: u8) -> bool {
    o == b'_' || o.is_ascii_alphanumeric()
}

/// Le corps `[accolade ouvrante, accolade fermante]` de la fonction `nom`,
/// definie exactement une fois dans `code`.
fn corps_de_fonction(code: &str, nom: &str) -> Result<(usize, usize), String> {
    let motif = format!("fn {nom}(");
    let positions: Vec<usize> = code
        .match_indices(&motif)
        .map(|(p, _)| p)
        .filter(|&p| p == 0 || !est_ident(code.as_bytes()[p - 1]))
        .collect();
    let [p] = positions.as_slice() else {
        return Err(format!("fn {nom}: {} definition(s)", positions.len()));
    };
    let ouvrante = code[*p..]
        .find('{')
        .ok_or_else(|| format!("fn {nom} sans corps"))?
        + p;
    let mut profondeur = 0usize;
    for (k, c) in code[ouvrante..].char_indices() {
        match c {
            '{' => profondeur += 1,
            '}' => {
                profondeur -= 1;
                if profondeur == 0 {
                    return Ok((ouvrante, ouvrante + k));
                }
            }
            _ => {}
        }
    }
    Err(format!("fn {nom}: corps non ferme"))
}

/// Chaque appel de `nom(...)` dans `code` (pas sa definition): position, et
/// arguments separes aux virgules de premier niveau, blancs retires.
fn appels(code: &str, nom: &str) -> Vec<(usize, Vec<String>)> {
    let motif = format!("{nom}(");
    let mut sortie = Vec::new();
    for (p, _) in code.match_indices(&motif) {
        if p > 0 && est_ident(code.as_bytes()[p - 1]) {
            continue;
        }
        if code[..p].trim_end().ends_with("fn") {
            continue;
        }
        let mut args = Vec::new();
        let mut courant = String::new();
        let mut profondeur = 0usize;
        for c in code[p + motif.len()..].chars() {
            match c {
                '(' | '[' | '{' => {
                    profondeur += 1;
                    courant.push(c);
                }
                ')' | ']' | '}' if profondeur > 0 => {
                    profondeur -= 1;
                    courant.push(c);
                }
                ')' => break,
                ',' if profondeur == 0 => args.push(std::mem::take(&mut courant)),
                _ => courant.push(c),
            }
        }
        args.push(courant);
        let args: Vec<String> = args
            .into_iter()
            .map(|a| a.split_whitespace().collect::<Vec<_>>().join(" "))
            .filter(|a| !a.is_empty())
            .collect();
        sortie.push((p, args));
    }
    sortie
}

fn ecarts_du_service_en_place(scm: &str) -> Vec<String> {
    let code = match code_seul(scm) {
        Ok(c) => c,
        Err(e) => return vec![format!("{SCM} illisible: {e}")],
    };
    let (install, maj, retrait) = match (
        corps_de_fonction(&code, "install"),
        corps_de_fonction(&code, "mettre_a_jour"),
        corps_de_fonction(&code, "uninstall"),
    ) {
        (Ok(a), Ok(b), Ok(c)) => (a, b, c),
        autre => return vec![format!("{SCM}: {autre:?}")],
    };
    let dans = |p: usize, (a, b): (usize, usize)| a < p && p < b;
    let mut ecarts = Vec::new();
    match appels(&code, "ChangeServiceConfigW").as_slice() {
        [(p, args)] => {
            if !dans(*p, maj) {
                ecarts.push("ChangeServiceConfigW appele hors de mettre_a_jour".to_string());
            }
            if args.len() != 11 {
                ecarts.push(format!(
                    "ChangeServiceConfigW: {} argument(s): {args:?}",
                    args.len()
                ));
            } else {
                if args[1] != "SERVICE_WIN32_OWN_PROCESS" {
                    ecarts.push(format!(
                        "ChangeServiceConfigW: type de service {:?}",
                        args[1]
                    ));
                }
                if args[2] != "SERVICE_NO_CHANGE" {
                    ecarts.push(format!(
                        "ChangeServiceConfigW: type de demarrage {:?} au lieu de SERVICE_NO_CHANGE",
                        args[2]
                    ));
                }
                if args[4].contains("null") {
                    ecarts.push(format!(
                        "ChangeServiceConfigW ne reecrit pas la ligne: {:?}",
                        args[4]
                    ));
                }
            }
        }
        autre => ecarts.push(format!(
            "{} appel(s) de ChangeServiceConfigW au lieu d'un",
            autre.len()
        )),
    }
    match appels(&code, "CreateServiceW").as_slice() {
        [(p, args)] if dans(*p, install) && args.len() == 13 => {
            if args[5] != "code_demarrage(s.demarrage)" {
                ecarts.push(format!(
                    "CreateServiceW: demarrage {:?} au lieu de celui de la specification",
                    args[5]
                ));
            }
        }
        autre => ecarts.push(format!(
            "CreateServiceW: {autre:?}, attendu un appel dans install"
        )),
    }
    let corps_install = &code[install.0..install.1];
    if appels(corps_install, "mettre_a_jour").len() != 1
        || !corps_install.contains("ERROR_SERVICE_EXISTS")
    {
        ecarts.push(
            "install ne mene pas un service existant (ERROR_SERVICE_EXISTS) a mettre_a_jour"
                .to_string(),
        );
    }
    for (p, _) in appels(&code, "DeleteService") {
        if !dans(p, retrait) {
            ecarts.push(format!(
                "DeleteService appele hors de uninstall (octet {p})"
            ));
        }
    }
    ecarts
}

#[test]
fn le_daemon_met_a_jour_un_service_existant_sans_toucher_au_demarrage() {
    let ecarts = ecarts_du_service_en_place(&lire(SCM));
    assert!(
        ecarts.is_empty(),
        "{} ecart(s):\n  {}",
        ecarts.len(),
        ecarts.join("\n  ")
    );
}

/// Chaque exigence de la mise a niveau mord sur une mutation du texte reel.
#[test]
fn chaque_exigence_de_la_mise_a_niveau_mord() {
    let wxs = lire(WXS);
    let script = lire(SCRIPT);
    let scm = lire(SCM);
    assert!(ecarts_de_la_mise_a_niveau(&wxs, &script).is_empty());
    assert!(ecarts_du_service_en_place(&scm).is_empty());
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
    for (avant, apres, motif) in [
        (
            "AllowSameVersionUpgrades=\"yes\" ",
            "",
            "MajorUpgrade sans AllowSameVersionUpgrades",
        ),
        (
            "AllowSameVersionUpgrades=\"yes\" Schedule=\"afterInstallInitialize\"",
            "AllowSameVersionUpgrades=\"yes\" Schedule=\"afterInstallValidate\"",
            "hors de la grammaire",
        ),
        (
            "<MajorUpgrade ",
            "<MajorUpgrade AllowDowngrades=\"yes\" ",
            "hors de la grammaire",
        ),
        (
            "Condition=\"NOT Installed AND NOT BIFROSTSERVICEEXISTANT\"",
            "Condition=\"NOT Installed\"",
            "BifrostServiceRollback lue",
        ),
        (
            "After=\"BifrostCleanupFirewall\" Condition=\"REMOVE=&quot;ALL&quot; AND NOT UPGRADINGPRODUCTCODE\"",
            "After=\"BifrostCleanupFirewall\" Condition=\"REMOVE=&quot;ALL&quot;\"",
            "BifrostServiceUninstall lue",
        ),
        (
            "<Property Id=\"BIFROSTSERVICEEXISTANT\" Secure=\"yes\">",
            "<Property Id=\"BIFROSTSERVICEEXISTANT\">",
            "Property BIFROSTSERVICEEXISTANT",
        ),
        (
            "Services\\BifrostDaemon\"",
            "Services\\BFE\"",
            "RegistrySearch de BIFROSTSERVICEEXISTANT",
        ),
        (
            "      <Custom Action=\"BifrostServiceInstall\" ",
            "      <Custom Action=\"BifrostServiceRollback\" After=\"InstallFiles\" Condition=\"1\" />\n      <Custom Action=\"BifrostServiceInstall\" ",
            "sequence",
        ),
        (
            "Execute=\"rollback\"",
            "Execute=\"deferred\"",
            "CustomAction BifrostServiceRollback",
        ),
    ] {
        mord(
            ecarts_de_la_mise_a_niveau(&remplacer(&wxs, avant, apres), &script),
            motif,
        );
    }
    mord(
        ecarts_de_la_mise_a_niveau(
            &wxs,
            &remplacer(
                &script,
                "$arguments = @('--install-service')",
                "& $Daemon --uninstall-service | Out-Null\n$arguments = @('--install-service')",
            ),
        ),
        "retire le service avant de reinstaller",
    );
    for (avant, apres, motif) in [
        (
            "            SERVICE_NO_CHANGE,\n            SERVICE_ERROR_NORMAL,",
            "            code_demarrage(s.demarrage),\n            SERVICE_ERROR_NORMAL,",
            "au lieu de SERVICE_NO_CHANGE",
        ),
        (
            "let service = mettre_a_jour(&scm, &s, &nom, &affiche, &ligne_w)?;",
            "let service: Poignee = bail!(\"le service existe deja\");",
            "a mettre_a_jour",
        ),
        (
            "    let service = Poignee(h);\n    // Une liste vide",
            "    let service = Poignee(h);\n    unsafe { DeleteService(service.0) };\n    // Une liste vide",
            "DeleteService appele hors de uninstall",
        ),
    ] {
        mord(
            ecarts_du_service_en_place(&remplacer(&scm, avant, apres)),
            motif,
        );
    }
    // La grammaire stricte des attributs refuse ce qu'elle ne sait pas lire.
    assert!(attributs_stricts("Id='x'").is_err());
    assert!(attributs_stricts("Id=\"x\" Id=\"y\"").is_err());
    assert!(attributs_stricts("Secure").is_err());
    assert_eq!(
        attributs_stricts(" Id=\"a&quot;b\"\n  Secure=\"yes\" "),
        Ok(paires(&[("Id", "a\"b"), ("Secure", "yes")]))
    );
}

// ================================================ le MSI de la coquille

const WXS_GUI: &str = "packaging/msi/bifrost-gui.wxs";

/// Un composant: (Id, Directory, balises de ses enfants, chacune avec ses
/// attributs).
type Composant = (String, String, Vec<(String, String)>);

/// Les composants d'un XML, dans l'ordre du texte.
fn composants(xml: &str) -> Vec<Composant> {
    let mut sortie = Vec::new();
    let mut courant: Option<Composant> = None;
    for (nom, attributs, vide) in balises(xml) {
        match nom.as_str() {
            "Component" => {
                let c = (
                    attribut(&attributs, "Id").unwrap_or_default(),
                    attribut(&attributs, "Directory").unwrap_or_default(),
                    Vec::new(),
                );
                if vide {
                    sortie.push(c);
                } else {
                    courant = Some(c);
                }
            }
            "/Component" => {
                if let Some(c) = courant.take() {
                    sortie.push(c);
                }
            }
            _ => {
                if let Some((_, _, enfants)) = courant.as_mut() {
                    enfants.push((nom, attributs));
                }
            }
        }
    }
    sortie
}

/// Un identifiant WiX: lettres ASCII, chiffres, souligne et point, une lettre
/// ou un souligne en tete. Le tiret rend WIX0014.
fn identifiant_wix_legal(id: &str) -> bool {
    let mut c = id.chars();
    c.next()
        .is_some_and(|p| p.is_ascii_alphabetic() || p == '_')
        && c.all(|x| x.is_ascii_alphanumeric() || x == '_' || x == '.')
}

fn ecarts_du_msi_de_la_coquille(gui: &str, daemon: &str) -> Vec<String> {
    let mut ecarts = Vec::new();
    let xml = sans_commentaires_xml(gui);
    let xml_daemon = sans_commentaires_xml(daemon);
    let package = |x: &str| -> String {
        balises(x)
            .into_iter()
            .find(|(n, _, _)| n == "Package")
            .map(|(_, a, _)| a)
            .unwrap_or_default()
    };
    let (p, pd) = (package(&xml), package(&xml_daemon));

    // 7. Un paquet distinct, dans le meme dossier.
    for (nom, attendu) in [
        ("Name", "Bifrost GUI"),
        ("Manufacturer", "Bifrost"),
        ("Version", "$(var.Version)"),
        ("Scope", "perMachine"),
    ] {
        if attribut(&p, nom).as_deref() != Some(attendu) {
            ecarts.push(format!(
                "Package {nom} de la coquille: {:?} au lieu de {attendu}",
                attribut(&p, nom)
            ));
        }
    }
    if attribut(&p, "Name") == attribut(&pd, "Name") {
        ecarts.push("les deux MSI portent le meme nom".to_string());
    }
    let upgrade = attribut(&p, "UpgradeCode").unwrap_or_default();
    let upgrade_daemon = attribut(&pd, "UpgradeCode").unwrap_or_default();
    if upgrade.len() != 36 || !upgrade.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-') {
        ecarts.push(format!("UpgradeCode de la coquille illisible: {upgrade:?}"));
    }
    if upgrade.eq_ignore_ascii_case(&upgrade_daemon) {
        ecarts.push(format!(
            "le MSI de la coquille reprend l'UpgradeCode du daemon ({upgrade}): chacun retirerait l'autre"
        ));
    }
    if !balises(&xml).iter().any(|(n, _, _)| n == "MajorUpgrade") {
        ecarts.push("aucun MajorUpgrade dans le MSI de la coquille".to_string());
    }
    let dossier = repertoires_du_msi(&xml).get("INSTALLFOLDER").cloned();
    let dossier_daemon = repertoires_du_msi(&xml_daemon)
        .get("INSTALLFOLDER")
        .cloned();
    if dossier.is_none() || dossier != dossier_daemon {
        ecarts.push(format!(
            "dossier d'installation de la coquille {dossier:?}, du daemon {dossier_daemon:?}"
        ));
    }
    let fichiers: Vec<String> = balises(&xml)
        .into_iter()
        .filter(|(n, _, _)| n == "File")
        .filter_map(|(_, a, _)| attribut(&a, "Source"))
        .collect();
    if fichiers != ["$(var.Binaires)\\bifrost-gui.exe"] {
        ecarts.push(format!(
            "le MSI de la coquille pose {fichiers:?}, pas le seul bifrost-gui.exe"
        ));
    }
    let ids_daemon: Vec<String> = composants(&xml_daemon).into_iter().map(|c| c.0).collect();
    let comps = composants(&xml);
    for (id, _, _) in &comps {
        if ids_daemon.contains(id) {
            ecarts.push(format!("composant {id} dans les deux MSI"));
        }
    }

    // 8. Rien d'autre que le fichier et le raccourci.
    for (nom, attributs, _) in balises(&xml) {
        if matches!(
            nom.as_str(),
            "CustomAction" | "SetProperty" | "Custom" | "ServiceInstall" | "ServiceControl"
        ) {
            ecarts.push(format!("le MSI de la coquille porte un {nom}: {attributs}"));
        }
        let id = attribut(&attributs, "Id").unwrap_or_default();
        if nom == "StandardDirectory"
            && matches!(
                id.as_str(),
                "CommonAppDataFolder" | "StartupFolder" | "DesktopFolder"
            )
        {
            ecarts.push(format!("le MSI de la coquille pose sous {id}"));
        }
        if matches!(nom.as_str(), "RegistryValue" | "RegistryKey")
            && attribut(&attributs, "Key")
                .unwrap_or_default()
                .to_ascii_lowercase()
                .contains("currentversion\\run")
        {
            ecarts.push(format!(
                "le MSI de la coquille ecrit une valeur de demarrage automatique: {attributs}"
            ));
        }
    }
    let raccourcis: Vec<(&String, &String, &(String, String))> = comps
        .iter()
        .flat_map(|(id, rep, enfants)| {
            enfants
                .iter()
                .filter(|(n, _)| n == "Shortcut")
                .map(move |e| (id, rep, e))
        })
        .collect();
    match raccourcis.as_slice() {
        [(id, rep, (_, a))] => {
            let repertoire = attribut(a, "Directory").unwrap_or_else(|| (*rep).clone());
            if repertoire != "ProgramMenuFolder" {
                ecarts.push(format!(
                    "raccourci dans {repertoire}, pas a la racine du Menu Demarrer"
                ));
            }
            if attribut(a, "Advertise").as_deref() != Some("no")
                || attribut(a, "Target").as_deref() != Some("[INSTALLFOLDER]bifrost-gui.exe")
            {
                ecarts.push(format!(
                    "raccourci annonce ou vers autre chose que bifrost-gui.exe: {a}"
                ));
            }
            let (_, _, enfants) = comps
                .iter()
                .find(|(i, _, _)| i == *id)
                .expect("le composant du raccourci");
            let fichier = enfants.iter().any(|(n, _)| n == "File");
            let cle_hkcu = enfants.iter().any(|(n, a)| {
                n == "RegistryValue"
                    && attribut(a, "Root").as_deref() == Some("HKCU")
                    && attribut(a, "KeyPath").as_deref() == Some("yes")
            });
            if fichier || !cle_hkcu {
                ecarts.push(format!(
                    "le composant {id} du raccourci porte un fichier ou pas de KeyPath HKCU (ICE43, ICE57)"
                ));
            }
        }
        autre => ecarts.push(format!(
            "{} raccourci(s) dans le MSI de la coquille, attendu un",
            autre.len()
        )),
    }
    let condition = balises(&xml)
        .into_iter()
        .find(|(n, _, _)| n == "Launch")
        .and_then(|(_, a, _)| attribut(&a, "Condition"))
        .unwrap_or_default();
    if !condition.starts_with("Installed OR ")
        || !condition.contains("WEBVIEW2HKLM")
        || !condition.contains("WEBVIEW2HKCU")
    {
        ecarts.push(format!("condition de lancement: {condition:?}"));
    }
    let depot = lire("Cargo.toml")
        .lines()
        .find_map(|l| l.strip_prefix("repository = \""))
        .map(|v| v.trim_end_matches('"').to_string())
        .unwrap_or_default();
    let page = element(&xml, "Property", "ARPURLINFOABOUT").and_then(|a| attribut(&a, "Value"));
    if depot.is_empty() || page.as_deref() != Some(depot.as_str()) {
        ecarts.push(format!("ARPURLINFOABOUT {page:?}, depot {depot:?}"));
    }
    for (source, x) in [(WXS_GUI, &xml), (WXS, &xml_daemon)] {
        for (nom, attributs, _) in balises(x) {
            if let Some(id) = attribut(&attributs, "Id")
                && !nom.starts_with('/')
                && !identifiant_wix_legal(&id)
            {
                ecarts.push(format!("{source}: identifiant WiX illegal {nom} Id={id:?}"));
            }
        }
    }
    ecarts
}

#[test]
fn le_msi_de_la_coquille_est_distinct_et_ne_pose_que_la_coquille() {
    let mut ecarts = ecarts_du_msi_de_la_coquille(&lire(WXS_GUI), &lire(WXS));
    let version = lire("Cargo.toml")
        .lines()
        .find_map(|l| l.strip_prefix("version = \""))
        .map(|v| v.trim_end_matches('"').to_string())
        .unwrap_or_default();
    if version.is_empty() || lire(WXS_GUI).contains(&format!("\"{version}\"")) {
        ecarts.push(format!(
            "{WXS_GUI} ecrit la version du workspace ({version}) en dur"
        ));
    }
    assert!(
        ecarts.is_empty(),
        "{} ecart(s):\n  {}",
        ecarts.len(),
        ecarts.join("\n  ")
    );
}

/// Chaque exigence du MSI de la coquille mord sur une mutation du texte reel.
#[test]
fn chaque_exigence_du_msi_de_la_coquille_mord() {
    let gui = lire(WXS_GUI);
    let daemon = lire(WXS);
    assert!(ecarts_du_msi_de_la_coquille(&gui, &daemon).is_empty());
    let upgrade_daemon = attribut(
        &balises(&sans_commentaires_xml(&daemon))
            .into_iter()
            .find(|(n, _, _)| n == "Package")
            .map(|(_, a, _)| a)
            .unwrap_or_default(),
        "UpgradeCode",
    )
    .expect("UpgradeCode du daemon");
    let upgrade_gui = attribut(
        &balises(&sans_commentaires_xml(&gui))
            .into_iter()
            .find(|(n, _, _)| n == "Package")
            .map(|(_, a, _)| a)
            .unwrap_or_default(),
        "UpgradeCode",
    )
    .expect("UpgradeCode de la coquille");
    let remplacer = |texte: &str, avant: &str, apres: &str| -> String {
        assert_eq!(
            texte.matches(avant).count(),
            1,
            "`{avant}` doit etre unique"
        );
        texte.replacen(avant, apres, 1)
    };
    let mord = |gui: &str, motif: &str| {
        let e = ecarts_du_msi_de_la_coquille(gui, &daemon);
        assert!(
            e.iter().any(|x| x.contains(motif)),
            "`{motif}` attendu dans {e:?}"
        );
    };
    let raccourci_marqueur = "      <RegistryValue Root=\"HKCU\" Key=\"Software\\Bifrost\\GUI\" Name=\"installed\" Type=\"integer\" Value=\"1\" KeyPath=\"yes\" />\n";
    let ancre_upgrade = format!("UpgradeCode=\"{upgrade_gui}\"");
    let mutations: [(&str, String, &str); 9] = [
        (
            &ancre_upgrade,
            format!("UpgradeCode=\"{upgrade_daemon}\""),
            "reprend l'UpgradeCode du daemon",
        ),
        (
            raccourci_marqueur,
            format!(
                "{raccourci_marqueur}      <RegistryValue Root=\"HKLM\" Key=\"Software\\Microsoft\\Windows\\CurrentVersion\\Run\" Name=\"Bifrost\" Type=\"string\" Value=\"[INSTALLFOLDER]bifrost-gui.exe\" />\n"
            ),
            "valeur de demarrage automatique",
        ),
        (
            "    <StandardDirectory Id=\"ProgramMenuFolder\" />\n",
            "    <StandardDirectory Id=\"ProgramMenuFolder\" />\n    <StandardDirectory Id=\"StartupFolder\" />\n".to_string(),
            "pose sous StartupFolder",
        ),
        (
            "<Directory Id=\"INSTALLFOLDER\" Name=\"Bifrost\" />",
            "<Directory Id=\"INSTALLFOLDER\" Name=\"Bifrost GUI\" />".to_string(),
            "dossier d'installation de la coquille",
        ),
        (
            "      <File Id=\"bifrostgui.exe\" Source=\"$(var.Binaires)\\bifrost-gui.exe\" KeyPath=\"yes\" />\n",
            "      <File Id=\"bifrostgui.exe\" Source=\"$(var.Binaires)\\bifrost-gui.exe\" KeyPath=\"yes\" />\n      <File Id=\"bifrostcli.exe\" Source=\"$(var.Binaires)\\bifrost-cli.exe\" />\n".to_string(),
            "pas le seul bifrost-gui.exe",
        ),
        (
            raccourci_marqueur,
            format!(
                "{raccourci_marqueur}      <File Id=\"bifrostgui2.exe\" Source=\"$(var.Binaires)\\bifrost-gui.exe\" />\n"
            ),
            "ICE43, ICE57",
        ),
        (
            "<Component Id=\"GuiExe\"",
            "<Component Id=\"DaemonExe\"".to_string(),
            "composant DaemonExe dans les deux MSI",
        ),
        (
            "<Launch Condition=\"Installed OR (",
            "<Launch Condition=\"(".to_string(),
            "condition de lancement",
        ),
        (
            "<Icon Id=\"bifrostgui.ico\"",
            "<Icon Id=\"bifrost-gui.ico\"".to_string(),
            "identifiant WiX illegal",
        ),
    ];
    for (avant, apres, motif) in &mutations {
        mord(&remplacer(&gui, avant, apres), motif);
    }
    // Une action personnalisee ajoutee.
    mord(
        &remplacer(
            &gui,
            "    <Feature Id=\"Principal\"",
            "    <CustomAction Id=\"Lancer\" FileRef=\"bifrostgui.exe\" ExeCommand=\"\" Execute=\"immediate\" Return=\"asyncNoWait\" />\n    <Feature Id=\"Principal\"",
        ),
        "porte un CustomAction",
    );
    assert!(identifiant_wix_legal("bifrostgui.exe"));
    assert!(!identifiant_wix_legal("bifrost-gui.exe"));
}

/// Exigence 15: le `MajorUpgrade` de la coquille, dans la grammaire de celui
/// du daemon.
fn ecarts_de_la_mise_a_niveau_de_la_coquille(gui: &str) -> Vec<String> {
    ecarts_du_major_upgrade(&balises(&sans_commentaires_xml(gui)))
        .into_iter()
        .map(|e| format!("{WXS_GUI}: {e}"))
        .collect()
}

#[test]
fn la_meme_version_de_la_coquille_est_une_mise_a_niveau() {
    let ecarts = ecarts_de_la_mise_a_niveau_de_la_coquille(&lire(WXS_GUI));
    assert!(
        ecarts.is_empty(),
        "{} ecart(s):\n  {}",
        ecarts.len(),
        ecarts.join("\n  ")
    );
}

/// Chaque exigence de la mise a niveau de la coquille mord sur une mutation
/// du texte reel.
#[test]
fn chaque_exigence_de_la_mise_a_niveau_de_la_coquille_mord() {
    let gui = lire(WXS_GUI);
    assert!(ecarts_de_la_mise_a_niveau_de_la_coquille(&gui).is_empty());
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
    let element =
        "<MajorUpgrade AllowSameVersionUpgrades=\"yes\" Schedule=\"afterInstallInitialize\"";
    for (avant, apres, motif) in [
        // Le MajorUpgrade de la base: ni l'un ni l'autre attribut.
        (
            element,
            "<MajorUpgrade",
            "MajorUpgrade sans AllowSameVersionUpgrades",
        ),
        (element, "<MajorUpgrade", "MajorUpgrade sans Schedule"),
        (
            element,
            "<MajorUpgrade Schedule=\"afterInstallInitialize\"",
            "MajorUpgrade sans AllowSameVersionUpgrades",
        ),
        (
            element,
            "<MajorUpgrade AllowSameVersionUpgrades=\"yes\"",
            "MajorUpgrade sans Schedule",
        ),
        (
            element,
            "<MajorUpgrade AllowSameVersionUpgrades=\"yes\" Schedule=\"afterInstallValidate\"",
            "hors de la grammaire",
        ),
        (
            element,
            "<MajorUpgrade AllowSameVersionUpgrades=\"no\" Schedule=\"afterInstallInitialize\"",
            "hors de la grammaire",
        ),
        (
            element,
            "<MajorUpgrade AllowDowngrades=\"yes\" AllowSameVersionUpgrades=\"yes\" Schedule=\"afterInstallInitialize\"",
            "hors de la grammaire",
        ),
        (
            element,
            "<MajorUpgrade AllowSameVersionUpgrades='yes' Schedule=\"afterInstallInitialize\"",
            "MajorUpgrade illisible",
        ),
        (
            "DowngradeErrorMessage=\"Une version plus recente de Bifrost GUI est deja installee.\"",
            "DowngradeErrorMessage=\" \"",
            "hors de la grammaire",
        ),
        (
            "    <MediaTemplate ",
            "    <MajorUpgrade AllowSameVersionUpgrades=\"yes\" Schedule=\"afterInstallInitialize\" DowngradeErrorMessage=\"x\" />\n    <MediaTemplate ",
            "2 element(s) MajorUpgrade",
        ),
        (element, "<!-- <MajorUpgrade", "0 element(s) MajorUpgrade"),
    ] {
        let texte = if apres.starts_with("<!--") {
            // L'element entier mis en commentaire: il ne compte plus.
            remplacer(
                &remplacer(&gui, avant, apres),
                " installee.\" />",
                " installee.\" /> -->",
            )
        } else {
            remplacer(&gui, avant, apres)
        };
        mord(ecarts_de_la_mise_a_niveau_de_la_coquille(&texte), motif);
    }
}

// ================================================ l'editeur du logiciel

const CONF_TAURI: &str = "gui/tauri.conf.json";
const CONSTRUCTEUR_MSI_GUI: &str = "scripts/paquets-gui-windows.ps1";

/// L'editeur du logiciel (decision du 18/10/2026): le fabricant des deux MSI
/// et l'editeur de l'executable de la coquille.
const EDITEUR: &str = "Bifrost";

/// Les formes du script qui disent l'editeur, a blancs ecrases, chacune
/// exactement une fois: la lecture dans la configuration, le refus si elle
/// manque, l'exigence sur l'executable (suivie de son Refus), et l'exigence sur
/// le MSI.
const FORMES_EDITEUR: [&str; 4] = [
    "$Editeur = $conf.bundle.publisher",
    "if (-not $Editeur) { Refus ",
    "if ($vi.CompanyName -cne $Editeur) {",
    "'Manufacturer' = $Editeur",
];

fn ecarts_de_l_editeur(conf: &str, gui: &str, daemon: &str, constructeur: &str) -> Vec<String> {
    let mut ecarts = Vec::new();
    match serde_json::from_str::<serde_json::Value>(conf) {
        Ok(v) => match v.get("bundle").and_then(|b| b.get("publisher")) {
            Some(serde_json::Value::String(s)) if s == EDITEUR => {}
            autre => ecarts.push(format!(
                "{CONF_TAURI}: bundle.publisher {autre:?}, attendu \"{EDITEUR}\" (absent, \
                 tauri-build ecrit dans CompanyName le deuxieme element de l'identifiant)"
            )),
        },
        Err(e) => ecarts.push(format!("{CONF_TAURI} illisible: {e}")),
    }
    for (nom, xml) in [(WXS_GUI, gui), (WXS, daemon)] {
        let fabricants: Vec<Option<String>> = balises(&sans_commentaires_xml(xml))
            .into_iter()
            .filter(|(n, _, _)| n == "Package")
            .map(|(_, a, _)| attribut(&a, "Manufacturer"))
            .collect();
        if fabricants != [Some(EDITEUR.to_string())] {
            ecarts.push(format!(
                "{nom}: Manufacturer du Package {fabricants:?}, attendu [\"{EDITEUR}\"]"
            ));
        }
    }
    // Grammaire fermee: chaque ligne active qui nomme $Editeur, CompanyName ou
    // Manufacturer est l'une des formes, ou un message (Ok, Fail, Refus).
    let lignes: Vec<String> = lignes_ps(constructeur)
        .iter()
        .map(|l| l.split_whitespace().collect::<Vec<_>>().join(" "))
        .collect();
    let mut vues = [0usize; 4];
    for (i, l) in lignes.iter().enumerate() {
        if !(l.contains("Editeur") || l.contains("CompanyName") || l.contains("Manufacturer")) {
            continue;
        }
        if l == FORMES_EDITEUR[0] {
            vues[0] += 1;
        } else if l.starts_with(FORMES_EDITEUR[1]) && l.ends_with('}') {
            vues[1] += 1;
        } else if l == FORMES_EDITEUR[2] {
            vues[2] += 1;
            if !lignes.get(i + 1).is_some_and(|s| s.starts_with("Refus ")) {
                ecarts.push(format!(
                    "{CONSTRUCTEUR_MSI_GUI}: `{l}` sans Refus a la ligne suivante"
                ));
            }
        } else if l == FORMES_EDITEUR[3] {
            vues[3] += 1;
        } else if !(l.starts_with("Ok \"") || l.starts_with("Fail \"") || l.starts_with("Refus \""))
        {
            ecarts.push(format!(
                "{CONSTRUCTEUR_MSI_GUI}: ligne non reconnue qui dit l'editeur: `{l}`"
            ));
        }
    }
    for (n, forme) in vues.iter().zip(FORMES_EDITEUR) {
        if *n != 1 {
            ecarts.push(format!(
                "{CONSTRUCTEUR_MSI_GUI}: `{forme}` {n} fois au lieu d'une"
            ));
        }
    }
    ecarts
}

#[test]
fn l_editeur_a_une_seule_source() {
    let ecarts = ecarts_de_l_editeur(
        &lire(CONF_TAURI),
        &lire(WXS_GUI),
        &lire(WXS),
        &lire(CONSTRUCTEUR_MSI_GUI),
    );
    assert!(
        ecarts.is_empty(),
        "{} ecart(s):\n  {}",
        ecarts.len(),
        ecarts.join("\n  ")
    );
}

/// Chaque exigence sur l'editeur mord sur une mutation du texte reel.
#[test]
fn chaque_exigence_de_l_editeur_mord() {
    let conf = lire(CONF_TAURI);
    let gui = lire(WXS_GUI);
    let daemon = lire(WXS);
    let script = lire(CONSTRUCTEUR_MSI_GUI);
    assert!(ecarts_de_l_editeur(&conf, &gui, &daemon, &script).is_empty());
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
    let publisher = "\"publisher\": \"Bifrost\"";
    let c = remplacer(&conf, publisher, "\"publisher\": \"Musyg\"");
    mord(
        ecarts_de_l_editeur(&c, &gui, &daemon, &script),
        "bundle.publisher",
    );
    let c = remplacer(&conf, &format!("{publisher},"), "");
    mord(
        ecarts_de_l_editeur(&c, &gui, &daemon, &script),
        "bundle.publisher None",
    );
    // L'attribut du Package, en fin de ligne (un commentaire du .wxs de la
    // coquille le cite aussi, suivi d'une virgule).
    let fabricant = "Manufacturer=\"Bifrost\"\n";
    let g = remplacer(&gui, fabricant, "Manufacturer=\"Inaricom\"\n");
    mord(ecarts_de_l_editeur(&conf, &g, &daemon, &script), WXS_GUI);
    let d = remplacer(&daemon, fabricant, "Manufacturer=\"Inaricom\"\n");
    mord(ecarts_de_l_editeur(&conf, &gui, &d, &script), WXS);
    for (avant, apres, motif) in [
        (
            "$Editeur = $conf.bundle.publisher",
            "$Editeur = 'Bifrost'",
            "ligne non reconnue",
        ),
        (
            "if ($vi.CompanyName -cne $Editeur) {",
            "if ($false) {",
            "0 fois au lieu d'une",
        ),
        (
            "'Manufacturer'    = $Editeur",
            "'Manufacturer'    = 'Bifrost'",
            "ligne non reconnue",
        ),
    ] {
        let s = remplacer(&script, avant, apres);
        mord(ecarts_de_l_editeur(&conf, &gui, &daemon, &s), motif);
    }
}
