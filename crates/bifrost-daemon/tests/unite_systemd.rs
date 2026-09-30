//! La garde du CYCLE DE VIE de l'unite systemd livree.
//!
//! # Sa jumelle
//!
//! Elle a une jumelle sous Windows: `crates/bifrost-daemon/src/service/spec.rs`,
//! test `l_arret_du_service_ne_rouvre_pas_le_trafic`, qui interdit a l'arret du
//! service Windows de desarmer le kill switch. Cette jumelle-la existait depuis
//! des mois et NOMMAIT `ExecStopPost` dans son propre commentaire, comme si le
//! cote Linux etait deja garde. Il ne l'etait pas: pendant tout ce temps
//! `packaging/systemd/bifrost-daemon.service` portait
//!
//! ```text
//! ExecStopPost=-/usr/bin/bifrost-daemon --cleanup-firewall
//! ```
//!
//! sous un commentaire qui annoncait l'invariant que la ligne cassait. Une
//! garde ecrite pour une plateforme et qui designe l'autre ne garde pas
//! l'autre. Ce fichier est le jumeau qui manquait.
//!
//! # Ce qu'elle mesure, et ce qu'elle ne mesure pas
//!
//! Elle couvre l'arret DEMANDE, celui que systemd orchestre: aucune directive
//! de l'unite ne doit invoquer un desarmement. Elle ne dit rien de la mort du
//! processus - un SIGKILL ne lit pas de fichier d'unite - et ce n'est pas son
//! travail: c'est le vecteur de fuite `daemon-mort` qui mesure celui-la, en
//! tuant un vrai daemon et en comptant les paquets sur l'interface physique.
//!
//! # Pourquoi le critere porte sur TOUTE directive, et pas sur une liste
//!
//! Une garde qui ne connaitrait que `ExecStopPost=` serait contournee par la
//! directive suivante. Le critere retenu est donc: aucune affectation de
//! l'unite, quelle que soit sa cle, ne doit invoquer une commande qui desarme.
//! La liste [`CYCLE_DE_VIE`] ne sert qu'a ecrire un message utile.
//!
//! # La seconde garde: les CAPACITES du service
//!
//! Jusqu'au 30/09/2026 l'unite donnait CAP_SYS_ADMIN au daemon, en bornes et en
//! ambiant, << pour les namespaces reseau que ce meme harnais cree >>. Mesure
//! du meme jour, daemon reel dans des namespaces jetables avec exactement les
//! capacites de l'unite: aucune fonction VPN ne s'en sert, et `check` n'en
//! tirait meme pas une mesure (neuf vecteurs sur dix sautaient, temoin muet).
//! Elle est retiree, le harnais se lance hors du service
//! (`sudo bifrost-daemon --run-checks`), et deux gardes la tiennent dehors:
//!
//! - l'unite, EVALUEE comme systemd l'evalue (plusieurs lignes, inversion
//!   `~`, remise a zero, noms en toute casse ou numeros), ne rend
//!   CAP_SYS_ADMIN ni en bornes ni en ambiant, et aucune ligne `Exec*=` ne se
//!   fait executer avec tous les privileges;
//! - chaque capacite qui reste est justifiee par une ligne de commentaire de
//!   la forme que l'unite emploie depuis son premier durcissement
//!   (`CAP_NET_ADMIN pour ...`), et aucune justification ne survit a sa
//!   capacite.

use std::path::PathBuf;

/// Les mots qui, dans la valeur d'une directive, DESARMENT le pare-feu.
///
/// En minuscules: la comparaison se fait sur la valeur abaissee. Une garde de
/// ce depot a deja ete verte parce que la casse la rendait aveugle a la seule
/// occurrence qu'elle devait voir.
const DESARMEMENTS: [&str; 2] = ["cleanup-firewall", "emergency-disarm"];

/// Les directives que systemd execute sur un chemin d'arret, d'echec ou de
/// redemarrage. Pour le MESSAGE seulement: le critere porte sur toutes.
///
/// `ExecStopPost=` est la premiere de la liste parce que c'est celle qui a
/// reellement casse l'invariant. `ExecStop=` et `ExecReload=` sont ses voisines
/// evidentes; `ExecCondition=`, `ExecStartPre=` et `ExecStartPost=` sont sur le
/// chemin de DEMARRAGE et n'ont pas moins a se tenir, man systemd.service
/// disant qu'un echec de l'une d'elles fait justement executer `ExecStopPost=`;
/// `OnFailure=` et `OnSuccess=` ne portent pas de commande mais un nom d'unite,
/// et une unite ainsi nommee peut desarmer aussi bien qu'une ligne de commande.
const CYCLE_DE_VIE: [&str; 8] = [
    "execstoppost",
    "execstop",
    "execreload",
    "execcondition",
    "execstartpre",
    "execstartpost",
    "onfailure",
    "onsuccess",
];

/// L'unite telle qu'elle est LIVREE, pas une copie d'essai.
fn chemin_de_l_unite() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../packaging/systemd/bifrost-daemon.service")
}

fn unite() -> String {
    let chemin = chemin_de_l_unite();
    std::fs::read_to_string(&chemin)
        .unwrap_or_else(|e| panic!("lecture de {}: {e}", chemin.display()))
}

/// Une affectation du fichier d'unite.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Directive {
    /// Numero de la premiere ligne PHYSIQUE, pour qu'un echec designe l'endroit.
    ligne: usize,
    /// La cle telle qu'ecrite.
    cle: String,
    /// La valeur, continuations jointes.
    valeur: String,
}

impl Directive {
    /// La cle abaissee. systemd, lui, est sensible a la casse et refuserait
    /// `execstoppost=`; la garde ne l'est pas, deliberement. Son travail n'est
    /// pas de valider le fichier pour systemd, c'est de reconnaitre une
    /// INTENTION, y compris ecrite de travers.
    fn cle_abaissee(&self) -> String {
        self.cle.to_ascii_lowercase()
    }

    fn desarme(&self) -> bool {
        let v = self.valeur.to_ascii_lowercase();
        DESARMEMENTS.iter().any(|m| v.contains(m))
    }

    fn est_du_cycle_de_vie(&self) -> bool {
        CYCLE_DE_VIE.contains(&self.cle_abaissee().as_str())
    }
}

/// Decoupe un fichier d'unite en affectations.
///
/// Trois formes valides que la garde doit voir, et qui ont toutes existe dans
/// ce depot ou dans sa documentation:
///
/// - le prefixe `-` de `ExecStopPost=-/usr/bin/...`, qui dit a systemd
///   d'ignorer le code de sortie. Il fait partie de la VALEUR, donc chercher la
///   commande dedans le traverse sans rien y faire;
/// - les espaces autour du `=`;
/// - la continuation par `\` en fin de ligne, dont l'`ExecStart=` de cette
///   unite se sert deja.
///
/// Les commentaires sont OTES, et c'est indispensable ici: l'unite corrigee
/// cite en commentaire la ligne exacte qu'on lui a retiree, pour que personne
/// ne la remette en croyant l'inventer. Une garde qui se contenterait d'un
/// `grep` serait rouge sur ce commentaire, et le seul moyen de la calmer serait
/// d'effacer l'explication. systemd ne connait que le commentaire de ligne
/// ENTIERE, `#` ou `;` en tete: on ne coupe donc jamais au milieu d'une valeur.
fn directives(source: &str) -> Vec<Directive> {
    let mut sorties = Vec::new();
    let mut accumule: Option<(usize, String)> = None;

    for (index, brute) in source.lines().enumerate() {
        let numero = index + 1;
        let taillee = brute.trim();
        if taillee.starts_with('#') || taillee.starts_with(';') {
            continue;
        }
        let (debut, morceau) = match accumule.take() {
            Some((d, deja)) => (d, format!("{deja} {taillee}")),
            None => (numero, taillee.to_owned()),
        };
        if let Some(sans) = morceau.strip_suffix('\\') {
            accumule = Some((debut, sans.trim_end().to_owned()));
            continue;
        }
        if morceau.is_empty() {
            continue;
        }
        let Some((cle, valeur)) = morceau.split_once('=') else {
            // En-tete de section, ou ligne qui n'affecte rien.
            continue;
        };
        sorties.push(Directive {
            ligne: debut,
            cle: cle.trim().to_owned(),
            valeur: valeur.trim().to_owned(),
        });
    }
    // Une continuation jamais close: on la rend telle quelle plutot que de la
    // perdre, sinon un fichier mal termine echapperait a la garde.
    if let Some((debut, morceau)) = accumule
        && let Some((cle, valeur)) = morceau.split_once('=')
    {
        sorties.push(Directive {
            ligne: debut,
            cle: cle.trim().to_owned(),
            valeur: valeur.trim().to_owned(),
        });
    }
    sorties
}

/// La garde elle-meme, sur l'unite LIVREE.
///
/// Si quelqu'un remet `ExecStopPost=-/usr/bin/bifrost-daemon --cleanup-firewall`
/// dans six mois, c'est ce test qui doit l'arreter. Le retrait du kill switch
/// est une commande qu'on tape - `bifrost-cli disconnect`, ou
/// `bifrost-cli emergency-disarm --je-sais-ce-que-je-fais` - jamais un effet de
/// bord de la fin d'un processus.
#[test]
fn l_arret_de_l_unite_ne_rouvre_pas_le_trafic() {
    let source = unite();
    let toutes = directives(&source);

    // D'abord: la garde REGARDE quelque chose. Un fichier deplace, vide ou lu
    // au mauvais endroit rendrait zero directive, donc zero coupable, donc un
    // vert qui ne mesure rien. Ce depot a deja paye ce piege-la.
    assert!(
        toutes.iter().any(|d| d.cle_abaissee() == "execstart"),
        "aucun ExecStart= dans {}: la garde ne lit pas l'unite qu'elle croit lire",
        chemin_de_l_unite().display()
    );

    let coupables: Vec<&Directive> = toutes.iter().filter(|d| d.desarme()).collect();
    assert!(
        coupables.is_empty(),
        "l'unite {} desarme le pare-feu depuis son cycle de vie:\n{}\n\
         Un desarmement doit rester explicite: 'bifrost-cli disconnect', ou \
         'bifrost-cli emergency-disarm --je-sais-ce-que-je-fais'. \
         Voir la jumelle Windows dans crates/bifrost-daemon/src/service/spec.rs, \
         test l_arret_du_service_ne_rouvre_pas_le_trafic.",
        chemin_de_l_unite().display(),
        coupables
            .iter()
            .map(|d| format!(
                "  ligne {}: {}={}{}",
                d.ligne,
                d.cle,
                d.valeur,
                if d.est_du_cycle_de_vie() {
                    "   <- directive de cycle de vie"
                } else {
                    ""
                }
            ))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// La ligne exacte retiree le 23/08/2026 fait bien rougir la garde.
///
/// Une falsification en dur, gardee pour toujours: elle prouve que le test
/// ci-dessus n'est pas vert parce qu'il ne saurait rien reconnaitre.
#[test]
fn la_ligne_retiree_ferait_rougir_la_garde() {
    let faux = "[Service]\nExecStart=/usr/bin/bifrost-daemon\n\
                ExecStopPost=-/usr/bin/bifrost-daemon --cleanup-firewall\n";
    let vues = directives(faux);
    let coupable = vues
        .iter()
        .find(|d| d.desarme())
        .expect("la ligne d'origine doit etre reconnue");
    assert_eq!(coupable.cle, "ExecStopPost");
    assert_eq!(coupable.ligne, 3);
    assert!(coupable.est_du_cycle_de_vie());
}

/// Les formes VALIDES de la meme intention sont toutes vues.
///
/// Chacune est du systemd legal, ou du systemd qu'un relecteur presse
/// laisserait passer. Une garde qui n'en verrait qu'une serait contournee par
/// la suivante sans que personne ne l'ait voulu.
#[test]
fn toutes_les_formes_de_la_meme_intention_sont_vues() {
    for (nom, texte) in [
        (
            "prefixe - qui ignore le code de sortie",
            "ExecStopPost=-/usr/bin/bifrost-daemon --cleanup-firewall",
        ),
        (
            "sans le prefixe",
            "ExecStopPost=/usr/bin/bifrost-daemon --cleanup-firewall",
        ),
        (
            "espaces autour du =",
            "ExecStopPost = -/usr/bin/bifrost-daemon --cleanup-firewall",
        ),
        (
            "casse inattendue",
            "execstoppost=-/usr/bin/bifrost-daemon --CLEANUP-FIREWALL",
        ),
        (
            "sur ExecStop plutot que ExecStopPost",
            "ExecStop=/usr/bin/bifrost-daemon --cleanup-firewall",
        ),
        (
            "sur le chemin de demarrage",
            "ExecStartPre=-/usr/bin/bifrost-daemon --cleanup-firewall",
        ),
        (
            "par continuation de ligne",
            "ExecStopPost=-/usr/bin/bifrost-daemon \\\n          --cleanup-firewall",
        ),
        (
            "par une unite nommee en OnFailure",
            "OnFailure=bifrost-cleanup-firewall.service",
        ),
        (
            "par la porte de secours detournee en automatisme",
            "ExecStopPost=/usr/bin/bifrost-cli emergency-disarm --je-sais-ce-que-je-fais",
        ),
        (
            "une directive a laquelle personne n'a pense",
            "DirectiveInventee=/usr/bin/bifrost-daemon --cleanup-firewall",
        ),
    ] {
        let complet = format!("[Service]\nExecStart=/usr/bin/bifrost-daemon\n{texte}\n");
        let vues = directives(&complet);
        assert!(
            vues.iter().any(Directive::desarme),
            "forme non vue par la garde ({nom}): {texte}"
        );
    }
}

/// Un commentaire qui CITE la ligne ne fait pas rougir la garde.
///
/// Et il le faut: l'unite corrigee garde la ligne d'origine sous un `#`, pour
/// que personne ne la reinvente en croyant combler un manque. Si la garde
/// rougissait la-dessus, le seul moyen de la calmer serait d'effacer
/// l'explication - donc de perdre la raison pour laquelle la ligne n'est plus
/// la.
#[test]
fn un_commentaire_qui_cite_la_ligne_reste_vert() {
    let texte = "[Service]\n\
                 # ExecStopPost=-/usr/bin/bifrost-daemon --cleanup-firewall\n\
                 ; ExecStop=/usr/bin/bifrost-daemon --cleanup-firewall\n\
                 ExecStart=/usr/bin/bifrost-daemon\n";
    let vues = directives(texte);
    assert!(
        !vues.iter().any(Directive::desarme),
        "un commentaire n'est pas une directive"
    );
    assert_eq!(vues.len(), 1, "seul l'ExecStart= est une affectation");
}

/// Le chainage avec l'unite: l'explication du retrait y est encore.
///
/// Sans ce test, quelqu'un pourrait retirer le commentaire sans rien casser, et
/// la prochaine personne remettrait la ligne faute de savoir pourquoi elle
/// avait disparu. La ligne et sa raison voyagent ensemble ou pas du tout.
#[test]
fn l_unite_explique_pourquoi_la_ligne_n_y_est_plus() {
    let source = unite();
    let commentaires: String = source
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        commentaires.contains("ExecStopPost"),
        "l'unite ne dit plus pourquoi elle n'a pas d'ExecStopPost=: \
         la prochaine personne le remettra"
    );
    assert!(
        commentaires.contains("emergency-disarm"),
        "l'unite doit nommer la porte de secours, sinon retirer le desarmement \
         automatique laisse une machine bloquee sans issue documentee"
    );
}

// ---------------------------------------------------------------------------
// Les capacites du service
// ---------------------------------------------------------------------------

/// Les capacites du noyau, par numero: capabilities(7), jusqu'a
/// CAP_CHECKPOINT_RESTORE (40), la derniere au 30/09/2026.
const CAPACITES_DU_NOYAU: [&str; 41] = [
    "CAP_CHOWN",
    "CAP_DAC_OVERRIDE",
    "CAP_DAC_READ_SEARCH",
    "CAP_FOWNER",
    "CAP_FSETID",
    "CAP_KILL",
    "CAP_SETGID",
    "CAP_SETUID",
    "CAP_SETPCAP",
    "CAP_LINUX_IMMUTABLE",
    "CAP_NET_BIND_SERVICE",
    "CAP_NET_BROADCAST",
    "CAP_NET_ADMIN",
    "CAP_NET_RAW",
    "CAP_IPC_LOCK",
    "CAP_IPC_OWNER",
    "CAP_SYS_MODULE",
    "CAP_SYS_RAWIO",
    "CAP_SYS_CHROOT",
    "CAP_SYS_PTRACE",
    "CAP_SYS_PACCT",
    "CAP_SYS_ADMIN",
    "CAP_SYS_BOOT",
    "CAP_SYS_NICE",
    "CAP_SYS_RESOURCE",
    "CAP_SYS_TIME",
    "CAP_SYS_TTY_CONFIG",
    "CAP_MKNOD",
    "CAP_LEASE",
    "CAP_AUDIT_WRITE",
    "CAP_AUDIT_CONTROL",
    "CAP_SETFCAP",
    "CAP_MAC_OVERRIDE",
    "CAP_MAC_ADMIN",
    "CAP_SYSLOG",
    "CAP_WAKE_ALARM",
    "CAP_BLOCK_SUSPEND",
    "CAP_AUDIT_READ",
    "CAP_PERFMON",
    "CAP_BPF",
    "CAP_CHECKPOINT_RESTORE",
];

/// La capacite qui ne doit pas revenir.
const CAP_SYS_ADMIN: u32 = 21;

/// Un ensemble de capacites, un bit par numero.
type Masque = u64;

/// Numero d'une capacite telle qu'une unite peut l'ecrire.
///
/// systemd (`capability_from_name`) accepte le nom ET le numero, entre
/// guillemets ou non. La garde accepte en plus toute casse et un nom sans
/// `CAP_`: deliberement plus large que systemd, parce que son travail est de
/// reconnaitre une intention, pas de valider le fichier. `None` pour un mot
/// qu'aucun des deux ne connait, et que systemd ignore.
fn numero_de(mot: &str) -> Option<u32> {
    let mot = mot.trim_matches(|c| c == '"' || c == '\'');
    if let Ok(n) = mot.parse::<u32>() {
        return (n < 64).then_some(n);
    }
    let haut = mot.to_ascii_uppercase();
    let complet = if haut.starts_with("CAP_") {
        haut
    } else {
        format!("CAP_{haut}")
    };
    CAPACITES_DU_NOYAU
        .iter()
        .position(|n| *n == complet)
        .and_then(|i| u32::try_from(i).ok())
}

/// Ce que systemd fait d'une suite d'affectations d'une directive de
/// capacites, dans l'ordre du fichier: le pendant de
/// `config_parse_capability_set` (src/core/load-fragment.c).
///
/// - `~` en tete inverse la liste;
/// - une affectation qui ne nomme rien (`=` vide, ou `=~` seul) REMPLACE tout
///   ce qui precede: le vide pour `=`, TOUT pour `=~`;
/// - tant que l'etat est celui par defaut, l'affectation le remplace;
/// - ensuite elles se cumulent: OU pour une liste, ET NON pour une inversion.
///
/// `defaut` n'est pas le meme pour les deux directives: une unite sans
/// `CapabilityBoundingSet=` ne borne RIEN (`None`, donc toutes les capacites),
/// l'ambiant part du vide.
fn evaluer(valeurs: &[&str], defaut: Option<Masque>) -> Option<Masque> {
    let mut etat = defaut;
    for brute in valeurs {
        let brute = brute.trim();
        let (inverse, liste) = match brute.strip_prefix('~') {
            Some(reste) => (true, reste),
            None => (false, brute),
        };
        let somme: Masque = liste
            .split_whitespace()
            .filter_map(numero_de)
            .fold(0, |m, n| m | (1u64 << n));
        etat = Some(if somme == 0 || etat == defaut {
            if inverse { !somme } else { somme }
        } else {
            let avant = etat.unwrap_or_default();
            if inverse {
                avant & !somme
            } else {
                avant | somme
            }
        });
    }
    etat
}

/// Les valeurs d'une cle, dans l'ordre du fichier. La cle EXACTE: systemd est
/// sensible a la casse, et une cle mal ecrite n'affecte rien.
fn valeurs<'a>(toutes: &'a [Directive], cle: &str) -> Vec<&'a str> {
    toutes
        .iter()
        .filter(|d| d.cle == cle)
        .map(|d| d.valeur.as_str())
        .collect()
}

/// Les capacites qu'une unite donne a son service: bornes et ambiant.
fn capacites(toutes: &[Directive]) -> (Masque, Masque) {
    let bornes = evaluer(&valeurs(toutes, "CapabilityBoundingSet"), None).unwrap_or(Masque::MAX);
    let ambiant = evaluer(&valeurs(toutes, "AmbientCapabilities"), Some(0)).unwrap_or(0);
    (bornes, ambiant)
}

/// Les noms d'un masque, pour qu'un echec dise ce qu'il a vu.
fn noms(masque: Masque) -> Vec<&'static str> {
    CAPACITES_DU_NOYAU
        .iter()
        .enumerate()
        .filter(|(i, _)| masque & (1u64 << i) != 0)
        .map(|(_, n)| *n)
        .collect()
}

/// Tout ce par quoi une unite rendrait CAP_SYS_ADMIN a son service. Vide si
/// rien.
///
/// Trois chemins, et chacun a sa forme valide:
///
/// - les bornes et l'ambiant, evalues comme systemd les evalue;
/// - une ligne `Exec*=` a prefixe `+`, que systemd execute << with full
///   privileges >> par-dessus les bornes (man systemd.service), ou `!!`, qui
///   sur un systeme sans ambiant elargit implicitement les bornes;
/// - `PermissionsStartOnly=` vrai, qui retire les restrictions de toutes les
///   lignes autres qu'`ExecStart=`.
///
/// Une cle de capacites ecrite dans une autre casse est refusee a part:
/// systemd l'ignorerait, et une unite qui CROIT se borner ne se bornerait pas.
fn rend_cap_sys_admin(source: &str) -> Vec<String> {
    let toutes = directives(source);
    let mut raisons = Vec::new();
    let (bornes, ambiant) = capacites(&toutes);
    if bornes & (1u64 << CAP_SYS_ADMIN) != 0 {
        raisons.push(if toutes.iter().any(|d| d.cle == "CapabilityBoundingSet") {
            "CapabilityBoundingSet= la rend (bornes evaluees comme systemd)".to_owned()
        } else {
            "aucun CapabilityBoundingSet=: rien n'est borne, donc tout est rendu".to_owned()
        });
    }
    if ambiant & (1u64 << CAP_SYS_ADMIN) != 0 {
        raisons.push("AmbientCapabilities= la rend".to_owned());
    }
    for d in &toutes {
        let cle = d.cle_abaissee();
        if cle.starts_with("exec") {
            let prefixe: String = d
                .valeur
                .chars()
                .take_while(|c| "@-:+!|".contains(*c))
                .collect();
            if prefixe.contains('+') || prefixe.contains("!!") {
                raisons.push(format!(
                    "ligne {}: {}={} s'execute avec tous les privileges",
                    d.ligne, d.cle, d.valeur
                ));
            }
        }
        if cle == "permissionsstartonly"
            && ["yes", "true", "on", "1"].contains(&d.valeur.to_ascii_lowercase().as_str())
        {
            raisons.push(format!(
                "ligne {}: PermissionsStartOnly= leve les restrictions des autres lignes",
                d.ligne
            ));
        }
        if (cle == "capabilityboundingset" || cle == "ambientcapabilities")
            && d.cle != "CapabilityBoundingSet"
            && d.cle != "AmbientCapabilities"
        {
            raisons.push(format!(
                "ligne {}: cle {} que systemd ignorerait",
                d.ligne, d.cle
            ));
        }
    }
    raisons
}

/// Une ligne de commentaire qui JUSTIFIE des capacites: une liste de noms
/// (`CAP_X`, ou `CAP_X, CAP_Y et CAP_Z`), puis ` pour `, puis la raison. C'est
/// la forme que l'unite emploie depuis son premier durcissement; toute autre
/// phrase qui cite une capacite n'en justifie aucune.
fn justifications(source: &str) -> Vec<(usize, Vec<String>)> {
    let est_un_nom = |m: &str| {
        m.len() > 4
            && m.starts_with("CAP_")
            && m[4..].chars().all(|c| c.is_ascii_uppercase() || c == '_')
    };
    let mut sorties = Vec::new();
    for (index, brute) in source.lines().enumerate() {
        let Some(texte) = brute.trim().strip_prefix('#') else {
            continue;
        };
        let Some((tete, _raison)) = texte.trim().split_once(" pour ") else {
            continue;
        };
        let liste: Vec<String> = tete
            .split(", ")
            .flat_map(|m| m.split(" et "))
            .map(|m| m.trim().to_owned())
            .collect();
        if liste.iter().all(|m| est_un_nom(m)) {
            sorties.push((index + 1, liste));
        }
    }
    sorties
}

/// Ce qui ne va pas entre les capacites d'une unite et leurs justifications.
/// Vide si chaque capacite des bornes est justifiee, si chaque justification
/// porte sur une capacite des bornes, et si l'ambiant tient dans les bornes.
fn ecarts_de_justification(source: &str) -> Vec<String> {
    let (bornes, ambiant) = capacites(&directives(source));
    let mut ecarts = Vec::new();
    if bornes == Masque::MAX {
        ecarts.push("les bornes ne bornent rien: aucune justification n'y suffirait".to_owned());
        return ecarts;
    }
    let lignes = justifications(source);
    let mut justifiees: Masque = 0;
    for (ligne, liste) in &lignes {
        for nom in liste {
            match numero_de(nom) {
                None => ecarts.push(format!(
                    "ligne {ligne}: {nom} justifiee, mais ce n'est pas une capacite du noyau"
                )),
                Some(n) if bornes & (1u64 << n) == 0 => ecarts.push(format!(
                    "ligne {ligne}: {nom} est justifiee et n'est plus dans les bornes: \
                     la justification a survecu a sa capacite"
                )),
                Some(n) => justifiees |= 1u64 << n,
            }
        }
    }
    for nom in noms(bornes & !justifiees) {
        ecarts.push(format!(
            "{nom} est dans les bornes sans ligne << {nom} pour ... >> qui dise a quoi elle sert"
        ));
    }
    for nom in noms(ambiant & !bornes) {
        ecarts.push(format!("{nom} est ambiante sans etre dans les bornes"));
    }
    ecarts
}

/// La garde, sur l'unite LIVREE: CAP_SYS_ADMIN ne revient par aucun chemin.
#[test]
fn l_unite_ne_rend_cap_sys_admin_par_aucun_chemin() {
    let source = unite();
    assert!(
        directives(&source)
            .iter()
            .any(|d| d.cle == "CapabilityBoundingSet"),
        "aucun CapabilityBoundingSet= dans {}: la garde ne lit pas l'unite qu'elle croit lire",
        chemin_de_l_unite().display()
    );
    let raisons = rend_cap_sys_admin(&source);
    assert!(
        raisons.is_empty(),
        "l'unite {} rend CAP_SYS_ADMIN au service:\n  {}\n\
         Le harnais de fuite, seul a s'en servir, se lance hors du service: \
         'sudo bifrost-daemon --run-checks'.",
        chemin_de_l_unite().display(),
        raisons.join("\n  ")
    );
}

/// Chaque capacite qui reste dit a quoi elle sert, et aucune justification ne
/// survit a sa capacite.
///
/// La forme existait avant la garde: l'unite ecrit << CAP_NET_ADMIN pour
/// nftables, les routes et l'interface du tunnel >> depuis son premier
/// durcissement. Ce qui manquait etait le lien. La justification de
/// CAP_SYS_ADMIN, << pour les namespaces reseau que ce meme harnais cree >>,
/// etait vraie de `check` et fausse du service; rien ne l'aurait fait relire.
#[test]
fn chaque_capacite_de_l_unite_a_sa_justification() {
    let source = unite();
    assert!(
        justifications(&source).len() >= 3,
        "moins de trois justifications lues dans {}: le parcours est casse",
        chemin_de_l_unite().display()
    );
    let ecarts = ecarts_de_justification(&source);
    assert!(
        ecarts.is_empty(),
        "capacites et justifications divergent dans {}:\n  {}",
        chemin_de_l_unite().display(),
        ecarts.join("\n  ")
    );
}

/// L'explication du retrait voyage avec l'unite, comme celle de l'ExecStopPost.
#[test]
fn l_unite_explique_pourquoi_cap_sys_admin_n_y_est_plus() {
    let commentaires: String = unite()
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        commentaires.contains("CAP_SYS_ADMIN"),
        "l'unite ne dit plus pourquoi elle n'a pas CAP_SYS_ADMIN: \
         la prochaine personne la remettra pour faire marcher check"
    );
    assert!(
        commentaires.contains("--run-checks"),
        "l'unite doit nommer la commande qui mesure hors du service"
    );
}

/// Les deux lignes d'avant le 30/09/2026 font rougir la garde. Falsification
/// en dur, gardee pour toujours.
#[test]
fn les_lignes_retirees_feraient_rougir_la_garde() {
    let avant = "[Service]\nExecStart=/usr/bin/bifrost-daemon\n\
        CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_ADMIN CAP_CHOWN \
        CAP_SETUID CAP_SETGID CAP_NET_BIND_SERVICE CAP_KILL\n\
        AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_ADMIN CAP_CHOWN \
        CAP_SETUID CAP_SETGID CAP_NET_BIND_SERVICE\n";
    let raisons = rend_cap_sys_admin(avant);
    assert_eq!(raisons.len(), 2, "bornes ET ambiant: {raisons:?}");
    // Et son masque est celui que le noyau a montre au daemon ce jour-la
    // (CapEff 00000000002034e1, CapAmb 00000000002034c1).
    assert_eq!(capacites(&directives(avant)), (0x2034e1, 0x2034c1));
}

/// Toutes les formes VALIDES qui rendent CAP_SYS_ADMIN sont vues.
#[test]
fn toutes_les_formes_qui_rendent_cap_sys_admin_sont_vues() {
    for (nom, texte) in [
        (
            "par son nom",
            "CapabilityBoundingSet=CAP_NET_ADMIN CAP_SYS_ADMIN",
        ),
        (
            "en minuscules",
            "CapabilityBoundingSet=CAP_NET_ADMIN cap_sys_admin",
        ),
        ("par son numero", "CapabilityBoundingSet=CAP_NET_ADMIN 21"),
        (
            "entre guillemets",
            "CapabilityBoundingSet=CAP_NET_ADMIN \"CAP_SYS_ADMIN\"",
        ),
        (
            "par une seconde ligne qui se cumule",
            "CapabilityBoundingSet=CAP_NET_ADMIN\nCapabilityBoundingSet=CAP_SYS_ADMIN",
        ),
        (
            "par une inversion qui en retire une autre",
            "CapabilityBoundingSet=~CAP_SYS_MODULE",
        ),
        (
            "par l'inversion seule, qui rend tout",
            "CapabilityBoundingSet=~",
        ),
        (
            "par l'absence de bornes",
            "AmbientCapabilities=CAP_NET_ADMIN",
        ),
        (
            "par l'ambiant seul",
            "CapabilityBoundingSet=CAP_NET_ADMIN\nAmbientCapabilities=CAP_SYS_ADMIN",
        ),
        (
            "par une cle que systemd ignorerait",
            "CapabilityBoundingSet=CAP_NET_ADMIN\ncapabilityboundingset=CAP_NET_ADMIN",
        ),
        (
            "par un prefixe + sur ExecStart",
            "CapabilityBoundingSet=CAP_NET_ADMIN\nExecStartPre=+/usr/bin/bifrost-daemon --run-checks",
        ),
        (
            "par un prefixe combine",
            "CapabilityBoundingSet=CAP_NET_ADMIN\nExecStartPost=-+/usr/bin/true",
        ),
        (
            "par un prefixe !!",
            "CapabilityBoundingSet=CAP_NET_ADMIN\nExecStartPre=!!/usr/bin/true",
        ),
        (
            "par PermissionsStartOnly",
            "CapabilityBoundingSet=CAP_NET_ADMIN\nPermissionsStartOnly=yes",
        ),
    ] {
        let complet = format!("[Service]\nExecStart=/usr/bin/bifrost-daemon\n{texte}\n");
        assert!(
            !rend_cap_sys_admin(&complet).is_empty(),
            "forme non vue par la garde ({nom}): {texte}"
        );
    }
}

/// Et celles qui la RETIRENT restent vertes: une garde qui rougirait sur
/// `~CAP_SYS_ADMIN` ou sur un commentaire ne lirait pas ce que systemd lit.
#[test]
fn les_formes_qui_la_retirent_restent_vertes() {
    for (nom, texte) in [
        (
            "l'inversion qui la retire",
            "CapabilityBoundingSet=~CAP_SYS_ADMIN",
        ),
        (
            "une remise a zero apres elle",
            "CapabilityBoundingSet=CAP_SYS_ADMIN\nCapabilityBoundingSet=\n\
             CapabilityBoundingSet=CAP_NET_ADMIN",
        ),
        (
            "une inversion qui la retire apres coup",
            "CapabilityBoundingSet=CAP_NET_ADMIN CAP_SYS_ADMIN\nCapabilityBoundingSet=~CAP_SYS_ADMIN",
        ),
        (
            "un commentaire qui la cite",
            "# CapabilityBoundingSet=CAP_SYS_ADMIN\nCapabilityBoundingSet=CAP_NET_ADMIN",
        ),
        (
            "un prefixe - qui ne leve rien",
            "CapabilityBoundingSet=CAP_NET_ADMIN\nExecStartPre=-/usr/bin/true",
        ),
    ] {
        let complet = format!("[Service]\nExecStart=/usr/bin/bifrost-daemon\n{texte}\n");
        let raisons = rend_cap_sys_admin(&complet);
        assert!(
            raisons.is_empty(),
            "forme lue a tort comme rendant CAP_SYS_ADMIN ({nom}): {texte}\n{raisons:?}"
        );
    }
}

/// La garde de justification rougit dans les deux sens.
#[test]
fn une_capacite_muette_ou_une_justification_orpheline_rougit() {
    let base = "[Service]\nExecStart=/usr/bin/bifrost-daemon\n";
    // Juste: chaque capacite a sa ligne, la liste a virgule et `et` comprise.
    let juste = format!(
        "{base}# CAP_NET_ADMIN pour nftables.\n\
         # CAP_SETUID, CAP_SETGID et CAP_KILL pour le resolveur.\n\
         CapabilityBoundingSet=CAP_NET_ADMIN CAP_SETUID CAP_SETGID CAP_KILL\n\
         AmbientCapabilities=CAP_NET_ADMIN\n"
    );
    assert_eq!(ecarts_de_justification(&juste), Vec::<String>::new());

    // Une capacite sans ligne.
    let muette = juste.replace("CAP_KILL\n", "CAP_KILL CAP_NET_RAW\n");
    assert!(
        ecarts_de_justification(&muette)
            .iter()
            .any(|e| e.contains("CAP_NET_RAW")),
        "une capacite sans justification doit rougir"
    );
    // Une justification restee apres le retrait: le defaut exact de
    // l'ancienne ligne << CAP_SYS_ADMIN pour les namespaces reseau >>.
    let orpheline = format!("{juste}# CAP_SYS_ADMIN pour les namespaces reseau du harnais.\n");
    assert!(
        ecarts_de_justification(&orpheline)
            .iter()
            .any(|e| e.contains("CAP_SYS_ADMIN")),
        "une justification sans capacite doit rougir"
    );
    // Une faute de frappe: justifiee, mais que le noyau ne connait pas.
    let faute = format!("{juste}# CAP_NET_ADMN pour rien.\n");
    assert!(
        !ecarts_de_justification(&faute).is_empty(),
        "une capacite inconnue justifiee doit rougir"
    );
    // Un ambiant hors des bornes.
    let hors = juste.replace(
        "AmbientCapabilities=CAP_NET_ADMIN",
        "AmbientCapabilities=CAP_CHOWN",
    );
    assert!(
        ecarts_de_justification(&hors)
            .iter()
            .any(|e| e.contains("CAP_CHOWN")),
        "un ambiant hors des bornes doit rougir"
    );
    // Une phrase qui cite une capacite sans la justifier n'en justifie aucune.
    let citee = format!("{base}# L'ambiant, lui, n'a pas CAP_KILL pour le resolveur.\n");
    assert!(justifications(&citee).is_empty());
}
