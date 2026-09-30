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
//!
//! # La troisieme: les drop-ins, et ce que l'installateur pose
//!
//! Releve du 30/09/2026 a la verification du retrait: la garde ne lisait que
//! le fichier d'unite, et un drop-in `*.service.d/*.conf` qui rendrait
//! CAP_SYS_ADMIN serait passe (aucun n'existe). Un drop-in ne compte que s'il
//! est pose, et ce depot en pose deja: deux bancs ecrivent le leur en ligne,
//! par `cat <<`, sans fichier sous `packaging/`. Lire les fichiers ne suffit
//! donc pas; le point d'accroche est ce que `packaging/install-linux.sh` pose:
//!
//! - l'unite, composee avec tout drop-in livre sous `packaging/` dans un
//!   repertoire que systemd lit pour elle (`bifrost-daemon.service.d/`,
//!   `bifrost-.service.d/`, `service.d/`), dans l'ordre de systemd, ne rend
//!   CAP_SYS_ADMIN par aucun des chemins ci-dessus, ne desarme pas a l'arret,
//!   et chaque capacite de l'ensemble a sa justification: les trois gardes
//!   lisent la meme composition;
//! - chaque ligne de l'installateur, et des scripts de `packaging/` qu'il
//!   source ou lance, qui touche a la configuration de systemd
//!   est un `install` depuis `packaging/` de l'unite que ces gardes lisent,
//!   ou d'un drop-in qu'elles lisent. Un drop-in ecrit en ligne, une propriete
//!   posee par `systemctl set-property`, une unite venue d'ailleurs rougissent.

use std::path::{Path, PathBuf};

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

/// L'unite LIVREE, relative a la racine du depot: le fichier que ces gardes
/// lisent, et celui que l'installateur doit poser (voir
/// [`poses_de_l_installateur`]).
const UNITE_LIVREE: &str = "packaging/systemd/bifrost-daemon.service";

/// Le nom sous lequel l'installateur pose l'unite, et que systemd lit.
const NOM_DE_L_UNITE: &str = "bifrost-daemon.service";

fn racine_du_depot() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// L'unite telle qu'elle est LIVREE, pas une copie d'essai.
fn chemin_de_l_unite() -> PathBuf {
    racine_du_depot().join(UNITE_LIVREE)
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

/// Les directives qui desarment, dans l'unite puis dans chaque drop-in, une
/// ligne par coupable, nommee avec son fichier. Un drop-in ajoute ses lignes a
/// celles de l'unite (systemd.unit(5)): une ligne retiree de l'unite et remise
/// par un drop-in desarme autant.
fn desarmements_avec(unite: &str, drop_ins: &[(String, String)]) -> Vec<String> {
    std::iter::once((String::new(), unite))
        .chain(
            drop_ins
                .iter()
                .map(|(chemin, texte)| (format!("{chemin}, "), texte.as_str())),
        )
        .flat_map(|(ou, texte)| {
            directives(texte)
                .into_iter()
                .filter(|d| d.desarme())
                .map(move |d| {
                    format!(
                        "{ou}ligne {}: {}={}{}",
                        d.ligne,
                        d.cle,
                        d.valeur,
                        if d.est_du_cycle_de_vie() {
                            "   <- directive de cycle de vie"
                        } else {
                            ""
                        }
                    )
                })
        })
        .collect()
}

/// La garde elle-meme, sur l'unite LIVREE et ses drop-ins livres.
///
/// Si quelqu'un remet `ExecStopPost=-/usr/bin/bifrost-daemon --cleanup-firewall`
/// dans six mois, c'est ce test qui doit l'arreter, dans l'unite ou dans un
/// drop-in. Le retrait du kill switch
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

    let (drop_ins, _) = drop_ins_livres();
    let coupables = desarmements_avec(&source, &drop_ins);
    assert!(
        coupables.is_empty(),
        "l'unite {} ou un de ses drop-ins desarme le pare-feu depuis son cycle de vie:\n  {}\n\
         Un desarmement doit rester explicite: 'bifrost-cli disconnect', ou \
         'bifrost-cli emergency-disarm --je-sais-ce-que-je-fais'. \
         Voir la jumelle Windows dans crates/bifrost-daemon/src/service/spec.rs, \
         test l_arret_du_service_ne_rouvre_pas_le_trafic.",
        chemin_de_l_unite().display(),
        coupables.join("\n  ")
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
    rend_cap_sys_admin_avec(source, &[])
}

/// [`rend_cap_sys_admin`] sur l'unite ET ses drop-ins, composes comme systemd
/// les compose (systemd.unit(5): un drop-in est lu << after the main unit file
/// itself has been parsed >>, les drop-ins << in lexicographic order >>): leurs
/// affectations suivent celles de l'unite, dans l'ordre recu, et s'y cumulent
/// ou les remettent a zero exactement comme des lignes de plus. Les lignes qui
/// levent les bornes sont cherchees fichier par fichier, et nommees avec lui.
///
/// `drop_ins`: (chemin, contenu), dans l'ordre ou systemd les applique; voir
/// [`dans_l_ordre_de_systemd`].
fn rend_cap_sys_admin_avec(unite: &str, drop_ins: &[(String, String)]) -> Vec<String> {
    let fichiers: Vec<(String, Vec<Directive>)> =
        std::iter::once((String::new(), directives(unite)))
            .chain(
                drop_ins
                    .iter()
                    .map(|(chemin, texte)| (format!("{chemin}, "), directives(texte))),
            )
            .collect();
    let toutes: Vec<Directive> = fichiers
        .iter()
        .flat_map(|(_, lues)| lues.iter().cloned())
        .collect();
    let composees = if drop_ins.is_empty() {
        String::new()
    } else {
        format!(
            ", unite et drop-ins composes: {}",
            drop_ins
                .iter()
                .map(|(chemin, _)| chemin.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    let mut raisons = Vec::new();
    let (bornes, ambiant) = capacites(&toutes);
    if bornes & (1u64 << CAP_SYS_ADMIN) != 0 {
        raisons.push(if toutes.iter().any(|d| d.cle == "CapabilityBoundingSet") {
            format!("CapabilityBoundingSet= la rend (bornes evaluees comme systemd{composees})")
        } else {
            "aucun CapabilityBoundingSet=: rien n'est borne, donc tout est rendu".to_owned()
        });
    }
    if ambiant & (1u64 << CAP_SYS_ADMIN) != 0 {
        raisons.push(format!("AmbientCapabilities= la rend{composees}"));
    }
    for (ou, lues) in &fichiers {
        for d in lues {
            let cle = d.cle_abaissee();
            if cle.starts_with("exec") {
                let prefixe: String = d
                    .valeur
                    .chars()
                    .take_while(|c| "@-:+!|".contains(*c))
                    .collect();
                if prefixe.contains('+') || prefixe.contains("!!") {
                    raisons.push(format!(
                        "{ou}ligne {}: {}={} s'execute avec tous les privileges",
                        d.ligne, d.cle, d.valeur
                    ));
                }
            }
            if cle == "permissionsstartonly"
                && ["yes", "true", "on", "1"].contains(&d.valeur.to_ascii_lowercase().as_str())
            {
                raisons.push(format!(
                    "{ou}ligne {}: PermissionsStartOnly= leve les restrictions des autres lignes",
                    d.ligne
                ));
            }
            if (cle == "capabilityboundingset" || cle == "ambientcapabilities")
                && d.cle != "CapabilityBoundingSet"
                && d.cle != "AmbientCapabilities"
            {
                raisons.push(format!(
                    "{ou}ligne {}: cle {} que systemd ignorerait",
                    d.ligne, d.cle
                ));
            }
        }
    }
    raisons
}

// ---------------------------------------------------------------------------
// Les drop-ins, et ce que l'installateur pose
// ---------------------------------------------------------------------------

/// Les repertoires de drop-in que systemd lit pour `unite`, du plus specifique
/// au plus general. Releve dans systemd.unit(5) (systemd 255): le repertoire
/// `foo-bar-baz.service.d/`, puis ceux des prefixes coupes apres chaque tiret
/// (`foo-bar-.service.d/`, `foo-.service.d/`), puis le repertoire de type
/// `service.d/`, qui vaut pour tous les services.
fn repertoires_de_drop_in(unite: &str) -> Vec<String> {
    let (nom, genre) = unite
        .rsplit_once('.')
        .expect("un nom d'unite porte son type");
    let mut repertoires = vec![format!("{unite}.d")];
    for (i, _) in nom.match_indices('-').collect::<Vec<_>>().into_iter().rev() {
        repertoires.push(format!("{}.{genre}.d", &nom[..=i]));
    }
    repertoires.push(format!("{genre}.d"));
    repertoires
}

/// Des drop-ins dans l'ordre ou systemd les applique: par nom de fichier,
/// << regardless of which of the directories they reside in >> (systemd.unit(5)),
/// puis par chemin pour que l'ordre soit total.
fn dans_l_ordre_de_systemd(mut drop_ins: Vec<(String, String)>) -> Vec<(String, String)> {
    fn nom_de_fichier(chemin: &str) -> &str {
        chemin.rsplit('/').next().unwrap_or(chemin)
    }
    drop_ins.sort_by(|a, b| {
        nom_de_fichier(&a.0)
            .cmp(nom_de_fichier(&b.0))
            .then_with(|| a.0.cmp(&b.0))
    });
    drop_ins
}

/// Les drop-ins que le depot livre pour l'unite: tout `*.conf` d'un repertoire
/// de `packaging/`, a toute profondeur, dont le nom est un de ceux que systemd
/// lit pour elle ([`repertoires_de_drop_in`]). Chemins relatifs a la racine du
/// depot, en `/`, dans l'ordre de [`dans_l_ordre_de_systemd`].
///
/// Plus stricte que systemd sur un point: deux drop-ins de meme nom dans deux
/// de ces repertoires sont lus tous les deux, la ou systemd ne garde que le
/// plus specifique. Un fichier livre qui rendrait CAP_SYS_ADMIN rougit donc
/// meme masque: il suffirait de retirer l'autre pour qu'il prenne effet.
///
/// Le second membre dit si le parcours a croise l'unite livree: sans drop-in a
/// trouver, c'est la seule preuve que la garde a regarde au bon endroit.
fn drop_ins_livres() -> (Vec<(String, String)>, bool) {
    fn parcourir(
        dossier: &Path,
        relatif: &str,
        noms: &[String],
        trouves: &mut Vec<(String, String)>,
        unite_vue: &mut bool,
    ) {
        let Ok(entrees) = std::fs::read_dir(dossier) else {
            return;
        };
        for entree in entrees.flatten() {
            let chemin = entree.path();
            let nom = entree.file_name().to_string_lossy().into_owned();
            let rel = format!("{relatif}/{nom}");
            if chemin.is_dir() {
                if noms.contains(&nom) {
                    for fichier in std::fs::read_dir(&chemin).into_iter().flatten().flatten() {
                        let nom_f = fichier.file_name().to_string_lossy().into_owned();
                        if nom_f.ends_with(".conf") && fichier.path().is_file() {
                            let texte = std::fs::read_to_string(fichier.path())
                                .unwrap_or_else(|e| panic!("lecture de {rel}/{nom_f}: {e}"));
                            trouves.push((format!("{rel}/{nom_f}"), texte));
                        }
                    }
                }
                parcourir(&chemin, &rel, noms, trouves, unite_vue);
            } else if rel == UNITE_LIVREE {
                *unite_vue = true;
            }
        }
    }
    let noms = repertoires_de_drop_in(NOM_DE_L_UNITE);
    let mut trouves = Vec::new();
    let mut unite_vue = false;
    parcourir(
        &racine_du_depot().join("packaging"),
        "packaging",
        &noms,
        &mut trouves,
        &mut unite_vue,
    );
    (dans_l_ordre_de_systemd(trouves), unite_vue)
}

/// Les repertoires ou systemd cherche les unites du systeme, releves dans
/// systemd.unit(5) (systemd 255, << System Unit Search Path >>), plus
/// `/lib/systemd/system` des systemes ou `/lib` n'est pas un lien. Y ecrire,
/// c'est configurer un service.
const REPERTOIRES_D_UNITES: [&str; 13] = [
    "/etc/systemd/system.control",
    "/run/systemd/system.control",
    "/run/systemd/transient",
    "/run/systemd/generator.early",
    "/etc/systemd/system",
    "/etc/systemd/system.attached",
    "/run/systemd/system",
    "/run/systemd/system.attached",
    "/run/systemd/generator",
    "/usr/local/lib/systemd/system",
    "/usr/lib/systemd/system",
    "/lib/systemd/system",
    "/run/systemd/generator.late",
];

/// Les lignes logiques d'un script shell: commentaires de ligne entiere otes,
/// continuations `\` jointes, chacune avec le numero de sa premiere ligne
/// physique.
fn lignes_logiques(script: &str) -> Vec<(usize, String)> {
    let mut sorties = Vec::new();
    let mut accumule: Option<(usize, String)> = None;
    for (index, brute) in script.lines().enumerate() {
        let taillee = brute.trim();
        if accumule.is_none() && taillee.starts_with('#') {
            continue;
        }
        let (debut, morceau) = match accumule.take() {
            Some((d, deja)) => (d, format!("{deja} {taillee}")),
            None => (index + 1, taillee.to_owned()),
        };
        if let Some(sans) = morceau.strip_suffix('\\') {
            accumule = Some((debut, sans.trim_end().to_owned()));
            continue;
        }
        if !morceau.is_empty() {
            sorties.push((debut, morceau));
        }
    }
    if let Some(reste) = accumule {
        sorties.push(reste);
    }
    sorties
}

/// Vrai si une ligne de l'installateur touche a la configuration d'un service:
/// elle nomme un repertoire d'unites (suivi d'un separateur: `system-sleep`
/// n'en est pas un), un repertoire de drop-in de l'unite, un generateur, ou une
/// sous-commande de systemctl qui ecrit un drop-in (`edit`, `set-property`) ou
/// lie une unite venue d'ailleurs (`link`).
fn touche_la_configuration(ligne: &str) -> bool {
    let repertoire = REPERTOIRES_D_UNITES.iter().any(|r| {
        ligne.match_indices(r).any(|(i, _)| {
            ligne[i + r.len()..]
                .chars()
                .next()
                .is_none_or(|c| !(c.is_ascii_alphanumeric() || "-_.".contains(c)))
        })
    });
    let drop_in = repertoires_de_drop_in(NOM_DE_L_UNITE)
        .iter()
        .any(|d| ligne.contains(d.as_str()));
    let generateur = ligne.contains("system-generators");
    let mots: Vec<&str> = ligne.split_whitespace().collect();
    let systemctl = mots.contains(&"systemctl")
        && ["edit", "set-property", "link"]
            .iter()
            .any(|s| mots.contains(s));
    repertoire || drop_in || generateur || systemctl
}

/// La source et la destination d'une ligne `install ... SOURCE DESTINATION`
/// dont la source est sous `$ICI`, le repertoire `packaging/` de
/// l'installateur: la source en chemin relatif a la racine du depot. `None`
/// pour toute autre forme.
fn pose_depuis_packaging(ligne: &str) -> Option<(String, String)> {
    let jetons: Vec<&str> = ligne
        .split_whitespace()
        .map(|j| j.trim_matches(|c| c == '"' || c == '\''))
        .collect();
    let [premier, .., source, destination] = jetons.as_slice() else {
        return None;
    };
    if *premier != "install" {
        return None;
    }
    let reste = source
        .strip_prefix("$ICI/")
        .or_else(|| source.strip_prefix("${ICI}/"))?;
    Some((format!("packaging/{reste}"), (*destination).to_owned()))
}

/// Ce que l'installateur pose dans la configuration de systemd: les lignes
/// que la garde lit, puis celles qu'elle ne sait pas lire.
///
/// Une ligne qui touche a la configuration ([`touche_la_configuration`]) n'est
/// lue que si elle est un `install` depuis `packaging/` vers un repertoire
/// d'unites, et qu'elle pose soit [`UNITE_LIVREE`] sous le nom de l'unite, soit
/// un drop-in que [`drop_ins_livres`] a lu, sous son nom et dans un repertoire
/// de drop-in du meme nom. Tout le reste - un drop-in ecrit en ligne, par
/// `tee` ou `cat <<`, une propriete posee par `systemctl set-property`, une
/// unite venue d'ailleurs, un repertoire d'unites range dans une variable -
/// poserait ce qu'aucune garde n'evalue.
fn poses_de_l_installateur(
    script: &str,
    drop_ins: &[(String, String)],
) -> (Vec<String>, Vec<String>) {
    let repertoires = repertoires_de_drop_in(NOM_DE_L_UNITE);
    let lue = |source: &str, destination: &str| {
        REPERTOIRES_D_UNITES.iter().any(|r| {
            let Some(apres) = destination
                .strip_prefix(r)
                .and_then(|a| a.strip_prefix('/'))
            else {
                return false;
            };
            if apres == NOM_DE_L_UNITE {
                return source == UNITE_LIVREE;
            }
            let Some((repertoire, fichier)) = apres.split_once('/') else {
                return false;
            };
            repertoires.iter().any(|d| d == repertoire)
                && fichier.ends_with(".conf")
                && !fichier.contains('/')
                && source.ends_with(&format!("/{repertoire}/{fichier}"))
                && drop_ins.iter().any(|(chemin, _)| chemin == source)
        })
    };
    let mut lues = Vec::new();
    let mut illisibles = Vec::new();
    for (numero, ligne) in lignes_logiques(script) {
        if !touche_la_configuration(&ligne) {
            continue;
        }
        if pose_depuis_packaging(&ligne).is_some_and(|(s, d)| lue(&s, &d)) {
            lues.push(ligne);
        } else {
            illisibles.push(format!("ligne {numero}: {ligne}"));
        }
    }
    (lues, illisibles)
}

/// Les scripts de `packaging/` qu'une ligne fait lire ou executer, relatifs a
/// la racine du depot: la cible d'un source (`. "$ICI/x"`, `source "$ICI/x"`),
/// et tout `$ICI/...sh` nomme ailleurs sur la ligne, lance (`bash "$ICI/x.sh"`,
/// `"$ICI/x.sh"`) ou range dans une variable qu'une autre ligne lancera
/// (`X="$ICI/x.sh"`).
///
/// Releve du 30/09/2026 sur `essai-linux`: quand seul le source etait suivi,
/// un script lance par l'installateur, directement ou par sa variable, pouvait
/// ecrire un drop-in rendant CAP_SYS_ADMIN, et toute la suite restait verte.
fn scripts_nommes(ligne: &str) -> Vec<String> {
    let mots: Vec<&str> = ligne.split_whitespace().collect();
    let mut scripts = Vec::new();
    for (i, mot) in mots.iter().enumerate() {
        let valeur = mot.split_once('=').map_or(*mot, |(_, v)| v);
        let nu = valeur.trim_matches(|c: char| "\"'`;()".contains(c));
        let Some(reste) = nu
            .strip_prefix("$ICI/")
            .or_else(|| nu.strip_prefix("${ICI}/"))
        else {
            continue;
        };
        let source = i == 1 && (mots[0] == "." || mots[0] == "source");
        if source || reste.ends_with(".sh") {
            scripts.push(format!("packaging/{reste}"));
        }
    }
    scripts
}

/// L'installateur et chaque script de `packaging/` qu'il source ou lance, de
/// proche en proche ([`scripts_nommes`]): une pose faite par un tel script est
/// faite par l'installateur, et `install-linux.sh` source deja `comptes.sh`.
/// Rend (chemin, texte), puis les scripts nommes introuvables.
fn scripts_de_l_installateur() -> (Vec<(String, String)>, Vec<String>) {
    let mut a_lire = vec!["packaging/install-linux.sh".to_owned()];
    let mut lus: Vec<(String, String)> = Vec::new();
    let mut introuvables = Vec::new();
    while let Some(chemin) = a_lire.pop() {
        if lus.iter().any(|(deja, _)| *deja == chemin) {
            continue;
        }
        let Ok(texte) = std::fs::read_to_string(racine_du_depot().join(&chemin)) else {
            introuvables.push(chemin);
            continue;
        };
        a_lire.extend(
            lignes_logiques(&texte)
                .iter()
                .flat_map(|(_, ligne)| scripts_nommes(ligne)),
        );
        lus.push((chemin, texte));
    }
    (lus, introuvables)
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
    ecarts_de_justification_avec(source, &[])
}

/// [`ecarts_de_justification`] sur l'unite ET ses drop-ins, composes comme
/// dans [`rend_cap_sys_admin_avec`]: une capacite qu'un drop-in ajoute aux
/// bornes doit etre justifiee, dans l'unite ou dans ce drop-in, et une
/// justification est nommee avec son fichier.
fn ecarts_de_justification_avec(unite: &str, drop_ins: &[(String, String)]) -> Vec<String> {
    let fichiers: Vec<(String, &str)> = std::iter::once((String::new(), unite))
        .chain(
            drop_ins
                .iter()
                .map(|(chemin, texte)| (format!("{chemin}, "), texte.as_str())),
        )
        .collect();
    let toutes: Vec<Directive> = fichiers
        .iter()
        .flat_map(|(_, texte)| directives(texte))
        .collect();
    let (bornes, ambiant) = capacites(&toutes);
    let mut ecarts = Vec::new();
    if bornes == Masque::MAX {
        ecarts.push("les bornes ne bornent rien: aucune justification n'y suffirait".to_owned());
        return ecarts;
    }
    let mut justifiees: Masque = 0;
    for (ou, texte) in &fichiers {
        for (ligne, liste) in justifications(texte) {
            for nom in &liste {
                match numero_de(nom) {
                    None => ecarts.push(format!(
                        "{ou}ligne {ligne}: {nom} justifiee, mais ce n'est pas une capacite du noyau"
                    )),
                    Some(n) if bornes & (1u64 << n) == 0 => ecarts.push(format!(
                        "{ou}ligne {ligne}: {nom} est justifiee et n'est plus dans les bornes: \
                         la justification a survecu a sa capacite"
                    )),
                    Some(n) => justifiees |= 1u64 << n,
                }
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

/// La garde, sur l'unite LIVREE et ses drop-ins livres: CAP_SYS_ADMIN ne
/// revient par aucun chemin.
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
    // Aucun drop-in n'est livre au 30/09/2026: le parcours doit prouver qu'il
    // a regarde, sinon zero drop-in se lirait comme zero coupable.
    let (drop_ins, unite_vue) = drop_ins_livres();
    assert!(
        unite_vue,
        "le parcours de packaging/ n'a pas croise {UNITE_LIVREE}: il ne lit pas ce qu'il croit lire"
    );
    let raisons = rend_cap_sys_admin_avec(&source, &drop_ins);
    assert!(
        raisons.is_empty(),
        "l'unite {} ou un de ses drop-ins rend CAP_SYS_ADMIN au service:\n  {}\n\
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
    let (drop_ins, _) = drop_ins_livres();
    let ecarts = ecarts_de_justification_avec(&source, &drop_ins);
    assert!(
        ecarts.is_empty(),
        "capacites et justifications divergent dans {} ou ses drop-ins:\n  {}",
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

// ---------------------------------------------------------------------------
// Les drop-ins et l'installateur
// ---------------------------------------------------------------------------

/// Les repertoires de drop-in sont ceux que systemd lit, exemple de
/// systemd.unit(5) compris.
#[test]
fn les_repertoires_de_drop_in_sont_ceux_que_systemd_lit() {
    assert_eq!(
        repertoires_de_drop_in(NOM_DE_L_UNITE),
        [
            "bifrost-daemon.service.d",
            "bifrost-.service.d",
            "service.d"
        ]
    );
    assert_eq!(
        repertoires_de_drop_in("foo-bar-baz.service"),
        [
            "foo-bar-baz.service.d",
            "foo-bar-.service.d",
            "foo-.service.d",
            "service.d"
        ]
    );
}

/// Chaque forme de drop-in qui rend CAP_SYS_ADMIN est vue, composee avec
/// l'unite LIVREE; celles qui la retirent ou n'y touchent pas restent vertes,
/// et l'ordre des noms de fichier est celui de systemd. Falsification en dur,
/// gardee pour toujours.
#[test]
fn un_drop_in_qui_rend_cap_sys_admin_est_vu() {
    let livree = unite();
    let seul = |texte: &str| {
        rend_cap_sys_admin_avec(
            &livree,
            &[(
                "packaging/systemd/bifrost-daemon.service.d/50-essai.conf".to_owned(),
                texte.to_owned(),
            )],
        )
    };
    for (nom, texte) in [
        (
            "par les bornes",
            "[Service]\nCapabilityBoundingSet=CAP_SYS_ADMIN\n",
        ),
        (
            "par l'ambiant",
            "[Service]\nAmbientCapabilities=CAP_SYS_ADMIN\n",
        ),
        ("par son numero", "[Service]\nCapabilityBoundingSet=21\n"),
        (
            "par une remise a zero puis une liste",
            "[Service]\nCapabilityBoundingSet=\nCapabilityBoundingSet=CAP_NET_ADMIN CAP_SYS_ADMIN\n",
        ),
        (
            "par l'inversion seule",
            "[Service]\nCapabilityBoundingSet=~\n",
        ),
        (
            "par un prefixe + sur une ligne ajoutee",
            "[Service]\nExecStartPre=+/usr/bin/true\n",
        ),
    ] {
        assert!(
            !seul(texte).is_empty(),
            "drop-in non vu par la garde ({nom}): {texte}"
        );
    }
    for (nom, texte) in [
        (
            "une inversion qui la retire",
            "[Service]\nCapabilityBoundingSet=~CAP_SYS_ADMIN\n",
        ),
        (
            "la deviation des bancs",
            "[Service]\nNetworkNamespacePath=/run/netns/essai\n",
        ),
        (
            "un commentaire qui la cite",
            "[Service]\n# AmbientCapabilities=CAP_SYS_ADMIN\n",
        ),
    ] {
        let raisons = seul(texte);
        assert!(
            raisons.is_empty(),
            "drop-in lu a tort comme rendant CAP_SYS_ADMIN ({nom}): {texte}\n{raisons:?}"
        );
    }
    // Deux drop-ins, et l'ordre de leurs noms decide: celui qui la retire ne
    // gagne que s'il vient apres, quel que soit son repertoire.
    let donne = "[Service]\nCapabilityBoundingSet=CAP_SYS_ADMIN\n".to_owned();
    let retire = "[Service]\nCapabilityBoundingSet=~CAP_SYS_ADMIN\n".to_owned();
    let tries = |a: (&str, &String), b: (&str, &String)| {
        dans_l_ordre_de_systemd(vec![
            (a.0.to_owned(), a.1.clone()),
            (b.0.to_owned(), b.1.clone()),
        ])
    };
    let retrait_apres = tries(
        (
            "packaging/systemd/bifrost-daemon.service.d/10-donne.conf",
            &donne,
        ),
        ("packaging/systemd/service.d/20-retire.conf", &retire),
    );
    assert!(rend_cap_sys_admin_avec(&livree, &retrait_apres).is_empty());
    let retrait_avant = tries(
        ("packaging/systemd/service.d/20-donne.conf", &donne),
        (
            "packaging/systemd/bifrost-daemon.service.d/10-retire.conf",
            &retire,
        ),
    );
    assert!(!rend_cap_sys_admin_avec(&livree, &retrait_avant).is_empty());
}

/// Les deux autres gardes du fichier lisent aussi les drop-ins: la ligne
/// retiree le 23/08/2026 remise par un drop-in, ou une capacite ajoutee par un
/// drop-in sans dire a quoi elle sert, sont vues; la deviation des bancs et
/// une capacite justifiee dans son drop-in restent vertes. Falsification en
/// dur, gardee pour toujours.
///
/// Releve du 30/09/2026 sur `essai-linux`: quand seule la garde de
/// CAP_SYS_ADMIN composait les drop-ins, ces deux drop-ins-la laissaient toute
/// la suite verte.
#[test]
fn un_drop_in_qui_desarme_ou_ajoute_une_capacite_muette_est_vu() {
    let livree = unite();
    let dans = |texte: &str| {
        vec![(
            "packaging/systemd/bifrost-daemon.service.d/50-essai.conf".to_owned(),
            texte.to_owned(),
        )]
    };
    assert_eq!(desarmements_avec(&livree, &[]), Vec::<String>::new());
    assert_eq!(
        ecarts_de_justification_avec(&livree, &[]),
        Vec::<String>::new()
    );

    let desarme = dans("[Service]\nExecStopPost=-/usr/bin/bifrost-daemon --cleanup-firewall\n");
    let vus = desarmements_avec(&livree, &desarme);
    assert!(
        vus.iter()
            .any(|v| v.starts_with("packaging/systemd/bifrost-daemon.service.d/50-essai.conf, ")),
        "un drop-in qui desarme a l'arret doit etre vu, et nomme: {vus:?}"
    );
    let banc = dans("[Service]\nNetworkNamespacePath=/run/netns/essai\n");
    assert_eq!(desarmements_avec(&livree, &banc), Vec::<String>::new());
    assert_eq!(
        ecarts_de_justification_avec(&livree, &banc),
        Vec::<String>::new()
    );

    // CAP_NET_RAW, retiree du service avec CAP_SYS_ADMIN.
    let muette =
        dans("[Service]\nCapabilityBoundingSet=CAP_NET_RAW\nAmbientCapabilities=CAP_NET_RAW\n");
    let ecarts = ecarts_de_justification_avec(&livree, &muette);
    assert!(
        ecarts.iter().any(|e| e.contains("CAP_NET_RAW")),
        "une capacite ajoutee par un drop-in sans justification doit rougir: {ecarts:?}"
    );
    let justifiee = dans(
        "[Service]\n# CAP_NET_RAW pour un essai.\n\
         CapabilityBoundingSet=CAP_NET_RAW\nAmbientCapabilities=CAP_NET_RAW\n",
    );
    assert_eq!(
        ecarts_de_justification_avec(&livree, &justifiee),
        Vec::<String>::new()
    );
}

/// La garde lit l'unite que l'installateur pose, et rien d'autre n'est pose.
///
/// # Pourquoi l'installateur, et pas seulement les fichiers
///
/// Un drop-in ne compte que s'il est pose, et ce depot en ecrit deja: les
/// bancs `service-systemd-linux.sh` et `mort-daemon-systemd-linux.sh` posent
/// le leur EN LIGNE, par `cat <<`, sans aucun fichier sous `packaging/`. Une
/// garde qui ne lirait que les fichiers laisserait passer la meme forme dans
/// `install-linux.sh`. Celle-ci lit donc ce que l'installateur pose dans la
/// configuration de systemd, lui et chaque script qu'il source ou lance, et exige que
/// ce soit une copie d'un fichier que les gardes voisines evaluent.
#[test]
fn l_installateur_ne_pose_que_ce_que_la_garde_lit() {
    let (drop_ins, _) = drop_ins_livres();
    let (scripts, introuvables) = scripts_de_l_installateur();
    assert!(
        introuvables.is_empty(),
        "l'installateur, ou un script qu'il source ou lance, est introuvable, donc lu par \
         aucune garde: {introuvables:?}"
    );
    let mut lues = Vec::new();
    let mut illisibles = Vec::new();
    for (chemin, texte) in &scripts {
        let (l, i) = poses_de_l_installateur(texte, &drop_ins);
        lues.extend(l);
        illisibles.extend(i.into_iter().map(|ligne| format!("{chemin}, {ligne}")));
    }
    assert!(
        illisibles.is_empty(),
        "l'installateur touche a la configuration de systemd par une ligne qu'aucune \
         garde n'evalue:\n  {}\n\
         Une unite ou un drop-in se pose par `install \"$ICI/...\" DESTINATION`, depuis \
         packaging/, pour que unite_systemd.rs evalue ce que le service recevra.",
        illisibles.join("\n  ")
    );
    let unite_posee = format!("/{NOM_DE_L_UNITE}");
    assert!(
        lues.iter().any(|l| l.ends_with(&unite_posee)),
        "packaging/install-linux.sh ne pose plus {UNITE_LIVREE} sous le nom \
         {NOM_DE_L_UNITE}: les gardes liraient un fichier que personne n'installe. \
         Lu: {lues:?}"
    );
}

/// Chaque pose que la garde ne sait pas lire est vue, et ce qui ne touche pas
/// a la configuration d'un service reste vert. Falsification en dur, gardee
/// pour toujours.
#[test]
fn une_pose_que_la_garde_ne_lit_pas_est_vue() {
    let lus = [(
        "packaging/systemd/bifrost-daemon.service.d/50-essai.conf".to_owned(),
        "[Service]\n".to_owned(),
    )];
    // La forme de l'installateur, continuation `\` comprise.
    let aujourd_hui = "install -D -m 0644 \"$ICI/systemd/bifrost-daemon.service\" \\\n\
                       /etc/systemd/system/bifrost-daemon.service\n";
    let (lues, illisibles) = poses_de_l_installateur(aujourd_hui, &lus);
    assert_eq!(
        (lues.len(), illisibles.len()),
        (1, 0),
        "la pose d'aujourd'hui doit etre lue: {illisibles:?}"
    );
    let drop_in_lu = "install -D -m 0644 \
                      \"$ICI/systemd/bifrost-daemon.service.d/50-essai.conf\" \
                      /etc/systemd/system/bifrost-daemon.service.d/50-essai.conf\n";
    let (lues, illisibles) = poses_de_l_installateur(drop_in_lu, &lus);
    assert_eq!(
        (lues.len(), illisibles.len()),
        (1, 0),
        "un drop-in livre, pose a sa place, doit etre lu: {illisibles:?}"
    );
    for (nom, ligne) in [
        (
            "un drop-in ecrit en ligne",
            "cat > /etc/systemd/system/bifrost-daemon.service.d/10-check.conf <<CONF",
        ),
        (
            "un drop-in ecrit par tee",
            "echo AmbientCapabilities=CAP_SYS_ADMIN | tee -a /run/systemd/system/bifrost-daemon.service.d/x.conf",
        ),
        (
            "un drop-in de prefixe",
            "cp \"$ICI/x.conf\" /etc/systemd/system/bifrost-.service.d/x.conf",
        ),
        (
            "un drop-in de type, pose depuis packaging/",
            "install -D -m 0644 \"$ICI/y.conf\" /etc/systemd/system/service.d/y.conf",
        ),
        (
            "un drop-in que la garde ne lit pas",
            "install -D -m 0644 \"$ICI/ailleurs/60-x.conf\" \
             /etc/systemd/system/bifrost-daemon.service.d/60-x.conf",
        ),
        (
            "une propriete posee par systemctl",
            "systemctl set-property bifrost-daemon.service AmbientCapabilities=CAP_SYS_ADMIN",
        ),
        (
            "un drop-in edite par systemctl",
            "systemctl edit bifrost-daemon",
        ),
        (
            "une autre unite posee sous le meme nom",
            "install -D -m 0644 \"$ICI/systemd/autre.service\" \
             /etc/systemd/system/bifrost-daemon.service",
        ),
        (
            "une unite venue d'ailleurs",
            "install -D -m 0644 /tmp/bifrost-daemon.service /usr/lib/systemd/system/bifrost-daemon.service",
        ),
        (
            "un repertoire d'unites range dans une variable",
            "UNITES=/usr/lib/systemd/system",
        ),
        (
            "un generateur",
            "install -D -m 0755 \"$ICI/gen\" /usr/lib/systemd/system-generators/bifrost",
        ),
    ] {
        let (_, illisibles) = poses_de_l_installateur(&format!("{aujourd_hui}{ligne}\n"), &lus);
        assert!(
            !illisibles.is_empty(),
            "pose non vue par la garde ({nom}): {ligne}"
        );
    }
    for ligne in [
        "HOOK_VEILLE_INSTALLE=/usr/lib/systemd/system-sleep/bifrost-reprise",
        "install -D -m 0644 \"$DECLARATION\" /usr/lib/sysusers.d/bifrost.conf",
        "systemctl daemon-reload",
        "systemctl enable --now bifrost-daemon",
        "# cat > /etc/systemd/system/bifrost-daemon.service.d/x.conf",
    ] {
        let (_, illisibles) = poses_de_l_installateur(&format!("{aujourd_hui}{ligne}\n"), &lus);
        assert!(
            illisibles.is_empty(),
            "ligne lue a tort comme une pose: {ligne}\n{illisibles:?}"
        );
    }
    // Un script source ou lance est suivi: une pose qu'il ferait serait celle
    // de l'installateur. Un fichier hors du depot ne l'est pas, faute de texte,
    // ni un fichier de packaging/ que l'installateur ne fait que copier.
    for (ligne, attendus) in [
        (". \"$ICI/comptes.sh\"", vec!["packaging/comptes.sh"]),
        ("source \"${ICI}/autre\"", vec!["packaging/autre"]),
        ("bash \"$ICI/poser.sh\" --tout", vec!["packaging/poser.sh"]),
        ("\"$ICI/poser.sh\"", vec!["packaging/poser.sh"]),
        ("POSEUR=\"$ICI/poser.sh\"", vec!["packaging/poser.sh"]),
        (". /etc/os-release", vec![]),
        (
            "install -D -m 0644 \"$ICI/systemd/bifrost-daemon.service\" /etc/systemd/system/x",
            vec![],
        ),
    ] {
        assert_eq!(scripts_nommes(ligne), attendus, "{ligne}");
    }
}
