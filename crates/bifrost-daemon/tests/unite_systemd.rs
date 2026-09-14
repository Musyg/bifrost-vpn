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
