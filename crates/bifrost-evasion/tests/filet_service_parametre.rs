//! Les chemins du filet de `scripts/service-windows.ps1` restent en parametre,
//! derives de la racine du banc.
//!
//! # Pourquoi cette recette existe
//!
//! Le banc `service-windows.ps1` arme deux filets avant de couper le reseau: un
//! `.cmd` de nettoyage pose en tache planifiee, et le `.log` ou il ecrit. Les
//! deux vivaient en dur sous une racine de banc absolue, un reliquat du banc
//! d'essai. Un editeur qui installe le service ailleurs les voudrait ailleurs,
//! et rien ne l'avertissait qu'il fallait toucher deux lignes enfouies au
//! milieu du script.
//!
//! L'arbitrage 8 (option A), rendu le 05/09/2026, a mis ces deux chemins en
//! parametre. L'arbitrage 8 (option B), rendu le 06/09/2026, les derive
//! desormais de `$Banc`, la racine du banc: le litteral absolu a disparu du
//! depot et la valeur par defaut suit le repertoire du script. Cette recette
//! garde la CLASSE que les deux arbitrages visent - un chemin du filet code en
//! dur hors du bloc `param()` - et non une ligne precise: la seule place ou un
//! chemin du filet a le droit de paraitre est la ligne de valeur par defaut de
//! son parametre, et cette valeur derive de `$Banc`.
//!
//! # Ce qu'elle ne fait pas
//!
//! Elle ne lit qu'un script, sur le disque et sans git: sur essai-linux le
//! depot est copie par `tar` et n'a pas de `.git`. Une recette qui appellerait
//! `git ls-files` s'y abstiendrait a chaque passage, et une recette qui ne
//! s'execute que sur une machine sur deux ne garde rien.

use std::path::PathBuf;

fn racine() -> PathBuf {
    // Meme idiome que `caracteres_de_controle.rs` et ses voisines:
    // `CARGO_MANIFEST_DIR` pointe sur crates/bifrost-evasion, la racine de
    // l'espace de travail est deux crans au-dessus.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("la racine de l'espace de travail doit exister")
        .to_path_buf()
}

const SCRIPT: &str = "scripts/service-windows.ps1";

/// Les deux parametres du filet, et le segment relatif que chacun porte.
///
/// Le segment est ce qui reste du chemin une fois la racine du banc otee: c'est
/// lui qui ne doit paraitre QUE sur la ligne de valeur par defaut du parametre.
const FILETS: [(&str, &str); 2] = [
    ("[string]$FiletCmd", "service-filet.cmd"),
    ("[string]$FiletLog", "service-filet.log"),
];

/// Sans espaces, pour reconnaitre une declaration quel que soit l'espacement:
/// `[string]$FiletCmd` comme `[string] $FiletCmd`.
fn sans_espaces(ligne: &str) -> String {
    ligne.chars().filter(|c| !c.is_whitespace()).collect()
}

#[test]
fn chaque_chemin_du_filet_est_un_parametre_derive_du_banc() {
    let chemin = racine().join(SCRIPT);
    let texte = std::fs::read_to_string(&chemin)
        .unwrap_or_else(|e| panic!("{} illisible: {e}", chemin.display()));

    // Controle positif: sans lui, une lecture qui echoue en silence ou un
    // script vide rendrait la recette verte sans avoir rien regarde. On exige
    // le bloc param() et les deux parametres du filet.
    assert!(
        texte.contains("param(")
            && texte.contains("[string]$FiletCmd")
            && texte.contains("[string]$FiletLog"),
        "{SCRIPT} ne porte plus le bloc param() ou les parametres du filet: la \
         recette ne verifie plus rien"
    );

    for (prefixe, segment) in FILETS {
        let mut hors_parametre = Vec::new();
        let mut sur_parametre = 0usize;
        for (rang, ligne) in texte.lines().enumerate() {
            if !ligne.contains(segment) {
                continue;
            }
            let compacte = sans_espaces(ligne);
            if compacte.starts_with(prefixe) {
                // Sur la ligne du parametre, le chemin doit derive de $Banc:
                // c'est ce qui garde le litteral absolu hors du depot tout en
                // preservant le comportement par defaut du banc.
                assert!(
                    ligne.contains("Join-Path $Banc"),
                    "{SCRIPT}:{}: {segment} est sur la ligne du parametre {prefixe}, mais \
                     sa valeur par defaut ne derive pas de $Banc (Join-Path $Banc absent). \
                     L'arbitrage 8B veut la racine du banc, pas un chemin fige:\n  {}",
                    rang + 1,
                    ligne.trim()
                );
                sur_parametre += 1;
            } else {
                hors_parametre.push(format!("{SCRIPT}:{}: {}", rang + 1, ligne.trim()));
            }
        }

        // Le coeur de la recette: chaque occurrence hors de la declaration du
        // parametre est un chemin du filet code en dur, la classe meme que
        // l'arbitrage 8 interdit.
        assert!(
            hors_parametre.is_empty(),
            "chemin du filet code en dur hors du bloc param() dans {SCRIPT}. \
             L'arbitrage 8 veut ces chemins en parametre, derives de $Banc; leur \
             seule place est la ligne de valeur par defaut du parametre:\n  {}",
            hors_parametre.join("\n  ")
        );

        // Et le segment doit paraitre une seule fois, sur la ligne du parametre:
        // c'est ce qui garde le comportement par defaut identique a celui du banc.
        assert_eq!(
            sur_parametre, 1,
            "{SCRIPT} devrait porter {segment} une seule fois, sur la ligne de \
             valeur par defaut de son parametre {prefixe}; trouve {sur_parametre} fois"
        );
    }
}
