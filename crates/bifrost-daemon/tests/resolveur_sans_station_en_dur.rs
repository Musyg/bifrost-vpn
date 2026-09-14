//! Invariants de SOURCE du resolveur: ce que `src/resolveur.rs` ne doit plus
//! porter, garde sur le disque, sans jugement.
//!
//! Deux gardes. La premiere (ecart 1, relance du 06/09/2026): le nom de la
//! window-station interactive n'est plus code en dur. La seconde (11b-2,
//! 13/09/2026): `dwCreationFlags` de `CreateProcessAsUserW` reste 0, donc
//! jamais `CREATE_BREAKAWAY_FROM_JOB`, l'invariant anti-orphelin de la forme
//! alpha; jusqu'ici il n'etait mesure qu'a l'execution, sur essai-windows.
//!
//! # Pourquoi la premiere recette existe (ecart 1, relance du 06/09/2026)
//!
//! `demarrer_sous_compte` posait l'ACE d'acces sur la window-station et le
//! desktop DU DAEMON (`GetProcessWindowStation` / `GetThreadDesktop`), mais
//! envoyait l'enfant sur le litteral de la window-station interactive via
//! `lpDesktop`. Les deux ne coincident que si le daemon est deja sur cette
//! station. Or en production le daemon est un service non interactif, qui recoit
//! sa PROPRE station (cf. « Window Station and Desktop Creation »,
//! learn.microsoft.com, ms.date 2018-05-31): l'ACE tombait alors sur un objet et
//! l'enfant etait envoye sur un autre, et le 0xC0000142 revenait.
//!
//! La correction (forme A) laisse `lpDesktop` NUL: l'enfant herite de la
//! window-station ET du desktop du parent (doc `CreateProcessAsUserW`,
//! learn.microsoft.com, ms.date 2018-12-05), donc exactement les objets ou l'ACE
//! est posee. Coherence par construction, plus aucun nom code en dur. Cette
//! recette garde l'invariant: le litteral de la station interactive ne doit plus
//! reapparaitre dans `resolveur.rs`, sous aucune casse.
//!
//! # Ce qu'elle ne fait pas
//!
//! Elle ne mesure pas l'effet a l'execution (0xC0000142, heritage reel de la
//! station): cela reste a l'orchestrateur sur essai-windows. Elle garde la
//! propriete de SOURCE, sur le disque, sans jugement.

use std::path::PathBuf;

/// `src/resolveur.rs`, relatif au manifeste de la crate bifrost-daemon.
fn source_du_resolveur() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("resolveur.rs")
}

/// Le nom de la station interactive, en fragments, jamais colle: le token
/// "station interactive + chiffre" ne doit pas apparaitre ENTIER dans la source
/// de cette recette, sans quoi un balayage futur du depot s'y accrocherait.
/// Concatene, en minuscules, il vaut le nom de la window-station historique.
fn aiguille() -> Vec<u8> {
    [b"winsta".as_slice(), b"0".as_slice()].concat()
}

#[test]
fn resolveur_ne_code_plus_la_station_interactive_en_dur() {
    let chemin = source_du_resolveur();
    let octets =
        std::fs::read(&chemin).unwrap_or_else(|e| panic!("{} illisible: {e}", chemin.display()));

    // Controle positif: une lecture qui echouerait en silence, ou un mauvais
    // chemin, rendrait un tampon vide - donc un succes sans avoir rien verifie.
    assert!(
        octets.len() > 1000,
        "resolveur.rs ne fait que {} octet(s): la recette ne verifie rien",
        octets.len()
    );

    let bas: Vec<u8> = octets.iter().map(|o| o.to_ascii_lowercase()).collect();
    let aiguille = aiguille();
    let present = bas
        .windows(aiguille.len())
        .any(|fenetre| fenetre == aiguille.as_slice());

    assert!(
        !present,
        "le nom de la window-station interactive est code en dur dans {}: \
         l'ACE serait posee sur un objet et l'enfant envoye sur un autre. \
         Laisser lpDesktop NUL (heritage du parent), sans aucun litteral.",
        chemin.display()
    );
}

/// Vrai si la ligne, une fois debarrassee de ses blancs de tete, est un
/// commentaire (`//`, `///` ou `//!`). Les commentaires ont le droit de NOMMER
/// le drapeau interdit pour dire qu'on ne le pose pas; seul le code compte.
fn est_un_commentaire(ligne: &str) -> bool {
    ligne.trim_start().starts_with("//")
}

/// 11b-2. `CreateProcessAsUserW` est appele avec `dwCreationFlags = 0`: jamais
/// `CREATE_BREAKAWAY_FROM_JOB`, ni sous son nom ni sous sa valeur numerique
/// (`0x01000000`, soit 16777216). Un enfant qui s'echapperait du job survivrait
/// a la mort du daemon et garderait le :53, exactement ce que le job existe
/// pour empecher. L'invariant n'etait garde qu'a l'execution (sonde
/// essai-windows du 06/09/2026); il l'est ici a la source, sur les deux hotes.
///
/// Controle positif en deux temps: le fichier est lu (plus de 1000 octets) ET
/// l'appel `CreateProcessAsUserW(` figure hors commentaire, sans quoi une
/// source ou l'appel aurait disparu rendrait un vert sans rien garder.
#[test]
fn resolveur_ne_pose_jamais_create_breakaway_from_job() {
    let chemin = source_du_resolveur();
    let texte = std::fs::read_to_string(&chemin)
        .unwrap_or_else(|e| panic!("{} illisible: {e}", chemin.display()));

    assert!(
        texte.len() > 1000,
        "resolveur.rs ne fait que {} octet(s): la recette ne verifie rien",
        texte.len()
    );
    let code: Vec<(usize, &str)> = texte
        .lines()
        .enumerate()
        .filter(|(_, l)| !est_un_commentaire(l))
        .map(|(i, l)| (i + 1, l))
        .collect();
    assert!(
        code.iter()
            .any(|(_, l)| l.contains("CreateProcessAsUserW(")),
        "aucun appel CreateProcessAsUserW( hors commentaire dans {}: la garde \
         ne regarde plus le bon fichier",
        chemin.display()
    );

    // Le nom du drapeau, et ses trois ecritures numeriques (avec separateur
    // de lisibilite, sans, et en decimal).
    let interdits = [
        "CREATE_BREAKAWAY_FROM_JOB",
        "0x0100_0000",
        "0x01000000",
        "16777216",
    ];
    for (numero, ligne) in &code {
        for motif in interdits {
            assert!(
                !ligne.contains(motif),
                "{}:{numero} porte {motif} hors commentaire: dwCreationFlags doit \
                 rester 0, l'enfant doit rester dans le job du daemon. Ligne: {}",
                chemin.display(),
                ligne.trim()
            );
        }
    }
}
