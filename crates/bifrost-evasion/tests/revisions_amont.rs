//! Les exceptions cargo-vet des sources Git portent une revision precise.
//! cargo-vet peut accepter une politique versionnee devenue inutilisee: cette
//! garde relie donc explicitement chaque source Git du verrou a sa politique.
//! Elle ne transforme pas ces exceptions temporaires en audits de code.

use std::collections::BTreeSet;

fn champ<'a>(bloc: &'a str, nom: &str) -> Result<&'a str, String> {
    let prefixe = format!("{nom} = \"");
    let valeurs: Vec<_> = bloc
        .lines()
        .filter_map(|l| l.strip_prefix(&prefixe).and_then(|v| v.strip_suffix('"')))
        .collect();
    match valeurs.as_slice() {
        [valeur] => Ok(valeur),
        _ => Err(format!("champ {nom} absent ou multiple")),
    }
}

fn revisions(verrou: &str) -> Result<BTreeSet<String>, String> {
    let mut resultat = BTreeSet::new();
    for paquet in verrou.split("[[package]]").skip(1) {
        let Ok(source) = champ(paquet, "source") else {
            continue;
        };
        if !source.starts_with("git+") {
            continue;
        }
        let (url, sha) = source.rsplit_once('#').ok_or("revision Git absente")?;
        if sha.len() != 40 || !sha.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("revision Git incomplete".into());
        }
        if !url.ends_with(&format!("?rev={sha}")) {
            return Err("la revision demandee doit egaler le commit verrouille".into());
        }
        let nom = champ(paquet, "name")?;
        let version = champ(paquet, "version")?;
        resultat.insert(format!("{nom}:{version}@git:{sha}"));
    }
    Ok(resultat)
}

fn verifier(racine: &str, fuzz: &str, config: &str) -> Result<(), String> {
    let attendues = revisions(racine)?;
    let declarees: BTreeSet<_> = config
        .lines()
        .filter_map(|l| {
            l.strip_prefix("[policy.\"")
                .and_then(|v| v.strip_suffix("\"]"))
        })
        .filter(|cle| cle.contains("@git:"))
        .map(str::to_owned)
        .collect();
    if attendues != declarees {
        return Err("les revisions Git du verrou et des politiques cargo-vet different".into());
    }
    if !revisions(fuzz)?.is_subset(&declarees) {
        return Err("le fuzzing emploie une revision Git non couverte".into());
    }
    Ok(())
}

const RACINE: &str = include_str!("../../../Cargo.lock");
const FUZZ: &str = include_str!("../../../fuzz/Cargo.lock");
const CONFIG: &str = include_str!("../../../supply-chain/config.toml");

#[test]
fn les_exceptions_git_couvrent_exactement_les_revisions_livrees() {
    verifier(RACINE, FUZZ, CONFIG).expect("exceptions Git a mettre a jour explicitement");
}

#[test]
fn une_revision_changee_ou_une_exception_absente_rougit() {
    for cle in revisions(RACINE).unwrap() {
        let sha = cle.rsplit_once(':').unwrap().1;
        let faux = "0000000000000000000000000000000000000000";
        assert_ne!(sha, faux);
        assert!(verifier(&RACINE.replace(sha, faux), FUZZ, CONFIG).is_err());
        assert!(verifier(RACINE, &FUZZ.replace(sha, faux), CONFIG).is_err());
        assert!(verifier(RACINE, FUZZ, &CONFIG.replace(&cle, "exception-retiree")).is_err());
        assert!(verifier(RACINE, FUZZ, &CONFIG.replace(sha, faux)).is_err());
    }
    // Les formes flottantes doivent echouer, meme si le commit est verrouille.
    let flottant = RACINE.replace("?rev=", "?branch=");
    assert!(verifier(&flottant, FUZZ, CONFIG).is_err());
    // Revenir au registre retire aussi les exceptions Git; aucun maintien force.
    assert!(verifier("", "", "").is_ok());
    assert!(verifier("", "", CONFIG).is_err());
}
