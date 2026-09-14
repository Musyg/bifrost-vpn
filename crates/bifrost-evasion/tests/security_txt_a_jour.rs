//! `packaging/security.txt` et `SECURITY.md` restent vrais, et coherents entre
//! eux, pas seulement le jour ou on les ecrit.
//!
//! # Pourquoi cette recette existe
//!
//! La politique de signalement de vulnerabilites de Bifrost fixe le canal: un
//! alias sur le domaine de l'editeur, `security@inaricom.com`, un `security.txt`
//! RFC 9116 servi par le site de l'editeur, un `SECURITY.md` dans le depot qui y
//! renvoie, et - pour l'instant - aucune cle PGP publiee. Deux fichiers ecrits a
//! la main, qui peuvent deriver:
//!
//! 1. le champ `Expires` d'un `security.txt` se perime en silence; la RFC 9116
//!    veut une date future, sous un an. Une garde qui refuse une date passee est
//!    exactement ce que cette politique demande: une garde de source qui refuse
//!    une date passee;
//! 2. l'adresse de contact peut changer d'un cote et pas de l'autre;
//! 3. le jour ou une cle PGP existera, l'un des deux fichiers peut l'annoncer
//!    sans que l'autre suive: un `Encryption` sans cle joignable, ou une cle
//!    annoncee dans `SECURITY.md` que `security.txt` ne pointe pas.
//!
//! # Ce qu'elle verifie
//!
//! - `security.txt` porte `Contact: mailto:security@inaricom.com`;
//! - il porte un `Expires` analysable, unique, situe entre 30 et 365 jours de
//!   maintenant (rouge sinon, avec la date lue et la date du jour);
//! - il porte `Preferred-Languages`;
//! - il ne porte `Encryption` que si `SECURITY.md` declare une cle, et l'inverse:
//!   les deux fichiers doivent dire la meme chose de la cle;
//! - `SECURITY.md` contient l'adresse de contact.
//!
//! # Ce qu'elle ne fait pas
//!
//! Elle ne juge pas la politique de divulgation, ni les delais annonces (valeurs
//! proposees, a confirmer). Elle garde les proprietes verifiables sans jugement.
//!
//! # Sans dependance de date
//!
//! `bifrost-evasion` ne depend ni de `chrono` ni de `time` (voir son
//! `Cargo.toml`). Le calcul des jours se fait donc sur `SystemTime::now()` et une
//! conversion civile ecrite ici (algorithme de Howard Hinnant, calendrier
//! gregorien proleptique), avec sa propre recette unitaire sur trois dates
//! connues. La recette n'utilise aucun `cfg`: elle compile et tourne a
//! l'identique sur Linux et sur Windows.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn racine() -> PathBuf {
    // Meme idiome que `suivi_a_jour.rs` et `sources_ascii.rs`:
    // `CARGO_MANIFEST_DIR` pointe sur crates/bifrost-evasion, la racine de
    // l'espace de travail est deux crans au-dessus.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("la racine de l'espace de travail doit exister")
        .to_path_buf()
}

fn lire(relatif: &str) -> String {
    let chemin = racine().join(relatif);
    std::fs::read_to_string(&chemin)
        .unwrap_or_else(|e| panic!("{} illisible: {e}", chemin.display()))
}

const SECURITY_TXT: &str = "packaging/security.txt";
const SECURITY_MD: &str = "SECURITY.md";
const ADRESSE: &str = "security@inaricom.com";
const CONTACT_ATTENDU: &str = "mailto:security@inaricom.com";

/// La fenetre de validite exigee pour `Expires`, en jours. La RFC 9116
/// recommande moins d'un an; le plancher de 30 jours force le renouvellement
/// avant l'echeance.
const FENETRE_MIN: i64 = 30;
const FENETRE_MAX: i64 = 365;

/// Les champs (nom en minuscules, valeur) d'un `security.txt`, commentaires et
/// lignes vides exclus.
///
/// La RFC 9116 rend les noms de champ insensibles a la casse et fait des lignes
/// commencant par `#` des commentaires. Le decoupage se fait sur le PREMIER
/// deux-points seulement, pour que la valeur d'`Expires`
/// (`2027-07-01T00:00:00Z`, qui en contient) reste entiere.
fn champs(texte: &str) -> Vec<(String, String)> {
    let mut sortie = Vec::new();
    for ligne in texte.lines() {
        let ligne = ligne.trim();
        if ligne.is_empty() || ligne.starts_with('#') {
            continue;
        }
        if let Some((nom, valeur)) = ligne.split_once(':') {
            sortie.push((nom.trim().to_lowercase(), valeur.trim().to_string()));
        }
    }
    sortie
}

/// Jours civils depuis l'epoque Unix (1970-01-01), calendrier gregorien
/// proleptique. Algorithme `days_from_civil` de Howard Hinnant.
fn jours_depuis_epoque(annee: i64, mois: i64, jour: i64) -> i64 {
    let annee = if mois <= 2 { annee - 1 } else { annee };
    let ere = (if annee >= 0 { annee } else { annee - 399 }) / 400;
    let annee_de_l_ere = annee - ere * 400; // [0, 399]
    let mois_decale = if mois > 2 { mois - 3 } else { mois + 9 };
    let jour_de_l_annee = (153 * mois_decale + 2) / 5 + jour - 1; // [0, 365]
    let jour_de_l_ere =
        annee_de_l_ere * 365 + annee_de_l_ere / 4 - annee_de_l_ere / 100 + jour_de_l_annee;
    ere * 146097 + jour_de_l_ere - 719468
}

/// L'inverse: (annee, mois, jour) depuis un compte de jours civils. Algorithme
/// `civil_from_days` de Howard Hinnant. Sert a rendre la date du jour lisible
/// dans le message d'echec.
fn civil_depuis_jours(jours: i64) -> (i64, i64, i64) {
    let jours = jours + 719468;
    let ere = (if jours >= 0 { jours } else { jours - 146096 }) / 146097;
    let jour_de_l_ere = jours - ere * 146097; // [0, 146096]
    let annee_de_l_ere = (jour_de_l_ere - jour_de_l_ere / 1460 + jour_de_l_ere / 36524
        - jour_de_l_ere / 146096)
        / 365; // [0, 399]
    let annee = annee_de_l_ere + ere * 400;
    let jour_de_l_annee =
        jour_de_l_ere - (365 * annee_de_l_ere + annee_de_l_ere / 4 - annee_de_l_ere / 100); // [0, 365]
    let mois_decale = (5 * jour_de_l_annee + 2) / 153; // [0, 11]
    let jour = jour_de_l_annee - (153 * mois_decale + 2) / 5 + 1; // [1, 31]
    let mois = if mois_decale < 10 {
        mois_decale + 3
    } else {
        mois_decale - 9
    }; // [1, 12]
    let annee = if mois <= 2 { annee + 1 } else { annee };
    (annee, mois, jour)
}

/// Le compte de jours civils d'aujourd'hui, depuis l'horloge systeme.
fn aujourd_hui_en_jours() -> i64 {
    let secondes = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("l'horloge systeme est anterieure a l'epoque Unix")
        .as_secs();
    (secondes / 86_400) as i64
}

/// Extrait (annee, mois, jour) d'une valeur `Expires` au format RFC 3339
/// (`2027-07-01T00:00:00Z`). Rend une explication en cas d'echec.
fn date_de_expires(valeur: &str) -> Result<(i64, i64, i64), String> {
    let octets = valeur.as_bytes();
    // Le separateur date/heure est 'T' en position 10: AAAA-MM-JJT...
    if octets.len() < 11 || octets[10] != b'T' {
        return Err(format!(
            "{valeur:?}: pas au format date-heure RFC 3339 (attendu AAAA-MM-JJThh:mm:ssZ)"
        ));
    }
    let date = &valeur[..10];
    let parties: Vec<&str> = date.split('-').collect();
    if parties.len() != 3 || parties[0].len() != 4 || parties[1].len() != 2 || parties[2].len() != 2
    {
        return Err(format!("{valeur:?}: partie date {date:?} malformee"));
    }
    let annee: i64 = parties[0]
        .parse()
        .map_err(|_| format!("{valeur:?}: annee illisible"))?;
    let mois: i64 = parties[1]
        .parse()
        .map_err(|_| format!("{valeur:?}: mois illisible"))?;
    let jour: i64 = parties[2]
        .parse()
        .map_err(|_| format!("{valeur:?}: jour illisible"))?;
    if !(1..=12).contains(&mois) {
        return Err(format!("{valeur:?}: mois {mois} hors de [1, 12]"));
    }
    if !(1..=31).contains(&jour) {
        return Err(format!("{valeur:?}: jour {jour} hors de [1, 31]"));
    }
    // Une zone doit clore l'horodatage: 'Z', ou un decalage +hh:mm / -hh:mm.
    let reste = &valeur[11..];
    let a_zone =
        reste.ends_with('Z') || reste.ends_with('z') || reste.contains('+') || reste.contains('-');
    if !a_zone {
        return Err(format!(
            "{valeur:?}: pas de zone (Z ou decalage) apres l'heure"
        ));
    }
    Ok((annee, mois, jour))
}

/// L'etat de la cle de chiffrement declare par `SECURITY.md`, via un jeton
/// unique. Deux jetons possibles, mutuellement exclusifs.
#[derive(Debug, PartialEq)]
enum EtatCle {
    Absente,
    Presente,
}

fn etat_cle_du_md(md: &str) -> EtatCle {
    let a_absente = md.contains("CLE-PGP=absente");
    let a_presente = md.contains("CLE-PGP=presente");
    match (a_absente, a_presente) {
        (true, false) => EtatCle::Absente,
        (false, true) => EtatCle::Presente,
        (true, true) => panic!(
            "{SECURITY_MD}: les jetons CLE-PGP=absente et CLE-PGP=presente sont \
             tous deux presents; l'etat de la cle est ambigu, la coherence avec \
             {SECURITY_TXT} ne peut pas etre verifiee"
        ),
        (false, false) => panic!(
            "{SECURITY_MD}: aucun jeton CLE-PGP=absente ni CLE-PGP=presente; \
             sans lui, la coherence Encryption avec {SECURITY_TXT} ne peut pas \
             etre verifiee"
        ),
    }
}

#[test]
fn le_contact_est_l_alias_de_l_editeur() {
    let txt = lire(SECURITY_TXT);
    let champs = champs(&txt);
    let contacts: Vec<&String> = champs
        .iter()
        .filter(|(nom, _)| nom == "contact")
        .map(|(_, valeur)| valeur)
        .collect();
    assert!(
        !contacts.is_empty(),
        "{SECURITY_TXT}: aucun champ Contact, obligatoire en RFC 9116"
    );
    assert!(
        contacts.iter().any(|v| v.as_str() == CONTACT_ATTENDU),
        "{SECURITY_TXT}: aucun Contact `{CONTACT_ATTENDU}`. Contacts lus: \
         {contacts:?}. La politique de signalement fixe l'alias `{ADRESSE}` sur \
         le domaine de l'editeur."
    );
}

#[test]
fn expires_est_analysable_et_dans_la_fenetre() {
    let txt = lire(SECURITY_TXT);
    let champs = champs(&txt);
    let expires: Vec<&String> = champs
        .iter()
        .filter(|(nom, _)| nom == "expires")
        .map(|(_, valeur)| valeur)
        .collect();
    assert_eq!(
        expires.len(),
        1,
        "{SECURITY_TXT}: le champ Expires doit apparaitre exactement une fois \
         (RFC 9116); {} trouve(s)",
        expires.len()
    );
    let valeur = expires[0];
    let (annee, mois, jour) =
        date_de_expires(valeur).unwrap_or_else(|e| panic!("{SECURITY_TXT}: Expires {e}"));
    let echeance = jours_depuis_epoque(annee, mois, jour);
    let aujourd_hui = aujourd_hui_en_jours();
    let delta = echeance - aujourd_hui;
    let (ay, am, aj) = civil_depuis_jours(aujourd_hui);
    assert!(
        (FENETRE_MIN..=FENETRE_MAX).contains(&delta),
        "{SECURITY_TXT}: Expires lue = {valeur} ({annee:04}-{mois:02}-{jour:02}), \
         date du jour = {ay:04}-{am:02}-{aj:02}, soit {delta} jour(s) d'ici \
         l'echeance. La fenetre exigee est [{FENETRE_MIN}, {FENETRE_MAX}] jours: \
         sous {FENETRE_MIN}, renouveler (cf. packaging/SECURITY-TXT.md); au-dela \
         de {FENETRE_MAX}, la RFC 9116 recommande moins d'un an."
    );
}

#[test]
fn preferred_languages_est_present() {
    let txt = lire(SECURITY_TXT);
    let champs = champs(&txt);
    let langues: Vec<&String> = champs
        .iter()
        .filter(|(nom, _)| nom == "preferred-languages")
        .map(|(_, valeur)| valeur)
        .collect();
    assert_eq!(
        langues.len(),
        1,
        "{SECURITY_TXT}: Preferred-Languages doit apparaitre exactement une fois \
         (RFC 9116); {} trouve(s)",
        langues.len()
    );
    assert!(
        !langues[0].is_empty(),
        "{SECURITY_TXT}: Preferred-Languages est vide"
    );
}

#[test]
fn encryption_coherent_avec_l_etat_de_la_cle() {
    let txt = lire(SECURITY_TXT);
    let md = lire(SECURITY_MD);
    let a_encryption = champs(&txt).iter().any(|(nom, _)| nom == "encryption");
    match etat_cle_du_md(&md) {
        EtatCle::Absente => assert!(
            !a_encryption,
            "{SECURITY_MD} declare qu'aucune cle n'est publiee (CLE-PGP=absente), \
             mais {SECURITY_TXT} porte un champ Encryption. Incoherence: pas \
             d'Encryption sans cle joignable."
        ),
        EtatCle::Presente => assert!(
            a_encryption,
            "{SECURITY_MD} declare une cle publiee (CLE-PGP=presente), mais \
             {SECURITY_TXT} ne porte aucun champ Encryption. Incoherence: une cle \
             annoncee doit etre joignable."
        ),
    }
}

#[test]
fn security_md_porte_l_adresse_de_contact() {
    let md = lire(SECURITY_MD);
    assert!(
        md.contains(ADRESSE),
        "{SECURITY_MD} ne contient pas l'adresse `{ADRESSE}`: le canal de \
         signalement n'y est pas nomme."
    );
}

#[test]
fn jours_civils_sur_trois_dates_connues() {
    // 1970-01-01 est l'origine.
    assert_eq!(jours_depuis_epoque(1970, 1, 1), 0);
    // 2000-01-01: 30 ans, 7 bissextiles (1972..=1996).
    assert_eq!(jours_depuis_epoque(2000, 1, 1), 10_957);
    // 2021-12-31: la date d'exemple de la RFC 9116.
    assert_eq!(jours_depuis_epoque(2021, 12, 31), 18_992);

    // L'inverse concorde sur les memes dates.
    assert_eq!(civil_depuis_jours(0), (1970, 1, 1));
    assert_eq!(civil_depuis_jours(10_957), (2000, 1, 1));
    assert_eq!(civil_depuis_jours(18_992), (2021, 12, 31));
}

#[test]
fn l_analyse_de_expires_et_la_fenetre_se_comportent_bien() {
    // Bon format reconnu, mauvais formats rejetes.
    assert_eq!(
        date_de_expires("2027-07-01T00:00:00Z").unwrap(),
        (2027, 7, 1)
    );
    assert!(
        date_de_expires("2027-07-01").is_err(),
        "une date nue sans heure doit etre refusee"
    );
    assert!(date_de_expires("pas une date").is_err());
    assert!(
        date_de_expires("2027-13-01T00:00:00Z").is_err(),
        "un mois 13 doit etre refuse"
    );

    // La fenetre se raisonne en jours, sans horloge: +10 jours est trop proche,
    // +400 trop loin, +200 dans la fenetre.
    let base = jours_depuis_epoque(2026, 9, 5);
    let trop_proche = jours_depuis_epoque(2026, 9, 15) - base;
    let trop_loin = jours_depuis_epoque(2027, 10, 10) - base;
    let bonne = jours_depuis_epoque(2027, 3, 23) - base;
    assert!(!(FENETRE_MIN..=FENETRE_MAX).contains(&trop_proche));
    assert!(!(FENETRE_MIN..=FENETRE_MAX).contains(&trop_loin));
    assert!((FENETRE_MIN..=FENETRE_MAX).contains(&bonne));

    // Le lecteur de champs ignore les commentaires et coupe au premier
    // deux-points seulement.
    let exemple =
        "# commentaire: pas un champ\nContact: mailto:x@y\nExpires: 2027-07-01T00:00:00Z\n";
    let champs = champs(exemple);
    assert_eq!(champs.len(), 2);
    assert_eq!(champs[0], ("contact".to_string(), "mailto:x@y".to_string()));
    assert_eq!(
        champs[1],
        ("expires".to_string(), "2027-07-01T00:00:00Z".to_string())
    );

    // Les deux jetons de cle sont mutuellement exclusifs.
    assert_eq!(etat_cle_du_md("... CLE-PGP=absente ..."), EtatCle::Absente);
    assert_eq!(
        etat_cle_du_md("... CLE-PGP=presente ..."),
        EtatCle::Presente
    );
}
