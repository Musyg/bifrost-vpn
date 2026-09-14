//! Ce que Bifrost ECRIT pour fermer le contournement que [`super::doh`] mesure.
//!
//! Le vecteur constate, ce module repare. Les deux sont separes a dessein: poser
//! des politiques avant d'avoir un temoin qui dit ce qu'elles changent aurait
//! laisse sans moyen de verifier qu'elles servent.
//!
//! # Pourquoi couper, plutot que pointer sur nous
//!
//! [`super::doh::Etat::Local`] passe aussi: un navigateur qui fait du DoH VERS
//! notre resolveur reste pince. Ce n'est pourtant pas ce qui est ecrit ici,
//! parce que le resolveur chiffre embarque n'existe pas encore (probleme ouvert
//! 6). Tant que notre resolveur local parle du DNS clair sur la boucle locale,
//! lui demander du DoH ne marcherait pas. Couper le DoH renvoie les navigateurs
//! vers le resolveur systeme, qui EST le notre. Le jour ou le resolveur chiffre
//! existe, c'est ce module qui changera, pas le vecteur.
//!
//! # Ne jamais ecraser ce qu'on n'a pas pose
//!
//! Chrome, Chromium et Edge lisent un REPERTOIRE: Bifrost y depose son propre
//! fichier et n'ouvre jamais ceux des autres. Le retrait supprime le sien, et
//! lui seul.
//!
//! Firefox n'offre pas ce luxe: `/etc/firefox/policies/policies.json` est un
//! fichier UNIQUE et partage. Il faut donc y fusionner, en preservant tout le
//! reste, et refuser net quand une politique DoH contraire s'y trouve deja.
//! Ecraser silencieusement la configuration deliberee de quelqu'un pour faire
//! passer notre propre vecteur au vert serait la pire facon de le faire passer.

use serde_json::{Map, Value, json};

/// Nom du fichier que Bifrost depose dans les repertoires `managed`.
///
/// Prefixe pour qu'il se voie, et fixe pour que le retrait sache quoi enlever.
pub const FICHIER: &str = "bifrost-doh.json";

/// Ce qu'il faut faire d'un `policies.json` Firefox existant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fusion {
    /// Voici le contenu a ecrire, tout le reste preserve.
    Ecrire(String),
    /// La politique voulue est deja en place: ne pas toucher au fichier.
    DejaPose,
    /// Une politique DoH contraire est deja la. On ne l'ecrase pas.
    Conflit(String),
    /// Le fichier existant ne se lit pas. Ecrire par-dessus perdrait ce qu'il
    /// contient, y compris ce que personne n'a relu depuis longtemps.
    Illisible(String),
}

/// La politique Chromium que Bifrost depose, telle qu'elle part sur le disque.
pub fn chromium_json() -> String {
    let contenu = json!({ "DnsOverHttpsMode": "off" });
    format!(
        "{}\n",
        serde_json::to_string_pretty(&contenu).expect("objet JSON constant")
    )
}

/// Fusionne la politique DoH de Bifrost dans un `policies.json` Firefox.
///
/// `existant` vaut `None` quand le fichier n'existe pas encore.
pub fn firefox_fusionner(existant: Option<&str>) -> Fusion {
    let mut racine = match existant {
        None => Map::new(),
        Some(texte) => match serde_json::from_str::<Value>(texte) {
            Err(e) => return Fusion::Illisible(format!("JSON invalide: {e}")),
            Ok(Value::Object(o)) => o,
            Ok(_) => {
                return Fusion::Illisible(
                    "le fichier n'est pas un objet JSON: son contenu ne se fusionne pas".to_owned(),
                );
            }
        },
    };

    let politiques = match racine.get("policies") {
        None => Map::new(),
        Some(Value::Object(o)) => o.clone(),
        Some(_) => {
            return Fusion::Illisible(
                "la clef 'policies' n'est pas un objet: son contenu ne se fusionne pas".to_owned(),
            );
        }
    };

    if let Some(doh) = politiques.get("DNSOverHTTPS") {
        match doh.get("Enabled") {
            // Deja coupe: reste a savoir s'il est verrouille.
            Some(Value::Bool(false)) => {
                if doh.get("Locked") == Some(&Value::Bool(true)) {
                    return Fusion::DejaPose;
                }
                // Coupe sans verrou: meme intention que la notre, laissee a
                // moitie. La completer n'ecrase aucune volonte contraire.
            }
            Some(Value::Bool(true)) => {
                let ou = doh
                    .get("ProviderURL")
                    .and_then(Value::as_str)
                    .unwrap_or("le fournisseur par defaut de Firefox");
                return Fusion::Conflit(format!(
                    "DNSOverHTTPS est deja ACTIF vers {ou}: quelqu'un l'a voulu, et Bifrost ne defait pas une configuration deliberee sans qu'on le lui demande"
                ));
            }
            autre => {
                return Fusion::Conflit(format!(
                    "DNSOverHTTPS.Enabled vaut {}, ce qui ne se lit pas comme un booleen: refus d'ecrire par-dessus une valeur qu'on ne comprend pas",
                    autre.unwrap_or(&Value::Null)
                ));
            }
        }
    }

    let mut politiques = politiques;
    politiques.insert(
        "DNSOverHTTPS".to_owned(),
        json!({ "Enabled": false, "Locked": true }),
    );
    racine.insert("policies".to_owned(), Value::Object(politiques));
    let texte = serde_json::to_string_pretty(&Value::Object(racine))
        .expect("un objet issu de serde_json se reserialise");
    Fusion::Ecrire(format!("{texte}\n"))
}

/// Un document Firefox qui ne porte plus rien, tel que serde_json le rend.
///
/// Verrouille par un test: si la mise en forme de `serde_json` changeait, le
/// retrait laisserait un fichier vide au lieu de le supprimer, et le residu
/// passerait inapercu.
pub const VIDE: &str = "{\n  \"policies\": {}\n}";

/// Ce qu'il est advenu d'une cible, cote pose comme cote retrait.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pose {
    /// Ecrite a l'instant.
    Posee(String),
    /// Deja dans l'etat voulu: le fichier n'a pas ete touche.
    DejaPose(String),
    /// Enlevee a l'instant.
    Retiree(String),
    /// Rien a faire ici, et ce n'est pas un echec.
    HorsObjet(String),
    /// Refus d'ecrire, avec sa raison. Compte comme un echec.
    Refus(String),
}

impl Pose {
    /// Vrai quand la cible n'est PAS dans l'etat demande.
    pub fn echec(&self) -> bool {
        matches!(self, Pose::Refus(_))
    }

    pub fn raison(&self) -> &str {
        match self {
            Pose::Posee(r)
            | Pose::DejaPose(r)
            | Pose::Retiree(r)
            | Pose::HorsObjet(r)
            | Pose::Refus(r) => r,
        }
    }

    pub fn etiquette(&self) -> &'static str {
        match self {
            Pose::Posee(_) => "POSEE",
            Pose::DejaPose(_) => "DEJA",
            Pose::Retiree(_) => "RETIREE",
            Pose::HorsObjet(_) => "SANS OBJET",
            Pose::Refus(_) => "REFUS",
        }
    }
}

/// Retire du `policies.json` la politique DoH de Bifrost, et elle seule.
///
/// Rend `Ok(None)` quand il n'y a rien a nous: soit aucune politique DoH, soit
/// une politique qui n'est pas exactement la notre. On ne retire QUE ce qu'on
/// reconnait, pour la meme raison qu'on n'ecrase que ce qu'on reconnait.
///
/// Limite assumee, et symetrique de celle de [`firefox_fusionner`]: une
/// politique identique a la notre posee par quelqu'un d'autre serait retiree
/// aussi, et une politique a moitie posee que nous avons completee ne revient
/// pas a son etat d'avant. Rien ne les distingue sans un marqueur separe, et le
/// resultat reste VISIBLE puisque le vecteur `doh-bypass` le dit aussitot.
pub fn firefox_defusionner(texte: &str) -> Result<Option<String>, String> {
    let Ok(Value::Object(mut racine)) = serde_json::from_str::<Value>(texte) else {
        return Err(
            "JSON invalide ou document qui n'est pas un objet: rien n'est retire".to_owned(),
        );
    };
    let Some(Value::Object(politiques)) = racine.get_mut("policies") else {
        return Ok(None);
    };
    if politiques.get("DNSOverHTTPS") != Some(&json!({ "Enabled": false, "Locked": true })) {
        return Ok(None);
    }
    politiques.remove("DNSOverHTTPS");
    let texte = serde_json::to_string_pretty(&Value::Object(racine))
        .expect("un objet issu de serde_json se reserialise");
    Ok(Some(format!("{texte}\n")))
}

/// Affiche ce qui a ete fait de chaque cible et echoue s'il reste un refus.
///
/// Un refus n'est pas une erreur d'execution: c'est le module qui a choisi de
/// ne pas ecraser quelque chose. Il doit se voir, et il doit faire echouer la
/// commande, sinon un `poser` qui n'a rien pose passerait pour un succes.
pub fn rapporter(action: &str, resultats: &[(String, Pose)]) -> anyhow::Result<()> {
    println!("Politiques DoH: {action}\n");
    for (cible, pose) in resultats {
        println!("{:<11}  {:<18}  {}", pose.etiquette(), cible, pose.raison());
    }
    let refus = resultats.iter().filter(|(_, p)| p.echec()).count();
    let agies = resultats
        .iter()
        .filter(|(_, p)| matches!(p, Pose::Posee(_) | Pose::Retiree(_)))
        .count();
    println!("\n{agies} cible(s) modifiee(s), {refus} refus");
    if refus > 0 {
        anyhow::bail!(
            "{refus} cible(s) laissee(s) en l'etat: Bifrost n'ecrase pas une configuration qu'il n'a pas posee. Les raisons sont au-dessus."
        );
    }
    println!("\nVerifier avec le vecteur: `bifrost-cli check`, ligne doh-bypass.");
    Ok(())
}

/// Affiche le verdict du vecteur, et echoue s'il est rouge.
///
/// C'est le troisieme verbe: il permet de constater l'effet de `poser` sans
/// daemon en cours d'execution, donc sur une machine ou l'on vient seulement de
/// deposer le binaire.
pub fn rapporter_constat(issue: &bifrost_core::checks::CheckOutcome) -> anyhow::Result<()> {
    use bifrost_core::checks::Verdict;
    let etiquette = match issue.verdict {
        Verdict::Passed => "PASSED",
        Verdict::Failed => "FAILED",
        Verdict::Skipped => "SKIPPED",
    };
    println!("{etiquette}  {}  {}", issue.vector.id(), issue.detail);
    for ligne in &issue.evidence {
        println!("        {ligne}");
    }
    if issue.verdict == Verdict::Failed {
        anyhow::bail!("le contournement DoH reste ouvert");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ecrit(f: &Fusion) -> &str {
        match f {
            Fusion::Ecrire(t) => t,
            autre => panic!("Ecrire attendu, recu {autre:?}"),
        }
    }

    #[test]
    fn la_politique_chromium_coupe_le_doh() {
        let t = chromium_json();
        let v: Value = serde_json::from_str(&t).unwrap();
        assert_eq!(v["DnsOverHttpsMode"], "off");
        // Relue par le vecteur, elle doit donner un pincage.
        assert_eq!(
            super::super::doh::chromium_depuis_json(&t).unwrap(),
            (Some("off".to_owned()), None)
        );
    }

    #[test]
    fn un_fichier_absent_se_cree() {
        let f = firefox_fusionner(None);
        let v: Value = serde_json::from_str(ecrit(&f)).unwrap();
        assert_eq!(v["policies"]["DNSOverHTTPS"]["Enabled"], false);
        assert_eq!(v["policies"]["DNSOverHTTPS"]["Locked"], true);
    }

    /// Le point qui compte: `policies.json` est partage. Tout ce qui n'est pas
    /// a nous doit ressortir intact, sans quoi poser notre politique
    /// effacerait celles de quelqu'un d'autre.
    #[test]
    fn les_autres_politiques_survivent_a_la_fusion() {
        let avant =
            r#"{"policies":{"DisableTelemetry":true,"Bookmarks":[{"Title":"a"}]},"autreClef":42}"#;
        let f = firefox_fusionner(Some(avant));
        let v: Value = serde_json::from_str(ecrit(&f)).unwrap();
        assert_eq!(v["policies"]["DisableTelemetry"], true);
        assert_eq!(v["policies"]["Bookmarks"][0]["Title"], "a");
        assert_eq!(v["autreClef"], 42);
        assert_eq!(v["policies"]["DNSOverHTTPS"]["Locked"], true);
    }

    #[test]
    fn une_politique_deja_posee_ne_reecrit_rien() {
        let avant = r#"{"policies":{"DNSOverHTTPS":{"Enabled":false,"Locked":true}}}"#;
        assert_eq!(firefox_fusionner(Some(avant)), Fusion::DejaPose);
    }

    /// Coupe sans verrou, c'est notre intention laissee a moitie: la completer
    /// n'ecrase aucune volonte contraire.
    #[test]
    fn une_politique_coupee_sans_verrou_se_complete() {
        let avant = r#"{"policies":{"DNSOverHTTPS":{"Enabled":false}}}"#;
        let f = firefox_fusionner(Some(avant));
        let v: Value = serde_json::from_str(ecrit(&f)).unwrap();
        assert_eq!(v["policies"]["DNSOverHTTPS"]["Locked"], true);
    }

    /// Un DoH ACTIF est un choix. Le defaire en silence pour faire passer
    /// notre propre vecteur au vert serait la pire facon de le faire passer.
    #[test]
    fn un_doh_actif_n_est_pas_ecrase() {
        let avant = r#"{"policies":{"DNSOverHTTPS":{"Enabled":true,"ProviderURL":"https://dns.google/dns-query"}}}"#;
        match firefox_fusionner(Some(avant)) {
            Fusion::Conflit(r) => {
                assert!(r.contains("dns.google"), "{r}");
            }
            autre => panic!("Conflit attendu, recu {autre:?}"),
        }
    }

    /// Ecrire par-dessus un fichier illisible perdrait ce qu'il contient.
    #[test]
    fn un_fichier_illisible_n_est_pas_ecrase() {
        assert!(matches!(
            firefox_fusionner(Some("{ pas du json")),
            Fusion::Illisible(_)
        ));
        assert!(matches!(
            firefox_fusionner(Some("[]")),
            Fusion::Illisible(_)
        ));
        assert!(matches!(
            firefox_fusionner(Some(r#"{"policies": "pas un objet"}"#)),
            Fusion::Illisible(_)
        ));
    }

    /// Poser puis relire doit donner un pincage, sinon les deux moities du
    /// travail ne se parlent pas.
    #[test]
    fn ce_qui_est_pose_est_lu_comme_pince() {
        let f = firefox_fusionner(None);
        let (active, verrou, url) = super::super::doh::firefox_depuis_json(ecrit(&f)).unwrap();
        assert_eq!(active, Some(false));
        assert_eq!(verrou, Some(true));
        assert_eq!(url, None);
        let etat = super::super::doh::interpreter_firefox(
            true,
            active.map(u32::from),
            verrou.map(u32::from),
            url.as_deref(),
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        );
        assert_eq!(etat, super::super::doh::Etat::Verrouille);
    }

    #[test]
    fn le_retrait_n_enleve_que_la_notre() {
        let avant = r#"{"policies":{"DisableTelemetry":true,"DNSOverHTTPS":{"Enabled":false,"Locked":true}}}"#;
        let apres = firefox_defusionner(avant)
            .unwrap()
            .expect("la notre devait etre reconnue");
        let v: Value = serde_json::from_str(&apres).unwrap();
        assert!(v["policies"].get("DNSOverHTTPS").is_none(), "{apres}");
        assert_eq!(v["policies"]["DisableTelemetry"], true);
    }

    /// Une politique qui n'est pas la notre reste en place. C'est le pendant du
    /// refus d'ecrire: on ne retire que ce qu'on reconnait.
    #[test]
    fn le_retrait_laisse_ce_qui_n_est_pas_a_nous() {
        for autre in [
            r#"{"policies":{"DNSOverHTTPS":{"Enabled":true}}}"#,
            r#"{"policies":{"DNSOverHTTPS":{"Enabled":false}}}"#,
            r#"{"policies":{"DisableTelemetry":true}}"#,
            r#"{"autreClef":1}"#,
        ] {
            assert_eq!(firefox_defusionner(autre).unwrap(), None, "{autre}");
        }
    }

    #[test]
    fn un_document_illisible_ne_se_retire_pas() {
        assert!(firefox_defusionner("{ pas du json").is_err());
        assert!(firefox_defusionner("[]").is_err());
    }

    /// Poser puis retirer sur un fichier qui n'existait pas doit rendre un
    /// document vide, que l'appelant sait alors supprimer. Ce test verrouille
    /// aussi la mise en forme: sans lui, un changement de `serde_json`
    /// laisserait un residu au lieu du fichier supprime.
    #[test]
    fn poser_puis_retirer_ne_laisse_rien() {
        let pose = match firefox_fusionner(None) {
            Fusion::Ecrire(t) => t,
            autre => panic!("Ecrire attendu, recu {autre:?}"),
        };
        let reste = firefox_defusionner(&pose)
            .unwrap()
            .expect("la notre devait etre reconnue");
        assert_eq!(reste.trim(), VIDE, "{reste}");
    }
}
