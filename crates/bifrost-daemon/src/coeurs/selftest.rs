//! Recette d'un coeur tiers, contre le VRAI binaire.
//!
//! Ce que les recettes de `tests/coeurs.rs` ne peuvent pas dire: elles
//! eprouvent le superviseur contre une doublure ecrite par nous, qui repond
//! forcement comme nous l'attendons. Ici le coeur est le vrai, et ce sont donc
//! nos hypotheses sur LUI qui sont mises a l'epreuve: la ligne de commande, le
//! schema de configuration, le port d'ecoute de l'API, la forme des reponses.
//!
//! Elle ne touche ni au kill switch ni au tunnel, n'ecoute que sur la boucle
//! locale, et n'a besoin d'aucun privilege.

use std::path::PathBuf;

use bifrost_evasion::Coeur;

use super::{alea, configuration, lancement, port, superviseur};

/// Etat d'une etape de la recette.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Etat {
    Reussi,
    Ignore,
    Echoue,
}

impl Etat {
    fn mot(self) -> &'static str {
        match self {
            Etat::Reussi => "PASSED",
            Etat::Ignore => "SKIPPED",
            Etat::Echoue => "FAILED",
        }
    }
}

fn dire(etape: &str, etat: Etat, detail: &str) {
    println!("{:<7} {etape}: {detail}", etat.mot());
}

/// Lance la recette pour un coeur.
///
/// `racine` contient les binaires; les configurations sont ecrites a cote,
/// dans un sous-repertoire, puis retirees.
pub async fn run(
    coeur: Coeur,
    racine: PathBuf,
    identite: &super::identite::IdentiteCoeur,
) -> anyhow::Result<()> {
    let emplacements = lancement::Emplacements {
        binaires: racine.clone(),
        configurations: racine.join("configurations"),
    };

    // Tenus jusqu'au lancement: voir [`super::port`].
    let reserve_api = port::reserver()?;
    let reserve_socks = port::reserver()?;
    let api = reserve_api.port();
    let parametres = configuration::Parametres {
        socks: reserve_socks.port(),
        api,
        secret: alea::secret()?,
        // Cet autotest ne traverse pas l'entree SOCKS, mais la configuration
        // engendree doit rester celle de l'exploitation: un coeur eprouve avec
        // une entree ouverte ne serait pas le coeur qu'on met en service.
        identifiants: super::socks::Identifiants::nouveaux("bifrost", &alea::secret()?)?,
        selecteur: "select".into(),
        sorties: vec!["sortie-a".into(), "sortie-b".into()],
        // Meme raison qu'en bout-en-bout: pas de tunnel monte ici.
        lier_a: None,
    };

    let mut prepare = lancement::preparer(&emplacements, coeur, api);
    identite.appliquer(&mut prepare);
    if !lancement::binaire_present(&prepare) {
        dire(
            "binaire",
            Etat::Ignore,
            &format!(
                "{} absent, recette non executee",
                prepare.programme.display()
            ),
        );
        // Un coeur absent rend SKIPPED et non FAILED: la recette n'a pas
        // echoue, elle n'a pas pu tourner. Le code de sortie le distingue.
        std::process::exit(3);
    }
    dire(
        "binaire",
        Etat::Reussi,
        &prepare.programme.display().to_string(),
    );

    let contenu = match coeur {
        Coeur::SingBox => configuration::sing_box(&parametres),
        Coeur::XrayCore => configuration::xray(&parametres),
        Coeur::AmneziaWg => {
            dire(
                "configuration",
                Etat::Ignore,
                "AmneziaWG se configure par UAPI, pas par un fichier",
            );
            std::process::exit(3);
        }
    };
    configuration::ecrire(&prepare.configuration, &contenu)?;
    dire(
        "configuration",
        Etat::Reussi,
        &format!("ecrite dans {}", prepare.configuration.display()),
    );

    // Rendus a l'instant ou l'enfant va les prendre, et pas avant.
    reserve_api.liberer();
    reserve_socks.liberer();
    let en_cours = superviseur::demarrer(coeur, &prepare, &parametres.secret).await?;
    let pid = en_cours.pid().unwrap_or(0);
    dire("demarrage", Etat::Reussi, &format!("pid {pid}"));

    let mut echecs = 0usize;

    if coeur.a_une_api_clash() {
        // La bascule, et sa VERIFICATION. Un 204 dit que la requete a ete
        // acceptee, pas que la sortie a change.
        let avant = en_cours.selection(&parametres.selecteur).await?;
        dire("selection initiale", Etat::Reussi, &avant);

        let cible = parametres
            .sorties
            .iter()
            .find(|s| **s != avant)
            .cloned()
            .expect("il faut au moins deux sorties pour eprouver une bascule");

        // Par le chemin de PRODUCTION: `basculer` demande, relit et compare,
        // exactement comme le fait le superviseur de tunnel quand un candidat
        // lache en cours de session. Cette recette mesure donc ce qui tourne,
        // et pas une seconde copie de la meme politique.
        match en_cours.basculer(&parametres.selecteur, &cible).await? {
            crate::coeurs::bascule::Issue::Faite { sortie } => {
                dire("bascule", Etat::Reussi, &format!("{avant} -> {sortie}"));
            }
            crate::coeurs::bascule::Issue::Refusee { sortie, raison } => {
                echecs += 1;
                dire(
                    "bascule",
                    Etat::Echoue,
                    &format!("demandee {sortie}: {raison}"),
                );
            }
        }

        // Temoin negatif: une sortie inexistante doit etre REFUSEE. Sans lui,
        // un coeur qui accepterait tout sans rien faire passerait la recette
        // precedente aussi bien qu'un coeur correct.
        match en_cours
            .basculer(&parametres.selecteur, "sortie-qui-n-existe-pas")
            .await?
        {
            crate::coeurs::bascule::Issue::Refusee { .. } => dire(
                "temoin negatif",
                Etat::Reussi,
                "une sortie inconnue est refusee",
            ),
            crate::coeurs::bascule::Issue::Faite { .. } => {
                echecs += 1;
                dire(
                    "temoin negatif",
                    Etat::Echoue,
                    "le coeur a accepte une sortie inconnue: la bascule ne prouve rien",
                );
            }
        }
    } else {
        dire(
            "bascule",
            Etat::Ignore,
            "ce coeur n'expose pas d'API Clash, rien a piloter a chaud",
        );
    }

    en_cours.arreter().await?;
    dire("arret", Etat::Reussi, "le coeur a rendu la main");

    let _ = std::fs::remove_file(&prepare.configuration);

    if echecs == 0 {
        println!("recette {} : complete", coeur.executable());
        Ok(())
    } else {
        anyhow::bail!(
            "recette {} : {echecs} etape(s) en echec",
            coeur.executable()
        )
    }
}
