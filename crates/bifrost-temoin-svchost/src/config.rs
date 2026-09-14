//! Ce que le temoin lit avant de mesurer, et ce qu'il refuse de deviner.
//!
//! Pur, et compile partout: c'est ici que se decide ce qui compte comme
//! configuration valide, et cela doit pouvoir se discuter et se tester sans
//! machine Windows ni privileges. Le registre, lui, vit dans `hote`.
//!
//! # Le principe qui gouverne ce module
//!
//! **Une configuration absente n'est pas une configuration par defaut.** Un
//! temoin qui vise une cible inventee parce qu'on a oublie de lui en donner
//! une n'emet rien - et une absence de connexion se lit exactement comme un
//! blocage reussi. C'est le piege que ce depot a deja paye deux fois: << un
//! temoin muet certifie n'importe quoi >>. La cible est donc OBLIGATOIRE et
//! son absence est une erreur nommee, jamais un repli silencieux.
//!
//! La duree de rafale, elle, a un defaut: une duree a un sens raisonnable, une
//! destination non. Mais le defaut est DIT, et une valeur ramenee aux bornes
//! est dite aussi. Un operateur qui croit avoir mesure vingt secondes alors
//! qu'on en a mesure huit ne lit pas la meme experience que celle qui a eu
//! lieu.

use std::net::SocketAddr;

/// Duree de rafale retenue quand le registre n'en porte pas.
///
/// Huit secondes: c'est la valeur des deux bancs de cause deja livres, et un
/// temoin qui emettrait pendant une autre duree qu'eux rendrait des comptes
/// d'evenements qu'on ne pourrait pas comparer.
pub const RAFALE_DEFAUT_MS: u64 = 8_000;

/// En dessous, la rafale n'a le temps de rien.
pub const RAFALE_MIN_MS: u64 = 500;

/// Au dessus, le SCM considere le demarrage en echec.
///
/// Le temoin annonce `SERVICE_RUNNING` AVANT de tirer sa rafale, donc le delai
/// de demarrage n'est pas le vrai plafond. Celui-ci est prudentiel: une rafale
/// qui dure plus longtemps que la fenetre d'observation du banc ferait lire un
/// arret force comme une fin normale.
pub const RAFALE_MAX_MS: u64 = 20_000;

/// Duree d'une tranche de rafale.
///
/// La rafale est decoupee pour une seule raison: honorer `SERVICE_CONTROL_STOP`
/// sans attendre la fin de la fenetre. Le decoupage ne change rien au
/// resultat, `plus_permissif` etant un maximum: le maximum des maximums des
/// tranches est le maximum de l'ensemble.
pub const TRANCHE_MS: u64 = 500;

/// En dessous de quoi une tranche ne vaut pas la peine d'exister.
///
/// PIEGE MESURE DANS LA SONDE EXISTANTE: `rafale` boucle tant que le temps
/// ecoule est inferieur a la duree demandee, et part de `Verdict::Bloque`. Une
/// duree nulle ou quasi nulle rend donc **Bloque sans avoir fait la moindre
/// tentative** - un blocage fabrique, indiscernable d'un vrai. Le reliquat
/// trop court rejoint la tranche precedente au lieu d'en former une.
pub const TRANCHE_MIN_MS: u64 = 100;

/// D'ou vient une valeur. Un champ qui ne nomme pas sa source laisse croire
/// qu'il a ete choisi alors qu'il a ete subi.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origine {
    Registre,
    Defaut,
}

impl Origine {
    pub fn en_clair(self) -> &'static str {
        match self {
            Origine::Registre => "registre",
            Origine::Defaut => "defaut",
        }
    }
}

/// Ce que le registre a rendu, sans jugement.
///
/// Separe de [`Config`] exactement comme la mesure est separee du verdict
/// ailleurs dans ce depot: la lecture ne decide de rien, elle rapporte.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Brut {
    /// `Parameters\Cible`, une chaine de la forme `adresse:port`.
    pub cible: Option<String>,
    /// `Parameters\RafaleMs`, un DWORD en millisecondes.
    pub rafale_ms: Option<u32>,
}

/// La configuration retenue, et ce qu'elle doit a chacune de ses sources.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub cible: SocketAddr,
    /// Ce qui sera reellement tire.
    pub rafale_ms: u64,
    /// Ce que le registre demandait, quand il demandait quelque chose.
    pub rafale_demandee_ms: Option<u64>,
    pub origine_rafale: Origine,
}

impl Config {
    /// Vrai si la valeur retenue n'est pas celle qui etait demandee.
    pub fn rafale_ramenee(&self) -> bool {
        match self.rafale_demandee_ms {
            Some(d) => d != self.rafale_ms,
            None => false,
        }
    }

    /// Ce que le journal doit porter: chaque champ, sa valeur, et sa source.
    pub fn en_clair(&self) -> String {
        let mut sortie = String::new();
        sortie.push_str(&format!(
            "cible      : {}  (source: {})\n",
            self.cible,
            Origine::Registre.en_clair()
        ));
        let detail = match self.rafale_demandee_ms {
            None => format!("{} ms retenus, aucune valeur au registre", self.rafale_ms),
            Some(d) if d != self.rafale_ms => format!(
                "{} ms retenus sur {} ms demandes  (RAMENEE AUX BORNES {}..{})",
                self.rafale_ms, d, RAFALE_MIN_MS, RAFALE_MAX_MS
            ),
            Some(d) => format!("{} ms retenus sur {} ms demandes", self.rafale_ms, d),
        };
        sortie.push_str(&format!(
            "rafale     : {}  (source: {})\n",
            detail,
            self.origine_rafale.en_clair()
        ));
        sortie
    }
}

/// Lit une cible, ou dit precisement ce qui manquait.
///
/// Exige un port explicite. Un `1.1.1.1` sans port serait accepte par une
/// lecture indulgente qui completerait avec un port de son choix, et le temoin
/// mesurerait alors une destination que personne n'a demandee.
pub fn cible_depuis_texte(texte: &str) -> Result<SocketAddr, String> {
    let nettoye = texte.trim();
    if nettoye.is_empty() {
        return Err("la cible est vide. Attendu: adresse:port, par exemple 192.0.2.1:443".into());
    }
    nettoye.parse::<SocketAddr>().map_err(|e| {
        format!(
            "cible {nettoye:?} illisible ({e}). Attendu une adresse ET un port, \
             par exemple 192.0.2.1:443. Une adresse sans port est refusee: le \
             temoin ne choisit pas la destination a la place de l'appelant."
        )
    })
}

/// Ce que le temoin retient, ou pourquoi il refuse de mesurer.
pub fn depuis(brut: &Brut) -> Result<Config, String> {
    let Some(texte) = brut.cible.as_deref() else {
        return Err(
            "aucune valeur Parameters\\Cible sous la cle du service. Le temoin \
             REFUSE de se donner une destination par defaut: il n'emettrait \
             pas, et une absence de connexion se lit exactement comme un \
             blocage reussi."
                .into(),
        );
    };
    let cible = cible_depuis_texte(texte)?;

    let (rafale_ms, rafale_demandee_ms, origine_rafale) = match brut.rafale_ms {
        None => (RAFALE_DEFAUT_MS, None, Origine::Defaut),
        Some(d) => {
            let demandee = u64::from(d);
            (
                demandee.clamp(RAFALE_MIN_MS, RAFALE_MAX_MS),
                Some(demandee),
                Origine::Registre,
            )
        }
    };

    Ok(Config {
        cible,
        rafale_ms,
        rafale_demandee_ms,
        origine_rafale,
    })
}

/// Le decoupage de la fenetre en tranches, en millisecondes.
///
/// Aucune tranche plus courte que [`TRANCHE_MIN_MS`] des lors que la fenetre
/// elle-meme est plus longue: un reliquat de quelques millisecondes formerait
/// une tranche ou la sonde n'aurait le temps d'aucune tentative et rendrait
/// `Bloque` sans avoir rien essaye.
pub fn plan_de_tranches(total_ms: u64, tranche_ms: u64) -> Vec<u64> {
    let mut plan = Vec::new();
    if total_ms == 0 || tranche_ms == 0 {
        return plan;
    }
    let mut reste = total_ms;
    while reste > 0 {
        let prise = reste.min(tranche_ms);
        let trop_courte = prise < TRANCHE_MIN_MS;
        match plan.last_mut() {
            Some(derniere) if trop_courte => {
                *derniere += prise;
                break;
            }
            _ => plan.push(prise),
        }
        reste -= prise;
    }
    plan
}

/// Le nom d'un code de sortie de la sonde, pour le journal.
///
/// `None` ne vaut pas zero. Une mesure qui n'a pas eu lieu et une mesure qui a
/// rendu << rien ne l'a refuse >> sont deux etats differents, et les confondre
/// ferait lire une case vide comme un resultat.
///
/// Les codes sont ceux de `bifrost_daemon::wfp_identity::Verdict::code`. Une
/// recette sous `cfg(windows)` confronte cette table a la source: si les deux
/// divergeaient, le journal nommerait un verdict pour un autre.
pub fn ligne_verdict(code: Option<i32>) -> String {
    match code {
        None => "NON MESURE (aucune tentative n'a eu lieu)".into(),
        Some(0) => "0 PASSE (rien ne l'a refuse, rien n'a abouti)".into(),
        Some(3) => "3 BLOQUE par un filtre".into(),
        Some(4) => "4 SANS ROUTE (la pile n'a meme pas essaye)".into(),
        Some(5) => "5 CONNECTE".into(),
        Some(n) => format!("{n} INATTENDU (ce code ne vient pas de la sonde)"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Le defaut le plus dangereux serait une cible: le temoin n'emettrait
    /// pas, et le banc lirait ce silence comme un blocage.
    #[test]
    fn une_cible_absente_n_est_pas_une_cible_par_defaut() {
        let erreur = depuis(&Brut::default()).expect_err("une cible absente doit etre une erreur");
        assert!(
            erreur.contains("Cible"),
            "l'erreur doit nommer la valeur qui manque: {erreur}"
        );
    }

    /// Une adresse sans port serait completee par une lecture indulgente, et le
    /// temoin viserait alors un port que personne n'a demande.
    #[test]
    fn une_cible_sans_port_est_refusee() {
        let erreur =
            cible_depuis_texte("192.0.2.1").expect_err("une adresse sans port est refusee");
        assert!(
            erreur.contains("port"),
            "l'erreur doit dire ce qui manque: {erreur}"
        );
    }

    /// Une valeur ramenee en silence ferait croire a l'operateur qu'il a mesure
    /// la fenetre qu'il avait demandee.
    #[test]
    fn la_rafale_hors_bornes_est_ramenee_et_le_dit() {
        let brut = Brut {
            cible: Some("192.0.2.1:443".into()),
            rafale_ms: Some(99_000),
        };
        let config = depuis(&brut).expect("la cible est lisible");
        assert_eq!(config.rafale_ms, RAFALE_MAX_MS);
        assert!(config.rafale_ramenee(), "la valeur a bien ete ramenee");
        let texte = config.en_clair();
        assert!(
            texte.contains("99000") && texte.contains("RAMENEE"),
            "le journal doit porter la valeur DEMANDEE et dire qu'elle a ete ramenee: {texte}"
        );
    }

    /// Un champ qui ne nomme pas sa source laisse croire qu'il a ete choisi.
    #[test]
    fn chaque_champ_nomme_sa_source() {
        let brut = Brut {
            cible: Some("192.0.2.1:443".into()),
            rafale_ms: None,
        };
        let texte = depuis(&brut).expect("la cible est lisible").en_clair();
        assert!(
            texte.contains("cible") && texte.contains("(source: registre)"),
            "la cible vient toujours du registre et doit le dire: {texte}"
        );
        assert!(
            texte.contains("(source: defaut)") && texte.contains("aucune valeur au registre"),
            "une rafale par defaut doit se declarer comme telle: {texte}"
        );
    }

    /// Une tranche trop courte rendrait `Bloque` sans aucune tentative.
    #[test]
    fn aucune_tranche_n_est_trop_courte_pour_une_tentative() {
        for total in [RAFALE_MIN_MS, 8_000, 8_250, 8_050, RAFALE_MAX_MS] {
            let plan = plan_de_tranches(total, TRANCHE_MS);
            assert!(
                !plan.is_empty(),
                "{total} ms doivent donner au moins une tranche"
            );
            for tranche in &plan {
                assert!(
                    *tranche >= TRANCHE_MIN_MS,
                    "tranche de {tranche} ms dans le plan de {total} ms: la sonde \
                     n'aurait le temps d'aucune tentative et rendrait BLOQUE sans \
                     avoir essaye. Plan complet: {plan:?}"
                );
            }
        }
    }

    /// Un reliquat perdu raccourcirait la fenetre sans que personne le voie.
    #[test]
    fn les_tranches_couvrent_exactement_la_fenetre_demandee() {
        for total in [RAFALE_MIN_MS, 8_000, 8_250, 8_050, RAFALE_MAX_MS] {
            let plan = plan_de_tranches(total, TRANCHE_MS);
            let somme: u64 = plan.iter().sum();
            assert_eq!(
                somme, total,
                "le plan {plan:?} ne couvre pas les {total} ms demandes"
            );
        }
    }

    /// Trois etats indiscernables valent zero information.
    #[test]
    fn un_code_absent_ne_se_lit_pas_comme_un_passage() {
        let texte = ligne_verdict(None);
        assert!(
            texte.contains("NON MESURE"),
            "l'absence de mesure doit se nommer: {texte}"
        );
        assert!(
            !texte.contains("PASSE") && !texte.contains("CONNECTE"),
            "l'absence de mesure ne doit ressembler a aucun verdict: {texte}"
        );
    }

    /// Un code hors table range sous un verdict connu inventerait un resultat.
    #[test]
    fn un_code_hors_table_est_nomme_inattendu() {
        let texte = ligne_verdict(Some(7));
        assert!(
            texte.contains("INATTENDU") && texte.contains('7'),
            "un code inconnu doit se dire inconnu ET se montrer: {texte}"
        );
    }

    /// La table de ce module et celle de la sonde doivent nommer les memes
    /// codes. Si la sonde en ajoutait un, le journal l'appellerait INATTENDU.
    #[cfg(windows)]
    #[test]
    fn les_verdicts_de_la_sonde_sont_tous_nommes_ici() {
        use bifrost_daemon::wfp_identity::Verdict;
        for verdict in [
            Verdict::Passe,
            Verdict::Bloque,
            Verdict::SansRoute,
            Verdict::Connecte,
        ] {
            let texte = ligne_verdict(Some(verdict.code()));
            assert!(
                !texte.contains("INATTENDU"),
                "{verdict:?} rend le code {} que ce module ne nomme pas: {texte}",
                verdict.code()
            );
        }
    }
}
