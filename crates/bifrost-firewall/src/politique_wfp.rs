//! Projection WFP v1 de la politique remise au moteur, et reference pure.
//!
//! Le pendant WFP de [`crate::politique_nft`], avec une difference de fond: le
//! plan WFP ne lit pas seulement la politique. Il autorise le binaire qui
//! l'execute, sous l'identite de son propre jeton, et l'interface qu'il a
//! resolue lui-meme. La projection porte donc deux parts, et le dit:
//!
//! - de la POLITIQUE recue par le moteur: `dns_resolver`, `allow_lan`,
//!   `resolveur_embarque`, `resolveur_executable`, `resolveur_sid`,
//!   `coeur_executable`, les seuls champs que `wfp_plan::plan` lit;
//! - de l'ENVIRONNEMENT que le moteur a lu de son hote au moment de poser
//!   (`bifrost_core::ports::EnvironnementMoteur`): `daemon_executable`,
//!   `identite`, et `tunnel_luid`, le LUID effectivement autorise.
//!
//! Deux valeurs restent a calculer par la preuve, sur SON hote, parce qu'elles
//! n'existent qu'en appelant Windows: l'identifiant d'application que WFP tire
//! d'un chemin, et le descripteur de securite d'une identite. La reference les
//! laisse en chemin et en identite ([`crate::wfp_plan::Valeur`]).
//!
//! C'est un ATTENDU, jamais une observation du moteur.

use std::net::IpAddr;
use std::path::PathBuf;

use bifrost_core::ports::{EnvironnementMoteur, FirewallPolicy};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::instantane_wfp::Sid;
use crate::wfp_plan::{self, FilterSpec, FiltreWfp};

/// Nom du moteur, tel que `KillSwitch::backend` le rend pour WFP. La
/// declaration du daemon joint cette projection-ci quand son moteur porte ce
/// nom, et la projection nft sinon.
pub const MOTEUR: &str = "wfp";
/// Discriminant de la projection: une declaration WFP ne se lit jamais comme
/// une declaration nft (sept cles), ni l'inverse.
pub const PROJECTION: &str = "wfp";
pub const VERSION: u32 = 1;

const CHAMPS: [&str; 11] = [
    "projection",
    "schema_version",
    "dns_resolver",
    "allow_lan",
    "resolveur_embarque",
    "resolveur_executable",
    "resolveur_sid",
    "coeur_executable",
    "tunnel_luid",
    "daemon_executable",
    "identite",
];

/// Tous les champs sont obligatoires, options explicites en `null` comprises.
/// Ne pas deserialiser directement avec serde: passer par [`PolitiqueWfp::lire`].
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolitiqueWfp {
    pub projection: String,
    pub schema_version: u32,
    pub dns_resolver: IpAddr,
    pub allow_lan: bool,
    pub resolveur_embarque: bool,
    pub resolveur_executable: Option<String>,
    pub resolveur_sid: Option<String>,
    pub coeur_executable: Option<String>,
    pub tunnel_luid: Option<u64>,
    pub daemon_executable: String,
    pub identite: String,
}

fn chemin_texte(p: &std::path::Path) -> Option<String> {
    p.to_str().map(str::to_owned)
}

impl PolitiqueWfp {
    /// Ce que le moteur WFP a LU pour poser: la politique recue et
    /// l'environnement qu'il en a tire.
    ///
    /// Aucune validation, comme la projection nft: une politique hors du
    /// perimetre de la reference se projette telle quelle, et c'est `lire` qui
    /// la refusera au moment de comparer. `None` seulement si un chemin n'est
    /// pas de l'UTF-8: le JSON ne saurait pas le porter sans le deformer, et
    /// une declaration deformee serait pire qu'absente.
    pub fn projeter(p: &FirewallPolicy, env: &EnvironnementMoteur) -> Option<Self> {
        let optionnel = |c: &Option<PathBuf>| -> Option<Option<String>> {
            match c {
                Some(c) => chemin_texte(c).map(Some),
                None => Some(None),
            }
        };
        Some(Self {
            projection: PROJECTION.to_owned(),
            schema_version: VERSION,
            dns_resolver: p.dns_resolver,
            allow_lan: p.allow_lan,
            resolveur_embarque: p.resolveur_embarque,
            resolveur_executable: optionnel(&p.resolveur_executable)?,
            resolveur_sid: p.resolveur_sid.clone(),
            coeur_executable: optionnel(&p.coeur_executable)?,
            tunnel_luid: env.interface,
            daemon_executable: chemin_texte(&env.executable)?,
            identite: env.identite.clone(),
        })
    }

    /// Le JSON doit deja avoir ete controle pour les cles dupliquees.
    pub fn lire(v: Value) -> Result<Self, &'static str> {
        let objet = v.as_object().ok_or("politique WFP invalide")?;
        if objet.len() != CHAMPS.len() || CHAMPS.iter().any(|c| !objet.contains_key(*c)) {
            return Err("champs de politique WFP manquants ou inconnus");
        }
        let p: Self = serde_json::from_value(v).map_err(|_| "types de politique WFP invalides")?;
        p.valider()?;
        Ok(p)
    }

    fn valider(&self) -> Result<(), &'static str> {
        if self.projection != PROJECTION || self.schema_version != VERSION {
            return Err("version de politique WFP inconnue");
        }
        // Le moteur refuse d'armer sur un resolveur routable: une declaration
        // posee qui en porte un contredit le moteur et ne se compare pas.
        if !self.dns_resolver.is_loopback() {
            return Err("destination DNS de politique WFP invalide");
        }
        let chemin_valide = |c: &str| !c.is_empty() && !c.contains('\0');
        if !chemin_valide(&self.daemon_executable)
            || self
                .coeur_executable
                .as_deref()
                .is_some_and(|c| !chemin_valide(c))
            || self
                .resolveur_executable
                .as_deref()
                .is_some_and(|c| !chemin_valide(c))
        {
            return Err("chemin de politique WFP invalide");
        }
        if Sid::lire_texte(&self.identite).is_none()
            || self
                .resolveur_sid
                .as_deref()
                .is_some_and(|s| Sid::lire_texte(s).is_none())
        {
            return Err("identite de politique WFP invalide");
        }
        if self.tunnel_luid == Some(0) {
            return Err("interface de politique WFP invalide");
        }
        Ok(())
    }

    /// L'identite que designe `Identity::Current` dans la reference: celle
    /// que le moteur a lue dans son jeton. Valide par construction apres
    /// `lire`.
    pub fn identite_courante(&self) -> Result<Sid, &'static str> {
        Sid::lire_texte(&self.identite).ok_or("identite de politique WFP invalide")
    }

    /// La politique que `wfp_plan::plan` recoit, champs qu'il ne lit pas a
    /// leur valeur neutre.
    pub fn firewall_policy(&self) -> FirewallPolicy {
        FirewallPolicy {
            tunnel_interface: None,
            tunnel_luid: self.tunnel_luid,
            fwmark: None,
            dns_resolver: self.dns_resolver,
            allow_lan: self.allow_lan,
            coeur_uid: None,
            coeur_executable: self.coeur_executable.as_ref().map(PathBuf::from),
            resolveur_uid: None,
            resolveur_executable: self.resolveur_executable.as_ref().map(PathBuf::from),
            resolveur_sid: self.resolveur_sid.clone(),
            resolveur_embarque: self.resolveur_embarque,
        }
    }

    /// Le plan, par le code meme que le moteur execute.
    pub fn plan(&self) -> Vec<FilterSpec> {
        wfp_plan::plan(
            &self.firewall_policy(),
            PathBuf::from(&self.daemon_executable),
            self.tunnel_luid,
        )
    }

    /// Les filtres que le moteur remet a WFP, couche par couche, par la
    /// traduction meme que `windows::mod` emploie.
    pub fn reference(&self) -> Result<Vec<FiltreWfp>, &'static str> {
        self.valider()?;
        wfp_plan::filtres_wfp(&self.plan()).map_err(|_| "reference WFP impossible")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn env(n: u32) -> EnvironnementMoteur {
        EnvironnementMoteur {
            executable: PathBuf::from(r"C:\Bifrost\bifrost-daemon.exe"),
            identite: "S-1-5-80-1-2-3-4-5".into(),
            interface: (n & 1 == 1).then_some(0x0123_4567_89ab_cdef),
        }
    }

    /// Une politique complete telle que le superviseur la remet au moteur.
    /// Les champs que WFP ne lit pas sont remplis expres, et `tunnel_luid`
    /// de la politique differe de celui que le moteur a resolu: si la
    /// projection ou le rendu en dependaient, les recettes ci-dessous le
    /// verraient.
    fn remise(n: u32) -> FirewallPolicy {
        FirewallPolicy {
            tunnel_interface: Some("Bifrost".into()),
            tunnel_luid: Some(0x7777),
            fwmark: Some(51820),
            dns_resolver: if n & 2 == 2 {
                "::1".parse().unwrap()
            } else {
                "127.0.0.1".parse().unwrap()
            },
            allow_lan: n & 4 == 4,
            coeur_uid: Some(1001),
            coeur_executable: (n & 8 == 8)
                .then(|| PathBuf::from(r"C:\Bifrost\coeurs\sing-box.exe")),
            resolveur_uid: Some(1002),
            resolveur_executable: (n & 16 == 16)
                .then(|| PathBuf::from(r"C:\Bifrost\dnscrypt-proxy.exe")),
            resolveur_sid: (n & 32 == 32).then(|| "S-1-5-19".to_owned()),
            resolveur_embarque: n & 64 == 64,
        }
    }

    /// LA recette de la projection: sur 128 combinaisons, le plan que le
    /// moteur rendrait avec la politique REMISE et son environnement est
    /// exactement celui que la projection relue rend. Un champ que le plan lit
    /// et que la projection perdrait ferait correspondre au moteur une
    /// declaration qui ne dit pas tout.
    #[test]
    fn la_projection_ne_perd_rien_de_ce_que_wfp_rend() {
        for n in 0..128 {
            let p = remise(n);
            let e = env(n);
            let moteur =
                wfp_plan::filtres_wfp(&wfp_plan::plan(&p, e.executable.clone(), e.interface))
                    .unwrap();
            let v = serde_json::to_value(PolitiqueWfp::projeter(&p, &e).unwrap()).unwrap();
            let relue = PolitiqueWfp::lire(v).unwrap();
            assert_eq!(relue.reference().unwrap(), moteur, "cas {n}");
        }
    }

    /// La forme transmise est exactement celle que `lire` accepte: onze cles,
    /// options absentes en null.
    #[test]
    fn la_projection_serialisee_se_relit_a_l_identique() {
        for n in 0..128 {
            let p = PolitiqueWfp::projeter(&remise(n), &env(n)).unwrap();
            let v = serde_json::to_value(&p).unwrap();
            assert_eq!(v.as_object().unwrap().len(), CHAMPS.len(), "cas {n}");
            assert_eq!(PolitiqueWfp::lire(v).unwrap(), p, "cas {n}");
        }
        let v = serde_json::to_value(PolitiqueWfp::projeter(&remise(0), &env(0)).unwrap()).unwrap();
        for cle in [
            "resolveur_executable",
            "resolveur_sid",
            "coeur_executable",
            "tunnel_luid",
        ] {
            assert!(v[cle].is_null(), "option absente non ecrite en null: {cle}");
        }
    }

    /// Les deux projections ne se confondent pas: chaque lecteur strict
    /// refuse la forme de l'autre.
    #[test]
    fn les_projections_nft_et_wfp_ne_se_lisent_pas_l_une_pour_l_autre() {
        let wfp =
            serde_json::to_value(PolitiqueWfp::projeter(&remise(5), &env(5)).unwrap()).unwrap();
        assert!(crate::politique_nft::Politique::lire(wfp).is_err());
        let nft =
            serde_json::to_value(crate::politique_nft::Politique::projeter(&remise(5))).unwrap();
        assert!(PolitiqueWfp::lire(nft).is_err());
    }

    fn valide() -> Value {
        serde_json::to_value(PolitiqueWfp::projeter(&remise(127), &env(1)).unwrap()).unwrap()
    }

    #[test]
    fn une_politique_incomplete_ambigue_ou_hors_perimetre_est_refusee() {
        let v = valide();
        assert!(PolitiqueWfp::lire(v.clone()).is_ok());
        for cle in CHAMPS {
            let mut cas = v.clone();
            cas.as_object_mut().unwrap().remove(cle);
            assert!(
                PolitiqueWfp::lire(cas).is_err(),
                "champ absent accepte: {cle}"
            );
        }
        for (cle, valeur) in [
            ("projection", json!("nft")),
            ("schema_version", json!(2)),
            ("dns_resolver", json!("192.0.2.1")),
            ("dns_resolver", json!("0.0.0.0")),
            ("daemon_executable", json!("")),
            ("coeur_executable", json!("")),
            ("resolveur_executable", json!("a\u{0}b")),
            ("identite", json!("S-1-05-18")),
            ("identite", json!("")),
            ("resolveur_sid", json!("administrateurs")),
            ("tunnel_luid", json!(0)),
            ("tunnel_luid", json!(-1)),
            ("allow_lan", json!("oui")),
            ("inconnu", json!(true)),
        ] {
            let mut cas = v.clone();
            cas[cle] = valeur;
            assert!(PolitiqueWfp::lire(cas).is_err(), "accepte: {cle}");
        }
    }

    /// Une projection hors perimetre se projette sans devenir valide: c'est
    /// `lire`, puis `reference`, qui la refusent.
    #[test]
    fn une_politique_hors_perimetre_se_projette_sans_devenir_valide() {
        let mut p = remise(0);
        p.dns_resolver = "192.0.2.53".parse().unwrap();
        let projete = PolitiqueWfp::projeter(&p, &env(0)).unwrap();
        assert!(projete.reference().is_err());
        assert!(PolitiqueWfp::lire(serde_json::to_value(projete).unwrap()).is_err());
    }
}
