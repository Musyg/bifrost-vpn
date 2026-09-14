//! Les vecteurs de fuite verifies par `bifrost-cli check`.
//!
//! Regle non negociable: un test qui ne peut pas s'executer dans
//! l'environnement courant retourne [`Verdict::Skipped`] avec sa raison. Jamais
//! [`Verdict::Passed`] par defaut. Un harnais qui passe silencieusement sans
//! rien tester est pire que pas de harnais.

use serde::{Deserialize, Serialize};

/// Les six vecteurs du document 02 partie 4, plus trois.
///
/// [`CheckVector::CoeurExemption`] ne vient pas du document: il est ne du
/// besoin d'ouvrir une sortie au coeur anti-censure. Toute exemption est un
/// trou potentiel, et une exemption dont personne ne mesure la LARGEUR n'est
/// qu'un trou qu'on croit etroit.
///
/// [`CheckVector::ResolveurExemption`] est son miroir inverse, et pas un
/// doublon: le coeur PORTE le trafic, donc sa sortie est large et seul son :53
/// lui est refuse; le resolveur chiffre ne sort QUE sur le :53, et malgre le
/// blocage. Une exception large lui ferait tenir lieu de second transport,
/// c'est-a-dire d'une sortie en clair hors tunnel accordee au composant qui
/// existe justement pour qu'il n'y en ait plus.
///
/// [`CheckVector::DohBypass`] non plus: il est ne d'un angle mort de
/// [`CheckVector::DnsLeak`]. Celui-la regarde le port 53 et rend PASSED
/// pendant qu'un navigateur resout en HTTPS sur le 443.
///
/// [`CheckVector::DaemonMort`] non plus, et il est ne d'un defaut mesure: le
/// cycle de vie systemd demontait le pare-feu a chaque arret, plantage compris.
/// Aucun autre vecteur ne le voyait, parce qu'aucun ne fait MOURIR le
/// composant qui protege. [`CheckVector::KillSwitchOnDrop`] en est le plus
/// proche et mesure autre chose: il detruit l'INTERFACE du tunnel, pas le
/// processus.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CheckVector {
    /// L'exemption du coeur laisse sortir le coeur, et rien d'autre.
    CoeurExemption,
    /// Le processus qui a arme le kill switch meurt: rien ne sort en clair.
    DaemonMort,
    /// Aucune requete DNS ne quitte l'interface physique en clair.
    DnsLeak,
    /// Aucun client ne peut resoudre en DoH hors du resolveur local.
    ///
    /// Le pendant de [`CheckVector::DnsLeak`], qui ne le voit pas: une requete
    /// DoH est du HTTPS sur le 443 et ne touche jamais le port 53 que le kill
    /// switch filtre.
    DohBypass,
    /// L'IP de sortie observee est celle du tunnel, pas celle du FAI.
    ExitIp,
    /// Aucun paquet IPv6 ne sort hors tunnel.
    Ipv6Leak,
    /// Le tunnel coupe brutalement ne produit aucun paquet en clair.
    KillSwitchOnDrop,
    /// La fenetre de reconnexion reste etanche.
    ReconnectWindow,
    /// L'exception du resolveur chiffre ouvre le :53, et rien d'autre.
    ResolveurExemption,
    /// Rien ne sort avant que le daemon ait arme le kill switch.
    StartupWindow,
}

impl CheckVector {
    pub const ALL: [CheckVector; 10] = [
        CheckVector::CoeurExemption,
        CheckVector::DaemonMort,
        CheckVector::DnsLeak,
        CheckVector::DohBypass,
        CheckVector::ExitIp,
        CheckVector::Ipv6Leak,
        CheckVector::KillSwitchOnDrop,
        CheckVector::ReconnectWindow,
        CheckVector::ResolveurExemption,
        CheckVector::StartupWindow,
    ];

    pub fn id(&self) -> &'static str {
        match self {
            CheckVector::CoeurExemption => "coeur-exemption",
            CheckVector::DaemonMort => "daemon-mort",
            CheckVector::DnsLeak => "dns-leak",
            CheckVector::DohBypass => "doh-bypass",
            CheckVector::ExitIp => "exit-ip",
            CheckVector::Ipv6Leak => "ipv6-leak",
            CheckVector::KillSwitchOnDrop => "kill-switch-on-drop",
            CheckVector::ReconnectWindow => "reconnect-window",
            CheckVector::ResolveurExemption => "resolveur-exemption",
            CheckVector::StartupWindow => "startup-window",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            CheckVector::CoeurExemption => "le coeur sort, et rien d'autre ne sort avec lui",
            CheckVector::DaemonMort => {
                "le daemon tue par SIGKILL: le kill switch tient, zero paquet en clair"
            }
            CheckVector::DnsLeak => "aucune requete DNS en clair hors tunnel",
            CheckVector::DohBypass => "aucun client ne resout en DoH hors du resolveur local",
            CheckVector::ExitIp => "l'IP de sortie est celle du tunnel",
            CheckVector::Ipv6Leak => "aucun paquet IPv6 hors tunnel",
            CheckVector::KillSwitchOnDrop => "tunnel coupe brutalement: zero paquet en clair",
            CheckVector::ReconnectWindow => "fenetre de reconnexion etanche",
            CheckVector::ResolveurExemption => {
                "le resolveur chiffre sort sur le :53, et nulle part ailleurs"
            }
            CheckVector::StartupWindow => "rien ne sort avant que le kill switch soit arme",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Verdict {
    Passed,
    Failed,
    Skipped,
}

/// Resultat d'un vecteur.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckOutcome {
    pub vector: CheckVector,
    pub verdict: Verdict,
    /// Pourquoi ce verdict. Obligatoire pour `Skipped` et `Failed`.
    pub detail: String,
    /// Preuve: paquets observes, chemin du pcap, sortie d'outil. Surtout en
    /// cas d'echec, mais un vecteur saute peut en porter aussi quand il a vu
    /// quelque chose sans pouvoir l'imputer.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<String>,
}

impl CheckOutcome {
    pub fn passed(vector: CheckVector, detail: impl Into<String>) -> Self {
        Self {
            vector,
            verdict: Verdict::Passed,
            detail: detail.into(),
            evidence: Vec::new(),
        }
    }

    pub fn skipped(vector: CheckVector, reason: impl Into<String>) -> Self {
        Self {
            vector,
            verdict: Verdict::Skipped,
            detail: reason.into(),
            evidence: Vec::new(),
        }
    }

    pub fn failed(vector: CheckVector, detail: impl Into<String>, evidence: Vec<String>) -> Self {
        Self {
            vector,
            verdict: Verdict::Failed,
            detail: detail.into(),
            evidence,
        }
    }
}

/// Rapport complet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckReport {
    pub outcomes: Vec<CheckOutcome>,
}

impl CheckReport {
    pub fn new(outcomes: Vec<CheckOutcome>) -> Self {
        Self { outcomes }
    }

    pub fn count(&self, verdict: Verdict) -> usize {
        self.outcomes
            .iter()
            .filter(|o| o.verdict == verdict)
            .count()
    }

    /// Vrai si au moins un vecteur a echoue. Un `Skipped` n'est pas un echec,
    /// mais il n'est pas non plus une preuve d'etancheite.
    pub fn has_failure(&self) -> bool {
        self.count(Verdict::Failed) > 0
    }

    /// Code de sortie du processus: 0 si rien n'a echoue, 1 sinon.
    pub fn exit_code(&self) -> i32 {
        if self.has_failure() { 1 } else { 0 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn les_vecteurs_ont_des_identifiants_uniques() {
        let mut ids: Vec<_> = CheckVector::ALL.iter().map(|v| v.id()).collect();
        ids.sort_unstable();
        let avant = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), avant, "identifiants dupliques");
        assert_eq!(avant, CheckVector::ALL.len());
    }

    /// Les DEUX exemptions sont deux vecteurs, et pas un seul.
    ///
    /// Elles mesurent la meme grandeur - la largeur d'une exception accordee a
    /// un composant - dans des sens opposes: le coeur PORTE le trafic, donc sa
    /// sortie est large et son :53 excepte; le resolveur chiffre ne sort QUE
    /// sur le :53. Les fondre en un seul vecteur reviendrait a mesurer une
    /// borne en croyant en mesurer deux.
    #[test]
    fn les_deux_exemptions_sont_deux_vecteurs_distincts() {
        assert!(CheckVector::ALL.contains(&CheckVector::CoeurExemption));
        assert!(CheckVector::ALL.contains(&CheckVector::ResolveurExemption));
        assert_ne!(
            CheckVector::CoeurExemption.id(),
            CheckVector::ResolveurExemption.id()
        );
        assert_eq!(CheckVector::ResolveurExemption.id(), "resolveur-exemption");
    }

    #[test]
    fn un_rapport_avec_des_skipped_n_est_pas_un_echec() {
        let r = CheckReport::new(
            CheckVector::ALL
                .iter()
                .map(|v| CheckOutcome::skipped(*v, "environnement non supporte"))
                .collect(),
        );
        assert!(!r.has_failure());
        assert_eq!(r.exit_code(), 0);
        assert_eq!(r.count(Verdict::Skipped), CheckVector::ALL.len());
        assert_eq!(r.count(Verdict::Passed), 0);
    }

    #[test]
    fn un_seul_echec_fait_echouer_le_rapport() {
        let mut outcomes: Vec<_> = CheckVector::ALL
            .iter()
            .map(|v| CheckOutcome::passed(*v, "ok"))
            .collect();
        outcomes[3] = CheckOutcome::failed(
            CheckVector::KillSwitchOnDrop,
            "2 paquets en clair observes",
            vec!["IP 10.0.0.5 > 93.184.216.34".into()],
        );
        let r = CheckReport::new(outcomes);
        assert!(r.has_failure());
        assert_eq!(r.exit_code(), 1);
    }

    #[test]
    fn un_echec_porte_toujours_une_preuve() {
        let o = CheckOutcome::failed(CheckVector::DnsLeak, "fuite", vec!["preuve".into()]);
        assert!(!o.evidence.is_empty());
        assert!(!o.detail.is_empty());
    }

    #[test]
    fn serialisation_stable_des_verdicts() {
        let o = CheckOutcome::skipped(CheckVector::Ipv6Leak, "pas de root");
        let json = serde_json::to_string(&o).unwrap();
        assert!(json.contains("\"ipv6-leak\""));
        assert!(json.contains("\"SKIPPED\""));
    }
}
