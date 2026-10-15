//! La Vue: tout ce que l'utilisateur voit, derive PUREMENT d'un `TunnelStatus`
//! ou d'une erreur du poste de commande.
//!
//! Aucun effet, aucun appel systeme, aucune fenetre. La coquille graphique ne
//! fait que peindre ce que cette fonction rend, et la couleur du tray comme
//! les textes se testent donc ici, sans fenetre.
//!
//! # L'invariant que ces types portent
//!
//! Un etat qui n'est PAS `Connected` ne doit jamais se lire comme connecte, et
//! une erreur non plus. C'est la meme regle que le rendu du CLI
//! (`bifrost-cli/src/render.rs`): un kill switch absent alors que l'etat est
//! actif est une fuite, et il doit sauter aux yeux. Ici, la traduction en
//! couleur de tray suit la meme logique et une recette la falsifie.

use bifrost_core::state::{State, TunnelStatus};
use bifrost_ipc::transport::ServerIdentityError;

use crate::commande::ErreurCommande;

/// L'etat, en clair, tel que la coquille l'affiche.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EtatVue {
    Connecte,
    ConnexionEnCours,
    Reprise,
    Echec,
    Deconnecte,
    DaemonInjoignable,
    /// Un serveur tient le canal et n'a pris aucune connexion de plus dans le
    /// delai: rien ne dit que le daemon soit arrete.
    DaemonSansReponse,
    /// Le serveur du canal n'a pas l'identite du daemon, ou elle n'a pas pu
    /// etre lue: rien ne lui a ete envoye.
    ServeurNonAdmis,
    Refuse,
}

/// Le kill switch. `Inconnu` quand la coquille n'a pas obtenu l'etat du
/// daemon: on ne PRETEND pas qu'il est desarme, car ce serait rassurant a
/// tort.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EtatKillSwitch {
    Arme,
    Desarme,
    Inconnu,
}

/// La couleur du tray, parmi TROIS seulement.
///
/// - `Vert` uniquement quand le tunnel est etabli;
/// - `Gris` quand tout est au repos (deconnecte) ou quand l'etat est inconnu
///   (daemon injoignable ou sans reponse, serveur du canal non admis, refus):
///   rien n'est etabli, ou rien ne permet de le dire;
/// - `Rouge` quand le kill switch est (ou doit etre) arme sans qu'un tunnel
///   soit etabli: connexion en cours, reprise, echec. C'est un etat sur du
///   point de vue de la fuite, mais actif, et il ne doit jamais passer pour
///   vert.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CouleurTray {
    Vert,
    Gris,
    Rouge,
}

/// Ce que la coquille peint. Serialisable pour etre emis vers le front tel
/// quel.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Vue {
    pub etat: EtatVue,
    pub texte_etat: String,
    pub kill_switch: EtatKillSwitch,
    pub texte_kill_switch: String,
    pub couleur: CouleurTray,
    pub interface: Option<String>,
    pub endpoint: Option<String>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub peut_connecter: bool,
    pub peut_deconnecter: bool,
    /// Le texte de l'entree inactive << Etat >> du menu du tray.
    pub texte_menu_etat: String,
}

/// Ce que la Vue dit d'un serveur du canal non admis, selon la cause.
fn texte_non_admis(cause: ServerIdentityError) -> &'static str {
    match cause {
        ServerIdentityError::Refused => {
            "serveur du canal refuse: il n'a pas l'identite du daemon, rien ne lui a ete envoye"
        }
        ServerIdentityError::Unreadable => {
            "serveur du canal non identifie: rien ne lui a ete envoye"
        }
    }
}

impl Vue {
    /// La Vue derivee d'un etat rendu par le daemon.
    pub fn depuis_status(s: &TunnelStatus) -> Self {
        let (etat, texte_etat) = match &s.state {
            State::Connected => (EtatVue::Connecte, "connecte".to_owned()),
            State::Connecting { attempt } => (
                EtatVue::ConnexionEnCours,
                format!("connexion en cours (tentative {attempt})"),
            ),
            State::Reconnecting { attempt } => {
                (EtatVue::Reprise, format!("reprise (tentative {attempt})"))
            }
            State::Error { reason } => (EtatVue::Echec, format!("echec: {reason}")),
            State::Disconnected => (EtatVue::Deconnecte, "deconnecte".to_owned()),
        };

        // Le meme raisonnement que render.rs du CLI: le point le plus important
        // est un kill switch absent alors que l'etat est actif.
        let (kill_switch, texte_kill_switch) = if s.kill_switch_engaged {
            (
                EtatKillSwitch::Arme,
                format!("arme ({})", s.firewall_backend),
            )
        } else if s.state.expects_kill_switch() {
            (
                EtatKillSwitch::Desarme,
                format!(
                    "NON ARME alors que l'etat est '{}' - le trafic peut fuir",
                    s.state.name()
                ),
            )
        } else {
            (EtatKillSwitch::Desarme, "desarme".to_owned())
        };

        let couleur = match &s.state {
            State::Connected => CouleurTray::Vert,
            State::Disconnected => CouleurTray::Gris,
            // Connecting, Reconnecting, Error: actif sans etre etabli.
            _ => CouleurTray::Rouge,
        };

        let peut_connecter = matches!(s.state, State::Disconnected | State::Error { .. });
        let peut_deconnecter = !matches!(s.state, State::Disconnected);

        Self {
            etat,
            texte_menu_etat: format!("Etat: {texte_etat}"),
            texte_etat,
            kill_switch,
            texte_kill_switch,
            couleur,
            interface: s.interface.clone(),
            endpoint: s.endpoint.clone(),
            rx_bytes: s.rx_bytes,
            tx_bytes: s.tx_bytes,
            peut_connecter,
            peut_deconnecter,
        }
    }

    /// La Vue derivee d'une erreur du poste de commande.
    ///
    /// Aucune de ces erreurs ne se lit comme connecte, et aucune ne rend le tray
    /// vert: c'est l'invariant que la recette `une_erreur_ne_se_lit_jamais_
    /// comme_connecte` garde.
    pub fn depuis_erreur(e: &ErreurCommande) -> Self {
        let (etat, texte_etat, pourquoi) = match e {
            ErreurCommande::DaemonInjoignable(_) => (
                EtatVue::DaemonInjoignable,
                "daemon injoignable".to_owned(),
                "daemon injoignable",
            ),
            ErreurCommande::DaemonSansReponse(_) => (
                EtatVue::DaemonSansReponse,
                "daemon sans reponse dans le delai".to_owned(),
                "daemon sans reponse",
            ),
            ErreurCommande::ServeurNonAdmis(cause) => (
                EtatVue::ServeurNonAdmis,
                texte_non_admis(*cause).to_owned(),
                "serveur du canal non admis",
            ),
            ErreurCommande::Refuse(_) => (
                EtatVue::Refuse,
                "acces refuse par le daemon".to_owned(),
                "acces refuse par le daemon",
            ),
            ErreurCommande::Autre(m) => (
                EtatVue::Refuse,
                format!("erreur du daemon: {m}"),
                "erreur du daemon",
            ),
        };
        Self {
            etat,
            texte_menu_etat: format!("Etat: {texte_etat}"),
            texte_etat,
            kill_switch: EtatKillSwitch::Inconnu,
            texte_kill_switch: format!("inconnu ({pourquoi})"),
            couleur: CouleurTray::Gris,
            interface: None,
            endpoint: None,
            rx_bytes: 0,
            tx_bytes: 0,
            // On ne propose une action que quand on sait a quoi elle repond.
            peut_connecter: false,
            peut_deconnecter: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(state: State, engaged: bool) -> TunnelStatus {
        TunnelStatus {
            state,
            kill_switch_engaged: engaged,
            firewall_backend: "nftables".into(),
            interface: Some("wg0".into()),
            endpoint: Some("203.0.113.7:51820".into()),
            last_handshake_secs_ago: Some(12),
            rx_bytes: 2048,
            tx_bytes: 1024,
        }
    }

    #[test]
    fn connecte_est_vert_et_se_lit_connecte() {
        let v = Vue::depuis_status(&status(State::Connected, true));
        assert_eq!(v.etat, EtatVue::Connecte);
        assert_eq!(v.couleur, CouleurTray::Vert);
        assert_eq!(v.kill_switch, EtatKillSwitch::Arme);
        assert!(v.texte_kill_switch.contains("arme (nftables)"));
        assert!(v.peut_deconnecter);
        assert!(!v.peut_connecter);
    }

    #[test]
    fn deconnecte_est_gris_et_desarme_sans_alerte() {
        let v = Vue::depuis_status(&status(State::Disconnected, false));
        assert_eq!(v.etat, EtatVue::Deconnecte);
        assert_eq!(v.couleur, CouleurTray::Gris);
        assert_eq!(v.kill_switch, EtatKillSwitch::Desarme);
        assert_eq!(v.texte_kill_switch, "desarme");
        assert!(v.peut_connecter);
        assert!(!v.peut_deconnecter);
    }

    /// Le kill switch arme dit arme, et le backend est nomme. La falsification
    /// (rendre << arme >> sur un booleen faux) fait tomber cette recette.
    #[test]
    fn le_kill_switch_arme_dit_arme() {
        let v = Vue::depuis_status(&status(State::Connecting { attempt: 1 }, true));
        assert_eq!(v.kill_switch, EtatKillSwitch::Arme);
        assert!(v.texte_kill_switch.starts_with("arme"));
    }

    /// Un kill switch absent alors que l'etat est actif est une fuite: il faut
    /// que la Vue le crie, comme le fait le CLI.
    #[test]
    fn un_kill_switch_absent_en_etat_actif_est_signale() {
        let v = Vue::depuis_status(&status(State::Connected, false));
        assert_eq!(v.kill_switch, EtatKillSwitch::Desarme);
        assert!(v.texte_kill_switch.contains("NON ARME"));
        assert!(v.texte_kill_switch.contains("fuir"));
    }

    /// L'invariant central: aucun etat actif non etabli n'est vert, et un etat
    /// d'echec ne se lit jamais comme connecte. La couleur rouge dit << arme
    /// sans tunnel etabli >>.
    #[test]
    fn les_etats_actifs_non_etablis_sont_rouges_jamais_verts() {
        for state in [
            State::Connecting { attempt: 2 },
            State::Reconnecting { attempt: 3 },
            State::Error {
                reason: "handshake perime".into(),
            },
        ] {
            let v = Vue::depuis_status(&status(state.clone(), true));
            assert_ne!(
                v.etat,
                EtatVue::Connecte,
                "etat {state:?} lu comme connecte"
            );
            assert_ne!(v.couleur, CouleurTray::Vert, "etat {state:?} rendu vert");
            assert_eq!(v.couleur, CouleurTray::Rouge, "etat {state:?}");
        }
    }

    /// Une erreur de chaque variante, et de chaque cause du serveur non admis.
    fn une_erreur_de_chaque_sorte() -> Vec<ErreurCommande> {
        vec![
            ErreurCommande::DaemonInjoignable("pipe absent".into()),
            ErreurCommande::DaemonSansReponse("canal occupe".into()),
            ErreurCommande::ServeurNonAdmis(ServerIdentityError::Refused),
            ErreurCommande::ServeurNonAdmis(ServerIdentityError::Unreadable),
            ErreurCommande::Refuse("acces refuse".into()),
            ErreurCommande::Autre("configuration invalide".into()),
        ]
    }

    /// Une erreur du poste de commande ne se lit JAMAIS comme connecte, et ne
    /// rend jamais le tray vert. C'est le pendant, cote erreur, de l'invariant
    /// ci-dessus.
    #[test]
    fn une_erreur_ne_se_lit_jamais_comme_connecte() {
        for e in une_erreur_de_chaque_sorte() {
            let v = Vue::depuis_erreur(&e);
            assert_ne!(v.etat, EtatVue::Connecte, "erreur {e:?} lue comme connecte");
            assert_ne!(v.couleur, CouleurTray::Vert, "erreur {e:?} rendue verte");
            assert_eq!(v.couleur, CouleurTray::Gris, "erreur {e:?}");
            assert_eq!(v.kill_switch, EtatKillSwitch::Inconnu, "erreur {e:?}");
            assert!(v.texte_kill_switch.starts_with("inconnu"), "erreur {e:?}");
            assert!(
                !v.peut_connecter && !v.peut_deconnecter,
                "erreur {e:?}: une action proposee sans savoir a quoi elle repond"
            );
        }
    }

    #[test]
    fn daemon_injoignable_est_gris_et_dit_injoignable() {
        let v = Vue::depuis_erreur(&ErreurCommande::DaemonInjoignable("pipe absent".into()));
        assert_eq!(v.etat, EtatVue::DaemonInjoignable);
        assert_eq!(v.couleur, CouleurTray::Gris);
        assert!(v.texte_etat.contains("injoignable"));
    }

    /// Le serveur non admis, le canal occupe et le daemon injoignable ont
    /// chacun leur etat et leur texte, et aucun ne se dit comme un autre: un
    /// canal tenu par un autre processus, ou par un serveur qui ne prend plus
    /// de connexion, n'est pas un daemon absent.
    #[test]
    fn non_admis_sans_reponse_et_injoignable_ne_se_confondent_pas() {
        let injoignable = Vue::depuis_erreur(&ErreurCommande::DaemonInjoignable("absent".into()));
        let sans_reponse = Vue::depuis_erreur(&ErreurCommande::DaemonSansReponse("occupe".into()));
        let refuse = Vue::depuis_erreur(&ErreurCommande::ServeurNonAdmis(
            ServerIdentityError::Refused,
        ));
        let illisible = Vue::depuis_erreur(&ErreurCommande::ServeurNonAdmis(
            ServerIdentityError::Unreadable,
        ));
        let acces = Vue::depuis_erreur(&ErreurCommande::Refuse("acces refuse".into()));

        assert_eq!(sans_reponse.etat, EtatVue::DaemonSansReponse);
        assert_eq!(refuse.etat, EtatVue::ServeurNonAdmis);
        assert_eq!(illisible.etat, EtatVue::ServeurNonAdmis);
        let etats = [injoignable.etat, sans_reponse.etat, refuse.etat, acces.etat];
        for (i, a) in etats.iter().enumerate() {
            for b in &etats[i + 1..] {
                assert_ne!(a, b, "deux erreurs distinctes rendues dans le meme etat");
            }
        }

        assert!(
            sans_reponse
                .texte_etat
                .contains("sans reponse dans le delai")
        );
        for v in [&refuse, &illisible] {
            assert!(
                v.texte_etat.contains("rien ne lui a ete envoye"),
                "{}",
                v.texte_etat
            );
        }
        assert_ne!(refuse.texte_etat, illisible.texte_etat);
        for v in [&sans_reponse, &refuse, &illisible] {
            for texte in [&v.texte_etat, &v.texte_kill_switch, &v.texte_menu_etat] {
                assert!(!texte.contains("injoignable"), "{texte}");
            }
        }
    }

    /// Les noms que la coquille emet vers sa page, un par etat: la page les
    /// compare tels quels.
    #[test]
    fn chaque_etat_a_son_nom_emis() {
        for (etat, nom) in [
            (EtatVue::Connecte, "connecte"),
            (EtatVue::ConnexionEnCours, "connexion-en-cours"),
            (EtatVue::Reprise, "reprise"),
            (EtatVue::Echec, "echec"),
            (EtatVue::Deconnecte, "deconnecte"),
            (EtatVue::DaemonInjoignable, "daemon-injoignable"),
            (EtatVue::DaemonSansReponse, "daemon-sans-reponse"),
            (EtatVue::ServeurNonAdmis, "serveur-non-admis"),
            (EtatVue::Refuse, "refuse"),
        ] {
            assert_eq!(
                serde_json::to_value(etat).expect("serialisation"),
                serde_json::Value::from(nom)
            );
        }
    }
}
