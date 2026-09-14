//! Machine a etats du tunnel.
//!
//! Fonction pure: `(etat, evenement) -> (etat, actions)`. Aucun appel systeme
//! ici, donc chaque transition est testable sans privileges ni reseau.
//!
//! L'invariant central est verifie par les tests: le kill switch est arme avant
//! la premiere tentative de connexion et n'est desarme que par un `Disconnect`
//! explicite. Aucune panne, aucun echec de handshake, aucun passage par `Error`
//! ne le leve.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::config::TunnelConfig;
use crate::ports::FirewallPolicy;

/// Plafond du backoff exponentiel entre deux tentatives.
pub const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// Etat du tunnel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum State {
    /// Aucun tunnel, aucun filtre. Le seul etat ou le trafic sort librement.
    Disconnected,
    /// Kill switch arme, tunnel en cours d'etablissement.
    Connecting { attempt: u32 },
    /// Tunnel etabli, handshake frais.
    Connected,
    /// Tunnel tombe, nouvelle tentative planifiee. Kill switch toujours arme.
    Reconnecting { attempt: u32 },
    /// Echec non recuperable. Kill switch toujours arme: fail-closed.
    Error { reason: String },
}

impl State {
    /// Le kill switch doit-il etre arme dans cet etat.
    ///
    /// C'est l'invariant de securite du produit: seul `Disconnected` autorise
    /// le trafic a sortir.
    pub fn expects_kill_switch(&self) -> bool {
        !matches!(self, State::Disconnected)
    }

    pub fn name(&self) -> &'static str {
        match self {
            State::Disconnected => "disconnected",
            State::Connecting { .. } => "connecting",
            State::Connected => "connected",
            State::Reconnecting { .. } => "reconnecting",
            State::Error { .. } => "error",
        }
    }
}

/// Evenements consommes par la machine a etats.
#[derive(Debug, Clone)]
pub enum Event {
    /// Demande de connexion. La config est deja validee et l'endpoint resolu.
    Connect(Box<TunnelConfig>),
    /// Demande de deconnexion. Seul evenement qui desarme le kill switch.
    Disconnect,
    /// L'interface du tunnel existe et est configuree.
    TunnelUp,
    /// Premier handshake vu avec le pair.
    HandshakeOk,
    /// La tentative a echoue. `retryable` distingue une panne reseau d'une
    /// erreur de configuration ou de privileges.
    TunnelFailed { reason: String, retryable: bool },
    /// Le tunnel etabli est tombe (handshake perime, interface disparue).
    TunnelLost { reason: String },
    /// Le delai de backoff est ecoule.
    RetryTimer,
    /// La machine sort d'une mise en veille.
    ///
    /// Ne change aucun etat: il demande de REAFFIRMER ce que l'etat courant
    /// exige deja. La mesure du 17 aout 2026 a montre que les filtres WFP
    /// survivent bien a une veille S3, mais sur une machine, un pilote reseau
    /// et une duree donnes. WireGuardNT, de son cote, embarque un fil de
    /// contournement parce que les notifications d'interface peuvent mentir
    /// lors d'un evenement PnP, et une reprise en est un. Reaffirmer coute une
    /// transaction WFP idempotente; parier sur la survie coute une fuite le
    /// jour ou la mesure ne vaut plus.
    SystemResumed,
}

/// Effets de bord a executer par le daemon, dans l'ordre.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Pose les filtres. Idempotent, applique en transaction.
    EngageKillSwitch(Box<FirewallPolicy>),
    /// Retire les filtres. Toujours la derniere action d'une deconnexion.
    DisengageKillSwitch,
    /// Cree et configure l'interface, les routes et les regles.
    BringTunnelUp(Box<TunnelConfig>),
    /// Detruit l'interface et nettoie routes et regles.
    BringTunnelDown(Box<TunnelConfig>),
    /// Pointe le resolveur systeme vers le resolveur local.
    ApplyDns(Box<TunnelConfig>),
    /// Restaure la configuration DNS d'origine.
    RestoreDns,
    /// Replanifie une tentative apres ce delai.
    ScheduleRetry(Duration),
}

/// Resultat d'une transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transition {
    pub state: State,
    pub actions: Vec<Action>,
    /// Vrai si l'evenement n'a pas de sens dans l'etat courant et a ete ignore.
    pub ignored: bool,
}

impl Transition {
    fn to(state: State, actions: Vec<Action>) -> Self {
        Self {
            state,
            actions,
            ignored: false,
        }
    }

    fn ignored(state: State) -> Self {
        Self {
            state,
            actions: Vec::new(),
            ignored: true,
        }
    }
}

/// Vue de l'etat exposee au client par l'IPC.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunnelStatus {
    pub state: State,
    pub kill_switch_engaged: bool,
    pub firewall_backend: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_handshake_secs_ago: Option<u64>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

/// Delai avant la tentative numero `attempt` (1 = premiere reprise).
///
/// Doublement a chaque tentative, plafonne a [`MAX_BACKOFF`]. Le decalage est
/// borne a 6 avant meme le plafond, sinon un compteur eleve deborderait le
/// decalage bien avant d'atteindre la duree maximale.
pub fn backoff(attempt: u32) -> Duration {
    let shift = attempt.saturating_sub(1).min(6);
    Duration::from_secs(1u64 << shift).min(MAX_BACKOFF)
}

/// La machine a etats. Detient l'etat courant et la config du tunnel actif.
#[derive(Debug)]
pub struct StateMachine {
    state: State,
    config: Option<Box<TunnelConfig>>,
}

impl Default for StateMachine {
    fn default() -> Self {
        Self::new()
    }
}

impl StateMachine {
    pub fn new() -> Self {
        Self {
            state: State::Disconnected,
            config: None,
        }
    }

    pub fn state(&self) -> &State {
        &self.state
    }

    pub fn config(&self) -> Option<&TunnelConfig> {
        self.config.as_deref()
    }

    /// Applique un evenement et renvoie l'etat resultant plus les actions.
    pub fn handle(&mut self, event: Event) -> Transition {
        let transition = self.next(event);
        self.state = transition.state.clone();
        transition
    }

    fn next(&mut self, event: Event) -> Transition {
        match (&self.state, event) {
            // --- Demarrage ---
            (State::Disconnected, Event::Connect(cfg)) => {
                let policy = FirewallPolicy::from_config(&cfg);
                self.config = Some(cfg.clone());
                Transition::to(
                    State::Connecting { attempt: 1 },
                    vec![
                        // Le kill switch est arme AVANT toute tentative: si la
                        // creation de l'interface echoue, rien n'a fuite.
                        Action::EngageKillSwitch(Box::new(policy)),
                        Action::BringTunnelUp(cfg),
                    ],
                )
            }

            // --- Montee de l'interface ---
            (State::Connecting { attempt }, Event::TunnelUp) => {
                let Some(cfg) = self.config.clone() else {
                    return Transition::ignored(self.state.clone());
                };
                // L'interface existe: on reengage pour autoriser le trafic qui
                // sort par le tunnel, puis on bascule le DNS.
                let mut policy = FirewallPolicy::from_config(&cfg);
                policy.tunnel_interface = Some(cfg.interface.clone());
                Transition::to(
                    State::Connecting { attempt: *attempt },
                    vec![
                        Action::EngageKillSwitch(Box::new(policy)),
                        Action::ApplyDns(cfg),
                    ],
                )
            }

            (State::Connecting { .. }, Event::HandshakeOk) => {
                Transition::to(State::Connected, Vec::new())
            }

            // --- Reprise apres veille ---
            //
            // L'etat ne bouge pas: seul le kill switch est repose, a l'identique
            // et sans condition sur ce qu'il en reste. Interroger d'abord les
            // filtres pour ne reengager qu'en cas de manque supposerait que
            // l'inventaire lu apres une reprise soit fiable, ce qui est
            // precisement ce dont on se mefie. `engage` est idempotent et
            // transactionnel; le pire cas est une transaction pour rien.
            //
            // Le chemin passe par la meme action que le reste, donc le LUID est
            // redemande au peripherique au moment de l'execution, comme apres
            // `TunnelUp`. C'est la moitie qui compte: des filtres intacts qui
            // designent un adaptateur perime laisseraient passer tout autant.
            (etat, Event::SystemResumed) if etat.expects_kill_switch() => {
                let Some(cfg) = self.config.clone() else {
                    // Sans configuration il n'y a rien a reposer. Ne devrait pas
                    // arriver hors de `Disconnected`, mais un etat incoherent ne
                    // justifie pas de poser une politique inventee.
                    return Transition::ignored(self.state.clone());
                };
                let mut policy = FirewallPolicy::from_config(&cfg);
                policy.tunnel_interface = Some(cfg.interface.clone());
                Transition::to(
                    self.state.clone(),
                    vec![Action::EngageKillSwitch(Box::new(policy))],
                )
            }
            // `Disconnected` y compris: le seul etat ou le trafic sort
            // librement est aussi le seul ou reposer des filtres serait un bug.
            (_, Event::SystemResumed) => Transition::ignored(self.state.clone()),

            // --- Echecs ---
            (
                State::Connecting { attempt } | State::Reconnecting { attempt },
                Event::TunnelFailed { reason, retryable },
            ) => {
                let cfg = self.config.clone();
                let mut actions = Vec::new();
                if let Some(cfg) = cfg {
                    actions.push(Action::BringTunnelDown(cfg));
                }
                if retryable {
                    let next = attempt.saturating_add(1);
                    actions.push(Action::ScheduleRetry(backoff(*attempt)));
                    // Le kill switch reste arme pendant toute la fenetre de
                    // reconnexion. C'est le vecteur de fuite classique.
                    Transition::to(State::Reconnecting { attempt: next }, actions)
                } else {
                    // Echec definitif: on ne desarme pas non plus. L'utilisateur
                    // doit demander explicitement la deconnexion.
                    Transition::to(State::Error { reason }, actions)
                }
            }

            (State::Connected, Event::TunnelLost { reason }) => {
                let cfg = self.config.clone();
                let mut actions = Vec::new();
                if let Some(cfg) = cfg {
                    actions.push(Action::BringTunnelDown(cfg));
                }
                actions.push(Action::ScheduleRetry(backoff(1)));
                tracing::warn!(reason = %reason, "tunnel perdu, reconnexion");
                Transition::to(State::Reconnecting { attempt: 2 }, actions)
            }

            // --- Reprise ---
            (State::Reconnecting { attempt }, Event::RetryTimer) => {
                let Some(cfg) = self.config.clone() else {
                    return Transition::ignored(self.state.clone());
                };
                let policy = FirewallPolicy::from_config(&cfg);
                Transition::to(
                    State::Connecting { attempt: *attempt },
                    vec![
                        // Reengage: idempotent, mais garantit que les filtres
                        // sont bien la meme si quelque chose les a retires.
                        Action::EngageKillSwitch(Box::new(policy)),
                        Action::BringTunnelUp(cfg),
                    ],
                )
            }

            // --- Arret ---
            (State::Disconnected, Event::Disconnect) => Transition::ignored(State::Disconnected),

            (_, Event::Disconnect) => {
                let cfg = self.config.take();
                let mut actions = vec![Action::RestoreDns];
                if let Some(cfg) = cfg {
                    actions.push(Action::BringTunnelDown(cfg));
                }
                // Le desarmement du kill switch est la DERNIERE action: le
                // trafic ne peut pas sortir avant que le tunnel soit tombe.
                actions.push(Action::DisengageKillSwitch);
                Transition::to(State::Disconnected, actions)
            }

            // --- Evenements sans effet dans l'etat courant ---
            (state, event) => {
                tracing::debug!(
                    state = state.name(),
                    event = ?std::mem::discriminant(&event),
                    "evenement ignore"
                );
                Transition::ignored(state.clone())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{DnsPolicy, Endpoint, IpNet, PeerConfig, WgKey};
    use std::net::{IpAddr, Ipv4Addr};

    /// Le 43e caractere d'une cle ne porte que quatre bits utiles, donc tous
    /// ne conviennent pas. 'A' vaut zero: il termine n'importe quelle cle.
    fn key(c: char) -> WgKey {
        let mut s: String = std::iter::repeat_n(c, 42).collect();
        s.push('A');
        s.push('=');
        s.parse().unwrap()
    }

    fn cfg() -> Box<TunnelConfig> {
        Box::new(TunnelConfig {
            interface: "wg0".into(),
            addresses: vec!["10.2.0.2/32".parse::<IpNet>().unwrap()],
            mtu: 1420,
            dns: DnsPolicy {
                local_resolver: IpAddr::V4(Ipv4Addr::LOCALHOST),
                upstream: vec![IpAddr::V4(Ipv4Addr::new(10, 2, 0, 1))],
                embarque: false,
                anti_telemetrie: crate::config::ProfilTelemetrie::Aucun,
            },
            allow_lan: false,
            portage: crate::config::Portage::Wireguard(Box::new(crate::config::WireguardParams {
                private_key: key('a'),
                fwmark: 0xca6c,
                routing_table: 51820,
                listen_port: None,
                peer: PeerConfig {
                    public_key: key('b'),
                    preshared_key: None,
                    endpoint: Endpoint {
                        addr: "203.0.113.7:51820".parse().unwrap(),
                    },
                    allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
                    persistent_keepalive: 25,
                },
            })),
        })
    }

    fn connected() -> StateMachine {
        let mut m = StateMachine::new();
        m.handle(Event::Connect(cfg()));
        m.handle(Event::TunnelUp);
        m.handle(Event::HandshakeOk);
        assert_eq!(*m.state(), State::Connected);
        m
    }

    fn engages(actions: &[Action]) -> bool {
        actions
            .iter()
            .any(|a| matches!(a, Action::EngageKillSwitch(_)))
    }

    fn disengages(actions: &[Action]) -> bool {
        actions.contains(&Action::DisengageKillSwitch)
    }

    #[test]
    fn connexion_arme_le_kill_switch_avant_de_monter_le_tunnel() {
        let mut m = StateMachine::new();
        let t = m.handle(Event::Connect(cfg()));

        assert_eq!(t.state, State::Connecting { attempt: 1 });
        // L'ordre est la garantie: armer, puis seulement monter le tunnel.
        assert!(matches!(t.actions[0], Action::EngageKillSwitch(_)));
        assert!(matches!(t.actions[1], Action::BringTunnelUp(_)));
        assert_eq!(t.actions.len(), 2);
    }

    #[test]
    fn le_premier_engage_ne_connait_pas_encore_l_interface() {
        let mut m = StateMachine::new();
        let t = m.handle(Event::Connect(cfg()));
        let Action::EngageKillSwitch(policy) = &t.actions[0] else {
            panic!("premiere action attendue: EngageKillSwitch");
        };
        assert_eq!(policy.tunnel_interface, None);
    }

    #[test]
    fn tunnel_up_reengage_avec_l_interface_puis_bascule_le_dns() {
        let mut m = StateMachine::new();
        m.handle(Event::Connect(cfg()));
        let t = m.handle(Event::TunnelUp);

        let Action::EngageKillSwitch(policy) = &t.actions[0] else {
            panic!("premiere action attendue: EngageKillSwitch");
        };
        assert_eq!(policy.tunnel_interface.as_deref(), Some("wg0"));
        assert!(matches!(t.actions[1], Action::ApplyDns(_)));
        // Toujours en Connecting: l'interface existe mais le handshake non.
        assert_eq!(t.state, State::Connecting { attempt: 1 });
    }

    #[test]
    fn handshake_fait_passer_en_connected() {
        let mut m = StateMachine::new();
        m.handle(Event::Connect(cfg()));
        m.handle(Event::TunnelUp);
        let t = m.handle(Event::HandshakeOk);
        assert_eq!(t.state, State::Connected);
        assert!(t.actions.is_empty());
    }

    #[test]
    fn perte_du_tunnel_reconnecte_sans_lever_le_kill_switch() {
        let mut m = connected();
        let t = m.handle(Event::TunnelLost {
            reason: "handshake perime".into(),
        });

        assert_eq!(t.state, State::Reconnecting { attempt: 2 });
        assert!(!disengages(&t.actions), "fuite: kill switch leve sur perte");
        assert!(matches!(t.actions[0], Action::BringTunnelDown(_)));
        assert!(matches!(t.actions[1], Action::ScheduleRetry(_)));
        assert!(t.state.expects_kill_switch());
    }

    #[test]
    fn echec_recuperable_replanifie_avec_backoff_croissant() {
        let mut m = StateMachine::new();
        m.handle(Event::Connect(cfg()));

        let mut delais = Vec::new();
        for _ in 0..4 {
            let t = m.handle(Event::TunnelFailed {
                reason: "reseau injoignable".into(),
                retryable: true,
            });
            assert!(!disengages(&t.actions));
            let Some(Action::ScheduleRetry(d)) = t
                .actions
                .iter()
                .find(|a| matches!(a, Action::ScheduleRetry(_)))
                .cloned()
            else {
                panic!("ScheduleRetry attendu");
            };
            delais.push(d);
            m.handle(Event::RetryTimer);
        }

        assert_eq!(
            delais,
            vec![
                Duration::from_secs(1),
                Duration::from_secs(2),
                Duration::from_secs(4),
                Duration::from_secs(8),
            ]
        );
    }

    #[test]
    fn backoff_double_puis_plafonne() {
        assert_eq!(backoff(1), Duration::from_secs(1));
        assert_eq!(backoff(2), Duration::from_secs(2));
        assert_eq!(backoff(5), Duration::from_secs(16));
        // 1 << 5 = 32 s, ramene au plafond.
        assert_eq!(backoff(6), MAX_BACKOFF);
        assert_eq!(backoff(50), MAX_BACKOFF);
        assert_eq!(backoff(u32::MAX), MAX_BACKOFF);
        // Croissance monotone: une reprise ne doit jamais devenir plus rapide.
        for n in 1..40 {
            assert!(backoff(n) <= backoff(n + 1), "regression a l'etape {n}");
        }
    }

    #[test]
    fn echec_non_recuperable_va_en_error_avec_kill_switch_arme() {
        let mut m = StateMachine::new();
        m.handle(Event::Connect(cfg()));
        let t = m.handle(Event::TunnelFailed {
            reason: "module wireguard absent".into(),
            retryable: false,
        });

        assert_eq!(
            t.state,
            State::Error {
                reason: "module wireguard absent".into()
            }
        );
        assert!(!disengages(&t.actions), "fuite: kill switch leve sur Error");
        assert!(t.state.expects_kill_switch());
    }

    #[test]
    fn retry_reengage_le_kill_switch_avant_de_remonter() {
        let mut m = StateMachine::new();
        m.handle(Event::Connect(cfg()));
        m.handle(Event::TunnelFailed {
            reason: "timeout".into(),
            retryable: true,
        });
        let t = m.handle(Event::RetryTimer);

        assert_eq!(t.state, State::Connecting { attempt: 2 });
        assert!(matches!(t.actions[0], Action::EngageKillSwitch(_)));
        assert!(matches!(t.actions[1], Action::BringTunnelUp(_)));
    }

    #[test]
    fn deconnexion_desarme_le_kill_switch_en_dernier() {
        let mut m = connected();
        let t = m.handle(Event::Disconnect);

        assert_eq!(t.state, State::Disconnected);
        assert_eq!(t.actions[0], Action::RestoreDns);
        assert!(matches!(t.actions[1], Action::BringTunnelDown(_)));
        // Invariant: on ne rouvre le trafic qu'apres avoir tout demonte.
        assert_eq!(
            *t.actions.last().unwrap(),
            Action::DisengageKillSwitch,
            "le desarmement doit etre la derniere action"
        );
    }

    #[test]
    fn deconnexion_depuis_error_desarme_aussi() {
        let mut m = StateMachine::new();
        m.handle(Event::Connect(cfg()));
        m.handle(Event::TunnelFailed {
            reason: "fatal".into(),
            retryable: false,
        });
        let t = m.handle(Event::Disconnect);
        assert_eq!(t.state, State::Disconnected);
        assert!(disengages(&t.actions));
    }

    #[test]
    fn deconnexion_depuis_disconnected_est_idempotente() {
        let mut m = StateMachine::new();
        let t = m.handle(Event::Disconnect);
        assert!(t.ignored);
        assert!(t.actions.is_empty());
        assert_eq!(t.state, State::Disconnected);
    }

    #[test]
    fn connect_est_ignore_si_deja_connecte() {
        let mut m = connected();
        let t = m.handle(Event::Connect(cfg()));
        assert!(t.ignored);
        assert!(t.actions.is_empty());
        assert_eq!(t.state, State::Connected);
    }

    #[test]
    fn evenements_hors_sequence_sont_ignores() {
        let mut m = StateMachine::new();
        for e in [
            Event::TunnelUp,
            Event::HandshakeOk,
            Event::RetryTimer,
            Event::TunnelLost { reason: "x".into() },
        ] {
            let t = m.handle(e);
            assert!(t.ignored);
            assert_eq!(t.state, State::Disconnected);
        }
    }

    /// L'invariant du produit, verifie sur toutes les combinaisons.
    ///
    /// Depuis n'importe quel etat non deconnecte, aucun evenement autre que
    /// `Disconnect` ne doit produire un desarmement du kill switch.
    #[test]
    fn seul_disconnect_desarme_le_kill_switch() {
        let etats: Vec<fn() -> StateMachine> = vec![
            || {
                let mut m = StateMachine::new();
                m.handle(Event::Connect(cfg()));
                m
            },
            connected,
            || {
                let mut m = connected();
                m.handle(Event::TunnelLost { reason: "x".into() });
                m
            },
            || {
                let mut m = StateMachine::new();
                m.handle(Event::Connect(cfg()));
                m.handle(Event::TunnelFailed {
                    reason: "x".into(),
                    retryable: false,
                });
                m
            },
        ];

        let evenements: Vec<fn() -> Event> = vec![
            || Event::Connect(cfg()),
            || Event::TunnelUp,
            || Event::HandshakeOk,
            || Event::TunnelFailed {
                reason: "x".into(),
                retryable: true,
            },
            || Event::TunnelFailed {
                reason: "x".into(),
                retryable: false,
            },
            || Event::TunnelLost { reason: "x".into() },
            || Event::RetryTimer,
        ];

        for build in &etats {
            for event in &evenements {
                let mut m = build();
                let depart = m.state().clone();
                assert!(depart.expects_kill_switch());

                let t = m.handle(event());
                assert!(
                    !disengages(&t.actions),
                    "fuite: {:?} desarme le kill switch depuis {:?}",
                    std::mem::discriminant(&event()),
                    depart
                );
                assert!(
                    t.state.expects_kill_switch(),
                    "fuite: {depart:?} a atteint {:?} sans kill switch",
                    t.state
                );
            }
        }
    }

    /// Toute transition qui (re)tente une connexion doit d'abord armer.
    #[test]
    fn toute_tentative_de_connexion_arme_d_abord() {
        let mut m = StateMachine::new();
        let t = m.handle(Event::Connect(cfg()));
        assert!(engages(&t.actions));

        m.handle(Event::TunnelFailed {
            reason: "x".into(),
            retryable: true,
        });
        let t = m.handle(Event::RetryTimer);
        assert!(engages(&t.actions));

        // Et dans les deux cas, l'engage precede le montage du tunnel.
        let i_engage = t
            .actions
            .iter()
            .position(|a| matches!(a, Action::EngageKillSwitch(_)))
            .unwrap();
        let i_up = t
            .actions
            .iter()
            .position(|a| matches!(a, Action::BringTunnelUp(_)))
            .unwrap();
        assert!(i_engage < i_up);
    }

    #[test]
    fn disconnected_est_le_seul_etat_sans_kill_switch() {
        assert!(!State::Disconnected.expects_kill_switch());
        assert!(State::Connecting { attempt: 1 }.expects_kill_switch());
        assert!(State::Connected.expects_kill_switch());
        assert!(State::Reconnecting { attempt: 3 }.expects_kill_switch());
        assert!(State::Error { reason: "x".into() }.expects_kill_switch());
    }

    #[test]
    fn une_reprise_repose_le_kill_switch_sans_changer_d_etat() {
        let mut m = connected();
        let t = m.handle(Event::SystemResumed);

        assert_eq!(
            t.state,
            State::Connected,
            "la reprise n'est pas une bascule"
        );
        assert!(engages(&t.actions));
        assert!(!disengages(&t.actions), "une reprise ne desarme jamais");
        assert_eq!(t.actions.len(), 1, "rien d'autre que le reengagement");
    }

    /// La moitie qui compte. Des filtres intacts qui designent un adaptateur
    /// perime laissent passer tout autant, donc la politique reposee doit
    /// nommer le tunnel: c'est ce nom qui fait redemander son LUID au systeme
    /// au moment d'executer l'action.
    #[test]
    fn la_politique_reposee_apres_une_reprise_nomme_le_tunnel() {
        let mut m = connected();
        let t = m.handle(Event::SystemResumed);
        let Some(Action::EngageKillSwitch(policy)) = t.actions.first() else {
            panic!("action attendue: EngageKillSwitch");
        };
        assert_eq!(policy.tunnel_interface.as_deref(), Some("wg0"));
    }

    /// L'invariant du produit lu a l'envers: le seul etat ou le trafic sort
    /// librement est aussi le seul ou reposer des filtres serait un bug.
    ///
    /// La configuration est PLANTEE a la main, alors que `Disconnect` la retire
    /// et qu'aucun chemin normal ne mene a cette combinaison. C'est voulu:
    /// sans elle, l'absence d'action viendrait du `config` vide et non de la
    /// garde, et le test resterait vert meme la garde supprimee. Il ne
    /// mesurerait alors rien.
    #[test]
    fn une_reprise_ne_pose_rien_quand_le_trafic_est_libre() {
        let mut m = StateMachine::new();
        m.config = Some(cfg());
        assert_eq!(*m.state(), State::Disconnected);

        let t = m.handle(Event::SystemResumed);

        assert_eq!(t.state, State::Disconnected);
        assert!(
            t.actions.is_empty(),
            "rien ne doit etre pose: {:?}",
            t.actions
        );
    }

    /// Les etats de repli sont ceux ou une fuite se paierait le plus cher: le
    /// tunnel n'y porte rien, seul le kill switch retient le trafic.
    #[test]
    fn une_reprise_repose_aussi_dans_les_etats_de_repli() {
        for etat in [
            State::Connecting { attempt: 1 },
            State::Reconnecting { attempt: 2 },
            State::Error {
                reason: "panne".into(),
            },
        ] {
            let mut m = connected();
            m.state = etat.clone();
            let t = m.handle(Event::SystemResumed);
            assert_eq!(t.state, etat, "l'etat doit rester {etat:?}");
            assert!(engages(&t.actions), "rien repose depuis {etat:?}");
        }
    }
}
