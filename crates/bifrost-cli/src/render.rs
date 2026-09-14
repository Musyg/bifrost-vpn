//! Mise en forme des reponses du daemon pour un terminal.

use bifrost_core::checks::{CheckReport, Verdict};
use bifrost_core::state::{State, TunnelStatus};

pub fn confirmation(command: &crate::Cmd) -> &'static str {
    match command {
        crate::Cmd::Connect { .. } => "tunnel monte",
        crate::Cmd::Disconnect => "tunnel demonte, kill switch desarme",
        _ => "ok",
    }
}

pub fn status(s: &TunnelStatus) -> String {
    let mut out = String::new();

    let etat = match &s.state {
        State::Disconnected => "deconnecte".to_owned(),
        State::Connecting { attempt } => format!("connexion en cours (tentative {attempt})"),
        State::Connected => "connecte".to_owned(),
        State::Reconnecting { attempt } => format!("reconnexion (tentative {attempt})"),
        State::Error { reason } => format!("erreur: {reason}"),
    };
    out.push_str(&format!("etat          {etat}\n"));

    // Le point le plus important de la sortie: si le kill switch n'est pas
    // arme alors que l'etat n'est pas "deconnecte", l'utilisateur fuit.
    let ks = if s.kill_switch_engaged {
        format!("arme ({})", s.firewall_backend)
    } else if s.state.expects_kill_switch() {
        format!(
            "NON ARME alors que l'etat est '{}' - le trafic peut fuir",
            s.state.name()
        )
    } else {
        "desarme".to_owned()
    };
    out.push_str(&format!("kill switch   {ks}\n"));

    if let Some(iface) = &s.interface {
        out.push_str(&format!("interface     {iface}\n"));
    }
    if let Some(ep) = &s.endpoint {
        out.push_str(&format!("endpoint      {ep}\n"));
    }
    match s.last_handshake_secs_ago {
        Some(secs) => out.push_str(&format!("handshake     il y a {secs} s\n")),
        None if s.state == State::Connected => {
            out.push_str("handshake     aucun\n");
        }
        None => {}
    }
    if s.rx_bytes > 0 || s.tx_bytes > 0 {
        out.push_str(&format!(
            "transfert     recu {}, emis {}\n",
            human_bytes(s.rx_bytes),
            human_bytes(s.tx_bytes)
        ));
    }
    out
}

pub fn check_report(report: &CheckReport) -> String {
    let mut out = String::from("Tests de fuite\n\n");

    for o in &report.outcomes {
        let verdict = match o.verdict {
            Verdict::Passed => "PASSED ",
            Verdict::Failed => "FAILED ",
            Verdict::Skipped => "SKIPPED",
        };
        out.push_str(&format!("{verdict}  {:<20}  {}\n", o.vector.id(), o.detail));
        // Affichee des qu'il y en a: un vecteur saute peut porter des paquets
        // observes que le verdict n'a pas pu imputer.
        for line in &o.evidence {
            out.push_str(&format!("                                 {line}\n"));
        }
    }

    let passed = report.count(Verdict::Passed);
    let failed = report.count(Verdict::Failed);
    let skipped = report.count(Verdict::Skipped);
    out.push_str(&format!(
        "\n{passed} passe(s), {failed} echec(s), {skipped} saute(s)\n"
    ));
    if skipped > 0 && failed == 0 {
        out.push_str(
            "Attention: un test saute n'est pas une preuve d'etancheite, \
             seulement l'absence de mesure.\n",
        );
    }
    out
}

fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 4] = ["o", "Kio", "Mio", "Gio"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} o")
    } else {
        format!("{v:.1} {}", UNITS[i])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bifrost_core::checks::{CheckOutcome, CheckVector};

    fn status_de(state: State, engaged: bool) -> TunnelStatus {
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

    /// Le cas dangereux doit sauter aux yeux: etat actif, kill switch absent.
    #[test]
    fn un_kill_switch_manquant_est_signale_explicitement() {
        let s = status(&status_de(State::Connected, false));
        assert!(s.contains("NON ARME"), "sortie: {s}");
        assert!(s.contains("fuir"), "sortie: {s}");
    }

    #[test]
    fn un_kill_switch_arme_affiche_son_backend() {
        let s = status(&status_de(State::Connected, true));
        assert!(s.contains("arme (nftables)"));
        assert!(!s.contains("NON ARME"));
    }

    #[test]
    fn deconnecte_sans_kill_switch_n_est_pas_une_alerte() {
        let mut st = status_de(State::Disconnected, false);
        st.interface = None;
        let s = status(&st);
        assert!(s.contains("desarme"));
        assert!(!s.contains("NON ARME"));
    }

    #[test]
    fn le_rapport_affiche_un_verdict_par_vecteur() {
        let report = CheckReport::new(
            CheckVector::ALL
                .iter()
                .map(|v| CheckOutcome::passed(*v, "ok"))
                .collect(),
        );
        let s = check_report(&report);
        for v in CheckVector::ALL {
            assert!(s.contains(v.id()), "vecteur absent: {}", v.id());
        }
        assert!(s.contains(&format!(
            "{} passe(s), 0 echec(s), 0 saute(s)",
            CheckVector::ALL.len()
        )));
    }

    #[test]
    fn un_echec_affiche_sa_preuve() {
        let report = CheckReport::new(vec![CheckOutcome::failed(
            CheckVector::DnsLeak,
            "1 paquet sorti",
            vec!["IP 10.77.0.2.5353 > 8.8.8.8.53: UDP".into()],
        )]);
        let s = check_report(&report);
        assert!(s.contains("FAILED"));
        assert!(s.contains("8.8.8.8.53"));
    }

    /// Un rapport tout en SKIPPED ne doit pas se lire comme un succes.
    #[test]
    fn des_tests_sautes_declenchent_un_avertissement() {
        let report = CheckReport::new(vec![CheckOutcome::skipped(
            CheckVector::ExitIp,
            "pas de root",
        )]);
        let s = check_report(&report);
        assert!(s.contains("SKIPPED"));
        assert!(s.contains("n'est pas une preuve d'etancheite"));
    }

    #[test]
    fn les_tailles_sont_lisibles() {
        assert_eq!(human_bytes(512), "512 o");
        assert_eq!(human_bytes(2048), "2.0 Kio");
        assert_eq!(human_bytes(5 * 1024 * 1024), "5.0 Mio");
    }
}
