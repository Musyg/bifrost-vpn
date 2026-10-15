//! Un faux daemon pour les recettes du poste de commande: un vrai
//! `IpcServer`, qui rend un etat connu a `status` et `Ok` a `connect-stored`
//! et `disconnect`.
//!
//! Inclus par `#[path = "commun/faux_daemon.rs"]` dans `tests/eleve_ipc.rs`,
//! et par `#[path = "../tests/commun/faux_daemon.rs"]` dans les recettes de
//! `src/commande.rs`: un fichier sous `tests/commun/` n'est pas une cible de
//! test a lui seul.

use bifrost_core::state::{State, TunnelStatus};
use bifrost_ipc::protocol::{Command, Response};
use bifrost_ipc::transport::IpcServer;

/// L'etat que le faux daemon rend a `status`: connecte, kill switch arme, de
/// quoi verifier que le poste de commande transporte bien les champs.
pub fn status_de_reference() -> TunnelStatus {
    TunnelStatus {
        state: State::Connected,
        kill_switch_engaged: true,
        firewall_backend: "nftables".into(),
        interface: Some("wg0".into()),
        endpoint: Some("203.0.113.7:51820".into()),
        last_handshake_secs_ago: Some(4),
        rx_bytes: 100,
        tx_bytes: 200,
    }
}

/// Sert les connexions ouvertes par le poste de commande. Chaque appel du
/// poste de commande ouvre une connexion, envoie une requete et la referme:
/// une requete par connexion, acceptees en boucle.
pub async fn servir(mut server: IpcServer) {
    loop {
        let mut conn = match server.accept().await {
            Ok(c) => c,
            Err(_) => return,
        };
        if let Ok(req) = conn.recv().await {
            let reponse = match req.command {
                Command::Status => Response::Status(Box::new(status_de_reference())),
                Command::ConnectStored | Command::Disconnect => Response::Ok,
                autre => Response::error(format!("commande inattendue: {}", autre.name())),
            };
            let _ = conn.send(&reponse).await;
        }
    }
}
