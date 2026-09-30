//! IPC entre le daemon privilegie et le client non privilegie.
//!
//! Deux garanties:
//!
//! - Le canal n'est joignable que par une identite autorisee. Sur Linux la
//!   verification se fait par `SO_PEERCRED` a l'acceptation, sur Windows par la
//!   DACL du named pipe, qui empeche un processus non privilegie de seulement
//!   ouvrir le canal.
//! - Le cadrage est borne. Une trame sans fin de ligne est refusee au-dela de
//!   [`protocol::MAX_FRAME_BYTES`] plutot que de faire grossir le tampon du
//!   daemon indefiniment.
//!
//! Et, dans l'autre sens, toujours: [`IpcClient::connect_verified`], le seul
//! constructeur du client, exige du SERVEUR une identite privilegiee (root par
//! `SO_PEERCRED`; pipe appartenant a LocalSystem, ou aussi aux Administrateurs
//! pour une commande) avant de lui ecrire quoi que ce soit.

pub mod auth;
pub mod protocol;
pub mod transport;

pub use auth::{AuthError, AuthPolicy, PeerIdentity};
pub use protocol::{Command, Request, Response};
pub use transport::{
    Connection, IpcClient, IpcError, IpcServer, ServerIdentityError, ServerRequirement, ServerRule,
    default_endpoint,
};
