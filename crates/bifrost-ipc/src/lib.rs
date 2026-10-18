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
//!   daemon indefiniment. Et dans le temps: une requete qui n'arrive pas
//!   complete dans le delai du serveur est rendue en erreur, plutot que de lui
//!   tenir une connexion indefiniment. Le serveur lit donc dans un runtime
//!   tokio dont le pilote de temps est actif.
//!
//! Et, dans l'autre sens, toujours: [`IpcClient::connect_verified`], le seul
//! constructeur du client, exige du SERVEUR une identite privilegiee (root par
//! `SO_PEERCRED`; pipe appartenant a LocalSystem, ou aussi aux Administrateurs
//! pour une commande) avant de lui ecrire quoi que ce soit. Sous Windows, un
//! pipe dont toutes les instances sont prises n'est pas un pipe absent: le
//! client attend une instance libre, dans une borne courte, et exige
//! l'identite de celle qu'il obtient.
//!
//! Un groupe ouvre le canal a des comptes qui ne sont pas administrateurs, et
//! ses membres n'y ont que trois commandes, `status`, `connect-stored` et
//! `disconnect`: le transport applique la decision de [`appelant`] a chaque
//! requete avant de la rendre au serveur. Sous Linux, c'est le groupe de la
//! politique (`AuthPolicy::allowed_gid`, le groupe `bifrost` du daemon): un
//! appelant admis seulement par lui a ces trois commandes, un appelant admis
//! par son uid (root) a tout le canal. Sous Windows, c'est un groupe d'acces
//! ([`groupe::GroupeDAcces`]): une ACE de plus dans la DACL du pipe, a un
//! masque qui permet d'echanger et rien d'autre, et seulement pour un groupe
//! cree localement par un administrateur; le transport identifie l'appelant
//! de chaque requete.

pub mod appelant;
pub mod auth;
#[cfg(windows)]
pub mod groupe;
pub mod protocol;
pub mod transport;

pub use appelant::{CommandeReservee, NiveauDAppelant, decider};
#[cfg(windows)]
pub use appelant::{CompteDuClient, EtapeDIdentification, Identification};
pub use auth::{Admission, AuthError, AuthPolicy, PeerIdentity, SupplementaryGroups};
#[cfg(windows)]
pub use groupe::{ErreurGroupe, GroupeDAcces};
pub use protocol::{Command, Request, Response};
pub use transport::{
    Connection, IpcClient, IpcError, IpcServer, ProprietaireDuPipe, ServerIdentityError,
    ServerRequirement, ServerRule, default_endpoint,
};
