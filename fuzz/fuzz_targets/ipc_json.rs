//! La deserialisation du protocole IPC: `bifrost_ipc::protocol::Request` (lue
//! par le daemon) et `Response` (lue par le client), puis la validation de la
//! configuration qu'une requete `connect` porte.
//!
//! Frontiere: une requete est ecrite par un client admis sur le socket et lue
//! par le daemon en root; la configuration de `connect` est ensuite validee
//! par `TunnelConfig::validate` avant tout effet. Une reponse est ecrite par le
//! daemon et lue par la CLI sous le compte de l'utilisateur. Cette cible
//! eprouve les deserialiseurs seuls, sans socket, donc bien plus vite que
//! `ipc_trame`, qui couvre le cadrage.
//!
//! Au-dela de l'absence de panique, la cible verifie pour une requete lue:
//! - aller-retour: reserialisee comme le client l'ecrit, elle se relit a
//!   l'identique (meme valeur JSON, meme commande, meme caractere mutant);
//! - la configuration d'un `connect` relue est identique et rend le meme
//!   verdict de validation.
#![no_main]

use bifrost_ipc::protocol::{Command, Request, Response};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|octets: &[u8]| {
    let _ = serde_json::from_slice::<Response>(octets);

    let Ok(requete) = serde_json::from_slice::<Request>(octets) else {
        return;
    };
    let ecrite = serde_json::to_vec(&requete).expect("une requete lue doit se serialiser");
    let relue: Request =
        serde_json::from_slice(&ecrite).expect("une requete serialisee doit se relire");
    assert_eq!(
        serde_json::to_value(&relue).expect("requete serialisable"),
        serde_json::to_value(&requete).expect("requete serialisable"),
        "la requete change a l'aller-retour"
    );
    assert_eq!(relue.version, requete.version);
    assert_eq!(relue.command.name(), requete.command.name());
    assert_eq!(relue.command.is_mutating(), requete.command.is_mutating());

    if let (Command::Connect { config: lue }, Command::Connect { config: relue }) =
        (&requete.command, &relue.command)
    {
        assert_eq!(relue, lue, "la configuration change a l'aller-retour");
        assert_eq!(
            relue.validate().map_err(|e| e.to_string()),
            lue.validate().map_err(|e| e.to_string()),
            "la validation change a l'aller-retour"
        );
    }
});
