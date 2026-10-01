//! Le profil de tunnel en TOML: `toml::from_str::<bifrost_core::TunnelConfig>`
//! puis `TunnelConfig::validate`, l'enchainement exact du daemon
//! (`server.rs`, `ouvrir_le_profil`, pour `connect-stored`) et de la CLI
//! (`profile.rs`, pour `connect --config`).
//!
//! Frontiere: le daemon lit en root le profil de son propre repertoire (en
//! clair ou descelle); la CLI lit, sous le compte de l'utilisateur, un fichier
//! qu'on lui designe. Dans les deux cas le contenu a pu arriver par un canal
//! (`bifrost profil recuperer`), signe mais ecrit par un tiers.
//!
//! Au-dela de l'absence de panique, la cible verifie qu'une configuration lue
//! traverse l'IPC comme la CLI l'y envoie: serialisee en JSON dans une requete
//! `connect`, puis relue par le daemon, elle revient identique et rend le meme
//! verdict de validation.
#![no_main]

use bifrost_core::TunnelConfig;
use bifrost_ipc::protocol::{Command, Request};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|octets: &[u8]| {
    let Ok(texte) = std::str::from_utf8(octets) else {
        return;
    };
    let Ok(config) = toml::from_str::<TunnelConfig>(texte) else {
        return;
    };
    let verdict = config.validate().map_err(|e| e.to_string());

    let trame = serde_json::to_vec(&Request::new(Command::Connect {
        config: Box::new(config.clone()),
    }))
    .expect("une configuration lue doit se serialiser");
    let relue: Request =
        serde_json::from_slice(&trame).expect("le daemon doit relire ce que le client envoie");
    let Command::Connect { config: relue } = relue.command else {
        panic!("une requete connect relue comme une autre commande");
    };
    assert_eq!(
        *relue, config,
        "la configuration change en traversant l'IPC"
    );
    assert_eq!(
        relue.validate().map_err(|e| e.to_string()),
        verdict,
        "la validation change en traversant l'IPC"
    );
});
