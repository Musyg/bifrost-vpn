//! Le lien de partage d'un profil de coeur: `bifrost_core::profil::Profil::depuis_lien`.
//!
//! Frontiere: un lien `vless://`, `hysteria2://` ou `hy2://` vient d'un
//! panneau d'administration, d'un fournisseur ou d'un QR code, donc d'un tiers.
//! Aucun chemin de production ne l'appelle encore (seules les recettes le
//! font); le document 07 le range parmi les parseurs a fuzzer. Le `Profil`
//! qu'il rend est le type que le daemon (root) recoit par l'IPC, dans la
//! configuration d'un `connect`, et dont il engendre celle du coeur; son
//! etiquette finit dans les journaux.
//!
//! Au-dela de l'absence de panique, la cible verifie:
//! - la lecture est deterministe: meme lien, meme profil ou meme refus;
//! - aucun caractere de controle venu du lien ne ressort: ni dans un refus,
//!   qui finit dans un journal, ni dans l'etiquette, ni dans les champs en
//!   clair que le coeur recoit (serveur, nom de serveur, `Host`, chemin). Les
//!   secrets (mot de passe, mot de passe d'obfuscation) restent libres;
//! - l'etiquette tient en `ETIQUETTE_MAX` caracteres sauf quand elle est la
//!   forme par defaut `serveur:port`;
//! - le profil traverse l'IPC: serialise puis relu par serde_json, comme le
//!   client l'envoie et le daemon le lit, il revient identique;
//! - un profil lu forme a lui seul une liste de profils valide.
#![no_main]

use bifrost_core::profil::{ETIQUETTE_MAX, Profil, Profils, Transport};
use libfuzzer_sys::fuzz_target;

fn sans_controle(champ: &str, texte: &str) {
    if let Some(c) = texte.chars().find(|c| c.is_control()) {
        panic!(
            "{champ} avec un caractere de controle U+{:04X}: {texte:?}",
            c as u32
        );
    }
}

fuzz_target!(|octets: &[u8]| {
    let Ok(lien) = std::str::from_utf8(octets) else {
        return;
    };
    let premiere = Profil::depuis_lien(lien);
    let seconde = Profil::depuis_lien(lien);
    match (&premiere, &seconde) {
        (Ok(a), Ok(b)) => assert_eq!(a, b, "deux lectures, deux profils"),
        (Err(a), Err(b)) => assert_eq!(a.to_string(), b.to_string(), "deux refus differents"),
        _ => panic!("deux lectures du meme lien ne rendent pas la meme issue"),
    }
    let profil = match premiere {
        Ok(p) => p,
        Err(e) => {
            sans_controle("refus", &e.to_string());
            return;
        }
    };

    sans_controle("etiquette", &profil.etiquette);
    match &profil.transport {
        Transport::VlessReality(v) => {
            sans_controle("serveur", &v.serveur);
            sans_controle("nom de serveur", &v.nom_de_serveur);
        }
        Transport::VlessWebsocket(v) | Transport::VlessHttpUpgrade(v) => {
            sans_controle("serveur", &v.serveur);
            sans_controle("nom de serveur", &v.nom_de_serveur);
            sans_controle("Host", &v.hote);
            sans_controle("chemin", &v.chemin);
        }
        Transport::Hysteria2(h) => {
            sans_controle("serveur", &h.serveur);
            sans_controle("nom de serveur", &h.nom_de_serveur);
        }
    }
    let (serveur, port) = profil.serveur();
    assert!(
        profil.etiquette.chars().count() <= ETIQUETTE_MAX
            || profil.etiquette == format!("{serveur}:{port}"),
        "etiquette de {} caracteres qui n'est pas la forme par defaut",
        profil.etiquette.chars().count()
    );

    let json = serde_json::to_string(&profil).expect("un profil lu doit se serialiser");
    let relu: Profil = serde_json::from_str(&json).expect("un profil serialise doit se relire");
    assert_eq!(relu, profil, "le profil change en traversant l'IPC");

    Profils::try_from(vec![profil]).expect("un profil lu forme une liste valide");
});
