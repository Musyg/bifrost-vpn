//! Le versant Linux de [`super::doh`]: la lecture des fichiers de politique.
//!
//! Meme partage que sous Windows: tout le jugement vit dans [`super::doh`], qui
//! se teste partout, et ce module ne fait que produire la liste de clients.
//! L'analyse JSON elle-meme est restee dans le module pur, pour qu'elle soit
//! eprouvee ailleurs que sur la seule cible Linux.
//!
//! # Ce qui differe de Windows, et pourquoi
//!
//! **Chrome lit TOUS les fichiers de son repertoire `managed`.** La ou le
//! registre porte une valeur par clef, il y a ici autant de declarations que de
//! fichiers, et deux qui se contredisent laissent le resultat dependre d'un
//! ordre que rien ne garantit. [`super::doh::fusionner`] refuse alors de
//! choisir.
//!
//! **Firefox a deux emplacements et une precedence.**
//! `/etc/firefox/policies/policies.json` l'emporte sur le
//! `distribution/policies.json` du repertoire d'installation. L'ordre est donc
//! su, contrairement au cas Chrome, et le premier trouve est le bon.
//!
//! **Il n'y a pas de pendant du client DNS de Windows.** `systemd-resolved`
//! sait faire du DoT, pas du DoH: il ne peut pas contourner le filtre `:53`
//! par le 443. Inventer un client toujours pince pour faire symetrique
//! ajouterait un succes qui ne mesure rien.
//!
//! # Angles morts, nommes
//!
//! Un navigateur installe par utilisateur (`~/.local`), en Flatpak, ou lance
//! depuis un repertoire quelconque, echappe a cette lecture: elle ne regarde
//! que les chemins pour tous. C'est la meme limite que sous Windows, aux
//! emplacements pres.

use std::path::{Path, PathBuf};

use bifrost_core::checks::{CheckOutcome, CheckVector};

use super::doh::{self, Client, Etat, Verdict};

/// Un navigateur de la famille Chromium: meme forme de politique, memes clefs,
/// seuls les chemins changent.
struct Chromium {
    nom: &'static str,
    binaires: &'static [&'static str],
    repertoires: &'static [&'static str],
}

const CHROMIUMS: &[Chromium] = &[
    Chromium {
        nom: "chrome",
        binaires: &["/usr/bin/google-chrome", "/usr/bin/google-chrome-stable"],
        repertoires: &["/etc/opt/chrome/policies/managed"],
    },
    Chromium {
        nom: "chromium",
        binaires: &["/usr/bin/chromium", "/usr/bin/chromium-browser"],
        // Selon la distribution, l'un ou l'autre. Les deux sont lus: un
        // repertoire absent ne declare rien et ne coute rien.
        repertoires: &[
            "/etc/chromium/policies/managed",
            "/etc/chromium-browser/policies/managed",
        ],
    },
    Chromium {
        nom: "edge",
        binaires: &["/usr/bin/microsoft-edge", "/usr/bin/microsoft-edge-stable"],
        repertoires: &["/etc/opt/edge/policies/managed"],
    },
];

const FIREFOX_BINAIRES: &[&str] = &[
    "/usr/bin/firefox",
    "/usr/lib/firefox/firefox",
    "/opt/firefox/firefox",
    "/snap/bin/firefox",
];

/// Par precedence: le systeme d'abord, l'installation ensuite.
const FIREFOX_POLITIQUES: &[&str] = &[
    "/etc/firefox/policies/policies.json",
    "/usr/lib/firefox/distribution/policies.json",
    "/opt/firefox/distribution/policies.json",
];

fn installe(binaires: &[&str]) -> bool {
    binaires.iter().any(|b| Path::new(b).exists())
}

/// Les `.json` d'un repertoire `managed`, tries par nom.
///
/// Le tri ne sert pas a departager: [`doh::fusionner`] refuse de le faire. Il
/// rend le message d'erreur STABLE d'une execution a l'autre, sans quoi deux
/// lancements accuseraient des fichiers dans un ordre different.
fn fichiers_json(repertoire: &str) -> Vec<PathBuf> {
    let Ok(entrees) = std::fs::read_dir(repertoire) else {
        return Vec::new();
    };
    let mut chemins: Vec<PathBuf> = entrees
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect();
    chemins.sort();
    chemins
}

fn nom_court(chemin: &Path) -> String {
    chemin.file_name().map_or_else(
        || chemin.display().to_string(),
        |n| n.to_string_lossy().into_owned(),
    )
}

fn chromium(c: &Chromium, resolveur: std::net::IpAddr) -> Client {
    let present = installe(c.binaires);
    let mut modes: Vec<(String, String)> = Vec::new();
    let mut gabarits: Vec<(String, String)> = Vec::new();

    for repertoire in c.repertoires {
        for chemin in fichiers_json(repertoire) {
            let nom = nom_court(&chemin);
            let texte = match std::fs::read_to_string(&chemin) {
                Ok(t) => t,
                Err(e) => return inattendu(c.nom, format!("{nom} illisible: {e}")),
            };
            match doh::chromium_depuis_json(&texte) {
                Ok((mode, gabarit)) => {
                    if let Some(m) = mode {
                        modes.push((nom.clone(), m));
                    }
                    if let Some(g) = gabarit {
                        gabarits.push((nom, g));
                    }
                }
                Err(e) => return inattendu(c.nom, format!("{nom}: {e}")),
            }
        }
    }

    let mode = match doh::fusionner("DnsOverHttpsMode", &modes) {
        Ok(m) => m,
        Err(e) => return inattendu(c.nom, e),
    };
    let gabarit = match doh::fusionner("DnsOverHttpsTemplates", &gabarits) {
        Ok(g) => g,
        Err(e) => return inattendu(c.nom, e),
    };

    Client {
        nom: c.nom,
        etat: doh::interpreter_chromium(present, mode.as_deref(), gabarit.as_deref(), resolveur),
    }
}

fn inattendu(nom: &'static str, quoi: String) -> Client {
    Client {
        nom,
        etat: Etat::Inattendu(quoi),
    }
}

fn firefox(resolveur: std::net::IpAddr) -> Client {
    // Le premier trouve gagne, et l'ordre de la liste EST la precedence.
    let trouve = FIREFOX_POLITIQUES
        .iter()
        .map(Path::new)
        .find(|p| p.exists());

    let (active, verrou, url) = match trouve {
        None => (None, None, None),
        Some(chemin) => {
            let nom = nom_court(chemin);
            match std::fs::read_to_string(chemin) {
                Err(e) => return inattendu("firefox", format!("{nom} illisible: {e}")),
                Ok(texte) => match doh::firefox_depuis_json(&texte) {
                    Ok(t) => t,
                    Err(e) => return inattendu("firefox", format!("{nom}: {e}")),
                },
            }
        }
    };

    // Le module pur parle en entiers, parce que le registre Windows y parle en
    // DWORD. La conversion appartient a celui qui sait d'ou vient la valeur.
    let en_entier = |b: Option<bool>| b.map(u32::from);
    Client {
        nom: "firefox",
        etat: doh::interpreter_firefox(
            installe(FIREFOX_BINAIRES),
            en_entier(active),
            en_entier(verrou),
            url.as_deref(),
            resolveur,
        ),
    }
}

/// Les clients DoH de cette machine, dans l'etat ou les fichiers les decrivent.
pub fn clients() -> Vec<Client> {
    let resolveur = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
    let mut clients: Vec<Client> = CHROMIUMS.iter().map(|c| chromium(c, resolveur)).collect();
    clients.push(firefox(resolveur));
    clients
}

/// Le vecteur, pret a entrer dans le rapport.
pub fn vecteur() -> CheckOutcome {
    let v = CheckVector::DohBypass;
    let clients = clients();
    let releve: Vec<String> = clients
        .iter()
        .map(|c| format!("{}: {}", c.nom, doh::decrire(&c.etat)))
        .collect();
    match doh::juger(&clients) {
        Verdict::Pince(raison) => CheckOutcome::passed(v, raison),
        Verdict::Indecis(raison) => CheckOutcome::skipped(v, raison),
        Verdict::Contournable(raison) => CheckOutcome::failed(v, raison, releve),
    }
}
