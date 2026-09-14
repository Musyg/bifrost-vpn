//! La fenetre de fuite au demarrage machine se ferme-t-elle sans driver noyau.
//!
//! Le probleme ouvert 2 affirmait que fermer cette fenetre "demande un driver
//! kernel posant des filtres boot-time, donc un budget de certificat EV". Le
//! releve du 17 aout 2026 a rouvert la question, et la lecture du code de
//! Mullvad l'a tranchee sur le papier: leur daemon pose, depuis l'espace
//! UTILISATEUR et dans une seule transaction, un provider persistant, un
//! sublayer persistant, quatre filtres BOOT-TIME et quatre filtres PERSISTANTS.
//! Aucun driver, aucun certificat EV.
//!
//! # Ce que la documentation Mullvad dit de trop
//!
//! Leur documentation annonce que les filtres persistants "restent actifs avant
//! le demarrage de BFE". Leur propre code dit le contraire, en commentaire:
//! "Boot-time filters are applied before the Base Filtering Engine starts,
//! persistent ones once it has started. Both are needed to keep traffic blocked
//! across a reboot." La documentation de Microsoft va dans le meme sens: la
//! transition est atomique "si un provider a A LA FOIS un filtre boot-time et un
//! filtre persistant". Un seul des deux laisse un trou. C'est le code qui a
//! raison, pas la prose.
//!
//! # Ce que cette recette mesure, et qu'aucune lecture ne donne
//!
//! `FWPM_FILTER_FLAG_DISABLED` porte une phrase lourde de consequences: "les
//! filtres d'un provider sont desactives au demarrage de BFE si le provider n'a
//! pas de nom de service associe, ou si ce service n'est pas en demarrage
//! automatique". Or Mullvad ne renseigne PAS de nom de service sur son provider
//! persistant: `wfp-rs` expose pourtant `ProviderBuilder::service_name`, et leur
//! `persistent.rs` ne l'appelle jamais.
//!
//! De deux choses l'une. Ou bien la phrase ne s'applique pas comme elle se lit,
//! et un provider sans service protege quand meme. Ou bien elle s'applique, et
//! les filtres persistants de Mullvad reviennent au reboot DESACTIVES: presents,
//! enumerables, et ne bloquant rien entre le demarrage de BFE et celui du
//! daemon. Compter les filtres ne repond pas: il faut lire leurs drapeaux ET
//! sonder le reseau.
//!
//! # Pourquoi cette recette ne bloque qu'une cible
//!
//! Un blocage total survivant au reboot sur une machine distante ne se repare
//! qu'a la main. Les filtres poses ici ne visent qu'une adresse, ce qui suffit
//! a mesurer s'ils sont appliques et laisse la machine joignable. La
//! demonstration du blocage total n'apporterait rien de plus a la question
//! posee, et couterait un deplacement le jour ou elle tourne mal.

use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::time::Duration;

use bifrost_firewall::windows::ffi::{self, Engine};
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWP_ACTION_BLOCK, FWP_CONDITION_VALUE0, FWP_CONDITION_VALUE0_0, FWP_MATCH_EQUAL, FWP_UINT32,
    FWPM_ACTION0, FWPM_ACTION0_0, FWPM_CONDITION_IP_REMOTE_ADDRESS, FWPM_DISPLAY_DATA0,
    FWPM_FILTER_CONDITION0, FWPM_FILTER_FLAG_BOOTTIME, FWPM_FILTER_FLAG_DISABLED,
    FWPM_FILTER_FLAG_PERSISTENT, FWPM_FILTER0, FWPM_LAYER_ALE_AUTH_CONNECT_V4,
};
use windows_sys::core::GUID;

/// Objets distincts de ceux du kill switch: ils lui survivent par construction,
/// donc les confondre ferait retirer les uns en desarmant les autres.
const PROVIDER: GUID = GUID::from_u128(0x7f2c1e40_9a55_4d31_b8e2_4c0f6d9a1b73);
const SUBLAYER: GUID = GUID::from_u128(0x7f2c1e41_9a55_4d31_b8e2_4c0f6d9a1b73);

/// Les filtres portent des cles FIXES, et ce n'est pas un detail de confort.
/// Un filtre boot-time n'apparait pas dans l'enumeration du moteur en marche:
/// il est desactive des que BFE demarre. Laisser BFE engendrer sa cle le rend
/// donc irretirable, et il retient alors le sublayer qui le porte. Constate le
/// 17 aout 2026: le retrait a echoue sur "objet encore reference", et il a
/// fallu relever la cle dans le registre pour debloquer la machine. Mullvad
/// fixe les siennes pour la meme raison.
const FILTRE_BOOTTIME: GUID = GUID::from_u128(0x7f2c1e42_9a55_4d31_b8e2_4c0f6d9a1b73);
const FILTRE_PERSISTANT: GUID = GUID::from_u128(0x7f2c1e43_9a55_4d31_b8e2_4c0f6d9a1b73);

/// Le sublayer prend le poids maximal, comme celui de Mullvad: un blocage de
/// demarrage ne doit pas pouvoir etre efface par un permit d'un autre sublayer.
const POIDS_SUBLAYER: u16 = u16::MAX;

const DELAI_SONDE: Duration = Duration::from_millis(2500);

/// Ce qu'une sonde a pu etablir.
#[derive(Debug, PartialEq, Eq)]
enum Sonde {
    Bloquee,
    Aboutie,
    /// Ni l'un ni l'autre. Ne prouve rien: cf. la lecon du vecteur Linux, ou une
    /// tentative muette ressemble a un blocage sans en etre un.
    Muette,
}

fn sonder(cible: SocketAddr) -> Sonde {
    match TcpStream::connect_timeout(&cible, DELAI_SONDE) {
        Ok(_) => Sonde::Aboutie,
        Err(e) => {
            // WFP refuse la connexion, il ne la laisse pas expirer: le blocage
            // remonte comme une erreur immediate. C'est toute la difference avec
            // un `drop` nftables, et ce qui rend la sonde decidable ici. Le
            // code vient de windows-sys, seule source: une copie locale fausse
            // lirait `Muette` la ou le filtre a mordu.
            use windows_sys::Win32::Networking::WinSock::WSAEACCES;
            match e.raw_os_error() {
                Some(WSAEACCES) => Sonde::Bloquee,
                _ if e.kind() == std::io::ErrorKind::PermissionDenied => Sonde::Bloquee,
                _ => Sonde::Muette,
            }
        }
    }
}

/// Pose les huit filtres, quatre boot-time et quatre persistants.
///
/// `service` renseigne le nom de service du provider. C'est la variable de
/// l'experience: la documentation dit que sans lui, les filtres reviennent
/// desactives.
pub fn poser(cible: Ipv4Addr, service: Option<&str>) -> anyhow::Result<()> {
    poser_et_rendre_ids(cible, service).map(|_| ())
}

/// Le meme, mais rend les identifiants d'execution des filtres poses.
///
/// Ce sont eux que l'audit WFP nomme dans son champ `FilterRTID`. Sans eux, un
/// blocage observe dans le journal ne pourrait pas etre attribue: le journal
/// est plein de blocages du pare-feu Windows, et les compter pour siens
/// certifierait une etancheite qu'on n'a pas posee.
pub fn poser_et_rendre_ids(cible: Ipv4Addr, service: Option<&str>) -> anyhow::Result<Vec<u64>> {
    let identifiants: std::cell::RefCell<Vec<u64>> = std::cell::RefCell::new(Vec::new());
    let engine = Engine::open().map_err(|e| anyhow::anyhow!("{e}"))?;
    engine
        .transaction(|| {
            retirer_dans(&engine)?;

            let mut nom = ffi::wide("Bifrost demarrage");
            let mut desc = ffi::wide("Blocage de la fenetre de demarrage machine");
            let mut service_utf16 = service.map(ffi::wide);
            engine.add_provider_persistent(
                &PROVIDER,
                &mut nom,
                &mut desc,
                service_utf16.as_mut(),
            )?;

            let mut sous_nom = ffi::wide("Bifrost demarrage");
            let mut sous_desc = ffi::wide("Filtres actifs avant le daemon");
            let mut provider = PROVIDER;
            engine.add_sublayer_persistent(
                &SUBLAYER,
                &mut provider,
                &mut sous_nom,
                &mut sous_desc,
                POIDS_SUBLAYER,
            )?;

            // Les deux vies, jamais sur le meme filtre: les drapeaux sont
            // exclusifs. C'est bien pour cela qu'il en faut deux jeux.
            for (cle, etiquette, drapeau) in [
                (FILTRE_BOOTTIME, "boot-time", FWPM_FILTER_FLAG_BOOTTIME),
                (FILTRE_PERSISTANT, "persistant", FWPM_FILTER_FLAG_PERSISTENT),
            ] {
                let id = ajouter_blocage(&engine, cible, cle, etiquette, drapeau)?;
                identifiants.borrow_mut().push(id);
            }
            Ok(())
        })
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    println!(
        "pose: provider persistant{}, sublayer persistant, 1 filtre boot-time et \
         1 filtre persistant bloquant {cible}",
        match service {
            Some(s) => format!(" (service \"{s}\")"),
            None => " (SANS nom de service)".to_owned(),
        }
    );
    Ok(identifiants.into_inner())
}

fn ajouter_blocage(
    engine: &Engine,
    cible: Ipv4Addr,
    cle: GUID,
    etiquette: &str,
    drapeau: u32,
) -> bifrost_core::Result<u64> {
    let mut nom = ffi::wide(&format!("Bifrost demarrage {etiquette}"));
    let mut desc = ffi::wide("Blocage pose avant le daemon");
    let mut provider = PROVIDER;

    let condition = FWPM_FILTER_CONDITION0 {
        fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: FWP_UINT32,
            Anonymous: FWP_CONDITION_VALUE0_0 {
                uint32: u32::from(cible),
            },
        },
    };

    let filtre = FWPM_FILTER0 {
        filterKey: cle,
        displayData: FWPM_DISPLAY_DATA0 {
            name: nom.as_mut_ptr(),
            description: desc.as_mut_ptr(),
        },
        flags: drapeau,
        providerKey: &mut provider,
        layerKey: FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        subLayerKey: SUBLAYER,
        numFilterConditions: 1,
        filterCondition: &condition as *const _ as *mut FWPM_FILTER_CONDITION0,
        action: FWPM_ACTION0 {
            r#type: FWP_ACTION_BLOCK,
            Anonymous: FWPM_ACTION0_0 {
                filterType: GUID::from_u128(0),
            },
        },
        ..Default::default()
    };
    // `nom`, `desc` et `condition` sont des locales vivantes jusqu'a la fin de
    // cette fonction, donc pendant tout l'appel, qui copie ce dont il a besoin.
    engine.add_filter(&filtre)
}

/// Dit ce que le moteur porte encore et ce que le reseau en fait.
///
/// Les deux moities comptent. Un filtre present mais marque `DISABLED` ne bloque
/// rien; une sonde bloquee sans filtre visible viendrait d'autre chose.
pub fn constater(cible: Ipv4Addr, temoin: Ipv4Addr) -> anyhow::Result<()> {
    let engine = Engine::open().map_err(|e| anyhow::anyhow!("{e}"))?;
    let filtres = engine
        .describe_filters(&PROVIDER, &[FWPM_LAYER_ALE_AUTH_CONNECT_V4])
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    println!("filtres du provider de demarrage: {}", filtres.len());
    let mut desactives = 0usize;
    for (id, drapeaux) in &filtres {
        let mut vies = Vec::new();
        if drapeaux & FWPM_FILTER_FLAG_BOOTTIME != 0 {
            vies.push("boot-time");
        }
        if drapeaux & FWPM_FILTER_FLAG_PERSISTENT != 0 {
            vies.push("persistant");
        }
        if drapeaux & FWPM_FILTER_FLAG_DISABLED != 0 {
            vies.push("DESACTIVE");
            desactives += 1;
        }
        println!(
            "  filtre {id}: drapeaux {drapeaux:#x} [{}]",
            vies.join(", ")
        );
    }

    let sur_cible = sonder(SocketAddr::from((cible, 443)));
    let sur_temoin = sonder(SocketAddr::from((temoin, 443)));
    println!("sonde vers {cible}:443  -> {sur_cible:?}");
    println!("sonde vers {temoin}:443 -> {sur_temoin:?}  (temoin, doit aboutir)");

    // L'ordre des verdicts compte. Sans temoin joignable, un blocage constate
    // sur la cible ne prouve rien: la machine pourrait n'avoir aucun reseau.
    if sur_temoin != Sonde::Aboutie {
        println!(
            "\nSKIPPED: le temoin {temoin} n'aboutit pas ({sur_temoin:?}). Rien ne \
             peut etre conclu du sort de la cible."
        );
        std::process::exit(3);
    }

    match (sur_cible, filtres.is_empty(), desactives) {
        (Sonde::Bloquee, false, 0) => {
            println!("\nles filtres de demarrage sont la, actifs, et ils bloquent");
            Ok(())
        }
        (Sonde::Bloquee, _, n) if n > 0 => {
            println!(
                "\nle blocage tient alors que {n} filtre(s) sont marques DESACTIVE: \
                 ce n'est donc pas eux qui bloquent, et la mesure ne dit pas quoi"
            );
            anyhow::bail!("etat incoherent")
        }
        (Sonde::Aboutie, false, n) if n > 0 => {
            println!(
                "\nECHEC ATTENDU: les {} filtres sont revenus mais {n} sont \
                 DESACTIVES, et la cible aboutit. Un provider sans nom de service \
                 ne protege donc pas la fenetre de demarrage.",
                filtres.len()
            );
            anyhow::bail!("filtres presents mais desactives")
        }
        (Sonde::Aboutie, false, 0) => {
            println!(
                "\nECHEC: les filtres sont la et actifs, et la cible aboutit \
                 quand meme. Le blocage ne vient pas de la ou on le croit."
            );
            anyhow::bail!("filtres actifs sans effet")
        }
        (_, true, _) => {
            println!("\nECHEC: aucun filtre n'a survecu.");
            anyhow::bail!("aucun filtre")
        }
        (autre, _, _) => {
            println!("\nSKIPPED: sonde {autre:?} sur la cible, rien de decidable.");
            std::process::exit(3);
        }
    }
}

/// Retire tout. Le chemin de reprise sans lequel cette recette n'aurait pas le
/// droit d'exister: des filtres qui survivent au reboot et au daemon peuvent
/// laisser une machine coupee.
pub fn retirer(orphelins: &[GUID]) -> anyhow::Result<()> {
    let engine = Engine::open().map_err(|e| anyhow::anyhow!("{e}"))?;
    engine
        .transaction(|| {
            // Les orphelins d'abord: une cle relevee dans le registre parce
            // qu'un filtre boot-time engendre par BFE retient le sublayer.
            for cle in orphelins {
                engine.delete_filter_by_key(cle)?;
            }
            retirer_dans(&engine)
        })
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    println!("filtres de demarrage retires");
    Ok(())
}

fn retirer_dans(engine: &Engine) -> bifrost_core::Result<()> {
    // Par cle D'ABORD: c'est le seul chemin qui atteint le filtre boot-time,
    // absent de l'enumeration. L'enumeration ensuite, pour ce qu'une version
    // anterieure aurait pu laisser sous une cle engendree par BFE.
    engine.delete_filter_by_key(&FILTRE_BOOTTIME)?;
    engine.delete_filter_by_key(&FILTRE_PERSISTANT)?;
    engine.delete_filters_by_provider(&PROVIDER, &[FWPM_LAYER_ALE_AUTH_CONNECT_V4])?;
    engine.delete_sublayer(&SUBLAYER)?;
    engine.delete_provider(&PROVIDER)
}

/// Lit un GUID sous la forme rendue par `reg query`, accolades comprises.
///
/// Ecrit a la main plutot que tire d'une bibliotheque: le seul appelant est le
/// chemin de deblocage, et y ajouter une dependance pour quatre lignes serait
/// disproportionne.
pub fn guid_depuis_texte(texte: &str) -> anyhow::Result<GUID> {
    let brut: String = texte
        .trim()
        .trim_start_matches('{')
        .trim_end_matches('}')
        .chars()
        .filter(|c| *c != '-')
        .collect();
    if brut.len() != 32 {
        anyhow::bail!("GUID attendu sous la forme {{xxxxxxxx-xxxx-...}}, recu: {texte}");
    }
    let valeur = u128::from_str_radix(&brut, 16)
        .map_err(|e| anyhow::anyhow!("GUID illisible ({texte}): {e}"))?;
    Ok(GUID::from_u128(valeur))
}
