//! Recettes de `prove wfp`, sans privilege et sur les deux hotes: le daemon
//! est une suite de trames lues par le vrai lecteur strict, le moteur un
//! instantane construit par le code meme du produit (`wfp_plan`), puis altere
//! comme un tiers ou une panne l'altererait.

use super::*;
use crate::declaration::{CLES, HORS_SCHEMA, analyser};
use bifrost_core::ports::{EnvironnementMoteur, FirewallPolicy};
use bifrost_firewall::instantane_wfp::{
    ConditionVue, FiltreVu, Instantane, SousCoucheVue, ValeurVue, descripteur_autorisant,
};
use bifrost_firewall::wfp_plan::Layer;
use bifrost_ipc::ServerRule;
use bifrost_ipc::protocol::{
    DECLARATION_PARE_FEU_VERSION, DeclarationPareFeu, IssueApplication, Response,
};
use serde_json::json;
use std::cell::Cell;
use std::path::PathBuf;
use std::rc::Rc;

const INSTANCE: &str = "0123456789abcdef0123456789abcdef0123456789abcdef";

/// La regle que le lecteur de production rend pour le pipe du service: celle
/// que les doublures de daemon declarent avoir verifiee.
fn regle() -> &'static str {
    ServerRule::WindowsSystemPipeOwner.name()
}

/// Une trame lue par le VRAI lecteur strict, servie par un serveur admis.
fn lue(trame: &[u8]) -> Result<Lue, Refus> {
    analyser(trame)
        .map(|d| (d, regle()))
        .map_err(Refus::Declaration)
}
const LUID: u64 = 0x0123_4567_89ab_cdef;
const AUTRE_SOUS_COUCHE: u128 = 0x1111_2222_3333_4444_5555_6666_7777_8888;
const AUTRE_FOURNISSEUR: u128 = 0x9999_aaaa_bbbb_cccc_dddd_eeee_ffff_0000;

/// Une politique de production plausible, et complete: LAN ouvert, resolveur
/// embarque sous son propre compte, coeur exempte, interface resolue.
fn remise() -> FirewallPolicy {
    FirewallPolicy {
        tunnel_interface: Some("Bifrost".into()),
        tunnel_luid: Some(LUID),
        fwmark: None,
        dns_resolver: "127.0.0.1".parse().unwrap(),
        allow_lan: true,
        coeur_uid: None,
        coeur_executable: Some(PathBuf::from(r"C:\Bifrost\coeurs\sing-box.exe")),
        resolveur_uid: None,
        resolveur_executable: Some(PathBuf::from(r"C:\Bifrost\dnscrypt-proxy.exe")),
        resolveur_sid: Some("S-1-5-19".into()),
        resolveur_embarque: true,
    }
}

fn environnement() -> EnvironnementMoteur {
    EnvironnementMoteur {
        executable: PathBuf::from(r"C:\Bifrost\bifrost-daemon.exe"),
        identite: "S-1-5-18".into(),
        interface: Some(LUID),
    }
}

fn projection(p: &FirewallPolicy, e: &EnvironnementMoteur) -> Value {
    serde_json::to_value(PolitiqueWfp::projeter(p, e).unwrap()).unwrap()
}

/// La reponse telle que le VRAI daemon l'ecrit: le type du protocole, pas un
/// JSON tape a la main.
fn trame(application: u64, issue: IssueApplication, politique: Option<Value>) -> Vec<u8> {
    let d = DeclarationPareFeu {
        schema_version: DECLARATION_PARE_FEU_VERSION,
        instance: INSTANCE.into(),
        application,
        moteur: politique_wfp::MOTEUR.into(),
        issue,
        politique,
    };
    let mut v = serde_json::to_vec(&Response::DeclarationPareFeu(Box::new(d))).unwrap();
    v.push(b'\n');
    v
}

fn posee(v: Value) -> Vec<u8> {
    trame(4, IssueApplication::Posee, Some(v))
}

fn modifier(trame: &[u8], cle: &str, valeur: Value) -> Vec<u8> {
    let mut v: Value = serde_json::from_slice(trame).unwrap();
    v[cle] = valeur;
    let mut t = serde_json::to_vec(&v).unwrap();
    t.push(b'\n');
    t
}

/// L'identifiant d'application d'une doublure: deterministe, distinct par
/// chemin, et reconnaissable s'il fuyait dans le rapport.
fn identifiant(chemin: &Path) -> Result<Vec<u8>, &'static str> {
    Ok(format!("appid:{}", chemin.display()).into_bytes())
}

/// Un filtre de la reference, tel que BFE le rendrait: identifiant
/// d'application et descripteur calcules, poids effectif portant la plage dans
/// ses quatre bits de tete et des bits bas que le moteur attribue, et le
/// drapeau d'indexation que BFE pose de lui-meme.
fn vu(f: &FiltreWfp, identite: &str) -> FiltreVu {
    let conditions = f
        .conditions
        .iter()
        .map(|c| ConditionVue {
            champ: c.champ.cle(),
            correspondance: c.correspondance.code(),
            valeur: match &c.valeur {
                Valeur::U8(v) => ValeurVue::U8(*v),
                Valeur::U16(v) => ValeurVue::U16(*v),
                Valeur::U32(v) => ValeurVue::U32(*v),
                Valeur::U64(v) => ValeurVue::U64(*v),
                Valeur::V4 { adresse, masque } => ValeurVue::V4 {
                    adresse: *adresse,
                    masque: *masque,
                },
                Valeur::V6 { adresse, prefixe } => ValeurVue::V6 {
                    adresse: *adresse,
                    prefixe: *prefixe,
                },
                Valeur::Application(p) => ValeurVue::Octets(identifiant(p).unwrap()),
                Valeur::Identite(Identity::Current) => ValeurVue::Descripteur(
                    descripteur_autorisant(&Sid::lire_texte(identite).unwrap(), 1),
                ),
                Valeur::Identite(Identity::Sid(s)) => {
                    ValeurVue::Descripteur(descripteur_autorisant(&Sid::lire_texte(s).unwrap(), 1))
                }
            },
        })
        .collect();
    FiltreVu {
        couche: f.couche,
        sous_couche: wfp_plan::SOUS_COUCHE,
        fournisseur: Some(wfp_plan::FOURNISSEUR),
        poids: ValeurVue::U8(f.poids),
        poids_effectif: ValeurVue::U64((u64::from(f.poids) << 60) | 0x0000_0000_0012_3456),
        action: match f.action {
            Action::Permit => cles::ACTION_AUTORISATION,
            Action::Block => cles::ACTION_BLOCAGE,
        },
        drapeaux: if f.veto { cles::DRAPEAU_VETO } else { 0 } | cles::DRAPEAU_INDEXE,
        conditions,
    }
}

/// Un filtre tiers inoffensif ou non, selon ses arguments.
fn tiers(sous_couche: u128, action: u32, drapeaux: u32) -> FiltreVu {
    FiltreVu {
        couche: Layer::AuthConnectV4,
        sous_couche,
        fournisseur: Some(AUTRE_FOURNISSEUR),
        poids: ValeurVue::U64(0x8000_0000_0000_0000),
        poids_effectif: ValeurVue::U64(0x8000_0000_0000_0000),
        action,
        drapeaux,
        conditions: vec![ConditionVue {
            champ: cles::CHAMP_ADRESSE_DISTANTE,
            correspondance: cles::CORRESPONDANCE_EGALE,
            valeur: ValeurVue::V4 {
                adresse: 0xc633_6407,
                masque: u32::MAX,
            },
        }],
    }
}

/// Le moteur conforme a une politique, avec un voisinage ordinaire: une
/// sous-couche tierce au poids maximal qui ne porte qu'une autorisation souple
/// et un blocage, une autre plus basse qui porte une autorisation dure.
fn moteur(p: &FirewallPolicy, e: &EnvironnementMoteur) -> Instantane {
    let reference = PolitiqueWfp::lire(projection(p, e))
        .unwrap()
        .reference()
        .unwrap();
    let mut filtres: Vec<FiltreVu> = reference.iter().map(|f| vu(f, &e.identite)).collect();
    filtres.push(tiers(AUTRE_SOUS_COUCHE, cles::ACTION_AUTORISATION, 0));
    filtres.push(tiers(
        AUTRE_SOUS_COUCHE,
        cles::ACTION_BLOCAGE,
        cles::DRAPEAU_VETO,
    ));
    filtres.push(tiers(
        AUTRE_SOUS_COUCHE + 1,
        cles::ACTION_AUTORISATION,
        cles::DRAPEAU_VETO,
    ));
    // Le moteur rend ses filtres dans son ordre a lui.
    filtres.reverse();
    Instantane {
        fournisseur_bifrost: true,
        sous_couches: vec![
            SousCoucheVue {
                cle: AUTRE_SOUS_COUCHE,
                poids: u16::MAX,
                fournisseur: Some(AUTRE_FOURNISSEUR),
            },
            SousCoucheVue {
                cle: AUTRE_SOUS_COUCHE + 1,
                poids: 0x8000,
                fournisseur: None,
            },
            SousCoucheVue {
                cle: wfp_plan::SOUS_COUCHE,
                poids: wfp_plan::SUBLAYER_WEIGHT,
                fournisseur: Some(wfp_plan::FOURNISSEUR),
            },
        ],
        filtres,
    }
}

fn conforme() -> Instantane {
    moteur(&remise(), &environnement())
}

fn de_bifrost(f: &FiltreVu) -> bool {
    f.sous_couche == wfp_plan::SOUS_COUCHE
}

fn porte(f: &FiltreVu, champ: u128) -> bool {
    f.conditions.iter().any(|c| c.champ == champ)
}

/// Le protocole complet: le daemon sert ses trames dans l'ordre (la derniere
/// se repete) et compte les lectures, le moteur rend `collecte`.
async fn prouver_avec(
    trames: Vec<Vec<u8>>,
    collecte: Result<Instantane, &'static str>,
) -> (Value, usize) {
    let lectures = Rc::new(Cell::new(0usize));
    let compte = lectures.clone();
    let r = verifier_declaration_avec(
        move || {
            let n = compte.get();
            compte.set(n + 1);
            let t = trames[n.min(trames.len() - 1)].clone();
            async move { lue(&t) }
        },
        move || async move { collecte },
        identifiant,
    )
    .await;
    let code = r.code();
    let v = serde_json::to_value(&r).unwrap();
    assert_eq!(
        code,
        match v["verdict"].as_str().unwrap() {
            "MATCH" => 0,
            "MISMATCH" => 1,
            _ => 2,
        }
    );
    rien_de_la_declaration(&v);
    (v, lectures.get())
}

async fn prouver(moteur: Instantane) -> Value {
    let (r, lectures) = prouver_avec(
        vec![posee(projection(&remise(), &environnement()))],
        Ok(moteur),
    )
    .await;
    assert_eq!(lectures, 2, "N1 puis N2, ni plus ni moins: {r}");
    r
}

async fn sans_collecte(trames: Vec<Vec<u8>>) -> Value {
    let r = verifier_declaration_avec(
        {
            let mut n = 0usize;
            move || {
                let t = trames[n.min(trames.len() - 1)].clone();
                n += 1;
                async move { lue(&t) }
            }
        },
        || async { panic!("collecte interdite sans politique a comparer") },
        identifiant,
    )
    .await;
    let v = serde_json::to_value(&r).unwrap();
    rien_de_la_declaration(&v);
    v
}

/// Rien de la declaration ni du moteur ne sort dans le rapport, hors la
/// version de schema: ni chemin, ni SID, ni LUID (decimal ou hexadecimal), ni
/// GUID, ni identifiant d'application. Les horodatages sont retires avant la
/// recherche, pour qu'une coincidence de chiffres ne passe pas pour une fuite.
fn rien_de_la_declaration(rapport: &Value) {
    let mut sans_horloge = rapport.clone();
    for cle in ["started_at_unix_ms", "completed_at_unix_ms", "duration_ms"] {
        sans_horloge.as_object_mut().unwrap().remove(cle);
    }
    let texte = sans_horloge.to_string().to_lowercase();
    for interdit in [
        "bifrost\\",
        "bifrost-daemon.exe",
        "sing-box",
        "dnscrypt",
        "s-1-5",
        "appid:",
        &LUID.to_string(),
        &format!("{LUID:x}"),
        "0bd4f5a1",
        "c38d57d1",
        "127.0.0.1",
        INSTANCE,
    ] {
        assert!(
            !texte.contains(interdit),
            "le rapport exporte {interdit}: {texte}"
        );
    }
    for cle in [
        "application",
        "instance",
        "politique",
        "moteur",
        "issue",
        "filters_detail",
    ] {
        assert!(rapport.get(cle).is_none(), "cle exportee: {cle}");
    }
}

fn ecarts(r: &Value) -> Vec<&str> {
    r["differences"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d.as_str().unwrap())
        .collect()
}

// --- correspondance ---------------------------------------------------------

#[tokio::test]
async fn un_moteur_conforme_a_la_declaration_correspond() {
    let m = conforme();
    let bifrost = m.filtres.iter().filter(|f| de_bifrost(f)).count();
    let r = prouver(m).await;
    assert_eq!(r["verdict"], "MATCH", "{r}");
    assert_eq!(r["schema_version"], 1);
    assert_eq!(r["scope"], "wfp-engine-comparison");
    assert_eq!(r["expected_source"], "daemon-declared-active-policy");
    assert_eq!(r["source"], "wfp-engine-read-only-transaction");
    assert_eq!(r["policy_schema_version"], 1);
    assert_eq!(r["live_kernel"], true);
    assert_eq!(r["generation_verified"], true);
    assert_eq!(r["network_security"], "not-evaluated");
    assert!(r["failed_input"].is_null());
    // Le nom de la regle qui a admis le serveur, jamais sa valeur.
    assert_eq!(r["daemon_identity"], "windows-system-pipe-owner");
    assert!(ecarts(&r).is_empty());
    assert_eq!(r["expected_counts"]["filters"], bifrost);
    assert_eq!(r["observed_counts"]["filters"], bifrost);
    assert_eq!(r["observed_counts"]["third_party_filters"], 3);
    assert_eq!(r["observed_counts"]["third_party_overriding"], 0);
}

/// Les deux valeurs que BFE rend a sa facon ne font pas d'ecart: un poids
/// rendu en 64 bits plutot qu'en plage, et un descripteur encode autrement mais
/// portant la meme liste de controle d'acces.
#[tokio::test]
async fn les_formes_equivalentes_du_moteur_correspondent() {
    let mut m = conforme();
    for f in m.filtres.iter_mut().filter(|f| de_bifrost(f)) {
        if let ValeurVue::U8(w) = f.poids {
            f.poids = ValeurVue::U64(u64::from(w) << 60);
        }
        f.drapeaux &= !cles::DRAPEAU_INDEXE;
    }
    assert_eq!(prouver(m).await["verdict"], "MATCH");
}

// --- les alterations de la recette d'acceptation ----------------------------

#[tokio::test]
async fn une_regle_retiree_est_un_ecart() {
    for (nom, choisir) in [
        (
            "catch-all",
            (|f: &FiltreVu| f.conditions.is_empty()) as fn(&FiltreVu) -> bool,
        ),
        ("blocage dns", |f| {
            f.action == cles::ACTION_BLOCAGE && porte(f, cles::CHAMP_PORT_DISTANT)
        }),
        ("autorisation du daemon", |f| porte(f, cles::CHAMP_USER_ID)),
    ] {
        let mut m = conforme();
        let i = m
            .filtres
            .iter()
            .position(|f| de_bifrost(f) && choisir(f))
            .unwrap_or_else(|| panic!("{nom}: aucun filtre"));
        m.filtres.remove(i);
        let r = prouver(m).await;
        assert_eq!(r["verdict"], "MISMATCH", "{nom}: {r}");
        assert_eq!(ecarts(&r), ["rule-missing"], "{nom}");
    }
}

#[tokio::test]
async fn une_regle_desactivee_est_un_ecart() {
    let mut m = conforme();
    let f = m
        .filtres
        .iter_mut()
        .find(|f| de_bifrost(f) && f.conditions.is_empty())
        .unwrap();
    f.drapeaux |= cles::DRAPEAU_DESACTIVE;
    let r = prouver(m).await;
    assert_eq!(ecarts(&r), ["rule-disabled"], "{r}");
}

/// Trois facons d'elargir une exception: retirer la condition d'identite de
/// l'autorisation du daemon, elargir un prefixe du LAN, monter un poids.
#[tokio::test]
async fn une_exception_trop_large_est_un_ecart() {
    type Alterer = fn(&mut Instantane);
    let cas: [(&str, Alterer); 4] = [
        ("identite retiree", |m| {
            let f = m
                .filtres
                .iter_mut()
                .find(|f| de_bifrost(f) && porte(f, cles::CHAMP_USER_ID))
                .unwrap();
            f.conditions.retain(|c| c.champ != cles::CHAMP_USER_ID);
        }),
        ("application retiree", |m| {
            let f = m
                .filtres
                .iter_mut()
                .find(|f| de_bifrost(f) && porte(f, cles::CHAMP_APP_ID))
                .unwrap();
            f.conditions.retain(|c| c.champ != cles::CHAMP_APP_ID);
        }),
        ("prefixe du lan elargi", |m| {
            let f = m
                .filtres
                .iter_mut()
                .find(|f| {
                    de_bifrost(f)
                        && f.action == cles::ACTION_AUTORISATION
                        && f.conditions.iter().any(|c| {
                            matches!(c.valeur, ValeurVue::V4 { masque, .. } if masque != u32::MAX)
                        })
                })
                .unwrap();
            let c = f
                .conditions
                .iter_mut()
                .find(|c| matches!(c.valeur, ValeurVue::V4 { .. }))
                .unwrap();
            c.valeur = ValeurVue::V4 {
                adresse: 0,
                masque: 0,
            };
        }),
        ("poids monte", |m| {
            let f = m
                .filtres
                .iter_mut()
                .find(|f| {
                    de_bifrost(f)
                        && f.action == cles::ACTION_AUTORISATION
                        && matches!(f.poids, ValeurVue::U8(w) if w < 15)
                })
                .unwrap();
            f.poids = ValeurVue::U8(15);
            f.poids_effectif = ValeurVue::U64(15 << 60);
        }),
    ];
    for (nom, alterer) in cas {
        let mut m = conforme();
        alterer(&mut m);
        let r = prouver(m).await;
        assert_eq!(r["verdict"], "MISMATCH", "{nom}: {r}");
        assert_eq!(ecarts(&r), ["exception-broadened"], "{nom}: {r}");
    }
}

/// Une autorisation ajoutee dans le perimetre de Bifrost, par Bifrost ou par un
/// tiers qui s'est glisse dans sa sous-couche, est une exception en trop.
#[tokio::test]
async fn une_exception_ajoutee_est_un_ecart() {
    for fournisseur in [Some(wfp_plan::FOURNISSEUR), Some(AUTRE_FOURNISSEUR), None] {
        let mut m = conforme();
        let mut f = tiers(wfp_plan::SOUS_COUCHE, cles::ACTION_AUTORISATION, 0);
        f.fournisseur = fournisseur;
        f.poids = ValeurVue::U8(15);
        f.poids_effectif = ValeurVue::U64(15 << 60);
        m.filtres.push(f);
        let r = prouver(m).await;
        assert_eq!(ecarts(&r), ["exception-added"], "{fournisseur:?}: {r}");
    }
    // Et un filtre du fournisseur de Bifrost pose hors de sa sous-couche.
    let mut m = conforme();
    let mut f = tiers(AUTRE_SOUS_COUCHE, cles::ACTION_BLOCAGE, 0);
    f.fournisseur = Some(wfp_plan::FOURNISSEUR);
    f.poids = ValeurVue::U8(3);
    f.poids_effectif = ValeurVue::U64(3 << 60);
    m.filtres.push(f);
    let r = prouver(m).await;
    assert_eq!(ecarts(&r), ["rule-extra"], "{r}");
}

/// Un veto retire d'un blocage: le filtre est la, a sa place, mais un
/// produit concurrent peut desormais l'ecraser.
#[tokio::test]
async fn un_veto_retire_est_un_ecart() {
    let mut m = conforme();
    let f = m
        .filtres
        .iter_mut()
        .find(|f| de_bifrost(f) && f.conditions.is_empty())
        .unwrap();
    f.drapeaux &= !cles::DRAPEAU_VETO;
    let r = prouver(m).await;
    assert_eq!(ecarts(&r), ["rule-changed"], "{r}");
}

#[tokio::test]
async fn une_interface_remplacee_est_un_ecart() {
    let mut m = conforme();
    let mut vus = 0;
    for f in m.filtres.iter_mut().filter(|f| de_bifrost(f)) {
        for c in f
            .conditions
            .iter_mut()
            .filter(|c| c.champ == cles::CHAMP_INTERFACE_LOCALE)
        {
            c.valeur = ValeurVue::U64(LUID + 1);
            vus += 1;
        }
    }
    assert!(vus > 0, "la politique de recette autorise une interface");
    let r = prouver(m).await;
    assert_eq!(ecarts(&r), ["interface-changed"], "{r}");
}

#[tokio::test]
async fn un_fournisseur_ou_une_sous_couche_alteres_sont_des_ecarts() {
    let mut m = conforme();
    m.fournisseur_bifrost = false;
    assert_eq!(ecarts(&prouver(m).await), ["provider-missing"]);

    // Sous-couche portee par un autre fournisseur: son poids, lui, appartient
    // au moteur et n'est pas compare.
    let mut m = conforme();
    m.sous_couches
        .iter_mut()
        .find(|s| s.cle == wfp_plan::SOUS_COUCHE)
        .unwrap()
        .fournisseur = Some(AUTRE_FOURNISSEUR);
    assert_eq!(ecarts(&prouver(m).await), ["sublayer-changed"]);

    // Sans sa sous-couche, plus aucun filtre de Bifrost ne tient.
    let mut m = conforme();
    m.sous_couches.retain(|s| s.cle != wfp_plan::SOUS_COUCHE);
    m.filtres.retain(|f| !de_bifrost(f));
    m.fournisseur_bifrost = false;
    assert_eq!(
        ecarts(&prouver(m).await),
        ["provider-missing", "sublayer-missing", "rule-missing"]
    );
}

/// Le poids que le moteur attribue a la sous-couche, et non celui demande,
/// decide de l'arbitrage. Un permit dur tiers a 0x8000 est sans effet tant que
/// la sous-couche de Bifrost est au-dessus; declassee sous lui, elle se laisse
/// desormais outrepasser. C'est la lecon du banc: comparer au poids DEMANDE
/// (0xFFFF) manquerait ce declassement.
#[tokio::test]
async fn une_sous_couche_bifrost_declassee_sous_un_permit_dur_tiers_est_un_ecart() {
    // Le permit dur tiers de `conforme` vit a 0x8000; sans effet a l'origine.
    assert!(ecarts(&prouver(conforme()).await).is_empty());
    let mut m = conforme();
    m.sous_couches
        .iter_mut()
        .find(|s| s.cle == wfp_plan::SOUS_COUCHE)
        .unwrap()
        .poids = 0x7000;
    let r = prouver(m).await;
    assert_eq!(ecarts(&r), ["third-party-override"], "{r}");
    assert_eq!(r["observed_counts"]["third_party_overriding"], 1);
}

/// L'arbitrage: un filtre tiers qui peut defaire un blocage de Bifrost est un
/// ecart, un filtre tiers qui ne le peut pas n'en est pas un.
#[tokio::test]
async fn un_filtre_tiers_prioritaire_est_un_ecart_et_lui_seul() {
    let capables = [
        (
            "autorisation dure",
            cles::ACTION_AUTORISATION,
            cles::DRAPEAU_VETO,
        ),
        ("appel terminal", cles::ACTION_APPEL_TERMINAL, 0),
        ("appel inconnu", cles::ACTION_APPEL_INCONNU, 0),
    ];
    for (nom, action, drapeaux) in capables {
        let mut m = conforme();
        m.filtres.push(tiers(AUTRE_SOUS_COUCHE, action, drapeaux));
        let r = prouver(m).await;
        assert_eq!(r["verdict"], "MISMATCH", "{nom}: {r}");
        assert_eq!(ecarts(&r), ["third-party-override"], "{nom}");
        assert_eq!(r["observed_counts"]["third_party_overriding"], 1, "{nom}");
    }
    let sans_effet = [
        (
            "autorisation souple",
            AUTRE_SOUS_COUCHE,
            cles::ACTION_AUTORISATION,
            0,
        ),
        (
            "autorisation dure plus bas",
            AUTRE_SOUS_COUCHE + 1,
            cles::ACTION_AUTORISATION,
            cles::DRAPEAU_VETO,
        ),
        (
            "autorisation dure desactivee",
            AUTRE_SOUS_COUCHE,
            cles::ACTION_AUTORISATION,
            cles::DRAPEAU_VETO | cles::DRAPEAU_DESACTIVE,
        ),
        ("blocage", AUTRE_SOUS_COUCHE, cles::ACTION_BLOCAGE, 0),
        (
            "inspection",
            AUTRE_SOUS_COUCHE,
            cles::ACTION_APPEL_INSPECTION,
            0,
        ),
        (
            "appel terminal plus bas",
            AUTRE_SOUS_COUCHE + 1,
            cles::ACTION_APPEL_TERMINAL,
            0,
        ),
    ];
    for (nom, sous_couche, action, drapeaux) in sans_effet {
        let mut m = conforme();
        m.filtres.push(tiers(sous_couche, action, drapeaux));
        let r = prouver(m).await;
        assert_eq!(r["verdict"], "MATCH", "{nom}: {r}");
    }
}

/// Ce que la reference ne sait pas decrire rend NON MESURE, jamais MATCH.
#[tokio::test]
async fn un_etat_que_la_reference_ne_decrit_pas_n_est_pas_mesure() {
    type Alterer = fn(&mut Instantane);
    let cas: [(&str, Alterer, &str); 4] = [
        (
            "action tierce inconnue",
            |m| m.filtres.push(tiers(AUTRE_SOUS_COUCHE, 0x7777, 0)),
            "action d'un filtre tiers hors perimetre de l'arbitrage",
        ),
        (
            "sous-couche tierce absente",
            |m| m.filtres.push(tiers(0x42, cles::ACTION_AUTORISATION, 0)),
            "sous-couche d'un filtre tiers absente de l'instantane",
        ),
        (
            "descripteur illisible",
            |m| {
                let c = m
                    .filtres
                    .iter_mut()
                    .flat_map(|f| f.conditions.iter_mut())
                    .find(|c| matches!(c.valeur, ValeurVue::Descripteur(_)))
                    .unwrap();
                c.valeur = ValeurVue::Descripteur(vec![1, 0, 4, 0x80]);
            },
            "descripteur de securite illisible dans un filtre Bifrost",
        ),
        (
            "poids incoherent",
            |m| {
                let f = m.filtres.iter_mut().find(|f| de_bifrost(f)).unwrap();
                f.poids = ValeurVue::U8(3);
                f.poids_effectif = ValeurVue::U64(4 << 60);
            },
            "poids d'un filtre Bifrost incoherent",
        ),
    ];
    for (nom, alterer, raison) in cas {
        let mut m = conforme();
        alterer(&mut m);
        let r = prouver(m).await;
        assert_eq!(r["verdict"], "UNMEASURED", "{nom}: {r}");
        assert_eq!(r["reason"], raison, "{nom}");
        assert_eq!(r["failed_input"], "observed", "{nom}");
    }
}

/// Les refus de la collecte gardent leur raison, et la declaration n'est pas
/// relue sans instantane.
#[tokio::test]
async fn un_moteur_illisible_reste_non_mesure() {
    for raison in [
        "acces au moteur WFP refuse; aucune elevation automatique",
        "donnees du moteur WFP tronquees ou incoherentes",
        "instantane WFP non obtenu: un autre processus tient le verrou de transaction",
        "transaction de lecture WFP non confirmee",
    ] {
        let (r, lectures) = prouver_avec(
            vec![posee(projection(&remise(), &environnement()))],
            Err(raison),
        )
        .await;
        assert_eq!(r["verdict"], "UNMEASURED");
        assert_eq!(r["reason"], raison);
        assert_eq!(r["failed_input"], "observed");
        assert_eq!(r["live_kernel"], false);
        assert_eq!(lectures, 1, "pas de N2 sans instantane");
    }
}

/// L'equivalent du GETGEN: toute difference entre N1 et N2 rend l'instantane
/// non attribuable, meme s'il est conforme a N1.
#[tokio::test]
async fn une_declaration_changee_pendant_la_collecte_n_est_pas_mesuree() {
    let v = projection(&remise(), &environnement());
    let n1 = posee(v.clone());
    let mut autre = remise();
    autre.allow_lan = false;
    for (nom, n2) in [
        (
            "numero suivant",
            trame(5, IssueApplication::Posee, Some(v.clone())),
        ),
        (
            "autre instance",
            modifier(&n1, "instance", json!("f".repeat(48))),
        ),
        (
            "autre politique",
            posee(projection(&autre, &environnement())),
        ),
        ("retrait", trame(5, IssueApplication::Retiree, None)),
        ("echec", trame(5, IssueApplication::Echec, None)),
    ] {
        let (r, lectures) = prouver_avec(vec![n1.clone(), n2], Ok(conforme())).await;
        assert_eq!(r["verdict"], "UNMEASURED", "{nom}: {r}");
        assert_eq!(
            r["reason"], "declaration du daemon modifiee pendant la collecte",
            "{nom}"
        );
        assert_eq!(r["failed_input"], "daemon-declaration", "{nom}");
        assert_eq!(lectures, 2, "{nom}");
    }
    let (r, _) = prouver_avec(vec![n1, b"{\"result\"".to_vec()], Ok(conforme())).await;
    assert_eq!(
        r["reason"],
        "declaration du daemon illisible ou injoignable apres la collecte"
    );
}

// --- l'identite du serveur ---------------------------------------------------

/// Un serveur dont l'identite n'est pas admise, a N1: rien n'est collecte, le
/// rapport dit l'entree qui manque et ne nomme aucune regle. A N2: la collecte
/// a eu lieu, mais l'instantane n'est pas attribuable, et la regle de N1 n'est
/// pas gardee. Memes raisons, meme champ que `prove nft`: le protocole est le
/// meme code.
#[tokio::test]
async fn un_serveur_non_admis_n_est_jamais_mesure() {
    let bonne = posee(projection(&remise(), &environnement()));
    for refus in [
        Refus::Identite("serveur de la declaration non privilegie"),
        Refus::Identite("identite du serveur de la declaration illisible"),
    ] {
        let r = verifier_declaration_avec(
            || std::future::ready(Err(refus)),
            || async { panic!("collecte interdite sans identite admise") },
            identifiant,
        )
        .await;
        assert_eq!(r.code(), 2);
        assert!(r.texte().contains("identite du daemon: non verifiee"));
        let r = serde_json::to_value(&r).unwrap();
        assert_eq!(r["verdict"], "UNMEASURED", "{r}");
        assert_eq!(r["reason"], refus.raison());
        assert_eq!(r["failed_input"], "daemon-identity");
        assert!(r["daemon_identity"].is_null(), "{r}");
        assert_eq!(r["live_kernel"], false);
        assert!(r["expected_counts"].is_null());
        rien_de_la_declaration(&r);

        let mut lectures = vec![Err(refus), lue(&bonne)];
        let r = verifier_declaration_avec(
            || std::future::ready(lectures.pop().unwrap()),
            || async { Ok(conforme()) },
            identifiant,
        )
        .await;
        let r = serde_json::to_value(&r).unwrap();
        assert_eq!(r["verdict"], "UNMEASURED", "{r}");
        assert_eq!(r["reason"], refus.raison());
        assert_eq!(r["failed_input"], "daemon-identity");
        assert!(r["daemon_identity"].is_null(), "{r}");
        assert_eq!(r["live_kernel"], true);
        rien_de_la_declaration(&r);
    }
}

/// LA garde de l'identite sur son occurrence reelle, sous Windows: la lecture
/// de production (`declaration::lire`, regle des preuves) face a un pipe servi
/// par CE processus. Son proprietaire est le compte de la recette, ou les
/// Administrateurs sous un jeton eleve: jamais LocalSystem hors d'un
/// processus SYSTEM. Refuse, il ne recoit RIEN: le client verifie avant
/// d'ecrire. Sous SYSTEM, le pipe appartient a LocalSystem et il est admis:
/// c'est la limite de la regle, et la branche le mesure aussi.
#[cfg(windows)]
#[tokio::test]
async fn la_preuve_wfp_exige_le_pipe_de_localsystem() {
    use tokio::io::AsyncReadExt;
    use tokio::net::windows::named_pipe::ServerOptions;

    let nom = format!(
        r"\\.\pipe\bifrost-preuve-wfp-identite-{}",
        std::process::id()
    );
    let mut serveur = ServerOptions::new()
        .first_pipe_instance(true)
        .reject_remote_clients(true)
        .create(&nom)
        .expect("creation du pipe");
    let ecoute = tokio::spawn(async move {
        let mut recus = Vec::new();
        // Un client refuse est deja venu et reparti quand cette tache tourne:
        // `ConnectNamedPipe` le dit par une erreur, et il n'y a rien a lire.
        // Qu'il soit bien venu, la raison du rapport le prouve: seule la
        // lecture du proprietaire, sur un pipe ouvert, la rend.
        if serveur.connect().await.is_ok() {
            let _ = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                serveur.read_to_end(&mut recus),
            )
            .await;
        }
        recus
    });
    let r = verifier_declaration_avec(
        || crate::declaration::lire(&nom),
        || async { panic!("collecte interdite sans declaration") },
        identifiant,
    )
    .await;
    let recus = ecoute.await.expect("le faux serveur rend la main");
    let r = serde_json::to_value(&r).unwrap();
    assert_eq!(r["verdict"], "UNMEASURED", "{r}");
    // Admis ou non, c'est le niveau d'integrite de CE processus qui le dit,
    // jamais ce que le client a fait: une regle neutralisee admettrait le
    // pipe du compte courant, et une recette qui accepterait les deux issues
    // resterait verte.
    let groupes = std::process::Command::new("whoami")
        .arg("/groups")
        .output()
        .expect("whoami /groups");
    let sous_system = String::from_utf8_lossy(&groupes.stdout).contains("S-1-16-16384");
    if !sous_system {
        assert!(
            recus.is_empty(),
            "{} octet(s) ecrit(s) a un serveur refuse",
            recus.len()
        );
        assert_eq!(
            r["reason"], "serveur de la declaration non privilegie",
            "{r}"
        );
        assert_eq!(r["failed_input"], "daemon-identity", "{r}");
        assert!(r["daemon_identity"].is_null(), "{r}");
    } else {
        // Admis: seul un processus SYSTEM cree un pipe de LocalSystem. La
        // requete est partie, la reponse n'est jamais venue.
        assert_eq!(
            String::from_utf8_lossy(&recus),
            "{\"version\":1,\"command\":\"declaration-pare-feu\"}\n"
        );
        assert_eq!(r["failed_input"], "daemon-declaration", "{r}");
    }
    rien_de_la_declaration(&r);
}

// --- la declaration ----------------------------------------------------------

/// Chaque parametre de la declaration, change SEUL, face au moteur de la
/// politique d'origine: un ecart a chaque fois.
#[tokio::test]
async fn chaque_parametre_declare_change_seul_devient_un_ecart() {
    type Changer = fn(&mut FirewallPolicy, &mut EnvironnementMoteur);
    let variantes: Vec<(&str, Changer)> = vec![
        ("dns autre", |p, _| p.dns_resolver = "::1".parse().unwrap()),
        ("lan ferme", |p, _| p.allow_lan = false),
        ("resolveur non embarque", |p, _| {
            p.resolveur_embarque = false
        }),
        ("resolveur autre", |p, _| {
            p.resolveur_executable = Some(r"C:\Autre\dnscrypt-proxy.exe".into())
        }),
        ("resolveur absent", |p, _| p.resolveur_executable = None),
        ("compte du resolveur autre", |p, _| {
            p.resolveur_sid = Some("S-1-5-20".into())
        }),
        ("compte du resolveur absent", |p, _| p.resolveur_sid = None),
        ("coeur autre", |p, _| {
            p.coeur_executable = Some(r"C:\Autre\sing-box.exe".into())
        }),
        ("coeur absent", |p, _| p.coeur_executable = None),
        ("interface autre", |_, e| e.interface = Some(LUID + 1)),
        ("interface absente", |_, e| e.interface = None),
        ("daemon autre", |_, e| {
            e.executable = r"C:\Autre\bifrost-daemon.exe".into()
        }),
        ("identite autre", |_, e| {
            e.identite = "S-1-5-80-1-2-3-4-5".into()
        }),
    ];
    for (nom, changer) in variantes {
        let (mut p, mut e) = (remise(), environnement());
        changer(&mut p, &mut e);
        let (r, lectures) = prouver_avec(vec![posee(projection(&p, &e))], Ok(conforme())).await;
        assert_eq!(r["verdict"], "MISMATCH", "{nom}: {r}");
        assert!(!ecarts(&r).is_empty(), "{nom}");
        assert_eq!(lectures, 2, "{nom}");
    }
}

#[tokio::test]
async fn sans_politique_posee_rien_n_est_compare() {
    for (issue, application, raison) in [
        (
            IssueApplication::Aucune,
            0,
            "aucune politique posee par ce daemon depuis son demarrage",
        ),
        (
            IssueApplication::Retiree,
            3,
            "kill switch retire par le daemon: aucune politique a comparer",
        ),
        (
            IssueApplication::Echec,
            2,
            "derniere application du daemon en echec: etat du moteur inconnu du daemon",
        ),
    ] {
        let r = sans_collecte(vec![trame(application, issue, None)]).await;
        assert_eq!(r["verdict"], "UNMEASURED", "{issue:?}");
        assert_eq!(r["reason"], raison);
        assert_eq!(r["live_kernel"], false);
        assert_eq!(r["failed_input"], "daemon-declaration");
    }
}

/// Une politique que la reference ne sait pas decrire, ou la projection de
/// l'autre moteur, ne se compare pas: la collecte n'a meme pas lieu.
#[tokio::test]
async fn une_politique_hors_perimetre_n_est_jamais_une_correspondance() {
    let v = projection(&remise(), &environnement());
    let mut cas: Vec<(&str, Value)> = Vec::new();
    for (cle, valeur) in [
        ("dns_resolver", json!("192.0.2.53")),
        ("identite", json!("S-1-05-18")),
        ("tunnel_luid", json!(0)),
        ("projection", json!("nft")),
        ("en_trop", json!(1)),
    ] {
        let mut x = v.clone();
        x[cle] = valeur;
        cas.push((cle, x));
    }
    cas.push((
        "projection nft",
        serde_json::to_value(bifrost_firewall::politique_nft::Politique::projeter(
            &remise(),
        ))
        .unwrap(),
    ));
    cas.push(("vide", json!({})));
    for (nom, x) in cas {
        let r = sans_collecte(vec![posee(x)]).await;
        assert_eq!(r["verdict"], "UNMEASURED", "{nom}: {r}");
        assert_eq!(
            r["reason"], "politique declaree hors du perimetre de la reference WFP v1",
            "{nom}"
        );
    }
    let nft = modifier(&posee(v), "moteur", json!("nftables"));
    let r = sans_collecte(vec![nft]).await;
    assert_eq!(
        r["reason"],
        "moteur de pare-feu du daemon hors perimetre de la reference WFP"
    );
}

#[tokio::test]
async fn une_reponse_tronquee_ou_hors_schema_n_est_pas_mesuree() {
    let bonne = posee(projection(&remise(), &environnement()));
    let mut cas: Vec<(&str, Vec<u8>)> = vec![
        ("coupee", bonne[..bonne.len() / 2].to_vec()),
        ("vide", Vec::new()),
        ("tableau", b"[]\n".to_vec()),
        ("etat", b"{\"result\":\"ok\"}\n".to_vec()),
        (
            "refus",
            b"{\"result\":\"error\",\"message\":\"acces refuse pour S-1-5-21-1-2-3-1001\"}\n"
                .to_vec(),
        ),
        (
            "autre erreur",
            b"{\"result\":\"error\",\"message\":\"requete illisible\"}\n".to_vec(),
        ),
    ];
    let mut doublon = bonne[..bonne.len() - 2].to_vec();
    doublon.extend_from_slice(b",\"moteur\":\"wfp\"}\n");
    cas.push(("cle dupliquee", doublon));
    for cle in CLES {
        let mut v: Value = serde_json::from_slice(&bonne).unwrap();
        v.as_object_mut().unwrap().remove(cle);
        let mut t = serde_json::to_vec(&v).unwrap();
        t.push(b'\n');
        cas.push((cle, t));
    }
    for (nom, cle, valeur) in [
        ("version", "schema_version", json!(2)),
        ("instance courte", "instance", json!("abcdef")),
        ("moteur vide", "moteur", json!("")),
        ("posee sans politique", "politique", Value::Null),
        ("politique texte", "politique", json!("{}")),
    ] {
        cas.push((nom, modifier(&bonne, cle, valeur)));
    }
    for (nom, t) in cas {
        let r = sans_collecte(vec![t]).await;
        assert_eq!(r["verdict"], "UNMEASURED", "{nom}: {r}");
        assert!(
            [
                HORS_SCHEMA,
                "reponse du daemon tronquee ou illisible",
                "le daemon a refuse la demande",
                "acces au daemon refuse",
            ]
            .contains(&r["reason"].as_str().unwrap()),
            "{nom}: {r}"
        );
        assert_eq!(r["failed_input"], "daemon-declaration", "{nom}");
    }
}

/// Un attendu que l'hote ne sait pas calculer n'est pas compare.
#[tokio::test]
async fn un_identifiant_d_application_incalculable_n_est_pas_mesure() {
    let r = verifier_declaration_avec(
        || async { lue(&posee(projection(&remise(), &environnement()))) },
        || async { panic!("collecte interdite sans attendu") },
        |_: &Path| Err("identifiant d'application non calculable sur cet hote"),
    )
    .await;
    let r = serde_json::to_value(&r).unwrap();
    assert_eq!(r["verdict"], "UNMEASURED");
    assert_eq!(r["failed_input"], "expected");
    assert_eq!(
        r["reason"],
        "identifiant d'application non calculable sur cet hote"
    );
}

/// Le vrai transport, sans daemon: un canal absent n'est pas un moteur vide.
#[tokio::test]
async fn un_daemon_absent_n_est_pas_mesure() {
    let canal = if cfg!(windows) {
        format!(r"\\.\pipe\bifrost-absent-{}", std::process::id())
    } else {
        std::env::temp_dir()
            .join(format!("bifrost-absent-{}.sock", std::process::id()))
            .to_string_lossy()
            .into_owned()
    };
    assert_eq!(
        crate::declaration::lire(&canal).await,
        Err(Refus::Declaration("daemon injoignable"))
    );
}

/// Hors Windows, la commande existe et dit pourquoi elle ne mesure pas.
#[cfg(not(windows))]
#[tokio::test]
async fn hors_windows_la_preuve_n_est_pas_mesuree() {
    let r = serde_json::to_value(verifier_declaration("/nulle/part").await).unwrap();
    assert_eq!(r["verdict"], "UNMEASURED");
    assert_eq!(r["reason"], "preuve WFP disponible uniquement sous Windows");
}

// --- les briques ------------------------------------------------------------

#[test]
fn une_condition_large_couvre_ce_qu_elle_contient_et_rien_d_autre() {
    let v4 = |adresse: u32, masque: u32| ConditionNorme {
        champ: cles::CHAMP_ADRESSE_DISTANTE,
        correspondance: 0,
        valeur: Norme::V4(adresse, masque),
    };
    let v6 = |premier: u8, prefixe: u8| {
        let mut a = [0u8; 16];
        a[0] = premier;
        ConditionNorme {
            champ: cles::CHAMP_ADRESSE_DISTANTE,
            correspondance: 0,
            valeur: Norme::V6(a, prefixe),
        }
    };
    // 10.0.0.0/8 couvre 10.1.0.0/16, pas l'inverse, pas 11.0.0.0/8.
    assert!(couvre(
        &v4(0x0a00_0000, 0xff00_0000),
        &v4(0x0a01_0000, 0xffff_0000)
    ));
    assert!(!couvre(
        &v4(0x0a01_0000, 0xffff_0000),
        &v4(0x0a00_0000, 0xff00_0000)
    ));
    assert!(!couvre(
        &v4(0x0b00_0000, 0xff00_0000),
        &v4(0x0a00_0000, 0xff00_0000)
    ));
    assert!(couvre(&v4(0, 0), &v4(0x0a00_0000, 0xff00_0000)));
    // fe80::/10 couvre fe80::/64; ::/0 couvre tout; fc00::/7 pas fe80::/10.
    assert!(couvre(&v6(0xfe, 10), &v6(0xfe, 64)));
    assert!(couvre(&v6(0, 0), &v6(0xfe, 10)));
    assert!(!couvre(&v6(0xfc, 7), &v6(0xfe, 10)));
    assert!(!couvre(&v6(0xfe, 64), &v6(0xfe, 10)));
    // Deux champs differents ne se couvrent jamais.
    let mut port = v4(0, 0);
    port.champ = cles::CHAMP_PORT_DISTANT;
    assert!(!couvre(&port, &v4(0, 0)));
}
