//! Recettes du mode daemon de `prove dns` (`--politique-daemon`): l'attendu
//! est le plan DNS que le daemon declare avoir pose, lu par le lecteur commun
//! des declarations (`declaration::lire_dns`, `declaration::analyser_dns`) et
//! encadre par son protocole (`declaration::encadrer`). Le comparateur est
//! celui de `--intention`: ces recettes tiennent ce qui est propre au mode
//! daemon, sur le resolveur FABRIQUE des recettes du module parent.
//!
//! Pures, sauf le module `socket`: elles tournent sur les deux hotes, le
//! daemon et le systeme etant joues par des fermetures.

use std::cell::Cell;
use std::net::{IpAddr, Ipv4Addr};

use bifrost_ipc::protocol::{DECLARATION_DNS_VERSION, DeclarationDns, EtatDns, PoseDns, Response};
use serde_json::{Value, json};

use super::super::*;
use super::{AMONT4, AMONT6, DHCP, I_PHY, I_TUN, TUNNEL, domaine, intention, pose, res};
use super::{intention_dns, json_intention, resynchroniser, tun};
use crate::declaration::{HORS_SCHEMA, LueDns, PLAN_DNS_CLES, Refus, analyser_dns};

const INSTANCE: &str = "0123456789abcdef0123456789abcdef0123456789abcdef";
const REGLE: &str = "root-peer-credentials";
const UID: u32 = 64000;

/// Le plan que le daemon declare, accorde a l'intention des recettes du module
/// parent: lien `bt0`, resolveur local en boucle locale, deux amonts.
fn plan(backend: &str, embarque: bool, uid: Option<u32>) -> PoseDns {
    PoseDns {
        backend: backend.into(),
        interface: TUNNEL.into(),
        local_resolver: IpAddr::V4(Ipv4Addr::LOCALHOST),
        upstream: vec![IpAddr::V4(AMONT4), IpAddr::V6(AMONT6)],
        embarque,
        resolveur_uid: uid,
    }
}

fn declaration(application: u64, issue: EtatDns, plan: Option<PoseDns>) -> DeclarationDns {
    DeclarationDns {
        schema_version: DECLARATION_DNS_VERSION,
        instance: INSTANCE.into(),
        application,
        issue,
        plan,
    }
}

fn posee(backend: &str) -> DeclarationDns {
    declaration(4, EtatDns::Pose, Some(plan(backend, false, None)))
}

/// La trame telle que le VRAI daemon l'ecrit: le type du protocole, pas un
/// JSON tape a la main.
fn trame(d: &DeclarationDns) -> Vec<u8> {
    let mut v = serde_json::to_vec(&Response::DeclarationDns(Box::new(d.clone()))).unwrap();
    v.push(b'\n');
    v
}

fn lue(d: &DeclarationDns) -> Result<LueDns, Refus> {
    Ok((d.clone(), REGLE))
}

/// Le resolveur conforme au backend `resolv-conf`: le fichier du plan, ni
/// resolved, ni lien.
fn pose_resolv_conf(i: &Intention) -> Observation {
    let mut o = pose(i);
    o.resolved = None;
    o.mode = None;
    o.tunnel = None;
    o.resolv_conf = Some(i.plan.contenu_resolv_conf().into_bytes());
    o
}

/// Ce qu'une preuve a lu, et ce qu'elle a rendu.
struct Jeu {
    rapport: Value,
    texte: String,
    code: i32,
    declarations: usize,
    systeme: usize,
}

/// Joue la preuve par declaration: `lectures` sont les lectures successives de
/// la declaration (N1, puis N2), `systeme` la lecture du resolveur, rendue a
/// chaque demande (`None`: toute collecte est interdite).
async fn jouer(lectures: Vec<Result<LueDns, Refus>>, systeme: Option<Observation>) -> Jeu {
    let mut lectures = lectures.into_iter();
    let declarations = Cell::new(0);
    let systeme_lu = Cell::new(0);
    let r = verifier_declaration_avec(
        true,
        || {
            declarations.set(declarations.get() + 1);
            std::future::ready(lectures.next().expect("lecture de declaration en trop"))
        },
        |_i: &Intention| {
            systeme_lu.set(systeme_lu.get() + 1);
            Ok(systeme
                .clone()
                .expect("collecte interdite: rien a comparer"))
        },
    )
    .await;
    let rapport = serde_json::to_value(&r).unwrap();
    let code = r.code();
    assert_eq!(
        code,
        match rapport["verdict"].as_str().unwrap() {
            "MATCH" => 0,
            "MISMATCH" => 1,
            _ => 2,
        }
    );
    Jeu {
        texte: r.texte(),
        rapport,
        code,
        declarations: declarations.get(),
        systeme: systeme_lu.get(),
    }
}

/// Rien de la declaration ne sort du rapport, ni en JSON ni en texte: ni
/// adresse, ni lien, ni compte, ni instance, ni numero. Les horodatages sont
/// retires avant la recherche: un instant en millisecondes contient tot ou
/// tard n'importe quelle suite de chiffres.
fn rien_de_la_declaration(j: &Jeu) {
    let mut sans_horloge = j.rapport.clone();
    for cle in ["started_at_unix_ms", "completed_at_unix_ms", "duration_ms"] {
        sans_horloge.as_object_mut().unwrap().remove(cle);
    }
    let json = sans_horloge.to_string();
    for interdit in [
        "192.0.2",
        "198.51.100",
        "2001:db8",
        "127.0.0",
        TUNNEL,
        "64000",
        "64001",
        INSTANCE,
    ] {
        assert!(
            !json.contains(interdit),
            "le rapport exporte {interdit}: {json}"
        );
        assert!(!j.texte.contains(interdit), "le texte exporte {interdit}");
    }
    for cle in ["application", "instance", "issue", "plan", "upstream"] {
        assert!(j.rapport.get(cle).is_none(), "cle exportee: {cle}");
    }
}

/// Un plan declare, conforme au resolveur, correspond, dans les deux backends.
/// Le rapport dit d'ou vient l'attendu et par quelle regle son serveur a ete
/// admis; deux lectures de la declaration encadrent les deux lectures du
/// systeme.
#[tokio::test]
async fn un_plan_declare_conforme_au_resolveur_correspond() {
    let d = posee("systemd-resolved");
    let j = jouer(
        vec![lue(&d), lue(&d)],
        Some(pose(&intention("systemd-resolved", false, None))),
    )
    .await;
    let r = &j.rapport;
    assert_eq!(r["verdict"], "MATCH", "{r}");
    assert_eq!(r["schema_version"], 1);
    assert_eq!(r["scope"], "linux-dns-comparison");
    assert_eq!(r["expected_source"], "daemon-declared-active-dns-plan");
    assert_eq!(r["source"], "resolved-dbus-and-system-files-read-twice");
    assert_eq!(r["backend"], "systemd-resolved");
    assert!(r["intention_schema_version"].is_null(), "{r}");
    assert_eq!(r["daemon_identity"], REGLE);
    assert!(r["failed_input"].is_null());
    assert_eq!(r["live_system"], true);
    assert_eq!(r["collection_verified"], true);
    assert_eq!(r["network_security"], "not-evaluated");
    assert_eq!(r["expected_counts"]["servers"], 2);
    assert_eq!(
        (j.declarations, j.systeme, j.code),
        (2, 2, 0),
        "N1, deux lectures du systeme, N2"
    );
    assert!(j.texte.contains(&format!("identite du daemon: {REGLE}\n")));
    rien_de_la_declaration(&j);

    // Le backend `resolv.conf` du gestionnaire est le `resolv-conf` du
    // rapport, comme en mode intention.
    let d = declaration(7, EtatDns::Pose, Some(plan("resolv.conf", true, Some(UID))));
    let i = intention("resolv-conf", true, Some(UID));
    let mut o = pose_resolv_conf(&i);
    o.ecoutes.push(Ecoute {
        adresse: IpAddr::V4(Ipv4Addr::LOCALHOST),
        port: 53,
        uid: UID,
    });
    let j = jouer(vec![lue(&d), lue(&d)], Some(o)).await;
    assert_eq!(j.rapport["verdict"], "MATCH", "{}", j.rapport);
    assert_eq!(j.rapport["backend"], "resolv-conf");
    assert_eq!(
        j.rapport["source"],
        "resolv-conf-and-system-files-read-twice"
    );
    rien_de_la_declaration(&j);
}

/// L'attendu du mode daemon est reconstruit par le meme constructeur
/// (`PlanDns::nouveau`) et porte les memes champs que celui de l'intention aux
/// memes valeurs: le comparateur recoit le meme objet dans les deux modes.
#[test]
fn l_attendu_du_daemon_est_celui_de_l_intention_aux_memes_valeurs() {
    for (gestionnaire, backend) in [
        ("systemd-resolved", "systemd-resolved"),
        ("resolv.conf", "resolv-conf"),
    ] {
        for (embarque, uid) in [(false, None), (true, None), (true, Some(UID))] {
            let d = declaration(1, EtatDns::Pose, Some(plan(gestionnaire, embarque, uid)));
            assert_eq!(
                intention_de_la_declaration(&d),
                intention_dns(json_intention(backend, embarque, uid)),
                "{gestionnaire} {embarque} {uid:?}"
            );
        }
    }
}

/// Chaque categorie d'ecart que le comparateur connait se voit aussi en mode
/// daemon, seule, a partir du plan declare.
#[tokio::test]
async fn chaque_categorie_d_ecart_se_voit_en_mode_daemon() {
    let resolved = posee("systemd-resolved");
    let i = intention("systemd-resolved", false, None);
    let mut cas: Vec<(&str, DeclarationDns, Observation)> = Vec::new();

    let mut o = pose(&i);
    o.mode = Some(ModeResolvConf::Uplink);
    res(&mut o).mode = "uplink".into();
    cas.push(("resolv-conf-path", resolved.clone(), o));

    let c = intention("resolv-conf", false, None);
    let mut o = pose_resolv_conf(&c);
    o.resolv_conf.as_mut().unwrap().push(b'\n');
    cas.push(("resolv-conf-content", posee("resolv.conf"), o));

    let mut o = pose(&i);
    o.hosts.push("ldap".into());
    cas.push(("hosts-sources", resolved.clone(), o));

    let mut o = pose(&i);
    res(&mut o).liens[2].portees = 0;
    cas.push(("tunnel-link-scope", resolved.clone(), o));

    let mut o = pose(&i);
    tun(&mut o).swap(0, 1);
    resynchroniser(&mut o, &[]);
    cas.push(("tunnel-link-servers", resolved.clone(), o));

    let mut o = pose(&i);
    res(&mut o).domaines.push(domaine(I_TUN, "example", true));
    cas.push(("tunnel-link-domains", resolved.clone(), o));

    let mut o = pose(&i);
    res(&mut o).domaines.push(domaine(I_PHY, "example", true));
    cas.push(("dns-exceptions", resolved.clone(), o));

    let mut o = pose(&i);
    res(&mut o).domaines.push(domaine(I_PHY, ".", true));
    cas.push(("competing-default-routes", resolved.clone(), o));

    let mut o = pose(&i);
    res(&mut o).liens[0].portees |= 1 << 1;
    cas.push(("multicast-resolution", resolved.clone(), o));

    let e = intention("systemd-resolved", true, Some(UID));
    let mut o = pose(&e);
    o.ecoutes.push(Ecoute {
        adresse: IpAddr::V4(Ipv4Addr::LOCALHOST),
        port: 53,
        uid: UID + 1,
    });
    cas.push((
        "local-resolver-listener",
        declaration(
            4,
            EtatDns::Pose,
            Some(plan("systemd-resolved", true, Some(UID))),
        ),
        o,
    ));

    assert_eq!(cas.len(), 10, "une alteration par categorie");
    for (categorie, d, o) in cas {
        let j = jouer(vec![lue(&d), lue(&d)], Some(o)).await;
        assert_eq!(
            j.rapport["verdict"], "MISMATCH",
            "{categorie}: {}",
            j.rapport
        );
        assert_eq!(j.rapport["differences"], json!([categorie]), "{categorie}");
        assert_eq!(j.code, 1, "{categorie}");
        assert_eq!(j.declarations, 2, "{categorie}");
        rien_de_la_declaration(&j);
    }
}

/// La moindre difference entre N1 et N2 rend la collecte non attribuable, meme
/// quand le resolveur est conforme a N1; une declaration illisible a N2 a sa
/// propre raison.
#[tokio::test]
async fn une_declaration_changee_pendant_la_collecte_n_est_pas_mesuree() {
    let n1 = posee("systemd-resolved");
    let mut autre_instance = n1.clone();
    autre_instance.instance = "f".repeat(48);
    let mut autre_plan = n1.clone();
    autre_plan.plan.as_mut().unwrap().upstream.reverse();
    let mut autre_backend = n1.clone();
    autre_backend.plan.as_mut().unwrap().backend = "resolv.conf".into();
    for (nom, n2) in [
        (
            "numero suivant",
            declaration(
                5,
                EtatDns::Pose,
                Some(plan("systemd-resolved", false, None)),
            ),
        ),
        ("autre instance", autre_instance),
        ("autre plan", autre_plan),
        ("autre backend", autre_backend),
        ("oubli au demontage", declaration(5, EtatDns::Aucun, None)),
        ("echec", declaration(5, EtatDns::Echec, None)),
    ] {
        let j = jouer(
            vec![lue(&n1), lue(&n2)],
            Some(pose(&intention("systemd-resolved", false, None))),
        )
        .await;
        assert_eq!(j.rapport["verdict"], "UNMEASURED", "{nom}: {}", j.rapport);
        assert_eq!(
            j.rapport["reason"], "declaration du daemon modifiee pendant la collecte",
            "{nom}"
        );
        assert_eq!(j.rapport["failed_input"], "daemon-declaration", "{nom}");
        assert_eq!((j.declarations, j.systeme), (2, 2), "{nom}");
        assert!(j.rapport["differences"].as_array().unwrap().is_empty());
        rien_de_la_declaration(&j);
    }
    let j = jouer(
        vec![
            lue(&n1),
            Err(Refus::Declaration(
                "reponse du daemon tronquee ou illisible",
            )),
        ],
        Some(pose(&intention("systemd-resolved", false, None))),
    )
    .await;
    assert_eq!(j.rapport["verdict"], "UNMEASURED");
    assert_eq!(
        j.rapport["reason"],
        "declaration du daemon illisible ou injoignable apres la collecte"
    );
    assert_eq!(j.rapport["failed_input"], "daemon-declaration");
}

/// Une declaration valide sans plan pose ne se compare pas: rien n'est
/// collecte, et N2 n'est pas lue.
#[tokio::test]
async fn sans_plan_pose_rien_n_est_compare() {
    for (d, raison) in [
        (
            declaration(0, EtatDns::Aucun, None),
            "aucun plan DNS pose par ce daemon: rien a comparer",
        ),
        (
            declaration(6, EtatDns::Aucun, None),
            "aucun plan DNS pose par ce daemon: rien a comparer",
        ),
        (
            declaration(3, EtatDns::Echec, None),
            "derniere operation DNS du daemon en echec: il ne sait pas ce que porte le resolveur, rien a comparer",
        ),
        (
            declaration(0, EtatDns::NonApplicable, None),
            "le daemon ne declare pas de plan DNS sur sa plateforme",
        ),
    ] {
        let j = jouer(vec![lue(&d)], None).await;
        assert_eq!(j.rapport["verdict"], "UNMEASURED", "{d:?}");
        assert_eq!(j.rapport["reason"], raison);
        assert_eq!(j.rapport["live_system"], false);
        assert!(j.rapport["backend"].is_null());
        assert!(j.rapport["source"].is_null());
        assert_eq!(j.rapport["daemon_identity"], REGLE);
        assert_eq!((j.declarations, j.systeme), (1, 0), "pas de N2 sans plan");
    }
}

/// Un plan declare hors du perimetre de la reference ne se compare jamais: la
/// declaration passe l'analyse de schema, c'est la reconstruction de
/// l'attendu qui refuse, avant toute collecte. Memes regles que l'intention,
/// et un backend que la preuve ne sait pas lire.
#[tokio::test]
async fn un_plan_declare_hors_perimetre_n_est_jamais_compare() {
    let base = plan("systemd-resolved", true, Some(UID));
    let avec = |changer: fn(&mut PoseDns)| {
        let mut p = base.clone();
        changer(&mut p);
        declaration(4, EtatDns::Pose, Some(p))
    };
    for d in [
        avec(|p| p.backend = "netsh".into()),
        avec(|p| p.backend = "faux".into()),
        avec(|p| p.backend = "resolv-conf".into()),
        avec(|p| p.interface = "lo".into()),
        avec(|p| p.interface = String::new()),
        avec(|p| p.interface = "une-interface-16".into()),
        avec(|p| p.interface = "bt 0".into()),
        avec(|p| p.upstream.clear()),
        avec(|p| {
            p.upstream = (1..=17)
                .map(|k| IpAddr::V4(Ipv4Addr::new(192, 0, 2, k)))
                .collect()
        }),
        avec(|p| p.upstream = vec![IpAddr::V4(AMONT4), IpAddr::V4(AMONT4)]),
        avec(|p| p.local_resolver = IpAddr::V4(DHCP)),
        avec(|p| p.resolveur_uid = Some(0)),
        avec(|p| p.embarque = false),
    ] {
        let j = jouer(vec![lue(&d)], None).await;
        assert_eq!(j.rapport["verdict"], "UNMEASURED", "{d:?}");
        assert!(
            j.rapport["reason"]
                .as_str()
                .unwrap()
                .contains("hors perimetre"),
            "{d:?}: {}",
            j.rapport
        );
        assert_eq!((j.declarations, j.systeme), (1, 0));
        rien_de_la_declaration(&j);
    }
    // Seize amonts: la borne de l'intention, admise.
    let d = avec(|p| {
        p.upstream = (1..=16)
            .map(|k| IpAddr::V4(Ipv4Addr::new(192, 0, 2, k)))
            .collect()
    });
    assert!(intention_de_la_declaration(&d).is_ok());
}

/// L'identite du serveur est exigee a chaque lecture: refusee a N1, rien n'est
/// collecte; refusee a N2, rien n'est compare, et le rapport ne garde pas la
/// regle de N1.
#[tokio::test]
async fn une_identite_refusee_ne_laisse_rien_comparer() {
    let j = jouer(
        vec![Err(Refus::Identite(
            "serveur de la declaration non privilegie",
        ))],
        None,
    )
    .await;
    assert_eq!(j.rapport["verdict"], "UNMEASURED");
    assert_eq!(
        j.rapport["reason"],
        "serveur de la declaration non privilegie"
    );
    assert_eq!(j.rapport["failed_input"], "daemon-identity");
    assert!(j.rapport["daemon_identity"].is_null(), "{}", j.rapport);
    assert_eq!(j.rapport["live_system"], false);
    assert_eq!((j.declarations, j.systeme), (1, 0));
    assert!(j.texte.contains("identite du daemon: non verifiee\n"));

    let d = posee("systemd-resolved");
    let j = jouer(
        vec![
            lue(&d),
            Err(Refus::Identite(
                "identite du serveur de la declaration illisible",
            )),
        ],
        Some(pose(&intention("systemd-resolved", false, None))),
    )
    .await;
    assert_eq!(j.rapport["verdict"], "UNMEASURED");
    assert_eq!(
        j.rapport["reason"],
        "identite du serveur de la declaration illisible"
    );
    assert_eq!(j.rapport["failed_input"], "daemon-identity");
    assert!(j.rapport["daemon_identity"].is_null(), "{}", j.rapport);
    assert_eq!(j.rapport["live_system"], true);
}

/// Une collecte instable ou une garde qui ne tient pas, en mode daemon: les
/// raisons de la collecte, sans verdict, et N2 n'est pas lue.
#[tokio::test]
async fn une_collecte_non_mesuree_ne_rend_pas_de_verdict() {
    let d = posee("systemd-resolved");
    let mut o = pose(&intention("systemd-resolved", false, None));
    res(&mut o).delegues = true;
    let j = jouer(vec![lue(&d), lue(&d)], Some(o)).await;
    assert_eq!(j.rapport["verdict"], "UNMEASURED");
    assert!(
        j.rapport["reason"]
            .as_str()
            .unwrap()
            .starts_with("delegues DNS")
    );
    assert_eq!(j.rapport["failed_input"], "observed");
    assert_eq!(j.declarations, 2);
}

/// La preuve de production, selon la plateforme: sous Linux elle lit le
/// socket nomme (absent ici: daemon injoignable); ailleurs elle rend un
/// non-applicable nomme, sans aucune lecture.
#[tokio::test]
async fn la_preuve_par_declaration_de_production_selon_la_plateforme() {
    let absent = std::env::temp_dir()
        .join(format!("bifrost-dnsdecl-absent-{}", std::process::id()))
        .join("d.sock");
    let r = verifier_declaration(&absent.to_string_lossy()).await;
    let v = serde_json::to_value(&r).unwrap();
    assert_eq!((v["verdict"].as_str(), r.code()), (Some("UNMEASURED"), 2));
    assert_eq!(v["expected_source"], "daemon-declared-active-dns-plan");
    assert_eq!(v["failed_input"], "daemon-declaration");
    assert!(v["daemon_identity"].is_null());
    assert_eq!(v["live_system"], false);
    assert!(!v.to_string().contains("bifrost-dnsdecl-absent"));
    #[cfg(target_os = "linux")]
    assert_eq!(v["reason"], "daemon injoignable");
    #[cfg(not(target_os = "linux"))]
    {
        assert_eq!(
            v["reason"],
            "declaration DNS non applicable sur cette plateforme: la preuve DNS par declaration ne lit que Linux"
        );
        assert!(v["source"].is_null());
    }
}

/// L'analyse stricte de la reponse `declaration-dns`: cles exactes au niveau
/// superieur et dans `plan`, doublons refuses en profondeur, entiers, version,
/// adresses ecrites sous leur forme canonique, coherence entre l'etat, le
/// numero et le plan. Les autres declarations, bien formees, sont refusees.
#[test]
fn une_reponse_dns_hors_schema_est_refusee() {
    let bonne = trame(&posee("systemd-resolved"));
    for d in [
        posee("systemd-resolved"),
        declaration(4, EtatDns::Pose, Some(plan("resolv.conf", true, Some(UID)))),
        declaration(0, EtatDns::Aucun, None),
        declaration(9, EtatDns::Aucun, None),
        declaration(2, EtatDns::Echec, None),
        declaration(0, EtatDns::NonApplicable, None),
    ] {
        assert_eq!(analyser_dns(&trame(&d)), Ok(d.clone()), "{d:?}");
    }
    let modifier = |cle: &str, valeur: Value| {
        let mut v: Value = serde_json::from_slice(&bonne).unwrap();
        v[cle] = valeur;
        serde_json::to_vec(&v).unwrap()
    };
    let modifier_plan = |cle: &str, valeur: Value| {
        let mut v: Value = serde_json::from_slice(&bonne).unwrap();
        v["plan"][cle] = valeur;
        serde_json::to_vec(&v).unwrap()
    };
    let retirer = |cle: &str| {
        let mut v: Value = serde_json::from_slice(&bonne).unwrap();
        v.as_object_mut().unwrap().remove(cle);
        serde_json::to_vec(&v).unwrap()
    };
    let retirer_du_plan = |cle: &str| {
        let mut v: Value = serde_json::from_slice(&bonne).unwrap();
        v["plan"].as_object_mut().unwrap().remove(cle);
        serde_json::to_vec(&v).unwrap()
    };
    let mut cas: Vec<(String, Vec<u8>)> = vec![
        ("coupee".into(), bonne[..bonne.len() / 2].to_vec()),
        ("vide".into(), Vec::new()),
        ("tableau".into(), b"[]\n".to_vec()),
        (
            "erreur sans message".into(),
            b"{\"result\":\"error\"}\n".to_vec(),
        ),
        ("cle en trop".into(), modifier("en_trop", json!(1))),
        (
            "cle en trop dans le plan".into(),
            modifier_plan("x", json!(1)),
        ),
        ("version".into(), modifier("schema_version", json!(2))),
        (
            "version texte".into(),
            modifier("schema_version", json!("1")),
        ),
        ("instance vide".into(), modifier("instance", json!(""))),
        (
            "instance majuscule".into(),
            modifier("instance", json!(INSTANCE.to_uppercase())),
        ),
        ("numero negatif".into(), modifier("application", json!(-1))),
        ("issue inconnue".into(), modifier("issue", json!("posee"))),
        ("pose sans plan".into(), modifier("plan", Value::Null)),
        (
            "autre resultat".into(),
            modifier("result", json!("declaration-routage")),
        ),
        ("backend vide".into(), modifier_plan("backend", json!(""))),
        ("backend nombre".into(), modifier_plan("backend", json!(1))),
        (
            "resolveur non canonique".into(),
            modifier_plan("local_resolver", json!("127.000.0.1")),
        ),
        (
            "amont non canonique".into(),
            modifier_plan("upstream", json!(["2001:DB8::53"])),
        ),
        (
            "amonts en texte".into(),
            modifier_plan("upstream", json!("192.0.2.53")),
        ),
        (
            "embarque texte".into(),
            modifier_plan("embarque", json!("non")),
        ),
        (
            "compte negatif".into(),
            modifier_plan("resolveur_uid", json!(-1)),
        ),
        (
            "compte hors u32".into(),
            modifier_plan("resolveur_uid", json!(4_294_967_296_u64)),
        ),
        (
            "compte flottant".into(),
            modifier_plan("resolveur_uid", json!(1.5)),
        ),
    ];
    for cle in [
        "result",
        "schema_version",
        "instance",
        "application",
        "issue",
        "plan",
    ] {
        cas.push((format!("sans {cle}"), retirer(cle)));
    }
    for cle in PLAN_DNS_CLES {
        cas.push((format!("plan sans {cle}"), retirer_du_plan(cle)));
    }
    let flottant = String::from_utf8(bonne.clone())
        .unwrap()
        .replace("\"application\":4", "\"application\":4.0")
        .into_bytes();
    cas.push(("numero flottant".into(), flottant));
    // Doublons, au niveau superieur et dans le plan: `Unique` les refuse.
    let mut doublon = bonne[..bonne.len() - 2].to_vec();
    doublon.extend_from_slice(b",\"issue\":\"pose\"}\n");
    cas.push(("cle superieure dupliquee".into(), doublon));
    let doublon_plan = String::from_utf8(bonne.clone())
        .unwrap()
        .replace(
            "\"embarque\":false",
            "\"embarque\":false,\"embarque\":false",
        )
        .into_bytes();
    cas.push(("cle du plan dupliquee".into(), doublon_plan));
    // Incoherences entre l'etat, le numero et le plan.
    let avec_plan = |issue: EtatDns, application: u64| {
        let mut v = serde_json::to_value(Response::DeclarationDns(Box::new(declaration(
            application,
            issue,
            None,
        ))))
        .unwrap();
        v["plan"] = serde_json::to_value(plan("systemd-resolved", false, None)).unwrap();
        serde_json::to_vec(&v).unwrap()
    };
    cas.push(("aucun avec plan".into(), avec_plan(EtatDns::Aucun, 3)));
    cas.push(("echec avec plan".into(), avec_plan(EtatDns::Echec, 3)));
    cas.push((
        "non applicable avec plan".into(),
        avec_plan(EtatDns::NonApplicable, 0),
    ));
    cas.push((
        "pose au numero zero".into(),
        trame(&declaration(
            0,
            EtatDns::Pose,
            Some(plan("systemd-resolved", false, None)),
        )),
    ));
    cas.push((
        "echec au numero zero".into(),
        trame(&declaration(0, EtatDns::Echec, None)),
    ));
    cas.push((
        "non applicable numerote".into(),
        trame(&declaration(2, EtatDns::NonApplicable, None)),
    ));
    // Les deux autres declarations, bien formees.
    let routage = bifrost_ipc::protocol::DeclarationRoutage {
        schema_version: 1,
        instance: INSTANCE.into(),
        application: 0,
        issue: bifrost_ipc::protocol::EtatRoutage::Aucun,
        plan: None,
    };
    cas.push((
        "declaration de routage".into(),
        serde_json::to_vec(&Response::DeclarationRoutage(Box::new(routage))).unwrap(),
    ));
    let pare_feu = bifrost_ipc::protocol::DeclarationPareFeu {
        schema_version: 1,
        instance: INSTANCE.into(),
        application: 0,
        moteur: "nftables".into(),
        issue: bifrost_ipc::protocol::IssueApplication::Aucune,
        politique: None,
    };
    cas.push((
        "declaration du pare-feu".into(),
        serde_json::to_vec(&Response::DeclarationPareFeu(Box::new(pare_feu))).unwrap(),
    ));
    for (nom, t) in cas {
        let issue = analyser_dns(&t);
        assert!(
            [
                Err(HORS_SCHEMA),
                Err("reponse du daemon tronquee ou illisible"),
                Err("le daemon a refuse la demande"),
            ]
            .contains(&issue.as_ref().map(|_| ()).map_err(|e| *e)),
            "{nom}: {issue:?}"
        );
    }
    // Le refus d'acces du daemon nomme l'appelant: jamais recopie.
    let refus = b"{\"result\":\"error\",\"message\":\"acces refuse pour uid=1000 gid=1000 pid=42: ni root\"}\n";
    assert_eq!(analyser_dns(refus), Err("acces au daemon refuse"));
}

/// Le lecteur de production sur un vrai socket Unix, face a un faux daemon:
/// la requete exacte, l'identite exigee, N1 et N2 par deux connexions.
#[cfg(target_os = "linux")]
mod socket {
    use super::*;
    use crate::declaration::{lire_dns, lire_dns_avec};
    use bifrost_ipc::ServerRequirement;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    /// L'uid effectif de ce processus: le faux daemon tourne sous lui, et
    /// SO_PEERCRED rend precisement cet uid.
    fn mon_uid() -> u32 {
        std::fs::read_to_string("/proc/self/status")
            .unwrap()
            .lines()
            .find_map(|l| l.strip_prefix("Uid:"))
            .and_then(|champs| champs.split_whitespace().nth(1))
            .and_then(|u| u.parse().ok())
            .expect("uid effectif lisible dans /proc/self/status")
    }

    /// Un faux daemon sur un vrai socket Unix: il sert ses trames dans l'ordre
    /// (la derniere se repete), verifie que la requete est exactement celle de
    /// la declaration DNS, et compte les requetes.
    struct FauxDaemon {
        dossier: PathBuf,
        socket: String,
        requetes: Arc<AtomicUsize>,
        tache: tokio::task::JoinHandle<()>,
    }

    impl FauxDaemon {
        fn demarrer(trames: Vec<Vec<u8>>) -> Self {
            static SUIVANT: AtomicUsize = AtomicUsize::new(0);
            let n = SUIVANT.fetch_add(1, Ordering::SeqCst);
            let dossier =
                std::env::temp_dir().join(format!("bfdnsdecl-{}-{n}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dossier);
            std::fs::create_dir(&dossier).unwrap();
            let chemin = dossier.join("d.sock");
            let ecoute = tokio::net::UnixListener::bind(&chemin).unwrap();
            let requetes = Arc::new(AtomicUsize::new(0));
            let compte = requetes.clone();
            let tache = tokio::spawn(async move {
                loop {
                    let Ok((flux, _)) = ecoute.accept().await else {
                        return;
                    };
                    let (lecture, mut ecriture) = tokio::io::split(flux);
                    let mut ligne = String::new();
                    if BufReader::new(lecture).read_line(&mut ligne).await.is_err() {
                        continue;
                    }
                    assert_eq!(
                        ligne, "{\"version\":1,\"command\":\"declaration-dns\"}\n",
                        "requete inattendue"
                    );
                    let n = compte.fetch_add(1, Ordering::SeqCst);
                    let t = &trames[n.min(trames.len() - 1)];
                    let _ = ecriture.write_all(t).await;
                    let _ = ecriture.shutdown().await;
                }
            });
            Self {
                socket: chemin.to_string_lossy().into_owned(),
                dossier,
                requetes,
                tache,
            }
        }

        fn requetes(&self) -> usize {
            self.requetes.load(Ordering::SeqCst)
        }
    }

    impl Drop for FauxDaemon {
        fn drop(&mut self) {
            self.tache.abort();
            let _ = std::fs::remove_dir_all(&self.dossier);
        }
    }

    async fn prouver(daemon: &FauxDaemon, exigence: Option<ServerRequirement>) -> Value {
        let socket = daemon.socket.clone();
        let systeme = pose(&intention("systemd-resolved", false, None));
        let r = verifier_declaration_avec(
            true,
            || {
                let socket = socket.clone();
                async move {
                    match exigence {
                        Some(e) => lire_dns_avec(&socket, Duration::from_secs(2), e).await,
                        None => lire_dns(&socket).await,
                    }
                }
            },
            |_i: &Intention| Ok(systeme.clone()),
        )
        .await;
        serde_json::to_value(&r).unwrap()
    }

    /// Par le socket: la requete exacte, deux connexions (N1, N2), une
    /// correspondance, la regle du compte de la recette.
    #[tokio::test]
    async fn la_lecture_par_le_socket_encadre_la_collecte() {
        let daemon = FauxDaemon::demarrer(vec![trame(&posee("systemd-resolved"))]);
        let r = prouver(&daemon, Some(ServerRequirement::Uid(mon_uid()))).await;
        assert_eq!(r["verdict"], "MATCH", "{r}");
        assert_eq!(r["daemon_identity"], "uid-peer-credentials");
        assert_eq!(daemon.requetes(), 2, "N1 puis N2");

        // Une trame hors schema par le socket: rien n'est compare.
        let daemon = FauxDaemon::demarrer(vec![b"{\"result\"".to_vec()]);
        let r = prouver(&daemon, Some(ServerRequirement::Uid(mon_uid()))).await;
        assert_eq!(r["verdict"], "UNMEASURED");
        assert_eq!(r["reason"], "reponse du daemon tronquee ou illisible");
        assert_eq!(daemon.requetes(), 1);
    }

    /// La lecture de PRODUCTION (`lire_dns`) exige un serveur root, comme les
    /// trois autres lecteurs. Non root, il n'est pas admis et ne recoit rien;
    /// root, il est admis (la regle dit qui ecoute, pas que c'est le daemon).
    #[tokio::test]
    async fn la_preuve_exige_un_serveur_root() {
        let daemon = FauxDaemon::demarrer(vec![trame(&posee("systemd-resolved"))]);
        let r = prouver(&daemon, None).await;
        if mon_uid() == 0 {
            assert_eq!(r["verdict"], "MATCH", "{r}");
            assert_eq!(r["daemon_identity"], "root-peer-credentials");
            assert_eq!(daemon.requetes(), 2);
        } else {
            assert_eq!(r["verdict"], "UNMEASURED", "{r}");
            assert_eq!(r["reason"], "serveur de la declaration non privilegie");
            assert_eq!(r["failed_input"], "daemon-identity");
            assert!(r["daemon_identity"].is_null(), "{r}");
            assert_eq!(r["live_system"], false);
            assert_eq!(
                daemon.requetes(),
                0,
                "rien n'est envoye a un serveur refuse"
            );
        }
    }
}
