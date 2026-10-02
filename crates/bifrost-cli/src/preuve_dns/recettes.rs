//! Recettes de `prove dns`: lecteur D-Bus, lecteurs des fichiers du systeme,
//! intention, comparaison et rapport. Pures: elles tournent sur les deux
//! hotes, sans bus, sans resolved et sans fichier du systeme.

use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

use serde_json::json;

use super::dbus::{self, Appel, Attente, Corps, Domaine, Forme, Issue, Propriete, Serveur, Valeur};
use super::*;

// --- lecteur D-Bus: authentification ----------------------------------------

#[test]
fn l_authentification_externe_porte_l_uid_en_decimal_puis_en_hexadecimal() {
    // "1000" en ASCII: 31 30 30 30 (specification, mecanisme EXTERNAL).
    assert_eq!(
        dbus::requete_authentification(1000),
        b"\0AUTH EXTERNAL 31303030\r\n"
    );
    assert_eq!(dbus::requete_authentification(0), b"\0AUTH EXTERNAL 30\r\n");
}

#[test]
fn l_accord_du_serveur_est_lu_strictement() {
    let ok = b"OK 0123456789abcdef0123456789ABCDEF\r\n";
    assert_eq!(dbus::lire_accord(ok), Ok(Some(ok.len())));
    for n in 0..ok.len() - 1 {
        assert_eq!(dbus::lire_accord(&ok[..n]), Ok(None), "prefixe {n}");
    }
    assert_eq!(
        dbus::lire_accord(b"REJECTED EXTERNAL\r\n"),
        Err(dbus::REFUSEE)
    );
    for refuse in [
        &b"OK 0123\r\n"[..],
        b"OK 0123456789abcdef0123456789abcdeg\r\n",
        b"DATA\r\n",
        b"ERROR\r\n",
        b"AGREE_UNIX_FD\r\n",
    ] {
        assert!(dbus::lire_accord(refuse).is_err(), "{refuse:?}");
    }
    assert_eq!(dbus::lire_accord(&[b'x'; 600]), Err(dbus::HORS_BORNE));
    let mut longue = vec![b'x'; 600];
    longue.extend_from_slice(b"\r\n");
    assert_eq!(dbus::lire_accord(&longue), Err(dbus::HORS_BORNE));
}

// --- lecteur D-Bus: ecriture d'un appel --------------------------------------

fn appel(destination: &str, chemin: &str, interface: &str, membre: &str, corps: Corps) -> Appel {
    Appel {
        destination: destination.into(),
        chemin: chemin.into(),
        interface: interface.into(),
        membre: membre.into(),
        corps,
    }
}

fn hello() -> Appel {
    appel(
        dbus::BUS,
        "/org/freedesktop/DBus",
        dbus::BUS,
        "Hello",
        Corps::Vide,
    )
}

/// `Hello`, octet par octet selon la specification: en-tete fixe, quatre
/// champs alignes sur 8, aucun corps, et `NO_AUTO_START`.
#[test]
fn hello_s_ecrit_au_format_de_la_specification() {
    let t = dbus::encoder_appel(&hello(), 1, b'l').unwrap();
    assert_eq!(t.len(), 128);
    assert_eq!(&t[..4], &[b'l', 1, 0x2, 1]);
    assert_eq!(&t[4..8], &0_u32.to_le_bytes(), "corps vide");
    assert_eq!(&t[8..12], &1_u32.to_le_bytes(), "serie");
    assert_eq!(&t[12..16], &110_u32.to_le_bytes(), "longueur des champs");
    assert_eq!(&t[16..20], &[1, 1, b'o', 0], "PATH, signature o");
    assert_eq!(&t[20..24], &21_u32.to_le_bytes());
    assert_eq!(&t[24..45], b"/org/freedesktop/DBus");
    assert_eq!(&t[48..52], &[6, 1, b's', 0], "DESTINATION");
    assert_eq!(&t[112..116], &[3, 1, b's', 0], "MEMBER");
    assert_eq!(&t[120..125], b"Hello");
    assert!(t[126..].iter().all(|&o| o == 0), "remplissage nul");
    let b = dbus::encoder_appel(&hello(), 1, b'B').unwrap();
    assert_eq!(&b[12..16], &110_u32.to_be_bytes());
}

#[test]
fn les_corps_d_appel_portent_leur_signature() {
    let get = appel(
        ":1.7",
        "/org/freedesktop/resolve1",
        "org.freedesktop.DBus.Properties",
        "Get",
        Corps::DeuxChaines("org.freedesktop.resolve1.Manager".into(), "DNSEx".into()),
    );
    let t = dbus::encoder_appel(&get, 9, dbus::ORDRE_NATIF).unwrap();
    let champs = u32::from_ne_bytes(t[12..16].try_into().unwrap()) as usize;
    let corps = u32::from_ne_bytes(t[4..8].try_into().unwrap()) as usize;
    let debut = (16 + champs).div_ceil(8) * 8;
    assert_eq!(t.len(), debut + corps);
    assert!(
        t.windows(5).any(|w| w == [8, 1, b'g', 0, 2]),
        "SIGNATURE ss"
    );
    let i = dbus::encoder_appel(
        &appel(
            ":1.7",
            "/org/freedesktop/resolve1",
            "org.freedesktop.resolve1.Manager",
            "GetLink",
            Corps::Entier32(-3),
        ),
        10,
        dbus::ORDRE_NATIF,
    )
    .unwrap();
    assert_eq!(&i[i.len() - 4..], &(-3_i32).to_ne_bytes());
}

/// Un appel invalide n'est jamais ecrit: le bus refuserait la connexion, et
/// la preuve n'enverrait pas ce qu'elle croit envoyer.
#[test]
fn un_appel_invalide_n_est_pas_ecrit() {
    assert!(
        dbus::encoder_appel(&hello(), 0, b'l').is_err(),
        "serie nulle"
    );
    assert!(dbus::encoder_appel(&hello(), 1, b'x').is_err(), "boutisme");
    let mut a = hello();
    a.chemin = "org/freedesktop".into();
    assert!(dbus::encoder_appel(&a, 1, b'l').is_err());
    a.chemin = "/org//x".into();
    assert!(dbus::encoder_appel(&a, 1, b'l').is_err());
    let mut a = hello();
    a.interface = "Properties".into();
    assert!(dbus::encoder_appel(&a, 1, b'l').is_err());
    let mut a = hello();
    a.membre = "Get.All".into();
    assert!(dbus::encoder_appel(&a, 1, b'l').is_err());
    let mut a = hello();
    a.destination = ":1".into();
    assert!(dbus::encoder_appel(&a, 1, b'l').is_err());
    let mut a = hello();
    a.destination = ":1.7".into();
    assert!(dbus::encoder_appel(&a, 1, b'l').is_ok());
}

// --- lecteur D-Bus: lecture d'une reponse ------------------------------------

const RES: &str = ":1.7";

fn attente(serie: u32, emetteur: &'static str, forme: Forme) -> Attente<'static> {
    Attente {
        serie,
        emetteur,
        forme,
        ordre: dbus::ORDRE_NATIF,
    }
}

fn retour(serie: u32, forme: Forme, v: Valeur) -> Vec<u8> {
    dbus::encoder_reponse(500, serie, RES, None, Some((forme, &v)), dbus::ORDRE_NATIF)
}

const VS: Forme = Forme::Variante(Propriete::Serveurs);
const VD: Forme = Forme::Variante(Propriete::Domaines);
const VC: Forme = Forme::Variante(Propriete::Chaine);
const VB: Forme = Forme::Variante(Propriete::Booleen);

fn lire(t: &[u8], forme: Forme) -> Result<Option<(Issue, usize)>, &'static str> {
    dbus::lire_reponse(t, &attente(4, RES, forme))
}

fn serveurs_exemple() -> Vec<Serveur> {
    vec![
        Serveur {
            index: 3,
            famille: 2,
            adresse: vec![192, 0, 2, 53],
            port: 53,
            nom: String::new(),
        },
        Serveur {
            index: 0,
            famille: 10,
            adresse: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x53)
                .octets()
                .to_vec(),
            port: 0,
            nom: "dns.example".into(),
        },
    ]
}

/// Chaque forme lue rend exactement la valeur ecrite, et consomme la trame
/// entiere.
#[test]
fn chaque_forme_lue_rend_la_valeur_ecrite() {
    let cas: Vec<(Forme, Valeur)> = vec![
        (Forme::Chaine, Valeur::Chaine(":1.42".into())),
        (Forme::Entier32NonSigne, Valeur::Entier32NonSigne(991)),
        (
            Forme::Chemin,
            Valeur::Chemin("/org/freedesktop/resolve1/link/_33".into()),
        ),
        (Forme::ListeDeDelegues, Valeur::Delegues(false)),
        (Forme::ListeDeDelegues, Valeur::Delegues(true)),
        (
            Forme::Variante(Propriete::Serveurs),
            Valeur::Serveurs(serveurs_exemple()),
        ),
        (
            Forme::Variante(Propriete::Serveurs),
            Valeur::Serveurs(vec![]),
        ),
        (
            Forme::Variante(Propriete::ServeursDuLien),
            Valeur::ServeursDuLien(
                serveurs_exemple()
                    .into_iter()
                    .map(|s| Serveur { index: 0, ..s })
                    .collect(),
            ),
        ),
        (
            Forme::Variante(Propriete::ServeursDuLien),
            Valeur::ServeursDuLien(vec![]),
        ),
        (
            Forme::Variante(Propriete::Domaines),
            Valeur::Domaines(vec![
                Domaine {
                    index: 3,
                    nom: ".".into(),
                    route_seule: true,
                },
                Domaine {
                    index: 0,
                    nom: "example".into(),
                    route_seule: false,
                },
            ]),
        ),
        (
            Forme::Variante(Propriete::Chaine),
            Valeur::Chaine("stub".into()),
        ),
        (Forme::Variante(Propriete::Booleen), Valeur::Booleen(false)),
        (Forme::Variante(Propriete::Booleen), Valeur::Booleen(true)),
        (Forme::Variante(Propriete::Entier64), Valeur::Entier64(0x1f)),
    ];
    for (forme, v) in cas {
        let t = retour(4, forme, v.clone());
        assert_eq!(
            lire(&t, forme),
            Ok(Some((Issue::Retour(v.clone()), t.len()))),
            "{forme:?}"
        );
        // Tout prefixe strict est incomplet, jamais une erreur ni une valeur.
        for n in 0..t.len() {
            assert_eq!(lire(&t[..n], forme), Ok(None), "{forme:?} prefixe {n}");
        }
    }
}

#[test]
fn une_erreur_de_l_appele_est_rendue_par_son_nom() {
    let t = dbus::encoder_reponse(
        500,
        4,
        RES,
        Some("org.freedesktop.resolve1.NoSuchLink"),
        None,
        dbus::ORDRE_NATIF,
    );
    assert_eq!(
        lire(&t, Forme::Chemin),
        Ok(Some((
            Issue::Erreur("org.freedesktop.resolve1.NoSuchLink".into()),
            t.len()
        )))
    );
}

/// Le bus rend lui-meme l'erreur d'un appel qu'il ne transmet pas: un refus,
/// jamais une valeur, et seulement s'il n'est pas l'appele.
#[test]
fn une_erreur_du_bus_pour_un_autre_appele_est_un_refus() {
    let refus = "org.freedesktop.DBus.Error.AccessDenied";
    let t = dbus::encoder_reponse(500, 4, dbus::BUS, Some(refus), None, dbus::ORDRE_NATIF);
    assert_eq!(
        lire(&t, Forme::Chaine),
        Ok(Some((Issue::RefusDuBus(refus.into()), t.len())))
    );
    assert_eq!(
        dbus::lire_reponse(&t, &attente(4, dbus::BUS, Forme::Chaine)),
        Ok(Some((Issue::Erreur(refus.into()), t.len())))
    );
    // Un RETOUR du bus a la place de l'appele n'est pas admis.
    let t = dbus::encoder_reponse(
        500,
        4,
        dbus::BUS,
        None,
        Some((Forme::Chaine, &Valeur::Chaine("x".into()))),
        dbus::ORDRE_NATIF,
    );
    assert_eq!(lire(&t, Forme::Chaine), Err(dbus::INATTENDUE));
}

#[test]
fn une_reponse_a_un_autre_appel_ou_d_un_autre_emetteur_est_refusee() {
    let v = Valeur::Chaine("stub".into());
    let t = retour(5, Forme::Chaine, v.clone());
    assert_eq!(lire(&t, Forme::Chaine), Err(dbus::INATTENDUE));
    let t = dbus::encoder_reponse(
        500,
        4,
        ":1.8",
        None,
        Some((Forme::Chaine, &v)),
        dbus::ORDRE_NATIF,
    );
    assert_eq!(lire(&t, Forme::Chaine), Err(dbus::INATTENDUE));
}

#[test]
fn un_appel_recu_d_un_pair_est_refuse() {
    let t = dbus::encoder_appel(&hello(), 4, dbus::ORDRE_NATIF).unwrap();
    assert!(lire(&t, Forme::Chaine).is_err());
}

// Les trames qui suivent sont fabriquees champ par champ, pour atteindre
// chaque refus du lecteur d'en-tete.

enum V<'a> {
    S(&'a str),
    O(&'a str),
    G(&'a str),
    U(u32),
    Y(u8),
    B(u32),
}

fn signature_de(v: &V<'_>) -> u8 {
    match v {
        V::S(_) => b's',
        V::O(_) => b'o',
        V::G(_) => b'g',
        V::U(_) => b'u',
        V::Y(_) => b'y',
        V::B(_) => b'b',
    }
}

fn aligner(v: &mut Vec<u8>, n: usize) {
    while !v.len().is_multiple_of(n) {
        v.push(0);
    }
}

/// Une trame dans l'ordre de l'hote. `sig` force la signature du champ quand
/// elle est donnee (pour ecrire un champ connu sous un autre type).
fn trame(genre: u8, serie: u32, champs: &[(u8, Option<u8>, V<'_>)], corps: &[u8]) -> Vec<u8> {
    let mut v = vec![dbus::ORDRE_NATIF, genre, 0, 1];
    v.extend_from_slice(&(corps.len() as u32).to_ne_bytes());
    v.extend_from_slice(&serie.to_ne_bytes());
    v.extend_from_slice(&0_u32.to_ne_bytes());
    for (code, sig, valeur) in champs {
        aligner(&mut v, 8);
        v.extend_from_slice(&[*code, 1, sig.unwrap_or(signature_de(valeur)), 0]);
        match valeur {
            V::S(s) | V::O(s) => {
                aligner(&mut v, 4);
                v.extend_from_slice(&(s.len() as u32).to_ne_bytes());
                v.extend_from_slice(s.as_bytes());
                v.push(0);
            }
            V::G(s) => {
                v.push(s.len() as u8);
                v.extend_from_slice(s.as_bytes());
                v.push(0);
            }
            V::U(x) | V::B(x) => {
                aligner(&mut v, 4);
                v.extend_from_slice(&x.to_ne_bytes());
            }
            V::Y(x) => v.push(*x),
        }
    }
    let longueur = (v.len() - 16) as u32;
    v[12..16].copy_from_slice(&longueur.to_ne_bytes());
    aligner(&mut v, 8);
    v.extend_from_slice(corps);
    v
}

/// Le corps `s` de "stub".
fn corps_stub() -> Vec<u8> {
    let mut c = 4_u32.to_ne_bytes().to_vec();
    c.extend_from_slice(b"stub\0");
    c
}

fn retour_s(champs_en_plus: Vec<(u8, Option<u8>, V<'static>)>) -> Vec<u8> {
    let mut champs = vec![
        (5, None, V::U(4)),
        (7, None, V::S(RES)),
        (8, None, V::G("s")),
    ];
    champs.extend(champs_en_plus);
    trame(2, 77, &champs, &corps_stub())
}

#[test]
fn la_trame_de_reference_fabriquee_se_lit() {
    let t = retour_s(vec![]);
    assert_eq!(
        lire(&t, Forme::Chaine),
        Ok(Some((
            Issue::Retour(Valeur::Chaine("stub".into())),
            t.len()
        )))
    );
}

#[test]
fn un_descripteur_de_fichier_n_est_jamais_lu() {
    // UNIX_FDS, champ 9: aucun descripteur n'a ete negocie.
    let t = retour_s(vec![(9, None, V::U(1))]);
    assert_eq!(lire(&t, Forme::Chaine), Err(dbus::DESCRIPTEUR));
    // Un champ inconnu de type `h` (index de descripteur).
    let t = retour_s(vec![(42, Some(b'h'), V::U(0))]);
    assert_eq!(lire(&t, Forme::Chaine), Err(dbus::DESCRIPTEUR));
}

#[test]
fn un_champ_inconnu_de_type_de_base_est_saute_et_les_autres_refuses() {
    for (code, v) in [
        (42, V::U(7)),
        (43, V::Y(1)),
        (44, V::S("x")),
        (45, V::G("ay")),
    ] {
        let t = retour_s(vec![(code, None, v)]);
        assert!(
            matches!(lire(&t, Forme::Chaine), Ok(Some((Issue::Retour(_), _)))),
            "champ {code}"
        );
    }
    // Un booleen d'en-tete inconnu doit valoir 0 ou 1.
    let t = retour_s(vec![(42, None, V::B(2))]);
    assert_eq!(lire(&t, Forme::Chaine), Err(dbus::MAL_FORMEE));
    // Une variante ou un tableau dans un champ inconnu: refuse.
    let t = retour_s(vec![(42, Some(b'v'), V::U(0))]);
    assert_eq!(lire(&t, Forme::Chaine), Err(dbus::SIGNATURE));
}

#[test]
fn un_en_tete_mal_forme_est_refuse() {
    // Champ connu en double.
    let t = retour_s(vec![(7, None, V::S(RES))]);
    assert_eq!(lire(&t, Forme::Chaine), Err(dbus::MAL_FORMEE));
    // Champ connu d'un autre type.
    let t = trame(
        2,
        77,
        &[
            (5, Some(b's'), V::S("4")),
            (7, None, V::S(RES)),
            (8, None, V::G("s")),
        ],
        &corps_stub(),
    );
    assert_eq!(lire(&t, Forme::Chaine), Err(dbus::MAL_FORMEE));
    // Retour sans REPLY_SERIAL; erreur sans ERROR_NAME.
    let t = trame(
        2,
        77,
        &[(7, None, V::S(RES)), (8, None, V::G("s"))],
        &corps_stub(),
    );
    assert_eq!(lire(&t, Forme::Chaine), Err(dbus::MAL_FORMEE));
    let t = trame(3, 77, &[(5, None, V::U(4)), (7, None, V::S(RES))], &[]);
    assert_eq!(lire(&t, Forme::Chaine), Err(dbus::MAL_FORMEE));
    // Nom d'erreur invalide, chemin invalide, code de champ nul.
    let t = trame(
        3,
        77,
        &[
            (5, None, V::U(4)),
            (7, None, V::S(RES)),
            (4, None, V::S("Erreur")),
        ],
        &[],
    );
    assert_eq!(lire(&t, Forme::Chaine), Err(dbus::MAL_FORMEE));
    let t = retour_s(vec![(1, None, V::O("pas/un/chemin"))]);
    assert_eq!(lire(&t, Forme::Chaine), Err(dbus::MAL_FORMEE));
    let t = retour_s(vec![(0, None, V::U(1))]);
    assert_eq!(lire(&t, Forme::Chaine), Err(dbus::MAL_FORMEE));
    // Un corps sans signature.
    let t = trame(
        2,
        77,
        &[(5, None, V::U(4)), (7, None, V::S(RES))],
        &corps_stub(),
    );
    assert_eq!(lire(&t, Forme::Chaine), Err(dbus::MAL_FORMEE));
}

#[test]
fn boutisme_version_type_et_serie_sont_controles() {
    let base = retour_s(vec![]);
    let autre = if dbus::ORDRE_NATIF == b'l' {
        b'B'
    } else {
        b'l'
    };
    let mut t = base.clone();
    t[0] = autre;
    assert_eq!(lire(&t, Forme::Chaine), Err(dbus::BOUTISME));
    assert_eq!(lire(&t[..1], Forme::Chaine), Err(dbus::BOUTISME));
    let mut t = base.clone();
    t[3] = 2;
    assert!(lire(&t, Forme::Chaine).is_err(), "version 2");
    let mut t = base.clone();
    t[1] = 0;
    assert_eq!(lire(&t, Forme::Chaine), Err(dbus::MAL_FORMEE));
    let mut t = base.clone();
    t[8..12].copy_from_slice(&0_u32.to_ne_bytes());
    assert_eq!(lire(&t, Forme::Chaine), Err(dbus::MAL_FORMEE));
    // Drapeaux inconnus: ignores, comme la specification l'exige.
    let mut t = base.clone();
    t[2] = 0xf0;
    assert!(matches!(lire(&t, Forme::Chaine), Ok(Some(_))));
}

#[test]
fn les_longueurs_hors_borne_sont_refusees_sans_attendre() {
    let base = retour_s(vec![]);
    let mut t = base.clone();
    t[4..8].copy_from_slice(&((dbus::MAX_MESSAGE as u32) + 1).to_ne_bytes());
    assert_eq!(lire(&t, Forme::Chaine), Err(dbus::HORS_BORNE));
    let mut t = base.clone();
    t[12..16].copy_from_slice(&4097_u32.to_ne_bytes());
    assert_eq!(lire(&t, Forme::Chaine), Err(dbus::HORS_BORNE));
    // Une chaine du corps plus longue que la borne.
    let mut t = base.clone();
    let n = t.len();
    t[n - 9..n - 5].copy_from_slice(&((dbus::MAX_MESSAGE as u32) + 1).to_ne_bytes());
    assert_eq!(lire(&t, Forme::Chaine), Err(dbus::HORS_BORNE));
}

#[test]
fn un_remplissage_non_nul_est_refuse() {
    let t = retour_s(vec![]);
    let champs = u32::from_ne_bytes(t[12..16].try_into().unwrap()) as usize;
    let fin = 16 + champs;
    assert!(
        !fin.is_multiple_of(8),
        "la trame de reference a un remplissage"
    );
    let mut x = t.clone();
    x[fin] = 1;
    assert_eq!(lire(&x, Forme::Chaine), Err(dbus::MAL_FORMEE));
    // Remplissage entre deux champs: apres REPLY_SERIAL (fin a l'octet 24,
    // deja aligne) puis apres SENDER (fin a 24 + 4 + 4 + 5 = 37).
    let mut x = t.clone();
    x[37] = 1;
    assert_eq!(lire(&x, Forme::Chaine), Err(dbus::MAL_FORMEE));
}

#[test]
fn un_corps_mal_forme_est_refuse() {
    let t = retour_s(vec![]);
    let n = t.len();
    // UTF-8 invalide, octet nul interne, octet de fin non nul.
    for (i, o) in [(n - 4, 0xff), (n - 4, 0), (n - 1, b'x')] {
        let mut x = t.clone();
        x[i] = o;
        assert_eq!(lire(&x, Forme::Chaine), Err(dbus::MAL_FORMEE), "octet {i}");
    }
    // Des octets en trop apres la valeur.
    let mut x = t.clone();
    x.extend_from_slice(&[0; 8]);
    let c = u32::from_ne_bytes(x[4..8].try_into().unwrap()) + 8;
    x[4..8].copy_from_slice(&c.to_ne_bytes());
    assert_eq!(lire(&x, Forme::Chaine), Err(dbus::MAL_FORMEE));
    // Un corps annonce plus court que la valeur: tronque.
    let mut x = t.clone();
    let c = u32::from_ne_bytes(x[4..8].try_into().unwrap()) - 1;
    x[4..8].copy_from_slice(&c.to_ne_bytes());
    x.pop();
    assert_eq!(lire(&x, Forme::Chaine), Err(dbus::TRONQUE));
}

#[test]
fn une_autre_signature_est_refusee() {
    let t = retour(4, Forme::Chaine, Valeur::Chaine("stub".into()));
    assert_eq!(lire(&t, Forme::Chemin), Err(dbus::SIGNATURE));
    assert_eq!(lire(&t, VC), Err(dbus::SIGNATURE));
    let t = retour(4, VC, Valeur::Chaine("stub".into()));
    assert_eq!(lire(&t, Forme::Chaine), Err(dbus::SIGNATURE));
    let t = retour(4, VB, Valeur::Booleen(true));
    assert_eq!(lire(&t, VC), Err(dbus::SIGNATURE));
    assert_eq!(lire(&t, Forme::Chaine), Err(dbus::SIGNATURE));
    // `a(iiay)` (la propriete DNS, sans port ni nom) n'est pas `a(iiayqs)`.
    let mut corps = vec![7];
    corps.extend_from_slice(b"a(iiay)\0");
    aligner(&mut corps, 4);
    corps.extend_from_slice(&0_u32.to_ne_bytes());
    let t = trame(
        2,
        77,
        &[
            (5, None, V::U(4)),
            (7, None, V::S(RES)),
            (8, None, V::G("v")),
        ],
        &corps,
    );
    assert_eq!(
        lire(&t, Forme::Variante(Propriete::Serveurs)),
        Err(dbus::SIGNATURE)
    );
    // Les serveurs du Manager et ceux d'un lien ne se lisent pas l'un pour
    // l'autre.
    let vl = Forme::Variante(Propriete::ServeursDuLien);
    let t = retour(4, VS, Valeur::Serveurs(serveurs_exemple()));
    assert_eq!(lire(&t, vl), Err(dbus::SIGNATURE));
    let t = retour(4, vl, Valeur::ServeursDuLien(vec![]));
    assert_eq!(lire(&t, VS), Err(dbus::SIGNATURE));
}

#[test]
fn un_booleen_hors_de_0_et_1_est_refuse() {
    let mut t = retour(4, VB, Valeur::Booleen(true));
    let n = t.len();
    t[n - 4..].copy_from_slice(&2_u32.to_ne_bytes());
    assert_eq!(lire(&t, VB), Err(dbus::MAL_FORMEE));
}

#[test]
fn une_adresse_de_famille_ou_de_taille_inattendue_est_refusee() {
    let mut s = serveurs_exemple();
    s[0].famille = 7;
    let t = retour(4, VS, Valeur::Serveurs(s));
    assert_eq!(lire(&t, VS), Err("famille d'adresse D-Bus inconnue"));
    let mut s = serveurs_exemple();
    s[0].adresse = vec![0; 16];
    let t = retour(4, VS, Valeur::Serveurs(s.clone()));
    assert_eq!(lire(&t, VS), Err(dbus::MAL_FORMEE));
    let vl = Forme::Variante(Propriete::ServeursDuLien);
    let t = retour(4, vl, Valeur::ServeursDuLien(s));
    assert_eq!(lire(&t, vl), Err(dbus::MAL_FORMEE));
}

/// La borne du nombre d'elements mord avant celle du message.
#[test]
fn la_borne_des_elements_mord() {
    let d = |n: usize| {
        Valeur::Domaines(
            (0..n)
                .map(|i| Domaine {
                    index: i as i32,
                    nom: ".".into(),
                    route_seule: true,
                })
                .collect(),
        )
    };
    let t = retour(4, VD, d(dbus::MAX_ELEMENTS));
    assert!(t.len() < dbus::MAX_MESSAGE);
    assert!(matches!(lire(&t, VD), Ok(Some((Issue::Retour(_), _)))));
    let t = retour(4, VD, d(dbus::MAX_ELEMENTS + 1));
    assert!(t.len() < dbus::MAX_MESSAGE);
    assert_eq!(lire(&t, VD), Err(dbus::HORS_BORNE));
    // Les serveurs du Manager et ceux d'un lien.
    type Faire = fn(Vec<Serveur>) -> Valeur;
    let vl = Forme::Variante(Propriete::ServeursDuLien);
    for (forme, faire) in [
        (VS, Valeur::Serveurs as Faire),
        (vl, Valeur::ServeursDuLien as Faire),
    ] {
        let s = |n: usize| faire(vec![serveur(0, IpAddr::V4(AMONT4)); n]);
        let t = retour(4, forme, s(dbus::MAX_ELEMENTS));
        assert!(t.len() < dbus::MAX_MESSAGE);
        assert!(matches!(lire(&t, forme), Ok(Some((Issue::Retour(_), _)))));
        let t = retour(4, forme, s(dbus::MAX_ELEMENTS + 1));
        assert_eq!(lire(&t, forme), Err(dbus::HORS_BORNE), "{forme:?}");
    }
}

/// Un signal (`NameAcquired` apres `Hello`) ou un message d'un type inconnu
/// est saute en entier; la reponse qui suit est lue, et la longueur rendue
/// couvre les deux.
#[test]
fn signaux_et_types_inconnus_sont_sautes() {
    let signal = trame(
        4,
        2,
        &[
            (1, None, V::O("/org/freedesktop/DBus")),
            (2, None, V::S("org.freedesktop.DBus")),
            (3, None, V::S("NameAcquired")),
            (7, None, V::S(dbus::BUS)),
            (8, None, V::G("s")),
        ],
        &corps_stub(),
    );
    let inconnu = trame(9, 3, &[(7, None, V::S(dbus::BUS))], &[]);
    let r = retour(4, Forme::Chaine, Valeur::Chaine("stub".into()));
    let mut flux = signal.clone();
    flux.extend_from_slice(&inconnu);
    flux.extend_from_slice(&r);
    assert_eq!(
        lire(&flux, Forme::Chaine),
        Ok(Some((
            Issue::Retour(Valeur::Chaine("stub".into())),
            flux.len()
        )))
    );
    // Un signal sans membre est mal forme, meme saute.
    let signal = trame(4, 2, &[(1, None, V::O("/a")), (2, None, V::S("a.b"))], &[]);
    assert_eq!(lire(&signal, Forme::Chaine), Err(dbus::MAL_FORMEE));
    // Une reponse suivie d'octets: seule la reponse est consommee.
    let mut flux = r.clone();
    flux.extend_from_slice(&signal);
    assert!(matches!(lire(&flux, Forme::Chaine), Ok(Some((_, n))) if n == r.len()));
}

// --- lecteurs des fichiers du systeme ----------------------------------------

#[test]
fn la_ligne_hosts_de_nsswitch_est_lue_avec_ses_actions() {
    let ubuntu = b"# commentaire\npasswd: files systemd\nhosts:          files mdns4_minimal [NOTFOUND=return] dns\nnetworks: files\n";
    assert_eq!(
        sources_hosts(ubuntu).unwrap(),
        ["files", "mdns4_minimal", "dns"]
    );
    assert_eq!(
        sources_hosts(b"  hosts: files resolve [!UNAVAIL=return]dns myhostname # fin\n").unwrap(),
        ["files", "resolve", "dns", "myhostname"]
    );
    assert_eq!(sources_hosts(b"hosts :files").unwrap(), ["files"]);
    assert_eq!(
        sources_hosts(b"#hosts: ldap\nhosts: files").unwrap(),
        ["files"]
    );
}

#[test]
fn une_ligne_hosts_ambigue_ou_absente_est_refusee() {
    for refuse in [
        &b"passwd: files\n"[..],
        b"",
        b"hosts: files\nhosts: dns\n",
        b"Hosts: files\n",
        b"HOSTS: files\nhosts: files\n",
        b"hosts: files [NOTFOUND=return dns\n",
        b"hosts:\n",
        b"hosts: [NOTFOUND=return]\n",
        b"hosts: files d\xc3\xa9\n",
        b"hosts: files mdns.minimal\n",
    ] {
        assert!(
            sources_hosts(refuse).is_err(),
            "{:?}",
            String::from_utf8_lossy(refuse)
        );
    }
}

const ENTETE4: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n";
/// L'en-tete de `/proc/net/udp6`, compose comme le noyau v7.0 le compose
/// (`IPV6_SEQ_DGRAM_HEADER`): chaque adresse alignee a gauche sur 38 colonnes.
fn entete6() -> String {
    format!(
        "  sl  {:<38}{:<38}st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n",
        "local_address", "remote_address"
    )
}

fn ligne4(local: &str, distant: &str, uid: &str) -> String {
    format!(
        " 7: {local} {distant} 07 00000000:00000000 00:00000000 00000000 {uid:>5}        0 23456 2 0000000000000000 0\n"
    )
}

/// L'adresse, ecrite comme le noyau l'ecrit sur CET hote: `%08X` d'un mot
/// reseau lu dans l'ordre de l'hote.
fn hexa4(a: Ipv4Addr) -> String {
    format!("{:08X}", u32::from_ne_bytes(a.octets()))
}

fn hexa6(a: Ipv6Addr) -> String {
    a.octets()
        .chunks(4)
        .map(|m| format!("{:08X}", u32::from_ne_bytes(m.try_into().unwrap())))
        .collect()
}

#[test]
fn les_ecoutes_udp_du_port_53_sont_lues_avec_leur_compte() {
    let stub = format!("{}:0035", hexa4(Ipv4Addr::new(127, 0, 0, 53)));
    let zero = "00000000:0000";
    let texte = format!(
        "{ENTETE4}{}{}{}{}",
        ligne4(&stub, zero, "991"),
        ligne4(&format!("{}:14E9", hexa4(Ipv4Addr::UNSPECIFIED)), zero, "0"),
        ligne4(
            &format!("{}:0035", hexa4(Ipv4Addr::new(127, 0, 0, 1))),
            &format!("{}:0035", hexa4(Ipv4Addr::new(192, 0, 2, 1))),
            "0"
        ),
        ligne4(
            &format!("{}:0035", hexa4(Ipv4Addr::LOCALHOST)),
            zero,
            "64000"
        ),
    );
    assert_eq!(
        ecoutes_udp(texte.as_bytes(), false).unwrap(),
        vec![
            Ecoute {
                adresse: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 53)),
                port: 53,
                uid: 991
            },
            Ecoute {
                adresse: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: 53,
                uid: 64000
            },
        ]
    );
    let un = hexa6(Ipv6Addr::LOCALHOST);
    let en_tete = entete6();
    let texte6 = format!(
        "{en_tete} 3: {un}:0035 {}:0000 07 00000000:00000000 00:00000000 00000000   990        0 1 2 0000000000000000 0\n",
        hexa6(Ipv6Addr::UNSPECIFIED)
    );
    assert_eq!(
        ecoutes_udp(texte6.as_bytes(), true).unwrap(),
        vec![Ecoute {
            adresse: IpAddr::V6(Ipv6Addr::LOCALHOST),
            port: 53,
            uid: 990
        }]
    );
}

#[test]
fn un_fichier_udp_illisible_est_refuse() {
    let stub = format!("{}:0035", hexa4(Ipv4Addr::new(127, 0, 0, 53)));
    let bonne = ligne4(&stub, "00000000:0000", "991");
    for (texte, v6) in [
        (bonne.clone(), false),
        (format!("{}{bonne}", entete6()), false),
        (format!("{ENTETE4}{bonne}"), true),
        (format!("{ENTETE4}{}", bonne.replace(" 0\n", "\n")), false),
        (format!("{ENTETE4}{}", bonne.replace("991", "99x")), false),
        (format!("{ENTETE4}{}", bonne.replace("991", "-1")), false),
        (
            format!("{ENTETE4}{}", bonne.replace(":0035", ":035")),
            false,
        ),
        (format!("{ENTETE4}{}", bonne.replace(" 7:", " 7")), false),
        (
            format!(
                "{ENTETE4}{}",
                bonne.replacen("00000000:0000", "0000000G:0000", 1)
            ),
            false,
        ),
    ] {
        assert!(ecoutes_udp(texte.as_bytes(), v6).is_err(), "{texte}");
    }
    assert_eq!(ecoutes_udp(ENTETE4.as_bytes(), false), Ok(vec![]));
}

#[test]
fn le_mode_de_resolv_conf_suit_l_ordre_de_resolved() {
    let (a, b, c, d) = (Some((1, 10)), Some((1, 11)), Some((1, 12)), Some((2, 10)));
    assert_eq!(mode_resolv_conf(None, a, b, c), ModeResolvConf::Absent);
    assert_eq!(mode_resolv_conf(a, a, b, c), ModeResolvConf::Uplink);
    assert_eq!(mode_resolv_conf(b, a, b, c), ModeResolvConf::Stub);
    assert_eq!(mode_resolv_conf(c, a, b, c), ModeResolvConf::Statique);
    assert_eq!(mode_resolv_conf(d, a, b, c), ModeResolvConf::Etranger);
    // Meme inode pour deux fichiers de resolved: le premier de l'ordre.
    assert_eq!(mode_resolv_conf(b, b, b, c), ModeResolvConf::Uplink);
    // Un fichier de resolved absent est passe.
    assert_eq!(mode_resolv_conf(c, None, None, c), ModeResolvConf::Statique);
    assert_eq!(ModeResolvConf::Statique.nom(), "static");
    assert_eq!(ModeResolvConf::Absent.nom(), "missing");
    assert_eq!(ModeResolvConf::Etranger.nom(), "foreign");
}

// --- intention ---------------------------------------------------------------

const TUNNEL: &str = "bt0";
const AMONT4: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 53);
const AMONT6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x53);
const DHCP: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 53);

fn json_intention(backend: &str, embarque: bool, uid: Option<u32>) -> serde_json::Value {
    json!({
        "schema_version": 1,
        "backend": backend,
        "interface": TUNNEL,
        "local_resolver": "127.0.0.1",
        "upstream": [AMONT4.to_string(), AMONT6.to_string()],
        "embarque": embarque,
        "resolveur_uid": uid,
    })
}

fn intention(backend: &str, embarque: bool, uid: Option<u32>) -> Intention {
    intention_dns(json_intention(backend, embarque, uid)).expect("intention valide")
}

/// L'attendu est le plan du produit, construit par le meme constructeur que
/// la pose: memes serveurs, memes commandes, meme fichier.
#[test]
fn l_attendu_est_le_plan_que_le_produit_pose() {
    for embarque in [false, true] {
        let i = intention("systemd-resolved", embarque, None);
        let politique = DnsPolicy {
            local_resolver: IpAddr::V4(Ipv4Addr::LOCALHOST),
            upstream: vec![IpAddr::V4(AMONT4), IpAddr::V6(AMONT6)],
            embarque,
            anti_telemetrie: ProfilTelemetrie::Aucun,
        };
        assert_eq!(i.plan, PlanDns::nouveau(TUNNEL, &politique));
        assert_eq!(
            i.plan.serveurs,
            bifrost_core::plan_dns::serveurs_a_interroger(&politique)
        );
    }
    let i = intention("systemd-resolved", false, None);
    assert_eq!(i.backend, Backend::Resolved);
    assert_eq!(i.plan.serveurs, [IpAddr::V4(AMONT4), IpAddr::V6(AMONT6)]);
    let e = intention("resolv-conf", true, Some(64000));
    assert_eq!(e.backend, Backend::ResolvConf);
    assert_eq!(e.plan.serveurs, [IpAddr::V4(Ipv4Addr::LOCALHOST)]);
    assert_eq!(e.resolveur_uid, Some(64000));
}

#[test]
fn une_intention_hors_regle_est_refusee() {
    let base = json_intention("systemd-resolved", false, None);
    let avec = |cle: &str, v: serde_json::Value| {
        let mut x = base.clone();
        x[cle] = v;
        x
    };
    let sans = |cle: &str| {
        let mut x = base.clone();
        x.as_object_mut().unwrap().remove(cle);
        x
    };
    let mut cas = vec![
        avec("schema_version", json!(2)),
        avec("schema_version", json!("1")),
        avec("backend", json!("networkmanager")),
        avec("interface", json!("lo")),
        avec("interface", json!("")),
        avec("interface", json!("une-interface-16")),
        avec("interface", json!("bt 0")),
        avec("interface", json!("bt0/x")),
        avec("local_resolver", json!("192.0.2.1")),
        avec("local_resolver", json!("127.000.0.1")),
        avec("local_resolver", json!("::0001")),
        avec("local_resolver", json!(1)),
        avec("upstream", json!([])),
        avec("upstream", json!(["192.0.2.53", "192.0.2.53"])),
        avec("upstream", json!(["2001:DB8::53"])),
        avec("upstream", json!("192.0.2.53")),
        avec(
            "upstream",
            json!((1..=17).map(|i| format!("192.0.2.{i}")).collect::<Vec<_>>()),
        ),
        avec("embarque", json!("non")),
        avec("resolveur_uid", json!(64000)),
        avec("resolveur_uid", json!(-1)),
        avec("resolveur_uid", json!(4_294_967_296_u64)),
        avec("resolveur_uid", json!("64000")),
        sans("resolveur_uid"),
        sans("backend"),
        avec("en_trop", json!(1)),
        json!([]),
    ];
    let mut zero = json_intention("systemd-resolved", true, None);
    zero["resolveur_uid"] = json!(0);
    cas.push(zero);
    for v in cas {
        assert!(intention_dns(v.clone()).is_err(), "{v}");
    }
    let seize: Vec<String> = (1..=16).map(|i| format!("192.0.2.{i}")).collect();
    assert!(intention_dns(avec("upstream", json!(seize))).is_ok());
}

// --- comparaison -------------------------------------------------------------

const RES_UID: u32 = 991;
const I_PHY: u32 = 2;
const I_TUN: u32 = 3;

fn serveur(index: u32, a: IpAddr) -> Serveur {
    let (famille, adresse) = match a {
        IpAddr::V4(v) => (2, v.octets().to_vec()),
        IpAddr::V6(v) => (10, v.octets().to_vec()),
    };
    Serveur {
        index: index as i32,
        famille,
        adresse,
        port: 0,
        nom: String::new(),
    }
}

fn domaine(index: u32, nom: &str, route_seule: bool) -> Domaine {
    Domaine {
        index: index as i32,
        nom: nom.into(),
        route_seule,
    }
}

fn lien(index: u32, nom: &str, route_par_defaut: bool, portees: u64) -> Lien {
    Lien {
        index,
        nom: nom.as_bytes().to_vec(),
        route_par_defaut,
        portees,
        serveurs: Vec::new(),
    }
}

/// Le `DNSEx` du Manager que resolved v255 rend pour ces serveurs globaux et
/// ces liens: chaque serveur une fois, sous l'index de l'interface
/// d'emission. `dns_server_ifindex`: une adresse de bouclage (127/8, ::1) part
/// par `lo` (index 1) quel que soit son lien; sinon l'index du lien, ou celui
/// qu'un serveur global porte.
fn dnsex(globaux: &[Serveur], liens: &[Lien]) -> Vec<Serveur> {
    let emission = |s: &Serveur, index: i32| {
        let bouclage = match s.famille {
            2 => s.adresse[0] == 127,
            _ => s.adresse == Ipv6Addr::LOCALHOST.octets(),
        };
        Serveur {
            index: if bouclage { 1 } else { index },
            ..s.clone()
        }
    };
    let mut v: Vec<Serveur> = globaux.iter().map(|s| emission(s, s.index)).collect();
    for l in liens {
        v.extend(l.serveurs.iter().map(|s| emission(s, l.index as i32)));
    }
    v
}

/// Les serveurs d'un lien, tels que son `DNSEx` les rend (index a 0).
fn du_lien(adresses: &[IpAddr]) -> Vec<Serveur> {
    adresses.iter().map(|a| serveur(0, *a)).collect()
}

/// Apres un changement des serveurs d'un lien: le Manager les rend aussi.
fn resynchroniser(o: &mut Observation, globaux: &[Serveur]) {
    let r = res(o);
    r.serveurs = dnsex(globaux, &r.liens);
    r.serveurs.sort_by_key(|s| s.index);
}

/// Les serveurs du lien du tunnel (troisieme lien de la pose).
fn tun(o: &mut Observation) -> &mut Vec<Serveur> {
    &mut res(o).liens[2].serveurs
}

const STUB: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 53));

/// La pose du produit sur un poste dont le lien physique a recu un serveur par
/// DHCP, sans domaine: ce que la mesure de la phase 1 a vu sur un poste reel.
fn pose(i: &Intention) -> Observation {
    let mut physique = lien(I_PHY, "bp0", true, 1);
    physique.serveurs = du_lien(&[IpAddr::V4(DHCP)]);
    let mut tunnel = lien(I_TUN, TUNNEL, true, 1);
    tunnel.serveurs = du_lien(&i.plan.serveurs);
    let liens = vec![lien(1, "lo", false, 0), physique, tunnel];
    let serveurs = dnsex(&[], &liens);
    Observation {
        hosts: vec!["files".into(), "mdns4_minimal".into(), "dns".into()],
        mdns_allow: None,
        ecoutes: vec![Ecoute {
            adresse: STUB,
            port: 53,
            uid: RES_UID,
        }],
        mode: Some(ModeResolvConf::Stub),
        resolv_conf: Some(STUB_RESOLV_CONF.to_vec()),
        tunnel: Some(I_TUN),
        resolved: Some(
            EtatResolved {
                proprietaire: ":1.7".into(),
                uid: RES_UID,
                mode: "stub".into(),
                serveurs,
                domaines: vec![domaine(I_TUN, ".", true)],
                delegues: false,
                liens,
            }
            .normaliser(),
        ),
    }
}

fn ecarts(i: &Intention, o: &Observation) -> Vec<&'static str> {
    comparer(i, o).expect("comparaison mesuree").3
}

fn res(o: &mut Observation) -> &mut EtatResolved {
    o.resolved.as_mut().unwrap()
}

#[test]
fn la_pose_du_produit_correspond() {
    for embarque in [false, true] {
        let i = intention("systemd-resolved", embarque, None);
        let mut o = pose(&i);
        if embarque {
            o.ecoutes.push(Ecoute {
                adresse: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: 53,
                uid: 64000,
            });
        }
        // Le resolveur embarque est sur le lien du tunnel, mais le Manager le
        // rend sous l'index de `lo` (mesure au banc, systemd 255).
        let sous_lo = o.resolved.as_ref().unwrap().serveurs.iter();
        assert_eq!(
            sous_lo.filter(|s| s.index == 1).count(),
            usize::from(embarque)
        );
        let (a, obs, lim, e) = comparer(&i, &o).unwrap();
        assert!(e.is_empty(), "{e:?}");
        assert_eq!(a.servers, i.plan.serveurs.len());
        assert_eq!(obs.tunnel_servers, Some(i.plan.serveurs.len()));
        assert_eq!(obs.scopes_with_servers, Some(2));
        assert_eq!(obs.other_default_route_links, Some(1));
        assert_eq!(obs.resolv_conf_mode, Some("stub"));
        assert_eq!(lim.mdns_nss_sources, 1);
        assert_eq!(lim.mdns_links, Some(0));
    }
}

#[test]
fn le_mode_statique_correspond_et_les_autres_sont_des_ecarts() {
    let i = intention("systemd-resolved", false, None);
    let mut o = pose(&i);
    o.mode = Some(ModeResolvConf::Statique);
    res(&mut o).mode = "static".into();
    assert!(ecarts(&i, &o).is_empty());
    for m in [
        ModeResolvConf::Uplink,
        ModeResolvConf::Etranger,
        ModeResolvConf::Absent,
    ] {
        let mut o = pose(&i);
        o.mode = Some(m);
        res(&mut o).mode = m.nom().into();
        assert_eq!(ecarts(&i, &o), ["resolv-conf-path"], "{m:?}");
    }
}

/// Le stub tel que systemd-resolved v255 l'ecrit (`resolved-resolv-conf.c`),
/// commentaires abreges.
const STUB_RESOLV_CONF: &[u8] = b"# This is /run/systemd/resolve/stub-resolv.conf managed by man:systemd-resolved(8).\n# Do not edit.\n\nnameserver 127.0.0.53\noptions edns0 trust-ad\nsearch .\n";

#[test]
fn les_lignes_nameserver_sont_lues_comme_glibc_les_lit() {
    assert_eq!(serveurs_resolv_conf(STUB_RESOLV_CONF), [&b"127.0.0.53"[..]]);
    let texte = b"nameserver\t192.0.2.1 # fin\n nameserver 192.0.2.2\n#nameserver 192.0.2.3\n;nameserver 192.0.2.4\nnameserver192.0.2.5\nnameserver  2001:db8::1\tx\nnameservers 192.0.2.6\n";
    assert_eq!(
        serveurs_resolv_conf(texte),
        [&b"192.0.2.1"[..], b"2001:db8::1"]
    );
}

/// Le mode compare des inodes: un fichier monte sur celui du stub garde son
/// inode, et glibc lit pourtant autre chose. Le contenu est donc juge aussi.
#[test]
fn le_mode_stub_exige_un_contenu_qui_designe_le_stub() {
    let i = intention("systemd-resolved", false, None);
    for (contenu, admis) in [
        (Some(&b"nameserver 127.0.0.53\n"[..]), true),
        (
            Some(b"nameserver 127.0.0.53\nnameserver 127.0.0.53\n"),
            true,
        ),
        (Some(b"nameserver 198.51.100.53\n"), false),
        (
            Some(b"nameserver 127.0.0.53\nnameserver 198.51.100.53\n"),
            false,
        ),
        (Some(b"options edns0\n"), false),
        (Some(b""), false),
        (Some(b"nameserver 127.0.0.54\n"), false),
        (None, false),
    ] {
        let mut o = pose(&i);
        o.resolv_conf = contenu.map(<[u8]>::to_vec);
        let e = ecarts(&i, &o);
        assert_eq!(
            e.is_empty(),
            admis,
            "{:?}",
            contenu.map(String::from_utf8_lossy)
        );
        if !admis {
            assert_eq!(e, ["resolv-conf-path"]);
        }
    }
}

#[test]
fn le_fichier_du_backend_resolv_conf_se_compare_au_bit_pres() {
    let i = intention("resolv-conf", false, None);
    let mut o = pose(&i);
    o.resolved = None;
    o.mode = None;
    o.tunnel = None;
    o.resolv_conf = Some(i.plan.contenu_resolv_conf().into_bytes());
    let (_, obs, _, e) = comparer(&i, &o).unwrap();
    assert!(e.is_empty(), "{e:?}");
    assert_eq!(obs.links, None);
    let mut x = o.clone();
    x.resolv_conf.as_mut().unwrap().push(b'\n');
    assert_eq!(ecarts(&i, &x), ["resolv-conf-content"]);
    let mut x = o.clone();
    x.resolv_conf = Some(contenu_resolv_conf_inverse(&i));
    assert_eq!(ecarts(&i, &x), ["resolv-conf-content"]);
    let mut x = o.clone();
    x.resolv_conf = None;
    assert_eq!(ecarts(&i, &x), ["resolv-conf-content"]);
}

/// Les memes serveurs dans l'autre ordre: glibc interroge le premier.
fn contenu_resolv_conf_inverse(i: &Intention) -> Vec<u8> {
    let mut s = i.plan.serveurs.clone();
    s.reverse();
    bifrost_core::plan_dns::contenu_resolv_conf(&s).into_bytes()
}

#[test]
fn les_sources_hosts_hors_de_la_liste_sont_un_ecart() {
    let i = intention("systemd-resolved", false, None);
    let c = intention("resolv-conf", false, None);
    let avec = |hosts: &[&str], mdns_allow: Option<bool>, i: &Intention| {
        let mut o = pose(i);
        if i.backend == Backend::ResolvConf {
            o.resolved = None;
            o.mode = None;
            o.resolv_conf = Some(i.plan.contenu_resolv_conf().into_bytes());
        }
        o.hosts = hosts.iter().map(|s| s.to_string()).collect();
        o.mdns_allow = mdns_allow;
        comparer(i, &o).unwrap()
    };
    let admis = ["files", "myhostname", "mymachines", "resolve", "dns"];
    assert!(avec(&admis, None, &i).3.is_empty());
    assert_eq!(
        avec(&admis, None, &c).3,
        ["hosts-sources"],
        "resolve sans resolved"
    );
    assert!(avec(&["files", "dns"], None, &c).3.is_empty());
    for hors in ["ldap", "wins", "extrausers", "libvirt", "mdns4", "mdns"] {
        assert_eq!(
            avec(&["files", hors, "dns"], Some(true), &i).3,
            ["hosts-sources"],
            "{hors}"
        );
    }
    let (_, _, lim, e) = avec(&["files", "mdns4", "dns"], Some(false), &i);
    assert!(e.is_empty());
    assert_eq!(lim.mdns_nss_sources, 1);
    let (_, _, lim, e) = avec(&["files", "mdns_minimal", "mdns6_minimal", "dns"], None, &i);
    assert!(e.is_empty());
    assert_eq!(lim.mdns_nss_sources, 2);
}

#[test]
fn le_lien_du_tunnel_absent_ou_sans_portee_dns_est_un_ecart() {
    let i = intention("systemd-resolved", false, None);
    let mut o = pose(&i);
    o.tunnel = None;
    let e = ecarts(&i, &o);
    assert_eq!(e[0], "tunnel-link-scope", "{e:?}");
    let mut o = pose(&i);
    res(&mut o).liens[2].portees = 0;
    assert_eq!(ecarts(&i, &o), ["tunnel-link-scope"]);
    // Les portees multidiffusion seules ne font pas une portee DNS.
    let mut o = pose(&i);
    res(&mut o).liens[2].portees = 1 << 3;
    assert_eq!(ecarts(&i, &o), ["tunnel-link-scope"]);
}

#[test]
fn les_serveurs_du_tunnel_sont_ceux_du_plan_dans_l_ordre() {
    let i = intention("systemd-resolved", false, None);
    let mut o = pose(&i);
    tun(&mut o).swap(0, 1);
    resynchroniser(&mut o, &[]);
    assert_eq!(ecarts(&i, &o), ["tunnel-link-servers"], "ordre");
    let mut o = pose(&i);
    tun(&mut o).remove(1);
    resynchroniser(&mut o, &[]);
    assert_eq!(ecarts(&i, &o), ["tunnel-link-servers"], "manquant");
    let mut o = pose(&i);
    tun(&mut o).push(serveur(0, IpAddr::V4(DHCP)));
    resynchroniser(&mut o, &[]);
    assert_eq!(ecarts(&i, &o), ["tunnel-link-servers"], "en trop");
    for (port, nom, ok) in [(53, "", true), (853, "", false), (0, "dns.example", false)] {
        let mut o = pose(&i);
        tun(&mut o)[0].port = port;
        tun(&mut o)[0].nom = nom.into();
        resynchroniser(&mut o, &[]);
        assert_eq!(ecarts(&i, &o).is_empty(), ok, "port {port} nom {nom}");
    }
    let mut o = pose(&i);
    tun(&mut o)[0].famille = 10;
    resynchroniser(&mut o, &[]);
    assert_eq!(ecarts(&i, &o), ["tunnel-link-servers"], "famille");
    // Un serveur global n'est pas un serveur du tunnel, meme sous son index
    // d'emission (`adresse%interface`).
    let mut o = pose(&i);
    let global = serveur(I_TUN, IpAddr::V4(AMONT4));
    tun(&mut o).remove(0);
    resynchroniser(&mut o, std::slice::from_ref(&global));
    assert_eq!(ecarts(&i, &o), ["tunnel-link-servers"], "global");
}

/// Le Manager rend un serveur sous l'index de l'interface d'emission: le
/// serveur de chaque lien est rattache a son lien, ce qui reste est global.
#[test]
fn chaque_serveur_est_rattache_a_sa_portee() {
    let lo4 = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let lo6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
    let autre_lo = IpAddr::V4(Ipv4Addr::new(127, 1, 2, 3));
    for (adresse, index_manager) in [
        (lo4, 1),
        (lo6, 1),
        (autre_lo, 1),
        (IpAddr::V4(AMONT4), I_TUN as i32),
        (IpAddr::V6(AMONT6), I_TUN as i32),
    ] {
        let mut o = pose(&intention("systemd-resolved", false, None));
        *tun(&mut o) = du_lien(&[adresse]);
        resynchroniser(&mut o, &[]);
        let r = o.resolved.as_ref().unwrap();
        assert!(
            r.serveurs
                .iter()
                .any(|s| s.index == index_manager && s.adresse == serveur(0, adresse).adresse),
            "{adresse}"
        );
        let v = attribuer(r).unwrap();
        assert_eq!(
            v.iter()
                .filter(|s| s.index == I_TUN as i32)
                .map(|s| s.adresse.clone())
                .collect::<Vec<_>>(),
            [serveur(0, adresse).adresse],
            "{adresse}"
        );
    }
    // Le meme serveur de bouclage, global et sur le tunnel: un de chaque.
    let i = intention("systemd-resolved", true, None);
    let mut o = pose(&i);
    o.ecoutes.push(Ecoute {
        adresse: lo4,
        port: 53,
        uid: 64000,
    });
    let globaux = [serveur(0, lo4), serveur(I_PHY, IpAddr::V4(AMONT4))];
    resynchroniser(&mut o, &globaux);
    let v = attribuer(o.resolved.as_ref().unwrap()).unwrap();
    assert_eq!(v.iter().filter(|s| s.index == 0).count(), 2);
    assert_eq!(v.iter().filter(|s| s.index == I_TUN as i32).count(), 1);
    assert_eq!(v.iter().filter(|s| s.index == I_PHY as i32).count(), 1);
    let (_, obs, _, e) = comparer(&i, &o).unwrap();
    assert!(e.is_empty(), "{e:?}");
    assert_eq!(obs.scopes_with_servers, Some(3));
    assert_eq!(obs.tunnel_servers, Some(1));
}

/// Un serveur qu'un lien declare et que le Manager ne rend pas, ou pas sous
/// l'index d'emission attendu: les deux lectures ne concordent pas.
#[test]
fn des_serveurs_discordants_ne_sont_pas_mesures() {
    let i = intention("systemd-resolved", true, None);
    let mut o = pose(&i);
    o.ecoutes.push(Ecoute {
        adresse: IpAddr::V4(Ipv4Addr::LOCALHOST),
        port: 53,
        uid: 64000,
    });
    assert!(comparer(&i, &o).is_ok());
    // Le Manager rend le serveur de bouclage sous l'index du lien.
    let mut x = o.clone();
    for s in &mut res(&mut x).serveurs {
        if s.index == 1 {
            s.index = I_TUN as i32;
        }
    }
    assert_eq!(comparer(&i, &x).unwrap_err(), DISCORDANTS);
    // Le Manager ne le rend pas.
    let mut x = o.clone();
    res(&mut x).serveurs.retain(|s| s.index != 1);
    assert_eq!(comparer(&i, &x).unwrap_err(), DISCORDANTS);
    // Deux fois sur le lien, une fois au Manager.
    let mut x = o.clone();
    let double = tun(&mut x)[0].clone();
    tun(&mut x).push(double);
    assert_eq!(comparer(&i, &x).unwrap_err(), DISCORDANTS);
}

#[test]
fn le_tunnel_porte_exactement_le_domaine_racine_de_routage() {
    let i = intention("systemd-resolved", false, None);
    for domaines in [
        vec![],
        vec![domaine(I_TUN, ".", false)],
        vec![domaine(I_TUN, ".", true), domaine(I_TUN, "example", true)],
        vec![domaine(I_TUN, "example", true)],
    ] {
        let mut o = pose(&i);
        res(&mut o).domaines = domaines.clone();
        assert_eq!(ecarts(&i, &o), ["tunnel-link-domains"], "{domaines:?}");
    }
}

/// La regle de legitimite, sans liste d'adresses: une autre portee qui a un
/// serveur est admise tant qu'aucun domaine ne la fait passer devant `~.` ou a
/// egalite.
#[test]
fn la_regle_de_legitimite_juge_les_domaines_des_autres_portees() {
    let i = intention("systemd-resolved", false, None);
    // Domaine de routage, puis de recherche, sur le lien physique.
    for route_seule in [true, false] {
        let mut o = pose(&i);
        res(&mut o)
            .domaines
            .push(domaine(I_PHY, "example", route_seule));
        assert_eq!(ecarts(&i, &o), ["dns-exceptions"], "route {route_seule}");
    }
    // La portee globale (index 0) avec un serveur et un domaine.
    let mut o = pose(&i);
    res(&mut o).serveurs.push(serveur(0, IpAddr::V4(DHCP)));
    res(&mut o).domaines.push(domaine(0, "example", false));
    assert_eq!(ecarts(&i, &o), ["dns-exceptions"]);
    // `~.` aussi sur le lien physique: les deux sont interroges.
    let mut o = pose(&i);
    res(&mut o).domaines.push(domaine(I_PHY, ".", true));
    assert_eq!(ecarts(&i, &o), ["competing-default-routes"]);
    let mut o = pose(&i);
    res(&mut o).domaines.push(domaine(I_PHY, ".", true));
    res(&mut o).domaines.push(domaine(I_PHY, "example", true));
    assert_eq!(
        ecarts(&i, &o),
        ["dns-exceptions", "competing-default-routes"]
    );
    // Une portee sans serveur ne recoit rien: ses domaines sont admis.
    let mut o = pose(&i);
    res(&mut o).liens[1].serveurs.clear();
    resynchroniser(&mut o, &[]);
    res(&mut o).domaines.push(domaine(I_PHY, "example", true));
    res(&mut o).domaines.push(domaine(I_PHY, ".", true));
    let (_, obs, _, e) = comparer(&i, &o).unwrap();
    assert!(e.is_empty(), "{e:?}");
    assert_eq!(obs.other_scopes_with_domains, Some(0));
    // DefaultRoute ne change pas le jugement: il est compte.
    let mut o = pose(&i);
    res(&mut o).liens[1].route_par_defaut = false;
    let (_, obs, _, e) = comparer(&i, &o).unwrap();
    assert!(e.is_empty());
    assert_eq!(obs.other_default_route_links, Some(0));
}

#[test]
fn llmnr_actif_est_un_ecart_et_mdns_une_limite() {
    let i = intention("systemd-resolved", false, None);
    for bit in [1 << 1, 1 << 2] {
        // Sur un lien sans serveur ni domaine: LLMNR n'en a pas besoin.
        let mut o = pose(&i);
        res(&mut o).liens[0].portees |= bit;
        assert_eq!(ecarts(&i, &o), ["multicast-resolution"], "bit {bit}");
    }
    for bit in [1 << 3, 1 << 4] {
        let mut o = pose(&i);
        res(&mut o).liens[1].portees |= bit;
        let (_, _, lim, e) = comparer(&i, &o).unwrap();
        assert!(e.is_empty(), "{e:?}");
        assert_eq!(lim.mdns_links, Some(1));
    }
}

#[test]
fn le_resolveur_embarque_doit_ecouter_sous_son_compte() {
    let i = intention("systemd-resolved", true, Some(64000));
    let local = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let avec = |ecoutes: Vec<(IpAddr, u32)>| {
        let mut o = pose(&i);
        o.ecoutes
            .extend(ecoutes.into_iter().map(|(adresse, uid)| Ecoute {
                adresse,
                port: 53,
                uid,
            }));
        comparer(&i, &o).unwrap()
    };
    assert!(avec(vec![(local, 64000)]).3.is_empty());
    assert_eq!(avec(vec![]).3, ["local-resolver-listener"]);
    assert_eq!(avec(vec![(local, 0)]).3, ["local-resolver-listener"]);
    assert_eq!(
        avec(vec![(local, 64000), (local, 1000)]).3,
        ["local-resolver-listener"]
    );
    assert_eq!(
        avec(vec![(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 64000)]).3,
        ["local-resolver-listener"]
    );
    let (_, obs, _, _) = avec(vec![(local, 64000)]);
    assert_eq!(obs.local_resolver_listeners, Some(1));
    // Sans compte declare, toute ecoute exacte suffit.
    let j = intention("systemd-resolved", true, None);
    let mut o = pose(&j);
    o.ecoutes.push(Ecoute {
        adresse: local,
        port: 53,
        uid: 0,
    });
    assert!(ecarts(&j, &o).is_empty());
}

#[test]
fn les_ecarts_sont_rendus_dans_l_ordre_fixe() {
    let i = intention("systemd-resolved", true, None);
    let mut o = pose(&i);
    o.hosts.push("ldap".into());
    o.mode = Some(ModeResolvConf::Uplink);
    res(&mut o).mode = "uplink".into();
    res(&mut o).liens[0].portees |= 1 << 1;
    res(&mut o).domaines.push(domaine(I_PHY, ".", true));
    res(&mut o).domaines.push(domaine(I_PHY, "example", true));
    res(&mut o).domaines.retain(|d| d.index != I_TUN as i32);
    assert_eq!(
        ecarts(&i, &o),
        [
            "resolv-conf-path",
            "hosts-sources",
            "tunnel-link-domains",
            "dns-exceptions",
            "competing-default-routes",
            "multicast-resolution",
            "local-resolver-listener",
        ]
    );
}

// --- gardes: NON MESURE, jamais un verdict ------------------------------------

#[test]
fn un_resolved_d_un_autre_namespace_n_est_pas_mesure() {
    let i = intention("systemd-resolved", false, None);
    // Pas d'ecoute du stub ici.
    let mut o = pose(&i);
    o.ecoutes.clear();
    assert!(comparer(&i, &o).unwrap_err().starts_with("ecoute du stub"));
    // Une ecoute du stub sous un autre compte que celui de resolved.
    let mut o = pose(&i);
    o.ecoutes[0].uid = RES_UID + 1;
    assert!(comparer(&i, &o).unwrap_err().starts_with("ecoute du stub"));
    // resolved cite un lien absent d'ici.
    let mut o = pose(&i);
    res(&mut o).serveurs.push(serveur(42, IpAddr::V4(DHCP)));
    assert_eq!(
        comparer(&i, &o).unwrap_err(),
        "systemd-resolved cite un lien absent du namespace courant"
    );
    let mut o = pose(&i);
    res(&mut o).domaines.push(domaine(42, "example", true));
    assert!(comparer(&i, &o).is_err());
    let mut o = pose(&i);
    res(&mut o).domaines.push(domaine(0, "example", true));
    assert!(
        comparer(&i, &o).is_ok(),
        "la portee globale est toujours connue"
    );
    // Un autre /etc/resolv.conf que celui de ce namespace de montage.
    let mut o = pose(&i);
    res(&mut o).mode = "foreign".into();
    assert!(
        comparer(&i, &o)
            .unwrap_err()
            .contains("autre /etc/resolv.conf")
    );
    let mut o = pose(&i);
    res(&mut o).mode = String::new();
    assert!(
        comparer(&i, &o).is_err(),
        "mode vide: resolved n'a pas pu le lire"
    );
}

#[test]
fn des_delegues_dns_rendent_la_preuve_non_mesuree() {
    let i = intention("systemd-resolved", false, None);
    let mut o = pose(&i);
    res(&mut o).delegues = true;
    assert!(comparer(&i, &o).unwrap_err().starts_with("delegues DNS"));
}

#[test]
fn le_regroupement_par_portee_garde_l_ordre_de_chaque_portee() {
    let a = serveur(3, IpAddr::V4(AMONT4));
    let b = serveur(3, IpAddr::V6(AMONT6));
    let c = serveur(2, IpAddr::V4(DHCP));
    let e = EtatResolved {
        proprietaire: ":1.7".into(),
        uid: 1,
        mode: "stub".into(),
        serveurs: vec![a.clone(), c.clone(), b.clone()],
        domaines: vec![],
        delegues: false,
        liens: vec![lien(3, "b", true, 1), lien(2, "a", true, 1)],
    }
    .normaliser();
    assert_eq!(e.serveurs, [c, a, b]);
    assert_eq!(e.liens[0].index, 2);
}

// --- encadrement, rapport, entrees -------------------------------------------

struct Fichier(PathBuf);

impl Fichier {
    fn nouveau(contenu: &str) -> Self {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static N: AtomicUsize = AtomicUsize::new(0);
        let p = std::env::temp_dir().join(format!(
            "bifrost-dns-{}-{}.json",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(contenu.as_bytes()).unwrap();
        Self(p)
    }
}

impl Drop for Fichier {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// La preuve jouee avec de fausses lectures; rend le rapport et le nombre de
/// lectures demandees.
fn jouer(texte: &str, mut lectures: Vec<Result<Observation, &'static str>>) -> (Rapport, usize) {
    let f = Fichier::nouveau(texte);
    let mut n = 0;
    lectures.reverse();
    let r = verifier_avec(&f.0, true, |_| {
        n += 1;
        lectures.pop().unwrap_or(Err("lecture en trop"))
    });
    (r, n)
}

fn texte_intention() -> String {
    json_intention("systemd-resolved", false, None).to_string()
}

#[test]
fn deux_lectures_identiques_donnent_un_verdict() {
    let i = intention("systemd-resolved", false, None);
    let (r, n) = jouer(&texte_intention(), vec![Ok(pose(&i)), Ok(pose(&i))]);
    assert_eq!((r.verdict, r.code(), n), ("MATCH", 0, 2));
    assert!(r.live_system && r.collection_verified);
    assert_eq!(r.backend, Some("systemd-resolved"));
    assert_eq!(r.source, Some("resolved-dbus-and-system-files-read-twice"));
    let mut x = pose(&i);
    res(&mut x).liens[0].portees |= 1 << 1;
    let (r, _) = jouer(&texte_intention(), vec![Ok(x.clone()), Ok(x)]);
    assert_eq!((r.verdict, r.code()), ("MISMATCH", 1));
    assert_eq!(r.differences, ["multicast-resolution"]);
}

#[test]
fn deux_lectures_differentes_ne_sont_pas_mesurees() {
    let i = intention("systemd-resolved", false, None);
    let mut x = pose(&i);
    res(&mut x).proprietaire = ":1.8".into();
    let (r, n) = jouer(&texte_intention(), vec![Ok(pose(&i)), Ok(x)]);
    assert_eq!((r.verdict, r.code(), n), ("UNMEASURED", 2, 2));
    assert_eq!(r.reason, INSTABLE);
    assert_eq!(r.failed_input, Some("observed"));
    assert!(!r.collection_verified);
}

#[test]
fn une_garde_qui_ne_tient_pas_n_est_pas_mesuree() {
    let i = intention("systemd-resolved", false, None);
    let mut x = pose(&i);
    res(&mut x).delegues = true;
    let (r, _) = jouer(&texte_intention(), vec![Ok(x.clone()), Ok(x)]);
    assert_eq!((r.verdict, r.code()), ("UNMEASURED", 2));
    assert!(r.reason.starts_with("delegues DNS"));
    assert!(r.differences.is_empty());
    let (r, n) = jouer(&texte_intention(), vec![Err("bus systeme injoignable")]);
    assert_eq!(
        (r.verdict, r.reason, n),
        ("UNMEASURED", "bus systeme injoignable", 1)
    );
}

/// L'intention est lue et validee AVANT toute lecture du systeme.
#[test]
fn une_intention_illisible_n_ouvre_aucune_lecture() {
    for texte in [
        "{",
        r#"{"schema_version":1,"schema_version":1}"#,
        &json_intention("systemd-resolved", false, Some(64000)).to_string(),
    ] {
        let (r, n) = jouer(texte, vec![]);
        assert_eq!((r.verdict, n), ("UNMEASURED", 0), "{texte}");
        assert_eq!(r.failed_input, Some("intention"));
        assert_eq!(r.source, None);
    }
}

/// Le rapport ne porte ni adresse, ni domaine, ni interface, ni compte.
#[test]
fn le_rapport_ne_porte_que_des_categories_et_des_comptes() {
    let i = intention("systemd-resolved", true, Some(64000));
    let mut o = pose(&i);
    o.ecoutes.push(Ecoute {
        adresse: IpAddr::V4(Ipv4Addr::LOCALHOST),
        port: 53,
        uid: 64000,
    });
    res(&mut o)
        .domaines
        .push(domaine(I_PHY, "secret-example", true));
    let texte = json_intention("systemd-resolved", true, Some(64000)).to_string();
    let (mut r, _) = jouer(&texte, vec![Ok(o.clone()), Ok(o)]);
    assert_eq!(r.verdict, "MISMATCH");
    // Les horodatages sont des nombres quelconques: hors de la recherche.
    r.started_at_unix_ms = None;
    r.completed_at_unix_ms = None;
    r.duration_ms = 0;
    let json = serde_json::to_string(&r).unwrap();
    for interdit in [
        "192.0.2",
        "198.51.100",
        "2001:db8",
        "127.0.0",
        "secret-example",
        TUNNEL,
        "bp0",
        "64000",
        "991",
        ":1.7",
    ] {
        assert!(!json.contains(interdit), "{interdit} dans {json}");
        assert!(!r.texte().contains(interdit), "{interdit} dans le texte");
    }
    assert!(json.contains("\"network_security\":\"not-evaluated\""));
}

#[test]
fn hors_linux_la_preuve_n_est_pas_mesuree_et_ne_nomme_aucune_source() {
    let f = Fichier::nouveau(&texte_intention());
    let r = verifier_avec(&f.0, false, |_| {
        Err("collecte DNS disponible uniquement sous Linux")
    });
    assert_eq!((r.verdict, r.source), ("UNMEASURED", None));
    assert_eq!(r.backend, Some("systemd-resolved"));
    #[cfg(not(target_os = "linux"))]
    {
        let r = verifier(&f.0);
        assert_eq!((r.verdict, r.code(), r.source), ("UNMEASURED", 2, None));
        assert_eq!(r.reason, "collecte DNS disponible uniquement sous Linux");
    }
}
