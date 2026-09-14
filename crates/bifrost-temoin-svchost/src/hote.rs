//! Le versant Windows: le SCM, le registre, et la rafale tiree dans svchost.
//!
//! Rien ici ne se teste sur une autre machine, et c'est pour cela que tout ce
//! qui peut etre pur vit dans [`crate::config`].
//!
//! # La forme qu'un service heberge doit avoir
//!
//! Un service `WIN32_SHARE_PROCESS` n'appelle PAS
//! `StartServiceCtrlDispatcherW`: c'est `svchost.exe` qui l'a deja fait pour
//! son groupe. Il expose un `ServiceMain` que svchost appelle, et c'est cette
//! fonction qui doit, dans cet ordre:
//!
//! 1. lire le nom du service dans `argv[0]` - c'est le SCM qui le donne, et
//!    `RegisterServiceCtrlHandlerW` en a besoin;
//! 2. enregistrer un gestionnaire de controle;
//! 3. annoncer `SERVICE_RUNNING` par `SetServiceStatus`. Sans cette annonce le
//!    gestionnaire de services tue le processus au bout de son delai, et le
//!    temoin mourrait avant d'emettre - une absence de connexion qui se lirait
//!    comme un blocage.
//!
//! Le `dwServiceType` annonce n'est PAS code en dur: il est relu au registre,
//! sous la cle du service. Releve du 23/08/2026 sur dev-windows qui l'impose:
//! **les deux cibles qui echappent ne portent meme pas le meme type**.
//! `DiagTrack` est enregistre `0x10` `WIN32_OWN_PROCESS`, `DoSvc` est `0x20`
//! `WIN32_SHARE_PROCESS`, et les deux sont pourtant hebergees dans
//! `svchost.exe` par le meme mecanisme: un `-k <groupe>` dans l'`ImagePath` et
//! une `ServiceDll` sous `Parameters`. Le type n'est donc pas ce qui fait
//! l'hebergement, et un temoin qui annoncerait autre chose que son type
//! enregistre ajouterait une difference de plus a une mesure qui existe pour
//! en isoler une seule.
//!
//! # La rafale tourne ICI, et c'est tout l'objet de la mesure
//!
//! Elle est tiree sur le thread que svchost nous donne, dans le processus
//! `svchost.exe`. Un processus fils porterait SON jeton, pas celui du service
//! heberge, et la mesure ne dirait rien de l'hypothese qu'elle sert a
//! trancher.
//!
//! La sonde n'est pas reecrite: c'est [`bifrost_daemon::wfp_identity::rafale`],
//! celle que `--connect-probe` execute, decoupee en tranches par
//! [`crate::config::plan_de_tranches`] pour une seule raison - honorer
//! `SERVICE_CONTROL_STOP` sans attendre la fin de la fenetre. Le decoupage ne
//! change pas le resultat: `plus_permissif` est un maximum, et le maximum des
//! maximums des tranches est celui de l'ensemble.
//!
//! # Ce que le temoin ecrit, et pourquoi il l'ecrit lui-meme
//!
//! Un service n'a pas de code de sortie qu'un banc puisse lire comme celui
//! d'un processus. Le temoin depose donc son releve dans un journal: son PID,
//! l'image de son processus, sa ligne de commande - `-p` compris ou absent -
//! la configuration retenue avec la source de chaque champ, et le verdict de
//! la rafale. C'est le signal qui ne depend d'aucun journal de securite, et
//! c'est celui que le banc croise avec les evenements 5156 et 5157.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bifrost_daemon::wfp_identity::{self, Verdict};
use windows_sys::Win32::Foundation::{ERROR_SERVICE_SPECIFIC_ERROR, ERROR_SUCCESS};
use windows_sys::Win32::System::Environment::GetCommandLineW;
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD, RRF_RT_REG_SZ, RegGetValueW,
};
use windows_sys::Win32::System::Services::{
    RegisterServiceCtrlHandlerW, SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP,
    SERVICE_CONTROL_INTERROGATE, SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP, SERVICE_RUNNING,
    SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STATUS_HANDLE, SERVICE_STOP_PENDING,
    SERVICE_STOPPED, SERVICE_WIN32_OWN_PROCESS, SERVICE_WIN32_SHARE_PROCESS, SetServiceStatus,
};

use crate::config::{self, Brut};

/// Nom du journal. Le banc le supprime avant chaque passage et exige de le
/// retrouver apres: un journal survivant d'un passage precedent se lirait
/// comme le releve du passage courant.
const NOM_JOURNAL: &str = "bifrost-temoin-svchost.log";

/// Codes rendus au SCM dans `dwServiceSpecificExitCode`. Ils ne servent qu'a
/// distinguer les refus entre eux quand le journal n'a pas pu etre ecrit.
const CODE_SANS_CONFIG: u32 = 10;

/// Delai annonce au SCM pendant le demarrage.
const DELAI_DEMARRAGE_MS: u32 = 10_000;

static POIGNEE: AtomicUsize = AtomicUsize::new(0);
static ETAT_ANNONCE: AtomicU32 = AtomicU32::new(SERVICE_STOPPED);
static ARRET_DEMANDE: AtomicBool = AtomicBool::new(false);
/// Le type enregistre, relu une fois au demarrage et annonce tel quel.
static TYPE_SERVICE: AtomicU32 = AtomicU32::new(SERVICE_WIN32_SHARE_PROCESS);

// ------------------------------------------------------------ chaines larges

/// Chaine UTF-16 terminee par un zero, comme l'attend l'API Win32.
fn large(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Lit une chaine large terminee par un zero.
///
/// # Safety
///
/// `p` doit pointer sur une chaine UTF-16 valide terminee par un zero, ou etre
/// nul.
unsafe fn depuis_large(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut fin = 0usize;
    // SAFETY: l'appelant garantit la terminaison par un zero.
    while unsafe { *p.add(fin) } != 0 {
        fin += 1;
    }
    // SAFETY: les `fin` premieres unites sont lisibles, le zero final exclu.
    let unites = unsafe { std::slice::from_raw_parts(p, fin) };
    String::from_utf16_lossy(unites)
}

// ----------------------------------------------------------------- registre
//
// Une copie locale, et c'est assume. Le lecteur du daemon est `pub(crate)`,
// donc hors de portee d'ici. Ce n'est PAS la sonde: c'est de la plomberie de
// configuration, et deux plomberies qui divergeraient rendraient une valeur
// mal lue, pas deux mesures incomparables. La sonde, elle, est partagee.

/// Valeur `REG_SZ`, ou `None` si la cle ou la valeur n'existe pas.
fn lire_chaine(racine: HKEY, sous_cle: &str, valeur: &str) -> Option<String> {
    let (sc, v) = (large(sous_cle), large(valeur));
    let mut octets: u32 = 0;
    // Premier appel sans tampon: il ne fait que renseigner la taille.
    // SAFETY: les deux chaines vivent jusqu'a la fin de l'appel, et les
    // pointeurs nuls sont admis pour le type et le tampon.
    let r = unsafe {
        RegGetValueW(
            racine,
            sc.as_ptr(),
            v.as_ptr(),
            RRF_RT_REG_SZ,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut octets,
        )
    };
    if r != ERROR_SUCCESS || octets == 0 {
        return None;
    }
    let mut tampon = vec![0u8; octets as usize];
    // SAFETY: `tampon` fait exactement `octets` octets, taille que le premier
    // appel a rendue.
    let r = unsafe {
        RegGetValueW(
            racine,
            sc.as_ptr(),
            v.as_ptr(),
            RRF_RT_REG_SZ,
            std::ptr::null_mut(),
            tampon.as_mut_ptr().cast(),
            &mut octets,
        )
    };
    if r != ERROR_SUCCESS {
        return None;
    }
    tampon.truncate(octets as usize);
    let unites: Vec<u16> = tampon
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| u16::from_le_bytes(*p))
        .collect();
    // `RegGetValueW` garantit le zero final et le compte dans la taille. Le
    // garder dans la chaine ferait echouer toute comparaison, en silence.
    let utiles = unites.split(|c| *c == 0).next().unwrap_or(&[]);
    Some(String::from_utf16_lossy(utiles))
}

/// Valeur `REG_DWORD`, ou `None` si la cle ou la valeur n'existe pas.
fn lire_dword(racine: HKEY, sous_cle: &str, valeur: &str) -> Option<u32> {
    let (sc, v) = (large(sous_cle), large(valeur));
    let mut donnee: u32 = 0;
    let mut octets: u32 = std::mem::size_of::<u32>() as u32;
    // SAFETY: `donnee` fait bien `octets` octets et vit jusqu'a la fin de
    // l'appel, comme les deux chaines.
    let r = unsafe {
        RegGetValueW(
            racine,
            sc.as_ptr(),
            v.as_ptr(),
            RRF_RT_REG_DWORD,
            std::ptr::null_mut(),
            std::ptr::from_mut(&mut donnee).cast(),
            &mut octets,
        )
    };
    (r == ERROR_SUCCESS).then_some(donnee)
}

fn cle_parametres(nom: &str) -> String {
    format!("SYSTEM\\CurrentControlSet\\Services\\{nom}\\Parameters")
}

// ------------------------------------------------------------------ journal

/// Ou le temoin depose son releve.
///
/// `Parameters\Journal` quand le banc en designe un, et c'est le cas normal:
/// le banc doit savoir ou lire. Le repli existe pour le seul chemin ou le nom
/// du service n'a pas pu etre obtenu, donc ou aucune cle ne peut etre lue.
fn chemin_journal(nom: &str) -> PathBuf {
    if !nom.is_empty()
        && let Some(designe) = lire_chaine(HKEY_LOCAL_MACHINE, &cle_parametres(nom), "Journal")
        && !designe.trim().is_empty()
    {
        return PathBuf::from(designe.trim());
    }
    std::env::temp_dir().join(NOM_JOURNAL)
}

/// Ajoute une ligne au journal. Une ecriture qui echoue ne se rattrape pas:
/// il n'existe aucun autre endroit ou le dire depuis un service.
fn noter(chemin: &Path, ligne: &str) {
    let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(chemin)
    else {
        return;
    };
    let _ = writeln!(f, "{ligne}");
}

fn horodatage() -> String {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => format!("t={}ms", d.as_millis()),
        Err(_) => "t=(horloge avant 1970)".to_owned(),
    }
}

// ------------------------------------------------------------- etat de service

/// Le type de service ANNONCE au SCM, lu la ou il est ecrit.
///
/// Ni devine ni code en dur, et le releve du 23/08/2026 sur dev-windows dit
/// pourquoi: **les deux cibles qui echappent ne portent meme pas le meme
/// type**. `DiagTrack` est `0x10` `WIN32_OWN_PROCESS` et `DoSvc` est `0x20`
/// `WIN32_SHARE_PROCESS`, alors que les deux sont hebergees dans `svchost.exe`
/// par le meme mecanisme - une `ServiceDll` et un `-k <groupe>` dans
/// l'`ImagePath`. Le type n'est donc pas ce qui fait l'hebergement, et un
/// temoin qui annoncerait un type different de celui sous lequel le SCM l'a
/// enregistre ajouterait une difference de plus a une mesure qui existe pour
/// en isoler une seule.
fn type_annonce(nom: &str) -> u32 {
    match lire_dword(
        HKEY_LOCAL_MACHINE,
        &format!("SYSTEM\\CurrentControlSet\\Services\\{nom}"),
        "Type",
    ) {
        Some(t) if t == SERVICE_WIN32_SHARE_PROCESS || t == SERVICE_WIN32_OWN_PROCESS => t,
        _ => SERVICE_WIN32_SHARE_PROCESS,
    }
}

fn annoncer(etat: u32, code_win32: u32, code_specifique: u32) {
    let poignee = POIGNEE.load(Ordering::Relaxed);
    if poignee == 0 {
        return;
    }
    ETAT_ANNONCE.store(etat, Ordering::Relaxed);
    let statut = SERVICE_STATUS {
        // Le type sous lequel le service est ENREGISTRE, relu au registre. En
        // annoncer un autre serait annoncer autre chose que ce qu'on est.
        dwServiceType: TYPE_SERVICE.load(Ordering::Relaxed),
        dwCurrentState: etat,
        dwControlsAccepted: if etat == SERVICE_RUNNING {
            SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
        } else {
            0
        },
        dwWin32ExitCode: code_win32,
        dwServiceSpecificExitCode: code_specifique,
        dwCheckPoint: u32::from(etat == SERVICE_START_PENDING || etat == SERVICE_STOP_PENDING),
        dwWaitHint: if etat == SERVICE_RUNNING {
            0
        } else {
            DELAI_DEMARRAGE_MS
        },
    };
    // SAFETY: la poignee vient d'un RegisterServiceCtrlHandlerW reussi, et
    // `statut` vit jusqu'a la fin de l'appel.
    unsafe { SetServiceStatus(poignee as SERVICE_STATUS_HANDLE, &statut) };
}

/// Le gestionnaire de controle. Il doit rendre la main tout de suite: il
/// signale, il n'attend pas.
///
/// # Safety
///
/// Appele par le SCM sur un thread qu'on ne choisit pas. Le corps ne
/// dereference rien.
unsafe extern "system" fn gestionnaire(controle: u32) {
    match controle {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
            annoncer(SERVICE_STOP_PENDING, 0, 0);
            ARRET_DEMANDE.store(true, Ordering::Relaxed);
        }
        SERVICE_CONTROL_INTERROGATE => {
            annoncer(ETAT_ANNONCE.load(Ordering::Relaxed), 0, 0);
        }
        _ => {}
    }
}

// --------------------------------------------------------------- la rafale

/// Tire la rafale par tranches et rend la plus permissive.
///
/// `None` quand AUCUNE tranche n'a pu etre tiree. Ce n'est pas la meme chose
/// qu'un blocage, et les confondre fabriquerait un refus: `rafale` part de
/// `Verdict::Bloque` et le rend tel quel quand sa fenetre est trop courte pour
/// une seule tentative.
fn tirer(cible: std::net::SocketAddr, total_ms: u64) -> Option<Verdict> {
    let plan = config::plan_de_tranches(total_ms, config::TRANCHE_MS);
    let mut verdict: Option<Verdict> = None;
    for tranche_ms in plan {
        if ARRET_DEMANDE.load(Ordering::Relaxed) {
            break;
        }
        let issue = wfp_identity::rafale(cible, Duration::from_millis(tranche_ms));
        verdict = Some(match verdict {
            None => issue,
            Some(deja) => wfp_identity::plus_permissif(deja, issue),
        });
    }
    verdict
}

// ---------------------------------------------------------------- ServiceMain

/// Le point d'entree que `svchost.exe` appelle.
///
/// Exporte sous le nom exact `ServiceMain`, celui que svchost cherche par
/// defaut dans une `ServiceDll`. Le nom Rust reste en minuscules pour ne pas
/// avoir a desactiver une regle de style sur un export.
///
/// # Safety
///
/// Appelee par svchost avec `argv` pointant sur un tableau de `argc` chaines
/// larges terminees par un zero, dont la premiere est le nom du service.
#[unsafe(export_name = "ServiceMain")]
pub unsafe extern "system" fn service_main(argc: u32, argv: *mut *mut u16) {
    let nom = if argc == 0 || argv.is_null() {
        String::new()
    } else {
        // SAFETY: svchost garantit `argc` entrees valides quand `argv` n'est
        // pas nul, et la premiere est le nom du service.
        unsafe { depuis_large(*argv) }
    };

    // Les statiques sont remises a zero A CHAQUE demarrage, et ce n'est pas
    // une precaution de style. Le banc demarre le temoin TROIS fois. Si le
    // processus svchost survivait entre deux passages - il n'a aucune raison de
    // le faire quand le temoin est seul dedans, mais rien ne le garantit - le
    // deuxieme `ServiceMain` verrait l'arret demande au premier et sortirait de
    // la rafale sans faire une seule tentative. Le journal dirait NON MESURE,
    // ce qui est deja mieux qu'un faux blocage, mais le passage serait perdu.
    ARRET_DEMANDE.store(false, Ordering::Relaxed);
    POIGNEE.store(0, Ordering::Relaxed);

    // Le journal AVANT le gestionnaire: si l'enregistrement echoue, c'est la
    // seule trace qui restera.
    let journal = chemin_journal(&nom);
    noter(
        &journal,
        &format!("---- {} nom={:?} ----", horodatage(), nom),
    );
    entete(&journal, &nom);

    if nom.is_empty() {
        noter(
            &journal,
            "ECHEC: svchost n'a pas passe de nom de service en argv[0]. Sans lui, RegisterServiceCtrlHandlerW n'a rien a enregistrer.",
        );
        return;
    }

    // Le type AVANT la premiere annonce: c'est lui qu'on annoncera.
    TYPE_SERVICE.store(type_annonce(&nom), Ordering::Relaxed);
    noter(
        &journal,
        &format!(
            "type       : 0x{:X} annonce au SCM  (relu au registre, non devine)",
            TYPE_SERVICE.load(Ordering::Relaxed)
        ),
    );

    let large_nom = large(&nom);
    // SAFETY: `large_nom` est une chaine large NUL-terminee vivante jusqu'a la
    // fin de l'appel; `gestionnaire` est un pointeur de fonction valide.
    let poignee = unsafe { RegisterServiceCtrlHandlerW(large_nom.as_ptr(), Some(gestionnaire)) };
    if poignee.is_null() {
        noter(
            &journal,
            "ECHEC: RegisterServiceCtrlHandlerW a rendu une poignee nulle. Le service ne peut ni s'annoncer ni etre arrete proprement.",
        );
        return;
    }
    POIGNEE.store(poignee as usize, Ordering::Relaxed);
    annoncer(SERVICE_START_PENDING, 0, 0);

    let brut = Brut {
        cible: lire_chaine(HKEY_LOCAL_MACHINE, &cle_parametres(&nom), "Cible"),
        rafale_ms: lire_dword(HKEY_LOCAL_MACHINE, &cle_parametres(&nom), "RafaleMs"),
    };
    let config = match config::depuis(&brut) {
        Ok(c) => c,
        Err(raison) => {
            noter(&journal, &format!("ECHEC de configuration: {raison}"));
            noter(
                &journal,
                &format!("verdict    : {}", config::ligne_verdict(None)),
            );
            annoncer(
                SERVICE_STOPPED,
                ERROR_SERVICE_SPECIFIC_ERROR,
                CODE_SANS_CONFIG,
            );
            return;
        }
    };
    for ligne in config.en_clair().lines() {
        noter(&journal, ligne);
    }

    // RUNNING avant la rafale: le SCM tuerait un service qui met huit secondes
    // a s'annoncer, et le temoin mourrait avant d'emettre.
    annoncer(SERVICE_RUNNING, 0, 0);
    noter(&journal, &format!("{} rafale: depart", horodatage()));

    // La rafale sous filet, et il y a une raison precise. `ServiceMain` est une
    // fonction `extern "system"`: une panique qui la traverserait ne
    // deroulerait pas, elle ABORTERAIT - et le processus qu'elle tuerait est un
    // `svchost.exe`. Un temoin de mesure n'a pas le droit d'emporter avec lui
    // le processus qu'on l'a charge d'observer. Ici la panique devient `None`,
    // c'est-a-dire NON MESURE, ce qui est exactement ce qu'elle est.
    let verdict = match std::panic::catch_unwind(|| tirer(config.cible, config.rafale_ms)) {
        Ok(v) => v,
        Err(_) => {
            noter(
                &journal,
                "ECHEC: la rafale a panique. Aucune mesure n'a eu lieu, et le processus hote a ete preserve.",
            );
            None
        }
    };
    let code = verdict.map(Verdict::code);
    noter(
        &journal,
        &format!(
            "{} arret demande pendant la rafale: {}",
            horodatage(),
            ARRET_DEMANDE.load(Ordering::Relaxed)
        ),
    );
    noter(
        &journal,
        &format!("verdict    : {}", config::ligne_verdict(code)),
    );
    noter(&journal, "---- fin ----");

    annoncer(SERVICE_STOPPED, 0, 0);
}

/// Ce que le temoin releve sur LUI-MEME, avant toute mesure.
///
/// La ligne de commande est la piece decisive: c'est elle qui porte `-k
/// <groupe>` et, sur les VRAIES cibles, le drapeau `-p`. Ce temoin ne peut pas
/// tourner avec `-p` - la politique d'attenuation qu'il active n'accepte que
/// des images signees par Microsoft, et cette DLL ne l'est pas. La limite est
/// donc RELEVEE ici plutot qu'affirmee dans un rapport.
fn entete(journal: &Path, nom: &str) {
    let image = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|e| format!("(illisible: {e})"));
    // SAFETY: `GetCommandLineW` rend un pointeur sur une chaine large du
    // processus, valide pour toute sa duree de vie.
    let ligne = unsafe { depuis_large(GetCommandLineW()) };
    let avec_p = ligne
        .split_whitespace()
        .any(|mot| mot.eq_ignore_ascii_case("-p"));
    noter(journal, &format!("pid        : {}", std::process::id()));
    noter(journal, &format!("image      : {image}"));
    noter(journal, &format!("ligne      : {ligne}"));
    noter(
        journal,
        &format!(
            "drapeau -p : {}  (ce temoin ne peut pas tourner avec -p: sa DLL n'est pas signee par Microsoft)",
            if avec_p { "PRESENT" } else { "absent" }
        ),
    );
    if !nom.is_empty() {
        let dll = lire_chaine(HKEY_LOCAL_MACHINE, &cle_parametres(nom), "ServiceDll")
            .unwrap_or_else(|| "(aucune valeur ServiceDll lisible)".to_owned());
        noter(journal, &format!("ServiceDll : {dll}"));
    }
}
