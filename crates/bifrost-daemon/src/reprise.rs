//! Prevenir le superviseur qu'une veille vient de se terminer.
//!
//! Le vecteur `wfp_veille` a MESURE, le 17 aout 2026, que les filtres WFP
//! statiques survivent a une veille S3, et que le LUID d'un adaptateur
//! WireGuardNT y survit aussi. Ce module existe quand meme, et c'est voulu: la
//! mesure porte sur une machine, un pilote reseau et une duree de veille. Elle
//! ne dit rien d'une hibernation, d'un demarrage rapide, ni d'une machine dont
//! l'adaptateur physique change au reveil. WireGuardNT, de son cote, embarque
//! un fil de contournement parce que les notifications d'interface peuvent ne
//! pas se declencher lors d'un evenement PnP, et une reprise en est un.
//! Reaffirmer coute une transaction WFP idempotente; parier sur la survie coute
//! une fuite le jour ou la mesure ne vaut plus.
//!
//! # Pourquoi un objet d'evenement et un fil, et pas le canal directement
//!
//! Le rappel d'alimentation tourne dans le chemin d'alimentation du systeme et
//! ne doit ni bloquer ni durer. Y poser un `Sender` serait deja impossible tel
//! quel - `mpsc::Sender` n'est pas `Sync`, donc pas rangeable dans un `static`
//! sans verrou - et l'y forcer par un `Mutex` mettrait une prise de verrou sur
//! ce chemin. Le rappel se contente donc d'un `SetEvent`, qui est fait pour
//! cela, et un fil dedie attend cet evenement pour parler au superviseur.
//!
//! # Ce que ce module ne fait pas
//!
//! Il ne decide pas s'il faut reposer les filtres: c'est la machine a etats qui
//! le sait, et elle refuse de rien poser dans `Disconnected`. Il ne lit pas non
//! plus l'inventaire des filtres pour ne reengager qu'en cas de manque: cela
//! supposerait fiable un inventaire lu apres une reprise, ce dont on se mefie
//! precisement.

use std::sync::atomic::{AtomicIsize, Ordering};
use std::sync::mpsc::Sender;

use windows_sys::Win32::Foundation::{CloseHandle, ERROR_SUCCESS, HANDLE, WAIT_OBJECT_0};
use windows_sys::Win32::System::Power::{
    DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS, PowerRegisterSuspendResumeNotification,
    PowerUnregisterSuspendResumeNotification,
};
use windows_sys::Win32::System::Threading::{
    CreateEventW, INFINITE, SetEvent, WaitForSingleObject,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{DEVICE_NOTIFY_CALLBACK, PBT_APMRESUMEAUTOMATIC};

use crate::supervisor::Cmd;

/// L'evenement que le rappel signale. `static` parce que le rappel est une
/// fonction nue: lui passer un contexte obligerait a garantir la duree de vie
/// d'un pointeur a travers une mise en veille, ce que rien ici ne demande.
static SIGNAL: AtomicIsize = AtomicIsize::new(0);

/// Rappel appele par le systeme. Un seul appel systeme, non bloquant, rien
/// d'autre. Tout le travail a lieu dans le fil qui attend le signal.
unsafe extern "system" fn rappel_alimentation(
    _contexte: *const core::ffi::c_void,
    evenement: u32,
    _reglage: *const core::ffi::c_void,
) -> u32 {
    if evenement == PBT_APMRESUMEAUTOMATIC {
        let poignee = SIGNAL.load(Ordering::SeqCst);
        if poignee != 0 {
            // SAFETY: poignee d'evenement creee par `brancher` et fermee
            // seulement quand l'abonnement est retire, donc apres que le
            // systeme a cesse d'appeler ce rappel.
            unsafe { SetEvent(poignee as HANDLE) };
        }
    }
    ERROR_SUCCESS
}

/// Abonnement vivant. Le retirer arrete les notifications.
pub struct Abonnement {
    notification: *mut core::ffi::c_void,
    signal: HANDLE,
}

// SAFETY: les deux champs sont des poignees systeme, valables depuis n'importe
// quel fil. Rien dans cet objet n'est lie au fil qui l'a cree.
unsafe impl Send for Abonnement {}

/// Abonne le processus aux reprises et parle au superviseur a chaque reprise.
///
/// Rend l'abonnement, a garder vivant: le laisser tomber coupe les
/// notifications. En cas d'echec, le daemon doit continuer de tourner - une
/// reprise non signalee est un manque, pas une raison de refuser de connecter -
/// donc l'erreur est rendue et non paniquee.
pub fn brancher(tx: Sender<Cmd>) -> Result<Abonnement, String> {
    // SAFETY: evenement anonyme, a reinitialisation automatique, non signale.
    // Automatique et non manuel: chaque reprise doit reveiller le fil une fois
    // et une seule, sans avoir a etre remis a zero apres coup.
    let signal = unsafe { CreateEventW(std::ptr::null(), 0, 0, std::ptr::null()) };
    if signal.is_null() {
        return Err("creation de l'evenement de reprise impossible".to_owned());
    }
    SIGNAL.store(signal as isize, Ordering::SeqCst);

    let mut parametres = DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS {
        Callback: Some(rappel_alimentation),
        Context: std::ptr::null_mut(),
    };
    let mut notification: *mut core::ffi::c_void = std::ptr::null_mut();
    // SAFETY: `parametres` vit jusqu'a la fin de l'appel, que le systeme copie;
    // `notification` est un pointeur valide vers une sortie.
    let code = unsafe {
        PowerRegisterSuspendResumeNotification(
            DEVICE_NOTIFY_CALLBACK,
            (&raw mut parametres).cast(),
            &raw mut notification,
        )
    };
    if code != ERROR_SUCCESS {
        SIGNAL.store(0, Ordering::SeqCst);
        // SAFETY: poignee creee juste au-dessus, jamais partagee ailleurs
        // puisque le rappel n'est pas encore enregistre.
        unsafe { CloseHandle(signal) };
        return Err(format!(
            "PowerRegisterSuspendResumeNotification a echoue (code {code})"
        ));
    }

    let attendu = signal as isize;
    std::thread::Builder::new()
        .name("bifrost-reprise".into())
        .spawn(move || veilleur(attendu, tx))
        .map_err(|e| format!("fil de reprise impossible a lancer: {e}"))?;

    Ok(Abonnement {
        notification,
        signal,
    })
}

/// Attend les reprises et les transmet. S'arrete quand le superviseur a ferme
/// son canal, c'est-a-dire a l'arret du daemon.
fn veilleur(signal: isize, tx: Sender<Cmd>) {
    loop {
        // SAFETY: poignee d'evenement valide tant que l'abonnement vit. Si
        // l'abonnement tombe, la poignee est fermee et l'attente rend une
        // erreur, traitee comme la sortie ci-dessous.
        let issue = unsafe { WaitForSingleObject(signal as HANDLE, INFINITE) };
        if issue != WAIT_OBJECT_0 {
            tracing::debug!(issue, "fil de reprise: fin de l'attente");
            return;
        }
        if tx.send(Cmd::Reprise).is_err() {
            return;
        }
    }
}

/// Point d'entree de `--reprise-selftest`.
///
/// Endort la machine et verifie qu'une `Cmd::Reprise` arrive bien au bout du
/// chemin: rappel du systeme, `SetEvent`, fil dedie, canal du superviseur. Ce
/// chemin-la ne se deduit pas de la compilation.
///
/// **Ne touche pas au pare-feu**, contrairement a `--wfp-veille-selftest`: le
/// reseau n'est pas coupe, seule la machine s'endort. Le risque se limite donc
/// a une machine qui ne se reveille pas, ce que `Reveil::armer` verifie avant
/// d'endormir quoi que ce soit.
pub fn selftest(dormir: std::time::Duration) -> anyhow::Result<()> {
    use std::time::{Duration, SystemTime};

    eprintln!(
        "AVERTISSEMENT: cet autotest ENDORT cette machine pendant {dormir:?}. Il ne \
         coupe pas le reseau."
    );

    let (tx, rx) = std::sync::mpsc::channel::<Cmd>();
    let _abonnement = match brancher(tx) {
        Ok(a) => a,
        Err(e) => {
            println!("SKIPPED: abonnement impossible ({e}). Rien n'a ete endormi.");
            std::process::exit(3);
        }
    };

    // Arme AVANT d'endormir: si la plateforme ne sait pas se reveiller, l'appel
    // le dit ici, tant que la machine est encore joignable.
    let reveil = match crate::wfp_veille::Reveil::armer(dormir) {
        Ok(r) => r,
        Err(e) => {
            println!("SKIPPED: {e}");
            std::process::exit(3);
        }
    };

    let murale_avant = SystemTime::now();
    // SAFETY: appel sans effet de bord memoire. Ne pas hiberner, ne pas forcer,
    // ne pas desactiver les evenements de reveil.
    let demande =
        unsafe { windows_sys::Win32::System::Power::SetSuspendState(false, false, false) };
    if !demande {
        println!("SKIPPED: SetSuspendState a echoue.");
        std::process::exit(3);
    }

    // Assez large pour couvrir la veille elle-meme et une reprise lente.
    let attente = dormir + Duration::from_secs(180);
    let recu = rx.recv_timeout(attente);
    let murale = SystemTime::now()
        .duration_since(murale_avant)
        .unwrap_or_default();
    drop(reveil);

    println!("\nhorloge murale traversee : {murale:?}");

    // L'ordre des verdicts compte. Une machine qui n'a pas dormi ne peut pas
    // dire si la reprise aurait ete signalee: c'est SKIPPED, pas un echec.
    if murale < Duration::from_secs(15) {
        println!(
            "\nSKIPPED: la machine n'a pas dormi, l'horloge murale n'a avance que \
             de {murale:?}. Rien n'a pu etre mesure du chemin de reprise."
        );
        std::process::exit(3);
    }

    match recu {
        Ok(Cmd::Reprise) => {
            println!(
                "\nvecteur reprise: la reprise est arrivee jusqu'au canal du \
                 superviseur, qui reposera donc la politique au reveil"
            );
            Ok(())
        }
        // `Cmd` porte des canaux de reponse et ne s'affiche pas. Rien d'autre
        // que `Reprise` ne peut arriver ici de toute facon: ce canal n'a qu'un
        // seul emetteur, le fil de ce module.
        Ok(_) => anyhow::bail!("commande inattendue sur le canal de la recette"),
        Err(_) => anyhow::bail!(
            "la machine a dormi {murale:?} et s'est reveillee, mais aucune \
             Cmd::Reprise n'est arrivee: au reveil, la politique ne serait pas \
             reposee"
        ),
    }
}

impl Drop for Abonnement {
    fn drop(&mut self) {
        // Retirer l'abonnement AVANT de fermer l'evenement: l'inverse
        // laisserait une fenetre ou le rappel signale une poignee fermee.
        //
        // Le retrait prend un HPOWERNOTIFY, qui est un `isize`, alors que
        // l'enregistrement rend un `*mut c_void`: meme valeur, seul le type
        // declare change.
        // SAFETY: poignee rendue par l'enregistrement, retiree une seule fois.
        unsafe { PowerUnregisterSuspendResumeNotification(self.notification as isize) };
        SIGNAL.store(0, Ordering::SeqCst);
        // SAFETY: plus aucun rappel ne peut etre en cours, l'abonnement vient
        // d'etre retire. Le fil qui attend voit son attente echouer et sort.
        unsafe { CloseHandle(self.signal) };
    }
}
