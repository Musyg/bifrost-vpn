//! Appels au gestionnaire de controle des services, et boucle de service.
//!
//! Le SCM impose une forme: le processus appelle `StartServiceCtrlDispatcherW`,
//! qui bloque et rappelle [`service_main`] sur un AUTRE thread. Ce thread doit
//! annoncer son etat au SCM sans trainer, sous peine de voir le service declare
//! en echec de demarrage, puis executer le travail reel.
//!
//! # L'arret demande ne desarme pas
//!
//! L'arret demande par le SCM n'a pas le droit de desarmer le kill switch. Le
//! service s'arrete, les filtres restent, et leur retrait passe par
//! `--cleanup-firewall`. Sans ca, arreter le service serait un moyen trivial
//! de lever la protection, y compris pour un logiciel malveillant qui sait
//! appeler `ControlService`. C'est ce que garde
//! `spec::tests::l_arret_du_service_ne_rouvre_pas_le_trafic`.
//!
//! Ce paragraphe revendiquait "la meme regle que `ExecStopPost` cote systemd".
//! La parite etait FAUSSE, et dans le mauvais sens: l'unite portait
//! `ExecStopPost=-/usr/bin/bifrost-daemon --cleanup-firewall`, qui s'execute
//! sur TOUS les chemins d'arret, fin inattendue comprise. Chaque plantage du
//! daemon demontait donc le pare-feu, cote Linux. Trouve le 22 aout 2026,
//! corrige a part.
//!
//! # La MORT du processus, qui est une autre question
//!
//! L'arret demande n'est pas le seul chemin, et la phrase ci-dessus n'a jamais
//! rien dit de l'autre: les filtres survivent-ils au processus qui les a
//! poses? Une fois la transaction fermee, plus rien de notre code ne les
//! tient; c'est le MOTEUR qui les detient, et WFP detruit automatiquement les
//! objets d'une session DYNAMIQUE des qu'elle se ferme, donc des que le
//! processus disparait. `Engine::open`, dans `bifrost-firewall`, ouvre une
//! session NON dynamique precisement pour cela.
//!
//! Mesure du 23 aout 2026 sur essai-windows, sous elevation, par
//! `--wfp-selftest`, qui pose le meme jeu d'objets avec tous les blocages
//! convertis en autorisations et ne coupe donc rien: temoin a 0 filtre;
//! armement; processus tue PAR PID pendant l'armement, son journal s'arretant
//! a "armement..." sans jamais contenir "desarmement...", ce qui etablit qu'il
//! n'a pas eu le temps de defaire son travail; puis un processus NEUF
//! interroge `netsh wfp show filters`, qui rend 22 filtres Bifrost toujours
//! en place. Ils ne partent qu'au `--cleanup-firewall` suivant, qui en retire
//! 22 et ramene le temoin a 0.
//!
//! Donc sous Windows, un daemon qui meurt ne rouvre pas le trafic. Ce n'est
//! pas notre code qui le rattrape apres coup, c'est la duree de vie des objets
//! du moteur.
//!
//! # Ce qui reste NON mesure
//!
//! Les filtres du kill switch ne portent ni `FWPM_FILTER_FLAG_PERSISTENT` ni
//! `FWPM_FILTER_FLAG_BOOTTIME`, voir `Cible::kill_switch`: ils ne survivent
//! donc PAS a un redemarrage, et c'est le filtre de demarrage, dans ses
//! propres objets persistants, qui couvre cette fenetre-la. La continuite
//! entre les deux jeux au fil d'un redemarrage n'est pas mesuree.
//!
//! Le cycle de redemarrage apres echec ne l'est pas non plus. Ce qui est
//! etabli par LECTURE seulement: `spec()` demande trois `SC_ACTION_RESTART`
//! espaces de `DELAI_REDEMARRAGE_MS`, et `WfpKillSwitch::install` commence par
//! purger puis repose tout DANS UNE TRANSACTION. Les filtres restant poses
//! entre-temps, rien ne devrait se rouvrir pendant le delai. Reste a le
//! mesurer, en tuant le service et en interrogeant le moteur pendant les cinq
//! secondes qui suivent.

use std::path::Path;
use std::sync::{Mutex, OnceLock};

use anyhow::{Context, anyhow, bail};
use tokio::sync::watch;
use windows_sys::Win32::Foundation::{
    ERROR_SERVICE_DOES_NOT_EXIST, ERROR_SERVICE_EXISTS, GetLastError,
};
use windows_sys::Win32::System::Services::{
    ChangeServiceConfig2W, CloseServiceHandle, CreateServiceW, DeleteService, OpenSCManagerW,
    OpenServiceW, QueryServiceConfig2W, RegisterServiceCtrlHandlerExW, SC_ACTION,
    SC_ACTION_RESTART, SC_HANDLE, SC_MANAGER_CONNECT, SC_MANAGER_CREATE_SERVICE,
    SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP, SERVICE_ALL_ACCESS, SERVICE_AUTO_START,
    SERVICE_CONFIG_DESCRIPTION, SERVICE_CONFIG_FAILURE_ACTIONS, SERVICE_CONFIG_SERVICE_SID_INFO,
    SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP, SERVICE_DEMAND_START, SERVICE_DESCRIPTIONW,
    SERVICE_DISABLED, SERVICE_ERROR_NORMAL, SERVICE_FAILURE_ACTIONSW, SERVICE_QUERY_CONFIG,
    SERVICE_RUNNING, SERVICE_SID_INFO, SERVICE_SID_TYPE_UNRESTRICTED, SERVICE_START_PENDING,
    SERVICE_STATUS, SERVICE_STATUS_HANDLE, SERVICE_STOP_PENDING, SERVICE_STOPPED,
    SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS, SetServiceStatus, StartServiceCtrlDispatcherW,
};

use super::spec::{Demarrage, ServiceSpec, spec};

/// Delai annonce au SCM pendant le demarrage. Trop court, le SCM declare le
/// service en echec; trop long, un vrai blocage passe pour une lenteur.
const DELAI_DEMARRAGE_MS: u32 = 15_000;
/// Delai avant un redemarrage apres echec.
const DELAI_REDEMARRAGE_MS: u32 = 5_000;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn derniere_erreur(quoi: &str) -> anyhow::Error {
    // SAFETY: GetLastError ne lit que l'etat du thread courant.
    let code = unsafe { GetLastError() };
    anyhow!("{quoi} a echoue (code systeme {code})")
}

/// Poignee SCM refermee a la liberation. Une poignee fuitee garde une
/// reference sur la base du SCM et empeche la suppression du service.
struct Poignee(SC_HANDLE);

impl Drop for Poignee {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: la poignee vient d'un Open/Create reussi et n'est
            // refermee qu'une fois.
            unsafe { CloseServiceHandle(self.0) };
        }
    }
}

fn ouvrir_scm(acces: u32) -> anyhow::Result<Poignee> {
    // SAFETY: les deux premiers arguments nuls designent la machine locale et
    // la base active, ce que documente OpenSCManagerW.
    let h = unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), acces) };
    if h.is_null() {
        return Err(derniere_erreur("OpenSCManagerW")).context(
            "ouverture du gestionnaire de services: cette commande demande les \
             privileges administrateur",
        );
    }
    Ok(Poignee(h))
}

fn code_demarrage(d: Demarrage) -> u32 {
    match d {
        Demarrage::Automatique => SERVICE_AUTO_START,
        Demarrage::Manuel => SERVICE_DEMAND_START,
        Demarrage::Desactive => SERVICE_DISABLED,
    }
}

/// Enregistre le service aupres du SCM.
///
/// `exe` doit etre le chemin ABSOLU du binaire: le SCM ne resout pas les
/// chemins relatifs, et un chemin relatif produit un service qui se cree sans
/// broncher puis echoue a chaque demarrage.
///
/// `avec_sonde` installe un service de DIAGNOSTIC: au lieu de servir, il pose
/// la sonde d'identite, journalise ses trois mesures et s'arrete. C'est le seul
/// moyen d'observer le filtre au SID de service a l'oeuvre, ce SID n'existant
/// dans le token que sous le gestionnaire de services.
///
/// `resolveur` est le chemin du resolveur chiffre embarque, quand
/// l'installation en depose un. Meme exigence de chemin absolu, et pour la
/// meme raison: le service tourne avec un repertoire courant qui n'est pas
/// celui de l'installation.
///
/// `compte` (11b-2) est le compte de service sous lequel le daemon lancera le
/// resolveur. Il est resolu ICI, a l'installation, et non au premier demarrage
/// du service, loin de sa cause: un nom que `LookupAccountNameW` et la table
/// des comptes bien connus ignorent fait echouer l'installation. Un compte
/// sans binaire est refuse aussi: il n'a de sens que si le service lance un
/// resolveur (l'equivalent d'un `requires`, tenu ici parce que
/// `--resolveur-utilisateur` reste legitime SANS binaire hors installation,
/// pour restreindre le :53 a un resolveur que quelqu'un d'autre pilote).
pub fn install(
    exe: &Path,
    avec_sonde: bool,
    resolveur: Option<&Path>,
    compte: Option<&str>,
) -> anyhow::Result<()> {
    let s = spec();
    if !exe.is_absolute() {
        bail!(
            "chemin du binaire non absolu ({}): le SCM ne le resoudrait pas",
            exe.display()
        );
    }
    if !exe.exists() {
        bail!("binaire introuvable: {}", exe.display());
    }

    let scm = ouvrir_scm(SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE)?;

    if let Some(r) = resolveur {
        if !r.is_absolute() {
            bail!(
                "chemin du resolveur non absolu ({}): le service ne le \
                 resoudrait pas, son repertoire courant n'etant pas celui de \
                 l'installation",
                r.display()
            );
        }
        if !r.exists() {
            bail!(
                "resolveur introuvable: {}. L'installer d'abord, ou ne pas le \
                 declarer: un service qui nomme un binaire absent refuse de \
                 demarrer.",
                r.display()
            );
        }
    }

    // 11b-2: fail-closed a l'installation. Sur le modele de "resolveur
    // introuvable: l'installer d'abord" juste au-dessus.
    if let Some(c) = compte {
        if resolveur.is_none() {
            bail!(
                "--resolveur-utilisateur {c:?} sans --resolveur-binaire: un compte \
                 pour le resolveur n'a de sens que si le service en lance un. \
                 Declarer les deux, ou aucun."
            );
        }
        if let Err(e) = crate::coeurs::identite::resoudre_sid_compte(c) {
            bail!(
                "compte du resolveur {c:?} introuvable: {e}. Le service ne pourrait \
                 pas lancer le resolveur sous ce compte; la forme recommandee est \
                 LocalService (NT AUTHORITY\\LocalService, S-1-5-19)."
            );
        }
    }

    // La ligne vient de `spec`, ou elle est une fonction pure mesuree sur les
    // deux hotes. La construire ici la rendrait invisible a la CI Linux.
    let ligne = super::spec::ligne_de_commande(exe, avec_sonde, resolveur, compte);

    let nom = wide(s.nom);
    let affiche = wide(s.nom_affiche);
    let ligne_w = wide(&ligne);
    let mut deps = super::spec::dependances_encodees(s.dependances);
    let deps_ptr = deps
        .as_mut()
        .map(|v| v.as_ptr())
        .unwrap_or(std::ptr::null());

    // SAFETY: tous les tampons vivent jusqu'a la fin de l'appel. Le compte nul
    // vaut LocalSystem, et le mot de passe nul va avec.
    let service = unsafe {
        CreateServiceW(
            scm.0,
            nom.as_ptr(),
            affiche.as_ptr(),
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            code_demarrage(s.demarrage),
            SERVICE_ERROR_NORMAL,
            ligne_w.as_ptr(),
            std::ptr::null(),
            std::ptr::null_mut(),
            deps_ptr,
            std::ptr::null(),
            std::ptr::null(),
        )
    };
    if service.is_null() {
        // SAFETY: lecture de l'etat du thread courant.
        let code = unsafe { GetLastError() };
        if code == ERROR_SERVICE_EXISTS {
            bail!(
                "le service {} existe deja. Le retirer d'abord avec \
                 --uninstall-service.",
                s.nom
            );
        }
        return Err(derniere_erreur("CreateServiceW"));
    }
    let service = Poignee(service);

    decrire(&service, &s)?;
    actions_sur_echec(&service, &s)?;
    type_de_sid(&service, &s)?;

    println!("service {} installe ({})", s.nom, ligne);
    Ok(())
}

fn decrire(service: &Poignee, s: &ServiceSpec) -> anyhow::Result<()> {
    let mut description = wide(s.description);
    let info = SERVICE_DESCRIPTIONW {
        lpDescription: description.as_mut_ptr(),
    };
    // SAFETY: `info` et le tampon qu'il pointe vivent jusqu'a la fin de
    // l'appel, et le niveau annonce correspond au type passe.
    let ok = unsafe {
        ChangeServiceConfig2W(
            service.0,
            SERVICE_CONFIG_DESCRIPTION,
            std::ptr::from_ref(&info).cast(),
        )
    };
    if ok == 0 {
        return Err(derniere_erreur("ChangeServiceConfig2W (description)"));
    }
    Ok(())
}

/// Pendant Windows de `Restart=on-failure`.
fn actions_sur_echec(service: &Poignee, s: &ServiceSpec) -> anyhow::Result<()> {
    if s.redemarrages_sur_echec == 0 {
        return Ok(());
    }
    let mut actions: Vec<SC_ACTION> = (0..s.redemarrages_sur_echec)
        .map(|_| SC_ACTION {
            Type: SC_ACTION_RESTART,
            Delay: DELAI_REDEMARRAGE_MS,
        })
        .collect();
    let info = SERVICE_FAILURE_ACTIONSW {
        // Compteur d'echecs remis a zero apres une journee sans incident.
        dwResetPeriod: 86_400,
        lpRebootMsg: std::ptr::null_mut(),
        lpCommand: std::ptr::null_mut(),
        cActions: actions.len() as u32,
        lpsaActions: actions.as_mut_ptr(),
    };
    // SAFETY: `actions` vit jusqu'a la fin de l'appel, et `cActions` decrit
    // exactement sa longueur.
    let ok = unsafe {
        ChangeServiceConfig2W(
            service.0,
            SERVICE_CONFIG_FAILURE_ACTIONS,
            std::ptr::from_ref(&info).cast(),
        )
    };
    if ok == 0 {
        return Err(derniere_erreur("ChangeServiceConfig2W (actions sur echec)"));
    }
    Ok(())
}

/// Fait porter au token du service le SID du service.
///
/// Sans cet appel, Windows n'y met rien: mesure le 16 aout 2026, le daemon
/// installe sans ca annoncait `sid=S-1-5-18 sid_de_service=false`, donc une
/// identite partagee par tous les services de la machine. C'est ce reglage qui
/// donne son sens a la condition `ALE_USER_ID`, et sans lui le passage en
/// service AFFAIBLIT la garantie au lieu de la renforcer.
fn type_de_sid(service: &Poignee, s: &ServiceSpec) -> anyhow::Result<()> {
    if !s.sid_de_service {
        return Ok(());
    }
    let info = SERVICE_SID_INFO {
        dwServiceSidType: SERVICE_SID_TYPE_UNRESTRICTED,
    };
    // SAFETY: `info` vit jusqu'a la fin de l'appel et correspond au niveau
    // annonce.
    let ok = unsafe {
        ChangeServiceConfig2W(
            service.0,
            SERVICE_CONFIG_SERVICE_SID_INFO,
            std::ptr::from_ref(&info).cast(),
        )
    };
    if ok == 0 {
        return Err(derniere_erreur("ChangeServiceConfig2W (type de SID)"));
    }
    Ok(())
}

/// Retire le service du SCM.
///
/// Ne touche pas aux filtres: si le kill switch est arme, il le reste. C'est
/// voulu, et `--cleanup-firewall` est la commande qui les retire.
/// Le type de SID configure pour un service QUELCONQUE de la machine.
///
/// `None` si le service n'existe pas. Sinon `SERVICE_SID_TYPE_NONE` (0),
/// `SERVICE_SID_TYPE_UNRESTRICTED` (1) ou `SERVICE_SID_TYPE_RESTRICTED` (3).
///
/// Le pendant en LECTURE de [`type_de_sid`], qui ecrit ce reglage sur notre
/// propre service. Ici on interroge les services d'en face, et la reponse
/// decide si un filtre WFP conditionne sur leur SID peut mordre: un service en
/// `NONE` ne porte aucun SID de service dans son jeton, et la condition
/// `ALE_USER_ID` ne correspondrait jamais - sans erreur, avec un filtre bien
/// present dans le moteur, et sans rien bloquer.
///
/// Ne demande que `SC_MANAGER_CONNECT` et `SERVICE_QUERY_CONFIG`: lire l'etat
/// des lieux ne doit pas exiger l'elevation.
pub fn type_de_sid_du_service(nom: &str) -> anyhow::Result<Option<u32>> {
    let scm = ouvrir_scm(SC_MANAGER_CONNECT)?;
    let n = wide(nom);
    // SAFETY: `scm` est une poignee vivante et `n` une chaine terminee par zero.
    let service = unsafe { OpenServiceW(scm.0, n.as_ptr(), SERVICE_QUERY_CONFIG) };
    if service.is_null() {
        // SAFETY: GetLastError ne lit que l'etat du thread courant.
        if unsafe { GetLastError() } == ERROR_SERVICE_DOES_NOT_EXIST {
            return Ok(None);
        }
        return Err(derniere_erreur("OpenServiceW"))
            .context(format!("lecture du type de SID du service {nom}"));
    }
    let service = Poignee(service);

    let mut tampon = vec![0u8; std::mem::size_of::<SERVICE_SID_INFO>()];
    let mut taille = 0u32;
    // SAFETY: le tampon fait au moins la taille de SERVICE_SID_INFO, seule
    // structure que SERVICE_CONFIG_SERVICE_SID_INFO peut y ecrire.
    let ok = unsafe {
        QueryServiceConfig2W(
            service.0,
            SERVICE_CONFIG_SERVICE_SID_INFO,
            tampon.as_mut_ptr(),
            tampon.len() as u32,
            &mut taille,
        )
    };
    if ok == 0 {
        return Err(derniere_erreur("QueryServiceConfig2W (type de SID)"));
    }
    // SAFETY: l'appel a reussi, donc le tampon porte un SERVICE_SID_INFO valide.
    let info = unsafe { *(tampon.as_ptr() as *const SERVICE_SID_INFO) };
    Ok(Some(info.dwServiceSidType))
}

pub fn uninstall() -> anyhow::Result<()> {
    let s = spec();
    let scm = ouvrir_scm(SC_MANAGER_CONNECT)?;
    let nom = wide(s.nom);
    // SAFETY: `nom` vit jusqu'a la fin de l'appel. `SERVICE_ALL_ACCESS`
    // (0xF01FF) contient le droit DELETE (0x10000) qu'exige DeleteService; la
    // constante DELETE elle-meme vit dans le module Storage::FileSystem de
    // windows-sys, qu'on ne va pas tirer pour un seul entier.
    let service = unsafe { OpenServiceW(scm.0, nom.as_ptr(), SERVICE_ALL_ACCESS) };
    if service.is_null() {
        return Err(derniere_erreur("OpenServiceW")).context(format!(
            "le service {} n'a pas pu etre ouvert; est-il installe?",
            s.nom
        ));
    }
    let service = Poignee(service);
    // SAFETY: la poignee vient d'un OpenServiceW reussi avec le droit DELETE.
    if unsafe { DeleteService(service.0) } == 0 {
        return Err(derniere_erreur("DeleteService"));
    }
    println!(
        "service {} retire. Les filtres eventuellement poses SUBSISTENT: \
         lancer --cleanup-firewall pour les enlever.",
        s.nom
    );
    Ok(())
}

// --- Boucle de service ---

/// Le travail reel, depose avant de rendre la main au SCM.
///
/// `service_main` est appelee par le SCM sur un thread qu'on ne choisit pas et
/// sans argument utilisable: il faut donc passer par un point de depot.
type Corps = Box<dyn FnOnce() -> anyhow::Result<()> + Send>;
static CORPS: Mutex<Option<Corps>> = Mutex::new(None);

/// Canal d'arret. Un `watch` plutot qu'un `Notify`: il RETIENT l'etat, donc un
/// arret demande avant que quiconque attende n'est pas perdu.
fn canal() -> &'static (watch::Sender<bool>, watch::Receiver<bool>) {
    static C: OnceLock<(watch::Sender<bool>, watch::Receiver<bool>)> = OnceLock::new();
    C.get_or_init(|| watch::channel(false))
}

/// Resolue quand le SCM demande l'arret.
pub async fn attendre_arret() {
    let mut rx = canal().1.clone();
    while !*rx.borrow_and_update() {
        if rx.changed().await.is_err() {
            return;
        }
    }
}

/// Rend la main au SCM, qui rappellera [`service_main`].
///
/// Echoue si le processus n'a pas ete lance PAR le SCM, ce qui est le cas
/// quand quelqu'un tape `--service` a la main dans un terminal.
pub fn run_as_service(corps: Corps) -> anyhow::Result<()> {
    *CORPS.lock().expect("verrou du corps de service") = Some(corps);

    let mut nom = wide(spec().nom);
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: nom.as_mut_ptr(),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW {
            lpServiceName: std::ptr::null_mut(),
            lpServiceProc: None,
        },
    ];
    // SAFETY: la table est terminee par une entree nulle, comme exige, et vit
    // jusqu'au retour de l'appel qui bloque.
    if unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } == 0 {
        return Err(derniere_erreur("StartServiceCtrlDispatcherW")).context(
            "ce mode est reserve au gestionnaire de services. Pour un essai en \
             console, lancer le daemon sans --service.",
        );
    }
    Ok(())
}

static POIGNEE_STATUT: OnceLock<usize> = OnceLock::new();

fn annoncer(etat: u32, attente_ms: u32, code_sortie: u32) {
    let Some(h) = POIGNEE_STATUT.get().copied() else {
        return;
    };
    let statut = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: etat,
        // Un service qui n'accepte pas STOP est un service qu'on ne peut
        // arreter qu'en tuant le processus.
        dwControlsAccepted: if etat == SERVICE_RUNNING {
            SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
        } else {
            0
        },
        dwWin32ExitCode: code_sortie,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: 0,
        dwWaitHint: attente_ms,
    };
    // SAFETY: la poignee vient d'un RegisterServiceCtrlHandlerExW reussi, et
    // `statut` vit jusqu'a la fin de l'appel.
    unsafe { SetServiceStatus(h as SERVICE_STATUS_HANDLE, &statut) };
}

extern "system" fn handler(
    controle: u32,
    _type_evenement: u32,
    _donnees: *mut core::ffi::c_void,
    _contexte: *mut core::ffi::c_void,
) -> u32 {
    match controle {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
            // Le gestionnaire doit rendre la main tout de suite: on signale, on
            // n'attend pas. Et on ne desarme RIEN ici.
            annoncer(SERVICE_STOP_PENDING, DELAI_DEMARRAGE_MS, 0);
            let _ = canal().0.send(true);
            0
        }
        _ => 0,
    }
}

extern "system" fn service_main(_argc: u32, _argv: *mut windows_sys::core::PWSTR) {
    let nom = wide(spec().nom);
    // SAFETY: `nom` vit jusqu'a la fin de l'appel, le contexte nul est admis.
    let h =
        unsafe { RegisterServiceCtrlHandlerExW(nom.as_ptr(), Some(handler), std::ptr::null_mut()) };
    if h.is_null() {
        return;
    }
    // Stockee en entier: un pointeur brut n'est pas `Sync`, et cette poignee
    // est lue depuis le gestionnaire de controle, sur un autre thread.
    let _ = POIGNEE_STATUT.set(h as usize);

    annoncer(SERVICE_START_PENDING, DELAI_DEMARRAGE_MS, 0);

    let corps = CORPS.lock().expect("verrou du corps de service").take();
    let Some(corps) = corps else {
        annoncer(SERVICE_STOPPED, 0, 1);
        return;
    };

    annoncer(SERVICE_RUNNING, 0, 0);
    let resultat = corps();
    let code = match resultat {
        Ok(()) => 0,
        Err(e) => {
            tracing::error!(error = %e, "le service s'arrete sur une erreur");
            1
        }
    };
    annoncer(SERVICE_STOPPED, 0, code);
}
