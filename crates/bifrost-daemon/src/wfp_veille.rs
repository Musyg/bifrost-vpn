//! Le kill switch tient-il a travers une mise en veille.
//!
//! Le document 02 demande d'eprouver "le boot et le resume". Le boot est
//! traite ailleurs; la reprise ne l'etait nulle part. Le harnais couvre la
//! chute du tunnel, la coupure du lien, la perte a 100% et le drop DPI, pas la
//! mise en veille. C'est pourtant le cas ou une pile reseau se reinitialise
//! entierement, donc celui ou des filtres non persistants sont le plus
//! suspects.
//!
//! # Pourquoi ce vecteur ne peut pas tourner en namespace
//!
//! Les sept autres vecteurs tournent confines. Celui-ci ne le peut pas: la
//! veille est globale, mais les veth et les netns sont de la memoire noyau qui
//! la traverse intacte. Un banc confine ne reproduirait ni la reinitialisation
//! du pilote physique, ni le re-DHCP, ni la recreation d'adaptateur. Il
//! rendrait un vert qui ne mesure rien.
//!
//! # Ce que la documentation laisse attendre, et pourquoi on mesure quand meme
//!
//! Les filtres WFP statiques, les notres, vivent "jusqu'a ce qu'ils soient
//! supprimes, que BFE s'arrete, ou que le systeme soit eteint". La veille n'est
//! aucun des trois, donc ils DEVRAIENT survivre. Mais c'est une deduction
//! depuis une regle, et une deduction n'est pas une mesure.
//!
//! Surtout, survivre ne suffit pas. Le plan Windows autorise le tunnel par son
//! LUID, un NUMERO rendu par WireGuardNT. Si l'adaptateur est detruit et recree
//! au reveil avec un autre LUID, le permit designe un adaptateur qui n'existe
//! plus. Deux issues, et une seule est benigne: ou bien il ne matche plus rien
//! et le tunnel est etrangle, fail-closed genant mais sur; ou bien le LUID a
//! ete reattribue a un autre adaptateur, et le permit du tunnel s'applique
//! desormais a du trafic en clair. La question posee ici n'est donc pas
//! seulement "les filtres ont-ils survecu" mais "designent-ils encore le bon
//! adaptateur".
//!
//! # Deux pieges du systeme, tous deux des temoins qui mentent
//!
//! `SetWaitableTimer` peut reveiller la machine, avec `fResume`. Mais depuis
//! Windows 8, "si un temps RELATIF est specifie, le minuteur n'inclut pas le
//! temps passe dans les etats de faible consommation": un delai relatif ne
//! s'ecoule pas pendant la veille, donc il ne reveille jamais rien. L'echeance
//! est ici ABSOLUE, en UTC.
//!
//! Et "si le systeme ne prend pas en charge la restauration, l'appel REUSSIT,
//! mais `GetLastError` rend `ERROR_NOT_SUPPORTED`". Le code de retour ne dit
//! donc pas si le reveil est arme. On lit `GetLastError` derriere le succes.
//!
//! # Pourquoi observer la reprise par un rappel
//!
//! `PowerRegisterSuspendResumeNotification` exige `DEVICE_NOTIFY_CALLBACK`,
//! donc un rappel direct, sans fenetre ni boucle de messages: utilisable tel
//! quel ici comme dans un service. L'interet n'est pas la commodite. La sonde
//! part alors du chemin de reprise lui-meme, bien plus tot qu'un guetteur
//! externe ne peut l'atteindre, et c'est justement dans ces premieres secondes
//! que la carte est deja `Up` alors que l'amont ne repond pas encore.
//!
//! # Ce qui decide qu'une veille a eu lieu
//!
//! Ni le code de retour de l'appel, ni l'horodatage des evenements du noyau.
//! `Kernel-Power 107` est ecrit avant que Windows resynchronise l'horloge
//! depuis le RTC: deux veilles mesurees, de 35 minutes et de 67 secondes, s'y
//! sont toutes deux inscrites comme trois secondes. Ce qui decide est l'ecart
//! d'horloge murale, `SystemTime`, qui lui ne peut pas ne pas avoir avance.
//!
//! Au passage, et gratuitement, l'ecart d'`Instant` repond a une question
//! restee ouverte sur le superviseur: `poll_handshake` compare la fraicheur du
//! handshake sur `SystemTime`, qui saute au reveil, tandis que `retry_at`
//! s'appuie sur `Instant`. Savoir si `Instant` compte ou non le temps suspendu
//! decide si les deux echeances se comportent pareil de part et d'autre d'une
//! veille.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant, SystemTime};

use bifrost_core::ports::{FirewallPolicy, KillSwitch};
use bifrost_firewall::windows::WfpKillSwitch;
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_NOT_SUPPORTED, ERROR_SUCCESS, GetLastError,
};
use windows_sys::Win32::System::Power::{
    DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS, PowerRegisterSuspendResumeNotification,
    PowerUnregisterSuspendResumeNotification, SetSuspendState,
};
use windows_sys::Win32::System::Threading::{CreateWaitableTimerW, SetWaitableTimer};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    DEVICE_NOTIFY_CALLBACK, PBT_APMRESUMEAUTOMATIC, PBT_APMSUSPEND,
};

use crate::tunnel::wgnt::config::FILETIME_TO_UNIX;
use crate::wfp_identity::{Issue, Verdict, via_copie};

// `Reveil::armer` additionne l'ecart FILETIME a des durees converties en
// `i64`, le type que `SetWaitableTimer` attend. La conversion `u64 -> i64` de
// la constante partagee est refusee a la compilation si elle perdait un bit.
const _: () = assert!(FILETIME_TO_UNIX <= i64::MAX.unsigned_abs());

/// Combien de temps attendre la reprise apres avoir demande la veille.
///
/// Genereux a dessein: la duree de sommeil demandee s'y ajoute, et une machine
/// qui met du temps a revenir n'est pas une machine qui ne revient pas.
const ATTENTE_REPRISE: Duration = Duration::from_secs(180);

/// Duree pendant laquelle on sonde sans relache apres la reprise.
///
/// La fenetre interessante se situe AVANT que l'amont reponde: c'est la que des
/// filtres disparus laisseraient passer. Elle doit pourtant durer assez pour
/// que la pile ait au moins essaye une fois, sans quoi la mesure se conclut a
/// vide. Le delai de retour de l'adaptateur varie beaucoup d'une reprise a
/// l'autre: 8 sondes sans route sur une reprise du 17 aout 2026, 20 sur la
/// suivante, meme machine et meme duree de veille. La mutation de ce jour n'a
/// rougi qu'a la 21e sonde, a la limite d'une fenetre de 20s. D'ou 45s: le
/// blocage constate reste un blocage quelle que soit la duree, seul le silence
/// de la pile coute une mesure.
const FENETRE_REPRISE: Duration = Duration::from_secs(45);

/// Marge du chien de garde, EN PLUS de la duree de sommeil demandee.
///
/// La duree de sommeil s'y ajoute parce que le sommeil du fil progresse
/// pendant la veille. Cela avait ete suppose faux, puis mesure: une veille S3
/// de 63.24s d'horloge murale a fait avancer `Instant` de 63.29s sur
/// essai-windows le 17 aout 2026. Un chien de garde dimensionne sur la seule
/// phase eveillee se declencherait donc PENDANT la veille, kill switch arme:
/// la machine reviendrait sans reseau et sans le processus cense l'y rendre,
/// exactement le desastre qu'il existe pour empecher.
const GARDE: Duration = Duration::from_secs(300);

/// Un ecart d'horloge murale inferieur a cela veut dire qu'on n'a pas dormi.
const VEILLE_MINIMALE: Duration = Duration::from_secs(15);

/// Incremente par le rappel du systeme. `static` parce que le rappel est une
/// fonction nue, sans etat: on ne lui passe pas de contexte pour ne pas avoir
/// a garantir la duree de vie d'un pointeur a travers une mise en veille.
static REPRISES: AtomicU32 = AtomicU32::new(0);
static SUSPENSIONS: AtomicU32 = AtomicU32::new(0);

/// Rappel appele par le systeme. Il ne doit rien faire de long ni de bloquant:
/// il tourne dans le chemin d'alimentation. Deux incrementations atomiques,
/// rien d'autre. Toute la mesure a lieu dans le fil principal, qui les guette.
unsafe extern "system" fn rappel_alimentation(
    _contexte: *const core::ffi::c_void,
    evenement: u32,
    _reglage: *const core::ffi::c_void,
) -> u32 {
    match evenement {
        PBT_APMSUSPEND => SUSPENSIONS.fetch_add(1, Ordering::SeqCst),
        PBT_APMRESUMEAUTOMATIC => REPRISES.fetch_add(1, Ordering::SeqCst),
        _ => 0,
    };
    ERROR_SUCCESS
}

/// Abonnement aux notifications d'alimentation, retire a la destruction.
struct Abonnement(*mut core::ffi::c_void);

impl Abonnement {
    fn poser() -> Result<Self, String> {
        let mut parametres = DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS {
            Callback: Some(rappel_alimentation),
            Context: std::ptr::null_mut(),
        };
        let mut poignee: *mut core::ffi::c_void = std::ptr::null_mut();
        // SAFETY: `parametres` vit jusqu'a la fin de l'appel, que le systeme
        // copie; `poignee` est un pointeur valide vers une sortie.
        let code = unsafe {
            PowerRegisterSuspendResumeNotification(
                DEVICE_NOTIFY_CALLBACK,
                (&raw mut parametres).cast(),
                &raw mut poignee,
            )
        };
        if code != ERROR_SUCCESS {
            return Err(format!(
                "PowerRegisterSuspendResumeNotification a echoue (code {code})"
            ));
        }
        Ok(Self(poignee))
    }
}

impl Drop for Abonnement {
    fn drop(&mut self) {
        // Le retrait prend un HPOWERNOTIFY, qui est un `isize`, alors que
        // l'enregistrement rend un `*mut c_void`: c'est la meme valeur des deux
        // cotes, seul le type declare change.
        // SAFETY: poignee rendue par l'enregistrement, retiree une seule fois.
        unsafe { PowerUnregisterSuspendResumeNotification(self.0 as isize) };
    }
}

/// Minuteur arme pour reveiller la machine, annule a la destruction.
///
/// Visible dans le crate parce que la recette de reprise s'en sert aussi: elle
/// endort la machine sans toucher au pare-feu, et a donc besoin du meme reveil.
pub(crate) struct Reveil(windows_sys::Win32::Foundation::HANDLE);

impl Reveil {
    /// `dans` est convertie en echeance ABSOLUE. Voir le piege en tete de
    /// module: une echeance relative ne s'ecoule pas pendant la veille.
    pub(crate) fn armer(dans: Duration) -> Result<Self, String> {
        // SAFETY: creation d'un minuteur anonyme a reinitialisation manuelle.
        let poignee = unsafe { CreateWaitableTimerW(std::ptr::null(), 1, std::ptr::null()) };
        if poignee.is_null() {
            // SAFETY: lecture du dernier code d'erreur du fil courant.
            return Err(format!("CreateWaitableTimerW a echoue ({})", unsafe {
                GetLastError()
            }));
        }

        // FILETIME: intervalles de 100 ns depuis le 1er janvier 1601, en UTC.
        // Positif vaut absolu, ce qui est exactement ce qu'on veut ici.
        // L'ecart a l'epoque Unix est celui de `wgnt::config`, garde la-bas
        // par un recalcul: une seule constante, pas deux copies a tenir egales.
        let maintenant = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|e| format!("horloge systeme anterieure a 1970: {e}"))?;
        let echeance: i64 = FILETIME_TO_UNIX as i64
            + (maintenant.as_nanos() / 100) as i64
            + (dans.as_nanos() / 100) as i64;

        // SAFETY: poignee valide, echeance pointant sur une valeur vivante.
        let pose = unsafe {
            SetWaitableTimer(
                poignee,
                &raw const echeance,
                0,
                None,
                std::ptr::null(),
                1, // fResume: c'est lui qui autorise le reveil.
            )
        };
        if pose == 0 {
            // SAFETY: lecture du dernier code d'erreur du fil courant.
            let e = unsafe { GetLastError() };
            // SAFETY: poignee valide, fermee une seule fois.
            unsafe { CloseHandle(poignee) };
            return Err(format!("SetWaitableTimer a echoue ({e})"));
        }

        // Le piege: un succes ne dit PAS que le reveil est arme. Quand la
        // plateforme ne sait pas restaurer, l'appel reussit quand meme et seul
        // le dernier code d'erreur le signale.
        // SAFETY: lecture du dernier code d'erreur du fil courant.
        if unsafe { GetLastError() } == ERROR_NOT_SUPPORTED {
            // SAFETY: poignee valide, fermee une seule fois.
            unsafe { CloseHandle(poignee) };
            return Err("cette plateforme ne sait pas se reveiller sur minuteur \
                        (ERROR_NOT_SUPPORTED). Verifier que la strategie \
                        d'alimentation autorise les minuteries de reveil: le \
                        reglage 'importantes uniquement' les refuse."
                .to_owned());
        }
        Ok(Self(poignee))
    }
}

impl Drop for Reveil {
    fn drop(&mut self) {
        // SAFETY: poignee valide, fermee une seule fois.
        unsafe { CloseHandle(self.0) };
    }
}

/// Ce qui a ete observe de part et d'autre de la veille.
#[derive(Debug)]
pub struct Traversee {
    pub murale: Duration,
    pub monotone: Duration,
    pub luid_avant: Option<u64>,
    pub luid_apres: Option<u64>,
    pub sondes: usize,
    /// Sondes qu'un filtre a refusees. Ce sont les SEULES qui prouvent que les
    /// filtres ont tenu: une fenetre sans aucune d'elles n'a rien mesure.
    pub bloquees: usize,
    /// Sondes ou la pile n'a meme pas essaye. Attendu juste apres la reprise,
    /// le temps que l'adaptateur revienne, et sans valeur de preuve.
    pub sans_route: usize,
    /// Ce que le systeme a annonce par le rappel d'alimentation.
    pub suspensions: u32,
    pub reprises: u32,
}

/// Endort la machine, kill switch arme, et mesure ce qui en ressort.
///
/// **Coupe tout le reseau de la machine** entre l'armement et le desarmement,
/// puis l'endort. A ne lancer que sur une machine dediee, capable de revenir
/// seule: le reglage des minuteries de reveil est verifie par `Reveil::armer`,
/// pas la presence d'une seconde voie.
pub fn run(
    firewall: &mut WfpKillSwitch,
    policy: &FirewallPolicy,
    cible: SocketAddr,
    dormir: Duration,
) -> anyhow::Result<(Issue, Option<Traversee>)> {
    // 1. Temoin negatif, au repos. Sans lui, un refus constate plus tard ne
    //    prouverait rien: une cible injoignable donnerait le meme resultat.
    match via_copie(cible)? {
        Verdict::Connecte => {}
        autre => {
            return Ok((
                Issue::Ignore(format!(
                    "au repos, {cible} n'aboutit pas ({autre:?}). La mesure ne \
                     peut rien conclure d'un blocage sur une cible deja muette."
                )),
                None,
            ));
        }
    }

    // 2. On s'abonne AVANT d'armer quoi que ce soit: si l'abonnement echoue,
    //    rien n'a encore ete coupe.
    let _abonnement = match Abonnement::poser() {
        Ok(a) => a,
        Err(e) => return Ok((Issue::Ignore(e), None)),
    };
    let reveil = match Reveil::armer(dormir) {
        Ok(r) => r,
        Err(e) => return Ok((Issue::Ignore(e), None)),
    };
    REPRISES.store(0, Ordering::SeqCst);
    SUSPENSIONS.store(0, Ordering::SeqCst);

    firewall
        .engage(policy)
        .map_err(|e| anyhow::anyhow!("armement impossible: {e}"))?;

    // A partir d'ici le reseau est coupe. Tout chemin de sortie desarme.
    let resultat = traverser(policy, cible, dormir);
    let desarme = firewall.disengage();

    // Le desarmement prime sur la lecture du resultat. L'inverse a deja coute
    // un redemarrage.
    if let Err(e) = desarme {
        return Err(anyhow::anyhow!("desarmement impossible: {e}"));
    }

    drop(reveil);

    // 4. Le reseau doit revenir. Sans cette mesure, un refus constate pendant
    //    la fenetre pourrait venir d'une machine encore sans reseau plutot que
    //    du kill switch.
    let (issue, traversee) = resultat?;
    if matches!(issue, Issue::Reussi) {
        match via_copie(cible)? {
            Verdict::Connecte => {}
            autre => {
                return Ok((
                    Issue::Echec(format!(
                        "apres desarmement, {cible} n'aboutit plus ({autre:?}): \
                         le blocage constate pendant la fenetre de reprise ne \
                         peut pas etre attribue au kill switch"
                    )),
                    traversee,
                ));
            }
        }
    }
    Ok((issue, traversee))
}

/// Le corps, kill switch arme. Separe pour que l'appelant desarme sur tous les
/// chemins, y compris celui de l'erreur.
fn traverser(
    policy: &FirewallPolicy,
    cible: SocketAddr,
    dormir: Duration,
) -> anyhow::Result<(Issue, Option<Traversee>)> {
    // Sous armement, avant de dormir: le blocage doit deja etre effectif.
    if via_copie(cible)? != Verdict::Bloque {
        return Ok((
            Issue::Echec(
                "le kill switch arme ne bloque pas AVANT la veille: inutile de \
                 mesurer ce qu'il en reste apres"
                    .to_owned(),
            ),
            None,
        ));
    }

    let luid_avant = policy.tunnel_luid;
    let murale_avant = SystemTime::now();
    let monotone_avant = Instant::now();

    // SAFETY: appel sans effet de bord memoire. Ne pas hiberner, ne pas
    // forcer, ne pas desactiver les evenements de reveil - sans quoi le
    // minuteur arme plus haut ne servirait a rien.
    let demande = unsafe { SetSuspendState(false, false, false) };
    if !demande {
        // SAFETY: lecture du dernier code d'erreur du fil courant.
        let code = unsafe { GetLastError() };
        return Ok((
            Issue::Ignore(format!("SetSuspendState a echoue ({code})")),
            None,
        ));
    }

    // On attend la reprise. Le rappel l'annonce; l'horloge murale la confirme.
    let limite = Instant::now() + ATTENTE_REPRISE + dormir;
    while REPRISES.load(Ordering::SeqCst) == 0 && Instant::now() < limite {
        std::thread::sleep(Duration::from_millis(100));
    }

    let murale = SystemTime::now()
        .duration_since(murale_avant)
        .unwrap_or_default();
    let monotone = monotone_avant.elapsed();

    if murale < VEILLE_MINIMALE {
        return Ok((
            Issue::Ignore(format!(
                "la machine n'a pas dormi: l'horloge murale n'a avance que de \
                 {murale:?}. Ni le code de retour de SetSuspendState ni les \
                 evenements du noyau ne suffisent a l'affirmer, seul cet ecart \
                 le dit."
            )),
            None,
        ));
    }

    // La fenetre qui compte. On sonde sans relache: c'est ici que des filtres
    // disparus laisseraient passer, et l'amont ne repond pas encore.
    //
    // Trois issues, pas deux. `SansRoute` dit que la pile n'a meme pas essaye:
    // le paquet n'a jamais atteint WFP, donc des filtres intacts et des filtres
    // disparus produisent exactement la meme sonde. La confondre avec une fuite
    // a fait echouer la mesure du 17 aout 2026 des la premiere sonde, a un
    // moment ou l'adaptateur n'etait tout simplement pas encore revenu. On
    // continue de sonder: c'est le seul moyen d'atteindre une reponse tranchee.
    let mut sondes = 0usize;
    let mut bloquees = 0usize;
    let mut sans_route = 0usize;
    let fin = Instant::now() + FENETRE_REPRISE;
    let mut fuite = None;
    while Instant::now() < fin {
        sondes += 1;
        let verdict = via_copie(cible)?;
        if verdict == Verdict::Bloque {
            bloquees += 1;
        } else if verdict == Verdict::SansRoute {
            sans_route += 1;
        } else {
            fuite = Some(format!(
                "a la sonde {sondes}, {murale:?} apres l'endormissement et \
                 dans la fenetre de reprise, {cible} n'est plus bloquee \
                 ({verdict:?}): les filtres n'ont pas tenu"
            ));
            break;
        }
    }

    // Le LUID que le systeme donne MAINTENANT pour cette interface, a comparer
    // avec celui que les filtres portent. Redemander plutot que relire un
    // champ: c'est justement le systeme qui peut avoir change d'avis.
    let luid_apres = policy
        .tunnel_interface
        .as_deref()
        .and_then(|nom| bifrost_firewall::windows::interface_luid(nom).ok());
    let traversee = Some(Traversee {
        murale,
        monotone,
        luid_avant,
        luid_apres,
        sondes,
        bloquees,
        sans_route,
        suspensions: SUSPENSIONS.load(Ordering::SeqCst),
        reprises: REPRISES.load(Ordering::SeqCst),
    });

    if let Some(raison) = fuite {
        return Ok((Issue::Echec(raison), traversee));
    }
    if bloquees == 0 {
        return Ok((
            Issue::Ignore(format!(
                "la fenetre de reprise s'est ecoulee sans qu'un seul paquet \
                 atteigne les filtres ({sondes} sondes, toutes SansRoute): rien \
                 n'a ete mesure. Un vert ici ne vaudrait rien, la pile n'ayant \
                 pas essaye. Rallonger FENETRE_REPRISE ou verifier que \
                 l'adaptateur revient."
            )),
            traversee,
        ));
    }
    if luid_avant.is_some() && luid_apres != luid_avant {
        return Ok((
            Issue::Echec(format!(
                "les filtres ont tenu mais le LUID du tunnel a change pendant \
                 la veille ({luid_avant:?} puis {luid_apres:?}): le permit du \
                 tunnel designe un adaptateur qui n'est plus le bon"
            )),
            traversee,
        ));
    }
    Ok((Issue::Reussi, traversee))
}

/// Point d'entree de `--wfp-veille-selftest`.
///
/// `tunnel` nomme l'interface WireGuard DEJA montee dont le permit doit etre
/// eprouve. Sans elle, la mesure tourne quand meme mais la question du LUID se
/// declare non mesuree au lieu de passer en silence: le kill switch peut
/// parfaitement survivre a une veille tout en designant, apres elle, un
/// adaptateur qui n'est plus le bon.
///
/// `monter` demande a la place la creation d'un adaptateur WireGuardNT de ce
/// nom, garde vivant d'un bout a l'autre de la mesure et retire a la fin. Meme
/// driver que les tunnels de production, donc meme question posee au LUID, sans
/// exiger qu'un tunnel tourne deja sur la machine d'essai.
pub fn selftest(
    cible: SocketAddr,
    dormir: Duration,
    tunnel: Option<&str>,
    monter: Option<&str>,
) -> anyhow::Result<()> {
    eprintln!(
        "AVERTISSEMENT: cet autotest coupe tout le reseau de cette machine, PUIS \
         l'endort. Machine dediee capable de revenir seule uniquement. Prevoir \
         une seconde voie de reveil: un reveil rate coute une pression sur le \
         bouton."
    );

    // Le chien de garde d'abord, avant que quoi que ce soit ne soit arme. Si le
    // corps fige alors que les filtres sont poses, une machine distante reste
    // sans reseau et personne ne peut plus y entrer pour la reparer.
    //
    // Son delai couvre la duree de sommeil demandee EN PLUS de sa marge: le
    // sommeil du fil progresse pendant la veille, c'est mesure (cf. GARDE).
    let echeance_garde = GARDE + dormir;
    std::thread::spawn(move || chien_de_garde(echeance_garde));

    let mut firewall = bifrost_firewall::windows::WfpKillSwitch::new()
        .map_err(|e| anyhow::anyhow!("ouverture du moteur WFP: {e}"))?;

    // L'adaptateur monte ici doit vivre jusqu'au bout: son `Drop` le retire, et
    // le retirer avant la veille reviendrait a ne rien mesurer du tout. On le
    // garde donc lie a une variable de cette portee, jamais a un temporaire.
    let _monte;
    let (tunnel_interface, tunnel_luid) = match (tunnel, monter) {
        (_, Some(nom)) => {
            let nt = crate::tunnel::wgnt::dll::WireGuardNt::load()
                .map_err(|e| anyhow::anyhow!("chargement de wireguard.dll: {e}"))?;
            let adaptateur = crate::tunnel::wgnt::adapter::Adapter::create(nt, nom)
                .map_err(|e| anyhow::anyhow!("creation de l'adaptateur {nom}: {e}"))?;
            let luid = adaptateur.luid();

            // Monte, parce qu'un adaptateur laisse a l'arret ne subit pas le
            // meme sort qu'un tunnel en service au moment de la veille.
            if let Err(e) = adaptateur.set_state(true) {
                println!("adaptateur {nom} cree mais non active ({e})");
            }
            // Le LUID que le driver annonce et celui que le systeme rend pour
            // ce nom doivent deja coincider AVANT la veille. Sinon la
            // comparaison d'apres ne dirait rien de la veille.
            match bifrost_firewall::windows::interface_luid(nom) {
                Ok(par_nom) if par_nom == luid => {
                    println!("tunnel monte: {nom}, LUID {luid:#x}")
                }
                Ok(par_nom) => anyhow::bail!(
                    "avant meme la veille, {nom} rend {par_nom:#x} par son nom et \
                     {luid:#x} par le driver: la mesure d'apres ne pourrait rien \
                     attribuer a la veille"
                ),
                Err(e) => anyhow::bail!("{nom} vient d'etre cree mais reste introuvable: {e}"),
            }
            _monte = adaptateur;
            (Some(nom.to_owned()), Some(luid))
        }
        (Some(nom), None) => {
            let luid = bifrost_firewall::windows::interface_luid(nom)
                .map_err(|e| anyhow::anyhow!("interface {nom} introuvable: {e}"))?;
            println!("tunnel eprouve: {nom}, LUID {luid:#x}");
            (Some(nom.to_owned()), Some(luid))
        }
        (None, None) => {
            println!(
                "SKIPPED (partiel): aucune interface de tunnel donnee, la survie \
                 du permit par LUID ne sera pas mesuree. Passer \
                 --veille-tunnel <INTERFACE> pour un tunnel deja monte, ou \
                 --veille-monter-tunnel <INTERFACE> pour en monter un le temps \
                 de la mesure."
            );
            (None, None)
        }
    };

    let policy = FirewallPolicy {
        tunnel_interface,
        tunnel_luid,
        fwmark: None,
        dns_resolver: std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        allow_lan: false,
        coeur_uid: None,
        coeur_executable: None,
        resolveur_uid: None,
        resolveur_executable: None,
        resolveur_sid: None,
        resolveur_embarque: false,
    };

    println!("\nendormissement pour {dormir:?}, sondes vers {cible}...");
    let (issue, traversee) = run(&mut firewall, &policy, cible, dormir)?;

    if let Some(t) = &traversee {
        println!("\nce que la veille a traverse:");
        println!("  horloge murale : {:?}", t.murale);
        println!(
            "  Instant        : {:?}  ({})",
            t.monotone,
            // La reponse a la question du superviseur, lue et non supposee.
            if t.monotone.as_secs() + 5 < t.murale.as_secs() {
                "ne compte PAS le temps suspendu"
            } else {
                "compte le temps suspendu"
            }
        );
        println!(
            "  veille annoncee : {} suspension(s), {} reprise(s) par le rappel",
            t.suspensions, t.reprises
        );
        println!(
            "  sondes apres reprise : {} dont {} bloquees et {} sans route",
            t.sondes, t.bloquees, t.sans_route
        );
        match (t.luid_avant, t.luid_apres) {
            (Some(a), Some(b)) if a == b => println!("  LUID du tunnel : {a:#x}, inchange"),
            (Some(a), Some(b)) => println!("  LUID du tunnel : {a:#x} PUIS {b:#x}"),
            _ => println!("  LUID du tunnel : non mesure"),
        }
    }

    match issue {
        Issue::Reussi => {
            let bloquees = traversee.as_ref().map_or(0, |t| t.bloquees);
            println!(
                "\nvecteur veille: le kill switch a tenu a travers la mise en \
                 veille ({bloquees} sonde(s) refusee(s) par un filtre apres la \
                 reprise), et son permit designe toujours le bon adaptateur"
            );
            Ok(())
        }
        Issue::Ignore(raison) => {
            println!("\nSKIPPED: {raison}");
            std::process::exit(3);
        }
        Issue::Echec(raison) => {
            eprintln!("\nECHEC: {raison}");
            anyhow::bail!("le vecteur veille a echoue")
        }
    }
}

/// Dernier recours: si le corps fige alors que les filtres sont poses, la
/// machine reste sans reseau, et sur une machine distante plus personne ne peut
/// y entrer pour la reparer.
///
/// Le meme role que celui de `wfp_selftest`, avec un delai bien plus long: ce
/// vecteur passe par une veille, que son echeance doit englober.
fn chien_de_garde(echeance: Duration) {
    std::thread::sleep(echeance);
    eprintln!("chien de garde: reprise apres {echeance:?}");
    for tentative in 1..=3 {
        match bifrost_firewall::new().and_then(|mut fw| fw.disengage()) {
            Ok(()) => {
                eprintln!("chien de garde: kill switch desarme");
                std::process::exit(2);
            }
            Err(e) => eprintln!("chien de garde: tentative {tentative} en echec: {e}"),
        }
        std::thread::sleep(Duration::from_secs(2));
    }
    eprintln!(
        "chien de garde: desarmement impossible. Le trafic reste bloque. \
         Lancer 'bifrost-daemon --cleanup-firewall', ou redemarrer: les filtres \
         ne sont pas persistants."
    );
    std::process::exit(3);
}
