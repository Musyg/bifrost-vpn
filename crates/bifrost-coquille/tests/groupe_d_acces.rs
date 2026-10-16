//! Le groupe d'acces du canal, de bout en bout, sous de vrais jetons: un
//! membre non eleve commande le daemon par la coquille, un non-membre est
//! refuse a l'ouverture.
//!
//! Ce que les recettes d'un poste non eleve ne mesurent pas: un tel compte ne
//! cree ni groupe ni compte, et ne porte qu'un SID, le sien. Cette recette
//! cree un groupe local et deux comptes locaux jetables, le premier membre du
//! groupe, le second non; prend leurs jetons par `LogonUserW`; et mesure face
//! a un vrai `IpcServer` lie avec ce groupe, dont le pipe appartient aux
//! Administrateurs (proprietaire par defaut du jeton du processus, pose comme
//! dans `tests/eleve_ipc.rs`):
//!
//! - (a) le membre, non eleve, ouvre le canal, et la coquille (`Commande`) lui
//!   fait servir `status`, `connect-stored` et `disconnect`;
//! - (b) le membre ne peut pas ajouter d'instance au pipe
//!   (`ERROR_ACCESS_DENIED`), et ne l'ouvre pas en
//!   `GENERIC_READ | GENERIC_WRITE`;
//! - (c) le non-membre est refuse a l'ouverture, et la coquille le rend
//!   << non admis par le canal >>;
//! - (d) le membre envoie chacune des sept commandes reservees aux
//!   administrateurs (`connect` avec un profil, `check`, le verdict TLS, la
//!   reprise, les trois declarations) et recoit pour chacune le refus qui la
//!   nomme, sans que le serveur en recoive aucune: seules ses trois commandes
//!   de (a) lui parviennent. Puis le processus de la recette, eleve, aux
//!   Administrateurs actifs, envoie les memes sept: toutes parviennent au
//!   serveur, il garde tout le canal;
//! - (e) ce que les recettes MIROIR de `bifrost-ipc` mesurent sur un poste
//!   sur le compte des recettes, et ne peuvent pas mesurer sur le runner (son
//!   compte est un compte predefini, elles s'y abstiennent): le groupe resolu
//!   par `GroupeDAcces::resoudre` porte la forme d'un compte cree et le
//!   domaine de la machine (celui des deux comptes que la recette cree dans
//!   la base locale, resolus par elle); une forme equivalente de son SID
//!   (zeros de tete, minuscules) est resolue et rendue sous la forme
//!   canonique; le meme domaine avec le RID 500, l'administrateur integre,
//!   est refuse `NonAdmissible` sous sa forme canonique (juge, et rien
//!   d'autre); et la DACL du pipe que le serveur lie avec ce groupe, lue par
//!   une poignee de client, porte exactement trois ACE d'autorisation: SYSTEM
//!   et les Administrateurs a tous les droits tels que le noyau les traduit,
//!   le groupe a `0x120083`.
//!
//! Elle ne tourne que si TROIS conditions tiennent: `BIFROST_RUNNER_JETABLE`
//! vaut `1`, `GITHUB_ACTIONS` vaut `true`, et le processus est eleve. Sinon
//! elle s'abstient, et dit laquelle manque. Le groupe et les comptes sont
//! retires a la fin, meme sur panique: la garde qui les cree les retire a sa
//! destruction, et ne retire que ce qu'elle a cree; sur le chemin nominal,
//! leur absence est ensuite relue aupres du systeme (`NetLocalGroupGetInfo`,
//! `NetUserGetInfo`), pour qu'un retrait qui echouerait en silence soit un
//! rouge. Les mots de passe sont tires au hasard par le systeme et ne
//! s'impriment jamais.
//!
//! Un binaire a part: la pose du proprietaire par defaut modifie le jeton du
//! PROCESSUS. Chaque compte agit dans un fil a lui, qui emprunte son jeton
//! (`ImpersonateLoggedOnUser`) et le rend (`RevertToSelf`) avant de finir. Ce
//! qu'elle lit s'imprime par classes, jamais par SID ni mot de passe.

#![cfg(windows)]

#[path = "commun/faux_daemon.rs"]
mod faux_daemon;
#[path = "commun/jeton.rs"]
mod jeton;

use std::ffi::c_void;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::panic::AssertUnwindSafe;

use bifrost_coquille::{Commande, CouleurTray, ErreurCommande, EtatVue, Vue};
use bifrost_ipc::{
    AuthPolicy, Command, CommandeReservee, ErreurGroupe, GroupeDAcces, IpcClient, IpcServer,
    Request, Response, ServerRequirement,
};
use jeton::{Integrite, Proprietaire};
use tokio::net::windows::named_pipe::{ClientOptions, ServerOptions};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ACCESS_DENIED, ERROR_LOGON_TYPE_NOT_GRANTED, HANDLE, LocalFree,
};
use windows_sys::Win32::NetworkManagement::NetManagement::{
    LOCALGROUP_INFO_1, LOCALGROUP_MEMBERS_INFO_3, NERR_GroupNotFound, NERR_Success,
    NERR_UserNotFound, NetApiBufferFree, NetLocalGroupAdd, NetLocalGroupAddMembers,
    NetLocalGroupDel, NetLocalGroupGetInfo, NetUserAdd, NetUserDel, NetUserGetInfo,
    UF_DONT_EXPIRE_PASSWD, UF_SCRIPT, USER_INFO_1, USER_PRIV_USER,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, GetSecurityInfo, SE_KERNEL_OBJECT,
};
use windows_sys::Win32::Security::Cryptography::{
    BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, CheckTokenMembership, CreateWellKnownSid,
    DACL_SECURITY_INFORMATION, EqualSid, GetAce, ImpersonateLoggedOnUser, IsWellKnownSid,
    LOGON32_LOGON, LOGON32_LOGON_INTERACTIVE, LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT,
    LogonUserW, LookupAccountNameW, PSECURITY_DESCRIPTOR, PSID, RevertToSelf,
    SECURITY_MAX_SID_SIZE, SID_NAME_USE, TOKEN_ELEVATION, TOKEN_QUERY, TOKEN_USER, TokenElevation,
    TokenUser, WinBuiltinAdministratorsSid, WinLocalSystemSid,
};
use windows_sys::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};

const NOM_RECETTE: &str = "le_groupe_d_acces_admet_ses_membres_et_eux_seuls";

/// `FILE_READ_DATA | FILE_WRITE_DATA | READ_CONTROL`: les droits par lesquels
/// le client de `bifrost-ipc` ouvre le canal, ecrits en clair; `READ_CONTROL`
/// y est ce qui permet de lire la DACL du pipe par la poignee.
const DROITS_DU_CLIENT: u32 = 0x0002_0003;

/// `SECURITY_IDENTIFICATION`: le serveur ne peut qu'identifier ce client,
/// comme pour le client de `bifrost-ipc`.
const IDENTIFICATION_SEULE: u32 = 0x0001_0000;

/// `ACCESS_ALLOWED_ACE_TYPE`.
const ACE_D_AUTORISATION: u8 = 0;

/// `GENERIC_ALL`, tel que le noyau le traduit dans la DACL d'un pipe.
const TOUS_LES_DROITS_DU_PIPE: u32 = 0x001F_01FF;

/// Le masque de l'ACE du groupe d'acces, mesure par `bifrost-ipc`, en clair.
const MASQUE_DU_GROUPE: u32 = 0x0012_0083;

/// Le RID de l'administrateur integre d'une machine.
const RID_ADMINISTRATEUR_INTEGRE: u32 = 500;

/// Le premier RID d'un compte ou d'un groupe cree par un administrateur.
const PREMIER_RID_CREE: u32 = 1000;

/// La condition qui manque pour tourner, s'il en manque une.
fn raison_de_s_abstenir() -> Option<&'static str> {
    if std::env::var("BIFROST_RUNNER_JETABLE").as_deref() != Ok("1") {
        return Some(
            "BIFROST_RUNNER_JETABLE ne vaut pas 1: la recette cree un groupe et deux comptes \
             locaux, elle ne tourne que sur une machine jetable",
        );
    }
    if std::env::var("GITHUB_ACTIONS").as_deref() != Ok("true") {
        return Some(
            "GITHUB_ACTIONS ne vaut pas true: la recette ne tourne que sur le runner jetable \
             de la CI",
        );
    }
    if jeton::integrite() == Integrite::Moyen {
        return Some(
            "processus non eleve: creer un groupe et des comptes locaux exige les droits \
             d'administrateur",
        );
    }
    None
}

/// Une chaine UTF-16 terminee par un zero.
fn large(texte: &str) -> Vec<u16> {
    texte.encode_utf16().chain(Some(0)).collect()
}

/// Un mot de passe tire au hasard par le systeme: un prefixe qui porte les
/// quatre classes de caracteres qu'une politique de complexite exige, puis
/// 24 caracteres aleatoires. Il ne sort de cette recette que vers
/// `NetUserAdd` et `LogonUserW`.
fn mot_de_passe() -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    let mut octets = [0u8; 24];
    // SAFETY: le tampon fait 24 octets, sa taille est passee; aucun
    // algorithme n'est ouvert, le generateur du systeme est demande par le
    // drapeau.
    let statut = unsafe {
        BCryptGenRandom(
            std::ptr::null_mut(),
            octets.as_mut_ptr(),
            octets.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    assert_eq!(statut, 0, "BCryptGenRandom: statut {statut:#x}");
    let mut mdp = String::from("Bf7-");
    for o in octets {
        mdp.push(char::from(ALPHABET[usize::from(o) % ALPHABET.len()]));
    }
    mdp
}

/// Le groupe et les comptes jetables. Chacun n'est retenu qu'une fois cree
/// par cette garde, et retire a sa destruction, panique comprise: jamais un
/// compte ou un groupe qu'elle n'a pas cree.
#[derive(Default)]
struct Jetables {
    groupe: Option<String>,
    comptes: Vec<String>,
}

impl Jetables {
    fn creer_le_groupe(&mut self, nom: &str) {
        let mut nom_l = large(nom);
        let mut commentaire = large("Bifrost, recette jetable du groupe d'acces");
        let info = LOCALGROUP_INFO_1 {
            lgrpi1_name: nom_l.as_mut_ptr(),
            lgrpi1_comment: commentaire.as_mut_ptr(),
        };
        let mut erreur = 0u32;
        // SAFETY: serveur local (nul); `info` et les chaines qu'il designe
        // vivent pendant l'appel, au niveau 1 qu'il declare.
        let code = unsafe {
            NetLocalGroupAdd(
                std::ptr::null(),
                1,
                (&info as *const LOCALGROUP_INFO_1).cast(),
                &mut erreur,
            )
        };
        assert_eq!(code, NERR_Success, "NetLocalGroupAdd: code {code}");
        self.groupe = Some(nom.to_owned());
    }

    fn creer_le_compte(&mut self, nom: &str, mdp: &str) {
        let mut nom_l = large(nom);
        let mut mdp_l = large(mdp);
        let info = USER_INFO_1 {
            usri1_name: nom_l.as_mut_ptr(),
            usri1_password: mdp_l.as_mut_ptr(),
            usri1_password_age: 0,
            usri1_priv: USER_PRIV_USER,
            usri1_home_dir: std::ptr::null_mut(),
            usri1_comment: std::ptr::null_mut(),
            usri1_flags: UF_SCRIPT | UF_DONT_EXPIRE_PASSWD,
            usri1_script_path: std::ptr::null_mut(),
        };
        let mut erreur = 0u32;
        // SAFETY: serveur local (nul); `info` et les chaines qu'il designe
        // vivent pendant l'appel, au niveau 1 qu'il declare.
        let code = unsafe {
            NetUserAdd(
                std::ptr::null(),
                1,
                (&info as *const USER_INFO_1).cast(),
                &mut erreur,
            )
        };
        assert_eq!(
            code, NERR_Success,
            "NetUserAdd: code {code}, parametre {erreur}"
        );
        self.comptes.push(nom.to_owned());
    }

    fn ajouter_au_groupe(&self, compte: &str) {
        let groupe = large(self.groupe.as_deref().expect("groupe cree d'abord"));
        let mut nom_l = large(compte);
        let membre = LOCALGROUP_MEMBERS_INFO_3 {
            lgrmi3_domainandname: nom_l.as_mut_ptr(),
        };
        // SAFETY: serveur local (nul); le groupe et l'unique entree, au niveau
        // 3 qu'elle declare, vivent pendant l'appel.
        let code = unsafe {
            NetLocalGroupAddMembers(
                std::ptr::null(),
                groupe.as_ptr(),
                3,
                (&membre as *const LOCALGROUP_MEMBERS_INFO_3).cast(),
                1,
            )
        };
        assert_eq!(code, NERR_Success, "NetLocalGroupAddMembers: code {code}");
    }
}

impl Drop for Jetables {
    fn drop(&mut self) {
        for compte in &self.comptes {
            let nom = large(compte);
            // SAFETY: serveur local (nul); le nom vit pendant l'appel.
            let code = unsafe { NetUserDel(std::ptr::null(), nom.as_ptr()) };
            println!("RELEVE groupe_d_acces: compte jetable retire: code {code}");
        }
        if let Some(groupe) = &self.groupe {
            let nom = large(groupe);
            // SAFETY: serveur local (nul); le nom vit pendant l'appel.
            let code = unsafe { NetLocalGroupDel(std::ptr::null(), nom.as_ptr()) };
            println!("RELEVE groupe_d_acces: groupe jetable retire: code {code}");
        }
    }
}

/// Le groupe local existe-t-il encore, selon le systeme? `Ok(false)` sur
/// `NERR_GroupNotFound`; tout autre echec est rendu tel quel.
fn le_groupe_existe(nom: &str) -> Result<bool, u32> {
    let nom_l = large(nom);
    let mut tampon: *mut u8 = std::ptr::null_mut();
    // SAFETY: serveur local (nul); le nom vit pendant l'appel; `tampon`
    // recoit une allocation du systeme, rendue ci-dessous par
    // NetApiBufferFree si l'appel aboutit.
    let code = unsafe { NetLocalGroupGetInfo(std::ptr::null(), nom_l.as_ptr(), 0, &mut tampon) };
    if code == NERR_Success {
        // SAFETY: le tampon vient d'etre alloue par le systeme pour cet
        // appel reussi, et n'est rendu qu'ici.
        unsafe { NetApiBufferFree(tampon.cast()) };
        return Ok(true);
    }
    if code == NERR_GroupNotFound {
        Ok(false)
    } else {
        Err(code)
    }
}

/// Le compte local existe-t-il encore, selon le systeme? `Ok(false)` sur
/// `NERR_UserNotFound`; tout autre echec est rendu tel quel.
fn le_compte_existe(nom: &str) -> Result<bool, u32> {
    let nom_l = large(nom);
    let mut tampon: *mut u8 = std::ptr::null_mut();
    // SAFETY: serveur local (nul); le nom vit pendant l'appel; `tampon`
    // recoit une allocation du systeme, rendue ci-dessous par
    // NetApiBufferFree si l'appel aboutit.
    let code = unsafe { NetUserGetInfo(std::ptr::null(), nom_l.as_ptr(), 0, &mut tampon) };
    if code == NERR_Success {
        // SAFETY: le tampon vient d'etre alloue par le systeme pour cet
        // appel reussi, et n'est rendu qu'ici.
        unsafe { NetApiBufferFree(tampon.cast()) };
        return Ok(true);
    }
    if code == NERR_UserNotFound {
        Ok(false)
    } else {
        Err(code)
    }
}

/// Un jeton, ferme quand il sort de portee.
struct Jeton(HANDLE);

impl Drop for Jeton {
    fn drop(&mut self) {
        // SAFETY: la poignee vient d'un appel reussi qui l'a ouverte pour ce
        // fil, et n'est fermee qu'ici.
        unsafe { CloseHandle(self.0) };
    }
}

/// Ouvre une session du compte: interactive d'abord, reseau si la politique
/// de la machine refuse l'interactive a ce compte. Rend le jeton et le genre
/// de session obtenu.
fn ouvrir_une_session(nom: &str, mdp: &str) -> (Jeton, &'static str) {
    let nom_l = large(nom);
    let point = large(".");
    let mdp_l = large(mdp);
    let essayer = |genre: LOGON32_LOGON| -> Result<Jeton, std::io::Error> {
        let mut poignee: HANDLE = std::ptr::null_mut();
        // SAFETY: trois chaines terminees par un zero, vivantes pendant
        // l'appel; `poignee` recoit un jeton que `Jeton` ferme.
        let ok = unsafe {
            LogonUserW(
                nom_l.as_ptr(),
                point.as_ptr(),
                mdp_l.as_ptr(),
                genre,
                LOGON32_PROVIDER_DEFAULT,
                &mut poignee,
            )
        };
        if ok != 0 {
            Ok(Jeton(poignee))
        } else {
            Err(std::io::Error::last_os_error())
        }
    };
    match essayer(LOGON32_LOGON_INTERACTIVE) {
        Ok(j) => (j, "interactive"),
        Err(e) if e.raw_os_error() == Some(ERROR_LOGON_TYPE_NOT_GRANTED as i32) => {
            let j = essayer(LOGON32_LOGON_NETWORK)
                .unwrap_or_else(|e| panic!("LogonUserW, session reseau: {e}"));
            (j, "reseau")
        }
        Err(e) => panic!("LogonUserW, session interactive: {e}"),
    }
}

/// Le jeton est-il eleve (`TokenElevation`)?
fn est_eleve(jeton: HANDLE) -> bool {
    let tampon = jeton::lire_le_jeton(jeton, TokenElevation);
    // SAFETY: le tampon, aligne sur 8 octets, a ete rempli pour
    // TokenElevation: un TOKEN_ELEVATION.
    unsafe { (*tampon.as_ptr().cast::<TOKEN_ELEVATION>()).TokenIsElevated != 0 }
}

/// Le fil courant agit-il sous le compte de `session`? Le jeton du fil et
/// celui de la session nomment-ils le meme utilisateur (`EqualSid`)?
fn le_fil_agit_sous(session: HANDLE) -> bool {
    let mut poignee: HANDLE = std::ptr::null_mut();
    // SAFETY: GetCurrentThread rend une pseudo-poignee toujours valide;
    // `poignee` recoit le jeton du fil, que `Jeton` ferme. Ouvert sous
    // l'identite du processus (OpenAsSelf).
    let ok = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut poignee) };
    if ok == 0 {
        return false;
    }
    let fil = Jeton(poignee);
    let du_fil = jeton::lire_le_jeton(fil.0, TokenUser);
    let de_la_session = jeton::lire_le_jeton(session, TokenUser);
    // SAFETY: deux tampons remplis pour TokenUser, chacun un TOKEN_USER dont
    // le SID pointe dans le meme tampon, vivant jusqu'a la fin de l'appel.
    unsafe {
        EqualSid(
            (*du_fil.as_ptr().cast::<TOKEN_USER>()).User.Sid,
            (*de_la_session.as_ptr().cast::<TOKEN_USER>()).User.Sid,
        ) != 0
    }
}

/// Ce que le compte a vu de sa session: son genre, et si le jeton est eleve.
struct Session {
    genre: &'static str,
    eleve: bool,
}

/// Joue `action` dans un fil a lui, sous le jeton du compte: la session est
/// ouverte, le jeton emprunte et verifie, l'action jouee dans un runtime de
/// ce fil, puis le jeton rendu, panique comprise.
fn sous_le_compte<T: Send + 'static>(
    nom: String,
    mdp: String,
    action: impl FnOnce(&tokio::runtime::Runtime) -> T + Send + 'static,
) -> (T, Session) {
    let fil = std::thread::spawn(move || {
        let (jeton, genre) = ouvrir_une_session(&nom, &mdp);
        let eleve = est_eleve(jeton.0);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime du compte");
        // SAFETY: le jeton vient de LogonUserW et vit jusqu'a la fin du fil;
        // RevertToSelf ci-dessous rend au fil le jeton du processus.
        let emprunte = unsafe { ImpersonateLoggedOnUser(jeton.0) };
        assert!(
            emprunte != 0,
            "ImpersonateLoggedOnUser: {}",
            std::io::Error::last_os_error()
        );
        let issue = std::panic::catch_unwind(AssertUnwindSafe(|| {
            assert!(
                le_fil_agit_sous(jeton.0),
                "le fil n'agit pas sous le compte emprunte"
            );
            action(&rt)
        }));
        // SAFETY: rend au fil le jeton du processus; sans argument.
        unsafe { RevertToSelf() };
        match issue {
            Ok(valeur) => (valeur, Session { genre, eleve }),
            Err(panique) => std::panic::resume_unwind(panique),
        }
    });
    fil.join()
        .unwrap_or_else(|panique| std::panic::resume_unwind(panique))
}

/// Les Administrateurs sont-ils actifs dans le jeton de ce fil, ou du
/// processus s'il n'emprunte aucune identite (`CheckTokenMembership`)?
fn administrateurs_actifs() -> bool {
    let mut sid = [0u32; (SECURITY_MAX_SID_SIZE as usize).div_ceil(4)];
    let mut taille = (sid.len() * 4) as u32;
    // SAFETY: le tampon fait au moins SECURITY_MAX_SID_SIZE octets, aligne
    // comme un SID, et sa taille est passee; aucun domaine n'est requis.
    let cree = unsafe {
        CreateWellKnownSid(
            WinBuiltinAdministratorsSid,
            std::ptr::null_mut(),
            sid.as_mut_ptr() as PSID,
            &mut taille,
        )
    };
    assert!(
        cree != 0,
        "CreateWellKnownSid: {}",
        std::io::Error::last_os_error()
    );
    let mut membre = 0;
    // SAFETY: jeton nul, donc celui du fil ou une copie du jeton du
    // processus; le SID est valide et vivant; `membre` est local.
    let lu = unsafe {
        CheckTokenMembership(std::ptr::null_mut(), sid.as_mut_ptr() as PSID, &mut membre)
    };
    assert!(
        lu != 0,
        "CheckTokenMembership: {}",
        std::io::Error::last_os_error()
    );
    membre != 0
}

/// Le SID d'un compte ou d'un groupe LOCAL, resolu par la recette elle-meme
/// (`LookupAccountNameW`), hors du code mesure.
fn sid_local(nom: &str) -> Vec<u8> {
    let nom_l = large(nom);
    let mut taille_sid = 0u32;
    let mut taille_domaine = 0u32;
    let mut type_de_compte: SID_NAME_USE = 0;
    // SAFETY: sonde de taille: tampons nuls de longueur zero, comme l'API le
    // prevoit; `nom_l` est une chaine UTF-16 terminee par un zero.
    unsafe {
        LookupAccountNameW(
            std::ptr::null(),
            nom_l.as_ptr(),
            std::ptr::null_mut(),
            &mut taille_sid,
            std::ptr::null_mut(),
            &mut taille_domaine,
            &mut type_de_compte,
        )
    };
    assert!(
        taille_sid > 0,
        "(e) LookupAccountNameW, sonde: {}",
        std::io::Error::last_os_error()
    );
    let mut sid = vec![0u8; taille_sid as usize];
    let mut domaine = vec![0u16; taille_domaine.max(1) as usize];
    // SAFETY: les tampons sont dimensionnes par la sonde et vivent pendant
    // l'appel; `nom_l` est une chaine UTF-16 terminee par un zero.
    let ok = unsafe {
        LookupAccountNameW(
            std::ptr::null(),
            nom_l.as_ptr(),
            sid.as_mut_ptr() as PSID,
            &mut taille_sid,
            domaine.as_mut_ptr(),
            &mut taille_domaine,
            &mut type_de_compte,
        )
    };
    assert!(
        ok != 0,
        "(e) LookupAccountNameW: {}",
        std::io::Error::last_os_error()
    );
    sid
}

/// La forme textuelle canonique d'un SID, rendue par le systeme.
fn texte_du_sid(sid: &[u8]) -> String {
    let mut texte: windows_sys::core::PWSTR = std::ptr::null_mut();
    // SAFETY: `sid` est un SID que le systeme a rendu; `texte` recoit une
    // allocation du systeme, liberee par LocalFree apres copie.
    let ok = unsafe { ConvertSidToStringSidW(sid.as_ptr() as PSID, &mut texte) };
    assert!(
        ok != 0 && !texte.is_null(),
        "(e) ConvertSidToStringSidW: {}",
        std::io::Error::last_os_error()
    );
    let mut longueur = 0usize;
    // SAFETY: le systeme a rendu une chaine terminee par un zero: la lecture
    // s'arrete sur lui.
    while unsafe { *texte.add(longueur) } != 0 {
        longueur += 1;
    }
    // SAFETY: les `longueur` unites qui precedent le zero sont lisibles.
    let copie = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(texte, longueur) });
    // SAFETY: `texte` a ete alloue par ConvertSidToStringSidW et n'est plus
    // lu.
    unsafe { LocalFree(texte.cast::<c_void>()) };
    copie
}

/// Le domaine et le RID d'une forme canonique `S-1-5-21-a-b-c-RID`, lus par
/// la recette; toute autre forme est un rouge. Le SID ne s'imprime pas.
fn domaine_et_rid(canonique: &str) -> (&str, u32) {
    assert!(
        canonique.starts_with("S-1-5-21-"),
        "(e) une forme hors du domaine des comptes d'une machine"
    );
    let (domaine, rid) = canonique
        .rsplit_once('-')
        .expect("(e) forme S-1-5-21-a-b-c-RID");
    assert_eq!(
        domaine.matches('-').count(),
        6,
        "(e) le domaine n'a pas trois champs apres S-1-5-21"
    );
    let rid: u32 = rid.parse().expect("(e) RID decimal");
    (domaine, rid)
}

/// La classe d'une erreur du groupe, sans le SID qu'elle porte.
fn classe_d_erreur(e: &ErreurGroupe) -> &'static str {
    match e {
        ErreurGroupe::Introuvable { .. } => "introuvable",
        ErreurGroupe::NonAdmissible { .. } => "non admissible",
        ErreurGroupe::PasUnGroupeLocal { .. } => "pas un groupe local",
        ErreurGroupe::Systeme { .. } => "erreur du systeme",
    }
}

/// Le SID est-il celui du compte predefini `genre`?
fn est_connu(sid: &[u8], genre: windows_sys::Win32::Security::WELL_KNOWN_SID_TYPE) -> bool {
    // SAFETY: SID lu dans une DACL du systeme, dans un tampon vivant.
    unsafe { IsWellKnownSid(sid.as_ptr() as PSID, genre) != 0 }
}

/// Deux SID valides, compares par le systeme.
fn egaux(a: &[u8], b: &[u8]) -> bool {
    // SAFETY: deux SID valides, lus seulement.
    unsafe { EqualSid(a.as_ptr() as PSID, b.as_ptr() as PSID) != 0 }
}

/// Une ACE d'autorisation lue dans la DACL d'un pipe: masque et SID.
struct AceLue {
    masque: u32,
    sid: Vec<u8>,
}

/// La DACL du pipe `chemin`, lue par une poignee de client ouverte aux droits
/// du client de `bifrost-ipc` (dont `READ_CONTROL`), telle que le noyau la
/// garde: `GA` y est deja traduit. Toute ACE qui n'est pas une autorisation
/// est un rouge.
fn dacl_du_pipe(chemin: &str) -> Vec<AceLue> {
    let client = std::fs::OpenOptions::new()
        .access_mode(DROITS_DU_CLIENT)
        .security_qos_flags(IDENTIFICATION_SEULE)
        .open(chemin)
        .unwrap_or_else(|e| panic!("(e) ouverture du pipe pour lire sa DACL: {e}"));
    let mut liste: *mut ACL = std::ptr::null_mut();
    let mut descripteur: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: la poignee du client vit jusqu'a la fin de la fonction; seule
    // la DACL est demandee, les autres sorties sont nulles; `liste` pointe
    // DANS `descripteur`, alloue par le systeme et libere ci-dessous.
    let rc = unsafe {
        GetSecurityInfo(
            client.as_raw_handle(),
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut liste,
            std::ptr::null_mut(),
            &mut descripteur,
        )
    };
    assert_eq!(rc, 0, "(e) GetSecurityInfo(DACL)");
    assert!(!liste.is_null(), "(e) le pipe n'a pas de DACL");
    let mut aces = Vec::new();
    // SAFETY: `liste` est une ACL valide rendue par le systeme.
    let nombre = unsafe { (*liste).AceCount };
    for rang in 0..u32::from(nombre) {
        let mut ace: *mut c_void = std::ptr::null_mut();
        // SAFETY: `rang` est sous AceCount; `ace` pointe dans la liste.
        let lue = unsafe { GetAce(liste, rang, &mut ace) };
        assert!(lue != 0, "(e) GetAce({rang})");
        // SAFETY: toute ACE commence par son en-tete.
        let entete = unsafe { *(ace as *const ACE_HEADER) };
        assert_eq!(
            entete.AceType, ACE_D_AUTORISATION,
            "(e) ACE {rang}: une autorisation est attendue"
        );
        // SAFETY: une ACE d'autorisation a la forme ACCESS_ALLOWED_ACE, son
        // SID commence a SidStart et finit avec l'ACE (AceSize).
        let (masque, sid) = unsafe {
            let a = ace as *const ACCESS_ALLOWED_ACE;
            let debut = std::ptr::addr_of!((*a).SidStart) as *const u8;
            let longueur = usize::from(entete.AceSize) - 8;
            (
                (*a).Mask,
                std::slice::from_raw_parts(debut, longueur).to_vec(),
            )
        };
        aces.push(AceLue { masque, sid });
    }
    // SAFETY: `descripteur` a ete alloue par GetSecurityInfo; `liste`, qui
    // pointe dedans, n'est plus lue.
    unsafe { LocalFree(descripteur) };
    aces
}

/// Les sept commandes que le daemon reserve aux administrateurs.
fn commandes_reservees() -> Vec<Command> {
    let config = serde_json::from_value(serde_json::json!({
        "interface": "wg0",
        "private_key": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaA=",
        "addresses": ["10.2.0.2/32"],
        "peer": {
            "public_key": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbA=",
            "endpoint": { "addr": "203.0.113.7:51820" },
            "allowed_ips": ["0.0.0.0/0"]
        },
        "dns": { "local_resolver": "127.0.0.1", "upstream": ["10.2.0.1"] }
    }))
    .expect("profil de recette");
    vec![
        Command::Connect {
            config: Box::new(config),
        },
        Command::Check,
        Command::VerdictInspectionTls { intercepte: true },
        Command::Reprise,
        Command::DeclarationPareFeu,
        Command::DeclarationRoutage,
        Command::DeclarationDns,
    ]
}

/// Envoie chaque commande sur une connexion neuve, ouverte comme celles de
/// la CLI (`connect_verified`, exigence des commandes), et rend la reponse
/// du serveur.
async fn envoyer(chemin: &str, commandes: Vec<Command>) -> Vec<(&'static str, Response)> {
    let mut issues = Vec::new();
    for commande in commandes {
        let nom = commande.name();
        let (mut client, _regle) = IpcClient::connect_verified(chemin, ServerRequirement::Elevated)
            .await
            .unwrap_or_else(|e| panic!("{nom}: ouverture du canal: {e}"));
        let reponse = client
            .request(&Request::new(commande))
            .await
            .unwrap_or_else(|e| panic!("{nom}: echange: {e}"));
        issues.push((nom, reponse));
    }
    issues
}

/// Les trois commandes du poste de commande, dans l'ordre, sur le canal.
async fn trois_commandes(chemin: &str) -> [(&'static str, Result<(), ErreurCommande>); 3] {
    let poste = Commande::new(chemin);
    let etat = poste.etat().await.map(|status| {
        assert_eq!(status, faux_daemon::status_de_reference(), "status");
    });
    [
        ("status", etat),
        ("connect-stored", poste.connecter().await),
        ("disconnect", poste.deconnecter().await),
    ]
}

#[test]
fn le_groupe_d_acces_admet_ses_membres_et_eux_seuls() {
    if let Some(raison) = raison_de_s_abstenir() {
        println!("SKIPPED {NOM_RECETTE}: {raison}");
        return;
    }

    // Le pipe appartient aux Administrateurs: sur le runner, un jeton eleve
    // a pour proprietaire par defaut le compte, que la regle des commandes
    // n'admet pas.
    let avant = jeton::proprietaire_par_defaut();
    println!(
        "RELEVE groupe_d_acces: integrite={}, proprietaire par defaut avant={}",
        jeton::integrite().nom(),
        avant.nom()
    );
    if avant != Proprietaire::Administrateurs {
        jeton::poser_les_administrateurs()
            .unwrap_or_else(|e| panic!("pose des Administrateurs: {e}"));
    }
    assert_eq!(
        jeton::proprietaire_par_defaut(),
        Proprietaire::Administrateurs,
        "proprietaire par defaut relu apres la pose"
    );

    let pid = std::process::id();
    let nom_groupe = format!("bfessai-{pid}");
    let (membre, autre) = (format!("bfm{pid}"), format!("bfa{pid}"));
    let (mdp_membre, mdp_autre) = (mot_de_passe(), mot_de_passe());

    let mut jetables = Jetables::default();
    jetables.creer_le_groupe(&nom_groupe);
    jetables.creer_le_compte(&membre, &mdp_membre);
    jetables.creer_le_compte(&autre, &mdp_autre);
    jetables.ajouter_au_groupe(&membre);

    let groupe = GroupeDAcces::resoudre(&nom_groupe).expect("le groupe cree localement est admis");

    // (e), le groupe reel: la forme d'un compte cree, et le domaine des
    // comptes que la recette vient de creer dans la base locale, resolus par
    // elle (`LookupAccountNameW`); le groupe retenu est bien celui que la
    // recette resout sous ce nom. Aucun SID ne s'imprime, meme sur un rouge.
    let (domaine, rid) = domaine_et_rid(groupe.sid());
    assert!(
        rid >= PREMIER_RID_CREE,
        "(e) le groupe cree porte un RID predefini: {rid}"
    );
    assert!(
        groupe.sid() == texte_du_sid(&sid_local(&nom_groupe)),
        "(e) le groupe retenu n'est pas celui que la recette resout sous ce nom"
    );
    for compte in [&membre, &autre] {
        let canonique = texte_du_sid(&sid_local(compte));
        let (domaine_du_compte, rid_du_compte) = domaine_et_rid(&canonique);
        assert!(
            domaine_du_compte == domaine,
            "(e) le groupe et un compte crees ici n'ont pas le meme domaine"
        );
        assert!(
            rid_du_compte >= PREMIER_RID_CREE,
            "(e) un compte cree ici porte un RID predefini: {rid_du_compte}"
        );
    }
    // Une forme equivalente du SID du groupe (zeros de tete, minuscules) est
    // resolue, et rendue sous la forme canonique: le meme groupe.
    for (rang, designation) in [
        format!("{domaine}-0{rid}"),
        format!("{domaine}-00{rid}").to_lowercase(),
    ]
    .into_iter()
    .enumerate()
    {
        let equivalent = GroupeDAcces::resoudre(&designation).unwrap_or_else(|e| {
            panic!(
                "(e) forme equivalente {rang} du groupe refusee: {}",
                classe_d_erreur(&e)
            )
        });
        assert!(
            equivalent == groupe && equivalent.sid() == groupe.sid(),
            "(e) la forme equivalente {rang} n'est pas rendue sous la forme canonique du groupe"
        );
    }
    // Le meme domaine avec le RID 500, l'administrateur integre de la machine
    // (sur le runner, le compte de la recette elle-meme): juge, et seulement
    // juge; refuse par la forme, sous sa forme canonique.
    let predefini = format!("{domaine}-{RID_ADMINISTRATEUR_INTEGRE}");
    match GroupeDAcces::resoudre(&predefini) {
        Err(ErreurGroupe::NonAdmissible { nom, sid }) => assert!(
            nom == predefini && sid == predefini,
            "(e) le refus du RID predefini ne nomme pas la designation sous sa forme canonique"
        ),
        Err(autre) => panic!(
            "(e) le RID predefini est refuse pour une autre raison: {}",
            classe_d_erreur(&autre)
        ),
        Ok(_) => panic!("(e) le RID predefini de la machine est admis comme groupe d'acces"),
    }
    println!(
        "RELEVE groupe_d_acces: (e) groupe resolu: forme d'un compte cree, domaine des comptes \
         crees ici; forme equivalente rendue canonique; RID predefini refuse non admissible"
    );

    let chemin = format!(r"\\.\pipe\bifrost-coquille-{pid}-groupe");
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("runtime du serveur");

    // (e), la DACL du pipe que le vrai serveur lie avec ce groupe, lue par
    // une poignee de client sur une instance a part (le processus eleve y a
    // READ_CONTROL par l'ACE des Administrateurs): trois ACE d'autorisation,
    // SYSTEM et les Administrateurs a tous les droits tels que le noyau les
    // traduit, le groupe a son masque, et rien d'autre.
    let chemin_dacl = format!(r"\\.\pipe\bifrost-coquille-{pid}-groupe-dacl");
    let serveur_dacl = rt
        .block_on(IpcServer::bind(
            &chemin_dacl,
            AuthPolicy::default(),
            Some(groupe.clone()),
        ))
        .expect("(e) bind du serveur dont la DACL se lit");
    let aces = dacl_du_pipe(&chemin_dacl);
    drop(serveur_dacl);
    assert_eq!(aces.len(), 3, "(e) la DACL du pipe lie avec le groupe");
    assert!(
        est_connu(&aces[0].sid, WinLocalSystemSid),
        "(e) la premiere ACE n'est pas SYSTEM"
    );
    assert!(
        est_connu(&aces[1].sid, WinBuiltinAdministratorsSid),
        "(e) la deuxieme ACE n'est pas les Administrateurs"
    );
    assert_eq!(
        aces[0].masque, TOUS_LES_DROITS_DU_PIPE,
        "(e) masque de SYSTEM"
    );
    assert_eq!(
        aces[1].masque, TOUS_LES_DROITS_DU_PIPE,
        "(e) masque des Administrateurs"
    );
    assert!(
        texte_du_sid(&aces[2].sid) == groupe.sid(),
        "(e) la troisieme ACE ne nomme pas le groupe sous sa forme canonique"
    );
    assert!(
        egaux(&aces[2].sid, &sid_local(&nom_groupe)),
        "(e) la troisieme ACE ne nomme pas le groupe que la recette resout"
    );
    assert_eq!(
        aces[2].masque, MASQUE_DU_GROUPE,
        "(e) masque de l'ACE du groupe"
    );
    println!(
        "RELEVE groupe_d_acces: (e) DACL du pipe lie: {} ACE, SYSTEM et Administrateurs a {:#x}, \
         le groupe a {:#x}",
        aces.len(),
        aces[0].masque,
        aces[2].masque
    );

    let serveur = rt
        .block_on(IpcServer::bind(
            &chemin,
            AuthPolicy::default(),
            Some(groupe),
        ))
        .expect("bind du vrai serveur IPC avec le groupe d'acces");
    let recues = faux_daemon::Recues::default();
    let tache = rt.spawn(faux_daemon::servir(serveur, recues.clone()));
    let trois = ["status", "connect-stored", "disconnect"];

    // (a), (b) et (d): le membre.
    let pour_le_membre = chemin.clone();
    let ((commandes, instance, generique, reservees), session) =
        sous_le_compte(membre.clone(), mdp_membre, move |rt| {
            let commandes = rt.block_on(trois_commandes(&pour_le_membre));
            let instance = rt.block_on(async {
                ServerOptions::new()
                    .first_pipe_instance(false)
                    .reject_remote_clients(true)
                    .create(&pour_le_membre)
                    .map(|_| ())
            });
            let generique =
                rt.block_on(async { ClientOptions::new().open(&pour_le_membre).map(|_| ()) });
            let reservees = rt.block_on(envoyer(&pour_le_membre, commandes_reservees()));
            (commandes, instance, generique, reservees)
        });
    println!(
        "RELEVE groupe_d_acces: membre, session {}, eleve={}",
        session.genre, session.eleve
    );
    assert!(!session.eleve, "le jeton du membre est eleve");
    for (commande, issue) in &commandes {
        assert_eq!(issue, &Ok(()), "(a) membre, {commande}");
    }
    assert_eq!(
        instance.map_err(|e| e.raw_os_error()),
        Err(Some(ERROR_ACCESS_DENIED as i32)),
        "(b) le membre a ajoute une instance au pipe, ou une autre erreur"
    );
    assert_eq!(
        generique.map_err(|e| e.raw_os_error()),
        Err(Some(ERROR_ACCESS_DENIED as i32)),
        "(b) le membre ouvre le pipe en GENERIC_READ|GENERIC_WRITE, ou une autre erreur"
    );
    assert_eq!(reservees.len(), 7, "(d) sept commandes reservees");
    for &(commande, ref reponse) in &reservees {
        match reponse {
            Response::Error { message } => assert_eq!(
                message,
                &CommandeReservee { commande }.to_string(),
                "(d) membre, {commande}"
            ),
            autre => panic!("(d) membre, {commande}: refus attendu, recu {autre:?}"),
        }
    }
    assert_eq!(
        *recues.lock().expect("commandes recues"),
        trois,
        "(d) le serveur a recu autre chose que les trois commandes du membre"
    );

    // (c): le non-membre.
    let pour_l_autre = chemin.clone();
    let (commandes, session) = sous_le_compte(autre.clone(), mdp_autre, move |rt| {
        rt.block_on(trois_commandes(&pour_l_autre))
    });
    println!(
        "RELEVE groupe_d_acces: non-membre, session {}, eleve={}",
        session.genre, session.eleve
    );
    assert!(!session.eleve, "le jeton du non-membre est eleve");
    for (commande, issue) in commandes {
        let e = issue.expect_err("(c) le non-membre a ete admis");
        assert!(
            matches!(e, ErreurCommande::CompteNonAdmis(_)),
            "(c) non-membre, {commande}: {e:?}"
        );
        let vue = Vue::depuis_erreur(&e);
        assert_eq!(vue.etat, EtatVue::CompteNonAdmis, "(c) {commande}");
        assert_ne!(vue.couleur, CouleurTray::Vert, "(c) {commande}");
    }
    assert_eq!(
        *recues.lock().expect("commandes recues"),
        trois,
        "(c) le non-membre a atteint le serveur"
    );

    // (d), suite: le processus de la recette, aux Administrateurs actifs,
    // garde tout le canal. Le faux daemon, qui ne sert que les trois
    // commandes, repond << commande inattendue >> a chacune: la preuve
    // qu'elle lui est parvenue.
    let actifs = administrateurs_actifs();
    println!("RELEVE groupe_d_acces: processus de la recette, administrateurs actifs={actifs}");
    assert!(
        actifs,
        "(d) le processus de la recette n'a pas les Administrateurs actifs"
    );
    let reservees = rt.block_on(envoyer(&chemin, commandes_reservees()));
    for (commande, reponse) in &reservees {
        match reponse {
            Response::Error { message } => assert_eq!(
                message,
                &format!("commande inattendue: {commande}"),
                "(d) administrateur, {commande}"
            ),
            autre => panic!("(d) administrateur, {commande}: recu {autre:?}"),
        }
    }
    let attendues: Vec<&str> = trois
        .into_iter()
        .chain(reservees.iter().map(|(commande, _)| *commande))
        .collect();
    assert_eq!(
        *recues.lock().expect("commandes recues"),
        attendues,
        "(d) les commandes de l'administrateur ne sont pas toutes parvenues au serveur"
    );

    tache.abort();
    drop(rt);
    drop(jetables);

    // Le menage, relu aupres du systeme: la garde a imprime les codes de
    // retrait, elle ne les a pas juges. Un groupe ou un compte jetable qui
    // survivrait est un rouge, pas une ligne de journal.
    assert_eq!(
        le_groupe_existe(&nom_groupe),
        Ok(false),
        "le groupe jetable existe encore apres le menage"
    );
    for compte in [&membre, &autre] {
        assert_eq!(
            le_compte_existe(compte),
            Ok(false),
            "le compte jetable existe encore apres le menage"
        );
    }
}
