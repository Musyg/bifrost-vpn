//! Le poste de commande face a un vrai `IpcServer`, sous Windows: par son
//! seul chemin public, `Commande::new`, il lui fait servir `status`,
//! `connect-stored` et `disconnect`.
//!
//! La regle des commandes n'admet qu'un pipe de LocalSystem ou des
//! Administrateurs, et un objet cree sans proprietaire explicite recoit le
//! proprietaire par defaut du jeton de son createur, `TokenOwner`
//! ([MS-DTYP] 2.5.3.4.1). La recette ne suppose rien de ce proprietaire par
//! defaut: elle le lit, puis pose les Administrateurs comme proprietaire par
//! defaut de son jeton, ce que fait l'elevation par UAC, le relit, et
//! seulement alors lie le serveur. Le systeme refuse la pose
//! (`ERROR_INVALID_OWNER`) quand les Administrateurs ne sont pas eligibles
//! comme proprietaire dans ce jeton: la recette s'abstient alors, et le dit.
//!
//! Un binaire a part: la pose modifie le jeton du PROCESSUS, et aucune autre
//! recette ne tourne dans ce processus. Ni jeton de fil, ni impersonation.
//!
//! Ce qu'elle lit s'imprime par classes, jamais par SID:
//! `RELEVE eleve_ipc: integrite=..., proprietaire par defaut avant=...`, puis,
//! apres la pose, `RELEVE eleve_ipc: proprietaire par defaut apres=...`.

#![cfg(windows)]

#[path = "commun/faux_daemon.rs"]
mod faux_daemon;

use bifrost_coquille::Commande;
use bifrost_ipc::{AuthPolicy, IpcServer};
use jeton::{Integrite, Proprietaire};
use windows_sys::Win32::Foundation::ERROR_INVALID_OWNER;

/// L'issue de la pose des Administrateurs comme proprietaire par defaut.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pose {
    /// Deja proprietaire par defaut: rien n'est pose.
    Deja,
    /// Posee par `SetTokenInformation`.
    Posee,
    /// Refusee par `ERROR_INVALID_OWNER`: les Administrateurs ne sont pas
    /// eligibles comme proprietaire dans ce jeton.
    NonEligible,
}

/// Le dialogue avec un vrai serveur IPC, une fois les Administrateurs poses
/// comme proprietaire par defaut du jeton et relus. Le niveau d'integrite
/// sert de controle croise de la pose: un jeton eleve ou systeme qui la
/// refuse, ou un jeton moyen dont les Administrateurs sont ou deviennent le
/// proprietaire par defaut, se contredisent, et la recette rougit en
/// imprimant les deux. Toute erreur de la pose autre que
/// `ERROR_INVALID_OWNER` est un rouge.
#[tokio::test(flavor = "multi_thread")]
async fn eleve_la_commande_dialogue_avec_un_vrai_serveur_ipc() {
    let integrite = jeton::integrite();
    let avant = jeton::proprietaire_par_defaut();
    println!(
        "RELEVE eleve_ipc: integrite={}, proprietaire par defaut avant={}",
        integrite.nom(),
        avant.nom()
    );

    let pose = if avant == Proprietaire::Administrateurs {
        Pose::Deja
    } else {
        match jeton::poser_les_administrateurs() {
            Ok(()) => Pose::Posee,
            Err(e) if e.raw_os_error() == Some(ERROR_INVALID_OWNER as i32) => Pose::NonEligible,
            Err(e) => panic!("pose des Administrateurs comme proprietaire par defaut: {e}"),
        }
    };
    match (integrite, pose) {
        (Integrite::Eleve | Integrite::Systeme, Pose::Deja | Pose::Posee) => {}
        (Integrite::Moyen, Pose::NonEligible) => {
            println!(
                "SKIPPED eleve_la_commande_dialogue_avec_un_vrai_serveur_ipc: les \
                 Administrateurs ne sont pas eligibles comme proprietaire dans le jeton de ce \
                 processus (ERROR_INVALID_OWNER), et la regle des commandes n'admet qu'un pipe \
                 de LocalSystem ou des Administrateurs"
            );
            return;
        }
        (Integrite::Eleve | Integrite::Systeme, Pose::NonEligible)
        | (Integrite::Moyen, Pose::Deja | Pose::Posee) => panic!(
            "contradiction: integrite={}, pose des Administrateurs comme proprietaire par \
             defaut: {pose:?}",
            integrite.nom()
        ),
    }

    let apres = jeton::proprietaire_par_defaut();
    println!(
        "RELEVE eleve_ipc: proprietaire par defaut apres={}",
        apres.nom()
    );
    assert_eq!(
        apres,
        Proprietaire::Administrateurs,
        "le proprietaire par defaut relu apres la pose ({pose:?})"
    );

    let path = format!(r"\\.\pipe\bifrost-coquille-{}-eleve", std::process::id());
    let server = IpcServer::bind(&path, AuthPolicy::default(), None)
        .await
        .expect("bind du vrai serveur IPC");
    let tache = tokio::spawn(faux_daemon::servir(server));

    let poste = Commande::new(path);
    assert_eq!(poste.etat().await, Ok(faux_daemon::status_de_reference()));
    poste.connecter().await.expect("connect-stored");
    poste.deconnecter().await.expect("disconnect");
    tache.abort();
}

/// Le jeton du processus, lu et modifie par les appels du systeme. Les SID
/// se comparent par `IsWellKnownSid` et `EqualSid`, jamais en chaines, et
/// aucun ne sort de ce module.
mod jeton {
    use std::ffi::c_void;

    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{
        CreateWellKnownSid, EqualSid, GetSidSubAuthority, GetSidSubAuthorityCount,
        GetTokenInformation, IsWellKnownSid, SECURITY_MAX_SID_SIZE, SetTokenInformation,
        TOKEN_ACCESS_MASK, TOKEN_ADJUST_DEFAULT, TOKEN_INFORMATION_CLASS, TOKEN_MANDATORY_LABEL,
        TOKEN_OWNER, TOKEN_QUERY, TOKEN_USER, TokenIntegrityLevel, TokenOwner, TokenUser,
        WinBuiltinAdministratorsSid, WinLocalSystemSid,
    };
    use windows_sys::Win32::System::SystemServices::{
        SECURITY_MANDATORY_HIGH_RID, SECURITY_MANDATORY_MEDIUM_RID, SECURITY_MANDATORY_SYSTEM_RID,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    /// Le niveau d'integrite du jeton, lu par le dernier RID de son etiquette.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Integrite {
        Moyen,
        Eleve,
        Systeme,
    }

    impl Integrite {
        pub fn nom(self) -> &'static str {
            match self {
                Self::Moyen => "moyen",
                Self::Eleve => "eleve",
                Self::Systeme => "systeme",
            }
        }
    }

    /// Le proprietaire par defaut du jeton, classe dans cet ordre.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Proprietaire {
        /// Les Administrateurs, `S-1-5-32-544`.
        Administrateurs,
        /// LocalSystem, `S-1-5-18`.
        Systeme,
        /// Le compte qui execute la recette, `TokenUser`.
        Compte,
        /// Tout autre SID.
        Autre,
    }

    impl Proprietaire {
        pub fn nom(self) -> &'static str {
            match self {
                Self::Administrateurs => "administrateurs",
                Self::Systeme => "systeme",
                Self::Compte => "compte",
                Self::Autre => "autre",
            }
        }
    }

    /// Le jeton du processus, ouvert avec un acces donne, ferme quand il sort
    /// de portee.
    struct Jeton(HANDLE);

    impl Jeton {
        fn ouvrir(acces: TOKEN_ACCESS_MASK) -> Self {
            let mut poignee: HANDLE = std::ptr::null_mut();
            // SAFETY: GetCurrentProcess rend une pseudo-poignee qui n'a pas a
            // etre fermee; `poignee` est une variable locale qui recoit, a la
            // reussite, une poignee de jeton que Drop ferme une fois.
            let ok = unsafe { OpenProcessToken(GetCurrentProcess(), acces, &mut poignee) };
            assert!(
                ok != 0,
                "OpenProcessToken: {}",
                std::io::Error::last_os_error()
            );
            Self(poignee)
        }

        /// Une classe d'information du jeton, dans un tampon dimensionne par
        /// un premier appel et aligne sur 8 octets, comme les pointeurs des
        /// structures qu'il porte.
        fn lire(&self, classe: TOKEN_INFORMATION_CLASS) -> Vec<u64> {
            let mut taille = 0u32;
            // SAFETY: la poignee est ouverte avec TOKEN_QUERY; un tampon nul
            // de taille zero ne demande que la taille requise, ecrite dans
            // `taille`, une variable locale.
            unsafe { GetTokenInformation(self.0, classe, std::ptr::null_mut(), 0, &mut taille) };
            assert!(
                taille > 0,
                "GetTokenInformation({classe}), taille: {}",
                std::io::Error::last_os_error()
            );
            let mut tampon = vec![0u64; (taille as usize).div_ceil(8)];
            // SAFETY: `tampon` fait au moins `taille` octets, la taille rendue
            // par l'appel precedent, et `taille` decrit sa capacite.
            let ok = unsafe {
                GetTokenInformation(
                    self.0,
                    classe,
                    tampon.as_mut_ptr().cast::<c_void>(),
                    taille,
                    &mut taille,
                )
            };
            assert!(
                ok != 0,
                "GetTokenInformation({classe}): {}",
                std::io::Error::last_os_error()
            );
            tampon
        }
    }

    impl Drop for Jeton {
        fn drop(&mut self) {
            // SAFETY: la poignee a ete ouverte par OpenProcessToken et n'est
            // fermee qu'ici, une fois.
            unsafe { CloseHandle(self.0) };
        }
    }

    /// Le niveau d'integrite du jeton du processus. Un RID hors des trois
    /// classes est un rouge: la recette ne sait pas en tirer de controle.
    pub fn integrite() -> Integrite {
        let etiquette = Jeton::ouvrir(TOKEN_QUERY).lire(TokenIntegrityLevel);
        // SAFETY: `etiquette`, aligne sur 8 octets, a ete rempli par
        // GetTokenInformation(TokenIntegrityLevel): il commence par un
        // TOKEN_MANDATORY_LABEL, dont le SID pointe dans ce meme tampon.
        let sid = unsafe {
            (*etiquette.as_ptr().cast::<TOKEN_MANDATORY_LABEL>())
                .Label
                .Sid
        };
        // SAFETY: `sid` est un SID valide, vivant tant que `etiquette` l'est;
        // le pointeur rendu designe son compte de sous-autorites, lu aussitot.
        let sous_autorites = unsafe { *GetSidSubAuthorityCount(sid) };
        assert!(
            sous_autorites > 0,
            "etiquette d'integrite sans sous-autorite"
        );
        // SAFETY: meme SID, toujours vivant; l'indice est le dernier,
        // inferieur au compte lu, et le pointeur rendu est lu aussitot.
        let rid = unsafe { *GetSidSubAuthority(sid, u32::from(sous_autorites) - 1) };
        match i32::try_from(rid) {
            Ok(SECURITY_MANDATORY_MEDIUM_RID) => Integrite::Moyen,
            Ok(SECURITY_MANDATORY_HIGH_RID) => Integrite::Eleve,
            Ok(SECURITY_MANDATORY_SYSTEM_RID) => Integrite::Systeme,
            _ => panic!("niveau d'integrite que la recette ne sait pas classer: {rid:#x}"),
        }
    }

    /// Le proprietaire par defaut du jeton du processus, classe par le
    /// systeme: Administrateurs, puis LocalSystem, puis le compte, sinon
    /// autre.
    pub fn proprietaire_par_defaut() -> Proprietaire {
        let jeton = Jeton::ouvrir(TOKEN_QUERY);
        let proprietaire = jeton.lire(TokenOwner);
        let utilisateur = jeton.lire(TokenUser);
        // SAFETY: `proprietaire`, aligne sur 8 octets, a ete rempli par
        // GetTokenInformation(TokenOwner): il commence par un TOKEN_OWNER,
        // dont le SID pointe dans ce meme tampon.
        let sid = unsafe { (*proprietaire.as_ptr().cast::<TOKEN_OWNER>()).Owner };
        // SAFETY: de meme pour `utilisateur`, rempli pour TokenUser: un
        // TOKEN_USER en tete, dont le SID pointe dans ce meme tampon.
        let compte = unsafe { (*utilisateur.as_ptr().cast::<TOKEN_USER>()).User.Sid };
        // SAFETY: `sid` et `compte` sont des SID valides, qui vivent dans les
        // deux tampons jusqu'a la fin de la fonction; les trois appels ne
        // font que les lire.
        unsafe {
            if IsWellKnownSid(sid, WinBuiltinAdministratorsSid) != 0 {
                Proprietaire::Administrateurs
            } else if IsWellKnownSid(sid, WinLocalSystemSid) != 0 {
                Proprietaire::Systeme
            } else if EqualSid(sid, compte) != 0 {
                Proprietaire::Compte
            } else {
                Proprietaire::Autre
            }
        }
    }

    /// Pose les Administrateurs comme proprietaire par defaut du jeton du
    /// processus, et rend l'erreur du systeme telle quelle.
    pub fn poser_les_administrateurs() -> std::io::Result<()> {
        let jeton = Jeton::ouvrir(TOKEN_QUERY | TOKEN_ADJUST_DEFAULT);
        let mut administrateurs = vec![0u64; (SECURITY_MAX_SID_SIZE as usize).div_ceil(8)];
        let mut taille = SECURITY_MAX_SID_SIZE;
        // SAFETY: le tampon fait au moins SECURITY_MAX_SID_SIZE octets, et
        // `taille` le dit; le SID des Administrateurs ne demande aucun SID de
        // domaine.
        let ok = unsafe {
            CreateWellKnownSid(
                WinBuiltinAdministratorsSid,
                std::ptr::null_mut(),
                administrateurs.as_mut_ptr().cast::<c_void>(),
                &mut taille,
            )
        };
        assert!(
            ok != 0,
            "CreateWellKnownSid: {}",
            std::io::Error::last_os_error()
        );
        let proprietaire = TOKEN_OWNER {
            Owner: administrateurs.as_mut_ptr().cast::<c_void>(),
        };
        // SAFETY: la poignee est ouverte avec TOKEN_ADJUST_DEFAULT;
        // `proprietaire` est un TOKEN_OWNER de la taille passee, et le SID
        // qu'il designe, `administrateurs`, vit jusqu'a la fin de l'appel.
        let ok = unsafe {
            SetTokenInformation(
                jeton.0,
                TokenOwner,
                (&proprietaire as *const TOKEN_OWNER).cast::<c_void>(),
                std::mem::size_of::<TOKEN_OWNER>() as u32,
            )
        };
        if ok != 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }
}
