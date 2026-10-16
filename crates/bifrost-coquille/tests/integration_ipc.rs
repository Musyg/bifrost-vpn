//! Le poste de commande face a un vrai canal, par son seul chemin public:
//! `Commande::new`, qui exige du serveur l'identite du daemon
//! (`ServerRequirement::Elevated`) avant d'ecrire quoi que ce soit.
//!
//! - Un faux serveur tenu par un compte ordinaire est refuse et ne recoit
//!   AUCUN octet, sur chacune des trois commandes. Linux: un socket ecoute
//!   par le compte de la recette (admis seulement si elle tourne en root, et
//!   la recette exige alors qu'il ait recu les commandes). Windows: un pipe
//!   dont le proprietaire et la DACL nomment le compte de la recette, poses
//!   explicitement, pour que le refus ne depende pas du proprietaire par
//!   defaut du jeton.
//! - Un canal qui existe et ne prend aucune connexion de plus est << sans
//!   reponse dans le delai >>, et un canal absent est injoignable: deux etats
//!   distincts, aucun vert.
//! - Un canal qui existe et dont les droits ferment l'ouverture a ce compte
//!   rend le compte << non admis par le canal >>: ni injoignable, ni vert.
//!
//! Le dialogue avec un vrai `IpcServer` sous Windows est dans
//! `tests/eleve_ipc.rs`, un binaire a part: il modifie le jeton de son
//! processus. Sous Linux, l'admission d'un faux daemon passe par la couture
//! d'exigence de `src/commande.rs`, qui n'existe que dans les recettes du
//! crate: ici, rien ne peut exiger autre chose que le chemin de production.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bifrost_coquille::{Commande, CouleurTray, ErreurCommande, EtatVue, Vue};
use bifrost_ipc::ServerIdentityError;
use tokio::io::{AsyncRead, AsyncReadExt};

/// Lit ce qu'un client envoie sur une connexion, jusqu'a la fin de ligne ou
/// du flux, ne repond jamais, et compte la connexion APRES la lecture: une
/// connexion comptee est une connexion dont tout ce qui est arrive a ete
/// releve.
async fn lire<R: AsyncRead + Unpin>(
    mut flux: R,
    connexions: Arc<AtomicUsize>,
    recus: Arc<Mutex<Vec<u8>>>,
) {
    let mut lu = Vec::new();
    let mut tampon = [0u8; 4096];
    let _ = tokio::time::timeout(Duration::from_secs(5), async {
        while let Ok(n) = flux.read(&mut tampon).await {
            if n == 0 {
                break;
            }
            lu.extend_from_slice(&tampon[..n]);
            if lu.ends_with(b"\n") {
                break;
            }
        }
    })
    .await;
    recus.lock().unwrap().extend_from_slice(&lu);
    connexions.fetch_add(1, Ordering::SeqCst);
}

/// Un faux serveur du COMPTE de la recette: il accepte, lit, ne repond
/// jamais, et compte connexions et octets.
struct Faux {
    socket: String,
    connexions: Arc<AtomicUsize>,
    recus: Arc<Mutex<Vec<u8>>>,
    tache: tokio::task::JoinHandle<()>,
}

impl Faux {
    #[cfg(unix)]
    fn demarrer(nom: &str) -> Self {
        let chemin = std::env::temp_dir().join(format!(
            "bifrost-coquille-{}-{nom}.sock",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&chemin);
        let ecoute = tokio::net::UnixListener::bind(&chemin).expect("ecoute du faux serveur");
        let (connexions, recus) = (Arc::default(), Arc::default());
        let (c, r) = (Arc::clone(&connexions), Arc::clone(&recus));
        let tache = tokio::spawn(async move {
            while let Ok((flux, _)) = ecoute.accept().await {
                tokio::spawn(lire(flux, Arc::clone(&c), Arc::clone(&r)));
            }
        });
        Self {
            socket: chemin.to_string_lossy().into_owned(),
            connexions,
            recus,
            tache,
        }
    }

    #[cfg(windows)]
    fn demarrer(nom: &str) -> Self {
        let socket = format!(r"\\.\pipe\bifrost-coquille-{}-{nom}", std::process::id());
        // Le proprietaire et le seul compte admis par la DACL: le compte de
        // la recette, pose ici pour que le refus ne depende pas du
        // proprietaire par defaut du jeton.
        let sid = windows::sid_du_compte_courant();
        let sddl = format!("O:{sid}D:P(A;;GA;;;{sid})");
        let premiere =
            windows::instance(&socket, &sddl, true).expect("premiere instance du faux serveur");
        let (connexions, recus) = (Arc::default(), Arc::default());
        let (c, r) = (Arc::clone(&connexions), Arc::clone(&recus));
        let nom_pipe = socket.clone();
        let tache = tokio::spawn(async move {
            let mut courante = premiere;
            while courante.connect().await.is_ok() {
                let Ok(suivante) = windows::instance(&nom_pipe, &sddl, false) else {
                    return;
                };
                let servie = std::mem::replace(&mut courante, suivante);
                tokio::spawn(lire(servie, Arc::clone(&c), Arc::clone(&r)));
            }
        });
        Self {
            socket,
            connexions,
            recus,
            tache,
        }
    }

    /// Attend qu'au moins `n` connexions aient ete relevees, puis laisse a
    /// celles qui suivraient le temps d'arriver, et rend les octets recus et
    /// le nombre de connexions relevees.
    async fn apres(&self, n: usize) -> (Vec<u8>, usize) {
        for _ in 0..100 {
            if self.connexions.load(Ordering::SeqCst) >= n {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
        let connexions = self.connexions.load(Ordering::SeqCst);
        assert!(
            connexions >= n,
            "le poste de commande n'a pas joint le faux serveur: un zero octet ne prouverait rien"
        );
        (self.recus.lock().unwrap().clone(), connexions)
    }
}

impl Drop for Faux {
    fn drop(&mut self) {
        self.tache.abort();
        #[cfg(unix)]
        let _ = std::fs::remove_file(&self.socket);
    }
}

/// Vrai si la recette tourne en root: le faux serveur est alors privilegie.
#[cfg(unix)]
fn serveur_privilegie() -> bool {
    // SAFETY: geteuid ne prend aucun argument, ne touche aucune memoire et ne
    // peut pas echouer.
    unsafe { libc::geteuid() == 0 }
}

/// Sous Windows, le proprietaire du pipe est pose: jamais privilegie.
#[cfg(windows)]
fn serveur_privilegie() -> bool {
    false
}

/// Les trois commandes du poste de commande, contre un faux serveur d'un compte
/// ordinaire: chacune refusee, et aucun octet ecrit, ni la commande ni rien
/// avant elle, sur aucune connexion; une connexion par commande, et aucune
/// autre.
#[tokio::test(flavor = "multi_thread")]
async fn un_faux_serveur_d_un_compte_ordinaire_est_refuse_et_ne_recoit_rien() {
    let faux = Faux::demarrer("refus");
    let poste = Commande::new(faux.socket.clone());
    let issues = [
        ("status", poste.etat().await.map(|_| ())),
        ("connect-stored", poste.connecter().await),
        ("disconnect", poste.deconnecter().await),
    ];
    let (recus, connexions) = faux.apres(3).await;

    if serveur_privilegie() {
        // Root: le faux serveur a l'identite exigee et recoit les commandes.
        for (commande, issue) in &issues {
            assert!(
                !matches!(issue, Err(ErreurCommande::ServeurNonAdmis(_))),
                "{commande}: un serveur root refuse: {issue:?}"
            );
        }
        assert!(!recus.is_empty(), "admis, et rien recu");
        return;
    }

    for (commande, issue) in &issues {
        assert_eq!(
            issue,
            &Err(ErreurCommande::ServeurNonAdmis(
                ServerIdentityError::Refused
            )),
            "{commande}"
        );
    }
    assert!(
        recus.is_empty(),
        "{} octet(s) ecrit(s) a un serveur refuse: {:?}",
        recus.len(),
        String::from_utf8_lossy(&recus)
    );
    assert_eq!(connexions, 3, "une connexion par commande, et aucune autre");
    let vue = Vue::depuis_erreur(&ErreurCommande::ServeurNonAdmis(
        ServerIdentityError::Refused,
    ));
    assert_eq!(vue.etat, EtatVue::ServeurNonAdmis);
    assert_ne!(vue.couleur, CouleurTray::Vert);
}

/// Un canal qui existe, et dont la seule place est tenue par un premier
/// client que personne n'accepte. Windows: un pipe a une seule instance,
/// prise par ce client. Linux: un socket d'ecoute dont la file d'attente a
/// une longueur de zero, remplie par ce client.
struct Occupe {
    socket: String,
    #[cfg(windows)]
    _tenu: (
        tokio::net::windows::named_pipe::NamedPipeServer,
        tokio::net::windows::named_pipe::NamedPipeClient,
    ),
    #[cfg(unix)]
    _tenu: (tokio::net::UnixListener, std::os::unix::net::UnixStream),
}

#[cfg(windows)]
fn occupe(nom: &str) -> Occupe {
    use tokio::net::windows::named_pipe::{ClientOptions, ServerOptions};
    let socket = format!(r"\\.\pipe\bifrost-coquille-{}-{nom}", std::process::id());
    let serveur = ServerOptions::new()
        .first_pipe_instance(true)
        .reject_remote_clients(true)
        .create(&socket)
        .expect("pipe de la recette");
    let premier = ClientOptions::new().open(&socket).expect("premier client");
    Occupe {
        socket,
        _tenu: (serveur, premier),
    }
}

#[cfg(unix)]
fn occupe(nom: &str) -> Occupe {
    let chemin = std::env::temp_dir().join(format!(
        "bifrost-coquille-{}-{nom}.sock",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&chemin);
    let prise = tokio::net::UnixSocket::new_stream().expect("socket de la recette");
    prise.bind(&chemin).expect("bind");
    let ecoute = prise.listen(0).expect("listen");
    let premier = std::os::unix::net::UnixStream::connect(&chemin).expect("premier client");
    Occupe {
        socket: chemin.to_string_lossy().into_owned(),
        _tenu: (ecoute, premier),
    }
}

#[cfg(unix)]
impl Drop for Occupe {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket);
    }
}

/// Un canal que personne ne tient.
fn absent(nom: &str) -> String {
    #[cfg(unix)]
    let chemin = std::env::temp_dir()
        .join(format!(
            "bifrost-coquille-{}-{nom}.sock",
            std::process::id()
        ))
        .to_string_lossy()
        .into_owned();
    #[cfg(windows)]
    let chemin = format!(r"\\.\pipe\bifrost-coquille-{}-{nom}", std::process::id());
    chemin
}

/// Un canal occupe se dit << sans reponse dans le delai >>, un canal absent
/// << injoignable >>: deux erreurs, deux etats de la Vue, aucun vert.
/// Windows: apres l'attente d'une instance libre (2 s). Linux: `connect(2)`
/// sur une file d'attente pleine rend `EAGAIN`.
#[tokio::test(flavor = "multi_thread")]
async fn un_canal_occupe_est_sans_reponse_et_un_canal_absent_injoignable() {
    let canal = occupe("occupe");
    let pris = Commande::new(canal.socket.clone()).etat().await;
    drop(canal);
    let personne = Commande::new(absent("absent")).etat().await;

    let pris = pris.expect_err("un canal occupe ne repond pas");
    assert!(
        matches!(pris, ErreurCommande::DaemonSansReponse(_)),
        "{pris:?}"
    );
    let personne = personne.expect_err("un canal absent ne repond pas");
    assert!(
        matches!(personne, ErreurCommande::DaemonInjoignable(_)),
        "{personne:?}"
    );

    let (vue_pris, vue_personne) = (Vue::depuis_erreur(&pris), Vue::depuis_erreur(&personne));
    assert_eq!(vue_pris.etat, EtatVue::DaemonSansReponse);
    assert_eq!(vue_personne.etat, EtatVue::DaemonInjoignable);
    assert_ne!(vue_pris.couleur, CouleurTray::Vert);
    assert_ne!(vue_personne.couleur, CouleurTray::Vert);
}

/// Un canal qui existe, et dont les droits ferment l'ouverture a ce compte.
/// Windows: un pipe a la DACL vide (`D:P`), qui n'accorde a personne ni la
/// lecture ni l'ecriture, eleve ou non. Linux: un socket d'ecoute dont le
/// fichier n'a plus aucun droit (mode 0), que `connect(2)` refuse a tout
/// compte sauf root.
struct Ferme {
    socket: String,
    #[cfg(windows)]
    _tenu: tokio::net::windows::named_pipe::NamedPipeServer,
    #[cfg(unix)]
    _tenu: tokio::net::UnixListener,
}

#[cfg(windows)]
fn ferme(nom: &str) -> Ferme {
    let socket = format!(r"\\.\pipe\bifrost-coquille-{}-{nom}", std::process::id());
    let tenu = windows::instance(&socket, "D:P", true).expect("pipe a la DACL vide");
    Ferme {
        socket,
        _tenu: tenu,
    }
}

#[cfg(unix)]
fn ferme(nom: &str) -> Ferme {
    use std::os::unix::fs::PermissionsExt;
    let chemin = std::env::temp_dir().join(format!(
        "bifrost-coquille-{}-{nom}.sock",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&chemin);
    let ecoute = tokio::net::UnixListener::bind(&chemin).expect("ecoute de la recette");
    std::fs::set_permissions(&chemin, std::fs::Permissions::from_mode(0o000))
        .expect("droits du socket retires");
    Ferme {
        socket: chemin.to_string_lossy().into_owned(),
        _tenu: ecoute,
    }
}

#[cfg(unix)]
impl Drop for Ferme {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket);
    }
}

/// Le compte que le canal refuse a l'ouverture est << non admis par le
/// canal >>, sur les trois commandes: ni injoignable, ni vert, sans action
/// proposee. C'est l'etat d'un compte hors du groupe d'acces du pipe, ou hors
/// du groupe du socket. Root passe outre les droits d'un fichier: sous root,
/// la recette mesure que le socket s'ouvre, ce qui est la limite de la
/// mesure sous ce compte.
#[tokio::test(flavor = "multi_thread")]
async fn un_canal_qui_refuse_ce_compte_le_rend_non_admis() {
    let canal = ferme("ferme");
    #[cfg(unix)]
    if serveur_privilegie() {
        assert!(
            std::os::unix::net::UnixStream::connect(&canal.socket).is_ok(),
            "root n'ouvre pas un socket au mode 0"
        );
        return;
    }
    let poste = Commande::new(canal.socket.clone());
    let issues = [
        ("status", poste.etat().await.map(|_| ())),
        ("connect-stored", poste.connecter().await),
        ("disconnect", poste.deconnecter().await),
    ];
    for (commande, issue) in issues {
        let e = issue.expect_err("un canal ferme a ce compte ne repond pas");
        assert!(
            matches!(e, ErreurCommande::CompteNonAdmis(_)),
            "{commande}: {e:?}"
        );
        let vue = Vue::depuis_erreur(&e);
        assert_eq!(vue.etat, EtatVue::CompteNonAdmis, "{commande}");
        assert_ne!(vue.couleur, CouleurTray::Vert, "{commande}");
        assert!(!vue.peut_connecter && !vue.peut_deconnecter, "{commande}");
        for texte in [
            &vue.texte_etat,
            &vue.texte_kill_switch,
            &vue.texte_menu_etat,
        ] {
            assert!(!texte.contains("injoignable"), "{commande}: {texte}");
        }
    }
}

#[cfg(windows)]
mod windows {
    use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;

    /// Le SID du compte de la recette, tel que `whoami /user` le rend: la
    /// forme `S-1-...` ne se traduit pas.
    pub fn sid_du_compte_courant() -> String {
        let sortie = std::process::Command::new("whoami")
            .args(["/user", "/fo", "csv", "/nh"])
            .output()
            .expect("whoami /user");
        let texte = String::from_utf8_lossy(&sortie.stdout);
        let sids: Vec<&str> = texte
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))
            .filter(|mot| mot.starts_with("S-1-"))
            .collect();
        assert_eq!(sids.len(), 1, "un seul SID dans whoami /user: {texte}");
        sids[0].to_owned()
    }

    /// Une instance du pipe `nom`, sous le descripteur `sddl`.
    pub fn instance(nom: &str, sddl: &str, premiere: bool) -> std::io::Result<NamedPipeServer> {
        let large: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
        let mut descripteur: *mut std::ffi::c_void = std::ptr::null_mut();
        // SAFETY: `large` est une chaine UTF-16 terminee par un zero, et
        // `descripteur` recoit un descripteur alloue par le systeme, libere
        // par LocalFree avant de sortir de la fonction.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                large.as_ptr(),
                SDDL_REVISION_1,
                &mut descripteur,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut attributs = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descripteur,
            bInheritHandle: 0,
        };
        let mut options = ServerOptions::new();
        options
            .first_pipe_instance(premiere)
            .reject_remote_clients(true);
        // SAFETY: `attributs` reste vivant pendant tout l'appel, et son
        // lpSecurityDescriptor pointe sur un descripteur valide.
        let issue = unsafe {
            options.create_with_security_attributes_raw(
                nom,
                (&mut attributs as *mut SECURITY_ATTRIBUTES).cast(),
            )
        };
        // SAFETY: `descripteur` a ete alloue par
        // ConvertStringSecurityDescriptorToSecurityDescriptorW et n'est plus
        // lu apres la creation de l'instance.
        unsafe { LocalFree(descripteur) };
        issue
    }
}
