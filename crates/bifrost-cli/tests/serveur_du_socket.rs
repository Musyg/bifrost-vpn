//! Aucune commande du client ne parle a un serveur qu'elle n'a pas verifie.
//!
//! Ce qui est mesure ici: le binaire REEL du client, lance pour chaque
//! commande qui parle au daemon, face a un faux serveur du COMPTE COURANT qui
//! tient le socket (Linux) ou le pipe (Windows) designe par `--socket`. Le faux
//! serveur accepte, lit tout ce qui arrive, ne repond jamais, et compte les
//! connexions et les octets. Sous un compte ordinaire chaque commande doit le
//! joindre (une connexion: sinon zero octet ne prouverait rien), refuser, sortir
//! en 4, et ne lui avoir rien ecrit.
//!
//! Avant ce refus, mesure du 30/09/2026 sur le client de `5baf9f3`: le meme
//! faux serveur recevait 506 octets de `connect --config`, dont la cle privee.
//!
//! Sous root (Linux), le faux serveur EST privilegie: il est admis, et la
//! recette exige alors qu'il recoive la requete, cle comprise pour `connect
//! --config`. C'est la limite de la regle, et la preuve que le faux serveur
//! voit ce qu'on lui envoie. Sous un jeton eleve (Windows), le proprietaire du
//! pipe depend d'une strategie locale: seul l'invariant est exige, refus sans
//! un octet ou admission avec la requete.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt};

/// Le code de sortie d'un serveur refuse, tel que l'aide le documente.
const CODE_SERVEUR_REFUSE: i32 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Attendu {
    /// Compte ordinaire: le faux serveur n'est jamais admis.
    Refus,
    /// Linux, root: le faux serveur EST privilegie, et admis.
    #[cfg(unix)]
    Admis,
    /// Windows, jeton eleve: seul l'invariant est exige.
    #[cfg(windows)]
    Selon,
}

#[cfg(unix)]
fn attendu() -> Attendu {
    let euid = std::fs::read_to_string("/proc/self/status")
        .expect("/proc/self/status")
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|u| u.parse::<u32>().ok())
        .expect("uid effectif");
    if euid == 0 {
        Attendu::Admis
    } else {
        Attendu::Refus
    }
}

/// Le niveau d'integrite du jeton, par son SID, qui ne se traduit pas.
#[cfg(windows)]
fn attendu() -> Attendu {
    let sortie = std::process::Command::new("whoami")
        .arg("/groups")
        .output()
        .expect("whoami /groups");
    let texte = String::from_utf8_lossy(&sortie.stdout);
    if texte.contains("S-1-16-12288") || texte.contains("S-1-16-16384") {
        Attendu::Selon
    } else {
        assert!(
            texte.contains("S-1-16-"),
            "niveau d'integrite introuvable dans whoami /groups"
        );
        Attendu::Refus
    }
}

fn etiquette_unique(nom: &str) -> String {
    static SUIVANT: AtomicUsize = AtomicUsize::new(0);
    let nom: String = nom
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    format!(
        "bfsock-{}-{}-{nom}",
        std::process::id(),
        SUIVANT.fetch_add(1, Ordering::SeqCst)
    )
}

/// Une cle JETABLE, tiree pour cette execution: 32 octets du hasard que la
/// bibliotheque standard seme pour ses tables, en base64. Elle ne sert qu'a
/// etre cherchee dans ce que le faux serveur recoit.
fn cle_jetable() -> String {
    use std::hash::{BuildHasher, RandomState};
    let graine = RandomState::new();
    let mut octets = Vec::with_capacity(32);
    for i in 0u64..4 {
        octets.extend_from_slice(&graine.hash_one(i).to_le_bytes());
    }
    base64(&octets)
}

fn base64(octets: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut sortie = String::new();
    for bloc in octets.chunks(3) {
        let b = [
            bloc[0],
            bloc.get(1).copied().unwrap_or(0),
            bloc.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for (i, decalage) in [18u32, 12, 6, 0].into_iter().enumerate() {
            if i <= bloc.len() {
                sortie.push(ALPHABET[((n >> decalage) & 63) as usize] as char);
            } else {
                sortie.push('=');
            }
        }
    }
    sortie
}

/// Un repertoire a nous, efface a la fin.
struct Atelier(PathBuf);

impl Atelier {
    fn nouveau(nom: &str) -> Self {
        let rep = std::env::temp_dir().join(etiquette_unique(nom));
        std::fs::create_dir_all(&rep).expect("atelier");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&rep, std::fs::Permissions::from_mode(0o700))
                .expect("atelier 0700");
        }
        Self(rep)
    }

    /// Un profil WireGuard de test: adresses de documentation, cles jetables.
    fn profil(&self, prive: &str) -> PathBuf {
        let chemin = self.0.join("profil.toml");
        let texte = format!(
            "interface = \"bfsecipc0\"\n\
             private_key = \"{prive}\"\n\
             addresses = [\"198.51.100.2/32\"]\n\
             \n\
             [peer]\n\
             public_key = \"{public}\"\n\
             endpoint = {{ addr = \"192.0.2.10:51820\" }}\n\
             allowed_ips = [\"0.0.0.0/0\", \"::/0\"]\n\
             \n\
             [dns]\n\
             local_resolver = \"127.0.0.1\"\n\
             upstream = [\"198.51.100.53\"]\n",
            public = cle_jetable()
        );
        std::fs::write(&chemin, texte).expect("profil");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&chemin, std::fs::Permissions::from_mode(0o600))
                .expect("profil 0600");
        }
        chemin
    }
}

impl Drop for Atelier {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Un faux serveur du COMPTE COURANT.
struct Faux {
    socket: String,
    connexions: Arc<AtomicUsize>,
    recus: Arc<Mutex<Vec<u8>>>,
    tache: tokio::task::JoinHandle<()>,
    #[cfg(unix)]
    dossier: PathBuf,
}

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

impl Faux {
    #[cfg(unix)]
    fn demarrer(nom: &str) -> Self {
        let dossier = std::env::temp_dir().join(etiquette_unique(nom));
        std::fs::create_dir_all(&dossier).unwrap();
        let chemin = dossier.join("d.sock");
        let ecoute = tokio::net::UnixListener::bind(&chemin).unwrap();
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
            dossier,
        }
    }

    /// Le descripteur par defaut: le proprietaire du pipe est le compte
    /// courant, comme celui d'un pipe pris par un compte ordinaire quand le
    /// service est arrete.
    #[cfg(windows)]
    fn demarrer(nom: &str) -> Self {
        use tokio::net::windows::named_pipe::ServerOptions;
        let socket = format!(r"\\.\pipe\{}", etiquette_unique(nom));
        let premier = ServerOptions::new()
            .first_pipe_instance(true)
            .reject_remote_clients(true)
            .create(&socket)
            .unwrap();
        let (connexions, recus) = (Arc::default(), Arc::default());
        let (c, r) = (Arc::clone(&connexions), Arc::clone(&recus));
        let nom_pipe = socket.clone();
        let tache = tokio::spawn(async move {
            let mut courant = premier;
            while courant.connect().await.is_ok() {
                let Ok(suivant) = ServerOptions::new()
                    .reject_remote_clients(true)
                    .create(&nom_pipe)
                else {
                    return;
                };
                let servi = std::mem::replace(&mut courant, suivant);
                tokio::spawn(lire(servi, Arc::clone(&c), Arc::clone(&r)));
            }
        });
        Self {
            socket,
            connexions,
            recus,
            tache,
        }
    }

    async fn apres(&self, n: usize) -> Vec<u8> {
        for _ in 0..100 {
            if self.connexions.load(Ordering::SeqCst) >= n {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert_eq!(
            self.connexions.load(Ordering::SeqCst),
            n,
            "le client n'a pas joint le faux serveur: un zero octet ne prouverait rien"
        );
        self.recus.lock().unwrap().clone()
    }
}

impl Drop for Faux {
    fn drop(&mut self) {
        self.tache.abort();
        #[cfg(unix)]
        let _ = std::fs::remove_dir_all(&self.dossier);
    }
}

struct Sortie {
    code: Option<i32>,
    sortie: String,
    erreur: String,
}

async fn lancer(cli: &Path, socket: &str, arguments: &[String]) -> Sortie {
    let (cli, socket, arguments) = (cli.to_path_buf(), socket.to_owned(), arguments.to_vec());
    let sortie = tokio::task::spawn_blocking(move || {
        std::process::Command::new(&cli)
            .arg("--socket")
            .arg(&socket)
            .args(&arguments)
            .output()
            .expect("le client doit s'executer")
    })
    .await
    .expect("le client doit rendre la main");
    Sortie {
        code: sortie.status.code(),
        sortie: String::from_utf8_lossy(&sortie.stdout).into_owned(),
        erreur: String::from_utf8_lossy(&sortie.stderr).into_owned(),
    }
}

fn cli() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_bifrost-cli"))
}

/// LA garde de la tranche, sur ses occurrences reelles: chaque commande qui
/// parle au daemon, par le binaire construit.
#[tokio::test(flavor = "multi_thread")]
async fn chaque_commande_refuse_un_serveur_du_compte_courant_sans_rien_lui_envoyer() {
    let atelier = Atelier::nouveau("profil");
    let cle = cle_jetable();
    let profil = atelier.profil(&cle).to_string_lossy().into_owned();
    let mut cas: Vec<(&str, Vec<&str>)> = vec![
        ("connect --config", vec!["connect", "--config", &profil]),
        ("connect", vec!["connect"]),
        ("disconnect", vec!["disconnect"]),
        ("status", vec!["status"]),
        ("--json status", vec!["--json", "status"]),
        ("check", vec!["check"]),
    ];
    // Le hook de reprise a ses propres recettes, par le script depose
    // (`reprise_linux.rs`); la commande elle-meme passe ici avec les autres.
    if cfg!(target_os = "linux") {
        cas.push((
            "reprise",
            vec!["reprise", "--phase", "post", "--operation", "suspend"],
        ));
    }
    let attendu = attendu();
    for (nom, arguments) in cas {
        let arguments: Vec<String> = arguments.into_iter().map(String::from).collect();
        let faux = Faux::demarrer(nom);
        let s = lancer(&cli(), &faux.socket, &arguments).await;
        let recus = faux.apres(1).await;
        let refuse = s.code == Some(CODE_SERVEUR_REFUSE);
        match attendu {
            Attendu::Refus => {
                assert!(refuse, "{nom}: code {:?}, stderr: {}", s.code, s.erreur);
                assert!(
                    recus.is_empty(),
                    "{nom}: {} octet(s) ecrit(s) a un serveur refuse",
                    recus.len()
                );
                assert!(
                    s.erreur.contains("n'a pas l'identite attendue du daemon")
                        && s.erreur.contains("Rien ne lui a ete envoye"),
                    "{nom}: le refus doit se lire: {}",
                    s.erreur
                );
                assert!(s.sortie.is_empty(), "{nom}: stdout: {}", s.sortie);
                assert!(!s.erreur.contains(&cle), "{nom}: la cle sort sur stderr");
            }
            #[cfg(unix)]
            Attendu::Admis => {
                assert!(!refuse, "{nom}: serveur root refuse: {}", s.erreur);
                assert!(!recus.is_empty(), "{nom}: admis, et rien recu");
            }
            #[cfg(windows)]
            Attendu::Selon => assert_eq!(
                refuse,
                recus.is_empty(),
                "{nom}: refus et octets recus ne concordent pas ({:?}, {} octet(s))",
                s.code,
                recus.len()
            ),
        }
        if nom == "connect --config" && !recus.is_empty() {
            // Le faux serveur voit ce qu'on lui envoie: sans cela, son zero
            // octet de la branche refusee ne vaudrait rien.
            assert!(
                String::from_utf8_lossy(&recus).contains(&cle),
                "admis sans que la cle arrive: le faux serveur ne voit pas le profil"
            );
        }
    }
}

/// La sonde de presence d'`emergency-disarm`: elle n'ecrit jamais, et ne
/// prend plus un processus quelconque pour le daemon. La commande va au bout
/// dans tous les cas: son daemon est ici une COPIE de ce binaire de recettes,
/// posee a cote d'une copie du client, qui refuse `--cleanup-firewall` et sort
/// en erreur sans rien toucher.
#[tokio::test(flavor = "multi_thread")]
async fn la_sonde_d_emergency_disarm_n_ecrit_rien_et_ne_prend_pas_un_autre_pour_le_daemon() {
    let atelier = Atelier::nouveau("urgence");
    let suffixe = std::env::consts::EXE_SUFFIX;
    let copie = atelier.0.join(format!("bifrost-cli{suffixe}"));
    std::fs::copy(cli(), &copie).expect("copie du client");
    let leurre = atelier.0.join(format!("bifrost-daemon{suffixe}"));
    std::fs::copy(std::env::current_exe().expect("ce binaire"), &leurre).expect("leurre");
    let faux = Faux::demarrer("urgence");
    let arguments = vec![
        "emergency-disarm".to_owned(),
        "--je-sais-ce-que-je-fais".to_owned(),
    ];
    let s = lancer(&copie, &faux.socket, &arguments).await;
    let recus = faux.apres(1).await;
    assert!(
        recus.is_empty(),
        "la sonde a ecrit {} octet(s)",
        recus.len()
    );
    let autre = s.erreur.contains("n'a pas l'identite attendue du daemon");
    let daemon = s.erreur.contains("un daemon repond encore");
    match attendu() {
        Attendu::Refus => assert!(autre && !daemon, "{}", s.erreur),
        #[cfg(unix)]
        Attendu::Admis => assert!(daemon && !autre, "{}", s.erreur),
        #[cfg(windows)]
        Attendu::Selon => assert!(autre != daemon, "{}", s.erreur),
    }
    // Et elle est allee au bout: le leurre a ete lance. Il refuse l'option
    // et sort en erreur, ce que le client rapporte avec son code.
    assert!(
        s.erreur.contains("a echoue (code"),
        "le desarmement n'a pas ete tente: {}",
        s.erreur
    );
}
