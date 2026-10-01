//! Serveur IPC: traduit les requetes du client en commandes au superviseur.

use std::sync::mpsc::Sender;

use bifrost_core::TunnelConfig;
use bifrost_ipc::protocol::{Command, Response};
use bifrost_ipc::transport::{IpcError, IpcServer};
use bifrost_ipc::{AuthPolicy, Connection};

use crate::supervisor::{Cmd, RoutageDeclare};

/// Boucle d'acceptation. Ne rend la main qu'en cas d'erreur fatale d'ecoute:
/// `IpcServer::accept` garde pour lui l'erreur qui ne touche qu'une connexion
/// et l'epuisement d'une ressource, qu'il attend.
pub async fn serve(
    mut server: IpcServer,
    tx: Sender<Cmd>,
    profil: std::path::PathBuf,
) -> anyhow::Result<()> {
    loop {
        let conn = match server.accept().await {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(error = %e, "acceptation impossible");
                return Err(e.into());
            }
        };
        let tx = tx.clone();
        let profil = profil.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(conn, tx, profil).await
                && !matches!(e, IpcError::Closed)
            {
                tracing::warn!(error = %e, "connexion terminee sur erreur");
            }
        });
    }
}

async fn handle(
    mut conn: Connection,
    tx: Sender<Cmd>,
    profil: std::path::PathBuf,
) -> Result<(), IpcError> {
    let peer = conn.peer().to_string();
    loop {
        let request = match conn.recv().await {
            Ok(r) => r,
            Err(IpcError::Closed) => return Ok(()),
            Err(e @ IpcError::VersionMismatch { .. }) => {
                conn.send(&Response::error(e.to_string())).await?;
                return Ok(());
            }
            Err(e) => {
                conn.send(&Response::error(format!("requete illisible: {e}")))
                    .await?;
                return Err(e);
            }
        };

        // Toute commande privilegiee est tracee avec son appelant: sans cela il
        // est impossible de savoir apres coup qui a coupe le tunnel.
        if request.command.is_mutating() {
            tracing::info!(peer = %peer, command = request.command.name(), "commande privilegiee");
        }

        let response = dispatch(request.command, &tx, &profil).await;
        conn.send(&response).await?;
    }
}

async fn dispatch(command: Command, tx: &Sender<Cmd>, profil: &std::path::Path) -> Response {
    match command {
        Command::Connect { config } => match ask(tx, |reply| Cmd::Connect(config, reply)).await {
            Ok(Ok(())) => Response::Ok,
            Ok(Err(e)) => Response::error(e.to_string()),
            Err(e) => Response::error(e),
        },
        Command::ConnectStored => match ouvrir_le_profil(profil).await {
            Ok(config) => match ask(tx, |reply| Cmd::Connect(config, reply)).await {
                Ok(Ok(())) => Response::Ok,
                Ok(Err(e)) => Response::error(e.to_string()),
                Err(e) => Response::error(e),
            },
            Err(e) => Response::error(e),
        },
        Command::Disconnect => match ask(tx, Cmd::Disconnect).await {
            Ok(Ok(())) => Response::Ok,
            Ok(Err(e)) => Response::error(e.to_string()),
            Err(e) => Response::error(e),
        },
        Command::Status => match ask(tx, Cmd::Status).await {
            Ok(status) => Response::Status(Box::new(status)),
            Err(e) => Response::error(e),
        },
        Command::Check => match ask(tx, Cmd::Check).await {
            Ok(report) => Response::Check(Box::new(report)),
            Err(e) => Response::error(e),
        },
        // Par `ask`, comme `Status`, et pour une raison de plus: la reponse
        // vient du thread qui appelle le moteur, donc elle ne peut pas etre
        // lue au milieu d'une application. Aucun controle d'acces propre: ce
        // canal n'en a qu'un, a l'acceptation, et il vaut pour toutes les
        // commandes.
        Command::DeclarationPareFeu => match ask(tx, Cmd::Declaration).await {
            Ok(declaration) => Response::DeclarationPareFeu(Box::new(declaration)),
            Err(e) => Response::error(e),
        },
        // Meme voie que `DeclarationPareFeu` et pour la meme raison: la reponse
        // vient du thread qui fait monter et demonter le tunnel, donc elle ne
        // peut pas etre lue au milieu d'un montage. Un seul controle d'acces, a
        // l'acceptation, vaut pour toutes les commandes.
        Command::DeclarationRoutage => match ask(tx, Cmd::DeclarationRoutage).await {
            Ok(RoutageDeclare::Linux(declaration)) => {
                Response::DeclarationRoutage(Box::new(declaration))
            }
            Ok(RoutageDeclare::Windows(declaration)) => {
                Response::DeclarationRoutageWindows(Box::new(declaration))
            }
            Err(e) => Response::error(e),
        },
        // Rien a attendre: le superviseur range le verdict et poursuit. Lui
        // demander de confirmer ferait patienter le client derriere une
        // eventuelle connexion en cours, pour une reponse qui ne peut pas
        // echouer.
        Command::VerdictInspectionTls { intercepte } => {
            match tx.send(Cmd::VerdictTls(intercepte)) {
                Ok(()) => Response::Ok,
                Err(_) => Response::error("le superviseur ne repond plus"),
            }
        }
        // Sans attendre non plus, et pour une raison plus forte que la
        // precedente: l'appelant est un hook `systemd-sleep`, et systemd ne
        // poursuit la reprise de la machine qu'une fois TOUS ses hooks
        // termines. Passer par `ask` ferait dependre le reveil du systeme de
        // l'etat du superviseur, qui peut etre en train de monter un tunnel.
        //
        // Ce que le client perd: la confirmation que la politique a ete
        // reposee. Il ne l'avait de toute facon pas - le superviseur execute
        // l'action apres coup - et c'est le journal du daemon qui en porte la
        // trace, pas la reponse a cette commande.
        Command::Reprise => match tx.send(Cmd::Reprise) {
            Ok(()) => Response::Ok,
            Err(_) => Response::error("le superviseur ne repond plus"),
        },
    }
}

/// Envoie une commande au superviseur et attend sa reponse.
/// Ouvre le profil du daemon et le lit.
///
/// Sur un fil bloquant, et ce n'est pas une precaution de style: desceller un
/// profil lance `systemd-creds`, qui bloque. L'attendre sur le runtime figerait
/// la boucle d'evenements qui sert TOUTES les connexions IPC, y compris celle
/// qui demanderait l'etat pour comprendre pourquoi rien ne repond.
async fn ouvrir_le_profil(chemin: &std::path::Path) -> Result<Box<TunnelConfig>, String> {
    let chemin = chemin.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let ouvert = bifrost_coffre::ouvrir(&chemin).map_err(|e| format!("{e:#}"))?;
        // Le nom du fichier qui a REELLEMENT servi: designer le clair alors
        // qu'on a ouvert le scelle enverrait corriger le mauvais fichier.
        let designe = match ouvert.forme {
            bifrost_coffre::Forme::Scelle => bifrost_coffre::chemin_scelle(&chemin),
            bifrost_coffre::Forme::EnClair => chemin,
        };
        let config: TunnelConfig = toml::from_str(&ouvert.contenu)
            .map_err(|e| format!("profil {} invalide: {e}", designe.display()))?;
        // Valide ici, a l'ouverture, pour que le refus nomme le fichier a
        // corriger, comme le fait le client pour le sien. Le superviseur
        // revalide de toute facon avant tout armement: c'est la meme fonction.
        // Un profil range par une version precedente avec une table que le
        // noyau se reserve s'arrete donc ici, avant tout montage.
        config
            .validate()
            .map_err(|e| format!("profil {} invalide: {e}", designe.display()))?;
        Ok(Box::new(config))
    })
    .await
    .map_err(|e| format!("la lecture du profil n'a pas abouti: {e}"))?
}

async fn ask<T, F>(tx: &Sender<Cmd>, build: F) -> Result<T, String>
where
    F: FnOnce(tokio::sync::oneshot::Sender<T>) -> Cmd,
{
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    tx.send(build(reply_tx))
        .map_err(|_| "le superviseur s'est arrete".to_owned())?;
    reply_rx
        .await
        .map_err(|_| "le superviseur n'a pas repondu".to_owned())
}

/// Politique d'autorisation construite depuis le nom d'un groupe systeme.
pub fn auth_policy(group: Option<&str>) -> AuthPolicy {
    AuthPolicy {
        allowed_gid: resolve_gid(group),
        ..AuthPolicy::default()
    }
}

#[cfg(unix)]
fn resolve_gid(group: Option<&str>) -> Option<u32> {
    let name = group?;
    match bifrost_ipc::auth::lookup_gid(name) {
        Some(gid) => {
            tracing::info!(group = name, gid, "groupe autorise");
            Some(gid)
        }
        None => {
            tracing::warn!(
                group = name,
                "groupe introuvable dans /etc/group: seul root pourra piloter le daemon"
            );
            None
        }
    }
}

/// Sur Windows l'autorisation est portee par la DACL du named pipe, pas par un
/// groupe applicatif: un processus non privilegie ne peut meme pas l'ouvrir.
#[cfg(not(unix))]
fn resolve_gid(group: Option<&str>) -> Option<u32> {
    if group.is_some() {
        tracing::warn!("--group est ignore sur Windows: la DACL du pipe fait foi");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROFIL: &str = r#"
interface = "wg0"
private_key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaA="
addresses = ["10.2.0.2/32"]

[peer]
public_key = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbA="
endpoint = { addr = "203.0.113.7:51820" }
allowed_ips = ["0.0.0.0/0"]

[dns]
local_resolver = "127.0.0.1"
upstream = ["10.2.0.1"]
"#;

    /// Le verdict d'inspection TLS arrive REELLEMENT au superviseur.
    ///
    /// La seule branche de `dispatch` qui ne passe pas par `ask`: elle n'attend
    /// pas de reponse, donc un `Response::Ok` ne prouve rien de ce que le
    /// superviseur a recu. Toutes les autres branches se trahiraient par un
    /// blocage; celle-ci se contenterait de repondre "ok" en jetant le verdict,
    /// et le daemon deciderait ensuite sur une mesure qu'on croirait lui avoir
    /// donnee.
    #[tokio::test]
    async fn le_verdict_d_inspection_tls_atteint_le_superviseur() {
        let (tx, rx) = std::sync::mpsc::channel();
        let reponse = dispatch(
            Command::VerdictInspectionTls { intercepte: true },
            &tx,
            std::path::Path::new("/inexistant"),
        )
        .await;
        assert!(matches!(reponse, Response::Ok), "{reponse:?}");
        // Sans `{:?}`: `Cmd` ne derive pas `Debug`, et ne doit pas le deriver -
        // `Cmd::Connect` porte une cle privee, qu'un `{:?}` egare suffirait a
        // deposer dans un journal.
        assert!(
            matches!(rx.try_recv(), Ok(Cmd::VerdictTls(true))),
            "le superviseur n'a pas recu le verdict"
        );
    }

    /// La reprise arrive REELLEMENT au superviseur.
    ///
    /// Meme raison que ci-dessus, et un cran plus haut: c'est la seule branche
    /// dont l'appelant est un SCRIPT, qui lit un code de sortie et rien
    /// d'autre. Si `dispatch` repondait "ok" en jetant la commande, le hook de
    /// veille reussirait a chaque reveil, le journal ne dirait rien, et la
    /// politique ne serait jamais reposee.
    #[tokio::test]
    async fn la_reprise_atteint_le_superviseur() {
        let (tx, rx) = std::sync::mpsc::channel();
        let reponse = dispatch(Command::Reprise, &tx, std::path::Path::new("/inexistant")).await;
        assert!(matches!(reponse, Response::Ok), "{reponse:?}");
        // Sans `{:?}`: `Cmd` ne derive pas `Debug` et ne doit pas le deriver.
        assert!(
            matches!(rx.try_recv(), Ok(Cmd::Reprise)),
            "le superviseur n'a pas recu la reprise"
        );
    }

    /// Un superviseur parti ne se signale pas par un "ok", reprise comprise.
    ///
    /// Le hook de veille n'a que le code de sortie pour savoir ou il en est.
    /// Un "ok" rendu par un daemon dont le superviseur est mort ferait passer
    /// pour reposee une politique que plus personne ne peut poser.
    #[tokio::test]
    async fn une_reprise_sans_superviseur_est_dite_perdue() {
        let (tx, rx) = std::sync::mpsc::channel();
        drop(rx);
        let reponse = dispatch(Command::Reprise, &tx, std::path::Path::new("/inexistant")).await;
        assert!(matches!(reponse, Response::Error { .. }), "{reponse:?}");
    }

    /// La declaration rendue est CELLE du superviseur, transmise sans retouche.
    ///
    /// Le superviseur est simule par un fil qui repond a `Cmd::Declaration`
    /// et a rien d'autre: une branche qui fabriquerait sa propre reponse, ou
    /// qui passerait par `Cmd::Status`, ne recevrait pas cette declaration.
    #[tokio::test]
    async fn la_declaration_vient_du_superviseur_sans_retouche() {
        use bifrost_ipc::protocol::{DeclarationPareFeu, IssueApplication};
        let (tx, rx) = std::sync::mpsc::channel();
        let attendue = DeclarationPareFeu {
            schema_version: 1,
            instance: "ab".repeat(24),
            application: 7,
            moteur: "nftables".into(),
            issue: IssueApplication::Posee,
            politique: Some(serde_json::json!({"schema_version": 1})),
        };
        let envoyee = attendue.clone();
        let fil = std::thread::spawn(move || match rx.recv() {
            Ok(Cmd::Declaration(reply)) => {
                let _ = reply.send(envoyee);
                true
            }
            _ => false,
        });
        let reponse = dispatch(
            Command::DeclarationPareFeu,
            &tx,
            std::path::Path::new("/inexistant"),
        )
        .await;
        assert!(fil.join().unwrap(), "le superviseur n'a pas ete interroge");
        match reponse {
            Response::DeclarationPareFeu(d) => assert_eq!(*d, attendue),
            autre => panic!("attendu une declaration, recu {autre:?}"),
        }
        let (tx, rx) = std::sync::mpsc::channel::<Cmd>();
        drop(rx);
        let reponse = dispatch(
            Command::DeclarationPareFeu,
            &tx,
            std::path::Path::new("/inexistant"),
        )
        .await;
        assert!(matches!(reponse, Response::Error { .. }), "{reponse:?}");
    }

    /// Un superviseur parti ne se signale pas par un "ok".
    #[tokio::test]
    async fn un_superviseur_absent_est_dit_absent() {
        let (tx, rx) = std::sync::mpsc::channel();
        drop(rx);
        let reponse = dispatch(
            Command::VerdictInspectionTls { intercepte: true },
            &tx,
            std::path::Path::new("/inexistant"),
        )
        .await;
        assert!(matches!(reponse, Response::Error { .. }), "{reponse:?}");
    }

    /// Un repertoire a nous, avec un profil correctement range.
    fn profil(nom: &str, contenu: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let rep =
            std::env::temp_dir().join(format!("bifrost-serveur-{}-{nom}", std::process::id()));
        let _ = std::fs::remove_dir_all(&rep);
        std::fs::create_dir_all(&rep).unwrap();
        let f = rep.join("tunnel.toml");
        std::fs::write(&f, contenu).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&rep, std::fs::Permissions::from_mode(0o700)).unwrap();
            std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        (rep, f)
    }

    /// Le daemon sait ouvrir son propre profil.
    #[tokio::test]
    async fn le_daemon_ouvre_son_profil() {
        let (rep, f) = profil("ouvre", PROFIL);
        let cfg = ouvrir_le_profil(&f).await.expect("le profil doit s'ouvrir");
        assert_eq!(cfg.interface, "wg0");
        let _ = std::fs::remove_dir_all(&rep);
    }

    /// Un profil illisible se plaint du bon fichier, et sans rien en divulguer.
    #[tokio::test]
    async fn un_profil_invalide_nomme_son_fichier_sans_le_citer() {
        let (rep, f) = profil("invalide", "interface = \"wg0\"\nprivate_key = 12\n");
        let e = ouvrir_le_profil(&f)
            .await
            .expect_err("un profil sans pair doit etre refuse");
        assert!(
            e.contains(&f.display().to_string()),
            "le message doit nommer le fichier: {e}"
        );
        let _ = std::fs::remove_dir_all(&rep);
    }

    /// Un profil range avec une table que le noyau se reserve est refuse a
    /// l'ouverture: le message nomme le fichier, la valeur et ce qu'il faut
    /// changer, et aucune commande n'atteint le superviseur.
    #[tokio::test]
    async fn un_profil_range_avec_une_table_reservee_est_refuse_a_l_ouverture() {
        let fautif = PROFIL.replace(
            "addresses = [\"10.2.0.2/32\"]\n",
            "addresses = [\"10.2.0.2/32\"]\nrouting_table = 254\n",
        );
        assert_ne!(fautif, PROFIL, "le remplacement doit avoir porte");
        let (rep, f) = profil("table-reservee", &fautif);
        let e = ouvrir_le_profil(&f)
            .await
            .expect_err("une table reservee doit etre refusee a l'ouverture");
        assert!(e.contains(&f.display().to_string()), "le fichier: {e}");
        assert!(e.contains("routing_table = 254"), "la valeur: {e}");
        assert!(
            e.contains("Retirer la ligne routing_table"),
            "ce qu'il faut changer: {e}"
        );
        let (tx, rx) = std::sync::mpsc::channel();
        let reponse = dispatch(Command::ConnectStored, &tx, &f).await;
        assert!(matches!(reponse, Response::Error { .. }), "{reponse:?}");
        assert!(
            rx.try_recv().is_err(),
            "rien ne doit atteindre le superviseur"
        );
        let _ = std::fs::remove_dir_all(&rep);
    }

    /// Le daemon descelle ce que le client ne saurait pas ouvrir.
    ///
    /// C'est la raison d'etre de ce chemin: le dechiffrement passe par le TPM,
    /// donc par root, et le daemon est le seul des deux a l'etre.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn le_daemon_descelle_un_profil_scelle() {
        fn est_root() -> bool {
            std::fs::read_to_string("/proc/self/status")
                .unwrap_or_default()
                .lines()
                .find_map(|l| l.strip_prefix("Uid:"))
                .and_then(|l| l.split_whitespace().nth(1).map(str::to_owned))
                .as_deref()
                == Some("0")
        }
        if std::process::Command::new("systemd-creds")
            .arg("--version")
            .output()
            .is_err()
        {
            println!("SKIPPED: systemd-creds absent");
            return;
        }
        if !est_root() {
            println!("SKIPPED: la cle du coffre est dans le TPM, qui n'est lisible que par root");
            return;
        }

        let (rep, f) = profil("scelle", PROFIL);
        bifrost_coffre::sceller(&f).expect("le scellement doit reussir");
        // Le clair disparait: seul le scelle peut donc repondre.
        std::fs::remove_file(&f).unwrap();

        let cfg = ouvrir_le_profil(&f)
            .await
            .expect("le daemon doit savoir desceller");
        assert_eq!(cfg.interface, "wg0");
        let _ = std::fs::remove_dir_all(&rep);
    }

    /// L'epuisement des descripteurs du daemon n'arrete pas son serveur IPC,
    /// et le serveur sert de nouveau des qu'ils se liberent.
    ///
    /// Par le chemin de production: `IpcServer::bind`, puis `serve` tel que
    /// le daemon l'appelle, et un client `connect_verified`. L'epuisement est
    /// provoque dans un PROCESSUS ENFANT, cette meme recette relancee: la
    /// limite basse de descripteurs n'est posee que la, jamais dans le
    /// processus de test que d'autres recettes partagent. Le parent tient plus
    /// de connexions que l'enfant n'a de descripteurs libres, mesure ce que le
    /// serveur en fait (rend-il? combien de temps processeur brule-t-il
    /// pendant l'episode? combien de lignes de journal ecrit-il?), puis les
    /// lache et mesure le temps qu'il met a servir de nouveau.
    #[cfg(target_os = "linux")]
    mod epuisement {
        use super::*;
        use std::io::{BufRead, BufReader, Write};
        use std::process::Stdio;
        use std::sync::mpsc;
        use std::time::{Duration, Instant};

        /// Le nom complet de la recette, pour que l'enfant ne lance qu'elle.
        const RECETTE: &str =
            "server::tests::epuisement::l_epuisement_des_descripteurs_n_arrete_pas_le_serveur";
        /// Present dans l'environnement de l'enfant, et la seulement: le
        /// repertoire de son socket, nomme et retire par le parent.
        const ROLE_ENFANT: &str = "BIFROST_RECETTE_EPUISEMENT_ENFANT";
        /// Descripteurs laisses a l'enfant au-dela de ceux qu'il tient deja:
        /// son serveur en acceptera autant, pas davantage.
        const MARGE: u64 = 8;
        /// Connexions tenues par le parent, bien au-dela de `MARGE`.
        const TENUES: usize = 40;
        /// Fenetre de mesure du temps processeur, pendant l'episode.
        const FENETRE: Duration = Duration::from_secs(1);
        /// Une boucle active brulerait la fenetre entiere.
        const PLAFOND_CPU: Duration = Duration::from_millis(250);
        /// Du lacher des connexions a la reponse d'un client complet.
        const PLAFOND_REPRISE: Duration = Duration::from_secs(2);
        /// La ligne de journal d'un episode d'epuisement.
        const MARQUE: &str = "acceptation suspendue";

        fn euid() -> u32 {
            // SAFETY: geteuid ne prend pas d'argument et ne touche aucune memoire.
            unsafe { libc::geteuid() }
        }

        /// Le plus grand descripteur ouvert de ce processus.
        fn plus_grand_descripteur() -> u64 {
            std::fs::read_dir("/proc/self/fd")
                .expect("/proc/self/fd")
                .filter_map(|e| e.ok()?.file_name().to_str()?.parse::<u64>().ok())
                .max()
                .expect("au moins un descripteur ouvert")
        }

        /// Le role de l'enfant: ecouter comme le daemon, sous une limite basse
        /// de descripteurs posee dans ce processus seul, et dire si `serve` a
        /// rendu.
        fn enfant() {
            // Un enfant que personne ne tuerait s'arrete seul.
            std::thread::spawn(|| {
                std::thread::sleep(Duration::from_secs(60));
                std::process::exit(4);
            });
            let _ = tracing_subscriber::fmt()
                .with_writer(std::io::stderr)
                .with_ansi(false)
                .with_env_filter(tracing_subscriber::EnvFilter::new(
                    "bifrost_ipc=debug,bifrost_daemon=debug",
                ))
                .try_init();
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("runtime");
            let dossier = std::path::PathBuf::from(
                std::env::var_os(ROLE_ENFANT).expect("repertoire de la recette"),
            );
            let _ = std::fs::remove_dir_all(&dossier);
            std::fs::create_dir_all(&dossier).expect("repertoire de la recette");
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&dossier, std::fs::Permissions::from_mode(0o755))
                    .expect("repertoire de la recette en 0755");
            }
            let chemin = dossier.join("d.sock");
            let policy = AuthPolicy {
                allowed_uids: vec![0, euid()],
                allowed_gid: None,
            };
            let serveur = rt
                .block_on(IpcServer::bind(&chemin, policy, None))
                .expect("bind");
            let (tx, rx) = std::sync::mpsc::channel();

            let mut actuelle = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            // SAFETY: getrlimit ecrit dans une structure locale, vivante
            // pendant l'appel.
            let rc = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut actuelle) };
            assert_eq!(rc, 0, "getrlimit");
            let basse = libc::rlimit {
                rlim_cur: (plus_grand_descripteur() + 1 + MARGE) as libc::rlim_t,
                rlim_max: actuelle.rlim_max,
            };
            // SAFETY: setrlimit lit une structure locale, vivante pendant
            // l'appel; seule la limite souple de CE processus baisse.
            let rc = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &basse) };
            assert_eq!(rc, 0, "setrlimit");

            println!("PRET {}", chemin.display());
            let _ = std::io::stdout().flush();
            let issue = rt.block_on(serve(serveur, tx, std::path::PathBuf::from("/inexistant")));
            drop(rx);
            println!("SERVE RENDU: {issue:?}");
            let _ = std::io::stdout().flush();
            std::process::exit(3);
        }

        /// Temps processeur consomme par le processus `pid`, tous fils
        /// compris (`utime` et `stime` de `/proc/<pid>/stat`).
        fn temps_processeur(pid: u32) -> Option<Duration> {
            let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
            let apres = &stat[stat.rfind(')')? + 1..];
            let champs: Vec<&str> = apres.split_whitespace().collect();
            // Apres la commande: l'etat (3e champ), puis utime (14e) et
            // stime (15e).
            let utime: u64 = champs.get(11)?.parse().ok()?;
            let stime: u64 = champs.get(12)?.parse().ok()?;
            // SAFETY: sysconf ne lit qu'une constante du systeme.
            let tics = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
            (tics > 0).then(|| Duration::from_secs_f64((utime + stime) as f64 / tics as f64))
        }

        /// Un client complet, par `connect_verified`, dans un fil a lui: son
        /// issue dans un temps borne.
        fn client_complet(chemin: &str) -> Result<(), String> {
            let chemin = chemin.to_owned();
            let (tx, rx) = mpsc::channel();
            std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("runtime du client");
                let issue = rt.block_on(async {
                    let (mut client, _) = bifrost_ipc::IpcClient::connect_verified(
                        &chemin,
                        bifrost_ipc::ServerRequirement::Uid(euid()),
                    )
                    .await
                    .map_err(|e| e.to_string())?;
                    client
                        .request(&bifrost_ipc::Request::new(Command::VerdictInspectionTls {
                            intercepte: false,
                        }))
                        .await
                        .map_err(|e| e.to_string())
                });
                let _ = tx.send(issue);
            });
            match rx.recv_timeout(Duration::from_secs(5)) {
                Ok(Ok(Response::Ok)) => Ok(()),
                Ok(Ok(autre)) => Err(format!("reponse inattendue: {autre:?}")),
                Ok(Err(e)) => Err(e),
                Err(_) => Err("aucune reponse en 5 s".to_owned()),
            }
        }

        /// Ce que le serveur de l'enfant a fait de l'episode.
        #[derive(Debug)]
        struct Mesure {
            /// Ce que `serve` a rendu, s'il a rendu.
            serve_rendu: Option<String>,
            /// Delai entre l'ouverture des connexions et la premiere ligne
            /// d'epuisement, si elle est venue.
            episode: Option<Duration>,
            /// Lignes d'epuisement ecrites, du debut a la fin de la mesure.
            lignes: usize,
            /// Temps processeur brule par l'enfant pendant `FENETRE`.
            cpu: Option<Duration>,
            /// Du lacher des connexions a la reponse d'un client complet.
            reprise: Result<Duration, String>,
        }

        /// Ce qui suit `marque` dans `ligne`. Pas en tete de ligne: le banc
        /// de test de l'enfant imprime `test <nom> ... ` sans fin de ligne
        /// avant que la recette n'ecrive.
        fn apres<'a>(ligne: &'a str, marque: &str) -> Option<&'a str> {
            ligne.split_once(marque).map(|(_, reste)| reste)
        }

        fn rendu(sortie: &mpsc::Receiver<String>) -> Option<String> {
            sortie
                .try_iter()
                .find_map(|l| apres(&l, "SERVE RENDU: ").map(str::to_owned))
        }

        fn mesurer(
            pid: u32,
            sortie: &mpsc::Receiver<String>,
            journal: &mpsc::Receiver<String>,
        ) -> Mesure {
            let chemin = loop {
                match sortie.recv_timeout(Duration::from_secs(10)) {
                    Ok(l) => {
                        if let Some(c) = apres(&l, "PRET ") {
                            break c.to_owned();
                        }
                    }
                    Err(_) => panic!("l'enfant n'a pas ouvert son ecoute en 10 s"),
                }
            };
            let tenues: Vec<std::os::unix::net::UnixStream> = (0..TENUES)
                .filter_map(|_| std::os::unix::net::UnixStream::connect(&chemin).ok())
                .collect();
            let ouverture = Instant::now();

            let mut serve_rendu = None;
            let mut episode = None;
            let mut lignes = 0;
            while episode.is_none()
                && serve_rendu.is_none()
                && ouverture.elapsed() < Duration::from_secs(5)
            {
                if let Ok(l) = journal.recv_timeout(Duration::from_millis(20))
                    && l.contains(MARQUE)
                {
                    lignes += 1;
                    episode = Some(ouverture.elapsed());
                }
                serve_rendu = rendu(sortie);
            }

            let mut cpu = None;
            if episode.is_some() {
                let avant = temps_processeur(pid);
                std::thread::sleep(FENETRE);
                if let (Some(a), Some(b)) = (avant, temps_processeur(pid)) {
                    cpu = Some(b.saturating_sub(a));
                }
            }

            drop(tenues);
            let lacher = Instant::now();
            let reprise = client_complet(&chemin).map(|()| lacher.elapsed());
            lignes += journal.try_iter().filter(|l| l.contains(MARQUE)).count();
            if serve_rendu.is_none() {
                serve_rendu = rendu(sortie);
            }
            Mesure {
                serve_rendu,
                episode,
                lignes,
                cpu,
                reprise,
            }
        }

        /// L'enfant: tue par le pid releve a son lancement, jamais par un
        /// motif, et son repertoire retire, a la sortie de la recette, sur
        /// une panique comprise.
        struct Enfant(std::process::Child, std::path::PathBuf);

        impl Drop for Enfant {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
                let _ = std::fs::remove_dir_all(&self.1);
            }
        }

        #[test]
        fn l_epuisement_des_descripteurs_n_arrete_pas_le_serveur() {
            if std::env::var_os(ROLE_ENFANT).is_some() {
                return enfant();
            }
            let dossier = std::env::temp_dir()
                .join(format!("bifrost-serveur-epuisement-{}", std::process::id()));
            let mut fils = Enfant(
                std::process::Command::new(std::env::current_exe().expect("binaire de la recette"))
                    .args(["--exact", RECETTE, "--nocapture", "--test-threads=1"])
                    .env(ROLE_ENFANT, &dossier)
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .expect("lancement de l'enfant"),
                dossier,
            );
            let pid = fils.0.id();
            let (tx_sortie, sortie) = mpsc::channel::<String>();
            let flux = fils.0.stdout.take().expect("sortie de l'enfant");
            std::thread::spawn(move || {
                for l in BufReader::new(flux).lines().map_while(Result::ok) {
                    if tx_sortie.send(l).is_err() {
                        break;
                    }
                }
            });
            let (tx_journal, journal) = mpsc::channel::<String>();
            let flux = fils.0.stderr.take().expect("journal de l'enfant");
            std::thread::spawn(move || {
                for l in BufReader::new(flux).lines().map_while(Result::ok) {
                    if tx_journal.send(l).is_err() {
                        break;
                    }
                }
            });

            let mesure = mesurer(pid, &sortie, &journal);
            drop(fils);

            println!("mesure epuisement des descripteurs: {mesure:?}");
            assert!(
                mesure.serve_rendu.is_none(),
                "le serveur s'est arrete sur l'epuisement: {mesure:?}"
            );
            assert!(
                mesure.episode.is_some(),
                "aucun episode observe: {mesure:?}"
            );
            assert!(
                matches!(mesure.cpu, Some(c) if c < PLAFOND_CPU),
                "attente active pendant l'episode: {mesure:?}"
            );
            assert_eq!(mesure.lignes, 1, "une ligne par episode: {mesure:?}");
            assert!(
                matches!(mesure.reprise, Ok(d) if d < PLAFOND_REPRISE),
                "le serveur ne sert pas de nouveau: {mesure:?}"
            );
        }
    }
}
