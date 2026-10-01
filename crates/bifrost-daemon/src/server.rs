//! Serveur IPC: traduit les requetes du client en commandes au superviseur.

use std::sync::mpsc::Sender;

use bifrost_core::TunnelConfig;
use bifrost_ipc::protocol::{Command, Response};
use bifrost_ipc::transport::{IpcError, IpcServer};
use bifrost_ipc::{AuthPolicy, Connection};

use crate::supervisor::{Cmd, RoutageDeclare};

/// Boucle d'acceptation. Ne rend la main qu'en cas d'erreur fatale d'ecoute.
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
}
