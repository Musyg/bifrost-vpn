//! Test d'intrusion de l'IPC.
//!
//! Exigence du perimetre: un processus non privilegie qui n'est pas autorise ne
//! doit pas pouvoir piloter le daemon. Ces tests montent un vrai serveur, s'y
//! connectent avec un vrai client, et verifient la decision de bout en bout,
//! pas seulement la fonction d'autorisation.

#![cfg(unix)]

use std::path::PathBuf;

use bifrost_ipc::protocol::{Command, Request, Response};
use bifrost_ipc::transport::{IpcClient, IpcServer};
use bifrost_ipc::{AuthPolicy, PeerIdentity};

fn socket_path(nom: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "bifrost-ipc-test-{}-{nom}.sock",
        std::process::id()
    ))
}

fn euid() -> u32 {
    // SAFETY: geteuid ne touche a rien et ne peut pas echouer.
    unsafe { libc::geteuid() }
}

/// Le serveur repond a une requete puis rend la main.
async fn serve_once(mut server: IpcServer) {
    if let Ok(mut conn) = server.accept().await
        && conn.recv().await.is_ok()
    {
        let _ = conn.send(&Response::Ok).await;
    }
}

/// Un processus non autorise doit etre refuse.
///
/// Le test n'a de sens que lance par un utilisateur non privilegie: root est
/// toujours autorise par conception. Lance en root, il se declare saute plutot
/// que de passer sans rien avoir verifie.
#[tokio::test]
async fn un_processus_non_autorise_ne_peut_pas_piloter_le_daemon() {
    if euid() == 0 {
        eprintln!("SKIPPED: lance en root, qui est autorise par conception");
        return;
    }

    let path = socket_path("refus");
    // Politique par defaut: root uniquement.
    let server = IpcServer::bind(&path, AuthPolicy::default(), None)
        .await
        .expect("bind");
    tokio::spawn(serve_once(server));

    let mut client = IpcClient::connect(&path).await.expect("connect");
    let response = client
        .request(&Request::new(Command::Status))
        .await
        .expect("le serveur doit repondre, meme pour refuser");

    match response {
        Response::Error { message } => {
            assert!(
                message.contains("refuse"),
                "le refus doit etre explicite, recu: {message}"
            );
        }
        autre => panic!("un uid non autorise a obtenu une reponse: {autre:?}"),
    }
}

/// Le meme processus, une fois son uid autorise, doit passer. Sans ce test, le
/// precedent pourrait passer parce que l'IPC est simplement casse.
#[tokio::test]
async fn un_uid_explicitement_autorise_est_accepte() {
    let path = socket_path("acces");
    let policy = AuthPolicy {
        allowed_uids: vec![0, euid()],
        allowed_gid: None,
    };
    let server = IpcServer::bind(&path, policy, None).await.expect("bind");
    tokio::spawn(serve_once(server));

    let mut client = IpcClient::connect(&path).await.expect("connect");
    let response = client
        .request(&Request::new(Command::Status))
        .await
        .expect("requete");

    assert!(
        matches!(response, Response::Ok),
        "un uid autorise doit passer, recu: {response:?}"
    );
}

/// Le socket ne doit jamais etre accessible a tout le monde: meme si
/// l'autorisation applicative refuse, un socket en 0666 laisse n'importe qui
/// consommer les ressources du daemon.
#[tokio::test]
async fn le_socket_n_est_pas_accessible_a_tous() {
    use std::os::unix::fs::PermissionsExt;

    let path = socket_path("permissions");
    let _server = IpcServer::bind(&path, AuthPolicy::default(), None)
        .await
        .expect("bind");

    let mode = std::fs::metadata(&path)
        .expect("metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        mode & 0o007,
        0,
        "le socket est accessible aux autres (mode {mode:o})"
    );
    assert_eq!(mode, 0o660, "mode attendu 660, obtenu {mode:o}");
}

/// Le socket est retire a l'arret: un fichier residuel empeche le bind suivant
/// et laisse croire qu'un daemon tourne.
#[tokio::test]
async fn le_socket_est_retire_a_l_arret() {
    let path = socket_path("nettoyage");
    {
        let _server = IpcServer::bind(&path, AuthPolicy::default(), None)
            .await
            .expect("bind");
        assert!(path.exists());
    }
    assert!(!path.exists(), "socket residuel apres arret du serveur");
}

/// Une version de protocole differente est refusee avec un message clair
/// plutot qu'interpretee au petit bonheur.
#[tokio::test]
async fn une_version_de_protocole_incompatible_est_refusee() {
    let path = socket_path("version");
    let policy = AuthPolicy {
        allowed_uids: vec![0, euid()],
        allowed_gid: None,
    };
    let server = IpcServer::bind(&path, policy, None).await.expect("bind");
    tokio::spawn(async move {
        let mut server = server;
        if let Ok(mut conn) = server.accept().await {
            match conn.recv().await {
                Ok(_) => {
                    let _ = conn.send(&Response::Ok).await;
                }
                Err(e) => {
                    let _ = conn.send(&Response::error(e.to_string())).await;
                }
            }
        }
    });

    // On envoie une trame brute: le client type ne permet pas de mentir sur la
    // version, ce qui est justement le comportement voulu.
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let mut stream = tokio::net::UnixStream::connect(&path)
        .await
        .expect("connect");
    stream
        .write_all(b"{\"version\":99,\"command\":\"status\"}\n")
        .await
        .expect("write");

    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).await.expect("read");
    assert!(
        line.contains("version") && line.contains("error"),
        "reponse inattendue: {line}"
    );
}

/// L'identite du pair sert aussi a journaliser qui a coupe le tunnel.
#[tokio::test]
async fn l_identite_du_pair_est_renseignee() {
    let path = socket_path("identite");
    let policy = AuthPolicy {
        allowed_uids: vec![0, euid()],
        allowed_gid: None,
    };
    let mut server = IpcServer::bind(&path, policy, None).await.expect("bind");

    let connexion = tokio::spawn(async move { server.accept().await });
    let _client = IpcClient::connect(&path).await.expect("connect");
    let conn = connexion.await.expect("join").expect("accept");

    let peer: &PeerIdentity = conn.peer();
    assert_eq!(peer.uid, euid());
    assert!(peer.pid.is_some(), "SO_PEERCRED doit fournir le pid");
    assert_eq!(peer.pid, Some(std::process::id() as i32));
}
