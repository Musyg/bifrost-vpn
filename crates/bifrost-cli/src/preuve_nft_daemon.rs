//! Recettes, sur un vrai socket Unix, du lecteur commun de la declaration
//! (`crate::declaration`) et du protocole de `prove nft --politique-daemon`.
//!
//! Le lecteur et le protocole vivent dans `declaration`, partages avec
//! `prove wfp`; ce qui reste ici est un faux daemon qui sert de vraies trames,
//! une vraie capture de noyau rendue par la reference, et les alterations que
//! la preuve doit voir. Linux seulement: le faux daemon ecoute sur un socket
//! Unix, et le client y lit l'identite du serveur par `SO_PEERCRED`.

#[cfg(test)]
mod tests {
    use crate::declaration::*;
    use crate::preuve_nft::verifier_declaration_avec;
    use bifrost_core::ports::FirewallPolicy;
    use bifrost_firewall::politique_nft::Politique;
    use bifrost_ipc::ServerRequirement;
    use bifrost_ipc::protocol::{
        DECLARATION_PARE_FEU_VERSION, DeclarationPareFeu, IssueApplication, Response,
    };
    use serde_json::Value;
    use serde_json::json;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    const INSTANCE: &str = "0123456789abcdef0123456789abcdef0123456789abcdef";

    /// L'uid effectif de ce processus, lu sans code non sur: le faux daemon
    /// des recettes tourne sous lui, et `SO_PEERCRED` rend precisement cet
    /// uid-la (le second champ de `Uid:`).
    fn mon_uid() -> u32 {
        std::fs::read_to_string("/proc/self/status")
            .unwrap()
            .lines()
            .find_map(|l| l.strip_prefix("Uid:"))
            .and_then(|champs| champs.split_whitespace().nth(1))
            .and_then(|u| u.parse().ok())
            .expect("uid effectif lisible dans /proc/self/status")
    }

    /// L'exigence des recettes de PROTOCOLE: le faux daemon a l'uid de la
    /// recette. L'exigence de production (`lire`) a ses propres recettes plus
    /// bas; celle-ci ne sert qu'a atteindre le protocole sans etre root.
    fn recette() -> ServerRequirement {
        ServerRequirement::Uid(mon_uid())
    }

    /// Une politique de production plausible, et complete: les six champs
    /// renseignes, pour qu'en changer un seul change le rendu.
    fn politique() -> FirewallPolicy {
        FirewallPolicy {
            tunnel_interface: Some("bifrost0".into()),
            tunnel_luid: None,
            fwmark: Some(51820),
            dns_resolver: "127.0.0.1".parse().unwrap(),
            allow_lan: false,
            coeur_uid: Some(1001),
            coeur_executable: None,
            resolveur_uid: Some(1002),
            resolveur_executable: None,
            resolveur_sid: None,
            resolveur_embarque: true,
        }
    }

    /// La reponse telle que le VRAI daemon l'ecrit: le type du protocole et la
    /// projection du pare-feu, pas un JSON tape a la main. Si l'un des deux
    /// derive, le lecteur strict le voit ici avant de le voir en production.
    fn trame(application: u64, issue: IssueApplication, p: Option<&FirewallPolicy>) -> Vec<u8> {
        let d = DeclarationPareFeu {
            schema_version: DECLARATION_PARE_FEU_VERSION,
            instance: INSTANCE.into(),
            application,
            moteur: "nftables".into(),
            issue,
            politique: p.map(|p| serde_json::to_value(Politique::projeter(p)).unwrap()),
        };
        let mut v = serde_json::to_vec(&Response::DeclarationPareFeu(Box::new(d))).unwrap();
        v.push(b'\n');
        v
    }

    fn posee(p: &FirewallPolicy) -> Vec<u8> {
        trame(4, IssueApplication::Posee, Some(p))
    }

    fn modifier(trame: &[u8], cle: &str, valeur: Value) -> Vec<u8> {
        let mut v: Value = serde_json::from_slice(trame).unwrap();
        v[cle] = valeur;
        let mut t = serde_json::to_vec(&v).unwrap();
        t.push(b'\n');
        t
    }

    /// Le noyau conforme a une politique: la reference que la preuve en tire,
    /// dans la forme de `nft --json`.
    fn noyau(p: &FirewallPolicy) -> Vec<u8> {
        let v = serde_json::to_value(Politique::projeter(p)).unwrap();
        serde_json::to_vec(&Politique::lire(v).unwrap().reference().unwrap()).unwrap()
    }

    /// Un faux daemon sur un vrai socket Unix: il sert ses trames dans l'ordre
    /// (la derniere se repete), verifie que la requete est exactement celle du
    /// protocole, et compte les requetes.
    struct FauxDaemon {
        dossier: PathBuf,
        socket: String,
        requetes: Arc<AtomicUsize>,
        tache: tokio::task::JoinHandle<()>,
    }

    impl FauxDaemon {
        fn dossier() -> PathBuf {
            static SUIVANT: AtomicUsize = AtomicUsize::new(0);
            let n = SUIVANT.fetch_add(1, Ordering::SeqCst);
            let d = std::env::temp_dir().join(format!("bfdecl-{}-{n}", std::process::id()));
            let _ = std::fs::remove_dir_all(&d);
            std::fs::create_dir(&d).unwrap();
            d
        }

        fn demarrer(trames: Vec<Vec<u8>>) -> Self {
            let dossier = Self::dossier();
            let chemin = dossier.join("d.sock");
            let ecoute = tokio::net::UnixListener::bind(&chemin).unwrap();
            let requetes = Arc::new(AtomicUsize::new(0));
            let compte = requetes.clone();
            let tache = tokio::spawn(async move {
                loop {
                    let Ok((flux, _)) = ecoute.accept().await else {
                        return;
                    };
                    let (lecture, mut ecriture) = tokio::io::split(flux);
                    let mut ligne = String::new();
                    if BufReader::new(lecture).read_line(&mut ligne).await.is_err() {
                        continue;
                    }
                    assert_eq!(
                        ligne, "{\"version\":1,\"command\":\"declaration-pare-feu\"}\n",
                        "requete inattendue"
                    );
                    let n = compte.fetch_add(1, Ordering::SeqCst);
                    let t = &trames[n.min(trames.len() - 1)];
                    let _ = ecriture.write_all(t).await;
                    let _ = ecriture.shutdown().await;
                }
            });
            Self {
                socket: chemin.to_string_lossy().into_owned(),
                dossier,
                requetes,
                tache,
            }
        }

        fn requetes(&self) -> usize {
            self.requetes.load(Ordering::SeqCst)
        }
    }

    impl Drop for FauxDaemon {
        fn drop(&mut self) {
            self.tache.abort();
            let _ = std::fs::remove_dir_all(&self.dossier);
        }
    }

    async fn prouver(daemon: &FauxDaemon, capture: Vec<u8>) -> Value {
        let socket = daemon.socket.clone();
        let r = verifier_declaration_avec(
            || lire_avec(&socket, Duration::from_secs(2), recette()),
            move || async move { Ok(capture) },
        )
        .await;
        let code = r.code();
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(
            code,
            match v["verdict"].as_str().unwrap() {
                "MATCH" => 0,
                "MISMATCH" => 1,
                _ => 2,
            }
        );
        v
    }

    async fn sans_collecte(daemon: &FauxDaemon) -> Value {
        let socket = daemon.socket.clone();
        let r = verifier_declaration_avec(
            || lire_avec(&socket, Duration::from_secs(2), recette()),
            || async { panic!("collecte interdite sans politique a comparer") },
        )
        .await;
        serde_json::to_value(&r).unwrap()
    }

    /// Rien de la declaration ne sort dans le rapport, hors sa version.
    ///
    /// Les horodatages sont retires avant la recherche: un instant en
    /// millisecondes contient tot ou tard `1001` ou `51820`, et la recette
    /// rougirait sur une coincidence au lieu d'une fuite.
    fn rien_de_la_declaration(rapport: &Value) {
        let mut sans_horloge = rapport.clone();
        for cle in ["started_at_unix_ms", "completed_at_unix_ms", "duration_ms"] {
            sans_horloge.as_object_mut().unwrap().remove(cle);
        }
        let texte = sans_horloge.to_string();
        for interdit in [
            "bifrost0",
            "51820",
            "1001",
            "1002",
            "127.0.0.1",
            INSTANCE,
            "uid=",
        ] {
            assert!(
                !texte.contains(interdit),
                "le rapport exporte {interdit}: {texte}"
            );
        }
        for cle in ["application", "instance", "politique", "moteur", "issue"] {
            assert!(rapport.get(cle).is_none(), "cle exportee: {cle}");
        }
    }

    #[tokio::test]
    async fn une_declaration_conforme_au_noyau_correspond() {
        let p = politique();
        let daemon = FauxDaemon::demarrer(vec![posee(&p)]);
        let r = prouver(&daemon, noyau(&p)).await;
        assert_eq!(r["verdict"], "MATCH", "{r}");
        assert_eq!(r["schema_version"], 1);
        assert_eq!(r["scope"], "nft-kernel-comparison");
        assert_eq!(r["expected_source"], "daemon-declared-active-policy");
        assert_eq!(r["policy_schema_version"], 1);
        assert_eq!(r["live_kernel"], true);
        assert_eq!(r["generation_verified"], true);
        assert_eq!(r["network_security"], "not-evaluated");
        assert!(r["failed_input"].is_null());
        // Le nom de la regle, jamais sa valeur: celle des recettes, puisque
        // le faux daemon tourne sous l'uid de la recette.
        assert_eq!(r["daemon_identity"], "uid-peer-credentials");
        assert_eq!(daemon.requetes(), 2, "N1 puis N2, ni plus ni moins");
        rien_de_la_declaration(&r);
    }

    /// Chaque parametre, change SEUL dans la declaration, face au noyau de la
    /// politique d'origine: six champs, deux sens pour les options.
    #[tokio::test]
    async fn chaque_parametre_change_seul_devient_un_ecart() {
        type Changer = fn(&mut FirewallPolicy);
        let base = politique();
        let variantes: Vec<(&str, Changer)> = vec![
            ("interface autre", |p| {
                p.tunnel_interface = Some("bifrost1".into())
            }),
            ("interface absente", |p| p.tunnel_interface = None),
            ("marque autre", |p| p.fwmark = Some(51821)),
            ("marque absente", |p| p.fwmark = None),
            ("dns autre", |p| p.dns_resolver = "::1".parse().unwrap()),
            ("lan ouvert", |p| p.allow_lan = true),
            ("coeur autre", |p| p.coeur_uid = Some(1003)),
            ("coeur absent", |p| p.coeur_uid = None),
            ("resolveur autre", |p| p.resolveur_uid = Some(1004)),
            ("resolveur absent", |p| p.resolveur_uid = None),
        ];
        for (nom, changer) in variantes {
            let mut declaree = base.clone();
            changer(&mut declaree);
            let daemon = FauxDaemon::demarrer(vec![posee(&declaree)]);
            let r = prouver(&daemon, noyau(&base)).await;
            assert_eq!(r["verdict"], "MISMATCH", "{nom}: {r}");
            assert!(!r["differences"].as_array().unwrap().is_empty(), "{nom}");
            assert_eq!(daemon.requetes(), 2, "{nom}");
        }
    }

    /// La moindre difference entre N1 et N2 rend la capture non attribuable,
    /// meme si le noyau est conforme a N1.
    #[tokio::test]
    async fn une_declaration_changee_pendant_la_collecte_n_est_pas_mesuree() {
        let p = politique();
        let mut autre = p.clone();
        autre.allow_lan = true;
        let n1 = posee(&p);
        for (nom, n2) in [
            (
                "numero suivant",
                trame(5, IssueApplication::Posee, Some(&p)),
            ),
            (
                "autre instance",
                modifier(&n1, "instance", json!("f".repeat(48))),
            ),
            ("autre politique", posee(&autre)),
            ("retrait", trame(5, IssueApplication::Retiree, None)),
            ("echec", trame(5, IssueApplication::Echec, None)),
        ] {
            let daemon = FauxDaemon::demarrer(vec![n1.clone(), n2]);
            let r = prouver(&daemon, noyau(&p)).await;
            assert_eq!(r["verdict"], "UNMEASURED", "{nom}: {r}");
            assert_eq!(
                r["reason"], "declaration du daemon modifiee pendant la collecte",
                "{nom}"
            );
            assert_eq!(r["failed_input"], "daemon-declaration", "{nom}");
            assert_eq!(daemon.requetes(), 2, "{nom}");
            rien_de_la_declaration(&r);
        }
        let daemon = FauxDaemon::demarrer(vec![n1.clone(), b"{\"result\"".to_vec()]);
        let r = prouver(&daemon, noyau(&p)).await;
        assert_eq!(r["verdict"], "UNMEASURED");
        assert_eq!(
            r["reason"],
            "declaration du daemon illisible ou injoignable apres la collecte"
        );
    }

    #[tokio::test]
    async fn un_daemon_absent_n_est_pas_mesure() {
        let daemon = FauxDaemon::demarrer(vec![posee(&politique())]);
        let socket = format!("{}.absent", daemon.socket);
        let r = verifier_declaration_avec(
            || lire_avec(&socket, Duration::from_secs(2), recette()),
            || async { panic!("collecte interdite sans declaration") },
        )
        .await;
        let r = serde_json::to_value(&r).unwrap();
        assert_eq!(r["verdict"], "UNMEASURED");
        assert_eq!(r["reason"], "daemon injoignable");
        assert_eq!(r["failed_input"], "daemon-declaration");
        assert_eq!(r["live_kernel"], false);
    }

    /// Deux refus: celui du daemon (SO_PEERCRED, message qui nomme l'appelant,
    /// jamais recopie), et celui du systeme de fichiers sur le socket.
    #[tokio::test]
    async fn un_acces_refuse_n_est_pas_mesure_et_ne_nomme_personne() {
        let refus = b"{\"result\":\"error\",\"message\":\"acces refuse pour uid=1000 gid=1000 pid=42: ni root\"}\n";
        let daemon = FauxDaemon::demarrer(vec![refus.to_vec()]);
        let r = sans_collecte(&daemon).await;
        assert_eq!(r["verdict"], "UNMEASURED");
        assert_eq!(r["reason"], "acces au daemon refuse");
        rien_de_la_declaration(&r);

        let daemon = FauxDaemon::demarrer(vec![posee(&politique())]);
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&daemon.socket, std::fs::Permissions::from_mode(0o000)).unwrap();
        let r = lire_avec(&daemon.socket, Duration::from_secs(2), recette()).await;
        match r {
            Err(refus) => assert_eq!(refus, Refus::Declaration("acces au daemon refuse")),
            // root passe outre les droits du socket: ce cas-la n'a pas ete
            // mesure, et la ligne le dit au decompte des abstentions.
            Ok(_) => println!(
                "SKIPPED: root ignore les droits d'un socket, le refus par le systeme de fichiers n'est pas mesurable ici"
            ),
        }
    }

    #[tokio::test]
    async fn une_reponse_tronquee_ou_hors_schema_n_est_pas_mesuree() {
        let p = politique();
        let bonne = posee(&p);
        let sans_fin = &bonne[..bonne.len() - 1];
        let mut cas: Vec<(&str, Vec<u8>)> = vec![
            ("sans fin de ligne", sans_fin.to_vec()),
            ("coupee", bonne[..bonne.len() / 2].to_vec()),
            ("vide", Vec::new()),
            ("tableau", b"[]\n".to_vec()),
            ("etat", b"{\"result\":\"ok\"}\n".to_vec()),
            ("erreur sans message", b"{\"result\":\"error\"}\n".to_vec()),
            (
                "autre erreur",
                b"{\"result\":\"error\",\"message\":\"requete illisible\"}\n".to_vec(),
            ),
        ];
        let mut doublon = bonne[..bonne.len() - 2].to_vec();
        doublon.extend_from_slice(b",\"moteur\":\"nftables\"}\n");
        cas.push(("cle dupliquee", doublon));
        let mut v: Value = serde_json::from_slice(&bonne).unwrap();
        v.as_object_mut()
            .unwrap()
            .insert("en_trop".into(), json!(1));
        let mut t = serde_json::to_vec(&v).unwrap();
        t.push(b'\n');
        cas.push(("cle en trop", t));
        for cle in CLES {
            let mut v: Value = serde_json::from_slice(&bonne).unwrap();
            v.as_object_mut().unwrap().remove(cle);
            let mut t = serde_json::to_vec(&v).unwrap();
            t.push(b'\n');
            cas.push((cle, t));
        }
        for (nom, cle, valeur) in [
            ("version", "schema_version", json!(2)),
            ("instance vide", "instance", json!("")),
            ("instance courte", "instance", json!("abcdef")),
            (
                "instance majuscule",
                "instance",
                json!(INSTANCE.to_uppercase()),
            ),
            ("numero negatif", "application", json!(-1)),
            ("numero texte", "application", json!("4")),
            ("moteur vide", "moteur", json!("")),
            ("issue inconnue", "issue", json!("inconnue")),
            ("posee sans politique", "politique", Value::Null),
            ("politique texte", "politique", json!("{}")),
            ("autre resultat", "result", json!("status")),
        ] {
            cas.push((nom, modifier(&bonne, cle, valeur)));
        }
        let mut flottant = bonne.clone();
        let texte = String::from_utf8(flottant.clone()).unwrap();
        flottant = texte
            .replace("\"application\":4", "\"application\":4.0")
            .into_bytes();
        cas.push(("numero flottant", flottant));
        cas.push((
            "aucune numerotee",
            modifier(
                &trame(0, IssueApplication::Aucune, None),
                "application",
                json!(3),
            ),
        ));
        cas.push((
            "aucune avec politique",
            modifier(
                &trame(0, IssueApplication::Aucune, None),
                "politique",
                json!({}),
            ),
        ));
        cas.push((
            "retrait avec politique",
            modifier(
                &trame(2, IssueApplication::Retiree, None),
                "politique",
                serde_json::to_value(Politique::projeter(&p)).unwrap(),
            ),
        ));
        cas.push((
            "echec au numero zero",
            trame(0, IssueApplication::Echec, None),
        ));
        cas.push((
            "posee au numero zero",
            trame(0, IssueApplication::Posee, Some(&p)),
        ));
        for (nom, t) in cas {
            let daemon = FauxDaemon::demarrer(vec![t]);
            let r = sans_collecte(&daemon).await;
            assert_eq!(r["verdict"], "UNMEASURED", "{nom}: {r}");
            assert!(
                [
                    HORS_SCHEMA,
                    "reponse du daemon tronquee ou illisible",
                    "le daemon a refuse la demande",
                ]
                .contains(&r["reason"].as_str().unwrap()),
                "{nom}: {r}"
            );
            assert_eq!(r["failed_input"], "daemon-declaration", "{nom}");
            rien_de_la_declaration(&r);
        }
    }

    #[tokio::test]
    async fn sans_politique_posee_rien_n_est_compare() {
        for (issue, application, raison) in [
            (
                IssueApplication::Aucune,
                0,
                "aucune politique posee par ce daemon depuis son demarrage",
            ),
            (
                IssueApplication::Retiree,
                3,
                "kill switch retire par le daemon: aucune politique a comparer",
            ),
            (
                IssueApplication::Echec,
                2,
                "derniere application du daemon en echec: etat du noyau inconnu du daemon",
            ),
        ] {
            let daemon = FauxDaemon::demarrer(vec![trame(application, issue, None)]);
            let r = sans_collecte(&daemon).await;
            assert_eq!(r["verdict"], "UNMEASURED", "{issue:?}");
            assert_eq!(r["reason"], raison);
            assert_eq!(r["live_kernel"], false);
        }
    }

    /// Ce que la reference ne sait pas decrire ne se compare pas: aucune
    /// correspondance par accident, pas meme avec un noyau vide ou conforme a
    /// autre chose. La collecte n'a meme pas lieu.
    #[tokio::test]
    async fn un_etat_non_modelise_n_est_jamais_une_correspondance() {
        let mut lo = politique();
        lo.tunnel_interface = Some("lo".into());
        let mut root = politique();
        root.coeur_uid = Some(0);
        let mut partage = politique();
        partage.resolveur_uid = partage.coeur_uid;
        let mut dns_public = politique();
        dns_public.dns_resolver = "192.0.2.1".parse().unwrap();
        for (nom, p) in [
            ("interface lo", lo),
            ("coeur root", root),
            ("identite partagee", partage),
            ("resolveur hors boucle", dns_public),
        ] {
            let daemon = FauxDaemon::demarrer(vec![posee(&p)]);
            let r = sans_collecte(&daemon).await;
            assert_eq!(r["verdict"], "UNMEASURED", "{nom}");
            assert_eq!(
                r["reason"], "politique declaree hors du perimetre de la reference nft v1",
                "{nom}"
            );
            rien_de_la_declaration(&r);
        }
        let wfp = modifier(&posee(&politique()), "moteur", json!("wfp"));
        let daemon = FauxDaemon::demarrer(vec![wfp]);
        let r = sans_collecte(&daemon).await;
        assert_eq!(r["verdict"], "UNMEASURED");
        assert_eq!(
            r["reason"],
            "moteur de pare-feu du daemon hors perimetre de la reference nft"
        );
    }

    /// Les refus de la collecte gardent leur raison: la declaration ne
    /// remplace jamais une observation manquee.
    #[tokio::test]
    async fn un_noyau_illisible_reste_non_mesure() {
        for raison in [
            "acces noyau refuse; aucune elevation automatique",
            "generation nft modifiee pendant la collecte",
        ] {
            let daemon = FauxDaemon::demarrer(vec![posee(&politique())]);
            let socket = daemon.socket.clone();
            let r = verifier_declaration_avec(
                || lire_avec(&socket, Duration::from_secs(2), recette()),
                move || async move { Err(raison) },
            )
            .await;
            let r = serde_json::to_value(&r).unwrap();
            assert_eq!(r["verdict"], "UNMEASURED");
            assert_eq!(r["reason"], raison);
            assert_eq!(r["failed_input"], "observed");
            assert_eq!(daemon.requetes(), 1, "pas de N2 sans capture");
        }
    }

    /// Un daemon qui accepte et se tait ne fait pas attendre la preuve.
    #[tokio::test]
    async fn un_daemon_muet_rend_la_main() {
        let dossier = FauxDaemon::dossier();
        let chemin = dossier.join("muet.sock");
        let ecoute = tokio::net::UnixListener::bind(&chemin).unwrap();
        let garde = tokio::spawn(async move {
            let mut tenus = Vec::new();
            while let Ok((flux, _)) = ecoute.accept().await {
                tenus.push(flux);
            }
        });
        let r = lire_avec(
            &chemin.to_string_lossy(),
            Duration::from_millis(200),
            recette(),
        )
        .await;
        garde.abort();
        let _ = std::fs::remove_dir_all(&dossier);
        assert_eq!(
            r,
            Err(Refus::Declaration("daemon sans reponse dans le delai"))
        );
    }

    /// LA garde de D1b.3c, sur son occurrence reelle: `lire`, la lecture de
    /// production, face a un faux daemon qui sert une declaration conforme au
    /// noyau. Non root, il n'est pas admis, et il ne recoit RIEN: le client
    /// verifie avant d'ecrire. Root, il est admis, et c'est la limite de la
    /// regle: elle dit qui ecoute, pas que c'est le daemon. Les deux branches
    /// mesurent.
    #[tokio::test]
    async fn la_preuve_exige_un_serveur_root() {
        let p = politique();
        let daemon = FauxDaemon::demarrer(vec![posee(&p)]);
        let socket = daemon.socket.clone();
        let capture = noyau(&p);
        let root = mon_uid() == 0;
        let r = verifier_declaration_avec(
            || lire(&socket),
            move || async move {
                assert!(root, "collecte interdite sans identite admise");
                Ok(capture)
            },
        )
        .await;
        let code = r.code();
        let r = serde_json::to_value(&r).unwrap();
        if root {
            assert_eq!(r["verdict"], "MATCH", "{r}");
            assert_eq!(r["daemon_identity"], "root-peer-credentials");
            assert_eq!(daemon.requetes(), 2);
        } else {
            assert_eq!(code, 2);
            assert_eq!(r["verdict"], "UNMEASURED", "{r}");
            assert_eq!(r["reason"], "serveur de la declaration non privilegie");
            assert_eq!(r["failed_input"], "daemon-identity");
            assert!(r["daemon_identity"].is_null(), "{r}");
            assert_eq!(r["live_kernel"], false);
            assert_eq!(
                daemon.requetes(),
                0,
                "une requete est partie vers un serveur refuse"
            );
        }
        rien_de_la_declaration(&r);
    }

    /// L'identite se reverifie a N2: un serveur admis pour la premiere
    /// lecture et refuse pour la seconde ne laisse rien comparer, et le
    /// rapport ne garde pas la regle de N1.
    #[tokio::test]
    async fn une_identite_refusee_apres_la_collecte_n_est_pas_mesuree() {
        let p = politique();
        let d = DeclarationPareFeu {
            schema_version: DECLARATION_PARE_FEU_VERSION,
            instance: INSTANCE.into(),
            application: 4,
            moteur: "nftables".into(),
            issue: IssueApplication::Posee,
            politique: Some(serde_json::to_value(Politique::projeter(&p)).unwrap()),
        };
        for (refus, entree) in [
            (
                Refus::Identite("serveur de la declaration non privilegie"),
                "daemon-identity",
            ),
            (
                Refus::Identite("identite du serveur de la declaration illisible"),
                "daemon-identity",
            ),
        ] {
            let mut lectures = vec![Err(refus), Ok((d.clone(), "root-peer-credentials"))];
            let capture = noyau(&p);
            let r = verifier_declaration_avec(
                || std::future::ready(lectures.pop().unwrap()),
                move || async move { Ok(capture) },
            )
            .await;
            let r = serde_json::to_value(&r).unwrap();
            assert_eq!(r["verdict"], "UNMEASURED", "{r}");
            assert_eq!(r["reason"], refus.raison());
            assert_eq!(r["failed_input"], entree);
            assert!(r["daemon_identity"].is_null(), "{r}");
            assert_eq!(r["live_kernel"], true);
        }
        // Et a N1: rien n'est lu, rien n'est collecte.
        let r = verifier_declaration_avec(
            || {
                std::future::ready(Err(Refus::Identite(
                    "identite du serveur de la declaration illisible",
                )))
            },
            || async { panic!("collecte interdite sans identite admise") },
        )
        .await;
        let r = serde_json::to_value(&r).unwrap();
        assert_eq!(r["failed_input"], "daemon-identity");
        assert!(r["daemon_identity"].is_null(), "{r}");
    }
}
