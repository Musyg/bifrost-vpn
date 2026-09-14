//! Le dernier metre: un PROFIL de coeur monte un tunnel PAR COEUR.
//!
//! Ce que les tests unitaires du superviseur donnent deja: que le peripherique
//! choisi est le bon, et que le refus tombe a la porte quand la decision et le
//! profil ne s'accordent pas. Ce qu'ils ne peuvent pas donner, parce qu'il faut
//! un vrai processus: qu'un profil arrive par l'IPC engendre reellement une
//! configuration, lance reellement un coeur, et que la connexion n'aboutit que
//! si ce coeur a repondu.
//!
//! # Comment un coeur est simule ici, et pourquoi c'est honnete
//!
//! Ni sing-box ni Xray ne sont installes sur les machines de recette. La
//! doublure de `coeurs::doublure` parle le minimum de l'API Clash, mais elle se
//! lance avec SES arguments, alors que le superviseur, lui, lance ce que
//! `lancement::preparer` engendre - `sing-box run -c <config>`. Un enrobage
//! nomme `sing-box` fait le pont: il ignore les arguments qu'on lui donne et
//! passe la main a la doublure.
//!
//! Ce qui est donc mesure est le chemin du superviseur en entier - selection du
//! peripherique, ecriture de la configuration, lancement, attente de la reponse
//! du coeur, montage - et non le comportement de sing-box. Cette derniere
//! moitie reste a la charge d'une recette sur machine equipee, et c'est deja ce
//! que dit l'en-tete de `tests/coeurs.rs`.
//!
//! L'enrobage est un script shell: la recette ne tourne donc que sous Unix, et
//! rend SKIPPED ailleurs plutot que PASSED par defaut.

/// Ailleurs que sous Unix la recette ne peut pas tourner, et le dit.
///
/// SKIPPED plutot que PASSED par defaut: un test vert qui n'a rien execute est
/// pire que pas de test du tout, parce qu'il se compte dans le total.
#[cfg(not(unix))]
#[test]
fn un_profil_de_coeur_ecrit_la_configuration_lance_le_coeur_et_monte_le_tun() {
    println!("SKIPPED: l'enrobage qui fait passer la doublure pour sing-box est un script shell");
}

#[cfg(unix)]
mod sous_unix {
    use std::path::{Path, PathBuf};
    use std::sync::mpsc;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use bifrost_core::Result;
    use bifrost_core::config::{Portage, TunnelConfig};
    use bifrost_core::ports::{DnsManager, FirewallPolicy, KillSwitch, TunnelDevice};
    use bifrost_core::profil::Profil;
    use bifrost_daemon::coeurs::doublure::Configuration;
    use bifrost_daemon::coeurs::identite::IdentiteCoeur;
    use bifrost_daemon::supervisor::{
        Carnetier, CheminCoeur, Cmd, Decision, Equipement, Resolveur, Supervisor,
    };

    /// Un lien de partage de documentation. RFC 5737 pour l'adresse, RFC 2606 pour
    /// le nom: ni l'un ni l'autre ne designe une machine reelle.
    const LIEN: &str =
        "hysteria2://mot-de-passe-de-documentation@203.0.113.8:8443/?sni=exemple.test#Essai";

    /// Le second candidat. Meme discipline: RFC 5737 pour l'adresse, RFC 2606
    /// pour le nom, clef factice.
    ///
    /// Il n'est joint par personne dans cette recette - aucune de ces adresses
    /// n'existe - et ce n'est pas ce qu'on y mesure: ce qu'on verifie est
    /// qu'un VRAI sing-box accepte une configuration a deux sorties derriere un
    /// selecteur, ce qu'une etiquette en double ou mal formee lui ferait
    /// refuser au demarrage.
    fn lien_reality() -> String {
        format!(
            "vless://4292f5ab-8963-476c-8052-3615895ce4f1@203.0.113.9:443?security=reality&flow=xtls-rprx-vision&encryption=none&fp=chrome&type=tcp&pbk={}&sid=d8c6b58bcbb0c323&sni=exemple.test#Repli",
            "a".repeat(43)
        )
    }

    fn port_mort() -> u16 {
        bifrost_daemon::coeurs::port::port_sans_personne().unwrap()
    }

    fn repertoire_temporaire(nom: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("bifrost-par-coeur-{nom}"));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn vivant(pid: u32) -> bool {
        // SAFETY: kill avec le signal 0 ne fait que tester l'existence du
        // processus; aucun pointeur, aucune memoire partagee.
        unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
    }

    fn attendre_mort(pid: u32, delai: Duration) -> bool {
        let fin = Instant::now() + delai;
        while Instant::now() < fin {
            if !vivant(pid) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        !vivant(pid)
    }

    /// Pose l'enrobage `sing-box` qui passe la main a la doublure, et rend le
    /// repertoire des binaires.
    ///
    /// L'enrobage ignore `run -c <config>`: la configuration que le superviseur
    /// engendre est ecrite pour de bon et verifiee par la recette, mais la doublure
    /// ne saurait pas la lire.
    ///
    /// `sorties` sont les etiquettes que la doublure acceptera. Les faire
    /// diverger de celles que `sing_box_avec` engendre rendrait la doublure
    /// incapable de repondre a une bascule que le daemon aurait toutes les
    /// raisons de croire legitime, et le desaccord se lirait comme une panne du
    /// daemon.
    fn poser_l_enrobage(rep: &Path, api: u16, secret: &str, sorties: &[String]) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let binaires = rep.join("binaires");
        std::fs::create_dir_all(&binaires).unwrap();

        let json = rep.join("doublure.json");
        std::fs::write(
            &json,
            serde_json::to_string(&Configuration {
                port: api,
                secret: secret.to_owned(),
                selecteur: bifrost_daemon::supervisor::SELECTEUR.to_owned(),
                sorties: sorties.to_vec(),
            })
            .unwrap(),
        )
        .unwrap();

        let daemon = PathBuf::from(env!("CARGO_BIN_EXE_bifrost-daemon"));
        let enrobage = binaires.join("sing-box");
        std::fs::write(
            &enrobage,
            format!(
                "#!/bin/sh\nexec {} --faux-coeur {}\n",
                daemon.display(),
                json.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&enrobage, std::fs::Permissions::from_mode(0o755)).unwrap();
        binaires
    }

    /// Le pare-feu de doublure: il retient les politiques posees, dans l'ordre.
    struct KillSwitchTemoin {
        posees: Arc<Mutex<Vec<FirewallPolicy>>>,
        arme: Arc<Mutex<bool>>,
    }

    impl KillSwitch for KillSwitchTemoin {
        fn engage(&mut self, policy: &FirewallPolicy) -> Result<()> {
            self.posees.lock().unwrap().push(policy.clone());
            *self.arme.lock().unwrap() = true;
            Ok(())
        }
        fn disengage(&mut self) -> Result<()> {
            *self.arme.lock().unwrap() = false;
            Ok(())
        }
        fn is_engaged(&self) -> Result<bool> {
            Ok(*self.arme.lock().unwrap())
        }
        fn backend(&self) -> &'static str {
            "temoin"
        }
    }

    /// Le peripherique de doublure. Il note son nom ET l'etat du kill switch au
    /// moment ou on le monte.
    ///
    /// Cette seconde mesure est le point: elle dit que le TUN n'a jamais ete monte
    /// devant un pare-feu ouvert. Combinee au fait que le coeur est lance dans la
    /// meme fonction, juste avant `up`, elle donne la chaine entiere - armer,
    /// lancer, monter - sans avoir a instrumenter le lancement lui-meme.
    struct TunnelTemoin {
        nom: &'static str,
        vues: Arc<Mutex<Vec<(String, bool)>>>,
        arme: Arc<Mutex<bool>>,
        /// Le meme signal que consulte le vrai `CoeurTunnel`.
        ///
        /// Le temoin REPRODUIT ici le contrat du peripherique par coeur - un
        /// tunnel dont le coeur n'est plus publie n'est pas vivant - et rien
        /// d'autre. Ce que cette recette mesure n'est pas ce contrat, qui est
        /// eprouve sur le VRAI peripherique dans `tests/coeur_tunnel.rs`, mais
        /// ce que le SUPERVISEUR en fait: perdre le tunnel, le demonter, et
        /// relancer un coeur.
        coeur_actif: tokio::sync::watch::Receiver<Option<std::net::SocketAddr>>,
    }

    impl TunnelDevice for TunnelTemoin {
        fn up(&mut self, _cfg: &TunnelConfig) -> Result<()> {
            let arme = *self.arme.lock().unwrap();
            self.vues
                .lock()
                .unwrap()
                .push((format!("up:{}", self.nom), arme));
            Ok(())
        }
        fn down(&mut self, _cfg: &TunnelConfig) -> Result<()> {
            let arme = *self.arme.lock().unwrap();
            self.vues
                .lock()
                .unwrap()
                .push((format!("down:{}", self.nom), arme));
            Ok(())
        }
        /// Vivant tant qu'un coeur est publie.
        ///
        /// Rendre toujours vivant ferait passer la recette meme si le
        /// superviseur ignorait completement la mort du coeur.
        fn handshake(
            &self,
            _cfg: &TunnelConfig,
        ) -> Result<Option<bifrost_core::ports::HandshakeInfo>> {
            if self.coeur_actif.borrow().is_none() {
                return Err(bifrost_core::Error::Tunnel(
                    "le coeur qui porte ce tunnel n'est plus la".into(),
                ));
            }
            Ok(Some(bifrost_core::ports::HandshakeInfo {
                last_handshake: Some(std::time::SystemTime::now()),
                rx_bytes: 1,
                tx_bytes: 1,
            }))
        }
    }

    struct DnsMuet;

    impl DnsManager for DnsMuet {
        fn apply(&mut self, _i: &str, _p: &bifrost_core::config::DnsPolicy) -> Result<()> {
            Ok(())
        }
        fn restore(&mut self) -> Result<()> {
            Ok(())
        }
        fn backend(&self) -> &'static str {
            "muet"
        }
    }

    /// Le profil du client: un TUN, des adresses, et un coeur derriere.
    fn configuration_par_coeur() -> Box<TunnelConfig> {
        Box::new(TunnelConfig {
            interface: "bifrost0".into(),
            addresses: vec!["10.7.0.2/32".parse().unwrap()],
            mtu: 1420,
            dns: bifrost_core::config::DnsPolicy {
                local_resolver: "127.0.0.1".parse().unwrap(),
                upstream: vec!["9.9.9.9".parse().unwrap()],
                // Pas de resolveur embarque: cette recette mesure le chemin du
                // coeur, et lancer un dnscrypt-proxy demanderait le :53, donc root.
                embarque: false,
                anti_telemetrie: bifrost_core::config::ProfilTelemetrie::Aucun,
            },
            allow_lan: false,
            // DEUX candidats, dans cet ordre-la. La selection doit remettre
            // REALITY en tete - le plan la prefere sur un reseau non censure -
            // donc l'ordre du fichier ne doit decider de rien.
            portage: Portage::Coeur(Box::new(
                bifrost_core::profil::Profils::try_from(vec![
                    Profil::depuis_lien(LIEN).expect("le lien de documentation doit se lire"),
                    Profil::depuis_lien(&lien_reality()).expect("le lien REALITY doit se lire"),
                ])
                .expect("deux transports distincts"),
            )),
        })
    }

    /// Le chemin complet, de l'IPC au processus.
    #[test]
    fn un_profil_de_coeur_ecrit_la_configuration_lance_le_coeur_et_monte_le_tun() {
        let rep = repertoire_temporaire("chemin-complet");
        // L'API que la doublure va lier, tenue jusqu'a son lancement. Le
        // mandataire, lui, n'a personne derriere: ce que la recette eprouve est
        // la PUBLICATION de son adresse, pas un relais.
        let reserve_api = bifrost_daemon::coeurs::port::reserver().unwrap();
        let api = reserve_api.port();
        let socks = bifrost_daemon::coeurs::socks::Mandataire::nouveau(
            std::net::SocketAddr::from(([127, 0, 0, 1], port_mort())),
            bifrost_daemon::coeurs::socks::Identifiants::nouveaux("bifrost", "recette").unwrap(),
        );
        let secret = bifrost_daemon::coeurs::alea::secret().unwrap();
        // Les etiquettes que le superviseur engendrera pour ce profil: le nom
        // de la technique de chaque profil. Les ecrire ici plutot que de les
        // recopier a la main garde la doublure d'accord avec la configuration
        // meme si les noms changent.
        let sorties: Vec<String> = bifrost_evasion::Technique::TOUTES
            .iter()
            .map(|t| t.nom().to_owned())
            .collect();
        let binaires = poser_l_enrobage(&rep, api, &secret, &sorties);
        let configurations = rep.join("configurations");

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let (poignee, actif, tache) = bifrost_daemon::coeurs::atelier::ouvrir();
        runtime.spawn(tache);

        // La sonde de vitalite s'assemble ici comme dans `main.rs`: elle vit
        // sur le runtime, comme l'atelier. Elle n'est pas ce que cette recette
        // eprouve - `tests/vitalite.rs` s'en charge, contre un vrai coeur -
        // mais la construire pour de vrai plutot que de la simuler garde ce
        // montage identique a celui de production.
        //
        // La bascule a chaud s'assemble de meme, et sur la MEME adresse: si les
        // deux visaient deux selecteurs, on basculerait l'un en sondant
        // l'autre. C'est aussi ce que fait `main.rs`.
        let adresse_du_coeur = bifrost_daemon::coeurs::vitalite::Adresse {
            api: std::net::SocketAddr::from(([127, 0, 0, 1], api)),
            secret: secret.clone(),
            selecteur: bifrost_daemon::supervisor::SELECTEUR.to_owned(),
        };
        let (sonde, veille) = bifrost_daemon::coeurs::vitalite::ouvrir(adresse_du_coeur.clone());
        runtime.spawn(veille);
        let (bascule, conduite) = bifrost_daemon::coeurs::bascule::ouvrir(adresse_du_coeur);
        runtime.spawn(conduite);

        let vues = Arc::new(Mutex::new(Vec::new()));
        let posees = Arc::new(Mutex::new(Vec::new()));
        let arme = Arc::new(Mutex::new(false));

        let superviseur = Supervisor::new(
            Box::new(KillSwitchTemoin {
                posees: posees.clone(),
                arme: arme.clone(),
            }),
            Box::new(TunnelTemoin {
                nom: "direct",
                vues: vues.clone(),
                arme: arme.clone(),
                coeur_actif: actif.clone(),
            }),
            Box::new(DnsMuet),
            IdentiteCoeur::default(),
            Resolveur::default(),
            Equipement {
                // La demarche ne se pose plus a la main: le superviseur la
                // DEDUIT du profil recu. Cette recette en devient une preuve de
                // plus - c'est le lien hysteria2 ci-dessus, et rien d'autre,
                // qui fait choisir la voie par coeur et sing-box avec elle.
                decision: Decision::default(),
                // Muet: cette recette ne doit rien ecrire dans le repertoire de
                // l'utilisateur qui l'execute. Une cle absente suffit a ce que
                // rien ne soit note, et la date reste fixe pour que le tableau
                // de survie soit lu au meme jour a chaque execution.
                carnetier: Carnetier {
                    cle: || Err("recette: reseau non identifie".to_owned()),
                    noter: |_, _, _| Ok(()),
                    souvenir: |_| Ok(bifrost_evasion::MemoireReseau::vierge()),
                    aujourd_hui: || Ok(bifrost_evasion::Date::new(2026, 6, 1)),
                },
                atelier: Some(poignee),
                chemin_coeur: Some(CheminCoeur {
                    tunnel: Box::new(TunnelTemoin {
                        nom: "coeur",
                        vues: vues.clone(),
                        arme: arme.clone(),
                        coeur_actif: actif.clone(),
                    }),
                    emplacements: bifrost_daemon::coeurs::lancement::Emplacements {
                        binaires,
                        configurations: configurations.clone(),
                    },
                    // Clone: la recette relit l'adresse ET les identifiants
                    // plus bas, sur le fichier que le superviseur aura ecrit.
                    socks: socks.clone(),
                    api,
                    secret: secret.clone(),
                    sonde,
                    bascule,
                }),
            },
        );

        // Le superviseur tourne sur un fil systeme ordinaire, comme en
        // production: c'est ce qui autorise l'atelier a bloquer.
        let (tx, rx) = mpsc::channel::<Cmd>();
        let fil = std::thread::spawn(move || superviseur.run(rx));

        // Rendue a l'instant ou le superviseur va lancer le coeur, qui la
        // liera: c'est `Connect` qui declenche ce lancement.
        reserve_api.liberer();
        let (repondre, reponse) = tokio::sync::oneshot::channel();
        tx.send(Cmd::Connect(configuration_par_coeur(), repondre))
            .unwrap();
        runtime
            .block_on(reponse)
            .expect("le superviseur doit repondre")
            .expect("la connexion par coeur doit aboutir");

        // 1. La configuration a ete ECRITE, et elle porte le profil.
        let ecrite = configurations.join("sing-box.json");
        let texte = std::fs::read_to_string(&ecrite)
            .unwrap_or_else(|e| panic!("{} non lisible: {e}", ecrite.display()));
        assert!(
            texte.contains("203.0.113.8"),
            "la sortie doit porter le serveur du profil: {texte}"
        );
        assert!(
            texte.contains("exemple.test"),
            "et son nom de serveur TLS: {texte}"
        );
        assert!(
            texte.contains(&socks.adresse.port().to_string()),
            "et l'entree SOCKS doit etre celle que l'atelier publie: {texte}"
        );
        // L'entree ne s'ouvre pas a qui passe. Verifie ICI, sur le fichier
        // reellement ecrit par le superviseur, et pas seulement sur ce que le
        // generateur rend: entre les deux il y a le cablage, et c'est lui qui
        // manquait.
        assert!(
            texte.contains(socks.identifiants.mot_de_passe()),
            "l'entree SOCKS engendree n'exige rien: tout processus local sortirait par le tunnel: {texte}"
        );
        assert!(
            !texte.contains("\"type\": \"direct\""),
            "une sortie directe ici ferait sortir le trafic en clair: {texte}"
        );

        // 1 bis. LES DEUX candidats sont ecrits, derriere le meme selecteur, et
        //        c'est la SELECTION qui a designe le defaut - pas l'ordre du
        //        fichier, qui donne hysteria2 en premier. Sans les deux, la
        //        course n'aurait rien a parcourir; sans le bon defaut, la
        //        selection serait un decor.
        let ecrit: serde_json::Value =
            serde_json::from_str(&texte).expect("la configuration ecrite doit etre du JSON");
        let sorties = ecrit["outbounds"].as_array().expect("des sorties");
        let etiquettes: Vec<&str> = sorties
            .iter()
            .filter_map(|o| o["tag"].as_str())
            .filter(|t| *t != bifrost_daemon::supervisor::SELECTEUR)
            .collect();
        assert_eq!(
            etiquettes,
            vec!["vless-reality-vision", "hysteria2"],
            "les deux candidats doivent etre ecrits, la retenue en tete: {texte}"
        );
        let selecteur = sorties
            .iter()
            .find(|o| o["tag"] == bifrost_daemon::supervisor::SELECTEUR)
            .expect("le selecteur doit exister");
        assert_eq!(
            selecteur["default"], "vless-reality-vision",
            "le defaut du selecteur est ce que la selection a retenu: {texte}"
        );
        // Et le champ sans lequel une bascule laisserait le trafic sur la
        // sortie gelee.
        //
        // Ce que cette ligne prouve, et ce qu'elle ne prouve PAS: la
        // configuration remise au coeur le porte. Elle ne dit rien de ce qu'un
        // vrai sing-box en fait - l'enrobage de cette recette ignore
        // `run -c <config>`, voir `poser_l_enrobage`. Que le champ soit
        // accepte sur un selecteur et pas seulement sur un urltest se lit dans
        // la documentation amont (verifie le 20 aout 2026) et se mesurera avec
        // `tests/vitalite.rs`, qui veut un vrai binaire.
        assert_eq!(
            selecteur["interrupt_exist_connections"], true,
            "le selecteur doit couper les connexions liees a la sortie abandonnee: {texte}"
        );

        // 2. Le bon peripherique a ete monte, et le kill switch etait deja
        //    arme a ce moment-la.
        let montes = vues.lock().unwrap().clone();
        assert_eq!(
            montes,
            vec![("up:coeur".to_owned(), true)],
            "le TUN du chemin par coeur, et lui seul, monte derriere un pare-feu deja arme"
        );

        // 3. L'etat annonce est bien Connected, et le kill switch tient.
        //
        // Sans cette mesure, "la connexion doit aboutir" ne voudrait pas dire
        // ce qu'elle a l'air de dire: un echec classe passager ferait repartir
        // la machine en tentative et `connect` rendrait quand meme Ok. C'est
        // exactement ce qui arrivait avant le 19/08/2026, et ce que le
        // marqueur lu par `is_retryable` a ferme.
        let (repondre, reponse) = tokio::sync::oneshot::channel();
        tx.send(Cmd::Status(repondre)).unwrap();
        let etat = runtime
            .block_on(reponse)
            .expect("le superviseur doit repondre");
        assert_eq!(
            etat.state,
            bifrost_core::state::State::Connected,
            "un tunnel par coeur doit etre annonce connecte"
        );
        assert!(etat.kill_switch_engaged, "et le kill switch tient");

        // 4. Une politique a bien ete posee avant tout cela.
        assert!(
            !posees.lock().unwrap().is_empty(),
            "le kill switch precede le lancement du coeur"
        );

        // 5. Un vrai processus tourne et ECOUTE.
        //
        // La distinction compte: `ss` absent n'est pas la meme chose que
        // personne au bout du port. Le premier cas retire une propriete de la
        // recette et le dit; le second est une panne.
        let pid = match pid_qui_ecoute(api) {
            Ok(p) => Some(p),
            Err(raison) if raison.starts_with("ss indisponible") => {
                println!("NON VERIFIE: {raison}");
                None
            }
            Err(raison) => panic!("un coeur devait ecouter sur l'API: {raison}"),
        };

        // 6. Un coeur qui meurt tout seul est remarque, et remplace.
        //
        // C'est le maillon qui manquait: l'interface d'un tunnel par coeur tient
        // debout meme quand le coeur est mort, donc rien ne signalait la panne.
        // Desormais l'atelier depublie, le peripherique cesse d'etre vivant, le
        // superviseur perd le tunnel, le demonte, et sa reprise ordinaire
        // relance un coeur. Aucun mecanisme de redemarrage a part: c'est le
        // chemin de reprise qui existait deja, avec son propre recul.
        //
        // Le coeur est tue par son PID et par SIGKILL - jamais par un motif de
        // nom, et sans le moindre arret propre.
        if let Some(ancien) = pid {
            tuer(ancien);

            // Attendre sur les MONTAGES, et non sur le processus. Le coeur
            // repond avant que l'interface ne soit montee - c'est l'ordre voulu,
            // le coeur devant etre debout quand le tunnel s'appuie sur lui - donc
            // observer le processus laisse une fenetre ou `up:coeur` n'est pas
            // encore inscrit. La recette a echoue exactement la, une fois, sous
            // la charge d'une compilation: `["up:coeur", "down:coeur"]` au lieu
            // des trois attendus. Ce n'etait pas la machine, c'etait la recette
            // qui se synchronisait sur le mauvais evenement.
            let noms_attendus = ["up:coeur", "down:coeur", "up:coeur"];
            attendre_les_montages(&vues, noms_attendus.len(), Duration::from_secs(30));

            let revenu = attendre_un_autre_coeur(api, ancien, Duration::from_secs(30))
                .expect("un coeur devait revenir apres la mort du precedent");
            assert_ne!(revenu, ancien, "et ce doit etre un NOUVEAU processus");

            let montes = vues.lock().unwrap().clone();
            let noms: Vec<&str> = montes.iter().map(|(n, _)| n.as_str()).collect();
            assert_eq!(
                noms,
                vec!["up:coeur", "down:coeur", "up:coeur"],
                "le tunnel doit avoir ete demonte puis remonte, et jamais par la voie directe"
            );
            assert!(
                montes.iter().all(|(_, arme)| *arme),
                "le kill switch n'a pas ete baisse pendant la reprise: {montes:?}"
            );
        }

        // 7. La deconnexion le tue.
        let (repondre, reponse) = tokio::sync::oneshot::channel();
        tx.send(Cmd::Disconnect(repondre)).unwrap();
        runtime
            .block_on(reponse)
            .expect("le superviseur doit repondre")
            .expect("la deconnexion doit aboutir");

        // Le PID courant, qui n'est plus celui d'avant si une relance a eu lieu.
        if let Ok(courant) = pid_qui_ecoute(api) {
            assert!(
                attendre_mort(courant, Duration::from_secs(5)),
                "le coeur doit mourir avec la connexion"
            );
        }

        let _ = tx.send(Cmd::Shutdown);
        let _ = fil.join();
        let _ = std::fs::remove_dir_all(&rep);
    }

    /// Tue un processus par son PID, jamais par un motif de nom.
    ///
    /// Un `pkill` par motif a deja coupe des services sans rapport sur une
    /// machine de la flotte. Le PID ne vise que ce qu'on a lance.
    fn tuer(pid: u32) {
        // SAFETY: pid est le pid positif du processus qu'on a lance; kill ne
        // touche aucune memoire.
        unsafe {
            libc::kill(pid as libc::pid_t, libc::SIGKILL);
        }
    }

    /// Attend qu'un coeur DIFFERENT reponde sur l'API, et rend son PID.
    ///
    /// Attendre un autre PID plutot que d'observer l'etat annonce: la reprise
    /// traverse plusieurs etats en quelques secondes, et guetter l'un d'eux
    /// serait une course. Un processus neuf, lui, est un fait stable.
    /// Attend que le journal des montages atteigne une longueur.
    ///
    /// Ne rend rien et n'echoue pas: c'est l'assertion qui suit qui doit se
    /// plaindre, avec le contenu reel du journal. Une attente qui paniquerait
    /// elle-meme priverait la recette de son message le plus utile.
    fn attendre_les_montages(
        vues: &std::sync::Arc<std::sync::Mutex<Vec<(String, bool)>>>,
        combien: usize,
        delai: Duration,
    ) {
        let fin = Instant::now() + delai;
        while Instant::now() < fin {
            if vues.lock().unwrap().len() >= combien {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn attendre_un_autre_coeur(api: u16, ancien: u32, delai: Duration) -> Option<u32> {
        let fin = Instant::now() + delai;
        while Instant::now() < fin {
            if let Ok(pid) = pid_qui_ecoute(api)
                && pid != ancien
            {
                return Some(pid);
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        None
    }

    /// Le PID du processus qui ecoute sur ce port de l'API, ou la raison de ne
    /// pas pouvoir le dire.
    ///
    /// Les deux raisons ne se valent pas, d'ou la chaine plutot qu'un `None`
    /// muet: `ss` absent retire une propriete a la recette, personne au bout du
    /// port est une panne. Les confondre ferait passer la seconde pour la
    /// premiere sur une machine ou l'outil manque.
    fn pid_qui_ecoute(api: u16) -> std::result::Result<u32, String> {
        let sortie = std::process::Command::new("ss")
            .args(["-lptnH", &format!("sport = :{api}")])
            .output()
            .map_err(|e| format!("ss indisponible: {e}"))?;
        let texte = String::from_utf8_lossy(&sortie.stdout);
        let manque = || format!("personne n'ecoute sur {api}: {texte:?}");
        let debut = texte.find("pid=").ok_or_else(manque)? + 4;
        let reste = &texte[debut..];
        let fin = reste
            .find(|c: char| !c.is_ascii_digit())
            .ok_or_else(manque)?;
        reste[..fin]
            .parse()
            .map_err(|e| format!("pid illisible: {e}"))
    }
}
