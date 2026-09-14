//! Client non privilegie. Il ne touche a rien: il parle au daemon.

#![forbid(unsafe_code)]

mod inspection;
mod pilote;
mod profile;
mod render;
/// La source des reprises sous Linux. Ici et pas dans le daemon: le producteur
/// y est un processus tiers - un hook `systemd-sleep` - la ou Windows abonne le
/// daemon lui-meme. Voir l'en-tete du module.
#[cfg(target_os = "linux")]
mod reprise_linux;

use anyhow::{Context, bail};
use clap::{Parser, Subcommand};

use bifrost_ipc::protocol::{Command as IpcCommand, Request, Response};
use bifrost_ipc::transport::IpcClient;

#[derive(Parser, Debug)]
#[command(
    name = "bifrost-cli",
    version,
    about = "Client Bifrost: pilote le daemon, ne modifie rien lui-meme"
)]
struct Args {
    /// Chemin du socket Unix ou du named pipe du daemon.
    #[arg(long, global = true, default_value_t = bifrost_ipc::default_endpoint())]
    socket: String,

    /// Sortie au format JSON, pour un script ou une CI.
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Monte le tunnel.
    ///
    /// Sans --config, c'est le DAEMON qui ouvre son propre profil. C'est le
    /// defaut, et la difference n'est pas cosmetique: le profil peut etre
    /// scelle, et son dechiffrement exige le TPM donc root. Un membre du groupe
    /// gagne ainsi le droit de se connecter sans gagner celui de lire la cle.
    Connect {
        /// Envoyer CE profil-la, lu par le client, au lieu de laisser le daemon
        /// ouvrir le sien.
        #[arg(short, long)]
        config: Option<std::path::PathBuf>,
    },
    /// Demonte le tunnel et desarme le kill switch.
    Disconnect,
    /// Etat courant du tunnel et du kill switch.
    Status,
    // Sans compte de vecteurs dans l'aide: il a ete faux quatre fois dans ce
    // depot. `CheckVector::ALL` fait foi, et un nombre recopie a la main ne
    // suit pas l'enum. En `//` et non en `///`: clap publierait la remarque
    // dans l'aide, ou elle ne regarde pas l'utilisateur.
    /// Execute la suite des tests de fuite et affiche un verdict par vecteur.
    Check,
    /// URGENCE: retire les filtres du kill switch SANS passer par le daemon.
    ///
    /// Pour la machine qui n'a plus de reseau et dont le daemon est mort ou
    /// fige. Ce n'est PAS un arret ordinaire: `disconnect` demonte le tunnel et
    /// desarme proprement, en laissant le daemon savoir ce qu'il a fait. Celle-
    /// ci ouvre le trafic en clair, et laisse un daemon eventuellement vivant
    /// croire qu'il protege encore.
    ///
    /// Elle existe parce que le cycle de vie ne desarme plus rien: ni l'arret
    /// du service, ni un plantage, ni un redemarrage. Ce qui etait auparavant
    /// un effet de bord de `ExecStopPost=` devient une commande qu'on tape.
    ///
    /// Elle exige `--je-sais-ce-que-je-fais`. Un drapeau redondant plutot
    /// qu'une question posee au terminal: qui tape ceci est coupe du reseau et
    /// presse, parfois sur une console serie, parfois depuis un script de
    /// secours sans entree standard, et une invite qui attend une reponse y
    /// resterait sans fin. Le drapeau se tape en une fois, ne peut pas etre
    /// atteint par megarde, et reste lisible dans l'historique du shell le
    /// lendemain, quand il faudra expliquer pourquoi la machine a fuit.
    #[command(name = "emergency-disarm")]
    EmergencyDisarm {
        /// Exigee. Sans elle, la commande refuse et dit quoi taper.
        #[arg(long = "je-sais-ce-que-je-fais")]
        je_sais_ce_que_je_fais: bool,
    },
    /// Range un profil: le sceller, ou dire sous quelle forme il est.
    Profil {
        #[command(subcommand)]
        quoi: CmdProfil,
    },
    /// Le pilote TUN de Windows, que le depot ne distribue pas.
    Pilote {
        #[command(subcommand)]
        quoi: CmdPilote,
    },
    /// Dit si quelqu'un dechiffre le TLS qui sort d'ici.
    ///
    /// La chaine presentee par des serveurs publics est validee contre le jeu
    /// de racines de Mozilla EMBARQUE dans ce programme, et non contre le
    /// magasin du systeme: c'est dans ce dernier qu'une interception
    /// d'entreprise installe son autorite, donc l'y interroger reviendrait a
    /// demander au renard si le poulailler va bien.
    ///
    /// Ici et non dans le daemon: une poignee de main TLS analyse des donnees
    /// choisies par le pair, et le daemon tourne en root.
    #[command(name = "inspection-tls")]
    InspectionTls {
        /// Transmet le verdict au daemon, qui en tiendra compte a la prochaine
        /// selection de protocole.
        ///
        /// Explicite, et jamais automatique. Une commande qui a l'air de ne
        /// faire que regarder ne doit pas modifier au passage ce sur quoi le
        /// daemon fondera ses refus. Rien n'est envoye si rien n'a pu etre
        /// conclu: transmettre son ignorance ecraserait une mesure precedente.
        #[arg(long)]
        annoncer: bool,
    },
    /// Previent le daemon qu'une veille vient de se terminer.
    ///
    /// Appelee par le hook depose dans `/usr/lib/systemd/system-sleep/`, qui
    /// passe tels quels les deux arguments que systemd lui donne. Rien
    /// n'empeche de la lancer a la main - elle ne fait que demander au daemon
    /// de reposer la politique qu'il tient deja - mais son appelant normal est
    /// ce hook-la.
    ///
    /// Linux seulement: sous Windows le daemon apprend les reprises lui-meme,
    /// par le systeme, et rien ne transite par cette ligne de commande.
    #[cfg(target_os = "linux")]
    Reprise {
        /// `pre` avant l'endormissement, `post` apres le reveil.
        ///
        /// systemd appelle le meme executable aux deux moments. Seul `post`
        /// previent le daemon.
        #[arg(long)]
        phase: String,
        /// L'operation de veille, telle que systemd la nomme: `suspend`,
        /// `hibernate`, `hybrid-sleep` ou `suspend-then-hibernate`.
        #[arg(long)]
        operation: String,
    },
}

#[derive(Subcommand, Debug)]
enum CmdPilote {
    /// Telecharge wintun.dll, verifie son empreinte, et le met en place.
    ///
    /// Le depot n'embarque aucun binaire tiers. L'archive vient de l'amont, et
    /// son empreinte est epinglee dans ce programme: le reseau n'a donc pas a
    /// etre digne de confiance.
    Recuperer {
        /// Ou poser la DLL. Par defaut, a cote de ce binaire - la ou le daemon
        /// la cherche.
        #[arg(short, long)]
        vers: Option<std::path::PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
enum CmdProfil {
    /// Fabrique un lien a transmettre, a partir d'un profil signe.
    ///
    /// A coller dans une messagerie, un QR code, un courriel. La signature
    /// voyage avec, donc le chemin emprunte n'a pas besoin d'etre fiable - c'est
    /// ainsi que Tor distribue ses bridges par Telegram: une personne copie, une
    /// personne colle.
    Partager {
        /// Le profil signe, avec sa signature a cote.
        source: std::path::PathBuf,
        /// Chiffrer le lien, et engendrer la phrase de passe qui l'ouvre.
        ///
        /// A transmettre par un AUTRE chemin que le lien. Sans cela, un lien
        /// intercepte revele l'adresse du serveur - donc le brule - avant meme
        /// de reveler la cle privee.
        #[arg(short = 'x', long)]
        chiffrer: bool,
    },
    /// Chiffre le profil au repos, avec la cle de CETTE machine.
    ///
    /// Le clair n'est pas supprime: c'est la seule copie d'une cle privee, et
    /// la detruire n'appartient pas a cette commande. Elle dit quoi faire.
    Sceller {
        #[arg(short, long, default_value = bifrost_coffre::CHEMIN_PAR_DEFAUT)]
        config: std::path::PathBuf,
    },
    /// Va chercher un profil signe, par plusieurs canaux a la fois.
    ///
    /// Tous les canaux sont interroges et la serie la plus haute gagne. S'arreter
    /// au premier qui repond suffirait contre une panne, pas contre quelqu'un:
    /// qui tient un canal n'aurait qu'a se placer en tete et servir un vieux
    /// profil authentique, dont le serveur est brule ou lui appartient.
    ///
    /// Un canal qui sert une signature que la cle de confiance ne reconnait pas
    /// est ecarte, pas fatal: le traiter en erreur laisserait un seul miroir
    /// empoisonne empecher toute mise a jour.
    ///
    /// N'ecrit rien en place: le profil recupere se relit avant d'etre installe.
    Recuperer {
        /// Un canal. Repeter l'option pour en donner plusieurs.
        ///
        /// Une adresse `http://` ou `https://`, un chemin de fichier, ou un
        /// lien `bifrost1.` colle depuis une messagerie. Une cle USB est un
        /// canal, et le seul qui repond quand tout est bloque.
        #[arg(short, long = "depuis", required = true)]
        depuis: Vec<String>,
        /// La cle publique qui authentifie les profils.
        #[arg(short = 'k', long)]
        cle: Option<std::path::PathBuf>,
        /// La phrase de passe d'un lien chiffre.
        #[arg(short = 'p', long)]
        phrase: Option<String>,
        /// Ou deposer ce qui aura ete recupere.
        #[arg(short, long, default_value = "profil-recu.toml")]
        vers: std::path::PathBuf,
    },
    /// Verifie la signature d'un profil recu, puis le met en place.
    ///
    /// Le profil peut venir de n'importe ou - un lien de partage, un miroir,
    /// une cle USB, un message. C'est precisement le point: la signature dit
    /// qui l'a emis, donc le canal n'a plus besoin d'etre fiable. Sa signature
    /// `<source>.minisig` doit l'accompagner, et la cle publique de confiance
    /// etre deja en place a cote de la destination.
    Installer {
        /// Le profil recu, avec sa signature a cote.
        source: std::path::PathBuf,
        /// Ou le mettre.
        #[arg(short, long, default_value = bifrost_coffre::CHEMIN_PAR_DEFAUT)]
        config: std::path::PathBuf,
    },
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let code = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(run(args))?;
    std::process::exit(code);
}

/// Scelle un profil et dit ce qu'il reste a faire.
/// Construit un canal a partir de ce que l'utilisateur a ecrit.
///
/// Le prefixe suffit a trancher, et il n'y a pas de troisieme cas: ce qui n'est
/// pas une adresse est un chemin. Deviner autrement - tester si le fichier
/// existe, par exemple - ferait qu'une faute de frappe dans une adresse
/// deviendrait silencieusement un chemin introuvable.
fn canal(designation: &str, phrase: Option<&str>) -> Box<dyn bifrost_amorce::Canal> {
    // Sur la designation EBARBEE, et ce n'est pas de la coquetterie: un lien
    // replie par une messagerie arrive avec des espaces et des retours en tete.
    // Sans cela il echappait a son prefixe, passait pour un chemin de fichier,
    // et le rapport imprimait alors le lien entier - cle privee encodee
    // comprise. Mesure en deroulant le chemin a la main le 19 aout 2026.
    let designation = designation.trim();
    if designation.starts_with(bifrost_amorce::colle::PREFIXE)
        || bifrost_amorce::colle::est_chiffre(designation)
    {
        return match phrase {
            Some(p) => Box::new(bifrost_amorce::colle::Colle::avec_phrase(designation, p)),
            None => Box::new(bifrost_amorce::colle::Colle::nouveau(designation)),
        };
    }
    if designation.starts_with("http://") || designation.starts_with("https://") {
        if let Some(reste) = designation.strip_prefix("http://") {
            // Dit, et non refuse. La signature protege l'AUTHENTICITE quel que
            // soit le transport, donc un profil servi en clair reste sur de ce
            // point de vue - et en situation de censure, le canal en clair est
            // parfois le seul qui passe. Ce qui se perd est la confidentialite:
            // un observateur apprend quels serveurs on utilise, donc lesquels
            // bloquer. C'est a l'utilisateur de savoir ce qu'il echange.
            eprintln!(
                "attention: {reste} est servi en clair. La signature protege \n\
                 l'authenticite du profil, pas le secret de son contenu: un \n\
                 observateur apprend quels serveurs vous utilisez."
            );
        }
        Box::new(bifrost_amorce::toile::Toile::nouvelle(designation))
    } else {
        Box::new(bifrost_amorce::fichier::Fichier::nouveau(designation))
    }
}

fn recuperer(
    depuis: &[String],
    cle: Option<&std::path::Path>,
    phrase: Option<&str>,
    vers: &std::path::Path,
) -> anyhow::Result<i32> {
    let chemin_cle = cle.map(std::path::Path::to_path_buf).unwrap_or_else(|| {
        bifrost_coffre::signature::chemin_cle_de_confiance(std::path::Path::new(
            bifrost_coffre::CHEMIN_PAR_DEFAUT,
        ))
    });
    let publique = bifrost_coffre::signature::lire_cle_de_confiance(&chemin_cle)?;

    // Une phrase donnee pour des liens qui n'en avaient pas besoin se DIT.
    // Croire avoir recu un lien protege quand il ne l'etait pas est un
    // malentendu qui ne se rattrape plus: le lien est deja parti en clair.
    if phrase.is_some()
        && !depuis
            .iter()
            .any(|d| bifrost_amorce::colle::est_chiffre(d.trim()))
    {
        eprintln!(
            "attention: une phrase de passe a ete donnee, mais aucun de ces canaux \n\
             ne porte de lien chiffre. Ce qui a ete transmis l'a ete en clair.\n"
        );
    }

    let canaux: Vec<Box<dyn bifrost_amorce::Canal>> =
        depuis.iter().map(|d| canal(d, phrase)).collect();
    let moisson = bifrost_amorce::recuperer(&canaux, &publique);

    for passage in &moisson.journal {
        match &passage.issue {
            bifrost_amorce::Issue::Authentique(Some(n)) => {
                println!("  {} : signe, serie {n}", passage.canal)
            }
            bifrost_amorce::Issue::Authentique(None) => {
                println!("  {} : signe, sans serie declaree", passage.canal)
            }
            bifrost_amorce::Issue::Muet(pourquoi) => {
                println!("  {} : pas de reponse ({pourquoi})", passage.canal)
            }
            bifrost_amorce::Issue::Suspect(pourquoi) => {
                println!("  {} : A SERVI AUTRE CHOSE ({pourquoi})", passage.canal)
            }
        }
    }

    // Dit meme quand la recuperation a reussi: un canal suspect a cote de deux
    // canaux sains reste la seule chose anormale de la journee, et la noyer
    // sous le succes des autres serait la taire.
    let suspects = moisson.suspects().count();
    if suspects > 0 {
        eprintln!(
            "\n{suspects} canal(aux) ont servi quelque chose que cette cle ne reconnait pas.\n\
             Ce n'est pas une panne: quelqu'un y publie autre chose que vos profils."
        );
    }

    let Some(retenu) = moisson.retenu else {
        anyhow::bail!("aucun canal n'a rendu de profil signe par cette cle");
    };

    std::fs::write(vers, &retenu.profil)
        .with_context(|| format!("ecriture de {}", vers.display()))?;
    std::fs::write(
        bifrost_coffre::signature::chemin_signature(vers),
        &retenu.signature,
    )
    .with_context(|| format!("ecriture de la signature de {}", vers.display()))?;

    println!("\nretenu: {} -> {}", retenu.canal, vers.display());
    println!(
        "Rien n'est encore en place. Pour installer:\n    bifrost profil installer {}",
        vers.display()
    );
    Ok(0)
}

/// Va chercher le pilote TUN de Windows et le met en place.
fn recuperer_pilote(quoi: &CmdPilote) -> anyhow::Result<i32> {
    let CmdPilote::Recuperer { vers } = quoi;
    let vers = match vers {
        Some(v) => v.clone(),
        None => pilote::emplacement_par_defaut()?,
    };
    let pose = pilote::recuperer(&vers)?;
    println!("pilote en place: {}", pose.display());
    println!(
        "Wintun {}. Le pilote lui-meme ne sera installe qu'a la premiere \n\
         interface, ce qui demande les droits d'administrateur.",
        pilote::VERSION
    );
    Ok(0)
}

fn ranger(quoi: &CmdProfil) -> anyhow::Result<i32> {
    match quoi {
        CmdProfil::Sceller { config } => {
            let scelle = bifrost_coffre::sceller(config)?;
            println!("profil scelle: {}", scelle.display());
            // La commande de la plateforme, et non `rm` partout: un conseil qui
            // ne s'execute pas ne sera pas suivi, et l'etape qu'il decrit est
            // celle sans laquelle le scellement n'a rien protege.
            let effacer = if cfg!(windows) { "del" } else { "rm" };
            println!(
                "Le clair existe toujours. Le supprimer maintenant, sinon le scellement \n\
                 n'aura rien protege:\n    {effacer} {}",
                config.display()
            );
        }
        CmdProfil::Partager { source, chiffrer } => {
            let profil = std::fs::read(source)
                .with_context(|| format!("lecture de {}", source.display()))?;
            let chemin_signature = bifrost_coffre::signature::chemin_signature(source);
            let signature = std::fs::read_to_string(&chemin_signature).with_context(|| {
                format!(
                    "signature introuvable: {}. Un lien sans signature ne dit pas \
                     d'ou il vient, et ne sera pas accepte a l'arrivee.",
                    chemin_signature.display()
                )
            })?;

            if *chiffrer {
                let phrase = bifrost_amorce::colle::engendrer_phrase();
                let lien = bifrost_amorce::colle::ecrire_chiffre(&profil, &signature, &phrase)
                    .map_err(anyhow::Error::msg)?;
                // La phrase AVANT le lien, et sur la sortie d'erreur: ce qui suit
                // huit cents caracteres ne se lit pas, et separer les deux flux
                // permet de rediriger le lien sans emporter la phrase avec lui.
                eprintln!(
                    "Phrase de passe: {phrase}\n\n\
                     A transmettre par un AUTRE chemin que le lien - un appel, un autre \n\
                     service, en personne. Dans la meme conversation que le lien, elle ne \n\
                     protege de rien.\n"
                );
                println!("{lien}");
            } else {
                // Avant le lien et non apres: ce qui suit un mur de huit cents
                // caracteres ne se lit pas.
                eprintln!(
                    "ATTENTION: ce lien contient la cle privee du profil. Elle y est ENCODEE, \n\
                     pas chiffree - le base64 en a l'apparence sans en avoir l'effet. Qui lit \n\
                     ce lien apprend l'adresse de votre serveur, donc peut le bloquer, et peut \n\
                     se connecter a votre place. Le transmettre a un destinataire, jamais a \n\
                     une audience. Pour le chiffrer: --chiffrer\n"
                );
                println!("{}", bifrost_amorce::colle::ecrire(&profil, &signature));
            }
        }
        CmdProfil::Recuperer {
            depuis,
            cle,
            phrase,
            vers,
        } => {
            return recuperer(depuis, cle.as_deref(), phrase.as_deref(), vers);
        }
        CmdProfil::Installer { source, config } => {
            let origine = bifrost_coffre::signature::installer(source, config)?;
            println!("profil installe: {}", config.display());
            println!("signe: {}", origine.commentaire);
            match origine.serie {
                Some(n) => println!(
                    "serie {n}: aucun profil de serie {n} ou inferieure ne pourra le remplacer."
                ),
                // Dit, parce que l'absence est silencieuse autrement, et qu'une
                // protection qu'on croit avoir est pire que pas de protection.
                None => println!(
                    "Ce profil ne declare aucune serie: rien n'empeche de le remplacer plus \n\
                     tard par une copie plus ancienne de lui-meme. Pour y remedier, signer \n\
                     avec un numero qui augmente:\n    minisign -S -t \"serie=1\" -m <profil>"
                ),
            }
        }
    }
    Ok(0)
}

/// Emet la sonde d'inspection TLS et rend un code de sortie.
///
/// `0` quand rien n'intercepte, `1` quand quelque chose intercepte, `3` quand
/// la sonde n'a pas pu conclure - le meme code que les vecteurs de fuite
/// emploient pour SKIPPED. Un verdict absent n'est pas un verdict negatif, et
/// la sortie doit le dire aussi bien a un humain qu'a un script.
async fn inspecter_le_tls(json: bool, annoncer: bool, socket: &str) -> anyhow::Result<i32> {
    use bifrost_evasion::environnement::Mesure;
    use inspection::Chaine;

    let vues = inspection::observer_les_cibles();
    let chaines: Vec<Chaine> = vues.iter().map(|(_, c)| c.clone()).collect();
    let verdict = inspection::conclure(&chaines);

    if json {
        let lignes: Vec<serde_json::Value> = vues
            .iter()
            .map(|(nom, c)| match c {
                Chaine::Publique => serde_json::json!({"cible": nom, "chaine": "publique"}),
                Chaine::Etrangere { empreinte } => serde_json::json!({
                    "cible": nom, "chaine": "etrangere", "empreinte_sha256": empreinte
                }),
                Chaine::Douteuse { raison } => {
                    serde_json::json!({"cible": nom, "chaine": "douteuse", "raison": raison})
                }
                Chaine::Injoignable => serde_json::json!({"cible": nom, "chaine": "injoignable"}),
            })
            .collect();
        let mitm = match verdict {
            Mesure::Vu(v) => serde_json::json!(v),
            Mesure::NonMesure => serde_json::Value::Null,
        };
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "mitm_tls": mitm,
                "raison": match verdict {
                    Mesure::NonMesure => Some(inspection::raison_du_silence(&chaines)),
                    Mesure::Vu(_) => None,
                },
                "cibles": lignes,
            }))?
        );
    } else {
        for (nom, c) in &vues {
            match c {
                Chaine::Publique => println!("{nom}: chaine ancree dans le jeu public"),
                Chaine::Etrangere { empreinte } => println!(
                    "{nom}: chaine ancree HORS du jeu public; empreinte SHA-256 du dernier                      certificat presente: {empreinte}"
                ),
                Chaine::Douteuse { raison } => println!("{nom}: chaine refusee ({raison})"),
                Chaine::Injoignable => println!("{nom}: injoignable"),
            }
        }
        match verdict {
            Mesure::Vu(true) => println!(
                "
mitm_tls = true: quelqu'un dechiffre le TLS qui sort d'ici.                  Comparez l'empreinte ci-dessus a celle de votre autorite interne."
            ),
            Mesure::Vu(false) => println!("
mitm_tls = false: rien n'intercepte ces chemins"),
            Mesure::NonMesure => println!(
                "
mitm_tls non mesure: {}",
                inspection::raison_du_silence(&chaines)
            ),
        }
    }

    // APRES l'affichage: le verdict appartient d'abord a qui l'a demande. Un
    // daemon absent ou muet ne doit pas priver l'utilisateur de sa mesure, donc
    // l'echec de l'annonce se dit sans changer le code de sortie, qui reste
    // celui de la MESURE.
    if annoncer {
        match verdict {
            Mesure::Vu(intercepte) => {
                if let Err(e) = annoncer_le_verdict(socket, intercepte).await {
                    eprintln!("verdict non transmis au daemon: {e:#}");
                }
            }
            // Ne rien envoyer, et le dire. Transmettre `NonMesure` ecraserait
            // une mesure precedente par une ignorance presente.
            Mesure::NonMesure => {
                eprintln!("rien de concluant a annoncer: le daemon garde ce qu'il savait")
            }
        }
    }

    Ok(match verdict {
        Mesure::Vu(true) => 1,
        Mesure::Vu(false) => 0,
        Mesure::NonMesure => 3,
    })
}

/// Porte le verdict au daemon.
async fn annoncer_le_verdict(socket: &str, intercepte: bool) -> anyhow::Result<()> {
    let mut client = IpcClient::connect(socket)
        .await
        .with_context(|| format!("connexion au daemon sur {socket}"))?;
    let reponse = client
        .request(&Request::new(IpcCommand::VerdictInspectionTls {
            intercepte,
        }))
        .await
        .context("dialogue avec le daemon")?;
    match reponse {
        Response::Ok => Ok(()),
        Response::Error { message } => anyhow::bail!("{message}"),
        autre => anyhow::bail!("reponse inattendue du daemon: {autre:?}"),
    }
}

/// Porte la reprise au daemon.
///
/// # Les codes de sortie sont le seul langage que le hook parle
///
/// systemd lance cet appel depuis un script, releve son code, et n'en lit rien
/// d'autre. Quatre issues, distinctes parce que les confondre rendrait
/// indiscernables des situations qui n'appellent pas la meme reaction:
///
/// - `0`, la reprise a ete signalee, ou l'invocation etait la phase `pre`, ou
///   aucun daemon n'a jamais ouvert ce canal sur cette machine;
/// - `1`, le canal existe mais le dialogue a echoue: un daemon est tombe, ou
///   son superviseur ne repond plus. La politique n'a PAS ete reposee;
/// - `2`, l'invocation ne respecte pas le contrat de `systemd-sleep`.
///
/// Le troisieme cas du code `0` merite sa raison: sur une machine ou Bifrost
/// est installe mais arrete, il n'y a aucune politique a reposer, et faire
/// echouer le hook a chaque reveil signalerait un incident qui n'en est pas un.
/// Ce qui separe ce cas du code `1` est l'EXISTENCE du socket, pas une
/// supposition sur l'etat du service.
#[cfg(target_os = "linux")]
async fn signaler_la_reprise(socket: &str, phase: &str, operation: &str) -> anyhow::Result<i32> {
    use bifrost_ipc::IpcError;
    use reprise_linux::Decision;

    match reprise_linux::decider(phase, operation) {
        // Dit, et non tu. C'est cette ligne, emise a chaque endormissement, qui
        // permet de voir dans le journal que le hook est en place et qu'il
        // s'execute - sans elle, un hook absent et un hook muet se ressemblent
        // jusqu'au jour ou une reprise n'est pas signalee.
        Decision::RienAFaire(raison) => {
            eprintln!("{raison}");
            return Ok(0);
        }
        Decision::Refus(raison) => {
            eprintln!("invocation refusee: {raison}");
            return Ok(2);
        }
        Decision::Signaler => {}
    }

    let mut client = match IpcClient::connect(socket).await {
        Ok(c) => c,
        Err(IpcError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("aucun daemon a l'ecoute sur {socket}: aucune politique a reposer");
            return Ok(0);
        }
        Err(e) => bail!(
            "le canal {socket} existe mais le daemon n'y repond pas ({e}): \
             la politique n'a PAS ete reposee apres cette veille"
        ),
    };

    let reponse = client
        .request(&Request::new(IpcCommand::Reprise))
        .await
        .context("dialogue avec le daemon")?;
    match reponse {
        Response::Ok => {
            eprintln!("reprise apres {operation} signalee au daemon sur {socket}");
            Ok(0)
        }
        Response::Error { message } => bail!("{message}"),
        autre => bail!("reponse inattendue du daemon: {autre:?}"),
    }
}

/// Le nom du binaire privilegie, tel qu'il est pose par l'installateur.
const NOM_DAEMON: &str = if cfg!(windows) {
    "bifrost-daemon.exe"
} else {
    "bifrost-daemon"
};

/// Ou chercher le binaire privilegie, dans l'ordre.
///
/// A COTE DE SOI d'abord, et pas par le PATH: les deux binaires sont poses
/// ensemble par l'installateur, et en developpement ils sortent du meme
/// `target/`. Chercher d'abord dans le PATH ferait qu'un client tout juste
/// compile appellerait le daemon INSTALLE, donc une autre version que la sienne,
/// sur la commande ou l'on peut le moins se permettre une surprise.
fn ou_chercher_le_daemon() -> Vec<std::path::PathBuf> {
    let mut candidats = Vec::new();
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        candidats.push(dir.join(NOM_DAEMON));
    }
    #[cfg(unix)]
    candidats.push(std::path::PathBuf::from("/usr/bin/bifrost-daemon"));
    #[cfg(windows)]
    if let Some(pf) = std::env::var_os("ProgramFiles") {
        candidats.push(std::path::Path::new(&pf).join("Bifrost").join(NOM_DAEMON));
    }
    candidats
}

/// Retire les filtres du kill switch sans passer par le daemon.
///
/// # Pourquoi elle ne parle pas a l'IPC
///
/// C'est sa raison d'etre entiere: le cas qu'elle sert est celui d'un daemon
/// mort ou fige. Une commande de secours qui exige que le composant en panne
/// reponde ne secourt rien.
///
/// # Pourquoi elle relance le binaire privilegie au lieu d'agir elle-meme
///
/// `bifrost-daemon --cleanup-firewall` est DEJA la voie du desarmement hors
/// ligne: la desinstallation l'appelle, et c'est ce que le message d'arret du
/// daemon designe. La reprendre ici donnerait au client une dependance au
/// pare-feu et les privileges qui vont avec, alors qu'il est ecrit pour ne
/// toucher a rien. Ce que cette commande ajoute est la VISIBILITE: qui panique
/// tape `bifrost-cli`, pas `bifrost-daemon`, et une porte de secours qu'on ne
/// trouve pas n'existe pas.
///
/// # Codes de sortie
///
/// `0` les filtres sont retires; `2` la commande a REFUSE, faute du drapeau
/// redondant; sinon le code du binaire privilegie.
async fn desarmer_en_urgence(confirme: bool, socket: &str) -> anyhow::Result<i32> {
    if !confirme {
        eprintln!(
            "REFUS: emergency-disarm ouvre le trafic en clair.\n\n\
             Elle retire les filtres du kill switch sans rien demander au daemon.\n\
             Apres elle, cette machine sort en clair jusqu'a une reconnexion.\n\n\
             Pour un arret ordinaire, avec le daemon vivant:\n    \
             bifrost-cli disconnect\n\n\
             Si c'est bien l'urgence, retaper avec le drapeau:\n    \
             bifrost-cli emergency-disarm --je-sais-ce-que-je-fais"
        );
        return Ok(2);
    }

    // Dit, jamais refuse. Un daemon fige tient son socket aussi bien qu'un
    // daemon sain: en faire une condition de refus rendrait la commande
    // inutilisable dans la moitie des situations ou elle sert. Mais desarmer
    // derriere le dos d'un daemon vivant le laisse croire qu'il protege, et
    // cela doit s'ecrire a l'ecran avant, pas se decouvrir apres.
    if IpcClient::connect(socket).await.is_ok() {
        eprintln!(
            "attention: un daemon repond encore sur {socket}. La voie ordinaire est\n\
             'bifrost-cli disconnect'; apres un desarmement d'urgence il continuera\n\
             d'annoncer un kill switch arme qui ne l'est plus."
        );
    }

    let candidats = ou_chercher_le_daemon();
    let Some(daemon) = candidats.iter().find(|c| c.is_file()) else {
        bail!(
            "binaire privilegie introuvable. Cherche: {}.\n\
             Le desarmement se fait alors a la main, en administrateur:\n    \
             {NOM_DAEMON} --cleanup-firewall",
            candidats
                .iter()
                .map(|c| c.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
    };

    // Sa sortie passe telle quelle: elle nomme le backend qui a rendu les
    // filtres et dit ce qu'il est advenu du resolveur. La reformuler ici
    // ferait deux messages a maintenir pour un seul evenement.
    let statut = std::process::Command::new(daemon)
        .arg("--cleanup-firewall")
        .status()
        .with_context(|| format!("lancement de {}", daemon.display()))?;
    match statut.code() {
        Some(0) => {
            println!(
                "kill switch desarme en urgence. Cette machine sort en clair: \n\
                 relancer 'bifrost-cli connect' des que possible."
            );
            Ok(0)
        }
        Some(code) => {
            eprintln!(
                "{} a echoue (code {code}). Les filtres sont peut-etre encore la: \n\
                 verifier avec 'bifrost-cli status', ou relancer en administrateur.",
                daemon.display()
            );
            Ok(code)
        }
        None => bail!("{} a ete tue par un signal", daemon.display()),
    }
}

async fn run(args: Args) -> anyhow::Result<i32> {
    let request = match &args.command {
        // Le chemin n'est PAS transmis quand il est absent: le daemon tourne
        // en root, et lui faire lire un fichier que le client designe ferait de
        // lui un depute confus. Il ouvre le sien, celui de sa ligne de commande.
        Cmd::Connect { config: None } => IpcCommand::ConnectStored,
        Cmd::Connect {
            config: Some(config),
        } => {
            let tunnel = profile::load(config)
                .with_context(|| format!("lecture du profil {}", config.display()))?;
            IpcCommand::Connect {
                config: Box::new(tunnel),
            }
        }
        Cmd::Disconnect => IpcCommand::Disconnect,
        Cmd::Status => IpcCommand::Status,
        Cmd::Check => IpcCommand::Check,
        // A part, et par construction: elle sert le cas ou le daemon ne repond
        // plus. Passer par le chemin commun ci-dessous la ferait echouer sur
        // "connexion au daemon" exactement quand elle est necessaire.
        Cmd::EmergencyDisarm {
            je_sais_ce_que_je_fais,
        } => {
            return desarmer_en_urgence(*je_sais_ce_que_je_fais, &args.socket).await;
        }
        // Ne parle a personne: le coffre est local, et le daemon n'a rien a
        // voir avec la facon dont un profil est range sur ce disque.
        Cmd::Profil { quoi } => return ranger(quoi),
        // Ne parle a personne non plus: le pilote se pose sur le disque, et le
        // daemon le chargera de lui-meme au prochain tunnel par coeur.
        Cmd::Pilote { quoi } => return recuperer_pilote(quoi),
        // Le daemon ne MESURE pas cela: la poignee de main TLS analyse des
        // donnees choisies par le pair, et il tourne en root. Il peut en
        // revanche l'apprendre, si on le lui annonce.
        Cmd::InspectionTls { annoncer } => {
            return inspecter_le_tls(args.json, *annoncer, &args.socket).await;
        }
        // A part: elle decide AVANT de parler, et le plus souvent elle ne parle
        // pas du tout. Passer par le chemin commun ci-dessous ouvrirait une
        // connexion au daemon pour la phase `pre`, c'est-a-dire pour rien, a
        // chaque endormissement.
        #[cfg(target_os = "linux")]
        Cmd::Reprise { phase, operation } => {
            return signaler_la_reprise(&args.socket, phase, operation).await;
        }
    };

    let mut client = IpcClient::connect(&args.socket).await.with_context(|| {
        format!(
            "connexion au daemon sur {}. Est-il demarre, et avez-vous le droit \
             de le piloter ?",
            args.socket
        )
    })?;

    let response = client
        .request(&Request::new(request))
        .await
        .context("dialogue avec le daemon")?;

    match response {
        Response::Ok => {
            if args.json {
                println!("{{\"result\":\"ok\"}}");
            } else {
                println!("{}", render::confirmation(&args.command));
            }
            Ok(0)
        }
        Response::Status(status) => {
            if args.json {
                println!("{}", serde_json::to_string_pretty(&status)?);
            } else {
                print!("{}", render::status(&status));
            }
            Ok(0)
        }
        Response::Check(report) => {
            if args.json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print!("{}", render::check_report(&report));
            }
            Ok(report.exit_code())
        }
        Response::Error { message } => {
            if args.json {
                println!(
                    "{}",
                    serde_json::json!({"result": "error", "message": message})
                );
                Ok(1)
            } else {
                bail!("{message}");
            }
        }
    }
}
