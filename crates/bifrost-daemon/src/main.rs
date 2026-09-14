//! Binaire du daemon privilegie.

use std::io::IsTerminal;
use std::net::Ipv4Addr;
use std::sync::mpsc;

use anyhow::{Context, bail};
use clap::Parser;

use bifrost_daemon::checks;
use bifrost_daemon::coeurs::identite::{IdentiteCoeur, IdentiteResolveur};
use bifrost_daemon::server;
use bifrost_daemon::supervisor::{Cmd, Resolveur, Supervisor};
use bifrost_evasion::Pays;

/// Doublure de `bifrost_evasion::Pays` pour clap.
///
/// Le crate de selection ne depend pas de clap et n'a pas a en dependre: c'est
/// une bibliotheque de politique, pas un programme. La conversion tient en un
/// `match` que le compilateur rendra exhaustif si un pays est ajoute.
#[derive(clap::ValueEnum, Clone, Copy, Debug)]
enum PaysArg {
    NonCensure,
    Chine,
    Russie,
    Iran,
    Turkmenistan,
}

impl From<PaysArg> for Pays {
    fn from(p: PaysArg) -> Self {
        match p {
            PaysArg::NonCensure => Pays::NonCensure,
            PaysArg::Chine => Pays::Chine,
            PaysArg::Russie => Pays::Russie,
            PaysArg::Iran => Pays::Iran,
            PaysArg::Turkmenistan => Pays::Turkmenistan,
        }
    }
}

/// Doublure de `bifrost_evasion::Coeur` pour clap, meme raison que `PaysArg`.
#[derive(clap::ValueEnum, Clone, Copy, Debug)]
enum CoeurArg {
    SingBox,
    Xray,
    AmneziaWg,
}

impl From<CoeurArg> for bifrost_evasion::Coeur {
    fn from(c: CoeurArg) -> Self {
        use bifrost_evasion::Coeur;
        match c {
            CoeurArg::SingBox => Coeur::SingBox,
            CoeurArg::Xray => Coeur::XrayCore,
            CoeurArg::AmneziaWg => Coeur::AmneziaWg,
        }
    }
}

#[derive(Parser, Debug)]
#[command(
    name = "bifrost-daemon",
    version,
    about = "Daemon privilegie Bifrost: tunnel WireGuard et kill switch"
)]
struct Args {
    /// Chemin du socket Unix ou du named pipe.
    #[arg(long, default_value_t = bifrost_ipc::default_endpoint())]
    socket: String,

    /// Groupe systeme autorise a piloter le daemon, en plus de root.
    #[arg(long)]
    group: Option<String>,

    /// Profil que le daemon detient, et qu'il monte quand on le lui demande
    /// sans en fournir un.
    ///
    /// Le chemin vient d'ICI et jamais du client: le daemon tourne en root, et
    /// lui faire lire un fichier que l'appelant designe ferait de lui un depute
    /// confus. Le profil peut etre scelle - `<chemin>.cred` l'emporte alors,
    /// et son dechiffrement est justement ce qu'un client non root ne saurait
    /// pas faire.
    #[arg(long, value_name = "CHEMIN", default_value = bifrost_coffre::CHEMIN_PAR_DEFAUT)]
    profil: std::path::PathBuf,

    /// Rend la machine a son etat d'avant le tunnel et sort: filtres du kill
    /// switch retires, et resolveur restaure la ou le tunnel en laisse une
    /// trace durable. Appele par la desinstallation, ou a la main si un daemon
    /// est mort en laissant le trafic bloque.
    ///
    /// Ne rendre que les filtres laissait une machine qui a son reseau et ne
    /// resout plus rien, parce que `/etc/resolv.conf` designait encore un
    /// resolveur joignable par le seul tunnel. Cela ne concerne que ce
    /// mode-la: systemd-resolved comme Windows posent leur configuration SUR
    /// L'INTERFACE du tunnel, qui disparait avec lui. Le nom du drapeau est
    /// garde: c'est celui que le message d'arret designe et celui que la
    /// desinstallation appelle.
    #[arg(long)]
    cleanup_firewall: bool,

    /// Sonde le reseau courant, affiche ce qui a ete mesure, ce qui ne l'a pas
    /// ete et pourquoi, puis le plan d'essai qui en decoule dans les trois
    /// modes. N'ouvre que des sockets clients, ne demande aucun privilege et ne
    /// touche ni au tunnel ni au kill switch.
    #[arg(long)]
    sonder_reseau: bool,

    /// Adresse d'ecoute de la facade: l'adresse locale STABLE derriere
    /// laquelle les coeurs se remplacent (document 04 partie 4).
    ///
    /// Absente par defaut. Un produit de securite n'ouvre pas une ecoute locale
    /// sans qu'on le lui demande, et tant que rien ne route le systeme vers
    /// elle, elle n'aurait aucun usage.
    #[arg(long, value_name = "ADRESSE")]
    facade: Option<std::net::SocketAddr>,

    /// Sonde meme si le carnet dispense de le faire.
    ///
    /// Sonder emet. Sur un reseau deja connu, la bonne quantite de sondes est
    /// zero, et c'est le defaut. Ce drapeau sert a mesurer DELIBEREMENT un
    /// reseau connu, par exemple pour verifier que ses regles n'ont pas change.
    #[arg(long, requires = "sonder_reseau")]
    sonder_quand_meme: bool,

    /// Juridiction supposee, pour le plan d'essai. Le tableau de survie n'a de
    /// lignes que pour les pays censeurs; ailleurs il ne dit rien, ce qui n'est
    /// pas la meme chose que dire que tout va bien.
    #[arg(long, value_enum, default_value_t = PaysArg::NonCensure, requires = "sonder_reseau")]
    pays: PaysArg,

    /// Fait tourner la doublure de coeur. Interne au harnais de test, et
    /// absente des binaires de release.
    #[cfg(debug_assertions)]
    #[arg(long, hide = true, value_name = "CONFIG.JSON")]
    faux_coeur: Option<std::path::PathBuf>,

    /// Eprouve un coeur tiers REEL: engendre sa configuration, le lance,
    /// verifie une bascule et son temoin negatif, puis l'arrete. N'ecoute que
    /// sur la boucle locale, ne touche ni au tunnel ni au kill switch, et ne
    /// demande aucun privilege. Rend 3 si le binaire est absent.
    #[arg(long, value_enum, value_name = "COEUR")]
    coeur_selftest: Option<CoeurArg>,

    /// Eprouve qu'un profil fait REELLEMENT passer le trafic par le coeur:
    /// lit une banniere placee sur la boucle locale du serveur de sortie,
    /// donc inatteignable autrement, et verifie qu'elle disparait des que le
    /// selecteur bascule en clair. Le profil contient des secrets: ne jamais
    /// le versionner.
    #[arg(long, value_name = "PROFIL.JSON")]
    coeur_e2e: Option<std::path::PathBuf>,

    /// Repertoire contenant les binaires des coeurs.
    ///
    /// Avec --facade, c'est ce qui donne au daemon un chemin PAR COEUR: sans
    /// l'un des deux, un profil qui demande un coeur est refuse en le disant.
    /// Les deux sont exiges ensemble parce qu'ils sont les deux moities du meme
    /// chemin - la facade est ou le trafic entre, ce repertoire est d'ou sort
    /// le processus qui l'attend derriere.
    #[arg(long, value_name = "REP")]
    coeurs_dans: Option<std::path::PathBuf>,

    /// Ou ecrire les configurations engendrees pour les coeurs.
    ///
    /// Ces fichiers portent le secret de l'API de controle et les identifiants
    /// de l'entree SOCKS: ils n'ont aucune raison de survivre a un
    /// redemarrage, d'ou `/run` sous Linux.
    ///
    /// Le defaut depend de la plateforme, et ce n'est pas cosmetique: un
    /// `/run/bifrost/coeurs` annonce sous Windows est un chemin qu'aucune
    /// machine Windows ne peut ecrire, donc un chemin par coeur qui echoue au
    /// premier `connect` chez qui ne passe pas le drapeau. Vu dans l'aide du
    /// binaire Windows le 21 aout 2026.
    #[arg(long, value_name = "REP", default_value = CONFIGURATIONS_PAR_DEFAUT)]
    coeurs_configurations: std::path::PathBuf,

    /// Port SOCKS local sur lequel le coeur ecoutera.
    ///
    /// Sur la boucle locale uniquement, ce que la configuration engendree
    /// impose et qu'un test garde.
    #[arg(long, value_name = "PORT", default_value_t = 1080)]
    coeur_socks_port: u16,

    /// Port local de l'API de controle du coeur.
    ///
    /// Son secret n'est PAS un drapeau: il est engendre a chaque demarrage. Un
    /// secret passe en argument serait lisible par tout le monde dans `ps`.
    #[arg(long, value_name = "PORT", default_value_t = 9090)]
    coeur_api_port: u16,

    /// Compte systeme sous lequel les coeurs anti-censure tournent.
    ///
    /// Un NOM (`bifrost-coeur`) en exploitation, ou `uid:gid` pour un banc. Le
    /// declarer fait deux choses d'un coup, et c'est le point: le kill switch
    /// exempte ce compte, et les coeurs sont lances sous lui. Ne pas le
    /// declarer laisse le comportement d'avant: aucune exemption, aucun compte
    /// impose. Une exemption inutile reste une sortie en clair, donc c'est une
    /// decision d'exploitation, pas un defaut.
    #[cfg(unix)]
    #[arg(long, value_name = "NOM|UID:GID")]
    coeur_utilisateur: Option<String>,

    /// Executable du coeur, pour les plateformes qui designent un processus
    /// par son binaire plutot que par son compte.
    ///
    /// C'est `ALE_APP_ID` sous Windows. Sous Linux `meta skuid` ne regarde que
    /// le compte, et ce chemin n'entre dans aucune regle.
    #[arg(long, value_name = "CHEMIN")]
    coeur_binaire: Option<std::path::PathBuf>,

    /// Compte systeme sous lequel tourne le resolveur chiffre embarque.
    ///
    /// Le contraire de --coeur-utilisateur, malgre la ressemblance. Celui-la
    /// n exempte rien: le declarer FERME le :53 pour tout le monde, y compris
    /// a l interieur du tunnel, en ne laissant que ce compte. Ne le declarer
    /// que si un resolveur ecoute reellement sur la boucle locale, sans quoi
    /// la machine perdrait la resolution de noms au lieu de la durcir.
    ///
    /// Sous Unix, un compte POSIX (nom ou uid:gid); le daemon prend ses
    /// identifiants entre fork et exec. Sous Windows (11b-1), un compte de
    /// service; le daemon ouvre un jeton par LogonUser et lance le resolveur
    /// par CreateProcessAsUser. Forme recommandee sous Windows: LocalService.
    #[cfg_attr(unix, arg(long, value_name = "NOM|UID:GID"))]
    #[cfg_attr(windows, arg(long, value_name = "COMPTE-DE-SERVICE"))]
    resolveur_utilisateur: Option<String>,

    /// Executable du resolveur chiffre (dnscrypt-proxy).
    ///
    /// Fourni par l'empaquetage, jamais cherche dans le PATH: un tiers qui y
    /// deposerait le sien serait exactement ce qu'un resolveur chiffre existe
    /// pour eviter. Sans lui, un profil qui demande `embarque` exige qu'un
    /// resolveur reponde deja sur la boucle locale, et fait echouer la
    /// connexion sinon: pointer resolv.conf sur une adresse muette priverait
    /// la machine de resolution de noms sans qu'aucune erreur ne le dise.
    #[arg(long, value_name = "CHEMIN")]
    resolveur_binaire: Option<std::path::PathBuf>,

    /// Eprouve la supervision d un VRAI resolveur chiffre: l engendre, le
    /// lance, verifie qu il repond, qu il tourne sous le compte annonce, puis
    /// l arrete et verifie qu il a disparu. Ecoute sur une adresse de boucle
    /// locale ecartee, ne touche ni au tunnel ni au kill switch. Rend 3 si le
    /// binaire est absent.
    ///
    /// Sous Unix, se lier au :53 exige root. Sous Windows non: il n'y a pas de
    /// port privilegie, et l'intuition est exactement inversee - mesure du
    /// 21/08/2026 sur les deux machines Windows, `127.0.0.9:53` se lie sans
    /// privilege quand `127.0.0.9:5353` est refuse, parce que le repondeur mDNS
    /// le tient deja. Le detail est dans `resolveur::selftest`.
    #[arg(long, requires = "resolveur_binaire")]
    resolveur_selftest: bool,

    /// Instrument de --resolveur-selftest, pas un mode d exploitation: lance le
    /// resolveur, annonce son PID, puis se fait tuer sans rien ranger - par
    /// SIGKILL sous Unix, par `TerminateProcess` sur soi-meme sous Windows,
    /// les deux seuls gestes qu'aucun gestionnaire n'intercepte. Sert a
    /// observer ce qui survit a un daemon qui n a pas pu s arreter proprement.
    #[arg(
        long,
        hide = true,
        value_name = "ADRESSE",
        requires = "resolveur_binaire"
    )]
    resolveur_abandon: Option<std::net::SocketAddr>,

    /// Ou ecrire la configuration engendree pour le resolveur.
    ///
    /// Sous Windows, dans le repertoire DU RESOLVEUR, `%ProgramData%\Bifrost\resolveur`,
    /// et non a la racine de `%ProgramData%\Bifrost` (11b-2, ecart 2 du
    /// 13/09/2026): le daemon ouvre ce repertoire en lecture heritable au
    /// compte du resolveur a chaque lancement, parce que dnscrypt-proxy en
    /// fait son repertoire courant au chargement; la racine, qui porte le
    /// profil et sa cle privee, ne doit rien lui accorder. Le repertoire du
    /// profil (`--profil`, ou un repertoire qui contient un `tunnel.toml`) est
    /// REFUSE au lancement, avant toute ACE (ecart 3). Linux ne change pas.
    #[cfg_attr(
        unix,
        arg(
            long,
            value_name = "CHEMIN",
            default_value = "/run/bifrost/dnscrypt-proxy.toml"
        )
    )]
    #[cfg_attr(
        windows,
        arg(
            long,
            value_name = "CHEMIN",
            default_value = r"C:\ProgramData\Bifrost\resolveur\dnscrypt-proxy.toml"
        )
    )]
    resolveur_configuration: std::path::PathBuf,

    /// Repertoire PERSISTANT du resolveur chiffre.
    ///
    /// Distinct de celui de sa configuration, et c'est le point: il y garde la
    /// liste des serveurs chiffres. Sous /run, elle disparait a chaque arret du
    /// service, et le demarrage suivant doit la retelecharger. Mesure du
    /// 17/08/2026: l'hebergeur de cette liste finit par repondre
    /// `429 Too Many Requests`, et sans liste utilisable dnscrypt-proxy
    /// s'arrete en FATAL, donc plus aucune connexion n'aboutit.
    ///
    /// Sous Windows, `%ProgramData%` joue le role de `/var/lib`: un emplacement
    /// hors profil utilisateur, qui survit aux sessions et que le service peut
    /// ecrire. Depuis 11b-2 (ecart 2) c'est le sous-repertoire `etat` du
    /// repertoire du resolveur: il herite de la lecture du parent et est le
    /// seul endroit que le compte du resolveur peut ecrire.
    #[cfg_attr(
        unix,
        arg(long, value_name = "REP", default_value = "/var/lib/bifrost/resolveur")
    )]
    #[cfg_attr(
        windows,
        arg(
            long,
            value_name = "REP",
            default_value = r"C:\ProgramData\Bifrost\resolveur\etat"
        )
    )]
    resolveur_etat: std::path::PathBuf,

    /// Noms des serveurs chiffres, tels qu'ils figurent dans la liste publique.
    #[arg(
        long,
        value_name = "NOMS",
        value_delimiter = ',',
        default_value = "quad9-dnscrypt-ip4-filter-pri,cloudflare"
    )]
    resolveur_serveurs: Vec<String>,

    /// Adresses interrogees en clair pour resoudre le NOM des serveurs
    /// chiffres. Elles rompent une circularite reelle, et leurs requetes
    /// partent par le tunnel.
    #[arg(
        long,
        value_name = "IP",
        value_delimiter = ',',
        default_value = "9.9.9.9,1.1.1.1"
    )]
    resolveur_bootstrap: Vec<std::net::IpAddr>,

    /// Qualifie des sites empruntes par REALITY, separes par des virgules.
    ///
    /// Le serveur REJOUE au client la poignee de main volee au site: si sa
    /// reponse ne tient pas dans le tampon prevu, la poignee ne se termine
    /// jamais et le client ne voit qu'un EOF muet. Cette sonde envoie un
    /// ClientHello, mesure ce que le site renvoie, et le dit. N'ouvre qu'une
    /// socket cliente et ne demande aucun privilege.
    #[arg(long, value_name = "HOTES", value_delimiter = ',')]
    qualifier_dest: Option<Vec<String>>,

    /// Joue le role du daemon pour la recette d'orphelin. Interne.
    #[cfg(debug_assertions)]
    #[arg(long, hide = true, value_name = "CONFIG.JSON")]
    faux_parent: Option<std::path::PathBuf>,

    /// Variante du precedent SANS la garde anti-orphelin: temoin negatif.
    #[cfg(debug_assertions)]
    #[arg(long, hide = true, requires = "faux_parent")]
    faux_parent_sans_garde: bool,

    /// Compte `uid:gid` sous lequel la doublure doit tourner. Interne.
    #[cfg(debug_assertions)]
    #[arg(long, hide = true, requires = "faux_parent", value_name = "UID:GID")]
    faux_parent_utilisateur: Option<String>,

    /// Emet une sonde de fuite puis sort. Interne au harnais de test.
    #[arg(long, hide = true, value_name = "dns|ipv4|ipv6|all")]
    probe: Option<String>,

    /// Emet du trafic vers une adresse du tunnel. Interne au harnais de test.
    #[arg(long, hide = true, value_name = "IPV4")]
    probe_tunnel: Option<Ipv4Addr>,

    /// Emet du trafic vers un voisin du LIEN, hors tunnel. Interne au harnais.
    ///
    /// Distincte de --probe-tunnel par la destination et par ce qu'elle sert a
    /// montrer: une adresse on-link, dont la route ne passe pas par le tunnel,
    /// donc la seule sonde qui reparte en clair quand un kill switch tombe.
    #[arg(long, hide = true, value_name = "IPV4")]
    probe_lan: Option<Ipv4Addr>,

    /// Arme le kill switch du BANC de fuite, puis attend d'etre tue. Interne.
    ///
    /// C'est le processus que le vecteur `daemon-mort` fait mourir. Il arme par
    /// le VRAI backend du produit, et non par un `nft -f -` comme le reste du
    /// banc: ce qu'on mesure est justement que les filtres poses par notre code
    /// survivent au processus qui les a poses.
    #[cfg(target_os = "linux")]
    #[arg(long, hide = true)]
    armer_le_banc_et_attendre: bool,

    /// Lit la banniere du pair a travers le tunnel et l'affiche. Sort non nul
    /// si rien n'a pu etre lu. Interne au harnais de test.
    #[arg(long, hide = true, value_name = "ADDR:PORT")]
    lire_banniere: Option<std::net::SocketAddr>,

    /// Fenetre de reessai de --lire-banniere. Zero fait une seule tentative,
    /// ce qu'attend le temoin negatif.
    #[arg(
        long,
        hide = true,
        requires = "lire_banniere",
        value_name = "MS",
        default_value_t = 3000
    )]
    lire_banniere_delai: u64,

    /// Sert la banniere du pair jusqu'a extinction. Interne au harnais de test.
    ///
    /// Ne restreint rien par lui-meme: c'est le banc qui rend la banniere
    /// inobtenable hors tunnel, voir `checks::transport::nft_banniere`.
    #[arg(long, hide = true, value_name = "ADDR:PORT")]
    servir_banniere: Option<std::net::SocketAddr>,

    /// Sert des reponses DNS jusqu'a extinction. Interne au harnais de test.
    #[arg(long, hide = true, value_name = "ADDR:PORT")]
    faux_resolveur: Option<std::net::SocketAddr>,

    /// Adresse que le faux resolveur renvoie pour tout nom.
    #[arg(
        long,
        hide = true,
        requires = "faux_resolveur",
        value_name = "IPV4",
        default_value = "10.99.9.42"
    )]
    faux_resolveur_adresse: Ipv4Addr,

    /// Amont vers lequel le faux resolveur relaie, au lieu de repondre
    /// lui-meme. Interne au harnais de test.
    #[arg(
        long,
        hide = true,
        requires = "faux_resolveur",
        value_name = "ADDR:PORT"
    )]
    faux_resolveur_amont: Option<std::net::SocketAddr>,

    /// Resout un nom par la configuration systeme et sort non nul si elle
    /// echoue. Interne au harnais de test.
    #[arg(long, hide = true, value_name = "NOM")]
    resoudre: Option<String>,

    /// Interroge un serveur DNS PRECIS, en contournant la configuration
    /// systeme, et sort non nul si rien ne repond. Interne au harnais de test.
    #[arg(long, hide = true, value_name = "ADDR:PORT")]
    interroger: Option<std::net::SocketAddr>,

    // Les trois options qui suivent s'appuient sur le device WireGuard du
    // noyau Linux. Elles sont declarees sous `cfg` et non simplement ignorees
    // ailleurs: une option acceptee mais sans effet ferait poursuivre le
    // programme vers le demarrage du daemon et produirait un message d'erreur
    // sans rapport avec ce que l'utilisateur a demande. Mieux vaut que clap la
    // refuse comme inconnue.
    /// Applique une specification WireGuard au namespace courant. Interne.
    #[cfg(target_os = "linux")]
    #[arg(long, hide = true, value_name = "JSON")]
    wg_apply: Option<String>,

    /// Affiche les compteurs du pair d'une interface, en JSON: poignee de main
    /// aboutie, octets emis, octets RECUS. Interne.
    #[cfg(target_os = "linux")]
    #[arg(long, hide = true, value_name = "IFACE")]
    wg_stats: Option<String>,

    /// Dit ce que la couche 1 anti-telemetrie ferait, **sans rien ecrire**.
    ///
    /// Une cible absente sur cette machine est dite SANS OBJET et jamais
    /// comptee comme posee: sur la build 26200, deux des neuf taches que le
    /// document 03 nomme n'existent pas sous ce nom-la.
    #[cfg(windows)]
    #[arg(long)]
    telemetrie_etat: bool,

    /// Applique la couche 1: registre, services, taches planifiees.
    ///
    /// Journalise l'etat d'origine AVANT chaque ecriture, et relit APRES.
    /// Demande les droits d'administrateur. Se defait par
    /// --telemetrie-restaurer.
    #[cfg(windows)]
    #[arg(long, conflicts_with = "telemetrie_etat")]
    telemetrie_appliquer: bool,

    /// Rend la machine a l'etat que le journal a garde, puis efface le journal.
    ///
    /// Le journal n'est efface que si TOUT a ete rendu: une restauration
    /// partielle qui perdrait son journal laisserait une machine a moitie
    /// modifiee et plus rien pour finir.
    #[cfg(windows)]
    #[arg(long, conflicts_with_all = ["telemetrie_etat", "telemetrie_appliquer"])]
    telemetrie_restaurer: bool,

    /// Dit ce que la couche 2 anti-telemetrie ferait, **sans rien poser**.
    ///
    /// Une cible qui ne peut pas etre bloquee est dite SANS OBJET, jamais
    /// comptee comme une protection: service absent, binaire absent, ou service
    /// en `SERVICE_SID_TYPE NONE`. Ce dernier cas est le piege de la couche: le
    /// filtre se poserait sans erreur et ne mordrait jamais.
    #[cfg(windows)]
    #[arg(long)]
    telemetrie_reseau_etat: bool,

    /// Pose la couche 2: blocage WFP par SID de service et par chemin.
    ///
    /// Dans son PROPRE provider et son propre sublayer, persistants, distincts
    /// de ceux du kill switch: ces filtres valent aussi quand le tunnel est
    /// baisse. Demande les droits d'administrateur. Se defait par
    /// --telemetrie-reseau-retirer.
    #[cfg(windows)]
    #[arg(long, conflicts_with = "telemetrie_reseau_etat")]
    telemetrie_reseau_appliquer: bool,

    /// Retire tous les filtres de la couche 2. La sortie de secours.
    ///
    /// Ne depend d'aucune connaissance de ce qui a ete pose: rejoue la suite de
    /// cles et supprime chacune. A executer AVANT toute desinstallation, parce
    /// que les filtres WFP survivent au produit qui les a poses - sans ca, on
    /// laisse une machine filtree par un logiciel absent.
    #[cfg(windows)]
    #[arg(long, conflicts_with_all = ["telemetrie_reseau_etat", "telemetrie_reseau_appliquer"])]
    telemetrie_reseau_retirer: bool,

    /// Sonde de DIAGNOSTIC: pose un seul blocage de la couche 2, sur ce SID.
    ///
    /// Ne protege rien et ne pretend rien proteger. Elle existe parce que la
    /// mesure du 22 aout 2026 a rendu un resultat negatif: filtre present,
    /// portant le bon SID de service, SID verifie present dans le jeton du
    /// processus, et connexion autorisee quand meme. Le filtre GAGNANT est
    /// nomme par le `FilterRTID` de l'evenement 5156, mais le seul emetteur
    /// disponible - DiagTrack - n'emet qu'une fois par redemarrage et assechait
    /// la fenetre. Il faut donc un declencheur qu'on commande: un service de
    /// test, dont le SID n'est par construction pas au catalogue.
    ///
    /// Le SID se lit avec `sc showsid <service>`. Tout ce qui n'est pas un SID
    /// de service est refuse, et tout SID d'un service intouchable aussi. Se
    /// defait par --telemetrie-reseau-retirer, comme le reste de la couche.
    #[cfg(windows)]
    #[arg(
        long,
        value_name = "SID",
        conflicts_with_all = [
            "telemetrie_reseau_etat",
            "telemetrie_reseau_appliquer",
            "telemetrie_reseau_retirer"
        ]
    )]
    telemetrie_sonde_sid: Option<String>,

    /// Sonde de DIAGNOSTIC, l'autre moitie: pose un seul blocage de la couche 2
    /// sur ce CHEMIN de binaire.
    ///
    /// Ne protege rien et ne pretend rien proteger. Elle existe parce que le
    /// catalogue de la couche 2 porte DEUX mecanismes et qu'un seul a ete
    /// eprouve en effet. `ALE_USER_ID` sur un SID de service mord: mesure les
    /// 22 et 23 aout 2026, sur un service de test ordinaire puis sur un service
    /// au jeton filtre. `ALE_APP_ID` sur un chemin d'image vise les cinq autres
    /// cibles et n'a jamais ete eprouve qu'en POSE: on sait que les filtres
    /// entrent dans le moteur et qu'ils portent le bon chemin NT, on ne sait
    /// pas qu'ils refusent quoi que ce soit.
    ///
    /// Plus simple que la sonde par SID: `ALE_APP_ID` compare le chemin de
    /// l'image du processus, donc n'importe quel processus fait un temoin et
    /// aucun service n'est necessaire. Copier ce daemon vers un chemin jetable
    /// suffit.
    ///
    /// Le chemin doit designer un fichier existant hors du catalogue et hors de
    /// la racine systeme; tout le reste est refuse en disant ce qui etait
    /// attendu. Se defait par --telemetrie-reseau-retirer, comme le reste de la
    /// couche.
    #[cfg(windows)]
    #[arg(
        long,
        value_name = "CHEMIN",
        conflicts_with_all = [
            "telemetrie_reseau_etat",
            "telemetrie_reseau_appliquer",
            "telemetrie_reseau_retirer",
            "telemetrie_sonde_sid"
        ]
    )]
    telemetrie_sonde_binaire: Option<std::path::PathBuf>,

    /// aucun, equilibre ou strict. Le meme vocabulaire que `dns.anti_telemetrie`
    /// dans le profil de tunnel, parce que c'est le meme choix.
    #[cfg(windows)]
    #[arg(long, value_name = "PROFIL", default_value = "equilibre")]
    telemetrie_profil: String,

    /// Ou vit le journal du retour en arriere.
    ///
    /// Sous %ProgramData% et non dans un profil utilisateur: c'est un service
    /// qui l'ecrit, et il doit survivre a la session qui l'a demande.
    #[cfg(windows)]
    #[arg(
        long,
        value_name = "CHEMIN",
        default_value = r"C:\ProgramData\Bifrost\telemetrie-journal.json"
    )]
    telemetrie_journal: std::path::PathBuf,

    /// Eprouve le cycle de vie des objets WFP: pose, reengagement, retrait
    /// complet, verifie avec netsh, puis sonde l'identite du filtre du daemon.
    /// Ne coupe aucun trafic reel, donc sans danger sur un poste de travail:
    /// le seul blocage pose vise une adresse de documentation RFC 5737.
    #[cfg(windows)]
    #[arg(long)]
    wfp_selftest: bool,

    /// Tente une connexion et sort avec un code disant si un filtre l'a
    /// refusee. Temoin de la sonde d'identite, interne a l'autotest WFP.
    #[cfg(windows)]
    #[arg(long, hide = true, value_name = "ADDR:PORT")]
    connect_probe: Option<std::net::SocketAddr>,

    /// Comme `--connect-probe`, mais en boucle pendant N millisecondes, et sort
    /// avec le code de la tentative la plus PERMISSIVE. Sert a sonder une
    /// fenetre de fuite trop breve pour un processus par tentative.
    #[cfg(windows)]
    #[arg(long, hide = true, value_name = "MS")]
    connect_probe_rafale: Option<u64>,

    /// Eprouve le transport WireGuardNT: cree un adaptateur, lui applique une
    /// configuration, la relit et la compare, puis retire l'adaptateur.
    /// N'echange aucun trafic et n'arme pas le kill switch. Le driver noyau
    /// s'installe au premier appel.
    #[cfg(windows)]
    #[arg(long)]
    wgnt_selftest: bool,

    /// Monte un vrai tunnel vers un pair distant, verifie qu'un handshake a
    /// lieu et que le trafic passe, puis demonte. N'arme PAS le kill switch et
    /// refuse un profil a route par defaut. Recette du transport Windows.
    #[cfg(windows)]
    #[arg(long, value_name = "PROFIL.TOML")]
    wgnt_e2e: Option<std::path::PathBuf>,

    /// Adresse a sonder a travers le tunnel, joignable uniquement par lui.
    #[cfg(windows)]
    #[arg(long, value_name = "ADDR:PORT")]
    wgnt_e2e_target: Option<std::net::SocketAddr>,

    /// Accepte un profil a ROUTE PAR DEFAUT. Sans ce drapeau, les recettes le
    /// refusent: un `/0` detourne tout le trafic de la machine vers le pair et
    /// lui fait perdre son acces reseau. C'est pourtant la configuration du
    /// produit en usage reel. Machine dediee uniquement. Tuer le processus
    /// retablit le reseau: l'adaptateur lui appartient.
    #[cfg(windows)]
    #[arg(long)]
    wgnt_e2e_route_par_defaut: bool,

    /// Provoque la condition de BOUCLAGE: une route hote vers l'endpoint est
    /// posee sur le tunnel, donc la table de routage affirme que le pair se
    /// joint par le tunnel lui-meme. Un handshake obtenu malgre ca etablit que
    /// le driver exclut ses propres paquets chiffres du routage. Sans ce
    /// drapeau, un pair sur le meme lien est joint par une route on-link et la
    /// question ne se pose jamais.
    #[cfg(windows)]
    #[arg(long)]
    wgnt_e2e_bouclage: bool,

    /// Mesure le vecteur exit-ip contre un vrai pair distant. Monte le tunnel
    /// par la recette --wgnt-e2e et capture en meme temps sur toutes les
    /// cartes reelles: la banniere doit passer par le tunnel, et rien ne doit
    /// apparaitre en clair vers la cible. NE COUPE PAS le reseau et n'arme pas
    /// le kill switch.
    #[cfg(windows)]
    #[arg(long, value_name = "PROFIL.TOML")]
    exit_ip_selftest: Option<std::path::PathBuf>,

    /// Cible du vecteur exit-ip, joignable uniquement par le tunnel.
    #[cfg(windows)]
    #[arg(long, value_name = "ADDR:PORT")]
    exit_ip_cible: Option<std::net::SocketAddr>,

    /// Destination PUBLIQUE tentee pendant la mesure exit-ip. Son aboutissement
    /// n'est pas juge: seule compte l'absence de paquet en clair vers elle sur
    /// le fil. C'est la promesse d'un VPN, qu'aucune sonde vers une adresse du
    /// tunnel ne peut etablir.
    #[cfg(windows)]
    #[arg(long, value_name = "ADDR:PORT", default_value = "1.1.1.1:443")]
    exit_ip_temoin: std::net::SocketAddr,

    /// Comme --wfp-selftest, mais avec le vrai plan de blocage. COUPE TOUT LE
    /// RESEAU de la machine pendant l'operation. Machine dediee uniquement.
    #[cfg(windows)]
    #[arg(long)]
    wfp_selftest_blocking: bool,

    /// Eprouve le kill switch A TRAVERS UNE MISE EN VEILLE. Arme, endort la
    /// machine, la reveille par minuteur, et sonde des le chemin de reprise.
    /// COUPE TOUT LE RESEAU puis ENDORT LA MACHINE. Machine dediee uniquement,
    /// capable de revenir seule.
    #[cfg(windows)]
    #[arg(long, requires = "leak_target")]
    wfp_veille_selftest: bool,

    /// Duree de sommeil de --wfp-veille-selftest, en secondes.
    #[cfg(windows)]
    #[arg(long, value_name = "SECONDES", default_value_t = 60)]
    veille_secondes: u64,

    /// Interface WireGuard DEJA montee dont le permit doit etre eprouve a
    /// travers la veille. Sans elle, la survie du permit par LUID se declare
    /// non mesuree au lieu de passer en silence.
    #[cfg(windows)]
    #[arg(long, value_name = "INTERFACE")]
    veille_tunnel: Option<String>,

    /// Monte un adaptateur WireGuardNT de ce nom pour la duree de la mesure,
    /// au lieu d'en exiger un deja present, et le retire a la fin. C'est le
    /// meme driver que celui des tunnels de production: la question posee au
    /// LUID est donc la meme. Exclusif de --veille-tunnel.
    #[cfg(windows)]
    #[arg(long, value_name = "INTERFACE", conflicts_with = "veille_tunnel")]
    veille_monter_tunnel: Option<String>,

    /// Filtre de demarrage: la vraie fonction, par opposition a la recette de
    /// mesure `--boot-filtres`. Valeurs: montrer, poser, retirer.
    ///
    /// `montrer` n'ecrit rien et ne touche a aucun objet WFP: il imprime le
    /// plan. C'est le seul mode sans danger sur une machine de travail.
    #[cfg(windows)]
    #[arg(long, value_name = "ACTION")]
    demarrage: Option<String>,

    /// Ouvre les plages du reseau local (imprimante, NAS).
    #[cfg(windows)]
    #[arg(long)]
    demarrage_reseau_local: bool,

    /// FERME la plage CGNAT 100.64.0.0/10, celle des reseaux overlay.
    ///
    /// Elle est ouverte par DEFAUT, contrairement aux deux autres options, et
    /// c'est un arbitrage assume plutot qu'une commodite.
    ///
    /// Cout de la fermer: une machine administree a distance par un reseau
    /// overlay - Tailscale, ZeroTier, Nebula - devient INJOIGNABLE apres
    /// redemarrage, et il faut aller la chercher. Mode de panne deja rencontre
    /// sur le banc, pas une hypothese.
    ///
    /// Cout de l'ouvrir: une exemption etroite par laquelle n'importe quel
    /// programme de la machine peut emettre hors tunnel pendant la fenetre de
    /// demarrage. C'est une vraie fuite, et elle est nommee comme telle.
    ///
    /// L'arbitrage: la seconde est bornee a une plage non routable sur
    /// l'Internet public, la premiere demande un deplacement physique. Sur une
    /// machine qu'on atteint a la main, poser ce drapeau resserre la fenetre et
    /// c'est le bon choix.
    ///
    /// `PolitiqueDemarrage::default()` reste, lui, tout ferme. Un appelant
    /// programmatique qui oublie un champ doit obtenir le strict et non le
    /// commode: l'arbitrage appartient a cette ligne de commande, pas au type.
    #[cfg(windows)]
    #[arg(long)]
    demarrage_sans_overlay: bool,

    /// Laisse passer DHCPv6 et NDP. Sans ce drapeau, IPv6 est bloque en entier
    /// et ses exemptions ne sont pas posees, ce qui serait se contredire.
    #[cfg(windows)]
    #[arg(long)]
    demarrage_ipv6: bool,

    /// Laisse le reseau local ouvert pendant --wfp-selftest-blocking.
    ///
    /// Sans ce drapeau, le mode bloquant coupe TOUT et ne peut donc pas etre
    /// lance sur une machine pilotee a distance. Avec lui, une session
    /// d'administration passant par le reseau LOCAL survit, alors qu'Internet
    /// reste coupe.
    #[cfg(windows)]
    #[arg(long)]
    wfp_selftest_lan: bool,

    /// Mesure le vecteur dns-leak. COUPE le reseau entre l'armement et le
    /// desarmement, comme toute mesure d'etancheite reelle.
    #[cfg(windows)]
    #[arg(long)]
    dns_leak_selftest: bool,

    /// Resolveur EXTERNE vers lequel sonder, port 53 obligatoire.
    #[cfg(windows)]
    #[arg(long, value_name = "ADDR:53", default_value = "9.9.9.9:53")]
    dns_leak_resolveur: std::net::SocketAddr,

    /// Mesure le vecteur coeur-exemption: la LARGEUR de l'exemption accordee au
    /// coeur anti-censure. COUPE le reseau entre l'armement et le desarmement.
    #[cfg(windows)]
    #[arg(long)]
    coeur_exemption_selftest: bool,

    /// Destination ordinaire du vecteur coeur-exemption. Le coeur doit la
    /// joindre sous armement; elle ne peut donc pas etre sur le port 53.
    #[cfg(windows)]
    #[arg(long, value_name = "ADDR:PORT", default_value = "1.1.1.1:443")]
    coeur_exemption_cible: std::net::SocketAddr,

    /// Resolveur EXTERNE que le coeur ne doit PAS pouvoir joindre, port 53
    /// obligatoire.
    #[cfg(windows)]
    #[arg(long, value_name = "ADDR:53", default_value = "9.9.9.9:53")]
    coeur_exemption_resolveur: std::net::SocketAddr,

    /// Mesure le vecteur resolveur-exemption: la BORNE de l'exception accordee
    /// au resolveur chiffre embarque. Le miroir du precedent, et son contraire:
    /// le coeur doit sortir largement mais pas sur le :53, le resolveur doit
    /// sortir sur le :53 et nulle part ailleurs. COUPE le reseau entre
    /// l'armement et le desarmement.
    #[cfg(windows)]
    #[arg(long)]
    resolveur_exemption_selftest: bool,

    /// Destination ordinaire du vecteur resolveur-exemption. Le resolveur ne
    /// doit PAS pouvoir la joindre sous armement; elle ne peut donc pas etre
    /// sur le port 53, que l'exception ouvre justement.
    #[cfg(windows)]
    #[arg(long, value_name = "ADDR:PORT", default_value = "1.1.1.1:443")]
    resolveur_exemption_cible: std::net::SocketAddr,

    /// Resolveur EXTERNE que le resolveur declare DOIT pouvoir joindre, pour
    /// l'amorcage de son propre serveur chiffre. Port 53 obligatoire.
    #[cfg(windows)]
    #[arg(long, value_name = "ADDR:53", default_value = "9.9.9.9:53")]
    resolveur_exemption_resolveur: std::net::SocketAddr,

    /// Mesure le vecteur ipv6-leak. COUPE le reseau entre l'armement et le
    /// desarmement, et FERME le reseau local si la cible est locale.
    #[cfg(windows)]
    #[arg(long)]
    ipv6_leak_selftest: bool,

    /// Destination IPv6 du vecteur ipv6-leak. Une unicast globale donne la
    /// pleine portee; une ULA ou une lien-local eprouve les memes couches sans
    /// le chemin de sortie.
    #[cfg(windows)]
    #[arg(
        long,
        value_name = "[ADDR]:PORT",
        default_value = "[2606:4700:4700::1111]:443"
    )]
    ipv6_leak_cible: std::net::SocketAddr,

    /// Mesure les vecteurs kill-switch-on-drop et reconnect-window. Cree des
    /// adaptateurs WireGuardNT et COUPE le reseau pendant les armements.
    #[cfg(windows)]
    #[arg(long)]
    chute_tunnel_selftest: bool,

    /// Destination des sondes de `--chute-tunnel-selftest`.
    #[cfg(windows)]
    #[arg(long, value_name = "ADDR:PORT", default_value = "1.1.1.1:443")]
    chute_tunnel_cible: std::net::SocketAddr,

    /// Pose ou retire les politiques qui coupent le DoH des navigateurs, le
    /// contournement que le vecteur `doh-bypass` mesure. ECRIT sur la machine:
    /// `poser` depose les fichiers de politique, `retirer` enleve ce que
    /// Bifrost a pose et rien d'autre. Demande les droits d'ecriture sur
    /// `/etc`. Rien n'est jamais ecrase: une politique DoH posee par quelqu'un
    /// d'autre fait REFUSER la cible, avec sa raison.
    #[arg(long, value_name = "poser|constater|retirer")]
    doh_policy: Option<String>,

    /// Mesure le vecteur startup-window, de part et d'autre d'un REDEMARRAGE.
    /// `armer` pose le filtre de demarrage, `constater` se lance apres le
    /// reboot. La politique vient des drapeaux `--demarrage-*`.
    #[cfg(windows)]
    #[arg(long, value_name = "armer|constater")]
    startup_window: Option<String>,

    /// Destination que le filtre de demarrage doit refuser apres le reboot.
    #[cfg(windows)]
    #[arg(long, value_name = "ADDR:PORT", default_value = "1.1.1.1:443")]
    startup_window_cible: std::net::SocketAddr,

    /// Eprouve le temoin de blocage WFP: pose un filtre sur UNE adresse, tente
    /// la connexion, et verifie que le journal d'audit nomme bien ce
    /// filtre-la. Ne coupe pas la machine, tout le reste passe.
    #[cfg(windows)]
    #[arg(long)]
    temoin_selftest: bool,

    /// Adresse bloquee par --temoin-selftest.
    #[cfg(windows)]
    #[arg(long, value_name = "IPV4", default_value = "1.1.1.1")]
    temoin_cible: std::net::Ipv4Addr,

    /// Adresse temoin, qui doit rester joignable.
    #[cfg(windows)]
    #[arg(long, value_name = "IPV4", default_value = "9.9.9.9")]
    temoin_libre: std::net::Ipv4Addr,

    /// Probleme ouvert 2: pose des filtres WFP boot-time et persistants depuis
    /// l'espace utilisateur, pour mesurer s'ils ferment la fenetre de fuite au
    /// demarrage machine. Ne bloque QU'UNE adresse: la machine reste joignable.
    /// Valeurs: poser, constater, retirer.
    #[cfg(windows)]
    #[arg(long, value_name = "ACTION")]
    boot_filtres: Option<String>,

    /// Adresse que les filtres de demarrage bloquent.
    #[cfg(windows)]
    #[arg(long, value_name = "IPV4", default_value = "1.1.1.1")]
    boot_cible: std::net::Ipv4Addr,

    /// Adresse temoin, qui doit rester joignable. Sans elle, un blocage
    /// constate pourrait n'etre qu'une machine sans reseau.
    #[cfg(windows)]
    #[arg(long, value_name = "IPV4", default_value = "9.9.9.9")]
    boot_temoin: std::net::Ipv4Addr,

    /// Cle d'un filtre a retirer en plus des notres, relevee dans le registre.
    /// Sert a debloquer un filtre boot-time dont BFE a engendre la cle: il
    /// n'apparait dans aucune enumeration et retient le sublayer.
    #[cfg(windows)]
    #[arg(long, value_name = "GUID")]
    boot_orphelin: Vec<String>,

    /// Nom de service a inscrire sur le provider persistant. C'est la variable
    /// de l'experience: sans lui, la documentation annonce que les filtres
    /// reviennent DESACTIVES au demarrage de BFE.
    #[cfg(windows)]
    #[arg(long, value_name = "SERVICE")]
    boot_service: Option<String>,

    /// Eprouve que le daemon est bien PREVENU d'une reprise. Endort la machine
    /// et verifie qu'une reprise atteint le canal du superviseur. NE COUPE PAS
    /// le reseau, contrairement a --wfp-veille-selftest: seule la machine
    /// s'endort.
    #[cfg(windows)]
    #[arg(long)]
    reprise_selftest: bool,

    /// Duree de sommeil de --reprise-selftest, en secondes.
    #[cfg(windows)]
    #[arg(long, value_name = "SECONDES", default_value_t = 60)]
    reprise_secondes: u64,

    /// Enregistre le daemon comme service Windows a demarrage automatique.
    #[cfg(windows)]
    #[arg(long)]
    install_service: bool,

    /// Retire le service. Ne touche pas aux filtres deja poses.
    #[cfg(windows)]
    #[arg(long)]
    uninstall_service: bool,

    /// Installe un service de DIAGNOSTIC au lieu du service normal: il pose la
    /// sonde d'identite, journalise ses mesures et s'arrete. Seul moyen de voir
    /// le filtre au SID de service a l'oeuvre, ce SID n'existant dans le token
    /// que sous le gestionnaire de services.
    #[cfg(windows)]
    #[arg(long, requires = "install_service")]
    with_identity_probe: bool,

    /// Reserve au gestionnaire de services, qui lance le binaire avec cet
    /// argument. Sans lui, le processus se comporte en daemon de console.
    #[cfg(windows)]
    #[arg(long, hide = true)]
    service: bool,

    /// Reserve au service de diagnostic pose par --with-identity-probe.
    #[cfg(windows)]
    #[arg(long, hide = true)]
    service_identity_probe: bool,

    /// Cible de la mesure d'etancheite de --wfp-selftest-blocking: une adresse
    /// qui accepte une connexion TCP depuis cette machine. Sans elle, l'autotest
    /// pose les filtres mais ne verifie jamais qu'ils retiennent le trafic, et
    /// le dit.
    #[cfg(windows)]
    #[arg(long, value_name = "ADDR:PORT")]
    leak_target: Option<std::net::SocketAddr>,

    /// Eprouve le kill switch A TRAVERS UNE MISE EN VEILLE, cote Linux. Arme,
    /// endort la machine par systemd, la reveille par alarme RTC, et sonde des
    /// le chemin de reprise. COUPE TOUT LE RESEAU puis ENDORT LA MACHINE.
    /// Machine dediee uniquement, capable de revenir seule.
    #[cfg(target_os = "linux")]
    #[arg(long, requires = "veille_cible")]
    veille_selftest: bool,

    /// Cible de --veille-selftest: une adresse qui accepte une connexion TCP
    /// depuis cette machine au repos. Sans elle, un blocage constate ne
    /// prouverait rien.
    #[cfg(target_os = "linux")]
    #[arg(long, value_name = "ADDR:PORT")]
    veille_cible: Option<std::net::SocketAddr>,

    /// Duree de sommeil de --veille-selftest, en secondes.
    #[cfg(target_os = "linux")]
    #[arg(long, value_name = "SECONDES", default_value_t = 60)]
    veille_secondes_linux: u64,

    /// Interface de tunnel DEJA montee dont le permit doit etre eprouve a
    /// travers la veille. Sans elle, la survie du permit ne sera pas mesuree.
    #[cfg(target_os = "linux")]
    #[arg(long, value_name = "INTERFACE")]
    veille_interface: Option<String>,

    /// Execute la suite des vecteurs de fuite et sort, sans demarrer de daemon
    /// ni d'IPC. C'est ce qu'utilise l'integration continue: aucun processus en
    /// tache de fond a nettoyer ensuite.
    #[arg(long)]
    run_checks: bool,

    /// Affiche l'identifiant de chaque vecteur, un par ligne, et sort.
    ///
    /// Sert au critere de completude de l'integration continue: sans lui le
    /// script comparerait le rapport a un nombre ecrit en dur, qu'il faut
    /// penser a changer a chaque vecteur ajoute. Il ne demande donc plus, il
    /// lit.
    #[arg(long)]
    list_checks: bool,

    /// Sortie JSON pour --run-checks.
    #[arg(long)]
    json: bool,

    /// Genere une paire de cles WireGuard et l'affiche: "privee publique".
    ///
    /// La cle privee part sur la sortie standard: la rediriger vers un fichier
    /// cree avec un umask restrictif, jamais vers un terminal partage.
    #[cfg(target_os = "linux")]
    #[arg(long)]
    genkey: bool,
}

/// Pilote le filtre de demarrage depuis la ligne de commande.
///
/// `montrer` existe pour une raison precise: poser ce filtre coupe tout sauf
/// les exemptions, et une machine joignable uniquement par un reseau overlay
/// devient injoignable si l'option correspondante manque. Lire le plan avant
/// de le poser n'est pas du confort.
#[cfg(windows)]
/// Dit tout haut ce que fermer la plage CGNAT coute.
///
/// Cet avertissement ne vivait que dans la branche `montrer`, celle qui ne
/// touche a rien. Il se taisait donc sur `poser`, la seule qui puisse
/// reellement couper la machine - l'avertissement parlait ou il n'y avait pas
/// de risque et se taisait ou il y en avait un.
///
/// Il ne se declenche plus par defaut depuis que la plage est ouverte sans
/// avoir a le demander: quand il parle, c'est qu'une decision explicite a ete
/// prise, et il est donc lisible comme un signal plutot que comme du bruit.
#[cfg(windows)]
fn avertir_si_overlay_ferme(politique: &bifrost_core::demarrage::PolitiqueDemarrage) {
    if politique.overlay_cgnat {
        return;
    }
    println!(
        "
AVERTISSEMENT: la plage CGNAT 100.64.0.0/10 n'est PAS ouverte.
               Une machine joignable uniquement par un reseau overlay
               (Tailscale, ZeroTier, Nebula) deviendra INJOIGNABLE apres
               redemarrage, et il faudra s'y rendre.
               Sortie de secours depuis la machine elle-meme:
                 bifrost-daemon --demarrage retirer"
    );
}

/// Pilote le filtre de demarrage depuis la ligne de commande.
///
/// `montrer` existe pour une raison precise: poser ce filtre coupe tout sauf
/// les exemptions, et une machine joignable uniquement par un reseau overlay
/// devient injoignable si l'option correspondante manque. Lire le plan avant
/// de le poser n'est pas du confort.
#[cfg(windows)]
fn demarrage_cli(
    action: &str,
    politique: bifrost_core::demarrage::PolitiqueDemarrage,
) -> anyhow::Result<()> {
    use bifrost_firewall::wfp_plan;

    match action {
        "montrer" => {
            let plan = wfp_plan::plan_demarrage(&politique);
            let filtres: usize = plan.iter().map(|f| f.layers.len()).sum();
            println!(
                "politique: reseau local={} overlay CGNAT={} IPv6={}",
                politique.reseau_local, politique.overlay_cgnat, politique.ipv6
            );
            println!(
                "{} regles, {} filtres par duree de vie, {} au total (boot-time + persistants)
",
                plan.len(),
                filtres,
                filtres * 2
            );
            for f in &plan {
                println!(
                    "  [{:>2}] {:<7} {}
        couches: {}
        conditions: {}",
                    f.weight,
                    match f.action {
                        wfp_plan::Action::Permit => "PERMIT",
                        wfp_plan::Action::Block => "BLOCK",
                    },
                    f.name,
                    f.layers
                        .iter()
                        .map(|l| l.name())
                        .collect::<Vec<_>>()
                        .join(", "),
                    if f.conditions.is_empty() {
                        "aucune (catch-all)".to_owned()
                    } else {
                        format!("{:?}", f.conditions)
                    }
                );
            }
            avertir_si_overlay_ferme(&politique);
            Ok(())
        }
        "poser" => {
            // AVANT de poser, pas apres: c'est la derniere ligne que
            // l'operateur lira si la machine se coupe, et une machine coupee
            // n'affiche plus rien.
            avertir_si_overlay_ferme(&politique);
            let ks = bifrost_firewall::windows::WfpKillSwitch::new()?;
            let n = ks.poser_demarrage(&politique)?;
            println!("filtre de demarrage pose: {n} filtres");
            Ok(())
        }
        // Le meme jeu d'objets sans aucun blocage. Eprouve la creation, la
        // survie au redemarrage et le retrait sur une machine distante, sans
        // jamais lui couper le reseau.
        "poser-sans-blocage" => {
            let ks = bifrost_firewall::windows::WfpKillSwitch::new()?;
            let n = ks.poser_demarrage_sans_blocage(&politique)?;
            println!("filtre de demarrage pose SANS BLOCAGE: {n} filtres");
            println!("aucun trafic n'est bloque: ne prouve pas l'etancheite");
            Ok(())
        }
        "retirer" => {
            let ks = bifrost_firewall::windows::WfpKillSwitch::new()?;
            ks.retirer_demarrage()?;
            println!("filtre de demarrage retire");
            Ok(())
        }
        autre => anyhow::bail!(
            "action inconnue: {autre}. Attendu: montrer, poser, poser-sans-blocage, retirer"
        ),
    }
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Le plus tot possible: une ligne de commande qui se contredit se refuse
    // avant tout le reste, sans privilege, sans runtime, et surtout sans avoir
    // rien arme. Voir `conflit_d_ecoute` pour ce que "le plus tot" evite.
    if let Some(raison) = conflit_d_ecoute(args.facade, args.coeur_socks_port, args.coeur_api_port)
    {
        anyhow::bail!(raison);
    }

    // Les sous-commandes internes tournent sans runtime ni journalisation:
    // elles sont lancees en masse par le harnais, dans des namespaces.
    if let Some(kind) = &args.probe {
        let probe: checks::probe::Probe = kind.parse().map_err(anyhow::Error::msg)?;
        checks::probe::emit(probe);
        return Ok(());
    }
    if let Some(dst) = args.probe_tunnel {
        checks::probe::emit_through_tunnel(dst);
        return Ok(());
    }
    if let Some(dst) = args.probe_lan {
        checks::probe::emit_lan(dst);
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    if args.armer_le_banc_et_attendre {
        return checks::armer_le_banc_et_attendre();
    }
    if let Some(cible) = args.lire_banniere {
        // Le code de sortie est le verdict, la sortie standard la preuve: le
        // harnais n'a pas a analyser du texte pour savoir si la lecture a
        // abouti, et le temoin negatif n'a besoin que du code.
        let fenetre = std::time::Duration::from_millis(args.lire_banniere_delai);
        match checks::transport::lire(cible, fenetre) {
            Ok(banniere) => {
                println!("{banniere}");
                return Ok(());
            }
            Err(e) => anyhow::bail!("{e}"),
        }
    }
    if let Some(ecoute) = args.servir_banniere {
        checks::transport::servir(ecoute)
            .with_context(|| format!("service de la banniere sur {ecoute}"))?;
        return Ok(());
    }
    if let Some(ecoute) = args.faux_resolveur {
        checks::resolveur::servir(
            ecoute,
            args.faux_resolveur_adresse,
            args.faux_resolveur_amont,
        )?;
        return Ok(());
    }
    if let Some(ecoute) = args.resolveur_abandon {
        let programme = args
            .resolveur_binaire
            .clone()
            .ok_or_else(|| anyhow::anyhow!("--resolveur-binaire est requis"))?;
        // La bascule d'identifiants est un mecanisme POSIX (setuid entre fork
        // et exec). Sous Windows, le compte de service passe par un autre
        // champ (`compte`), lu par `demarrer_sous_compte`: le mode abandon doit
        // le propager pour que la garde anti-orphelin soit mesuree sur le meme
        // chemin de lancement que la production (11b-1).
        #[cfg(unix)]
        let bascule = match args.resolveur_utilisateur.as_deref() {
            Some(nom) => Some(bifrost_daemon::resolveur::Bascule::pour(nom)?),
            None => None,
        };
        #[cfg(not(unix))]
        let bascule = None;
        bifrost_daemon::resolveur::abandon(&bifrost_daemon::resolveur::Lancement {
            programme,
            configuration: args.resolveur_configuration.clone(),
            ecoute,
            bascule,
            #[cfg(windows)]
            compte: args.resolveur_utilisateur.clone(),
            // 11b-2 (ecart 2): `demarrer_sous_compte` ouvre lui-meme au
            // compte, a chaque lancement, la lecture heritable du repertoire
            // de cette configuration (ou vit la liste qu'elle nomme) et
            // l'ecriture heritable de l'etat. Le mode abandon n'a donc rien
            // de plus a transmettre que l'etat, et repose sur le meme
            // mecanisme que la production: plus aucun couplage avec les ACE
            // laissees par le lancement precedent du selftest.
            #[cfg(windows)]
            etat: args.resolveur_etat.clone(),
            // Ecart 3: le repertoire du profil est refuse comme repertoire du
            // resolveur; la garde a besoin de savoir ou il vit.
            #[cfg(windows)]
            profil: args.profil.clone(),
        })?;
        unreachable!("la mort brutale ne rend pas la main")
    }
    if args.resolveur_selftest {
        let programme = args
            .resolveur_binaire
            .clone()
            .ok_or_else(|| anyhow::anyhow!("--resolveur-binaire est requis"))?;
        // Le compte demande, sur les deux plateformes depuis 11b-1: sous
        // Windows le selftest lance le resolveur sous ce compte et verifie
        // son SID effectif, au lieu de l'ignorer. Sous Windows aussi (ecart 3),
        // le chemin du profil: son repertoire est refuse comme repertoire du
        // resolveur, et le selftest passe par la meme garde que la production.
        // Le selftest Unix ne change pas.
        #[cfg(unix)]
        return bifrost_daemon::resolveur::selftest(
            &programme,
            &args.resolveur_configuration,
            &args.resolveur_etat,
            &args.resolveur_serveurs,
            &args.resolveur_bootstrap,
            args.resolveur_utilisateur.as_deref(),
        );
        #[cfg(windows)]
        return bifrost_daemon::resolveur::selftest(
            &programme,
            &args.resolveur_configuration,
            &args.resolveur_etat,
            &args.resolveur_serveurs,
            &args.resolveur_bootstrap,
            args.resolveur_utilisateur.as_deref(),
            &args.profil,
        );
    }
    if let Some(serveur) = args.interroger {
        let reponse = checks::resolveur::interroger(serveur, "bifrost.test")
            .with_context(|| format!("interrogation de {serveur}"))?;
        println!("{} octet(s) recus de {serveur}", reponse.len());
        return Ok(());
    }
    if let Some(nom) = &args.resoudre {
        // Le code de sortie est le verdict: le harnais n'a pas a analyser du
        // texte pour savoir si la resolution a marche.
        let adresses =
            checks::resolveur::resoudre(nom).with_context(|| format!("resolution de {nom}"))?;
        for adresse in &adresses {
            println!("{adresse}");
        }
        if adresses.is_empty() {
            anyhow::bail!("{nom} resolu sans aucune adresse");
        }
        return Ok(());
    }
    #[cfg(debug_assertions)]
    if let Some(config) = &args.faux_coeur {
        return tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(bifrost_daemon::coeurs::doublure::servir(config));
    }
    #[cfg(debug_assertions)]
    if let Some(config) = &args.faux_parent {
        let avec_garde = !args.faux_parent_sans_garde;
        let utilisateur = match &args.faux_parent_utilisateur {
            None => None,
            Some(s) => Some(lire_utilisateur(s)?),
        };
        return tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?
            .block_on(bifrost_daemon::coeurs::doublure::parent(
                config,
                avec_garde,
                utilisateur,
            ));
    }
    // Avant `ensure_privileged`: le temoin ne touche a rien de privilegie, et
    // l'exiger administrateur masquerait ce que la sonde mesure.
    #[cfg(windows)]
    if let Some(addr) = args.connect_probe {
        let verdict = match args.connect_probe_rafale {
            Some(ms) => {
                bifrost_daemon::wfp_identity::rafale(addr, std::time::Duration::from_millis(ms))
            }
            None => bifrost_daemon::wfp_identity::connect(addr),
        };
        std::process::exit(verdict.code());
    }
    #[cfg(target_os = "linux")]
    if let Some(json) = &args.wg_apply {
        let spec: checks::wgapply::WgSpec =
            serde_json::from_str(json).context("specification WireGuard illisible")?;
        checks::wgapply::apply(&spec)?;
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    if args.genkey {
        let (private, public) = checks::wgapply::generate_keypair();
        println!("{private} {public}");
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    if let Some(iface) = &args.wg_stats {
        let compteurs = checks::wgapply::peer_stats(iface)?;
        println!("{}", serde_json::to_string(&compteurs)?);
        return Ok(());
    }

    #[cfg(windows)]
    init_tracing(args.service);
    #[cfg(not(windows))]
    init_tracing(false);

    if args.cleanup_firewall {
        let mut fw = bifrost_firewall::new()?;
        fw.disengage()?;
        println!("filtres du kill switch retires ({})", fw.backend());
        // Le resolveur ENSUITE, et pas avant: tant que les filtres tiennent,
        // une machine qui resout de nouveau ne sort toujours pas. L'inverse
        // laisserait une fenetre ou le trafic passe et le DNS pointe encore
        // dans le vide.
        #[cfg(target_os = "linux")]
        match bifrost_dns::linux::restaurer_apres_arret() {
            Ok(Some(dit)) => println!("{dit}"),
            Ok(None) => println!("resolveur: rien a rendre, il n'est pas de nous"),
            // Ne PAS faire echouer le nettoyage: les filtres, eux, sont bien
            // retires, et c'est le plus urgent des deux. Le dire suffit.
            Err(e) => eprintln!("resolveur non restaure: {e}"),
        }
        return Ok(());
    }

    // Avant `ensure_privileged`: le sondage n'ouvre que des sockets clients et
    // ne fait que LIRE le carnet, deux choses a la portee de n'importe quel
    // utilisateur. L'exiger administrateur le rendrait inutilisable pour
    // diagnostiquer un reseau depuis un poste ordinaire, ce qui est precisement
    // son emploi. L'ecriture du carnet, elle, reste au daemon.
    if args.sonder_reseau {
        return sonder_reseau(args.pays, args.sonder_quand_meme);
    }

    // Meme raison: une socket cliente vers le port 443 d'un site public.
    if let Some(hotes) = &args.qualifier_dest {
        return qualifier_dest(hotes);
    }

    // Avant `ensure_privileged`: dire l'etat de la couche 1 ne fait que LIRE le
    // registre et interroger le planificateur, ce que n'importe quel compte
    // peut faire. Exiger l'elevation pour lire pousserait a lancer en
    // privilegie la commande qu'on voulait justement pouvoir passer sans
    // risque - le depot a deja tire cette lecon ailleurs. Poser et restaurer,
    // en revanche, ecrivent sous HKLM et passent par `ensure_privileged`.
    #[cfg(windows)]
    if args.telemetrie_etat {
        return telemetrie_commande(&args);
    }

    // Meme raison: l'etat des lieux de la couche 2 ne fait qu'interroger le
    // SCM en SC_MANAGER_CONNECT, lire des chemins et enumerer le moteur.
    #[cfg(windows)]
    if args.telemetrie_reseau_etat {
        return telemetrie_reseau_commande(&args);
    }

    // Avant `ensure_privileged`, comme le sondage: la recette n'ouvre que des
    // sockets locales et lance un programme sans droits particuliers.
    if let Some(coeur) = args.coeur_selftest {
        let racine = args
            .coeurs_dans
            .clone()
            .ok_or_else(|| anyhow::anyhow!("--coeurs-dans est requis"))?;
        let identite = identite_du_coeur(&args)?;
        return tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?
            .block_on(bifrost_daemon::coeurs::selftest::run(
                coeur.into(),
                racine,
                &identite,
            ));
    }

    if let Some(profil) = args.coeur_e2e.clone() {
        let racine = args
            .coeurs_dans
            .clone()
            .ok_or_else(|| anyhow::anyhow!("--coeurs-dans est requis"))?;
        let identite = identite_du_coeur(&args)?;
        return tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?
            .block_on(bifrost_daemon::coeurs::e2e::run(racine, &profil, &identite));
    }

    // Avant le controle de privileges: `montrer` n'ouvre pas le moteur WFP et
    // ne touche a aucun objet. Exiger l'elevation pour LIRE un plan pousserait
    // a lancer en administrateur la commande qu'on voulait justement pouvoir
    // relire sans risque.
    #[cfg(windows)]
    if args.demarrage.as_deref() == Some("montrer") {
        return demarrage_cli("montrer", politique_demarrage(&args));
    }

    // Meme raison que `montrer` juste au-dessus: `constater` ne fait que LIRE
    // des politiques. Exiger root ou l'elevation pour verifier un etat
    // pousserait a lancer en privilegie la commande qu'on voulait justement
    // pouvoir passer sans risque.
    if args.doh_policy.as_deref() == Some("constater") {
        #[cfg(target_os = "linux")]
        use bifrost_daemon::checks::doh_fichiers as lecteur;
        #[cfg(windows)]
        use bifrost_daemon::checks::doh_registre as lecteur;
        return bifrost_daemon::checks::doh_pose::rapporter_constat(&lecteur::vecteur());
    }

    ensure_privileged()?;

    #[cfg(windows)]
    if args.telemetrie_appliquer || args.telemetrie_restaurer {
        return telemetrie_commande(&args);
    }

    #[cfg(windows)]
    if args.telemetrie_reseau_appliquer
        || args.telemetrie_reseau_retirer
        || args.telemetrie_sonde_sid.is_some()
        || args.telemetrie_sonde_binaire.is_some()
    {
        return telemetrie_reseau_commande(&args);
    }

    #[cfg(windows)]
    if args.install_service {
        let exe = std::env::current_exe().context("chemin du binaire courant")?;
        // Le MEME champ que celui dont l'atelier fait un lancement, et que
        // l'exemption WFP nomme. Un service installe avec un autre chemin que
        // celui qu'il lancera serait une divergence qui ne se voit qu'au
        // demarrage.
        return bifrost_daemon::service::scm::install(
            &exe,
            args.with_identity_probe,
            args.resolveur_binaire.as_deref(),
            // 11b-2: le compte de service du resolveur, porte jusqu'a
            // l'ImagePath. C'est le MEME champ que celui dont l'atelier fait un
            // lancement et que l'exemption WFP nomme; `scm::install` le resout
            // a l'installation et refuse un compte inconnu, plutot que de
            // laisser le service echouer a son premier demarrage.
            args.resolveur_utilisateur.as_deref(),
        );
    }

    #[cfg(windows)]
    if args.uninstall_service {
        return bifrost_daemon::service::scm::uninstall();
    }

    #[cfg(target_os = "linux")]
    if args.veille_selftest {
        let cible = args
            .veille_cible
            .expect("clap garantit --veille-cible par son attribut requires");
        return bifrost_daemon::veille_linux::selftest(
            cible,
            std::time::Duration::from_secs(args.veille_secondes_linux),
            args.veille_interface.as_deref(),
        );
    }

    #[cfg(windows)]
    if let Some(action) = args.demarrage.as_deref() {
        let politique = politique_demarrage(&args);
        return demarrage_cli(action, politique);
    }

    #[cfg(windows)]
    if args.dns_leak_selftest {
        return bifrost_daemon::dns_leak::selftest(args.dns_leak_resolveur, args.wfp_selftest_lan);
    }

    if let Some(verbe) = args.doh_policy.as_deref() {
        use bifrost_daemon::checks::doh_pose;
        #[cfg(target_os = "linux")]
        use bifrost_daemon::checks::doh_pose_fichiers as poseur;
        #[cfg(windows)]
        use bifrost_daemon::checks::doh_pose_registre as poseur;

        // Ce que la commande touche n'est pas que du navigateur sous Windows:
        // le dire AVANT d'ecrire, et seulement quand elle ecrit. L'annoncer sur
        // `constater`, qui ne touche a rien, userait l'avertissement.
        #[cfg(windows)]
        if verbe == "poser" || verbe == "retirer" {
            println!(
                "{}
",
                bifrost_daemon::checks::doh_pose_registre::avertissement()
            );
        }

        let resultats = match verbe {
            "poser" => poseur::poser(),
            "retirer" => poseur::retirer(),
            autre => {
                anyhow::bail!("verbe inconnu: {autre}. Attendu: poser, constater, retirer")
            }
        };
        return doh_pose::rapporter(verbe, &resultats);
    }

    #[cfg(windows)]
    if let Some(phase) = args.startup_window.as_deref() {
        let politique = politique_demarrage(&args);
        return match phase {
            "armer" => bifrost_daemon::startup_window::armer(args.startup_window_cible, politique),
            "constater" => bifrost_daemon::startup_window::constater(),
            autre => anyhow::bail!("phase inconnue: {autre}. Attendu: armer, constater"),
        };
    }

    #[cfg(windows)]
    if args.ipv6_leak_selftest {
        return bifrost_daemon::ipv6_leak::selftest(args.ipv6_leak_cible, args.wfp_selftest_lan);
    }

    #[cfg(windows)]
    if args.chute_tunnel_selftest {
        return bifrost_daemon::chute_tunnel::selftest(
            args.chute_tunnel_cible,
            args.wfp_selftest_lan,
        );
    }

    #[cfg(windows)]
    if args.coeur_exemption_selftest {
        return bifrost_daemon::coeur_exemption::selftest(
            args.coeur_exemption_cible,
            args.coeur_exemption_resolveur,
            args.wfp_selftest_lan,
        );
    }

    #[cfg(windows)]
    if args.resolveur_exemption_selftest {
        return bifrost_daemon::resolveur_exemption::selftest(
            args.resolveur_exemption_cible,
            args.resolveur_exemption_resolveur,
            args.wfp_selftest_lan,
        );
    }

    #[cfg(windows)]
    if args.temoin_selftest {
        return bifrost_daemon::temoin_wfp::selftest(args.temoin_cible, args.temoin_libre);
    }

    #[cfg(windows)]
    if let Some(action) = args.boot_filtres.as_deref() {
        use bifrost_daemon::boot_filtres;
        return match action {
            "poser" => boot_filtres::poser(args.boot_cible, args.boot_service.as_deref()),
            "constater" => boot_filtres::constater(args.boot_cible, args.boot_temoin),
            "retirer" => {
                let orphelins = args
                    .boot_orphelin
                    .iter()
                    .map(|s| boot_filtres::guid_depuis_texte(s))
                    .collect::<anyhow::Result<Vec<_>>>()?;
                boot_filtres::retirer(&orphelins)
            }
            autre => anyhow::bail!("action inconnue: {autre}. Attendu: poser, constater, retirer"),
        };
    }

    #[cfg(windows)]
    if args.reprise_selftest {
        return bifrost_daemon::reprise::selftest(std::time::Duration::from_secs(
            args.reprise_secondes,
        ));
    }

    #[cfg(windows)]
    if args.wfp_veille_selftest {
        let cible = args
            .leak_target
            .expect("clap garantit --leak-target par son attribut requires");
        return bifrost_daemon::wfp_veille::selftest(
            cible,
            std::time::Duration::from_secs(args.veille_secondes),
            args.veille_tunnel.as_deref(),
            args.veille_monter_tunnel.as_deref(),
        );
    }

    #[cfg(windows)]
    if args.wfp_selftest || args.wfp_selftest_blocking {
        return bifrost_daemon::wfp_selftest::run_avec_lan(
            args.wfp_selftest_blocking,
            args.leak_target,
            args.wfp_selftest_lan,
        );
    }

    #[cfg(windows)]
    if args.wgnt_selftest {
        return bifrost_daemon::tunnel::wgnt::selftest::run();
    }

    #[cfg(windows)]
    if let Some(profil) = &args.wgnt_e2e {
        let cible = args
            .wgnt_e2e_target
            .ok_or_else(|| anyhow::anyhow!("--wgnt-e2e demande --wgnt-e2e-target <ADDR:PORT>"))?;
        // `None`: la recette de transport ne sonde pas de destination publique.
        // Ce temoin n'a de sens qu'avec une capture pour le lire, donc pour le
        // vecteur `exit-ip`.
        return bifrost_daemon::tunnel::wgnt::e2e::run(
            profil,
            cible,
            args.wgnt_e2e_route_par_defaut,
            None,
            args.wgnt_e2e_bouclage,
        );
    }

    #[cfg(windows)]
    if let Some(profil) = &args.exit_ip_selftest {
        let cible = args.exit_ip_cible.ok_or_else(|| {
            anyhow::anyhow!("--exit-ip-selftest demande --exit-ip-cible <ADDR:PORT>")
        })?;
        return bifrost_daemon::exit_ip::selftest(
            profil,
            cible,
            args.wgnt_e2e_route_par_defaut,
            args.exit_ip_temoin,
        );
    }

    if args.list_checks {
        for v in bifrost_core::checks::CheckVector::ALL {
            println!("{}", v.id());
        }
        return Ok(());
    }

    if args.run_checks {
        let rapport = checks::run_all();
        if args.json {
            println!("{}", serde_json::to_string_pretty(&rapport)?);
        } else {
            for o in &rapport.outcomes {
                println!("{:?}\t{}\t{}", o.verdict, o.vector.id(), o.detail);
                for preuve in &o.evidence {
                    println!("\t\t{preuve}");
                }
            }
        }
        std::process::exit(rapport.exit_code());
    }

    // Sous le gestionnaire de services, c'est lui qui appelle le corps: on lui
    // rend la main plutot que de demarrer le runtime ici.
    #[cfg(windows)]
    if args.service {
        let sonde = args.service_identity_probe;
        return bifrost_daemon::service::scm::run_as_service(Box::new(move || {
            if sonde {
                // Un coup, puis le service s'arrete proprement. Pas de runtime
                // tokio ni d'IPC: on ne mesure qu'une identite.
                return sonde_identite_en_service();
            }
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?
                .block_on(run(args))
        }));
    }

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(run(args))
}

/// Lit un `uid:gid`. Interne au harnais de test.
#[cfg(debug_assertions)]
fn lire_utilisateur(s: &str) -> anyhow::Result<bifrost_daemon::coeurs::lancement::Utilisateur> {
    let (uid, gid) = s
        .split_once(':')
        .ok_or_else(|| anyhow::anyhow!("attendu uid:gid, recu {s:?}"))?;
    Ok(bifrost_daemon::coeurs::lancement::Utilisateur {
        uid: uid.parse()?,
        gid: gid.parse()?,
    })
}

/// Assemble le chemin par coeur, quand l'exploitation a donne les deux moities.
///
/// # Pourquoi les deux, ou rien
///
/// Ce que deux ecoutes locales ne peuvent pas partager, dit AVANT de rien armer.
///
/// Le chemin par coeur pose trois ecoutes sur la boucle: la facade, ou le TUN
/// mene les paquets; le SOCKS du coeur, derriere elle; l'API de controle du
/// coeur, par ou passent la sonde de vitalite et la bascule. Elles ne sont pas
/// liees en meme temps - la facade au demarrage, les deux autres au lancement
/// du coeur, c'est-a-dire a la premiere connexion.
///
/// # Pourquoi ce controle existe
///
/// Mesure le 20 aout 2026: `--facade 127.0.0.1:1080` contre le defaut de
/// `--coeur-socks-port`, lui aussi 1080. Le daemon demarre sans rien dire, la
/// facade prend le port, le kill switch s'arme, et c'est le COEUR qui echoue,
/// avec "FATAL start inbound/socks[entree]: listen tcp 127.0.0.1:1080: bind:
/// address already in use". Le message accuse sing-box, ne nomme aucun des deux
/// drapeaux qui se disputent le port, et arrive au pire moment: apres
/// l'armement, quand l'exploitant croit son tunnel en train de monter.
///
/// Le conflit etait pourtant connu des la ligne de commande.
///
/// # Comparer les valeurs, et non essayer de se lier
///
/// Une sonde de liaison dirait aussi si un TIERS occupe le port, ce que la
/// comparaison ignore. Elle le dirait au prix d'une course: entre la sonde et
/// la liaison reelle, le port peut changer de main, et ce depot a deja un test
/// qui clignote pour cette raison exacte. Le tiers, lui, se manifeste de toute
/// facon a la liaison, avec un message que l'exploitant peut lire. Ce qui ne se
/// manifeste PAS lisiblement est le conflit avec nous-memes: c'est donc lui
/// qu'on refuse ici, et rien d'autre.
fn conflit_d_ecoute(facade: Option<std::net::SocketAddr>, socks: u16, api: u16) -> Option<String> {
    fn dit(a: &str, b: &str, port: u16) -> Option<String> {
        Some(format!(
            "{a} et {b} demandent le meme port {port} sur la boucle locale. Sans ce refus, le conflit n'apparaitrait qu'a la premiere connexion, quand le coeur echouerait a se lier: le kill switch serait deja arme, et le message accuserait le coeur."
        ))
    }

    if socks == api {
        return dit("--coeur-socks-port", "--coeur-api-port", socks);
    }
    let f = facade?;
    // Le port 0 demande au systeme d'en choisir un: il ne peut disputer aucun
    // port fixe, et le compter comme tel refuserait la seule forme qui permette
    // a une recette de ne pas se battre pour un port avec sa machine.
    if f.port() == 0 {
        return None;
    }
    // Une ecoute sur toutes les adresses prend AUSSI la boucle: `0.0.0.0:1080`
    // accepte ce qui arrive sur `127.0.0.1:1080`. A l'inverse, une adresse
    // precise qui n'est pas la boucle ne dispute rien, et la refuser serait un
    // refus faux - aussi mauvais qu'une panne tardive.
    if !(f.ip().is_loopback() || f.ip().is_unspecified()) {
        return None;
    }
    if f.port() == socks {
        return dit("--facade", "--coeur-socks-port", socks);
    }
    if f.port() == api {
        return dit("--facade", "--coeur-api-port", api);
    }
    None
}

/// Le peripherique mene les paquets a la facade; le necessaire de lancement
/// fait qu'un coeur ecoute derriere elle. Avec la facade seule, le TUN
/// enverrait tout le trafic de la machine vers une ecoute qui ferme les
/// connexions. Avec le repertoire seul, un coeur tournerait sans que rien ne le
/// rejoigne. C'est pourquoi ce chemin est `None` des qu'une moitie manque, et
/// pourquoi le superviseur refuse alors un profil de coeur en NOMMANT les deux
/// drapeaux.
///
/// Rend `None` sur une plateforme ou le peripherique par coeur n'est pas
/// ecrit - ni Linux ni Windows aujourd'hui. Le declarer disponible ferait
/// echouer la connexion au montage plutot qu'a la porte.
fn chemin_par_coeur(
    args: &Args,
    facade: Option<std::net::SocketAddr>,
    _identite: &IdentiteCoeur,
    _coeur_actif: tokio::sync::watch::Receiver<Option<std::net::SocketAddr>>,
) -> anyhow::Result<Option<bifrost_daemon::supervisor::CheminCoeur>> {
    let (Some(binaires), Some(facade)) = (args.coeurs_dans.clone(), facade) else {
        return Ok(None);
    };

    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = (binaires, facade, _coeur_actif);
        tracing::info!(
            "chemin par coeur non disponible sur cette plateforme: le peripherique n'y est pas ecrit"
        );
        Ok(None)
    }

    #[cfg(any(target_os = "linux", windows))]
    {
        // Le passeur vit sur le runtime, comme l'atelier, et pour la meme
        // raison: le superviseur de tunnel n'a pas de handle de runtime.
        let (passage, tache) = bifrost_daemon::coeurs::passage::ouvrir();
        tokio::spawn(tache);

        // La sonde de vitalite vit au meme endroit et pour la meme raison. Le
        // secret est celui qu'on engendre plus bas pour l'API du coeur: le
        // meme, sans quoi la sonde se ferait refuser par ce que nous avons
        // nous-memes configure.
        let secret = bifrost_daemon::coeurs::alea::secret()?;
        // UNE adresse pour les deux. La sonde demande au coeur si la sortie
        // courante repond, la bascule lui demande d'en changer: si les deux
        // visaient deux selecteurs, on basculerait l'un en sondant l'autre, et
        // le tunnel paraitrait gele juste apres avoir ete repare.
        let adresse_du_coeur = bifrost_daemon::coeurs::vitalite::Adresse {
            api: std::net::SocketAddr::from(([127, 0, 0, 1], args.coeur_api_port)),
            secret: secret.clone(),
            selecteur: bifrost_daemon::supervisor::SELECTEUR.to_owned(),
        };
        let (sonde, veille) = bifrost_daemon::coeurs::vitalite::ouvrir(adresse_du_coeur.clone());
        tokio::spawn(veille);

        // La bascule a chaud vit au meme endroit et pour la meme raison: deux
        // allers-retours HTTP n'ont rien a faire sur le fil qui tient le kill
        // switch.
        let (bascule, conduite) = bifrost_daemon::coeurs::bascule::ouvrir(adresse_du_coeur);
        tokio::spawn(conduite);

        // Le compte que le coeur exigera de son entree SOCKS. Engendre au
        // demarrage comme le secret de l'API, et pour la meme raison: un mot de
        // passe passe en argument est lisible par tout le monde dans `ps`.
        // Sans lui, l'entree du coeur accepte n'importe quel processus de la
        // machine - mesure sur le banc le 20 aout 2026.
        let coeur = bifrost_daemon::coeurs::socks::Mandataire::nouveau(
            facade,
            bifrost_daemon::coeurs::socks::Identifiants::nouveaux(
                "bifrost",
                &bifrost_daemon::coeurs::alea::secret()?,
            )?,
        );
        let socks = bifrost_daemon::coeurs::socks::Mandataire::nouveau(
            std::net::SocketAddr::from(([127, 0, 0, 1], args.coeur_socks_port)),
            coeur.identifiants.clone(),
        );
        tracing::info!(
            %facade,
            socks = %socks.adresse,
            binaires = %binaires.display(),
            "chemin par coeur disponible"
        );
        Ok(Some(bifrost_daemon::supervisor::CheminCoeur {
            tunnel: Box::new(bifrost_daemon::tunnel::coeur::CoeurTunnel::new(
                passage,
                coeur,
                // Sous Windows le coeur ne s'echappe pas par son compte mais par
                // la liaison de sa socket, decidee au lancement: le
                // peripherique ignore alors cette valeur. Elle est passee
                // quand meme pour que l'assemblage soit le meme des deux cotes.
                _identite.utilisateur.map(|u| u.uid),
                // Le meme signal que suit la facade: elle s'en sert pour mener
                // les octets, ce peripherique pour savoir s'il est encore
                // vivant. Deux lecteurs d'une seule verite, plutot que deux
                // idees de l'etat du coeur qui pourraient diverger.
                _coeur_actif,
            )),
            emplacements: bifrost_daemon::coeurs::lancement::Emplacements {
                binaires,
                configurations: args.coeurs_configurations.clone(),
            },
            socks,
            api: args.coeur_api_port,
            // Engendre a chaque demarrage, et jamais ailleurs: le secret ne
            // passe ni par un argument, ni par un fichier que nous n'ecrivons
            // pas nous-memes.
            secret,
            sonde,
            bascule,
        }))
    }
}

/// Ou ecrire les configurations engendrees, faute d'indication contraire.
///
/// Un chemin par plateforme, et pas le meme critere pour les deux. Sous Linux
/// `/run` disparait au redemarrage, ce qui suffit a proteger un fichier que le
/// code pose deja en 0600. Sous Windows le fichier herite de l'ACL de son
/// repertoire - `coeurs::configuration::ecrire` le dit et ne fait pas
/// semblant du contraire - donc ce qui compte n'est pas d'etre jetable mais
/// d'etre sous un repertoire dont l'ACL est posee a l'installation. C'est
/// `%ProgramData%\Bifrost`, la ou vit deja le profil.
///
/// Ecrit ici, a cote de l'argument qui s'en sert, plutot que dans une
/// constante partagee: contrairement au profil, que le client et le daemon
/// doivent tous deux designer, ce repertoire n'est nomme que par le daemon.
#[cfg(unix)]
const CONFIGURATIONS_PAR_DEFAUT: &str = "/run/bifrost/coeurs";
#[cfg(windows)]
const CONFIGURATIONS_PAR_DEFAUT: &str = r"C:\ProgramData\Bifrost\coeurs";

/// Assemble l'identite du coeur a partir de ce que l'exploitation declare.
///
/// Les deux champs sont independants parce que les deux plateformes ne
/// designent pas un processus de la meme facon: un compte sous Linux, un
/// binaire sous Windows. Declarer l'un sans l'autre est donc normal, et non
/// une configuration a moitie faite.
fn identite_du_coeur(args: &Args) -> anyhow::Result<IdentiteCoeur> {
    #[cfg(unix)]
    let utilisateur = match &args.coeur_utilisateur {
        Some(s) => Some(
            bifrost_daemon::coeurs::identite::lire_compte(s)
                .with_context(|| format!("--coeur-utilisateur {s:?}"))?,
        ),
        None => None,
    };
    #[cfg(not(unix))]
    let utilisateur = None;

    Ok(IdentiteCoeur {
        utilisateur,
        executable: args.coeur_binaire.clone(),
    })
}

/// Identite du resolveur chiffre embarque, quand l'exploitation en declare un.
///
/// Ne pas la declarer n'est pas un defaut de configuration: sans resolveur qui
/// ecoute sur la boucle locale, fermer le :53 retirerait la resolution de noms
/// a la machine au lieu de la durcir.
///
/// Les deux plateformes ne repondent pas a la meme question. Sous Linux,
/// `meta skuid` compare le proprietaire du socket, donc l'identite EST un
/// compte. Sous Windows, WFP compare `ALE_APP_ID`, donc l'identite est un
/// CHEMIN - et c'est pourquoi Windows peut nommer le resolveur dans un filtre
/// sans lui donner de compte a lui. Les deux champs sont renseignes
/// separement, chacun par ce que sa plateforme sait fournir.
fn identite_du_resolveur(args: &Args) -> anyhow::Result<IdentiteResolveur> {
    #[cfg(unix)]
    let utilisateur = match &args.resolveur_utilisateur {
        Some(s) => Some(
            bifrost_daemon::coeurs::identite::lire_compte(s)
                .with_context(|| format!("--resolveur-utilisateur {s:?}"))?,
        ),
        None => None,
    };
    #[cfg(not(unix))]
    let utilisateur = None;

    // Sous Windows (11b-1), le compte de service demande et son SID resolu une
    // fois pour toutes. Le SID est ce que `restreindre` posera dans la politique
    // et ce que `permit-resolveur-dns` nommera; le nom est ce sous quoi le
    // daemon lancera le resolveur. Sans compte declare, les deux sont None et le
    // filtre garde `Identity::Current` (comportement d'avant 11b-1).
    #[cfg(windows)]
    let sid = match &args.resolveur_utilisateur {
        Some(nom) => Some(
            bifrost_daemon::coeurs::identite::resoudre_sid_compte(nom)
                .with_context(|| format!("--resolveur-utilisateur {nom:?}"))?,
        ),
        None => None,
    };

    Ok(IdentiteResolveur {
        utilisateur,
        // Le MEME champ que celui dont l'atelier fait un lancement. C'est ce
        // qui rend impossible - et pas seulement improbable - qu'on exempte un
        // chemin dont rien ne sort.
        executable: args.resolveur_binaire.clone(),
        #[cfg(windows)]
        compte: args.resolveur_utilisateur.clone(),
        #[cfg(windows)]
        sid,
    })
}

/// L'atelier du resolveur: de quoi en lancer un, quand un binaire est designe.
///
/// Separe de l'identite, et pas par gout du decoupage. Restreindre le :53 sans
/// embarquer de binaire est un cas legitime: un dnscrypt-proxy installe par la
/// distribution et pilote par systemd merite la meme restriction. Lier les
/// deux obligerait a embarquer un resolveur pour avoir le droit d'en proteger
/// un.
fn atelier_du_resolveur(args: &Args) -> Option<bifrost_daemon::resolveur::Atelier> {
    let programme = args.resolveur_binaire.clone()?;
    Some(bifrost_daemon::resolveur::Atelier {
        programme,
        configuration: args.resolveur_configuration.clone(),
        etat: args.resolveur_etat.clone(),
        serveurs: args.resolveur_serveurs.clone(),
        bootstrap: args.resolveur_bootstrap.clone(),
        // Ecart 3: ou vit le profil, pour refuser son repertoire comme
        // repertoire du resolveur (avant toute ACE).
        #[cfg(windows)]
        profil: args.profil.clone(),
        // Le compte sous lequel le daemon fait tourner le resolveur. C'est le
        // meme que celui declare au kill switch, et il vient de la meme source:
        // les faire diverger donnerait un resolveur dont les requetes seraient
        // bloquees par la regle censee les laisser passer. Sous Unix c'est un
        // compte POSIX (bascule setuid); sous Windows (11b-1) un compte de
        // service (LogonUser + CreateProcessAsUser).
        compte: args.resolveur_utilisateur.clone(),
    })
}

/// Qualifie des sites empruntes par REALITY et affiche la mesure.
///
/// Affiche les CHIFFRES et pas seulement un verdict: la limite est une borne
/// calibree, pas une constante lue dans le code de Xray, et quiconque choisit
/// un site doit pouvoir voir de combien il passe ou de combien il deborde.
fn qualifier_dest(hotes: &[String]) -> anyhow::Result<()> {
    use bifrost_daemon::tls;
    use bifrost_evasion::environnement::Mesure;

    // La reference d'abord: c'est le temoin, et sans elle rien ne se conclut.
    let reference = tls::observer_maintenant(tls::SITE_DE_REFERENCE, 443)?;
    let taille_reference = tls::taille_exploitable(&reference);
    match taille_reference {
        Some(n) => println!(
            "reference: {} renvoie {n} octets sur son plus grand enregistrement\n",
            tls::SITE_DE_REFERENCE
        ),
        None => println!(
            "reference: {} n'a pas pu etre mesure, donc AUCUN candidat ne sera qualifie\n",
            tls::SITE_DE_REFERENCE
        ),
    }

    println!(
        "{:<26} {:>11} {:>9} {:>6}  verdict",
        "site", "plus grand", "total", "enr."
    );
    for hote in hotes {
        let observation = tls::observer_maintenant(hote, 443)?;
        let verdict = tls::conclure_site_emprunte(&observation, &reference);
        let (plus_grand, total, compte) = match &observation {
            tls::Observation::Vue(v) => (
                v.plus_grand().to_string(),
                v.total().to_string(),
                v.enregistrements.len().to_string(),
            ),
            _ => ("-".into(), "-".into(), "-".into()),
        };
        let mot = match verdict {
            Mesure::Vu(true) => "DANS L'ENVELOPPE",
            Mesure::Vu(false) => "AU-DELA",
            Mesure::NonMesure => "NON MESURE",
        };
        let motif = match (&observation, taille_reference) {
            (tls::Observation::Injoignable, _) => " (site injoignable)".to_string(),
            (tls::Observation::Muet, _) => " (aucune reponse avant l'echeance)".to_string(),
            (tls::Observation::Vue(v), _) if v.tronquee => {
                " (volee tronquee, borne inferieure)".to_string()
            }
            (tls::Observation::Vue(v), _) if v.alerte() => {
                " (le site a repondu une alerte)".to_string()
            }
            (tls::Observation::Vue(v), _) if !v.a_repondu() => {
                " (aucun enregistrement de poignee)".to_string()
            }
            (_, None) => " (pas de reference a quoi comparer)".to_string(),
            (tls::Observation::Vue(v), Some(r)) => {
                format!(" ({:.2}x la reference)", v.plus_grand() as f64 / r as f64)
            }
        };
        println!("{hote:<26} {plus_grand:>11} {total:>9} {compte:>6}  {mot}{motif}");
    }
    println!(
        "\n\"dans l'enveloppe\" ne certifie rien: cela dit que le site ne renvoie pas PLUS\n\
         que {}, dont on sait qu'il fait passer du trafic. C'est \"au-dela\" qui informe.",
        tls::SITE_DE_REFERENCE
    );
    Ok(())
}

/// Sonde le reseau et affiche le resultat.
///
/// L'affichage donne autant de place aux champs NON mesures qu'aux autres, et
/// c'est le point: un sondage muet et un sondage qui n'a rien trouve se
/// ressemblent, et seul le motif les separe.
fn sonder_reseau(pays: PaysArg, quand_meme: bool) -> anyhow::Result<()> {
    use bifrost_daemon::sondes;
    let pays: Pays = pays.into();
    let aujourd_hui = aujourd_hui()?;

    // AVANT toute sonde: ce reseau est-il deja connu. Chacune des mesures de
    // l'environnement exige un paquet sortant, la reconnaissance n'en exige
    // aucun. L'ordre est donc le fond de l'affaire et pas un detail
    // d'agencement: reconnaitre apres avoir sonde n'economiserait rien.
    let cle = bifrost_daemon::carnet::cle_courante();
    let chemin = bifrost_daemon::carnet::chemin();
    let carnet = match &chemin {
        Ok(c) => bifrost_daemon::carnet::lire(c).map_err(|e| anyhow::anyhow!(e))?,
        Err(e) => bail!("{e}"),
    };
    let vierge = bifrost_evasion::MemoireReseau::vierge();
    let memoire = match &cle {
        Ok(cle) => {
            println!("reseau: {}", cle.as_str());
            carnet.souvenir(cle).unwrap_or(&vierge)
        }
        Err(e) => {
            // Ne pas savoir ou l'on est n'est pas une panne: c'est un reseau
            // sans souvenir possible, donc un sondage de plus. Le dire.
            println!("reseau: NON IDENTIFIE - {e}");
            &vierge
        }
    };

    let decision = bifrost_evasion::sondage(memoire, aujourd_hui);
    match &decision {
        bifrost_evasion::Sondage::Inutile { technique, quand } if !quand_meme => {
            println!(
                "\nAUCUNE SONDE EMISE: {} a marche ici le {:?}. Sonder lancerait six sondes\npour reapprendre ce que le carnet sait deja. --sonder-quand-meme force la mesure.",
                technique.nom(),
                quand
            );
            return plan_du_reseau(pays, None, memoire, aujourd_hui);
        }
        bifrost_evasion::Sondage::Inutile { technique, .. } => {
            println!(
                "\nle carnet dispensait de sonder ({} a marche ici), --sonder-quand-meme passe outre.",
                technique.nom()
            );
        }
        bifrost_evasion::Sondage::Necessaire(raison) => println!("sondage necessaire: {raison}"),
    }

    let cibles = sondes::Cibles::par_defaut();

    let rapport = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async { tokio::time::timeout(sondes::BUDGET, sondes::sonder(&cibles)).await });

    let rapport = match rapport {
        Ok(r) => r,
        Err(_) => bail!(
            "budget de sondage depasse ({} s): rien n'est mesure",
            sondes::BUDGET.as_secs()
        ),
    };

    let e = &rapport.environnement;
    println!("\nmesure:");
    for (nom, m) in [
        ("tcp443_passe", e.tcp443_passe),
        ("udp_passe", e.udp_passe),
        ("ports_hauts_ouverts", e.ports_hauts_ouverts),
        ("portail_captif", e.portail_captif),
        ("quic_passe", e.quic_passe),
        ("mitm_tls", e.mitm_tls),
    ] {
        match m {
            bifrost_evasion::Mesure::Vu(v) => println!("  {nom} = {v}"),
            bifrost_evasion::Mesure::NonMesure => {}
        }
    }
    // A part, parce que ce n'est pas un booleen: c'est un taux.
    if let bifrost_evasion::Mesure::Vu(p) = e.perte_pourcent {
        println!("  perte_pourcent = {p}");
    }
    println!("non mesure:");
    for (nom, raison) in &rapport.non_mesures {
        println!("  {nom}: {raison}");
    }
    if !rapport.remarques.is_empty() {
        println!("remarques:");
        for (nom, texte) in &rapport.remarques {
            println!("  {nom}: {texte}");
        }
    }
    // Sept champs, et le denominateur se lit dans le type plutot que de se
    // recopier a la main: il valait 6 pendant tout le temps ou `perte_pourcent`
    // etait le septieme, et personne ne l'a vu.
    println!(
        "{} sonde(s) aboutie(s) sur {}",
        e.sondes_abouties(),
        bifrost_evasion::Environnement::SONDES
    );

    plan_du_reseau(pays, Some(*e), memoire, aujourd_hui)
}

/// Affiche le plan qui sort de ce qu'on sait du reseau.
///
/// `environnement` est absent quand le carnet a dispense de sonder: la
/// selection travaille alors sur un environnement vierge, ou toutes les mesures
/// valent `NonMesure`, et c'est exact. Rien n'a ete mesure, et le crate de
/// selection ne conclut rien d'une sonde qui n'a pas tourne.
///
/// L'horloge est lue au bord, par l'appelant, et passee a une politique qui
/// reste pure.
fn plan_du_reseau(
    pays: Pays,
    environnement: Option<bifrost_evasion::Environnement>,
    memoire: &bifrost_evasion::MemoireReseau,
    aujourd_hui: bifrost_evasion::Date,
) -> anyhow::Result<()> {
    let environnement = environnement.unwrap_or_default();
    for mode in [
        bifrost_evasion::Mode::Auto,
        bifrost_evasion::Mode::Discret,
        bifrost_evasion::Mode::Rapide,
    ] {
        let plan = bifrost_evasion::planifier(&bifrost_evasion::Contexte {
            pays,
            environnement,
            mode,
            memoire,
            aujourd_hui,
        });
        println!("\nplan {mode:?} ({pays:?}, {aujourd_hui:?}):");
        if plan.est_sans_issue() {
            println!("  AUCUN CANDIDAT. Le kill switch reste arme, la connexion echoue.");
        }
        for (i, c) in plan.candidats.iter().enumerate() {
            println!("  {}. {} - {}", i + 1, c.technique.nom(), c.pourquoi);
        }
        for (t, r) in &plan.ecartes {
            println!("  ecarte {} - {}", t.nom(), r.motif());
        }
        // Ce que le plan IMPLIQUE, et non seulement ce qu'il prefere.
        //
        // Cette ligne repond a "que ferait-on du MEILLEUR candidat". Le flux de
        // connexion, lui, pose l'autre question: l'utilisateur arrive avec un
        // profil, donc avec UNE technique, et la selection l'arbitre par
        // `demarche_arbitree`. Les deux se lisent ensemble: ci-dessous les
        // ecartes disent quel profil serait refuse ici, et cette ligne dit ce
        // que le plan aurait prefere qu'on ait.
        println!(
            "  demarche: {}",
            decrire_demarche(&bifrost_evasion::demarche(&plan))
        );
        println!("  course: {}", decrire_course(&plan));
    }
    Ok(())
}

/// Ce que la course ferait de ce plan, en une ligne.
///
/// Le partage qui compte est celui du COUT: une technique sans coeur ne demande
/// rien de plus au daemon, une technique a coeur exige qu'il ait ete demarre
/// avec `--coeurs-dans` et `--facade`, et que le coeur retenu sache rendre un
/// profil - ce que seul sing-box fait, cf. `supervisor::refus`. Un plan de cinq
/// techniques dont une seule se monte sur ce daemon-ci n'est pas un plan de
/// cinq techniques, et la difference ne se voit nulle part ailleurs.
/// La politique de demarrage que cette ligne de commande demande.
///
/// Un seul endroit, et ce n'est pas de l'esthetique: elle etait construite a
/// l'identique en trois points, et `overlay_cgnat` est desormais l'INVERSE de
/// son drapeau. Trois copies auraient donne trois occasions d'oublier la
/// negation, et l'oubli aurait ferme la plage CGNAT en silence - donc rendu
/// une machine distante injoignable au redemarrage suivant, sans que rien dans
/// la sortie ne le laisse voir.
#[cfg(windows)]
fn politique_demarrage(args: &Args) -> bifrost_core::demarrage::PolitiqueDemarrage {
    bifrost_core::demarrage::PolitiqueDemarrage {
        reseau_local: args.demarrage_reseau_local,
        overlay_cgnat: !args.demarrage_sans_overlay,
        ipv6: args.demarrage_ipv6,
    }
}

fn decrire_course(plan: &bifrost_evasion::Plan) -> String {
    use bifrost_daemon::supervisor::refus_de_coeur;
    use bifrost_evasion::{Demarche, Pas};

    let mut course = match bifrost_evasion::Course::nouvelle(plan) {
        Ok(c) => c,
        Err(raison) => return raison,
    };
    // On deroule la course a sec: chaque candidat distribue est note lancable ou
    // non, et declare en echec pour que la course passe au suivant. Rien n'est
    // emis, c'est le plan qu'on lit, pas le reseau.
    let (mut sans_coeur, mut par_coeur, mut refuses) = (Vec::new(), Vec::new(), Vec::new());
    loop {
        match course.prochain_pas(std::time::Duration::ZERO) {
            Pas::Lancer(t) => {
                match Demarche::pour(t) {
                    Demarche::TunnelDirect(_) => sans_coeur.push(t.nom().to_owned()),
                    // Le MEME predicat que le flux de connexion applique, et
                    // non une liste recopiee ici: le jour ou un generateur
                    // arrive, cet affichage suit sans qu'on y pense. Une liste
                    // recopiee, elle, aurait vieilli en silence - c'est
                    // exactement ce qui vient d'arriver a la phrase "seul
                    // sing-box porte un profil", restee vraie alors que la
                    // technique par defaut avait change de coeur.
                    Demarche::ParCoeur { coeur, .. } => match refus_de_coeur(coeur) {
                        None => par_coeur.push(t.nom().to_owned()),
                        Some(_) => refuses.push(format!("{} ({})", t.nom(), coeur.executable())),
                    },
                    // `Demarche::pour` traduit UNE technique et ne rend que les
                    // deux formes ci-dessus; les trois autres decrivent un plan
                    // entier. Cette branche ne peut donc pas se prendre. La
                    // laisser muette ferait disparaitre le candidat du compte,
                    // et un compte faux est pire qu'un compte bruyant.
                    autre => refuses.push(format!("{} (demarche inattendue: {autre:?})", t.nom())),
                }
                course.noter_echec(
                    t,
                    bifrost_evasion::Echec::NonLancable("deroulement a sec".to_owned()),
                );
            }
            Pas::Patienter(_) => {}
            Pas::Etabli(_) | Pas::Epuisee => break,
        }
    }
    let total = sans_coeur.len() + par_coeur.len() + refuses.len();
    if total == 0 {
        return "aucun candidat: la connexion echoue, kill switch arme".to_owned();
    }
    let liste = |v: Vec<String>| {
        if v.is_empty() {
            "aucun".to_owned()
        } else {
            v.join(", ")
        }
    };
    format!(
        "{total} candidat(s) dont {} montable(s) sur ce daemon, au plus {} en vol, gigue {}-{} ms. Sans coeur: {}. Par coeur (daemon demarre avec --coeurs-dans et --facade): {}. Sans generateur de configuration, donc refuses a la connexion: {}",
        sans_coeur.len() + par_coeur.len(),
        plan.parallelisme_max,
        plan.jitter.0.as_millis(),
        plan.jitter.1.as_millis(),
        liste(sans_coeur),
        liste(par_coeur),
        liste(refuses),
    )
}

/// La demarche en une ligne, avec ce qui manque encore pour la suivre.
fn decrire_demarche(d: &bifrost_evasion::Demarche) -> String {
    use bifrost_evasion::Demarche;
    match d {
        Demarche::PortailDAbord => {
            "franchir le portail captif avant toute tentative; enchainer les protocoles devant lui n'emettrait qu'une rafale".to_owned()
        }
        Demarche::TunnelDirect(t) => format!(
            "monter le tunnel {} directement, sans coeur tiers",
            t.nom()
        ),
        // Le refus est un SUFFIXE et ne remplace pas la phrase. Ce verbe
        // decrit un plan, pas une connexion: sans profil sous la main, dire
        // "REFUSE" tout court affirmerait plus que ce qui est su. Ce qui est
        // su, c'est que ce daemon-ci ne saurait pas la suivre.
        Demarche::ParCoeur { technique, coeur } => {
            match bifrost_daemon::supervisor::refus_de_coeur(*coeur) {
                None => format!(
                    "lancer {} pour {}, sous le compte dedie et exempte AVANT qu'il ne tourne",
                    coeur.executable(),
                    technique.nom()
                ),
                Some(raison) => format!(
                    "lancer {} pour {} - mais ce daemon le REFUSERAIT: {}",
                    coeur.executable(),
                    technique.nom(),
                    raison
                ),
            }
        }
        Demarche::Ecartee { motifs } => format!(
            "ecarter {}. Un profil qui ne proposerait que cela se verrait refuser ici",
            motifs
                .iter()
                .map(|(t, r)| format!("{} ({})", t.nom(), r.motif()))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Demarche::SansIssue => {
            "aucun candidat: refuser la connexion, kill switch arme. Echouer garde est le bon echec".to_owned()
        }
    }
}

/// Lit l'horloge du systeme et la ramene a une date civile.
///
/// Seul endroit du chemin de selection qui touche a l'heure. Tout ce qui suit
/// la recoit en argument, et reste donc testable a une date choisie.
fn aujourd_hui() -> anyhow::Result<bifrost_evasion::Date> {
    bifrost_daemon::carnet::aujourd_hui().map_err(anyhow::Error::msg)
}

async fn run(args: Args) -> anyhow::Result<()> {
    // Avant tout ce qui peut lancer un processus. Le coeur tiers et le
    // resolveur chiffre ne doivent jamais survivre au daemon, et le code
    // d'arret ne suffit pas: il ne tourne pas quand le daemon est tue. La
    // garde demande la garantie au systeme, et inscrire le daemon LUI-MEME
    // fait entrer chaque enfant dans le job a sa naissance - donc sans la
    // fenetre qu'une inscription apres coup laisserait ouverte.
    #[cfg(windows)]
    bifrost_daemon::anti_orphelin::armer_pour_le_processus().context("garde anti-orphelin")?;

    let firewall = bifrost_firewall::new().context("initialisation du kill switch")?;
    let tunnel = bifrost_daemon::tunnel::new().context("initialisation du device tunnel")?;
    let dns = bifrost_dns::new().context("initialisation du DNS")?;

    tracing::info!(
        firewall = firewall.backend(),
        dns = dns.backend(),
        "backends charges"
    );

    // Annoncee et pas seulement retenue: un filtre qui designe la mauvaise
    // identite se pose sans erreur, ne matche jamais, et le daemon se retrouve
    // incapable de joindre son endpoint une fois le kill switch arme. La ligne
    // ci-dessous est ce qui permet de le voir avant.
    #[cfg(windows)]
    match bifrost_firewall::windows::identite_courante() {
        Ok((sid, service)) => tracing::info!(
            %sid,
            sid_de_service = service,
            "identite retenue pour ALE_USER_ID"
        ),
        Err(e) => tracing::warn!(error = %e, "identite ALE_USER_ID illisible"),
    }

    // Un compte declare mais introuvable fait echouer le demarrage, il ne
    // degrade pas en silence. Retomber sur "aucune exemption" donnerait un
    // daemon qui parait sain et un coeur que le kill switch etrangle des qu'il
    // demarre, sans que rien ne relie les deux.
    let coeur = identite_du_coeur(&args)?;
    if coeur.est_vide() {
        tracing::info!(
            "aucun compte de coeur declare: le kill switch ne posera aucune \
             exemption. Voir --coeur-utilisateur."
        );
    } else {
        tracing::info!(
            uid = ?coeur.utilisateur.map(|u| u.uid),
            executable = ?coeur.executable,
            "identite du coeur retenue pour l'exemption et pour le lancement"
        );
    }

    // Meme discipline, sens inverse. Un compte de resolveur introuvable fait
    // aussi echouer le demarrage: retomber en silence sur "aucune restriction"
    // rendrait un daemon qui parait durci et un :53 grand ouvert dans le
    // tunnel, ce qui est exactement la situation que ce drapeau ferme.
    let resolveur = identite_du_resolveur(&args)?;
    if resolveur.est_vide() {
        tracing::info!(
            "aucun resolveur chiffre declare: le :53 continue de circuler dans \
             le tunnel. Voir --resolveur-utilisateur et --resolveur-binaire."
        );
    } else {
        // Les DEUX champs, et le message qui dit lequel compte ou. Annoncer
        // "le :53 ne sortira plus que par lui" sur la foi du seul champ que la
        // plateforme courante n'utilise pas serait un journal qui ment: sous
        // Linux la restriction se rend depuis l'UID, sous Windows depuis le
        // chemin du binaire.
        tracing::info!(
            uid = ?resolveur.utilisateur.map(|u| u.uid),
            executable = ?resolveur.executable,
            "identite du resolveur retenue. Linux restreint le :53 par l'UID, \
             Windows par le chemin: un champ vide ne restreint rien sur la \
             plateforme qui le lit."
        );
    }
    let atelier = atelier_du_resolveur(&args);
    if let Some(a) = &atelier {
        tracing::info!(
            programme = %a.programme.display(),
            configuration = %a.configuration.display(),
            etat = %a.etat.display(),
            "resolveur chiffre embarque: binaire designe"
        );
    }
    let resolveur = Resolveur::nouveau(resolveur, atelier);

    // Le superviseur possede les ressources privilegiees et tourne sur son
    // propre thread: les appels netlink et WFP sont bloquants.
    let (tx, rx) = mpsc::channel::<Cmd>();
    // Ce qui alimente la selection et ne change pas d'une connexion a l'autre.
    // La demarche, elle, se calcule dans `connect`: elle depend du profil qu'on
    // recoit, donc elle ne peut pas etre arretee ici.
    //
    // L'environnement part VIERGE. Aucune mesure n'est faite sur le chemin de
    // connexion, et c'est delibere: la regle de la selection est que seule une
    // mesure elimine, donc un environnement vierge n'ecarte rien et ne peut pas
    // refuser a tort. Voir `Decision::environnement` pour l'etat de l'art qui
    // deconseille de sonder avant de choisir.
    let decision = bifrost_daemon::supervisor::Decision {
        pays: args.pays.into(),
        ..Default::default()
    };
    // L'atelier des coeurs vit sur le runtime, le superviseur de tunnel sur un
    // fil systeme ordinaire. Les deux ne se parlent que par ce canal: donner un
    // handle de runtime au superviseur lui permettrait d'appeler n'importe quel
    // code asynchrone depuis n'importe ou, et la separation que le document 06
    // demande n'existerait plus que par discipline.
    let (poignee_atelier, coeur_actif, atelier) = bifrost_daemon::coeurs::atelier::ouvrir();
    // Cloner AVANT: la facade consomme le sien, et le peripherique par coeur a
    // besoin du meme signal pour savoir si le coeur tient toujours.
    let suivre_le_coeur = coeur_actif.clone();
    tokio::spawn(atelier);

    // La facade n'est ouverte que si on la demande. Un produit de securite
    // n'ouvre pas une ecoute locale par defaut: tant que rien ne route le
    // systeme vers elle, elle n'aurait pas d'usage et serait une surface de
    // plus. Elle ferme d'ailleurs toute connexion tant qu'aucun coeur ne
    // tourne, ce qui est l'etat correct et se verifie.
    //
    // L'adresse REELLEMENT liee est retenue, et non celle qui a ete demandee:
    // un port 0 en argument est legitime, et c'est le systeme qui tranche.
    // C'est vers elle que le passeur menera.
    let mut adresse_facade = None;
    if let Some(ecoute) = args.facade {
        match bifrost_daemon::coeurs::facade::ouvrir(ecoute, coeur_actif).await {
            Ok((adresse, facade)) => {
                tracing::info!(%adresse, "facade ouverte: adresse stable vers le coeur actif");
                adresse_facade = Some(adresse);
                tokio::spawn(facade.servir());
            }
            Err(e) => {
                tracing::error!(erreur = %e, %ecoute, "facade non ouverte");
                anyhow::bail!("facade non ouverte sur {ecoute}: {e}");
            }
        }
    }

    let chemin_coeur = chemin_par_coeur(&args, adresse_facade, &coeur, suivre_le_coeur)?;

    let supervisor = Supervisor::new(
        firewall,
        tunnel,
        dns,
        coeur,
        resolveur,
        bifrost_daemon::supervisor::Equipement {
            decision,
            carnetier: bifrost_daemon::supervisor::Carnetier::default(),
            atelier: Some(poignee_atelier),
            chemin_coeur,
        },
    );
    let handle = std::thread::Builder::new()
        .name("bifrost-supervisor".into())
        .spawn(move || supervisor.run(rx))?;

    // Reaffirmer la politique a chaque reprise. L'abonnement doit vivre aussi
    // longtemps que le daemon: le laisser tomber ici couperait les
    // notifications sans un mot.
    //
    // Un echec n'arrete pas le daemon, mais il n'est pas tu non plus: une
    // reprise cesserait alors d'etre signalee, et le seul moyen de le savoir
    // apres coup est cette ligne de journal.
    #[cfg(windows)]
    let _reprise = match bifrost_daemon::reprise::brancher(tx.clone()) {
        Ok(a) => Some(a),
        Err(e) => {
            tracing::warn!(
                erreur = %e,
                "reprises apres veille non signalees: la politique ne sera pas \
                 reposee au reveil"
            );
            None
        }
    };

    let policy = server::auth_policy(args.group.as_deref());
    let gid = policy.allowed_gid;
    let ipc = bifrost_ipc::IpcServer::bind(&args.socket, policy, gid)
        .await
        .with_context(|| format!("ecoute sur {}", args.socket))?;

    let shutdown_tx = tx.clone();
    tokio::select! {
        result = server::serve(ipc, tx, args.profil.clone()) => {
            result?;
        }
        _ = shutdown_signal() => {
            tracing::info!("signal d'arret recu");
        }
    }

    let _ = shutdown_tx.send(Cmd::Shutdown);
    let _ = handle.join();
    Ok(())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "SIGTERM non ecoutable");
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        tokio::select! {
            _ = term.recv() => {}
            _ = tokio::signal::ctrl_c() => {}
        }
    }
    #[cfg(not(unix))]
    {
        // En console, seul Ctrl-C arrive. Sous le gestionnaire de services,
        // seul le canal d'arret arrive. Attendre les deux evite d'avoir deux
        // chemins d'arret a maintenir.
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = bifrost_daemon::service::scm::attendre_arret() => {}
        }
    }
}

fn filtre_de_journalisation() -> tracing_subscriber::EnvFilter {
    tracing_subscriber::EnvFilter::try_from_env("BIFROST_LOG").unwrap_or_else(|_| {
        tracing_subscriber::EnvFilter::new(
            "bifrost_daemon=info,bifrost_firewall=info,bifrost_dns=info,bifrost_ipc=info",
        )
    })
}

/// `vers_fichier` vaut pour le mode service, qui n'a pas de sortie standard.
///
/// Sans ca, un service qui refuse de demarrer ne laisse aucune trace, ce qui
/// est precisement le moment ou on en a besoin. En cas d'echec d'ouverture du
/// fichier on retombe sur la sortie standard: refuser de demarrer parce que le
/// journal est indisponible serait pire que de demarrer sans journal.
fn init_tracing(vers_fichier: bool) {
    let fichier = if vers_fichier {
        journal_de_service()
    } else {
        None
    };
    match fichier {
        Some(f) => tracing_subscriber::fmt()
            .with_env_filter(filtre_de_journalisation())
            .with_target(true)
            // Un fichier ne rend pas les sequences de couleur.
            .with_ansi(false)
            .with_writer(move || {
                f.try_clone()
                    .expect("clonage du descripteur du journal de service")
            })
            .init(),
        None => tracing_subscriber::fmt()
            .with_env_filter(filtre_de_journalisation())
            .with_target(true)
            // Meme regle qu'au-dessus, et elle vaut aussi ici: la sortie
            // standard d'un daemon finit presque toujours dans un fichier ou
            // dans un journal de service. `tracing_subscriber` colore sans
            // regarder ou il ecrit, et le resultat est un journal dont chaque
            // ligne porte des sequences d'echappement qu'aucun `grep` ne veut.
            .with_ansi(std::io::stdout().is_terminal())
            .init(),
    }
}

/// Pose la sonde d'identite depuis le service, et journalise ses mesures.
///
/// Repond a la seule question que la sonde en console ne peut pas poser: un
/// filtre portant le SID de SERVICE laisse-t-il passer le trafic de ce service,
/// et bloque-t-il tout le reste? En console le token n'a pas de SID de service,
/// donc la sonde y mesure l'identite d'utilisateur, ce qui est une autre
/// question.
#[cfg(windows)]
fn sonde_identite_en_service() -> anyhow::Result<()> {
    use bifrost_core::ports::KillSwitch;
    use bifrost_daemon::wfp_identity::{Issue, juger, mesurer_tout};

    let (sid, service) =
        bifrost_firewall::windows::identite_courante().map_err(anyhow::Error::msg)?;
    tracing::info!(%sid, sid_de_service = service, "identite sous laquelle la sonde tourne");
    if !service {
        tracing::warn!(
            "aucun SID de service dans le token: la sonde va mesurer l'identite \
             d'utilisateur, pas celle du service. Verifier que le service a bien \
             ete installe avec SERVICE_SID_TYPE_UNRESTRICTED."
        );
    }

    let mut fw = bifrost_firewall::windows::WfpKillSwitch::new().map_err(anyhow::Error::msg)?;

    // La sonde se retire en appelant `disengage`, qui purge TOUS les objets de
    // Bifrost. Si un kill switch etait deja arme, elle le demonterait et
    // rouvrirait le trafic. Refuser plutot que de faire ca.
    if fw.is_engaged().map_err(anyhow::Error::msg)? {
        anyhow::bail!(
            "des filtres Bifrost sont deja poses: la sonde les retirerait en se \
             retirant elle-meme, ce qui rouvrirait le trafic. Refus."
        );
    }

    let m = mesurer_tout(&mut fw)?;
    tracing::info!(
        daemon = ?m.daemon,
        temoin = ?m.temoin,
        mutation = ?m.mute,
        "mesures de la sonde d'identite"
    );
    match juger(m) {
        Issue::Reussi => {
            tracing::info!(
                %sid,
                "le filtre designe bien ce service: il passe, la copie est \
                 bloquee, la mutation aussi"
            );
            Ok(())
        }
        Issue::Ignore(raison) => {
            tracing::warn!(%raison, "sonde d'identite sans conclusion");
            Ok(())
        }
        Issue::Echec(raison) => {
            tracing::error!(%raison, "sonde d'identite en echec");
            anyhow::bail!(raison)
        }
    }
}

#[cfg(windows)]
fn journal_de_service() -> Option<std::fs::File> {
    let base = std::env::var_os("ProgramData")?;
    let chemin = bifrost_daemon::service::spec::chemin_journal(std::path::Path::new(&base));
    std::fs::create_dir_all(chemin.parent()?).ok()?;
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&chemin)
        .ok()
}

#[cfg(not(windows))]
fn journal_de_service() -> Option<std::fs::File> {
    // Sous Linux le daemon tourne sous systemd, qui capte la sortie standard.
    None
}

/// Le daemon manipule nftables, WFP, les routes et les interfaces: sans
/// privileges il echouerait plus tard, au pire moment, avec le kill switch a
/// moitie pose. Autant refuser de demarrer.
/// Les trois commandes de la couche 1 anti-telemetrie.
///
/// Le code de sortie ne vaut 1 que si une ligne est en ECHEC, c'est-a-dire
/// ecrite puis relue differente. SANS OBJET et REFUSE sont des mesures qui
/// n'ont pas eu lieu et qui disent pourquoi: les compter comme des echecs
/// ferait rougir une machine saine, les compter comme des succes ferait
/// exactement l'inverse.
#[cfg(windows)]
fn telemetrie_reseau_commande(args: &Args) -> anyhow::Result<()> {
    use bifrost_daemon::telemetrie_reseau;

    if let Some(sid) = &args.telemetrie_sonde_sid {
        let poses = telemetrie_reseau::sonder_sid(sid)?;
        println!("sonde posee sur {sid}: {poses} filtre(s) dans le moteur");
        println!(
            "Ceci est un DIAGNOSTIC, pas une protection. A retirer par \
             --telemetrie-reseau-retirer."
        );
        // Zero filtre pose est un echec silencieux: la commande a l'air d'avoir
        // marche et rien n'a ete mesure.
        std::process::exit(if poses > 0 { 0 } else { 1 });
    }

    if let Some(binaire) = &args.telemetrie_sonde_binaire {
        let poses = telemetrie_reseau::sonder_binaire(binaire)?;
        println!(
            "sonde posee sur {}: {poses} filtre(s) dans le moteur",
            binaire.display()
        );
        println!(
            "Ceci est un DIAGNOSTIC, pas une protection. A retirer par \
             --telemetrie-reseau-retirer."
        );
        // Meme raison qu'au-dessus: zero filtre pose est un echec silencieux.
        std::process::exit(if poses > 0 { 0 } else { 1 });
    }

    let profil =
        bifrost_telemetrie::profil_depuis_nom(&args.telemetrie_profil).ok_or_else(|| {
            anyhow::anyhow!(
                "--telemetrie-profil {:?} inconnu. Attendu: {}",
                args.telemetrie_profil,
                bifrost_telemetrie::catalogue::NOMS_DE_PROFIL.join(", ")
            )
        })?;

    if args.telemetrie_reseau_retirer {
        let restants = telemetrie_reseau::retirer()?;
        println!("couche 2 retiree, {restants} filtre(s) restant(s) dans le moteur");
        // Un seul filtre restant est un echec, pas un detail: le retrait est la
        // sortie de secours, et une sortie de secours qui laisse quelque chose
        // derriere elle n'en est pas une.
        std::process::exit(if restants == 0 { 0 } else { 1 });
    }

    if args.telemetrie_reseau_etat {
        print!("{}", telemetrie_reseau::etat(profil).en_clair());
        return Ok(());
    }

    let rapport = telemetrie_reseau::appliquer(profil)?;
    print!("{}", rapport.en_clair());
    Ok(())
}

#[cfg(windows)]
fn telemetrie_commande(args: &Args) -> anyhow::Result<()> {
    use bifrost_daemon::telemetrie;

    let profil =
        bifrost_telemetrie::profil_depuis_nom(&args.telemetrie_profil).ok_or_else(|| {
            anyhow::anyhow!(
                "--telemetrie-profil {:?} inconnu. Attendu: {}",
                args.telemetrie_profil,
                bifrost_telemetrie::catalogue::NOMS_DE_PROFIL.join(", ")
            )
        })?;

    if args.telemetrie_restaurer {
        let rapport =
            telemetrie::restaurer(&args.telemetrie_journal).map_err(|e| anyhow::anyhow!(e))?;
        rapport.imprimer();
        println!(
            "
{} rendu(s), {} refuse(s), {} echec(s)",
            rapport.compte("POSE"),
            rapport.compte("REFUSE"),
            rapport.compte("ECHEC")
        );
        std::process::exit(rapport.code());
    }

    if args.telemetrie_etat {
        let rapport = telemetrie::etat(profil);
        rapport.imprimer();
        println!(
            "
{} deja conforme(s), {} a poser, {} hors portee, {} sans objet",
            rapport.compte("DEJA"),
            rapport.compte("A POSER"),
            rapport.compte("REFUSE"),
            rapport.compte("SANS OBJET")
        );
        return Ok(());
    }

    // La date et la build entrent dans le journal: le moteur de derive en aura
    // besoin, une mise a jour de fonctionnalite changeant le numero de build ET
    // remettant DiagTrack en automatique.
    let pose_le = horodatage();
    let build = telemetrie::build_du_systeme();
    let rapport = telemetrie::appliquer(profil, &args.telemetrie_journal, &pose_le, &build)
        .map_err(|e| anyhow::anyhow!(e))?;
    rapport.imprimer();
    println!(
        "
{} pose(s), {} deja conforme(s), {} refuse(s), {} sans objet, {} echec(s)",
        rapport.compte("POSE"),
        rapport.compte("DEJA"),
        rapport.compte("REFUSE"),
        rapport.compte("SANS OBJET"),
        rapport.compte("ECHEC")
    );
    println!("journal: {}", args.telemetrie_journal.display());
    std::process::exit(rapport.code());
}

/// L'instant present, en secondes depuis l'epoque, en toutes lettres.
///
/// Pas de dependance de mise en forme de date pour une ligne de journal: le
/// depot n'en a aucune, et en ajouter une pour cela seul serait cher.
#[cfg(windows)]
fn horodatage() -> String {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => format!("{}s depuis l'epoque Unix", d.as_secs()),
        Err(_) => "horloge anterieure a l'epoque Unix".to_owned(),
    }
}

fn ensure_privileged() -> anyhow::Result<()> {
    #[cfg(unix)]
    // SAFETY: geteuid ne prend pas d'argument et ne touche aucune memoire.
    if unsafe { libc::geteuid() } != 0 {
        bail!(
            "bifrost-daemon doit tourner en root: il configure nftables, les \
             routes et l'interface du tunnel"
        );
    }
    #[cfg(windows)]
    if !is_elevated() {
        bail!(
            "bifrost-daemon doit tourner avec les privileges administrateur: \
             il pose des filtres WFP via la Base Filtering Engine"
        );
    }
    Ok(())
}

#[cfg(windows)]
fn is_elevated() -> bool {
    use std::mem::size_of;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{
        GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    // SAFETY: on ouvre le token du processus courant, on lit un champ de taille
    // connue, et on referme le handle dans tous les chemins de sortie.
    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut size = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            &mut elevation as *mut _ as *mut std::ffi::c_void,
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut size,
        );
        CloseHandle(token);
        ok != 0 && elevation.TokenIsElevated != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    /// La plage CGNAT est ouverte au demarrage sauf demande contraire.
    ///
    /// Le drapeau est le seul des trois a etre inverse, et l'affirmation porte
    /// sur l'EXEMPTION PRODUITE, pas sur le booleen. Une recette qui lirait le
    /// champ verifierait qu'une negation est ecrite la ou elle est ecrite;
    /// celle-ci verifie que la plage passe vraiment.
    ///
    /// Motif de l'arbitrage: toute la flotte qui exploite ce daemon est
    /// administree par un reseau overlay. Un verrou de demarrage sans cette
    /// exemption rend la machine injoignable et impose un deplacement, mode de
    /// panne deja rencontre sur le banc.
    #[cfg(windows)]
    #[test]
    fn la_plage_cgnat_reste_ouverte_au_demarrage_sauf_demande_contraire() {
        use bifrost_core::demarrage::{Famille, PolitiqueDemarrage};
        use clap::Parser;

        let ouverte = |p: PolitiqueDemarrage| {
            p.exemptions()
                .iter()
                .filter(|e| e.etiquette == "reseau overlay")
                .count()
        };

        // Sans rien demander: la plage passe, dans les deux sens.
        let par_defaut = politique_demarrage(&Args::parse_from(["bifrost-daemon"]));
        assert_eq!(
            ouverte(par_defaut),
            2,
            "la plage CGNAT doit passer par defaut, sortant et entrant"
        );
        assert!(
            par_defaut
                .exemptions()
                .iter()
                .any(|e| e.etiquette == "reseau overlay" && e.famille == Famille::V4),
            "l'exemption overlay porte sur IPv4"
        );

        // Les deux autres options restent, elles, fermees par defaut.
        assert!(!par_defaut.reseau_local, "le reseau local reste ferme");
        assert!(!par_defaut.ipv6, "IPv6 reste bloque en entier");

        // Et le drapeau la ferme.
        let ferme = politique_demarrage(&Args::parse_from([
            "bifrost-daemon",
            "--demarrage-sans-overlay",
        ]));
        assert_eq!(
            ouverte(ferme),
            0,
            "--demarrage-sans-overlay doit retirer l'exemption"
        );

        // Le TYPE, lui, reste tout ferme: l'arbitrage appartient a la ligne de
        // commande. Un appelant programmatique qui oublie un champ doit
        // obtenir le strict.
        assert_eq!(
            ouverte(PolitiqueDemarrage::default()),
            0,
            "PolitiqueDemarrage::default() doit rester la politique la plus stricte"
        );
    }

    /// Un plan de cinq techniques dont trois se montent n'est pas un plan de
    /// cinq techniques.
    ///
    /// Cette recette existe parce que l'affichage a menti. Le 21 aout 2026,
    /// `--sonder-reseau` annoncait sous "Par coeur" les quatre techniques a
    /// coeur du plan Auto, dont `xhttp-cdn` et `amneziawg` que le flux de
    /// connexion refuse faute de generateur de configuration. La seule mise en
    /// garde etait une phrase dans le libelle, "seul sing-box porte un profil",
    /// que la liste juste apres contredisait. Le compte, lui, etait faux sans
    /// reserve.
    #[test]
    fn une_course_nomme_les_candidats_que_ce_daemon_ne_saurait_pas_monter() {
        use bifrost_evasion::{Technique, selection};

        let ligne = decrire_course(&bifrost_evasion::Plan {
            candidats: [
                Technique::RealityVision,
                Technique::XhttpCdn,
                Technique::Hysteria2,
                Technique::AmneziaWg,
                Technique::WireGuardNu,
            ]
            .into_iter()
            .map(|technique| bifrost_evasion::selection::Candidat {
                technique,
                pourquoi: "recette",
            })
            .collect(),
            ecartes: Vec::new(),
            portail_a_franchir: false,
            parallelisme_max: selection::PARALLELISME_MAX,
            jitter: (selection::JITTER_MIN, selection::JITTER_MAX),
        });

        assert!(
            ligne.contains("5 candidat(s) dont 3 montable(s)"),
            "le compte doit distinguer le plan de ce que CE daemon sait suivre: {ligne}"
        );
        assert!(ligne.contains("Sans coeur: wireguard-nu"), "{ligne}");
        assert!(
            ligne.contains("Par coeur (daemon demarre avec --coeurs-dans et --facade): vless-reality-vision, hysteria2"),
            "les deux techniques que sing-box porte, et elles seules: {ligne}"
        );
        assert!(
            ligne.contains("refuses a la connexion: xhttp-cdn (xray), amneziawg (amneziawg-go)"),
            "les refuses sont NOMMES avec leur coeur, pas passes sous silence: {ligne}"
        );
    }

    /// La demarche d'un candidat sans generateur ne se presente pas comme
    /// suivable.
    ///
    /// Le refus est un suffixe et non un remplacement: `--sonder-reseau` n'a
    /// pas de profil sous la main, donc il ne peut pas affirmer que la
    /// connexion echouerait, seulement que ce daemon-ci ne saurait pas suivre.
    #[test]
    fn une_demarche_par_coeur_sans_generateur_annonce_le_refus() {
        use bifrost_evasion::{Demarche, Technique};

        let sans_generateur = decrire_demarche(&Demarche::pour(Technique::XhttpCdn));
        assert!(sans_generateur.contains("xray"), "{sans_generateur}");
        assert!(
            sans_generateur.contains("REFUSERAIT"),
            "un candidat que ce daemon ne sait pas monter doit le dire: {sans_generateur}"
        );

        // Le temoin: la technique par defaut, elle, se suit sans reserve.
        let portee = decrire_demarche(&Demarche::pour(Technique::RealityVision));
        assert!(portee.contains("lancer sing-box"), "{portee}");
        assert!(
            !portee.contains("REFUSERAIT"),
            "sing-box porte un profil, rien ne doit etre ajoute: {portee}"
        );
    }

    /// Chaque option longue porte sa propre aide.
    ///
    /// Ce test existe parce que le cas s'est produit, deux fois de suite:
    /// inserer un champ entre un commentaire de documentation et le champ qu'il
    /// decrivait fait passer l'aide sur le nouveau voisin, et l'option d'origine
    /// se retrouve sans aide. Rien ne le signale - pour clap, un champ sans
    /// documentation est simplement un champ sans aide, ce qui est un etat
    /// parfaitement legal. Seule une option qui SAIT qu'elle doit en avoir une
    /// peut s'en plaindre.
    fn adr(s: &str) -> std::net::SocketAddr {
        s.parse().unwrap()
    }

    /// Le defaut qui rendait la panne illisible.
    ///
    /// Mesure le 20 aout 2026 en montant le banc de bascule: `--facade
    /// 127.0.0.1:1080` contre le defaut de `--coeur-socks-port`, lui aussi
    /// 1080. Le daemon demarre, la facade prend le port, le kill switch
    /// s'arme, et c'est le COEUR qui echoue a la premiere connexion, avec un
    /// message qui accuse sing-box: "FATAL start inbound/socks[entree]: listen
    /// tcp 127.0.0.1:1080: bind: address already in use". Rien dans cette
    /// phrase ne designe les deux drapeaux qui se disputent le port, ni le fait
    /// que le conflit etait connu des le demarrage.
    #[test]
    fn deux_ecoutes_locales_sur_le_meme_port_sont_refusees_au_demarrage() {
        let raison = conflit_d_ecoute(Some(adr("127.0.0.1:1080")), 1080, 9090)
            .expect("la facade et le port SOCKS du coeur se disputent 1080");
        assert!(raison.contains("--facade"), "{raison}");
        assert!(raison.contains("--coeur-socks-port"), "{raison}");
        assert!(raison.contains("1080"), "{raison}");
    }

    #[test]
    fn le_port_de_l_api_du_coeur_compte_aussi() {
        let raison = conflit_d_ecoute(None, 9090, 9090)
            .expect("le coeur ne peut pas servir son SOCKS et son API sur un port");
        assert!(raison.contains("--coeur-socks-port"), "{raison}");
        assert!(raison.contains("--coeur-api-port"), "{raison}");
        let raison = conflit_d_ecoute(Some(adr("127.0.0.1:9090")), 1080, 9090)
            .expect("la facade et l'API du coeur se disputent 9090");
        assert!(raison.contains("--coeur-api-port"), "{raison}");
    }

    /// Une ecoute qui n'est pas sur la boucle prend quand meme le port de la
    /// boucle: `0.0.0.0:1080` accepte ce qui arrive sur `127.0.0.1:1080`.
    /// Le conflit est le meme, et le refuser demande de regarder l'adresse et
    /// pas seulement le port.
    #[test]
    fn une_facade_sur_toutes_les_adresses_prend_aussi_la_boucle() {
        assert!(conflit_d_ecoute(Some(adr("0.0.0.0:1080")), 1080, 9090).is_some());
        assert!(conflit_d_ecoute(Some(adr("[::]:1080")), 1080, 9090).is_some());
    }

    /// Et symetriquement: une facade posee sur une adresse precise qui n'est
    /// pas la boucle ne dispute rien au coeur. Refuser ce cas ferait un refus
    /// FAUX, ce qui est aussi mauvais qu'une panne tardive.
    #[test]
    fn une_facade_sur_une_autre_adresse_ne_dispute_rien() {
        assert_eq!(
            conflit_d_ecoute(Some(adr("192.0.2.7:1080")), 1080, 9090),
            None
        );
    }

    /// Le port zero demande au systeme d'en choisir un, et deux demandes de
    /// port zero obtiennent deux ports DIFFERENTS: elles ne se disputent donc
    /// rien. Les compter comme egales ferait un refus faux, et refuserait la
    /// seule forme qui permette a une recette de ne pas se battre pour un port
    /// avec la machine qui l'execute.
    ///
    /// La comparaison a zero est le seul endroit ou cette garde s'observe:
    /// avec un port de coeur fixe, zero ne ressemble a rien de toute facon.
    /// Premiere version de cette recette: elle comparait a 1080, restait verte
    /// sans la garde, et ne prouvait donc rien.
    #[test]
    fn deux_ports_zero_ne_se_disputent_rien() {
        assert_eq!(conflit_d_ecoute(Some(adr("127.0.0.1:0")), 0, 9090), None);
    }

    #[test]
    fn une_configuration_saine_ne_dit_rien() {
        assert_eq!(
            conflit_d_ecoute(Some(adr("127.0.0.1:1081")), 1080, 9090),
            None
        );
        assert_eq!(conflit_d_ecoute(None, 1080, 9090), None);
    }

    /// Les deux sondes posent chacune UN filtre apres avoir balaye ce qui
    /// etait la. Lancees ensemble, la seconde effacerait la premiere et la
    /// ligne de commande annoncerait deux mesures pour une seule.
    ///
    /// Le conflit n'est ecrit que sur `--telemetrie-sonde-binaire`, comme les
    /// autres drapeaux de la couche 2 n'ecrivent le leur que contre ceux qui
    /// les precedent. C'est suffisant et c'est MESURE, pas suppose: le 23 aout
    /// 2026, la declaration retiree d'un seul cote laisse cette recette verte,
    /// retiree des deux elle la fait rougir. Les conflits de clap valent donc
    /// dans les deux sens. La recette eprouve quand meme les DEUX ordres: le
    /// jour ou ce ne serait plus vrai, c'est ici qu'on l'apprendrait.
    #[cfg(windows)]
    #[test]
    fn les_deux_sondes_de_telemetrie_ne_se_lancent_pas_ensemble() {
        let paires: &[[&str; 2]] = &[
            [
                "--telemetrie-sonde-sid=S-1-5-80-1-2-3-4-5",
                "--telemetrie-sonde-binaire=C:\\x\\t.exe",
            ],
            [
                "--telemetrie-sonde-binaire=C:\\x\\t.exe",
                "--telemetrie-sonde-sid=S-1-5-80-1-2-3-4-5",
            ],
        ];
        for paire in paires {
            let issue = Args::try_parse_from(["bifrost-daemon", paire[0], paire[1]]);
            assert!(
                issue.is_err(),
                "clap accepte {} avec {}: la seconde sonde effacerait la premiere",
                paire[0],
                paire[1]
            );
        }
        // Et chacune des deux doit rester acceptee seule, sinon le conflit
        // au-dessus serait vert parce que rien ne passe.
        for seule in [
            "--telemetrie-sonde-sid=S-1-5-80-1-2-3-4-5",
            "--telemetrie-sonde-binaire=C:\\x\\t.exe",
        ] {
            Args::try_parse_from(["bifrost-daemon", seule])
                .unwrap_or_else(|e| panic!("{seule} doit rester accepte seul: {e}"));
        }
        // Et chacune conflit avec les trois commandes de la couche 2.
        for sonde in [
            "--telemetrie-sonde-sid=S-1-5-80-1-2-3-4-5",
            "--telemetrie-sonde-binaire=C:\\x\\t.exe",
        ] {
            for commande in [
                "--telemetrie-reseau-etat",
                "--telemetrie-reseau-appliquer",
                "--telemetrie-reseau-retirer",
            ] {
                assert!(
                    Args::try_parse_from(["bifrost-daemon", sonde, commande]).is_err(),
                    "clap accepte {sonde} avec {commande}"
                );
            }
        }
    }

    #[test]
    fn chaque_option_porte_sa_propre_aide() {
        let commande = Args::command();
        let muettes: Vec<String> = commande
            .get_arguments()
            .filter(|a| a.get_long().is_some())
            .filter(|a| a.get_help().is_none() && a.get_long_help().is_none())
            .map(|a| format!("--{}", a.get_long().unwrap()))
            .collect();
        assert!(
            muettes.is_empty(),
            "option(s) sans aide, probablement un commentaire capture par le voisin: {muettes:?}"
        );
    }
}
