//! Schema du dialogue daemon / client.
//!
//! Cadrage: une requete ou une reponse par ligne, en JSON. Pas de protobuf, pas
//! de gRPC: le canal est local, mono-client, et la surface d'attaque d'un
//! parseur JSON de la bibliotheque standard est plus facile a raisonner qu'une
//! pile HTTP/2 complete.

use bifrost_core::TunnelConfig;
use bifrost_core::checks::CheckReport;
use bifrost_core::state::TunnelStatus;
use serde::{Deserialize, Serialize};

/// Taille maximale d'une ligne acceptee par le serveur.
///
/// Sans cette borne, un client autorise mais bogue (ou malveillant) peut faire
/// grossir le tampon du daemon jusqu'a l'epuisement memoire en envoyant une
/// ligne sans fin.
pub const MAX_FRAME_BYTES: usize = 256 * 1024;

/// Version du protocole. Le serveur refuse un client d'une autre version
/// plutot que d'interpreter des champs qu'il ne comprend pas.
pub const PROTOCOL_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub version: u32,
    #[serde(flatten)]
    pub command: Command,
}

impl Request {
    pub fn new(command: Command) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            command,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "kebab-case")]
pub enum Command {
    /// Monte le tunnel. La config est validee par le daemon avant tout effet.
    Connect { config: Box<TunnelConfig> },
    /// Monte le tunnel decrit par le profil que le DAEMON detient.
    ///
    /// # Pourquoi une commande distincte, et surtout sans chemin
    ///
    /// Sans chemin, deliberement: le daemon tourne en root, et lui faire lire
    /// un fichier que l'appelant designe ferait de lui un depute confus. Le
    /// profil vient de sa propre ligne de commande, comme tout le reste de sa
    /// configuration.
    ///
    /// Et distincte de `Connect` plutot qu'un `Option` dedans, parce que les
    /// deux ne demandent pas la meme chose. `Connect` porte un profil que
    /// l'appelant a lu - il en connait donc les secrets. Celle-ci demande au
    /// daemon d'ouvrir le sien, que l'appelant peut ne pas savoir lire: c'est
    /// le cas d'un profil scelle, dont le dechiffrement exige le TPM donc root.
    /// La consequence est le point entier: **un membre du groupe gagne le droit
    /// de se connecter sans gagner celui de lire la cle**.
    ConnectStored,
    /// Demonte le tunnel et desarme le kill switch.
    Disconnect,
    /// Etat courant.
    Status,
    /// Execute la suite des vecteurs de fuite.
    Check,
    /// Porte au daemon le verdict d'inspection TLS mesure PAR LE CLIENT.
    ///
    /// # Pourquoi le client mesure et le daemon ecoute
    ///
    /// `bifrost-daemon/tests/frontiere_reseau.rs` interdit de lier une pile TLS
    /// au daemon: il tourne en root, en permanence, et une poignee de main TLS
    /// analyse des donnees choisies par le pair - ici, par hypothese, un
    /// equipement qui intercepte. La mesure vit donc du cote non privilegie.
    /// Restait a l'y faire arriver, et le client est deja ce processus non
    /// privilegie: le daemon n'a ni binaire a trouver, ni compte a creer, ni
    /// privilege a laisser tomber. Le faire lancer un sous-processus qui parle
    /// TLS lui redonnerait par la fenetre ce que la frontiere lui interdit par
    /// la porte.
    ///
    /// # Ce qu'un client menteur y gagne: rien
    ///
    /// Un verdict a VRAI elimine REALITY, et rien d'autre - voir
    /// `bifrost_evasion::selection::Refus::MitmTlsMesure`. Or le client choisit
    /// deja le profil: pour eviter REALITY, il lui suffit de ne pas en envoyer.
    /// Un verdict a FAUX n'elimine rien du tout, puisque seule une mesure
    /// elimine et qu'aucun refus ne se declenche sur l'absence d'interception.
    /// La commande n'accorde donc aucun pouvoir que l'appelant n'ait deja.
    ///
    /// Elle ne porte QUE le verdict conclu. Un client qui n'a rien pu mesurer
    /// n'envoie rien: transmettre son ignorance ecraserait une mesure
    /// precedente, ce qui est le seul degat que cette commande pourrait faire.
    VerdictInspectionTls { intercepte: bool },
    /// La machine sort d'une mise en veille: reposer la politique.
    ///
    /// # Pourquoi cette commande existe sous Linux et pas sous Windows
    ///
    /// Sous Windows le daemon apprend la reprise LUI-MEME, par
    /// `PowerRegisterSuspendResumeNotification`: la source est dans son propre
    /// processus et rien ne transite par l'IPC. Sous Linux, la seule voie qui
    /// n'ajoute aucune dependance est un hook `systemd-sleep`, donc un
    /// processus TIERS, lance par systemd au reveil. Il lui faut une porte, et
    /// c'est celle-ci.
    ///
    /// # Ce qu'un appelant y gagne: une transaction idempotente
    ///
    /// Elle ne porte aucun parametre, et ne peut donc rien decrire. Ce qu'elle
    /// declenche est `Event::SystemResumed`, qui ne change aucun etat et repose
    /// la politique que l'etat courant exige DEJA - dont `Disconnected`, ou
    /// elle ne pose rien du tout. Un membre du groupe qui l'enverrait en
    /// rafale couterait des transactions de pare-feu, pas une fuite ni une
    /// coupure. `Disconnect`, deja exposee, est strictement plus puissante.
    Reprise,
    /// Ce que le daemon dit avoir remis a son moteur de pare-feu, en dernier.
    ///
    /// # Pourquoi une commande a part, et pas un champ de `Status`
    ///
    /// `TunnelStatus` decrit l'etat de la machine d'etats; la politique, elle,
    /// est completee au moment d'agir (identite du coeur, restriction du
    /// resolveur, handle du tunnel) et n'existe nulle part ailleurs que dans
    /// l'appel au moteur. La recalculer depuis l'etat serait une seconde
    /// source de verite, qui peut diverger de la premiere sans que rien ne le
    /// dise. La reponse est donc ce que le superviseur a RETENU de cet appel.
    ///
    /// # Ce qu'un appelant y gagne: une lecture
    ///
    /// Aucun parametre, aucun effet: elle ne pose rien, ne change aucun etat,
    /// et passe par le meme controle d'acces que `Status`. Elle ne transporte
    /// ni cle ni profil, seulement les six champs que le moteur nft lit (voir
    /// [`DeclarationPareFeu`]).
    DeclarationPareFeu,
}

impl Command {
    /// Vrai si la commande modifie l'etat du systeme. Sert a journaliser les
    /// actions privilegiees et leur appelant.
    pub fn is_mutating(&self) -> bool {
        matches!(
            self,
            Command::Connect { .. }
                | Command::ConnectStored
                | Command::Disconnect
                // Ne touche pas au systeme, mais change ce que le daemon
                // REFUSERA ensuite. Une connexion ecartee plus tard pour cause
                // d'interception sans qu'on sache qui a fourni le verdict
                // serait indebogable, et c'est exactement ce que cette
                // journalisation existe pour empecher.
                | Command::VerdictInspectionTls { .. }
                // Elle repose des filtres. L'effet est idempotent, mais une
                // transaction de pare-feu reste une transaction de pare-feu:
                // sans cette ligne, une rafale de reprises fabriquees ne
                // laisserait aucune trace de son auteur.
                | Command::Reprise
        )
    }

    pub fn name(&self) -> &'static str {
        match self {
            Command::Connect { .. } => "connect",
            Command::ConnectStored => "connect-stored",
            Command::Disconnect => "disconnect",
            Command::Status => "status",
            Command::Check => "check",
            Command::VerdictInspectionTls { .. } => "verdict-inspection-tls",
            Command::Reprise => "reprise",
            Command::DeclarationPareFeu => "declaration-pare-feu",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "kebab-case")]
pub enum Response {
    Ok,
    Status(Box<TunnelStatus>),
    Check(Box<CheckReport>),
    DeclarationPareFeu(Box<DeclarationPareFeu>),
    Error { message: String },
}

/// Version du contenu de [`DeclarationPareFeu`], distincte de
/// [`PROTOCOL_VERSION`]: un lecteur strict refuse une forme qu'il ne connait
/// pas plutot que d'en comparer une partie.
pub const DECLARATION_PARE_FEU_VERSION: u32 = 1;

/// Issue du dernier appel du daemon a son moteur de pare-feu.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IssueApplication {
    /// Aucun appel depuis le demarrage du daemon: il n'a rien pose.
    Aucune,
    /// Le moteur a accepte la politique jointe.
    Posee,
    /// Le moteur a accepte le retrait: le daemon ne declare aucune politique.
    Retiree,
    /// Le moteur a refuse. Le daemon ne sait pas ce que porte le noyau, et le
    /// dit: aucune politique n'est jointe, pas meme la precedente.
    Echec,
}

/// Declaration du daemon: la derniere politique qu'il a remise a son moteur.
///
/// C'est une DECLARATION, jamais une observation: elle dit ce que le daemon a
/// demande et ce que le moteur a repondu, pas ce que le noyau porte. Seul un
/// verificateur qui lit le noyau peut la confronter a la realite.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeclarationPareFeu {
    /// Toujours [`DECLARATION_PARE_FEU_VERSION`].
    pub schema_version: u32,
    /// Alea tire au demarrage du daemon. Le numero d'application repart de
    /// zero a chaque demarrage: sans cet alea, un daemon redemarre entre deux
    /// lectures, qui aurait fait le meme nombre d'applications, serait pris
    /// pour le meme. Il ne designe rien d'autre et n'est pas un secret.
    pub instance: String,
    /// Numero de l'appel au moteur, monotone sur la vie du daemon; zero tant
    /// qu'aucun appel n'a eu lieu. Chaque appel l'incremente, reussi ou non.
    pub application: u64,
    /// `KillSwitch::backend` du moteur appele, par exemple `nftables`.
    pub moteur: String,
    pub issue: IssueApplication,
    /// Presente si et seulement si `issue` vaut `posee`: la projection v1
    /// (`bifrost_firewall::politique_nft::Politique::projeter`) de la
    /// politique EXACTE remise au moteur, soit les six champs que le rendu nft
    /// lit. Aucune cle, aucun point d'acces, aucun chemin: ni le profil ni les
    /// executables n'en font partie. Pour un autre moteur que `nftables`, ces
    /// six champs ne decrivent pas ce que le moteur lit, et un lecteur doit
    /// refuser de s'en servir.
    pub politique: Option<serde_json::Value>,
}

impl Response {
    pub fn error(message: impl Into<String>) -> Self {
        Self::Error {
            message: message.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn les_commandes_mutantes_sont_identifiees() {
        assert!(Command::Disconnect.is_mutating());
        // Monter le tunnel depuis le profil du daemon est aussi mutant que le
        // monter depuis un profil fourni. L'oublier ferait qu'une connexion sur
        // deux ne serait pas journalisee avec son appelant, et c'est justement
        // celle qu'un membre du groupe peut declencher sans lire la cle.
        assert!(Command::ConnectStored.is_mutating());
        assert!(!Command::Status.is_mutating());
        assert!(!Command::Check.is_mutating());
        // Ne touche pas au systeme, mais change ce que le daemon refusera
        // ensuite: son appelant doit se retrouver dans le journal.
        assert!(Command::VerdictInspectionTls { intercepte: true }.is_mutating());
        // Elle repose des filtres: son appelant se retrouve dans le journal,
        // sans quoi une rafale de reprises fabriquees serait anonyme.
        assert!(Command::Reprise.is_mutating());
        // Une lecture: la ranger parmi les mutantes ne changerait aucun droit
        // (le controle d'acces est le meme pour toutes), mais ferait passer
        // pour une action ce qui n'en est pas une dans le journal d'audit.
        assert!(!Command::DeclarationPareFeu.is_mutating());
    }

    /// Le nom sur le fil est un contrat avec `bifrost-cli prove nft
    /// --politique-daemon`, et la commande ne porte rien: un appelant ne peut
    /// pas lui faire decrire autre chose que ce que le daemon a retenu.
    #[test]
    fn la_declaration_du_pare_feu_a_son_nom_et_ne_porte_rien() {
        let s = serde_json::to_string(&Request::new(Command::DeclarationPareFeu)).unwrap();
        assert_eq!(s, r#"{"version":1,"command":"declaration-pare-feu"}"#);
        let back: Request = serde_json::from_str(&s).unwrap();
        assert_eq!(back.command.name(), "declaration-pare-feu");
    }

    /// La forme de la reponse, cle par cle: c'est ce que le lecteur strict de
    /// la preuve compare, et une cle ajoutee ici doit le faire tomber plutot
    /// que d'etre ignoree en silence.
    #[test]
    fn la_reponse_de_declaration_a_exactement_sept_cles() {
        let d = DeclarationPareFeu {
            schema_version: DECLARATION_PARE_FEU_VERSION,
            instance: "00".repeat(24),
            application: 3,
            moteur: "nftables".into(),
            issue: IssueApplication::Posee,
            politique: Some(serde_json::json!({"schema_version": 1})),
        };
        let v = serde_json::to_value(Response::DeclarationPareFeu(Box::new(d.clone()))).unwrap();
        let mut cles: Vec<_> = v.as_object().unwrap().keys().cloned().collect();
        cles.sort();
        assert_eq!(
            cles,
            [
                "application",
                "instance",
                "issue",
                "moteur",
                "politique",
                "result",
                "schema_version"
            ]
        );
        assert_eq!(v["result"], "declaration-pare-feu");
        assert_eq!(v["issue"], "posee");
        match serde_json::from_value::<Response>(v).unwrap() {
            Response::DeclarationPareFeu(relue) => assert_eq!(*relue, d),
            autre => panic!("attendu une declaration, recu {autre:?}"),
        }
        for (issue, fil) in [
            (IssueApplication::Aucune, "aucune"),
            (IssueApplication::Retiree, "retiree"),
            (IssueApplication::Echec, "echec"),
        ] {
            assert_eq!(serde_json::to_value(issue).unwrap(), fil);
        }
    }

    /// Le nom sur le fil de la reprise, qui est un contrat avec un SCRIPT.
    ///
    /// Plus fragile que les autres: les commandes voisines sont ecrites par du
    /// Rust qui construit l'enum, donc un renommage les suit. Celle-ci part
    /// d'un hook `systemd-sleep` qui appelle le client par sa ligne de
    /// commande, et rien dans la chaine de compilation ne relie ce script au
    /// nom serialise ici.
    #[test]
    fn la_reprise_a_son_propre_nom_sur_le_fil() {
        let r = Request::new(Command::Reprise);
        let s = serde_json::to_string(&r).unwrap();
        assert!(
            s.contains("\"command\":\"reprise\""),
            "nom inattendu sur le fil: {s}"
        );
        // Sans parametre, et cela compte: elle ne decrit rien, donc elle ne
        // peut pas faire poser une politique choisie par l'appelant.
        let back: Request = serde_json::from_str(&s).unwrap();
        assert_eq!(back.command.name(), "reprise");
        assert!(matches!(back.command, Command::Reprise));
    }

    /// Le nom sur le fil est un contrat: un client d'une autre version le lit.
    #[test]
    fn le_profil_local_a_son_propre_nom_sur_le_fil() {
        let r = Request::new(Command::ConnectStored);
        let s = serde_json::to_string(&r).unwrap();
        assert!(
            s.contains("\"command\":\"connect-stored\""),
            "nom inattendu sur le fil: {s}"
        );
        // Et surtout: il ne porte aucun chemin. Le daemon tourne en root, et
        // lui laisser designer le fichier a ouvrir ferait de lui un depute
        // confus. Si un champ apparaissait ici un jour, cette recette tombe.
        assert!(
            !s.contains("config") && !s.contains("path") && !s.contains("chemin"),
            "cette commande ne doit transporter aucun chemin: {s}"
        );
        let back: Request = serde_json::from_str(&s).unwrap();
        assert_eq!(back.command.name(), "connect-stored");
    }

    #[test]
    fn aller_retour_json_d_une_requete() {
        let r = Request::new(Command::Status);
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains("\"version\":1"));
        assert!(s.contains("\"command\":\"status\""));
        let back: Request = serde_json::from_str(&s).unwrap();
        assert_eq!(back.version, PROTOCOL_VERSION);
        assert_eq!(back.command.name(), "status");
    }

    #[test]
    fn aller_retour_json_d_une_reponse_d_erreur() {
        let r = Response::error("acces refuse");
        let s = serde_json::to_string(&r).unwrap();
        let back: Response = serde_json::from_str(&s).unwrap();
        match back {
            Response::Error { message } => assert_eq!(message, "acces refuse"),
            other => panic!("attendu Error, recu {other:?}"),
        }
    }

    #[test]
    fn une_requete_d_une_autre_version_reste_lisible_pour_etre_refusee() {
        // Le serveur doit pouvoir lire la version avant de decider, sinon il
        // ne peut pas renvoyer un message d'erreur utile.
        let s = r#"{"version":99,"command":"status"}"#;
        let r: Request = serde_json::from_str(s).unwrap();
        assert_eq!(r.version, 99);
    }
}
