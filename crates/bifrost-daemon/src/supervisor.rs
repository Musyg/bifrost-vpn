//! Le superviseur: il execute les actions decidees par la machine a etats.
//!
//! Il tourne sur un thread dedie parce que les traits de `bifrost_core::ports`
//! sont synchrones (netlink, WFP, sous-processus courts). Le serveur IPC, lui,
//! est asynchrone et lui parle par canal.

use bifrost_evasion::{
    CleReseau, Coeur, Demarche, Environnement, MemoireReseau, Mode, Pays, Technique,
};
use std::collections::VecDeque;
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::{Duration, Instant, SystemTime};

use bifrost_core::checks::CheckReport;
use bifrost_core::config::Portage;
use bifrost_core::ports::{DnsManager, KillSwitch, TunnelDevice};
use bifrost_core::profil::{Profil, Profils};
use bifrost_core::state::{Action, Event, State, StateMachine, TunnelStatus};
use bifrost_core::{Error, Result, TunnelConfig};

use bifrost_evasion::course::{Course, Echec, Pas};
use bifrost_evasion::observation::{self, Echantillon, Observateur, Perte, Sonde, Verdict};

use crate::coeurs::identite::{IdentiteCoeur, IdentiteResolveur};

/// Periode d'interrogation du handshake. WireGuard renouvelle son handshake
/// toutes les 120 s; deux secondes suffisent a detecter une chute sans peser.
const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Tire la cadence d'une sonde de vitalite, entre les deux bornes que
/// [`bifrost_evasion::observation`] fixe.
///
/// L'intervalle EST la politique. Une sonde a periode fixe est un motif
/// regulier, ce que le document 04 partie 3.2 interdit explicitement et ce que
/// Psiphon evite par le meme moyen - `prng.Period(min, max)`, avec en
/// commentaire "to make the resulting traffic less fingerprintable".
///
/// Un tirage impossible retombe sur la borne basse plutot que d'echouer:
/// manquer de hasard doit rendre la cadence previsible, pas empecher de sonder.
fn cadence_de_sonde() -> Duration {
    let mut tirage = [0u8; 2];
    if crate::coeurs::alea::octets(&mut tirage).is_err() {
        return observation::PERIODE_SONDE_MIN;
    }
    let etendue =
        observation::PERIODE_SONDE_MAX.as_secs() - observation::PERIODE_SONDE_MIN.as_secs();
    let part = u64::from(u16::from_be_bytes(tirage)) * etendue / u64::from(u16::MAX);
    observation::PERIODE_SONDE_MIN + Duration::from_secs(part)
}

/// Tire la gigue qui separe deux bascules, entre les deux bornes que
/// [`bifrost_evasion::selection`] fixe.
///
/// Meme regle et meme repli que [`cadence_de_sonde`]: manquer de hasard doit
/// rendre l'attente previsible, pas empecher de basculer. La borne basse est le
/// bon repli - elle attend quand meme, la seule chose qu'on perd est
/// l'imprevisibilite.
fn gigue_de_course() -> Duration {
    let mut tirage = [0u8; 2];
    if crate::coeurs::alea::octets(&mut tirage).is_err() {
        return bifrost_evasion::selection::JITTER_MIN;
    }
    let etendue = bifrost_evasion::selection::JITTER_MAX.as_millis() as u64
        - bifrost_evasion::selection::JITTER_MIN.as_millis() as u64;
    let part = u64::from(u16::from_be_bytes(tirage)) * etendue / u64::from(u16::MAX);
    bifrost_evasion::selection::JITTER_MIN + Duration::from_millis(part)
}

/// Garde-fou contre une boucle d'evenements qui s'auto-alimenterait.
const MAX_EVENTS_PER_PUMP: usize = 32;

pub enum Cmd {
    Connect(Box<TunnelConfig>, Reply<Result<()>>),
    Disconnect(Reply<Result<()>>),
    Status(Reply<TunnelStatus>),
    Check(Reply<CheckReport>),
    /// La machine sort d'une mise en veille. Sans reponse: personne n'attend
    /// derriere, et la source est un rappel du systeme qui ne doit surtout pas
    /// se retrouver a attendre le superviseur.
    Reprise,
    /// Le verdict d'inspection TLS, mesure hors de ce processus.
    ///
    /// Sans reponse a rendre: il n'y a rien a echouer. Le champ est ecrit, et
    /// il pesera sur la PROCHAINE selection - pas sur le tunnel en cours, qui
    /// est monte et dont la technique ne se rechoisit pas sous les pieds.
    VerdictTls(bool),
    Shutdown,
}

pub type Reply<T> = tokio::sync::oneshot::Sender<T>;

/// Tout ce que le superviseur sait du resolveur chiffre.
///
/// Les deux moities ne se confondent pas et ne s'impliquent pas. L'IDENTITE
/// ferme le :53 pour tout le monde sauf un compte, et vaut meme si Bifrost
/// n'embarque rien: un dnscrypt-proxy installe par la distribution et pilote
/// par systemd est un cas legitime. L'ATELIER, lui, sert a en lancer un
/// nous-memes. Declarer l'un sans l'autre reste coherent, et les melanger
/// obligerait a embarquer un binaire pour avoir le droit de restreindre.
pub struct Resolveur {
    pub identite: IdentiteResolveur,
    pub atelier: Option<crate::resolveur::Atelier>,
    en_cours: Option<crate::resolveur::ResolveurEnCours>,
    /// Comment s'assurer qu'un resolveur repond, quand Bifrost n'en lance pas
    /// lui-meme. Remplacable, et uniquement pour cela: les recettes qui
    /// mesurent ce que le superviseur ecrit dans la politique de pare-feu
    /// n'ont pas a faire dependre leur verdict d'un port ouvert sur la machine
    /// qui les execute.
    verification: fn(std::net::SocketAddr) -> Result<()>,
}

impl Default for Resolveur {
    fn default() -> Self {
        Self {
            identite: IdentiteResolveur::default(),
            atelier: None,
            en_cours: None,
            verification: crate::resolveur::verifier_repond,
        }
    }
}

impl Resolveur {
    pub fn nouveau(
        identite: IdentiteResolveur,
        atelier: Option<crate::resolveur::Atelier>,
    ) -> Self {
        Self {
            identite,
            atelier,
            ..Default::default()
        }
    }
}

pub struct Supervisor {
    machine: StateMachine,
    firewall: Box<dyn KillSwitch>,
    /// Le peripherique EN SERVICE.
    tunnel: Box<dyn TunnelDevice>,
    /// L'autre chemin, au repos. `None` quand ce daemon n'en a qu'un.
    ///
    /// Les deux boites s'ECHANGENT au lieu de se choisir a chaque usage. Le
    /// reste du superviseur continue donc de ne connaitre qu'un `self.tunnel`,
    /// et il n'existe aucun appel qui pourrait partir vers le mauvais
    /// peripherique parce qu'on aurait oublie de le faire passer par un
    /// accesseur.
    en_reserve: Option<Box<dyn TunnelDevice>>,
    /// Laquelle des deux voies `tunnel` designe en ce moment.
    voie: Voie,
    /// De quoi ecrire une configuration de coeur et la lancer. Va toujours
    /// avec `en_reserve`: l'un sans l'autre monterait un TUN devant un coeur
    /// qui n'existe pas, ou lancerait un coeur que rien ne rejoint.
    lancement_coeur: Option<LancementCoeur>,
    dns: Box<dyn DnsManager>,
    /// Identite du coeur anti-censure, telle que l'exploitation la declare.
    ///
    /// Vide par defaut. Elle vit ici et non dans la machine a etats pour la
    /// meme raison que le LUID du tunnel: la machine decide QUOI autoriser,
    /// pas comment le systeme designe un processus.
    coeur: IdentiteCoeur,
    /// Le resolveur chiffre: son identite, son materiel, son instance.
    resolveur: Resolveur,
    /// Comment tenir le carnet des reseaux.
    carnetier: Carnetier,
    /// Le pont vers les coeurs, quand il y en a un.
    atelier: Option<crate::coeurs::atelier::Poignee>,
    /// Ce que la couche de selection retient POUR LA CONNEXION EN COURS.
    ///
    /// Sans ce champ, `connect` montait un tunnel WireGuard QUELLE QUE SOIT la
    /// technique choisie. Le daemon faisait donc silencieusement autre chose
    /// que ce que sa propre couche de decision avait retenu, et l'ecart ne se
    /// voyait nulle part: ni dans le journal, ni dans l'etat, ni dans un
    /// verdict.
    ///
    /// **Recalcule a chaque `connect`, et c'est le fond de ce cablage.** Il a
    /// d'abord ete fixe a la construction du daemon, ce qui revenait a decider
    /// avant de savoir ce qu'on nous demanderait: un profil de coeur etait
    /// alors refuse par une demarche epinglee sur `TunnelDirect(WireGuardNu)`,
    /// et tout le chemin par coeur - ecrit, teste, exempte par le kill switch -
    /// restait injoignable par `Connect`. Une demarche est une propriete de la
    /// connexion, pas du daemon.
    ///
    /// Au repos, `SansIssue`: rien n'a ete demande, donc rien n'est engage, et
    /// ce qui lirait ce champ hors connexion echouerait garde.
    demarche: Demarche,
    /// Ce qui alimente la selection et ne change pas d'une connexion a l'autre.
    decision: Decision,
    pending: VecDeque<Event>,
    retry_at: Option<Instant>,
    last_error: Option<String>,
    /// De quoi demander au pair s'il est encore la, quand un coeur porte le
    /// trafic. `None` sur un daemon sans chemin par coeur.
    sonde: Option<crate::coeurs::vitalite::Poignee>,
    /// Ce qui regarde couler le tunnel monte, et depuis quand il l'est.
    ///
    /// Pose au premier sondage d'un tunnel etabli, repris a zero a chaque
    /// montage: les compteurs d'une interface neuve repartent de zero, et un
    /// observateur qui garderait la fenetre du tunnel precedent lirait un
    /// effondrement la ou il y a eu une reconnexion.
    ///
    /// Repris a zero AUSSI a chaque bascule de selecteur, pour la meme raison
    /// exactement: le candidat suivant heriterait sinon du silence de celui
    /// qu'il remplace, et mourrait d'un gel qui n'est pas le sien.
    observation: Option<(Instant, Observateur)>,
    /// De quoi mettre en service le candidat suivant. `None` sur un daemon
    /// sans chemin par coeur, ou aucun selecteur n'existe.
    bascule: Option<crate::coeurs::bascule::Poignee>,
    /// Le parcours des candidats de CETTE connexion.
    ///
    /// `None` hors connexion, et `None` pour une voie directe: une bascule a
    /// chaud passe par un selecteur, et il n'y en a que derriere un coeur. Un
    /// profil WireGuard n'a qu'une technique et rien vers quoi basculer.
    ///
    /// # Pourquoi aucune reussite ne lui est jamais notee
    ///
    /// [`Course::noter_reussite`] arrete la course: `prochain_pas` rend
    /// `Etabli` pour toujours ensuite. C'est le bon comportement pour la phase
    /// d'ETABLISSEMENT, ou le plus furtif qui marche est celui qu'on garde. La
    /// degradation en cours de session est l'autre moitie du meme paragraphe du
    /// document 04 partie 3.2, et elle a besoin que la liste reste parcourable
    /// tant que la connexion vit. Le candidat courant reste donc "en vol" toute
    /// la session, et chaque perte le remplace par le suivant.
    course: Option<Course>,
    /// Quand reconsulter la course, quand elle a demande a patienter.
    ///
    /// La gigue entre deux tentatives n'est pas un detail de confort: le
    /// document 04 partie 3.2 la demande deux fois, "espacer les tentatives"
    /// et "ne pas emettre de motif de bascule regulier". Une rafale de
    /// bascules est elle-meme une signature.
    reprise_de_course: Option<Instant>,
    /// La cle du reseau traverse par la connexion en cours.
    ///
    /// Gardee parce qu'une perte en cours de session doit s'inscrire au carnet
    /// et que la cle ne peut plus etre relue a ce moment-la: le tunnel est
    /// monte, donc la route par defaut est la sienne, et la cle decrirait le
    /// tunnel au lieu du reseau. Voir le commentaire en tete de `connect`.
    cle: Option<CleReseau>,
}

/// Comment le superviseur tient le carnet des reseaux.
///
/// Deux fonctions plutot qu'un appel direct au module `carnet`: le superviseur
/// se teste avec des doublures, et l'ordre dans lequel il les appelle est
/// justement ce qu'il faut pouvoir mesurer.
#[derive(Clone, Copy)]
pub struct Carnetier {
    /// La cle du reseau courant.
    ///
    /// **Appelee avant que le tunnel monte**, et l'ordre n'est pas negociable:
    /// une fois le tunnel en place, la route par defaut est la sienne, donc la
    /// cle decrirait le tunnel au lieu du reseau qu'il traverse. Le souvenir
    /// serait range sous un nom qu'on ne reverra jamais en clair, et le carnet
    /// resterait eternellement inutile sans que rien ne le signale.
    pub cle: fn() -> std::result::Result<CleReseau, String>,
    /// Note ce que cette technique a donne sur ce reseau.
    pub noter: fn(&CleReseau, Technique, bool) -> std::result::Result<(), String>,
    /// Ce que le carnet retient DEJA de ce reseau.
    ///
    /// Lu avant de planifier, et c'est la regle 1 du document 04 partie 3.2:
    /// "reseau deja connu -> reutiliser directement le protocole memorise qui
    /// a marche". Sans cette lecture, le carnet ne servait qu'a s'ecrire.
    pub souvenir: fn(&CleReseau) -> std::result::Result<MemoireReseau, String>,
    /// L'horloge, lue au bord une seule fois par connexion.
    ///
    /// La selection est pure et recoit sa date en argument: la peremption d'un
    /// souvenir et la fraicheur d'une observation de survie en dependent
    /// toutes deux, et un module qui lit l'heure lui-meme ne se teste pas.
    pub aujourd_hui: fn() -> std::result::Result<bifrost_evasion::Date, String>,
}

impl Default for Carnetier {
    fn default() -> Self {
        Self {
            cle: crate::carnet::cle_courante,
            noter: noter_au_carnet,
            souvenir: crate::carnet::souvenir_de,
            aujourd_hui: crate::carnet::aujourd_hui,
        }
    }
}

/// Ouvre le carnet, y inscrit une ligne, le referme.
///
/// Relire a chaque fois plutot que garder le carnet en memoire: le daemon n'est
/// pas seul a pouvoir y toucher, et une copie gardee en memoire ecraserait au
/// prochain enregistrement ce qu'un autre y aurait mis.
fn noter_au_carnet(
    cle: &CleReseau,
    technique: Technique,
    reussite: bool,
) -> std::result::Result<(), String> {
    let chemin = crate::carnet::chemin()?;
    let mut carnet = crate::carnet::lire(&chemin)?;
    let aujourd_hui = crate::carnet::aujourd_hui()?;
    if reussite {
        carnet.noter_reussite(cle.clone(), technique, aujourd_hui);
    } else {
        carnet.noter_echec(cle.clone(), technique, aujourd_hui);
    }
    // Le moment ou le carnet est ouvert de toute facon est le bon pour laisser
    // partir ce qui ne sert plus: une entree qui ne pese plus sur aucune
    // decision n'est plus qu'une trace des reseaux frequentes.
    carnet.oublier_les_perimes(aujourd_hui);
    crate::carnet::ecrire(&chemin, &carnet)
}

/// Laquelle des deux voies porte la connexion.
///
/// Un marqueur, pas une donnee: le peripherique correspondant est deja dans
/// `tunnel`. Ce champ ne sert qu'a savoir s'il faut echanger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Voie {
    /// Le tunnel chiffre par le daemon lui-meme, WireGuard aujourd'hui.
    Direct,
    /// Le TUN devant un coeur tiers, qui chiffre a notre place.
    ParCoeur,
}

/// De quoi porter une connexion par coeur, de bout en bout.
///
/// Les cinq champs vont ensemble et n'ont aucun sens separement. Le
/// peripherique mene les paquets a la facade; les quatre autres font qu'un
/// coeur ecoute derriere elle. En fournir une moitie donnerait exactement ce
/// que l'en-tete de [`crate::tunnel::coeur`] appelle un chemin qui ne mene
/// nulle part.
pub struct CheminCoeur {
    /// Le TUN, l'aiguillage et le passeur, vus comme un tunnel.
    pub tunnel: Box<dyn TunnelDevice>,
    /// Ou trouver les binaires des coeurs et ou ecrire leurs configurations.
    pub emplacements: crate::coeurs::lancement::Emplacements,
    /// Ou le coeur ecoutera en SOCKS, et ce qu'il exigera de qui s'y presente.
    ///
    /// L'adresse est celle que l'atelier publie et que la facade suit. Les
    /// identifiants voyagent avec elle parce que la boucle locale n'est pas une
    /// frontiere: une entree SOCKS sans compte est ouverte a tout processus de
    /// la machine, mesure sur le banc le 20 aout 2026. La MEME valeur sert a
    /// engendrer la configuration du coeur et a l'appeler, donc les deux ne
    /// peuvent pas diverger.
    pub socks: crate::coeurs::socks::Mandataire,
    /// Port local de l'API de controle du coeur.
    pub api: u16,
    /// Secret de cette API.
    ///
    /// Engendre au demarrage et jamais lu d'une ligne de commande: un secret
    /// passe en argument est lisible par tout le monde dans `ps`.
    pub secret: String,
    /// De quoi demander au coeur de composer un aller-retour.
    ///
    /// Va avec les quatre autres pour la meme raison qu'eux: une sonde sans
    /// coeur ne sonderait rien. Assemblee la ou le passeur l'est, parce qu'elle
    /// vit comme lui sur le runtime.
    pub sonde: crate::coeurs::vitalite::Poignee,
    /// De quoi mettre en service le candidat suivant sans rien relancer.
    ///
    /// Va avec la sonde pour une raison qui n'est pas de commodite: les deux
    /// sont batis sur la MEME `vitalite::Adresse`, donc sur le meme selecteur.
    /// S'ils en visaient deux, on basculerait l'un en sondant l'autre, et le
    /// tunnel paraitrait gele juste apres avoir ete repare.
    pub bascule: crate::coeurs::bascule::Poignee,
}

/// La moitie de [`CheminCoeur`] qui sert a LANCER, une fois le peripherique
/// range dans `en_reserve`.
struct LancementCoeur {
    emplacements: crate::coeurs::lancement::Emplacements,
    socks: crate::coeurs::socks::Mandataire,
    api: u16,
    secret: String,
}

/// Nom du selecteur, par lequel une bascule a chaud passera.
pub const SELECTEUR: &str = "select";

/// Ce qui prefixe toute erreur de lancement de coeur.
///
/// Un marqueur plutot qu'une enumeration des messages de l'atelier: ceux-ci
/// changent, celui-ci est pose et lu au meme endroit du code. Voir
/// [`is_retryable`] pour ce qu'il commande.
const MARQUEUR_COEUR: &str = "coeur non demarre";

/// Ce dont le superviseur DISPOSE pour travailler, par opposition a ses ports.
///
/// Les trois vont ensemble et changent ensemble: la demarche dit ce qu'il faut
/// faire, le carnetier ce qu'on en retient, l'atelier avec quoi le faire. Les
/// passer separement a fini par donner un constructeur a huit arguments, ou
/// l'ordre etait la seule chose qui distinguait un `Option` d'un autre.
pub struct Equipement {
    pub decision: Decision,
    pub carnetier: Carnetier,
    /// `None` quand le daemon tourne sans atelier: les recettes qui n'ont rien
    /// a faire d'un coeur ne doivent pas avoir a en monter un pour s'executer.
    pub atelier: Option<crate::coeurs::atelier::Poignee>,
    /// De quoi servir un profil par coeur. `None` quand le daemon n'a pas ete
    /// demarre avec ce qu'il faut, ce qui reste le cas ordinaire.
    pub chemin_coeur: Option<CheminCoeur>,
}

/// Ce dont la selection a besoin et qui ne depend pas de la connexion demandee.
///
/// Fixe au demarrage, contrairement a la demarche qui se recalcule a chaque
/// `connect`. La ligne de partage est celle-la: le pays et ce qu'on a mesure du
/// reseau sont des proprietes de la machine et de sa liaison, la demarche est
/// une propriete de la connexion qu'on demande.
#[derive(Debug, Clone, Copy)]
pub struct Decision {
    pub pays: Pays,
    /// Ce qui a ete MESURE du reseau.
    ///
    /// Vierge par defaut, et ce n'est pas un pis-aller. La regle du crate de
    /// selection est que SEULE UNE MESURE ELIMINE: un environnement vierge
    /// n'ecarte donc rien et ne peut pas refuser a tort. C'est aussi ce que
    /// l'etat de l'art commande - voir l'en-tete de `bifrost_evasion::course`:
    /// Psiphon, le Smart Dialer d'Outline et le Connection Assist de Tor
    /// choisissent SANS sonder d'abord, et le seul systeme documente qui sonde
    /// avant de choisir met 13,8 s en Chine pour une reponse que la tentative
    /// donne en meme temps que la connexion. Ce champ existe pour recevoir ce
    /// qui aura ete mesure HORS du chemin de connexion, jamais pour justifier
    /// d'y sonder.
    pub environnement: Environnement,
    /// L'intention de l'utilisateur. Toujours `Auto` aujourd'hui: aucun
    /// drapeau ne l'expose encore, et l'inventer ici ne le rendrait pas
    /// choisissable.
    pub mode: Mode,
}

impl Default for Decision {
    fn default() -> Self {
        Self {
            pays: Pays::NonCensure,
            environnement: Environnement::default(),
            mode: Mode::Auto,
        }
    }
}

/// La technique QUE CE PROFIL DECRIT.
///
/// Total et sans defaut: un profil nomme son transport, et chaque transport est
/// exactement une technique.
pub(crate) fn technique_du_profil(profil: &Profil) -> Technique {
    use bifrost_core::profil::Transport;
    match profil.transport {
        Transport::VlessReality(_) => Technique::RealityVision,
        Transport::VlessWebsocket(_) => Technique::WebsocketCdn,
        Transport::VlessHttpUpgrade(_) => Technique::HttpUpgradeFront,
        Transport::Hysteria2(_) => Technique::Hysteria2,
    }
}

/// Les techniques QUE LE PORTAGE PROPOSE, dans l'ordre ou il les declare.
///
/// Plusieurs desormais, et c'est ce qui rend une course possible: un tunnel n'a
/// pas UNE technique mais une liste de candidats, comme le demande le document
/// 04 partie 3.2. Un `Portage::Wireguard` en propose une seule - AmneziaWG ne
/// se monte pas ainsi, il se pilote par UAPI derriere un coeur.
///
/// Jamais vide: `Profils` interdit la liste vide par construction.
///
/// **L'ordre rendu n'est PAS un ordre de preference.** C'est celui du fichier;
/// le classement appartient a [`bifrost_evasion::demarche_parmi`], qui prend
/// cette liste et rend le premier candidat du PLAN qui s'y trouve. Laisser
/// l'ordre d'ecriture d'un fichier decider reviendrait a ne pas selectionner.
///
/// La correspondance INVERSE, de la technique vers le coeur, appartient a
/// [`Demarche::pour`] et a elle seule. Les deux se rejoignent dans [`refus`],
/// qui refuse tout desaccord: c'est ce qui rend leur divergence visible plutot
/// qu'improbable.
pub(crate) fn techniques_du_portage(portage: &Portage) -> Vec<Technique> {
    match portage {
        Portage::Wireguard(_) => vec![Technique::WireGuardNu],
        Portage::Coeur(p) => p.tous().map(technique_du_profil).collect(),
    }
}

/// Pourquoi ce superviseur ne peut pas honorer cette demarche AVEC ce profil,
/// ou `None`.
///
/// Pure et hors de l'`impl` a dessein: c'est une regle, elle se lit et se teste
/// sans monter un superviseur ni une doublure.
///
/// # Pourquoi les deux, et pas la demarche seule
///
/// La demarche est calculee A PARTIR du portage, par [`technique_du_portage`]
/// puis [`bifrost_evasion::demarche_arbitree`]. Les deux devraient donc
/// toujours s'accorder - et c'est justement pourquoi la question se pose ici.
/// Deux correspondances existent, portage vers technique et technique vers
/// coeur, dans deux crates differents. Le jour ou elles divergeront, le daemon
/// monterait du WireGuard sous le nom d'une technique qui n'a rien a voir, ou
/// l'inverse. Un daemon qui fait autre chose que ce que sa couche de decision a
/// retenu est pire qu'un daemon qui refuse, parce qu'il a l'air de marcher. Les
/// deux bras de desaccord ci-dessous sont donc INATTEIGNABLES aujourd'hui, et
/// se gardent pour cette raison-la, pas par prudence rituelle.
///
/// Ce qui, lui, arrive: [`Demarche::Ecartee`]. La selection a mesure quelque
/// chose qui condamne la technique du profil sur ce reseau, et le refus le dit
/// avec le motif de la selection.
pub(crate) fn refus(d: &Demarche, portage: &Portage) -> Option<String> {
    match (d, portage) {
        (Demarche::TunnelDirect(_), Portage::Wireguard(_)) => None,
        (Demarche::ParCoeur { coeur, .. }, Portage::Coeur(_)) => refus_de_coeur(*coeur),

        (Demarche::TunnelDirect(technique), Portage::Coeur(_)) => Some(format!(
            "desaccord entre la decision et le profil: la couche de selection a retenu un tunnel direct ({}), le profil demande un coeur anti-censure. Aucun des deux ne sera monte",
            technique.nom()
        )),
        (Demarche::ParCoeur { technique, coeur }, Portage::Wireguard(_)) => Some(format!(
            "desaccord entre la decision et le profil: la couche de selection a retenu {} par le coeur {}, le profil decrit un pair WireGuard. Aucun des deux ne sera monte",
            technique.nom(),
            coeur.executable()
        )),

        (Demarche::PortailDAbord, _) => Some(
            "un portail captif est a franchir avant toute tentative: se connecter maintenant n'emettrait qu'une rafale, et une rafale est elle-meme une signature".to_owned(),
        ),
        (Demarche::Ecartee { motifs }, _) => Some(format!(
            "la couche de selection ecarte sur ce reseau tout ce que ce profil propose ({}). La connexion est refusee et le kill switch reste arme",
            motifs
                .iter()
                .map(|(t, r)| format!("{}: {}", t.nom(), r.motif()))
                .collect::<Vec<_>>()
                .join("; ")
        )),
        (Demarche::SansIssue, _) => Some(
            "aucune technique candidate: la connexion est refusee et le kill switch reste arme. Echouer garde est le bon echec".to_owned(),
        ),
    }
}

/// Ce coeur sait-il rendre un profil, ou seulement le laisser passer en clair.
///
/// La question n'est pas academique. [`crate::coeurs::configuration::xray`]
/// engendre une sortie `freedom` et ignore le profil qu'on lui donne: lancer
/// Xray avec un vrai profil ferait sortir le trafic EN CLAIR, depuis un compte
/// que le kill switch exempte, avec un tunnel qui monte et une interface qui
/// compte des octets. C'est le mode d'echec le plus couteux qui soit, parce que
/// tout a l'air correct. Il vaut mieux refuser en le disant.
///
/// Publique parce que `--sonder-reseau` la lit aussi, pour ne pas annoncer
/// montable un candidat que la connexion refuserait. Deux lecteurs, une seule
/// verite: recopier la liste cote affichage la ferait vieillir toute seule le
/// jour ou un generateur arrive.
pub fn refus_de_coeur(coeur: Coeur) -> Option<String> {
    match coeur {
        Coeur::SingBox => None,
        Coeur::XrayCore => Some(
            "le coeur retenu est xray, dont le generateur de configuration ne rend pas encore les sorties d'un profil: il n'ecrit qu'une sortie directe. Le lancer ferait sortir le trafic en clair depuis un compte exempte par le kill switch, avec un tunnel qui a l'air monte. Seul sing-box porte un profil aujourd'hui".to_owned(),
        ),
        Coeur::AmneziaWg => Some(
            "le coeur retenu est amneziawg, qui ne prend pas de fichier de configuration au lancement mais se pilote par UAPI, et rien n'ecrit encore ce dialogue. Seul sing-box porte un profil aujourd'hui".to_owned(),
        ),
    }
}

impl Supervisor {
    pub fn new(
        firewall: Box<dyn KillSwitch>,
        tunnel: Box<dyn TunnelDevice>,
        dns: Box<dyn DnsManager>,
        coeur: IdentiteCoeur,
        resolveur: Resolveur,
        equipement: Equipement,
    ) -> Self {
        let Equipement {
            decision,
            carnetier,
            atelier,
            chemin_coeur,
        } = equipement;
        // Le peripherique par coeur part au repos et son necessaire de
        // lancement reste a cote: les deux se separent ici, et une seule fois,
        // pour que `en_reserve` puisse ensuite s'echanger avec `tunnel` sans
        // que le sens d'aucun champ ne derive.
        let (en_reserve, lancement_coeur, sonde, bascule) = match chemin_coeur {
            Some(c) => (
                Some(c.tunnel),
                Some(LancementCoeur {
                    emplacements: c.emplacements,
                    socks: c.socks,
                    api: c.api,
                    secret: c.secret,
                }),
                Some(c.sonde),
                Some(c.bascule),
            ),
            None => (None, None, None, None),
        };
        Self {
            machine: StateMachine::new(),
            firewall,
            tunnel,
            en_reserve,
            voie: Voie::Direct,
            sonde,
            bascule,
            observation: None,
            // Rien n'a ete demande: il n'y a rien a parcourir. La course prend
            // son sens au premier `connect`, comme la demarche.
            course: None,
            reprise_de_course: None,
            cle: None,
            lancement_coeur,
            dns,
            // Rien n'a ete demande: rien n'est engage. La demarche prend son
            // sens au premier `connect`, qui la recalcule.
            demarche: Demarche::SansIssue,
            decision,
            carnetier,
            atelier,
            coeur,
            resolveur,
            pending: VecDeque::new(),
            retry_at: None,
            last_error: None,
        }
    }

    /// Boucle principale. Se termine sur `Cmd::Shutdown` ou fermeture du canal.
    pub fn run(mut self, rx: Receiver<Cmd>) {
        loop {
            match rx.recv_timeout(POLL_INTERVAL) {
                Ok(Cmd::Connect(cfg, reply)) => {
                    let r = self.connect(cfg);
                    let _ = reply.send(r);
                }
                Ok(Cmd::Disconnect(reply)) => {
                    let r = self.disconnect();
                    let _ = reply.send(r);
                }
                Ok(Cmd::Status(reply)) => {
                    let _ = reply.send(self.status());
                }
                Ok(Cmd::Check(reply)) => {
                    let _ = reply.send(crate::checks::run_all());
                }
                Ok(Cmd::VerdictTls(intercepte)) => {
                    self.noter_le_verdict_tls(intercepte);
                }
                Ok(Cmd::Reprise) => {
                    tracing::info!("reprise apres veille: la politique est reposee");
                    self.push(Event::SystemResumed);
                }
                Ok(Cmd::Shutdown) | Err(RecvTimeoutError::Disconnected) => {
                    self.on_shutdown();
                    return;
                }
                Err(RecvTimeoutError::Timeout) => {}
            }
            self.tick();
        }
    }

    fn connect(&mut self, cfg: Box<TunnelConfig>) -> Result<()> {
        // ICI, et pas plus bas: la cle doit designer le reseau qu'on traverse,
        // pas le tunnel. Des que le tunnel est monte, la route par defaut est
        // la sienne et la cle changerait de sens sans changer de forme.
        //
        // Ne pas savoir ou l'on est n'empeche pas de se connecter. Cela empeche
        // seulement de s'en souvenir - et de se servir de ce qu'on avait retenu.
        // C'est un motif de trace, pas de refus.
        let cle = match (self.carnetier.cle)() {
            Ok(c) => Some(c),
            Err(raison) => {
                tracing::debug!(%raison, "reseau non identifie: ni souvenir lu, ni souvenir note");
                None
            }
        };

        // La demarche se calcule POUR CETTE CONNEXION, a partir du profil qu'on
        // recoit et de ce qu'on sait du reseau. La calculer au demarrage
        // revenait a decider avant de savoir ce qu'on nous demanderait.
        //
        // Rien n'est emis pour cela: on lit un fichier et on applique une
        // fonction pure. La sonde, elle, reste hors du chemin de connexion.
        let (demarche, course) = self.arbitrer(&cfg.portage, cle.as_ref());
        self.demarche = demarche;
        self.course = course;
        self.reprise_de_course = None;
        // Gardee pour la SUITE de la connexion: une perte en cours de session
        // s'inscrit au carnet, et la cle ne pourra plus etre relue a ce
        // moment-la. Voir le commentaire en tete de cette fonction.
        self.cle = cle.clone();

        // AVANT toute validation et tout armement: la decision et le profil
        // doivent s'accorder, et le chemin demande doit exister ici. Refuser se
        // fait a la porte, avant qu'un filtre ne soit pose ou qu'un processus
        // ne soit lance.
        if let Some(raison) = refus(&self.demarche, &cfg.portage) {
            return Err(Error::Config(raison));
        }
        self.mettre_en_service(match cfg.portage {
            Portage::Wireguard(_) => Voie::Direct,
            Portage::Coeur(_) => Voie::ParCoeur,
        })?;
        cfg.validate()?;
        if *self.machine.state() != State::Disconnected {
            return Err(Error::Config(format!(
                "deja en etat {}: deconnecter avant de reconnecter",
                self.machine.state().name()
            )));
        }
        self.last_error = None;

        self.push(Event::Connect(cfg));
        self.pump();

        // La reponse au client reflete ce qui s'est reellement passe: si armer
        // le kill switch a echoue, la connexion est refusee, pas differee.
        let issue = match self.machine.state() {
            State::Error { reason } => Err(Error::Tunnel(reason.clone())),
            _ => Ok(()),
        };

        // Le carnet note les deux, la reussite comme l'echec: un echec ecarte la
        // technique du prochain essai, ce qui vaut autant qu'une reussite.
        //
        // Et il note les deux VOIES. Le filtrage se faisait sur `TunnelDirect`
        // seul, donc une connexion par coeur ne laissait aucune trace: la
        // moitie de la memoire dont la selection se sert n'etait jamais ecrite,
        // et rien ne le disait. `Demarche::technique` rend `None` pour les trois
        // demarches qui ne montent rien, qui sont exactement celles dont une
        // ligne de carnet ne parlerait pas du reseau.
        if let (Some(cle), Some(technique)) = (&cle, self.demarche.technique())
            && let Err(raison) = (self.carnetier.noter)(cle, technique, issue.is_ok())
        {
            // Un carnet qui ne s'ecrit pas ne casse pas la connexion en cours.
            // Il coute un sondage de plus a la prochaine, donc il se trace.
            tracing::warn!(%raison, "carnet non tenu a jour");
        }

        issue
    }

    /// Les sorties a proposer au selecteur, LA RETENUE EN TETE.
    ///
    /// L'etiquette d'une sortie est le nom de sa technique. Ce n'est pas
    /// cosmetique: c'est cette etiquette que la bascule du selecteur porte dans
    /// le corps de sa requete, donc c'est par elle que la course designera le
    /// candidat suivant. La faire coincider avec le vocabulaire de la selection
    /// evite une table de correspondance de plus.
    ///
    /// Les doublons sont impossibles ici parce que `Profils` refuse deux
    /// profils du meme transport - et sing-box exige des etiquettes uniques.
    fn sorties_du_coeur(&self, profils: &Profils) -> Vec<crate::coeurs::configuration::Sortie> {
        let retenue = self.demarche.technique();
        let mut ordonnes: Vec<&Profil> = profils.tous().collect();
        // Tri STABLE: la retenue passe devant, le reste garde l'ordre du
        // fichier. Un tri total inventerait un classement des replis que la
        // selection n'a pas encore rendu - c'est la course qui le donnera.
        ordonnes.sort_by_key(|p| Some(technique_du_profil(p)) != retenue);
        ordonnes
            .into_iter()
            .map(|p| {
                crate::coeurs::configuration::Sortie::depuis_profil(p, technique_du_profil(p).nom())
            })
            .collect()
    }

    /// Range le verdict d'inspection TLS dans ce qui alimente la selection.
    ///
    /// Le seul champ de l'`Environnement` que le daemon ne mesure PAS lui-meme,
    /// et le seul qui lui arrive donc du dehors. La raison est dans
    /// `tests/frontiere_reseau.rs`: une pile TLS n'a rien a faire dans un
    /// processus qui tourne en root, puisqu'une poignee de main analyse des
    /// donnees choisies par le pair - ici, par hypothese, l'equipement qui
    /// intercepte.
    fn noter_le_verdict_tls(&mut self, intercepte: bool) {
        self.decision.environnement.mitm_tls = bifrost_evasion::Mesure::Vu(intercepte);
        tracing::info!(
            intercepte,
            "verdict d'inspection TLS retenu: il pesera sur la prochaine selection"
        );
    }

    /// Ce que la couche de selection retient POUR CE PROFIL, sur ce reseau.
    ///
    /// La selection n'y choisit pas la technique - le profil la porte - elle
    /// dit si ce reseau la condamne, et avec quel motif. C'est le role de veto
    /// que decrit [`bifrost_evasion::demarche_arbitree`]: opposer a un profil
    /// le premier candidat du plan le refuserait presque toujours, puisque le
    /// plan prefere REALITY et que la plupart des profils ne sont pas cela.
    ///
    /// Deux pannes locales ne condamnent rien, et pour la meme raison dans les
    /// deux cas: la regle du crate de selection est qu'une mesure absente
    /// n'elimine jamais. Un carnet illisible rend un reseau inconnu, une
    /// horloge en panne rend une selection qui n'ecarte rien. Les deux se
    /// tracent; aucune ne refuse.
    ///
    /// # Ce qui sort d'ici, et pourquoi les deux ensemble
    ///
    /// La demarche dit par quoi COMMENCER, la course dit par quoi CONTINUER.
    /// Les deux se lisent sur le meme plan et le meme jeu de techniques, dans
    /// le meme appel: les separer donnerait deux endroits ou la preference se
    /// decide, et le jour ou l'un changerait sans l'autre, le selecteur
    /// designerait un candidat que la course ne connait pas.
    fn arbitrer(&self, portage: &Portage, cle: Option<&CleReseau>) -> (Demarche, Option<Course>) {
        let techniques = techniques_du_portage(portage);

        let aujourd_hui = match (self.carnetier.aujourd_hui)() {
            Ok(d) => d,
            Err(raison) => {
                // Sans date, ni la peremption d'un souvenir ni la fraicheur
                // d'une observation de survie ne se jugent. Planifier quand
                // meme ferait ecarter sur une date inventee. On prend alors ce
                // que le profil declare en premier, faute de pouvoir classer.
                tracing::warn!(%raison, "date indisponible: la selection n'ecartera ni ne classera rien");
                // Et pas de course non plus: elle se batit sur un plan, il n'y
                // en a pas. Sans horloge on se connecte encore, on ne bascule
                // plus - ce qui est exactement ce qu'une mesure absente doit
                // couter, ni plus ni moins.
                return match techniques.first() {
                    Some(t) => (Demarche::pour(*t), None),
                    None => (Demarche::SansIssue, None),
                };
            }
        };

        let memoire = match cle {
            Some(cle) => (self.carnetier.souvenir)(cle).unwrap_or_else(|raison| {
                tracing::warn!(%raison, "carnet non lu: ce reseau est traite comme inconnu");
                MemoireReseau::vierge()
            }),
            None => MemoireReseau::vierge(),
        };

        let plan = bifrost_evasion::planifier(&bifrost_evasion::Contexte {
            pays: self.decision.pays,
            environnement: self.decision.environnement,
            mode: self.decision.mode,
            memoire: &memoire,
            aujourd_hui,
        });
        let demarche = bifrost_evasion::demarche_parmi(&plan, &techniques);
        tracing::debug!(
            proposees = techniques.len(),
            retenue = demarche.technique().map(|t| t.nom()),
            pays = ?self.decision.pays,
            candidats = plan.candidats.len(),
            ecartes = plan.ecartes.len(),
            "selection: la demarche de cette connexion est arretee"
        );
        let course = self.course_pour(portage, &plan, &techniques, &demarche);
        (demarche, course)
    }

    /// La course qui accompagne cette demarche, s'il y a lieu d'en avoir une.
    ///
    /// `None` pour une voie directe: une bascule a chaud passe par un
    /// selecteur, et il n'y en a que derriere un coeur. `None` aussi si la
    /// course et la demarche ne nommaient pas la meme tete - ce qui ne peut pas
    /// arriver, les deux prenant le premier candidat du plan present chez
    /// l'appelant, et qui degrade alors vers "on se connecte sans pouvoir
    /// basculer" plutot que vers "on bascule vers autre chose que ce qui est
    /// monte".
    ///
    /// # Pourquoi un premier pas est consomme ici
    ///
    /// Parce que le premier candidat est LANCE par la connexion qui suit: c'est
    /// lui que `sorties_du_coeur` met en tete, donc lui que le selecteur sert.
    /// Une course qui le garderait dans ses restants le proposerait une seconde
    /// fois a la premiere perte, et on basculerait vers la sortie qui vient
    /// justement d'echouer.
    fn course_pour(
        &self,
        portage: &Portage,
        plan: &bifrost_evasion::Plan,
        techniques: &[Technique],
        demarche: &Demarche,
    ) -> Option<Course> {
        if !matches!(portage, Portage::Coeur(_)) {
            return None;
        }
        let mut course = match Course::parmi(plan, techniques) {
            Ok(c) => c,
            Err(raison) => {
                tracing::debug!(%raison, "pas de course pour cette connexion");
                return None;
            }
        };
        match course.prochain_pas(gigue_de_course()) {
            Pas::Lancer(t) if Some(t) == demarche.technique() => Some(course),
            autre => {
                tracing::warn!(
                    ?autre,
                    retenue = demarche.technique().map(Technique::nom),
                    "la course et la demarche ne nomment pas la meme tete: aucune bascule ne sera possible sur cette connexion"
                );
                None
            }
        }
    }

    /// Ce qu'une perte en cours de session doit devenir.
    ///
    /// Rend `Some(motif)` quand le tunnel est vraiment perdu, `None` quand la
    /// course a de quoi continuer - une bascule est alors partie, ou une gigue
    /// court avant la suivante.
    ///
    /// C'est ICI que la degradation en cours de session du document 04 partie
    /// 3.2 cesse d'etre un nom. Les quatre sorties anticipees rendent toutes la
    /// perte telle quelle, et aucune n'est de la prudence rituelle:
    ///
    /// - voie directe: il n'y a pas de selecteur, donc rien vers quoi basculer;
    /// - [`Perte::echec`] a `None`: une mort sans signature reconnue peut etre
    ///   le serveur qui redemarre ou un Wi-Fi qui saute, et basculer la-dessus
    ///   brulerait un candidat sain a chaque coupure ordinaire;
    /// - demarche sans technique: rien n'est monte, il n'y a rien a remplacer;
    /// - pas de course: voir [`Self::course_pour`] pour les deux cas.
    fn encaisser(&mut self, perte: Perte) -> Option<String> {
        let motif = perte.motif();
        if self.voie != Voie::ParCoeur {
            return Some(motif);
        }
        let Some(echec) = perte.echec() else {
            return Some(motif);
        };
        let Some(courante) = self.demarche.technique() else {
            return Some(motif);
        };
        if !self.noter_a_la_course(courante, echec) {
            return Some(motif);
        }
        tracing::info!(
            technique = courante.nom(),
            %motif,
            "candidat perdu en cours de session: la course passe au suivant"
        );
        self.avancer_la_course()
    }

    /// Le SEUL endroit ou un echec entre dans la course, et donc le seul ou il
    /// peut atteindre le carnet.
    ///
    /// Rend faux quand il n'y a pas de course, auquel cas l'appelant n'a rien
    /// obtenu et doit le dire.
    ///
    /// # Pourquoi les deux gestes ensemble
    ///
    /// Ils ont ete separes un moment, et une falsification l'a puni: le filtre
    /// de [`Echec::accuse_le_reseau`] etait devenu du code mort, parce que le
    /// seul chemin qui produit un `NonLancable` - une bascule refusee - ne
    /// passait pas par le carnet du tout. Le filtre avait l'air de proteger
    /// quelque chose et ne protegeait rien; l'enlever ne changeait aucun
    /// resultat. Les reunir rend la regle vraie pour TOUT echec, quel que soit
    /// le chemin qui l'a produit.
    ///
    /// # Ce que le filtre ecarte, et pourquoi
    ///
    /// Un `NonLancable` est une panne CHEZ NOUS: coeur absent, requete de
    /// controle refusee. Le noter ecarterait la technique du prochain essai sur
    /// ce reseau pour une raison qui n'a rien a voir avec lui - et la panne
    /// etant locale, elle suivrait la machine sur tous les reseaux qu'elle
    /// visite, en salissant le carnet a chaque fois.
    ///
    /// Sans cle, rien n'est note: on ne sait pas sous quel nom.
    ///
    /// La ligne peut contredire celle que `connect` vient d'ecrire pour la meme
    /// technique, et c'est voulu: la reussite y est notee des la montee, avant
    /// que rien ne soit prouve. Un gel trente secondes plus tard est la mesure
    /// plus recente, et le carnet garde les deux dans l'ordre ou elles se sont
    /// produites.
    fn noter_a_la_course(&mut self, technique: Technique, echec: Echec) -> bool {
        let porte_au_carnet = echec.accuse_le_reseau();
        match self.course.as_mut() {
            Some(c) => c.noter_echec(technique, echec),
            None => return false,
        }
        // Ce candidat est juge: son observation est consommee. Sans cela la
        // fenetre qui vient de le condamner serait relue au tour suivant - la
        // gigue de course dure plusieurs tours - et reconclurait la meme chute
        // sur quelqu'un qui n'est deja plus en cause. Voir
        // `un_candidat_condamne_n_est_plus_juge_pendant_la_gigue`.
        self.observation = None;
        if !porte_au_carnet {
            return true;
        }
        let Some(cle) = self.cle.as_ref() else {
            return true;
        };
        if let Err(raison) = (self.carnetier.noter)(cle, technique, false) {
            tracing::warn!(%raison, "carnet non tenu a jour");
        }
        true
    }

    /// Consulte la course et fait ce qu'elle dit.
    ///
    /// L'appelant DOIT honorer le pas rendu: un `Lancer` qui n'est pas suivi
    /// d'une bascule laisse une technique comptee en vol qui ne conclura
    /// jamais, et la course attendra pour toujours.
    fn avancer_la_course(&mut self) -> Option<String> {
        let gigue = gigue_de_course();
        // Pas de course: rien a proposer, et donc rien de perdu non plus - le
        // tunnel qui tourne continue de tourner. Voir `course_pour`.
        let course = self.course.as_mut()?;
        match course.prochain_pas(gigue) {
            Pas::Lancer(t) => self.basculer_vers(t),
            Pas::Patienter(d) => {
                // La gigue que le plan demande deux fois. Une rafale de
                // bascules est elle-meme une signature.
                self.reprise_de_course = Some(Instant::now() + d);
                None
            }
            Pas::Epuisee => {
                let essayes = self
                    .course
                    .as_ref()
                    .map(|c| {
                        c.echoues()
                            .iter()
                            .map(|(t, e)| format!("{}: {}", t.nom(), e.motif()))
                            .collect::<Vec<_>>()
                            .join("; ")
                    })
                    .unwrap_or_default();
                Some(format!(
                    "tous les candidats de ce profil ont echoue sur ce reseau ({essayes}). Le kill switch reste arme: echouer garde est le bon echec"
                ))
            }
            // Inatteignable: le superviseur ne note jamais de reussite a la
            // course, faute de quoi elle s'arreterait et la degradation en
            // cours de session n'aurait plus rien a parcourir. Voir le champ
            // `course`.
            Pas::Etabli(_) => None,
        }
    }

    /// Met en service le candidat suivant, sans rien relancer.
    ///
    /// L'etiquette visee est le NOM de la technique, ce que
    /// [`Self::sorties_du_coeur`] garantit du cote de la configuration ecrite.
    ///
    /// La demarche suit immediatement, avant meme que le coeur ait confirme:
    /// elle designe ce que cette connexion POURSUIT, et c'est ce candidat-la
    /// qu'un refus devra accuser. La confirmation, elle, se ramasse au tour
    /// suivant.
    fn basculer_vers(&mut self, technique: Technique) -> Option<String> {
        let sortie = technique.nom();
        if !self.bascule.as_ref().is_some_and(|b| b.demander(sortie)) {
            // Panne LOCALE: aucune poignee, ou une bascule deja en vol. Le
            // reseau n'y est pour rien, donc rien n'ira au carnet - mais le
            // candidat est brule pour cette connexion, sans quoi la course
            // buterait dessus indefiniment.
            let echec = Echec::NonLancable(
                "aucune poignee de bascule disponible, ou une bascule est deja en vol".to_owned(),
            );
            if !self.noter_a_la_course(technique, echec) {
                return None;
            }
            return self.avancer_la_course();
        }
        self.demarche = Demarche::pour(technique);
        // Le candidat suivant heriterait sinon du silence de celui qu'il
        // remplace, et mourrait d'un gel qui n'est pas le sien.
        //
        // Cette remise a zero n'est PAS celle de `noter_a_la_course`, et il a
        // fallu un banc pour s'en convaincre. La condamnation consomme bien la
        // fenetre - sans quoi la meme chute serait reconclue au tour suivant -
        // mais la gigue de course dure PLUSIEURS tours de boucle, et chacun
        // reverse les compteurs: `regarder_couler` rouvre alors une fenetre,
        // qui appartient encore au candidat sortant. Un `debug_assert` mis ici
        // le 20 aout 2026 a saute sur deux essais du banc sur trois.
        self.observation = None;
        tracing::info!(sortie, "bascule demandee vers le candidat suivant");
        None
    }

    /// Ramasse le verdict d'une bascule partie au tour precedent.
    ///
    /// Un refus est une panne locale: le coeur n'a pas accepte notre requete de
    /// controle, ou il sert toujours l'ancienne sortie. Le candidat n'a pas eu
    /// sa chance, donc rien n'est porte au carnet - mais la course passe au
    /// suivant, sans quoi le trafic resterait sur la sortie gelee en attendant
    /// une confirmation qui ne viendra pas.
    fn ramasser_la_bascule(&mut self) -> Option<String> {
        let issue = self.bascule.as_mut()?.ramasser()?;
        match issue {
            crate::coeurs::bascule::Issue::Faite { sortie } => {
                tracing::info!(%sortie, "le coeur sert desormais cette sortie");
                None
            }
            crate::coeurs::bascule::Issue::Refusee { sortie, raison } => {
                tracing::warn!(%sortie, %raison, "bascule refusee: la course passe au suivant");
                let technique = self.demarche.technique()?;
                if !self.noter_a_la_course(technique, Echec::NonLancable(raison)) {
                    return None;
                }
                self.avancer_la_course()
            }
        }
    }

    /// Met en service le peripherique qui sait porter cette voie.
    ///
    /// Echange les deux boites plutot que d'en choisir une a chaque usage.
    /// Rend une erreur qui NOMME ce qui manque quand ce daemon n'a pas le
    /// chemin demande: sans cela l'exploitant verrait une connexion echouer
    /// sans savoir qu'il lui manque deux drapeaux au demarrage.
    fn mettre_en_service(&mut self, voulue: Voie) -> Result<()> {
        if self.voie == voulue {
            return Ok(());
        }
        let Some(autre) = self.en_reserve.as_mut() else {
            return Err(Error::Config(
                "ce daemon n'a pas de chemin par coeur: il a ete demarre sans --coeurs-dans ou sans --facade. Le profil demande un coeur, et monter le TUN sans rien derriere la facade ferait un chemin qui ne mene nulle part".to_owned(),
            ));
        };
        std::mem::swap(&mut self.tunnel, autre);
        self.voie = voulue;
        tracing::info!(
            voie = match voulue {
                Voie::Direct => "direct",
                Voie::ParCoeur => "par coeur",
            },
            "peripherique de tunnel mis en service"
        );
        Ok(())
    }

    /// Engendre la configuration du coeur, l'ecrit, et lance le coeur.
    ///
    /// # Pourquoi ici, et pas ailleurs
    ///
    /// APRES l'armement du kill switch, qui est l'action precedente de la meme
    /// transition et dont l'echec interrompt la suite. Le coeur trouve donc son
    /// exemption deja posee, et il n'existe aucun instant ou il tourne sans
    /// elle - c'est la propriete que decrit `IdentiteCoeur::exempter`.
    ///
    /// AVANT la montee de l'interface, parce que l'interface est ce qui envoie
    /// le systeme vers la facade. Monter d'abord ouvrirait une fenetre ou tout
    /// le trafic de la machine part vers un coeur qui n'ecoute pas encore.
    ///
    /// Un echec ici remonte tel quel: la transition s'interrompt, le tunnel
    /// n'est pas monte, et le kill switch reste arme. Echouer garde.
    fn lancer_le_coeur(&self, profils: &Profils) -> Result<()> {
        use crate::coeurs::{configuration, lancement};

        let Demarche::ParCoeur { coeur, .. } = self.demarche else {
            // Inatteignable: `refus` a deja ecarte tout autre accord. Le dire
            // plutot que de paniquer garde le daemon debout si la regle et
            // cette fonction devaient un jour diverger.
            return Err(Error::Config(
                "aucun coeur retenu par la couche de decision: rien a lancer".to_owned(),
            ));
        };
        let Some(atelier) = self.atelier.as_ref() else {
            return Err(Error::Config(
                "ce daemon tourne sans atelier des coeurs: aucun coeur ne peut etre lance"
                    .to_owned(),
            ));
        };
        let Some(l) = self.lancement_coeur.as_ref() else {
            return Err(Error::Config(
                "ce daemon n'a pas de quoi lancer un coeur: ni repertoire de binaires, ni port SOCKS"
                    .to_owned(),
            ));
        };

        // TOUTES les sorties, derriere le meme selecteur, et la retenue en
        // tete. `sing_box_avec` fait de la premiere le defaut du selecteur,
        // donc cet ordre EST la decision - il n'y a pas de second endroit ou
        // elle serait appliquee, ni de risque qu'ils divergent.
        //
        // Les autres ne coutent rien tant que le selecteur ne les designe pas:
        // sing-box n'ouvre une socket que sur la sortie active. Elles sont la
        // pour que la bascule se fasse SANS relancer le coeur, donc sans que le
        // SOCKS local bouge ni que le kill switch soit leve - les deux
        // conditions du document 04 partie 3.2 pour une bascule en session.
        let sorties = self.sorties_du_coeur(profils);
        let etiquettes: Vec<String> = sorties.iter().map(|s| s.tag().to_owned()).collect();
        let valeur = configuration::sing_box_avec(
            &configuration::Parametres {
                socks: l.socks.adresse.port(),
                api: l.api,
                secret: l.secret.clone(),
                identifiants: l.socks.identifiants.clone(),
                selecteur: SELECTEUR.to_owned(),
                sorties: etiquettes,
                // Toutes les sorties quittent la machine par le MEME lien
                // physique; la destination ne sert qu'a interroger la table de
                // routage, et n'importe laquelle rend la meme reponse. Celle de
                // la sortie retenue, donc, plutot qu'un choix a expliquer.
                lier_a: interface_de_sortie_du_coeur(profils.tous().next().expect("jamais vide")),
            },
            &sorties,
        );

        let mut prepare = lancement::preparer(&l.emplacements, coeur, l.api);
        // Le compte du coeur vient de la MEME valeur que l'exemption posee a
        // l'armement. C'est ce qui rend leur divergence impossible plutot
        // qu'improbable.
        self.coeur.appliquer(&mut prepare);

        // L'absence du binaire se dit ICI, avec son chemin. Laisser `spawn`
        // echouer plus loin rendrait "No such file or directory" sans dire
        // lequel, au milieu d'une connexion.
        if !lancement::binaire_present(&prepare) {
            return Err(Error::Config(format!(
                "coeur introuvable: {} n'existe pas ou n'est pas un fichier",
                prepare.programme.display()
            )));
        }
        // Le prefixe `MARQUEUR_COEUR` n'est pas cosmetique: c'est ce que
        // `is_retryable` reconnait pour ne PAS retenter. Voir la ou il est lu.
        configuration::ecrire(&prepare.configuration, &valeur).map_err(|e| {
            Error::Tunnel(format!("{MARQUEUR_COEUR}: configuration non ecrite: {e}"))
        })?;

        let vivant = atelier
            .lancer(coeur, prepare, &l.secret, l.socks.adresse)
            .map_err(|e| Error::Tunnel(format!("{MARQUEUR_COEUR}: {e}")))?;
        tracing::info!(
            coeur = coeur.executable(),
            pid = ?vivant.pid,
            socks = %l.socks.adresse,
            "coeur lance: il porte desormais la connexion"
        );
        Ok(())
    }

    fn disconnect(&mut self) -> Result<()> {
        self.push(Event::Disconnect);
        self.pump();
        self.retry_at = None;

        // Le coeur meurt avec la connexion. Un coeur qui survivrait a la
        // deconnexion garderait son ecoute SOCKS locale ouverte, donc une
        // sortie que plus personne ne supervise, pendant que l'utilisateur
        // croit avoir tout coupe. La garde du systeme (Job, PDEATHSIG) ne
        // couvre que la mort du DAEMON, pas une simple deconnexion.
        //
        // Un echec ici ne masque pas l'etat du kill switch, qui est verifie
        // juste apres: les deux problemes sont distincts et se disent
        // separement.
        if let Some(atelier) = &self.atelier
            && let Err(raison) = atelier.arreter()
        {
            tracing::error!(%raison, "coeur non arrete a la deconnexion");
        }

        // Le seul echec qui compte ici: des filtres encore en place alors que
        // l'utilisateur croit etre deconnecte. Le silence serait pire.
        match self.firewall.is_engaged() {
            Ok(true) => Err(Error::Firewall(
                "le kill switch n'a pas pu etre retire: le trafic reste bloque".into(),
            )),
            Ok(false) => Ok(()),
            Err(e) => Err(e),
        }
    }

    fn status(&mut self) -> TunnelStatus {
        let engaged = self.firewall.is_engaged().unwrap_or(false);
        let cfg = self.machine.config().cloned();

        let (last_handshake_secs_ago, rx_bytes, tx_bytes) = match &cfg {
            Some(cfg) => match self.tunnel.handshake(cfg) {
                Ok(Some(h)) => {
                    let ago = h.last_handshake.and_then(|t| {
                        SystemTime::now()
                            .duration_since(t)
                            .ok()
                            .map(|d| d.as_secs())
                    });
                    (ago, h.rx_bytes, h.tx_bytes)
                }
                _ => (None, 0, 0),
            },
            None => (None, 0, 0),
        };

        TunnelStatus {
            state: self.machine.state().clone(),
            kill_switch_engaged: engaged,
            firewall_backend: self.firewall.backend().to_owned(),
            interface: cfg.as_ref().map(|c| c.interface.clone()),
            endpoint: cfg
                .as_ref()
                .and_then(|c| c.portage.wireguard())
                .map(|w| w.peer.endpoint.to_string()),
            last_handshake_secs_ago,
            rx_bytes,
            tx_bytes,
        }
    }

    /// Appele a chaque tour de boucle: echeance de reprise, sante du tunnel.
    fn tick(&mut self) {
        if let Some(at) = self.retry_at
            && Instant::now() >= at
        {
            self.retry_at = None;
            self.push(Event::RetryTimer);
        }

        // Le verdict d'une bascule partie au tour precedent. AVANT
        // l'observation: le candidat qu'elle refuserait doit etre remplace
        // avant qu'on lui reproche un silence dont il n'est pas responsable.
        if let Some(motif) = self.ramasser_la_bascule() {
            self.push(Event::TunnelLost { reason: motif });
        }

        // La gigue est passee: la course peut proposer le candidat suivant.
        if let Some(at) = self.reprise_de_course
            && Instant::now() >= at
        {
            self.reprise_de_course = None;
            if let Some(motif) = self.avancer_la_course() {
                self.push(Event::TunnelLost { reason: motif });
            }
        }

        match self.machine.state().clone() {
            State::Connecting { .. } => self.poll_handshake(false),
            State::Connected => self.poll_handshake(true),
            _ => {}
        }

        self.pump();
    }

    fn poll_handshake(&mut self, established: bool) {
        let Some(cfg) = self.machine.config().cloned() else {
            return;
        };
        match self.tunnel.handshake(&cfg) {
            Ok(Some(h)) if h.is_alive(SystemTime::now()) => {
                if !established {
                    self.push(Event::HandshakeOk);
                } else if let Some(perte) = self.regarder_couler(&h)
                    && let Some(motif) = self.encaisser(perte)
                {
                    // La course n'avait rien a proposer. C'est seulement
                    // maintenant que le tunnel est perdu.
                    self.push(Event::TunnelLost { reason: motif });
                }
            }
            Ok(Some(_)) if established => {
                self.push(Event::TunnelLost {
                    reason: "aucun handshake depuis plus de 180 s".into(),
                });
            }
            Ok(None) if established => {
                self.push(Event::TunnelLost {
                    reason: format!("l'interface {} a disparu", cfg.interface),
                });
            }
            Ok(_) => {}
            Err(e) => {
                // Le message vient du peripherique et dit ce qui ne va
                // pas: une lecture impossible pour WireGuard, un coeur disparu
                // pour un tunnel par coeur. Le journal ne prejuge donc de rien.
                tracing::warn!(error = %e, "tunnel non concluant");
                if established {
                    self.push(Event::TunnelLost {
                        reason: e.to_string(),
                    });
                }
            }
        }
    }

    /// Verse les compteurs du tunnel a l'observateur et rend ce qu'il conclut.
    ///
    /// C'est ici que les criteres d'echec EN COURS DE SESSION du document 04
    /// deviennent autre chose que des noms: [`bifrost_evasion::observation`]
    /// porte toute la politique, ce corps ne fait que lui donner a manger. Il
    /// est appele au rythme de `POLL_INTERVAL`, deja en place pour la vitalite
    /// du handshake, donc cette detection ne coute aucun reveil de plus.
    ///
    /// # Ce que les deux chemins donnent, et ce qu'ils ne donnent pas
    ///
    /// Pour WireGuard, `rx_bytes` et `tx_bytes` comptent le trafic CHIFFRE de
    /// l'interface, donc ce que le pair a reellement rendu. Pour un chemin par
    /// coeur, ils comptent le trafic de l'interface TUN, donc le trafic EN
    /// CLAIR entre la machine et le passeur - un cran en deca du transport
    /// exterieur. Un rideau qui tombe sur le transport se voit quand meme, mais
    /// une seconde plus tard et a travers une pile locale.
    ///
    /// # La sonde, et pourquoi les DEUX criteres en dependent
    ///
    /// [`Verdict::Sonder`] demande un aller-retour reel vers le pair, seule
    /// facon de distinguer un tunnel inactif d'un tunnel gele - l'en-tete de
    /// `observation` explique pourquoi aucun comptage ne le peut. Le fil du
    /// superviseur etant synchrone, il ne l'emet pas: il la DEMANDE d'un cote
    /// et la RAMASSE de l'autre, par [`crate::coeurs::vitalite`].
    ///
    /// La tentation serait de repondre avec ce qu'on a sous la main:
    /// `HandshakeInfo::last_handshake`. Pour WireGuard il dit vrai, et
    /// [`Self::demander_au_pair`] s'en sert. Pour un chemin par coeur,
    /// [`crate::tunnel::coeur::CoeurTunnel`] le FABRIQUE - il n'y a pas de
    /// poignee de main periodique la-bas - donc il repondrait toujours "le pair
    /// est vivant". Une reponse toujours positive est pire que pas de reponse:
    /// elle a l'air d'une mesure.
    ///
    /// Une version de ce commentaire ajoutait que le critere de DEBIT, lui, ne
    /// demandait rien au pair et "se lisait entierement dans les compteurs".
    /// C'etait vrai du code et faux du monde: un debit recu est un produit de
    /// ce que le reseau livre ET de ce que la machine demande, et une machine
    /// au repos se lisait comme un tunnel etrangle. Mesure le 21 aout 2026,
    /// corrigee le meme jour. Les deux criteres passent desormais par la meme
    /// sonde.
    fn regarder_couler(&mut self, h: &bifrost_core::ports::HandshakeInfo) -> Option<Perte> {
        let (depuis, _) = self
            .observation
            .get_or_insert_with(|| (Instant::now(), Observateur::nouveau()));
        let age = depuis.elapsed();
        self.verser(h, age)
    }

    /// La meme chose sans lire l'horloge, pour que la recette puisse choisir le
    /// temps qui passe.
    ///
    /// Le decoupage n'est pas une commodite de test: c'est le partage que tout
    /// ce depot applique, et que `bifrost-evasion` applique deja a la gigue de
    /// la course. Une detection qui ne se mesure qu'en attendant trente
    /// secondes de vrai temps ne se mesure pas.
    fn verser(&mut self, h: &bifrost_core::ports::HandshakeInfo, age: Duration) -> Option<Perte> {
        let (_, observateur) = self
            .observation
            .get_or_insert_with(|| (Instant::now(), Observateur::nouveau()));
        let echantillon = Echantillon {
            age,
            emis: h.tx_bytes,
            recus: h.rx_bytes,
        };
        // Le verdict d'une sonde partie au tour precedent, s'il est arrive.
        // Avant d'observer: sans quoi l'echantillon serait juge alors qu'une
        // reponse attend deja, et le silence paraitrait durer plus longtemps
        // qu'il ne dure.
        if let Some(issue) = self.sonde.as_mut().and_then(|s| s.ramasser()) {
            // Se dit AUSSI quand tout va bien. Une sonde qui aboutit ne change
            // rien a l'etat et ne laissait donc aucune trace: trois situations
            // devenaient indiscernables dans un journal - la sonde est partie
            // et le pair a repondu, la sonde n'est jamais partie, il n'y a pas
            // d'observateur du tout. Le banc en a besoin pour prouver qu'un
            // tunnel au repos DECLENCHE bien la question, et pas seulement
            // qu'il n'est pas condamne: sans cette ligne, un critere mort et un
            // critere qui marche s'ecrivent pareil.
            tracing::debug!(?issue, "sonde de vitalite: verdict rendu");
            if let Verdict::Perdu(p) = observateur.noter_sonde(issue) {
                return Some(p);
            }
        }

        match observateur.observer(echantillon, cadence_de_sonde()) {
            Verdict::Rien => None,
            Verdict::Sonder { budget } => self.demander_au_pair(h, budget),
            Verdict::Perdu(p) => Some(p),
        }
    }

    /// Repond a [`Verdict::Sonder`] avec ce que la voie courante detient
    /// vraiment.
    ///
    /// # WireGuard: la reponse est deja la, et elle n'a rien coute
    ///
    /// Le protocole renouvelle sa poignee de main AVEC le pair. Une poignee
    /// plus recente que le debut du silence est donc un aller-retour reel,
    /// deja fait et deja paye: le pair a repondu PENDANT le silence, et il n'y
    /// a rien a emettre pour le savoir. C'est la comparaison qui compte, pas
    /// l'age absolu: une poignee vieille de deux minutes prouve la vie d'un
    /// tunnel silencieux depuis dix secondes, et ne prouve rien d'un tunnel
    /// silencieux depuis cinq minutes.
    ///
    /// # Par coeur: il faut demander, et c'est le coeur qui demande
    ///
    /// `last_handshake` y est FABRIQUE - il n'existe pas de poignee de main
    /// periodique derriere un coeur - donc il repondrait toujours oui. Voir
    /// [`crate::coeurs::vitalite`] pour ce que la sonde traverse et pourquoi
    /// ce n'est pas le daemon qui l'emet.
    ///
    /// Sans poignee de sonde - un daemon monte sans chemin par coeur, ce qui ne
    /// devrait pas coexister avec une voie par coeur - on rend `Impossible`.
    /// Ne rien rendre du tout laisserait la sonde en vol pour toujours, et le
    /// tunnel definitivement insondable.
    fn demander_au_pair(
        &mut self,
        h: &bifrost_core::ports::HandshakeInfo,
        budget: Duration,
    ) -> Option<Perte> {
        // Le pendant de la trace du verdict, en amont: elle seule distingue
        // "aucune sonde n'a ete demandee" de "la sonde n'a pas rendu".
        tracing::debug!(
            voie = ?self.voie,
            budget_ms = budget.as_millis(),
            "sonde de vitalite demandee"
        );
        if self.voie == Voie::Direct {
            let silence = self
                .observation
                .as_ref()
                .map_or(Duration::ZERO, |(_, o)| o.silence());
            let repondu = h
                .last_handshake
                .and_then(|t| SystemTime::now().duration_since(t).ok())
                .is_some_and(|age| age <= silence);
            let issue = if repondu {
                Sonde::Aboutie
            } else {
                Sonde::Echouee
            };
            return match self.noter(issue) {
                Verdict::Perdu(p) => Some(p),
                _ => None,
            };
        }

        let demandee = self.sonde.as_ref().is_some_and(|s| s.demander(budget));
        if demandee {
            return None;
        }
        tracing::warn!(
            "aucune sonde de vitalite disponible pour ce tunnel: son gel restera invisible"
        );
        match self.noter(Sonde::Impossible) {
            Verdict::Perdu(p) => Some(p),
            _ => None,
        }
    }

    fn noter(&mut self, issue: Sonde) -> Verdict {
        match self.observation.as_mut() {
            Some((_, o)) => o.noter_sonde(issue),
            None => Verdict::Rien,
        }
    }

    fn push(&mut self, event: Event) {
        self.pending.push_back(event);
    }

    /// Draine la file d'evenements. Une boucle plutot qu'une recursion: un
    /// echec produit un evenement, qui peut lui-meme produire des actions.
    fn pump(&mut self) {
        let mut budget = MAX_EVENTS_PER_PUMP;
        while let Some(event) = self.pending.pop_front() {
            if budget == 0 {
                tracing::error!("boucle d'evenements: arret du pompage");
                break;
            }
            budget -= 1;

            let transition = self.machine.handle(event);
            if transition.ignored {
                continue;
            }
            tracing::info!(state = transition.state.name(), "transition");

            for action in transition.actions {
                let label = action_label(&action);
                match self.apply(action) {
                    Ok(follow_up) => {
                        for e in follow_up {
                            self.push(e);
                        }
                    }
                    Err(e) => {
                        tracing::error!(action = label, error = %e, "action en echec");
                        self.last_error = Some(e.to_string());
                        // On abandonne les actions restantes de cette
                        // transition: enchainer apres un echec, c'est monter
                        // un tunnel alors que le kill switch n'est pas pose.
                        self.push(Event::TunnelFailed {
                            reason: format!("{label}: {e}"),
                            retryable: is_retryable(label, &e),
                        });
                        break;
                    }
                }
            }
        }
    }

    fn apply(&mut self, action: Action) -> Result<Vec<Event>> {
        match action {
            Action::EngageKillSwitch(mut policy) => {
                // La machine a etats decide QUOI autoriser, pas comment le
                // systeme designe l'interface. Le LUID n'existe qu'une fois le
                // tunnel monte: c'est ici, au moment d'executer, qu'on peut le
                // demander au device. Sans lui, le kill switch Windows en
                // serait reduit a resoudre le nom, resolution qui peut echouer
                // ou arriver avant que Windows ait enregistre l'alias.
                policy.tunnel_luid = self.tunnel.interface_handle();

                // Meme raison, et une contrainte de temps opposee. Le LUID ne
                // peut etre connu qu'APRES la montee du tunnel; l'identite du
                // coeur doit etre posee AVANT qu'aucun coeur ne tourne, sans
                // quoi il faudrait soit demarrer le coeur sans exemption, soit
                // baisser le kill switch pour la lui donner. Elle est donc
                // inscrite a chaque armement, y compris le premier, qui
                // precede la montee du tunnel.
                self.coeur.exempter(&mut policy);

                // Et son oppose, pose au meme instant pour la raison
                // symetrique. La restriction du :53 ne doit exister qu'a
                // partir du moment ou un resolveur ecoute pour la recevoir:
                // posee plus tot, elle retirerait la resolution de noms; posee
                // plus tard, elle laisserait une fenetre ou n'importe quelle
                // application choisit son propre resolveur a travers le tunnel.
                self.resolveur.identite.restreindre(&mut policy);

                self.firewall.engage(&policy)?;
                Ok(Vec::new())
            }
            Action::DisengageKillSwitch => {
                self.firewall.disengage()?;
                Ok(Vec::new())
            }
            Action::BringTunnelUp(cfg) => {
                // Le coeur d'abord, l'interface ensuite. Voir l'en-tete de
                // `lancer_le_coeur` pour ce que cet ordre garantit aux deux
                // bouts.
                if let Some(profils) = cfg.portage.coeurs() {
                    self.lancer_le_coeur(profils)?;
                }
                self.tunnel.up(&cfg)?;
                Ok(vec![Event::TunnelUp])
            }
            Action::BringTunnelDown(cfg) => {
                // L'observation meurt avec le tunnel. Les compteurs d'une
                // interface neuve repartent de zero et son age aussi: un
                // observateur conserve lirait un effondrement la ou il y a eu
                // une reconnexion, et condamnerait le tunnel qui vient de
                // monter pour ce qu'a fait le precedent.
                self.observation = None;
                // Et la course avec elle, pour la meme raison: elle decrit les
                // candidats de CETTE connexion. La garder ferait basculer la
                // suivante vers un candidat que son propre plan n'a peut-etre
                // pas retenu, sur un reseau qui n'est peut-etre plus le meme.
                self.course = None;
                self.reprise_de_course = None;
                self.cle = None;
                // Et le verdict d'une sonde partie pour le tunnel precedent:
                // le ramasser plus tard le ferait porter sur le suivant.
                if let Some(s) = self.sonde.as_mut() {
                    while s.ramasser().is_some() {}
                }
                self.tunnel.down(&cfg)?;
                Ok(Vec::new())
            }
            Action::ApplyDns(cfg) => {
                // L'ORDRE est la propriete, pas un detail de mise en oeuvre.
                // Le resolveur doit repondre AVANT que quoi que ce soit ne
                // pointe sur lui: l'inverse laisserait la machine interroger
                // un port qui accepte les paquets sans y repondre encore,
                // c'est-a-dire sans resolution de noms, au moment precis de la
                // connexion. `demarrer` n'a donc pas rendu la main tant qu'une
                // requete n'a pas obtenu de reponse.
                self.demarrer_resolveur(&cfg)?;
                self.dns.apply(&cfg.interface, &cfg.dns)?;
                Ok(Vec::new())
            }
            Action::RestoreDns => {
                // Et l'ordre inverse au demontage, pour la meme raison lue a
                // l'envers: on rend d'abord au systeme sa configuration
                // d'origine, ENSUITE on arrete le resolveur. Le tuer d'abord
                // ouvrirait une fenetre ou `resolv.conf` designe un port mort.
                let restauration = self.dns.restore();
                self.arreter_resolveur();
                restauration?;
                Ok(Vec::new())
            }
            Action::ScheduleRetry(delay) => {
                tracing::info!(delay_s = delay.as_secs(), "nouvelle tentative planifiee");
                self.retry_at = Some(Instant::now() + delay);
                Ok(Vec::new())
            }
        }
    }

    /// Demarre le resolveur chiffre, quand la configuration en demande un.
    ///
    /// Ne fait rien si le profil ne declare pas `embarque`, ou si
    /// l'exploitation n'a designe ni binaire ni compte. Ce n'est pas une
    /// degradation silencieuse: sans resolveur, `resolv.conf` pointe les
    /// amonts et le :53 continue de circuler dans le tunnel, ce qui est le
    /// comportement documente et mesure.
    fn demarrer_resolveur(&mut self, cfg: &TunnelConfig) -> Result<()> {
        if !cfg.dns.embarque {
            return Ok(());
        }
        let ecoute = std::net::SocketAddr::new(cfg.dns.local_resolver, 53);
        let Some(atelier) = self.resolveur.atelier.clone() else {
            // Pas d'atelier: le profil demande que `resolv.conf` pointe la
            // boucle locale, mais c'est quelqu'un d'autre qui sert cette
            // adresse -- un dnscrypt-proxy de la distribution, un resolveur
            // deja pilote par systemd. Cas legitime, et pourtant on ne le
            // croit pas sur parole: pointer `resolv.conf` sur un port que
            // personne n'ecoute couperait la resolution de noms de la machine
            // sans qu'aucune erreur ne le dise. La question qui compte n'est
            // pas QUI a lance le resolveur, mais s'il REPOND.
            return (self.resolveur.verification)(ecoute);
        };
        // Une reconnexion repasse par ici. Arreter l'ancien avant d'en lancer
        // un autre: deux dnscrypt-proxy sur le meme :53, le second echoue a se
        // lier et le premier continue de servir avec l'ancienne configuration.
        self.arreter_resolveur();

        // Le fichier des noms refuses vit A COTE de la configuration, et non
        // dans le repertoire d'etat: l'etat est ce que le resolveur ECRIT, le
        // blocage est ce qu'il LIT. Les melanger donnerait au resolveur le
        // droit de reecrire la liste qui le contraint.
        let blocage = match cfg.dns.anti_telemetrie {
            bifrost_core::config::ProfilTelemetrie::Aucun => None,
            profil => Some((
                atelier
                    .configuration
                    .parent()
                    .unwrap_or_else(|| std::path::Path::new("."))
                    .join("blocked-names.txt"),
                profil,
            )),
        };

        let contenu = bifrost_dns::resolveur::dnscrypt_proxy_toml(
            &bifrost_dns::resolveur::ResolveurChiffre {
                ecoute,
                serveurs: atelier.serveurs.clone(),
                bootstrap: atelier.bootstrap.clone(),
                cache: atelier.etat.join("public-resolvers.md"),
                blocage: blocage.as_ref().map(|(chemin, _)| chemin.clone()),
            },
        )?;
        // La bascule est resolue AVANT d'ecrire quoi que ce soit: un compte
        // introuvable doit faire echouer la connexion tout de suite, et non
        // laisser le resolveur demarrer en root avec une regle de kill switch
        // qui ne le laissera jamais emettre.
        //
        // Sous Windows il n'y a pas de bascule d'identifiants a faire: `Bascule`
        // et son resolveur de compte sont `cfg(unix)`, parce qu'ils reposent sur
        // setuid et sur la base des comptes POSIX. Le `cfg` est ici et non
        // ailleurs pour que le chemin Unix reste lisible d'un bloc.
        #[cfg(unix)]
        let bascule = match atelier.compte.as_deref() {
            Some(nom) => Some(crate::resolveur::Bascule::pour(nom)?),
            None => None,
        };
        #[cfg(not(unix))]
        let bascule = None;
        // La liste AVANT la configuration qui la designe. L'ordre inverse
        // laisserait une fenetre ou dnscrypt-proxy, relance entre les deux,
        // lirait une configuration pointant un fichier absent.
        if let Some((chemin, profil)) = &blocage {
            let liste = bifrost_dns::telemetrie::blocked_names(*profil);
            crate::resolveur::ecrire_configuration(chemin, &liste, bascule)?;
            tracing::info!(
                fichier = %chemin.display(),
                profil = ?profil,
                entrees = bifrost_dns::telemetrie::regles(*profil).len(),
                "liste anti-telemetrie posee"
            );
        }
        crate::resolveur::ecrire_configuration(&atelier.configuration, &contenu, bascule)?;
        // Le repertoire d'etat doit exister et appartenir au resolveur AVANT
        // qu'il ne demarre: il y ecrit la liste des serveurs des sa premiere
        // seconde, et il n'a plus une seule instruction en root pour le creer.
        crate::resolveur::partager_repertoire(&atelier.etat, bascule)?;

        let en_cours = crate::resolveur::demarrer(&crate::resolveur::Lancement {
            programme: atelier.programme.clone(),
            configuration: atelier.configuration.clone(),
            ecoute,
            bascule,
            // Sous Windows, le compte de service sous lequel lancer le resolveur
            // (11b-1). C'est le meme que celui declare au kill switch, et il
            // vient de la meme source (`atelier.compte`): les faire diverger
            // donnerait un resolveur dont les requetes seraient bloquees par la
            // regle censee les laisser passer. `None` = compte du daemon.
            #[cfg(windows)]
            compte: atelier.compte.clone(),
            // 11b-2: l'etat, ce que le resolveur ECRIT (cache de la liste des
            // serveurs). `demarrer_sous_compte` l'ouvre au compte en ecriture
            // heritable a chaque lancement, et ouvre en lecture heritable le
            // repertoire de la configuration (ecart 2 du 13/09/2026:
            // dnscrypt-proxy en fait son repertoire courant): la configuration
            // et la liste anti-telemetrie qui viennent d'etre ecrites la
            // ci-dessus en heritent. Le daemon les ecrit EN PLACE (SYSTEM);
            // l'installateur ne pouvait pas les ouvrir, elles n'existaient pas
            // encore.
            #[cfg(windows)]
            etat: atelier.etat.clone(),
            // Ecart 3: le repertoire du profil est refuse comme repertoire du
            // resolveur, avant toute ACE.
            #[cfg(windows)]
            profil: atelier.profil.clone(),
        })?;
        tracing::info!(
            pid = en_cours.pid(),
            %ecoute,
            "resolveur chiffre demarre et repond"
        );
        self.resolveur.en_cours = Some(en_cours);
        Ok(())
    }

    /// Arrete le resolveur s'il tourne. Ne rend jamais d'erreur: on est sur un
    /// chemin de demontage, et un resolveur recalcitrant ne doit pas empecher
    /// la restauration du reste.
    fn arreter_resolveur(&mut self) {
        if let Some(r) = self.resolveur.en_cours.take() {
            let pid = r.pid();
            match r.arreter() {
                Ok(()) => tracing::info!(pid, "resolveur chiffre arrete"),
                Err(e) => tracing::warn!(pid, error = %e, "arret du resolveur imparfait"),
            }
        }
    }

    /// A l'arret du daemon, on ne desarme PAS le kill switch.
    ///
    /// Un daemon qui meurt ne doit pas rouvrir le trafic: c'est exactement la
    /// situation ou l'utilisateur croit etre protege. Les filtres restent en
    /// place jusqu'a un `disconnect` explicite ou un `--cleanup-firewall`.
    fn on_shutdown(&mut self) {
        if self.machine.state().expects_kill_switch() {
            tracing::warn!(
                "arret du daemon avec le kill switch arme: le trafic reste \
                 bloque. Utiliser 'bifrost-cli disconnect' ou \
                 'bifrost-daemon --cleanup-firewall' pour le retirer."
            );
        }
    }
}

fn action_label(action: &Action) -> &'static str {
    match action {
        Action::EngageKillSwitch(_) => "armement du kill switch",
        Action::DisengageKillSwitch => "desarmement du kill switch",
        Action::BringTunnelUp(_) => "montage du tunnel",
        Action::BringTunnelDown(_) => "demontage du tunnel",
        Action::ApplyDns(_) => "configuration DNS",
        Action::RestoreDns => "restauration DNS",
        Action::ScheduleRetry(_) => "planification de reprise",
    }
}

/// Un echec vaut-il la peine d'etre retente.
///
/// L'interface par laquelle le coeur doit sortir, ou `None` quand la
/// plateforme s'en charge autrement.
///
/// # Pourquoi la reponse depend du MOMENT
///
/// La route par defaut du tunnel n'existe pas encore quand `lancer_le_coeur`
/// s'execute - c'est ce que sa documentation garantit, et c'est ce qui rend
/// cette question repondable. Posee apres la montee, elle rendrait le TUN
/// lui-meme, c'est-a-dire exactement la boucle qu'elle sert a eviter.
///
/// # Ce qui n'est pas fait ici, et pourquoi
///
/// Le nom du serveur n'est PAS resolu. Le kill switch vient d'etre arme, une
/// action plus tot: une resolution partirait sur le reseau et pourrait etre
/// bloquee, ce qui ferait echouer un lancement de coeur pour une raison sans
/// rapport. `GetBestInterfaceEx`, lui, ne consulte que la table de routage et
/// n'emet rien.
///
/// Quand le serveur est deja une adresse, on demande donc la route vers la
/// destination exacte que le coeur composera. Sinon on la demande pour une
/// adresse temoin: toute adresse publique suit la meme route par defaut tant
/// qu'aucune route plus specifique n'existe, et ce chemin n'en pose aucune.
#[cfg(windows)]
fn interface_de_sortie_du_coeur(profil: &Profil) -> Option<String> {
    use std::net::{IpAddr, Ipv4Addr};

    /// TEST-NET-1, reservee a la documentation: aucune machine reelle n'est
    /// derriere, et c'est sans importance - on interroge une table, pas un
    /// hote.
    const TEMOIN: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));

    let (serveur, _) = profil.serveur();
    let dest = serveur.parse::<IpAddr>().unwrap_or(TEMOIN);
    crate::tunnel::wgnt::ipcfg::interface_de_sortie(dest)
}

/// Sous Linux l'echappement n'est pas dans la configuration du coeur mais dans
/// la table de routage, par identite: voir [`crate::tunnel::aiguillage`].
#[cfg(not(windows))]
fn interface_de_sortie_du_coeur(_profil: &Profil) -> Option<String> {
    None
}

/// Un armement de kill switch qui echoue ne se retente pas: c'est un probleme
/// de privileges ou de nftables absent, pas un alea reseau. Insister
/// masquerait la cause et laisserait l'utilisateur en boucle.
fn is_retryable(label: &str, error: &Error) -> bool {
    if label.contains("kill switch") {
        return false;
    }
    match error {
        Error::Config(_) | Error::Unsupported(_) => false,
        // Un resolveur qui refuse de demarrer n'est pas un incident passager,
        // et le retenter AGGRAVE la panne: chaque tentative refait chercher la
        // liste des serveurs chez le meme hebergeur, qui finit par repondre
        // `429 Too Many Requests`. Mesure du 17/08/2026 sur essai-linux: la boucle ne
        // convergeait jamais et affichait la meme erreur a chaque tour, en la
        // rendant un peu plus vraie a chaque fois. Mieux vaut refuser la
        // connexion en montrant ce que le resolveur a dit.
        Error::Dns(m) => {
            let m = m.to_lowercase();
            !(m.contains("n'a pas repondu")
                || m.contains("s'est arrete avant de repondre")
                || m.contains("rien n'y repond"))
        }
        Error::Tunnel(m) => {
            let m = m.to_lowercase();
            !(m.contains("module noyau")
                || m.contains("invalide")
                || m.contains("operation not permitted")
                || m.contains("permission denied")
                // Un coeur qui ne demarre pas, exactement pour la meme raison
                // que le resolveur juste au-dessus. Le retenter relance le MEME
                // binaire avec la MEME configuration et le MEME secret, que
                // nous avons ecrits nous-memes une ligne plus haut: le
                // deuxieme essai ne peut pas mieux se passer que le premier.
                // La boucle ne converge donc jamais, et chaque tour coute un
                // processus de plus.
                //
                // Mesure du 19/08/2026 sur essai-linux, en falsifiant le secret
                // de l'API dans `tests/tunnel_par_coeur.rs`: sans cette ligne,
                // `connect` rendait Ok pendant que rien n'etait monte, parce
                // que l'echec etait classe passager.
                || m.contains(MARQUEUR_COEUR))
        }
        _ => true,
    }
}

#[cfg(test)]
mod tests {

    /// Chaque transport de profil designe SA technique, et pas celle d'a cote.
    ///
    /// Ajoutee le 21 aout 2026 apres une falsification qui n'a rien casse:
    /// echanger les deux transports HTTP dans `technique_du_profil` laissait la
    /// suite entierement verte. Le defaut n'aurait pas ete visible non plus a
    /// l'usage - le tunnel serait monte pareil - mais la selection aurait juge
    /// le profil sur la MAUVAISE ligne du tableau de survie, et le nom affiche
    /// aurait menti.
    ///
    /// Les deux transports HTTP portent les memes champs: rien dans leur forme
    /// ne rattrape une correspondance inversee, seule cette recette le fait.
    #[test]
    fn chaque_transport_de_profil_designe_sa_propre_technique() {
        use bifrost_core::profil::{Hysteria2, MotDePasse, Transport, VlessSurHttp};

        let sur_http = || {
            Box::new(VlessSurHttp {
                serveur: "cdn.exemple.test".into(),
                port: 443,
                uuid: "00000000-0000-4000-8000-000000000000".parse().unwrap(),
                nom_de_serveur: "cdn.exemple.test".into(),
                hote: "cdn.exemple.test".into(),
                chemin: "/x".into(),
            })
        };
        let profil = |t| Profil {
            etiquette: "essai".into(),
            transport: t,
        };

        assert_eq!(
            technique_du_profil(&profil(Transport::VlessWebsocket(sur_http()))),
            Technique::WebsocketCdn
        );
        assert_eq!(
            technique_du_profil(&profil(Transport::VlessHttpUpgrade(sur_http()))),
            Technique::HttpUpgradeFront
        );
        assert_eq!(
            technique_du_profil(&profil(Transport::Hysteria2(Box::new(Hysteria2 {
                serveur: "exemple.test".into(),
                port: 443,
                mot_de_passe: "secret".parse::<MotDePasse>().unwrap(),
                obfs: None,
                nom_de_serveur: "exemple.test".into(),
                certificat: None,
            })))),
            Technique::Hysteria2
        );
    }
    use super::*;
    use bifrost_core::ports::FirewallPolicy;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    /// Kill switch de doublure: il ne pose rien, il enregistre les politiques
    /// qu'on lui donne. C'est ce qui permet de verifier ce que le superviseur
    /// transmet, sans toucher a nftables ni a WFP.
    struct FauxKillSwitch {
        vues: Arc<Mutex<Vec<FirewallPolicy>>>,
    }

    impl KillSwitch for FauxKillSwitch {
        fn engage(&mut self, policy: &FirewallPolicy) -> Result<()> {
            self.vues.lock().unwrap().push(policy.clone());
            Ok(())
        }
        fn disengage(&mut self) -> Result<()> {
            Ok(())
        }
        fn is_engaged(&self) -> Result<bool> {
            Ok(!self.vues.lock().unwrap().is_empty())
        }
        fn backend(&self) -> &'static str {
            "faux"
        }
    }

    /// Device de doublure qui annonce un LUID, comme le fait WireGuardNT une
    /// fois l'adaptateur cree.
    struct FauxTunnel {
        luid: Option<u64>,
    }

    impl TunnelDevice for FauxTunnel {
        fn up(&mut self, _cfg: &TunnelConfig) -> Result<()> {
            Ok(())
        }
        fn down(&mut self, _cfg: &TunnelConfig) -> Result<()> {
            Ok(())
        }
        fn handshake(
            &self,
            _cfg: &TunnelConfig,
        ) -> Result<Option<bifrost_core::ports::HandshakeInfo>> {
            Ok(None)
        }
        fn interface_handle(&self) -> Option<u64> {
            self.luid
        }
    }

    /// Device de doublure qui NOTE son nom des qu'on le monte.
    ///
    /// Le superviseur en detient deux et n'en sert qu'un. Sans temoin, un test
    /// de selection ne mesurerait que l'absence d'erreur, ce qu'un superviseur
    /// qui monte systematiquement le mauvais peripherique donne aussi.
    struct TunnelNomme {
        nom: &'static str,
        vues: Arc<Mutex<Vec<String>>>,
    }

    impl TunnelDevice for TunnelNomme {
        fn up(&mut self, _cfg: &TunnelConfig) -> Result<()> {
            self.vues.lock().unwrap().push(format!("up:{}", self.nom));
            Ok(())
        }
        fn down(&mut self, _cfg: &TunnelConfig) -> Result<()> {
            self.vues.lock().unwrap().push(format!("down:{}", self.nom));
            Ok(())
        }
        fn handshake(
            &self,
            _cfg: &TunnelConfig,
        ) -> Result<Option<bifrost_core::ports::HandshakeInfo>> {
            Ok(None)
        }
    }

    /// Une configuration portee par un coeur, dans la forme qu'un lien de
    /// partage produit.
    fn cfg_par_coeur() -> Box<TunnelConfig> {
        let mut c = cfg();
        c.interface = "bifrost0".into();
        c.portage = portage_par_coeur();
        c
    }

    /// Un superviseur minimal, juste de quoi verser des compteurs.
    fn superviseur_nu() -> Supervisor {
        Supervisor::new(
            Box::new(FauxKillSwitch {
                vues: Arc::new(Mutex::new(Vec::new())),
            }),
            Box::new(FauxTunnel { luid: None }),
            Box::new(FauxDns),
            IdentiteCoeur::default(),
            Resolveur {
                verification: |_| Ok(()),
                ..Default::default()
            },
            Equipement {
                decision: Decision::default(),
                carnetier: carnetier_muet(),
                atelier: None,
                chemin_coeur: None,
            },
        )
    }

    /// Une poignee de sonde dont les deux autres bouts restent tenus.
    ///
    /// La premiere version laissait tomber le futur rendu par `ouvrir`, ce qui
    /// emportait le recepteur des demandes: la poignee refusait alors TOUTE
    /// demande en silence, et les recettes qui verifiaient qu'une sonde etait
    /// partie passaient sans rien mesurer. La falsification l'a montre.
    fn sonde_de_recette() -> (
        crate::coeurs::vitalite::Poignee,
        tokio::sync::mpsc::Receiver<Duration>,
        tokio::sync::mpsc::Sender<crate::coeurs::vitalite::Sonde>,
    ) {
        crate::coeurs::vitalite::en_deux_bouts(4)
    }

    /// Une poignee de bascule dont les deux autres bouts restent tenus.
    ///
    /// Meme raison que [`sonde_de_recette`], et la meme falsification aurait
    /// mordu ici: sans les deux bouts, la poignee refuserait toute demande en
    /// silence et une recette qui verifie "une bascule est-elle partie"
    /// passerait sans rien mesurer.
    fn bascule_de_recette() -> (
        crate::coeurs::bascule::Poignee,
        tokio::sync::mpsc::Receiver<String>,
        tokio::sync::mpsc::Sender<crate::coeurs::bascule::Issue>,
    ) {
        crate::coeurs::bascule::en_deux_bouts(4)
    }

    fn compteurs(emis: u64, recus: u64) -> bifrost_core::ports::HandshakeInfo {
        bifrost_core::ports::HandshakeInfo {
            last_handshake: Some(SystemTime::now()),
            rx_bytes: recus,
            tx_bytes: emis,
        }
    }

    /// Le critere de DEBIT du document 04, de bout en bout: des compteurs
    /// d'interface entrent, un motif de perte sort. C'est celui des deux qui ne
    /// demande rien au pair, donc le seul qui soit vivant aujourd'hui.
    #[test]
    fn un_debit_qui_s_effondre_perd_le_tunnel_avec_un_motif_qui_le_dit() {
        let mut sup = superviseur_nu();
        let mut recus = 0u64;
        // Vingt secondes a bon debit: la reference s'etablit.
        for s in 0..=20 {
            recus = s * 100_000;
            assert_eq!(
                sup.verser(&compteurs(s * 1_000, recus), Duration::from_secs(s)),
                None,
                "condamne a {s} s alors que le tunnel coulait"
            );
        }
        // Puis l'ordre de grandeur du throttling que le document 04 chiffre.
        let mut perte = None;
        for s in 21..=40 {
            recus += 200;
            perte = sup.verser(&compteurs(s * 1_000, recus), Duration::from_secs(s));
            if perte.is_some() {
                break;
            }
        }
        let motif = perte.expect("l'effondrement doit etre vu").motif();
        assert!(motif.contains("throttling"), "{motif}");
    }

    /// Le cas que le plan aurait mal traite. Personne n'utilise le tunnel: rien
    /// n'arrive, et rien ne doit en etre conclu. Un tunnel demonte parce que
    /// son proprietaire est alle dejeuner serait un defaut bien plus visible
    /// que celui qu'on cherche.
    #[test]
    fn un_tunnel_inactif_ne_perd_jamais_le_tunnel() {
        let mut sup = superviseur_nu();
        for s in 0..=600 {
            assert_eq!(
                sup.verser(&compteurs(s * 10, 0), Duration::from_secs(s)),
                None,
                "tunnel condamne a {s} s alors qu'il n'a jamais rien recu"
            );
        }
    }

    /// Un superviseur avec une poignee de sonde, et la voie par coeur en
    /// service: c'est la configuration ou la sonde est necessaire.
    fn superviseur_par_coeur() -> (
        Supervisor,
        tokio::sync::mpsc::Receiver<Duration>,
        tokio::sync::mpsc::Sender<crate::coeurs::vitalite::Sonde>,
    ) {
        let mut sup = superviseur_nu();
        let (poignee, demandes, verdicts) = sonde_de_recette();
        sup.sonde = Some(poignee);
        sup.voie = Voie::ParCoeur;
        (sup, demandes, verdicts)
    }

    /// Des compteurs avec une poignee de main d'un age choisi.
    fn compteurs_avec_poignee(
        emis: u64,
        recus: u64,
        age: Duration,
    ) -> bifrost_core::ports::HandshakeInfo {
        bifrost_core::ports::HandshakeInfo {
            last_handshake: Some(SystemTime::now() - age),
            rx_bytes: recus,
            tx_bytes: emis,
        }
    }

    /// Verse assez de silence pour que l'observateur reclame une sonde, et rend
    /// ce que le superviseur en a fait.
    ///
    /// Le premier echantillon porte le MEME compte de recus que le second, et
    /// c'est tout le point: un compteur qui MONTE n'est pas un silence. La
    /// premiere version en versait deux differents, donc aucune sonde n'etait
    /// jamais reclamee et trois recettes passaient a vide.
    fn faire_reclamer_une_sonde(
        sup: &mut Supervisor,
        h: &bifrost_core::ports::HandshakeInfo,
    ) -> Option<Perte> {
        sup.verser(&compteurs(0, h.rx_bytes), Duration::from_secs(0));
        // Onze secondes sans un octet de plus: au-dela des dix que
        // l'observateur attend avant de demander.
        sup.verser(h, Duration::from_secs(11))
    }

    /// Sous WireGuard, la reponse a la sonde est deja la et n'a rien coute: le
    /// protocole renouvelle sa poignee de main AVEC le pair. Une poignee plus
    /// recente que le debut du silence est un aller-retour reel, deja paye.
    #[test]
    fn sous_wireguard_une_poignee_recente_repond_a_la_sonde_sans_rien_emettre() {
        let mut sup = superviseur_nu();
        assert_eq!(sup.voie, Voie::Direct);
        let h = compteurs_avec_poignee(500, 1_000, Duration::from_secs(3));
        assert_eq!(
            faire_reclamer_une_sonde(&mut sup, &h),
            None,
            "le pair a repondu il y a 3 s, pendant un silence de 11 s"
        );
    }

    /// Et une poignee ANTERIEURE au silence ne prouve rien: le pair a pu mourir
    /// depuis. C'est la comparaison qui repond, pas l'age absolu.
    #[test]
    fn sous_wireguard_une_poignee_anterieure_au_silence_condamne() {
        let mut sup = superviseur_nu();
        // Le tunnel s'est tu apres 17 000 octets: la bande du rideau.
        sup.verser(&compteurs(0, 17_000), Duration::from_secs(0));
        let h = compteurs_avec_poignee(500, 17_000, Duration::from_secs(60));
        let perte = sup
            .verser(&h, Duration::from_secs(11))
            .expect("une poignee vieille de 60 s ne prouve rien d'un silence de 11 s");
        assert!(matches!(perte, Perte::Gel { octets: 17_000 }), "{perte:?}");
    }

    /// Sur un chemin par coeur, `last_handshake` est FABRIQUE: il repondrait
    /// toujours oui. Le superviseur doit donc DEMANDER, et ne rien conclure en
    /// attendant.
    #[test]
    fn sur_un_chemin_par_coeur_la_sonde_est_demandee_et_rien_n_est_conclu() {
        let (mut sup, mut demandes, _verdicts) = superviseur_par_coeur();
        // La meme poignee FRAICHE que la recette WireGuard, et les memes octets
        // dans la bande: si le superviseur la lisait, il conclurait "vivant" et
        // n'emettrait rien du tout.
        let h = compteurs_avec_poignee(500, 17_000, Duration::from_secs(3));
        assert_eq!(faire_reclamer_une_sonde(&mut sup, &h), None);
        assert_eq!(
            demandes.try_recv().ok(),
            Some(observation::BUDGET_SONDE),
            "aucune sonde demandee: le superviseur a cru une poignee de main fabriquee"
        );
    }

    /// Le verdict arrive au tour suivant, et il conclut.
    #[test]
    fn le_verdict_d_une_sonde_echouee_perd_le_tunnel() {
        let (mut sup, mut demandes, verdicts) = superviseur_par_coeur();
        let h = compteurs_avec_poignee(500, 17_000, Duration::from_secs(3));
        assert_eq!(faire_reclamer_une_sonde(&mut sup, &h), None);
        assert!(demandes.try_recv().is_ok());

        verdicts
            .try_send(crate::coeurs::vitalite::Sonde::Echouee)
            .expect("le verdict doit entrer dans la file");
        let perte = sup
            .verser(&h, Duration::from_secs(13))
            .expect("un pair muet apres 17 000 octets est un gel");
        assert!(matches!(perte, Perte::Gel { octets: 17_000 }), "{perte:?}");
    }

    /// Et un verdict qui n'accuse pas le reseau ne conclut rien.
    #[test]
    fn le_verdict_d_une_sonde_impossible_ne_perd_pas_le_tunnel() {
        let (mut sup, mut demandes, verdicts) = superviseur_par_coeur();
        let h = compteurs_avec_poignee(500, 17_000, Duration::from_secs(3));
        faire_reclamer_une_sonde(&mut sup, &h);
        assert!(demandes.try_recv().is_ok());

        verdicts
            .try_send(crate::coeurs::vitalite::Sonde::Impossible)
            .expect("le verdict doit entrer dans la file");
        assert_eq!(
            sup.verser(&h, Duration::from_secs(13)),
            None,
            "condamne sur une panne locale"
        );
    }

    /// Un verdict qui arrive apres le demontage porterait sur le tunnel
    /// PRECEDENT. Le laisser trainer ferait condamner le suivant pour ce qu'a
    /// fait celui d'avant.
    #[test]
    fn le_demontage_jette_le_verdict_qui_attendait() {
        let (mut sup, _demandes, verdicts) = superviseur_par_coeur();
        verdicts
            .try_send(crate::coeurs::vitalite::Sonde::Echouee)
            .expect("le verdict doit entrer dans la file");

        sup.apply(Action::BringTunnelDown(cfg()))
            .expect("le demontage de doublure doit aboutir");

        assert!(
            sup.sonde.as_mut().unwrap().ramasser().is_none(),
            "un verdict du tunnel precedent attend encore"
        );
    }

    /// Sans poignee de sonde, le tunnel doit rester en service. Rendre un echec
    /// demonterait un tunnel sain pour une raison qui n'a rien a voir avec le
    /// reseau; ne rien rendre du tout laisserait la sonde en vol pour toujours.
    #[test]
    fn sans_poignee_de_sonde_un_chemin_par_coeur_n_est_pas_condamne() {
        let mut sup = superviseur_nu();
        sup.voie = Voie::ParCoeur;
        assert!(sup.sonde.is_none());
        let h = compteurs_avec_poignee(500, 17_000, Duration::from_secs(3));
        assert_eq!(faire_reclamer_une_sonde(&mut sup, &h), None);
        assert_eq!(
            sup.observation.as_ref().unwrap().1.perdu(),
            None,
            "condamne alors qu'aucune sonde n'a pu etre posee"
        );
    }

    /// L'observation meurt avec le tunnel. Sans cela, les compteurs d'une
    /// interface neuve - qui repartent de zero, et dont l'age repart de zero -
    /// seraient lus dans la fenetre du tunnel precedent, et la reconnexion
    /// serait condamnee pour ce qu'a fait celui d'avant.
    #[test]
    fn le_demontage_oublie_ce_qui_a_ete_observe() {
        let mut sup = superviseur_nu();
        for s in 0..=20 {
            sup.verser(&compteurs(s * 1_000, s * 100_000), Duration::from_secs(s));
        }
        assert!(sup.observation.is_some());

        sup.apply(Action::BringTunnelDown(cfg()))
            .expect("le demontage de doublure doit aboutir");
        assert!(
            sup.observation.is_none(),
            "l'observation a survecu au demontage"
        );
    }

    /// L'intervalle EST la politique: une cadence fixe serait le motif regulier
    /// que le document 04 partie 3.2 interdit. Cent tirages, tous dans les
    /// bornes, et pas tous identiques.
    #[test]
    fn la_cadence_des_sondes_est_tiree_et_bornee() {
        let tirages: Vec<Duration> = (0..100).map(|_| cadence_de_sonde()).collect();
        for c in &tirages {
            assert!(
                (observation::PERIODE_SONDE_MIN..=observation::PERIODE_SONDE_MAX).contains(c),
                "cadence hors bornes: {c:?}"
            );
        }
        assert!(
            tirages.iter().any(|c| *c != tirages[0]),
            "cent tirages identiques: la cadence n'est pas tiree"
        );
    }

    /// Monte un superviseur a deux voies et rend ce qui a ete monte.
    ///
    /// La demarche ne se donne plus en argument: elle se DEDUIT du profil, ce
    /// qui est precisement ce que ces recettes doivent verifier. Un profil
    /// hysteria2 qui monte la voie par coeur le prouve mieux qu'une demarche
    /// qu'on aurait posee soi-meme a cote.
    fn selection(
        decision: Decision,
        configuration: Box<TunnelConfig>,
        avec_chemin_coeur: bool,
    ) -> (Result<()>, Vec<String>, Vec<FirewallPolicy>) {
        selection_avec(decision, carnetier_muet(), configuration, avec_chemin_coeur)
    }

    /// Le meme montage, avec un carnetier qu'on observe.
    fn selection_avec(
        decision: Decision,
        carnetier: Carnetier,
        configuration: Box<TunnelConfig>,
        avec_chemin_coeur: bool,
    ) -> (Result<()>, Vec<String>, Vec<FirewallPolicy>) {
        let vues = Arc::new(Mutex::new(Vec::new()));
        let politiques = Arc::new(Mutex::new(Vec::new()));
        let mut sup = Supervisor::new(
            Box::new(FauxKillSwitch {
                vues: politiques.clone(),
            }),
            Box::new(TunnelNomme {
                nom: "direct",
                vues: vues.clone(),
            }),
            Box::new(FauxDns),
            IdentiteCoeur::default(),
            Resolveur {
                verification: |_| Ok(()),
                ..Default::default()
            },
            Equipement {
                decision,
                carnetier,
                // Pas d'atelier: le LANCEMENT ne peut donc pas aboutir, et
                // c'est voulu. Ce que ces recettes mesurent est le CHOIX du
                // peripherique, qui le precede. Le lancement lui-meme demande
                // un vrai processus, et c'est `tests/tunnel_par_coeur.rs`.
                atelier: None,
                chemin_coeur: avec_chemin_coeur.then(|| CheminCoeur {
                    tunnel: Box::new(TunnelNomme {
                        nom: "coeur",
                        vues: vues.clone(),
                    }),
                    emplacements: crate::coeurs::lancement::Emplacements {
                        binaires: std::path::PathBuf::from("/inexistant"),
                        configurations: std::path::PathBuf::from("/inexistant"),
                    },
                    socks: crate::coeurs::socks::Mandataire::nouveau(
                        "127.0.0.1:1080".parse().unwrap(),
                        crate::coeurs::socks::Identifiants::nouveaux("bifrost", "recette").unwrap(),
                    ),
                    api: 9090,
                    secret: "secret-de-recette".into(),
                    // La poignee suffit: son futur n'est pas lance, donc rien
                    // ne repondra jamais. Ces recettes mesurent le CHOIX du
                    // peripherique, pas la vitalite.
                    sonde: sonde_de_recette().0,
                    bascule: bascule_de_recette().0,
                }),
            },
        );
        let issue = sup.connect(configuration);
        let montes = vues.lock().unwrap().clone();
        let posees = politiques.lock().unwrap().clone();
        (issue, montes, posees)
    }

    /// Un profil WireGuard monte la voie directe, meme quand l'autre existe.
    #[test]
    fn un_profil_wireguard_monte_la_voie_directe() {
        let (issue, montes, _) = selection(Decision::default(), cfg(), true);
        issue.expect("un tunnel direct doit monter");
        assert_eq!(montes, vec!["up:direct"], "la voie directe, et elle seule");
    }

    /// Le coeur de ce chantier: un profil de coeur met en service l'AUTRE
    /// peripherique.
    ///
    /// Le lancement echoue ensuite, faute d'atelier, et c'est ce qui rend la
    /// mesure lisible: si la selection n'avait pas eu lieu, c'est le
    /// peripherique direct qui serait monte, et il aurait REUSSI. Une
    /// connexion qui aboutit serait ici la preuve du defaut.
    #[test]
    fn un_profil_de_coeur_met_en_service_l_autre_peripherique() {
        let (issue, montes, posees) = selection(Decision::default(), cfg_par_coeur(), true);
        let e = issue.expect_err("sans atelier, le coeur ne peut pas etre lance");
        assert!(
            e.to_string().contains("atelier"),
            "l'erreur doit nommer ce qui manque: {e}"
        );
        assert!(
            !montes.iter().any(|m| m == "up:direct"),
            "le peripherique direct n'a rien a faire ici: {montes:?}"
        );
        assert!(
            !montes.iter().any(|m| m == "up:coeur"),
            "et le TUN ne monte pas devant un coeur qui n'a pas demarre: {montes:?}"
        );
        // Le kill switch, lui, est bien reste arme: echouer garde.
        assert!(
            !posees.is_empty(),
            "l'armement precede le lancement et ne se defait pas sur son echec"
        );
    }

    /// Sans chemin par coeur, le refus NOMME les deux drapeaux manquants.
    ///
    /// Un refus muet enverrait l'exploitant chercher la panne dans le profil ou
    /// dans le serveur, alors qu'il manque deux arguments au demarrage.
    #[test]
    fn sans_chemin_par_coeur_le_refus_nomme_les_drapeaux() {
        let (issue, montes, posees) = selection(Decision::default(), cfg_par_coeur(), false);
        let e = issue.expect_err("ce daemon n'a pas de chemin par coeur");
        let e = e.to_string();
        assert!(e.contains("--coeurs-dans"), "{e}");
        assert!(e.contains("--facade"), "{e}");
        assert!(montes.is_empty(), "rien ne doit etre monte: {montes:?}");
        assert!(
            posees.is_empty(),
            "et rien ne doit etre arme: le refus tombe a la porte"
        );
    }

    struct FauxDns;

    impl DnsManager for FauxDns {
        fn apply(
            &mut self,
            _interface: &str,
            _policy: &bifrost_core::config::DnsPolicy,
        ) -> Result<()> {
            Ok(())
        }
        fn restore(&mut self) -> Result<()> {
            Ok(())
        }
        fn backend(&self) -> &'static str {
            "faux"
        }
    }

    fn cfg() -> Box<TunnelConfig> {
        let mut s: String = std::iter::repeat_n('A', 42).collect();
        s.push('A');
        s.push('=');
        let cle: bifrost_core::config::WgKey = s.parse().unwrap();
        Box::new(TunnelConfig {
            interface: "wg0".into(),
            addresses: vec!["10.2.0.2/32".parse().unwrap()],
            mtu: 1420,
            dns: bifrost_core::config::DnsPolicy {
                local_resolver: "127.0.0.1".parse().unwrap(),
                upstream: vec!["9.9.9.9".parse().unwrap()],
                embarque: false,
                anti_telemetrie: bifrost_core::config::ProfilTelemetrie::Aucun,
            },
            allow_lan: false,
            portage: bifrost_core::config::Portage::Wireguard(Box::new(
                bifrost_core::config::WireguardParams {
                    private_key: cle.clone(),
                    fwmark: 0xca6c,
                    routing_table: 51820,
                    listen_port: None,
                    peer: bifrost_core::config::PeerConfig {
                        public_key: cle,
                        preshared_key: None,
                        endpoint: bifrost_core::config::Endpoint {
                            addr: "203.0.113.7:51820".parse().unwrap(),
                        },
                        allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
                        persistent_keepalive: 25,
                    },
                },
            )),
        })
    }

    fn connecte(luid: Option<u64>) -> Vec<FirewallPolicy> {
        connecte_avec(luid, IdentiteCoeur::default())
    }

    fn connecte_avec(luid: Option<u64>, coeur: IdentiteCoeur) -> Vec<FirewallPolicy> {
        connecte_avec_les_deux(luid, coeur, IdentiteResolveur::default())
    }

    fn connecte_avec_les_deux(
        luid: Option<u64>,
        coeur: IdentiteCoeur,
        resolveur: IdentiteResolveur,
    ) -> Vec<FirewallPolicy> {
        connecte_complet(luid, coeur, resolveur, false)
    }

    fn connecte_complet(
        luid: Option<u64>,
        coeur: IdentiteCoeur,
        resolveur: IdentiteResolveur,
        embarque: bool,
    ) -> Vec<FirewallPolicy> {
        let vues = Arc::new(Mutex::new(Vec::new()));
        let mut sup = Supervisor::new(
            Box::new(FauxKillSwitch { vues: vues.clone() }),
            Box::new(FauxTunnel { luid }),
            Box::new(FauxDns),
            coeur,
            Resolveur {
                identite: resolveur,
                // Doublure: un resolveur est cense repondre. Ce que ces
                // recettes mesurent est ce que le superviseur ECRIT dans la
                // politique, pas la disponibilite d'un port sur le runner.
                verification: |_| Ok(()),
                ..Default::default()
            },
            Equipement {
                decision: Decision::default(),
                carnetier: carnetier_muet(),
                atelier: None,
                chemin_coeur: None,
            },
        );
        let mut configuration = cfg();
        configuration.dns.embarque = embarque;
        sup.connect(configuration).expect("connexion");
        vues.lock().unwrap().clone()
    }

    /// Un lien REALITY de documentation. Adresse RFC 5737, clef factice.
    fn lien_reality() -> String {
        format!(
            "vless://4292f5ab-8963-476c-8052-3615895ce4f1@203.0.113.9:443?security=reality&flow=xtls-rprx-vision&encryption=none&fp=chrome&type=tcp&pbk={}&sid=d8c6b58bcbb0c323&sni=exemple.test#Essai",
            "a".repeat(43)
        )
    }

    /// Un profil REALITY, la seule technique qui ne survive pas a une
    /// interception TLS. Adresse RFC 5737, clef de documentation.
    fn cfg_reality() -> Box<TunnelConfig> {
        let profil = Profil::depuis_lien(&lien_reality()).expect("ce lien doit se lire");
        let mut c = cfg();
        c.interface = "bifrost0".into();
        c.portage = Portage::Coeur(Box::new(profil.into()));
        c
    }

    /// Le pont ferme: le verdict mesure HORS de ce processus pese sur la
    /// selection.
    ///
    /// `mitm_tls` est le seul champ de l'`Environnement` que le daemon ne
    /// mesure pas lui-meme - `tests/frontiere_reseau.rs` lui interdit une pile
    /// TLS - donc le seul qui lui arrive du dehors. REALITY est la seule
    /// technique qui n'y survive pas: le proxy termine le TLS, donc le
    /// ClientHello camoufle n'atteint jamais le serveur.
    #[test]
    fn le_verdict_d_inspection_tls_ecarte_reality_a_la_prochaine_connexion() {
        let (avant, _, _) = selection(Decision::default(), cfg_reality(), true);
        let avant = avant
            .expect_err("sans atelier, rien ne se lance")
            .to_string();
        assert!(
            !avant.contains("intercepte"),
            "sans verdict, rien ne doit ecarter REALITY: {avant}"
        );

        let apres = selection_avec_verdict(cfg_reality(), true);
        let apres = apres.expect_err("REALITY doit etre ecartee").to_string();
        assert!(
            apres.contains("vless-reality-vision") && apres.contains("intercepte"),
            "le refus doit nommer la technique et l'interception: {apres}"
        );
    }

    /// L'asymetrie, la meme que partout ailleurs ici: seule une mesure elimine,
    /// et "pas d'interception" n'elimine personne.
    ///
    /// Sans ce temoin, la recette ci-dessus serait satisfaite par un daemon qui
    /// refuse REALITY des qu'un verdict, quel qu'il soit, lui parvient.
    #[test]
    fn un_verdict_a_faux_n_ecarte_rien() {
        let issue = selection_avec_verdict(cfg_reality(), false);
        let e = issue
            .expect_err("sans atelier, rien ne se lance")
            .to_string();
        assert!(
            !e.contains("intercepte"),
            "un TLS sain ne doit ecarter aucune technique: {e}"
        );
    }

    /// Monte un superviseur, lui annonce un verdict d'inspection TLS, puis
    /// tente la connexion.
    fn selection_avec_verdict(configuration: Box<TunnelConfig>, intercepte: bool) -> Result<()> {
        let mut sup = Supervisor::new(
            Box::new(FauxKillSwitch {
                vues: Arc::new(Mutex::new(Vec::new())),
            }),
            Box::new(FauxTunnel { luid: None }),
            Box::new(FauxDns),
            IdentiteCoeur::default(),
            Resolveur {
                verification: |_| Ok(()),
                ..Default::default()
            },
            Equipement {
                decision: Decision::default(),
                carnetier: carnetier_muet(),
                atelier: None,
                chemin_coeur: None,
            },
        );
        sup.noter_le_verdict_tls(intercepte);
        sup.connect(configuration)
    }

    /// Un profil qui propose LES DEUX transports.
    fn profils_a_deux() -> Profils {
        let reality = Profil::depuis_lien(&lien_reality()).expect("ce lien doit se lire");
        let hysteria2 = Profil::depuis_lien(
            "hysteria2://mot-de-passe-de-documentation@203.0.113.8:8443/?sni=exemple.test#Essai",
        )
        .expect("ce lien doit se lire");
        // REALITY EN PREMIER dans le fichier: les recettes ci-dessous verifient
        // que cet ordre-la ne decide de rien.
        Profils::try_from(vec![reality, hysteria2]).expect("deux transports distincts")
    }

    fn cfg_a_deux_coeurs() -> Box<TunnelConfig> {
        let mut c = cfg();
        c.interface = "bifrost0".into();
        c.portage = Portage::Coeur(Box::new(profils_a_deux()));
        c
    }

    /// Un superviseur en cours de session par coeur, avec DEUX candidats et
    /// les deux autres bouts de sa bascule.
    ///
    /// La demarche et la course ne sont pas fabriquees a la main: elles sortent
    /// de `arbitrer`, comme en production. Une course posee de force
    /// mesurerait ce que la recette a ecrit, pas ce que la selection decide.
    fn superviseur_en_course() -> (
        Supervisor,
        tokio::sync::mpsc::Receiver<String>,
        tokio::sync::mpsc::Sender<crate::coeurs::bascule::Issue>,
    ) {
        let mut sup = superviseur_nu();
        let (poignee, demandes, verdicts) = bascule_de_recette();
        sup.bascule = Some(poignee);
        sup.voie = Voie::ParCoeur;
        let cfg = cfg_a_deux_coeurs();
        let (demarche, course) = sup.arbitrer(&cfg.portage, None);
        sup.demarche = demarche;
        sup.course = course;
        sup.cle = Some(CleReseau::nouvelle("banc", "192.168.1.1", None));
        (sup, demandes, verdicts)
    }

    /// Fait passer la gigue et rend la main a la course.
    ///
    /// `avant` est l'instant pris JUSTE avant la perte: l'echeance posee par la
    /// course vaut `Instant::now() + gigue`, donc elle est necessairement au
    /// moins `avant + gigue`. La comparaison est exacte et ne peut pas
    /// clignoter, contrairement a une mesure prise apres coup.
    fn laisser_passer_la_gigue(sup: &mut Supervisor, avant: Instant) {
        let echeance = sup
            .reprise_de_course
            .expect("la course devait demander a patienter");
        assert!(
            echeance >= avant + bifrost_evasion::selection::JITTER_MIN,
            "l'attente doit etre une VRAIE gigue: une rafale de bascules est elle-meme une signature"
        );
        sup.reprise_de_course = Some(Instant::now());
        sup.tick();
    }

    /// Le coeur de ce chantier: une perte avec signature ne perd plus le
    /// tunnel, elle change de sortie.
    ///
    /// Document 04 partie 3.2, "degradation en cours de session". Sans cela, un
    /// gel a 16 Ko demontait tout et rearmait une connexion complete, alors que
    /// le candidat suivant etait deja ecrit derriere le meme selecteur.
    #[test]
    fn une_perte_avec_signature_bascule_au_lieu_de_perdre_le_tunnel() {
        let (mut sup, mut demandes, _verdicts) = superviseur_en_course();
        assert_eq!(
            sup.demarche.technique(),
            Some(Technique::RealityVision),
            "le plan retient REALITY sur un reseau non censure"
        );

        let avant = Instant::now();
        assert_eq!(
            sup.encaisser(Perte::Gel { octets: 17_000 }),
            None,
            "un gel avec un candidat en reserve ne perd pas le tunnel"
        );
        assert!(
            demandes.try_recv().is_err(),
            "la gigue precede la bascule: une rafale est elle-meme une signature"
        );

        laisser_passer_la_gigue(&mut sup, avant);
        assert_eq!(
            demandes.try_recv().ok().as_deref(),
            Some("hysteria2"),
            "le selecteur devait passer au candidat suivant"
        );
        assert_eq!(
            sup.demarche.technique(),
            Some(Technique::Hysteria2),
            "la demarche designe ce que la connexion poursuit"
        );
    }

    /// Une mort sans signature ne bascule pas.
    ///
    /// [`Perte::Muet`] peut etre le censeur, mais aussi le serveur qui
    /// redemarre, un Wi-Fi qui saute ou un NAT recycle. Basculer la-dessus
    /// brulerait un candidat sain a chaque coupure ordinaire, et de proche en
    /// proche toute la liste.
    #[test]
    fn une_perte_sans_signature_ne_bascule_pas() {
        let (mut sup, mut demandes, _verdicts) = superviseur_en_course();
        assert!(
            sup.encaisser(Perte::Muet { octets: 4_000 }).is_some(),
            "sans signature, le tunnel est perdu comme avant"
        );
        assert!(demandes.try_recv().is_err(), "rien ne devait basculer");
    }

    /// Une voie directe n'a pas de selecteur, donc rien vers quoi basculer.
    #[test]
    fn une_voie_directe_ne_bascule_jamais() {
        let (mut sup, mut demandes, _verdicts) = superviseur_en_course();
        sup.voie = Voie::Direct;
        assert!(
            sup.encaisser(Perte::Gel { octets: 17_000 }).is_some(),
            "un tunnel WireGuard gele est perdu: il n'y a pas de second candidat derriere lui"
        );
        assert!(demandes.try_recv().is_err(), "rien ne devait basculer");
    }

    /// Quand la liste est epuisee, le tunnel est perdu et le motif NOMME
    /// chaque echec.
    ///
    /// Un "tunnel perdu" sans detail ferait chercher la panne du mauvais cote:
    /// deux techniques ont ete essayees, chacune pour une raison mesuree.
    #[test]
    fn la_course_epuisee_perd_le_tunnel_en_nommant_chaque_echec() {
        let (mut sup, mut demandes, _verdicts) = superviseur_en_course();
        let avant = Instant::now();
        assert_eq!(sup.encaisser(Perte::Gel { octets: 17_000 }), None);
        laisser_passer_la_gigue(&mut sup, avant);
        assert_eq!(demandes.try_recv().ok().as_deref(), Some("hysteria2"));

        let motif = sup
            .encaisser(Perte::Debit {
                avant: 800_000,
                maintenant: 12,
            })
            .expect("plus aucun candidat: le tunnel est perdu");
        assert!(
            motif.contains("vless-reality-vision") && motif.contains("hysteria2"),
            "le motif doit nommer les deux echecs: {motif}"
        );
        assert!(
            motif.contains("kill switch reste arme"),
            "echouer garde est le bon echec: {motif}"
        );
    }

    /// Une perte, une condamnation.
    ///
    /// Mesure le 20 aout 2026 sur le banc de bascule en session: le journal
    /// portait DEUX "candidat perdu" pour un seul gel, a une seconde d'ecart.
    /// Entre les deux, la gigue de course, qui dure plusieurs tours de boucle.
    /// L'observation survivait a la condamnation, donc le tour suivant relisait
    /// la meme fenetre, reconcluait la meme chute, et notait une deuxieme fois
    /// un candidat deja juge. Le carnet, idempotent par technique, n'en gardait
    /// qu'une trace - mais la course en gardait deux, et son message
    /// d'epuisement nommait deux fois la meme technique en la faisant passer
    /// pour deux echecs distincts.
    #[test]
    fn un_candidat_condamne_n_est_plus_juge_pendant_la_gigue() {
        let (mut sup, _demandes, _verdicts) = superviseur_en_course();
        // Une sonde joignable, parce qu'un effondrement de debit ne condamne
        // plus tout seul: il fait DEMANDER au pair, et c'est le silence du pair
        // qui tranche. Voir l'en-tete de `bifrost_evasion::observation`.
        let (poignee, mut sondes, reponses) = sonde_de_recette();
        sup.sonde = Some(poignee);

        let mut recus = 0u64;
        for s in 0..=20 {
            recus = s * 100_000;
            assert_eq!(
                sup.verser(&compteurs(s * 1_000, recus), Duration::from_secs(s)),
                None
            );
        }
        let mut perte = None;
        let mut s = 21;
        while perte.is_none() && s <= 40 {
            recus += 200;
            perte = sup.verser(&compteurs(s * 1_000, recus), Duration::from_secs(s));
            if perte.is_none() && sondes.try_recv().is_ok() {
                reponses
                    .try_send(crate::coeurs::vitalite::Sonde::Echouee)
                    .expect("la file de recette a de la place");
            }
            s += 1;
        }
        assert_eq!(
            sup.encaisser(perte.expect("l'effondrement doit etre vu")),
            None,
            "la course avait un candidat suivant"
        );

        // La gigue court, et le meme silence continue: il ne doit plus rien
        // conclure, parce qu'il n'y a plus personne a juger.
        for _ in 0..20 {
            recus += 200;
            s += 1;
            assert_eq!(
                sup.verser(&compteurs(s * 1_000, recus), Duration::from_secs(s)),
                None,
                "un candidat deja condamne est juge une seconde fois"
            );
        }
        assert_eq!(
            sup.course.as_ref().unwrap().echoues().len(),
            1,
            "une seule perte, et pourtant plusieurs echecs au compte de la course"
        );
    }

    /// La fenetre qui renait PENDANT la gigue n'appartient pas au suivant.
    ///
    /// Mesure le 20 aout 2026, sur le banc de bascule: le `debug_assert` pose
    /// dans `basculer_vers` a saute, deux essais sur trois. La condamnation
    /// consomme bien l'observation - c'est l'objet de
    /// `un_candidat_condamne_n_est_plus_juge_pendant_la_gigue` - mais la gigue
    /// dure PLUSIEURS tours de boucle, et chacun de ces tours verse a nouveau
    /// les compteurs: `regarder_couler` rouvre alors une fenetre, qui appartient
    /// encore au candidat sortant.
    ///
    /// Les deux remises a zero sont donc necessaires, et elles ne disent pas la
    /// meme chose: celle de la condamnation empeche de condamner deux fois,
    /// celle de la bascule empeche le candidat suivant d'heriter d'une fenetre
    /// qui n'est pas la sienne. Avoir cru la seconde redondante etait une
    /// deduction sur le code; le banc a repondu en une heure.
    #[test]
    fn la_fenetre_rouverte_pendant_la_gigue_ne_suit_pas_le_candidat_suivant() {
        let (mut sup, _demandes, _verdicts) = superviseur_en_course();
        let avant = Instant::now();
        assert_eq!(sup.encaisser(Perte::Gel { octets: 17_000 }), None);
        assert!(
            sup.observation.is_none(),
            "la condamnation doit consommer la fenetre"
        );

        // Le tour de boucle suivant, pendant la gigue: les compteurs sont
        // verses comme a chaque tour, et une fenetre neuve nait.
        sup.verser(&compteurs(1_000, 100_000), Duration::from_secs(1));
        assert!(
            sup.observation.is_some(),
            "le tour de boucle rouvre bien une fenetre"
        );

        laisser_passer_la_gigue(&mut sup, avant);
        assert!(
            sup.observation.is_none(),
            "le candidat suivant herite d'une fenetre qui n'est pas la sienne"
        );
    }

    /// La bascule remet l'observation a zero.
    ///
    /// Sans cela le candidat suivant heriterait du silence de celui qu'il
    /// remplace, et mourrait d'un gel qui n'est pas le sien - en entrainant
    /// toute la liste avec lui.
    #[test]
    fn la_bascule_remet_l_observation_a_zero() {
        let (mut sup, _demandes, _verdicts) = superviseur_en_course();
        sup.observation = Some((Instant::now(), Observateur::nouveau()));
        let avant = Instant::now();
        assert_eq!(sup.encaisser(Perte::Gel { octets: 17_000 }), None);
        laisser_passer_la_gigue(&mut sup, avant);
        assert!(
            sup.observation.is_none(),
            "le candidat suivant doit repartir d'une fenetre neuve"
        );
    }

    /// Une bascule REFUSEE ne laisse pas le trafic sur la sortie gelee.
    ///
    /// Un 204 dit que le coeur a compris, pas qu'il a change: le verdict est
    /// relu. S'il dit non, le candidat n'a pas eu sa chance et la course passe
    /// au suivant - ici il n'y en a plus, donc le tunnel est perdu, mais il
    /// l'est en le DISANT plutot qu'en attendant une confirmation qui ne
    /// viendra pas.
    #[test]
    fn une_bascule_refusee_ne_laisse_pas_le_trafic_sur_la_sortie_gelee() {
        let (mut sup, mut demandes, verdicts) = superviseur_en_course();
        let avant = Instant::now();
        assert_eq!(sup.encaisser(Perte::Gel { octets: 17_000 }), None);
        laisser_passer_la_gigue(&mut sup, avant);
        assert_eq!(demandes.try_recv().ok().as_deref(), Some("hysteria2"));

        verdicts
            .try_send(crate::coeurs::bascule::Issue::Refusee {
                sortie: "hysteria2".to_owned(),
                raison: "le coeur a accepte la requete mais sert toujours vless-reality-vision"
                    .to_owned(),
            })
            .expect("le verdict doit entrer dans la file");

        let motif = sup
            .ramasser_la_bascule()
            .expect("apres un refus sur le dernier candidat, il n'y a plus rien a tenter");
        assert!(
            motif.contains("tous les candidats"),
            "le motif doit dire que la liste est epuisee: {motif}"
        );
    }

    /// Une bascule REUSSIE ne conclut rien de plus.
    #[test]
    fn une_bascule_faite_ne_perd_pas_le_tunnel() {
        let (mut sup, _demandes, verdicts) = superviseur_en_course();
        verdicts
            .try_send(crate::coeurs::bascule::Issue::Faite {
                sortie: "hysteria2".to_owned(),
            })
            .expect("le verdict doit entrer dans la file");
        assert_eq!(
            sup.ramasser_la_bascule(),
            None,
            "une bascule confirmee laisse la connexion vivre"
        );
    }

    /// Le demontage oublie la course.
    ///
    /// Elle decrit les candidats de CETTE connexion. La garder ferait basculer
    /// la suivante vers un candidat que son propre plan n'a peut-etre pas
    /// retenu, sur un reseau qui n'est peut-etre plus le meme.
    #[test]
    fn le_demontage_oublie_la_course() {
        let (mut sup, _demandes, _verdicts) = superviseur_en_course();
        assert!(sup.course.is_some(), "la connexion en avait une");
        sup.apply(Action::BringTunnelDown(cfg()))
            .expect("le demontage de doublure doit aboutir");
        assert!(sup.course.is_none(), "la course meurt avec le tunnel");
        assert!(
            sup.cle.is_none(),
            "la cle aussi: elle designait ce reseau-la"
        );
    }

    static NOTES_DE_COURSE: Mutex<Vec<(String, bool)>> = Mutex::new(Vec::new());

    /// Une perte en cours de session s'inscrit au carnet, et une bascule
    /// refusee non.
    ///
    /// La difference est celle de [`Echec::accuse_le_reseau`]: un gel est une
    /// action de censeur, un coeur qui refuse notre requete de controle est une
    /// panne chez nous. Noter la seconde ecarterait une technique d'un reseau
    /// pour une raison qui n'a rien a voir avec lui - et la panne etant locale,
    /// elle suivrait la machine sur tous les reseaux qu'elle visite.
    #[test]
    fn une_perte_va_au_carnet_une_bascule_refusee_non() {
        let (mut sup, mut demandes, verdicts) = superviseur_en_course();
        sup.carnetier = Carnetier {
            noter: |cle, technique, reussite| {
                NOTES_DE_COURSE
                    .lock()
                    .unwrap()
                    .push((format!("{}/{}", cle.as_str(), technique.nom()), reussite));
                Ok(())
            },
            ..carnetier_muet()
        };

        let avant = Instant::now();
        assert_eq!(sup.encaisser(Perte::Gel { octets: 17_000 }), None);
        laisser_passer_la_gigue(&mut sup, avant);
        assert_eq!(demandes.try_recv().ok().as_deref(), Some("hysteria2"));

        verdicts
            .try_send(crate::coeurs::bascule::Issue::Refusee {
                sortie: "hysteria2".to_owned(),
                raison: "le coeur ne repond plus".to_owned(),
            })
            .expect("le verdict doit entrer dans la file");
        sup.ramasser_la_bascule();

        let notes = NOTES_DE_COURSE.lock().unwrap().clone();
        assert_eq!(
            notes.len(),
            1,
            "seul le gel accuse le reseau, pas le refus de bascule: {notes:?}"
        );
        assert!(
            notes[0].0.ends_with("/vless-reality-vision"),
            "c'est la technique GELEE qui est notee: {:?}",
            notes[0].0
        );
        assert!(!notes[0].1, "un gel est un echec");
    }

    /// Un portage propose desormais TOUTES ses techniques.
    ///
    /// Sans cela il n'y a rien a parcourir: la course distribue des candidats,
    /// et un portage qui n'en nomme qu'un n'en fournit aucun a distribuer.
    #[test]
    fn un_portage_par_coeur_propose_toutes_ses_techniques() {
        assert_eq!(
            techniques_du_portage(&Portage::Coeur(Box::new(profils_a_deux()))),
            vec![Technique::RealityVision, Technique::Hysteria2]
        );
        // WireGuard n'en propose qu'une, et ce n'est pas AmneziaWG: celle-la ne
        // se monte pas ainsi, elle se pilote par UAPI derriere un coeur.
        assert_eq!(
            techniques_du_portage(&wireguard()),
            vec![Technique::WireGuardNu]
        );
    }

    /// Les deux crates nomment la meme chose de la meme facon.
    ///
    /// `bifrost-core` ignore la selection - il n'en depend pas, et c'est
    /// voulu - donc rien ne les tient ensemble a part cette recette. Un
    /// utilisateur qui lit "hysteria2" dans un refus doit retrouver
    /// "hysteria2" dans son profil, et l'etiquette de sortie sing-box est ce
    /// meme nom.
    #[test]
    fn le_nom_d_un_transport_est_celui_de_sa_technique() {
        for profil in profils_a_deux().tous() {
            assert_eq!(
                profil.transport.nom(),
                technique_du_profil(profil).nom(),
                "le transport et la technique se nomment differemment"
            );
        }
    }

    /// C'est la SELECTION qui devient le defaut du selecteur, pas l'ordre du
    /// fichier.
    ///
    /// `sing_box_avec` fait de la premiere sortie le `default` du selecteur.
    /// L'ordre rendu ici EST donc la decision, et il n'existe pas de second
    /// endroit ou elle serait appliquee - donc pas de risque qu'ils divergent.
    #[test]
    fn la_sortie_retenue_passe_en_tete_quel_que_soit_l_ordre_du_fichier() {
        let mut sup = superviseur_nu();
        sup.demarche = Demarche::pour(Technique::Hysteria2);
        let tags: Vec<String> = sup
            .sorties_du_coeur(&profils_a_deux())
            .iter()
            .map(|s| s.tag().to_owned())
            .collect();
        assert_eq!(
            tags,
            vec!["hysteria2", "vless-reality-vision"],
            "la retenue doit venir en tete, le reste garder l'ordre du fichier"
        );
    }

    /// Et le reste garde l'ordre du fichier: un tri total inventerait un
    /// classement des replis que la selection n'a pas rendu.
    #[test]
    fn les_replis_gardent_l_ordre_du_fichier() {
        let mut sup = superviseur_nu();
        sup.demarche = Demarche::pour(Technique::RealityVision);
        let tags: Vec<String> = sup
            .sorties_du_coeur(&profils_a_deux())
            .iter()
            .map(|s| s.tag().to_owned())
            .collect();
        assert_eq!(tags, vec!["vless-reality-vision", "hysteria2"]);
    }

    /// Une seule technique debout suffit a se connecter.
    ///
    /// Le TLS est intercepte, ce qui condamne REALITY et rien d'autre. Un
    /// profil qui propose aussi Hysteria2 doit passer par celle-la, et non se
    /// voir refuser parce que son premier candidat est tombe.
    #[test]
    fn un_profil_a_deux_survit_a_la_perte_d_un_candidat() {
        let mut decision = Decision::default();
        decision.environnement.mitm_tls = bifrost_evasion::Mesure::Vu(true);
        let (issue, _, _) = selection(decision, cfg_a_deux_coeurs(), true);
        let e = issue
            .expect_err("sans atelier, rien ne se lance")
            .to_string();
        assert!(
            !e.contains("ecarte"),
            "il restait Hysteria2: la connexion ne doit pas etre refusee par la selection: {e}"
        );
        assert!(
            e.contains("atelier"),
            "l'obstacle restant doit etre le lancement: {e}"
        );
    }

    /// Tout ecarter refuse, et NOMME chaque motif.
    ///
    /// N'en montrer qu'un ferait corriger un point pour se heurter au suivant.
    /// Le TLS intercepte condamne REALITY, l'UDP coupe condamne Hysteria2:
    /// deux mesures independantes, deux motifs distincts.
    #[test]
    fn tout_ecarter_refuse_en_nommant_chaque_motif() {
        let mut decision = Decision::default();
        decision.environnement.mitm_tls = bifrost_evasion::Mesure::Vu(true);
        decision.environnement.udp_passe = bifrost_evasion::Mesure::Vu(false);
        let (issue, _, posees) = selection(decision, cfg_a_deux_coeurs(), true);
        let e = issue
            .expect_err("les deux techniques sont ecartees")
            .to_string();
        assert!(e.contains("vless-reality-vision"), "{e}");
        assert!(e.contains("intercepte"), "{e}");
        assert!(e.contains("hysteria2"), "{e}");
        assert!(e.contains("UDP"), "{e}");
        assert!(
            posees.is_empty(),
            "le refus tombe a la porte: rien ne doit etre arme"
        );
    }

    /// Un portage par coeur, tel qu'un lien de partage le produit.
    fn portage_par_coeur() -> Portage {
        let profil = Profil::depuis_lien(
            "hysteria2://mot-de-passe-de-documentation@203.0.113.8:8443/?sni=exemple.test#Essai",
        )
        .expect("ce lien doit se lire");
        Portage::Coeur(Box::new(profil.into()))
    }

    fn wireguard() -> Portage {
        cfg().portage.clone()
    }

    fn par_coeur(coeur: bifrost_evasion::Coeur) -> Demarche {
        Demarche::ParCoeur {
            technique: bifrost_evasion::Technique::Hysteria2,
            coeur,
        }
    }

    /// Le tunnel direct, avec le profil qui va avec.
    #[test]
    fn un_tunnel_direct_ne_se_refuse_pas() {
        assert_eq!(
            refus(
                &Demarche::TunnelDirect(bifrost_evasion::Technique::WireGuardNu),
                &wireguard()
            ),
            None
        );
    }

    /// Le temoin de la lacune fermee.
    ///
    /// Ce refus a existe, et son message disait ce qui manquait: rien ne
    /// portait un PROFIL de coeur jusqu'ici. Ce n'est plus vrai, et c'est ce
    /// test qui l'affirme. Il tombera le jour ou l'on cassera le chemin en
    /// amont, ce qui est exactement ce qu'on lui demande.
    #[test]
    fn un_profil_de_coeur_avec_la_demarche_qui_va_ne_se_refuse_plus() {
        assert_eq!(
            refus(
                &par_coeur(bifrost_evasion::Coeur::SingBox),
                &portage_par_coeur()
            ),
            None
        );
    }

    /// Le desaccord entre ce que la decision a retenu et ce que le profil
    /// demande, dans les deux sens.
    ///
    /// Un refus muet enverrait chercher la panne partout sauf ou elle est: le
    /// message doit nommer la technique ET le coeur.
    #[test]
    fn un_desaccord_entre_la_decision_et_le_profil_est_refuse() {
        let r = refus(&par_coeur(bifrost_evasion::Coeur::SingBox), &wireguard())
            .expect("un profil WireGuard sous une demarche par coeur doit etre refuse");
        assert!(r.contains("hysteria2"), "{r}");
        assert!(r.contains("sing-box"), "{r}");
        assert!(r.contains("WireGuard"), "{r}");

        let r = refus(
            &Demarche::TunnelDirect(bifrost_evasion::Technique::WireGuardNu),
            &portage_par_coeur(),
        )
        .expect("un profil de coeur sous une demarche directe doit etre refuse");
        assert!(r.contains("wireguard-nu"), "{r}");
        assert!(r.contains("coeur"), "{r}");
    }

    /// Le refus le plus important du lot.
    ///
    /// Xray et amneziawg ne rendent PAS le profil qu'on leur donne: le premier
    /// n'ecrit qu'une sortie directe, le second ne prend pas de configuration
    /// au lancement. Les lancer ferait sortir le trafic en clair depuis un
    /// compte que le kill switch exempte, avec un tunnel qui a l'air monte.
    /// Le message doit le dire, sans quoi on chercherait la panne dans le
    /// serveur.
    #[test]
    fn un_coeur_qui_ne_rend_pas_le_profil_est_refuse() {
        let r = refus(
            &par_coeur(bifrost_evasion::Coeur::XrayCore),
            &portage_par_coeur(),
        )
        .expect("xray ne rend pas encore un profil");
        assert!(r.contains("clair"), "le refus doit nommer la fuite: {r}");
        assert!(r.contains("sing-box"), "et ce qui marche: {r}");

        let r = refus(
            &par_coeur(bifrost_evasion::Coeur::AmneziaWg),
            &portage_par_coeur(),
        )
        .expect("amneziawg ne prend pas de configuration au lancement");
        assert!(r.contains("UAPI"), "{r}");
    }

    #[test]
    fn les_demarches_sans_issue_sont_refusees_quel_que_soit_le_profil() {
        for portage in [wireguard(), portage_par_coeur()] {
            assert!(refus(&Demarche::SansIssue, &portage).is_some());
            assert!(refus(&Demarche::PortailDAbord, &portage).is_some());
        }
    }

    /// Le point qui compte vraiment: le refus tombe AVANT tout effet de bord.
    ///
    /// Un superviseur qui refuserait apres avoir arme, ou apres avoir monte le
    /// tunnel, laisserait la machine dans un etat que personne n'a demande. On
    /// mesure donc l'absence de politique posee, pas seulement l'erreur rendue.
    ///
    /// Le refus mis a l'epreuve a change, et le changement dit ou en est le
    /// cablage. Il s'agissait d'un DESACCORD entre une demarche epinglee au
    /// demarrage et le profil recu; la demarche se deduisant desormais du
    /// profil, ce desaccord n'est plus atteignable par `connect` - les deux
    /// bras subsistent dans `refus` comme garde entre les deux
    /// correspondances, et se testent la, sur la fonction pure. Ce qui est
    /// atteignable, et ce qu'on mesure ici, c'est le VETO de la selection: le
    /// tableau de survie donne WireGuard nu pour mort en Chine.
    ///
    /// Le carnetier n'explose plus sur la lecture de la cle: la lire est
    /// desormais ce qui PERMET de refuser, puisque la demarche se calcule avec.
    /// L'invariant, lui, n'a pas bouge - aucun filtre pose, aucun processus
    /// lance, rien d'inscrit au carnet - et c'est celui-la qu'on verifie.
    #[test]
    fn une_demarche_impossible_n_arme_rien() {
        let vues = Arc::new(Mutex::new(Vec::new()));
        let mut sup = Supervisor::new(
            Box::new(FauxKillSwitch { vues: vues.clone() }),
            Box::new(FauxTunnel { luid: None }),
            Box::new(FauxDns),
            IdentiteCoeur::default(),
            Resolveur {
                verification: |_| Ok(()),
                ..Default::default()
            },
            Equipement {
                decision: Decision {
                    pays: Pays::Chine,
                    ..Default::default()
                },
                carnetier: Carnetier {
                    noter: |_, _, _| panic!("une connexion refusee ne s'inscrit pas au carnet"),
                    ..carnetier_muet()
                },
                atelier: None,
                chemin_coeur: None,
            },
        );
        let issue = sup.connect(cfg());
        let e = issue
            .expect_err("la connexion devait etre refusee")
            .to_string();
        assert!(
            e.contains("wireguard-nu") && e.contains("morte"),
            "le refus doit nommer la technique et le motif de la selection: {e}"
        );
        assert!(
            vues.lock().unwrap().is_empty(),
            "aucune politique ne devait etre posee: {:?}",
            vues.lock().unwrap()
        );
    }

    /// Le meme profil, le meme daemon, un pays de moins: la connexion passe.
    ///
    /// Sans ce temoin, la recette ci-dessus serait satisfaite par un daemon qui
    /// refuse tout. C'est le pays qui doit faire la difference, et rien d'autre
    /// dans le montage ne change entre les deux.
    #[test]
    fn le_meme_profil_passe_la_ou_la_technique_n_est_pas_condamnee() {
        let (issue, montes, _) = selection(Decision::default(), cfg(), false);
        issue.expect("wireguard nu n'est condamne dans aucun pays non censure");
        assert!(
            montes.iter().any(|m| m == "up:direct"),
            "le tunnel direct devait monter: {montes:?}"
        );
    }

    /// La voie par coeur est joignable par `Connect`, et c'est le defaut que
    /// ce cablage corrige.
    ///
    /// Le chemin par coeur etait ecrit, teste et exempte par le kill switch,
    /// mais une demarche epinglee sur `TunnelDirect(WireGuardNu)` refusait tout
    /// profil de coeur: en production, ce chemin etait injoignable. La recette
    /// s'arrete a l'absence d'atelier, qui est le premier obstacle APRES le
    /// refus - donc la preuve que le refus n'a plus lieu.
    #[test]
    fn un_profil_de_coeur_n_est_plus_refuse_par_le_flux_de_connexion() {
        let (issue, _, _) = selection(Decision::default(), cfg_par_coeur(), true);
        let e = issue
            .expect_err("sans atelier, rien ne peut etre lance")
            .to_string();
        assert!(
            !e.contains("desaccord"),
            "le profil de coeur ne doit plus se heurter a la demarche: {e}"
        );
        assert!(
            e.contains("atelier"),
            "l'obstacle restant doit etre le lancement: {e}"
        );
    }

    /// Une connexion PAR COEUR laisse une trace au carnet.
    ///
    /// La notation filtrait sur `TunnelDirect` seul: la moitie de la memoire
    /// dont la selection se sert n'etait jamais ecrite, et rien ne le disait.
    /// La technique notee doit etre celle du PROFIL, pas celle que le plan
    /// aurait preferee.
    ///
    /// Le montage doit porter un chemin par coeur. Sans lui, `connect` refuse
    /// a la porte pour cause de drapeaux manquants et n'atteint jamais le
    /// carnet - ce qui est correct, et c'est la meme regle que
    /// `bifrost_evasion::course::Echec::NonLancable`: une panne LOCALE ne se
    /// note pas au carnet, sans quoi elle ecarterait la technique sur tous les
    /// reseaux que cette machine visite, pour une raison qui ne les regarde
    /// pas. La connexion echoue quand meme, plus loin, faute d'atelier - et un
    /// echec se note autant qu'une reussite, puisqu'il ecarte la technique du
    /// prochain essai sur CE reseau.
    #[test]
    fn une_connexion_par_coeur_se_note_au_carnet() {
        static NOTES: Mutex<Vec<(String, Technique, bool)>> = Mutex::new(Vec::new());
        let (issue, _, _) = selection_avec(
            Decision::default(),
            Carnetier {
                noter: |cle, t, reussite| {
                    NOTES
                        .lock()
                        .unwrap()
                        .push((cle.as_str().to_owned(), t, reussite));
                    Ok(())
                },
                ..carnetier_muet()
            },
            cfg_par_coeur(),
            true,
        );
        assert!(
            issue.is_err(),
            "sans atelier, le coeur ne peut pas etre lance"
        );
        let notes = NOTES.lock().unwrap().clone();
        assert_eq!(notes.len(), 1, "une ligne devait etre notee: {notes:?}");
        assert_eq!(
            notes[0].1,
            Technique::Hysteria2,
            "la technique notee doit etre celle du profil"
        );
        assert!(
            !notes[0].2,
            "cette tentative a echoue, le carnet doit le dire"
        );
    }

    /// Le pendant: une panne LOCALE ne salit pas le carnet.
    ///
    /// Il manque deux drapeaux au demarrage, ce qui n'apprend rien sur le
    /// reseau. Noter cet echec ecarterait la technique du prochain essai ICI,
    /// et la panne etant locale, elle suivrait la machine sur tous les reseaux
    /// qu'elle visite en salissant le carnet a chaque fois.
    #[test]
    fn une_panne_locale_ne_se_note_pas_au_carnet() {
        let (issue, _, _) = selection_avec(
            Decision::default(),
            Carnetier {
                noter: |_, _, _| panic!("une panne locale n'apprend rien sur le reseau"),
                ..carnetier_muet()
            },
            cfg_par_coeur(),
            false,
        );
        assert!(issue.is_err(), "ce daemon n'a pas de chemin par coeur");
    }

    /// Un carnetier qui ne touche a aucun fichier.
    ///
    /// La date est FIXE, et pas seulement pour eviter de lire l'horloge: le
    /// tableau de survie elimine sur des observations qui vieillissent. Une
    /// recette calee sur le jour courant cesserait de prouver quoi que ce soit
    /// le jour ou l'observation passerait le seuil de fraicheur, sans que rien
    /// ne devienne rouge.
    fn carnetier_muet() -> Carnetier {
        Carnetier {
            cle: || Ok(CleReseau::nouvelle("banc", "192.168.1.1", None)),
            noter: |_, _, _| Ok(()),
            souvenir: |_| Ok(MemoireReseau::vierge()),
            aujourd_hui: || Ok(LE_JOUR_DIT),
        }
    }

    /// Le jour de reference des recettes. Deux mois apres l'observation la plus
    /// recente du tableau de survie, donc dans sa fenetre de fraicheur.
    const LE_JOUR_DIT: bifrost_evasion::Date = bifrost_evasion::Date::new(2026, 6, 1);

    /// Chaque test a son propre etat: les tests tournent en parallele, et un
    /// enregistrement partage les ferait se marcher dessus.
    static ORDRE: Mutex<Vec<(String, bool)>> = Mutex::new(Vec::new());
    /// Mis a vrai des que le tunnel est monte, pour que la lecture de cle
    /// puisse rendre une valeur DIFFERENTE apres coup.
    static TUNNEL_MONTE: AtomicBool = AtomicBool::new(false);
    static SANS_CLE: Mutex<Vec<(String, bool)>> = Mutex::new(Vec::new());

    /// Le piege que ce champ existe pour eviter: une cle lue APRES le montage
    /// designe le tunnel et non le reseau traverse. Le souvenir serait range
    /// sous un nom qu'on ne reverra jamais en clair, et le carnet resterait
    /// inutile sans que rien ne le signale.
    #[test]
    fn la_cle_est_lue_avant_que_le_tunnel_monte() {
        TUNNEL_MONTE.store(false, Ordering::SeqCst);

        let mut sup = Supervisor::new(
            Box::new(FauxKillSwitch {
                vues: Arc::new(Mutex::new(Vec::new())),
            }),
            Box::new(FauxTunnel { luid: None }),
            Box::new(FauxDns),
            IdentiteCoeur::default(),
            Resolveur {
                verification: |_| Ok(()),
                ..Default::default()
            },
            Equipement {
                decision: Decision::default(),
                carnetier: Carnetier {
                    cle: || {
                        Ok(CleReseau::nouvelle(
                            if TUNNEL_MONTE.load(Ordering::SeqCst) {
                                "tunnel"
                            } else {
                                "reseau-reel"
                            },
                            "192.168.1.1",
                            None,
                        ))
                    },
                    noter: |cle, _, reussite| {
                        ORDRE
                            .lock()
                            .unwrap()
                            .push((cle.as_str().to_owned(), reussite));
                        Ok(())
                    },
                    ..carnetier_muet()
                },
                atelier: None,
                chemin_coeur: None,
            },
        );
        // Le faux tunnel ne bascule rien tout seul: on marque le montage au
        // moment ou `connect` rend la main, ce qui suffit a distinguer une
        // lecture faite avant d'une lecture faite apres.
        sup.connect(cfg()).expect("la connexion doit reussir");
        TUNNEL_MONTE.store(true, Ordering::SeqCst);

        let notes = ORDRE.lock().unwrap().clone();
        assert_eq!(notes.len(), 1, "une ligne devait etre notee: {notes:?}");
        assert!(
            notes[0].0.starts_with("reseau-reel"),
            "la cle a ete lue apres le montage du tunnel: {:?}",
            notes[0].0
        );
        assert!(notes[0].1, "la connexion a reussi, le carnet doit le dire");
    }

    /// Un reseau non identifiable n'empeche pas de se connecter: cela empeche
    /// seulement de s'en souvenir.
    #[test]
    fn un_reseau_non_identifie_n_empeche_pas_la_connexion() {
        let mut sup = Supervisor::new(
            Box::new(FauxKillSwitch {
                vues: Arc::new(Mutex::new(Vec::new())),
            }),
            Box::new(FauxTunnel { luid: None }),
            Box::new(FauxDns),
            IdentiteCoeur::default(),
            Resolveur {
                verification: |_| Ok(()),
                ..Default::default()
            },
            Equipement {
                decision: Decision::default(),
                carnetier: Carnetier {
                    cle: || Err("pas de route par defaut".to_owned()),
                    noter: |cle, _, reussite| {
                        SANS_CLE
                            .lock()
                            .unwrap()
                            .push((cle.as_str().to_owned(), reussite));
                        Ok(())
                    },
                    ..carnetier_muet()
                },
                atelier: None,
                chemin_coeur: None,
            },
        );
        sup.connect(cfg())
            .expect("la connexion doit reussir quand meme");
        assert!(
            SANS_CLE.lock().unwrap().is_empty(),
            "rien ne doit etre note sous une cle qu'on n'a pas"
        );
    }

    /// Un carnet qui ne s'ecrit pas ne casse pas la connexion en cours.
    #[test]
    fn un_carnet_qui_ne_s_ecrit_pas_ne_casse_pas_la_connexion() {
        let mut sup = Supervisor::new(
            Box::new(FauxKillSwitch {
                vues: Arc::new(Mutex::new(Vec::new())),
            }),
            Box::new(FauxTunnel { luid: None }),
            Box::new(FauxDns),
            IdentiteCoeur::default(),
            Resolveur {
                verification: |_| Ok(()),
                ..Default::default()
            },
            Equipement {
                decision: Decision::default(),
                carnetier: Carnetier {
                    noter: |_, _, _| Err("disque plein".to_owned()),
                    ..carnetier_muet()
                },
                atelier: None,
                chemin_coeur: None,
            },
        );
        sup.connect(cfg())
            .expect("un carnet non ecrit ne doit pas faire echouer la connexion");
    }

    fn identite() -> IdentiteCoeur {
        IdentiteCoeur {
            utilisateur: Some(crate::coeurs::lancement::Utilisateur { uid: 977, gid: 977 }),
            executable: Some(std::path::PathBuf::from("/opt/bifrost/coeurs/sing-box")),
        }
    }

    /// Le coeur du cablage. Le kill switch Windows autorise le trafic du tunnel
    /// par LUID; si le superviseur ne le lui transmet pas, le block-all bloque
    /// aussi le tunnel et la connexion se declare pourtant etablie.
    #[test]
    fn le_luid_du_device_arrive_jusqu_a_la_politique() {
        let vues = connecte(Some(0xdead_beef));
        assert!(
            vues.iter().all(|p| p.tunnel_luid == Some(0xdead_beef)),
            "chaque armement doit porter le LUID du device: {vues:?}"
        );
    }

    /// Sur une plateforme qui designe l'interface par son nom, comme Linux avec
    /// nftables, l'absence de LUID doit rester l'absence de LUID.
    #[test]
    fn un_device_sans_identifiant_ne_fabrique_pas_de_luid() {
        assert!(connecte(None).iter().all(|p| p.tunnel_luid.is_none()));
    }

    /// La sequence attendue: on arme AVANT que l'interface existe, donc sans
    /// interface nommee, puis on reengage une fois montee. C'est ce second
    /// armement qui autorise le tunnel.
    #[test]
    fn le_second_armement_est_celui_qui_connait_le_tunnel() {
        let vues = connecte(Some(1));
        assert_eq!(vues.len(), 2, "deux armements attendus: {vues:?}");
        assert_eq!(vues[0].tunnel_interface, None);
        assert_eq!(vues[1].tunnel_interface.as_deref(), Some("wg0"));
    }

    /// Le fil entre le daemon et le coeur. Sans lui, la mecanique d'exemption
    /// existe dans le pare-feu et n'est jamais renseignee: le coeur sort avec
    /// une politique qui ne le connait pas, donc il ne sort pas.
    #[test]
    fn l_identite_du_coeur_arrive_jusqu_a_la_politique() {
        let vues = connecte_avec(None, identite());
        assert!(!vues.is_empty());
        for p in &vues {
            assert_eq!(p.coeur_uid, Some(977), "armement sans exemption: {p:?}");
            assert_eq!(
                p.coeur_executable.as_deref(),
                Some(std::path::Path::new("/opt/bifrost/coeurs/sing-box"))
            );
        }
    }

    /// La propriete de temps, et c'est celle qui compte.
    ///
    /// Le premier armement precede la montee du tunnel, donc precede tout
    /// lancement de coeur. S'il ne portait pas deja l'exemption, il faudrait
    /// soit demarrer le coeur sans elle, soit baisser le kill switch pour la
    /// lui donner: deux fenetres de fuite pour eviter un etranglement.
    #[test]
    fn l_exemption_est_posee_des_le_premier_armement() {
        let vues = connecte_avec(Some(1), identite());
        assert_eq!(vues.len(), 2, "deux armements attendus: {vues:?}");
        assert_eq!(vues[0].tunnel_interface, None, "premier armement attendu");
        assert_eq!(
            vues[0].coeur_uid,
            Some(977),
            "l'exemption arrive trop tard: un coeur demarre avant le second \
             armement serait etrangle"
        );
    }

    /// Rien de declare, rien d'ouvert. C'est le comportement d'avant ce
    /// cablage, et il doit rester celui des installations qui ne lancent pas
    /// de coeur: une exemption inutile reste une sortie en clair.
    #[test]
    fn sans_identite_declaree_aucune_politique_n_ouvre_de_sortie() {
        let vues = connecte(Some(1));
        assert!(!vues.is_empty());
        assert!(
            vues.iter()
                .all(|p| p.coeur_uid.is_none() && p.coeur_executable.is_none()),
            "une exemption est apparue sans avoir ete declaree: {vues:?}"
        );
    }

    fn identite_resolveur() -> IdentiteResolveur {
        IdentiteResolveur {
            utilisateur: Some(crate::coeurs::lancement::Utilisateur { uid: 981, gid: 981 }),
            executable: None,
            #[cfg(windows)]
            compte: None,
            #[cfg(windows)]
            sid: None,
        }
    }

    /// Meme cablage que pour le coeur, et la meme exigence: ce qui est declare
    /// au demarrage doit se retrouver dans CHAQUE politique posee, y compris
    /// celle du premier armement, qui precede la montee du tunnel.
    #[test]
    fn l_identite_du_resolveur_arrive_jusqu_a_la_politique() {
        let vues = connecte_complet(
            Some(1),
            IdentiteCoeur::default(),
            identite_resolveur(),
            true,
        );
        assert!(!vues.is_empty());
        assert!(
            vues.iter().all(|p| p.resolveur_uid == Some(981)),
            "une politique a ete posee sans la restriction du resolveur: {vues:?}"
        );
    }

    /// Sans resolveur declare, aucune restriction: fermer le :53 quand rien
    /// n'ecoute sur la boucle locale retirerait la resolution de noms a la
    /// machine au lieu de la durcir.
    #[test]
    fn sans_resolveur_declare_aucune_politique_ne_ferme_le_53() {
        let vues = connecte(Some(1));
        assert!(
            vues.iter().all(|p| p.resolveur_uid.is_none()),
            "une restriction du :53 est apparue sans resolveur declare: {vues:?}"
        );
    }

    /// Le controle qui rend l'unite systemd sure. Elle nomme le compte du
    /// resolveur une fois pour toutes, au demarrage du daemon; les profils,
    /// eux, vont et viennent. Un profil qui ne route pas le DNS par la boucle
    /// locale ne doit pas voir son :53 se fermer, sans quoi installer Bifrost
    /// suffirait a priver la machine de resolution de noms des la premiere
    /// connexion avec un profil ordinaire.
    #[test]
    fn un_profil_sans_resolveur_local_ne_ferme_pas_le_53_meme_avec_un_compte() {
        let vues = connecte_complet(
            Some(1),
            IdentiteCoeur::default(),
            identite_resolveur(),
            false,
        );
        assert!(!vues.is_empty());
        assert!(
            vues.iter().all(|p| p.resolveur_uid.is_none()),
            "le :53 a ete ferme pour un profil qui n'embarque aucun resolveur: {vues:?}"
        );
    }

    /// Le defaut qui compte vraiment ici. Les deux identites empruntent la
    /// meme mecanique d'UID pour des effets OPPOSES: le coeur recoit une
    /// sortie hors tunnel, le resolveur n'en recoit aucune. Les confondre
    /// donnerait au resolveur DNS le droit d'emettre en clair, c'est-a-dire
    /// exactement la fuite que ce composant existe pour fermer.
    #[test]
    fn les_deux_identites_n_ecrivent_pas_dans_le_meme_champ() {
        let vues = connecte_complet(Some(1), identite(), identite_resolveur(), true);
        let derniere = vues.last().expect("au moins une politique");
        assert_eq!(derniere.coeur_uid, Some(977));
        assert_eq!(derniere.resolveur_uid, Some(981));
        assert_ne!(
            derniere.coeur_uid, derniere.resolveur_uid,
            "le resolveur a herite de l'exemption du coeur"
        );
    }

    #[test]
    fn un_echec_d_armement_n_est_jamais_retente() {
        assert!(!is_retryable(
            "armement du kill switch",
            &Error::Firewall("nft absent".into())
        ));
    }

    #[test]
    fn une_panne_reseau_est_retentee() {
        assert!(is_retryable(
            "montage du tunnel",
            &Error::Tunnel("network is unreachable".into())
        ));
    }

    #[test]
    fn un_module_noyau_absent_n_est_pas_retente() {
        assert!(!is_retryable(
            "montage du tunnel",
            &Error::Tunnel("Le module noyau wireguard est-il disponible ?".into())
        ));
    }

    #[test]
    fn un_probleme_de_privileges_n_est_pas_retente() {
        assert!(!is_retryable(
            "montage du tunnel",
            &Error::Tunnel("RTNETLINK answers: Operation not permitted".into())
        ));
    }

    /// Un coeur qui ne demarre pas ne se retente pas.
    ///
    /// La recette la plus utile du lot, parce que le mode d'echec qu'elle
    /// ferme est invisible: sans elle, l'echec passait pour passager, la
    /// machine a etats repartait en tentative, et `connect` rendait Ok au
    /// client pendant qu'aucun tunnel n'existait.
    #[test]
    fn un_coeur_qui_ne_demarre_pas_n_est_pas_retente() {
        assert!(!is_retryable(
            "montage du tunnel",
            &Error::Tunnel(format!(
                "{MARQUEUR_COEUR}: l'API du coeur a refuse le secret"
            ))
        ));
        assert!(!is_retryable(
            "montage du tunnel",
            &Error::Tunnel(format!(
                "{MARQUEUR_COEUR}: configuration non ecrite: disque plein"
            ))
        ));
        // Le temoin negatif: une panne reseau ordinaire, elle, se retente.
        assert!(is_retryable(
            "montage du tunnel",
            &Error::Tunnel("network is unreachable".into())
        ));
    }

    #[test]
    fn une_erreur_de_configuration_n_est_pas_retentee() {
        assert!(!is_retryable(
            "montage du tunnel",
            &Error::Config("fwmark 0".into())
        ));
    }
}
