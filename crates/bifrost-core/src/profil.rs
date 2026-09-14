//! Le profil de coeur: ce qui porte un serveur et ses identifiants jusqu'au
//! superviseur.
//!
//! C'est la piece que le document de reprise nommait manquante. Le daemon sait
//! deja lancer un coeur, ecrire sa configuration, monter le TUN et y router le
//! systeme; rien ne lui disait VERS QUOI se connecter.
//!
//! # Ce que le plan demande
//!
//! Document 04, partie 6: "le client genere ses JSON/YAML a la volee a partir
//! d'un profil (secrets + parametres) recu par subscription, plutot que des
//! fichiers statiques embarques". Le profil est donc l'entree, et
//! `coeurs::configuration` la sortie. Le meme document classe les secrets:
//! l'UUID et les mots de passe sont des secrets d'authentification, les cles
//! publiques REALITY ne le sont pas.
//!
//! Document 06 place cela dans un crate `hyper-profiles`. Il vit ici plutot que
//! dans un crate a lui: un profil doit traverser l'IPC, `bifrost-ipc` importe
//! deja `bifrost-core`, et un troisieme noeud sur la meme ligne de dependances
//! n'aurait rien achete. La responsabilite du document 06 - gestion, import,
//! validation - est tenue; c'est son decoupage en crates qui ne l'est pas.
//!
//! # Pourquoi le lien de partage, et pas un format maison
//!
//! Un profil existe deja dans le monde reel sous une forme: le lien de partage.
//! `vless://` est specifie par le projet Xray, `hysteria2://` par le projet
//! hysteria, et c'est ce que rend un panneau d'administration, un fournisseur,
//! ou un QR code. Inventer un TOML maison aurait rendu chaque import manuel,
//! or ce qui se transcrit a la main ici est un UUID et une cle base64 - et
//! l'erreur de transcription se manifeste, ce depot l'a mesure, par un `EOF`
//! muet qui ne dit rien de sa cause.
//!
//! # La regle qui gouverne tout ce module: refuser, jamais degrader
//!
//! Un lien peut demander ce que le generateur n'ecrit pas: `type=ws`,
//! `security=tls`, `obfs=gecko`, un `alpn`. L'ignorer produirait un coeur qui
//! demarre, une configuration qui ne correspond pas au lien, et une panne sans
//! symptome utile. Chaque parametre non gere est donc REFUSE en nommant
//! lequel, exactement comme un nom d'interface trop long est refuse plutot que
//! tronque.
//!
//! Deux refus meritent d'etre lus deux fois:
//!
//! - `insecure=1` est rejete, pas ignore. [`crate::config`] et le generateur
//!   n'offrent volontairement aucune variante "ne pas verifier"; accepter le
//!   parametre pour l'ignorer donnerait un tunnel authentifie a un utilisateur
//!   qui a demande le contraire, ce qui est un mensonge meme quand il est
//!   favorable.
//! - `pinSHA256` est rejete faute de pouvoir etre honore: la confiance
//!   s'exprime ici par un certificat epingle en PEM, pas par une empreinte.
//!
//! # Un ecart delibere avec la specification
//!
//! La specification VLESS dit que `sni` vaut l'hote du serveur par defaut. Ici
//! il est OBLIGATOIRE pour REALITY. Le `sni` d'un lien REALITY n'est pas
//! l'hote: c'est le site emprunte, celui dont le serveur rejoue la poignee de
//! main. Prendre l'hote par defaut fabriquerait un profil syntaxiquement
//! valide et fonctionnellement mort, avec le meme `EOF` muet pour tout
//! diagnostic.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::{Error, Result};

/// Longueur maximale d'une etiquette, apres decodage.
///
/// Elle vient d'un lien, donc de l'exterieur, et finit dans un journal et dans
/// une interface. Une etiquette sans bornes y ferait passer une ligne entiere.
pub const ETIQUETTE_MAX: usize = 128;

/// Longueur d'une cle publique REALITY: 32 octets en base64url sans
/// remplissage.
pub const CLE_REALITY_CARS: usize = 43;

/// Longueur maximale d'un `shortId`, en caracteres hexadecimaux. Xray en
/// accepte jusqu'a 8 octets.
pub const SHORT_ID_CARS_MAX: usize = 16;

/// Port par defaut d'un lien `hysteria2://`, tel que sa specification le donne.
pub const PORT_HYSTERIA2_DEFAUT: u16 = 443;

// --------------------------------------------------------------------------
// Valeurs validees a la construction
// --------------------------------------------------------------------------

/// L'identite VLESS.
///
/// C'est un secret d'authentification malgre son nom: qui le connait peut se
/// connecter. Son `Debug` est donc opaque, comme celui de
/// [`crate::config::WgKey`].
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Uuid(String);

impl Uuid {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for Uuid {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        // 8-4-4-4-12, en hexadecimal. Le controle porte sur la FORME et non sur
        // la version: les serveurs en circulation portent des UUID v4 comme des
        // valeurs derivees d'une chaine, et refuser ces dernieres rejetterait
        // des profils qui fonctionnent.
        const GROUPES: [usize; 5] = [8, 4, 4, 4, 12];
        let morceaux: Vec<&str> = s.split('-').collect();
        if morceaux.len() != GROUPES.len() {
            return Err(Error::Config(format!(
                "UUID invalide: {} groupes separes par des tirets, 5 attendus",
                morceaux.len()
            )));
        }
        for (morceau, attendu) in morceaux.iter().zip(GROUPES) {
            if morceau.len() != attendu || !morceau.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(Error::Config(
                    "UUID invalide: forme 8-4-4-4-12 en hexadecimal attendue".into(),
                ));
            }
        }
        Ok(Self(s.to_ascii_lowercase()))
    }
}

impl fmt::Debug for Uuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Uuid(<redacted>)")
    }
}

impl TryFrom<String> for Uuid {
    type Error = Error;
    fn try_from(s: String) -> Result<Self> {
        s.parse()
    }
}

impl From<Uuid> for String {
    fn from(v: Uuid) -> Self {
        v.0
    }
}

/// Un mot de passe: authentification Hysteria2, ou obfuscation Salamander.
///
/// Aucune forme imposee, le protocole n'en impose pas. Seul le vide est refuse:
/// un mot de passe vide vient d'un lien tronque bien plus souvent que d'un
/// serveur qui n'en veut pas.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct MotDePasse(String);

impl MotDePasse {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for MotDePasse {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        if s.is_empty() {
            return Err(Error::Config("mot de passe vide".into()));
        }
        Ok(Self(s.to_owned()))
    }
}

impl fmt::Debug for MotDePasse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MotDePasse(<redacted>)")
    }
}

impl TryFrom<String> for MotDePasse {
    type Error = Error;
    fn try_from(s: String) -> Result<Self> {
        s.parse()
    }
}

impl From<MotDePasse> for String {
    fn from(v: MotDePasse) -> Self {
        v.0
    }
}

/// La cle publique REALITY, ce que `xray x25519` nomme desormais
/// "Password (PublicKey)".
///
/// Publique, donc son `Debug` la montre: la cacher rendrait indebogable le seul
/// champ dont une erreur de transcription produit un `EOF` muet.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ClePublique(String);

impl ClePublique {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for ClePublique {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        if s.chars().count() != CLE_REALITY_CARS {
            return Err(Error::Config(format!(
                "cle publique REALITY invalide: {} caracteres, {CLE_REALITY_CARS} attendus",
                s.chars().count()
            )));
        }
        // base64url SANS remplissage: c'est ce que produit `xray x25519`. Un
        // `+` ou un `/` signale une cle recopiee depuis un base64 ordinaire,
        // qui ne sera pas comprise du serveur.
        if !s
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(Error::Config(
                "cle publique REALITY invalide: alphabet base64url attendu, sans remplissage"
                    .into(),
            ));
        }
        Ok(Self(s.to_owned()))
    }
}

impl fmt::Debug for ClePublique {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ClePublique({})", self.0)
    }
}

impl TryFrom<String> for ClePublique {
    type Error = Error;
    fn try_from(s: String) -> Result<Self> {
        s.parse()
    }
}

impl From<ClePublique> for String {
    fn from(v: ClePublique) -> Self {
        v.0
    }
}

/// Le `shortId` REALITY. Vide est une valeur legitime.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ShortId(String);

impl ShortId {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Le `shortId` absent, que le serveur accepte quand il n'en exige pas.
    pub fn vide() -> Self {
        Self(String::new())
    }
}

impl FromStr for ShortId {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        if s.len() > SHORT_ID_CARS_MAX {
            return Err(Error::Config(format!(
                "shortId invalide: {} caracteres, {SHORT_ID_CARS_MAX} au plus",
                s.len()
            )));
        }
        // Longueur impaire: il code des octets, donc il en faut deux par octet.
        // Une longueur impaire est le symptome d'une copie tronquee, pas d'un
        // choix.
        if !s.len().is_multiple_of(2) {
            return Err(Error::Config(
                "shortId invalide: nombre pair de caracteres attendu".into(),
            ));
        }
        if !s.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Error::Config(
                "shortId invalide: hexadecimal attendu".into(),
            ));
        }
        Ok(Self(s.to_ascii_lowercase()))
    }
}

impl fmt::Debug for ShortId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ShortId({})", self.0)
    }
}

impl TryFrom<String> for ShortId {
    type Error = Error;
    fn try_from(s: String) -> Result<Self> {
        s.parse()
    }
}

impl From<ShortId> for String {
    fn from(v: ShortId) -> Self {
        v.0
    }
}

/// Le certificat d'un serveur, epingle en PEM.
///
/// # Pourquoi ce champ existe
///
/// Un serveur auto-heberge presente presque toujours un certificat auto-signe,
/// qu'aucune autorite du systeme n'ancre. Ce module refuse `insecure=1` en
/// disant qu'un tel certificat "s'epingle, il ne s'ignore pas", et refuse
/// `pinSHA256` en disant que la confiance "s'exprime ici par un certificat
/// epingle en PEM". Les deux refus ont longtemps designe un mecanisme qui
/// n'existait nulle part: le profil n'avait pas de champ pour le porter, et le
/// generateur du daemon posait les autorites du systeme sans condition. Le cas
/// ordinaire de ce produit etait donc injoignable par le seul chemin qu'un
/// utilisateur peut ecrire - alors meme que le banc `--coeur-e2e` du depot
/// epinglait, par une route interne que personne d'autre n'emprunte.
///
/// # Ce qui est verifie, et ce qui ne l'est pas
///
/// Les deux bornes du PEM, et rien de plus: aucune X.509 n'est analysee ici, ce
/// crate n'a pas de quoi le faire et n'a pas a l'avoir. La verification qui
/// compte est celle que le coeur fait a la poignee de main. Ce controle-la
/// attrape ce qu'une borne manquante annonce toujours - un copier-coller
/// tronque, un chemin de fichier ecrit a la place du contenu - et laisse le
/// reste au seul qui puisse le faire.
///
/// Plusieurs certificats a la file sont admis: une chaine s'epingle entiere.
///
/// Publique par nature, donc lisible dans un `Debug`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct CertificatPem(String);

impl CertificatPem {
    /// Le PEM ligne par ligne, forme que sing-box attend pour `tls.certificate`.
    pub fn lignes(&self) -> Vec<String> {
        self.0.lines().map(str::to_owned).collect()
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for CertificatPem {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        // Les retours chariot d'un profil ecrit sous Windows, et les lignes
        // vides d'un copier-coller: ni l'un ni l'autre n'est une erreur, et les
        // laisser passer donnerait un PEM que le coeur refuse.
        let lignes: Vec<&str> = s.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
        if !lignes.contains(&"-----BEGIN CERTIFICATE-----") {
            return Err(Error::Config(
                "certificat: aucune ligne '-----BEGIN CERTIFICATE-----'. C'est le contenu du fichier PEM qui se met ici, pas son chemin".into(),
            ));
        }
        if !lignes.contains(&"-----END CERTIFICATE-----") {
            return Err(Error::Config(
                "certificat: aucune ligne '-----END CERTIFICATE-----'. Le PEM est tronque".into(),
            ));
        }
        Ok(Self(lignes.join(
            "
",
        )))
    }
}

impl TryFrom<String> for CertificatPem {
    type Error = Error;
    fn try_from(s: String) -> Result<Self> {
        s.parse()
    }
}

impl From<CertificatPem> for String {
    fn from(v: CertificatPem) -> Self {
        v.0
    }
}

// --------------------------------------------------------------------------
// Le profil
// --------------------------------------------------------------------------

/// Un serveur, une technique, et de quoi s'y authentifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profil {
    /// Ce que l'utilisateur lit. Vient du fragment du lien, decode.
    pub etiquette: String,
    pub transport: Transport,
}

/// Les techniques qu'un profil peut decrire.
///
/// Il n'y en a que deux parce que le generateur n'en ecrit que deux, et que le
/// but de ce module est justement qu'un profil ne puisse pas promettre ce que
/// la suite ne sait pas tenir.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "transport", rename_all = "kebab-case")]
pub enum Transport {
    VlessReality(Box<VlessReality>),
    /// VLESS en TLS ordinaire, encadre par une poignee WebSocket, derriere un
    /// CDN.
    ///
    /// Le repli du mode Discret. Il n'imite pas un site, il EST du trafic web:
    /// une poignee `Upgrade` puis un flux, vers un domaine de CDN qui en sert
    /// des millions d'autres. D'ou sa propriete decisive, que REALITY n'a pas:
    /// il survit a une interception TLS d'entreprise, le CDN terminant deja le
    /// TLS pour tout le monde.
    VlessWebsocket(Box<VlessSurHttp>),
    /// Le meme, encadre par un simple HTTP Upgrade, derriere un front que
    /// l'operateur heberge.
    ///
    /// **Il ne traverse pas un CDN**, mesure du 21 aout 2026: l'edge exige une
    /// poignee WebSocket complete que ce transport n'emet pas, et le serveur
    /// refuse celle-ci quand elle est complete. Un proxy inverse ordinaire, lui,
    /// relaie sans valider.
    ///
    /// Garde parce que ce client ne choisit pas le transport: l'operateur du
    /// serveur le choisit, et un lien `type=httpupgrade` colle par un
    /// utilisateur doit fonctionner.
    VlessHttpUpgrade(Box<VlessSurHttp>),
    Hysteria2(Box<Hysteria2>),
}

impl Transport {
    /// Le nom du transport, pour un message ou une etiquette de sortie.
    ///
    /// Volontairement identique au nom que `bifrost_evasion::Technique` donne
    /// a la meme chose. Les deux types ne se connaissent pas - ce crate ignore
    /// la selection - mais ils designent le meme objet, et un utilisateur qui
    /// lit "hysteria2" dans un refus doit retrouver "hysteria2" dans son
    /// profil. Une recette du daemon, qui voit les deux, garde l'accord.
    pub fn nom(&self) -> &'static str {
        match self {
            Transport::VlessReality(_) => "vless-reality-vision",
            Transport::VlessWebsocket(_) => "websocket-cdn",
            Transport::VlessHttpUpgrade(_) => "httpupgrade-front",
            Transport::Hysteria2(_) => "hysteria2",
        }
    }
}

/// VLESS + REALITY + XTLS-Vision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VlessReality {
    pub serveur: String,
    pub port: u16,
    pub uuid: Uuid,
    pub cle_publique: ClePublique,
    pub short_id: ShortId,
    /// Le site emprunte, jamais l'hote du serveur. Voir l'en-tete du module.
    pub nom_de_serveur: String,
}

/// VLESS + TLS, encadre par du HTTP, derriere un CDN ou un front.
///
/// Une seule structure pour les deux transports, et ce n'est pas de l'economie:
/// ils portent exactement les memes champs et ne different que par la maniere
/// de negocier l'upgrade. Ce que le format decrit est identique; ce qui change
/// est ce que le coeur ecrit sur le fil.
///
/// Aucune cle publique, aucun short id: rien de REALITY ici. La confiance est
/// celle des autorites du systeme, ce qu'un domaine de CDN a toujours.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VlessSurHttp {
    pub serveur: String,
    pub port: u16,
    pub uuid: Uuid,
    /// La SNI presentee. Contrairement a REALITY, elle designe bien l'hote
    /// joint - le CDN - et non un site emprunte: il n'y a rien a emprunter
    /// quand on se fond dans le trafic d'un CDN au lieu de l'imiter.
    pub nom_de_serveur: String,
    /// L'en-tete `Host` de la requete d'upgrade. Souvent identique a la SNI,
    /// mais distinct par nature: le CDN route sur le `Host`, le TLS se
    /// negocie sur la SNI, et les separer est ce qui rend le "domain fronting"
    /// possible la ou il l'est encore.
    pub hote: String,
    /// Le chemin HTTP. Long et imprevisible en pratique: c'est lui qui evite
    /// qu'un sondage actif retrouve le point d'entree en devinant.
    pub chemin: String,
}

/// Hysteria2 sur QUIC.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hysteria2 {
    pub serveur: String,
    pub port: u16,
    pub mot_de_passe: MotDePasse,
    /// Mot de passe Salamander. `None` laisse le QUIC nu, donc reconnaissable a
    /// sa poignee de main: c'est un choix, pas un defaut.
    pub obfs: Option<MotDePasse>,
    pub nom_de_serveur: String,
    /// Certificat du serveur, epingle. `None` s'en remet aux autorites du
    /// systeme, ce qu'un serveur a vrai certificat demande. Voir
    /// [`CertificatPem`] pour pourquoi il n'existe pas de troisieme choix.
    pub certificat: Option<CertificatPem>,
}

/// Les profils de coeur d'un tunnel: au moins un, un par transport.
///
/// # Pourquoi pas un `Vec`
///
/// Un `Vec` rendrait ecrivable un portage par coeur qui ne designe AUCUN
/// coeur. La suite n'aurait rien a en faire: elle lancerait un coeur sans
/// sortie, derriere un selecteur vide, avec un tunnel qui monte devant. La
/// non-vacuite est donc STRUCTURELLE et non validee, comme [`crate::config::Portage`]
/// a cesse d'etre un jeu de champs facultatifs pour la meme raison.
///
/// `tete` n'est PAS un premier choix. L'ordre d'essai vient de la couche de
/// selection, qui ne connait pas ce type; `tete` est seulement celui dont
/// l'absence vaudrait une liste vide.
///
/// # Pourquoi un seul profil par transport
///
/// La couche de selection raisonne en TECHNIQUES, pas en serveurs: elle
/// ordonne "REALITY avant Hysteria2", et la course qui la suit distribue des
/// techniques. Deux profils REALITY seraient deux serveurs pour une meme
/// technique, ce qu'aucune des deux ne sait distinguer - la course en
/// essaierait un et croirait la technique jugee. Le choix d'un serveur PARMI
/// plusieurs est un autre axe, et il attendra d'etre traite comme tel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "Vec<Profil>", into = "Vec<Profil>")]
pub struct Profils {
    tete: Profil,
    reste: Vec<Profil>,
}

impl Profils {
    /// Un seul profil, ce qui est le cas ordinaire aujourd'hui.
    pub fn un(profil: Profil) -> Self {
        Self {
            tete: profil,
            reste: Vec::new(),
        }
    }

    /// Tous les profils, dans l'ordre ou ils ont ete declares.
    ///
    /// Cet ordre n'est pas un ordre de preference et ne doit jamais etre lu
    /// comme tel: c'est la selection qui classe.
    pub fn tous(&self) -> impl Iterator<Item = &Profil> {
        std::iter::once(&self.tete).chain(self.reste.iter())
    }

    pub fn combien(&self) -> usize {
        1 + self.reste.len()
    }

    /// Le profil qui decrit ce transport, s'il y en a un.
    ///
    /// Au plus un: le constructeur refuse les doublons.
    pub fn pour(&self, nom_du_transport: &str) -> Option<&Profil> {
        self.tous().find(|p| p.transport.nom() == nom_du_transport)
    }
}

impl From<Profil> for Profils {
    fn from(p: Profil) -> Self {
        Self::un(p)
    }
}

impl From<Profils> for Vec<Profil> {
    fn from(p: Profils) -> Self {
        std::iter::once(p.tete).chain(p.reste).collect()
    }
}

impl TryFrom<Vec<Profil>> for Profils {
    type Error = Error;

    /// C'est ICI que la liste est validee, donc a la lecture du fichier comme
    /// a la lecture de la trame IPC. Aucun appelant n'a a se rappeler de le
    /// faire.
    fn try_from(profils: Vec<Profil>) -> Result<Self> {
        let mut profils = profils.into_iter();
        let tete = profils.next().ok_or_else(|| {
            Error::Config(
                "aucun profil de coeur: un portage par coeur qui ne designe aucun coeur lancerait un coeur sans sortie, derriere un selecteur vide"
                    .into(),
            )
        })?;
        let reste: Vec<Profil> = profils.collect();

        let liste = Self { tete, reste };
        let mut vus: Vec<&str> = Vec::new();
        for p in liste.tous() {
            let nom = p.transport.nom();
            if vus.contains(&nom) {
                return Err(Error::Config(format!(
                    "deux profils decrivent le transport {nom}: la selection raisonne en techniques et non en serveurs, donc elle ne saurait pas les distinguer. Choisir un serveur parmi plusieurs est un autre besoin, pas encore traite"
                )));
            }
            vus.push(nom);
        }
        Ok(liste)
    }
}

impl Profil {
    /// Lit un lien de partage.
    ///
    /// Accepte `vless://`, `hysteria2://` et son alias `hy2://`. Tout le reste,
    /// y compris ce que ces schemas savent exprimer mais que le generateur
    /// n'ecrit pas, est refuse en nommant la raison.
    pub fn depuis_lien(lien: &str) -> Result<Self> {
        let decoupe = Lien::decouper(lien.trim())?;
        match decoupe.schema.as_str() {
            "vless" => decoupe.en_vless(),
            "hysteria2" | "hy2" => decoupe.en_hysteria2(),
            autre => Err(Error::Config(format!(
                "schema de lien non gere: {autre}. Attendus: vless, hysteria2, hy2"
            ))),
        }
    }

    /// Le serveur vise, pour un journal ou un diagnostic. Ne contient aucun
    /// secret.
    pub fn serveur(&self) -> (&str, u16) {
        match &self.transport {
            Transport::VlessReality(v) => (&v.serveur, v.port),
            Transport::VlessWebsocket(v) | Transport::VlessHttpUpgrade(v) => (&v.serveur, v.port),
            Transport::Hysteria2(h) => (&h.serveur, h.port),
        }
    }
}

// --------------------------------------------------------------------------
// Decoupage d'un lien
// --------------------------------------------------------------------------

/// Un lien decoupe, avant d'etre interprete selon son schema.
struct Lien {
    schema: String,
    /// Deja decode. Peut etre vide.
    userinfo: String,
    hote: String,
    port: Option<u16>,
    parametres: Vec<(String, String)>,
    etiquette: String,
}

impl Lien {
    fn decouper(lien: &str) -> Result<Self> {
        let (schema, reste) = lien
            .split_once("://")
            .ok_or_else(|| Error::Config("lien invalide: '://' absent".into()))?;
        if schema.is_empty() {
            return Err(Error::Config("lien invalide: schema vide".into()));
        }

        // Le fragment d'abord: il peut contenir n'importe quoi, y compris un
        // '?' ou un '@' qui feraient derailler les decoupages suivants.
        let (avant_fragment, fragment) = match reste.split_once('#') {
            Some((a, f)) => (a, f),
            None => (reste, ""),
        };
        let etiquette = decoder(fragment, "etiquette")?;
        if etiquette.chars().count() > ETIQUETTE_MAX {
            return Err(Error::Config(format!(
                "etiquette trop longue: {} caracteres, {ETIQUETTE_MAX} au plus",
                etiquette.chars().count()
            )));
        }
        // Une etiquette voyage jusqu'aux journaux. Un saut de ligne y
        // fabriquerait une ligne entiere a la main de qui a ecrit le lien.
        if let Some(c) = etiquette.chars().find(|c| c.is_control()) {
            return Err(Error::Config(format!(
                "etiquette invalide: caractere de controle U+{:04X}",
                c as u32
            )));
        }

        let (autorite, requete) = match avant_fragment.split_once('?') {
            Some((a, q)) => (a, q),
            None => (avant_fragment, ""),
        };
        // `hysteria2://` porte une barre avant sa requete; `vless://` non.
        let autorite = autorite.strip_suffix('/').unwrap_or(autorite);

        // Le DERNIER '@': un mot de passe non encode peut en contenir un, et
        // l'hote, jamais.
        let (userinfo, hote_port) = match autorite.rsplit_once('@') {
            Some((u, h)) => (decoder(u, "identifiants")?, h),
            None => (String::new(), autorite),
        };
        if hote_port.is_empty() {
            return Err(Error::Config("lien invalide: hote absent".into()));
        }
        let (hote, port) = separer_hote_port(hote_port)?;

        let mut parametres: Vec<(String, String)> = Vec::new();
        for (cle, valeur) in form_urlencoded::parse(requete.as_bytes()) {
            // Une valeur vide vaut absente: les liens reels portent souvent un
            // `&sid=&spx=` que le panneau a laisse.
            if valeur.is_empty() {
                continue;
            }
            let cle = cle.into_owned();
            if parametres.iter().any(|(c, _)| *c == cle) {
                return Err(Error::Config(format!(
                    "parametre '{cle}' present deux fois: lequel serait le bon"
                )));
            }
            parametres.push((cle, valeur.into_owned()));
        }

        Ok(Self {
            schema: schema.to_ascii_lowercase(),
            userinfo,
            hote: hote.to_owned(),
            port,
            parametres,
            etiquette,
        })
    }

    fn parametre(&self, nom: &str) -> Option<&str> {
        self.parametres
            .iter()
            .find(|(c, _)| c == nom)
            .map(|(_, v)| v.as_str())
    }

    /// Refuse tout parametre qui n'est pas dans la liste.
    ///
    /// Un parametre inconnu n'est pas decoratif: c'est souvent lui qui decide
    /// si la connexion aboutit. L'ignorer donnerait une configuration qui ne
    /// dit pas la meme chose que le lien dont elle vient.
    fn refuser_les_autres(&self, connus: &[&str]) -> Result<()> {
        if let Some((cle, _)) = self
            .parametres
            .iter()
            .find(|(c, _)| !connus.contains(&c.as_str()))
        {
            return Err(Error::Config(format!(
                "parametre '{cle}' non gere par ce client: il changerait la connexion sans que la configuration engendree le dise. Parametres acceptes: {}",
                connus.join(", ")
            )));
        }
        Ok(())
    }

    /// Refuse une valeur differente de celle que le generateur ecrit en dur.
    fn exiger_valeur(&self, nom: &str, attendue: &str) -> Result<()> {
        match self.parametre(nom) {
            None => Ok(()),
            Some(v) if v.eq_ignore_ascii_case(attendue) => Ok(()),
            Some(v) => Err(Error::Config(format!(
                "'{nom}={v}' non gere par ce client, qui ecrit '{nom}={attendue}'"
            ))),
        }
    }

    fn etiquette_ou(&self, hote: &str, port: u16) -> String {
        if self.etiquette.is_empty() {
            format!("{hote}:{port}")
        } else {
            self.etiquette.clone()
        }
    }

    fn en_vless(self) -> Result<Profil> {
        const CONNUS: [&str; 10] = [
            "security",
            "type",
            "flow",
            "encryption",
            "fp",
            "pbk",
            "sid",
            "sni",
            "host",
            "path",
        ];
        self.refuser_les_autres(&CONNUS)?;

        // Le `type` decide de tout le reste, et c'est pourquoi il est lu en
        // premier. Deux formes seulement, parce que le generateur n'en ecrit
        // que deux: un profil ne doit pas pouvoir promettre ce que la suite ne
        // sait pas tenir.
        match self.parametre("type").unwrap_or("tcp") {
            t if t.eq_ignore_ascii_case("tcp") => {}
            t if t.eq_ignore_ascii_case("ws") => return self.en_vless_sur_http(true),
            t if t.eq_ignore_ascii_case("httpupgrade") => return self.en_vless_sur_http(false),
            t => {
                return Err(Error::Config(format!(
                    "'type={t}' non gere: ce client ecrit 'tcp' (REALITY), 'ws' (repli CDN) et 'httpupgrade' (front auto-heberge)"
                )));
            }
        }

        // REALITY seul sur le transport TCP: un `security=tls` y produirait un
        // VLESS en TLS ordinaire, qui n'a ni les proprietes ni les risques de
        // REALITY. Le TLS ordinaire a sa place, mais derriere HTTPUpgrade.
        match self.parametre("security") {
            Some(v) if v.eq_ignore_ascii_case("reality") => {}
            Some(v) => {
                return Err(Error::Config(format!(
                    "'security={v}' non gere sur 'type=tcp': ce client n'y ecrit que REALITY"
                )));
            }
            None => {
                return Err(Error::Config(
                    "'security' absent: un lien VLESS sans 'security=reality' decrit un transport que ce client n'ecrit pas".into(),
                ));
            }
        }
        self.exiger_valeur("flow", "xtls-rprx-vision")?;
        self.exiger_valeur("encryption", "none")?;
        self.exiger_valeur("fp", "chrome")?;

        let port = self
            .port
            .ok_or_else(|| Error::Config("lien VLESS invalide: port absent".into()))?;
        if self.userinfo.is_empty() {
            return Err(Error::Config("lien VLESS invalide: UUID absent".into()));
        }
        let uuid: Uuid = self.userinfo.parse()?;

        let cle_publique: ClePublique = self
            .parametre("pbk")
            .ok_or_else(|| {
                Error::Config("lien VLESS invalide: 'pbk' absent, REALITY l'exige".into())
            })?
            .parse()?;
        let short_id = match self.parametre("sid") {
            Some(v) => v.parse()?,
            None => ShortId::vide(),
        };
        // Obligatoire, contre la specification, et l'en-tete du module dit
        // pourquoi.
        let nom_de_serveur = self
            .parametre("sni")
            .ok_or_else(|| {
                Error::Config(
                    "lien VLESS invalide: 'sni' absent. La specification le fait defaut a l'hote, mais pour REALITY c'est le site emprunte, que l'hote n'est jamais"
                        .into(),
                )
            })?
            .to_owned();

        let etiquette = self.etiquette_ou(&self.hote, port);
        Ok(Profil {
            etiquette,
            transport: Transport::VlessReality(Box::new(VlessReality {
                serveur: self.hote,
                port,
                uuid,
                cle_publique,
                short_id,
                nom_de_serveur,
            })),
        })
    }

    /// Les branches `ws` et `httpupgrade`, qui ne different que par leur
    /// variante de sortie.
    ///
    /// # Pourquoi le flow est refuse ici et non ignore
    ///
    /// XTLS-Vision ne s'applique qu'a un transport TCP nu: le document 04
    /// partie 2.1 le pose, "incompatible avec WebSocket/gRPC/XHTTP". Un lien
    /// qui porte les deux decrit une chose qui ne fonctionne pas. L'ignorer
    /// silencieusement engendrerait une configuration que le coeur rejette au
    /// demarrage, et l'utilisateur lirait un echec de coeur sans rapport
    /// apparent avec le lien qu'il a colle.
    fn en_vless_sur_http(self, websocket: bool) -> Result<Profil> {
        self.exiger_valeur("security", "tls")?;
        if self.parametre("security").is_none() {
            return Err(Error::Config(
                "'security' absent: un repli CDN se decrit par 'security=tls'".into(),
            ));
        }
        if let Some(f) = self.parametre("flow") {
            return Err(Error::Config(format!(
                "'flow={f}' refuse sur un transport HTTP: XTLS-Vision ne s'applique qu'a un transport TCP nu"
            )));
        }
        self.exiger_valeur("encryption", "none")?;
        self.exiger_valeur("fp", "chrome")?;
        for absent in ["pbk", "sid"] {
            if self.parametre(absent).is_some() {
                return Err(Error::Config(format!(
                    "'{absent}' refuse sur un transport HTTP: ce parametre appartient a REALITY, que ce transport n'emploie pas"
                )));
            }
        }

        let port = self
            .port
            .ok_or_else(|| Error::Config("lien VLESS invalide: port absent".into()))?;
        if self.userinfo.is_empty() {
            return Err(Error::Config("lien VLESS invalide: UUID absent".into()));
        }
        let uuid: Uuid = self.userinfo.parse()?;

        // Exige, alors que la specification le fait defaut a l'hote. Meme
        // raison que pour REALITY: un defaut silencieux ferait dependre la
        // poignee de main d'une valeur que l'utilisateur n'a pas ecrite.
        let nom_de_serveur = self
            .parametre("sni")
            .ok_or_else(|| Error::Config("lien VLESS invalide: 'sni' absent".into()))?
            .to_owned();
        // Le `Host` par defaut vaut la SNI, et ce defaut-la est sur: les deux
        // designent alors le meme CDN. Les separer est un choix explicite.
        let hote = self.parametre("host").unwrap_or(&nom_de_serveur).to_owned();
        let chemin = match self.parametre("path") {
            Some(c) if c.starts_with('/') => c.to_owned(),
            Some(c) => {
                return Err(Error::Config(format!(
                    "'path={c}' invalide: un chemin HTTP commence par '/'"
                )));
            }
            None => {
                return Err(Error::Config(
                    "'path' absent: c'est lui qui empeche un sondage actif de retrouver le point d'entree en devinant".into(),
                ));
            }
        };

        let etiquette = self.etiquette_ou(&self.hote, port);
        let sur_http = Box::new(VlessSurHttp {
            serveur: self.hote,
            port,
            uuid,
            nom_de_serveur,
            hote,
            chemin,
        });
        Ok(Profil {
            etiquette,
            transport: if websocket {
                Transport::VlessWebsocket(sur_http)
            } else {
                Transport::VlessHttpUpgrade(sur_http)
            },
        })
    }

    fn en_hysteria2(self) -> Result<Profil> {
        const CONNUS: [&str; 3] = ["obfs", "obfs-password", "sni"];
        // `insecure` et `pinSHA256` sont refuses par ce filtre comme le reste,
        // mais leur message merite d'etre plus precis que "non gere".
        if let Some(v) = self.parametre("insecure")
            && v != "0"
        {
            return Err(Error::Config(format!(
                "'insecure={v}' refuse: ce client n'a deliberement aucun mode 'ne pas verifier'. Un certificat auto-signe s'epingle par le champ 'certificat' du profil, il ne s'ignore pas"
            )));
        }
        if self.parametre("pinSHA256").is_some() {
            return Err(Error::Config(
                "'pinSHA256' non gere: la confiance s'exprime par le champ 'certificat' du profil, qui porte le PEM entier, pas par une empreinte dans le lien".into(),
            ));
        }
        let connus_avec_insecure: Vec<&str> = CONNUS.iter().copied().chain(["insecure"]).collect();
        self.refuser_les_autres(&connus_avec_insecure)?;

        self.exiger_valeur("obfs", "salamander")?;

        let port = self.port.unwrap_or(PORT_HYSTERIA2_DEFAUT);
        if self.userinfo.is_empty() {
            return Err(Error::Config(
                "lien Hysteria2 invalide: authentification absente".into(),
            ));
        }
        let mot_de_passe: MotDePasse = self.userinfo.parse()?;

        // Un `obfs` sans son mot de passe donne un client qui obfusque avec
        // rien: la poignee de main ne ressemble ni a du QUIC nu ni a du
        // Salamander, et le serveur la jette sans rien dire.
        let obfs = match (self.parametre("obfs"), self.parametre("obfs-password")) {
            (Some(_), Some(mdp)) => Some(mdp.parse()?),
            (Some(_), None) => {
                return Err(Error::Config(
                    "lien Hysteria2 invalide: 'obfs' demande sans 'obfs-password'".into(),
                ));
            }
            (None, Some(_)) => {
                return Err(Error::Config(
                    "lien Hysteria2 invalide: 'obfs-password' fourni sans 'obfs'".into(),
                ));
            }
            (None, None) => None,
        };

        // Le SNI d'un lien Hysteria2 vaut bien l'hote par defaut: il n'y a pas
        // de site emprunte ici, le serveur presente son propre certificat.
        let nom_de_serveur = self
            .parametre("sni")
            .unwrap_or(self.hote.as_str())
            .to_owned();

        let etiquette = self.etiquette_ou(&self.hote, port);
        Ok(Profil {
            etiquette,
            transport: Transport::Hysteria2(Box::new(Hysteria2 {
                serveur: self.hote,
                port,
                mot_de_passe,
                obfs,
                nom_de_serveur,
                // Un lien ne porte pas de PEM: le format Hysteria2 n'a pas de
                // parametre pour ca, et en inventer un donnerait un lien que
                // les autres clients refusent. L'epinglage passe par le profil.
                certificat: None,
            })),
        })
    }
}

/// Decode le pourcent-encodage et exige de l'UTF-8.
fn decoder(brut: &str, quoi: &str) -> Result<String> {
    percent_encoding::percent_decode_str(brut)
        .decode_utf8()
        .map(|c| c.into_owned())
        .map_err(|e| Error::Config(format!("{quoi}: sequence non UTF-8 apres decodage ({e})")))
}

/// Separe l'hote de son port, en tenant compte des crochets IPv6.
fn separer_hote_port(brut: &str) -> Result<(&str, Option<u16>)> {
    if let Some(reste) = brut.strip_prefix('[') {
        let (hote, apres) = reste
            .split_once(']')
            .ok_or_else(|| Error::Config("adresse IPv6 invalide: ']' absent".into()))?;
        if hote.is_empty() {
            return Err(Error::Config("adresse IPv6 vide".into()));
        }
        let port = match apres {
            "" => None,
            p => Some(lire_port(p.strip_prefix(':').ok_or_else(|| {
                Error::Config(format!("caracteres inattendus apres l'adresse IPv6: {p}"))
            })?)?),
        };
        return Ok((hote, port));
    }
    match brut.rsplit_once(':') {
        Some((hote, port)) if !hote.is_empty() => Ok((hote, Some(lire_port(port)?))),
        Some(_) => Err(Error::Config("lien invalide: hote vide".into())),
        None => Ok((brut, None)),
    }
}

fn lire_port(brut: &str) -> Result<u16> {
    // Hysteria2 sait sauter de port par une liste ou une plage. Ce client
    // n'ecrit qu'un port, donc il refuse plutot que d'en choisir un au hasard
    // dans une intention qu'il ne saurait pas tenir.
    if brut.contains(',') || brut.contains('-') {
        return Err(Error::Config(format!(
            "port '{brut}' non gere: le saut de port demande une plage, ce client n'ecrit qu'un port"
        )));
    }
    brut.parse::<u16>()
        .map_err(|_| Error::Config(format!("port invalide: {brut}")))
        .and_then(|p| {
            if p == 0 {
                Err(Error::Config("port invalide: 0".into()))
            } else {
                Ok(p)
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 43 caracteres de l'alphabet base64url, la forme que rend `xray x25519`.
    fn cle() -> String {
        "a".repeat(CLE_REALITY_CARS)
    }

    const UUID: &str = "4292f5ab-8963-476c-8052-3615895ce4f1";

    fn lien_reality() -> String {
        format!(
            "vless://{UUID}@203.0.113.7:443?security=reality&flow=xtls-rprx-vision&encryption=none&fp=chrome&type=tcp&pbk={}&sid=d8c6b58bcbb0c323&sni=dl.google.com#Sortie%20de%20secours",
            cle()
        )
    }

    #[test]
    fn un_lien_reality_complet_se_lit() {
        let p = Profil::depuis_lien(&lien_reality()).expect("le lien doit se lire");
        assert_eq!(p.etiquette, "Sortie de secours");
        let Transport::VlessReality(v) = p.transport else {
            panic!("attendu VLESS");
        };
        assert_eq!(v.serveur, "203.0.113.7");
        assert_eq!(v.port, 443);
        assert_eq!(v.uuid.as_str(), UUID);
        assert_eq!(v.cle_publique.as_str(), cle());
        assert_eq!(v.short_id.as_str(), "d8c6b58bcbb0c323");
        // Le site emprunte, pas l'hote: c'est tout l'interet du controle.
        assert_eq!(v.nom_de_serveur, "dl.google.com");
    }

    fn lien_httpupgrade() -> String {
        format!(
            "vless://{UUID}@cdn.exemple.test:443?security=tls&type=httpupgrade&encryption=none&fp=chrome&host=cdn.exemple.test&path=%2Fw1s2x3&sni=cdn.exemple.test#Repli%20CDN"
        )
    }

    /// Le repli derriere CDN, celui qui survit a une interception TLS.
    ///
    /// Sa raison d'etre est mesuree ailleurs: en mode Discret, une interception
    /// TLS d'entreprise elimine REALITY et le mode elimine tout le reste. Sans
    /// ce transport, le plan rend un candidat que rien ne sait monter.
    #[test]
    fn un_lien_httpupgrade_complet_se_lit() {
        let p = Profil::depuis_lien(&lien_httpupgrade()).expect("le lien doit se lire");
        assert_eq!(p.etiquette, "Repli CDN");
        let Transport::VlessHttpUpgrade(v) = p.transport else {
            panic!("attendu VLESS httpupgrade");
        };
        assert_eq!(v.serveur, "cdn.exemple.test");
        assert_eq!(v.port, 443);
        assert_eq!(v.uuid.as_str(), UUID);
        assert_eq!(v.nom_de_serveur, "cdn.exemple.test");
        assert_eq!(v.hote, "cdn.exemple.test");
        assert_eq!(v.chemin, "/w1s2x3");
    }

    /// XTLS-Vision ne s'applique qu'a un transport TCP nu.
    ///
    /// Le document 04 partie 2.1 le dit: le flow est "incompatible avec
    /// WebSocket/gRPC/XHTTP". Un lien qui le porte sur un transport HTTP
    /// decrit donc une chose qui ne marche pas, et le refuser tot vaut mieux
    /// que d'engendrer une configuration que le coeur rejettera.
    #[test]
    fn un_lien_httpupgrade_refuse_le_flow_vision() {
        let lien = lien_httpupgrade().replace("&encryption=", "&flow=xtls-rprx-vision&encryption=");
        let e = Profil::depuis_lien(&lien).expect_err("le flow doit etre refuse ici");
        assert!(
            e.to_string().contains("flow"),
            "le refus doit nommer le flow: {e}"
        );
    }

    /// L'accord des deux vocabulaires, cote profil.
    #[test]
    fn le_nom_des_transports_sur_http_suit_les_techniques() {
        let hu = Profil::depuis_lien(&lien_httpupgrade()).expect("le lien doit se lire");
        assert_eq!(hu.transport.nom(), "httpupgrade-front");
        assert_eq!(hu.serveur(), ("cdn.exemple.test", 443));

        let ws = Profil::depuis_lien(&lien_websocket()).expect("le lien doit se lire");
        assert_eq!(ws.transport.nom(), "websocket-cdn");
        assert_eq!(ws.serveur(), ("cdn.exemple.test", 443));
    }

    fn lien_websocket() -> String {
        lien_httpupgrade().replace("type=httpupgrade", "type=ws")
    }

    /// Le repli qui traverse REELLEMENT un CDN.
    ///
    /// Mesure du 21 aout 2026 a travers un edge Cloudflare: `ws` passe,
    /// `httpupgrade` non. Les deux se lisent, parce que ce client ne choisit
    /// pas le transport - l'operateur du serveur le choisit - mais ils ne
    /// donnent pas la meme variante, et c'est cette distinction que la recette
    /// garde.
    #[test]
    fn un_lien_websocket_complet_se_lit_et_donne_une_autre_variante() {
        let p = Profil::depuis_lien(&lien_websocket()).expect("le lien doit se lire");
        let Transport::VlessWebsocket(v) = p.transport else {
            panic!("attendu VLESS websocket, pas httpupgrade");
        };
        assert_eq!(v.serveur, "cdn.exemple.test");
        assert_eq!(v.chemin, "/w1s2x3");

        // Et le controle: le meme lien en httpupgrade ne donne PAS la variante
        // websocket. Sans lui, un parseur qui rendrait toujours la meme
        // variante passerait la recette ci-dessus.
        let autre = Profil::depuis_lien(&lien_httpupgrade()).expect("le lien doit se lire");
        assert!(matches!(autre.transport, Transport::VlessHttpUpgrade(_)));
    }

    /// Les restes de REALITY sont refuses sur un transport HTTP, ws compris.
    #[test]
    fn un_lien_websocket_refuse_les_restes_de_reality() {
        // Par l'aide, pas par concatenation: un '&' colle apres le '#' irait
        // dans l'etiquette et la recette passerait sans rien mesurer.
        let lien = avec_parametre(&lien_websocket(), &format!("pbk={}", cle()));
        let e = Profil::depuis_lien(&lien).expect_err("'pbk' n'a rien a faire ici");
        assert!(e.to_string().contains("pbk"), "{e}");
    }

    #[test]
    fn un_lien_hysteria2_complet_se_lit() {
        let p = Profil::depuis_lien(
            "hysteria2://motdepasse@203.0.113.8:8443/?obfs=salamander&obfs-password=sel&sni=exemple.test#Rapide",
        )
        .expect("le lien doit se lire");
        assert_eq!(p.etiquette, "Rapide");
        let Transport::Hysteria2(h) = p.transport else {
            panic!("attendu Hysteria2");
        };
        assert_eq!(h.serveur, "203.0.113.8");
        assert_eq!(h.port, 8443);
        assert_eq!(h.mot_de_passe.as_str(), "motdepasse");
        assert_eq!(h.obfs.as_ref().map(MotDePasse::as_str), Some("sel"));
        assert_eq!(h.nom_de_serveur, "exemple.test");
    }

    #[test]
    fn le_port_hysteria2_par_defaut_est_celui_de_la_specification() {
        let p = Profil::depuis_lien("hy2://mdp@203.0.113.8").unwrap();
        assert_eq!(p.serveur(), ("203.0.113.8", PORT_HYSTERIA2_DEFAUT));
    }

    #[test]
    fn sans_sni_un_lien_reality_est_refuse() {
        // La specification ferait defaut a l'hote. Ce serait un profil valide
        // et mort: le SNI de REALITY est le site emprunte.
        let lien = lien_reality().replace("&sni=dl.google.com", "");
        let e = Profil::depuis_lien(&lien).expect_err("le sni doit etre exige");
        assert!(e.to_string().contains("sni"), "{e}");
        assert!(e.to_string().contains("emprunte"), "{e}");
    }

    #[test]
    fn un_transport_non_ecrit_est_refuse_et_nomme() {
        // `grpc` est un transport que sing-box porte mais que ce client
        // n'ecrit pas. Cette recette visait `ws` avant que celui-ci ne devienne
        // le repli CDN: la remplacer plutot que la supprimer garde la propriete
        // qu'elle mesurait, qu'un transport inconnu soit refuse ET nomme.
        let lien = lien_reality().replace("type=tcp", "type=grpc");
        let e = Profil::depuis_lien(&lien).expect_err("grpc doit etre refuse");
        assert!(e.to_string().contains("type=grpc"), "{e}");
    }

    #[test]
    fn un_vless_en_tls_ordinaire_est_refuse() {
        let lien = lien_reality().replace("security=reality", "security=tls");
        let e = Profil::depuis_lien(&lien).expect_err("tls seul doit etre refuse");
        assert!(e.to_string().contains("REALITY"), "{e}");
    }

    /// Ajoute un parametre a la requete, donc AVANT le fragment. Le poser
    /// apres le '#' le mettrait dans l'etiquette, ce qui ne prouverait rien:
    /// le decoupage detache le fragment en premier, exactement pour qu'un '&'
    /// ou un '?' ecrit dans un libelle ne devienne pas un parametre.
    fn avec_parametre(lien: &str, ajout: &str) -> String {
        let (avant, fragment) = lien
            .split_once('#')
            .expect("le lien de reference a un fragment");
        format!("{avant}&{ajout}#{fragment}")
    }

    #[test]
    fn un_parametre_inconnu_est_refuse_plutot_qu_ignore() {
        let lien = avec_parametre(&lien_reality(), "alpn=h2");
        let e = Profil::depuis_lien(&lien).expect_err("alpn doit etre refuse");
        assert!(e.to_string().contains("alpn"), "{e}");
    }

    #[test]
    fn insecure_est_refuse_avec_sa_raison() {
        let e = Profil::depuis_lien("hysteria2://mdp@203.0.113.8:443/?insecure=1")
            .expect_err("insecure doit etre refuse");
        assert!(e.to_string().contains("epingle"), "{e}");
    }

    #[test]
    fn insecure_a_zero_ne_gene_pas() {
        // Beaucoup de panneaux le posent a 0. Le refuser rejetterait des liens
        // qui ne demandent rien.
        Profil::depuis_lien("hysteria2://mdp@203.0.113.8:443/?insecure=0")
            .expect("insecure=0 ne demande rien");
    }

    #[test]
    fn une_empreinte_epinglee_est_refusee_faute_de_pouvoir_etre_honoree() {
        let e = Profil::depuis_lien("hysteria2://mdp@203.0.113.8:443/?pinSHA256=ab%3Acd")
            .expect_err("pinSHA256 doit etre refuse");
        assert!(e.to_string().contains("PEM"), "{e}");
    }

    #[test]
    fn obfs_sans_mot_de_passe_est_refuse() {
        let e = Profil::depuis_lien("hysteria2://mdp@203.0.113.8:443/?obfs=salamander")
            .expect_err("un obfs muet doit etre refuse");
        assert!(e.to_string().contains("obfs-password"), "{e}");
    }

    #[test]
    fn le_saut_de_port_est_refuse_plutot_que_tranche() {
        let e = Profil::depuis_lien("hysteria2://mdp@203.0.113.8:443,5000-6000")
            .expect_err("le saut de port doit etre refuse");
        assert!(e.to_string().contains("saut de port"), "{e}");
    }

    #[test]
    fn une_adresse_ipv6_garde_son_port() {
        let p = Profil::depuis_lien("hy2://mdp@[2001:db8::1]:8443").unwrap();
        assert_eq!(p.serveur(), ("2001:db8::1", 8443));
    }

    #[test]
    fn une_adresse_ipv6_sans_port_prend_le_defaut() {
        let p = Profil::depuis_lien("hy2://mdp@[2001:db8::1]").unwrap();
        assert_eq!(p.serveur(), ("2001:db8::1", PORT_HYSTERIA2_DEFAUT));
    }

    #[test]
    fn un_parametre_repete_est_refuse() {
        let lien = avec_parametre(&lien_reality(), "sni=autre.test");
        let e = Profil::depuis_lien(&lien).expect_err("le doublon doit etre refuse");
        assert!(e.to_string().contains("deux fois"), "{e}");
    }

    #[test]
    fn un_parametre_vide_vaut_absent() {
        // Les panneaux laissent souvent un `&sid=` derriere eux.
        let lien = lien_reality().replace("sid=d8c6b58bcbb0c323", "sid=");
        let p = Profil::depuis_lien(&lien).expect("un sid vide est legitime");
        let Transport::VlessReality(v) = p.transport else {
            panic!("attendu VLESS");
        };
        assert_eq!(v.short_id.as_str(), "");
    }

    #[test]
    fn une_etiquette_ne_peut_pas_fabriquer_une_ligne_de_journal() {
        let lien = lien_reality().replace("#Sortie%20de%20secours", "#a%0Adeconnecte");
        let e = Profil::depuis_lien(&lien).expect_err("le saut de ligne doit etre refuse");
        assert!(e.to_string().contains("controle"), "{e}");
    }

    #[test]
    fn une_etiquette_absente_devient_le_serveur() {
        let lien = lien_reality().replace("#Sortie%20de%20secours", "");
        let p = Profil::depuis_lien(&lien).unwrap();
        assert_eq!(p.etiquette, "203.0.113.7:443");
    }

    #[test]
    fn un_uuid_malforme_est_refuse() {
        let lien = lien_reality().replace(UUID, "pas-un-uuid");
        let e = Profil::depuis_lien(&lien).expect_err("l'uuid doit etre valide");
        assert!(e.to_string().contains("UUID"), "{e}");
    }

    #[test]
    fn une_cle_reality_en_base64_ordinaire_est_refusee() {
        // Le symptome d'une cle recopiee du mauvais champ. La laisser passer
        // donne un EOF muet a la connexion.
        let mauvaise = format!("{}+", "a".repeat(CLE_REALITY_CARS - 1));
        let lien = lien_reality().replace(&cle(), &mauvaise);
        let e = Profil::depuis_lien(&lien).expect_err("le '+' doit etre refuse");
        assert!(e.to_string().contains("base64url"), "{e}");
    }

    #[test]
    fn un_short_id_de_longueur_impaire_est_refuse() {
        let lien = lien_reality().replace("sid=d8c6b58bcbb0c323", "sid=abc");
        let e = Profil::depuis_lien(&lien).expect_err("une longueur impaire doit etre refusee");
        assert!(e.to_string().contains("pair"), "{e}");
    }

    #[test]
    fn un_schema_inconnu_est_refuse_en_nommant_ce_qui_est_accepte() {
        let e = Profil::depuis_lien("vmess://quelquechose@203.0.113.9:443")
            .expect_err("vmess n'est pas gere");
        assert!(e.to_string().contains("vless"), "{e}");
    }

    /// Le controle qui compte pour un secret: il ne doit atterrir ni dans un
    /// journal, ni dans un rapport de diagnostic.
    #[test]
    fn les_secrets_ne_sortent_pas_par_debug() {
        let p = Profil::depuis_lien(&lien_reality()).unwrap();
        let rendu = format!("{p:?}");
        assert!(!rendu.contains(UUID), "l'UUID a fuit par Debug: {rendu}");
        assert!(rendu.contains("<redacted>"), "{rendu}");
        // La cle publique, elle, doit rester lisible: c'est le champ dont une
        // erreur de transcription est la plus dure a diagnostiquer.
        assert!(rendu.contains(&cle()), "{rendu}");

        let h = Profil::depuis_lien(
            "hysteria2://motdepasse-secret@203.0.113.8:443/?obfs=salamander&obfs-password=sel",
        )
        .unwrap();
        let rendu = format!("{h:?}");
        assert!(!rendu.contains("motdepasse-secret"), "{rendu}");
        assert!(!rendu.contains("sel"), "{rendu}");
    }

    /// Le chainon manquant entre deux refus et rien.
    ///
    /// Ce module refuse `insecure=1` en disant "un certificat auto-signe
    /// s'epingle, il ne s'ignore pas", et refuse `pinSHA256` en disant "la
    /// confiance s'exprime ici par un certificat epingle en PEM". Les deux
    /// messages designaient un mecanisme qui n'existait nulle part:
    /// `Hysteria2` n'avait pas de champ pour le porter, et le generateur du
    /// daemon posait `Confiance::AutoritesDuSysteme` sans condition. Un
    /// serveur auto-heberge - le cas ordinaire de ce produit, et celui que le
    /// banc `--coeur-e2e` monte lui-meme - etait donc injoignable par le seul
    /// chemin qu'un utilisateur peut ecrire.
    /// Un PEM de forme correcte et de contenu quelconque: ces recettes
    /// controlent la structure, et aucune ne dechiffre le certificat.
    const PEM: &str = "-----BEGIN CERTIFICATE-----
TUlJQlBBU1VOVlJBSUNFUlQ=
-----END CERTIFICATE-----";

    #[test]
    fn un_profil_hysteria2_epingle_le_certificat_de_son_serveur() {
        let json = format!(
            r#"{{"etiquette":"maison","transport":{{"transport":"hysteria2","serveur":"203.0.113.8","port":443,"mot_de_passe":"secret","obfs":null,"nom_de_serveur":"exemple.test","certificat":{}}}}}"#,
            serde_json::to_string(PEM).unwrap()
        );
        let p: Profil = serde_json::from_str(&json).expect("un certificat PEM doit etre accepte");
        let Transport::Hysteria2(h) = &p.transport else {
            panic!("transport inattendu");
        };
        let c = h
            .certificat
            .as_ref()
            .expect("le certificat doit etre retenu");
        assert_eq!(c.lignes().first().unwrap(), "-----BEGIN CERTIFICATE-----");
        assert_eq!(c.lignes().len(), 3);
        // Et il franchit l'IPC: le daemon lit le profil que le client envoie.
        let retour: Profil = serde_json::from_str(&serde_json::to_string(&p).unwrap()).unwrap();
        assert_eq!(p, retour);
    }

    /// Refuser, jamais degrader. Un certificat qui n'en est pas un donnerait un
    /// coeur qui demarre et un tunnel qui echoue sans dire pourquoi.
    #[test]
    fn un_certificat_qui_n_est_pas_un_pem_est_refuse_en_nommant_ce_qui_manque() {
        let e = "MIIB..."
            .parse::<CertificatPem>()
            .expect_err("doit etre refuse");
        let m = e.to_string();
        assert!(m.contains("BEGIN CERTIFICATE"), "{m}");
        let sans_fin = "-----BEGIN CERTIFICATE-----
QUJD
";
        let e = sans_fin
            .parse::<CertificatPem>()
            .expect_err("doit etre refuse");
        assert!(e.to_string().contains("END CERTIFICATE"), "{e}");
    }

    /// Le refus doit nommer le champ qui existe, sinon il envoie l'utilisateur
    /// chercher un mecanisme sans lui dire ou.
    #[test]
    fn le_refus_de_pinsha256_nomme_le_champ_du_profil() {
        let e = Profil::depuis_lien("hysteria2://mdp@203.0.113.8:443/?pinSHA256=aa:bb")
            .expect_err("pinSHA256 doit etre refuse");
        assert!(e.to_string().contains("certificat"), "{e}");
    }

    #[test]
    fn un_profil_traverse_le_json_sans_perdre_ses_secrets() {
        // Il doit franchir l'IPC. Le controle est un aller-retour complet.
        let p = Profil::depuis_lien(&lien_reality()).unwrap();
        let json = serde_json::to_string(&p).unwrap();
        let retour: Profil = serde_json::from_str(&json).unwrap();
        assert_eq!(p, retour);
    }

    #[test]
    fn un_json_dont_l_uuid_est_malforme_est_refuse_a_la_lecture() {
        // La validation ne doit pas dependre du chemin d'entree: un profil
        // fabrique a la main et pousse par l'IPC passe par les memes controles.
        let p = Profil::depuis_lien(&lien_reality()).unwrap();
        let json = serde_json::to_string(&p)
            .unwrap()
            .replace(UUID, "pas-un-uuid");
        serde_json::from_str::<Profil>(&json).expect_err("la validation doit tenir aussi ici");
    }
}
