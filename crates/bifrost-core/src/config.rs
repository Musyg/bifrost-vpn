//! Configuration d'un tunnel, et validation.

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::profil::{Profil, Profils};
use crate::{Error, Result};

/// fwmark par defaut, identique a celui de wg-quick (0xca6c = 51820).
pub const DEFAULT_FWMARK: u32 = 0xca6c;

/// Table de routage dediee, meme convention que wg-quick.
pub const DEFAULT_ROUTING_TABLE: u32 = 51820;

/// MTU par defaut WireGuard (1500 - 80 octets d'overhead IPv6).
pub const DEFAULT_MTU: u32 = 1420;

/// Un prefixe reseau, par exemple `10.2.0.2/32` ou `::/0`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct IpNet {
    pub addr: IpAddr,
    pub prefix_len: u8,
}

impl IpNet {
    pub fn new(addr: IpAddr, prefix_len: u8) -> Result<Self> {
        let max = if addr.is_ipv4() { 32 } else { 128 };
        if prefix_len > max {
            return Err(Error::Config(format!(
                "prefixe /{prefix_len} hors plage pour {addr} (max /{max})"
            )));
        }
        Ok(Self { addr, prefix_len })
    }

    pub fn is_ipv4(&self) -> bool {
        self.addr.is_ipv4()
    }

    /// Vrai pour `0.0.0.0/0` et `::/0`, les prefixes qui capturent tout le trafic.
    pub fn is_default_route(&self) -> bool {
        self.prefix_len == 0
    }
}

impl FromStr for IpNet {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let (addr, prefix) = s
            .split_once('/')
            .ok_or_else(|| Error::Config(format!("prefixe manquant dans '{s}'")))?;
        let addr: IpAddr = addr
            .parse()
            .map_err(|_| Error::Config(format!("adresse IP invalide dans '{s}'")))?;
        let prefix_len: u8 = prefix
            .parse()
            .map_err(|_| Error::Config(format!("longueur de prefixe invalide dans '{s}'")))?;
        Self::new(addr, prefix_len)
    }
}

impl fmt::Display for IpNet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix_len)
    }
}

impl TryFrom<String> for IpNet {
    type Error = Error;
    fn try_from(s: String) -> Result<Self> {
        s.parse()
    }
}

impl From<IpNet> for String {
    fn from(v: IpNet) -> Self {
        v.to_string()
    }
}

/// Point de sortie du tunnel, cote serveur.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Endpoint {
    /// Hote resolu. Le daemon resout un eventuel nom de domaine avant d'armer
    /// le kill switch, sans quoi la resolution serait bloquee par le block-all.
    pub addr: SocketAddr,
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.addr)
    }
}

/// Le pair distant WireGuard.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerConfig {
    pub public_key: WgKey,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preshared_key: Option<WgKey>,
    pub endpoint: Endpoint,
    pub allowed_ips: Vec<IpNet>,
    #[serde(default = "default_keepalive")]
    pub persistent_keepalive: u16,
}

fn default_keepalive() -> u16 {
    25
}

/// Une cle WireGuard en base64 (32 octets, 44 caracteres).
///
/// Le `Debug` est volontairement opaque: une cle privee ne doit jamais atterrir
/// dans un log ou un rapport de diagnostic.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct WgKey(String);

/// Longueur d'une cle WireGuard, en octets. Curve25519.
pub const WG_KEY_BYTES: usize = 32;

impl WgKey {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Les 32 octets de la cle.
    ///
    /// Le plan de controle Linux prend la cle en base64 et la decode lui-meme.
    /// WireGuardNT, lui, attend les octets bruts dans son blob de
    /// configuration, d'ou ce decodage.
    ///
    /// Le tableau renvoye contient du secret quand la cle est privee. Il est
    /// `Copy`, donc l'appelant est responsable de ne pas le faire trainer: le
    /// seul usage prevu est de le recopier immediatement dans le blob.
    pub fn to_bytes(&self) -> Result<[u8; WG_KEY_BYTES]> {
        use base64::Engine as _;
        let raw = base64::engine::general_purpose::STANDARD
            .decode(&self.0)
            .map_err(|e| Error::Config(format!("cle WireGuard non decodable: {e}")))?;
        // Le constructeur impose deja 44 caracteres, donc 32 octets. On le
        // reverifie ici parce que ce tableau part directement vers un driver
        // noyau: une longueur inattendue ne doit jamais devenir une copie
        // hors bornes.
        raw.try_into().map_err(|v: Vec<u8>| {
            Error::Config(format!(
                "cle WireGuard de {} octets, {WG_KEY_BYTES} attendus",
                v.len()
            ))
        })
    }

    /// Construit une cle a partir de ses octets.
    ///
    /// Sert a reprendre une cle publique rendue par un driver, qui la derive
    /// lui-meme de la cle privee. Ca evite d'embarquer Curve25519 pour refaire
    /// ce calcul.
    pub fn from_bytes(bytes: &[u8; WG_KEY_BYTES]) -> Self {
        use base64::Engine as _;
        Self(base64::engine::general_purpose::STANDARD.encode(bytes))
    }
}

impl FromStr for WgKey {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let s = s.trim();
        if s.len() != 44 || !s.ends_with('=') {
            return Err(Error::Config(
                "cle WireGuard invalide: 44 caracteres base64 attendus".into(),
            ));
        }
        if !s[..43]
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
        {
            return Err(Error::Config(
                "cle WireGuard invalide: caractere hors alphabet base64".into(),
            ));
        }
        let key = Self(s.to_owned());
        // La longueur et l'alphabet ne suffisent pas. Le 43e caractere ne porte
        // que quatre bits utiles: ses deux bits de poids faible doivent etre
        // nuls, sans quoi la chaine ne code pas 32 octets. Sans ce controle,
        // une cle malformee traverse toute la configuration et n'est refusee
        // qu'au moment de la passer au driver, kill switch deja arme.
        key.to_bytes()?;
        Ok(key)
    }
}

impl fmt::Debug for WgKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("WgKey(<redacted>)")
    }
}

impl TryFrom<String> for WgKey {
    type Error = Error;
    fn try_from(s: String) -> Result<Self> {
        s.parse()
    }
}

impl From<WgKey> for String {
    fn from(v: WgKey) -> Self {
        v.0
    }
}

/// Politique DNS appliquee pendant que le tunnel est monte.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsPolicy {
    /// Adresse de loopback du resolveur local. C'est la SEULE destination :53
    /// autorisee hors tunnel par le kill switch.
    pub local_resolver: IpAddr,
    /// Resolveurs amont, joignables uniquement a l'interieur du tunnel.
    pub upstream: Vec<IpAddr>,
    /// Un resolveur chiffre tourne-t-il sur `local_resolver`.
    ///
    /// Ce drapeau change QUI le systeme interroge. Faux, le systeme interroge
    /// directement les resolveurs amont: les requetes traversent le tunnel
    /// chiffrees, puis en ressortent en clair, lisibles de qui exploite la
    /// sortie. Vrai, le systeme interroge la boucle locale, ou un
    /// dnscrypt-proxy embarque les rechiffre pour de bon jusqu'au resolveur
    /// public.
    ///
    /// Faux par defaut, et deliberement: le poser sans qu'un resolveur ecoute
    /// reellement en face pointerait le systeme vers un port muet, ce qui ne
    /// serait pas un durcissement mais une machine sans resolution de noms.
    #[serde(default)]
    pub embarque: bool,
    /// Ce que le resolveur embarque refuse de resoudre.
    ///
    /// La couche 3 du document 03: intercepter les noms de telemetrie AVANT
    /// que la requete n'entre dans le tunnel. La liste elle-meme vit dans
    /// `bifrost_dns::telemetrie`; ce champ ne porte que le CHOIX.
    #[serde(default)]
    pub anti_telemetrie: ProfilTelemetrie,
}

/// Jusqu'ou le resolveur embarque refuse de resoudre.
///
/// Les trois profils du document 03 partie 6, moins "Parano" qui coupe Windows
/// Update, le Store et l'activation: celui-la n'est pas un durcissement mais
/// une machine deconnectee, et il n'aurait pas sa place derriere un reglage qui
/// se pose en un mot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProfilTelemetrie {
    /// Le resolveur resout tout. Defaut, pour la meme raison que
    /// [`DnsPolicy::embarque`] est faux par defaut: un produit qui se met a
    /// refuser des noms sans qu'on le lui ait demande est un produit dont on
    /// ne sait plus ce qu'il fait.
    #[default]
    Aucun,
    /// Ce qui n'a d'autre fonction que de mesurer l'utilisateur ou de lui
    /// vendre quelque chose. Windows Update, le Store, Defender, l'activation
    /// et l'indicateur de connectivite restent intacts.
    Equilibre,
    /// En plus: ce qui porte aussi du contenu que l'utilisateur pourrait
    /// remarquer manquant - Spotlight, le fil MSN, la configuration dynamique
    /// des applications, les notifications poussees.
    Strict,
}

impl DnsPolicy {
    /// Verifie que le resolveur local est bien sur loopback. Un resolveur
    /// "local" pointant vers une IP routable ouvrirait un trou dans le kill
    /// switch: c'est une erreur de configuration, pas un avertissement.
    pub fn validate(&self) -> Result<()> {
        if !self.local_resolver.is_loopback() {
            return Err(Error::Config(format!(
                "le resolveur local doit etre sur loopback, recu {}",
                self.local_resolver
            )));
        }
        if self.upstream.is_empty() {
            return Err(Error::Config(
                "au moins un resolveur amont est requis".into(),
            ));
        }
        // Le blocage est APPLIQUE par le resolveur embarque, et par personne
        // d'autre: sans lui, ce champ ne ferait rien du tout. Un reglage qui
        // reste sans effet est pire qu'un reglage absent, parce qu'il se lit
        // comme une protection posee. C'est exactement la forme du defaut
        // trouve trois fois en aout 2026 en portant le produit sur Windows: un
        // reglage porte d'un cote et pas de l'autre, qui ne se voit qu'a
        // l'usage.
        if self.anti_telemetrie != ProfilTelemetrie::Aucun && !self.embarque {
            return Err(Error::Config(format!(
                "anti_telemetrie = {:?} demande sans resolveur embarque. C'est \
                 le resolveur embarque qui refuse les noms; sans lui ce reglage \
                 n'a aucun effet et se lirait pourtant comme une protection",
                self.anti_telemetrie
            )));
        }
        Ok(())
    }
}

/// Ce qui porte reellement le trafic, et ce qu'il faut savoir pour cela.
///
/// # Pourquoi une enumeration et pas des champs facultatifs
///
/// Un tunnel par coeur n'a ni cle privee, ni pair, ni marque, ni table de
/// routage dediee: le coeur EST le transport, il s'exempte par son identite, et
/// c'est [`crate::tunnel_aiguillage`] qui decide de sa table. Les garder au
/// niveau du tunnel obligeait un client a envoyer une cle privee bidon pour
/// demander un coeur, et laissait le type decrire des etats qui n'existent pas.
///
/// C'est aussi le decoupage de talpid, dont ce depot s'inspire pour ses
/// crates: un bloc commun a tous les transports, et des parametres par
/// protocole.
///
/// # Qui a besoin de faire la difference
///
/// Presque personne. La machine a etats ne parle qu'a un port,
/// [`crate::ports::TunnelDevice`], et il en existe deux implementations. Le
/// kill switch, lui, doit trancher: sous Linux la seule sortie autorisee vers
/// Internet est `meta mark <fwmark> accept`, liee au CHIFFREMENT et non a une
/// destination. Un coeur ne produit aucun paquet marque, donc aucune marque ne
/// doit ouvrir quoi que ce soit - et surtout pas `0`, qui rendrait
/// `meta mark 0x0 accept`, lequel matche tout paquet non marque.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Portage {
    /// WireGuard, monte par Bifrost lui-meme. Le trafic chiffre sort marque.
    Wireguard(Box<WireguardParams>),
    /// Un coeur anti-censure tiers, joint par les profils que voici.
    ///
    /// Plusieurs, parce qu'un tunnel n'a pas UNE technique mais une liste de
    /// candidats: c'est ce que demande le document 04 partie 3.2, et ce que la
    /// course parcourt. Ils sont tous ecrits derriere le meme selecteur
    /// sing-box, ce qui permet de basculer de l'un a l'autre sans relancer le
    /// coeur, donc sans que le SOCKS local bouge ni que le kill switch soit
    /// leve - les deux conditions que le plan pose pour une bascule en cours de
    /// session.
    Coeur(Box<Profils>),
}

impl Portage {
    /// Les parametres WireGuard, ou `None` si un coeur porte le trafic.
    ///
    /// Rendre une option plutot que paniquer: les appelants qui n'existent que
    /// pour WireGuard - le montage netlink, WireGuardNT - savent deja dans quel
    /// cas ils sont, et ceux qui l'ignorent doivent pouvoir le decouvrir sans
    /// risquer d'abattre le daemon.
    pub fn wireguard(&self) -> Option<&WireguardParams> {
        match self {
            Portage::Wireguard(w) => Some(w),
            Portage::Coeur(_) => None,
        }
    }

    /// Les profils du coeur, ou `None` si WireGuard porte le trafic.
    pub fn coeurs(&self) -> Option<&Profils> {
        match self {
            Portage::Coeur(p) => Some(p),
            Portage::Wireguard(_) => None,
        }
    }

    /// Nom lisible du portage, pour un journal ou un message d'erreur.
    pub fn nom(&self) -> &'static str {
        match self {
            Portage::Wireguard(_) => "wireguard",
            Portage::Coeur(_) => "coeur",
        }
    }
}

/// Ce que WireGuard exige, et que lui seul exige.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireguardParams {
    pub private_key: WgKey,
    /// Marque appliquee par le noyau au trafic deja chiffre. C'est elle que le
    /// kill switch reconnait pour laisser sortir le tunnel, et rien d'autre.
    #[serde(default = "default_fwmark")]
    pub fwmark: u32,
    /// Table de routage dediee. Le chemin par coeur n'en utilise pas
    /// celle-ci: il a la sienne, dans `tunnel::aiguillage`.
    #[serde(default = "default_table")]
    pub routing_table: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen_port: Option<u16>,
    pub peer: PeerConfig,
}

/// Configuration complete d'un tunnel.
///
/// # Pourquoi une representation intermediaire pour serde
///
/// Le type Rust distingue les transports par une enumeration, ce qui interdit
/// les etats qui n'existent pas. Le FICHIER, lui, ne doit pas changer de forme
/// pour autant: `/etc/bifrost/tunnel.toml` est documente, livre, et decrit dans
/// le README. Une representation directe de l'enumeration aurait impose un
/// `[portage.wireguard]` a tous les profils existants, cassant des fichiers qui
/// marchaient pour servir une fonction que leur auteur n'utilise pas.
///
/// La forme a plat reste donc celle de WireGuard - `private_key`, `fwmark` et
/// `[peer]` au premier niveau - et un profil de coeur s'ecrit `[coeur]`. La
/// conversion valide ce que serde ne peut pas exprimer, et rend des messages
/// ecrits ici plutot que "missing field", qui ne dirait pas quelle forme
/// choisir.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "TunnelConfigBrut", into = "TunnelConfigBrut")]
pub struct TunnelConfig {
    /// Nom de l'interface, par exemple `wg0`.
    pub interface: String,
    /// Adresses portees par l'interface du tunnel.
    pub addresses: Vec<IpNet>,
    #[serde(default = "default_mtu")]
    pub mtu: u32,
    pub dns: DnsPolicy,
    /// Autorise le trafic vers les prefixes RFC1918 hors tunnel.
    #[serde(default)]
    pub allow_lan: bool,
    /// Ce qui porte le trafic, et ce qu'il exige.
    pub portage: Portage,
}

/// La forme du FICHIER, et de la trame IPC. Voir l'en-tete de
/// [`TunnelConfig`] pour la raison d'etre de ce doublon.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TunnelConfigBrut {
    interface: String,
    addresses: Vec<IpNet>,
    #[serde(default = "default_mtu")]
    mtu: u32,
    dns: DnsPolicy,
    #[serde(default)]
    allow_lan: bool,

    // Forme WireGuard, a plat: c'est le format historique.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    private_key: Option<WgKey>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    fwmark: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    routing_table: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    listen_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    peer: Option<PeerConfig>,

    // Forme coeur, historique: UN profil. Lue, jamais ecrite - la forme rendue
    // est toujours `coeurs`, qui sait tout dire.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    coeur: Option<Box<Profil>>,
    // Forme coeur, generale: plusieurs profils, un par transport.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    coeurs: Option<Profils>,
}

impl TryFrom<TunnelConfigBrut> for TunnelConfig {
    type Error = Error;

    fn try_from(b: TunnelConfigBrut) -> Result<Self> {
        // Les deux formes de coeur a la fois: refuser plutot que de choisir. Un
        // profil qui ecrit `[coeur]` ET `[[coeurs]]` ne dit pas lequel compte,
        // et en prendre un ferait monter un tunnel vers un serveur que son
        // auteur croyait avoir remplace.
        let coeurs = match (b.coeur, b.coeurs) {
            (Some(_), Some(_)) => {
                return Err(Error::Config(
                    "profil ambigu: il ecrit a la fois [coeur] (forme historique, un seul \
                     profil) et [[coeurs]] (forme generale). Garder [[coeurs]]"
                        .into(),
                ));
            }
            (Some(un), None) => Some(Profils::un(*un)),
            (None, plusieurs) => plusieurs,
        };

        let a_du_wireguard = b.private_key.is_some() || b.peer.is_some();
        // Les deux a la fois: refuser plutot que de choisir. Un profil qui
        // decrit un coeur ET un pair WireGuard ne dit pas ce qu'il veut, et
        // deviner ferait monter un tunnel que son auteur n'a pas demande.
        if coeurs.is_some() && a_du_wireguard {
            return Err(Error::Config(
                "profil ambigu: il decrit a la fois un coeur ([[coeurs]]) et un pair WireGuard \
                 (private_key, [peer]). Garder l'un des deux"
                    .into(),
            ));
        }
        let portage = match coeurs {
            Some(profils) => Portage::Coeur(Box::new(profils)),
            None => {
                let private_key = b.private_key.ok_or_else(|| {
                    Error::Config(
                        "profil incomplet: ni 'private_key' pour un tunnel WireGuard, ni \
                         [[coeurs]] pour un tunnel par coeur anti-censure"
                            .into(),
                    )
                })?;
                let peer = b.peer.ok_or_else(|| {
                    Error::Config("profil WireGuard incomplet: section [peer] absente".into())
                })?;
                Portage::Wireguard(Box::new(WireguardParams {
                    private_key,
                    fwmark: b.fwmark.unwrap_or(DEFAULT_FWMARK),
                    routing_table: b.routing_table.unwrap_or(DEFAULT_ROUTING_TABLE),
                    listen_port: b.listen_port,
                    peer,
                }))
            }
        };
        Ok(Self {
            interface: b.interface,
            addresses: b.addresses,
            mtu: b.mtu,
            dns: b.dns,
            allow_lan: b.allow_lan,
            portage,
        })
    }
}

impl From<TunnelConfig> for TunnelConfigBrut {
    fn from(c: TunnelConfig) -> Self {
        let (private_key, fwmark, routing_table, listen_port, peer, coeurs) = match c.portage {
            Portage::Wireguard(w) => {
                let w = *w;
                (
                    Some(w.private_key),
                    Some(w.fwmark),
                    Some(w.routing_table),
                    w.listen_port,
                    Some(w.peer),
                    None,
                )
            }
            Portage::Coeur(p) => (None, None, None, None, None, Some(*p)),
        };
        Self {
            interface: c.interface,
            addresses: c.addresses,
            mtu: c.mtu,
            dns: c.dns,
            allow_lan: c.allow_lan,
            private_key,
            fwmark,
            routing_table,
            listen_port,
            peer,
            // Jamais la forme historique: une seule forme rendue vaut mieux que
            // deux, et `coeurs` sait dire ce que `coeur` disait.
            coeur: None,
            coeurs,
        }
    }
}

fn default_mtu() -> u32 {
    DEFAULT_MTU
}

fn default_fwmark() -> u32 {
    DEFAULT_FWMARK
}

fn default_table() -> u32 {
    DEFAULT_ROUTING_TABLE
}

impl TunnelConfig {
    pub fn validate(&self) -> Result<()> {
        if self.interface.is_empty() || self.interface.len() > 15 {
            return Err(Error::Config(format!(
                "nom d'interface invalide: '{}' (1 a 15 caracteres)",
                self.interface
            )));
        }
        if !self
            .interface
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(Error::Config(format!(
                "nom d'interface invalide: '{}'",
                self.interface
            )));
        }
        if self.addresses.is_empty() {
            return Err(Error::Config(
                "au moins une adresse d'interface est requise".into(),
            ));
        }
        if let Portage::Wireguard(wg) = &self.portage {
            if wg.peer.allowed_ips.is_empty() {
                return Err(Error::Config("allowed_ips ne peut pas etre vide".into()));
            }
            if wg.fwmark == 0 {
                return Err(Error::Config(
                    "fwmark 0 est invalide: le kill switch ne pourrait pas distinguer \
                     le trafic deja chiffre"
                        .into(),
                ));
            }
        }
        if !(576..=9000).contains(&self.mtu) {
            return Err(Error::Config(format!("mtu hors plage: {}", self.mtu)));
        }
        self.dns.validate()?;
        Ok(())
    }

    /// Vrai si le tunnel capture tout le trafic.
    ///
    /// Pour WireGuard, cela se lit dans `allowed_ips`. Pour un coeur, il n'y a
    /// pas d'equivalent a lire: l'aiguillage envoie TOUT dans le TUN par
    /// construction, et n'en fait sortir que le compte du coeur. C'est donc
    /// toujours vrai, et ce n'est pas un defaut de mesure.
    pub fn is_full_tunnel(&self) -> bool {
        match &self.portage {
            Portage::Wireguard(w) => w.peer.allowed_ips.iter().any(IpNet::is_default_route),
            Portage::Coeur(_) => true,
        }
    }

    /// Les parametres WireGuard, ou une erreur qui dit ce qui porte a la place.
    ///
    /// Pour les appelants qui ne savent construire qu'un tunnel WireGuard et
    /// doivent le dire plutot que de le supposer.
    pub fn wireguard(&self) -> Result<&WireguardParams> {
        self.portage.wireguard().ok_or_else(|| {
            Error::Config(format!(
                "cette operation demande un tunnel WireGuard, or le portage est {}",
                self.portage.nom()
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    /// Le 43e caractere d'une cle ne porte que quatre bits utiles, donc tous
    /// ne conviennent pas. 'A' vaut zero: il termine n'importe quelle cle.
    fn key(c: char) -> WgKey {
        let mut s: String = std::iter::repeat_n(c, 42).collect();
        s.push('A');
        s.push('=');
        s.parse().unwrap()
    }

    /// 43 'A' suivis de '=' est le codage base64 de 32 octets nuls. C'est le
    /// point fixe le plus simple pour verifier que le decodage n'est ni
    /// decale ni tronque.
    #[test]
    fn une_cle_de_zeros_donne_32_octets_nuls() {
        assert_eq!(key('A').to_bytes().unwrap(), [0u8; WG_KEY_BYTES]);
    }

    /// Le premier octet decode doit etre le premier octet de la cle, pas un
    /// octet decale. Ce blob part vers un driver noyau: un decalage d'un octet
    /// donnerait une cle silencieusement fausse et un handshake qui n'aboutit
    /// jamais, sans message d'erreur.
    #[test]
    fn le_decodage_n_est_pas_decale() {
        let k: WgKey = format!("AQ{}=", "A".repeat(41)).parse().unwrap();
        let octets = k.to_bytes().unwrap();
        assert_eq!(octets[0], 1);
        assert_eq!(&octets[1..], &[0u8; WG_KEY_BYTES - 1][..]);
    }

    /// Aller-retour: ce qui sort du driver doit pouvoir y retourner tel quel.
    #[test]
    fn une_cle_construite_depuis_ses_octets_se_redecode() {
        for octets in [
            [0u8; WG_KEY_BYTES],
            [1u8; WG_KEY_BYTES],
            [0xffu8; WG_KEY_BYTES],
        ] {
            let k = WgKey::from_bytes(&octets);
            assert_eq!(k.as_str().len(), 44, "cle: {}", k.as_str());
            assert_eq!(k.to_bytes().unwrap(), octets);
            // Et elle doit passer la validation d'entree, sinon elle ne
            // pourrait pas etre reinjectee dans une configuration.
            assert_eq!(k.as_str().parse::<WgKey>().unwrap(), k);
        }
    }

    #[test]
    fn toute_cle_valide_donne_exactement_32_octets() {
        for c in ['A', 'Z', 'a', 'z', '0', '9', '+', '/'] {
            assert_eq!(key(c).to_bytes().unwrap().len(), WG_KEY_BYTES);
        }
    }

    /// 43 caracteres du bon alphabet ne font pas une cle: le dernier avant le
    /// '=' ne porte que quatre bits utiles. Une chaine comme celle-ci passait
    /// la validation et n'aurait ete refusee qu'au moment de la donner au
    /// driver, tunnel a moitie monte.
    #[test]
    fn une_cle_aux_bits_de_fin_non_nuls_est_refusee() {
        let s = format!("{}=", "Z".repeat(43));
        assert_eq!(
            s.len(),
            44,
            "le refus doit venir des bits, pas de la longueur"
        );
        let err = match s.parse::<WgKey>() {
            Ok(_) => panic!("cle non canonique acceptee"),
            Err(e) => e.to_string(),
        };
        assert!(err.contains("decodable"), "{err}");
    }

    fn sample() -> TunnelConfig {
        TunnelConfig {
            interface: "wg0".into(),
            addresses: vec!["10.2.0.2/32".parse().unwrap()],
            mtu: DEFAULT_MTU,
            dns: DnsPolicy {
                local_resolver: IpAddr::V4(Ipv4Addr::LOCALHOST),
                upstream: vec![IpAddr::V4(Ipv4Addr::new(10, 2, 0, 1))],
                embarque: false,
                anti_telemetrie: ProfilTelemetrie::Aucun,
            },
            allow_lan: false,
            portage: Portage::Wireguard(Box::new(WireguardParams {
                private_key: key('a'),
                fwmark: DEFAULT_FWMARK,
                routing_table: DEFAULT_ROUTING_TABLE,
                listen_port: None,
                peer: PeerConfig {
                    public_key: key('b'),
                    preshared_key: None,
                    endpoint: Endpoint {
                        addr: "203.0.113.7:51820".parse().unwrap(),
                    },
                    allowed_ips: vec!["0.0.0.0/0".parse().unwrap(), "::/0".parse().unwrap()],
                    persistent_keepalive: 25,
                },
            })),
        }
    }

    #[test]
    fn ipnet_parse_et_affichage() {
        let n: IpNet = "10.2.0.2/32".parse().unwrap();
        assert_eq!(n.to_string(), "10.2.0.2/32");
        assert!(n.is_ipv4());
        assert!(!n.is_default_route());
        assert!("::/0".parse::<IpNet>().unwrap().is_default_route());
    }

    #[test]
    fn ipnet_rejette_prefixe_hors_plage() {
        assert!("10.0.0.1/33".parse::<IpNet>().is_err());
        assert!("::1/129".parse::<IpNet>().is_err());
        assert!("10.0.0.1".parse::<IpNet>().is_err());
    }

    #[test]
    fn cle_wireguard_valide_et_opaque_en_debug() {
        let k = key('A');
        assert_eq!(k.as_str().len(), 44);
        assert_eq!(format!("{k:?}"), "WgKey(<redacted>)");
        assert!(!format!("{k:?}").contains("AAA"));
    }

    #[test]
    fn cle_wireguard_rejette_les_formats_invalides() {
        assert!("trop-court=".parse::<WgKey>().is_err());
        assert!("a".repeat(44).parse::<WgKey>().is_err()); // pas de '=' final
        let mut mauvais: String = std::iter::repeat_n('!', 43).collect();
        mauvais.push('=');
        assert!(mauvais.parse::<WgKey>().is_err());
    }

    #[test]
    fn config_valide_accepte_le_cas_nominal() {
        let c = sample();
        c.validate().unwrap();
        assert!(c.is_full_tunnel());
    }

    /// Un utilitaire pour les tests qui veulent tordre un champ WireGuard.
    /// Il panique si le portage n'est pas WireGuard, ce qui ne peut arriver
    /// qu'a un test mal ecrit.
    fn wg(c: &mut TunnelConfig) -> &mut WireguardParams {
        match &mut c.portage {
            Portage::Wireguard(w) => w,
            Portage::Coeur(_) => panic!("ce test suppose un portage WireGuard"),
        }
    }

    #[test]
    fn config_rejette_fwmark_zero() {
        let mut c = sample();
        wg(&mut c).fwmark = 0;
        assert!(c.validate().is_err());
    }

    /// Le pendant du precedent, et la raison d'etre de l'enumeration: un
    /// portage par coeur n'a pas de marque du tout, donc rien a rejeter.
    #[test]
    fn un_portage_par_coeur_n_a_pas_de_marque_a_valider() {
        let mut c = sample();
        c.portage = Portage::Coeur(Box::new(
            crate::profil::Profil::depuis_lien("hy2://mot-de-passe@203.0.113.8:8443")
                .unwrap()
                .into(),
        ));
        c.validate()
            .expect("un profil de coeur doit passer la validation sans champ WireGuard");
        // Et l'aiguillage envoie tout dans le TUN par construction: il n'y a
        // pas d'`allowed_ips` a lire pour le savoir.
        assert!(c.is_full_tunnel());
        assert!(c.wireguard().is_err());
    }

    #[test]
    fn config_rejette_resolveur_non_loopback() {
        let mut c = sample();
        c.dns.local_resolver = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let err = c.validate().unwrap_err().to_string();
        assert!(err.contains("loopback"), "message inattendu: {err}");
    }

    #[test]
    fn config_rejette_nom_interface_invalide() {
        let mut c = sample();
        c.interface = "wg 0; rm -rf".into();
        assert!(c.validate().is_err());
        c.interface = "a".repeat(16);
        assert!(c.validate().is_err());
    }

    #[test]
    fn split_tunnel_detecte() {
        let mut c = sample();
        wg(&mut c).peer.allowed_ips = vec!["10.0.0.0/8".parse().unwrap()];
        assert!(!c.is_full_tunnel());
    }

    /// Le profil de coeur tel qu'il se serialise reellement, plutot qu'ecrit a
    /// la main: sa forme est celle de `profil::Transport`, et la recopier ici
    /// ferait de ces tests une deuxieme source de verite qui derive.
    fn profil_json() -> serde_json::Value {
        let p = crate::profil::Profil::depuis_lien(
            "hysteria2://mot-de-passe@203.0.113.8:8443/?sni=exemple.test#Essai",
        )
        .unwrap();
        serde_json::to_value(p).unwrap()
    }

    /// Un profil REALITY, l'autre transport, pour les listes a deux.
    fn profil_reality_json() -> serde_json::Value {
        let lien = format!(
            "vless://4292f5ab-8963-476c-8052-3615895ce4f1@203.0.113.9:443?security=reality&flow=xtls-rprx-vision&encryption=none&fp=chrome&type=tcp&pbk={}&sid=d8c6b58bcbb0c323&sni=exemple.test#Essai",
            "a".repeat(43)
        );
        let p = crate::profil::Profil::depuis_lien(&lien).unwrap();
        serde_json::to_value(p).unwrap()
    }

    /// La forme generale: plusieurs profils, un par transport.
    ///
    /// C'est ce qui rend une course possible - un tunnel a une LISTE de
    /// candidats, pas une technique.
    #[test]
    fn un_profil_peut_proposer_plusieurs_coeurs() {
        let json = serde_json::json!({
            "interface": "bf0",
            "addresses": ["10.99.0.1/24"],
            "dns": { "local_resolver": "127.0.0.1", "upstream": ["127.0.0.1"] },
            "coeurs": [profil_reality_json(), profil_json()]
        });
        let c: TunnelConfig =
            serde_json::from_value(json).expect("la forme a plusieurs coeurs doit se lire");
        let profils = c.portage.coeurs().expect("portage par coeur attendu");
        assert_eq!(profils.combien(), 2);
        assert!(profils.pour("vless-reality-vision").is_some());
        assert!(profils.pour("hysteria2").is_some());
        c.validate().expect("une liste de coeurs reste valide");
    }

    /// Une liste VIDE est refusee a la lecture, pas plus loin.
    ///
    /// Un portage par coeur qui ne designe aucun coeur ferait lancer un coeur
    /// sans sortie, derriere un selecteur vide, avec un tunnel qui monte
    /// devant. Le refuser ici est ce qui rend cet etat inatteignable.
    #[test]
    fn une_liste_de_coeurs_vide_est_refusee() {
        let json = serde_json::json!({
            "interface": "bf0",
            "addresses": ["10.99.0.1/24"],
            "dns": { "local_resolver": "127.0.0.1", "upstream": ["127.0.0.1"] },
            "coeurs": []
        });
        let e = serde_json::from_value::<TunnelConfig>(json)
            .expect_err("une liste vide doit etre refusee");
        assert!(e.to_string().contains("aucun profil"), "{e}");
    }

    /// Deux profils du MEME transport: refuses, en disant pourquoi.
    ///
    /// La selection raisonne en techniques, pas en serveurs: elle ne saurait
    /// pas les distinguer, et la course en essaierait un en croyant avoir juge
    /// la technique. Choisir un serveur parmi plusieurs est un autre axe.
    #[test]
    fn deux_profils_du_meme_transport_sont_refuses() {
        let json = serde_json::json!({
            "interface": "bf0",
            "addresses": ["10.99.0.1/24"],
            "dns": { "local_resolver": "127.0.0.1", "upstream": ["127.0.0.1"] },
            "coeurs": [profil_json(), profil_json()]
        });
        let e = serde_json::from_value::<TunnelConfig>(json)
            .expect_err("deux profils du meme transport doivent etre refuses");
        let m = e.to_string();
        assert!(m.contains("hysteria2"), "le transport doit etre nomme: {m}");
        assert!(m.contains("serveur"), "et l'axe qui manque aussi: {m}");
    }

    /// Les deux formes de coeur a la fois: refuser plutot que choisir. En
    /// prendre une ferait monter un tunnel vers un serveur que son auteur
    /// croyait avoir remplace.
    #[test]
    fn les_deux_formes_de_coeur_a_la_fois_sont_refusees() {
        let json = serde_json::json!({
            "interface": "bf0",
            "addresses": ["10.99.0.1/24"],
            "dns": { "local_resolver": "127.0.0.1", "upstream": ["127.0.0.1"] },
            "coeur": profil_json(),
            "coeurs": [profil_reality_json()]
        });
        let e = serde_json::from_value::<TunnelConfig>(json)
            .expect_err("les deux formes a la fois doivent etre refusees");
        let m = e.to_string();
        assert!(m.contains("ambigu"), "{m}");
        assert!(m.contains("[[coeurs]]"), "{m}");
    }

    /// Une liste a deux franchit l'IPC sans perdre le second.
    ///
    /// C'est tout l'objet du changement de format: si le second profil ne
    /// survit pas a la trame, le daemon n'aura jamais qu'un candidat et la
    /// course n'aura rien a parcourir.
    #[test]
    fn une_liste_a_deux_fait_l_aller_retour() {
        let json = serde_json::json!({
            "interface": "bf0",
            "addresses": ["10.99.0.1/24"],
            "dns": { "local_resolver": "127.0.0.1", "upstream": ["127.0.0.1"] },
            "coeurs": [profil_reality_json(), profil_json()]
        });
        let c: TunnelConfig = serde_json::from_value(json).unwrap();
        let brut = serde_json::to_string(&c).unwrap();
        let retour: TunnelConfig = serde_json::from_str(&brut).unwrap();
        assert_eq!(c, retour);
        assert_eq!(retour.portage.coeurs().unwrap().combien(), 2);
    }

    /// La forme rendue est TOUJOURS `coeurs`, jamais la forme historique.
    ///
    /// Deux formes en sortie voudraient dire deux chemins a garder vivants,
    /// dont un que rien n'exerce des que les listes a plusieurs existent.
    #[test]
    fn la_forme_rendue_est_toujours_la_generale() {
        let mut c = sample();
        c.portage = Portage::Coeur(Box::new(
            crate::profil::Profil::depuis_lien("hy2://mot-de-passe@203.0.113.8:8443")
                .unwrap()
                .into(),
        ));
        let brut = serde_json::to_string(&c).unwrap();
        assert!(brut.contains("\"coeurs\""), "{brut}");
        assert!(!brut.contains("\"coeur\":"), "{brut}");
    }

    /// La forme historique du fichier doit continuer a se lire telle quelle.
    /// C'est la raison d'etre de la representation intermediaire: le type Rust
    /// a change, le fichier livre ne doit pas.
    #[test]
    fn un_profil_wireguard_a_plat_se_lit_encore() {
        let json = serde_json::json!({
            "interface": "wg0",
            "private_key": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaA=",
            "addresses": ["10.2.0.2/32"],
            "peer": {
                "public_key": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbA=",
                "endpoint": { "addr": "203.0.113.7:51820" },
                "allowed_ips": ["0.0.0.0/0"]
            },
            "dns": { "local_resolver": "127.0.0.1", "upstream": ["10.2.0.1"] }
        });
        let c: TunnelConfig = serde_json::from_value(json).expect("la forme a plat doit se lire");
        let w = c.portage.wireguard().expect("portage WireGuard attendu");
        assert_eq!(w.fwmark, DEFAULT_FWMARK);
        assert_eq!(w.routing_table, DEFAULT_ROUTING_TABLE);
    }

    /// Un profil de coeur s'ecrit `[coeur]`, et n'a aucun champ WireGuard.
    #[test]
    fn un_profil_de_coeur_se_lit_par_sa_section() {
        let json = serde_json::json!({
            "interface": "bf0",
            "addresses": ["10.99.0.1/24"],
            "dns": { "local_resolver": "127.0.0.1", "upstream": ["127.0.0.1"] },
            "coeur": profil_json()
        });
        let c: TunnelConfig = serde_json::from_value(json).expect("la forme coeur doit se lire");
        assert!(c.portage.coeurs().is_some());
        assert!(c.wireguard().is_err());
        c.validate()
            .expect("un profil de coeur est valide sans champ WireGuard");
    }

    /// Les deux formes a la fois: refuser plutot que deviner. Deviner ferait
    /// monter un tunnel que l'auteur du profil n'a pas demande.
    #[test]
    fn un_profil_qui_decrit_les_deux_est_refuse() {
        let json = serde_json::json!({
            "interface": "wg0",
            "private_key": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaA=",
            "addresses": ["10.2.0.2/32"],
            "peer": {
                "public_key": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbA=",
                "endpoint": { "addr": "203.0.113.7:51820" },
                "allowed_ips": ["0.0.0.0/0"]
            },
            "dns": { "local_resolver": "127.0.0.1", "upstream": ["10.2.0.1"] },
            "coeur": profil_json()
        });
        let e = serde_json::from_value::<TunnelConfig>(json)
            .expect_err("un profil ambigu doit etre refuse");
        assert!(e.to_string().contains("ambigu"), "{e}");
    }

    /// Ni l'un ni l'autre: le message doit nommer les DEUX formes possibles.
    /// Un "missing field private_key" laisserait croire qu'il n'y en a qu'une.
    #[test]
    fn un_profil_sans_portage_nomme_les_deux_formes() {
        let json = serde_json::json!({
            "interface": "wg0",
            "addresses": ["10.2.0.2/32"],
            "dns": { "local_resolver": "127.0.0.1", "upstream": ["10.2.0.1"] }
        });
        let e = serde_json::from_value::<TunnelConfig>(json)
            .expect_err("un profil sans portage doit etre refuse");
        let m = e.to_string();
        assert!(m.contains("private_key"), "{m}");
        assert!(m.contains("coeur"), "{m}");
    }

    /// L'aller-retour doit tenir dans les deux sens: la configuration franchit
    /// l'IPC en JSON a chaque connexion.
    #[test]
    fn les_deux_portages_font_l_aller_retour() {
        let wg = sample();
        let retour: TunnelConfig =
            serde_json::from_str(&serde_json::to_string(&wg).unwrap()).unwrap();
        assert_eq!(wg, retour);

        let mut coeur = sample();
        coeur.portage = Portage::Coeur(Box::new(
            crate::profil::Profil::depuis_lien("hy2://mot-de-passe@203.0.113.8:8443")
                .unwrap()
                .into(),
        ));
        let brut = serde_json::to_string(&coeur).unwrap();
        // Aucun champ WireGuard ne doit trainer dans la trame d'un coeur.
        assert!(!brut.contains("private_key"), "{brut}");
        assert!(!brut.contains("fwmark"), "{brut}");
        let retour: TunnelConfig = serde_json::from_str(&brut).unwrap();
        assert_eq!(coeur, retour);
    }
}
