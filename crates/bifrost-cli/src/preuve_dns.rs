//! DNS: le plan du produit confronte a l'etat du resolveur systeme Linux.
//!
//! `prove dns --intention F --actif` lit une intention DNS (backend, interface
//! du tunnel, resolveur local, amonts, resolveur embarque et son compte), en
//! tire le plan que le produit pose (`bifrost_core::plan_dns::PlanDns`, la
//! meme source que `bifrost_dns::linux`), puis lit le systeme en passif
//! (`preuve_dns_linux`) et compare. Rien n'est pose, retire ou change; aucun
//! programme externe n'est lance; aucune elevation n'est demandee.
//!
//! # Ce qui est lu
//!
//! - `/etc/nsswitch.conf`: les sources de la ligne `hosts`; et, seulement si
//!   un module mDNS non minimal y figure, la presence de `/etc/mdns.allow`.
//! - `/proc/net/udp` (et `udp6` pour un resolveur embarque IPv6): les ecoutes
//!   UDP du port 53 du namespace reseau courant et leur compte.
//! - Le contenu de `/etc/resolv.conf`: compare au bit pres au rendu du produit
//!   (backend `resolv-conf`), ou dont les lignes `nameserver` doivent toutes
//!   designer le stub (backend `systemd-resolved`).
//! - Backend `systemd-resolved`: le mode de `/etc/resolv.conf`, par
//!   comparaison d'inodes comme systemd-resolved le calcule; les liens du
//!   namespace courant (rtnetlink); puis, par le bus systeme
//!   (`dbus::`, lecteur ecrit a la main): le nom unique et le compte du
//!   proprietaire de `org.freedesktop.resolve1`, les serveurs (`DNSEx`) et
//!   domaines (`Domains`) du Manager, le mode vu par resolved
//!   (`ResolvConfMode`), l'absence de delegues DNS (`ListDelegates`), et, pour
//!   chaque lien du namespace, `DefaultRoute`, `ScopesMask` et ses serveurs
//!   (`DNSEx` du lien). Les serveurs du lien sont necessaires: le Manager
//!   donne a un serveur l'index de l'interface par laquelle resolved
//!   l'interroge, 1 pour une adresse de bouclage quel que soit le lien qui la
//!   porte (`dns_server_ifindex`, systemd v255 et v262; mesure au banc avec le
//!   resolveur embarque). Voir `attribuer`.
//!
//! La collecte entiere est faite deux fois; deux lectures differentes rendent
//! NON MESURE, comme les autres preuves passives.
//!
//! # Gardes, avant toute comparaison (NON MESURE sinon)
//!
//! - Le bus systeme repond et `org.freedesktop.resolve1` y a un proprietaire.
//! - Le resolved lu est celui du namespace reseau courant: le bus systeme est
//!   joignable depuis un autre namespace et y rend les liens de l'hote (mesure
//!   par la phase 1). L'ecoute du stub (`127.0.0.53:53`, UDP) doit donc etre
//!   visible ici, sous le compte du proprietaire du nom; tout index de lien que
//!   resolved cite doit exister ici, et resolved doit connaitre chaque lien
//!   d'ici. C'est une heuristique: un processus de ce compte peut lier cette
//!   adresse ailleurs, et `DNSStubListener=no` la rend impossible.
//! - Le mode de `/etc/resolv.conf` que resolved calcule est celui que la
//!   preuve calcule: sinon resolved juge un autre fichier (autre namespace de
//!   montage).
//! - Aucun delegue DNS: ces portees (systemd 258 et suivants) ne figurent ni
//!   dans `DNSEx` ni dans `Domains`, et ne sont pas lues.
//! - Chaque serveur qu'un lien declare figure dans le `DNSEx` du Manager.
//!
//! # Ecarts, dans cet ordre
//!
//! - `resolv-conf-path` (resolved): `/etc/resolv.conf` n'est ni le stub ni le
//!   fichier statique de resolved. `uplink` liste les serveurs des autres
//!   liens, `foreign` et `missing` envoient ailleurs. Et le mode ne suffit pas:
//!   il compare des inodes, et un fichier monte sur celui du stub garde son
//!   inode. Le contenu est donc lu aussi, comme glibc le lit: chaque ligne
//!   `nameserver` doit designer le stub, et il en faut une.
//! - `resolv-conf-content` (resolv-conf): le fichier differe du rendu du
//!   produit.
//! - `hosts-sources`: un module de la ligne `hosts` qui n'est ni `files`, ni
//!   `myhostname`, ni `mymachines`, ni `dns`, ni (resolved seulement)
//!   `resolve`, ni un module mDNS de la limite nommee. Les actions `[...]` ne
//!   changent pas le jugement.
//! - `tunnel-link-scope` (resolved): le lien du tunnel est absent, ou resolved
//!   n'y tient pas de portee DNS active (lien eteint, par exemple): son `~.`
//!   est alors inerte et les autres portees prennent les requetes.
//! - `tunnel-link-servers` (resolved): les serveurs du lien du tunnel ne sont
//!   pas exactement ceux du plan, dans l'ordre, au port 53, sans nom TLS.
//! - `tunnel-link-domains` (resolved): autre chose qu'exactement `~.`.
//! - `dns-exceptions` (resolved): une autre portee qui a un serveur porte un
//!   domaine, de routage ou de recherche, autre que la racine: elle bat `~.`
//!   pour ses noms.
//! - `competing-default-routes` (resolved): une autre portee qui a un serveur
//!   porte aussi `~.`: les deux sont interrogees.
//! - `multicast-resolution` (resolved): une portee LLMNR active, sur
//!   n'importe quel lien: elle prend les noms a une etiquette, devant `~.`.
//! - `local-resolver-listener` (resolveur embarque): aucune ecoute UDP de
//!   `local_resolver:53`, ou une qui n'est pas sous le compte declare.
//!
//! # Regle de legitimite, sans liste d'adresses
//!
//! Une portee autre que celle du tunnel (un lien, ou la portee globale) est
//! admise si, pour aucun nom, elle ne fait jeu egal avec `~.` ni ne le bat:
//! elle n'a ni domaine, ni `~.`, ni portee LLMNR. Ses serveurs ne sont alors
//! consultes que lorsqu'aucun domaine ne correspond, ce que `~.` bat toujours
//! (`dns_scope_good_domain`, systemd v255 et v262). Une portee sans serveur ne
//! recoit rien. `DefaultRoute` ne change donc pas le jugement; il est compte.
//!
//! # Limites nommees: MATCH alors qu'une emission hors du tunnel reste possible
//!
//! - `.local` par mDNS: une portee mDNS de resolved, ou un module `mdns*` de
//!   nsswitch (minimal, ou non minimal sans `/etc/mdns.allow`). Comptees.
//! - La recherche inverse d'une adresse du reseau d'un lien fait jeu egal avec
//!   `~.` sur ce lien.
//! - Les noms a une etiquette quand `ResolveUnicastSingleLabel=yes`, que le bus
//!   ne dit pas, et, apres systemd 255, quand l'appelant le demande.
//!
//! Le rapport ne porte que des categories et des comptes: ni adresse, ni
//! domaine, ni interface, ni compte. `network_security` reste `not-evaluated`.
//! MATCH n'est pas une preuve d'etancheite.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::net::IpAddr;
use std::path::Path;
use std::time::Instant;

use bifrost_core::config::{DnsPolicy, ProfilTelemetrie};
use bifrost_core::plan_dns::PlanDns;
use serde::Serialize;
use serde_json::Value;

use crate::preuve_nft::{Unique, heure};

/// Le lecteur D-Bus minimal, pur: public pour le harnais de fuzzing.
pub mod dbus;

#[cfg(test)]
mod recettes;

const LIMITE: &str = "Intention declaree, pas le profil actif atteste. Etat du resolveur du namespace courant, lu deux fois de suite: un changement qui s'annule entre deux lectures echappe, et ce qui change apres la collecte n'est pas vu. Limites nommees, ou du trafic DNS peut sortir hors du tunnel alors que la preuve correspond: .local par mDNS (resolved ou nsswitch); la recherche inverse d'une adresse du reseau d'un lien; les noms a une etiquette quand ResolveUnicastSingleLabel=yes, que le bus ne dit pas. La garde d'espace de noms est une heuristique (ecoute du stub sous le compte de resolved). Ni les caches (resolved, nscd, applications), ni les connexions ouvertes, ni les resolveurs propres aux applications, ni le pare-feu ne sont prouves ici; le mode DNS sur TLS n'est pas compare. Pas une preuve d'etancheite du VPN.";

pub(crate) const INSTABLE: &str =
    "collecte instable: deux lectures consecutives du systeme different";

// ---------------------------------------------------------------------------
// L'intention, et le plan qu'elle designe.
// ---------------------------------------------------------------------------

/// Le backend DNS que l'intention declare. La preuve ne le devine pas: le
/// daemon le choisit a l'execution, et ce choix n'est ecrit nulle part.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    /// `systemd-resolved`: `resolvectl` sur le lien du tunnel.
    Resolved,
    /// `resolv-conf`: le fichier `/etc/resolv.conf`.
    ResolvConf,
}

/// L'intention DNS v1, lue strictement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Intention {
    pub backend: Backend,
    /// Le plan que le produit pose, rendu par le meme constructeur que lui.
    pub plan: PlanDns,
    pub local_resolver: IpAddr,
    pub embarque: bool,
    /// Le compte du resolveur embarque, s'il en a un dedie.
    pub resolveur_uid: Option<u32>,
}

const CLES: [&str; 7] = [
    "schema_version",
    "backend",
    "interface",
    "local_resolver",
    "upstream",
    "embarque",
    "resolveur_uid",
];

/// Borne du nombre de serveurs amont d'une intention.
const MAX_AMONTS: usize = 16;

fn adresse_canonique(v: &Value) -> Result<IpAddr, &'static str> {
    let texte = v.as_str().ok_or("types d'intention DNS invalides")?;
    let a: IpAddr = texte
        .parse()
        .map_err(|_| "adresse d'intention DNS invalide")?;
    if a.to_string() != texte {
        return Err("adresse d'intention DNS non canonique");
    }
    Ok(a)
}

/// L'intention DNS v1: exactement les sept cles. `backend` vaut
/// `systemd-resolved` ou `resolv-conf`; l'interface suit la regle du produit
/// (1 a 15 caracteres, alphanumeriques, `-` et `_`), sans `lo`; les adresses
/// sont ecrites sous leur forme canonique; les amonts sont de 1 a 16, sans
/// doublon; `resolveur_uid` est null ou un compte non nul, et seulement avec un
/// resolveur embarque. La politique doit passer la regle du produit
/// (`DnsPolicy::validate`: resolveur local en boucle locale, au moins un
/// amont).
pub fn intention_dns(v: Value) -> Result<Intention, &'static str> {
    let objet = v.as_object().ok_or("intention DNS invalide")?;
    if objet.len() != CLES.len() || CLES.iter().any(|c| !objet.contains_key(*c)) {
        return Err("champs d'intention DNS manquants ou inconnus");
    }
    if objet["schema_version"].as_u64() != Some(1) {
        return Err("version d'intention DNS inconnue");
    }
    let backend = match objet["backend"].as_str() {
        Some("systemd-resolved") => Backend::Resolved,
        Some("resolv-conf") => Backend::ResolvConf,
        _ => return Err("backend d'intention DNS inconnu"),
    };
    let interface = objet["interface"]
        .as_str()
        .ok_or("types d'intention DNS invalides")?;
    if interface.is_empty()
        || interface.len() > 15
        || interface == "lo"
        || !interface
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err("interface d'intention DNS invalide");
    }
    let local_resolver = adresse_canonique(&objet["local_resolver"])?;
    let amonts = objet["upstream"]
        .as_array()
        .ok_or("types d'intention DNS invalides")?;
    if amonts.is_empty() || amonts.len() > MAX_AMONTS {
        return Err("nombre de serveurs amont hors perimetre");
    }
    let mut upstream = Vec::new();
    for a in amonts {
        let a = adresse_canonique(a)?;
        if upstream.contains(&a) {
            return Err("serveur amont en double");
        }
        upstream.push(a);
    }
    let embarque = objet["embarque"]
        .as_bool()
        .ok_or("types d'intention DNS invalides")?;
    let resolveur_uid = match &objet["resolveur_uid"] {
        Value::Null => None,
        Value::Number(n) => Some(
            n.as_u64()
                .and_then(|n| u32::try_from(n).ok())
                .ok_or("types d'intention DNS invalides")?,
        ),
        _ => return Err("types d'intention DNS invalides"),
    };
    if resolveur_uid == Some(0) {
        return Err("compte du resolveur root interdit");
    }
    if resolveur_uid.is_some() && !embarque {
        return Err("compte de resolveur sans resolveur embarque");
    }
    let politique = DnsPolicy {
        local_resolver,
        upstream,
        embarque,
        anti_telemetrie: ProfilTelemetrie::Aucun,
    };
    politique
        .validate()
        .map_err(|_| "intention DNS refusee par la regle du produit")?;
    Ok(Intention {
        backend,
        plan: PlanDns::nouveau(interface, &politique),
        local_resolver,
        embarque,
        resolveur_uid,
    })
}

// ---------------------------------------------------------------------------
// Ce que le systeme rend, normalise.
// ---------------------------------------------------------------------------

/// Le mode de `/etc/resolv.conf`, au sens de systemd-resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ModeResolvConf {
    Uplink,
    Stub,
    Statique,
    Etranger,
    Absent,
}

impl ModeResolvConf {
    /// Le nom que resolved rend dans `ResolvConfMode`.
    pub(crate) fn nom(self) -> &'static str {
        match self {
            ModeResolvConf::Uplink => "uplink",
            ModeResolvConf::Stub => "stub",
            ModeResolvConf::Statique => "static",
            ModeResolvConf::Etranger => "foreign",
            ModeResolvConf::Absent => "missing",
        }
    }
}

/// Un inode: `(peripherique, numero)`.
pub(crate) type Inode = (u64, u64);

/// Le mode, calcule comme `resolv_conf_mode()` de systemd v255
/// (`resolved-resolv-conf.c`): `/etc/resolv.conf` absent donne `missing`;
/// sinon le premier des fichiers de resolved, dans l'ordre uplink, stub,
/// statique, qui a le meme inode; sinon `foreign`. Un fichier de resolved
/// absent est passe.
pub(crate) fn mode_resolv_conf(
    systeme: Option<Inode>,
    uplink: Option<Inode>,
    stub: Option<Inode>,
    statique: Option<Inode>,
) -> ModeResolvConf {
    let Some(s) = systeme else {
        return ModeResolvConf::Absent;
    };
    for (candidat, mode) in [
        (uplink, ModeResolvConf::Uplink),
        (stub, ModeResolvConf::Stub),
        (statique, ModeResolvConf::Statique),
    ] {
        if candidat == Some(s) {
            return mode;
        }
    }
    ModeResolvConf::Etranger
}

/// Les adresses des lignes `nameserver` de `resolv.conf`, telles que glibc les
/// lit (`res_vinit_1`, `resolv/res_init.c`): une ligne qui commence par `;` ou
/// `#` est un commentaire; le mot-cle doit etre en colonne 0 et suivi d'un
/// blanc; l'adresse va jusqu'au blanc suivant. Toutes sont rendues, meme
/// au-dela des trois que glibc garde: la preuve juge ce que le fichier dit.
pub(crate) fn serveurs_resolv_conf(texte: &[u8]) -> Vec<&[u8]> {
    texte
        .split(|&c| c == b'\n')
        .filter_map(|ligne| ligne.strip_prefix(b"nameserver"))
        .filter(|reste| matches!(reste.first(), Some(b' ' | b'\t')))
        .map(|reste| {
            let debut = reste
                .iter()
                .position(|&c| c != b' ' && c != b'\t')
                .unwrap_or(reste.len());
            let reste = &reste[debut..];
            let fin = reste
                .iter()
                .position(|&c| c == b' ' || c == b'\t')
                .unwrap_or(reste.len());
            &reste[..fin]
        })
        .collect()
}

/// Vrai si glibc, lisant ce fichier, n'interroge que le stub de resolved.
/// Sans aucune ligne `nameserver`, glibc interroge la boucle locale par
/// defaut: pas le stub.
fn vers_le_stub(contenu: Option<&[u8]>) -> bool {
    contenu.is_some_and(|c| {
        let s = serveurs_resolv_conf(c);
        !s.is_empty() && s.iter().all(|a| *a == b"127.0.0.53")
    })
}

/// Une ecoute UDP sans pair (adresse distante nulle).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Ecoute {
    pub(crate) adresse: IpAddr,
    pub(crate) port: u16,
    pub(crate) uid: u32,
}

/// Un lien du namespace courant, vu par resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Lien {
    pub(crate) index: u32,
    pub(crate) nom: Vec<u8>,
    pub(crate) route_par_defaut: bool,
    pub(crate) portees: u64,
    /// Ses serveurs, dans son ordre (`DNSEx` du lien, index lu a 0).
    pub(crate) serveurs: Vec<dbus::Serveur>,
}

/// L'etat de systemd-resolved, tel que le bus le rend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EtatResolved {
    /// Le nom unique du proprietaire de `org.freedesktop.resolve1`: deux
    /// lectures doivent lire la meme instance.
    pub(crate) proprietaire: String,
    pub(crate) uid: u32,
    /// `ResolvConfMode`, tel que resolved le calcule.
    pub(crate) mode: String,
    /// `DNSEx` du Manager, groupes par index, l'ordre propre a chaque index
    /// garde. L'index est celui de l'interface d'emission, pas la portee:
    /// voir `attribuer`.
    pub(crate) serveurs: Vec<dbus::Serveur>,
    pub(crate) domaines: Vec<dbus::Domaine>,
    pub(crate) delegues: bool,
    /// Par index croissant.
    pub(crate) liens: Vec<Lien>,
}

impl EtatResolved {
    /// L'ordre de `DNSEx` et `Domains` entre les portees suit une table de
    /// hachage interne de resolved: seul l'ordre au sein d'une portee a un
    /// sens. Les deux listes sont donc regroupees par index, de facon stable.
    pub(crate) fn normaliser(mut self) -> Self {
        self.serveurs.sort_by_key(|s| s.index);
        self.domaines.sort_by_key(|d| d.index);
        self.liens.sort_by_key(|l| l.index);
        self
    }
}

const DISCORDANTS: &str =
    "systemd-resolved: les serveurs du Manager et ceux des liens ne concordent pas";

/// Une adresse de bouclage, au sens de `in_addr_is_localhost` (systemd v255):
/// `127.0.0.0/8` et `::1`.
fn bouclage(s: &dbus::Serveur) -> bool {
    match s.famille {
        2 => s.adresse.first() == Some(&127),
        10 => s.adresse == std::net::Ipv6Addr::LOCALHOST.octets(),
        _ => false,
    }
}

/// Chaque serveur rattache a sa portee: l'index de son lien, ou 0 pour la
/// portee globale.
///
/// Le `DNSEx` du Manager liste les serveurs globaux et ceux de chaque lien,
/// chacun une fois, sous l'index de l'interface par laquelle resolved
/// l'interroge (`dns_server_ifindex`, systemd v255 et v262): 1 pour une
/// adresse de bouclage, quel que soit le lien qui la porte, et l'interface
/// nommee d'un serveur global ecrit `adresse%interface`. Le `DNSEx` de chaque
/// lien dit ses serveurs, dans son ordre: chacun est retire du Manager, un a
/// un, sous l'index que le Manager doit lui donner. Ce qui reste est la portee
/// globale. Un serveur de lien que le Manager ne liste pas rend NON MESURE.
pub(crate) fn attribuer(r: &EtatResolved) -> Result<Vec<dbus::Serveur>, &'static str> {
    let mut reste: Vec<Option<&dbus::Serveur>> = r.serveurs.iter().map(Some).collect();
    let mut des_liens = Vec::new();
    for l in &r.liens {
        let index = i32::try_from(l.index).map_err(|_| DISCORDANTS)?;
        for s in &l.serveurs {
            let emission = if bouclage(s) { 1 } else { index };
            let vu = reste
                .iter_mut()
                .find(|m| {
                    m.is_some_and(|m| {
                        m.index == emission
                            && m.famille == s.famille
                            && m.adresse == s.adresse
                            && m.port == s.port
                            && m.nom == s.nom
                    })
                })
                .ok_or(DISCORDANTS)?;
            *vu = None;
            des_liens.push(dbus::Serveur { index, ..s.clone() });
        }
    }
    let mut v: Vec<dbus::Serveur> = reste
        .into_iter()
        .flatten()
        .map(|s| dbus::Serveur {
            index: 0,
            ..s.clone()
        })
        .collect();
    v.extend(des_liens);
    Ok(v)
}

/// Une lecture complete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Observation {
    /// Les sources de la ligne `hosts`, dans l'ordre.
    pub(crate) hosts: Vec<String>,
    /// Presence de `/etc/mdns.allow`, lue seulement si un module mDNS non
    /// minimal figure dans `hosts`.
    pub(crate) mdns_allow: Option<bool>,
    /// Les ecoutes UDP du port 53.
    pub(crate) ecoutes: Vec<Ecoute>,
    /// Backend resolved: le mode calcule par la preuve.
    pub(crate) mode: Option<ModeResolvConf>,
    /// Le contenu de `/etc/resolv.conf`, lu pour les deux backends; `None` si
    /// le fichier est absent.
    pub(crate) resolv_conf: Option<Vec<u8>>,
    /// Backend resolved: l'index du lien du tunnel, `None` s'il est absent.
    pub(crate) tunnel: Option<u32>,
    pub(crate) resolved: Option<EtatResolved>,
}

/// L'encadrement: deux lectures completes, qui doivent etre identiques. Aucune
/// de ces sources ne porte de numero de generation, et beaucoup de proprietes
/// de resolved n'emettent pas de signal de changement.
pub(crate) fn encadrer<L>(mut lire: L) -> Result<Observation, &'static str>
where
    L: FnMut() -> Result<Observation, &'static str>,
{
    let premiere = lire()?;
    let seconde = lire()?;
    if premiere != seconde {
        return Err(INSTABLE);
    }
    Ok(premiere)
}

// ---------------------------------------------------------------------------
// Lecteurs des fichiers du systeme, purs.
// ---------------------------------------------------------------------------

fn nom_de_source_valide(s: &[u8]) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.iter()
            .all(|&c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
}

/// Les sources de la ligne `hosts` de `nsswitch.conf` (nsswitch.conf(5)):
/// colonnes separees par des blancs, la premiere est la base, `#` ouvre un
/// commentaire, `[...]` est une action. Une ligne `hosts` absente ou en
/// double, une base `hosts` ecrite dans une autre casse, une action non
/// fermee, un nom de source hors de `[A-Za-z0-9_-]` ou une ligne sans source
/// sont refuses: glibc pourrait les lire autrement.
pub(crate) fn sources_hosts(texte: &[u8]) -> Result<Vec<String>, &'static str> {
    let mut trouvee: Option<Vec<String>> = None;
    for ligne in texte.split(|&c| c == b'\n') {
        let ligne = match ligne.iter().position(|&c| c == b'#') {
            Some(i) => &ligne[..i],
            None => ligne,
        };
        let debut = ligne
            .iter()
            .position(|c| !c.is_ascii_whitespace())
            .unwrap_or(ligne.len());
        let ligne = &ligne[debut..];
        let Some(deux_points) = ligne.iter().position(|&c| c == b':') else {
            continue;
        };
        let base = ligne[..deux_points].trim_ascii();
        if !base.eq_ignore_ascii_case(b"hosts") {
            continue;
        }
        if base != b"hosts" || trouvee.is_some() {
            return Err("ligne hosts de nsswitch.conf ambigue");
        }
        let mut sources = Vec::new();
        let mut reste = &ligne[deux_points + 1..];
        loop {
            let i = reste
                .iter()
                .position(|c| !c.is_ascii_whitespace())
                .unwrap_or(reste.len());
            reste = &reste[i..];
            match reste.first() {
                None => break,
                Some(b'[') => {
                    let fin = reste
                        .iter()
                        .position(|&c| c == b']')
                        .ok_or("action de nsswitch.conf non fermee")?;
                    reste = &reste[fin + 1..];
                }
                Some(_) => {
                    let fin = reste
                        .iter()
                        .position(|&c| c.is_ascii_whitespace() || c == b'[')
                        .unwrap_or(reste.len());
                    let nom = &reste[..fin];
                    if !nom_de_source_valide(nom) {
                        return Err("source de nsswitch.conf illisible");
                    }
                    sources.push(String::from_utf8_lossy(nom).into_owned());
                    reste = &reste[fin..];
                }
            }
        }
        if sources.is_empty() {
            return Err("ligne hosts de nsswitch.conf sans source");
        }
        trouvee = Some(sources);
    }
    trouvee.ok_or("aucune ligne hosts dans nsswitch.conf")
}

/// Vrai pour un module mDNS non minimal (nss-mdns): il lit `/etc/mdns.allow`,
/// qui peut lui ouvrir d'autres domaines que `.local`.
pub(crate) fn mdns_non_minimal(source: &str) -> bool {
    matches!(source, "mdns" | "mdns4" | "mdns6")
}

fn hex(b: &[u8]) -> Option<u32> {
    if b.len() != 8 && b.len() != 4 {
        return None;
    }
    let t = std::str::from_utf8(b).ok()?;
    if !t.bytes().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    u32::from_str_radix(t, 16).ok()
}

/// `HHHHHHHH:PPPP` (IPv4) ou 32 chiffres puis `:PPPP` (IPv6): l'adresse est
/// ecrite mot de 32 bits par mot de 32 bits, chacun dans l'ordre de l'hote
/// (`%08X` d'un `__be32`, `udp4_format_sock` et `__ip6_dgram_sock_seq_show`,
/// noyau v7.0), le port dans l'ordre de l'hote.
fn point(champ: &[u8], v6: bool) -> Option<(IpAddr, u16)> {
    let (adresse, port) = champ.split_at(champ.iter().position(|&c| c == b':')?);
    let port = hex(&port[1..])
        .filter(|_| port.len() == 5)
        .and_then(|p| u16::try_from(p).ok())?;
    let mots = if v6 { 4 } else { 1 };
    if adresse.len() != mots * 8 {
        return None;
    }
    let mut octets = Vec::with_capacity(mots * 4);
    for i in 0..mots {
        octets.extend_from_slice(&hex(&adresse[i * 8..i * 8 + 8])?.to_ne_bytes());
    }
    let ip = if v6 {
        IpAddr::from(<[u8; 16]>::try_from(octets).ok()?)
    } else {
        IpAddr::from(<[u8; 4]>::try_from(octets).ok()?)
    };
    Some((ip, port))
}

/// Les ecoutes UDP du port 53, sans pair, de `/proc/net/udp` (ou `udp6`).
/// L'en-tete doit etre exactement celui du noyau v7.0; chaque ligne doit avoir
/// ses treize colonnes; une ligne illisible refuse le fichier entier.
pub(crate) fn ecoutes_udp(texte: &[u8], v6: bool) -> Result<Vec<Ecoute>, &'static str> {
    const ENTETE4: [&str; 15] = [
        "sl",
        "local_address",
        "rem_address",
        "st",
        "tx_queue",
        "rx_queue",
        "tr",
        "tm->when",
        "retrnsmt",
        "uid",
        "timeout",
        "inode",
        "ref",
        "pointer",
        "drops",
    ];
    let mut lignes = texte.split(|&c| c == b'\n');
    let entete: Vec<&[u8]> = lignes
        .next()
        .unwrap_or_default()
        .split(u8::is_ascii_whitespace)
        .filter(|t| !t.is_empty())
        .collect();
    let attendu = ENTETE4.iter().map(|t| {
        if v6 && *t == "rem_address" {
            "remote_address"
        } else {
            *t
        }
    });
    if entete.len() != ENTETE4.len() || !entete.iter().zip(attendu).all(|(a, b)| *a == b.as_bytes())
    {
        return Err("en-tete de /proc/net/udp inattendu");
    }
    let mut v = Vec::new();
    for ligne in lignes {
        let t: Vec<&[u8]> = ligne
            .split(u8::is_ascii_whitespace)
            .filter(|t| !t.is_empty())
            .collect();
        if t.is_empty() {
            continue;
        }
        if t.len() != 13 || !t[0].ends_with(b":") {
            return Err("ligne de /proc/net/udp illisible");
        }
        let (local, distant) = (
            point(t[1], v6).ok_or("adresse de /proc/net/udp illisible")?,
            point(t[2], v6).ok_or("adresse de /proc/net/udp illisible")?,
        );
        let uid: u32 = std::str::from_utf8(t[7])
            .ok()
            .filter(|u| u.bytes().all(|c| c.is_ascii_digit()))
            .and_then(|u| u.parse().ok())
            .ok_or("compte de /proc/net/udp illisible")?;
        if local.1 == 53 && distant.0.is_unspecified() && distant.1 == 0 {
            v.push(Ecoute {
                adresse: local.0,
                port: local.1,
                uid,
            });
        }
    }
    Ok(v)
}

// ---------------------------------------------------------------------------
// La comparaison.
// ---------------------------------------------------------------------------

/// `SD_RESOLVED_DNS` et les portees LLMNR et mDNS de `ScopesMask`
/// (`resolved-def.h`, systemd v255).
const PORTEE_DNS: u64 = 1 << 0;
const PORTEES_LLMNR: u64 = (1 << 1) | (1 << 2);
const PORTEES_MDNS: u64 = (1 << 3) | (1 << 4);

/// L'adresse du stub de resolved.
const STUB: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 53));

/// Les categories d'ecart, dans l'ordre ou le rapport les ecrit.
const ORDRE: [&str; 10] = [
    "resolv-conf-path",
    "resolv-conf-content",
    "hosts-sources",
    "tunnel-link-scope",
    "tunnel-link-servers",
    "tunnel-link-domains",
    "dns-exceptions",
    "competing-default-routes",
    "multicast-resolution",
    "local-resolver-listener",
];

/// Comptes attendus.
#[derive(Debug, Default, Serialize, PartialEq, Eq)]
pub(crate) struct Attendus {
    servers: usize,
    /// `~.` seul sur le lien du tunnel (resolved), `null` sinon.
    tunnel_domains: Option<usize>,
}

/// Comptes observes.
#[derive(Debug, Default, Serialize, PartialEq, Eq)]
pub(crate) struct Observes {
    hosts_sources: usize,
    /// Le mode de `/etc/resolv.conf` (resolved): un mot de systemd, jamais un
    /// chemin.
    resolv_conf_mode: Option<&'static str>,
    links: Option<usize>,
    scopes_with_servers: Option<usize>,
    tunnel_servers: Option<usize>,
    tunnel_domains: Option<usize>,
    other_scopes_with_domains: Option<usize>,
    other_default_route_links: Option<usize>,
    llmnr_links: Option<usize>,
    /// Resolveur embarque: les ecoutes de `local_resolver:53`.
    local_resolver_listeners: Option<usize>,
}

/// Les limites nommees rencontrees, comptees, admises.
#[derive(Debug, Default, Serialize, PartialEq, Eq)]
pub(crate) struct Limites {
    mdns_links: Option<usize>,
    mdns_nss_sources: usize,
}

/// Ce que la comparaison rend.
pub(crate) type Comparaison = (Attendus, Observes, Limites, Vec<&'static str>);

enum Jugement {
    Admise,
    Mdns,
    Ecart,
}

fn juger_source(source: &str, backend: Backend, mdns_allow: Option<bool>) -> Jugement {
    match source {
        "files" | "myhostname" | "mymachines" | "dns" => Jugement::Admise,
        "resolve" if backend == Backend::Resolved => Jugement::Admise,
        "mdns_minimal" | "mdns4_minimal" | "mdns6_minimal" => Jugement::Mdns,
        s if mdns_non_minimal(s) && mdns_allow == Some(false) => Jugement::Mdns,
        _ => Jugement::Ecart,
    }
}

/// Le serveur du plan, sous la forme ou resolved le rend: famille, adresse,
/// port 53 (ou 0, non precise), sans nom TLS.
fn serveur_du_plan(s: &dbus::Serveur, a: &IpAddr) -> bool {
    let (famille, octets) = match a {
        IpAddr::V4(v) => (2, v.octets().to_vec()),
        IpAddr::V6(v) => (10, v.octets().to_vec()),
    };
    s.famille == famille && s.adresse == octets && matches!(s.port, 0 | 53) && s.nom.is_empty()
}

/// Les gardes, puis la comparaison. Une garde qui ne tient pas rend une
/// erreur: NON MESURE.
pub(crate) fn comparer(i: &Intention, obs: &Observation) -> Result<Comparaison, &'static str> {
    let mut ecarts = Vec::new();
    let mut a = Attendus {
        servers: i.plan.serveurs.len(),
        tunnel_domains: None,
    };
    let mut o = Observes {
        hosts_sources: obs.hosts.len(),
        ..Observes::default()
    };
    let mut lim = Limites::default();

    // Les sources nsswitch, pour les deux backends.
    let mut hors = false;
    for s in &obs.hosts {
        match juger_source(s, i.backend, obs.mdns_allow) {
            Jugement::Admise => {}
            Jugement::Mdns => lim.mdns_nss_sources += 1,
            Jugement::Ecart => hors = true,
        }
    }
    if hors {
        ecarts.push("hosts-sources");
    }

    match i.backend {
        Backend::ResolvConf => {
            if obs.resolv_conf.as_deref() != Some(i.plan.contenu_resolv_conf().as_bytes()) {
                ecarts.push("resolv-conf-content");
            }
        }
        Backend::Resolved => {
            let r = obs
                .resolved
                .as_ref()
                .ok_or("etat de systemd-resolved non lu")?;
            let mode = obs.mode.ok_or("mode de /etc/resolv.conf non lu")?;
            // Gardes.
            if r.delegues {
                return Err("delegues DNS presents: portees non lues par cette preuve");
            }
            if !obs
                .ecoutes
                .iter()
                .any(|e| e.adresse == STUB && e.port == 53 && e.uid == r.uid)
            {
                return Err(
                    "ecoute du stub de systemd-resolved absente du namespace courant: resolved d'un autre namespace, ou stub coupe",
                );
            }
            let connus = |index: i32| {
                index == 0
                    || (index > 0
                        && r.liens
                            .iter()
                            .any(|l| i64::from(l.index) == i64::from(index)))
            };
            if !r.serveurs.iter().all(|s| connus(s.index))
                || !r.domaines.iter().all(|d| connus(d.index))
            {
                return Err("systemd-resolved cite un lien absent du namespace courant");
            }
            if r.mode != mode.nom() {
                return Err(
                    "systemd-resolved juge un autre /etc/resolv.conf que celui de ce namespace de montage",
                );
            }
            let serveurs = attribuer(r)?;
            o.resolv_conf_mode = Some(mode.nom());
            if !matches!(mode, ModeResolvConf::Stub | ModeResolvConf::Statique)
                || !vers_le_stub(obs.resolv_conf.as_deref())
            {
                ecarts.push("resolv-conf-path");
            }

            // Le lien du tunnel.
            let tunnel = obs
                .tunnel
                .and_then(|t| r.liens.iter().find(|l| l.index == t));
            if tunnel.is_none_or(|l| l.portees & PORTEE_DNS == 0) {
                ecarts.push("tunnel-link-scope");
            }
            let index_tunnel = tunnel.map(|l| l.index as i32);
            let serveurs_tunnel: Vec<&dbus::Serveur> = serveurs
                .iter()
                .filter(|s| Some(s.index) == index_tunnel)
                .collect();
            o.tunnel_servers = Some(serveurs_tunnel.len());
            if serveurs_tunnel.len() != i.plan.serveurs.len()
                || !serveurs_tunnel
                    .iter()
                    .zip(&i.plan.serveurs)
                    .all(|(s, a)| serveur_du_plan(s, a))
            {
                ecarts.push("tunnel-link-servers");
            }
            let domaines_tunnel: Vec<&dbus::Domaine> = r
                .domaines
                .iter()
                .filter(|d| Some(d.index) == index_tunnel)
                .collect();
            a.tunnel_domains = Some(1);
            o.tunnel_domains = Some(domaines_tunnel.len());
            if !matches!(domaines_tunnel.as_slice(), [d] if d.nom == "." && d.route_seule) {
                ecarts.push("tunnel-link-domains");
            }

            // Les autres portees qui ont un serveur: la regle de legitimite.
            let mut portees: Vec<i32> = serveurs
                .iter()
                .map(|s| s.index)
                .filter(|&x| Some(x) != index_tunnel)
                .collect();
            portees.sort_unstable();
            portees.dedup();
            o.scopes_with_servers = Some(portees.len() + usize::from(!serveurs_tunnel.is_empty()));
            let (mut exceptions, mut concurrentes) = (0, 0);
            for p in &portees {
                let domaines: Vec<&dbus::Domaine> =
                    r.domaines.iter().filter(|d| d.index == *p).collect();
                if domaines.iter().any(|d| d.nom != ".") {
                    exceptions += 1;
                }
                if domaines.iter().any(|d| d.nom == ".") {
                    concurrentes += 1;
                }
            }
            o.other_scopes_with_domains = Some(
                portees
                    .iter()
                    .filter(|p| r.domaines.iter().any(|d| d.index == **p))
                    .count(),
            );
            if exceptions > 0 {
                ecarts.push("dns-exceptions");
            }
            if concurrentes > 0 {
                ecarts.push("competing-default-routes");
            }
            o.links = Some(r.liens.len());
            o.other_default_route_links = Some(
                r.liens
                    .iter()
                    .filter(|l| Some(l.index as i32) != index_tunnel && l.route_par_defaut)
                    .count(),
            );
            let llmnr = r
                .liens
                .iter()
                .filter(|l| l.portees & PORTEES_LLMNR != 0)
                .count();
            o.llmnr_links = Some(llmnr);
            if llmnr > 0 {
                ecarts.push("multicast-resolution");
            }
            lim.mdns_links = Some(
                r.liens
                    .iter()
                    .filter(|l| l.portees & PORTEES_MDNS != 0)
                    .count(),
            );
        }
    }

    // Le resolveur embarque: qui ecoute sur son adresse, et sous quel compte.
    if i.embarque {
        let ecoutes: Vec<&Ecoute> = obs
            .ecoutes
            .iter()
            .filter(|e| e.adresse == i.local_resolver && e.port == 53)
            .collect();
        o.local_resolver_listeners = Some(ecoutes.len());
        if ecoutes.is_empty()
            || i.resolveur_uid
                .is_some_and(|u| ecoutes.iter().any(|e| e.uid != u))
        {
            ecarts.push("local-resolver-listener");
        }
    }

    ecarts.sort_by_key(|c| ORDRE.iter().position(|x| x == c));
    Ok((a, o, lim, ecarts))
}

// ---------------------------------------------------------------------------
// Le rapport.
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct Rapport {
    schema_version: u32,
    scope: &'static str,
    verdict: &'static str,
    started_at_unix_ms: Option<u128>,
    completed_at_unix_ms: Option<u128>,
    duration_ms: u128,
    /// La collecte de cet hote; `null` hors Linux, ou rien n'est lu.
    source: Option<&'static str>,
    expected_source: &'static str,
    intention_schema_version: Option<u32>,
    /// Le backend que l'intention declare.
    backend: Option<&'static str>,
    live_system: bool,
    collection_verified: bool,
    network_security: &'static str,
    expected_counts: Option<Attendus>,
    observed_counts: Option<Observes>,
    named_limits: Option<Limites>,
    differences: Vec<&'static str>,
    failed_input: Option<&'static str>,
    reason: &'static str,
    limitation: &'static str,
}

impl Rapport {
    pub fn code(&self) -> i32 {
        match self.verdict {
            "MATCH" => 0,
            "MISMATCH" => 1,
            _ => 2,
        }
    }

    pub fn texte(&self) -> String {
        format!(
            "{}  {}\n{}\nentree non mesuree: {}\necarts: {}\n\n{}\n",
            self.verdict,
            self.scope,
            self.reason,
            self.failed_input.unwrap_or("aucune"),
            self.differences.join(", "),
            self.limitation
        )
    }
}

fn commencer() -> Rapport {
    Rapport {
        schema_version: 1,
        scope: "linux-dns-comparison",
        verdict: "UNMEASURED",
        started_at_unix_ms: heure(),
        completed_at_unix_ms: None,
        duration_ms: 0,
        source: None,
        expected_source: "bifrost-dns-plan-v1-user-declared",
        intention_schema_version: None,
        backend: None,
        live_system: false,
        collection_verified: false,
        network_security: "not-evaluated",
        expected_counts: None,
        observed_counts: None,
        named_limits: None,
        differences: Vec::new(),
        failed_input: Some("intention"),
        reason: "intention DNS illisible ou non prise en charge",
        limitation: LIMITE,
    }
}

/// La source d'un backend, quand la collecte existe sur cet hote.
fn source(b: Backend) -> &'static str {
    match b {
        Backend::Resolved => "resolved-dbus-and-system-files-read-twice",
        Backend::ResolvConf => "resolv-conf-and-system-files-read-twice",
    }
}

/// La preuve, separee de sa collecte pour que les recettes la jouent avec une
/// fausse lecture. `lire` rend UNE lecture complete; l'encadrement (deux
/// lectures identiques) est fait ici. `collecte` dit si cet hote a une
/// collecte: sans elle, le rapport ne nomme aucune source.
pub(crate) fn verifier_avec<L>(intention: &Path, collecte: bool, mut lire: L) -> Rapport
where
    L: FnMut(&Intention) -> Result<Observation, &'static str>,
{
    let debut = Instant::now();
    let mut r = commencer();
    let resultat = (|| {
        let Unique(v) = serde_json::from_slice(&crate::preuve_nft::lire(intention)?)
            .map_err(|_| "intention DNS JSON invalide ou ambigue")?;
        let i = intention_dns(v)?;
        r.intention_schema_version = Some(1);
        r.backend = Some(match i.backend {
            Backend::Resolved => "systemd-resolved",
            Backend::ResolvConf => "resolv-conf",
        });
        if collecte {
            r.source = Some(source(i.backend));
        }
        r.failed_input = Some("observed");
        // L'intention est lue et validee AVANT toute lecture du systeme.
        let obs = encadrer(|| lire(&i))?;
        r.live_system = true;
        r.collection_verified = true;
        let (attendus, observes, limites, ecarts) = comparer(&i, &obs)?;
        r.expected_counts = Some(attendus);
        r.observed_counts = Some(observes);
        r.named_limits = Some(limites);
        r.failed_input = None;
        r.verdict = if ecarts.is_empty() {
            "MATCH"
        } else {
            "MISMATCH"
        };
        r.differences = ecarts;
        Ok(())
    })();
    r.reason = match resultat {
        Ok(()) => "etat du resolveur systeme compare au plan DNS du produit",
        Err(raison) => raison,
    };
    r.completed_at_unix_ms = heure();
    r.duration_ms = debut.elapsed().as_millis();
    r
}

/// `prove dns --intention F --actif`. Hors Linux, l'intention est lue, puis
/// la preuve rend NON MESURE, sans source.
pub fn verifier(intention: &Path) -> Rapport {
    #[cfg(target_os = "linux")]
    {
        verifier_avec(intention, true, crate::preuve_dns_linux::lire_une_fois)
    }
    #[cfg(not(target_os = "linux"))]
    {
        verifier_avec(intention, false, |_| {
            Err("collecte DNS disponible uniquement sous Linux")
        })
    }
}
