//! Lecteur D-Bus minimal, en lecture seule, pour `prove dns`.
//!
//! Pur: aucune entree-sortie ici, pour que les recettes et le harnais de
//! fuzzing le jouent partout sur des trames fabriquees ou captees. Le protocole
//! vient de la specification D-Bus 0.43 (revision du 29/10/2024), relue le
//! 02/10/2026: format des messages, marshalling, noms valides, authentification
//! et interface du bus.
//!
//! # Ce qu'il sait faire, et rien d'autre
//!
//! - l'authentification EXTERNAL, sans negociation de descripteurs;
//! - ecrire un appel de methode a une poignee de formes de corps (`s`, `ss`,
//!   `i`, vide), toujours avec `NO_AUTO_START`: un appel ne doit jamais faire
//!   demarrer un service par activation;
//! - lire la reponse a cet appel, et seulement aux formes que la preuve
//!   demande: `s`, `u`, `o`, `a(so)` (dont seule la longueur est lue), et une
//!   variante (`v`) qui porte `a(iiayqs)`, `a(iayqs)`, `a(isb)`, `s`, `b` ou
//!   `t`.
//!
//! Tout le reste est refuse, jamais ignore: une autre signature, un descripteur
//! de fichier passe (`UNIX_FDS`), un message tronque, une longueur hors borne, un
//! boutisme autre que celui de l'hote, une version de protocole inconnue, un
//! remplissage non nul, une chaine qui n'est pas de l'UTF-8 strict, un champ
//! d'en-tete connu du mauvais type ou en double, une reponse a un autre appel ou
//! d'un autre emetteur (hors l'erreur que le bus rend lui-meme pour un appel
//! qu'il ne transmet pas), un appel recu d'un pair. La preuve devient alors NON
//! MESUREE.
//!
//! Deux points d'extension de la specification sont honores, parce qu'ils sont
//! des obligations et qu'ils ne changent rien a ce qui est lu: un signal (le bus
//! envoie `NameAcquired` apres `Hello`) ou un message d'un type inconnu est
//! saute en entier, apres lecture stricte de son en-tete; un champ d'en-tete de
//! code inconnu est saute s'il porte un type de base de taille connue, et refuse
//! sinon. Les drapeaux d'en-tete inconnus sont ignores, comme la specification
//! l'exige.

/// Le boutisme des trames que la preuve ecrit et accepte: celui de l'hote.
/// systemd ecrit ses messages dans le boutisme de sa machine, et le bus les
/// relaie tels quels.
pub const ORDRE_NATIF: u8 = if cfg!(target_endian = "little") {
    b'l'
} else {
    b'B'
};

/// Borne d'un message lu, en-tete et corps compris. La specification autorise
/// 128 Mio; les reponses lues ici font quelques kilo-octets.
pub const MAX_MESSAGE: usize = 1024 * 1024;
/// Borne du tableau des champs d'en-tete.
const MAX_CHAMPS: usize = 4096;
/// Borne d'une ligne de l'authentification.
const MAX_LIGNE: usize = 512;
/// Borne du nombre d'elements d'un tableau lu: serveurs ou domaines, toutes
/// portees confondues. Atteignable sous `MAX_MESSAGE` (un element `(isb)` fait
/// au moins 16 octets), et tres au-dela de toute configuration reelle.
pub(crate) const MAX_ELEMENTS: usize = 4096;

const METHOD_CALL: u8 = 1;
const METHOD_RETURN: u8 = 2;
const ERROR: u8 = 3;
const SIGNAL: u8 = 4;
const NO_AUTO_START: u8 = 0x2;

const CHAMP_PATH: u8 = 1;
const CHAMP_INTERFACE: u8 = 2;
const CHAMP_MEMBER: u8 = 3;
const CHAMP_ERROR_NAME: u8 = 4;
const CHAMP_REPLY_SERIAL: u8 = 5;
const CHAMP_DESTINATION: u8 = 6;
const CHAMP_SENDER: u8 = 7;
const CHAMP_SIGNATURE: u8 = 8;
const CHAMP_UNIX_FDS: u8 = 9;

/// Le nom du bus lui-meme, emetteur de ses propres reponses.
pub const BUS: &str = "org.freedesktop.DBus";

pub(crate) const TRONQUE: &str = "trame D-Bus tronquee";
pub(crate) const HORS_BORNE: &str = "trame D-Bus hors borne";
pub(crate) const BOUTISME: &str = "trame D-Bus d'un boutisme inattendu";
pub(crate) const DESCRIPTEUR: &str = "descripteur de fichier passe dans une trame D-Bus";
pub(crate) const SIGNATURE: &str = "signature D-Bus non prise en charge";
pub(crate) const MAL_FORMEE: &str = "trame D-Bus mal formee";
pub(crate) const INATTENDUE: &str = "reponse D-Bus inattendue";
pub(crate) const REFUSEE: &str = "authentification D-Bus refusee";

// ---------------------------------------------------------------------------
// Authentification.
// ---------------------------------------------------------------------------

/// L'octet nul initial puis `AUTH EXTERNAL`, l'identite etant l'uid en decimal
/// ASCII, encode en hexadecimal, comme la specification le recommande.
pub fn requete_authentification(uid: u32) -> Vec<u8> {
    let mut v = b"\0AUTH EXTERNAL ".to_vec();
    for octet in uid.to_string().bytes() {
        v.extend_from_slice(format!("{octet:02x}").as_bytes());
    }
    v.extend_from_slice(b"\r\n");
    v
}

/// Ce qui suit l'accord du serveur: la fin de l'authentification. Aucun
/// `NEGOTIATE_UNIX_FD`: le serveur ne peut alors passer aucun descripteur.
pub const DEBUT: &[u8] = b"BEGIN\r\n";

/// La reponse du serveur a `AUTH`: `Ok(None)` tant que la ligne n'est pas
/// complete, `Ok(Some(n))` pour `OK <GUID>` complet en `n` octets. Toute autre
/// ligne est refusee.
pub fn lire_accord(flux: &[u8]) -> Result<Option<usize>, &'static str> {
    let Some(fin) = flux.windows(2).position(|w| w == b"\r\n") else {
        return if flux.len() >= MAX_LIGNE {
            Err(HORS_BORNE)
        } else {
            Ok(None)
        };
    };
    if fin > MAX_LIGNE {
        return Err(HORS_BORNE);
    }
    let ligne = &flux[..fin];
    if ligne.starts_with(b"REJECTED") {
        return Err(REFUSEE);
    }
    match ligne.strip_prefix(b"OK ") {
        Some(guid) if guid.len() == 32 && guid.iter().all(u8::is_ascii_hexdigit) => {
            Ok(Some(fin + 2))
        }
        _ => Err("reponse d'authentification D-Bus inattendue"),
    }
}

// ---------------------------------------------------------------------------
// Noms et chemins (section "Valid Names").
// ---------------------------------------------------------------------------

fn element_valide(e: &[u8], tiret: bool, chiffre_en_tete: bool) -> bool {
    !e.is_empty()
        && (chiffre_en_tete || !e[0].is_ascii_digit())
        && e.iter()
            .all(|&c| c.is_ascii_alphanumeric() || c == b'_' || (tiret && c == b'-'))
}

/// Un chemin d'objet valide.
pub fn chemin_valide(p: &str) -> bool {
    if p == "/" {
        return true;
    }
    let Some(reste) = p.strip_prefix('/') else {
        return false;
    };
    reste
        .split('/')
        .all(|e| !e.is_empty() && e.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_'))
}

/// Un nom d'interface, de membre ou d'erreur, ou un nom de bus.
fn nom_point_valide(n: &str, tiret: bool, unique: bool) -> bool {
    if n.is_empty() || n.len() > 255 {
        return false;
    }
    let corps = if unique {
        match n.strip_prefix(':') {
            Some(c) => c,
            None => return false,
        }
    } else {
        n
    };
    let elements: Vec<&str> = corps.split('.').collect();
    elements.len() >= 2
        && elements
            .iter()
            .all(|e| element_valide(e.as_bytes(), tiret, unique))
}

/// Un nom unique de connexion (`:1.42`).
pub fn nom_unique_valide(n: &str) -> bool {
    nom_point_valide(n, true, true)
}

fn nom_membre_valide(n: &str) -> bool {
    n.len() <= 255 && element_valide(n.as_bytes(), false, false)
}

// ---------------------------------------------------------------------------
// Ecriture d'un appel.
// ---------------------------------------------------------------------------

/// Le corps d'un appel: les seules formes que la preuve envoie.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Corps {
    Vide,
    /// `s`
    Chaine(String),
    /// `ss`: interface et propriete de `Properties.Get`.
    DeuxChaines(String, String),
    /// `i`: l'index de `Manager.GetLink`.
    Entier32(i32),
}

impl Corps {
    fn signature(&self) -> &'static str {
        match self {
            Corps::Vide => "",
            Corps::Chaine(_) => "s",
            Corps::DeuxChaines(..) => "ss",
            Corps::Entier32(_) => "i",
        }
    }
}

/// Un appel de methode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Appel {
    pub destination: String,
    pub chemin: String,
    pub interface: String,
    pub membre: String,
    pub corps: Corps,
}

struct Ecrivain {
    ordre: u8,
    v: Vec<u8>,
}

impl Ecrivain {
    fn aligner(&mut self, n: usize) {
        while !self.v.len().is_multiple_of(n) {
            self.v.push(0);
        }
    }
    fn u32(&mut self, x: u32) {
        self.aligner(4);
        let o = if self.ordre == b'l' {
            x.to_le_bytes()
        } else {
            x.to_be_bytes()
        };
        self.v.extend_from_slice(&o);
    }
    fn chaine(&mut self, s: &str) {
        self.u32(s.len() as u32);
        self.v.extend_from_slice(s.as_bytes());
        self.v.push(0);
    }
    fn signature(&mut self, s: &str) {
        self.v.push(s.len() as u8);
        self.v.extend_from_slice(s.as_bytes());
        self.v.push(0);
    }
    fn champ(&mut self, code: u8, genre: &str, valeur: &str) {
        self.aligner(8);
        self.v.push(code);
        self.signature(genre);
        if genre == "g" {
            self.signature(valeur);
        } else {
            self.chaine(valeur);
        }
    }
}

/// Le message d'un appel de methode, numero `serie`, dans le boutisme
/// `ordre`. Refuse un nom ou un chemin invalide plutot que de l'ecrire.
pub fn encoder_appel(appel: &Appel, serie: u32, ordre: u8) -> Result<Vec<u8>, &'static str> {
    let destination_valide = appel.destination == BUS
        || nom_unique_valide(&appel.destination)
        || nom_point_valide(&appel.destination, true, false);
    if serie == 0
        || !matches!(ordre, b'l' | b'B')
        || !destination_valide
        || !chemin_valide(&appel.chemin)
        || !nom_point_valide(&appel.interface, false, false)
        || !nom_membre_valide(&appel.membre)
    {
        return Err("appel D-Bus invalide");
    }
    let mut e = Ecrivain {
        ordre,
        v: vec![ordre, METHOD_CALL, NO_AUTO_START, 1],
    };
    e.u32(0); // longueur du corps, posee plus bas
    e.u32(serie);
    e.u32(0); // longueur du tableau des champs, posee plus bas
    let debut_champs = e.v.len();
    e.champ(CHAMP_PATH, "o", &appel.chemin);
    e.champ(CHAMP_DESTINATION, "s", &appel.destination);
    e.champ(CHAMP_INTERFACE, "s", &appel.interface);
    e.champ(CHAMP_MEMBER, "s", &appel.membre);
    let signature = appel.corps.signature();
    if !signature.is_empty() {
        e.champ(CHAMP_SIGNATURE, "g", signature);
    }
    let longueur_champs = (e.v.len() - debut_champs) as u32;
    e.aligner(8);
    let debut_corps = e.v.len();
    match &appel.corps {
        Corps::Vide => {}
        Corps::Chaine(s) => e.chaine(s),
        Corps::DeuxChaines(a, b) => {
            e.chaine(a);
            e.chaine(b);
        }
        Corps::Entier32(i) => e.u32(*i as u32),
    }
    let longueur_corps = (e.v.len() - debut_corps) as u32;
    let ecrire = |v: &mut Vec<u8>, a: usize, x: u32| {
        let o = if ordre == b'l' {
            x.to_le_bytes()
        } else {
            x.to_be_bytes()
        };
        v[a..a + 4].copy_from_slice(&o);
    };
    ecrire(&mut e.v, 4, longueur_corps);
    ecrire(&mut e.v, 12, longueur_champs);
    Ok(e.v)
}

// ---------------------------------------------------------------------------
// Lecture.
// ---------------------------------------------------------------------------

/// Un curseur sur un bloc aligne sur 8 octets depuis le debut du message.
struct Lecteur<'a> {
    ordre: u8,
    b: &'a [u8],
    pos: usize,
}

impl<'a> Lecteur<'a> {
    fn prendre(&mut self, n: usize) -> Result<&'a [u8], &'static str> {
        if n > self.b.len() - self.pos {
            return Err(TRONQUE);
        }
        let s = &self.b[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    /// Le remplissage doit etre fait d'octets nuls, et minimal.
    fn aligner(&mut self, n: usize) -> Result<(), &'static str> {
        let pad = (n - self.pos % n) % n;
        if self.prendre(pad)?.iter().any(|&o| o != 0) {
            return Err(MAL_FORMEE);
        }
        Ok(())
    }
    fn u8(&mut self) -> Result<u8, &'static str> {
        Ok(self.prendre(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, &'static str> {
        self.aligner(2)?;
        let b: [u8; 2] = self.prendre(2)?.try_into().map_err(|_| TRONQUE)?;
        Ok(if self.ordre == b'l' {
            u16::from_le_bytes(b)
        } else {
            u16::from_be_bytes(b)
        })
    }
    fn u32(&mut self) -> Result<u32, &'static str> {
        self.aligner(4)?;
        let b: [u8; 4] = self.prendre(4)?.try_into().map_err(|_| TRONQUE)?;
        Ok(if self.ordre == b'l' {
            u32::from_le_bytes(b)
        } else {
            u32::from_be_bytes(b)
        })
    }
    fn u64(&mut self) -> Result<u64, &'static str> {
        self.aligner(8)?;
        let b: [u8; 8] = self.prendre(8)?.try_into().map_err(|_| TRONQUE)?;
        Ok(if self.ordre == b'l' {
            u64::from_le_bytes(b)
        } else {
            u64::from_be_bytes(b)
        })
    }
    fn booleen(&mut self) -> Result<bool, &'static str> {
        match self.u32()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(MAL_FORMEE),
        }
    }
    /// Le texte d'une chaine ou d'une signature: UTF-8 strict, sans octet nul,
    /// suivi de son octet nul.
    fn texte(&mut self, n: usize) -> Result<&'a str, &'static str> {
        let octets = self.prendre(n)?;
        if self.u8()? != 0 || octets.contains(&0) {
            return Err(MAL_FORMEE);
        }
        std::str::from_utf8(octets).map_err(|_| MAL_FORMEE)
    }
    fn chaine(&mut self) -> Result<&'a str, &'static str> {
        let n = self.u32()? as usize;
        if n > MAX_MESSAGE {
            return Err(HORS_BORNE);
        }
        self.texte(n)
    }
    fn chemin(&mut self) -> Result<&'a str, &'static str> {
        let c = self.chaine()?;
        if chemin_valide(c) {
            Ok(c)
        } else {
            Err(MAL_FORMEE)
        }
    }
    fn signature(&mut self) -> Result<&'a str, &'static str> {
        let n = self.u8()? as usize;
        self.texte(n)
    }
    /// L'en-tete d'un tableau: sa longueur en octets, puis l'alignement de
    /// ses elements, meme s'il n'y en a aucun. Rend la position de fin.
    fn tableau(&mut self, alignement: usize) -> Result<usize, &'static str> {
        let n = self.u32()? as usize;
        if n > MAX_MESSAGE {
            return Err(HORS_BORNE);
        }
        self.aligner(alignement)?;
        if n > self.b.len() - self.pos {
            return Err(TRONQUE);
        }
        Ok(self.pos + n)
    }
}

/// Un serveur DNS de `DNSEx`: `(ifindex, famille, adresse, port, nom)` pour
/// le Manager, `(famille, adresse, port, nom)` pour un lien, dont l'index lu
/// est alors 0.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Serveur {
    pub index: i32,
    pub famille: i32,
    pub adresse: Vec<u8>,
    pub port: u16,
    pub nom: String,
}

/// Un domaine de `Domains`: `(ifindex, nom, route seule)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Domaine {
    pub index: i32,
    pub nom: String,
    pub route_seule: bool,
}

/// Ce qu'une variante doit porter, propriete par propriete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Propriete {
    /// `a(iiayqs)`: `DNSEx` du Manager.
    Serveurs,
    /// `a(iayqs)`: `DNSEx` d'un lien.
    ServeursDuLien,
    /// `a(isb)`: `Domains` du Manager.
    Domaines,
    /// `s`
    Chaine,
    /// `b`
    Booleen,
    /// `t`
    Entier64,
}

impl Propriete {
    pub fn signature(self) -> &'static str {
        match self {
            Propriete::Serveurs => "a(iiayqs)",
            Propriete::ServeursDuLien => "a(iayqs)",
            Propriete::Domaines => "a(isb)",
            Propriete::Chaine => "s",
            Propriete::Booleen => "b",
            Propriete::Entier64 => "t",
        }
    }
}

/// La forme de la reponse attendue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Forme {
    /// `s`
    Chaine,
    /// `u`
    Entier32NonSigne,
    /// `o`
    Chemin,
    /// `a(so)`, dont seule la longueur est lue: vide ou non.
    ListeDeDelegues,
    /// `v`, portant la propriete donnee.
    Variante(Propriete),
}

impl Forme {
    pub fn signature(self) -> &'static str {
        match self {
            Forme::Chaine => "s",
            Forme::Entier32NonSigne => "u",
            Forme::Chemin => "o",
            Forme::ListeDeDelegues => "a(so)",
            Forme::Variante(_) => "v",
        }
    }
}

/// Une valeur lue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Valeur {
    Chaine(String),
    Entier32NonSigne(u32),
    Chemin(String),
    /// Vrai si la liste porte au moins un element.
    Delegues(bool),
    Serveurs(Vec<Serveur>),
    /// Les serveurs d'un lien, index a 0.
    ServeursDuLien(Vec<Serveur>),
    Domaines(Vec<Domaine>),
    Booleen(bool),
    Entier64(u64),
}

/// L'issue d'un appel: le retour, le nom de l'erreur rendue par l'appele, ou
/// celui de l'erreur rendue par le bus lui-meme pour un appel qu'il n'a pas
/// transmis (politique, service parti).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Issue {
    Retour(Valeur),
    Erreur(String),
    RefusDuBus(String),
}

/// Ce que la reponse doit etre.
#[derive(Debug, Clone, Copy)]
pub struct Attente<'a> {
    /// Le numero de l'appel auquel elle repond.
    pub serie: u32,
    /// Son emetteur: le bus, ou le nom unique du service appele.
    pub emetteur: &'a str,
    pub forme: Forme,
    /// Le boutisme accepte.
    pub ordre: u8,
}

/// L'en-tete d'un message lu.
struct Message<'a> {
    genre: u8,
    reponse_a: Option<u32>,
    emetteur: Option<&'a str>,
    nom_erreur: Option<&'a str>,
    signature: &'a str,
    corps: &'a [u8],
    total: usize,
}

/// Saute la valeur d'un champ d'en-tete inconnu, s'il est d'un type de base.
fn sauter_base(l: &mut Lecteur<'_>, genre: &str) -> Result<(), &'static str> {
    match genre {
        "y" => l.u8().map(drop),
        "n" | "q" => l.u16().map(drop),
        "b" => l.booleen().map(drop),
        "i" | "u" => l.u32().map(drop),
        "h" => Err(DESCRIPTEUR),
        "x" | "t" | "d" => l.u64().map(drop),
        "s" | "o" => l.chaine().map(drop),
        "g" => l.signature().map(drop),
        _ => Err(SIGNATURE),
    }
}

/// Lit l'en-tete du premier message de `flux`; `Ok(None)` s'il n'est pas
/// encore complet.
fn message<'a>(flux: &'a [u8], ordre: u8) -> Result<Option<Message<'a>>, &'static str> {
    if flux.is_empty() {
        return Ok(None);
    }
    if flux[0] != ordre {
        return Err(BOUTISME);
    }
    if flux.len() < 16 {
        return Ok(None);
    }
    let mut l = Lecteur {
        ordre,
        b: &flux[..16],
        pos: 1,
    };
    let genre = l.u8()?;
    let _drapeaux = l.u8()?;
    if l.u8()? != 1 {
        return Err("version de protocole D-Bus inconnue");
    }
    let longueur_corps = l.u32()? as usize;
    let serie = l.u32()?;
    let longueur_champs = l.u32()? as usize;
    if genre == 0 || serie == 0 {
        return Err(MAL_FORMEE);
    }
    if longueur_champs > MAX_CHAMPS || longueur_corps > MAX_MESSAGE {
        return Err(HORS_BORNE);
    }
    let fin_champs = 16 + longueur_champs;
    let debut_corps = fin_champs.div_ceil(8) * 8;
    let total = debut_corps + longueur_corps;
    if total > MAX_MESSAGE {
        return Err(HORS_BORNE);
    }
    if flux.len() < total {
        return Ok(None);
    }
    let mut l = Lecteur {
        ordre,
        b: &flux[..fin_champs],
        pos: 16,
    };
    let mut vus = [false; 256];
    let (mut chemin, mut membre, mut interface) = (false, false, false);
    let mut m = Message {
        genre,
        reponse_a: None,
        emetteur: None,
        nom_erreur: None,
        signature: "",
        corps: &flux[debut_corps..total],
        total,
    };
    while l.pos < fin_champs {
        l.aligner(8)?;
        let code = l.u8()?;
        let genre_champ = l.signature()?;
        if code == 0 || vus[code as usize] {
            return Err(MAL_FORMEE);
        }
        vus[code as usize] = true;
        let attendu = match code {
            CHAMP_PATH => "o",
            CHAMP_INTERFACE | CHAMP_MEMBER | CHAMP_ERROR_NAME | CHAMP_DESTINATION
            | CHAMP_SENDER => "s",
            CHAMP_REPLY_SERIAL | CHAMP_UNIX_FDS => "u",
            CHAMP_SIGNATURE => "g",
            _ => {
                sauter_base(&mut l, genre_champ)?;
                continue;
            }
        };
        if genre_champ != attendu {
            return Err(MAL_FORMEE);
        }
        match code {
            CHAMP_PATH => {
                l.chemin()?;
                chemin = true;
            }
            CHAMP_INTERFACE => {
                if !nom_point_valide(l.chaine()?, false, false) {
                    return Err(MAL_FORMEE);
                }
                interface = true;
            }
            CHAMP_MEMBER => {
                if !nom_membre_valide(l.chaine()?) {
                    return Err(MAL_FORMEE);
                }
                membre = true;
            }
            CHAMP_ERROR_NAME => {
                let n = l.chaine()?;
                if !nom_point_valide(n, false, false) {
                    return Err(MAL_FORMEE);
                }
                m.nom_erreur = Some(n);
            }
            CHAMP_REPLY_SERIAL => {
                let s = l.u32()?;
                if s == 0 {
                    return Err(MAL_FORMEE);
                }
                m.reponse_a = Some(s);
            }
            CHAMP_DESTINATION => {
                l.chaine()?;
            }
            CHAMP_SENDER => m.emetteur = Some(l.chaine()?),
            CHAMP_SIGNATURE => m.signature = l.signature()?,
            _ => {
                // UNIX_FDS: aucun descripteur n'a ete negocie.
                l.u32()?;
                return Err(DESCRIPTEUR);
            }
        }
    }
    if l.pos != fin_champs {
        return Err(MAL_FORMEE);
    }
    // Le remplissage entre les champs et le corps.
    if flux[fin_champs..debut_corps].iter().any(|&o| o != 0) {
        return Err(MAL_FORMEE);
    }
    if m.signature.is_empty() && longueur_corps != 0 {
        return Err(MAL_FORMEE);
    }
    let complet = match genre {
        METHOD_CALL => chemin && membre,
        METHOD_RETURN => m.reponse_a.is_some(),
        ERROR => m.reponse_a.is_some() && m.nom_erreur.is_some(),
        SIGNAL => chemin && membre && interface,
        _ => true,
    };
    if !complet {
        return Err(MAL_FORMEE);
    }
    Ok(Some(m))
}

/// `a(iiayqs)` si `avec_index`, `a(iayqs)` sinon (index lu a 0).
fn lire_serveurs(l: &mut Lecteur<'_>, avec_index: bool) -> Result<Vec<Serveur>, &'static str> {
    let fin = l.tableau(8)?;
    let mut v = Vec::new();
    while l.pos < fin {
        if v.len() >= MAX_ELEMENTS {
            return Err(HORS_BORNE);
        }
        l.aligner(8)?;
        let index = if avec_index { l.u32()? as i32 } else { 0 };
        let famille = l.u32()? as i32;
        let n = l.u32()? as usize;
        let taille = match famille {
            2 => 4,
            10 => 16,
            _ => return Err("famille d'adresse D-Bus inconnue"),
        };
        if n != taille {
            return Err(MAL_FORMEE);
        }
        let adresse = l.prendre(n)?.to_vec();
        let port = l.u16()?;
        let nom = l.chaine()?.to_owned();
        v.push(Serveur {
            index,
            famille,
            adresse,
            port,
            nom,
        });
    }
    if l.pos != fin {
        return Err(MAL_FORMEE);
    }
    Ok(v)
}

fn lire_domaines(l: &mut Lecteur<'_>) -> Result<Vec<Domaine>, &'static str> {
    let fin = l.tableau(8)?;
    let mut v = Vec::new();
    while l.pos < fin {
        if v.len() >= MAX_ELEMENTS {
            return Err(HORS_BORNE);
        }
        l.aligner(8)?;
        let index = l.u32()? as i32;
        let nom = l.chaine()?.to_owned();
        let route_seule = l.booleen()?;
        v.push(Domaine {
            index,
            nom,
            route_seule,
        });
    }
    if l.pos != fin {
        return Err(MAL_FORMEE);
    }
    Ok(v)
}

/// Le corps d'un retour, a la forme attendue et rien d'autre.
fn lire_corps(m: &Message<'_>, forme: Forme, ordre: u8) -> Result<Valeur, &'static str> {
    if m.signature != forme.signature() {
        return Err(SIGNATURE);
    }
    let mut l = Lecteur {
        ordre,
        b: m.corps,
        pos: 0,
    };
    let valeur = match forme {
        Forme::Chaine => Valeur::Chaine(l.chaine()?.to_owned()),
        Forme::Entier32NonSigne => Valeur::Entier32NonSigne(l.u32()?),
        Forme::Chemin => Valeur::Chemin(l.chemin()?.to_owned()),
        Forme::ListeDeDelegues => {
            let fin = l.tableau(8)?;
            let presents = fin > l.pos;
            // Les elements ne sont pas lus: seule leur presence compte, et
            // elle rend la collecte non mesuree.
            l.pos = fin;
            Valeur::Delegues(presents)
        }
        Forme::Variante(p) => {
            if l.signature()? != p.signature() {
                return Err(SIGNATURE);
            }
            match p {
                Propriete::Serveurs => Valeur::Serveurs(lire_serveurs(&mut l, true)?),
                Propriete::ServeursDuLien => Valeur::ServeursDuLien(lire_serveurs(&mut l, false)?),
                Propriete::Domaines => Valeur::Domaines(lire_domaines(&mut l)?),
                Propriete::Chaine => Valeur::Chaine(l.chaine()?.to_owned()),
                Propriete::Booleen => Valeur::Booleen(l.booleen()?),
                Propriete::Entier64 => Valeur::Entier64(l.u64()?),
            }
        }
    };
    if l.pos != m.corps.len() {
        return Err(MAL_FORMEE);
    }
    Ok(valeur)
}

/// Lit, dans ce que le serveur a envoye depuis la fin de l'authentification
/// (ou depuis la reponse precedente), la reponse a l'appel attendu.
///
/// Rend `Ok(None)` tant qu'elle n'est pas complete, et `Ok(Some((issue, n)))`
/// une fois lue, `n` etant le nombre d'octets consommes, signaux sautes
/// compris. Un retour ou une erreur qui repond a un autre appel, ou qui vient
/// d'un autre emetteur, est refuse; un appel recu aussi.
pub fn lire_reponse(
    flux: &[u8],
    attente: &Attente<'_>,
) -> Result<Option<(Issue, usize)>, &'static str> {
    let mut debut = 0;
    loop {
        let Some(m) = message(&flux[debut..], attente.ordre)? else {
            return Ok(None);
        };
        debut += m.total;
        match m.genre {
            METHOD_RETURN | ERROR => {
                // Le bus repond lui-meme, par une erreur et jamais par une
                // valeur, a un appel qu'il refuse de transmettre.
                let refus = m.genre == ERROR && m.emetteur == Some(BUS) && attente.emetteur != BUS;
                if m.reponse_a != Some(attente.serie)
                    || !(refus || m.emetteur == Some(attente.emetteur))
                {
                    return Err(INATTENDUE);
                }
                let issue = match m.nom_erreur {
                    Some(nom) if refus => Issue::RefusDuBus(nom.to_owned()),
                    Some(nom) if m.genre == ERROR => Issue::Erreur(nom.to_owned()),
                    _ => Issue::Retour(lire_corps(&m, attente.forme, attente.ordre)?),
                };
                return Ok(Some((issue, debut)));
            }
            METHOD_CALL => return Err("appel D-Bus recu d'un pair"),
            // Signal, ou type inconnu: saute en entier.
            _ => {}
        }
    }
}

// ---------------------------------------------------------------------------
// Ecriture d'une reponse: pour les recettes et le harnais de fuzzing, qui
// fabriquent ce qu'un serveur enverrait. La preuve n'en ecrit jamais.
// ---------------------------------------------------------------------------

/// Le message de retour (`erreur` absente) ou d'erreur qui repond a `serie`,
/// emis par `emetteur`, portant `valeur` sous la forme donnee. Ne sert qu'a
/// fabriquer des trames: une forme qui ne va pas avec la valeur rend un corps
/// vide sous la signature de la forme.
pub fn encoder_reponse(
    serie_message: u32,
    serie: u32,
    emetteur: &str,
    erreur: Option<&str>,
    valeur: Option<(Forme, &Valeur)>,
    ordre: u8,
) -> Vec<u8> {
    let genre = if erreur.is_some() {
        ERROR
    } else {
        METHOD_RETURN
    };
    let mut e = Ecrivain {
        ordre,
        v: vec![ordre, genre, 0, 1],
    };
    e.u32(0);
    e.u32(serie_message);
    e.u32(0);
    let debut_champs = e.v.len();
    e.aligner(8);
    e.v.push(CHAMP_REPLY_SERIAL);
    e.signature("u");
    e.u32(serie);
    e.champ(CHAMP_SENDER, "s", emetteur);
    if let Some(nom) = erreur {
        e.champ(CHAMP_ERROR_NAME, "s", nom);
    }
    let signature = valeur.map_or("", |(forme, _)| forme.signature());
    if !signature.is_empty() {
        e.champ(CHAMP_SIGNATURE, "g", signature);
    }
    let longueur_champs = (e.v.len() - debut_champs) as u32;
    e.aligner(8);
    let debut_corps = e.v.len();
    match valeur {
        None => {}
        Some((Forme::Variante(_), v)) => encoder_variante(&mut e, v),
        Some((_, Valeur::Chaine(s) | Valeur::Chemin(s))) => e.chaine(s),
        Some((_, Valeur::Entier32NonSigne(x))) => e.u32(*x),
        Some((_, Valeur::Delegues(presents))) => {
            if *presents {
                let a = e.v.len();
                e.u32(0);
                e.aligner(8);
                let debut = e.v.len();
                e.chaine("delegue");
                e.chaine("/");
                let n = (e.v.len() - debut) as u32;
                let o = if ordre == b'l' {
                    n.to_le_bytes()
                } else {
                    n.to_be_bytes()
                };
                e.v[a..a + 4].copy_from_slice(&o);
            } else {
                e.u32(0);
                e.aligner(8);
            }
        }
        // Une forme qui ne va pas avec la valeur: corps vide.
        Some(_) => {}
    }
    let longueur_corps = (e.v.len() - debut_corps) as u32;
    for (a, x) in [(4, longueur_corps), (12, longueur_champs)] {
        let o = if ordre == b'l' {
            x.to_le_bytes()
        } else {
            x.to_be_bytes()
        };
        e.v[a..a + 4].copy_from_slice(&o);
    }
    e.v
}

fn encoder_variante(e: &mut Ecrivain, v: &Valeur) {
    let tableau = |e: &mut Ecrivain, ecrire: &dyn Fn(&mut Ecrivain)| {
        let a = {
            e.aligner(4);
            e.v.len()
        };
        e.u32(0);
        e.aligner(8);
        let debut = e.v.len();
        ecrire(e);
        let n = (e.v.len() - debut) as u32;
        let o = if e.ordre == b'l' {
            n.to_le_bytes()
        } else {
            n.to_be_bytes()
        };
        e.v[a..a + 4].copy_from_slice(&o);
    };
    match v {
        Valeur::Serveurs(s) | Valeur::ServeursDuLien(s) => {
            let avec_index = matches!(v, Valeur::Serveurs(_));
            e.signature(if avec_index { "a(iiayqs)" } else { "a(iayqs)" });
            tableau(e, &|e| {
                for x in s {
                    e.aligner(8);
                    if avec_index {
                        e.u32(x.index as u32);
                    }
                    e.u32(x.famille as u32);
                    e.u32(x.adresse.len() as u32);
                    e.v.extend_from_slice(&x.adresse);
                    e.aligner(2);
                    let p = if e.ordre == b'l' {
                        x.port.to_le_bytes()
                    } else {
                        x.port.to_be_bytes()
                    };
                    e.v.extend_from_slice(&p);
                    e.chaine(&x.nom);
                }
            });
        }
        Valeur::Domaines(d) => {
            e.signature("a(isb)");
            tableau(e, &|e| {
                for x in d {
                    e.aligner(8);
                    e.u32(x.index as u32);
                    e.chaine(&x.nom);
                    e.u32(u32::from(x.route_seule));
                }
            });
        }
        Valeur::Chaine(s) => {
            e.signature("s");
            e.chaine(s);
        }
        Valeur::Booleen(b) => {
            e.signature("b");
            e.u32(u32::from(*b));
        }
        Valeur::Entier64(x) => {
            e.signature("t");
            e.aligner(8);
            let o = if e.ordre == b'l' {
                x.to_le_bytes()
            } else {
                x.to_be_bytes()
            };
            e.v.extend_from_slice(&o);
        }
        Valeur::Entier32NonSigne(_) | Valeur::Chemin(_) | Valeur::Delegues(_) => {}
    }
}
