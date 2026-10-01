//! La declaration du daemon, lue pour une preuve: le lecteur COMMUN a
//! `prove nft --politique-daemon` et `prove wfp --politique-daemon`.
//!
//! La declaration est ce que le daemon DIT avoir remis a son moteur: un
//! attendu, jamais une observation. Ce lecteur ne lui fait donc aucune
//! confiance de forme: cles exactes, doublons refuses, nombres entiers,
//! coherence entre l'issue, le numero et la politique. Tout ce qui ne passe
//! pas rend NON MESURE avec une raison, jamais une comparaison partielle.
//!
//! Tout ce que les deux preuves ont en commun vit ici, et nulle part ailleurs:
//! - la lecture ([`lire`]): l'identite du serveur exigee AVANT le premier
//!   octet ([`EXIGENCE_PREUVE`]), la requete, un echange borne
//!   dans le temps, l'analyse stricte;
//! - le protocole ([`encadrer`]): la declaration lue (N1), la mesure propre a
//!   chaque preuve, la declaration relue (N2), et ce que le rapport en dit
//!   (`failed_input`, `daemon_identity`);
//! - l'identite telle que le rapport la dit ([`IdentiteDaemon`]).
//!
//! Une copie par preuve deriverait. La premiere forme de `prove wfp` en avait
//! une, et elle n'avait pas l'exigence d'identite que `prove nft` venait de
//! recevoir: un processus quelconque aurait pu y servir une declaration
//! taillee pour un moteur altere.

// Sous Linux la preuve WFP s'arrete avant toute lecture et sous Windows la
// preuve nft par declaration n'existe pas: chacune n'appelle qu'une moitie
// des chemins. Hors de ces deux systemes, aucune ne lit.
#![cfg_attr(not(any(target_os = "linux", windows)), allow(dead_code))]

use std::io::ErrorKind;
use std::time::Duration;

use bifrost_ipc::protocol::{
    Command, DECLARATION_PARE_FEU_VERSION, DeclarationPareFeu, IssueApplication, Request, Response,
};
use bifrost_ipc::{IpcClient, IpcError, ServerIdentityError, ServerRequirement};
use serde::Serialize;
use serde_json::Value;

use crate::preuve_nft::Unique;

/// Borne de l'echange complet. Le daemon sert la declaration sur le fil qui
/// applique les politiques: il peut etre occupe a monter un tunnel, mais une
/// preuve qui attendrait sans fin ne rendrait jamais son NON MESURE.
const DELAI: Duration = Duration::from_secs(5);

/// Pourquoi la declaration n'a pas pu servir d'attendu, et quelle entree
/// manque: le rapport distingue un serveur dont l'identite n'est pas admise
/// (`daemon-identity`) d'une declaration absente ou illisible
/// (`daemon-declaration`). Les raisons ne nomment ni uid, ni pid, ni SID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refus {
    Identite(&'static str),
    Declaration(&'static str),
}

impl Refus {
    pub(crate) fn entree(self) -> &'static str {
        match self {
            Refus::Identite(_) => "daemon-identity",
            Refus::Declaration(_) => "daemon-declaration",
        }
    }

    pub(crate) fn raison(self) -> &'static str {
        match self {
            Refus::Identite(r) | Refus::Declaration(r) => r,
        }
    }
}

/// La declaration du pare-feu, et le nom de la regle qui a admis son serveur.
pub(crate) type Lue = (DeclarationPareFeu, &'static str);

/// La declaration du routage Linux, et le nom de la regle qui a admis son
/// serveur (voir `preuve_routes`).
#[cfg(target_os = "linux")]
pub(crate) type LueRoutage = (bifrost_ipc::protocol::DeclarationRoutage, &'static str);

/// La declaration du routage Windows, et le nom de la regle qui a admis son
/// serveur (voir `preuve_routes_windows`).
pub(crate) type LueRoutageWindows = (
    bifrost_ipc::protocol::DeclarationRoutageWindows,
    &'static str,
);

pub(crate) const CLES: [&str; 7] = [
    "result",
    "schema_version",
    "instance",
    "application",
    "moteur",
    "issue",
    "politique",
];

pub(crate) const HORS_SCHEMA: &str = "declaration du daemon hors schema";

/// L'exigence d'identite des lectures de preuve, une seule pour les trois
/// lecteurs (pare-feu, routage Linux, routage Windows): sous Windows, le pipe
/// de LocalSystem et lui seul, jamais celui des Administrateurs, que la regle
/// des commandes admet. Gardee par deux recettes: la decision de `bifrost_ipc`
/// appliquee a cette constante, et une regle de forme sur ce source.
pub(crate) const EXIGENCE_PREUVE: ServerRequirement = ServerRequirement::Privileged;

/// La lecture des preuves: le serveur doit etre PRIVILEGIE, toujours.
///
/// `--socket` est choisi par l'utilisateur, et n'importe quel processus peut
/// ecouter sur un chemin qu'il cree: sans cette exigence, il servirait une
/// declaration taillee pour un noyau ou un moteur altere, et la preuve dirait
/// MATCH. Sous Linux le daemon tourne en root sans exception
/// (`ensure_privileged` avant l'ecoute, aucun `User=` dans l'unite livree);
/// sous Windows, la regle des preuves n'admet que le pipe de LocalSystem, celle
/// du service. La regle vit dans `bifrost_ipc`; les deux preuves la reprennent
/// ici, sans la changer.
pub(crate) async fn lire(socket: &str) -> Result<Lue, Refus> {
    lire_avec(socket, DELAI, EXIGENCE_PREUVE).await
}

pub(crate) async fn lire_avec(
    socket: &str,
    delai: Duration,
    attendu: ServerRequirement,
) -> Result<Lue, Refus> {
    let (octets, regle) =
        connecter_et_demander(socket, delai, attendu, Command::DeclarationPareFeu).await?;
    Ok((analyser(&octets).map_err(Refus::Declaration)?, regle))
}

/// La lecture de production de `prove routes --politique-daemon`: meme exigence
/// d'identite, meme echange borne, meme analyse stricte que le pare-feu, mais la
/// commande et la forme de la reponse sont celles du routage.
#[cfg(target_os = "linux")]
pub(crate) async fn lire_routage(socket: &str) -> Result<LueRoutage, Refus> {
    lire_routage_avec(socket, DELAI, EXIGENCE_PREUVE).await
}

#[cfg(target_os = "linux")]
pub(crate) async fn lire_routage_avec(
    socket: &str,
    delai: Duration,
    attendu: ServerRequirement,
) -> Result<LueRoutage, Refus> {
    let (octets, regle) =
        connecter_et_demander(socket, delai, attendu, Command::DeclarationRoutage).await?;
    Ok((
        analyser_routage(&octets).map_err(Refus::Declaration)?,
        regle,
    ))
}

/// La lecture de production de `prove routes --politique-daemon` sous Windows:
/// la meme commande, le meme tronc commun (identite du serveur exigee avant le
/// premier octet, echange borne), et l'analyse stricte de la forme Windows.
#[cfg(windows)]
pub(crate) async fn lire_routage_windows(socket: &str) -> Result<LueRoutageWindows, Refus> {
    lire_routage_windows_avec(socket, DELAI, EXIGENCE_PREUVE).await
}

#[cfg(windows)]
pub(crate) async fn lire_routage_windows_avec(
    socket: &str,
    delai: Duration,
    attendu: ServerRequirement,
) -> Result<LueRoutageWindows, Refus> {
    let (octets, regle) =
        connecter_et_demander(socket, delai, attendu, Command::DeclarationRoutage).await?;
    Ok((
        analyser_routage_windows(&octets).map_err(Refus::Declaration)?,
        regle,
    ))
}

/// Le tronc commun aux deux lectures: l'identite du serveur exigee AVANT le
/// premier octet, la requete, un echange borne dans le temps. Une SEULE copie
/// de cette logique: la commande et l'analyse de la reponse sont propres a
/// chaque preuve, l'identite et l'echange ne le sont pas.
///
/// `--socket` est choisi par l'utilisateur, et n'importe quel processus peut
/// ecouter sur un chemin qu'il cree: sans cette exigence, il servirait une
/// declaration taillee pour un noyau ou un moteur altere, et la preuve dirait
/// MATCH. Sous Linux le daemon tourne en root sans exception; sous Windows, la
/// regle des preuves n'admet que le pipe de LocalSystem. La regle vit dans
/// `bifrost_ipc`; les deux lectures la reprennent ici, sans la changer.
async fn connecter_et_demander(
    socket: &str,
    delai: Duration,
    attendu: ServerRequirement,
    commande: Command,
) -> Result<(Vec<u8>, &'static str), Refus> {
    let echange = async {
        let (mut client, regle) =
            IpcClient::connect_verified(socket, attendu)
                .await
                .map_err(|e| match e {
                    IpcError::ServerIdentity(ServerIdentityError::Refused) => {
                        Refus::Identite("serveur de la declaration non privilegie")
                    }
                    IpcError::ServerIdentity(ServerIdentityError::Unreadable) => {
                        Refus::Identite("identite du serveur de la declaration illisible")
                    }
                    // Le socket existe et ses droits nous ecartent: ce n'est pas une
                    // absence de daemon, et le rapport ne doit pas le laisser croire.
                    IpcError::Io(e) if e.kind() == ErrorKind::PermissionDenied => {
                        Refus::Declaration("acces au daemon refuse")
                    }
                    _ => Refus::Declaration("daemon injoignable"),
                })?;
        let octets = client
            .request_raw(&Request::new(commande))
            .await
            .map_err(|_| Refus::Declaration("reponse du daemon tronquee ou illisible"))?;
        Ok((octets, regle.name()))
    };
    tokio::time::timeout(delai, echange)
        .await
        .map_err(|_| Refus::Declaration("daemon sans reponse dans le delai"))?
}

/// Analyse une trame de reponse, sans jamais recopier ce qu'elle contient
/// dans une raison: un message d'erreur du daemon nomme l'appelant (uid, gid,
/// pid, SID), et une declaration porte des parametres de politique.
pub fn analyser(octets: &[u8]) -> Result<DeclarationPareFeu, &'static str> {
    let Unique(v) =
        serde_json::from_slice(octets).map_err(|_| "reponse du daemon tronquee ou illisible")?;
    let objet = v.as_object().ok_or(HORS_SCHEMA)?;
    erreur_declaree(objet)?;
    if objet.len() != CLES.len() || CLES.iter().any(|c| !objet.contains_key(*c)) {
        return Err(HORS_SCHEMA);
    }
    let d = match serde_json::from_value::<Response>(v) {
        Ok(Response::DeclarationPareFeu(d)) => *d,
        _ => return Err(HORS_SCHEMA),
    };
    let instance_valide = (32..=128).contains(&d.instance.len())
        && d.instance
            .bytes()
            .all(|o| o.is_ascii_digit() || (b'a'..=b'f').contains(&o));
    let coherente = match d.issue {
        IssueApplication::Aucune => d.application == 0 && d.politique.is_none(),
        IssueApplication::Posee => {
            d.application > 0 && d.politique.as_ref().is_some_and(Value::is_object)
        }
        IssueApplication::Retiree | IssueApplication::Echec => {
            d.application > 0 && d.politique.is_none()
        }
    };
    if d.schema_version != DECLARATION_PARE_FEU_VERSION
        || !instance_valide
        || d.moteur.is_empty()
        || !coherente
    {
        return Err(HORS_SCHEMA);
    }
    Ok(d)
}

/// La branche d'erreur, commune aux deux analyses: le serveur refuse un pair
/// non autorise AVANT de lire sa requete, et le dit par ce prefixe
/// (`bifrost_ipc::auth::AuthError::Denied`). Toute autre erreur, dont celle d'un
/// daemon d'une version qui ne connait pas la commande, est un refus de la
/// demande, pas un refus d'acces.
fn erreur_declaree(objet: &serde_json::Map<String, Value>) -> Result<(), &'static str> {
    if objet.get("result").and_then(Value::as_str) == Some("error") {
        let message = objet
            .get("message")
            .and_then(Value::as_str)
            .ok_or(HORS_SCHEMA)?;
        return Err(if message.starts_with("acces refuse") {
            "acces au daemon refuse"
        } else {
            "le daemon a refuse la demande"
        });
    }
    Ok(())
}

/// Les cles de la reponse `declaration-routage`, tag `result` compris; ce sont
/// aussi celles de `declaration-routage-windows`.
pub(crate) const CLES_ROUTAGE: [&str; 6] = [
    "result",
    "schema_version",
    "instance",
    "application",
    "issue",
    "plan",
];

/// Les cles du sous-objet `plan`, quand il est present.
#[cfg(target_os = "linux")]
pub(crate) const PLAN_CLES: [&str; 5] = ["chemin", "interface", "fwmark", "table", "coeur_uid"];

/// Analyse une trame de reponse `declaration-routage`, aussi strictement que
/// [`analyser`]: cles exactes au niveau superieur ET dans le sous-objet `plan`,
/// doublons refuses (par [`Unique`], en profondeur), entiers, version, et
/// coherence entre l'etat, le numero et le plan. Rien de ce qu'elle contient
/// n'entre dans une raison.
#[cfg(target_os = "linux")]
pub fn analyser_routage(
    octets: &[u8],
) -> Result<bifrost_ipc::protocol::DeclarationRoutage, &'static str> {
    use bifrost_ipc::protocol::{CheminRoutage, DECLARATION_ROUTAGE_VERSION, EtatRoutage};
    let Unique(v) =
        serde_json::from_slice(octets).map_err(|_| "reponse du daemon tronquee ou illisible")?;
    let objet = v.as_object().ok_or(HORS_SCHEMA)?;
    erreur_declaree(objet)?;
    if objet.len() != CLES_ROUTAGE.len() || CLES_ROUTAGE.iter().any(|c| !objet.contains_key(*c)) {
        return Err(HORS_SCHEMA);
    }
    // Les cles du sous-objet `plan` sont verifiees sur la valeur BRUTE: serde
    // ignorerait une cle inconnue en le deserialisant, ce qui elargirait le
    // schema en silence.
    if let Some(plan) = objet.get("plan").filter(|p| !p.is_null()) {
        let po = plan.as_object().ok_or(HORS_SCHEMA)?;
        if po.len() != PLAN_CLES.len() || PLAN_CLES.iter().any(|c| !po.contains_key(*c)) {
            return Err(HORS_SCHEMA);
        }
    }
    let d = match serde_json::from_value::<Response>(v) {
        Ok(Response::DeclarationRoutage(d)) => *d,
        _ => return Err(HORS_SCHEMA),
    };
    let instance_valide = (32..=128).contains(&d.instance.len())
        && d.instance
            .bytes()
            .all(|o| o.is_ascii_digit() || (b'a'..=b'f').contains(&o));
    let coherente = match d.issue {
        EtatRoutage::NonApplicable | EtatRoutage::Aucun => d.plan.is_none(),
        EtatRoutage::Pose => d.application > 0 && d.plan.is_some(),
    };
    // Le plan, present, doit s'accorder a son chemin: WireGuard a une marque et
    // une table, pas de compte; le coeur a un compte ou rien, ni marque ni
    // table (la sienne est fixee par le produit).
    let plan_coherent = match &d.plan {
        None => true,
        Some(p) => match p.chemin {
            CheminRoutage::Wireguard => {
                p.fwmark.is_some() && p.table.is_some() && p.coeur_uid.is_none()
            }
            CheminRoutage::Coeur => p.fwmark.is_none() && p.table.is_none(),
        },
    };
    if d.schema_version != DECLARATION_ROUTAGE_VERSION
        || !instance_valide
        || !coherente
        || !plan_coherent
    {
        return Err(HORS_SCHEMA);
    }
    Ok(d)
}

/// Les cles du sous-objet `plan` de la forme Windows, quand il est present.
pub(crate) const PLAN_WINDOWS_CLES: [&str; 5] =
    ["chemin", "interface", "mtu", "familles", "destinations"];

/// Analyse une trame de reponse `declaration-routage-windows`, aussi
/// strictement que [`analyser_routage`]: cles exactes au niveau superieur ET
/// dans `plan`, doublons refuses en profondeur, entiers, version, coherence
/// entre l'etat, le numero et le plan, et entre le chemin et les destinations
/// (WireGuard en a au moins une, le coeur aucune). Chaque destination est
/// ecrite sous sa forme canonique, celle que le daemon rend: une autre
/// graphie du meme prefixe vient d'un autre producteur. Le contenu du plan
/// (interface, MTU, familles, masquage) est juge ensuite, par le meme lecteur
/// que l'intention. Rien de ce que la trame contient n'entre dans une raison.
///
/// Compilee partout, pour que ses recettes comptent sur les deux hotes; seule
/// la preuve Windows l'appelle.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn analyser_routage_windows(
    octets: &[u8],
) -> Result<bifrost_ipc::protocol::DeclarationRoutageWindows, &'static str> {
    use bifrost_ipc::protocol::{CheminRoutage, DECLARATION_ROUTAGE_WINDOWS_VERSION, EtatRoutage};
    let Unique(v) =
        serde_json::from_slice(octets).map_err(|_| "reponse du daemon tronquee ou illisible")?;
    let objet = v.as_object().ok_or(HORS_SCHEMA)?;
    erreur_declaree(objet)?;
    if objet.len() != CLES_ROUTAGE.len() || CLES_ROUTAGE.iter().any(|c| !objet.contains_key(*c)) {
        return Err(HORS_SCHEMA);
    }
    if let Some(plan) = objet.get("plan").filter(|p| !p.is_null()) {
        let po = plan.as_object().ok_or(HORS_SCHEMA)?;
        if po.len() != PLAN_WINDOWS_CLES.len()
            || PLAN_WINDOWS_CLES.iter().any(|c| !po.contains_key(*c))
        {
            return Err(HORS_SCHEMA);
        }
        // La graphie de chaque destination, sur la valeur BRUTE: serde lit
        // `10.1.2.3/8` ou `2001:0db8::/32` sans rien dire.
        if let Some(liste) = po.get("destinations").and_then(Value::as_array) {
            for d in liste {
                let texte = d.as_str().ok_or(HORS_SCHEMA)?;
                let lu: bifrost_core::config::IpNet = texte.parse().map_err(|_| HORS_SCHEMA)?;
                if lu.to_string() != texte {
                    return Err(HORS_SCHEMA);
                }
            }
        }
    }
    let d = match serde_json::from_value::<Response>(v) {
        Ok(Response::DeclarationRoutageWindows(d)) => *d,
        _ => return Err(HORS_SCHEMA),
    };
    let instance_valide = (32..=128).contains(&d.instance.len())
        && d.instance
            .bytes()
            .all(|o| o.is_ascii_digit() || (b'a'..=b'f').contains(&o));
    let coherente = match d.issue {
        EtatRoutage::NonApplicable | EtatRoutage::Aucun => d.plan.is_none(),
        EtatRoutage::Pose => d.application > 0 && d.plan.is_some(),
    };
    let plan_coherent = match &d.plan {
        None => true,
        Some(p) => match p.chemin {
            CheminRoutage::Wireguard => p.destinations.as_ref().is_some_and(|l| !l.is_empty()),
            CheminRoutage::Coeur => p.destinations.is_none(),
        },
    };
    if d.schema_version != DECLARATION_ROUTAGE_WINDOWS_VERSION
        || !instance_valide
        || !coherente
        || !plan_coherent
    {
        return Err(HORS_SCHEMA);
    }
    Ok(d)
}

/// Le moteur qu'une preuve sait comparer, et ce qu'elle dit des autres cas.
pub(crate) struct Perimetre {
    /// Le `KillSwitch::backend` dont la preuve lit la projection.
    pub(crate) moteur: &'static str,
    /// La raison quand le daemon declare un autre moteur: sa projection ne
    /// decrit pas ce que la reference sait rendre, et une correspondance
    /// serait fortuite.
    pub(crate) autre_moteur: &'static str,
    /// La raison quand la derniere application du daemon a echoue.
    pub(crate) echec: &'static str,
}

/// La politique a comparer, ou la raison pour laquelle il n'y en a pas.
pub(crate) fn politique_posee<'a>(
    d: &'a DeclarationPareFeu,
    perimetre: &Perimetre,
) -> Result<&'a Value, &'static str> {
    if d.moteur != perimetre.moteur {
        return Err(perimetre.autre_moteur);
    }
    match d.issue {
        IssueApplication::Aucune => {
            Err("aucune politique posee par ce daemon depuis son demarrage")
        }
        IssueApplication::Retiree => {
            Err("kill switch retire par le daemon: aucune politique a comparer")
        }
        IssueApplication::Echec => Err(perimetre.echec),
        IssueApplication::Posee => d.politique.as_ref().ok_or(HORS_SCHEMA),
    }
}

/// L'identite du serveur de la declaration, telle que le rapport la dit.
///
/// Absente du rapport hors de la preuve par declaration: une comparaison de
/// fichiers n'a pas de serveur. Dans cette preuve, `null` tant qu'elle n'est
/// pas etablie, puis le NOM de la regle qui l'a admise; jamais une valeur.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IdentiteDaemon {
    HorsPerimetre,
    NonVerifiee,
    Verifiee(&'static str),
}

impl IdentiteDaemon {
    pub(crate) fn hors_perimetre(&self) -> bool {
        *self == IdentiteDaemon::HorsPerimetre
    }

    /// La ligne du rapport texte, vide hors de la preuve par declaration.
    pub(crate) fn ligne(&self) -> String {
        match self {
            IdentiteDaemon::HorsPerimetre => String::new(),
            IdentiteDaemon::NonVerifiee => "identite du daemon: non verifiee\n".to_owned(),
            IdentiteDaemon::Verifiee(regle) => format!("identite du daemon: {regle}\n"),
        }
    }
}

impl Serialize for IdentiteDaemon {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            IdentiteDaemon::Verifiee(regle) => s.serialize_str(regle),
            _ => s.serialize_none(),
        }
    }
}

/// Ce que le protocole ecrit dans le rapport d'une preuve: l'entree qui manque
/// et l'identite du serveur. Chaque preuve a son rapport; aucune n'ecrit ces
/// deux champs elle-meme autour des lectures.
pub(crate) trait Suivi {
    fn entree_manquante(&mut self, entree: &'static str);
    fn identite(&mut self, identite: IdentiteDaemon);
}

/// Le protocole des preuves par declaration: N1, la mesure, N2.
///
/// Ordre impose. La declaration est lue (N1) et sa politique extraite selon
/// `perimetre`; `mesurer` en tire l'attendu et collecte l'observe, dans un
/// instantane coherent (deux GETGEN pour nft, une transaction en lecture
/// seule pour WFP); la declaration est relue (N2). N1 et N2 doivent etre
/// IDENTIQUES en entier (instance, numero, issue, politique): une application
/// glissee entre les deux, meme vers la meme politique, rend l'instantane non
/// attribuable. Rien de la declaration n'entre dans le rapport, hors la
/// version de schema que la mesure y met.
///
/// Chaque lecture exige l'identite du serveur AVANT de lui ecrire (voir
/// [`lire`]). Le rapport en garde le NOM de la regle, et `failed_input =
/// daemon-identity` quand c'est elle qui manque, a N1 comme a N2: une
/// declaration dont le second serveur n'est pas admis n'est pas attribuable
/// non plus, et le rapport ne garde pas alors la regle de N1.
///
/// Rendu `Ok`, le rapport attend sa comparaison: `failed_input` vaut
/// `observed` jusqu'a ce que la preuve l'ait faite.
/// Generique sur la declaration `D` (comparee en entier pour N1 == N2) et sur
/// l'attendu `X` que `extraire` en tire: pour `prove nft`/`prove wfp`, `D` est
/// [`DeclarationPareFeu`] et `X` la politique (`&Value`, via
/// [`politique_posee`]); pour `prove routes`, `D` est `DeclarationRoutage` et
/// `X` le plan reconstruit. Une seule implementation du protocole.
pub(crate) async fn encadrer<R, D, L, FL, X, EX, M, T>(
    r: &mut R,
    mut lire: L,
    extraire: EX,
    mesurer: M,
) -> Result<T, &'static str>
where
    R: Suivi,
    D: PartialEq,
    L: FnMut() -> FL,
    FL: std::future::Future<Output = Result<(D, &'static str), Refus>>,
    EX: FnOnce(&D) -> Result<X, &'static str>,
    M: AsyncFnOnce(&mut R, X) -> Result<T, &'static str>,
{
    let (premiere, regle) = lire().await.map_err(|refus| {
        r.entree_manquante(refus.entree());
        refus.raison()
    })?;
    r.identite(IdentiteDaemon::Verifiee(regle));
    let attendu = extraire(&premiere)?;
    let mesure = mesurer(r, attendu).await?;
    r.entree_manquante("daemon-declaration");
    let (seconde, _) = lire().await.map_err(|refus| match refus {
        Refus::Identite(raison) => {
            r.entree_manquante(refus.entree());
            r.identite(IdentiteDaemon::NonVerifiee);
            raison
        }
        Refus::Declaration(_) => "declaration du daemon illisible ou injoignable apres la collecte",
    })?;
    if seconde != premiere {
        return Err("declaration du daemon modifiee pendant la collecte");
    }
    r.entree_manquante("observed");
    Ok(mesure)
}

#[cfg(test)]
mod tests {
    use super::*;

    const INSTANCE: &str = "0123456789abcdef0123456789abcdef0123456789abcdef";

    #[derive(Default)]
    struct Journal {
        entree: Option<&'static str>,
        identite: Option<IdentiteDaemon>,
        mesures: usize,
    }

    impl Suivi for Journal {
        fn entree_manquante(&mut self, entree: &'static str) {
            self.entree = Some(entree);
        }
        fn identite(&mut self, identite: IdentiteDaemon) {
            self.identite = Some(identite);
        }
    }

    const PERIMETRE: Perimetre = Perimetre {
        moteur: "moteur-de-recette",
        autre_moteur: "autre moteur",
        echec: "echec",
    };

    fn declaree(application: u64) -> DeclarationPareFeu {
        DeclarationPareFeu {
            schema_version: DECLARATION_PARE_FEU_VERSION,
            instance: INSTANCE.into(),
            application,
            moteur: PERIMETRE.moteur.into(),
            issue: IssueApplication::Posee,
            politique: Some(serde_json::json!({ "champ": application })),
        }
    }

    /// Joue le protocole sur une suite de lectures (N1 puis N2), avec une
    /// mesure qui compte ses appels et rend la politique qu'on lui a remise.
    async fn jouer(lectures: Vec<Result<Lue, Refus>>) -> (Journal, Result<Value, &'static str>) {
        let mut lectures = lectures.into_iter();
        let mut j = Journal::default();
        let issue = encadrer(
            &mut j,
            || std::future::ready(lectures.next().expect("lecture de trop")),
            |d: &DeclarationPareFeu| politique_posee(d, &PERIMETRE).cloned(),
            async |j: &mut Journal, politique: Value| {
                j.mesures += 1;
                Ok(politique)
            },
        )
        .await;
        (j, issue)
    }

    /// Le chemin nominal: la regle de N1 reste, la mesure a lieu une fois,
    /// et le rapport attend sa comparaison.
    #[tokio::test]
    async fn deux_lectures_identiques_encadrent_une_seule_mesure() {
        let (j, issue) = jouer(vec![
            Ok((declaree(4), "regle-de-recette")),
            Ok((declaree(4), "regle-de-recette")),
        ])
        .await;
        assert_eq!(issue, Ok(serde_json::json!({ "champ": 4 })));
        assert_eq!(j.mesures, 1);
        assert_eq!(
            j.identite,
            Some(IdentiteDaemon::Verifiee("regle-de-recette"))
        );
        assert_eq!(j.entree, Some("observed"));
    }

    /// Un serveur refuse a N1: rien n'est mesure, l'entree manquante est
    /// l'identite, et aucune regle n'est retenue.
    #[tokio::test]
    async fn une_identite_refusee_a_n1_ne_laisse_rien_mesurer() {
        let refus = Refus::Identite("serveur de la declaration non privilegie");
        let (j, issue) = jouer(vec![Err(refus)]).await;
        assert_eq!(issue, Err(refus.raison()));
        assert_eq!(j.mesures, 0);
        assert_eq!(j.entree, Some("daemon-identity"));
        assert_eq!(j.identite, None);
    }

    /// Un serveur admis a N1 et refuse a N2: la regle de N1 n'est pas gardee.
    #[tokio::test]
    async fn une_identite_refusee_a_n2_efface_la_regle_de_n1() {
        let refus = Refus::Identite("identite du serveur de la declaration illisible");
        let (j, issue) = jouer(vec![Ok((declaree(4), "regle-de-recette")), Err(refus)]).await;
        assert_eq!(issue, Err(refus.raison()));
        assert_eq!(j.mesures, 1);
        assert_eq!(j.entree, Some("daemon-identity"));
        assert_eq!(j.identite, Some(IdentiteDaemon::NonVerifiee));
    }

    /// Une declaration qui a change entre N1 et N2, ou illisible a N2.
    #[tokio::test]
    async fn une_seconde_lecture_differente_ou_illisible_n_est_pas_attribuable() {
        let (j, issue) = jouer(vec![
            Ok((declaree(4), "regle-de-recette")),
            Ok((declaree(5), "regle-de-recette")),
        ])
        .await;
        assert_eq!(
            issue,
            Err("declaration du daemon modifiee pendant la collecte")
        );
        assert_eq!(j.entree, Some("daemon-declaration"));
        let (j, issue) = jouer(vec![
            Ok((declaree(4), "regle-de-recette")),
            Err(Refus::Declaration("daemon injoignable")),
        ])
        .await;
        assert_eq!(
            issue,
            Err("declaration du daemon illisible ou injoignable apres la collecte")
        );
        assert_eq!(j.entree, Some("daemon-declaration"));
        assert_eq!(
            j.identite,
            Some(IdentiteDaemon::Verifiee("regle-de-recette"))
        );
    }

    /// Un autre moteur, ou une issue sans politique: rien n'est mesure, et
    /// chaque raison est celle du perimetre de la preuve.
    #[tokio::test]
    async fn hors_perimetre_rien_n_est_mesure() {
        let mut autre = declaree(4);
        autre.moteur = "autre".into();
        let mut echec = declaree(4);
        echec.issue = IssueApplication::Echec;
        echec.politique = None;
        for (d, raison) in [(autre, "autre moteur"), (echec, "echec")] {
            let (j, issue) = jouer(vec![Ok((d, "regle-de-recette"))]).await;
            assert_eq!(issue, Err(raison));
            assert_eq!(j.mesures, 0);
        }
    }

    /// Le rapport ne dit de l'identite qu'un nom de regle, ou rien.
    #[test]
    fn l_identite_ne_se_dit_que_par_le_nom_de_sa_regle() {
        assert_eq!(
            serde_json::to_value(IdentiteDaemon::Verifiee("windows-system-pipe-owner")).unwrap(),
            "windows-system-pipe-owner"
        );
        assert!(
            serde_json::to_value(IdentiteDaemon::NonVerifiee)
                .unwrap()
                .is_null()
        );
        assert_eq!(IdentiteDaemon::HorsPerimetre.ligne(), "");
        assert_eq!(
            IdentiteDaemon::NonVerifiee.ligne(),
            "identite du daemon: non verifiee\n"
        );
    }

    /// L'exigence des preuves, jugee par la decision de `bifrost_ipc` elle-meme,
    /// celle que le client applique au proprietaire du pipe: LocalSystem admis,
    /// les Administrateurs refuses (la regle des commandes les admet), tout
    /// autre proprietaire refuse. Sans privilege: la decision est pure.
    #[cfg(windows)]
    #[test]
    fn l_exigence_des_preuves_n_admet_que_le_pipe_de_localsystem() {
        use bifrost_ipc::ServerRule;
        use bifrost_ipc::transport::{PipeOwner, decide_pipe_owner};
        assert_eq!(
            decide_pipe_owner(PipeOwner::LocalSystem, EXIGENCE_PREUVE),
            Ok(ServerRule::WindowsSystemPipeOwner)
        );
        assert_eq!(
            decide_pipe_owner(PipeOwner::Administrators, EXIGENCE_PREUVE),
            Err(ServerIdentityError::Refused)
        );
        assert_eq!(
            decide_pipe_owner(PipeOwner::Other, EXIGENCE_PREUVE),
            Err(ServerIdentityError::Refused)
        );
    }

    /// La fin d'un litteral qui commence en `i` (chaine, chaine brute, octet,
    /// caractere), ou `None`. Une duree de vie n'est pas un litteral.
    fn fin_de_litteral(c: &[char], i: usize) -> Option<usize> {
        let a = |k: usize| c.get(k).copied();
        let chaine = |debut: usize| {
            let mut k = debut + 1;
            while k < c.len() {
                match c[k] {
                    '\\' => k += 2,
                    '"' => return Some(k + 1),
                    _ => k += 1,
                }
            }
            Some(c.len())
        };
        let caractere = |debut: usize| {
            if a(debut + 1) == Some('\\') {
                let mut k = debut + 3;
                while k < c.len() && c[k] != '\'' {
                    k += 1;
                }
                Some(k + 1)
            } else if a(debut + 2) == Some('\'') {
                Some(debut + 3)
            } else {
                None
            }
        };
        match (c[i], a(i + 1)) {
            ('"', _) => chaine(i),
            ('b', Some('"')) => chaine(i + 1),
            ('\'', _) => caractere(i),
            ('b', Some('\'')) => caractere(i + 1),
            ('r', _) | ('b', Some('r')) => {
                let mut k = if c[i] == 'r' { i + 1 } else { i + 2 };
                let mut dieses = 0;
                while a(k) == Some('#') {
                    dieses += 1;
                    k += 1;
                }
                if a(k) != Some('"') {
                    return None;
                }
                k += 1;
                while k < c.len() {
                    if c[k] == '"' && (1..=dieses).all(|d| a(k + d) == Some('#')) {
                        return Some(k + 1 + dieses);
                    }
                    k += 1;
                }
                Some(c.len())
            }
            _ => None,
        }
    }

    /// Les jetons d'un source Rust, sans commentaires ni litteraux: ce qu'un
    /// commentaire ou une chaine nomme ne compte pas, ce que le code nomme, si.
    /// `::` est un jeton; chaque autre ponctuation en est un.
    fn jetons(source: &str) -> Vec<String> {
        let c: Vec<char> = source.chars().collect();
        let mot = |x: char| x.is_ascii_alphanumeric() || x == '_';
        let mut j = Vec::new();
        let mut i = 0;
        while i < c.len() {
            let suivant = c.get(i + 1).copied();
            if c[i].is_whitespace() {
                i += 1;
            } else if c[i] == '/' && suivant == Some('/') {
                while i < c.len() && c[i] != '\n' {
                    i += 1;
                }
            } else if c[i] == '/' && suivant == Some('*') {
                let mut profondeur = 0;
                while i < c.len() {
                    if c[i] == '/' && c.get(i + 1) == Some(&'*') {
                        profondeur += 1;
                        i += 2;
                    } else if c[i] == '*' && c.get(i + 1) == Some(&'/') {
                        profondeur -= 1;
                        i += 2;
                        if profondeur == 0 {
                            break;
                        }
                    } else {
                        i += 1;
                    }
                }
            } else if let Some(fin) = fin_de_litteral(&c, i) {
                i = fin;
            } else if mot(c[i]) {
                let debut = i;
                while i < c.len() && mot(c[i]) {
                    i += 1;
                }
                j.push(c[debut..i].iter().collect());
            } else if c[i] == ':' && suivant == Some(':') {
                j.push("::".to_owned());
                i += 2;
            } else {
                j.push(c[i].to_string());
                i += 1;
            }
        }
        j
    }

    /// Les jetons de production: ce qui precede l'unique module de recettes,
    /// qui doit fermer le fichier.
    fn production(source: &str) -> Vec<String> {
        let j = jetons(source);
        let marque = jetons("#[cfg(test)] mod tests {");
        let debuts: Vec<usize> = (0..j.len())
            .filter(|&k| j[k..].starts_with(&marque))
            .collect();
        assert_eq!(debuts.len(), 1, "un seul module de recettes");
        let ouvre = debuts[0] + marque.len() - 1;
        assert_eq!(
            fermeture(&j, ouvre),
            j.len() - 1,
            "du code suit le module de recettes"
        );
        j[..debuts[0]].to_vec()
    }

    /// L'indice de l'accolade qui ferme celle ouverte en `ouvre`.
    fn fermeture(j: &[String], ouvre: usize) -> usize {
        let mut profondeur = 0;
        for (k, t) in j.iter().enumerate().skip(ouvre) {
            match t.as_str() {
                "{" => profondeur += 1,
                "}" => {
                    profondeur -= 1;
                    if profondeur == 0 {
                        return k;
                    }
                }
                _ => {}
            }
        }
        panic!("accolade ouverte en {ouvre} jamais fermee")
    }

    /// Le corps de l'unique `fn nom(`, entre ses accolades.
    fn corps_de(p: &[String], nom: &str) -> Vec<String> {
        let debuts: Vec<usize> = (0..p.len().saturating_sub(2))
            .filter(|&k| p[k] == "fn" && p[k + 1] == nom && p[k + 2] == "(")
            .collect();
        assert_eq!(debuts.len(), 1, "fn {nom}");
        let ouvre = (debuts[0]..p.len())
            .find(|&k| p[k] == "{")
            .expect("un corps");
        p[ouvre + 1..fermeture(p, ouvre)].to_vec()
    }

    /// Les trois lecteurs de preuve passent l'exigence nommee, et le code ne
    /// nomme l'exigence d'identite qu'a sa definition: une regle de forme sur
    /// les jetons de production, commentaires et litteraux retires. Une autre
    /// exigence passee par un lecteur, ecrite en chemin complet, sous un alias
    /// ou par une autre constante, un etage qui remplace l'exigence recue, ou
    /// un client ouvert avec autre chose qu'elle, rougit.
    #[test]
    fn les_trois_lecteurs_passent_l_exigence_nommee() {
        let p = production(include_str!("declaration.rs"));
        let compte = |texte: &str| {
            let motif = jetons(texte);
            (0..p.len()).filter(|&k| p[k..].starts_with(&motif)).count()
        };
        assert_eq!(
            compte("const EXIGENCE_PREUVE: ServerRequirement = ServerRequirement::Privileged;"),
            1,
            "la definition de l'exigence"
        );
        for (lecteur, appel) in [
            ("lire", "lire_avec"),
            ("lire_routage", "lire_routage_avec"),
            ("lire_routage_windows", "lire_routage_windows_avec"),
        ] {
            assert_eq!(
                corps_de(&p, lecteur),
                jetons(&format!("{appel}(socket, DELAI, EXIGENCE_PREUVE).await")),
                "{lecteur}"
            );
        }
        assert_eq!(
            p.iter().filter(|t| *t == "EXIGENCE_PREUVE").count(),
            4,
            "la definition et les trois lecteurs"
        );
        // Le type ne se nomme que dans l'import groupe, la definition et les
        // parametres; sa seule valeur nommee est celle de la definition.
        for k in (1..p.len()).filter(|&k| p[k] == "ServerRequirement") {
            let apres = |d: usize| p.get(k + d).map(String::as_str);
            let admis = match (p[k - 1].as_str(), apres(1)) {
                ("{" | ",", Some("," | "}")) | (":", Some("=" | "," | ")")) => true,
                ("=", Some("::")) => apres(2) == Some("Privileged") && apres(3) == Some(";"),
                _ => false,
            };
            assert!(
                admis,
                "exigence nommee hors de sa place: {:?}",
                &p[k.saturating_sub(4)..(k + 4).min(p.len())]
            );
        }
        // L'exigence recue descend telle quelle jusqu'au client: chaque etage la
        // nomme une fois, pour la transmettre, et aucun ne la remplace.
        for etage in [
            "lire_avec",
            "lire_routage_avec",
            "lire_routage_windows_avec",
            "connecter_et_demander",
        ] {
            assert_eq!(
                corps_de(&p, etage)
                    .iter()
                    .filter(|t| *t == "attendu")
                    .count(),
                1,
                "{etage} transmet l'exigence recue sans la remplacer"
            );
        }
        assert_eq!(
            compte("connecter_et_demander(socket, delai, attendu,"),
            3,
            "les trois lectures transmettent l'exigence recue"
        );
        assert_eq!(compte("connect_verified("), 1, "un seul client");
        assert_eq!(
            compte("connect_verified(socket, attendu)"),
            1,
            "le client recoit l'exigence passee"
        );
    }
}
