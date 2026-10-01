//! Lecture seule des tables IP Helper, pour `prove routes` sous Windows.
//!
//! # Pourquoi ici
//!
//! La preuve vit dans le client, qui interdit `unsafe`; la lecture passe par
//! trois appels de `iphlpapi.dll`. Ce crate est celui du depot que le client
//! emploie deja pour lire un etat Windows par une API du systeme (le moteur
//! WFP, [`super::lecture`]): la lecture des routes s'y range a cote, et rend
//! des donnees pures (`bifrost_core::routage_windows::TableIpHelper`) que la
//! comparaison lit sur les deux hotes.
//!
//! # Ce qui est lu
//!
//! L'alias de l'interface du tunnel, resolu en LUID; puis, pour toutes les
//! interfaces et les deux familles, la table des routes
//! (`GetIpForwardTable2`), celle des lignes d'interface
//! (`GetIpInterfaceTable`) et celle des adresses
//! (`GetUnicastIpAddressTable`). De chaque ligne, seul ce qui entre dans le
//! choix de route est garde: les valeurs d'etat qui changent seules (age d'une
//! route, durees de vie restantes, temps d'accessibilite tire au hasard) sont
//! laissees, pour que deux lectures successives d'un etat stable soient
//! egales. Les entrees sont triees: l'ordre de la table ne decide de rien.
//!
//! # Aucune elevation, aucune ecriture
//!
//! Ces trois tables se lisent sans privilege. Ce module n'appelle aucune
//! fonction qui cree, retire ou change un objet de la pile IP, ni aucune qui
//! emette sur le reseau: il ne nomme de l'espace IP Helper que les trois
//! lectures, la resolution de l'alias et la liberation des tables, et hors de
//! cet espace que les chemins de sa liste (ni le moteur WFP voisin, ni un
//! processus). La recette `la_lecture_n_appelle_rien_qui_ecrive` le verifie
//! sur son propre source, par des listes fermees et non par une liste de mots
//! interdits.
//!
//! # Une lecture n'est pas un instantane
//!
//! IP Helper n'offre ni transaction ni numero de generation: les trois tables
//! sont lues l'une apres l'autre. C'est la preuve qui lit deux fois et exige
//! deux lectures identiques, comme elle le fait de rtnetlink sous Linux.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bifrost_core::config::IpNet;
use bifrost_core::routage::Famille;
use bifrost_core::routage_windows::{AdresseLue, LigneLue, RouteLue, TableIpHelper};
use windows_sys::Win32::Foundation::{ERROR_INVALID_PARAMETER, ERROR_SUCCESS};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceAliasToLuid, FreeMibTable, GetIpForwardTable2, GetIpInterfaceTable,
    GetUnicastIpAddressTable, MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2, MIB_IPINTERFACE_ROW,
    MIB_IPINTERFACE_TABLE, MIB_UNICASTIPADDRESS_ROW, MIB_UNICASTIPADDRESS_TABLE,
};
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_INET};

use super::ffi;

/// Pourquoi il n'y a pas de lecture. Aucun de ces cas n'est une table vide.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refus {
    /// L'alias n'a pas pu etre resolu pour une autre raison que son absence.
    Alias(u32),
    /// La table des routes est refusee, avec son code.
    Routes(u32),
    /// La table des lignes d'interface est refusee, avec son code.
    Interfaces(u32),
    /// La table des adresses est refusee, avec son code.
    Adresses(u32),
    /// Une donnee hors bornes: famille inconnue, longueur de prefixe
    /// aberrante, pointeur nul, table demesuree. Rien de partiel n'est rendu.
    Tronquee,
}

/// Au-dela, une table est tenue pour aberrante plutot que lue en partie.
const MAX_ENTREES: usize = 1 << 20;

/// Une table rendue par IP Helper, liberee quoi qu'il arrive.
struct TableMib<T> {
    table: *mut T,
}

impl<T> Drop for TableMib<T> {
    fn drop(&mut self) {
        if !self.table.is_null() {
            // SAFETY: le pointeur vient d'un appel IP Helper reussi, qui alloue
            // la table et en confie la liberation a FreeMibTable; il n'est
            // libere qu'une fois, ici.
            unsafe { FreeMibTable(self.table.cast()) };
        }
    }
}

/// Les lignes d'une table IP Helper `{ NumEntries: u32, Table: [R; 1] }`.
///
/// # Safety
///
/// `premiere` doit pointer sur le champ `Table` d'une table valide rendue par
/// IP Helper, dont `nombre` (son `NumEntries`) entrees de type `R` se suivent a
/// partir de la, et qui vit au moins autant que le resultat.
unsafe fn lignes_de<'a, R>(nombre: u32, premiere: *const R) -> Result<&'a [R], Refus> {
    let nombre = nombre as usize;
    if nombre > MAX_ENTREES || (nombre > 0 && premiere.is_null()) {
        return Err(Refus::Tronquee);
    }
    if nombre == 0 {
        return Ok(&[]);
    }
    // SAFETY: garanti par l'appelant: `nombre` entrees contigues de type `R`
    // a partir de `premiere`, vivantes le temps du resultat.
    Ok(unsafe { std::slice::from_raw_parts(premiere, nombre) })
}

/// Une lecture complete. `alias` est le nom de l'interface du tunnel; une
/// interface absente rend `tunnel: None`, pas un refus.
pub fn lire_une_fois(alias: &str) -> Result<TableIpHelper, Refus> {
    let tunnel = luid_de(alias)?;
    let mut routes = lire_routes()?;
    let mut lignes = lire_lignes()?;
    let mut adresses = lire_adresses()?;
    routes.sort_by_key(|r| {
        (
            r.interface,
            r.destination.addr,
            r.destination.prefix_len,
            r.prochain_saut,
            r.metrique,
        )
    });
    lignes.sort_by_key(|l| (l.interface, l.famille));
    adresses.sort_by_key(|a| (a.interface, a.adresse.addr, a.adresse.prefix_len));
    Ok(TableIpHelper {
        tunnel,
        routes,
        lignes,
        adresses,
    })
}

/// Le LUID de l'alias, ou `None` s'il n'existe pas. `ConvertInterfaceAliasToLuid`
/// rend `ERROR_INVALID_PARAMETER` pour un alias qu'il ne connait pas (Microsoft
/// Learn: << if the InterfaceAlias parameter was invalid >>; mesure sous
/// Windows 10 22H2: 87 pour un alias absent); l'alias a deja ete valide par
/// l'appelant, ce code ne peut donc plus dire que l'absence. Tout autre code
/// est un refus, jamais une absence.
fn luid_de(alias: &str) -> Result<Option<u64>, Refus> {
    let large = ffi::wide(alias);
    let mut luid = NET_LUID_LH::default();
    // SAFETY: `large` est une chaine UTF-16 terminee par zero, `luid` une union
    // locale valide; les deux vivent le temps de l'appel.
    let code = unsafe { ConvertInterfaceAliasToLuid(large.as_ptr(), &mut luid) };
    match code {
        // SAFETY: `Value` est la vue u64 de l'union, valide quoi que l'API y
        // ait ecrit.
        ERROR_SUCCESS => Ok(Some(unsafe { luid.Value })),
        ERROR_INVALID_PARAMETER => Ok(None),
        autre => Err(Refus::Alias(autre)),
    }
}

/// Une adresse d'une `SOCKADDR_INET`, ou `None` pour une famille inconnue.
fn adresse_de(sa: &SOCKADDR_INET) -> Option<IpAddr> {
    // SAFETY: `si_family` occupe les deux premiers octets des trois vues de
    // l'union, toujours initialises par IP Helper.
    let famille = unsafe { sa.si_family };
    match famille {
        // SAFETY: la famille dit quelle vue de l'union est ecrite.
        AF_INET => Some(IpAddr::V4(Ipv4Addr::from(
            unsafe { sa.Ipv4.sin_addr.S_un.S_addr }.to_ne_bytes(),
        ))),
        // SAFETY: idem, vue IPv6.
        AF_INET6 => Some(IpAddr::V6(Ipv6Addr::from(unsafe {
            sa.Ipv6.sin6_addr.u.Byte
        }))),
        _ => None,
    }
}

/// Un prefixe, borne a la longueur de sa famille.
fn prefixe(addr: IpAddr, longueur: u8) -> Result<IpNet, Refus> {
    let max = if addr.is_ipv4() { 32 } else { 128 };
    if longueur > max {
        return Err(Refus::Tronquee);
    }
    Ok(IpNet {
        addr,
        prefix_len: longueur,
    })
}

fn famille_de(famille: u16) -> Result<Famille, Refus> {
    match famille {
        AF_INET => Ok(Famille::Ipv4),
        AF_INET6 => Ok(Famille::Ipv6),
        _ => Err(Refus::Tronquee),
    }
}

fn lire_routes() -> Result<Vec<RouteLue>, Refus> {
    let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
    // SAFETY: `table` recoit un pointeur alloue par l'API, libere par
    // `TableMib`; AF_UNSPEC demande les deux familles.
    let code = unsafe { GetIpForwardTable2(AF_UNSPEC, &mut table) };
    let garde = TableMib { table };
    if code != ERROR_SUCCESS {
        return Err(Refus::Routes(code));
    }
    if garde.table.is_null() {
        return Err(Refus::Tronquee);
    }
    // SAFETY: la table vient d'un appel reussi et vit autant que `garde`; ses
    // entrees suivent l'entete au champ `Table`.
    let lignes: &[MIB_IPFORWARD_ROW2] = unsafe {
        lignes_de(
            (*garde.table).NumEntries,
            std::ptr::addr_of!((*garde.table).Table).cast(),
        )?
    };
    let mut routes = Vec::with_capacity(lignes.len());
    for r in lignes {
        let destination = adresse_de(&r.DestinationPrefix.Prefix).ok_or(Refus::Tronquee)?;
        let saut = adresse_de(&r.NextHop).ok_or(Refus::Tronquee)?;
        routes.push(RouteLue {
            // SAFETY: vue u64 de l'union, valide quoi qu'on y ait ecrit.
            interface: unsafe { r.InterfaceLuid.Value },
            destination: prefixe(destination, r.DestinationPrefix.PrefixLength)?,
            prochain_saut: (!saut.is_unspecified()).then_some(saut),
            metrique: r.Metric,
        });
    }
    Ok(routes)
}

fn lire_lignes() -> Result<Vec<LigneLue>, Refus> {
    let mut table: *mut MIB_IPINTERFACE_TABLE = std::ptr::null_mut();
    // SAFETY: idem `lire_routes`.
    let code = unsafe { GetIpInterfaceTable(AF_UNSPEC, &mut table) };
    let garde = TableMib { table };
    if code != ERROR_SUCCESS {
        return Err(Refus::Interfaces(code));
    }
    if garde.table.is_null() {
        return Err(Refus::Tronquee);
    }
    // SAFETY: idem `lire_routes`.
    let lignes: &[MIB_IPINTERFACE_ROW] = unsafe {
        lignes_de(
            (*garde.table).NumEntries,
            std::ptr::addr_of!((*garde.table).Table).cast(),
        )?
    };
    lignes
        .iter()
        .map(|l| {
            Ok(LigneLue {
                // SAFETY: vue u64 de l'union.
                interface: unsafe { l.InterfaceLuid.Value },
                famille: famille_de(l.Family)?,
                metrique: l.Metric,
                metrique_automatique: l.UseAutomaticMetric,
            })
        })
        .collect()
}

fn lire_adresses() -> Result<Vec<AdresseLue>, Refus> {
    let mut table: *mut MIB_UNICASTIPADDRESS_TABLE = std::ptr::null_mut();
    // SAFETY: idem `lire_routes`.
    let code = unsafe { GetUnicastIpAddressTable(AF_UNSPEC, &mut table) };
    let garde = TableMib { table };
    if code != ERROR_SUCCESS {
        return Err(Refus::Adresses(code));
    }
    if garde.table.is_null() {
        return Err(Refus::Tronquee);
    }
    // SAFETY: idem `lire_routes`.
    let lignes: &[MIB_UNICASTIPADDRESS_ROW] = unsafe {
        lignes_de(
            (*garde.table).NumEntries,
            std::ptr::addr_of!((*garde.table).Table).cast(),
        )?
    };
    lignes
        .iter()
        .map(|a| {
            let adresse = adresse_de(&a.Address).ok_or(Refus::Tronquee)?;
            Ok(AdresseLue {
                // SAFETY: vue u64 de l'union.
                interface: unsafe { a.InterfaceLuid.Value },
                adresse: prefixe(adresse, a.OnLinkPrefixLength)?,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    /// Les chemins `a::b` que la production nomme, et eux seuls (voir
    /// `la_lecture_n_appelle_rien_qui_ecrive`): les types de donnees du coeur,
    /// les trois lectures et leurs tables, la conversion de chaine de `ffi`.
    const CHEMINS: [(&str, &str); 58] = [
        ("Famille", "Ipv4"),
        ("Famille", "Ipv6"),
        ("Foundation", "ERROR_INVALID_PARAMETER"),
        ("Foundation", "ERROR_SUCCESS"),
        ("IpAddr", "V4"),
        ("IpAddr", "V6"),
        ("IpHelper", "ConvertInterfaceAliasToLuid"),
        ("IpHelper", "FreeMibTable"),
        ("IpHelper", "GetIpForwardTable2"),
        ("IpHelper", "GetIpInterfaceTable"),
        ("IpHelper", "GetUnicastIpAddressTable"),
        ("IpHelper", "MIB_IPFORWARD_ROW2"),
        ("IpHelper", "MIB_IPFORWARD_TABLE2"),
        ("IpHelper", "MIB_IPINTERFACE_ROW"),
        ("IpHelper", "MIB_IPINTERFACE_TABLE"),
        ("IpHelper", "MIB_UNICASTIPADDRESS_ROW"),
        ("IpHelper", "MIB_UNICASTIPADDRESS_TABLE"),
        ("Ipv4Addr", "from"),
        ("Ipv6Addr", "from"),
        ("NET_LUID_LH", "default"),
        ("Ndis", "NET_LUID_LH"),
        ("NetworkManagement", "IpHelper"),
        ("NetworkManagement", "Ndis"),
        ("Networking", "WinSock"),
        ("Refus", "Adresses"),
        ("Refus", "Alias"),
        ("Refus", "Interfaces"),
        ("Refus", "Routes"),
        ("Refus", "Tronquee"),
        ("Vec", "with_capacity"),
        ("Win32", "Foundation"),
        ("Win32", "NetworkManagement"),
        ("Win32", "Networking"),
        ("WinSock", "AF_INET"),
        ("WinSock", "AF_INET6"),
        ("WinSock", "AF_UNSPEC"),
        ("WinSock", "SOCKADDR_INET"),
        ("bifrost_core", "config"),
        ("bifrost_core", "routage"),
        ("bifrost_core", "routage_windows"),
        ("config", "IpNet"),
        ("ffi", "wide"),
        ("net", "IpAddr"),
        ("net", "Ipv4Addr"),
        ("net", "Ipv6Addr"),
        ("ptr", "addr_of"),
        ("ptr", "null_mut"),
        ("routage", "Famille"),
        ("routage_windows", "AdresseLue"),
        ("routage_windows", "LigneLue"),
        ("routage_windows", "RouteLue"),
        ("routage_windows", "TableIpHelper"),
        ("slice", "from_raw_parts"),
        ("std", "net"),
        ("std", "ptr"),
        ("std", "slice"),
        ("super", "ffi"),
        ("windows_sys", "Win32"),
    ];

    /// Les seules fonctions IP Helper que le collecteur peut nommer: les trois
    /// lectures, la resolution de l'alias, la liberation des tables.
    const ADMISES: [&str; 5] = [
        "ConvertInterfaceAliasToLuid",
        "GetIpForwardTable2",
        "GetIpInterfaceTable",
        "GetUnicastIpAddressTable",
        "FreeMibTable",
    ];

    /// Les appels a majuscule de la production qui ne sont pas des fonctions
    /// du systeme: `Option`, `Result`, `IpAddr` et les refus de ce module.
    const CONSTRUCTEURS: [&str; 9] = [
        "Some",
        "Ok",
        "Err",
        "V4",
        "V6",
        "Alias",
        "Routes",
        "Interfaces",
        "Adresses",
    ];

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

    /// Les jetons de production: ce qui precede l'unique module de recettes,
    /// qui doit fermer le fichier.
    fn production(source: &str) -> Vec<String> {
        let j = jetons(source);
        let marque = jetons("#[cfg(test)] mod tests {");
        let debuts: Vec<usize> = (0..j.len())
            .filter(|&k| j[k..].starts_with(&marque))
            .collect();
        assert_eq!(debuts.len(), 1, "un seul module de recettes");
        assert_eq!(
            fermeture(&j, debuts[0] + marque.len() - 1),
            j.len() - 1,
            "du code suit le module de recettes"
        );
        j[..debuts[0]].to_vec()
    }

    /// Le collecteur ne nomme de l'espace IP Helper que ses lectures admises:
    /// une liste FERMEE, pas une liste de mots interdits, qui serait aveugle a
    /// ce qu'elle ne prevoit pas (`AddIPAddress`, `EnableRouter`,
    /// `ResolveIpNetEntry2` qui emet sur le reseau, `SendARP`...). Regle de
    /// forme sur les jetons de production, commentaires et litteraux retires:
    /// l'espace ne se nomme que par un chemin vers une fonction admise ou un
    /// type de table (`MIB_*`), jamais par un alias ni un glob; toute fonction
    /// a majuscule appelee est admise ou un constructeur; aucune declaration
    /// d'import a la main (`extern`, `link`); et tout chemin nomme est dans la
    /// liste fermee [`CHEMINS`].
    #[test]
    fn la_lecture_n_appelle_rien_qui_ecrive() {
        let p = production(include_str!("lecture_routes.rs"));
        let voisins = |k: usize| p[k.saturating_sub(3)..(k + 4).min(p.len())].join(" ");
        for k in (0..p.len()).filter(|&k| p[k] == "IpHelper") {
            assert_eq!(
                p.get(k + 1).map(String::as_str),
                Some("::"),
                "IpHelper sans chemin: {}",
                voisins(k)
            );
            let noms: Vec<&str> = match p.get(k + 2).map(String::as_str) {
                Some("{") => p[k + 3..fermeture(&p, k + 2)]
                    .iter()
                    .map(String::as_str)
                    .filter(|t| *t != ",")
                    .collect(),
                autre => vec![autre.unwrap_or("")],
            };
            for nom in noms {
                assert!(
                    ADMISES.contains(&nom) || nom.starts_with("MIB_"),
                    "IpHelper nomme hors de la liste admise: {nom}"
                );
            }
        }
        for k in (1..p.len()).filter(|&k| p[k] == "(") {
            let nom = p[k - 1].as_str();
            if nom.starts_with(|x: char| x.is_ascii_uppercase()) {
                assert!(
                    ADMISES.contains(&nom) || CONSTRUCTEURS.contains(&nom),
                    "appel hors de la liste admise: {}",
                    voisins(k)
                );
            }
        }
        for interdit in ["extern", "link"] {
            assert!(
                !p.iter().any(|t| t == interdit),
                "import declare a la main: {interdit}"
            );
        }
        // Hors de l'espace IP Helper, la meme fermeture: chaque chemin `a::b`
        // de la production est dans la liste. Un module voisin qui ecrit (le
        // moteur WFP de `ffi`), un autre espace du systeme, un processus lance
        // (`std::process`) ou un glob y ajouteraient une paire.
        let vus = chemins(&p);
        let admis: BTreeSet<(String, String)> = CHEMINS
            .iter()
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .collect();
        let hors: Vec<_> = vus.difference(&admis).collect();
        assert!(hors.is_empty(), "chemins hors de la liste: {hors:?}");
        let perimes: Vec<_> = admis.difference(&vus).collect();
        assert!(perimes.is_empty(), "liste a tenir a jour: {perimes:?}");
    }

    /// Les paires `a::b` d'une suite de jetons. Un groupe `a::{x, y::z}` donne
    /// `(a, x)`, `(a, y)` et `(y, z)`; tout ce qui suit `::` compte, `*`, un
    /// alias (`as`) ou un chevron compris.
    fn chemins(p: &[String]) -> BTreeSet<(String, String)> {
        let mut vus = BTreeSet::new();
        for k in (1..p.len()).filter(|&k| p[k] == "::") {
            let a = p[k - 1].clone();
            match p.get(k + 1).map(String::as_str) {
                Some("{") => {
                    let fin = fermeture(p, k + 1);
                    let mut profondeur = 0;
                    for i in k + 2..fin {
                        match p[i].as_str() {
                            "{" => profondeur += 1,
                            "}" => profondeur -= 1,
                            "," | "::" => {}
                            t if profondeur == 0 && p[i - 1] != "::" => {
                                vus.insert((a.clone(), t.to_owned()));
                            }
                            _ => {}
                        }
                    }
                }
                Some(b) => {
                    vus.insert((a, b.to_owned()));
                }
                None => {}
            }
        }
        vus
    }

    /// Une lecture reelle de l'hote, sans privilege: un alias absent rend
    /// `tunnel: None`, et les trois tables sont lues dans les deux familles.
    /// L'interface de bouclage est reconnue a son LUID.
    #[test]
    fn la_table_de_l_hote_se_lit_sans_privilege() {
        let t = lire_une_fois("bfabsent0").expect("les tables IP Helper se lisent");
        assert_eq!(t.tunnel, None, "alias absent");
        for f in Famille::TOUTES {
            assert!(
                t.routes.iter().any(|r| r.famille() == f),
                "aucune route {}",
                f.nom()
            );
            assert!(
                t.lignes.iter().any(|l| l.famille == f),
                "aucune ligne {}",
                f.nom()
            );
        }
        assert!(
            t.lignes
                .iter()
                .any(|l| bifrost_core::routage_windows::est_boucle_locale(l.interface)),
            "l'interface de bouclage doit etre reconnue a son LUID"
        );
        assert!(!t.adresses.is_empty());
        // Les routes et l'adresse que Windows pose sur le bouclage, sur tout
        // hote: elles tiennent l'ordre des octets, la longueur du prefixe et le
        // prochain saut non specifie lu comme "sur le lien".
        let boucle = |destination: &str| {
            let d: IpNet = destination.parse().unwrap();
            t.routes.iter().any(|r| {
                bifrost_core::routage_windows::est_boucle_locale(r.interface)
                    && r.destination == d
                    && r.prochain_saut.is_none()
            })
        };
        assert!(boucle("127.0.0.0/8"), "route du bouclage IPv4");
        assert!(boucle("::1/128"), "route du bouclage IPv6");
        let locale: IpNet = "127.0.0.1/8".parse().unwrap();
        assert!(
            t.adresses.iter().any(|a| a.adresse == locale),
            "adresse du bouclage"
        );
    }
}
