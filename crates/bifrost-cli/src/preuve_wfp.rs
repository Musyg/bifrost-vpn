//! `prove wfp --politique-daemon --actif`: le moteur WFP confronte a la
//! politique que le daemon declare lui avoir remise.
//!
//! Le pendant Windows de `prove nft --politique-daemon`, dans le meme ordre:
//! declaration (N1), instantane du moteur, declaration (N2). N1 et N2 doivent
//! etre identiques en entier; une application glissee entre les deux rend
//! l'instantane non attribuable. L'instantane est lu dans UNE transaction en
//! lecture seule (`bifrost_firewall::windows::lecture`): c'est elle qui tient
//! le role du GETGEN de nftables.
//!
//! Le lecteur de la declaration et ce protocole sont ceux de `prove nft`
//! (`crate::declaration`), avec la meme exigence: l'identite du serveur est
//! etablie AVANT de lui ecrire, par la regle des preuves (sous Windows, le pipe
//! appartient a LocalSystem). Un autre serveur rend NON MESURE
//! `failed_input = daemon-identity`, sans requete envoyee; le rapport porte le
//! NOM de la regle admise (`daemon_identity`), jamais une valeur.
//!
//! Trois controles, et chacun a son nom dans `differences`:
//!
//! 1. Les objets de Bifrost. L'attendu est la projection WFP v1 relue par un
//!    lecteur strict, rendue en filtres par `wfp_plan` - le code meme du
//!    produit - avec deux valeurs calculees sur CET hote: l'identifiant
//!    d'application d'un chemin, et l'identite comme liste de controle d'acces.
//!    L'observe est tout filtre des quatre couches qui porte le fournisseur OU
//!    la sous-couche de Bifrost; les deux se comparent en multi-ensemble.
//! 2. La sous-couche et le fournisseur eux-memes: presents, la sous-couche
//!    portee par le fournisseur de Bifrost. Son POIDS n'est pas compare a une
//!    constante: le moteur ne stocke pas le poids demande quand il entre en
//!    collision avec une sous-couche existante (mesure sur banc), donc le poids
//!    rendu est celui du moteur, pas celui du produit. C'est ce poids rendu qui
//!    sert de seuil a l'arbitrage ci-dessous.
//! 3. L'arbitrage. Un filtre TIERS defait un blocage de Bifrost s'il est
//!    evalue avant lui et que son action ne se laisse pas ecraser: une
//!    autorisation dure (`FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT`) ou un appel a
//!    un pilote qui peut rendre une autorisation (terminal ou inconnu), dans
//!    une sous-couche de poids au moins egal a celui de Bifrost. Plus bas, le
//!    blocage de Bifrost est deja final. Voir `capable`.
//!
//! Rien de la declaration n'entre dans le rapport, hors la version de schema:
//! ni chemin, ni SID, ni LUID, ni GUID, ni nom de filtre.
//!
//! Le protocole et la comparaison sont purs et compiles partout: leurs
//! recettes comptent sur les deux hotes. Hors Windows, seules elles les
//! appellent, la commande rendant NON MESURE sans lire quoi que ce soit.
#![cfg_attr(not(windows), allow(dead_code))]

use std::path::Path;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use serde_json::Value;

use bifrost_firewall::instantane_wfp::{
    Ace, Dacl, FiltreVu, Instantane, Sid, ValeurVue, lire_dacl,
};
use bifrost_firewall::politique_wfp::{self, PolitiqueWfp};
use bifrost_firewall::wfp_plan::{self, Action, FiltreWfp, Identity, Valeur, cles};

use crate::declaration::{IdentiteDaemon, Lue, Perimetre, Refus, Suivi};

const LIMITE: &str = "Attendu declare par le daemon, pas observe: une correspondance dit que le moteur WFP porte les filtres que le daemon dit avoir poses et qu'aucun filtre tiers lisible des quatre couches ALE ne peut defaire leurs blocages; les filtres illisibles par l'appelant et les pilotes noyau echappent a la lecture; pas une preuve d'etancheite du VPN.";

#[derive(Serialize, Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompteAttendu {
    filters: usize,
}

#[derive(Serialize, Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompteObserve {
    /// Filtres portant le fournisseur ou la sous-couche de Bifrost.
    filters: usize,
    /// Tous les autres filtres des quatre couches.
    third_party_filters: usize,
    /// Parmi eux, ceux qui peuvent defaire un blocage de Bifrost.
    third_party_overriding: usize,
    sublayers: usize,
}

#[derive(Serialize, Debug)]
pub struct Rapport {
    schema_version: u32,
    scope: &'static str,
    verdict: &'static str,
    started_at_unix_ms: Option<u128>,
    completed_at_unix_ms: Option<u128>,
    duration_ms: u128,
    source: &'static str,
    expected_source: &'static str,
    /// Le NOM de la regle qui a admis le serveur de la declaration, ou `null`.
    daemon_identity: IdentiteDaemon,
    policy_schema_version: Option<u32>,
    live_kernel: bool,
    generation_verified: bool,
    network_security: &'static str,
    expected_counts: Option<CompteAttendu>,
    observed_counts: Option<CompteObserve>,
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
        let identite = self.daemon_identity.ligne();
        format!(
            "{}  {}\n{}\n{identite}entree non mesuree: {}\necarts: {}\n\n{}\n",
            self.verdict,
            self.scope,
            self.reason,
            self.failed_input.unwrap_or("aucune"),
            self.differences.join(", "),
            self.limitation
        )
    }
}

fn heure() -> Option<u128> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_millis())
}

fn commencer() -> Rapport {
    Rapport {
        schema_version: 1,
        scope: "wfp-engine-comparison",
        verdict: "UNMEASURED",
        started_at_unix_ms: heure(),
        completed_at_unix_ms: None,
        duration_ms: 0,
        source: "wfp-engine-read-only-transaction",
        expected_source: "daemon-declared-active-policy",
        daemon_identity: IdentiteDaemon::NonVerifiee,
        policy_schema_version: None,
        live_kernel: false,
        generation_verified: false,
        network_security: "not-evaluated",
        expected_counts: None,
        observed_counts: None,
        differences: Vec::new(),
        failed_input: Some("daemon-declaration"),
        reason: "declaration du daemon non lue",
        limitation: LIMITE,
    }
}

fn terminer(mut r: Rapport, debut: Instant, resultat: Result<(), &'static str>) -> Rapport {
    r.reason = match resultat {
        Ok(()) => {
            "comparaison des objets Bifrost du moteur et arbitrage des filtres tiers; seuls les identifiants d'execution, les noms affiches, les bits de poids et le drapeau d'indexation que le moteur attribue lui-meme sont ignores"
        }
        Err(raison) => raison,
    };
    r.completed_at_unix_ms = heure();
    r.duration_ms = debut.elapsed().as_millis();
    r
}

// --- declaration ------------------------------------------------------------

/// Le moteur dont cette preuve lit la projection. Le lecteur, l'exigence
/// d'identite du serveur et le protocole N1 / mesure / N2 sont ceux de
/// `prove nft`, dans `crate::declaration`: une seule copie.
const PERIMETRE: Perimetre = Perimetre {
    moteur: politique_wfp::MOTEUR,
    autre_moteur: "moteur de pare-feu du daemon hors perimetre de la reference WFP",
    echec: "derniere application du daemon en echec: etat du moteur inconnu du daemon",
};

impl Suivi for Rapport {
    fn entree_manquante(&mut self, entree: &'static str) {
        self.failed_input = Some(entree);
    }
    fn identite(&mut self, identite: IdentiteDaemon) {
        self.daemon_identity = identite;
    }
}

// --- normalisation ----------------------------------------------------------

/// Une valeur de condition, sous la forme ou deux descriptions egales se
/// comparent egales. L'identite n'y est plus un descripteur binaire mais sa
/// liste de controle d'acces lue: deux encodages d'une meme liste sont la meme
/// identite, deux listes differentes ne le sont jamais.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Norme {
    Vide,
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    V4(u32, u32),
    V6([u8; 16], u8),
    Octets(Vec<u8>),
    Identite(Dacl),
    Autre(i32),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ConditionNorme {
    champ: u128,
    correspondance: u32,
    valeur: Norme,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct FiltreNorme {
    couche: u128,
    sous_couche: u128,
    fournisseur: Option<u128>,
    poids: u8,
    action: u32,
    drapeaux: u32,
    conditions: Vec<ConditionNorme>,
}

/// Les bits de drapeau que BFE pose lui-meme et qui ne changent pas ce que le
/// filtre fait. `INDEXE` accelere la classification, rien de plus. Tout autre
/// bit se compare: `DESACTIVE` change tout.
const DRAPEAUX_DU_MOTEUR: u32 = cles::DRAPEAU_INDEXE;

fn identite_attendue(sid: Sid) -> Norme {
    Norme::Identite(Dacl::Liste(vec![Ace::Acces {
        genre: bifrost_firewall::instantane_wfp::ACE_AUTORISATION,
        drapeaux: 0,
        masque: cles::DROIT_DE_CORRESPONDRE,
        sid,
    }]))
}

/// L'attendu, filtre par filtre, avec les deux valeurs d'hote calculees.
fn normaliser_attendu<A>(
    p: &PolitiqueWfp,
    reference: &[FiltreWfp],
    identifiant_application: &A,
) -> Result<Vec<FiltreNorme>, &'static str>
where
    A: Fn(&Path) -> Result<Vec<u8>, &'static str>,
{
    let courante = p.identite_courante()?;
    let mut sortie = Vec::with_capacity(reference.len());
    for f in reference {
        let mut conditions = Vec::with_capacity(f.conditions.len());
        for c in &f.conditions {
            let valeur = match &c.valeur {
                Valeur::U8(v) => Norme::U8(*v),
                Valeur::U16(v) => Norme::U16(*v),
                Valeur::U32(v) => Norme::U32(*v),
                Valeur::U64(v) => Norme::U64(*v),
                Valeur::V4 { adresse, masque } => Norme::V4(*adresse, *masque),
                Valeur::V6 { adresse, prefixe } => Norme::V6(*adresse, *prefixe),
                Valeur::Application(chemin) => Norme::Octets(identifiant_application(chemin)?),
                Valeur::Identite(Identity::Current) => identite_attendue(courante.clone()),
                Valeur::Identite(Identity::Sid(s)) => identite_attendue(
                    Sid::lire_texte(s).ok_or("identite de politique WFP invalide")?,
                ),
            };
            conditions.push(ConditionNorme {
                champ: c.champ.cle(),
                correspondance: c.correspondance.code(),
                valeur,
            });
        }
        conditions.sort();
        sortie.push(FiltreNorme {
            couche: f.couche.cle(),
            sous_couche: wfp_plan::SOUS_COUCHE,
            fournisseur: Some(wfp_plan::FOURNISSEUR),
            poids: f.poids,
            action: match f.action {
                Action::Permit => cles::ACTION_AUTORISATION,
                Action::Block => cles::ACTION_BLOCAGE,
            },
            drapeaux: if f.veto { cles::DRAPEAU_VETO } else { 0 },
            conditions,
        });
    }
    sortie.sort();
    Ok(sortie)
}

/// La plage 0-15 d'un filtre observe. `effectiveWeight` porte la plage dans
/// ses quatre bits de tete (Microsoft Learn, "Filter Weight Assignment");
/// `weight` la rend telle qu'elle a ete posee. Les deux doivent dire la meme
/// chose; un poids qu'on ne sait pas lire n'est pas compare.
fn plage(f: &FiltreVu) -> Result<u8, &'static str> {
    let effective = match f.poids_effectif {
        ValeurVue::U64(e) => Some((e >> 60) as u8),
        _ => None,
    };
    let posee = match f.poids {
        ValeurVue::U8(w) if w <= 15 => Some(w),
        ValeurVue::U64(w) => Some((w >> 60) as u8),
        _ => None,
    };
    match (posee, effective) {
        (Some(a), Some(b)) if a != b => Err("poids d'un filtre Bifrost incoherent"),
        (Some(a), _) | (None, Some(a)) => Ok(a),
        (None, None) => Err("poids d'un filtre Bifrost illisible"),
    }
}

fn normaliser_observe(f: &FiltreVu) -> Result<FiltreNorme, &'static str> {
    let mut conditions = Vec::with_capacity(f.conditions.len());
    for c in &f.conditions {
        let valeur = match &c.valeur {
            ValeurVue::Vide => Norme::Vide,
            ValeurVue::U8(v) => Norme::U8(*v),
            ValeurVue::U16(v) => Norme::U16(*v),
            ValeurVue::U32(v) => Norme::U32(*v),
            ValeurVue::U64(v) => Norme::U64(*v),
            ValeurVue::V4 { adresse, masque } => Norme::V4(*adresse, *masque),
            ValeurVue::V6 { adresse, prefixe } => Norme::V6(*adresse, *prefixe),
            ValeurVue::Octets(o) => Norme::Octets(o.clone()),
            ValeurVue::Descripteur(o) => Norme::Identite(
                lire_dacl(o).ok_or("descripteur de securite illisible dans un filtre Bifrost")?,
            ),
            ValeurVue::Autre(t) => Norme::Autre(*t),
        };
        conditions.push(ConditionNorme {
            champ: c.champ,
            correspondance: c.correspondance,
            valeur,
        });
    }
    conditions.sort();
    Ok(FiltreNorme {
        couche: f.couche.cle(),
        sous_couche: f.sous_couche,
        fournisseur: f.fournisseur,
        poids: plage(f)?,
        action: f.action,
        drapeaux: f.drapeaux & !DRAPEAUX_DU_MOTEUR,
        conditions,
    })
}

// --- comparaison ------------------------------------------------------------

/// `m` et `e` ne different-ils que par le bit `DESACTIVE` de `e`.
fn desactive(e: &FiltreNorme, m: &FiltreNorme) -> bool {
    e.drapeaux & cles::DRAPEAU_DESACTIVE != 0
        && FiltreNorme {
            drapeaux: e.drapeaux & !cles::DRAPEAU_DESACTIVE,
            ..e.clone()
        } == *m
}

/// `m` et `e` ne different-ils que par la valeur de l'interface locale.
fn interface_remplacee(e: &FiltreNorme, m: &FiltreNorme) -> bool {
    let sans = |f: &FiltreNorme| -> FiltreNorme {
        FiltreNorme {
            conditions: f
                .conditions
                .iter()
                .filter(|c| c.champ != cles::CHAMP_INTERFACE_LOCALE)
                .cloned()
                .collect(),
            ..f.clone()
        }
    };
    let interface = |f: &FiltreNorme| {
        f.conditions
            .iter()
            .any(|c| c.champ == cles::CHAMP_INTERFACE_LOCALE)
    };
    interface(e) && interface(m) && e != m && sans(e) == sans(m)
}

/// La condition `large` laisse-t-elle passer tout ce que `etroite` laisse
/// passer, pour le meme champ.
fn couvre(large: &ConditionNorme, etroite: &ConditionNorme) -> bool {
    if large.champ != etroite.champ || large.correspondance != etroite.correspondance {
        return false;
    }
    match (&large.valeur, &etroite.valeur) {
        (Norme::V4(a, ma), Norme::V4(b, mb)) => ma & mb == *ma && (b & ma) == (a & ma),
        (Norme::V6(a, pa), Norme::V6(b, pb)) => {
            pa <= pb && {
                let bits = u128::from_be_bytes(*a) ^ u128::from_be_bytes(*b);
                *pa == 0 || bits >> (128 - u32::from(*pa).min(128)) == 0
            }
        }
        (x, y) => x == y,
    }
}

/// Une autorisation `e` est-elle plus large que l'autorisation attendue `m`.
///
/// WFP combine en OU les conditions d'un meme champ et en ET les champs
/// differents. `e` laisse passer au moins ce que `m` laisse passer si, pour
/// chaque champ que `e` contraint, `m` le contraint aussi et chacune de ses
/// valeurs est couverte par une valeur de `e`. Un champ que `m` contraint et
/// que `e` ne contraint plus est une contrainte retiree. Un poids plus fort
/// passe au-dessus de davantage de blocages: c'est aussi elargir.
fn plus_large(e: &FiltreNorme, m: &FiltreNorme) -> bool {
    if e.action != cles::ACTION_AUTORISATION
        || m.action != cles::ACTION_AUTORISATION
        || e.couche != m.couche
        || e.poids < m.poids
        || e == m
    {
        return false;
    }
    let champs_e: Vec<u128> = e.conditions.iter().map(|c| c.champ).collect();
    champs_e.iter().all(|champ| {
        let de_m: Vec<&ConditionNorme> =
            m.conditions.iter().filter(|c| c.champ == *champ).collect();
        !de_m.is_empty()
            && de_m.iter().all(|cm| {
                e.conditions
                    .iter()
                    .filter(|ce| ce.champ == *champ)
                    .any(|ce| couvre(ce, cm))
            })
    })
}

/// Une regle qui dit qu'un filtre observe en trop est la forme alteree d'un
/// filtre attendu manquant, et laquelle.
type Apparier = fn(&FiltreNorme, &FiltreNorme) -> bool;

/// Retire de `a` un exemplaire de chaque element de `b` (multi-ensembles).
fn soustraire(a: &[FiltreNorme], b: &[FiltreNorme]) -> Vec<FiltreNorme> {
    let mut reste: Vec<Option<&FiltreNorme>> = b.iter().map(Some).collect();
    let mut sortie = Vec::new();
    for x in a {
        match reste.iter_mut().find(|y| **y == Some(x)) {
            Some(y) => *y = None,
            None => sortie.push(x.clone()),
        }
    }
    sortie
}

/// Un filtre tiers peut-il defaire un blocage de Bifrost. `Err` quand la
/// reference ne sait pas le dire: le rapport sera NON MESURE, jamais MATCH.
///
/// Arbitrage (Microsoft Learn, "Filter Arbitration"): les sous-couches sont
/// evaluees par poids decroissant, "Block" l'emporte sur "Permit" et est final.
/// Le blocage de Bifrost defait tout ce qui est evalue APRES lui, donc toute
/// sous-couche de poids strictement inferieur. Une sous-couche de poids
/// superieur, ou EGAL (l'ordre a poids egal n'est pas documente), est evaluee
/// avant ou peut l'etre: elle defait le blocage si son action ne se laisse pas
/// ecraser: une autorisation dure (veto pose sur une autorisation), ou un appel
/// a un pilote qui peut rendre une autorisation dure (terminal ou inconnu). Une
/// autorisation souple, un blocage, une inspection, une continuation n'y
/// peuvent rien. Un filtre desactive non plus.
///
/// `seuil` est le poids EFFECTIF de la sous-couche de Bifrost tel que le moteur
/// l'a rendu, jamais la valeur demandee: BFE rebat les poids de sous-couche qui
/// entrent en collision avec une sous-couche deja installee (mesure sur banc,
/// 30/09/2026: une demande 0xFFFF est rendue 0xFFFE quand une sous-couche tierce
/// occupe deja 0xFFFF; une valeur libre est rendue telle quelle). Comparer au
/// poids demande ferait manquer une sous-couche tierce qui, remontee au-dessus
/// d'un kill switch declasse, l'outrepasse.
fn capable(f: &FiltreVu, poids_sous_couche: u16, seuil: u16) -> Result<bool, &'static str> {
    if poids_sous_couche < seuil || f.drapeaux & cles::DRAPEAU_DESACTIVE != 0 {
        return Ok(false);
    }
    const CONTINUER: u32 = 0x2006;
    const AUCUNE: u32 = 0x7;
    const AUCUNE_SANS_CORRESPONDANCE: u32 = 0x8;
    match f.action {
        cles::ACTION_AUTORISATION => Ok(f.drapeaux & cles::DRAPEAU_VETO != 0),
        cles::ACTION_APPEL_TERMINAL | cles::ACTION_APPEL_INCONNU => Ok(true),
        cles::ACTION_BLOCAGE
        | cles::ACTION_APPEL_INSPECTION
        | CONTINUER
        | AUCUNE
        | AUCUNE_SANS_CORRESPONDANCE => Ok(false),
        _ => Err("action d'un filtre tiers hors perimetre de l'arbitrage"),
    }
}

fn dans_le_perimetre_bifrost(f: &FiltreVu) -> bool {
    f.fournisseur == Some(wfp_plan::FOURNISSEUR) || f.sous_couche == wfp_plan::SOUS_COUCHE
}

fn confronter(
    r: &mut Rapport,
    attendus: Vec<FiltreNorme>,
    i: &Instantane,
) -> Result<(), &'static str> {
    let mut differences: Vec<&'static str> = Vec::new();
    if !i.fournisseur_bifrost {
        differences.push("provider-missing");
    }
    // Le poids EFFECTIF de la sous-couche de Bifrost, rendu par le moteur: c'est
    // lui, et non la valeur demandee, qui decide quelles sous-couches tierces
    // sont evaluees avant le kill switch. Le comparer a une constante serait
    // faux: BFE ne garantit pas la valeur demandee (voir `capable`). `None` si
    // la sous-couche manque, auquel cas plus aucun filtre Bifrost ne tient et
    // l'arbitrage n'a pas de reference.
    let seuil = match i
        .sous_couches
        .iter()
        .find(|s| s.cle == wfp_plan::SOUS_COUCHE)
    {
        None => {
            differences.push("sublayer-missing");
            None
        }
        Some(s) => {
            if s.fournisseur != Some(wfp_plan::FOURNISSEUR) {
                differences.push("sublayer-changed");
            }
            Some(s.poids)
        }
    };

    let mut observes = Vec::new();
    let mut tiers = 0usize;
    let mut prioritaires = 0usize;
    for f in &i.filtres {
        if dans_le_perimetre_bifrost(f) {
            observes.push(normaliser_observe(f)?);
            continue;
        }
        tiers += 1;
        // Sans sous-couche Bifrost, il n'y a pas de seuil d'arbitrage: le rapport
        // est deja MISMATCH par la regle manquante, et un tiers ne peut defaire
        // un blocage qui n'existe plus.
        if let Some(seuil) = seuil {
            let poids = i
                .sous_couches
                .iter()
                .find(|s| s.cle == f.sous_couche)
                .map(|s| s.poids)
                .ok_or("sous-couche d'un filtre tiers absente de l'instantane")?;
            if capable(f, poids, seuil)? {
                prioritaires += 1;
            }
        }
    }
    observes.sort();
    r.observed_counts = Some(CompteObserve {
        filters: observes.len(),
        third_party_filters: tiers,
        third_party_overriding: prioritaires,
        sublayers: i.sous_couches.len(),
    });

    let manquants = soustraire(&attendus, &observes);
    let mut en_trop = soustraire(&observes, &attendus);
    let mut libres: Vec<bool> = vec![true; manquants.len()];
    let regles: [(&'static str, Apparier); 4] = [
        ("rule-disabled", desactive),
        ("interface-changed", interface_remplacee),
        ("exception-broadened", plus_large),
        ("rule-changed", |e, m| {
            e.couche == m.couche && e.action == m.action && e.poids == m.poids
        }),
    ];
    for (etiquette, regle) in regles {
        en_trop.retain(|e| {
            let trouve = manquants
                .iter()
                .enumerate()
                .find(|(k, m)| libres[*k] && regle(e, m));
            match trouve {
                Some((k, _)) => {
                    libres[k] = false;
                    differences.push(etiquette);
                    false
                }
                None => true,
            }
        });
    }
    if libres.iter().any(|l| *l) {
        differences.push("rule-missing");
    }
    for e in &en_trop {
        // Toute autorisation de trop dans le perimetre de Bifrost passe
        // au-dessus du blocage final: c'est une exception, et elle est large
        // par definition puisque rien ne l'attendait.
        differences.push(if e.action == cles::ACTION_AUTORISATION {
            "exception-added"
        } else {
            "rule-extra"
        });
    }
    if prioritaires > 0 {
        differences.push("third-party-override");
    }
    let mut vus = Vec::new();
    differences.retain(|d| {
        let nouveau = !vus.contains(d);
        vus.push(*d);
        nouveau
    });
    r.differences = differences;
    r.failed_input = None;
    r.verdict = if r.differences.is_empty() {
        "MATCH"
    } else {
        "MISMATCH"
    };
    Ok(())
}

// --- le protocole -----------------------------------------------------------

/// Le protocole, separe de ses trois sources (daemon, moteur, identifiants
/// d'application de l'hote) pour que les recettes sans privilege le jouent
/// avec des doublures, sur les deux hotes.
///
/// N1, instantane en une transaction en lecture seule, N2: le protocole commun
/// des preuves par declaration (`declaration::encadrer`), avec son exigence
/// d'identite du serveur et ce qu'il en dit au rapport. Seule la mesure est
/// propre a WFP.
pub(crate) async fn verifier_declaration_avec<L, FL, C, FC, A>(
    lire: L,
    collecter: C,
    identifiant_application: A,
) -> Rapport
where
    L: FnMut() -> FL,
    FL: std::future::Future<Output = Result<Lue, Refus>>,
    C: FnOnce() -> FC,
    FC: std::future::Future<Output = Result<Instantane, &'static str>>,
    A: Fn(&Path) -> Result<Vec<u8>, &'static str>,
{
    let debut = Instant::now();
    let mut r = commencer();
    let resultat = async {
        let (attendus, instantane) = crate::declaration::encadrer(
            &mut r,
            lire,
            |d| crate::declaration::politique_posee(d, &PERIMETRE).cloned(),
            async move |r: &mut Rapport, politique: Value| {
                let p = PolitiqueWfp::lire(politique)
                    .map_err(|_| "politique declaree hors du perimetre de la reference WFP v1")?;
                let reference = p.reference()?;
                r.failed_input = Some("expected");
                let attendus = normaliser_attendu(&p, &reference, &identifiant_application)?;
                r.policy_schema_version = Some(politique_wfp::VERSION);
                r.expected_counts = Some(CompteAttendu {
                    filters: attendus.len(),
                });
                r.failed_input = Some("observed");
                let instantane = collecter().await?;
                r.live_kernel = true;
                r.generation_verified = true;
                Ok((attendus, instantane))
            },
        )
        .await?;
        confronter(&mut r, attendus, &instantane)
    }
    .await;
    terminer(r, debut, resultat)
}

/// L'attendu est la declaration du daemon joint par `socket`, le moteur WFP
/// l'observe. Windows seulement: le moteur n'existe que la.
///
/// La declaration n'est lue qu'aupres d'un serveur admis par la regle des
/// preuves (`ServerRequirement::Privileged`, sous Windows le pipe de
/// LocalSystem), la meme que celle de `prove nft`: un autre serveur rend NON
/// MESURE `daemon-identity` sans avoir recu un octet.
pub async fn verifier_declaration(socket: &str) -> Rapport {
    #[cfg(windows)]
    {
        use bifrost_firewall::windows::lecture;
        verifier_declaration_avec(
            move || crate::declaration::lire(socket),
            || async {
                tokio::task::spawn_blocking(lecture::instantane)
                    .await
                    .map_err(|_| "lecture du moteur WFP interrompue")?
                    .map_err(|e| match e {
                        lecture::Refus::AccesRefuse => {
                            "acces au moteur WFP refuse; aucune elevation automatique"
                        }
                        lecture::Refus::Verrou => {
                            "instantane WFP non obtenu: un autre processus tient le verrou de transaction"
                        }
                        lecture::Refus::MoteurInjoignable(_) => "moteur WFP injoignable",
                        lecture::Refus::Interrompue(_) => "enumeration du moteur WFP interrompue",
                        lecture::Refus::Tronquee => "donnees du moteur WFP tronquees ou incoherentes",
                        lecture::Refus::NonConfirmee(_) => "transaction de lecture WFP non confirmee",
                    })
            },
            |chemin: &Path| {
                lecture::identifiant_application(chemin)
                    .ok_or("identifiant d'application non calculable sur cet hote")
            },
        )
        .await
    }
    #[cfg(not(windows))]
    {
        let _ = socket;
        let debut = Instant::now();
        terminer(
            commencer(),
            debut,
            Err("preuve WFP disponible uniquement sous Windows"),
        )
    }
}

#[cfg(test)]
mod tests;
