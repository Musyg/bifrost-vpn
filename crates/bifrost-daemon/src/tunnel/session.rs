//! Les sessions de routage du produit sous Linux: ce que chacune a pose, et a
//! qui est un objet qui porte l'etiquette du produit.
//!
//! # Pourquoi ce module existe
//!
//! L'etiquette du produit (`PROTOCOLE_PRODUIT`, 177) rend le retrait exact
//! face a ce qui ne la porte pas. Elle ne dit ni QUELLE session du produit a
//! pose un objet, ni meme que c'est le produit: n'importe quel programme peut
//! l'employer, et deux sessions du produit peuvent poser des objets de meme
//! forme. Ce qu'une session a pose se lit donc dans un journal, et le montage
//! ne retire, parmi ce qui porte l'etiquette, que ce qu'une session morte de
//! ce journal a pose: il refuse en le nommant tout ce qu'aucune session
//! n'explique, et tout montage a cote d'une session vivante.
//!
//! # Le journal
//!
//! Chaque session inscrit, AVANT la premiere commande qui pose, une entree
//! dans un repertoire d'execution que le daemon possede
//! ([`JOURNAL_PAR_DEFAUT`], ou `--journal-routage`): le processus qui la tient
//! (son PID et sa date de debut, couple que le noyau ne redonne pas), son
//! namespace reseau, son chemin et ses parametres, son interface, sa cle
//! publique WireGuard, puis les priorites que le noyau a donnees a ses regles
//! posees sans `pref`, relevees apres la pose. L'entree est effacee quand le
//! demontage a tout retire. `/run` est un tmpfs: le journal disparait au
//! redemarrage de la machine, comme les regles et les routes qu'il decrit.
//! L'unite systemd garde le repertoire d'un demarrage du service au suivant
//! (`RuntimeDirectoryPreserve=yes`): un daemon arrete ou tue laisse son
//! routage en place, et le suivant doit savoir que ce qui reste vient de lui.
//!
//! # Ce que le montage en fait
//!
//! Avant de poser, le montage lit le noyau et les entrees de son namespace
//! reseau ([`preparer_avec`]):
//!
//! - une session vivante (son processus tourne, ou elle est tenue par ce
//!   processus-ci) tient deja ce namespace: refus nomme, rien n'est retire;
//! - chaque objet a l'etiquette du produit est attribue a une session morte
//!   dont il a exactement la forme, et la priorite quand elle a ete relevee
//!   ([`attribuer`]); ceux-la seuls sont retires, avec l'interface WireGuard
//!   de la session quand elle porte encore sa cle, puis son entree est
//!   effacee;
//! - un objet a l'etiquette qu'aucune session inscrite n'explique: refus
//!   nomme, et RIEN n'est retire. Un tiers qui emploie l'etiquette et le reste
//!   d'une session dont le journal a disparu ne se distinguent pas: le
//!   produit ne retire ni l'un ni l'autre.
//!
//! Le demontage d'une session ([`demonter_avec`]) ne retire que ce qui lui
//! est attribue, chaque regle par sa priorite.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use bifrost_core::routage::{
    Chemin, Consultation, PROTOCOLE_PRODUIT, Plan, Regle, RegleLue, RouteLue, Selecteur,
    table_reservee,
};
use bifrost_core::{Error, Result};

use super::occupation::Etat;

/// La premiere ligne de chaque entree: le format et sa version.
const ENTETE: &str = "bifrost-session-routage 1";

/// Le journal des sessions, sous le repertoire d'execution du daemon.
pub const JOURNAL_PAR_DEFAUT: &str = "/run/bifrost/routage";

/// Une entree plus grande n'est pas une entree du produit.
const TAILLE_MAX_ENTREE: u64 = 4096;

/// Ce qu'une session inscrit au journal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Entree {
    /// Le processus qui tient la session.
    pub(crate) pid: u32,
    /// Sa date de debut (`starttime`, champ 22 de `/proc/<pid>/stat`, en tops
    /// d'horloge depuis le demarrage de la machine): un PID reutilise n'a pas
    /// la meme.
    pub(crate) debut: u64,
    /// Le namespace reseau de la session.
    pub(crate) reseau: String,
    pub(crate) chemin: Chemin,
    pub(crate) interface: String,
    /// WireGuard: la cle publique de la session, qui designe son interface.
    pub(crate) cle: Option<String>,
    /// Par regle du plan (`Plan::regles_posees`): la priorite qu'elle a
    /// recue, `None` tant qu'elle n'a pas ete relevee.
    pub(crate) priorites: Vec<Option<u32>>,
}

fn nom_d_interface_valide(n: &str) -> bool {
    (1..=15).contains(&n.len())
        && n.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn cle_valide(c: &str) -> bool {
    c.len() == 44
        && c.ends_with('=')
        && c.as_bytes()[..43]
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'+' || *b == b'/')
}

/// Un entier ecrit en decimal canonique: des chiffres, sans zero de tete.
fn nombre<T: std::str::FromStr>(s: &str) -> std::result::Result<T, String> {
    let canonique =
        !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) && (s == "0" || !s.starts_with('0'));
    if !canonique {
        return Err(format!("nombre invalide: '{s}'"));
    }
    s.parse()
        .map_err(|_| format!("nombre hors de portee: '{s}'"))
}

struct Lignes<'a>(std::str::Split<'a, char>);

impl<'a> Lignes<'a> {
    fn champ(&mut self, nom: &str) -> std::result::Result<&'a str, String> {
        let l = self
            .0
            .next()
            .ok_or_else(|| format!("champ '{nom}' absent"))?;
        l.strip_prefix(nom)
            .and_then(|r| r.strip_prefix(' '))
            .filter(|v| !v.is_empty())
            .ok_or_else(|| format!("champ '{nom}' attendu"))
    }
}

impl Entree {
    /// Le plan que la session pose: la meme fonction pure que la pose.
    pub(crate) fn plan(&self) -> Plan {
        match self.chemin {
            Chemin::WireGuard { marque, table } => Plan::wireguard(&self.interface, marque, table),
            Chemin::Coeur { compte } => Plan::coeur(&self.interface, compte),
        }
    }

    /// L'entree en texte, une ligne par champ, dans un ordre fixe.
    pub(crate) fn ecrire(&self) -> String {
        let mut s = format!(
            "{ENTETE}\npid {}\ndebut {}\nreseau {}\n",
            self.pid, self.debut, self.reseau
        );
        match self.chemin {
            Chemin::WireGuard { marque, table } => {
                s.push_str(&format!(
                    "chemin wireguard\ninterface {}\nmarque {marque}\ntable {table}\ncle {}\n",
                    self.interface,
                    self.cle.as_deref().unwrap_or("-")
                ));
            }
            Chemin::Coeur { compte } => {
                s.push_str(&format!(
                    "chemin coeur\ninterface {}\ncompte {}\n",
                    self.interface,
                    compte.map_or_else(|| "aucun".to_owned(), |c| c.to_string())
                ));
            }
        }
        let p: Vec<String> = self
            .priorites
            .iter()
            .map(|p| p.map_or_else(|| "?".to_owned(), |p| p.to_string()))
            .collect();
        s.push_str(&format!("priorites {}\n", p.join(" ")));
        s
    }

    /// Relit une entree. Tout ecart au format est une erreur: une entree que
    /// le produit ne comprend pas n'explique rien, et n'autorise aucun
    /// retrait.
    pub(crate) fn lire(texte: &str) -> std::result::Result<Self, String> {
        let corps = texte.strip_suffix('\n').ok_or("entree sans fin de ligne")?;
        let mut l = Lignes(corps.split('\n'));
        if l.0.next() != Some(ENTETE) {
            return Err("en-tete inconnu".into());
        }
        let pid = nombre(l.champ("pid")?)?;
        let debut = nombre(l.champ("debut")?)?;
        let reseau = l.champ("reseau")?;
        if !reseau
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err("namespace reseau invalide".into());
        }
        let chemin = l.champ("chemin")?;
        let interface = l.champ("interface")?;
        if !nom_d_interface_valide(interface) {
            return Err(format!("nom d'interface invalide: '{interface}'"));
        }
        let (chemin, cle) = match chemin {
            "wireguard" => {
                let marque = nombre(l.champ("marque")?)?;
                let table = nombre(l.champ("table")?)?;
                if table_reservee(table).is_some() {
                    return Err(format!("table reservee au noyau: {table}"));
                }
                let cle = l.champ("cle")?;
                if !cle_valide(cle) {
                    return Err("cle publique invalide".into());
                }
                (Chemin::WireGuard { marque, table }, Some(cle.to_owned()))
            }
            "coeur" => {
                let compte = match l.champ("compte")? {
                    "aucun" => None,
                    c => Some(nombre(c)?),
                };
                (Chemin::Coeur { compte }, None)
            }
            autre => return Err(format!("chemin inconnu: '{autre}'")),
        };
        let priorites = l.champ("priorites")?;
        if l.0.next().is_some() {
            return Err("ligne en trop".into());
        }
        let mut e = Entree {
            pid,
            debut,
            reseau: reseau.to_owned(),
            chemin,
            interface: interface.to_owned(),
            cle,
            priorites: Vec::new(),
        };
        let regles = e.plan().regles_posees();
        let jetons: Vec<&str> = priorites.split(' ').collect();
        if jetons.len() != regles.len() {
            return Err(format!(
                "{} priorite(s) pour {} regle(s)",
                jetons.len(),
                regles.len()
            ));
        }
        for (j, r) in jetons.iter().zip(&regles) {
            let p = if *j == "?" {
                None
            } else {
                Some(nombre::<u32>(j)?)
            };
            if r.priorite.is_some() && p != r.priorite {
                return Err("priorite differente de celle que le plan fixe".into());
            }
            e.priorites.push(p);
        }
        Ok(e)
    }
}

/// Une session du journal, jugee au moment de la lecture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Inscrite {
    /// Le nom de son entree au journal.
    pub(crate) nom: String,
    pub(crate) entree: Entree,
    /// Son processus tourne encore, ou ce processus-ci la tient.
    pub(crate) vivante: bool,
    /// Le numero de son interface quand celle-ci est encore a elle, `None`
    /// sinon: WireGuard, une interface WireGuard qui porte sa cle; coeur, le
    /// TUN que ce processus-ci tient pour elle. Ses routes ne se reconnaissent
    /// que par lui: une route vers une interface qui n'est plus la sienne
    /// n'est pas la sienne.
    pub(crate) index: Option<u32>,
}

impl Inscrite {
    /// Son interface part avec elle: WireGuard, et encore a elle. Le TUN du
    /// coeur, lui, disparait avec le descripteur qui le tient.
    pub(crate) fn lien_a_retirer(&self) -> bool {
        matches!(self.entree.chemin, Chemin::WireGuard { .. }) && self.index.is_some()
    }
}

/// Ce qui, d'une session, est encore dans le noyau.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Presence {
    /// Par regle du plan (`Plan::regles_posees`): sa priorite lue, si elle est
    /// la.
    pub(crate) regles: Vec<Option<u32>>,
    /// Par route du plan (`Plan::routes_posees`): est-elle la.
    pub(crate) routes: Vec<bool>,
}

impl Presence {
    pub(crate) fn vide(&self) -> bool {
        self.regles.iter().all(Option::is_none) && !self.routes.contains(&true)
    }

    fn decrire(&self) -> String {
        format!(
            "{} regle(s), {} route(s)",
            self.regles.iter().filter(|r| r.is_some()).count(),
            self.routes.iter().filter(|r| **r).count()
        )
    }
}

/// A qui sont les objets a l'etiquette du produit.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Attribution {
    /// Par session, dans l'ordre donne.
    pub(crate) presences: Vec<Presence>,
    /// Ceux qu'aucune session n'explique, decrits.
    pub(crate) inexpliques: Vec<String>,
    /// Les formes ou il y a plus d'objets que de regles posees sans priorite
    /// relevee: aucun n'est attribue, faute de savoir lequel.
    pub(crate) ambigus: Vec<String>,
    /// Une commande qui retirerait le premier objet inexplique, pour le refus.
    pub(crate) exemple: Option<String>,
}

/// Une forme de regle, dans la graphie d'`ip rule`.
fn forme_ip(selecteur: Selecteur, consultation: Consultation) -> String {
    let s = match selecteur {
        Selecteur::Tout => String::new(),
        Selecteur::HorsMarque(m) => format!("not fwmark {m} "),
        Selecteur::Compte(u) => format!("uidrange {u}-{u} "),
    };
    let c = match consultation {
        Consultation::Table(t) => format!("lookup {t}"),
        Consultation::Main => "lookup main".to_owned(),
        Consultation::MainSansDefaut => "lookup main suppress_prefixlength 0".to_owned(),
    };
    s + &c
}

/// Attribue chaque regle et chaque route a l'etiquette du produit a l'une des
/// sessions donnees, ou a aucune.
///
/// Une regle va a la session dont une regle posee a sa famille, sa forme et
/// son etiquette (`Regle::designe`), et sa priorite quand elle est connue
/// (fixee par le plan, ou relevee apres la pose); chaque regle lue va a une
/// seule session, et chaque regle posee recoit au plus une regle lue. Les
/// regles posees sans priorite relevee viennent ensuite, forme par forme: si
/// les regles lues de cette forme qui restent ne sont pas plus nombreuses
/// qu'elles, chacune en recoit une; sinon aucune, la forme est ambigue, et
/// les regles lues restent inexpliquees. Une route va a la session dont la
/// route posee a sa famille, sa table, son etiquette, et vise l'interface qui
/// est encore a elle (`Inscrite::index`).
pub(crate) fn attribuer(
    sessions: &[&Inscrite],
    regles: &[RegleLue],
    routes: &[RouteLue],
) -> Attribution {
    let plans: Vec<Plan> = sessions.iter().map(|s| s.entree.plan()).collect();
    let posees: Vec<Vec<Regle>> = plans.iter().map(Plan::regles_posees).collect();
    let mut a = Attribution {
        presences: plans
            .iter()
            .map(|p| Presence {
                regles: vec![None; p.regles_posees().len()],
                routes: vec![false; p.routes_posees().len()],
            })
            .collect(),
        ..Attribution::default()
    };
    let mut prise = vec![false; regles.len()];
    let mut inconnues: Vec<(usize, usize)> = Vec::new();
    for (s, regles_s) in posees.iter().enumerate() {
        for (i, r) in regles_s.iter().enumerate() {
            let connue = r
                .priorite
                .or(sessions[s].entree.priorites.get(i).copied().flatten());
            if connue.is_none() {
                inconnues.push((s, i));
                continue;
            }
            if let Some(k) = (0..regles.len()).find(|&k| !prise[k] && r.designe(&regles[k], connue))
            {
                prise[k] = true;
                a.presences[s].regles[i] = Some(regles[k].priorite);
            }
        }
    }
    let mut vues = vec![false; inconnues.len()];
    for x in 0..inconnues.len() {
        if vues[x] {
            continue;
        }
        let modele = posees[inconnues[x].0][inconnues[x].1];
        let groupe: Vec<usize> = (x..inconnues.len())
            .filter(|&y| {
                let r = posees[inconnues[y].0][inconnues[y].1];
                !vues[y]
                    && r.famille == modele.famille
                    && r.selecteur == modele.selecteur
                    && r.consultation == modele.consultation
            })
            .collect();
        for &y in &groupe {
            vues[y] = true;
        }
        let candidates: Vec<usize> = (0..regles.len())
            .filter(|&k| !prise[k] && modele.designe(&regles[k], None))
            .collect();
        if candidates.len() > groupe.len() {
            a.ambigus.push(format!(
                "{}: {} regle(s) `{}` a l'etiquette du produit pour {} posee(s) sans priorite relevee",
                modele.famille.nom(),
                candidates.len(),
                forme_ip(modele.selecteur, modele.consultation),
                groupe.len()
            ));
            continue;
        }
        for (&y, &k) in groupe.iter().zip(&candidates) {
            prise[k] = true;
            let (s, i) = inconnues[y];
            a.presences[s].regles[i] = Some(regles[k].priorite);
        }
    }
    let mut prise_r = vec![false; routes.len()];
    for (s, plan) in plans.iter().enumerate() {
        for (j, r) in plan.routes_posees().iter().enumerate() {
            if let Some(k) =
                (0..routes.len()).find(|&k| !prise_r[k] && r.designe(&routes[k], sessions[s].index))
            {
                prise_r[k] = true;
                a.presences[s].routes[j] = true;
            }
        }
    }
    for (k, r) in regles.iter().enumerate() {
        if r.protocole != PROTOCOLE_PRODUIT || prise[k] {
            continue;
        }
        a.inexpliques.push(match r.forme {
            Some((s, c)) => format!(
                "{}: regle `{}` de priorite {}",
                r.famille.nom(),
                forme_ip(s, c),
                r.priorite
            ),
            None => format!("{}: regle de priorite {}", r.famille.nom(), r.priorite),
        });
        a.exemple.get_or_insert_with(|| {
            format!(
                "ip {} rule del pref {} protocol {PROTOCOLE_PRODUIT}",
                r.famille.option_ip(),
                r.priorite
            )
        });
    }
    for (k, r) in routes.iter().enumerate() {
        if r.protocole != PROTOCOLE_PRODUIT || prise_r[k] {
            continue;
        }
        a.inexpliques.push(format!(
            "{}: route dans la table {}",
            r.famille.nom(),
            r.table
        ));
        a.exemple.get_or_insert_with(|| {
            format!(
                "ip {} route del default table {} proto {PROTOCOLE_PRODUIT}",
                r.famille.option_ip(),
                r.table
            )
        });
    }
    a
}

/// La priorite que le noyau a donnee a chaque regle du plan, lue juste apres
/// la pose: celle du plan quand il la fixe, sinon celle de l'unique regle a
/// l'etiquette du produit qui a la forme de la regle posee. Avant la pose, le
/// montage a verifie qu'aucune n'existait dans ce namespace: une seule est
/// donc la sienne. Plus d'une (un tiers s'est pose entre-temps) ou aucune:
/// `None`, et la regle reste attribuee par sa forme seule (voir
/// [`attribuer`]).
pub(crate) fn relever(plan: &Plan, regles: &[RegleLue]) -> Vec<Option<u32>> {
    plan.regles_posees()
        .iter()
        .map(|r| {
            r.priorite.or_else(|| {
                let mut c = regles.iter().filter(|l| r.designe(l, None));
                match (c.next(), c.next()) {
                    (Some(l), None) => Some(l.priorite),
                    _ => None,
                }
            })
        })
        .collect()
}

/// L'etat d'un processus et sa date de debut, lus dans le texte de
/// `/proc/<pid>/stat`. Le nom du programme, entre parentheses, peut contenir
/// des espaces et des parentheses: les champs se comptent apres la DERNIERE
/// parenthese fermante (`proc_pid_stat(5)`). L'etat est le champ 3, la date
/// de debut le champ 22.
pub(crate) fn etat_et_debut(stat: &str) -> Option<(char, u64)> {
    let reste = &stat[stat.rfind(')')? + 1..];
    let champs: Vec<&str> = reste.split_whitespace().collect();
    let etat = champs.first()?.chars().next()?;
    let debut = champs.get(19)?.parse().ok()?;
    Some((etat, debut))
}

/// Ce que le montage et le demontage lisent et font. Separe pour que les
/// recettes le jouent sans noyau et sans privilege, sur toutes les
/// plateformes.
pub(crate) trait Monde {
    /// Ou est le journal, pour les messages.
    fn journal(&self) -> String;
    /// Les regles et les routes du namespace reseau.
    fn lire(&mut self) -> Result<Etat>;
    /// Les sessions inscrites dans ce namespace reseau, jugees.
    fn inscrites(&mut self) -> Result<Vec<Inscrite>>;
    /// Une session dont on tient l'entree, jugee maintenant.
    fn juger(&mut self, nom: &str, entree: &Entree) -> Result<Inscrite>;
    /// Retire ce qui de la session est present, et son interface si elle
    /// part avec elle. N'efface pas son entree.
    fn retirer(&mut self, s: &Inscrite, p: &Presence) -> Result<()>;
    /// Efface l'entree de la session.
    fn effacer(&mut self, nom: &str) -> Result<()>;
}

fn refus_vivante(s: &Inscrite) -> Error {
    Error::Tunnel(format!(
        "montage refuse: une autre session du produit tient deja le routage de \
         ce namespace reseau (processus {pid}, interface {interface}). Rien \
         n'est retire ni pose. Demonter d'abord cette session, ou arreter le \
         processus qui la tient: ce qu'elle a pose sera retire au montage \
         suivant",
        pid = s.entree.pid,
        interface = s.entree.interface,
    ))
}

fn refus_inexpliques(a: &Attribution, journal: &str) -> Error {
    let mut detail = a.inexpliques.join("; ");
    if !a.ambigus.is_empty() {
        detail.push_str(&format!(" (indiscernables: {})", a.ambigus.join("; ")));
    }
    Error::Tunnel(format!(
        "montage refuse: {n} regle(s) ou route(s) portent l'etiquette du \
         produit (protocole {PROTOCOLE_PRODUIT}) sans qu'aucune session inscrite \
         au journal ({journal}) ne les ait posees: {detail}. Rien n'est retire \
         ni pose. Si ce sont les restes d'une session du produit dont le journal \
         a disparu, les retirer a la main{exemple}; sinon, un autre programme \
         emploie cette etiquette: l'arreter, ou lui en faire employer une autre",
        n = a.inexpliques.len(),
        exemple = a
            .exemple
            .as_ref()
            .map(|e| format!(" (par exemple `{e}`)"))
            .unwrap_or_default(),
    ))
}

/// Avant la premiere commande du montage: juger ce qui porte l'etiquette du
/// produit, retirer ce que des sessions mortes ont pose et elles seules,
/// verifier qu'il n'en reste rien, effacer leurs entrees, puis refuser une
/// voie qu'un tiers occupe (`Plan::occupation`). Rien n'est pose ici; un
/// refus est rendu avant tout retrait, sauf celui qui constate qu'un retrait
/// n'a pas abouti.
pub(crate) fn preparer_avec(plan: &Plan, m: &mut impl Monde) -> Result<()> {
    let etat = m.lire()?;
    let sessions = m.inscrites()?;
    if let Some(v) = sessions.iter().find(|s| s.vivante) {
        return Err(refus_vivante(v));
    }
    let toutes: Vec<&Inscrite> = sessions.iter().collect();
    let a = attribuer(&toutes, &etat.0, &etat.1);
    if !a.inexpliques.is_empty() {
        return Err(refus_inexpliques(&a, &m.journal()));
    }
    let etat = if sessions.is_empty() {
        etat
    } else {
        for (s, p) in sessions.iter().zip(&a.presences) {
            tracing::warn!(
                session = %s.nom,
                pid = s.entree.pid,
                interface = %s.entree.interface,
                present = %p.decrire(),
                "session morte du produit: retrait de ce qu'elle a pose"
            );
            m.retirer(s, p)?;
        }
        let etat = m.lire()?;
        let apres = m.inscrites()?;
        let toutes: Vec<&Inscrite> = apres.iter().collect();
        let b = attribuer(&toutes, &etat.0, &etat.1);
        let mut reste: Vec<String> = apres
            .iter()
            .zip(&b.presences)
            .filter(|(s, p)| s.vivante || !p.vide() || s.lien_a_retirer())
            .map(|(s, p)| {
                format!(
                    "session {} (interface {}): {}{}{}",
                    s.nom,
                    s.entree.interface,
                    p.decrire(),
                    if s.lien_a_retirer() {
                        ", son interface"
                    } else {
                        ""
                    },
                    if s.vivante { ", vivante" } else { "" },
                )
            })
            .collect();
        reste.extend(b.inexpliques.iter().cloned());
        if !reste.is_empty() {
            return Err(Error::Tunnel(format!(
                "montage refuse: le retrait de ce que des sessions mortes du \
                 produit ont pose n'a pas abouti ({}). Rien n'est pose; leurs \
                 entrees restent au journal ({}), et le montage suivant \
                 reessaiera",
                reste.join("; "),
                m.journal()
            )));
        }
        for s in &apres {
            m.effacer(&s.nom)?;
        }
        etat
    };
    let occupations = plan.occupation(&etat.0, &etat.1);
    if occupations.is_empty() {
        return Ok(());
    }
    Err(Error::Tunnel(plan.refus_d_occupation(&occupations)))
}

/// Le demontage d'une session tenue par ce processus: retirer ce qui lui est
/// attribue, et cela seul, relire, verifier que rien d'elle ne reste, puis
/// effacer son entree. Une forme ambigue (plus de regles a l'etiquette que de
/// regles posees sans priorite relevee) n'est pas retiree: le produit ne sait
/// pas laquelle est la sienne. L'entree reste alors au journal.
pub(crate) fn demonter_avec(nom: &str, entree: &Entree, m: &mut impl Monde) -> Result<()> {
    let etat = m.lire()?;
    let s = m.juger(nom, entree)?;
    let a = attribuer(&[&s], &etat.0, &etat.1);
    if !a.ambigus.is_empty() {
        return Err(Error::Tunnel(format!(
            "demontage incomplet: {}. Aucune de ces regles n'est retiree, faute \
             de savoir laquelle est celle de la session; la session reste \
             inscrite au journal ({})",
            a.ambigus.join("; "),
            m.journal()
        )));
    }
    m.retirer(&s, &a.presences[0])?;
    let etat = m.lire()?;
    let s = m.juger(nom, entree)?;
    let b = attribuer(&[&s], &etat.0, &etat.1);
    if !b.presences[0].vide() || s.lien_a_retirer() || !b.ambigus.is_empty() {
        return Err(Error::Tunnel(format!(
            "demontage incomplet: il reste de la session {}{}; elle reste \
             inscrite au journal ({})",
            b.presences[0].decrire(),
            if s.lien_a_retirer() {
                format!(" et l'interface {}", s.entree.interface)
            } else {
                String::new()
            },
            m.journal()
        )));
    }
    m.effacer(nom)
}

/// Ce processus: son PID et sa date de debut (`/proc/self/stat`), le couple
/// qui le designe sans qu'un autre processus puisse le reprendre tant que la
/// machine ne redemarre pas. Le journal et les configurations des coeurs
/// nomment leur processus par lui.
#[cfg(target_os = "linux")]
pub(crate) fn ce_processus() -> std::io::Result<(u32, u64)> {
    static MOI: std::sync::OnceLock<(u32, u64)> = std::sync::OnceLock::new();
    if let Some(m) = MOI.get() {
        return Ok(*m);
    }
    let stat = std::fs::read_to_string("/proc/self/stat")?;
    let (_, debut) = etat_et_debut(&stat)
        .ok_or_else(|| std::io::Error::other("/proc/self/stat: format inattendu"))?;
    Ok(*MOI.get_or_init(|| (std::process::id(), debut)))
}

/// Le processus `pid` de cette date de debut tourne-t-il encore. Un PID
/// absent, repris par un processus d'une autre date de debut, ou un zombie:
/// non. Une lecture impossible pour une autre raison est une erreur.
#[cfg(target_os = "linux")]
pub(crate) fn processus_vivant(pid: u32, debut: u64) -> std::io::Result<bool> {
    let stat = match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
    };
    match etat_et_debut(&stat) {
        Some((etat, d)) => Ok(d == debut && !matches!(etat, 'Z' | 'X' | 'x')),
        None => Err(std::io::Error::other(format!(
            "/proc/{pid}/stat: format inattendu"
        ))),
    }
}

#[cfg(target_os = "linux")]
pub(crate) use systeme::preparer;
#[cfg(target_os = "linux")]
pub use systeme::{Session, designer_le_journal};

#[cfg(target_os = "linux")]
mod systeme {
    use std::io::Write;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Mutex, OnceLock};

    use bifrost_core::routage::{Chemin, Plan};
    use bifrost_core::{Error, Result};

    use super::{Entree, Inscrite, Monde, Presence, TAILLE_MAX_ENTREE};
    use crate::tunnel::netcfg::Cmd;

    static REPERTOIRE: OnceLock<PathBuf> = OnceLock::new();
    /// Les entrees que ce processus tient: une session de ce processus est
    /// vivante si son entree y figure, morte sinon (un montage interrompu, ou
    /// une session abandonnee).
    static TENUES: Mutex<Vec<String>> = Mutex::new(Vec::new());
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);

    /// Designe le repertoire du journal. A appeler avant le premier montage;
    /// rend `false` si le journal etait deja designe (le premier choix reste).
    pub fn designer_le_journal(repertoire: PathBuf) -> bool {
        REPERTOIRE.set(repertoire).is_ok()
    }

    fn repertoire() -> &'static Path {
        REPERTOIRE.get_or_init(|| PathBuf::from(super::JOURNAL_PAR_DEFAUT))
    }

    fn tenues() -> std::sync::MutexGuard<'static, Vec<String>> {
        TENUES
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn erreur(quoi: &str, e: impl std::fmt::Display) -> Error {
        Error::Tunnel(format!(
            "journal des sessions de routage: {quoi}: {e}; rien n'est retire ni pose"
        ))
    }

    /// Le repertoire du journal, verifie: un repertoire (pas un lien), a ce
    /// processus, que ni le groupe ni les autres ne peuvent ecrire. Un
    /// journal que d'autres ecriraient ferait retirer ce qu'ils voudraient.
    /// Absent, il est cree (`creer`) ou dit absent (`false`).
    pub(super) fn repertoire_sur(rep: &Path, creer: bool) -> Result<bool> {
        let lieu = rep.display().to_string();
        let m = match std::fs::symlink_metadata(rep) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if !creer {
                    return Ok(false);
                }
                std::fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(rep)
                    .map_err(|e| erreur(&format!("creation de {lieu}"), e))?;
                std::fs::symlink_metadata(rep)
                    .map_err(|e| erreur(&format!("lecture de {lieu}"), e))?
            }
            Err(e) => return Err(erreur(&format!("lecture de {lieu}"), e)),
        };
        // SAFETY: appel systeme sans argument ni effet.
        let moi = unsafe { libc::geteuid() };
        if !m.file_type().is_dir() || m.uid() != moi || m.permissions().mode() & 0o022 != 0 {
            return Err(erreur(
                &lieu,
                "ce n'est pas un repertoire de ce processus ferme en ecriture aux autres",
            ));
        }
        Ok(true)
    }

    /// Ecrit une entree d'un coup: un fichier neuf a cote, puis un
    /// renommage, qui remplace l'ancien sans etat intermediaire.
    pub(super) fn ecrire(rep: &Path, nom: &str, texte: &str) -> Result<()> {
        repertoire_sur(rep, true)?;
        let provisoire = rep.join(format!(".{nom}.tmp"));
        match std::fs::remove_file(&provisoire) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(erreur("ecriture", e)),
        }
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&provisoire)
            .map_err(|e| erreur("ecriture", e))?;
        f.write_all(texte.as_bytes())
            .and_then(|()| f.sync_all())
            .map_err(|e| erreur("ecriture", e))?;
        std::fs::rename(&provisoire, rep.join(nom)).map_err(|e| erreur("ecriture", e))
    }

    pub(super) fn effacer_dans(rep: &Path, nom: &str) -> Result<()> {
        match std::fs::remove_file(rep.join(nom)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(erreur("effacement", e)),
        }
    }

    /// Un nom d'entree: `<pid>-<debut>-<numero>`. Tout autre nom (un fichier
    /// provisoire, commence par un point) n'est pas une entree.
    fn nom_d_entree(nom: &str) -> Option<(u32, u64)> {
        let mut p = nom.split('-');
        let pid = super::nombre(p.next()?).ok()?;
        let debut = super::nombre(p.next()?).ok()?;
        super::nombre::<u64>(p.next()?).ok()?;
        p.next().is_none().then_some((pid, debut))
    }

    /// Les entrees du journal dont le namespace reseau est `reseau`. Une
    /// entree illisible est une erreur, quel que soit son namespace: on ne
    /// sait pas lequel c'est.
    pub(super) fn entrees(rep: &Path, reseau: &str) -> Result<Vec<(String, Entree)>> {
        if !repertoire_sur(rep, false)? {
            return Ok(Vec::new());
        }
        let mut v = Vec::new();
        for e in std::fs::read_dir(rep).map_err(|e| erreur("lecture", e))? {
            let e = e.map_err(|e| erreur("lecture", e))?;
            let Some(nom) = e.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            let Some((pid, debut)) = nom_d_entree(&nom) else {
                continue;
            };
            let illisible = |raison: String| {
                Error::Tunnel(format!(
                    "montage refuse: entree illisible au journal des sessions de \
                     routage ({}): {raison}. Rien n'est retire ni pose: le produit \
                     ne sait plus ce que cette session a pose",
                    rep.join(&nom).display()
                ))
            };
            let m = std::fs::symlink_metadata(e.path()).map_err(|e| erreur("lecture", e))?;
            if !m.file_type().is_file() || m.len() > TAILLE_MAX_ENTREE {
                return Err(illisible("ce n'est pas un fichier d'entree".into()));
            }
            let texte = std::fs::read_to_string(e.path()).map_err(|e| illisible(e.to_string()))?;
            let entree = Entree::lire(&texte).map_err(illisible)?;
            if (entree.pid, entree.debut) != (pid, debut) {
                return Err(illisible("son nom ne designe pas son processus".into()));
            }
            if entree.reseau == reseau {
                v.push((nom, entree));
            }
        }
        v.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(v)
    }

    /// Ce processus: PID et date de debut.
    fn moi() -> Result<(u32, u64)> {
        super::ce_processus().map_err(|e| erreur("lecture de /proc/self/stat", e))
    }

    /// Le processus de cette entree tourne-t-il encore. Un PID absent, ou
    /// repris par un processus d'une autre date de debut, ou un zombie: non.
    /// Une lecture impossible pour une autre raison est une erreur.
    pub(super) fn vivant(pid: u32, debut: u64) -> Result<bool> {
        super::processus_vivant(pid, debut)
            .map_err(|e| erreur(&format!("lecture de /proc/{pid}/stat"), e))
    }

    /// Le namespace reseau de ce processus: son cookie (`SO_NETNS_COOKIE`),
    /// que le noyau ne redonne jamais a un autre namespace; a defaut (un noyau
    /// qui ne le connait pas), le peripherique et l'inode du namespace.
    pub(super) fn reseau_courant() -> Result<String> {
        // SAFETY: appel systeme sans pointeur; le descripteur rendu, s'il est
        // valide, est aussitot confie a un `OwnedFd` qui le fermera.
        let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
        if fd < 0 {
            return Err(erreur("namespace reseau", std::io::Error::last_os_error()));
        }
        // SAFETY: `fd` vient d'etre ouvert et n'appartient a personne d'autre.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let mut cookie: u64 = 0;
        let mut taille = std::mem::size_of::<u64>() as libc::socklen_t;
        // SAFETY: `cookie` et `taille` vivent jusqu'a la fin de l'appel, et
        // `taille` est celle de `cookie`, ce que le noyau attend.
        let r = unsafe {
            libc::getsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_NETNS_COOKIE,
                (&raw mut cookie).cast(),
                &raw mut taille,
            )
        };
        if r == 0 && taille as usize == std::mem::size_of::<u64>() {
            return Ok(format!("cookie-{cookie}"));
        }
        let e = std::io::Error::last_os_error();
        if r != 0 && e.raw_os_error() != Some(libc::ENOPROTOOPT) {
            return Err(erreur("namespace reseau", e));
        }
        let m = std::fs::metadata("/proc/thread-self/ns/net")
            .map_err(|e| erreur("namespace reseau", e))?;
        Ok(format!("inode-{}-{}", m.dev(), m.ino()))
    }

    /// Le numero d'une interface de ce namespace, `None` si aucune ne porte
    /// ce nom.
    fn index_de(interface: &str) -> Option<u32> {
        let nom = std::ffi::CString::new(interface).ok()?;
        // SAFETY: `nom` est une chaine terminee par un octet nul qui vit
        // jusqu'a la fin de l'appel.
        let i = unsafe { libc::if_nametoindex(nom.as_ptr()) };
        (i != 0).then_some(i)
    }

    fn executer(cmd: &Cmd) {
        match std::process::Command::new(cmd.program)
            .args(&cmd.args)
            .output()
        {
            Ok(o) if o.status.success() => {}
            Ok(o) => tracing::debug!(
                cmd = %cmd.display(),
                stderr = %String::from_utf8_lossy(&o.stderr).trim(),
                "echec tolere"
            ),
            Err(e) => tracing::debug!(cmd = %cmd.display(), error = %e, "echec tolere"),
        }
    }

    /// Le monde reel: le noyau de ce namespace, et le journal.
    pub(super) struct Reel {
        pub(super) rep: PathBuf,
    }

    impl Monde for Reel {
        fn journal(&self) -> String {
            self.rep.display().to_string()
        }

        fn lire(&mut self) -> Result<super::Etat> {
            crate::tunnel::occupation::lire()
        }

        fn inscrites(&mut self) -> Result<Vec<Inscrite>> {
            let reseau = reseau_courant()?;
            entrees(&self.rep, &reseau)?
                .into_iter()
                .map(|(nom, e)| self.juger(&nom, &e))
                .collect()
        }

        fn juger(&mut self, nom: &str, entree: &Entree) -> Result<Inscrite> {
            let a_moi = (entree.pid, entree.debut) == moi()?;
            let vivante = if a_moi {
                tenues().iter().any(|n| n == nom)
            } else {
                vivant(entree.pid, entree.debut)?
            };
            let index = index_de(&entree.interface).filter(|_| match entree.chemin {
                Chemin::WireGuard { .. } => {
                    entree.cle.is_some()
                        && crate::tunnel::linux::cle_de_l_interface(&entree.interface) == entree.cle
                }
                Chemin::Coeur { .. } => a_moi && vivante,
            });
            Ok(Inscrite {
                nom: nom.to_owned(),
                entree: entree.clone(),
                vivante,
                index,
            })
        }

        fn retirer(&mut self, s: &Inscrite, p: &Presence) -> Result<()> {
            for args in s
                .entree
                .plan()
                .arguments_retrait_presents(&p.regles, &p.routes)
            {
                executer(&Cmd::ip_plan_tolere(args));
            }
            if s.lien_a_retirer() {
                executer(&Cmd::ip_lenient(&[
                    "link",
                    "del",
                    "dev",
                    &s.entree.interface,
                ]));
            }
            Ok(())
        }

        fn effacer(&mut self, nom: &str) -> Result<()> {
            effacer_dans(&self.rep, nom)?;
            tenues().retain(|n| n != nom);
            Ok(())
        }
    }

    /// Avant la premiere commande du montage, dans le monde reel: voir
    /// [`super::preparer_avec`].
    pub(crate) fn preparer(plan: &Plan) -> Result<()> {
        super::preparer_avec(
            plan,
            &mut Reel {
                rep: repertoire().to_path_buf(),
            },
        )
    }

    /// Une session de routage tenue par ce processus: inscrite au journal
    /// avant la premiere commande qui pose, effacee quand son demontage a
    /// tout retire. Abandonnee sans demontage (l'objet detruit), elle n'est
    /// plus tenue: le montage suivant la traite en session morte.
    pub struct Session {
        nom: String,
        entree: Entree,
        rep: PathBuf,
    }

    impl Session {
        /// Inscrit la session du plan au journal. A appeler apres
        /// [`preparer`] et avant la premiere commande qui pose.
        pub(crate) fn ouvrir(plan: &Plan, cle: Option<String>) -> Result<Self> {
            Self::ouvrir_dans(repertoire(), plan, cle)
        }

        /// [`Session::ouvrir`], dans le journal `rep`.
        fn ouvrir_dans(rep: &Path, plan: &Plan, cle: Option<String>) -> Result<Self> {
            let (pid, debut) = moi()?;
            let entree = Entree {
                pid,
                debut,
                reseau: reseau_courant()?,
                chemin: plan.chemin,
                interface: plan.interface.clone(),
                cle,
                priorites: plan.regles_posees().iter().map(|r| r.priorite).collect(),
            };
            let texte = entree.ecrire();
            // Une entree que le journal ne relirait pas bloquerait tout montage
            // suivant: elle n'est pas ecrite.
            if Entree::lire(&texte).as_ref() != Ok(&entree) {
                return Err(erreur(
                    "inscription",
                    "entree que le journal ne relirait pas",
                ));
            }
            let nom = format!("{pid}-{debut}-{}", SEQUENCE.fetch_add(1, Ordering::Relaxed));
            tenues().push(nom.clone());
            let s = Session {
                nom,
                entree,
                rep: rep.to_path_buf(),
            };
            ecrire(&s.rep, &s.nom, &texte)?;
            Ok(s)
        }

        /// Apres la pose: releve la priorite que le noyau a donnee a chaque
        /// regle posee sans `pref`, et la reinscrit. Une releve impossible
        /// laisse la regle sans priorite connue; elle est dite, pas fatale.
        pub(crate) fn relever(&mut self) {
            let plan = self.entree.plan();
            match crate::tunnel::occupation::lire() {
                Ok((regles, _)) => self.entree.priorites = super::relever(&plan, &regles),
                Err(e) => {
                    tracing::warn!(error = %e, "priorites des regles non relevees");
                    return;
                }
            }
            if self.entree.priorites.iter().any(Option::is_none) {
                tracing::warn!(
                    interface = %self.entree.interface,
                    "une regle posee sans pref n'a pas de priorite relevee: \
                     elle ne sera retiree que si elle est seule de sa forme"
                );
            }
            if let Err(e) = ecrire(&self.rep, &self.nom, &self.entree.ecrire()) {
                tracing::warn!(error = %e, "priorites relevees non reinscrites");
            }
        }

        /// Retire ce que la session a pose et qui est encore la, et cela
        /// seul, puis efface son entree. En erreur, l'entree reste au journal
        /// et la session reste tenue: un nouvel essai est possible.
        pub fn retirer(&self) -> Result<()> {
            super::demonter_avec(
                &self.nom,
                &self.entree,
                &mut Reel {
                    rep: self.rep.clone(),
                },
            )
        }
    }

    impl Drop for Session {
        fn drop(&mut self) {
            tenues().retain(|n| n != &self.nom);
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// Le chemin d'un repertoire de la recette, sans le creer.
        fn chemin_de_recette(quoi: &str) -> PathBuf {
            let rep =
                std::env::temp_dir().join(format!("bifrost-session-{quoi}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&rep);
            rep
        }

        /// Un repertoire de la recette, cree ici en 0700. Le mode est pose
        /// explicitement, pas laisse a l'umask du processus de recettes.
        fn repertoire_de_recette(quoi: &str) -> PathBuf {
            let rep = chemin_de_recette(quoi);
            std::fs::create_dir(&rep).expect("repertoire de la recette");
            std::fs::set_permissions(&rep, std::fs::Permissions::from_mode(0o700))
                .expect("repertoire de la recette en 0700");
            rep
        }

        fn entree(reseau: &str, pid: u32, debut: u64) -> Entree {
            Entree {
                pid,
                debut,
                reseau: reseau.to_owned(),
                chemin: Chemin::Coeur { compte: None },
                interface: "bftun0".into(),
                cle: None,
                priorites: vec![Some(9110), Some(9120), Some(9110), Some(9120)],
            }
        }

        /// Sans privilege, dans un repertoire de la recette: une entree
        /// s'ecrit, se relit, ne se lit que dans son namespace reseau, et
        /// s'efface. Les fichiers qui ne sont pas des entrees sont ignores.
        #[test]
        fn le_journal_s_ecrit_se_relit_par_namespace_et_s_efface() {
            let ici = reseau_courant().expect("namespace reseau");
            assert!(
                ici.starts_with("cookie-") || ici.starts_with("inode-"),
                "{ici}"
            );
            // Absent, le journal est vide et n'est pas cree par la lecture; le
            // produit le cree ferme au groupe et aux autres quand il ecrit.
            let neuf = chemin_de_recette("neuf");
            assert!(entrees(&neuf, &ici).unwrap().is_empty());
            assert!(!repertoire_sur(&neuf, false).unwrap());
            assert!(repertoire_sur(&neuf, true).unwrap());
            assert_eq!(
                std::fs::symlink_metadata(&neuf)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o077,
                0
            );
            std::fs::remove_dir(&neuf).unwrap();
            let rep = repertoire_de_recette("journal");
            assert!(entrees(&rep, &ici).unwrap().is_empty());
            let a = entree(&ici, 4242, 77);
            let b = entree("cookie-0", 4243, 78);
            ecrire(&rep, "4242-77-0", &a.ecrire()).unwrap();
            ecrire(&rep, "4243-78-0", &b.ecrire()).unwrap();
            std::fs::write(rep.join(".4242-77-1.tmp"), "rien").unwrap();
            std::fs::write(rep.join("autre"), "rien").unwrap();
            assert_eq!(
                entrees(&rep, &ici).unwrap(),
                [("4242-77-0".to_owned(), a.clone())]
            );
            effacer_dans(&rep, "4242-77-0").unwrap();
            effacer_dans(&rep, "4242-77-0").unwrap();
            assert!(entrees(&rep, &ici).unwrap().is_empty());
            std::fs::remove_dir_all(&rep).unwrap();
        }

        /// Une entree illisible, ou dont le nom ne designe pas son processus,
        /// est une erreur nommee, quel que soit son namespace; un repertoire
        /// que d'autres peuvent ecrire aussi.
        #[test]
        fn un_journal_illisible_ou_ouvert_est_une_erreur() {
            let rep = repertoire_de_recette("illisible");
            let ici = reseau_courant().unwrap();
            ecrire(&rep, "1-2-0", "pas une entree\n").unwrap();
            let e = entrees(&rep, &ici).unwrap_err().to_string();
            assert!(
                e.contains("entree illisible") && e.contains("montage refuse"),
                "{e}"
            );
            effacer_dans(&rep, "1-2-0").unwrap();
            ecrire(&rep, "1-2-0", &entree("cookie-0", 9, 2).ecrire()).unwrap();
            let e = entrees(&rep, &ici).unwrap_err().to_string();
            assert!(e.contains("ne designe pas son processus"), "{e}");
            effacer_dans(&rep, "1-2-0").unwrap();
            assert!(entrees(&rep, &ici).unwrap().is_empty());
            std::fs::set_permissions(&rep, std::fs::Permissions::from_mode(0o777)).unwrap();
            let e = entrees(&rep, &ici).unwrap_err().to_string();
            assert!(e.contains("ferme en ecriture"), "{e}");
            std::fs::remove_dir_all(&rep).unwrap();
        }

        /// Ce processus est vivant a sa date de debut, pas a une autre; un
        /// PID que le noyau ne donne pas n'est pas vivant.
        #[test]
        fn la_vivacite_se_lit_par_pid_et_date_de_debut() {
            let (pid, debut) = moi().unwrap();
            assert_eq!(pid, std::process::id());
            assert!(vivant(pid, debut).unwrap());
            assert!(!vivant(pid, debut + 1).unwrap());
            assert!(!vivant(u32::MAX, debut).unwrap());
        }

        /// Une session de ce processus est vivante tant qu'elle est tenue, et
        /// morte des qu'elle ne l'est plus, sans toucher au noyau.
        #[test]
        fn une_session_de_ce_processus_est_vivante_tant_qu_elle_est_tenue() {
            let (pid, debut) = moi().unwrap();
            let e = entree(&reseau_courant().unwrap(), pid, debut);
            let mut m = Reel {
                rep: chemin_de_recette("tenue"),
            };
            let nom = format!("{pid}-{debut}-9999");
            assert!(!m.juger(&nom, &e).unwrap().vivante);
            tenues().push(nom.clone());
            assert!(m.juger(&nom, &e).unwrap().vivante);
            tenues().retain(|n| n != &nom);
            assert!(!m.juger(&nom, &e).unwrap().vivante);
        }

        /// La session d'un autre processus vit tant que ce processus tourne,
        /// a sa date de debut, et meurt avec lui. Le processus est tue et
        /// attendu avant tout constat, pour qu'un echec ne le laisse pas.
        #[test]
        fn la_session_d_un_autre_processus_vit_et_meurt_avec_lui() {
            let mut enfant = std::process::Command::new("sleep")
                .arg("30")
                .spawn()
                .expect("lancement de sleep");
            let pid = enfant.id();
            let debut = std::fs::read_to_string(format!("/proc/{pid}/stat"))
                .ok()
                .and_then(|s| super::super::etat_et_debut(&s))
                .map(|(_, d)| d);
            let ici = reseau_courant().unwrap();
            let mut m = Reel {
                rep: chemin_de_recette("autre"),
            };
            let nom = format!("{pid}-0-0");
            let mut juger = |d: u64| m.juger(&nom, &entree(&ici, pid, d)).map(|s| s.vivante);
            let vivante = debut.map(&mut juger);
            let autre_date = debut.map(|d| juger(d + 1));
            enfant.kill().expect("arret de sleep");
            enfant.wait().expect("attente de sleep");
            let finie = debut.map(&mut juger);
            let debut = debut.expect("date de debut de sleep");
            assert!(vivante.unwrap().unwrap(), "{pid} a {debut}");
            assert!(!autre_date.unwrap().unwrap(), "{pid} a {}", debut + 1);
            assert!(!finie.unwrap().unwrap(), "{pid} fini");
        }

        /// Ouvrir une session l'inscrit au journal avant toute pose, et la
        /// tient: relue dans ce namespace reseau, elle est de ce processus,
        /// de son plan, et vivante; abandonnee, elle reste au journal, morte.
        #[test]
        fn ouvrir_inscrit_la_session_avant_toute_pose() {
            let rep = repertoire_de_recette("ouvrir");
            let ici = reseau_courant().unwrap();
            let plan = Plan::coeur("bftun0", None);
            let s = Session::ouvrir_dans(&rep, &plan, None).unwrap();
            assert_eq!(
                entrees(&rep, &ici).unwrap(),
                [(s.nom.clone(), s.entree.clone())]
            );
            assert_eq!(s.entree.plan(), plan);
            assert_eq!((s.entree.pid, s.entree.debut), moi().unwrap());
            let mut m = Reel { rep: rep.clone() };
            assert!(m.juger(&s.nom, &s.entree).unwrap().vivante);
            let (nom, entree) = (s.nom.clone(), s.entree.clone());
            drop(s);
            assert_eq!(entrees(&rep, &ici).unwrap().len(), 1);
            assert!(!m.juger(&nom, &entree).unwrap().vivante);
            std::fs::remove_dir_all(&rep).unwrap();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bifrost_core::routage::{Famille, TABLE_MAIN};

    /// Une cle de documentation: le 43e caractere ne porte que quatre bits
    /// utiles, 'A' (zero) termine n'importe quelle cle.
    fn cle_a() -> String {
        "a".repeat(42) + "A="
    }

    fn entree_wg(interface: &str, marque: u32, table: u32, priorites: [Option<u32>; 4]) -> Entree {
        Entree {
            pid: 4242,
            debut: 77,
            reseau: "cookie-12".into(),
            chemin: Chemin::WireGuard { marque, table },
            interface: interface.into(),
            cle: Some(cle_a()),
            priorites: priorites.to_vec(),
        }
    }

    fn entree_coeur(compte: Option<u32>) -> Entree {
        let plan = Plan::coeur("bftun0", compte);
        Entree {
            pid: 4243,
            debut: 78,
            reseau: "cookie-12".into(),
            chemin: Chemin::Coeur { compte },
            interface: "bftun0".into(),
            cle: None,
            priorites: plan.regles_posees().iter().map(|r| r.priorite).collect(),
        }
    }

    /// Les objets que le plan pose, tels que le noyau les rend, a ces
    /// priorites (pour les regles sans priorite fixe) et vers l'interface
    /// `index`.
    fn pose(plan: &Plan, priorites: &[u32], index: u32) -> Etat {
        let regles = plan
            .regles_posees()
            .iter()
            .enumerate()
            .map(|(i, r)| RegleLue {
                famille: r.famille,
                priorite: r.priorite.unwrap_or_else(|| priorites[i]),
                table: Some(r.consultation.table()),
                marque: match r.selecteur {
                    Selecteur::HorsMarque(m) => Some((m, u32::MAX)),
                    _ => None,
                },
                protocole: PROTOCOLE_PRODUIT,
                forme: Some((r.selecteur, r.consultation)),
            })
            .collect();
        let routes = plan
            .routes_posees()
            .iter()
            .map(|r| RouteLue {
                famille: r.famille,
                table: r.table,
                protocole: PROTOCOLE_PRODUIT,
                par_defaut_vers: Some(index),
            })
            .collect();
        (regles, routes)
    }

    fn regle_lan_tierce(famille: Famille, priorite: u32) -> RegleLue {
        RegleLue {
            famille,
            priorite,
            table: Some(TABLE_MAIN),
            marque: None,
            protocole: PROTOCOLE_PRODUIT,
            forme: Some((Selecteur::Tout, Consultation::MainSansDefaut)),
        }
    }

    // --- le format -----------------------------------------------------

    #[test]
    fn une_entree_se_relit_telle_qu_elle_s_ecrit() {
        for e in [
            entree_wg("bfwg0", 51820, 51820, [None; 4]),
            entree_wg(
                "bf-wg_9",
                0x1f2e3d,
                30303,
                [Some(32765), None, Some(32763), Some(32762)],
            ),
            entree_coeur(Some(4242)),
            entree_coeur(None),
        ] {
            let texte = e.ecrire();
            assert!(texte.is_ascii() && texte.ends_with('\n'), "{texte}");
            assert_eq!(Entree::lire(&texte).as_ref(), Ok(&e), "{texte}");
        }
        assert_eq!(
            entree_coeur(Some(4242)).ecrire(),
            "bifrost-session-routage 1\npid 4243\ndebut 78\nreseau cookie-12\n\
             chemin coeur\ninterface bftun0\ncompte 4242\n\
             priorites 9100 9110 9120 9100 9110 9120\n"
        );
    }

    /// Chaque ecart au format est refuse: une entree que le produit ne
    /// comprend pas n'explique rien.
    #[test]
    fn chaque_ecart_au_format_est_refuse() {
        let bon = entree_wg("bfwg0", 51820, 51820, [Some(1), Some(2), Some(3), Some(4)]).ecrire();
        let coeur = entree_coeur(Some(4242)).ecrire();
        let mutations: Vec<(&str, String)> = vec![
            ("sans fin de ligne", bon.trim_end().to_owned()),
            ("en-tete", bon.replace("routage 1", "routage 2")),
            ("pid", bon.replace("pid 4242", "pid -1")),
            ("pid a zero de tete", bon.replace("pid 4242", "pid 04242")),
            ("pid signe", bon.replace("pid 4242", "pid +4242")),
            ("debut", bon.replace("debut 77", "debut x")),
            ("reseau", bon.replace("cookie-12", "cookie/12")),
            ("chemin", bon.replace("chemin wireguard", "chemin autre")),
            (
                "interface",
                bon.replace("interface bfwg0", "interface bf wg0"),
            ),
            (
                "interface longue",
                bon.replace("interface bfwg0", "interface bfwg0123456789ab"),
            ),
            ("table reservee", bon.replace("table 51820", "table 254")),
            ("cle", bon.replace(&cle_a(), "pas-une-cle")),
            (
                "priorites en moins",
                bon.replace("priorites 1 2 3 4", "priorites 1 2 3"),
            ),
            (
                "priorites en trop",
                bon.replace("priorites 1 2 3 4", "priorites 1 2 3 4 5"),
            ),
            (
                "priorite",
                bon.replace("priorites 1 2 3 4", "priorites 1 2 3 x"),
            ),
            ("ligne en trop", format!("{bon}autre 1\n")),
            ("champ manquant", bon.replace("marque 51820\n", "")),
            (
                "champs inverses",
                bon.replace("pid 4242\ndebut 77", "debut 77\npid 4242"),
            ),
            (
                "priorite fixe changee",
                coeur.replace("9100 9110", "9100 9111"),
            ),
            (
                "priorite fixe inconnue",
                coeur.replace("9100 9110", "9100 ?"),
            ),
            ("compte", coeur.replace("compte 4242", "compte quelqu'un")),
        ];
        for (nom, texte) in mutations {
            assert!(Entree::lire(&texte).is_err(), "{nom} accepte:\n{texte}");
        }
        assert!(Entree::lire(&bon).is_ok());
        assert!(Entree::lire(&coeur).is_ok());
    }

    #[test]
    fn l_etat_et_la_date_de_debut_se_lisent_apres_le_nom_du_programme() {
        let mut champs = vec!["S"; 1];
        champs.extend(std::iter::repeat_n("0", 18));
        champs.push("123456");
        champs.extend(["7", "8"]);
        let reste = champs.join(" ");
        assert_eq!(
            etat_et_debut(&format!("17 (bifrost) daemon) {reste}")),
            Some(('S', 123456))
        );
        assert_eq!(
            etat_et_debut(&format!("17 (a b) {}", reste.replacen('S', "Z", 1))),
            Some(('Z', 123456))
        );
        assert_eq!(etat_et_debut("17 (tronque) S 1 2"), None);
        assert_eq!(etat_et_debut("sans parenthese"), None);
    }

    // --- l'attribution ---------------------------------------------------

    fn inscrite(nom: &str, entree: Entree, vivante: bool, index: Option<u32>) -> Inscrite {
        Inscrite {
            nom: nom.into(),
            entree,
            vivante,
            index,
        }
    }

    /// Une session WireGuard relevee: ses quatre regles a leurs priorites,
    /// ses deux routes vers son interface. La regle du LAN d'un tiers, meme
    /// forme et meme etiquette a une autre priorite, reste inexpliquee.
    #[test]
    fn une_session_relevee_n_explique_que_ce_qu_elle_a_pose() {
        let prios = [32765, 32764, 32763, 32762];
        let e = entree_wg("bfwg0", 51820, 51820, prios.map(Some));
        let (mut regles, routes) = pose(&e.plan(), &prios, 7);
        regles.push(regle_lan_tierce(Famille::Ipv4, 32761));
        let s = inscrite("a", e, false, Some(7));
        let a = attribuer(&[&s], &regles, &routes);
        assert_eq!(a.presences[0].regles, prios.map(Some));
        assert_eq!(a.presences[0].routes, [true, true]);
        assert_eq!(a.inexpliques.len(), 1, "{a:?}");
        assert!(a.inexpliques[0].contains("32761"), "{a:?}");
        assert_eq!(
            a.exemple.as_deref(),
            Some("ip -4 rule del pref 32761 protocol 177")
        );
    }

    /// Sans interface a elle, une session n'a pas de route: une route vers
    /// une autre interface, ou vers la sienne reprise par un autre, est
    /// inexpliquee.
    #[test]
    fn une_route_n_est_a_la_session_que_vers_son_interface() {
        let prios = [32765, 32764, 32763, 32762];
        let e = entree_wg("bfwg0", 51820, 51820, prios.map(Some));
        let (regles, routes) = pose(&e.plan(), &prios, 7);
        for index in [None, Some(8)] {
            let s = inscrite("a", e.clone(), false, index);
            let a = attribuer(&[&s], &regles, &routes);
            assert_eq!(a.presences[0].routes, [false, false]);
            assert_eq!(a.inexpliques.len(), 2, "{a:?}");
        }
    }

    /// Priorites inconnues: chaque regle posee sans priorite relevee recoit
    /// une regle de sa forme, tant qu'il n'y en a pas plus que de regles
    /// posees; au-dela, aucune n'est attribuee et la forme est ambigue.
    #[test]
    fn une_priorite_inconnue_n_attribue_que_sans_ambiguite() {
        let prios = [32765, 32764, 32763, 32762];
        let e = entree_wg("bfwg0", 51820, 51820, [None; 4]);
        let (mut regles, routes) = pose(&e.plan(), &prios, 7);
        let s = inscrite("a", e.clone(), false, Some(7));
        let a = attribuer(&[&s], &regles, &routes);
        assert_eq!(a.presences[0].regles, prios.map(Some));
        assert!(a.inexpliques.is_empty() && a.ambigus.is_empty(), "{a:?}");
        regles.push(regle_lan_tierce(Famille::Ipv6, 32700));
        let a = attribuer(&[&s], &regles, &routes);
        assert_eq!(
            a.presences[0].regles,
            [Some(32765), Some(32764), Some(32763), None]
        );
        assert_eq!(a.ambigus.len(), 1, "{a:?}");
        assert!(a.ambigus[0].starts_with("ipv6: 2 regle(s)"), "{a:?}");
        assert_eq!(a.inexpliques.len(), 2, "{a:?}");
        // Deux sessions mortes sans releve, deux regles du LAN par famille:
        // une chacune.
        let e2 = entree_wg("bfwg1", 51821, 51821, [None; 4]);
        let (r2, t2) = pose(&e2.plan(), &[32761, 32760, 32759, 32758], 8);
        let (mut regles, mut routes) = pose(&e.plan(), &prios, 7);
        regles.extend(r2);
        routes.extend(t2);
        let s2 = inscrite("b", e2, false, Some(8));
        let a = attribuer(&[&s, &s2], &regles, &routes);
        assert!(a.inexpliques.is_empty() && a.ambigus.is_empty(), "{a:?}");
        assert!(
            a.presences
                .iter()
                .all(|p| p.regles.iter().all(Option::is_some))
        );
    }

    /// Le coeur: priorites fixes. Une regle tierce a l'etiquette a la
    /// priorite du LAN mais vers une autre table n'est pas la sienne.
    #[test]
    fn le_coeur_n_explique_que_ses_formes_a_ses_priorites() {
        let e = entree_coeur(Some(4242));
        let (mut regles, routes) = pose(&e.plan(), &[], 3);
        regles.push(RegleLue {
            forme: Some((Selecteur::Tout, Consultation::Table(100))),
            table: Some(100),
            ..regle_lan_tierce(Famille::Ipv4, 9120)
        });
        let s = inscrite("c", e, false, None);
        let a = attribuer(&[&s], &regles, &routes);
        assert!(a.presences[0].regles.iter().all(Option::is_some), "{a:?}");
        assert_eq!(a.presences[0].routes, [false, false]);
        // Les routes vers le TUN mort et la regle du tiers.
        assert_eq!(a.inexpliques.len(), 3, "{a:?}");
    }

    #[test]
    fn la_releve_rend_la_priorite_de_l_unique_regle_de_chaque_forme() {
        let plan = Plan::wireguard("bfwg0", 51820, 51820);
        let (mut regles, _) = pose(&plan, &[32765, 32764, 32763, 32762], 7);
        assert_eq!(
            relever(&plan, &regles),
            [Some(32765), Some(32764), Some(32763), Some(32762)]
        );
        regles.push(regle_lan_tierce(Famille::Ipv4, 32700));
        assert_eq!(
            relever(&plan, &regles),
            [Some(32765), None, Some(32763), Some(32762)]
        );
        assert_eq!(relever(&plan, &[]), [None; 4]);
        let coeur = Plan::coeur("bftun0", None);
        assert_eq!(
            relever(&coeur, &[]),
            [Some(9110), Some(9120), Some(9110), Some(9120)]
        );
    }

    // --- le montage et le demontage, sans noyau --------------------------

    /// Un monde de recette: un noyau en memoire, un journal en memoire. Le
    /// retrait retire du noyau ce que les commandes de retrait designeraient,
    /// par la meme correspondance que le noyau (`Regle::designe` a la
    /// priorite donnee, `RouteParDefaut::designe`).
    #[derive(Default)]
    struct Recette {
        regles: Vec<RegleLue>,
        routes: Vec<RouteLue>,
        journal: Vec<Inscrite>,
        retraits: Vec<String>,
        effaces: Vec<String>,
        /// Le retrait ne fait rien: un noyau qui refuse.
        sourd: bool,
        lecture_impossible: bool,
    }

    impl Monde for Recette {
        fn journal(&self) -> String {
            "/run/bifrost/routage".into()
        }

        fn lire(&mut self) -> Result<Etat> {
            if self.lecture_impossible {
                return Err(Error::Tunnel("lecture impossible".into()));
            }
            Ok((self.regles.clone(), self.routes.clone()))
        }

        fn inscrites(&mut self) -> Result<Vec<Inscrite>> {
            Ok(self.journal.clone())
        }

        fn juger(&mut self, nom: &str, _: &Entree) -> Result<Inscrite> {
            Ok(self
                .journal
                .iter()
                .find(|s| s.nom == nom)
                .cloned()
                .expect("session de la recette"))
        }

        fn retirer(&mut self, s: &Inscrite, p: &Presence) -> Result<()> {
            self.retraits.push(s.nom.clone());
            if self.sourd {
                return Ok(());
            }
            let plan = s.entree.plan();
            for (r, lue) in plan.regles_posees().iter().zip(&p.regles) {
                if let Some(prio) = lue
                    && let Some(k) = self.regles.iter().position(|l| r.designe(l, Some(*prio)))
                {
                    self.regles.remove(k);
                }
            }
            for (r, la) in plan.routes_posees().iter().zip(&p.routes) {
                if *la && let Some(k) = self.routes.iter().position(|l| r.designe(l, s.index)) {
                    self.routes.remove(k);
                }
            }
            if s.lien_a_retirer() {
                for i in self.journal.iter_mut().filter(|i| i.nom == s.nom) {
                    i.index = None;
                }
            }
            Ok(())
        }

        fn effacer(&mut self, nom: &str) -> Result<()> {
            self.effaces.push(nom.into());
            self.journal.retain(|s| s.nom != nom);
            Ok(())
        }
    }

    fn wg_defaut() -> Plan {
        Plan::wireguard("bfwg0", 51820, 51820)
    }

    #[test]
    fn une_voie_libre_se_prepare_sans_rien_retirer() {
        let mut m = Recette::default();
        preparer_avec(&wg_defaut(), &mut m).unwrap();
        assert!(m.retraits.is_empty() && m.effaces.is_empty());
    }

    /// Des objets a l'etiquette du produit qu'aucune session n'a inscrits
    /// (un tiers, ou un journal disparu): refus nomme, rien de retire.
    #[test]
    fn des_objets_a_l_etiquette_sans_session_sont_refuses_sans_rien_retirer() {
        let (regles, routes) = pose(&wg_defaut(), &[32765, 32764, 32763, 32762], 9);
        let mut m = Recette {
            regles: regles.clone(),
            routes: routes.clone(),
            ..Recette::default()
        };
        let e = preparer_avec(&wg_defaut(), &mut m).unwrap_err().to_string();
        assert!(
            e.contains("montage refuse") && e.contains("protocole 177") && e.contains("6 regle(s)"),
            "{e}"
        );
        assert!(e.contains("Rien n'est retire ni pose"), "{e}");
        assert!(m.retraits.is_empty() && m.effaces.is_empty());
        assert_eq!((m.regles, m.routes), (regles, routes));
    }

    /// Une autre session vivante: refus nomme, rien de retire, meme si elle
    /// a pose sur une autre table.
    #[test]
    fn une_session_vivante_est_refusee_sans_rien_retirer() {
        let e = entree_wg(
            "bfwg1",
            51821,
            51821,
            [Some(32765), Some(32764), Some(32763), Some(32762)],
        );
        let (regles, routes) = pose(&e.plan(), &[32765, 32764, 32763, 32762], 9);
        let mut m = Recette {
            regles,
            routes,
            journal: vec![inscrite("b", e, true, Some(9))],
            ..Recette::default()
        };
        let e = preparer_avec(&wg_defaut(), &mut m).unwrap_err().to_string();
        assert!(
            e.contains("autre session du produit") && e.contains("bfwg1"),
            "{e}"
        );
        assert!(m.retraits.is_empty() && m.effaces.is_empty());
    }

    /// Des sessions mortes (un autre profil WireGuard, un coeur): tout ce
    /// qu'elles ont pose est retire, leurs entrees effacees, et la voie est
    /// libre. Ce qui ne porte pas l'etiquette reste.
    #[test]
    fn les_sessions_mortes_sont_retirees_exactement() {
        let prios = [32765, 32764, 32763, 32762];
        let wg = entree_wg("bfwg1", 51821, 51821, prios.map(Some));
        let coeur = entree_coeur(Some(4242));
        let (mut regles, mut routes) = pose(&wg.plan(), &prios, 9);
        let (r2, _) = pose(&coeur.plan(), &[], 3);
        regles.extend(r2);
        let neutre = RegleLue {
            protocole: 3,
            ..regle_lan_tierce(Famille::Ipv4, 32700)
        };
        regles.push(neutre);
        let premiere = routes[0];
        routes.push(RouteLue {
            protocole: 3,
            ..premiere
        });
        let mut m = Recette {
            regles,
            routes: routes.clone(),
            journal: vec![
                inscrite("b", wg, false, Some(9)),
                inscrite("c", coeur, false, None),
            ],
            ..Recette::default()
        };
        // La route non etiquetee occupe la table 51821, pas celle du profil.
        preparer_avec(&wg_defaut(), &mut m).unwrap();
        assert_eq!(m.retraits, ["b", "c"]);
        assert_eq!(m.effaces, ["b", "c"]);
        assert_eq!(m.regles, [neutre]);
        assert_eq!(m.routes, [routes[2]]);
    }

    /// Une session morte et un tiers a l'etiquette: refus, et la session
    /// morte n'est pas retiree non plus.
    #[test]
    fn un_objet_inexplique_empeche_aussi_le_retrait_des_sessions_mortes() {
        let prios = [32765, 32764, 32763, 32762];
        let wg = entree_wg("bfwg0", 51820, 51820, prios.map(Some));
        let (mut regles, routes) = pose(&wg.plan(), &prios, 9);
        regles.push(regle_lan_tierce(Famille::Ipv4, 32761));
        let mut m = Recette {
            regles,
            routes,
            journal: vec![inscrite("a", wg, false, Some(9))],
            ..Recette::default()
        };
        let e = preparer_avec(&wg_defaut(), &mut m).unwrap_err().to_string();
        assert!(e.contains("32761") && e.contains("montage refuse"), "{e}");
        assert!(m.retraits.is_empty() && m.effaces.is_empty());
    }

    /// Un retrait qui n'aboutit pas: refus, et les entrees restent au
    /// journal pour le montage suivant.
    #[test]
    fn un_retrait_qui_n_aboutit_pas_garde_les_entrees() {
        let prios = [32765, 32764, 32763, 32762];
        let wg = entree_wg("bfwg0", 51820, 51820, prios.map(Some));
        let (regles, routes) = pose(&wg.plan(), &prios, 9);
        let mut m = Recette {
            regles,
            routes,
            journal: vec![inscrite("a", wg, false, Some(9))],
            sourd: true,
            ..Recette::default()
        };
        let e = preparer_avec(&wg_defaut(), &mut m).unwrap_err().to_string();
        assert!(
            e.contains("n'a pas abouti") && e.contains("session a"),
            "{e}"
        );
        assert_eq!(m.retraits, ["a"]);
        assert!(m.effaces.is_empty());
    }

    /// Apres le retrait des sessions mortes, un tiers sans etiquette dans
    /// la table du profil: refus d'occupation.
    #[test]
    fn l_occupation_par_un_tiers_est_jugee_apres_le_retrait() {
        let mut m = Recette {
            routes: vec![RouteLue {
                famille: Famille::Ipv6,
                table: 51820,
                protocole: 3,
                par_defaut_vers: Some(4),
            }],
            ..Recette::default()
        };
        let e = preparer_avec(&wg_defaut(), &mut m).unwrap_err().to_string();
        assert!(e.contains("ipv6: 1 route(s) dans la table 51820"), "{e}");
    }

    #[test]
    fn une_lecture_impossible_empeche_le_montage() {
        let mut m = Recette {
            lecture_impossible: true,
            ..Recette::default()
        };
        assert!(preparer_avec(&wg_defaut(), &mut m).is_err());
    }

    /// Le demontage ne retire que ce qui est a la session: la regle du LAN
    /// qu'un tiers pose apres elle, a l'etiquette, reste.
    #[test]
    fn le_demontage_ne_retire_que_la_session() {
        let prios = [32765, 32764, 32763, 32762];
        let wg = entree_wg("bfwg0", 51820, 51820, prios.map(Some));
        let (mut regles, routes) = pose(&wg.plan(), &prios, 9);
        let tiers = regle_lan_tierce(Famille::Ipv4, 32761);
        regles.insert(0, tiers);
        let mut m = Recette {
            regles,
            routes,
            journal: vec![inscrite("a", wg.clone(), true, Some(9))],
            ..Recette::default()
        };
        demonter_avec("a", &wg, &mut m).unwrap();
        assert_eq!(m.regles, [tiers]);
        assert!(m.routes.is_empty());
        assert_eq!(m.effaces, ["a"]);
    }

    /// Une forme ambigue au demontage: rien n'est retire, l'entree reste.
    #[test]
    fn un_demontage_ambigu_ne_retire_rien() {
        let prios = [32765, 32764, 32763, 32762];
        let wg = entree_wg(
            "bfwg0",
            51820,
            51820,
            [Some(32765), None, Some(32763), Some(32762)],
        );
        let (mut regles, routes) = pose(&wg.plan(), &prios, 9);
        regles.push(regle_lan_tierce(Famille::Ipv4, 32761));
        let mut m = Recette {
            regles,
            routes,
            journal: vec![inscrite("a", wg.clone(), true, Some(9))],
            ..Recette::default()
        };
        let e = demonter_avec("a", &wg, &mut m).unwrap_err().to_string();
        assert!(
            e.contains("demontage incomplet") && e.contains("ipv4: 2 regle(s)"),
            "{e}"
        );
        assert!(m.retraits.is_empty() && m.effaces.is_empty());
    }

    /// Un demontage dont le retrait n'aboutit pas garde l'entree.
    #[test]
    fn un_demontage_qui_n_aboutit_pas_garde_l_entree() {
        let prios = [32765, 32764, 32763, 32762];
        let wg = entree_wg("bfwg0", 51820, 51820, prios.map(Some));
        let (regles, routes) = pose(&wg.plan(), &prios, 9);
        let mut m = Recette {
            regles,
            routes,
            journal: vec![inscrite("a", wg.clone(), true, Some(9))],
            sourd: true,
            ..Recette::default()
        };
        let e = demonter_avec("a", &wg, &mut m).unwrap_err().to_string();
        assert!(
            e.contains("demontage incomplet") && e.contains("4 regle(s), 2 route(s)"),
            "{e}"
        );
        assert!(e.contains("l'interface bfwg0"), "{e}");
        assert!(m.effaces.is_empty());
    }
}
