//! Ce qu'une lecture du moteur WFP rend, en donnee pure.
//!
//! Le collecteur (`windows::lecture`) recopie ici ce que la Base Filtering
//! Engine rend dans UNE transaction en lecture seule: les sous-couches, et TOUS
//! les filtres des quatre couches ALE du plan, qu'ils soient de Bifrost ou non.
//! Rien n'y est interprete. C'est la preuve (`bifrost-cli prove wfp`) qui
//! compare les filtres de Bifrost a la reference et arbitre ceux des autres.
//!
//! Etre pur sert deux fois: les recettes jouent un enumerateur factice sur les
//! deux hotes, et le collecteur, seul code non sur de la chaine, ne fait que
//! recopier.
//!
//! Les identites (`ALE_USER_ID`) arrivent en descripteur de securite binaire.
//! Elles se comparent par leur liste de controle d'acces lue ici, jamais par une
//! forme textuelle: un meme SID a plusieurs ecritures, et comparer des chaines
//! a deja laisse passer un SID a zeros de tete devant une liste noire.

use crate::wfp_plan::Layer;

/// Un instantane du moteur.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Instantane {
    /// Le fournisseur du kill switch existe-t-il comme objet du moteur.
    pub fournisseur_bifrost: bool,
    /// Toutes les sous-couches du moteur.
    pub sous_couches: Vec<SousCoucheVue>,
    /// Tous les filtres des quatre couches du plan, desactives compris.
    pub filtres: Vec<FiltreVu>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SousCoucheVue {
    pub cle: u128,
    pub poids: u16,
    pub fournisseur: Option<u128>,
}

/// Un filtre tel que BFE le rend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FiltreVu {
    pub couche: Layer,
    pub sous_couche: u128,
    pub fournisseur: Option<u128>,
    /// Le champ `weight` rendu: la plage 0-15 quand le filtre a ete pose en
    /// `FWP_UINT8`, comme ceux de Bifrost.
    pub poids: ValeurVue,
    /// Le champ `effectiveWeight`: le poids 64 bits que BFE a attribue, dont
    /// les quatre bits de tete sont la plage.
    pub poids_effectif: ValeurVue,
    pub action: u32,
    pub drapeaux: u32,
    pub conditions: Vec<ConditionVue>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConditionVue {
    pub champ: u128,
    pub correspondance: u32,
    pub valeur: ValeurVue,
}

/// Valeur d'une condition ou d'un poids, par type WFP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValeurVue {
    Vide,
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    V4 {
        adresse: u32,
        masque: u32,
    },
    V6 {
        adresse: [u8; 16],
        prefixe: u8,
    },
    /// `FWP_BYTE_BLOB_TYPE`: l'identifiant d'application, entre autres.
    Octets(Vec<u8>),
    /// `FWP_SECURITY_DESCRIPTOR_TYPE`: un descripteur auto-relatif.
    Descripteur(Vec<u8>),
    /// Tout autre type, par son code: la preuve ne l'interprete pas, et un
    /// filtre de Bifrost qui en porterait un ne correspond a rien d'attendu.
    Autre(i32),
}

/// Un SID, sous forme structuree. Revision 1 seulement.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Sid {
    pub autorite: u64,
    pub sous_autorites: Vec<u32>,
}

/// Borne de Windows (`SID_MAX_SUB_AUTHORITIES`).
const MAX_SOUS_AUTORITES: usize = 15;
const AUTORITE_MAX: u64 = (1 << 48) - 1;

impl Sid {
    /// Lit la forme textuelle CANONIQUE, `S-1-<autorite>-<n>...`, en decimal
    /// sans zero de tete, au plus quinze sous-autorites et au moins une.
    ///
    /// Toute autre ecriture est refusee plutot que normalisee: une declaration
    /// qui porte une forme inhabituelle n'est pas une forme que le moteur a
    /// produite, et la preuve n'a pas a deviner ce qu'elle voulait dire.
    pub fn lire_texte(texte: &str) -> Option<Sid> {
        let reste = texte.strip_prefix("S-1-")?;
        let mut parts = reste.split('-');
        let autorite = decimal(parts.next()?)?;
        if autorite > AUTORITE_MAX {
            return None;
        }
        let mut sous_autorites = Vec::new();
        for p in parts {
            sous_autorites.push(u32::try_from(decimal(p)?).ok()?);
        }
        if sous_autorites.is_empty() || sous_autorites.len() > MAX_SOUS_AUTORITES {
            return None;
        }
        Some(Sid {
            autorite,
            sous_autorites,
        })
    }

    /// La forme textuelle canonique.
    pub fn texte(&self) -> String {
        let mut s = format!("S-1-{}", self.autorite);
        for a in &self.sous_autorites {
            s.push_str(&format!("-{a}"));
        }
        s
    }

    /// La forme binaire: revision, nombre, autorite sur six octets gros
    /// boutistes, sous-autorites petits boutistes.
    pub fn octets(&self) -> Vec<u8> {
        let mut o = vec![1, self.sous_autorites.len() as u8];
        o.extend_from_slice(&self.autorite.to_be_bytes()[2..]);
        for a in &self.sous_autorites {
            o.extend_from_slice(&a.to_le_bytes());
        }
        o
    }

    /// Lit un SID binaire au debut de `o`, et rend sa longueur.
    pub fn lire_octets(o: &[u8]) -> Option<(Sid, usize)> {
        if o.len() < 8 || o[0] != 1 {
            return None;
        }
        let n = o[1] as usize;
        if n > MAX_SOUS_AUTORITES {
            return None;
        }
        let longueur = 8 + 4 * n;
        if o.len() < longueur {
            return None;
        }
        let mut autorite = [0u8; 8];
        autorite[2..].copy_from_slice(&o[2..8]);
        let sous_autorites = (0..n)
            .map(|i| {
                let d = 8 + 4 * i;
                u32::from_le_bytes([o[d], o[d + 1], o[d + 2], o[d + 3]])
            })
            .collect();
        Some((
            Sid {
                autorite: u64::from_be_bytes(autorite),
                sous_autorites,
            },
            longueur,
        ))
    }
}

fn decimal(s: &str) -> Option<u64> {
    if s.is_empty() || s.len() > 20 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if s.len() > 1 && s.starts_with('0') {
        return None;
    }
    s.parse().ok()
}

/// Une entree de controle d'acces.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Ace {
    /// Autorisation ou refus d'acces (types 0 et 1), lus en entier.
    Acces {
        genre: u8,
        drapeaux: u8,
        masque: u32,
        sid: Sid,
    },
    /// Tout autre type, garde tel quel: il ne ressemble a rien d'attendu.
    Autre {
        genre: u8,
        drapeaux: u8,
        corps: Vec<u8>,
    },
}

pub const ACE_AUTORISATION: u8 = 0;
const ACE_REFUS: u8 = 1;

/// La liste de controle d'acces discretionnaire d'un descripteur.
///
/// Trois etats, parce que les deux premiers ne sont PAS une liste vide: un
/// descripteur sans liste, ou avec une liste nulle, accorde tout a tout le
/// monde. Pour une condition `ALE_USER_ID`, c'est un filtre qui correspond a
/// n'importe quel processus.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Dacl {
    Absente,
    Nulle,
    Liste(Vec<Ace>),
}

const SE_DACL_PRESENT: u16 = 0x0004;
const SE_SELF_RELATIVE: u16 = 0x8000;

/// Lit la liste discretionnaire d'un descripteur AUTO-RELATIF, seule forme
/// qu'un moteur rend. Proprietaire, groupe et liste d'audit sont ignores: le
/// controle d'acces que WFP fait pour une condition d'identite ne lit que la
/// liste discretionnaire. `None` si la moindre borne deborde.
pub fn lire_dacl(o: &[u8]) -> Option<Dacl> {
    if o.len() < 20 || o[0] != 1 {
        return None;
    }
    let controle = u16::from_le_bytes([o[2], o[3]]);
    if controle & SE_SELF_RELATIVE == 0 {
        return None;
    }
    if controle & SE_DACL_PRESENT == 0 {
        return Some(Dacl::Absente);
    }
    let debut = u32::from_le_bytes([o[16], o[17], o[18], o[19]]) as usize;
    if debut == 0 {
        return Some(Dacl::Nulle);
    }
    let acl = o.get(debut..)?;
    if acl.len() < 8 || !matches!(acl[0], 2 | 4) {
        return None;
    }
    let taille = u16::from_le_bytes([acl[2], acl[3]]) as usize;
    let nombre = u16::from_le_bytes([acl[4], acl[5]]) as usize;
    if taille < 8 || taille > acl.len() {
        return None;
    }
    let acl = &acl[..taille];
    let mut entrees = Vec::with_capacity(nombre);
    let mut d = 8usize;
    for _ in 0..nombre {
        let tete = acl.get(d..d + 4)?;
        let (genre, drapeaux) = (tete[0], tete[1]);
        let longueur = u16::from_le_bytes([tete[2], tete[3]]) as usize;
        if longueur < 4 {
            return None;
        }
        let corps = acl.get(d + 4..d + longueur)?;
        entrees.push(if matches!(genre, ACE_AUTORISATION | ACE_REFUS) {
            let masque = u32::from_le_bytes(corps.get(..4)?.try_into().ok()?);
            let (sid, lu) = Sid::lire_octets(corps.get(4..)?)?;
            // Le reste de l'entree n'est que du bourrage d'alignement.
            if 4 + lu > corps.len() {
                return None;
            }
            Ace::Acces {
                genre,
                drapeaux,
                masque,
                sid,
            }
        } else {
            Ace::Autre {
                genre,
                drapeaux,
                corps: corps.to_vec(),
            }
        });
        d += longueur;
    }
    Some(Dacl::Liste(entrees))
}

/// Descripteur auto-relatif dont la liste n'accorde qu'a `sid` le masque
/// `masque`, sans proprietaire ni groupe: la forme binaire de
/// `D:(A;;<masque>;;;<sid>)`, celle que le produit construit.
///
/// Sert aux recettes (l'enumerateur factice doit rendre ce qu'un moteur
/// rendrait) et a nommer la forme attendue; une recette Windows la confronte au
/// descripteur que `ConvertStringSecurityDescriptorToSecurityDescriptorW`
/// produit reellement.
pub fn descripteur_autorisant(sid: &Sid, masque: u32) -> Vec<u8> {
    let sid = sid.octets();
    let ace_longueur = 8 + sid.len();
    let acl_longueur = 8 + ace_longueur;
    let mut o = vec![1u8, 0];
    o.extend_from_slice(&(SE_SELF_RELATIVE | SE_DACL_PRESENT).to_le_bytes());
    o.extend_from_slice(&[0u8; 12]);
    o.extend_from_slice(&20u32.to_le_bytes());
    o.extend_from_slice(&[2u8, 0]);
    o.extend_from_slice(&(acl_longueur as u16).to_le_bytes());
    o.extend_from_slice(&1u16.to_le_bytes());
    o.extend_from_slice(&[0u8, 0]);
    o.extend_from_slice(&[ACE_AUTORISATION, 0]);
    o.extend_from_slice(&(ace_longueur as u16).to_le_bytes());
    o.extend_from_slice(&masque.to_le_bytes());
    o.extend_from_slice(&sid);
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn un_sid_textuel_se_relit_et_se_reecrit_a_l_identique() {
        for s in [
            "S-1-5-18",
            "S-1-5-19",
            "S-1-5-21-1111111111-2222222222-3333333333-1001",
            "S-1-5-80-3262478231-3923453534-1469004531-56507889-2197805297",
            "S-1-0-0",
        ] {
            let sid = Sid::lire_texte(s).unwrap_or_else(|| panic!("{s}"));
            assert_eq!(sid.texte(), s);
            let (relu, n) = Sid::lire_octets(&sid.octets()).unwrap();
            assert_eq!(relu, sid);
            assert_eq!(n, sid.octets().len());
        }
    }

    /// Une ecriture non canonique n'est pas normalisee en silence: c'est le
    /// piege du SID a zeros de tete.
    #[test]
    fn une_ecriture_non_canonique_est_refusee() {
        for s in [
            "",
            "S-1-5",
            "S-1-05-18",
            "S-1-5-018",
            "S-2-5-18",
            "s-1-5-18",
            "S-1-5-18-",
            "S-1-5--18",
            "S-1-5-18 ",
            "S-1-5-4294967296",
            "S-1-281474976710656-1",
            "S-1-0x5-18",
            "S-1-5-1-2-3-4-5-6-7-8-9-10-11-12-13-14-15-16",
        ] {
            assert!(Sid::lire_texte(s).is_none(), "accepte: {s:?}");
        }
    }

    #[test]
    fn le_descripteur_construit_se_relit_en_une_seule_autorisation() {
        let sid = Sid::lire_texte("S-1-5-18").unwrap();
        let sd = descripteur_autorisant(&sid, 1);
        assert_eq!(
            lire_dacl(&sd),
            Some(Dacl::Liste(vec![Ace::Acces {
                genre: ACE_AUTORISATION,
                drapeaux: 0,
                masque: 1,
                sid,
            }]))
        );
    }

    /// Tronquer n'importe ou rend `None`, jamais une liste partielle: une
    /// liste raccourcie se lirait comme une identite plus etroite.
    #[test]
    fn un_descripteur_tronque_n_est_jamais_lu() {
        let sid = Sid::lire_texte("S-1-5-21-1-2-3-1001").unwrap();
        let sd = descripteur_autorisant(&sid, 1);
        for n in 0..sd.len() {
            assert_eq!(lire_dacl(&sd[..n]), None, "lu a {n} octets");
        }
    }

    /// Sans liste, ou liste nulle: tout le monde passe. Ce n'est pas une
    /// liste vide, qui ne laisserait passer personne.
    #[test]
    fn l_absence_de_liste_n_est_pas_une_liste_vide() {
        let sid = Sid::lire_texte("S-1-5-18").unwrap();
        let mut sans = descripteur_autorisant(&sid, 1);
        sans[2] &= !(SE_DACL_PRESENT as u8);
        assert_eq!(lire_dacl(&sans), Some(Dacl::Absente));
        let mut nulle = descripteur_autorisant(&sid, 1);
        nulle[16..20].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(lire_dacl(&nulle), Some(Dacl::Nulle));
        let mut absolu = descripteur_autorisant(&sid, 1);
        absolu[3] &= 0x7f;
        assert_eq!(lire_dacl(&absolu), None, "forme absolue lue");
    }
}
