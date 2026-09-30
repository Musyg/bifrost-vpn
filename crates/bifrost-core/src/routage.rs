//! Le plan de routage que le produit pose sous Linux, en donnees pures.
//!
//! # Pourquoi ce module existe
//!
//! Deux chemins posent des regles et des routes: WireGuard (`netcfg`, dans le
//! daemon) et le coeur (`aiguillage`, dans le daemon aussi). Jusqu'a D1c.1 ils
//! rendaient directement des lignes de commande `ip`. La preuve `prove routes`
//! doit comparer l'etat du noyau a ce que le produit pose; si elle recopiait les
//! commandes a la main, sa reference pourrait diverger de la pose sans que rien
//! ne le dise. Le plan vit donc ICI, une seule fois: le daemon en tire ses
//! commandes ([`Plan::arguments_ip`]), la preuve en tire son attendu. Ce crate
//! ne touche ni au reseau ni au systeme, et il est compile partout: les
//! recettes du plan tournent aussi sous Windows.
//!
//! # Ce que le plan ne sait pas, et le dit
//!
//! Le chemin WireGuard pose ses regles SANS priorite (`pref`): c'est le noyau
//! qui la choisit. Le plan ne connait donc pas leur priorite, seulement leur
//! ordre d'evaluation, que [`Plan::ordre_d_evaluation`] deduit de l'ordre de
//! pose et de la regle du noyau (voir cette fonction). Le chemin par coeur pose
//! des priorites fixes.

/// Famille d'adresses. Le produit traite toujours les DEUX, meme sans adresse
/// IPv6 au tunnel: une famille sans route est une famille qui sort par la porte
/// d'a cote.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Famille {
    Ipv4,
    Ipv6,
}

impl Famille {
    /// Les familles que le produit pose, dans l'ordre de pose.
    pub const TOUTES: [Famille; 2] = [Famille::Ipv4, Famille::Ipv6];

    /// L'option d'`ip` qui choisit la famille.
    pub fn option_ip(self) -> &'static str {
        match self {
            Famille::Ipv4 => "-4",
            Famille::Ipv6 => "-6",
        }
    }

    /// Le nom de la famille dans un rapport.
    pub fn nom(self) -> &'static str {
        match self {
            Famille::Ipv4 => "ipv4",
            Famille::Ipv6 => "ipv6",
        }
    }
}

/// Table `main` du noyau (`RT_TABLE_MAIN`).
pub const TABLE_MAIN: u32 = 254;
/// Table `local` du noyau (`RT_TABLE_LOCAL`).
pub const TABLE_LOCAL: u32 = 255;

/// Les tables que le noyau se reserve (`RT_TABLE_UNSPEC`, `RT_TABLE_DEFAULT`,
/// `RT_TABLE_MAIN`, `RT_TABLE_LOCAL`). Une table de tunnel qui en serait une
/// melangerait les routes du tunnel a celles du systeme.
pub const TABLES_RESERVEES: [u32; 4] = [0, 253, TABLE_MAIN, TABLE_LOCAL];

/// Table de routage du chemin par coeur. `0xb1f` se lit "bif"; le choix et ses
/// raisons sont documentes dans l'aiguillage du daemon, qui la reexporte.
pub const TABLE_COEUR: u32 = 0xb1f;
/// Chemin par coeur: le compte du coeur sort dehors, en premier.
pub const PREF_COEUR: u32 = 9100;
/// Chemin par coeur: le LAN garde ses routes connectees, pas la route par defaut.
pub const PREF_LAN: u32 = 9110;
/// Chemin par coeur: tout le reste entre dans le TUN.
pub const PREF_TUNNEL: u32 = 9120;

/// Ce qu'une regle selectionne.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Selecteur {
    /// Tout le trafic.
    Tout,
    /// Le trafic qui ne porte PAS cette marque (`not fwmark M`): tout sauf ce
    /// que WireGuard vient de chiffrer.
    HorsMarque(u32),
    /// Le trafic de ce seul compte (`uidrange U-U`).
    Compte(u32),
}

/// La table qu'une regle consulte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Consultation {
    /// Une table du produit.
    Table(u32),
    /// `main`, route par defaut comprise.
    Main,
    /// `main` avec `suppress_prefixlength 0`: une decision dont le prefixe a
    /// une longueur de 0 (la route par defaut) est rejetee, les routes plus
    /// specifiques restent.
    MainSansDefaut,
}

impl Consultation {
    /// Le numero de la table consultee.
    pub fn table(self) -> u32 {
        match self {
            Consultation::Table(t) => t,
            Consultation::Main | Consultation::MainSansDefaut => TABLE_MAIN,
        }
    }

    /// La longueur de prefixe en dessous de laquelle (incluse) une decision
    /// est rejetee, si la regle en porte une.
    pub fn suppression(self) -> Option<u32> {
        match self {
            Consultation::MainSansDefaut => Some(0),
            Consultation::Table(_) | Consultation::Main => None,
        }
    }
}

/// Une regle de politique de routage posee par le produit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Regle {
    pub famille: Famille,
    /// `None`: posee sans `pref`, le noyau choisit.
    pub priorite: Option<u32>,
    pub selecteur: Selecteur,
    pub consultation: Consultation,
}

/// La route par defaut posee dans la table du tunnel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteParDefaut {
    pub famille: Famille,
    pub table: u32,
    pub interface: String,
}

/// Une etape de la pose, dans l'ordre ou le produit l'execute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Etape {
    Route(RouteParDefaut),
    Regle(Regle),
}

/// Le chemin qui pose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Chemin {
    /// `netcfg::add_routing`: la marque de WireGuard et sa table.
    WireGuard { marque: u32, table: u32 },
    /// `aiguillage::poser`: le compte du coeur, s'il y en a un.
    Coeur { compte: Option<u32> },
}

/// Le plan: ce que le produit pose, etape par etape, dans l'ordre.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub chemin: Chemin,
    pub interface: String,
    pub etapes: Vec<Etape>,
}

impl Plan {
    /// Le chemin WireGuard, tel que wg-quick le pose: pour chaque famille, la
    /// route par defaut dans la table du tunnel, puis `not fwmark M table T`,
    /// puis `table main suppress_prefixlength 0`. Aucune priorite.
    pub fn wireguard(interface: &str, marque: u32, table: u32) -> Self {
        let mut etapes = Vec::new();
        for famille in Famille::TOUTES {
            etapes.push(Etape::Route(RouteParDefaut {
                famille,
                table,
                interface: interface.to_owned(),
            }));
            etapes.push(Etape::Regle(Regle {
                famille,
                priorite: None,
                selecteur: Selecteur::HorsMarque(marque),
                consultation: Consultation::Table(table),
            }));
            etapes.push(Etape::Regle(Regle {
                famille,
                priorite: None,
                selecteur: Selecteur::Tout,
                consultation: Consultation::MainSansDefaut,
            }));
        }
        Self {
            chemin: Chemin::WireGuard { marque, table },
            interface: interface.to_owned(),
            etapes,
        }
    }

    /// Le chemin par coeur: pour chaque famille, la route par defaut dans
    /// [`TABLE_COEUR`], puis le compte du coeur vers `main` (s'il y en a un),
    /// le LAN, et tout le reste dans la table du coeur, a priorites fixes.
    pub fn coeur(interface: &str, compte: Option<u32>) -> Self {
        let mut etapes = Vec::new();
        for famille in Famille::TOUTES {
            etapes.push(Etape::Route(RouteParDefaut {
                famille,
                table: TABLE_COEUR,
                interface: interface.to_owned(),
            }));
            if let Some(uid) = compte {
                etapes.push(Etape::Regle(Regle {
                    famille,
                    priorite: Some(PREF_COEUR),
                    selecteur: Selecteur::Compte(uid),
                    consultation: Consultation::Main,
                }));
            }
            etapes.push(Etape::Regle(Regle {
                famille,
                priorite: Some(PREF_LAN),
                selecteur: Selecteur::Tout,
                consultation: Consultation::MainSansDefaut,
            }));
            etapes.push(Etape::Regle(Regle {
                famille,
                priorite: Some(PREF_TUNNEL),
                selecteur: Selecteur::Tout,
                consultation: Consultation::Table(TABLE_COEUR),
            }));
        }
        Self {
            chemin: Chemin::Coeur { compte },
            interface: interface.to_owned(),
            etapes,
        }
    }

    /// La table qui porte la route par defaut du tunnel.
    pub fn table_du_tunnel(&self) -> u32 {
        match self.chemin {
            Chemin::WireGuard { table, .. } => table,
            Chemin::Coeur { .. } => TABLE_COEUR,
        }
    }

    /// Les regles d'une famille, dans l'ordre ou le produit les pose.
    pub fn regles(&self, famille: Famille) -> Vec<Regle> {
        self.etapes
            .iter()
            .filter_map(|e| match e {
                Etape::Regle(r) if r.famille == famille => Some(*r),
                _ => None,
            })
            .collect()
    }

    /// Les routes d'une famille, dans l'ordre ou le produit les pose.
    pub fn routes(&self, famille: Famille) -> Vec<RouteParDefaut> {
        self.etapes
            .iter()
            .filter_map(|e| match e {
                Etape::Route(r) if r.famille == famille => Some(r.clone()),
                _ => None,
            })
            .collect()
    }

    /// Les regles d'une famille dans l'ordre ou le noyau les EVALUE.
    ///
    /// A priorites fixes, c'est l'ordre des priorites. Sans priorite, c'est le
    /// noyau qui en choisit une a l'insertion: `fib_default_rule_pref`
    /// (`net/core/fib_rules.c`, lu dans la v7.0 le 30/09/2026) rend la
    /// priorite de la DEUXIEME regle de la liste moins un, et la liste est
    /// triee par priorite croissante. Chaque regle posee sans `pref` se place
    /// donc juste apres la regle de priorite 0 (`local`), devant celles posees
    /// avant elle: l'ordre d'evaluation est l'inverse de l'ordre de pose. C'est
    /// ce sur quoi wg-quick repose pour placer `suppress_prefixlength 0` avant
    /// `not fwmark`, et le banc le mesure. Le produit ne melange jamais les
    /// deux formes dans une famille: `None` si c'etait le cas.
    pub fn ordre_d_evaluation(&self, famille: Famille) -> Option<Vec<Regle>> {
        let mut regles = self.regles(famille);
        if regles.iter().all(|r| r.priorite.is_some()) {
            regles.sort_by_key(|r| r.priorite);
            Some(regles)
        } else if regles.iter().all(|r| r.priorite.is_none()) {
            regles.reverse();
            Some(regles)
        } else {
            None
        }
    }

    /// Les arguments d'`ip` de chaque etape, dans l'ordre de pose.
    ///
    /// La graphie est celle que chaque chemin employait avant D1c.1, gardee a
    /// l'octet pres (recettes du daemon): WireGuard ecrit `table` et
    /// `0.0.0.0/0` (`::/0`), le coeur ecrit `lookup` et `default`. Pour
    /// iproute2 ce sont des synonymes; les garder evite de changer une seule
    /// commande executee en production.
    pub fn arguments_ip(&self) -> Vec<Vec<String>> {
        let wg = matches!(self.chemin, Chemin::WireGuard { .. });
        let mot_table = if wg { "table" } else { "lookup" };
        self.etapes
            .iter()
            .map(|etape| match etape {
                Etape::Route(r) => {
                    let defaut = match (wg, r.famille) {
                        (true, Famille::Ipv4) => "0.0.0.0/0",
                        (true, Famille::Ipv6) => "::/0",
                        (false, _) => "default",
                    };
                    vec![
                        r.famille.option_ip().to_owned(),
                        "route".to_owned(),
                        "add".to_owned(),
                        defaut.to_owned(),
                        "dev".to_owned(),
                        r.interface.clone(),
                        "table".to_owned(),
                        r.table.to_string(),
                    ]
                }
                Etape::Regle(r) => {
                    let mut a = vec![
                        r.famille.option_ip().to_owned(),
                        "rule".to_owned(),
                        "add".to_owned(),
                    ];
                    match r.selecteur {
                        Selecteur::Tout => {}
                        Selecteur::HorsMarque(m) => {
                            a.extend(["not".to_owned(), "fwmark".to_owned(), m.to_string()]);
                        }
                        Selecteur::Compte(u) => {
                            a.extend(["uidrange".to_owned(), format!("{u}-{u}")]);
                        }
                    }
                    a.push(mot_table.to_owned());
                    match r.consultation {
                        Consultation::Table(t) => a.push(t.to_string()),
                        Consultation::Main => a.push("main".to_owned()),
                        Consultation::MainSansDefaut => a.extend([
                            "main".to_owned(),
                            "suppress_prefixlength".to_owned(),
                            "0".to_owned(),
                        ]),
                    }
                    if let Some(p) = r.priorite {
                        a.extend(["pref".to_owned(), p.to_string()]);
                    }
                    a
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lignes(p: &Plan) -> Vec<String> {
        p.arguments_ip().iter().map(|a| a.join(" ")).collect()
    }

    /// Les deux chemins, rendus: la meme liste que les recettes du daemon
    /// figent sur la base (`la_pose_*_est_celle_de_la_base_a_l_octet_pres`).
    #[test]
    fn le_rendu_de_chaque_chemin_est_la_graphie_historique() {
        assert_eq!(
            lignes(&Plan::wireguard("wg0", 51820, 51820)),
            [
                "-4 route add 0.0.0.0/0 dev wg0 table 51820",
                "-4 rule add not fwmark 51820 table 51820",
                "-4 rule add table main suppress_prefixlength 0",
                "-6 route add ::/0 dev wg0 table 51820",
                "-6 rule add not fwmark 51820 table 51820",
                "-6 rule add table main suppress_prefixlength 0",
            ]
        );
        assert_eq!(
            lignes(&Plan::coeur("bftun0", Some(4242))),
            [
                "-4 route add default dev bftun0 table 2847",
                "-4 rule add uidrange 4242-4242 lookup main pref 9100",
                "-4 rule add lookup main suppress_prefixlength 0 pref 9110",
                "-4 rule add lookup 2847 pref 9120",
                "-6 route add default dev bftun0 table 2847",
                "-6 rule add uidrange 4242-4242 lookup main pref 9100",
                "-6 rule add lookup main suppress_prefixlength 0 pref 9110",
                "-6 rule add lookup 2847 pref 9120",
            ]
        );
    }

    /// L'ordre d'evaluation: inverse de la pose sans priorite, priorites
    /// croissantes sinon. La regle qui aiguille vers le tunnel vient en
    /// dernier dans les deux chemins: tout ce qui la precede passe avant lui.
    #[test]
    fn l_ordre_d_evaluation_suit_la_regle_du_noyau() {
        let wg = Plan::wireguard("wg0", 7, 30303);
        for f in Famille::TOUTES {
            let ordre = wg.ordre_d_evaluation(f).unwrap();
            assert_eq!(ordre.len(), 2);
            assert_eq!(ordre[0].consultation, Consultation::MainSansDefaut);
            assert_eq!(ordre[1].consultation, Consultation::Table(30303));
            assert!(ordre.iter().all(|r| r.famille == f));
        }
        let coeur = Plan::coeur("bftun0", Some(4242));
        for f in Famille::TOUTES {
            let prefs: Vec<_> = coeur
                .ordre_d_evaluation(f)
                .unwrap()
                .iter()
                .map(|r| r.priorite)
                .collect();
            assert_eq!(prefs, [Some(PREF_COEUR), Some(PREF_LAN), Some(PREF_TUNNEL)]);
        }
        let mut melange = Plan::coeur("bftun0", None);
        if let Some(Etape::Regle(r)) = melange.etapes.get_mut(1) {
            r.priorite = None;
        }
        assert_eq!(melange.ordre_d_evaluation(Famille::Ipv4), None);
    }

    /// Les deux familles, toujours: un plan qui en oublierait une laisserait
    /// sortir l'autre en clair.
    #[test]
    fn chaque_chemin_pose_les_deux_familles() {
        for p in [
            Plan::wireguard("wg0", 1, 100),
            Plan::coeur("bftun0", None),
            Plan::coeur("bftun0", Some(1000)),
        ] {
            for f in Famille::TOUTES {
                assert_eq!(p.routes(f).len(), 1, "{f:?}");
                assert!(!p.regles(f).is_empty(), "{f:?}");
                assert_eq!(p.routes(f)[0].table, p.table_du_tunnel());
            }
        }
    }

    /// La table du coeur n'est aucune de celles que le noyau se reserve.
    #[test]
    fn la_table_du_coeur_n_est_pas_reservee() {
        let t = [TABLE_COEUR];
        assert!(t.iter().all(|t| !TABLES_RESERVEES.contains(t)));
        let prefs = [PREF_COEUR, PREF_LAN, PREF_TUNNEL];
        assert!(prefs.windows(2).all(|p| p[0] < p[1]));
    }
}
