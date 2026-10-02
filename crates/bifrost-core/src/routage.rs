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
//!
//! # Ne retirer que ce que le produit a pose
//!
//! Chaque regle et chaque route du plan porte l'etiquette du produit,
//! [`PROTOCOLE_PRODUIT`], et le retrait ([`Plan::arguments_retrait_presents`])
//! est le miroir exact de la pose: meme selecteur, meme table, meme interface
//! pour une route, la meme etiquette, et la priorite de chaque regle. Le noyau
//! retire la PREMIERE regle qui correspond a ce que la requete precise, et
//! tient pour joker tout ce qu'elle ne precise pas (`rule_find`,
//! `net/core/fib_rules.c`, v7.0, lu le 30/09/2026): sans l'etiquette, ni le
//! selecteur complet ni la priorite ne designent une regle a coup sur. Mesure
//! le 30/09/2026 sur essai-linux (noyau 7.0, iproute2 6.1.0), en namespace
//! jetable: `rule del lookup main suppress_prefixlength 0 pref 9110` retire
//! une regle tierce `from 192.0.2.0/24 lookup main suppress_prefixlength 0
//! pref 9110` posee avant celle du produit; avec `protocol`, seule celle du
//! produit part. Les routes se retirent une par une, par leur interface et
//! leur etiquette, jamais par `ip route flush table`, qui vidait la table du
//! tiers qui l'occupait aussi.
//!
//! L'etiquette dit qu'un objet a la forme d'un objet du produit, pas quelle
//! session l'a pose, ni meme que le produit l'a pose: n'importe quel
//! programme peut l'employer, et deux sessions du produit posent les memes
//! formes. Ce qu'une session a pose se lit donc dans le journal des sessions
//! que le daemon tient (`tunnel::session`), et [`Regle::designe`] et
//! [`RouteParDefaut::designe`] disent si un objet lu dans le noyau est celui
//! qu'une session enregistree a pose: meme forme, meme etiquette, et la
//! priorite qu'elle a relevee.
//!
//! Avant la pose, [`Plan::occupation`] dit ce qu'un tiers occupe deja: une
//! route dans la table du tunnel, une regle qui la consulte, ou (WireGuard)
//! une regle sur la marque du produit. Le montage refuse alors, sans rien
//! poser ([`Plan::refus_d_occupation`]).

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
///
/// C'est la SEULE liste: la validation de la configuration, la pose et le
/// demontage WireGuard (`netcfg` dans le daemon) et la preuve `prove routes` la
/// lisent toutes, par [`table_reservee`] ou directement. Le demontage fait
/// `ip route flush table <T>`: avec 254 il vide `main`, avec 255 `local`, avec 0
/// toutes les tables (iproute2 lit 0 comme `all`), avec 253 `default`.
pub const TABLES_RESERVEES: [u32; 4] = [0, 253, TABLE_MAIN, TABLE_LOCAL];

/// Le nom que le noyau donne a une table qu'il se reserve, ou `None` si la
/// table est libre pour un tunnel.
///
/// [`TABLES_RESERVEES`] decide, et elle seule: le nom ne sert qu'au message.
/// `RT_TABLE_COMPAT` (252) n'en fait pas partie. Ce n'est pas une table du
/// noyau mais la valeur qu'il ecrit dans le champ de huit bits d'une route
/// dont la table depasse 255, la vraie table voyageant dans `RTA_TABLE`;
/// iproute2 lit `RTA_TABLE` et pose, liste et vide la table 252 comme une
/// autre.
pub fn table_reservee(table: u32) -> Option<&'static str> {
    if !TABLES_RESERVEES.contains(&table) {
        return None;
    }
    Some(match table {
        0 => "unspec",
        253 => "default",
        TABLE_MAIN => "main",
        TABLE_LOCAL => "local",
        _ => "reservee",
    })
}

/// Les tables reservees, pour un message: `0, 253, 254, 255`.
pub fn liste_des_tables_reservees() -> String {
    TABLES_RESERVEES
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Table de routage du chemin par coeur. `0xb1f` se lit "bif"; le choix et ses
/// raisons sont documentes dans l'aiguillage du daemon, qui la reexporte.
pub const TABLE_COEUR: u32 = 0xb1f;

/// L'etiquette de propriete que le produit pose sur chacune de ses regles
/// (`protocol`, attribut FRA_PROTOCOL) et de ses routes (`proto`, champ
/// `rtm_protocol`), dans les deux chemins.
///
/// Le noyau ne l'interprete pas: `include/uapi/linux/rtnetlink.h` (v7.0) dit
/// des valeurs a partir de RTPROT_STATIC qu'elles sont << just passed from
/// user and back as is >>, pour distinguer les demons de routage. Mais il la
/// COMPARE quand une suppression la precise: `rule_find`
/// (`net/core/fib_rules.c`) saute une regle d'une autre etiquette, et
/// `fib_table_delete` (`net/ipv4/fib_trie.c`) une route IPv4 d'un autre
/// protocole (lus dans la v7.0 le 30/09/2026). En IPv6 c'est MESURE, pas lu.
/// Un noyau qui ne comparerait pas l'etiquette retirerait comme avant, par
/// correspondance: ce n'est pas mesure ailleurs que sur la v7.0. C'est ce qui rend
/// le retrait exact: une regle ou une route d'un tiers ne porte pas cette
/// etiquette, quelle que soit sa ressemblance avec celle du produit. Mesure
/// sur essai-linux, noyau 7.0, dans les deux familles: voir l'en-tete du
/// module.
///
/// `0xb1` (177), comme `0xb1f` pour la table du coeur. Aucun protocole n'y est
/// attribue, ni dans `rtnetlink.h` (v7.0) ni dans le `rt_protos` d'iproute2
/// 6.1.0 (releves le 30/09/2026).
pub const PROTOCOLE_PRODUIT: u8 = 0xb1;
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

impl Regle {
    /// La regle lue dans le noyau est-elle celle-ci, posee par le produit:
    /// meme famille, meme forme (selecteur et table consultee, rien de plus),
    /// son etiquette, et sa priorite quand le plan la fixe ou que la pose l'a
    /// relevee (`relevee`, pour une regle posee sans `pref`).
    pub fn designe(&self, lue: &RegleLue, relevee: Option<u32>) -> bool {
        lue.famille == self.famille
            && lue.protocole == PROTOCOLE_PRODUIT
            && lue.forme == Some((self.selecteur, self.consultation))
            && self.priorite.or(relevee).is_none_or(|p| lue.priorite == p)
    }
}

/// La route par defaut posee dans la table du tunnel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteParDefaut {
    pub famille: Famille,
    pub table: u32,
    pub interface: String,
}

impl RouteParDefaut {
    /// La route lue dans le noyau est-elle celle-ci, posee par le produit:
    /// route par defaut de sa famille, dans sa table, vers l'interface dont
    /// `index` est le numero (une interface absente n'a plus de route), a son
    /// etiquette.
    pub fn designe(&self, lue: &RouteLue, index: Option<u32>) -> bool {
        lue.famille == self.famille
            && lue.protocole == PROTOCOLE_PRODUIT
            && lue.table == self.table
            && index.is_some()
            && lue.par_defaut_vers == index
    }
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
    /// La graphie est celle que chaque chemin employait avant D1c.1: WireGuard
    /// ecrit `table` et `0.0.0.0/0` (`::/0`), le coeur ecrit `lookup` et
    /// `default`; pour iproute2 ce sont des synonymes. Chaque commande porte en
    /// plus, en dernier, l'etiquette du produit ([`PROTOCOLE_PRODUIT`]):
    /// `protocol 177` sur une regle (`ip-rule(8)`), `proto 177` sur une route
    /// (`ip-route(8)`). Elle ne change aucune decision de routage; elle permet
    /// au retrait de ne designer que ce que le produit a pose.
    pub fn arguments_ip(&self) -> Vec<Vec<String>> {
        self.etapes
            .iter()
            .map(|etape| self.argv(etape, "add"))
            .collect()
    }

    /// Les regles du plan dans l'ordre de pose, les deux familles a la
    /// suite. C'est l'ordre des priorites qu'une session du produit releve
    /// et inscrit, et celui de [`Plan::arguments_retrait_presents`].
    pub fn regles_posees(&self) -> Vec<Regle> {
        self.etapes
            .iter()
            .filter_map(|e| match e {
                Etape::Regle(r) => Some(*r),
                Etape::Route(_) => None,
            })
            .collect()
    }

    /// Les routes du plan dans l'ordre de pose, les deux familles a la suite.
    pub fn routes_posees(&self) -> Vec<RouteParDefaut> {
        self.etapes
            .iter()
            .filter_map(|e| match e {
                Etape::Route(r) => Some(r.clone()),
                Etape::Regle(_) => None,
            })
            .collect()
    }

    /// Les arguments d'`ip` du retrait de ce que ce plan a pose et qui est
    /// encore la, dans l'ordre ou le produit les execute: pour chaque
    /// famille, la regle qui envoie au tunnel d'abord, puis les autres regles
    /// de la derniere posee a la premiere, puis la route.
    ///
    /// `regles[i]` dit ce qu'il en est de la i-eme regle de
    /// [`Plan::regles_posees`]: `Some(p)` si elle est la, a la priorite `p`
    /// lue dans le noyau; `None` (ou rien) si elle n'y est pas, et aucune
    /// commande ne la vise. `routes[j]` dit de meme si la j-eme route de
    /// [`Plan::routes_posees`] est la.
    ///
    /// Chaque commande est la commande de pose, `add` devenu `del`: meme
    /// selecteur, meme table, meme interface pour la route, meme etiquette,
    /// et chaque regle porte sa priorite (celle du plan quand il la fixe,
    /// sinon celle qui a ete lue). Rien n'est retire par table entiere ni par
    /// priorite seule, et aucune regle sans sa priorite.
    pub fn arguments_retrait_presents(
        &self,
        regles: &[Option<u32>],
        routes: &[bool],
    ) -> Vec<Vec<String>> {
        let tunnel = self.table_du_tunnel();
        // Le rang de chaque etape parmi les regles, ou parmi les routes, dans
        // l'ordre de pose.
        let mut rang = Vec::with_capacity(self.etapes.len());
        let (mut nr, mut nt) = (0, 0);
        for e in &self.etapes {
            match e {
                Etape::Regle(_) => {
                    rang.push(nr);
                    nr += 1;
                }
                Etape::Route(_) => {
                    rang.push(nt);
                    nt += 1;
                }
            }
        }
        let mut sortie = Vec::new();
        for famille in Famille::TOUTES {
            let mut a_retirer: Vec<(usize, &Etape)> = self
                .etapes
                .iter()
                .enumerate()
                .filter(|(_, e)| matches!(e, Etape::Regle(r) if r.famille == famille))
                .collect();
            a_retirer.reverse();
            // Tri stable: la regle vers le tunnel passe devant, les autres
            // gardent l'ordre inverse de la pose.
            a_retirer.sort_by_key(|(_, e)| {
                !matches!(e, Etape::Regle(r) if r.consultation == Consultation::Table(tunnel))
            });
            a_retirer.extend(
                self.etapes
                    .iter()
                    .enumerate()
                    .rev()
                    .filter(|(_, e)| matches!(e, Etape::Route(r) if r.famille == famille)),
            );
            for (i, etape) in a_retirer {
                match etape {
                    Etape::Regle(_) => {
                        if let Some(p) = regles.get(rang[i]).copied().flatten() {
                            sortie.push(self.argv_releve(etape, "del", Some(p)));
                        }
                    }
                    Etape::Route(_) => {
                        if routes.get(rang[i]).copied().unwrap_or(false) {
                            sortie.push(self.argv(etape, "del"));
                        }
                    }
                }
            }
        }
        sortie
    }

    /// Une etape, en arguments d'`ip`, pour le verbe donne (`add` ou `del`).
    fn argv(&self, etape: &Etape, verbe: &str) -> Vec<String> {
        self.argv_releve(etape, verbe, None)
    }

    /// [`Plan::argv`], et la priorite relevee d'une regle posee sans `pref`.
    fn argv_releve(&self, etape: &Etape, verbe: &str, relevee: Option<u32>) -> Vec<String> {
        let wg = matches!(self.chemin, Chemin::WireGuard { .. });
        let mot_table = if wg { "table" } else { "lookup" };
        let etiquette = PROTOCOLE_PRODUIT.to_string();
        match etape {
            Etape::Route(r) => {
                let defaut = match (wg, r.famille) {
                    (true, Famille::Ipv4) => "0.0.0.0/0",
                    (true, Famille::Ipv6) => "::/0",
                    (false, _) => "default",
                };
                vec![
                    r.famille.option_ip().to_owned(),
                    "route".to_owned(),
                    verbe.to_owned(),
                    defaut.to_owned(),
                    "dev".to_owned(),
                    r.interface.clone(),
                    "table".to_owned(),
                    r.table.to_string(),
                    "proto".to_owned(),
                    etiquette,
                ]
            }
            Etape::Regle(r) => {
                let mut a = vec![
                    r.famille.option_ip().to_owned(),
                    "rule".to_owned(),
                    verbe.to_owned(),
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
                if let Some(p) = r.priorite.or(relevee) {
                    a.extend(["pref".to_owned(), p.to_string()]);
                }
                a.extend(["protocol".to_owned(), etiquette]);
                a
            }
        }
    }

    /// Ce qu'un tiers occupe deja de ce que ce plan veut poser, lu dans le
    /// noyau avant la premiere commande. Vide: la voie est libre.
    ///
    /// Ce qui porte l'etiquette du produit n'est pas juge ici: le daemon le
    /// confronte d'abord au journal de ses sessions (`tunnel::session`), qui
    /// retire ce qu'une session morte a pose et refuse le montage devant tout
    /// le reste; quand cette lecture-ci a lieu, il n'en reste plus. Pour ce
    /// qui ne porte pas l'etiquette, trois cas, dans chaque famille:
    ///
    /// - une route dans la table du tunnel: la table est celle d'un autre;
    /// - une regle qui consulte la table du tunnel, dont une regle identique a
    ///   celle du plan (`not fwmark M table T`): un tiers y envoie deja du
    ///   trafic;
    /// - WireGuard seulement, une regle sur la marque du produit (`fwmark M`,
    ///   inversee ou non, masque complet): la marque est celle d'un autre
    ///   WireGuard, dont le kill switch laisserait sortir les paquets.
    ///
    /// Une regle tierce identique a `table main suppress_prefixlength 0`, que
    /// pose tout wg-quick, n'occupe rien: elle ne consulte pas la table du
    /// tunnel, et le retrait etiquete ne la touche pas.
    pub fn occupation(&self, regles: &[RegleLue], routes: &[RouteLue]) -> Vec<Occupation> {
        let table = self.table_du_tunnel();
        let marque = match self.chemin {
            Chemin::WireGuard { marque, .. } => Some(marque),
            Chemin::Coeur { .. } => None,
        };
        let mut sortie = Vec::new();
        for famille in Famille::TOUTES {
            let nombre = routes
                .iter()
                .filter(|r| {
                    r.famille == famille && r.table == table && r.protocole != PROTOCOLE_PRODUIT
                })
                .count();
            if nombre > 0 {
                sortie.push(Occupation::RoutesDansLaTable {
                    famille,
                    table,
                    nombre,
                });
            }
            for r in regles
                .iter()
                .filter(|r| r.famille == famille && r.protocole != PROTOCOLE_PRODUIT)
            {
                if r.table == Some(table) {
                    sortie.push(Occupation::RegleVersLaTable {
                        famille,
                        priorite: r.priorite,
                        table,
                    });
                } else if let Some(m) = marque
                    && r.marque == Some((m, u32::MAX))
                {
                    sortie.push(Occupation::RegleSurLaMarque {
                        famille,
                        priorite: r.priorite,
                        marque: m,
                    });
                }
            }
        }
        sortie
    }

    /// Le refus nomme d'un montage dont la voie est occupee: quoi, ou, et
    /// quoi faire. Rien n'a ete pose quand il est rendu.
    pub fn refus_d_occupation(&self, occupations: &[Occupation]) -> String {
        let detail = occupations
            .iter()
            .map(Occupation::decrire)
            .collect::<Vec<_>>()
            .join("; ");
        match self.chemin {
            Chemin::WireGuard { marque, table } => format!(
                "montage refuse: la table {table} ou la marque {marque} est deja employee \
                 par un tiers ({detail}). Aucune regle, aucune route, aucune interface n'est \
                 posee. Choisir dans le profil une routing_table qu'aucune route ni regle \
                 n'emploie, et une fwmark qu'aucune regle n'emploie: wg-quick prend 51820 \
                 pour les deux quand cette table est libre"
            ),
            Chemin::Coeur { .. } => format!(
                "montage refuse: la table {TABLE_COEUR} du chemin par coeur est deja \
                 employee par un tiers ({detail}). Aucune regle, aucune route, aucune \
                 interface n'est posee. Cette table est fixee par le produit: retirer ce \
                 qui l'occupe, ou arreter le tiers qui s'y est pose"
            ),
        }
    }
}

/// Ce qu'un peripherique de tunnel a pose comme plan de routage, tel qu'il le
/// declare au superviseur qui le sert par IPC.
///
/// La preuve `prove routes --politique-daemon` compare le noyau au plan que le
/// PERIPHERIQUE retient de sa pose, pas a un plan recalcule au moment de la
/// lecture: le peripherique rend donc ICI le [`Plan`] de la meme fonction pure,
/// sur la meme configuration, que celle dont il a tire ses commandes
/// (`Plan::arguments_ip`), evaluee une seconde fois apres la derniere commande
/// reussie. Egal par construction au plan des commandes, ce n'est pas une
/// capture de ces commandes. Les cas sont ceux que la commande IPC porte:
///
/// - [`RoutagePose::Pose`]: une interface est montee sous Linux, avec ce plan;
/// - [`RoutagePose::PoseWindows`]: une interface est montee sous Windows, avec
///   le plan IP Helper ([`crate::routage_windows::PlanWindows`]) que la pose a
///   execute;
/// - [`RoutagePose::Aucun`]: rien de pose (jamais monte, ou demonte);
/// - [`RoutagePose::NonApplicable`]: ce peripherique ne pose pas de plan de
///   routage. C'est le defaut du port (`TunnelDevice::routage_pose`): un
///   peripherique qui ne le surcharge pas, comme un double de test, ne pretend
///   rien avoir pose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoutagePose {
    NonApplicable,
    Aucun,
    Pose(Plan),
    PoseWindows(crate::routage_windows::PlanWindows),
}

/// Une regle telle que la lit la verification d'occupation: ce qui decide
/// d'un conflit, rien d'autre.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegleLue {
    pub famille: Famille,
    pub priorite: u32,
    /// La table consultee, si l'action de la regle est d'en consulter une
    /// (FR_ACT_TO_TBL); `None` pour un saut, un rejet ou une regle neutre.
    pub table: Option<u32>,
    /// `fwmark` de la regle, (valeur, masque), inversee ou non.
    pub marque: Option<(u32, u32)>,
    /// FRA_PROTOCOL: qui l'a posee.
    pub protocole: u8,
    /// La forme de la regle quand c'est une forme que le produit pose
    /// (selecteur et table consultee), et que la regle ne porte RIEN d'autre;
    /// `None` sinon. Une regle qui ajoute quoi que ce soit (une source, une
    /// interface, un masque partiel, un saut) n'a pas de forme du produit.
    pub forme: Option<(Selecteur, Consultation)>,
}

/// Une route telle que la lit la verification d'occupation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteLue {
    pub famille: Famille,
    pub table: u32,
    /// `rtm_protocol`: qui l'a posee.
    pub protocole: u8,
    /// Le numero de l'interface quand la route est une route par defaut
    /// directe (ni passerelle, ni chemins multiples, ni source) vers une
    /// seule interface, la forme que le produit pose; `None` sinon.
    pub par_defaut_vers: Option<u32>,
}

/// Ce qu'un tiers occupe deja de ce que le plan veut poser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Occupation {
    /// Des routes d'un tiers dans la table du tunnel.
    RoutesDansLaTable {
        famille: Famille,
        table: u32,
        nombre: usize,
    },
    /// Une regle d'un tiers qui consulte la table du tunnel.
    RegleVersLaTable {
        famille: Famille,
        priorite: u32,
        table: u32,
    },
    /// Une regle d'un tiers sur la marque du produit.
    RegleSurLaMarque {
        famille: Famille,
        priorite: u32,
        marque: u32,
    },
}

impl Occupation {
    /// Une ligne du refus.
    pub fn decrire(&self) -> String {
        match *self {
            Occupation::RoutesDansLaTable {
                famille,
                table,
                nombre,
            } => format!("{}: {nombre} route(s) dans la table {table}", famille.nom()),
            Occupation::RegleVersLaTable {
                famille,
                priorite,
                table,
            } => format!(
                "{}: regle de priorite {priorite} vers la table {table}",
                famille.nom()
            ),
            Occupation::RegleSurLaMarque {
                famille,
                priorite,
                marque,
            } => format!(
                "{}: regle de priorite {priorite} sur la marque {marque}",
                famille.nom()
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lignes(p: &Plan) -> Vec<String> {
        p.arguments_ip().iter().map(|a| a.join(" ")).collect()
    }

    /// Les deux chemins, rendus: la meme liste que les recettes du daemon
    /// figent (`la_pose_*_est_celle_de_la_base_a_l_octet_pres`). La graphie
    /// historique, chaque commande suivie de l'etiquette du produit.
    #[test]
    fn le_rendu_de_chaque_chemin_est_la_graphie_historique() {
        assert_eq!(
            lignes(&Plan::wireguard("wg0", 51820, 51820)),
            [
                "-4 route add 0.0.0.0/0 dev wg0 table 51820 proto 177",
                "-4 rule add not fwmark 51820 table 51820 protocol 177",
                "-4 rule add table main suppress_prefixlength 0 protocol 177",
                "-6 route add ::/0 dev wg0 table 51820 proto 177",
                "-6 rule add not fwmark 51820 table 51820 protocol 177",
                "-6 rule add table main suppress_prefixlength 0 protocol 177",
            ]
        );
        assert_eq!(
            lignes(&Plan::coeur("bftun0", Some(4242))),
            [
                "-4 route add default dev bftun0 table 2847 proto 177",
                "-4 rule add uidrange 4242-4242 lookup main pref 9100 protocol 177",
                "-4 rule add lookup main suppress_prefixlength 0 pref 9110 protocol 177",
                "-4 rule add lookup 2847 pref 9120 protocol 177",
                "-6 route add default dev bftun0 table 2847 proto 177",
                "-6 rule add uidrange 4242-4242 lookup main pref 9100 protocol 177",
                "-6 rule add lookup main suppress_prefixlength 0 pref 9110 protocol 177",
                "-6 rule add lookup 2847 pref 9120 protocol 177",
            ]
        );
    }

    /// Tout ce que le plan pose, present: chaque regle a la priorite donnee
    /// dans l'ordre de pose, ou a celle que le plan fixe.
    fn tout_present(p: &Plan, priorites: &[u32]) -> Vec<String> {
        let regles: Vec<Option<u32>> = p
            .regles_posees()
            .iter()
            .enumerate()
            .map(|(i, r)| r.priorite.or(priorites.get(i).copied()))
            .collect();
        let routes = vec![true; p.routes_posees().len()];
        p.arguments_retrait_presents(&regles, &routes)
            .iter()
            .map(|a| a.join(" "))
            .collect()
    }

    /// Le retrait, commande par commande et dans l'ordre: celui que chaque
    /// chemin suivait (regle du tunnel, autres regles, route; IPv4 puis IPv6),
    /// chaque commande la pose, `add` devenu `del`, et la priorite de chaque
    /// regle: celle qui a ete lue pour WireGuard, celle du plan pour le coeur.
    #[test]
    fn le_retrait_de_chaque_chemin_est_le_miroir_de_sa_pose() {
        assert_eq!(
            tout_present(
                &Plan::wireguard("wg0", 51820, 51820),
                &[32765, 32764, 32763, 32762]
            ),
            [
                "-4 rule del not fwmark 51820 table 51820 pref 32765 protocol 177",
                "-4 rule del table main suppress_prefixlength 0 pref 32764 protocol 177",
                "-4 route del 0.0.0.0/0 dev wg0 table 51820 proto 177",
                "-6 rule del not fwmark 51820 table 51820 pref 32763 protocol 177",
                "-6 rule del table main suppress_prefixlength 0 pref 32762 protocol 177",
                "-6 route del ::/0 dev wg0 table 51820 proto 177",
            ]
        );
        assert_eq!(
            tout_present(&Plan::coeur("bftun0", Some(4242)), &[]),
            [
                "-4 rule del lookup 2847 pref 9120 protocol 177",
                "-4 rule del lookup main suppress_prefixlength 0 pref 9110 protocol 177",
                "-4 rule del uidrange 4242-4242 lookup main pref 9100 protocol 177",
                "-4 route del default dev bftun0 table 2847 proto 177",
                "-6 rule del lookup 2847 pref 9120 protocol 177",
                "-6 rule del lookup main suppress_prefixlength 0 pref 9110 protocol 177",
                "-6 rule del uidrange 4242-4242 lookup main pref 9100 protocol 177",
                "-6 route del default dev bftun0 table 2847 proto 177",
            ]
        );
    }

    /// Ce qui n'est pas la n'est vise par aucune commande: une regle sans
    /// priorite lue, une route absente.
    #[test]
    fn le_retrait_ne_vise_que_ce_qui_est_la() {
        let wg = Plan::wireguard("wg0", 51820, 51820);
        let l: Vec<String> = wg
            .arguments_retrait_presents(&[None, Some(32764)], &[false, true])
            .iter()
            .map(|a| a.join(" "))
            .collect();
        assert_eq!(
            l,
            [
                "-4 rule del table main suppress_prefixlength 0 pref 32764 protocol 177",
                "-6 route del ::/0 dev wg0 table 51820 proto 177",
            ]
        );
        assert!(wg.arguments_retrait_presents(&[], &[]).is_empty());
        let coeur = Plan::coeur("bftun0", None);
        assert!(
            coeur
                .arguments_retrait_presents(&[None, None, None, None], &[false, false])
                .is_empty()
        );
    }

    /// Pour chaque plan, tout present, le retrait et la pose sont en
    /// bijection: chaque commande de pose a exactement une commande de
    /// retrait qui n'en differe que par le verbe et la priorite, et chaque
    /// commande porte l'etiquette. Aucune ne vide une table, chaque regle
    /// porte sa priorite et sa forme, chaque route son interface.
    #[test]
    fn chaque_retrait_designe_exactement_une_pose() {
        for p in [
            Plan::wireguard("wg0", 1, 100),
            Plan::wireguard("bf-wg_9", 0x1f2e3d, 30303),
            Plan::coeur("bftun0", None),
            Plan::coeur("bftun0", Some(1000)),
        ] {
            let priorites: Vec<u32> = (101..101 + 16).collect();
            let regles: Vec<Option<u32>> = p
                .regles_posees()
                .iter()
                .enumerate()
                .map(|(i, r)| r.priorite.or(Some(priorites[i])))
                .collect();
            let routes = vec![true; p.routes_posees().len()];
            let retrait = p.arguments_retrait_presents(&regles, &routes);
            let mut pose: Vec<Vec<String>> = p.arguments_ip();
            let mut miroir: Vec<Vec<String>> = retrait
                .iter()
                .cloned()
                .map(|mut a| {
                    assert_eq!(a[2], "del", "{a:?}");
                    a[2] = "add".to_owned();
                    // La priorite lue d'une regle posee sans `pref`.
                    if let Some(i) = a.iter().position(|m| m == "pref")
                        && priorites.iter().any(|x| a[i + 1] == x.to_string())
                    {
                        a.drain(i..i + 2);
                    }
                    a
                })
                .collect();
            assert_eq!(pose.len(), miroir.len());
            pose.sort();
            miroir.sort();
            assert_eq!(pose, miroir);
            for a in retrait {
                assert!(!a.iter().any(|m| m == "flush"), "{a:?}");
                let n = a.len();
                assert_eq!(a[n - 1], "177", "{a:?}");
                assert!(a[n - 2] == "protocol" || a[n - 2] == "proto", "{a:?}");
                if a[1] == "rule" {
                    assert!(
                        a.iter().any(|m| m == "table" || m == "lookup"),
                        "une regle retiree par sa seule priorite: {a:?}"
                    );
                    assert!(
                        a.iter().any(|m| m == "pref"),
                        "une regle retiree sans sa priorite: {a:?}"
                    );
                } else {
                    assert!(a.iter().any(|m| m == "dev"), "{a:?}");
                }
            }
        }
    }

    fn regle_lue(famille: Famille, priorite: u32, table: Option<u32>) -> RegleLue {
        RegleLue {
            famille,
            priorite,
            table,
            marque: None,
            protocole: 0,
            forme: None,
        }
    }

    /// Une regle du produit se reconnait a sa famille, sa forme, son
    /// etiquette, et a sa priorite quand elle est connue (fixee par le plan
    /// ou relevee a la pose). Chaque difference la rend etrangere.
    #[test]
    fn une_regle_lue_est_designee_par_forme_etiquette_et_priorite() {
        let wg = Plan::wireguard("wg0", 51820, 51820);
        let lan = wg.regles_posees()[1];
        let lue = RegleLue {
            protocole: PROTOCOLE_PRODUIT,
            forme: Some((Selecteur::Tout, Consultation::MainSansDefaut)),
            ..regle_lue(Famille::Ipv4, 32764, Some(TABLE_MAIN))
        };
        assert!(lan.designe(&lue, Some(32764)));
        assert!(
            lan.designe(&lue, None),
            "priorite inconnue: la forme suffit"
        );
        assert!(!lan.designe(&lue, Some(32763)), "autre priorite relevee");
        assert!(!lan.designe(
            &RegleLue {
                protocole: 0,
                ..lue
            },
            Some(32764)
        ));
        assert!(!lan.designe(&RegleLue { forme: None, ..lue }, Some(32764)));
        assert!(!lan.designe(
            &RegleLue {
                famille: Famille::Ipv6,
                ..lue
            },
            Some(32764)
        ));
        assert!(!wg.regles_posees()[0].designe(&lue, Some(32764)));
        // Une priorite fixee par le plan l'emporte sur toute releve.
        let coeur_lan = Plan::coeur("bftun0", None).regles_posees()[0];
        assert_eq!(coeur_lan.priorite, Some(PREF_LAN));
        let a_9110 = RegleLue {
            priorite: PREF_LAN,
            forme: Some((Selecteur::Tout, Consultation::MainSansDefaut)),
            ..lue
        };
        assert!(coeur_lan.designe(&a_9110, None));
        assert!(coeur_lan.designe(&a_9110, Some(1)));
        assert!(!coeur_lan.designe(
            &RegleLue {
                priorite: 9111,
                ..a_9110
            },
            None
        ));
    }

    /// Une route du produit: route par defaut de sa famille, dans sa table,
    /// vers l'interface donnee, a l'etiquette. Sans interface, aucune.
    #[test]
    fn une_route_lue_est_designee_par_table_interface_et_etiquette() {
        let r = &Plan::wireguard("wg0", 51820, 51820).routes_posees()[0];
        let lue = RouteLue {
            famille: Famille::Ipv4,
            table: 51820,
            protocole: PROTOCOLE_PRODUIT,
            par_defaut_vers: Some(7),
        };
        assert!(r.designe(&lue, Some(7)));
        assert!(!r.designe(&lue, Some(8)));
        assert!(!r.designe(&lue, None));
        assert!(!r.designe(
            &RouteLue {
                protocole: 3,
                ..lue
            },
            Some(7)
        ));
        assert!(!r.designe(
            &RouteLue {
                table: 51821,
                ..lue
            },
            Some(7)
        ));
        assert!(!r.designe(
            &RouteLue {
                par_defaut_vers: None,
                ..lue
            },
            Some(7)
        ));
        assert!(!r.designe(
            &RouteLue {
                famille: Famille::Ipv6,
                ..lue
            },
            Some(7)
        ));
    }

    /// Ce que le noyau pose de lui-meme, et un namespace ordinaire: rien
    /// n'occupe la voie d'aucun plan.
    fn regles_du_noyau() -> Vec<RegleLue> {
        let mut v = Vec::new();
        for f in Famille::TOUTES {
            for (p, t) in [(0, 255), (32766, 254), (32767, 253)] {
                v.push(RegleLue {
                    protocole: 2,
                    ..regle_lue(f, p, Some(t))
                });
            }
        }
        v
    }

    fn route_lue(famille: Famille, table: u32, protocole: u8) -> RouteLue {
        RouteLue {
            famille,
            table,
            protocole,
            par_defaut_vers: None,
        }
    }

    fn routes_ordinaires() -> Vec<RouteLue> {
        let mut v = Vec::new();
        for f in Famille::TOUTES {
            for (t, p) in [(254, 3), (254, 2), (255, 2)] {
                v.push(route_lue(f, t, p));
            }
        }
        v
    }

    #[test]
    fn une_voie_libre_n_est_pas_occupee() {
        for p in [
            Plan::wireguard("wg0", 51820, 51820),
            Plan::coeur("bftun0", Some(4242)),
        ] {
            assert_eq!(p.occupation(&regles_du_noyau(), &routes_ordinaires()), []);
        }
    }

    /// La table du tunnel porte une route d'un tiers, dans une famille puis
    /// dans l'autre: occupee, par famille, avec le nombre de routes.
    #[test]
    fn une_route_tierce_dans_la_table_du_tunnel_l_occupe() {
        for (p, t) in [
            (Plan::wireguard("wg0", 51820, 51820), 51820),
            (Plan::coeur("bftun0", None), TABLE_COEUR),
        ] {
            for f in Famille::TOUTES {
                let mut routes = routes_ordinaires();
                for _ in 0..2 {
                    routes.push(route_lue(f, t, 0));
                }
                assert_eq!(
                    p.occupation(&regles_du_noyau(), &routes),
                    [Occupation::RoutesDansLaTable {
                        famille: f,
                        table: t,
                        nombre: 2
                    }]
                );
            }
        }
    }

    /// Une regle tierce qui consulte la table du tunnel l'occupe, a n'importe
    /// quelle priorite; la meme regle vers une autre table ne l'occupe pas,
    /// meme a une priorite du produit.
    #[test]
    fn une_regle_tierce_vers_la_table_du_tunnel_l_occupe() {
        let wg = Plan::wireguard("wg0", 51820, 51820);
        let coeur = Plan::coeur("bftun0", Some(4242));
        for f in Famille::TOUTES {
            let mut r = regles_du_noyau();
            r.push(regle_lue(f, 32765, Some(51820)));
            assert_eq!(
                wg.occupation(&r, &routes_ordinaires()),
                [Occupation::RegleVersLaTable {
                    famille: f,
                    priorite: 32765,
                    table: 51820
                }]
            );
            let mut r = regles_du_noyau();
            r.push(regle_lue(f, 9115, Some(TABLE_COEUR)));
            assert_eq!(coeur.occupation(&r, &routes_ordinaires()).len(), 1);
            let mut r = regles_du_noyau();
            for pref in [PREF_COEUR, PREF_LAN, PREF_TUNNEL] {
                r.push(regle_lue(f, pref, Some(100)));
            }
            r.push(regle_lue(f, 32764, Some(51821)));
            assert_eq!(coeur.occupation(&r, &routes_ordinaires()), []);
            assert_eq!(wg.occupation(&r, &routes_ordinaires()), []);
        }
    }

    /// La regle `table main suppress_prefixlength 0` d'un wg-quick sur une
    /// autre table n'occupe rien: elle ne consulte pas la table du tunnel.
    /// La regle sur la marque du produit, si: c'est un autre WireGuard qui la
    /// porte. Un masque partiel n'est pas la marque du produit.
    #[test]
    fn la_marque_du_produit_est_occupee_mais_pas_la_regle_du_lan() {
        let wg = Plan::wireguard("wg0", 51820, 51820);
        let mut r = regles_du_noyau();
        r.push(regle_lue(Famille::Ipv4, 32763, Some(TABLE_MAIN)));
        assert_eq!(wg.occupation(&r, &routes_ordinaires()), []);
        r.push(RegleLue {
            marque: Some((51820, u32::MAX)),
            ..regle_lue(Famille::Ipv6, 32762, Some(51821))
        });
        r.push(RegleLue {
            marque: Some((51820, 0xffff)),
            ..regle_lue(Famille::Ipv4, 32761, Some(51822))
        });
        assert_eq!(
            wg.occupation(&r, &routes_ordinaires()),
            [Occupation::RegleSurLaMarque {
                famille: Famille::Ipv6,
                priorite: 32762,
                marque: 51820
            }]
        );
        // Le chemin par coeur n'a pas de marque.
        assert_eq!(
            Plan::coeur("bftun0", None).occupation(&r, &routes_ordinaires()),
            []
        );
    }

    /// Ce qui porte l'etiquette du produit n'est pas juge par l'occupation:
    /// le journal des sessions en decide avant elle (`tunnel::session`, dans
    /// le daemon).
    #[test]
    fn ce_qui_porte_l_etiquette_du_produit_n_est_pas_juge_ici() {
        let wg = Plan::wireguard("wg0", 51820, 51820);
        let mut r = regles_du_noyau();
        let mut routes = routes_ordinaires();
        for f in Famille::TOUTES {
            r.push(RegleLue {
                protocole: PROTOCOLE_PRODUIT,
                marque: Some((51820, u32::MAX)),
                ..regle_lue(f, 32765, Some(51820))
            });
            routes.push(route_lue(f, 51820, PROTOCOLE_PRODUIT));
        }
        assert_eq!(wg.occupation(&r, &routes), []);
    }

    /// Le refus nomme la table, la marque, chaque occupation, dit que rien
    /// n'est pose et quoi faire.
    #[test]
    fn le_refus_nomme_ce_qui_occupe_et_quoi_faire() {
        let wg = Plan::wireguard("wg0", 51820, 51821);
        let o = [
            Occupation::RoutesDansLaTable {
                famille: Famille::Ipv6,
                table: 51821,
                nombre: 1,
            },
            Occupation::RegleVersLaTable {
                famille: Famille::Ipv4,
                priorite: 32765,
                table: 51821,
            },
        ];
        let m = wg.refus_d_occupation(&o);
        for attendu in [
            "table 51821",
            "marque 51820",
            "ipv6: 1 route(s) dans la table 51821",
            "ipv4: regle de priorite 32765 vers la table 51821",
            "Aucune regle, aucune route, aucune interface n'est posee",
            "routing_table",
            "fwmark",
        ] {
            assert!(m.contains(attendu), "{attendu} absent de: {m}");
        }
        let m = Plan::coeur("bftun0", None).refus_d_occupation(&o[..1]);
        assert!(
            m.contains("table 2847") && m.contains("fixee par le produit"),
            "{m}"
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

    /// Les tables reservees, ecrites ici en litteraux lus dans `rt_class_t`
    /// (`include/uapi/linux/rtnetlink.h`, v7.0) et non tires de
    /// [`TABLES_RESERVEES`]: retirer une valeur de la liste doit faire rougir
    /// cette recette, pas la suivre.
    #[test]
    fn chaque_table_reservee_du_noyau_est_nommee() {
        for (table, nom) in [
            (0, "unspec"),
            (253, "default"),
            (254, "main"),
            (255, "local"),
        ] {
            assert_eq!(table_reservee(table), Some(nom), "table {table}");
        }
        assert_eq!(liste_des_tables_reservees(), "0, 253, 254, 255");
    }

    /// Les voisines restent libres: 252 (`RT_TABLE_COMPAT`, voir
    /// [`table_reservee`]), 1, 256, la table par defaut de wg-quick et du
    /// produit, et la plus grande.
    #[test]
    fn les_tables_voisines_ne_sont_pas_reservees() {
        for table in [1, 252, 256, 51820, u32::MAX] {
            assert_eq!(table_reservee(table), None, "table {table}");
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
