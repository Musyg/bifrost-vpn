//! Construction des commandes `ip` qui montent et demontent le routage.
//!
//! Fonctions pures: elles renvoient des listes d'arguments, sans rien executer.
//! C'est ce qui permet de tester la politique de routage (celle qui evite les
//! fuites) sans avoir besoin de root ni d'une interface reelle.
//!
//! Le mecanisme est celui de wg-quick, decrit au document 02 partie 2.1.

use bifrost_core::config::WireguardParams;
use bifrost_core::{Error, Result, TunnelConfig};

/// La table dediee du tunnel WireGuard, si le noyau ne se la reserve pas.
///
/// Defense en profondeur. `TunnelConfig::validate` refuse deja ces tables, et
/// `LinuxTunnel::up` valide avant tout. Mais les commandes rendues ici
/// s'executent en root, et une configuration peut arriver jusqu'ici sans etre
/// passee par la validation: un appelant futur, un outil de banc, une
/// validation affaiblie. Le refus est donc repete au seul endroit qui ecrit
/// `table <T>`, pour la pose comme pour le demontage: aucune liste de
/// commandes ne sort avec une table reservee, et en particulier aucun
/// `ip route flush table <T>`, qui viderait `main` (254), `local` (255) ou
/// toutes les tables (0). Refuser toute la liste plutot qu'en retirer les
/// seules lignes fautives: une pose partielle monterait un tunnel sans sa
/// route, et un demontage partiel laisserait croire que tout est retire.
fn table_libre(wg: &WireguardParams, quoi: &str) -> Result<u32> {
    match bifrost_core::routage::table_reservee(wg.routing_table) {
        None => Ok(wg.routing_table),
        Some(nom) => Err(Error::Config(format!(
            "{quoi} refuse: la table {table} ('{nom}') est reservee au noyau \
             Linux, aucune commande n'est emise. Corriger routing_table dans le \
             profil (tables reservees: {liste})",
            table = wg.routing_table,
            liste = bifrost_core::routage::liste_des_tables_reservees(),
        ))),
    }
}

/// Une commande a executer: le programme et ses arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cmd {
    pub program: &'static str,
    pub args: Vec<String>,
    /// Si vrai, un code de retour non nul est journalise mais n'interrompt pas
    /// la sequence. Sert au demontage, ou une regle deja absente est normale.
    pub tolerate_failure: bool,
}

impl Cmd {
    pub(crate) fn ip(args: &[&str]) -> Self {
        Self {
            program: "ip",
            args: args.iter().map(|s| (*s).to_owned()).collect(),
            tolerate_failure: false,
        }
    }

    pub(crate) fn ip_lenient(args: &[&str]) -> Self {
        Self {
            tolerate_failure: true,
            ..Self::ip(args)
        }
    }

    /// Une etape du plan de routage pur (`bifrost_core::routage`), telle
    /// qu'elle s'execute: jamais toleree en echec, comme les poses d'avant.
    pub(crate) fn ip_plan(args: Vec<String>) -> Self {
        Self {
            program: "ip",
            args,
            tolerate_failure: false,
        }
    }

    pub fn display(&self) -> String {
        format!("{} {}", self.program, self.args.join(" "))
    }
}

/// Cree l'interface WireGuard.
///
/// `ip link add type wireguard` est prefere a une creation par netlink maison:
/// c'est la meme operation, deja correcte partout, et elle echoue proprement si
/// le module noyau est absent.
pub fn create_link(cfg: &TunnelConfig) -> Cmd {
    Cmd::ip(&["link", "add", "dev", &cfg.interface, "type", "wireguard"])
}

/// Adresses, MTU et mise en service de l'interface.
pub fn configure_link(cfg: &TunnelConfig) -> Vec<Cmd> {
    let mut cmds = Vec::new();
    for addr in &cfg.addresses {
        let family = if addr.is_ipv4() { "-4" } else { "-6" };
        cmds.push(Cmd::ip(&[
            family,
            "address",
            "add",
            &addr.to_string(),
            "dev",
            &cfg.interface,
        ]));
    }
    cmds.push(Cmd::ip(&[
        "link",
        "set",
        "mtu",
        &cfg.mtu.to_string(),
        "up",
        "dev",
        &cfg.interface,
    ]));
    cmds
}

/// Routes et regles de politique de routage.
///
/// Le couple `not fwmark X table Y` plus `suppress_prefixlength 0` est le coeur
/// du montage: le trafic non encore chiffre part dans la table Y dont la route
/// par defaut est le tunnel, tandis que le trafic deja chiffre par WireGuard,
/// qui porte la marque, echappe a cette regle et sort par l'interface physique.
/// `suppress_prefixlength 0` fait ignorer la seule route par defaut de la table
/// main, ce qui preserve les routes LAN specifiques.
///
/// Depuis D1c.1, les commandes sont celles du plan pur
/// (`bifrost_core::routage::Plan::wireguard`), que la preuve `prove routes`
/// compare au noyau: une seule source pour la pose et pour l'attendu. Les
/// argv sont ceux d'avant, a l'octet pres (recette
/// `la_pose_wireguard_est_celle_de_la_base_a_l_octet_pres`).
///
/// Refuse une table que le noyau se reserve, sans rendre aucune commande:
/// voir [`table_libre`].
pub fn add_routing(cfg: &TunnelConfig) -> Result<Vec<Cmd>> {
    // Ces commandes n'existent que pour WireGuard: c'est sa marque qui echappe
    // a la regle, et sa table dediee qui porte la route par defaut. Le chemin
    // par coeur a son propre aiguillage, avec sa table. Rendre une liste vide
    // plutot qu'echouer, parce que le seul appelant est le peripherique
    // WireGuard, qui sait deja dans quel cas il est.
    let Some(wg) = cfg.portage.wireguard() else {
        return Ok(Vec::new());
    };
    let table = table_libre(wg, "pose du routage")?;
    // Les deux familles sont traitees meme si le tunnel n'a pas d'adresse IPv6:
    // sans route par defaut IPv6 dans le tunnel, l'IPv6 sortirait par
    // l'interface physique. C'est le vecteur de fuite IPv6 classique. Le plan
    // les pose toutes les deux (`Famille::TOUTES`).
    Ok(
        bifrost_core::routage::Plan::wireguard(&cfg.interface, wg.fwmark, table)
            .arguments_ip()
            .into_iter()
            .map(Cmd::ip_plan)
            .collect(),
    )
}

/// Retrait des regles et de l'interface.
///
/// Toutes les commandes tolerent l'echec: le demontage doit aboutir a un
/// systeme propre meme s'il est appele apres un demontage partiel ou un crash.
/// Supprimer le lien supprime aussi les routes de la table dediee.
///
/// Refuse une table que le noyau se reserve, sans rendre aucune commande:
/// voir [`table_libre`]. C'est ici que le refus compte le plus, puisque c'est
/// ici qu'est ecrit `ip route flush table <T>`.
pub fn teardown(cfg: &TunnelConfig) -> Result<Vec<Cmd>> {
    // Ces commandes n'existent que pour WireGuard: c'est sa marque qui echappe
    // a la regle, et sa table dediee qui porte la route par defaut. Le chemin
    // par coeur a son propre aiguillage, avec sa table. Rendre une liste vide
    // plutot qu'echouer, parce que le seul appelant est le peripherique
    // WireGuard, qui sait deja dans quel cas il est.
    let Some(wg) = cfg.portage.wireguard() else {
        return Ok(Vec::new());
    };
    let table = table_libre(wg, "demontage")?.to_string();
    let mark = wg.fwmark.to_string();
    let mut cmds = Vec::new();

    for family in ["-4", "-6"] {
        cmds.push(Cmd::ip_lenient(&[
            family, "rule", "del", "not", "fwmark", &mark, "table", &table,
        ]));
        cmds.push(Cmd::ip_lenient(&[
            family,
            "rule",
            "del",
            "table",
            "main",
            "suppress_prefixlength",
            "0",
        ]));
        cmds.push(Cmd::ip_lenient(&[
            family, "route", "flush", "table", &table,
        ]));
    }
    cmds.push(Cmd::ip_lenient(&["link", "del", "dev", &cfg.interface]));
    Ok(cmds)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bifrost_core::config::{DnsPolicy, Endpoint, PeerConfig, WgKey};
    use std::net::{IpAddr, Ipv4Addr};

    /// Le 43e caractere d'une cle ne porte que quatre bits utiles, donc tous
    /// ne conviennent pas. 'A' vaut zero: il termine n'importe quelle cle.
    fn key(c: char) -> WgKey {
        let mut s: String = std::iter::repeat_n(c, 42).collect();
        s.push('A');
        s.push('=');
        s.parse().unwrap()
    }

    fn cfg() -> TunnelConfig {
        TunnelConfig {
            interface: "wg0".into(),
            addresses: vec!["10.2.0.2/32".parse().unwrap()],
            mtu: 1420,
            portage: bifrost_core::config::Portage::Wireguard(Box::new(
                bifrost_core::config::WireguardParams {
                    private_key: key('a'),
                    fwmark: 0xca6c,
                    routing_table: 51820,
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
                },
            )),
            dns: DnsPolicy {
                local_resolver: IpAddr::V4(Ipv4Addr::LOCALHOST),
                upstream: vec![IpAddr::V4(Ipv4Addr::new(10, 2, 0, 1))],
                embarque: false,
                anti_telemetrie: bifrost_core::config::ProfilTelemetrie::Aucun,
            },
            allow_lan: false,
        }
    }

    /// Les parametres WireGuard d'une configuration de test, modifiables.
    /// Panique si le portage n'est pas WireGuard: seul un test mal ecrit peut
    /// y arriver.
    fn wg(c: &mut TunnelConfig) -> &mut bifrost_core::config::WireguardParams {
        match &mut c.portage {
            bifrost_core::config::Portage::Wireguard(w) => w,
            bifrost_core::config::Portage::Coeur(_) => {
                panic!("ce test suppose un portage WireGuard")
            }
        }
    }

    fn lignes(cmds: &[Cmd]) -> Vec<String> {
        cmds.iter().map(Cmd::display).collect()
    }

    /// La pose d'une configuration dont la table est libre.
    fn pose(c: &TunnelConfig) -> Vec<Cmd> {
        add_routing(c).expect("une table libre doit se poser")
    }

    /// Le demontage d'une configuration dont la table est libre.
    fn retrait(c: &TunnelConfig) -> Vec<Cmd> {
        teardown(c).expect("une table libre doit se retirer")
    }

    /// Les tables que le noyau se reserve (`rt_class_t`,
    /// `include/uapi/linux/rtnetlink.h`), en litteraux et non tirees de
    /// `routage::TABLES_RESERVEES`: retirer une valeur de la liste doit faire
    /// rougir ces recettes, pas les suivre.
    const RESERVEES: [(u32, &str); 4] = [
        (0, "unspec"),
        (253, "default"),
        (254, "main"),
        (255, "local"),
    ];

    /// Une configuration qui n'est PAS passee par la validation: c'est le cas
    /// que la defense en profondeur couvre. Ces recettes n'appellent jamais
    /// `validate`: elles doivent tenir seules, la validation retiree.
    fn contournant_la_validation(table: u32) -> TunnelConfig {
        let mut c = cfg();
        wg(&mut c).routing_table = table;
        c
    }

    /// Ni pose, ni demontage: aucune commande ne sort pour une table que le
    /// noyau se reserve, meme quand la validation n'a pas eu lieu. Avant cette
    /// garde, le demontage rendait `ip -4 route flush table 254`, qui vide
    /// `main`, et `ip route flush table 0`, que iproute2 lit comme `all`.
    #[test]
    fn une_table_reservee_n_emet_ni_pose_ni_demontage() {
        for (table, nom) in RESERVEES {
            let c = contournant_la_validation(table);
            let e = add_routing(&c)
                .expect_err(&format!("pose rendue pour la table {table}"))
                .to_string();
            assert!(
                e.contains(&format!("table {table} ('{nom}')")) && e.contains("routing_table"),
                "le refus de pose doit nommer la table et le champ: {e}"
            );
            let e = teardown(&c)
                .expect_err(&format!("demontage rendu pour la table {table}"))
                .to_string();
            assert!(
                e.contains(&format!("table {table} ('{nom}')")) && e.contains("routing_table"),
                "le refus de demontage doit nommer la table et le champ: {e}"
            );
            assert!(
                e.contains("aucune commande n'est emise"),
                "et dire que rien n'est parti: {e}"
            );
        }
    }

    /// Le temoin du precedent: les voisines des tables reservees se posent et
    /// se retirent, avec leur table dans chaque commande qui en porte une.
    /// 252 est `RT_TABLE_COMPAT`, que le noyau n'utilise pas comme table.
    #[test]
    fn les_tables_voisines_des_reservees_se_posent_et_se_retirent() {
        for table in [1u32, 252, 256, 51820, u32::MAX] {
            let c = contournant_la_validation(table);
            let t = table.to_string();
            let up = lignes(&pose(&c));
            assert_eq!(up.len(), 6, "table {table}: {up:?}");
            assert!(up.iter().any(|l| l.ends_with(&format!("table {t}"))));
            let down = lignes(&retrait(&c));
            assert!(
                down.contains(&format!("ip -4 route flush table {t}")),
                "table {table}: {down:?}"
            );
        }
    }

    /// Le demontage, commande par commande et dans l'ordre, a l'octet pres,
    /// tel que la base `c1fa41a` le rendait pour une table libre: le refus des
    /// tables reservees ne change pas une seule commande executee pour les
    /// autres. Ecrit depuis la base et releve sur elle par le banc.
    #[test]
    fn le_demontage_wireguard_est_celui_de_la_base_a_l_octet_pres() {
        assert_eq!(
            lignes(&retrait(&cfg())),
            [
                "ip -4 rule del not fwmark 51820 table 51820",
                "ip -4 rule del table main suppress_prefixlength 0",
                "ip -4 route flush table 51820",
                "ip -6 rule del not fwmark 51820 table 51820",
                "ip -6 rule del table main suppress_prefixlength 0",
                "ip -6 route flush table 51820",
                "ip link del dev wg0",
            ]
        );
        assert!(retrait(&cfg()).iter().all(|c| c.program == "ip"));
    }

    /// Un portage par coeur n'a ni pose ni demontage WireGuard, et ce n'est
    /// pas un refus: la liste est vide, comme avant.
    #[test]
    fn un_portage_par_coeur_ne_rend_rien_et_ne_refuse_rien() {
        let mut c = cfg();
        c.portage = bifrost_core::config::Portage::Coeur(Box::new(
            bifrost_core::profil::Profil::depuis_lien("hy2://mot-de-passe@203.0.113.8:8443")
                .unwrap()
                .into(),
        ));
        assert!(add_routing(&c).unwrap().is_empty());
        assert!(teardown(&c).unwrap().is_empty());
    }

    /// Les litteraux de ces recettes sont ceux du noyau, lus DEHORS: dans libc,
    /// qui les tient de `rtnetlink.h`. Linux seulement, parce que libc ne les
    /// declare que la.
    #[cfg(target_os = "linux")]
    #[test]
    fn les_tables_reservees_sont_celles_de_libc() {
        let libc_tables = [
            libc::RT_TABLE_UNSPEC as u32,
            libc::RT_TABLE_DEFAULT as u32,
            libc::RT_TABLE_MAIN as u32,
            libc::RT_TABLE_LOCAL as u32,
        ];
        assert_eq!(RESERVEES.map(|(t, _)| t), libc_tables);
        assert_eq!(bifrost_core::routage::TABLES_RESERVEES, libc_tables);
    }

    #[test]
    fn creation_de_l_interface_wireguard() {
        assert_eq!(
            create_link(&cfg()).display(),
            "ip link add dev wg0 type wireguard"
        );
    }

    #[test]
    fn les_adresses_et_le_mtu_sont_poses() {
        let l = lignes(&configure_link(&cfg()));
        assert!(l.contains(&"ip -4 address add 10.2.0.2/32 dev wg0".to_owned()));
        assert!(l.contains(&"ip link set mtu 1420 up dev wg0".to_owned()));
    }

    #[test]
    fn une_adresse_ipv6_utilise_la_bonne_famille() {
        let mut c = cfg();
        c.addresses = vec!["fd00::2/128".parse().unwrap()];
        let l = lignes(&configure_link(&c));
        assert!(l.contains(&"ip -6 address add fd00::2/128 dev wg0".to_owned()));
    }

    /// Le coeur du mecanisme wg-quick.
    #[test]
    fn la_regle_fwmark_et_la_suppression_de_prefixe_sont_posees() {
        let l = lignes(&pose(&cfg()));
        assert!(l.contains(&"ip -4 rule add not fwmark 51820 table 51820".to_owned()));
        assert!(l.contains(&"ip -4 rule add table main suppress_prefixlength 0".to_owned()));
        assert!(l.contains(&"ip -4 route add 0.0.0.0/0 dev wg0 table 51820".to_owned()));
    }

    /// La pose, commande par commande et dans l'ordre, a l'octet pres.
    ///
    /// Depuis D1c.1 ces commandes sont rendues par le plan pur de
    /// `bifrost_core::routage`, que la preuve `prove routes` lit aussi. Cette
    /// recette fige la liste telle que la base `6e9a200` la rendait: toute
    /// difference d'un seul argument, ou de l'ordre (qui decide des priorites
    /// que le noyau attribue a des regles posees sans `pref`), la fait rougir.
    #[test]
    fn la_pose_wireguard_est_celle_de_la_base_a_l_octet_pres() {
        assert_eq!(
            lignes(&pose(&cfg())),
            [
                "ip -4 route add 0.0.0.0/0 dev wg0 table 51820",
                "ip -4 rule add not fwmark 51820 table 51820",
                "ip -4 rule add table main suppress_prefixlength 0",
                "ip -6 route add ::/0 dev wg0 table 51820",
                "ip -6 rule add not fwmark 51820 table 51820",
                "ip -6 rule add table main suppress_prefixlength 0",
            ]
        );
        let mut c = cfg();
        c.interface = "bf-wg_9".into();
        wg(&mut c).fwmark = 0x1f2e3d;
        wg(&mut c).routing_table = 30303;
        assert_eq!(
            lignes(&pose(&c)),
            [
                "ip -4 route add 0.0.0.0/0 dev bf-wg_9 table 30303",
                "ip -4 rule add not fwmark 2043453 table 30303",
                "ip -4 rule add table main suppress_prefixlength 0",
                "ip -6 route add ::/0 dev bf-wg_9 table 30303",
                "ip -6 rule add not fwmark 2043453 table 30303",
                "ip -6 rule add table main suppress_prefixlength 0",
            ]
        );
        assert!(
            pose(&c)
                .iter()
                .all(|cmd| cmd.program == "ip" && !cmd.tolerate_failure),
            "la pose n'est jamais toleree en echec"
        );
    }

    /// Sans route par defaut IPv6 dans le tunnel, l'IPv6 fuit par l'interface
    /// physique meme quand IPv4 est correctement route.
    #[test]
    fn l_ipv6_est_route_dans_le_tunnel_meme_sans_adresse_ipv6() {
        let mut c = cfg();
        c.addresses = vec!["10.2.0.2/32".parse().unwrap()];
        let l = lignes(&pose(&c));
        assert!(l.contains(&"ip -6 route add ::/0 dev wg0 table 51820".to_owned()));
        assert!(l.contains(&"ip -6 rule add not fwmark 51820 table 51820".to_owned()));
    }

    #[test]
    fn le_fwmark_de_la_config_est_utilise_partout() {
        let mut c = cfg();
        wg(&mut c).fwmark = 0x1234;
        wg(&mut c).routing_table = 4660;
        let l = lignes(&pose(&c)).join("\n");
        assert!(l.contains("not fwmark 4660 table 4660") || l.contains("not fwmark 4660"));
        assert!(!l.contains("51820"));
    }

    #[test]
    fn le_demontage_tolere_l_absence_des_regles() {
        let cmds = retrait(&cfg());
        assert!(
            cmds.iter().all(|c| c.tolerate_failure),
            "le demontage doit aboutir meme partiellement applique"
        );
    }

    #[test]
    fn le_demontage_retire_regles_routes_et_interface() {
        let l = lignes(&retrait(&cfg())).join("\n");
        assert!(l.contains("rule del not fwmark 51820"));
        assert!(l.contains("rule del table main suppress_prefixlength 0"));
        assert!(l.contains("link del dev wg0"));
        // v4 et v6 pour les regles.
        assert_eq!(l.matches("rule del not fwmark").count(), 2);
    }

    /// Le demontage doit annuler exactement ce que le montage a pose.
    #[test]
    fn montage_et_demontage_sont_symetriques() {
        let c = cfg();
        let up = lignes(&pose(&c));
        let down = lignes(&retrait(&c));
        for cmd in &up {
            let inverse = cmd.replacen(" add ", " del ", 1);
            let couvert = down.contains(&inverse)
                // les routes de la table dediee partent avec `route flush`
                || (cmd.contains("route add") && down.iter().any(|d| d.contains("route flush")));
            assert!(couvert, "aucun inverse pour: {cmd}");
        }
    }

    /// Le nom d'interface vient de la config, deja validee, mais on verifie
    /// qu'il est passe comme argument distinct et jamais concatene dans un
    /// shell: aucune commande ne doit passer par un interpreteur.
    #[test]
    fn les_arguments_ne_sont_jamais_concatenes() {
        for cmd in pose(&cfg()) {
            assert!(
                cmd.args.iter().all(|a| !a.contains(' ')),
                "argument contenant un espace: {cmd:?}"
            );
        }
    }
}
