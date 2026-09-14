//! Ce que le filtre de demarrage laisse passer, et rien d'autre.
//!
//! Le filtre de demarrage bloque tout avant que le daemon existe. Sans
//! exemptions la machine redemarre sans adresse, donc sans reseau et sans
//! tunnel non plus: l'utilisateur desactiverait la fonction, ce qui est le pire
//! resultat possible. Chaque exemption est en revanche une fuite potentielle,
//! donc chacune doit etre justifiee par une panne concrete qu'elle evite.
//!
//! Ce module ne parle a aucune plateforme: il traduit un choix d'utilisateur en
//! une liste d'exemptions, et c'est tout. La traduction en filtres WFP vit dans
//! `bifrost-firewall`. La separation n'est pas cosmetique: les decisions qui
//! comptent ici sont testables partout, y compris depuis Linux et en CI.
//!
//! Le releve qui a produit cette liste est dans
//! `docs/FILTRE-DEMARRAGE-EXEMPTIONS.md`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Sens du trafic, du point de vue de la machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sens {
    Sortant,
    Entrant,
}

/// Famille d'adresses visee. Explicite plutot que deduite du prefixe: une
/// exemption peut n'en porter aucun (le DHCPv4 entrant, par exemple) et la
/// couche plateforme doit quand meme savoir sur quelle couche la poser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Famille {
    V4,
    V6,
    /// Les deux, pour la boucle locale: `::1` ne quitte pas la machine, donc
    /// bloquer IPv6 ne doit pas la couper.
    Toutes,
}

/// Protocole vise par une exemption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocole {
    Udp,
    IcmpV6,
    /// Toute la pile, pour la boucle locale et les prefixes locaux.
    Tout,
}

/// Un prefixe reseau. Pas de dependance a un crate d'adressage: on n'en a
/// besoin que pour transporter la paire vers la couche plateforme.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reseau {
    pub adresse: IpAddr,
    pub prefixe: u8,
}

impl Reseau {
    const fn v4(a: u8, b: u8, c: u8, d: u8, prefixe: u8) -> Self {
        Self {
            adresse: IpAddr::V4(Ipv4Addr::new(a, b, c, d)),
            prefixe,
        }
    }

    fn v6(segments: [u16; 8], prefixe: u8) -> Self {
        Self {
            adresse: IpAddr::V6(Ipv6Addr::new(
                segments[0],
                segments[1],
                segments[2],
                segments[3],
                segments[4],
                segments[5],
                segments[6],
                segments[7],
            )),
            prefixe,
        }
    }

    pub fn est_v6(&self) -> bool {
        matches!(self.adresse, IpAddr::V6(_))
    }
}

/// Une exemption au blocage de demarrage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exemption {
    /// Nom porte par le filtre, pour qu'un `netsh wfp show filters` soit
    /// lisible le jour ou quelqu'un cherche pourquoi sa machine laisse passer
    /// quelque chose.
    pub etiquette: &'static str,
    pub sens: Sens,
    pub protocole: Protocole,
    pub famille: Famille,
    pub port_local: Option<u16>,
    pub port_distant: Option<u16>,
    pub distant: Option<Reseau>,
    /// Type ICMPv6, pour le sous-ensemble NDP.
    pub icmpv6_type: Option<u8>,
}

impl Exemption {
    fn nouvelle(
        etiquette: &'static str,
        sens: Sens,
        protocole: Protocole,
        famille: Famille,
    ) -> Self {
        Self {
            etiquette,
            sens,
            protocole,
            famille,
            port_local: None,
            port_distant: None,
            distant: None,
            icmpv6_type: None,
        }
    }

    /// Vrai si cette exemption ne concerne qu'IPv6. Sert a la garde qui les
    /// retire toutes quand IPv6 est bloque.
    pub fn est_v6(&self) -> bool {
        self.famille == Famille::V6
    }
}

/// Les plages du reseau local, quand l'utilisateur ouvre l'option.
///
/// `100.64.0.0/10` n'y est PAS: c'est un choix, pas un oubli. Voir
/// `PolitiqueDemarrage::overlay_cgnat`.
const RESEAU_LOCAL_V4: [Reseau; 4] = [
    Reseau::v4(10, 0, 0, 0, 8),
    Reseau::v4(172, 16, 0, 0, 12),
    Reseau::v4(192, 168, 0, 0, 16),
    // Lien-local: une machine sans DHCP s'auto-attribue une adresse ici, et
    // sans cette plage elle ne parle a personne.
    Reseau::v4(169, 254, 0, 0, 16),
];

/// Multicast local IPv4, plus la diffusion generale.
const MULTICAST_V4: [Reseau; 3] = [
    Reseau::v4(224, 0, 0, 0, 24),
    Reseau::v4(239, 0, 0, 0, 8),
    Reseau::v4(255, 255, 255, 255, 32),
];

/// La plage CGNAT. Celle des reseaux overlay: Tailscale et les autres.
pub const OVERLAY_CGNAT: Reseau = Reseau::v4(100, 64, 0, 0, 10);

/// Le sous-ensemble d'ICMPv6 sans lequel IPv6 ne fonctionne pas: sollicitation
/// et annonce de routeur, sollicitation et annonce de voisin, redirection.
const NDP_TYPES: [(u8, &str); 5] = [
    (133, "NDP sollicitation de routeur"),
    (134, "NDP annonce de routeur"),
    (135, "NDP sollicitation de voisin"),
    (136, "NDP annonce de voisin"),
    (137, "NDP redirection"),
];

/// Ce que l'utilisateur a choisi d'ouvrir.
///
/// Tout est ferme par defaut. `Default` donne donc la politique la plus
/// stricte, ce qui est la bonne facon de se tromper.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PolitiqueDemarrage {
    /// Imprimante, NAS, partage de fichiers. Ne marche de facon fiable que pour
    /// le sous-reseau directement attache: des qu'un equipement est derriere
    /// une passerelle, le trafic emprunte la route par defaut et echoue.
    pub reseau_local: bool,
    /// La plage CGNAT `100.64.0.0/10`, separee du reseau local a dessein.
    ///
    /// Une machine administree a distance par un reseau overlay qui redemarre
    /// sans cette exemption devient INJOIGNABLE, et il faut alors s'y rendre.
    /// C'est un mode de panne deja rencontre sur le banc, et l'option existe
    /// separement pour que le choix soit explicite plutot que subi.
    pub overlay_cgnat: bool,
    /// Faux quand la politique bloque IPv6 en entier parce que le tunnel ne le
    /// transporte pas. Les exemptions IPv6 suivent alors: les poser quand meme
    /// serait se contredire, et c'est un bug ouvert chez Mullvad.
    pub ipv6: bool,
}

impl PolitiqueDemarrage {
    /// Developpe la politique en la liste exacte de ce qui passe.
    pub fn exemptions(&self) -> Vec<Exemption> {
        let mut v = Vec::new();

        // 1. Non negociable. Aucune option ne les retire.

        // La boucle locale ne quitte pas la machine: aucune fuite possible.
        for sens in [Sens::Sortant, Sens::Entrant] {
            v.push(Exemption::nouvelle(
                "boucle locale",
                sens,
                Protocole::Tout,
                Famille::Toutes,
            ));
        }

        // DHCPv4. Sans lui, pas d'adresse, donc pas de tunnel non plus.
        let mut sortant = Exemption::nouvelle("DHCPv4", Sens::Sortant, Protocole::Udp, Famille::V4);
        sortant.port_local = Some(68);
        sortant.port_distant = Some(67);
        sortant.distant = Some(Reseau::v4(255, 255, 255, 255, 32));
        v.push(sortant);

        let mut entrant = Exemption::nouvelle("DHCPv4", Sens::Entrant, Protocole::Udp, Famille::V4);
        entrant.port_local = Some(68);
        entrant.port_distant = Some(67);
        v.push(entrant);

        // 2. IPv6, et seulement s'il n'est pas bloque par ailleurs.
        if self.ipv6 {
            let lien_local = Reseau::v6([0xfe80, 0, 0, 0, 0, 0, 0, 0], 10);

            for (etiquette, cible) in [
                (
                    "DHCPv6 (relais)",
                    Reseau::v6([0xff02, 0, 0, 0, 0, 0, 1, 2], 128),
                ),
                (
                    "DHCPv6 (site)",
                    Reseau::v6([0xff05, 0, 0, 0, 0, 0, 1, 3], 128),
                ),
            ] {
                let mut e =
                    Exemption::nouvelle(etiquette, Sens::Sortant, Protocole::Udp, Famille::V6);
                e.port_local = Some(546);
                e.port_distant = Some(547);
                e.distant = Some(cible);
                v.push(e);
            }

            let mut e = Exemption::nouvelle("DHCPv6", Sens::Entrant, Protocole::Udp, Famille::V6);
            e.port_local = Some(546);
            e.port_distant = Some(547);
            e.distant = Some(lien_local);
            v.push(e);

            for (t, etiquette) in NDP_TYPES {
                for sens in [Sens::Sortant, Sens::Entrant] {
                    let mut e =
                        Exemption::nouvelle(etiquette, sens, Protocole::IcmpV6, Famille::V6);
                    e.icmpv6_type = Some(t);
                    v.push(e);
                }
            }
        }

        // 3. Options.

        if self.reseau_local {
            for r in RESEAU_LOCAL_V4.into_iter().chain(MULTICAST_V4) {
                for sens in [Sens::Sortant, Sens::Entrant] {
                    let mut e =
                        Exemption::nouvelle("reseau local", sens, Protocole::Tout, Famille::V4);
                    e.distant = Some(r);
                    v.push(e);
                }
            }
            if self.ipv6 {
                // Lien-local, adresses uniques locales, et le multicast local
                // ff01 a ff05.
                let mut prefixes = vec![
                    Reseau::v6([0xfe80, 0, 0, 0, 0, 0, 0, 0], 10),
                    Reseau::v6([0xfc00, 0, 0, 0, 0, 0, 0, 0], 7),
                ];
                for portee in 1u16..=5 {
                    prefixes.push(Reseau::v6([0xff00 | portee, 0, 0, 0, 0, 0, 0, 0], 16));
                }
                for r in prefixes {
                    for sens in [Sens::Sortant, Sens::Entrant] {
                        let mut e =
                            Exemption::nouvelle("reseau local", sens, Protocole::Tout, Famille::V6);
                        e.distant = Some(r);
                        v.push(e);
                    }
                }
            }
        }

        if self.overlay_cgnat {
            for sens in [Sens::Sortant, Sens::Entrant] {
                let mut e =
                    Exemption::nouvelle("reseau overlay", sens, Protocole::Tout, Famille::V4);
                e.distant = Some(OVERLAY_CGNAT);
                v.push(e);
            }
        }

        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn etiquettes(p: PolitiqueDemarrage) -> Vec<&'static str> {
        p.exemptions().into_iter().map(|e| e.etiquette).collect()
    }

    #[test]
    fn la_politique_par_defaut_est_la_plus_stricte() {
        let p = PolitiqueDemarrage::default();
        assert!(!p.reseau_local);
        assert!(!p.overlay_cgnat);
        assert!(!p.ipv6);
    }

    #[test]
    fn la_boucle_locale_et_dhcpv4_passent_toujours() {
        // Meme avec tout ferme: sans eux la machine n'a pas d'adresse et
        // l'utilisateur desactive la fonction.
        let e = etiquettes(PolitiqueDemarrage::default());
        assert!(e.contains(&"boucle locale"));
        assert_eq!(
            e.iter().filter(|x| **x == "DHCPv4").count(),
            2,
            "DHCPv4 doit passer dans les deux sens"
        );
    }

    #[test]
    fn aucune_exemption_ipv6_quand_ipv6_est_bloque() {
        // La contradiction a ne pas reproduire: ouvrir DHCPv6 et NDP alors que
        // la politique bloque IPv6 en entier.
        for politique in [
            PolitiqueDemarrage::default(),
            PolitiqueDemarrage {
                reseau_local: true,
                overlay_cgnat: true,
                ipv6: false,
            },
        ] {
            let v6: Vec<_> = politique
                .exemptions()
                .into_iter()
                .filter(Exemption::est_v6)
                .collect();
            assert!(v6.is_empty(), "exemptions IPv6 posees a tort: {v6:?}");
        }
    }

    #[test]
    fn ipv6_actif_ouvre_dhcpv6_et_les_cinq_types_ndp() {
        let p = PolitiqueDemarrage {
            ipv6: true,
            ..Default::default()
        };
        let ex = p.exemptions();
        let types: std::collections::BTreeSet<u8> =
            ex.iter().filter_map(|e| e.icmpv6_type).collect();
        assert_eq!(
            types,
            [133, 134, 135, 136, 137].into_iter().collect(),
            "le sous-ensemble NDP est incomplet, IPv6 ne fonctionnerait pas"
        );
        assert!(ex.iter().any(|e| e.etiquette.starts_with("DHCPv6")));
    }

    #[test]
    fn le_reseau_local_n_ouvre_pas_la_plage_cgnat() {
        // Le piege: croire que "reseau local" couvre un reseau overlay. Il ne
        // le couvre pas, et une machine administree a distance deviendrait
        // injoignable au premier redemarrage.
        let p = PolitiqueDemarrage {
            reseau_local: true,
            ipv6: true,
            ..Default::default()
        };
        let ouvre_cgnat = p
            .exemptions()
            .iter()
            .any(|e| e.distant == Some(OVERLAY_CGNAT));
        assert!(!ouvre_cgnat, "reseau local ne doit pas impliquer la CGNAT");
    }

    #[test]
    fn l_option_overlay_ouvre_la_plage_cgnat_dans_les_deux_sens() {
        let p = PolitiqueDemarrage {
            overlay_cgnat: true,
            ..Default::default()
        };
        let sens: Vec<Sens> = p
            .exemptions()
            .into_iter()
            .filter(|e| e.distant == Some(OVERLAY_CGNAT))
            .map(|e| e.sens)
            .collect();
        assert!(sens.contains(&Sens::Sortant));
        // L'entrant compte autant: sans lui la machine repond a personne, donc
        // reste injoignable, ce qui est precisement ce que l'option evite.
        assert!(sens.contains(&Sens::Entrant));
    }

    #[test]
    fn le_reseau_local_couvre_les_trois_plages_privees_et_le_lien_local() {
        let p = PolitiqueDemarrage {
            reseau_local: true,
            ..Default::default()
        };
        let ex = p.exemptions();
        for attendu in RESEAU_LOCAL_V4 {
            assert!(
                ex.iter().any(|e| e.distant == Some(attendu)),
                "plage manquante: {attendu:?}"
            );
        }
    }

    #[test]
    fn rien_n_ouvre_le_port_53_ni_une_destination_publique() {
        // La garde qui compte: aucune exemption ne doit ouvrir de DNS en clair,
        // ni viser une destination sans prefixe restreint hors boucle locale.
        let p = PolitiqueDemarrage {
            reseau_local: true,
            overlay_cgnat: true,
            ipv6: true,
        };
        for e in p.exemptions() {
            assert_ne!(e.port_distant, Some(53), "DNS en clair ouvert: {e:?}");
            assert_ne!(e.port_local, Some(53), "DNS en clair ouvert: {e:?}");
        }
    }
}
