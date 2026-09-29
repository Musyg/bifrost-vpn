//! Intention nft v1 sans secrets et reference pure du generateur produit.
//!
//! L'intention a deux sources, et un seul lecteur (`lire`): un fichier declare
//! par l'appelant (`prove nft --politique`), ou la projection de la politique
//! que le daemon a remise a son moteur (`projeter`, `prove nft
//! --politique-daemon`). Dans les deux cas c'est un ATTENDU, jamais une
//! observation du noyau.
//! Le rendu JSON est confronte au rendu texte REEL dans le banc Linux jetable.
//! Toute evolution des regles produit doit faire evoluer ce contrat et le banc.

use std::net::IpAddr;

use bifrost_core::ports::FirewallPolicy;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// Tous les champs sont obligatoires, y compris les options explicites null.
/// Ne pas deserialiser directement avec serde: passer par `lire`.
///
/// `Serialize` ecrit toujours les sept cles, les options absentes en `null`:
/// c'est la forme que `lire` exige, donc la forme que le daemon transmet.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Politique {
    pub schema_version: u32,
    pub tunnel_interface: Option<String>,
    pub fwmark: Option<u32>,
    pub dns_resolver: IpAddr,
    pub allow_lan: bool,
    pub coeur_uid: Option<u32>,
    pub resolveur_uid: Option<u32>,
}

impl Politique {
    /// Le JSON doit deja avoir ete controle pour les cles dupliquees.
    pub fn lire(v: Value) -> Result<Self, &'static str> {
        let champs = [
            "schema_version",
            "tunnel_interface",
            "fwmark",
            "dns_resolver",
            "allow_lan",
            "coeur_uid",
            "resolveur_uid",
        ];
        let objet = v.as_object().ok_or("politique nft invalide")?;
        if objet.len() != champs.len() || champs.iter().any(|c| !objet.contains_key(*c)) {
            return Err("champs de politique nft manquants ou inconnus");
        }
        let p: Self = serde_json::from_value(v).map_err(|_| "types de politique nft invalides")?;
        p.valider()?;
        Ok(p)
    }

    fn valider(&self) -> Result<(), &'static str> {
        if self.schema_version != 1 {
            return Err("version de politique nft inconnue");
        }
        if let Some(i) = &self.tunnel_interface
            && (i.is_empty()
                || i.len() > 15
                || i == "lo"
                || !i
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'))
        {
            return Err("interface de politique nft invalide");
        }
        if self.fwmark == Some(0) {
            return Err("marque nulle interdite");
        }
        if self.coeur_uid == Some(0)
            || self.resolveur_uid == Some(0)
            || (self.coeur_uid.is_some() && self.coeur_uid == self.resolveur_uid)
        {
            return Err("identites privilegiees ou partagees interdites");
        }
        if self.dns_resolver.is_unspecified()
            || self.dns_resolver.is_multicast()
            || self.dns_resolver == IpAddr::V4(std::net::Ipv4Addr::BROADCAST)
            || (self.resolveur_uid.is_some() && !self.dns_resolver.is_loopback())
        {
            return Err("destination DNS de politique nft invalide");
        }
        Ok(())
    }

    /// Ce que le moteur nftables LIT d'une politique qu'on lui a remise.
    ///
    /// Le rendu Linux (`linux::ruleset::render`) ne lit que ces six champs. Les
    /// autres (LUID, executables, SID, `resolveur_embarque`) servent a WFP ou
    /// au superviseur et ne changent pas un octet du ruleset; la recette
    /// `la_projection_ne_perd_rien_de_ce_que_nft_rend` le mesure sur le rendu
    /// reel, parce qu'un champ lu par le rendu et absent d'ici ferait
    /// correspondre au noyau une declaration qui ne dit pas tout.
    ///
    /// Aucune validation ici, et c'est voulu: une politique posee par le daemon
    /// peut sortir du perimetre de la reference (interface `lo`, UID root ou
    /// partage). C'est `lire` qui le dira au moment de comparer, et la
    /// comparaison sera alors NON MESUREE, jamais une correspondance.
    pub fn projeter(p: &FirewallPolicy) -> Self {
        Self {
            schema_version: 1,
            tunnel_interface: p.tunnel_interface.clone(),
            fwmark: p.fwmark,
            dns_resolver: p.dns_resolver,
            allow_lan: p.allow_lan,
            coeur_uid: p.coeur_uid,
            resolveur_uid: p.resolveur_uid,
        }
    }

    /// Meme type que celui consomme par le moteur du daemon. Aucun appel OS.
    pub fn firewall_policy(&self) -> Result<FirewallPolicy, &'static str> {
        self.valider()?;
        Ok(FirewallPolicy {
            tunnel_interface: self.tunnel_interface.clone(),
            tunnel_luid: None,
            fwmark: self.fwmark,
            dns_resolver: self.dns_resolver,
            allow_lan: self.allow_lan,
            coeur_uid: self.coeur_uid,
            coeur_executable: None,
            resolveur_uid: self.resolveur_uid,
            resolveur_executable: None,
            resolveur_sid: None,
            resolveur_embarque: self.resolveur_uid.is_some(),
        })
    }

    /// Forme de `nft --json --numeric list ruleset`, hors handles/compteurs.
    pub fn reference(&self) -> Result<Value, &'static str> {
        let p = self.firewall_policy()?;
        let mut objets = vec![
            json!({"metainfo":{"json_schema_version":1}}),
            json!({"table":{"family":"inet","name":"bifrost"}}),
        ];
        for chaine in ["output", "input", "forward"] {
            objets.push(
                json!({"chain":{"family":"inet","table":"bifrost","name":chaine,
                "type":"filter","hook":chaine,"prio":0,"policy":"drop"}}),
            );
        }
        // nft liste toutes les chaines avant leurs regles, meme si le script
        // texte les declare entrelacees. Conserver cet ordre dans la reference.
        for chaine in ["output", "input", "forward"] {
            let mut regles: Vec<Vec<Value>> = Vec::new();
            match chaine {
                "output" => {
                    regles.push(accepter(vec![meta("oifname", json!("lo"))]));
                    if let Some(m) = p.fwmark {
                        regles.push(accepter(vec![meta("mark", json!(m))]));
                    }
                    if let Some(uid) = p.resolveur_uid {
                        for proto in ["udp", "tcp"] {
                            regles.push(accepter(vec![
                                meta("skuid", json!(uid)),
                                charge(proto, "dport", json!(53)),
                            ]));
                        }
                        for proto in ["udp", "tcp"] {
                            regles.push(vec![
                                charge(proto, "dport", json!(53)),
                                json!({"drop":null}),
                            ]);
                        }
                    }
                    if let Some(i) = &p.tunnel_interface {
                        regles.push(accepter(vec![meta("oifname", json!(i))]));
                    }
                    regles.push(accepter(vec![
                        charge("udp", "sport", json!(68)),
                        charge("udp", "dport", json!(67)),
                    ]));
                    regles.push(accepter(vec![
                        charge("ip6", "daddr", prefixe("fe80::", 10)),
                        charge("udp", "sport", json!(546)),
                        charge("udp", "dport", json!(547)),
                    ]));
                    regles.push(ndp());
                    let proto_ip = if p.dns_resolver.is_ipv4() {
                        "ip"
                    } else {
                        "ip6"
                    };
                    for proto in ["udp", "tcp"] {
                        regles.push(accepter(vec![
                            charge(proto_ip, "daddr", json!(p.dns_resolver.to_string())),
                            charge(proto, "dport", json!(53)),
                        ]));
                    }
                    if let Some(uid) = p.coeur_uid {
                        for proto in ["udp", "tcp"] {
                            regles.push(vec![
                                meta("skuid", json!(uid)),
                                charge(proto, "dport", json!(53)),
                                json!({"drop":null}),
                            ]);
                        }
                        regles.push(accepter(vec![meta("skuid", json!(uid))]));
                    }
                    if p.allow_lan {
                        lan(&mut regles, "daddr");
                    }
                }
                "input" => {
                    regles.push(accepter(vec![meta("iifname", json!("lo"))]));
                    // --numeric rend les bits established=2, related=4.
                    regles.push(accepter(vec![
                        json!({"match":{"op":"in","left":{"ct":{"key":"state"}},"right":[2,4]}}),
                    ]));
                    if let Some(i) = &p.tunnel_interface {
                        regles.push(accepter(vec![meta("iifname", json!(i))]));
                    }
                    regles.push(accepter(vec![
                        charge("udp", "sport", json!(67)),
                        charge("udp", "dport", json!(68)),
                    ]));
                    regles.push(accepter(vec![
                        charge("ip6", "saddr", prefixe("fe80::", 10)),
                        charge("udp", "sport", json!(547)),
                        charge("udp", "dport", json!(546)),
                    ]));
                    regles.push(ndp());
                    if p.allow_lan {
                        lan(&mut regles, "saddr");
                    }
                }
                _ => {
                    if let Some(i) = &p.tunnel_interface {
                        regles.push(accepter(vec![meta("oifname", json!(i))]));
                        regles.push(accepter(vec![meta("iifname", json!(i))]));
                    }
                }
            }
            for expr in regles {
                objets.push(
                    json!({"rule":{"family":"inet","table":"bifrost","chain":chaine,"expr":expr}}),
                );
            }
            objets.push(json!({"rule":{"family":"inet","table":"bifrost","chain":chaine,
                "expr":[{"counter":{"packets":0,"bytes":0}}],"comment":format!("bifrost-{chaine}-dropped")}}));
        }
        Ok(json!({"nftables":objets}))
    }
}

fn egal(left: Value, right: Value) -> Value {
    json!({"match":{"op":"==","left":left,"right":right}})
}
fn meta(cle: &str, v: Value) -> Value {
    egal(json!({"meta":{"key":cle}}), v)
}
fn charge(proto: &str, champ: &str, v: Value) -> Value {
    egal(json!({"payload":{"protocol":proto,"field":champ}}), v)
}
fn prefixe(addr: &str, len: u32) -> Value {
    json!({"prefix":{"addr":addr,"len":len}})
}
fn accepter(mut expr: Vec<Value>) -> Vec<Value> {
    expr.push(json!({"accept":null}));
    expr
}
fn ndp() -> Vec<Value> {
    accepter(vec![charge(
        "icmpv6",
        "type",
        json!({"set":[133,134,135,136,137]}),
    )])
}
fn lan(regles: &mut Vec<Vec<Value>>, champ: &str) {
    regles.push(accepter(vec![charge("ip", champ, json!({"set":[prefixe("10.0.0.0",8),prefixe("169.254.0.0",16),prefixe("172.16.0.0",12),prefixe("192.168.0.0",16)]}))]));
    regles.push(accepter(vec![charge(
        "ip6",
        champ,
        json!({"set":[prefixe("fc00::",7),prefixe("fe80::",10)]}),
    )]));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn intention() -> Value {
        json!({"schema_version":1,"tunnel_interface":"wg0","fwmark":51820,
            "dns_resolver":"127.0.0.1","allow_lan":false,"coeur_uid":null,"resolveur_uid":null})
    }

    #[test]
    fn intention_incomplete_ambigue_ou_dangereuse_refusee() {
        let v = intention();
        for cle in v.as_object().unwrap().keys() {
            let mut cas = v.clone();
            cas.as_object_mut().unwrap().remove(cle);
            assert!(Politique::lire(cas).is_err(), "champ absent accepte: {cle}");
        }
        for (cle, valeur) in [
            ("schema_version", json!(2)),
            ("fwmark", json!(0)),
            ("coeur_uid", json!(0)),
            ("resolveur_uid", json!(0)),
            ("dns_resolver", json!("0.0.0.0")),
            ("dns_resolver", json!("ff02::1")),
            ("dns_resolver", json!("255.255.255.255")),
            ("unknown", json!(true)),
            ("tunnel_interface", json!("lo")),
            ("tunnel_interface", json!("wg0\" accept #")),
            ("tunnel_interface", json!("abcdefghijklmnop")),
        ] {
            let mut cas = v.clone();
            cas[cle] = valeur;
            assert!(
                Politique::lire(cas).is_err(),
                "champ invalide accepte: {cle}"
            );
        }
        let mut cas = v.clone();
        cas["coeur_uid"] = json!(1001);
        cas["resolveur_uid"] = json!(1001);
        assert!(Politique::lire(cas).is_err());
        let mut cas = v;
        cas["resolveur_uid"] = json!(1002);
        cas["dns_resolver"] = json!("192.0.2.1");
        assert!(Politique::lire(cas).is_err());
    }

    /// Une politique complete telle que le daemon la remet au moteur: les six
    /// champs que nft lit, plus ceux qu'il ne lit pas, remplis expres pour
    /// qu'une projection qui en dependrait se voie.
    fn remise(n: u32) -> FirewallPolicy {
        FirewallPolicy {
            tunnel_interface: (n & 1 == 1).then(|| "wg0".to_string()),
            tunnel_luid: Some(0x0123_4567_89ab_cdef),
            fwmark: (n & 2 == 2).then_some(51820),
            dns_resolver: if n & 32 == 32 {
                "::1".parse().unwrap()
            } else {
                "127.0.0.1".parse().unwrap()
            },
            allow_lan: n & 4 == 4,
            coeur_uid: (n & 8 == 8).then_some(1001),
            coeur_executable: Some(std::path::PathBuf::from("coeur")),
            resolveur_uid: (n & 16 == 16).then_some(1002),
            resolveur_executable: Some(std::path::PathBuf::from("resolveur")),
            resolveur_sid: Some("S-1-5-19".to_string()),
            // Inverse de ce que `firewall_policy` deduit: si le rendu Linux
            // lisait ce champ, la recette Linux ci-dessous le verrait.
            resolveur_embarque: n & 16 == 0,
        }
    }

    /// La forme transmise par le daemon est exactement celle que `lire`
    /// accepte: sept cles, options absentes en null, rien de plus. Sans cette
    /// egalite, le lecteur strict refuserait une declaration valide, ou une
    /// cle ajoutee cote daemon passerait inapercue cote preuve.
    #[test]
    fn la_projection_serialisee_se_relit_a_l_identique() {
        for n in 0..64 {
            let p = Politique::projeter(&remise(n));
            let v = serde_json::to_value(&p).unwrap();
            assert_eq!(v.as_object().unwrap().len(), 7, "cas {n}");
            assert_eq!(Politique::lire(v).unwrap(), p, "cas {n}");
        }
        let v = serde_json::to_value(Politique::projeter(&remise(0))).unwrap();
        for cle in ["tunnel_interface", "fwmark", "coeur_uid", "resolveur_uid"] {
            assert!(v[cle].is_null(), "option absente non ecrite en null: {cle}");
        }
    }

    /// Le perimetre de la reference ne s'elargit pas par la projection: une
    /// politique que la reference ne sait pas decrire se projette telle
    /// quelle, et c'est `lire` qui la refuse.
    #[test]
    fn une_politique_hors_perimetre_se_projette_sans_devenir_valide() {
        let mut lo = remise(1);
        lo.tunnel_interface = Some("lo".to_string());
        let mut root = remise(8);
        root.coeur_uid = Some(0);
        let mut partage = remise(8 | 16);
        partage.resolveur_uid = partage.coeur_uid;
        for p in [lo, root, partage] {
            let projete = Politique::projeter(&p);
            assert_eq!(projete.tunnel_interface, p.tunnel_interface);
            assert_eq!(projete.coeur_uid, p.coeur_uid);
            assert_eq!(projete.resolveur_uid, p.resolveur_uid);
            let v = serde_json::to_value(projete).unwrap();
            assert!(Politique::lire(v).is_err(), "{p:?}");
        }
    }

    /// La projection ne garde que six champs: c'est sur si et seulement si le
    /// VRAI rendu du moteur ne lit rien d'autre. On le mesure sur le rendu, pas
    /// sur une relecture de son code: 64 combinaisons, tous les champs non
    /// projetes remplis, et `resolveur_embarque` inverse de ce que la
    /// reconstruction en deduit.
    #[cfg(target_os = "linux")]
    #[test]
    fn la_projection_ne_perd_rien_de_ce_que_nft_rend() {
        use crate::linux::ruleset::render;
        for n in 0..64 {
            let remise = remise(n);
            let relue = Politique::projeter(&remise).firewall_policy().unwrap();
            assert_eq!(render(&remise), render(&relue), "cas {n}");
        }
    }

    #[test]
    fn les_exceptions_dns_precedent_les_permits_larges() {
        let mut v = intention();
        v["coeur_uid"] = json!(1001);
        v["resolveur_uid"] = json!(1002);
        let p = Politique::lire(v).unwrap();
        let attendu = p.reference().unwrap();
        let regles: Vec<_> = attendu["nftables"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.get("rule"))
            .filter(|r| r["chain"] == "output")
            .collect();
        let tunnel = regles
            .iter()
            .position(|r| r["expr"][0] == meta("oifname", json!("wg0")))
            .unwrap();
        let dns_drop = regles
            .iter()
            .position(|r| r["expr"] == json!([charge("udp","dport",json!(53)),{"drop":null}]))
            .unwrap();
        assert!(dns_drop < tunnel);
        let coeur = regles
            .iter()
            .position(|r| r["expr"] == json!(accepter(vec![meta("skuid", json!(1001))])))
            .unwrap();
        assert!(
            regles[coeur - 1]["expr"]
                .as_array()
                .unwrap()
                .last()
                .unwrap()
                .get("drop")
                .is_some()
        );
        assert!(
            regles[coeur - 2]["expr"]
                .as_array()
                .unwrap()
                .last()
                .unwrap()
                .get("drop")
                .is_some()
        );
    }
}
