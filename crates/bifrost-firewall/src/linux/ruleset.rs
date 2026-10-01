//! Generation du ruleset nftables.
//!
//! Fonctions pures: elles produisent du texte, sans toucher au systeme. Le
//! contenu du kill switch est donc verifiable en test sans privileges, ce qui
//! est le seul moyen de tester une regle de blocage sans risquer de couper la
//! machine qui execute les tests.
//!
//! Le ruleset suit le document 02 partie 2.1: famille `inet` (IPv4 et IPv6
//! unifies), `policy drop` sur les trois hooks, et le trafic deja chiffre par
//! WireGuard reconnu par son fwmark.

use std::net::IpAddr;

use bifrost_core::ports::FirewallPolicy;

/// Nom de la table. Une table dediee permet un remplacement atomique sans
/// toucher aux regles des autres outils (Docker, ufw, l'agent de l'hote).
pub const TABLE: &str = "bifrost";

/// Prefixes RFC1918 et unique-local, autorises seulement si `allow_lan`, et
/// jamais pour leur DNS hors resolveur declare, en clair (:53) comme chiffre
/// (:853) (voir `render_lan_permit`).
const LAN_V4: &str = "10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16";
const LAN_V6: &str = "fc00::/7, fe80::/10";

/// Port du DNS chiffre sur TLS (DoT, RFC 7858) en TCP, et sur QUIC (DoQ,
/// RFC 9250) ou DTLS (RFC 8094) en UDP.
const PORT_DNS_CHIFFRE: u16 = 853;

/// L'adresse tombe-t-elle dans un prefixe du LAN (`LAN_V4`, `LAN_V6`)?
///
/// Les quatre plages IPv4 sont exactement `is_private` (10/8, 172.16/12,
/// 192.168/16) et `is_link_local` (169.254/16); les deux IPv6, exactement
/// `is_unique_local` (fc00::/7) et `is_unicast_link_local` (fe80::/10). La
/// recette `l_appartenance_au_lan_suit_les_prefixes_rendus` le verifie aux
/// bornes de chaque prefixe ecrit dans les constantes.
fn dans_le_lan(adresse: IpAddr) -> bool {
    match adresse {
        IpAddr::V4(a) => a.is_private() || a.is_link_local(),
        IpAddr::V6(a) => a.is_unique_local() || a.is_unicast_link_local(),
    }
}

/// La famille nft et l'adresse ecrite d'une destination.
fn famille_et_adresse(adresse: IpAddr) -> (&'static str, String) {
    match adresse {
        IpAddr::V4(a) => ("ip", a.to_string()),
        IpAddr::V6(a) => ("ip6", a.to_string()),
    }
}

/// Types ICMPv6 indispensables au fonctionnement d'IPv6 (NDP).
const NDP_TYPES: &str = "nd-router-solicit, nd-router-advert, nd-neighbor-solicit, \
                         nd-neighbor-advert, nd-redirect";

/// Le ruleset complet, pret pour `nft -f -`.
///
/// Le fichier commence par une creation puis une suppression de la table: c'est
/// l'idiome nftables pour un remplacement idempotent. `nft` traite tout le
/// fichier en une seule transaction noyau, donc il n'existe aucun instant ou
/// les anciennes regles sont retirees sans que les nouvelles soient posees.
pub fn render(policy: &FirewallPolicy) -> String {
    let mut s = String::with_capacity(2048);

    s.push_str("# Bifrost kill switch - genere automatiquement, ne pas editer\n");
    s.push_str(&format!("table inet {TABLE} {{}}\n"));
    s.push_str(&format!("delete table inet {TABLE}\n\n"));
    s.push_str(&format!("table inet {TABLE} {{\n"));

    render_output(&mut s, policy);
    render_input(&mut s, policy);
    render_forward(&mut s, policy);

    s.push_str("}\n");
    s
}

/// Le fichier qui retire entierement le kill switch.
pub fn render_teardown() -> String {
    format!(
        "# Bifrost kill switch - retrait\n\
         table inet {TABLE} {{}}\n\
         delete table inet {TABLE}\n"
    )
}

fn render_output(s: &mut String, policy: &FirewallPolicy) {
    s.push_str("\tchain output {\n");
    s.push_str("\t\ttype filter hook output priority filter; policy drop;\n\n");

    s.push_str("\t\t# loopback\n");
    s.push_str("\t\toifname \"lo\" accept\n\n");

    match policy.fwmark {
        Some(mark) => {
            s.push_str("\t\t# trafic deja chiffre par WireGuard: le module noyau marque\n");
            s.push_str("\t\t# ses paquets sortants, ils partent vers l'endpoint en clair.\n");
            s.push_str("\t\t# C'est la seule sortie autorisee vers Internet, et elle est\n");
            s.push_str("\t\t# liee au chiffrement, pas a une IP de destination.\n");
            s.push_str(&format!("\t\tmeta mark {mark:#x} accept\n\n"));
        }
        None => {
            // Un coeur anti-censure porte le trafic: il tourne en espace
            // utilisateur, ses paquets ne sont pas marques, et c'est son
            // identite qui l'exempte, plus bas. Emettre ici une marque de
            // remplissage ouvrirait une sortie que rien n'emprunte; emettre
            // `meta mark 0x0 accept` les ouvrirait toutes.
            s.push_str("\t\t# aucun permit de marque: le trafic n'est pas chiffre par\n");
            s.push_str("\t\t# WireGuard mais porte par un coeur, qui sort par son identite.\n\n");
        }
    }

    render_resolveur_restriction(s, policy);

    if let Some(iface) = &policy.tunnel_interface {
        s.push_str("\t\t# trafic circulant a l'interieur du tunnel\n");
        s.push_str(&format!("\t\toifname \"{iface}\" accept\n\n"));
    }

    s.push_str("\t\t# client DHCPv4\n");
    s.push_str("\t\tudp sport 68 udp dport 67 accept\n");
    s.push_str("\t\t# client DHCPv6\n");
    s.push_str("\t\tip6 daddr fe80::/10 udp sport 546 udp dport 547 accept\n");
    s.push_str("\t\t# NDP\n");
    s.push_str(&format!("\t\ticmpv6 type {{ {NDP_TYPES} }} accept\n\n"));

    s.push_str("\t\t# DNS hors tunnel: uniquement vers le resolveur declare. Tout\n");
    s.push_str("\t\t# autre :53 qui arrive ici tombe: dans la policy drop, ou,\n");
    s.push_str("\t\t# LAN ouvert, dans le drop pose avant l'acceptation du LAN,\n");
    s.push_str("\t\t# comme le :853 (DoT, DoQ) du LAN hors resolveur declare.\n");
    render_dns_permits(s, policy.dns_resolver);

    render_coeur_permit(s, policy);

    if policy.allow_lan {
        render_lan_permit(s, policy.dns_resolver);
    }

    s.push_str("\n\t\t# tout le reste est droppe par la policy. Le compteur sert\n");
    s.push_str("\t\t# au diagnostic: il n'a pas de verdict et n'affaiblit rien.\n");
    s.push_str("\t\tcounter comment \"bifrost-output-dropped\"\n");
    s.push_str("\t}\n\n");
}

/// Laisse sortir le coeur anti-censure, et lui seul.
///
/// Un coeur est ce qui sort HORS du tunnel, puisque c'est lui le transport:
/// ses paquets ne portent pas le `fwmark` et ne passent pas par l'interface du
/// tunnel. Sans cette regle, la `policy drop` les jette et le kill switch
/// etrangle le composant meme qui devait porter le trafic.
///
/// Les deux `drop` qui precedent l'`accept` ne sont pas une precaution
/// decorative. Les permits DNS sont poses PLUS HAUT dans la chaine, donc un
/// `skuid` nu placerait le coeur au-dessus de la restriction: il pourrait
/// interroger n'importe quel resolveur en clair, ce qui est exactement la
/// fuite DNS que le reste du ruleset interdit. Le coeur garde le droit de
/// resoudre, mais par le resolveur local comme tout le monde, puisque ce
/// permit-la est deja passe.
///
/// Rien n'est ajoute a `input`: les reponses reviennent par
/// `ct state established,related`, deja autorise. Ouvrir davantage serait
/// accorder au coeur le droit d'ETRE joint, dont il n'a pas besoin.
///
/// Pourquoi cette exemption ne remplace pas celle du `fwmark`, et ne peut pas
/// la remplacer. `meta skuid` lit le proprietaire du SOCKET emetteur. Mesure du
/// 16/08/2026 sur un tunnel WireGuard noyau, en namespace: le paquet chiffre
/// est bien presente au hook `output`, mais il n'y porte NI l'uid de
/// l'application qui a ecrit dans le tunnel, NI l'uid 0 du socket noyau; aucune
/// valeur de `skuid` ne le matche. Le `fwmark`, lui, y est present, ce qui
/// confirme que le noyau marque apres avoir chiffre. D'ou deux exemptions de
/// formes differentes, et c'est voulu: un coeur tiers tourne en espace
/// utilisateur et vise des destinations arbitraires, donc il s'exempte par
/// identite; WireGuard nu est monte par Bifrost lui-meme en mode noyau, n'a
/// aucune identite a offrir, et s'exempte par la marque que le chiffrement
/// laisse. Les unifier reviendrait a couper l'un des deux.
fn render_coeur_permit(s: &mut String, policy: &FirewallPolicy) {
    let Some(uid) = policy.coeur_uid else {
        return;
    };
    s.push_str("\n\t\t# coeur anti-censure: il porte le trafic, donc il sort en\n");
    s.push_str("\t\t# clair. On autorise une IDENTITE, jamais une destination.\n");
    s.push_str("\t\t# Son :53 hors resolveur local tombe d'abord, sans quoi\n");
    s.push_str("\t\t# cette exemption rouvrirait la fuite DNS.\n");
    s.push_str(&format!("\t\tmeta skuid {uid} udp dport 53 drop\n"));
    s.push_str(&format!("\t\tmeta skuid {uid} tcp dport 53 drop\n"));
    s.push_str(&format!("\t\tmeta skuid {uid} accept\n"));
}

/// Ferme le :53 A L'INTERIEUR du tunnel quand un resolveur embarque ecoute.
///
/// La position de ces regles est leur raison d'etre. `oifname <tunnel> accept`
/// accepte TOUT ce qui sort par le tunnel, y compris une requete DNS vers le
/// resolveur public que l'application a choisi. Rien ne fuit sur le fil local,
/// et c'est ce qui rend le trou difficile a voir: le vecteur `dns-leak` reste
/// vert. Mais la requete ressort en clair a la sortie du tunnel, lisible et
/// falsifiable par qui l'exploite, pendant que l'utilisateur croit interroger
/// le resolveur qu'on lui a annonce. Posees APRES l'acceptation du tunnel, ces
/// regles ne serviraient a rien.
///
/// L'exception vise le resolveur lui-meme, et par IDENTITE, jamais par
/// destination. Il en a besoin pour son bootstrap: pour joindre son serveur
/// DoH il doit d'abord resoudre le NOM de ce serveur, et cette premiere
/// requete-la ne peut pas etre chiffree par le service qu'elle sert a
/// atteindre. Elle part donc en clair, mais par le tunnel, vers les
/// `bootstrap_resolvers` de sa configuration.
///
/// Rien n'est emis quand aucun resolveur n'est declare: fermer le :53 sans
/// que rien n'ecoute sur la boucle locale ne serait pas un durcissement, ce
/// serait une machine sans resolution de noms.
fn render_resolveur_restriction(s: &mut String, policy: &FirewallPolicy) {
    let Some(uid) = policy.resolveur_uid else {
        return;
    };
    s.push_str("\t\t# Resolveur chiffre embarque: le :53 ne sort plus, meme par\n");
    s.push_str("\t\t# le tunnel. Les applications passent par la boucle locale,\n");
    s.push_str("\t\t# acceptee plus haut. Seul le resolveur garde le droit d'en\n");
    s.push_str("\t\t# emettre, pour le bootstrap de son propre serveur chiffre.\n");
    s.push_str(&format!("\t\tmeta skuid {uid} udp dport 53 accept\n"));
    s.push_str(&format!("\t\tmeta skuid {uid} tcp dport 53 accept\n"));
    s.push_str("\t\tudp dport 53 drop\n");
    s.push_str("\t\ttcp dport 53 drop\n\n");
}

/// Ouvre le LAN, que l'utilisateur a demande, sauf son DNS: le :53 en clair
/// et le :853 du DNS chiffre (DoT en TCP, DoQ en UDP).
///
/// Les drops precedent l'acceptation du LAN, dans les deux familles et en TCP
/// comme en UDP, et c'est leur position qui les fait mordre: poses apres elle,
/// ils seraient syntaxiquement corrects et sans le moindre effet. Sans ceux du
/// :53, une requete DNS vers une adresse du LAN (le serveur DNS du lien
/// physique, annonce par DHCP, typiquement la box) sortirait en clair par ce
/// permis, hors tunnel. Sans ceux du :853, la meme requete y sortirait
/// chiffree, mais vers un resolveur du LAN qui n'est pas celui que le produit
/// impose, hors tunnel lui aussi. Windows ferme les deux par le poids:
/// `block-dns` (14) au-dessus du tunnel (12) et du LAN, et `block-dot-lan-v4`
/// et `block-dot-lan-v6` (11) au-dessus de `permit-lan-v4` et `permit-lan-v6`
/// (10) mais sous le tunnel.
///
/// Le resolveur declare (`dns_resolver`) echappe aux deux. Son :53 est accepte
/// plus haut par son propre permit; son :853, quand il vit sur le LAN, par les
/// deux accepts poses ici juste avant les drops du :853. Hors du LAN, aucun
/// drop ne le concerne et rien n'est emis: un resolveur de boucle locale passe
/// par `oifname "lo" accept`, un resolveur public ne gagne aucune sortie.
///
/// Ce qui passe encore, parce que c'est accepte PLUS HAUT dans la chaine: le
/// tunnel, y compris vers un resolveur d'une plage privee joint par lui, :853
/// compris; le trafic marque par WireGuard; le coeur, dont le :53 est deja
/// tombe par ses propres drops; et le resolveur embarque, dont la restriction
/// ferme deja le :53 pour tous les autres. Le reste du LAN reste ouvert, 443
/// compris: un DoH vers le LAN ne se distingue pas de HTTPS a la couche ou
/// travaillent nftables et WFP, et ce ruleset ne pretend pas le fermer.
fn render_lan_permit(s: &mut String, resolveur: IpAddr) {
    s.push_str("\n\t\t# acces LAN active explicitement par l'utilisateur, sauf son\n");
    s.push_str("\t\t# DNS, :53 puis :853, qui tombe d'abord dans les deux familles:\n");
    s.push_str("\t\t# le resolveur declare a son permit :53 plus haut, et son :853\n");
    s.push_str("\t\t# juste avant les drops du :853 quand il vit sur le LAN.\n");
    for (famille, prefixes) in [("ip", LAN_V4), ("ip6", LAN_V6)] {
        for proto in ["udp", "tcp"] {
            s.push_str(&format!(
                "\t\t{famille} daddr {{ {prefixes} }} {proto} dport 53 drop\n"
            ));
        }
    }
    if dans_le_lan(resolveur) {
        let (famille, adresse) = famille_et_adresse(resolveur);
        for proto in ["udp", "tcp"] {
            s.push_str(&format!(
                "\t\t{famille} daddr {adresse} {proto} dport {PORT_DNS_CHIFFRE} accept\n"
            ));
        }
    }
    for (famille, prefixes) in [("ip", LAN_V4), ("ip6", LAN_V6)] {
        for proto in ["udp", "tcp"] {
            s.push_str(&format!(
                "\t\t{famille} daddr {{ {prefixes} }} {proto} dport {PORT_DNS_CHIFFRE} drop\n"
            ));
        }
    }
    s.push_str(&format!("\t\tip daddr {{ {LAN_V4} }} accept\n"));
    s.push_str(&format!("\t\tip6 daddr {{ {LAN_V6} }} accept\n"));
}

fn render_dns_permits(s: &mut String, resolver: IpAddr) {
    let (family, addr) = famille_et_adresse(resolver);
    s.push_str(&format!("\t\t{family} daddr {addr} udp dport 53 accept\n"));
    s.push_str(&format!("\t\t{family} daddr {addr} tcp dport 53 accept\n"));
}

fn render_input(s: &mut String, policy: &FirewallPolicy) {
    s.push_str("\tchain input {\n");
    s.push_str("\t\ttype filter hook input priority filter; policy drop;\n\n");
    s.push_str("\t\tiifname \"lo\" accept\n");
    s.push_str("\t\tct state established,related accept\n");
    if let Some(iface) = &policy.tunnel_interface {
        s.push_str(&format!("\t\tiifname \"{iface}\" accept\n"));
    }
    s.push_str("\t\tudp sport 67 udp dport 68 accept\n");
    s.push_str("\t\tip6 saddr fe80::/10 udp sport 547 udp dport 546 accept\n");
    s.push_str(&format!("\t\ticmpv6 type {{ {NDP_TYPES} }} accept\n"));
    if policy.allow_lan {
        s.push_str(&format!("\t\tip saddr {{ {LAN_V4} }} accept\n"));
        s.push_str(&format!("\t\tip6 saddr {{ {LAN_V6} }} accept\n"));
    }
    s.push_str("\t\tcounter comment \"bifrost-input-dropped\"\n");
    s.push_str("\t}\n\n");
}

fn render_forward(s: &mut String, policy: &FirewallPolicy) {
    // Sans ce hook, un bridge Docker ou une VM en TAP sort par l'interface
    // physique sans jamais passer par la chaine output.
    s.push_str("\tchain forward {\n");
    s.push_str("\t\ttype filter hook forward priority filter; policy drop;\n\n");
    if let Some(iface) = &policy.tunnel_interface {
        s.push_str(&format!("\t\toifname \"{iface}\" accept\n"));
        s.push_str(&format!("\t\tiifname \"{iface}\" accept\n"));
    }
    s.push_str("\t\tcounter comment \"bifrost-forward-dropped\"\n");
    s.push_str("\t}\n");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::regles_nft;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn policy() -> FirewallPolicy {
        FirewallPolicy {
            tunnel_interface: Some("wg0".into()),
            tunnel_luid: None,
            fwmark: Some(0xca6c),
            dns_resolver: IpAddr::V4(Ipv4Addr::LOCALHOST),
            allow_lan: false,
            coeur_uid: None,
            coeur_executable: None,
            resolveur_uid: None,
            resolveur_executable: None,
            resolveur_sid: None,
            resolveur_embarque: false,
        }
    }

    fn policy_avec_coeur() -> FirewallPolicy {
        FirewallPolicy {
            coeur_uid: Some(977),
            ..policy()
        }
    }

    fn policy_avec_resolveur() -> FirewallPolicy {
        FirewallPolicy {
            resolveur_uid: Some(981),
            resolveur_executable: None,
            resolveur_embarque: true,
            ..policy()
        }
    }

    /// Indice de la premiere ligne dont la REGLE NORMALISEE egale `motif`, pour
    /// comparer des POSITIONS dans la chaine. Une regle nftables correcte posee
    /// au mauvais endroit est sans effet, et rien dans sa syntaxe ne le montre.
    ///
    /// La comparaison porte sur la regle entiere, mot pour mot: une ligne
    /// `meta skuid 9770 accept` ne repond pas pour `meta skuid 977 accept`, la
    /// ou `l.contains(motif)` aurait rendu la position d'un simple prolongement.
    fn ligne_de(regles: &str, motif: &str) -> usize {
        let voulue = regles_nft::normaliser(motif)
            .unwrap_or_else(|| panic!("motif vide apres normalisation: {motif}"));
        regles
            .lines()
            .position(|l| regles_nft::normaliser(l).as_deref() == Some(voulue.as_str()))
            .unwrap_or_else(|| panic!("regle absente des regles: {motif}\n{regles}"))
    }

    /// Sans resolveur embarque, le :53 doit continuer de circuler dans le
    /// tunnel: c'est ainsi que la resolution fonctionne aujourd'hui, et la
    /// fermer sans que rien n'ecoute en boucle locale casserait la machine.
    #[test]
    fn sans_resolveur_declare_le_53_circule_dans_le_tunnel() {
        let r = render(&policy());
        // Absence par sous-chaine, et c'est la bonne question ici: on veut
        // qu'AUCUNE variante d'un drop du :53 ne soit posee. Une sous-chaine
        // attrape aussi une variante enrobee (compteur, commentaire) qu'une
        // egalite de ligne entiere laisserait passer; pour une absence de
        // comportement, la sous-chaine est le filet le plus large.
        assert!(
            !r.contains("udp dport 53 drop"),
            "un drop du :53 est pose alors qu'aucun resolveur local n'ecoute"
        );
    }

    /// Le defaut que cette restriction ferme: `oifname <tunnel> accept`
    /// accepte tout ce qui sort par le tunnel, requetes DNS comprises. Posee
    /// apres lui, la restriction serait syntaxiquement correcte et sans le
    /// moindre effet.
    #[test]
    fn la_restriction_dns_precede_l_acceptation_du_tunnel() {
        let r = render(&policy_avec_resolveur());
        assert!(
            ligne_de(&r, "udp dport 53 drop") < ligne_de(&r, "oifname \"wg0\" accept"),
            "le drop du :53 est pose apres l'acceptation du tunnel: sans effet\n{r}"
        );
    }

    /// Et l'exception du resolveur doit preceder le drop, sinon son bootstrap
    /// tombe et il ne peut jamais joindre son serveur chiffre.
    #[test]
    fn l_exception_du_resolveur_precede_le_drop() {
        let r = render(&policy_avec_resolveur());
        assert!(
            ligne_de(&r, "meta skuid 981 udp dport 53 accept") < ligne_de(&r, "udp dport 53 drop"),
            "le resolveur est bloque par le drop qu'il est cense franchir\n{r}"
        );
    }

    /// L'exception vise une IDENTITE et jamais une destination. Autoriser une
    /// IP de bootstrap ouvrirait ce :53 a tous les programmes de la machine.
    #[test]
    fn l_exception_du_resolveur_ne_nomme_aucune_destination() {
        let r = render(&policy_avec_resolveur());
        for ligne in r.lines().filter(|l| l.contains("dport 53 accept")) {
            assert!(
                ligne.contains("meta skuid") || ligne.contains("daddr 127.0.0.1"),
                "une autorisation :53 designe autre chose qu'une identite ou \
                 la boucle locale: {ligne}"
            );
        }
    }

    /// TCP autant qu'UDP: un resolveur qui bascule en TCP sur reponse tronquee
    /// est le comportement normal du DNS, pas un cas limite.
    #[test]
    fn la_restriction_couvre_tcp_et_udp() {
        let r = render(&policy_avec_resolveur());
        // Reconnaissance de la regle ENTIERE: `meta skuid 9810 ...` ne
        // repondrait pas pour l'uid 981, la ou `contains` l'aurait fait.
        for regle in [
            "udp dport 53 drop",
            "tcp dport 53 drop",
            "meta skuid 981 udp dport 53 accept",
            "meta skuid 981 tcp dport 53 accept",
        ] {
            assert!(regles_nft::porte(&r, regle), "regle absente: {regle}\n{r}");
        }
    }

    /// Les deux UID ne jouent pas le meme role et ne doivent pas se confondre:
    /// le coeur est exempte pour sortir hors du tunnel, le resolveur est
    /// restreint pour ne pas en sortir.
    #[test]
    fn le_resolveur_n_herite_pas_de_l_exemption_du_coeur() {
        let r = render(&FirewallPolicy {
            coeur_uid: Some(977),
            resolveur_uid: Some(981),
            resolveur_executable: None,
            resolveur_embarque: true,
            ..policy()
        });
        let sorties_en_clair: Vec<_> = r
            .lines()
            .filter(|l| l.contains("meta skuid") && l.contains("accept") && !l.contains("dport 53"))
            .collect();
        // L'identite est lue par mot exact, pas par sous-chaine: `contains("977")`
        // aurait aussi accepte `meta skuid 9770 accept` ou `9771`, donnant une
        // sortie hors tunnel au resolveur sans que la recette ne rougisse.
        assert!(
            sorties_en_clair
                .iter()
                .all(|l| regles_nft::uid_de(l) == Some(977)),
            "le resolveur a recu une sortie hors tunnel: {sorties_en_clair:?}"
        );
    }

    /// Nombre de declarations de chaine en policy drop. On compte la
    /// declaration exacte et pas la sous-chaine "policy drop", qui apparait
    /// aussi dans les commentaires du ruleset.
    fn chaines_en_drop(r: &str) -> usize {
        r.matches("priority filter; policy drop;").count()
    }

    /// Les trois hooks doivent etre en policy drop. C'est le kill switch.
    #[test]
    fn les_trois_hooks_sont_en_policy_drop() {
        let r = render(&policy());
        for hook in ["output", "input", "forward"] {
            assert!(
                r.contains(&format!("hook {hook} priority filter; policy drop;")),
                "hook {hook} sans policy drop:\n{r}"
            );
        }
        assert_eq!(chaines_en_drop(&r), 3, "ruleset:\n{r}");
        assert!(!r.contains("policy accept"), "ruleset:\n{r}");
    }

    #[test]
    fn le_trafic_marque_par_wireguard_sort() {
        let r = render(&policy());
        // Regle de marque reconnue entiere: `meta mark 0xca6c1 accept` ne
        // repondrait pas pour la marque 0xca6c.
        assert!(regles_nft::porte(&r, "meta mark 0xca6c accept"));
    }

    #[test]
    fn le_fwmark_suit_la_politique() {
        let mut p = policy();
        p.fwmark = Some(0x1234);
        let r = render(&p);
        assert!(regles_nft::porte(&r, "meta mark 0x1234 accept"));
        // Absence par la sous-chaine la plus large: un variant enrobe echappe a l'egalite de regle.
        assert!(
            !r.contains("0xca6c"),
            "l'ancienne marque 0xca6c survit au changement de fwmark:\n{r}"
        );
    }

    /// Le cas d'un coeur: rien ne sort marque, donc AUCUN permit de marque.
    ///
    /// C'est la raison d'etre du type optionnel. Tant que le champ etait un
    /// `u32`, "pas de marque" ne pouvait s'ecrire que `0`, qui rend
    /// `meta mark 0x0 accept` - un laissez-passer. Le seul recours etait de
    /// refuser d'armer, ce qui empechait purement et simplement un tunnel par
    /// coeur d'exister.
    #[test]
    fn sans_marque_aucun_permit_de_marque_n_est_emis() {
        let mut p = policy();
        p.fwmark = None;
        let r = render(&p);
        // Absence du mot-cle `meta mark`: la question est qu'AUCUN permit de
        // marque n'existe. Le mot-cle ne parait que dans un permit de marque,
        // donc la sous-chaine est ici exacte pour l'absence, et plus large
        // qu'une egalite de regle: elle attrape n'importe quelle marque.
        assert!(
            !r.contains("meta mark"),
            "un permit de marque a ete emis sans marque a permettre:\n{r}"
        );
        // Et surtout pas la forme qui laisse tout passer. Absence par la
        // sous-chaine la plus large: la marque nulle, quelle que soit sa forme.
        assert!(!r.contains("0x0 accept"), "{r}");
        // Le reste de la politique tient: la sortie reste fermee par defaut.
        // `policy drop` reste une sous-chaine: c'est un fragment de tete de
        // chaine, jamais une regle entiere.
        assert!(r.contains("policy drop"), "{r}");
    }

    /// Le temoin negatif du precedent: sans lui, un rendu qui n'emettrait
    /// jamais de permit de marque passerait les deux tests.
    #[test]
    fn avec_une_marque_le_permit_revient() {
        let r = render(&policy());
        assert!(r.contains("meta mark"), "{r}");
    }

    /// L'endpoint ne doit jamais etre autorise par son IP: ce serait un canal
    /// de sortie en clair exploitable par n'importe quel processus. Seul le
    /// fwmark, qui atteste du chiffrement, ouvre la sortie.
    #[test]
    fn l_endpoint_n_est_pas_autorise_par_ip() {
        let r = render(&policy());
        assert!(
            !r.contains("203.0.113.7"),
            "l'IP de l'endpoint ne doit pas apparaitre dans le ruleset:\n{r}"
        );
    }

    #[test]
    fn dns_limite_au_resolveur_local_en_udp_et_tcp() {
        let r = render(&policy());
        assert!(r.contains("ip daddr 127.0.0.1 udp dport 53 accept"));
        assert!(r.contains("ip daddr 127.0.0.1 tcp dport 53 accept"));
        assert_eq!(r.matches("dport 53").count(), 2);
    }

    #[test]
    fn dns_supporte_un_resolveur_ipv6() {
        let mut p = policy();
        p.dns_resolver = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let r = render(&p);
        assert!(r.contains("ip6 daddr ::1 udp dport 53 accept"));
        assert!(r.contains("ip6 daddr ::1 tcp dport 53 accept"));
        assert!(!r.contains("ip daddr 127.0.0.1"));
    }

    /// Avant que l'interface existe, le ruleset ne doit reference aucun tunnel.
    /// C'est l'etat du premier engage, quand seul le handshake peut sortir.
    #[test]
    fn sans_interface_aucune_regle_ne_mentionne_le_tunnel() {
        let mut p = policy();
        p.tunnel_interface = None;
        let r = render(&p);
        // Absence par la sous-chaine la plus large: un `wg0` sans guillemets echappe au mot exact.
        assert!(
            !r.contains("wg0"),
            "une regle nomme le tunnel alors qu'aucune interface n'existe:\n{r}"
        );
        // Mais le blocage est deja complet.
        assert_eq!(chaines_en_drop(&r), 3);
        assert!(regles_nft::porte(&r, "meta mark 0xca6c accept"));
    }

    #[test]
    fn l_interface_du_tunnel_est_autorisee_dans_les_trois_chaines() {
        let r = render(&policy());
        // Regles entieres, et comptees entieres: `oifname "wg01" accept` ne
        // s'ajouterait pas, la ou `matches(...).count()` compte les sous-chaines.
        assert!(regles_nft::porte(&r, "oifname \"wg0\" accept"));
        assert!(regles_nft::porte(&r, "iifname \"wg0\" accept"));
        // output + forward pour oifname, input + forward pour iifname
        assert_eq!(regles_nft::compte(&r, "oifname \"wg0\" accept"), 2);
        assert_eq!(regles_nft::compte(&r, "iifname \"wg0\" accept"), 2);
    }

    #[test]
    fn ndp_et_dhcp_passent() {
        let r = render(&policy());
        assert!(r.contains("nd-neighbor-solicit"));
        assert!(r.contains("nd-router-advert"));
        assert!(r.contains("udp sport 68 udp dport 67 accept"));
        assert!(r.contains("udp sport 546 udp dport 547 accept"));
    }

    /// mDNS, LLMNR, NetBIOS et SSDP ne sont jamais autorises: ils tombent dans
    /// la policy drop. Le test verifie qu'aucun permit ne les a reintroduits.
    #[test]
    fn aucun_permit_pour_les_protocoles_de_decouverte_locale() {
        let r = render(&policy());
        for port in ["5353", "5355", "137", "138", "139", "1900"] {
            assert!(
                !r.contains(&format!("dport {port}")),
                "un permit pour le port {port} a ete introduit:\n{r}"
            );
        }
    }

    #[test]
    fn allow_lan_desactive_n_ouvre_aucun_prefixe_prive() {
        let r = render(&policy());
        assert!(!r.contains("192.168.0.0/16"));
        assert!(!r.contains("10.0.0.0/8"));
    }

    #[test]
    fn allow_lan_active_ouvre_les_prefixes_prives() {
        let mut p = policy();
        p.allow_lan = true;
        let r = render(&p);
        assert!(r.contains("10.0.0.0/8"));
        assert!(r.contains("192.168.0.0/16"));
        assert!(r.contains("fc00::/7"));
    }

    fn policy_lan() -> FirewallPolicy {
        FirewallPolicy {
            allow_lan: true,
            ..policy()
        }
    }

    /// Les deux familles du LAN, avec leurs prefixes tels que le rendu les ecrit.
    const FAMILLES_DU_LAN: [(&str, &str); 2] = [("ip", LAN_V4), ("ip6", LAN_V6)];

    /// Sous `allow_lan`, le :53 du LAN tombe AVANT son acceptation.
    ///
    /// Le defaut que ces drops ferment: `ip daddr { LAN } accept` acceptait
    /// aussi le :53 vers une adresse du LAN (la box, typiquement), et aucun
    /// drop ne le precedait sans resolveur embarque. Mesure avant correction le
    /// 30/09/2026 sur essai-linux, ruleset rendu par ce code dans un namespace
    /// jetable: huit requetes sur huit (UDP et TCP; IPv4, IPv6 unique-locale et
    /// de lien) arrivaient au serveur DNS du LAN. Poses apres l'acceptation,
    /// les drops ne mordraient pas: c'est la position que la recette garde,
    /// famille par famille et protocole par protocole, regle entiere.
    #[test]
    fn sous_allow_lan_le_53_du_lan_tombe_avant_son_acceptation() {
        let r = render(&policy_lan());
        for (famille, prefixes) in FAMILLES_DU_LAN {
            let acceptation = ligne_de(&r, &format!("{famille} daddr {{ {prefixes} }} accept"));
            for proto in ["udp", "tcp"] {
                let drop = ligne_de(
                    &r,
                    &format!("{famille} daddr {{ {prefixes} }} {proto} dport 53 drop"),
                );
                assert!(
                    drop < acceptation,
                    "{famille}/{proto}: le drop du :53 du LAN suit son acceptation, sans effet\n{r}"
                );
            }
        }
    }

    /// Le cas legitime: la box DECLAREE comme resolveur. Son permit, dans sa
    /// famille, precede le drop du :53 du LAN, donc elle reste servie. Une
    /// correction qui poserait les drops au-dessus des permits DNS couperait
    /// toute resolution a qui a declare un resolveur local de son reseau.
    #[test]
    fn un_resolveur_declare_sur_le_lan_reste_admis() {
        for (resolveur, famille, prefixes) in [
            ("192.168.1.1", "ip", LAN_V4),
            ("10.0.0.53", "ip", LAN_V4),
            ("fd00::53", "ip6", LAN_V6),
            ("fe80::1", "ip6", LAN_V6),
        ] {
            let p = FirewallPolicy {
                dns_resolver: resolveur.parse().unwrap(),
                ..policy_lan()
            };
            let r = render(&p);
            for proto in ["udp", "tcp"] {
                let permit = ligne_de(
                    &r,
                    &format!("{famille} daddr {resolveur} {proto} dport 53 accept"),
                );
                let drop = ligne_de(
                    &r,
                    &format!("{famille} daddr {{ {prefixes} }} {proto} dport 53 drop"),
                );
                assert!(
                    permit < drop,
                    "{resolveur}/{proto}: le resolveur declare est bloque par le drop du LAN\n{r}"
                );
            }
        }
    }

    /// Sous `allow_lan`, le :853 du LAN (DoT en TCP, DoQ en UDP) tombe AVANT
    /// son acceptation, comme le :53, famille par famille et protocole par
    /// protocole, regle entiere.
    ///
    /// Le defaut que ces drops ferment: l'acceptation du LAN admettait le DNS
    /// chiffre vers toute adresse du LAN, hors tunnel. Mesure avant correction
    /// le 01/10/2026 sur essai-linux, ruleset rendu par ce code dans un
    /// namespace jetable, LAN ouvert: les huit envois :853 (TCP et UDP; IPv4,
    /// IPv6 unique-locale et de lien) arrivaient aux ecouteurs du LAN.
    #[test]
    fn sous_allow_lan_le_853_du_lan_tombe_avant_son_acceptation() {
        let r = render(&policy_lan());
        for (famille, prefixes) in FAMILLES_DU_LAN {
            let acceptation = ligne_de(&r, &format!("{famille} daddr {{ {prefixes} }} accept"));
            for proto in ["udp", "tcp"] {
                let drop = ligne_de(
                    &r,
                    &format!("{famille} daddr {{ {prefixes} }} {proto} dport 853 drop"),
                );
                assert!(
                    drop < acceptation,
                    "{famille}/{proto}: le drop du :853 du LAN suit son acceptation, sans effet\n{r}"
                );
            }
        }
    }

    /// Le resolveur declare echappe au drop du :853 comme a celui du :53:
    /// quand il vit sur le LAN, son accept, dans sa famille seulement, precede
    /// les drops du :853. Sans lui, un resolveur du lien que l'intention
    /// declare perdrait son DNS chiffre a l'ouverture du LAN.
    #[test]
    fn le_853_d_un_resolveur_declare_sur_le_lan_reste_admis() {
        for (resolveur, famille, prefixes, autre) in [
            ("192.168.1.1", "ip", LAN_V4, "ip6"),
            ("10.0.0.53", "ip", LAN_V4, "ip6"),
            ("172.31.255.254", "ip", LAN_V4, "ip6"),
            ("169.254.0.1", "ip", LAN_V4, "ip6"),
            ("fd00::53", "ip6", LAN_V6, "ip"),
            ("fe80::1", "ip6", LAN_V6, "ip"),
        ] {
            let p = FirewallPolicy {
                dns_resolver: resolveur.parse().unwrap(),
                ..policy_lan()
            };
            let r = render(&p);
            for proto in ["udp", "tcp"] {
                let accept = ligne_de(
                    &r,
                    &format!("{famille} daddr {resolveur} {proto} dport 853 accept"),
                );
                let drop = ligne_de(
                    &r,
                    &format!("{famille} daddr {{ {prefixes} }} {proto} dport 853 drop"),
                );
                assert!(
                    accept < drop,
                    "{resolveur}/{proto}: le resolveur declare est bloque par le drop du :853\n{r}"
                );
                assert!(
                    !regles_nft::porte(
                        &r,
                        &format!("{autre} daddr {resolveur} {proto} dport 853 accept")
                    ),
                    "{resolveur}/{proto}: accept du :853 dans la mauvaise famille\n{r}"
                );
            }
            assert_eq!(
                r.matches("dport 853 accept").count(),
                2,
                "{resolveur}: l'exception du :853 vise plus que le resolveur declare\n{r}"
            );
        }
    }

    /// Hors du LAN, le resolveur declare n'a besoin d'aucune exception (aucun
    /// drop ne le vise) et n'en recoit aucune: une boucle locale passe deja par
    /// `oifname "lo" accept`, et un resolveur public ne doit gagner aucune
    /// sortie :853 hors tunnel du seul fait que le LAN s'ouvre.
    #[test]
    fn hors_du_lan_le_resolveur_declare_ne_gagne_aucun_853() {
        for resolveur in ["127.0.0.1", "::1", "9.9.9.9", "2001:db8::53", "100.64.0.1"] {
            let p = FirewallPolicy {
                dns_resolver: resolveur.parse().unwrap(),
                ..policy_lan()
            };
            let r = render(&p);
            // Absence par la sous-chaine la plus large: aucune variante d'accept du :853.
            assert!(
                !r.contains("dport 853 accept"),
                "{resolveur}: accept du :853 hors du LAN\n{r}"
            );
            assert_eq!(r.matches("dport 853 drop").count(), 4, "{resolveur}\n{r}");
        }
    }

    /// LAN ferme, le :853 ne parait nulle part: la policy drop le refuse deja
    /// partout hors tunnel, et le rendu sans LAN reste celui d'avant.
    #[test]
    fn sans_allow_lan_aucune_regle_ne_nomme_le_853() {
        for resolveur in ["127.0.0.1", "192.168.1.1", "fd00::53"] {
            let p = FirewallPolicy {
                dns_resolver: resolveur.parse().unwrap(),
                ..policy()
            };
            // Absence par la sous-chaine la plus large, sur les REGLES: un
            // commentaire du rendu nomme le :853, et n'est pas une regle.
            let r = render(&p);
            assert!(
                regles_nft::lignes_normalisees(&r)
                    .iter()
                    .all(|l| !l.contains("853")),
                "{resolveur}: une regle nomme le :853 alors que le LAN est ferme\n{r}"
            );
        }
    }

    /// La boucle locale passe avant toute regle du DNS, en clair comme chiffre.
    ///
    /// Voulu, et c'est un ecart avec Windows, ou `block-dns` (14) passe
    /// au-dessus de `permit-loopback` (13). Ici le systeme interroge son
    /// resolveur sur la boucle locale (le stub `127.0.0.53` de
    /// systemd-resolved, ou le resolveur embarque), et ce sont les sorties de
    /// CE resolveur que les regles suivantes filtrent. Une regle du :53 ou du
    /// :853 posee avant `oifname "lo" accept` couperait la resolution de la
    /// machine au lieu de la contenir. Mesure le 01/10/2026 en namespaces
    /// jetables: un stub de boucle locale non declare est servi, et ses relais
    /// vers le LAN et vers le tunnel suivent le ruleset.
    #[test]
    fn la_boucle_locale_precede_toute_regle_du_dns() {
        for p in [
            policy(),
            policy_avec_resolveur(),
            policy_avec_coeur(),
            FirewallPolicy {
                dns_resolver: "192.168.1.1".parse().unwrap(),
                ..policy_lan()
            },
        ] {
            let r = render(&p);
            let boucle = ligne_de(&r, "oifname \"lo\" accept");
            let mut vues = 0;
            for (i, l) in r.lines().enumerate() {
                if let Some(regle) = regles_nft::normaliser(l)
                    && regle
                        .split_whitespace()
                        .collect::<Vec<_>>()
                        .windows(2)
                        .any(|w| w[0] == "dport" && (w[1] == "53" || w[1] == "853"))
                {
                    vues += 1;
                    assert!(
                        boucle < i,
                        "regle du DNS avant la boucle locale: {regle}\n{r}"
                    );
                }
            }
            assert!(
                vues >= 2,
                "aucune regle du DNS lue: la recette ne regarde rien\n{r}"
            );
        }
    }

    /// `dans_le_lan` et les prefixes ECRITS dans le rendu disent la meme chose:
    /// aux deux bornes de chaque prefixe de `LAN_V4` et `LAN_V6` l'adresse est
    /// dedans, et juste a cote elle est dehors. Une plage ajoutee a l'une sans
    /// l'autre ferait diverger l'exception du resolveur et les drops.
    #[test]
    fn l_appartenance_au_lan_suit_les_prefixes_rendus() {
        for prefixe in LAN_V4.split(", ") {
            let (adresse, longueur) = prefixe.split_once('/').unwrap();
            let debut = u32::from(adresse.parse::<Ipv4Addr>().unwrap());
            let taille = 1u32 << (32 - longueur.parse::<u32>().unwrap());
            let fin = debut + (taille - 1);
            for (a, attendu) in [
                (debut, true),
                (fin, true),
                (debut - 1, false),
                (fin + 1, false),
            ] {
                let ip = IpAddr::V4(Ipv4Addr::from(a));
                assert_eq!(dans_le_lan(ip), attendu, "{prefixe}: {ip}");
            }
        }
        for prefixe in LAN_V6.split(", ") {
            let (adresse, longueur) = prefixe.split_once('/').unwrap();
            let debut = u128::from(adresse.parse::<Ipv6Addr>().unwrap());
            let taille = 1u128 << (128 - longueur.parse::<u32>().unwrap());
            let fin = debut + (taille - 1);
            for (a, attendu) in [
                (debut, true),
                (fin, true),
                (debut - 1, false),
                (fin + 1, false),
            ] {
                let ip = IpAddr::V6(Ipv6Addr::from(a));
                assert_eq!(dans_le_lan(ip), attendu, "{prefixe}: {ip}");
            }
        }
    }

    /// Le bloc LAN est le SEUL apport d'`allow_lan`, et il est pose en dernier.
    ///
    /// Sur 32 politiques (tunnel, marque, coeur, resolveur embarque, resolveur
    /// v4 ou v6), le rendu avec LAN, prive de son bloc, est mot pour mot celui
    /// sans LAN: le permit du resolveur declare, l'acceptation du tunnel, la
    /// marque, les drops du coeur et la restriction du resolveur embarque ne
    /// changent ni de forme ni d'ordre. Et le bloc sortant est d'un seul tenant,
    /// drops du :53 puis du :853 d'abord, juste avant le compteur de la chaine.
    /// Les resolveurs de ces 32 politiques sont de boucle locale: aucun accept
    /// du :853 ne s'intercale.
    #[test]
    fn le_bloc_lan_ne_change_aucune_autre_regle() {
        let mut bloc_sortie: Vec<String> = Vec::new();
        for port in [53, PORT_DNS_CHIFFRE] {
            for (famille, prefixes) in FAMILLES_DU_LAN {
                for proto in ["udp", "tcp"] {
                    bloc_sortie.push(format!(
                        "{famille} daddr {{ {prefixes} }} {proto} dport {port} drop"
                    ));
                }
            }
        }
        for (famille, prefixes) in FAMILLES_DU_LAN {
            bloc_sortie.push(format!("{famille} daddr {{ {prefixes} }} accept"));
        }
        bloc_sortie.push("counter comment \"bifrost-output-dropped\"".to_owned());
        let bloc_sortie: Vec<String> = bloc_sortie
            .iter()
            .map(|l| regles_nft::normaliser(l).unwrap())
            .collect();
        let bloc_entree: Vec<String> = FAMILLES_DU_LAN
            .iter()
            .map(|(famille, prefixes)| {
                regles_nft::normaliser(&format!("{famille} saddr {{ {prefixes} }} accept")).unwrap()
            })
            .collect();
        for n in 0u8..32 {
            let base = FirewallPolicy {
                tunnel_interface: (n & 1 == 1).then(|| "wg0".into()),
                fwmark: (n & 2 == 2).then_some(0xca6c),
                coeur_uid: (n & 4 == 4).then_some(977),
                resolveur_uid: (n & 8 == 8).then_some(981),
                resolveur_embarque: n & 8 == 8,
                dns_resolver: if n & 16 == 16 {
                    IpAddr::V6(Ipv6Addr::LOCALHOST)
                } else {
                    IpAddr::V4(Ipv4Addr::LOCALHOST)
                },
                ..policy()
            };
            let sans = regles_nft::lignes_normalisees(&render(&base));
            let avec = regles_nft::lignes_normalisees(&render(&FirewallPolicy {
                allow_lan: true,
                ..base.clone()
            }));
            // Le bloc sortant, d'un seul tenant et dans cet ordre, compteur compris.
            let debut = avec
                .windows(bloc_sortie.len())
                .position(|w| w == bloc_sortie.as_slice())
                .unwrap_or_else(|| {
                    panic!("cas {n}: bloc LAN sortant absent ou desordonne\n{avec:#?}")
                });
            let mut reste = avec.clone();
            reste.drain(debut..debut + bloc_sortie.len() - 1);
            for ligne in &bloc_entree {
                let i = reste
                    .iter()
                    .position(|l| l == ligne)
                    .unwrap_or_else(|| panic!("cas {n}: acceptation entrante absente: {ligne}"));
                reste.remove(i);
            }
            assert_eq!(reste, sans, "cas {n}: le LAN a change une autre regle");
        }
    }

    /// Le remplacement doit etre atomique: creation puis suppression de la
    /// table en tete de fichier, le tout applique en une transaction par nft.
    #[test]
    fn le_ruleset_remplace_la_table_de_facon_idempotente() {
        let r = render(&policy());
        let i_create = r.find("table inet bifrost {}").unwrap();
        let i_delete = r.find("delete table inet bifrost").unwrap();
        let i_real = r.find("table inet bifrost {\n").unwrap();
        assert!(i_create < i_delete, "creation avant suppression");
        assert!(i_delete < i_real, "suppression avant la vraie table");
    }

    #[test]
    fn le_teardown_supprime_la_table() {
        let r = render_teardown();
        assert!(r.contains("delete table inet bifrost"));
        assert!(!r.contains("policy drop"));
    }

    #[test]
    fn sans_coeur_declare_aucune_regle_ne_parle_d_utilisateur() {
        // Le tunnel WireGuard nu ne lance aucun coeur. L'exemption ne doit pas
        // exister par defaut: une regle `skuid` posee "au cas ou" serait un
        // trou ouvert en permanence.
        let r = render(&policy());
        assert!(!r.contains("skuid"), "ruleset:\n{r}");
    }

    #[test]
    fn le_coeur_declare_sort_par_son_uid() {
        let r = render(&policy_avec_coeur());
        // Regle par identite reconnue entiere: un uid qui PROLONGE 977 (par
        // exemple 9770) ne satisfait pas cette recette. `contains` s'y serait
        // pris; la piege `un_uid_en_prolongement_ne_satisfait_pas_la_recette_du_coeur`
        // ci-dessous l'exerce sur un rendu fabrique.
        assert!(
            regles_nft::porte(&r, "meta skuid 977 accept"),
            "ruleset:\n{r}"
        );
    }

    /// La regression qui rouvrirait une fuite DNS.
    ///
    /// Les permits DNS sont poses plus haut dans la chaine, donc un `skuid`
    /// nu placerait le coeur AU-DESSUS de la restriction: il pourrait
    /// interroger n'importe quel resolveur en clair. Les deux `drop` doivent
    /// donc preceder l'`accept`, et ce test garde cet ordre.
    #[test]
    fn l_exemption_du_coeur_ne_rouvre_pas_le_dns() {
        let r = render(&policy_avec_coeur());
        // Positions de REGLES entieres (par `ligne_de`, egalite de ligne
        // normalisee): un prolongement d'uid ne repond pas a la place de 977.
        let drop_udp = ligne_de(&r, "meta skuid 977 udp dport 53 drop");
        let drop_tcp = ligne_de(&r, "meta skuid 977 tcp dport 53 drop");
        let accept = ligne_de(&r, "meta skuid 977 accept");
        assert!(
            drop_udp < accept,
            "le drop UDP doit preceder l'accept:\n{r}"
        );
        assert!(
            drop_tcp < accept,
            "le drop TCP doit preceder l'accept:\n{r}"
        );
        // Et le resolveur local reste joignable, par le permit general pose
        // encore avant: le coeur resout, mais comme tout le monde.
        let permit_local = ligne_de(&r, "ip daddr 127.0.0.1 udp dport 53 accept");
        assert!(permit_local < drop_udp, "ruleset:\n{r}");
    }

    /// L'exemption designe une identite, jamais une destination. Le jour ou
    /// quelqu'un la remplacerait par l'IP du serveur, ce test tombe.
    #[test]
    fn l_exemption_du_coeur_n_ouvre_aucune_destination() {
        let r = render(&policy_avec_coeur());
        assert!(!r.contains("203.0.113.7"), "ruleset:\n{r}");
        // Et elle ne touche ni input ni forward: les reponses reviennent par
        // ct state established, et un coeur n'a pas a etre joignable.
        assert_eq!(r.matches("skuid").count(), 3, "ruleset:\n{r}");
    }

    #[test]
    fn l_exemption_du_coeur_ne_leve_pas_la_policy_drop() {
        let r = render(&policy_avec_coeur());
        assert_eq!(chaines_en_drop(&r), 3, "ruleset:\n{r}");
        assert!(!r.contains("policy accept"), "ruleset:\n{r}");
    }

    /// Un nom d'interface est valide par bifrost-core avant d'arriver ici, mais
    /// on verifie qu'aucun caractere de la politique ne peut casser la syntaxe.
    #[test]
    fn les_noms_d_interface_sont_toujours_entre_guillemets() {
        let mut p = policy();
        p.tunnel_interface = Some("bifrost-wg0".into());
        let r = render(&p);
        // Presence par la regle entiere, guillemets compris: un rendu qui les
        // oublierait ne la porte pas, et un `iifname` seul ne repond pas pour elle.
        assert!(
            regles_nft::porte(&r, "oifname \"bifrost-wg0\" accept"),
            "ruleset:\n{r}"
        );
    }

    /// Piege (5u): une regle par identite dont l'uid PROLONGE celui du coeur ne
    /// doit pas satisfaire la recette du coeur. On exerce la reconnaissance
    /// elle-meme sur un rendu FABRIQUE, car le produit n'emet jamais 9770. Sur
    /// la reconnaissance d'avant (`regles_par_uid` par sous-chaine, ou
    /// `contains("977")`), 9770 contient 977 et la garde se laissait prendre.
    #[test]
    fn un_uid_en_prolongement_ne_satisfait_pas_la_recette_du_coeur() {
        // Meme fonction de rendu que la vraie recette, uid remplace par un
        // prolongement. Dans ce rendu, "977" ne parait que dans les regles du
        // coeur, donc le remplacement ne fabrique que des uid 9770.
        let fabrique = render(&policy_avec_coeur()).replace("977", "9770");
        // L'uid du coeur (977) n'a AUCUNE regle dans ce rendu.
        assert!(
            regles_nft::regles_par_uid(&fabrique, 977).is_empty(),
            "un uid prolonge (9770) a ete reconnu comme le coeur (977):\n{fabrique}"
        );
        assert!(!regles_nft::porte(&fabrique, "meta skuid 977 accept"));
        // ... tandis que l'uid fabrique, lui, est reconnu ENTIER: trois regles
        // (les deux drop du :53 et l'accept).
        assert_eq!(regles_nft::regles_par_uid(&fabrique, 9770).len(), 3);
        assert!(regles_nft::porte(&fabrique, "meta skuid 9770 accept"));
    }

    /// Piege (5u): pour `mentionne_interface`, une interface dont le nom
    /// PROLONGE celui du tunnel n'est pas le tunnel. On exerce la reconnaissance
    /// elle-meme sur un rendu FABRIQUE: le produit ne rend jamais wg01 a la
    /// place de wg0, et c'est justement pourquoi la recette << sans interface
    /// aucune regle ne mentionne le tunnel >> nie, elle, la sous-chaine `wg0`
    /// (une absence se verifie par le filet le plus large). Le mot exact sert
    /// aux PRESENCES, ou un prolongement ne doit pas satisfaire la recette.
    #[test]
    fn un_nom_d_interface_en_prolongement_ne_fait_pas_rougir_l_absence_du_tunnel() {
        // wg0 -> wg01 sur un rendu qui nomme le tunnel: "wg0" n'y parait que
        // dans les regles d'interface, le remplacement ne fabrique que wg01.
        let fabrique = render(&policy()).replace("wg0", "wg01");
        assert!(
            !regles_nft::mentionne_interface(&fabrique, "wg0"),
            "wg01 a ete pris pour le tunnel wg0:\n{fabrique}"
        );
        assert!(regles_nft::mentionne_interface(&fabrique, "wg01"));
        // L'autre prolongement cite par la tranche.
        let autre = render(&policy()).replace("wg0", "bifrost-wg0-bis");
        assert!(!regles_nft::mentionne_interface(&autre, "bifrost-wg0"));
        assert!(regles_nft::mentionne_interface(&autre, "bifrost-wg0-bis"));
    }
}
