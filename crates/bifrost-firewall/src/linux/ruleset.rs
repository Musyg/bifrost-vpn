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

/// Prefixes RFC1918 et unique-local, autorises seulement si `allow_lan`.
const LAN_V4: &str = "10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16";
const LAN_V6: &str = "fc00::/7, fe80::/10";

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

    s.push_str("\t\t# DNS: uniquement vers le resolveur local. Tout autre :53\n");
    s.push_str("\t\t# sortant tombe dans la policy drop.\n");
    render_dns_permits(s, policy.dns_resolver);

    render_coeur_permit(s, policy);

    if policy.allow_lan {
        s.push_str("\n\t\t# acces LAN active explicitement par l'utilisateur\n");
        s.push_str(&format!("\t\tip daddr {{ {LAN_V4} }} accept\n"));
        s.push_str(&format!("\t\tip6 daddr {{ {LAN_V6} }} accept\n"));
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

fn render_dns_permits(s: &mut String, resolver: IpAddr) {
    let (family, addr) = match resolver {
        IpAddr::V4(a) => ("ip", a.to_string()),
        IpAddr::V6(a) => ("ip6", a.to_string()),
    };
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
            "un permit de marque a ete emis sans marque a permettre:
{r}"
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
