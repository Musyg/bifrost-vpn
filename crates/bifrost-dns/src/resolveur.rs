//! Configuration du resolveur chiffre embarque (dnscrypt-proxy).
//!
//! Ce que ce resolveur apporte, et qu'il faut savoir enoncer sous peine de le
//! croire redondant: A L'INTERIEUR du tunnel, le DNS est deja chiffre par
//! WireGuard. Ce qu'il n'est pas, c'est chiffre APRES la sortie du tunnel. La
//! requete y redevient du clair, lisible et falsifiable par qui exploite cette
//! sortie, et c'est precisement la partie du chemin sur laquelle l'utilisateur
//! d'un VPN n'a aucune raison d'accorder sa confiance. Le resolveur chiffre
//! ferme ce segment.
//!
//! Le fichier engendre ici est de la DONNEE, comme le ruleset nftables et le
//! plan WFP. Ce qui determine s'il y a fuite se verifie donc en test, sans
//! dnscrypt-proxy installe et sans reseau.

use std::fmt::Write as _;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

use bifrost_core::{Error, Result};

/// Port :53 des resolveurs de bootstrap. Ils sont interroges en CLAIR, c'est
/// leur nature: ils servent a joindre le premier serveur chiffre.
const PORT_BOOTSTRAP: u16 = 53;

/// Ce qu'il faut savoir pour engendrer la configuration du resolveur.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolveurChiffre {
    /// Adresse d'ecoute. Obligatoirement sur la boucle locale: c'est la seule
    /// destination :53 que le kill switch laisse passer hors tunnel.
    pub ecoute: SocketAddr,
    /// Noms des resolveurs chiffres, tels qu'ils figurent dans la liste
    /// publique de dnscrypt-proxy.
    pub serveurs: Vec<String>,
    /// Adresses en dur servant a resoudre le NOM des serveurs chiffres.
    ///
    /// Elles rompent une circularite reelle: pour joindre un serveur DoH il
    /// faut resoudre son nom, ce que seul un resolveur peut faire. Ces
    /// adresses-la sont donc interrogees en clair, une fois, par le tunnel.
    pub bootstrap: Vec<IpAddr>,
    /// Ou dnscrypt-proxy garde la liste des serveurs chiffres.
    ///
    /// Chemin ABSOLU, et sur un support qui survit aux redemarrages. Ce
    /// n'est pas un detail d'exploitation: sans liste utilisable, le binaire
    /// s'arrete en FATAL et la connexion echoue. Mesure du 17/08/2026 avec un
    /// cache sous /run, donc efface a chaque arret du service: chaque
    /// demarrage refaisait le telechargement chez le meme hebergeur, qui a
    /// fini par repondre `429 Too Many Requests`. Avec un cache persistant,
    /// seul le tout premier demarrage depend du reseau.
    pub cache: PathBuf,
    /// Fichier des noms refuses, quand un profil anti-telemetrie est demande.
    ///
    /// `None` quand le profil est `Aucun`, et la section n'est alors pas
    /// ecrite du tout plutot qu'ecrite avec un fichier vide: un fichier vide
    /// et une absence de blocage se lisent pareil dans les journaux, et seul
    /// le second dit ce qui a ete decide.
    ///
    /// Le CONTENU est engendre par [`crate::telemetrie::blocked_names`]; ce
    /// champ ne porte que l'emplacement.
    pub blocage: Option<PathBuf>,
}

impl ResolveurChiffre {
    /// Refuse une configuration qui ouvrirait un trou plutot que d'en fermer un.
    ///
    /// Ces controles ne font DOUBLE EMPLOI avec rien. Mesure du 17/08/2026 sur
    /// dnscrypt-proxy 2.1.18: `-check` refuse une cle inconnue et un type
    /// invalide, tous deux en FATAL, mais accepte sans un mot une ecoute sur
    /// `0.0.0.0:53`, c'est-a-dire un resolveur ouvert a tout le reseau local.
    /// Le binaire juge la SYNTAXE de sa configuration; les proprietes de
    /// securite, personne ne les juge a sa place.
    pub fn valider(&self) -> Result<()> {
        if !self.ecoute.ip().is_loopback() {
            return Err(Error::Config(format!(
                "le resolveur embarque doit ecouter sur la boucle locale, recu {}. \
                 Ailleurs, il servirait de resolveur ouvert au reseau local",
                self.ecoute.ip()
            )));
        }
        if self.serveurs.is_empty() {
            return Err(Error::Config(
                "aucun serveur chiffre declare: le resolveur n'aurait rien a \
                 interroger et la resolution serait simplement cassee"
                    .into(),
            ));
        }
        if self.bootstrap.is_empty() {
            return Err(Error::Config(
                "aucun resolveur de bootstrap: le nom des serveurs chiffres ne \
                 pourrait jamais etre resolu"
                    .into(),
            ));
        }
        // Un bootstrap sur la boucle locale designerait le resolveur lui-meme.
        // Il s'interrogerait pour savoir ou joindre ce qu'il doit interroger,
        // et resterait bloque a son demarrage sans rien signaler d'utile.
        if let Some(boucle) = self.bootstrap.iter().find(|a| a.is_loopback()) {
            return Err(Error::Config(format!(
                "resolveur de bootstrap sur la boucle locale ({boucle}): le \
                 resolveur s'interrogerait lui-meme pour demarrer"
            )));
        }
        // Un chemin relatif atterrirait dans le repertoire courant du
        // processus, c'est-a-dire sous /run: efface a chaque arret, donc un
        // telechargement force a chaque demarrage.
        // `is_absolute` repond selon la plateforme qui COMPILE, pas selon celle
        // qui fera tourner le resolveur: depuis Windows elle declare relatif
        // /var/lib/bifrost/..., qui est pourtant le chemin reel du service
        // Linux vise. La garde existe pour refuser un chemin RELATIF, celui qui
        // atterrit dans le repertoire courant du processus. Les deux formes
        // d'absolu sont donc acceptees, sans quoi le meme reglage serait valide
        // ou non selon la machine ayant lance les tests.
        let absolu = self.cache.is_absolute() || self.cache.to_string_lossy().starts_with('/');
        if !absolu {
            return Err(Error::Config(format!(
                "le cache des serveurs doit etre un chemin absolu, recu {}. \
                 Relatif, il atterrit sous /run et disparait a chaque arret, \
                 ce qui force un telechargement a chaque demarrage",
                self.cache.display()
            )));
        }
        // Absolu, comme le cache, mais pas pour la meme raison. dnscrypt-proxy
        // documente qu'un `blocked_names_file` relatif se resout par rapport au
        // repertoire de la CONFIGURATION, quand `cache_file` relatif, lui,
        // atterrit dans le repertoire courant du processus. Deux bases
        // relatives differentes dans un meme fichier est un piege qu'on ferme
        // en n'ecrivant que de l'absolu, puisque le daemon sait ou il a ecrit.
        if let Some(blocage) = &self.blocage {
            let absolu = blocage.is_absolute() || blocage.to_string_lossy().starts_with('/');
            if !absolu {
                return Err(Error::Config(format!(
                    "le fichier des noms refuses doit etre un chemin absolu,                      recu {}. Relatif, il se resout par rapport au repertoire                      de la configuration, base differente de celle du cache",
                    blocage.display()
                )));
            }
        }
        Ok(())
    }
}

/// Engendre le `dnscrypt-proxy.toml`.
///
/// Fonction pure: aucune de ces lignes n'est verifiable en lisant le binaire
/// tourner, et plusieurs d'entre elles ne se voient qu'a l'usage, des mois
/// plus tard, sous forme de requetes qui ne passent pas par ou l'on croit.
pub fn dnscrypt_proxy_toml(r: &ResolveurChiffre) -> Result<String> {
    r.valider()?;

    let mut s = String::new();
    s.push_str("# Engendre par Bifrost. Toute modification sera ecrasee.\n\n");

    let _ = writeln!(s, "listen_addresses = ['{}']", r.ecoute);
    let serveurs: Vec<String> = r.serveurs.iter().map(|n| format!("'{n}'")).collect();
    let _ = writeln!(s, "server_names = [{}]", serveurs.join(", "));
    s.push('\n');

    s.push_str("# DNSSEC exige, journalisation et filtrage refuses: un\n");
    s.push_str("# resolveur qui journalise annule l'interet de le chiffrer.\n");
    s.push_str("require_dnssec = true\nrequire_nolog = true\nrequire_nofilter = true\n\n");

    s.push_str("# Le point le plus important de ce fichier. Sans lui,\n");
    s.push_str("# dnscrypt-proxy demande au resolveur SYSTEME ou joindre son\n");
    s.push_str("# serveur chiffre. Or le resolveur systeme, c'est lui: il\n");
    s.push_str("# s'interroge, n'obtient rien, et le symptome est une machine\n");
    s.push_str("# sans resolution dont les journaux ne disent rien d'utile.\n");
    s.push_str("ignore_system_dns = true\n");
    let bootstrap: Vec<String> = r
        .bootstrap
        .iter()
        .map(|a| format!("'{}'", SocketAddr::new(*a, PORT_BOOTSTRAP)))
        .collect();
    let _ = writeln!(s, "bootstrap_resolvers = [{}]", bootstrap.join(", "));
    s.push('\n');

    // Pas de `user_name`, et c'est une decision mesuree, pas un oubli. Le
    // laisser baisser ses propres privileges revenait a un `setuid` en cours
    // de route, et le noyau efface `pdeath_signal` des que les identifiants
    // changent (`commit_creds`). Mesure sur essai-linux le 17/08/2026: avec
    // `user_name`, un resolveur survivait au daemon tue par SIGKILL et gardait
    // le :53 de la boucle locale; sans lui, il mourait avec. Le daemon prend
    // donc les identifiants LUI-MEME avant l'exec, et arme la garde apres.

    s.push_str("# Aucun repli en clair. dnscrypt-proxy sait retomber sur un\n");
    s.push_str("# resolveur ordinaire quand les serveurs chiffres sont\n");
    s.push_str("# injoignables: ce serait une fuite silencieuse, exactement le\n");
    s.push_str("# defaut que ce composant existe pour fermer. Mieux vaut une\n");
    s.push_str("# resolution qui echoue et se voit.\n");
    s.push_str("netprobe_timeout = 0\n\n");

    s.push_str("# Cache: les requetes repetees ne ressortent pas. L'empoisonnement\n");
    s.push_str("# n'est pas un risque ici puisque DNSSEC est exige au-dessus.\n");
    s.push_str("cache = true\ncache_min_ttl = 2400\ncache_max_ttl = 86400\n\n");

    s.push_str("# Aucun journal de requetes: la liste des noms consultes est\n");
    s.push_str("# exactement ce qu'un VPN sert a ne pas laisser derriere soi.\n");
    s.push_str("log_level = 2\n\n");

    // AVANT `[sources]`: en TOML, tout ce qui suit une table lui appartient.
    // Ecrite apres, cette section deviendrait une sous-table de la source des
    // resolveurs, que dnscrypt-proxy refuserait. Le meme piege a coute un
    // fichier `deny.toml` entier le 22/08/2026.
    if let Some(blocage) = &r.blocage {
        s.push_str("# Noms refuses. Le resolveur les rejette AVANT que la\n");
        s.push_str("# requete n'entre dans le tunnel: ce trafic ne ressort pas\n");
        s.push_str("# a l'autre bout, il ne part pas du tout.\n");
        s.push_str("#\n");
        s.push_str("# `require_nofilter` ci-dessus refuse les resolveurs AMONT\n");
        s.push_str("# qui filtrent, et ne contredit pas ceci: on refuse qu'un\n");
        s.push_str("# tiers decide, pas de decider soi-meme.\n");
        s.push_str("[blocked_names]\n");
        let _ = writeln!(s, "blocked_names_file = '{}'", blocage.display());
        // Pas de `log_file`: la liste des noms refuses est la liste des noms
        // consultes, exactement ce qu'un VPN sert a ne pas laisser derriere
        // soi. Meme raison que l'absence de journal de requetes.
        s.push('\n');
    }

    s.push_str("[sources.'public-resolvers']\n");
    // TROIS miroirs, et non le seul depot d'origine. Sans liste utilisable,
    // dnscrypt-proxy s'arrete en FATAL et aucune connexion n'aboutit: en faire
    // dependre le demarrage d'un seul hebergeur est un point unique de
    // defaillance. Mesure du 17/08/2026: apres quelques demarrages a froid,
    // `raw.githubusercontent.com` a repondu `429 Too Many Requests` puis a
    // cesse de repondre du tout a cette adresse, pendant que github.com restait
    // joignable. Les trois miroirs sont ceux de la configuration de reference
    // de dnscrypt-proxy 2.1.18, dans le meme ordre.
    //
    // Multiplier les miroirs n'affaiblit rien: la liste est signee, et la cle
    // publique ci-dessous est epinglee ici. Un miroir hostile ne peut que
    // servir une liste que le binaire refusera.
    s.push_str("urls = [\n");
    for url in [
        "https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/public-resolvers.md",
        "https://download.dnscrypt.info/resolvers-list/v3/public-resolvers.md",
        "https://cdn.jsdelivr.net/gh/DNSCrypt/dnscrypt-resolvers@master/v3/public-resolvers.md",
    ] {
        let _ = writeln!(s, "  '{url}',");
    }
    s.push_str("]\n");
    // Chemin absolu et persistant: voir `ResolveurChiffre::cache`. Relatif, il
    // atterrirait sous /run et serait perdu a chaque arret du service.
    let _ = writeln!(s, "cache_file = '{}'", r.cache.display());
    s.push_str("minisign_key = 'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3'\n");
    // Delai de rafraichissement de la liste, en heures. Celui de la
    // configuration de reference. Avec un cache persistant, c'est lui qui
    // determine a quelle frequence le reseau est sollicite: une fois par
    // trois jours, et non a chaque demarrage.
    s.push_str("refresh_delay = 73\n");

    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn resolveur() -> ResolveurChiffre {
        ResolveurChiffre {
            ecoute: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53),
            serveurs: vec!["quad9-dnscrypt-ip4-filter-pri".into(), "cloudflare".into()],
            bootstrap: vec![
                IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
                IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            ],
            cache: PathBuf::from("/var/lib/bifrost/resolveur/public-resolvers.md"),
            blocage: None,
        }
    }

    fn avec_blocage() -> ResolveurChiffre {
        ResolveurChiffre {
            blocage: Some(PathBuf::from("/etc/bifrost/resolveur/blocked-names.txt")),
            ..resolveur()
        }
    }

    /// Profil `Aucun`: pas de section vide, pas de fichier vide. L'absence de
    /// blocage et un blocage qui ne bloque rien se lisent pareil dans les
    /// journaux; seule l'absence dit ce qui a ete decide.
    #[test]
    fn sans_profil_la_section_n_existe_pas() {
        let t = dnscrypt_proxy_toml(&resolveur()).unwrap();
        assert!(!t.contains("[blocked_names]"), "{t}");
        assert!(!t.contains("blocked_names_file"), "{t}");
    }

    #[test]
    fn avec_profil_la_section_porte_le_chemin_absolu() {
        let t = dnscrypt_proxy_toml(&avec_blocage()).unwrap();
        assert!(t.contains("[blocked_names]"), "{t}");
        assert!(
            t.contains("blocked_names_file = '/etc/bifrost/resolveur/blocked-names.txt'"),
            "{t}"
        );
    }

    /// En TOML, tout ce qui suit une table lui appartient. Ecrite apres
    /// `[sources]`, la section deviendrait `[sources.'public-resolvers'.
    /// blocked_names]` et dnscrypt-proxy refuserait le fichier entier. Le meme
    /// piege a coute un `deny.toml` complet le 22/08/2026.
    #[test]
    fn la_section_de_blocage_precede_les_sources() {
        let t = dnscrypt_proxy_toml(&avec_blocage()).unwrap();
        let blocage = t.find("[blocked_names]").expect("section absente");
        let sources = t.find("[sources.").expect("sources absentes");
        assert!(
            blocage < sources,
            "la section de blocage suit les sources, elle en deviendrait une \
             sous-table:\n{t}"
        );
    }

    /// Un chemin relatif ne se resout pas ici comme pour le cache:
    /// dnscrypt-proxy le prend par rapport au repertoire de la CONFIGURATION.
    /// Deux bases relatives differentes dans un meme fichier, personne ne s'en
    /// souvient au bon moment.
    #[test]
    fn un_fichier_de_blocage_relatif_est_refuse() {
        let mut r = avec_blocage();
        r.blocage = Some(PathBuf::from("blocked-names.txt"));
        let e = dnscrypt_proxy_toml(&r).unwrap_err().to_string();
        assert!(e.contains("absolu"), "message peu utile: {e}");
    }

    /// Le blocage local ne contredit pas `require_nofilter`, et les deux
    /// doivent pouvoir coexister dans le fichier: l'un refuse qu'un tiers
    /// decide, l'autre decide soi-meme.
    #[test]
    fn le_blocage_local_coexiste_avec_le_refus_des_amonts_filtrants() {
        let t = dnscrypt_proxy_toml(&avec_blocage()).unwrap();
        assert!(t.contains("require_nofilter = true"), "{t}");
        assert!(t.contains("[blocked_names]"), "{t}");
    }

    /// Le defaut qui a coute une session entiere de diagnostic. Un cache
    /// relatif atterrit dans le repertoire courant du resolveur, sous /run,
    /// efface a chaque arret du service: chaque demarrage refait alors le
    /// telechargement de la liste des serveurs, et l'hebergeur finit par
    /// repondre 429. Sans liste utilisable, dnscrypt-proxy s'arrete en FATAL
    /// et plus aucune connexion n'aboutit.
    /// Le chemin vise est celui du service Linux, quelle que soit la machine
    /// qui compile. `Path::is_absolute` seule le declarait relatif sous
    /// Windows, ce qui faisait echouer sept tests la-bas et passer les memes
    /// ailleurs: un reglage ne peut pas etre valide selon l'hote qui l'examine.
    #[test]
    fn un_cache_posix_est_accepte_meme_depuis_windows() {
        let mut r = resolveur();
        r.cache = PathBuf::from("/var/lib/bifrost/resolveur/public-resolvers.md");
        assert!(dnscrypt_proxy_toml(&r).is_ok());
    }

    #[test]
    fn un_cache_relatif_est_refuse() {
        let mut r = resolveur();
        r.cache = PathBuf::from("public-resolvers.md");
        let e = dnscrypt_proxy_toml(&r).unwrap_err().to_string();
        assert!(e.contains("absolu"), "message peu utile: {e}");
    }

    /// Un seul miroir suffit a empecher toute connexion quand il refuse de
    /// repondre, et c'est arrive: `raw.githubusercontent.com` a rendu 429 puis
    /// s'est tu apres quelques demarrages a froid.
    #[test]
    fn la_liste_des_serveurs_a_plusieurs_miroirs() {
        let t = dnscrypt_proxy_toml(&resolveur()).unwrap();
        let miroirs = t.matches("https://").count();
        assert!(miroirs >= 3, "un seul point de defaillance: {t}");
        assert!(t.contains("download.dnscrypt.info"), "{t}");
        assert!(t.contains("cdn.jsdelivr.net"), "{t}");
    }

    #[test]
    fn le_cache_figure_en_absolu_dans_la_configuration() {
        let t = dnscrypt_proxy_toml(&resolveur()).unwrap();
        assert!(
            t.contains("cache_file = '/var/lib/bifrost/resolveur/public-resolvers.md'"),
            "{t}"
        );
    }

    #[test]
    fn l_adresse_d_ecoute_est_celle_demandee() {
        let t = dnscrypt_proxy_toml(&resolveur()).unwrap();
        assert!(t.contains("listen_addresses = ['127.0.0.1:53']"), "{t}");
    }

    /// Sans `ignore_system_dns`, dnscrypt-proxy interroge le resolveur systeme
    /// pour trouver son serveur chiffre. Le resolveur systeme etant lui-meme,
    /// il attend une reponse qu'il est seul a pouvoir donner.
    #[test]
    fn le_resolveur_ne_s_interroge_pas_lui_meme() {
        let t = dnscrypt_proxy_toml(&resolveur()).unwrap();
        assert!(t.contains("ignore_system_dns = true"), "{t}");
    }

    #[test]
    fn le_bootstrap_porte_le_port_53() {
        let t = dnscrypt_proxy_toml(&resolveur()).unwrap();
        assert!(
            t.contains("bootstrap_resolvers = ['9.9.9.9:53', '1.1.1.1:53']"),
            "{t}"
        );
    }

    /// Les trois exigences qui distinguent un resolveur chiffre d'un simple
    /// resolveur distant: signature verifiee, aucun journal, aucun filtrage.
    #[test]
    fn dnssec_et_absence_de_journal_sont_exiges() {
        let t = dnscrypt_proxy_toml(&resolveur()).unwrap();
        for exigence in [
            "require_dnssec = true",
            "require_nolog = true",
            "require_nofilter = true",
        ] {
            assert!(t.contains(exigence), "exigence absente: {exigence}\n{t}");
        }
    }

    /// Le defaut le plus insidieux qu'on puisse laisser dans ce fichier: un
    /// repli en clair quand les serveurs chiffres sont injoignables. Il ne se
    /// declenche que le jour ou le chiffrement etait le plus utile.
    #[test]
    fn aucun_repli_en_clair_n_est_declare() {
        let t = dnscrypt_proxy_toml(&resolveur()).unwrap();
        assert!(
            !t.contains("fallback_resolver"),
            "un repli en clair est declare: il fuirait au pire moment\n{t}"
        );
    }

    /// Une ecoute ailleurs que sur la boucle locale ferait du resolveur un
    /// service ouvert au reseau, et le kill switch ne laisse de toute facon
    /// passer le :53 que vers la boucle locale.
    #[test]
    fn une_ecoute_hors_boucle_locale_est_refusee() {
        let mut r = resolveur();
        r.ecoute = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 53);
        assert!(dnscrypt_proxy_toml(&r).is_err());
    }

    /// Un bootstrap sur la boucle locale designe le resolveur lui-meme.
    #[test]
    fn un_bootstrap_sur_la_boucle_locale_est_refuse() {
        let mut r = resolveur();
        r.bootstrap = vec![IpAddr::V6(Ipv6Addr::LOCALHOST)];
        assert!(dnscrypt_proxy_toml(&r).is_err());
    }

    #[test]
    fn une_configuration_sans_serveur_ou_sans_bootstrap_est_refusee() {
        let mut sans_serveur = resolveur();
        sans_serveur.serveurs.clear();
        assert!(dnscrypt_proxy_toml(&sans_serveur).is_err());

        let mut sans_bootstrap = resolveur();
        sans_bootstrap.bootstrap.clear();
        assert!(dnscrypt_proxy_toml(&sans_bootstrap).is_err());
    }
}
