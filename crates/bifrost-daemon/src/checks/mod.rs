//! Suite de tests de fuite: les six vecteurs du document 02 partie 4, plus
//! trois - la largeur de l'exemption du coeur, la borne de celle du resolveur
//! chiffre, et le contournement DoH.
//! `CheckVector::ALL` fait foi; ce commentaire a compte sept pendant un temps.
//!
//! Regle non negociable, appliquee partout dans ce module: un test qui ne peut
//! pas s'executer renvoie `SKIPPED` avec sa raison, jamais `PASSED`.
//!
//! Chaque vecteur mesurable est double d'un temoin negatif. On verifie d'abord
//! que la sonde produit bien du trafic observable SANS kill switch, puis qu'elle
//! n'en produit plus AVEC. Si le temoin negatif ne fuit pas, le test ne prouve
//! rien et se declare `SKIPPED` plutot que de passer sur un artefact.

// Le banc et la capture reposent sur les namespaces reseau, `ip` et tcpdump:
// ils n'ont de sens que sous Linux. Les sondes et la specification WireGuard,
// elles, restent compilees partout, la premiere parce que `--probe` est
// multi-plateforme, la seconde parce que ses tests le sont.
#[cfg(target_os = "linux")]
pub mod capture;
pub mod doh;
#[cfg(target_os = "linux")]
pub mod doh_fichiers;
pub mod doh_pose;
#[cfg(target_os = "linux")]
pub mod doh_pose_fichiers;
#[cfg(windows)]
pub mod doh_pose_registre;
#[cfg(windows)]
pub mod doh_registre;
#[cfg(target_os = "linux")]
pub mod netns;
pub mod probe;
pub mod regles_nft;
pub mod resolveur;
pub mod transport;
pub mod wgapply;

/// Grammaire commune de la ligne de commande de nft (voir le module): les
/// deux gardes nft -- le refus runtime `netns::refuser_nft_hors_entree` et la
/// garde de source `tests_source::toute_invocation_nft_passe_par_poser_ou_retirer`
/// -- y DELEGUENT.
///
/// Porte d'OS `any(target_os = "linux", test)`: ses deux seuls utilisateurs
/// sont `netns` (`#[cfg(target_os = "linux")]`) et `tests_source`
/// (`#[cfg(test)]`). En bibliotheque Windows HORS test, aucun des deux ne
/// compile: le module n'a alors aucun utilisateur, et `dead_code` fait echouer
/// `cargo clippy --workspace --all-targets -- -D warnings` (le job Windows de la
/// CI). La porte le retire de cette seule configuration. Ses huit recettes
/// (`#[cfg(test)] mod tests`, dans le module) restent compilees et executees sur
/// dev-windows par `cargo test`: le bras `test` de la porte les couvre.
#[cfg(any(target_os = "linux", test))]
mod nft_argv;

use bifrost_core::checks::{CheckOutcome, CheckReport, CheckVector};

/// Arme le kill switch du banc, puis attend d'etre tue.
///
/// Le processus que le vecteur `daemon-mort` fait mourir. Il vit dans un
/// processus SEPARE pour une raison qui est tout le vecteur: on ne peut pas
/// mesurer ce que devient une protection quand celui qui l'a posee meurt si
/// c'est le mesureur lui-meme qui doit mourir.
#[cfg(target_os = "linux")]
pub fn armer_le_banc_et_attendre() -> anyhow::Result<()> {
    linux::armer_le_banc_et_attendre()
}

/// Les motifs qui n'appartiennent a aucune des deux plateformes.
///
/// Un seul aujourd'hui, et il compte quand meme: c'etait le dernier `skipped(`
/// du module dont la raison etait ecrite en ligne, et la garde de source l'a
/// trouve la ou aucune lecture de messages ne pouvait le voir - il ne se rend
/// que sur un systeme qui n'est ni Linux ni Windows, donc sur aucune des deux
/// machines qui font tourner ces recettes.
pub mod motifs_portables {
    /// Ni namespaces reseau, ni Base Filtering Engine.
    pub fn plateforme_sans_harnais(systeme: &str) -> String {
        format!(
            "le harnais de fuite s'appuie sur les namespaces reseau Linux et sur l'audit WFP \
             sous Windows; {systeme} n'a ni l'un ni l'autre."
        )
    }
}

/// Execute la suite complete.
pub fn run_all() -> CheckReport {
    #[cfg(target_os = "linux")]
    {
        linux::run_all()
    }
    #[cfg(windows)]
    {
        windows::run_all()
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        all_skipped(&motifs_portables::plateforme_sans_harnais(
            std::env::consts::OS,
        ))
    }
}

/// Les raisons de `Skipped` sous Windows, une par vecteur.
///
/// Un motif global serait plus court, et il serait FAUX. Ce module en portait
/// un jusqu'au 18 aout 2026: "le harnais s'appuie sur les namespaces reseau
/// Linux, Windows n'en dispose pas, les garanties Windows se verifient avec une
/// capture Npcap sur une VM dediee". Les deux moities sont tombees le meme jour.
/// Windows n'a pas besoin de namespaces, parce que l'audit WFP nomme le filtre
/// qui a bloque - ce qu'aucun compteur nftables ne sait faire - et le mode
/// bloquant est lancable a distance des lors que le reseau local reste ouvert.
/// Ni VM ni Npcap.
///
/// Un motif faux est pire qu'un motif absent: il fait renoncer a une mesure
/// pourtant possible, et celui-la l'a fait pendant des semaines. D'ou une
/// raison par vecteur, qui dit ce qui manque VRAIMENT a chacun.
#[cfg(windows)]
mod windows {
    use super::*;

    pub fn run_all() -> CheckReport {
        CheckReport::new(
            CheckVector::ALL
                .iter()
                .map(|v| match v {
                    // Le seul vecteur qui tourne vraiment ici. Il ne pose aucun
                    // filtre, ne cree aucun adaptateur et ne coupe rien: il
                    // lit des configurations. Rien ne justifierait de le
                    // renvoyer a une commande dediee.
                    CheckVector::DohBypass => doh_registre::vecteur(),
                    autre => motif(*autre),
                })
                .collect(),
        )
    }

    /// Y a-t-il une adresse IPv6 GLOBALE sur cette machine?
    ///
    /// Une adresse unique-locale ne suffit pas: le banc n'a qu'un prefixe
    /// `fc00::/7` pose par un reseau overlay, et un ping vers une adresse
    /// publique y perd 100% des paquets. Mesurer une fuite IPv6 sans
    /// connectivite IPv6 rendrait un temoin negatif qui ne fuit pas, donc un
    /// test qui ne prouve rien.
    ///
    /// Ce que cette absence n'interdit PAS: eprouver les couches V6. Le vecteur
    /// `ipv6-leak` accepte une cible locale et le dit dans son verdict.
    fn ipv6_global() -> bool {
        std::net::UdpSocket::bind("[::]:0")
            .and_then(|s| {
                // Aucun paquet n'est emis: `connect` sur UDP ne fait que
                // choisir une route et une adresse source. C'est exactement ce
                // qu'on cherche a savoir.
                s.connect("[2606:4700:4700::1111]:53")?;
                s.local_addr()
            })
            .map(|a| match a.ip() {
                std::net::IpAddr::V6(v6) => {
                    !v6.is_loopback() && !v6.is_unspecified() && !est_locale(&v6)
                }
                std::net::IpAddr::V4(_) => false,
            })
            .unwrap_or(false)
    }

    /// Lien-local `fe80::/10` ou unique-locale `fc00::/7`.
    fn est_locale(a: &std::net::Ipv6Addr) -> bool {
        let o = a.octets();
        (o[0] == 0xfe && (o[1] & 0xc0) == 0x80) || (o[0] & 0xfe) == 0xfc
    }

    /// Les motifs de saut de ce cote, rendus SANS executer quoi que ce soit.
    ///
    /// # Pourquoi ce module existe
    ///
    /// Les gardes de `tests_windows` lisaient `run_all()`, donc elles ne
    /// voyaient que les motifs que la MACHINE COURANTE rend. Mesure sur
    /// dev-windows le 23/08/2026: en glissant une suite de deux espaces dans
    /// le motif IPv6 de la branche << cette machine a une adresse globale >>,
    /// aucune recette n'a rougi - cette machine n'a pas d'IPv6 globale, donc
    /// la branche n'est jamais evaluee. Ce motif n'etait garde nulle part.
    ///
    /// Le catalogue rend les DEUX branches, et toutes les autres, sans
    /// dependre de ce que la machine se trouve avoir. C'est le pendant exact
    /// de `linux::motifs`, pour la meme raison: une garde qui ne lit que ce
    /// qui s'execute ne garde que la moitie de ce qui est ecrit.
    pub mod motifs {
        pub fn dns_leak() -> &'static str {
            "cable, mais hors de `check`: ce vecteur ARME le kill switch, donc il COUPE le reseau de cette machine le temps de la mesure. Couper le reseau au detour d'un `check` serait une mauvaise surprise, d'ou une commande dediee qui l'annonce avant de le faire: `bifrost-daemon --dns-leak-selftest`."
        }

        pub fn ipv6_leak_sans_global() -> &'static str {
            "aucune adresse IPv6 GLOBALE sur cette machine: le temoin negatif ne pourrait pas fuir vers l'exterieur, donc la pleine portee est hors d'atteinte ici. Le vecteur est cable et accepte une cible locale, qui eprouve les memes couches V6 sans le chemin de sortie: `bifrost-daemon --ipv6-leak-selftest --ipv6-leak-cible [ADDR]:PORT`."
        }

        pub fn ipv6_leak_avec_global() -> &'static str {
            "cable, mais hors de `check`: il ARME le kill switch. Cette machine a de l'IPv6 global, donc la pleine portee y est atteignable. Lancer `bifrost-daemon --ipv6-leak-selftest`."
        }

        pub fn coeur_exemption() -> &'static str {
            "cable, mais hors de `check` comme dns-leak: il ARME le kill switch. Contrairement a Linux, ou l'exemption designe un UID, elle designe ici un CHEMIN et une identite: aucun coeur n'a besoin de tourner, un binaire pose au bon chemin suffit. Lancer `bifrost-daemon --coeur-exemption-selftest`."
        }

        pub fn exit_ip() -> &'static str {
            "cable, mais hors de `check`: il monte un VRAI tunnel vers un pair distant et capture sur les cartes reelles, ce qui demande un serveur WireGuard en face. Contrairement aux autres il n'arme PAS le kill switch et ne coupe pas le reseau: il mesure le routage. Lancer `bifrost-daemon --exit-ip-selftest PROFIL.TOML --exit-ip-cible ADDR:PORT`, la cible etant une adresse joignable UNIQUEMENT par le tunnel."
        }

        pub fn daemon_mort() -> &'static str {
            "non cable ici, et ce n'est PAS une limite du harnais: la question que ce vecteur pose a deja ses deux reponses de ce cote, par mesure. L'arret DEMANDE est garde par `crates/bifrost-daemon/src/service/spec.rs`, test `l_arret_du_service_ne_rouvre_pas_le_trafic`. La survie des filtres a la mort BRUTALE du processus est mesuree: processus tue par PID en pleine phase d'armement, 22 filtres encore poses, comptes depuis un processus NEUF, avec le journal qui prouve que le desarmement n'avait pas tourne - voir l'en-tete de `crates/bifrost-daemon/src/service/scm.rs`. Le defaut qui a fait naitre ce vecteur etait propre a Linux et propre a `ExecStopPost=`. Ce qui reste non mesure ici est le COMPTAGE des paquets pendant la fenetre, faute d'un banc equivalent; le cabler serait un gain, pas une reparation."
        }

        pub fn kill_switch_on_drop() -> &'static str {
            "cable, mais hors de `check`: il ARME le kill switch et cree des adaptateurs WireGuardNT. Le tunnel qu'il demande n'a pas besoin de transporter, seulement d'exister puis de disparaitre. Lancer `bifrost-daemon --chute-tunnel-selftest`."
        }

        pub fn reconnect_window() -> &'static str {
            "cable avec kill-switch-on-drop, meme commande: une reconnexion sous Windows est un nouvel adaptateur, donc un nouveau LUID, donc un reengagement. La fenetre mesuree est celle entre deux plans."
        }

        pub fn resolveur_exemption() -> &'static str {
            "cable, mais hors de `check` comme coeur-exemption: il ARME le kill switch. C'est le miroir inverse de celui-la, et pas un doublon - le coeur sort largement sauf sur le :53, le resolveur ne sort QUE sur le :53. L'exception designe ici un CHEMIN et non un compte, et une copie du meme binaire pose ailleurs sert de temoin. Lancer `bifrost-daemon --resolveur-exemption-selftest`."
        }

        pub fn startup_window() -> &'static str {
            "cable, mais en DEUX temps et hors de `check`: le filtre de demarrage SURVIT au redemarrage, donc une erreur ne se repare pas par un reboot. `armer` refuse une politique sans reseau local et refuse tant que la tache planifiee de retrait n'existe pas. Lancer `bifrost-daemon --startup-window armer --demarrage-reseau-local`, redemarrer, puis `--startup-window constater`."
        }

        /// Tout ce que ce cote sait dire, y compris les branches que la
        /// machine courante n'atteint pas.
        #[cfg(test)]
        pub fn catalogue() -> Vec<(&'static str, String)> {
            vec![
                ("dns-leak", dns_leak().to_owned()),
                ("ipv6-leak/sans-global", ipv6_leak_sans_global().to_owned()),
                ("ipv6-leak/avec-global", ipv6_leak_avec_global().to_owned()),
                ("coeur-exemption", coeur_exemption().to_owned()),
                ("exit-ip", exit_ip().to_owned()),
                ("daemon-mort", daemon_mort().to_owned()),
                ("kill-switch-on-drop", kill_switch_on_drop().to_owned()),
                ("reconnect-window", reconnect_window().to_owned()),
                ("resolveur-exemption", resolveur_exemption().to_owned()),
                ("startup-window", startup_window().to_owned()),
            ]
        }
    }

    /// Le motif de CE vecteur sur CETTE machine.
    ///
    /// Un aiguillage et rien d'autre: le texte vit dans [`motifs`], ou une
    /// garde peut le lire sans que la branche ait besoin d'etre atteinte.
    fn motif(v: CheckVector) -> CheckOutcome {
        let raison = match v {
            // `run_all` l'a intercepte avant d'arriver ici: ce vecteur
            // tourne pour de bon. Un motif de saut serait un mensonge.
            CheckVector::DohBypass => unreachable!("doh-bypass est execute par run_all"),
            CheckVector::DnsLeak => motifs::dns_leak(),
            CheckVector::Ipv6Leak if !ipv6_global() => motifs::ipv6_leak_sans_global(),
            CheckVector::Ipv6Leak => motifs::ipv6_leak_avec_global(),
            CheckVector::CoeurExemption => motifs::coeur_exemption(),
            CheckVector::ExitIp => motifs::exit_ip(),
            CheckVector::DaemonMort => motifs::daemon_mort(),
            CheckVector::KillSwitchOnDrop => motifs::kill_switch_on_drop(),
            CheckVector::ReconnectWindow => motifs::reconnect_window(),
            CheckVector::ResolveurExemption => motifs::resolveur_exemption(),
            CheckVector::StartupWindow => motifs::startup_window(),
        };
        CheckOutcome::skipped(v, raison)
    }
}

/// Les deux exigences de FORME que tout message de verdict doit tenir, quelle
/// que soit la plateforme qui l'a produit.
///
/// # Pourquoi celles-la sont partagees
///
/// Le defaut qui a fait naitre `tests_linux` est exactement celui-ci: une garde
/// ecrite sous Windows, jamais accordee sous Linux, et des motifs Linux gardes
/// nulle part pendant tout ce temps. Deux jeux de gardes derivent; il n'y en a
/// donc qu'un pour ce que les deux plateformes doivent au lecteur.
///
/// # Pourquoi les autres ne le sont pas
///
/// La distinction des motifs vecteur par vecteur et l'interdiction des deux
/// affirmations tombees le 18 aout 2026 disent ce que Windows ne peut PAS
/// faire. Sous Linux les memes mots sont vrais - le harnais y monte reellement
/// des espaces de noms - et les recopier interdirait des phrases justes. Une
/// garde partagee doit porter sur une exigence commune, pas sur une histoire
/// commune.
#[cfg(test)]
fn forme_des_messages(messages: &[(&str, String)]) {
    for (site, texte) in messages {
        assert!(!texte.trim().is_empty(), "{site}: verdict sans raison");
        // Une continuation de ligne `\` dans un litteral disparait quand
        // rustfmt rejoint les deux lignes, et l'indentation reste alors DANS la
        // chaine. Le code compile, les recettes passent, et le message sort
        // troue d'espaces sous les yeux de celui qui lit le rapport.
        assert!(
            !texte.contains("  "),
            "{site}: suite d'espaces dans [{texte}]"
        );
    }
}

pub fn all_skipped(reason: &str) -> CheckReport {
    CheckReport::new(
        CheckVector::ALL
            .iter()
            .map(|v| CheckOutcome::skipped(*v, reason))
            .collect(),
    )
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use bifrost_core::ports::FirewallPolicy;
    use bifrost_core::state::{Action, Event, StateMachine};
    use bifrost_firewall::linux::ruleset;
    use netns::{
        BANNIERE_PORT, Bench, CLIENT_ADDR, NS_CLIENT, NS_PHYS, PHYS_ADDR, PREFIX, TUN_CLIENT_ADDR,
        TUN_SERVER_ADDR, VETH_PHYS, WG_CLIENT_IF, WG_PORT, WG_SERVER_IF,
    };
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::Path;
    use std::time::{Duration, Instant};
    use transport::Compteurs;
    use wgapply::{WgPeerSpec, WgSpec};

    /// fwmark utilise dans le banc, identique a celui du produit.
    const BENCH_FWMARK: u32 = 0xca6c;
    const BENCH_TABLE: u32 = 51820;
    /// Temps laisse au handshake WireGuard avant de renoncer.
    const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(8);
    /// Fenetre laissee a la lecture de la banniere, en millisecondes.
    ///
    /// Elle couvre le lancement du serveur dans l'autre namespace et
    /// l'echauffement du tunnel. Un echec unique confondrait "pas encore
    /// pret" avec "ne transporte pas", et le second verdict est bien plus
    /// grave que le premier. Large parce qu'elle ne coute rien quand tout va
    /// bien: la premiere tentative aboutit et la fenetre n'est jamais atteinte.
    const LECTURE_BANNIERE_MS: u64 = 5000;
    /// Compte sous lequel le banc fait tourner le faux coeur.
    ///
    /// `nobody` plutot qu'un compte cree pour l'occasion: il existe sur toute
    /// distribution, et un harnais qui fabrique des comptes systeme laisse des
    /// traces sur la machine de recette. En production le coeur a son propre
    /// compte dedie; ce qui se mesure ici est le mecanisme, pas le numero.
    const COEUR_UID: u32 = 65534;

    /// Compte sous lequel le banc fait tourner le faux resolveur chiffre.
    ///
    /// DISTINCT de [`COEUR_UID`], et pas par gout de la variete: l'installateur
    /// refuse que le coeur et le resolveur partagent un identifiant, parce que
    /// les confondre donnerait au resolveur la sortie LARGE du coeur, c'est-a-
    /// dire exactement la fuite que ce vecteur cherche. Un banc qui les
    /// melangerait mesurerait une seule exemption en croyant en mesurer deux.
    ///
    /// Un numero qu'aucun compte ne porte, et c'est voulu: `setpriv` l'accepte
    /// tel quel, verifie sur essai-linux le 22/08/2026, donc le banc ne cree
    /// aucun compte systeme sur la machine de recette.
    const RESOLVEUR_UID: u32 = 65533;

    /// Les identites que le plan du banc exempte, et le sens de chacune.
    ///
    /// Deux `Option<u32>` nus a la suite se seraient echanges sans un mot, et
    /// l'echange aurait ete muet: le vecteur du coeur serait alors passe en
    /// mesurant l'exception du resolveur, et reciproquement. Les deux
    /// exemptions sont des CONTRAIRES - large sauf le :53 d'un cote, rien que
    /// le :53 de l'autre - donc les confondre ne rend pas une mesure
    /// approximative, elle rend une mesure inversee.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct Exemptions {
        /// Le coeur anti-censure: sortie large, son :53 excepte.
        coeur: Option<u32>,
        /// Le resolveur chiffre: le :53 malgre le blocage, et rien d'autre.
        resolveur: Option<u32>,
    }

    impl Exemptions {
        const AUCUNE: Self = Self {
            coeur: None,
            resolveur: None,
        };

        const fn coeur(uid: u32) -> Self {
            Self {
                coeur: Some(uid),
                resolveur: None,
            }
        }

        const fn resolveur(uid: u32) -> Self {
            Self {
                coeur: None,
                resolveur: Some(uid),
            }
        }
    }

    /// Les motifs de saut du chemin Linux, rendus SANS monter de banc.
    ///
    /// # Pourquoi ce module existe
    ///
    /// Le pendant Windows garde ses motifs en appelant `windows::run_all()`
    /// depuis une recette. Ce chemin-la n'a PAS d'equivalent ici, et pas par
    /// negligence:
    ///
    /// - sans privileges, `linux::run_all()` s'arrete au premier prerequis et
    ///   rend le MEME motif pour les neuf vecteurs qui montent le banc, le
    ///   dixieme etant `doh-bypass`, qui n'en a pas besoin. Une recette qui
    ///   lirait ce rapport n'eprouverait donc qu'UNE phrase;
    /// - avec privileges, il monte des espaces de noms, ARME le kill switch et
    ///   coupe le reseau de la machine. Une recette n'a pas le droit de faire
    ///   ca, et `sudo cargo test` suffirait a le declencher.
    ///
    /// D'ou ce catalogue: chaque motif est rendu par la fonction que le chemin
    /// d'execution appelle LUI-MEME. Une recette qui recopierait les phrases
    /// serait verte pendant que le produit en dirait d'autres - c'est
    /// exactement la derive qui a laisse ces messages sans garde.
    ///
    /// Ne sont ici que les motifs de PROSE FIXE. Ceux qui ne font qu'ajouter un
    /// prefixe a une erreur du systeme (<< capture: {e} >>) n'ont rien a garder
    /// qui ne soit deja dans l'erreur.
    pub mod motifs {
        use super::super::probe;
        use super::{ARMEMENT_TIMEOUT, COEUR_UID, FENETRE_APRES_MORT, RESOLVEUR_UID};

        /// Ce dont le harnais Linux a besoin, et a quoi chaque outil sert.
        ///
        /// Table plutot que trois `if`: le motif rendu au sauteur en est tire,
        /// donc ajouter un outil sans dire a quoi il sert devient impossible.
        pub const PREREQUIS: [(&str, &str); 3] = [
            ("ip", "creation des namespaces et du veth"),
            ("nft", "application du kill switch dans le namespace"),
            ("tcpdump", "capture et analyse pcap"),
        ];

        pub fn exige_root() -> String {
            "le harnais cree des namespaces reseau et capture du trafic: il exige root".to_owned()
        }

        pub fn binaire_absent(bin: &str, usage: &str) -> String {
            format!("'{bin}' est absent, requis pour {usage}")
        }

        pub fn exe_introuvable() -> String {
            "chemin du binaire du daemon introuvable".to_owned()
        }

        pub fn setpriv_absent_exemption() -> String {
            setpriv_absent("une exemption")
        }

        pub fn setpriv_absent_exception() -> String {
            setpriv_absent("une exception")
        }

        /// `quoi` distingue l'exemption du coeur de l'exception du resolveur:
        /// les deux vecteurs sautent pour la meme cause et n'en tirent pas la
        /// meme consequence.
        ///
        /// Prive, et les deux entrees publiques ci-dessus ne prennent aucun
        /// argument: la garde de source refuse un litteral dans la raison d'un
        /// `skipped(`, et `setpriv_absent("une exemption")` en serait un.
        fn setpriv_absent(quoi: &str) -> String {
            format!(
                "'setpriv' est absent: impossible d'emettre une sonde sous une identite \
                 choisie, donc impossible de mesurer {quoi} qui porte justement sur \
                 l'identite"
            )
        }

        pub fn banc_impossible(cause: &str) -> String {
            format!("montage du banc en namespaces impossible: {cause}")
        }

        pub fn tunnel_non_etabli(cause: &str) -> String {
            format!("tunnel de test non etabli: {cause}")
        }

        /// Temoin negatif muet d'un vecteur de fuite.
        ///
        /// `desarmement` n'est pas decoratif: un temoin muet a deux causes
        /// opposees - la sonde n'a rien emis, ou le kill switch etait encore
        /// pose - et c'est la seule ligne qui les separe.
        pub fn temoin_muet_sonde(sonde: &str, desarmement: &str) -> String {
            format!(
                "temoin negatif muet: sans kill switch, la sonde '{sonde}' n'a produit aucun \
                 paquet observable. Le test ne prouverait rien. Ce que le retrait des filtres \
                 a fait: {desarmement}"
            )
        }

        /// Ce que le banc a repondu quand on lui a demande sa chaine.
        ///
        /// Trois etats et non deux. `Illisible` existe parce que l'ancien
        /// `sortie_de` rendait la plainte de `nft` comme une ligne de regle: le
        /// motif annoncait alors << chaine PRESENTE (1 lignes), donc le
        /// desarmement a echoue >> alors que personne n'avait rien lu.
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub enum EtatChaine {
            Absente,
            Presente(usize),
            Illisible(String),
        }

        impl EtatChaine {
            /// Lit l'etat a partir de ce que le listage a rendu.
            pub fn depuis(lu: Result<Vec<String>, String>) -> Self {
                match lu {
                    Ok(l) if l.is_empty() => Self::Absente,
                    Ok(l) => Self::Presente(l.len()),
                    Err(e) => Self::Illisible(e),
                }
            }

            fn dit(&self) -> String {
                match self {
                    Self::Absente => "absente, comme attendu".to_owned(),
                    Self::Presente(n) => {
                        format!("PRESENTE ({n} lignes), donc le desarmement a echoue")
                    }
                    Self::Illisible(e) => {
                        format!("ILLISIBLE ({e}), donc ni sa presence ni son absence n'est etablie")
                    }
                }
            }
        }

        /// Temoin negatif muet sous une identite choisie.
        pub fn temoin_muet_identite(qui: &str, sonde: &str, chaine: &EtatChaine) -> String {
            format!(
                "temoin negatif muet: SANS kill switch, la sonde lancee sous {qui} n'a produit \
                 aucun paquet [{sonde}]; la chaine du kill switch est {}. Le reste du vecteur \
                 lirait des silences sans pouvoir les attribuer.",
                chaine.dit()
            )
        }

        /// La chaine n'a pas pu etre lue, et la preuve le DIT.
        pub fn chaine_illisible(cause: &str) -> String {
            format!("chaine du kill switch illisible, aucune preuve n'en a ete tiree: {cause}")
        }

        /// Les regles par identite n'ont pas pu etre relues apres l'armement.
        ///
        /// Sans cette relecture, rien n'etablit que le plan ACCEPTE par nft
        /// est le plan POSE dans le noyau: les silences mesures ensuite
        /// seraient imputes a l'identite sans que la regle qui la nomme ait
        /// ete vue.
        pub fn regles_par_identite_illisibles(cause: &str) -> String {
            format!(
                "regles par identite non relues apres l'armement, donc rien n'etablit que \
                 le plan accepte est le plan pose: {cause}"
            )
        }

        /// Le noyau ne tient pas les regles par identite que le generateur a
        /// emises, ou en tient d'autres: nft a accepte un plan qui n'est pas
        /// celui qu'il applique. Chaque regle est nommee ENTIERE, mot pour
        /// mot, sur la forme que nft rend (5m).
        pub fn regles_par_identite_divergentes(ecart: &super::super::regles_nft::Ecart) -> String {
            format!(
                "nft a accepte le plan, mais les regles par identite que le noyau tient ne \
                 sont pas celles emises: {}",
                ecart.dit()
            )
        }

        /// Les motifs qui n'ajoutent qu'un prefixe a une erreur du systeme.
        ///
        /// Un par site, et jamais deux sites sous le meme nom. Ils etaient
        /// ecrits en ligne, et deux d'entre eux disaient exactement
        /// << capture: {e} >> dans la MEME fonction, l'un pour un demarrage
        /// rate, l'autre pour un arret rate: le rapport ne permettait pas de
        /// savoir laquelle des deux etapes avait lache.
        pub fn desarmement_impossible(cause: &str) -> String {
            format!("desarmement impossible: {cause}")
        }
        pub fn temoin_negatif_impossible(cause: &str) -> String {
            format!("temoin negatif non observable: {cause}")
        }
        pub fn armement_impossible(cause: &str) -> String {
            format!("armement impossible: {cause}")
        }
        pub fn mesure_impossible(cause: &str) -> String {
            format!("mesure sous kill switch impossible: {cause}")
        }
        pub fn copie_de_sonde_impossible(cause: &str) -> String {
            format!("copie de la sonde en lecture pour tous impossible: {cause}")
        }
        pub fn armement_sans_exemption(cause: &str) -> String {
            format!("armement sans exemption impossible: {cause}")
        }
        pub fn armement_avec_exemption(cause: &str) -> String {
            format!("armement avec exemption impossible: {cause}")
        }
        pub fn armement_sans_exception(cause: &str) -> String {
            format!("armement sans exception impossible: {cause}")
        }
        pub fn armement_avec_exception(cause: &str) -> String {
            format!("armement avec exception impossible: {cause}")
        }
        pub fn temoin_du_coeur_impossible(cause: &str) -> String {
            format!("temoin du coeur sous armement non observable: {cause}")
        }
        pub fn mesure_de_la_sortie(cause: &str) -> String {
            format!("mesure de la sortie du coeur impossible: {cause}")
        }
        pub fn mesure_de_l_exclusion(cause: &str) -> String {
            format!("mesure de l'exclusion des autres identites impossible: {cause}")
        }
        pub fn mesure_du_dns(cause: &str) -> String {
            format!("mesure du :53 sous l'identite du coeur impossible: {cause}")
        }
        pub fn observation_impossible(tag: &str, cause: &str) -> String {
            format!("observation '{tag}' impossible: {cause}")
        }
        pub fn pair_non_leve(cause: &str) -> String {
            format!("pair de banniere non leve: {cause}")
        }
        pub fn compteurs_avant(cause: &str) -> String {
            format!("compteurs du tunnel illisibles avant la mesure: {cause}")
        }
        pub fn compteurs_apres(cause: &str) -> String {
            format!("compteurs du tunnel illisibles apres la mesure: {cause}")
        }
        pub fn capture_non_demarree(cause: &str) -> String {
            format!("capture non demarree: {cause}")
        }
        pub fn capture_non_arretee(cause: &str) -> String {
            format!("capture non arretee proprement: {cause}")
        }
        pub fn capture_du_temoin_non_demarree(cause: &str) -> String {
            format!("capture du temoin non demarree: {cause}")
        }
        pub fn capture_du_temoin_non_arretee(cause: &str) -> String {
            format!("capture du temoin non arretee proprement: {cause}")
        }
        pub fn analyse_des_chiffres(cause: &str) -> String {
            format!("comptage des paquets chiffres impossible: {cause}")
        }
        pub fn analyse_du_clair(cause: &str) -> String {
            format!("relecture des paquets en clair impossible: {cause}")
        }
        pub fn analyse_du_temoin(cause: &str) -> String {
            format!("relecture du pcap du temoin impossible: {cause}")
        }
        pub fn analyse_du_pcap(cause: &str) -> String {
            format!("relecture du pcap impossible: {cause}")
        }
        pub fn armeur_non_lance(cause: &str) -> String {
            format!("processus armeur non lance: {cause}")
        }
        pub fn mise_a_mort_impossible(cause: &str) -> String {
            format!("mise a mort du processus armeur impossible: {cause}")
        }
        pub fn injection_de_panne(cause: &str) -> String {
            format!("destruction de l'interface du tunnel impossible: {cause}")
        }
        pub fn injection_dpi(cause: &str) -> String {
            format!("injection du DPI simule impossible: {cause}")
        }
        pub fn kill_switch_illisible(cause: &str) -> String {
            format!(
                "etat du kill switch illisible apres la mort du processus: {cause}. Ni sa \
                 survie ni sa disparition n'est etablie, et les deux se concluent \
                 differemment"
            )
        }

        /// Le kill switch ne mord pas sur ce banc: mesurer la largeur d'une
        /// exemption n'y prouverait rien.
        pub fn temoin_invalide_coeur(paquets: usize) -> String {
            format!(
                "temoin invalide: sans aucune exemption, l'uid {COEUR_UID} sort deja \
                 ({paquets} paquet(s)). Le kill switch ne s'applique pas sur ce banc, donc \
                 mesurer la largeur de l'exemption ne prouverait rien."
            )
        }

        pub fn temoin_muet_apres_mort(sonde: &str) -> String {
            format!(
                "temoin negatif muet: sans kill switch, les sondes n'ont produit aucun paquet \
                 observable sur le lien, donc un zero apres la mort ne prouverait rien. Ce \
                 qu'elles ont fait: {sonde}"
            )
        }

        pub fn armeur_muet() -> String {
            format!(
                "le processus armeur n'a pose aucune table en {} s: il n'y a rien a faire \
                 mourir",
                ARMEMENT_TIMEOUT.as_secs()
            )
        }

        // --- Les raisons d'ECHEC et de REUSSITE, entrees au catalogue (5h) ---
        //
        // Elles etaient ecrites en ligne dans les appels `failed(` et `passed(`,
        // donc hors du catalogue et vues par aucune garde: ni celle de forme, ni
        // celle de distinction, ni la garde de source qui ne lisait que
        // `skipped(`. 5g avait fait entrer `sortie_de`; voici le reste de la
        // meme famille pour les verdicts. La donnee de mesure - comptes,
        // contexte - reste un argument: c'est la PROSE qui entre au catalogue, la
        // garde de source refusant desormais tout litteral dans ces appels aussi.

        /// Vecteur de fuite: rien ne sort une fois le kill switch pose.
        pub fn zero_sous_kill_switch(baseline: usize) -> String {
            format!("{baseline} paquet(s) sans kill switch, 0 avec")
        }

        /// Vecteur de fuite: du trafic est sorti malgre le kill switch.
        pub fn fuite_malgre_kill_switch(compte: usize) -> String {
            format!("{compte} paquet(s) sortis malgre le kill switch")
        }

        /// Exemption du coeur: l'uid exempte ne parvient meme pas a sortir.
        pub fn coeur_etrangle(cible: impl std::fmt::Display) -> String {
            format!(
                "l'exemption ne laisse pas sortir le coeur: aucun paquet vers {cible} alors \
                 que l'uid {COEUR_UID} est explicitement autorise. Un coeur lance dans ces \
                 conditions serait etrangle par le kill switch."
            )
        }

        /// Exemption du coeur: une autre identite que le coeur est sortie.
        pub fn sortie_hors_coeur(compte: usize) -> String {
            format!(
                "{compte} paquet(s) sortis sous root alors que seul l'uid {COEUR_UID} est \
                 exempte: l'exemption n'est pas liee a l'identite"
            )
        }

        /// Exemption du coeur: l'exemption a rouvert le DNS.
        pub fn dns_rouvert_par_coeur(compte: usize) -> String {
            format!(
                "{compte} requete(s) DNS sorties sous l'uid du coeur: l'exemption passe \
                 au-dessus des permits DNS et rouvre la fuite"
            )
        }

        /// Exemption du coeur: la reussite, bornee a la seule identite du coeur.
        pub fn coeur_exempte_sans_deborder(compte: usize) -> String {
            format!(
                "sans exemption le coeur ne sort pas; avec, il sort ({compte} paquet(s)) \
                 pendant que root reste bloque et que son :53 tombe"
            )
        }

        /// Daemon mort: les filtres ont disparu avec le processus.
        pub fn daemon_mort_rouvre_le_trafic() -> String {
            "les filtres du kill switch ont disparu avec le processus qui les avait poses: un \
             daemon qui meurt rouvre le trafic"
                .to_owned()
        }

        /// Daemon mort: du trafic en clair apres la mort du processus.
        pub fn fuite_apres_la_mort(compte: usize) -> String {
            format!("{compte} paquet(s) en clair apres la mort du processus")
        }

        /// Daemon mort: la reussite, filtres survivants et silence apres la mort.
        pub fn etanche_apres_la_mort(
            temoin: usize,
            mort: &str,
            tunnel: &str,
            sondes: &str,
        ) -> String {
            format!(
                "{temoin} paquet(s) en clair sans kill switch, 0 pendant les {} s qui suivent \
                 la mort du processus; les filtres sont toujours poses ({mort}; {tunnel}; \
                 dernieres sondes: {sondes})",
                FENETRE_APRES_MORT.as_secs()
            )
        }

        // --- Fenetre de reconnexion: les trois injections du document 02 (5i) ---
        //
        // Le vecteur `reconnect-window` porte desormais TROIS phases, une par
        // injection de defaillance de la partie 4 du document 02: le DPI qui
        // jette l'UDP de WireGuard (deja `injection_dpi` plus haut), la perte
        // totale (netem loss 100%), et la coupure de lien. Chaque phase a sa
        // propre cause au catalogue, sa propre capture, et fait echouer le
        // vecteur en se nommant. Chaque phase mesure DEUX choses: un temoin
        // vivant (la sonde de lien vue SANS kill switch) et l'absence de clair
        // sous kill switch. Un pcap vide ne prouve rien tant que le temoin ne
        // l'a pas rempli une fois.

        /// Injection de la perte totale (netem loss 100%) impossible.
        pub fn injection_perte_totale(cause: &str) -> String {
            format!("injection de la perte totale (netem loss 100%) impossible: {cause}")
        }

        /// Injection de la coupure de lien impossible.
        pub fn injection_coupure_lien(cause: &str) -> String {
            format!("injection de la coupure du lien physique impossible: {cause}")
        }

        /// Rearmement du kill switch impossible entre deux phases.
        ///
        /// Le temoin de chaque phase desarme puis rearme; un rearmement rate
        /// laisserait les phases suivantes mesurer un banc sans kill switch, et
        /// un vecteur n'a pas le droit de faire mentir ses voisines.
        pub fn rearmement_impossible(cause: &str) -> String {
            format!("rearmement du kill switch impossible apres le temoin d'une phase: {cause}")
        }

        /// Fenetre de reconnexion: le temoin d'une phase est muet.
        ///
        /// La sonde de lien vise un voisin ON-LINK, dont la route ne passe pas
        /// par le tunnel: elle repart en clair des que le kill switch ne tient
        /// plus, et c'est la seule sonde qui discrimine ici. Muette SANS kill
        /// switch, elle ne peut rien prouver ARME, et la phase s'abstient.
        pub fn temoin_muet_reconnexion(phase: &str, dit: &str) -> String {
            format!(
                "temoin negatif muet pendant la phase '{phase}': sans kill switch, la sonde \
                 de lien n'a produit aucun paquet observable cote physique, donc un zero \
                 sous kill switch ne prouverait rien. Ce que la sonde a fait: {dit}"
            )
        }

        /// Fenetre de reconnexion: une phase n'a pas pu s'executer.
        pub fn phase_reconnexion_sautee(phase: &str, cause: &str) -> String {
            format!("phase '{phase}' de la fenetre de reconnexion non mesuree: {cause}")
        }

        /// Fenetre de reconnexion: du clair est sorti pendant une phase.
        pub fn fuite_pendant_reconnexion(compte: usize, phase: &str) -> String {
            format!(
                "{compte} paquet(s) en clair cote physique pendant la phase '{phase}' de la \
                 fenetre de reconnexion"
            )
        }

        /// Fenetre de reconnexion: la reussite, phase par phase.
        pub fn reconnexion_etanche_par_phase(rapport: &str) -> String {
            format!(
                "zero paquet en clair sous kill switch pendant la fenetre de reconnexion, \
                 phase par phase: {rapport}"
            )
        }

        /// Le rapport d'une phase etanche, compose au catalogue (5q).
        ///
        /// Il etait fabrique en ligne par `mesurer_phase_reconnexion` puis porte
        /// par `PhaseReconnexionIssue::Etanche`, hors catalogue. La phrase entre
        /// ici; le nom de phase et le compte du temoin restent des arguments.
        pub fn phase_temoin_puis_silence(phase: &str, temoin: usize) -> String {
            format!("{phase}: {temoin} paquet(s) temoin sans kill switch, 0 sous kill switch")
        }

        // --- Les trois trous fermes par 5s: la chute avec temoin, le tunnel ---
        // --- vivant de reconnexion, la reprise pilotee par la machine a etats ---
        //
        // (a) `kill-switch-on-drop` recoit enfin un temoin (le trou que `5i` a
        // ferme pour `reconnect-window`); (b) `reconnect-window` reconstruit un
        // tunnel vivant avant d'injecter; (c) une quatrieme phase fait JOUER a
        // la machine a etats la sequence de reprise reelle. Chaque raison passe
        // par le catalogue.

        /// (a) Temoin muet a la chute de l'interface du tunnel.
        ///
        /// Sort quand, kill switch retire, la sonde de lien on-link ne produit
        /// aucun paquet: un zero sous kill switch apres la destruction de
        /// l'interface ne prouverait alors rien.
        pub fn temoin_muet_chute(dit: &str) -> String {
            format!(
                "temoin negatif muet a la chute: sans kill switch, la sonde de lien n'a \
                 produit aucun paquet observable cote physique, donc un zero apres la \
                 destruction de l'interface ne prouverait rien. Ce que la sonde a fait: {dit}"
            )
        }

        /// (a) La chute: temoin vu sans kill switch, silence sous kill switch.
        ///
        /// La reussite de `kill-switch-on-drop`: la sonde on-link fuit sans kill
        /// switch, plus rien ne sort une fois l'interface detruite et le kill
        /// switch en place.
        pub fn chute_etanche(temoin: usize) -> String {
            format!(
                "{temoin} paquet(s) temoin sans kill switch, 0 sous kill switch apres \
                 destruction de l'interface du tunnel"
            )
        }

        /// (a) La chute: du clair est sorti alors que le kill switch tenait.
        pub fn fuite_apres_chute(compte: usize) -> String {
            format!(
                "{compte} paquet(s) en clair apres destruction de l'interface du tunnel, \
                 alors que le kill switch etait cense tenir"
            )
        }

        /// (b) Reconstruction du tunnel client de reconnexion impossible.
        ///
        /// Sort quand `reconnect-window` n'a pas pu remonter le client apres la
        /// destruction d'interface laissee par `kill-switch-on-drop`.
        pub fn reconstruction_tunnel_impossible(cause: &str) -> String {
            format!("reconstruction du tunnel client de reconnexion impossible: {cause}")
        }

        /// (b) Le tunnel reconstruit ne repond pas avant l'injection.
        ///
        /// Sort quand aucune poignee de main n'aboutit sur le tunnel remonte:
        /// mesurer les phases sur un tunnel mort ne dirait rien de la fenetre
        /// de reconnexion reelle, un tunnel vivant qui n'arrive plus a se
        /// reetablir.
        pub fn tunnel_de_reconnexion_non_vivant(cause: &str) -> String {
            format!(
                "tunnel de reconnexion non vivant avant injection, aucune poignee de main: \
                 {cause}. Les phases mesureraient un tunnel mort, pas la fenetre de \
                 reconnexion reelle"
            )
        }

        /// (c) Configuration de banc impossible a batir pour piloter la machine.
        ///
        /// Sort si une cle ou une adresse du banc ne se laisse pas analyser: la
        /// machine a etats exige un `Connect(TunnelConfig)` pour atteindre
        /// `Connected`, et sans config la sequence de reprise ne peut pas etre
        /// jouee.
        pub fn config_de_banc_impossible(cause: &str) -> String {
            format!("configuration de banc pour piloter la machine a etats impossible: {cause}")
        }

        /// (c) La machine a etats n'a pas atteint `Connected`.
        ///
        /// Sort si `Connect`, `TunnelUp` puis `HandshakeOk` ne menent pas la
        /// machine en `Connected`: la sequence de reprise part de cet etat.
        pub fn machine_pas_connectee(etat: &str) -> String {
            format!(
                "la machine a etats n'a pas atteint Connected apres Connect, TunnelUp et \
                 HandshakeOk, etat rendu: {etat}. La sequence de reprise ne peut pas etre jouee"
            )
        }

        /// (c) Une action de reprise sans executeur dans le banc a ete emise.
        ///
        /// Sort si la machine rend, a `TunnelLost` ou `RetryTimer`, une action
        /// que le banc ne sait pas jouer: la sequence ne la prevoit pas, et le
        /// banc la nomme plutot que de la sauter en silence.
        pub fn action_de_reprise_inattendue(action: &str) -> String {
            format!(
                "l'action '{action}' rendue par la machine a etats pendant la reprise n'a pas \
                 d'executeur dans le banc: la sequence de reprise ne la prevoit pas"
            )
        }

        /// (c) L'execution d'une action de reprise a echoue.
        pub fn executeur_de_reprise_impossible(action: &str, cause: &str) -> String {
            format!("execution de l'action de reprise '{action}' impossible: {cause}")
        }

        /// (c) La reprise: temoin vu, silence pendant la sequence de la machine.
        ///
        /// La reussite de la quatrieme phase: la sonde de lien fuit sans kill
        /// switch, et rien ne sort en clair pendant toute la sequence emise par
        /// la machine a etats, la seconde sans route comprise. `jetes` porte le
        /// compte de paquets que le kill switch a jetes pendant cette seconde
        /// sans route (5s, second passage): sans lui, le rapport ne dirait pas
        /// que la fenetre a ete reellement sondee.
        pub fn phase_reprise_etanche(temoin: usize, jetes: u64, sequence: &str) -> String {
            format!(
                "reprise-du-daemon: {temoin} paquet(s) temoin sans kill switch, 0 sous kill \
                 switch pendant la sequence emise par la machine a etats ({sequence}); {jetes} \
                 paquet(s) de sonde jetes par le kill switch pendant la seconde sans route"
            )
        }

        // --- Le temoin interne de la seconde sans route et le reengagement ---
        // --- effectif du kill switch (5s, second passage: (i) et (ii)) ---
        //
        // (i) La seconde sans route (ScheduleRetry) etait sondee mais rien ne le
        // prouvait: `sonder_sans_route` videe passait mot pour mot. Le compteur
        // `bifrost-output-dropped` de la table du kill switch devient le temoin
        // INTERNE de la fenetre. (ii) `EngageKillSwitch` inerte passait aussi,
        // le banc etant deja arme; le meme compteur, remis a zero par `arm`, le
        // prouve maintenant. Chaque raison passe par le catalogue.

        /// (i) Le compteur du kill switch n'a pas pu etre lu pendant la reprise.
        ///
        /// La chaine `output` de la table du kill switch porte le compteur des
        /// paquets jetes; ne pas pouvoir la lire laisse la seconde sans route
        /// sans temoin interne, et la phase s'abstient plutot que de conclure.
        pub fn compteur_du_kill_switch_illisible(cause: &str) -> String {
            format!("compteur du kill switch illisible pendant la reprise: {cause}")
        }

        /// (i) La table du kill switch ne porte pas le compteur attendu.
        ///
        /// Sort quand la chaine se lit mais que la regle `counter ... comment
        /// bifrost-output-dropped` n'y est pas, sous sa forme vivante: la table
        /// n'est pas celle du kill switch, ou sa forme a change. La seconde sans
        /// route reste alors sans temoin interne.
        pub fn compteur_du_kill_switch_absent() -> String {
            "compteur bifrost-output-dropped absent de la table du kill switch: la seconde sans \
             route ne peut pas servir de temoin interne"
                .to_owned()
        }

        /// (i) Les sondes de la seconde sans route n'ont pas ete jetees.
        ///
        /// Le compteur `bifrost-output-dropped` est reste a zero juste avant
        /// `EngageKillSwitch`: `sonder_sans_route` n'a rien emis, ou le kill
        /// switch ne tenait pas. La fenetre sans route n'a alors rien mesure, et
        /// la phase s'abstient en donnant le compte et ce que la sonde a dit.
        pub fn sondes_non_jetees_seconde_sans_route(compte: u64, dit: &str) -> String {
            format!(
                "reprise-du-daemon: le kill switch n'a jete aucune sonde pendant la seconde sans \
                 route (compteur bifrost-output-dropped = {compte} paquet(s)), donc la fenetre \
                 sans route n'a rien mesure. Ce que la sonde a dit: {dit}"
            )
        }

        /// (ii) `EngageKillSwitch` sans effet: compteur non remis a zero.
        ///
        /// `arm` recree la table et remet le compteur a zero. S'il reste non nul
        /// apres l'action, le reengagement n'a rien recree: un executeur inerte
        /// passerait sinon inapercu, le banc etant deja arme a son arrivee.
        pub fn kill_switch_reengage_sans_effet(action: &str, compte: u64) -> String {
            format!(
                "l'action '{action}' n'a pas repose le kill switch: le compteur \
                 bifrost-output-dropped n'est pas revenu a zero apres l'action (il vaut {compte} \
                 paquet(s)), donc la table n'a pas ete recreee"
            )
        }

        /// (ii) `EngageKillSwitch` sans effet: compteur introuvable apres.
        ///
        /// Le pendant du precedent quand la table a disparu apres l'action: le
        /// compteur ne se lit plus, ce qui prouve aussi que le reengagement n'a
        /// pas eu lieu.
        pub fn kill_switch_repose_absent(action: &str, cause: &str) -> String {
            format!(
                "l'action '{action}' n'a pas repose le kill switch: son compteur est introuvable \
                 apres l'action, la table n'a donc pas ete recreee ({cause})"
            )
        }

        /// (3)/(i) Du clair a fui ET un abandon coexistait pendant la reprise.
        ///
        /// La regle du chemin de conclusion sous capture: si du clair est passe,
        /// la phase rend FAILED meme quand une raison voulait la faire sauter (un
        /// compteur illisible, un executeur en echec, un reengagement sans effet).
        /// La fuite prime, et la raison dit les deux: le compte de clair ET
        /// l'abandon qui l'aurait masquee sans la mesure sous capture. Le defaut
        /// ferme par 5s (troisieme passage): un SKIPPED cachait alors un FAILED.
        pub fn fuite_et_abandon_pendant_reconnexion(
            compte: usize,
            phase: &str,
            abandon: &str,
        ) -> String {
            format!(
                "{compte} paquet(s) en clair cote physique pendant la phase '{phase}' de la fenetre de reconnexion; l'abstention qui l'aurait masquee sans la mesure sous capture: {abandon}"
            )
        }

        /// Abstention SOUS CAPTURE quand le pcap n'a pas pu etre mesure.
        ///
        /// Une sortie de la sequence de reprise entre `Capture::start` et la fin
        /// doit arreter la capture et relire le pcap avant de rendre une
        /// abstention. Si cet arret ou cette relecture echoue, on ne peut PAS
        /// dire si du clair a passe (l'absence de trace n'est pas une mesure): on
        /// nomme la cause de non-mesure et, s'il coexistait, l'abandon en cours.
        pub fn abandon_et_mesure_impossible(abandon: &str, cause: &str) -> String {
            format!(
                "abstention pendant la reprise sans mesure possible du pcap ({cause}); impossible de dire si l'abandon suivant a masque une fuite: {abandon}"
            )
        }

        // --- L'exception du resolveur chiffre: ses verdicts, au catalogue (5q) ---
        //
        // `juger_resolveur` construisait ses `IssueResolveur::{Reussi,Ignore,Echec}`
        // en `format!` a meme la variante, hors catalogue et vus par aucune garde.
        // La PROSE entre ici; les comptes de paquets restent des arguments. Aucune
        // phrase ne change: seule l'interpolation se deplace du juge vers ces
        // fonctions.

        /// Temoin negatif muet: l'uid du resolveur n'emet meme pas hors :53.
        pub fn resolveur_temoin_muet() -> String {
            format!(
                "temoin negatif muet: sans kill switch, l'uid {RESOLVEUR_UID} n'a produit \
                 aucun paquet vers {}. Son refus sous armement s'expliquerait aussi bien \
                 par une sonde qui n'emet pas que par la borne de l'exception.",
                probe::PROBE_V4
            )
        }

        /// Temoin negatif muet sur le :53: l'uid du resolveur n'y emet pas.
        pub fn resolveur_temoin_muet_dns() -> String {
            format!(
                "temoin negatif muet sur le :53: sans kill switch, l'uid {RESOLVEUR_UID} \
                 n'a produit aucune requete vers {}. Un succes sous armement serait alors \
                 impossible, et l'exception resterait inconnue.",
                probe::PROBE_DNS
            )
        }

        /// Temoin invalide: le :53 sort deja sans aucune exception.
        pub fn resolveur_temoin_invalide(temoin: usize) -> String {
            format!(
                "temoin invalide: sans aucune exception, l'uid {RESOLVEUR_UID} joint deja \
                 le :53 ({temoin} paquet(s)). Le kill switch ne s'applique pas sur ce banc, donc \
                 mesurer la borne de l'exception ne prouverait rien."
            )
        }

        /// Fuite: root sort sur le :53, l'exception ne discrimine pas l'identite.
        pub fn resolveur_fuite_identite(etranger: usize) -> String {
            format!(
                "FUITE: {etranger} paquet(s) sortis sous root vers le :53 de {} alors que seul \
                 l'uid {RESOLVEUR_UID} est excepte. L'exception ne discrimine pas \
                 l'identite, elle rouvre le :53 a tout le monde.",
                probe::PROBE_DNS
            )
        }

        /// Fuite: le resolveur sort hors du :53, l'exception n'est pas bornee.
        pub fn resolveur_fuite_hors_port(hors: usize) -> String {
            format!(
                "FUITE: {hors} paquet(s) sortis sous l'uid {RESOLVEUR_UID} vers {}, hors du \
                 :53. Son exception n'est pas bornee au port: elle en fait un second \
                 transport, c'est-a-dire une sortie en clair hors tunnel.",
                probe::PROBE_V4
            )
        }

        /// L'exception ne matche pas: le resolveur ne pourrait pas demarrer.
        pub fn resolveur_exception_morte() -> String {
            format!(
                "l'exception ne matche pas: aucune requete de l'uid {RESOLVEUR_UID} vers \
                 le :53 de {} n'est sortie sous armement. Le resolveur ne pourrait pas \
                 resoudre le nom de son propre serveur chiffre, donc pas demarrer. Les \
                 deux silences constates ne prouvent alors rien de la borne, puisqu'ils \
                 s'expliquent par un plan qui bloque tout.",
                probe::PROBE_DNS
            )
        }

        /// La reussite: le :53 s'ouvre pour le resolveur, borne au port.
        pub fn resolveur_borne_ok(resolveur_dns: usize) -> String {
            format!(
                "sans exception le :53 de l'uid {RESOLVEUR_UID} ne sort pas; avec, il sort \
                 ({resolveur_dns} paquet(s)) pendant que le meme uid reste bloque hors du :53 et que root \
                 ne resout pas"
            )
        }

        /// Tout ce que le chemin Linux sait dire, rendu sans banc ni root.
        ///
        /// Chaque entree porte le nom du site qui l'emet, pour qu'une garde
        /// rouge designe la phrase a corriger et pas seulement son texte.
        #[cfg(test)]
        pub fn catalogue() -> Vec<(&'static str, String)> {
            // Une cause differente par entree: deux motifs qui se lisent
            // pareil sont refuses par une garde, et une cause identique partout
            // rendrait ce refus inoperant.
            let mut tout = vec![
                ("prerequis/root", exige_root()),
                ("prerequis/exe", exe_introuvable()),
                ("coeur/setpriv", setpriv_absent_exemption()),
                ("resolveur/setpriv", setpriv_absent_exception()),
                ("run_all/banc", banc_impossible("Operation not permitted")),
                ("run_all/tunnel", tunnel_non_etabli("handshake absent")),
                ("coeur/temoin-invalide", temoin_invalide_coeur(23)),
                (
                    "daemon-mort/temoin-muet",
                    temoin_muet_apres_mort("probe all: sortie 0; probe-lan: sortie 0"),
                ),
                ("daemon-mort/armeur-muet", armeur_muet()),
                (
                    "temoin/identite-chaine-absente",
                    temoin_muet_identite("le coeur", "sortie 0", &EtatChaine::Absente),
                ),
                (
                    "temoin/identite-chaine-presente",
                    temoin_muet_identite(
                        "le resolveur",
                        "sortie 1: refus",
                        &EtatChaine::Presente(2),
                    ),
                ),
                (
                    "temoin/identite-chaine-illisible",
                    temoin_muet_identite(
                        "le coeur",
                        "sortie 0",
                        &EtatChaine::Illisible("nft: command not found".to_owned()),
                    ),
                ),
                ("preuve/chaine-illisible", chaine_illisible("nft muet")),
                (
                    "desarmement",
                    desarmement_impossible("table toujours posee"),
                ),
                (
                    "temoin-negatif",
                    temoin_negatif_impossible("tcpdump non attache"),
                ),
                ("armement", armement_impossible("nft refuse le plan")),
                ("mesure", mesure_impossible("pcap absent")),
                ("copie-sonde", copie_de_sonde_impossible("disque plein")),
                (
                    "armement/sans-exemption",
                    armement_sans_exemption("regle invalide"),
                ),
                (
                    "armement/avec-exemption",
                    armement_avec_exemption("uid refuse"),
                ),
                (
                    "armement/sans-exception",
                    armement_sans_exception("plan rejete"),
                ),
                (
                    "armement/avec-exception",
                    armement_avec_exception("port refuse"),
                ),
                ("coeur/temoin", temoin_du_coeur_impossible("setpriv absent")),
                ("coeur/sortie", mesure_de_la_sortie("capture vide")),
                ("coeur/exclusion", mesure_de_l_exclusion("sonde absente")),
                ("coeur/dns", mesure_du_dns("resolveur muet")),
                (
                    "resolveur/observation",
                    observation_impossible("resolveur-borne", "capture perdue"),
                ),
                ("exit-ip/pair", pair_non_leve("port occupe")),
                ("exit-ip/compteurs-avant", compteurs_avant("wg absent")),
                ("exit-ip/compteurs-apres", compteurs_apres("wg disparu")),
                ("capture/demarrage", capture_non_demarree("tcpdump absent")),
                ("capture/arret", capture_non_arretee("paquets perdus")),
                (
                    "temoin/capture-demarrage",
                    capture_du_temoin_non_demarree("veth absent"),
                ),
                (
                    "temoin/capture-arret",
                    capture_du_temoin_non_arretee("compteurs absents"),
                ),
                ("exit-ip/chiffres", analyse_des_chiffres("filtre invalide")),
                ("exit-ip/clair", analyse_du_clair("pcap tronque")),
                ("temoin/analyse", analyse_du_temoin("pcap illisible")),
                ("pcap/analyse", analyse_du_pcap("fichier absent")),
                ("daemon-mort/armeur", armeur_non_lance("exec refuse")),
                (
                    "daemon-mort/mise-a-mort",
                    mise_a_mort_impossible("processus deja parti"),
                ),
                (
                    "daemon-mort/kill-switch-illisible",
                    kill_switch_illisible("nft sans reponse"),
                ),
                (
                    "kill-switch-on-drop/panne",
                    injection_de_panne("interface absente"),
                ),
                ("reconnect-window/dpi", injection_dpi("hook occupe")),
                (
                    "identite/illisibles",
                    regles_par_identite_illisibles("nft sans reponse"),
                ),
                (
                    "identite/divergentes",
                    regles_par_identite_divergentes(&super::super::regles_nft::Ecart {
                        manquantes: vec!["meta skuid 65533 udp dport 53 accept".to_owned()],
                        en_trop: Vec::new(),
                    }),
                ),
                // Les raisons d'echec et de reussite, entrees au catalogue (5h).
                // Une valeur de mesure representative par entree, choisie pour
                // que les phrases restent distinctes.
                ("fuite/zero-sous-kill-switch", zero_sous_kill_switch(3)),
                ("fuite/malgre-kill-switch", fuite_malgre_kill_switch(2)),
                (
                    "coeur/etrangle",
                    coeur_etrangle(super::super::probe::PROBE_V4),
                ),
                ("coeur/sortie-hors-coeur", sortie_hors_coeur(4)),
                ("coeur/dns-rouvert", dns_rouvert_par_coeur(5)),
                (
                    "coeur/exempte-sans-deborder",
                    coeur_exempte_sans_deborder(6),
                ),
                ("daemon-mort/rouvre", daemon_mort_rouvre_le_trafic()),
                ("daemon-mort/fuite-apres", fuite_apres_la_mort(7)),
                (
                    "daemon-mort/etanche",
                    etanche_apres_la_mort(
                        8,
                        "processus tue (signal 9)",
                        "tunnel wgc: handshake=true",
                        "probe all: sortie 0",
                    ),
                ),
                (
                    "reconnect/injection-perte",
                    injection_perte_totale("qdisc netem deja pose"),
                ),
                (
                    "reconnect/injection-lien",
                    injection_coupure_lien("interface veth introuvable"),
                ),
                (
                    "reconnect/rearmement",
                    rearmement_impossible("nft refuse le plan"),
                ),
                (
                    "reconnect/temoin-muet",
                    temoin_muet_reconnexion("perte-totale-netem", "probe-lan: sortie 0"),
                ),
                (
                    "reconnect/phase-sautee",
                    phase_reconnexion_sautee("coupure-lien", "capture perdue"),
                ),
                (
                    "reconnect/fuite",
                    fuite_pendant_reconnexion(4, "coupure-lien"),
                ),
                (
                    "reconnect/etanche",
                    reconnexion_etanche_par_phase(
                        "dpi-udp-51820: 4 paquet(s) temoin, 0 sous kill switch",
                    ),
                ),
                (
                    "reconnect/phase-temoin",
                    phase_temoin_puis_silence("dpi-udp-51820", 4),
                ),
                // Les trois trous fermes par 5s: chute avec temoin, tunnel
                // vivant de reconnexion, reprise pilotee par la machine.
                (
                    "kill-switch-on-drop/temoin-muet",
                    temoin_muet_chute("probe-lan: sortie 0"),
                ),
                ("kill-switch-on-drop/etanche", chute_etanche(5)),
                ("kill-switch-on-drop/fuite", fuite_apres_chute(3)),
                (
                    "reconnect/reconstruction",
                    reconstruction_tunnel_impossible("ip link add refuse"),
                ),
                (
                    "reconnect/non-vivant",
                    tunnel_de_reconnexion_non_vivant("handshake jamais vu"),
                ),
                (
                    "reprise/config",
                    config_de_banc_impossible("cle du pair invalide"),
                ),
                (
                    "reprise/pas-connectee",
                    machine_pas_connectee("reconnecting"),
                ),
                (
                    "reprise/action-inattendue",
                    action_de_reprise_inattendue("ApplyDns"),
                ),
                (
                    "reprise/executeur",
                    executeur_de_reprise_impossible("BringTunnelUp", "ip link add refuse"),
                ),
                (
                    "reprise/etanche",
                    phase_reprise_etanche(
                        4,
                        8,
                        "BringTunnelDown, ScheduleRetry, EngageKillSwitch, BringTunnelUp",
                    ),
                ),
                // Le temoin interne de la seconde sans route et le reengagement
                // effectif (5s, second passage: (i) et (ii)).
                (
                    "reprise/compteur-illisible",
                    compteur_du_kill_switch_illisible("nft sans reponse"),
                ),
                ("reprise/compteur-absent", compteur_du_kill_switch_absent()),
                (
                    "reprise/sondes-non-jetees",
                    sondes_non_jetees_seconde_sans_route(0, "probe-lan: sortie 0"),
                ),
                (
                    "reprise/reengage-sans-effet",
                    kill_switch_reengage_sans_effet("EngageKillSwitch", 8),
                ),
                (
                    "reprise/repose-absent",
                    kill_switch_repose_absent("EngageKillSwitch", "table introuvable"),
                ),
                (
                    "reprise/fuite-et-abandon",
                    fuite_et_abandon_pendant_reconnexion(
                        16,
                        "reprise-du-daemon",
                        &compteur_du_kill_switch_illisible("No such file or directory"),
                    ),
                ),
                (
                    "reprise/abandon-sans-mesure",
                    abandon_et_mesure_impossible(
                        "le compteur du kill switch etait illisible",
                        "relecture du pcap impossible: pcap tronque",
                    ),
                ),
                // Les verdicts de l'exception du resolveur chiffre (5q).
                ("resolveur/temoin-muet", resolveur_temoin_muet()),
                ("resolveur/temoin-muet-dns", resolveur_temoin_muet_dns()),
                ("resolveur/temoin-invalide", resolveur_temoin_invalide(3)),
                ("resolveur/fuite-identite", resolveur_fuite_identite(6)),
                ("resolveur/fuite-hors-port", resolveur_fuite_hors_port(4)),
                ("resolveur/exception-morte", resolveur_exception_morte()),
                ("resolveur/borne-ok", resolveur_borne_ok(5)),
            ];
            for (bin, usage) in PREREQUIS {
                tout.push(("prerequis/binaire", binaire_absent(bin, usage)));
            }
            for sonde in ["all", "dns", "ipv6"] {
                tout.push((
                    "vecteur/temoin-muet",
                    temoin_muet_sonde(sonde, super::Desarmement::RienARetirer.dit()),
                ));
            }
            tout
        }
    }

    pub fn run_all() -> CheckReport {
        if let Some(reason) = missing_prerequisite() {
            // `doh-bypass` conclut quand meme: il ne demande ni namespace ni
            // capture, seulement de lire des fichiers. Le sauter avec les
            // autres le rendrait muet la ou il avait parfaitement de quoi
            // repondre.
            let outcomes = CheckVector::ALL
                .iter()
                .map(|v| match v {
                    CheckVector::DohBypass => doh_fichiers::vecteur(),
                    autre => CheckOutcome::skipped(*autre, &reason),
                })
                .collect();
            return CheckReport::new(outcomes);
        }

        let bench = match Bench::setup() {
            Ok(b) => b,
            Err(e) => {
                return all_skipped(&motifs::banc_impossible(&e.to_string()));
            }
        };

        // Vecteurs qui ne dependent pas d'un tunnel etabli: ils mesurent le
        // kill switch seul, dans l'etat ou le daemon vient de l'armer.
        let mut outcomes = vec![
            leak_vector(
                &bench,
                CheckVector::StartupWindow,
                probe::Probe::All,
                &capture::leak_filter(),
            ),
            leak_vector(
                &bench,
                CheckVector::DnsLeak,
                probe::Probe::Dns,
                &capture::dns_filter(),
            ),
            leak_vector(
                &bench,
                CheckVector::Ipv6Leak,
                probe::Probe::Ipv6,
                &capture::ipv6_filter(),
            ),
            coeur_exemption(&bench),
            resolveur_exemption(&bench),
            doh_fichiers::vecteur(),
        ];

        // Vecteurs qui exigent un vrai tunnel entre les deux namespaces.
        match setup_tunnel(&bench) {
            Ok(cles) => {
                outcomes.push(exit_ip(&bench));
                // AVANT `kill_switch_on_drop`, et l'ordre n'est pas indifferent:
                // celui-la DETRUIT l'interface du tunnel, et `daemon-mort` a
                // besoin d'une connexion active pour mesurer ce qu'il mesure.
                outcomes.push(daemon_mort(&bench));
                outcomes.push(kill_switch_on_drop(&bench));
                // `reconnect-window` recoit les cles du banc: il reconstruit le
                // tunnel client (b) que `kill-switch-on-drop` vient de detruire,
                // et sa phase de reprise (c) le remonte. Le serveur cote phys
                // n'accepte que la cle publique du client d'origine.
                outcomes.push(reconnect_window(&bench, &cles));
            }
            Err(e) => {
                let reason = motifs::tunnel_non_etabli(&e.to_string());
                for v in [
                    CheckVector::DaemonMort,
                    CheckVector::ExitIp,
                    CheckVector::KillSwitchOnDrop,
                    CheckVector::ReconnectWindow,
                ] {
                    outcomes.push(CheckOutcome::skipped(v, &reason));
                }
            }
        }

        outcomes.sort_by_key(|o| {
            CheckVector::ALL
                .iter()
                .position(|v| *v == o.vector)
                .unwrap_or(usize::MAX)
        });
        CheckReport::new(outcomes)
    }

    /// Vrai si le processus tourne sous l'uid effectif 0 (root).
    fn est_root() -> bool {
        // SAFETY: geteuid ne prend aucun argument, ne dereference aucun
        // pointeur et ne peut pas echouer; l'appel est toujours defini.
        let euid = unsafe { libc::geteuid() };
        euid == 0
    }

    /// Verifie ce dont le harnais a besoin. Renvoie la premiere raison de sauter.
    pub(super) fn missing_prerequisite() -> Option<String> {
        if !est_root() {
            return Some(motifs::exige_root());
        }
        for (bin, usage) in motifs::PREREQUIS {
            if !binary_exists(bin) {
                return Some(motifs::binaire_absent(bin, usage));
            }
        }
        if std::env::current_exe().is_err() {
            return Some(motifs::exe_introuvable());
        }
        None
    }

    /// Cherche un executable dans le PATH, plus les repertoires systeme.
    ///
    /// On ne lance pas `<binaire> --version` pour le detecter: `ip --version`
    /// affiche l'aide et sort en erreur, ce qui ferait declarer iproute2 absent
    /// et sauter toute la suite en silence. Et le PATH d'un daemon systemd ne
    /// contient generalement pas les repertoires sbin.
    fn binary_exists(name: &str) -> bool {
        let extra = ["/usr/sbin", "/sbin", "/usr/bin", "/bin", "/usr/local/bin"];
        let from_path = std::env::var_os("PATH")
            .map(|paths| std::env::split_paths(&paths).any(|dir| dir.join(name).is_file()))
            .unwrap_or(false);
        from_path || extra.iter().any(|dir| Path::new(dir).join(name).is_file())
    }

    fn self_exe() -> String {
        std::env::current_exe()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| "bifrost-daemon".to_owned())
    }

    fn bench_policy(with_tunnel: bool, exemptions: Exemptions) -> FirewallPolicy {
        FirewallPolicy {
            tunnel_interface: with_tunnel.then(|| WG_CLIENT_IF.to_owned()),
            tunnel_luid: None,
            fwmark: Some(BENCH_FWMARK),
            dns_resolver: IpAddr::V4(Ipv4Addr::LOCALHOST),
            allow_lan: false,
            coeur_uid: exemptions.coeur,
            // Sous Linux le ruleset designe le coeur par son UID; le chemin de
            // l'executable ne sert qu'a WFP.
            coeur_executable: None,
            resolveur_uid: exemptions.resolveur,
            resolveur_executable: None,
            // Le compte de service Windows ne joue aucun role dans ce banc
            // Linux, qui restreint le :53 par l'UID: `None` conserve
            // `Identity::Current` la ou WFP le lirait.
            resolveur_sid: None,
            // Le drapeau vient du PROFIL, l'uid de l'EXPLOITATION, et il en
            // faut deux: `Identite::restreindre` efface l'uid quand le profil
            // ne demande pas de resolveur embarque. Un banc qui declarerait le
            // compte sans le drapeau armerait un plan que le produit ne pose
            // jamais, et sa mesure ne porterait sur rien.
            resolveur_embarque: exemptions.resolveur.is_some(),
        }
    }

    /// Le ruleset du DPI de `reconnect-window`: hook input cote phys, drop de
    /// l'UDP de WireGuard, le reste du lien passe. Isole ici pour que
    /// [`rulesets_du_banc`] le pose sans le recopier. La chaine se nomme
    /// `entree` et jamais `fwd` (mot reserve de nft): c'est la faute d'avant,
    /// avalee faute de lire le statut, que la recette d'acceptation garde.
    fn dpi_ruleset(port: u16) -> String {
        format!(
            "table inet dpi {{\n\
             \tchain entree {{\n\
             \t\ttype filter hook input priority filter; policy accept;\n\
             \t\tudp dport {port} drop\n\
             \t}}\n}}\n"
        )
    }

    /// Le retrait du ruleset [`dpi_ruleset`], qu'il existe ou non.
    fn dpi_teardown() -> String {
        "table inet dpi {}\ndelete table inet dpi\n".to_owned()
    }

    /// Tous les rulesets nftables que le banc POSE par entree standard, nommes.
    ///
    /// # Pourquoi une liste, et ce qu'elle garde (5t)
    ///
    /// Chaque entree est un `(nom, namespace, script)` que le banc envoie a nft
    /// par [`Bench::poser_nft`] ou [`Bench::retirer_nft`]. La recette
    /// `chaque_ruleset_du_banc_est_accepte_par_nft` pose chacun dans un espace
    /// de noms jetable sous root et exige que nft l'accepte; la garde
    /// `chaque_injection_du_banc_a_son_ruleset_dans_la_liste` compte les sites
    /// d'injection de la source et exige qu'ils soient aussi nombreux que cette
    /// liste. Un ruleset ajoute plus tard est donc soit ajoute ici (couvert),
    /// soit revele par un ecart de compte (rouge).
    ///
    /// L'entree du kill switch prend la politique la plus riche (tunnel, coeur
    /// ET resolveur): son rendu porte alors toutes les formes de regle - marque,
    /// skuid, ensembles ICMPv6 et LAN - donc son acceptation par nft couvre le
    /// plus. Les variantes plus pauvres que le banc pose (sans exemption, sans
    /// tunnel) n'en sont qu'un sous-ensemble syntaxique.
    ///
    /// Uniquement exercee par les recettes (acceptation par nft, compte des
    /// sites d'injection), d'ou `#[cfg(test)]`.
    #[cfg(test)]
    fn rulesets_du_banc() -> Vec<(&'static str, &'static str, String)> {
        let politique_riche = bench_policy(
            true,
            Exemptions {
                coeur: Some(977),
                resolveur: Some(981),
            },
        );
        vec![
            ("kill-switch", NS_CLIENT, ruleset::render(&politique_riche)),
            (
                "kill-switch-teardown",
                NS_CLIENT,
                ruleset::render_teardown(),
            ),
            (
                "banniere",
                NS_PHYS,
                transport::nft_banniere(WG_SERVER_IF, BANNIERE_PORT),
            ),
            ("dpi", NS_PHYS, dpi_ruleset(WG_PORT)),
            (
                "banniere-teardown",
                NS_PHYS,
                transport::nft_banniere_teardown(),
            ),
            ("dpi-teardown", NS_PHYS, dpi_teardown()),
        ]
    }

    fn arm(bench: &Bench, with_tunnel: bool, exemptions: Exemptions) -> bifrost_core::Result<()> {
        let script = ruleset::render(&bench_policy(with_tunnel, exemptions));
        bench.poser_nft(NS_CLIENT, &script)
    }

    /// Ce qu'un desarmement a REELLEMENT fait.
    ///
    /// Cette fonction rendait `Ok(())` quoi qu'il arrive, en ignorant a la fois
    /// l'echec de lancement et le code de sortie de `nft`. Un retrait rate
    /// etait donc indiscernable d'un retrait reussi, alors que c'est le premier
    /// suspect quand un temoin negatif est muet: sans filtres la sonde DOIT
    /// fuir, et un kill switch reste pose produit exactement le silence qu'on
    /// attribuerait alors a la sonde.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Desarmement {
        /// Aucune table du kill switch n'etait posee: l'objectif etait deja
        /// atteint avant la commande.
        RienARetirer,
        /// La table etait posee, et elle ne l'est plus.
        Retire,
    }

    impl Desarmement {
        fn dit(self) -> &'static str {
            match self {
                Self::RienARetirer => "aucune table du kill switch n'etait posee",
                Self::Retire => "la table du kill switch a ete retiree",
            }
        }
    }

    /// La table du kill switch est-elle nommee, ENTIERE, dans une sortie
    /// `nft list tables`?
    ///
    /// # Une presence se reconnait par la ligne entiere (5t, regle 5u-a)
    ///
    /// La version d'avant testait `l.contains(ruleset::TABLE)`, soit la
    /// sous-chaine `bifrost`: une table `inet bifrost2` ou `inet bifrost-old`
    /// la satisfaisait, et le kill switch se declarait pose alors qu'aucune
    /// table de CE nom ne l'etait. `nft list tables` rend une table par ligne,
    /// `table inet bifrost` (mesure du 05/09/2026 sur essai-linux), donc la
    /// ligne entiere est la bonne unite. La reconnaissance passe par
    /// [`regles_nft::porte`], qui normalise les deux cotes et compare mot pour
    /// mot: `table inet bifrost2` n'est pas `table inet bifrost`.
    ///
    /// Pur, donc gardable sans banc: la piege
    /// `la_table_du_kill_switch_se_reconnait_par_la_ligne_entiere` l'exerce sur
    /// une sortie fabriquee, rouge sur la reconnaissance par sous-chaine.
    fn table_du_kill_switch_dans(sortie: &str) -> bool {
        regles_nft::porte(sortie, &format!("table inet {}", ruleset::TABLE))
    }

    /// La table du kill switch est-elle posee dans le namespace du client, ou
    /// bien l'ignore-t-on?
    ///
    /// Trois etats et non deux. La version d'avant, `kill_switch_pose`, rendait
    /// `false` aussi bien quand la table etait absente que quand le listage
    /// avait echoue, et ses trois appelants en tiraient trois conclusions
    /// fausses: un desarmement qui se declarait reussi sans avoir rien vu, un
    /// armeur accuse d'un silence qui n'etait pas le sien, et un verdict
    /// `FAILED` << les filtres ont disparu >> rendu sur un `nft` muet.
    ///
    /// La reconnaissance du nom, elle, passe par [`table_du_kill_switch_dans`]:
    /// la ligne entiere, jamais la sous-chaine.
    fn table_du_kill_switch_posee(bench: &Bench) -> bifrost_core::Result<bool> {
        let sortie = sortie_de(bench, NS_CLIENT, &["nft", "list", "tables"])?;
        Ok(table_du_kill_switch_dans(&sortie.join("\n")))
    }

    /// Retire le kill switch du banc, et DIT ce qui s'est passe.
    ///
    /// # Pourquoi le code de sortie de `nft` ne suffit pas
    ///
    /// `ruleset::render_teardown()` declare la table vide AVANT de la
    /// supprimer, precisement pour que la suppression aboutisse quand elle
    /// n'existait pas. `nft` rend donc zero dans les deux cas, et il ne peut
    /// pas separer << rien a retirer >> de << retire >>. Mesure du 23/08/2026
    /// sur la machine d'essai, dans un espace de noms vide puis avec la table
    /// posee: code 0 et erreur standard vide les deux fois.
    ///
    /// La difference se MESURE donc, en listant les tables avant et apres, et
    /// pas en interpretant un code de sortie. Ce qui reste au code de sortie
    /// est le seul cas qu'il sait vraiment dire: le script a ete REFUSE.
    ///
    /// # Ce que la relecture d'apres attrape
    ///
    /// Un `nft` qui rend zero sans avoir rien retire - script applique dans le
    /// mauvais espace de noms, table homonyme ailleurs - laisserait le banc
    /// arme en annoncant l'inverse. C'est l'effet qui est relu, pas la
    /// commande. La garde de source `disarm_relit_l_effet_du_retrait` exige que
    /// cette relecture reste APRES le retrait, dans le corps de `disarm`.
    fn disarm(bench: &Bench) -> bifrost_core::Result<Desarmement> {
        let pose_avant = table_du_kill_switch_posee(bench)?;
        // Le retrait est une pose dont l'acceptation par nft compte: un script
        // refuse laisserait le banc arme. Il passe donc par `poser_nft` (statut
        // lu), pas par le retrait best effort, et l'effet est relu ensuite.
        bench.poser_nft(NS_CLIENT, &ruleset::render_teardown())?;
        if table_du_kill_switch_posee(bench)? {
            return Err(bifrost_core::Error::Firewall(format!(
                "retrait accepte par nft, sans effet: la table '{}' est toujours posee dans \
                 {NS_CLIENT}",
                ruleset::TABLE
            )));
        }
        Ok(if pose_avant {
            Desarmement::Retire
        } else {
            Desarmement::RienARetirer
        })
    }

    /// Emet une sonde depuis le namespace client pendant une capture.
    fn observe(
        bench: &Bench,
        tag: &str,
        p: probe::Probe,
        filter: &str,
    ) -> bifrost_core::Result<capture::Releve> {
        observe_sous(bench, tag, p, filter, None)
    }

    /// Copie du binaire atteignable par un compte non privilegie.
    ///
    /// Le daemon vit ou il a ete compile, souvent sous un `$HOME` en 0750 que
    /// `nobody` ne peut meme pas traverser. `setpriv` echouerait alors avant
    /// d'emettre quoi que ce soit, et la mesure lirait zero paquet: exactement
    /// ce que produirait un kill switch qui fonctionne. Deux causes opposees,
    /// une seule observation. On supprime l'ambiguite a la source.
    struct SondeAccessible(std::path::PathBuf);

    impl SondeAccessible {
        fn nouvelle() -> std::io::Result<Self> {
            use std::os::unix::fs::PermissionsExt;
            let cible = std::env::temp_dir().join("bifrost-check-probe");
            let _ = std::fs::remove_file(&cible);
            std::fs::copy(self_exe(), &cible)?;
            std::fs::set_permissions(&cible, std::fs::Permissions::from_mode(0o755))?;
            Ok(Self(cible))
        }

        fn chemin(&self) -> String {
            self.0.to_string_lossy().into_owned()
        }
    }

    impl Drop for SondeAccessible {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    /// La meme chose, sous une identite donnee.
    ///
    /// `setpriv` plutot qu'un drapeau du daemon qui baisserait son propre UID:
    /// la sonde doit etre emise par un processus dont l'identite est etablie
    /// AVANT qu'il n'ouvre le moindre socket. Un processus qui baisse son UID
    /// en cours de route pourrait avoir deja ouvert le socket sous l'ancien, et
    /// `meta skuid` lit le proprietaire du socket, pas celui du processus.
    fn observe_sous(
        bench: &Bench,
        tag: &str,
        p: probe::Probe,
        filter: &str,
        uid: Option<(u32, &str)>,
    ) -> bifrost_core::Result<capture::Releve> {
        Ok(observer(bench, tag, p, filter, uid)?.paquets)
    }

    /// Ce qu'une observation a produit, et comment la sonde s'est terminee.
    struct Observation {
        /// Le COMPTE et les preuves, separes. La longueur de la liste de
        /// preuves n'est pas un compte: elle est plafonnee.
        paquets: capture::Releve,
        /// Etat de sortie de la sonde. Un pcap vide a deux causes possibles:
        /// le trafic a ete bloque, ou la sonde n'a jamais tourne. Jeter cette
        /// information, c'est rendre les deux indiscernables.
        sonde: String,
    }

    fn observer(
        bench: &Bench,
        tag: &str,
        p: probe::Probe,
        filter: &str,
        uid: Option<(u32, &str)>,
    ) -> bifrost_core::Result<Observation> {
        let exe = match uid {
            Some((_, chemin)) => chemin.to_owned(),
            None => self_exe(),
        };
        let cap = capture::Capture::start(bench, NS_PHYS, tag)?;
        let (reuid, regid);
        let argv: Vec<&str> = match uid {
            Some((u, _)) => {
                reuid = format!("--reuid={u}");
                regid = format!("--regid={u}");
                vec![
                    "setpriv",
                    &reuid,
                    &regid,
                    "--clear-groups",
                    &exe,
                    "--probe",
                    p.as_str(),
                ]
            }
            None => vec![&exe, "--probe", p.as_str()],
        };
        let sonde = match bench.exec(NS_CLIENT, &argv) {
            Ok(out) if out.status.success() && out.stderr.is_empty() => "sortie 0".to_owned(),
            Ok(out) => format!(
                "sortie {}: {}",
                out.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&out.stderr).trim()
            ),
            Err(e) => format!("lancement impossible: {e}"),
        };
        let (pcap, compte_rendu) = cap.stop_bavard()?;
        Ok(Observation {
            paquets: capture::relever(pcap.chemin(), filter)?,
            sonde: format!("{sonde}; tcpdump: {compte_rendu}"),
        })
    }

    /// Le patron commun: temoin negatif, puis mesure sous kill switch.
    fn leak_vector(
        bench: &Bench,
        vector: CheckVector,
        p: probe::Probe,
        filter: &str,
    ) -> CheckOutcome {
        // 1. Sans kill switch: la sonde doit fuir, sinon le test ne prouve rien.
        let desarme = match disarm(bench) {
            Ok(d) => d,
            Err(e) => {
                return CheckOutcome::skipped(
                    vector,
                    motifs::desarmement_impossible(&e.to_string()),
                );
            }
        };
        let baseline = match observe(bench, &format!("{}-baseline", vector.id()), p, filter) {
            Ok(v) => v,
            Err(e) => {
                return CheckOutcome::skipped(
                    vector,
                    motifs::temoin_negatif_impossible(&e.to_string()),
                );
            }
        };
        if baseline.compte == 0 {
            return CheckOutcome::skipped(
                vector,
                motifs::temoin_muet_sonde(p.as_str(), desarme.dit()),
            );
        }

        // 2. Avec kill switch: plus rien ne doit sortir.
        if let Err(e) = arm(bench, false, Exemptions::AUCUNE) {
            return CheckOutcome::skipped(vector, motifs::armement_impossible(&e.to_string()));
        }
        let guarded = match observe(bench, &format!("{}-guarded", vector.id()), p, filter) {
            Ok(v) => v,
            Err(e) => {
                return CheckOutcome::skipped(vector, motifs::mesure_impossible(&e.to_string()));
            }
        };

        if guarded.compte == 0 {
            CheckOutcome::passed(vector, motifs::zero_sous_kill_switch(baseline.compte))
        } else {
            CheckOutcome::failed(
                vector,
                motifs::fuite_malgre_kill_switch(guarded.compte),
                guarded.preuves_dites(),
            )
        }
    }

    /// La chaine `output` telle que le noyau la voit, avec ses compteurs.
    ///
    /// Une preuve d'echec doit montrer ce que le systeme applique, pas ce que le
    /// generateur croit avoir produit: quand les deux divergent, c'est
    /// precisement la divergence qu'il faut lire.
    fn chaine_vivante(bench: &Bench) -> bifrost_core::Result<Vec<String>> {
        sortie_de(
            bench,
            NS_CLIENT,
            &["nft", "list", "chain", "inet", ruleset::TABLE, "output"],
        )
    }

    /// Le compteur `bifrost-output-dropped` lu dans une sortie de
    /// `nft list chain`, sous la forme vivante `counter packets N bytes M`.
    ///
    /// Rend `(paquets, octets)`. `None` si la ligne du compteur est absente - la
    /// table retiree, par exemple - ou si sa forme n'est pas celle mesuree par
    /// 5m et gardee par [`regles_nft`]. Pur: du texte entre, un couple sort, et
    /// sa recette `le_compteur_de_sortie_jetee_se_lit_dans_le_rendu_de_nft`
    /// l'eprouve sur une sortie fabriquee, sans root.
    fn compteur_sortie_jetee(lignes: &[String]) -> Option<(u64, u64)> {
        const COMMENTAIRE: &str = "bifrost-output-dropped";
        lignes.iter().find_map(|ligne| {
            if !ligne.contains(COMMENTAIRE) {
                return None;
            }
            let mots: Vec<&str> = ligne.split_whitespace().collect();
            let i = mots.iter().position(|m| *m == "counter")?;
            if mots.get(i + 1) != Some(&"packets") || mots.get(i + 3) != Some(&"bytes") {
                return None;
            }
            let paquets = mots.get(i + 2)?.parse::<u64>().ok()?;
            let octets = mots.get(i + 4)?.parse::<u64>().ok()?;
            Some((paquets, octets))
        })
    }

    /// Lit le compteur de paquets jetes du kill switch dans NS_CLIENT.
    ///
    /// La derniere regle de la chaine `output` compte, avant la policy `drop`,
    /// les paquets de sortie qu'elle jette. Ce compteur est le temoin INTERNE de
    /// la seconde sans route (5s, i): les sondes de `sonder_sans_route` s'y
    /// impriment quand le kill switch tient, et `arm` le remet a zero en
    /// recreant la table.
    fn compteur_du_kill_switch(bench: &Bench) -> Result<(u64, u64), String> {
        let lignes = chaine_vivante(bench)
            .map_err(|e| motifs::compteur_du_kill_switch_illisible(&e.to_string()))?;
        compteur_sortie_jetee(&lignes).ok_or_else(motifs::compteur_du_kill_switch_absent)
    }

    /// (ii) `EngageKillSwitch` a-t-il REELLEMENT repose le kill switch ?
    ///
    /// Le banc etant deja arme quand l'action arrive, la seule presence de la
    /// table ne prouverait rien: un executeur inerte y passerait. La mesure
    /// honnete est le COMPTEUR - `arm` recree la table, donc remet a zero le
    /// compteur que la seconde sans route a laisse strictement positif. Le
    /// reengagement n'a eu d'effet que si le compteur est revenu a zero; s'il ne
    /// l'est pas, ou si la table a disparu, l'action est restee inerte et on la
    /// nomme.
    fn kill_switch_repose_avec_effet(bench: &Bench, action: &str) -> Result<(), String> {
        match compteur_du_kill_switch(bench) {
            Ok((0, _)) => Ok(()),
            Ok((paquets, _)) => Err(motifs::kill_switch_reengage_sans_effet(action, paquets)),
            Err(cause) => Err(motifs::kill_switch_repose_absent(action, &cause)),
        }
    }

    /// La chaine pour une PREUVE, ou la raison de ne pas l'avoir.
    ///
    /// Une preuve n'a pas le droit de faire echouer un verdict deja etabli.
    /// Elle n'a pas le droit non plus de se faire passer pour la chaine quand
    /// le listage a echoue: c'est ce que faisait l'ancien `sortie_de`, qui
    /// rendait la PLAINTE comme s'il s'agissait d'une ligne de regle. Un
    /// lecteur comptait alors une ligne qui n'en etait pas une.
    fn chaine_pour_preuve(bench: &Bench) -> Vec<String> {
        match chaine_vivante(bench) {
            Ok(lignes) => lignes,
            Err(e) => vec![motifs::chaine_illisible(&e.to_string())],
        }
    }

    /// La table entiere telle que le noyau la tient.
    ///
    /// La table et non la seule chaine `output`: les regles par identite y
    /// vivent aujourd'hui, mais la confrontation ne doit pas le presupposer,
    /// sinon une regle deplacee dans une autre chaine serait dite absente.
    fn table_vivante(bench: &Bench) -> bifrost_core::Result<Vec<String>> {
        sortie_de(
            bench,
            NS_CLIENT,
            &["nft", "list", "table", "inet", ruleset::TABLE],
        )
    }

    /// Les regles par identite que le noyau tient sont celles que le
    /// generateur a emises pour ce plan, ni plus ni moins; sinon le verdict
    /// qui le dit, en nommant chaque regle entiere (5m).
    ///
    /// # Pourquoi `arm` ne suffit pas
    ///
    /// `arm` lit le code de sortie de nft, et nft accepte un plan sans dire ce
    /// qu'il en a garde. Une regle `meta skuid` acceptee et non posee se
    /// lirait plus bas comme un compte qui ne sort pas: un silence de plus,
    /// impute a l'identite. La confrontation se fait sur la forme que nft
    /// REND, relue dans le noyau, et non sur la chaine envoyee; c'est
    /// [`regles_nft`] qui la reconnait, mot pour mot, apres normalisation
    /// des deux cotes. La preuve est le listage meme sur lequel le verdict a
    /// ete rendu.
    ///
    /// Une relecture impossible est une abstention: le vecteur ne sait pas ce
    /// qui est pose. Un ecart est un echec: nft a dit oui a un plan que le
    /// noyau n'applique pas, et c'est un fail-open qui ne s'annonce pas.
    fn regles_par_identite_conformes(
        bench: &Bench,
        v: CheckVector,
        with_tunnel: bool,
        exemptions: Exemptions,
    ) -> Result<(), CheckOutcome> {
        let lu = table_vivante(bench).map_err(|e| {
            CheckOutcome::skipped(v, motifs::regles_par_identite_illisibles(&e.to_string()))
        })?;
        let emis = ruleset::render(&bench_policy(with_tunnel, exemptions));
        let ecart = regles_nft::ecart_skuid(&emis, &lu.join("\n"));
        if ecart.est_vide() {
            return Ok(());
        }
        Err(CheckOutcome::failed(
            v,
            motifs::regles_par_identite_divergentes(&ecart),
            lu,
        ))
    }

    /// Les lignes non vides produites par une commande dans un namespace.
    ///
    /// # Une erreur d'instrument est une ERREUR
    ///
    /// Cette fonction rendait la plainte comme une ligne de sortie, donc un
    /// listage qui avait echoue se lisait comme un listage qui avait reussi et
    /// trouve une ligne. Trois lectures fausses en decoulaient: la table du
    /// kill switch declaree ABSENTE alors qu'on l'ignorait, une chaine declaree
    /// PRESENTE alors que c'etait la plainte qu'on comptait, et - le plus cher -
    /// un verdict FAILED << les filtres ont disparu >> rendu sur un `nft` qui
    /// n'avait simplement pas repondu.
    fn sortie_de(bench: &Bench, ns: &str, argv: &[&str]) -> bifrost_core::Result<Vec<String>> {
        let out = bench.exec(ns, argv)?;
        if !out.status.success() {
            return Err(bifrost_core::Error::Firewall(format!(
                "'{}' a echoue dans {ns} (code {}): {}",
                argv.join(" "),
                out.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        Ok(String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(|l| l.trim().to_owned())
            .filter(|l| !l.is_empty())
            .collect())
    }

    /// Verifie qu'une identite donnee emet bien, kill switch retire.
    ///
    /// Rend les paquets observes quand elle le fait, et la raison de s'abstenir
    /// quand elle ne le fait pas. Le silence a plusieurs causes possibles et le
    /// message les separe: une sonde qui n'a pas tourne, un desarmement qui a
    /// echoue, ou un compte qui ne peut reellement pas sortir.
    ///
    /// Les paquets ne sont pas jetes une fois le temoin etabli: le vecteur du
    /// resolveur les compte dans ses mesures, et un compte porte plus qu'un
    /// booleen quand il faut relire un rapport sans avoir la machine.
    fn temoin_vivant(
        bench: &Bench,
        v: CheckVector,
        qui: &str,
        tag: &str,
        p: probe::Probe,
        filtre: &str,
        identite: Option<(u32, &str)>,
    ) -> Result<capture::Releve, CheckOutcome> {
        match observer(bench, tag, p, filtre, identite) {
            Err(e) => Err(CheckOutcome::skipped(
                v,
                motifs::temoin_negatif_impossible(&e.to_string()),
            )),
            Ok(o) if o.paquets.compte == 0 => {
                let chaine =
                    motifs::EtatChaine::depuis(chaine_vivante(bench).map_err(|e| e.to_string()));
                Err(CheckOutcome::skipped(
                    v,
                    motifs::temoin_muet_identite(qui, &o.sonde, &chaine),
                ))
            }
            Ok(o) => Ok(o.paquets),
        }
    }

    /// L'exemption du coeur laisse sortir le coeur, et RIEN d'autre.
    ///
    /// Qu'une regle laisse passer quelque chose se verifie en la lisant. Qu'elle
    /// ne laisse passer QUE cela ne se verifie que par une mesure, et c'est la
    /// seule des deux moities qui distingue une exemption etroite d'un trou.
    ///
    /// Cinq observations, dont aucune n'est redondante:
    ///
    /// 0. Sans kill switch, le coeur sort. C'est le temoin negatif du module:
    ///    une sonde muette produirait zero paquet partout, et zero paquet est
    ///    aussi ce que produit un blocage. Sans cette observation, une sonde qui
    ///    n'a jamais demarre serait lue comme un kill switch qui fonctionne.
    /// 1. Kill switch arme sans exemption, le coeur ne sort plus. Sur un banc ou
    ///    le kill switch ne s'appliquerait pas, les trois observations suivantes
    ///    donneraient le meme resultat qu'une exemption qui fonctionne.
    /// 2. Avec exemption, le coeur sort. Sinon l'exemption ne sert a rien et le
    ///    kill switch etrangle le composant qui porte le trafic.
    /// 3. Avec exemption, root ne sort toujours pas. C'est la largeur du trou:
    ///    on prend l'identite la plus privilegiee de la machine, celle qui
    ///    passerait en premier si l'exemption etait en realite globale.
    /// 4. Avec exemption, le :53 du coeur ne sort pas non plus. Les permits DNS
    ///    sont poses plus haut dans la chaine, donc un `skuid` nu placerait le
    ///    coeur AU-DESSUS de la restriction et rouvrirait la fuite DNS que tout
    ///    le reste du ruleset interdit.
    ///
    /// La sonde IPv4 plutot que `all` pour les quatre premieres: `all` emet
    /// aussi du DNS, que l'observation 4 attend precisement bloque. Les melanger
    /// rendrait un resultat non vide impossible a attribuer.
    ///
    /// Apres chaque armement, la table est RELUE dans le noyau et ses regles
    /// par identite confrontees a celles emises, entieres et mot pour mot:
    /// un plan accepte par nft dont la regle `meta skuid` n'aurait pas
    /// atteint le noyau se lirait sinon, en 2, comme un coeur etrangle, et
    /// en 1, comme un kill switch qui bloque. Voir
    /// [`regles_par_identite_conformes`].
    fn coeur_exemption(bench: &Bench) -> CheckOutcome {
        let v = CheckVector::CoeurExemption;
        if !binary_exists("setpriv") {
            return CheckOutcome::skipped(v, motifs::setpriv_absent_exemption());
        }
        let filtre = format!("host {}", probe::PROBE_V4);

        // 0. Temoin negatif, en deux temps. Le banc est-il vivant, et ce
        //    compte-la peut-il emettre? Les mesurer dans cet ordre evite
        //    d'attribuer a l'identite un silence qui viendrait du banc.
        if let Err(e) = disarm(bench) {
            return CheckOutcome::skipped(v, motifs::desarmement_impossible(&e.to_string()));
        }

        if let Err(raison) = temoin_vivant(
            bench,
            v,
            "root",
            "coeur-vivant-root",
            probe::Probe::Ipv4,
            &filtre,
            None,
        ) {
            return raison;
        }

        // La copie de la sonde n'est faite qu'ici, apres le premier temoin: sur
        // une machine de recette c'est un binaire de debogage de plusieurs
        // centaines de mega-octets, et l'ecriture qui suivait immediatement le
        // demarrage de tcpdump lui faisait manquer ses premiers paquets.
        let sonde = match SondeAccessible::nouvelle() {
            Ok(s) => s,
            Err(e) => {
                return CheckOutcome::skipped(v, motifs::copie_de_sonde_impossible(&e.to_string()));
            }
        };
        let chemin = sonde.chemin();
        let coeur = Some((COEUR_UID, chemin.as_str()));

        if let Err(raison) = temoin_vivant(
            bench,
            v,
            "le coeur",
            "coeur-vivant-uid",
            probe::Probe::Ipv4,
            &filtre,
            coeur,
        ) {
            return raison;
        }

        // 1. Le kill switch seul bloque bien ce compte.
        if let Err(e) = arm(bench, false, Exemptions::AUCUNE) {
            return CheckOutcome::skipped(v, motifs::armement_sans_exemption(&e.to_string()));
        }
        if let Err(verdict) = regles_par_identite_conformes(bench, v, false, Exemptions::AUCUNE) {
            return verdict;
        }
        match observe_sous(bench, "coeur-temoin", probe::Probe::Ipv4, &filtre, coeur) {
            Err(e) => {
                return CheckOutcome::skipped(
                    v,
                    motifs::temoin_du_coeur_impossible(&e.to_string()),
                );
            }
            Ok(paquets) if paquets.compte > 0 => {
                return CheckOutcome::skipped(v, motifs::temoin_invalide_coeur(paquets.compte));
            }
            Ok(_) => {}
        }

        // 2. Le coeur sort.
        if let Err(e) = arm(bench, false, Exemptions::coeur(COEUR_UID)) {
            return CheckOutcome::skipped(v, motifs::armement_avec_exemption(&e.to_string()));
        }
        if let Err(verdict) =
            regles_par_identite_conformes(bench, v, false, Exemptions::coeur(COEUR_UID))
        {
            return verdict;
        }
        let sortie = match observe_sous(bench, "coeur-sortie", probe::Probe::Ipv4, &filtre, coeur) {
            Ok(p) => p,
            Err(e) => return CheckOutcome::skipped(v, motifs::mesure_de_la_sortie(&e.to_string())),
        };
        if sortie.compte == 0 {
            return CheckOutcome::failed(
                v,
                motifs::coeur_etrangle(probe::PROBE_V4),
                chaine_pour_preuve(bench),
            );
        }

        // 3. Personne d'autre ne sort.
        let autre = match observe_sous(bench, "coeur-autrui", probe::Probe::Ipv4, &filtre, None) {
            Ok(p) => p,
            Err(e) => {
                return CheckOutcome::skipped(v, motifs::mesure_de_l_exclusion(&e.to_string()));
            }
        };
        if autre.compte > 0 {
            return CheckOutcome::failed(
                v,
                motifs::sortie_hors_coeur(autre.compte),
                autre.preuves_dites(),
            );
        }

        // 4. Le coeur ne rouvre pas le DNS.
        let dns = match observe_sous(
            bench,
            "coeur-dns",
            probe::Probe::Dns,
            &capture::dns_filter(),
            coeur,
        ) {
            Ok(p) => p,
            Err(e) => return CheckOutcome::skipped(v, motifs::mesure_du_dns(&e.to_string())),
        };
        if dns.compte > 0 {
            return CheckOutcome::failed(
                v,
                motifs::dns_rouvert_par_coeur(dns.compte),
                dns.preuves_dites(),
            );
        }

        CheckOutcome::passed(v, motifs::coeur_exempte_sans_deborder(sortie.compte))
    }

    /// Les six observations du vecteur `resolveur-exemption`, en nombre de
    /// paquets vus sur le lien physique.
    ///
    /// Les separer de la conclusion permet d'eprouver le raisonnement sans
    /// root, sans banc et sans machine, exactement comme le pendant Windows le
    /// fait de ses cinq mesures. C'est la que se discute ce qui compte comme
    /// une exception correctement bornee, et c'est la seule partie du vecteur
    /// qu'une recette ordinaire peut falsifier.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct MesuresResolveur {
        /// Kill switch retire, sous l'identite du resolveur, vers la
        /// destination ordinaire.
        repos: usize,
        /// Kill switch retire, sous l'identite du resolveur, vers le :53
        /// externe.
        repos_dns: usize,
        /// Arme SANS aucune exception, sous l'identite du resolveur, vers le
        /// :53 externe.
        temoin: usize,
        /// Arme AVEC l'exception, sous l'identite du resolveur, vers le :53
        /// externe. C'est l'exception elle-meme.
        resolveur_dns: usize,
        /// Arme AVEC l'exception, sous l'identite du resolveur, vers la
        /// destination ordinaire. C'est la BORNE.
        resolveur_hors_53: usize,
        /// Arme AVEC l'exception, sous root, vers le :53 externe.
        etranger: usize,
    }

    /// Ce que la mesure a conclu. Jamais un succes par defaut.
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum IssueResolveur {
        Reussi(String),
        Ignore(String),
        Echec(String),
    }

    /// L'exception du resolveur chiffre ouvre le :53, et RIEN d'autre.
    ///
    /// Le miroir de [`coeur_exemption`], et son exact contraire. Le coeur EST
    /// le transport: sa sortie est large, et seul son :53 lui est refuse, sans
    /// quoi il deviendrait le contournement du blocage DNS. Le resolveur
    /// chiffre est l'inverse: son exception passe AU-DESSUS du blocage, parce
    /// que sans elle il ne peut pas resoudre le nom de son propre serveur
    /// chiffre et ne demarre jamais - mais il ne doit sortir QUE sur le :53.
    /// Large, elle en ferait un second transport, c'est-a-dire une sortie en
    /// clair hors tunnel accordee au composant qui existe pour qu'il n'y en ait
    /// plus.
    ///
    /// Sous Linux l'exception designe un UID, la ou WFP designe un CHEMIN: la
    /// propriete mesuree est la meme, les moyens de la mesurer non. Le temoin
    /// de discrimination est donc root, l'identite la plus privilegiee de la
    /// machine, celle qui passerait en premier si l'exception etait globale -
    /// et non une copie du binaire posee ailleurs, qui ne dirait rien ici.
    fn resolveur_exemption(bench: &Bench) -> CheckOutcome {
        let v = CheckVector::ResolveurExemption;
        match mesurer_resolveur(bench, v) {
            // Une abstention, ou l'echec d'un plan accepte par nft dont le
            // noyau ne tient pas les regles par identite: dans les deux cas
            // les six observations n'ont pas eu lieu et le verdict est deja
            // rendu.
            Err(verdict_anticipe) => verdict_anticipe,
            Ok((mesures, fuites)) => match juger_resolveur(mesures) {
                IssueResolveur::Reussi(detail) => CheckOutcome::passed(v, detail),
                IssueResolveur::Ignore(raison) => CheckOutcome::skipped(v, raison),
                IssueResolveur::Echec(raison) => {
                    // La preuve d'une fuite, ce sont les paquets eux-memes.
                    // Quand il n'y en a aucun, l'echec est une exception morte
                    // et la preuve devient la chaine que le NOYAU applique, pas
                    // celle que le generateur croit avoir ecrite: quand les
                    // deux divergent, c'est la divergence qu'il faut lire.
                    let preuves = if fuites.is_empty() {
                        chaine_pour_preuve(bench)
                    } else {
                        fuites
                    };
                    CheckOutcome::failed(v, raison, preuves)
                }
            },
        }
    }

    /// Enchaine les six observations, ou rend le verdict anticipe: la raison
    /// de s'abstenir, ou l'echec d'une regle par identite que le noyau ne
    /// tient pas alors que nft a accepte le plan.
    ///
    /// Rend aussi les paquets des deux observations qui attendent un silence:
    /// ce sont les preuves d'une fuite, et un verdict d'echec sans elles serait
    /// inexploitable sans avoir la machine sous la main.
    fn mesurer_resolveur(
        bench: &Bench,
        v: CheckVector,
    ) -> Result<(MesuresResolveur, Vec<String>), CheckOutcome> {
        if !binary_exists("setpriv") {
            return Err(CheckOutcome::skipped(v, motifs::setpriv_absent_exception()));
        }
        let ordinaire = format!("host {}", probe::PROBE_V4);
        let dns = capture::dns_filter();

        // 0. Temoins negatifs. Le banc est-il vivant, et ce compte-la peut-il
        //    emettre, sur le :53 comme ailleurs? Sans ces deux-la, les silences
        //    sous armement ne seraient imputables a rien.
        disarm(bench).map_err(|e| {
            CheckOutcome::skipped(v, motifs::desarmement_impossible(&e.to_string()))
        })?;

        let sonde = SondeAccessible::nouvelle().map_err(|e| {
            CheckOutcome::skipped(v, motifs::copie_de_sonde_impossible(&e.to_string()))
        })?;
        let chemin = sonde.chemin();
        let resolveur = Some((RESOLVEUR_UID, chemin.as_str()));

        let repos = temoin_vivant(
            bench,
            v,
            "le resolveur",
            "resolveur-vivant",
            probe::Probe::Ipv4,
            &ordinaire,
            resolveur,
        )?;
        let repos_dns = temoin_vivant(
            bench,
            v,
            "le resolveur, vers le :53",
            "resolveur-vivant-dns",
            probe::Probe::Dns,
            &dns,
            resolveur,
        )?;

        // 1. Le kill switch seul refuse bien ce compte sur le :53. Sur un banc
        //    ou il ne s'appliquerait pas, les trois observations suivantes
        //    rendraient le meme resultat qu'une exception correctement bornee.
        arm(bench, false, Exemptions::AUCUNE).map_err(|e| {
            CheckOutcome::skipped(v, motifs::armement_sans_exception(&e.to_string()))
        })?;
        regles_par_identite_conformes(bench, v, false, Exemptions::AUCUNE)?;
        let temoin = observation(
            bench,
            v,
            "resolveur-temoin",
            probe::Probe::Dns,
            &dns,
            resolveur,
        )?;

        // 2 a 4. Le plan que le produit pose reellement: le compte est declare
        //    ET le profil demande un resolveur embarque.
        arm(bench, false, Exemptions::resolveur(RESOLVEUR_UID)).map_err(|e| {
            CheckOutcome::skipped(v, motifs::armement_avec_exception(&e.to_string()))
        })?;
        regles_par_identite_conformes(bench, v, false, Exemptions::resolveur(RESOLVEUR_UID))?;
        let resolveur_dns = observation(
            bench,
            v,
            "resolveur-amorcage",
            probe::Probe::Dns,
            &dns,
            resolveur,
        )?;
        let resolveur_hors_53 = observation(
            bench,
            v,
            "resolveur-borne",
            probe::Probe::Ipv4,
            &ordinaire,
            resolveur,
        )?;
        let etranger = observation(bench, v, "resolveur-autrui", probe::Probe::Dns, &dns, None)?;

        // Les COMPTES, pas la longueur des listes de preuves: celle-ci est
        // plafonnee, et une fuite de trois cents paquets se serait lue
        // << 20 paquet(s) >> dans le verdict d'echec.
        let mesures = MesuresResolveur {
            repos: repos.compte,
            repos_dns: repos_dns.compte,
            temoin: temoin.compte,
            resolveur_dns: resolveur_dns.compte,
            resolveur_hors_53: resolveur_hors_53.compte,
            etranger: etranger.compte,
        };
        // L'ordre suit celui du jugement: la fuite d'identite se lit avant
        // celle du port.
        let fuites = etranger
            .preuves_dites()
            .into_iter()
            .chain(resolveur_hors_53.preuves_dites())
            .collect();
        Ok((mesures, fuites))
    }

    /// Une observation, ou la raison de s'abstenir.
    fn observation(
        bench: &Bench,
        v: CheckVector,
        tag: &str,
        p: probe::Probe,
        filtre: &str,
        identite: Option<(u32, &str)>,
    ) -> Result<capture::Releve, CheckOutcome> {
        observe_sous(bench, tag, p, filtre, identite).map_err(|e| {
            CheckOutcome::skipped(v, motifs::observation_impossible(tag, &e.to_string()))
        })
    }

    /// Conclut a partir des six observations.
    ///
    /// Pure et sans effet de bord, donc verifiable sans root ni banc.
    fn juger_resolveur(m: MesuresResolveur) -> IssueResolveur {
        if m.repos == 0 {
            return IssueResolveur::Ignore(motifs::resolveur_temoin_muet());
        }
        if m.repos_dns == 0 {
            return IssueResolveur::Ignore(motifs::resolveur_temoin_muet_dns());
        }
        if m.temoin != 0 {
            return IssueResolveur::Ignore(motifs::resolveur_temoin_invalide(m.temoin));
        }

        // L'ordre compte, et c'est celui du pendant Windows: la fuite se dit
        // avant la panne. Une exception trop large est un defaut d'etancheite;
        // une exception morte n'est qu'un resolveur qui ne demarre pas, visible
        // au premier usage et sans consequence sur ce que le kill switch
        // retient. Et parmi les deux fuites, celle de l'identite passe devant:
        // nommer la borne du port enverrait corriger un port alors que
        // l'exception ne discrimine personne.
        if m.etranger != 0 {
            return IssueResolveur::Echec(motifs::resolveur_fuite_identite(m.etranger));
        }
        if m.resolveur_hors_53 != 0 {
            return IssueResolveur::Echec(motifs::resolveur_fuite_hors_port(m.resolveur_hors_53));
        }
        if m.resolveur_dns == 0 {
            return IssueResolveur::Echec(motifs::resolveur_exception_morte());
        }
        IssueResolveur::Reussi(motifs::resolveur_borne_ok(m.resolveur_dns))
    }

    /// Monte un vrai tunnel WireGuard entre les deux namespaces.
    /// Les cles du tunnel du banc, gardees accessibles au vecteur (5s).
    ///
    /// `reconnect-window` reconstruit le client (b) que `kill-switch-on-drop`
    /// detruit, et sa phase de reprise (c) le remonte. Le serveur cote phys
    /// reste en place tout du long et n'accepte QUE la cle publique du client
    /// d'origine: il faut donc conserver la cle privee du client - pour rebatir
    /// le meme client - et la cle publique du serveur - pour le declarer pair.
    struct ClesTunnel {
        client_priv: String,
        server_pub: String,
    }

    fn setup_tunnel(bench: &Bench) -> bifrost_core::Result<ClesTunnel> {
        let (server_priv, server_pub) = wgapply::generate_keypair();
        let (client_priv, client_pub) = wgapply::generate_keypair();
        let exe = self_exe();

        // Serveur, cote phys.
        bench.exec_ok(
            NS_PHYS,
            &["ip", "link", "add", WG_SERVER_IF, "type", "wireguard"],
        )?;
        apply_spec(
            bench,
            NS_PHYS,
            &exe,
            &WgSpec {
                interface: WG_SERVER_IF.into(),
                private_key: server_priv,
                listen_port: Some(WG_PORT),
                fwmark: None,
                peers: vec![WgPeerSpec {
                    public_key: client_pub,
                    endpoint: None,
                    allowed_ips: vec![format!("{TUN_CLIENT_ADDR}/32")],
                    keepalive: None,
                }],
            },
        )?;
        bench.exec_ok(
            NS_PHYS,
            &[
                "ip",
                "addr",
                "add",
                &format!("{TUN_SERVER_ADDR}/{PREFIX}"),
                "dev",
                WG_SERVER_IF,
            ],
        )?;
        bench.exec_ok(NS_PHYS, &["ip", "link", "set", WG_SERVER_IF, "up"])?;

        // Client, cote client. Factorise pour que (b) et (c) remontent
        // EXACTEMENT le meme client, avec la cle publique du pair inchangee.
        let cles = ClesTunnel {
            client_priv,
            server_pub,
        };
        construire_tunnel_client(bench, &cles)?;

        arm(bench, true, Exemptions::AUCUNE)?;
        wait_for_handshake(bench)?;
        Ok(cles)
    }

    /// (Re)construit le cote client du tunnel: interface, cle, pair, adresse,
    /// route. Demontage prealable comme `tunnel::linux::up` (tunnel/linux.rs:135,
    /// qui rejoue `netcfg::teardown`), pour repartir propre meme apres une
    /// destruction d'interface ou un teardown partiel.
    ///
    /// C'est ce que `setup_tunnel` faisait en ligne; extrait pour (5s), ou
    /// `reconnect-window` remonte le client (b) et la sequence de reprise le
    /// rebatit (c). Le pair serveur est declare avec la cle publique conservee
    /// dans `ClesTunnel`: le serveur cote phys n'accepte que la cle publique du
    /// client d'origine, donc la cle privee du client ne doit pas changer.
    fn construire_tunnel_client(bench: &Bench, cles: &ClesTunnel) -> bifrost_core::Result<()> {
        let exe = self_exe();
        demonter_tunnel_client(bench);
        bench.exec_ok(
            NS_CLIENT,
            &["ip", "link", "add", WG_CLIENT_IF, "type", "wireguard"],
        )?;
        apply_spec(
            bench,
            NS_CLIENT,
            &exe,
            &WgSpec {
                interface: WG_CLIENT_IF.into(),
                private_key: cles.client_priv.clone(),
                listen_port: None,
                fwmark: Some(BENCH_FWMARK),
                peers: vec![WgPeerSpec {
                    public_key: cles.server_pub.clone(),
                    endpoint: Some(format!("{PHYS_ADDR}:{WG_PORT}")),
                    allowed_ips: vec!["0.0.0.0/0".into(), "::/0".into()],
                    keepalive: Some(5),
                }],
            },
        )?;
        bench.exec_ok(
            NS_CLIENT,
            &[
                "ip",
                "addr",
                "add",
                &format!("{TUN_CLIENT_ADDR}/{PREFIX}"),
                "dev",
                WG_CLIENT_IF,
            ],
        )?;
        bench.exec_ok(NS_CLIENT, &["ip", "link", "set", WG_CLIENT_IF, "up"])?;
        ajouter_routage_client(bench)
    }

    /// Le routage du produit dans NS_CLIENT: table dediee, regle fwmark,
    /// suppression du prefixe 0 sur main. Les deux familles sont traitees,
    /// exactement comme `tunnel::netcfg::add_routing` (netcfg.rs:85). Ne poser
    /// que l'IPv4 ferait sortir l'IPv6 par l'interface physique et donnerait un
    /// banc qui ne teste pas ce que le produit fait reellement.
    fn ajouter_routage_client(bench: &Bench) -> bifrost_core::Result<()> {
        let table = BENCH_TABLE.to_string();
        let mark = BENCH_FWMARK.to_string();
        for (family, default_route) in [("-4", "0.0.0.0/0"), ("-6", "::/0")] {
            bench.exec_ok(
                NS_CLIENT,
                &[
                    "ip",
                    family,
                    "route",
                    "add",
                    default_route,
                    "dev",
                    WG_CLIENT_IF,
                    "table",
                    &table,
                ],
            )?;
            bench.exec_ok(
                NS_CLIENT,
                &[
                    "ip", family, "rule", "add", "not", "fwmark", &mark, "table", &table,
                ],
            )?;
            bench.exec_ok(
                NS_CLIENT,
                &[
                    "ip",
                    family,
                    "rule",
                    "add",
                    "table",
                    "main",
                    "suppress_prefixlength",
                    "0",
                ],
            )?;
        }
        Ok(())
    }

    /// Demonte le cote client, best effort: rejoue `netcfg::teardown`
    /// (netcfg.rs:133) dans NS_CLIENT - regles par famille, purge de la table
    /// dediee, puis destruction du lien. Chaque commande tolere l'echec, comme
    /// le teardown du produit: une regle deja absente est normale. `exec_ok`
    /// echappe a la garde des sondes, qui ne vise que `let _ = ...exec(...)`.
    fn demonter_tunnel_client(bench: &Bench) {
        let table = BENCH_TABLE.to_string();
        let mark = BENCH_FWMARK.to_string();
        for family in ["-4", "-6"] {
            let _ = bench.exec_ok(
                NS_CLIENT,
                &[
                    "ip", family, "rule", "del", "not", "fwmark", &mark, "table", &table,
                ],
            );
            let _ = bench.exec_ok(
                NS_CLIENT,
                &[
                    "ip",
                    family,
                    "rule",
                    "del",
                    "table",
                    "main",
                    "suppress_prefixlength",
                    "0",
                ],
            );
            let _ = bench.exec_ok(
                NS_CLIENT,
                &["ip", family, "route", "flush", "table", &table],
            );
        }
        let _ = bench.exec_ok(NS_CLIENT, &["ip", "link", "del", WG_CLIENT_IF]);
    }

    fn apply_spec(bench: &Bench, ns: &str, exe: &str, spec: &WgSpec) -> bifrost_core::Result<()> {
        let json = serde_json::to_string(spec)
            .map_err(|e| bifrost_core::Error::Tunnel(format!("serialisation: {e}")))?;
        let out = bench.exec(ns, &[exe, "--wg-apply", &json])?;
        if !out.status.success() {
            return Err(bifrost_core::Error::Tunnel(format!(
                "configuration de {} dans {ns}: {}",
                spec.interface,
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        Ok(())
    }

    /// Lance une sonde ou un reveil dont seuls les PAQUETS comptent, et
    /// JOURNALISE si le lancement echoue.
    ///
    /// Le resultat de la commande n'est pas lu: ce sont les paquets qu'elle
    /// emet, captures par ailleurs, qui portent la mesure. Un `let _ =` cachait
    /// pourtant le cas ou la commande n'a PAS TOURNE - binaire absent, namespace
    /// disparu: `bench.exec` ne rend `Err` que la, jamais pour une sonde
    /// simplement bloquee, qui rend `Ok` avec un code non nul. Une sonde qui n'a
    /// rien emis se lisait alors comme une sonde correctement bloquee, et
    /// l'absence de trace passait pour une mesure. La cause du non-lancement est
    /// donc journalisee, jamais avalee.
    fn sonde_best_effort(bench: &Bench, ns: &str, argv: &[&str], role: &str) {
        if let Err(e) = bench.exec(ns, argv) {
            eprintln!(
                "[checks] sonde '{role}' non lancee ({}): {e}",
                argv.join(" ")
            );
        }
    }

    /// Relit les compteurs du pair depuis le namespace client.
    ///
    /// La lecture se fait en relancant le binaire dans le namespace: le device
    /// WireGuard n'existe que la, et un processus ne voit que le sien.
    fn compteurs(bench: &Bench) -> bifrost_core::Result<Compteurs> {
        let exe = self_exe();
        let out = bench.exec(NS_CLIENT, &[&exe, "--wg-stats", WG_CLIENT_IF])?;
        if !out.status.success() {
            return Err(bifrost_core::Error::Tunnel(format!(
                "lecture des compteurs de {WG_CLIENT_IF}: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        serde_json::from_slice(&out.stdout).map_err(|e| {
            bifrost_core::Error::Tunnel(format!("compteurs de {WG_CLIENT_IF} illisibles: {e}"))
        })
    }

    fn wait_for_handshake(bench: &Bench) -> bifrost_core::Result<()> {
        let exe = self_exe();
        let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
        let mut dernier = Compteurs::default();
        while Instant::now() < deadline {
            // Provoque le handshake: WireGuard n'en initie un que sur trafic.
            sonde_best_effort(
                bench,
                NS_CLIENT,
                &[&exe, "--probe-tunnel", TUN_SERVER_ADDR],
                "reveil-handshake",
            );
            dernier = compteurs(bench)?;
            if dernier.handshake {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(400));
        }
        // Les compteurs dans le message: c'est ce qui distingue "personne en
        // face" de "quelqu'un repond mais la cle est fausse". Un endpoint mort
        // laisse rx a zero, un pair qui refuse la poignee de main aussi, mais
        // le tx dit combien de fois on a essaye.
        Err(bifrost_core::Error::Tunnel(format!(
            "aucun handshake WireGuard en {} s entre les namespaces ({} octet(s) emis, {} recus)",
            HANDSHAKE_TIMEOUT.as_secs(),
            dernier.tx_bytes,
            dernier.rx_bytes
        )))
    }

    /// Le pair du banc, qui sert sa banniere aux seules connexions ARRIVANT
    /// par le tunnel. Tue a la liberation.
    ///
    /// Il tourne dans `phys`, la ou vit deja l'autre bout du tunnel: le banc
    /// n'a besoin d'aucune infrastructure de plus pour porter cette preuve.
    struct Pair<'a> {
        bench: &'a Bench,
        child: Option<std::process::Child>,
    }

    impl<'a> Pair<'a> {
        /// L'adresse servie: celle du serveur DANS le tunnel.
        fn cible() -> String {
            format!("{TUN_SERVER_ADDR}:{BANNIERE_PORT}")
        }

        /// Pose d'abord la regle qui restreint l'arrivee, ensuite le serveur.
        ///
        /// Cet ordre est le bon: entre les deux instants, un serveur sans
        /// regle servirait la banniere par n'importe quel chemin.
        fn lever(bench: &'a Bench) -> bifrost_core::Result<Self> {
            let script = transport::nft_banniere(WG_SERVER_IF, BANNIERE_PORT);
            bench.poser_nft(NS_PHYS, &script)?;
            let exe = self_exe();
            let child = bench.spawn(NS_PHYS, &[&exe, "--servir-banniere", &Self::cible()])?;
            Ok(Self {
                bench,
                child: Some(child),
            })
        }
    }

    impl Pair<'_> {
        /// Ce que le serveur a eu a dire, s'il est deja mort.
        ///
        /// Un serveur vivant ne dit rien: il boucle sur `accept`. Un serveur
        /// mort, lui, a une raison, et sans elle la lecture qui echoue derriere
        /// se lit comme "le tunnel ne transporte pas" alors que c'est le pair
        /// qui n'existe pas. Deux causes opposees, une seule observation: c'est
        /// exactement ce que ce module s'interdit ailleurs.
        fn plainte(&mut self) -> Option<String> {
            use std::io::Read;
            let child = self.child.as_mut()?;
            // Trois etats, pas deux. `try_wait().ok().flatten()` confondait
            // << le pair tourne encore >> (Ok(None)) et << son etat est
            // illisible >> (Err): les deux rendaient None, donc aucune plainte,
            // donc la lecture ratee derriere etait imputee au tunnel. C'est la
            // meme lecon que celle de `sortie_de`: une erreur qui disparait rend
            // trois etats indiscernables. Elle remonte maintenant avec sa cause.
            let status = match child.try_wait() {
                Ok(None) => return None,
                Ok(Some(status)) => status.to_string(),
                Err(e) => {
                    return Some(format!(
                        "et l'etat du pair est illisible ({e}): ni sa mort ni sa survie \
                         n'est etablie"
                    ));
                }
            };
            let mut texte = String::new();
            if let Some(flux) = &mut child.stderr {
                // La sortie d'erreur du pair mort est le seul indice de la
                // cause; un `let _ =` la faisait disparaitre et laissait lire un
                // silence comme une absence de message.
                if let Err(e) = flux.read_to_string(&mut texte) {
                    texte = format!("<erreur standard du pair illisible: {e}>");
                }
            }
            Some(format!(
                "et le pair s'est arrete ({status}): {}",
                texte.trim()
            ))
        }
    }

    /// Sans ce `Drop`, chaque chemin qui renvoie `SKIPPED` avant la fin du
    /// vecteur laisserait un serveur root tourner dans un namespace que le
    /// banc va detruire, et une regle nftables dans un namespace qu'il
    /// reutilise.
    impl Drop for Pair<'_> {
        fn drop(&mut self) {
            if let Some(mut child) = self.child.take() {
                netns::kill_group(&mut child);
            }
            // Retrait best effort: si la table n'existe pas, l'objectif est
            // atteint, et le banc est de toute facon detruit derriere. Mais le
            // statut n'est plus RAVALE - `retirer_nft` le journalise s'il echoue.
            self.bench
                .retirer_nft(NS_PHYS, &transport::nft_banniere_teardown());
        }
    }

    /// Lit la banniere du pair depuis un namespace donne.
    ///
    /// `fenetre_ms` a zero fait une seule tentative: c'est ce qu'il faut au
    /// temoin negatif, qui attend un refus.
    fn lire_banniere(bench: &Bench, ns: &str, fenetre_ms: u64) -> Result<String, String> {
        let exe = self_exe();
        let cible = Pair::cible();
        let fenetre = fenetre_ms.to_string();
        let out = bench
            .exec(
                ns,
                &[
                    &exe,
                    "--lire-banniere",
                    &cible,
                    "--lire-banniere-delai",
                    &fenetre,
                ],
            )
            .map_err(|e| e.to_string())?;
        if out.status.success() {
            return Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned());
        }
        // `anyhow` prefixe son message; le garder ferait lire "Error: Error:"
        // dans la raison du SKIPPED.
        Err(String::from_utf8_lossy(&out.stderr)
            .trim()
            .trim_start_matches("Error:")
            .trim()
            .to_owned())
    }

    /// Le trafic destine au reseau du tunnel ne doit apparaitre sur le lien
    /// physique que chiffre, jamais en clair.
    ///
    /// Ce vecteur mesure le CHEMIN DE SORTIE, donc le routage (table dediee,
    /// regle fwmark, suppression du prefixe 0). Il est volontairement peu
    /// sensible a l'etat du pare-feu: quand le routage est correct, tout part
    /// dans le tunnel meme si le kill switch est ouvert. Ce sont les cinq
    /// autres vecteurs qui mesurent le pare-feu.
    ///
    /// # Ce qu'il ne conclut plus des paquets chiffres
    ///
    /// Ce vecteur a longtemps conclu que le tunnel transportait parce que des
    /// paquets chiffres apparaissaient sur le lien. C'etait faux: un endpoint
    /// MORT en produit exactement autant, ce sont ses poignees de main
    /// reemises. Le trafic partait alors dans un trou noir, ou il ne fuitait
    /// evidemment pas, et le vecteur rendait PASSED sur un tunnel qui ne
    /// portait rien. Les paquets chiffres n'etablissent plus qu'une chose ici:
    /// que la CAPTURE etait vivante.
    ///
    /// # Ce qui etablit le transport, et pourquoi il en faut quatre
    ///
    /// 1. Les compteurs du driver, releves de part et d'autre de la mesure:
    ///    poignee de main aboutie, `rx_bytes` non nul, et les deux compteurs
    ///    qui bougent PENDANT la lecture. Un pair mort laisse `rx_bytes` a
    ///    zero quoi que le client emette.
    /// 2. La banniere, lue a travers le tunnel depuis une adresse dont la
    ///    passerelle ne sert le port qu'aux connexions ARRIVANT par `wgs`.
    ///    Elle ne peut venir que de l'autre bout.
    /// 3. Le temoin negatif: la meme banniere, demandee hors tunnel, doit
    ///    etre REFUSEE. Sans lui, la lire ne prouverait rien, et c'est une
    ///    propriete du noyau qu'on ne se contente pas de croire.
    /// 4. Le filtre de fuite, qui n'exempte ni l'adresse ni le port de la
    ///    banniere: si elle etait arrivee en clair par le lien, ce vecteur
    ///    echouerait au lieu de passer.
    fn exit_ip(bench: &Bench) -> CheckOutcome {
        let v = CheckVector::ExitIp;
        let exe = self_exe();

        let mut pair = match Pair::lever(bench) {
            Ok(p) => p,
            Err(e) => {
                return CheckOutcome::skipped(v, motifs::pair_non_leve(&e.to_string()));
            }
        };

        let avant = match compteurs(bench) {
            Ok(c) => c,
            Err(e) => return CheckOutcome::skipped(v, motifs::compteurs_avant(&e.to_string())),
        };

        let cap = match capture::Capture::start(bench, NS_PHYS, "exit-ip") {
            Ok(c) => c,
            Err(e) => {
                return CheckOutcome::skipped(v, motifs::capture_non_demarree(&e.to_string()));
            }
        };
        // Reveille le tunnel avant de le mesurer. WireGuard n'etablit rien
        // sans trafic, et la premiere demande de connexion sert alors de
        // reveil au lieu de porter la mesure.
        sonde_best_effort(
            bench,
            NS_CLIENT,
            &[&exe, "--probe-tunnel", TUN_SERVER_ADDR],
            "reveil-tunnel",
        );
        // La preuve du transport, puis les sondes qui doivent rester dedans.
        let mut banniere = lire_banniere(bench, NS_CLIENT, LECTURE_BANNIERE_MS);
        sonde_best_effort(bench, NS_CLIENT, &[&exe, "--probe", "all"], "sonde-exit-ip");
        let mut pcap = match cap.stop() {
            Ok(p) => p,
            Err(e) => return CheckOutcome::skipped(v, motifs::capture_non_arretee(&e.to_string())),
        };

        // Un pair mort explique la lecture qui a echoue; le taire ferait
        // accuser le tunnel a sa place.
        if let (Err(raison), Some(plainte)) = (&banniere, pair.plainte()) {
            banniere = Err(format!("{raison}, {plainte}"));
        }

        let apres = match compteurs(bench) {
            Ok(c) => c,
            Err(e) => return CheckOutcome::skipped(v, motifs::compteurs_apres(&e.to_string())),
        };

        // Temoin negatif, hors capture pour ne pas la polluer: la meme
        // banniere, demandee depuis la passerelle, doit rester hors d'atteinte.
        // Elle y arriverait par `lo` et non par `wgs`, donc la regle la jette.
        // L'ordre compte: la lecture ci-dessus a deja etabli que le serveur
        // ecoute, sans quoi cet echec ne dirait que "personne n'ecoute".
        let hors_tunnel = lire_banniere(bench, NS_PHYS, 0).is_ok();

        let chiffres = match capture::count(
            pcap.chemin(),
            &format!("udp port {WG_PORT} and host {PHYS_ADDR}"),
        ) {
            Ok(n) => n,
            Err(e) => {
                return CheckOutcome::skipped(v, motifs::analyse_des_chiffres(&e.to_string()));
            }
        };
        let en_clair = match capture::relever(pcap.chemin(), &capture::leak_filter()) {
            Ok(m) => m,
            Err(e) => return CheckOutcome::skipped(v, motifs::analyse_du_clair(&e.to_string())),
        };

        // `transport::Observation` en toutes lettres: ce module en a deja une,
        // qui decrit une capture de sonde. Les confondre du regard couterait
        // cher, l'ambiguite est donc levee au point d'usage.
        let observation = transport::Observation {
            chiffres,
            avant,
            apres,
            banniere,
            banniere_hors_tunnel: hors_tunnel,
            en_clair: en_clair.compte,
        };
        match transport::juger(&observation) {
            transport::Verdict::Etanche(raison) => CheckOutcome::passed(v, raison),
            transport::Verdict::Indecis(raison) => {
                // Les lignes voyagent meme sans echec: si le banc etait casse
                // ET que du trafic est sorti, c'est la seule trace exploitable.
                // Et le pcap survit: un vecteur qui n'a pas conclu est
                // precisement celui qu'on voudra rouvrir a la main.
                pcap.garder();
                let mut issue = CheckOutcome::skipped(v, raison);
                issue.evidence = en_clair.preuves_dites();
                issue
            }
            transport::Verdict::Fuite(raison) => {
                pcap.garder();
                CheckOutcome::failed(v, raison, en_clair.preuves_dites())
            }
        }
    }

    /// Temps laisse au processus armeur pour poser ses filtres.
    ///
    /// Sur une attente de CONDITION et non sur un delai fixe, et genereux: la
    /// CI tourne sur un runner partage, plus lent et plus variable que nos
    /// machines. Un vecteur instable est pire qu'un vecteur absent, parce qu'il
    /// apprend a une equipe a ignorer le rouge.
    const ARMEMENT_TIMEOUT: Duration = Duration::from_secs(20);

    /// Fenetre pendant laquelle on tente de fuir apres la mort du processus.
    ///
    /// Plus longue que le `RestartSec=2` de l'unite systemd: la fenetre qu'un
    /// utilisateur subirait vraiment est celle-la, et la mesurer plus courte
    /// laisserait croire a une etancheite qu'on n'aurait pas eprouvee.
    const FENETRE_APRES_MORT: Duration = Duration::from_secs(4);

    /// Le processus qui arme le kill switch, et le filet qui l'empeche de
    /// survivre au vecteur.
    ///
    /// Sans ce `Drop`, chacun des chemins de sortie anticipee de `daemon_mort`
    /// laisserait un `bifrost-daemon` root en attente jusqu'a l'arret de la
    /// machine. Ce que cela coute est documente dans `.github/workflows/ci.yml`:
    /// un seul survivant que le runner, qui tourne en utilisateur ordinaire, ne
    /// peut pas tuer, et le job reste bloque sur "Cleaning up orphan processes"
    /// alors que toutes ses etapes ont reussi.
    struct Armeur {
        enfant: Option<std::process::Child>,
        pid: i32,
    }

    impl Armeur {
        fn lancer(bench: &Bench, exe: &str) -> bifrost_core::Result<Self> {
            let enfant = bench.spawn(NS_CLIENT, &[exe, "--armer-le-banc-et-attendre"])?;
            let pid = enfant.id() as i32;
            Ok(Self {
                enfant: Some(enfant),
                pid,
            })
        }

        /// SIGKILL au PROCESSUS, par son PID, et la PREUVE qu'il en est mort.
        ///
        /// Par PID et jamais par motif de nom: un `pkill` trop large a deja
        /// coupe deux services de production sur une machine de ce parc.
        ///
        /// Et on relit le statut de sortie. Un processus mort d'autre chose -
        /// d'une panne de son propre fait, par exemple - rendrait exactement le
        /// meme pcap, et le vecteur passerait en croyant avoir mesure un
        /// SIGKILL qu'il n'a pas mesure.
        fn tuer(&mut self) -> bifrost_core::Result<String> {
            use std::os::unix::process::ExitStatusExt;
            let Some(mut enfant) = self.enfant.take() else {
                return Err(bifrost_core::Error::Tunnel(
                    "l'armeur a deja ete tue une fois".into(),
                ));
            };
            // SAFETY: un pid POSITIF designe le processus seul, et il est
            // vivant tant que `enfant` n'a pas ete moissonne.
            if unsafe { libc::kill(self.pid, libc::SIGKILL) } != 0 {
                let e = std::io::Error::last_os_error();
                netns::kill_group(&mut enfant);
                return Err(bifrost_core::Error::Tunnel(format!(
                    "SIGKILL au pid {}: {e}",
                    self.pid
                )));
            }
            let statut = enfant.wait().map_err(|e| {
                bifrost_core::Error::Tunnel(format!("attente du pid {}: {e}", self.pid))
            })?;
            match statut.signal() {
                Some(libc::SIGKILL) => Ok(format!("pid {} tue par SIGKILL", self.pid)),
                autre => Err(bifrost_core::Error::Tunnel(format!(
                    "le pid {} ne s'est pas termine par SIGKILL (signal {autre:?}, code {:?}): \
                     ce n'est pas la mort qu'on voulait mesurer",
                    self.pid,
                    statut.code()
                ))),
            }
        }
    }

    impl Drop for Armeur {
        fn drop(&mut self) {
            if let Some(mut enfant) = self.enfant.take() {
                netns::kill_group(&mut enfant);
            }
        }
    }

    /// Arme le kill switch du banc par le VRAI backend, puis attend d'etre tue.
    ///
    /// Le reste du banc arme par `nft -f -` sur un ruleset rendu, ce qui suffit
    /// a mesurer une politique. Pas ici: ce vecteur mesure que les filtres
    /// poses PAR NOTRE CODE survivent au processus qui les a poses, et un
    /// `nft` externe ne dirait rien de ce que fait notre poignee de pare-feu
    /// quand elle est liberee.
    pub fn armer_le_banc_et_attendre() -> anyhow::Result<()> {
        let mut fw = bifrost_firewall::new()?;
        fw.engage(&bench_policy(true, Exemptions::AUCUNE))?;
        // Le vecteur n'attend PAS cette ligne pour tuer: il attend que la table
        // apparaisse dans le namespace, qui est l'effet et non l'annonce. Elle
        // sert au diagnostic quand rien n'apparait.
        println!("kill switch du banc arme, en attente d'etre tue");
        loop {
            std::thread::sleep(Duration::from_secs(3600));
        }
    }

    /// Attend que l'armeur ait pose ses filtres, et le dit.
    ///
    /// Trois issues et non deux: pose, pas pose dans le temps imparti, et
    /// instrument casse. La derniere remonte en `Err` plutot que de se
    /// confondre avec la deuxieme, qui accuserait l'armeur d'un silence dont il
    /// n'est pas responsable.
    fn attendre_le_kill_switch(bench: &Bench) -> bifrost_core::Result<bool> {
        let echeance = Instant::now() + ARMEMENT_TIMEOUT;
        loop {
            if table_du_kill_switch_posee(bench)? {
                return Ok(true);
            }
            if Instant::now() >= echeance {
                return Ok(false);
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    /// Les deux sondes du vecteur, emises ensemble.
    ///
    /// `--probe all` vise des destinations hors lien, dont la route passe par
    /// le tunnel des qu'il est monte: elles ne fuient donc pas en clair meme
    /// sans filtres. Elles restent la pour qu'un changement de routage ne rende
    /// pas le vecteur aveugle. Celle qui DISCRIMINE est `--probe-lan`, dont la
    /// destination est on-link: le plan du banc pose `allow_lan = false`, donc
    /// le kill switch doit la refuser, et elle repart en clair des qu'il tombe.
    ///
    /// Rend ce que les DEUX sondes ont fait, code de sortie et plainte
    /// comprises. Sans cela, un pcap vide a deux lectures indiscernables - le
    /// trafic a ete bloque, ou il n'a jamais ete emis - et ce module a deja
    /// paye cette confusion ailleurs.
    fn sonder_pour_la_mort(bench: &Bench, exe: &str) -> String {
        let mut dits = Vec::new();
        for (nom, argv) in [
            ("probe all", vec![exe, "--probe", "all"]),
            ("probe-lan", vec![exe, "--probe-lan", PHYS_ADDR]),
        ] {
            let dit = match bench.exec(NS_CLIENT, &argv) {
                Ok(out) if out.status.success() && out.stderr.is_empty() => "sortie 0".to_owned(),
                // Les retours a la ligne de la plainte deviennent des
                // separateurs: ce compte rendu finit dans le `detail` d'un
                // `CheckOutcome`, que des scripts lisent ligne par ligne.
                Ok(out) => format!(
                    "sortie {}: {}",
                    out.status.code().unwrap_or(-1),
                    String::from_utf8_lossy(&out.stderr)
                        .lines()
                        .map(str::trim)
                        .filter(|l| !l.is_empty())
                        .collect::<Vec<_>>()
                        .join(" / ")
                ),
                Err(e) => format!("lancement impossible: {e}"),
            };
            dits.push(format!("{nom}: {dit}"));
        }
        dits.join("; ")
    }

    /// Le processus qui a arme le kill switch MEURT. Rien ne repart en clair.
    ///
    /// # D'ou vient ce vecteur
    ///
    /// D'un defaut mesure le 23/08/2026, que rien dans ce depot ne voyait:
    /// `packaging/systemd/bifrost-daemon.service` portait un `ExecStopPost=`
    /// qui lancait `--cleanup-firewall`, sous un commentaire qui annoncait
    /// l'invariant que cette ligne cassait. `man systemd.service` dit que la
    /// directive s'execute sur TOUS les chemins d'arret, fin inattendue
    /// comprise, et qu'un redemarrage est un arret suivi d'un demarrage: avec
    /// `Restart=on-failure` et `RestartSec=2`, chaque plantage demontait le
    /// pare-feu puis laissait la machine nue jusqu'au retour du daemon.
    ///
    /// # Ses deux bras
    ///
    /// Le temoin: sans filtres, les sondes DOIVENT se voir sur le lien. S'il
    /// est muet, un zero apres la mort ne prouverait rien, et le vecteur se
    /// declare `SKIPPED` plutot que de passer sur une capture vide. La mesure:
    /// filtres poses par un vrai processus, SIGKILL, puis tentatives de fuite
    /// pendant toute la fenetre ou personne ne protege plus.
    ///
    /// # Ce qu'il ne couvre pas
    ///
    /// systemd n'intervient pas: aucun banc portable ne peut faire rejouer un
    /// cycle de redemarrage a l'init de la machine sans toucher a cette
    /// machine. Il faut donc les trois pieces, et elles se nomment l'une
    /// l'autre: ce vecteur pour la mort du processus,
    /// `crates/bifrost-daemon/tests/unite_systemd.rs` pour l'unite livree, et
    /// `scripts/mort-daemon-systemd-linux.sh` pour la meme mesure sur le
    /// service REEL, cycle de redemarrage compris.
    ///
    /// # Son plus proche voisin, et pourquoi ce n'est pas le meme
    ///
    /// [`CheckVector::KillSwitchOnDrop`] detruit l'INTERFACE du tunnel;
    /// celui-ci tue le PROCESSUS. Une protection peut survivre a la premiere
    /// et pas a la seconde: c'etait exactement le cas ici.
    fn daemon_mort(bench: &Bench) -> CheckOutcome {
        let issue = daemon_mort_mesure(bench);
        // Quoi qu'il arrive, le banc repart ARME. Ce vecteur desarme pour son
        // temoin, et chacun de ses chemins de sortie anticipee laisserait
        // sinon les vecteurs suivants mesurer un banc sans kill switch: le
        // 23/08/2026, `kill-switch-on-drop` et `reconnect-window` ont rendu
        // FAILED sur une fuite qui etait celle du banc et pas celle du produit.
        // Un vecteur n'a pas le droit de faire mentir ses voisins.
        //
        // Un listage illisible se traite comme un banc DESARME et non comme un
        // banc arme: l'erreur ne dit pas ce qui est pose, et rearmer un banc
        // deja arme ne coute qu'un `nft -f` de plus, tandis que ne pas rearmer
        // un banc tombe fait mentir les deux vecteurs suivants. Le doute penche
        // du cote qui ne fabrique pas de faux verdict chez le voisin.
        if !matches!(table_du_kill_switch_posee(bench), Ok(true)) {
            let _ = arm(bench, true, Exemptions::AUCUNE);
        }
        issue
    }

    fn daemon_mort_mesure(bench: &Bench) -> CheckOutcome {
        let v = CheckVector::DaemonMort;
        let exe = self_exe();

        // 1. Temoin: sans filtres, les sondes doivent apparaitre sur le lien.
        if let Err(e) = disarm(bench) {
            return CheckOutcome::skipped(v, motifs::desarmement_impossible(&e.to_string()));
        }
        let temoin = {
            let cap = match capture::Capture::start(bench, NS_PHYS, "daemon-mort-temoin") {
                Ok(c) => c,
                Err(e) => {
                    return CheckOutcome::skipped(
                        v,
                        motifs::capture_du_temoin_non_demarree(&e.to_string()),
                    );
                }
            };
            let dit = sonder_pour_la_mort(bench, &exe);
            // Aucune attente ici, et c'est une SUPPRESSION, pas un oubli. Ce
            // vecteur a longtemps dormi 2500 ms avant chaque arret de capture,
            // parce que sa derniere sonde emet a la toute fin et que libpcap ne
            // reveillait tcpdump qu'apres son delai de lecture, une seconde par
            // defaut. Cette cause a ete traitee a la source le 23/08/2026:
            // `--immediate-mode` fait retomber l'anneau en TPACKET_V2, ou le
            // noyau ne retient rien, et `stop_bavard` attend que le pcap se
            // TAISE au lieu d'une duree fixe. Les deux attentes se recouvraient
            // donc entierement, pour 5 s par passage.
            //
            // Ce qui protege desormais la mesure n'est plus un delai mais un
            // refus: `stop_bavard` compare ce que le noyau a laisse passer a ce
            // que tcpdump a remis, et rend une erreur - donc un SKIPPED motive -
            // des qu'il manque un paquet. Une attente trop courte ne peut plus
            // se lire comme une absence de fuite.
            let (pcap, compte_rendu) = match cap.stop_bavard() {
                Ok(p) => p,
                Err(e) => {
                    return CheckOutcome::skipped(
                        v,
                        motifs::capture_du_temoin_non_arretee(&e.to_string()),
                    );
                }
            };
            let vus = match capture::relever(pcap.chemin(), &capture::leak_filter()) {
                Ok(m) => m,
                Err(e) => {
                    return CheckOutcome::skipped(v, motifs::analyse_du_temoin(&e.to_string()));
                }
            };
            // Les tables VIVANTES au moment de la mesure, et pas seulement ce
            // qu'on croit avoir desarme: un temoin muet a deux causes
            // opposees - les sondes n'ont rien emis, ou un filtre les a
            // arretees - et sans cette ligne elles sont indiscernables.
            let tables = match sortie_de(bench, NS_CLIENT, &["nft", "list", "tables"]) {
                Ok(l) => l.join(", "),
                Err(e) => format!("illisible: {e}"),
            };
            (
                vus,
                format!("{dit}; tcpdump: {compte_rendu}; nft list tables: [{tables}]"),
            )
        };
        let (temoin, temoin_dit) = temoin;
        if temoin.compte == 0 {
            return CheckOutcome::skipped(v, motifs::temoin_muet_apres_mort(&temoin_dit));
        }

        // 2. Un vrai processus arme, par le backend du produit.
        let mut armeur = match Armeur::lancer(bench, &exe) {
            Ok(a) => a,
            Err(e) => return CheckOutcome::skipped(v, motifs::armeur_non_lance(&e.to_string())),
        };
        match attendre_le_kill_switch(bench) {
            // L'instrument casse ne s'impute pas a l'armeur: dire qu'il n'a
            // rien pose alors qu'on n'a pas su regarder enverrait chercher le
            // defaut dans le produit plutot que dans le banc.
            Err(e) => {
                return CheckOutcome::skipped(v, motifs::kill_switch_illisible(&e.to_string()));
            }
            Ok(false) => return CheckOutcome::skipped(v, motifs::armeur_muet()),
            Ok(true) => {}
        }

        // 3. La connexion est active, et on le DIT plutot que de le supposer.
        let tunnel = match compteurs(bench) {
            Ok(c) => format!(
                "tunnel {WG_CLIENT_IF}: handshake={}, rx={} o, tx={} o",
                c.handshake, c.rx_bytes, c.tx_bytes
            ),
            Err(e) => format!("compteurs du tunnel illisibles: {e}"),
        };

        // 4. La mort, sous capture, et les tentatives de fuite pendant toute la
        //    fenetre qui suit. La capture demarre AVANT le SIGKILL: ouverte
        //    apres, elle manquerait justement les premiers paquets, qui sont
        //    ceux du moment ou la protection tombe.
        let cap = match capture::Capture::start(bench, NS_PHYS, "daemon-mort") {
            Ok(c) => c,
            Err(e) => {
                return CheckOutcome::skipped(v, motifs::capture_non_demarree(&e.to_string()));
            }
        };
        let mort = armeur.tuer();
        let echeance = Instant::now() + FENETRE_APRES_MORT;
        let mut dit_apres;
        loop {
            dit_apres = sonder_pour_la_mort(bench, &exe);
            if Instant::now() >= echeance {
                break;
            }
            std::thread::sleep(Duration::from_millis(300));
        }
        // Meme raison qu'au temoin ci-dessus: le vidage est attendu par
        // `stop`, sur le silence du pcap et non sur un delai.
        let mut pcap = match cap.stop() {
            Ok(p) => p,
            Err(e) => return CheckOutcome::skipped(v, motifs::capture_non_arretee(&e.to_string())),
        };
        let mort = match mort {
            Ok(dit) => dit,
            Err(e) => {
                return CheckOutcome::skipped(v, motifs::mise_a_mort_impossible(&e.to_string()));
            }
        };
        let fuites = match capture::relever(pcap.chemin(), &capture::leak_filter()) {
            Ok(m) => m,
            Err(e) => return CheckOutcome::skipped(v, motifs::analyse_du_pcap(&e.to_string())),
        };

        // 5. Deux verdicts d'echec, et pas un seul. Des filtres disparus et des
        //    paquets sortis sont deux observations differentes: la premiere
        //    peut se produire sans la seconde - rien a emettre a cet
        //    instant-la - et la taire ferait passer un fail-open pour une
        //    etancheite.
        //
        // Trois etats et non deux: pose, disparu, et illisible. Le dernier
        // rendait `false` avant cette version, donc un `nft` muet suffisait a
        // faire declarer un fail-open que personne n'avait observe. C'est le
        // verdict le plus grave de toute la suite, et il ne se rend pas sur
        // une absence de lecture.
        let encore_pose = match table_du_kill_switch_posee(bench) {
            Ok(b) => b,
            Err(e) => {
                pcap.garder();
                return CheckOutcome::skipped(v, motifs::kill_switch_illisible(&e.to_string()));
            }
        };
        if !encore_pose {
            pcap.garder();
            let mut preuve = vec![
                format!("{mort}; {tunnel}; sondes: {dit_apres}"),
                "nft list tables, apres la mort: aucune table du kill switch".to_owned(),
            ];
            preuve.extend(fuites.preuves_dites());
            return CheckOutcome::failed(v, motifs::daemon_mort_rouvre_le_trafic(), preuve);
        }
        if fuites.compte > 0 {
            pcap.garder();
            let mut preuve = vec![format!("{mort}; {tunnel}; sondes: {dit_apres}")];
            let combien = fuites.compte;
            preuve.extend(fuites.preuves_dites());
            preuve.extend(chaine_pour_preuve(bench));
            return CheckOutcome::failed(v, motifs::fuite_apres_la_mort(combien), preuve);
        }
        CheckOutcome::passed(
            v,
            motifs::etanche_apres_la_mort(temoin.compte, &mort, &tunnel, &dit_apres),
        )
    }

    /// L'interface du tunnel est detruite brutalement pendant une connexion
    /// active. Rien ne doit repartir en clair.
    ///
    /// # Le trou que 5s ferme (a)
    ///
    /// La version d'avant concluait sur `verdict()` SANS temoin - une capture
    /// aveugle (mauvaise interface, filtre qui ne matche rien) se lisait alors
    /// comme une etancheite - et ne sondait que hors lien (`--probe all`,
    /// `--probe-tunnel`), que le routage garde dans le tunnel, kill switch ou
    /// pas: rien ne pouvait fuir en clair, donc rien ne discriminait. C'est le
    /// trou exact que `5i` a ferme pour `reconnect-window`. Ce vecteur recoit le
    /// meme temoin, dans le meme ordre: desarmer, voir la sonde de lien on-link,
    /// rearmer, detruire l'interface, sonder (avec `--probe-lan`, la seule sonde
    /// qui discrimine), exiger zero clair.
    fn kill_switch_on_drop(bench: &Bench) -> CheckOutcome {
        let v = CheckVector::KillSwitchOnDrop;
        let exe = self_exe();

        // 1. Temoin: SANS kill switch, la sonde de lien on-link DOIT etre vue
        //    cote phys. Sans lui, la capture vide qui suit la destruction de
        //    l'interface ne prouve rien.
        if let Err(e) = disarm(bench) {
            return CheckOutcome::skipped(v, motifs::desarmement_impossible(&e.to_string()));
        }
        let temoin = match temoin_de_lien(bench, &exe, "kill-switch-temoin") {
            Ok(t) => t,
            Err(raison) => {
                // Rearmer avant de sortir: un vecteur n'a pas le droit de laisser
                // le suivant mesurer un banc sans kill switch.
                let _ = arm(bench, true, Exemptions::AUCUNE);
                return CheckOutcome::skipped(v, raison);
            }
        };
        if let Err(e) = arm(bench, true, Exemptions::AUCUNE) {
            return CheckOutcome::skipped(v, motifs::rearmement_impossible(&e.to_string()));
        }
        if temoin.releve.compte == 0 {
            return CheckOutcome::skipped(v, motifs::temoin_muet_chute(&temoin.dit));
        }

        // 2. La panne exacte du critere de recette: ip link del pendant le trafic.
        if let Err(e) = bench.exec_ok(NS_CLIENT, &["ip", "link", "del", WG_CLIENT_IF]) {
            return CheckOutcome::skipped(v, motifs::injection_de_panne(&e.to_string()));
        }
        // 3. Fuite sous kill switch: `fuite_de_lien` emet `--probe-lan` - la
        //    sonde on-link qui discrimine - avec les sondes hors lien et le
        //    reveil du tunnel. Zero clair exige.
        match fuite_de_lien(bench, &exe, "kill-switch") {
            Ok(fuites) if fuites.compte == 0 => {
                CheckOutcome::passed(v, motifs::chute_etanche(temoin.releve.compte))
            }
            Ok(fuites) => CheckOutcome::failed(
                v,
                motifs::fuite_apres_chute(fuites.compte),
                fuites.preuves_dites(),
            ),
            Err(raison) => CheckOutcome::skipped(v, raison),
        }
    }

    /// Duree pendant laquelle le lien physique reste coupe avant sa remontee.
    const COUPURE_LIEN_BAS: Duration = Duration::from_millis(700);
    /// Delai apres remontee, pour que la route on-link se repose avant la mesure.
    const COUPURE_LIEN_REMONTE: Duration = Duration::from_millis(700);

    /// Une des trois injections de defaillance de la fenetre de reconnexion,
    /// partie 4 du document 02.
    ///
    /// L'injection portee par les trois premieres [`PhaseReconnexion`]; la
    /// quatrieme, `Reprise`, n'injecte rien et rend `None` a
    /// [`PhaseReconnexion::injection`].
    #[derive(Clone, Copy)]
    enum InjectionDeLien {
        /// Un DPI cote passerelle jette l'UDP de WireGuard. Le lien reste UP.
        Dpi,
        /// Perte totale sur le RETOUR phys vers client (netem loss 100%).
        ///
        /// Applique sur l'egress de `veth-bfp` et non de `veth-bfc`: posee sur
        /// l'egress du client, la perte totale couperait aussi la sonde du
        /// temoin et aveuglerait la capture cote phys, celle-la meme qui doit
        /// voir l'absence de fuite. En cassant le RETOUR, on tient le tunnel en
        /// echec de handshake tout en laissant l'egress du client atteindre le
        /// point de capture. Mesure du banc le 05/09/2026 sur essai-linux:
        /// perte sur `veth-bfc`, temoin desarme MUET (0 paquet); perte sur
        /// `veth-bfp`, temoin desarme VU (2 paquets).
        PerteTotale,
        /// Coupure puis remontee du lien physique.
        ///
        /// La capture est aveugle tant que `veth-bfp` est down; on mesure donc
        /// APRES la remontee, dans la fenetre ou le lien est revenu mais le
        /// tunnel n'a pas encore refait sa poignee de main.
        CoupureLien,
    }

    impl InjectionDeLien {
        fn nom(self) -> &'static str {
            match self {
                Self::Dpi => "dpi-udp-51820",
                Self::PerteTotale => "perte-totale-netem",
                Self::CoupureLien => "coupure-lien",
            }
        }

        /// La cause de saut propre a l'injection de cette phase.
        fn motif_injection(self, cause: &str) -> String {
            match self {
                Self::Dpi => motifs::injection_dpi(cause),
                Self::PerteTotale => motifs::injection_perte_totale(cause),
                Self::CoupureLien => motifs::injection_coupure_lien(cause),
            }
        }

        /// Pose la condition de defaillance. Le lien reste observable cote phys.
        fn injecter(self, bench: &Bench) -> bifrost_core::Result<()> {
            match self {
                Self::Dpi => {
                    // Un DPI cote phys: hook input, drop de l'UDP de WireGuard,
                    // le reste du lien continue de passer. La chaine ne peut pas
                    // s'appeler `fwd`, mot reserve de nft: la version d'avant
                    // l'appelait ainsi et son ruleset etait une ERREUR de syntaxe
                    // avalee en silence, faute de lire le code de sortie de nft.
                    // Le DPI n'a donc jamais ete pose avant le 05/09/2026.
                    // `poser_nft` lit ce statut; le ruleset est nomme dans
                    // `rulesets_du_banc` pour que la recette d'acceptation le pose.
                    bench.poser_nft(NS_PHYS, &dpi_ruleset(WG_PORT))
                }
                Self::PerteTotale => bench.exec_ok(
                    NS_PHYS,
                    &[
                        "tc", "qdisc", "add", "dev", VETH_PHYS, "root", "netem", "loss", "100%",
                    ],
                ),
                Self::CoupureLien => {
                    bench.exec_ok(NS_PHYS, &["ip", "link", "set", VETH_PHYS, "down"])?;
                    std::thread::sleep(COUPURE_LIEN_BAS);
                    bench.exec_ok(NS_PHYS, &["ip", "link", "set", VETH_PHYS, "up"])?;
                    std::thread::sleep(COUPURE_LIEN_REMONTE);
                    Ok(())
                }
            }
        }

        /// Retire la condition. Best effort: le banc repart propre pour la phase
        /// suivante, et un demontage rate d'une phase deja mesuree n'a pas de
        /// trace a perdre. Le retrait nft passe par `retirer_nft`, qui JOURNALISE
        /// son echec au lieu de le ravaler. Les demontages `tc` et `ip`, eux,
        /// restent best effort par `let _ = ...exec_ok(...)`: la garde des sondes
        /// ne les voit PAS - elle ne vise que `.exec(`, et `.exec_ok(` n'en est
        /// pas une sous-chaine - mais ce ne sont ni des sondes ni du `nft`, juste
        /// des `tc`/`ip` dont l'echec de demontage n'a pas de trace a perdre.
        /// (Correction 5t: la version d'avant pretendait a tort ce `let _ =`
        /// << deja couvert par la garde des sondes >>.)
        fn retirer(self, bench: &Bench) {
            match self {
                Self::Dpi => {
                    bench.retirer_nft(NS_PHYS, &dpi_teardown());
                }
                Self::PerteTotale => {
                    let _ =
                        bench.exec_ok(NS_PHYS, &["tc", "qdisc", "del", "dev", VETH_PHYS, "root"]);
                }
                Self::CoupureLien => {
                    let _ = bench.exec_ok(NS_PHYS, &["ip", "link", "set", VETH_PHYS, "up"]);
                }
            }
        }
    }

    /// Les quatre phases de la fenetre de reconnexion, portees par UNE liste.
    ///
    /// Les trois premieres injectent une defaillance de lien (document 02,
    /// partie 4); la quatrieme, `Reprise` (5s), n'injecte rien mais fait JOUER a
    /// la machine a etats la sequence de reprise reelle. Le vecteur ET la
    /// recette `les_quatre_phases_de_reconnexion_sont_nommees_distinctement`
    /// tirent leurs noms de la meme liste [`TOUTES`]: une phase perdue en route
    /// cesse d'etre mesuree ET fait rougir cette recette, au lieu de ne laisser
    /// qu'un `dead_code` chez clippy comme avant 5s (second passage).
    #[derive(Clone, Copy)]
    enum PhaseReconnexion {
        Dpi,
        PerteTotale,
        CoupureLien,
        Reprise,
    }

    impl PhaseReconnexion {
        /// La source unique des quatre phases, lue par le vecteur et par sa
        /// recette. Une tranche et non un tableau de taille figee: en retirer
        /// une reste compilable et fait rougir la recette qui exige quatre noms,
        /// au lieu d'un echec de compilation qui n'est pas une recette rouge.
        const TOUTES: &'static [PhaseReconnexion] = &[
            Self::Dpi,
            Self::PerteTotale,
            Self::CoupureLien,
            Self::Reprise,
        ];

        /// L'injection de lien portee par cette phase, ou `None` pour la
        /// reprise, qui n'injecte rien mais pilote la machine a etats.
        fn injection(self) -> Option<InjectionDeLien> {
            match self {
                Self::Dpi => Some(InjectionDeLien::Dpi),
                Self::PerteTotale => Some(InjectionDeLien::PerteTotale),
                Self::CoupureLien => Some(InjectionDeLien::CoupureLien),
                Self::Reprise => None,
            }
        }

        /// Le nom de la phase: celui de son injection, ou [`NOM_REPRISE`].
        fn nom(self) -> &'static str {
            match self.injection() {
                Some(injection) => injection.nom(),
                None => NOM_REPRISE,
            }
        }
    }

    /// Ce qu'une phase de la fenetre de reconnexion a donne.
    enum PhaseReconnexionIssue {
        /// Temoin vu, zero clair sous kill switch. Porte le rapport de la phase.
        Etanche(String),
        /// La phase n'a pas pu conclure. Porte la raison, deja au catalogue.
        Sautee(String),
        /// Du clair est sorti sous kill switch. Porte le releve (la preuve) et,
        /// s'il coexistait, l'abandon qui aurait masque la fuite: la fuite prime,
        /// mais la raison FAILED dira les deux (5s, troisieme passage).
        Fuite(capture::Releve, Option<String>),
    }

    /// Le lien est perturbe de trois facons pendant que le tunnel tente de se
    /// reetablir, et la fenetre de reconnexion doit rester etanche a chacune.
    ///
    /// # Ce qui a change le 05/09/2026, et pourquoi (5i)
    ///
    /// La version d'avant posait le seul DPI, capturait, sondait HORS lien, et
    /// concluait a l'etancheite sur un pcap vide. Deux trous. D'abord aucun
    /// temoin ne prouvait que la capture voyait passer quoi que ce soit: le pcap
    /// vide se lisait comme une preuve d'etancheite. Ensuite les sondes hors
    /// lien restent dans le tunnel PAR LE ROUTAGE - kill switch ou pas - donc
    /// rien ne pouvait fuir en clair meme si le kill switch tombait, et le
    /// vecteur passait quoi qu'il arrive. Chaque phase mesure desormais DEUX
    /// choses, comme `daemon-mort`: un temoin vivant (la sonde de lien vue SANS
    /// kill switch), puis l'absence de clair sous kill switch. La sonde qui
    /// discrimine est `--probe-lan`: sa destination est ON-LINK, sa route ne
    /// passe pas par le tunnel, et elle repart en clair des que le kill switch
    /// ne tient plus. Le vecteur echoue si une phase echoue, en la nommant.
    ///
    /// # Ce que 5s ajoute: un tunnel vivant (b) et la reprise reelle (c)
    ///
    /// `kill-switch-on-drop`, qui precede, a detruit l'interface du tunnel. La
    /// version d'avant mesurait donc les trois phases sur un client SANS
    /// interface, alors que la fenetre de reconnexion reelle est un tunnel
    /// VIVANT qui n'arrive plus a refaire sa poignee de main. Ce vecteur
    /// RECONSTRUIT donc le client au depart (b, `construire_tunnel_client`, avec
    /// la cle publique du pair serveur inchangee), verifie qu'il est vivant
    /// AVANT d'injecter (une poignee de main doit aboutir), et mesure chaque
    /// phase sur ce tunnel vivant. Une quatrieme phase (c, `reprise-du-daemon`)
    /// fait ensuite JOUER a la machine a etats la sequence de reprise reelle.
    ///
    /// On ne presume pas de l'etat du kill switch laisse par la voisine: on le
    /// POSE au depart, et on le repose apres la reconstruction.
    fn reconnect_window(bench: &Bench, cles: &ClesTunnel) -> CheckOutcome {
        let v = CheckVector::ReconnectWindow;
        let exe = self_exe();

        // Repartir d'un banc ARME quel que soit ce que la voisine a laisse.
        if let Err(e) = arm(bench, true, Exemptions::AUCUNE) {
            return CheckOutcome::skipped(v, motifs::rearmement_impossible(&e.to_string()));
        }

        // (b) Reconstruire un tunnel client VIVANT: `kill-switch-on-drop` vient
        // de detruire l'interface. Les phases doivent mesurer une fenetre de
        // reconnexion reelle - un tunnel vivant qui n'arrive plus a se
        // reetablir - et non un client sans interface.
        if let Err(e) = construire_tunnel_client(bench, cles) {
            return CheckOutcome::skipped(
                v,
                motifs::reconstruction_tunnel_impossible(&e.to_string()),
            );
        }
        // La reconstruction a repose son propre routage; le kill switch, lui,
        // est repose ici pour ne rien presumer.
        if let Err(e) = arm(bench, true, Exemptions::AUCUNE) {
            return CheckOutcome::skipped(v, motifs::rearmement_impossible(&e.to_string()));
        }
        // Vivant AVANT d'injecter: une poignee de main doit aboutir, sinon on
        // mesurerait des phases sur un tunnel mort.
        if let Err(e) = wait_for_handshake(bench) {
            return CheckOutcome::skipped(
                v,
                motifs::tunnel_de_reconnexion_non_vivant(&e.to_string()),
            );
        }

        // Les quatre phases sont pilotees par la MEME liste
        // `PhaseReconnexion::TOUTES`: les trois injections de lien passent par
        // `mesurer_phase_reconnexion`, la reprise (c) par la sequence de la
        // machine a etats. Retirer une phase de la liste cesse de la mesurer ET
        // fait rougir la recette qui exige quatre noms - le trou que 5s (second
        // passage) ferme.
        let mut rapports: Vec<String> = Vec::new();
        for &phase in PhaseReconnexion::TOUTES {
            let issue = match phase.injection() {
                Some(injection) => mesurer_phase_reconnexion(bench, &exe, injection),
                None => mesurer_reprise_du_daemon(bench, &exe, cles),
            };
            match issue {
                PhaseReconnexionIssue::Etanche(rapport) => rapports.push(rapport),
                PhaseReconnexionIssue::Sautee(raison) => return CheckOutcome::skipped(v, raison),
                PhaseReconnexionIssue::Fuite(fuites, abandon) => {
                    // La fuite prime sur l'abandon qui coexistait, mais la raison
                    // FAILED dit les deux: le compte de clair ET l'abandon qui
                    // l'aurait masquee sans la mesure sous capture.
                    let raison = match &abandon {
                        Some(abandon) => motifs::fuite_et_abandon_pendant_reconnexion(
                            fuites.compte,
                            phase.nom(),
                            abandon,
                        ),
                        None => motifs::fuite_pendant_reconnexion(fuites.compte, phase.nom()),
                    };
                    return CheckOutcome::failed(v, raison, fuites.preuves_dites());
                }
            }
        }
        // Le separateur est joint AVANT l'appel: un litteral dans l'argument
        // d'un verdict, meme un simple separateur de `join`, ferait rougir la
        // garde de source qui refuse toute raison ecrite en ligne.
        let rapport = rapports.join("; ");
        CheckOutcome::passed(v, motifs::reconnexion_etanche_par_phase(&rapport))
    }

    /// Mesure une phase: injection, temoin, puis absence de clair sous kill
    /// switch. Retire l'injection avant de rendre, quoi qu'il arrive.
    fn mesurer_phase_reconnexion(
        bench: &Bench,
        exe: &str,
        injection: InjectionDeLien,
    ) -> PhaseReconnexionIssue {
        let nom = injection.nom();

        // 1. Poser la condition de defaillance de la fenetre de reconnexion.
        if let Err(e) = injection.injecter(bench) {
            return PhaseReconnexionIssue::Sautee(motifs::phase_reconnexion_sautee(
                nom,
                &injection.motif_injection(&e.to_string()),
            ));
        }

        // 2. Temoin: SANS kill switch, la sonde de lien DOIT etre vue cote phys.
        //    Un pcap vide sous kill switch ne prouve rien tant qu'on n'a pas
        //    etabli que la capture voit un paquet quand rien ne le bloque.
        if let Err(e) = disarm(bench) {
            injection.retirer(bench);
            return PhaseReconnexionIssue::Sautee(motifs::phase_reconnexion_sautee(
                nom,
                &motifs::desarmement_impossible(&e.to_string()),
            ));
        }
        let temoin = match temoin_de_lien(bench, exe, &format!("reconnect-{nom}-temoin")) {
            Ok(t) => t,
            Err(raison) => {
                let _ = arm(bench, true, Exemptions::AUCUNE);
                injection.retirer(bench);
                return PhaseReconnexionIssue::Sautee(motifs::phase_reconnexion_sautee(
                    nom, &raison,
                ));
            }
        };
        // Rearmer avant toute conclusion: la mesure de fuite d'en dessous et la
        // phase suivante exigent un banc arme.
        if let Err(e) = arm(bench, true, Exemptions::AUCUNE) {
            injection.retirer(bench);
            return PhaseReconnexionIssue::Sautee(motifs::phase_reconnexion_sautee(
                nom,
                &motifs::rearmement_impossible(&e.to_string()),
            ));
        }
        if temoin.releve.compte == 0 {
            injection.retirer(bench);
            return PhaseReconnexionIssue::Sautee(motifs::temoin_muet_reconnexion(
                nom,
                &temoin.dit,
            ));
        }

        // 3. Fuite: kill switch arme, rien ne doit sortir en clair.
        let issue = match fuite_de_lien(bench, exe, &format!("reconnect-{nom}")) {
            Ok(fuites) if fuites.compte == 0 => PhaseReconnexionIssue::Etanche(
                motifs::phase_temoin_puis_silence(nom, temoin.releve.compte),
            ),
            Ok(fuites) => PhaseReconnexionIssue::Fuite(fuites, None),
            Err(raison) => {
                PhaseReconnexionIssue::Sautee(motifs::phase_reconnexion_sautee(nom, &raison))
            }
        };
        injection.retirer(bench);
        issue
    }

    /// Le temoin d'une phase: la sonde de lien vue par la capture cote phys.
    struct TemoinDeLien {
        releve: capture::Releve,
        dit: String,
    }

    /// Capture cote phys pendant que la sonde de lien tourne, SANS kill switch.
    ///
    /// La sonde vise un voisin ON-LINK (`--probe-lan`): sa route ne passe pas
    /// par le tunnel, donc elle repart en clair quand rien ne la bloque. Un
    /// releve non nul prouve que la capture n'est pas aveugle pour cette phase;
    /// un releve nul rend la phase muette, jamais etanche.
    fn temoin_de_lien(bench: &Bench, exe: &str, tag: &str) -> Result<TemoinDeLien, String> {
        let cap = capture::Capture::start(bench, NS_PHYS, tag)
            .map_err(|e| motifs::capture_du_temoin_non_demarree(&e.to_string()))?;
        let dit = dire_sonde(bench, &[exe, "--probe-lan", PHYS_ADDR]);
        let pcap = cap
            .stop()
            .map_err(|e| motifs::capture_du_temoin_non_arretee(&e.to_string()))?;
        let releve = capture::relever(pcap.chemin(), &capture::leak_filter())
            .map_err(|e| motifs::analyse_du_temoin(&e.to_string()))?;
        Ok(TemoinDeLien { releve, dit })
    }

    /// Capture cote phys pendant que les sondes tentent de fuir, SOUS kill
    /// switch. La sonde de lien discrimine; les sondes hors lien et le reveil du
    /// tunnel completent la couverture. Le pcap est conserve si du clair passe,
    /// efface sinon.
    fn fuite_de_lien(bench: &Bench, exe: &str, tag: &str) -> Result<capture::Releve, String> {
        let cap = capture::Capture::start(bench, NS_PHYS, tag)
            .map_err(|e| motifs::capture_non_demarree(&e.to_string()))?;
        for _ in 0..3 {
            sonde_best_effort(
                bench,
                NS_CLIENT,
                &[exe, "--probe-lan", PHYS_ADDR],
                "sonde-lan-reconnexion",
            );
            sonde_best_effort(
                bench,
                NS_CLIENT,
                &[exe, "--probe", "all"],
                "sonde-reconnexion",
            );
            sonde_best_effort(
                bench,
                NS_CLIENT,
                &[exe, "--probe-tunnel", TUN_SERVER_ADDR],
                "reveil-reconnexion",
            );
            std::thread::sleep(Duration::from_millis(300));
        }
        let mut pcap = cap
            .stop()
            .map_err(|e| motifs::capture_non_arretee(&e.to_string()))?;
        match capture::relever(pcap.chemin(), &capture::leak_filter()) {
            Ok(fuites) if fuites.compte == 0 => Ok(fuites),
            Ok(fuites) => {
                pcap.garder();
                Ok(fuites)
            }
            Err(e) => Err(motifs::analyse_du_pcap(&e.to_string())),
        }
    }

    /// Ce qu'une sonde a fait: code de sortie et plainte, jamais avale.
    ///
    /// Le pendant de [`sonder_pour_la_mort`] pour une seule sonde: quand le
    /// temoin d'une phase est muet, sa raison doit dire si la sonde a emis ou
    /// echoue a se lancer, sinon un pcap vide a deux lectures indiscernables.
    fn dire_sonde(bench: &Bench, argv: &[&str]) -> String {
        match bench.exec(NS_CLIENT, argv) {
            Ok(out) if out.status.success() && out.stderr.is_empty() => "sortie 0".to_owned(),
            Ok(out) => format!(
                "sortie {}: {}",
                out.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&out.stderr)
                    .lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty())
                    .collect::<Vec<_>>()
                    .join(" / ")
            ),
            Err(e) => format!("sonde non lancee: {e}"),
        }
    }

    /// Le nom de la quatrieme phase de `reconnect-window` (5s): la reprise que
    /// le daemon joue REELLEMENT a la perte, pilotee par la machine a etats.
    const NOM_REPRISE: &str = "reprise-du-daemon";

    /// Un `TunnelConfig` de banc, uniquement pour PILOTER la machine a etats (c).
    ///
    /// Ses champs decrivent le client du banc (interface, marque, table, pair
    /// serveur), mais ils ne sont PAS executes tels quels: la sequence de (c)
    /// mappe chaque `Action` rendue a un executeur du banc, qui agit dans
    /// NS_CLIENT. La machine, elle, exige un `Event::Connect(TunnelConfig)` pour
    /// atteindre `Connected`, d'ou cette config. Une cle ou une adresse
    /// invalide fait sauter la phase plutot que paniquer.
    fn config_du_banc(cles: &ClesTunnel) -> Result<Box<bifrost_core::TunnelConfig>, String> {
        use bifrost_core::config::{
            DnsPolicy, Endpoint, IpNet, PeerConfig, Portage, ProfilTelemetrie, WgKey,
            WireguardParams,
        };
        let private_key: WgKey = cles
            .client_priv
            .parse()
            .map_err(|e: bifrost_core::Error| motifs::config_de_banc_impossible(&e.to_string()))?;
        let public_key: WgKey = cles
            .server_pub
            .parse()
            .map_err(|e: bifrost_core::Error| motifs::config_de_banc_impossible(&e.to_string()))?;
        let adresse: IpNet = format!("{TUN_CLIENT_ADDR}/{PREFIX}")
            .parse()
            .map_err(|e: bifrost_core::Error| motifs::config_de_banc_impossible(&e.to_string()))?;
        let endpoint: std::net::SocketAddr =
            format!("{PHYS_ADDR}:{WG_PORT}")
                .parse()
                .map_err(|e: std::net::AddrParseError| {
                    motifs::config_de_banc_impossible(&e.to_string())
                })?;
        let voie_v4: IpNet = "0.0.0.0/0"
            .parse()
            .map_err(|e: bifrost_core::Error| motifs::config_de_banc_impossible(&e.to_string()))?;
        let voie_v6: IpNet = "::/0"
            .parse()
            .map_err(|e: bifrost_core::Error| motifs::config_de_banc_impossible(&e.to_string()))?;
        Ok(Box::new(bifrost_core::TunnelConfig {
            interface: WG_CLIENT_IF.to_owned(),
            addresses: vec![adresse],
            mtu: 1420,
            dns: DnsPolicy {
                local_resolver: IpAddr::V4(Ipv4Addr::LOCALHOST),
                upstream: vec![IpAddr::V4(Ipv4Addr::new(10, 88, 0, 1))],
                embarque: false,
                anti_telemetrie: ProfilTelemetrie::Aucun,
            },
            allow_lan: false,
            portage: Portage::Wireguard(Box::new(WireguardParams {
                private_key,
                fwmark: BENCH_FWMARK,
                routing_table: BENCH_TABLE,
                listen_port: None,
                peer: PeerConfig {
                    public_key,
                    preshared_key: None,
                    endpoint: Endpoint { addr: endpoint },
                    allowed_ips: vec![voie_v4, voie_v6],
                    persistent_keepalive: 25,
                },
            })),
        }))
    }

    /// Le nom court d'une `Action`, pour dire ce que la sequence a joue.
    ///
    /// Match EXHAUSTIF sans joker: une action ajoutee au produit fait echouer la
    /// compilation ici, donc rougir la voie - c'est la garde de plus bas niveau
    /// contre une action de reprise nouvelle qu'aucun executeur ne jouerait.
    fn nom_action(action: &Action) -> &'static str {
        match action {
            Action::EngageKillSwitch(_) => "EngageKillSwitch",
            Action::DisengageKillSwitch => "DisengageKillSwitch",
            Action::BringTunnelUp(_) => "BringTunnelUp",
            Action::BringTunnelDown(_) => "BringTunnelDown",
            Action::ApplyDns(_) => "ApplyDns",
            Action::RestoreDns => "RestoreDns",
            Action::ScheduleRetry(_) => "ScheduleRetry",
        }
    }

    /// L'executeur du banc pour une `Action` de la sequence de reprise (c).
    ///
    /// Match EXHAUSTIF sans joker, comme `nom_action`. Les quatre actions que
    /// `TunnelLost` puis `RetryTimer` emettent ont un executeur reel dans le
    /// banc; les trois autres (deconnexion, DNS) ne sont pas emises par cette
    /// sequence et rendent une erreur NOMMEE plutot qu'un faux silence.
    fn executer_action_de_reprise(
        bench: &Bench,
        action: &Action,
        cles: &ClesTunnel,
    ) -> Result<(), String> {
        match action {
            // state.rs:289 (TunnelLost): teardown de l'interface et des routes.
            // Rejoue `netcfg::teardown` (netcfg.rs:133) dans NS_CLIENT.
            Action::BringTunnelDown(_) => {
                demonter_tunnel_client(bench);
                Ok(())
            }
            // state.rs:295 (ScheduleRetry): attente du backoff. C'est la seconde
            // SANS ROUTE ou seul le kill switch protege: on la sonde.
            Action::ScheduleRetry(delai) => {
                sonder_sans_route(bench, *delai);
                Ok(())
            }
            // state.rs:311 (RetryTimer): reengagement idempotent du kill switch.
            Action::EngageKillSwitch(_) => arm(bench, true, Exemptions::AUCUNE).map_err(|e| {
                motifs::executeur_de_reprise_impossible(nom_action(action), &e.to_string())
            }),
            // state.rs:312 (RetryTimer): remontee de l'interface, des routes et
            // des regles - la reconstruction de (b).
            Action::BringTunnelUp(_) => construire_tunnel_client(bench, cles).map_err(|e| {
                motifs::executeur_de_reprise_impossible(nom_action(action), &e.to_string())
            }),
            Action::DisengageKillSwitch | Action::ApplyDns(_) | Action::RestoreDns => {
                Err(motifs::action_de_reprise_inattendue(nom_action(action)))
            }
        }
    }

    /// Sonde la fenetre SANS ROUTE de la reprise, pendant la duree rendue par la
    /// machine (`ScheduleRetry`).
    ///
    /// `--probe-lan` est la sonde qui discrimine: sa destination est on-link, sa
    /// route ne passe pas par le tunnel, et elle repart en clair des que le kill
    /// switch ne tient plus. `--probe all` complete la couverture. Best effort:
    /// seuls les paquets comptent, la capture est ouverte par l'appelant.
    fn sonder_sans_route(bench: &Bench, duree: Duration) {
        let exe = self_exe();
        let echeance = Instant::now() + duree;
        loop {
            sonde_best_effort(
                bench,
                NS_CLIENT,
                &[&exe, "--probe-lan", PHYS_ADDR],
                "sonde-lan-reprise",
            );
            sonde_best_effort(bench, NS_CLIENT, &[&exe, "--probe", "all"], "sonde-reprise");
            if Instant::now() >= echeance {
                break;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    /// La sequence de reprise du daemon, jouee par la MACHINE A ETATS (c).
    ///
    /// # Ce qu'elle mesure, et ce que le banc ne mesure pas
    ///
    /// `kill-switch-on-drop` detruit l'interface a la main; les trois phases
    /// ci-dessus injectent une defaillance sur un tunnel vivant. Aucune ne fait
    /// REAGIR le produit. Or a la perte, `bifrost_core::state` emet une sequence
    /// precise (state.rs:289 `TunnelLost` -> BringTunnelDown puis
    /// ScheduleRetry(backoff(1)) = 1 s, kill switch tenu; state.rs:301
    /// `RetryTimer` -> EngageKillSwitch puis BringTunnelUp), et c'est pendant la
    /// SECONDE SANS ROUTE - interface et routes demontees, kill switch seul -
    /// que le releve du verificateur voit fuir sans kill switch (ETAT l.
    /// 925-935). Cette phase amene la machine en `Connected` (recette `connected`
    /// de state.rs: Connect, TunnelUp, HandshakeOk), lui donne `TunnelLost`, et
    /// EXECUTE les `Action` rendues avec les executeurs du banc, sous capture,
    /// temoin vu avant, zero clair exige pendant toute la sequence.
    ///
    /// La liste d'actions vient de la MACHINE, pas d'un tableau ecrit ici:
    /// ajouter une action au produit rougit dans `nom_action`,
    /// `executer_action_de_reprise` et la recette
    /// `chaque_action_de_reprise_a_un_executeur_dans_le_banc`.
    ///
    /// # Ce qui reste NON MESURE
    ///
    /// Le superviseur vivant lui-meme reste hors de portee. Le seuil de 180 s
    /// sans handshake est `HandshakeInfo::STALE_AFTER`
    /// (crates/bifrost-core/src/ports.rs:196), lu par `is_alive` (ports.rs:198);
    /// c'est `poll_handshake` (supervisor.rs:1322) qui, dans sa branche
    /// `Ok(Some(_)) if established` (supervisor.rs:1338-1342), emet alors
    /// `TunnelLost` « aucun handshake depuis plus de 180 s ». `regarder_couler`
    /// (supervisor.rs:1403), lui, ne tourne que TANT QUE le handshake est vivant
    /// et emet sur des criteres de DEBIT (`Perte::Gel`, `Perte::Debit`,
    /// `Perte::Muet`), pas sur ce seuil de handshake. Aucun banc portable ne fait
    /// attendre trois minutes, et on n'abaisse AUCUN seuil du produit pour le
    /// banc. On donne donc `TunnelLost` directement, et on mesure ce que la
    /// machine emet ENSUITE.
    fn mesurer_reprise_du_daemon(
        bench: &Bench,
        exe: &str,
        cles: &ClesTunnel,
    ) -> PhaseReconnexionIssue {
        let nom = NOM_REPRISE;

        // La config ne sert qu'a PILOTER la machine; les actions rendues sont
        // executees par le banc, pas par leurs charges utiles.
        let cfg = match config_du_banc(cles) {
            Ok(c) => c,
            Err(raison) => {
                return PhaseReconnexionIssue::Sautee(motifs::phase_reconnexion_sautee(
                    nom, &raison,
                ));
            }
        };

        // Amener la machine en Connected, exactement comme sa recette `connected`.
        let mut machine = StateMachine::new();
        machine.handle(Event::Connect(cfg));
        machine.handle(Event::TunnelUp);
        machine.handle(Event::HandshakeOk);
        if *machine.state() != bifrost_core::state::State::Connected {
            return PhaseReconnexionIssue::Sautee(motifs::phase_reconnexion_sautee(
                nom,
                &motifs::machine_pas_connectee(machine.state().name()),
            ));
        }

        // Temoin: SANS kill switch, la sonde de lien DOIT etre vue cote phys.
        if let Err(e) = disarm(bench) {
            return PhaseReconnexionIssue::Sautee(motifs::phase_reconnexion_sautee(
                nom,
                &motifs::desarmement_impossible(&e.to_string()),
            ));
        }
        let temoin = match temoin_de_lien(bench, exe, &format!("reconnect-{nom}-temoin")) {
            Ok(t) => t,
            Err(raison) => {
                let _ = arm(bench, true, Exemptions::AUCUNE);
                return PhaseReconnexionIssue::Sautee(motifs::phase_reconnexion_sautee(
                    nom, &raison,
                ));
            }
        };
        // Rearmer avant toute conclusion: la sequence exige un banc arme au
        // depart, et un vecteur n'a pas le droit de mentir a son voisin.
        if let Err(e) = arm(bench, true, Exemptions::AUCUNE) {
            return PhaseReconnexionIssue::Sautee(motifs::phase_reconnexion_sautee(
                nom,
                &motifs::rearmement_impossible(&e.to_string()),
            ));
        }
        if temoin.releve.compte == 0 {
            return PhaseReconnexionIssue::Sautee(motifs::temoin_muet_reconnexion(
                nom,
                &temoin.dit,
            ));
        }

        // La sequence, sous capture: TunnelLost puis RetryTimer, les actions
        // rendues executees dans l'ordre. La capture couvre le teardown, la
        // seconde sans route (ScheduleRetry, seule protection: le kill switch),
        // et la remontee.
        let cap = match capture::Capture::start(bench, NS_PHYS, &format!("reconnect-{nom}")) {
            Ok(c) => c,
            Err(e) => {
                return PhaseReconnexionIssue::Sautee(motifs::phase_reconnexion_sautee(
                    nom,
                    &motifs::capture_non_demarree(&e.to_string()),
                ));
            }
        };
        let mut sequence: Vec<&str> = Vec::new();
        let mut jetes_sans_route: u64 = 0;
        // La sequence, sous capture. Toute sortie ANTICIPEE (compteur illisible,
        // sondes non jetees, executeur en echec, reengagement sans effet) quitte
        // ce bloc avec la RAISON de son abandon, jamais en rendant l'issue: c'est
        // `conclure_sous_capture`, un seul appel plus bas, qui arrete la capture
        // et relit le pcap AVANT de conclure. Un abandon ne peut donc plus cacher
        // une fuite (5s, troisieme passage).
        let abandon: Option<String> = 'sequence: {
            for evenement in [
                Event::TunnelLost {
                    reason: String::from("perte simulee par le banc"),
                },
                Event::RetryTimer,
            ] {
                for action in machine.handle(evenement).actions {
                    sequence.push(nom_action(&action));
                    // (i) La seconde sans route vient de s'ecouler. Le compteur du
                    // kill switch, releve JUSTE avant `EngageKillSwitch` (donc
                    // apres `ScheduleRetry`), porte le compte de la fenetre sans
                    // route qu'`arm` remet a zero. Un zero veut dire que rien n'a
                    // ete sonde ou que le kill switch ne tenait pas.
                    if matches!(action, Action::EngageKillSwitch(_)) {
                        match compteur_du_kill_switch(bench) {
                            Ok((paquets, _octets)) => {
                                if paquets == 0 {
                                    let dit = dire_sonde(bench, &[exe, "--probe-lan", PHYS_ADDR]);
                                    break 'sequence Some(
                                        motifs::sondes_non_jetees_seconde_sans_route(paquets, &dit),
                                    );
                                }
                                jetes_sans_route = paquets;
                            }
                            Err(raison) => {
                                break 'sequence Some(motifs::phase_reconnexion_sautee(
                                    nom, &raison,
                                ));
                            }
                        }
                    }
                    if let Err(raison) = executer_action_de_reprise(bench, &action, cles) {
                        break 'sequence Some(motifs::phase_reconnexion_sautee(nom, &raison));
                    }
                    // (ii) `EngageKillSwitch` inerte passerait inapercu, le banc
                    // etant deja arme a son arrivee: la mesure honnete est le
                    // COMPTEUR qu'`arm` remet a zero en recreant la table.
                    if matches!(action, Action::EngageKillSwitch(_))
                        && let Err(raison) =
                            kill_switch_repose_avec_effet(bench, nom_action(&action))
                    {
                        break 'sequence Some(raison);
                    }
                }
            }
            None
        };
        // Le banc repart arme quoi qu'il arrive, abandon ou non: le voisin ne
        // mesurera pas un banc nu, et la capture tombe juste apres, dans la
        // conclusion.
        let _ = arm(bench, true, Exemptions::AUCUNE);
        // Un seul chemin de conclusion, emprunte par TOUTES les sorties de la
        // sequence: il arrete la capture et relit le pcap avant de rendre une
        // abstention. Du clair sorti => `Fuite` (FAILED), meme si un abandon
        // coexistait; sinon `Sautee(abandon)`, ou `Etanche` au bout.
        conclure_sous_capture(cap, nom, abandon, || {
            motifs::phase_reprise_etanche(
                temoin.releve.compte,
                jetes_sans_route,
                &sequence.join(", "),
            )
        })
    }

    /// Le seul chemin de conclusion SOUS CAPTURE de la sequence de reprise.
    ///
    /// Toute sortie de la sequence, entre `Capture::start` et la fin, passe par
    /// ici avec, le cas echeant, la RAISON de son abandon. On arrete la capture
    /// et on relit le pcap AVANT de rendre la moindre abstention:
    ///
    /// - du clair a passe: `Fuite` (FAILED), pcap garde, quel que soit l'abandon
    ///   qui voulait faire sauter la phase - la fuite prime, la raison dit les deux;
    /// - aucun clair, un abandon en cours: `Sautee(abandon)`, pcap efface;
    /// - aucun clair, rien a abandonner: `Etanche(rapport)`;
    /// - arret ou relecture impossible: `Sautee`, en nommant la non-mesure (et
    ///   l'abandon s'il coexistait) - l'absence de trace n'est pas une mesure.
    ///
    /// Le defaut ferme (5s, troisieme passage): un abandon (compteur illisible)
    /// rendait un SKIPPED sans relire le pcap, et des paquets en clair deja
    /// captures restaient orphelins - un SKIPPED cachait un FAILED.
    fn conclure_sous_capture(
        cap: capture::Capture,
        nom: &str,
        abandon: Option<String>,
        rapport_si_etanche: impl FnOnce() -> String,
    ) -> PhaseReconnexionIssue {
        let mut pcap = match cap.stop() {
            Ok(p) => p,
            Err(e) => {
                return PhaseReconnexionIssue::Sautee(abstention_sous_capture(
                    nom,
                    abandon.as_deref(),
                    &motifs::capture_non_arretee(&e.to_string()),
                ));
            }
        };
        match capture::relever(pcap.chemin(), &capture::leak_filter()) {
            Ok(fuites) if fuites.compte == 0 => match abandon {
                Some(raison) => PhaseReconnexionIssue::Sautee(raison),
                None => PhaseReconnexionIssue::Etanche(rapport_si_etanche()),
            },
            Ok(fuites) => {
                pcap.garder();
                PhaseReconnexionIssue::Fuite(fuites, abandon)
            }
            Err(e) => PhaseReconnexionIssue::Sautee(abstention_sous_capture(
                nom,
                abandon.as_deref(),
                &motifs::analyse_du_pcap(&e.to_string()),
            )),
        }
    }

    /// L'abstention SOUS CAPTURE quand l'arret ou la relecture du pcap a echoue.
    ///
    /// On n'a pas pu mesurer, donc on ne peut pas dire si l'abandon a masque une
    /// fuite: on nomme la cause de non-mesure, et l'abandon s'il coexistait.
    fn abstention_sous_capture(nom: &str, abandon: Option<&str>, cause: &str) -> String {
        match abandon {
            Some(raison) => motifs::abandon_et_mesure_impossible(raison, cause),
            None => motifs::phase_reconnexion_sautee(nom, cause),
        }
    }

    // Le client n'est plus utilise apres le dernier vecteur; on garde ce
    // symbole pour eviter un avertissement sur une constante importee.
    #[allow(dead_code)]
    const _CLIENT_ADDR: &str = CLIENT_ADDR;

    #[cfg(test)]
    mod tests {
        use super::*;

        /// (5t) Autant de sites d'injection dans la source que de rulesets
        /// nommes: un ruleset pose sans etre ajoute a `rulesets_du_banc` (ou
        /// l'inverse) fait diverger le compte.
        ///
        /// Recette pure. Elle compte les appels a poser/retirer - les seuls
        /// points d'entree qui posent nft, cf. la garde
        /// `toute_invocation_nft_passe_par_poser_ou_retirer` - dans `mod.rs`, et
        /// exige qu'ils soient aussi nombreux que la liste. Substitut assume au
        /// << compte des nft -f - >> suggere par la tranche: la centralisation
        /// dans les deux entrees ne laisse que DEUX litteraux nft -f - (dans
        /// netns.rs), tandis que les sites d'appel, eux, suivent un a un les
        /// rulesets que le banc pose.
        #[test]
        fn chaque_injection_du_banc_a_son_ruleset_dans_la_liste() {
            let chemin = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("src")
                .join("checks")
                .join("mod.rs");
            let source = std::fs::read_to_string(&chemin).expect("mod.rs de checks/ lisible");
            // Les sites d'injection du BANC vivent dans le code du banc, hors du
            // module de recettes. On ne compte donc que la source AVANT
            // `mod tests`: la recette d'acceptation pose en boucle les rulesets
            // de la liste PAR poser_nft (5t) et se compterait elle-meme sinon,
            // faisant diverger un compte qui n'a rien a voir avec elle.
            let code_du_banc = match source.find("mod tests {") {
                Some(i) => &source[..i],
                None => &source[..],
            };
            // Aiguilles en morceaux: la source de CETTE garde ne se compte pas.
            let poser = format!("poser{}", "_nft(");
            let retirer = format!("retirer{}", "_nft(");
            let mut sites = 0usize;
            for ligne in code_du_banc.lines() {
                if ligne.trim_start().starts_with("//") {
                    continue;
                }
                sites += ligne.matches(&poser).count();
                sites += ligne.matches(&retirer).count();
            }
            assert!(
                sites >= 2,
                "aucun site d'injection repere ({sites}): la lecture de la source a \
                 echoue, une garde aveugle est verte pour rien"
            );
            let liste = rulesets_du_banc();
            assert_eq!(
                sites,
                liste.len(),
                "le banc injecte par {sites} site(s) d'appel, mais rulesets_du_banc en \
                 nomme {}: un ruleset a ete pose sans etre ajoute a la liste, ou retire \
                 de la liste sans l'etre du banc",
                liste.len()
            );
            // (5t) Compter ne suffit pas: une entree DUPLIQUEE garde la taille
            // (un `dpi-teardown` remplace par un second `dpi`, taille 6) tout en
            // laissant un ruleset du banc sans entree distincte qui lui
            // corresponde. On exige donc des noms uniques ET des scripts uniques.
            let mut noms: Vec<&str> = liste.iter().map(|(nom, _, _)| *nom).collect();
            noms.sort_unstable();
            let mut noms_uniques = noms.clone();
            noms_uniques.dedup();
            assert_eq!(
                noms_uniques.len(),
                noms.len(),
                "deux entrees de rulesets_du_banc portent le meme nom (liste triee): {noms:?}"
            );
            let mut scripts: Vec<&str> =
                liste.iter().map(|(_, _, script)| script.as_str()).collect();
            scripts.sort_unstable();
            let mut scripts_uniques = scripts.clone();
            scripts_uniques.dedup();
            assert_eq!(
                scripts_uniques.len(),
                scripts.len(),
                "deux entrees de rulesets_du_banc portent le meme script: un ruleset du \
                 banc n'a alors pas d'entree distincte qui lui corresponde"
            );
        }

        /// (5t) Chaque ruleset que le banc pose par entree standard est ACCEPTE
        /// par nft, et un ruleset a chaine `fwd` (mot reserve) est REFUSE.
        ///
        /// # Ce que cette recette garde, et pourquoi elle POSE PAR `poser_nft`
        ///
        /// Le DPI d'avant << passait >> sur un ruleset que nft refusait, faute
        /// de lire le statut. Cette recette pose chaque ruleset de
        /// `rulesets_du_banc` dans un espace de noms jetable et exige `Ok`, puis
        /// pose le ruleset historique a chaine `fwd` (mot reserve) et exige
        /// `Err` dont le message porte `fwd` ou << syntax error >>. Elle prouve
        /// ainsi a la fois que tous les rulesets du banc sont valides et qu'elle
        /// SAIT voir un refus - sinon elle serait verte quoi qu'il arrive.
        ///
        /// La pose passe par [`Bench::poser_nft`], pas par un `Command` recopie
        /// a cote: c'est LE point du 5t. Une recette qui posait par sa propre
        /// fermeture prouvait que les rulesets etaient valides, jamais que
        /// `poser_nft` LIT le refus; muter le coeur de `poser_nft` (statut lu
        /// puis ignore) ne rougissait alors nulle part. Ici le piege `fwd`
        /// traverse `poser_nft`: s'il ravale le statut, il rend `Ok` sur le
        /// `fwd` et la recette rougit.
        ///
        /// # La mesure qui fixe la forme (05/09/2026, essai-linux, nft 1.0.9)
        ///
        /// `nft -c -f -` (verification sans application) NE discrimine PAS sans
        /// root, mais PAS parce que l'analyse n'aurait pas lieu: l'analyse
        /// syntaxique TOURNE quand meme. Sur le ruleset a chaine `fwd`, ses cinq
        /// erreurs de syntaxe sortent AVANT le message << netlink: Error: cache
        /// initialization failed: Operation not permitted >>, qui vient en
        /// dernier. Le code de sortie vaut 1 dans les DEUX cas - ruleset valide
        /// comme ruleset `fwd` -, le cache netlink ne pouvant s'initialiser sans
        /// privilege: le code ne separe donc pas l'accepte du refuse. La recette
        /// pose donc dans un espace de noms jetable SOUS root (ou `nft -f -` rend
        /// 0 sur un valide, 1 sur le `fwd`), et rend SKIPPED motive sans root -
        /// une mesure qui ne peut pas tourner n'est jamais un PASSED.
        #[test]
        fn chaque_ruleset_du_banc_est_accepte_par_nft() {
            if !est_root() {
                println!(
                    "SKIPPED chaque_ruleset_du_banc_est_accepte_par_nft: pose sous root \
                     requise (nft -c ne discrimine pas sans root: cache netlink refuse), \
                     relancer avec sudo"
                );
                return;
            }
            let ns = format!("bfnftok-{}", std::process::id());
            let cree = std::process::Command::new("ip")
                .args(["netns", "add", &ns])
                .status()
                .expect("lancement de ip netns add");
            assert!(cree.success(), "creation de l'espace de noms jetable {ns}");

            // Gardien RAII du netns jetable: sa destruction est garantie a la
            // sortie de portee, panic compris. Un panic entre `netns add` et la
            // fin - une assertion, ou `poser_nft` qui deroule - ne laisse donc
            // plus le netns `bfnftok-<pid>` derriere lui (residu mesure par le
            // verificateur en simulant un panic dans `poser_nft`).
            struct NetnsJetable(String);
            impl Drop for NetnsJetable {
                fn drop(&mut self) {
                    let _ = std::process::Command::new("ip")
                        .args(["netns", "del", &self.0])
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null())
                        .status();
                }
            }
            let _netns_jetable = NetnsJetable(ns.clone());

            // Le banc jetable ne monte rien: il n'apporte que `poser_nft`, qui
            // pose dans le netns qu'on vient de creer et LIT le statut de nft.
            // C'est le vrai chemin du produit, celui que le FAIL du 5t reprochait
            // a la recette de contourner par un `Command` recopie a cote.
            // `ManuallyDrop` des sa construction: le `Drop` du banc
            // (`teardown_quiet` sur NS_CLIENT/NS_PHYS) ne tourne JAMAIS, meme en
            // deroulant sur un panic, donc il ne retire pas les namespaces d'un
            // vrai banc monte en parallele. Plus de `mem::forget` a placer au bon
            // endroit.
            let bench = std::mem::ManuallyDrop::new(Bench::sans_montage());

            let mut refuses = Vec::new();
            for (nom, _ns_cible, script) in rulesets_du_banc() {
                if let Err(e) = bench.poser_nft(&ns, &script) {
                    refuses.push(format!("{nom}: poser_nft a rendu Err [{e}]"));
                }
            }
            // Le piege: le ruleset historique, chaine `fwd` (mot reserve). nft
            // DOIT le refuser, et poser_nft DOIT rendre l'Err correspondante.
            let fwd = dpi_ruleset(WG_PORT).replace("chain entree", "chain fwd");
            let fwd_res = bench.poser_nft(&ns, &fwd);

            // Plus de `mem::forget` ni de `netns del` a la main: le gardien RAII
            // detruit le netns a la sortie de portee, le `ManuallyDrop` neutralise
            // le `Drop` du banc. On peut donc asserter directement, un panic ne
            // laissant plus rien derriere.
            assert!(
                refuses.is_empty(),
                "un ruleset que le banc pose est refuse par nft, ou poser_nft a echoue:\n{}",
                refuses.join("\n")
            );
            match fwd_res {
                Ok(()) => panic!(
                    "poser_nft a rendu Ok sur un ruleset a chaine `fwd` (mot reserve): son \
                     statut n'est pas lu, la recette serait verte quoi qu'il arrive"
                ),
                Err(e) => {
                    let msg = e.to_string();
                    assert!(
                        msg.contains("fwd") || msg.contains("syntax error"),
                        "poser_nft a bien rejete le `fwd` mais son erreur ne porte ni `fwd` \
                         ni << syntax error >>, le stderr de nft n'est donc pas remonte: [{msg}]"
                    );
                }
            }
        }

        /// (5t) Un retrait refuse par nft est JOURNALISE, jamais ravale.
        ///
        /// `retirer_nft` est best effort mais NE RAVALE PLUS le statut: un
        /// retrait refuse, ou un nft qui n'a pas tourne, part en `tracing::debug!`
        /// au lieu de disparaitre. Le banc ne fait tourner aucun abonne tracing,
        /// donc l'echec y est invisible; cette recette en installe un POUR CE FIL
        /// et provoque un retrait qui echoue (espace de noms inexistant): le
        /// journal doit en porter la trace. Muter `retirer_nft` pour ravaler
        /// (`let _ = self.exec_stdin(...)`) laisse le carnet vide et fait rougir.
        ///
        /// Observable SANS root: `ip netns exec <inexistant>` echoue avant tout
        /// privilege, donc la branche d'echec est atteinte partout ou ip existe.
        #[test]
        fn un_retrait_nft_refuse_est_journalise() {
            use std::sync::{Arc, Mutex};
            #[derive(Clone, Default)]
            struct Carnet(Arc<Mutex<Vec<u8>>>);
            impl std::io::Write for Carnet {
                fn write(&mut self, tampon: &[u8]) -> std::io::Result<usize> {
                    self.0.lock().unwrap().extend_from_slice(tampon);
                    Ok(tampon.len())
                }
                fn flush(&mut self) -> std::io::Result<()> {
                    Ok(())
                }
            }
            impl tracing_subscriber::fmt::MakeWriter<'_> for Carnet {
                type Writer = Carnet;
                fn make_writer(&self) -> Carnet {
                    self.clone()
                }
            }
            let carnet = Carnet::default();
            let abonne = tracing_subscriber::fmt()
                .with_writer(carnet.clone())
                .with_max_level(tracing::Level::DEBUG)
                .with_ansi(false)
                .finish();
            // Thread-local: retirer_nft tourne sur ce fil, l'evenement y arrive.
            let _garde = tracing::subscriber::set_default(abonne);

            // Un retrait dans un espace de noms qui n'existe pas: ip (ou nft) ne
            // peut pas aboutir, et retirer_nft doit le JOURNALISER.
            //
            // `ManuallyDrop` des sa construction: le `Drop` du banc jetable ne
            // tourne jamais, meme si une assertion panique plus bas, donc il ne
            // retire pas les namespaces d'un vrai banc. Cette recette ne cree
            // aucun netns, il n'y a rien d'autre a nettoyer.
            let bench = std::mem::ManuallyDrop::new(Bench::sans_montage());
            let ns = format!("bfabsent-{}", std::process::id());
            bench.retirer_nft(&ns, "delete table inet bifrost\n");

            let trace = String::from_utf8_lossy(&carnet.0.lock().unwrap()).into_owned();
            assert!(
                trace.contains("retrait nft best effort"),
                "un retrait nftables qui echoue n'a rien journalise (carnet: {trace:?}): son \
                 statut est ravale au lieu de partir en trace"
            );
        }

        /// (5t) La table du kill switch se reconnait par la LIGNE ENTIERE d'une
        /// sortie `nft list tables`, jamais par la sous-chaine du nom.
        ///
        /// Piege sur une sortie fabriquee: une table dont le nom PROLONGE le
        /// notre (`bifrost2`, `bifrost-old`) ne doit pas passer pour le kill
        /// switch. Sur la reconnaissance d'avant (`l.contains(ruleset::TABLE)`),
        /// `bifrost2` contient `bifrost` et la garde se laissait prendre - le
        /// dernier `assert!` le prouve. Recette pure, sans root.
        #[test]
        fn la_table_du_kill_switch_se_reconnait_par_la_ligne_entiere() {
            // Deux tables voisines et une d'une autre famille: aucune n'est le
            // kill switch.
            let sans = "table inet bifrost2\ntable ip6 bifrost-old\ntable inet autre";
            assert!(
                !table_du_kill_switch_dans(sans),
                "une table dont le nom prolonge le notre a ete prise pour le kill switch"
            );
            // La vraie ligne, au milieu de voisines, est reconnue.
            let avec = "table inet bifrost2\ntable inet bifrost\ntable ip6 other";
            assert!(table_du_kill_switch_dans(avec));
            // Temoin de la reconnaissance d'avant: la sous-chaine se serait
            // laissee prendre par `bifrost2`. Sans cela, le piege ne prouve rien.
            assert!(
                sans.contains(ruleset::TABLE),
                "le piege doit contenir la sous-chaine du nom, sinon il ne teste pas le \
                 defaut"
            );
        }

        /// Les quatre phases de la fenetre de reconnexion existent et se
        /// nomment differemment.
        ///
        /// Recette pure: elle tourne partout ou le module compile, sans root.
        /// La partie 4 du document 02 pose TROIS injections de defaillance, et
        /// 5s ajoute une quatrieme phase, `reprise-du-daemon`, ou la machine a
        /// etats joue la sequence reelle. Le vecteur echoue en nommant la phase
        /// fautive, donc deux phases de meme nom rendraient un echec
        /// inutilisable, et une phase perdue en route laisserait une injection
        /// non mesuree sans que rien ne rougisse.
        #[test]
        fn les_quatre_phases_de_reconnexion_sont_nommees_distinctement() {
            // Une seule source: la liste que le vecteur PILOTE. Retirer une
            // phase de `TOUTES` la fait disparaitre du vecteur ET fait rougir
            // ici, au lieu du seul `dead_code` d'avant, quand la recette poussait
            // elle-meme le nom de la reprise.
            let noms: Vec<&str> = PhaseReconnexion::TOUTES.iter().map(|p| p.nom()).collect();
            assert_eq!(
                noms.len(),
                4,
                "il faut les trois injections du document 02 plus la reprise (5s)"
            );
            for nom in &noms {
                assert!(
                    !nom.is_empty(),
                    "une phase sans nom ne peut pas etre nommee"
                );
            }
            let distincts: std::collections::BTreeSet<&str> = noms.iter().copied().collect();
            assert_eq!(
                distincts.len(),
                noms.len(),
                "deux phases portent le meme nom: {noms:?}"
            );
        }

        /// Le lecteur du compteur `bifrost-output-dropped` lit la forme que nft
        /// REND (`counter packets N bytes M`), et rien d'autre (5s, i).
        ///
        /// Recette pure: une sortie de `nft list chain` fabriquee entre, un
        /// couple (paquets, octets) sort. C'est le temoin INTERNE de la seconde
        /// sans route; sans lui, `sonder_sans_route` videe laisserait la phase
        /// `reprise-du-daemon` passer mot pour mot. La forme est celle mesuree
        /// par 5m et gardee par `regles_nft`: `counter comment "x"` seul, sans
        /// `packets N bytes M`, n'est pas un compteur vivant et ne se lit pas.
        #[test]
        fn le_compteur_de_sortie_jetee_se_lit_dans_le_rendu_de_nft() {
            let plein: Vec<String> = [
                "table inet bifrost {",
                "chain output {",
                "type filter hook output priority filter; policy drop;",
                "oifname \"lo\" accept",
                "counter packets 8 bytes 464 comment \"bifrost-output-dropped\"",
                "}",
                "}",
            ]
            .iter()
            .map(|l| (*l).to_owned())
            .collect();
            assert_eq!(compteur_sortie_jetee(&plein), Some((8, 464)));

            // Compteur a zero: la seconde sans route n'a rien fait jeter.
            let zero =
                vec!["counter packets 0 bytes 0 comment \"bifrost-output-dropped\"".to_owned()];
            assert_eq!(compteur_sortie_jetee(&zero), Some((0, 0)));

            // Table sans le compteur du kill switch: rien a lire.
            let sans = vec!["oifname \"lo\" accept".to_owned()];
            assert_eq!(compteur_sortie_jetee(&sans), None);

            // Le commentaire sans forme vivante `packets N bytes M`: pas un
            // compteur lu, comme `regles_nft` le distingue deja.
            let mal_forme = vec!["counter comment \"bifrost-output-dropped\"".to_owned()];
            assert_eq!(compteur_sortie_jetee(&mal_forme), None);
        }

        /// Vrai si le banc a un executeur concret pour cette action de reprise.
        ///
        /// Le pendant lisible sans root de `executer_action_de_reprise`: les
        /// quatre actions que `TunnelLost` puis `RetryTimer` emettent en ont un;
        /// les trois autres n'entrent pas dans la sequence. Match exhaustif sans
        /// joker: une action ajoutee au produit fait echouer la compilation ici
        /// comme dans l'executeur.
        fn reprise_action_a_un_executeur(action: &Action) -> bool {
            match action {
                Action::BringTunnelDown(_)
                | Action::ScheduleRetry(_)
                | Action::EngageKillSwitch(_)
                | Action::BringTunnelUp(_) => true,
                Action::DisengageKillSwitch | Action::ApplyDns(_) | Action::RestoreDns => false,
            }
        }

        /// Chaque action que la machine a etats emet a la perte a un executeur
        /// dans le banc (5s, c).
        ///
        /// La sequence de reprise ne joue pas un tableau ecrit a la main: elle
        /// execute les `Action` que `bifrost_core::state` rend a `TunnelLost`
        /// puis `RetryTimer`. Si le produit ajoutait a ces evenements une action
        /// que le banc ne sait pas jouer, la reprise la sauterait; cette recette
        /// la ferait rougir. Pure: aucune interface, aucun root, seulement la
        /// machine a etats et un classement.
        #[test]
        fn chaque_action_de_reprise_a_un_executeur_dans_le_banc() {
            let (client_priv, _) = super::super::wgapply::generate_keypair();
            let (_, server_pub) = super::super::wgapply::generate_keypair();
            let cles = ClesTunnel {
                client_priv,
                server_pub,
            };
            let cfg = config_du_banc(&cles).expect("config de banc valide");
            let mut machine = StateMachine::new();
            machine.handle(Event::Connect(cfg));
            machine.handle(Event::TunnelUp);
            machine.handle(Event::HandshakeOk);
            assert_eq!(*machine.state(), bifrost_core::state::State::Connected);

            let mut vues = 0usize;
            for evenement in [
                Event::TunnelLost {
                    reason: String::from("recette"),
                },
                Event::RetryTimer,
            ] {
                for action in machine.handle(evenement).actions {
                    vues += 1;
                    assert!(
                        reprise_action_a_un_executeur(&action),
                        "action sans executeur dans le banc: {}",
                        nom_action(&action)
                    );
                }
            }
            assert!(
                vues >= 4,
                "la sequence de reprise n'a rendu que {vues} action(s), au moins 4 attendues"
            );
        }

        /// La politique du banc doit rendre exactement l'exemption demandee.
        ///
        /// Le vecteur ne peut s'executer qu'en root, donc il est `SKIPPED` sur
        /// la plupart des machines. Ce test-la, lui, tourne partout ou le
        /// module compile: il verifie que ce que le vecteur ARME correspond a
        /// ce qu'il croit armer. Un `coeur_uid` perdu en route rendrait le
        /// vecteur muet, et un vecteur muet passe.
        #[test]
        fn la_politique_du_banc_porte_l_exemption_demandee() {
            let sans = bench_policy(false, Exemptions::AUCUNE);
            assert_eq!(sans.coeur_uid, None);
            let vide = regles_nft::regles_skuid(&ruleset::render(&sans));
            assert!(
                vide.is_empty(),
                "sans exemption, aucune regle par identite ne doit etre emise: {vide:?}"
            );

            let avec = bench_policy(false, Exemptions::coeur(COEUR_UID));
            assert_eq!(avec.coeur_uid, Some(COEUR_UID));
            let script = ruleset::render(&avec);
            let attendue = format!("meta skuid {COEUR_UID} accept");
            assert!(
                regles_nft::porte(&script, &attendue),
                "regle absente, entiere: {attendue}\n{script}"
            );
        }

        /// L'exception du resolveur doit etre BORNEE au :53 dans le plan que le
        /// banc arme, sinon le vecteur mesure une borne qui n'existe pas.
        ///
        /// Le contraire exact du test ci-dessus: pour le coeur on exige un
        /// `accept` nu, ici on l'interdit. Un `meta skuid N accept` sec ferait
        /// du resolveur un second transport, et la mesure 3 du vecteur
        /// passerait de silencieuse a bavarde sans que rien d'autre ne bouge.
        #[test]
        fn la_politique_du_banc_borne_l_exception_du_resolveur() {
            let p = bench_policy(false, Exemptions::resolveur(RESOLVEUR_UID));
            assert_eq!(p.resolveur_uid, Some(RESOLVEUR_UID));
            let script = ruleset::render(&p);
            for attendu in [
                format!("meta skuid {RESOLVEUR_UID} udp dport 53 accept"),
                format!("meta skuid {RESOLVEUR_UID} tcp dport 53 accept"),
                "udp dport 53 drop".to_owned(),
                "tcp dport 53 drop".to_owned(),
            ] {
                assert!(
                    regles_nft::porte(&script, &attendu),
                    "regle absente, entiere: {attendu}\n{script}"
                );
            }
            let large = format!("meta skuid {RESOLVEUR_UID} accept");
            assert!(
                !regles_nft::porte(&script, &large),
                "l'exception du resolveur est devenue une sortie large:\n{script}"
            );
            // Et rien d'autre sous cette identite: les deux regles du :53,
            // reconnues entieres, sont TOUTES ses regles.
            assert_eq!(
                regles_nft::regles_par_uid(&script, RESOLVEUR_UID).len(),
                2,
                "le resolveur porte d'autres regles que ses deux du :53:\n{script}"
            );
        }

        /// Le drapeau du profil accompagne toujours le compte.
        ///
        /// `Identite::restreindre` efface l'uid quand le profil ne demande pas
        /// `embarque`: un banc qui declarerait le compte sans le drapeau
        /// armerait un plan que le produit ne pose jamais, et sa mesure ne
        /// porterait sur rien.
        #[test]
        fn le_drapeau_du_profil_accompagne_le_compte_du_resolveur() {
            assert!(bench_policy(false, Exemptions::resolveur(RESOLVEUR_UID)).resolveur_embarque);
            assert!(!bench_policy(false, Exemptions::AUCUNE).resolveur_embarque);
            assert!(!bench_policy(false, Exemptions::coeur(COEUR_UID)).resolveur_embarque);
        }

        /// Les deux comptes du banc restent distincts.
        ///
        /// L'installateur refuse que le coeur et le resolveur partagent un UID,
        /// parce que les confondre donnerait au resolveur la sortie large du
        /// coeur. Un banc qui les confondrait mesurerait une seule exemption en
        /// croyant en mesurer deux.
        ///
        /// La regle est reconnue par son identite, mot pour mot, et non par la
        /// presence des chiffres de l'uid quelque part dans le texte: cette
        /// recette rougissait a uid 0 parce que `0` figure dans `127.0.0.1`,
        /// et « 6553 » est une sous-chaine de « 65533 ». Elle passait donc
        /// pour la mauvaise raison (5m).
        #[test]
        fn les_deux_comptes_du_banc_ne_se_confondent_pas() {
            assert_ne!(COEUR_UID, RESOLVEUR_UID);
            let coeur = ruleset::render(&bench_policy(false, Exemptions::coeur(COEUR_UID)));
            assert!(
                !regles_nft::regles_par_uid(&coeur, COEUR_UID).is_empty(),
                "le plan du coeur ne nomme pas le coeur:\n{coeur}"
            );
            assert!(
                regles_nft::regles_par_uid(&coeur, RESOLVEUR_UID).is_empty(),
                "le plan du coeur nomme le resolveur:\n{coeur}"
            );
            let resolveur =
                ruleset::render(&bench_policy(false, Exemptions::resolveur(RESOLVEUR_UID)));
            assert!(
                !regles_nft::regles_par_uid(&resolveur, RESOLVEUR_UID).is_empty(),
                "le plan du resolveur ne nomme pas le resolveur:\n{resolveur}"
            );
            assert!(
                regles_nft::regles_par_uid(&resolveur, COEUR_UID).is_empty(),
                "le plan du resolveur nomme le coeur:\n{resolveur}"
            );
        }

        /// Aucun des deux comptes du banc n'est root.
        ///
        /// L'invariant que la sous-chaine « 0 » faisait passer pour tenu, et
        /// qui ne l'etait par rien (5m). Il compte: root est le temoin de
        /// discrimination des deux vecteurs, l'identite qui doit rester
        /// bloquee pendant que l'exemption sort. Un banc dont le coeur ou le
        /// resolveur serait root mesurerait l'exemption avec son propre
        /// temoin.
        #[test]
        fn aucun_compte_du_banc_n_est_root() {
            assert_ne!(COEUR_UID, 0, "le coeur du banc est root");
            assert_ne!(RESOLVEUR_UID, 0, "le resolveur du banc est root");
        }

        /// Ce que le generateur emet pour le banc est reconnu dans ce que nft
        /// en REND.
        ///
        /// Les relectures ci-dessous sont la sortie reelle de
        /// `nft list chain inet bifrost output` pour les deux plans du banc,
        /// mesuree le 05/09/2026 sur essai-linux (nftables 1.0.9) et recopiee
        /// telle quelle. Le vecteur confronte ces deux textes sous root; ici
        /// la confrontation se joue sans root, sur la mesure. Si le
        /// generateur change la forme de ses regles par identite, ou si une
        /// version de nft les reecrit autrement, c'est ici que l'ecart se lit.
        #[test]
        fn les_regles_par_identite_emises_sont_reconnues_dans_le_rendu_de_nft() {
            let coeur = ruleset::render(&bench_policy(false, Exemptions::coeur(COEUR_UID)));
            let rendu_coeur = [
                "table inet bifrost {",
                "\tchain output {",
                "\t\ttype filter hook output priority filter; policy drop;",
                "\t\toifname \"lo\" accept",
                "\t\tmeta mark 0x0000ca6c accept",
                "\t\tudp sport 68 udp dport 67 accept",
                "\t\tip6 daddr fe80::/10 udp sport 546 udp dport 547 accept",
                "\t\ticmpv6 type { nd-router-solicit, nd-router-advert, nd-neighbor-solicit, \
                 nd-neighbor-advert, nd-redirect } accept",
                "\t\tip daddr 127.0.0.1 udp dport 53 accept",
                "\t\tip daddr 127.0.0.1 tcp dport 53 accept",
                "\t\tmeta skuid 65534 udp dport 53 drop",
                "\t\tmeta skuid 65534 tcp dport 53 drop",
                "\t\tmeta skuid 65534 accept",
                "\t\tcounter packets 0 bytes 0 comment \"bifrost-output-dropped\"",
                "\t}",
                "}",
            ]
            .join("\n");
            let ecart = regles_nft::ecart_skuid(&coeur, &rendu_coeur);
            assert!(ecart.est_vide(), "coeur: {}", ecart.dit());
            assert_eq!(regles_nft::regles_skuid(&rendu_coeur).len(), 3);

            let resolveur =
                ruleset::render(&bench_policy(false, Exemptions::resolveur(RESOLVEUR_UID)));
            let rendu_resolveur = [
                "table inet bifrost {",
                "\tchain output {",
                "\t\ttype filter hook output priority filter; policy drop;",
                "\t\toifname \"lo\" accept",
                "\t\tmeta mark 0x0000ca6c accept",
                "\t\tmeta skuid 65533 udp dport 53 accept",
                "\t\tmeta skuid 65533 tcp dport 53 accept",
                "\t\tudp dport 53 drop",
                "\t\ttcp dport 53 drop",
                "\t\tudp sport 68 udp dport 67 accept",
                "\t\tip6 daddr fe80::/10 udp sport 546 udp dport 547 accept",
                "\t\ticmpv6 type { nd-router-solicit, nd-router-advert, nd-neighbor-solicit, \
                 nd-neighbor-advert, nd-redirect } accept",
                "\t\tip daddr 127.0.0.1 udp dport 53 accept",
                "\t\tip daddr 127.0.0.1 tcp dport 53 accept",
                "\t\tcounter packets 0 bytes 0 comment \"bifrost-output-dropped\"",
                "\t}",
                "}",
            ]
            .join("\n");
            let ecart = regles_nft::ecart_skuid(&resolveur, &rendu_resolveur);
            assert!(ecart.est_vide(), "resolveur: {}", ecart.dit());
            assert_eq!(regles_nft::regles_skuid(&rendu_resolveur).len(), 2);

            // Et la confrontation n'est pas aveugle: le plan du coeur contre
            // le rendu du resolveur nomme les trois regles du coeur absentes
            // et les deux du resolveur en trop.
            let croise = regles_nft::ecart_skuid(&coeur, &rendu_resolveur);
            assert_eq!(croise.manquantes.len(), 3, "{}", croise.dit());
            assert_eq!(croise.en_trop.len(), 2, "{}", croise.dit());
        }

        fn mesures(resolveur_dns: usize, hors_53: usize, etranger: usize) -> MesuresResolveur {
            MesuresResolveur {
                repos: 2,
                repos_dns: 2,
                temoin: 0,
                resolveur_dns,
                resolveur_hors_53: hors_53,
                etranger,
            }
        }

        #[test]
        fn la_combinaison_attendue_vaut_reussite() {
            assert!(matches!(
                juger_resolveur(mesures(2, 0, 0)),
                IssueResolveur::Reussi(_)
            ));
        }

        /// LE test de ce vecteur, et le miroir exact de celui du coeur. Le
        /// resolveur amorce, aucune autre identite ne sort: tout semble en
        /// ordre, et pourtant l'exception vient d'en faire un second transport.
        #[test]
        fn un_resolveur_qui_sort_hors_du_53_est_une_fuite_et_pas_un_succes() {
            match juger_resolveur(mesures(2, 3, 0)) {
                IssueResolveur::Echec(r) => assert!(r.contains("transport"), "{r}"),
                autre => panic!("attendu un echec, obtenu {autre:?}"),
            }
        }

        #[test]
        fn une_exception_qui_matche_toutes_les_identites_est_une_fuite() {
            match juger_resolveur(mesures(2, 0, 4)) {
                IssueResolveur::Echec(r) => assert!(r.contains("identite"), "{r}"),
                autre => panic!("attendu un echec, obtenu {autre:?}"),
            }
        }

        /// L'ordre compte: la fuite se dit avant la panne, et la fuite
        /// d'identite avant celle du port. Un rapport qui nommerait la seconde
        /// enverrait corriger la borne alors que l'exception ne discrimine
        /// personne.
        #[test]
        fn deux_fuites_a_la_fois_nomment_d_abord_celle_de_l_identite() {
            match juger_resolveur(mesures(2, 3, 4)) {
                IssueResolveur::Echec(r) => assert!(r.contains("identite"), "{r}"),
                autre => panic!("attendu un echec, obtenu {autre:?}"),
            }
        }

        /// Une exception morte n'est pas une fuite, mais ce n'est pas un succes
        /// non plus: le resolveur ne pourrait pas resoudre le nom de son propre
        /// serveur chiffre, donc jamais demarrer.
        #[test]
        fn une_exception_morte_est_un_echec() {
            match juger_resolveur(mesures(0, 0, 0)) {
                IssueResolveur::Echec(r) => assert!(r.contains("ne matche pas"), "{r}"),
                autre => panic!("attendu un echec, obtenu {autre:?}"),
            }
        }

        /// Un temoin negatif muet rend les silences sous armement
        /// inattribuables: le vecteur s'abstient au lieu de passer.
        #[test]
        fn un_temoin_negatif_muet_ne_permet_aucune_conclusion() {
            for m in [
                MesuresResolveur {
                    repos: 0,
                    ..mesures(2, 0, 0)
                },
                MesuresResolveur {
                    repos_dns: 0,
                    ..mesures(2, 0, 0)
                },
            ] {
                assert!(
                    matches!(juger_resolveur(m), IssueResolveur::Ignore(_)),
                    "{m:?}"
                );
            }
        }

        /// Sur un banc ou le kill switch ne mord pas, les trois observations
        /// sous armement rendraient le meme resultat qu'une exception bornee.
        #[test]
        fn un_banc_ou_le_kill_switch_ne_mord_pas_ne_permet_aucune_conclusion() {
            let m = MesuresResolveur {
                temoin: 5,
                ..mesures(2, 0, 0)
            };
            match juger_resolveur(m) {
                IssueResolveur::Ignore(r) => assert!(r.contains("temoin invalide"), "{r}"),
                autre => panic!("attendu un Ignore, obtenu {autre:?}"),
            }
        }

        /// Une continuation de ligne mal placee laisse l'indentation DANS la
        /// chaine, et le message sort troue d'espaces sous les yeux de celui
        /// qui lit le rapport. Le pendant Windows garde deja ses messages ainsi.
        #[test]
        fn aucun_message_du_verdict_ne_porte_de_suite_d_espaces() {
            let cas = [
                mesures(2, 0, 0),
                mesures(2, 3, 0),
                mesures(2, 0, 4),
                mesures(0, 0, 0),
                MesuresResolveur {
                    repos: 0,
                    ..mesures(2, 0, 0)
                },
                MesuresResolveur {
                    repos_dns: 0,
                    ..mesures(2, 0, 0)
                },
                MesuresResolveur {
                    temoin: 5,
                    ..mesures(2, 0, 0)
                },
            ];
            for m in cas {
                let texte = match juger_resolveur(m) {
                    IssueResolveur::Reussi(r) | IssueResolveur::Ignore(r) => r,
                    IssueResolveur::Echec(r) => r,
                };
                assert!(!texte.contains("  "), "{m:?}: {texte}");
                assert!(!texte.is_empty(), "{m:?}: verdict sans raison");
            }
        }
    }
}

#[cfg(all(test, windows))]
mod tests_windows {
    use super::*;

    #[test]
    fn chaque_vecteur_porte_sa_propre_raison() {
        // Un motif global serait plus court et il a deja ete faux pendant des
        // semaines. Exiger des raisons DISTINCTES empeche d'y revenir sans
        // s'en apercevoir.
        let rapport = windows::run_all();
        let raisons: std::collections::BTreeSet<&str> =
            rapport.outcomes.iter().map(|o| o.detail.as_str()).collect();
        assert_eq!(
            rapport.outcomes.len(),
            CheckVector::ALL.len(),
            "il manque des vecteurs"
        );
        // Le seuil a longtemps ete `>= ALL.len() - 1`, ce qui tolerait
        // EXACTEMENT un motif duplique: la garde disait exiger des raisons
        // distinctes et laissait passer le premier doublon. Mesure du
        // 22/08/2026: en recopiant le motif de `coeur-exemption` sur
        // `resolveur-exemption`, la recette restait verte. Resserre a
        // l'egalite, elle rougit. C'est la deuxieme fois dans ce depot qu'une
        // garde est verte parce qu'elle ne regarde pas.
        assert_eq!(
            raisons.len(),
            CheckVector::ALL.len(),
            "deux vecteurs partagent un motif: {raisons:#?}"
        );
    }

    #[test]
    fn aucune_raison_ne_repete_les_deux_affirmations_tombees() {
        // "il faut des namespaces" et "il faut Npcap sur une VM dediee" ont ete
        // mesurees fausses le 18 aout 2026. Les reecrire ferait renoncer a une
        // mesure possible, ce qui est pire qu'un motif absent.
        //
        // Sur le CATALOGUE et non sur `run_all()`: la version d'avant ne
        // lisait que les motifs rendus par la machine courante, donc la
        // branche IPv6 que dev-windows n'atteint pas pouvait reecrire ce que
        // l'on s'interdit sans qu'aucune recette ne bouge. Mesure du
        // 23/08/2026 sur dev-windows: une suite de deux espaces glissee dans
        // ce motif-la laissait la suite verte.
        for (site, motif) in windows::motifs::catalogue() {
            let d = motif.to_lowercase();
            assert!(!d.contains("npcap"), "{site}: {d}");
            assert!(!d.contains("namespace"), "{site}: {d}");
            assert!(!d.contains("vm dediee"), "{site}: {d}");
        }
    }

    /// La forme, sur TOUT ce que ce cote sait dire.
    ///
    /// La recette voisine lit le rapport, donc les preuves et les motifs
    /// reellement rendus; celle-ci lit le catalogue, donc les branches que
    /// cette machine n'atteint pas. Les deux sont necessaires, et c'est la
    /// seconde qui manquait.
    #[test]
    fn aucun_motif_du_catalogue_n_est_vide_ni_troue_d_espaces() {
        let catalogue = windows::motifs::catalogue();
        assert_eq!(
            catalogue.len(),
            CheckVector::ALL.len(),
            "le catalogue ne couvre pas tous les vecteurs, branches comprises"
        );
        forme_des_messages(&catalogue);
    }

    /// Le rapport ne doit rien dire que le catalogue ne contienne.
    ///
    /// # Le trou que celle-ci ferme
    ///
    /// Les gardes du catalogue eprouvent `motifs`; le rapport, lui, vient de
    /// l'aiguillage `motif()`. Rien ne les reliait. Mesure du 23/08/2026 sur
    /// dev-windows: en remplacant l'appel a `motifs::startup_window()` par une
    /// phrase ecrite en ligne dans l'aiguillage, la suite entiere restait
    /// verte. Le catalogue continuait d'affirmer l'ancien texte pendant que le
    /// rapport en montrait un autre, garde par personne. La garde de source ne
    /// pouvait pas le voir non plus: la raison arrive a `skipped(` par une
    /// variable.
    ///
    /// `doh-bypass` est exclu, et lui seul: il s'execute vraiment, donc son
    /// verdict n'est pas un motif de saut.
    #[test]
    fn le_rapport_ne_dit_que_ce_que_le_catalogue_contient() {
        let catalogue: std::collections::BTreeSet<String> = windows::motifs::catalogue()
            .into_iter()
            .map(|(_, m)| m)
            .collect();
        for o in windows::run_all().outcomes {
            if o.vector == CheckVector::DohBypass {
                continue;
            }
            assert!(
                catalogue.contains(&o.detail),
                "{}: motif hors catalogue, donc garde par rien: [{}]",
                o.vector.id(),
                o.detail
            );
        }
    }

    /// Deux motifs identiques dans le catalogue, y compris entre les deux
    /// branches d'un meme vecteur, se lisent comme une seule cause.
    #[test]
    fn deux_motifs_du_catalogue_ne_se_lisent_pas_pareil() {
        let catalogue = windows::motifs::catalogue();
        let distincts: std::collections::BTreeSet<&str> =
            catalogue.iter().map(|(_, m)| m.as_str()).collect();
        assert_eq!(
            distincts.len(),
            catalogue.len(),
            "deux motifs Windows se lisent pareil: {catalogue:#?}"
        );
    }

    /// Le test d'origine exigeait `Skipped` PARTOUT et annoncait qu'il
    /// tomberait le jour ou un vecteur serait reellement cable. C'est arrive
    /// avec `doh-bypass`, qui ne pose aucun filtre, ne cree aucun adaptateur et
    /// ne coupe rien: il lit des configurations, donc rien ne justifiait de le
    /// renvoyer a une commande dediee. Il est retire de l'exigence, sciemment
    /// et lui seul. Les sept autres arment le kill switch et restent sautes.
    #[test]
    fn tous_restent_skipped_sauf_celui_qui_est_cable() {
        use bifrost_core::checks::Verdict;
        for o in windows::run_all().outcomes {
            // Ce qui ne bouge pas: aucun verdict sans raison, nulle part.
            assert!(!o.detail.is_empty(), "{} sans raison", o.vector.id());
            if o.vector == CheckVector::DohBypass {
                continue;
            }
            assert_eq!(o.verdict, Verdict::Skipped, "{}", o.vector.id());
        }
    }

    /// Une continuation de ligne `\` dans un litteral disparait quand rustfmt
    /// rejoint les deux lignes, et l'indentation reste alors DANS la chaine.
    /// Le code compile, les tests passent, et le message sort troue d'espaces
    /// sous les yeux de celui qui lit le rapport. Quinze messages du depot
    /// l'avaient, dont plusieurs depuis des semaines.
    ///
    /// L'exigence elle-meme est tenue par [`forme_des_messages`], partagee avec
    /// le pendant Linux: c'est la meme dette envers le meme lecteur, et deux
    /// copies auraient derive comme le reste.
    #[test]
    fn aucun_message_ne_porte_de_suite_d_espaces() {
        let mut messages = Vec::new();
        for o in windows::run_all().outcomes {
            messages.push((o.vector.id(), o.detail));
            for l in o.evidence {
                messages.push((o.vector.id(), l));
            }
        }
        forme_des_messages(&messages);
    }

    /// Un echec de `doh-bypass` sans preuve serait inexploitable: la raison
    /// nomme les fautifs, le releve dit ou en etait CHAQUE client, y compris
    /// ceux qui vont bien. Sans lui, impossible de relire un rapport sans avoir
    /// la machine sous la main.
    #[test]
    fn un_echec_doh_porte_l_etat_de_tous_les_clients() {
        use bifrost_core::checks::Verdict;
        let o = doh_registre::vecteur();
        if o.verdict == Verdict::Failed {
            assert_eq!(
                o.evidence.len(),
                doh_registre::clients().len(),
                "releve incomplet: {:?}",
                o.evidence
            );
        }
    }
}

/// Le pendant Linux des gardes ci-dessus, et ce qui l'en separe.
///
/// # Ce qui manquait
///
/// Les quatre gardes de `tests_windows` lisent `windows::run_all()`. Il n'en
/// existait AUCUN equivalent ici, donc les motifs du chemin Linux n'etaient
/// gardes sur aucune plateforme. Le 23/08/2026 un motif neuf a reecrit une des
/// deux affirmations tombees le 18 aout, et c'est la garde Windows qui l'a
/// attrape; le meme defaut ecrit dans un motif Linux serait passe.
///
/// # Pourquoi ces gardes ne lisent pas `linux::run_all()`
///
/// Parce que ce chemin ne se prete a aucune des deux lectures possibles:
/// sans privileges il s'arrete au premier prerequis et rend le MEME motif pour
/// neuf vecteurs, avec privileges il monte des espaces de noms, arme le kill
/// switch et coupe le reseau de la machine. Un `sudo cargo test` suffirait a
/// declencher le second. Voir [`linux::motifs`] pour le chemin retenu: les
/// motifs sont rendus par les fonctions que le produit appelle lui-meme, sans
/// monter de banc.
///
/// # Ce qui n'est pas repris de Windows, et pourquoi
///
/// - **La distinction vecteur par vecteur.** Sous Windows chaque vecteur saute
///   pour une raison qui lui est propre; sous Linux ils sautent ENSEMBLE, pour
///   une propriete de la machine - pas de root, pas de `tcpdump`. Exiger des
///   motifs distincts y serait faux. Ce qui les remplace est plus haut: un
///   motif partage doit dire ce qui manque ET a quoi cela sert.
/// - **Les deux affirmations tombees.** Elles disent ce que Windows ne peut pas
///   faire. Sous Linux, << il faut des espaces de noms >> est vrai et le motif
///   de root le dit a juste titre. Interdire ces mots ici interdirait une
///   phrase juste.
#[cfg(all(test, target_os = "linux"))]
mod tests_linux {
    use super::*;

    /// La forme, tenue par la MEME fonction que sous Windows.
    #[test]
    fn aucun_motif_du_chemin_linux_n_est_vide_ni_troue_d_espaces() {
        let catalogue = linux::motifs::catalogue();
        assert!(
            catalogue.len() >= 10,
            "catalogue trop maigre pour garder quoi que ce soit: {}",
            catalogue.len()
        );
        forme_des_messages(&catalogue);
    }

    /// Deux abstentions differentes ne doivent pas se lire pareil.
    ///
    /// Non pas vecteur par vecteur - sous Linux plusieurs vecteurs partagent
    /// legitimement un motif - mais SITE par site: deux causes distinctes qui
    /// rendraient la meme phrase enverraient chercher au mauvais endroit.
    #[test]
    fn deux_causes_differentes_ne_rendent_pas_la_meme_phrase() {
        let catalogue = linux::motifs::catalogue();
        let distincts: std::collections::BTreeSet<&str> =
            catalogue.iter().map(|(_, t)| t.as_str()).collect();
        assert_eq!(
            distincts.len(),
            catalogue.len(),
            "deux motifs Linux se lisent pareil: {:#?}",
            catalogue
        );
    }

    /// Un motif de prerequis doit dire ce qui manque ET a quoi cela sert.
    ///
    /// C'est ce qui remplace ici l'exigence de distinction: le motif est le
    /// meme pour neuf vecteurs, donc toute sa valeur tient dans ce qu'il rend
    /// actionnable. << il manque un outil >> ferait renoncer a une mesure
    /// possible, ce que ce depot paye deja ailleurs.
    #[test]
    fn chaque_prerequis_nomme_l_outil_et_son_usage() {
        for (bin, usage) in linux::motifs::PREREQUIS {
            let motif = linux::motifs::binaire_absent(bin, usage);
            assert!(motif.contains(bin), "l'outil n'est pas nomme: {motif}");
            assert!(motif.contains(usage), "l'usage a disparu: {motif}");
        }
        let root = linux::motifs::exige_root();
        assert!(
            root.contains("root"),
            "le motif de privilege ne dit pas ce qu'il faut: {root}"
        );
    }

    /// Un temoin muet doit toujours dire ce que la sonde a FAIT.
    ///
    /// Le silence a deux causes opposees - la sonde n'a rien emis, ou un filtre
    /// l'a arretee - et sans le compte rendu de la sonde elles sont
    /// indiscernables. C'est la lecon la plus chere de ce module, et elle
    /// n'etait tenue par aucune recette.
    #[test]
    fn un_temoin_muet_dit_toujours_ce_que_la_sonde_a_fait() {
        const DIT: &str = "sortie 7: refus du noyau";

        let sonde = linux::motifs::temoin_muet_sonde("dns", "temoin de desarmement");
        assert!(sonde.contains("dns"), "la sonde n'est pas nommee: {sonde}");
        assert!(
            sonde.contains("temoin de desarmement"),
            "le sort du desarmement a disparu, or c'est l'autre cause du silence: {sonde}"
        );

        let absente = linux::motifs::EtatChaine::Absente;
        let identite = linux::motifs::temoin_muet_identite("le coeur", DIT, &absente);
        assert!(
            identite.contains(DIT) && identite.contains("le coeur"),
            "compte rendu ou identite perdus: {identite}"
        );

        // Chaine presente: le motif doit dire que le desarmement a echoue,
        // sinon le lecteur cherchera du cote de la sonde.
        let presente = linux::motifs::EtatChaine::Presente(1);
        let pose = linux::motifs::temoin_muet_identite("le coeur", DIT, &presente);
        assert!(
            pose.contains("desarmement a echoue"),
            "une chaine encore posee doit etre nommee comme telle: {pose}"
        );
        assert_ne!(identite, pose, "les deux etats du banc se lisent pareil");

        let mort = linux::motifs::temoin_muet_apres_mort(DIT);
        assert!(mort.contains(DIT), "compte rendu des sondes perdu: {mort}");
    }

    /// Le seul motif du chemin Linux qu'une recette peut rendre en s'executant
    /// doit venir du catalogue.
    ///
    /// Le pendant du controle de confinement de `tests_windows`. Il ne couvre
    /// qu'un site, et c'est le seul possible ici: `linux::run_all()` n'est pas
    /// executable dans une recette, alors que `missing_prerequisite()` l'est,
    /// et c'est justement lui qui parle pour neuf vecteurs a la fois.
    ///
    /// En root - `sudo cargo test`, que rien n'interdit - tous les prerequis
    /// sont remplis et la fonction rend `None`. La recette s'abstient alors au
    /// lieu de conclure sur rien.
    #[test]
    fn le_motif_de_prerequis_vient_du_catalogue() {
        let Some(raison) = linux::missing_prerequisite() else {
            println!(
                "SKIPPED le_motif_de_prerequis_vient_du_catalogue: cette machine remplit \
                 tous les prerequis du harnais, aucun motif de saut a lire"
            );
            return;
        };
        let catalogue: std::collections::BTreeSet<String> = linux::motifs::catalogue()
            .into_iter()
            .map(|(_, m)| m)
            .collect();
        assert!(
            catalogue.contains(&raison),
            "motif de prerequis hors catalogue, donc garde par rien: [{raison}]"
        );
    }

    /// Une chaine qu'on n'a pas su lire n'est ni presente ni absente.
    ///
    /// Le troisieme etat existe parce que l'ancien `sortie_de` rendait la
    /// plainte de `nft` comme une ligne de regle: le motif annoncait alors
    /// << PRESENTE (1 lignes), donc le desarmement a echoue >> alors que
    /// personne n'avait rien lu, et envoyait chercher un desarmement rate qui
    /// n'avait peut-etre jamais eu lieu.
    #[test]
    fn une_chaine_illisible_ne_se_lit_ni_comme_presente_ni_comme_absente() {
        use linux::motifs::EtatChaine;

        assert_eq!(EtatChaine::depuis(Ok(Vec::new())), EtatChaine::Absente);
        assert_eq!(
            EtatChaine::depuis(Ok(vec!["une regle".to_owned()])),
            EtatChaine::Presente(1)
        );
        assert!(matches!(
            EtatChaine::depuis(Err("nft muet".to_owned())),
            EtatChaine::Illisible(_)
        ));

        let illisible = EtatChaine::Illisible("nft muet".to_owned());
        let texte = linux::motifs::temoin_muet_identite("le coeur", "sortie 0", &illisible);
        assert!(
            texte.contains("ILLISIBLE") && texte.contains("nft muet"),
            "l'etat inconnu n'est pas nomme: {texte}"
        );
        assert!(
            !texte.contains("desarmement a echoue"),
            "un listage rate se lit comme un desarmement rate: {texte}"
        );
        assert!(
            !texte.contains("absente, comme attendu"),
            "un listage rate se lit comme une chaine absente: {texte}"
        );
    }
}

/// La garde qui lit la SOURCE, la ou toutes les autres lisent des messages.
///
/// # Le trou qu'elle ferme
///
/// `linux::motifs` et `windows::motifs` rendent leurs catalogues sans banc et
/// sans privileges, et des recettes les eprouvent. Rien n'obligeait pourtant un
/// motif NEUF a y entrer: un `CheckOutcome::skipped(v, "une phrase")` ecrit en
/// ligne quelque part echappait a tout, sur les deux plateformes. C'est le trou
/// residuel que la tranche precedente avait laisse ouvert en le nommant.
///
/// Une garde qui lit des messages ne peut pas le fermer, par construction:
/// elle ne voit que ce que quelqu'un a pense a lui donner. Celle-ci lit les
/// fichiers.
///
/// # La regle
///
/// La raison d'un `skipped(` ne doit contenir AUCUN litteral de chaine. Elle
/// est donc soit un appel a `motifs::`, soit une variable qui en vient. La
/// regle est volontairement plus dure que << passer par `motifs::` >>: elle
/// couvre aussi `motifs::machin("un bout de phrase")`, qui remettrait de la
/// prose hors catalogue par la porte de derriere.
///
/// # Ce qu'elle ne sait pas lire
///
/// Elle ignore une occurrence precedee de `//` sur sa ligne, donc les mentions
/// en commentaire. Elle suit les guillemets doubles et leurs echappements a
/// partir de l'occurrence, mais pas les chaines brutes `r"..."`: il n'y en a
/// aucune dans un argument de `skipped(` aujourd'hui, et une qui apparaitrait
/// serait comptee comme un litteral, donc refusee. Le sens de l'erreur est le
/// bon.
#[cfg(test)]
mod tests_source {
    use std::path::{Path, PathBuf};

    fn dossier_checks() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join("checks")
    }

    /// Les fichiers `.rs` de `checks/` ET de ses sous-dossiers, RECURSIVEMENT,
    /// tries pour que l'echec soit reproductible.
    ///
    /// La recursion ferme le point 5g: `checks/` est plat aujourd'hui, mais un
    /// sous-dossier futur echapperait a une lecture a plat, et une garde qui ne
    /// lit pas un fichier ne le garde pas. Un balayage vide (dossier illisible)
    /// rend `None`, ce que chaque garde traite en SKIPPED motive plutot qu'en
    /// vert aveugle.
    fn fichiers() -> Option<Vec<PathBuf>> {
        fn recolter(dir: &Path, dans: &mut Vec<PathBuf>) -> Option<()> {
            for e in std::fs::read_dir(dir).ok()? {
                let Ok(e) = e else { continue };
                let p = e.path();
                if p.is_dir() {
                    recolter(&p, dans)?;
                } else if p.extension().is_some_and(|x| x == "rs") {
                    dans.push(p);
                }
            }
            Some(())
        }
        let mut v = Vec::new();
        recolter(&dossier_checks(), &mut v)?;
        v.sort();
        Some(v)
    }

    /// Un appel trouve dans la source: son fichier, sa ligne, sa raison.
    struct Appel {
        fichier: String,
        ligne: usize,
        raison: String,
    }

    /// Le texte des arguments, depuis la parenthese ouvrante jusqu'a sa fermante.
    ///
    /// Rend `None` quand les parentheses ne se referment pas: mieux vaut ne
    /// rien conclure que conclure sur un fragment.
    fn arguments(source: &str, depuis: usize) -> Option<String> {
        let octets: Vec<char> = source[depuis..].chars().collect();
        let mut parens = 1usize;
        let mut dans_chaine = false;
        let mut echappe = false;
        let mut dans_commentaire = false;
        let mut sortie = String::new();
        for (i, c) in octets.iter().enumerate() {
            if dans_commentaire {
                if *c == '\n' {
                    dans_commentaire = false;
                    sortie.push('\n');
                }
                continue;
            }
            if dans_chaine {
                sortie.push(*c);
                if echappe {
                    echappe = false;
                } else if *c == '\\' {
                    echappe = true;
                } else if *c == '"' {
                    dans_chaine = false;
                }
                continue;
            }
            if *c == '/' && octets.get(i + 1) == Some(&'/') {
                dans_commentaire = true;
                continue;
            }
            match c {
                '"' => {
                    dans_chaine = true;
                    sortie.push(*c);
                }
                '(' => {
                    parens += 1;
                    sortie.push(*c);
                }
                ')' => {
                    parens -= 1;
                    if parens == 0 {
                        return Some(sortie);
                    }
                    sortie.push(*c);
                }
                _ => sortie.push(*c),
            }
        }
        None
    }

    /// Decoupe les arguments au premier niveau, hors chaines.
    fn au_premier_niveau(args: &str) -> Vec<String> {
        let mut morceaux = Vec::new();
        let mut courant = String::new();
        let mut imbrication = 0i32;
        let mut dans_chaine = false;
        let mut echappe = false;
        for c in args.chars() {
            if dans_chaine {
                courant.push(c);
                if echappe {
                    echappe = false;
                } else if c == '\\' {
                    echappe = true;
                } else if c == '"' {
                    dans_chaine = false;
                }
                continue;
            }
            match c {
                '"' => {
                    dans_chaine = true;
                    courant.push(c);
                }
                '(' | '[' | '{' => {
                    imbrication += 1;
                    courant.push(c);
                }
                ')' | ']' | '}' => {
                    imbrication -= 1;
                    courant.push(c);
                }
                ',' if imbrication == 0 => {
                    morceaux.push(courant.trim().to_owned());
                    courant = String::new();
                }
                _ => courant.push(c),
            }
        }
        if !courant.trim().is_empty() {
            morceaux.push(courant.trim().to_owned());
        }
        morceaux
    }

    /// Tous les appels a `mot(` de `checks/`, avec la raison passee a chacun.
    ///
    /// `mot` est `skipped`, `failed` ou `passed`: la meme lecture sert aux trois
    /// familles de verdict. La raison est l'argument 1 (0 pour un `all_`).
    fn appels(fichiers: &[PathBuf], mot: &str) -> Vec<Appel> {
        // L'aiguille est assemblee et non ecrite: ce fichier fait partie de
        // ceux qu'on relit, et une occurrence litterale s'y trouverait
        // elle-meme.
        let aiguille = format!("{mot}(");
        let mut trouves = Vec::new();
        for chemin in fichiers {
            let Ok(source) = std::fs::read_to_string(chemin) else {
                continue;
            };
            let nom = chemin
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            let mut depuis = 0usize;
            while let Some(rel) = source[depuis..].find(&aiguille) {
                let debut = depuis + rel;
                depuis = debut + aiguille.len();
                // Debut de ligne, pour ecarter les mentions en commentaire et
                // pour numeroter l'echec.
                let ligne_debut = source[..debut].rfind('\n').map(|i| i + 1).unwrap_or(0);
                let ligne = source[..debut].matches('\n').count() + 1;
                if source[ligne_debut..debut].contains("//") {
                    continue;
                }
                let global = source[ligne_debut..debut].contains("all_");
                let Some(args) = arguments(&source, depuis) else {
                    continue;
                };
                let morceaux = au_premier_niveau(&args);
                let rang = if global { 0 } else { 1 };
                let Some(raison) = morceaux.get(rang) else {
                    continue;
                };
                trouves.push(Appel {
                    fichier: nom.clone(),
                    ligne,
                    raison: raison.clone(),
                });
            }
        }
        trouves
    }

    /// Le motif portable tient la meme forme que les deux autres.
    ///
    /// Il ne se rend que sur un systeme qui n'est ni Linux ni Windows, donc sur
    /// aucune des deux machines qui font tourner ces recettes. Sans cette
    /// ligne, il ne serait garde nulle part - exactement le defaut que la
    /// branche IPv6 de Windows a revele.
    #[test]
    fn le_motif_portable_tient_la_forme() {
        let motifs = [(
            "portable/plateforme",
            super::motifs_portables::plateforme_sans_harnais("freebsd"),
        )];
        super::forme_des_messages(&motifs);
        assert!(
            motifs[0].1.contains("freebsd"),
            "le motif ne nomme pas le systeme: {}",
            motifs[0].1
        );
    }

    /// Aucune raison de saut n'est ecrite en ligne.
    #[test]
    fn aucune_raison_de_saut_n_est_un_litteral() {
        let Some(fichiers) = fichiers() else {
            println!(
                "SKIPPED aucune_raison_de_saut_n_est_un_litteral: {} est \
                 illisible, la source n'est pas la",
                dossier_checks().display()
            );
            return;
        };
        let appels = appels(&fichiers, "skipped");
        // Une garde qui n'a rien trouve ne peut pas rougir. Le seuil est bas et
        // grossier a dessein: il ne dit pas combien il devrait y en avoir, il
        // dit que la lecture a eu lieu.
        assert!(
            appels.len() >= 20,
            "seulement {} appel(s) reperes dans {} fichier(s): la lecture de la \
             source n'a pas fonctionne, et une garde aveugle est verte pour rien",
            appels.len(),
            fichiers.len()
        );
        let fautifs: Vec<String> = appels
            .iter()
            .filter(|a| a.raison.contains('"'))
            .map(|a| format!("{}:{} raison litterale [{}]", a.fichier, a.ligne, a.raison))
            .collect();
        assert!(
            fautifs.is_empty(),
            "une raison de saut est ecrite en ligne au lieu de passer par un \
             motif du catalogue, donc aucune garde ne la lira:\n{}",
            fautifs.join("\n")
        );
    }

    /// Ni un echec ni une reussite n'ecrit sa raison en ligne (5h).
    ///
    /// Le pendant de la garde ci-dessus pour les verdicts `failed`/`passed`. 5g
    /// avait fait entrer `sortie_de` par le catalogue; les raisons d'echec et de
    /// reussite, elles, restaient ecrites en `format!` a meme l'appel, donc hors
    /// du catalogue et vues par aucune garde: ni celle de forme, ni celle de
    /// distinction, et pas cette lecture de source, qui ne regardait que les
    /// sauts. La regle est la meme: aucun litteral de chaine dans la raison, ni
    /// direct ni par un `motifs::machin("phrase")` de derriere.
    #[test]
    fn aucune_raison_de_verdict_n_est_un_litteral() {
        let Some(fichiers) = fichiers() else {
            println!(
                "SKIPPED aucune_raison_de_verdict_n_est_un_litteral: {} est \
                 illisible, la source n'est pas la",
                dossier_checks().display()
            );
            return;
        };
        let mut verdicts = appels(&fichiers, "failed");
        verdicts.extend(appels(&fichiers, "passed"));
        assert!(
            verdicts.len() >= 12,
            "seulement {} verdict(s) reperes dans {} fichier(s): la lecture de la \
             source n'a pas fonctionne, et une garde aveugle est verte pour rien",
            verdicts.len(),
            fichiers.len()
        );
        let fautifs: Vec<String> = verdicts
            .iter()
            .filter(|a| a.raison.contains('"'))
            .map(|a| {
                format!(
                    "{}:{} raison de verdict litterale [{}]",
                    a.fichier, a.ligne, a.raison
                )
            })
            .collect();
        assert!(
            fautifs.is_empty(),
            "une raison d'echec ou de reussite est ecrite en ligne au lieu de passer \
             par un motif du catalogue, donc aucune garde de catalogue ne la lira:\n{}",
            fautifs.join("\n")
        );
    }

    /// Aucune erreur de lancement de sonde n'est avalee, et `plainte` ne gobe
    /// pas la sienne (5h).
    ///
    /// Deux membres de la meme famille que `sortie_de`. Les sondes et reveils du
    /// chemin Linux etaient lances par `let _ = bench.exec(...)`: le resultat
    /// n'est pas lu - ce sont les paquets qui comptent - mais `bench.exec` ne
    /// rend `Err` QUE si la commande n'a pas tourne, et ce cas-la disparaissait.
    /// Une sonde qui n'a rien emis se lisait alors comme une sonde bloquee, et
    /// l'absence de trace passait pour une mesure. De meme `plainte` faisait
    /// `try_wait().ok().flatten()`, ce qui rend le meme `None` pour un pair
    /// vivant et pour un etat illisible, et lisait sa sortie d'erreur par un
    /// `let _ =`.
    ///
    /// La garde lit la source: elle refuse `let _ = ....exec(...)` partout dans
    /// `checks/`, et refuse dans le corps de `plainte` le `.ok().flatten()` et le
    /// `let _ =`. Les teardown `let _ = ....exec_stdin(...)` ne sont PAS vises:
    /// `.exec(` ne matche pas `.exec_stdin(`, et un demontage best-effort qui
    /// suit la destruction du banc n'a pas de trace a perdre.
    #[test]
    fn aucune_erreur_de_sonde_n_est_avalee() {
        let Some(fichiers) = fichiers() else {
            println!(
                "SKIPPED aucune_erreur_de_sonde_n_est_avalee: {} est illisible, la \
                 source n'est pas la",
                dossier_checks().display()
            );
            return;
        };
        // A. Les sondes: aucune erreur de lancement avalee par `let _ =`.
        let mut avales = Vec::new();
        let mut total_exec = 0usize;
        for chemin in &fichiers {
            let Ok(source) = std::fs::read_to_string(chemin) else {
                continue;
            };
            let nom = chemin
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            for (i, ligne) in source.lines().enumerate() {
                // Les mentions en commentaire ne sont pas du code: la docstring
                // de cette recette parle elle-meme de `let _ = ....exec(...)`.
                if ligne.trim_start().starts_with("//") {
                    continue;
                }
                if ligne.contains(".exec(") {
                    total_exec += 1;
                    if ligne.contains("let _ =") {
                        avales.push(format!("{nom}:{} [{}]", i + 1, ligne.trim()));
                    }
                }
            }
        }
        assert!(
            total_exec >= 3,
            "aucun appel .exec repere ({total_exec}): la lecture de la source a echoue, \
             une garde aveugle est verte pour rien"
        );
        assert!(
            avales.is_empty(),
            "une erreur de lancement de sonde est avalee par `let _ =`: la commande peut \
             n'avoir pas tourne, et ce silence passe pour une sonde bloquee:\n{}",
            avales.join("\n")
        );

        // B. `plainte`: aucun ravalement d'erreur. On cherche, dans le corps de
        // `plainte`, deux formes assemblees en morceaux (point 3): un `.ok()`
        // suivi de `.flatten()` sur try_wait, et une liaison `let` a underscore.
        // La source de cette garde discute ces memes formes; les assembler evite
        // qu'un corps qui deborderait sur elle - regression de l'analyseur - n'y
        // trouve l'aiguille dans son propre texte.
        let source_mod = std::fs::read_to_string(dossier_checks().join("mod.rs"))
            .expect("mod.rs de checks/ lisible");
        // Ceinture et bretelles (5t): un intervalle qui deborde contiendrait une
        // seconde signature de fonction a la meme indentation et pourrait
        // engloutir un corps voisin. On le refuse en nommant les deux lignes.
        let interv_plainte = intervalle_de(&source_mod, "fn plainte")
            .expect("l'intervalle de fn plainte doit etre isolable pour etre garde");
        if let Some((sig, seconde)) = seconde_fn_dans_intervalle(&source_mod, interv_plainte) {
            panic!(
                "l'intervalle de fn plainte (mod.rs:{sig}..={}) contient une seconde \
                 signature de fonction a la meme indentation (mod.rs:{seconde}): il a \
                 deborde et pourrait engloutir un corps voisin",
                interv_plainte.1
            );
        }
        let corps = corps_de(&source_mod, "fn plainte")
            .expect("le corps de fn plainte doit etre isolable pour etre garde");
        let aig_flatten = format!(".ok().{}", "flatten()");
        let aig_let_ignore = format!("let {}", "_ =");
        assert!(
            !corps.contains(&aig_flatten),
            "plainte gobe l'erreur de try_wait en enchainant .ok() puis .flatten(): un \
             etat illisible se lit alors comme un pair vivant, et la lecture ratee \
             derriere est imputee au tunnel"
        );
        assert!(
            !corps.contains(&aig_let_ignore),
            "plainte gobe une erreur par une liaison `let` a underscore: un silence se lit \
             comme une absence de message"
        );
    }

    /// Les litteraux de chaine de `texte`, dans l'ordre, contenu seul (sans les
    /// guillemets). Saute les commentaires de ligne, les litteraux de caractere
    /// et les lifetimes; suit les echappements `\"` a l'interieur d'une chaine.
    /// CONSERVE l'antislash d'une sequence d'echappement (`\n`, `\r`, `\x..`,
    /// `\u{..}`): la garde de source le VOIT alors comme un caractere du jeton,
    /// la ou la source ecrit deux caracteres (antislash puis lettre) que le
    /// compilateur replierait en un separateur reel (cf. `nft_lecture_seule`).
    /// Sert a lire l'argv d'un appel repere par la garde nft.
    fn litteraux_de(texte: &str) -> Vec<String> {
        let chars: Vec<char> = texte.chars().collect();
        let mut lits = Vec::new();
        let mut i = 0usize;
        while i < chars.len() {
            let c = chars[i];
            if c == '/' && chars.get(i + 1) == Some(&'/') {
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
                continue;
            }
            if c == '\'' {
                if chars.get(i + 1) == Some(&'\\') {
                    i += 4;
                    continue;
                }
                if chars.get(i + 2) == Some(&'\'') {
                    i += 3;
                    continue;
                }
                i += 1;
                continue;
            }
            if c == '"' {
                let mut s = String::new();
                i += 1;
                let mut echappe = false;
                while i < chars.len() {
                    let d = chars[i];
                    i += 1;
                    if echappe {
                        s.push(d);
                        echappe = false;
                    } else if d == '\\' {
                        // Conserve l'antislash: la garde de source voit
                        // l'echappement, la ou un jeton deja replie le cacherait.
                        s.push(d);
                        echappe = true;
                    } else if d == '"' {
                        break;
                    } else {
                        s.push(d);
                    }
                }
                lits.push(s);
                continue;
            }
            i += 1;
        }
        lits
    }

    /// Les litteraux du PREMIER tableau `[...]` de niveau superieur de `args`
    /// (l'argv d'un appel du banc), ou `None` s'il n'y a pas de tableau. Un
    /// crochet ou un guillemet DANS une chaine ne compte pas: un premier argument
    /// litteral qui contiendrait `[` (le nom de l'espace de noms, par exemple) ne
    /// prend pas la place du tableau.
    fn argv_tableau(args: &str) -> Option<Vec<String>> {
        let chars: Vec<char> = args.chars().collect();
        let mut i = 0usize;
        let debut = loop {
            if i >= chars.len() {
                return None;
            }
            let c = chars[i];
            if c == '/' && chars.get(i + 1) == Some(&'/') {
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
                continue;
            }
            if c == '"' {
                i += 1;
                let mut echappe = false;
                while i < chars.len() {
                    let d = chars[i];
                    i += 1;
                    if echappe {
                        echappe = false;
                    } else if d == '\\' {
                        echappe = true;
                    } else if d == '"' {
                        break;
                    }
                }
                continue;
            }
            if c == '\'' {
                if chars.get(i + 1) == Some(&'\\') {
                    i += 4;
                    continue;
                }
                if chars.get(i + 2) == Some(&'\'') {
                    i += 3;
                    continue;
                }
                i += 1;
                continue;
            }
            if c == '[' {
                break i;
            }
            i += 1;
        };
        let mut profondeur = 0i32;
        let mut j = debut;
        let mut fin = None;
        while j < chars.len() {
            let c = chars[j];
            if c == '"' {
                j += 1;
                let mut echappe = false;
                while j < chars.len() {
                    let d = chars[j];
                    j += 1;
                    if echappe {
                        echappe = false;
                    } else if d == '\\' {
                        echappe = true;
                    } else if d == '"' {
                        break;
                    }
                }
                continue;
            }
            if c == '\'' {
                if chars.get(j + 1) == Some(&'\\') {
                    j += 4;
                    continue;
                }
                if chars.get(j + 2) == Some(&'\'') {
                    j += 3;
                    continue;
                }
                j += 1;
                continue;
            }
            if c == '[' {
                profondeur += 1;
            } else if c == ']' {
                profondeur -= 1;
                if profondeur == 0 {
                    fin = Some(j);
                    break;
                }
            }
            j += 1;
        }
        let fin = fin?;
        let interieur: String = chars[debut + 1..fin].iter().collect();
        Some(litteraux_de(&interieur))
    }

    /// Le texte de l'instruction commencant a l'offset d'octet `depuis` dans
    /// `source`: jusqu'au `;` ou a l'accolade ouvrante `{` de profondeur nulle
    /// (chaines, commentaires et litteraux de caractere sautes), borne a 4000
    /// caracteres. Sert a lire l'argv d'un `Command::new(...)` et de sa chaine
    /// `.args(...)`, la ou l'argv d'un appel du banc tient dans une seule paire de
    /// parentheses lisible par [`arguments`].
    fn fenetre_instruction(source: &str, depuis: usize) -> String {
        let chars: Vec<char> = source[depuis..].chars().collect();
        let mut d = 0i32;
        let mut sortie = String::new();
        let mut i = 0usize;
        while i < chars.len() && sortie.len() < 4000 {
            let c = chars[i];
            if c == '/' && chars.get(i + 1) == Some(&'/') {
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
                continue;
            }
            if c == '"' {
                sortie.push(c);
                i += 1;
                let mut echappe = false;
                while i < chars.len() {
                    let dd = chars[i];
                    sortie.push(dd);
                    i += 1;
                    if echappe {
                        echappe = false;
                    } else if dd == '\\' {
                        echappe = true;
                    } else if dd == '"' {
                        break;
                    }
                }
                continue;
            }
            if c == '\'' {
                if chars.get(i + 1) == Some(&'\\') {
                    sortie.extend(chars[i..(i + 4).min(chars.len())].iter());
                    i += 4;
                    continue;
                }
                if chars.get(i + 2) == Some(&'\'') {
                    sortie.push(chars[i]);
                    sortie.push(chars[i + 1]);
                    sortie.push(chars[i + 2]);
                    i += 3;
                    continue;
                }
                sortie.push(c);
                i += 1;
                continue;
            }
            match c {
                '(' | '[' => {
                    d += 1;
                    sortie.push(c);
                }
                ')' | ']' => {
                    d -= 1;
                    sortie.push(c);
                }
                ';' if d == 0 => break,
                '{' if d == 0 => break,
                _ => sortie.push(c),
            }
            i += 1;
        }
        sortie
    }

    /// Les jetons `apres` (ceux qui SUIVENT le programme nft) sont-ils une
    /// LECTURE? DELEGUE a la grammaire commune
    /// [`super::nft_argv::est_une_lecture`], partagee avec le refus runtime
    /// `netns::nft_en_lecture_seule`: une seule modelisation de la ligne de
    /// commande de nft 1.0.9 (getopt_long, ensembles fermes d'options, sortie de
    /// `nft --help`), plus deux jumelles a la main qui divergeaient. Le refus de
    /// l'antislash -- utile a la vue de SOURCE, ou une sequence d'echappement
    /// peut cacher un separateur reel, et sans effet sur un argv du banc -- vit
    /// desormais dans cette fonction commune.
    ///
    /// Les jeux d'essai de cette garde ont migre dans `super::nft_argv` (module
    /// commun, `#[cfg(test)]`), ou ils tournent sur les deux hotes.
    fn nft_lecture_seule(apres: &[String]) -> bool {
        let apres: Vec<&str> = apres.iter().map(String::as_str).collect();
        super::nft_argv::est_une_lecture(&apres)
    }

    /// Dans les litteraux d'une instruction (un `Command::new(...)` et sa chaine
    /// `.args(...)`), l'indice du PREMIER litteral qui designe le programme nft
    /// par son NOM DE FICHIER (cf. [`super::nft_argv::jeton_est_nft`]), a TOUTE
    /// position -- pas seulement en tete:
    ///
    /// - `Command::new("nft")` -> litteral 0;
    /// - `Command::new("/usr/sbin/nft")` -> litteral 0 (le chemin absolu, que le
    ///   FAIL 3 ratait);
    /// - `Command::new("ip").args(["netns", "exec", <ns>, "nft", ...])` -> le
    ///   litteral `nft`, ou qu'il tombe (le `<ns>` variable ne compte pas parmi
    ///   les litteraux);
    /// - `Command::new("env").args(["nft", ...])`, `"timeout", "5", "nft" ...`
    ///   -> le litteral `nft` a sa position.
    ///
    /// `None` si aucun litteral n'est un chemin nft.
    fn indice_nft_en_tete_command(lits: &[String]) -> Option<usize> {
        lits.iter().position(|l| super::nft_argv::jeton_est_nft(l))
    }

    /// L'offset d'octet ou commencent les recettes du fichier: le premier
    /// `mod tests {`. La garde nft ne lit que le CODE DE PRODUCTION (avant cette
    /// borne), pour deux raisons tenant l'une a l'autre:
    ///
    /// - les recettes qui EPROUVENT le refus runtime appellent `exec` avec un
    ///   argv `nft` a dessein (`nft_qui_modifie_est_refuse_avant_lancement`);
    ///   les balayer les signalerait a tort;
    /// - le texte de CETTE garde vit lui-meme apres cette borne (dans
    ///   `mod tests_source`), avec toutes ses aiguilles.
    ///
    /// Le code de production, lui, ne doit poser nft que par poser_nft /
    /// retirer_nft; ce qu'une obfuscation glisserait dans une recette est repris
    /// au runtime par le refus de `super::netns`.
    fn borne_production(source: &str) -> usize {
        source.find("mod tests {").unwrap_or(source.len())
    }

    /// (5t, sixieme passage) Toute invocation de `nft` QUI MODIFIE, quel que soit
    /// le chemin, passe par les deux seuls points d'entree qui lisent le statut:
    /// `Bench::poser_nft` (statut lu, stderr rendu) et `Bench::retirer_nft` (best
    /// effort, echec journalise). Une LECTURE (`nft list`, `nft -c`) est laissee
    /// passer. Aucun appelant de poser_nft ne jette le statut que poser_nft lit.
    ///
    /// # La classe que le cinquieme livre ne gardait pas
    ///
    /// La garde d'avant ne voyait QUE `.exec_stdin(`. Deux lignes naturelles lui
    /// echappaient donc dans `Dpi::injecter`/`Dpi::retirer`, passant clippy: un
    /// `bench.exec(NS_PHYS, &["nft", "add", ...])?` (l'`Output` jete, le `?` ne
    /// lit que l'echec de lancement, jamais le statut) et un
    /// `let _ = bench.exec_ok(NS_PHYS, &["nft", ...])`. La classe n'est pas
    /// << une injection par `exec_stdin` >> mais << une injection nft dont on ne
    /// lit pas le statut >>, par N'IMPORTE quel appel.
    ///
    /// # Ce que la garde VOIT (appels textuels, argv en tete)
    ///
    /// Dans le code de PRODUCTION (avant `mod tests {`, cf. [`borne_production`])
    /// de tous les fichiers de `checks/` ET de ses sous-dossiers (cf.
    /// [`fichiers`], recursif: le point 5g est ferme), elle repere:
    ///
    /// - les appels du banc `.exec(`, `.exec_ok(`, `.exec_stdin(`,
    ///   `.exec_stdin_brut(` et leurs formes UFCS `Bench::exec...(`, dont un
    ///   element de l'argv (via [`argv_tableau`]) designe nft par son NOM DE
    ///   FICHIER (via [`super::nft_argv::jeton_est_nft`]), a TOUTE position;
    /// - les `Command::new(` dont un litteral designe nft par son nom de fichier,
    ///   a toute position: `Command::new("nft")`, `Command::new("/usr/sbin/nft")`,
    ///   `Command::new("ip")` suivi de `["netns", "exec", <ns>, "nft", ...]`, ou
    ///   `Command::new("env").args(["nft", ...])` (cf.
    ///   [`indice_nft_en_tete_command`]);
    /// - tout jeton (argv de banc ou litteral) qui EMBARQUE une commande shell
    ///   nft (`sh -c "nft add ..."`, cf.
    ///   [`super::nft_argv::jeton_embarque_commande_nft`]) -- la seule concession
    ///   a la liste noire, jamais legitime, meme dans un corps d'entree.
    ///
    /// Chaque appel est lu ENTIER: [`arguments`] pour la paire de parentheses d'un
    /// appel du banc (multi-lignes comprises), [`fenetre_instruction`] pour la
    /// chaine d'un `Command`. Elle n'accepte que:
    ///
    /// - (a) un appel dans l'intervalle de lignes de `fn poser_nft(` ou de
    ///   `fn retirer_nft(` de `netns.rs` (via [`intervalle_de`]);
    /// - (b) une LECTURE, sur liste BLANCHE de verbes ([`nft_lecture_seule`]),
    ///   jamais une liste noire.
    ///
    /// Tout le reste rougit en nommant le fichier, la ligne et l'argv.
    ///
    /// # Ce que la garde NE VOIT PAS (obfuscations), et le filet
    ///
    /// Une garde textuelle ne suit pas un argv assemble a l'execution, une valeur
    /// passee par variable, ni les tours (`let ok = ..is_ok(); let _ = ok;`,
    /// `if let Ok(()) = .. {}`, `.map_err(drop).ok()`, une UFCS a la reception
    /// deroutee). CE QU'ELLE RATE, le REFUS RUNTIME de `super::netns` le rattrape:
    /// `Bench::exec`, `exec_ok` et `exec_stdin` rendent `Err` des qu'un `nft` a un
    /// verbe hors lecture seule, avant tout lancement; `poser_nft`/`retirer_nft`
    /// passent par `exec_stdin_brut`, l'entree brute que la garde de source
    /// cantonne a leurs deux corps. Ceinture (texte) et bretelles (runtime).
    ///
    /// # Appartenance PAR POSITION (5t)
    ///
    /// L'appartenance d'un appel a l'un des deux corps se decide par son
    /// INTERVALLE DE LIGNES, pas par une egalite de texte: une `poser_nft_bis`
    /// recopiee au corps identique tomberait hors des deux intervalles. Un
    /// `Command::new` n'est jamais dans un corps (poser/retirer passent par
    /// `exec_stdin_brut`), donc jamais accorde par (a).
    ///
    /// # L'appelant ne doit pas jeter le statut (5t)
    ///
    /// Lire le statut dans poser_nft ne sert a rien si l'APPELANT le ravale. On
    /// refuse un `let _ = ...poser_nft(...)`, une liaison `let _<nom> = ...` (que
    /// clippy laisse passer) et tout appel de poser_nft en position d'instruction
    /// (`;`) qui ne soit ni une liaison ni pris par `?`, `match`, `if let` ou
    /// `map_err`. On ACCEPTE une expression de queue, un `?`, un
    /// `match`/`if let`/`map_err`, ou une liaison `let nom = ...`.
    ///
    /// # Rouge d'abord
    ///
    /// Verte sur HEAD. Elle rougit sur (x11) `bench.exec(NS_PHYS, &["nft", ...])`,
    /// (x13) `let _ = bench.exec_ok(NS_PHYS, &["nft", ...])`, une variante
    /// multi-lignes, `Command::new("nft")`, `Command::new("ip")` sur
    /// `["netns", "exec", ns, "nft", "-f", "-"]`, le site historique
    /// `let _ = bench.exec_stdin(..., ["nft", "-f", "-"], ...)` hors des deux
    /// corps, une `poser_nft_bis` recopiee, ou un appelant `let _ = poser_nft`.
    #[test]
    fn toute_invocation_nft_passe_par_poser_ou_retirer() {
        let Some(fichiers) = fichiers() else {
            println!(
                "SKIPPED toute_invocation_nft_passe_par_poser_ou_retirer: {} est \
                 illisible, la source n'est pas la",
                dossier_checks().display()
            );
            return;
        };
        // Aiguilles construites en morceaux pour que la source de CETTE garde ne
        // se signale pas (elle vit apres `mod tests {`, donc deja hors balayage,
        // mais l'assemblage est la regle du depot).
        let appels_banc = [
            format!(".{}(", "exec"),
            format!(".{}(", "exec_ok"),
            format!(".{}(", "exec_stdin"),
            format!(".{}(", "exec_stdin_brut"),
            format!("Bench::{}(", "exec"),
            format!("Bench::{}(", "exec_ok"),
            format!("Bench::{}(", "exec_stdin"),
            format!("Bench::{}(", "exec_stdin_brut"),
        ];
        let aiguille_cmd = format!("Command::{}(", "new");
        let appel_poser = format!(".poser{}", "_nft(");
        let source_netns = std::fs::read_to_string(dossier_checks().join("netns.rs"))
            .expect("netns.rs de checks/ lisible");
        // Ancre sur la parenthese de la signature: `fn poser_nft(` ne matche pas
        // `fn poser_nft_bis(`, donc l'intervalle reste celui de la vraie.
        let interv_poser = intervalle_de(&source_netns, "fn poser_nft(")
            .expect("l'intervalle de fn poser_nft doit etre isolable pour etre garde");
        let interv_retirer = intervalle_de(&source_netns, "fn retirer_nft(")
            .expect("l'intervalle de fn retirer_nft doit etre isolable pour etre garde");
        // Ceinture et bretelles (5t): si l'intervalle d'une des deux entrees
        // contient une SECONDE signature de fonction a la meme indentation que la
        // sienne, c'est qu'il a deborde (litteral de caractere non saute par
        // `intervalle_de`, accolade desequilibree) et a pu engloutir une jumelle
        // recopiee dont l'entree passerait alors pour interne. On refuse un tel
        // intervalle en nommant les deux lignes, meme si `intervalle_de` venait a
        // regresser.
        for (quoi, interv) in [
            ("fn poser_nft", interv_poser),
            ("fn retirer_nft", interv_retirer),
        ] {
            if let Some((sig, seconde)) = seconde_fn_dans_intervalle(&source_netns, interv) {
                panic!(
                    "l'intervalle de {quoi} (netns.rs:{sig}..={}) contient une seconde \
                     signature de fonction a la meme indentation (netns.rs:{seconde}): il a \
                     deborde et pourrait engloutir une jumelle recopiee, dont l'entree nft \
                     passerait pour interne",
                    interv.1
                );
            }
        }
        let mut total = 0usize;
        let mut total_poser = 0usize;
        let mut hors = Vec::new();
        let mut avales = Vec::new();
        let mut jettent = Vec::new();
        for chemin in &fichiers {
            let Ok(source) = std::fs::read_to_string(chemin) else {
                continue;
            };
            let nom = chemin
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            let borne = borne_production(&source);
            let borne_ligne = source[..borne].matches('\n').count() + 1;
            let est_netns = nom == "netns.rs";

            // Ligne 1-based et texte de la ligne pour un offset d'octet donne.
            let situe = |debut: usize| -> (usize, String) {
                let ligne_debut = source[..debut].rfind('\n').map(|k| k + 1).unwrap_or(0);
                let ligne_fin = source[debut..]
                    .find('\n')
                    .map(|k| debut + k)
                    .unwrap_or(source.len());
                let ligne = source[..debut].matches('\n').count() + 1;
                (ligne, source[ligne_debut..ligne_fin].trim().to_owned())
            };
            let commente_avant = |debut: usize| -> bool {
                let ligne_debut = source[..debut].rfind('\n').map(|k| k + 1).unwrap_or(0);
                source[ligne_debut..debut].contains("//")
            };

            // --- A. Toute invocation nft, quel que soit le chemin ---
            // (a) Appels du banc: l'argv est le premier tableau de l'appel, lu
            //     entier (multi-lignes comprises) par `arguments`.
            for aiguille in &appels_banc {
                let mut depuis = 0usize;
                while let Some(rel) = source[depuis..].find(aiguille) {
                    let debut = depuis + rel;
                    depuis = debut + aiguille.len();
                    if debut >= borne || commente_avant(debut) {
                        continue;
                    }
                    let Some(args) = arguments(&source, depuis) else {
                        continue;
                    };
                    let Some(argv) = argv_tableau(&args) else {
                        continue;
                    };
                    let argv_str: Vec<&str> = argv.iter().map(String::as_str).collect();
                    let embarque = argv_str
                        .iter()
                        .any(|j| super::nft_argv::jeton_embarque_commande_nft(j));
                    let pos = argv_str
                        .iter()
                        .position(|j| super::nft_argv::jeton_est_nft(j));
                    if !embarque && pos.is_none() {
                        continue;
                    }
                    total += 1;
                    let (ligne, texte) = situe(debut);
                    // nft reconnu par nom de fichier a TOUTE position: la lecture
                    // se juge sur les jetons APRES nft, par la grammaire commune.
                    let ro = pos
                        .map(|p| nft_lecture_seule(&argv[p + 1..]))
                        .unwrap_or(false);
                    let dans_entree = est_netns
                        && (dans_intervalle(ligne, interv_poser)
                            || dans_intervalle(ligne, interv_retirer));
                    if embarque {
                        // Une commande nft embarquee dans un jeton shell n'est
                        // jamais legitime, meme dans un corps d'entree.
                        hors.push(format!("{nom}:{ligne} [commande nft embarquee] ({texte})"));
                    } else if !dans_entree && !ro {
                        hors.push(format!("{nom}:{ligne} [{}] ({texte})", argv.join(" ")));
                    }
                    if !ro && texte.contains("let _ =") {
                        avales.push(format!("{nom}:{ligne} [{}] ({texte})", argv.join(" ")));
                    }
                }
            }
            // (b) `Command::new(...)`: l'argv se lit dans l'instruction et sa
            //     chaine `.args(...)`. Un Command n'est jamais dans les deux
            //     corps (ils passent par `exec_stdin_brut`), donc jamais (a).
            {
                let mut depuis = 0usize;
                while let Some(rel) = source[depuis..].find(&aiguille_cmd) {
                    let debut = depuis + rel;
                    depuis = debut + aiguille_cmd.len();
                    if debut >= borne || commente_avant(debut) {
                        continue;
                    }
                    let lits = litteraux_de(&fenetre_instruction(&source, debut));
                    let embarque = lits
                        .iter()
                        .any(|j| super::nft_argv::jeton_embarque_commande_nft(j));
                    let idx = indice_nft_en_tete_command(&lits);
                    if !embarque && idx.is_none() {
                        continue;
                    }
                    total += 1;
                    let (ligne, texte) = situe(debut);
                    let ro = idx
                        .map(|p| nft_lecture_seule(&lits[p + 1..]))
                        .unwrap_or(false);
                    // Un `Command::new` n'est jamais dans un corps d'entree
                    // (poser/retirer passent par `exec_stdin_brut`).
                    if embarque {
                        hors.push(format!("{nom}:{ligne} [commande nft embarquee] ({texte})"));
                    } else if !ro {
                        hors.push(format!("{nom}:{ligne} [{}] ({texte})", lits.join(" ")));
                    }
                    if !ro && texte.contains("let _ =") {
                        avales.push(format!("{nom}:{ligne} [{}] ({texte})", lits.join(" ")));
                    }
                }
            }

            // --- B. Aucun appelant de poser_nft ne jette le statut ---
            for (i, ligne) in source.lines().enumerate() {
                if i + 1 >= borne_ligne || ligne.trim_start().starts_with("//") {
                    continue;
                }
                let t = ligne.trim();
                if ligne.contains(&appel_poser) {
                    total_poser += 1;
                    let sans_com = t.split(" //").next().unwrap_or(t).trim_end();
                    // Une liaison `let _<nom> =` (y compris `let _ =`) dit au
                    // compilateur << je n'utiliserai pas cette valeur >>: clippy
                    // ne la signale donc jamais en variable inutilisee, et le
                    // statut de nft s'y perd en silence - c'est la mutation (g),
                    // (b) affublee d'un nom. La seule liaison legitime des sites
                    // est `let fwd_res =`, SANS underscore: sous `-D warnings`,
                    // clippy (unused_variables) garantit qu'une telle variable
                    // est ENSUITE lue, donc que le statut est consomme. La garde
                    // prend les liaisons `let _...` que clippy laisse passer, et
                    // clippy prend les liaisons sans underscore laissees mortes:
                    // a elles deux, aucune liaison ne peut ravaler le statut.
                    let lie_a_underscore = sans_com
                        .strip_prefix("let ")
                        .map(|reste| reste.trim_start().starts_with('_'))
                        .unwrap_or(false);
                    let jette = lie_a_underscore
                        || sans_com.contains("let _ =")
                        || (sans_com.ends_with(';')
                            && !sans_com.starts_with("let ")
                            && !sans_com.contains('?')
                            && !sans_com.contains("match ")
                            && !sans_com.contains("if let ")
                            && !sans_com.contains("map_err"));
                    if jette {
                        jettent.push(format!("{nom}:{} [{t}]", i + 1));
                    }
                }
            }
        }
        assert!(
            total >= 2,
            "aucune invocation nft en tete reperee ({total}): la lecture de la source a \
             echoue, une garde aveugle est verte pour rien"
        );
        assert!(
            total_poser >= 4,
            "moins de quatre appels a poser_nft reperes ({total_poser}): la lecture de la \
             source a echoue, une garde aveugle est verte pour rien"
        );
        assert!(
            hors.is_empty(),
            "une invocation nft qui MODIFIE ne passe pas par poser_nft/retirer_nft (hors de \
             leur intervalle de lignes dans netns.rs) et n'est pas une lecture: son statut \
             peut n'etre lu par personne (le refus runtime la rattrape, mais la source \
             doit deja la refuser):\n{}",
            hors.join("\n")
        );
        assert!(
            avales.is_empty(),
            "un statut d'invocation nft qui modifie est ravale par `let _ =`: la commande \
             peut avoir ete refusee par nft sans que quiconque le voie:\n{}",
            avales.join("\n")
        );
        assert!(
            jettent.is_empty(),
            "un appelant de poser_nft jette le statut (let _ =, ou instruction terminee \
             par ; sans ? ni match/if let/map_err): lire le statut dans poser_nft ne sert \
             a rien si l'appelant l'abandonne:\n{}",
            jettent.join("\n")
        );
    }

    /// (5t) `disarm` RELIT l'etat de la table APRES le retrait, dans son corps.
    ///
    /// `disarm` pose `render_teardown()` par poser_nft (statut lu), puis relit
    /// l'etat POSE de la table pour attraper un `nft` qui rend 0 sans avoir rien
    /// retire - mauvais espace de noms, table homonyme ailleurs - et qui
    /// laisserait le banc arme en annoncant l'inverse. Cet effet ne se declenche
    /// que dans des conditions que le banc ne fabrique pas: aucune recette
    /// runtime ne le mesure. Cette garde-ci tient sa FORME a peu de frais - dans
    /// le corps de `disarm`, une relecture de cet etat POSE doit exister APRES
    /// l'appel a poser_nft. Retirer la relecture (l'etat de HEAD que 5t reecrit)
    /// la fait rougir.
    ///
    /// # Ceinture et aiguille en morceaux (5t)
    ///
    /// Le corps de `disarm` est isole par l'intervalle de [`intervalle_de`], seul
    /// analyseur d'accolades du fichier. Deux garde-fous ferment la classe ou un
    /// corps deborde jusqu'a la garde elle-meme et s'y trouve satisfait:
    ///
    /// - CEINTURE: si l'intervalle de `disarm` contient une SECONDE signature de
    ///   fonction a la meme indentation, c'est qu'il a deborde (litteral de
    ///   caractere non saute, accolade desequilibree); on le refuse en nommant
    ///   les deux lignes, meme si `intervalle_de` venait a regresser.
    /// - AIGUILLE EN MORCEAUX: la chaine cherchee APRES le retrait est assemblee
    ///   et jamais ecrite d'un tenant dans cette garde (comme `poser_nft` l'est
    ///   deja), pour qu'un corps qui deborderait sur elle ne trouve pas l'aiguille
    ///   dans son propre texte.
    ///
    /// Pure, sans root: elle lit la source.
    #[test]
    fn disarm_relit_l_effet_du_retrait() {
        let source_mod = std::fs::read_to_string(dossier_checks().join("mod.rs"))
            .expect("mod.rs de checks/ lisible");
        let ancre = "fn disarm(";
        // Un seul analyseur: le meme intervalle sert a la ceinture et au corps.
        let interv = intervalle_de(&source_mod, ancre)
            .expect("l'intervalle de fn disarm doit etre isolable pour etre garde");
        // Ceinture et bretelles (5t): un intervalle qui deborde contiendrait une
        // seconde signature de fonction a la meme indentation et pourrait
        // engloutir la garde elle-meme, dont le texte contient l'aiguille.
        if let Some((sig, seconde)) = seconde_fn_dans_intervalle(&source_mod, interv) {
            panic!(
                "l'intervalle de fn disarm (mod.rs:{sig}..={}) contient une seconde \
                 signature de fonction a la meme indentation (mod.rs:{seconde}): il a \
                 deborde et pourrait engloutir la garde elle-meme, qui contient l'aiguille",
                interv.1
            );
        }
        let corps = corps_de(&source_mod, ancre)
            .expect("le corps de fn disarm doit etre isolable pour etre garde");
        // Aiguilles en morceaux: la source de CETTE garde ne se signale pas.
        let poser = format!("poser{}", "_nft(");
        let i_pose = corps
            .find(&poser)
            .expect("disarm doit poser le retrait par poser_nft");
        let apres_pose = &corps[i_pose..];
        let aiguille = format!("table_du_kill_switch{}", "_posee");
        assert!(
            apres_pose.contains(&aiguille),
            "disarm ne relit pas l'etat de la table APRES le retrait: un nft qui rend 0 \
             sans rien retirer laisserait le banc arme en annoncant l'inverse"
        );
    }

    /// Une raison qui arrive a un verdict par une VARIABLE ne cache pas un
    /// litteral (5h).
    ///
    /// # Le trou que 5g avait nomme sans le fermer
    ///
    /// La lecture de source refuse un litteral ecrit DIRECTEMENT dans l'appel.
    /// Une variable y echappait: `let reason = "..."; skipped(v, &reason)`. Le
    /// 23/08 un sabotage exactement de cette forme n'avait pas rougi. On suit
    /// donc la variable jusqu'a sa liaison dans le meme fichier, et on refuse une
    /// liaison dont le membre droit EST une expression litterale - commence par
    /// un guillemet ou par `format!`.
    ///
    /// # Pourquoi ce critere et pas << contient un guillemet >>
    ///
    /// Une liaison a un `match`, a `motifs::...` ou a un appel de fonction n'est
    /// pas un litteral et ne doit pas etre signalee. En particulier
    /// `let raison = match v { ... unreachable!("...") ... }` de l'aiguillage
    /// Windows contient un guillemet sans qu'aucune raison ne soit litterale:
    /// un critere << contient un guillemet >> la refuserait a tort.
    ///
    /// # L'extension 5q
    ///
    /// La meme porte de derriere existe cote catalogue: `let p = format!("...");
    /// motifs::x(&p)` remettrait une phrase composee en ligne comme argument
    /// d'une fonction du catalogue. La garde suit donc aussi les identifiants
    /// passes a `motifs::` (voir [`idents_passes_au_catalogue`]), avec le meme
    /// critere de liaison. Les valeurs - comptes, noms de phase, sorties de
    /// sonde - ne sont pas liees a un litteral, donc jamais signalees.
    ///
    /// # Sur HEAD
    ///
    /// Aucune raison n'arrive par une variable liee a un litteral, ni au verdict
    /// ni au catalogue: la garde est verte ici. C'est la falsification qui prouve
    /// qu'elle mord - une raison ecrite `let reason = "..."` puis passee a un
    /// verdict, ou un `let p = format!("...")` passe a une fonction du catalogue.
    #[test]
    fn une_raison_par_variable_ne_cache_pas_un_litteral() {
        let Some(fichiers) = fichiers() else {
            println!(
                "SKIPPED une_raison_par_variable_ne_cache_pas_un_litteral: {} est \
                 illisible, la source n'est pas la",
                dossier_checks().display()
            );
            return;
        };
        let (ids, fautifs) = raisons_par_variable(&fichiers);
        // Non-aveugle: la lecture doit avoir repere des raisons passees par une
        // variable, sinon la partie qui suit ne verifie rien.
        assert!(
            ids.len() >= 2,
            "aucune raison par variable reperee ({}): la lecture de la source a echoue",
            ids.len()
        );
        assert!(
            fautifs.is_empty(),
            "une raison arrive a un verdict, ou une phrase arrive a une fonction du \
             catalogue, par une variable liee a un litteral, ce qu'aucune garde de \
             message ne verra:\n{}",
            fautifs.join("\n")
        );
    }

    /// L'analyseur d'accolades UNIQUE de ce fichier: pour la fonction dont la
    /// signature contient la premiere occurrence de `ancre`, il rend
    /// - `debut`: la ligne (1-based) de la signature,
    /// - `fin`: la ligne (1-based) de l'accolade fermante de MEME PROFONDEUR,
    /// - `texte`: le corps entre les deux accolades, commentaires de ligne
    ///   retires (chaines, litteraux de caractere et chaines brutes gardes
    ///   verbatim - une mention en commentaire n'est pas du code, les gardes
    ///   lisent du code).
    ///
    /// [`intervalle_de`] et [`corps_de`] en sont deux vues; aucune ne compte les
    /// accolades pour son compte. La version 5t precedente en portait DEUX:
    /// `corps_de` avait sa propre boucle a `profondeur`, jumelle de celle-ci mais
    /// sans le meme soin - elle ne sautait ni le litteral de caractere ni la
    /// chaine brute. Un `let _c = '{';` glisse dans `fn disarm` faisait alors
    /// deborder le corps rendu par `corps_de` jusqu'a la fin du module, ou le
    /// texte de la garde `disarm_relit_l_effet_du_retrait` contenait l'aiguille
    /// cherchee: la garde se satisfaisait de son propre texte. Une seule boucle,
    /// desormais.
    ///
    /// # Ce que le comptage d'accolades ignore
    ///
    /// Une accolade qui vit dans une chaine, un commentaire de ligne, un litteral
    /// de caractere ou une chaine brute n'ouvre ni ne ferme un bloc. On saute:
    ///
    /// - les commentaires de ligne (jusqu'au saut de ligne);
    /// - les chaines normales (echappement par contre-oblique);
    /// - les chaines brutes (`r"..."`, `r#"..."#`, n dieses, aucun echappement);
    /// - les litteraux de caractere (un caractere, ou un caractere echappe).
    ///
    /// Une lifetime (`'a`, `'static`) n'est PAS un litteral: c'est une apostrophe
    /// suivie d'un identifiant sans apostrophe fermante a la position attendue. La
    /// sauter comme un litteral avalerait le code qui la suit; on la laisse passer
    /// comme un caractere ordinaire.
    ///
    /// `None` si l'ancre manque ou si les accolades (ou une chaine) ne se
    /// referment pas: mieux vaut ne rien conclure que conclure sur un fragment.
    fn balayer_corps(source: &str, ancre: &str) -> Option<(usize, usize, String)> {
        let debut = source.find(ancre)?;
        let ligne_debut = source[..debut].bytes().filter(|&b| b == b'\n').count() + 1;
        let apres = &source[debut..];
        let ouvre = apres.find('{')?;
        // Ligne de l'accolade ouvrante (la signature peut tenir sur plusieurs
        // lignes), point de depart du comptage qui suit.
        let mut ligne = ligne_debut + apres[..ouvre].bytes().filter(|&b| b == b'\n').count();
        let chars: Vec<char> = apres[ouvre + 1..].chars().collect();
        let mut profondeur = 1usize;
        let mut texte = String::new();
        let mut i = 0usize;
        while i < chars.len() {
            let c = chars[i];
            if c == '\n' {
                ligne += 1;
            }
            // Commentaire de ligne: tout jusqu'au saut de ligne est inerte et
            // retire du texte. Le saut de ligne lui-meme est pousse au tour
            // suivant, si bien qu'une ligne de commentaire ne laisse que son
            // indentation et son retour a la ligne.
            if c == '/' && chars.get(i + 1) == Some(&'/') {
                i += 2;
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
                continue;
            }
            // Chaine brute `r"..."`, `r#"..."#`, n dieses: aucun echappement, fin
            // marquee par un guillemet suivi d'AUTANT de dieses. Pas une chaine
            // brute si `r` prolonge un identifiant (`render`), ni si un
            // identifiant suit les dieses (`r#type`, identifiant brut). Gardee
            // verbatim dans le texte.
            if c == 'r' && chars.get(i + 1).is_some_and(|d| *d == '"' || *d == '#') {
                let precedent_identifiant =
                    i > 0 && (chars[i - 1].is_ascii_alphanumeric() || chars[i - 1] == '_');
                let mut j = i + 1;
                let mut dieses = 0usize;
                while chars.get(j) == Some(&'#') {
                    dieses += 1;
                    j += 1;
                }
                if !precedent_identifiant && chars.get(j) == Some(&'"') {
                    j += 1;
                    let mut ferme = false;
                    while j < chars.len() {
                        if chars[j] == '\n' {
                            ligne += 1;
                        }
                        if chars[j] == '"' {
                            let mut k = j + 1;
                            let mut d = 0usize;
                            while d < dieses && chars.get(k) == Some(&'#') {
                                d += 1;
                                k += 1;
                            }
                            if d == dieses {
                                j = k;
                                ferme = true;
                                break;
                            }
                        }
                        j += 1;
                    }
                    if !ferme {
                        return None;
                    }
                    texte.extend(chars[i..j].iter());
                    i = j;
                    continue;
                }
                // Sinon `r` est un caractere ordinaire: on le traite plus bas.
            }
            // Chaine normale: echappement par contre-oblique, fin au guillemet
            // non echappe. Gardee verbatim dans le texte.
            if c == '"' {
                let mut j = i + 1;
                let mut echappe = false;
                let mut ferme = false;
                while j < chars.len() {
                    let d = chars[j];
                    if d == '\n' {
                        ligne += 1;
                    }
                    if echappe {
                        echappe = false;
                    } else if d == '\\' {
                        echappe = true;
                    } else if d == '"' {
                        ferme = true;
                        break;
                    }
                    j += 1;
                }
                if !ferme {
                    return None;
                }
                texte.extend(chars[i..=j].iter());
                i = j + 1;
                continue;
            }
            // Litteral de caractere vs lifetime. Garde verbatim dans le texte.
            if c == '\'' {
                if chars.get(i + 1) == Some(&'\\') {
                    // Litteral echappe: fin a la prochaine apostrophe,
                    // l'echappement ne portant que sur le caractere suivant.
                    let mut j = i + 2;
                    while j < chars.len() && chars[j] != '\'' {
                        if chars[j] == '\n' {
                            ligne += 1;
                        }
                        j += 1;
                    }
                    let fin_lit = (j + 1).min(chars.len());
                    texte.extend(chars[i..fin_lit].iter());
                    i = fin_lit;
                    continue;
                }
                if chars.get(i + 2) == Some(&'\'') {
                    // Litteral d'un seul caractere.
                    texte.extend(chars[i..i + 3].iter());
                    i += 3;
                    continue;
                }
                // Lifetime: l'apostrophe est un caractere ordinaire.
                texte.push(c);
                i += 1;
                continue;
            }
            match c {
                '{' => {
                    profondeur += 1;
                    texte.push(c);
                }
                '}' => {
                    profondeur -= 1;
                    if profondeur == 0 {
                        return Some((ligne_debut, ligne, texte));
                    }
                    texte.push(c);
                }
                _ => texte.push(c),
            }
            i += 1;
        }
        None
    }

    /// L'intervalle de lignes [debut, fin] (1-based, inclus) de la fonction dont
    /// la signature contient la premiere occurrence de `ancre`: de la ligne de la
    /// signature a la ligne de l'accolade fermante de MEME PROFONDEUR. Vue de
    /// [`balayer_corps`], seul analyseur d'accolades du fichier.
    ///
    /// `None` si l'ancre manque ou si les accolades ne se referment pas: mieux
    /// vaut ne rien conclure que conclure sur un fragment. Sert a decider
    /// l'appartenance d'un appel a un corps par sa POSITION, la ou une egalite de
    /// texte confondrait deux corps identiques (une fonction recopiee sous un
    /// autre nom, meme ligne d'entree standard).
    fn intervalle_de(source: &str, ancre: &str) -> Option<(usize, usize)> {
        balayer_corps(source, ancre).map(|(debut, fin, _)| (debut, fin))
    }

    /// Le corps `{...}` de la fonction dont la signature contient la premiere
    /// occurrence de `ancre`: le TEXTE entre accolades rendu par
    /// [`balayer_corps`], commentaires de ligne retires. Vue de [`balayer_corps`],
    /// il ne compte plus les accolades lui-meme (voir la doc de `balayer_corps`
    /// pour la classe de bug 5t que cette unification ferme).
    ///
    /// `None` si l'ancre est absente ou si les accolades ne se referment pas:
    /// mieux vaut ne rien conclure que conclure sur un fragment.
    fn corps_de(source: &str, ancre: &str) -> Option<String> {
        balayer_corps(source, ancre).map(|(_, _, texte)| texte)
    }

    /// (5t) `intervalle_de` saute litteraux de caractere et chaines brutes, sans
    /// prendre une lifetime pour un litteral, sur une source fabriquee dont
    /// l'intervalle est connu d'avance.
    ///
    /// # Ce que cette recette pince
    ///
    /// Le FAIL du 5t: `let _accolade = '{';` glisse dans `poser_nft` un `{` que
    /// l'ancien `intervalle_de` comptait sans jamais le refermer; l'intervalle
    /// debordait jusqu'a la fin du bloc `impl` et englobait une `poser_nft_bis`
    /// recopiee, dont l'entree standard passait alors pour interne. La source
    /// fabriquee ci-dessous porte les cinq pieges a la fois - une chaine qui
    /// contient `{`, un commentaire qui contient `}`, le litteral `'{'`, la
    /// chaine brute `r#"{"#`, une lifetime `'a` dans le corps - et son intervalle
    /// attendu est connu: la signature en ligne 1, l'accolade fermante de `cible`
    /// en ligne 8, `fn apres` en ligne 9 HORS de l'intervalle. Casser le saut
    /// d'un seul piege deplace la profondeur, l'intervalle deborde et la recette
    /// rougit.
    ///
    /// Recette pure, sans root.
    #[test]
    fn intervalle_de_saute_litteraux_et_chaines_brutes() {
        let source = concat!(
            "fn cible<'a>(x: &'a str) -> &'a str {\n",
            "    let s = \"accolade { dans une chaine\";\n",
            "    // commentaire avec } accolade\n",
            "    let c = '{';\n",
            "    let r = r#\"{ dans une chaine brute\"#;\n",
            "    let _t: &'a str = x;\n",
            "    x\n",
            "}\n",
            "fn apres() {}\n",
        );
        assert_eq!(
            intervalle_de(source, "fn cible"),
            Some((1, 8)),
            "l'intervalle de `fn cible` doit couvrir sa signature jusqu'a son accolade \
             fermante (lignes 1 a 8), sans deborder sur `fn apres`: un `{{` de chaine, de \
             commentaire, de litteral ou de chaine brute a ete compte a tort"
        );
        assert_eq!(
            intervalle_de(source, "fn apres"),
            Some((9, 9)),
            "l'intervalle de `fn apres` (corps vide sur une ligne) doit etre (9, 9)"
        );
        // `fn apres` (ligne 9) tombe HORS de l'intervalle de `cible`: la preuve
        // que l'intervalle ne deborde pas sur la fonction suivante.
        assert!(
            !dans_intervalle(9, intervalle_de(source, "fn cible").unwrap()),
            "l'intervalle de `fn cible` deborde sur `fn apres` (ligne 9)"
        );
    }

    /// (5t) `corps_de` rend le corps entre accolades sans deborder sur les
    /// pieges, sur une source fabriquee dont le corps attendu est connu d'avance.
    ///
    /// Meme classe que le FAIL de `intervalle_de`: un litteral de caractere `'{'`
    /// et un `}` de chaine brute que l'ancienne boucle propre de `corps_de`
    /// comptait, faisant deborder le corps rendu. `corps_de` delegue desormais a
    /// `balayer_corps` (seul analyseur), qui les saute. La source fabriquee porte
    /// le litteral `'{'`, une chaine brute avec un `}`, un `{` en chaine et un `}`
    /// en commentaire; le corps attendu retire les commentaires de ligne (une
    /// ligne de commentaire ne laisse que son indentation) et garde le reste
    /// verbatim, sans avaler `fn apres`.
    ///
    /// Recette pure, sans root.
    #[test]
    fn corps_de_rend_le_corps_sans_deborder_sur_les_pieges() {
        let source = concat!(
            "fn cible() {\n",
            "    let s = \"accolade { en chaine\";\n",
            "    // commentaire avec } et .ok().flatten()\n",
            "    let c = '{';\n",
            "    let r = r#\"} en chaine brute\"#;\n",
            "    let x = 1;\n",
            "}\n",
            "fn apres() { let _y = 2; }\n",
        );
        let corps = corps_de(source, "fn cible").expect("le corps de fn cible doit etre isolable");
        // Corps attendu: l'interieur des accolades, commentaires de ligne retires
        // (la ligne de commentaire ne laisse que son indentation), chaine,
        // litteral et chaine brute gardes verbatim. Le `'{'` et le `}` de la
        // chaine brute ne sont pas comptes: le corps s'arrete a l'accolade de
        // `cible`, sans deborder sur `fn apres`.
        let attendu = concat!(
            "\n",
            "    let s = \"accolade { en chaine\";\n",
            "    \n",
            "    let c = '{';\n",
            "    let r = r#\"} en chaine brute\"#;\n",
            "    let x = 1;\n",
        );
        assert_eq!(
            corps, attendu,
            "corps_de a deborde ou mal saute un piege (litteral, chaine brute, commentaire)"
        );
        assert!(
            !corps.contains("fn apres"),
            "corps_de a deborde sur `fn apres`: un piege d'accolade a ete compte a tort"
        );
        assert!(
            !corps.contains(".ok().flatten()"),
            "corps_de n'a pas retire le commentaire: une mention en commentaire n'est pas \
             du code"
        );
    }

    /// La ligne (1-based) est-elle dans l'intervalle inclusif de
    /// [`intervalle_de`]?
    fn dans_intervalle(ligne: usize, intervalle: (usize, usize)) -> bool {
        ligne >= intervalle.0 && ligne <= intervalle.1
    }

    /// L'intervalle contient-il une SECONDE signature de fonction (`fn `,
    /// `pub fn `, `pub(crate) fn `) a la meme indentation que sa ligne d'ancrage?
    ///
    /// Rend `Some((ligne_ancre, ligne_seconde))` si oui. Un intervalle sain
    /// s'arrete a l'accolade fermante de la fonction ancree et ne contient donc
    /// aucune autre signature de meme niveau; un intervalle qui en contient une a
    /// deborde (litteral de caractere non saute par [`intervalle_de`], accolade
    /// desequilibree) et a pu engloutir une jumelle recopiee. Ceinture et
    /// bretelles de la garde d'appartenance par position.
    fn seconde_fn_dans_intervalle(
        source: &str,
        intervalle: (usize, usize),
    ) -> Option<(usize, usize)> {
        let lignes: Vec<&str> = source.lines().collect();
        let (debut, fin) = intervalle;
        if debut == 0 || debut > lignes.len() {
            return None;
        }
        let indent_ancre = indentation(lignes[debut - 1]);
        let fin = fin.min(lignes.len());
        for no in (debut + 1)..=fin {
            let ligne = lignes[no - 1];
            let t = ligne.trim_start();
            let signature =
                t.starts_with("fn ") || t.starts_with("pub fn ") || t.starts_with("pub(crate) fn ");
            if signature && indentation(ligne) == indent_ancre {
                return Some((debut, no));
            }
        }
        None
    }

    /// Le nombre d'espaces ou de tabulations en tete de `ligne`.
    fn indentation(ligne: &str) -> usize {
        ligne
            .chars()
            .take_while(|c| *c == ' ' || *c == '\t')
            .count()
    }

    /// Si la raison passee a un verdict est une simple variable, son nom.
    ///
    /// `&reason` rend `reason`; `raison` rend `raison`; `motifs::foo(...)` ou
    /// `format!(...)` rendent `None` - ce ne sont pas des variables nues.
    fn identifiant_de_raison(raison: &str) -> Option<String> {
        let net = raison
            .trim()
            .trim_start_matches('&')
            .trim_start_matches('*')
            .trim();
        let est_ident = !net.is_empty()
            && net
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            && net.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
        est_ident.then(|| net.to_owned())
    }

    /// Les lignes ou `id` est lie a une expression LITTERALE.
    ///
    /// Litterale veut dire: le membre droit, une fois `=` franchi, commence par
    /// un guillemet ou par `format!`. Une liaison a un `match`, a `motifs::...`
    /// ou a un autre appel n'en est pas une.
    fn lignes_de_liaison_litterale(source: &str, id: &str) -> Vec<usize> {
        let mut trouves = Vec::new();
        for (i, ligne) in source.lines().enumerate() {
            let apres_let = match ligne.trim_start().strip_prefix("let ") {
                Some(r) => r,
                None => continue,
            };
            let apres_mut = apres_let.strip_prefix("mut ").unwrap_or(apres_let);
            let Some(apres_nom) = apres_mut.strip_prefix(id) else {
                continue;
            };
            let apres = apres_nom.trim_start();
            let Some(rhs) = apres.strip_prefix('=') else {
                continue;
            };
            // Ecarter `==` (comparaison, pas liaison).
            if rhs.starts_with('=') {
                continue;
            }
            let rhs = rhs.trim_start();
            if rhs.starts_with('"') || rhs.starts_with("format!") {
                trouves.push(i + 1);
            }
        }
        trouves
    }

    /// Les identifiants passes en argument a une fonction du catalogue (`motifs::`).
    ///
    /// L'extension 5q de la garde par variable: une variable liee a un `format!`
    /// puis passee a une fonction du catalogue y remettrait une phrase composee
    /// en ligne, par la porte de derriere - exactement ce qu'une fonction du
    /// catalogue existe pour empecher. Les VALEURS restent legitimes (comptes,
    /// noms de phase, sorties de sonde): seule la liaison a un litteral ou a
    /// `format!` est ensuite refusee, par `lignes_de_liaison_litterale`. On
    /// ecarte `motifs::catalogue()`, qui n'est pas une phrase.
    fn idents_passes_au_catalogue(source: &str) -> std::collections::BTreeSet<String> {
        let mut ids = std::collections::BTreeSet::new();
        let aiguille = "motifs::";
        let mut depuis = 0usize;
        while let Some(rel) = source[depuis..].find(aiguille) {
            let debut = depuis + rel;
            depuis = debut + aiguille.len();
            let ligne_debut = source[..debut].rfind('\n').map(|i| i + 1).unwrap_or(0);
            if source[ligne_debut..debut].contains("//") {
                continue;
            }
            let nom: String = source[depuis..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            if nom.is_empty() || nom == "catalogue" {
                continue;
            }
            let apres_nom = depuis + nom.len();
            if !source[apres_nom..].starts_with('(') {
                continue;
            }
            let Some(args) = arguments(source, apres_nom + 1) else {
                continue;
            };
            for morceau in au_premier_niveau(&args) {
                if let Some(id) = identifiant_de_raison(&morceau) {
                    ids.insert(id);
                }
            }
        }
        ids
    }

    /// Les identifiants de raison vus, et les liaisons litterales fautives.
    ///
    /// Deux sources d'identifiants: la raison passee a un verdict
    /// (`skipped`/`failed`/`passed`), et - depuis 5q - un argument passe a une
    /// fonction du catalogue. Dans les deux cas, une liaison du meme fichier a
    /// un litteral ou a un `format!` est refusee.
    fn raisons_par_variable(
        fichiers: &[PathBuf],
    ) -> (std::collections::BTreeSet<String>, Vec<String>) {
        let mut ids_globaux = std::collections::BTreeSet::new();
        let mut fautifs = Vec::new();
        for chemin in fichiers {
            let Ok(source) = std::fs::read_to_string(chemin) else {
                continue;
            };
            let nom = chemin
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            let un = [chemin.clone()];
            let mut ids = std::collections::BTreeSet::new();
            for mot in ["skipped", "failed", "passed"] {
                for a in appels(&un, mot) {
                    if let Some(id) = identifiant_de_raison(&a.raison) {
                        ids.insert(id);
                    }
                }
            }
            ids.extend(idents_passes_au_catalogue(&source));
            for id in &ids {
                for ligne_no in lignes_de_liaison_litterale(&source, id) {
                    fautifs.push(format!(
                        "{nom}:{ligne_no} la variable '{id}' est liee a un litteral ou a un \
                         `format!` puis passee a un verdict ou a une fonction du catalogue: \
                         la phrase doit vivre au catalogue"
                    ));
                }
            }
            ids_globaux.extend(ids);
        }
        (ids_globaux, fautifs)
    }

    /// Les constructeurs de verdict des juges, CHAQUE argument inspecte.
    ///
    /// `transport::juger` rend `Verdict::{Etanche,Indecis,Fuite}`, le verdict
    /// DoH `Verdict::{Pince,Indecis,Contournable}`, `juger_resolveur`
    /// `IssueResolveur::{Reussi,Ignore,Echec}`, et les issues de phase de
    /// `reconnect-window` `PhaseReconnexionIssue::{Etanche,Sautee,Fuite}`.
    ///
    /// # Le trou que 5s (troisieme passage) ferme
    ///
    /// `::Sautee` et `::Fuite` n'etaient PAS listees, au motif que l'une portait
    /// une raison deja au catalogue, l'autre un `Releve` sans prose. Faux pour la
    /// premiere: un Sautee compose en ligne avec un litteral echappait a tout,
    /// comme les treize sites que cette classe visait. On les liste donc, et l'on
    /// inspecte CHAQUE argument de premier niveau - l'abandon que `::Fuite` porte
    /// desormais compris -, pas seulement l'argument 0.
    const CONSTRUCTEURS_DE_JUGE: [&str; 11] = [
        "Verdict::Etanche(",
        "Verdict::Fuite(",
        "Verdict::Pince(",
        "Verdict::Contournable(",
        "Verdict::Indecis(",
        "IssueResolveur::Reussi(",
        "IssueResolveur::Echec(",
        "IssueResolveur::Ignore(",
        "PhaseReconnexionIssue::Etanche(",
        "PhaseReconnexionIssue::Sautee(",
        "PhaseReconnexionIssue::Fuite(",
    ];

    /// Les constructions de verdict trouvees dans la source, raison comprise.
    ///
    /// Une variante en position de MOTIF (`Verdict::Fuite(raison) =>`) ou de
    /// filtre (`matches!(v, Verdict::Fuite(_))`) porte un identifiant nu ou `_`
    /// en argument 0: ni guillemet ni `format!`, donc jamais signalee. Seule une
    /// CONSTRUCTION composee en ligne l'est.
    fn constructions_de_juge(fichiers: &[PathBuf]) -> Vec<Appel> {
        let mut trouves = Vec::new();
        for chemin in fichiers {
            let Ok(source) = std::fs::read_to_string(chemin) else {
                continue;
            };
            let nom = chemin
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            for aiguille in CONSTRUCTEURS_DE_JUGE {
                let mut depuis = 0usize;
                while let Some(rel) = source[depuis..].find(aiguille) {
                    let debut = depuis + rel;
                    depuis = debut + aiguille.len();
                    let ligne_debut = source[..debut].rfind('\n').map(|i| i + 1).unwrap_or(0);
                    let ligne = source[..debut].matches('\n').count() + 1;
                    // Les mentions en commentaire ne sont pas des constructions.
                    if source[ligne_debut..debut].contains("//") {
                        continue;
                    }
                    let Some(args) = arguments(&source, depuis) else {
                        continue;
                    };
                    // CHAQUE argument de premier niveau, pas seulement le
                    // premier: `PhaseReconnexionIssue::Fuite` porte sa raison
                    // d'abandon en argument 1, jamais en 0.
                    let morceaux = au_premier_niveau(&args);
                    if morceaux.is_empty() {
                        continue;
                    }
                    for morceau in morceaux {
                        trouves.push(Appel {
                            fichier: nom.clone(),
                            ligne,
                            raison: morceau,
                        });
                    }
                }
            }
        }
        trouves
    }

    /// Aucun juge ne compose sa raison en ligne; elle passe par le catalogue (5q).
    ///
    /// # Le trou que 5h avait nomme
    ///
    /// 5h a fait entrer au catalogue les onze raisons de `failed`/`passed`
    /// ecrites en litteral a l'appel. Restaient les JUGES: `transport::juger`,
    /// `juger_resolveur` et le verdict DoH fabriquent leur raison en construisant
    /// une variante d'enum (`Verdict::Fuite(format!(...))`, ...), qui n'est ni un
    /// `skipped(`, ni un `failed(`, ni un `passed(`. La raison arrive ensuite au
    /// verdict par une variable liee par le `match`, donc aucune garde ne la
    /// lisait: ni la forme, ni la distinction, ni les lectures de source
    /// existantes. Le rapport de phase de `reconnect-window`, compose en ligne
    /// puis porte par `PhaseReconnexionIssue::Etanche`, etait de la meme famille.
    ///
    /// # La regle
    ///
    /// La raison portee par une de ces variantes ne doit etre ni un litteral, ni
    /// un `format!`: soit un appel au catalogue (`motifs::...`), soit une
    /// variable qui en vient. La donnee de mesure reste un argument du catalogue.
    #[test]
    fn aucune_raison_de_juge_n_est_composee_en_ligne() {
        let Some(fichiers) = fichiers() else {
            println!(
                "SKIPPED aucune_raison_de_juge_n_est_composee_en_ligne: {} est \
                 illisible, la source n'est pas la",
                dossier_checks().display()
            );
            return;
        };
        let constructions = constructions_de_juge(&fichiers);
        assert!(
            constructions.len() >= 50,
            "seulement {} construction(s) de verdict reperees dans {} fichier(s): la \
             lecture de la source a echoue, une garde aveugle est verte pour rien",
            constructions.len(),
            fichiers.len()
        );
        let fautifs: Vec<String> = constructions
            .iter()
            .filter(|a| a.raison.contains('"') || a.raison.trim_start().starts_with("format!"))
            .map(|a| {
                format!(
                    "{}:{} raison de juge composee en ligne, hors catalogue [{}]",
                    a.fichier,
                    a.ligne,
                    a.raison.lines().next().unwrap_or_default()
                )
            })
            .collect();
        assert!(
            fautifs.is_empty(),
            "un juge fabrique sa raison en ligne au lieu de passer par le catalogue, \
             donc aucune garde de catalogue ne la lira:\n{}",
            fautifs.join("\n")
        );
    }
}
