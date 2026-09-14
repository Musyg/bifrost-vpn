//! Qui entre dans le TUN, et qui en sort.
//!
//! Le chemin par coeur pose une question que le chemin WireGuard ne posait
//! pas. Si la route par defaut entre dans le TUN, **le trafic du coeur y entre
//! aussi**, et il boucle: le coeur essaie de joindre son serveur, ses paquets
//! repassent par le TUN, le passeur les lui redonne, sans fin.
//!
//! # Pourquoi l'identite, et non la marque
//!
//! WireGuard s'echappe par `fwmark`, et [`super::netcfg`] l'implemente: le
//! noyau marque les paquets qu'il vient de chiffrer, la regle `not fwmark`
//! les laisse suivre la table `main`. Le mecanisme suppose qu'on pose la marque
//! soi-meme. Un coeur est un processus TIERS: on ne touche pas ses sockets.
//!
//! Ce qu'on tient de lui, c'est son IDENTITE - le compte dedie non privilegie
//! sous lequel il tourne. Le depot s'en sert deja au pare-feu: `render_coeur_permit`
//! exempte par `meta skuid`, et son en-tete explique pourquoi la marque ne peut
//! pas y servir. Le meme discriminant vaut ici, et il vaut mieux qu'il soit le
//! meme: un coeur permis par le pare-feu mais route dans le TUN serait autorise
//! a sortir par une porte qui le ramene a l'interieur.
//!
//! Le plan disait deja cela. Document 02 partie 8: exempter le proxy "par
//! `socket cgroupv2` OU UID dedie (pas par IP)", et partie 2.1 note que
//! `meta skuid` ne marche qu'en sortie - ce qui est exactement le cas ici.
//!
//! # Etat de l'art au 19 aout 2026
//!
//! `uidrange NUMBER-NUMBER` est un selecteur de premier ordre d'`ip rule`,
//! au meme titre que `fwmark`. C'est ce que fait sing-tun, la bibliotheque TUN
//! de sing-box, qui expose `IncludeUID`/`ExcludeUID` sur Linux pour ce cas
//! precis; et c'est ce sur quoi repose le VPN par application d'Android. Aucune
//! des trois references ne route un proxy hors de son propre TUN autrement que
//! par identite.
//!
//! # La forme posee
//!
//! ```text
//! ip -4 route add default dev <tun> table <T>
//! ip -4 rule add uidrange U-U lookup main pref 9100   # le coeur sort dehors
//! ip -4 rule add lookup main suppress_prefixlength 0 pref 9110   # le LAN reste
//! ip -4 rule add lookup <T> pref 9120                 # tout le reste entre
//! ```
//!
//! L'ordre EST la politique, et chaque rang se justifie:
//!
//! - le coeur d'abord, sinon il n'aurait jamais l'occasion de sortir;
//! - le LAN ensuite. `suppress_prefixlength 0` fait ignorer la seule route par
//!   defaut de `main` en gardant les routes connectees: on garde l'imprimante
//!   du bureau sans rendre Internet joignable en clair. C'est le tour de
//!   wg-quick, repris tel quel;
//! - le TUN en dernier, pour tout ce qui n'a pas trouve avant.
//!
//! Ce que cette table NE protege pas: si le TUN disparait, sa route par defaut
//! part avec lui et le trafic retombe sur `main`. C'est le kill switch qui
//! l'arrete, pas le routage, et c'est la repartition voulue - le routage dit ou
//! passer, les filtres disent qui a le droit.

use super::netcfg::Cmd;

/// Table de routage du chemin par coeur.
///
/// `0xb1f` se lit "bif". Choisie hors des valeurs qu'on rencontre: 52 est celle
/// de Tailscale sur cette flotte, wg-quick prend son port d'ecoute (51820), et
/// sing-tun utilise 2022. Une collision ne se verrait pas: elle melangerait nos
/// routes a celles d'un autre.
pub const TABLE: u32 = 0xb1f;

/// Le coeur sort dehors. En premier, sinon il n'en aurait jamais l'occasion.
pub const PREF_COEUR: u32 = 9100;
/// Le LAN garde ses routes connectees, mais pas la route par defaut.
pub const PREF_LAN: u32 = 9110;
/// Tout le reste entre dans le TUN.
pub const PREF_TUNNEL: u32 = 9120;

/// L'ordre EST la politique: une inversion ferait entrer le coeur dans le TUN,
/// ou rendrait Internet joignable en clair par la route par defaut de `main`.
///
/// Verifie a la COMPILATION et non par un test. Clippy avait raison de signaler
/// l'assertion correspondante: portant sur des constantes, elle ne verifiait
/// rien a l'execution et se contentait d'en avoir l'air. Ici, un rangement
/// fautif ne produit pas un test rouge, il produit un binaire qui n'existe pas.
const _: () = assert!(
    PREF_COEUR < PREF_LAN && PREF_LAN < PREF_TUNNEL,
    "le coeur avant le LAN, le LAN avant le TUN"
);

/// Ce qu'il faut savoir pour aiguiller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Aiguillage {
    /// L'interface TUN qui mene au passeur.
    pub interface: String,
    /// Le compte du coeur, s'il y en a un.
    ///
    /// `None` decrit un chemin SANS coeur tiers. Le declarer a tort ferait
    /// boucler le coeur sur lui-meme, ce qu'aucun filtre ne rattraperait: c'est
    /// un probleme de routage, pas de permission.
    pub coeur_uid: Option<u32>,
}

/// Les familles traitees. IPv6 est routee dans le TUN plutot que laissee de
/// cote: une famille sans route est une famille qui sort par la porte d'a cote.
const FAMILLES: [&str; 2] = ["-4", "-6"];

/// Pose l'aiguillage.
pub fn poser(a: &Aiguillage) -> Vec<Cmd> {
    let table = TABLE.to_string();
    let mut cmds = Vec::new();
    for f in FAMILLES {
        cmds.push(Cmd::ip(&[
            f,
            "route",
            "add",
            "default",
            "dev",
            &a.interface,
            "table",
            &table,
        ]));
        if let Some(uid) = a.coeur_uid {
            let plage = format!("{uid}-{uid}");
            cmds.push(Cmd::ip(&[
                f,
                "rule",
                "add",
                "uidrange",
                &plage,
                "lookup",
                "main",
                "pref",
                &PREF_COEUR.to_string(),
            ]));
        }
        cmds.push(Cmd::ip(&[
            f,
            "rule",
            "add",
            "lookup",
            "main",
            "suppress_prefixlength",
            "0",
            "pref",
            &PREF_LAN.to_string(),
        ]));
        cmds.push(Cmd::ip(&[
            f,
            "rule",
            "add",
            "lookup",
            &table,
            "pref",
            &PREF_TUNNEL.to_string(),
        ]));
    }
    cmds
}

/// Retire l'aiguillage.
///
/// Tout y est tolerant: le demontage suit aussi bien un montage complet qu'un
/// montage interrompu au milieu, et une regle deja absente n'est pas une
/// erreur. S'arreter a la premiere laisserait les suivantes en place - c'est-a-
/// dire une table qui aiguille vers une interface disparue.
pub fn retirer(a: &Aiguillage) -> Vec<Cmd> {
    let table = TABLE.to_string();
    let mut cmds = Vec::new();
    for f in FAMILLES {
        cmds.push(Cmd::ip_lenient(&[
            f,
            "rule",
            "del",
            "pref",
            &PREF_TUNNEL.to_string(),
        ]));
        cmds.push(Cmd::ip_lenient(&[
            f,
            "rule",
            "del",
            "pref",
            &PREF_LAN.to_string(),
        ]));
        if a.coeur_uid.is_some() {
            cmds.push(Cmd::ip_lenient(&[
                f,
                "rule",
                "del",
                "pref",
                &PREF_COEUR.to_string(),
            ]));
        }
        cmds.push(Cmd::ip_lenient(&[f, "route", "flush", "table", &table]));
    }
    cmds
}

#[cfg(test)]
mod tests {
    use super::*;

    fn avec_coeur() -> Aiguillage {
        Aiguillage {
            interface: "bftun0".to_owned(),
            coeur_uid: Some(4242),
        }
    }

    fn lignes(cmds: &[Cmd]) -> Vec<String> {
        cmds.iter().map(Cmd::display).collect()
    }

    #[test]
    fn la_table_porte_la_route_par_defaut_vers_le_tun() {
        let l = lignes(&poser(&avec_coeur()));
        assert!(l.contains(&format!("ip -4 route add default dev bftun0 table {TABLE}")));
        assert!(l.contains(&format!("ip -6 route add default dev bftun0 table {TABLE}")));
    }

    /// Le point du module: sans cette regle le coeur boucle sur lui-meme.
    #[test]
    fn le_coeur_sort_par_son_identite() {
        let l = lignes(&poser(&avec_coeur()));
        assert!(l.contains(&format!(
            "ip -4 rule add uidrange 4242-4242 lookup main pref {PREF_COEUR}"
        )));
        assert!(l.contains(&format!(
            "ip -6 rule add uidrange 4242-4242 lookup main pref {PREF_COEUR}"
        )));
    }

    /// `suppress_prefixlength 0` garde les routes connectees et ignore la seule
    /// route par defaut: le LAN reste joignable sans qu'Internet le soit.
    #[test]
    fn le_lan_survit_mais_pas_la_route_par_defaut_de_main() {
        let l = lignes(&poser(&avec_coeur()));
        assert!(l.contains(&format!(
            "ip -4 rule add lookup main suppress_prefixlength 0 pref {PREF_LAN}"
        )));
    }

    /// Un chemin sans coeur tiers n'a personne a faire sortir. Poser la regle
    /// quand meme ouvrirait une sortie a un uid arbitraire.
    #[test]
    fn sans_coeur_declare_aucune_sortie_n_est_ouverte() {
        let sans = Aiguillage {
            interface: "bftun0".to_owned(),
            coeur_uid: None,
        };
        let l = lignes(&poser(&sans));
        assert!(
            !l.iter().any(|c| c.contains("uidrange")),
            "aucune sortie par identite ne doit etre posee: {l:?}"
        );
        assert!(l.iter().any(|c| c.contains("route add default")));
    }

    /// Tout ce qui est pose doit pouvoir etre retire. Une regle oubliee
    /// survivrait a la deconnexion et aiguillerait vers une interface morte.
    #[test]
    fn tout_ce_qui_est_pose_est_retire() {
        let a = avec_coeur();
        let retire = lignes(&retirer(&a));
        for f in FAMILLES {
            for pref in [PREF_COEUR, PREF_LAN, PREF_TUNNEL] {
                assert!(
                    retire.contains(&format!("ip {f} rule del pref {pref}")),
                    "la regle {pref} en {f} n'est pas retiree: {retire:?}"
                );
            }
            assert!(retire.contains(&format!("ip {f} route flush table {TABLE}")));
        }
    }

    /// Le demontage suit aussi bien un montage complet qu'un montage
    /// interrompu au milieu: s'arreter a la premiere absence laisserait les
    /// suivantes en place.
    #[test]
    fn le_demontage_tolere_ce_qui_manque_deja() {
        assert!(
            retirer(&avec_coeur()).iter().all(|c| c.tolerate_failure),
            "aucune etape de demontage ne doit interrompre les suivantes"
        );
    }

    /// Les valeurs de routage evitent ce que le noyau se reserve.
    ///
    /// L'ordre des prefs est deja verifie a la COMPILATION, mais une assertion
    /// const sur des constantes ne rougit pas en recette nommee: on la reaffirme
    /// ici sous une forme qui PEUT rougir, et on y ajoute deux exigences que
    /// rien ne tenait - toutes deux lues DEHORS, pas comparees a nos litteraux.
    ///
    /// - `TABLE` ne doit heurter aucune table reservee (`RT_TABLE_*`, lues dans
    ///   libc). La plus dangereuse est `main` (254): y poser nos routes les
    ///   melerait a la route par defaut du systeme, donc en clair.
    /// - Aucune pref ne doit atteindre la priorite des regles fib par defaut du
    ///   noyau. `ip rule` installe `from all lookup main` a la priorite 32766:
    ///   une regle a nous a 32766 ou plus serait masquee par elle, le trafic
    ///   ordinaire ne verrait jamais la route TUN et sortirait en clair.
    #[test]
    fn les_valeurs_de_routage_evitent_les_reserves_du_noyau() {
        // Lues au travers de tableaux, donc a l'EXECUTION: une assertion sur des
        // constantes pures ne verifie rien, et clippy a raison de la refuser -
        // c'est la meme lecon que l'assertion const de ce module (l.82).
        let reservees = [
            0u32, // RT_TABLE_UNSPEC
            libc::RT_TABLE_DEFAULT as u32,
            libc::RT_TABLE_MAIN as u32,
            libc::RT_TABLE_LOCAL as u32,
        ];
        assert!(
            !reservees.contains(&TABLE),
            "TABLE heurte une table reservee du noyau (RT_TABLE_*): {TABLE}"
        );
        let prefs = [PREF_COEUR, PREF_LAN, PREF_TUNNEL];
        assert!(
            prefs.windows(2).all(|p| p[0] < p[1]),
            "l'ordre des prefs est la politique: {prefs:?}"
        );
        // Priorite de la regle `main` par defaut du noyau (fib_default_rules):
        // une regle a nous a 32766 ou plus serait masquee par `from all lookup
        // main`, le trafic ordinaire ne verrait jamais la route TUN et sortirait
        // en clair.
        let plafond_regles_par_defaut = 32766u32;
        assert!(
            prefs.iter().all(|p| *p < plafond_regles_par_defaut),
            "une pref atteint la regle main par defaut ({plafond_regles_par_defaut}): route TUN masquee: {prefs:?}"
        );
    }

    // Ce qui suit sort du pur: on demande au noyau ce qu'il ferait vraiment.
    // Tout se passe dans un espace de noms, et c'est une precaution serieuse:
    // pose sur l'hote, un aiguillage de ce genre couperait la session par
    // laquelle on travaille.

    /// Pourquoi ce qui suit ne peut pas tourner ici, s'il y a une raison.
    fn raison_de_sauter() -> Option<&'static str> {
        let statut = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
        let effectif = statut
            .lines()
            .find_map(|l| l.strip_prefix("Uid:"))
            .and_then(|l| l.split_whitespace().nth(1).map(str::to_owned));
        if effectif.as_deref() != Some("0") {
            return Some("creer un espace de noms reseau demande CAP_NET_ADMIN");
        }
        None
    }

    /// Un espace de noms qui disparait meme si le test echoue.
    struct Espace(String);

    impl Espace {
        fn neuf(nom: String) -> Self {
            let _ = std::process::Command::new("ip")
                .args(["netns", "del", &nom])
                .output();
            let sortie = std::process::Command::new("ip")
                .args(["netns", "add", &nom])
                .output()
                .expect("ip netns add doit se lancer");
            assert!(
                sortie.status.success(),
                "espace de noms non cree: {}",
                String::from_utf8_lossy(&sortie.stderr).trim()
            );
            Self(nom)
        }

        /// Lance une commande DANS l'espace de noms et rend sa sortie.
        fn dedans(&self, programme: &str, args: &[String]) -> std::process::Output {
            std::process::Command::new("ip")
                .args(["netns", "exec", &self.0])
                .arg(programme)
                .args(args)
                .output()
                .expect("ip netns exec doit se lancer")
        }

        fn exiger(&self, programme: &str, args: &[String]) {
            let sortie = self.dedans(programme, args);
            assert!(
                sortie.status.success(),
                "{programme} {args:?}: {}",
                String::from_utf8_lossy(&sortie.stderr).trim()
            );
        }

        fn ip(&self, args: &[&str]) {
            self.exiger(
                "ip",
                &args.iter().map(|a| (*a).to_owned()).collect::<Vec<_>>(),
            );
        }

        /// Ce que le noyau ferait de ce paquet.
        fn route_vers(&self, args: &[&str]) -> String {
            let mut a = vec!["route".to_owned(), "get".to_owned()];
            a.extend(args.iter().map(|x| (*x).to_owned()));
            let sortie = self.dedans("ip", &a);
            assert!(
                sortie.status.success(),
                "ip route get {args:?}: {}",
                String::from_utf8_lossy(&sortie.stderr).trim()
            );
            String::from_utf8_lossy(&sortie.stdout).into_owned()
        }
    }

    impl Drop for Espace {
        fn drop(&mut self) {
            let _ = std::process::Command::new("ip")
                .args(["netns", "del", &self.0])
                .output();
        }
    }

    /// Le test qui compte: le noyau aiguille-t-il comme la politique le dit.
    ///
    /// Il execute la sortie REELLE de [`poser`] et [`retirer`], et non une
    /// copie a la main: une liste recopiee dans un test ne prouve que la
    /// copie.
    #[test]
    fn le_noyau_aiguille_comme_la_politique_le_dit() {
        if let Some(raison) = raison_de_sauter() {
            println!("SKIPPED: {raison}");
            return;
        }
        let espace = Espace::neuf(format!("bfaig{}", std::process::id()));

        // Une fausse interface physique, avec la route par defaut du monde
        // ordinaire, et un TUN a cote.
        espace.ip(&["link", "add", "dummy0", "type", "dummy"]);
        espace.ip(&["addr", "add", "192.0.2.2/24", "dev", "dummy0"]);
        espace.ip(&["link", "set", "dummy0", "up"]);
        espace.ip(&[
            "route",
            "add",
            "default",
            "via",
            "192.0.2.1",
            "dev",
            "dummy0",
        ]);
        espace.ip(&["tuntap", "add", "mode", "tun", "name", "bftun0"]);
        espace.ip(&["addr", "add", "10.99.0.1/24", "dev", "bftun0"]);
        espace.ip(&["link", "set", "bftun0", "up"]);

        assert!(
            espace.route_vers(&["1.1.1.1"]).contains("dev dummy0"),
            "avant l'aiguillage, tout sort par l'interface physique"
        );

        let a = Aiguillage {
            interface: "bftun0".to_owned(),
            coeur_uid: Some(4242),
        };
        for cmd in poser(&a) {
            espace.exiger(cmd.program, &cmd.args);
        }

        let ordinaire = espace.route_vers(&["1.1.1.1"]);
        assert!(
            ordinaire.contains("dev bftun0") && ordinaire.contains(&format!("table {TABLE}")),
            "le trafic ordinaire doit entrer dans le TUN: {ordinaire}"
        );

        // Le point du module. Sans cette regle, le coeur boucle sur lui-meme.
        let coeur = espace.route_vers(&["1.1.1.1", "uid", "4242"]);
        assert!(
            coeur.contains("dev dummy0"),
            "le coeur doit sortir par l'interface physique, sinon il boucle: {coeur}"
        );

        // `suppress_prefixlength 0` ignore la route par defaut de main sans
        // toucher aux routes connectees.
        let lan = espace.route_vers(&["192.0.2.50"]);
        assert!(
            lan.contains("dev dummy0"),
            "le LAN doit rester joignable directement: {lan}"
        );

        for cmd in retirer(&a) {
            espace.dedans(cmd.program, &cmd.args);
        }
        assert!(
            espace.route_vers(&["1.1.1.1"]).contains("dev dummy0"),
            "apres demontage, la route par defaut d'origine doit reprendre"
        );
    }
}
