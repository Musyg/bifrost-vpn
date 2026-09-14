//! Banc de test en namespaces reseau imbriques.
//!
//! Deux namespaces relies par un veth:
//!
//! ```text
//!   bifrost-check-client                bifrost-check-phys
//!   (kill switch + tunnel)              (passerelle + serveur WireGuard)
//!         veth-bfc  10.77.0.2/24 <---> veth-bfp  10.77.0.1/24
//!                                       wgs      10.88.0.1/24
//! ```
//!
//! Le namespace `phys` joue le reseau physique: c'est la qu'on capture. Tout ce
//! qui apparait sur `veth-bfp` sans etre chiffre est une fuite, exactement
//! comme un paquet qui sortirait de la carte reseau d'une vraie machine.
//!
//! Les deux namespaces sont detruits a la fin, y compris si un test panique.

use std::process::{Command, Output, Stdio};

use bifrost_core::{Error, Result};

pub const NS_CLIENT: &str = "bifrost-check-client";
pub const NS_PHYS: &str = "bifrost-check-phys";
pub const VETH_CLIENT: &str = "veth-bfc";
pub const VETH_PHYS: &str = "veth-bfp";

pub const CLIENT_ADDR: &str = "10.77.0.2";
pub const PHYS_ADDR: &str = "10.77.0.1";
pub const PREFIX: &str = "24";

/// Adresses IPv6 uniques locales du banc.
///
/// Sans IPv6 sur le lien, la sonde IPv6 echoue localement et n'emet rien: le
/// temoin negatif serait muet et le vecteur ipv6-leak se declarerait SKIPPED
/// faute de pouvoir prouver quoi que ce soit. Le banc doit donc pouvoir fuir en
/// IPv6 pour que l'absence de fuite ait un sens.
pub const CLIENT_ADDR6: &str = "fd00:77::2";
pub const PHYS_ADDR6: &str = "fd00:77::1";
pub const PREFIX6: &str = "64";

/// Port d'ecoute du faux serveur WireGuard, cote `phys`.
pub const WG_PORT: u16 = 51820;
/// Interface WireGuard cote client.
pub const WG_CLIENT_IF: &str = "wgc";
/// Interface WireGuard cote serveur.
pub const WG_SERVER_IF: &str = "wgs";
/// Adresse du client dans le tunnel.
pub const TUN_CLIENT_ADDR: &str = "10.88.0.2";
/// Adresse du serveur dans le tunnel: joignable uniquement par le tunnel.
pub const TUN_SERVER_ADDR: &str = "10.88.0.1";
/// Port ou le pair sert sa banniere, sur cette adresse et par `wgs` seulement.
///
/// C'est la preuve que le tunnel TRANSPORTE, celle que le lien physique ne peut
/// pas donner: un endpoint mort y produit les memes paquets chiffres qu'un
/// endpoint vivant. Voir [`crate::checks::transport`].
pub const BANNIERE_PORT: u16 = 7000;

/// Le banc, detruit a la liberation.
pub struct Bench {
    _private: (),
}

impl Bench {
    /// Monte le banc. Detruit d'abord toute trace d'une execution precedente.
    pub fn setup() -> Result<Self> {
        teardown_quiet();
        let bench = Self { _private: () };

        run(&["netns", "add", NS_CLIENT])?;
        run(&["netns", "add", NS_PHYS])?;
        run(&[
            "link",
            "add",
            VETH_CLIENT,
            "type",
            "veth",
            "peer",
            "name",
            VETH_PHYS,
        ])?;
        run(&["link", "set", VETH_CLIENT, "netns", NS_CLIENT])?;
        run(&["link", "set", VETH_PHYS, "netns", NS_PHYS])?;

        for (ns, iface, addr, addr6) in [
            (NS_CLIENT, VETH_CLIENT, CLIENT_ADDR, CLIENT_ADDR6),
            (NS_PHYS, VETH_PHYS, PHYS_ADDR, PHYS_ADDR6),
        ] {
            run(&["-n", ns, "link", "set", "lo", "up"])?;
            run(&[
                "-n",
                ns,
                "addr",
                "add",
                &format!("{addr}/{PREFIX}"),
                "dev",
                iface,
            ])?;
            // `nodad` evite d'attendre la detection d'adresse dupliquee: sans
            // cela l'adresse reste "tentative" pendant une seconde et les
            // premieres sondes IPv6 echouent, ce qui rendrait le temoin
            // negatif intermittent.
            run(&[
                "-n",
                ns,
                "addr",
                "add",
                &format!("{addr6}/{PREFIX6}"),
                "dev",
                iface,
                "nodad",
            ])?;
            run(&["-n", ns, "link", "set", iface, "up"])?;
        }

        // Le client voit le monde par la passerelle: sans ces routes, aucun
        // paquet ne quitterait le namespace et le harnais passerait pour de
        // mauvaises raisons.
        run(&["-n", NS_CLIENT, "route", "add", "default", "via", PHYS_ADDR])?;
        run(&[
            "-n", NS_CLIENT, "-6", "route", "add", "default", "via", PHYS_ADDR6,
        ])?;

        // La passerelle avale les destinations des sondes au lieu de repondre
        // "net unreachable".
        //
        // Sans cela elle se comporte comme un routeur honnete: elle emet un
        // ICMP destination unreachable, que le client met en cache. Le
        // PROCHAIN envoi vers la meme destination echoue alors localement, avec
        // ENETUNREACH, sans jamais atteindre le lien. Un vecteur qui reutilise
        // une destination deja sondee mesure donc un silence qui ne doit rien
        // au kill switch. Incident du 16/08/2026: le temoin negatif de
        // l'exemption du coeur, muet parce que startup-window avait sonde la
        // meme adresse quelques secondes plus tot. Internet, lui, ne repond
        // rien du tout: le trou noir est le comportement realiste.
        for (famille, prefixe) in [
            ("-4", "203.0.113.0/24"),
            ("-4", "8.8.8.8/32"),
            ("-6", "2001:db8::/32"),
        ] {
            run(&["-n", NS_PHYS, famille, "route", "add", "blackhole", prefixe])?;
        }

        Ok(bench)
    }

    /// Un banc qui NE MONTE RIEN, pour les recettes qui apportent leur propre
    /// espace de noms.
    ///
    /// [`Bench::setup`] cree deux namespaces et un veth, et les detruit a la
    /// liberation. Certaines recettes - l'acceptation des rulesets par nft, la
    /// journalisation d'un retrait refuse - creent et detruisent ELLES-MEMES un
    /// espace de noms jetable, et ne veulent qu'une chose du banc: poser ou
    /// retirer un ruleset dedans PAR [`Bench::poser_nft`] / [`Bench::retirer_nft`],
    /// pour que le statut de nft passe par le vrai chemin plutot que par un
    /// `Command` recopie a cote qui n'exercerait pas ces methodes. Ce
    /// constructeur rend donc un `Bench` sans monter ni detruire aucun
    /// namespace: `exec_stdin` accepte deja un nom d'espace de noms arbitraire.
    ///
    /// Le `Drop` du banc appelle malgre tout `teardown_quiet`, qui ne touche
    /// qu'aux namespaces bien connus du VRAI banc ([`NS_CLIENT`], [`NS_PHYS`]),
    /// jamais a l'espace jetable de la recette. Une recette qui pourrait tourner
    /// en parallele d'un vrai banc monte ailleurs enveloppe cette valeur dans
    /// [`std::mem::ManuallyDrop`] des sa construction, pour que ce `Drop` ne
    /// tourne JAMAIS - meme en deroulant sur un panic - et ne lui retire pas ses
    /// namespaces sous les pieds; il n'y a de toute facon rien a liberer ici, ce
    /// banc n'ayant rien monte.
    ///
    /// Uniquement pour les recettes, d'ou `#[cfg(test)]`.
    #[cfg(test)]
    pub(crate) fn sans_montage() -> Self {
        Self { _private: () }
    }

    /// Execute une commande dans un des namespaces.
    ///
    /// Refuse AVANT tout lancement une invocation de `nft` par un verbe qui
    /// MODIFIE (voir [`refuser_nft_hors_entree`]): seuls [`Bench::poser_nft`] et
    /// [`Bench::retirer_nft`] posent un ruleset, par `exec_stdin_brut` qui NE
    /// passe PAS par ce garde-fou. Une LECTURE (`nft list ...`, `nft -c ...`)
    /// est laissee passer. C'est la ceinture runtime de la garde de source
    /// `toute_invocation_nft_passe_par_poser_ou_retirer`: ce que la lecture
    /// textuelle rate (obfuscation), ce refus le rattrape des que le code tourne.
    pub fn exec(&self, ns: &str, argv: &[&str]) -> Result<Output> {
        refuser_nft_hors_entree(argv)?;
        let mut cmd = Command::new("ip");
        cmd.args(["netns", "exec", ns]).args(argv);
        cmd.stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .map_err(|e| Error::Tunnel(format!("ip netns exec {ns} {}: {e}", argv.join(" "))))
    }

    /// Execute une commande dans un namespace en lui passant une entree
    /// standard.
    ///
    /// Refuse AVANT tout lancement un `nft` par un verbe qui MODIFIE, comme
    /// [`Bench::exec`]: l'application d'un ruleset (`nft -f -`) ne se fait que
    /// par [`Bench::poser_nft`] / [`Bench::retirer_nft`], qui passent par
    /// `exec_stdin_brut` sans ce garde-fou.
    pub fn exec_stdin(&self, ns: &str, argv: &[&str], input: &str) -> Result<Output> {
        refuser_nft_hors_entree(argv)?;
        self.exec_stdin_brut(ns, argv, input)
    }

    /// [`Bench::exec_stdin`] SANS le garde-fou nft: l'entree BRUTE par laquelle
    /// un `nft -f -` atteint le noyau. Reservee a [`Bench::poser_nft`] et
    /// [`Bench::retirer_nft`], et confinee a leurs deux corps par la garde de
    /// source `toute_invocation_nft_passe_par_poser_ou_retirer`, qui refuse un
    /// `.exec_stdin_brut(` a argv `nft` en tete hors de ces deux intervalles. La
    /// garde textuelle et ce cantonnement forment le meme couple ceinture et
    /// bretelles que le refus runtime.
    fn exec_stdin_brut(&self, ns: &str, argv: &[&str], input: &str) -> Result<Output> {
        use std::io::Write;
        let mut child = Command::new("ip")
            .args(["netns", "exec", ns])
            .args(argv)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| Error::Tunnel(format!("ip netns exec {ns}: {e}")))?;
        child
            .stdin
            .take()
            .expect("stdin demande a la creation")
            .write_all(input.as_bytes())
            .map_err(|e| Error::Tunnel(format!("ecriture vers {}: {e}", argv.join(" "))))?;
        child
            .wait_with_output()
            .map_err(|e| Error::Tunnel(format!("attente de {}: {e}", argv.join(" "))))
    }

    /// Comme [`Bench::exec`] mais echoue si la commande echoue.
    pub fn exec_ok(&self, ns: &str, argv: &[&str]) -> Result<()> {
        let out = self.exec(ns, argv)?;
        if !out.status.success() {
            return Err(Error::Tunnel(format!(
                "dans {ns}: {} -> {}",
                argv.join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        Ok(())
    }

    /// Applique un ruleset via `nft -f -` dans un namespace, et LIT le statut.
    ///
    /// # Le seul point d'entree pour une pose dont l'acceptation compte (5t)
    ///
    /// Un `exec_stdin(ns, ["nft", "-f", "-"], script)` dont personne ne lit le
    /// code de sortie est ce qui a laisse le DPI de `reconnect-window` "pose"
    /// pendant des semaines sur un ruleset que nft refusait (chaine `fwd`, mot
    /// reserve): le vecteur mesurait un pcap vide et concluait a l'etancheite.
    /// 5i a corrige ce site precis; cette methode ferme la CLASSE. La garde de
    /// source `toute_invocation_nft_passe_par_poser_ou_retirer` (5t) refuse
    /// desormais TOUTE invocation de `nft` qui modifie - par `exec`, `exec_ok`,
    /// `exec_stdin`, `exec_stdin_brut`, `Bench::exec...` (UFCS) ou
    /// `Command::new` - hors d'ici et de [`Bench::retirer_nft`]; et le refus
    /// runtime de [`Bench::exec`] rattrape ce qu'une garde textuelle raterait.
    /// La pose passe par `exec_stdin_brut`, l'entree BRUTE que seuls ces deux
    /// corps ont le droit d'appeler.
    ///
    /// L'erreur porte le code de sortie ET la sortie d'erreur de nft: c'est ce
    /// que nft a a dire sur le ruleset refuse, et sans elle un appelant ne peut
    /// pas distinguer un refus de syntaxe d'un echec de lancement.
    pub fn poser_nft(&self, ns: &str, script: &str) -> Result<()> {
        let out = self.exec_stdin_brut(ns, &["nft", "-f", "-"], script)?;
        if out.status.success() {
            return Ok(());
        }
        Err(Error::Firewall(format!(
            "nft a refuse le ruleset dans {ns} (code {}): {}",
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stderr).trim()
        )))
    }

    /// Retire un ruleset via `nft -f -`, best effort, mais JOURNALISE l'echec.
    ///
    /// Le pendant de [`Bench::poser_nft`] pour les demontages dont l'echec n'a
    /// pas de trace a perdre - le banc est detruit derriere, ou la phase est
    /// deja mesuree. La difference avec le `let _ = ...` d'avant est que le
    /// statut n'est plus RAVALE en silence: un retrait refuse par nft, ou un nft
    /// qui n'a pas tourne, part en `tracing::debug!` au lieu de disparaitre.
    ///
    /// Retire par `exec_stdin_brut`, l'entree BRUTE reservee a ce corps et a
    /// [`Bench::poser_nft`]; la garde de source
    /// `toute_invocation_nft_passe_par_poser_ou_retirer` le verifie.
    pub fn retirer_nft(&self, ns: &str, script: &str) {
        match self.exec_stdin_brut(ns, &["nft", "-f", "-"], script) {
            Ok(out) if out.status.success() => {}
            Ok(out) => {
                let err = String::from_utf8_lossy(&out.stderr);
                tracing::debug!(
                    namespace = ns,
                    code = out.status.code().unwrap_or(-1),
                    stderr = %err.trim(),
                    "retrait nft best effort refuse par nft"
                );
            }
            Err(e) => tracing::debug!(
                namespace = ns,
                erreur = %e,
                "retrait nft best effort: la commande n'a pas tourne"
            ),
        }
    }

    /// Lance un processus dans un namespace sans attendre sa fin.
    ///
    /// L'enfant est place dans son propre groupe de processus. Sans cela,
    /// `Child::kill` ne tuerait que le `ip netns exec` qui sert d'enveloppe et
    /// laisserait le vrai programme, tcpdump par exemple, tourner en orphelin
    /// jusqu'a la fin de la machine.
    pub fn spawn(&self, ns: &str, argv: &[&str]) -> Result<std::process::Child> {
        use std::os::unix::process::CommandExt;
        Command::new("ip")
            .args(["netns", "exec", ns])
            .args(argv)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0)
            .spawn()
            .map_err(|e| Error::Tunnel(format!("ip netns exec {ns}: {e}")))
    }
}

/// Refuse une invocation de `nft` par un verbe qui MODIFIE, ou qui l'embarque
/// dans un jeton shell.
///
/// [`Bench::exec`], [`Bench::exec_ok`] (par `exec`) et [`Bench::exec_stdin`]
/// passent par ici AVANT tout lancement. nft est reconnu par son NOM DE FICHIER
/// (cf. [`super::nft_argv::jeton_est_nft`]) a TOUTE position de l'argv, pas
/// seulement en tete: `/usr/sbin/nft add`, `env nft add`, `nice nft ...`,
/// `timeout 5 nft ...`, un `ip netns exec <ns> nft ...` imbrique deviennent tous
/// une invocation nft a partir de cette position, soumise a la grammaire commune
/// [`super::nft_argv::est_une_lecture`]. Si le verbe n'est pas en LECTURE SEULE,
/// l'appel est refuse, motif << nft ne se pose que par poser_nft / retirer_nft >>.
/// Un jeton qui EMBARQUE une commande shell nft (`sh -c "nft add ..."`, cf.
/// [`super::nft_argv::jeton_embarque_commande_nft`]) est refuse de meme -- la
/// seule concession a la liste noire. Seuls [`Bench::poser_nft`] et
/// [`Bench::retirer_nft`] atteignent le noyau, par `exec_stdin_brut` qui NE
/// passe PAS par ce garde-fou. C'est la ceinture qui rattrape ce qu'une garde
/// de source textuelle ne peut voir - un `nft` argv assemble a l'execution, une
/// UFCS, une obfuscation.
///
/// La grammaire est celle de [`super::nft_argv`]: ce refus runtime et la garde
/// de source `tests_source::nft_lecture_seule` (mod.rs) DELEGUENT tous deux au
/// meme juge, si bien qu'ils ne peuvent plus diverger.
///
/// Refuse AVANT tout lancement: le controle ne depend d'aucun namespace ni
/// d'aucun privilege, et rougirait donc aussi sur une plateforme ou le module
/// compilerait sans `ip` - mais `netns` est `#[cfg(target_os = "linux")]`, donc
/// ce chemin ne s'exerce que sur Linux.
fn refuser_nft_hors_entree(argv: &[&str]) -> Result<()> {
    if let Some(jeton) = argv
        .iter()
        .find(|j| super::nft_argv::jeton_embarque_commande_nft(j))
    {
        return Err(Error::Firewall(format!(
            "nft ne se pose que par poser_nft / retirer_nft (commande nft embarquee dans un jeton: {jeton})"
        )));
    }
    let Some(pos) = argv.iter().position(|j| super::nft_argv::jeton_est_nft(j)) else {
        return Ok(());
    };
    if nft_en_lecture_seule(&argv[pos + 1..]) {
        return Ok(());
    }
    Err(Error::Firewall(format!(
        "nft ne se pose que par poser_nft / retirer_nft (verbe hors lecture seule: {})",
        argv.join(" ")
    )))
}

/// Les jetons `reste` (ceux qui SUIVENT le programme nft) sont-ils une LECTURE?
///
/// DELEGUE a la grammaire commune [`super::nft_argv::est_une_lecture`], partagee
/// avec la garde de source `tests_source::nft_lecture_seule` (mod.rs): une seule
/// modelisation de la ligne de commande de nft 1.0.9 (getopt_long, ensembles
/// fermes d'options, sortie de `nft --help`), plus deux jumelles a la main qui
/// pouvaient diverger. Voir [`super::nft_argv`] pour la grammaire et ses jeux
/// d'essai.
fn nft_en_lecture_seule(reste: &[&str]) -> bool {
    super::nft_argv::est_une_lecture(reste)
}

/// Termine un enfant et tout son groupe de processus.
///
/// `SIGTERM` d'abord: tcpdump vide alors son tampon et ferme proprement le
/// pcap. `SIGKILL` seulement si l'enfant s'attarde.
pub fn kill_group(child: &mut std::process::Child) {
    let pid = child.id() as i32;
    // SAFETY: `spawn` a place l'enfant dans son propre groupe, dont
    // l'identifiant vaut son pid. Un pid negatif designe ce groupe entier.
    unsafe {
        libc::kill(-pid, libc::SIGTERM);
    }
    for _ in 0..20 {
        match child.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) => std::thread::sleep(std::time::Duration::from_millis(50)),
            Err(_) => break,
        }
    }
    // SAFETY: meme raisonnement, en dernier recours.
    unsafe {
        libc::kill(-pid, libc::SIGKILL);
    }
    let _ = child.kill();
    let _ = child.wait();
}

impl Drop for Bench {
    fn drop(&mut self) {
        teardown_quiet();
    }
}

/// Detruit le banc sans se plaindre de ce qui n'existe pas.
///
/// Supprimer un namespace supprime aussi les interfaces qu'il contient, donc le
/// veth part avec. Le lien residuel dans le namespace initial n'est nettoye que
/// si la creation s'est arretee en cours de route.
pub fn teardown_quiet() {
    for ns in [NS_CLIENT, NS_PHYS] {
        let _ = quiet(&["netns", "del", ns]);
    }
    let _ = quiet(&["link", "del", VETH_CLIENT]);
    let _ = quiet(&["link", "del", VETH_PHYS]);
}

fn run(args: &[&str]) -> Result<()> {
    let out = Command::new("ip")
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| Error::Tunnel(format!("ip {}: {e}", args.join(" "))))?;
    if !out.status.success() {
        return Err(Error::Tunnel(format!(
            "ip {} -> {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(())
}

fn quiet(args: &[&str]) -> std::io::Result<std::process::ExitStatus> {
    Command::new("ip")
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    // Les constantes de ce banc ne sont exercees que par des recettes qui
    // montent de vrais espaces de noms, donc SKIPPED sans CAP_NET_ADMIN: sur la
    // machine de mesure elles s'abstiennent ENSEMBLE. Une valeur incoherente -
    // deux adresses hors du meme sous-reseau, un nom d'interface trop long -
    // passerait pour un banc sain tout en rendant muet chaque vecteur de fuite
    // Linux, qui s'appuie sur ce banc. Ces gardes-la sont PURES: elles lisent
    // les constantes et confrontent leur forme a une exigence du noyau
    // (IFNAMSIZ) ou a l'arithmetique des adresses, jamais a elles-memes, donc
    // elles rougissent partout ou le module compile, root ou pas.

    fn prefixe_dans_plage(p: &str, max: u32, quoi: &str) -> u32 {
        let n: u32 = p
            .parse()
            .unwrap_or_else(|_| panic!("{quoi} doit etre un entier: {p}"));
        assert!(n <= max, "{quoi} hors plage (<= {max}): {n}");
        n
    }

    fn meme_reseau_v4(a: Ipv4Addr, b: Ipv4Addr, prefixe: u32) -> bool {
        if prefixe == 0 {
            return true;
        }
        let masque = u32::MAX << (32 - prefixe);
        (u32::from(a) & masque) == (u32::from(b) & masque)
    }

    fn meme_reseau_v6(a: Ipv6Addr, b: Ipv6Addr, prefixe: u32) -> bool {
        if prefixe == 0 {
            return true;
        }
        let masque = u128::MAX << (128 - prefixe);
        (u128::from(a) & masque) == (u128::from(b) & masque)
    }

    /// Les noms d'interface tiennent dans la limite du noyau.
    ///
    /// `IFNAMSIZ` compte le zero final: un nom de seize octets ou plus est
    /// refuse par le noyau a la creation du veth, et le banc echouerait a monter
    /// au lieu de mesurer. La borne vient de libc, pas d'un nombre recopie.
    #[test]
    fn les_noms_d_interface_tiennent_dans_ifnamsiz() {
        for nom in [VETH_CLIENT, VETH_PHYS, WG_CLIENT_IF, WG_SERVER_IF] {
            assert!(!nom.is_empty(), "nom d'interface vide");
            assert!(
                nom.len() < libc::IFNAMSIZ,
                "nom d'interface trop long pour IFNAMSIZ ({}): {nom}",
                libc::IFNAMSIZ
            );
        }
    }

    /// Les adresses du lien physique partagent leur sous-reseau.
    ///
    /// Le client et la passerelle doivent se joindre sur le veth: hors du meme
    /// sous-reseau, aucun paquet ne quitte le namespace et le banc passerait
    /// pour de mauvaises raisons. Verifie par l'arithmetique des adresses.
    #[test]
    fn les_adresses_du_lien_sont_dans_le_meme_sous_reseau() {
        let c: Ipv4Addr = CLIENT_ADDR.parse().expect("CLIENT_ADDR invalide");
        let p: Ipv4Addr = PHYS_ADDR.parse().expect("PHYS_ADDR invalide");
        let pfx = prefixe_dans_plage(PREFIX, 32, "PREFIX");
        assert_ne!(c, p, "client et passerelle partagent une adresse");
        assert!(
            meme_reseau_v4(c, p, pfx),
            "CLIENT_ADDR et PHYS_ADDR hors du meme /{pfx}"
        );

        let c6: Ipv6Addr = CLIENT_ADDR6.parse().expect("CLIENT_ADDR6 invalide");
        let p6: Ipv6Addr = PHYS_ADDR6.parse().expect("PHYS_ADDR6 invalide");
        let pfx6 = prefixe_dans_plage(PREFIX6, 128, "PREFIX6");
        assert_ne!(c6, p6, "client et passerelle partagent une adresse v6");
        assert!(
            meme_reseau_v6(c6, p6, pfx6),
            "CLIENT_ADDR6 et PHYS_ADDR6 hors du meme /{pfx6}"
        );
    }

    /// Les deux bouts du tunnel partagent leur sous-reseau.
    ///
    /// Le diagramme du module fixe le tunnel en 10.88.0.0/24. Les deux adresses
    /// doivent y tenir et differer, sinon le pair est injoignable par le tunnel
    /// et le temoin positif du transport disparait.
    #[test]
    fn les_adresses_du_tunnel_sont_coherentes() {
        const PREFIXE_TUNNEL: u32 = 24;
        let c: Ipv4Addr = TUN_CLIENT_ADDR.parse().expect("TUN_CLIENT_ADDR invalide");
        let s: Ipv4Addr = TUN_SERVER_ADDR.parse().expect("TUN_SERVER_ADDR invalide");
        assert_ne!(c, s, "les deux bouts du tunnel partagent une adresse");
        assert!(
            meme_reseau_v4(c, s, PREFIXE_TUNNEL),
            "TUN_CLIENT_ADDR et TUN_SERVER_ADDR hors du meme /{PREFIXE_TUNNEL}"
        );
    }

    /// Les noms et ports du banc sont distincts et non nuls.
    ///
    /// Deux namespaces de meme nom, ou deux interfaces de meme nom, feraient
    /// echouer la creation; un port nul ne s'ecoute pas.
    #[test]
    fn les_noms_et_ports_du_banc_sont_distincts() {
        assert_ne!(
            NS_CLIENT, NS_PHYS,
            "les deux namespaces portent le meme nom"
        );
        assert_ne!(VETH_CLIENT, VETH_PHYS, "les deux veth portent le meme nom");
        assert_ne!(
            WG_CLIENT_IF, WG_SERVER_IF,
            "les deux interfaces wg portent le meme nom"
        );
        assert_ne!(WG_PORT, 0, "WG_PORT nul ne s'ecoute pas");
        assert_ne!(BANNIERE_PORT, 0, "BANNIERE_PORT nul ne s'ecoute pas");
        assert_ne!(
            WG_PORT, BANNIERE_PORT,
            "le port wg et celui de la banniere se confondent"
        );
    }

    /// (5t) `nft` par un verbe qui MODIFIE est refuse AVANT tout lancement.
    ///
    /// Le pendant RUNTIME de la garde de source
    /// `toute_invocation_nft_passe_par_poser_ou_retirer`: ce qu'une lecture
    /// textuelle raterait - un argv `nft` assemble a l'execution, une UFCS, une
    /// obfuscation - ce refus le rattrape des que le code tourne. `exec`,
    /// `exec_ok` (par `exec`) et `exec_stdin` refusent tous une pose nft avec le
    /// motif << poser_nft / retirer_nft >>, et le refus tombe AVANT le moindre
    /// `ip netns exec`: le namespace `bfabsent-x` n'existe pas, et pourtant
    /// aucune erreur de lancement ne remonte - c'est le motif qui sort, donc
    /// sans root et meme sans `ip`. `poser_nft`/`retirer_nft`, eux, passent par
    /// `exec_stdin_brut` et ne sont PAS refuses (voir, sous root,
    /// `chaque_ruleset_du_banc_est_accepte_par_nft`).
    ///
    /// Pure, sans root, sans lancement (le refus precede l'`ip netns exec`).
    #[test]
    fn nft_qui_modifie_est_refuse_avant_lancement() {
        let bench = std::mem::ManuallyDrop::new(Bench::sans_montage());
        let motif = "poser_nft / retirer_nft";
        match bench.exec("bfabsent-x", &["nft", "add", "table", "inet", "x"]) {
            Ok(_) => panic!("exec a laisse passer un nft qui modifie"),
            Err(e) => assert!(
                e.to_string().contains(motif),
                "exec a echoue, mais pas par le motif du refus nft: {e}"
            ),
        }
        match bench.exec_ok("bfabsent-x", &["nft", "add", "table", "inet", "x"]) {
            Ok(()) => panic!("exec_ok a laisse passer un nft qui modifie"),
            Err(e) => assert!(
                e.to_string().contains(motif),
                "exec_ok a echoue, mais pas par le motif du refus nft: {e}"
            ),
        }
        match bench.exec_stdin("bfabsent-x", &["nft", "-f", "-"], "add table inet x\n") {
            Ok(_) => panic!("exec_stdin a laisse passer un nft -f -"),
            Err(e) => assert!(
                e.to_string().contains(motif),
                "exec_stdin a echoue, mais pas par le motif du refus nft: {e}"
            ),
        }
    }

    /// (5t) Une LECTURE nft (`nft list ...`) n'est PAS refusee par le motif.
    ///
    /// Le complement de la recette ci-dessus: la liste blanche laisse passer
    /// `list`. `exec(ns, ["nft", "list", "tables"])` ne rend donc jamais le motif
    /// du refus; il echoue PLUS LOIN, faute de namespace `bfabsent-x` (l'`ip netns
    /// exec` ne peut pas ouvrir un namespace inexistant), ou reussirait s'il
    /// existait. On exige seulement que, s'il echoue, ce ne soit pas par le motif.
    ///
    /// Sans root: l'echec d'ouverture du namespace precede tout privilege.
    #[test]
    fn une_lecture_nft_n_est_pas_refusee() {
        let bench = std::mem::ManuallyDrop::new(Bench::sans_montage());
        let motif = "poser_nft / retirer_nft";
        if let Err(e) = bench.exec("bfabsent-x", &["nft", "list", "tables"]) {
            assert!(
                !e.to_string().contains(motif),
                "une lecture nft a ete refusee par le motif de pose, a tort: {e}"
            );
        }
    }

    /// (5t, septieme passage) Un `nft list` SUIVI d'un verbe qui MODIFIE, glisse
    /// dans un jeton par `;` ou par un saut de ligne, est refuse AVANT tout
    /// lancement.
    ///
    /// nft concatene TOUS ses arguments restants en un seul tampon separe
    /// d'espaces (`nft_run_cmd_from_buffer`, src/main.c de nftables), puis
    /// l'interprete comme UNE suite de commandes: l'argv
    /// `["nft", "list", "tables;", "add", "table", "inet", "x"]` devient le texte
    /// `list tables; add table inet x`, ou le `;` ferme le `list` et ouvre un
    /// `add` qui pose une table - le verbe de tete `list` l'avait fait passer
    /// pour une lecture. Un saut de ligne dans un jeton fait de meme. Mesure sous
    /// root le 05/09/2026: la commande a cree `table inet bfsemi` dans un netns
    /// jetable. Le motif rejette donc tout jeton portant `;`, `\n` ou `\r`, et
    /// l'appel rend le motif du refus avant le moindre `ip netns exec`: le
    /// namespace `bfabsent-x` n'existe pas, et pourtant aucune erreur de
    /// lancement ne remonte.
    ///
    /// Pure, sans root, sans lancement (le refus precede l'`ip netns exec`).
    #[test]
    fn nft_list_concatene_un_verbe_qui_modifie_est_refuse() {
        let bench = std::mem::ManuallyDrop::new(Bench::sans_montage());
        let motif = "poser_nft / retirer_nft";
        // Un `;` dans un jeton: nft lit `list tables; add table inet x`.
        match bench.exec(
            "bfabsent-x",
            &["nft", "list", "tables;", "add", "table", "inet", "x"],
        ) {
            Ok(_) => panic!("exec a laisse passer un nft list suivi d'un add par `;`"),
            Err(e) => assert!(
                e.to_string().contains(motif),
                "exec a echoue, mais pas par le motif du refus nft: {e}"
            ),
        }
        // Un saut de ligne dans un jeton: nft lit deux lignes de commandes.
        match bench.exec("bfabsent-x", &["nft", "list", "tables\nadd table inet x"]) {
            Ok(_) => panic!("exec a laisse passer un nft list suivi d'un add par saut de ligne"),
            Err(e) => assert!(
                e.to_string().contains(motif),
                "exec a echoue, mais pas par le motif du refus nft: {e}"
            ),
        }
    }

    /// (5t, neuvieme passage) nft reconnu a TOUTE position et sous toutes ses
    /// formes: refuse par le motif quand il MODIFIE, laisse passer quand il LIT.
    /// Pendant runtime des recettes de grammaire de `super::nft_argv`.
    ///
    /// Les trois lignes du quatrieme FAIL (mesurees sous root par le
    /// verificateur, une table creee a chaque fois), plus `env nft`,
    /// `timeout 5 nft`, un `sh -c "nft ..."` et les formes collees de
    /// l'includepath: toutes rendent le motif AVANT tout lancement (le namespace
    /// `bfabsent-x` n'existe pas, et pourtant aucune erreur de lancement ne
    /// remonte). Les lectures (`nft -c`, `nft -j list`, `/usr/sbin/nft list`) ne
    /// rendent jamais le motif.
    ///
    /// Pure, sans root, sans lancement: le refus precede l'`ip netns exec`.
    #[test]
    fn nft_reconnu_a_toute_position_et_forme() {
        let bench = std::mem::ManuallyDrop::new(Bench::sans_montage());
        let motif = "poser_nft / retirer_nft";
        let refuses: &[&[&str]] = &[
            // Les trois lignes du FAIL.
            &["nft", "-I", "list", "add", "table", "inet", "bfv6"],
            &["nft", "-I", "-c", "add", "table", "inet", "bfv7"],
            &["/usr/sbin/nft", "add", "table", "inet", "bfv5"],
            // nft a une position autre que la tete.
            &["env", "nft", "add", "table", "inet", "x"],
            &["timeout", "5", "nft", "add", "table", "inet", "x"],
            // Formes collees de l'includepath.
            &["nft", "-Ilist", "add", "table", "inet", "x"],
            &["nft", "--includepath=x", "add", "table", "inet", "x"],
            // Une commande nft embarquee dans un jeton shell.
            &["sh", "-c", "nft add table inet x"],
            // Le corps brut `nft -f -` hors des deux entrees.
            &["nft", "-f", "-"],
        ];
        for argv in refuses {
            match bench.exec("bfabsent-x", argv) {
                Ok(_) => panic!("exec a laisse passer une modification nft: {argv:?}"),
                Err(e) => assert!(
                    e.to_string().contains(motif),
                    "exec a echoue, mais pas par le motif du refus nft: {argv:?} -> {e}"
                ),
            }
        }
        let lectures: &[&[&str]] = &[
            &["nft", "-c", "add", "table", "inet", "x"],
            &["nft", "-j", "list", "tables"],
            &["nft", "list", "tables"],
            &["/usr/sbin/nft", "list", "tables"],
        ];
        for argv in lectures {
            if let Err(e) = bench.exec("bfabsent-x", argv) {
                assert!(
                    !e.to_string().contains(motif),
                    "une lecture nft a ete refusee par le motif, a tort: {argv:?} -> {e}"
                );
            }
        }
    }
}
