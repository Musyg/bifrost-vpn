//! Sonde d'identite: le permit du daemon matche-t-il vraiment?
//!
//! Le kill switch autorise le daemon a sortir par son IDENTITE, jamais par
//! l'adresse de l'endpoint. Cette identite est faite de deux conditions
//! combinees en ET: le chemin du binaire (`ALE_APP_ID`) et l'utilisateur qui
//! l'execute (`ALE_USER_ID`). Une erreur sur l'une des deux ne se voit pas a la
//! pose des filtres: WFP accepte le filtre, il ne matche simplement jamais, et
//! le daemon se retrouve incapable de joindre son endpoint une fois le kill
//! switch arme.
//!
//! L'autotest du cycle de vie ne peut pas voir ce defaut: il convertit les
//! blocages en autorisations, donc tout passe de toute facon. Observer un
//! matching demande un blocage reel. La sonde en pose un, mais restreint a UNE
//! adresse de destination sans trafic reel, ce qui laisse la machine en ligne.
//!
//! Trois mesures, parce qu'aucune ne suffit seule:
//!
//! 1. le daemon tente une connexion vers l'adresse et ne doit PAS etre refuse;
//! 2. une copie du meme binaire, a un autre chemin, tente la meme connexion et
//!    doit l'etre. C'est le temoin: sans lui, un blocage qui ne s'applique a
//!    personne donnerait exactement le meme resultat que le succes attendu.
//!    Seul le chemin change entre les deux, donc c'est bien `ALE_APP_ID` qui
//!    fait la difference;
//! 3. la meme sonde est reposee avec une identite d'utilisateur que le daemon
//!    n'a pas, et il doit alors etre refuse. C'est la mutation: sans elle, une
//!    condition `ALE_USER_ID` inoperante donnerait les memes mesures 1 et 2
//!    qu'une condition correcte, et la sonde certifierait une garantie
//!    inexistante.
//!
//! Ce que la sonde ne montre toujours pas: qu'un AUTRE utilisateur lancant le
//! binaire au bon chemin serait refuse. Le verifier demanderait un second
//! compte et ses identifiants. La mutation 3 en est le plus proche substitut:
//! elle etablit que WFP applique bien la condition d'utilisateur.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use anyhow::{Context, anyhow};
use bifrost_core::ports::KillSwitch;
use bifrost_firewall::wfp_plan::Identity;
use bifrost_firewall::windows::WfpKillSwitch;

/// Adresse de la sonde. TEST-NET-3 (RFC 5737), reservee a la documentation:
/// aucune machine legitime ne s'y trouve, et le blocage pose dessus ne peut
/// donc gener aucun trafic.
pub const TARGET: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 9);
/// Port discard (RFC 863).
const PORT: u16 = 9;
/// SID nul: syntaxiquement valide, porte par aucun token. Un DACL qui ne
/// l'autorise que lui n'autorise personne, ce qui est exactement ce que la
/// mutation veut poser.
const PERSONNE: &str = "S-1-0-0";
/// Au-dela, la destination est consideree injoignable, ce qui est le cas
/// attendu quand le permit a matche.
const DELAI: Duration = Duration::from_secs(2);

/// Un connect() refuse par un filtre WFP echoue avec ce code.
const WSAEACCES: i32 = 10013;
const WSAENETUNREACH: i32 = 10051;
const WSAEHOSTUNREACH: i32 = 10065;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Un filtre a refuse la connexion.
    Bloque,
    /// Rien n'a refuse la connexion. Elle n'a pas abouti pour autant: la
    /// destination n'existe pas.
    Passe,
    /// La connexion s'est etablie pour de bon. Distinct de [`Verdict::Passe`],
    /// qui couvre aussi l'echeance atteinte. La distinction n'a pas d'objet
    /// pour la sonde d'identite, qui vise une adresse de documentation ou rien
    /// ne repond; elle est indispensable a la mesure d'etancheite, dont le
    /// temoin negatif doit avoir REELLEMENT abouti avant l'armement. Un temoin
    /// qui expire ne prouve rien, et le confondre avec un succes rendrait la
    /// mesure vide de sens sur une cible injoignable.
    Connecte,
    /// La pile n'a meme pas essaye. La sonde ne mesure rien dans ce cas.
    SansRoute,
}

impl Verdict {
    /// Vrai si rien n'a refuse la connexion, qu'elle ait abouti ou expire.
    pub fn laisse_passer(self) -> bool {
        matches!(self, Verdict::Passe | Verdict::Connecte)
    }
}

impl Verdict {
    /// Code de sortie du processus temoin. Le zero revient a `Passe`: c'est le
    /// cas ou rien d'anormal ne s'est produit du point de vue du systeme.
    pub fn code(self) -> i32 {
        match self {
            Verdict::Passe => 0,
            Verdict::Bloque => 3,
            Verdict::SansRoute => 4,
            Verdict::Connecte => 5,
        }
    }

    pub fn from_code(code: i32) -> Option<Self> {
        match code {
            0 => Some(Verdict::Passe),
            3 => Some(Verdict::Bloque),
            4 => Some(Verdict::SansRoute),
            5 => Some(Verdict::Connecte),
            _ => None,
        }
    }
}

/// Traduit le resultat d'une tentative de connexion.
///
/// `None` correspond a l'echeance de `connect_timeout`, que la bibliotheque
/// standard signale sans code systeme. Une echeance atteinte veut dire que la
/// connexion est partie: rien ne l'a refusee.
pub fn classify(raw_os_error: Option<i32>) -> Verdict {
    match raw_os_error {
        Some(WSAEACCES) => Verdict::Bloque,
        Some(WSAENETUNREACH) | Some(WSAEHOSTUNREACH) => Verdict::SansRoute,
        _ => Verdict::Passe,
    }
}

pub fn address() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(TARGET), PORT)
}

/// Tente la connexion depuis le processus courant.
pub fn connect(addr: SocketAddr) -> Verdict {
    match TcpStream::connect_timeout(&addr, DELAI) {
        // Improbable sur une adresse de documentation, ou la sonde d'identite
        // se contente d'y lire une absence de refus. Sur une vraie cible, en
        // revanche, c'est la seule reponse qui atteste que le trafic circule,
        // et donc le seul temoin negatif recevable.
        Ok(_) => Verdict::Connecte,
        Err(e) => classify(e.raw_os_error()),
    }
}

/// La plus PERMISSIVE de deux issues.
///
/// Sert a resumer une rafale de tentatives: ce qui compte n'est pas ce que la
/// derniere a rendu, mais qu'UNE seule ait pu passer. Prendre le maximum dans
/// cet ordre, c'est refuser qu'une fuite breve soit noyee par les refus qui
/// l'entourent.
pub fn plus_permissif(a: Verdict, b: Verdict) -> Verdict {
    fn rang(v: Verdict) -> u8 {
        match v {
            Verdict::Bloque => 0,
            Verdict::SansRoute => 1,
            Verdict::Passe => 2,
            Verdict::Connecte => 3,
        }
    }
    if rang(a) >= rang(b) { a } else { b }
}

/// Tente la connexion en boucle pendant `duree`, et rend la plus permissive.
///
/// Une fenetre de fuite se mesure en millisecondes: la sonder en relancant un
/// processus par tentative laisserait entre deux essais plus de temps que la
/// fenetre n'en dure. Ici le processus est lance une fois et boucle a l'interieur.
/// Une rafale fait TOUJOURS au moins une tentative, et cette phrase a ete
/// payee. La redaction d'origine partait de `Verdict::Bloque` et bouclait
/// `while elapsed < duree`: avec une duree nulle, elle rendait **BLOQUE sans
/// avoir tente une seule connexion**. Mesure du 23/08/2026 sur dev-windows,
/// `rafale(addr, 0 ms)` rend le code 3 en imprimant `rafale: 0 tentatives en
/// 4.2us`. Aucun appelant ne passait zero - ils passent tous 8000 ms - donc
/// rien n'a jamais menti; c'etait un piege arme pour le suivant, et de la pire
/// espece: un blocage fabrique est indiscernable d'un vrai. La premiere
/// tentative est desormais hors de la boucle.
pub fn rafale(addr: SocketAddr, duree: Duration) -> Verdict {
    let debut = std::time::Instant::now();
    let mut pire = connect(addr);
    let mut essais = 1u64;
    while debut.elapsed() < duree {
        pire = plus_permissif(pire, connect(addr));
        essais += 1;
        // Un refus WFP revient immediatement; une tentative qui aboutit prend
        // le temps d'un aller-retour. Rien a temporiser: la densite de
        // l'echantillonnage est ce qu'on cherche a maximiser.
    }
    eprintln!("rafale: {essais} tentatives en {:?}", debut.elapsed());
    pire
}

/// Ce que la sonde a conclu.
pub enum Issue {
    Reussi,
    /// La sonde n'a pas pu mesurer. Jamais un succes par defaut.
    Ignore(String),
    Echec(String),
}

/// Pose la sonde, mesure, retire la sonde.
///
/// Le retrait a lieu quel que soit le resultat des mesures, et avant leur
/// analyse: laisser des filtres en place parce qu'une comparaison a echoue
/// serait le meme defaut que celui qui a deja coute un redemarrage.
/// Les trois mesures, sans interpretation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mesures {
    /// Le daemon lui-meme, qui doit passer.
    pub daemon: Verdict,
    /// Une copie du binaire ailleurs, qui doit etre bloquee.
    pub temoin: Verdict,
    /// Le daemon sous une identite que personne ne porte, qui doit etre
    /// bloquee.
    pub mute: Verdict,
}

/// Pose la sonde, mesure trois fois, retire la sonde.
pub fn mesurer_tout(firewall: &mut WfpKillSwitch) -> anyhow::Result<Mesures> {
    let (daemon, temoin) = mesurer(firewall, Identity::Current, |addr| {
        (connect(addr), via_copie(addr))
    })?;
    let temoin = temoin?;
    // Mutation: la meme sonde, avec une identite que personne ne porte.
    let mute = mesurer(firewall, Identity::Sid(PERSONNE.to_owned()), connect)?;
    Ok(Mesures {
        daemon,
        temoin,
        mute,
    })
}

pub fn run(firewall: &mut WfpKillSwitch) -> anyhow::Result<Issue> {
    let m = mesurer_tout(firewall)?;
    println!("  identite du daemon, depuis le daemon:  {:?}", m.daemon);
    println!("  identite du daemon, depuis une copie:  {:?}", m.temoin);
    println!("  identite {PERSONNE}, depuis le daemon:   {:?}", m.mute);
    Ok(juger(m))
}

/// Ce que les trois mesures etablissent.
///
/// Pure et separee de la mesure: c'est ici que se decide ce qui compte comme
/// preuve, et ca doit pouvoir se discuter et se tester sans machine Windows ni
/// privileges. La presentation, elle, differe selon l'appelant: la console
/// affiche, le service journalise.
pub fn juger(m: Mesures) -> Issue {
    let Mesures {
        daemon,
        temoin,
        mute,
    } = m;
    if [daemon, temoin, mute].contains(&Verdict::SansRoute) {
        return Issue::Ignore(format!(
            "pas de route vers {TARGET}: la sonde ne peut rien conclure"
        ));
    }
    if temoin != Verdict::Bloque {
        return Issue::Echec(format!(
            "le temoin n'a pas ete bloque ({temoin:?}): le blocage de la sonde \
             ne s'applique a personne, le succes du daemon ne prouve donc rien"
        ));
    }
    if !daemon.laisse_passer() {
        return Issue::Echec(format!(
            "le daemon a ete bloque par son propre kill switch ({daemon:?}): \
             les conditions ALE_APP_ID et ALE_USER_ID ne le designent pas"
        ));
    }
    if mute != Verdict::Bloque {
        return Issue::Echec(format!(
            "avec l'identite {PERSONNE}, que le daemon n'a pas, il passe quand \
             meme ({mute:?}): WFP n'applique pas la condition ALE_USER_ID, qui \
             n'apporte donc aucune garantie"
        ));
    }
    Issue::Reussi
}

/// Pose la sonde avec l'identite demandee, mesure, retire la sonde.
///
/// Le retrait a lieu avant toute analyse et quel que soit le resultat des
/// mesures: laisser des filtres en place parce qu'une comparaison a echoue
/// serait le meme defaut que celui qui a deja coute un redemarrage.
fn mesurer<T>(
    firewall: &mut WfpKillSwitch,
    user: Identity,
    mesures: impl FnOnce(SocketAddr) -> T,
) -> anyhow::Result<T> {
    let addr = address();
    let poses = firewall
        .engage_identity_probe(TARGET, user)
        .map_err(|e| anyhow!("pose de la sonde d'identite: {e}"))?;
    tracing::debug!(filtres = poses, cible = %addr, "sonde d'identite posee");
    let resultats = mesures(addr);
    firewall
        .disengage()
        .map_err(|e| anyhow!("retrait de la sonde d'identite: {e}"))?;
    Ok(resultats)
}

/// Rejoue la meme tentative depuis une copie du binaire placee ailleurs.
///
/// Meme contenu, meme utilisateur, seul le chemin change: c'est donc
/// exactement la condition `ALE_APP_ID` qui doit faire la difference.
pub(crate) fn via_copie(addr: SocketAddr) -> anyhow::Result<Verdict> {
    let source = std::env::current_exe().context("chemin du binaire courant")?;
    let copie = Copie::depuis(&source)?;
    sonder_depuis(&copie.chemin, addr)
}

/// Rejoue la meme tentative depuis le binaire situe a `chemin`.
///
/// Separe de [`via_copie`] parce que tous les appelants ne veulent pas la meme
/// copie: la sonde d'identite veut un chemin QUELCONQUE, le vecteur
/// `coeur-exemption` veut CELUI que le plan exempte. Confondre les deux ferait
/// sonder l'un en croyant sonder l'autre, et la mesure serait verte pour la
/// mauvaise raison.
pub(crate) fn sonder_depuis(chemin: &std::path::Path, addr: SocketAddr) -> anyhow::Result<Verdict> {
    sonder_depuis_pendant(chemin, addr, None)
}

/// La meme sonde, mais en rafale pendant `duree` quand elle est donnee.
///
/// Rendue separement pour que l'appelant CHOISISSE: une mesure d'etat se
/// contente d'une tentative, une mesure de FENETRE en demande des milliers.
pub(crate) fn sonder_depuis_pendant(
    chemin: &std::path::Path,
    addr: SocketAddr,
    duree: Option<Duration>,
) -> anyhow::Result<Verdict> {
    let mut cmd = Command::new(chemin);
    cmd.arg("--connect-probe").arg(addr.to_string());
    if let Some(d) = duree {
        cmd.arg("--connect-probe-rafale")
            .arg(d.as_millis().to_string());
    }
    let status = cmd
        .status()
        .with_context(|| format!("lancement de {}", chemin.display()))?;

    let code = status
        .code()
        .ok_or_else(|| anyhow!("le temoin s'est termine sans code de sortie"))?;
    Verdict::from_code(code).ok_or_else(|| {
        anyhow!("code de sortie inattendu du temoin: {code}. La sonde ne conclut rien.")
    })
}

/// Copie temporaire du binaire, effacee a la liberation.
struct Copie {
    chemin: PathBuf,
}

impl Copie {
    fn depuis(source: &std::path::Path) -> anyhow::Result<Self> {
        let chemin =
            std::env::temp_dir().join(format!("bifrost-temoin-{}.exe", std::process::id()));
        std::fs::copy(source, &chemin)
            .with_context(|| format!("copie de {} vers {}", source.display(), chemin.display()))?;
        Ok(Self { chemin })
    }
}

impl Drop for Copie {
    fn drop(&mut self) {
        // Windows peut garder l'image mappee un court instant apres la sortie
        // du processus. On reessaie plutot que de laisser un exe dans le
        // repertoire temporaire.
        for _ in 0..5 {
            if std::fs::remove_file(&self.chemin).is_ok() {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        eprintln!(
            "copie temoin non effacee: {} (a supprimer a la main)",
            self.chemin.display()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::TcpListener;

    const WSAECONNREFUSED: i32 = 10061;

    /// Les valeurs de plateforme sont epinglees sur leur source, pas sur
    /// elles-memes.
    ///
    /// `classify` compare `raw_os_error` a ces constantes, et les recettes de
    /// classification ci-dessous les emploient DES DEUX COTES de l'egalite: une
    /// valeur fausse s'y teste alors elle-meme et ne rougit pas. Mesure du
    /// 04/09/2026 sur dev-windows, mutation d'un cran sur chacune: les cinq
    /// muettes. Cette recette-ci les confronte a leur seule source possible.
    ///
    /// Les trois codes Winsock viennent de `winerror.h`; ils ne se deduisent de
    /// rien et sont donc recopies en clair, comme `AF_INET6` l'est cote wgnt.
    /// Le SID nul est celui de la convention Windows, et le port 9 est le port
    /// discard de la RFC 863.
    #[test]
    fn les_valeurs_de_plateforme_sont_epinglees_sur_leur_source() {
        assert_eq!(WSAEACCES, 10013);
        assert_eq!(WSAENETUNREACH, 10051);
        assert_eq!(WSAEHOSTUNREACH, 10065);
        assert_eq!(PERSONNE, "S-1-0-0");
        assert_eq!(PORT, 9);
    }

    /// Le seul code qui atteste d'un refus par un filtre. Le confondre avec un
    /// autre ferait passer la sonde pour reussie sur une machine sans reseau.
    #[test]
    fn seul_wsaeacces_vaut_blocage() {
        assert_eq!(classify(Some(WSAEACCES)), Verdict::Bloque);
        assert_eq!(classify(Some(WSAECONNREFUSED)), Verdict::Passe);
        assert_eq!(classify(None), Verdict::Passe);
    }

    /// Une pile qui n'a pas de route n'a rien mesure. Traiter ce cas comme un
    /// succes donnerait une sonde qui passe sur une machine deconnectee.
    #[test]
    fn l_absence_de_route_ne_vaut_ni_succes_ni_echec() {
        assert_eq!(classify(Some(WSAENETUNREACH)), Verdict::SansRoute);
        assert_eq!(classify(Some(WSAEHOSTUNREACH)), Verdict::SansRoute);
    }

    #[test]
    fn les_codes_de_sortie_font_l_aller_retour() {
        for v in [
            Verdict::Passe,
            Verdict::Bloque,
            Verdict::SansRoute,
            Verdict::Connecte,
        ] {
            assert_eq!(Verdict::from_code(v.code()), Some(v));
        }
        assert_eq!(Verdict::from_code(1), None);
    }

    /// Les codes de sortie voyagent entre deux processus. Deux verdicts qui
    /// partageraient un code rendraient le temoin illisible, et la collision
    /// ne se verrait qu'a l'execution sur la vraie machine.
    #[test]
    fn deux_verdicts_ne_partagent_jamais_un_code() {
        let tous = [
            Verdict::Passe,
            Verdict::Bloque,
            Verdict::SansRoute,
            Verdict::Connecte,
        ];
        let mut codes: Vec<i32> = tous.iter().map(|v| v.code()).collect();
        codes.sort_unstable();
        let avant = codes.len();
        codes.dedup();
        assert_eq!(codes.len(), avant, "deux verdicts partagent un code");
    }

    /// `laisse_passer` sert a distinguer un refus de tout le reste. Confondre
    /// `Connecte` avec un blocage ferait echouer la sonde d'identite le jour ou
    /// quelque chose repondrait a l'adresse de documentation.
    #[test]
    fn seul_un_blocage_ne_laisse_pas_passer() {
        assert!(Verdict::Passe.laisse_passer());
        assert!(Verdict::Connecte.laisse_passer());
        assert!(!Verdict::Bloque.laisse_passer());
        assert!(!Verdict::SansRoute.laisse_passer());
    }

    fn nom(issue: &Issue) -> &'static str {
        match issue {
            Issue::Reussi => "Reussi",
            Issue::Ignore(_) => "Ignore",
            Issue::Echec(_) => "Echec",
        }
    }

    fn mesures(daemon: Verdict, temoin: Verdict, mute: Verdict) -> Mesures {
        Mesures {
            daemon,
            temoin,
            mute,
        }
    }

    /// Le daemon passe, la copie est bloquee, la mutation est bloquee. C'est la
    /// seule combinaison qui etablit quelque chose.
    #[test]
    fn la_combinaison_attendue_vaut_reussite() {
        for daemon in [Verdict::Passe, Verdict::Connecte] {
            let i = juger(mesures(daemon, Verdict::Bloque, Verdict::Bloque));
            assert_eq!(nom(&i), "Reussi", "avec un daemon {daemon:?}");
        }
    }

    /// Sans temoin bloque, le blocage pose ne s'applique a personne: le succes
    /// du daemon ne prouve alors rien du tout.
    #[test]
    fn un_temoin_non_bloque_ne_prouve_rien() {
        let i = juger(mesures(Verdict::Passe, Verdict::Passe, Verdict::Bloque));
        assert_eq!(nom(&i), "Echec");
    }

    /// Un daemon bloque par son propre kill switch est le defaut qu'on cherche:
    /// les conditions le decrivent mal, et une fois le kill switch arme il ne
    /// pourra plus joindre son endpoint.
    #[test]
    fn un_daemon_bloque_par_son_propre_filtre_est_un_echec() {
        let i = juger(mesures(Verdict::Bloque, Verdict::Bloque, Verdict::Bloque));
        assert_eq!(nom(&i), "Echec");
    }

    /// La mutation est ce qui distingue une condition appliquee d'une condition
    /// ignoree. Si le daemon passe sous une identite que personne ne porte,
    /// c'est que WFP n'applique pas ALE_USER_ID.
    #[test]
    fn une_mutation_qui_passe_invalide_la_condition() {
        let i = juger(mesures(Verdict::Passe, Verdict::Bloque, Verdict::Passe));
        assert_eq!(nom(&i), "Echec");
    }

    /// Une pile sans route n'a rien mesure. Ni succes ni echec.
    #[test]
    fn sans_route_rien_n_est_conclu() {
        for m in [
            mesures(Verdict::SansRoute, Verdict::Bloque, Verdict::Bloque),
            mesures(Verdict::Passe, Verdict::SansRoute, Verdict::Bloque),
            mesures(Verdict::Passe, Verdict::Bloque, Verdict::SansRoute),
        ] {
            assert_eq!(nom(&juger(m)), "Ignore", "mesures {m:?}");
        }
    }

    /// L'adresse de la sonde doit rester dans un prefixe de documentation:
    /// c'est ce qui garantit que le blocage pose ne gene aucun trafic reel.
    #[test]
    fn la_cible_est_une_adresse_de_documentation() {
        assert_eq!(TARGET.octets()[0..3], [203, 0, 113]);
    }

    /// Une rafale tente TOUJOURS au moins une connexion, meme avec une duree
    /// nulle. La redaction d'origine partait de `Verdict::Bloque` et placait sa
    /// premiere tentative DANS `while debut.elapsed() < duree`: avec zero, la
    /// boucle ne tournait pas et le verdict initial ressortait tel quel.
    ///
    /// Ce que cette garde tient n'est pas un cas limite d'appelant. Un blocage
    /// fabrique est indiscernable d'un vrai: la sonde certifierait un refus
    /// qu'elle n'a jamais mesure, et rien dans sa sortie ne le trahirait. La
    /// garde ne peut pas mesurer WFP, mais elle mesure ce qui est ici
    /// mesurable: qu'une rafale de duree nulle a bien REJOINT une machine qui
    /// ecoute. Seul `Connecte` atteste d'un aller-retour reel, ce qui exclut
    /// aussi le cas ou une future redaction rendrait `Passe` sans rien tenter.
    #[test]
    fn une_rafale_de_duree_nulle_tente_quand_meme() {
        // Le listener doit vivre pendant tout l'appel a `rafale`: s'il tombe
        // avant, la connexion est refusee et le verdict change pour une raison
        // qui n'a rien a voir avec ce que la garde surveille.
        let ecoute =
            TcpListener::bind("127.0.0.1:0").expect("la boucle locale doit accepter un listener");
        let addr = ecoute
            .local_addr()
            .expect("le listener doit connaitre son adresse");

        let verdict = rafale(addr, Duration::ZERO);

        assert_eq!(
            verdict,
            Verdict::Connecte,
            "rafale(duree nulle) vers {addr}, ou un listener ecoute pourtant, \
             rend {verdict:?} au lieu de Connecte. Si c'est Bloque: la premiere \
             tentative est retombee dans `while debut.elapsed() < duree`, qui \
             ne tourne pas avec une duree nulle, donc le verdict initial sort \
             sans qu'AUCUNE connexion ait ete tentee. C'est un blocage \
             fabrique, indiscernable d'un vrai."
        );
    }
}
