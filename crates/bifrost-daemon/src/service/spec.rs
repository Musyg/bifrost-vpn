//! Ce que le service Windows doit etre, sous forme de donnee.
//!
//! Meme parti pris que pour le plan WFP et le ruleset nftables: la politique
//! est une donnee produite par une fonction pure, donc lisible et testable sans
//! la machine cible. Ce qui est declare ici a des consequences de securite, et
//! chaque champ est verrouille par un test qui dit pourquoi.
//!
//! La reference est l'unite systemd, `packaging/systemd/bifrost-daemon.service`.
//! Elle porte trois decisions qui ne sont pas cosmetiques: demarrer avant que
//! le reseau soit monte, redemarrer sur echec, et **ne pas desarmer le kill
//! switch en s'arretant**. Elles se disent autrement sous Windows, elles ne
//! disparaissent pas.

/// Nom interne, celui que voit le gestionnaire de controle des services.
pub const NOM: &str = "BifrostDaemon";

/// Service dont depend toute la pose de filtres.
///
/// Verifie le 16 aout 2026 par `sc qc BFE` sur une machine Windows 11: nom
/// court `BFE`, demarrage automatique, groupe d'ordre de chargement
/// `NetworkProvider`, dependante de `RpcSs`.
pub const BFE: &str = "BFE";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Demarrage {
    Automatique,
    Manuel,
    Desactive,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceSpec {
    pub nom: &'static str,
    pub nom_affiche: &'static str,
    pub description: &'static str,
    pub demarrage: Demarrage,
    /// `None` vaut LocalSystem. Le daemon pose des filtres WFP et cree des
    /// interfaces reseau: aucun compte moins privilegie ne suffit, et en
    /// nommer un ici obligerait a manipuler son mot de passe.
    pub compte: Option<&'static str>,
    pub dependances: &'static [&'static str],
    /// Le token du service porte-t-il le SID du service?
    ///
    /// Par defaut Windows repond NON, et c'est un piege mesure le 16 aout 2026:
    /// le daemon installe en service annoncait `sid=S-1-5-18
    /// sid_de_service=false`. Autrement dit, passer en service SANS ce reglage
    /// degrade la garantie au lieu de l'ameliorer, puisque `S-1-5-18` est
    /// partage par tous les services de la machine, alors qu'en console le
    /// daemon tombait au moins sur le SID d'un utilisateur precis.
    pub sid_de_service: bool,
    /// Zero vaut "ne pas redemarrer".
    pub redemarrages_sur_echec: u32,
    /// Le daemon retire-t-il ses filtres quand le service s'arrete?
    pub desarme_en_s_arretant: bool,
}

pub const fn spec() -> ServiceSpec {
    ServiceSpec {
        nom: NOM,
        nom_affiche: "Bifrost, tunnel WireGuard et kill switch",
        description: "Monte le tunnel WireGuard et pose le kill switch WFP. \
                      L'arret du service ne rouvre pas le trafic: le retrait \
                      des filtres est explicite.",
        demarrage: Demarrage::Automatique,
        compte: None,
        dependances: &[BFE],
        sid_de_service: true,
        redemarrages_sur_echec: 3,
        desarme_en_s_arretant: false,
    }
}

/// Sous-repertoire de `%ProgramData%` ou le service ecrit ce qu'il a a dire.
pub const REPERTOIRE: &str = "Bifrost";
/// Journal du service.
///
/// Un service n'a pas de sortie standard: sans fichier, tout ce que le daemon
/// journalise part dans le vide, y compris la raison pour laquelle il refuse de
/// demarrer. `%ProgramData%` plutot que le profil d'un utilisateur, le service
/// tournant en LocalSystem.
pub const FICHIER_JOURNAL: &str = "bifrost-daemon.log";

/// Chemin du journal, a partir de la racine de donnees de la machine.
pub fn chemin_journal(program_data: &std::path::Path) -> std::path::PathBuf {
    program_data.join(REPERTOIRE).join(FICHIER_JOURNAL)
}

/// La ligne de commande que le SCM enregistre pour le service.
///
/// Le pendant de l'`ExecStart` de `packaging/systemd/bifrost-daemon.service`,
/// et il faut lire les deux ensemble: l'unite systemd nomme le resolveur
/// chiffre, cette ligne ne le nommait pas. Un service qui ne le nomme pas ne
/// peut PAS en lancer un, meme avec le binaire depose a cote de lui - c'est
/// `atelier_du_resolveur` qui rend `None` faute de `--resolveur-binaire`.
/// Deposer ne suffit donc pas: il faut nommer.
///
/// Fonction pure, et hors de `scm.rs` pour cette raison: elle est mesuree sur
/// les deux hotes, y compris celui qui ne peut pas installer de service. Une
/// citation manquante n'echouerait qu'au DEMARRAGE du service, loin de sa
/// cause.
///
/// Les guillemets sont indispensables sur les DEUX chemins. Le chemin
/// d'installation naturel contient une espace (`C:\Program Files\Bifrost`):
/// sans eux, le SCM lance le mauvais executable, et clap recoit `C:\Program`
/// comme valeur de `--resolveur-binaire`.
///
/// `compte` (11b-2) est le compte de service sous lequel le daemon lance le
/// resolveur (`--resolveur-utilisateur`, forme canonique `LocalService`). Cite
/// comme les chemins, et pour la meme raison: un compte peut porter une espace
/// (`NT AUTHORITY\LocalService`), et sans guillemets le SCM couperait
/// l'argument en deux. Il vient APRES le binaire, et `install-windows.ps1`
/// comme `packaging-windows.ps1` s'alignent sur cette forme exacte.
pub fn ligne_de_commande(
    exe: &std::path::Path,
    avec_sonde: bool,
    resolveur: Option<&std::path::Path>,
    compte: Option<&str>,
) -> String {
    let mut ligne = format!("\"{}\" --service", exe.display());
    if avec_sonde {
        ligne.push_str(" --service-identity-probe");
    }
    if let Some(r) = resolveur {
        ligne.push_str(&format!(" --resolveur-binaire \"{}\"", r.display()));
    }
    if let Some(c) = compte {
        ligne.push_str(&format!(" --resolveur-utilisateur \"{c}\""));
    }
    ligne
}

/// Encode la liste de dependances au format attendu par `CreateServiceW`.
///
/// Le SCM veut des chaines terminees chacune par un nul, la derniere suivie
/// d'un nul supplementaire. Rend `None` pour une liste vide, le SCM attendant
/// alors un pointeur nul et non une liste vide.
///
/// Volontairement ecrit sur `encode_utf16`, disponible partout, plutot que sur
/// `OsStrExt::encode_wide` qui n'existe que sous Windows: une erreur de
/// terminaison ici est SILENCIEUSE, le service se cree sans sa dependance, et
/// ca ne se voit qu'au premier demarrage trop rapide. Ca merite d'etre teste en
/// CI, y compris sous Linux.
pub fn dependances_encodees(items: &[&str]) -> Option<Vec<u16>> {
    if items.is_empty() {
        return None;
    }
    let mut brut = Vec::new();
    for item in items {
        brut.extend(item.encode_utf16());
        brut.push(0);
    }
    brut.push(0);
    Some(brut)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn exe() -> &'static Path {
        Path::new(r"C:\Program Files\Bifrost\bifrost-daemon.exe")
    }
    fn resolveur() -> &'static Path {
        Path::new(r"C:\Program Files\Bifrost\dnscrypt-proxy.exe")
    }

    /// Le pendant de l'`ExecStart` de l'unite systemd, et le defaut qu'il
    /// corrige. L'unite porte `--resolveur-binaire`; la ligne du service
    /// Windows ne le portait pas, donc `atelier_du_resolveur` rendait `None` et
    /// le service ne pouvait PAS embarquer de resolveur chiffre - meme avec le
    /// binaire depose a cote de lui. Deposer ne suffit pas: il faut nommer.
    #[test]
    fn le_resolveur_declare_est_nomme_dans_la_ligne() {
        let l = ligne_de_commande(exe(), false, Some(resolveur()), None);
        assert!(
            l.contains("--resolveur-binaire"),
            "sans ce drapeau le service ne lancera aucun resolveur: {l}"
        );
        assert!(l.contains("dnscrypt-proxy.exe"), "{l}");
    }

    /// LA recette de ce coin du fichier. `C:\Program Files\...` contient une
    /// espace: sans guillemets, clap recevrait `C:\Program` comme valeur et le
    /// service demarrerait en cherchant un binaire qui n'existe pas. L'echec
    /// serait au DEMARRAGE, pas a l'installation, donc loin de sa cause.
    #[test]
    fn les_deux_chemins_sont_cites() {
        let l = ligne_de_commande(exe(), false, Some(resolveur()), None);
        assert!(
            l.contains(&format!("\"{}\"", exe().display())),
            "chemin du daemon non cite: {l}"
        );
        assert!(
            l.contains(&format!("\"{}\"", resolveur().display())),
            "chemin du resolveur non cite: {l}"
        );
        assert_eq!(
            l.matches('"').count() % 2,
            0,
            "guillemets impairs, le decoupage Windows serait imprevisible: {l}"
        );
    }

    /// Rien de declare, rien d'ecrit. Un `--resolveur-binaire ""` donnerait un
    /// service qui refuse de demarrer, ce qui est pire que pas de resolveur du
    /// tout: sans le drapeau, le daemon sert sans resolveur embarque et le dit.
    #[test]
    fn sans_resolveur_la_ligne_n_en_mentionne_aucun() {
        let l = ligne_de_commande(exe(), false, None, None);
        assert!(!l.contains("--resolveur-binaire"), "{l}");
        assert!(l.ends_with("--service"), "{l}");
    }

    /// Le service de DIAGNOSTIC et le resolveur ne s'excluent pas: la sonde
    /// mesure une identite, elle ne remplace pas la configuration.
    #[test]
    fn la_sonde_et_le_resolveur_cohabitent() {
        let l = ligne_de_commande(exe(), true, Some(resolveur()), None);
        assert!(l.contains("--service-identity-probe"), "{l}");
        assert!(l.contains("--resolveur-binaire"), "{l}");
    }

    /// L'ordre n'est pas cosmetique: `--service` doit rester le premier
    /// argument. C'est lui que `main` regarde pour rendre la main au
    /// gestionnaire de services au lieu de demarrer un runtime.
    #[test]
    fn le_drapeau_de_service_vient_en_premier() {
        for (sonde, r) in [(false, None), (true, Some(resolveur()))] {
            let l = ligne_de_commande(exe(), sonde, r, None);
            let apres = l.split_once("--").expect("au moins un drapeau").1;
            assert!(apres.starts_with("service"), "{l}");
        }
    }

    /// 11b-2. Le compte de service declare est nomme, cite, et APRES le
    /// binaire: c'est ce que `install-windows.ps1` inscrit dans la ligne du
    /// service et ce que `packaging-windows.ps1` relit dans le registre. Les
    /// guillemets ne sont pas cosmetiques: un compte peut porter une espace
    /// (`NT AUTHORITY\LocalService`), et sans eux le SCM couperait l'argument.
    #[test]
    fn le_compte_declare_est_nomme_cite_et_apres_le_binaire() {
        let l = ligne_de_commande(exe(), false, Some(resolveur()), Some("LocalService"));
        assert!(
            l.contains("--resolveur-utilisateur \"LocalService\""),
            "compte non nomme ou non cite: {l}"
        );
        let binaire = l.find("--resolveur-binaire").expect("binaire nomme");
        let compte = l.find("--resolveur-utilisateur").expect("compte nomme");
        assert!(
            compte > binaire,
            "le compte doit venir APRES le binaire: {l}"
        );
        assert_eq!(
            l.matches('"').count() % 2,
            0,
            "guillemets impairs, le decoupage Windows serait imprevisible: {l}"
        );
    }

    /// Un compte portant une espace reste UN argument, cite entier.
    #[test]
    fn un_compte_avec_une_espace_est_cite_entier() {
        let l = ligne_de_commande(
            exe(),
            false,
            Some(resolveur()),
            Some(r"NT AUTHORITY\LocalService"),
        );
        assert!(
            l.contains("--resolveur-utilisateur \"NT AUTHORITY\\LocalService\""),
            "{l}"
        );
    }

    /// Sans compte, la ligne n'en mentionne aucun: un `--resolveur-utilisateur ""`
    /// ferait echouer le lancement du resolveur au demarrage du service, loin
    /// de sa cause. Avec ou sans binaire.
    #[test]
    fn sans_compte_la_ligne_n_en_mentionne_aucun() {
        for r in [None, Some(resolveur())] {
            let l = ligne_de_commande(exe(), false, r, None);
            assert!(!l.contains("--resolveur-utilisateur"), "{l}");
        }
    }

    /// Une dependance unique se termine par DEUX nuls: celui de la chaine et
    /// celui de la liste. Avec un seul, le SCM lit au-dela du tampon.
    #[test]
    fn une_dependance_est_terminee_par_deux_nuls() {
        let encode = dependances_encodees(&["BFE"]).expect("liste non vide");
        assert_eq!(encode, vec![b'B' as u16, b'F' as u16, b'E' as u16, 0, 0]);
    }

    #[test]
    fn les_dependances_sont_separees_par_un_nul() {
        let encode = dependances_encodees(&["A", "BC"]).expect("liste non vide");
        assert_eq!(encode, vec![b'A' as u16, 0, b'B' as u16, b'C' as u16, 0, 0]);
    }

    /// Une liste vide n'est pas une liste de zero element: le SCM veut un
    /// pointeur nul. Lui passer `[0]` ferait une premiere chaine vide.
    #[test]
    fn une_liste_vide_ne_produit_aucun_tampon() {
        assert_eq!(dependances_encodees(&[]), None);
    }

    /// Le journal va sous `%ProgramData%`, pas dans le profil d'un
    /// utilisateur: le service tourne en LocalSystem, et un chemin de profil
    /// le renverrait dans un repertoire qui n'existe pas pour lui.
    #[test]
    fn le_journal_va_sous_le_repertoire_de_donnees_de_la_machine() {
        let c = chemin_journal(std::path::Path::new("X:\\Donnees"));
        assert!(c.ends_with(FICHIER_JOURNAL));
        assert!(
            c.to_string_lossy().contains(REPERTOIRE),
            "chemin obtenu: {}",
            c.display()
        );
        assert!(c.starts_with("X:\\Donnees"));
    }

    /// La specification reelle doit passer l'encodage sans cas particulier.
    #[test]
    fn la_specification_reelle_s_encode() {
        let encode = dependances_encodees(spec().dependances).expect("BFE au moins");
        assert_eq!(encode.last(), Some(&0));
        assert_eq!(encode[encode.len() - 2], 0);
    }

    /// Le test le plus important du fichier. Toute la pose de filtres passe par
    /// la Base Filtering Engine. Un service qui demarre avant elle voit chaque
    /// `FwpmEngineOpen0` echouer, et un kill switch qui echoue au demarrage est
    /// exactement la fenetre de fuite qu'il etait cense fermer. Le jour ou
    /// quelqu'un retire cette dependance parce que "ca demarre quand meme sur
    /// ma machine", c'est ce test qui doit l'arreter: ca demarre quand meme
    /// tant que BFE a eu le temps de monter, et ca cesse le jour ou la machine
    /// est plus lente ou plus chargee.
    #[test]
    fn le_service_depend_de_la_base_filtering_engine() {
        assert!(
            spec().dependances.contains(&BFE),
            "sans dependance a BFE, le kill switch peut demarrer avant le \
             moteur qui pose ses filtres"
        );
    }

    /// L'arret DEMANDE ne desarme pas. C'est tout ce que cette garde dit.
    ///
    /// Elle lit un booleen de NOTRE PROPRE specification de service. S'il
    /// passait a vrai, l'arret du service deviendrait un moyen trivial de lever
    /// le kill switch, y compris pour un logiciel malveillant qui sait appeler
    /// `ControlService`.
    ///
    /// # Ce qu'elle ne verifie pas
    ///
    /// Elle ne dit rien de la MORT du processus, et rien du tout du moteur WFP.
    /// Son commentaire annoncait pourtant "un daemon qui meurt ne doit pas
    /// rouvrir le trafic", affirmation bien plus large que l'assertion ne
    /// pouvait porter, et il se reclamait d'une parite avec `ExecStopPost` qui
    /// etait fausse: l'unite systemd desarmait sur tous les chemins d'arret,
    /// plantage compris. C'est cet ecart entre ce qu'une garde affirme et ce
    /// qu'elle mesure qui a laisse vivre le defaut Linux.
    ///
    /// Ce que devient le trafic quand le daemon MEURT est etabli ailleurs, et
    /// par mesure, pas par lecture d'un booleen: voir l'en-tete de
    /// `super::scm`.
    ///
    /// # Sa jumelle
    ///
    /// `l_arret_de_l_unite_ne_rouvre_pas_le_trafic`, cote Linux, qui lit
    /// l'unite systemd et refuse qu'une directive du cycle de vie desarme. Les
    /// deux se nomment l'une l'autre a dessein: c'est ce chainage qui manquait,
    /// et le defaut Linux a survecu parce que le cote Windows revendiquait une
    /// parite que rien n'allait verifier.
    #[test]
    fn l_arret_du_service_ne_rouvre_pas_le_trafic() {
        assert!(
            !spec().desarme_en_s_arretant,
            "l'arret du service ne doit pas desarmer le kill switch"
        );
    }

    /// Sans ce reglage, le token du service ne contient aucun SID de service et
    /// la condition `ALE_USER_ID` retombe sur `S-1-5-18`, partage par tous les
    /// services de la machine. Ce n'est pas une amelioration marginale qu'on
    /// pourrait remettre a plus tard: mesure le 16 aout 2026, passer en service
    /// sans ca rend la garantie PLUS FAIBLE qu'en console, ou le daemon tombait
    /// au moins sur le SID d'un utilisateur precis.
    #[test]
    fn le_service_porte_son_propre_sid() {
        assert!(
            spec().sid_de_service,
            "sans SID de service, ALE_USER_ID retombe sur S-1-5-18"
        );
    }

    /// LocalSystem, et pas un compte nomme. Un compte nomme demanderait un mot
    /// de passe a la creation du service, donc un secret a stocker quelque
    /// part, pour un daemon qui a de toute facon besoin des privileges les plus
    /// eleves.
    #[test]
    fn le_service_tourne_en_localsystem() {
        assert_eq!(spec().compte, None);
    }

    /// Un kill switch qui attend qu'on le lance a la main ne protege personne
    /// au demarrage de la machine, ce qui est precisement le moment ou la
    /// fenetre de fuite est ouverte.
    #[test]
    fn le_demarrage_est_automatique() {
        assert_eq!(spec().demarrage, Demarrage::Automatique);
        assert!(spec().redemarrages_sur_echec > 0);
    }
}
