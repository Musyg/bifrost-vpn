//! Reconnaissance des regles nft par identite, sur la forme que nft REND.
//!
//! Pur: du texte entre, une reponse sort, rien ne touche au systeme. Compile
//! partout, donc ses recettes comptent sur les deux hotes.
//!
//! # D'ou vient ce module, et pourquoi il a bouge (5u)
//!
//! Ecrit par 5m dans `bifrost-daemon/src/checks/regles_nft.rs`, il a demenage
//! ici avec 5u: le crate qui REND les regles (`bifrost-firewall`) est celui qui
//! sait quelle forme elles ont, et `bifrost-daemon` depend de lui, jamais
//! l'inverse; `checks::regles_nft` n'est plus qu'une pelure qui re-exporte ce
//! module. Il vit au niveau superieur du crate, volontairement hors de tout
//! `cfg`, sur le modele de `wfp_plan` et `plan_telemetrie`: un module pur
//! compte sur les deux hotes. Le poser sous `linux/`
//! (gate `cfg(target_os = "linux")`) l'aurait fait ne compter que sur
//! essai-linux, ce qui contredisait sa nature pure et portable; il est donc
//! remonte au niveau du crate.
//!
//! # Le defaut que ce module ferme (5m)
//!
//! La presence d'une regle par identite se verifiait par sous-chaine:
//! `ruleset.contains(&uid.to_string())`. La sous-chaine `0` se trouve dans
//! n'importe quel ruleset (`127.0.0.1`, `dport 53`, `0x0000ca6c`,
//! `packets 0`), et `6553` est une sous-chaine de `65533`. Une garde ecrite
//! ainsi rougit pour une raison qui n'est pas la sienne, et une absence
//! reelle de la regle `meta skuid <uid> ...` passe inapercue des que le
//! chiffre figure ailleurs: elle passe pour la mauvaise raison.
//!
//! Ici une regle est reconnue ENTIERE et mot a mot, apres normalisation: la
//! ligne est decoupee en mots, l'identite est la suite exacte des mots
//! `meta`, `skuid`, `<uid>`, et deux regles sont egales quand toutes leurs
//! suites de mots le sont. `6553` n'est pas le mot `65533`, et `165534` n'est
//! pas le mot `65534`.
//!
//! # Ce que nft rend reellement, mesure
//!
//! Mesure du 05/09/2026 sur essai-linux, nftables 1.0.9: le ruleset du banc
//! pose par `nft -f -` dans un espace de noms jetable, puis relu par
//! `nft list chain inet bifrost output`, avec et sans `-n`.
//!
//! - Les regles `meta skuid <uid> ...` reviennent mot pour mot, l'uid en
//!   NOMBRE meme sans `-n`: 65534 n'est pas rendu `nobody` bien que le compte
//!   existe. Seule l'option `-g`, que ce depot ne passe jamais, le nommerait.
//! - Les commentaires `# ...` et les lignes vides disparaissent; l'indentation
//!   devient deux tabulations.
//! - `counter comment "x"` devient `counter packets 0 bytes 0 comment "x"`,
//!   et un `counter` place dans une regle par identite s'etend de meme.
//! - `meta mark 0xca6c` devient `meta mark 0x0000ca6c`.
//! - Sans `-n`, `priority filter` et les types ICMPv6 restent nommes; avec,
//!   ils deviennent `priority 0` et `{ 133, 134, 135, 136, 137 }`. Aucune
//!   regle par identite n'en porte.
//!
//! La normalisation absorbe exactement ces reecritures, et rien de plus: les
//! commentaires hors guillemets, les blancs, les compteurs vivants ramenes au
//! mot `counter`, et le remplissage des nombres hexadecimaux. Ce qu'une
//! version future de nft reecrirait autrement ne serait pas absorbe en
//! silence: la regle serait dite ABSENTE, et le verdict rougirait en la
//! nommant, ce qui est le comportement voulu pour une garde d'etancheite.

/// La partie d'une ligne qui precede un `#` hors guillemets.
///
/// Un `#` entre guillemets fait partie d'un `comment "..."` de nft et n'ouvre
/// pas de commentaire; un antislash echappe le guillemet qui le suit.
fn hors_commentaire(ligne: &str) -> &str {
    let mut dans_chaine = false;
    let mut echappe = false;
    for (i, c) in ligne.char_indices() {
        if dans_chaine {
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
            '"' => dans_chaine = true,
            '#' => return &ligne[..i],
            _ => {}
        }
    }
    ligne
}

/// Un nombre hexadecimal ramene a sa forme sans remplissage: `0x0000ca6c`
/// devient `0xca6c`. Tout autre mot revient tel quel.
fn mot_canonique(mot: &str) -> String {
    if let Some(chiffres) = mot.strip_prefix("0x")
        && !chiffres.is_empty()
        && let Ok(valeur) = u64::from_str_radix(chiffres, 16)
    {
        return format!("{valeur:#x}");
    }
    mot.to_owned()
}

/// `packets N bytes M` suit-il l'indice `i` (celui du mot `counter`) ?
fn compteur_vivant(mots: &[&str], i: usize) -> bool {
    mots.get(i + 1) == Some(&"packets")
        && mots.get(i + 2).is_some_and(|n| n.parse::<u64>().is_ok())
        && mots.get(i + 3) == Some(&"bytes")
        && mots.get(i + 4).is_some_and(|n| n.parse::<u64>().is_ok())
}

/// Une ligne ramenee a sa forme canonique: sans commentaire, sans
/// indentation, un seul espace entre les mots, les compteurs vivants ramenes
/// au mot `counter`, les hexadecimaux sans remplissage.
///
/// `None` quand il ne reste rien: ligne vide, ou qui n'etait qu'un
/// commentaire.
pub fn normaliser(ligne: &str) -> Option<String> {
    let mots: Vec<&str> = hors_commentaire(ligne).split_whitespace().collect();
    let mut sortie: Vec<String> = Vec::with_capacity(mots.len());
    let mut i = 0;
    while i < mots.len() {
        let mot = mots[i];
        sortie.push(mot_canonique(mot));
        if mot == "counter" && compteur_vivant(&mots, i) {
            i += 5;
        } else {
            i += 1;
        }
    }
    if sortie.is_empty() {
        None
    } else {
        Some(sortie.join(" "))
    }
}

/// Toutes les lignes d'un texte, normalisees, dans l'ordre, sans les vides.
///
/// Le texte est indifferemment le script que le generateur a rendu ou ce
/// que `nft list` a repondu: c'est tout l'objet de la normalisation.
pub fn lignes_normalisees(texte: &str) -> Vec<String> {
    texte.lines().filter_map(normaliser).collect()
}

/// L'identite que porte une regle normalisee: le mot qui suit la suite
/// exacte `meta skuid`, s'il est un nombre. Un nom de compte ne l'est pas,
/// et c'est voulu: nft ne nomme jamais l'uid sans `-g`, mesure ci-dessus,
/// donc un nom ici serait une forme inconnue et non une identite reconnue.
pub fn uid_de(regle: &str) -> Option<u32> {
    let mots: Vec<&str> = regle.split_whitespace().collect();
    mots.windows(3)
        .find(|w| w[0] == "meta" && w[1] == "skuid")
        .and_then(|w| w[2].parse::<u32>().ok())
}

/// Toutes les regles par identite d'un texte: l'uid et la regle entiere,
/// normalisee, dans l'ordre du texte.
pub fn regles_skuid(texte: &str) -> Vec<(u32, String)> {
    lignes_normalisees(texte)
        .into_iter()
        .filter_map(|regle| uid_de(&regle).map(|uid| (uid, regle)))
        .collect()
}

/// Les regles entieres qui portent EXACTEMENT cette identite.
///
/// Par [`uid_de`], donc par le mot qui suit `meta skuid`, jamais par la
/// presence des chiffres de l'uid quelque part dans la ligne.
pub fn regles_par_uid(texte: &str, uid: u32) -> Vec<String> {
    regles_skuid(texte)
        .into_iter()
        .filter(|(u, _)| *u == uid)
        .map(|(_, regle)| regle)
        .collect()
}

/// La regle entiere, mot pour mot apres normalisation des deux cotes, est-elle
/// dans le texte ?
pub fn porte(texte: &str, regle: &str) -> bool {
    match normaliser(regle) {
        Some(voulue) => lignes_normalisees(texte).contains(&voulue),
        None => false,
    }
}

/// L'ecart entre les regles par identite EMISES par le generateur et celles
/// que le noyau TIENT, relues par `nft list`.
///
/// Deux listes et non un booleen: un verdict qui rougit doit nommer la regle
/// qui manque, mot pour mot, sinon il envoie relire tout le plan.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Ecart {
    /// Emises, et absentes de ce que le noyau tient.
    pub manquantes: Vec<String>,
    /// Tenues par le noyau sans avoir ete emises.
    pub en_trop: Vec<String>,
}

impl Ecart {
    /// Rien ne manque, rien n'est en trop.
    pub fn est_vide(&self) -> bool {
        self.manquantes.is_empty() && self.en_trop.is_empty()
    }

    /// L'ecart, dit pour un rapport: chaque regle entiere entre crochets.
    pub fn dit(&self) -> String {
        let mut parts = Vec::new();
        if !self.manquantes.is_empty() {
            parts.push(format!(
                "emise(s) et absente(s) du noyau: [{}]",
                self.manquantes.join("] [")
            ));
        }
        if !self.en_trop.is_empty() {
            parts.push(format!(
                "tenue(s) par le noyau sans avoir ete emise(s): [{}]",
                self.en_trop.join("] [")
            ));
        }
        if parts.is_empty() {
            "aucun ecart".to_owned()
        } else {
            parts.join("; ")
        }
    }
}

/// Confronte les regles par identite du texte emis a celles du texte pose.
///
/// Une regle emise deux fois doit etre tenue deux fois: la comparaison
/// consomme les occurrences, elle ne teste pas l'appartenance a un ensemble.
pub fn ecart_skuid(emis: &str, pose: &str) -> Ecart {
    let mut tenues: Vec<String> = regles_skuid(pose).into_iter().map(|(_, r)| r).collect();
    let mut manquantes = Vec::new();
    for (_, regle) in regles_skuid(emis) {
        match tenues.iter().position(|t| *t == regle) {
            Some(i) => {
                tenues.remove(i);
            }
            None => manquantes.push(regle),
        }
    }
    Ecart {
        manquantes,
        en_trop: tenues,
    }
}

/// Le texte nomme-t-il EXACTEMENT cette interface, comme argument d'un
/// `oifname` ou d'un `iifname` ?
///
/// nft rend le nom entre guillemets et la normalisation garde les guillemets
/// comme partie du mot, donc la comparaison porte sur le token entier `"wg0"`:
/// `wg0` n'est pas `wg01`, et `bifrost-wg0` n'est pas `bifrost-wg0-bis`. Une
/// reconnaissance par sous-chaine (`texte.contains("wg0")`) confondrait les
/// deux et signalerait un tunnel la ou il n'y en a pas.
pub fn mentionne_interface(texte: &str, interface: &str) -> bool {
    let voulu = format!("\"{interface}\"");
    lignes_normalisees(texte).into_iter().any(|regle| {
        let mots: Vec<&str> = regle.split_whitespace().collect();
        mots.windows(2)
            .any(|w| (w[0] == "oifname" || w[0] == "iifname") && w[1] == voulu.as_str())
    })
}

/// Combien de fois la regle entiere, mot pour mot apres normalisation des deux
/// cotes, apparait dans le texte.
///
/// La forme entiere de [`porte`] quand une recette compte les occurrences: une
/// regle voisine qui ne fait que PROLONGER un mot (`oifname "wg01" accept` pour
/// `oifname "wg0" accept`) ne s'y ajoute pas, la ou `texte.matches(...).count()`
/// pourrait la compter.
pub fn compte(texte: &str, regle: &str) -> usize {
    match normaliser(regle) {
        Some(voulue) => lignes_normalisees(texte)
            .into_iter()
            .filter(|l| *l == voulue)
            .count(),
        None => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Un ruleset tel que nft le REND, d'apres la mesure du 05/09/2026 sur
    /// essai-linux: compteurs vivants, hexadecimal rempli, et des chiffres
    /// partout.
    fn rendu_par_nft() -> String {
        [
            "table inet bifrost {",
            "\tchain output {",
            "\t\ttype filter hook output priority filter; policy drop;",
            "\t\toifname \"lo\" accept",
            "\t\tmeta mark 0x0000ca6c accept",
            "\t\tip daddr 127.0.0.1 udp dport 53 accept",
            "\t\tmeta skuid 165534 udp dport 53 accept",
            "\t\tmeta skuid 65533 accept",
            "\t\tcounter packets 0 bytes 0 comment \"bifrost-output-dropped\"",
            "\t}",
            "}",
        ]
        .join("\n")
    }

    /// Le piege releve par 5d: l'uid present comme sous-chaine d'un autre
    /// nombre, ou le chiffre present ailleurs sans la regle.
    ///
    /// `0` figure dans `127.0.0.1`, dans `0x0000ca6c` et dans `packets 0`;
    /// `6553` est une sous-chaine de `65533`; `65534` est une sous-chaine de
    /// `165534`. Aucune de ces trois identites n'a de regle.
    #[test]
    fn un_uid_en_sous_chaine_n_est_pas_une_regle() {
        let texte = rendu_par_nft();
        for absente in [0u32, 6553, 65534] {
            let trouvees = regles_par_uid(&texte, absente);
            assert!(
                trouvees.is_empty(),
                "l'uid {absente} n'a aucune regle, et la reconnaissance en rend {}: {trouvees:?}",
                trouvees.len()
            );
        }
        assert_eq!(
            regles_par_uid(&texte, 65533),
            vec!["meta skuid 65533 accept".to_owned()],
            "la regle qui existe doit etre rendue entiere"
        );
        assert_eq!(
            regles_par_uid(&texte, 165534),
            vec!["meta skuid 165534 udp dport 53 accept".to_owned()]
        );
    }

    /// L'identite est la suite exacte `meta skuid <nombre>`, ou qu'elle soit
    /// dans la regle; un nom de compte n'est pas une identite reconnue.
    #[test]
    fn l_identite_est_la_suite_exacte_des_trois_mots() {
        assert_eq!(uid_de("meta skuid 65534 accept"), Some(65534));
        assert_eq!(uid_de("udp dport 53 meta skuid 65533 accept"), Some(65533));
        assert_eq!(uid_de("meta skgid 65534 accept"), None);
        assert_eq!(uid_de("skuid 65534 accept"), None);
        assert_eq!(uid_de("meta skuid nobody accept"), None);
        assert_eq!(uid_de("meta mark 0xca6c accept"), None);
    }

    /// La forme rendue par nft et la forme emise par le generateur sont la
    /// meme regle: commentaires, blancs, compteurs vivants et remplissage
    /// hexadecimal sont les reecritures MESUREES, et les seules absorbees.
    #[test]
    fn la_forme_rendue_par_nft_est_ramenee_a_la_forme_emise() {
        assert_eq!(
            normaliser("\t\tcounter packets 0 bytes 0 comment \"bifrost-output-dropped\""),
            Some("counter comment \"bifrost-output-dropped\"".to_owned())
        );
        assert_eq!(
            normaliser("\t\tmeta mark 0x0000ca6c accept"),
            Some("meta mark 0xca6c accept".to_owned())
        );
        assert_eq!(
            normaliser("   meta   skuid 65533   udp dport 53 accept  # bootstrap"),
            Some("meta skuid 65533 udp dport 53 accept".to_owned())
        );
        assert_eq!(
            normaliser("\t\tmeta skuid 65533 counter packets 12 bytes 3456 accept"),
            Some("meta skuid 65533 counter accept".to_owned())
        );
        assert_eq!(normaliser("\t\t# coeur anti-censure"), None);
        assert_eq!(normaliser(""), None);
        // Un compteur qui n'est pas vivant n'est pas absorbe: `counter`
        // suivi d'autre chose reste tel quel, mot pour mot.
        assert_eq!(
            normaliser("counter packets accept"),
            Some("counter packets accept".to_owned())
        );
    }

    /// Un `#` entre guillemets fait partie du commentaire nft de la regle.
    #[test]
    fn un_diese_entre_guillemets_n_ouvre_pas_un_commentaire() {
        assert_eq!(
            normaliser("counter comment \"bifrost # sortie\" # vrai commentaire"),
            Some("counter comment \"bifrost # sortie\"".to_owned())
        );
        assert_eq!(
            normaliser("counter comment \"a \\\" # b\" drop"),
            Some("counter comment \"a \\\" # b\" drop".to_owned())
        );
    }

    /// `porte` reconnait la regle entiere, dans l'une ou l'autre forme, et
    /// refuse une regle qui n'en est qu'un prefixe ou qu'un voisin.
    #[test]
    fn porte_reconnait_la_regle_entiere_et_rien_d_autre() {
        let texte = rendu_par_nft();
        assert!(porte(&texte, "meta skuid 65533 accept"));
        assert!(porte(&texte, "   meta skuid 65533 accept   # avec bruit"));
        assert!(porte(&texte, "meta mark 0xca6c accept"));
        assert!(porte(&texte, "counter comment \"bifrost-output-dropped\""));
        assert!(!porte(&texte, "meta skuid 65533"));
        assert!(!porte(&texte, "meta skuid 65534 udp dport 53 accept"));
        assert!(!porte(&texte, "meta skuid 6553 accept"));
        assert!(!porte(&texte, "# rien"));
    }

    /// Une regle emise et absente du noyau est nommee ENTIERE, et une regle
    /// tenue sans avoir ete emise aussi; les occurrences se consomment.
    #[test]
    fn l_ecart_nomme_la_regle_entiere_qui_manque() {
        let emis = [
            "\t\t# coeur anti-censure",
            "\t\tmeta skuid 65534 udp dport 53 drop",
            "\t\tmeta skuid 65534 tcp dport 53 drop",
            "\t\tmeta skuid 65534 accept",
        ]
        .join("\n");
        let pose = [
            "\t\tmeta skuid 65534 udp dport 53 drop",
            "\t\tmeta skuid 65534 accept",
            "\t\tmeta skuid 0 accept",
        ]
        .join("\n");
        let ecart = ecart_skuid(&emis, &pose);
        assert_eq!(
            ecart.manquantes,
            vec!["meta skuid 65534 tcp dport 53 drop".to_owned()]
        );
        assert_eq!(ecart.en_trop, vec!["meta skuid 0 accept".to_owned()]);
        assert!(!ecart.est_vide());
        let dit = ecart.dit();
        assert!(
            dit.contains("[meta skuid 65534 tcp dport 53 drop]"),
            "{dit}"
        );
        assert!(dit.contains("[meta skuid 0 accept]"), "{dit}");
        assert!(!dit.contains("  "), "suite d'espaces dans [{dit}]");

        // Meme regle emise deux fois, tenue une fois: il en manque une.
        let deux = format!("{emis}\n\t\tmeta skuid 65534 accept");
        let une = "\t\tmeta skuid 65534 udp dport 53 drop\n\t\tmeta skuid 65534 tcp dport 53 drop\n\t\tmeta skuid 65534 accept";
        assert_eq!(
            ecart_skuid(&deux, une).manquantes,
            vec!["meta skuid 65534 accept".to_owned()]
        );
    }

    /// Aucun ecart entre un script emis et sa relecture par nft, sur la forme
    /// mesuree: c'est le cas nominal du vecteur, et il doit rester silencieux.
    #[test]
    fn aucun_ecart_entre_le_script_emis_et_sa_relecture() {
        let emis = [
            "# Bifrost kill switch - genere automatiquement, ne pas editer",
            "table inet bifrost {}",
            "delete table inet bifrost",
            "",
            "table inet bifrost {",
            "\tchain output {",
            "\t\ttype filter hook output priority filter; policy drop;",
            "",
            "\t\t# loopback",
            "\t\toifname \"lo\" accept",
            "\t\tmeta mark 0xca6c accept",
            "\t\t# Resolveur chiffre embarque",
            "\t\tmeta skuid 65533 udp dport 53 accept",
            "\t\tmeta skuid 65533 tcp dport 53 accept",
            "\t\tudp dport 53 drop",
            "\t\ttcp dport 53 drop",
            "\t\tcounter comment \"bifrost-output-dropped\"",
            "\t}",
            "}",
        ]
        .join("\n");
        let relu = [
            "table inet bifrost {",
            "\tchain output {",
            "\t\ttype filter hook output priority filter; policy drop;",
            "\t\toifname \"lo\" accept",
            "\t\tmeta mark 0x0000ca6c accept",
            "\t\tmeta skuid 65533 udp dport 53 accept",
            "\t\tmeta skuid 65533 tcp dport 53 accept",
            "\t\tudp dport 53 drop",
            "\t\ttcp dport 53 drop",
            "\t\tcounter packets 0 bytes 0 comment \"bifrost-output-dropped\"",
            "\t}",
            "}",
        ]
        .join("\n");
        let ecart = ecart_skuid(&emis, &relu);
        assert!(ecart.est_vide(), "{}", ecart.dit());
        assert_eq!(ecart.dit(), "aucun ecart");
        assert_eq!(
            regles_skuid(&relu),
            vec![
                (65533, "meta skuid 65533 udp dport 53 accept".to_owned()),
                (65533, "meta skuid 65533 tcp dport 53 accept".to_owned()),
            ]
        );
    }

    /// Un nom d'interface est reconnu ENTIER, entre guillemets: le tunnel `wg0`
    /// n'est pas reconnu dans une regle qui nomme `wg01`, ni `bifrost-wg0` dans
    /// `bifrost-wg0-bis`. C'est le pendant, pour les interfaces, de la piege
    /// `un_uid_en_sous_chaine_n_est_pas_une_regle`.
    #[test]
    fn un_nom_d_interface_est_reconnu_entier() {
        let texte = [
            "\t\toifname \"wg01\" accept",
            "\t\tiifname \"bifrost-wg0-bis\" accept",
        ]
        .join("\n");
        assert!(!mentionne_interface(&texte, "wg0"));
        assert!(!mentionne_interface(&texte, "bifrost-wg0"));
        assert!(mentionne_interface(&texte, "wg01"));
        assert!(mentionne_interface(&texte, "bifrost-wg0-bis"));
        // oifname et iifname tous deux, et rien d'autre: un nom qui n'est pas
        // l'argument d'oifname/iifname (ici dans un commentaire, efface par la
        // normalisation) n'est pas une mention.
        assert!(mentionne_interface("\t\toifname \"wg0\" accept", "wg0"));
        assert!(mentionne_interface("\t\tiifname \"wg0\" accept", "wg0"));
        assert!(!mentionne_interface(
            "\t\tmeta skuid 1000 accept # wg0",
            "wg0"
        ));
    }

    /// `compte` ne compte que les regles entieres, jamais un prolongement de
    /// mot: `oifname "wg01" accept` ne s'ajoute pas au compte de
    /// `oifname "wg0" accept`, et la forme rendue par nft (hexadecimal rempli)
    /// est ramenee a la forme emise avant le comptage.
    #[test]
    fn compte_ne_compte_que_les_regles_entieres() {
        let texte = [
            "\t\toifname \"wg0\" accept",
            "\t\toifname \"wg0\" accept",
            "\t\toifname \"wg01\" accept",
            "\t\tmeta mark 0x0000ca6c accept",
        ]
        .join("\n");
        assert_eq!(compte(&texte, "oifname \"wg0\" accept"), 2);
        assert_eq!(compte(&texte, "oifname \"wg01\" accept"), 1);
        assert_eq!(compte(&texte, "meta mark 0xca6c accept"), 1);
        assert_eq!(compte(&texte, "meta skuid 999 accept"), 0);
    }
}
