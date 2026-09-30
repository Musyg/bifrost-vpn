//! Qui ecoute derriere un port de boucle locale: est-ce le coeur qu'on a lance.
//!
//! # Le defaut que ce module ferme
//!
//! Le daemon parle a un port fixe de la boucle locale (`127.0.0.1:<api>`,
//! `<socks>`) SANS savoir qui l'ecoute. Un compte ordinaire qui lie le port
//! AVANT le coeur - ou apres sa mort, en cours de session - recoit ce que le
//! daemon y envoie: le secret de l'API de controle (`Authorization: Bearer
//! ...`), puis les reponses que le daemon croit (version, vitalite, selection).
//! Sur l'entree SOCKS, il recevrait le trafic de l'utilisateur en clair, avant
//! que le coeur ne le chiffre.
//!
//! Ce module repond a une seule question, et fail-closed: **l'ecouteur du port
//! est-il le coeur que j'ai lance?** Un canal qu'on ne sait pas authentifier se
//! refuse, et le refus dit POURQUOI: un refus faute de pouvoir lire n'accuse
//! jamais un squatteur.
//!
//! # Quelles ecoutes comptent
//!
//! Le daemon se connecte TOUJOURS a `127.0.0.1` (la configuration du coeur y
//! ecrit ses ecoutes, `configuration::ECOUTE_LOCALE`). Comptent donc les ecoutes
//! qui RECEVRAIENT une connexion vers `127.0.0.1:<port>`: `127.0.0.1` et
//! `0.0.0.0` en v4; en v6, `::` (en double pile elle recoit la v4 mappee) et les
//! adresses v4 mappees `::ffff:127.0.0.1` et `::ffff:0.0.0.0`. `::1` n'en recoit
//! aucune et ne compte pas. Un `::` en `IPV6_V6ONLY` compte quand meme, faute de
//! pouvoir le distinguer ici d'un `::` en double pile: le verdict est alors un
//! refus a tort, jamais une fuite (voir le rapport de la voie, section 9).
//!
//! Il suffit d'UNE ecoute comptee qui n'est pas au coeur pour refuser, meme si
//! la connexion irait aujourd'hui au coeur. C'est voulu: deux ecoutes PEUVENT
//! coexister sur un port. Sous Linux, `SO_REUSEPORT` pose des deux cotes par le
//! meme UID effectif en met plusieurs sur la meme adresse, et le noyau leur
//! distribue les connexions. Sous Windows, un `0.0.0.0:<port>` se lie a cote
//! d'un `127.0.0.1:<port>` dans les deux ordres, sans aucune option (mesure
//! sous un meme compte), et c'est l'adresse la plus precise qui
//! recoit les connexions TANT QU'ELLE VIT: le jour ou le coeur meurt, l'ecoute
//! large qui attendait a cote les recoit sans delai. Refuser des qu'elle existe
//! ferme ce relais tout pret.
//!
//! # Comment on identifie le proprietaire, par plateforme
//!
//! - **Windows**: `GetExtendedTcpTable` avec `TCP_TABLE_OWNER_PID_LISTENER`
//!   rend le PID proprietaire de chaque ecoute, pour tout compte et sans
//!   privilege. On le compare au PID de l'enfant. La reutilisation de PID est
//!   fermee tant que le `Child` vit: tokio en garde la poignee, et Windows ne
//!   reattribue un PID qu'une fois toutes ses poignees fermees.
//! - **Linux**, par ordre de force:
//!   1. **L'inode, quand les descripteurs de l'enfant sont lisibles.**
//!      `/proc/net/tcp{,6}` donne l'inode de chaque ecoute, `/proc/<pid>/fd`
//!      les inodes que l'enfant detient. C'est la reponse exacte a << est-ce MON
//!      enfant >>. Lisible quand le coeur tourne sous le compte du daemon, ou
//!      quand le daemon a `CAP_SYS_PTRACE` et `CAP_DAC_READ_SEARCH`.
//!   2. **Le compte dedie du coeur, sinon.** L'unite livree
//!      (`packaging/systemd/bifrost-daemon.service`) lance le coeur sous
//!      `bifrost-coeur` et ne donne au daemon ni `CAP_SYS_PTRACE` ni
//!      `CAP_DAC_READ_SEARCH`: `/proc/<pid>/fd` du coeur lui est alors refuse,
//!      et c'est voulu (ces deux capacites seraient une regression). La colonne
//!      `uid` de `/proc/net/tcp{,6}`, elle, est lisible sans privilege. On exige
//!      alors que CHAQUE ecoute comptee appartienne a l'UID du compte declare,
//!      et que l'enfant soit vivant sous ce compte (`/proc/<pid>/status`, lisible
//!      par tous). Un squatteur devrait tourner sous `bifrost-coeur`, compte
//!      systeme sans session que seul le daemon utilise. Ce que ce chemin ne
//!      distingue PAS: deux processus du meme compte dedie (un coeur orphelin,
//!      par exemple, que la garde anti-orphelin existe pour empecher).
//!   3. **Rien de lisible et aucun compte declare**: `Illisible`, avec la raison
//!      exacte. Jamais `Autre`.
//!
//!   Un lien de `/proc/<pid>/fd` REFUSE (repertoire listable, liens illisibles:
//!   le cas d'un root prive de `CAP_SYS_PTRACE`) est un refus de lecture, traite
//!   comme au point 2, et non un descripteur manquant: le prendre pour tel
//!   ferait accuser un squatteur qui n'existe pas.
//!
//! # La course qui reste, et sa borne
//!
//! Entre la verification et la connexion, l'ecoute peut changer de main. Si la
//! verification a vu un seul ecouteur, le coeur, et aucun autre, un tiers ne
//! peut recevoir la connexion qu'en se liant dans cet intervalle: sous Linux il
//! lui faut que le coeur ait relache son ecoute (ou partager son UID, pour
//! `SO_REUSEPORT`); sous Windows, une ecoute large posee APRES la verification
//! ne recoit rien tant que le coeur, plus precis, vit. Les consommateurs
//! verifient JUSTE avant chaque envoi, ce qui reduit l'intervalle a la duree de
//! la verification et de la connexion.

/// Ce que la verification a etabli sur un port de la boucle locale.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Proprietaire {
    /// Toute ecoute qui recevrait la connexion appartient au coeur attendu. Sur
    /// ce port, on peut ecrire le premier octet.
    Confirme,
    /// Personne n'ecoute encore sur ce port. Un coeur qui demarre n'a pas
    /// forcement fini de lier: l'appelant qui attend l'API doit reessayer, pas
    /// conclure.
    PersonneEncore,
    /// Une ecoute qui recevrait la connexion n'est PAS au coeur: un autre
    /// processus, ou un autre compte. L'appelant refuse, sans envoyer un octet.
    Autre { details: String },
    /// On n'a pas pu etablir qui ecoute. Fail-closed: un canal qu'on ne sait pas
    /// authentifier se refuse, il ne se suppose pas sain. N'accuse personne.
    Illisible { details: String },
}

/// Qui doit tenir l'ecoute: l'enfant lance, et le compte dedie sous lequel il
/// tourne quand il en a un.
///
/// `uid` est ce que le daemon a lui-meme pose au lancement
/// (`Lancement::utilisateur`), jamais une valeur lue chez l'enfant: c'est la
/// seule garantie que ce compte est celui du coeur. Ignore sous Windows, ou la
/// table des ecoutes donne le PID a tout compte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Attendu {
    pub pid: u32,
    pub uid: Option<u32>,
}

/// Le port `port` de la boucle locale est-il ecoute par le coeur `attendu`.
///
/// Ne se connecte jamais au port: elle ne fait qu'interroger le systeme sur qui
/// le detient. C'est ce qui la rend utilisable AVANT le premier octet.
pub fn verifier_ecoute(port: u16, attendu: Attendu) -> Proprietaire {
    #[cfg(target_os = "linux")]
    {
        linux::verifier(port, attendu)
    }
    #[cfg(windows)]
    {
        windows_impl::verifier(port, attendu.pid)
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = (port, attendu);
        Proprietaire::Illisible {
            details:
                "identification du proprietaire d'une ecoute non implementee sur cette plateforme"
                    .to_owned(),
        }
    }
}

/// Exige que `port` soit ecoute par le coeur `attendu`, ou dit pourquoi refuser.
///
/// La forme STRICTE de [`verifier_ecoute`], pour les usages EN COURS de session,
/// ou l'attente n'a plus de sens: au (re)lancement, une ecoute absente veut dire
/// << le coeur finit de lier >> et l'on patiente; une fois la session etablie,
/// une ecoute absente veut dire << le coeur n'est plus la >>, et l'on refuse.
/// `Confirme` seul rend `Ok`; tout le reste - personne, un autre, illisible -
/// est un refus fail-closed. `quoi` nomme le canal dans le message.
pub fn exiger_le_coeur(port: u16, attendu: Attendu, quoi: &str) -> Result<(), String> {
    let pid = attendu.pid;
    match verifier_ecoute(port, attendu) {
        Proprietaire::Confirme => Ok(()),
        Proprietaire::PersonneEncore => Err(format!(
            "{quoi}: plus personne n'ecoute le port {port}, le coeur {pid} n'est plus la"
        )),
        Proprietaire::Autre { details } => Err(format!(
            "{quoi}: le port {port} est tenu par un autre que le coeur {pid} ({details})"
        )),
        Proprietaire::Illisible { details } => Err(format!(
            "{quoi}: impossible de verifier qui tient le port {port} ({details})"
        )),
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::{Attendu, Proprietaire};
    use std::collections::HashSet;
    use std::io::ErrorKind;

    /// Adresses locales v4 dont une ecoute recevrait une connexion vers
    /// `127.0.0.1`: la boucle elle-meme et l'ecoute sur toutes les adresses.
    /// Format de `/proc/net/tcp`: 4 octets en hexa, petit-boutiste par mot.
    const V4_BOUCLE: &str = "0100007F";
    const V4_TOUTES: &str = "00000000";

    /// Idem en v6, pour `/proc/net/tcp6` (quatre mots de 32 bits, chacun ecrit
    /// petit-boutiste): `::`, `::ffff:127.0.0.1`, `::ffff:0.0.0.0`. `::1`
    /// (`...01000000`) n'y est PAS: il ne recoit aucune connexion v4.
    const V6_QUI_RECOIVENT: [&str; 3] = [
        "00000000000000000000000000000000",
        "0000000000000000FFFF00000100007F",
        "0000000000000000FFFF000000000000",
    ];

    /// Etat TCP LISTEN, tel que `/proc/net/tcp` l'ecrit.
    const ETAT_LISTEN: &str = "0A";

    /// Une ecoute qui recevrait la connexion: son proprietaire au sens du noyau
    /// (l'UID du socket) et son inode.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(super) struct Ecoute {
        pub uid: u32,
        pub inode: u64,
    }

    /// Ce que `/proc/<pid>/fd` a rendu.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(super) enum Descripteurs {
        /// Les inodes de socket que le processus detient.
        Lus(HashSet<u64>),
        /// Lecture REFUSEE (repertoire ou liens): ce n'est pas un squatteur,
        /// c'est un droit qui manque. La raison est gardee telle quelle.
        Refuses(String),
        /// Le processus n'existe plus.
        Absent,
        /// Toute autre erreur de lecture.
        Erreur(String),
    }

    /// Ce qu'on lit de `/proc/<pid>/status`, lisible par tous.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(super) struct Statut {
        /// Ni zombie ni mort.
        pub vivant: bool,
        /// UID effectif.
        pub uid: u32,
    }

    /// Que faire d'un lien de `/proc/<pid>/fd` qu'on n'a pas pu lire.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(super) enum SuiteLien {
        /// Le descripteur a ete ferme entre la liste et la lecture: course
        /// ordinaire, on passe au suivant.
        Ignorer,
        /// Lecture refusee: toute la table est illisible, et le dire.
        Refus,
        /// Autre erreur: le dire.
        Erreur,
    }

    pub fn verifier(port: u16, attendu: Attendu) -> Proprietaire {
        verifier_avec(port, attendu, descripteurs_de)
    }

    /// [`verifier`], avec la lecture des descripteurs de l'enfant en parametre.
    ///
    /// Le chemin par le compte dedie ne s'emprunte que quand ces descripteurs
    /// sont REFUSES, ce qu'un compte ordinaire ne sait pas provoquer sur son
    /// propre enfant. Les recettes fournissent donc le refus; tout le reste - la
    /// table des ecoutes, l'etat et l'uid de l'enfant - est lu pour de vrai.
    /// Sans ce parametre, aucune recette ne voyait l'etat de l'enfant: le forcer
    /// a << vivant, sous le compte declare >> les laissait toutes vertes. La
    /// production passe [`descripteurs_de`].
    pub(super) fn verifier_avec(
        port: u16,
        attendu: Attendu,
        lire_descripteurs: impl Fn(u32) -> Descripteurs,
    ) -> Proprietaire {
        let ecoutes = match ecoutes_sur(port) {
            Ok(e) => e,
            Err(details) => return Proprietaire::Illisible { details },
        };
        if ecoutes.is_empty() {
            return Proprietaire::PersonneEncore;
        }
        let fds = lire_descripteurs(attendu.pid);
        let statut = match fds {
            Descripteurs::Refuses(_) => Some(statut_de(attendu.pid)),
            _ => None,
        };
        let verdict = trancher(&ecoutes, &fds, statut.as_ref(), attendu);

        // Par les inodes, une ecoute etrangere peut n'etre que celle de l'enfant
        // qui s'arretait entre la lecture de la table et celle de ses liens. On
        // relit la table: si l'ecoute en cause a disparu, personne n'est a
        // accuser.
        if let (Proprietaire::Autre { .. }, Descripteurs::Lus(a_moi)) = (&verdict, &fds) {
            let en_cause: Vec<u64> = ecoutes
                .iter()
                .map(|e| e.inode)
                .filter(|i| !a_moi.contains(i))
                .collect();
            if let Ok(encore) = ecoutes_sur(port)
                && !encore.iter().any(|e| en_cause.contains(&e.inode))
            {
                return Proprietaire::Illisible {
                    details: format!(
                        "l'ecoute en cause a disparu pendant la verification: le processus {} s'arretait",
                        attendu.pid
                    ),
                };
            }
        }
        verdict
    }

    /// Le verdict, a partir de ce qui a ete lu. Pure: c'est ici que se decide
    /// qui est accuse, et les recettes l'eprouvent sans privilege.
    pub(super) fn trancher(
        ecoutes: &[Ecoute],
        fds: &Descripteurs,
        statut: Option<&Result<Statut, String>>,
        attendu: Attendu,
    ) -> Proprietaire {
        let pid = attendu.pid;
        match fds {
            Descripteurs::Lus(a_moi) => {
                for e in ecoutes {
                    if !a_moi.contains(&e.inode) {
                        return Proprietaire::Autre {
                            details: format!(
                                "le port est ecoute par un socket (inode {}, uid {}) que le processus {pid} ne detient pas",
                                e.inode, e.uid
                            ),
                        };
                    }
                }
                Proprietaire::Confirme
            }
            Descripteurs::Refuses(raison) => {
                let Some(uid) = attendu.uid else {
                    return Proprietaire::Illisible {
                        details: format!(
                            "les descripteurs du processus {pid} sont illisibles ({raison}), et aucun compte dedie n'est declare pour trancher par l'uid du socket"
                        ),
                    };
                };
                match statut {
                    Some(Ok(s)) if !s.vivant => {
                        return Proprietaire::Illisible {
                            details: format!(
                                "le processus {pid} est mort: aucune ecoute ne peut plus etre la sienne"
                            ),
                        };
                    }
                    Some(Ok(s)) if s.uid != uid => {
                        return Proprietaire::Illisible {
                            details: format!(
                                "le processus {pid} tourne sous l'uid {}, et non sous le compte declare du coeur (uid {uid})",
                                s.uid
                            ),
                        };
                    }
                    Some(Ok(_)) => {}
                    Some(Err(e)) => {
                        return Proprietaire::Illisible {
                            details: format!("etat du processus {pid} illisible: {e}"),
                        };
                    }
                    None => {
                        return Proprietaire::Illisible {
                            details: format!("etat du processus {pid} non lu"),
                        };
                    }
                }
                for e in ecoutes {
                    if e.uid != uid {
                        return Proprietaire::Autre {
                            details: format!(
                                "le port est ecoute par un socket de l'uid {}, et non du compte dedie du coeur (uid {uid})",
                                e.uid
                            ),
                        };
                    }
                }
                Proprietaire::Confirme
            }
            Descripteurs::Absent => Proprietaire::Illisible {
                details: format!(
                    "le processus {pid} n'existe plus: aucune ecoute ne peut etre la sienne"
                ),
            },
            Descripteurs::Erreur(e) => Proprietaire::Illisible {
                details: format!("lecture des descripteurs de {pid}: {e}"),
            },
        }
    }

    /// Les ecoutes de `port` qui recevraient une connexion vers `127.0.0.1`.
    fn ecoutes_sur(port: u16) -> Result<Vec<Ecoute>, String> {
        let mut ecoutes = Vec::new();
        for (chemin, v6) in [("/proc/net/tcp", false), ("/proc/net/tcp6", true)] {
            match std::fs::read_to_string(chemin) {
                Ok(contenu) => {
                    for ligne in contenu.lines().skip(1) {
                        if let Some(e) = ecoute_si_recoit_la_boucle(ligne, port, v6) {
                            ecoutes.push(e);
                        }
                    }
                }
                // `/proc/net/tcp6` manque si l'IPv6 est desactivee: une table de
                // moins, pas une panne.
                Err(e) if v6 && e.kind() == ErrorKind::NotFound => {}
                Err(e) => return Err(format!("lecture de {chemin}: {e}")),
            }
        }
        Ok(ecoutes)
    }

    /// L'ecoute decrite par CETTE ligne de `/proc/net/tcp{,6}` si c'est une
    /// ecoute LISTEN sur `port`, a une adresse qui recoit `127.0.0.1`.
    ///
    /// Colonnes comptees depuis 0, `sl` compris: adresse locale `IP:PORT` en 1,
    /// etat en 3, uid en 7, inode en 9. La ligne d'en-tete est sautee par
    /// l'appelant.
    pub(super) fn ecoute_si_recoit_la_boucle(ligne: &str, port: u16, v6: bool) -> Option<Ecoute> {
        let cols: Vec<&str> = ligne.split_whitespace().collect();
        let local = cols.get(1)?;
        let etat = cols.get(3)?;
        let uid = cols.get(7)?;
        let inode = cols.get(9)?;
        if *etat != ETAT_LISTEN {
            return None;
        }
        let (ip, port_hex) = local.split_once(':')?;
        if u16::from_str_radix(port_hex, 16).ok()? != port {
            return None;
        }
        let ip = ip.to_ascii_uppercase();
        let recoit = if v6 {
            V6_QUI_RECOIVENT.contains(&ip.as_str())
        } else {
            ip == V4_BOUCLE || ip == V4_TOUTES
        };
        if !recoit {
            return None;
        }
        Some(Ecoute {
            uid: uid.parse().ok()?,
            inode: inode.parse().ok()?,
        })
    }

    /// Classe l'echec de lecture d'un lien. Un REFUS n'est jamais un
    /// descripteur manquant: l'ignorer ferait accuser un squatteur inexistant.
    pub(super) fn suite_apres_echec_de_lien(sorte: ErrorKind) -> SuiteLien {
        match sorte {
            ErrorKind::NotFound => SuiteLien::Ignorer,
            ErrorKind::PermissionDenied => SuiteLien::Refus,
            _ => SuiteLien::Erreur,
        }
    }

    /// Les inodes de socket que ce PID detient, lus par `/proc/<pid>/fd`.
    fn descripteurs_de(pid: u32) -> Descripteurs {
        let repertoire = format!("/proc/{pid}/fd");
        let entrees = match std::fs::read_dir(&repertoire) {
            Ok(e) => e,
            Err(e) => {
                return match e.kind() {
                    ErrorKind::NotFound => Descripteurs::Absent,
                    ErrorKind::PermissionDenied => {
                        Descripteurs::Refuses(format!("ouverture de {repertoire}: {e}"))
                    }
                    _ => Descripteurs::Erreur(format!("ouverture de {repertoire}: {e}")),
                };
            }
        };
        let mut a_moi = HashSet::new();
        for entree in entrees {
            let entree = match entree {
                Ok(e) => e,
                Err(e) => return Descripteurs::Erreur(format!("parcours de {repertoire}: {e}")),
            };
            let chemin = entree.path();
            match std::fs::read_link(&chemin) {
                Ok(cible) => {
                    if let Some(inode) = inode_de_lien(&cible.to_string_lossy()) {
                        a_moi.insert(inode);
                    }
                }
                Err(e) => match suite_apres_echec_de_lien(e.kind()) {
                    SuiteLien::Ignorer => continue,
                    SuiteLien::Refus => {
                        return Descripteurs::Refuses(format!(
                            "lecture du lien {}: {e}",
                            chemin.display()
                        ));
                    }
                    SuiteLien::Erreur => {
                        return Descripteurs::Erreur(format!(
                            "lecture du lien {}: {e}",
                            chemin.display()
                        ));
                    }
                },
            }
        }
        Descripteurs::Lus(a_moi)
    }

    /// L'etat et l'UID effectif du processus, par `/proc/<pid>/status`.
    fn statut_de(pid: u32) -> Result<Statut, String> {
        let chemin = format!("/proc/{pid}/status");
        let contenu = std::fs::read_to_string(&chemin).map_err(|e| match e.kind() {
            // Reape entre la lecture de ses descripteurs et celle-ci.
            ErrorKind::NotFound => format!("{chemin} absent: le processus n'existe plus"),
            _ => format!("lecture de {chemin}: {e}"),
        })?;
        lire_statut(&contenu).ok_or_else(|| format!("{chemin}: champs State ou Uid introuvables"))
    }

    /// `State:` (sa lettre) et `Uid:` (le deuxieme nombre, l'effectif).
    pub(super) fn lire_statut(contenu: &str) -> Option<Statut> {
        let mut etat = None;
        let mut uid = None;
        for ligne in contenu.lines() {
            if let Some(reste) = ligne.strip_prefix("State:") {
                etat = reste.trim().chars().next();
            } else if let Some(reste) = ligne.strip_prefix("Uid:") {
                uid = reste.split_whitespace().nth(1).and_then(|u| u.parse().ok());
            }
        }
        Some(Statut {
            vivant: !matches!(etat?, 'Z' | 'X' | 'x'),
            uid: uid?,
        })
    }

    /// L'inode d'un lien `socket:[12345]`, ou `None` si ce n'est pas un socket.
    fn inode_de_lien(lien: &str) -> Option<u64> {
        let reste = lien.strip_prefix("socket:[")?;
        let nombre = reste.strip_suffix(']')?;
        nombre.parse::<u64>().ok()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn ligne_v4(adresse: &str, etat: &str, uid: u32, inode: u64) -> String {
            format!(
                "   3: {adresse} 00000000:0000 {etat} 00000000:00000000 00:00000000 00000000 {uid:>5}        0 {inode} 1 ffff0000 100 0 0 10 0"
            )
        }

        fn ecoute(uid: u32, inode: u64) -> Ecoute {
            Ecoute { uid, inode }
        }

        const MOI: Attendu = Attendu {
            pid: 4242,
            uid: Some(990),
        };

        #[test]
        fn une_ecoute_sur_la_boucle_au_bon_port_donne_son_uid_et_son_inode() {
            // 127.0.0.1:0x1F90 (8080) en LISTEN, uid 990, inode 45678.
            let l = ligne_v4("0100007F:1F90", "0A", 990, 45678);
            assert_eq!(
                ecoute_si_recoit_la_boucle(&l, 8080, false),
                Some(ecoute(990, 45678))
            );
        }

        #[test]
        fn une_ecoute_a_un_autre_port_est_ignoree() {
            let l = ligne_v4("0100007F:1F90", "0A", 990, 45678);
            assert_eq!(ecoute_si_recoit_la_boucle(&l, 9090, false), None);
        }

        #[test]
        fn une_connexion_etablie_n_est_pas_une_ecoute() {
            let l = ligne_v4("0100007F:1F90", "01", 990, 45678);
            assert_eq!(ecoute_si_recoit_la_boucle(&l, 8080, false), None);
        }

        #[test]
        fn une_ecoute_sur_une_autre_adresse_locale_ne_recoit_pas_la_boucle() {
            // 127.0.0.2 ne recoit pas une connexion vers 127.0.0.1.
            let l = ligne_v4("0200007F:1F90", "0A", 990, 45678);
            assert_eq!(ecoute_si_recoit_la_boucle(&l, 8080, false), None);
        }

        #[test]
        fn une_ecoute_sur_toutes_les_adresses_recoit_la_boucle() {
            let l = ligne_v4("00000000:1F90", "0A", 1000, 99999);
            assert_eq!(
                ecoute_si_recoit_la_boucle(&l, 8080, false),
                Some(ecoute(1000, 99999))
            );
        }

        /// `::1` ne recoit aucune connexion vers `127.0.0.1`: le compter
        /// refusait a tort un coeur servi (mesure du verificateur, cas 4).
        #[test]
        fn une_ecoute_sur_la_boucle_v6_ne_recoit_pas_la_boucle_v4() {
            let l = ligne_v4("00000000000000000000000001000000:1F90", "0A", 1000, 7);
            assert_eq!(ecoute_si_recoit_la_boucle(&l, 8080, true), None);
        }

        /// `::` en double pile recoit la v4 mappee: compte.
        #[test]
        fn une_ecoute_v6_sur_toutes_les_adresses_compte() {
            let l = ligne_v4("00000000000000000000000000000000:1F90", "0A", 1000, 8);
            assert_eq!(
                ecoute_si_recoit_la_boucle(&l, 8080, true),
                Some(ecoute(1000, 8))
            );
        }

        /// Un socket v6 lie a `::ffff:127.0.0.1` recoit la connexion v4.
        #[test]
        fn une_ecoute_v6_mappee_sur_la_boucle_compte() {
            let l = ligne_v4("0000000000000000FFFF00000100007F:1F90", "0A", 1000, 9);
            assert_eq!(
                ecoute_si_recoit_la_boucle(&l, 8080, true),
                Some(ecoute(1000, 9))
            );
        }

        #[test]
        fn un_lien_de_socket_rend_son_inode() {
            assert_eq!(inode_de_lien("socket:[12345]"), Some(12345));
            assert_eq!(inode_de_lien("/dev/null"), None);
            assert_eq!(inode_de_lien("anon_inode:[eventpoll]"), None);
        }

        /// Le lien REFUSE n'est jamais un descripteur manquant. C'etait le
        /// `continue` qui, sous un root prive de `CAP_SYS_PTRACE`, faisait
        /// accuser un squatteur inexistant (mesure du verificateur).
        #[test]
        fn un_lien_refuse_est_un_refus_de_lecture_et_non_un_descripteur_manquant() {
            assert_eq!(
                suite_apres_echec_de_lien(ErrorKind::PermissionDenied),
                SuiteLien::Refus
            );
            assert_eq!(
                suite_apres_echec_de_lien(ErrorKind::NotFound),
                SuiteLien::Ignorer
            );
            assert_eq!(
                suite_apres_echec_de_lien(ErrorKind::InvalidData),
                SuiteLien::Erreur
            );
        }

        #[test]
        fn le_statut_rend_l_etat_et_l_uid_effectif() {
            let s = "Name:\tsing-box\nState:\tS (sleeping)\nUid:\t990\t990\t990\t990\n";
            assert_eq!(
                lire_statut(s),
                Some(Statut {
                    vivant: true,
                    uid: 990
                })
            );
            let z = "State:\tZ (zombie)\nUid:\t990\t990\t990\t990\n";
            assert_eq!(lire_statut(z).map(|s| s.vivant), Some(false));
            assert_eq!(lire_statut("Name:\tx\n"), None);
        }

        #[test]
        fn par_les_inodes_une_ecoute_detenue_est_confirmee() {
            let fds = Descripteurs::Lus([45678].into_iter().collect());
            assert_eq!(
                trancher(&[ecoute(990, 45678)], &fds, None, MOI),
                Proprietaire::Confirme
            );
        }

        #[test]
        fn par_les_inodes_une_ecoute_non_detenue_est_etrangere() {
            let fds = Descripteurs::Lus([1].into_iter().collect());
            assert!(matches!(
                trancher(&[ecoute(990, 45678)], &fds, None, MOI),
                Proprietaire::Autre { .. }
            ));
        }

        /// Le cas de l'unite livree: descripteurs refuses, compte dedie declare,
        /// enfant vivant sous ce compte, ecoute de ce compte.
        #[test]
        fn des_descripteurs_refuses_se_tranchent_par_le_compte_du_coeur() {
            let fds = Descripteurs::Refuses("ouverture de /proc/4242/fd: refuse".into());
            let statut = Ok(Statut {
                vivant: true,
                uid: 990,
            });
            assert_eq!(
                trancher(&[ecoute(990, 45678)], &fds, Some(&statut), MOI),
                Proprietaire::Confirme
            );
        }

        /// La LIMITE du chemin par le compte, epinglee pour qu'un changement de
        /// comportement soit un choix et non un accident: deux ecoutes du compte
        /// dedie, dont une que l'enfant ne tient peut-etre pas (un coeur
        /// orphelin), sont confirmees ensemble. L'uid d'un socket ne dit pas
        /// QUEL processus de ce compte le tient.
        #[test]
        fn par_le_compte_deux_processus_du_compte_dedie_ne_se_distinguent_pas() {
            let fds = Descripteurs::Refuses("refuse".into());
            let statut = Ok(Statut {
                vivant: true,
                uid: 990,
            });
            assert_eq!(
                trancher(&[ecoute(990, 1), ecoute(990, 2)], &fds, Some(&statut), MOI),
                Proprietaire::Confirme
            );
        }

        /// Un squatteur sous un autre compte est refuse sans lire un seul
        /// descripteur.
        #[test]
        fn une_ecoute_d_un_autre_compte_est_etrangere_meme_sans_les_descripteurs() {
            let fds = Descripteurs::Refuses("refuse".into());
            let statut = Ok(Statut {
                vivant: true,
                uid: 990,
            });
            let v = trancher(&[ecoute(990, 1), ecoute(1000, 2)], &fds, Some(&statut), MOI);
            match v {
                Proprietaire::Autre { details } => {
                    assert!(details.contains("uid 1000"), "{details}")
                }
                autre => panic!("un socket d'un autre compte doit etre etranger: {autre:?}"),
            }
        }

        /// Sans compte declare, un refus de lecture ne designe PERSONNE.
        #[test]
        fn des_descripteurs_refuses_sans_compte_declare_n_accusent_personne() {
            let fds = Descripteurs::Refuses("lecture du lien /proc/4242/fd/3: refuse".into());
            let sans_compte = Attendu {
                pid: 4242,
                uid: None,
            };
            match trancher(&[ecoute(990, 45678)], &fds, None, sans_compte) {
                Proprietaire::Illisible { details } => {
                    assert!(details.contains("illisibles"), "{details}");
                    assert!(details.contains("aucun compte dedie"), "{details}");
                }
                autre => panic!("un refus de lecture ne doit accuser personne: {autre:?}"),
            }
        }

        #[test]
        fn un_enfant_mort_ou_sous_un_autre_compte_ne_confirme_rien() {
            let fds = Descripteurs::Refuses("refuse".into());
            let mort = Ok(Statut {
                vivant: false,
                uid: 990,
            });
            assert!(matches!(
                trancher(&[ecoute(990, 1)], &fds, Some(&mort), MOI),
                Proprietaire::Illisible { .. }
            ));
            let deplace = Ok(Statut {
                vivant: true,
                uid: 0,
            });
            assert!(matches!(
                trancher(&[ecoute(990, 1)], &fds, Some(&deplace), MOI),
                Proprietaire::Illisible { .. }
            ));
        }

        #[test]
        fn un_processus_absent_n_accuse_personne() {
            assert!(matches!(
                trancher(&[ecoute(990, 1)], &Descripteurs::Absent, None, MOI),
                Proprietaire::Illisible { .. }
            ));
        }

        // Le chemin par le compte dedie, COMPOSE: vraie table des ecoutes, vrai
        // enfant, vrai `/proc/<pid>/status`; seul le refus des descripteurs est
        // fourni (`refus_simule`), parce qu'un compte ordinaire ne sait pas le
        // provoquer sur son propre enfant. Ce sont ces recettes qui rougissent
        // quand on force l'etat de l'enfant a << vivant, sous le compte
        // declare >>, ce que les recettes pures de `trancher` ne voient pas.

        /// L'uid effectif de ce processus, lu comme celui de l'enfant.
        fn mon_uid() -> u32 {
            statut_de(std::process::id())
                .expect("son propre /proc/<pid>/status est lisible")
                .uid
        }

        /// Le refus que l'unite livree provoque sur les descripteurs du coeur.
        fn refus_simule(_: u32) -> Descripteurs {
            Descripteurs::Refuses("refus simule par la recette".to_owned())
        }

        /// Une ecoute de CE processus sur la boucle: son socket porte notre uid,
        /// celui que les recettes declarent comme compte du coeur.
        fn ecoute_du_compte() -> (std::net::TcpListener, u16) {
            let e = std::net::TcpListener::bind("127.0.0.1:0").expect("un port libre");
            let port = e.local_addr().unwrap().port();
            (e, port)
        }

        /// Un enfant vivant, sous notre uid. Tue par PID par chaque recette.
        fn enfant_qui_dort() -> std::process::Child {
            std::process::Command::new("sleep")
                .arg("30")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .expect("un enfant vivant de test doit se lancer")
        }

        /// Temoin positif: enfant vivant sous le compte declare, ecoute de ce
        /// compte, `Confirme`. L'ecoute est ici celle de la recette: c'est la
        /// limite deja epinglee plus haut (deux processus du meme compte). Sans
        /// ce temoin, un etat toujours refuse passerait les trois suivantes.
        #[test]
        fn par_le_compte_un_enfant_vivant_sous_le_compte_declare_est_confirme() {
            let (_ecoute, port) = ecoute_du_compte();
            let mut enfant = enfant_qui_dort();
            let attendu = Attendu {
                pid: enfant.id(),
                uid: Some(mon_uid()),
            };
            let v = verifier_avec(port, attendu, refus_simule);
            let _ = enfant.kill();
            let _ = enfant.wait();
            assert_eq!(v, Proprietaire::Confirme);
        }

        /// Enfant tue et reape: son etat n'existe plus, et l'ecoute du compte
        /// declare, fut-elle la seule, n'est pas la sienne.
        #[test]
        fn par_le_compte_un_enfant_mort_et_reape_ne_confirme_rien() {
            let (_ecoute, port) = ecoute_du_compte();
            let mut enfant = enfant_qui_dort();
            let pid = enfant.id();
            enfant.kill().expect("tuer l'enfant par son PID");
            enfant.wait().expect("reaper l'enfant");
            let attendu = Attendu {
                pid,
                uid: Some(mon_uid()),
            };
            match verifier_avec(port, attendu, refus_simule) {
                Proprietaire::Illisible { details } => {
                    assert!(details.contains("n'existe plus"), "{details}")
                }
                autre => panic!("un enfant reape ne doit rien confirmer: {autre:?}"),
            }
        }

        /// Enfant tue mais pas encore reape: zombie, etat `Z`.
        #[test]
        fn par_le_compte_un_enfant_zombie_ne_confirme_rien() {
            let (_ecoute, port) = ecoute_du_compte();
            let mut enfant = enfant_qui_dort();
            let pid = enfant.id();
            enfant.kill().expect("tuer l'enfant par son PID");
            let debut = std::time::Instant::now();
            while statut_de(pid).map(|s| s.vivant).unwrap_or(true) {
                assert!(
                    debut.elapsed() < std::time::Duration::from_secs(5),
                    "l'enfant tue n'est jamais devenu zombie"
                );
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            let attendu = Attendu {
                pid,
                uid: Some(mon_uid()),
            };
            let v = verifier_avec(port, attendu, refus_simule);
            let _ = enfant.wait();
            match v {
                Proprietaire::Illisible { details } => {
                    assert!(details.contains("est mort"), "{details}")
                }
                autre => panic!("un enfant zombie ne doit rien confirmer: {autre:?}"),
            }
        }

        /// Enfant vivant sous un autre uid que le compte declare. Un compte
        /// ordinaire ne peut lancer d'enfant que sous son propre uid, ni poser
        /// d'ecoute que sous le sien: on declare donc un compte qui n'est pas
        /// celui de l'enfant. Le refus doit venir de l'etat de l'enfant, qui
        /// nomme son uid, avant toute comparaison des ecoutes.
        #[test]
        fn par_le_compte_un_enfant_sous_un_autre_uid_que_le_compte_declare_ne_confirme_rien() {
            let (_ecoute, port) = ecoute_du_compte();
            let moi = mon_uid();
            let mut enfant = enfant_qui_dort();
            let attendu = Attendu {
                pid: enfant.id(),
                uid: Some(moi.wrapping_add(1)),
            };
            let v = verifier_avec(port, attendu, refus_simule);
            let _ = enfant.kill();
            let _ = enfant.wait();
            match v {
                Proprietaire::Illisible { details } => assert!(
                    details.contains(&format!("tourne sous l'uid {moi}")),
                    "{details}"
                ),
                autre => panic!(
                    "un enfant sous un autre uid que le compte declare ne doit rien confirmer: {autre:?}"
                ),
            }
        }

        /// Le cas entier: l'ecoute EST au compte declare, mais le processus
        /// declare tourne sous un autre uid. Un compte ordinaire ne peut lancer
        /// d'enfant que sous son propre uid; on declare donc un processus qui
        /// existe deja sous un autre compte, le PID 1 (root sur un hote
        /// ordinaire), et notre uid comme compte du coeur. L'ecoute ne refuse
        /// plus rien: seul l'etat du processus declare le peut.
        #[test]
        fn par_le_compte_une_ecoute_du_compte_declare_ne_couvre_pas_un_processus_d_un_autre_uid() {
            let moi = mon_uid();
            let init = match statut_de(1) {
                Ok(s) if s.vivant && s.uid != moi => s,
                autre => {
                    println!(
                        "SKIPPED par_le_compte_une_ecoute_du_compte_declare_ne_couvre_pas_un_processus_d_un_autre_uid: \
                         le PID 1 n'est pas lisible, vivant, sous un autre uid que le notre ({moi}): {autre:?}"
                    );
                    return;
                }
            };
            let (_ecoute, port) = ecoute_du_compte();
            let attendu = Attendu {
                pid: 1,
                uid: Some(moi),
            };
            match verifier_avec(port, attendu, refus_simule) {
                Proprietaire::Illisible { details } => assert!(
                    details.contains(&format!("tourne sous l'uid {}", init.uid)),
                    "{details}"
                ),
                autre => panic!(
                    "un processus d'un autre uid que le compte declare ne doit rien confirmer: {autre:?}"
                ),
            }
        }
    }
}

#[cfg(windows)]
mod windows_impl {
    use super::Proprietaire;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, MIB_TCP_STATE_LISTEN, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID,
        MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_LISTENER,
    };
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};

    /// 127.0.0.1 tel que `dwLocalAddr` le porte (ordre reseau lu en u32
    /// petit-boutiste: 0x0100007F).
    const V4_BOUCLE: u32 = 0x0100_007F;
    const V4_TOUTES: u32 = 0;

    pub fn verifier(port: u16, pid_attendu: u32) -> Proprietaire {
        let mut proprietaires = Vec::new();

        match lire_v4(port) {
            Ok(mut v) => proprietaires.append(&mut v),
            Err(e) => {
                return Proprietaire::Illisible {
                    details: format!("GetExtendedTcpTable v4: {e}"),
                };
            }
        }
        match lire_v6(port) {
            Ok(mut v) => proprietaires.append(&mut v),
            Err(e) => {
                return Proprietaire::Illisible {
                    details: format!("GetExtendedTcpTable v6: {e}"),
                };
            }
        }

        if proprietaires.is_empty() {
            return Proprietaire::PersonneEncore;
        }
        for pid in &proprietaires {
            if *pid != pid_attendu {
                return Proprietaire::Autre {
                    details: format!(
                        "le port est ecoute par le processus {pid}, et non par {pid_attendu}"
                    ),
                };
            }
        }
        Proprietaire::Confirme
    }

    /// Une ecoute v4 a cette adresse recevrait-elle une connexion vers
    /// `127.0.0.1`. `0.0.0.0` OUI: sous Windows elle coexiste avec le coeur sur
    /// `127.0.0.1` et prend le relais des qu'il meurt.
    pub(super) fn recoit_la_boucle_v4(adresse_locale: u32) -> bool {
        adresse_locale == V4_BOUCLE || adresse_locale == V4_TOUTES
    }

    /// Idem en v6: `::`, `::ffff:127.0.0.1`, `::ffff:0.0.0.0`. Pas `::1`.
    pub(super) fn recoit_la_boucle_v6(octets: &[u8; 16]) -> bool {
        *octets == Ipv6Addr::UNSPECIFIED.octets()
            || *octets == Ipv4Addr::LOCALHOST.to_ipv6_mapped().octets()
            || *octets == Ipv4Addr::UNSPECIFIED.to_ipv6_mapped().octets()
    }

    /// Le port d'une ligne de la table, en ordre hote. `dwLocalPort` est en
    /// ordre reseau, sur les deux octets de poids faible.
    fn port_hote(dw_local_port: u32) -> u16 {
        let octets = dw_local_port.to_le_bytes();
        u16::from_be_bytes([octets[0], octets[1]])
    }

    /// Les PID proprietaires des ecoutes v4 sur `port` qui recevraient la
    /// connexion.
    fn lire_v4(port: u16) -> Result<Vec<u32>, String> {
        let tampon = table_brute(AF_INET as u32)?;
        if tampon.is_empty() {
            return Ok(Vec::new());
        }
        // La table commence par dwNumEntries, suivi des lignes.
        let entete = tampon.as_ptr() as *const MIB_TCPTABLE_OWNER_PID;
        // SAFETY: `tampon` a ete rempli par GetExtendedTcpTable pour AF_INET et
        // fait au moins la taille de l'en-tete; on ne lit que ce que
        // dwNumEntries annonce.
        let nombre = unsafe { (*entete).dwNumEntries } as usize;
        // SAFETY: `entete` pointe sur un en-tete valide (meme tampon), et
        // `table` est le premier element du tableau flexible qui suit.
        let premieres = unsafe { (*entete).table.as_ptr() };
        let mut trouves = Vec::new();
        for i in 0..nombre {
            // SAFETY: i < dwNumEntries, donc la ligne est dans le tampon rempli.
            let ligne: &MIB_TCPROW_OWNER_PID = unsafe { &*premieres.add(i) };
            if ligne.dwState != MIB_TCP_STATE_LISTEN as u32 {
                continue;
            }
            if port_hote(ligne.dwLocalPort) != port {
                continue;
            }
            if !recoit_la_boucle_v4(ligne.dwLocalAddr) {
                continue;
            }
            trouves.push(ligne.dwOwningPid);
        }
        Ok(trouves)
    }

    /// Les PID proprietaires des ecoutes v6 sur `port` qui recevraient la
    /// connexion.
    fn lire_v6(port: u16) -> Result<Vec<u32>, String> {
        let tampon = table_brute(AF_INET6 as u32)?;
        if tampon.is_empty() {
            return Ok(Vec::new());
        }
        let entete = tampon.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID;
        // SAFETY: meme raisonnement que lire_v4, pour la table v6.
        let nombre = unsafe { (*entete).dwNumEntries } as usize;
        // SAFETY: `entete` pointe sur un en-tete valide (meme tampon), et
        // `table` est le premier element du tableau flexible qui suit.
        let premieres = unsafe { (*entete).table.as_ptr() };
        let mut trouves = Vec::new();
        for i in 0..nombre {
            // SAFETY: i < dwNumEntries.
            let ligne: &MIB_TCP6ROW_OWNER_PID = unsafe { &*premieres.add(i) };
            if ligne.dwState != MIB_TCP_STATE_LISTEN as u32 {
                continue;
            }
            if port_hote(ligne.dwLocalPort) != port {
                continue;
            }
            if !recoit_la_boucle_v6(&ligne.ucLocalAddr) {
                continue;
            }
            trouves.push(ligne.dwOwningPid);
        }
        Ok(trouves)
    }

    /// Le tampon brut de la table des ecoutes, pour la famille donnee. Deux
    /// appels a taille croissante, comme partout ailleurs avec les API Win32 a
    /// tampon: le premier dit combien il faut, le second remplit.
    fn table_brute(famille: u32) -> Result<Vec<u8>, String> {
        let mut taille: u32 = 0;
        // SAFETY: pointeur de table nul pour la seule sonde de taille; `taille`
        // vit ici et recoit le nombre d'octets requis.
        unsafe {
            GetExtendedTcpTable(
                std::ptr::null_mut(),
                &mut taille,
                0,
                famille,
                TCP_TABLE_OWNER_PID_LISTENER,
                0,
            );
        }
        if taille == 0 {
            return Ok(Vec::new());
        }
        let mut tampon = vec![0u8; taille as usize];
        // SAFETY: `tampon` fait `taille` octets, la taille passee est la sienne,
        // et la famille est celle demandee a la sonde.
        let code = unsafe {
            GetExtendedTcpTable(
                tampon.as_mut_ptr() as *mut core::ffi::c_void,
                &mut taille,
                0,
                famille,
                TCP_TABLE_OWNER_PID_LISTENER,
                0,
            )
        };
        if code != 0 {
            return Err(format!("erreur Win32 {code}"));
        }
        Ok(tampon)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn le_port_reseau_se_lit_en_ordre_hote() {
            // 0x1F90 = 8080 en ordre reseau: octets 0x1F, 0x90 dans dwLocalPort.
            let dw = u32::from_le_bytes([0x1F, 0x90, 0, 0]);
            assert_eq!(port_hote(dw), 8080);
            let dw = u32::from_le_bytes([0x23, 0x82, 0, 0]);
            assert_eq!(port_hote(dw), 9090);
        }

        /// La garde que le verificateur a trouvee aveugle (M8w): ignorer
        /// `0.0.0.0` ne rougissait rien. Elle compte, parce qu'elle coexiste
        /// avec le coeur sous Windows et prend le relais a sa mort.
        #[test]
        fn une_ecoute_sur_toutes_les_adresses_v4_compte() {
            let adresse = |o: [u8; 4]| u32::from_le_bytes(o);
            assert!(recoit_la_boucle_v4(adresse([127, 0, 0, 1])));
            assert!(recoit_la_boucle_v4(adresse([0, 0, 0, 0])));
            assert!(!recoit_la_boucle_v4(adresse([127, 0, 0, 2])));
            assert!(!recoit_la_boucle_v4(adresse([192, 168, 1, 10])));
        }

        #[test]
        fn en_v6_toutes_et_mappees_comptent_mais_pas_la_boucle_v6() {
            assert!(recoit_la_boucle_v6(&Ipv6Addr::UNSPECIFIED.octets()));
            assert!(recoit_la_boucle_v6(
                &Ipv4Addr::LOCALHOST.to_ipv6_mapped().octets()
            ));
            assert!(!recoit_la_boucle_v6(&Ipv6Addr::LOCALHOST.octets()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    fn moi() -> Attendu {
        Attendu {
            pid: std::process::id(),
            uid: None,
        }
    }

    /// Une ecoute que CE processus detient est reconnue comme sienne, et
    /// refusee a tout autre PID.
    #[test]
    fn une_ecoute_appartient_a_qui_la_tient_et_a_personne_d_autre() {
        let ecoute = TcpListener::bind("127.0.0.1:0").expect("un port libre sur la boucle");
        let port = ecoute.local_addr().unwrap().port();

        assert_eq!(
            verifier_ecoute(port, moi()),
            Proprietaire::Confirme,
            "le processus qui tient l'ecoute doit etre reconnu"
        );

        // Un PID qui n'est pas le mien ne doit jamais etre confirme.
        let autre = Attendu {
            pid: std::process::id().wrapping_add(1).max(2),
            uid: None,
        };
        match verifier_ecoute(port, autre) {
            Proprietaire::Confirme => {
                panic!("l'ecoute a ete attribuee au mauvais PID: le secret irait au squatteur")
            }
            Proprietaire::Autre { .. } | Proprietaire::Illisible { .. } => {}
            Proprietaire::PersonneEncore => {
                panic!("l'ecoute existe pourtant: la verification ne l'a pas vue")
            }
        }
    }

    /// Un proprietaire VIVANT mais different est rejete, de facon deterministe.
    ///
    /// L'enfant est a nous (lisible sous `ptrace_scope=1`, meme compte) et ne
    /// tient pas le port: le verdict est `Autre` par les inodes, ni `Illisible`
    /// (l'enfant est lisible) ni `Confirme`.
    #[cfg(target_os = "linux")]
    #[test]
    fn un_proprietaire_vivant_mais_different_est_rejete() {
        let ecoute = TcpListener::bind("127.0.0.1:0").expect("un port libre sur la boucle");
        let port = ecoute.local_addr().unwrap().port();
        let mut enfant = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("sleep doit se lancer");
        let attendu = Attendu {
            pid: enfant.id(),
            uid: None,
        };
        std::thread::sleep(std::time::Duration::from_millis(150));
        let verdict = verifier_ecoute(port, attendu);
        // Tuer et reaper AVANT d'asserter: par PID, jamais par motif.
        let _ = enfant.kill();
        let _ = enfant.wait();
        assert!(
            matches!(verdict, Proprietaire::Autre { .. }),
            "un proprietaire vivant qui ne tient pas le port doit etre rejete comme Autre, obtenu: {verdict:?}"
        );
    }

    /// Un port que personne n'ecoute rend `PersonneEncore`, jamais `Confirme`.
    #[test]
    fn un_port_sans_ecoute_n_est_ni_confirme_ni_usurpe() {
        // Un port tenu, lie mais jamais mis en ecoute. Voir `super::port`.
        let tenu = super::super::port::port_sans_personne().unwrap();
        assert_eq!(
            verifier_ecoute(tenu.port(), moi()),
            Proprietaire::PersonneEncore,
            "un port sans ecoute ne doit pas etre pris pour une presence"
        );
    }
}
