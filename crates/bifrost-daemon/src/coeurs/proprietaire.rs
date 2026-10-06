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
//! L'enfant est designe par un COUPLE: son PID et sa date de demarrage, que le
//! daemon releve lui-meme sur son enfant au lancement, tant qu'il en tient le
//! `Child` sans l'avoir attendu ([`date_de_demarrage`], porte par
//! [`Attendu::demarrage`]). Ce couple designe un seul processus tant que la
//! machine ne redemarre pas. A chaque verification, la decision exige que le
//! processus du PID ait encore cette date AVANT de faire confiance a ce qu'elle
//! lit de lui, et la relit APRES: date differente, illisible ou jamais relevee,
//! le verdict est `Illisible`. Jamais `Confirme`, et jamais `Autre` non plus:
//! un processus qui n'est plus l'enfant ne dit rien des ecoutes de l'enfant, et
//! n'accuse donc personne.
//!
//! - **Windows**: `GetExtendedTcpTable` avec `TCP_TABLE_OWNER_PID_LISTENER`
//!   rend le PID proprietaire de chaque ecoute, pour tout compte et sans
//!   privilege. On le compare au PID de l'enfant. La date est sa date de
//!   creation (`GetProcessTimes`, en centaines de nanosecondes), lue avant la
//!   table et relue apres elle. Tant que le `Child` vit, tokio en garde la
//!   poignee, et Windows ne reattribue un PID qu'une fois toutes ses poignees
//!   fermees; la date exige en plus que le PID de la table designe encore
//!   l'enfant au moment de chaque verification.
//! - **Linux**: la date est le champ 22 (`starttime`) de `/proc/<pid>/stat`,
//!   lisible par tout compte comme `/proc/<pid>/status`, compte apres la
//!   DERNIERE parenthese fermante (le nom du processus peut contenir espaces
//!   et parentheses). Elle est lue avant les descripteurs de l'enfant et
//!   relue apres eux et apres son statut, sur chacun des deux chemins
//!   suivants, par ordre de force:
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
    /// La date de demarrage de l'enfant, relevee par le daemon a son lancement
    /// ([`date_de_demarrage`], tant qu'il tient le `Child`), dans l'unite du
    /// systeme: sous Linux le `starttime` de `/proc/<pid>/stat`, en tics
    /// d'horloge depuis le demarrage de la machine; sous Windows la date de
    /// creation du processus, en centaines de nanosecondes depuis 1601. Avec
    /// `pid`, c'est ce qui designe l'enfant. `None` quand elle n'a pas pu etre
    /// relevee: aucune verification ne confirme alors rien.
    pub demarrage: Option<u64>,
}

/// La date de demarrage du processus `pid`, dans l'unite que porte
/// [`Attendu::demarrage`].
///
/// Le daemon l'appelle sur son enfant au lancement, tant qu'il en tient le
/// `Child` sans l'avoir attendu: ce PID ne designe alors que cet enfant. La
/// verification la relit ensuite pour s'assurer que le PID le designe encore.
pub fn date_de_demarrage(pid: u32) -> Result<u64, String> {
    #[cfg(target_os = "linux")]
    {
        linux::demarrage_de(pid)
    }
    #[cfg(windows)]
    {
        windows_impl::demarrage_de(pid)
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = pid;
        Err("date de demarrage d'un processus non implementee sur cette plateforme".to_owned())
    }
}

/// Le processus du PID attendu est-il encore l'enfant que le daemon a lance.
///
/// `avant` et `apres` sont les deux lectures de sa date de demarrage qui
/// encadrent ce que la verification lit de lui: ses descripteurs ou son
/// statut sous Linux, la table des ecoutes sous Windows. Les deux doivent etre
/// lisibles et egales a la date relevee au lancement
/// ([`Attendu::demarrage`]). Sinon, la raison: l'appelant en fait
/// `Illisible`, ni `Confirme` ni `Autre`, puisqu'un processus qui n'est plus
/// l'enfant ne dit rien des ecoutes de l'enfant. Pure.
#[cfg(any(target_os = "linux", windows))]
fn meme_processus(
    attendu: Attendu,
    avant: &Result<u64, String>,
    apres: &Result<u64, String>,
) -> Result<(), String> {
    let pid = attendu.pid;
    let Some(relevee) = attendu.demarrage else {
        return Err(format!(
            "aucune date de demarrage n'a ete relevee au lancement du processus {pid}: rien n'etablit que ce PID designe encore l'enfant lance"
        ));
    };
    for (quand, lue) in [("avant", avant), ("apres", apres)] {
        match lue {
            Ok(date) if *date == relevee => {}
            Ok(date) => {
                return Err(format!(
                    "le processus {pid} n'est plus l'enfant lance: date de demarrage {date} lue {quand} la verification, {relevee} relevee au lancement"
                ));
            }
            Err(e) => {
                return Err(format!(
                    "date de demarrage du processus {pid} illisible {quand} la verification: {e}"
                ));
            }
        }
    }
    Ok(())
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
        windows_impl::verifier(port, attendu)
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
    /// table des ecoutes, la date de demarrage, l'etat et l'uid de l'enfant -
    /// est lu pour de vrai. Sans ce parametre, aucune recette ne voyait l'etat
    /// de l'enfant: le forcer a << vivant, sous le compte declare >> les
    /// laissait toutes vertes. La production passe [`descripteurs_de`].
    pub(super) fn verifier_avec(
        port: u16,
        attendu: Attendu,
        lire_descripteurs: impl Fn(u32) -> Descripteurs,
    ) -> Proprietaire {
        verifier_avec_lecteurs(port, attendu, lire_descripteurs, demarrage_de)
    }

    /// [`verifier_avec`], avec aussi la lecture de la date de demarrage en
    /// parametre: les recettes y eprouvent l'ordre des lectures, la date AVANT
    /// les descripteurs, puis relue APRES eux et apres le statut. La production
    /// passe [`demarrage_de`].
    pub(super) fn verifier_avec_lecteurs(
        port: u16,
        attendu: Attendu,
        lire_descripteurs: impl Fn(u32) -> Descripteurs,
        lire_demarrage: impl Fn(u32) -> Result<u64, String>,
    ) -> Proprietaire {
        let ecoutes = match ecoutes_sur(port) {
            Ok(e) => e,
            Err(details) => return Proprietaire::Illisible { details },
        };
        if ecoutes.is_empty() {
            return Proprietaire::PersonneEncore;
        }
        // La date de demarrage encadre tout ce qu'on lit du PID: lue avant ses
        // descripteurs, relue apres eux et apres son statut. Egale des deux
        // cotes a celle du lancement, ces lectures sont celles de l'enfant.
        let avant = lire_demarrage(attendu.pid);
        let fds = lire_descripteurs(attendu.pid);
        let statut = match fds {
            Descripteurs::Refuses(_) => Some(statut_de(attendu.pid)),
            _ => None,
        };
        let apres = lire_demarrage(attendu.pid);
        let verdict = decider(&ecoutes, &fds, statut.as_ref(), &avant, &apres, attendu);

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

    /// Le verdict entier: l'identite du processus d'abord, ses ecoutes ensuite.
    ///
    /// Chacun des deux chemins qui FONT CONFIANCE a ce qu'on a lu du PID - ses
    /// descripteurs (par l'inode) ou son statut (par le compte dedie) - exige
    /// d'abord que ce PID designe encore l'enfant lance: sa date de demarrage,
    /// lue avant ces lectures et relue apres, est celle que le daemon a relevee
    /// au lancement (`super::meme_processus`). Sinon `Illisible`, ni `Confirme`
    /// ni `Autre`. Les deux autres cas ne font confiance a rien, et [`trancher`]
    /// les refuse deja sans accuser personne. Pure, comme [`trancher`].
    pub(super) fn decider(
        ecoutes: &[Ecoute],
        fds: &Descripteurs,
        statut: Option<&Result<Statut, String>>,
        avant: &Result<u64, String>,
        apres: &Result<u64, String>,
        attendu: Attendu,
    ) -> Proprietaire {
        let identite = match fds {
            // Par l'inode: les inodes lus ne sont ceux de l'enfant que si le
            // PID le designe encore.
            Descripteurs::Lus(_) => super::meme_processus(attendu, avant, apres),
            // Par le compte: l'etat et l'uid lus ne sont ceux de l'enfant qu'a
            // la meme condition.
            Descripteurs::Refuses(_) => super::meme_processus(attendu, avant, apres),
            Descripteurs::Absent | Descripteurs::Erreur(_) => Ok(()),
        };
        match identite {
            Ok(()) => trancher(ecoutes, fds, statut, attendu),
            Err(details) => Proprietaire::Illisible { details },
        }
    }

    /// Le verdict sur les ecoutes, a partir de ce qui a ete lu, une fois
    /// l'identite du processus etablie par [`decider`]. Pure: c'est ici que se
    /// decide qui est accuse, et les recettes l'eprouvent sans privilege.
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

    /// La date de demarrage du processus, par `/proc/<pid>/stat`: le champ 22
    /// (`starttime`), en tics d'horloge depuis le demarrage de la machine.
    /// Le fichier est lisible par tout compte, comme `/proc/<pid>/status`, et
    /// le noyau y ecrit cette date pour tout processus, zombie compris.
    pub(super) fn demarrage_de(pid: u32) -> Result<u64, String> {
        let chemin = format!("/proc/{pid}/stat");
        let contenu = std::fs::read(&chemin).map_err(|e| match e.kind() {
            ErrorKind::NotFound => format!("{chemin} absent: le processus n'existe plus"),
            _ => format!("lecture de {chemin}: {e}"),
        })?;
        demarrage_dans_stat(&contenu)
            .ok_or_else(|| format!("{chemin}: champ 22 (starttime) absent ou non numerique"))
    }

    /// Le champ 22 d'un texte de `/proc/<pid>/stat`, compte apres la DERNIERE
    /// parenthese fermante: le nom du processus, entre parentheses, peut
    /// contenir espaces et parentheses. Le parseur est celui du journal des
    /// sessions de routage (`tunnel::session::etat_et_debut`), pour qu'une
    /// seule lecture de ce format vive dans le produit. Un nom qui n'est pas de
    /// l'UTF-8 ne change rien aux champs qui le suivent, tous ASCII.
    pub(super) fn demarrage_dans_stat(contenu: &[u8]) -> Option<u64> {
        crate::tunnel::session::etat_et_debut(&String::from_utf8_lossy(contenu))
            .map(|(_, debut)| debut)
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

        /// La date de demarrage que les recettes pures declarent pour `MOI`.
        const DATE: u64 = 98765;

        const MOI: Attendu = Attendu {
            pid: 4242,
            uid: Some(990),
            demarrage: Some(DATE),
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
                demarrage: MOI.demarrage,
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
                demarrage: demarrage_de(enfant.id()).ok(),
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
            let demarrage = demarrage_de(pid).ok();
            enfant.kill().expect("tuer l'enfant par son PID");
            enfant.wait().expect("reaper l'enfant");
            let attendu = Attendu {
                pid,
                uid: Some(mon_uid()),
                demarrage,
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
            let demarrage = demarrage_de(pid).ok();
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
                demarrage,
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
                demarrage: demarrage_de(enfant.id()).ok(),
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
                demarrage: demarrage_de(1).ok(),
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

        // La date de demarrage: sa lecture dans `/proc/<pid>/stat`, puis la
        // decision avec une date egale, differente et illisible, sur chacun
        // des deux chemins.

        /// Un texte de `/proc/<pid>/stat` au format du noyau: le champ 3 est
        /// l'etat, chacun des champs 4 a 52 porte son propre numero, sauf le
        /// 22, qui porte `demarrage`. Lire un autre champ que le 22 rend donc
        /// un numero de champ, et non la date.
        fn stat(nom: &str, demarrage: &str) -> Vec<u8> {
            let champs: Vec<String> = (4..=52)
                .map(|n| {
                    if n == 22 {
                        demarrage.to_owned()
                    } else {
                        n.to_string()
                    }
                })
                .collect();
            format!("4242 ({nom}) S {}\n", champs.join(" ")).into_bytes()
        }

        #[test]
        fn la_date_de_demarrage_est_le_champ_22_de_stat() {
            assert_eq!(demarrage_dans_stat(&stat("sing-box", "98765")), Some(98765));
        }

        /// Le nom peut porter espaces et parentheses: les champs se comptent
        /// apres la DERNIERE parenthese fermante, jamais apres la premiere.
        #[test]
        fn un_nom_avec_espaces_et_parentheses_ne_decale_pas_les_champs() {
            for nom in ["sing box", "x) y (z", "a) S 1 (b", ") )", "(("] {
                assert_eq!(
                    demarrage_dans_stat(&stat(nom, "98765")),
                    Some(98765),
                    "nom {nom:?}"
                );
            }
        }

        /// Un nom qui n'est pas de l'UTF-8 ne rend pas la date illisible.
        #[test]
        fn un_nom_hors_utf8_ne_rend_pas_la_date_illisible() {
            let mut texte = stat("ab", "98765");
            let debut = texte.iter().position(|&o| o == b'a').unwrap();
            texte[debut] = 0xff;
            texte[debut + 1] = 0xfe;
            assert_eq!(demarrage_dans_stat(&texte), Some(98765));
        }

        /// Des champs manquants ne donnent aucune date: ni celle d'un autre
        /// champ, ni zero.
        #[test]
        fn des_champs_manquants_ne_donnent_aucune_date() {
            let complet = String::from_utf8(stat("sing-box", "98765")).unwrap();
            let jusqu_au_21 = &complet[..complet.find(" 98765").unwrap()];
            assert_eq!(demarrage_dans_stat(jusqu_au_21.as_bytes()), None);
            assert_eq!(demarrage_dans_stat(b"4242 (sing-box"), None);
            assert_eq!(demarrage_dans_stat(b"4242 sing-box S 4 5 6"), None);
            assert_eq!(demarrage_dans_stat(b""), None);
        }

        #[test]
        fn une_date_non_numerique_ne_donne_aucune_date() {
            for valeur in ["abc", "-5", "12a", "1.5", "99999999999999999999999"] {
                assert_eq!(
                    demarrage_dans_stat(&stat("sing-box", valeur)),
                    None,
                    "valeur {valeur:?}"
                );
            }
        }

        /// La lecture reelle: la date de ce processus, lue deux fois, est la
        /// meme, et c'est celle que le journal des sessions lit de son cote.
        /// Un PID qui n'existe pas rend une raison, jamais une date.
        #[test]
        fn la_date_de_ce_processus_se_lit_et_ne_change_pas() {
            let pid = std::process::id();
            let une = demarrage_de(pid).expect("son propre /proc/<pid>/stat est lisible");
            assert_eq!(demarrage_de(pid), Ok(une));
            assert_eq!(
                crate::tunnel::session::ce_processus()
                    .map(|(_, debut)| debut)
                    .ok(),
                Some(une)
            );
            let absent = demarrage_de(u32::MAX).expect_err("aucun processus ne porte ce PID");
            assert!(absent.contains("n'existe plus"), "{absent}");
        }

        /// Une date lue, une date qui n'est pas celle du lancement, une date
        /// illisible.
        fn egale() -> Result<u64, String> {
            Ok(DATE)
        }
        fn differente() -> Result<u64, String> {
            Ok(DATE + 1)
        }
        fn illisible() -> Result<u64, String> {
            Err("/proc/4242/stat absent: le processus n'existe plus".to_owned())
        }

        /// Ce que le chemin par l'inode lit: l'ecoute est detenue par le PID.
        fn par_l_inode() -> (Vec<Ecoute>, Descripteurs) {
            (
                vec![ecoute(990, 45678)],
                Descripteurs::Lus([45678].into_iter().collect()),
            )
        }

        /// Ce que le chemin par le compte lit: descripteurs refuses, PID vivant
        /// sous le compte declare, ecoute de ce compte.
        fn par_le_compte() -> (Vec<Ecoute>, Descripteurs, Result<Statut, String>) {
            (
                vec![ecoute(990, 45678)],
                Descripteurs::Refuses("refuse".into()),
                Ok(Statut {
                    vivant: true,
                    uid: 990,
                }),
            )
        }

        /// Le refus attendu quand le PID ne designe plus l'enfant: `Illisible`,
        /// avec une raison qui contient `motif`.
        fn illisible_avec(v: Proprietaire, motif: &str) {
            match v {
                Proprietaire::Illisible { details } => {
                    assert!(details.contains(motif), "{details}")
                }
                autre => panic!("attendu Illisible ({motif}), obtenu {autre:?}"),
            }
        }

        #[test]
        fn par_l_inode_la_date_du_lancement_avant_et_apres_confirme() {
            let (ecoutes, fds) = par_l_inode();
            assert_eq!(
                decider(&ecoutes, &fds, None, &egale(), &egale(), MOI),
                Proprietaire::Confirme
            );
        }

        #[test]
        fn par_l_inode_une_date_differente_ne_confirme_rien() {
            let (ecoutes, fds) = par_l_inode();
            illisible_avec(
                decider(&ecoutes, &fds, None, &differente(), &egale(), MOI),
                "n'est plus l'enfant lance",
            );
            illisible_avec(
                decider(&ecoutes, &fds, None, &egale(), &differente(), MOI),
                "lue apres",
            );
        }

        #[test]
        fn par_l_inode_une_date_illisible_ne_confirme_rien() {
            let (ecoutes, fds) = par_l_inode();
            illisible_avec(
                decider(&ecoutes, &fds, None, &illisible(), &egale(), MOI),
                "illisible avant",
            );
            illisible_avec(
                decider(&ecoutes, &fds, None, &egale(), &illisible(), MOI),
                "illisible apres",
            );
        }

        /// Une ecoute que le PID ne detient pas n'accuse personne quand le PID
        /// n'est plus l'enfant: ses descripteurs ne disent rien de l'enfant.
        #[test]
        fn par_l_inode_un_pid_qui_n_est_plus_l_enfant_n_accuse_personne() {
            let fds = Descripteurs::Lus([1].into_iter().collect());
            let ecoutes = [ecoute(990, 45678)];
            assert!(matches!(
                decider(&ecoutes, &fds, None, &egale(), &egale(), MOI),
                Proprietaire::Autre { .. }
            ));
            illisible_avec(
                decider(&ecoutes, &fds, None, &differente(), &differente(), MOI),
                "n'est plus l'enfant lance",
            );
        }

        #[test]
        fn par_le_compte_la_date_du_lancement_avant_et_apres_confirme() {
            let (ecoutes, fds, statut) = par_le_compte();
            assert_eq!(
                decider(&ecoutes, &fds, Some(&statut), &egale(), &egale(), MOI),
                Proprietaire::Confirme
            );
        }

        #[test]
        fn par_le_compte_une_date_differente_ne_confirme_rien() {
            let (ecoutes, fds, statut) = par_le_compte();
            illisible_avec(
                decider(&ecoutes, &fds, Some(&statut), &differente(), &egale(), MOI),
                "n'est plus l'enfant lance",
            );
            illisible_avec(
                decider(&ecoutes, &fds, Some(&statut), &egale(), &differente(), MOI),
                "lue apres",
            );
        }

        #[test]
        fn par_le_compte_une_date_illisible_ne_confirme_rien() {
            let (ecoutes, fds, statut) = par_le_compte();
            illisible_avec(
                decider(&ecoutes, &fds, Some(&statut), &illisible(), &egale(), MOI),
                "illisible avant",
            );
            illisible_avec(
                decider(&ecoutes, &fds, Some(&statut), &egale(), &illisible(), MOI),
                "illisible apres",
            );
        }

        /// Une ecoute d'un autre compte n'accuse personne quand le PID n'est
        /// plus l'enfant: son statut ne dit rien de l'enfant.
        #[test]
        fn par_le_compte_un_pid_qui_n_est_plus_l_enfant_n_accuse_personne() {
            let (_, fds, statut) = par_le_compte();
            let ecoutes = [ecoute(1000, 45678)];
            assert!(matches!(
                decider(&ecoutes, &fds, Some(&statut), &egale(), &egale(), MOI),
                Proprietaire::Autre { .. }
            ));
            illisible_avec(
                decider(
                    &ecoutes,
                    &fds,
                    Some(&statut),
                    &differente(),
                    &differente(),
                    MOI,
                ),
                "n'est plus l'enfant lance",
            );
        }

        /// Une date jamais relevee au lancement ne confirme rien, sur aucun
        /// des deux chemins, meme quand les lectures concordent entre elles.
        #[test]
        fn sans_date_relevee_au_lancement_aucun_chemin_ne_confirme() {
            let sans_date = Attendu {
                demarrage: None,
                ..MOI
            };
            let (ecoutes, fds) = par_l_inode();
            illisible_avec(
                decider(&ecoutes, &fds, None, &egale(), &egale(), sans_date),
                "aucune date de demarrage",
            );
            let (ecoutes, fds, statut) = par_le_compte();
            illisible_avec(
                decider(&ecoutes, &fds, Some(&statut), &egale(), &egale(), sans_date),
                "aucune date de demarrage",
            );
        }

        // L'ordre des lectures, compose: vraie table des ecoutes (une ecoute de
        // CE processus, qui est ici le processus attendu), vrais descripteurs
        // ou refus simule, vrai statut; seule la date est fournie, pour qu'elle
        // puisse changer entre ses deux lectures.

        /// Des lectures de date qui rendent les dates donnees, dans l'ordre, et
        /// inscrivent chaque lecture, de date comme de descripteurs, au meme
        /// journal.
        struct Lectures {
            dates: Vec<u64>,
            rang: std::cell::Cell<usize>,
            journal: std::cell::RefCell<Vec<&'static str>>,
        }

        impl Lectures {
            fn nouvelles(dates: &[u64]) -> Self {
                Lectures {
                    dates: dates.to_vec(),
                    rang: std::cell::Cell::new(0),
                    journal: std::cell::RefCell::new(Vec::new()),
                }
            }

            fn date(&self, _: u32) -> Result<u64, String> {
                self.journal.borrow_mut().push("date");
                let i = self.rang.get();
                self.rang.set(i + 1);
                self.dates
                    .get(i)
                    .copied()
                    .ok_or_else(|| format!("lecture de date numero {i} non prevue"))
            }

            fn descripteurs(&self, pid: u32, par_l_inode: bool) -> Descripteurs {
                self.journal.borrow_mut().push("descripteurs");
                if par_l_inode {
                    descripteurs_de(pid)
                } else {
                    refus_simule(pid)
                }
            }

            fn ordre(&self) -> Vec<&'static str> {
                self.journal.borrow().clone()
            }
        }

        /// Le processus attendu est celui-ci, avec la date que les lectures
        /// fournies rendent d'abord.
        fn ce_processus_date(uid: Option<u32>) -> Attendu {
            Attendu {
                pid: std::process::id(),
                uid,
                demarrage: Some(DATE),
            }
        }

        #[test]
        fn par_l_inode_la_date_est_lue_avant_les_descripteurs_et_relue_apres() {
            let (_ecoute, port) = ecoute_du_compte();
            let attendu = ce_processus_date(None);

            let stable = Lectures::nouvelles(&[DATE, DATE]);
            let v = verifier_avec_lecteurs(
                port,
                attendu,
                |p| stable.descripteurs(p, true),
                |p| stable.date(p),
            );
            assert_eq!(v, Proprietaire::Confirme);
            assert_eq!(stable.ordre(), ["date", "descripteurs", "date"]);

            let changee = Lectures::nouvelles(&[DATE, DATE + 1]);
            let v = verifier_avec_lecteurs(
                port,
                attendu,
                |p| changee.descripteurs(p, true),
                |p| changee.date(p),
            );
            illisible_avec(v, "lue apres");
            assert_eq!(changee.ordre(), ["date", "descripteurs", "date"]);
        }

        #[test]
        fn par_le_compte_la_date_est_lue_avant_les_descripteurs_et_relue_apres() {
            let (_ecoute, port) = ecoute_du_compte();
            let attendu = ce_processus_date(Some(mon_uid()));

            let stable = Lectures::nouvelles(&[DATE, DATE]);
            let v = verifier_avec_lecteurs(
                port,
                attendu,
                |p| stable.descripteurs(p, false),
                |p| stable.date(p),
            );
            assert_eq!(v, Proprietaire::Confirme);
            assert_eq!(stable.ordre(), ["date", "descripteurs", "date"]);

            let changee = Lectures::nouvelles(&[DATE, DATE + 1]);
            let v = verifier_avec_lecteurs(
                port,
                attendu,
                |p| changee.descripteurs(p, false),
                |p| changee.date(p),
            );
            illisible_avec(v, "lue apres");
            assert_eq!(changee.ordre(), ["date", "descripteurs", "date"]);
        }
    }
}

#[cfg(windows)]
mod windows_impl {
    use super::{Attendu, Proprietaire};
    use std::net::{Ipv4Addr, Ipv6Addr};
    use windows_sys::Win32::Foundation::{CloseHandle, ERROR_INVALID_PARAMETER, FILETIME};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, MIB_TCP_STATE_LISTEN, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID,
        MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_LISTENER,
    };
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};
    use windows_sys::Win32::System::Threading::{
        GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    /// 127.0.0.1 tel que `dwLocalAddr` le porte (ordre reseau lu en u32
    /// petit-boutiste: 0x0100007F).
    const V4_BOUCLE: u32 = 0x0100_007F;
    const V4_TOUTES: u32 = 0;

    pub fn verifier(port: u16, attendu: Attendu) -> Proprietaire {
        verifier_avec(port, attendu, demarrage_de)
    }

    /// [`verifier`], avec la lecture de la date de creation en parametre: les
    /// recettes y eprouvent qu'elle est relue APRES la table des ecoutes. La
    /// production passe [`demarrage_de`].
    pub(super) fn verifier_avec(
        port: u16,
        attendu: Attendu,
        lire_demarrage: impl Fn(u32) -> Result<u64, String>,
    ) -> Proprietaire {
        // La date de creation du PID encadre la lecture de la table: lue avant,
        // relue apres. Egale des deux cotes a celle du lancement, le PID que la
        // table nomme est celui de l'enfant.
        let avant = lire_demarrage(attendu.pid);
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
        let apres = lire_demarrage(attendu.pid);
        trancher(&proprietaires, &avant, &apres, attendu)
    }

    /// Le verdict, a partir des PID proprietaires des ecoutes et des deux
    /// lectures de la date de creation du PID attendu. L'identite d'abord: le
    /// PID de la table ne designe l'enfant que si sa date de creation est
    /// celle relevee au lancement (`super::meme_processus`); sinon
    /// `Illisible`, ni `Confirme` ni `Autre`. Pure.
    pub(super) fn trancher(
        proprietaires: &[u32],
        avant: &Result<u64, String>,
        apres: &Result<u64, String>,
        attendu: Attendu,
    ) -> Proprietaire {
        if let Err(details) = super::meme_processus(attendu, avant, apres) {
            return Proprietaire::Illisible { details };
        }
        let pid_attendu = attendu.pid;
        for pid in proprietaires {
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

    /// La date de creation du processus `pid`, en centaines de nanosecondes
    /// depuis 1601 (`FILETIME`), la meme que `lancement` lit pour nommer les
    /// configurations. `PROCESS_QUERY_LIMITED_INFORMATION` suffit.
    pub(super) fn demarrage_de(pid: u32) -> Result<u64, String> {
        // SAFETY: OpenProcess ne lit que ses arguments entiers; la poignee
        // rendue est fermee ci-dessous sur tous les chemins.
        let poignee = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if poignee.is_null() {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(ERROR_INVALID_PARAMETER as i32) {
                return Err(format!("aucun processus {pid}: le processus n'existe plus"));
            }
            return Err(format!("ouverture du processus {pid}: {e}"));
        }
        let vide = || FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let (mut creation, mut fin, mut noyau, mut utilisateur) = (vide(), vide(), vide(), vide());
        // SAFETY: `poignee` est ouverte ci-dessus avec
        // PROCESS_QUERY_LIMITED_INFORMATION; les quatre pointeurs designent des
        // FILETIME locaux et vivants.
        let lu = unsafe {
            GetProcessTimes(
                poignee,
                &mut creation,
                &mut fin,
                &mut noyau,
                &mut utilisateur,
            )
        };
        // L'erreur est prise AVANT CloseHandle, qui la remplacerait.
        let erreur = (lu == 0).then(std::io::Error::last_os_error);
        // SAFETY: `poignee` a ete ouverte ici et n'est plus utilisee apres.
        unsafe { CloseHandle(poignee) };
        match erreur {
            Some(e) => Err(format!("date de creation du processus {pid}: {e}")),
            None => Ok(date_de_filetime(&creation)),
        }
    }

    /// Les deux moities d'un `FILETIME`, poids fort d'abord, en un nombre.
    pub(super) fn date_de_filetime(f: &FILETIME) -> u64 {
        (u64::from(f.dwHighDateTime) << 32) | u64::from(f.dwLowDateTime)
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

        // La date de creation: sa lecture, puis la decision avec une date
        // egale, differente et illisible.

        /// La date que les recettes pures declarent pour `MOI`.
        const DATE: u64 = 133_000_000_000_000_000;

        const MOI: Attendu = Attendu {
            pid: 4242,
            uid: None,
            demarrage: Some(DATE),
        };

        fn egale() -> Result<u64, String> {
            Ok(DATE)
        }
        fn differente() -> Result<u64, String> {
            Ok(DATE + 1)
        }
        fn illisible() -> Result<u64, String> {
            Err("aucun processus 4242: le processus n'existe plus".to_owned())
        }

        /// Le refus attendu quand le PID ne designe plus l'enfant.
        fn illisible_avec(v: Proprietaire, motif: &str) {
            match v {
                Proprietaire::Illisible { details } => {
                    assert!(details.contains(motif), "{details}")
                }
                autre => panic!("attendu Illisible ({motif}), obtenu {autre:?}"),
            }
        }

        #[test]
        fn les_deux_moities_d_un_filetime_font_la_date() {
            let f = FILETIME {
                dwLowDateTime: 0x8765_4321,
                dwHighDateTime: 0x01DC_1234,
            };
            assert_eq!(date_de_filetime(&f), 0x01DC_1234_8765_4321);
        }

        #[test]
        fn la_date_du_lancement_avant_et_apres_confirme() {
            assert_eq!(
                trancher(&[4242], &egale(), &egale(), MOI),
                Proprietaire::Confirme
            );
        }

        #[test]
        fn une_date_de_creation_differente_ne_confirme_rien() {
            illisible_avec(
                trancher(&[4242], &differente(), &egale(), MOI),
                "n'est plus l'enfant lance",
            );
            illisible_avec(trancher(&[4242], &egale(), &differente(), MOI), "lue apres");
        }

        #[test]
        fn une_date_de_creation_illisible_ne_confirme_rien() {
            illisible_avec(
                trancher(&[4242], &illisible(), &egale(), MOI),
                "illisible avant",
            );
            illisible_avec(
                trancher(&[4242], &egale(), &illisible(), MOI),
                "illisible apres",
            );
        }

        /// Une ecoute d'un autre PID n'accuse personne quand le PID attendu
        /// n'est plus l'enfant; elle est etrangere quand il l'est encore.
        #[test]
        fn un_pid_qui_n_est_plus_l_enfant_n_accuse_personne() {
            assert!(matches!(
                trancher(&[4242, 7], &egale(), &egale(), MOI),
                Proprietaire::Autre { .. }
            ));
            illisible_avec(
                trancher(&[4242, 7], &differente(), &differente(), MOI),
                "n'est plus l'enfant lance",
            );
        }

        #[test]
        fn sans_date_relevee_au_lancement_rien_n_est_confirme() {
            let sans_date = Attendu {
                demarrage: None,
                ..MOI
            };
            illisible_avec(
                trancher(&[4242], &egale(), &egale(), sans_date),
                "aucune date de demarrage",
            );
        }

        /// La lecture reelle: la date de ce processus, lue deux fois, est la
        /// meme et n'est pas nulle.
        #[test]
        fn la_date_de_ce_processus_se_lit_et_ne_change_pas() {
            let pid = std::process::id();
            let une = demarrage_de(pid).expect("sa propre date de creation est lisible");
            assert_ne!(une, 0);
            assert_eq!(demarrage_de(pid), Ok(une));
        }

        /// La date est relue APRES la table: une ecoute de CE processus, qui
        /// est ici le processus attendu, et une date fournie qui change entre
        /// ses deux lectures.
        #[test]
        fn la_date_de_creation_est_relue_apres_la_table() {
            let ecoute =
                std::net::TcpListener::bind("127.0.0.1:0").expect("un port libre sur la boucle");
            let port = ecoute.local_addr().unwrap().port();
            let attendu = Attendu {
                pid: std::process::id(),
                uid: None,
                demarrage: Some(DATE),
            };
            let lectures = |dates: [u64; 2]| {
                let rang = std::cell::Cell::new(0usize);
                move |_: u32| {
                    let i = rang.get();
                    rang.set(i + 1);
                    dates
                        .get(i)
                        .copied()
                        .ok_or_else(|| format!("lecture de date numero {i} non prevue"))
                }
            };
            assert_eq!(
                verifier_avec(port, attendu, lectures([DATE, DATE])),
                Proprietaire::Confirme
            );
            illisible_avec(
                verifier_avec(port, attendu, lectures([DATE, DATE + 1])),
                "lue apres",
            );
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
            demarrage: date_de_demarrage(std::process::id()).ok(),
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
            demarrage: moi().demarrage,
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
            demarrage: date_de_demarrage(enfant.id()).ok(),
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

    /// L'identite du processus, commune aux deux plateformes: les deux
    /// lectures de la date doivent etre lisibles et egales a celle du
    /// lancement, et une date jamais relevee ne vaut rien.
    #[cfg(any(target_os = "linux", windows))]
    #[test]
    fn le_meme_processus_exige_la_date_du_lancement_avant_et_apres() {
        let attendu = Attendu {
            pid: 4242,
            uid: None,
            demarrage: Some(10),
        };
        let date = |d: u64| -> Result<u64, String> { Ok(d) };
        let illisible = || -> Result<u64, String> { Err("lecture refusee".to_owned()) };

        assert_eq!(meme_processus(attendu, &date(10), &date(10)), Ok(()));
        for (avant, apres, motif) in [
            (date(11), date(10), "lue avant"),
            (date(10), date(11), "lue apres"),
            (illisible(), date(10), "illisible avant"),
            (date(10), illisible(), "illisible apres"),
        ] {
            let raison = meme_processus(attendu, &avant, &apres)
                .expect_err("une seule lecture qui differe suffit a refuser");
            assert!(raison.contains(motif), "{raison}");
        }
        let sans_date = Attendu {
            demarrage: None,
            ..attendu
        };
        let raison = meme_processus(sans_date, &date(10), &date(10))
            .expect_err("une date jamais relevee ne designe personne");
        assert!(raison.contains("aucune date de demarrage"), "{raison}");
    }
}
