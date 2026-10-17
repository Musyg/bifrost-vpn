//! Autorisation du pair qui se connecte a l'IPC.
//!
//! La decision est une fonction pure de l'identite du pair et de la politique,
//! donc testable sans socket. La recuperation de l'identite, elle, est
//! specifique a l'OS: `SO_PEERCRED` sur Linux, DACL du named pipe sur Windows.
//!
//! Elle rend la RAISON de l'admission ([`Admission`]), et pas seulement un
//! oui: un pair admis par son uid (root, ou un uid de `allowed_uids`) n'a pas
//! le meme canal qu'un pair admis seulement par le groupe `allowed_gid`. La
//! correspondance vers ce qu'il peut demander est dans `crate::appelant`
//! (`niveau_admis`).

use std::fmt;

/// Identite du processus a l'autre bout du canal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerIdentity {
    pub uid: u32,
    pub gid: u32,
    pub pid: Option<i32>,
    /// Groupes supplementaires, lus dans `/proc/<pid>/status`, ou la raison
    /// pour laquelle ils n'ont pas pu l'etre.
    pub supplementary_groups: SupplementaryGroups,
}

/// Les groupes supplementaires d'un pair: lus, ou illisibles.
///
/// Deux variantes et non une liste: une lecture impossible (descripteurs
/// epuises, fichier absent ou malforme) ne doit pas se lire comme "membre
/// d'aucun groupe". [`authorize`] ne la consulte que quand un groupe
/// supplementaire pourrait seul admettre le pair, et refuse alors en nommant
/// la cause.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SupplementaryGroups {
    /// Lus: la liste, vide comprise.
    Known(Vec<u32>),
    /// Non lus, et pourquoi.
    Unreadable(String),
}

impl fmt::Display for PeerIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.pid {
            Some(pid) => write!(f, "uid={} gid={} pid={}", self.uid, self.gid, pid),
            None => write!(f, "uid={} gid={}", self.uid, self.gid),
        }
    }
}

/// Qui a le droit de piloter le daemon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthPolicy {
    /// UIDs explicitement autorises. root (uid 0) l'est toujours. Un pair
    /// admis par son uid a tout le canal.
    pub allowed_uids: Vec<u32>,
    /// GID du groupe `bifrost`. Un membre de ce groupe ouvre le canal, et n'y
    /// a que `status`, `connect-stored` et `disconnect` (`crate::appelant`).
    pub allowed_gid: Option<u32>,
}

impl Default for AuthPolicy {
    /// Par defaut, seul root. Toute ouverture est un choix explicite de
    /// l'administrateur, jamais un defaut herite.
    fn default() -> Self {
        Self {
            allowed_uids: vec![0],
            allowed_gid: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuthError {
    #[error(
        "acces refuse pour {peer}: ni root, ni dans les uid autorises, ni membre du groupe bifrost"
    )]
    Denied { peer: String },
    /// Seul un groupe supplementaire pourrait admettre le pair, et ses groupes
    /// n'ont pas pu etre lus: ce n'est pas un refus d'appartenance. Le message
    /// commence comme celui de `Denied`, que le client reconnait pour un refus
    /// d'acces, et nomme la cause.
    #[error(
        "acces refuse pour {peer}: groupes supplementaires illisibles ({cause}), \
         l'appartenance au groupe bifrost n'a pas pu etre etablie"
    )]
    GroupsUnreadable { peer: String, cause: String },
    #[error("identite du pair indisponible: {0}")]
    Unavailable(String),
}

/// Pourquoi un pair est admis sur le canal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// Par son uid: root, toujours, meme s'il est aussi membre du groupe; ou
    /// un uid de `allowed_uids`.
    ParUid,
    /// Seulement par le groupe `allowed_gid`: son gid primaire, ou l'un de ses
    /// groupes supplementaires.
    ParGroupe,
}

/// Decide si le pair peut ouvrir le canal, et pourquoi.
///
/// L'uid est juge avant le groupe: un pair que son uid admet est
/// [`Admission::ParUid`] quels que soient ses groupes, lus ou non.
pub fn authorize(peer: &PeerIdentity, policy: &AuthPolicy) -> Result<Admission, AuthError> {
    if peer.uid == 0 {
        return Ok(Admission::ParUid);
    }
    if policy.allowed_uids.contains(&peer.uid) {
        return Ok(Admission::ParUid);
    }
    if let Some(gid) = policy.allowed_gid {
        if peer.gid == gid {
            return Ok(Admission::ParGroupe);
        }
        match &peer.supplementary_groups {
            SupplementaryGroups::Known(groupes) => {
                if groupes.contains(&gid) {
                    return Ok(Admission::ParGroupe);
                }
            }
            SupplementaryGroups::Unreadable(cause) => {
                return Err(AuthError::GroupsUnreadable {
                    peer: peer.to_string(),
                    cause: cause.clone(),
                });
            }
        }
    }
    Err(AuthError::Denied {
        peer: peer.to_string(),
    })
}

/// Resout le GID d'un groupe par son nom, en lisant `/etc/group`.
///
/// Passer par `getgrnam` imposerait une dependance a libc pour un besoin qui
/// se resume a lire un fichier texte au format fige depuis quarante ans.
#[cfg(unix)]
pub fn lookup_gid(group: &str) -> Option<u32> {
    let content = std::fs::read_to_string("/etc/group").ok()?;
    for line in content.lines() {
        let mut fields = line.split(':');
        if fields.next()? == group {
            let _passwd = fields.next()?;
            return fields.next()?.parse().ok();
        }
    }
    None
}

#[cfg(unix)]
pub(crate) fn supplementary_groups(pid: i32) -> SupplementaryGroups {
    groups_from_status(std::fs::read_to_string(format!("/proc/{pid}/status")))
}

/// Les groupes supplementaires, tires de la lecture de `/proc/<pid>/status`.
///
/// Une lecture qui echoue, une ligne `Groups:` absente ou un groupe qui ne se
/// lit pas comme un nombre rendent [`SupplementaryGroups::Unreadable`]: aucun
/// de ces cas ne dit que le pair n'a pas de groupe. Seule une ligne `Groups:`
/// vide le dit.
#[cfg(unix)]
pub(crate) fn groups_from_status(status: std::io::Result<String>) -> SupplementaryGroups {
    let content = match status {
        Ok(content) => content,
        Err(e) => return SupplementaryGroups::Unreadable(e.to_string()),
    };
    let Some(ligne) = content.lines().find_map(|l| l.strip_prefix("Groups:")) else {
        return SupplementaryGroups::Unreadable("ligne Groups absente".to_owned());
    };
    match ligne
        .split_whitespace()
        .map(str::parse::<u32>)
        .collect::<Result<Vec<u32>, _>>()
    {
        Ok(groupes) => SupplementaryGroups::Known(groupes),
        Err(_) => SupplementaryGroups::Unreadable("ligne Groups illisible".to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(uid: u32, gid: u32) -> PeerIdentity {
        PeerIdentity {
            uid,
            gid,
            pid: Some(4242),
            supplementary_groups: SupplementaryGroups::Known(Vec::new()),
        }
    }

    /// Le pair `peer(uid, gid)` dont les groupes supplementaires n'ont pas pu
    /// etre lus.
    fn sans_groupes_lus(uid: u32, gid: u32) -> PeerIdentity {
        PeerIdentity {
            supplementary_groups: SupplementaryGroups::Unreadable(
                "Too many open files (os error 24)".to_owned(),
            ),
            ..peer(uid, gid)
        }
    }

    #[test]
    fn root_est_toujours_autorise() {
        assert_eq!(
            authorize(&peer(0, 0), &AuthPolicy::default()),
            Ok(Admission::ParUid)
        );
    }

    /// La table d'admission: la raison rendue pour chaque facon d'etre admis,
    /// et les refus inchanges. root est admis par son uid meme quand son gid
    /// primaire ou un groupe supplementaire est celui de la politique; un uid
    /// autorise aussi; le gid primaire et un groupe supplementaire admettent
    /// par le groupe.
    #[test]
    fn la_table_d_admission_rend_la_raison() {
        let politique = AuthPolicy {
            allowed_uids: vec![0, 1001],
            allowed_gid: Some(970),
        };
        let avec_groupes = |uid: u32, gid: u32, groupes: Vec<u32>| PeerIdentity {
            supplementary_groups: SupplementaryGroups::Known(groupes),
            ..peer(uid, gid)
        };
        for (nom, pair, issue) in [
            ("root", peer(0, 0), Ok(Admission::ParUid)),
            (
                "root au gid primaire du groupe",
                peer(0, 970),
                Ok(Admission::ParUid),
            ),
            (
                "root membre supplementaire du groupe",
                avec_groupes(0, 0, vec![970]),
                Ok(Admission::ParUid),
            ),
            (
                "root, groupes illisibles",
                sans_groupes_lus(0, 970),
                Ok(Admission::ParUid),
            ),
            ("uid autorise", peer(1001, 1001), Ok(Admission::ParUid)),
            (
                "uid autorise et membre du groupe",
                avec_groupes(1001, 970, vec![970]),
                Ok(Admission::ParUid),
            ),
            (
                "uid autorise, groupes illisibles",
                sans_groupes_lus(1001, 1001),
                Ok(Admission::ParUid),
            ),
            ("gid primaire", peer(1000, 970), Ok(Admission::ParGroupe)),
            (
                "gid primaire, groupes illisibles",
                sans_groupes_lus(1000, 970),
                Ok(Admission::ParGroupe),
            ),
            (
                "groupe supplementaire",
                avec_groupes(1000, 1000, vec![4, 27, 970]),
                Ok(Admission::ParGroupe),
            ),
        ] {
            assert_eq!(authorize(&pair, &politique), issue, "{nom}");
        }
        assert_eq!(
            authorize(&avec_groupes(1000, 1000, vec![4, 27]), &politique),
            Err(AuthError::Denied {
                peer: "uid=1000 gid=1000 pid=4242".to_owned()
            }),
            "non membre"
        );
        assert_eq!(
            authorize(&sans_groupes_lus(1000, 1000), &politique),
            Err(AuthError::GroupsUnreadable {
                peer: "uid=1000 gid=1000 pid=4242".to_owned(),
                cause: "Too many open files (os error 24)".to_owned(),
            }),
            "groupes illisibles"
        );
    }

    /// Le test que demande le jalon J2 du document 06: un processus non
    /// privilegie ne doit pas pouvoir piloter le daemon.
    #[test]
    fn un_utilisateur_non_privilegie_est_refuse_par_defaut() {
        let err = authorize(&peer(1000, 1000), &AuthPolicy::default()).unwrap_err();
        assert!(matches!(err, AuthError::Denied { .. }));
        assert!(err.to_string().contains("uid=1000"));
    }

    #[test]
    fn un_uid_explicitement_autorise_passe() {
        let policy = AuthPolicy {
            allowed_uids: vec![0, 1000],
            allowed_gid: None,
        };
        assert_eq!(authorize(&peer(1000, 1000), &policy), Ok(Admission::ParUid));
        assert!(authorize(&peer(1001, 1001), &policy).is_err());
    }

    #[test]
    fn le_groupe_primaire_autorise() {
        let policy = AuthPolicy {
            allowed_uids: vec![0],
            allowed_gid: Some(970),
        };
        assert_eq!(
            authorize(&peer(1000, 970), &policy),
            Ok(Admission::ParGroupe)
        );
        assert!(authorize(&peer(1000, 971), &policy).is_err());
    }

    #[test]
    fn un_groupe_supplementaire_autorise() {
        let policy = AuthPolicy {
            allowed_uids: vec![0],
            allowed_gid: Some(970),
        };
        let mut p = peer(1000, 1000);
        p.supplementary_groups = SupplementaryGroups::Known(vec![4, 27, 970]);
        assert_eq!(authorize(&p, &policy), Ok(Admission::ParGroupe));

        p.supplementary_groups = SupplementaryGroups::Known(vec![4, 27]);
        assert!(authorize(&p, &policy).is_err());
    }

    /// Sans groupe configure, appartenir a un groupe quelconque ne suffit pas.
    #[test]
    fn aucun_groupe_configure_signifie_aucun_acces_par_groupe() {
        let policy = AuthPolicy::default();
        let mut p = peer(1000, 1000);
        p.supplementary_groups = SupplementaryGroups::Known(vec![0, 970, 4]);
        assert!(authorize(&p, &policy).is_err());
    }

    #[test]
    fn le_message_de_refus_ne_revele_pas_la_politique() {
        let err = authorize(&peer(1000, 1000), &AuthPolicy::default()).unwrap_err();
        let msg = err.to_string();
        assert!(!msg.contains("allowed_uids"));
    }

    /// Des groupes illisibles ne decident que la ou un groupe supplementaire
    /// le pourrait seul: root, un uid autorise et le gid primaire passent
    /// toujours; sans groupe configure, le refus reste celui d'un pair non
    /// autorise.
    #[test]
    fn des_groupes_illisibles_ne_decident_que_la_ou_ils_comptent() {
        let par_groupe = AuthPolicy {
            allowed_uids: vec![0, 1001],
            allowed_gid: Some(970),
        };
        assert_eq!(
            authorize(&sans_groupes_lus(0, 0), &par_groupe),
            Ok(Admission::ParUid)
        );
        assert_eq!(
            authorize(&sans_groupes_lus(1001, 1001), &par_groupe),
            Ok(Admission::ParUid)
        );
        assert_eq!(
            authorize(&sans_groupes_lus(1000, 970), &par_groupe),
            Ok(Admission::ParGroupe)
        );
        assert!(matches!(
            authorize(&sans_groupes_lus(1000, 1000), &AuthPolicy::default()),
            Err(AuthError::Denied { .. })
        ));
    }

    /// Seul un groupe supplementaire pourrait admettre le pair, et ils sont
    /// illisibles: refus, qui n'est pas celui d'un non-membre et nomme la
    /// cause, sans rien dire de la politique.
    #[test]
    fn des_groupes_illisibles_ne_valent_pas_aucun_groupe() {
        let policy = AuthPolicy {
            allowed_uids: vec![0],
            allowed_gid: Some(970),
        };
        let err = authorize(&sans_groupes_lus(1000, 1000), &policy).unwrap_err();
        assert!(matches!(err, AuthError::GroupsUnreadable { .. }), "{err:?}");
        let msg = err.to_string();
        assert!(msg.starts_with("acces refuse pour uid=1000"), "{msg}");
        assert!(msg.contains("groupes supplementaires illisibles"), "{msg}");
        assert!(msg.contains("Too many open files (os error 24)"), "{msg}");
        assert!(!msg.contains("ni membre"), "{msg}");
        assert!(
            !msg.contains("allowed_uids") && !msg.contains("970"),
            "{msg}"
        );
        // Lus et vides, ils disent bien "aucun groupe".
        assert!(matches!(
            authorize(&peer(1000, 1000), &policy),
            Err(AuthError::Denied { .. })
        ));
    }

    /// La ligne `Groups:` lue telle que le noyau l'ecrit, vide comprise; tout
    /// le reste est illisible, jamais vide.
    #[cfg(unix)]
    #[test]
    fn la_lecture_des_groupes_ne_rend_vide_que_sur_une_ligne_vide() {
        let status = |groupes: &str| {
            Ok(format!(
                "Name:\tx\nGid:\t1000\t1000\t1000\t1000\nGroups:{groupes}\nNgid:\t0\n"
            ))
        };
        assert_eq!(
            groups_from_status(status("\t4 27 970 ")),
            SupplementaryGroups::Known(vec![4, 27, 970])
        );
        assert_eq!(
            groups_from_status(status("\t")),
            SupplementaryGroups::Known(Vec::new())
        );
        assert_eq!(
            groups_from_status(Err(std::io::Error::from_raw_os_error(libc::EMFILE))),
            SupplementaryGroups::Unreadable(
                std::io::Error::from_raw_os_error(libc::EMFILE).to_string()
            )
        );
        assert_eq!(
            groups_from_status(Ok("Name:\tx\nNgid:\t0\n".to_owned())),
            SupplementaryGroups::Unreadable("ligne Groups absente".to_owned())
        );
        assert_eq!(
            groups_from_status(status("\t4 x 970")),
            SupplementaryGroups::Unreadable("ligne Groups illisible".to_owned())
        );
    }

    /// Sur ce processus: ses groupes se lisent, et ce sont ceux du noyau.
    #[cfg(unix)]
    #[test]
    fn les_groupes_de_ce_processus_se_lisent() {
        // SAFETY: getpid ne prend aucun argument et ne touche aucune memoire.
        let pid = unsafe { libc::getpid() };
        // SAFETY: getgroups(0, NULL) ne lit ni n'ecrit aucune memoire et rend
        // le nombre de groupes supplementaires.
        let n = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
        assert!(n >= 0, "getgroups: {}", std::io::Error::last_os_error());
        let mut noyau = vec![libc::gid_t::default(); n as usize];
        // SAFETY: le tampon a la place de `n` groupes, la taille passee.
        let lus = unsafe { libc::getgroups(n, noyau.as_mut_ptr()) };
        assert_eq!(lus, n, "getgroups: {}", std::io::Error::last_os_error());
        noyau.sort_unstable();
        match supplementary_groups(pid) {
            SupplementaryGroups::Known(mut groupes) => {
                groupes.sort_unstable();
                assert_eq!(groupes, noyau);
            }
            autre => panic!("groupes de ce processus illisibles: {autre:?}"),
        }
    }
}
