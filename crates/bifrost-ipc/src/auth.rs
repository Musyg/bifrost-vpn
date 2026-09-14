//! Autorisation du pair qui se connecte a l'IPC.
//!
//! La decision est une fonction pure de l'identite du pair et de la politique,
//! donc testable sans socket. La recuperation de l'identite, elle, est
//! specifique a l'OS: `SO_PEERCRED` sur Linux, DACL du named pipe sur Windows.

use std::fmt;

/// Identite du processus a l'autre bout du canal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerIdentity {
    pub uid: u32,
    pub gid: u32,
    pub pid: Option<i32>,
    /// Groupes supplementaires, lus dans `/proc/<pid>/status`. Vide si
    /// indisponible: l'autorisation retombe alors sur le gid primaire.
    pub supplementary_groups: Vec<u32>,
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
    /// UIDs explicitement autorises. root (uid 0) l'est toujours.
    pub allowed_uids: Vec<u32>,
    /// GID du groupe `bifrost`. Un membre de ce groupe peut piloter le daemon.
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
    #[error("identite du pair indisponible: {0}")]
    Unavailable(String),
}

/// Decide si le pair peut piloter le daemon.
pub fn authorize(peer: &PeerIdentity, policy: &AuthPolicy) -> Result<(), AuthError> {
    if peer.uid == 0 {
        return Ok(());
    }
    if policy.allowed_uids.contains(&peer.uid) {
        return Ok(());
    }
    if let Some(gid) = policy.allowed_gid
        && (peer.gid == gid || peer.supplementary_groups.contains(&gid))
    {
        return Ok(());
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
pub(crate) fn supplementary_groups(pid: i32) -> Vec<u32> {
    let path = format!("/proc/{pid}/status");
    let Ok(content) = std::fs::read_to_string(&path) else {
        return Vec::new();
    };
    content
        .lines()
        .find_map(|l| l.strip_prefix("Groups:"))
        .map(|g| {
            g.split_whitespace()
                .filter_map(|s| s.parse().ok())
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(uid: u32, gid: u32) -> PeerIdentity {
        PeerIdentity {
            uid,
            gid,
            pid: Some(4242),
            supplementary_groups: Vec::new(),
        }
    }

    #[test]
    fn root_est_toujours_autorise() {
        assert!(authorize(&peer(0, 0), &AuthPolicy::default()).is_ok());
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
        assert!(authorize(&peer(1000, 1000), &policy).is_ok());
        assert!(authorize(&peer(1001, 1001), &policy).is_err());
    }

    #[test]
    fn le_groupe_primaire_autorise() {
        let policy = AuthPolicy {
            allowed_uids: vec![0],
            allowed_gid: Some(970),
        };
        assert!(authorize(&peer(1000, 970), &policy).is_ok());
        assert!(authorize(&peer(1000, 971), &policy).is_err());
    }

    #[test]
    fn un_groupe_supplementaire_autorise() {
        let policy = AuthPolicy {
            allowed_uids: vec![0],
            allowed_gid: Some(970),
        };
        let mut p = peer(1000, 1000);
        p.supplementary_groups = vec![4, 27, 970];
        assert!(authorize(&p, &policy).is_ok());

        p.supplementary_groups = vec![4, 27];
        assert!(authorize(&p, &policy).is_err());
    }

    /// Sans groupe configure, appartenir a un groupe quelconque ne suffit pas.
    #[test]
    fn aucun_groupe_configure_signifie_aucun_acces_par_groupe() {
        let policy = AuthPolicy::default();
        let mut p = peer(1000, 1000);
        p.supplementary_groups = vec![0, 970, 4];
        assert!(authorize(&p, &policy).is_err());
    }

    #[test]
    fn le_message_de_refus_ne_revele_pas_la_politique() {
        let err = authorize(&peer(1000, 1000), &AuthPolicy::default()).unwrap_err();
        let msg = err.to_string();
        assert!(!msg.contains("allowed_uids"));
    }
}
