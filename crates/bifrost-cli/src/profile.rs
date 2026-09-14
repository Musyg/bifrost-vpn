//! Lecture d'un profil de tunnel au format TOML.
//!
//! La forme sous laquelle le profil est RANGE, et qui a le droit de l'ouvrir,
//! appartiennent a [`crate::coffre`]. Ici on ne fait qu'interpreter le texte
//! qu'il rend.

use std::path::Path;

use anyhow::bail;
use bifrost_core::TunnelConfig;

use bifrost_coffre as coffre;

/// Charge et valide un profil.
///
/// La validation se fait ici, cote client, pour donner un message utile avant
/// meme d'atteindre le daemon. Le daemon revalide de son cote: il ne fait pas
/// confiance a ce qui arrive par l'IPC.
pub fn load(path: &Path) -> anyhow::Result<TunnelConfig> {
    let ouvert = coffre::ouvrir(path)?;
    // Le nom du fichier qui a REELLEMENT servi, pour que les messages ne
    // designent pas un chemin qu'on n'a pas ouvert.
    let designe = match ouvert.forme {
        coffre::Forme::Scelle => coffre::chemin_scelle(path),
        coffre::Forme::EnClair => path.to_path_buf(),
    };

    let config: TunnelConfig = toml::from_str(&ouvert.contenu)
        .map_err(|e| anyhow::anyhow!("profil {} invalide: {e}", designe.display()))?;
    if let Err(e) = config.validate() {
        bail!("profil {} invalide: {e}", designe.display());
    }
    if !config.is_full_tunnel() {
        eprintln!(
            "avertissement: allowed_ips ne contient pas de route par defaut. \
             Le kill switch bloquera tout ce qui ne passe pas par le tunnel, \
             ce qui n'est probablement pas ce que vous voulez."
        );
    }
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROFIL: &str = r#"
interface = "wg0"
private_key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaA="
addresses = ["10.2.0.2/32"]
mtu = 1420
fwmark = 51820

[peer]
public_key = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbA="
endpoint = { addr = "203.0.113.7:51820" }
allowed_ips = ["0.0.0.0/0", "::/0"]
persistent_keepalive = 25

[dns]
local_resolver = "127.0.0.53"
upstream = ["10.2.0.1"]
"#;

    fn ecrire(contenu: &str) -> tempfile_like::Temp {
        tempfile_like::Temp::new(contenu)
    }

    #[test]
    fn un_profil_complet_se_charge() {
        let f = ecrire(PROFIL);
        let cfg = load(f.path()).unwrap();
        assert_eq!(cfg.interface, "wg0");
        assert_eq!(cfg.portage.wireguard().unwrap().fwmark, 51820);
        assert!(cfg.is_full_tunnel());
        assert_eq!(cfg.dns.upstream.len(), 1);
    }

    #[test]
    fn les_valeurs_par_defaut_s_appliquent() {
        let minimal = r#"
interface = "wg0"
private_key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaA="
addresses = ["10.2.0.2/32"]

[peer]
public_key = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbA="
endpoint = { addr = "203.0.113.7:51820" }
allowed_ips = ["0.0.0.0/0"]

[dns]
local_resolver = "127.0.0.1"
upstream = ["10.2.0.1"]
"#;
        let f = ecrire(minimal);
        let cfg = load(f.path()).unwrap();
        assert_eq!(cfg.mtu, 1420);
        assert_eq!(cfg.portage.wireguard().unwrap().fwmark, 0xca6c);
        assert_eq!(cfg.portage.wireguard().unwrap().routing_table, 51820);
        assert!(!cfg.allow_lan);
    }

    #[test]
    fn un_resolveur_non_loopback_est_refuse_des_le_client() {
        let f = ecrire(&PROFIL.replace("127.0.0.53", "8.8.8.8"));
        let err = load(f.path()).unwrap_err().to_string();
        assert!(err.contains("invalide"), "message inattendu: {err}");
    }

    #[test]
    fn une_cle_malformee_est_refusee() {
        let f =
            ecrire(&PROFIL.replace("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaA=", "trop-court"));
        assert!(load(f.path()).is_err());
    }

    /// Un profil que le groupe peut lire est REFUSE, pas seulement signale.
    ///
    /// La version d'avant se contentait d'un avertissement sur la sortie
    /// d'erreur, au milieu d'une connexion qui reussissait: personne ne change
    /// un mode pour cela, et le fichier porte une cle privee.
    #[cfg(unix)]
    #[test]
    fn un_profil_lisible_par_d_autres_est_refuse() {
        use std::os::unix::fs::PermissionsExt;

        let f = ecrire(PROFIL);
        std::fs::set_permissions(f.path(), std::fs::Permissions::from_mode(0o640)).unwrap();
        let err = load(f.path()).unwrap_err().to_string();
        assert!(err.contains("640"), "le mode fautif doit etre nomme: {err}");
        assert!(
            err.contains("chmod 600"),
            "et la correction doit etre donnee telle quelle: {err}"
        );
        // Le temoin negatif: le meme profil en 0600 se charge.
        std::fs::set_permissions(f.path(), std::fs::Permissions::from_mode(0o600)).unwrap();
        load(f.path()).expect("un profil bien range doit se charger");
    }

    #[test]
    fn un_fichier_absent_donne_un_message_actionnable() {
        let err = load(Path::new("/nexiste/pas/tunnel.toml"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("--config"), "message inattendu: {err}");
    }

    /// Petit utilitaire local: creer un fichier temporaire sans tirer une
    /// dependance de plus pour trois tests.
    mod tempfile_like {
        use std::path::{Path, PathBuf};
        use std::sync::atomic::{AtomicU32, Ordering};

        static COMPTEUR: AtomicU32 = AtomicU32::new(0);

        pub struct Temp(PathBuf);

        impl Temp {
            pub fn new(contenu: &str) -> Self {
                let n = COMPTEUR.fetch_add(1, Ordering::Relaxed);
                let path = std::env::temp_dir().join(format!(
                    "bifrost-profil-test-{}-{n}.toml",
                    std::process::id()
                ));
                std::fs::write(&path, contenu).unwrap();
                // Le coffre refuse un profil que d'autres peuvent lire, et le
                // repertoire temporaire est commun: sans ce mode, ces recettes
                // echoueraient pour la bonne raison, mais pas celle qu'elles
                // mesurent.
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                        .unwrap();
                }
                Self(path)
            }

            pub fn path(&self) -> &Path {
                &self.0
            }
        }

        impl Drop for Temp {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.0);
            }
        }
    }
}
