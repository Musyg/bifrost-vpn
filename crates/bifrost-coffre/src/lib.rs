//! Le profil au repos: qui peut le lire, et sous quelle forme.
//!
//! Un profil porte des secrets d'authentification - une cle privee WireGuard,
//! ou l'UUID et le mot de passe d'un profil de coeur. Ce module decide comment
//! il est range sur le disque et refuse de l'ouvrir quand il ne l'est pas
//! correctement.
//!
//! # Ce que le plan disait, et pourquoi ce n'est pas ce qui est ecrit ici
//!
//! Le document 04 partie 407 et le document 06 partie 137 nomment le keystore
//! du systeme: DPAPI sous Windows, **libsecret/Secret Service** sous Linux.
//! Cette seconde moitie ne tient pas pour ce produit, et pour une raison
//! mecanique: le Secret Service se joint par le bus de SESSION. Un daemon
//! systeme n'en a pas, et un `bifrost` lance par `sudo` non plus - `sudo`
//! nettoie `DBUS_SESSION_BUS_ADDRESS`. L'unite de ce depot va plus loin et
//! interdit deja les appels systeme du trousseau: `SystemCallFilter=~@keyring`.
//!
//! # Ce que fait l'etat de l'art, verifie le 19 aout 2026
//!
//! La reference du domaine est WireGuard lui-meme, et elle est asymetrique.
//! Sous Windows il CHIFFRE ses configurations avec DPAPI, dans
//! `C:\Program Files\WireGuard\Data`. Sous Linux, `wg-quick` s'en remet aux
//! droits du fichier - `/etc/wireguard/wg0.conf` en 0600 - et sa page de manuel
//! nomme deux voies pour aller plus loin: `pass(1)`, et **systemd-creds**.
//!
//! C'est cette derniere qui est retenue ici. Le chiffrement est AES256-GCM, et
//! la cle maitresse est par defaut PARTAGEE entre la puce TPM2 et un fichier de
//! `/var/`: il faut les deux pour dechiffrer. Le nom du credential est
//! authentifie, donc un ciphertext ne peut pas etre glisse dans un autre
//! creneau - mesure sur essai-linux: `systemd-creds` refuse en disant que le nom
//! embarque ne correspond pas.
//!
//! Le fichier scelle sort en 0644, et ce n'est pas un oubli: c'est du
//! ciphertext, et la documentation de systemd le dit explicitement - un
//! credential chiffre peut figurer dans une unite lisible par tout le monde
//! sans que cela le compromette. Ce sont les droits du CLAIR qui comptent, et
//! ce module les exige.
//!
//! # Ce que cela protege, et ce que cela ne protege pas
//!
//! La frontiere est celle que Tailscale trace pour son propre chiffrement
//! d'etat, et elle est plus utile que le raccourci "root peut tout": cela
//! protege contre qui peut LIRE des fichiers, meme en root, sans executer de
//! code - le vol du disque, la recopie sur une autre machine, un voleur
//! d'informations qui ramasse des fichiers. Cela ne protege pas contre qui peut
//! EXECUTER du code en root, qui n'a qu'a appeler `systemd-creds` comme nous, ni
//! contre qui lit la memoire du processus. La limite est la meme sous Windows,
//! ou qui peut executer du code en SYSTEM appelle DPAPI comme nous.
//! `systemd-creds` la rappelle d'ailleurs lui-meme quand `/var/` n'est pas sur
//! un support chiffre, et ce message est laisse visible.
//!
//! # Ce qu'il en coute, et que personne ne dit
//!
//! La cle est liee a CETTE machine. Une reinitialisation du TPM, un changement
//! de carte mere, une reinstallation qui refait
//! `/var/lib/systemd/credential.secret`: le profil scelle devient illisible,
//! definitivement. Le billet de Tailscale sur le meme mecanisme n'aborde ni la
//! reinitialisation du TPM ni la migration de machine, et le sujet merite mieux
//! que le silence quand le fichier peut etre l'unique copie d'une cle privee.
//! [`sceller`] le dit donc a haute voix.
//!
//! # Ce qui n'est pas fait ici, et pourquoi
//!
//! Le dechiffrement exige le TPM, donc root: un simple membre du groupe
//! `bifrost` ne peut pas ouvrir un profil scelle - mesure, le TPM rend
//! `Permission denied`. La suite naturelle est donc que le DAEMON detienne le
//! profil, par `LoadCredentialEncrypted=` dans son unite, qui le lui presente
//! dechiffre et en lecture seule dans `$CREDENTIALS_DIRECTORY`. Cela demande
//! trois choses que ce lot ne fait pas: que le daemon lise des profils, un
//! verbe d'IPC pour les demander sans les porter, et une entree dans l'unite.
//!
//! Sous Windows, la meme chose passe par DPAPI - dans le contexte du compte qui
//! appelle, et NON en portee machine comme le plan le demandait, parce que la
//! portee machine laisserait n'importe quel compte de la machine rouvrir le
//! profil. Le detail de cette correction est en tete du module `dpapi`.

#[cfg(windows)]
mod acl;
#[cfg(windows)]
mod dpapi;
pub mod signature;
#[cfg(windows)]
mod texte;

use std::path::{Path, PathBuf};

use anyhow::{Context, bail};

/// Ou vit le profil, faute d'indication contraire.
///
/// Ici et non dans le client ou dans le daemon: les deux doivent designer le
/// MEME fichier, et un defaut recopie a deux endroits finit toujours par
/// diverger. Seule change la question de savoir qui l'ouvre.
#[cfg(unix)]
pub const CHEMIN_PAR_DEFAUT: &str = "/etc/bifrost/tunnel.toml";
#[cfg(windows)]
pub const CHEMIN_PAR_DEFAUT: &str = r"C:\ProgramData\Bifrost\tunnel.toml";

/// Le nom sous lequel un profil est scelle.
///
/// Authentifie au scellement et verifie au dechiffrement - par `systemd-creds`
/// sous Linux, par la description DPAPI sous Windows: c'est ce qui empeche de
/// presenter le ciphertext d'autre chose a la place de celui-ci.
pub const NOM_CREDENTIAL: &str = "bifrost.tunnel";

/// L'extension d'un profil scelle.
pub const EXTENSION_SCELLEE: &str = "cred";

/// Le chemin du profil scelle correspondant a un profil en clair.
///
/// Une extension AJOUTEE et non remplacee: `tunnel.toml` donne
/// `tunnel.toml.cred`. Remplacer donnerait `tunnel.cred`, qui perdrait la trace
/// du format une fois dechiffre.
pub fn chemin_scelle(clair: &Path) -> PathBuf {
    let mut nom = clair.as_os_str().to_owned();
    nom.push(".");
    nom.push(EXTENSION_SCELLEE);
    PathBuf::from(nom)
}

/// Sous quelle forme un profil a ete trouve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Forme {
    /// Scelle: par `systemd-creds` sous Linux, par DPAPI sous Windows.
    Scelle,
    /// En clair, protege par les seuls droits du fichier.
    EnClair,
}

/// Le contenu d'un profil, et la forme sous laquelle il etait range.
pub struct Ouvert {
    pub contenu: String,
    pub forme: Forme,
}

/// Ecrit a la main, et jamais derive: `contenu` EST le secret - une cle privee
/// WireGuard, ou l'UUID et le mot de passe d'un profil de coeur. Un `derive`
/// le deverserait dans le premier message d'erreur qui encadre un `Ouvert`,
/// c'est-a-dire dans le journal. Le depot applique deja cette regle a `WgKey`,
/// `Uuid` et `MotDePasse`; elle vaut autant ici, ou le secret n'est meme plus
/// enveloppe dans un type qui le protege.
impl std::fmt::Debug for Ouvert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ouvert")
            .field("contenu", &"<expurge>")
            .field("octets", &self.contenu.len())
            .field("forme", &self.forme)
            .finish()
    }
}

/// Ouvre un profil, scelle de preference.
///
/// Le scelle l'emporte quand les deux existent, et la coexistence est SIGNALEE:
/// un profil en clair qui traine a cote du scelle reste parfaitement lisible,
/// et le fait qu'il soit ignore ne le rend pas moins dangereux. Le supprimer
/// d'office serait pire - c'est la seule copie d'une cle privee, et rien ici ne
/// justifie de detruire un fichier que l'utilisateur n'a pas designe.
pub fn ouvrir(clair: &Path) -> anyhow::Result<Ouvert> {
    // Avant tout le reste, et pour les deux formes: un profil scelle qu'on
    // peut REMPLACER est aussi dangereux qu'un clair qu'on peut remplacer. Le
    // chiffrement protege le contenu, pas le choix du fichier.
    exiger_repertoire_sur(clair)?;

    let scelle = chemin_scelle(clair);
    if scelle.is_file() {
        if clair.is_file() {
            eprintln!(
                "avertissement: {} et {} coexistent. Le profil scelle est utilise, \
                 mais le profil en clair reste lisible: le supprimer.",
                scelle.display(),
                clair.display()
            );
        }
        return Ok(Ouvert {
            contenu: desceller(&scelle)?,
            forme: Forme::Scelle,
        });
    }

    // Les droits AVANT la lecture. Les verifier apres reviendrait a se plaindre
    // d'un fichier qu'on vient d'ouvrir quand meme.
    exiger_droits_stricts(clair)?;
    let contenu = std::fs::read_to_string(clair).with_context(|| {
        format!(
            "impossible de lire {}. Creer le profil ou passer --config",
            clair.display()
        )
    })?;
    Ok(Ouvert {
        contenu,
        forme: Forme::EnClair,
    })
}

/// Le repertoire qui contient un profil ne doit etre modifiable que par son
/// proprietaire.
///
/// Une propriete d'INTEGRITE, distincte de celle du fichier, et qui manque a
/// qui ne regarde que le mode du profil: un profil parfaitement en 0600 dans un
/// repertoire ou n'importe qui ecrit peut etre REMPLACE. Le remplacant designe
/// le serveur de son choix, et le tunnel monte vers lui sans que rien ne le
/// signale - c'est une redirection complete du trafic, obtenue sans jamais lire
/// le moindre secret.
///
/// C'est exactement ce que protege le `0700` de `/etc/mullvad-vpn`, et c'est
/// pourquoi la verification porte ici sur l'ECRITURE et non sur la lecture: un
/// repertoire lisible ne divulgue que des noms de fichiers.
#[cfg(unix)]
pub(crate) fn exiger_repertoire_sur(chemin: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    // Un chemin relatif sans parent designe le repertoire courant.
    let parent = match chemin.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let Ok(meta) = std::fs::metadata(&parent) else {
        // Le repertoire est illisible ou absent: la lecture du profil dira
        // laquelle des deux, avec un message plus utile que celui-ci.
        return Ok(());
    };
    let mode = meta.permissions().mode() & 0o777;
    // Le sticky bit change tout: dans un repertoire collant, seul le
    // proprietaire d'un fichier peut le retirer, donc `/tmp` en 1777 ne permet
    // pas de remplacer le profil de quelqu'un d'autre. L'ignorer refuserait le
    // repertoire temporaire, ou vivent les recettes.
    let collant = meta.permissions().mode() & 0o1000 != 0;
    if mode & 0o022 != 0 && !collant {
        bail!(
            "{} est en {mode:o}: d'autres peuvent y remplacer le profil, donc choisir \
             le serveur vers lequel le tunnel monte. Le corriger:\n    chmod 700 {}",
            parent.display(),
            parent.display()
        );
    }
    Ok(())
}

/// Sous Windows, la meme propriete se lit sur le PROPRIETAIRE du repertoire.
///
/// Le mecanisme differe - il n'y a pas de mode octal - mais l'attaque est la
/// meme, et elle etait ouverte: voir la mesure en tete du module `acl`.
#[cfg(windows)]
pub(crate) fn exiger_repertoire_sur(chemin: &Path) -> anyhow::Result<()> {
    let parent = match chemin.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    acl::exiger_proprietaire_sur(&parent, "le repertoire")
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn exiger_repertoire_sur(_chemin: &Path) -> anyhow::Result<()> {
    Ok(())
}

/// Un profil en clair ne doit etre lisible que par son proprietaire.
///
/// Un REFUS, et non l'avertissement d'avant. Un avertissement sur la sortie
/// d'erreur au milieu d'une connexion qui reussit ne change le mode de personne,
/// et le fichier porte une cle privee. Le groupe est refuse au meme titre que
/// le monde: un profil lisible par le groupe `bifrost` donne la cle privee a
/// tous ceux qui ont le droit de PILOTER le daemon, ce qui n'est pas la meme
/// chose que d'avoir le droit de la lire.
#[cfg(unix)]
fn exiger_droits_stricts(chemin: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let meta = std::fs::metadata(chemin).with_context(|| {
        format!(
            "impossible de lire {}. Creer le profil ou passer --config",
            chemin.display()
        )
    })?;
    let mode = meta.permissions().mode() & 0o777;
    if let Some(raison) = trop_ouvert(mode) {
        bail!(
            "{} est en {mode:o} et porte des secrets ({raison}). Le corriger:\n    \
             chmod 600 {}\n\
             Ou le sceller, pour qu'il ne soit plus lisible du tout:\n    \
             bifrost profil sceller",
            chemin.display(),
            chemin.display()
        );
    }
    Ok(())
}

/// Sous Windows, ce qui est verifie est a QUI est le profil, et non qui peut le
/// lire.
///
/// Un profil en clair range dans `C:\ProgramData\Bifrost` est lisible par tous
/// les comptes de la machine, par une ACE `Users` heritee de `C:\ProgramData`.
/// Ce n'est pas rattrape ici, et le refuser serait refuser toute installation
/// par defaut: la reponse est de le SCELLER, ce que [`ouvrir`] conseille deja et
/// que ce module sait desormais faire des deux cotes.
///
/// Ce qui est refuse, en revanche, est un profil qui appartient a un tiers. Sans
/// ce controle, dans un repertoire ou `Users` peut ajouter des fichiers, le
/// premier a creer `tunnel.toml` designe le serveur - meme quand le repertoire,
/// lui, est irreprochable.
#[cfg(windows)]
fn exiger_droits_stricts(chemin: &Path) -> anyhow::Result<()> {
    acl::exiger_proprietaire_sur(chemin, "le profil")
}

#[cfg(not(any(unix, windows)))]
fn exiger_droits_stricts(_chemin: &Path) -> anyhow::Result<()> {
    Ok(())
}

/// Pourquoi ce mode est trop ouvert, ou `None`.
///
/// Pure et separee: c'est une regle, elle se teste sans toucher au disque, et
/// elle se lit sur les deux plateformes meme si elle n'y sert pas. D'ou l'`allow`
/// hors Unix: la regle reste compilee et eprouvee la ou aucun mode ne l'appelle,
/// plutot que d'exister en deux versions dont une seule serait relue.
#[cfg_attr(not(unix), allow(dead_code))]
pub fn trop_ouvert(mode: u32) -> Option<&'static str> {
    match (mode & 0o070 != 0, mode & 0o007 != 0) {
        (_, true) => Some("tout le monde y a acces"),
        (true, false) => Some("son groupe y a acces"),
        (false, false) => None,
    }
}

/// Scelle un profil en clair et rend le chemin du scelle.
///
/// Ne supprime PAS le clair: voir [`ouvrir`] pour la raison. L'appelant en est
/// averti et le supprime lui-meme.
pub fn sceller(clair: &Path) -> anyhow::Result<PathBuf> {
    let sortie = chemin_scelle(clair);
    if sortie.exists() {
        bail!(
            "{} existe deja. Le supprimer d'abord si l'intention est de le remplacer",
            sortie.display()
        );
    }
    // Un profil illisible ou trop ouvert ne se scelle pas non plus: le sceller
    // graverait dans le coffre un fichier que n'importe qui a pu modifier.
    exiger_droits_stricts(clair)?;

    sceller_ici(clair, &sortie).with_context(|| format!("scellement de {}", clair.display()))?;

    // Dit ICI, au moment ou la decision est prise, et pas dans une page de
    // documentation que personne ne relit avant de supprimer le clair.
    eprintln!(
        "ATTENTION: {A_QUI_APPARTIENT_LA_CLE}.\n\
         {CE_QUI_LA_DETRUIT} rendent {} illisible, definitivement.\n\
         Garder une copie du profil hors de cette machine avant de supprimer le clair.",
        sortie.display()
    );
    Ok(sortie)
}

/// Descelle un profil et rend son contenu.
fn desceller(scelle: &Path) -> anyhow::Result<String> {
    // La sortie est le SECRET: elle ne passe ni par un fichier temporaire ni par
    // le journal, seulement par la memoire de ce processus.
    let brut =
        desceller_ici(scelle).with_context(|| format!("ouverture de {}", scelle.display()))?;
    String::from_utf8(brut)
        .with_context(|| format!("{} descelle n'est pas du texte", scelle.display()))
}

/// A qui la cle du coffre appartient, pour le dire dans l'avertissement.
///
/// Deux mecanismes differents, une meme consequence: le fichier scelle ne se
/// rouvre que la ou il a ete scelle, et rien ne le rattrape.
#[cfg(target_os = "linux")]
const A_QUI_APPARTIENT_LA_CLE: &str =
    "la cle du coffre est dans le TPM de CETTE machine et dans un fichier de /var/";
#[cfg(windows)]
const A_QUI_APPARTIENT_LA_CLE: &str =
    "la cle du coffre appartient a CETTE machine et au COMPTE qui a scelle";
#[cfg(not(any(target_os = "linux", windows)))]
const A_QUI_APPARTIENT_LA_CLE: &str = "la cle du coffre appartient a CETTE machine";

/// Ce qui la detruit, et que personne ne dit avant qu'il soit trop tard.
///
/// Sous Windows, la reinitialisation du mot de passe par un administrateur est
/// dans la liste parce que Microsoft la documente comme telle: les donnees
/// protegees ne se dechiffrent plus avec la cle derivee du nouveau mot de passe.
/// Un domaine garde des cles de secours sur ses controleurs; une machine
/// autonome - le cas d'un poste client VPN - n'en a aucune.
#[cfg(target_os = "linux")]
const CE_QUI_LA_DETRUIT: &str =
    "Une reinitialisation du TPM, un changement de carte mere ou une reinstallation";
#[cfg(windows)]
const CE_QUI_LA_DETRUIT: &str = "Une reinstallation, un changement de machine, ou la \n\
     reinitialisation du mot de passe de ce compte par un administrateur,";
#[cfg(not(any(target_os = "linux", windows)))]
const CE_QUI_LA_DETRUIT: &str = "Une reinstallation ou un changement de machine";

/// Scelle, avec ce que la plateforme offre.
#[cfg(target_os = "linux")]
fn sceller_ici(clair: &Path, sortie: &Path) -> anyhow::Result<()> {
    lancer(
        &["encrypt", &format!("--name={NOM_CREDENTIAL}")],
        &[clair, sortie],
    )?;
    Ok(())
}

/// Scelle par DPAPI, dans le contexte du compte qui appelle.
///
/// Donc de SYSTEM quand c'est le daemon, ce qui rend la regle identique a celle
/// de Linux: seul le compte privilegie rouvre le coffre. Le detail du choix -
/// et pourquoi la portee machine que le plan demandait serait un recul - est
/// dans `dpapi.rs`.
#[cfg(windows)]
fn sceller_ici(clair: &Path, sortie: &Path) -> anyhow::Result<()> {
    let contenu =
        std::fs::read(clair).with_context(|| format!("lecture de {}", clair.display()))?;
    let chiffre = dpapi::chiffrer(&contenu, NOM_CREDENTIAL)?;
    std::fs::write(sortie, chiffre).with_context(|| format!("ecriture de {}", sortie.display()))?;
    Ok(())
}

#[cfg(not(any(target_os = "linux", windows)))]
fn sceller_ici(_clair: &Path, _sortie: &Path) -> anyhow::Result<()> {
    bail!("{}", SANS_COFFRE)
}

#[cfg(target_os = "linux")]
fn desceller_ici(scelle: &Path) -> anyhow::Result<Vec<u8>> {
    lancer(
        &["decrypt", &format!("--name={NOM_CREDENTIAL}")],
        &[scelle, Path::new("-")],
    )
}

#[cfg(windows)]
fn desceller_ici(scelle: &Path) -> anyhow::Result<Vec<u8>> {
    let chiffre =
        std::fs::read(scelle).with_context(|| format!("lecture de {}", scelle.display()))?;
    dpapi::dechiffrer(&chiffre, NOM_CREDENTIAL)
}

#[cfg(not(any(target_os = "linux", windows)))]
fn desceller_ici(_scelle: &Path) -> anyhow::Result<Vec<u8>> {
    bail!("{}", SANS_COFFRE)
}

#[cfg(not(any(target_os = "linux", windows)))]
const SANS_COFFRE: &str = "le scellement des profils demande systemd-creds sous Linux ou \
     DPAPI sous Windows, et cette plateforme n'a ni l'un ni l'autre: garder le \
     profil en clair et le proteger par les droits de son repertoire";

/// Appelle `systemd-creds` et rend sa sortie standard.
///
/// La sortie d'erreur est LAISSEE visible: `systemd-creds` y previent quand
/// `/var/` n'est pas sur un support chiffre, et cet avertissement dit
/// exactement contre quoi le scellement protege ou non.
#[cfg(target_os = "linux")]
fn lancer(verbe: &[&str], chemins: &[&Path]) -> anyhow::Result<Vec<u8>> {
    let mut commande = std::process::Command::new("systemd-creds");
    commande.args(verbe).args(chemins);
    let sortie = commande.output().with_context(|| {
        "systemd-creds est introuvable. Il vient de systemd 250 ou plus recent, \
         et c'est lui qui detient la cle du coffre"
    })?;
    if !sortie.status.success() {
        let dit = String::from_utf8_lossy(&sortie.stderr);
        let dit = dit.trim();
        // Le cas le plus frequent, et le plus deroutant si on ne le nomme pas:
        // le TPM n'est lisible que par root.
        let indice = if dit.contains("Permission denied") {
            "\nLa cle du coffre est dans le TPM, qui n'est lisible que par root."
        } else {
            ""
        };
        bail!("systemd-creds a refuse: {dit}{indice}");
    }
    Ok(sortie.stdout)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Le vrai `systemd-creds`, sur la vraie machine.
    ///
    /// Dans le module plutot que dans `tests/`, et pour une raison mecanique:
    /// `bifrost-cli` n'a pas de cible bibliotheque, donc une recette
    /// d'integration ne pourrait pas appeler ces fonctions. Le depot fait deja
    /// ainsi pour le `nft` reel.
    #[cfg(target_os = "linux")]
    mod reel {
        use super::*;

        /// L'UID effectif, lu sans dependance: le TPM n'est lisible que par
        /// root, et une recette qui l'ignorerait echouerait pour une raison
        /// sans rapport avec ce qu'elle mesure.
        fn est_root() -> bool {
            std::fs::read_to_string("/proc/self/status")
                .unwrap_or_default()
                .lines()
                .find_map(|l| l.strip_prefix("Uid:"))
                .and_then(|l| l.split_whitespace().nth(1).map(str::to_owned))
                .as_deref()
                == Some("0")
        }

        fn systemd_creds_present() -> bool {
            std::process::Command::new("systemd-creds")
                .arg("--version")
                .output()
                .is_ok()
        }

        /// Pourquoi cette recette ne peut pas tourner ici, ou `None`.
        fn raison_de_sauter() -> Option<&'static str> {
            if !systemd_creds_present() {
                return Some("systemd-creds absent: il vient de systemd 250 ou plus recent");
            }
            if !est_root() {
                return Some("la cle du coffre est dans le TPM, qui n'est lisible que par root");
            }
            None
        }

        /// Un repertoire a nous, en 0700: le repertoire temporaire est commun,
        /// et le coffre a precisement le droit d'y voir un profil trop ouvert.
        fn repertoire(nom: &str) -> PathBuf {
            use std::os::unix::fs::PermissionsExt;

            let p =
                std::env::temp_dir().join(format!("bifrost-coffre-{}-{nom}", std::process::id()));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
            p
        }

        fn ecrire_profil(rep: &Path, contenu: &str) -> PathBuf {
            use std::os::unix::fs::PermissionsExt;

            let f = rep.join("tunnel.toml");
            std::fs::write(&f, contenu).unwrap();
            std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600)).unwrap();
            f
        }

        /// Un secret reconnaissable a l'oeil dans un vidage d'octets.
        const SECRET: &str = "MOT-DE-PASSE-QUI-NE-DOIT-PAS-APPARAITRE";

        /// L'aller-retour, et la propriete qui compte vraiment: le chiffre ne
        /// dit rien.
        ///
        /// Verifier seulement que l'aller-retour rend le meme texte passerait
        /// aussi pour une implementation qui recopierait le fichier.
        #[test]
        fn un_profil_scelle_se_rouvre_et_son_chiffre_ne_dit_rien() {
            if let Some(raison) = raison_de_sauter() {
                println!("SKIPPED: {raison}");
                return;
            }
            let rep = repertoire("aller-retour");
            let contenu = format!("mot_de_passe = \"{SECRET}\"\n");
            let clair = ecrire_profil(&rep, &contenu);

            let scelle = sceller(&clair).expect("le scellement doit reussir");
            assert_eq!(scelle, chemin_scelle(&clair));

            let chiffre = std::fs::read(&scelle).expect("le scelle doit etre lisible");
            assert!(
                !chiffre
                    .windows(SECRET.len())
                    .any(|f| f == SECRET.as_bytes()),
                "le secret apparait en clair dans {}",
                scelle.display()
            );

            // Le clair est retire: le coffre doit se suffire a lui-meme.
            std::fs::remove_file(&clair).unwrap();
            let ouvert = ouvrir(&clair).expect("un profil scelle doit s'ouvrir sans le clair");
            assert_eq!(ouvert.forme, Forme::Scelle);
            assert_eq!(ouvert.contenu, contenu, "l'aller-retour doit etre fidele");

            let _ = std::fs::remove_dir_all(&rep);
        }

        /// Le scelle l'emporte, et un ciphertext d'un AUTRE nom est refuse.
        ///
        /// Cette seconde moitie est la propriete d'integrite que `systemd-creds`
        /// apporte et qu'un simple chiffrement n'aurait pas: le nom du
        /// credential est authentifie, donc un ciphertext ne peut pas etre
        /// glisse dans le creneau du profil.
        #[test]
        fn le_scelle_l_emporte_et_un_chiffre_etranger_est_refuse() {
            if let Some(raison) = raison_de_sauter() {
                println!("SKIPPED: {raison}");
                return;
            }
            let rep = repertoire("priorite");
            let clair = ecrire_profil(&rep, "mot_de_passe = \"celui-du-clair\"\n");
            sceller(&clair).expect("le scellement doit reussir");
            // Le clair change APRES le scellement: si c'est lui qu'on lit, la
            // recette le verra.
            std::fs::write(&clair, "mot_de_passe = \"celui-du-clair-modifie\"\n").unwrap();

            let ouvert = ouvrir(&clair).expect("le scelle doit s'ouvrir");
            assert_eq!(ouvert.forme, Forme::Scelle);
            assert!(
                ouvert.contenu.contains("celui-du-clair\""),
                "c'est le scelle qui doit servir, pas le clair: {}",
                ouvert.contenu
            );

            // Un ciphertext scelle sous un autre nom, glisse a la place.
            let etranger = rep.join("etranger.cred");
            let sortie = std::process::Command::new("systemd-creds")
                .args(["encrypt", "--name=autre.chose", "-"])
                .arg(&etranger)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .spawn()
                .and_then(|mut e| {
                    use std::io::Write;
                    e.stdin.as_mut().unwrap().write_all(b"contenu etranger")?;
                    e.wait()
                })
                .expect("le scellement etranger doit s'executer");
            assert!(sortie.success(), "le scellement etranger a echoue");
            std::fs::copy(&etranger, chemin_scelle(&clair)).unwrap();

            let e = ouvrir(&clair).expect_err("un chiffre d'un autre nom doit etre refuse");
            // `{e:#}` et non `{e}`: anyhow ne rend que la couche externe par
            // defaut, et la raison est dans la cause. La mesurer sur
            // `to_string()` reviendrait a mesurer le contexte qu'on a soi-meme
            // ajoute.
            let vu = format!("{e:#}");
            assert!(
                vu.contains("systemd-creds a refuse"),
                "le refus doit venir de systemd-creds: {vu}"
            );
            // Ce que systemd-creds a dit, mesure le 19/08/2026 sur essai-linux:
            // "Embedded credential name 'autre.chose' does not match filename
            // 'bifrost.tunnel', refusing."
            assert!(
                vu.contains("does not match"),
                "et nommer la liaison au nom, qui est la propriete d'integrite: {vu}"
            );

            let _ = std::fs::remove_dir_all(&rep);
        }
    }

    /// Le vrai DPAPI, sur la vraie machine.
    ///
    /// Le pendant Windows de `reel`, et il tourne SANS privilege: DPAPI chiffre
    /// dans le contexte du compte qui appelle, il n'y a donc rien a elever. La
    /// consequence est que ces recettes ne sautent jamais ici - contrairement a
    /// leurs jumelles Linux, qui attendent le TPM donc root.
    #[cfg(windows)]
    mod reel_windows {
        use super::*;

        /// Un repertoire a nous. Il nous appartient, donc il passe le controle
        /// de proprietaire - et c'est aussi ce que la recette veut: mesurer le
        /// coffre, pas le repertoire.
        fn repertoire(nom: &str) -> PathBuf {
            let p =
                std::env::temp_dir().join(format!("bifrost-coffre-{}-{nom}", std::process::id()));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).unwrap();
            p
        }

        fn ecrire_profil(rep: &Path, contenu: &str) -> PathBuf {
            let f = rep.join("tunnel.toml");
            std::fs::write(&f, contenu).unwrap();
            f
        }

        const SECRET: &str = "MOT-DE-PASSE-QUI-NE-DOIT-PAS-APPARAITRE";

        /// L'aller-retour, et la propriete qui compte vraiment: le chiffre ne
        /// dit rien.
        ///
        /// Verifier seulement que l'aller-retour rend le meme texte passerait
        /// aussi pour une implementation qui recopierait le fichier.
        #[test]
        fn un_profil_scelle_se_rouvre_et_son_chiffre_ne_dit_rien() {
            let rep = repertoire("aller-retour");
            let contenu = format!(
                "mot_de_passe = \"{SECRET}\"
"
            );
            let clair = ecrire_profil(&rep, &contenu);

            let scelle = sceller(&clair).expect("le scellement doit reussir");
            assert_eq!(scelle, chemin_scelle(&clair));

            let chiffre = std::fs::read(&scelle).expect("le scelle doit etre lisible");
            assert!(
                !chiffre
                    .windows(SECRET.len())
                    .any(|f| f == SECRET.as_bytes()),
                "le secret apparait en clair dans {}",
                scelle.display()
            );

            // Le clair est retire: le coffre doit se suffire a lui-meme.
            std::fs::remove_file(&clair).unwrap();
            let ouvert = ouvrir(&clair).expect("un profil scelle doit s'ouvrir sans le clair");
            assert_eq!(ouvert.forme, Forme::Scelle);
            assert_eq!(ouvert.contenu, contenu, "l'aller-retour doit etre fidele");

            let _ = std::fs::remove_dir_all(&rep);
        }

        /// Le scelle l'emporte, et un ciphertext d'un AUTRE nom est refuse.
        ///
        /// Cette seconde moitie est la propriete d'integrite que `systemd-creds`
        /// apporte sous Linux, et que la description DPAPI apporte ici: le nom
        /// voyage avec le chiffre, son integrite est couverte, et il est relu au
        /// dechiffrement. Sans elle, le chiffre de n'importe quoi d'autre
        /// passerait pour un profil.
        #[test]
        fn le_scelle_l_emporte_et_un_chiffre_etranger_est_refuse() {
            let rep = repertoire("priorite");
            let clair = ecrire_profil(
                &rep,
                "mot_de_passe = \"celui-du-clair\"
",
            );
            sceller(&clair).expect("le scellement doit reussir");
            // Le clair change APRES le scellement: si c'est lui qu'on lit, la
            // recette le verra.
            std::fs::write(
                &clair,
                "mot_de_passe = \"celui-du-clair-modifie\"
",
            )
            .unwrap();

            let ouvert = ouvrir(&clair).expect("le scelle doit s'ouvrir");
            assert_eq!(ouvert.forme, Forme::Scelle);
            assert!(
                ouvert.contenu.contains("celui-du-clair\""),
                "c'est le scelle qui doit servir, pas le clair: {}",
                ouvert.contenu
            );

            // Un chiffre parfaitement valide, scelle sous un autre nom, glisse a
            // la place de celui du profil.
            let etranger = crate::dpapi::chiffrer(b"contenu etranger", "autre.chose")
                .expect("le scellement etranger doit reussir");
            std::fs::write(chemin_scelle(&clair), &etranger).unwrap();

            let e = ouvrir(&clair).expect_err("un chiffre d'un autre nom doit etre refuse");
            // `{e:#}` et non `{e}`: anyhow ne rend que la couche externe par
            // defaut, et la raison est dans la cause.
            let vu = format!("{e:#}");
            assert!(
                vu.contains("autre.chose") && vu.contains(NOM_CREDENTIAL),
                "le refus doit nommer les deux noms, qui sont la propriete                  d'integrite: {vu}"
            );

            let _ = std::fs::remove_dir_all(&rep);
        }
    }

    /// Un `Ouvert` qui traverse un message d'erreur ne doit pas emporter le
    /// secret avec lui.
    #[test]
    fn le_contenu_ne_s_imprime_pas() {
        let o = Ouvert {
            contenu: "private_key = \"le-secret\"".into(),
            forme: Forme::EnClair,
        };
        let vu = format!("{o:?}");
        assert!(
            !vu.contains("le-secret"),
            "le secret a fuite dans Debug: {vu}"
        );
        assert!(
            vu.contains("expurge"),
            "et le remplacement doit se voir: {vu}"
        );
    }

    /// Le repertoire temporaire est en 1777, et il doit passer.
    ///
    /// Sans la prise en compte du bit collant, cette regle refuserait `/tmp`,
    /// donc toutes les recettes de ce depot - et l'on serait tente de la
    /// relacher au lieu de la corriger.
    #[cfg(unix)]
    #[test]
    fn un_repertoire_collant_est_accepte() {
        let f = std::env::temp_dir().join("bifrost-coffre-collant.toml");
        exiger_repertoire_sur(&f).expect("/tmp est en 1777 et ne permet pas de remplacer");
    }

    /// Un repertoire ou d'autres ecrivent, sans bit collant, est refuse.
    #[cfg(unix)]
    #[test]
    fn un_repertoire_ou_d_autres_ecrivent_est_refuse() {
        use std::os::unix::fs::PermissionsExt;

        let rep =
            std::env::temp_dir().join(format!("bifrost-coffre-ouvert-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&rep);
        std::fs::create_dir_all(&rep).unwrap();
        std::fs::set_permissions(&rep, std::fs::Permissions::from_mode(0o777)).unwrap();

        let e = exiger_repertoire_sur(&rep.join("tunnel.toml"))
            .expect_err("un repertoire ou tout le monde ecrit doit etre refuse");
        let e = e.to_string();
        assert!(e.contains("777"), "le mode fautif doit etre nomme: {e}");
        assert!(
            e.contains("serveur"),
            "et la consequence dite: c'est le choix du serveur qui est en jeu. {e}"
        );

        // Le temoin negatif.
        std::fs::set_permissions(&rep, std::fs::Permissions::from_mode(0o700)).unwrap();
        exiger_repertoire_sur(&rep.join("tunnel.toml")).expect("0700 doit passer");
        let _ = std::fs::remove_dir_all(&rep);
    }

    #[test]
    fn l_extension_s_ajoute_et_ne_remplace_pas() {
        assert_eq!(
            chemin_scelle(Path::new("/etc/bifrost/tunnel.toml")),
            PathBuf::from("/etc/bifrost/tunnel.toml.cred"),
            "remplacer l'extension perdrait la trace du format"
        );
    }

    #[test]
    fn seul_le_proprietaire_a_le_droit_de_lire() {
        assert_eq!(trop_ouvert(0o600), None);
        assert_eq!(trop_ouvert(0o400), None);
        // 0700 est bizarre pour un fichier de configuration, mais il ne fuit
        // rien: la regle porte sur qui LIT, pas sur ce qui est esthetique.
        assert_eq!(trop_ouvert(0o700), None);
    }

    #[test]
    fn le_groupe_est_refuse_autant_que_le_monde() {
        // Le cas qui compte, et le moins evident: 0640 root:bifrost donne la
        // cle privee a tous ceux qui ont le droit de piloter le daemon.
        assert_eq!(
            trop_ouvert(0o640),
            Some("son groupe y a acces"),
            "un profil lisible par le groupe donne la cle a tous les pilotes"
        );
        assert_eq!(trop_ouvert(0o644), Some("tout le monde y a acces"));
        assert_eq!(trop_ouvert(0o666), Some("tout le monde y a acces"));
        // L'ecriture compte autant que la lecture, d'ou un message qui parle
        // d'ACCES: un profil que le groupe peut reecrire laisse choisir a un
        // tiers le serveur vers lequel on se connecte.
        assert_eq!(trop_ouvert(0o620), Some("son groupe y a acces"));
    }
}
