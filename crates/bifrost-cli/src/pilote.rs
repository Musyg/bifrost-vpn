//! Le pilote TUN de Windows: aller le chercher, et prouver que c'est le bon.
//!
//! Le chemin par coeur a besoin d'un TUN generique - une interface qui rend des
//! paquets IP bruts, que le passeur traduit ensuite en connexions SOCKS5. Sous
//! Linux c'est un `ioctl`, et [`bifrost_daemon`] l'ecrit a la main. Sous
//! Windows cela demande `wintun.dll`, qui n'est pas dans ce depot et n'y sera
//! pas: un binaire tiers versionne est un binaire que personne ne relit, que
//! rien ne date, et qui grossit l'historique a chaque mise a jour.
//!
//! WireGuardNT ne remplace pas Wintun: il cree un adaptateur WIREGUARD, qui
//! chiffre lui-meme. Un coeur ne chiffre pas de cette facon - il ouvre un SOCKS
//! local, et le systeme doit y etre mene par une interface ordinaire.
//!
//! # Pourquoi c'est le CLIENT qui telecharge, et jamais le daemon
//!
//! Une recette l'interdit deja: `frontiere_reseau.rs` refuse `ureq`, `reqwest`,
//! `rustls` et le reste dans la fermeture transitive du daemon. La raison n'a
//! pas change - il tourne en root ou en SYSTEM, avec un socket joignable, et
//! lui apprendre a parler au reseau ouvert lui ajouterait une surface qu'il n'a
//! aucune raison d'avoir. Le client, lui, tourne sous le compte de
//! l'utilisateur.
//!
//! # Ce qui rend le transport sans importance
//!
//! L'empreinte SHA-256 publiee par l'amont est EPINGLEE ici, et l'archive est
//! refusee si elle ne correspond pas. Le reseau n'a donc plus a etre digne de
//! confiance: un miroir hostile, un proxy d'entreprise, une interception - rien
//! de tout cela ne permet de faire charger autre chose au daemon.
//!
//! L'epinglage repose sur une premiere lecture, faite ici le 19 aout 2026, de
//! la page de l'amont. C'est un premier contact, avec ce que cela suppose - et
//! c'est strictement mieux que de refaire confiance au transport a chaque
//! telechargement.
//!
//! # Pourquoi PAS de verification Authenticode en plus
//!
//! Elle n'ajouterait rien ici, et il vaut mieux le dire que de l'ecrire pour
//! l'apparence. L'empreinte fixe l'identite du fichier plus etroitement qu'une
//! signature: elle designe UN fichier, la signature en accepte tous ceux que la
//! meme cle a signes. Si la cle de l'amont etait compromise et une version
//! malveillante publiee, l'empreinte le verrait et une verification de
//! signature non. La seule question qu'une signature repondrait encore - Windows
//! acceptera-t-il d'installer ce pilote - se repond bien mieux en creant
//! reellement un adaptateur, ce que le daemon fait de toute facon.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, bail};

/// La version epinglee. Seule version publiee par l'amont depuis 2021, et celle
/// qu'embarquent WireGuard pour Windows, Tailscale, Mullvad et sing-box.
pub const VERSION: &str = "0.14.1";

/// L'archive officielle.
pub const URL: &str = "https://www.wintun.net/builds/wintun-0.14.1.zip";

/// L'empreinte publiee a cote du lien, lue le 19 aout 2026.
pub const EMPREINTE: &str = "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51";

/// Le nom du fichier une fois en place, celui que le daemon cherchera.
pub const NOM: &str = "wintun.dll";

/// L'archive pese environ 350 Ko. Le plafond laisse de la marge sans laisser
/// un serveur deverser un corps sans fin.
const PLAFOND: u64 = 8 * 1024 * 1024;

/// Assez pour une liaison lente, trop court pour un serveur qui accepte puis se
/// tait.
const DELAI: Duration = Duration::from_secs(60);

/// L'architecture de ce binaire, dans les mots de l'archive.
///
/// Celle du BINAIRE et non celle de la machine: un client 32 bits sur un
/// Windows 64 bits doit charger la DLL 32 bits, sans quoi le chargement echoue
/// avec une erreur qui ne dit pas pourquoi.
pub fn architecture() -> Result<&'static str, String> {
    match std::env::consts::ARCH {
        "x86_64" => Ok("amd64"),
        "aarch64" => Ok("arm64"),
        "x86" => Ok("x86"),
        "arm" => Ok("arm"),
        autre => Err(format!(
            "architecture {autre} inconnue de l'archive Wintun, qui ne publie que \
             amd64, arm64, x86 et arm"
        )),
    }
}

/// L'empreinte SHA-256, en hexadecimal minuscule.
///
/// Pure: la comparaison d'empreintes se lit et s'eprouve sans reseau.
pub fn empreinte(octets: &[u8]) -> String {
    use sha2::{Digest, Sha256};

    let mut h = Sha256::new();
    h.update(octets);
    h.finalize().iter().map(|o| format!("{o:02x}")).collect()
}

/// Refuse une archive qui n'est pas celle qui est epinglee.
///
/// La comparaison n'a pas a etre a temps constant: une empreinte publiee n'est
/// pas un secret, et rien ne se deduit de la vitesse a laquelle on la rejette.
pub fn verifier(octets: &[u8], attendue: &str) -> Result<(), String> {
    let vue = empreinte(octets);
    if vue == attendue {
        return Ok(());
    }
    Err(format!(
        "l'archive telechargee n'est pas celle qui est attendue.\n    \
         attendue: {attendue}\n    \
         recue:    {vue}\n    \
         Ne pas l'installer. Soit l'amont a republie sous le meme nom - auquel cas \n    \
         il faut relire son empreinte a la source et mettre a jour ce programme - \n    \
         soit quelqu'un a servi autre chose."
    ))
}

/// Le membre de l'archive a extraire, choisi dans ce qu'elle contient vraiment.
///
/// Cherche plutot que devine: le prefixe de l'archive est un detail de son
/// fabricant, et le deviner ferait echouer la recuperation le jour ou il change,
/// pour une raison que le message ne dirait pas.
pub fn choisir_membre(entrees: &[String], arch: &str) -> Result<String, String> {
    let queue = format!("bin/{arch}/{NOM}");
    entrees
        .iter()
        .find(|e| e.replace('\\', "/").ends_with(&queue))
        .cloned()
        .ok_or_else(|| {
            format!(
                "l'archive ne contient pas de {NOM} pour {arch}: aucune entree ne \
                 finit par {queue}"
            )
        })
}

/// L'outil d'extraction, par chemin absolu.
///
/// `bsdtar`, livre avec Windows depuis la version 1803, sait lire un zip. Le
/// nommer par son chemin plutot que par son nom evite qu'un `tar.exe` depose
/// ailleurs dans le PATH prenne sa place - c'est la meme raison qui fait charger
/// les DLL par chemin absolu.
fn tar() -> PathBuf {
    let racine = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_owned());
    PathBuf::from(racine).join(r"System32\tar.exe")
}

/// Ce que l'archive contient.
fn lister(archive: &Path) -> anyhow::Result<Vec<String>> {
    let sortie = std::process::Command::new(tar())
        .arg("-tf")
        .arg(archive)
        .output()
        .with_context(|| format!("execution de {}", tar().display()))?;
    if !sortie.status.success() {
        bail!(
            "lecture de l'archive: {}",
            String::from_utf8_lossy(&sortie.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&sortie.stdout)
        .lines()
        .map(|l| l.trim().to_owned())
        .filter(|l| !l.is_empty())
        .collect())
}

/// Sort un seul membre de l'archive.
fn extraire(archive: &Path, membre: &str, vers: &Path) -> anyhow::Result<()> {
    let sortie = std::process::Command::new(tar())
        .arg("-xf")
        .arg(archive)
        .arg("-C")
        .arg(vers)
        .arg(membre)
        .output()
        .with_context(|| format!("execution de {}", tar().display()))?;
    if !sortie.status.success() {
        bail!(
            "extraction de {membre}: {}",
            String::from_utf8_lossy(&sortie.stderr).trim()
        );
    }
    Ok(())
}

/// Ou le pilote est attendu: a cote du binaire.
pub fn emplacement_par_defaut() -> anyhow::Result<PathBuf> {
    let exe = std::env::current_exe().context("chemin du binaire introuvable")?;
    let dir = exe
        .parent()
        .ok_or_else(|| anyhow::anyhow!("binaire sans repertoire parent: {}", exe.display()))?;
    Ok(dir.join(NOM))
}

/// Va chercher le pilote, le verifie, et le met en place.
///
/// Rend le chemin du fichier ecrit. N'ecrase pas: remplacer une DLL qu'un
/// daemon a peut-etre deja chargee ne ferait rien de bon, et le dire vaut mieux
/// que de le tenter.
pub fn recuperer(vers: &Path) -> anyhow::Result<PathBuf> {
    if !cfg!(windows) {
        bail!(
            "{NOM} ne sert que sous Windows. Ailleurs le TUN est un appel du noyau, \
             et il n'y a rien a telecharger"
        );
    }
    if vers.exists() {
        bail!(
            "{} existe deja. Le supprimer d'abord si l'intention est de le remplacer, \
             daemon arrete",
            vers.display()
        );
    }
    let arch = architecture().map_err(anyhow::Error::msg)?;

    eprintln!("telechargement de {URL}");
    let archive = bifrost_amorce::toile::tirer_une_fois(URL, PLAFOND, DELAI)
        .map_err(anyhow::Error::msg)
        .context("telechargement du pilote")?;

    verifier(&archive, EMPREINTE).map_err(anyhow::Error::msg)?;
    eprintln!("empreinte verifiee: {EMPREINTE}");

    // Un repertoire a nous, supprime a la fin: l'archive contient quatre
    // architectures et un en-tete, dont une seule chose nous interesse.
    let atelier = std::env::temp_dir().join(format!("bifrost-pilote-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&atelier);
    std::fs::create_dir_all(&atelier)
        .with_context(|| format!("creation de {}", atelier.display()))?;
    let resultat = poser(&archive, arch, &atelier, vers);
    let _ = std::fs::remove_dir_all(&atelier);
    resultat?;

    Ok(vers.to_path_buf())
}

/// La moitie qui touche au disque, separee pour que l'atelier soit nettoye
/// quoi qu'il arrive.
fn poser(archive: &[u8], arch: &str, atelier: &Path, vers: &Path) -> anyhow::Result<()> {
    let zip = atelier.join("wintun.zip");
    std::fs::write(&zip, archive).with_context(|| format!("ecriture de {}", zip.display()))?;

    let membre = choisir_membre(&lister(&zip)?, arch).map_err(anyhow::Error::msg)?;
    extraire(&zip, &membre, atelier)?;

    let sorti = atelier.join(membre.replace('/', "\\"));
    if let Some(parent) = vers.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creation de {}", parent.display()))?;
    }
    std::fs::copy(&sorti, vers).with_context(|| format!("mise en place de {}", vers.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Le vecteur de reference de SHA-256, pour que le calcul soit mesure et
    /// non suppose: l'empreinte de la chaine vide.
    #[test]
    fn l_empreinte_est_bien_du_sha256() {
        assert_eq!(
            empreinte(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn une_archive_qui_ne_correspond_pas_est_refusee_en_montrant_les_deux() {
        let e = verifier(b"pas la bonne archive", EMPREINTE).expect_err("doit etre refusee");
        assert!(e.contains(EMPREINTE), "l'attendue doit etre montree: {e}");
        assert!(
            e.contains(&empreinte(b"pas la bonne archive")),
            "et la recue aussi, sinon on ne peut rien en faire: {e}"
        );
        assert!(
            e.contains("Ne pas l'installer"),
            "et la consequence dite: {e}"
        );
    }

    #[test]
    fn l_archive_epinglee_serait_acceptee() {
        // Le temoin positif de la comparaison, sans reseau: une suite d'octets
        // dont on connait l'empreinte est acceptee quand on l'attend.
        let octets = b"n'importe quoi, mais dont on sait l'empreinte";
        verifier(octets, &empreinte(octets)).expect("la meme empreinte doit passer");
    }

    /// Le membre est CHERCHE dans l'archive, prefixe compris.
    #[test]
    fn le_membre_se_trouve_quel_que_soit_le_prefixe() {
        let entrees: Vec<String> = [
            "wintun/bin/amd64/wintun.dll",
            "wintun/bin/arm64/wintun.dll",
            "wintun/bin/x86/wintun.dll",
            "wintun/include/wintun.h",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(
            choisir_membre(&entrees, "amd64").unwrap(),
            "wintun/bin/amd64/wintun.dll"
        );
        assert_eq!(
            choisir_membre(&entrees, "arm64").unwrap(),
            "wintun/bin/arm64/wintun.dll"
        );

        // Sans prefixe, ce qui arriverait si l'amont changeait la forme.
        let plates: Vec<String> = ["bin/amd64/wintun.dll".to_string()].into();
        assert_eq!(
            choisir_membre(&plates, "amd64").unwrap(),
            "bin/amd64/wintun.dll"
        );
    }

    /// Une architecture absente est nommee, pas devinee.
    #[test]
    fn une_architecture_absente_de_l_archive_est_dite() {
        let entrees: Vec<String> = ["wintun/bin/amd64/wintun.dll".to_string()].into();
        let e = choisir_membre(&entrees, "arm64").expect_err("doit etre refusee");
        assert!(e.contains("arm64"), "{e}");
        assert!(e.contains(NOM), "{e}");
    }

    /// L'architecture de compilation se traduit dans les mots de l'archive.
    #[test]
    fn l_architecture_courante_a_un_nom_dans_l_archive() {
        let a = architecture().expect("cette architecture doit etre connue");
        assert!(["amd64", "arm64", "x86", "arm"].contains(&a), "{a}");
    }

    /// L'epinglage se tient: la version, le lien et l'empreinte parlent du
    /// MEME fichier.
    ///
    /// Aucune recette ne pouvait tomber sur ces trois constantes: `verifier`
    /// recoit l'empreinte attendue en parametre, et les recettes lui passent
    /// soit `EMPREINTE`, soit une empreinte qu'elles viennent de calculer.
    /// Mesure du 23 aout 2026 sur dev-windows: en changeant `VERSION`, `URL`
    /// et `EMPREINTE`, la suite du crate restait entierement verte.
    ///
    /// Ce qui se verifie sans reseau, c'est la COHERENCE. La justesse de
    /// l'empreinte, elle, demande l'archive et ne se verifie qu'a
    /// l'installation - mais une empreinte tronquee ou une version qui ne
    /// correspond plus au lien sont deux defauts silencieux que le depot peut
    /// attraper ici. Le second est le plus probable: une mise a jour d'amont
    /// se fait en touchant trois lignes, et en oublier une donnerait un
    /// telechargement de l'ancienne archive refuse par la nouvelle empreinte,
    /// avec un message qui accuse le reseau.
    #[test]
    fn la_version_le_lien_et_l_empreinte_designent_le_meme_fichier() {
        assert!(
            URL.contains(VERSION),
            "le lien ne porte pas la version epinglee: {URL} contre {VERSION}"
        );
        assert!(
            URL.starts_with("https://"),
            "l'archive doit etre demandee en TLS: {URL}"
        );
        assert!(
            URL.ends_with(".zip"),
            "l'archive est un zip, et `lister` l'ouvre comme tel: {URL}"
        );

        // Une empreinte SHA-256 fait 64 caracteres hexadecimaux minuscules.
        // La comparaison de `verifier` est textuelle: une majuscule egaree
        // refuserait la bonne archive, et un caractere manquant refuserait
        // tout.
        assert_eq!(
            EMPREINTE.len(),
            64,
            "une empreinte SHA-256 fait 64 caracteres: {EMPREINTE}"
        );
        assert!(
            EMPREINTE
                .bytes()
                .all(|o| o.is_ascii_digit() || (b'a'..=b'f').contains(&o)),
            "hexadecimal minuscule attendu, comme ce que rend `empreinte`: {EMPREINTE}"
        );
    }
}
