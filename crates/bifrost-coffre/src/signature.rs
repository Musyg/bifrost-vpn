//! D'ou vient un profil: qui l'a signe, et s'il remplace vraiment le precedent.
//!
//! # Le probleme, et pourquoi le transport ne le resout pas
//!
//! Un profil designe un serveur et porte de quoi s'y authentifier. Le transport
//! authentifie ensuite ce serveur - REALITY verifie sa cle publique, WireGuard
//! son pair - mais il authentifie le serveur QUE LE PROFIL NOMME. Il ne dit
//! rien du CHOIX de ce serveur. Un profil fabrique par un tiers monte donc un
//! tunnel parfaitement chiffre vers ce tiers, sans qu'aucune verification
//! n'echoue nulle part.
//!
//! C'est la meme faille que celle du repertoire trop ouvert, un cran plus tot:
//! la ou celle-la laissait REMPLACER un profil deja range, celle-ci laisse en
//! INSTALLER un faux. Et elle s'aggrave a chaque canal ajoute - le document 04
//! partie 381 en veut trois (subscription CDN, miroir GitHub raw, bot Telegram),
//! donc trois points d'injection. **La signature est ce qui rend un canal
//! hostile acceptable**: sans elle, ajouter des canaux augmente la surface
//! d'attaque; avec elle, chaque canal supplementaire est gratuit. C'est pourquoi
//! elle vient AVANT le multi-canal, et non apres.
//!
//! # Ce que fait l'etat de l'art, verifie le 19 aout 2026
//!
//! **Psiphon** est la reference deployee, et depuis quinze ans: sa liste de
//! serveurs distante est signee, la cle publique de verification vit dans la
//! configuration du client (`RemoteServerListSignaturePublicKey`), et le
//! telechargement bascule entre PLUSIEURS URL racines. C'est exactement
//! l'architecture du plan, avec la signature comme fondation et le multi-canal
//! par-dessus.
//!
//! **Tor** a retire son API `moat` en 2024 et distribue desormais ses bridges
//! par Telegram et par les reglages de contournement geolocalises. Ses bridge
//! lines portent l'empreinte de la cle du bridge: la aussi, ce qui vient d'un
//! canal non fiable porte de quoi etre authentifie hors du canal.
//!
//! Le format retenu est **minisign**, en mode prehache uniquement. Ed25519, une
//! specification tenant en une page, et une implementation de verification sans
//! aucune dependance (`minisign-verify`, MIT, de l'auteur de libsodium). Le
//! commentaire dit "de confiance" y est signe avec la signature elle-meme, ce
//! qui donne un endroit AUTHENTIFIE ou porter des metadonnees - la serie s'y
//! loge sans inventer de format.
//!
//! **Ni TUF, ni Sigstore**, contre ce que le document 06 suggerait pour le canal
//! du daemon. TUF resout la delegation de roles et la rotation en ligne dans un
//! depot de paquets; ici il y a un fichier et une seule autorite, et son
//! anti-rejeu se reduit alors a un compteur monotone. Son implementation Rust,
//! `tough`, a d'ailleurs porte CVE-2025-2885 - une validation manquante du
//! numero de version des metadonnees racine, c'est-a-dire un defaut sur le point
//! meme que le cadre existe pour proteger. Sigstore, lui, se disqualifie tout
//! seul: la verification sans reseau exige un bundle et une infrastructure
//! miroir, l'amont deconseille explicitement de figer les URL de ses instances
//! Rekor d'une annee sur l'autre, et le mode keyless lie le signataire a un
//! fournisseur OIDC. Un client anti-censure doit pouvoir verifier **hors ligne**
//! un fichier ramasse n'importe ou, et son signataire est souvent pseudonyme.
//!
//! # Ce que le plan disait, et le seul point ou ce produit differe
//!
//! Le document 04 dit "profils signes (Ed25519)" et le document 06 "cle publique
//! jamais partagee, signature obligatoire", tous deux en supposant un editeur
//! qui signe pour ses utilisateurs. Bifrost est **auto-heberge**: l'utilisateur
//! EST l'operateur, il signe ses propres serveurs avec sa propre cle. Une cle
//! publique codee en dur par nous n'aurait donc rien a authentifier - nous ne
//! signons pas ses serveurs. Elle est par consequent un fichier,
//! [`NOM_CLE_DE_CONFIANCE`], installe une fois a cote du profil.
//!
//! Cela ne l'affaiblit pas: ce fichier vit dans le repertoire du profil, dont ce
//! meme module exige deja qu'il ne soit pas modifiable par d'autres. Qui peut y
//! remplacer la cle peut de toute facon y remplacer le profil. Ce que la
//! signature protege, c'est le trajet AVANT l'installation - le canal.
//!
//! # La ou la signature n'intervient PAS
//!
//! A l'ouverture d'un profil deja installe. Un administrateur qui ecrit ses
//! trois lignes dans un editeur doit rester servi, et exiger une signature a
//! chaque ouverture obligerait tout le monde a signer pour se connecter. Le plan
//! parle du BOOTSTRAP, c'est-a-dire du moment ou le profil vient d'ailleurs;
//! une fois installe, c'est le rangement au repos qui prend le relais.
//!
//! # Le format herite, et l'interoperabilite
//!
//! Le format herite (algorithme `Ed`, sans prehachage) est refuse: [`verifier`]
//! passe `allow_legacy = false`, comme la specification amont le demande aux
//! nouvelles implementations. La crate de signature ne sait plus en emettre,
//! mais le BINAIRE `minisign` le fait encore avec `-l`, et c'est ce qui rend le
//! refus mesurable plutot que declaratif.
//!
//! `tests/interop_minisign.rs` s'en sert, et couvre au passage une question que
//! les recettes de ce module ne posent pas: ce que produit le vrai outil, dans
//! un autre langage et avec son propre encodage, est-il accepte ici. Une
//! incompatibilite ne se verrait sinon qu'au pire moment, le jour ou quelqu'un
//! installe un profil. Cette recette rend SKIPPED la ou le binaire est absent,
//! ce qui est le cas de dev-windows.

use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};

/// L'extension d'une signature, celle de minisign.
pub const EXTENSION_SIGNATURE: &str = "minisig";

/// Le nom de la cle publique de confiance, dans le repertoire du profil.
///
/// Un nom fixe plutot qu'un chemin a fournir: la cle et le profil doivent
/// partager le meme repertoire protege, et laisser designer la cle ailleurs
/// reviendrait a laisser choisir sa propre racine de confiance en ligne de
/// commande.
pub const NOM_CLE_DE_CONFIANCE: &str = "confiance.pub";

/// Le chemin de la signature qui accompagne un fichier.
///
/// AJOUTEE et non substituee, comme pour le scelle: `tunnel.toml` donne
/// `tunnel.toml.minisig`, ce qui est aussi la convention de minisign.
pub fn chemin_signature(fichier: &Path) -> PathBuf {
    let mut nom = fichier.as_os_str().to_os_string();
    nom.push(".");
    nom.push(EXTENSION_SIGNATURE);
    PathBuf::from(nom)
}

/// Le chemin de la cle de confiance, a cote d'un profil.
pub fn chemin_cle_de_confiance(profil: &Path) -> PathBuf {
    match profil.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.join(NOM_CLE_DE_CONFIANCE),
        _ => PathBuf::from(NOM_CLE_DE_CONFIANCE),
    }
}

/// Ce qu'une signature VERIFIEE dit du profil.
///
/// Rendue par [`verifier`] et par elle seule. C'est delibere: `minisign-verify`
/// expose le commentaire de confiance sur une signature qui n'a pas encore ete
/// verifiee, et le lire la reviendrait a faire confiance a un texte que
/// n'importe qui peut ecrire. Ici, aucun chemin ne rend ce commentaire sans que
/// la verification ait reussi, ce qui rend le piege inatteignable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origine {
    /// Ce qui ordonne deux profils, quand le signataire l'a declare.
    pub serie: Option<u64>,
    /// Le commentaire de confiance entier, tel que signe.
    pub commentaire: String,
}

/// Ce qui declare une serie dans le commentaire de confiance.
const MARQUEUR_SERIE: &str = "serie=";

/// Verifie une signature et rend ce qu'elle dit.
///
/// `cle_publique` est la ligne base64 nue, pas le fichier entier: c'est ce
/// qu'attend `minisign-verify`, et [`lire_cle_de_confiance`] fait l'extraction.
///
/// # Pourquoi `allow_legacy` vaut `false`
///
/// Le format herite signe le fichier entier au lieu de son empreinte Blake2b.
/// La specification de minisign demande aux nouvelles implementations d'utiliser
/// le format hache et de ne pas accepter l'ancien par defaut. L'accepter serait
/// ouvrir un chemin que l'amont deconseille, pour ne servir que des signatures
/// produites par des outils d'avant 2015.
pub fn verifier(contenu: &[u8], signature: &str, cle_publique: &str) -> Result<Origine> {
    let cle = minisign_verify::PublicKey::from_base64(cle_publique.trim())
        .context("la cle de confiance n'est pas une cle publique minisign")?;
    let signature = minisign_verify::Signature::decode(signature)
        .context("la signature n'est pas une signature minisign")?;

    cle.verify(contenu, &signature, false)
        .map_err(|e| anyhow::anyhow!("{e}"))
        .context("le profil n'a pas ete signe par la cle de confiance de cette machine")?;

    // APRES la verification, et pas avant: c'est tout l'interet du commentaire
    // dit "de confiance" - il est couvert par la signature globale, donc le lire
    // ici a un sens, alors que le lire trois lignes plus haut n'en aurait aucun.
    let commentaire = signature.trusted_comment().to_string();
    Ok(Origine {
        serie: lire_serie(&commentaire),
        commentaire,
    })
}

/// Le numero de serie declare dans un commentaire de confiance, s'il y est.
///
/// Un seul marqueur, `serie=N`, et rien d'implicite. L'horodatage que minisign
/// ecrit tout seul serait tentant comme serie de secours, mais il ne dit pas ce
/// qu'on croit: resigner le MEME profil le change, alors que "ceci remplace
/// cela" est une decision et non un effet de bord de l'heure de signature.
fn lire_serie(commentaire: &str) -> Option<u64> {
    commentaire
        .split_whitespace()
        .find_map(|mot| mot.strip_prefix(MARQUEUR_SERIE))
        .and_then(|n| n.parse().ok())
}

/// Lit un fichier de cle publique minisign et en extrait la ligne base64.
///
/// Le fichier porte une ligne de commentaire non signe puis la cle. Refuser ce
/// qui n'a pas exactement une ligne de cle vaut mieux que d'en deviner une:
/// deux cles dans un fichier, c'est une question sans reponse evidente.
pub fn lire_cle_de_confiance(chemin: &Path) -> Result<String> {
    let contenu = std::fs::read_to_string(chemin).with_context(|| {
        format!(
            "cle de confiance introuvable: {}\n    \
             Elle authentifie les profils qui arrivent par un canal quelconque.\n    \
             La generer sur la machine qui signe:\n        minisign -G -p {}\n    \
             puis y deposer le fichier public produit.",
            chemin.display(),
            NOM_CLE_DE_CONFIANCE
        )
    })?;

    let lignes: Vec<&str> = contenu
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with("untrusted comment:"))
        .collect();

    match lignes.as_slice() {
        [cle] => Ok((*cle).to_string()),
        [] => bail!(
            "{} ne contient aucune cle: une cle publique minisign tient sur une \
             ligne de commentaire et une ligne de cle",
            chemin.display()
        ),
        _ => bail!(
            "{} contient {} lignes de cle: il en faut exactement une, sans quoi \
             c'est le fichier qui choisit a qui faire confiance",
            chemin.display(),
            lignes.len()
        ),
    }
}

/// Installe un profil signe a sa place definitive.
///
/// L'ordre importe et il est mesure: le repertoire est juge AVANT toute lecture,
/// la signature AVANT toute ecriture, et la serie AVANT de remplacer quoi que ce
/// soit. Un profil qui echoue a l'une de ces etapes laisse l'installation
/// precedente intacte.
pub fn installer(source: &Path, destination: &Path) -> Result<Origine> {
    crate::exiger_repertoire_sur(destination)?;

    let contenu =
        std::fs::read(source).with_context(|| format!("lecture du profil {}", source.display()))?;
    let signature_source = chemin_signature(source);
    let signature = std::fs::read_to_string(&signature_source).with_context(|| {
        format!(
            "signature introuvable: {}\n    \
             Un profil non signe ne dit pas d'ou il vient, et c'est precisement \
             ce qu'un canal hostile exploite.",
            signature_source.display()
        )
    })?;

    let cle = lire_cle_de_confiance(&chemin_cle_de_confiance(destination))?;
    let origine = verifier(&contenu, &signature, &cle)?;

    if let Some(installee) = origine_installee(destination, &cle) {
        refuser_un_recul(&installee, &origine)?;
    }

    // Le profil AVANT sa signature: mourir entre les deux laisse alors un profil
    // valide sans anti-rejeu, ce qui degrade une protection. L'ordre inverse
    // laisserait une signature qui ne correspond pas a son profil, ce qui
    // rendrait la prochaine installation incomprehensible.
    ecrire_prive(destination, &contenu)?;
    ecrire_prive(&chemin_signature(destination), signature.as_bytes())?;

    Ok(origine)
}

/// Ce que dit la signature du profil DEJA installe, quand elle dit encore
/// quelque chose.
///
/// `None` couvre trois cas qui ne se distinguent pas ici et n'ont pas a l'etre:
/// rien d'installe, installe sans signature, ou signature qui ne se verifie plus
/// parce que la cle de confiance a change. Aucun n'autorise a refuser la
/// nouvelle installation: dans les trois, il n'y a rien contre quoi comparer.
fn origine_installee(destination: &Path, cle: &str) -> Option<Origine> {
    let contenu = std::fs::read(destination).ok()?;
    let signature = std::fs::read_to_string(chemin_signature(destination)).ok()?;
    verifier(&contenu, &signature, cle).ok()
}

/// Refuse un profil qui ne va pas de l'avant.
///
/// Le second cas est le piege: retirer `serie=` d'un profil deja numerote
/// contournerait l'anti-rejeu en le desactivant. Une protection qu'on desarme en
/// omettant un champ n'en est pas une.
fn refuser_un_recul(installee: &Origine, nouvelle: &Origine) -> Result<()> {
    match (installee.serie, nouvelle.serie) {
        (Some(ancienne), Some(neuve)) if neuve <= ancienne => bail!(
            "ce profil porte la serie {neuve}, celui qui est installe porte la \
             serie {ancienne}: il ne le remplace pas, il le rejoue"
        ),
        (Some(ancienne), None) => bail!(
            "le profil installe porte la serie {ancienne} et celui-ci n'en \
             declare aucune: l'accepter reviendrait a desarmer l'anti-rejeu en \
             omettant un champ"
        ),
        _ => Ok(()),
    }
}

/// Ecrit un fichier que son proprietaire seul peut lire.
///
/// Par un temporaire puis un renommage, pour qu'une interruption ne laisse
/// jamais un profil tronque a la place d'un profil valide. Et le mode est pose a
/// la CREATION, pas apres: le poser apres laisserait le fichier lisible par tous
/// pendant l'ecriture, ce qui est exactement le moment ou il contient la cle.
fn ecrire_prive(chemin: &Path, contenu: &[u8]) -> Result<()> {
    use std::io::Write;

    let temporaire = chemin.with_extension(format!(
        "{}.partiel",
        chemin
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or_default()
    ));

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut f = options
        .open(&temporaire)
        .with_context(|| format!("ecriture de {}", temporaire.display()))?;
    f.write_all(contenu)
        .and_then(|()| f.sync_all())
        .with_context(|| format!("ecriture de {}", temporaire.display()))?;
    drop(f);

    std::fs::rename(&temporaire, chemin)
        .with_context(|| format!("mise en place de {}", chemin.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Une paire de test, generee a chaque execution.
    ///
    /// Jamais commitee: une cle privee dans un depot est une cle privee
    /// publiee, meme quand elle ne signe que des recettes. Le prix est une
    /// dependance de developpement sur la crate de signature, qui n'entre donc
    /// dans aucun binaire livre - le produit ne sait que VERIFIER, et la cle
    /// privee n'approche jamais son code.
    struct Signataire {
        paire: minisign::KeyPair,
    }

    impl Signataire {
        fn nouveau() -> Self {
            Self {
                paire: minisign::KeyPair::generate_unencrypted_keypair().unwrap(),
            }
        }

        fn cle_publique(&self) -> String {
            self.paire.pk.to_base64()
        }

        fn signer(&self, contenu: &[u8], commentaire: Option<&str>) -> String {
            minisign::sign(
                None,
                &self.paire.sk,
                std::io::Cursor::new(contenu),
                commentaire,
                None,
            )
            .unwrap()
            .into_string()
        }
    }

    fn atelier(nom: &str) -> PathBuf {
        let rep =
            std::env::temp_dir().join(format!("bifrost-signature-{}-{nom}", std::process::id()));
        let _ = std::fs::remove_dir_all(&rep);
        std::fs::create_dir_all(&rep).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&rep, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        rep
    }

    /// Un fichier de signature aux fins de ligne de Windows se verifie.
    ///
    /// # Pourquoi cette recette existe
    ///
    /// Les quatre recettes d'interoperabilite contre le VRAI binaire
    /// (`tests/interop_minisign.rs`) n'ont jamais tourne que sur essai-linux:
    /// sur dev-windows le binaire est absent et elles se declarent SKIPPED. Le
    /// risque propre a Windows qu'elles auraient couvert tient en une chose,
    /// les fins de ligne. Un `.minisig` produit sur Windows, ou simplement
    /// passe par un editeur ou par un `git` en `autocrlf`, porte des retours
    /// chariot.
    ///
    /// La reponse se lit dans `minisign-verify` 0.2.5, qui decoupe par
    /// `str::lines()`, lequel retire le retour chariot. Ce n'est pas notre
    /// code, et c'est justement pourquoi une recette le tient: une version
    /// amont qui passerait a un decoupage strict rougirait ici, et pas le jour
    /// ou quelqu'un installe un profil.
    #[test]
    fn une_signature_aux_fins_de_ligne_windows_se_verifie() {
        let s = Signataire::nouveau();
        let contenu = b"interface = \"wg0\"" as &[u8];
        let signature = s.signer(contenu, Some("serie=7 signe ailleurs"));
        assert!(
            !signature.contains('\r'),
            "la signature de reference doit etre en sauts simples"
        );

        let avec_retours = signature.replace("\n", "\r\n");
        let origine = verifier(contenu, &avec_retours, &s.cle_publique())
            .expect("une signature aux fins de ligne Windows doit se verifier");
        assert_eq!(origine.serie, Some(7));
    }

    /// Une cle entouree d'espaces se lit quand meme.
    ///
    /// La recette existe parce qu'une ronde de falsification a montre que
    /// `.map(str::trim)` ne protegeait RIEN: la recette des fins de ligne
    /// passait aussi sans lui, `str::lines()` retirant deja le retour chariot.
    /// Une ligne qui a l'air de proteger quelque chose sans rien proteger est
    /// pire qu'absente. Ou elle part, ou elle gagne une raison; ici elle en a
    /// une, le collage a la main d'une cle publique, et la voici mesuree.
    #[test]
    fn une_cle_entouree_d_espaces_se_lit() {
        let s = Signataire::nouveau();
        let rep = atelier("cle-espaces");
        let chemin = rep.join(NOM_CLE_DE_CONFIANCE);
        std::fs::write(
            &chemin,
            format!(
                "untrusted comment: minisign public key\n   {}  \n",
                s.cle_publique()
            ),
        )
        .unwrap();

        assert_eq!(
            lire_cle_de_confiance(&chemin).unwrap(),
            s.cle_publique(),
            "les espaces d'un collage a la main ne doivent pas entrer dans la cle"
        );
        let _ = std::fs::remove_dir_all(&rep);
    }

    /// Et le fichier de cle publique aussi, qui est notre code a nous.
    #[test]
    fn une_cle_de_confiance_aux_fins_de_ligne_windows_se_lit() {
        let s = Signataire::nouveau();
        let rep = atelier("cle-retours");
        let chemin = rep.join(NOM_CLE_DE_CONFIANCE);
        let fichier = format!(
            "untrusted comment: minisign public key\n{}\n",
            s.cle_publique()
        )
        .replace("\n", "\r\n");
        std::fs::write(&chemin, &fichier).unwrap();

        assert_eq!(
            lire_cle_de_confiance(&chemin).unwrap(),
            s.cle_publique(),
            "un retour chariot ne doit pas entrer dans la cle"
        );
        let _ = std::fs::remove_dir_all(&rep);
    }

    #[test]
    fn l_extension_s_ajoute_et_ne_remplace_pas() {
        assert_eq!(
            chemin_signature(Path::new("/etc/bifrost/tunnel.toml")),
            PathBuf::from("/etc/bifrost/tunnel.toml.minisig")
        );
    }

    #[test]
    fn la_cle_se_cherche_a_cote_du_profil() {
        assert_eq!(
            chemin_cle_de_confiance(Path::new("/etc/bifrost/tunnel.toml")),
            PathBuf::from("/etc/bifrost/confiance.pub")
        );
    }

    #[test]
    fn une_signature_valide_rend_la_serie() {
        let s = Signataire::nouveau();
        let contenu = b"interface = \"wg0\"";
        let sig = s.signer(contenu, Some("serie=7 profil de recette"));

        let origine = verifier(contenu, &sig, &s.cle_publique()).expect("doit se verifier");
        assert_eq!(origine.serie, Some(7));
        assert!(origine.commentaire.contains("profil de recette"));
    }

    #[test]
    fn une_signature_sans_serie_se_verifie_quand_meme() {
        let s = Signataire::nouveau();
        let sig = s.signer(b"x", Some("aucune serie ici"));
        let origine = verifier(b"x", &sig, &s.cle_publique()).unwrap();
        assert_eq!(origine.serie, None);
    }

    #[test]
    fn une_cle_etrangere_est_refusee() {
        let vrai = Signataire::nouveau();
        let autre = Signataire::nouveau();
        let sig = vrai.signer(b"x", Some("serie=1"));

        let e = verifier(b"x", &sig, &autre.cle_publique())
            .expect_err("une autre cle ne doit pas passer");
        assert!(
            format!("{e:#}").contains("cle de confiance"),
            "le message doit dire ce qui a echoue: {e:#}"
        );
    }

    #[test]
    fn un_profil_modifie_apres_signature_est_refuse() {
        let s = Signataire::nouveau();
        let sig = s.signer(b"endpoint = \"203.0.113.7:51820\"", Some("serie=1"));
        verifier(
            b"endpoint = \"198.51.100.9:51820\"",
            &sig,
            &s.cle_publique(),
        )
        .expect_err("un octet change doit suffire");
    }

    /// Le piege de l'API amont, ferme et garde ferme.
    ///
    /// `minisign-verify` rend le commentaire de confiance d'une signature qui
    /// n'a pas ete verifiee. Si un jour quelqu'un lisait ce commentaire avant
    /// l'appel a `verify`, cette recette tomberait: elle exige qu'une signature
    /// refusee ne laisse RIEN passer de ce qu'elle raconte.
    #[test]
    fn un_commentaire_non_verifie_ne_sort_pas() {
        let menteur = Signataire::nouveau();
        let vrai = Signataire::nouveau();
        let sig = menteur.signer(b"x", Some("serie=999999 profil officiel"));

        let e = verifier(b"x", &sig, &vrai.cle_publique()).expect_err("doit etre refuse");
        let dit = format!("{e:#}");
        assert!(
            !dit.contains("999999") && !dit.contains("officiel"),
            "rien du commentaire non verifie ne doit ressortir: {dit}"
        );
    }

    #[test]
    fn une_cle_illisible_est_nommee() {
        let rep = atelier("cle-vide");
        let cle = rep.join(NOM_CLE_DE_CONFIANCE);
        std::fs::write(&cle, "untrusted comment: minisign public key ABC\n").unwrap();

        let e = lire_cle_de_confiance(&cle).expect_err("un fichier sans cle doit etre refuse");
        assert!(format!("{e:#}").contains("aucune cle"), "{e:#}");
        let _ = std::fs::remove_dir_all(&rep);
    }

    #[test]
    fn deux_cles_dans_un_fichier_sont_refusees() {
        let rep = atelier("deux-cles");
        let s = Signataire::nouveau();
        let cle = rep.join(NOM_CLE_DE_CONFIANCE);
        std::fs::write(
            &cle,
            format!("{}\n{}\n", s.cle_publique(), s.cle_publique()),
        )
        .unwrap();

        let e = lire_cle_de_confiance(&cle).expect_err("deux cles doivent etre refusees");
        assert!(format!("{e:#}").contains("exactement une"), "{e:#}");
        let _ = std::fs::remove_dir_all(&rep);
    }

    /// Le chemin complet: une source signee, une cle installee, un profil range.
    fn poser(rep: &Path, s: &Signataire, contenu: &[u8], commentaire: &str) -> PathBuf {
        std::fs::write(rep.join(NOM_CLE_DE_CONFIANCE), s.cle_publique()).unwrap();
        let source = rep.join("arrive.toml");
        std::fs::write(&source, contenu).unwrap();
        std::fs::write(
            chemin_signature(&source),
            s.signer(contenu, Some(commentaire)),
        )
        .unwrap();
        source
    }

    #[test]
    fn un_profil_signe_s_installe() {
        let rep = atelier("installe");
        let s = Signataire::nouveau();
        let source = poser(&rep, &s, b"interface = \"wg0\"", "serie=3");
        let dest = rep.join("tunnel.toml");

        let origine = installer(&source, &dest).expect("doit s'installer");
        assert_eq!(origine.serie, Some(3));
        assert_eq!(std::fs::read(&dest).unwrap(), b"interface = \"wg0\"");
        assert!(
            chemin_signature(&dest).is_file(),
            "la signature reste a cote"
        );

        // Range comme le coffre l'exige, sinon la premiere ouverture le refuse.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&dest).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "mode {mode:o}");
        }
        let _ = std::fs::remove_dir_all(&rep);
    }

    #[test]
    fn une_serie_qui_recule_est_refusee() {
        let rep = atelier("recul");
        let s = Signataire::nouveau();
        let dest = rep.join("tunnel.toml");

        let source = poser(&rep, &s, b"a = 1", "serie=5");
        installer(&source, &dest).unwrap();

        let vieux = poser(&rep, &s, b"a = 2", "serie=4");
        let e = installer(&vieux, &dest).expect_err("un profil plus ancien doit etre refuse");
        assert!(format!("{e:#}").contains("rejoue"), "{e:#}");
        // Et l'installation precedente est intacte.
        assert_eq!(std::fs::read(&dest).unwrap(), b"a = 1");
        let _ = std::fs::remove_dir_all(&rep);
    }

    #[test]
    fn la_meme_serie_ne_passe_pas_deux_fois() {
        let rep = atelier("egal");
        let s = Signataire::nouveau();
        let dest = rep.join("tunnel.toml");

        installer(&poser(&rep, &s, b"a = 1", "serie=5"), &dest).unwrap();
        installer(&poser(&rep, &s, b"a = 2", "serie=5"), &dest)
            .expect_err("une serie egale n'avance pas");
        let _ = std::fs::remove_dir_all(&rep);
    }

    #[test]
    fn retirer_la_serie_est_un_recul() {
        let rep = atelier("sans-serie");
        let s = Signataire::nouveau();
        let dest = rep.join("tunnel.toml");

        installer(&poser(&rep, &s, b"a = 1", "serie=5"), &dest).unwrap();
        let e = installer(&poser(&rep, &s, b"a = 2", "sans numero"), &dest)
            .expect_err("omettre la serie ne doit pas desarmer l'anti-rejeu");
        assert!(format!("{e:#}").contains("desarmer"), "{e:#}");
        let _ = std::fs::remove_dir_all(&rep);
    }

    #[test]
    fn une_serie_qui_avance_remplace() {
        let rep = atelier("avance");
        let s = Signataire::nouveau();
        let dest = rep.join("tunnel.toml");

        installer(&poser(&rep, &s, b"a = 1", "serie=5"), &dest).unwrap();
        let origine = installer(&poser(&rep, &s, b"a = 2", "serie=6"), &dest)
            .expect("une serie superieure doit passer");
        assert_eq!(origine.serie, Some(6));
        assert_eq!(std::fs::read(&dest).unwrap(), b"a = 2");
        let _ = std::fs::remove_dir_all(&rep);
    }

    #[test]
    fn sans_cle_de_confiance_l_installation_dit_quoi_faire() {
        let rep = atelier("sans-cle");
        let s = Signataire::nouveau();
        let source = rep.join("arrive.toml");
        std::fs::write(&source, b"a = 1").unwrap();
        std::fs::write(
            chemin_signature(&source),
            s.signer(b"a = 1", Some("serie=1")),
        )
        .unwrap();

        let e = installer(&source, &rep.join("tunnel.toml"))
            .expect_err("sans cle de confiance, rien ne s'installe");
        let dit = format!("{e:#}");
        assert!(dit.contains(NOM_CLE_DE_CONFIANCE), "{dit}");
        assert!(
            dit.contains("minisign -G"),
            "le message doit dire quoi faire: {dit}"
        );
        let _ = std::fs::remove_dir_all(&rep);
    }

    #[test]
    fn un_profil_sans_signature_est_refuse() {
        let rep = atelier("nue");
        let s = Signataire::nouveau();
        std::fs::write(rep.join(NOM_CLE_DE_CONFIANCE), s.cle_publique()).unwrap();
        let source = rep.join("arrive.toml");
        std::fs::write(&source, b"a = 1").unwrap();

        let e = installer(&source, &rep.join("tunnel.toml"))
            .expect_err("un profil nu ne s'installe pas");
        assert!(format!("{e:#}").contains("canal hostile"), "{e:#}");
        let _ = std::fs::remove_dir_all(&rep);
    }

    /// Le repertoire est juge AVANT la lecture, comme pour l'ouverture.
    #[cfg(unix)]
    #[test]
    fn un_repertoire_ou_d_autres_ecrivent_refuse_l_installation() {
        use std::os::unix::fs::PermissionsExt;

        let rep = atelier("repertoire-ouvert");
        let s = Signataire::nouveau();
        let source = poser(&rep, &s, b"a = 1", "serie=1");
        let cible = rep.join("cible");
        std::fs::create_dir_all(&cible).unwrap();
        std::fs::set_permissions(&cible, std::fs::Permissions::from_mode(0o777)).unwrap();

        let e = installer(&source, &cible.join("tunnel.toml"))
            .expect_err("un repertoire ouvert doit etre refuse");
        assert!(format!("{e:#}").contains("777"), "{e:#}");
        let _ = std::fs::remove_dir_all(&rep);
    }
}
