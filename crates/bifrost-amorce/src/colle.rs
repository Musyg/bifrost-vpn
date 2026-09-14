//! Le canal qui passe par un humain: une chaine a copier.
//!
//! # Pourquoi celui-ci plutot que le client Telegram que le plan demande
//!
//! Le document 04 partie 381 veut un bot Telegram, et cite Tor en exemple. La
//! citation est exacte, le mecanisme ne l'est pas: **Tor Browser n'interroge
//! jamais Telegram**. Sa documentation decrit quatre gestes, tous humains -
//! ecrire a `@GetBridgesBot` depuis son application, taper `/webtunnel`, copier
//! les adresses, les coller dans le navigateur. Le bot est un canal pour une
//! PERSONNE, pas pour un programme.
//!
//! La difference n'est pas academique. Ce qui fait passer Telegram la ou tout
//! est bloque, c'est l'application elle-meme: ses proxys MTProto, et la mise a
//! jour d'avril 2026 qui deguise son trafic en trafic de navigateur. Un
//! programme qui ferait un GET sur `api.telegram.org` n'heriterait d'aucun de
//! ces contournements. Il serait exactement aussi bloquable qu'un GET sur
//! n'importe quel domaine - en pire, `telegram.org` etant nommement cible: au
//! 10 avril 2026, 95% des connexions Telegram echouent en Russie sans VPN.
//!
//! Ecrire ce client aurait donc ajoute une dependance a une API a jeton pour un
//! canal MOINS resistant qu'un miroir HTTPS quelconque. Ce qui manquait n'etait
//! pas un client d'API: c'etait le chemin par lequel une personne fait entrer un
//! profil recu dans n'importe quelle messagerie, un QR code, un courriel, un
//! SMS. Ce module est ce chemin, et il sert Telegram exactement comme Tor s'en
//! sert.
//!
//! # Ce que le format doit supporter
//!
//! Une messagerie n'est pas un tuyau propre: elle replie les longues lignes,
//! insere des retours, parfois des espaces. Un profil TOML et une signature
//! minisign colles tels quels y survivent mal - les deux sont multi-lignes, et
//! la signature ne tolere pas qu'on touche a ses lignes. D'ou une chaine unique
//! en base64url sans remplissage: pas de `+`, pas de `/`, pas de `=` que les URL
//! et les messageries transforment, et tout espace blanc est ignore a la
//! lecture.
//!
//! Le prefixe porte un NUMERO DE VERSION. Un format qu'on colle vit longtemps -
//! il traine dans des messages, des carnets, des captures d'ecran - et le jour
//! ou il faudra en changer, un lien de l'ancien monde doit etre refuse en le
//! disant, pas mal interprete.
//!
//! # Deux formes, et pourquoi la seconde existe
//!
//! Un lien nu est **signe, pas chiffre**. La signature protege son authenticite
//! quel que soit le chemin parcouru, ce qui est tout l'interet. Mais le profil y
//! est en base64, c'est-a-dire ENCODE ET NON CHIFFRE, et un profil porte une cle
//! privee. Le base64 a l'apparence du secret sans en avoir l'effet, et c'est le
//! genre de malentendu qui fait publier une cle dans un canal public.
//!
//! Ce qui fuit alors n'est d'ailleurs pas d'abord la cle: c'est **l'adresse du
//! serveur**. Un lien intercepte brule le serveur, ce qui est exactement le
//! dommage que ce produit existe pour eviter.
//!
//! D'ou la seconde forme, chiffree, que le plan reclame en une ligne ("signes et
//! chiffres") sans dire comment.
//!
//! # Signer puis chiffrer, dans cet ordre
//!
//! Le lien signe entier est chiffre, plutot que de signer un chiffre. La raison
//! est pratique autant que theorique: une signature posee sur du chiffre
//! n'authentifie que le chiffre, et ne dirait rien du profil - alors qu'ici, ce
//! qui sort du dechiffrement EST le lien nu, que le reste de la chaine sait deja
//! verifier et installer sans rien changer.
//!
//! La faiblesse connue de cet ordre est le renvoi subreptice: un destinataire
//! peut rechiffrer pour un tiers un profil signe qu'il a recu, et se donner
//! l'air d'en etre le destinataire prevu. Ici cela ne mene nulle part - le
//! profil reste celui du meme operateur, signe par lui, et le tiers n'obtient
//! rien qu'un profil authentique de quelqu'un d'autre.
//!
//! # Le chiffrement: age, par phrase de passe
//!
//! Le format est `age-encryption.org/v1`, celui de l'outil `age`, avec un
//! destinataire scrypt - donc une phrase de passe, sans echange prealable de
//! cles. Ce choix conserve la porte ouverte: `age` accepte plusieurs types de
//! destinataires dans un meme fichier, donc chiffrer un jour pour une cle
//! publique X25519 du destinataire n'obligera pas a changer le format du lien.
//!
//! **La phrase est engendree par le programme, jamais tapee par une personne.**
//! Une phrase choisie par un humain, dans un produit ou l'adversaire peut etre
//! un Etat, ne vaut pas le scrypt qui la protege. Et elle est affichee A PART du
//! lien, avec la seule consigne qui compte: la transmettre par un AUTRE chemin.
//! Envoyer la phrase et le lien dans la meme conversation ne protege de rien -
//! c'est le genre de geste qui donne le sentiment d'avoir chiffre sans l'avoir
//! fait.

use crate::{Canal, Recu};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// Ce qui ouvre un lien nu, version comprise.
pub const PREFIXE: &str = "bifrost1.";

/// Ce qui ouvre un lien chiffre.
///
/// Une forme distincte plutot qu'un drapeau a l'interieur: le lecteur doit
/// savoir AVANT de decoder s'il lui faut une phrase de passe, et le message qui
/// la reclame vaut mieux qu'un echec de decodage.
pub const PREFIXE_CHIFFRE: &str = "bifrost1c.";

/// Au-dela, ce n'est plus quelque chose qu'on colle.
///
/// Meme raison que les plafonds du canal HTTP, et meme ordre de grandeur: un
/// profil tient en deux kilo-octets. Ce qui arrive ici vient d'un inconnu tout
/// autant que ce qui arrive par le reseau.
const PLAFOND: usize = 64 * 1024;

/// Fabrique le lien a transmettre.
///
/// La signature est ELLE AUSSI reencodee, alors qu'elle est deja du texte: ses
/// quatre lignes ne survivraient pas au repliement d'une messagerie, et une
/// signature dont un retour a saute est une signature invalide - donc un canal
/// suspect, donc une alerte pour rien.
pub fn ecrire(profil: &[u8], signature: &str) -> String {
    format!(
        "{PREFIXE}{}.{}",
        URL_SAFE_NO_PAD.encode(profil),
        URL_SAFE_NO_PAD.encode(signature.as_bytes())
    )
}

/// L'alphabet d'une phrase de passe engendree.
///
/// Base32 de Crockford: ni `I`, ni `L`, ni `O`, ni `U`. Les trois premieres se
/// confondent avec `1` et `0` quand on dicte au telephone ou qu'on recopie
/// depuis une capture d'ecran, et la quatrieme evite qu'un mot desagreable
/// apparaisse par hasard. Trente-deux caracteres, donc cinq bits chacun sans
/// biais - 32 divise 256, et le masque `& 0x1F` est donc uniforme.
const ALPHABET: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Longueur de la phrase, en caracteres significatifs.
///
/// Vingt-quatre caracteres a cinq bits font 120 bits. Bien au-dela de ce que
/// scrypt aurait a proteger, ce qui est le but: la resistance ne doit pas
/// dependre du facteur de travail, parce qu'un facteur de travail se rattrape
/// avec du materiel et pas une entropie de 120 bits.
const LONGUEUR_PHRASE: usize = 24;

/// Engendre une phrase de passe, groupee pour etre dictee et recopiee.
pub fn engendrer_phrase() -> String {
    let mut octets = [0u8; LONGUEUR_PHRASE];
    // Un echec de la source d'alea du systeme n'est pas rattrapable: se replier
    // sur autre chose donnerait une phrase faible sans que personne ne le sache,
    // ce qui est pire que de s'arreter.
    getrandom::fill(&mut octets).expect("la source d'alea du systeme doit repondre");

    let mut phrase = String::with_capacity(LONGUEUR_PHRASE + LONGUEUR_PHRASE / 4);
    for (i, o) in octets.iter().enumerate() {
        if i > 0 && i % 4 == 0 {
            phrase.push('-');
        }
        phrase.push(ALPHABET[(o & 0x1F) as usize] as char);
    }
    phrase
}

/// Fabrique un lien chiffre a partir d'un profil signe.
pub fn ecrire_chiffre(profil: &[u8], signature: &str, phrase: &str) -> Result<String, String> {
    use std::io::Write;

    let nu = ecrire(profil, signature);
    let chiffreur =
        age::Encryptor::with_user_passphrase(age::secrecy::SecretString::from(phrase.to_string()));

    let mut chiffre = Vec::new();
    let mut sortie = chiffreur
        .wrap_output(&mut chiffre)
        .map_err(|e| format!("chiffrement impossible: {e}"))?;
    sortie
        .write_all(nu.as_bytes())
        .and_then(|()| sortie.finish().map(|_| ()))
        .map_err(|e| format!("chiffrement impossible: {e}"))?;

    Ok(format!(
        "{PREFIXE_CHIFFRE}{}",
        URL_SAFE_NO_PAD.encode(&chiffre)
    ))
}

/// Un lien colle par une personne.
pub struct Colle {
    lien: String,
    phrase: Option<String>,
}

impl Colle {
    pub fn nouveau(lien: impl Into<String>) -> Self {
        Self {
            lien: lien.into(),
            phrase: None,
        }
    }

    /// Le meme, avec de quoi le dechiffrer.
    pub fn avec_phrase(lien: impl Into<String>, phrase: impl Into<String>) -> Self {
        Self {
            lien: lien.into(),
            phrase: Some(phrase.into()),
        }
    }
}

impl Canal for Colle {
    /// Jamais le lien lui-meme: il porte une cle privee, et le nom d'un canal
    /// va dans le rapport, donc a l'ecran et dans ce que l'utilisateur recopie
    /// quand il demande de l'aide.
    fn nom(&self) -> String {
        "lien colle".to_string()
    }

    fn chercher(&self) -> Result<Recu, String> {
        lire(&self.lien, self.phrase.as_deref())
    }
}

/// Le lien est-il chiffre, avant toute tentative de le lire.
///
/// Publique parce que l'appelant doit pouvoir reclamer la phrase de passe avant
/// d'echouer, et surtout AVERTIR quand une phrase a ete fournie pour un lien qui
/// n'en avait pas besoin: croire avoir recu un lien protege quand il ne l'etait
/// pas est un malentendu qui ne se rattrape plus une fois le lien envoye.
pub fn est_chiffre(lien: &str) -> bool {
    lien.trim_start().starts_with(PREFIXE_CHIFFRE)
}

/// Decode un lien, en le dechiffrant s'il le faut.
pub fn lire(lien: &str, phrase: Option<&str>) -> Result<Recu, String> {
    // Tout espace blanc saute: c'est le point entier. Une messagerie qui replie
    // une chaine de huit cents caracteres y insere des retours, et l'utilisateur
    // qui recopie ajoute parfois une espace. Refuser pour cela ferait echouer le
    // canal sur du bruit de transport, pas sur son contenu.
    let propre: String = lien.chars().filter(|c| !c.is_whitespace()).collect();

    if let Some(chiffre) = propre.strip_prefix(PREFIXE_CHIFFRE) {
        let phrase = phrase.ok_or(
            "ce lien est chiffre: il faut la phrase de passe qui l'accompagne, \
             transmise par un autre chemin que le lien lui-meme",
        )?;
        let nu = dechiffrer(&decoder(chiffre, "le lien chiffre")?, phrase)?;
        // Une seule fois: le clair d'un lien chiffre est un lien nu, et un lien
        // nu ne contient pas de lien chiffre. Reappeler `lire` sans cette
        // precaution laisserait fabriquer des poupees russes dont le decodage
        // couterait autant que l'attaquant le voudrait.
        return lire(&nu, None);
    }

    let corps = propre.strip_prefix(PREFIXE).ok_or_else(|| {
        if let Some(version) = version_etrangere(&propre) {
            format!(
                "ce lien est en {version}, cette version de Bifrost lit {}. \
                 Un lien plus recent que le programme se refuse plutot qu'il ne \
                 se devine.",
                PREFIXE.trim_end_matches('.')
            )
        } else {
            format!("ceci ne commence pas par {PREFIXE}, ce n'est pas un lien Bifrost")
        }
    })?;

    let (profil, signature) = corps
        .split_once('.')
        .ok_or("lien incomplet: il manque la signature, ou le lien a ete coupe")?;

    let profil = decoder(profil, "le profil")?;
    let signature = decoder(signature, "la signature")?;
    let signature = String::from_utf8(signature)
        .map_err(|_| "la signature de ce lien n'est pas du texte".to_string())?;

    Ok(Recu { profil, signature })
}

/// Le nom de version d'un lien qui n'est pas le notre, s'il en a l'allure.
///
/// Sert a distinguer "ce n'est pas un lien Bifrost" de "c'est un lien Bifrost
/// d'une autre version": les deux se corrigent tres differemment.
fn version_etrangere(propre: &str) -> Option<&str> {
    let debut = propre.strip_prefix("bifrost")?;
    let fin = debut.find('.')?;
    Some(&propre[..7 + fin])
}

/// Dechiffre, et ne dit rien de plus que l'echec.
///
/// Le message ne distingue pas "mauvaise phrase" de "lien abime": les deux se
/// corrigent en redemandant a l'expediteur, et un message qui confirmerait
/// qu'une phrase est presque bonne rendrait service a qui les essaie.
fn dechiffrer(chiffre: &[u8], phrase: &str) -> Result<String, String> {
    use std::io::Read;

    let dechiffreur = age::Decryptor::new(chiffre)
        .map_err(|_| "ce lien chiffre est illisible: il a ete abime en chemin".to_string())?;
    let identite = age::scrypt::Identity::new(age::secrecy::SecretString::from(phrase.to_string()));

    let mut lecture = dechiffreur
        .decrypt(std::iter::once(&identite as &dyn age::Identity))
        .map_err(|_| {
            "ce lien ne s'ouvre pas avec cette phrase de passe: la verifier \
             caractere par caractere, ou la redemander a l'expediteur"
                .to_string()
        })?;

    let mut nu = String::new();
    lecture
        .read_to_string(&mut nu)
        .map_err(|_| "le contenu de ce lien chiffre n'est pas du texte".to_string())?;
    Ok(nu)
}

fn decoder(morceau: &str, quoi: &str) -> Result<Vec<u8>, String> {
    // Avant de decoder, pas apres: decoder d'abord ferait allouer la memoire que
    // le plafond existe pour refuser.
    if morceau.len() > PLAFOND {
        return Err(format!(
            "{quoi} de ce lien fait {} caracteres, au-dela de ce qui se colle",
            morceau.len()
        ));
    }
    URL_SAFE_NO_PAD
        .decode(morceau)
        .map_err(|e| format!("{quoi} de ce lien est illisible: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIGNATURE: &str =
        "untrusted comment: signature\nRWQABBBB\ntrusted comment: serie=1\nGLOBALE\n";

    #[test]
    fn un_lien_fait_l_aller_et_le_retour() {
        let lien = ecrire(b"interface = \"wg0\"", SIGNATURE);
        let recu = lire(&lien, None).expect("son propre lien doit se relire");
        assert_eq!(recu.profil, b"interface = \"wg0\"");
        assert_eq!(recu.signature, SIGNATURE);
    }

    /// Le cas d'usage reel: une messagerie a replie la chaine.
    ///
    /// Sans cette tolerance, le canal echouerait sur du bruit de transport, et
    /// l'utilisateur ne saurait pas que son lien etait bon.
    #[test]
    fn les_retours_a_la_ligne_d_une_messagerie_sont_ignores() {
        let lien = ecrire(b"interface = \"wg0\"", SIGNATURE);
        let milieu = lien.len() / 2;
        let replie = format!("{}\n  {}\n", &lien[..milieu], &lien[milieu..]);

        let recu = lire(&replie, None).expect("un lien replie doit se lire");
        assert_eq!(recu.profil, b"interface = \"wg0\"");
    }

    /// L'encodage ne doit produire aucun caractere qu'une URL ou une messagerie
    /// transforme.
    #[test]
    fn le_lien_ne_contient_que_des_caracteres_qui_voyagent() {
        // Des octets choisis pour produire `+`, `/` et `=` en base64 ordinaire.
        let lien = ecrire(&[0xfb, 0xff, 0xbf, 0x00], SIGNATURE);
        assert!(
            !lien.contains('+') && !lien.contains('/') && !lien.contains('='),
            "caractere fragile dans le lien: {lien}"
        );
    }

    #[test]
    fn ce_qui_n_est_pas_un_lien_bifrost_le_dit() {
        let e = lire("https://exemple/tunnel.toml", None).expect_err("doit etre refuse");
        assert!(e.contains(PREFIXE), "{e}");
    }

    /// Une version future se refuse en la nommant, jamais en la devinant.
    #[test]
    fn un_lien_d_une_autre_version_est_distingue() {
        let e = lire("bifrost2.AAAA.BBBB", None).expect_err("doit etre refuse");
        assert!(e.contains("bifrost2"), "la version doit etre nommee: {e}");
        assert!(e.contains("bifrost1"), "et celle qu'on lit aussi: {e}");
    }

    #[test]
    fn un_lien_coupe_se_plaint_de_l_etre() {
        let e = lire("bifrost1.QUJD", None).expect_err("doit etre refuse");
        assert!(e.contains("coupe") || e.contains("incomplet"), "{e}");
    }

    #[test]
    fn un_base64_invalide_dit_quelle_moitie_est_en_cause() {
        let e = lire("bifrost1.!!!!.QUJD", None).expect_err("doit etre refuse");
        assert!(e.contains("profil"), "{e}");
    }

    /// Le nom du canal ne divulgue pas le lien, qui porte la cle privee.
    #[test]
    fn le_nom_du_canal_ne_montre_pas_le_lien() {
        let lien = ecrire(b"private_key = \"SECRET\"", SIGNATURE);
        let c = Colle::nouveau(&lien);
        assert!(!c.nom().contains("bifrost1"), "{}", c.nom());
        assert!(!c.nom().contains("SECRET"), "{}", c.nom());
    }

    // ------------------------------------------------------- la forme chiffree

    const PROFIL: &[u8] = b"endpoint = { addr = \"203.0.113.7:51820\" }";

    #[test]
    fn un_lien_chiffre_fait_l_aller_et_le_retour() {
        let phrase = engendrer_phrase();
        let lien = ecrire_chiffre(PROFIL, SIGNATURE, &phrase).expect("doit chiffrer");

        let recu = lire(&lien, Some(&phrase)).expect("doit se dechiffrer");
        assert_eq!(recu.profil, PROFIL);
        assert_eq!(recu.signature, SIGNATURE);
    }

    /// Ce que le chiffrement doit reellement cacher.
    ///
    /// Pas d'abord la cle privee: **l'adresse du serveur**. Un lien intercepte
    /// qui la revele brule le serveur, ce qui est le dommage que ce produit
    /// existe pour eviter. Le lien nu, lui, la porte en base64 - la recette le
    /// montre a cote, pour que la difference entre les deux formes soit une
    /// mesure et non une affirmation.
    #[test]
    fn le_lien_chiffre_ne_laisse_pas_voir_le_serveur() {
        let phrase = engendrer_phrase();
        let chiffre = ecrire_chiffre(PROFIL, SIGNATURE, &phrase).unwrap();
        let nu = ecrire(PROFIL, SIGNATURE);

        let en_base64 = URL_SAFE_NO_PAD.encode(PROFIL);
        assert!(
            nu.contains(&en_base64),
            "temoin: le lien nu porte bien le profil encode"
        );
        assert!(
            !chiffre.contains(&en_base64) && !chiffre.contains("203.0.113.7"),
            "le lien chiffre laisse voir le serveur"
        );

        // Et surtout: le contenu EST un fichier age. Sans cette derniere
        // verification, la recette passerait pour un simple double encodage -
        // mesure en remplacant le chiffrement par `encode(encode(profil))`, qui
        // ne fait apparaitre aucun des deux motifs ci-dessus. Un nom de recette
        // qui promet le chiffrement doit mesurer le chiffrement.
        let brut = URL_SAFE_NO_PAD
            .decode(chiffre.strip_prefix(PREFIXE_CHIFFRE).unwrap())
            .unwrap();
        assert!(
            brut.starts_with(b"age-encryption.org/v1"),
            "le contenu n'est pas un fichier age: {:?}",
            String::from_utf8_lossy(&brut[..brut.len().min(32)])
        );
    }

    #[test]
    fn les_deux_formes_se_distinguent_avant_toute_lecture() {
        let phrase = engendrer_phrase();
        assert!(est_chiffre(
            &ecrire_chiffre(PROFIL, SIGNATURE, &phrase).unwrap()
        ));
        assert!(!est_chiffre(&ecrire(PROFIL, SIGNATURE)));
        // Y compris replie par une messagerie, qui indente.
        assert!(est_chiffre(&format!(
            "  \n{}",
            ecrire_chiffre(PROFIL, SIGNATURE, &phrase).unwrap()
        )));
    }

    #[test]
    fn un_lien_chiffre_sans_phrase_reclame_la_phrase() {
        let lien = ecrire_chiffre(PROFIL, SIGNATURE, &engendrer_phrase()).unwrap();
        let e = lire(&lien, None).expect_err("doit reclamer la phrase");
        assert!(e.contains("phrase de passe"), "{e}");
        assert!(
            e.contains("autre chemin"),
            "et dire par ou elle doit venir: {e}"
        );
    }

    /// Le message d'echec ne renseigne pas qui essaie des phrases.
    #[test]
    fn une_mauvaise_phrase_est_refusee_sans_rien_confirmer() {
        let bonne = engendrer_phrase();
        let lien = ecrire_chiffre(PROFIL, SIGNATURE, &bonne).unwrap();

        // Une phrase a un caractere pres: rien dans le message ne doit le
        // laisser deviner.
        //
        // Le caractere de remplacement doit DIFFERER du dernier, et se choisir
        // plutot que s'ecrire en dur. `ALPHABET` est du base32 Crockford: il
        // CONTIENT "X", donc une phrase finissant par "X" faisait de la
        // "mauvaise" phrase la bonne, `lire` reussissait et `expect_err`
        // paniquait. Une fois sur 32, soit assez rare pour passer pour un
        // hasard de charge et assez frequent pour salir une ronde de
        // falsifications - ce qu'il a fait le 20 aout 2026.
        let dernier = bonne
            .chars()
            .next_back()
            .expect("une phrase n'est pas vide");
        let autre = if dernier == 'X' { 'Y' } else { 'X' };
        let presque = format!("{}{autre}", &bonne[..bonne.len() - 1]);
        let e = lire(&lien, Some(&presque)).expect_err("doit etre refusee");
        assert!(
            !e.contains(&bonne),
            "la bonne phrase ne doit pas fuiter: {e}"
        );
        assert!(
            !e.to_lowercase().contains("presque") && !e.to_lowercase().contains("proche"),
            "rien ne doit confirmer une approche: {e}"
        );
    }

    #[test]
    fn un_lien_chiffre_replie_se_lit_quand_meme() {
        let phrase = engendrer_phrase();
        let lien = ecrire_chiffre(PROFIL, SIGNATURE, &phrase).unwrap();
        let milieu = lien.len() / 2;
        let replie = format!("  {}\n   {}\n", &lien[..milieu], &lien[milieu..]);

        let recu = lire(&replie, Some(&phrase)).expect("un lien chiffre replie doit se lire");
        assert_eq!(recu.profil, PROFIL);
    }

    /// Un lien chiffre qui en contient un autre n'est pas ouvert deux fois.
    ///
    /// Sans cette borne, un lien pourrait couter autant de dechiffrements que
    /// son auteur le voudrait - chacun payant un scrypt.
    #[test]
    fn les_poupees_russes_s_arretent_a_la_premiere() {
        let phrase = engendrer_phrase();
        let interieur = ecrire_chiffre(PROFIL, SIGNATURE, &phrase).unwrap();
        // Un lien chiffre dont le clair est lui-meme un lien chiffre.
        let dehors = {
            use std::io::Write;
            let c = age::Encryptor::with_user_passphrase(age::secrecy::SecretString::from(
                phrase.clone(),
            ));
            let mut v = Vec::new();
            let mut w = c.wrap_output(&mut v).unwrap();
            w.write_all(interieur.as_bytes()).unwrap();
            w.finish().unwrap();
            format!("{PREFIXE_CHIFFRE}{}", URL_SAFE_NO_PAD.encode(&v))
        };

        let e = lire(&dehors, Some(&phrase)).expect_err("la seconde couche ne doit pas s'ouvrir");
        assert!(e.contains("phrase de passe"), "{e}");
    }

    #[test]
    fn la_phrase_engendree_evite_les_caracteres_qui_se_confondent() {
        let phrase = engendrer_phrase();
        assert_eq!(
            phrase.chars().filter(|c| *c != '-').count(),
            LONGUEUR_PHRASE
        );
        for interdit in ['I', 'L', 'O', 'U'] {
            assert!(
                !phrase.contains(interdit),
                "{interdit} se confond a la dictee: {phrase}"
            );
        }
    }

    /// Deux phrases engendrees ne se ressemblent pas.
    ///
    /// Le controle le plus grossier qui soit, et le seul qui attraperait une
    /// source d'alea muette rendant toujours les memes octets.
    #[test]
    fn deux_phrases_engendrees_different() {
        let a = engendrer_phrase();
        let b = engendrer_phrase();
        assert_ne!(a, b);
    }

    /// La phrase engendree porte au moins 120 bits, et le calcul est ecrit.
    ///
    /// `la_phrase_engendree_evite_les_caracteres_qui_se_confondent` compte les
    /// caracteres et compare le compte a `LONGUEUR_PHRASE`, c'est-a-dire au
    /// nombre d'octets que la meme fonction vient de tirer. Elle eprouve donc
    /// le groupage par quatre et l'alphabet, jamais la LONGUEUR. Mesure du
    /// 23 aout 2026 sur dev-windows: avec `LONGUEUR_PHRASE` a 6, les dix-huit
    /// recettes du module restaient vertes, et la phrase tombait a trente bits,
    /// cassable hors ligne quel que soit le facteur de travail de scrypt. C'est
    /// exactement ce que l'en-tete de ce module s'engage a eviter.
    ///
    /// Le seuil est un PLANCHER et non une egalite: allonger la phrase est
    /// toujours legitime, la raccourcir est le defaut a attraper.
    #[test]
    fn la_phrase_engendree_porte_l_entropie_annoncee() {
        // Cinq bits par caractere ne valent que si l'alphabet en compte
        // exactement trente-deux: `& 0x1F` tire un indice sur 0..=31, donc un
        // alphabet plus court ferait paniquer et un alphabet plus long
        // laisserait ses derniers caracteres inatteignables.
        assert_eq!(
            ALPHABET.len(),
            32,
            "le masque & 0x1F suppose trente-deux caracteres"
        );
        let bits = LONGUEUR_PHRASE * 5;
        assert!(
            bits >= 120,
            "{LONGUEUR_PHRASE} caracteres font {bits} bits: sous les 120 bits              annonces, la phrase redevient attaquable hors ligne"
        );
    }

    /// Les deux prefixes se distinguent AVANT tout decodage.
    ///
    /// `lire` essaie `PREFIXE_CHIFFRE` puis `PREFIXE`. Si l'un ouvrait l'autre,
    /// un lien nu serait pris pour un lien chiffre ou l'inverse, et l'erreur
    /// rendue parlerait de base64 au lieu de reclamer la phrase de passe.
    /// Aucune recette ne le disait: toutes fabriquent le lien avec la meme
    /// constante qu'elles relisent ensuite.
    #[test]
    fn les_deux_prefixes_ne_s_ouvrent_pas_l_un_l_autre() {
        assert_eq!(PREFIXE, "bifrost1.");
        assert_eq!(PREFIXE_CHIFFRE, "bifrost1c.");
        assert!(
            !PREFIXE_CHIFFRE.starts_with(PREFIXE),
            "un lien chiffre serait lu comme un lien nu: {PREFIXE_CHIFFRE} / {PREFIXE}"
        );
        assert!(
            !PREFIXE.starts_with(PREFIXE_CHIFFRE),
            "un lien nu serait lu comme un lien chiffre: {PREFIXE} / {PREFIXE_CHIFFRE}"
        );
    }

    #[test]
    fn un_lien_demesure_est_refuse_avant_d_etre_decode() {
        let enorme = format!("{PREFIXE}{}.QUJD", "A".repeat(PLAFOND + 1));
        let e = lire(&enorme, None).expect_err("doit etre refuse");
        assert!(e.contains("au-dela"), "{e}");
    }
}
