//! Aller chercher un profil la ou il se trouve, par plusieurs chemins a la fois.
//!
//! # Pourquoi plusieurs canaux, et ce que cela demande vraiment
//!
//! Le document 04 partie 381 en veut trois: subscription sur domaine CDN,
//! miroir GitHub raw, bot Telegram. La raison affichee est la disponibilite -
//! un canal bloque, un autre repond. Mais un multi-canal naif ne fait que
//! MULTIPLIER LES POINTS D'INJECTION: trois endroits d'ou peut venir un faux
//! profil au lieu d'un seul.
//!
//! Ce qui renverse le compte, c'est la signature: elle deplace la confiance du
//! canal vers la cle, et rend alors chaque canal supplementaire gratuit. C'est
//! l'ordre dans lequel ces deux lots ont ete faits, et il n'etait pas
//! interchangeable.
//!
//! # Deux decisions qui distinguent ce module d'un `telecharger le premier`
//!
//! **Tous les canaux sont interroges, et la serie la plus haute gagne.**
//! S'arreter au premier qui repond suffirait contre une panne, pas contre un
//! adversaire: qui controle un canal n'aurait qu'a se placer en tete et servir
//! un vieux profil authentique, dont le serveur est brule ou lui appartient
//! desormais. En retenant la serie la plus haute de TOUS les canaux, il lui faut
//! aussi faire taire les autres. C'est ce qui donne sa valeur au multi-canal
//! contre quelqu'un, et pas seulement contre une panne.
//!
//! **Un canal qui sert une mauvaise signature est ecarte, pas fatal.** Traiter
//! une signature invalide comme une erreur laisserait un seul miroir empoisonne
//! empecher toute mise a jour - un deni de service a un contre trois, sur le
//! mecanisme meme cense y resister. Le canal est donc ecarte comme un canal en
//! panne, et la moisson continue.
//!
//! # Ce que le rapport distingue, et pourquoi cela compte
//!
//! Un canal MUET et un canal SUSPECT echouent tous deux, et il serait tentant de
//! les confondre. Ils ne disent pourtant pas la meme chose: trois canaux muets,
//! c'est un reseau qui filtre; un canal suspect, c'est quelqu'un qui sert autre
//! chose que ce que notre cle reconnait - un miroir corrompu, ou une tentative.
//! Le premier appelle a changer de chemin, le second a changer de miroir et a
//! s'inquieter. Les fondre en un "echec" priverait l'utilisateur de la seule
//! information qui distingue une panne d'une attaque.
//!
//! # Ce qui n'est pas ici
//!
//! Un client d'API **Telegram**, et pour une raison mesuree plutot que par
//! manque de temps: Tor Browser, que le plan cite en exemple, n'interroge jamais
//! Telegram - c'est une personne qui parle au bot depuis son application, puis
//! qui colle. Ce qui fait passer Telegram est l'application elle-meme, dont un
//! GET sur `api.telegram.org` n'heriterait pas. Le chemin humain est servi par
//! [`colle`], qui vaut pour toute messagerie, un QR code ou un SMS. Le
//! **mimetisme d'empreinte TLS**
//! (JA3/JA4) aussi: `wreq` le fait, au prix de BoringSSL, donc de `cmake` et de
//! Go dans la chaine de construction. La pile retenue est rustls avec aws-lc-rs,
//! qui presente une empreinte ordinaire et porte les echanges de cles
//! post-quantiques - ce qui, en 2026, ressemble davantage au trafic courant
//! qu'un ClientHello qui n'en a pas.

#![forbid(unsafe_code)]

pub mod colle;
pub mod fichier;
pub mod toile;

use bifrost_coffre::signature::{Origine, verifier};

/// Ce qu'un canal a rendu: le profil et sa signature detachee.
pub struct Recu {
    pub profil: Vec<u8>,
    pub signature: String,
}

/// Ecrit a la main, et jamais derive.
///
/// `profil` EST le secret - c'est le fichier qui porte la cle privee. Un
/// `derive` le deverserait dans le premier `expect_err` d'une recette et dans
/// le premier message d'erreur qui encadre un `Recu`, donc dans le journal. Le
/// depot applique deja cette regle a `Ouvert`, a `WgKey` et a `MotDePasse`. La
/// signature, elle, s'imprime: elle est publique par construction.
impl std::fmt::Debug for Recu {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Recu")
            .field(
                "profil",
                &format_args!("<{} octets tus>", self.profil.len()),
            )
            .field("signature", &self.signature)
            .finish()
    }
}

/// Un endroit d'ou un profil peut venir.
///
/// Rend une `String` en erreur et non une erreur typee: du point de vue de la
/// politique, tous les echecs de transport se valent - il n'y a rien a decider
/// differemment selon qu'un nom ne resout pas ou qu'un serveur rend 404. Ce qui
/// compte est le texte, qui ira dans le rapport lu par un humain.
pub trait Canal {
    /// Comment ce canal se nomme dans le rapport. Jamais un secret.
    fn nom(&self) -> String;
    fn chercher(&self) -> Result<Recu, String>;
}

/// Ce qu'un canal a donne, une fois juge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Issue {
    /// Signe par la cle de confiance. La serie, si elle est declaree.
    Authentique(Option<u64>),
    /// A repondu, mais pas avec quelque chose que notre cle reconnait.
    ///
    /// Distinct de [`Issue::Muet`] deliberement: ce n'est pas une panne.
    Suspect(String),
    /// N'a rien rendu du tout.
    Muet(String),
}

/// Le passage par un canal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Passage {
    pub canal: String,
    pub issue: Issue,
}

/// Le profil retenu, et d'ou il vient.
pub struct Retenu {
    pub canal: String,
    pub profil: Vec<u8>,
    pub signature: String,
    pub origine: Origine,
}

/// Ce qu'une recuperation a donne.
///
/// Jamais une erreur, meme quand tout echoue: le journal EST le resultat, et il
/// dit plus qu'un message unique - lequel des trois canaux a repondu, lequel
/// s'est tu, lequel a servi autre chose.
pub struct Moisson {
    pub retenu: Option<Retenu>,
    pub journal: Vec<Passage>,
}

impl Moisson {
    /// Y a-t-il eu quelqu'un pour servir autre chose que ce qu'on attendait.
    ///
    /// Se lit meme quand la moisson a reussi: un canal suspect a cote de deux
    /// canaux sains reste une nouvelle, et l'ecraser sous le succes des autres
    /// serait taire la seule chose anormale de la journee.
    pub fn suspects(&self) -> impl Iterator<Item = &Passage> {
        self.journal
            .iter()
            .filter(|p| matches!(p.issue, Issue::Suspect(_)))
    }
}

/// Interroge tous les canaux et retient le meilleur profil.
///
/// L'ordre des canaux ne departage qu'a serie egale: le premier a avoir repondu
/// l'emporte alors. C'est le seul endroit ou leur ordre compte.
pub fn recuperer(canaux: &[Box<dyn Canal>], cle_publique: &str) -> Moisson {
    let mut journal = Vec::with_capacity(canaux.len());
    let mut retenu: Option<Retenu> = None;

    for canal in canaux {
        let nom = abreger(&canal.nom());
        let issue = match canal.chercher() {
            Err(pourquoi) => Issue::Muet(pourquoi),
            Ok(recu) => match verifier(&recu.profil, &recu.signature, cle_publique) {
                Err(e) => Issue::Suspect(format!("{e:#}")),
                Ok(origine) => {
                    let serie = origine.serie;
                    if merite_d_etre_retenu(retenu.as_ref(), serie) {
                        retenu = Some(Retenu {
                            canal: nom.clone(),
                            profil: recu.profil,
                            signature: recu.signature,
                            origine,
                        });
                    }
                    Issue::Authentique(serie)
                }
            },
        };
        journal.push(Passage { canal: nom, issue });
    }

    Moisson { retenu, journal }
}

/// Un nom de canal, ramene a ce qui se lit.
///
/// Le nom vient du canal, donc d'une designation que l'utilisateur a tapee ou
/// collee - et un lien colle fait huit cents caracteres dont la moitie est une
/// cle privee encodee. Cela s'est produit: un lien replie par une messagerie
/// commence par des espaces, echappe a la reconnaissance de son prefixe, passe
/// pour un chemin de fichier, et le rapport le deverse entier a l'ecran.
///
/// La reconnaissance a ete corrigee, et ceci reste: un rapport n'a pas besoin de
/// plus de cent caracteres pour designer un canal, et cette borne vaut pour tous
/// les canaux, y compris ceux qui n'existent pas encore.
fn abreger(nom: &str) -> String {
    const LARGEUR: usize = 100;
    let compte = nom.chars().count();
    if compte <= LARGEUR {
        return nom.to_string();
    }
    let debut: String = nom.chars().take(LARGEUR).collect();
    format!("{debut}... ({compte} caracteres)")
}

/// Le nouveau venu remplace-t-il celui qu'on tenait.
///
/// Un profil SANS serie ne remplace jamais un profil qui en a une, quel que soit
/// son rang dans la liste: sans quoi un canal place plus loin desarmerait le
/// classement en omettant simplement le champ. C'est la meme regle que celle qui
/// refuse la retrogradation a l'installation, et pour la meme raison.
fn merite_d_etre_retenu(tenu: Option<&Retenu>, serie: Option<u64>) -> bool {
    match (tenu.and_then(|r| r.origine.serie), serie) {
        (_, None) => tenu.is_none(),
        (None, Some(_)) => true,
        (Some(ancienne), Some(neuve)) => neuve > ancienne,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Un canal de recette: rend ce qu'on lui a mis dedans.
    struct Doublure {
        nom: String,
        reponse: Result<Recu, String>,
    }

    impl Canal for Doublure {
        fn nom(&self) -> String {
            self.nom.clone()
        }
        fn chercher(&self) -> Result<Recu, String> {
            match &self.reponse {
                Ok(r) => Ok(Recu {
                    profil: r.profil.clone(),
                    signature: r.signature.clone(),
                }),
                Err(e) => Err(e.clone()),
            }
        }
    }

    struct Signataire(minisign::KeyPair);

    impl Signataire {
        fn nouveau() -> Self {
            Self(minisign::KeyPair::generate_unencrypted_keypair().unwrap())
        }
        fn cle(&self) -> String {
            self.0.pk.to_base64()
        }
        fn signe(&self, profil: &[u8], commentaire: &str) -> Recu {
            let signature = minisign::sign(
                None,
                &self.0.sk,
                std::io::Cursor::new(profil),
                Some(commentaire),
                None,
            )
            .unwrap()
            .into_string();
            Recu {
                profil: profil.to_vec(),
                signature,
            }
        }
    }

    fn canal(nom: &str, reponse: Result<Recu, String>) -> Box<dyn Canal> {
        Box::new(Doublure {
            nom: nom.to_string(),
            reponse,
        })
    }

    #[test]
    fn un_seul_canal_sain_suffit() {
        let s = Signataire::nouveau();
        let canaux = vec![canal("miroir", Ok(s.signe(b"a = 1", "serie=1")))];

        let m = recuperer(&canaux, &s.cle());
        let r = m.retenu.expect("un canal sain doit rendre un profil");
        assert_eq!(r.canal, "miroir");
        assert_eq!(r.origine.serie, Some(1));
        assert_eq!(m.journal[0].issue, Issue::Authentique(Some(1)));
    }

    /// La decision qui distingue ce module d'un `telecharger le premier`.
    #[test]
    fn la_serie_la_plus_haute_gagne_meme_en_derniere_position() {
        let s = Signataire::nouveau();
        let canaux = vec![
            canal("cdn", Ok(s.signe(b"vieux", "serie=2"))),
            canal("github", Ok(s.signe(b"moyen", "serie=5"))),
            canal("secours", Ok(s.signe(b"neuf", "serie=9"))),
        ];

        let m = recuperer(&canaux, &s.cle());
        let r = m.retenu.unwrap();
        assert_eq!(r.canal, "secours", "le plus recent doit gagner");
        assert_eq!(r.profil, b"neuf");
        // Et les trois sont journalises: aucun n'est passe sous silence.
        assert_eq!(m.journal.len(), 3);
    }

    /// Le rejeu depuis un canal place en tete ne gagne pas.
    ///
    /// C'est l'attaque que le multi-canal est cense couvrir et qu'un
    /// `premier qui repond` laisserait passer.
    #[test]
    fn un_vieux_profil_authentique_en_tete_ne_l_emporte_pas() {
        let s = Signataire::nouveau();
        let canaux = vec![
            canal(
                "controle-par-l-adversaire",
                Ok(s.signe(b"brule", "serie=1")),
            ),
            canal("miroir-honnete", Ok(s.signe(b"courant", "serie=12"))),
        ];

        let r = recuperer(&canaux, &s.cle()).retenu.unwrap();
        assert_eq!(r.profil, b"courant");
    }

    /// Un miroir empoisonne n'empeche pas les autres de servir.
    #[test]
    fn une_mauvaise_signature_ecarte_le_canal_sans_tout_arreter() {
        let vrai = Signataire::nouveau();
        let faux = Signataire::nouveau();
        let canaux = vec![
            canal("empoisonne", Ok(faux.signe(b"piege", "serie=99"))),
            canal("sain", Ok(vrai.signe(b"bon", "serie=1"))),
        ];

        let m = recuperer(&canaux, &vrai.cle());
        assert!(
            matches!(m.journal[0].issue, Issue::Suspect(_)),
            "le canal empoisonne doit etre suspect, pas muet: {:?}",
            m.journal[0].issue
        );
        assert_eq!(m.suspects().count(), 1);
        let r = m.retenu.expect("le canal sain doit encore servir");
        assert_eq!(r.profil, b"bon");
    }

    /// Muet et suspect ne se confondent pas.
    #[test]
    fn un_canal_qui_se_tait_et_un_canal_qui_ment_se_distinguent() {
        let s = Signataire::nouveau();
        let faux = Signataire::nouveau();
        let canaux = vec![
            canal("bloque", Err("le nom ne resout pas".into())),
            canal("menteur", Ok(faux.signe(b"x", "serie=1"))),
        ];

        let m = recuperer(&canaux, &s.cle());
        assert!(m.retenu.is_none());
        assert!(matches!(m.journal[0].issue, Issue::Muet(_)));
        assert!(matches!(m.journal[1].issue, Issue::Suspect(_)));
        // Un canal bloque n'est pas une tentative: il ne doit pas alarmer.
        assert_eq!(m.suspects().count(), 1);
    }

    #[test]
    fn tous_muets_ne_rend_rien_mais_dit_tout() {
        let s = Signataire::nouveau();
        let canaux = vec![
            canal("cdn", Err("delai depasse".into())),
            canal("github", Err("404".into())),
        ];

        let m = recuperer(&canaux, &s.cle());
        assert!(m.retenu.is_none());
        assert_eq!(m.journal.len(), 2);
        assert_eq!(m.journal[1].issue, Issue::Muet("404".into()));
        assert_eq!(m.suspects().count(), 0);
    }

    #[test]
    fn sans_aucune_serie_le_premier_qui_repond_gagne() {
        let s = Signataire::nouveau();
        let canaux = vec![
            canal("premier", Ok(s.signe(b"un", "sans numero"))),
            canal("second", Ok(s.signe(b"deux", "sans numero non plus"))),
        ];

        let r = recuperer(&canaux, &s.cle()).retenu.unwrap();
        assert_eq!(r.canal, "premier");
    }

    /// Omettre la serie ne doit pas permettre de doubler celui qui en a une.
    #[test]
    fn un_profil_sans_serie_ne_deloge_pas_un_profil_qui_en_a_une() {
        let s = Signataire::nouveau();
        let canaux = vec![
            canal("numerote", Ok(s.signe(b"numerote", "serie=3"))),
            canal("anonyme", Ok(s.signe(b"anonyme", "aucune serie"))),
        ];

        let r = recuperer(&canaux, &s.cle()).retenu.unwrap();
        assert_eq!(r.profil, b"numerote");
    }

    /// Et l'inverse: une serie deloge un profil qui n'en avait pas.
    #[test]
    fn une_serie_deloge_un_profil_qui_n_en_a_pas() {
        let s = Signataire::nouveau();
        let canaux = vec![
            canal("anonyme", Ok(s.signe(b"anonyme", "rien"))),
            canal("numerote", Ok(s.signe(b"numerote", "serie=1"))),
        ];

        let r = recuperer(&canaux, &s.cle()).retenu.unwrap();
        assert_eq!(r.profil, b"numerote");
    }

    /// Le profil ne s'imprime pas, meme quand un `expect_err` le reclame.
    #[test]
    fn le_profil_ne_s_imprime_pas() {
        let recu = Recu {
            profil: b"private_key = \"SECRET-A-NE-PAS-VOIR\"".to_vec(),
            signature: "untrusted comment: x".into(),
        };
        let dit = format!("{recu:?}");
        assert!(!dit.contains("SECRET"), "le profil a fuite: {dit}");
        assert!(dit.contains("octets tus"), "{dit}");
    }

    /// Un canal au nom demesure ne deverse pas ce nom dans le rapport.
    ///
    /// Le cas reel: un lien colle pris pour un chemin de fichier. Le rapport
    /// affichait alors la cle privee encodee, en entier.
    #[test]
    fn un_nom_de_canal_demesure_est_abrege() {
        let s = Signataire::nouveau();
        let long = format!("bifrost1.{}", "S3CRET".repeat(200));
        let canaux = vec![canal(&long, Err("peu importe".into()))];

        let m = recuperer(&canaux, &s.cle());
        let nom = &m.journal[0].canal;
        assert!(
            nom.chars().count() < 140,
            "nom de {} caracteres",
            nom.chars().count()
        );
        assert!(
            nom.contains("caracteres"),
            "l'abregement doit se voir: {nom}"
        );
    }

    #[test]
    fn sans_canal_la_moisson_est_vide_et_ne_panique_pas() {
        let s = Signataire::nouveau();
        let m = recuperer(&[], &s.cle());
        assert!(m.retenu.is_none());
        assert!(m.journal.is_empty());
    }
}
