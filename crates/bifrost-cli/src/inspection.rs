//! La sonde d'inspection TLS: quelqu'un dechiffre-t-il ce qui sort d'ici.
//!
//! # Ce que le plan demandait, et pourquoi il faut le corriger
//!
//! Le document 04 partie 3.1 prescrit "un domaine dont on connait l'empreinte
//! de chaine" et une comparaison au pin. Cette forme-la n'est plus tenable, et
//! la date de peremption est publique: le CA/Browser Forum a adopte le scrutin
//! SC-081v3 en avril 2025, qui ramene la duree de vie maximale d'un certificat
//! public a **200 jours depuis le 15 mars 2026**, puis 100 jours en mars 2027 et
//! 47 jours en mars 2029. Une empreinte de certificat epinglee vieillirait donc
//! en quelques mois, et la sonde annoncerait "votre reseau est intercepte" a
//! chaque renouvellement. C'est le pire faux positif possible pour ce produit:
//! il accuse le reseau de l'utilisateur d'une chose qu'il ne fait pas.
//!
//! # Ce qui est epingle a la place
//!
//! Le JEU DE RACINES, pas un certificat. Une interception d'entreprise ne
//! fonctionne que d'une facon: en installant une autorite a elle dans le magasin
//! LOCAL de la machine. Il suffit donc de valider la chaine observee contre un
//! jeu de racines publiques embarque - celui de Mozilla, fige dans le binaire -
//! et non contre le magasin du systeme. Une chaine qui ne s'y ancre pas a ete
//! signee par quelqu'un d'autre.
//!
//! C'est bien le pin que le plan demande, pris un cran plus haut: les ancres de
//! confiance changent tous les quelques ANS, la ou un certificat de site change
//! desormais tous les quelques mois.
//!
//! # Lire le certificat sans casser la connexion
//!
//! Le plan insiste: "on lit seulement le certificat, on ne casse pas la
//! connexion". En TLS 1.3 le message `Certificate` est CHIFFRE sous les clefs de
//! poignee de main - contrairement a TLS 1.2 - donc il n'y a pas moyen de le
//! lire en comptant des octets comme le fait `bifrost-daemon::tls` pour les tailles. Il
//! faut une vraie pile TLS.
//!
//! La poignee est donc menee jusqu'au bout avec un verificateur qui NOTE la
//! chaine et accepte tout, puis la validation se fait hors ligne sur ce qui a
//! ete note. Refuser pendant la poignee enverrait une alerte et couperait, ce
//! que le plan interdit - et surtout, un client qui rejette bruyamment se
//! signale a l'equipement qui l'intercepte.
//!
//! # Pourquoi ce module vit dans le CLIENT et pas dans le daemon
//!
//! Il a d'abord ete ecrit dans `bifrost-daemon`, ou vivent les autres sondes.
//! `tests/frontiere_reseau.rs` l'a refuse, et il a eu raison: le daemon tourne
//! en root, en permanence, et une poignee de main TLS analyse des donnees
//! choisies par le pair - ici, par hypothese, un equipement qui intercepte.
//! Lier une pile TLS a ce processus-la ferait d'un defaut d'analyseur une
//! compromission racine permanente. C'est exactement ce que cette frontiere
//! protege, et c'etait le pire endroit ou la franchir.
//!
//! La sonde vit donc du cote non privilegie. Le prix a payer est reel et il est
//! dit: `--sonder-reseau` du daemon laisse `mitm_tls` a `NonMesure` avec cette
//! raison, en attendant que la selection soit cablee dans le flux de connexion
//! et que le verdict lui arrive par l'IPC.
//!
//! # Le danger de ce module, et ce qui le contient
//!
//! Un verificateur qui accepte tout est exactement ce qu'il ne faut jamais
//! brancher sur du vrai trafic. Il est donc prive, il ne sort pas de ce fichier,
//! et une recette structurelle verifie que l'API `dangerous` de rustls
//! n'apparait nulle part ailleurs dans le depot. La discipline ne suffit pas
//! quand l'erreur est silencieuse.
//!
//! # Ce que cette sonde ne voit pas
//!
//! Les cibles par defaut sont les deux resolveurs publics deja joints par les
//! autres sondes, ce qui n'ajoute aucune destination a la trace de ce client.
//! Un equipement d'inspection configure pour NE PAS dechiffrer ces points-la
//! passerait donc inapercu. La limite est reelle et assumee: elle se paierait
//! sinon en destinations supplementaires, donc en signature.

use std::io::Write as _;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bifrost_evasion::environnement::Mesure;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, RootCertStore, SignatureScheme};

/// Delai de connexion et de lecture. Aligne sur les autres sondes: la mesure
/// partage le budget de cinq secondes du document 04 partie 3.1.
pub const DELAI: Duration = Duration::from_millis(1_500);

/// Cibles par defaut: adresse, puis nom a demander.
///
/// Les memes que les autres sondes du depot, donc aucune destination de plus
/// dans la trace de ce client. Publiques, stables, et deliberement banales.
pub const CIBLES: &[(&str, &str)] = &[
    ("1.1.1.1:443", "cloudflare-dns.com"),
    ("8.8.8.8:443", "dns.google"),
];

/// Observe toutes les cibles par defaut et rend ce que chacune a montre.
pub fn observer_les_cibles() -> Vec<(String, Chaine)> {
    CIBLES
        .iter()
        .map(|(adresse, nom)| {
            let vue = match adresse.parse() {
                Ok(a) => observer(a, nom),
                Err(_) => Chaine::Douteuse {
                    raison: format!("adresse inutilisable: {adresse}"),
                },
            };
            ((*nom).to_owned(), vue)
        })
        .collect()
}

/// Ce qu'une poignee de main a montre de la chaine du serveur.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Chaine {
    /// Elle s'ancre dans le jeu de racines publiques embarque. Personne
    /// n'intercepte ce chemin.
    Publique,
    /// Elle ne s'y ancre pas: une autorite absente du jeu public l'a signee.
    /// C'est la signature d'une interception.
    Etrangere {
        /// Empreinte SHA-256 du DERNIER certificat presente, en hexadecimal.
        ///
        /// De quoi identifier l'equipement sans embarquer d'analyseur X.509:
        /// un administrateur la compare a celle de son autorite interne. Le
        /// serveur n'envoie pas sa racine, donc c'est en general
        /// l'intermediaire du haut de la chaine.
        empreinte: String,
    },
    /// La chaine est refusee pour une autre raison que son ancrage: nom qui ne
    /// correspond pas, dates, encodage. Ce n'est PAS un verdict d'interception,
    /// et le confondre avec un ferait accuser un reseau sain a cause d'une
    /// horloge qui derive.
    Douteuse {
        /// Ce que la validation a repondu, pour le journal.
        raison: String,
    },
    /// La poignee n'a pas abouti. Ne dit rien de personne.
    Injoignable,
}

/// Le verificateur qui note la chaine au lieu de la juger.
///
/// PRIVE, et il doit le rester. Voir l'en-tete du module: c'est precisement ce
/// qu'il ne faut jamais brancher sur du vrai trafic. Il ne juge rien parce que
/// juger pendant la poignee enverrait une alerte et couperait la connexion, ce
/// que le plan interdit; la validation vient apres, hors ligne, sur ce qu'il a
/// note.
#[derive(Debug)]
struct Greffier {
    vue: Mutex<Vec<CertificateDer<'static>>>,
    fournisseur: Arc<CryptoProvider>,
}

impl ServerCertVerifier for Greffier {
    fn verify_server_cert(
        &self,
        feuille: &CertificateDer<'_>,
        intermediaires: &[CertificateDer<'_>],
        _nom: &ServerName<'_>,
        _ocsp: &[u8],
        _maintenant: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let mut vue = Vec::with_capacity(1 + intermediaires.len());
        vue.push(feuille.clone().into_owned());
        vue.extend(intermediaires.iter().map(|c| c.clone().into_owned()));
        *self.vue.lock().expect("verrou de la chaine vue") = vue;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificat: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        // Les SIGNATURES sont verifiees pour de bon. Seul l'ancrage est
        // suspendu: une poignee dont la signature ne tient pas ne vient de
        // personne, et sa chaine n'apprendrait rien.
        rustls::crypto::verify_tls12_signature(
            message,
            certificat,
            signature,
            &self.fournisseur.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificat: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            certificat,
            signature,
            &self.fournisseur.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.fournisseur
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn fournisseur() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

/// Le jeu de racines publiques embarque dans le binaire.
///
/// Celui de Mozilla, et surtout PAS celui du systeme: c'est dans le magasin du
/// systeme qu'une interception d'entreprise s'installe, donc l'y interroger
/// reviendrait a demander au renard si le poulailler va bien.
fn racines_publiques() -> Arc<RootCertStore> {
    Arc::new(RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    })
}

fn empreinte(certificat: &CertificateDer<'_>) -> String {
    use sha2::Digest as _;
    let condense = sha2::Sha256::digest(certificat.as_ref());
    condense.iter().map(|o| format!("{o:02x}")).collect()
}

/// Juge hors ligne une chaine deja observee.
///
/// Separe de la poignee de main pour la raison habituelle de ce depot: c'est la
/// partie qui decide, donc c'est la partie qui doit se tester sans reseau.
pub fn juger(vue: &[CertificateDer<'static>], nom: &str) -> Chaine {
    let Some((feuille, intermediaires)) = vue.split_first() else {
        return Chaine::Douteuse {
            raison: "le serveur n'a presente aucun certificat".to_owned(),
        };
    };
    let Ok(nom_serveur) = ServerName::try_from(nom.to_owned()) else {
        return Chaine::Douteuse {
            raison: format!("nom de serveur inutilisable: {nom}"),
        };
    };
    let verificateur = match rustls::client::WebPkiServerVerifier::builder_with_provider(
        racines_publiques(),
        fournisseur(),
    )
    .build()
    {
        Ok(v) => v,
        Err(e) => {
            return Chaine::Douteuse {
                raison: format!("jeu de racines inutilisable: {e}"),
            };
        }
    };

    match verificateur.verify_server_cert(
        feuille,
        intermediaires,
        &nom_serveur,
        &[],
        UnixTime::now(),
    ) {
        Ok(_) => Chaine::Publique,
        Err(rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer)) => {
            Chaine::Etrangere {
                // Le dernier presente: c'est le plus haut de la chaine que le
                // serveur ait envoye, donc le plus proche de l'autorite qui
                // signe. Le serveur n'envoie pas sa racine.
                empreinte: empreinte(vue.last().expect("la chaine n'est pas vide")),
            }
        }
        Err(autre) => Chaine::Douteuse {
            raison: autre.to_string(),
        },
    }
}

/// Etablit une poignee de main jusqu'au bout, note la chaine, et raccroche
/// proprement.
///
/// Synchrone: rustls l'est, et l'envelopper dans une pile asynchrone ajouterait
/// une dependance pour un echange qui dure moins d'une seconde. L'appelant la
/// place sur un fil bloquant.
pub fn observer(cible: SocketAddr, nom: &str) -> Chaine {
    let Ok(nom_serveur) = ServerName::try_from(nom.to_owned()) else {
        return Chaine::Douteuse {
            raison: format!("nom de serveur inutilisable: {nom}"),
        };
    };

    let greffier = Arc::new(Greffier {
        vue: Mutex::new(Vec::new()),
        fournisseur: fournisseur(),
    });
    let configuration = match rustls::ClientConfig::builder_with_provider(fournisseur())
        .with_safe_default_protocol_versions()
    {
        Ok(c) => c
            .dangerous()
            .with_custom_certificate_verifier(greffier.clone())
            .with_no_client_auth(),
        Err(_) => return Chaine::Injoignable,
    };

    let Ok(mut connexion) = rustls::ClientConnection::new(Arc::new(configuration), nom_serveur)
    else {
        return Chaine::Injoignable;
    };
    let Ok(mut prise) = std::net::TcpStream::connect_timeout(&cible, DELAI) else {
        return Chaine::Injoignable;
    };
    let _ = prise.set_read_timeout(Some(DELAI));
    let _ = prise.set_write_timeout(Some(DELAI));

    if connexion.complete_io(&mut prise).is_err() {
        // La chaine a pu etre notee avant l'echec: une poignee qui casse APRES
        // le certificat en apprend autant qu'une qui aboutit.
        let vue = greffier.vue.lock().expect("verrou").clone();
        if vue.is_empty() {
            return Chaine::Injoignable;
        }
        return juger(&vue, nom);
    }

    // On raccroche par un `close_notify`, comme le ferait n'importe quel
    // client: le plan demande de ne pas casser la connexion, et une coupure
    // brutale est elle-meme remarquable.
    connexion.send_close_notify();
    let _ = connexion.complete_io(&mut prise);
    let _ = prise.flush();

    let vue = greffier.vue.lock().expect("verrou").clone();
    juger(&vue, nom)
}

/// Ce que l'ensemble des observations dit du reseau.
///
/// Une seule chaine etrangere suffit a conclure: un equipement qui dechiffre un
/// de ces chemins dechiffre. A l'inverse, il faut au moins une chaine PUBLIQUE
/// pour conclure negativement - sans quoi "rien d'anormal vu" se confondrait
/// avec "rien vu du tout", ce que tout ce depot s'emploie a distinguer.
pub fn conclure(observations: &[Chaine]) -> Mesure<bool> {
    if observations
        .iter()
        .any(|c| matches!(c, Chaine::Etrangere { .. }))
    {
        return Mesure::Vu(true);
    }
    if observations.contains(&Chaine::Publique) {
        return Mesure::Vu(false);
    }
    Mesure::NonMesure
}

/// Pourquoi la sonde n'a rien conclu, en une ligne pour le rapport.
pub fn raison_du_silence(observations: &[Chaine]) -> &'static str {
    if observations.is_empty() {
        return "aucune cible d'inspection TLS configuree";
    }
    if observations
        .iter()
        .any(|c| matches!(c, Chaine::Douteuse { .. }))
    {
        return "la chaine est refusee pour une raison etrangere a son ancrage \
                (nom, dates, encodage): ce n'est pas un verdict d'interception";
    }
    "aucune poignee de main TLS n'a abouti"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn une_chaine_etrangere_suffit_a_conclure_a_l_interception() {
        let vues = [
            Chaine::Publique,
            Chaine::Etrangere {
                empreinte: "ab".repeat(32),
            },
        ];
        assert_eq!(conclure(&vues), Mesure::Vu(true));
    }

    #[test]
    fn une_chaine_publique_suffit_a_conclure_a_l_absence_d_interception() {
        let vues = [Chaine::Injoignable, Chaine::Publique];
        assert_eq!(conclure(&vues), Mesure::Vu(false));
    }

    /// La ligne qui separe "rien d'anormal" de "rien du tout". Sans elle, un
    /// reseau muet passerait pour un reseau sain, et la selection garderait
    /// REALITY sur un chemin dont personne n'a rien mesure.
    #[test]
    fn sans_une_seule_chaine_vue_rien_n_est_conclu() {
        assert_eq!(conclure(&[]), Mesure::NonMesure);
        assert_eq!(
            conclure(&[Chaine::Injoignable, Chaine::Injoignable]),
            Mesure::NonMesure
        );
    }

    /// Une horloge qui derive ne doit pas accuser le reseau.
    #[test]
    fn une_chaine_douteuse_n_accuse_personne() {
        let vues = [Chaine::Douteuse {
            raison: "expired".to_owned(),
        }];
        assert_eq!(conclure(&vues), Mesure::NonMesure);
        assert!(raison_du_silence(&vues).contains("etrangere a son ancrage"));
    }

    /// Un serveur qui ne presente rien n'est pas un intercepteur.
    #[test]
    fn une_chaine_vide_est_douteuse_et_non_etrangere() {
        assert!(matches!(
            juger(&[], "exemple.test"),
            Chaine::Douteuse { .. }
        ));
    }

    /// Un certificat auto-signe ne s'ancre nulle part: c'est exactement la
    /// forme d'une interception, et la validation doit le dire.
    ///
    /// Le certificat est engendre ici, donc la recette ne demande ni reseau ni
    /// racine installee.
    #[test]
    fn un_certificat_qui_ne_s_ancre_nulle_part_est_declare_etranger() {
        let certificat =
            rcgen::generate_simple_self_signed(vec!["exemple.test".to_owned()]).unwrap();
        let der = CertificateDer::from(certificat.cert.der().to_vec());
        match juger(&[der], "exemple.test") {
            Chaine::Etrangere { empreinte } => {
                assert_eq!(empreinte.len(), 64, "une empreinte SHA-256 fait 64 signes");
            }
            autre => panic!("un certificat auto-signe doit etre declare etranger: {autre:?}"),
        }
    }

    /// Le TEMOIN POSITIF de la sonde, et sans lui elle ne prouverait rien.
    ///
    /// `mitm_tls = false` sur un reseau sain est le resultat attendu, et c'est
    /// aussi ce que rendrait une sonde qui ne regarde rien. Il faut donc
    /// montrer qu'elle voit une interception quand il y en a une - la meme
    /// exigence que pour les vecteurs de fuite, ou une sonde muette invalide la
    /// mesure.
    ///
    /// L'interception est fabriquee ici et n'existe que le temps de la recette:
    /// un serveur TLS local presentant un certificat auto-signe, exactement ce
    /// qu'un equipement d'entreprise presente une fois sa racine installee. Le
    /// magasin du systeme n'est pas touche - le modifier serait un changement
    /// de configuration de securite de la machine, et ce n'est pas a une
    /// recette de le faire.
    #[test]
    fn une_interception_fabriquee_est_bien_vue_comme_telle() {
        let nom = "essai.interception.test";
        let engendre = rcgen::generate_simple_self_signed(vec![nom.to_owned()]).unwrap();
        let certificat = CertificateDer::from(engendre.cert.der().to_vec());
        let clef = rustls::pki_types::PrivateKeyDer::try_from(engendre.signing_key.serialize_der())
            .unwrap();

        let configuration = rustls::ServerConfig::builder_with_provider(fournisseur())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![certificat], clef)
            .unwrap();

        let ecoute = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let adresse = ecoute.local_addr().unwrap();
        // Le serveur rend ce QU'IL a vu de la poignee. C'est le seul endroit
        // d'ou l'on peut constater qu'elle n'a pas ete cassee: du cote client,
        // une chaine notee puis refusee et une chaine notee puis acceptee se
        // ressemblent - une falsification l'a montre, la sonde conclut pareil
        // dans les deux cas. Ce que le refus change est ailleurs: il envoie une
        // alerte, coupe la connexion, et signale ce client a l'equipement qui
        // l'intercepte. C'est ce que le document 04 interdit, et c'est donc ici
        // que ca se verifie.
        let fil = std::thread::spawn(move || {
            let (mut prise, _) = ecoute.accept().unwrap();
            let mut connexion = rustls::ServerConnection::new(Arc::new(configuration)).unwrap();
            let poignee = connexion.complete_io(&mut prise).is_ok();
            (poignee, connexion)
        });

        let vu = observer(adresse, nom);
        let (poignee_cote_serveur, _) = fil.join().expect("le fil du serveur");

        assert!(
            poignee_cote_serveur,
            "le serveur n'a pas vu la poignee aboutir: la sonde l'a cassee,              ce que le document 04 interdit et qui signale ce client"
        );

        match vu {
            Chaine::Etrangere { empreinte } => {
                assert_eq!(empreinte.len(), 64);
                assert_eq!(
                    conclure(&[Chaine::Etrangere { empreinte }]),
                    Mesure::Vu(true),
                    "la sonde a vu l'interception mais n'en a rien conclu"
                );
            }
            autre => panic!(
                "une interception fabriquee n'a pas ete vue comme telle: {autre:?}.                  Sans ce temoin, un mitm_tls a false ne prouve rien"
            ),
        }
    }

    /// Le garde structurel du module.
    ///
    /// Le verificateur qui accepte tout ne doit exister qu'ici. Un test ne peut
    /// pas prouver qu'il n'est pas utilise ailleurs par un raisonnement; il peut
    /// LIRE les sources et le constater. C'est le meme moyen que la frontiere de
    /// licence, et pour la meme raison: l'erreur serait silencieuse.
    #[test]
    fn l_api_dangereuse_de_rustls_n_apparait_que_dans_ce_module() {
        let racine = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("crates/")
            .to_path_buf();

        let mut fautifs = Vec::new();
        let mut a_visiter = vec![racine];
        while let Some(repertoire) = a_visiter.pop() {
            let Ok(entrees) = std::fs::read_dir(&repertoire) else {
                continue;
            };
            for entree in entrees.flatten() {
                let chemin = entree.path();
                if chemin.is_dir() {
                    if chemin.file_name().is_some_and(|n| n == "target") {
                        continue;
                    }
                    a_visiter.push(chemin);
                } else if chemin.extension().is_some_and(|e| e == "rs") {
                    let Ok(texte) = std::fs::read_to_string(&chemin) else {
                        continue;
                    };
                    let nomme =
                        chemin.file_name().and_then(|n| n.to_str()) == Some("inspection.rs");
                    if !nomme
                        && (texte.contains(".dangerous()")
                            || texte.contains("with_custom_certificate_verifier"))
                    {
                        fautifs.push(chemin.display().to_string());
                    }
                }
            }
        }
        assert!(
            fautifs.is_empty(),
            "un verificateur de certificat sur mesure est branche hors de inspection.rs: {fautifs:?}"
        );
    }
}
