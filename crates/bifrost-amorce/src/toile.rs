//! Le canal HTTP: une adresse, et sa signature juste a cote.
//!
//! # Deux limites, et pourquoi elles ne sont pas facultatives
//!
//! Ce code parle a un serveur qui n'est pas forcement le notre - c'est meme
//! l'hypothese de depart de tout ce module. Un tel serveur peut repondre
//! lentement pour toujours, ou servir un corps sans fin. Sans **delai** ni
//! **plafond de taille**, le premier canal pendrait la commande entiere et le
//! second la ferait grossir jusqu'a la mort du processus, sans qu'aucune
//! signature n'ait a etre fabriquee. Ce sont les deux defauts qu'un
//! `telecharger l'adresse` naif laisse ouverts.
//!
//! Les valeurs sont larges par rapport a l'objet: un profil de tunnel tient en
//! deux kilo-octets, on en accepte soixante-quatre pour laisser place a un
//! profil qui declare plusieurs transports. Un profil legitime n'atteint jamais
//! ces bornes; les atteindre est en soi le signe que quelque chose ne va pas.
//!
//! # L'empreinte TLS
//!
//! rustls avec aws-lc-rs, qui est le fournisseur par defaut de rustls depuis que
//! `ring` porte RUSTSEC-2025-0007 - non maintenu, repris par l'equipe rustls
//! pour la seule securite. La feature `prefer-post-quantum` de rustls est
//! activee: le premier ClientHello met l'echange hybride X25519MLKEM768 en tete
//! de `supported_groups` et en porte la part, 1216 octets, suivie d'une part
//! X25519. Sans elle, X25519MLKEM768 venait en dernier et sans part: il ne
//! servait que si le serveur le reclamait. Mesure sur la boucle locale de
//! dev-windows, sans nom de serveur: 1443 octets de ClientHello contre 223.
//! Le mimetisme complet (JA3/JA4, `wreq`) demanderait BoringSSL, donc `cmake`
//! et Go dans la chaine de construction: c'est un cran au-dessus, nomme et non
//! pris.
//!
//! # Le repli classique, et ce qu'il concede
//!
//! A 1448 octets de charge TCP sans nom, ce ClientHello remplit deja un segment
//! TCP usuel et le depasse des qu'il porte un nom; des boitiers intermediaires
//! qui reassemblent mal coupent alors la connexion. TLS ne se replie pas seul:
//! `tirer` le fait. Quand l'essai hybride sur une adresse `https` echoue par
//! une fin de flux, une reinitialisation, une interruption de la connexion ou
//! un delai depasse, UN second essai part avec [`fournisseur_classique`]:
//! X25519, P-256, P-384, aucun groupe hybride. Jamais apres une alerte TLS, une
//! erreur de certificat, une reponse HTTP ou une erreur de corps: ureq les rend
//! autrement. L'echec final nomme les deux essais et leurs erreurs.
//!
//! - Le repli se declenche AUSSI apres une reponse partielle du serveur: ureq
//!   rend la meme erreur pour une coupure avant toute reponse et pour une
//!   coupure apres un ServerHello, et pareil pour une reinitialisation ou un
//!   silence (mesure sur la boucle locale de dev-windows). Un delai depasse
//!   pendant la connexion TCP, avant tout octet TLS, se rend lui aussi comme un
//!   delai, et rejoue de meme.
//! - Un attaquant ACTIF qui coupe le premier essai obtient un echange
//!   classique, toujours authentifie par la meme verification de certificat
//!   (les racines de Mozilla embarquees). La protection visee est celle contre
//!   l'enregistrement PASSIF d'un echange, dechiffre plus tard; pas celle
//!   contre qui peut couper la connexion.
//! - Une adresse muette coute deux delais au lieu d'un.

use crate::{Canal, Recu};
use std::sync::Arc;
use std::time::Duration;

/// Au-dela, ce n'est plus un profil.
const PLAFOND_PROFIL: u64 = 64 * 1024;

/// Une signature minisign fait quelques centaines d'octets.
const PLAFOND_SIGNATURE: u64 = 4 * 1024;

/// Par canal, pas pour l'ensemble: trois canaux lents ne doivent pas s'ajouter
/// jusqu'a donner l'impression que la commande a gele.
const DELAI: Duration = Duration::from_secs(15);

/// Une adresse HTTP, dont la signature vit a `<adresse>.minisig`.
pub struct Toile {
    adresse: String,
    delai: Duration,
}

impl Toile {
    pub fn nouvelle(adresse: impl Into<String>) -> Self {
        Self::avec_delai(adresse, DELAI)
    }

    /// Le meme, avec un autre delai.
    ///
    /// Existe pour que le delai soit MESURABLE: la recette d'un serveur muet
    /// attendrait sinon quinze secondes, et personne n'ecrit une recette qui
    /// coute quinze secondes - donc personne ne verifierait jamais que le delai
    /// joue. Ce qui est mesure est le mecanisme, pas la valeur du defaut.
    pub fn avec_delai(adresse: impl Into<String>, delai: Duration) -> Self {
        Self {
            adresse: adresse.into(),
            delai,
        }
    }
}

/// Les deux agents d'une recuperation: l'essai hybride, et le repli.
///
/// Crees ensemble et gardes pour le profil ET sa signature, comme l'agent
/// unique d'avant: la seconde requete reprend la connexion de la premiere
/// quand le serveur la garde ouverte.
struct Agents {
    hybride: ureq::Agent,
    classique: ureq::Agent,
}

impl Agents {
    fn nouveaux(delai: Duration) -> Self {
        // Une fois par processus, et sans se plaindre si quelqu'un l'a deja
        // fait: installer le fournisseur deux fois n'est pas une erreur ici.
        // C'est le fournisseur de l'essai hybride, pris par ureq faute d'un
        // fournisseur dans sa configuration TLS.
        static UNE_FOIS: std::sync::Once = std::sync::Once::new();
        UNE_FOIS.call_once(|| {
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        });

        // Le fournisseur du repli ne peut pas etre celui du processus, qui est
        // unique et sert deja l'essai hybride. ureq 3.3 n'offre qu'une voie
        // pour en donner un a un seul agent, hors de son API stable:
        // `unversioned_rustls_crypto_provider`. Une rupture de cette methode a
        // une version mineure de ureq serait une erreur de compilation.
        let tls_classique = ureq::tls::TlsConfig::builder()
            .unversioned_rustls_crypto_provider(Arc::new(fournisseur_classique()))
            .build();

        Self {
            hybride: ureq::Agent::config_builder()
                .timeout_global(Some(delai))
                .build()
                .into(),
            classique: ureq::Agent::config_builder()
                .timeout_global(Some(delai))
                .tls_config(tls_classique)
                .build()
                .into(),
        }
    }
}

/// Le fournisseur du second essai: aws-lc-rs, sans aucun groupe hybride.
///
/// Les trois groupes classiques que rustls offre par defaut, dans son ordre.
/// Le reste (suites, algorithmes de signature) est celui du fournisseur par
/// defaut: le repli ne change que l'echange de cles. Public parce que la sonde
/// d'inspection TLS du client se replie avec le meme.
pub fn fournisseur_classique() -> rustls::crypto::CryptoProvider {
    use rustls::crypto::aws_lc_rs::{default_provider, kx_group};
    rustls::crypto::CryptoProvider {
        kx_groups: vec![kx_group::X25519, kx_group::SECP256R1, kx_group::SECP384R1],
        ..default_provider()
    }
}

impl Canal for Toile {
    fn nom(&self) -> String {
        self.adresse.clone()
    }

    fn chercher(&self) -> Result<Recu, String> {
        let agents = Agents::nouveaux(self.delai);
        let profil = tirer(&agents, &self.adresse, PLAFOND_PROFIL)?;
        let signature = tirer(
            &agents,
            &format!(
                "{}.{}",
                self.adresse,
                bifrost_coffre::signature::EXTENSION_SIGNATURE
            ),
            PLAFOND_SIGNATURE,
        )?;
        let signature = String::from_utf8(signature)
            .map_err(|_| "la signature recue n'est pas du texte".to_string())?;
        Ok(Recu { profil, signature })
    }
}

/// Va chercher des octets une fois, avec les memes bornes que les canaux.
///
/// Publique parce qu'il n'y a aucune raison d'avoir DEUX clients HTTP dans ce
/// depot: celui-ci porte deja le delai et le plafond, c'est-a-dire ce qu'un
/// serveur hostile peut faire sans rien forger - accepter puis se taire, ou
/// servir un corps sans fin. Le client s'en sert aussi pour aller chercher le
/// pilote TUN de Windows. Le repli classique de l'en-tete du module y vaut
/// aussi.
pub fn tirer_une_fois(adresse: &str, plafond: u64, delai: Duration) -> Result<Vec<u8>, String> {
    tirer(&Agents::nouveaux(delai), adresse, plafond)
}

/// Les echecs de l'essai hybride qui appellent le second essai.
///
/// Ce que ureq rend quand la connexion est coupee, reinitialisee, interrompue,
/// ou qu'un delai est depasse. Ni une alerte TLS ni une erreur de certificat
/// (`Io` de genre `InvalidData`), ni une reponse HTTP, ni une connexion
/// refusee (`Io` de genre `ConnectionRefused`) ou un nom qui ne resout pas:
/// rien de cela ne vient d'un ClientHello trop grand. Avec le seul delai
/// global que ce module configure, ureq rend un delai depasse a la connexion
/// TCP comme tout autre delai: celui-la rejoue aussi.
fn appelle_le_repli(erreur: &ureq::Error) -> bool {
    use std::io::ErrorKind;
    match erreur {
        ureq::Error::Io(e) => matches!(
            e.kind(),
            ErrorKind::UnexpectedEof | ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted
        ),
        ureq::Error::Timeout(_) => true,
        _ => false,
    }
}

/// Vrai si l'adresse demande TLS: sans ClientHello, le repli ne changerait
/// rien au second essai.
fn porte_du_tls(adresse: &str) -> bool {
    adresse
        .get(..8)
        .is_some_and(|debut| debut.eq_ignore_ascii_case("https://"))
}

fn tirer(agents: &Agents, adresse: &str, plafond: u64) -> Result<Vec<u8>, String> {
    // Le repli se decide sur `call()` seul: une erreur de corps arrive apres
    // la reponse HTTP, et ne rejoue jamais.
    let mut reponse = match agents.hybride.get(adresse).call() {
        Ok(reponse) => reponse,
        Err(premier) if porte_du_tls(adresse) && appelle_le_repli(&premier) => {
            agents.classique.get(adresse).call().map_err(|second| {
                format!(
                    "{adresse}: premier essai (echange hybride post-quantique): {premier}; \
                     second essai (echange classique): {second}"
                )
            })?
        }
        Err(e) => return Err(format!("{adresse}: {e}")),
    };
    reponse
        .body_mut()
        .with_config()
        .limit(plafond)
        .read_to_vec()
        .map_err(|e| format!("{adresse}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// L'adresse de la signature se deduit de celle du profil.
    ///
    /// Une convention et non un second reglage: deux adresses a tenir a jour
    /// finiraient par diverger, et un profil servi avec la signature d'un autre
    /// est exactement ce que la verification doit attraper - autant ne pas
    /// fabriquer soi-meme l'occasion.
    #[test]
    fn le_canal_se_nomme_par_son_adresse() {
        let t = Toile::nouvelle("https://exemple.invalide/tunnel.toml");
        assert_eq!(t.nom(), "https://exemple.invalide/tunnel.toml");
    }

    /// Un nom qui ne resout pas rend un canal muet, jamais une panique.
    #[test]
    fn une_adresse_injoignable_est_muette_et_se_nomme() {
        let e = Toile::nouvelle("https://ceci-nexiste-pas.invalid/tunnel.toml")
            .chercher()
            .expect_err("un domaine invalide ne doit pas repondre");
        assert!(e.contains("ceci-nexiste-pas.invalid"), "{e}");
    }
}
