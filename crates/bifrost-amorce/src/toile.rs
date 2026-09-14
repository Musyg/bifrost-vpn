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
//! pour la seule securite. Il apporte les echanges de cles post-quantiques, ce
//! qui rapproche notre ClientHello de celui des navigateurs de 2026 plutot que
//! de l'en eloigner. Le mimetisme complet (JA3/JA4, `wreq`) demanderait
//! BoringSSL, donc `cmake` et Go dans la chaine de construction: c'est un cran
//! au-dessus, nomme et non pris.

use crate::{Canal, Recu};
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

    fn agent(delai: Duration) -> ureq::Agent {
        // Une fois par processus, et sans se plaindre si quelqu'un l'a deja
        // fait: installer le fournisseur deux fois n'est pas une erreur ici.
        static UNE_FOIS: std::sync::Once = std::sync::Once::new();
        UNE_FOIS.call_once(|| {
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        });

        ureq::Agent::config_builder()
            .timeout_global(Some(delai))
            .build()
            .into()
    }
}

impl Canal for Toile {
    fn nom(&self) -> String {
        self.adresse.clone()
    }

    fn chercher(&self) -> Result<Recu, String> {
        let agent = Self::agent(self.delai);
        let profil = tirer(&agent, &self.adresse, PLAFOND_PROFIL)?;
        let signature = tirer(
            &agent,
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
/// pilote TUN de Windows.
pub fn tirer_une_fois(adresse: &str, plafond: u64, delai: Duration) -> Result<Vec<u8>, String> {
    tirer(&Toile::agent(delai), adresse, plafond)
}

fn tirer(agent: &ureq::Agent, adresse: &str, plafond: u64) -> Result<Vec<u8>, String> {
    let mut reponse = agent
        .get(adresse)
        .call()
        .map_err(|e| format!("{adresse}: {e}"))?;
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
