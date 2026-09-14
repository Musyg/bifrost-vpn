//! Le pont entre le superviseur de tunnel, synchrone, et le passeur, asynchrone.
//!
//! Jumeau de [`super::atelier`], et pour la meme raison. Le superviseur de
//! tunnel vit sur un fil systeme ordinaire; le passeur est une pompe asynchrone
//! qui doit tourner tant que la connexion dure. Il faut donc porter la demande
//! d'un cote a l'autre de la frontiere, et rien de plus.
//!
//! On ne donne pas non plus de `tokio::runtime::Handle` au superviseur, pour la
//! raison deja ecrite dans l'atelier: il pourrait alors appeler n'importe quel
//! code asynchrone depuis n'importe ou, et la separation ne tiendrait plus que
//! par discipline. Un canal ne laisse passer que ce qu'on a ecrit.
//!
//! Meme garde-fou, aussi: `blocking_send` PANIQUE depuis un contexte
//! asynchrone, et le fil qui paniquerait est celui qui tient le kill switch.
//! On verifie donc, et on rend une erreur.
//!
//! # Ce que fermer veut dire
//!
//! Fermer le passage abandonne la tache, ce qui abandonne le [`Tun`], ce qui
//! ferme le descripteur, ce qui **fait disparaitre l'interface**. La chaine est
//! voulue et c'est elle qui garantit qu'aucun TUN ne survit a la deconnexion:
//! une interface orpheline resterait designee par une politique de pare-feu et
//! ne menerait plus nulle part.
//!
//! Les connexions deja etablies a travers le passeur tombent avec lui. Leurs
//! taches ne sont pas abandonnees une a une; elles s'arretent d'elles-memes des
//! que le peripherique ne repond plus. C'est le meme cout qu'une bascule de
//! coeur, deja decrit dans [`super::facade`].

use tokio::sync::{mpsc, oneshot};

use crate::tunnel::brut::TunBrut;

use super::passeur::{self, Tun};

/// Profondeur du canal. Un passage se monte et se demonte, il ne se demande pas
/// en rafale.
const PROFONDEUR: usize = 1;

/// Ce qu'on peut demander au passage.
pub enum Demande {
    /// Mene le systeme de ce TUN vers l'entree du coeur.
    ///
    /// Le TUN est REMIS, pas emprunte: a partir d'ici sa duree de vie est celle
    /// du passage, et personne d'autre ne peut le fermer par megarde.
    Ouvrir {
        tun: Box<TunBrut>,
        /// Ou frapper ET ce qu'il faut dire: l'entree du coeur exige des
        /// identifiants, et les separer de son adresse rendrait possible un
        /// appelant qui se presente les mains vides.
        coeur: super::socks::Mandataire,
        /// Celle de l'interface, et non une constante: c'est celui qui monte
        /// l'interface qui sait ce qu'il lui a pose.
        mtu: u16,
        reponse: oneshot::Sender<Result<String, String>>,
    },
    /// Arrete le passeur et laisse disparaitre l'interface.
    Fermer { reponse: oneshot::Sender<()> },
}

/// De quoi demander, depuis un fil synchrone.
#[derive(Clone)]
pub struct Poignee {
    envoi: mpsc::Sender<Demande>,
}

/// Pourquoi cet appel ne peut pas se faire d'ici, s'il y a une raison.
fn hors_contexte() -> Option<String> {
    tokio::runtime::Handle::try_current().is_ok().then(|| {
        "le passage se demande depuis un fil synchrone: l'appeler depuis une tache asynchrone ferait paniquer le fil qui tient le kill switch".to_owned()
    })
}

impl Poignee {
    /// Ouvre le passage et rend le nom de l'interface servie.
    pub fn ouvrir_passage(
        &self,
        tun: TunBrut,
        coeur: super::socks::Mandataire,
        mtu: u16,
    ) -> Result<String, String> {
        if let Some(raison) = hors_contexte() {
            return Err(raison);
        }
        let (repondre, reponse) = oneshot::channel();
        self.envoi
            .blocking_send(Demande::Ouvrir {
                tun: Box::new(tun),
                coeur,
                mtu,
                reponse: repondre,
            })
            .map_err(|_| "le passage est ferme: personne ne recoit les demandes".to_owned())?;
        reponse
            .blocking_recv()
            .map_err(|_| "le passage n'a pas repondu".to_owned())?
    }

    /// Ferme le passage. Reussit meme si rien n'etait ouvert.
    pub fn fermer(&self) -> Result<(), String> {
        if let Some(raison) = hors_contexte() {
            return Err(raison);
        }
        let (repondre, reponse) = oneshot::channel();
        self.envoi
            .blocking_send(Demande::Fermer { reponse: repondre })
            .map_err(|_| "le passage est ferme: personne ne recoit les demandes".to_owned())?;
        reponse
            .blocking_recv()
            .map_err(|_| "le passage n'a pas repondu".to_owned())
    }
}

/// Ouvre le pont. Le futur rendu doit tourner sur le runtime.
pub fn ouvrir() -> (Poignee, impl std::future::Future<Output = ()>) {
    let (envoi, demandes) = mpsc::channel(PROFONDEUR);
    (Poignee { envoi }, tenir(demandes))
}

/// La tache qui detient le passeur. N'en garde jamais plus d'un.
async fn tenir(mut demandes: mpsc::Receiver<Demande>) {
    let mut en_cours: Option<tokio::task::JoinHandle<()>> = None;
    while let Some(demande) = demandes.recv().await {
        match demande {
            Demande::Ouvrir {
                tun,
                coeur,
                mtu,
                reponse,
            } => {
                // Le precedent d'abord: deux passeurs sur deux TUN differents
                // laisseraient une interface que plus rien ne remplit.
                if let Some(ancienne) = en_cours.take() {
                    ancienne.abort();
                }
                let rendu = match Tun::nouveau(*tun) {
                    Ok(passage) => {
                        let nom = passage.nom().to_owned();
                        en_cours = Some(tokio::spawn(passeur::servir(passage, coeur, mtu)));
                        Ok(nom)
                    }
                    Err(e) => Err(format!("TUN non utilisable par la pile: {e}")),
                };
                let _ = reponse.send(rendu);
            }
            Demande::Fermer { reponse } => {
                if let Some(tache) = en_cours.take() {
                    tache.abort();
                }
                let _ = reponse.send(());
            }
        }
    }
    if let Some(tache) = en_cours.take() {
        tache.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Le garde-fou qui compte: appele depuis une tache asynchrone, la poignee
    /// doit rendre une erreur et non paniquer. Le fil qui paniquerait est celui
    /// qui tient le kill switch.
    #[tokio::test]
    async fn depuis_une_tache_asynchrone_la_poignee_refuse_au_lieu_de_paniquer() {
        let (poignee, _tenir) = ouvrir();
        let e = poignee
            .fermer()
            .expect_err("l'appel depuis un contexte asynchrone doit etre refuse");
        assert!(e.contains("synchrone"), "{e}");
    }

    /// Fermer sans rien d'ouvert reussit: le demontage doit pouvoir suivre un
    /// montage interrompu au milieu.
    #[test]
    fn fermer_sans_passage_ouvert_reussit() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let (poignee, tenir) = ouvrir();
        rt.spawn(tenir);
        std::thread::spawn(move || poignee.fermer())
            .join()
            .unwrap()
            .expect("fermer sans passage ouvert doit reussir");
    }
}
