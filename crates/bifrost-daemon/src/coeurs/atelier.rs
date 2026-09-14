//! Le pont entre le superviseur de tunnel, synchrone, et les coeurs, asynchrones.
//!
//! # Pourquoi un pont et non une fusion
//!
//! Le plan separe les deux depuis le debut. Document 06: la machine a etats du
//! tunnel vit dans un composant, "la supervision sing-box/Xray" dans un autre,
//! avec "restart, health" pour attributions propres. Les deux existent ici:
//! [`crate::supervisor`] tient le tunnel sur un fil systeme ordinaire,
//! [`super::superviseur`] tient le cycle de vie des coeurs en asynchrone.
//!
//! Il manquait de quoi les faire se parler. Ce module est cette piece, et rien
//! d'autre: il ne lance pas de processus lui-meme, il porte la demande de
//! l'autre cote de la frontiere.
//!
//! # Pourquoi un canal et non une poignee de runtime
//!
//! Donner un `tokio::runtime::Handle` au superviseur de tunnel marcherait, et
//! ce serait la mauvaise reponse: il pourrait alors appeler n'importe quel code
//! asynchrone depuis n'importe ou, et la separation que le plan demande
//! n'existerait plus que par discipline. Un canal ne laisse passer que les
//! demandes qu'on a ecrites.
//!
//! # Le garde-fou qui compte
//!
//! `blocking_send` et `blocking_recv` PANIQUENT si on les appelle depuis un
//! contexte asynchrone; c'est documente par tokio et c'est le piege classique
//! de ce pont. Ici la consequence serait particuliere: le fil qui paniquerait
//! est celui qui tient le kill switch. [`Poignee`] verifie donc d'abord qu'elle
//! n'est pas dans un runtime, et rend une erreur au lieu de paniquer. Une
//! connexion qui echoue en le disant vaut infiniment mieux qu'un superviseur
//! mort avec des filtres poses que plus personne ne retire.
//!
//! # Ou ce module commence, et ou il ne commence pas
//!
//! Il recoit un [`Lancement`] et le secret de l'API de controle: la
//! configuration du coeur est donc DEJA ecrite quand on l'appelle, et c'est
//! voulu. Le secret vit dans ce fichier et sert ensuite a parler au coeur; le
//! tirer ici en ignorant celui que la configuration porte donnerait deux
//! secrets differents et un coeur qui refuserait poliment de repondre. Ecrire
//! la configuration est le travail de qui connait la technique et le profil,
//! pas de qui lance des processus.
//!
//! # Un seul coeur a la fois
//!
//! L'atelier n'en detient jamais deux. Un coeur qu'on aurait oublie garde son
//! ecoute SOCKS locale ouverte, donc une sortie que plus personne ne supervise
//! et que le kill switch ne connait pas: c'est exactement ce que l'en-tete de
//! [`super::superviseur`] designe comme le danger principal. Lancer alors qu'un
//! coeur tourne arrete donc le precedent d'abord.

use std::net::SocketAddr;

use bifrost_evasion::Coeur;
use tokio::sync::{mpsc, oneshot, watch};

use super::lancement::Lancement;
use super::superviseur::{self, CoeurEnCours};

/// Profondeur du canal de demandes.
///
/// Une seule demande peut etre en attente: le superviseur de tunnel bloque sur
/// la reponse de chacune, donc il n'en emet jamais deux a la fois. Une file
/// plus profonde ne servirait qu'a masquer un atelier qui ne repond plus.
const PROFONDEUR: usize = 1;

/// Ce que le superviseur de tunnel apprend d'un coeur lance.
///
/// Volontairement maigre: le `CoeurEnCours` reste dans l'atelier, du cote
/// asynchrone. Le faire traverser la frontiere donnerait au superviseur de
/// tunnel un objet dont toutes les methodes utiles sont `async`, et le probleme
/// serait deplace au lieu d'etre resolu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Vivant {
    pub pid: Option<u32>,
    pub api: Option<SocketAddr>,
}

/// Ce qu'on demande a l'atelier.
pub enum Demande {
    Lancer {
        coeur: Coeur,
        /// Encadre: un `Lancement` porte deux chemins et un vecteur
        /// d'arguments, et la variante la plus grosse fixe la taille de tout
        /// message qui passe par le canal.
        lancement: Box<Lancement>,
        /// Le secret de l'API de controle, tel que la configuration deja
        /// ecrite le porte.
        secret: String,
        /// Ou ce coeur ecoutera en SOCKS, tel que sa configuration le declare.
        ///
        /// C'est cette adresse que l'atelier PUBLIE, et que [`super::facade`]
        /// suit. L'atelier ne la devine pas: elle est dans la configuration,
        /// donc connue de qui l'a ecrite.
        socks: SocketAddr,
        reponse: oneshot::Sender<Result<Vivant, String>>,
    },
    Arreter {
        reponse: oneshot::Sender<Result<(), String>>,
    },
}

/// La poignee synchrone, cote superviseur de tunnel.
#[derive(Clone)]
pub struct Poignee {
    envoi: mpsc::Sender<Demande>,
}

/// Pourquoi cette poignee refuse de servir maintenant.
///
/// Rendue plutot que paniquee: voir l'en-tete du module.
fn hors_contexte() -> Option<String> {
    tokio::runtime::Handle::try_current().is_ok().then(|| {
        "la poignee de l'atelier a ete appelee depuis un contexte asynchrone: elle y bloquerait le runtime, et tokio y fait paniquer blocking_send".to_owned()
    })
}

impl Poignee {
    /// Lance ce coeur, et attend de savoir s'il repond.
    ///
    /// Bloque le fil appelant, ce qui est voulu: le superviseur de tunnel ne
    /// doit pas poursuivre une connexion tant qu'il ignore si le coeur qui doit
    /// la porter est vivant.
    pub fn lancer(
        &self,
        coeur: Coeur,
        lancement: Lancement,
        secret: &str,
        socks: SocketAddr,
    ) -> Result<Vivant, String> {
        if let Some(raison) = hors_contexte() {
            return Err(raison);
        }
        let (repondre, reponse) = oneshot::channel();
        self.envoi
            .blocking_send(Demande::Lancer {
                coeur,
                lancement: Box::new(lancement),
                secret: secret.to_owned(),
                socks,
                reponse: repondre,
            })
            .map_err(|_| {
                "l'atelier des coeurs ne repond plus: aucun coeur ne peut etre lance".to_owned()
            })?;
        reponse
            .blocking_recv()
            .map_err(|_| "l'atelier des coeurs a rendu l'ame pendant le lancement".to_owned())?
    }

    /// Arrete le coeur en cours, s'il y en a un.
    ///
    /// Ne rend PAS d'erreur quand il n'y a rien a arreter: une deconnexion qui
    /// echouerait parce qu'aucun coeur ne tournait ferait passer un etat propre
    /// pour une panne.
    pub fn arreter(&self) -> Result<(), String> {
        if let Some(raison) = hors_contexte() {
            return Err(raison);
        }
        let (repondre, reponse) = oneshot::channel();
        self.envoi
            .blocking_send(Demande::Arreter { reponse: repondre })
            .map_err(|_| {
                "l'atelier des coeurs ne repond plus: le coeur en cours n'a pas pu etre arrete"
                    .to_owned()
            })?;
        reponse
            .blocking_recv()
            .map_err(|_| "l'atelier des coeurs a rendu l'ame pendant l'arret".to_owned())?
    }
}

/// Ouvre l'atelier: rend la poignee synchrone et la tache qui la sert.
///
/// La tache est rendue et non lancee ici, pour que l'appelant decide sur quel
/// runtime elle vit. Tant que personne ne l'execute, la poignee rend des
/// erreurs claires plutot que d'attendre.
///
/// Rend aussi de quoi SUIVRE le coeur actif: [`super::facade`] s'en sert pour
/// mener les octets au bon endroit sans que son adresse d'ecoute change.
pub fn ouvrir() -> (
    Poignee,
    watch::Receiver<Option<SocketAddr>>,
    impl std::future::Future<Output = ()>,
) {
    let (envoi, demandes) = mpsc::channel(PROFONDEUR);
    // Aucun coeur au depart: la facade ferme les connexions plutot que de les
    // faire attendre, ce qui est l'etat correct tant que rien ne tourne.
    let (publier, suivre) = watch::channel(None);
    (Poignee { envoi }, suivre, tenir(demandes, publier))
}

/// La tache qui detient les coeurs. N'en garde jamais plus d'un.
async fn tenir(mut demandes: mpsc::Receiver<Demande>, publier: watch::Sender<Option<SocketAddr>>) {
    let mut en_cours: Option<CoeurEnCours> = None;
    loop {
        // Deux choses peuvent arriver: on nous demande quelque chose, ou le
        // coeur meurt tout seul.
        //
        // Le second cas est la raison d'etre de ce `select!`. Sans lui, un
        // coeur qui sort de lui-meme - binaire qui panique, serveur qui coupe,
        // OOM killer - restait publie: la facade continuait de mener vers un
        // port mort et le tunnel par coeur se croyait vivant, puisque son
        // interface, elle, tenait toujours debout. La boucle ne se reveillait
        // qu'a la demande suivante, qui pouvait ne jamais venir.
        let demande = tokio::select! {
            demande = demandes.recv() => match demande {
                Some(d) => d,
                // Le canal est ferme: plus personne ne demandera rien.
                None => break,
            },
            // La garde est indispensable: `attendre_la_fin` sur un `None`
            // n'aurait rien a attendre et cette branche gagnerait toujours.
            raison = attendre_la_mort(&mut en_cours), if en_cours.is_some() => {
                // Depublier AVANT d'oublier le coeur, pour la meme raison qu'a
                // l'arret: entre les deux, la facade menerait des octets vers
                // un processus qui n'est plus la.
                let _ = publier.send(None);
                tracing::warn!(%raison, "le coeur est mort de lui-meme");
                if let Some(defunt) = en_cours.take() {
                    // Le processus est parti, mais il reste a reaper, et sous
                    // Windows le Job reste a fermer.
                    let _ = defunt.arreter().await;
                }
                continue;
            }
        };
        match demande {
            Demande::Lancer {
                coeur,
                lancement,
                secret,
                socks,
                reponse,
            } => {
                // Le precedent d'abord. Un coeur oublie garde son ecoute SOCKS
                // ouverte, donc une sortie que le kill switch ne connait pas.
                if let Some(ancien) = en_cours.take() {
                    // Depublier AVANT d'arreter: entre l'arret et la
                    // depublication, la facade menerait des octets vers un
                    // processus qui meurt, et le client verrait une coupure
                    // au lieu d'un refus franc.
                    let _ = publier.send(None);
                    if let Err(e) = ancien.arreter().await {
                        tracing::warn!(erreur = %e, "coeur precedent mal arrete avant un nouveau lancement");
                    }
                }
                let issue = lancer_un(coeur, &lancement, &secret).await;
                let rendu = match issue {
                    Ok(vivant_et_coeur) => {
                        let (vivant, garde) = vivant_et_coeur;
                        en_cours = Some(garde);
                        // Publier seulement une fois le coeur VIVANT: annoncer
                        // avant enverrait la facade vers un port que personne
                        // n'ecoute encore.
                        let _ = publier.send(Some(socks));
                        Ok(vivant)
                    }
                    Err(e) => Err(e),
                };
                // Le demandeur a pu abandonner: ce n'est pas une raison de
                // laisser un coeur tourner sans personne pour l'arreter.
                if reponse.send(rendu).is_err()
                    && let Some(orphelin) = en_cours.take()
                {
                    let _ = publier.send(None);
                    if let Err(e) = orphelin.arreter().await {
                        tracing::warn!(erreur = %e, "coeur lance pour un demandeur disparu, et mal arrete");
                    }
                }
            }
            Demande::Arreter { reponse } => {
                let _ = publier.send(None);
                let rendu = match en_cours.take() {
                    None => Ok(()),
                    Some(c) => c.arreter().await.map_err(|e| e.to_string()),
                };
                let _ = reponse.send(rendu);
            }
        }
    }
    // Ne pas laisser le coeur derriere.
    let _ = publier.send(None);
    if let Some(dernier) = en_cours.take()
        && let Err(e) = dernier.arreter().await
    {
        tracing::warn!(erreur = %e, "coeur mal arrete a la fermeture de l'atelier");
    }
}

/// Attend que le coeur en cours meure, et rend de quoi le dire.
///
/// Ecrite a part pour rester annulable: `tokio::select!` abandonne la branche
/// perdante, et ce qui est abandonne ici n'est qu'une attente - aucun etat n'a
/// bouge, donc reprendre au tour suivant est correct.
async fn attendre_la_mort(en_cours: &mut Option<CoeurEnCours>) -> String {
    match en_cours.as_mut() {
        Some(c) => c.attendre_la_fin().await,
        // Inatteignable: la garde du `select!` interdit cette branche. Attendre
        // indefiniment plutot que de rendre, pour qu'une garde oubliee un jour
        // ne se traduise pas par une boucle qui tourne a vide.
        None => std::future::pending().await,
    }
}

/// Lance un coeur et rend de quoi le decrire, plus de quoi le tenir.
async fn lancer_un(
    coeur: Coeur,
    lancement: &Lancement,
    secret: &str,
) -> Result<(Vivant, CoeurEnCours), String> {
    let en_cours = superviseur::demarrer(coeur, lancement, secret)
        .await
        .map_err(|e| format!("{} n'a pas demarre: {e}", coeur.executable()))?;
    let vivant = Vivant {
        pid: en_cours.pid(),
        api: en_cours.api(),
    };
    Ok((vivant, en_cours))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Le piege documente de ce pont, et la raison pour laquelle la poignee
    /// verifie avant d'envoyer: `blocking_send` depuis un contexte asynchrone
    /// panique, et le fil qui paniquerait ici est celui qui tient le kill
    /// switch. Une erreur rendue vaut infiniment mieux.
    #[tokio::test]
    async fn la_poignee_appelee_depuis_l_asynchrone_rend_une_erreur_sans_paniquer() {
        let (poignee, _suivre, _tache) = ouvrir();
        let e = poignee
            .arreter()
            .expect_err("un appel depuis un runtime doit etre refuse");
        assert!(e.contains("asynchrone"), "{e}");
        assert!(e.contains("paniquer"), "{e}");
    }

    /// Un atelier dont la tache ne tourne pas ne doit pas faire attendre: la
    /// connexion echoue en le disant.
    #[test]
    fn un_atelier_ferme_rend_une_erreur_qui_le_nomme() {
        let (poignee, _suivre, tache) = ouvrir();
        // La tache n'est jamais executee et tombe ici: le canal se ferme.
        drop(tache);
        let e = poignee
            .arreter()
            .expect_err("un atelier ferme doit etre signale");
        assert!(e.contains("atelier"), "{e}");
    }
}
