//! La sonde aller-retour qui rend le critere de gel concluant.
//!
//! [`bifrost_evasion::observation`] sait dire QUAND demander au pair s'il est
//! encore la, et pourquoi aucun comptage ne peut repondre a sa place. Ce module
//! est ce qui demande.
//!
//! # Ce que la sonde traverse, et pourquoi ce n'est pas nous qui l'emettons
//!
//! `GET /proxies/<selecteur>/delay` fait COMPOSER le coeur: il dialogue avec la
//! cible A TRAVERS la sortie courante et rend le temps d'aller-retour. La sonde
//! emprunte donc exactement le transport dont on doute.
//!
//! Emettre nous-memes aurait paru plus direct et se serait heurte a notre
//! propre kill switch. Le ruleset accepte tout ce qui sort par l'interface du
//! tunnel - `oifname <tunnel> accept` - mais il pose AVANT lui, des qu'un
//! resolveur embarque est declare, un `udp dport 53 drop` et son jumeau TCP.
//! Une sonde DNS emise par le daemon serait donc jetee par nos propres regles,
//! et son echec se lirait comme un pair mort: on demonterait un tunnel sain
//! parce qu'on aurait ferme la porte nous-memes.
//!
//! La sortie du coeur, elle, est exemptee par IDENTITE. Passer par lui evite la
//! question entierement, et lui seul sait de toute facon par ou passe la sortie
//! courante.
//!
//! # La cible
//!
//! `generate_204`, celle que sing-box prend par defaut pour son `urltest`. Le
//! choix est deliberement banal: une sonde qui viserait une adresse a nous
//! distinguerait ce client de tous les autres, ce qui est exactement ce qu'un
//! outil de contournement doit eviter. Le corps fait zero octet, ce qui suffit
//! ici - la question posee est "le pair repond-il", pas "combien passe-t-il".
//! C'est aussi pourquoi le meme point de mesure ne peut PAS servir a
//! l'`urltest`, dont le document 04 partie 3.3 dit qu'il ne voit pas le gel.
//!
//! # Pourquoi elle ne bloque jamais le superviseur
//!
//! Le fil du superviseur tient le kill switch et repond aux commandes. L'y
//! faire attendre cinq secondes une reponse reseau suspendrait tout le daemon a
//! chaque silence de tunnel. La sonde est donc DEMANDEE d'un cote et RAMASSEE
//! de l'autre, deux gestes qui ne bloquent ni l'un ni l'autre, et l'observateur
//! est deja fait pour ca: il pose `Sonder`, puis attend `noter_sonde` aussi
//! longtemps qu'il le faut sans jamais en redemander une deuxieme.

use std::net::SocketAddr;
use std::time::Duration;

pub use bifrost_evasion::observation::Sonde;
use tokio::sync::mpsc;

use super::clash;

/// Cible de la sonde. Voir l'en-tete: la banalite est le point.
pub const CIBLE: &str = "https://www.gstatic.com/generate_204";

/// Marge laissee a l'API au-dela du budget confie au coeur.
///
/// Sans elle, notre propre echeance tomberait en meme temps que la sienne et on
/// lirait un `Impossible` la ou le coeur allait repondre `Echouee`. Un aller
/// simple sur la boucle locale ne coute rien; la marge est la pour l'ecriture
/// de la reponse, pas pour le reseau.
pub const MARGE: Duration = Duration::from_secs(2);

/// Profondeur des deux files. Une seule sonde peut etre en vol - l'observateur
/// s'en assure - donc une place suffit, et une file pleine est un signal utile
/// plutot qu'une attente.
const PROFONDEUR: usize = 1;

/// Ce qu'il faut pour sonder, fige au demarrage du daemon.
#[derive(Debug, Clone)]
pub struct Adresse {
    /// L'API de controle du coeur, sur la boucle locale.
    pub api: SocketAddr,
    /// Son secret.
    pub secret: String,
    /// Le selecteur a sonder. C'est lui qu'on interroge et non une sortie
    /// nommee: il designe celle qui sert EN CE MOMENT, et une bascule a chaud
    /// changera la reponse sans qu'on ait rien a mettre a jour.
    pub selecteur: String,
}

/// Ce que le superviseur tient. Ni `demander` ni `ramasser` ne bloquent.
pub struct Poignee {
    demandes: mpsc::Sender<Duration>,
    resultats: mpsc::Receiver<Sonde>,
}

impl Poignee {
    /// Demande une sonde dans ce budget.
    ///
    /// Rend faux si la precedente n'a pas encore rendu son verdict, ce qui ne
    /// devrait pas arriver - l'observateur n'en demande qu'une a la fois - et
    /// qui, si cela arrivait, ne doit surtout pas faire attendre le
    /// superviseur.
    pub fn demander(&self, budget: Duration) -> bool {
        self.demandes.try_send(budget).is_ok()
    }

    /// Ramasse un verdict s'il y en a un.
    pub fn ramasser(&mut self) -> Option<Sonde> {
        self.resultats.try_recv().ok()
    }
}

/// Ouvre la sonde. Le futur rendu doit tourner sur le runtime.
pub fn ouvrir(adresse: Adresse) -> (Poignee, impl std::future::Future<Output = ()>) {
    let (demandes, recevoir) = mpsc::channel(PROFONDEUR);
    let (rendre, resultats) = mpsc::channel(PROFONDEUR);
    (
        Poignee {
            demandes,
            resultats,
        },
        tenir(adresse, recevoir, rendre),
    )
}

/// Fabrique une poignee dont l'appelant garde les DEUX autres bouts.
///
/// Le seam est reel, et il vient d'une falsification. Sans lui, une doublure
/// doit laisser tomber le futur rendu par [`ouvrir`], ce qui emporte avec lui
/// le recepteur des demandes: la poignee refuse alors silencieusement toute
/// demande, et une recette qui verifie "une sonde a-t-elle ete demandee" passe
/// sans rien mesurer. C'est exactement ce qui est arrive.
///
/// Rendre les deux bouts permet de CONSTATER qu'une sonde est partie, et de
/// fournir le verdict de son choix.
pub fn en_deux_bouts(capacite: usize) -> (Poignee, mpsc::Receiver<Duration>, mpsc::Sender<Sonde>) {
    let (demandes, recevoir) = mpsc::channel(capacite.max(1));
    let (rendre, resultats) = mpsc::channel(capacite.max(1));
    (
        Poignee {
            demandes,
            resultats,
        },
        recevoir,
        rendre,
    )
}

async fn tenir(
    adresse: Adresse,
    mut demandes: mpsc::Receiver<Duration>,
    rendre: mpsc::Sender<Sonde>,
) {
    while let Some(budget) = demandes.recv().await {
        let issue = sonder(&adresse, CIBLE, budget).await;
        // Le superviseur a pu disparaitre entre-temps: c'est un arret, pas une
        // faute.
        if rendre.send(issue).await.is_err() {
            return;
        }
    }
}

/// Un aller-retour a travers la sortie courante.
///
/// Une erreur de transport vers l'API - le coeur n'est pas la, il n'ecoute pas
/// encore, il vient de mourir - rend [`Sonde::Impossible`] et non
/// [`Sonde::Echouee`]. La distinction est la propriete qui compte: un coeur
/// absent est une panne CHEZ NOUS, et la lire comme un pair muet demonterait un
/// tunnel pour une raison qui n'a rien a voir avec le reseau. Le superviseur a
/// par ailleurs son propre signal pour un coeur mort, qu'il tient de l'atelier.
///
/// # Pourquoi la cible est un argument et non le constant lu sur place
///
/// Pour que la recette d'integration puisse viser un temoin LOCAL. Le seul
/// interet de cette fonction est la traduction du statut HTTP en verdict, et
/// cette traduction n'est ecrite nulle part en amont: elle a ete mesuree contre
/// le binaire epingle. La verifier demande donc un vrai coeur, et la faire
/// dependre d'un acces a internet la rendrait verte ou rouge selon la salle ou
/// elle tourne.
///
/// Ce n'est PAS un reglage. La production ne passe jamais autre chose que
/// [`CIBLE`], et ne doit pas: voir l'en-tete du module, une cible choisie par
/// l'operateur distinguerait ce client de tous les autres, ce qui est
/// exactement ce qu'un outil de contournement doit eviter.
pub async fn sonder(adresse: &Adresse, cible: &str, budget: Duration) -> Sonde {
    let chemin = clash::chemin_du_delai(&adresse.selecteur, cible, budget);
    match clash::envoyer_avec(
        adresse.api,
        "GET",
        &chemin,
        &adresse.secret,
        None,
        budget + MARGE,
    )
    .await
    {
        Ok((statut, _)) => clash::issue_du_delai(statut),
        Err(_) => Sonde::Impossible,
    }
}
