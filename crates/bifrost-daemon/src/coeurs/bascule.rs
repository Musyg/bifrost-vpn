//! La bascule a chaud du selecteur, qui rend la course autre chose qu'un
//! affichage.
//!
//! [`bifrost_evasion::course`] sait quel candidat vient apres celui qui vient
//! d'echouer. Ce module est ce qui le met en service, sans rien relancer.
//!
//! # Pourquoi une bascule et non une reconnexion
//!
//! Document 04 partie 3.2, "degradation en cours de session": basculer vers le
//! candidat suivant EN GARDANT l'etat applicatif, le SOCKS local reste stable,
//! le kill switch n'est jamais leve pendant la bascule. Les trois tiennent
//! parce que les candidats sont ecrits ensemble derriere un seul selecteur,
//! dans un seul processus: changer de sortie ne demonte rien, ne rouvre aucun
//! port et ne touche pas au pare-feu.
//!
//! Une reconnexion ferait l'inverse des trois. C'est aussi ce que la partie 3.3
//! decrit en toutes lettres - "un superviseur maison qui pilote le selector via
//! la Clash API" - et le diagnostic tient toujours: verifie le 20 aout 2026,
//! l'`urltest` amont ne choisit que par LATENCE, n'a aucun repli sur echec, et
//! les demandes qui reclament un tel repli (SagerNet/sing-box#2130 et #2061)
//! sont toujours ouvertes. Il n'y a donc rien de natif a adopter a la place.
//!
//! # Pourquoi le verdict est VERIFIE et non deduit du statut
//!
//! `PUT /proxies/<selecteur>` rend 204 quand le coeur a ACCEPTE la requete. Ce
//! n'est pas la meme chose que d'avoir change de sortie. Se fier au statut
//! ferait croire la course avancee alors que le trafic continuerait de passer
//! par la sortie gelee, et le tunnel mourrait une seconde fois sans qu'on
//! comprenne pourquoi. On relit donc le selecteur et on compare, ce que
//! [`super::clash::lire_selection`] est la pour faire.
//!
//! # Pourquoi elle ne bloque jamais le superviseur
//!
//! Meme raison que [`super::vitalite`], mot pour mot: le fil du superviseur
//! tient le kill switch et repond aux commandes. Deux allers-retours HTTP, meme
//! sur la boucle locale, n'ont rien a y faire. La bascule est donc DEMANDEE
//! d'un cote et RAMASSEE de l'autre.

use tokio::sync::mpsc;

use super::clash;
use super::vitalite::Adresse;

/// Profondeur des deux files. Une seule bascule peut etre en vol - la course
/// n'a qu'un candidat courant - donc une place suffit, et une file pleine est
/// un signal utile plutot qu'une attente.
const PROFONDEUR: usize = 1;

/// Ce que la bascule a obtenu.
///
/// Les deux variantes nomment la sortie VOULUE, pas celle qui sert: c'est ce
/// que l'appelant a demande, et c'est ce qu'il compare a ce qu'il attendait.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Issue {
    /// Le coeur sert desormais cette sortie, RELU et non deduit.
    Faite { sortie: String },
    /// La bascule n'a pas eu lieu. La raison est celle du coeur ou du
    /// transport, jamais une invention d'ici.
    ///
    /// C'est une panne LOCALE au sens de
    /// [`bifrost_evasion::course::Echec::accuse_le_reseau`]: un coeur qui
    /// refuse notre requete de controle ne dit rien du reseau traverse, et le
    /// porter au carnet ecarterait une technique d'un reseau pour une raison
    /// qui n'a rien a voir avec lui.
    Refusee { sortie: String, raison: String },
}

/// Ce que le superviseur tient. Ni `demander` ni `ramasser` ne bloquent.
pub struct Poignee {
    demandes: mpsc::Sender<String>,
    resultats: mpsc::Receiver<Issue>,
}

impl Poignee {
    /// Demande le passage a cette sortie.
    ///
    /// Rend faux si la precedente n'a pas encore rendu son verdict. La course
    /// n'en demande qu'une a la fois, donc cela ne devrait pas arriver; si cela
    /// arrivait, cela ne doit surtout pas faire attendre le superviseur.
    pub fn demander(&self, sortie: &str) -> bool {
        self.demandes.try_send(sortie.to_owned()).is_ok()
    }

    /// Ramasse un verdict s'il y en a un.
    pub fn ramasser(&mut self) -> Option<Issue> {
        self.resultats.try_recv().ok()
    }
}

/// Ouvre la bascule. Le futur rendu doit tourner sur le runtime.
///
/// L'adresse est celle de [`super::vitalite`], le MEME type et, en production,
/// la meme valeur. Ce n'est pas une economie: si la sonde et la bascule
/// visaient deux selecteurs, on basculerait l'un en sondant l'autre, et le
/// tunnel paraitrait gele juste apres avoir ete repare.
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
/// Meme seam que [`super::vitalite::en_deux_bouts`], et pour la meme raison
/// mesuree: sans lui, une doublure doit laisser tomber le futur rendu par
/// [`ouvrir`], ce qui emporte le recepteur des demandes; la poignee refuse
/// alors silencieusement toute demande, et une recette qui verifie "une bascule
/// a-t-elle ete demandee" passe sans rien mesurer.
pub fn en_deux_bouts(capacite: usize) -> (Poignee, mpsc::Receiver<String>, mpsc::Sender<Issue>) {
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
    mut demandes: mpsc::Receiver<String>,
    rendre: mpsc::Sender<Issue>,
) {
    while let Some(sortie) = demandes.recv().await {
        let issue = basculer(&adresse, &sortie).await;
        // Le superviseur a pu disparaitre entre-temps: c'est un arret, pas une
        // faute.
        if rendre.send(issue).await.is_err() {
            return;
        }
    }
}

/// Demande le passage, puis RELIT pour savoir s'il a eu lieu.
///
/// Voir l'en-tete: un 204 dit que le coeur a compris, pas qu'il a change. La
/// relecture est ce qui distingue les deux, et elle ne coute qu'un aller-retour
/// sur la boucle locale.
pub async fn basculer(adresse: &Adresse, sortie: &str) -> Issue {
    if let Err(e) = clash::choisir(adresse.api, &adresse.secret, &adresse.selecteur, sortie).await {
        return Issue::Refusee {
            sortie: sortie.to_owned(),
            raison: e.to_string(),
        };
    }
    match clash::lire_selection(adresse.api, &adresse.secret, &adresse.selecteur).await {
        Ok(servie) if servie == sortie => Issue::Faite {
            sortie: sortie.to_owned(),
        },
        Ok(servie) => Issue::Refusee {
            sortie: sortie.to_owned(),
            raison: format!("le coeur a accepte la requete mais sert toujours {servie}"),
        },
        Err(e) => Issue::Refusee {
            sortie: sortie.to_owned(),
            raison: format!("bascule inverifiable: {e}"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Une API Clash qui ACCEPTE tout et ne change JAMAIS de sortie.
    ///
    /// C'est le seul cas ou la relecture sert a quelque chose, et un vrai
    /// sing-box ne le produit pas: interroge le 20 aout 2026 avec le binaire
    /// epingle 1.13.18, il refuse une etiquette inconnue par un statut non-204,
    /// donc `choisir` echoue et la relecture n'a rien a rattraper. La recette
    /// contre un vrai coeur ne pouvait donc PAS falsifier la relecture - elle
    /// restait verte quand on la supprimait, ce qu'une falsification a montre.
    ///
    /// Cette doublure produit le cas manquant. Elle ne remplace pas la recette
    /// contre un vrai coeur, qui mesure le protocole; elle mesure ce que NOUS
    /// faisons d'une reponse qui ment.
    ///
    /// Le client lit jusqu'a la fermeture (`read_to_end`), donc la doublure
    /// repond puis ferme.
    async fn api_qui_accepte_sans_rien_faire(sert: &'static str) -> SocketAddr {
        let ecoute = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("un port libre sur la boucle locale");
        let adresse = ecoute.local_addr().expect("l'adresse liee");
        tokio::spawn(async move {
            while let Ok((mut flux, _)) = ecoute.accept().await {
                let mut tampon = [0u8; 2048];
                let lus = flux.read(&mut tampon).await.unwrap_or(0);
                let requete = String::from_utf8_lossy(&tampon[..lus]).into_owned();
                let reponse = if requete.starts_with("PUT ") {
                    "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".to_owned()
                } else {
                    let corps = format!("{{\"now\":\"{sert}\"}}");
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{corps}",
                        corps.len()
                    )
                };
                let _ = flux.write_all(reponse.as_bytes()).await;
                let _ = flux.shutdown().await;
            }
        });
        adresse
    }

    fn adresse_de(api: SocketAddr) -> Adresse {
        Adresse {
            api,
            secret: "secret-de-recette".to_owned(),
            selecteur: "select".to_owned(),
        }
    }

    /// Un 204 ne suffit pas: la sortie servie fait foi.
    ///
    /// Sans la relecture, la course se croirait avancee pendant que le trafic
    /// continuerait de passer par la sortie gelee, et le tunnel mourrait une
    /// seconde fois sans qu'on comprenne pourquoi.
    #[tokio::test]
    async fn un_204_qui_ne_change_rien_est_une_bascule_refusee() {
        let api = api_qui_accepte_sans_rien_faire("premier").await;
        let issue = basculer(&adresse_de(api), "second").await;
        match issue {
            Issue::Refusee { sortie, raison } => {
                assert_eq!(sortie, "second");
                assert!(
                    raison.contains("sert toujours premier"),
                    "la raison doit nommer ce que le coeur sert VRAIMENT: {raison}"
                );
            }
            Issue::Faite { .. } => {
                panic!(
                    "le coeur n'a pas change de sortie: se fier au 204 laisse le trafic sur la sortie gelee"
                )
            }
        }
    }

    /// Et quand la sortie servie est bien celle qu'on a demandee, c'est fait.
    ///
    /// Le pendant du precedent: sans lui, une mise en oeuvre qui refuserait
    /// TOUJOURS passerait la recette ci-dessus sans rien piloter.
    #[tokio::test]
    async fn une_sortie_servie_conforme_est_une_bascule_faite() {
        let api = api_qui_accepte_sans_rien_faire("second").await;
        assert_eq!(
            basculer(&adresse_de(api), "second").await,
            Issue::Faite {
                sortie: "second".to_owned()
            }
        );
    }

    /// Une API muette ne rend pas une bascule FAITE.
    ///
    /// L'echec de transport est une panne locale, pas une reussite optimiste.
    #[tokio::test]
    async fn une_api_absente_refuse_la_bascule() {
        // Un port ou personne n'ecoute: on lie puis on relache aussitot.
        let libre = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let api = libre.local_addr().unwrap();
        drop(libre);
        assert!(matches!(
            basculer(&adresse_de(api), "second").await,
            Issue::Refusee { .. }
        ));
    }
}
