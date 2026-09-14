//! L'adresse locale STABLE derriere laquelle les coeurs se remplacent.
//!
//! Document 04 partie 4: le superviseur maison "active l'un ou l'autre selon le
//! protocole choisi et expose un SOCKS local unique stable vers lequel le
//! systeme (via TUN) est route". Partie 3.2, sur la bascule en cours de
//! session: "le SOCKS local reste stable, le kill switch WFP/nftables n'est
//! jamais leve pendant la bascule".
//!
//! Ces deux phrases decrivent la meme piece, et c'est celle-ci. Elle existe
//! pour une raison precise: **changer de technique ne doit pas changer l'adresse
//! que le systeme utilise pour sortir.** Sans elle, chaque bascule
//! demanderait de reconfigurer le chemin des paquets, donc de toucher aux
//! routes ou aux filtres pendant que le trafic passe - exactement le moment ou
//! le document interdit de lever la garde.
//!
//! # Ce qu'elle ne fait pas: parler SOCKS
//!
//! Et ce n'est pas un raccourci. Le client parle SOCKS5 au coeur, qui le parle
//! aussi: la facade n'a donc qu'a faire passer les octets. Les analyser pour
//! les reecrire a l'identique ajouterait une implementation de RFC 1928 dans le
//! chemin de production, avec ses cas limites, pour aboutir aux memes octets.
//!
//! Ce qu'elle rend stable est donc l'ADRESSE, pas un protocole. Le nom "facade"
//! plutot que "SOCKS local" dit cela, parce que la difference se paie le jour
//! ou quelqu'un cherche ici du code qui n'y est pas.
//!
//! # Quand aucun coeur ne tourne
//!
//! La connexion est FERMEE tout de suite, jamais mise en attente. Un client
//! suspendu ne sait pas s'il attend un reseau lent ou un tunnel absent, et
//! l'application qui est derriere finit par decider elle-meme - souvent en
//! reessayant hors du tunnel. Fermer est le refus que le plan demande partout
//! ailleurs: echouer garde est le bon echec.
//!
//! # Ce qu'une bascule coute, et qu'il faut dire
//!
//! Les connexions DEJA ouvertes a travers l'ancien coeur tombent avec lui: il
//! n'y a pas de moyen honnete de les recoudre, leur etat vivant etant dans le
//! processus qui meurt. Ce qui survit est l'adresse, donc les connexions
//! SUIVANTES n'ont rien a reapprendre. C'est ce que le document appelle garder
//! l'etat applicatif, et c'est tout ce qu'on peut garder.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

/// Delai d'etablissement vers le coeur.
///
/// Court a dessein: le coeur ecoute sur la boucle locale de la meme machine.
/// Au-dela, ce n'est pas un reseau lent, c'est un coeur qui ne repond pas, et
/// faire patienter le client ne le rendrait pas plus vivant.
pub const DELAI_VERS_LE_COEUR: Duration = Duration::from_secs(2);

/// Ou la facade ecoute, et vers quoi elle mene.
///
/// L'arriere est un canal `watch` et non une valeur: la facade doit voir un
/// changement de coeur sans etre recreee, puisque ne pas etre recreee est
/// precisement sa raison d'etre.
pub struct Facade {
    ecoute: TcpListener,
    arriere: watch::Receiver<Option<SocketAddr>>,
}

/// Ouvre la facade et rend l'adresse REELLEMENT obtenue.
///
/// L'adresse est rendue plutot que supposee: demander le port 0 est la seule
/// facon d'ecrire une recette qui ne se dispute pas un port fixe avec la
/// machine qui l'execute, et il faut alors savoir lequel le systeme a donne.
pub async fn ouvrir(
    ecoute: SocketAddr,
    arriere: watch::Receiver<Option<SocketAddr>>,
) -> std::io::Result<(SocketAddr, Facade)> {
    let ecoute = TcpListener::bind(ecoute).await?;
    let adresse = ecoute.local_addr()?;
    Ok((adresse, Facade { ecoute, arriere }))
}

impl Facade {
    /// Sert jusqu'a ce que l'appelant abandonne la tache.
    pub async fn servir(self) {
        loop {
            let Ok((client, _)) = self.ecoute.accept().await else {
                // Une acceptation qui echoue n'est pas une raison d'arreter de
                // servir: le cas courant est une limite de descripteurs, qui
                // passe. Fermer la facade ici couperait la sortie de tout le
                // systeme pour un incident transitoire.
                continue;
            };
            let arriere = *self.arriere.borrow();
            tokio::spawn(async move {
                if let Err(raison) = relayer(client, arriere).await {
                    tracing::debug!(%raison, "connexion non relayee");
                }
            });
        }
    }
}

/// Fait passer les octets entre le client et le coeur.
async fn relayer(mut client: TcpStream, arriere: Option<SocketAddr>) -> Result<(), String> {
    let Some(arriere) = arriere else {
        // Fermer, pas attendre: voir l'en-tete du module.
        let _ = client.shutdown().await;
        return Err(
            "aucun coeur actif: connexion fermee au lieu d'etre mise en attente".to_owned(),
        );
    };
    let coeur = tokio::time::timeout(DELAI_VERS_LE_COEUR, TcpStream::connect(arriere))
        .await
        .map_err(|_| format!("le coeur a {arriere} n'a pas repondu en {DELAI_VERS_LE_COEUR:?}"))?
        .map_err(|e| format!("le coeur a {arriere} est injoignable: {e}"))?;

    let mut coeur = coeur;
    tokio::io::copy_bidirectional(&mut client, &mut coeur)
        .await
        .map_err(|e| format!("relais interrompu: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    /// Un serveur qui renvoie ce qu'on lui envoie, prefixe de son etiquette.
    /// L'etiquette est ce qui permet de dire PAR QUEL arriere on est passe.
    async fn arriere_etiquete(etiquette: &'static str) -> SocketAddr {
        let ecoute = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let adresse = ecoute.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut flux, _)) = ecoute.accept().await {
                tokio::spawn(async move {
                    let mut tampon = [0u8; 64];
                    if let Ok(n) = flux.read(&mut tampon).await
                        && n > 0
                    {
                        let _ = flux.write_all(etiquette.as_bytes()).await;
                        let _ = flux.write_all(&tampon[..n]).await;
                        let _ = flux.flush().await;
                    }
                });
            }
        });
        adresse
    }

    /// Envoie un mot par la facade et rend ce qui revient.
    async fn aller_retour(facade: SocketAddr, mot: &str) -> std::io::Result<String> {
        let mut flux = TcpStream::connect(facade).await?;
        flux.write_all(mot.as_bytes()).await?;
        flux.flush().await?;
        let mut recu = Vec::new();
        flux.read_to_end(&mut recu).await?;
        Ok(String::from_utf8_lossy(&recu).into_owned())
    }

    #[tokio::test]
    async fn les_octets_passent_jusqu_au_coeur_et_reviennent() {
        let arriere = arriere_etiquete("A:").await;
        let (_tx, rx) = watch::channel(Some(arriere));
        let (adresse, facade) = ouvrir("127.0.0.1:0".parse().unwrap(), rx).await.unwrap();
        tokio::spawn(facade.servir());

        assert_eq!(aller_retour(adresse, "salut").await.unwrap(), "A:salut");
    }

    /// Le point du module: l'adresse d'ecoute ne bouge pas quand le coeur
    /// change. Sans cela, chaque bascule demanderait de reconfigurer le chemin
    /// des paquets pendant que le trafic passe.
    #[tokio::test]
    async fn l_adresse_ne_bouge_pas_quand_le_coeur_change() {
        let premier = arriere_etiquete("A:").await;
        let second = arriere_etiquete("B:").await;
        let (tx, rx) = watch::channel(Some(premier));
        let (adresse, facade) = ouvrir("127.0.0.1:0".parse().unwrap(), rx).await.unwrap();
        tokio::spawn(facade.servir());

        assert_eq!(aller_retour(adresse, "un").await.unwrap(), "A:un");

        tx.send(Some(second)).unwrap();

        assert_eq!(
            aller_retour(adresse, "deux").await.unwrap(),
            "B:deux",
            "la nouvelle connexion devait aller au nouveau coeur"
        );
        // Ce que ce test prouve tient dans sa structure et non dans une
        // assertion de plus: les deux allers-retours passent par la MEME
        // `adresse`, sans que la facade ait ete rouverte entre les deux.
    }

    /// Un client suspendu ne sait pas s'il attend un reseau lent ou un tunnel
    /// absent, et l'application derriere finit par decider elle-meme, souvent
    /// en reessayant hors du tunnel.
    #[tokio::test]
    async fn sans_coeur_actif_la_connexion_est_fermee_et_non_mise_en_attente() {
        let (_tx, rx) = watch::channel(None);
        let (adresse, facade) = ouvrir("127.0.0.1:0".parse().unwrap(), rx).await.unwrap();
        tokio::spawn(facade.servir());

        let recu = tokio::time::timeout(Duration::from_secs(2), aller_retour(adresse, "salut"))
            .await
            .expect("la facade ne doit pas faire attendre");
        assert_eq!(
            recu.unwrap_or_default(),
            "",
            "rien ne doit revenir quand aucun coeur ne tourne"
        );
    }

    /// Un coeur declare mais mort ne doit pas non plus faire patienter. Le cas
    /// arrive vraiment: le processus meurt entre sa publication et la
    /// connexion suivante.
    #[tokio::test]
    async fn un_coeur_declare_mais_injoignable_ne_fait_pas_attendre() {
        // Un port qu'on vient de liberer: personne n'ecoute derriere.
        let mort = {
            let ecoute = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let a = ecoute.local_addr().unwrap();
            drop(ecoute);
            a
        };
        let (_tx, rx) = watch::channel(Some(mort));
        let (adresse, facade) = ouvrir("127.0.0.1:0".parse().unwrap(), rx).await.unwrap();
        tokio::spawn(facade.servir());

        let recu = tokio::time::timeout(
            DELAI_VERS_LE_COEUR + Duration::from_secs(2),
            aller_retour(adresse, "salut"),
        )
        .await
        .expect("la facade ne doit pas depasser son propre delai");
        assert_eq!(recu.unwrap_or_default(), "");
    }

    /// Deux clients a la fois: une facade qui servirait en serie bloquerait
    /// tout le systeme sur la connexion la plus lente.
    #[tokio::test]
    async fn deux_clients_sont_servis_en_meme_temps() {
        let arriere = arriere_etiquete("A:").await;
        let (_tx, rx) = watch::channel(Some(arriere));
        let (adresse, facade) = ouvrir("127.0.0.1:0".parse().unwrap(), rx).await.unwrap();
        tokio::spawn(facade.servir());

        let (un, deux) = tokio::join!(aller_retour(adresse, "un"), aller_retour(adresse, "deux"));
        assert_eq!(un.unwrap(), "A:un");
        assert_eq!(deux.unwrap(), "A:deux");
    }
}
