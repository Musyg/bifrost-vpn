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
//! # Qui peut partager son port
//!
//! Son seul client est le passeur du meme processus, qui frappe l'adresse
//! exacte qu'[`ouvrir`](crate::coeurs::facade::ouvrir) a rendue. Ce qu'un tiers peut faire de ce port depend
//! de la plateforme (mesure par `tests/proprietaire_squat.rs`):
//!
//! - **Linux**: tokio, par mio, pose `SO_REUSEADDR` et jamais `SO_REUSEPORT`.
//!   Le noyau refuse deux ecoutes qui se recouvrent - la meme adresse, ou
//!   `0.0.0.0` et `127.0.0.1` - tant qu'elles ne posent pas TOUTES DEUX
//!   `SO_REUSEPORT`, sous le meme UID: aucun tiers ne partage le port, dans
//!   aucun ordre. S'il le
//!   tient d'abord, `ouvrir` echoue et le daemon le dit.
//! - **Windows**: la meme adresse, tenue d'abord, fait echouer `ouvrir`. Une
//!   ecoute LARGE (`0.0.0.0`), elle, se lie a cote de la facade dans les deux
//!   ordres. C'est alors la facade, plus precise, qui recoit les connexions vers
//!   `127.0.0.1`, tant qu'elle ecoute - donc tant que le daemon, et le passeur
//!   avec lui, vit.
//!
//! Ce que la facade VERIFIE a chaque connexion est l'autre bout: l'entree SOCKS
//! du coeur, que [`proprietaire`](crate::coeurs::proprietaire) authentifie
//! avant le premier octet.
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

use super::atelier::CoeurPublie;
use super::proprietaire;

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
/// precisement sa raison d'etre. Il porte un [`CoeurPublie`] et non une simple
/// adresse: la facade a besoin du PID pour VERIFIER, avant chaque connexion,
/// que l'entree SOCKS est toujours tenue par le coeur qu'on a lance.
pub struct Facade {
    ecoute: TcpListener,
    arriere: watch::Receiver<Option<CoeurPublie>>,
}

/// Ouvre la facade et rend l'adresse REELLEMENT obtenue.
///
/// L'adresse est rendue plutot que supposee: demander le port 0 est la seule
/// facon d'ecrire une recette qui ne se dispute pas un port fixe avec la
/// machine qui l'execute, et il faut alors savoir lequel le systeme a donne.
pub async fn ouvrir(
    ecoute: SocketAddr,
    arriere: watch::Receiver<Option<CoeurPublie>>,
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
async fn relayer(mut client: TcpStream, arriere: Option<CoeurPublie>) -> Result<(), String> {
    let Some(coeur) = arriere else {
        // Fermer, pas attendre: voir l'en-tete du module.
        let _ = client.shutdown().await;
        return Err(
            "aucun coeur actif: connexion fermee au lieu d'etre mise en attente".to_owned(),
        );
    };
    // AVANT de verser le moindre octet utilisateur - en clair, avant que le
    // coeur ne le chiffre - verifier que l'entree SOCKS est TOUJOURS tenue par
    // le coeur qu'on a lance. Entre la publication et cette connexion, le coeur
    // a pu mourir et un squatteur reprendre le port; sans ce controle, la facade
    // lui menerait le trafic. La verification precede immediatement la connexion,
    // ce qui reduit la course a la borne que decrit `super::proprietaire`.
    let arriere = coeur.socks;
    if let Err(raison) =
        proprietaire::exiger_le_coeur(arriere.port(), coeur.attendu(), "l'entree SOCKS")
    {
        let _ = client.shutdown().await;
        return Err(raison);
    }
    let flux = tokio::time::timeout(DELAI_VERS_LE_COEUR, TcpStream::connect(arriere))
        .await
        .map_err(|_| format!("le coeur a {arriere} n'a pas repondu en {DELAI_VERS_LE_COEUR:?}"))?
        .map_err(|e| format!("le coeur a {arriere} est injoignable: {e}"))?;

    let mut flux = flux;
    tokio::io::copy_bidirectional(&mut client, &mut flux)
        .await
        .map_err(|e| format!("relais interrompu: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    /// Un coeur publie dont l'arriere est une ecoute du PROCESSUS DE TEST.
    ///
    /// Toutes les recettes de ce module font ecouter leur arriere dans le
    /// processus de test lui-meme: son proprietaire est donc notre propre PID.
    /// La facade verifie desormais la propriete avant de relayer; construire le
    /// [`CoeurPublie`] avec `std::process::id()` fait passer ce controle comme le
    /// vrai coeur le ferait en production, sans quoi la facade refuserait ses
    /// propres arrieres de test.
    fn coeur_en_test(socks: SocketAddr) -> CoeurPublie {
        CoeurPublie {
            socks,
            api: None,
            pid: std::process::id(),
            uid: None,
            demarrage: proprietaire::date_de_demarrage(std::process::id()).ok(),
        }
    }

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
        let (_tx, rx) = watch::channel(Some(coeur_en_test(arriere)));
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
        let (tx, rx) = watch::channel(Some(coeur_en_test(premier)));
        let (adresse, facade) = ouvrir("127.0.0.1:0".parse().unwrap(), rx).await.unwrap();
        tokio::spawn(facade.servir());

        assert_eq!(aller_retour(adresse, "un").await.unwrap(), "A:un");

        tx.send(Some(coeur_en_test(second))).unwrap();

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
    ///
    /// Depuis la fermeture de la classe, ce cas est refuse PLUS TOT et plus
    /// franchement: la facade verifie la propriete de l'entree avant de s'y
    /// connecter, et un port qui n'est plus une ecoute tenue par le PID publie
    /// n'est meme pas joint. Le delai `DELAI_VERS_LE_COEUR` reste comme filet de
    /// la course residuelle (le coeur meurt APRES la verification, avant la
    /// connexion); ici c'est la verification qui tranche. La propriete observable
    /// est la meme qu'avant: aucune attente, rien qui revient.
    #[tokio::test]
    async fn un_coeur_declare_mais_injoignable_ne_fait_pas_attendre() {
        // Un port TENU sans ecoute: personne derriere, et personne ne peut s'y
        // mettre. Un port lie puis relache, comme avant le 30/09/2026, peut
        // etre rendu par l'attribueur de Windows a une autre liaison, y
        // compris a la connexion sortante de la facade elle-meme, qui aboutit
        // alors sur elle-meme: la facade relaie vers quelque chose qui ne
        // ferme jamais, et la recette tombe sur son echeance. Rouge 2 fois sur
        // 314 suites de ce crate lancees deux a deux, sur dev-windows, le
        // 30/09/2026; 0 sur 314 avec le port tenu. Voir `super::super::port`.
        let tenu = super::super::port::port_sans_personne().unwrap();
        let mort = tenu.adresse();
        // Le PID publie est le notre (le port tenu est a nous), mais l'ecoute
        // n'existe pas: la verification rend `PersonneEncore`, donc un refus.
        let (_tx, rx) = watch::channel(Some(coeur_en_test(mort)));
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
        let (_tx, rx) = watch::channel(Some(coeur_en_test(arriere)));
        let (adresse, facade) = ouvrir("127.0.0.1:0".parse().unwrap(), rx).await.unwrap();
        tokio::spawn(facade.servir());

        let (un, deux) = tokio::join!(aller_retour(adresse, "un"), aller_retour(adresse, "deux"));
        assert_eq!(un.unwrap(), "A:un");
        assert_eq!(deux.unwrap(), "A:deux");
    }
}
