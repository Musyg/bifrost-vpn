//! Client SOCKS5 minimal, pour verifier qu'un coeur transporte vraiment.
//!
//! Ecrit a la main, comme le client Clash, et pour la meme raison: la surface
//! utilisee tient en deux echanges, et un produit de securite n'a pas a tirer
//! un arbre de dependances pour ca.
//!
//! Il a d'abord servi de recette - le seul moyen de prouver que le trafic passe
//! REELLEMENT par le coeur plutot que de croire un selecteur sur parole. Il est
//! depuis aussi le chemin de production: [`super::passeur`] s'en sert pour
//! chaque connexion tiree du TUN. RFC 1928.
//!
//! Les deux emplois n'envoient pas la meme requete, et la difference n'est pas
//! cosmetique. La recette vise un NOM, pour que la resolution se fasse a la
//! sortie du tunnel. Le passeur, lui, ne connait qu'une ADRESSE: il lit des
//! paquets IP, ou la resolution a deja eu lieu. Lui faire ecrire cette adresse
//! sous forme de nom marcherait chez la plupart des coeurs, mais ce serait
//! ecrire un mensonge dans le protocole, et compter sur l'indulgence du
//! lecteur.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub const VERSION: u8 = 0x05;
pub const SANS_AUTHENTIFICATION: u8 = 0x00;
/// Nom et mot de passe, RFC 1929.
pub const AVEC_MOT_DE_PASSE: u8 = 0x02;
/// Version de la SOUS-negociation, qui n'est pas celle de SOCKS. RFC 1929,
/// verifiee a la source le 20 aout 2026: "The VER field contains the current
/// version of the subnegotiation, which is X'01'". Les confondre est l'erreur
/// classique, et elle produit un refus que rien n'explique.
pub const SOUS_NEGOCIATION: u8 = 0x01;
/// Le seul STATUS favorable de la RFC 1929. "If the server returns a 'failure'
/// (STATUS value other than X'00') status, it MUST close the connection."
pub const AUTHENTIFIE: u8 = 0x00;
pub const COMMANDE_CONNECT: u8 = 0x01;
/// Ouvre une association UDP. Le mandataire rend alors l'adresse d'un relais
/// vers lequel envoyer les datagrammes, encapsules.
pub const COMMANDE_ASSOCIER_UDP: u8 = 0x03;
pub const TYPE_IPV4: u8 = 0x01;
pub const TYPE_NOM: u8 = 0x03;
pub const TYPE_IPV6: u8 = 0x04;
pub const SUCCES: u8 = 0x00;

pub const DELAI: Duration = Duration::from_secs(8);

/// Ce que le coeur exige de quiconque se presente a son entree SOCKS.
///
/// # Pourquoi cette entree est authentifiee
///
/// Parce que la boucle locale n'est pas une frontiere. Mesure le 20 aout 2026
/// sur le banc en espaces de noms: un processus tiers - ni le passeur, ni le
/// coeur - se connectait a `127.0.0.1:1080` sans rien presenter et obtenait une
/// banniere joignable seulement par la SORTIE du tunnel. FlClash #1934 (ouvert
/// le 7 avril 2026, toujours ouvert au 20 aout) decrit le meme mecanisme et ce
/// qu'il coute vraiment: une application quelconque y lit l'IP de sortie du
/// serveur, donc de quoi le faire bloquer. Pour un outil de contournement,
/// c'est l'actif que tout le document 04 partie 4 apprend a proteger, perdu par
/// la porte de derriere.
///
/// # Ce que cette protection vaut, et ou elle s'arrete
///
/// Les identifiants sont engendres a chaque demarrage et n'apparaissent que
/// dans la configuration engendree, ecrite en 0600 et donnee au compte du
/// coeur. Ils sont donc exactement aussi proteges que le secret de l'API de
/// controle, et pas davantage: un autre processus tournant SOUS LE MEME COMPTE
/// les lit. C'est une raison de plus de donner au coeur un compte dedie plutot
/// que `nobody`, qui est partage.
#[derive(Clone, PartialEq, Eq)]
pub struct Identifiants {
    utilisateur: String,
    mot_de_passe: String,
}

impl Identifiants {
    /// Refuse ici ce que la RFC 1929 ne saurait transporter.
    ///
    /// Les deux longueurs y tiennent sur un octet. Rejeter a la CONSTRUCTION
    /// plutot qu'a l'envoi n'est pas un detail de style: entre les deux, la
    /// configuration du coeur aurait deja ete ecrite avec un compte que
    /// personne ne peut presenter, et la panne se serait montree bien plus
    /// tard, sous la forme d'un coeur qui refuse son propre passeur.
    pub fn nouveaux(utilisateur: &str, mot_de_passe: &str) -> anyhow::Result<Self> {
        for (quoi, champ) in [("nom", utilisateur), ("mot de passe", mot_de_passe)] {
            // En OCTETS, ce que `str::len` rend, et non en caracteres: c'est
            // ce que la RFC compte.
            let n = champ.len();
            if n == 0 || n > 255 {
                anyhow::bail!("{quoi} de longueur impossible pour la RFC 1929: {n}");
            }
        }
        Ok(Self {
            utilisateur: utilisateur.to_owned(),
            mot_de_passe: mot_de_passe.to_owned(),
        })
    }

    pub fn utilisateur(&self) -> &str {
        &self.utilisateur
    }

    pub fn mot_de_passe(&self) -> &str {
        &self.mot_de_passe
    }
}

impl std::fmt::Debug for Identifiants {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Identifiants({}, <redacted>)", self.utilisateur)
    }
}

/// Ou frapper, et ce qu'il faut dire en arrivant.
///
/// Les deux ne voyagent jamais l'un sans l'autre: une adresse seule ferait un
/// appelant qui se presente les mains vides, ce qui est exactement l'etat que
/// ce chantier a ferme. Les tenir ensemble rend l'oubli impossible plutot
/// qu'improbable.
#[derive(Clone, Debug)]
pub struct Mandataire {
    pub adresse: SocketAddr,
    pub identifiants: Identifiants,
}

impl Mandataire {
    pub fn nouveau(adresse: SocketAddr, identifiants: Identifiants) -> Self {
        Self {
            adresse,
            identifiants,
        }
    }
}

/// Salutation: version, une methode proposee, nom et mot de passe.
///
/// UNE seule methode, et pas deux. Proposer aussi "sans authentification"
/// laisserait le coeur choisir, et un coeur qui choisirait 0x00 serait un coeur
/// qui n'exige rien - donc une configuration qui n'a pas pris. Cet etat doit se
/// voir, pas se rattraper en silence.
pub fn salutation() -> [u8; 3] {
    [VERSION, 1, AVEC_MOT_DE_PASSE]
}

/// La reponse a la salutation est-elle exploitable.
pub fn salutation_acceptee(reponse: &[u8]) -> bool {
    reponse.len() == 2 && reponse[0] == VERSION && reponse[1] == AVEC_MOT_DE_PASSE
}

/// Sous-negociation de la RFC 1929: `VER | ULEN | UNAME | PLEN | PASSWD`.
///
/// Ne rend pas de `Result`, et c'est voulu: [`Identifiants::nouveaux`] a deja
/// refuse ce qui ne tient pas sur un octet, et les champs sont prives. Poser
/// ici une seconde garde donnerait une branche qu'aucune recette ne peut
/// atteindre - donc une garde dont on ne saurait jamais si elle mord.
pub fn sous_negociation(id: &Identifiants) -> Vec<u8> {
    let u = id.utilisateur.as_bytes();
    let p = id.mot_de_passe.as_bytes();
    let mut m = vec![SOUS_NEGOCIATION, u.len() as u8];
    m.extend_from_slice(u);
    m.push(p.len() as u8);
    m.extend_from_slice(p);
    m
}

/// La reponse a la sous-negociation vaut-elle authentification.
///
/// Tout ce qui n'est pas exactement `VER=0x01, STATUS=0x00` est un refus, y
/// compris une reponse qu'on ne comprend pas.
pub fn sous_negociation_acceptee(reponse: &[u8]) -> bool {
    reponse.len() == 2 && reponse[0] == SOUS_NEGOCIATION && reponse[1] == AUTHENTIFIE
}

/// Requete CONNECT vers un hote NOMME.
///
/// Le nom est envoye tel quel plutot que resolu ici, et c'est le point: la
/// resolution se fait alors du cote du coeur, donc a la SORTIE du tunnel. Une
/// resolution locale ferait fuir la requete DNS hors du tunnel et, pour une
/// recette qui vise une adresse de boucle locale, viserait la mauvaise
/// machine.
pub fn requete_connect(hote: &str, port: u16) -> anyhow::Result<Vec<u8>> {
    let nom = hote.as_bytes();
    if nom.is_empty() || nom.len() > 255 {
        anyhow::bail!(
            "nom d'hote de longueur impossible pour SOCKS5: {}",
            nom.len()
        );
    }
    let mut r = vec![VERSION, COMMANDE_CONNECT, 0x00, TYPE_NOM, nom.len() as u8];
    r.extend_from_slice(nom);
    r.extend_from_slice(&port.to_be_bytes());
    Ok(r)
}

/// Requete CONNECT vers une ADRESSE.
///
/// C'est la forme qu'emploie le passeur: un paquet IP porte une adresse, pas un
/// nom, et l'annoncer telle quelle evite au coeur de reresoudre ce qui l'est
/// deja. Contrairement a [`requete_connect`], rien ne peut echouer ici - une
/// adresse a toujours une longueur admissible.
pub fn requete_connect_ip(cible: SocketAddr) -> Vec<u8> {
    let mut r = vec![VERSION, COMMANDE_CONNECT, 0x00];
    match cible.ip() {
        std::net::IpAddr::V4(a) => {
            r.push(TYPE_IPV4);
            r.extend_from_slice(&a.octets());
        }
        std::net::IpAddr::V6(a) => {
            r.push(TYPE_IPV6);
            r.extend_from_slice(&a.octets());
        }
    }
    r.extend_from_slice(&cible.port().to_be_bytes());
    r
}

/// Interprete la reponse a un CONNECT.
///
/// Rend le code de reponse du mandataire. `None` si la reponse n'a pas la
/// forme attendue: la lire de travers ferait passer un refus pour un succes.
pub fn code_de_reponse(reponse: &[u8]) -> Option<u8> {
    if reponse.len() < 4 || reponse[0] != VERSION {
        return None;
    }
    Some(reponse[1])
}

/// Texte des codes de la RFC, pour que l'echec soit lisible.
pub fn explication(code: u8) -> &'static str {
    match code {
        0x00 => "succes",
        0x01 => "echec general du mandataire",
        0x02 => "connexion interdite par la politique",
        0x03 => "reseau injoignable",
        0x04 => "hote injoignable",
        0x05 => "connexion refusee",
        0x06 => "TTL expire",
        0x07 => "commande non supportee",
        0x08 => "type d'adresse non supporte",
        _ => "code inconnu",
    }
}

/// Ouvre une connexion vers `hote:port` a travers le mandataire SOCKS5.
pub async fn connecter(
    mandataire: &Mandataire,
    hote: &str,
    port: u16,
) -> anyhow::Result<TcpStream> {
    Ok(etablir(mandataire, requete_connect(hote, port)?).await?.0)
}

/// Ouvre une connexion vers une ADRESSE a travers le mandataire SOCKS5.
pub async fn connecter_vers(
    mandataire: &Mandataire,
    cible: SocketAddr,
) -> anyhow::Result<TcpStream> {
    Ok(etablir(mandataire, requete_connect_ip(cible)).await?.0)
}

/// La poignee de main commune aux deux formes de requete.
async fn etablir(
    mandataire: &Mandataire,
    requete: Vec<u8>,
) -> anyhow::Result<(TcpStream, Option<SocketAddr>)> {
    let travail = async {
        let mut flux = TcpStream::connect(mandataire.adresse).await?;
        flux.write_all(&salutation()).await?;
        let mut rep = [0u8; 2];
        flux.read_exact(&mut rep).await?;
        if !salutation_acceptee(&rep) {
            anyhow::bail!(
                "le mandataire SOCKS5 n'accepte pas l'authentification par mot de passe. S'il repond 0x00, c'est qu'il n'exige rien de personne: sa configuration n'a pas pris"
            );
        }
        flux.write_all(&sous_negociation(&mandataire.identifiants))
            .await?;
        let mut rep = [0u8; 2];
        // Un refus fait FERMER la connexion au serveur, RFC 1929: une lecture
        // qui s'interrompt ici est donc un refus, pas un incident reseau.
        flux.read_exact(&mut rep).await?;
        if !sous_negociation_acceptee(&rep) {
            anyhow::bail!("identifiants refuses par le mandataire SOCKS5");
        }

        flux.write_all(&requete).await?;
        let mut entete = [0u8; 4];
        flux.read_exact(&mut entete).await?;
        let code =
            code_de_reponse(&entete).ok_or_else(|| anyhow::anyhow!("reponse SOCKS5 malformee"))?;
        if code != SUCCES {
            anyhow::bail!("CONNECT refuse ({code}): {}", explication(code));
        }
        // L'adresse liee. CONNECT n'en fait rien; UDP ASSOCIATE en depend, car
        // c'est la que partiront les datagrammes.
        let liee = match entete[3] {
            TYPE_IPV4 => {
                let mut a = [0u8; 6];
                flux.read_exact(&mut a).await?;
                Some(SocketAddr::from((
                    [a[0], a[1], a[2], a[3]],
                    u16::from_be_bytes([a[4], a[5]]),
                )))
            }
            TYPE_IPV6 => {
                let mut a = [0u8; 18];
                flux.read_exact(&mut a).await?;
                let mut brut = [0u8; 16];
                brut.copy_from_slice(&a[..16]);
                Some(SocketAddr::from((
                    std::net::Ipv6Addr::from(brut),
                    u16::from_be_bytes([a[16], a[17]]),
                )))
            }
            TYPE_NOM => {
                let mut n = [0u8; 1];
                flux.read_exact(&mut n).await?;
                let mut poubelle = vec![0u8; n[0] as usize + 2];
                flux.read_exact(&mut poubelle).await?;
                // Un nom ne se resout pas ici: le kill switch est arme et rien
                // ne sortirait pour l'interroger.
                None
            }
            autre => anyhow::bail!("type d'adresse inattendu dans la reponse: {autre}"),
        };
        anyhow::Ok((flux, liee))
    };
    tokio::time::timeout(DELAI, travail)
        .await
        .map_err(|_| anyhow::anyhow!("le mandataire SOCKS5 n'a pas repondu en {DELAI:?}"))?
}

/// Demande une association UDP.
///
/// L'adresse annoncee est `0.0.0.0:0`: la RFC 1928 y attend l'adresse depuis
/// laquelle le client emettra, mais elle n'est pas connue avant d'avoir lie la
/// socket, et les mandataires en circulation - sing-box comme Xray - acceptent
/// l'adresse nulle, qui veut dire "n'importe laquelle".
pub fn requete_associer_udp() -> Vec<u8> {
    vec![
        VERSION,
        COMMANDE_ASSOCIER_UDP,
        0x00,
        TYPE_IPV4,
        0,
        0,
        0,
        0,
        0,
        0,
    ]
}

/// Ouvre une association UDP et rend le lien de controle avec l'adresse du
/// relais.
///
/// **Le lien de controle doit rester ouvert.** L'association vit exactement le
/// temps de cette connexion TCP: la fermer, ou la laisser tomber, fait
/// disparaitre le relais. C'est pourquoi le flux est RENDU plutot que consomme
/// ici.
pub async fn associer_udp(mandataire: &Mandataire) -> anyhow::Result<(TcpStream, SocketAddr)> {
    let (controle, liee) = etablir(mandataire, requete_associer_udp()).await?;
    let liee =
        liee.ok_or_else(|| anyhow::anyhow!("le mandataire annonce son relais par un nom"))?;
    Ok((controle, relais_effectif(liee, mandataire.adresse)))
}

/// L'adresse ou envoyer reellement les datagrammes.
///
/// Un mandataire qui ecoute sur toutes les interfaces annonce souvent son
/// relais en `0.0.0.0` ou `::`, qui n'est l'adresse de personne. La regle
/// d'interoperabilite, suivie par tous les clients serieux, est alors de garder
/// le PORT annonce et de reprendre l'adresse du mandataire lui-meme. Sans cela
/// les datagrammes partiraient vers une adresse non routable et l'association
/// paraitrait muette.
pub fn relais_effectif(liee: SocketAddr, mandataire: SocketAddr) -> SocketAddr {
    if liee.ip().is_unspecified() {
        SocketAddr::new(mandataire.ip(), liee.port())
    } else {
        liee
    }
}

/// L'en-tete qui prefixe chaque datagramme encapsule: RSV, FRAG, puis la
/// destination.
pub fn entete_datagramme(cible: SocketAddr) -> Vec<u8> {
    let mut t = vec![0x00, 0x00, 0x00];
    match cible.ip() {
        std::net::IpAddr::V4(v4) => {
            t.push(TYPE_IPV4);
            t.extend_from_slice(&v4.octets());
        }
        std::net::IpAddr::V6(v6) => {
            t.push(TYPE_IPV6);
            t.extend_from_slice(&v6.octets());
        }
    }
    t.extend_from_slice(&cible.port().to_be_bytes());
    t
}

/// Lit un datagramme encapsule et rend sa source et sa charge utile.
///
/// Un datagramme FRAGMENTE est refuse plutot que traite: le reassemblage
/// demande de garder un etat par association et une horloge, et aucun
/// mandataire en circulation ne fragmente. Le traiter comme entier donnerait
/// une charge utile tronquee que l'application prendrait pour la vraie.
pub fn lire_datagramme(trame: &[u8]) -> Result<(SocketAddr, &[u8]), String> {
    if trame.len() < 4 {
        return Err(format!("datagramme trop court: {} octets", trame.len()));
    }
    if trame[2] != 0 {
        return Err(format!("datagramme fragmente (FRAG={}), refuse", trame[2]));
    }
    let (source, apres) = match trame[3] {
        TYPE_IPV4 => {
            if trame.len() < 10 {
                return Err("datagramme IPv4 tronque".into());
            }
            (
                SocketAddr::from((
                    [trame[4], trame[5], trame[6], trame[7]],
                    u16::from_be_bytes([trame[8], trame[9]]),
                )),
                10,
            )
        }
        TYPE_IPV6 => {
            if trame.len() < 22 {
                return Err("datagramme IPv6 tronque".into());
            }
            let mut brut = [0u8; 16];
            brut.copy_from_slice(&trame[4..20]);
            (
                SocketAddr::from((
                    std::net::Ipv6Addr::from(brut),
                    u16::from_be_bytes([trame[20], trame[21]]),
                )),
                22,
            )
        }
        TYPE_NOM => {
            let n = *trame.get(4).ok_or("datagramme tronque")? as usize;
            if trame.len() < 5 + n + 2 {
                return Err("datagramme a nom tronque".into());
            }
            // La source annoncee par un nom n'est pas exploitable ici, et elle
            // ne sert qu'a un controle: on rend une adresse nulle plutot que
            // d'echouer, la charge utile restant valable.
            (
                SocketAddr::from((
                    [0, 0, 0, 0],
                    u16::from_be_bytes([trame[5 + n], trame[5 + n + 1]]),
                )),
                5 + n + 2,
            )
        }
        autre => {
            return Err(format!(
                "type d'adresse inconnu dans un datagramme: {autre}"
            ));
        }
    };
    Ok((source, &trame[apres..]))
}

/// Fait un GET HTTP a travers le mandataire et rend le corps.
pub async fn get_via_socks(
    mandataire: &Mandataire,
    hote: &str,
    port: u16,
    chemin: &str,
) -> anyhow::Result<String> {
    let mut flux = connecter(mandataire, hote, port).await?;
    let requete =
        format!("GET {chemin} HTTP/1.1\r\nHost: {hote}:{port}\r\nConnection: close\r\n\r\n");
    flux.write_all(requete.as_bytes()).await?;
    let mut reponse = Vec::new();
    tokio::time::timeout(DELAI, flux.read_to_end(&mut reponse))
        .await
        .map_err(|_| anyhow::anyhow!("pas de reponse HTTP a travers le mandataire"))??;
    let texte = String::from_utf8_lossy(&reponse).into_owned();
    match texte.find("\r\n\r\n") {
        Some(i) => Ok(texte[i + 4..].to_string()),
        None => anyhow::bail!("reponse sans separateur d'en-tetes"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id() -> Identifiants {
        Identifiants::nouveaux("bifrost", "MOT-DE-PASSE-DE-RECETTE").unwrap()
    }

    /// La salutation ne propose PLUS de passer sans identifiants.
    ///
    /// Mesure le 20 aout 2026 sur le banc: un processus local quelconque -
    /// ni le passeur ni le coeur - obtenait par `127.0.0.1:1080` une banniere
    /// qui n'est joignable que par la sortie du tunnel. C'est le mecanisme de
    /// FlClash #1934 (ouvert le 7 avril 2026, toujours ouvert), ou une
    /// application tierce lit ainsi l'IP de sortie du serveur.
    ///
    /// Ne proposer QUE 0x02 est deliberement plus strict que d'en proposer
    /// deux: si le coeur repondait 0x00, cela voudrait dire qu'il n'exige rien,
    /// donc que notre configuration n'a pas pris - un etat qui doit se voir et
    /// non se rattraper en silence.
    #[test]
    fn la_salutation_n_offre_que_l_authentification() {
        assert_eq!(salutation(), [0x05, 0x01, AVEC_MOT_DE_PASSE]);
        assert!(!salutation_acceptee(&[0x05, SANS_AUTHENTIFICATION]));
        assert!(salutation_acceptee(&[0x05, AVEC_MOT_DE_PASSE]));
    }

    /// RFC 1929, verifiee a la source le 20 aout 2026: la sous-negociation a sa
    /// PROPRE version, `X'01'`, et non celle de SOCKS. Confondre les deux est
    /// l'erreur classique, et elle produit un refus que rien n'explique.
    #[test]
    fn la_sous_negociation_suit_la_rfc_1929() {
        let m = sous_negociation(&id());
        assert_eq!(m[0], SOUS_NEGOCIATION, "la version doit etre 0x01");
        assert_eq!(m[1], 7);
        assert_eq!(&m[2..9], b"bifrost");
        assert_eq!(m[9], 23);
        assert_eq!(&m[10..], b"MOT-DE-PASSE-DE-RECETTE");
    }

    /// "If the server returns a 'failure' (STATUS value other than X'00')
    /// status, it MUST close the connection." Lire ce refus de travers ferait
    /// passer une connexion morte pour une connexion authentifiee.
    #[test]
    fn un_refus_d_authentification_ne_passe_pas_pour_un_succes() {
        assert!(sous_negociation_acceptee(&[0x01, 0x00]));
        assert!(!sous_negociation_acceptee(&[0x01, 0x01]));
        // La version de SOCKS a la place de celle de la sous-negociation: une
        // reponse qu'on ne comprend pas n'est pas une reponse favorable.
        assert!(!sous_negociation_acceptee(&[0x05, 0x00]));
        assert!(!sous_negociation_acceptee(&[0x01]));
    }

    /// Les deux champs tiennent sur un octet de longueur: ce qui n'y tient pas
    /// est refuse avant l'envoi, jamais tronque. Un mot de passe tronque
    /// s'authentifierait aupres de personne, et la panne accuserait le reseau.
    #[test]
    fn un_identifiant_impossible_est_refuse_avant_l_envoi() {
        assert!(Identifiants::nouveaux("", "x").is_err());
        assert!(Identifiants::nouveaux("u", "").is_err());
        assert!(Identifiants::nouveaux(&"u".repeat(256), "x").is_err());
        assert!(Identifiants::nouveaux("u", &"p".repeat(256)).is_err());
        // La borne exacte, des deux cotes: 255 passe, 256 non. Sans elle, un
        // `>=` mis pour un `>` ne ferait tomber aucune des lignes ci-dessus.
        assert!(Identifiants::nouveaux(&"u".repeat(255), &"p".repeat(255)).is_ok());
    }

    /// Le mot de passe ne doit pas se retrouver dans un journal.
    #[test]
    fn les_identifiants_ne_se_montrent_pas() {
        let rendu = format!("{:?}", id());
        assert!(!rendu.contains("MOT-DE-PASSE-DE-RECETTE"), "{rendu}");
    }

    #[test]
    fn une_salutation_refusee_se_voit() {
        assert!(salutation_acceptee(&[0x05, AVEC_MOT_DE_PASSE]));
        // 0xFF est le refus explicite de la RFC.
        assert!(!salutation_acceptee(&[0x05, 0xFF]));
        assert!(
            !salutation_acceptee(&[0x04, 0x00]),
            "mauvaise version acceptee"
        );
        assert!(!salutation_acceptee(&[0x05]), "reponse tronquee acceptee");
    }

    #[test]
    fn le_connect_envoie_le_nom_et_non_une_adresse_resolue() {
        // La propriete qui fait tout: le nom part tel quel, donc la resolution
        // se fait a la sortie du tunnel.
        let r = requete_connect("exemple.test", 8080).unwrap();
        assert_eq!(r[0], VERSION);
        assert_eq!(r[1], COMMANDE_CONNECT);
        assert_eq!(r[3], TYPE_NOM);
        assert_eq!(r[4] as usize, "exemple.test".len());
        assert_eq!(&r[5..5 + 12], b"exemple.test");
        assert_eq!(&r[r.len() - 2..], &8080u16.to_be_bytes());
    }

    #[test]
    fn une_adresse_litterale_passe_aussi_comme_un_nom() {
        // 127.0.0.1 vise alors la boucle locale DU SERVEUR, ce qui est
        // exactement ce que la recette veut atteindre.
        let r = requete_connect("127.0.0.1", 44344).unwrap();
        assert_eq!(r[3], TYPE_NOM);
        assert_eq!(&r[5..14], b"127.0.0.1");
    }

    #[test]
    fn un_nom_impossible_est_refuse_avant_l_envoi() {
        assert!(requete_connect("", 80).is_err());
        assert!(requete_connect(&"a".repeat(256), 80).is_err());
        assert!(requete_connect(&"a".repeat(255), 80).is_ok());
    }

    #[test]
    fn un_refus_ne_passe_pas_pour_un_succes() {
        assert_eq!(code_de_reponse(&[0x05, 0x00, 0x00, 0x01]), Some(SUCCES));
        assert_eq!(code_de_reponse(&[0x05, 0x05, 0x00, 0x01]), Some(0x05));
        // Reponse tronquee ou d'une autre version: aucune conclusion.
        assert_eq!(code_de_reponse(&[0x05, 0x00]), None);
        assert_eq!(code_de_reponse(&[0x04, 0x00, 0x00, 0x01]), None);
        assert_eq!(code_de_reponse(&[]), None);
    }

    #[test]
    fn chaque_code_de_la_rfc_a_son_explication() {
        for c in 0x00u8..=0x08 {
            assert_ne!(explication(c), "code inconnu", "code {c} sans explication");
        }
        assert_eq!(explication(0x42), "code inconnu");
    }

    #[test]
    fn une_adresse_v4_est_annoncee_comme_telle() {
        let r = requete_connect_ip("93.184.216.34:443".parse().unwrap());
        assert_eq!(
            r,
            vec![
                VERSION,
                COMMANDE_CONNECT,
                0x00,
                TYPE_IPV4,
                93,
                184,
                216,
                34,
                0x01,
                0xbb
            ]
        );
    }

    #[test]
    fn une_adresse_v6_est_annoncee_comme_telle() {
        let r = requete_connect_ip("[2001:db8::1]:80".parse().unwrap());
        assert_eq!(r[..4], [VERSION, COMMANDE_CONNECT, 0x00, TYPE_IPV6]);
        assert_eq!(
            r.len(),
            4 + 16 + 2,
            "seize octets d'adresse et deux de port"
        );
        assert_eq!(&r[r.len() - 2..], &80u16.to_be_bytes());
    }

    /// Le passeur ne connait qu'une adresse. L'ecrire sous forme de nom
    /// marcherait chez la plupart des coeurs, et serait un mensonge dans le
    /// protocole; la longueur du message suffit a distinguer les deux formes.
    #[test]
    fn une_adresse_n_est_pas_envoyee_comme_un_nom() {
        let cible: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let par_adresse = requete_connect_ip(cible);
        let par_nom = requete_connect(&cible.ip().to_string(), cible.port()).unwrap();
        assert_eq!(par_adresse[3], TYPE_IPV4);
        assert_eq!(par_nom[3], TYPE_NOM);
        assert_ne!(par_adresse, par_nom);
    }

    /// L'en-tete et sa lecture doivent etre exactement inverses: c'est le seul
    /// endroit ou une erreur d'un octet se traduit par un tunnel qui marche
    /// pour TCP et se tait pour UDP.
    #[test]
    fn un_datagramme_fait_l_aller_retour_en_v4() {
        let cible: SocketAddr = "203.0.113.9:5353".parse().unwrap();
        let mut trame = entete_datagramme(cible);
        trame.extend_from_slice(b"charge utile");
        let (source, charge) = lire_datagramme(&trame).expect("la trame doit se lire");
        assert_eq!(source, cible);
        assert_eq!(charge, b"charge utile");
    }

    #[test]
    fn un_datagramme_fait_l_aller_retour_en_v6() {
        let cible: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        let mut trame = entete_datagramme(cible);
        trame.extend_from_slice(b"quic");
        let (source, charge) = lire_datagramme(&trame).unwrap();
        assert_eq!(source, cible);
        assert_eq!(charge, b"quic");
    }

    /// Un datagramme fragmente doit etre refuse, pas traite comme entier: le
    /// prendre pour entier remonterait une charge utile tronquee que
    /// l'application croirait complete.
    #[test]
    fn un_datagramme_fragmente_est_refuse() {
        let mut trame = entete_datagramme("203.0.113.9:53".parse().unwrap());
        trame[2] = 1;
        trame.extend_from_slice(b"morceau");
        let e = lire_datagramme(&trame).expect_err("un fragment doit etre refuse");
        assert!(e.contains("fragmente"), "{e}");
    }

    #[test]
    fn un_datagramme_tronque_est_refuse_plutot_que_lu_de_travers() {
        let trame = entete_datagramme("203.0.113.9:53".parse().unwrap());
        for n in 0..trame.len() {
            assert!(
                lire_datagramme(&trame[..n]).is_err(),
                "une trame de {n} octets ne devrait pas se lire"
            );
        }
    }

    /// Le piege d'interoperabilite: un mandataire qui ecoute partout annonce
    /// son relais en 0.0.0.0, qui n'est l'adresse de personne. Envoyer la
    /// serait envoyer nulle part, et l'association paraitrait muette.
    #[test]
    fn un_relais_annonce_sans_adresse_prend_celle_du_mandataire() {
        let mandataire: SocketAddr = "127.0.0.1:1080".parse().unwrap();
        let annonce: SocketAddr = "0.0.0.0:34567".parse().unwrap();
        assert_eq!(
            relais_effectif(annonce, mandataire),
            "127.0.0.1:34567".parse::<SocketAddr>().unwrap()
        );
        // Une adresse reelle, elle, est gardee telle quelle.
        let vraie: SocketAddr = "203.0.113.9:34567".parse().unwrap();
        assert_eq!(relais_effectif(vraie, mandataire), vraie);
    }

    #[test]
    fn la_requete_d_association_est_bien_formee() {
        let r = requete_associer_udp();
        assert_eq!(r[0], VERSION);
        assert_eq!(r[1], COMMANDE_ASSOCIER_UDP);
        assert_eq!(r[2], 0x00, "l'octet reserve doit etre nul");
        assert_eq!(r[3], TYPE_IPV4);
        assert_eq!(&r[4..], &[0, 0, 0, 0, 0, 0], "adresse et port nuls");
    }

    /// Les octets de SOCKS5 sont ceux de la RFC 1928.
    ///
    /// `le_connect_envoie_le_nom_et_non_une_adresse_resolue` verifie
    /// `r[1] == COMMANDE_CONNECT` et `r[3] == TYPE_NOM` sur une requete que
    /// `requete_connect` vient d'ecrire DEPUIS ces memes constantes. La forme
    /// de la requete est donc eprouvee, jamais la valeur des octets.
    ///
    /// Mesure du 23 aout 2026 sur dev-windows: en decalant `COMMANDE_CONNECT`,
    /// `COMMANDE_ASSOCIER_UDP`, `TYPE_IPV4`, `TYPE_NOM` et `TYPE_IPV6`, les 524
    /// recettes du binaire de bibliotheque restaient vertes. Aucun mandataire
    /// SOCKS5 reel n'aurait alors repondu, et le passeur aurait echoue avec un
    /// refus que rien n'explique - le meme piege que la note de
    /// `SOUS_NEGOCIATION` decrit deja pour la version.
    ///
    /// Les cinq autres octets sont deja epingles ailleurs par des litteraux
    /// (`[0x05, 0xFF]`, `[0x05, 0x00, 0x00, 0x01]`); ils sont repris ici pour
    /// que la table de la RFC se lise d'un seul endroit.
    ///
    /// RFC 1928 section 4 pour CMD et ATYP, section 6 pour REP.
    #[test]
    fn les_octets_de_socks5_sont_ceux_de_la_rfc_1928() {
        assert_eq!(VERSION, 0x05);
        assert_eq!(SANS_AUTHENTIFICATION, 0x00);
        assert_eq!(AVEC_MOT_DE_PASSE, 0x02, "nom et mot de passe, RFC 1929");
        assert_eq!(SOUS_NEGOCIATION, 0x01, "version de la SOUS-negociation");
        assert_eq!(AUTHENTIFIE, 0x00);
        assert_eq!(COMMANDE_CONNECT, 0x01, "CMD CONNECT");
        assert_eq!(COMMANDE_ASSOCIER_UDP, 0x03, "CMD UDP ASSOCIATE");
        assert_eq!(TYPE_IPV4, 0x01, "ATYP IP V4");
        assert_eq!(TYPE_NOM, 0x03, "ATYP DOMAINNAME");
        assert_eq!(TYPE_IPV6, 0x04, "ATYP IP V6");
        assert_eq!(SUCCES, 0x00, "REP succeeded");

        // Les trois ATYP doivent rester distincts: `requete_connect` annonce un
        // nom et le passeur relit le type pour savoir combien d'octets suivent.
        // Deux valeurs egales feraient lire une adresse la ou il y a un nom.
        let mut atyp = [TYPE_IPV4, TYPE_NOM, TYPE_IPV6];
        atyp.sort_unstable();
        let avant = atyp.len();
        let mut v = atyp.to_vec();
        v.dedup();
        assert_eq!(v.len(), avant, "deux ATYP partagent une valeur: {atyp:?}");
    }
}
