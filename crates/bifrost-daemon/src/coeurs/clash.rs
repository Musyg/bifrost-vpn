//! Client minimal de l'API Clash, celle par laquelle sing-box se pilote.
//!
//! Volontairement ecrit a la main plutot qu'avec un client HTTP: la surface
//! utilisee tient en trois requetes vers 127.0.0.1, et un produit de securite
//! n'a pas a tirer un arbre de dependances entier pour ca.
//!
//! Le secret n'est pas optionnel dans notre usage, et la raison merite d'etre
//! dite. L'API Clash est une interface de controle: elle choisit par ou sort le
//! trafic. Exposee sans authentification sur la boucle locale, n'importe quel
//! programme du poste, y compris non privilegie, pourrait faire basculer la
//! sortie du VPN. sing-box permet de s'en passer; nous non.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Intervalle entre deux tentatives d'attente de disponibilite.
pub const PAS_DE_SONDAGE: Duration = Duration::from_millis(100);

/// Delai d'une requete isolee.
pub const DELAI_REQUETE: Duration = Duration::from_secs(2);

/// Construit une requete HTTP pour l'API.
///
/// `Connection: close` est deliberatif: le client lit jusqu'a la fin du flux
/// et n'a donc pas besoin de comprendre `Content-Length` ni le decoupage en
/// morceaux, deux endroits ou un analyseur ecrit a la main se trompe.
pub fn requete(methode: &str, chemin: &str, secret: &str, corps: Option<&str>) -> String {
    let mut r = format!(
        "{methode} {chemin} HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {secret}\r\nConnection: close\r\n"
    );
    match corps {
        Some(c) => {
            r.push_str("Content-Type: application/json\r\n");
            r.push_str(&format!("Content-Length: {}\r\n\r\n", c.len()));
            r.push_str(c);
        }
        None => r.push_str("\r\n"),
    }
    r
}

/// Separe le statut du corps dans une reponse HTTP.
pub fn depouiller(reponse: &str) -> Option<(u16, &str)> {
    let ligne = reponse.lines().next()?;
    let mut morceaux = ligne.split(' ');
    if !morceaux.next()?.starts_with("HTTP/") {
        return None;
    }
    let statut: u16 = morceaux.next()?.parse().ok()?;
    // Une reponse sans separateur d'en-tetes n'est pas du HTTP valide.
    let corps = &reponse[reponse.find("\r\n\r\n")? + 4..];
    Some((statut, corps))
}

/// Extrait la version annoncee par le coeur.
pub fn version_annoncee(corps: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(corps).ok()?;
    v.get("version")?.as_str().map(str::to_string)
}

/// Corps de la requete qui bascule un selecteur.
pub fn corps_de_selection(sortie: &str) -> String {
    serde_json::json!({ "name": sortie }).to_string()
}

/// Chemin de la ressource d'un selecteur, avec son nom encode.
///
/// L'encodage n'est pas cosmetique: un nom de selecteur contenant une barre
/// oblique ou un espace fabriquerait une autre requete que celle voulue.
pub fn chemin_du_selecteur(selecteur: &str) -> String {
    format!("/proxies/{}", encoder_segment(selecteur))
}

fn encoder_segment(s: &str) -> String {
    let mut sortie = String::with_capacity(s.len());
    for o in s.bytes() {
        match o {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                sortie.push(o as char)
            }
            _ => sortie.push_str(&format!("%{o:02X}")),
        }
    }
    sortie
}

/// Envoie une requete et rend le statut et le corps.
pub async fn envoyer(
    adresse: SocketAddr,
    methode: &str,
    chemin: &str,
    secret: &str,
    corps: Option<&str>,
) -> anyhow::Result<(u16, String)> {
    envoyer_avec(adresse, methode, chemin, secret, corps, DELAI_REQUETE).await
}

/// La meme, avec l'echeance en parametre.
///
/// Une requete qui fait TRAVAILLER le coeur - la sonde de vitalite, qui lui
/// fait composer un aller-retour - dure ce qu'on lui a confie comme budget, et
/// non le delai d'une lecture d'etat. Garder [`DELAI_REQUETE`] la couperait
/// avant que le coeur ait fini, et son verdict se lirait comme une panne de
/// l'API.
pub async fn envoyer_avec(
    adresse: SocketAddr,
    methode: &str,
    chemin: &str,
    secret: &str,
    corps: Option<&str>,
    delai: Duration,
) -> anyhow::Result<(u16, String)> {
    let brut = requete(methode, chemin, secret, corps);
    let travail = async {
        let mut flux = TcpStream::connect(adresse).await?;
        flux.write_all(brut.as_bytes()).await?;
        let mut reponse = Vec::new();
        flux.read_to_end(&mut reponse).await?;
        anyhow::Ok(String::from_utf8_lossy(&reponse).into_owned())
    };
    let texte = tokio::time::timeout(delai, travail)
        .await
        .map_err(|_| anyhow::anyhow!("l'API Clash n'a pas repondu en {delai:?}"))??;
    let (statut, corps) =
        depouiller(&texte).ok_or_else(|| anyhow::anyhow!("reponse non HTTP de l'API Clash"))?;
    Ok((statut, corps.to_string()))
}

/// L'API repond-elle, et avec la bonne autorisation.
///
/// Un 401 est traite comme un echec et non comme "pas encore pret": le coeur
/// est bien la, c'est le secret qui ne correspond pas, et attendre n'y changera
/// rien.
pub async fn interroger_version(adresse: SocketAddr, secret: &str) -> anyhow::Result<String> {
    let (statut, corps) = envoyer(adresse, "GET", "/version", secret, None).await?;
    match statut {
        200 => version_annoncee(&corps)
            .ok_or_else(|| anyhow::anyhow!("l'API Clash ne declare pas de version")),
        401 | 403 => Err(anyhow::anyhow!(
            "l'API Clash refuse le secret (statut {statut}): le coeur tourne mais n'est pas pilotable"
        )),
        autre => Err(anyhow::anyhow!("statut inattendu de l'API Clash: {autre}")),
    }
}

/// Chemin de la sonde de vitalite d'une sortie.
///
/// `GET /proxies/<tag>/delay?timeout=<ms>&url=<cible>` fait COMPOSER le coeur:
/// il dialogue avec la cible A TRAVERS la sortie nommee, et rend le temps
/// d'aller-retour. C'est donc une vraie sonde du transport, et non un sondage
/// de l'API.
///
/// Deux raisons de passer par la plutot que d'emettre nous-memes. La sortie du
/// coeur est EXEMPTEE par le kill switch, par identite: une sonde emise par le
/// daemon, elle, se heurterait au `udp dport 53 drop` pose avant l'acceptation
/// du tunnel des qu'un resolveur embarque est declare. Et c'est le coeur qui
/// sait par ou passe la sortie courante, ce que le daemon ne peut que deviner.
///
/// La cible et le nom sont encodes: un nom de sortie contenant une esperluette
/// ou un espace fabriquerait une autre requete que celle voulue.
pub fn chemin_du_delai(sortie: &str, cible: &str, budget: Duration) -> String {
    format!(
        "/proxies/{}/delay?timeout={}&url={}",
        encoder_segment(sortie),
        budget.as_millis(),
        encoder_segment(cible)
    )
}

/// Ce que la sonde a donne, lu du statut HTTP.
///
/// Les trois issues ne sont pas deduites de la documentation, qui n'en dit
/// rien: elles sont MESUREES contre le binaire epingle, sing-box 1.13.18, le
/// 20 aout 2026.
///
/// - **200** avec `{"delay":N}`: l'aller-retour a traverse la sortie.
/// - **503** `{"message":"An error occurred in the delay test"}`: obtenu en
///   pointant la sortie sur un mandataire SOCKS inexistant. Le transport est
///   mort, et c'est bien le RESEAU qui a repondu non.
/// - **404** `Resource not found` pour une sortie inconnue, **401**
///   `Unauthorized` pour un mauvais secret. Les deux sont des pannes CHEZ NOUS:
///   elles ne disent rien du pair, et les lire comme un echec ferait demonter
///   un tunnel sain sur une faute de configuration.
///
/// Tout autre statut rejoint le dernier groupe: une reponse qu'on ne comprend
/// pas n'est pas une reponse negative.
pub fn issue_du_delai(statut: u16) -> bifrost_evasion::observation::Sonde {
    use bifrost_evasion::observation::Sonde;
    match statut {
        200 => Sonde::Aboutie,
        503 => Sonde::Echouee,
        _ => Sonde::Impossible,
    }
}

/// Lit la sortie actuellement choisie par un selecteur.
///
/// Permet de VERIFIER une bascule au lieu de se fier au code de retour. Un
/// 204 dit que le coeur a accepte la requete, pas qu'il a change de sortie.
pub fn selection_courante(corps: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(corps).ok()?;
    v.get("now")?.as_str().map(str::to_string)
}

/// Interroge un selecteur et rend la sortie active.
pub async fn lire_selection(
    adresse: SocketAddr,
    secret: &str,
    selecteur: &str,
) -> anyhow::Result<String> {
    let (statut, corps) = envoyer(
        adresse,
        "GET",
        &chemin_du_selecteur(selecteur),
        secret,
        None,
    )
    .await?;
    if statut != 200 {
        anyhow::bail!("lecture du selecteur {selecteur}: statut {statut}");
    }
    selection_courante(&corps)
        .ok_or_else(|| anyhow::anyhow!("le selecteur {selecteur} ne declare pas de sortie active"))
}

/// Bascule un selecteur vers une sortie.
pub async fn choisir(
    adresse: SocketAddr,
    secret: &str,
    selecteur: &str,
    sortie: &str,
) -> anyhow::Result<()> {
    let corps = corps_de_selection(sortie);
    let (statut, reponse) = envoyer(
        adresse,
        "PUT",
        &chemin_du_selecteur(selecteur),
        secret,
        Some(&corps),
    )
    .await?;
    // L'API rend 204 en cas de succes. Tout le reste est un echec, y compris
    // les 2xx: un 200 signalerait que le coeur a compris autre chose.
    if statut == 204 {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "bascule vers {sortie} refusee (statut {statut}): {}",
            reponse.trim()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn la_requete_porte_toujours_le_secret() {
        // Sans en-tete d'autorisation, n'importe quel programme du poste
        // pourrait faire basculer la sortie du VPN.
        let r = requete("GET", "/version", "s3cr3t", None);
        assert!(r.contains("Authorization: Bearer s3cr3t\r\n"));
        let r = requete("PUT", "/proxies/select", "s3cr3t", Some("{}"));
        assert!(r.contains("Authorization: Bearer s3cr3t\r\n"));
    }

    #[test]
    fn une_requete_avec_corps_annonce_sa_longueur() {
        let corps = corps_de_selection("reality");
        let r = requete("PUT", "/proxies/select", "x", Some(&corps));
        assert!(r.contains(&format!("Content-Length: {}\r\n", corps.len())));
        assert!(r.ends_with(&corps));
        assert!(r.contains("\r\n\r\n"), "en-tetes et corps non separes");
    }

    #[test]
    fn une_requete_sans_corps_n_annonce_pas_de_longueur() {
        let r = requete("GET", "/version", "x", None);
        assert!(!r.contains("Content-Length"));
        assert!(r.ends_with("\r\n\r\n"));
    }

    #[test]
    fn le_depouillement_separe_le_statut_du_corps() {
        let (s, c) = depouiller("HTTP/1.1 200 OK\r\nX: y\r\n\r\n{\"version\":\"1.13\"}").unwrap();
        assert_eq!(s, 200);
        assert_eq!(c, "{\"version\":\"1.13\"}");
    }

    #[test]
    fn une_reponse_vide_ou_tronquee_ne_depouille_pas() {
        // Un coeur tue en pleine reponse produit exactement ca. La lire comme
        // un succes ferait croire le superviseur pret.
        assert!(depouiller("").is_none());
        assert!(depouiller("HTTP/1.1 200 OK\r\nX: y\r\n").is_none());
        assert!(depouiller("bonjour").is_none());
        assert!(depouiller("HTTP/1.1 abc\r\n\r\n").is_none());
    }

    #[test]
    fn un_corps_de_204_est_vide_et_reste_valide() {
        let (s, c) = depouiller("HTTP/1.1 204 No Content\r\n\r\n").unwrap();
        assert_eq!(s, 204);
        assert!(c.is_empty());
    }

    #[test]
    fn la_version_se_lit_dans_le_json() {
        assert_eq!(
            version_annoncee("{\"version\":\"1.13.0\"}").as_deref(),
            Some("1.13.0")
        );
    }

    #[test]
    fn un_json_sans_version_ou_illisible_ne_rend_rien() {
        assert!(version_annoncee("{}").is_none());
        assert!(version_annoncee("pas du json").is_none());
        // Une version numerique et non textuelle: on ne la devine pas.
        assert!(version_annoncee("{\"version\":113}").is_none());
    }

    #[test]
    fn un_nom_de_selecteur_hostile_ne_fabrique_pas_une_autre_requete() {
        // Sans encodage, ce nom viserait /proxies/../version.
        let c = chemin_du_selecteur("../version");
        assert_eq!(c, "/proxies/..%2Fversion");
        assert!(!c.contains("/../"));

        let c = chemin_du_selecteur("mon selecteur");
        assert_eq!(c, "/proxies/mon%20selecteur");
        // Un saut de ligne injecterait des en-tetes entieres.
        let c = chemin_du_selecteur("a\r\nX-Evil: 1");
        assert!(!c.contains('\r') && !c.contains('\n'));
    }

    #[test]
    fn un_nom_ordinaire_traverse_sans_etre_deforme() {
        assert_eq!(chemin_du_selecteur("select"), "/proxies/select");
        assert_eq!(chemin_du_selecteur("auto-2.0_b~c"), "/proxies/auto-2.0_b~c");
    }

    #[test]
    fn la_selection_courante_se_lit_dans_le_champ_now() {
        assert_eq!(
            selection_courante("{\"name\":\"select\",\"now\":\"sortie-b\"}").as_deref(),
            Some("sortie-b")
        );
    }

    #[test]
    fn un_selecteur_sans_champ_now_ne_rend_rien() {
        // Lire l'absence comme une chaine vide ferait passer une bascule
        // ratee pour une bascule vers rien.
        assert!(selection_courante("{\"name\":\"select\"}").is_none());
        assert!(selection_courante("pas du json").is_none());
        assert!(selection_courante("{\"now\":null}").is_none());
    }

    #[test]
    fn le_corps_de_selection_est_du_json_valide() {
        let c = corps_de_selection("reality \"guillemets\"");
        let v: serde_json::Value = serde_json::from_str(&c).unwrap();
        assert_eq!(v["name"], "reality \"guillemets\"");
    }
    /// Les trois issues ne viennent pas d'une documentation - elle n'en dit
    /// rien - mais d'une mesure contre le binaire epingle, sing-box 1.13.18, le
    /// 20 aout 2026. Le 503 a ete obtenu en pointant la sortie sur un
    /// mandataire SOCKS inexistant, ce qui est un transport mort sans avoir a
    /// couper quoi que ce soit.
    #[test]
    fn les_trois_issues_de_la_sonde_viennent_du_statut_mesure() {
        use bifrost_evasion::observation::Sonde;
        assert_eq!(issue_du_delai(200), Sonde::Aboutie);
        assert_eq!(issue_du_delai(503), Sonde::Echouee);
        // Sortie inconnue et secret refuse: des pannes CHEZ NOUS. Les lire
        // comme un pair muet demonterait un tunnel sain sur une faute de
        // configuration.
        assert_eq!(issue_du_delai(404), Sonde::Impossible);
        assert_eq!(issue_du_delai(401), Sonde::Impossible);
        // Et tout ce qu'on n'a pas mesure rejoint le meme groupe: une reponse
        // qu'on ne comprend pas n'est pas une reponse negative.
        for statut in [204u16, 400, 429, 500, 502, 504] {
            assert_eq!(
                issue_du_delai(statut),
                Sonde::Impossible,
                "statut {statut} lu comme une reponse du reseau"
            );
        }
    }

    #[test]
    fn le_chemin_de_la_sonde_porte_le_budget_et_la_cible_encodee() {
        let c = chemin_du_delai("select", "https://exemple.test/204", Duration::from_secs(5));
        assert!(c.starts_with("/proxies/select/delay?"), "{c}");
        assert!(c.contains("timeout=5000"), "{c}");
        // Sans encodage, les deux barres obliques et le deux-points feraient
        // une autre requete que celle voulue.
        assert!(c.contains("url=https%3A%2F%2Fexemple.test%2F204"), "{c}");
    }

    /// Un nom de selecteur hostile ne doit pas pouvoir sortir de sa ressource
    /// ni ajouter un parametre a la requete.
    #[test]
    fn un_nom_de_selecteur_hostile_reste_dans_sa_ressource() {
        let c = chemin_du_delai("../version?x=", "https://e.test/", Duration::from_secs(1));
        assert!(c.starts_with("/proxies/..%2Fversion%3Fx%3D/delay?"), "{c}");
    }
}
