//! Recette de bout en bout: le trafic passe-t-il VRAIMENT par le coeur.
//!
//! `--coeur-selftest` prouve qu'un selecteur bascule; il ne prouve pas que la
//! bascule change le chemin des paquets, ses deux sorties etant des `direct`
//! qui ne different que par leur etiquette. C'est cette recette-ci qui repond,
//! et elle repose entierement sur une banniere placee sur la BOUCLE LOCALE du
//! serveur de sortie.
//!
//! Le choix n'est pas anodin. Une banniere sur une adresse publique serait
//! joignable des deux facons et ne distinguerait rien. Sur `127.0.0.1` du
//! serveur, elle n'est atteignable que par un CONNECT resolu a la SORTIE du
//! tunnel: si elle repond, le trafic a traverse, et il n'y a pas d'autre
//! explication.
//!
//! Trois temoins negatifs encadrent l'affirmation, parce qu'une reponse seule
//! ne suffirait pas: la meme adresse doit etre injoignable en direct depuis le
//! client, elle doit redevenir injoignable des que le selecteur bascule vers la
//! sortie en clair, et elle doit redevenir joignable au retour.
//!
//! Le profil peut declarer PLUSIEURS transports, chacun eprouve a son tour.
//! C'est ce qui permet de comparer REALITY, qui vit dans TCP, et Hysteria2,
//! qui vit dans QUIC: un reseau peut tres bien porter l'un et pas l'autre, et
//! c'est precisement la raison d'etre du choix de technique.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use bifrost_evasion::Coeur;
use serde::Deserialize;

use super::{alea, configuration, lancement, port, socks, superviseur};
use crate::sondes;

/// Ou trouver la banniere, et ce qu'elle doit dire.
#[derive(Debug, Clone, Deserialize)]
pub struct Banniere {
    pub hote: String,
    pub port: u16,
    pub chemin: String,
    pub attendu: String,
}

/// Un transport a eprouver, tel que le profil le decrit.
///
/// Distinct de `configuration::Sortie` a dessein: celui-ci est une forme de
/// FICHIER, que l'on deserialise depuis du JSON venu du dehors, alors que
/// l'autre est la forme interne qui engendre la configuration du coeur. Les
/// confondre ferait dependre le format de fichier de tout remaniement interne.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum SortieDuProfil {
    VlessReality {
        tag: String,
        serveur: String,
        port: u16,
        uuid: String,
        cle_publique: String,
        short_id: String,
        nom_de_serveur: String,
    },
    /// Derriere un CDN. Seul transport HTTP qui traverse un edge Cloudflare,
    /// mesure du 21 aout 2026.
    VlessWebsocket {
        tag: String,
        serveur: String,
        port: u16,
        uuid: String,
        nom_de_serveur: String,
        /// En-tete `Host` de la requete d'upgrade. Le CDN route dessus.
        hote: String,
        chemin: String,
    },
    /// Derriere un front auto-heberge. Ne traverse pas un CDN.
    VlessHttpUpgrade {
        tag: String,
        serveur: String,
        port: u16,
        uuid: String,
        nom_de_serveur: String,
        hote: String,
        chemin: String,
    },
    Hysteria2 {
        tag: String,
        serveur: String,
        port: u16,
        mot_de_passe: String,
        #[serde(default)]
        obfs: Option<String>,
        nom_de_serveur: String,
        /// Certificat du serveur, en PEM ligne par ligne. Obligatoire: la
        /// recette n'a aucun moyen de ne pas verifier, et c'est voulu.
        certificat: Vec<String>,
    },
}

impl SortieDuProfil {
    pub fn tag(&self) -> &str {
        match self {
            SortieDuProfil::VlessReality { tag, .. }
            | SortieDuProfil::VlessWebsocket { tag, .. }
            | SortieDuProfil::VlessHttpUpgrade { tag, .. }
            | SortieDuProfil::Hysteria2 { tag, .. } => tag,
        }
    }

    fn en_sortie(&self) -> configuration::Sortie {
        match self.clone() {
            SortieDuProfil::VlessReality {
                tag,
                serveur,
                port,
                uuid,
                cle_publique,
                short_id,
                nom_de_serveur,
            } => configuration::Sortie::VlessReality(Box::new(configuration::Reality {
                tag,
                serveur,
                port,
                uuid,
                cle_publique,
                short_id,
                nom_de_serveur,
            })),
            SortieDuProfil::VlessWebsocket {
                tag,
                serveur,
                port,
                uuid,
                nom_de_serveur,
                hote,
                chemin,
            } => configuration::Sortie::VlessWebsocket(Box::new(configuration::SurHttp {
                tag,
                serveur,
                port,
                uuid,
                nom_de_serveur,
                hote,
                chemin,
            })),
            SortieDuProfil::VlessHttpUpgrade {
                tag,
                serveur,
                port,
                uuid,
                nom_de_serveur,
                hote,
                chemin,
            } => configuration::Sortie::VlessHttpUpgrade(Box::new(configuration::SurHttp {
                tag,
                serveur,
                port,
                uuid,
                nom_de_serveur,
                hote,
                chemin,
            })),
            SortieDuProfil::Hysteria2 {
                tag,
                serveur,
                port,
                mot_de_passe,
                obfs,
                nom_de_serveur,
                certificat,
            } => configuration::Sortie::Hysteria2(Box::new(configuration::Hysteria2 {
                tag,
                serveur,
                port,
                mot_de_passe,
                obfs,
                nom_de_serveur,
                confiance: configuration::Confiance::Epingle(certificat),
            })),
        }
    }
}

/// Profil de la recette. Contient des secrets: l'UUID VLESS comme le mot de
/// passe Hysteria2 authentifient leur porteur.
#[derive(Debug, Clone, Deserialize)]
pub struct Profil {
    pub sorties: Vec<SortieDuProfil>,
    pub banniere: Banniere,
}

const TAG_CLAIR: &str = "en-clair";
const SELECTEUR: &str = "select";

/// Issue d'une etape.
///
/// `Saute` existe pour une raison precise: certains temoins ne prouvent quelque
/// chose QUE si l'etape qu'ils encadrent a reussi. Les annoncer `PASSED` quand
/// ils echouent pour la meme cause que l'etape precedente est un mensonge
/// confortable, et c'est exactement le defaut que cette recette a eu.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Etat {
    Reussi,
    Echoue,
    Saute,
}

impl Etat {
    fn de(ok: bool) -> Self {
        if ok { Etat::Reussi } else { Etat::Echoue }
    }
}

/// Ce qu'une etape ajoute au total des echecs.
///
/// Pure, et separee de `dire` qui imprime, pour une raison mesuree le
/// 22/08/2026. La recette qui verifiait ce calcul appelait `dire`, donc elle
/// IMPRIMAIT `SKIPPED essai: `. Or `recettes-strict.sh` compte les abstentions
/// en lignes contenant `SKIPPED`: il comptait donc cette recette-la, qui ne
/// s'abstient pas et n'a jamais rien saute, parmi les mesures qui n'ont pas eu
/// lieu. Un test qui faussait le compte des tests, et dans le sens qui
/// SOUS-estime ce qui a ete verifie.
fn poids(etat: Etat) -> usize {
    usize::from(etat == Etat::Echoue)
}

fn dire(etape: &str, etat: Etat, detail: &str) -> usize {
    let mot = match etat {
        Etat::Reussi => "PASSED",
        Etat::Echoue => "FAILED",
        Etat::Saute => "SKIPPED",
    };
    println!("{mot:<7} {etape}: {detail}");
    poids(etat)
}

/// Raison invariable pour laquelle les temoins avals sont sautes.
const SANS_TUNNEL: &str =
    "aucun transport n'a porte de trafic, ce temoin ne distinguerait plus rien d'un coeur casse";

/// La banniere est-elle joignable EN DIRECT depuis cette machine.
///
/// Doit toujours repondre non. Si elle repond oui, tout le reste de la recette
/// ne prouve plus rien: la banniere serait accessible sans tunnel.
async fn joignable_en_direct(b: &Banniere) -> bool {
    let cible = format!("{}:{}", b.hote, b.port);
    matches!(
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            tokio::net::TcpStream::connect(&cible)
        )
        .await,
        Ok(Ok(_))
    )
}

/// Lit la banniere a travers le mandataire local du coeur.
async fn lire_banniere(coeur: &socks::Mandataire, b: &Banniere) -> anyhow::Result<String> {
    socks::get_via_socks(coeur, &b.hote, b.port, &b.chemin).await
}

/// Affiche ce que le coeur a dit, JUSTE APRES l'etape qui a echoue.
///
/// Le meme journal lu a la fin de la recette montrerait la derniere erreur et
/// non la bonne: l'etape "en clair" echoue exprES, donc elle masque
/// systematiquement la panne qu'on cherche. C'est arrive, et c'est ce qui a
/// impose d'aller relire les journaux a la main sur la machine.
async fn expliquer(en_cours: &superviseur::CoeurEnCours) {
    match en_cours.diagnostic().await {
        d if d.is_empty() => println!("        (le coeur n'a rien ecrit sur sa sortie d'erreur)"),
        d => println!("        {}", abreger(&d)),
    }
}

/// Le chemin est-il trop etroit pour ce transport, et si oui pourquoi.
///
/// Ne concerne que les transports batis sur QUIC. Rend une raison SEULEMENT
/// quand la sonde a conclu: un doute laisse le transport s'eprouver, quitte a
/// echouer, parce que sauter sur un doute reviendrait a masquer des pannes
/// derriere une excuse toute prete.
///
/// Sans cette mesure, la recette expire au bout de dix secondes sans rien
/// dire, exactement comme si le serveur etait mort ou le mot de passe faux.
/// C'est ce qui a coute une journee d'instrumentation le 16 aout 2026.
async fn chemin_trop_etroit(t: &SortieDuProfil) -> Option<String> {
    let SortieDuProfil::Hysteria2 {
        serveur,
        port,
        obfs,
        ..
    } = t
    else {
        return None;
    };
    let cible = tokio::net::lookup_host((serveur.as_str(), *port))
        .await
        .ok()?
        .next()?;
    let obfusque = obfs.is_some();
    if !sondes::sonder_chemin_quic(cible, obfusque).vu_faux() {
        return None;
    }
    Some(format!(
        "le lien local refuse un paquet IP de {} octets sans le fragmenter, taille a laquelle \
         quic-go emet ({} de paquet QUIC{}, {} d'en-tetes IP et UDP); ni sing-box ni hysteria \
         n'exposent de reglage pour la reduire",
        sondes::paquet_ip_quic(obfusque),
        sondes::PAQUET_QUIC,
        if obfusque {
            format!(" plus {} de sel Salamander", sondes::SEL_SALAMANDER)
        } else {
            String::new()
        },
        sondes::ENTETES_IP_UDP,
    ))
}

pub async fn run(
    racine: PathBuf,
    profil: &Path,
    identite: &super::identite::IdentiteCoeur,
) -> anyhow::Result<()> {
    let brut = std::fs::read_to_string(profil)
        .map_err(|e| anyhow::anyhow!("lecture du profil {}: {e}", profil.display()))?;
    let profil: Profil = serde_json::from_str(&brut)?;
    if profil.sorties.is_empty() {
        anyhow::bail!("le profil ne declare aucun transport a eprouver");
    }
    if let Some(t) = profil.sorties.iter().find(|s| s.tag() == TAG_CLAIR) {
        anyhow::bail!(
            "un transport porte l'etiquette reservee {:?}: le temoin en clair ne distinguerait plus rien",
            t.tag()
        );
    }

    let emplacements = lancement::Emplacements {
        binaires: racine.clone(),
        configurations: racine.join("configurations"),
    };
    // Tenus jusqu'au lancement, et pas seulement tires: voir [`super::port`]
    // pour ce que cela ferme.
    let reserve_api = port::reserver()?;
    let reserve_socks = port::reserver()?;
    let api = reserve_api.port();
    let socks_port = reserve_socks.port();
    // Une seule valeur pour ce que la configuration DECLARE et ce que la
    // recette PRESENTE. Deux valeurs distinctes se seraient contentees de
    // prouver que le banc sait se refuser lui-meme l'entree.
    let identifiants = socks::Identifiants::nouveaux("bifrost", &alea::secret()?)?;
    let parametres = configuration::Parametres {
        socks: socks_port,
        api,
        secret: alea::secret()?,
        identifiants: identifiants.clone(),
        selecteur: SELECTEUR.into(),
        sorties: vec![],
        // Ce banc lance le coeur SANS tunnel: rien ne l'enfermerait, donc rien
        // n'a besoin de l'en faire sortir.
        lier_a: None,
    };

    let mut sorties: Vec<configuration::Sortie> = profil
        .sorties
        .iter()
        .map(SortieDuProfil::en_sortie)
        .collect();
    sorties.push(configuration::Sortie::Directe {
        tag: TAG_CLAIR.into(),
    });

    // Le compte declare au daemon vaut aussi ici. Un coeur eprouve sous le
    // compte de root et exempte sous un autre en exploitation ne serait pas la
    // meme chose eprouvee.
    let mut prepare = lancement::preparer(&emplacements, Coeur::SingBox, api);
    identite.appliquer(&mut prepare);
    if !lancement::binaire_present(&prepare) {
        println!("SKIPPED binaire: {} absent", prepare.programme.display());
        std::process::exit(3);
    }
    configuration::ecrire(
        &prepare.configuration,
        &configuration::sing_box_avec(&parametres, &sorties),
    )?;

    let mut echecs = 0usize;
    let socks_local =
        socks::Mandataire::nouveau(SocketAddr::from(([127, 0, 0, 1], socks_port)), identifiants);

    // Le temoin qui conditionne tous les autres, mesure AVANT de lancer quoi
    // que ce soit: la banniere doit etre hors d'atteinte sans tunnel. S'il
    // tombe, la recette entiere est vide de sens et il n'y a rien a lancer.
    let cible = format!("{}:{}", profil.banniere.hote, profil.banniere.port);
    if joignable_en_direct(&profil.banniere).await {
        dire(
            "temoin: banniere injoignable en direct",
            Etat::Echoue,
            &format!("{cible} repond sans tunnel: la recette ne prouverait rien"),
        );
        anyhow::bail!("premisse fausse: la banniere est joignable en direct");
    }
    dire(
        "temoin: banniere injoignable en direct",
        Etat::Reussi,
        &format!("{cible} depuis cette machine"),
    );

    // Rendus a l'instant ou l'enfant va les prendre, et pas avant.
    reserve_api.liberer();
    reserve_socks.liberer();
    let en_cours = superviseur::demarrer(Coeur::SingBox, &prepare, &parametres.secret).await?;
    dire(
        "demarrage",
        Etat::Reussi,
        &format!("sing-box pid {}", en_cours.pid().unwrap_or(0)),
    );

    // 1. Chaque transport a son tour: la banniere doit repondre par chacun.
    //    Un transport en echec n'interrompt pas les autres: savoir que QUIC
    //    passe la ou TCP ne passe pas est justement l'information utile.
    let mut premier_qui_marche: Option<&str> = None;
    for transport in &profil.sorties {
        let tag = transport.tag();
        if let Some(raison) = chemin_trop_etroit(transport).await {
            dire(&format!("trafic par {tag}"), Etat::Saute, &raison);
            continue;
        }
        en_cours.choisir(SELECTEUR, tag).await?;
        let selection = en_cours.selection(SELECTEUR).await?;
        if selection != tag {
            echecs += dire(
                &format!("selection de {tag}"),
                Etat::Echoue,
                &format!("le selecteur annonce {selection}"),
            );
            continue;
        }
        match lire_banniere(&socks_local, &profil.banniere).await {
            Ok(corps) if corps.trim() == profil.banniere.attendu => {
                dire(&format!("trafic par {tag}"), Etat::Reussi, corps.trim());
                premier_qui_marche.get_or_insert(tag);
            }
            Ok(corps) => {
                echecs += dire(
                    &format!("trafic par {tag}"),
                    Etat::Echoue,
                    &format!("banniere inattendue: {:?}", corps.trim()),
                );
                expliquer(&en_cours).await;
            }
            Err(e) => {
                echecs += dire(
                    &format!("trafic par {tag}"),
                    Etat::Echoue,
                    &abreger(&format!("{e}")),
                );
                expliquer(&en_cours).await;
            }
        }
    }

    // 2. Bascule vers la sortie en clair: la MEME requete doit desormais
    //    echouer. C'est ce qui distingue un selecteur qui route d'un
    //    selecteur qui se contente d'annoncer un etat.
    en_cours.choisir(SELECTEUR, TAG_CLAIR).await?;
    let apres = en_cours.selection(SELECTEUR).await?;
    echecs += dire(
        "bascule vers la sortie en clair",
        Etat::de(apres == TAG_CLAIR),
        &apres,
    );

    const TEMOIN_CLAIR: &str = "temoin: en clair, la banniere est hors d'atteinte";
    match premier_qui_marche {
        None => {
            dire(TEMOIN_CLAIR, Etat::Saute, SANS_TUNNEL);
        }
        Some(_) => match lire_banniere(&socks_local, &profil.banniere).await {
            Err(e) => {
                dire(TEMOIN_CLAIR, Etat::Reussi, &abreger(&format!("{e}")));
            }
            Ok(corps) => {
                echecs += dire(
                    TEMOIN_CLAIR,
                    Etat::Echoue,
                    &format!(
                        "elle a repondu {:?}: le selecteur ne route rien",
                        corps.trim()
                    ),
                );
            }
        },
    }

    // 3. Retour au tunnel: elle doit redevenir joignable. Sans ce troisieme
    //    temps, un coeur qui serait simplement casse apres la bascule
    //    passerait l'etape 2 aussi bien qu'un coeur qui route correctement.
    match premier_qui_marche {
        None => {
            dire("retour au tunnel", Etat::Saute, SANS_TUNNEL);
        }
        Some(tag) => {
            en_cours.choisir(SELECTEUR, tag).await?;
            match lire_banniere(&socks_local, &profil.banniere).await {
                Ok(corps) if corps.trim() == profil.banniere.attendu => {
                    dire(&format!("retour par {tag}"), Etat::Reussi, corps.trim());
                }
                Ok(corps) => {
                    echecs += dire(
                        &format!("retour par {tag}"),
                        Etat::Echoue,
                        &format!("{:?}", corps.trim()),
                    );
                    expliquer(&en_cours).await;
                }
                Err(e) => {
                    echecs += dire(
                        &format!("retour par {tag}"),
                        Etat::Echoue,
                        &abreger(&format!("{e}")),
                    );
                    expliquer(&en_cours).await;
                }
            }
        }
    }

    en_cours.arreter().await?;
    let _ = std::fs::remove_file(&prepare.configuration);

    if echecs == 0 {
        println!("recette de bout en bout: complete");
        Ok(())
    } else {
        anyhow::bail!("recette de bout en bout: {echecs} etape(s) en echec")
    }
}

const LARGEUR_ABREGE: usize = 160;

/// Ramene un message sur une ligne et le raccourcit.
///
/// La coupe cherche une frontiere de caractere: trancher au milieu d'un accent
/// ferait paniquer le formatage, et une recette qui panique en RAPPORTANT une
/// panne ne rapporte plus rien.
fn abreger(s: &str) -> String {
    let s = s.replace('\n', " ");
    if s.len() <= LARGEUR_ABREGE {
        return s;
    }
    let coupe = (0..=LARGEUR_ABREGE)
        .rev()
        .find(|i| s.is_char_boundary(*i))
        .unwrap_or(0);
    format!("{}...", &s[..coupe])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sur `poids` et non sur `dire`: appeler `dire` imprimerait une ligne
    /// `SKIPPED`, que `recettes-strict.sh` compterait comme une abstention.
    #[test]
    fn seul_l_echec_compte_dans_le_total() {
        assert_eq!(poids(Etat::Reussi), 0);
        assert_eq!(poids(Etat::Echoue), 1);
        // Le point de l'ajout: une etape sautee ne masque pas un echec, mais
        // elle n'en invente pas un non plus.
        assert_eq!(poids(Etat::Saute), 0);
    }

    #[test]
    fn abreger_ne_coupe_pas_un_caractere_en_deux() {
        // Chaine volontairement multi-octets: c'est l'une des deux
        // exceptions nommees de la garde de source tests/sources_ascii.rs.
        // La reecrire en ASCII rendrait chaque octet une frontiere valide
        // et le test ne mesurerait plus rien.
        let accents = "é".repeat(200);
        let court = abreger(&accents);
        assert!(court.ends_with("..."));
        assert!(court.len() <= LARGEUR_ABREGE + 3);
    }

    #[test]
    fn abreger_met_tout_sur_une_ligne() {
        assert_eq!(abreger("une\ndeux\ntrois"), "une deux trois");
    }

    #[test]
    fn un_message_court_passe_intact() {
        assert_eq!(abreger("CONNECT refuse (1)"), "CONNECT refuse (1)");
    }

    const PROFIL: &str = r#"{
        "banniere": { "hote": "127.0.0.1", "port": 44344,
                      "chemin": "/index.txt", "attendu": "TEMOIN" },
        "sorties": [
            { "type": "vless-reality", "tag": "reality", "serveur": "192.0.2.10",
              "port": 44343, "uuid": "00000000-0000-4000-8000-000000000000",
              "cle_publique": "CLE", "short_id": "0000000000000000",
              "nom_de_serveur": "dl.google.com" },
            { "type": "hysteria2", "tag": "hy2", "serveur": "192.0.2.10",
              "port": 44345, "mot_de_passe": "MDP", "nom_de_serveur": "exemple.test",
              "certificat": ["-----BEGIN CERTIFICATE-----"] }
        ]
    }"#;

    #[test]
    fn un_profil_a_deux_transports_se_lit() {
        let p: Profil = serde_json::from_str(PROFIL).unwrap();
        assert_eq!(p.banniere.attendu, "TEMOIN");
        assert_eq!(
            p.sorties
                .iter()
                .map(SortieDuProfil::tag)
                .collect::<Vec<_>>(),
            vec!["reality", "hy2"]
        );
    }

    #[test]
    fn chaque_transport_du_profil_engendre_la_bonne_sortie() {
        let p: Profil = serde_json::from_str(PROFIL).unwrap();
        let sorties: Vec<_> = p.sorties.iter().map(SortieDuProfil::en_sortie).collect();
        assert!(matches!(sorties[0], configuration::Sortie::VlessReality(_)));
        match &sorties[1] {
            configuration::Sortie::Hysteria2(h) => {
                assert_eq!(h.mot_de_passe, "MDP");
                // L'absence d'obfs dans le JSON doit donner None, pas une
                // chaine vide qui produirait un salamander sans mot de passe.
                assert_eq!(h.obfs, None);
                // Et le certificat est TOUJOURS epingle: il n'existe pas de
                // chemin par lequel un profil demanderait de ne rien verifier.
                assert!(matches!(h.confiance, configuration::Confiance::Epingle(_)));
            }
            autre => panic!("mauvaise sortie: {autre:?}"),
        }
    }

    #[test]
    fn un_transport_hysteria2_sans_certificat_est_refuse_a_la_lecture() {
        // Champ obligatoire: un profil qui l'oublie doit echouer bruyamment
        // plutot que de monter un tunnel non authentifie.
        let sans = r#"{
            "banniere": { "hote": "127.0.0.1", "port": 1, "chemin": "/", "attendu": "x" },
            "sorties": [ { "type": "hysteria2", "tag": "hy2", "serveur": "192.0.2.10",
                           "port": 44345, "mot_de_passe": "MDP",
                           "nom_de_serveur": "exemple.test" } ]
        }"#;
        assert!(serde_json::from_str::<Profil>(sans).is_err());
    }

    #[test]
    fn un_type_de_transport_inconnu_est_refuse() {
        let inconnu = r#"{
            "banniere": { "hote": "127.0.0.1", "port": 1, "chemin": "/", "attendu": "x" },
            "sorties": [ { "type": "wireguard-nu", "tag": "wg" } ]
        }"#;
        assert!(serde_json::from_str::<Profil>(inconnu).is_err());
    }
}
