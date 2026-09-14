//! Ce qu'on apprend d'une poignee de main TLS sans en etablir une.
//!
//! Le piege que ce module existe pour rendre lisible: dans REALITY, le serveur
//! REJOUE au client la poignee de main qu'il vole a un site tiers. Si la
//! reponse de ce site ne tient pas dans le tampon prevu, la poignee ne se
//! termine jamais et le client ne voit qu'un `EOF`, sans le moindre rapport
//! apparent avec la cause. Choisir le site emprunte est donc une condition de
//! CORRECTION, pas un gout, et cela a coute une journee de diagnostic.
//!
//! La mesure ne demande aucune bibliotheque TLS, et c'est delibere. Ce qu'il
//! faut connaitre est la TAILLE de ce que le site renvoie, or les en-tetes
//! d'enregistrement TLS sont en clair meme quand leur contenu ne l'est pas. On
//! envoie donc un `ClientHello` credible, on compte ce qui revient, et on
//! raccroche sans jamais deriver la moindre clef. Terminer la poignee
//! demanderait X25519, HKDF et AES-GCM, donc soit une pile TLS complete, soit
//! une chaine de construction native (`nasm`, `cmake`) que ce depot n'exige
//! nulle part ailleurs.
//!
//! Le partage habituel du depot est reconduit: la fabrication du `ClientHello`
//! et le decoupage des enregistrements sont purs et testes partout, le socket
//! est a cote.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use bifrost_evasion::environnement::Mesure;

/// Delai au-dela duquel on considere que le site a fini de parler.
///
/// Il n'y a pas de marqueur de fin de volee lisible sans dechiffrer: le site
/// envoie sa volee puis ATTEND le `Finished` du client, qui ne viendra pas.
/// Le silence est donc la fin, et ce delai est la definition du silence.
const SILENCE: Duration = Duration::from_millis(1_500);

/// Budget total d'une observation, connexion comprise.
const BUDGET: Duration = Duration::from_secs(6);

/// Types d'enregistrement TLS utiles ici.
const ENREGISTREMENT_HANDSHAKE: u8 = 22;
const ENREGISTREMENT_ALERTE: u8 = 21;
const ENREGISTREMENT_APPLICATION: u8 = 23;

/// Taille de l'en-tete d'un enregistrement TLS: type, version, longueur.
const ENTETE_ENREGISTREMENT: usize = 5;

/// Site auquel les candidats sont compares, faute de limite absolue connue.
///
/// Il n'y a pas de seuil en dur ici, et l'absence est deliberee. Xray annonce
/// 8273 octets contre 4282 disponibles quand il refuse `www.microsoft.com`,
/// mais cette grandeur n'est pas celle qu'un client peut mesurer: la meme
/// poignee, observee de l'exterieur, donne un plus grand enregistrement de
/// 5924 octets. Figer 4282 dans ce module reviendrait a comparer deux
/// grandeurs qui ne se recouvrent pas, et le premier effet serait de declarer
/// inutilisable `dl.google.com`, qui fait passer du trafic tous les jours.
///
/// La sonde compare donc a un site de REFERENCE mesure dans le meme passage.
/// C'est le meme temoin que partout ailleurs dans ce depot: une mesure seule
/// ne conclut rien, il lui faut un point de comparaison pris dans les memes
/// conditions. Si la reference elle-meme n'a pas pu etre mesuree, aucun
/// candidat n'est qualifie.
///
/// Mesures du 16/08/2026, plus grand enregistrement, sites dont l'issue est
/// connue par la recette de bout en bout contre Xray 26.3.27:
///
/// | Site | Plus grand | Issue reelle |
/// |---|---|---|
/// | `www.cloudflare.com` | 1970 | passe |
/// | `addons.mozilla.org` | 4133 | passe |
/// | `dl.google.com` | 4985 | passe |
/// | `www.microsoft.com` | 5924 | echoue |
///
/// Quatre points ne font pas une loi. Ce que la sonde peut dire, c'est qu'un
/// candidat renvoie PLUS que le plus gros site verifie; elle ne peut pas
/// certifier celui qui renvoie moins.
pub const SITE_DE_REFERENCE: &str = "dl.google.com";

/// Marge, en pourcent, sous laquelle deux mesures ne se distinguent pas.
///
/// Deux observations du MEME site dans le meme passage ont donne 4985 puis
/// 4984 octets: la taille varie d'un tirage a l'autre, ne serait-ce que par
/// l'identifiant de session ou l'agrafage OCSP. Un verdict qui bascule sur un
/// octet ne dirait rien de vrai sur le site, seulement sur le bruit.
///
/// Les ecarts qui comptent sont d'un tout autre ordre: `www.microsoft.com`
/// renvoie 19% de plus que la reference, `www.bing.com` 20%. Cinq pourcent
/// separe donc largement le bruit du signal sans reclasser aucun des six sites
/// mesures.
pub const MARGE_POUR_CENT: usize = 5;

/// Nombre d'octets d'alea qu'un `ClientHello` consomme.
///
/// 32 pour le champ `Random`, 32 pour le `legacy_session_id`, 32 pour la part
/// publique X25519 de l'echange de clefs. Trois tirages INDEPENDANTS: recopier
/// le meme dans deux champs serait une signature a soi seul, alors qu'on
/// cherche justement a ressembler a tout le monde.
///
/// La part publique n'a pas besoin d'etre une vraie clef: n'importe quelle
/// valeur de 32 octets est une part publique X25519 valide, et le site
/// repondra sa volee entiere sans qu'on ait a la dechiffrer.
pub const OCTETS_D_ALEA: usize = 96;

/// Une volee de reponse, telle qu'elle se lit sans dechiffrer.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Volee {
    /// Type et longueur utile de chaque enregistrement, dans l'ordre.
    pub enregistrements: Vec<(u8, usize)>,
    /// Vrai si la lecture s'est arretee au milieu d'un enregistrement. La
    /// volee est alors une borne INFERIEURE, ce qui doit interdire de conclure
    /// qu'elle tient dans un tampon.
    pub tronquee: bool,
}

impl Volee {
    /// Le plus grand enregistrement, en-tete compris.
    ///
    /// C'est cette valeur que le tampon doit pouvoir contenir: un
    /// enregistrement se lit d'un bloc, et c'est le certificat, seul dans son
    /// enregistrement, qui deborde.
    pub fn plus_grand(&self) -> usize {
        self.enregistrements
            .iter()
            .map(|(_, n)| n + ENTETE_ENREGISTREMENT)
            .max()
            .unwrap_or(0)
    }

    /// Tout ce que le site a envoye, en-tetes compris.
    pub fn total(&self) -> usize {
        self.enregistrements
            .iter()
            .map(|(_, n)| n + ENTETE_ENREGISTREMENT)
            .sum()
    }

    /// Le site a-t-il refuse la poignee au lieu de la mener.
    ///
    /// Une alerte est une reponse, mais pas celle qu'on mesure: la traiter
    /// comme une volee ferait qualifier un site qui nous a claque la porte.
    pub fn alerte(&self) -> bool {
        self.enregistrements
            .iter()
            .any(|(t, _)| *t == ENREGISTREMENT_ALERTE)
    }

    /// A-t-on vu au moins un enregistrement de poignee de main.
    pub fn a_repondu(&self) -> bool {
        self.enregistrements
            .iter()
            .any(|(t, _)| *t == ENREGISTREMENT_HANDSHAKE || *t == ENREGISTREMENT_APPLICATION)
    }
}

/// Ce qu'une observation a donne, avant toute interpretation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Observation {
    /// Le site a parle.
    Vue(Volee),
    /// La connexion s'est etablie et rien n'est revenu avant l'echeance.
    Muet,
    /// La connexion n'a pas pu etre etablie. Ce n'est PAS un verdict sur le
    /// site: une machine sans reseau produit exactement ce resultat.
    Injoignable,
}

/// Fabrique un `ClientHello` TLS 1.3 pour ce nom de serveur.
///
/// Pur, donc testable sans reseau. L'alea est un parametre pour la meme
/// raison: un `ClientHello` engendre a partir d'octets fixes doit etre
/// reproductible octet pour octet, sans quoi rien ne garde ses longueurs.
///
/// L'ALPN annonce `h2` puis `http/1.1`. Ce n'est pas decoratif: un site
/// emprunte par REALITY doit parler HTTP/2, et un site qui ne le propose pas
/// n'est de toute facon pas un bon candidat.
pub fn client_hello(nom_de_serveur: &str, alea: &[u8; OCTETS_D_ALEA]) -> Vec<u8> {
    let mut corps = Vec::with_capacity(512);
    // legacy_version: 1.2 sur le fil, la vraie version est dans l'extension
    // supported_versions. C'est ce que fait tout client TLS 1.3, et s'en
    // ecarter suffirait a nous distinguer.
    corps.extend_from_slice(&[0x03, 0x03]);
    corps.extend_from_slice(&alea[..32]);
    // legacy_session_id non vide: le mode de compatibilite, que tous les
    // navigateurs utilisent. Un identifiant vide est legal et rare, donc
    // remarquable.
    corps.extend(bloc_u8(&alea[32..64]));
    // Les trois suites de TLS 1.3, dans l'ordre habituel.
    corps.extend(bloc_u16(&[0x13, 0x01, 0x13, 0x02, 0x13, 0x03]));
    corps.extend(bloc_u8(&[0x00]));

    let mut extensions = Vec::with_capacity(256);
    // server_name: la seule extension dont le contenu change d'un site a
    // l'autre, et tout l'objet de la mesure.
    let nom = nom_de_serveur.as_bytes();
    let mut sni = vec![0x00];
    sni.extend(bloc_u16(nom));
    extensions.extend(extension(0x0000, &bloc_u16(&sni)));
    // supported_groups: x25519 seul, puisque c'est le seul groupe dont on
    // fabrique une part publique.
    extensions.extend(extension(0x000a, &bloc_u16(&[0x00, 0x1d])));
    // signature_algorithms: obligatoire, sans quoi le site refuse.
    extensions.extend(extension(
        0x000d,
        &bloc_u16(&[0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x08, 0x05, 0x08, 0x06]),
    ));
    // supported_versions: TLS 1.3 seul. Negocier 1.2 donnerait un certificat
    // en clair, donc une mesure DIFFERENTE de celle que REALITY subit.
    extensions.extend(extension(0x002b, &bloc_u8(&[0x03, 0x04])));
    // key_share: x25519, 32 octets quelconques.
    let mut part = vec![0x00, 0x1d];
    part.extend(bloc_u16(&alea[64..96]));
    extensions.extend(extension(0x0033, &bloc_u16(&part)));
    // ALPN.
    let mut alpn = Vec::new();
    alpn.extend(bloc_u8(b"h2"));
    alpn.extend(bloc_u8(b"http/1.1"));
    extensions.extend(extension(0x0010, &bloc_u16(&alpn)));
    // compress_certificate, algorithme brotli. Ce n'est PAS un detail de
    // confort: c'est l'extension qui decide de la TAILLE du certificat renvoye,
    // donc de la grandeur meme qu'on mesure. Chrome l'annonce, uTLS l'imite, et
    // c'est cette poignee-la que REALITY rejoue. L'omettre reviendrait a
    // mesurer une reponse que le vrai client ne recevra jamais.
    extensions.extend(extension(0x001b, &bloc_u8(&[0x00, 0x02])));

    corps.extend(bloc_u16(&extensions));

    let mut poignee = vec![0x01];
    poignee.extend(bloc_u24(&corps));

    let mut enregistrement = vec![ENREGISTREMENT_HANDSHAKE, 0x03, 0x01];
    enregistrement.extend(bloc_u16(&poignee));
    enregistrement
}

/// Decoupe un flux d'octets en enregistrements TLS.
///
/// Pur. Ne dechiffre rien: seuls le type et la longueur sont lus, et tous deux
/// sont en clair y compris apres que le chiffrement a commence.
pub fn decouper(flux: &[u8]) -> Volee {
    let mut v = Volee::default();
    let mut i = 0;
    while i + ENTETE_ENREGISTREMENT <= flux.len() {
        let type_ = flux[i];
        let longueur = usize::from(u16::from_be_bytes([flux[i + 3], flux[i + 4]]));
        v.enregistrements.push((type_, longueur));
        let fin = i + ENTETE_ENREGISTREMENT + longueur;
        if fin > flux.len() {
            v.tronquee = true;
            return v;
        }
        i = fin;
    }
    if i < flux.len() {
        v.tronquee = true;
    }
    v
}

/// Une volee est-elle exploitable comme mesure.
///
/// Une volee tronquee est une borne INFERIEURE, une alerte est un refus et non
/// une poignee: dans les deux cas la taille lue ne represente pas ce qu'on
/// croit, et la traiter comme une mesure qualifierait un site sur autre chose
/// que ce qu'on voulait mesurer.
pub fn taille_exploitable(o: &Observation) -> Option<usize> {
    match o {
        Observation::Injoignable | Observation::Muet => None,
        Observation::Vue(v) if v.tronquee || !v.a_repondu() || v.alerte() => None,
        Observation::Vue(v) => Some(v.plus_grand()),
    }
}

/// Ce candidat renvoie-t-il au plus autant qu'un site verifie.
///
/// `Vu(true)` ne certifie pas que REALITY fonctionnera: il dit que la reponse
/// du candidat ne depasse pas celle d'un site dont on SAIT qu'il fait passer
/// du trafic. `Vu(false)` est l'information utile, celle qui evite de perdre
/// une journee sur un `EOF` muet.
///
/// Sans reference exploitable, aucune conclusion: c'est la meme regle que pour
/// le temoin des sondes reseau, et pour la meme raison. Un site injoignable et
/// un site qui deborde produisent le meme silence.
pub fn conclure_site_emprunte(candidat: &Observation, reference: &Observation) -> Mesure<bool> {
    match (taille_exploitable(candidat), taille_exploitable(reference)) {
        // Entier plutot que flottant: la comparaison doit rendre exactement le
        // meme verdict partout, et il n'y a rien a gagner a arrondir.
        (Some(c), Some(r)) => Mesure::Vu(c * 100 <= r * (100 + MARGE_POUR_CENT)),
        _ => Mesure::NonMesure,
    }
}

/// Envoie un `ClientHello` et compte ce qui revient.
pub fn observer(nom_de_serveur: &str, port: u16, alea: &[u8; OCTETS_D_ALEA]) -> Observation {
    let debut = Instant::now();
    let Ok(mut adresses) = (nom_de_serveur, port).to_socket_addrs() else {
        return Observation::Injoignable;
    };
    let Some(adresse) = adresses.next() else {
        return Observation::Injoignable;
    };
    let Ok(mut flux) = TcpStream::connect_timeout(&adresse, BUDGET) else {
        return Observation::Injoignable;
    };
    if flux.set_read_timeout(Some(SILENCE)).is_err()
        || flux.write_all(&client_hello(nom_de_serveur, alea)).is_err()
    {
        return Observation::Injoignable;
    }

    let mut recu = Vec::with_capacity(16 * 1024);
    let mut tampon = [0u8; 8 * 1024];
    loop {
        match flux.read(&mut tampon) {
            Ok(0) => break,
            Ok(n) => recu.extend_from_slice(&tampon[..n]),
            // Le silence EST la fin de la volee: le site attend un `Finished`
            // qui ne viendra pas.
            Err(_) => break,
        }
        if debut.elapsed() > BUDGET {
            break;
        }
    }

    if recu.is_empty() {
        return Observation::Muet;
    }
    Observation::Vue(decouper(&recu))
}

/// Comme [`observer`], avec l'alea tire du generateur du systeme.
pub fn observer_maintenant(nom_de_serveur: &str, port: u16) -> anyhow::Result<Observation> {
    let mut alea = [0u8; OCTETS_D_ALEA];
    crate::coeurs::alea::octets(&mut alea)?;
    Ok(observer(nom_de_serveur, port, &alea))
}

fn bloc_u8(contenu: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(contenu.len() + 1);
    v.push(contenu.len() as u8);
    v.extend_from_slice(contenu);
    v
}

fn bloc_u16(contenu: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(contenu.len() + 2);
    v.extend_from_slice(&(contenu.len() as u16).to_be_bytes());
    v.extend_from_slice(contenu);
    v
}

fn bloc_u24(contenu: &[u8]) -> Vec<u8> {
    let n = contenu.len() as u32;
    let mut v = Vec::with_capacity(contenu.len() + 3);
    v.extend_from_slice(&n.to_be_bytes()[1..]);
    v.extend_from_slice(contenu);
    v
}

fn extension(code: u16, contenu: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(contenu.len() + 4);
    v.extend_from_slice(&code.to_be_bytes());
    v.extend(bloc_u16(contenu));
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alea() -> [u8; OCTETS_D_ALEA] {
        let mut a = [0u8; OCTETS_D_ALEA];
        for (i, o) in a.iter_mut().enumerate() {
            *o = (i as u8).wrapping_mul(7).wrapping_add(3);
        }
        a
    }

    /// Relit toutes les longueurs annoncees et les confronte aux octets
    /// reellement presents.
    ///
    /// C'est le seul test qui compte vraiment ici: une longueur fausse produit
    /// un `ClientHello` que le site jette SANS RIEN DIRE, donc une mesure
    /// absente et inexplicable. Le mode d'echec de ce module est le silence,
    /// exactement comme celui qu'il sert a diagnostiquer.
    fn longueurs_coherentes(h: &[u8]) -> Result<(), String> {
        if h.len() < 9 {
            return Err("trop court pour porter un en-tete".into());
        }
        if h[0] != ENREGISTREMENT_HANDSHAKE {
            return Err(format!("type d'enregistrement {} au lieu de 22", h[0]));
        }
        let long_enr = usize::from(u16::from_be_bytes([h[3], h[4]]));
        if h.len() != ENTETE_ENREGISTREMENT + long_enr {
            return Err(format!(
                "enregistrement annonce {long_enr}, presents {}",
                h.len() - ENTETE_ENREGISTREMENT
            ));
        }
        if h[5] != 0x01 {
            return Err(format!("message de poignee {} au lieu de 1", h[5]));
        }
        let long_hs = u32::from_be_bytes([0, h[6], h[7], h[8]]) as usize;
        if h.len() != 9 + long_hs {
            return Err(format!(
                "poignee annoncee {long_hs}, presents {}",
                h.len() - 9
            ));
        }

        let corps = &h[9..];
        let mut i = 2 + 32; // legacy_version puis Random
        i += 1 + usize::from(corps[i]); // legacy_session_id
        i += 2 + usize::from(u16::from_be_bytes([corps[i], corps[i + 1]])); // suites
        i += 1 + usize::from(corps[i]); // compression
        let long_ext = usize::from(u16::from_be_bytes([corps[i], corps[i + 1]]));
        i += 2;
        if i + long_ext != corps.len() {
            return Err(format!(
                "bloc d'extensions annonce {long_ext}, restants {}",
                corps.len() - i
            ));
        }

        // Et chaque extension a son tour, sans quoi une longueur interne
        // fausse passerait tant que le total tombe juste.
        let mut j = i;
        while j < corps.len() {
            if j + 4 > corps.len() {
                return Err("extension tronquee".into());
            }
            let n = usize::from(u16::from_be_bytes([corps[j + 2], corps[j + 3]]));
            j += 4 + n;
        }
        if j != corps.len() {
            return Err(format!("les extensions debordent de {}", j - corps.len()));
        }
        Ok(())
    }

    /// Les types d'enregistrement sont ceux du registre TLS, pas les notres.
    ///
    /// `alert(21)`, `handshake(22)` et `application_data(23)` viennent du
    /// registre ContentType de la RFC 8446, section 5.1. Tout le module les
    /// manipule par leur NOM: la volee est decoupee avec la constante et
    /// relue avec la meme, si bien qu'aucune recette ne rougissait quand la
    /// valeur bougeait. Mesure du 23/08/2026 sur dev-windows, mutation d'un
    /// cran appliquee a chaque constante seule: deux des trois muettes.
    ///
    /// La faute grave n'est pas la recopie approximative, c'est la CONFUSION
    /// de deux types. Une alerte prise pour une poignee de main ferait compter
    /// le refus d'un site comme une volee, et la sonde qualifierait justement
    /// le site qui vient de la refuser - ce que
    /// `une_alerte_n_est_pas_une_volee` cherche a interdire, avec des valeurs
    /// ecrites en clair de son cote.
    #[test]
    fn les_types_d_enregistrement_sont_ceux_du_registre_tls() {
        assert_eq!(ENREGISTREMENT_ALERTE, 21);
        assert_eq!(ENREGISTREMENT_HANDSHAKE, 22);
        assert_eq!(ENREGISTREMENT_APPLICATION, 23);
        assert_ne!(ENREGISTREMENT_ALERTE, ENREGISTREMENT_HANDSHAKE);
        assert_ne!(ENREGISTREMENT_ALERTE, ENREGISTREMENT_APPLICATION);
        assert_ne!(ENREGISTREMENT_HANDSHAKE, ENREGISTREMENT_APPLICATION);
    }

    /// L'alea consomme, recalcule depuis les trois champs qui le consomment.
    ///
    /// `client_hello` decoupe le tampon en trois tranches de 32 octets:
    /// `Random`, `legacy_session_id`, et la part publique X25519. Le tampon
    /// est DIMENSIONNE par la constante, donc il a toujours la taille qu'elle
    /// annonce, quelle qu'elle soit.
    ///
    /// L'erreur n'est donc pas symetrique. Trop court, le decoupage sort des
    /// bornes et une recette existante panique. Trop long, rien ne le voit: on
    /// tire de l'aleatoire que personne n'ecrit, et la seule trace est un
    /// appel de plus au generateur. C'est ce cote-la que cette recette couvre.
    #[test]
    fn l_alea_consomme_couvre_exactement_les_trois_champs() {
        // Random, legacy_session_id, part publique X25519.
        const CHAMPS: usize = 3;
        const OCTETS_PAR_CHAMP: usize = 32;
        assert_eq!(OCTETS_D_ALEA, CHAMPS * OCTETS_PAR_CHAMP);
    }

    #[test]
    fn le_client_hello_annonce_des_longueurs_exactes() {
        for nom in ["dl.google.com", "a.b", "x", &"t".repeat(200)] {
            let h = client_hello(nom, &alea());
            longueurs_coherentes(&h).unwrap_or_else(|e| panic!("pour {nom:?}: {e}"));
        }
    }

    #[test]
    fn le_nom_de_serveur_voyage_bien_dans_le_client_hello() {
        let h = client_hello("dl.google.com", &alea());
        let aiguille = b"dl.google.com";
        assert!(
            h.windows(aiguille.len()).any(|f| f == aiguille),
            "le SNI n'apparait pas: la mesure porterait sur le site par defaut"
        );
    }

    #[test]
    fn les_trois_champs_aleatoires_sont_independants() {
        // Recopier le meme tirage dans le Random et le session_id serait une
        // signature a soi seul, alors que tout l'objet est de ressembler a
        // n'importe quel navigateur.
        let h = client_hello("exemple.test", &alea());
        let corps = &h[9..];
        let random = &corps[2..34];
        let session = &corps[35..67];
        assert_ne!(random, session);
    }

    #[test]
    fn le_decoupage_rend_type_et_longueur_de_chaque_enregistrement() {
        let mut flux = vec![22, 3, 3, 0, 4, 1, 2, 3, 4];
        flux.extend_from_slice(&[23, 3, 3, 0, 2, 9, 9]);
        let v = decouper(&flux);
        assert!(!v.tronquee);
        assert_eq!(v.enregistrements, vec![(22, 4), (23, 2)]);
        assert_eq!(v.plus_grand(), 9);
        assert_eq!(v.total(), 16);
    }

    #[test]
    fn un_enregistrement_coupe_en_deux_est_annonce_tronque() {
        // Une volee tronquee est une borne INFERIEURE. La declarer complete
        // ferait qualifier un site sur une mesure partielle, ce qui est
        // precisement l'erreur a ne pas commettre ici.
        let v = decouper(&[22, 3, 3, 0, 100, 1, 2, 3]);
        assert!(v.tronquee);
        let v = decouper(&[22, 3]);
        assert!(v.tronquee);
    }

    fn volee(taille: usize) -> Observation {
        Observation::Vue(Volee {
            enregistrements: vec![(22, 100), (23, taille - ENTETE_ENREGISTREMENT)],
            tronquee: false,
        })
    }

    #[test]
    fn une_volee_tronquee_ne_qualifie_aucun_site() {
        let coupee = Observation::Vue(Volee {
            enregistrements: vec![(22, 10)],
            tronquee: true,
        });
        assert!(!conclure_site_emprunte(&coupee, &volee(9_000)).est_mesure());
        // Et symetriquement: une reference tronquee ne qualifie rien non plus.
        assert!(!conclure_site_emprunte(&volee(100), &coupee).est_mesure());
    }

    #[test]
    fn un_site_muet_ou_injoignable_ne_conclut_rien() {
        assert!(!conclure_site_emprunte(&Observation::Muet, &volee(9_000)).est_mesure());
        assert!(!conclure_site_emprunte(&Observation::Injoignable, &volee(9_000)).est_mesure());
    }

    #[test]
    fn sans_reference_exploitable_aucun_candidat_n_est_qualifie() {
        // Le point entier de la conception: la reference EST le temoin. Sans
        // elle, un candidat parfaitement mesure ne prouve rien, puisqu'il n'y
        // a plus rien a quoi le comparer.
        assert!(!conclure_site_emprunte(&volee(100), &Observation::Injoignable).est_mesure());
        assert!(!conclure_site_emprunte(&volee(100), &Observation::Muet).est_mesure());
    }

    #[test]
    fn une_alerte_n_est_pas_une_volee() {
        // Un site qui refuse la poignee repond quelque chose. Compter ce
        // quelque chose comme une volee le qualifierait pour la seule raison
        // que son refus est court.
        let refus = Observation::Vue(Volee {
            enregistrements: vec![(22, 100), (21, 2)],
            tronquee: false,
        });
        assert!(!conclure_site_emprunte(&refus, &volee(9_000)).est_mesure());
    }

    #[test]
    fn la_comparaison_se_fait_sur_le_plus_grand_enregistrement() {
        let reference = volee(4_985);
        assert!(conclure_site_emprunte(&volee(1_970), &reference).vu_vrai());
        assert!(conclure_site_emprunte(&volee(4_985), &reference).vu_vrai());
        assert!(conclure_site_emprunte(&volee(5_924), &reference).vu_faux());
    }

    #[test]
    fn un_octet_de_plus_ne_fait_pas_basculer_le_verdict() {
        // Deux mesures du meme site ont donne 4985 puis 4984. Sans marge, le
        // site de reference se declarerait lui-meme au-dela de lui-meme une
        // fois sur deux, et le verdict parlerait du bruit, pas du site.
        let reference = volee(4_984);
        assert!(conclure_site_emprunte(&volee(4_985), &reference).vu_vrai());
        // La marge reste tres en dessous des ecarts qui comptent: le premier
        // site connu pour echouer est a +19%.
        assert!(conclure_site_emprunte(&volee(5_924), &reference).vu_faux());
    }

    #[test]
    fn les_quatre_sites_connus_se_classent_du_bon_cote() {
        // Les tailles sont celles mesurees le 16/08/2026, et l'issue reelle
        // vient de la recette de bout en bout contre Xray. Ce test ne prouve
        // pas que la sonde a raison en general; il prouve qu'elle n'a pas tort
        // sur les seuls cas dont on connaisse la reponse, ce qui est le
        // minimum avant de s'en servir pour choisir un site.
        let reference = volee(4_985); // dl.google.com, passe
        for (taille, passe) in [(1_970, true), (4_133, true), (4_985, true), (5_924, false)] {
            assert_eq!(
                conclure_site_emprunte(&volee(taille), &reference).vu_vrai(),
                passe,
                "site de {taille} octets mal classe"
            );
        }
    }
}
