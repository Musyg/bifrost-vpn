//! La sonde QUIC: le protocole passe-t-il ici, et si non, comment est-il coupe.
//!
//! # Ce que le plan demandait, et pourquoi ce n'est pas ce qui est fait
//!
//! Le document 04 partie 3.1 prescrit "tenter H3 vers un domaine H3-capable;
//! echec mais TCP/443 OK -> QUIC filtre". Deux corrections, toutes deux
//! appuyees sur des mesures publiees.
//!
//! **Aucune pile HTTP-3 n'est necessaire.** Ce module en tenait lieu de raison
//! pour laisser `quic_passe` a `NonMesure`. La question posee est "le pair
//! repond-il a du QUIC", pas "une requete HTTP aboutit-elle": il suffit
//! d'emettre un paquet que seul un serveur QUIC sait reconnaitre et de
//! regarder si quelque chose revient. Rien n'est dechiffre en retour.
//!
//! **Une seule tentative ne suffit pas a lire ce qui se passe.** Le pare-feu
//! chinois DECHIFFRE l'Initial QUIC - les clefs se derivent d'un sel public et
//! du numero de connexion, tous deux en clair - et filtre sur le SNI qu'il y
//! trouve (Zohaib et al., USENIX Security 2025). Un echec unique ne dirait pas
//! si l'UDP est coupe ou si c'est le contenu qui a ete lu. Le module envoie
//! donc DEUX paquets et lit leur difference:
//!
//! - une **negociation de version**, avec un numero de version que personne ne
//!   supporte. Sa charge est indechiffrable par construction, donc aucun
//!   censeur ne peut y lire de SNI, et tout serveur QUIC doit repondre en
//!   annoncant ses versions (RFC 9000 section 6). C'est le `quicping` d'OONI.
//! - un **Initial version 1** valide, portant un vrai `ClientHello` et un SNI
//!   banal. C'est exactement ce qu'un censeur inspecte.
//!
//! La negociation repond mais pas l'Initial: le contenu est filtre. Ni l'une ni
//! l'autre alors que le temoin TCP vit: l'UDP est coupe vers cette cible. Les
//! deux repondent: QUIC passe.
//!
//! # Le danger que cette sonde doit eviter, et qui n'est pas dans le plan
//!
//! Le meme article mesure la reaction du pare-feu: **un seul paquet suffit a
//! declencher un blocage residuel**, apres quoi TOUS les paquets UDP partageant
//! le triplet (IP source, IP destination, port destination) sont jetes pendant
//! environ 180 secondes. Une sonde imprudente puniraient donc le reseau de son
//! propre utilisateur pendant trois minutes, et le chemin UDP qu'elle venait
//! justement mesurer serait mort A CAUSE d'elle.
//!
//! D'ou deux regles tenues ici. Le SNI emis est BANAL - le nom du resolveur
//! public que l'on vise deja par ailleurs - et jamais celui d'un endpoint que
//! l'on compte utiliser. Et la cible de la sonde n'est jamais l'endpoint du
//! tunnel: la sonde mesure le RESEAU, pas le serveur.
//!
//! Le meme article donne une derniere raison de ne rien bricoler sur le port
//! source: le pare-feu ignore les paquets QUIC dont le port source est
//! INFERIEUR au port destination. Un port source ephemere ordinaire est
//! superieur a 443, donc inspecte, ce qui est bien ce qu'on veut mesurer. Lier
//! la sonde a un port bas la ferait passer a cote du censeur et rapporter
//! "QUIC passe" sur un reseau qui le coupe.
//!
//! # Le partage habituel du depot
//!
//! La fabrication des paquets et la lecture des reponses sont pures, donc
//! testees partout - et pas seulement contre elles-memes: la protection d'un
//! Initial est confrontee aux vecteurs de l'annexe A du RFC 9001, octet pour
//! octet. Le socket est a cote.

use std::net::SocketAddr;
use std::time::Duration;

use aes::cipher::{BlockEncrypt, KeyInit as _};
use aes_gcm::aead::{Aead, Payload};
use bifrost_evasion::environnement::Mesure;
use hkdf::Hkdf;
use sha2::Sha256;

use crate::sondes::Tentative;

/// Sel des secrets initiaux de QUIC version 1. RFC 9001 section 5.2.
pub const SEL_INITIAL_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

/// QUIC version 1, RFC 9000. La seule que le pare-feu chinois bloque; la
/// version 2 (RFC 9369) passe encore, ce qui est un contournement connu et non
/// une mesure - la sonde veut etre inspectee, pas passer.
pub const VERSION_1: u32 = 0x0000_0001;

/// Une version que personne ne supporte, et qui ne le sera jamais.
///
/// RFC 9000 section 15: les versions de la forme `0x?a?a?a?a` sont reservees a
/// l'exercice de la negociation de version. En emettre une garantit une reponse
/// de negociation d'un serveur QUIC, et garantit surtout que la charge du
/// paquet est INDECHIFFRABLE - aucun censeur n'y lira de nom de serveur.
pub const VERSION_RESERVEE: u32 = 0x1a2a_3a4a;

/// Taille minimale d'un datagramme portant un Initial. RFC 9000 section 14.1:
/// le client DOIT l'atteindre, et un serveur peut jeter ce qui est plus court.
/// Le declencheur de negociation la respecte aussi, pour la meme raison.
pub const TAILLE_DATAGRAMME: usize = 1200;

/// Longueur des numeros de connexion emis. RFC 9000 section 7.2 demande au
/// moins huit octets IMPREVISIBLES pour le premier numero de destination: c'est
/// lui qui derive les clefs initiales, et un numero devinable les donnerait.
pub const OCTETS_DE_NUMERO: usize = 8;

/// Alea consomme par un paquet Initial: `Random`, identifiant de session, part
/// publique x25519, puis les deux numeros de connexion.
pub const OCTETS_D_ALEA: usize = 32 + 32 + 32 + OCTETS_DE_NUMERO * 2;

/// Delai au-dela duquel on considere que rien ne reviendra.
///
/// Aligne sur [`crate::sondes::DELAI_TENTATIVE`]: la sonde partage le budget de
/// cinq secondes du document 04 partie 3.1 avec les autres.
pub const DELAI: Duration = Duration::from_millis(1_500);

/// Secrets de protection d'un paquet Initial, cote client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Secrets {
    pub cle: [u8; 16],
    pub iv: [u8; 12],
    pub hp: [u8; 16],
}

/// Les deux numeros de connexion d'un paquet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Numeros {
    /// Numero de destination. C'est lui qui derive les clefs initiales.
    pub destination: [u8; OCTETS_DE_NUMERO],
    /// Numero de source, celui par lequel le serveur nous repondra.
    pub source: [u8; OCTETS_DE_NUMERO],
}

/// Ce qu'un datagramme recu apprend, sans rien dechiffrer.
///
/// Aucune de ces formes ne demande de clef: l'en-tete long de QUIC est en
/// clair, et une negociation de version l'est entierement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reponse {
    /// Version a zero: une negociation de version. Le serveur parle QUIC et
    /// annonce ce qu'il sait faire.
    NegociationVersion,
    /// En-tete long avec une version connue: un Initial ou un Retry. Le serveur
    /// a accepte notre paquet et a commence a repondre.
    EnteteLong { version: u32 },
    /// En-tete court: le serveur nous croit deja en session. Ne devrait pas
    /// arriver ici, mais reste un signe de vie QUIC.
    EnteteCourt,
    /// Quelque chose est revenu qui ne ressemble pas a du QUIC.
    Inconnue,
}

/// HKDF-Expand-Label de TLS 1.3, tel que QUIC le reutilise.
///
/// L'etiquette est prefixee de `tls13 ` et le contexte est vide dans tous les
/// usages de ce module. Le format est verifie contre l'annexe A.1 du RFC 9001,
/// qui donne les quatre `HkdfLabel` encodes.
pub fn etiquette_hkdf(etiquette: &str, longueur: u16) -> Vec<u8> {
    let mut complete = Vec::with_capacity(6 + etiquette.len());
    complete.extend_from_slice(b"tls13 ");
    complete.extend_from_slice(etiquette.as_bytes());

    let mut info = Vec::with_capacity(4 + complete.len());
    info.extend_from_slice(&longueur.to_be_bytes());
    info.push(complete.len() as u8);
    info.extend_from_slice(&complete);
    // Contexte vide.
    info.push(0);
    info
}

fn deriver(prk: &Hkdf<Sha256>, etiquette: &str, sortie: &mut [u8]) {
    let info = etiquette_hkdf(etiquette, sortie.len() as u16);
    prk.expand(&info, sortie)
        .expect("longueur de derivation valide pour SHA-256");
}

/// Derive les secrets de protection du client depuis le numero de destination.
///
/// RFC 9001 section 5.2. Rien de secret ici: le sel est public et le numero de
/// connexion voyage en clair, ce qui est exactement pourquoi un observateur
/// sur le chemin peut dechiffrer l'Initial et y lire le SNI.
pub fn secrets_client(destination: &[u8]) -> Secrets {
    let initial = Hkdf::<Sha256>::new(Some(&SEL_INITIAL_V1), destination);
    let mut secret_client = [0u8; 32];
    deriver(&initial, "client in", &mut secret_client);

    let du_client = Hkdf::<Sha256>::from_prk(&secret_client).expect("32 octets forment un PRK");
    let mut s = Secrets {
        cle: [0u8; 16],
        iv: [0u8; 12],
        hp: [0u8; 16],
    };
    deriver(&du_client, "quic key", &mut s.cle);
    deriver(&du_client, "quic iv", &mut s.iv);
    deriver(&du_client, "quic hp", &mut s.hp);
    s
}

/// Chiffre la charge et protege l'en-tete d'un paquet Initial.
///
/// `entete` doit deja contenir le numero de paquet encode a sa fin, en clair:
/// c'est la donnee associee de l'AEAD, et c'est aussi ce que la protection
/// d'en-tete masque ensuite.
///
/// Rendu separement de [`paquet_initial`] pour une seule raison, qui vaut le
/// detour: cette fonction-la peut etre confrontee aux vecteurs de l'annexe A.2
/// du RFC 9001, octet pour octet. Un chiffrement qui se verifie contre
/// lui-meme ne prouve rien.
pub fn proteger(entete: &[u8], charge: &[u8], secrets: &Secrets, numero: u64) -> Vec<u8> {
    let taille_numero = (entete[0] & 0x03) as usize + 1;
    let decalage_numero = entete.len() - taille_numero;

    // Le nonce est l'IV combine au numero de paquet COMPLET, aligne a droite,
    // et non au numero tronque qui voyage dans l'en-tete.
    let mut nonce = secrets.iv;
    let n = numero.to_be_bytes();
    for i in 0..8 {
        nonce[4 + i] ^= n[i];
    }

    let scelle = aes_gcm::Aes128Gcm::new_from_slice(&secrets.cle)
        .expect("clef de 16 octets")
        .encrypt(
            aes_gcm::Nonce::from_slice(&nonce),
            Payload {
                msg: charge,
                aad: entete,
            },
        )
        .expect("le chiffrement AES-GCM ne peut pas echouer sur une entree bornee");

    let mut paquet = Vec::with_capacity(entete.len() + scelle.len());
    paquet.extend_from_slice(entete);
    paquet.extend_from_slice(&scelle);

    // Echantillon: quatre octets apres le debut du numero de paquet, quelle que
    // soit sa taille reelle. RFC 9001 section 5.4.2.
    let debut = decalage_numero + 4;
    let mut echantillon = [0u8; 16];
    echantillon.copy_from_slice(&paquet[debut..debut + 16]);

    let mut masque = aes::cipher::generic_array::GenericArray::from(echantillon);
    aes::Aes128::new_from_slice(&secrets.hp)
        .expect("clef de 16 octets")
        .encrypt_block(&mut masque);

    // En-tete long: seuls les quatre bits bas du premier octet sont masques.
    paquet[0] ^= masque[0] & 0x0f;
    for i in 0..taille_numero {
        paquet[decalage_numero + i] ^= masque[1 + i];
    }
    paquet
}

/// Encodage entier a longueur variable de QUIC. RFC 9000 section 16.
pub fn varint(v: u64) -> Vec<u8> {
    match v {
        0..=63 => vec![v as u8],
        64..=16_383 => {
            let x = (v as u16) | 0x4000;
            x.to_be_bytes().to_vec()
        }
        16_384..=1_073_741_823 => {
            let x = (v as u32) | 0x8000_0000;
            x.to_be_bytes().to_vec()
        }
        _ => {
            let x = v | 0xc000_0000_0000_0000;
            x.to_be_bytes().to_vec()
        }
    }
}

fn bloc_u8(contenu: &[u8]) -> Vec<u8> {
    let mut v = vec![contenu.len() as u8];
    v.extend_from_slice(contenu);
    v
}

fn bloc_u16(contenu: &[u8]) -> Vec<u8> {
    let mut v = (contenu.len() as u16).to_be_bytes().to_vec();
    v.extend_from_slice(contenu);
    v
}

fn bloc_u24(contenu: &[u8]) -> Vec<u8> {
    let n = contenu.len() as u32;
    let mut v = vec![(n >> 16) as u8, (n >> 8) as u8, n as u8];
    v.extend_from_slice(contenu);
    v
}

fn extension(code: u16, contenu: &[u8]) -> Vec<u8> {
    let mut v = code.to_be_bytes().to_vec();
    v.extend(bloc_u16(contenu));
    v
}

fn parametre(identifiant: u64, valeur: &[u8]) -> Vec<u8> {
    let mut v = varint(identifiant);
    v.extend(varint(valeur.len() as u64));
    v.extend_from_slice(valeur);
    v
}

/// Parametres de transport QUIC, extension TLS obligatoire cote client.
///
/// # La raison n'est PAS celle que j'avais ecrite
///
/// J'avais note que son absence ferait refuser le paquet, donc que la sonde ne
/// mesurerait plus le reseau. La mesure dit autre chose: en la retirant, les
/// deux cibles repondent EXACTEMENT pareil - un en-tete long version 1 de 1200
/// octets. De l'exterieur, un Initial conforme et un Initial ampute sont
/// indiscernables, parce que tout ce que la sonde regarde est "quelque chose
/// est-il revenu", et un refus revient aussi.
///
/// La vraie raison est ailleurs, et elle est plus forte: le paquet doit etre
/// fidele a ce qu'emet un VRAI client, non pour le serveur mais pour le
/// CENSEUR. Un Initial que l'analyseur d'un pare-feu rejette comme malforme ne
/// sera pas filtre, et la sonde rapporterait alors "QUIC passe" sur un reseau
/// qui coupe les vrais clients. La fidelite est la propriete mesuree, pas
/// l'acceptation.
///
/// `initial_source_connection_id` vaut NOTRE numero de source: le serveur le
/// compare a celui de l'en-tete (RFC 9000 section 7.3).
pub fn parametres_transport(source: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(64);
    // max_idle_timeout: 30 s. La sonde raccroche bien avant, mais un zero
    // signifie "sans limite", ce qui est un reglage remarquable.
    p.extend(parametre(0x01, &varint(30_000)));
    // initial_max_data et les trois limites de flux par flux.
    p.extend(parametre(0x04, &varint(1_048_576)));
    p.extend(parametre(0x05, &varint(65_535)));
    p.extend(parametre(0x06, &varint(65_535)));
    p.extend(parametre(0x07, &varint(65_535)));
    // Deux flux dans chaque sens: assez pour etre credible, aucun ne servira.
    p.extend(parametre(0x08, &varint(2)));
    p.extend(parametre(0x09, &varint(2)));
    p.extend(parametre(0x0f, source));
    p
}

/// Fabrique le `ClientHello` que porte l'Initial.
///
/// Distinct de [`crate::tls::client_hello`] et ce n'est pas une duplication a
/// resorber: celui-la est calibre pour une AUTRE mesure - la taille de ce que
/// renvoie un site emprunte par REALITY - et annonce donc `h2`, la compression
/// de certificat, et s'enveloppe dans un enregistrement TLS. Celui-ci annonce
/// `h3`, porte les parametres de transport, et n'a pas d'enregistrement du
/// tout: QUIC transporte les messages de poignee de main directement.
pub fn client_hello(nom_de_serveur: &str, source: &[u8], alea: &[u8; OCTETS_D_ALEA]) -> Vec<u8> {
    let mut corps = Vec::with_capacity(512);
    corps.extend_from_slice(&[0x03, 0x03]);
    corps.extend_from_slice(&alea[..32]);
    corps.extend(bloc_u8(&alea[32..64]));
    corps.extend(bloc_u16(&[0x13, 0x01, 0x13, 0x02, 0x13, 0x03]));
    corps.extend(bloc_u8(&[0x00]));

    let mut extensions = Vec::with_capacity(256);
    let mut sni = vec![0x00];
    sni.extend(bloc_u16(nom_de_serveur.as_bytes()));
    extensions.extend(extension(0x0000, &bloc_u16(&sni)));
    extensions.extend(extension(0x000a, &bloc_u16(&[0x00, 0x1d])));
    extensions.extend(extension(
        0x000d,
        &bloc_u16(&[0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x08, 0x05, 0x08, 0x06]),
    ));
    extensions.extend(extension(0x002b, &bloc_u8(&[0x03, 0x04])));
    let mut part = vec![0x00, 0x1d];
    part.extend(bloc_u16(&alea[64..96]));
    extensions.extend(extension(0x0033, &bloc_u16(&part)));
    // ALPN `h3`. Meme remarque que pour les parametres de transport: annoncer
    // `h2` ne change RIEN a ce que la sonde observe - mesure, les deux cibles
    // repondent pareil - mais un vrai client QUIC annonce `h3`, et c'est ce
    // qu'un censeur s'attend a lire.
    extensions.extend(extension(0x0010, &bloc_u16(&bloc_u8(b"h3"))));
    extensions.extend(extension(0x0039, &parametres_transport(source)));

    corps.extend(bloc_u16(&extensions));

    let mut poignee = vec![0x01];
    poignee.extend(bloc_u24(&corps));
    poignee
}

/// Le datagramme complet d'un Initial version 1, pret a partir.
pub fn paquet_initial(
    numeros: &Numeros,
    nom_de_serveur: &str,
    alea: &[u8; OCTETS_D_ALEA],
) -> Vec<u8> {
    let poignee = client_hello(nom_de_serveur, &numeros.source, alea);

    // Une trame CRYPTO au decalage zero, puis du remplissage jusqu'a la taille
    // minimale du datagramme. Le remplissage est indispensable et pas
    // cosmetique: un datagramme plus court est jete par le serveur.
    let mut charge = Vec::with_capacity(TAILLE_DATAGRAMME);
    charge.push(0x06);
    charge.extend(varint(0));
    charge.extend(varint(poignee.len() as u64));
    charge.extend_from_slice(&poignee);

    // Taille de l'en-tete, connue avant de la construire: premier octet, quatre
    // de version, deux longueurs de numero, les numeros, la longueur du jeton,
    // la longueur du reste, et quatre octets de numero de paquet.
    let taille_entete =
        1 + 4 + 1 + numeros.destination.len() + 1 + numeros.source.len() + 1 + 2 + 4;
    let vise = TAILLE_DATAGRAMME.saturating_sub(taille_entete + 16);
    while charge.len() < vise {
        // Trame PADDING: un octet nul.
        charge.push(0x00);
    }

    let mut entete = Vec::with_capacity(taille_entete);
    // Forme longue, bit fixe, type Initial, numero de paquet sur quatre octets.
    entete.push(0xc3);
    entete.extend_from_slice(&VERSION_1.to_be_bytes());
    entete.extend(bloc_u8(&numeros.destination));
    entete.extend(bloc_u8(&numeros.source));
    // Jeton vide: nous n'avons pas recu de Retry.
    entete.extend(varint(0));
    let longueur = 4 + charge.len() + 16;
    // Longueur forcee sur deux octets: la taille de l'en-tete a ete calculee
    // avec cette hypothese, et un varint plus court la contredirait.
    entete.extend_from_slice(&((longueur as u16) | 0x4000).to_be_bytes());
    entete.extend_from_slice(&2u32.to_be_bytes());

    proteger(&entete, &charge, &secrets_client(&numeros.destination), 2)
}

/// Le datagramme qui declenche une negociation de version.
///
/// Aucune cryptographie: la version est inconnue, donc le serveur ne cherche
/// meme pas a dechiffrer la charge et repond par la liste de ce qu'il supporte.
/// C'est aussi ce qui rend ce paquet inoffensif face a un censeur qui filtre
/// sur le SNI - il n'y en a pas a lire.
pub fn paquet_negociation(numeros: &Numeros) -> Vec<u8> {
    let mut p = Vec::with_capacity(TAILLE_DATAGRAMME);
    p.push(0xc0);
    p.extend_from_slice(&VERSION_RESERVEE.to_be_bytes());
    p.extend(bloc_u8(&numeros.destination));
    p.extend(bloc_u8(&numeros.source));
    p.resize(TAILLE_DATAGRAMME, 0);
    p
}

/// Lit ce qu'un datagramme recu dit, sans rien dechiffrer.
pub fn lire_reponse(datagramme: &[u8]) -> Option<Reponse> {
    let premier = *datagramme.first()?;
    if premier & 0x80 == 0 {
        // Forme courte: pas de version, un seul bit a lire.
        return Some(Reponse::EnteteCourt);
    }
    if datagramme.len() < 5 {
        return Some(Reponse::Inconnue);
    }
    let version = u32::from_be_bytes([datagramme[1], datagramme[2], datagramme[3], datagramme[4]]);
    Some(match version {
        0 => Reponse::NegociationVersion,
        v => Reponse::EnteteLong { version: v },
    })
}

/// Ce que les deux paquets, pris ensemble, disent de QUIC sur ce reseau.
///
/// La table entiere, et chaque ligne compte:
///
/// | Negociation | Initial v1 | Conclusion |
/// |---|---|---|
/// | repond | repond | QUIC passe |
/// | repond | muet | le CONTENU est filtre: un censeur lit le SNI |
/// | muet | repond | invraisemblable; on croit ce qui a REPONDU |
/// | muet | muet | l'UDP est coupe vers cette cible, si le temoin vit |
///
/// La troisieme ligne merite son cas: elle ne devrait pas arriver, mais une
/// reponse recue est un fait, et un silence n'en est pas un. Conclure "QUIC ne
/// passe pas" en ayant recu du QUIC serait absurde.
pub fn conclure(negociation: Tentative, initial: Tentative, temoin: Mesure<bool>) -> Mesure<bool> {
    let aucune_faite = !negociation.a_pu_etre_faite() && !initial.a_pu_etre_faite();
    if aucune_faite {
        return Mesure::NonMesure;
    }
    if initial == Tentative::Aboutie || negociation == Tentative::Aboutie {
        // Une reponse a l'Initial v1 tranche seule. Une reponse a la seule
        // negociation ne suffit pas: c'est precisement la signature du filtrage
        // par SNI, et la conclusion est alors "QUIC ne passe pas".
        return Mesure::Vu(initial == Tentative::Aboutie);
    }
    // Les deux muettes: sans reseau vivant, ce silence n'apprend rien.
    match temoin {
        Mesure::Vu(true) => Mesure::Vu(false),
        Mesure::Vu(false) | Mesure::NonMesure => Mesure::NonMesure,
    }
}

/// Vrai quand le silence de l'Initial contraste avec une negociation qui, elle,
/// a repondu: la signature d'un censeur qui DECHIFFRE et lit le nom de serveur.
///
/// Distinct de [`conclure`], qui n'a qu'un booleen a rendre. Cette
/// discrimination-la ne change pas la selection du protocole - dans les deux
/// cas QUIC est inutilisable - mais elle change tout au diagnostic, et le
/// rapport de sondage l'affiche.
pub fn contenu_filtre(negociation: Tentative, initial: Tentative) -> bool {
    negociation == Tentative::Aboutie && initial != Tentative::Aboutie
}

/// Emet un datagramme et attend une reponse.
///
/// Le socket est lie a `0.0.0.0:0`, donc a un port ephemere, superieur a 443:
/// voir l'en-tete, un port source bas ferait ignorer la sonde par le censeur
/// qu'elle cherche a mesurer.
async fn emettre(cible: SocketAddr, datagramme: &[u8]) -> Tentative {
    let liaison = if cible.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let Ok(socket) = tokio::net::UdpSocket::bind(liaison).await else {
        return Tentative::Impossible;
    };
    if socket.connect(cible).await.is_err() {
        return Tentative::Impossible;
    }
    if socket.send(datagramme).await.is_err() {
        return Tentative::Impossible;
    }
    let mut tampon = [0u8; 2048];
    match tokio::time::timeout(DELAI, socket.recv(&mut tampon)).await {
        Ok(Ok(n)) => match lire_reponse(&tampon[..n]) {
            // Un datagramme qui ne ressemble pas a du QUIC ne prouve rien du
            // protocole: c'est du bruit, ou une reponse forgee.
            Some(Reponse::Inconnue) | None => Tentative::Expiree,
            Some(_) => Tentative::Aboutie,
        },
        // ICMP port unreachable remonte ici sous forme d'erreur de lecture.
        Ok(Err(_)) => Tentative::Refusee,
        Err(_) => Tentative::Expiree,
    }
}

/// Sonde une cible: negociation de version d'abord, Initial version 1 ensuite.
///
/// Dans cet ordre et jamais en parallele. Si un censeur devait reagir a
/// l'Initial par un blocage residuel sur le triplet, la negociation aurait deja
/// eu sa reponse; l'inverse perdrait les deux mesures d'un coup.
pub async fn sonder(
    cible: SocketAddr,
    nom_de_serveur: &str,
    alea: &[u8; OCTETS_D_ALEA],
) -> (Tentative, Tentative) {
    let mut numeros = Numeros {
        destination: [0u8; OCTETS_DE_NUMERO],
        source: [0u8; OCTETS_DE_NUMERO],
    };
    numeros
        .destination
        .copy_from_slice(&alea[96..96 + OCTETS_DE_NUMERO]);
    numeros
        .source
        .copy_from_slice(&alea[96 + OCTETS_DE_NUMERO..]);

    let negociation = emettre(cible, &paquet_negociation(&numeros)).await;
    let initial = emettre(cible, &paquet_initial(&numeros, nom_de_serveur, alea)).await;
    (negociation, initial)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let propre: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        (0..propre.len() / 2)
            .map(|i| u8::from_str_radix(&propre[i * 2..i * 2 + 2], 16).unwrap())
            .collect()
    }

    /// Les quatre `HkdfLabel` de l'annexe A.1 du RFC 9001, tels quels.
    ///
    /// Une erreur d'encodage ici donnerait des clefs coherentes avec
    /// elles-memes et fausses pour tout le monde. C'est le genre de defaut
    /// qu'aucun test contre soi-meme ne trouve.
    #[test]
    fn les_etiquettes_hkdf_sont_celles_du_rfc() {
        assert_eq!(
            etiquette_hkdf("client in", 32),
            hex("00200f746c73313320636c69656e7420696e00")
        );
        assert_eq!(
            etiquette_hkdf("server in", 32),
            hex("00200f746c7331332073657276657220696e00")
        );
        assert_eq!(
            etiquette_hkdf("quic key", 16),
            hex("00100e746c7331332071756963206b657900")
        );
        assert_eq!(
            etiquette_hkdf("quic iv", 12),
            hex("000c0d746c733133207175696320697600")
        );
        assert_eq!(
            etiquette_hkdf("quic hp", 16),
            hex("00100d746c733133207175696320687000")
        );
    }

    /// Les secrets du client pour le numero de connexion de l'annexe A.1.
    #[test]
    fn les_secrets_initiaux_sont_ceux_du_rfc() {
        let s = secrets_client(&hex("8394c8f03e515708"));
        assert_eq!(s.cle.to_vec(), hex("1f369613dd76d5467730efcbe3b1a22d"));
        assert_eq!(s.iv.to_vec(), hex("fa044b2f42a3fd3b46fb255c"));
        assert_eq!(s.hp.to_vec(), hex("9f50449e04a0e810283a1e9933adedd2"));
    }

    /// Le paquet protege de l'annexe A.2, octet pour octet.
    ///
    /// C'est la recette qui donne sa valeur a tout ce module. Elle confronte
    /// d'un coup la derivation, le nonce, la donnee associee, le chiffrement et
    /// la protection d'en-tete a une reference exterieure. Chacun de ces cinq
    /// points a une facon d'etre faux qui reste coherente avec les autres.
    #[test]
    fn un_initial_protege_reproduit_le_vecteur_du_rfc() {
        let charge_utile = hex(
            "060040f1010000ed0303ebf8fa56f129 39b9584a3896472ec40bb863cfd3e868
             04fe3a47f06a2b69484c000004130113 02010000c000000010000e00000b6578
             616d706c652e636f6dff01000100000a 00080006001d00170018001000070005
             04616c706e0005000501000000000033 00260024001d00209370b2c9caa47fba
             baf4559fedba753de171fa71f50f1ce1 5d43e994ec74d748002b000302030400
             0d0010000e0403050306030203080408 050806002d00020101001c0002400100
             3900320408ffffffffffffffff050480 00ffff07048000ffff08011001048000
             75300901100f088394c8f03e51570806 048000ffff",
        );
        // L'annexe annonce 1162 octets de trames: la trame CRYPTO ci-dessus,
        // puis du remplissage.
        let mut charge = charge_utile;
        charge.resize(1162, 0);

        let entete = hex("c300000001088394c8f03e5157080000449e00000002");
        let secrets = secrets_client(&hex("8394c8f03e515708"));
        let paquet = proteger(&entete, &charge, &secrets, 2);

        assert_eq!(
            &paquet[..22],
            &hex("c000000001088394c8f03e5157080000449e7b9aec34")[..],
            "l'en-tete protege ne reproduit pas celui du RFC"
        );
        assert_eq!(
            &paquet[22..38],
            &hex("d1b1c98dd7689fb8ec11d242b123dc9b")[..],
            "l'echantillon de protection d'en-tete differe de celui du RFC"
        );
        assert_eq!(paquet.len(), 1200, "le datagramme du RFC fait 1200 octets");
    }

    #[test]
    fn les_entiers_a_longueur_variable_suivent_le_rfc_9000() {
        // Section 16, exemples donnes par le RFC.
        assert_eq!(varint(37), hex("25"));
        assert_eq!(varint(15_293), hex("7bbd"));
        assert_eq!(varint(494_878_333), hex("9d7f3e7d"));
        assert_eq!(varint(151_288_809_941_952_652), hex("c2197c5eff14e88c"));
    }

    #[test]
    fn un_initial_fait_la_taille_minimale_du_datagramme() {
        let numeros = Numeros {
            destination: [1; OCTETS_DE_NUMERO],
            source: [2; OCTETS_DE_NUMERO],
        };
        let paquet = paquet_initial(&numeros, "exemple.test", &[7u8; OCTETS_D_ALEA]);
        assert_eq!(
            paquet.len(),
            TAILLE_DATAGRAMME,
            "un datagramme plus court est jete par le serveur, et la sonde ne mesurerait rien"
        );
    }

    /// Le SNI doit etre LISIBLE par un observateur qui derive les clefs, sans
    /// quoi la sonde ne mesure pas le filtrage qu'elle pretend mesurer.
    #[test]
    fn le_nom_de_serveur_est_dechiffrable_depuis_le_seul_paquet() {
        use aes_gcm::aead::Aead;

        let numeros = Numeros {
            destination: [9; OCTETS_DE_NUMERO],
            source: [3; OCTETS_DE_NUMERO],
        };
        let paquet = paquet_initial(&numeros, "exemple.test", &[5u8; OCTETS_D_ALEA]);
        let secrets = secrets_client(&numeros.destination);

        // Retrouver l'en-tete demande d'abord de defaire la protection, ce que
        // seul l'echantillon permet - et l'echantillon est en clair.
        let decalage_numero = 1 + 4 + 1 + 8 + 1 + 8 + 1 + 2;
        let mut echantillon = [0u8; 16];
        echantillon.copy_from_slice(&paquet[decalage_numero + 4..decalage_numero + 20]);
        let mut masque = aes::cipher::generic_array::GenericArray::from(echantillon);
        aes::Aes128::new_from_slice(&secrets.hp)
            .unwrap()
            .encrypt_block(&mut masque);

        let mut entete = paquet[..decalage_numero + 4].to_vec();
        entete[0] ^= masque[0] & 0x0f;
        for i in 0..4 {
            entete[decalage_numero + i] ^= masque[1 + i];
        }
        let numero = u32::from_be_bytes([
            entete[decalage_numero],
            entete[decalage_numero + 1],
            entete[decalage_numero + 2],
            entete[decalage_numero + 3],
        ]) as u64;

        let mut nonce = secrets.iv;
        let n = numero.to_be_bytes();
        for i in 0..8 {
            nonce[4 + i] ^= n[i];
        }
        let clair = aes_gcm::Aes128Gcm::new_from_slice(&secrets.cle)
            .unwrap()
            .decrypt(
                aes_gcm::Nonce::from_slice(&nonce),
                Payload {
                    msg: &paquet[decalage_numero + 4..],
                    aad: &entete,
                },
            )
            .expect("un observateur sur le chemin dechiffre l'Initial, et c'est le point");

        let motif = b"exemple.test";
        assert!(
            clair.windows(motif.len()).any(|f| f == motif),
            "le nom de serveur n'est pas lisible: la sonde ne serait pas inspectee"
        );
    }

    /// Les deux champs que la mesure a montres INUTILES au verdict, et qui
    /// doivent pourtant rester la.
    ///
    /// C'est exactement le genre de chose qu'un remaniement retire sans que
    /// rien ne rougisse: la sonde continuerait de conclure, et sur un reseau
    /// censeur elle conclurait FAUX. Le garde est ici parce que le reseau ne
    /// peut pas le poser.
    #[test]
    fn le_client_hello_reste_fidele_a_celui_d_un_vrai_client() {
        let poignee = client_hello(
            "exemple.test",
            &[8u8; OCTETS_DE_NUMERO],
            &[3u8; OCTETS_D_ALEA],
        );

        assert!(
            poignee.windows(2).any(|f| f == [0x00, 0x39]),
            "les parametres de transport ont disparu du ClientHello"
        );
        let alpn = [0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, b'h', b'3'];
        assert!(
            poignee.windows(alpn.len()).any(|f| f == alpn),
            "l'ALPN n'annonce plus h3"
        );
        // Le numero de source doit se retrouver dans les parametres: le serveur
        // le compare a l'en-tete, et un desaccord ferme la connexion.
        let source = [8u8; OCTETS_DE_NUMERO];
        assert!(
            poignee.windows(source.len()).any(|f| f == source),
            "initial_source_connection_id ne porte pas notre numero de source"
        );
    }

    #[test]
    fn une_negociation_ne_porte_aucun_nom_de_serveur() {
        let numeros = Numeros {
            destination: [4; OCTETS_DE_NUMERO],
            source: [6; OCTETS_DE_NUMERO],
        };
        let p = paquet_negociation(&numeros);
        assert_eq!(p.len(), TAILLE_DATAGRAMME);
        assert_eq!(
            u32::from_be_bytes([p[1], p[2], p[3], p[4]]),
            VERSION_RESERVEE
        );
        assert_eq!(
            VERSION_RESERVEE & 0x0f0f_0f0f,
            0x0a0a_0a0a,
            "la version doit suivre le motif 0x?a?a?a?a reserve par le RFC 9000"
        );
    }

    #[test]
    fn les_formes_de_reponse_se_lisent_sans_dechiffrer() {
        assert_eq!(
            lire_reponse(&hex("c000000000 04aabbccdd 00")),
            Some(Reponse::NegociationVersion)
        );
        assert_eq!(
            lire_reponse(&hex("c000000001 04aabbccdd 00")),
            Some(Reponse::EnteteLong { version: 1 })
        );
        assert_eq!(lire_reponse(&hex("40aabb")), Some(Reponse::EnteteCourt));
        assert_eq!(lire_reponse(&hex("c0aabb")), Some(Reponse::Inconnue));
        assert_eq!(lire_reponse(&[]), None);
    }

    #[test]
    fn deux_reponses_disent_que_quic_passe() {
        assert_eq!(
            conclure(Tentative::Aboutie, Tentative::Aboutie, Mesure::Vu(true)),
            Mesure::Vu(true)
        );
    }

    /// La ligne qui justifie le second paquet: sans lui, ce reseau passerait
    /// pour ouvert a QUIC alors qu'il en filtre le contenu.
    #[test]
    fn une_negociation_seule_ne_dit_pas_que_quic_passe() {
        assert_eq!(
            conclure(Tentative::Aboutie, Tentative::Expiree, Mesure::Vu(true)),
            Mesure::Vu(false)
        );
        assert!(contenu_filtre(Tentative::Aboutie, Tentative::Expiree));
    }

    #[test]
    fn deux_silences_sans_temoin_vivant_ne_concluent_rien() {
        assert_eq!(
            conclure(Tentative::Expiree, Tentative::Expiree, Mesure::Vu(false)),
            Mesure::NonMesure
        );
        assert_eq!(
            conclure(Tentative::Expiree, Tentative::Expiree, Mesure::NonMesure),
            Mesure::NonMesure
        );
        assert_eq!(
            conclure(Tentative::Expiree, Tentative::Expiree, Mesure::Vu(true)),
            Mesure::Vu(false)
        );
    }

    #[test]
    fn deux_tentatives_impossibles_ne_concluent_rien() {
        assert_eq!(
            conclure(
                Tentative::Impossible,
                Tentative::Impossible,
                Mesure::Vu(true)
            ),
            Mesure::NonMesure
        );
    }

    /// Une reponse a l'Initial tranche meme si la negociation s'est tue: on
    /// croit ce qui a repondu, jamais un silence.
    #[test]
    fn une_reponse_a_l_initial_suffit() {
        assert_eq!(
            conclure(Tentative::Expiree, Tentative::Aboutie, Mesure::Vu(true)),
            Mesure::Vu(true)
        );
        assert!(!contenu_filtre(Tentative::Expiree, Tentative::Aboutie));
    }

    /// Les deux entiers que la sonde QUIC doit a la RFC 9000.
    ///
    /// `VERSION_RESERVEE` et `OCTETS_DE_NUMERO` sont deja epingles par des
    /// recettes qui lisent les octets emis a la main. `VERSION_1` et
    /// `TAILLE_DATAGRAMME`, non: les recettes qui les mentionnent comparent le
    /// datagramme construit a la constante qui l'a construit.
    ///
    /// Mesure du 23 aout 2026 sur dev-windows: en decalant les deux, les 524
    /// recettes du binaire de bibliotheque restaient vertes. Une version
    /// autre que 1 ferait repondre une negociation de version la ou la sonde
    /// veut precisement etre INSPECTEE par le censeur, et un datagramme sous
    /// 1200 octets peut etre jete par le serveur sans un mot: dans les deux
    /// cas la sonde mesurerait autre chose que ce qu'elle annonce.
    ///
    /// RFC 9000: section 15 pour le numero de version 1, section 14.1 pour la
    /// taille minimale d'un datagramme portant un Initial.
    #[test]
    fn la_sonde_quic_porte_les_valeurs_de_la_rfc_9000() {
        assert_eq!(VERSION_1, 0x0000_0001, "QUIC version 1");
        assert_eq!(
            TAILLE_DATAGRAMME, 1200,
            "un Initial plus court peut etre jete sans reponse"
        );
        // La version reservee ne doit surtout pas etre la version 1: c'est
        // toute la difference entre << je veux etre inspecte >> et << je veux
        // une negociation >>.
        assert_ne!(VERSION_1, VERSION_RESERVEE);
    }
}
