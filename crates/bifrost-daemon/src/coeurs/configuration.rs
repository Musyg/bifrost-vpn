//! Generation des configurations des coeurs tiers.
//!
//! Les schemas sont ceux valides le 16 aout 2026 contre les vrais binaires,
//! sing-box 1.13.18 et Xray 26.3.27, par `sing-box check` et `xray run -test`.
//! Les deviner aurait ete une mauvaise idee: les deux ont deprecie des champs
//! recemment, et un champ obsolete produit un coeur qui refuse de demarrer
//! avec un message qui ne dit pas lequel.
//!
//! Le fichier produit contient le secret de l'API de controle. Il est donc
//! ecrit avec des droits restreints, et jamais dans un repertoire partage.

use std::path::Path;

use bifrost_core::profil::{self, Profil};
use serde_json::{Value, json};

/// Une sortie proposee au selecteur.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sortie {
    /// Sortie en clair, sans coeur. Sert de repli et de temoin: si le trafic
    /// passe aussi bien par elle, c'est que le tunnel n'y est pour rien.
    Directe { tag: String },
    /// VLESS + REALITY + XTLS-Vision, tel que decrit au document 04 partie 2.1.
    VlessReality(Box<Reality>),
    /// VLESS + TLS + WebSocket derriere un CDN, document 04 partie 2.2.
    ///
    /// Le repli du mode Discret. Il n'imite pas un site, il se fond dans le
    /// trafic d'un CDN - d'ou la seule propriete qui compte ici et que REALITY
    /// n'a pas: il survit a une interception TLS d'entreprise, puisque le CDN
    /// termine deja le TLS pour tout le monde.
    VlessWebsocket(Box<SurHttp>),
    /// Le meme derriere un front auto-heberge, ou l'upgrade est relaye sans
    /// etre valide. Ne traverse PAS un CDN: voir `bifrost_evasion::Technique`.
    VlessHttpUpgrade(Box<SurHttp>),
    /// Hysteria2 sur QUIC, document 04 partie 2.3. Sa raison d'etre est le
    /// reseau qui perd des paquets: son controle de congestion tient la ou TCP
    /// s'effondre. Il ne survit evidemment pas a un blocage de l'UDP.
    Hysteria2(Box<Hysteria2>),
}

/// VLESS + TLS encadre par du HTTP. Une structure pour les deux transports:
/// ils portent les memes champs et ne different que sur le fil.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SurHttp {
    pub tag: String,
    pub serveur: String,
    pub port: u16,
    pub uuid: String,
    /// SNI presentee. Ici elle designe bien l'hote joint, contrairement a
    /// REALITY ou elle nomme le site emprunte.
    pub nom_de_serveur: String,
    /// En-tete `Host` de la requete d'upgrade. Le CDN route dessus.
    pub hote: String,
    pub chemin: String,
}

/// Comment le certificat du serveur est valide.
///
/// Il n'existe volontairement AUCUNE variante "ne pas verifier". sing-box
/// accepte un `insecure: true` que tous les tutoriels recopient pour faire
/// marcher un certificat auto-signe; l'admettre ici ferait passer la recette
/// avec un tunnel non authentifie, donc lui ferait prouver le contraire de ce
/// qu'elle annonce. Un certificat auto-signe s'epingle, il ne s'ignore pas.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Confiance {
    /// Certificat du serveur, en PEM, ligne par ligne.
    Epingle(Vec<String>),
    /// Autorites de certification du systeme, pour un serveur qui a un vrai
    /// certificat.
    AutoritesDuSysteme,
}

/// Parametres d'une sortie Hysteria2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hysteria2 {
    pub tag: String,
    pub serveur: String,
    pub port: u16,
    pub mot_de_passe: String,
    /// Mot de passe d'obfuscation Salamander. `None` laisse le QUIC nu, donc
    /// reconnaissable a sa poignee de main: c'est un choix, pas un defaut.
    pub obfs: Option<String>,
    /// SNI presentee au serveur.
    pub nom_de_serveur: String,
    pub confiance: Confiance,
}

/// Parametres d'une sortie REALITY.
///
/// `cle_publique` porte ce que Xray 26.x nomme "Password (PublicKey)" dans la
/// sortie de `xray x25519`. Le nom a change en amont; la valeur, non.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reality {
    pub tag: String,
    pub serveur: String,
    pub port: u16,
    pub uuid: String,
    pub cle_publique: String,
    pub short_id: String,
    /// SNI presentee, qui doit etre celle du site emprunte cote serveur.
    ///
    /// Le choix du site emprunte n'est pas une question de gout: le serveur
    /// REALITY rejoue vers le client la poignee de main TLS qu'il vole a ce
    /// site, et si la chaine de certificats de celui-ci ne tient pas dans le
    /// tampon prevu, la poignee ne se termine jamais. Mesure le 16/08/2026
    /// contre Xray 26.3.27: `dl.google.com`, `www.cloudflare.com` et
    /// `addons.mozilla.org` passent; `www.microsoft.com` echoue, son
    /// enregistrement Certificate faisant 8273 octets pour 4282 disponibles.
    /// Le symptome cote client est un `EOF` muet, sans rapport apparent avec
    /// la cause: d'ou cette note plutot qu'un simple exemple.
    ///
    /// `--qualifier-dest <hotes>` mesure un candidat avant qu'on l'adopte. Il
    /// ne le compare PAS aux 8273 ci-dessus, qui sont la grandeur vue par Xray
    /// et qu'aucun client ne peut observer, mais a un site de reference mesure
    /// dans le meme passage. Voir [`crate::tls`].
    pub nom_de_serveur: String,
}

/// L'agent annonce par les transports HTTP.
///
/// Il ne trompe pas un censeur - il est chiffre - mais il evite d'annoncer un
/// client Go au CDN et a l'origine, qui eux le lisent en clair.
const NAVIGATEUR: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)      Chrome/139.0.0.0 Safari/537.36";

impl Sortie {
    pub fn tag(&self) -> &str {
        match self {
            Sortie::Directe { tag } => tag,
            Sortie::VlessReality(r) => &r.tag,
            Sortie::VlessWebsocket(h) | Sortie::VlessHttpUpgrade(h) => &h.tag,
            Sortie::Hysteria2(h) => &h.tag,
        }
    }

    /// Forme sing-box de la sortie.
    fn en_json(&self) -> Value {
        match self {
            Sortie::Directe { tag } => json!({ "type": "direct", "tag": tag }),
            Sortie::VlessReality(r) => json!({
                "type": "vless",
                "tag": r.tag,
                "server": r.serveur,
                "server_port": r.port,
                "uuid": r.uuid,
                "flow": "xtls-rprx-vision",
                "tls": {
                    "enabled": true,
                    "server_name": r.nom_de_serveur,
                    // uTLS n'est pas decoratif: sans lui, l'empreinte TLS du
                    // client le distingue d'un navigateur, ce que le document
                    // 04 releve comme reellement exploite cote censeur.
                    "utls": { "enabled": true, "fingerprint": "chrome" },
                    "reality": {
                        "enabled": true,
                        "public_key": r.cle_publique,
                        "short_id": r.short_id,
                    }
                }
            }),
            // Aucun `flow` ici, et ce n'est pas un oubli: XTLS-Vision ne
            // s'applique qu'a un transport TCP nu, le document 04 partie 2.1 le
            // donnant "incompatible avec WebSocket/gRPC/XHTTP". L'ecrire
            // produirait une configuration que le coeur refuse au demarrage, et
            // le symptome - un coeur qui ne demarre pas - n'aurait aucun
            // rapport visible avec la cause.
            //
            // La forme du bloc `transport` est relevee le 21 aout 2026 dans
            // `option/v2ray_transport.go` de sing-box v1.13.18, la version que
            // ce depot execute: `V2RayHTTPUpgradeOptions { host, path, headers }`,
            // sous le nom de type de la constante `httpupgrade`.
            Sortie::VlessWebsocket(h) => json!({
                "type": "vless",
                "tag": h.tag,
                "server": h.serveur,
                "server_port": h.port,
                "uuid": h.uuid,
                "tls": {
                    "enabled": true,
                    "server_name": h.nom_de_serveur,
                    "utls": { "enabled": true, "fingerprint": "chrome" },
                },
                // `ws` n'a pas de champ `host`, contrairement a `httpupgrade`:
                // releve dans `option/v2ray_transport.go` de sing-box v1.13.18,
                // ou `V2RayWebsocketOptions` porte `path`, `headers`,
                // `max_early_data` et `early_data_header_name`, rien d'autre.
                // Le client LIT un `Host` dans les en-tetes, le retire, et
                // s'en sert comme hote de la requete
                // (`transport/v2raywebsocket/client.go`). C'est donc la, et
                // seulement la, qu'un hote distinct de la SNI se pose.
                //
                // L'agent est ecrit parce que sing-box met sinon
                // `Go-http-client/1.1`, ce qu'aucun navigateur n'envoie. Il
                // voyage a l'interieur du TLS, donc il ne dit rien a un censeur
                // sur le chemin - mais le CDN et l'origine le voient, et se
                // fondre dans du trafic web ordinaire commence par ne pas
                // s'annoncer comme un client Go.
                "transport": {
                    "type": "ws",
                    "path": h.chemin,
                    "headers": {
                        "Host": h.hote,
                        "User-Agent": NAVIGATEUR,
                    },
                }
            }),
            Sortie::VlessHttpUpgrade(h) => json!({
                "type": "vless",
                "tag": h.tag,
                "server": h.serveur,
                "server_port": h.port,
                "uuid": h.uuid,
                "tls": {
                    "enabled": true,
                    "server_name": h.nom_de_serveur,
                    "utls": { "enabled": true, "fingerprint": "chrome" },
                },
                "transport": {
                    "type": "httpupgrade",
                    "host": h.hote,
                    "path": h.chemin,
                }
            }),
            Sortie::Hysteria2(h) => {
                let mut tls = json!({
                    "enabled": true,
                    "server_name": h.nom_de_serveur,
                });
                if let Confiance::Epingle(pem) = &h.confiance {
                    tls["certificate"] = json!(pem);
                }
                // Aucun reglage de taille de paquet QUIC ici, et ce n'est pas
                // un oubli: sing-box 1.13.18 refuse `initial_packet_size` et
                // hysteria n'expose pas son equivalent cote serveur. Les deux
                // bouts emettent donc les 1280 octets par defaut de quic-go,
                // qui ne passent pas un chemin a 1280 de MTU. C'est la sonde
                // `sondes::sonder_chemin_quic` qui mesure le chemin AVANT
                // d'essayer, plutot que ce module qui promettrait un reglage
                // que le binaire n'accepte pas.
                let mut sortie = json!({
                    "type": "hysteria2",
                    "tag": h.tag,
                    "server": h.serveur,
                    "server_port": h.port,
                    "password": h.mot_de_passe,
                    "tls": tls,
                });
                // Ni `up_mbps` ni `down_mbps`: les renseigner bascule sur le
                // controle de congestion Brutal, qui envoie au debit annonce
                // sans ecouter le reseau. Une valeur trop haute recopiee d'un
                // exemple degrade la ligne de tout le monde. Sans eux,
                // sing-box utilise BBR.
                if let Some(mdp) = &h.obfs {
                    sortie["obfs"] = json!({ "type": "salamander", "password": mdp });
                }
                sortie
            }
        }
    }
}

impl Sortie {
    /// Traduit un profil en sortie.
    ///
    /// Infaillible, et c'est tout l'interet: ce qui pouvait etre refuse l'a ete
    /// a la porte, quand le profil s'est construit depuis son lien. Un profil
    /// qui existe decrit forcement une sortie que ce module sait ecrire.
    ///
    /// **Le `tag` est donne, pas derive de l'etiquette.** sing-box exige des
    /// etiquettes de sortie uniques dans une meme configuration, et deux
    /// profils peuvent tres bien porter le meme libelle - "Suisse", "Rapide".
    /// Seul celui qui tient la liste entiere peut garantir l'unicite; la
    /// deriver ici, profil par profil, produirait des doublons qu'aucun des
    /// deux appels ne pourrait voir. Le tag voyage ensuite dans le CORPS JSON
    /// de la requete qui bascule le selecteur, jamais dans son chemin, donc sa
    /// forme n'a pas a etre contrainte au-dela de cela.
    ///
    /// **La confiance est celle des autorites du systeme**, et c'est la seule
    /// qu'un lien sache exprimer: `pinSHA256` y est refuse faute de pouvoir
    /// etre honore sous cette forme, et `insecure` par principe. Un serveur a
    /// certificat auto-signe reste donc joignable - la recette `--coeur-e2e` le
    /// fait - mais par un profil construit autrement que depuis un lien.
    pub fn depuis_profil(profil: &Profil, tag: impl Into<String>) -> Self {
        let tag = tag.into();
        match &profil.transport {
            profil::Transport::VlessReality(v) => Sortie::VlessReality(Box::new(Reality {
                tag,
                serveur: v.serveur.clone(),
                port: v.port,
                uuid: v.uuid.as_str().to_owned(),
                cle_publique: v.cle_publique.as_str().to_owned(),
                short_id: v.short_id.as_str().to_owned(),
                nom_de_serveur: v.nom_de_serveur.clone(),
            })),
            profil::Transport::VlessWebsocket(v) => Sortie::VlessWebsocket(Box::new(SurHttp {
                tag,
                serveur: v.serveur.clone(),
                port: v.port,
                uuid: v.uuid.as_str().to_owned(),
                nom_de_serveur: v.nom_de_serveur.clone(),
                hote: v.hote.clone(),
                chemin: v.chemin.clone(),
            })),
            profil::Transport::VlessHttpUpgrade(v) => Sortie::VlessHttpUpgrade(Box::new(SurHttp {
                tag,
                serveur: v.serveur.clone(),
                port: v.port,
                uuid: v.uuid.as_str().to_owned(),
                nom_de_serveur: v.nom_de_serveur.clone(),
                hote: v.hote.clone(),
                chemin: v.chemin.clone(),
            })),
            profil::Transport::Hysteria2(h) => Sortie::Hysteria2(Box::new(Hysteria2 {
                tag,
                serveur: h.serveur.clone(),
                port: h.port,
                mot_de_passe: h.mot_de_passe.as_str().to_owned(),
                obfs: h.obfs.as_ref().map(|m| m.as_str().to_owned()),
                nom_de_serveur: h.nom_de_serveur.clone(),
                confiance: match &h.certificat {
                    Some(pem) => Confiance::Epingle(pem.lignes()),
                    None => Confiance::AutoritesDuSysteme,
                },
            })),
        }
    }
}

/// Ce qu'il faut savoir pour engendrer une configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parametres {
    /// Port SOCKS local par lequel le trafic entrera dans le coeur.
    pub socks: u16,
    /// Port de l'API Clash. Ignore par les coeurs qui n'en ont pas.
    pub api: u16,
    /// Secret de l'API Clash.
    pub secret: String,
    /// Ce que le coeur exigera de quiconque se presente a son entree SOCKS.
    ///
    /// Sans eux, l'entree accepte n'importe quel processus de la machine: la
    /// boucle locale n'est pas une frontiere. Voir [`super::socks::Identifiants`]
    /// pour la mesure qui l'a etabli.
    pub identifiants: super::socks::Identifiants,
    /// Nom du selecteur pilote a chaud.
    pub selecteur: String,
    /// Sorties proposees au selecteur, dans l'ordre. La premiere est le defaut.
    pub sorties: Vec<String>,
    /// L'interface a laquelle le coeur doit lier sa propre sortie.
    ///
    /// # Ce que cela empeche
    ///
    /// Quand le chemin par coeur est monte, la route par defaut entre dans le
    /// TUN. Le trafic du coeur y entre alors AUSSI, et il boucle: le coeur
    /// essaie de joindre son serveur, ses paquets repassent par le TUN, le
    /// passeur les lui redonne, sans fin.
    ///
    /// # Pourquoi ce n'est pas au meme endroit que sous Linux
    ///
    /// Sous Linux l'echappement est dans la table de routage, par IDENTITE:
    /// `ip rule uidrange` envoie ce qui vient du compte du coeur dans la table
    /// `main`. Windows ne sait pas router par processus - sa table de routage ne
    /// connait que des destinations - et la seule facon d'y router par processus
    /// serait un pilote de rappel WFP en mode noyau, que le document 06 ecarte
    /// explicitement.
    ///
    /// L'echappement DEMENAGE donc: de la table de routage vers la
    /// configuration du coeur, qui est engendree ici. Les deux coeurs exposent
    /// de quoi lier leur sortie a une interface - `bind_interface` pour
    /// sing-box, `sockopt.interface` pour Xray, tous deux documentes pour
    /// Windows - ce qui pose `IP_UNICAST_IF` sur la socket sortante et fait
    /// sortir par cette interface QUELLE QUE SOIT la table de routage.
    ///
    /// La propriete reste la meme des deux cotes, et elle reste celle que le
    /// plan demandait: l'echappement se decide sur la SOCKET du coeur, pas sur
    /// une adresse de destination. Le document 02 partie 8 disait "pas par IP",
    /// et ce n'est toujours pas par IP.
    ///
    /// # Ce que cela coute
    ///
    /// Le nom est fige au lancement du coeur. Si la machine change de lien -
    /// Wi-Fi a la place du cable - la liaison devient caduque et le coeur ne
    /// joint plus rien. C'est un echec FERME: aucun trafic ne sort par une porte
    /// qu'on ne voulait pas, le tunnel cesse simplement de fonctionner. Dans ce
    /// sens-la, c'est la bonne direction pour un produit de securite.
    ///
    /// `None` sous Linux, ou c'est le routage qui s'en charge.
    pub lier_a: Option<String>,
}

/// L'API de controle n'ecoute JAMAIS ailleurs que sur la boucle locale.
///
/// Un `0.0.0.0` ici donnerait a tout le reseau le droit de choisir par ou sort
/// le trafic du poste. C'est le genre de valeur qu'on copie d'un exemple sans
/// y penser, d'ou la constante et le test qui la garde.
pub const ECOUTE_LOCALE: &str = "127.0.0.1";

/// Configuration sing-box: un SOCKS en entree, un selecteur en sortie, et
/// l'API Clash par laquelle on le pilote.
///
/// Les deux sorties sont `direct` et se distinguent par leur seule etiquette.
/// C'est voulu pour la recette: ce qu'on verifie est que la BASCULE prend, pas
/// que le trafic change de chemin. Les vrais profils remplaceront ces sorties
/// par des VLESS et des Hysteria2.
pub fn sing_box(p: &Parametres) -> Value {
    sing_box_avec(
        p,
        &p.sorties
            .iter()
            .map(|tag| Sortie::Directe { tag: tag.clone() })
            .collect::<Vec<_>>(),
    )
}

/// Comme [`sing_box`], mais avec des sorties decrites une a une.
///
/// C'est la forme qui sert aux vrais profils; `sing_box` n'en est que le cas
/// ou toutes les sorties sont directes.
pub fn sing_box_avec(p: &Parametres, sorties: &[Sortie]) -> Value {
    let etiquettes: Vec<&str> = sorties.iter().map(|s| s.tag()).collect();
    let mut outbounds: Vec<Value> = sorties.iter().map(Sortie::en_json).collect();

    // Sur chaque sortie qui COMPOSE reellement, et pas sur le selecteur: c'est
    // la sortie qui ouvre la socket, le selecteur ne fait que designer laquelle.
    //
    // Et non `route.auto_detect_interface`, que sing-box offre pour ce cas: il
    // lie a l'interface par defaut du moment, or ici le TUN ne lui appartient
    // pas - il le verrait comme une interface ordinaire, et pourrait choisir
    // celle-la meme dont on veut sortir. Nommer l'interface retire la question.
    if let Some(nic) = &p.lier_a {
        for sortie in &mut outbounds {
            sortie["bind_interface"] = json!(nic);
        }
    }
    outbounds.push(json!({
        "type": "selector",
        "tag": p.selecteur,
        "outbounds": etiquettes,
        "default": etiquettes.first(),
        // # Pourquoi VRAI ici, alors que le document 04 partie 3.3 le met a
        //   faux dans son exemple
        //
        // Parce que son exemple le pose sur l'`urltest`, et que les deux ne
        // basculent pas pour la meme raison. Un `urltest` bascule sur une
        // PREFERENCE - une sortie repond cinquante millisecondes plus vite -
        // et couper des connexions saines pour une preference est destructeur.
        // Ce selecteur-ci ne bascule que sur un VERDICT: le superviseur a
        // mesure un gel a 16 Ko ou un debit effondre sur dix secondes, et il a
        // conclu que la sortie courante ne passe plus.
        //
        // Ce que dit la documentation amont, verbatim (verifie le 20 aout
        // 2026): "Interrupt existing connections when the selected outbound
        // has changed. Only inbound connections are affected by this setting,
        // internal connections will always be interrupted."
        //
        // # Ce que FAUX couterait, et ce n'est pas ce qu'on croit
        //
        // Une connexion TCP etablie a travers la sortie A ne peut pas etre
        // deplacee vers B: son etat cryptographique vit dans A. Les laisser
        // vivre ne les sauve donc pas, cela les fait PENDRE jusqu'a
        // l'echeance de l'application, au lieu de lui rendre une erreur
        // qu'elle sait retenter - et la retentative, elle, passerait par le
        // nouveau candidat.
        //
        // Pire, et c'est l'argument decisif: notre observation lit les
        // compteurs du TUN, qui AGREGENT toutes les connexions. Des connexions
        // gelees laissees en place continueraient de tirer la moyenne vers le
        // bas, et l'observateur conclurait que le nouveau candidat gele aussi.
        // On eliminerait au carnet une technique qui n'a jamais eu sa chance,
        // et de proche en proche toute la liste.
        //
        // Et un troisieme argument, celui du terrain. Le gel decrit par
        // net4people/bbs#490 (ouvert le 27 juin 2025) porte sur UNE CONNEXION
        // TCP a la fois: passe ~15-20 Ko recus du serveur, les paquets cessent
        // d'arriver POUR CETTE CONNEXION-LA. Une connexion ainsi gelee ne se
        // retablit jamais, quoi qu'on fasse du selecteur. La laisser ouverte
        // n'est donc pas prudent, c'est garder un mort au chaud.
        //
        // L'etat applicatif que la partie 3.2 demande de garder n'est pas la
        // liste des sockets: c'est le SOCKS local qui ne bouge pas, le TUN qui
        // reste monte et le kill switch qui n'est jamais leve. Les trois sont
        // vrais ici, precisement parce qu'on ne relance rien.
        "interrupt_exist_connections": true,
    }));

    json!({
        "log": { "level": "warn", "timestamp": false },
        "inbounds": [{
            "type": "socks",
            "tag": "entree",
            "listen": ECOUTE_LOCALE,
            "listen_port": p.socks,
            // Sans `users`, sing-box n'exige rien: sa documentation le dit
            // mot pour mot, "No authentication required if empty" (consultee
            // le 20 aout 2026). L'entree serait alors ouverte a tout processus
            // de la machine.
            "users": [{
                "username": p.identifiants.utilisateur(),
                "password": p.identifiants.mot_de_passe(),
            }],
        }],
        "outbounds": outbounds,
        "route": { "final": p.selecteur },
        // Sans `store_selected`, que le document 04 partie 3.3 mentionne
        // pourtant. Il ferait garder au coeur, dans un cache a lui, le dernier
        // choix de selecteur - donc une SECONDE memoire a cote du carnet, que
        // rien ne synchronise et que personne ne relit. Un coeur qui redemarre
        // reprendrait alors une technique que la selection n'a pas retenue, et
        // le desaccord ne se verrait nulle part. La memoire de ce produit est
        // le carnet, et elle est une.
        "experimental": {
            "clash_api": {
                "external_controller": format!("{ECOUTE_LOCALE}:{}", p.api),
                "secret": p.secret,
            }
        }
    })
}

/// Configuration Xray: un SOCKS en entree, une sortie directe.
///
/// Aucune API de controle: Xray n'expose pas l'API Clash, il a son propre
/// mecanisme d'observatoire et d'equilibrage. Le secret n'apparait donc pas
/// dans ce fichier, et le lui passer serait une fuite gratuite.
pub fn xray(p: &Parametres) -> Value {
    let mut sortie = json!({ "tag": "sortie", "protocol": "freedom", "settings": {} });
    // Xray nomme la meme chose autrement: `sockopt.interface`, documente comme
    // n'ayant de sens que sous Linux et Windows - les deux ou il pose
    // `SO_BINDTODEVICE` et `IP_UNICAST_IF`. Voir [`Parametres::lier_a`].
    if let Some(nic) = &p.lier_a {
        sortie["streamSettings"] = json!({ "sockopt": { "interface": nic } });
    }

    json!({
        "log": { "loglevel": "warning" },
        "inbounds": [{
            "tag": "entree",
            "listen": ECOUTE_LOCALE,
            "port": p.socks,
            "protocol": "socks",
            // Xray nomme la meme chose autrement, et `users` n'a d'effet que
            // si `auth` vaut "password" (documentation XTLS consultee le
            // 20 aout 2026). Poser l'un sans l'autre laisserait l'entree
            // ouverte en croyant l'avoir fermee.
            "settings": {
                "auth": "password",
                "users": [{
                    "user": p.identifiants.utilisateur(),
                    "pass": p.identifiants.mot_de_passe(),
                }],
                "udp": false,
            },
        }],
        "outbounds": [sortie]
    })
}

/// Ecrit une configuration avec des droits restreints.
///
/// Le fichier de sing-box porte le secret de l'API de controle: le laisser
/// lisible par tous rendrait inutile le fait d'avoir un secret.
pub fn ecrire(chemin: &Path, valeur: &Value) -> anyhow::Result<()> {
    if let Some(parent) = chemin.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let texte = serde_json::to_string_pretty(valeur)?;
    std::fs::write(chemin, texte)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(chemin, std::fs::Permissions::from_mode(0o600))?;
    }
    // Sous Windows, le fichier herite de l'ACL de son repertoire. Le
    // superviseur ecrit sous %ProgramData%\Bifrost, dont l'ACL est posee a
    // l'installation. Ce n'est pas equivalent a un 0600 pose ici, et c'est
    // note comme tel plutot que passe sous silence.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parametres() -> Parametres {
        Parametres {
            socks: 21080,
            api: 29090,
            secret: "un-secret".into(),
            identifiants: super::super::socks::Identifiants::nouveaux("bifrost", "un-mot-de-passe")
                .unwrap(),
            selecteur: "select".into(),
            sorties: vec!["sortie-a".into(), "sortie-b".into()],
            lier_a: None,
        }
    }

    /// Ce que mesure ce test n'est pas une preference de configuration, c'est
    /// un trou mesure sur le banc le 20 aout 2026: un processus tiers de la
    /// machine, ni le passeur ni le coeur, s'est connecte a l'entree SOCKS
    /// sans rien presenter et est ressorti par le tunnel. La boucle locale
    /// n'authentifie personne, et l'entree du coeur est la seule frontiere.
    #[test]
    fn l_entree_du_coeur_exige_des_identifiants() {
        let p = parametres();
        let c = sing_box(&p);
        let entree = &c["inbounds"][0];
        assert_eq!(entree["type"], "socks");
        let comptes = entree["users"]
            .as_array()
            .expect("sing-box n'exige rien sans `users`");
        assert_eq!(comptes.len(), 1);
        assert_eq!(comptes[0]["username"], p.identifiants.utilisateur());
        assert_eq!(comptes[0]["password"], p.identifiants.mot_de_passe());
    }

    #[test]
    fn l_entree_du_coeur_xray_exige_des_identifiants() {
        let p = parametres();
        let c = xray(&p);
        let entree = &c["inbounds"][0];
        assert_eq!(entree["protocol"], "socks");
        // Les deux vont ensemble: `users` seul, avec `auth` reste a "noauth",
        // laisserait l'entree ouverte tout en donnant l'apparence du contraire.
        assert_eq!(entree["settings"]["auth"], "password");
        let comptes = entree["settings"]["users"].as_array().unwrap();
        assert_eq!(comptes.len(), 1);
        assert_eq!(comptes[0]["user"], p.identifiants.utilisateur());
        assert_eq!(comptes[0]["pass"], p.identifiants.mot_de_passe());
    }

    /// Garde de portee: les deux tests ci-dessus nomment l'entree par son
    /// indice. Celui-ci ne nomme rien et parcourt tout ce qui sort d'ici, pour
    /// qu'une entree ajoutee plus tard ne puisse pas etre laissee ouverte sans
    /// que le fichier proteste.
    #[test]
    fn aucune_entree_engendree_n_est_laissee_ouverte() {
        let p = parametres();
        for (nom, c) in [("sing-box", sing_box(&p)), ("xray", xray(&p))] {
            for entree in c["inbounds"].as_array().unwrap() {
                let comptes = entree["users"]
                    .as_array()
                    .or_else(|| entree["settings"]["users"].as_array());
                let comptes =
                    comptes.unwrap_or_else(|| panic!("{nom}: une entree sans identifiants"));
                assert!(!comptes.is_empty(), "{nom}: une liste de comptes vide");
            }
            let texte = serde_json::to_string(&c).unwrap();
            assert!(!texte.contains("noauth"), "{nom}: il reste un \"noauth\"");
        }
    }

    #[test]
    fn l_api_de_controle_n_ecoute_que_sur_la_boucle_locale() {
        // Le piege le plus couteux du fichier: un 0.0.0.0 recopie d'un exemple
        // donnerait a tout le reseau le droit de choisir la sortie du VPN.
        let c = sing_box(&parametres());
        let ecoute = c["experimental"]["clash_api"]["external_controller"]
            .as_str()
            .unwrap();
        assert!(ecoute.starts_with("127.0.0.1:"), "ecoute large: {ecoute}");
        assert!(!ecoute.starts_with("0.0.0.0"));
        assert_eq!(c["inbounds"][0]["listen"], ECOUTE_LOCALE);
    }

    /// Les valeurs sont des valeurs de DOCUMENTATION, comme `192.0.2.10`.
    /// Un UUID VLESS authentifie son porteur: recopier ici celui d'un serveur
    /// reel, meme jetable, reviendrait a le publier avec le depot.
    fn reality() -> Sortie {
        Sortie::VlessReality(Box::new(Reality {
            tag: "reality".into(),
            serveur: "192.0.2.10".into(),
            port: 44343,
            uuid: "00000000-0000-4000-8000-000000000000".into(),
            cle_publique: "PUBLIQUE-DE-DOCUMENTATION-PAS-UNE-VRAIE-CLE".into(),
            short_id: "0000000000000000".into(),
            nom_de_serveur: "dl.google.com".into(),
        }))
    }

    fn sur_http() -> Box<SurHttp> {
        Box::new(SurHttp {
            tag: "repli-cdn".into(),
            serveur: "cdn.exemple.test".into(),
            port: 443,
            uuid: "00000000-0000-4000-8000-000000000000".into(),
            nom_de_serveur: "cdn.exemple.test".into(),
            hote: "cdn.exemple.test".into(),
            chemin: "/w1s2x3".into(),
        })
    }

    fn httpupgrade() -> Sortie {
        Sortie::VlessHttpUpgrade(sur_http())
    }

    fn websocket() -> Sortie {
        Sortie::VlessWebsocket(sur_http())
    }

    /// La forme exacte que sing-box attend, relevee le 21 aout 2026 dans
    /// `option/v2ray_transport.go` et `constant/v2ray.go` de la version
    /// v1.13.18 - celle que ce depot execute, pas la derniere en date.
    /// `V2RayHTTPUpgradeOptions` y porte `host`, `path` et `headers`; le nom du
    /// type est la constante `httpupgrade`.
    #[test]
    fn la_sortie_httpupgrade_porte_la_forme_que_sing_box_attend() {
        let c = sing_box_avec(&parametres(), &[httpupgrade()]);
        let o = &c["outbounds"][0];
        assert_eq!(o["type"], "vless");
        assert_eq!(o["server"], "cdn.exemple.test");
        assert_eq!(o["server_port"], 443);
        assert_eq!(o["transport"]["type"], "httpupgrade");
        assert_eq!(o["transport"]["host"], "cdn.exemple.test");
        assert_eq!(o["transport"]["path"], "/w1s2x3");
        assert_eq!(o["tls"]["enabled"], true);
        assert_eq!(o["tls"]["server_name"], "cdn.exemple.test");
        assert_eq!(o["tls"]["utls"]["fingerprint"], "chrome");
    }

    /// XTLS-Vision ne s'applique qu'a un transport TCP nu.
    ///
    /// Le document 04 partie 2.1: "incompatible avec WebSocket/gRPC/XHTTP".
    /// L'ecrire ici produirait une configuration que le coeur rejette au
    /// demarrage, et le symptome - un coeur qui ne demarre pas - n'aurait aucun
    /// rapport visible avec la cause.
    #[test]
    fn la_sortie_httpupgrade_ne_porte_aucun_flow() {
        let c = sing_box_avec(&parametres(), &[httpupgrade()]);
        assert!(
            c["outbounds"][0]["flow"].is_null(),
            "le flow Vision ne doit pas etre ecrit sur un transport HTTP"
        );
    }

    /// La forme exacte de `ws`, relevee le 21 aout 2026 dans
    /// `option/v2ray_transport.go` de sing-box v1.13.18.
    ///
    /// `V2RayWebsocketOptions` porte `path`, `headers`, `max_early_data` et
    /// `early_data_header_name` - et PAS de champ `host`, contrairement a
    /// `httpupgrade`. L'hote passe donc par les en-tetes, ou le client le lit,
    /// le retire, et s'en sert comme hote de la requete.
    #[test]
    fn la_sortie_websocket_porte_la_forme_que_sing_box_attend() {
        let c = sing_box_avec(&parametres(), &[websocket()]);
        let o = &c["outbounds"][0];
        assert_eq!(o["type"], "vless");
        assert_eq!(o["transport"]["type"], "ws");
        assert_eq!(o["transport"]["path"], "/w1s2x3");
        assert_eq!(o["transport"]["headers"]["Host"], "cdn.exemple.test");
        assert!(
            o["transport"]["host"].is_null(),
            "`ws` n'a pas de champ `host`: l'ecrire ferait refuser la configuration"
        );
        assert_eq!(o["tls"]["enabled"], true);
        assert_eq!(o["tls"]["utls"]["fingerprint"], "chrome");
        assert!(o["flow"].is_null(), "pas de Vision sur un transport HTTP");
    }

    /// Les deux transports HTTP ne s'ecrivent pas pareil, et c'est tout
    /// l'interet de les distinguer.
    ///
    /// Mesure du 21 aout 2026 a travers un edge Cloudflare: `ws` passe,
    /// `httpupgrade` recoit un 400 qui n'atteint jamais l'origine. Un
    /// generateur qui rendrait le meme JSON pour les deux rendrait le repli CDN
    /// inutilisable sans que rien ne le signale.
    #[test]
    fn les_deux_transports_sur_http_ne_produisent_pas_le_meme_json() {
        let ws = sing_box_avec(&parametres(), &[websocket()]);
        let hu = sing_box_avec(&parametres(), &[httpupgrade()]);
        assert_eq!(ws["outbounds"][0]["transport"]["type"], "ws");
        assert_eq!(hu["outbounds"][0]["transport"]["type"], "httpupgrade");
        assert_ne!(
            ws["outbounds"][0]["transport"],
            hu["outbounds"][0]["transport"]
        );
    }

    /// L'agent annonce n'est pas celui d'un client Go.
    ///
    /// sing-box met `Go-http-client/1.1` par defaut. Il voyage chiffre, donc il
    /// ne dit rien a un censeur sur le chemin - mais le CDN et l'origine le
    /// lisent en clair, et se fondre dans du trafic web ordinaire commence par
    /// ne pas s'annoncer comme un client Go.
    #[test]
    fn l_agent_annonce_n_est_pas_celui_d_un_client_go() {
        let c = sing_box_avec(&parametres(), &[websocket()]);
        let agent = c["outbounds"][0]["transport"]["headers"]["User-Agent"]
            .as_str()
            .expect("un agent doit etre ecrit");
        assert!(!agent.contains("Go-http-client"), "agent: {agent}");
        assert!(agent.contains("Mozilla/5.0"), "agent: {agent}");
    }

    /// Et le controle qui donne son sens au precedent: REALITY, lui, le porte.
    #[test]
    fn la_sortie_reality_porte_bien_le_flow() {
        let c = sing_box_avec(&parametres(), &[reality()]);
        assert_eq!(c["outbounds"][0]["flow"], "xtls-rprx-vision");
    }

    /// Aucune trace de REALITY sur le repli: pas de cle publique, pas de short
    /// id. Une recette qui ne regarderait que les champs presents laisserait
    /// passer un generateur qui recopie ceux de la sortie voisine.
    #[test]
    fn la_sortie_httpupgrade_ne_porte_rien_de_reality() {
        let c = sing_box_avec(&parametres(), &[httpupgrade()]);
        assert!(c["outbounds"][0]["tls"]["reality"].is_null());
    }

    #[test]
    fn la_sortie_reality_porte_ses_quatre_secrets_au_bon_endroit() {
        let c = sing_box_avec(&parametres(), &[reality()]);
        let o = &c["outbounds"][0];
        assert_eq!(o["type"], "vless");
        assert_eq!(o["uuid"], "00000000-0000-4000-8000-000000000000");
        assert_eq!(o["tls"]["server_name"], "dl.google.com");
        assert_eq!(o["tls"]["reality"]["enabled"], true);
        assert_eq!(
            o["tls"]["reality"]["public_key"],
            "PUBLIQUE-DE-DOCUMENTATION-PAS-UNE-VRAIE-CLE"
        );
        assert_eq!(o["tls"]["reality"]["short_id"], "0000000000000000");
    }

    fn hysteria2(obfs: Option<&str>, confiance: Confiance) -> Sortie {
        Sortie::Hysteria2(Box::new(Hysteria2 {
            tag: "hy2".into(),
            serveur: "192.0.2.10".into(),
            port: 44345,
            mot_de_passe: "MOT-DE-PASSE-DE-DOCUMENTATION".into(),
            obfs: obfs.map(str::to_string),
            nom_de_serveur: "exemple.test".into(),
            confiance,
        }))
    }

    const PEM_DE_RECETTE: &str = "-----BEGIN CERTIFICATE-----
TUlJQlBBU1VOVlJBSUNFUlQ=
-----END CERTIFICATE-----";

    fn pem() -> Confiance {
        Confiance::Epingle(vec![
            "-----BEGIN CERTIFICATE-----".into(),
            "TU5PTlBBU1VOVlJBSUNFUlRJRklDQVQ=".into(),
            "-----END CERTIFICATE-----".into(),
        ])
    }

    #[test]
    fn la_sortie_hysteria2_porte_son_mot_de_passe_et_epingle_le_certificat() {
        let c = sing_box_avec(&parametres(), &[hysteria2(None, pem())]);
        let o = &c["outbounds"][0];
        assert_eq!(o["type"], "hysteria2");
        assert_eq!(o["server_port"], 44345);
        assert_eq!(o["password"], "MOT-DE-PASSE-DE-DOCUMENTATION");
        assert_eq!(o["tls"]["enabled"], true);
        assert_eq!(o["tls"]["server_name"], "exemple.test");
        assert_eq!(o["tls"]["certificate"][0], "-----BEGIN CERTIFICATE-----");
    }

    /// Le profil que l'utilisateur ecrit doit atteindre l'epinglage.
    ///
    /// `Confiance::Epingle` existait, et rien du chemin ordinaire n'y menait:
    /// `depuis_profil` posait `AutoritesDuSysteme` sans regarder le profil.
    /// Seule la recette interne `--coeur-e2e` savait epingler, donc le banc du
    /// depot prouvait un chemin que personne ne peut emprunter.
    #[test]
    fn le_certificat_du_profil_devient_l_epinglage_de_la_sortie() {
        let pem: profil::CertificatPem = PEM_DE_RECETTE.parse().unwrap();
        let p = profil::Profil {
            etiquette: "maison".into(),
            transport: profil::Transport::Hysteria2(Box::new(profil::Hysteria2 {
                serveur: "203.0.113.8".into(),
                port: 443,
                mot_de_passe: "secret".parse().unwrap(),
                obfs: None,
                nom_de_serveur: "exemple.test".into(),
                certificat: Some(pem),
            })),
        };
        let sortie = Sortie::depuis_profil(&p, "hysteria2");
        let Sortie::Hysteria2(h) = &sortie else {
            panic!("sortie inattendue");
        };
        assert!(matches!(h.confiance, Confiance::Epingle(_)));
        let c = sing_box_avec(&parametres(), &[sortie]);
        assert_eq!(
            c["outbounds"][0]["tls"]["certificate"][0],
            "-----BEGIN CERTIFICATE-----"
        );
    }

    /// Et sans certificat, rien ne change: un serveur a vrai certificat
    /// s'ancre aux autorites du systeme.
    #[test]
    fn un_profil_sans_certificat_s_en_remet_aux_autorites_du_systeme() {
        let p = profil::Profil {
            etiquette: "maison".into(),
            transport: profil::Transport::Hysteria2(Box::new(profil::Hysteria2 {
                serveur: "203.0.113.8".into(),
                port: 443,
                mot_de_passe: "secret".parse().unwrap(),
                obfs: None,
                nom_de_serveur: "exemple.test".into(),
                certificat: None,
            })),
        };
        let Sortie::Hysteria2(h) = Sortie::depuis_profil(&p, "hysteria2") else {
            panic!("sortie inattendue");
        };
        assert_eq!(h.confiance, Confiance::AutoritesDuSysteme);
    }

    #[test]
    fn les_autorites_du_systeme_n_epinglent_aucun_certificat() {
        let c = sing_box_avec(
            &parametres(),
            &[hysteria2(None, Confiance::AutoritesDuSysteme)],
        );
        // Absent, et non pas present et vide: une liste vide se lirait comme
        // "n'accepter aucun certificat", ce qui n'est pas ce qu'on demande.
        assert!(c["outbounds"][0]["tls"].get("certificate").is_none());
    }

    #[test]
    fn aucune_sortie_ne_peut_desactiver_la_verification_du_certificat() {
        // Le test qui garde l'invariant du type `Confiance`. `insecure: true`
        // est ce que recopient les tutoriels pour faire marcher un certificat
        // auto-signe; la recette passerait alors avec un tunnel non
        // authentifie, donc en prouvant le contraire de ce qu'elle annonce.
        let toutes = vec![
            Sortie::Directe { tag: "d".into() },
            reality(),
            hysteria2(Some("obfs"), pem()),
            hysteria2(None, Confiance::AutoritesDuSysteme),
        ];
        let rendu = serde_json::to_string(&sing_box_avec(&parametres(), &toutes)).unwrap();
        assert!(!rendu.contains("insecure"), "une sortie emet insecure");
    }

    #[test]
    fn l_obfuscation_est_absente_par_defaut_et_salamander_quand_demandee() {
        let sans = sing_box_avec(&parametres(), &[hysteria2(None, pem())]);
        assert!(sans["outbounds"][0].get("obfs").is_none());

        let avec = sing_box_avec(&parametres(), &[hysteria2(Some("cry-me-a-river"), pem())]);
        assert_eq!(avec["outbounds"][0]["obfs"]["type"], "salamander");
        assert_eq!(avec["outbounds"][0]["obfs"]["password"], "cry-me-a-river");
    }

    /// Les memes parametres, avec une interface de sortie a lier.
    fn parametres_lies() -> Parametres {
        Parametres {
            lier_a: Some("Ethernet".into()),
            ..parametres()
        }
    }

    #[test]
    fn la_liaison_va_sur_les_sorties_qui_composent_et_jamais_sur_le_selecteur() {
        // C'est la sortie qui ouvre la socket; le selecteur ne fait que
        // designer laquelle. Poser la liaison sur lui la mettrait la ou aucune
        // connexion n'est composee - elle n'aurait aucun effet, et l'aurait
        // l'air d'en avoir un.
        let sorties = [
            Sortie::depuis_profil(
                &Profil::depuis_lien(&lien_reality_doc()).unwrap(),
                "coeur-0",
            ),
            Sortie::depuis_profil(
                &Profil::depuis_lien("hy2://mdp@192.0.2.11:8443").unwrap(),
                "coeur-1",
            ),
        ];
        let c = sing_box_avec(&parametres_lies(), &sorties);
        let outbounds = c["outbounds"].as_array().unwrap();

        assert_eq!(outbounds[0]["bind_interface"], "Ethernet");
        assert_eq!(outbounds[1]["bind_interface"], "Ethernet");

        let selecteur = outbounds.last().unwrap();
        assert_eq!(selecteur["type"], "selector");
        // Voir le commentaire a l'emission: ce selecteur ne bascule que sur un
        // VERDICT, jamais sur une preference. Laisser vivre des connexions
        // liees a une sortie gelee ne les sauve pas - elles pendent - et leurs
        // compteurs continueraient de tirer vers le bas une observation qui
        // AGREGE tout le TUN, jusqu'a condamner un candidat qui n'a jamais eu
        // sa chance.
        assert_eq!(
            selecteur["interrupt_exist_connections"], true,
            "sans ce champ, la bascule laisse le trafic sur la sortie gelee"
        );
        assert!(
            selecteur.get("bind_interface").is_none(),
            "le selecteur ne compose rien: {selecteur}"
        );
    }

    #[test]
    fn sans_interface_a_lier_aucune_sortie_n_en_porte() {
        // Sous Linux l'echappement est dans la table de routage: emettre le
        // champ quand meme lierait le coeur a une interface que personne n'a
        // choisie.
        let c = sing_box_avec(
            &parametres(),
            &[Sortie::depuis_profil(
                &Profil::depuis_lien(&lien_reality_doc()).unwrap(),
                "coeur-0",
            )],
        );
        for sortie in c["outbounds"].as_array().unwrap() {
            assert!(
                sortie.get("bind_interface").is_none(),
                "liaison non demandee et pourtant emise: {sortie}"
            );
        }
    }

    #[test]
    fn xray_lie_sa_sortie_par_sockopt() {
        // Xray nomme la meme chose autrement, et ce n'est pas lu dans une
        // documentation: `infra/conf/transport_internet.go` de la version
        // epinglee porte un champ `Interface` etiquete "interface", et
        // `transport/internet/sockopt_windows.go` en fait un `IP_UNICAST_IF`
        // apres avoir resolu le nom par `net.InterfaceByName` - le nom convivial
        // de Windows, celui que rend `ipcfg::alias`. Un nom introuvable y rend
        // une erreur: la liaison echoue FERMEE.
        //
        // Cette lecture de la source n'est pas un exces de zele: contrairement
        // a sing-box, `xray run -test` accepte un champ inconnu dans `sockopt`
        // sans broncher - mesure du 20 aout 2026, temoin negatif compris. Il ne
        // peut donc rien attester ici, et un garde-fou a la
        // `hysteria2_n_emet_que_des_champs_connus_du_binaire_epingle` serait
        // trompeur de ce cote.
        let c = xray(&parametres_lies());
        assert_eq!(
            c["outbounds"][0]["streamSettings"]["sockopt"]["interface"],
            "Ethernet"
        );

        let sans = xray(&parametres());
        assert!(sans["outbounds"][0].get("streamSettings").is_none());
    }

    #[test]
    fn hysteria2_n_emet_que_des_champs_connus_du_binaire_epingle() {
        // Ce test vient d'un incident: un `initial_packet_size` ajoute sur la
        // foi de la documentation en ligne, qui decrit la branche `testing`,
        // a fait refuser la configuration ENTIERE par le binaire epingle. Un
        // champ inconnu n'est pas ignore, il est fatal, et il emporte avec lui
        // les transports qui n'ont rien demande.
        //
        // La liste ci-dessous n'est pas recopiee d'une documentation: elle a
        // ete obtenue en soumettant chaque champ a `sing-box check` avec le
        // binaire epingle, version 1.13.18, le 16 aout 2026.
        const ACCEPTES: &[&str] = &[
            "type",
            "tag",
            "server",
            "server_port",
            "password",
            "tls",
            "obfs",
            "udp_fragment",
            "hop_interval",
            "brutal_debug",
            // Champ de composition commun a toutes les sorties, soumis a
            // `sing-box check` avec le binaire epingle le 20 aout 2026 - la
            // configuration engendree par ce fichier meme, et un temoin negatif
            // `bind_interface_xyz` que le binaire a bien refuse.
            "bind_interface",
        ];
        // Les DEUX formes, sans quoi le garde-fou cesserait de couvrir le champ
        // le jour ou il est emis: la configuration sans liaison ne le contient
        // pas, donc ne peut rien en dire.
        for p in [parametres(), parametres_lies()] {
            let c = sing_box_avec(&p, &[hysteria2(Some("o"), pem())]);
            let emis = c["outbounds"][0].as_object().unwrap();
            for champ in emis.keys() {
                assert!(
                    ACCEPTES.contains(&champ.as_str()),
                    "champ {champ:?} inconnu de sing-box 1.13.18: la configuration entiere sera refusee"
                );
            }
        }
    }

    #[test]
    fn hysteria2_n_annonce_aucun_debit() {
        // Renseigner up_mbps/down_mbps bascule sur le controle de congestion
        // Brutal, qui emet au debit annonce sans ecouter le reseau: une valeur
        // recopiee d'un exemple degraderait la ligne de tout le monde.
        let c = sing_box_avec(&parametres(), &[hysteria2(Some("o"), pem())]);
        let o = &c["outbounds"][0];
        assert!(o.get("up_mbps").is_none());
        assert!(o.get("down_mbps").is_none());
    }

    #[test]
    fn la_sortie_reality_active_utls() {
        // Sans uTLS, l'empreinte TLS distingue le client d'un navigateur, ce
        // que le document 04 releve comme reellement exploite cote censeur.
        let c = sing_box_avec(&parametres(), &[reality()]);
        assert_eq!(c["outbounds"][0]["tls"]["utls"]["enabled"], true);
        assert_eq!(c["outbounds"][0]["tls"]["utls"]["fingerprint"], "chrome");
    }

    #[test]
    fn le_flow_vision_accompagne_toujours_reality() {
        // xtls-rprx-vision est incompatible avec WS, gRPC et XHTTP; ici le
        // transport est TCP nu, donc il doit etre present.
        let c = sing_box_avec(&parametres(), &[reality()]);
        assert_eq!(c["outbounds"][0]["flow"], "xtls-rprx-vision");
    }

    #[test]
    fn un_melange_de_sorties_reste_coherent_avec_le_selecteur() {
        let sorties = vec![
            reality(),
            Sortie::Directe {
                tag: "en-clair".into(),
            },
        ];
        let p = parametres();
        let c = sing_box_avec(&p, &sorties);
        let outbounds = c["outbounds"].as_array().unwrap();
        let sel = outbounds
            .iter()
            .find(|o| o["tag"] == p.selecteur.as_str())
            .unwrap();
        assert_eq!(sel["outbounds"], json!(["reality", "en-clair"]));
        assert_eq!(sel["default"], "reality");
        // Et chaque etiquette du selecteur existe bien comme outbound.
        let etiquettes: Vec<&str> = outbounds.iter().filter_map(|o| o["tag"].as_str()).collect();
        for s in &sorties {
            assert!(etiquettes.contains(&s.tag()));
        }
    }

    #[test]
    fn le_secret_est_present_chez_sing_box() {
        let c = sing_box(&parametres());
        assert_eq!(c["experimental"]["clash_api"]["secret"], "un-secret");
    }

    #[test]
    fn le_secret_n_est_pas_recopie_dans_la_configuration_xray() {
        // Xray n'a pas d'API Clash: l'y ecrire serait une fuite gratuite.
        let c = xray(&parametres());
        assert!(
            !serde_json::to_string(&c).unwrap().contains("un-secret"),
            "le secret a fuite dans la configuration Xray"
        );
        assert!(c.get("experimental").is_none());
    }

    #[test]
    fn le_selecteur_liste_exactement_les_sorties_declarees() {
        let p = parametres();
        let c = sing_box(&p);
        let outbounds = c["outbounds"].as_array().unwrap();
        let sel = outbounds
            .iter()
            .find(|o| o["tag"] == p.selecteur.as_str())
            .expect("le selecteur doit exister");
        assert_eq!(sel["outbounds"], json!(p.sorties));
        assert_eq!(sel["default"], "sortie-a");
    }

    #[test]
    fn chaque_sortie_du_selecteur_existe_comme_outbound() {
        // Un selecteur qui pointe vers une etiquette inexistante fait refuser
        // la configuration entiere, et le message ne dit pas laquelle.
        let p = parametres();
        let c = sing_box(&p);
        let outbounds = c["outbounds"].as_array().unwrap();
        let etiquettes: Vec<&str> = outbounds.iter().filter_map(|o| o["tag"].as_str()).collect();
        for s in &p.sorties {
            assert!(etiquettes.contains(&s.as_str()), "sortie orpheline: {s}");
        }
        assert!(etiquettes.contains(&p.selecteur.as_str()));
    }

    #[test]
    fn la_route_finale_passe_par_le_selecteur() {
        // Sinon le trafic sortirait sans jamais consulter le selecteur, et la
        // bascule n'aurait aucun effet visible.
        let p = parametres();
        assert_eq!(sing_box(&p)["route"]["final"], p.selecteur.as_str());
    }

    #[test]
    fn les_ports_demandes_se_retrouvent_dans_la_configuration() {
        let p = parametres();
        let c = sing_box(&p);
        assert_eq!(c["inbounds"][0]["listen_port"], 21080);
        assert_eq!(
            c["experimental"]["clash_api"]["external_controller"],
            "127.0.0.1:29090"
        );
        assert_eq!(xray(&p)["inbounds"][0]["port"], 21080);
    }

    #[test]
    fn les_deux_configurations_sont_du_json_serialisable() {
        let p = parametres();
        for c in [sing_box(&p), xray(&p)] {
            let texte = serde_json::to_string(&c).unwrap();
            let relu: Value = serde_json::from_str(&texte).unwrap();
            assert_eq!(relu, c);
        }
    }

    #[cfg(unix)]
    #[test]
    fn le_fichier_ecrit_n_est_lisible_que_par_son_proprietaire() {
        use std::os::unix::fs::PermissionsExt;
        let chemin = std::env::temp_dir().join("bifrost-config-droits/sing-box.json");
        ecrire(&chemin, &sing_box(&parametres())).unwrap();
        let mode = std::fs::metadata(&chemin).unwrap().permissions().mode();
        assert_eq!(
            mode & 0o077,
            0,
            "le fichier au secret est lisible par d'autres"
        );
        let _ = std::fs::remove_dir_all(chemin.parent().unwrap());
    }

    /// Cle de DOCUMENTATION: 43 caracteres de l'alphabet base64url, la forme
    /// que rend `xray x25519`, mais qui n'ouvre rien.
    const CLE_DOC: &str = "PUBLIQUE-DE-DOCUMENTATION-PAS-UNE-VRAIE-CLE";
    /// UUID nul: valide dans sa forme, sans porteur.
    const UUID_DOC: &str = "00000000-0000-4000-8000-000000000000";

    fn lien_reality_doc() -> String {
        format!(
            "vless://{UUID_DOC}@192.0.2.10:44343?security=reality&flow=xtls-rprx-vision&encryption=none&fp=chrome&type=tcp&pbk={CLE_DOC}&sid=0000000000000000&sni=dl.google.com#Suisse"
        )
    }

    #[test]
    fn un_lien_reality_traverse_jusqu_au_json_du_coeur() {
        // Le trajet complet de ce chantier: un lien tel qu'un panneau le rend,
        // jusqu'a la configuration que le binaire lit. Sans lui, les deux
        // moities pourraient etre justes separement et ne pas se rejoindre.
        let profil = Profil::depuis_lien(&lien_reality_doc()).expect("le lien doit se lire");
        let sortie = Sortie::depuis_profil(&profil, "coeur-0");
        let c = sing_box_avec(&parametres(), &[sortie]);
        let o = &c["outbounds"][0];
        assert_eq!(o["type"], "vless");
        assert_eq!(o["tag"], "coeur-0");
        assert_eq!(o["server"], "192.0.2.10");
        assert_eq!(o["server_port"], 44343);
        assert_eq!(o["uuid"], UUID_DOC);
        assert_eq!(o["tls"]["reality"]["public_key"], CLE_DOC);
        assert_eq!(o["tls"]["reality"]["short_id"], "0000000000000000");
        // Le site emprunte, pas l'hote. C'est la raison d'etre du controle pose
        // a la lecture du lien.
        assert_eq!(o["tls"]["server_name"], "dl.google.com");
    }

    #[test]
    fn un_lien_hysteria2_traverse_avec_son_obfuscation() {
        let profil = Profil::depuis_lien(
            "hysteria2://mot-de-passe-de-documentation@192.0.2.11:8443/?obfs=salamander&obfs-password=sel-de-documentation&sni=exemple.test#Rapide",
        )
        .expect("le lien doit se lire");
        let c = sing_box_avec(&parametres(), &[Sortie::depuis_profil(&profil, "coeur-1")]);
        let o = &c["outbounds"][0];
        assert_eq!(o["type"], "hysteria2");
        assert_eq!(o["password"], "mot-de-passe-de-documentation");
        assert_eq!(o["obfs"]["type"], "salamander");
        assert_eq!(o["obfs"]["password"], "sel-de-documentation");
        assert_eq!(o["tls"]["server_name"], "exemple.test");
    }

    #[test]
    fn un_lien_sans_obfs_n_ecrit_pas_d_obfuscation() {
        // Ecrire un `obfs` vide donnerait un client qui obfusque avec rien: la
        // poignee de main ne ressemblerait ni a du QUIC nu ni a du Salamander.
        let profil = Profil::depuis_lien("hy2://mdp@192.0.2.11:8443").unwrap();
        let c = sing_box_avec(&parametres(), &[Sortie::depuis_profil(&profil, "coeur-1")]);
        assert!(
            c["outbounds"][0].get("obfs").is_none(),
            "obfs ecrit sans etre demande: {}",
            c["outbounds"][0]
        );
    }

    #[test]
    fn un_profil_importe_par_lien_s_en_remet_aux_autorites_du_systeme() {
        // Un lien ne sait pas exprimer d'epinglage: `pinSHA256` est refuse a la
        // lecture faute de pouvoir etre honore sous cette forme. La sortie ne
        // doit donc porter AUCUN certificat, et surtout pas un champ vide qui
        // ferait echouer le coeur au demarrage.
        let profil = Profil::depuis_lien("hy2://mdp@192.0.2.11:8443").unwrap();
        let c = sing_box_avec(&parametres(), &[Sortie::depuis_profil(&profil, "coeur-1")]);
        assert!(
            c["outbounds"][0]["tls"].get("certificate").is_none(),
            "certificat ecrit sans epinglage: {}",
            c["outbounds"][0]["tls"]
        );
        assert_eq!(c["outbounds"][0]["tls"]["enabled"], true);
    }

    #[test]
    fn deux_profils_de_meme_libelle_gardent_des_etiquettes_distinctes() {
        // La raison pour laquelle le tag est donne et non derive: deux serveurs
        // peuvent porter le meme libelle, et sing-box refuse une configuration
        // dont deux sorties partagent une etiquette.
        let a = Profil::depuis_lien("hy2://mdp-a@192.0.2.11:8443#Suisse").unwrap();
        let b = Profil::depuis_lien("hy2://mdp-b@192.0.2.12:8443#Suisse").unwrap();
        assert_eq!(a.etiquette, b.etiquette);
        let sorties = [
            Sortie::depuis_profil(&a, "coeur-0"),
            Sortie::depuis_profil(&b, "coeur-1"),
        ];
        assert_ne!(sorties[0].tag(), sorties[1].tag());
        let c = sing_box_avec(&parametres(), &sorties);
        assert_eq!(c["outbounds"][0]["tag"], "coeur-0");
        assert_eq!(c["outbounds"][1]["tag"], "coeur-1");
    }
}
