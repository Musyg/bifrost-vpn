//! Ce qui etablit qu'un tunnel TRANSPORTE, et ce qui ne l'etablit pas.
//!
//! Le vecteur `exit-ip` demande deux choses a la fois: que la sortie passe par
//! le tunnel, et que rien ne parte en clair a cote. La seconde se lit dans une
//! capture. La premiere, non, et c'est la tout le piege de ce vecteur.
//!
//! # Le trou noir
//!
//! Un endpoint MORT produit exactement les memes paquets qu'un endpoint vivant
//! sur le lien physique: ce sont ses tentatives de poignee de main, reemises
//! indefiniment. Compter les paquets chiffres vers l'endpoint etablit donc
//! qu'il se passe quelque chose, jamais que quelque chose ARRIVE. Le trafic du
//! client part alors dans un trou noir, ou il ne fuite evidemment pas, et la
//! capture rend zero paquet en clair. Un vecteur qui s'arrete la certifie
//! l'etancheite d'un tunnel qui ne transporte rien.
//!
//! # Ce qui ecarte le trou noir
//!
//! Deux observations, dont aucune ne se deduit du lien physique:
//!
//! 1. **Les compteurs du driver.** `last_handshake` present et `rx_bytes` non
//!    nul: un pair mort laisse `rx_bytes` a zero, quoi que le client emette.
//! 2. **Une banniere lue A TRAVERS le tunnel**, servie a une adresse joignable
//!    uniquement par lui. Elle ne peut venir que de l'autre bout. Encore
//!    faut-il l'etablir: le harnais verifie que la meme adresse REFUSE la
//!    connexion hors tunnel, sans quoi la lire ne prouverait rien.
//!
//! # Pourquoi les regles sont ordonnees, et pourquoi cet ordre est teste
//!
//! Chaque regle ci-dessous ecarte une lecture possible du silence. Les
//! appliquer dans le desordre nommerait une cause plus lointaine que la vraie,
//! et un message qui designe la mauvaise cause coute plus cher qu'une absence
//! de message. L'ordre fait donc partie du contrat, et il est verrouille par un
//! test.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

/// Delai de la CONNEXION, court a dessein.
///
/// Un tunnel qui vient d'etre monte perd parfois la premiere demande de
/// connexion, et le noyau ne la reemet qu'apres une seconde. Un delai long
/// n'ajoute alors aucune chance de succes: il consomme la fenetre en attendant
/// une reponse qui ne viendra pas, et deux tentatives suffisent a l'epuiser.
/// Court, il rend la main vite et laisse la place a plusieurs essais.
/// Mesure du 18 aout 2026 sur le banc: avec deux secondes, la lecture echouait
/// par intermittence apres quatre demandes perdues en quatre secondes.
const DELAI_CONNEXION: Duration = Duration::from_millis(700);
/// Delai de la LECTURE, une fois la connexion ouverte. Plus long: la banniere
/// traverse le tunnel, et l'autre bout a le droit d'etre lent.
const DELAI_LECTURE: Duration = Duration::from_secs(2);
/// Pas entre deux tentatives, le temps que le serveur se lie et que le tunnel
/// s'echauffe.
const PAS: Duration = Duration::from_millis(200);

/// Ce que le pair sert a travers le tunnel, et rien d'autre.
///
/// Une chaine choisie plutot qu'un simple "la connexion s'ouvre": un port
/// ouvert par hasard sur un autre chemin donnerait une connexion, pas cette
/// chaine.
///
/// Elle differe volontairement de celle de la recette Windows
/// (`BIFROST-E2E-OK`): celle-la est servie par une machine deja provisionnee
/// hors du depot, changer son nom demanderait de la reprovisionner. Ici le
/// serveur est monte par le banc lui-meme a chaque execution.
pub const BANNIERE: &str = "BIFROST-TUNNEL-OK";

/// Etat d'un pair WireGuard tel que le driver le rend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Compteurs {
    /// Vrai si le pair a deja repondu a une poignee de main.
    pub handshake: bool,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
}

/// Tout ce que la mesure a observe, avant tout jugement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    /// Paquets WireGuard vus sur le lien physique. Signal de vie de la CAPTURE,
    /// pas du tunnel: un endpoint mort en produit autant.
    pub chiffres: usize,
    /// Compteurs releves avant la lecture de la banniere.
    pub avant: Compteurs,
    /// Compteurs releves apres.
    pub apres: Compteurs,
    /// Ce qui a ete lu a travers le tunnel, ou pourquoi rien ne l'a ete.
    pub banniere: Result<String, String>,
    /// Vrai si la meme banniere s'obtient AUSSI hors tunnel. Dans ce cas la
    /// lire ne prouve aucun transport.
    pub banniere_hors_tunnel: bool,
    /// Paquets en clair vus sur le lien physique.
    pub en_clair: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Le tunnel a transporte, et rien n'est parti en clair.
    Etanche(String),
    /// Rien ne permet de conclure. Devient `SKIPPED` avec cette raison.
    Indecis(String),
    /// Du trafic en clair est sorti.
    Fuite(String),
}

/// Les phrases des verdicts de transport, chacune au catalogue (5q).
///
/// `juger` et `regles` ne composent plus leur raison en ligne: la PROSE vit
/// ici, sous les gardes de forme et de distinction de [`tests`], et la donnee de
/// mesure (compteurs, comptes de paquets) reste un argument. C'est la meme
/// famille que les onze raisons de `failed`/`passed` que 5h avait fait entrer au
/// catalogue de `checks/mod.rs`; ce juge est un module a part, donc son
/// catalogue l'est aussi. Aucune phrase ne change: seule l'interpolation se
/// deplace du site du verdict vers ces fonctions.
pub mod motifs {
    use super::BANNIERE;

    /// Indecis, avec une note quand du clair a ete vu malgre l'indecision.
    pub fn indecis_avec_clair(raison: &str, en_clair: usize) -> String {
        format!(
            "{raison}; a noter: {en_clair} paquet(s) en clair observes pendant la mesure, a reexaminer une fois la cause ci-dessus levee"
        )
    }

    /// La capture n'a vu aucun paquet WireGuard: le silence ne vaut rien.
    pub fn capture_muette() -> String {
        "aucun paquet WireGuard sur le lien pendant la mesure: la capture \
         n'a rien vu, et zero paquet en clair ne vaut alors pas une absence \
         de fuite"
            .to_owned()
    }

    /// Aucune poignee de main aboutie: le tunnel n'a pas d'autre bout.
    pub fn sans_handshake(tx_bytes: u64) -> String {
        format!(
            "aucune poignee de main aboutie sur le pair ({tx_bytes} octet(s) emis, \
             aucun recu): le tunnel n'a pas d'autre bout, et le trafic qui y \
             entre n'en ressort nulle part"
        )
    }

    /// Le trou noir: `rx_bytes` reste a zero, comme un endpoint mort.
    pub fn trou_noir(tx_bytes: u64) -> String {
        format!(
            "le pair n'a jamais rien renvoye: rx_bytes reste a zero apres {tx_bytes} \
             octet(s) emis. C'est exactement ce que produit un endpoint mort \
             qui reemet ses poignees de main, et le trafic part alors dans un \
             trou noir ou il ne peut evidemment pas fuir"
        )
    }

    /// La banniere n'a pas ete lue a travers le tunnel.
    pub fn banniere_non_lue(erreur: &str) -> String {
        format!(
            "la banniere du pair n'a pas ete lue a travers le tunnel ({erreur}): \
             le tunnel a repondu, mais rien n'etablit qu'il porte des donnees"
        )
    }

    /// Une reponse est arrivee, mais ce n'est pas la banniere du pair.
    pub fn banniere_inattendue(lue: &str) -> String {
        format!(
            "banniere inattendue '{lue}' au lieu de '{BANNIERE}': quelque chose \
             repond a l'adresse du pair, mais ce n'est pas le pair"
        )
    }

    /// La banniere s'obtient AUSSI hors tunnel: elle ne prouve aucun transport.
    pub fn banniere_hors_tunnel() -> String {
        "la banniere s'obtient aussi hors tunnel: le temoin qui devait \
         etablir qu'elle n'est joignable QUE par le tunnel a abouti, donc \
         l'avoir lue ne prouve aucun transport"
            .to_owned()
    }

    /// Les compteurs du driver n'ont pas bouge pendant la lecture.
    pub fn compteurs_immobiles(
        avant_tx: u64,
        apres_tx: u64,
        avant_rx: u64,
        apres_rx: u64,
    ) -> String {
        format!(
            "les compteurs du pair n'ont pas bouge pendant la lecture \
             ({avant_tx} puis {apres_tx} octet(s) emis, {avant_rx} puis {apres_rx} recus): si la banniere est \
             arrivee, elle n'est pas passee par le tunnel"
        )
    }

    /// Du trafic en clair est sorti hors tunnel.
    pub fn fuite_hors_tunnel(en_clair: usize) -> String {
        format!("{en_clair} paquet(s) sortis hors tunnel")
    }

    /// Le transport est etabli et rien n'est parti en clair.
    pub fn etanche(
        avant_tx: u64,
        avant_rx: u64,
        apres_tx: u64,
        apres_rx: u64,
        chiffres: usize,
    ) -> String {
        format!(
            "banniere '{BANNIERE}' lue a travers le tunnel, inobtenable hors de lui; \
             compteurs du pair passes de {avant_tx}/{avant_rx} a {apres_tx}/{apres_rx} octet(s) emis/recus; \
             {chiffres} paquet(s) chiffres et aucun paquet en clair sur le lien"
        )
    }
}

/// Conclut a partir des observations.
///
/// Tout ce qui n'est pas conclu rend [`Verdict::Indecis`], jamais un succes.
///
/// Indecis ne veut pas dire muet. Si des paquets en clair ont ete vus, la
/// raison les mentionne. Le verdict ne peut pas les imputer au kill switch
/// tant qu'on ignore si le tunnel transportait, mais les taire les ferait
/// disparaitre: `CheckOutcome::skipped` ne porte pas de preuve, et une mesure
/// ou le tunnel est un trou noir ET ou du trafic est sorti en clair se lirait
/// alors comme un simple banc a reparer.
pub fn juger(o: &Observation) -> Verdict {
    match regles(o) {
        Verdict::Indecis(raison) if o.en_clair > 0 => {
            Verdict::Indecis(motifs::indecis_avec_clair(&raison, o.en_clair))
        }
        v => v,
    }
}

/// Les huit regles, dans l'ordre. Passer par [`juger`], seul point d'entree.
fn regles(o: &Observation) -> Verdict {
    // 1. La capture etait-elle vivante? Sans ca, tout le reste se lit dans un
    //    silence qui ne veut rien dire. C'est la SEULE chose que les paquets
    //    chiffres etablissent: un endpoint mort en produit autant qu'un vivant.
    if o.chiffres == 0 {
        return Verdict::Indecis(motifs::capture_muette());
    }
    // 2. Le pair a-t-il seulement repondu une fois?
    if !o.apres.handshake {
        return Verdict::Indecis(motifs::sans_handshake(o.apres.tx_bytes));
    }
    // 3. Le trou noir, nomme. Un pair mort laisse `rx_bytes` a zero quoi que le
    //    client emette; c'est ce que la version d'avant ne regardait pas.
    if o.apres.rx_bytes == 0 {
        return Verdict::Indecis(motifs::trou_noir(o.apres.tx_bytes));
    }
    // 4. La banniere a-t-elle ete lue?
    if let Err(e) = &o.banniere {
        return Verdict::Indecis(motifs::banniere_non_lue(e));
    }
    // 5. Est-ce bien celle du pair? Une reponse quelconque ne mesurerait que
    // "un port est ouvert quelque part".
    if let Ok(lue) = &o.banniere
        && lue != BANNIERE
    {
        return Verdict::Indecis(motifs::banniere_inattendue(lue));
    }
    // 6. Etait-elle inobtenable autrement? Toute sa valeur de preuve tient la.
    if o.banniere_hors_tunnel {
        return Verdict::Indecis(motifs::banniere_hors_tunnel());
    }
    // 7. Et elle est bien passee par le tunnel: les compteurs du driver ont
    //    bouge pendant qu'on la lisait, dans les deux sens.
    if o.apres.tx_bytes <= o.avant.tx_bytes || o.apres.rx_bytes <= o.avant.rx_bytes {
        return Verdict::Indecis(motifs::compteurs_immobiles(
            o.avant.tx_bytes,
            o.apres.tx_bytes,
            o.avant.rx_bytes,
            o.apres.rx_bytes,
        ));
    }
    // 8. Le transport est etabli. Seconde moitie du vecteur: le lien physique.
    if o.en_clair > 0 {
        return Verdict::Fuite(motifs::fuite_hors_tunnel(o.en_clair));
    }
    Verdict::Etanche(motifs::etanche(
        o.avant.tx_bytes,
        o.avant.rx_bytes,
        o.apres.tx_bytes,
        o.apres.rx_bytes,
        o.chiffres,
    ))
}

/// Lit la banniere a `cible`, en reessayant jusqu'a l'echeance.
///
/// Les tentatives sont repetees parce que deux choses peuvent n'etre pas
/// encore pretes: le serveur, qui vient d'etre lance dans un autre namespace,
/// et le tunnel, dont la premiere poignee de main peut etre en cours. Un echec
/// unique confondrait "pas encore" avec "jamais".
///
/// `fenetre` a zero fait une seule tentative. C'est ce qu'il faut au temoin
/// negatif, qui attend un refus: reessayer un refus pendant trois secondes
/// n'apprendrait rien de plus et ferait trainer la mesure.
pub fn lire(cible: SocketAddr, fenetre: Duration) -> Result<String, String> {
    let echeance = Instant::now() + fenetre;
    loop {
        let derniere = match tenter(cible) {
            Ok(banniere) => return Ok(banniere),
            Err(e) => e,
        };
        if Instant::now() >= echeance {
            return Err(derniere);
        }
        std::thread::sleep(PAS);
    }
}

fn tenter(cible: SocketAddr) -> Result<String, String> {
    let mut flux = TcpStream::connect_timeout(&cible, DELAI_CONNEXION)
        .map_err(|e| format!("connexion a {cible}: {e}"))?;
    flux.set_read_timeout(Some(DELAI_LECTURE))
        .map_err(|e| format!("delai de lecture sur {cible}: {e}"))?;
    let mut recu = String::new();
    // Le serveur ferme apres avoir ecrit: la lecture jusqu'a la fin de flux
    // rend la banniere entiere sans avoir a en connaitre la longueur.
    flux.read_to_string(&mut recu)
        .map_err(|e| format!("lecture depuis {cible}: {e}"))?;
    let recu = recu.trim();
    // Une fermeture sans un octet n'est pas une banniere vide, c'est une
    // absence de banniere. La rendre en `Ok` la ferait juger comme une reponse
    // inattendue du pair, alors que le pair n'a rien dit: deux causes
    // differentes, et la seconde merite une nouvelle tentative.
    if recu.is_empty() {
        return Err(format!("{cible} a ferme sans rien ecrire"));
    }
    Ok(recu.to_owned())
}

/// Sert la banniere jusqu'a extinction.
///
/// **Ce serveur ne restreint rien par lui-meme.** Ce qui rend la banniere
/// inobtenable hors du tunnel est la regle rendue par [`nft_banniere`], que le
/// banc pose dans le namespace de la passerelle, et dont le temoin negatif du
/// vecteur verifie l'effet. Servir sans cette regle donnerait une banniere
/// lisible par n'importe quel chemin, donc sans valeur de preuve.
pub fn servir(ecoute: SocketAddr) -> std::io::Result<()> {
    let ecouteur = TcpListener::bind(ecoute)?;
    for flux in ecouteur.incoming() {
        match flux {
            Ok(mut f) => {
                let _ = f.set_write_timeout(Some(DELAI_LECTURE));
                if let Err(e) = f.write_all(BANNIERE.as_bytes()) {
                    eprintln!("banniere non servie: {e}");
                }
            }
            Err(e) => eprintln!("connexion non acceptee: {e}"),
        }
    }
    Ok(())
}

/// Rend la banniere inobtenable autrement que par le tunnel: tout ce qui
/// n'ARRIVE pas par `interface` est jete.
///
/// # Pourquoi pas `SO_BINDTODEVICE`
///
/// Lier le socket d'ecoute a l'interface du tunnel parait plus direct, et ne
/// marche pas ici. Mesure du 18 aout 2026 sur le banc: une connexion emise
/// DANS le namespace de la passerelle vers l'adresse du tunnel est servie,
/// alors que la meme option refuse bien une connexion vers `127.0.0.1`. Le
/// paquet est livre localement a une adresse qui appartient a l'interface liee,
/// et la recherche du socket d'ecoute n'y voit donc aucun ecart. L'option
/// distingue les interfaces, pas les CHEMINS, et c'est le chemin qui est en
/// question.
///
/// La regle nftables, elle, lit l'interface d'ARRIVEE au hook `input`: `lo`
/// pour une livraison locale, le veth pour une fuite en clair, l'interface
/// WireGuard pour ce qui sort du tunnel. Un seul test les separe tous les
/// trois, et c'est celui qu'il fallait.
///
/// Le `counter` n'entre dans aucune decision: il rend la regle lisible quand
/// on inspecte le banc a la main, et distingue "rien n'est arrive par ce
/// chemin" de "quelque chose est arrive et a ete jete".
///
/// Le temoin negatif du vecteur ne fait pas confiance a ce commentaire: il
/// tente la lecture hors tunnel et refuse de conclure si elle aboutit.
pub fn nft_banniere(interface: &str, port: u16) -> String {
    format!(
        "table inet banniere {{\n\
         \tchain entree {{\n\
         \t\ttype filter hook input priority filter; policy accept;\n\
         \t\ttcp dport {port} iifname != \"{interface}\" counter drop\n\
         \t}}\n\
         }}\n"
    )
}

/// Retire la table posee par [`nft_banniere`], qu'elle existe ou non.
pub fn nft_banniere_teardown() -> String {
    "table inet banniere {}\ndelete table inet banniere\n".to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Un tunnel qui va bien: pair vivant, banniere lue par lui seul,
    /// compteurs qui bougent, rien en clair. Chaque test ci-dessous en abime
    /// UNE observation et exige que le verdict change.
    fn sain() -> Observation {
        Observation {
            chiffres: 12,
            avant: Compteurs {
                handshake: true,
                tx_bytes: 180,
                rx_bytes: 92,
            },
            apres: Compteurs {
                handshake: true,
                tx_bytes: 516,
                rx_bytes: 444,
            },
            banniere: Ok(BANNIERE.to_owned()),
            banniere_hors_tunnel: false,
            en_clair: 0,
        }
    }

    fn raison(v: &Verdict) -> &str {
        match v {
            Verdict::Etanche(r) | Verdict::Indecis(r) | Verdict::Fuite(r) => r,
        }
    }

    /// Tout ce que ce juge sait dire, rendu sans banc: chaque phrase de verdict
    /// avec une donnee de mesure representative. Les deux gardes ci-dessous
    /// s'appuient dessus, comme les catalogues de plateforme sur le leur (5q).
    fn catalogue() -> Vec<(&'static str, String)> {
        vec![
            (
                "transport/indecis-avec-clair",
                motifs::indecis_avec_clair(&motifs::capture_muette(), 3),
            ),
            ("transport/capture-muette", motifs::capture_muette()),
            ("transport/sans-handshake", motifs::sans_handshake(148)),
            ("transport/trou-noir", motifs::trou_noir(592)),
            (
                "transport/banniere-non-lue",
                motifs::banniere_non_lue("connexion refusee"),
            ),
            (
                "transport/banniere-inattendue",
                motifs::banniere_inattendue("HTTP/1.1 400"),
            ),
            (
                "transport/banniere-hors-tunnel",
                motifs::banniere_hors_tunnel(),
            ),
            (
                "transport/compteurs-immobiles",
                motifs::compteurs_immobiles(516, 516, 444, 444),
            ),
            ("transport/fuite-hors-tunnel", motifs::fuite_hors_tunnel(2)),
            ("transport/etanche", motifs::etanche(180, 92, 516, 444, 12)),
        ]
    }

    /// La forme, tenue par la meme fonction que les catalogues de plateforme.
    #[test]
    fn aucune_phrase_de_transport_n_est_vide_ni_trouee_d_espaces() {
        super::super::forme_des_messages(&catalogue());
    }

    /// Deux phrases de verdict distinctes ne doivent pas se lire pareil.
    #[test]
    fn deux_phrases_de_transport_ne_se_lisent_pas_pareil() {
        let cat = catalogue();
        let distinctes: std::collections::BTreeSet<&str> =
            cat.iter().map(|(_, m)| m.as_str()).collect();
        assert_eq!(
            distinctes.len(),
            cat.len(),
            "deux phrases de transport se lisent pareil: {cat:#?}"
        );
    }

    #[test]
    fn le_tunnel_qui_transporte_et_ne_fuit_pas_passe() {
        assert!(matches!(juger(&sain()), Verdict::Etanche(_)));
    }

    /// LE test de ce module. Un endpoint mort emet ses poignees de main
    /// indefiniment: le lien porte donc des paquets chiffres, et le trafic du
    /// client tombe dans un trou noir ou il ne fuite pas. Les deux moities de
    /// l'ancien raisonnement sont reunies, et pourtant rien n'a transporte.
    #[test]
    fn un_endpoint_mort_ne_vaut_pas_un_transport() {
        let mut o = sain();
        // Les poignees de main partent, personne ne repond.
        o.avant = Compteurs {
            handshake: false,
            tx_bytes: 148,
            rx_bytes: 0,
        };
        o.apres = Compteurs {
            handshake: false,
            tx_bytes: 592,
            rx_bytes: 0,
        };
        o.banniere = Err("connexion a 10.88.0.1:7000: delai depasse".to_owned());
        let v = juger(&o);
        assert!(
            matches!(v, Verdict::Indecis(_)),
            "un trou noir ne fuite pas, ce n'est pas une etancheite: {v:?}"
        );
    }

    /// Le pair a repondu une fois, puis s'est tu. La poignee de main seule
    /// prouve le transport de la poignee de main, pas celui des donnees.
    #[test]
    fn un_pair_muet_apres_la_poignee_de_main_ne_vaut_pas_un_transport() {
        let mut o = sain();
        o.apres = Compteurs {
            handshake: true,
            tx_bytes: 1204,
            rx_bytes: o.avant.rx_bytes,
        };
        o.banniere = Err("connexion a 10.88.0.1:7000: delai depasse".to_owned());
        assert!(matches!(juger(&o), Verdict::Indecis(_)));
    }

    #[test]
    fn sans_poignee_de_main_rien_ne_se_conclut() {
        let mut o = sain();
        o.apres.handshake = false;
        let v = juger(&o);
        assert!(matches!(v, Verdict::Indecis(_)), "{v:?}");
        assert!(raison(&v).contains("poignee de main"), "{}", raison(&v));
    }

    /// Un pair mort laisse `rx_bytes` a zero quoi que le client emette. C'est
    /// la seule observation qui distingue le trou noir du tunnel vivant sans
    /// rien lire a travers lui.
    #[test]
    fn rx_bytes_a_zero_designe_nommement_le_trou_noir() {
        let mut o = sain();
        o.avant.rx_bytes = 0;
        o.apres.rx_bytes = 0;
        let v = juger(&o);
        assert!(matches!(v, Verdict::Indecis(_)), "{v:?}");
        assert!(raison(&v).contains("rx_bytes"), "{}", raison(&v));
    }

    #[test]
    fn une_banniere_non_lue_laisse_le_vecteur_indecis() {
        let mut o = sain();
        o.banniere = Err("connexion refusee".to_owned());
        let v = juger(&o);
        assert!(matches!(v, Verdict::Indecis(_)), "{v:?}");
        assert!(raison(&v).contains("connexion refusee"), "{}", raison(&v));
    }

    /// Quelque chose repond, mais ce n'est pas le pair du tunnel. Accepter
    /// n'importe quelle reponse reviendrait a mesurer "un port est ouvert".
    #[test]
    fn une_banniere_etrangere_n_est_pas_celle_du_pair() {
        let mut o = sain();
        o.banniere = Ok("SSH-2.0-OpenSSH_9.6".to_owned());
        let v = juger(&o);
        assert!(matches!(v, Verdict::Indecis(_)), "{v:?}");
        assert!(raison(&v).contains("SSH-2.0-OpenSSH_9.6"), "{}", raison(&v));
    }

    /// Toute la valeur de la banniere tient a ce qu'elle soit inobtenable
    /// autrement. Si le harnais n'a pas pu l'etablir, la lire ne prouve rien.
    #[test]
    fn une_banniere_joignable_hors_tunnel_ne_prouve_rien() {
        let mut o = sain();
        o.banniere_hors_tunnel = true;
        let v = juger(&o);
        assert!(matches!(v, Verdict::Indecis(_)), "{v:?}");
        assert!(raison(&v).contains("hors tunnel"), "{}", raison(&v));
    }

    /// La banniere est arrivee, les compteurs n'ont pas bouge: elle est donc
    /// passee par un autre chemin que le tunnel.
    #[test]
    fn des_compteurs_immobiles_pendant_la_lecture_ne_prouvent_rien() {
        let mut o = sain();
        o.apres = o.avant;
        let v = juger(&o);
        assert!(matches!(v, Verdict::Indecis(_)), "{v:?}");
        assert!(raison(&v).contains("compteurs"), "{}", raison(&v));
    }

    #[test]
    fn une_capture_muette_ne_vaut_pas_une_absence_de_fuite() {
        let mut o = sain();
        o.chiffres = 0;
        assert!(matches!(juger(&o), Verdict::Indecis(_)));
    }

    /// Le transport etabli n'excuse rien: c'est la seconde moitie du vecteur.
    #[test]
    fn une_fuite_en_clair_echoue_meme_avec_la_banniere() {
        let mut o = sain();
        o.en_clair = 3;
        let v = juger(&o);
        assert!(matches!(v, Verdict::Fuite(_)), "{v:?}");
        assert!(raison(&v).contains('3'), "{}", raison(&v));
    }

    /// Une mesure abimee de plusieurs cotes doit nommer la cause la plus
    /// proche, pas la premiere venue. Un message qui designe la mauvaise cause
    /// envoie corriger ce qui n'est pas casse.
    #[test]
    fn l_ordre_des_regles_nomme_la_cause_la_plus_proche() {
        // Capture muette ET trou noir: la capture d'abord, sans elle rien
        // n'aurait pu etre observe.
        let mut o = sain();
        o.chiffres = 0;
        o.avant.rx_bytes = 0;
        o.apres.rx_bytes = 0;
        assert!(raison(&juger(&o)).contains("capture"));

        // Trou noir ET banniere absente: le trou noir, qui explique l'autre.
        let mut o = sain();
        o.avant.rx_bytes = 0;
        o.apres.rx_bytes = 0;
        o.banniere = Err("delai depasse".to_owned());
        assert!(raison(&juger(&o)).contains("rx_bytes"));

        // Transport indecis ET fuite en clair: l'indecision d'abord. Une fuite
        // observee pendant qu'on ne sait pas si le tunnel transportait ne dit
        // pas si le kill switch est en cause ou le banc.
        let mut o = sain();
        o.apres.handshake = false;
        o.en_clair = 2;
        assert!(matches!(juger(&o), Verdict::Indecis(_)));
    }

    /// Une fuite observee pendant une mesure indecise reste une observation. Le
    /// verdict ne peut pas l'imputer, mais taire les paquets vus les ferait
    /// disparaitre du rapport: `skipped` ne porte pas de preuve, et le banc une
    /// fois repare plus personne ne saurait qu'il y avait la quelque chose a
    /// regarder.
    #[test]
    fn l_indecision_ne_fait_pas_disparaitre_les_paquets_en_clair() {
        let mut o = sain();
        o.apres.handshake = false;
        o.en_clair = 2;
        let v = juger(&o);
        assert!(matches!(v, Verdict::Indecis(_)), "{v:?}");
        assert!(raison(&v).contains("en clair observes"), "{}", raison(&v));
        assert!(raison(&v).contains('2'), "{}", raison(&v));
    }

    /// Et rien n'est ajoute quand il n'y avait rien a voir: une mention
    /// systematique se lirait comme une fuite a chaque mesure indecise.
    #[test]
    fn une_mesure_indecise_sans_fuite_n_invente_pas_de_paquets() {
        let mut o = sain();
        o.apres.handshake = false;
        let v = juger(&o);
        assert!(!raison(&v).contains("en clair observes"), "{}", raison(&v));
    }

    /// Une continuation de ligne `\` dans un litteral disparait quand rustfmt
    /// rejoint les deux lignes, et l'indentation reste alors DANS la chaine.
    /// Le code compile, les tests passent, et le message sort troue d'espaces
    /// sous les yeux de celui qui lit le rapport. Quinze messages du depot
    /// l'avaient, dont plusieurs depuis des semaines.
    #[test]
    fn aucun_message_ne_porte_de_suite_d_espaces() {
        let mut jeux = vec![sain()];
        for casse in [
            |o: &mut Observation| o.chiffres = 0,
            |o: &mut Observation| o.apres.handshake = false,
            |o: &mut Observation| o.apres.rx_bytes = 0,
            |o: &mut Observation| o.banniere = Err("delai depasse".to_owned()),
            |o: &mut Observation| o.banniere = Ok("autre".to_owned()),
            |o: &mut Observation| o.banniere_hors_tunnel = true,
            |o: &mut Observation| o.apres.tx_bytes = o.avant.tx_bytes,
            |o: &mut Observation| o.en_clair = 2,
        ] {
            let mut o = sain();
            casse(&mut o);
            jeux.push(o);
        }
        for o in jeux {
            let v = juger(&o);
            let r = raison(&v);
            assert!(!r.contains("  "), "{r}");
        }
    }

    /// Ecoute sur la boucle locale et sert `reponse` a une seule connexion,
    /// puis ferme. Sert de doublure au pair du banc.
    fn doublure(reponse: &'static str) -> SocketAddr {
        let ecouteur = TcpListener::bind("127.0.0.1:0").unwrap();
        let adresse = ecouteur.local_addr().unwrap();
        std::thread::spawn(move || {
            if let Ok((mut flux, _)) = ecouteur.accept() {
                let _ = flux.write_all(reponse.as_bytes());
            }
        });
        adresse
    }

    #[test]
    fn la_banniere_se_lit_jusqu_a_la_fermeture_du_pair() {
        let adresse = doublure(BANNIERE);
        assert_eq!(lire(adresse, Duration::from_secs(3)).unwrap(), BANNIERE);
    }

    /// Le pair ecrit une fin de ligne, comme le ferait n'importe quel serveur
    /// de banniere. La comparaison ne doit pas trebucher dessus.
    #[test]
    fn la_banniere_est_rendue_sans_ses_blancs() {
        let adresse = doublure("BIFROST-TUNNEL-OK\r\n");
        assert_eq!(lire(adresse, Duration::from_secs(3)).unwrap(), BANNIERE);
    }

    /// Personne n'ecoute: la lecture doit rendre une erreur qui NOMME la cible,
    /// puisque cette erreur devient la raison du `SKIPPED`. Une raison qui ne
    /// dit pas vers ou la lecture a echoue n'aide personne a la corriger.
    #[test]
    fn une_cible_muette_rend_une_erreur_qui_la_nomme() {
        // Un ecouteur ouvert puis ferme: le port est certainement libre, alors
        // qu'un port choisi au hasard pourrait etre pris par un autre test.
        let ecouteur = TcpListener::bind("127.0.0.1:0").unwrap();
        let adresse = ecouteur.local_addr().unwrap();
        drop(ecouteur);
        let e = lire(adresse, Duration::ZERO).unwrap_err();
        assert!(e.contains(&adresse.to_string()), "{e}");
    }

    /// Un pair qui accepte puis ferme sans rien dire n'a pas servi de banniere
    /// vide: il n'en a pas servi du tout. La distinction porte le verdict, une
    /// banniere vide serait jugee "inattendue" et enverrait chercher un
    /// serveur pirate la ou il n'y a qu'un serveur pas encore pret.
    #[test]
    fn un_pair_qui_ferme_sans_rien_ecrire_n_a_pas_servi_de_banniere() {
        let adresse = doublure("");
        let e = lire(adresse, Duration::ZERO).unwrap_err();
        assert!(e.contains("sans rien ecrire"), "{e}");
    }

    /// La fenetre couvre un pair pas encore pret, et une fenetre nulle ne
    /// reessaie pas. Les deux se mesurent sur la meme doublure: elle se tait a
    /// la premiere connexion et sert la banniere a la seconde.
    #[test]
    fn la_fenetre_distingue_pas_encore_pret_de_jamais() {
        fn tardive() -> SocketAddr {
            let ecouteur = TcpListener::bind("127.0.0.1:0").unwrap();
            let adresse = ecouteur.local_addr().unwrap();
            std::thread::spawn(move || {
                for (n, flux) in ecouteur.incoming().enumerate() {
                    let Ok(mut flux) = flux else { return };
                    if n > 0 {
                        let _ = flux.write_all(BANNIERE.as_bytes());
                    }
                }
            });
            adresse
        }

        // Une seule tentative: elle tombe sur le silence et renonce.
        assert!(lire(tardive(), Duration::ZERO).is_err());
        // Avec une fenetre, la seconde tentative aboutit.
        assert_eq!(
            lire(tardive(), Duration::from_secs(3)).unwrap(),
            BANNIERE,
            "un pair pas encore pret doit avoir droit a une seconde tentative"
        );
    }

    /// La regle doit jeter ce qui n'arrive PAS par le tunnel. Ecrite a
    /// l'envers elle jetterait exactement le trafic legitime, et le vecteur se
    /// declarerait indecis a chaque execution sans que personne comprenne
    /// pourquoi.
    #[test]
    fn la_regle_jette_ce_qui_n_arrive_pas_par_le_tunnel() {
        let r = nft_banniere("wgs", 7000);
        assert!(r.contains("tcp dport 7000"), "{r}");
        assert!(
            r.contains("iifname != \"wgs\" counter drop"),
            "la regle doit jeter les AUTRES interfaces: {r}"
        );
        assert!(r.contains("hook input"), "{r}");
    }

    /// Le retrait doit viser la table que la pose a creee. Deux noms
    /// differents laisseraient la regle en place dans un namespace que le banc
    /// reutilise.
    #[test]
    fn le_retrait_vise_la_table_posee() {
        let pose = nft_banniere("wgs", 7000);
        let retrait = nft_banniere_teardown();
        assert!(pose.contains("table inet banniere"));
        assert!(retrait.contains("delete table inet banniere"));
    }

    /// Les compteurs traversent une frontiere de processus: le harnais les lit
    /// dans un namespace, en relancant le binaire. Le format doit donc etre
    /// stable, et l'aller-retour est la seule facon de le verrouiller.
    #[test]
    fn les_compteurs_font_l_aller_retour_json() {
        let c = Compteurs {
            handshake: true,
            tx_bytes: 516,
            rx_bytes: 444,
        };
        let json = serde_json::to_string(&c).unwrap();
        assert_eq!(serde_json::from_str::<Compteurs>(&json).unwrap(), c);
    }
}
