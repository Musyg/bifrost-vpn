//! Le trou que `block-dns` ne bouche pas.
//!
//! Le kill switch pose deux filtres sur le port 53: un qui laisse passer vers
//! le resolveur local, un qui bloque tout le reste. Un navigateur qui resout en
//! DoH ne touche jamais ce port. Sa requete est du HTTPS vers le 443, elle
//! traverse les deux filtres sans les rencontrer, et le vecteur `dns-leak`,
//! qui regarde le 53 sur le lien physique, rend PASSED pendant que la
//! resolution se fait ailleurs.
//!
//! Le document 01 partie 106 le pose comme une exigence: "sur Windows,
//! desactiver le DoH interne qui contourne les regles". Rien ne l'implementait.
//!
//! # Ce que ce vecteur etablit, et ce qu'il n'etablit pas
//!
//! Il lit des configurations, il n'observe pas de paquets. Il etablit donc
//! qu'aucun contournement n'est CONFIGURE, pas qu'aucun contournement ne se
//! produit. Un navigateur portable lance depuis une cle USB, ou un binaire qui
//! embarque son propre resolveur, sortent de sa portee. La distinction est
//! dans le verdict: il parle de pincage, pas d'etancheite.
//!
//! # Pourquoi "desactive" ne suffit pas
//!
//! Trois etats different et un seul est acceptable. Une politique HKLM qui
//! coupe le DoH tient, l'utilisateur ne peut pas la defaire. Un reglage a
//! "automatique" fonctionne aujourd'hui parce que notre resolveur est sur la
//! boucle locale et qu'aucun fournisseur DoH connu ne s'y trouve: la protection
//! ne vient alors pas de ce que nous avons pose, mais de la liste interne du
//! navigateur. Et une absence de politique laisse s'appliquer un defaut que
//! nous ne controlons pas. Les deux derniers ne sont pas des fuites, ce sont
//! des configurations non pincees, et les compter comme des succes reviendrait
//! a annoncer prouve ce qui n'est qu'heureux.

/// Ce qu'un client DoH est configure pour faire.
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Etat {
    /// Pas installe: sa configuration ne peut rien contourner.
    Absent,
    /// DoH coupe par une politique machine, hors de portee de l'utilisateur.
    Verrouille,
    /// DoH coupe, mais rien n'empeche de le rallumer dans l'interface.
    Deverrouille,
    /// DoH actif vers le resolveur local: la resolution reste pincee.
    Local,
    /// DoH actif vers un resolveur qui n'est pas le notre.
    Externe(String),
    /// Installe, aucune politique: le defaut du client s'applique.
    SansPolitique,
    /// Une politique existe, mais sa valeur ne se lit pas. Ne pas savoir n'est
    /// pas un pincage: c'est exactement le cas ou annoncer PASSED serait un
    /// mensonge confortable.
    Inattendu(String),
}

/// Un client capable de resoudre en DoH, et l'etat ou on l'a trouve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Client {
    pub nom: &'static str,
    pub etat: Etat,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Tous les clients presents sont pinces.
    Pince(String),
    /// Rien ne permet de conclure.
    Indecis(String),
    /// Au moins un client peut resoudre hors du resolveur local.
    Contournable(String),
}

/// Les phrases du verdict DoH, chacune au catalogue (5q).
///
/// `juger` ne compose plus sa raison en ligne: chaque phrase - les quatre
/// fautes de contournement, l'indecision, le pincage - vit ici, sous les gardes
/// de forme et de distinction de [`tests`]. Le juge tourne sur les deux
/// plateformes (Linux par `doh_fichiers`, Windows par `doh_registre`), donc son
/// catalogue est ici, dans le module du juge, plutot que dans l'un des deux
/// catalogues de plateforme. La donnee (nom du client, cause) reste un
/// argument; aucune phrase ne change.
pub mod motifs {
    /// Aucun client n'a ete inspecte: une liste vide ne prouve rien.
    pub fn aucun_client() -> String {
        "aucun client DoH inspecte: rien n'a ete regarde, et une liste vide ne vaut pas une absence de contournement"
            .to_owned()
    }

    /// Un client resout deja en DoH vers un tiers.
    pub fn resout_vers(client: &str, url: &str) -> String {
        format!("{client} resout en DoH vers {url}")
    }

    /// Une politique existe, mais sa valeur ne se lit pas.
    pub fn politique_illisible(client: &str, cause: &str) -> String {
        format!("{client}: {cause}, donc rien n'etablit qu'il soit pince")
    }

    /// Aucune politique: le defaut du client s'applique.
    pub fn sans_politique(client: &str) -> String {
        format!(
            "{client} n'a aucune politique DoH: son defaut s'applique, et nous ne le controlons pas"
        )
    }

    /// DoH coupe mais non verrouille: un reglage le rallume.
    pub fn coupe_non_verrouille(client: &str) -> String {
        format!("{client} a le DoH coupe mais non verrouille: un reglage le rallume")
    }

    /// Tous les clients inspectes sont absents: rien a pincer ici.
    pub fn tous_absents(absents: usize) -> String {
        format!(
            "{absents} client(s) DoH inspecte(s), tous NON INSTALLES: il n'y a rien a pincer sur cette machine, donc rien qui etablisse qu'une protection soit en place"
        )
    }

    /// Tous les clients presents sont pinces.
    pub fn tous_pinces(total: usize, verrouilles: usize, locaux: usize, absents: usize) -> String {
        format!(
            "{total} client(s) inspecte(s): {verrouilles} verrouille(s) par politique machine, {locaux} pointe(s) sur le resolveur local, {absents} non installe(s). Aucun ne peut resoudre hors du resolveur local"
        )
    }
}

/// Conclut a partir des clients inspectes.
///
/// Les fautes sont nommees de la plus grave a la moindre. Un message qui
/// commence par le defaut le plus benin envoie corriger ce qui ne l'est pas:
/// verrouiller un Firefox deja coupe pendant qu'un Chrome parle a un tiers.
pub fn juger(clients: &[Client]) -> Verdict {
    if clients.is_empty() {
        return Verdict::Indecis(motifs::aucun_client());
    }

    let mut fautes: Vec<String> = Vec::new();
    // 1. Une resolution qui part deja chez un tiers, sur le 443, sans jamais
    //    toucher le port que le kill switch filtre.
    for c in clients {
        if let Etat::Externe(url) = &c.etat {
            fautes.push(motifs::resout_vers(c.nom, url));
        }
    }
    // 2. Une politique existe mais ne se lit pas. Ne pas savoir ou ira la
    //    resolution n'est pas la meme chose que savoir qu'elle reste chez nous.
    for c in clients {
        if let Etat::Inattendu(quoi) = &c.etat {
            fautes.push(motifs::politique_illisible(c.nom, quoi));
        }
    }
    // 3. Aucune politique: le defaut du client decide. Celui de Chrome et
    // d'Edge est "automatique", donc capable de DoH des maintenant.
    for c in clients {
        if c.etat == Etat::SansPolitique {
            fautes.push(motifs::sans_politique(c.nom));
        }
    }
    // 4. Coupe mais pas verrouille: rien ne sort aujourd'hui, et rien
    //    n'empeche que cela change sans que personne le remarque.
    for c in clients {
        if c.etat == Etat::Deverrouille {
            fautes.push(motifs::coupe_non_verrouille(c.nom));
        }
    }
    if !fautes.is_empty() {
        // Le separateur est joint AVANT le verdict: un litteral dans l'argument
        // d'un verdict, meme le "; " d'un `join`, ferait rougir la garde de
        // source qui refuse toute raison composee en ligne, comme pour le
        // rapport de phase de reconnect-window. Les fautes viennent du catalogue.
        let raison = fautes.join("; ");
        return Verdict::Contournable(raison);
    }

    let verrouilles = compter(clients, |e| *e == Etat::Verrouille);
    let locaux = compter(clients, |e| *e == Etat::Local);
    let absents = compter(clients, |e| *e == Etat::Absent);

    // Aucun client pince, aucun fautif: il ne restait que des absents. Rien
    // n'a ete mesure ici, et l'annoncer PASSED serait exactement le succes que
    // ce module refuse ailleurs - un succes qui ne doit rien a une protection.
    // Une machine sans navigateur ne peut effectivement pas fuir par ce
    // chemin, mais elle ne dit rien de celles qui en ont, et c'est un rapport
    // sur la machine QU'ON REGARDE qu'on attend.
    if verrouilles + locaux == 0 {
        return Verdict::Indecis(motifs::tous_absents(absents));
    }

    Verdict::Pince(motifs::tous_pinces(
        clients.len(),
        verrouilles,
        locaux,
        absents,
    ))
}

fn compter(clients: &[Client], p: impl Fn(&Etat) -> bool) -> usize {
    clients.iter().filter(|c| p(&c.etat)).count()
}

/// Hote d'une URL, sans schema, sans utilisateur, sans port, crochets IPv6
/// retires. Ecrit a la main: ajouter une dependance d'analyse d'URL a un
/// produit de securite pour en extraire un hote serait cher paye.
pub fn hote(url: &str) -> Option<&str> {
    let sans_schema = url.split_once("//").map_or(url, |(_, r)| r);
    let autorite = sans_schema
        .split(['/', '?', '#'])
        .next()
        .filter(|a| !a.is_empty())?;
    // L'utilisateur precede l'arobase, l'hote suit. Prendre le premier
    // morceau ferait passer https://127.0.0.1@dns.hostile/ pour un renvoi
    // vers la boucle locale, ce qui est exactement le deguisement.
    let hote = autorite.rsplit_once('@').map_or(autorite, |(_, h)| h);
    // Litteral IPv6: le port vient apres le crochet fermant, et les deux
    // points a l'interieur ne le separent pas.
    if let Some(fin) = hote.strip_prefix('[') {
        return fin.split_once(']').map(|(h, _)| h);
    }
    Some(hote.split_once(':').map_or(hote, |(h, _)| h))
}

/// Vrai quand l'URL designe exactement le resolveur que Bifrost a pose.
pub fn pointe_vers(url: &str, resolveur: IpAddr) -> bool {
    // Comparaison d'adresses, pas de chaines: 127.0.0.10 commence par
    // 127.0.0.1 et n'est pas la meme machine.
    hote(url).and_then(|h| h.parse::<IpAddr>().ok()) == Some(resolveur)
}

/// Chrome et Edge partagent la meme politique: `DnsOverHttpsMode` en chaine,
/// `DnsOverHttpsTemplates` pour la cible.
pub fn interpreter_chromium(
    installe: bool,
    mode: Option<&str>,
    gabarit: Option<&str>,
    resolveur: IpAddr,
) -> Etat {
    if !installe {
        return Etat::Absent;
    }
    let Some(mode) = mode else {
        return Etat::SansPolitique;
    };
    match mode {
        "off" => Etat::Verrouille,
        // `secure` resout UNIQUEMENT en DoH: le gabarit dit ou, et son absence
        // est une configuration que Chrome refuse autant que nous.
        "secure" => match gabarit {
            Some(g) if pointe_vers(g, resolveur) => Etat::Local,
            Some(g) => Etat::Externe(g.to_owned()),
            None => Etat::Inattendu(
                "mode 'secure' sans DnsOverHttpsTemplates: rien n'etablit vers \
                 quel resolveur les requetes partiraient"
                    .to_owned(),
            ),
        },
        // `automatic` tente le DoH et retombe en clair. Sans gabarit il ne
        // trouve rien sur la boucle locale et retombe donc chez nous, mais
        // c'est la liste interne du navigateur qui en decide, pas nous.
        "automatic" => match gabarit {
            Some(g) if pointe_vers(g, resolveur) => Etat::Local,
            Some(g) => Etat::Externe(g.to_owned()),
            None => Etat::Deverrouille,
        },
        autre => Etat::Inattendu(format!("valeur DnsOverHttpsMode inattendue '{autre}'")),
    }
}

/// Firefox: les valeurs `Enabled`, `Locked` et `ProviderURL` sous la cle
/// `DNSOverHTTPS`.
pub fn interpreter_firefox(
    installe: bool,
    active: Option<u32>,
    verrou: Option<u32>,
    url: Option<&str>,
    resolveur: IpAddr,
) -> Etat {
    if !installe {
        return Etat::Absent;
    }
    match active {
        None => Etat::SansPolitique,
        // Le verrou ne vaut que sur un DoH deja coupe. Pose sur un DoH actif
        // il verrouille le contournement au lieu de le corriger.
        Some(0) if verrou == Some(1) => Etat::Verrouille,
        Some(0) => Etat::Deverrouille,
        Some(1) => match url {
            Some(u) if pointe_vers(u, resolveur) => Etat::Local,
            Some(u) => Etat::Externe(u.to_owned()),
            None => Etat::Externe("fournisseur par defaut de Firefox".to_owned()),
        },
        Some(v) => Etat::Inattendu(format!("valeur DNSOverHTTPS\\Enabled inattendue '{v}'")),
    }
}

/// Le client DNS de Windows lui-meme, via `EnableAutoDoh`. Toujours present:
/// il n'y a pas de cas "non installe".
pub fn interpreter_windows(auto_doh: Option<u32>) -> Etat {
    match auto_doh {
        None => Etat::SansPolitique,
        Some(0) => Etat::Verrouille,
        // Non nul: le client peut promouvoir en DoH les resolveurs qu'il
        // reconnait. Le notre est sur la boucle locale et n'y figure pas, donc
        // rien ne monte aujourd'hui. La encore, ce n'est pas nous qui l'assurons.
        Some(_) => Etat::Deverrouille,
    }
}

/// Le mode et le gabarit declares par un fichier de politique Chromium.
///
/// Sous Linux ces politiques sont des fichiers JSON plats, un objet dont les
/// clefs sont les noms de politique. Une erreur ici n'est pas une absence: un
/// fichier pose mais illisible ne dit pas que le DoH est coupe, il dit qu'on
/// ne sait pas, et [`Etat::Inattendu`] est fait pour ca.
pub fn chromium_depuis_json(texte: &str) -> Result<(Option<String>, Option<String>), String> {
    let valeur: serde_json::Value =
        serde_json::from_str(texte).map_err(|e| format!("JSON invalide: {e}"))?;
    let objet = valeur
        .as_object()
        .ok_or_else(|| "le fichier de politique n'est pas un objet JSON".to_owned())?;
    let chaine = |clef: &str| match objet.get(clef) {
        None => Ok(None),
        Some(serde_json::Value::String(s)) => Ok(Some(s.clone())),
        Some(autre) => Err(format!("{clef} vaut {autre}, une chaine etait attendue")),
    };
    Ok((
        chaine("DnsOverHttpsMode")?,
        chaine("DnsOverHttpsTemplates")?,
    ))
}

/// Ce qu'un `policies.json` declare sous `DNSOverHTTPS`: actif, verrouille, et
/// vers quel fournisseur.
pub type PolitiqueFirefox = (Option<bool>, Option<bool>, Option<String>);

/// `Enabled`, `Locked` et `ProviderURL` sous `policies.DNSOverHTTPS`.
///
/// Les valeurs sont des booleens JSON la ou le registre Windows porte des
/// DWORD; la conversion est faite par l'appelant, qui sait de quel monde il
/// vient.
pub fn firefox_depuis_json(texte: &str) -> Result<PolitiqueFirefox, String> {
    let valeur: serde_json::Value =
        serde_json::from_str(texte).map_err(|e| format!("JSON invalide: {e}"))?;
    // Un policies.json qui ne parle pas de DoH ne dit rien, et ne rien dire
    // n'est pas une erreur: c'est l'absence de politique, que l'appelant sait
    // deja traduire.
    let Some(doh) = valeur.get("policies").and_then(|p| p.get("DNSOverHTTPS")) else {
        return Ok((None, None, None));
    };
    let booleen = |clef: &str| match doh.get(clef) {
        None => Ok(None),
        Some(serde_json::Value::Bool(b)) => Ok(Some(*b)),
        Some(autre) => Err(format!(
            "DNSOverHTTPS.{clef} vaut {autre}, un booleen etait attendu"
        )),
    };
    let url = match doh.get("ProviderURL") {
        None => None,
        Some(serde_json::Value::String(s)) => Some(s.clone()),
        Some(autre) => {
            return Err(format!(
                "DNSOverHTTPS.ProviderURL vaut {autre}, une chaine etait attendue"
            ));
        }
    };
    Ok((booleen("Enabled")?, booleen("Locked")?, url))
}

/// Reunit une meme clef declaree par plusieurs fichiers du repertoire
/// `managed`.
///
/// Chrome lit TOUS les fichiers de ce repertoire. Deux fichiers qui declarent
/// des valeurs differentes laissent le resultat dependre d'un ordre que rien
/// ne garantit: ce n'est pas un choix, c'est une ignorance, et elle doit se
/// dire. Le cas n'existe pas sous Windows, ou la valeur est unique par clef.
pub fn fusionner(clef: &str, trouvailles: &[(String, String)]) -> Result<Option<String>, String> {
    let Some((premier_fichier, premiere_valeur)) = trouvailles.first() else {
        return Ok(None);
    };
    for (fichier, valeur) in &trouvailles[1..] {
        if valeur != premiere_valeur {
            // Litteral sur une seule ligne, volontairement. Une continuation
            // `\` ici disparaitrait au passage de rustfmt en laissant
            // l'indentation DANS la chaine, defaut qui a troue quinze messages
            // du depot avant d'etre vu.
            return Err(format!(
                "{clef} vaut '{premiere_valeur}' dans {premier_fichier} et '{valeur}' dans {fichier}: Chrome lit les deux fichiers et rien ne dit lequel gagne"
            ));
        }
    }
    Ok(Some(premiere_valeur.clone()))
}

/// L'etat d'un client en une ligne lisible, pour le releve joint au verdict.
///
/// Partage par les deux lecteurs: un rapport qui nommerait les memes etats
/// differemment selon la plateforme se relirait mal.
pub fn decrire(etat: &Etat) -> String {
    match etat {
        Etat::Absent => "non installe".to_owned(),
        Etat::Verrouille => "DoH coupe par politique machine".to_owned(),
        Etat::Deverrouille => "DoH coupe mais non verrouille".to_owned(),
        Etat::Local => "DoH vers le resolveur local".to_owned(),
        Etat::Externe(cible) => format!("DoH vers {cible}"),
        Etat::SansPolitique => "aucune politique".to_owned(),
        Etat::Inattendu(quoi) => format!("illisible: {quoi}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client(nom: &'static str, etat: Etat) -> Client {
        Client { nom, etat }
    }

    fn raison(v: &Verdict) -> String {
        match v {
            Verdict::Pince(r) | Verdict::Indecis(r) | Verdict::Contournable(r) => r.clone(),
        }
    }

    /// Tout ce que ce juge sait dire, rendu sans machine: chaque phrase du
    /// verdict avec une donnee representative. Les deux gardes ci-dessous
    /// s'appuient dessus, comme les catalogues de plateforme sur le leur (5q).
    fn catalogue() -> Vec<(&'static str, String)> {
        vec![
            ("doh/aucun-client", motifs::aucun_client()),
            (
                "doh/resout-vers",
                motifs::resout_vers("chrome", "https://dns.tiers.example/dns-query"),
            ),
            (
                "doh/politique-illisible",
                motifs::politique_illisible("edge", "valeur de politique non lue"),
            ),
            ("doh/sans-politique", motifs::sans_politique("firefox")),
            (
                "doh/coupe-non-verrouille",
                motifs::coupe_non_verrouille("windows"),
            ),
            ("doh/tous-absents", motifs::tous_absents(2)),
            ("doh/tous-pinces", motifs::tous_pinces(3, 1, 1, 1)),
        ]
    }

    /// La forme, tenue par la meme fonction que les catalogues de plateforme.
    #[test]
    fn aucune_phrase_doh_n_est_vide_ni_trouee_d_espaces() {
        super::super::forme_des_messages(&catalogue());
    }

    /// Deux phrases de verdict distinctes ne doivent pas se lire pareil.
    #[test]
    fn deux_phrases_doh_ne_se_lisent_pas_pareil() {
        let cat = catalogue();
        let distinctes: std::collections::BTreeSet<&str> =
            cat.iter().map(|(_, m)| m.as_str()).collect();
        assert_eq!(
            distinctes.len(),
            cat.len(),
            "deux phrases DoH se lisent pareil: {cat:#?}"
        );
    }

    /// Aucun client inspecte n'est pas un succes: c'est une mesure qui n'a rien
    /// regarde. La distinction est la raison d'etre de `Indecis`.
    #[test]
    fn une_liste_vide_ne_prouve_rien() {
        assert!(matches!(juger(&[]), Verdict::Indecis(_)));
    }

    /// Un client absent ne peut rien contourner - mais une machine ou aucun
    /// navigateur n'est installe n'a rien mesure, et ne se declare pas pincee.
    ///
    /// La recette posait l'inverse jusqu'au 23 aout 2026. Sur essai-linux,
    /// `chrome` et `edge` ne sont pas installes: ils comptaient donc pour deux
    /// succes dans un verdict PASSED, a cote d'une politique deposee deux
    /// jours plus tot. Le vert ne mesurait pas une protection, il mesurait un
    /// reste et deux absences. Un succes doit reposer sur au moins un client
    /// REELLEMENT pince.
    #[test]
    fn des_clients_tous_absents_ne_prouvent_rien() {
        let v = juger(&[
            client("chrome", Etat::Absent),
            client("firefox", Etat::Absent),
        ]);
        assert!(matches!(v, Verdict::Indecis(_)), "{v:?}");
        // Et l'absence est DITE, pas escamotee derriere un verdict.
        assert!(raison(&v).contains("NON INSTALLES"), "{}", raison(&v));
    }

    /// Le seul etat pleinement acceptable, avec le DoH pointe sur nous.
    #[test]
    fn verrouille_et_local_sont_pinces() {
        let v = juger(&[
            client("chrome", Etat::Verrouille),
            client("windows", Etat::Local),
            client("edge", Etat::Absent),
        ]);
        assert!(matches!(v, Verdict::Pince(_)), "{v:?}");
    }

    /// Un DoH externe est le contournement le plus direct: la resolution part
    /// chez un tiers, sur le 443, sans jamais toucher le port que nous filtrons.
    #[test]
    fn un_resolveur_externe_est_un_contournement() {
        let v = juger(&[client(
            "firefox",
            Etat::Externe("https://mozilla.cloudflare-dns.com/dns-query".to_owned()),
        )]);
        assert!(matches!(v, Verdict::Contournable(_)), "{v:?}");
        assert!(raison(&v).contains("firefox"), "{}", raison(&v));
        assert!(raison(&v).contains("cloudflare"), "{}", raison(&v));
    }

    /// Desactive sans verrou: rien ne fuit aujourd'hui, mais la configuration
    /// n'est pas pincee et un seul clic la defait.
    #[test]
    fn deverrouille_ne_passe_pas() {
        let v = juger(&[client("firefox", Etat::Deverrouille)]);
        assert!(matches!(v, Verdict::Contournable(_)), "{v:?}");
    }

    /// Aucune politique: c'est le defaut du client qui decide, et nous ne le
    /// controlons pas.
    #[test]
    fn sans_politique_ne_passe_pas() {
        let v = juger(&[client("chrome", Etat::SansPolitique)]);
        assert!(matches!(v, Verdict::Contournable(_)), "{v:?}");
    }

    /// Plusieurs defauts a la fois: le message doit nommer le plus grave en
    /// premier. Envoyer verrouiller Firefox pendant que Chrome parle a un
    /// tiers ferait corriger le mauvais.
    #[test]
    fn le_message_nomme_le_plus_grave_en_premier() {
        let v = juger(&[
            client("firefox", Etat::Deverrouille),
            client("edge", Etat::SansPolitique),
            client(
                "chrome",
                Etat::Externe("https://dns.google/dns-query".to_owned()),
            ),
        ]);
        let r = raison(&v);
        let externe = r.find("chrome").expect("chrome absent du message");
        let deverrouille = r.find("firefox").expect("firefox absent du message");
        let sans = r.find("edge").expect("edge absent du message");
        assert!(externe < sans, "{r}");
        assert!(sans < deverrouille, "{r}");
    }

    /// Un client pince ne doit pas etre cite parmi les fautifs.
    #[test]
    fn les_clients_pinces_ne_sont_pas_denonces() {
        let v = juger(&[
            client("chrome", Etat::Verrouille),
            client("firefox", Etat::SansPolitique),
        ]);
        assert!(!raison(&v).contains("chrome"), "{}", raison(&v));
    }

    const LOCAL: IpAddr = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);

    #[test]
    fn l_hote_se_lit_a_travers_les_formes_d_url() {
        assert_eq!(hote("https://127.0.0.1/dns-query"), Some("127.0.0.1"));
        assert_eq!(hote("https://127.0.0.1:8443/dns-query"), Some("127.0.0.1"));
        assert_eq!(hote("https://[::1]/dns-query"), Some("::1"));
        assert_eq!(hote("https://[::1]:443/dns-query"), Some("::1"));
        assert_eq!(hote("https://dns.google/dns-query"), Some("dns.google"));
        // Un utilisateur devant l'arobase ne doit pas passer pour l'hote:
        // c'est la forme meme qui deguise une URL hostile en URL familiere.
        assert_eq!(hote("https://127.0.0.1@dns.evil/q"), Some("dns.evil"));
        assert_eq!(hote(""), None);
    }

    #[test]
    fn un_nom_de_domaine_ne_pointe_pas_vers_le_resolveur_local() {
        assert!(pointe_vers("https://127.0.0.1/dns-query", LOCAL));
        assert!(!pointe_vers("https://dns.google/dns-query", LOCAL));
        // Le piege du prefixe: 127.0.0.10 n'est pas 127.0.0.1.
        assert!(!pointe_vers("https://127.0.0.10/dns-query", LOCAL));
    }

    #[test]
    fn chromium_absent_ou_coupe() {
        assert_eq!(interpreter_chromium(false, None, None, LOCAL), Etat::Absent);
        assert_eq!(
            interpreter_chromium(true, Some("off"), None, LOCAL),
            Etat::Verrouille
        );
        assert_eq!(
            interpreter_chromium(true, None, None, LOCAL),
            Etat::SansPolitique
        );
    }

    /// "automatic" marche aujourd'hui parce qu'aucun fournisseur DoH connu
    /// n'est sur la boucle locale. Ce n'est pas nous qui l'assurons.
    #[test]
    fn chromium_automatique_n_est_pas_un_pincage() {
        assert_eq!(
            interpreter_chromium(true, Some("automatic"), None, LOCAL),
            Etat::Deverrouille
        );
        assert_eq!(
            interpreter_chromium(
                true,
                Some("automatic"),
                Some("https://127.0.0.1/dns-query"),
                LOCAL
            ),
            Etat::Local
        );
    }

    #[test]
    fn chromium_secure_suit_son_gabarit() {
        assert_eq!(
            interpreter_chromium(
                true,
                Some("secure"),
                Some("https://127.0.0.1/dns-query"),
                LOCAL
            ),
            Etat::Local
        );
        assert!(matches!(
            interpreter_chromium(
                true,
                Some("secure"),
                Some("https://dns.google/dns-query"),
                LOCAL
            ),
            Etat::Externe(_)
        ));
        // `secure` sans gabarit: rien n'etablit ou Chrome ira resoudre.
        assert!(matches!(
            interpreter_chromium(true, Some("secure"), None, LOCAL),
            Etat::Inattendu(_)
        ));
    }

    #[test]
    fn une_valeur_de_mode_inconnue_ne_passe_pas_pour_un_pincage() {
        assert!(matches!(
            interpreter_chromium(true, Some("peut-etre"), None, LOCAL),
            Etat::Inattendu(_)
        ));
    }

    #[test]
    fn firefox_distingue_le_verrou() {
        assert_eq!(
            interpreter_firefox(false, None, None, None, LOCAL),
            Etat::Absent
        );
        assert_eq!(
            interpreter_firefox(true, Some(0), Some(1), None, LOCAL),
            Etat::Verrouille
        );
        assert_eq!(
            interpreter_firefox(true, Some(0), None, None, LOCAL),
            Etat::Deverrouille
        );
        assert_eq!(
            interpreter_firefox(true, None, None, None, LOCAL),
            Etat::SansPolitique
        );
    }

    #[test]
    fn firefox_actif_suit_son_fournisseur() {
        assert_eq!(
            interpreter_firefox(
                true,
                Some(1),
                Some(1),
                Some("https://127.0.0.1/dns-query"),
                LOCAL
            ),
            Etat::Local
        );
        // Actif sans URL: Firefox retombe sur son fournisseur par defaut, qui
        // n'est pas le notre.
        assert!(matches!(
            interpreter_firefox(true, Some(1), Some(1), None, LOCAL),
            Etat::Externe(_)
        ));
    }

    /// Un verrou pose sur un DoH ACTIF verrouille le contournement, il ne le
    /// corrige pas. Confondre les deux ferait passer le pire des cas.
    #[test]
    fn un_verrou_sur_un_doh_actif_ne_le_rend_pas_acceptable() {
        assert!(matches!(
            interpreter_firefox(
                true,
                Some(1),
                Some(1),
                Some("https://dns.google/dns-query"),
                LOCAL
            ),
            Etat::Externe(_)
        ));
    }

    #[test]
    fn le_client_dns_de_windows() {
        assert_eq!(interpreter_windows(Some(0)), Etat::Verrouille);
        assert_eq!(interpreter_windows(Some(2)), Etat::Deverrouille);
        assert_eq!(interpreter_windows(None), Etat::SansPolitique);
    }

    /// Une continuation de ligne `\` dans un litteral disparait quand rustfmt
    /// rejoint les deux lignes, et l'indentation reste alors DANS la chaine.
    /// Le code compile, les tests passent, et le message sort troue d'espaces
    /// sous les yeux de celui qui lit le rapport. Quinze messages du depot
    /// l'avaient, dont plusieurs depuis des semaines.
    #[test]
    fn aucun_message_ne_porte_de_suite_d_espaces() {
        let jeux: Vec<Vec<Client>> = vec![
            vec![],
            vec![
                client("chrome", Etat::Verrouille),
                client("edge", Etat::Local),
            ],
            vec![client("chrome", Etat::SansPolitique)],
            vec![client("firefox", Etat::Deverrouille)],
            vec![client(
                "edge",
                Etat::Externe("https://dns.google/q".to_owned()),
            )],
            vec![client("chrome", Etat::Inattendu("mode 'x'".to_owned()))],
        ];
        for jeu in jeux {
            let r = raison(&juger(&jeu));
            assert!(!r.contains("  "), "{r}");
        }
    }

    /// Une valeur illisible doit ressortir dans le verdict, pas s'y dissoudre.
    #[test]
    fn un_etat_inattendu_est_un_contournement() {
        let v = juger(&[client(
            "chrome",
            Etat::Inattendu("mode 'peut-etre'".to_owned()),
        )]);
        assert!(matches!(v, Verdict::Contournable(_)), "{v:?}");
        assert!(raison(&v).contains("peut-etre"), "{}", raison(&v));
    }

    fn trouvaille(fichier: &str, valeur: &str) -> (String, String) {
        (fichier.to_owned(), valeur.to_owned())
    }

    #[test]
    fn une_politique_chromium_se_lit() {
        let j = r#"{"DnsOverHttpsMode": "off", "AutoplayAllowed": true}"#;
        assert_eq!(
            chromium_depuis_json(j).unwrap(),
            (Some("off".to_owned()), None)
        );
        let j = r#"{"DnsOverHttpsMode":"secure","DnsOverHttpsTemplates":"https://127.0.0.1/dns-query"}"#;
        assert_eq!(
            chromium_depuis_json(j).unwrap(),
            (
                Some("secure".to_owned()),
                Some("https://127.0.0.1/dns-query".to_owned())
            )
        );
        // Un fichier sans politique DoH n'est pas une erreur: il ne dit rien.
        assert_eq!(chromium_depuis_json("{}").unwrap(), (None, None));
    }

    /// Un fichier pose mais illisible ne dit pas que le DoH est coupe. Le
    /// confondre avec une absence transformerait une machine mal configuree en
    /// machine pincee.
    #[test]
    fn une_politique_chromium_illisible_est_une_erreur() {
        assert!(chromium_depuis_json("{ pas du json").is_err());
        // Un tableau n'est pas un objet de politiques.
        assert!(chromium_depuis_json("[]").is_err());
        // La bonne clef avec le mauvais type ne se lit pas davantage.
        assert!(chromium_depuis_json(r#"{"DnsOverHttpsMode": 3}"#).is_err());
    }

    #[test]
    fn une_politique_firefox_se_lit() {
        let j = r#"{"policies":{"DNSOverHTTPS":{"Enabled":false,"Locked":true}}}"#;
        assert_eq!(
            firefox_depuis_json(j).unwrap(),
            (Some(false), Some(true), None)
        );
        let j = r#"{"policies":{"DNSOverHTTPS":{"Enabled":true,"ProviderURL":"https://dns.google/dns-query"}}}"#;
        assert_eq!(
            firefox_depuis_json(j).unwrap(),
            (
                Some(true),
                None,
                Some("https://dns.google/dns-query".to_owned())
            )
        );
        // Un policies.json qui ne parle pas de DoH ne dit rien, sans erreur.
        assert_eq!(
            firefox_depuis_json(r#"{"policies":{"DisableTelemetry":true}}"#).unwrap(),
            (None, None, None)
        );
        assert_eq!(firefox_depuis_json("{}").unwrap(), (None, None, None));
    }

    #[test]
    fn une_politique_firefox_illisible_est_une_erreur() {
        assert!(firefox_depuis_json("{ pas du json").is_err());
        // `Enabled` en chaine plutot qu'en booleen: la valeur ne se lit pas.
        assert!(
            firefox_depuis_json(r#"{"policies":{"DNSOverHTTPS":{"Enabled":"false"}}}"#).is_err()
        );
    }

    #[test]
    fn plusieurs_fichiers_qui_disent_la_meme_chose_se_reunissent() {
        assert_eq!(fusionner("DnsOverHttpsMode", &[]).unwrap(), None);
        assert_eq!(
            fusionner("DnsOverHttpsMode", &[trouvaille("10-dns.json", "off")]).unwrap(),
            Some("off".to_owned())
        );
        assert_eq!(
            fusionner(
                "DnsOverHttpsMode",
                &[
                    trouvaille("10-dns.json", "off"),
                    trouvaille("99-local.json", "off")
                ]
            )
            .unwrap(),
            Some("off".to_owned())
        );
    }

    /// Deux fichiers qui se contredisent: Chrome les lit tous les deux et rien
    /// ne dit lequel gagne. Choisir le premier venu serait inventer une regle.
    #[test]
    fn deux_fichiers_qui_se_contredisent_ne_se_reunissent_pas() {
        let e = fusionner(
            "DnsOverHttpsMode",
            &[
                trouvaille("10-dns.json", "off"),
                trouvaille("99-local.json", "secure"),
            ],
        )
        .unwrap_err();
        // Le message doit nommer les DEUX fichiers et les DEUX valeurs, sans
        // quoi il envoie chercher au mauvais endroit.
        assert!(e.contains("10-dns.json"), "{e}");
        assert!(e.contains("99-local.json"), "{e}");
        assert!(e.contains("off"), "{e}");
        assert!(e.contains("secure"), "{e}");
    }
}
