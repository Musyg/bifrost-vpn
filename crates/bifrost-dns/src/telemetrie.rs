//! Ce que le resolveur embarque refuse de resoudre.
//!
//! Couche 3 du document 03 (`docs/03-anti-telemetrie-os.md`, partie 6), et la
//! seule des quatre qui vaut pour les DEUX plateformes: les couches registre,
//! services et WFP n'existent que sous Windows. C'est aussi celle que le
//! document appelle son argument central, parce qu'elle intercepte le nom
//! AVANT que la requete n'entre dans le tunnel: le trafic de telemetrie ne
//! ressort pas a l'autre bout, il ne part pas du tout.
//!
//! # Deux ecarts avec ce que le document proposait
//!
//! Le document recommandait d'embarquer **blocky** (Apache-2.0) comme
//! resolveur local, et de charger les listes **hagezi**. Ni l'un ni l'autre
//! n'est fait ici, pour deux raisons qui n'existaient pas quand il a ete
//! ecrit:
//!
//! 1. Bifrost embarque DEJA un resolveur, dnscrypt-proxy, livre avec le
//!    chantier du resolveur chiffre. Il sait refuser des noms nativement
//!    (`[blocked_names]`). Ajouter blocky reviendrait a faire tourner deux
//!    resolveurs sur la meme machine pour une fonction que le premier porte.
//! 2. `hagezi/dns-blocklists` est sous **GPL-3.0** - releve le 22/08/2026 sur
//!    le `LICENSE` du depot. Le document avait pris soin d'ecarter simplewall
//!    pour cette raison exacte, mais n'avait pas verifie la licence des
//!    LISTES. Bifrost est sous MPL-2.0 et
//!    `crates/bifrost-evasion/tests/frontiere_licence.rs` refuse le GPL: une
//!    liste GPL embarquee poserait la meme question, avec la meme reponse.
//!
//! La liste ci-dessous est donc ecrite ici, entree par entree, chacune avec sa
//! raison. Sa source primaire est la page Microsoft Learn "Connection
//! endpoints for Windows 11 Enterprise", `ms.date: 2026-06-16`, relue le
//! 22/08/2026. `WindowsSpyBlocker` (MIT, Copyright (c) 2016-2022 CrazyMax) a
//! fourni les hotes publicitaires que cette page ne nomme pas.
//!
//! # Deux formes de motif, et pas une de plus
//!
//! dnscrypt-proxy accepte `*`, `?` et `[]` n'importe ou. Son fichier d'exemple
//! documente un piege qu'on ne peut pas se permettre ici:
//!
//! ```text
//! *.example.com  | matches example.com and all names within that zone
//! example.com    | identical to the above
//! =example.com   | blocks example.com but not *.example.com
//! ```
//!
//! Un nom ecrit NU bloque donc toute sa zone. `microsoft.com` seul couperait
//! Windows Update, le Store, Defender et l'activation. Ce module n'emploie
//! jamais cette forme: il ecrit `*.zone` quand il vise une zone et `=nom`
//! quand il vise un nom, pour qu'un lecteur n'ait pas a connaitre la
//! convention pour lire la liste. [`forme`] refuse tout le reste, et une
//! recette le verifie sur chaque entree - sans quoi [`motif_couvre`], qui ne
//! sait interpreter que ces deux formes, jugerait a cote.

use bifrost_core::config::ProfilTelemetrie;

/// Une entree de la liste, et pourquoi elle y est.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Regle {
    /// Le motif, tel qu'il sera ecrit dans le fichier lu par dnscrypt-proxy.
    pub motif: &'static str,
    /// Ce qui tombe, et pourquoi c'est acceptable a ce profil.
    pub pourquoi: &'static str,
}

const fn r(motif: &'static str, pourquoi: &'static str) -> Regle {
    Regle { motif, pourquoi }
}

/// Ce qui n'a d'autre fonction que de mesurer l'utilisateur ou de lui vendre
/// quelque chose.
pub const EQUILIBRE: &[Regle] = &[
    r(
        "*.events.data.microsoft.com",
        "Le pipeline Connected User Experiences and Telemetry: v10, self, \
         functional, kmwatson, umwatson, teams, mobile. La page Microsoft \
         range aussi self.events.data.microsoft.com sous Office; c'est la \
         telemetrie d'Office qui y passe, l'enregistrement des documents \
         passant par www.office.com et blobs.officehome.msocdn.com. Lecture \
         de la page, pas mesure sur machine.",
    ),
    r(
        "*.events.data.msn.com",
        "browser.events.data.msn.com, la telemetrie de navigation, rangee \
         sous Diagnostic Data. Hors de la zone microsoft.com, donc une entree \
         a elle seule.",
    ),
    r(
        "*.vortex.data.microsoft.com",
        "L'ancien nom du meme pipeline. Absent de la page de 2026, donc \
         peut-etre mort: le garder ne coute rien et ferme un retour \
         silencieux. La zone au-dessus, *.data.microsoft.com, serait trop \
         large - settings.data.microsoft.com y vit et casse des applications.",
    ),
    r(
        "*.telemetry.microsoft.com",
        "Windows Error Reporting et Watson: telecommand.telemetry, \
         oca.telemetry, alpha.telemetry, reports.wes.df.telemetry. Ce qui \
         tombe est l'envoi des rapports de plantage. Aucune fonction visible \
         ne disparait, et Microsoft documente lui-meme la coupure par GPO.",
    ),
    r(
        "=www.telecommandsvc.microsoft.com",
        "La troisieme adresse de Windows Error Reporting, hors de la zone \
         telemetry.microsoft.com. Exacte: la zone microsoft.com au-dessus \
         porte tout le reste du systeme.",
    ),
    r(
        "*.iris.microsoft.com",
        "ris.api.iris et fd.api.iris, la plateforme d'experimentation et de \
         suggestion. Elle sert les applications suggerees et les astuces. Les \
         images de l'ecran de verrouillage, elles, viennent des hotes \
         msn.com, laisses au profil Strict.",
    ),
    r(
        "*.adnxs.com",
        "AppNexus, regie publicitaire tierce: adnxs.com et secure.adnxs.com. \
         Rien de Microsoft ne depend d'elle.",
    ),
    r(
        "*.msads.net",
        "La zone publicitaire de Microsoft, dont a.ads2.msads.net.",
    ),
    r(
        "=bingads.microsoft.com",
        "La regie de Bing. Exacte et non zone: bing.com sert aussi la \
         recherche, que ce profil ne casse pas.",
    ),
    r(
        "=a.ads1.msn.com",
        "Hote publicitaire de la zone msn.com. Nomme un par un parce que \
         *.msn.com couperait aussi le fil d'actualites et Spotlight, ce qui \
         est le profil Strict.",
    ),
    r("=ads.msn.com", "Idem: publicite, zone msn.com."),
    r("=a.rad.msn.com", "Idem: publicite, zone msn.com."),
    r("=ac3.msn.com", "Idem: publicite, zone msn.com."),
];

/// Ce que Strict ajoute: des noms qui portent AUSSI du contenu ou de la
/// configuration, donc dont le blocage se remarque.
pub const STRICT_EN_PLUS: &[Regle] = &[
    r(
        "*.pipe.aria.microsoft.com",
        "Aria, la telemetrie applicative de Microsoft. Ecart releve avec le \
         document 03, qui la rangeait en telemetrie pure d'apres \
         WindowsSpyBlocker: la page Microsoft du 16/06/2026 la range sous \
         Skype, ou elle sert a RECUPERER la configuration. Elle ne fait donc \
         pas que mesurer, et n'a pas sa place dans Equilibre.",
    ),
    r(
        "=settings-win.data.microsoft.com",
        "Configuration dynamique des applications. Microsoft ecrit qu'une \
         application qui s'en sert peut cesser de fonctionner: c'est une \
         casse, donc Strict et non Equilibre.",
    ),
    r(
        "=settings.data.microsoft.com",
        "Le second hote de la meme fonction. Exact: la zone data.microsoft.com \
         porte bien autre chose.",
    ),
    r(
        "=arc.msn.com",
        "Spotlight: metadonnees des images, applications suggerees, astuces.",
    ),
    r(
        "=api.msn.com",
        "L'API du fil MSN, dont Spotlight tire ses suggestions et ses tuiles.",
    ),
    r(
        "=assets.msn.com",
        "Les ressources servies a Spotlight et au fil MSN: c'est de la que \
         viennent les images de l'ecran de verrouillage.",
    ),
    r(
        "=ntp.msn.com",
        "La page de nouvel onglet MSN. Ce qui tombe se voit tout de suite, \
         d'ou Strict.",
    ),
    r(
        "=srtb.msn.com",
        "Un des hotes du fil MSN releves sur la page Microsoft sous Windows \
         Spotlight. Sa fonction exacte n'est pas documentee la; il est bloque \
         avec le reste du fil, pas separement.",
    ),
    r(
        "=c.msn.com",
        "Idem: hote du fil MSN, range sous Windows Spotlight par la page \
         Microsoft.",
    ),
    r(
        "=www.msn.com",
        "Le portail MSN lui-meme, source du fil d'actualites de Windows.",
    ),
    r(
        "=staticview.msn.com",
        "Les ressources statiques du fil MSN, rangees sous Windows Spotlight.",
    ),
    r(
        "=windows.msn.com",
        "Le fil de la page de nouvel onglet d'Edge, range sous Microsoft Edge \
         par la page Microsoft.",
    ),
    r(
        "*.wns.windows.com",
        "Windows Push Notification Services. Ce qui tombe: les notifications \
         poussees, la synchronisation du courrier et des reglages, et la \
         gestion MDM. Le document 03 le range explicitement dans Strict.",
    ),
    r(
        "=nexus.officeapps.live.com",
        "Le point de collecte de la telemetrie d'Office, releve par \
         WindowsSpyBlocker. Absent de la page Microsoft, qui ne couvre que \
         Windows.",
    ),
    r(
        "=nexusrules.officeapps.live.com",
        "Le meme service, qui livre aussi des regles de politique: d'ou \
         Strict plutot qu'Equilibre.",
    ),
];

/// Les noms qu'AUCUN profil ne doit faire tomber, et ce qu'ils portent.
///
/// C'est le plancher du produit. Le document 03 le pose comme critere du
/// profil Equilibre - "Store/Update/Defender/NCSI intacts" - et il vaut aussi
/// pour Strict: casser la mise a jour d'un systeme au nom de la vie privee
/// serait un mauvais echange, et le support qu'il couterait est nomme dans le
/// document comme un risque produit.
///
/// Tous releves sur la page Microsoft du 16/06/2026.
pub const NE_DOIT_PAS_TOMBER: &[(&str, &str)] = &[
    ("download.windowsupdate.com", "Windows Update"),
    ("fe3.delivery.mp.microsoft.com", "Windows Update"),
    ("sls.update.microsoft.com", "Windows Update"),
    ("dl.delivery.mp.microsoft.com", "Windows Update"),
    (
        "tsfe.trafficshaping.dsp.mp.microsoft.com",
        "Windows Update, regulation de contenu",
    ),
    ("adl.windows.com", "Base de compatibilite de Windows"),
    ("definitionupdates.microsoft.com", "Definitions Defender"),
    ("displaycatalog.mp.microsoft.com", "Microsoft Store"),
    ("storeedgefd.dsx.mp.microsoft.com", "Microsoft Store"),
    ("livetileedge.dsx.mp.microsoft.com", "Microsoft Store"),
    (
        "storecatalogrevocation.storequality.microsoft.com",
        "Revocation des applications malveillantes du Store",
    ),
    ("wdcp.microsoft.com", "Defender, protection par le cloud"),
    ("checkappexec.microsoft.com", "Defender SmartScreen"),
    (
        "ping-edge.smartscreen.microsoft.com",
        "Defender SmartScreen",
    ),
    ("nav-edge.smartscreen.microsoft.com", "Defender SmartScreen"),
    (
        "www.msftconnecttest.com",
        "Indicateur de connectivite: bloque, l'icone reseau annonce une \
         absence d'Internet sur une machine qui en a",
    ),
    ("ipv6.msftconnecttest.com", "Indicateur de connectivite"),
    (
        "ctldl.windowsupdate.com",
        "Mise a jour de la liste des certificats racine: la bloquer AUGMENTE \
         la surface d'attaque",
    ),
    (
        "ocsp.digicert.com",
        "Verification de revocation des certificats",
    ),
    (
        "licensing.mp.microsoft.com",
        "Activation en ligne et licences",
    ),
    (
        "login.live.com",
        "Authentification du compte et de l'appareil",
    ),
    (
        "www.microsoft.com",
        "Le piege de la page Microsoft, qui le range sous Diagnostic Data: \
         c'est le site de Microsoft. Une categorie de documentation n'est pas \
         un verdict",
    ),
    ("microsoft.com", "La zone elle-meme"),
    (
        "www.office.com",
        "Enregistrement des documents dans le cloud",
    ),
];

/// Les regles d'un profil.
pub fn regles(profil: ProfilTelemetrie) -> Vec<Regle> {
    match profil {
        ProfilTelemetrie::Aucun => Vec::new(),
        ProfilTelemetrie::Equilibre => EQUILIBRE.to_vec(),
        ProfilTelemetrie::Strict => EQUILIBRE
            .iter()
            .chain(STRICT_EN_PLUS.iter())
            .copied()
            .collect(),
    }
}

/// Le contenu du fichier lu par dnscrypt-proxy.
///
/// Trie et dedoublonne: le fichier est engendre a chaque connexion, et deux
/// executions sur le meme profil doivent rendre le meme octet. Sans cela, une
/// difference de fichier ne voudrait plus rien dire.
pub fn blocked_names(profil: ProfilTelemetrie) -> String {
    let mut motifs: Vec<&str> = regles(profil).iter().map(|r| r.motif).collect();
    motifs.sort_unstable();
    motifs.dedup();

    let mut s = String::from("# Engendre par Bifrost. Toute modification sera ecrasee.\n");
    s.push_str("# Profil: ");
    s.push_str(match profil {
        ProfilTelemetrie::Aucun => "aucun",
        ProfilTelemetrie::Equilibre => "equilibre",
        ProfilTelemetrie::Strict => "strict",
    });
    s.push('\n');
    s.push_str("# La raison de chaque entree vit dans bifrost-dns/src/telemetrie.rs.\n\n");
    for motif in motifs {
        s.push_str(motif);
        s.push('\n');
    }
    s
}

/// Les deux seules formes que ce module emploie.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Forme<'a> {
    /// `*.zone`: la zone elle-meme et tout ce qu'elle contient.
    Zone(&'a str),
    /// `=nom`: ce nom, et rien d'autre.
    Exact(&'a str),
}

/// Reconnait la forme d'un motif, ou rend `None`.
///
/// `None` n'est pas une commodite: c'est le signal qu'une entree a ete ecrite
/// dans une forme que [`motif_couvre`] ne sait pas juger, donc que les
/// recettes de non-debordement ne prouveraient plus rien sur elle. Une recette
/// tombe dessus.
pub fn forme(motif: &str) -> Option<Forme<'_>> {
    if let Some(zone) = motif.strip_prefix("*.") {
        // Un deuxieme joker plus loin sortirait du sous-ensemble juge ici.
        if zone.is_empty() || zone.contains(['*', '?', '[', ']']) {
            return None;
        }
        return Some(Forme::Zone(zone));
    }
    if let Some(nom) = motif.strip_prefix('=') {
        if nom.is_empty() || nom.contains(['*', '?', '[', ']']) {
            return None;
        }
        return Some(Forme::Exact(nom));
    }
    None
}

/// Ce motif fait-il tomber ce nom?
///
/// Reproduit la semantique documentee par dnscrypt-proxy pour les deux formes
/// employees ici, et pour elles seules. Un motif d'une autre forme rend
/// `false`, ce qui serait un jugement faux: c'est [`forme`], verifiee par une
/// recette sur chaque entree, qui empeche ce cas d'exister.
pub fn motif_couvre(motif: &str, nom: &str) -> bool {
    match forme(motif) {
        Some(Forme::Zone(zone)) => nom == zone || nom.ends_with(&format!(".{zone}")),
        Some(Forme::Exact(exact)) => nom == exact,
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ce que le module promet: aucune entree, dans aucun profil, ne fait
    /// tomber un nom du plancher.
    ///
    /// Ce n'est pas une comparaison de chaines: le motif est INTERPRETE. Une
    /// entree ecrite `*.microsoft.com` passerait une egalite de chaines et
    /// couperait la machine.
    #[test]
    fn aucun_profil_ne_touche_au_plancher() {
        for profil in [ProfilTelemetrie::Equilibre, ProfilTelemetrie::Strict] {
            for regle in regles(profil) {
                for (nom, service) in NE_DOIT_PAS_TOMBER {
                    assert!(
                        !motif_couvre(regle.motif, nom),
                        "profil {profil:?}: le motif {} fait tomber {nom} ({service})",
                        regle.motif
                    );
                }
            }
        }
    }

    /// Le controle positif. Sans lui, une liste vide passerait la recette
    /// precedente sans rien bloquer, et le module tiendrait sa promesse en ne
    /// faisant rien.
    #[test]
    fn les_noms_de_telemetrie_tombent_bien() {
        let attendus = [
            "v10.events.data.microsoft.com",
            "self.events.data.microsoft.com",
            "functional.events.data.microsoft.com",
            "kmwatson.events.data.microsoft.com",
            "browser.events.data.msn.com",
            "telecommand.telemetry.microsoft.com",
            "oca.telemetry.microsoft.com",
            "www.telecommandsvc.microsoft.com",
            "ris.api.iris.microsoft.com",
            "fd.api.iris.microsoft.com",
            "secure.adnxs.com",
            "a.ads2.msads.net",
        ];
        let regles = regles(ProfilTelemetrie::Equilibre);
        for nom in attendus {
            assert!(
                regles.iter().any(|r| motif_couvre(r.motif, nom)),
                "Equilibre ne bloque pas {nom}"
            );
        }
    }

    #[test]
    fn strict_ajoute_ce_qu_equilibre_epargne() {
        let equilibre = regles(ProfilTelemetrie::Equilibre);
        let strict = regles(ProfilTelemetrie::Strict);
        for nom in [
            "mobile.pipe.aria.microsoft.com",
            "settings-win.data.microsoft.com",
            "arc.msn.com",
            "ntp.msn.com",
            "hk2.wns.windows.com",
            "nexus.officeapps.live.com",
        ] {
            assert!(
                !equilibre.iter().any(|r| motif_couvre(r.motif, nom)),
                "Equilibre bloque {nom}, qui porte autre chose que de la mesure"
            );
            assert!(
                strict.iter().any(|r| motif_couvre(r.motif, nom)),
                "Strict ne bloque pas {nom}"
            );
        }
    }

    /// Strict contient Equilibre. Un profil plus dur qui laisserait passer ce
    /// qu'un profil plus doux refuse serait une surprise desagreable.
    #[test]
    fn strict_contient_equilibre() {
        let strict: Vec<&str> = regles(ProfilTelemetrie::Strict)
            .iter()
            .map(|r| r.motif)
            .collect();
        for regle in EQUILIBRE {
            assert!(strict.contains(&regle.motif), "Strict perd {}", regle.motif);
        }
    }

    /// Toute entree doit etre dans une des deux formes que `motif_couvre` sait
    /// juger. Sans cette recette, une entree en `*sex*` rendrait `false` a
    /// toutes les questions et traverserait le controle de plancher sans etre
    /// examinee.
    #[test]
    fn chaque_entree_est_dans_une_forme_jugeable() {
        for regle in EQUILIBRE.iter().chain(STRICT_EN_PLUS.iter()) {
            assert!(
                forme(regle.motif).is_some(),
                "motif hors des deux formes admises: {}. Employer *.zone ou \
                 =nom, ou etendre motif_couvre ET cette recette",
                regle.motif
            );
        }
    }

    /// Le piege documente par dnscrypt-proxy: un nom NU bloque toute sa zone.
    #[test]
    fn un_nom_nu_n_est_jamais_employe() {
        for regle in EQUILIBRE.iter().chain(STRICT_EN_PLUS.iter()) {
            assert!(
                regle.motif.starts_with("*.") || regle.motif.starts_with('='),
                "motif nu: {}. Ecrit ainsi, dnscrypt-proxy bloque TOUTE la \
                 zone, ce qui n'est presque jamais l'intention",
                regle.motif
            );
        }
    }

    /// Un plancher contre le remplissage, pas un jugement de qualite. Il a
    /// mordu des le premier passage: quatre entree msn.com portaient "Fil
    /// MSN.", ce qui ne dit ni ce que l'hote sert ni ce qui tombe avec lui.
    #[test]
    fn chaque_entree_porte_sa_raison() {
        for regle in EQUILIBRE.iter().chain(STRICT_EN_PLUS.iter()) {
            assert!(
                regle.pourquoi.len() > 20,
                "entree sans raison utilisable: {}",
                regle.motif
            );
        }
    }

    #[test]
    fn aucun_doublon_entre_les_deux_listes() {
        for regle in STRICT_EN_PLUS {
            assert!(
                !EQUILIBRE.iter().any(|e| e.motif == regle.motif),
                "{} figure dans les deux listes",
                regle.motif
            );
        }
    }

    #[test]
    fn le_profil_aucun_ne_bloque_rien() {
        assert!(regles(ProfilTelemetrie::Aucun).is_empty());
        let fichier = blocked_names(ProfilTelemetrie::Aucun);
        assert!(
            fichier.lines().all(|l| l.starts_with('#') || l.is_empty()),
            "le profil Aucun a produit des motifs:\n{fichier}"
        );
    }

    /// Deux executions sur le meme profil doivent rendre le meme octet, sans
    /// quoi une difference de fichier ne voudrait plus rien dire.
    #[test]
    fn le_fichier_est_trie_dedoublonne_et_stable() {
        let a = blocked_names(ProfilTelemetrie::Strict);
        let b = blocked_names(ProfilTelemetrie::Strict);
        assert_eq!(a, b);

        let motifs: Vec<&str> = a
            .lines()
            .filter(|l| !l.starts_with('#') && !l.is_empty())
            .collect();
        let mut tries = motifs.clone();
        tries.sort_unstable();
        assert_eq!(motifs, tries, "fichier non trie");

        let mut vus = motifs.clone();
        vus.dedup();
        assert_eq!(vus.len(), motifs.len(), "doublon dans le fichier");
        assert_eq!(
            motifs.len(),
            EQUILIBRE.len() + STRICT_EN_PLUS.len(),
            "le fichier ne porte pas toutes les entrees"
        );
    }

    #[test]
    fn la_forme_zone_couvre_la_zone_et_ses_sous_domaines() {
        assert!(motif_couvre("*.example.com", "example.com"));
        assert!(motif_couvre("*.example.com", "www.example.com"));
        assert!(motif_couvre("*.example.com", "a.b.example.com"));
        // Et pas le voisin qui finit par les memes lettres.
        assert!(!motif_couvre("*.example.com", "notexample.com"));
        assert!(!motif_couvre("*.example.com", "example.com.evil.net"));
    }

    #[test]
    fn la_forme_exacte_ne_couvre_que_le_nom() {
        assert!(motif_couvre("=example.com", "example.com"));
        assert!(!motif_couvre("=example.com", "www.example.com"));
    }

    #[test]
    fn les_formes_non_jugeables_sont_refusees() {
        for motif in ["example.com", "*sex*", "ads.*", "ads[0-9]*", "*.", "=", ""] {
            assert!(forme(motif).is_none(), "forme acceptee a tort: {motif}");
        }
    }
}
