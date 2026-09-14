//! Ce que la couche 1 pose, et d'ou chaque entree vient.
//!
//! # La regle d'entree
//!
//! Un reglage n'entre ici que s'il a une **source primaire datee** et que l'on
//! sait dire ce qu'il casse. Pas de recette recopiee d'un depot de debloat: le
//! document 03 en recense huit, tous utiles comme references de comportement,
//! aucun comme source. Les chemins de registre viennent des pages Policy CSP de
//! Microsoft Learn, qui donnent la ligne `Registry Key Name` et la ligne
//! `Registry Value Name` en toutes lettres.
//!
//! # Ce qui a ete ecarte, et pourquoi
//!
//! Trois entrees que le document 03 recommande ne sont PAS ici. Les taire
//! serait pire que les poser: quelqu'un les reajouterait.
//!
//! - **`TurnOffWindowsCopilot`**. Le document 03 le range dans un bloc `.reg`
//!   sous `HKEY_LOCAL_MACHINE`. La page Policy CSP WindowsAI
//!   (`ms.date: 2026-06-22`, relevee le 22/08/2026) le donne en portee
//!   **utilisateur uniquement** - `Location: User Configuration` - donc sous
//!   HKCU. Pose sous HKLM, il ne fait rien. Et la meme page le marque
//!   *"This policy is deprecated and may be removed in a future release"*, avec
//!   une liste de systemes qui s'arrete a Windows 11 23H2 et une note disant
//!   qu'il ne vise pas le nouveau Copilot. Le poser reviendrait a livrer une
//!   reassurance.
//! - **`RemoveMicrosoftCopilotApp`**, la politique de desinstallation dediee
//!   que le document 03 disait "a verifier au moment de l'implementation".
//!   Elle existe bien, mais sa correspondance de politique de groupe ne porte
//!   AUCUNE ligne `Registry Key Name`: elle n'est atteignable que par CSP, donc
//!   par une gestion de parc, pas par le registre. Et elle exclut Pro.
//! - **Le fichier hosts.** Defender le detecte comme
//!   `SettingsModifier:Win32/HostsFileHijack` des qu'on y met de la telemetrie
//!   Microsoft. C'est la couche 4 du plan, et le plan la deconseille lui-meme
//!   pour ces domaines.
//!
//! # Les cles ContentDeliveryManager
//!
//! Le document 03 en liste quatre sous HKCU et note lui-meme que leur fiabilite
//! est reduite sur les builds recents, le shell ayant ete durci. Elles ne sont
//! pas ici: `DisableWindowsConsumerFeatures`, sous CloudContent et en portee
//! machine, couvre le meme terrain de facon durable.

use bifrost_core::config::ProfilTelemetrie;

/// Le profil demande, tel qu'il est deja ecrit dans le profil de tunnel.
///
/// Le meme type que la couche DNS: un utilisateur choisit `equilibre` une fois,
/// et les deux couches en tirent leurs consequences.
pub type Profil = ProfilTelemetrie;

/// Ou vit le reglage: la machine, ou la session d'un utilisateur.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ruche {
    /// `HKEY_LOCAL_MACHINE`. Pose par un administrateur, vaut pour tous.
    Machine,
    /// `HKEY_CURRENT_USER`. Ne vaut que pour la session qui pose.
    ///
    /// Piege deja paye ailleurs dans ce depot, et documente en tete de
    /// `checks::doh_registre`: le daemon tourne en service sous SYSTEM, et
    /// `HKEY_CURRENT_USER` y designe la ruche de SYSTEM. Un reglage de vie
    /// privee pose la ne protege personne, et se lirait pourtant comme une
    /// protection. Le moteur refuse donc ces reglages quand il tourne sous
    /// SYSTEM, au lieu de les poser dans le vide.
    Utilisateur,
}

/// Ce sur quoi un reglage agit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cible {
    /// Une valeur `REG_DWORD` sous une cle de politique.
    Dword {
        ruche: Ruche,
        cle: &'static str,
        valeur: &'static str,
        voulu: u32,
    },
    /// Un service, par son `Start` dans le registre.
    ///
    /// Le registre et non le gestionnaire de services: le document 03 releve
    /// que `sc config` se heurte a des refus d'acces sur DoSvc. La valeur 4 est
    /// "desactive", 3 "manuel", 2 "automatique".
    Service { nom: &'static str, voulu: u32 },
    /// Une tache planifiee, a desactiver.
    ///
    /// Le chemin complet, barre oblique inverse comprise, tel que
    /// `schtasks /TN` l'attend.
    Tache { chemin: &'static str },
}

/// Un reglage: ce qu'on pose, pourquoi, ce que ca coute, et d'ou ca vient.
#[derive(Debug, Clone, Copy)]
pub struct Reglage {
    /// Identifiant stable. C'est la cle du journal, donc il ne change jamais,
    /// meme si le chemin de registre change.
    pub id: &'static str,
    pub cible: Cible,
    /// Le profil a partir duquel ce reglage s'applique. `Equilibre` implique
    /// `Strict`: [`reglages`] s'en charge.
    pub depuis: Profil,
    pub pourquoi: &'static str,
    /// Ce que l'utilisateur perd. Jamais "rien" par facilite: si on ne sait pas
    /// ce que ca casse, le reglage n'a pas sa place ici.
    pub ce_qui_casse: &'static str,
    /// La page et sa date, ou la mesure et la sienne.
    pub source: &'static str,
}

const POLITIQUES_DATA_COLLECTION: &str = r"SOFTWARE\Policies\Microsoft\Windows\DataCollection";
const POLITIQUES_CLOUD_CONTENT: &str = r"SOFTWARE\Policies\Microsoft\Windows\CloudContent";
const POLITIQUES_PUBLICITE: &str = r"SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo";
const POLITIQUES_WINDOWS_AI: &str = r"SOFTWARE\Policies\Microsoft\Windows\WindowsAI";
const POLITIQUES_SAISIE: &str = r"SOFTWARE\Policies\Microsoft\InputPersonalization";

/// Source des chemins de registre des politiques Windows AI.
const CSP_WINDOWS_AI: &str = "Policy CSP WindowsAI, ms.date 2026-06-22, releve le 22/08/2026";
/// Source des endpoints et du role de chaque service.
const DOC_03: &str = "document 03, partie 1.3, d'apres Microsoft Learn 2026-06-16";

/// Tout ce que la couche 1 sait poser, profils confondus.
///
/// L'ordre compte pour la lecture, pas pour la pose: le moteur applique dans
/// l'ordre et defait dans l'ordre inverse, ce qui n'a d'importance que si deux
/// entrees touchaient la meme cible. Aucune ne le fait, et une recette le
/// verifie.
const TOUS: &[Reglage] = &[
    // ---------------------------------------------------------------- Equilibre
    Reglage {
        id: "collecte-niveau",
        cible: Cible::Dword {
            ruche: Ruche::Machine,
            cle: POLITIQUES_DATA_COLLECTION,
            valeur: "AllowTelemetry",
            voulu: 0,
        },
        depuis: Profil::Equilibre,
        pourquoi: "Demande le niveau de diagnostic le plus bas que la politique \
                   accepte d'ecrire.",
        ce_qui_casse: "Rien de fonctionnel. Mais hors Enterprise, Education et \
                       Server, Microsoft ecrit que 0 est traite comme 1: ce \
                       reglage reduit la surface et retire le choix de \
                       l'interface, il n'annule PAS la telemetrie Required. \
                       C'est le blocage reseau qui la refuse.",
        source: "Policy CSP System, ms.date 2026-02-27, releve le 22/08/2026",
    },
    Reglage {
        id: "collecte-nom-machine",
        cible: Cible::Dword {
            ruche: Ruche::Machine,
            cle: POLITIQUES_DATA_COLLECTION,
            valeur: "AllowDeviceNameInTelemetry",
            voulu: 0,
        },
        depuis: Profil::Equilibre,
        pourquoi: "Le nom de la machine est un identifiant stable et souvent \
                   nominatif. Rien n'oblige a le joindre aux evenements.",
        ce_qui_casse: "Rien. Certains diagnostics de support sont moins \
                       facilement rattachables a un appareil.",
        source: DOC_03,
    },
    Reglage {
        id: "collecte-invites-retour",
        cible: Cible::Dword {
            ruche: Ruche::Machine,
            cle: POLITIQUES_DATA_COLLECTION,
            valeur: "DoNotShowFeedbackNotifications",
            voulu: 1,
        },
        depuis: Profil::Equilibre,
        pourquoi: "Les invites de retour d'experience declenchent une remontee \
                   et sollicitent l'utilisateur sans qu'il l'ait demande.",
        ce_qui_casse: "Plus d'invitation a donner son avis. Le Hub de \
                       commentaires reste utilisable a la demande.",
        source: DOC_03,
    },
    Reglage {
        id: "publicite-identifiant-machine",
        cible: Cible::Dword {
            ruche: Ruche::Machine,
            cle: POLITIQUES_PUBLICITE,
            valeur: "DisabledByGroupPolicy",
            voulu: 1,
        },
        depuis: Profil::Equilibre,
        pourquoi: "L'identifiant de publicite suit l'utilisateur d'une \
                   application a l'autre. En portee machine, il ne depend pas \
                   de la session.",
        ce_qui_casse: "Les publicites restent, elles cessent d'etre ciblees par \
                       cet identifiant.",
        source: DOC_03,
    },
    Reglage {
        id: "experiences-personnalisees",
        cible: Cible::Dword {
            ruche: Ruche::Machine,
            cle: POLITIQUES_CLOUD_CONTENT,
            valeur: "DisableTailoredExperiencesWithDiagnosticData",
            voulu: 1,
        },
        depuis: Profil::Equilibre,
        pourquoi: "C'est la reutilisation des donnees de diagnostic pour \
                   personnaliser conseils et publicites: exactement la boucle \
                   que la couche 1 doit ouvrir.",
        ce_qui_casse: "Conseils et suggestions cessent d'etre personnalises.",
        source: DOC_03,
    },
    Reglage {
        id: "fonctions-grand-public",
        cible: Cible::Dword {
            ruche: Ruche::Machine,
            cle: POLITIQUES_CLOUD_CONTENT,
            valeur: "DisableWindowsConsumerFeatures",
            voulu: 1,
        },
        depuis: Profil::Equilibre,
        pourquoi: "Coupe les installations silencieuses d'applications \
                   suggerees et les contenus pousses dans le menu Demarrer. \
                   Preferee aux quatre cles ContentDeliveryManager, dont le \
                   document 03 dit la fiabilite reduite sur les builds \
                   recents.",
        ce_qui_casse: "Plus de suggestions d'applications ni de contenus \
                       pousses.",
        source: DOC_03,
    },
    Reglage {
        id: "service-diagtrack",
        cible: Cible::Service {
            nom: "DiagTrack",
            voulu: 4,
        },
        depuis: Profil::Equilibre,
        pourquoi: "Le pipeline principal. C'est lui qui parle a \
                   *.events.data.microsoft.com, et ses noms d'hotes sont codes \
                   en dur dans diagtrack.dll d'apres le BSI: l'eteindre est \
                   plus sur que d'esperer le filtrer.",
        ce_qui_casse: "Succes Xbox et Game Bar, diagnostics enrichis cote \
                       support.",
        source: DOC_03,
    },
    Reglage {
        id: "service-dmwappushservice",
        cible: Cible::Service {
            nom: "dmwappushservice",
            voulu: 4,
        },
        depuis: Profil::Equilibre,
        pourquoi: "Routage WAP push de gestion d'appareils. Sans parc gere, il \
                   n'a pas d'usage.",
        ce_qui_casse: "La gestion a distance par MDM. A NE PAS poser sur une \
                       machine d'entreprise geree.",
        source: DOC_03,
    },
    Reglage {
        id: "tache-consolidator",
        cible: Cible::Tache {
            chemin: r"\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
        },
        depuis: Profil::Equilibre,
        pourquoi: "Consolide et envoie les donnees du programme d'amelioration \
                   de l'experience. Lance wsqmcons.exe toutes les six heures.",
        ce_qui_casse: "Rien de fonctionnel.",
        source: "releve le 22/08/2026 sur essai-windows, build 26200: presente, \
                 et son declencheur est PT6H",
    },
    Reglage {
        id: "tache-usbceip",
        cible: Cible::Tache {
            chemin: r"\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
        },
        depuis: Profil::Equilibre,
        pourquoi: "Meme programme, versant USB: remonte les peripheriques \
                   branches.",
        ce_qui_casse: "Rien de fonctionnel.",
        source: "releve le 22/08/2026 sur essai-windows, build 26200: presente",
    },
    // Deux entrees pour un seul travail, et ce n'est pas une erreur: la tache a
    // change de nom entre les deux systemes. Releve du 22/08/2026, la meme
    // heure sur les deux machines:
    //   dev-windows, Windows 10 build 19045: `Microsoft Compatibility Appraiser`
    //   essai-windows, Windows 11 build 26200: le meme, suffixe ` Exp`
    // Sur chaque machine l'une des deux est SANS OBJET et le dit. Une seule
    // entree, quel que soit le nom retenu, ne ferait rien sur la moitie du parc
    // en annoncant la meme chose des deux cotes.
    Reglage {
        id: "tache-appraiser",
        cible: Cible::Tache {
            chemin: r"\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
        },
        depuis: Profil::Equilibre,
        pourquoi: "L'appraiser de compatibilite, qui lance CompatTelRunner.exe \
                   et remonte l'inventaire logiciel et materiel. Nom porte par \
                   Windows 10.",
        ce_qui_casse: "L'evaluation de compatibilite avant une mise a niveau. \
                       Et le document 03 previent, defaut WinUtil 4035: \
                       CompatTelRunner peut se relancer a chaque installation \
                       malgre la tache desactivee. Seule la couche WFP le tient \
                       vraiment.",
        source: "releve le 22/08/2026 sur dev-windows, build 19045: presente \
                 sous ce nom, et absente sous ce nom sur la build 26200",
    },
    Reglage {
        id: "tache-appraiser-exp",
        cible: Cible::Tache {
            chemin: r"\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser Exp",
        },
        depuis: Profil::Equilibre,
        pourquoi: "Le meme appraiser sous le nom que Windows 11 25H2 lui donne. \
                   Le document 03 ne connait que l'ancien.",
        ce_qui_casse: "Comme l'entree precedente, dont c'est le pendant.",
        source: "releve le 22/08/2026 sur essai-windows, build 26200: presente \
                 sous ce nom, et le nom sans suffixe n'y existe pas",
    },
    Reglage {
        id: "tache-program-data-updater",
        cible: Cible::Tache {
            chemin: r"\Microsoft\Windows\Application Experience\ProgramDataUpdater",
        },
        depuis: Profil::Equilibre,
        pourquoi: "Alimente la base d'inventaire applicatif que l'appraiser \
                   remonte ensuite.",
        ce_qui_casse: "L'inventaire de compatibilite applicative cesse d'etre \
                       tenu a jour.",
        source: "releve le 22/08/2026: presente sur dev-windows, build 19045, \
                 ABSENTE sur essai-windows, build 26200. Le document 03 la \
                 nomme sans dire qu'elle a disparu",
    },
    Reglage {
        id: "tache-pca-patch-db",
        cible: Cible::Tache {
            chemin: r"\Microsoft\Windows\Application Experience\PcaPatchDbTask",
        },
        depuis: Profil::Equilibre,
        pourquoi: "Assistant de compatibilite des programmes: alimente la base \
                   d'inventaire applicatif.",
        ce_qui_casse: "Les correctifs automatiques de compatibilite \
                       applicative.",
        source: "releve le 22/08/2026 sur essai-windows, build 26200: presente",
    },
    Reglage {
        id: "tache-dmclient",
        cible: Cible::Tache {
            chemin: r"\Microsoft\Windows\Feedback\Siuf\DmClient",
        },
        depuis: Profil::Equilibre,
        pourquoi: "Siuf, System Initiated User Feedback: declenche les \
                   sollicitations de retour d'experience.",
        ce_qui_casse: "Rien de fonctionnel.",
        source: "releve le 22/08/2026 sur essai-windows, build 26200: presente",
    },
    Reglage {
        id: "tache-dmclient-scenario",
        cible: Cible::Tache {
            chemin: r"\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload",
        },
        depuis: Profil::Equilibre,
        pourquoi: "Le pendant du precedent, declenche au telechargement d'un \
                   scenario de retour d'experience.",
        ce_qui_casse: "Rien de fonctionnel.",
        source: "releve le 22/08/2026 sur essai-windows, build 26200: presente",
    },
    Reglage {
        id: "tache-autochk-proxy",
        cible: Cible::Tache {
            chemin: r"\Microsoft\Windows\Autochk\Proxy",
        },
        depuis: Profil::Equilibre,
        pourquoi: "Collecte et envoie des donnees pour le programme \
                   d'amelioration de l'experience.",
        ce_qui_casse: "Rien de fonctionnel.",
        source: "releve le 22/08/2026 sur essai-windows, build 26200: presente",
    },
    // ------------------------------------------------------------------- Strict
    Reglage {
        id: "recall-composant",
        cible: Cible::Dword {
            ruche: Ruche::Machine,
            cle: POLITIQUES_WINDOWS_AI,
            valeur: "AllowRecallEnablement",
            voulu: 0,
        },
        depuis: Profil::Strict,
        pourquoi: "Retire le composant Recall et supprime les instantanes deja \
                   stockes. Le risque est local - rien ne remonte a Microsoft - \
                   mais une base d'instantanes de l'ecran est une base \
                   d'instantanes de l'ecran.",
        ce_qui_casse: "Recall, et son retrait demande un redemarrage. Sans \
                       machine Copilot+, le composant n'existe pas et le \
                       reglage n'a aucun effet observable.",
        source: CSP_WINDOWS_AI,
    },
    Reglage {
        id: "recall-instantanes",
        cible: Cible::Dword {
            ruche: Ruche::Machine,
            cle: POLITIQUES_WINDOWS_AI,
            valeur: "DisableAIDataAnalysis",
            voulu: 1,
        },
        depuis: Profil::Strict,
        pourquoi: "Deuxieme verrou, independant du premier: empeche \
                   l'enregistrement d'instantanes meme si le composant est la.",
        ce_qui_casse: "L'utilisateur ne peut plus choisir d'activer les \
                       instantanes. Ceux deja enregistres sont supprimes.",
        source: CSP_WINDOWS_AI,
    },
    Reglage {
        id: "saisie-personnalisation",
        cible: Cible::Dword {
            ruche: Ruche::Machine,
            cle: POLITIQUES_SAISIE,
            valeur: "AllowInputPersonalization",
            voulu: 0,
        },
        depuis: Profil::Strict,
        pourquoi: "Coupe la collecte de frappe, d'encre et de voix qui alimente \
                   la personnalisation de la saisie.",
        ce_qui_casse: "Suggestions de saisie, reconnaissance d'ecriture et \
                       dictee en ligne perdent leur apprentissage.",
        source: DOC_03,
    },
    Reglage {
        id: "service-dosvc",
        cible: Cible::Service {
            nom: "DoSvc",
            voulu: 4,
        },
        depuis: Profil::Strict,
        pourquoi: "Optimisation de livraison: pair a pair pour les mises a \
                   jour, et graphe d'appareils.",
        ce_qui_casse: "Le pair a pair. Les mises a jour continuent de \
                       fonctionner, plus lentement sur un parc.",
        source: DOC_03,
    },
    Reglage {
        id: "service-wersvc",
        cible: Cible::Service {
            nom: "WerSvc",
            voulu: 4,
        },
        depuis: Profil::Strict,
        pourquoi: "Rapport d'erreurs Windows. Un vidage memoire de plantage \
                   peut contenir a peu pres n'importe quoi de ce qui etait en \
                   memoire.",
        ce_qui_casse: "Plus de rapport de plantage envoye, et le support \
                       Microsoft en demande.",
        source: DOC_03,
    },
    Reglage {
        id: "service-cdpsvc",
        cible: Cible::Service {
            nom: "CDPSvc",
            voulu: 4,
        },
        depuis: Profil::Strict,
        pourquoi: "Plateforme d'appareils connectes: c'est le graphe \
                   d'appareils, dont le document 03 rappelle qu'il se cache \
                   derriere des IP Azure Front Door partagees et ne peut donc \
                   pas etre bloque par adresse.",
        ce_qui_casse: "Continuite entre appareils, partage de proximite.",
        source: DOC_03,
    },
    Reglage {
        id: "tache-queue-reporting",
        cible: Cible::Tache {
            chemin: r"\Microsoft\Windows\Windows Error Reporting\QueueReporting",
        },
        depuis: Profil::Strict,
        pourquoi: "Vide la file des rapports d'erreur en attente. Sans elle, ce \
                   qui a ete collecte reste sur la machine.",
        ce_qui_casse: "Meme perte que WerSvc, et les deux vont ensemble.",
        source: "releve le 22/08/2026 sur essai-windows, build 26200: presente",
    },
    Reglage {
        id: "tache-startup-app",
        cible: Cible::Tache {
            chemin: r"\Microsoft\Windows\Application Experience\StartupAppTask",
        },
        depuis: Profil::Strict,
        pourquoi: "Recense les applications lancees au demarrage et leur cout, \
                   pour l'inventaire d'experience applicative.",
        ce_qui_casse: "La page Applications de demarrage perd ses mesures \
                       d'impact.",
        source: "releve le 22/08/2026 sur essai-windows, build 26200: presente",
    },
    // ------------------------------------- Strict, ruche utilisateur
    Reglage {
        id: "publicite-identifiant-utilisateur",
        cible: Cible::Dword {
            ruche: Ruche::Utilisateur,
            cle: r"Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo",
            valeur: "Enabled",
            voulu: 0,
        },
        depuis: Profil::Equilibre,
        pourquoi: "Le pendant par session de l'identifiant de publicite. La \
                   politique machine prime, mais celle-ci eteint aussi \
                   l'interrupteur visible dans les reglages.",
        ce_qui_casse: "Rien de plus que la politique machine.",
        source: DOC_03,
    },
    Reglage {
        id: "experiences-personnalisees-utilisateur",
        cible: Cible::Dword {
            ruche: Ruche::Utilisateur,
            cle: r"Software\Microsoft\Windows\CurrentVersion\Privacy",
            valeur: "TailoredExperiencesWithDiagnosticDataEnabled",
            voulu: 0,
        },
        depuis: Profil::Equilibre,
        pourquoi: "Le pendant par session des experiences personnalisees.",
        ce_qui_casse: "Rien de plus que la politique machine.",
        source: DOC_03,
    },
    Reglage {
        id: "encre-implicite",
        cible: Cible::Dword {
            ruche: Ruche::Utilisateur,
            cle: r"Software\Microsoft\InputPersonalization",
            valeur: "RestrictImplicitInkCollection",
            voulu: 1,
        },
        depuis: Profil::Strict,
        pourquoi: "Empeche la collecte implicite de ce qui est ecrit au stylet.",
        ce_qui_casse: "La reconnaissance d'ecriture ne s'ameliore plus avec \
                       l'usage.",
        source: DOC_03,
    },
    Reglage {
        id: "texte-implicite",
        cible: Cible::Dword {
            ruche: Ruche::Utilisateur,
            cle: r"Software\Microsoft\InputPersonalization",
            valeur: "RestrictImplicitTextCollection",
            voulu: 1,
        },
        depuis: Profil::Strict,
        pourquoi: "Empeche la collecte implicite du texte frappe.",
        ce_qui_casse: "Les suggestions de saisie ne s'ameliorent plus avec \
                       l'usage.",
        source: DOC_03,
    },
    Reglage {
        id: "parole-en-ligne",
        cible: Cible::Dword {
            ruche: Ruche::Utilisateur,
            cle: r"Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy",
            valeur: "HasAccepted",
            voulu: 0,
        },
        depuis: Profil::Strict,
        pourquoi: "Retire le consentement a la reconnaissance vocale en ligne, \
                   qui envoie l'audio a Microsoft.",
        ce_qui_casse: "La dictee et les commandes vocales en ligne. La \
                       reconnaissance locale reste.",
        source: DOC_03,
    },
];

/// Les reglages d'un profil. `Equilibre` est inclus dans `Strict`.
///
/// `Aucun` rend une liste vide, et c'est le comportement voulu: un profil qui
/// ne demande rien ne doit rien poser, pas meme "le minimum".
pub fn reglages(profil: Profil) -> Vec<&'static Reglage> {
    TOUS.iter()
        .filter(|r| match profil {
            Profil::Aucun => false,
            Profil::Equilibre => r.depuis == Profil::Equilibre,
            Profil::Strict => true,
        })
        .collect()
}

/// Le profil nomme sur la ligne de commande.
///
/// `Aucun` est accepte et ne pose rien: c'est le moyen de demander explicitement
/// qu'aucune couche 1 ne s'applique, distinct de ne rien demander du tout.
pub fn profil_depuis_nom(nom: &str) -> Option<Profil> {
    match nom.trim().to_ascii_lowercase().as_str() {
        "aucun" => Some(Profil::Aucun),
        "equilibre" => Some(Profil::Equilibre),
        "strict" => Some(Profil::Strict),
        _ => None,
    }
}

/// Les noms acceptes, pour les messages d'erreur et l'aide.
pub const NOMS_DE_PROFIL: &[&str] = &["aucun", "equilibre", "strict"];

/// Tout le catalogue, profils confondus. Pour les recettes et pour `--etat`.
pub fn tous() -> &'static [Reglage] {
    TOUS
}

impl Cible {
    /// Comment un humain lit cette cible dans le journal ou dans un rapport.
    ///
    /// Le journal la porte en clair pour qu'un retour en arriere reste possible
    /// a la main le jour ou le binaire n'est plus la.
    pub fn en_clair(&self) -> String {
        match self {
            Cible::Dword {
                ruche,
                cle,
                valeur,
                voulu,
            } => {
                let racine = match ruche {
                    Ruche::Machine => "HKLM",
                    Ruche::Utilisateur => "HKCU",
                };
                format!("{racine}\\{cle} :: {valeur} = {voulu}")
            }
            Cible::Service { nom, voulu } => {
                format!("service {nom} :: Start = {voulu}")
            }
            Cible::Tache { chemin } => format!("tache {chemin} :: desactivee"),
        }
    }

    /// La ruche concernee, quand il y en a une.
    pub fn ruche(&self) -> Option<Ruche> {
        match self {
            Cible::Dword { ruche, .. } => Some(*ruche),
            // Les services vivent sous HKLM\SYSTEM, les taches ne passent pas
            // par le registre: dans les deux cas la portee est la machine, et
            // le refus sous SYSTEM ne les concerne pas.
            Cible::Service { .. } | Cible::Tache { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// Un nom inconnu ne doit pas retomber sur un defaut silencieux: une
    /// faute de frappe rendrait `Aucun`, donc une machine non protegee qu'on
    /// croirait protegee.
    #[test]
    fn un_nom_de_profil_inconnu_est_refuse() {
        assert_eq!(profil_depuis_nom("equilibre"), Some(Profil::Equilibre));
        assert_eq!(profil_depuis_nom("  STRICT "), Some(Profil::Strict));
        assert_eq!(profil_depuis_nom("aucun"), Some(Profil::Aucun));
        assert_eq!(profil_depuis_nom("equilibree"), None);
        assert_eq!(profil_depuis_nom(""), None);
        for nom in NOMS_DE_PROFIL {
            assert!(
                profil_depuis_nom(nom).is_some(),
                "{nom} est annonce dans l'aide mais refuse a la lecture"
            );
        }
    }

    #[test]
    fn aucun_ne_pose_rien() {
        assert!(
            reglages(Profil::Aucun).is_empty(),
            "le profil Aucun doit poser zero reglage: c'est le defaut, et un \
             defaut qui agit est un defaut qui surprend"
        );
    }

    #[test]
    fn equilibre_est_inclus_dans_strict() {
        let equilibre: HashSet<&str> = reglages(Profil::Equilibre).iter().map(|r| r.id).collect();
        let strict: HashSet<&str> = reglages(Profil::Strict).iter().map(|r| r.id).collect();
        for id in &equilibre {
            assert!(
                strict.contains(id),
                "{id} est dans Equilibre mais pas dans Strict: un profil plus \
                 severe qui protege moins n'a pas de sens"
            );
        }
        assert!(
            strict.len() > equilibre.len(),
            "Strict devrait ajouter quelque chose a Equilibre; {} contre {}",
            strict.len(),
            equilibre.len()
        );
    }

    #[test]
    fn les_identifiants_sont_uniques() {
        let mut vus = HashSet::new();
        for r in tous() {
            assert!(
                vus.insert(r.id),
                "identifiant {} en double: le journal s'ecraserait lui-meme et \
                 le retour en arriere restaurerait le mauvais etat",
                r.id
            );
        }
    }

    #[test]
    fn aucune_cible_n_est_visee_deux_fois() {
        let mut vues = HashSet::new();
        for r in tous() {
            let clef = match r.cible {
                Cible::Dword {
                    ruche, cle, valeur, ..
                } => format!("{ruche:?}|{cle}|{valeur}"),
                Cible::Service { nom, .. } => format!("service|{nom}"),
                Cible::Tache { chemin } => format!("tache|{chemin}"),
            };
            assert!(
                vues.insert(clef.clone()),
                "{} vise une cible deja visee ({clef}). Deux reglages sur la \
                 meme cible: le second ecrase le premier, et le journal \
                 restaurerait un etat qui n'a jamais existe",
                r.id
            );
        }
    }

    /// Une entree sans raison lisible est une entree qu'on ne saura pas
    /// defendre le jour ou elle cassera quelque chose.
    #[test]
    fn chaque_entree_porte_sa_raison_et_son_cout() {
        for r in tous() {
            assert!(
                r.pourquoi.len() > 40,
                "{}: `pourquoi` fait {} caracteres, c'est une etiquette et pas \
                 une raison",
                r.id,
                r.pourquoi.len()
            );
            assert!(
                r.ce_qui_casse.len() > 15,
                "{}: `ce_qui_casse` fait {} caracteres. Si un reglage ne coute \
                 vraiment rien, l'ecrire prend une phrase; si on ne sait pas, \
                 l'entree n'a pas sa place ici",
                r.id,
                r.ce_qui_casse.len()
            );
            assert!(
                r.source.len() > 20,
                "{}: `source` fait {} caracteres. Une entree sans source datee \
                 est une recette recopiee",
                r.id,
                r.source.len()
            );
        }
    }

    /// Le piege que le document 03 pose lui-meme: il range
    /// `TurnOffWindowsCopilot` sous HKLM alors que la politique est en portee
    /// utilisateur, deprecise, et hors liste depuis 24H2.
    #[test]
    fn les_politiques_ecartees_le_restent() {
        for r in tous() {
            let clair = r.cible.en_clair();
            for ecarte in [
                "TurnOffWindowsCopilot",
                "RemoveMicrosoftCopilotApp",
                "ContentDeliveryManager",
            ] {
                assert!(
                    !clair.contains(ecarte),
                    "{} vise {ecarte}, qui a ete ecarte pour une raison ecrite \
                     en tete de ce fichier. Si la raison ne tient plus, la \
                     reecrire d'abord",
                    r.id
                );
            }
        }
    }

    /// Un chemin de tache commence par une barre oblique inverse et n'en porte
    /// pas deux de suite: `schtasks /TN` ne rendrait rien, et un moteur qui ne
    /// distingue pas "rien" de "fait" annoncerait un succes.
    #[test]
    fn les_chemins_de_taches_sont_bien_formes() {
        let mut taches = 0;
        for r in tous() {
            if let Cible::Tache { chemin } = r.cible {
                taches += 1;
                assert!(
                    chemin.starts_with('\\'),
                    "{}: {chemin} ne commence pas par une barre oblique \
                     inverse",
                    r.id
                );
                assert!(
                    !chemin.contains("\\\\"),
                    "{}: {chemin} porte deux barres de suite",
                    r.id
                );
                assert!(
                    !chemin.ends_with('\\'),
                    "{}: {chemin} se termine par une barre",
                    r.id
                );
            }
        }
        assert!(
            taches >= 5,
            "seulement {taches} taches lues: parcours casse"
        );
    }

    /// Une valeur `Start` qui ne serait ni 2, ni 3, ni 4 mettrait un service
    /// dans un etat que personne n'a voulu.
    #[test]
    fn les_services_ne_prennent_que_des_valeurs_de_demarrage_connues() {
        let mut services = 0;
        for r in tous() {
            if let Cible::Service { nom, voulu } = r.cible {
                services += 1;
                assert!(
                    (2..=4).contains(&voulu),
                    "{}: Start={voulu} pour {nom}. 0 et 1 sont des pilotes \
                     charges au demarrage du noyau; les poser sur un service \
                     rend la machine non demarrable",
                    r.id
                );
            }
        }
        assert!(
            services >= 3,
            "seulement {services} services lus: parcours casse"
        );
    }

    #[test]
    fn les_cibles_se_lisent_en_clair() {
        let dword = Cible::Dword {
            ruche: Ruche::Machine,
            cle: r"SOFTWARE\Exemple",
            valeur: "Chose",
            voulu: 1,
        };
        assert_eq!(dword.en_clair(), r"HKLM\SOFTWARE\Exemple :: Chose = 1");
        let utilisateur = Cible::Dword {
            ruche: Ruche::Utilisateur,
            cle: r"Software\Exemple",
            valeur: "Chose",
            voulu: 0,
        };
        assert_eq!(
            utilisateur.en_clair(),
            r"HKCU\Software\Exemple :: Chose = 0"
        );
        assert_eq!(
            Cible::Service {
                nom: "Truc",
                voulu: 4
            }
            .en_clair(),
            "service Truc :: Start = 4"
        );
        assert_eq!(
            Cible::Tache { chemin: r"\A\B" }.en_clair(),
            r"tache \A\B :: desactivee"
        );
    }

    #[test]
    fn seules_les_valeurs_de_registre_portent_une_ruche() {
        assert_eq!(
            Cible::Service {
                nom: "Truc",
                voulu: 4
            }
            .ruche(),
            None
        );
        assert_eq!(Cible::Tache { chemin: r"\A" }.ruche(), None);
        assert_eq!(
            Cible::Dword {
                ruche: Ruche::Utilisateur,
                cle: "c",
                valeur: "v",
                voulu: 0
            }
            .ruche(),
            Some(Ruche::Utilisateur)
        );
    }

    /// Le catalogue vise des cles de POLITIQUE, sous `Policies`, et non les
    /// cles de reglage qu'une application peut reecrire a tout moment. Deux
    /// exceptions assumees et nommees: les deux cles par session qui n'ont pas
    /// d'equivalent sous `Policies`, et la ruche des services.
    #[test]
    fn les_cles_machine_sont_des_cles_de_politique() {
        for r in tous() {
            if let Cible::Dword {
                ruche: Ruche::Machine,
                cle,
                ..
            } = r.cible
            {
                assert!(
                    cle.starts_with(r"SOFTWARE\Policies\"),
                    "{}: {cle} n'est pas sous SOFTWARE\\Policies. Une cle hors \
                     politique se fait reecrire par le systeme sans prevenir, \
                     et le reglage se lirait pourtant comme pose",
                    r.id
                );
            }
        }
    }
}
