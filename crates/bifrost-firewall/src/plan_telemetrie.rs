//! La couche 2 du document 03: refuser le reseau a la telemetrie sans toucher
//! a Windows Update ni a BITS.
//!
//! # Deux mecanismes, et le catalogue s'en sert des deux
//!
//! Ce module a longtemps ete decrit comme s'il n'en avait qu'un, et la phrase
//! qui le disait etait vraie mais mal cadree: << le seul discriminant est le
//! SID de service >>. C'est vrai **a l'interieur de svchost.exe**, et faux de
//! la couche. Lu froid, on en concluait que la moitie du catalogue n'existait
//! pas.
//!
//! - [`Cible::Service`] -> `ALE_USER_ID`, que WFP evalue contre le JETON. C'est
//!   le point que le document appelle differenciant: `ALE_APP_ID` compare un
//!   CHEMIN, et toutes les instances de `svchost.exe` portent le meme, donc
//!   bloquer par chemin y couperait la machine entiere. Le SID de service est
//!   le seul discriminant qui reste.
//! - [`Cible::Binaire`] -> `ALE_APP_ID`, quand la cible a son propre
//!   executable. Le chemin SUFFIT alors, et il vaut mieux: `CompatTelRunner.exe`
//!   se relance de lui-meme malgre la desactivation de ses taches.
//!
//! **Ce qui est mesure de chacun, au 23 aout 2026, en fin de journee.** Les
//! DEUX mecanismes mordent, et l'un des deux a une limite qui n'est pas la
//! notre.
//!
//! `ALE_USER_ID` mord: 569 refus sur un service de test ordinaire, 673 sur un
//! service au jeton filtre, 9 sur 9 sur `W32Time` qui est un VRAI service du
//! systeme, l'evenement 5157 nommant notre filtre. Mais deux vraies cibles lui
//! echappent, `DiagTrack` et `DoSvc`, **et ce n'est pas reparable ici**: la
//! condition est un CONTROLE D'ACCES contre le jeton capture a la creation de
//! la socket, et un service qui usurpe l'identite d'un client a cet instant y
//! echappe. Mesure: le jeton capture de `DoSvc` porte un compte utilisateur et
//! non `NetworkService`. Et la construction de Microsoft echoue identiquement -
//! `New-NetFirewallRule -Service DoSvc -Action Block` laisse passer 25
//! connexions la ou la meme commande sur `W32Time` en refuse 5. **Ce mecanisme
//! ne peut donc pas porter une garantie**, seulement une defense en profondeur.
//!
//! `ALE_APP_ID` mord aussi, mesure le 23/08 avec un temoin qu'on commande: 636
//! puis 639 refus, zero connexion autorisee, deux signaux independants
//! concordants. Il ne depend d'aucun jeton, donc il ne connait pas cette
//! limite - mais pour un service heberge dans `svchost.exe`, le chemin d'image
//! est celui de `svchost.exe`, partage par des dizaines de services, et ne
//! discrimine rien. La sonde [`plan_sonde_binaire`] est l'instrument de cette
//! mesure.
//!
//! **Une troisieme facon de viser a cote, et ce n'est plus celle du jeton.** Un
//! service peut ne pas faire son reseau DU TOUT. `WerSvc` le delegue a
//! `WerFault.exe`, un processus DISTINCT qui porte son propre jeton: aucun
//! `ALE_USER_ID` sur le SID du service ne peut matcher ces sorties, quel que
//! soit le nombre de filtres poses. Trois sorties relevees le 23/08/2026, dont
//! deux pendant que les filtres de la couche 2 etaient poses. La cible n'etait
//! pas mauvaise, le mecanisme l'etait: l'entree vit desormais du cote
//! [`Cible::Binaire`], sur `System32\WerFault.exe`, et la garde
//! [`tests::aucune_cible_de_service_ne_delegue_son_reseau_a_un_autre_binaire`]
//! refuse le retour en arriere.
//!
//! # Ce qu'un mecanisme mordant ne dit PAS d'une cible
//!
//! Tout ce qui precede parle des MECANISMES. Le catalogue, lui, parle de
//! CIBLES, et le pont entre les deux n'existe pas: `ALE_USER_ID` mord sur
//! `W32Time` et sur trois temoins de test, et `DiagTrack` comme `DoSvc` lui
//! echappent quand meme. `ALE_APP_ID` mord sur une copie jetable du daemon, et
//! **aucune vraie cible du catalogue n'a jamais ete eprouvee sous filtre**.
//!
//! Le produit imprimait pourtant << N pose(s) >>, et un lecteur y comprend
//! << N bloque(s) >>. C'est le malentendu que toute l'enquete du 22 et du
//! 23 aout 2026 a servi a debusquer, et il ne se corrige pas dans le rapport:
//! il se corrige ici, en faisant porter a chaque entree son [`Effet`] MESURE.
//!
//! Trois regles tiennent ce champ, et chacune vient d'un defaut paye:
//!
//! 1. **Un effet ne s'annonce pas sans provenance.** [`Effet::Mordant`] et
//!    [`Effet::SansEffet`] exigent une [`Provenance`] par construction, avec
//!    une date et un role de machine.
//! 2. **Une mesure de mecanisme n'est pas une mesure de cible.** La provenance
//!    doit NOMMER la cible: le 636/639 refus de la sonde de binaire appartient
//!    a la sonde, pas a `CompatTelRunner`.
//! 3. **Un effet ne suit pas une cible qui change de mecanisme.** `WerSvc`
//!    avait trois sorties relevees sous filtres poses; en devenant
//!    `binaire-werfault` la cible a change de condition, et ces trois releves
//!    ne disent plus rien de la nouvelle.
//!
//! Etat du catalogue a l'ecriture de ce champ: **zero cible mesuree
//! mordante**, deux mesurees sans effet (`DiagTrack`, `DoSvc`), huit non
//! mesurees. Ce compte n'est pas fige dans une garde - il bougera - mais
//! [`comptes_effet`] le rend a qui veut l'imprimer.
//!
//! Pur, et hors de `#[cfg(windows)]` pour la meme raison que
//! [`crate::wfp_plan`]: la politique de blocage se verifie sur les deux hotes,
//! meme si elle ne s'applique que sur un seul.
//!
//! # Trois choses mesurees le 22 aout 2026, sur essai-windows build 26200
//!
//! 1. **La derivation nom -> SID est verifiable.** `S-1-5-80-` suivi du SHA-1
//!    du nom en majuscules encode en UTF-16LE, lu en cinq `u32` petit-boutistes.
//!    Deux temoins releves par `sc showsid` servent de test, pas des valeurs
//!    inventees: voir [`tests::la_derivation_rend_les_sid_releves_sur_machine`].
//! 2. **Le piege qui rendrait la couche inoperante en silence:** un service en
//!    `SERVICE_SID_TYPE: NONE` ne porte AUCUN SID de service dans son jeton, et
//!    la condition ne mordrait jamais. Le depot connait deja ce piege pour son
//!    PROPRE service (`service::spec`, `le_service_porte_son_propre_sid`); ici
//!    il vise les services d'en face. Les CINQ services alors au catalogue sont
//!    tous `UNRESTRICTED` sur 26200 - ils ne sont plus que quatre depuis que
//!    `WerSvc` est passe du cote `ALE_APP_ID`, mais la mesure du 22/08 porte
//!    bien sur cinq. Ca se verifie a la pose, jamais ca ne se suppose: une cible
//!    sans SID dans son jeton est SANS OBJET, pas posee.
//! 3. **`SvcHostSplitThresholdInKB` vaut 0x380000**, soit 3,5 Go: au-dessus,
//!    chaque service a son propre processus `svchost.exe`. Ca ne change rien au
//!    raisonnement -- le chemin reste identique -- mais ca explique pourquoi
//!    l'idee de viser le PID est aussi une impasse: il change a chaque
//!    redemarrage du service.

use crate::wfp_plan::{Action, Condition, FilterSpec, Identity, Layer, est_sid_de_service};
use bifrost_core::config::ProfilTelemetrie as Profil;
use sha1::{Digest, Sha1};
use std::path::{Path, PathBuf};

/// Ce qu'un blocage vise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cible {
    /// Un service, par son nom court. Le SID se derive du nom, il ne se lit
    /// pas dans le registre: `sc showsid` le calcule de la meme facon, et un
    /// nom inconnu du systeme donne simplement un SID que personne ne porte.
    Service(&'static str),
    /// Un binaire, par son chemin RELATIF a la racine systeme. La racine est
    /// fournie a la construction du plan, jamais codee en dur: elle n'est pas
    /// toujours `C:\Windows`.
    Binaire(&'static str),
}

/// La condition WFP par laquelle une cible est visee.
///
/// Elle se DEDUIT de la cible - [`Mecanisme::de`] - et pourtant [`Provenance`]
/// la porte aussi. Ce n'est pas une redite: le champ de la provenance dit
/// contre quel mecanisme la mesure a REELLEMENT ete faite, ce qui n'est pas la
/// meme chose que celui que la cible emploie aujourd'hui. Les deux ont diverge
/// une fois, le 23/08/2026, et c'est ce qui rend la garde
/// [`tests::un_effet_mesure_contre_un_mecanisme_ne_suit_pas_la_cible_qui_change`]
/// utile plutot que decorative.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mecanisme {
    /// `FWPM_CONDITION_ALE_USER_ID`, evalue contre le JETON capture a la
    /// creation de la socket. Celui de [`Cible::Service`].
    AleUserId,
    /// `FWPM_CONDITION_ALE_APP_ID`, evalue contre le CHEMIN de l'image, sans
    /// jamais lire de jeton. Celui de [`Cible::Binaire`].
    AleAppId,
}

impl Mecanisme {
    /// Celui qu'une cible emploie. Un `match` exhaustif: le jour ou une
    /// troisieme forme de cible apparait, cette fonction cesse de compiler
    /// plutot que de ranger la nouvelle venue avec l'une des deux autres.
    pub fn de(cible: &Cible) -> Self {
        match cible {
            Cible::Service(_) => Mecanisme::AleUserId,
            Cible::Binaire(_) => Mecanisme::AleAppId,
        }
    }
}

/// Ou, quand, et contre quoi un effet a ete mesure.
///
/// Les quatre champs sont obligatoires PAR CONSTRUCTION: [`Effet::Mordant`] et
/// [`Effet::SansEffet`] en exigent une, donc aucun effet ne peut s'annoncer
/// sans dire d'ou vient le chiffre. C'est la regle que ce depot applique
/// partout ailleurs a la main, et qu'il a payee deux fois - un compte de
/// recettes recopie de memoire, des dates d'issues inventees.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provenance {
    /// Le ROLE de la machine, jamais son nom reel. Une mesure sans machine
    /// n'est pas une mesure: les deux hotes Windows n'ont ni la meme version,
    /// ni les memes binaires systeme, et deux des cibles du catalogue existent
    /// sur l'un et pas sur l'autre.
    pub hote: &'static str,
    /// `JJ/MM/AAAA`. La FORME est gardee, la fraicheur ne l'est pas: une garde
    /// qui se perimerait toute seule ferait rougir le depot un matin sans
    /// qu'aucun defaut n'existe.
    pub date: &'static str,
    /// Le mecanisme REELLEMENT eprouve ce jour-la, qui n'est pas forcement
    /// celui que la cible emploie aujourd'hui.
    pub mecanisme: Mecanisme,
    /// Le chiffre, et l'endroit du depot ou il est ecrit. Il doit NOMMER la
    /// cible: une mesure faite sur un temoin qu'on commande eprouve le
    /// MECANISME, jamais cette cible-la, et confondre les deux est exactement
    /// ce qui a fait croire la couche 2 acquise pendant une journee.
    pub releve: &'static str,
}

/// Ce qu'on a MESURE d'une cible, par opposition a ce qu'on a POSE sur elle.
///
/// Le catalogue disait jusqu'ici combien de filtres etaient poses, et un
/// lecteur comprenait << bloques >>. Les deux ne se recouvrent pas: `DiagTrack`
/// et `DoSvc` portent chacun deux filtres verifies presents dans le moteur,
/// verifies porteurs de leur SID exact, et sortent quand meme.
///
/// Trois etats, et le troisieme est le plus frequent. Il n'y a pas de
/// quatrieme etat << suppose >>: une cible dont on n'a pas la mesure est
/// [`Effet::NonMesure`], meme quand le mecanisme qu'elle emploie, lui, est
/// mesure mordant ailleurs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effet {
    /// Mesure, et le filtre a REFUSE la sortie de CETTE cible-la.
    Mordant(Provenance),
    /// Mesure, et la cible est sortie QUAND MEME, filtre pose et verifie.
    SansEffet(Provenance),
    /// Jamais mesure sur cette cible. `pourquoi` dit ce qui manque pour la
    /// mesurer - un temoin qui emette, un hote ou la cible existe, un
    /// declencheur - et non ce qu'on suppose qu'il arriverait.
    NonMesure { pourquoi: &'static str },
}

impl Effet {
    /// Le mot que le rapport imprime. Court, et sans jamais dire << bloque >>
    /// de ce qui n'a pas ete mesure bloquant.
    pub fn resume(&self) -> &'static str {
        match self {
            Effet::Mordant(_) => "mesure mordant",
            Effet::SansEffet(_) => "mesure sans effet",
            Effet::NonMesure { .. } => "non mesure",
        }
    }

    /// La provenance, quand il y en a une. `None` vaut exactement
    /// [`Effet::NonMesure`]: il n'y a rien a dater.
    pub fn provenance(&self) -> Option<&Provenance> {
        match self {
            Effet::Mordant(p) | Effet::SansEffet(p) => Some(p),
            Effet::NonMesure { .. } => None,
        }
    }
}

/// Combien de cibles dans chaque etat d'effet.
///
/// Existe pour que l'appelant n'ait pas a refaire le `match` lui-meme, et
/// surtout pour qu'il ne puisse pas additionner les mordantes et les
/// non mesurees en un seul nombre rassurant.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ComptesEffet {
    pub mordant: usize,
    pub sans_effet: usize,
    pub non_mesure: usize,
}

impl ComptesEffet {
    /// Le total, qui doit valoir le nombre de cibles du profil.
    pub fn total(&self) -> usize {
        self.mordant + self.sans_effet + self.non_mesure
    }
}

/// Les comptes par etat d'effet, pour les cibles qu'un profil demande.
pub fn comptes_effet(profil: Profil) -> ComptesEffet {
    let mut comptes = ComptesEffet::default();
    for blocage in blocages(profil) {
        match blocage.effet {
            Effet::Mordant(_) => comptes.mordant += 1,
            Effet::SansEffet(_) => comptes.sans_effet += 1,
            Effet::NonMesure { .. } => comptes.non_mesure += 1,
        }
    }
    comptes
}

/// Le blocage qui porte cet identifiant.
///
/// Le rapport de pose ne retient que l'`id` de chaque ligne; sans ce point
/// d'entree, y rattacher l'effet demanderait de rejouer [`blocages`] et de se
/// fier a l'ORDRE des deux parcours. Deux parcours qui se suivent par accident
/// finissent par diverger.
pub fn par_id(id: &str) -> Option<&'static Blocage> {
    CATALOGUE.iter().find(|b| b.id == id)
}

/// Un blocage du catalogue, avec de quoi le justifier a un client.
#[derive(Debug)]
pub struct Blocage {
    pub id: &'static str,
    pub cible: Cible,
    /// Profil a partir duquel le blocage s'applique.
    pub depuis: Profil,
    pub pourquoi: &'static str,
    /// Ce que l'utilisateur perd. Vide est interdit: un blocage qui ne casse
    /// rien du tout n'existe pas, et pretendre le contraire est ce qui fait
    /// desinstaller un produit.
    pub ce_qui_casse: &'static str,
    pub source: &'static str,
    /// Ce que la POSE de ce blocage fait reellement, mesure sur cette cible.
    /// Distinct de [`Blocage::source`], qui justifie qu'on la VISE.
    pub effet: Effet,
}

/// Les services que la couche 2 ne doit JAMAIS viser, quel que soit le profil.
///
/// Ce n'est pas une precaution de style. Le document 03 pose la promesse en
/// toutes lettres: on peut bloquer DiagTrack **tout en laissant** wuauserv et
/// BITS. Un catalogue qui viserait l'un d'eux tiendrait le contraire de ce que
/// le produit annonce, et la garde
/// [`tests::aucune_cible_n_est_dans_la_liste_intouchable`] le refuse a la
/// compilation des tests plutot qu'en clientele.
pub const JAMAIS: &[&str] = &[
    "wuauserv",          // Windows Update
    "BITS",              // transfert en arriere-plan, dont les mises a jour
    "Dnscache",          // sans lui, plus de resolution du tout
    "WinDefend",         // Defender
    "wlidsvc",           // compte Microsoft, donc activation et Store
    "sppsvc",            // activation de la licence
    "cryptsvc",          // verification des signatures, donc des mises a jour
    "LanmanWorkstation", // partages reseau
];

/// Poids des filtres de la couche 2.
///
/// Volontairement au-dessus de zero: le block-all du kill switch vit en 0, et
/// ces filtres-ci doivent valoir AUSSI quand le kill switch est desarme, donc
/// dans leur propre sous-couche. Le choix de la sous-couche appartient a la
/// pose, pas au plan; ce module n'en decide pas et ne pretend pas le contraire.
pub const POIDS: u8 = 10;

/// Le catalogue.
///
/// La repartition entre Equilibre et Strict suit une regle simple: Equilibre ne
/// prend que ce dont l'unique fonction est de mesurer l'utilisateur. Tout ce
/// qui touche a la reparation ou a la distribution des mises a jour part en
/// Strict, avec ce que ca coute ecrit noir sur blanc.
static CATALOGUE: &[Blocage] = &[
    // ---------------------------------------------------------- Equilibre
    Blocage {
        id: "service-diagtrack",
        cible: Cible::Service("DiagTrack"),
        depuis: Profil::Equilibre,
        pourquoi: "Connected User Experiences and Telemetry: le collecteur \
                   principal. C'est la cible que le document 03 nomme quand il \
                   dit que WFP est la seule couche qui distingue un service \
                   d'un autre dans svchost.",
        ce_qui_casse: "Le retour d'experience et les diagnostics envoyes a \
                       Microsoft. Windows Update, le Store et Defender restent \
                       intacts, c'est tout l'interet de viser le SID.",
        source: "docs/03 partie 2.2, et SID releve par sc showsid le 22/08/2026",
        // docs/03, << La mesure decisive du 23 aout 2026, et elle ferme
        // l'enquete >>. Deux echecs concordants, celui du 22/08 et celui-ci.
        effet: Effet::SansEffet(Provenance {
            hote: "essai-windows",
            date: "23/08/2026",
            mecanisme: Mecanisme::AleUserId,
            releve: "DiagTrack sort quand meme: 1 autorisee, 0 refusee, dont par nos \
                     filtres 0, gagnant Default Outbound. Banc a boot + 6 min, les 2 \
                     filtres verifies porteurs du SID exact de DiagTrack et le PID \
                     verifie continu. docs/03, section << La mesure decisive du 23 \
                     aout 2026 >>, scripts/telemetrie-effet-windows.ps1",
        }),
    },
    Blocage {
        id: "service-dmwappushservice",
        cible: Cible::Service("dmwappushservice"),
        depuis: Profil::Equilibre,
        pourquoi: "Routage de messages WAP Push, employe comme canal de \
                   telemetrie de gestion d'appareil.",
        ce_qui_casse: "La gestion a distance par MDM. Sans parc gere, rien.",
        source: "docs/03 partie 1.2, liste des services",
        // docs/03, << Les trois autres, et pourquoi elles ne disent rien >>.
        // Un temoin muet ne certifie rien: ni que le filtre mord, ni qu'il
        // rate. Et constater qu'un temoin est muet n'autorise pas a dire
        // POURQUOI - c'est la faute exacte commise sur CompatTelRunner.
        effet: Effet::NonMesure {
            pourquoi: "Le temoin n'emet pas. Demarre trois fois le 23/08/2026 sur \
                       essai-windows, seul dans son svchost, zero connexion y compris \
                       sur dix minutes d'inactivite, sans omadmclient ni deviceenroller. \
                       Il faudrait un enrolement MDM, absent de cette machine",
        },
    },
    Blocage {
        id: "binaire-compattelrunner",
        cible: Cible::Binaire("System32\\CompatTelRunner.exe"),
        depuis: Profil::Equilibre,
        pourquoi: "Le document 03 note, d'apres WinUtil issue #4035, que ce \
                   binaire se relance a chaque installation malgre la \
                   desactivation de ses taches: le blocage par chemin est le \
                   seul moyen fiable. Ici le chemin SUFFIT, contrairement a \
                   svchost, parce qu'il ne sert qu'a ca.",
        ce_qui_casse: "L'evaluation de compatibilite avant montee de version. \
                       Une mise a niveau majeure peut demander de le reactiver.",
        source: "docs/03 partie 1.3, note operationnelle",
        // docs/03, << Correction: CompatTelRunner.exe SE CONNECTE >>. Le
        // binaire emet, c'est mesure - mais l'emission et l'effet sont deux
        // questions, et seule la premiere a sa reponse. Le mecanisme ALE_APP_ID
        // est mesure mordant le meme jour, sur une COPIE JETABLE du daemon:
        // ce chiffre-la n'appartient pas a cette entree.
        effet: Effet::NonMesure {
            pourquoi: "Jamais eprouve SOUS filtre. Le binaire emet - deux connexions \
                       relevees le 23/08/2026 sur essai-windows apres avoir declenche \
                       ses taches a la main, qui n'avaient jamais tourne - mais son \
                       emission depend du premier passage de l'appraiser et n'est pas \
                       rejouable a volonte. La mesurer demande une machine dont \
                       l'appraiser n'a pas encore tourne",
        },
    },
    Blocage {
        id: "binaire-devicecensus",
        cible: Cible::Binaire("System32\\DeviceCensus.exe"),
        depuis: Profil::Equilibre,
        pourquoi: "Recensement materiel et logiciel de la machine, envoye au \
                   recensement Microsoft.",
        ce_qui_casse: "Rien de visible pour l'utilisateur.",
        source: "docs/03 partie 1.3, processus emetteurs",
        // docs/03, << Ce que le catalogue ALE_APP_ID couvre reellement sur
        // 25H2 >>. Le controle positif tenait au meme instant - 466 puis 448
        // evenements portant une copie jetable du daemon - donc le journal
        // enregistrait bien: le zero est celui de la cible, pas de l'instrument.
        effet: Effet::NonMesure {
            pourquoi: "Temoin muet. A tourne deux fois le 23/08/2026 sur essai-windows, \
                       zero evenement les deux fois, avec un controle positif au meme \
                       instant. Pourquoi il est muet n'est PAS mesure: qu'il ecrive dans \
                       le magasin de telemetrie et que DiagTrack televerse reste une \
                       hypothese",
        },
    },
    // ------------------------------------------------------------- Strict
    Blocage {
        id: "service-dosvc",
        cible: Cible::Service("DoSvc"),
        depuis: Profil::Strict,
        pourquoi: "Delivery Optimization: distribution pair a pair des mises a \
                   jour, qui annonce la machine a un service de coordination.",
        ce_qui_casse: "Les mises a jour se telechargent uniquement depuis \
                       Microsoft, donc plus lentement sur un parc. Elles \
                       arrivent quand meme.",
        source: "docs/03 partie 1.2",
        // docs/03, << DiagTrack n'est PAS un cas particulier: une deuxieme
        // vraie cible echappe >>, puis << CE N'EST PAS NOTRE FILTRE >>. Trois
        // series concordantes, et la derniere n'emploie AUCUN code a nous.
        effet: Effet::SansEffet(Provenance {
            hote: "essai-windows",
            date: "23/08/2026",
            mecanisme: Mecanisme::AleUserId,
            releve: "DoSvc sort quand meme: 26 autorisees, 0 refusee, 2 filtres verifies \
                     porteurs de son SID exact, PID continu, seul dans son svchost. Refait \
                     avec la sonde posee SEULE: 25 / 0, trois passages. Et la regle de \
                     Microsoft echoue identiquement sur DoSvc - New-NetFirewallRule \
                     -Service, 25 autorisees / 0 refusee - la ou la meme commande mord sur \
                     W32Time. docs/03, sections << une deuxieme vraie cible echappe >> et \
                     << CE N'EST PAS NOTRE FILTRE >>",
        }),
    },
    Blocage {
        id: "service-cdpsvc",
        cible: Cible::Service("CDPSvc"),
        depuis: Profil::Strict,
        pourquoi: "Connected Devices Platform: alimente le device-graph, dont \
                   le document 03 note qu'il se cache derriere des IP Azure \
                   Front Door partagees avec Office et Bing. Impossible a \
                   bloquer par IP sans casser le reste; par SID, oui.",
        ce_qui_casse: "Le presse-papiers partage, la reprise d'activite entre \
                       appareils, le partage de proximite.",
        source: "docs/03 partie 3, CDN partages",
        // docs/03, << Les trois autres, et pourquoi elles ne disent rien >>.
        effet: Effet::NonMesure {
            pourquoi: "Le temoin n'emet pas. Vivant 48 tours sur 48 pendant dix minutes \
                       le 23/08/2026 sur essai-windows, redemarrages compris, et zero \
                       evenement: wlidsvc est arrete et la machine ne porte que des \
                       comptes locaux, donc il n'y a rien a synchroniser",
        },
    },
    // Cette entree a longtemps vise le SERVICE `WerSvc`, sous l'identifiant
    // `service-wersvc`, et elle visait a cote PAR CONSTRUCTION: le reseau de
    // Windows Error Reporting n'est pas fait par le service mais par
    // `WerFault.exe`, un processus DISTINCT qui porte son propre jeton. Un
    // `ALE_USER_ID` sur le SID de `WerSvc` ne pouvait pas matcher ces sorties,
    // quel que soit le nombre de filtres poses. Le chemin, lui, ne depend
    // d'aucun jeton, et il est mesure mordant depuis le 23/08/2026.
    //
    // Le pendant 32 bits, `SysWOW64\WerFault.exe`, existe lui aussi - releve le
    // 23/08/2026 sur dev-windows - et n'est PAS vise: les trois sorties
    // relevees viennent toutes de `System32`. Une deuxieme entree posee sans
    // mesure serait une protection annoncee sans preuve. C'est un trou connu,
    // pas un oubli.
    Blocage {
        id: "binaire-werfault",
        cible: Cible::Binaire("System32\\WerFault.exe"),
        depuis: Profil::Strict,
        pourquoi: "Windows Error Reporting: envoie des vidages memoire, qui \
                   peuvent contenir des donnees du document ouvert au moment \
                   du plantage. Vise par le CHEMIN et non par le SID du \
                   service: le reseau n'est pas fait par `WerSvc` mais par \
                   `WerFault.exe`, processus distinct portant son propre jeton, \
                   qu'un filtre sur le SID du service ne pouvait pas matcher.",
        ce_qui_casse: "Plus de remontee de plantage, donc plus de correctif \
                       cible recu de Microsoft pour un bug qu'on subit.",
        source: "docs/03 partie 1.2, et trois sorties de WerFault.exe relevees \
                 le 23/08/2026 sur essai-windows, dont deux filtres poses",
        // docs/03, encadre << FAIT le 23 aout 2026 >>: << Ce qui n'est
        // toujours pas mesure: que ce filtre-la refuse une sortie REELLE de
        // WerFault.exe. Ce qui est mesure, c'est que le MECANISME mord. >>
        // Les deux sorties relevees sous filtres poses l'ont ete sous
        // l'ANCIENNE entree, un ALE_USER_ID sur le SID de WerSvc qui ne
        // pouvait pas les matcher: elles mesurent l'echec de la cible d'avant,
        // pas l'effet de celle-ci.
        effet: Effet::NonMesure {
            pourquoi: "Jamais eprouve EN POSE. Les trois sorties du 23/08/2026 ont ete \
                       relevees quand l'entree etait encore service-wersvc, un filtre \
                       ALE_USER_ID qui ne pouvait pas les matcher par construction. \
                       La mesurer demande essai-windows et un plantage provoque",
        },
    },
    Blocage {
        id: "binaire-musnotification",
        cible: Cible::Binaire("System32\\MusNotification.exe"),
        depuis: Profil::Strict,
        pourquoi: "Notifications du service de mise a jour.",
        ce_qui_casse: "Plus d'invite de redemarrage apres mise a jour: il faut \
                       penser a redemarrer soi-meme.",
        source: "docs/03 partie 1.3, processus emetteurs",
        // docs/03, releve du 22/08 point 5, et << Ce que le catalogue
        // ALE_APP_ID couvre reellement sur 25H2 >>. Sans objet la ou l'on
        // mesure, present la ou l'on ne mesure pas: le trou est reel.
        effet: Effet::NonMesure {
            pourquoi: "Rien a eprouver sur l'hote ou les mesures d'effet se font: absent \
                       de System32 sur essai-windows (25H2), donc SANS OBJET a la pose, \
                       et ses quatre taches y rendent ERROR_FILE_NOT_FOUND. Present sur \
                       dev-windows (19045), ou aucune mesure d'effet ne se fait. Releves \
                       du 22 et du 23/08/2026",
        },
    },
    Blocage {
        id: "binaire-sihclient",
        cible: Cible::Binaire("System32\\SIHClient.exe"),
        depuis: Profil::Strict,
        pourquoi: "Server Initiated Healing: laisse Microsoft declencher des \
                   reparations a distance sur la machine.",
        ce_qui_casse: "Une pile de mise a jour cassee ne se repare plus toute \
                       seule. C'est le prix, et il est reel.",
        source: "docs/03 partie 1.3, processus emetteurs",
        // docs/03, << Ce que le catalogue ALE_APP_ID couvre reellement sur
        // 25H2 >>. Present des deux cotes, et pourtant intestable ici.
        effet: Effet::NonMesure {
            pourquoi: "Pas de declencheur, donc pas de temoin. Present sur essai-windows, \
                       mais aucune des 274 taches de la machine ne le nomme, releve du \
                       23/08/2026: son lanceur est UsoSvc. Le faire emettre a la demande \
                       reste a trouver",
        },
    },
    Blocage {
        id: "binaire-waasmedicagent",
        cible: Cible::Binaire("System32\\WaaSMedicAgent.exe"),
        depuis: Profil::Strict,
        pourquoi: "Windows-as-a-Service Medic: repare la pile de mise a jour, \
                   et defait au passage une partie des reglages de la couche 1.",
        ce_qui_casse: "Meme prix que SIHClient, et c'est le blocage qui \
                       empeche la derive de la couche 1 d'etre annulee.",
        source: "docs/03 partie 1.3, processus emetteurs",
        // docs/03, releve du 22/08 point 5, et << Ce que le catalogue
        // ALE_APP_ID couvre reellement sur 25H2 >>.
        effet: Effet::NonMesure {
            pourquoi: "Rien a eprouver sur l'hote ou les mesures d'effet se font: absent \
                       de System32 sur essai-windows (25H2), donc SANS OBJET a la pose. \
                       Sa tache PerformRemediation existe mais son action porte un Execute \
                       VIDE, c'est un gestionnaire COM. Present sur dev-windows (19045), \
                       ou aucune mesure d'effet ne se fait. Releves du 22 et du 23/08/2026",
        },
    },
];

/// Le SID d'un service, derive de son nom.
///
/// `S-1-5-80-` suivi du SHA-1 du nom **en majuscules**, encode en UTF-16LE sans
/// terminateur, lu en cinq `u32` petit-boutistes. C'est le meme calcul que
/// `sc showsid`, ce qui se verifie: deux SID releves sur machine le 22/08/2026
/// servent de temoins dans les tests.
///
/// La casse est indifferente, comme pour les noms de service eux-memes. Un nom
/// inconnu du systeme rend un SID parfaitement bien forme que personne ne
/// porte: c'est pourquoi l'existence de la cible se verifie a la pose et non
/// ici.
pub fn sid_de_service(nom: &str) -> String {
    let majuscules: String = nom.to_uppercase();
    let utf16: Vec<u8> = majuscules
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();
    let hachage = Sha1::digest(&utf16);
    let mut sid = String::from("S-1-5-80");
    for morceau in hachage.as_chunks::<4>().0 {
        let mot = u32::from_le_bytes(*morceau);
        sid.push('-');
        sid.push_str(&mot.to_string());
    }
    sid
}

/// Les blocages qu'un profil demande. `Aucun` n'en demande aucun.
pub fn blocages(profil: Profil) -> Vec<&'static Blocage> {
    CATALOGUE
        .iter()
        .filter(|b| match profil {
            Profil::Aucun => false,
            Profil::Equilibre => b.depuis == Profil::Equilibre,
            Profil::Strict => true,
        })
        .collect()
}

/// Le catalogue entier, profils confondus.
pub fn tous() -> &'static [Blocage] {
    CATALOGUE
}

/// Le chemin absolu que vise un blocage de binaire.
pub fn chemin(racine_systeme: &Path, relatif: &str) -> PathBuf {
    racine_systeme.join(relatif.replace('\\', std::path::MAIN_SEPARATOR_STR))
}

/// Le plan de filtres pour un profil.
///
/// Chaque blocage donne UN filtre couvrant les quatre couches sortantes v4 et
/// v6. Le v6 n'est pas decoratif: une machine qui n'a pas d'IPv6 aujourd'hui en
/// aura au prochain reseau, et un filtre v4 seul se contournerait tout seul.
/// Vrai si ce texte est le SID d'un service, au sens de [`est_sid_de_service`].
///
/// Analyse la forme `S-1-<autorite>-<sous-autorites>` puis delegue la REGLE,
/// pour qu'il n'y ait toujours qu'un seul endroit ou elle soit ecrite. Refuse
/// une sous-autorite qui ne s'analyse pas, plutot que de l'ignorer: un SID a
/// moitie lu est un SID qu'on ne connait pas.
pub fn est_sid_de_service_texte(sid: &str) -> bool {
    let mut morceaux = sid.split('-');
    if morceaux.next() != Some("S") || morceaux.next() != Some("1") {
        return false;
    }
    let autorite: u64 = match morceaux.next().and_then(|a| a.parse().ok()) {
        Some(v) => v,
        None => return false,
    };
    let mut sous = Vec::new();
    for morceau in morceaux {
        match morceau.parse::<u32>() {
            Ok(v) => sous.push(v),
            Err(_) => return false,
        }
    }
    let octets = autorite.to_be_bytes();
    let mut identifiant = [0u8; 6];
    identifiant.copy_from_slice(&octets[2..]);
    est_sid_de_service(identifiant, &sous)
}

/// Le plan d'UNE sonde de diagnostic: un seul blocage, sur un SID choisi.
///
/// Il existe pour une raison precise et datee. Le 22 aout 2026, la couche 2 a
/// ete mesuree sur essai-windows: filtres poses, verifies presents dans le
/// moteur par `netsh`, portant le SID de DiagTrack - lui-meme verifie present
/// dans le jeton du processus - et **la connexion est passee quand meme**.
/// L'instrument qui nommerait le filtre gagnant est le `FilterRTID` porte par
/// l'evenement 5156, mais DiagTrack n'emet qu'une fois par redemarrage et
/// assechait la fenetre avant qu'on puisse le lire. Isoler la cause demande
/// donc un declencheur qu'on COMMANDE, c'est-a-dire un service de test, donc un
/// SID qui ne sera jamais au catalogue.
///
/// La forme du filtre est celle de [`plan`] et pas une approximation: meme
/// couches, meme poids, meme veto, meme condition. Une sonde qui poserait autre
/// chose que ce qu'on eprouve ne mesurerait pas ce qu'on croit.
///
/// Deux refus, et aucun n'est decoratif: un SID qui n'est pas un SID de service
/// ferait de cette sonde un moyen de couper le reseau d'un utilisateur, et un
/// SID de la liste [`JAMAIS`] casserait la machine par la porte de derriere que
/// le catalogue ferme par devant.
pub fn plan_sonde(sid: &str) -> Result<Vec<FilterSpec>, String> {
    if !est_sid_de_service_texte(sid) {
        return Err(format!(
            "{sid:?} n'est pas un SID de service. Attendu S-1-5-80 et cinq sous-autorites au moins, tel que le rend `sc showsid <service>`"
        ));
    }
    if let Some(nom) = JAMAIS.iter().find(|nom| sid_de_service(nom) == sid) {
        return Err(format!(
            "{sid:?} est le SID de {nom}, qui est intouchable. La sonde ne sert pas a contourner le catalogue"
        ));
    }
    Ok(vec![FilterSpec {
        name: format!("bifrost telemetrie sonde {sid}"),
        layers: vec![Layer::AuthConnectV4, Layer::AuthConnectV6],
        weight: POIDS,
        action: Action::Block,
        hard: true,
        conditions: vec![Condition::UserId(Identity::Sid(sid.to_string()))],
    }])
}

/// Un chemin sous la forme ou deux chemins Windows se comparent: minuscules, et
/// les deux separateurs ramenes a un seul.
///
/// Pas de [`Path::starts_with`], qui decoupe en composants. Sur essai-linux, ou
/// cette politique se verifie aussi, `C:\Windows\System32\x.exe` n'a qu'UN
/// composant et aucun prefixe ne s'y retrouve: la garde serait verte la-bas et
/// mordante ici, c'est-a-dire verte sans regarder sur l'hote qui la compile en
/// premier.
fn forme_comparable(chemin: &Path) -> String {
    chemin
        .as_os_str()
        .to_string_lossy()
        .to_lowercase()
        .replace('\\', "/")
}

/// Vrai si les deux chemins designent la meme entree, a la casse et au
/// separateur pres.
fn meme_chemin(a: &Path, b: &Path) -> bool {
    forme_comparable(a) == forme_comparable(b)
}

/// Vrai si `chemin` est STRICTEMENT sous `racine`. La racine elle-meme n'est
/// pas sous elle-meme, et `C:\Windows2` n'est pas sous `C:\Windows`: le
/// separateur qui suit le prefixe est exige.
fn est_sous(chemin: &Path, racine: &Path) -> bool {
    let racine = forme_comparable(racine);
    let racine = racine.trim_end_matches('/');
    if racine.is_empty() {
        return false;
    }
    let chemin = forme_comparable(chemin);
    chemin.len() > racine.len()
        && chemin.starts_with(racine)
        && chemin.as_bytes()[racine.len()] == b'/'
}

/// Le plan d'UNE sonde de diagnostic sur un CHEMIN de binaire: le pendant de
/// [`plan_sonde`] pour l'autre moitie du catalogue.
///
/// Il existe pour une raison symetrique de celle de son ainee, et tout aussi
/// datee. Le catalogue porte deux mecanismes: `ALE_USER_ID` sur un SID de
/// service, mesure le 22 et le 23 aout 2026 - il mord, 569 refus sur un service
/// de test ordinaire et 673 sur un service au jeton filtre - et `ALE_APP_ID`
/// sur un chemin d'image, qui vise six cibles et, **le jour ou cette sonde a
/// ete ecrite, n'avait jamais ete eprouve qu'en pose**. On savait que les
/// filtres entraient dans le moteur et qu'ils portaient le bon chemin NT; on ne
/// savait pas qu'ils refusaient quoi que ce soit. La moitie du catalogue
/// reposait donc sur une supposition, et cette sonde est l'instrument qui l'a
/// transformee en mesure: 636 puis 639 refus le 23/08/2026, zero connexion
/// autorisee.
///
/// Elle est plus simple que celle des SID: `ALE_APP_ID` compare le chemin de
/// l'image du processus, donc n'importe quel processus fait un temoin et aucun
/// service n'est necessaire.
///
/// La forme du filtre est celle des entrees [`Cible::Binaire`] de [`plan`] et
/// pas une approximation. Une sonde qui poserait autre chose que ce qu'on
/// eprouve ne mesurerait pas ce qu'on croit.
///
/// # Les refus, et pourquoi dans cet ORDRE
///
/// Les deux refus de politique passent AVANT celui d'existence. Ce n'est pas
/// cosmetique: une politique se refuse identiquement sur toute machine, alors
/// que l'existence depend de celle qui execute. Refuser d'abord sur l'existence
/// rendrait les deux gardes de politique vertes partout ou le fichier manque -
/// c'est-a-dire vertes parce qu'elles ne regardent pas, sur essai-linux comme
/// sur toute machine ou la cible n'est pas installee.
///
/// L'intention de [`JAMAIS`] transposee au chemin donne deux interdits et non
/// un: le catalogue, parce qu'une sonde qui poserait en douce ce que
/// `--telemetrie-reseau-appliquer` pose au grand jour ne mesurerait plus rien
/// d'isole; et la racine systeme entiere, parce que c'est la que vivent les
/// binaires dont le blocage casse la machine. La liste nominative n'a pas de
/// sens ici: `JAMAIS` peut enumerer huit services, personne ne peut enumerer
/// les binaires de `System32`.
///
/// # Ce que cette fonction ne sait pas garder
///
/// Un lien symbolique depose hors de la racine et pointant vers un binaire du
/// systeme passerait les deux refus, `FwpmGetAppIdFromFileName0` resolvant la
/// cible. Creer un tel lien demande deja le privilege, que l'appelant possede
/// puisque poser un filtre WFP l'exige: ce n'est donc pas une frontiere de
/// securite, et la pretendre serait pire que de l'ecrire ici.
pub fn plan_sonde_binaire(
    binaire: &Path,
    racine_systeme: &Path,
) -> Result<Vec<FilterSpec>, String> {
    // Les deux lectures, et il en faut deux: sur essai-linux, `C:\a\..\b` n'a
    // qu'un composant et `components()` n'y voit aucune remontee, alors que la
    // forme comparable la montre. L'inverse est vrai d'un chemin natif.
    if binaire
        .components()
        .any(|c| c == std::path::Component::ParentDir)
        || forme_comparable(binaire).split('/').any(|s| s == "..")
    {
        return Err(format!(
            "{} remonte d'un repertoire. Les deux refus qui suivent comparent des \
             chemins, et une remontee les rend inverifiables: donner le chemin sans \
             detour",
            binaire.display()
        ));
    }
    if let Some(blocage) = tous().iter().find(|b| match b.cible {
        Cible::Binaire(relatif) => meme_chemin(binaire, &chemin(racine_systeme, relatif)),
        Cible::Service(_) => false,
    }) {
        return Err(format!(
            "{} est la cible du blocage {} du catalogue. La sonde ne sert pas a \
             contourner le catalogue: pour eprouver cette cible-la, c'est \
             --telemetrie-reseau-appliquer",
            binaire.display(),
            blocage.id
        ));
    }
    if est_sous(binaire, racine_systeme) || meme_chemin(binaire, racine_systeme) {
        return Err(format!(
            "{} vit sous la racine systeme {}. La sonde ne vise que des binaires \
             JETABLES: bloquer un binaire du systeme par la porte de derriere est \
             exactement ce que la liste des intouchables ferme par devant",
            binaire.display(),
            racine_systeme.display()
        ));
    }
    // Le SEUL point de ce module qui touche le disque, et il est delibere:
    // `FwpmGetAppIdFromFileName0` OUVRE le fichier pour en tirer le chemin NT,
    // et rend FWP_E_FILE_NOT_FOUND sinon. Sans ce refus, une faute de frappe
    // remonterait un code WFP au lieu de dire ce qu'on attendait. Le fait que
    // l'appel refuse un fichier absent n'est pas suppose: il est mesure par
    // `windows::ffi::tests::l_identifiant_d_application_refuse_un_fichier_absent`.
    if !binaire.is_file() {
        return Err(format!(
            "{} n'est pas un fichier existant. Attendu: le chemin d'un executable \
             JETABLE deja depose sur CETTE machine, typiquement une copie du daemon \
             dans un repertoire a soi. FwpmGetAppIdFromFileName0 ouvre le fichier \
             pour en tirer le chemin NT que WFP compare, donc un chemin qui ne \
             designe rien ne peut pas devenir une condition ALE_APP_ID",
            binaire.display()
        ));
    }
    Ok(vec![FilterSpec {
        name: format!("bifrost telemetrie sonde binaire {}", binaire.display()),
        layers: vec![Layer::AuthConnectV4, Layer::AuthConnectV6],
        weight: POIDS,
        action: Action::Block,
        hard: true,
        conditions: vec![Condition::AppId(binaire.to_path_buf())],
    }])
}

pub fn plan(profil: Profil, racine_systeme: &Path) -> Vec<FilterSpec> {
    blocages(profil)
        .into_iter()
        .map(|b| FilterSpec {
            name: format!("bifrost telemetrie {}", b.id),
            layers: vec![Layer::AuthConnectV4, Layer::AuthConnectV6],
            weight: POIDS,
            action: Action::Block,
            // Veto: un hard permit concurrent ne doit pas rouvrir la sortie a
            // un service que l'utilisateur a demande de faire taire.
            hard: true,
            conditions: vec![match &b.cible {
                Cible::Service(nom) => Condition::UserId(Identity::Sid(sid_de_service(nom))),
                Cible::Binaire(rel) => Condition::AppId(chemin(racine_systeme, rel)),
            }],
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Les deux temoins: releves par `sc showsid` sur essai-windows le
    /// 22/08/2026, build 10.0.26200.9168. `wuauserv` est la pour une raison
    /// precise: c'est le service qu'il ne faut PAS casser, et savoir calculer
    /// son SID est ce qui permet de verifier qu'aucun filtre ne le porte.
    const TEMOINS: &[(&str, &str)] = &[
        (
            "DiagTrack",
            "S-1-5-80-2620808479-2171380039-3191355562-2070425692-3097948119",
        ),
        (
            "wuauserv",
            "S-1-5-80-1014140700-3308905587-3330345912-272242898-93311788",
        ),
    ];

    #[test]
    fn la_derivation_rend_les_sid_releves_sur_machine() {
        for (nom, attendu) in TEMOINS {
            assert_eq!(
                &sid_de_service(nom),
                attendu,
                "le SID derive de {nom} ne correspond pas a celui que la \
                 machine annonce: toute la couche 2 viserait un service que \
                 personne ne porte, sans jamais le dire"
            );
        }
    }

    /// Les noms de service sont insensibles a la casse, donc leur SID doit
    /// l'etre aussi. Sans ca, `diagtrack` au catalogue viserait dans le vide.
    #[test]
    fn la_casse_du_nom_ne_change_pas_le_sid() {
        assert_eq!(sid_de_service("diagtrack"), sid_de_service("DiagTrack"));
        assert_eq!(sid_de_service("DIAGTRACK"), sid_de_service("DiagTrack"));
    }

    /// Le SID derive doit passer le meme controle de forme que celui que le
    /// daemon applique au sien. Les deux fonctions vivent dans le meme crate
    /// pour qu'elles ne puissent pas diverger en silence.
    #[test]
    fn tout_sid_derive_est_reconnu_comme_sid_de_service() {
        for b in tous() {
            let Cible::Service(nom) = b.cible else {
                continue;
            };
            let sid = sid_de_service(nom);
            let sous: Vec<u32> = sid
                .strip_prefix("S-1-5-")
                .expect("prefixe d'autorite NT")
                .split('-')
                .map(|m| m.parse().expect("sous-autorite numerique"))
                .collect();
            assert!(
                crate::wfp_plan::est_sid_de_service(crate::wfp_plan::AUTORITE_NT, &sous),
                "{nom} rend {sid}, que est_sid_de_service refuse"
            );
        }
    }

    /// La promesse du document 03 est qu'on bloque DiagTrack SANS casser
    /// Windows Update. Un catalogue qui viserait wuauserv ou BITS tiendrait
    /// exactement le contraire.
    #[test]
    fn aucune_cible_n_est_dans_la_liste_intouchable() {
        for b in tous() {
            if let Cible::Service(nom) = b.cible {
                assert!(
                    !JAMAIS.iter().any(|j| j.eq_ignore_ascii_case(nom)),
                    "{} vise {nom}, qui est sur la liste intouchable",
                    b.id
                );
            }
        }
    }

    /// Les services dont le reseau est fait par un AUTRE binaire, et le binaire
    /// qui le fait.
    ///
    /// Releve, jamais devine: `WerFault.exe` y est parce que trois de ses
    /// sorties ont ete relevees le 23/08/2026 sur essai-windows, dont deux
    /// pendant que les filtres de la couche 2 etaient poses. La liste n'a qu'une
    /// entree et c'est voulu: on n'y met que ce qui a ete mesure. Un deuxieme
    /// cas ajoute par analogie ferait de cette garde une opinion.
    const DELEGUENT_LEUR_RESEAU: &[(&str, &str)] = &[("WerSvc", "WerFault.exe")];

    /// La lecon, pas seulement le cas: `ALE_USER_ID` est evalue contre le JETON
    /// du processus qui cree la socket. Un service qui ne fait pas son reseau
    /// lui-meme ne peut donc PAS etre bloque par le SID du service - le
    /// processus qui sort porte son propre jeton, ou le SID du service n'est
    /// pas. Ce n'est pas une defaillance du mecanisme, c'est une cible mal
    /// choisie, et rien dans le type ne l'empeche: `Cible::Service("WerSvc")`
    /// compile aussi bien que n'importe quelle autre.
    ///
    /// Deux exigences, et chacune mord sur une facon differente de se tromper:
    /// remettre la cible du cote du SID, ou la faire disparaitre en croyant la
    /// deplacer.
    #[test]
    fn aucune_cible_de_service_ne_delegue_son_reseau_a_un_autre_binaire() {
        for (service, binaire) in DELEGUENT_LEUR_RESEAU {
            let vise_par_sid = tous().iter().find(
                |b| matches!(b.cible, Cible::Service(nom) if nom.eq_ignore_ascii_case(service)),
            );
            assert!(
                vise_par_sid.is_none(),
                "{} vise le service {service} par ALE_USER_ID, alors que son \
                 reseau est fait par {binaire}, un processus distinct qui porte \
                 son propre jeton: ce filtre ne peut pas mordre, par construction",
                vise_par_sid.map_or("", |b| b.id)
            );
            assert!(
                tous().iter().any(|b| match b.cible {
                    Cible::Binaire(rel) => rel
                        .rsplit('\\')
                        .next()
                        .is_some_and(|fichier| fichier.eq_ignore_ascii_case(binaire)),
                    Cible::Service(_) => false,
                }),
                "le reseau de {service} est fait par {binaire}, et aucune entree \
                 Cible::Binaire du catalogue ne le vise: la cible n'a pas ete \
                 deplacee vers ALE_APP_ID, elle a ete perdue"
            );
        }
    }

    /// Et la verification par le SID plutot que par le nom: si un jour une
    /// cible etait ecrite avec une casse ou une graphie differente, la
    /// comparaison de chaines ci-dessus pourrait la laisser passer alors que
    /// le SID, lui, serait le meme.
    #[test]
    fn aucun_filtre_ne_porte_le_sid_d_un_service_intouchable() {
        let interdits: Vec<String> = JAMAIS.iter().map(|n| sid_de_service(n)).collect();
        for spec in plan(Profil::Strict, Path::new("C:\\Windows")) {
            for c in &spec.conditions {
                if let Condition::UserId(Identity::Sid(sid)) = c {
                    assert!(
                        !interdits.contains(sid),
                        "le filtre {} porte le SID d'un service intouchable",
                        spec.name
                    );
                }
            }
        }
    }

    #[test]
    fn aucune_cible_n_est_visee_deux_fois() {
        let mut vues: Vec<&Cible> = Vec::new();
        for b in tous() {
            assert!(
                !vues.contains(&&b.cible),
                "{} vise une cible deja visee: deux filtres pour un blocage, \
                 et un seul retire au retour en arriere",
                b.id
            );
            vues.push(&b.cible);
        }
    }

    #[test]
    fn aucun_identifiant_n_est_repete() {
        let mut vus: Vec<&str> = Vec::new();
        for b in tous() {
            assert!(!vus.contains(&b.id), "identifiant repete: {}", b.id);
            vus.push(b.id);
        }
    }

    /// Un blocage qui ne coute rien n'existe pas. La case vide est ce qui
    /// permet de vendre une promesse sans contrepartie, puis de la voir
    /// decouverte par l'utilisateur.
    #[test]
    fn chaque_blocage_dit_ce_qu_il_casse_et_d_ou_il_vient() {
        for b in tous() {
            assert!(!b.pourquoi.trim().is_empty(), "{}: pourquoi vide", b.id);
            assert!(
                !b.ce_qui_casse.trim().is_empty(),
                "{}: ce_qui_casse vide",
                b.id
            );
            assert!(!b.source.trim().is_empty(), "{}: source vide", b.id);
        }
    }

    /// Les roles de machine ou un effet de la couche 2 PEUT se mesurer.
    ///
    /// `essai-linux` n'y est pas, et pas par oubli: WFP n'existe pas la-bas.
    /// Une entree qui l'y nommerait annoncerait une mesure impossible. Les
    /// deux Windows y sont tous les deux, et il en faut deux:
    /// `MusNotification.exe` et `WaaSMedicAgent.exe` n'existent que sur
    /// dev-windows, donc c'est le seul endroit ou ils pourraient un jour etre
    /// eprouves.
    const HOTES_QUI_MESURENT: &[&str] = &["dev-windows", "essai-windows"];

    /// `JJ/MM/AAAA`, et rien d'autre. La FORME seulement: juger de la
    /// fraicheur ferait rougir le depot un matin sans qu'aucun defaut
    /// n'existe, ce que `ETAT.md` s'interdit explicitement.
    fn est_une_date(texte: &str) -> bool {
        let octets = texte.as_bytes();
        octets.len() == 10
            && octets[2] == b'/'
            && octets[5] == b'/'
            && [0, 1, 3, 4, 6, 7, 8, 9]
                .iter()
                .all(|i| octets[*i].is_ascii_digit())
    }

    /// Le nom sous lequel une cible se reconnait dans une phrase: le nom du
    /// service, ou le nom du binaire sans son extension.
    fn nom_de(cible: &Cible) -> String {
        match cible {
            Cible::Service(nom) => nom.to_lowercase(),
            Cible::Binaire(rel) => rel
                .rsplit('\\')
                .next()
                .unwrap_or(rel)
                .to_lowercase()
                .trim_end_matches(".exe")
                .to_owned(),
        }
    }

    /// **Un effet ne s'annonce pas sans dire QUAND et SUR QUEL HOTE.**
    ///
    /// Le type impose deja qu'une [`Provenance`] existe; il ne peut pas
    /// imposer qu'elle dise quelque chose. Une provenance a champs vides ou a
    /// date en prose serait exactement la meme absence de preuve, avec
    /// l'apparence du contraire.
    ///
    /// Le pendant vaut pour [`Effet::NonMesure`]: << non mesure >> sans raison
    /// ne se distingue pas de << pas encore rempli >>.
    #[test]
    fn tout_effet_annonce_dit_quand_et_sur_quel_hote() {
        for b in tous() {
            match &b.effet {
                Effet::Mordant(p) | Effet::SansEffet(p) => {
                    assert!(
                        HOTES_QUI_MESURENT.contains(&p.hote),
                        "{}: l'effet est annonce mesure sur {:?}, qui n'est pas un hote \
                         ou la couche 2 se mesure. Attendu l'un de {HOTES_QUI_MESURENT:?}",
                        b.id,
                        p.hote
                    );
                    assert!(
                        est_une_date(p.date),
                        "{}: {:?} n'est pas une date JJ/MM/AAAA. Un effet date << en \
                         aout >> ne se retrouve dans aucun journal de banc",
                        b.id,
                        p.date
                    );
                    assert!(
                        !p.releve.trim().is_empty(),
                        "{}: effet annonce mesure sans releve. Le chiffre et l'endroit \
                         ou il est ecrit sont ce qui separe une mesure d'une opinion",
                        b.id
                    );
                }
                Effet::NonMesure { pourquoi } => assert!(
                    !pourquoi.trim().is_empty(),
                    "{}: non mesure sans raison. << pas encore mesure >> et << mesure \
                     impossible ici >> ne demandent pas la meme suite",
                    b.id
                ),
            }
        }
    }

    /// **Une mesure de MECANISME n'est pas une mesure de CIBLE**, et c'est la
    /// lecon que cette tranche existe pour tenir.
    ///
    /// Le depot a deux chiffres eclatants sous la main: 569 et 673 refus pour
    /// `ALE_USER_ID`, 636 et 639 pour `ALE_APP_ID`. Aucun ne vient d'une cible
    /// du catalogue - ils viennent tous d'un temoin qu'on commande, service de
    /// test ou copie jetable du daemon. Les recopier dans une entree
    /// donnerait un catalogue entierement vert, mesure de bout en bout, et
    /// entierement faux: le jour ou ces chiffres existaient, `DiagTrack` et
    /// `DoSvc` sortaient deja malgre leurs filtres.
    ///
    /// La forme mecanique de cette lecon: le releve doit NOMMER la cible. Un
    /// chiffre pris sur un temoin nomme le temoin.
    ///
    /// **Ce qu'elle ne garde pas, et il faut le dire**: elle n'inspecte que
    /// les entrees qui annoncent un effet mesure. Il y en a deux aujourd'hui.
    /// Sur les huit autres elle ne regarde rien - c'est le prix d'une garde
    /// qui suit l'etat reel plutot que de le figer.
    #[test]
    fn un_effet_annonce_nomme_la_cible_qu_il_a_mesuree() {
        for b in tous() {
            let Some(p) = b.effet.provenance() else {
                continue;
            };
            let nom = nom_de(&b.cible);
            assert!(
                p.releve.to_lowercase().contains(&nom),
                "{}: le releve d'effet ne nomme jamais {nom}. Un chiffre obtenu sur un \
                 temoin qu'on commande mesure le MECANISME, pas cette cible-la, et le \
                 confondre est ce qui a fait croire la couche 2 acquise pendant une \
                 journee. Releve: {}",
                b.id,
                p.releve
            );
        }
    }

    /// **Un effet ne suit pas une cible qui change de mecanisme.**
    ///
    /// Cas reel, et il a coute une relecture complete: `WerSvc` portait trois
    /// sorties relevees, dont deux pendant que les filtres de la couche 2
    /// etaient poses. En passant du cote [`Cible::Binaire`] sous
    /// l'identifiant `binaire-werfault`, la cible a change de CONDITION - et
    /// ces trois releves, faits contre un `ALE_USER_ID` qui ne pouvait pas
    /// matcher, ne disent plus rien de la nouvelle. Garder l'effet en
    /// deplacant la cible aurait converti un echec structurel en preuve.
    ///
    /// La provenance porte donc le mecanisme qu'elle a EPROUVE, et il doit
    /// etre celui que la cible emploie aujourd'hui.
    #[test]
    fn un_effet_mesure_contre_un_mecanisme_ne_suit_pas_la_cible_qui_change() {
        for b in tous() {
            let Some(p) = b.effet.provenance() else {
                continue;
            };
            let emploie = Mecanisme::de(&b.cible);
            assert_eq!(
                p.mecanisme, emploie,
                "{}: l'effet a ete mesure contre {:?}, et la cible emploie {emploie:?} \
                 aujourd'hui. Une cible qui change de condition perd sa mesure: il faut \
                 la refaire, pas la reporter",
                b.id, p.mecanisme
            );
        }
    }

    /// Le contrat que la seconde moitie de la tranche consommera: chaque cible
    /// d'un profil tombe dans exactement un etat d'effet, et [`par_id`]
    /// rattache une ligne de rapport a son entree sans dependre de l'ordre de
    /// deux parcours.
    #[test]
    fn les_comptes_par_effet_couvrent_chaque_cible_du_profil() {
        for profil in [Profil::Aucun, Profil::Equilibre, Profil::Strict] {
            let cibles = blocages(profil);
            let comptes = comptes_effet(profil);
            assert_eq!(
                comptes.total(),
                cibles.len(),
                "{profil:?}: {} cible(s) au profil et {} comptee(s) par etat d'effet. \
                 Un appelant qui additionne les trois etats doit retrouver le nombre \
                 de cibles, sans quoi son rapport en perd en silence",
                cibles.len(),
                comptes.total()
            );
            for b in cibles {
                let retrouve = par_id(b.id)
                    .unwrap_or_else(|| panic!("{} est au profil et introuvable par id", b.id));
                assert_eq!(
                    retrouve.effet, b.effet,
                    "{}: par_id rend une autre entree que le parcours du profil",
                    b.id
                );
            }
        }
    }

    #[test]
    fn le_texte_et_les_octets_disent_la_meme_chose_du_sid() {
        // Toute cible de service du catalogue doit passer les DEUX portes: la
        // derivation, et la relecture du texte qu'elle produit. Si les deux
        // divergent, la sonde refuserait un SID que le catalogue pose.
        for blocage in tous() {
            if let Cible::Service(nom) = blocage.cible {
                let sid = sid_de_service(nom);
                assert!(
                    est_sid_de_service_texte(&sid),
                    "{nom} derive {sid}, que la relecture refuse"
                );
            }
        }
    }

    #[test]
    fn la_sonde_refuse_ce_qui_n_est_pas_un_sid_de_service() {
        // Chaque refus correspond a une facon de se tromper, pas a un cas
        // d'ecole. S-1-5-18 est LOCAL SYSTEM, partage par tous les services:
        // l'accepter couperait la machine. S-1-5-80 tout court designe la
        // FAMILLE des services, meme consequence.
        for texte in [
            "S-1-5-18",
            "S-1-5-80",
            "S-1-5-80-2620808479",
            "S-1-5-21-1234567890-1234567890-1234567890-1001",
            "S-1-5-80-2620808479-2171380039-3191355562-2070425692-abc",
            "pas un sid du tout",
            "",
        ] {
            assert!(
                plan_sonde(texte).is_err(),
                "{texte:?} devrait etre refuse par la sonde"
            );
        }
    }

    #[test]
    fn la_sonde_refuse_le_sid_d_un_service_intouchable() {
        for nom in JAMAIS {
            let sid = sid_de_service(nom);
            let erreur = plan_sonde(&sid).expect_err(&format!(
                "la sonde a accepte le SID de {nom}, qui est intouchable"
            ));
            assert!(
                erreur.contains(nom),
                "le refus doit NOMMER le service, sinon il est indebogable: {erreur}"
            );
        }
    }

    #[test]
    fn la_sonde_pose_exactement_la_meme_forme_que_le_catalogue() {
        // Une sonde qui poserait autre chose que ce qu'on eprouve mesurerait
        // autre chose que ce qu'on croit. C'est tout l'interet du test.
        let racine = Path::new("C:\\Windows");
        let reference = plan(Profil::Strict, racine)
            .into_iter()
            .find(|s| s.name.ends_with("service-diagtrack"))
            .expect("le catalogue doit porter DiagTrack");

        let sonde = plan_sonde("S-1-5-80-1-2-3-4-5").expect("un SID de service valide");
        assert_eq!(
            sonde.len(),
            1,
            "la sonde pose UN blocage, pas une politique"
        );
        let sonde = &sonde[0];

        assert_eq!(sonde.layers, reference.layers);
        assert_eq!(sonde.weight, reference.weight);
        assert_eq!(sonde.action, reference.action);
        assert_eq!(sonde.hard, reference.hard);
        assert_eq!(
            sonde.conditions,
            vec![Condition::UserId(Identity::Sid(
                "S-1-5-80-1-2-3-4-5".into()
            ))]
        );
    }

    #[test]
    fn la_sonde_se_retire_par_le_meme_chemin_que_la_couche() {
        // Le nom porte le prefixe de la couche, donc le balayage de retrait la
        // ramasse. Une sonde avec sa propre sortie de secours serait une sortie
        // de secours de plus a oublier.
        let sonde = plan_sonde("S-1-5-80-1-2-3-4-5").expect("un SID de service valide");
        assert!(
            sonde[0].name.starts_with("bifrost telemetrie "),
            "la sonde doit porter le prefixe de la couche: {}",
            sonde[0].name
        );
    }

    /// Le temoin des recettes de la sonde de binaire: un fichier qui existe
    /// vraiment, sur les deux hotes, et qui n'est ni du catalogue ni du
    /// systeme. Le binaire de la recette elle-meme repond aux trois.
    fn temoin_existant() -> PathBuf {
        std::env::current_exe().expect("le binaire de la recette existe forcement")
    }

    #[test]
    fn la_sonde_binaire_refuse_un_binaire_du_catalogue() {
        // La racine passee est celle qui a servi a construire le chemin: c'est
        // le cas reel, un operateur qui copierait la cible du catalogue.
        let racine = Path::new("C:\\Windows");
        for blocage in tous() {
            let Cible::Binaire(relatif) = blocage.cible else {
                continue;
            };
            let vise = chemin(racine, relatif);
            let erreur = plan_sonde_binaire(&vise, racine).expect_err(&format!(
                "la sonde a accepte {}, qui est la cible du blocage {}",
                vise.display(),
                blocage.id
            ));
            // Le refus doit NOMMER le blocage. Sans cette exigence, le refus de
            // la racine systeme - qui couvre les memes chemins, puisque tout le
            // catalogue vit dans System32 - rendrait cette recette verte alors
            // que la garde du catalogue aurait disparu.
            assert!(
                erreur.contains(blocage.id),
                "le refus doit nommer le blocage du catalogue, sinon la garde de \
                 la racine systeme le couvre et celle-ci ne regarde plus rien: {erreur}"
            );
        }
    }

    #[test]
    fn la_sonde_binaire_refuse_un_binaire_du_systeme() {
        // Un binaire du systeme qui n'est PAS au catalogue: sinon le refus du
        // catalogue repondrait a sa place.
        let racine = Path::new("C:\\Windows");
        for vise in [
            racine.join("System32").join("notepad.exe"),
            racine.join("explorer.exe"),
            racine.join("System32\\drivers\\etc\\quelconque.exe"),
        ] {
            let erreur = plan_sonde_binaire(&vise, racine)
                .expect_err(&format!("la sonde a accepte {}", vise.display()));
            assert!(
                erreur.contains("racine systeme"),
                "le refus doit dire QUELLE regle a mordu: {erreur}"
            );
        }
        // La casse et le separateur ne doivent pas ouvrir de passage: Windows
        // compare les chemins sans egard a l'une ni a l'autre.
        for texte in [
            "c:\\windows\\system32\\notepad.exe",
            "C:/Windows/System32/notepad.exe",
            "C:\\WINDOWS\\SYSTEM32\\NOTEPAD.EXE",
        ] {
            assert!(
                plan_sonde_binaire(Path::new(texte), racine).is_err(),
                "{texte} doit etre refuse: il designe la meme entree que C:\\Windows\\System32\\notepad.exe"
            );
        }
    }

    /// `C:\Windows2` n'est pas sous `C:\Windows`. Une garde qui comparerait des
    /// prefixes sans exiger le separateur refuserait des chemins parfaitement
    /// legitimes, et un refus faux coute aussi cher qu'un refus manquant.
    #[test]
    fn la_racine_systeme_ne_deborde_pas_sur_son_voisin() {
        assert!(!est_sous(
            Path::new("C:\\Windows2\\temoin.exe"),
            Path::new("C:\\Windows")
        ));
        assert!(est_sous(
            Path::new("C:\\Windows\\temoin.exe"),
            Path::new("C:\\Windows")
        ));
        // La racine avec ou sans separateur final designe la meme racine.
        assert!(est_sous(
            Path::new("C:\\Windows\\temoin.exe"),
            Path::new("C:\\Windows\\")
        ));
    }

    #[test]
    fn la_sonde_binaire_refuse_un_chemin_qui_ne_designe_aucun_fichier() {
        let racine = Path::new("C:\\Windows");
        let absent = std::env::temp_dir().join("bifrost-sonde-binaire-qui-n-existe-pas.exe");
        assert!(
            !absent.is_file(),
            "le temoin de cette recette doit etre absent: {}",
            absent.display()
        );
        let erreur = plan_sonde_binaire(&absent, racine).expect_err("un fichier absent");
        assert!(
            erreur.contains("fichier existant"),
            "le refus doit dire ce qui etait attendu: {erreur}"
        );
        // Un REPERTOIRE existe et n'est pas une image: le refus doit tenir.
        let repertoire = std::env::temp_dir();
        assert!(
            plan_sonde_binaire(&repertoire, racine).is_err(),
            "{} est un repertoire, pas une image",
            repertoire.display()
        );
    }

    #[test]
    fn la_sonde_binaire_refuse_une_remontee_de_repertoire() {
        let racine = Path::new("C:\\Windows");
        // La remontee est ce qui permettrait d'atteindre System32 sans que la
        // comparaison de chemins le voie.
        for texte in [
            "C:\\banc\\..\\Windows\\System32\\notepad.exe",
            "C:/banc/../Windows/System32/notepad.exe",
        ] {
            let erreur = plan_sonde_binaire(Path::new(texte), racine)
                .expect_err(&format!("{texte} remonte d'un repertoire"));
            assert!(
                erreur.contains("remonte"),
                "le refus doit dire pourquoi: {erreur}"
            );
        }
    }

    #[test]
    fn la_sonde_binaire_pose_exactement_la_meme_forme_qu_une_entree_du_catalogue() {
        // La reference est une entree REELLE du catalogue, jamais une constante
        // recopiee: une constante recopiee suit le catalogue quand on la change
        // en meme temps, et le trahit quand on l'oublie.
        let racine = Path::new("C:\\Windows");
        let reference = plan(Profil::Strict, racine)
            .into_iter()
            .find(|s| s.name.ends_with("binaire-compattelrunner"))
            .expect("le catalogue doit porter une cible de binaire");
        assert!(
            matches!(reference.conditions.as_slice(), [Condition::AppId(_)]),
            "la reference doit porter UNE condition de chemin: {:?}",
            reference.conditions
        );

        let temoin = temoin_existant();
        let sonde = plan_sonde_binaire(&temoin, racine).expect("un fichier existant hors systeme");
        assert_eq!(
            sonde.len(),
            1,
            "la sonde pose UN blocage, pas une politique"
        );
        let sonde = &sonde[0];

        assert_eq!(sonde.layers, reference.layers);
        assert_eq!(sonde.weight, reference.weight);
        assert_eq!(sonde.action, reference.action);
        assert_eq!(sonde.hard, reference.hard);
        assert_eq!(sonde.conditions, vec![Condition::AppId(temoin)]);
    }

    #[test]
    fn la_sonde_binaire_se_retire_par_le_meme_chemin_que_la_couche() {
        let sonde = plan_sonde_binaire(&temoin_existant(), Path::new("C:\\Windows"))
            .expect("un fichier existant hors systeme");
        assert!(
            sonde[0].name.starts_with("bifrost telemetrie "),
            "la sonde doit porter le prefixe de la couche, sinon le balayage de \
             retrait la laisse derriere: {}",
            sonde[0].name
        );
    }

    #[test]
    fn le_profil_aucun_ne_bloque_rien() {
        assert!(blocages(Profil::Aucun).is_empty());
        assert!(plan(Profil::Aucun, Path::new("C:\\Windows")).is_empty());
    }

    /// Strict contient Equilibre. Un profil plus dur qui relacherait une cible
    /// serait une regression que personne ne verrait.
    #[test]
    fn strict_contient_equilibre() {
        let equilibre: Vec<&str> = blocages(Profil::Equilibre).iter().map(|b| b.id).collect();
        let strict: Vec<&str> = blocages(Profil::Strict).iter().map(|b| b.id).collect();
        for id in equilibre {
            assert!(strict.contains(&id), "{id} disparait en profil Strict");
        }
    }

    /// Un filtre qui ne couvrirait que l'IPv4 se contournerait tout seul des
    /// que la machine change de reseau.
    #[test]
    fn chaque_filtre_couvre_v4_et_v6_et_bloque() {
        for spec in plan(Profil::Strict, Path::new("C:\\Windows")) {
            assert_eq!(
                spec.action,
                Action::Block,
                "{} n'est pas un blocage",
                spec.name
            );
            assert!(
                spec.layers.contains(&Layer::AuthConnectV4)
                    && spec.layers.contains(&Layer::AuthConnectV6),
                "{} ne couvre pas les deux familles d'adresses",
                spec.name
            );
        }
    }

    /// Le coeur du sujet: un filtre sans condition discriminante bloquerait
    /// TOUT. Sur la couche `AuthConnect`, c'est la machine entiere.
    #[test]
    fn aucun_filtre_n_est_sans_condition_discriminante() {
        for spec in plan(Profil::Strict, Path::new("C:\\Windows")) {
            assert!(
                spec.conditions.iter().any(|c| matches!(
                    c,
                    Condition::UserId(Identity::Sid(_)) | Condition::AppId(_)
                )),
                "{} n'a ni SID ni chemin: il bloquerait tout le trafic sortant \
                 de la machine",
                spec.name
            );
        }
    }

    /// Jamais `svchost.exe` par le chemin: c'est l'erreur que le document 03
    /// interdit nommement, parce qu'elle coupe la machine.
    /// La documentation de ce module doit nommer chaque mecanisme que le
    /// catalogue emploie reellement.
    ///
    /// **Ce qu'elle n'aurait PAS attrape, et il faut le dire**: le defaut du
    /// 23/08/2026 etait que l'en-tete parlait bien d'`ALE_APP_ID`, mais pour
    /// expliquer pourquoi on ne s'en sert PAS dans svchost - la chaine etait la,
    /// dans le sens inverse. Une garde de presence n'aurait rien vu. Ce qu'elle
    /// garde est tourne vers l'avant: le jour ou une troisieme forme de cible
    /// apparait, le `match` exhaustif ci-dessous cesse de compiler, et la
    /// documentation ne peut plus l'oublier.
    #[test]
    fn la_documentation_nomme_chaque_mecanisme_du_catalogue() {
        let source = include_str!("plan_telemetrie.rs");
        let entete: String = source
            .lines()
            .take_while(|l| l.starts_with("//!") || l.trim().is_empty())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            entete.len() > 500,
            "l'en-tete lu ne fait que {} caracteres: la lecture est cassee",
            entete.len()
        );
        for blocage in CATALOGUE {
            let condition = match blocage.cible {
                Cible::Service(_) => "ALE_USER_ID",
                Cible::Binaire(_) => "ALE_APP_ID",
            };
            assert!(
                entete.contains(condition),
                "le catalogue emploie {condition} pour {}, et l'en-tete du module \
                 ne le nomme nulle part",
                blocage.id
            );
        }
    }

    #[test]
    fn aucun_blocage_ne_vise_svchost_par_le_chemin() {
        for b in tous() {
            if let Cible::Binaire(rel) = b.cible {
                assert!(
                    !rel.to_lowercase().contains("svchost"),
                    "{} vise svchost par le chemin: tous les services de la \
                     machine partagent ce chemin",
                    b.id
                );
            }
        }
    }

    /// Le chemin d'un binaire est relatif: la racine systeme est fournie a la
    /// construction du plan. Un chemin absolu au catalogue viserait `C:` sur
    /// une machine installee ailleurs.
    #[test]
    fn les_chemins_du_catalogue_sont_relatifs_et_executables() {
        for b in tous() {
            if let Cible::Binaire(rel) = b.cible {
                assert!(
                    !rel.contains(':') && !rel.starts_with('\\'),
                    "{}: {rel} n'est pas relatif a la racine systeme",
                    b.id
                );
                assert!(
                    rel.to_lowercase().ends_with(".exe"),
                    "{}: {rel} n'est pas un executable",
                    b.id
                );
            }
        }
    }
}
