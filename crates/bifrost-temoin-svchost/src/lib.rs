//! Un temoin de mesure heberge dans `svchost.exe`, et rien d'autre.
//!
//! # Pourquoi ce crate existe
//!
//! La couche 2 de l'anti-telemetrie bloque par SID de service. Le MECANISME
//! mord: un blocage `ALE_USER_ID` portant le SID d'un service refuse bien la
//! connexion de ce service. Mesure trois fois sur trois temoins differents -
//! 569, 621 et 673 refus, l'evenement 5157 nommant notre filtre.
//!
//! Et pourtant deux VRAIES cibles lui echappent, `DiagTrack` et `DoSvc`:
//! filtre pose, verifie porteur du SID exact, processus continu et seul dans
//! son `svchost`, et c'est `Default Outbound` qui gagne en AUTORISANT.
//!
//! Tout ce qui pouvait expliquer l'ecart est tombe: le compte, le groupe
//! `svchost`, le type de demarrage, les attributs du SID dans le jeton, le
//! jeton filtre, la protection de processus, la couche, l'arbitrage entre
//! sous-couches, et l'usurpation durable.
//!
//! Il reste UNE difference structurelle entre les temoins et les cibles: les
//! trois temoins bloques portent **leur propre binaire**, les deux cibles qui
//! echappent sont **hebergees dans `svchost.exe`**. C'est une HYPOTHESE.
//! Personne ne l'a mesuree, parce qu'il n'a jamais existe de temoin heberge
//! dans `svchost` dont on maitrise le SID et l'emission.
//!
//! Ce crate est ce temoin.
//!
//! # La question a ete tranchee AILLEURS, quelques heures apres
//!
//! **Ce crate n'a jamais tourne, et il ne le doit plus pour cette raison-la.**
//! Le 23/08/2026, `W32Time` a repondu a la meme question, plus tot et mieux:
//! il est heberge dans `svchost.exe -k LocalService`, et il **se bloque** - 9
//! refus sur 9, deux series independantes. L'hebergement dans `svchost` n'est
//! donc PAS le discriminant, et un vrai service du systeme vaut mieux qu'un
//! montage a nous, dont on pourrait toujours suspecter la representativite.
//!
//! La vraie cause a ete etablie le meme jour, et elle est ailleurs:
//! `FWPM_CONDITION_ALE_USER_ID` est un CONTROLE D'ACCES contre le jeton
//! capture **a la creation de la socket**. Un service qui usurpe l'identite
//! d'un client a cet instant y echappe - mesure: le jeton capture de `DoSvc`
//! porte un compte utilisateur, pas `NetworkService`. Et ce n'est pas notre
//! filtre: `New-NetFirewallRule -Service DoSvc -Action Block`, la construction
//! de Microsoft, echoue identiquement. Detail dans `docs/03-anti-telemetrie-os.md`.
//!
//! **Ce qui reste a ce crate**, et ce n'est pas rien: c'est le seul moyen de
//! poser un service heberge dans `svchost` dont on maitrise le SID, la ligne
//! de commande et l'emission. Toute question future sur l'identite WFP d'un
//! service heberge passera par lui. Il est livre comme instrument, pas comme
//! mesure faite.
//!
//! # Ce qu'il est, et ce qu'il n'est pas
//!
//! C'est un instrument de DIAGNOSTIC. Il ne protege rien, ne pretend rien
//! proteger, n'entre dans aucun profil, et le produit ne l'installe jamais.
//! Il se pose par `scripts/telemetrie-svchost-windows.ps1`, qui le retire.
//!
//! # Les trois choses qu'il doit faire, et pourquoi chacune
//!
//! 1. **S'annoncer au gestionnaire de services.** Un service qui n'appelle pas
//!    `RegisterServiceCtrlHandlerW` puis `SetServiceStatus(SERVICE_RUNNING)`
//!    est tue par le SCM au bout de son delai. Le temoin mourrait avant
//!    d'emettre, et une absence de connexion se lirait comme un blocage.
//! 2. **Emettre DEPUIS le processus `svchost`.** C'est tout l'objet de la
//!    mesure. Un processus fils porterait SON jeton, pas celui du service
//!    heberge, et la mesure ne dirait rien de l'hypothese. La rafale tourne
//!    donc sur le thread que le SCM nous donne, dans `svchost.exe`.
//! 3. **Reutiliser la sonde qui existe.** Le temoin appelle
//!    [`bifrost_daemon::wfp_identity::rafale`], celle que `--connect-probe`
//!    execute, plutot que d'ecrire une seconde boucle de connexion. Deux
//!    implementations qui divergeraient rendraient deux mesures incomparables,
//!    et ce depot a deja paye ce principe ailleurs.
//!
//! # La limite que cette mesure ne peut PAS effacer: le drapeau `-p`
//!
//! `DiagTrack` et `DoSvc` tournent en `svchost.exe -k <groupe> -p`. Ce `-p`
//! active une politique d'attenuation qui n'accepte que des images signees par
//! Microsoft. Cette DLL ne l'est pas: le temoin tourne donc **sans `-p`**, et
//! aucun reglage de ce crate ne peut changer cela.
//!
//! Ce qu'on mesure ici est donc exactement: *un service qui porte son propre
//! SID, heberge dans `svchost.exe` SANS `-p`, est-il refuse par un blocage
//! `ALE_USER_ID` sur son SID ?* La question du `-p` reste ouverte et se mesure
//! ailleurs, sur un VRAI service Windows heberge dans svchost.
//!
//! Le temoin ne se contente pas de le dire dans un rapport: il releve la ligne
//! de commande de son propre processus et l'ecrit dans son journal, `-p`
//! compris ou absent. Une limite qu'on affirme sans la relever n'est pas une
//! limite mesuree.
//!
//! # Ou vit quoi
//!
//! [`config`] est PUR et se compile partout: c'est la ou se decide ce qui
//! compte comme configuration valide, et cela doit pouvoir se tester sans
//! machine Windows. Le reste - le SCM, le registre, la ligne de commande - vit
//! dans `hote`, sous `cfg(windows)`.

pub mod config;

#[cfg(windows)]
mod hote;
