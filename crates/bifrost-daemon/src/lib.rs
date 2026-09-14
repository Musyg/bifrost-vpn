//! Daemon privilegie Bifrost.
//!
//! Expose ses modules en bibliotheque pour que la suite de tests de fuite soit
//! executable depuis `cargo test` en CI, et pas seulement a travers l'IPC.

/// Interdit a tout processus lance par le daemon de lui survivre.
///
/// Sous Windows uniquement: sous Linux la garde se pose par processus,
/// entre le `fork` et l'`exec`, et vit donc dans les modules qui lancent.
#[cfg(windows)]
pub mod anti_orphelin;
/// Reconnaitre le reseau courant sans rien emettre, et ranger ce qu'on a
/// appris de lui. Le pendant impur de `bifrost_evasion::carnet`.
pub mod carnet;
pub mod checks;
pub mod coeurs;
/// La sonde QUIC. Separee de `sondes` parce qu'elle fabrique des paquets
/// complets, chiffrement compris, la ou les autres n'ouvrent que des sockets.
pub mod quic;
/// Cycle de vie du resolveur chiffre embarque.
///
/// Compile partout: le lancement, l'attente d'une reponse et le drainage de la
/// sortie d'erreur n'ont rien de specifique. Seules la garde anti-orphelin et
/// la terminaison douce sont gardees par `cfg`, faute d'equivalent portable.
pub mod resolveur;
pub mod server;
pub mod service;
pub mod sondes;
pub mod supervisor;
pub mod tls;
pub mod tunnel;

/// Le pendant Linux de `wfp_veille`. Meme question, trois differences qui ont
/// chacune demande une mesure: le drop nftables n'a pas de signal d'erreur, le
/// compteur du ruleset fournit le temoin positif qui manque, et `Instant` ne
/// compte pas le temps suspendu, a l'inverse de Windows.
#[cfg(target_os = "linux")]
pub mod veille_linux;

/// La source des reprises, cote Windows: le daemon s'abonne LUI-MEME aux
/// notifications d'alimentation, et rien ne transite par l'IPC.
///
/// Le pendant Linux n'est pas ici et ne peut pas y etre: la seule voie qui
/// n'ajoute pas de dependance DBus au daemon est un hook `systemd-sleep`, donc
/// un processus tiers. Il vit dans `bifrost-cli`, module `reprise_linux`, et
/// arrive par `Command::Reprise` sur l'IPC. Ce que la veille elle-meme laisse
/// des regles sous Linux est encore une autre question, mesuree par
/// [`crate::veille_linux`].
#[cfg(windows)]
pub mod reprise;

/// La recette du probleme ouvert 2: la fenetre de fuite au demarrage machine
/// se ferme-t-elle avec des filtres poses depuis l'espace utilisateur.
#[cfg(windows)]
pub mod boot_filtres;

/// Le vecteur `dns-leak` sous Windows, le premier des sept a avoir ete cable:
/// il ne demandait ni tunnel, ni coeur, ni IPv6.
#[cfg(windows)]
pub mod dns_leak;

/// Le vecteur `coeur-exemption` sous Windows. Il ne demande pas non plus de
/// coeur en cours d'execution: l'exemption designe un CHEMIN et une identite,
/// pas un processus vivant.
#[cfg(windows)]
pub mod coeur_exemption;

/// Le vecteur `resolveur-exemption` sous Windows: le miroir du precedent, et
/// son contraire. Le coeur est exempte pour sortir HORS du tunnel; le resolveur
/// chiffre est exempte pour emettre du :53 malgre le blocage, et rien de plus.
#[cfg(windows)]
pub mod resolveur_exemption;

/// Le vecteur `ipv6-leak` sous Windows. Il porte une notion de PORTEE: une
/// cible globale mesure la fuite reelle, une cible locale les memes couches
/// sans le chemin de sortie.
#[cfg(windows)]
pub mod ipv6_leak;

/// Le vecteur `exit-ip` sous Windows. Contrairement a ce que son nom laisse
/// croire, il ne compare aucune adresse publique: il etablit que le trafic
/// sort par le tunnel et que rien ne part en clair vers les memes
/// destinations. Il exige un vrai pair distant.
#[cfg(windows)]
pub mod exit_ip;

/// Les vecteurs `kill-switch-on-drop` et `reconnect-window` sous Windows. Le
/// tunnel qu'ils demandent n'a pas besoin de transporter: il leur faut une
/// interface qui existe puis qui n'existe plus.
#[cfg(windows)]
pub mod chute_tunnel;

/// Le vecteur `startup-window` sous Windows, le seul en deux temps: ce qu'il
/// mesure vaut avant que le daemon existe, donc de part et d'autre d'un reboot.
#[cfg(windows)]
pub mod startup_window;

/// Le temoin de blocage sous Windows: quel filtre a jete quel paquet. C'est ce
/// qui remplace l'isolation par namespaces, absente de Windows.
#[cfg(windows)]
pub mod temoin_wfp;

#[cfg(windows)]
pub mod wfp_identity;
#[cfg(windows)]
pub mod wfp_leaktest;
#[cfg(windows)]
pub mod wfp_selftest;
#[cfg(windows)]
pub mod wfp_veille;

/// Couche 1 de l'anti-telemetrie: le versant qui touche la machine.
///
/// Le jugement vit dans `bifrost-telemetrie`, qui se teste partout; ici il
/// n'y a que le registre, les taches planifiees et le jeton du processus.
#[cfg(windows)]
pub mod telemetrie;

/// Couche 2 de l'anti-telemetrie: le blocage reseau par SID de service.
///
/// Le PLAN vit dans `bifrost_firewall::plan_telemetrie`, pur et verifie sur les
/// deux hotes; ici il n'y a que le SCM, le systeme de fichiers et le moteur WFP.
#[cfg(windows)]
pub mod telemetrie_reseau;
