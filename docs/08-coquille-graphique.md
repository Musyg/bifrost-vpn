# 08 - Coquille graphique

Date: 16 octobre 2026. Specification et etat de la coquille graphique de
Bifrost: une fenetre et une icone de la zone de notification (tray) qui
commandent le daemon. Ce document complete le document 06 (separation entre
daemon privilegie et interface non privilegiee, partie 1.2) sans le remplacer.
L'etat courant et les comptes de recettes sont dans ETAT.md.

## Perimetre

La coquille fait trois choses, et seulement trois:

- montrer l'etat du tunnel et du kill switch, relu toutes les deux secondes;
- monter le tunnel avec le profil que le daemon detient deja
  (`connect-stored`): la coquille ne lit, n'importe ni ne transmet aucune cle;
- le demonter (`disconnect`).

Elle n'offre ni import de profil, ni `check`, ni preuve, ni reglage: ces
commandes restent dans la CLI. Une surface qu'on n'ouvre pas est une surface
qu'on n'a pas a defendre.

Elle tient en trois parties du depot:

| Partie | Ou | Ce qu'elle porte |
|---|---|---|
| Logique | `crates/bifrost-coquille`, membre de l'espace de travail | poste de commande (IPC), vue derivee de l'etat ou de l'erreur, garde d'elevation; aucune dependance graphique |
| Icone | `crates/bifrost-icone`, membre de l'espace de travail | dessin de l'icone et des trois pastilles du tray par le code, PNG et ICO ecrits a la main, sans dependance |
| Fenetre | `gui/`, espace de travail separe (Tauri 2) | la fenetre, le tray, la page (HTML, JavaScript, CSS), la configuration de Tauri et ses capacites |

`gui/` a son propre `Cargo.lock`: la pile de la WebView (Tauri, et sous Linux
gtk-rs et WebKitGTK) n'entre pas dans le verrou des binaires privilegies. Sa
politique d'avis, de licences et de sources est `gui/deny.toml`; ses avis
ignores, chacun avec sa raison datee, y sont, et les memes identifiants sont
dans `gui/.cargo/audit.toml`.

## Une coquille non privilegiee

La coquille n'a besoin d'aucun privilege: elle commande le daemon par l'IPC,
comme la CLI. Elle refuse de demarrer elevee: sous Windows un jeton eleve
(`TokenElevation`), sous Linux un `euid` nul. Elle ecrit alors pourquoi sur la
sortie d'erreur et sort en code 3, avant de creer une fenetre. Une WebView
lancee en administrateur ferait tourner toute la surface web avec des droits
qu'elle n'a pas a avoir.

Pas de demarrage automatique: la coquille se lance a la main, depuis une
session ordinaire. Fermer la fenetre la cache; `Quitter`, dans le menu du
tray, arrete le processus.

## Regles de l'IPC

Du cote de la coquille:

- le canal ne s'ouvre que par `connect_verified`, avec l'exigence des
  commandes de la CLI: sous Linux un serveur root (`SO_PEERCRED`), sous
  Windows un pipe possede par LocalSystem ou par les Administrateurs. Un
  processus qui tiendrait le canal sans cette identite ne recoit rien, pas
  meme la commande;
- trois commandes seulement: l'etat, `connect-stored` et `disconnect`.

Du cote du daemon, rien ne change: il admet sous Linux root et les membres du
groupe de pilotage `bifrost`, sous Windows SYSTEM et les Administrateurs (DACL
du pipe). Sous Linux, une coquille lancee par un membre du groupe `bifrost`
commande donc le daemon comme la CLI du meme compte (lu dans le code, pas
mesure par un lancement reel).

**Limite sous Windows.** La coquille tourne sans elevation, et le pipe du
daemon n'admet que SYSTEM et les Administrateurs: sous Windows, elle ne
commande pas encore le daemon. Elle le montre sans le maquiller: `daemon
injoignable`, une note qui en donne les causes possibles (service arrete,
compte sans le droit d'ouvrir son canal, echange coupe), et un tray gris. Un
groupe d'acces au canal, pose par l'installeur Windows, levera cette limite;
il n'existe pas encore. Lancement reel du 16/10/2026 sur dev-windows, sans
elevation et sans daemon: la fenetre dit `daemon injoignable` et, pour le
kill switch, `inconnu (daemon injoignable)`, avec la note et une pastille
grise; `Connecter` et `Deconnecter` sont inactifs; l'info-bulle du tray dit
`Bifrost - daemon injoignable`. Le meme rendu deux minutes plus tard.

## Chaque etat, son rendu

La vue est derivee de l'etat que rend le daemon, ou de l'erreur du poste de
commande. Un seul etat se lit comme connecte et rend le tray vert: le tunnel
etabli que le daemon declare. Aucune erreur ne le fait.

| Etat de la vue | D'ou il vient | Fenetre | Tray |
|---|---|---|---|
| `connecte` | le daemon: tunnel etabli | `connecte`, kill switch, interface, serveur, transfert | vert |
| `connexion-en-cours` | le daemon: montee, avec sa tentative | `connexion en cours (tentative N)` | rouge |
| `reprise` | le daemon: remontee, avec sa tentative | `reprise (tentative N)` | rouge |
| `echec` | le daemon: etat d'erreur, avec sa raison | `echec: <raison>` | rouge |
| `deconnecte` | le daemon: aucun tunnel | `deconnecte` | gris |
| `daemon-injoignable` | personne ne tient le canal, ou personne que ce compte puisse joindre, ou l'echange a ete coupe | `daemon injoignable`, kill switch `inconnu`, une note | gris |
| `daemon-sans-reponse` | un serveur tient le canal et n'a pris aucune connexion de plus dans le delai | `daemon sans reponse dans le delai`, une note: rien ne dit qu'il soit arrete | gris |
| `serveur-non-admis` | un serveur tient le canal sans l'identite du daemon | sa cause, et `rien ne lui a ete envoye` | gris |
| `refuse` | le daemon a refuse l'appelant, ou rendu une autre erreur | `acces refuse par le daemon`, ou `erreur du daemon: <message>` | gris |

Rouge dit "actif sans etre etabli": un tunnel est attendu et n'est pas la.
Quand l'etat attend un kill switch que le daemon ne declare pas arme, la ligne
du kill switch le dit en toutes lettres (`NON ARME alors que l'etat est ... -
le trafic peut fuir`). Les boutons de la fenetre suivent l'etat: `Connecter`
depuis `deconnecte` ou `echec`, `Deconnecter` des qu'un tunnel est attendu;
apres une erreur, aucun des deux. L'info-bulle du tray et l'entree `Etat` de
son menu portent le texte de l'etat (`Bifrost - <etat>`, `Etat: <etat>`). Un
etat que la page ne connaitrait pas s'affiche comme tel (`Etat inconnu de
cette page`), jamais comme un autre.

## Ce qui garde ces regles

- `crates/bifrost-coquille`: la vue (aucune erreur lue comme connectee ni
  rendue verte), la garde d'elevation dans les deux sens, l'exigence du
  canal, contre un faux serveur d'un compte ordinaire et contre un canal
  occupe.
- `crates/bifrost-coquille/tests/gui_conf.rs`: l'identifiant Tauri
  (`io.github.musyg.bifrost-vpn`), la CSP exacte, les capacites exactes
  (`core:default` et `core:event:default`, fenetre `main`), le bundling
  desactive, aucune image ni aucun binaire dans `gui/`, et une note de la page
  pour chaque etat de la vue, non vide pour chaque erreur et sans le mot
  connecte.
- les recettes de `gui/` (`cargo test --manifest-path gui/Cargo.toml`):
  chaque erreur et chaque etat peints tels que la vue les derive, aucune
  erreur en vert, au tray comme dans l'info-bulle.
- la CI: le job `interface-linux` formate, compile, passe clippy et lance ces
  recettes a chaque push et a chaque PR; `interface-windows` fait de meme sur
  un lancement manuel avec la case `windows`. Une PR qui touche `gui/`,
  `crates/bifrost-coquille`, `crates/bifrost-icone`, `crates/bifrost-ipc` ou
  `packaging/msi` attend un run manuel `windows` vert sur sa revision avant sa
  fusion. Le job `dependances` lance `cargo audit` et `cargo deny check`
  depuis `gui/`, y compris sur le run planifie quotidien.

## Ce qui n'est pas fait

- Aucun paquet: ni MSI, ni .deb, ni .rpm, pour la coquille comme pour le
  daemon. `bundle.active` vaut `false` dans `gui/tauri.conf.json`; la
  coquille se construit depuis les sources (`cargo build --manifest-path
  gui/Cargo.toml`), et ses icones sont engendrees a la construction, sous
  `gui/target/`.
- Sous Windows, la commande du daemon par une coquille non elevee (voir la
  limite ci-dessus).
- Sous Linux, aucun lancement reel de la fenetre n'est mesure: la coquille y
  est construite et ses recettes y tournent, dans le job `interface-linux`.
- Le refus de demarrer elevee est garde par recette dans les deux sens; il
  n'a pas ete observe sur un lancement reel eleve.
- `cargo vet` ne couvre pas le verrou de `gui/`.
