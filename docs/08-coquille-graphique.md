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

Du cote du daemon: il admet sous Linux root et les membres du groupe
`bifrost`; sous Windows SYSTEM, les Administrateurs et, si le service en
nomme un, les membres de son groupe d'acces. Sur les deux plateformes, un
membre du groupe n'y a que trois commandes (partie suivante); root, SYSTEM
et un jeton aux Administrateurs actifs gardent tout le canal (pour SYSTEM,
mesure sur essai-windows, partie suivante). La coquille d'un compte admis
lui envoie l'etat, `connect-stored` et `disconnect`, et rien d'autre: pour
ces trois gestes, elle fait ce que fait la CLI du meme compte. Sous Linux,
ce point est lu dans le code, pas mesure par un lancement reel.

## Le groupe d'acces sous Windows

La coquille tourne sans elevation. Sous Windows, le canal l'admet par un
groupe local, le groupe d'acces que le daemon recoit par `--group <nom>`.

- **Qui le cree.** L'installeur (`packaging/install-windows.ps1`) cree le
  groupe local `Bifrost`, vide, s'il n'existe pas, et le passe a
  `--install-service --group`, qui ecrit dans la ligne du service
  `--group "<SID>"`: le SID du groupe, sous la forme que rend le systeme. Un
  administrateur y ajoute les comptes qui commandent le daemon
  (`Add-LocalGroupMember -Group Bifrost -Member <compte>`); l'appartenance
  vaut a la prochaine ouverture de session du compte.
- **Ce qui est admissible.** Un groupe local cree par un administrateur, et
  lui seul: un SID du domaine de la machine, `S-1-5-21-<a>-<b>-<c>-<RID>`,
  de RID 1000 ou plus, de type groupe local. Jamais un compte, ni un groupe
  ou un compte predefini (`Utilisateurs`, `Tout le monde`, l'administrateur
  integre). Le nom ou le SID donne est resolu par le systeme, et le jugement
  porte sur la forme que celui-ci rend (`EqualSid`, SID canonise), jamais
  sur la chaine tapee: zeros de tete et casse n'y changent rien.
- **Fail-closed.** Un groupe introuvable ou non admissible arrete le daemon
  au demarrage, avant que son superviseur ne tourne, avec un message qui
  nomme le groupe et la raison; `--install-service --group` refuse
  d'inscrire le service. Sans `--group`, le descripteur du pipe est
  `D:P(A;;GA;;;SY)(A;;GA;;;BA)`.
- **Ce que le pipe accorde au groupe.** Avec un groupe, le descripteur
  porte une ACE de plus, et une seule: `(A;;0x120083;;;<SID>)`. Ce masque
  accorde la lecture et l'ecriture du canal (`FILE_READ_DATA`,
  `FILE_WRITE_DATA`), la lecture de ses attributs et de son descripteur
  (`FILE_READ_ATTRIBUTES`, et `READ_CONTROL`, qui sert a verifier le
  proprietaire) et l'attente (`SYNCHRONIZE`): de quoi ouvrir le canal et y
  echanger.
- **Ce qu'un membre peut demander.** Trois commandes, par la coquille comme
  par la CLI: l'etat, `connect-stored` (le profil que le daemon detient,
  enregistre par un administrateur) et `disconnect`. SYSTEM et un jeton aux
  Administrateurs actifs (une console elevee, le service lui-meme) gardent
  tout le canal. Pour SYSTEM, c'est mesure le 17/10/2026 sur essai-windows,
  par une tache planifiee ponctuelle sous SYSTEM (session 0) et le binaire
  des recettes: le pipe lie comme en service appartient a LocalSystem, le
  client l'admet sous la regle des preuves comme sous celle des commandes,
  et les dix commandes du protocole atteignent le serveur, l'appelant
  identifie SYSTEM, Administrateurs actifs, au niveau complet. Le daemon
  identifie l'appelant de chaque requete sur le
  jeton que le pipe lui presente: il emprunte l'identite du client
  (`ImpersonateNamedPipeClient`), ouvre le jeton du fil, rend au fil son
  propre jeton (`RevertToSelf`, sur tous les chemins), puis demande au
  systeme si SYSTEM y est present et les Administrateurs actifs
  (`CheckTokenMembership`). Un appelant qu'il ne sait pas identifier, par
  exemple un client ouvert en `SECURITY_ANONYMOUS`, a les trois commandes
  et elles seules. Toute autre commande recoit un refus qui la nomme
  (`commande <nom> refusee: reservee aux administrateurs`, suivi de ce que
  le compte peut demander) et n'atteint jamais le daemon. Mesure le
  17/10/2026 sur une machine virtuelle Windows Server 2025 jetable (build
  26100), UAC active: un administrateur non eleve, membre du groupe
  d'acces (un compte de recette cree dans une surcouche jetable), lance
  avec son jeton filtre, lit son jeton lie (Administrateurs actifs, niveau
  identification). Porte par un fil, ce jeton lie ne permet ni d'ouvrir le
  pipe (`CreateFileW` rend 1346, `ERROR_BAD_IMPERSONATION_LEVEL`) ni d'y
  ecrire (`WriteFile` rend 1346), en suivi statique comme dynamique du
  contexte, avec ou sans `SECURITY_EFFECTIVE_ONLY`. Chaque requete atteint
  donc le daemon sous le jeton filtre: niveau restreint, `check` refuse.
  Non mesure: Windows 10 et 11, le service reel, les entrees et sorties
  asynchrones, un bureau interactif. Sous Linux, la
  regle est la meme pour un membre du groupe `bifrost` (gid primaire ou
  groupe supplementaire), identifie a l'acceptation par `SO_PEERCRED`, une
  fois par connexion; son refus dit `reservee a root`, et root garde tout
  le canal.
- **Ce qu'il ne peut pas faire.** Creer une instance du pipe: le masque ne
  porte ni `FILE_CREATE_PIPE_INSTANCE` (0x4, la valeur de `FILE_APPEND_DATA`
  pour un pipe), ni `GENERIC_ALL`; un membre ne peut donc pas tenir le canal
  a la place du daemon. Il ne peut pas non plus changer le descripteur ni le
  proprietaire du pipe, et le client exige toujours un pipe possede par
  LocalSystem ou par les Administrateurs.
- **L'ouverture du client.** `bifrost-ipc` ouvre le canal par les droits
  individuels `FILE_READ_DATA | FILE_WRITE_DATA | READ_CONTROL` (0x20003),
  et le systeme y ajoute `SYNCHRONIZE` et `FILE_READ_ATTRIBUTES`: tous dans
  le masque du groupe. Une ouverture en `GENERIC_WRITE` demanderait aussi
  `FILE_WRITE_ATTRIBUTES` et `FILE_WRITE_EA`, que ce masque n'accorde pas
  (mesure sur dev-windows: refusee).

Un compte que le canal n'admet pas recoit un refus a l'ouverture
(`ERROR_ACCESS_DENIED` sous Windows, `EACCES` sous Linux). La coquille le
rend dans un etat a lui, `compte non admis par le canal`, avec une note qui
nomme le groupe d'acces et un tray gris: jamais `daemon injoignable`,
jamais vert.

Ce refus n'est pas toujours celui du daemon. Sous Linux, le repertoire du
socket par defaut appartient a root: c'est le daemon qui fixe les droits du
socket, et le texte de l'etat dit `ce compte n'a pas acces au daemon`. Sous
Windows, le nom du pipe est libre quand le service est arrete, et un autre
processus peut le tenir avec une DACL qui refuse ce compte: l'ouverture
echoue alors avant toute verification d'identite, et sans poignee ni le
proprietaire ni le processus serveur ne se lisent. Le texte de l'etat dit
donc les deux cas (`le daemon ne l'admet pas, ou un autre processus tient ce
nom`), assez court pour l'info-bulle du tray, et la note de la page aussi.
`bifrost-cli` nomme ce refus de la meme facon pour toutes ses commandes, et
`emergency-disarm` en avertit sans refuser.

Lancement reel du 16/10/2026 sur dev-windows, revision `10ef89b`, sans
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
| `daemon-injoignable` | personne ne tient le canal, ou l'echange a ete coupe | `daemon injoignable`, kill switch `inconnu`, une note | gris |
| `compte-non-admis` | le systeme refuse a ce compte d'ouvrir le canal (`ERROR_ACCESS_DENIED`, `EACCES`): sous Windows hors du groupe d'acces, ou un autre processus tient le nom du pipe; sous Linux hors du groupe du socket | `compte non admis par le canal` et sa cause, selon la plateforme (`ce compte n'a pas acces au daemon` sous Linux, `le daemon ne l'admet pas, ou un autre processus tient ce nom` sous Windows), kill switch `inconnu`, une note qui nomme le groupe d'acces | gris |
| `daemon-sans-reponse` | un serveur tient le canal et n'a pris aucune connexion de plus dans le delai | `daemon sans reponse dans le delai`, une note: rien ne dit qu'il soit arrete | gris |
| `serveur-non-admis` | un serveur tient le canal sans l'identite du daemon | sa cause, et `rien ne lui a ete envoye` | gris |
| `refuse` | le daemon a refuse l'appelant, ou rendu une autre erreur | `acces refuse par le daemon`, ou `erreur du daemon: <message>` | gris |

Rouge dit "actif sans etre etabli": un tunnel est attendu et n'est pas la.
Quand l'etat attend un kill switch que le daemon ne declare pas arme, la ligne
du kill switch le dit en toutes lettres (`NON ARME alors que l'etat est ... -
le trafic peut fuir`). Les boutons de la fenetre suivent l'etat: `Connecter`
depuis `deconnecte` ou `echec`, `Deconnecter` des qu'un tunnel est attendu;
apres une erreur, aucun des deux. Les entrees `Connecter` et `Deconnecter`
du menu du tray suivent la meme regle, tirees des memes champs de la vue.
L'info-bulle du tray et l'entree `Etat` de son menu portent le texte de
l'etat (`Bifrost - <etat>`, `Etat: <etat>`). Un
etat que la page ne connaitrait pas s'affiche comme tel (`Etat inconnu de
cette page`), jamais comme un autre.

## Ce qui garde ces regles

- `crates/bifrost-coquille`: la vue (aucune erreur lue comme connectee ni
  rendue verte), la garde d'elevation dans les deux sens, l'exigence du
  canal, contre un faux serveur d'un compte ordinaire et contre un canal
  occupe, le refus d'ouverture rendu `compte non admis par le canal` (sous
  Windows un pipe a DACL vide, sous Linux un socket en mode 0), et le
  constat que le poste de commande ne nomme que l'etat, `connect-stored` et
  `disconnect`, que la decision du daemon admet au niveau des membres.
- `crates/bifrost-ipc`: la decision, commande par commande et niveau par
  niveau (le niveau des membres n'admet que les trois commandes, et le
  refus nomme la commande), et une garde qui lit la decision et rougit sur
  tout bras qui ne nomme pas sa commande; la raison de l'admission sous
  Linux (uid ou groupe) et le niveau qu'elle vaut; sous Linux, par le
  chemin du daemon, chaque commande rendue au serveur pour un appelant
  admis par son uid, et, pour un appelant admis par le seul groupe (gid
  primaire, puis groupe supplementaire), les trois commandes rendues et
  chacune des sept autres refusee sans atteindre le serveur.
- `crates/bifrost-ipc`, sous Windows: la forme des groupes admissibles
  (comptes et groupes predefinis, zeros de tete, RID sous 1000, domaine
  etranger refuses), le descripteur sans groupe et avec groupe (une ACE de
  plus, relue sur le pipe lie), le masque `0x120083` sans le bit 0x4 et
  distinct de GA, la recette miroir: un pipe dont l'ACE du groupe nomme le
  compte courant, ou ce compte s'ouvre en client par ses droits
  individuels et echange, et ne peut pas ajouter d'instance
  (`ERROR_ACCESS_DENIED`). Les recettes qui nomment ainsi le compte
  courant la ou le daemon nommerait le groupe (les miroirs) sont des
  mesures de poste: elles supposent un compte cree par un administrateur,
  et pour deux d'entre elles un jeton sans Administrateurs actifs. Quand
  la premisse manque, elles s'abstiennent en le nommant; sur le runner de
  la CI, dont le compte est un compte predefini, elles rendent `SKIPPED`
  sous une seule raison, attendue par le budget d'abstention Windows, et
  c'est la recette du runner, ci-dessous, qui mesure a leur place sur un
  groupe reel. Et, par le chemin du daemon (`accept`, puis la lecture des
  requetes), chaque commande rendue au serveur ou refusee selon le niveau
  de l'appelant (un compte sans Administrateurs actifs a le niveau des
  membres), un client anonyme rendu a ce niveau meme sous un jeton eleve,
  et le fil rendu a son jeton sur chaque chemin de l'identification.
- `crates/bifrost-daemon`: `--group` juge avant le superviseur (un groupe
  refuse arrete le daemon, et le message le nomme), et porte par la ligne
  du service sous la forme `--group "<SID>"`; la lecture des trois scripts
  Windows: l'installeur cree le groupe et le passe, les deux bancs relisent
  la ligne.
- `crates/bifrost-coquille/tests/groupe_d_acces.rs`, sur le runner jetable
  de la CI seulement (`BIFROST_RUNNER_JETABLE=1`, `GITHUB_ACTIONS=true`,
  processus eleve; ailleurs `SKIPPED` qui le dit): un groupe local et deux
  comptes jetables, l'un membre, l'autre non, face a un vrai `IpcServer`
  lie avec ce groupe et dont le pipe appartient aux Administrateurs. Le
  membre, non eleve, fait servir l'etat, `connect-stored` et `disconnect`
  par la coquille, ne peut pas ajouter d'instance, et recoit pour chacune
  des sept autres commandes le refus qui la nomme sans que le serveur en
  recoive aucune; le non-membre est refuse a l'ouverture et rendu `compte
  non admis par le canal`; le processus de la recette, aux Administrateurs
  actifs, fait parvenir au serveur les sept memes commandes. Elle mesure
  aussi, sur ce groupe reel, ce que les miroirs mesurent ailleurs: le
  groupe resolu porte la forme d'un compte cree et le domaine des comptes
  que la recette cree; une forme equivalente de son SID (zeros de tete,
  minuscules) est resolue et rendue sous la forme canonique; le meme
  domaine avec le RID de l'administrateur integre est refuse, non
  admissible, sous sa forme canonique; la DACL du pipe que le serveur lie
  avec ce groupe porte trois ACE d'autorisation, SYSTEM et les
  Administrateurs a tous les droits, le groupe a `0x120083`, rien d'autre.
  Groupe et comptes sont retires en fin de recette, meme sur panique.
- `crates/bifrost-coquille/tests/gui_conf.rs`: l'identifiant Tauri
  (`io.github.musyg.bifrost-vpn`), la CSP exacte, les capacites exactes
  (`core:default` et `core:event:default`, fenetre `main`), le bundling
  desactive, aucune image ni aucun binaire dans `gui/`, une note de la page
  pour chaque etat de la vue, non vide pour chaque erreur et sans le mot
  connecte, et le menu du tray qui suit les boutons de la page (ses deux
  entrees tirees d'une seule fonction de la vue, appliquees a chaque vue).
- les recettes de `gui/` (`cargo test --manifest-path gui/Cargo.toml`):
  chaque erreur et chaque etat peints tels que la vue les derive, aucune
  erreur en vert, au tray comme dans l'info-bulle, et chaque info-bulle
  d'erreur dans les 128 unites UTF-16 du tray Windows; et, etat par etat, les
  entrees `Connecter` et `Deconnecter` du tray actives la seulement ou le
  bouton l'est.
- la CI: le job `interface-linux` formate, compile, passe clippy et lance ces
  recettes a chaque push et a chaque PR; `interface-windows` fait de meme sur
  un lancement manuel avec la case `windows`. Une PR qui touche `gui/`,
  `crates/bifrost-coquille`, `crates/bifrost-icone`, `crates/bifrost-ipc` ou
  `packaging/msi` attend un run manuel `windows` vert sur sa revision avant sa
  fusion. Le job `dependances` lance `cargo audit`, `cargo deny check` et
  `cargo vet` depuis `gui/`, y compris sur le run planifie quotidien.

## Ce qui n'est pas fait

- Aucun paquet pour la coquille: ni MSI, ni .deb, ni .rpm. Ceux du daemon et
  de la CLI (README, section Paquets) n'en contiennent rien. `bundle.active`
  vaut `false` dans `gui/tauri.conf.json`; la coquille se construit depuis
  les sources (`cargo build --manifest-path gui/Cargo.toml`), et ses icones
  sont engendrees a la construction, sous `gui/target/`.
- Sous Windows, le bout en bout du groupe d'acces (un membre commande le
  daemon par la coquille et recoit un refus nomme pour toute autre
  commande, un non-membre est refuse, un processus eleve garde tout le
  canal) n'est mesure que sur le runner jetable de la CI, au run manuel
  `windows`, face a un `IpcServer` de recette et non au service installe.
  Aucun lancement reel de la fenetre par un membre du groupe n'est mesure,
  ni l'identification d'un appelant par le daemon installe en service.
- Sous Linux, la regle des trois commandes est mesuree par les recettes de
  `bifrost-ipc` (un vrai `IpcServer`; le groupe de la politique est le gid
  effectif de la recette, ou l'un de ses groupes supplementaires), pas par
  le daemon installe sous systemd ni par un compte cree membre du groupe
  `bifrost`.
- Les trois scripts Windows qui creent le groupe et le passent au service
  (`packaging/install-windows.ps1`, `scripts/service-windows.ps1`,
  `scripts/packaging-windows.ps1`) sont gardes par la lecture de leur
  texte; leur execution n'est pas mesuree.
- Sous Linux, aucun lancement reel de la fenetre n'est mesure: la coquille y
  est construite et ses recettes y tournent, dans le job `interface-linux`.
- Le refus de demarrer elevee est garde par recette dans les deux sens; il
  n'a pas ete observe sur un lancement reel eleve.
