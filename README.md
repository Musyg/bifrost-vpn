# Bifrost

VPN auto-heberge pour Windows 11 et Linux. Trois objectifs, dans cet ordre de priorite :

1. **Ne pas fuir.** Kill switch de niveau noyau, fail-closed, sans fenetre de fuite au boot, au reveil, ni pendant la reconnexion.
2. **Ne pas etre bloque.** Resistance active au DPI et a la censure, du FAI europeen au reseau d'entreprise jusqu'aux censures etatiques.
3. **Ne pas laisser l'OS parler.** Blocage de la telemetrie du systeme d'exploitation avant qu'elle n'entre dans le tunnel.

Le produit s'appelle Bifrost. Les documents de conception ont porte le nom de travail "Hyper VPN" jusqu'au 21 aout 2026; il ne subsiste que dans l'historique git, ou une recherche sur ce nom retrouve les versions d'origine.

## Statut : MVP de l'objectif 1

Le premier objectif est implemente. Daemon et CLI uniquement, pas d'interface graphique. L'objectif 2 avance : couche de decision, sondes reseau, lancement des coeurs tiers, un tunnel VLESS+REALITY qui porte du trafic reel, et le chemin qui fait entrer le trafic du systeme dans un coeur, tout cela decrit plus bas ; l'objectif 3 reste au stade de la conception.

| Composant | Linux | Windows |
|---|---|---|
| Kill switch | nftables `inet`, policy drop, fwmark. Fonctionnel et verifie | WFP user-mode (BFE). Fonctionnel, execute et mesure sur machine dediee |
| Tunnel WireGuard | Module noyau pilote en netlink. Fonctionnel | WireGuardNT. Fonctionnel, handshake et chemin de donnees verifies |
| Choix du protocole anti-DPI | `bifrost-evasion` : politique pure, sondes et coeurs tiers lances en processus separes | idem, le crate est multiplateforme |
| DNS | systemd-resolved ou `/etc/resolv.conf` | `netsh` plus filtres WFP |
| IPC authentifie | Socket Unix, `SO_PEERCRED` | Named pipe, DACL SYSTEM et Administrateurs |
| Suite de fuite | Dix vecteurs, namespaces reseau et pcap | Un seul y tourne dans `check` (`doh-bypass`); les neuf autres sont cables et renvoyes a une commande dediee, avec la raison |
| Anti-telemetrie | Couche DNS: le resolveur embarque refuse les noms de telemetrie AVANT le tunnel | idem, plus la couche 1: registre, services et taches planifiees, journalisee et reversible |

## Ce que Bifrost vise, et ce qu'il ne promettra pas

Bifrost vise la confidentialite, le controle et la resistance a la censure. Il ne promettra pas l'anonymat en configuration mono-saut, pour une raison technique documentee : une IP de sortie unique et non partagee est un identifiant stable, donc potentiellement moins protectrice qu'un pool commercial partage. L'anonymat reel n'est revendique que pour les modes de chainage vers Tor ou vers le mixnet Nym, et avec leurs limites explicitees.

Aucune architecture reseau ne rend anonyme un utilisateur connecte a ses comptes ou dont le navigateur n'est pas durci. Le produit le dira.

## Architecture

```
crates/
  bifrost-core/       types du domaine et machine a etats. Aucun appel systeme.
  bifrost-evasion/    choix du protocole anti-DPI. Aucun appel systeme.
  bifrost-firewall/   kill switch : nftables (Linux), WFP (Windows)
  bifrost-dns/        resolveur systeme pendant la duree du tunnel
  bifrost-ipc/        schema et transport IPC authentifie
  bifrost-daemon/     daemon privilegie, tunnel, suite de fuite
  bifrost-cli/        client non privilegie
```

Deux principes de conception structurent tout le reste.

**La politique de blocage est une donnee, pas du code.** Le ruleset nftables et le plan des filtres WFP sont produits par des fonctions pures qui renvoient du texte et des structures. Ce qui protege l'utilisateur est donc verifiable en test unitaire, sans privileges, sans interface reseau, et sur une plateforme qui n'est pas la cible. Le plan WFP est teste sur Linux, ou personne ne peut l'executer mais ou tout le monde peut le lire.

**La machine a etats ne fait rien elle-meme.** Elle transforme un couple `(etat, evenement)` en une liste d'actions que le daemon execute. L'invariant du produit se teste alors directement : pour chaque etat non deconnecte et chaque evenement possible, aucune action ne desarme le kill switch et aucun etat atteint ne se passe de lui. Seul un `disconnect` explicite le leve, et il est alors la derniere action executee, apres le demontage du tunnel.

## Construire

```bash
cargo build --workspace --locked
```

Rust 1.93 ou superieur (`rust-version`), edition 2024. La chaine de construction
est epinglee a 1.98.0 par `rust-toolchain.toml`, que rustup applique de lui-meme:
changer de version est un changement a part entiere, verifie sur chaque hote. Sous Linux, le module noyau `wireguard` et le binaire `nft` sont requis a l'execution.

## Utiliser

Ecrire un profil, par exemple `/etc/bifrost/tunnel.toml`, a partir de [`examples/tunnel.toml`](examples/tunnel.toml). Il contient une cle privee : `chmod 600`.

Generer une paire de cles (Linux : la generation s'appuie sur le device WireGuard du noyau) :

```bash
bifrost-daemon --genkey
```

Demarrer le daemon (root), puis piloter avec le client :

```bash
bifrost-cli connect
bifrost-cli status
bifrost-cli check
bifrost-cli disconnect
```

`connect` sans argument demande au **daemon** d'ouvrir son propre profil, celui de sa ligne de commande (`--profil`, par defaut `/etc/bifrost/tunnel.toml`). C'est le defaut, et la difference n'est pas cosmetique : un profil scelle ne se dechiffre qu'en root, donc un membre du groupe `bifrost` gagne ainsi le droit de se connecter sans gagner celui de lire la cle. `--config` reste possible, et envoie alors un profil que le client a lu lui-meme.

`--json` sur n'importe quelle commande donne une sortie exploitable par un script.

Si le daemon meurt alors que le kill switch est arme, le trafic reste bloque : c'est voulu. Pour rouvrir :

```bash
bifrost-daemon --cleanup-firewall
```

### Avertissement

Armer le kill switch coupe tout trafic sortant qui ne passe pas par le tunnel, y compris les connexions deja etablies. Sur une machine distante, cela inclut la session SSH depuis laquelle vous travaillez. Il n'y a pas d'exception pour les connexions etablies, parce qu'une telle exception laisserait fuir exactement le trafic que le kill switch existe pour arreter.

C'est pourquoi la recette de bout en bout tourne dans des namespaces reseau.

## Installer sur un systeme systemd

```bash
sudo ./packaging/install-linux.sh
sudo RESOLVEUR=/chemin/vers/dnscrypt-proxy ./packaging/install-linux.sh   # avec le resolveur chiffre
```

Le script cree les comptes, installe les binaires et l'unite, puis **s'arrete la**. Il n'active ni ne demarre le service : armer un kill switch coupe tout trafic hors tunnel, session SSH comprise, donc le demarrage reste une decision explicite prise par quelqu'un qui sait ou il se trouve.

Deux comptes sont crees, et ce sont surtout deux roles qui ne doivent pas se rencontrer. Le groupe `bifrost` donne le droit de piloter le daemon, donc de connecter et de deconnecter ; c'est l'administrateur qui y ajoute des humains. Le compte `bifrost-coeur` fait tourner les coeurs anti-censure : c'est du code tiers qui analyse du trafic reseau hostile pendant que le daemon tourne en root, et c'est lui que le kill switch exempte. Il n'a ni shell ni repertoire personnel, parce que l'exemption lui ouvre une sortie en clair dont heriterait quiconque pourrait se placer sous cette identite. Il n'appartient deliberement pas au groupe `bifrost` : l'y mettre donnerait au coeur le droit de couper le VPN qu'il est cense porter, et un debordement dans un parseur tiers deviendrait une deconnexion a distance.

Le compte `bifrost-resolveur` fait tourner le resolveur chiffre, et son role est l'exact oppose : il n'est exempte de rien, son UID sert au contraire a fermer le `:53` a tout le monde SAUF a lui. Les confondre donnerait au resolveur DNS une sortie en clair, c'est-a-dire exactement la fuite qu'il existe pour boucher ; l'installateur refuse de continuer s'ils partagent un UID.

La declaration est dans [`packaging/sysusers.d/bifrost.conf`](packaging/sysusers.d/bifrost.conf), au format `sysusers.d(5)` : declaratif, idempotent, et rejoue au demarrage si les comptes venaient a disparaitre. L'installateur retombe sur `useradd` quand `systemd-sysusers` est absent, en reproduisant les memes proprietes.

`dnscrypt-proxy` n'est pas dans ce depot : c'est un binaire tiers, recupere et verifie separement. Le designer par `RESOLVEUR=` l'installe en `/usr/lib/bifrost/dnscrypt-proxy`, `root:root` en 0755 - jamais accessible en ecriture au compte qui l'execute, sans quoi n'importe quel defaut de dnscrypt-proxy deviendrait une persistance sur la machine. L'unite le designe par ce chemin en dur. Sans lui, tout le reste s'installe et seul un profil demandant `embarque` echoue, avec un message qui dit quoi faire.

### Desinstaller

```bash
sudo systemctl disable --now bifrost-daemon
sudo bifrost-daemon --cleanup-firewall
sudo rm -f /etc/systemd/system/bifrost-daemon.service /usr/lib/sysusers.d/bifrost.conf
sudo rm -f /usr/bin/bifrost-daemon /usr/bin/bifrost-cli
sudo rm -rf /usr/lib/bifrost
sudo systemctl daemon-reload
```

`--cleanup-firewall` avant tout le reste : un daemon arrete ne desarme pas le kill switch, c'est voulu, et retirer le binaire avant d'avoir retire les filtres laisserait une machine bloquee sans l'outil pour la debloquer.

Les comptes ne sont volontairement pas supprimes. Des fichiers peuvent leur appartenir, et un UID libere est reattribue au compte systeme suivant, qui heriterait alors de tout ce qui portait l'ancien numero. Les retirer explicitement si l'on sait qu'il n'en reste rien :

```bash
sudo userdel bifrost-coeur && sudo userdel bifrost-resolveur && sudo groupdel bifrost
```

## Installer sur Windows

```powershell
.\packaging\install-windows.ps1
.\packaging\install-windows.ps1 -Pilote C:\telechargements\wireguard.dll -Resolveur C:\telechargements\dnscrypt-proxy.exe
```

Meme parti pris que sous Linux, et la meme phrase : le script depose les binaires, durcit le repertoire de donnees, enregistre le service, puis **s'arrete la**. Il ne demarre rien.

Une divergence avec systemd, qu'il vaut mieux lire que decouvrir : le service Windows est enregistre en demarrage **automatique**, donc il partira de lui-meme au prochain redemarrage. Sous Linux, `install-linux.sh` n'active pas l'unite. Le reglage vit dans la specification du service Windows, pas dans l'installateur.

Les binaires vont dans `%ProgramFiles%\Bifrost`, dont les droits par defaut interdisent deja l'ecriture aux comptes ordinaires. Ce qui s'ecrit va dans `%ProgramData%\Bifrost`, et celui-la doit etre **durci a l'installation** : `C:\ProgramData` porte une ACE `CREATOR OWNER` heritee, donc un repertoire cree la par un compte ordinaire lui appartient, et le proprietaire d'un objet detient implicitement `WRITE_DAC` quoi que dise la liste. Il pourrait attendre qu'un administrateur y installe un profil, puis le remplacer par le sien - et le profil designe le serveur vers lequel le tunnel monte. C'est la mecanique de CVE-2026-35603. L'installateur reprend la propriete, coupe l'heritage et ne laisse que SYSTEM et les administrateurs, par leurs **SID** et jamais par leurs noms, qui sont traduits d'une machine a l'autre.

`dnscrypt-proxy.exe` n'est pas dans ce depot, pas plus que sous Linux. Le designer par `-Resolveur` le depose a cote du daemon **et le fait nommer par la ligne de commande du service** : sans cela le service ne peut pas en lancer un, meme avec le binaire pose a cote de lui. C'est aussi pourquoi l'installateur retire et recree le service au lieu de le laisser en place - sa ligne change avec le resolveur.

`wireguard.dll` non plus, et c'est le tiers sans lequel **aucun tunnel ne monte du tout**. Il n'a pas d'equivalent Linux, ou WireGuard est un module du noyau et ou l'installateur n'a rien a deposer. Le mode d'echec est particulierement discret : le daemon resout la DLL par le repertoire du binaire **qui tourne** (`current_exe().parent()`), donc une copie posee dans un repertoire d'essai ou a cote d'une construction de developpement est invisible pour un service qui s'execute depuis `%ProgramFiles%\Bifrost`. Le service demarre, repond a tout, et echoue au premier `connect`. Sans `-Pilote`, l'installateur le dit en toutes lettres a la fin plutot que de laisser la decouverte au premier usage.

Le resolveur chiffre tourne sous `NT AUTHORITY\LocalService` (SID `S-1-5-19`), un compte integre, non administrateur, qui ne peut pas reecrire son propre binaire - mesure sur essai-windows le 06/09/2026. Depuis le 06/09/2026 (`11b-1`) le daemon ouvre un jeton pour ce compte par `LogonUser` et lance le resolveur par `CreateProcessAsUser`, enfant du job anti-orphelin, jamais detache de lui ; depuis le 13/09/2026 (`11b-2`) l'installateur inscrit ce compte dans la ligne du service et pose ce qu'il peut poser. Contrairement a `bifrost-resolveur` sous Linux, ce compte n'est pas propre a Bifrost : d'autres services de Windows le partagent. L'installateur lui accorde la lecture heritable de `%ProgramData%\Bifrost\resolveur`, son repertoire - la configuration et la liste anti-telemetrie y sont ecrites par le daemon a la connexion et en heritent, sans qu'il puisse les modifier - et l'ecriture heritable de `%ProgramData%\Bifrost\resolveur\etat`, son seul etat ; le daemon repose ces deux droits a chaque lancement. Il faut ouvrir le repertoire et non les seuls fichiers : dnscrypt-proxy en fait son repertoire courant au chargement, mesure sur essai-windows le 13/09/2026 (sans ce droit il sort en 255 sur `chdir`). Le daemon refuse de lancer le resolveur si ce repertoire est celui du profil (`--profil`, ou tout repertoire qui contient un `tunnel.toml`) : il serait ouvert en lecture au compte, cle privee comprise, et le refus arrive avant toute ACE. Rien n'est ouvert sur `%ProgramData%\Bifrost` lui-meme : le profil reste a SYSTEM et aux administrateurs, par leurs SID. L'exemption WFP du `:53` nomme ce SID et le chemin du binaire.

### Desinstaller sous Windows

```powershell
Stop-Service BifrostDaemon
& "$env:ProgramFiles\Bifrost\bifrost-daemon.exe" --cleanup-firewall
& "$env:ProgramFiles\Bifrost\bifrost-daemon.exe" --uninstall-service
Remove-Item -Recurse -Force "$env:ProgramFiles\Bifrost"
```

`--cleanup-firewall` avant de retirer quoi que ce soit, pour la meme raison que sous Linux : arreter le service ne desarme pas le kill switch, et supprimer le binaire avant les filtres laisserait une machine bloquee sans l'outil pour la debloquer.

## Tester

```bash
cargo test --workspace                 # tests unitaires et d'integration
sudo ./scripts/e2e-linux.sh            # recette de bout en bout, en namespaces
sudo ./scripts/check-strict.sh         # exige que les dix vecteurs soient PASSED
sudo ./scripts/packaging-linux.sh      # empaquetage, dans une racine jetable
./scripts/resolveur-linux.sh           # configuration du resolveur chiffre et liste anti-telemetrie
sudo ./scripts/resolveur-systemd-linux.sh   # le resolveur sous l'unite reelle
sudo ./scripts/service-systemd-linux.sh     # connect complet par le service installe
sudo ./scripts/mort-daemon-systemd-linux.sh # le daemon tue: le kill switch tient-il, sous l'unite reelle
```

Cote Windows, `.\scripts\packaging-windows.ps1` (en administrateur) eprouve l'installateur en detournant `%ProgramFiles%` et `%ProgramData%` vers un bac a sable : ce qui est mesure est exactement ce qui se produirait a l'installation, sans rien laisser sur la machine. Le service, lui, ne se detourne pas - le gestionnaire de services est unique - donc la recette l'installe pour de bon, relit dans le **registre** ce que le SCM a enregistre, puis le retire ; elle refuse de tourner si un service `BifrostDaemon` existe deja, pour ne jamais defaire une installation reelle. Elle verifie que les quatre fichiers sont deposes - les deux binaires du produit, le resolveur chiffre et `wireguard.dll` -, que le repertoire de donnees a l'heritage coupe et ne laisse de droits qu'a SYSTEM et aux administrateurs - jamais a `S-1-5-19` -, que son sous-repertoire `resolveur` existe et est ouvert en lecture heritable a `S-1-5-19` sans aucun bit d'ecriture (un `Modify` la serait un echec : la configuration deviendrait reinscriptible par le resolveur), que `resolveur\etat` est ouvert en ecriture heritable, et que rejouer l'installation ne fait grossir ni l'un ni l'autre compte d'ACE, que le service depend de `BFE`, qu'il n'est pas demarre, et que sa ligne **nomme le resolveur avec son chemin cite et le compte `LocalService`, cite lui aussi, apres le binaire**. Sans droits administrateur elle rend `SKIPPED` avec sa raison, apres avoir tout de meme fait analyser l'installateur.

Ce qu'elle n'etablit pas : que le service **sert**. Elle ne le demarre pas, et c'est delibere - le demarrer armerait le kill switch sur la machine de recette. C'est le role de `.\scripts\service-windows.ps1`, pendant de `service-systemd-linux.sh` : il installe pour de bon, demarre le service, `connect`, et mesure ce que la machine fait entre `connect` et `disconnect` - le tunnel transporte (une banniere du pair, verifiee muette avant le montage, et non des compteurs qu'un endpoint mort ferait monter), le vrai dnscrypt-proxy tourne comme ENFANT du service depuis le binaire que sa ligne nomme et sous `S-1-5-19` (decide sur le SID du proprietaire, jamais sur son nom traduit), l'interface du tunnel pointe le resolveur local, un vrai nom y resout, `permit-resolveur-dns` et `block-dns` sont poses pendant qu'une requete en clair vers un resolveur public n'aboutit pas, le DNS de la machine n'a pas bouge, puis le resolveur s'arrete avec le tunnel et le service tient sans redemarrer.

Il lui faut un pair en face : `scripts/service-windows-pair.sh`, a lancer sur une machine Linux du meme lien, monte un serveur WireGuard avec un **vrai acces a Internet** - sans lui, dnscrypt-proxy ne demarre pas et il n'y aurait plus rien a mesurer du resolveur. Il ne touche a la machine que par une table nft a lui et trois regles, toutes retirees par `--menage`.

Ce banc **coupe le reseau de la machine** : profil a route par defaut, `allow_lan = false`. Il se lance en tache planifiee SYSTEM detachee, arme d'abord un `--cleanup-firewall` differe dont il **relit la prochaine execution** avant de s'y fier, et on lit son journal apres coup.

`packaging-linux.sh` n'ecrit rien sur la machine qui l'execute : il applique le fichier de comptes dans une racine jetable avec `--root` et lit ce qui y est produit. Il verifie qu'aucun compte de service ne peut ouvrir de session ni piloter le daemon, que le coeur et le resolveur ont des identifiants DISTINCTS, que rejouer l'installation ne change rien, que l'unite et le fichier de comptes nomment bien le meme compte, et que les deux voies de creation donnent le meme resultat. Deux mutations le font echouer comme prevu : ajouter un compte de service au groupe de pilotage, et faire diverger le nom du compte entre l'unite et la declaration.

`resolveur-linux.sh` confronte la configuration engendree au VRAI dnscrypt-proxy. Sans le binaire, la generation et la relecture des proprietes tournent quand meme et seule la confrontation se declare `SKIPPED` ; avec, elle passe par `dnscrypt-proxy -check`. Lui designer le binaire, jamais le chercher dans le `PATH` :

```bash
./scripts/resolveur-linux.sh /chemin/vers/dnscrypt-proxy
```

Les deux couches ne font pas double emploi, et c'est mesure sur la version 2.1.18 : `-check` refuse une cle inconnue et un type invalide, tous deux en `FATAL`, mais accepte sans un mot une ecoute sur `0.0.0.0:53`, donc un resolveur ouvert a tout le reseau local, et une configuration privee d'`ignore_system_dns`, qui le fait silencieusement retomber sur le resolveur du systeme. Le binaire juge la syntaxe de sa configuration ; les proprietes de securite, personne ne les juge a notre place.

Une configuration acceptee ne dit rien du processus qui en sort. `--resolveur-selftest` lance le vrai binaire et mesure sur `/proc`, pas sur le fichier - et, depuis le 22 aout 2026, INTERROGE le resolveur vivant pour verifier que la liste anti-telemetrie mord :

```bash
sudo ./target/debug/bifrost-daemon --resolveur-selftest \
  --resolveur-binaire /chemin/vers/dnscrypt-proxy \
  --resolveur-utilisateur bifrost-resolveur
```

Il repond a une requete, il tourne sous le compte annonce, il ne garde que `CAP_NET_BIND_SERVICE` et aucun groupe supplementaire, il accepte de s'arreter, il disparait, plus rien n'ecoute apres lui, et il ne survit pas a un daemon tue par `SIGKILL`. Il ecoute sur `127.0.0.9:53` et non `127.0.0.1:53`, pour ne pas prendre le `:53` a `systemd-resolved` pendant son execution. Sans le binaire, ou sans les droits de se lier au `:53`, il rend `3` : `SKIPPED`, jamais `PASSED` par defaut.

Ce dernier temoin a trouve un conflit entre deux proprietes de securite. Le noyau efface `pdeath_signal` des qu'un processus change d'identifiants, donc laisser dnscrypt-proxy baisser ses privileges lui-meme par `user_name` desarmait la garde anti-orphelin, sans un mot : le resolveur survivait alors au daemon et gardait son ecoute sur le `:53`. Le daemon prend desormais les identifiants lui-meme avant l'`exec`, ne transmet que `CAP_NET_BIND_SERVICE` en capacite ambiante, et arme la garde apres.

**Et `sudo` ne suffit pas a l'eprouver.** Root y garde toutes ses capacites et tous les repertoires sont accessibles : une recette qui n'y tourne que sous `sudo` mesure un environnement que le produit ne connaitra jamais. `resolveur-systemd-linux.sh` relit le durcissement dans l'unite INSTALLEE - il ne le recopie pas, sans quoi il verifierait sa propre copie - et rejoue l'autotest sous un service transitoire qui porte exactement les memes directives. Trois defauts qu'il a trouves, tous verts sous `sudo` :

- le daemon donnait le repertoire de travail au resolveur AVANT d'y ecrire sa configuration, ce que l'absence de `CAP_DAC_OVERRIDE` lui interdisait ensuite ;
- le `CapabilityBoundingSet` de l'unite ne contenait ni `CAP_SETUID` ni `CAP_NET_BIND_SERVICE`, donc la bascule etait impossible ;
- et surtout il ne contenait pas `CAP_KILL`. Root n'a pas le droit de signaler un processus d'un autre UID sans cette capacite : le daemon pouvait lancer le resolveur et jamais l'arreter. Il restait bloque a l'arret, en silence, pendant que le resolveur gardait le `:53`.

Retirer l'une de ces trois capacites de l'unite fait virer la recette au rouge, chacune a l'endroit qui lui correspond.

### Le cycle complet, par le service installe

Un autotest reste un autotest. `service-systemd-linux.sh` ne fabrique plus rien : il demarre l'unite INSTALLEE, la pilote par le CLI d'un `connect` a un `disconnect`, et mesure ce que la machine fait pendant ce temps. Le resolveur chiffre n'y est plus lance pour lui-meme, il l'est parce qu'un profil le demande.

**Il tourne confine, et ce n'est pas un detail a taire.** Armer le kill switch coupe tout trafic hors tunnel, session SSH comprise, sans exception possible - c'est le propos de la chose. La recette monte donc deux namespaces reseau, un serveur WireGuard dans l'un, le service dans l'autre par `NetworkNamespacePath=`, et isole son `/etc` par un overlay. Ce qui est mesure est le vrai binaire, la vraie unite, le vrai durcissement ; ce qui ne l'est pas, c'est le comportement sur les interfaces physiques de la machine hote.

Ce qu'elle a trouve, et qui ne se voyait ni en test unitaire ni a l'autotest :

- **le budget de demarrage etait trop court.** Vingt secondes suffisent a un resolveur dont la liste de serveurs est en cache, pas a un demarrage a froid qui doit d'abord la telecharger et en verifier la signature. Mesure : quarante-cinq ;
- **le cache atterrissait sous `/run`,** donc etait efface a chaque arret du service. Chaque demarrage retelechargeait la liste depuis un hote unique, qui a fini par repondre `429 Too Many Requests`, puis par ne plus repondre du tout. La reprise sur erreur aggravait le mal : elle relancait aussitot, donc redemandait aussitot. Trois corrections, pas une - un repertoire d'etat persistant, les trois miroirs que la configuration de reference amont enumere au lieu du seul premier, et un echec de demarrage du resolveur classe NON rejouable, pour que la boucle de reprise cesse de nourrir le probleme ;
- **la restriction du `:53` tenait a une seule condition, il en fallait deux.** Fermer le `:53` a tout le monde sauf a un compte n'a de sens que si un resolveur ecoute derriere. Avec la seule declaration du compte dans l'unite, installer Bifrost aurait casse la resolution de noms des le premier profil ordinaire. La restriction demande desormais AUSSI que le profil demande `embarque` : l'exploitation declare le compte, le profil declare l'usage, et il faut les deux.

Deux mutations la mettent a l'epreuve. Basculer le profil sur `embarque = false` fait tomber sept controles, dont celui qui compte : une requete part alors en clair vers l'amont, et le renifleur place a la sortie du tunnel la capture. Retirer `--resolveur-utilisateur` de l'unite en fait tomber trois - le resolveur tourne encore, et chiffre encore, mais sous root et sans que le `:53` se ferme derriere lui. La mesure vaut d'etre retenue : sans le compte declare, Bifrost resout toujours de facon chiffree, il perd seulement le verrou.

Ces mutations ont d'abord servi a corriger la recette elle-meme, ou deux temoins mentaient. « Le nom resout par le resolveur chiffre » passait par `getent`, qui suit `resolv.conf` : sans resolveur embarque il resolvait quand meme, en clair, et le temoin restait vert. Il interroge maintenant `127.0.0.1` explicitement. Et « le resolveur s'est arrete avec le tunnel » se contentait de constater qu'aucun ne tournait plus, ce qui est trivialement vrai quand aucun n'a jamais demarre ; il exige desormais d'en avoir vu un vivant.

### Recette Windows

En administrateur :

```powershell
.\bifrost-daemon.exe --wfp-selftest
```

L'autotest pose le jeu de filtres, verifie qu'ils apparaissent dans
`netsh wfp show filters`, refait un armement par-dessus (ce que la machine a
etats fait a chaque connexion), retire tout, et verifie qu'il ne reste aucun
filtre. Dans ce mode **tous les blocages du kill switch sont convertis en
autorisations** : le nombre d'objets, leurs layers, leurs poids et leurs
conditions sont identiques au plan reel, donc le chemin de creation et de
suppression est exactement le meme, mais aucun trafic de la machine n'est coupe.
Sans danger sur un poste de travail.

Il finit par la **sonde d'identite**, qui repond a une question que le cycle de
vie ne pose pas : le filtre qui autorise le daemon le designe-t-il vraiment ?
Cette autorisation repose sur deux conditions combinees en ET, le chemin du
binaire (`ALE_APP_ID`) et l'utilisateur qui l'execute (`ALE_USER_ID`). Une
erreur sur l'une des deux ne se voit nulle part a la pose : WFP accepte le
filtre, il ne matche simplement jamais, et le daemon devient incapable de
joindre son endpoint des que le kill switch est arme.

Observer un matching demande un blocage reel. La sonde en pose un, mais
restreint a `203.0.113.9`, une adresse de documentation RFC 5737 vers laquelle
rien ne circule : c'est le seul blocage pose par ce mode, et il ne peut gener
aucun trafic. Elle prend trois mesures, parce qu'aucune ne suffit seule :

1. le daemon tente une connexion vers cette adresse et ne doit pas etre refuse ;
2. une copie du meme binaire, a un autre chemin, tente la meme connexion et doit
   l'etre. C'est le temoin : sans lui, un blocage qui ne s'applique a personne
   donnerait exactement le meme resultat que le succes attendu. Seul le chemin
   change entre les deux, donc c'est bien `ALE_APP_ID` qui fait la difference ;
3. la sonde est reposee avec une identite d'utilisateur que le daemon n'a pas,
   et il doit alors etre refuse. C'est la mutation : sans elle, une condition
   `ALE_USER_ID` inoperante donnerait les memes mesures 1 et 2 qu'une condition
   correcte, et la sonde certifierait une garantie inexistante.

Ce mode eprouve le cycle de vie des objets et l'identite du daemon, pas
l'etancheite generale. Pour eprouver le blocage de tout le reste, sur une
machine dediee dont vous ne dependez pas a distance :

```powershell
.\bifrost-daemon.exe --wfp-selftest-blocking
```

**Celui-la coupe tout le reseau de la machine** pendant l'operation : le
block-all n'autorise que ce binaire. Une session RDP ou SSH tombe avec. Il n'est
pas dans la CI : l'essai a montre que le kill switch coupe aussi la liaison
entre le runner et GitHub, et que le job reste bloque jusqu'a son echeance.
Verifier un kill switch sur la machine qui doit rapporter le resultat n'a pas de
sens.

Si un autotest est interrompu au mauvais moment, le trafic reste bloque, par
conception. Pour rouvrir : `bifrost-daemon --cleanup-firewall`. Un redemarrage
suffit aussi, les filtres n'etant pas persistants.

### La suite de fuite

`bifrost-cli check` couvre dix vecteurs : fuite DNS, contournement en DoH, IP de sortie, fuite IPv6, comportement du kill switch quand le tunnel tombe brutalement, fenetre de reconnexion, comportement au demarrage avant que le daemon ne soit pret, largeur de l'exemption accordee au coeur anti-censure, borne de l'exception accordee au resolveur chiffre, et ce que devient la protection quand le daemon MEURT. Celui du resolveur chiffre est entre dans `check` le 22 aout 2026, quand son pendant sur le banc Linux a ete ecrit : sans lui, `check-strict` serait passe d'un rapport tout PASSED a une abstention permanente. Sous Windows il reste renvoye a une commande dediee, `bifrost-daemon --resolveur-exemption-selftest`, comme les huit autres vecteurs que `check` n'y execute pas.

`daemon-mort` est le dernier arrive, le 23 aout 2026, et il est ne d'un defaut que rien ne voyait : l'unite systemd portait un `ExecStopPost=` qui lancait `--cleanup-firewall`, donc chaque plantage du daemon demontait le kill switch puis laissait la machine nue pendant `RestartSec`. Il tue un processus qui vient d'armer, par SIGKILL et par PID, et compte les paquets sur le lien pendant qu'il n'est pas revenu. Deux gardes l'accompagnent, parce qu'un vecteur ne peut pas tout voir : `crates/bifrost-daemon/tests/unite_systemd.rs` refuse qu'une directive de l'unite desarme le pare-feu, et `scripts/mort-daemon-systemd-linux.sh` rejoue la mesure sur le service REEL, cycle de redemarrage systemd compris.

Le harnais monte deux namespaces reseau relies par un veth, y etablit un vrai tunnel WireGuard entre les deux, injecte les pannes, capture sur le lien qui joue la carte reseau physique, et rend son verdict sur la capture.

Deux regles gouvernent ses verdicts.

Un test qui ne peut pas s'executer renvoie `SKIPPED` avec sa raison, jamais `PASSED`. Un `SKIPPED` n'est pas un echec, mais il n'est pas non plus une preuve d'etancheite, et la sortie le dit.

Chaque vecteur mesurable est double d'un temoin negatif : on verifie d'abord que la sonde fuit reellement SANS kill switch, avant de verifier qu'elle ne fuit plus AVEC. Si le temoin est muet, le test ne prouve rien et se declare `SKIPPED`. C'est ce qui empeche un harnais de passer parce qu'il ne mesure rien.

Cette regle a paye. Le temoin du septieme vecteur s'est declare muet, et derriere se cachait un defaut du banc lui-meme : sa passerelle repondait `ICMP net unreachable` aux destinations de sonde, le client mettait cette negation en cache, et le sondage suivant vers la meme adresse echouait localement sans jamais atteindre le lien. Un silence de cette nature se lit comme une etancheite parfaite. La passerelle avale desormais ces destinations en `blackhole`, comme le ferait Internet.

En integration continue, `check-strict.sh` durcit le critere : tout ce qui n'est pas `PASSED` fait echouer le build. Il passe par `bifrost-daemon --run-checks`, qui execute la suite au premier plan sans daemon ni IPC.

Les recettes `cargo`, elles, ont le meme piege que les vecteurs : une recette qui ne peut pas s'executer imprime `SKIPPED` et rend `Ok`, donc `cargo test --workspace` la compte verte, et sans `--nocapture` son motif reste invisible. Les deux jobs de tests passent donc par `recettes-strict.sh`, qui relance la MEME suite avec `--nocapture` et affiche le compte honnete (vertes, abstentions, rouges), puis par `abstentions-budget.sh`, qui exige que chaque abstention du runner figure dans `ci/abstentions-attendues-linux.txt` ou `ci/abstentions-attendues-windows.txt`. Une abstention nouvelle, ou une raison de forme instable, fait echouer le build ; une ligne de la liste qui n'apparait plus est signalee comme un progres a retirer, sans rougir. Chaque ligne de ces deux fichiers est un aveu a faire tomber : le jour ou ils seront tous deux vides, la CI passera a `recettes-strict.sh --strict`, qui refuse toute abstention. Le budget lui-meme est garde par `crates/bifrost-evasion/tests/abstentions_budget.rs`.

`e2e-linux.sh`, en revanche, n'est pas dans la CI. Il passe, mais il lance un daemon et une capture en root dans des namespaces reseau, et quelque chose dans cet arbre de processus empeche le runner GitHub, qui tourne en utilisateur ordinaire, de clore son job : toutes les etapes reussissaient puis le job restait bloque sur `Cleaning up orphan processes` jusqu'a son echeance. Mesure faite, sans cette etape le meme job se termine en cent secondes. Ce que la recette verifie, la montee du tunnel et l'etancheite quand l'interface est detruite, est couvert par les vecteurs `exit-ip` et `kill-switch-on-drop`.

## La couche anti-telemetrie

Le document 03 decrit quatre couches contre la telemetrie du systeme : registre et politiques, services et taches planifiees, WFP par service, et DNS local. **Deux sont posees et mesurees efficaces : la DNS et la couche 1. La couche 2 est posee et retirable - « defense en profondeur, jamais la couche qui porte la promesse » -, et son effet est mesure negatif** - voir plus bas : un filtre present n'est pas un filtre qui mord. Reste la 4, le fichier hosts, que le plan deconseille lui-meme pour les domaines Microsoft.

### La couche DNS

La seule des quatre qui vaut pour les deux plateformes - les trois autres n'existent que sous Windows -, et celle que le document appelle son argument central, parce qu'elle refuse le nom AVANT que la requete n'entre dans le tunnel : ce trafic-la ne ressort pas a l'autre bout, il ne part pas du tout.

Elle ne coute aucun composant supplementaire. Le document recommandait d'embarquer `blocky` comme resolveur local ; Bifrost en embarque deja un, `dnscrypt-proxy`, et il sait refuser des noms nativement. Il recommandait aussi les listes `hagezi` : elles sont sous **GPL-3.0**, verifie le 22 aout 2026 sur le `LICENSE` du depot amont, ce qui les met du mauvais cote de la frontiere de licence que `frontiere_licence.rs` fait respecter. La liste est donc ecrite dans le depot, entree par entree et chacune avec sa raison, d'apres la page Microsoft Learn du 16 juin 2026 et `WindowsSpyBlocker` (MIT).

Deux profils, poses par `dns.anti_telemetrie` dans le profil de tunnel :

| Profil | Ce qu'il refuse | Ce qu'il epargne |
|---|---|---|
| `equilibre` | Ce qui n'a d'autre fonction que de mesurer l'utilisateur ou de lui vendre quelque chose : le pipeline `events.data`, Watson et Windows Error Reporting, la plateforme d'experimentation `iris`, les regies publicitaires | Windows Update, le Store, Defender, l'activation, l'indicateur de connectivite, les certificats |
| `strict` | En plus : ce qui porte aussi du contenu ou de la configuration - Spotlight et le fil MSN, `aria`, `settings.data`, les notifications poussees, la telemetrie d'Office | idem |

Le troisieme profil du document, « parano », n'est pas livre : il coupe Windows Update, le Store et l'activation, ce qui n'est pas un durcissement mais une machine deconnectee. `aucun` est le defaut, pour la meme raison que le resolveur embarque est desactive par defaut - un produit qui se met a refuser des noms sans qu'on le lui ait demande est un produit dont on ne sait plus ce qu'il fait. Demander un profil sans resolveur embarque est une erreur de configuration refusee a la validation, et non un reglage sans effet.

**Le piege que ce module existe pour fermer.** `dnscrypt-proxy` documente qu'un nom ecrit nu bloque toute sa zone : `example.com` est identique a `*.example.com`. Un `microsoft.com` egare couperait Update, le Store, Defender et l'activation d'un seul coup. La liste n'emploie donc que deux formes, `*.zone` et `=nom` ; une recette refuse toute autre forme, et le motif est INTERPRETE pour verifier qu'aucun ne touche un plancher de vingt-quatre noms releves sur la page Microsoft. Une comparaison de chaines aurait laisse passer `*.microsoft.com` ; le test de mutation, lui, nomme sa victime.

**Ce qu'elle mesure.** `--resolveur-selftest` interroge le resolveur vivant : `v10.events.data.microsoft.com` ne doit rendre aucune adresse pendant que `www.msftconnecttest.com` en rend dans la MEME execution. La question de controle n'est pas decorative - un resolveur casse et un resolveur qui bloque bien rendent la meme reponse vide -, et son echec rend `SKIPPED`, jamais `PASSED`.

**Ce qu'elle ne fait pas, et qu'il faut dire.** Le document 03 est net sur ce point et le produit ne promettra pas mieux : le filtrage par nom ne couvre ni les adresses codees en dur dans `diagtrack.dll`, documentees par le BSI, ni un composant qui resoudrait par son propre DoH. Il faut pour cela le blocage par service, c'est-a-dire la couche 2 ci-dessous.

### La couche 1 : registre, services, taches planifiees

Windows seulement, et posee a la source : on n'y filtre pas un flux, on eteint ce qui le produit. Vingt-huit reglages, deux profils, chacun avec sa raison, ce qu'il casse et sa source datee. `bifrost-telemetrie` porte le catalogue et le journal, purs et testes sur les deux hotes ; `bifrost_daemon::telemetrie` porte ce qui touche la machine.

```bash
bifrost-daemon --telemetrie-etat --telemetrie-profil strict        # ne fait que LIRE
bifrost-daemon --telemetrie-appliquer --telemetrie-profil strict   # journalise, pose, RELIT
bifrost-daemon --telemetrie-restaurer                              # rend la machine, efface le journal
```

**Trois regles, chacune tiree d'un defaut connu.**

Une cible absente est dite `SANS OBJET`, jamais posee. Ce n'est pas theorique : le document 03 nomme neuf taches planifiees, et deux d'entre elles n'existent pas sur Windows 11 25H2 - `Microsoft Compatibility Appraiser` y porte un suffixe ` Exp`, et `ProgramDataUpdater` a disparu. Les deux noms sont au catalogue ; sur chaque machine, celui qui n'existe pas le dit.

On relit apres avoir ecrit. Winhance, defaut 281 du 29 decembre 2025 : un interrupteur intitule « Disable » qui ecrivait 1, sur Windows 11 Enterprise 24H2. L'outil affichait le bon etat parce qu'il affichait SON etat. Le verdict `ECHEC` est reserve a ce cas : ecrit, puis relu different.

Le journal distingue « la valeur n'existait pas » de « la CLE n'existait pas ». Sur essai-windows, quatre des cles de politique visees n'existent pas d'avance : les poser les cree. Un retour en arriere qui se contenterait de supprimer la valeur laisserait des cles de politique vides derriere lui.

**Ce que le moteur refuse de faire.** Poser un reglage de ruche utilisateur quand il tourne sous SYSTEM. Le daemon tourne en service, et `HKEY_CURRENT_USER` y designe la ruche de SYSTEM. Mesure du 22 aout 2026, par une tache SYSTEM : les cinq reglages HKCU sortent `REFUSE` avec leur raison, et l'un d'eux cesse meme d'etre « deja conforme » parce que la ruche lue n'est plus la meme. Sans ce refus, le moteur aurait ecrit cinq valeurs qui ne protegent personne et annonce cinq protections.

**Ce qui est mesure.** `scripts/telemetrie-windows.ps1` releve les 44 cibles lui-meme - pas par le binaire qu'il eprouve, qui confirmerait sa propre erreur -, fait poser, fait defaire, et exige que les deux releves soient identiques cible par cible. Mesure du 22 aout 2026 sur essai-windows, build 10.0.26200.9168 : 27 reglages poses, 32 cibles bougees, aucun `ECHEC`, 44 cibles identiques apres le retour, et les 5 cles creees supprimees.

### La couche 2 : blocage WFP par SID de service - defense en profondeur, jamais la couche qui porte la promesse

Windows seulement. C'est le point que le document 03 appelle differenciant, et la raison tient en une ligne : `ALE_APP_ID` compare un CHEMIN, et toutes les instances de `svchost.exe` portent le meme. Bloquer par chemin couperait la machine entiere. Le seul discriminant est le SID de service, que WFP lit dans le jeton via `ALE_USER_ID`.

```bash
bifrost-daemon --telemetrie-reseau-etat --telemetrie-profil strict   # ne fait que LIRE
bifrost-daemon --telemetrie-reseau-appliquer --telemetrie-profil strict
bifrost-daemon --telemetrie-reseau-retirer                           # la sortie de secours
```

Les filtres vivent dans leur PROPRE provider et leur propre sublayer, persistants et distincts de ceux du kill switch : ils valent aussi quand le tunnel est baisse. Quelqu'un qui coupe son VPN ne demande pas a rallumer la telemetrie de son systeme.

**Le retrait ne depend d'aucune connaissance de ce qui a ete pose.** Il rejoue une suite de cles fixes et supprime chacune en tolerant les absentes, donc il marche apres un plantage, apres un changement de profil, ou depuis un desinstalleur. Ce n'est pas du confort : un filtre WFP survit au processus qui l'a pose, et sans cette commande, desinstaller le produit laisserait une machine filtree par un logiciel absent.

**Une cible qui ne peut pas etre bloquee est dite `SANS OBJET`, jamais posee.** Trois cas, et le troisieme est le piege de la couche : le service n'existe pas ; le binaire n'existe pas - sur Windows 11 25H2, `MusNotification.exe` et `WaaSMedicAgent.exe` ont disparu de `System32` ; ou le service est configure en `SERVICE_SID_TYPE NONE`, auquel cas son jeton ne porte aucun SID de service et le filtre se poserait sans jamais mordre.

**Ce qui est mesure.** `scripts/telemetrie-reseau-windows.ps1` pose, verifie et retire, en s'instrumentant avec `netsh wfp show filters` et non avec le binaire qu'il eprouve. Mesure du 22 aout 2026 sur essai-windows, build 26200, profil Strict : 8 cibles posables sur 10, 16 filtres poses, un filtre portant le SID de DiagTrack, **aucun portant celui de Windows Update**, et plus une seule reference au provider apres retrait.

**Ce qui est mesure ensuite, et qui est negatif : sur DiagTrack, le filtre ne mord pas.** La pose et l'effet sont deux questions, et la seconde a maintenant une reponse qui n'est pas celle qu'on esperait. `scripts/telemetrie-effet-windows.ps1` redemarre DiagTrack trois fois en alternant les filtres, audit des connexions AUTORISEES active, et lit le `FilterRTID` porte par chaque evenement. Mesure du 22 aout 2026 sur essai-windows : au passage ou les huit filtres etaient poses et verifies presents dans le moteur, **DiagTrack s'est connecte quand meme**, vers `20.42.73.27:443`, et aucun 5157 n'impute quoi que ce soit a la couche 2. Le filtre est dans le moteur, il porte le bon SID de service, et la connexion passe.

**Le mecanisme, lui, mord - et c'est mesure sur un declencheur qu'on commande.** DiagTrack n'emettant qu'une fois par redemarrage, il assechait la fenetre avant qu'on puisse lire le `FilterRTID` du 5156. `scripts/telemetrie-cause-windows.ps1` se donne donc son propre emetteur : un service de test jetable dont le binaire est le daemon en `--connect-probe`, avec un `SERVICE_SID_TYPE` unrestricted comme DiagTrack, et un blocage de la MEME forme que ceux du catalogue pose sur son SID par `--telemetrie-sonde-sid`.

| Passage | Sonde | Autorisees | Refusees | Filtre gagnant, nomme par l'evenement |
|---|---|---|---|---|
| A | absente | 1236 | 0 | `Default Outbound` |
| B | posee | **0** | **569** | **`bifrost telemetrie sonde S-1-5-80-...` (ALE_AUTH_CONNECT_V4), a nous** |

**Un blocage `ALE_USER_ID` sur un SID de service refuse donc bien le service qui porte ce SID**, et le systeme designe lui-meme notre filtre comme decideur. Deux des trois hypotheses tombent : le controle d'acces WFP reconnait un SID de service porte comme groupe du jeton, et l'arbitrage entre sous-couches nous donne la main.

**Ce qui reste ouvert est donc propre a DiagTrack, et c'est desormais reproduit.** Relance du banc apres un redemarrage d'essai-windows, dans la fenetre qui suit le demarrage : **2 connexions autorisees alors que les huit filtres etaient poses et verifies presents**, et le banc nomme le gagnant - `Default Outbound`, rtid 89644, layer 48, **qui n'est pas a nous**. Nettoyage verifie independamment du banc, par un releve `netsh` distinct.

**La lecture de ce resultat oriente toute la suite, et elle merite d'etre separee du releve.** Le releve : un permit gagne. La lecture : chez WFP un blocage l'emporte sur une autorisation, donc si une autorisation gagne, notre filtre **n'a pas matche**. Ce n'est pas l'arbitrage entre filtres, deja elimine par la sonde ; c'est le **controle d'acces** de `ALE_USER_ID`, qui compare le jeton a un descripteur de securite et non a un SID.

**Toutes les explications cote Windows ont ensuite ete mesurees, et toutes sont tombees.** Les attributs du SID de service sont identiques au bit pres entre DiagTrack et un service que le filtre bloque (`0x0000000E`, `ENABLED`, aucun `USE_FOR_DENY_ONLY`, aucun SID restreignant). Le `-p` de son `svchost` n'est pas une protection de processus (`PS_PROTECTION = 0x00`). Et un service au jeton FILTRE, fabrique pour reproduire le seul ecart qui restait, est bloque exactement comme l'autre : 673 refus, notre filtre nomme. Le layer est le meme des deux cotes, 48.

**Les deux derniers doutes portaient sur nos propres bancs, et ils sont leves.** Le filtre visant DiagTrack a bien ete pose : condition par condition, il porte exactement le SID que `sc showsid` rend, aux deux couches, avec le veto. Et la mesure finale, faite a six minutes d'un redemarrage avec un banc qui verifie desormais ce qu'il eprouve et la continuite du processus, redonne le meme resultat : **une connexion autorisee par `Default Outbound` alors que les filtres etaient poses et verifies porteurs du SID de la cible.**

**L'usurpation d'identite, derniere hypothese, tombe aussi.** 24 releves pendant la fenetre, 428 fils examines, 48 fils portant un jeton d'usurpation - et les 48 portent le SID de service de DiagTrack, `ENABLED`. Ce n'est pas un jeton qui echapperait au filtre : c'est un jeton que le filtre devrait mordre comme celui du processus. Le lecteur est falsifie, ce qui n'etait pas un luxe : un lecteur retombant en silence sur le jeton du processus aurait imprime exactement la meme chose.

**Le bilan, et il tient en deux phrases.** Le mecanisme fonctionne : un blocage `ALE_USER_ID` par SID de service refuse le service qui porte ce SID, mesure dans les deux sens sur des services de test. DiagTrack y echappe, deux fois, et **aucune explication mesurable ne survit** - une seule reserve subsiste, qu'un echantillonnage a neuf secondes ne peut pas lever : une usurpation qui ne durerait que le temps d'un appel.

**DiagTrack n'est pas un cas particulier, et c'est la mesure du 23 aout qui le dit.** Les quatre autres services du catalogue ont ete eprouves, et `DoSvc` echappe avec la signature EXACTE de DiagTrack : filtre pose, verifie porteur du SID exact, processus continu et seul dans son `svchost`, et `Default Outbound` qui gagne en autorisant 26 connexions. Refait deux fois, sur deux redemarrages differents du service. Le contraste tient dans la MEME session : cinq minutes plus tot, le meme moteur refuse 609 connexions a un service de test en nommant notre filtre.

**Ce que cette deuxieme cible elimine.** DiagTrack est `LocalSystem` dans `-k utcsvc`, DoSvc est `NetworkService` dans `-k NetworkService`, avec un type de demarrage et des destinations differents : **ni le compte, ni le groupe `svchost`, ni le type de demarrage ne sont le discriminant**. Une piste ouverte au passage se referme aussi : les 72 filtres que Windows lui-meme porte sur le SID de DoSvc sont **tous entrants**, aucun sur la couche de sortie.

**L'hypothese qui restait est morte le jour meme, et c'est `W32Time` qui la tue.** Elle disait : les deux cibles qui echappent sont hebergees dans `svchost.exe`, les trois temoins bloques portent leur propre binaire. Or `W32Time` est heberge dans `svchost.exe -k LocalService` et il **se bloque** - 9 refus sur 9, deux series independantes. L'hebergement n'est pas le discriminant. Deux confondants tombent avec : `DoSvc` echappe aussi a la sonde posee SEULE (25 autorisees / 0 refusee, trois fois), donc ce n'est pas le nombre de filtres ; et `DoSvc` est un processus protege quand `DiagTrack` ne l'est pas, donc ce n'est pas la protection.

**Et le fond de l'affaire est ailleurs : ce n'est pas notre filtre.** La mesure qui ferme l'enquete ne construit rien - elle demande a Windows de poser lui-meme la politique. `New-NetFirewallRule -Service DoSvc -Direction Outbound -Action Block` produit six filtres portant le SID exact du service, aux deux couches, sur les trois profils, et **echoue identiquement** : 25 connexions autorisees, zero refusee, gagnant `Default Outbound`. Le meme script, la meme session, sur `W32Time` : **0 autorisee, 5 refusees**, gagnant nomme, et `w32tm /resync` qui echoue faute de donnees de temps - deux signaux independants.

**La cause est documentee, et elle est mesuree.** `FWPM_CONDITION_ALE_USER_ID` n'est pas une comparaison de SID : c'est un controle d'acces contre le jeton **capture a la creation de la socket**. Si le thread usurpe l'identite d'un client a cet instant, le jeton capture est celui du client, le SID de service n'y est pas, et le filtre ne matche pas. Microsoft l'ecrit de son propre mecanisme. Et le champ `userId` d'un net event WFP le confirme sur cette machine : `W32Time` rend `S-1-5-19`, son propre compte ; `DoSvc` rend un `S-1-5-21-...-1001`, un compte **utilisateur**, alors que le service tourne sous `NetworkService`. Attribution au bon processus etablie par jointure avec l'evenement 5157, qui porte le PID - sur dix refus imputes a la regle, quatre seulement etaient de la cible.

**Ce que le produit a donc le droit de dire.** La couche 2 pose et retire des blocages, et le mecanisme par SID de service mord sur un service qui porte son propre binaire. Mais **les quatre cibles `ALE_USER_ID` qui restent au catalogue sont toutes des services heberges dans `svchost.exe`** - `DiagTrack`, `dmwappushservice`, `DoSvc`, `CDPSvc` - deux sont mesurees echappant et deux n'ont pas pu etre eprouvees faute de temoin qui emette. **Aucune des quatre n'est annoncee comme bloquee.** Ce qui eteint la telemetrie aujourd'hui, c'est la couche 1, et le document 03 le disait avant l'enquete : << l'eteindre est plus sur que d'esperer le filtrer >>.

**Deux defauts de catalogue trouves en chemin. Le premier est CORRIGE.** `service-wersvc` visait a cote : le reseau de Windows Error Reporting n'est pas fait par le service mais par `WerFault.exe`, un processus distinct portant son propre jeton, qu'un filtre sur le SID du service ne peut pas matcher par construction - trois sorties relevees, dont deux pendant que les filtres etaient poses. L'entree est devenue `binaire-werfault`, une cible `ALE_APP_ID` sur `System32\WerFault.exe`, des que ce mecanisme a ete mesure mordant. **Le pendant 32 bits, `SysWOW64\WerFault.exe`, existe et n'est PAS vise** : aucune sortie n'en a ete relevee, et poser un filtre sans mesure serait annoncer une protection sans preuve. C'est ecrit dans le code, a cote de l'entree. Le second defaut tient : `CDPUserSvc`, nomme dans le document 03, est absent des catalogues, son nom portant un suffixe propre a l'installation qu'une derivation de SID a partir d'un nom fixe ne peut pas atteindre.

**L'autre moitie du catalogue est mesuree, et le mecanisme mord.** Les six cibles `ALE_APP_ID` - `WerFault.exe` les a rejointes - reposent sur une comparaison de chemin d'image, qui ne depend d'aucun jeton. Mesure du 23 aout avec un temoin qu'on commande : passages filtres **0 autorisee / 636 puis 639 refusees**, passage sans filtre 1225 autorisees, le 5157 nommant notre filtre. Deux signaux independants concordants.

**Mais sa couverture reelle sur 25H2 est maigre, et il faut le dire : une cible et demie.** `MusNotification.exe` et `WaaSMedicAgent.exe` ont disparu du systeme, `SIHClient.exe` n'a de declencheur dans aucune des 274 taches de la machine, `DeviceCensus.exe` est muet, et `CompatTelRunner.exe` n'emet qu'au premier passage de l'appraiser. Le mecanisme fonctionne ; ce qu'il protege ici, non.

**Ce que le produit promet, apres tout cela.** Le blocage par SID de service **n'est pas une garantie et ne peut pas en etre une** : ce n'est pas une prudence de notre part, c'est ce que la plateforme dit de son propre mecanisme, et ce qu'on a mesure avec l'outil de la plateforme. Il reste utile la ou il mord, comme defense en profondeur, jamais la couche qui porte la promesse. Ce qui eteint la telemetrie, c'est la couche 1 et la couche DNS, toutes deux mesurees efficaces.

**Deux pieges de methode ont ete payes pour arriver a cette phrase, et ils valent d'etre notes.** `CompatTelRunner.exe` etait le declencheur evident : mesure avec l'audit des succes actif, aucun 5156 ne le citait, meme sans aucun filtre - un temoin muet aurait certifie n'importe quoi. Et DiagTrack n'emet qu'une fois par redemarrage : un banc qui aurait compare « sans filtre » puis « avec filtre » dans cet ordre aurait attribue au filtre un simple epuisement de file. D'ou les passages alternes, commences par le cas filtre.

**Correction du 23 aout, et elle porte sur ce paragraphe meme.** De ce zero, on avait conclu que `CompatTelRunner.exe` << ne se connecte pas >>. C'etait faux. Ses quatre taches planifiees **n'avaient jamais tourne** - `dernier essai : 30.11.1999`, resultat `SCHED_S_TASK_HAS_NOT_RUN` - et deux d'entre elles n'ont meme aucune prochaine execution prevue. Declenchees a la main, elles rendent 0 et le binaire emet deux connexions. **Le zero mesurait le declencheur, pas le binaire.** La lecon etait juste, la conclusion ne l'etait pas : constater qu'un temoin est muet n'autorise pas a dire POURQUOI il l'est.

**`ALE_APP_ID`, le second mecanisme du catalogue, a enfin sa mesure d'effet - et il MORD.** Temoin qu'on commande, une copie jetable du daemon a un chemin a nous : passages filtres **0 autorisee / 636 puis 639 refusees, toutes imputees a nos filtres**, passage sans filtre 1225 autorisees. Le 5157 nomme notre filtre comme decideur, et les deux signaux independants concordent - le code de sortie de `--connect-probe`, qui ne depend d'aucun journal, et le journal, seul a nommer le gagnant.

**Mais la couverture reelle est maigre sur Windows 11 25H2, et il faut le dire.** Des **six** cibles `ALE_APP_ID` du catalogue : `MusNotification.exe` et `WaaSMedicAgent.exe` sont **absents** du systeme, `SIHClient.exe` est present mais **aucune des 274 taches de la machine ne le nomme**, `DeviceCensus.exe` a tourne deux fois sans emettre une seule connexion, `CompatTelRunner.exe` n'emet qu'au premier passage de l'appraiser, et `WerFault.exe`, qui vient de rejoindre ce mecanisme, n'a jamais eu de sortie reelle eprouvee sous filtre. Le mecanisme fonctionne ; ce qu'il protege ici, c'est une cible et demie. Et **aucune vraie cible n'a encore ete eprouvee sous filtre**.

**LA PHRASE QUI MANQUAIT, ET QUE LE CATALOGUE SAIT DESORMAIS DIRE SEUL.** Depuis le 23 aout, chaque entree porte son effet MESURE, avec la date et l'hote, et refuse de l'annoncer sans provenance. Le compte tombe alors d'un bloc, et il est severe : **aucune des dix cibles du catalogue n'est mesuree bloquante.** Deux sont mesurees SANS effet - `DiagTrack` et `DoSvc` - et huit ne sont pas mesurees du tout. Les chiffres eclatants de cette section - 569, 673, 636, 639, et 9 sur 9 - appartiennent tous a des temoins qu'on commande, ou a `W32Time`, qui n'est pas au catalogue. Les deux moities de cette page le disaient separement ; personne ne l'avait dit ensemble.

**Ce qu'elle ne fait pas.** Sur Home et Pro, `AllowTelemetry=0` est traite comme 1 par Microsoft : la couche 1 reduit la surface et retire le choix de l'interface, elle n'annule pas la telemetrie Required. Elle ne pose pas non plus de point de restauration systeme, que le document 03 demande, et ne detecte pas encore la derive - une mise a jour de fonctionnalite reactive DiagTrack, et rien ne la remet aujourd'hui.

## Limites connues

**Le transport Windows fonctionne, chemin de donnees compris.** Deux recettes le couvrent. `--wgnt-selftest` monte deux adaptateurs sur la machine et les fait dialoguer par la boucle locale : handshake WireGuard reel, date des deux cotes, compteurs qui bougent. `--wgnt-e2e` va plus loin et monte un vrai tunnel vers un pair distant, puis lit une banniere sur une adresse joignable uniquement par le tunnel : c'est ce qui distingue « le transport marche » de « les donnees passent ». Aucune des deux n'arme le kill switch, et toutes deux refusent un profil a route par defaut.

Le kill switch, lui, autorise bien le trafic du tunnel : il le designe par le LUID que WireGuardNT donne a la creation de l'adaptateur, transmis par le superviseur au moment d'armer. Il ne le deduit plus du nom de l'interface, resolution qui pouvait echouer ou arriver avant que Windows ait enregistre l'alias, et dont l'echec etait avale - ce qui produisait un kill switch bloquant aussi le tunnel pendant que la connexion se declarait etablie.

**La route par defaut sous Windows est posee telle quelle, sans decoupage en deux moities `/1`**, comme le fait le client WireGuard officiel. Sous Linux, Bifrost evite la boucle par le fwmark ; sous Windows il n'y en a pas, et WireGuardNT exclut lui-meme ses paquets de transport du routage du tunnel. Ce n'est pas une deduction : en routant l'adresse de l'endpoint elle-meme dans le tunnel, `GetBestRoute2` confirme que Windows choisit le tunnel pour la joindre, et le handshake aboutit quand meme. Reserve : l'epreuve porte sur le bouclage, pas sur un vrai `/0`, qui touche aussi le DNS et le MTU.

**L'etancheite du kill switch WFP est mesuree, sur une seule connexion TCP sortante.** Le mode bloquant a ete execute sur une machine dediee : 22 filtres poses, presence confirmee dans `netsh wfp show filters`, reengagement idempotent, retrait complet. L'etancheite elle-meme se lit dans une table `Connecte / Bloque / Connecte` produite par une sonde que le plan n'autorise pas, avant, pendant et apres l'armement. Ce qui n'est PAS couvert : les vecteurs de fuite du harnais Linux (DNS, IPv6, fenetre de reconnexion, chute du lien) n'ont pas d'equivalent Windows et restent `Skipped`. Ce qui est mesure est un block-all sur une connexion TCP sortante, pas chacun de ces chemins.

Quatre defauts ont ete trouves en executant ce code, tous corriges : des codes d'erreur WFP redeclares a la main et decales d'un cran ; une attente non bornee du verrou de transaction ; l'absence de suppression des filtres avant celle du sublayer, qui rendait le kill switch inamovible et a coute un redemarrage a un poste de travail ; et un `layerKey` nul suppose signifier "tous les layers", que WFP traite en realite comme un layer inexistant.

**L'identite autorisee est celle du service, et le detour merite d'etre connu.** Le filtre du daemon porte `ALE_APP_ID` et `ALE_USER_ID` combines en ET, comme celui de WireGuard for Windows, et `ALE_USER_ID` porte le SID de service (`S-1-5-80-...`), qui designe ce service et lui seul. Le piege : Windows ne met PAS le SID du service dans son token par defaut. Passer en service sans poser `SERVICE_SID_TYPE_UNRESTRICTED` degrade la garantie au lieu de l'ameliorer, puisque le token retombe sur `S-1-5-18`, partage par tous les services de la machine, la ou le mode console tombait au moins sur le SID d'un utilisateur precis. Le reglage est pose a l'installation et verrouille par un test. Que ce filtre matche effectivement le trafic du service est mesure, par une sonde qui tourne DANS le service : elle passe, une copie du meme binaire sous le meme compte est bloquee, un SID mute d'un caractere aussi.

**Le kill switch sait desormais laisser sortir un coeur anti-censure, et rien d'autre, ce qui est mesure.** Un coeur est par construction ce qui sort HORS du tunnel, puisque c'est lui le transport : ses paquets ne portent pas le `fwmark` et ne passent pas par l'interface du tunnel, donc la `policy drop` les jetait. Le document 02 le prevoyait au point 6 de son plan ; ce n'etait pas implemente.

L'exemption designe une **identite**, jamais une destination : autoriser l'IP du serveur ouvrirait un canal de sortie en clair a n'importe quel programme de la machine, travers que ce depot refuse deja pour l'endpoint WireGuard. Sous Linux c'est un UID dedie (`meta skuid`), sous Windows le binaire et l'identite combines en ET (`ALE_APP_ID` + `ALE_USER_ID`). UID plutot que `cgroup v2`, que le document proposait aussi : l'identifiant de cgroup que nftables matche est un numero qui change a chaque redemarrage du service, et son matching en namespace n'est fiable qu'a partir du noyau 6.12 - seuil qui ne gene pas le banc, essai-linux tournant en 7.0, mais bien un utilisateur sur un Ubuntu 24.04 d'origine livre en 6.8.

Le piege qui a decide de la forme des regles : les permits DNS sont poses plus haut dans la chaine, donc un `skuid` nu placerait le coeur **au-dessus** de la restriction et lui laisserait interroger n'importe quel resolveur en clair. Deux `drop` precedent donc l'`accept`, et le coeur resout par le resolveur local comme tout le monde. Meme raisonnement sous Windows par le poids, `permit-coeur` restant strictement sous le blocage DNS.

Le coeur tourne sous un compte dedie, groupe compris - ne baisser que l'UID laisserait le GID 0. Ce n'est pas qu'une affaire de pare-feu : un coeur est du code tiers qui analyse du trafic reseau hostile, et le daemon tourne en root. Consequence mesuree sur machine : `PR_SET_PDEATHSIG` est efface quand les credentials d'un processus changent, donc la garde anti-orphelin aurait pu etre posee puis effacee en silence. Elle tient - la bibliotheque standard applique l'UID avant les closures `pre_exec` - et un test le verifie plutot que de le supposer, en `SKIPPED` quand il ne tourne pas en root. Le resolveur chiffre a rencontre le meme piege par une autre porte, et il y est tombe : ce n'etait pas le daemon qui changeait les identifiants mais dnscrypt-proxy lui-meme, APRES l'`exec`, hors de portee de cet ordre-la. Connaitre un piege ne suffit pas ; seule une mesure dit s'il a ete evite.

**La largeur de l'exemption est mesuree, pas supposee.** Une regle qui laisse passer quelque chose se verifie en la lisant ; qu'elle ne laisse passer QUE cela ne se verifie que par une mesure, et c'est cette moitie-la qui distingue une exemption etroite d'un trou. Le vecteur `coeur-exemption` enchaine cinq observations sur le banc : sans kill switch le coeur sort, arme sans exemption il ne sort plus, arme avec exemption il sort a nouveau, root reste bloque au meme instant, et le `:53` du coeur tombe. Si la premiere est muette, le vecteur se declare `SKIPPED` plutot que de lire des silences qu'il ne peut pas attribuer.

**Le meme raisonnement dans l'autre sens, pour le resolveur.** Le coeur EST le transport : son permit est large et doit rester SOUS le blocage DNS, sinon il en devient le contournement. Le resolveur chiffre est l'inverse : son permit passe AU-DESSUS du blocage, faute de quoi il ne peut pas resoudre le nom de son propre serveur chiffre et ne demarre jamais - mais il ne doit sortir QUE sur le `:53`. Le vecteur `resolveur-exemption` mesure cette borne, et exige que chaque blocage soit imputable au filtre nomme : sur la mesure de reference, 211 blocages WFP dans la fenetre, dont deux seulement attribuables. Sans ce tri, n'importe lequel passerait pour une preuve.

**Deux exemptions de formes differentes, et ce n'est pas une incoherence.** Mesure sur un tunnel WireGuard noyau : le paquet chiffre est bien presente au hook `output`, mais il n'y porte ni l'uid de l'application qui a ecrit dans le tunnel, ni l'uid 0 du socket noyau - `meta skuid` lit le proprietaire d'un socket, et un paquet fabrique par le noyau n'en a pas. Le `fwmark`, lui, y est present : le noyau marque apres avoir chiffre. Un coeur tiers tourne en espace utilisateur et vise des destinations arbitraires, donc il s'exempte par identite ; WireGuard nu, que Bifrost monte lui-meme par netlink, n'a aucune identite a offrir et s'exempte par la marque. Les unifier couperait l'un des deux.

**Le daemon est branche dessus.** `--coeur-utilisateur` declare le compte : un nom en exploitation, `uid:gid` pour un banc. Le daemon le resout au demarrage et refuse de demarrer si le compte n'existe pas, plutot que de retomber en silence sur « aucune exemption » - ce qui donnerait un daemon d'apparence saine et un coeur etrangle des son lancement. Le superviseur inscrit ensuite cette identite dans chaque armement, comme il complete deja le LUID du tunnel, avec une contrainte de temps opposee : le LUID ne peut etre connu qu'apres la montee du tunnel, l'identite du coeur doit etre posee avant qu'aucun coeur ne tourne. Elle figure donc des le premier armement, celui qui precede la montee du tunnel ; sans cela il faudrait soit demarrer le coeur sans exemption, soit baisser le kill switch pour la lui donner.

La meme valeur alimente le lancement. C'etaient deux champs independants - celui que le pare-feu exempte et celui sous lequel le coeur tourne - et rien n'empechait qu'ils divergent, une divergence qui ne se voit nulle part et se manifeste par un tunnel qui ne monte pas. Il n'y a plus qu'une valeur a lire.

`e2e-linux.sh` en est le temoin de bout en bout : un vrai daemon lance avec le drapeau, un vrai `connect`, et les regles que le noyau applique verifiees sur pieces - l'exemption presente, le `:53` du coeur bloque avant elle, et trois occurrences sur la table entiere, donc rien en `input` ni en `forward`.

L'empaquetage cree ce compte depuis, en `sysusers.d(5)` et hors du groupe de pilotage. **Ce qui manque encore** : le flux de connexion ne choisit pas encore de technique, donc il ne lance aucun coeur. Ce sont `--coeur-selftest` et `--coeur-e2e` qui en lancent, et ils lisent la meme identite. Relier la selection de technique au flux de connexion appartient a l'objectif 2.

**Le resolveur chiffre embarque tourne sous le service installe, sur Linux.** La plomberie est posee - le `:53` sortant n'est autorise que vers une adresse de boucle locale, le systeme est empeche d'utiliser un resolveur pousse par DHCP, et le `:53` se ferme a tout le monde sauf au compte du resolveur, y compris a l'interieur du tunnel, des lors que l'exploitation declare ce compte ET que le profil demande `embarque`. L'empaquetage installe dnscrypt-proxy en `/usr/lib/bifrost/dnscrypt-proxy` et l'unite le designe par ce chemin, jamais par le `PATH`. Un cycle `connect` / `disconnect` complet a ete mesure a travers l'unite reelle : le resolveur demarre avec le tunnel sous son propre UID, la machine resout par lui, rien ne sort en clair a la sortie du tunnel, et il s'arrete avec lui. Cette mesure a ete prise confinee dans des namespaces reseau, pas sur les interfaces physiques de l'hote - armer le kill switch y coupe la session qui pilote la recette.

Ce qui manque : le DoH des navigateurs n'est desactive par aucune policy, et l'equivalent Windows de la restriction du `:53` par UID, qui passerait par `ALE_APP_ID`, n'est pas ecrit. Le critere du document 02, « dnsleaktest ne montre que le resolveur attendu », n'est donc pas encore atteint.

**La fenetre de fuite au demarrage de la machine n'est pas fermee, mais le motif avance ici etait faux.** Les filtres que le daemon pose sont non persistants : ils survivent a sa mort, pas au redemarrage. Cette ligne affirmait que la fermer demande un driver noyau, donc un budget de certificat EV ; `--boot-filtres` l'a mesure faux le 17 aout 2026 sur machine dediee. Un filtre `FWPM_FILTER_FLAG_BOOTTIME` pose par un simple processus utilisateur s'inscrit dans le magasin que `tcpip.sys` lit AVANT le demarrage de BFE, et un filtre `FWPM_FILTER_FLAG_PERSISTENT` survit a un vrai redemarrage et bloque encore. Ce qui reste non mesure est le rejet d'un paquet PENDANT la fenetre pre-BFE, qui demanderait un temoin d'audit horodate ; a ne pas confondre avec ce qui precede. Cote Linux, l'unite systemd fournie demarre le daemon tot, mais le kill switch n'est arme qu'a la connexion.

**Un client DHCP utilisant des sockets `AF_PACKET` contourne Netfilter**, donc le kill switch nftables. C'est une limite du mecanisme, documentee par `wg-quick(8)`. Le confinement en namespace reseau est la parade structurelle.

## Documentation

**Ou on en est se lit dans [`ETAT.md`](ETAT.md)**, qui tient sur un ecran et se met a jour a chaque tranche : l'etat des sept documents du plan, les chantiers ouverts avec leur prochaine action, et les comptes de recettes avec la commande qui les rend. Le reste est du detail.

| Document | Objet |
|---|---|
| `ETAT.md` | **Ou on en est.** Une page, mise a jour a chaque tranche |
| `docs/SOTA-2026-07.md` | Versions retenues pour le MVP et leur justification |
| `docs/01-architecture-technique.md` | Architecture generale, transport, cryptographie post-quantique |
| `docs/02-killswitch-anti-fuite.md` | Kill switch WFP et nftables au niveau code, elimination de toutes les fuites, suite de tests CI. Specification de reference du MVP |
| `docs/03-anti-telemetrie-os.md` | Cartographie des endpoints de telemetrie Windows 11 24H2 et 25H2, equivalent Linux, couches de blocage |
| `docs/04-anti-censure-dpi.md` | Resistance DPI : VLESS et REALITY, XHTTP, Hysteria2, AmneziaWG, bascule automatique, etat mesure de la censure |
| `docs/05-anonymat-chainage.md` | Modeles de menace, architectures de sortie comparees, multi-hop, Tor, Nym, defense contre la correlation de trafic |
| `docs/06-architecture-logicielle-packaging.md` | Daemon Rust et interface Tauri, IPC privilegie, MSI et paquets Linux, signature, mise a jour TUF, provisioning serveur |
| `docs/07-programme-securite-produit.md` | Modele de menace du produit, fuzzing, audit externe, divulgation coordonnee, conformite Cyber Resilience Act |

## Decisions structurantes deja actees

- **Stack** : daemon Rust privilegie, IPC authentifie. L'interface Tauri v2 non privilegiee est prevue hors MVP, en jalon propre apres J2. Les coeurs anti-censure sing-box et Xray tourneront en processus separes, jamais lies statiquement, pour eviter la contamination GPL.
- **Kill switch** : Windows Filtering Platform en mode utilisateur sur Windows, nftables avec fwmark sur Linux. Aucun driver noyau au depart.
- **Licence** : MPL-2.0 pour le client (champ `license` du workspace).
- **Conformite** : le VPN est un produit important de classe I au sens du Cyber Resilience Act. Obligations de signalement des le 11 septembre 2026, conformite complete au 11 decembre 2027.

## Objectif 2 : ce qui est fait, ce qui ne l'est pas

Le document 04 chiffre cet objectif a 90-130 jours-homme et repartit clairement le travail : sing-box, Xray, hysteria et amneziawg sont reutilises tels quels comme binaires ; ce qu'il faut ecrire soi-meme, c'est la colle, dont le superviseur pese a lui seul 20-30 jours.

Le crate `bifrost-evasion` en porte la **decision**, et rien d'autre : au vu de ce qui a ete reellement mesure de ce reseau, dans quel ordre essayer les protocoles. Il ne touche ni au reseau, ni au systeme, ni a un processus tiers, donc il se teste entierement en CI Linux, sans privileges et sans binaire externe. Deux regles le gouvernent. **Seule une mesure elimine** : une sonde qui n'a pas tourne ne retire jamais un candidat, exactement comme un vecteur de fuite qui ne peut pas s'executer rend `SKIPPED` et jamais `PASSED`. Et **tout candidat ecarte dit pourquoi**, parce qu'un choix de protocole qui ne s'explique pas est indebogable sur le terrain. Il n'a par ailleurs aucun verbe pour toucher au kill switch : l'exigence "jamais leve pendant une bascule" est structurelle, pas disciplinaire.

Les **sondes** qui remplissent cette structure sont ecrites, dans `bifrost-daemon`, et `--sonder-reseau` affiche d'un coup ce qui a ete mesure, ce qui ne l'a pas ete avec son motif, et le plan qui en decoule dans les trois modes. Elles n'ouvrent que des sockets clients, donc aucun privilege n'est requis. Six des sept champs sont mesures dans le daemon : TCP/443, UDP, ports hauts, portail captif, QUIC et taux de perte. Le septieme, l'inspection TLS, est mesure lui aussi mais AILLEURS - dans le client, hors du processus privilegie - et le rapport du daemon le declare non mesure en disant pourquoi.

La **sonde QUIC** est ecrite, et elle corrige le plan sur deux points. Le document 04 prescrit "tenter H3 vers un domaine H3-capable" ; aucune pile HTTP-3 n'est necessaire, parce que la question posee est "le pair repond-il a du QUIC" et non "une requete HTTP aboutit-elle". Et une seule tentative ne suffit pas a lire ce qui se passe : le pare-feu chinois DECHIFFRE l'Initial QUIC - ses clefs se derivent d'un sel public et d'un numero de connexion en clair - puis filtre sur le nom de serveur qu'il y trouve. Un echec unique ne dirait pas si l'UDP est coupe ou si c'est le contenu qui a ete lu.

La sonde envoie donc deux paquets et lit leur DIFFERENCE. Une negociation de version d'abord, avec un numero de version que personne ne supportera jamais : sa charge est indechiffrable par construction, donc aucun censeur n'y lit de nom de serveur, et tout serveur QUIC doit repondre. Un Initial version 1 valide ensuite, portant un vrai `ClientHello` et un nom banal - exactement ce qu'un censeur inspecte. La negociation repond mais pas l'Initial : le contenu est filtre. Les deux se taisent alors que le temoin TCP vit : l'UDP est coupe. Les deux repondent : QUIC passe.

**Un risque que le plan ne mentionne pas** a dicte deux regles. Le meme article de recherche mesure que le blocage chinois est RESIDUEL et qu'un seul paquet le declenche : tous les paquets UDP partageant le triplet (source, destination, port) sont ensuite jetes pendant environ trois minutes. Une sonde imprudente punirait donc le reseau de son propre utilisateur, et tuerait le chemin UDP qu'elle venait mesurer. D'ou : le nom annonce est banal et jamais celui d'un endpoint qu'on compte utiliser, et la cible n'est jamais l'endpoint du tunnel.

La partie pure se confronte aux **vecteurs de l'annexe A du RFC 9001**, octet pour octet : derivation, nonce, donnee associee, chiffrement et protection d'en-tete y passent d'un coup, et chacun de ces cinq points a une facon d'etre faux qui reste coherente avec les quatre autres. La partie reseau est mesuree contre de vrais serveurs, et une falsification a un octet du sel initial suffit a faire taire l'Initial en laissant la negociation repondre : la signature exacte d'un contenu filtre.

La **sonde d'inspection TLS** est ecrite, et elle corrige le plan sur sa forme meme. Le document 04 demande "un domaine dont on connait l'empreinte de chaine" et une comparaison au pin. Cette forme a une date de peremption publique : le CA/Browser Forum a ramene la duree de vie maximale d'un certificat public a 200 jours depuis le 15 mars 2026, puis 100 jours en 2027 et 47 en 2029. Une empreinte epinglee vieillirait en quelques mois et la sonde crierait a l'interception a chaque renouvellement - le pire faux positif possible, puisqu'il accuse le reseau de l'utilisateur d'une chose qu'il ne fait pas.

Ce qui est epingle a la place, c'est le **jeu de racines**, pas un certificat. Une interception d'entreprise ne fonctionne que d'une facon : en installant une autorite a elle dans le magasin LOCAL de la machine. La chaine observee est donc validee contre le jeu de racines de Mozilla EMBARQUE dans le binaire, jamais contre le magasin du systeme - l'y interroger reviendrait a demander au renard si le poulailler va bien. C'est bien le pin que le plan demande, pris un cran plus haut, la ou les ancres changent tous les quelques ans.

La poignee est menee jusqu'au bout par un verificateur qui NOTE la chaine et accepte tout, puis la validation se fait hors ligne. Refuser pendant la poignee enverrait une alerte et couperait, ce que le plan interdit - et un client qui rejette bruyamment se signale a l'equipement qui l'intercepte. Une falsification a montre que refuser ne change rien a ce que la sonde LIT ; la propriete se verifie donc du cote serveur, et une recette l'y verifie.

**Elle ne tourne pas dans le daemon, et c'est une frontiere du depot qui l'a impose.** Elle y avait ete ecrite ; `frontiere_reseau.rs` l'a refusee, et il a eu raison : le daemon tourne en root, en permanence, et une poignee de main TLS analyse des donnees choisies par le pair - ici, par hypothese, un equipement qui intercepte. Lier une pile TLS a ce processus ferait d'un defaut d'analyseur une compromission racine permanente. La sonde vit donc du cote non privilegie, exposee par `bifrost-cli inspection-tls`, et `--sonder-reseau` laisse `mitm_tls` non mesure en le disant. Le prix est reel et il est ecrit.

Son **temoin positif** compte autant que le reste : un `mitm_tls` a faux sur un reseau sain est aussi ce que rendrait une sonde qui ne regarde rien. Une recette monte donc un serveur TLS local a certificat auto-signe - exactement ce que presente un equipement d'entreprise une fois sa racine installee - et verifie que la sonde le voit. Le magasin du systeme n'est pas touche : le modifier serait un changement de configuration de securite de la machine, et ce n'est pas a une recette de le faire.

La **sonde de perte** ferme la liste, et la raison qui la disait impossible etait fausse. Il etait ecrit que ce champ demandait une mesure sur duree, hors du budget de cinq secondes. Ce qui coutait cher n'etait pas la duree mais l'ATTENTE : sonder tir par tir aurait fait payer une echeance entiere a chaque paquet perdu, donc trente-sept secondes sur une serie a moitie perdue. Une salve qui emet et ecoute en meme temps dure trois secondes, que le reseau perde tout ou rien.

Elle emet vingt-cinq requetes STUN par cible, espacees de soixante millisecondes, sur les serveurs que les autres sondes joignent deja - aucune destination de plus dans la trace de ce client, et le bon transport : le chiffre sert a promouvoir ou non un protocole UDP. La taille de l'echantillon se deduit de la decision et non d'un gout : le seuil est a 5 %, les regimes qui comptent sont 5 % puis 20-30 %, et distinguer 4 % de 6 % demanderait des centaines de tirs sans changer aucune decision.

Deux garde-fous, et chacun repare une facon de mentir. Les serveurs STUN publics **limitent leur debit sans jamais publier de seuil** ; une limitation laisse passer un debut puis coupe, donc ses pertes sont groupees en queue, la ou une perte reseau est dispersee - la sonde ecarte les series coupees net plutot que de les moyenner. Et **cent pour cent de perte n'est pas un regime de reseau** : c'est un UDP coupe, question que `udp_passe` porte deja. Le rendre ferait franchir le seuil et promouvoir Hysteria2, un protocole UDP, sur un reseau ou l'UDP ne passe pas du tout.

Cette sonde a trouve un defaut que personne ne cherchait. La liste des cibles portait `1.1.1.1:3478` sous le commentaire « stun.cloudflare.com ». Cette adresse ne parle pas STUN, et le vrai serveur est ailleurs. Le defaut avait survecu parce que la sonde d'UDP se contente d'UNE reussite dans la liste : la moitie des preuves d'UDP etait fabriquee, et rien ne le disait. La sonde de perte est la premiere a interroger chaque cible SEPAREMENT ; elle a mis en commun vingt-cinq reponses et vingt-cinq silences, et annonce 50 % de perte sur un lien filaire impeccable. L'adresse est corrigee, mais surtout le garde manquait : une cible muette est desormais ecartee, comme une cible en panne l'est partout ailleurs ici.

**La selection est enfin appelee par le flux de connexion**, et le defaut qu'elle y corrige etait un chemin entier rendu injoignable. La demarche - ce que la couche de decision engage a monter - etait arretee au DEMARRAGE du daemon, sur une ligne qui disait `TunnelDirect(WireGuardNu)`. Or le chemin par coeur etait ecrit, teste, exempte par le kill switch et prouve de bout en bout sur essai-linux : il etait simplement refuse a la porte, parce que la decision avait ete prise avant de savoir ce qu'on demanderait. Une demarche est une propriete de la CONNEXION, pas du daemon.

Le meme defaut avait une seconde face, plus silencieuse : le carnet ne notait que les tunnels directs. La moitie de la memoire dont la selection se sert - celle des techniques a coeur - n'etait jamais ecrite, et rien ne le disait.

**Le flux de connexion ne sonde pas, et c'est un choix documente.** Le plan suppose un sondage au premier contact ; l'etat de l'art dit l'inverse par trois voix independantes - Psiphon, le Smart Dialer d'Outline, le Connection Assist de Tor - et le seul systeme documente qui sonde avant de choisir met 13,8 s en Chine pour une reponse que la tentative donne en meme temps que la connexion. Cela tient parce que la selection est asymetrique : seule une mesure elimine. Un environnement vierge n'ecarte donc rien, non par prudence de l'appelant mais par construction du type.

**Et la selection y joue un role de veto, pas de choix.** L'utilisateur arrive avec un profil, donc avec une technique. Lui opposer le premier candidat du plan refuserait presque toutes les connexions, puisque le plan prefere REALITY et que la plupart des profils ne sont pas cela - la falsification le mesure : vingt recettes rouges. La selection dit donc ce qu'il ne faut PAS monter ici et avec quel motif, ce qui est la regle « un candidat ecarte dit pourquoi » portee jusqu'au refus que l'utilisateur lit. La documentation d'Outline decrit la meme discipline : son dialer choisit dans ce que la configuration fournit, jamais en dehors.

Une derniere chose sur la duree de vie de ce veto, et elle a d'abord ete ecrite FAUSSE ici meme. On y lisait que le tableau de survie portait des observations d'avril 2026 et qu'aucune de ses lignes ne pouvait plus eliminer depuis debut juillet. Verification faite le 20 aout 2026 : ses lignes les plus recentes datent de juillet, elles ont cinquante jours, et elles gardent donc parfaitement le droit d'eliminer. Seules Hysteria2, mesuree en janvier, et WireGuard nu, mesure en avril, sont perimees.

La lecon n'est pas l'erreur, c'est ce qui l'a permise : une affirmation sur une date, ecrite en prose dans quatre documents, que rien ne verifiait. Elle est desormais une constante, `TABLEAU_INERTE_A_PARTIR_DU`, epinglee par une recette qui verifie qu'a la veille une ligne mord encore et que le jour dit plus aucune. **Le tableau devient inerte le 30 septembre 2026** s'il n'est pas rafraichi d'ici la ; rafraichir une observation sans corriger la constante rend la recette rouge, ce qui force a corriger les documents avec.

**Le verdict d'inspection TLS rejoint enfin la decision du daemon**, et par l'IPC plutot que par un sous-processus. C'etait le seul champ de l'environnement que le daemon ne mesure pas lui-meme : une frontiere du depot lui interdit une pile TLS, parce qu'il tourne en root et qu'une poignee de main analyse des donnees choisies par le pair - ici, par hypothese, l'equipement qui intercepte. Lui faire lancer un enfant qui parle TLS lui rendrait par la fenetre ce que la frontiere lui interdit par la porte : il faudrait un chemin de binaire, un compte dedie, une bascule de privileges dans du code root. Or le client EST deja ce processus non privilegie, et il parle deja au daemon. `bifrost-cli inspection-tls --annoncer` mesure et transmet ; le daemon ecoute.

Le chemin de binaire, en particulier, est exactement ce que ce depot refuse ailleurs : `connect` sans argument n'accepte aucun chemin, parce que faire lire au daemon un fichier que l'appelant designe ferait de lui un depute confus. Un `--client-dans` aurait eu la meme forme et le meme defaut.

**Et un client menteur n'y gagne rien, ce qui se demontre plutot que s'espere.** Un verdict a vrai ecarte REALITY, et rien d'autre ; or le client choisit deja le profil, donc pour eviter REALITY il lui suffit de ne pas en envoyer. Un verdict a faux n'ecarte rien du tout, puisque seule une mesure elimine. Quant a l'ignorance, elle ne peut pas voyager : la commande porte un booleen et non un `Option`, donc « je n'ai rien pu mesurer » est inexprimable sur le fil - le seul degat possible, ecraser une mesure par une ignorance, n'est pas teste, il est **impossible a ecrire**.

`--annoncer` est explicite, et le restera : une commande qui a l'air de ne faire que regarder ne doit pas modifier au passage ce sur quoi le daemon fondera ses refus. Si le daemon est absent, l'echec se dit sans changer le code de sortie, qui reste celui de la mesure - le verdict appartient d'abord a qui l'a demande.

Une falsification a trouve ce que la relecture n'avait pas vu : cette commande est **la seule** que le daemon ne traite pas par un aller-retour. Toutes les autres attendent une reponse du superviseur, donc un « ok » prouve qu'il a recu. Celle-ci pourrait repondre « ok » en jetant le verdict, et le daemon deciderait ensuite sur une mesure qu'on croirait lui avoir donnee. Deux recettes gardent maintenant ce fil-la.

**Un tunnel a desormais plusieurs candidats**, et c'est ce qui manquait pour qu'une course existe. Un profil ne decrivait qu'une technique ; il en decrit une liste, un par transport, et le daemon les ecrit toutes derriere le meme selecteur sing-box. La liste est **non vide par construction** et non par validation : un portage par coeur qui ne designerait aucun coeur lancerait un coeur sans sortie, derriere un selecteur vide, avec un tunnel qui monte devant - autant rendre cet etat inecrivable.

**C'est la selection qui devient le defaut du selecteur, pas l'ordre du fichier.** Le generateur fait de la premiere sortie le defaut ; l'ordre rendu EST donc la decision, et il n'existe pas de second endroit ou elle serait appliquee - donc pas de risque qu'ils divergent. Le reste garde l'ordre du fichier : un tri total inventerait un classement des replis que la selection n'a pas encore rendu, et c'est la course qui le donnera.

**Un profil qui propose deux techniques survit a la perte de l'une.** Le TLS intercepte condamne REALITY et rien d'autre ; il reste Hysteria2, et la connexion passe. Quand tout tombe, le refus nomme **chaque** motif : n'en montrer qu'un ferait corriger un point pour se heurter au suivant.

**Le plan est corrige sur le coeur qui porte REALITY, et c'est le plan lui-meme qui tranche contre lui-meme.** Sa partie 6 designe Xray, qui porte REALITY en premier et le plus abouti en amont. Sa partie 3.3 exige que le choix se pilote via la Clash API, parce qu'urltest ne detecte ni le gel a 16 Ko ni l'accessibilite reelle - et seul sing-box expose cette API. Une technique routee vers Xray ne peut donc pas etre pilotee par le mecanisme que le plan prescrit. Verification faite sur la documentation amont : sing-box accepte `flow: xtls-rprx-vision` et porte `reality { public_key, short_id }` cote client. REALITY et Hysteria2 vivent maintenant dans le meme processus, donc derriere le meme selecteur : basculer de l'une a l'autre ne relance rien, ne bouge pas le SOCKS local, et ne demande jamais de lever le kill switch. Les licences ne bougent pas : sing-box etait deja requis pour Hysteria2, et la frontiere reste celle du processus.

Ce defaut-la etait invisible et coutait cher : **un profil REALITY etait purement et simplement refuse** par le daemon, alors que le generateur savait ecrire sa sortie. Il a fallu ajouter un second candidat pour que la recette le fasse tomber.

**La course pilote maintenant le selecteur pour de vrai.** C'etait la moitie qui manquait : elle savait quoi lancer, quand, et quand passer au suivant, mais personne ne l'appelait hors de l'affichage. Un gel a 16 Ko ou un debit effondre sur dix secondes ne demonte plus le tunnel : le superviseur note l'echec a la course, attend une gigue, et fait passer le selecteur au candidat suivant. Le SOCKS local ne bouge pas, le TUN reste monte, le kill switch n'est jamais leve - les trois conditions que le document 04 partie 3.2 pose pour une bascule en cours de session, vraies precisement parce qu'on ne relance rien.

**Le verdict d'une bascule est RELU, jamais deduit du statut.** `PUT /proxies/<selecteur>` rend 204 quand le coeur a *accepte* la requete ; ce n'est pas la meme chose que d'avoir change de sortie. S'y fier ferait croire la course avancee pendant que le trafic continuerait de passer par la sortie gelee, et le tunnel mourrait une seconde fois sans qu'on comprenne pourquoi. La sequence « demander, relire, comparer » est desormais ecrite **une seule fois** : `--coeur-selftest`, qui la mesure contre un vrai binaire, appelle exactement le code qui tourne quand un candidat lache en cours de session. Elle etait en double, et deux copies d'une meme politique divergent un jour.

**`interrupt_exist_connections` est a VRAI sur notre selecteur, la ou le plan le met a faux dans son exemple.** L'exemple le pose sur un `urltest`, qui bascule sur une *preference* - couper des connexions saines pour cinquante millisecondes serait destructeur. Notre selecteur ne bascule que sur un *verdict* mesure. Et une connexion TCP etablie a travers la sortie A ne peut pas etre deplacee vers B : la laisser vivre ne la sauve pas, cela la fait pendre. L'argument decisif est ailleurs : notre observation lit les compteurs du TUN, qui **agregent** tout ; des connexions gelees laissees en place tireraient la moyenne vers le bas et feraient condamner un candidat qui n'a jamais eu sa chance, puis de proche en proche toute la liste.

**Ce qui ne declenche pas de bascule est aussi precis que ce qui en declenche une.** Une mort sans signature reconnue (`Muet`) perd le tunnel comme avant : elle peut etre le censeur, mais aussi le serveur qui redemarre, un Wi-Fi qui saute ou un NAT recycle, et basculer la-dessus brulerait un candidat sain a chaque coupure ordinaire. Une voie WireGuard ne bascule jamais - il n'y a pas de selecteur derriere elle. Et une bascule refusee par le coeur est une panne **chez nous** : elle fait passer au suivant mais n'entre pas au carnet, sans quoi elle ecarterait une technique d'un reseau pour une raison qui n'a rien a voir avec lui, et suivrait la machine sur tous les reseaux qu'elle visite.

Une falsification a paye ici aussi : le filtre qui protege le carnet de ces pannes locales etait devenu **du code mort**, parce que le seul chemin qui produit ce genre d'echec n'atteignait pas le carnet du tout. Il avait l'air de proteger quelque chose et ne protegeait rien ; l'enlever ne changeait aucun resultat. Les deux gestes - noter a la course, porter au carnet - sont maintenant au meme endroit, et la regle vaut pour tout echec quel que soit le chemin qui l'a produit.

**Le mecanisme du plan tient toujours en aout 2026, verification faite.** L'`urltest` de sing-box ne choisit que par latence et n'a aucun repli sur echec ; les demandes qui en reclament un (SagerNet/sing-box#2130, #2061) sont toujours ouvertes en amont. Il n'y a rien de natif a adopter a la place du « superviseur maison qui pilote le selector via la Clash API » que la partie 3.3 prescrit.

Deux choses qu'on n'a pas prises dans le standard de l'ecosysteme. Les XTLS Subscription Standards renvoient un tableau JSON de configurations xray-core completes ; nous portons des **profils**, pas des configurations de moteur etranger - c'est exactement ce que le type de profil existe pour empecher. Et `store_selected` de sing-box reste eteint : il ferait garder au coeur sa propre memoire du dernier choix, une seconde memoire a cote du carnet que rien ne synchronise et que personne ne relit.

Leur piece maitresse est un **temoin**. Un echec de connexion sur 443 ne prouve rien seul : une machine debranchee produit exactement le meme symptome qu'un port filtre. Le port 80 sert d'arbitre, et sans lui un cable debranche se lirait comme une censure. Une recette le verifie de bout en bout en pointant toutes les cibles vers TEST-NET-1, qui n'est routee nulle part : aucune sonde ne doit conclure.

Le **lancement des coeurs tiers** est ecrit. sing-box est sous GPL-3.0 : le lier au client en ferait une oeuvre derivee et imposerait la GPLv3 a tout Bifrost, qui est sous MPL-2.0. La parade est une frontiere de processus, et elle n'est pas seulement documentee : `crates/bifrost-evasion/tests/frontiere_licence.rs` lit le graphe de dependances reel et refuse toute dependance Rust sous GPL ou AGPL, toute LGPL non explicitement tranchee, et tout paquet sans licence declaree.

Le superviseur garantit surtout qu'un coeur **ne survit pas au daemon**. Un sing-box orphelin garderait son ecoute SOCKS ouverte, donc une sortie que plus personne ne supervise. Le code d'arret ne protege pas de ce cas, puisqu'il ne tourne pas quand le daemon est tue net : la garantie est demandee au systeme, par `PR_SET_PDEATHSIG` sous Linux et par un objet Job sous Windows. Une recette tue le daemon brutalement et verifie que le coeur meurt, avec le temoin negatif qui va avec - sans la garde, le meme coeur survit.

Les deux coeurs ont ete **lances pour de vrai et pilotes**, sing-box 1.13.18 et Xray 26.3.27 : `--coeur-selftest` engendre la configuration, demarre le coeur, verifie que la bascule du selecteur PREND en relisant celui-ci, refuse une sortie inexistante comme temoin negatif, puis arrete. Elle ne demande aucun privilege.

La **degradation en cours de session** est detectee, et le mecanisme merite d'etre dit parce qu'il corrige le plan. Le document 04 decrit le gel apres 16-20 Ko et l'effondrement du debit comme des observations d'un flux vivant. Le second l'est ; le premier ne peut pas l'etre. Un tunnel inactif et un tunnel gele sont indiscernables de l'exterieur : dans les deux cas plus rien n'arrive, et une session SSH ouverte et silencieuse produit exactement la trace d'une connexion coupee par un DPI. L'information manquante n'est pas dans les compteurs, elle est chez le pair, et il faut la lui DEMANDER.

C'est ce que fait la **sonde de vitalite**, et elle ne l'emet pas elle-meme : elle demande au coeur de composer un aller-retour a travers la sortie courante. Deux raisons. Le kill switch exempte la sortie du coeur par identite, alors qu'une sonde emise par le daemon se heurterait au `udp dport 53 drop` que nos propres regles posent avant d'accepter le tunnel - son echec se lirait comme un pair mort, et on demonterait un tunnel sain parce qu'on aurait ferme la porte soi-meme. Et c'est le coeur, pas le daemon, qui sait par ou passe la sortie du moment. Sur un tunnel WireGuard la question ne coute rien : le protocole renouvelle sa poignee de main AVEC le pair, donc une poignee plus recente que le debut du silence est un aller-retour deja paye. Sur un chemin par coeur elle serait trompeuse - la poignee y est fabriquee, elle repondrait toujours "vivant", et une reponse toujours positive est pire que pas de reponse : elle a l'air d'une mesure.

Trois issues, et la troisieme est celle qui protege : le pair a repondu, le pair n'a pas repondu, **je n'ai pas pu demander**. Un coeur absent, un secret refuse, un selecteur inconnu ne disent rien du reseau et ne condamnent donc rien. Les statuts qui les distinguent ne sont documentes nulle part en amont ; ils ont ete mesures contre le binaire epingle, et `tests/vitalite.rs` les rejoue contre un vrai sing-box quand `BIFROST_COEURS` designe son repertoire, `SKIPPED` avec sa raison sinon. Elle ne demande ni privilege ni acces a internet : la cible est un temoin HTTP local, et le pair muet est obtenu par une sortie pointee sur un port ferme.

A noter pour l'empaquetage : Xray publie une empreinte SHA-256 par archive, verifiee avant execution ; sing-box n'en publie aucune, ni signature, sur aucun de ses 154 assets. La chaine de mise a jour devra donc fabriquer cette garantie elle-meme.

**Du trafic reel traverse maintenant un tunnel VLESS + REALITY**, d'un client sing-box sous Windows a un serveur Xray sous Linux. La recette `--coeur-e2e` ne se contente pas de constater que le selecteur change d'avis : elle vise une banniere posee sur la BOUCLE LOCALE du serveur de sortie, donc une adresse qui n'est atteignable que si le CONNECT a ete resolu a la sortie du tunnel. Trois temoins l'encadrent - injoignable en direct, injoignable des la bascule vers la sortie en clair, joignable de nouveau au retour. Sans le troisieme, un coeur simplement casse passerait le deuxieme aussi bien qu'un coeur qui route.

Un piege s'y est revele, qui merite d'etre connu de quiconque deploie REALITY : **le site emprunte est une condition de correction, pas un gout**. Le serveur rejoue au client la poignee de main TLS qu'il vole a ce site ; si la chaine de certificats ne tient pas dans le tampon prevu, la poignee ne se termine jamais et le client ne voit qu'un `EOF` muet. `dl.google.com`, `www.cloudflare.com` et `addons.mozilla.org` passent ; `www.microsoft.com` echoue, son enregistrement Certificate faisant 8273 octets pour 4282 disponibles. L'authentification REALITY, elle, reussissait depuis le debut : les clefs n'y etaient pour rien.

**Du trafic reel traverse aussi un tunnel Hysteria2**, du meme client sing-box sous Windows vers un serveur hysteria sous Linux, avec la meme banniere sur la boucle locale du serveur et les memes trois temoins. Son certificat est **epingle** : le type `Confiance` n'offre volontairement aucune variante « ne pas verifier », parce qu'un `insecure: true` recopie d'un tutoriel ferait passer la recette avec un tunnel non authentifie, donc lui ferait prouver le contraire de ce qu'elle annonce.

Mais il ne passe que sur un chemin assez large, et cela a coute cher a etablir. **Sur un chemin a 1280 de MTU, Hysteria2 ne se connecte pas, et la panne est muette des deux cotes.** quic-go emet des paquets de 1280 octets, aux deux bouts, tant que rien ne les reduit. Avec les 8 octets de sel Salamander et les 28 d'en-tetes IP et UDP, cela fait un paquet IP de **1316 octets** sur un chemin dont le MTU est de **1280**. Le compte tient meme sans obfuscation : 1308, toujours au-dessus.

L'asymetrie explique pourquoi la panne etait muette. Windows ne pose pas le bit DF : il fragmente, et ses paquets arrivent, reassembles sans un seul echec cote Linux. Linux pose DF : son `Initial` porteur du ServerHello est **refuse par son propre noyau**, sans qu'aucun paquet ne parte ni qu'aucune ligne de journal ne le dise. Mesure directe sur le serveur :

| Charge UDP | Paquet IP | DF pose | DF absent |
|---|---|---|---|
| 1250 | 1278 | envoye | envoye |
| 1258 | 1286 | `EMSGSIZE` | envoye, fragmente |
| 1288 | 1316 | `EMSGSIZE` | envoye, fragmente |

Le temoin positif acheve la demonstration : le meme serveur, joint par un client Linux en boucle locale ou le MTU est de 65536, emet bien un `Initial` de 1280 octets. Sur le chemin etroit, cet `Initial` n'existe pas. Le client n'obtient donc jamais les clefs de niveau Handshake et reemet le sien indefiniment, ce qui est exactement ce que les captures montraient.

Deux eliminations precedentes etaient fausses et meritent d'etre corrigees. Le MTU avait ete ecarte parce que « UDP passe jusqu'a 1400 octets » : c'est vrai, et c'est precisement parce que l'emetteur du test, Windows, fragmentait. La mesure repondait a une autre question que celle posee. Tailscale avait ete ecarte parce que « l'echec se reproduit a l'identique sur le LAN » : refait en visant l'adresse LAN, le client emet bien onze `Initial` de 1316 octets qui ARRIVENT tous sur l'interface du serveur, mais `ufw` les jette avant le socket, sa chaine n'acceptant que `tcp/22`, `tailscale0` et `tcp/8121`. `tcpdump` lit avant netfilter, d'ou des paquets visibles et un serveur muet. Cette ligne mesurait un pare-feu, pas un reseau.

**La preuve par retournement, une fois le port ouvert :** meme client, meme serveur, meme certificat, meme mot de passe, seule l'adresse change pour emprunter un chemin a 1500 au lieu de 1280. Le serveur emet alors son `Initial` de 1316 octets AVEC le bit DF - exactement le paquet que son noyau lui refusait - la poignee de main est bouclee en neuf millisecondes, et le journal du serveur nomme pour la premiere fois un client Windows. La recette est verte sur ses sept etapes, les deux transports compris.

```
t+0.007s  client  -> serveur  1316o      Initial(1280o)
t+0.009s  serveur -> client   1316o DF   Initial(1280o)     <- le ServerHello
t+0.009s  serveur -> client    868o DF   Handshake(741o), 1-RTT(91o)
```

Aucun reglage ne corrige cela avec les binaires epingles. `initial_packet_size` n'existe que dans la branche `testing` de sing-box ; la version epinglee, 1.13.18, **refuse la configuration entiere** des qu'il apparait, emportant avec elle les transports qui n'avaient rien demande. Les champs qu'elle accepte ont ete etablis en soumettant chacun a `sing-box check`, et un test garde desormais cette liste. Cote serveur, hysteria n'expose que `disablePathMTUDiscovery`, qui coupe la sonde ascendante sans toucher a la taille de depart.

Ce n'est pas un blocage produit : un chemin ordinaire fait 1500 octets. Cela mord sur les chemins a 1307 ou moins, c'est-a-dire tout tunnel WireGuard, Tailscale, et le minimum impose par IPv6 - **y compris le tunnel de Bifrost lui-meme**, ce qui est une contrainte reelle des qu'un coeur QUIC tourne a l'interieur.

Ce qui a ete construit a la place d'un correctif introuvable : la sonde `sonder_chemin_quic`, qui pose DF et demande au noyau si un paquet de cette taille peut partir, arbitree par un temoin court pour ne pas confondre un chemin etroit avec une machine debranchee. La recette l'interroge avant d'essayer et annonce **`SKIPPED` avec les chiffres** au lieu d'expirer sans rien dire. Elle est eprouvee sur de vrais sockets, sous Windows et sous Linux, sur un chemin large comme sur un chemin a 1280 : sous Windows, ou le systeme fragmente par defaut, seule une pose de DF reellement effective peut rendre la bonne reponse.

**Le site emprunte par REALITY se qualifie maintenant avant de le choisir.** `--qualifier-dest <hotes>` envoie un `ClientHello` credible, compte ce que le site renvoie, et le compare a un site de reference mesure dans le meme passage. Aucune bibliotheque TLS n'est necessaire : les en-tetes d'enregistrement sont en clair meme quand leur contenu ne l'est pas, donc on mesure des tailles sans jamais deriver de clef.

La comparaison est relative, et c'est le resultat d'une calibration ratee qu'il vaut mieux raconter. Xray annonce 8273 octets contre 4282 disponibles quand il refuse `www.microsoft.com`, mais cette grandeur n'est pas observable depuis un client : la meme poignee, vue du dehors, donne un plus grand enregistrement de 5924 octets. Figer 4282 aurait d'abord declare inutilisable `dl.google.com`, qui fait passer du trafic tous les jours. La sonde compare donc a un site verifie plutot qu'a un seuil invente, et ce site de reference joue exactement le role de temoin du reste du depot : sans lui, rien n'est qualifie.

| Site | Plus grand enregistrement | Verdict de la sonde | Issue reelle |
|---|---|---|---|
| `www.cloudflare.com` | 1970 | dans l'enveloppe | passe |
| `www.apple.com` | 3271 | dans l'enveloppe | non eprouve |
| `addons.mozilla.org` | 4133 | dans l'enveloppe | passe |
| `dl.google.com` | 4985 | reference | passe |
| `www.microsoft.com` | 5924 | au-dela | echoue |
| `www.bing.com` | 5991 | au-dela | non eprouve |

Quatre points ne font pas une loi, et la sonde le dit : « dans l'enveloppe » ne certifie rien, c'est « au-dela » qui informe. Une marge de 5 % separe le bruit du signal, deux mesures du meme site ayant donne 4985 puis 4984 octets alors que les ecarts qui comptent sont de 19 a 20 %.

**Le trafic du systeme entre maintenant dans un coeur.** Un coeur parle SOCKS ; le systeme, lui, emet des paquets IP. Ce qui manquait entre les deux est ecrit et mesure sur machine Linux. Un **TUN** ouvert a la main plutot que par une bibliotheque, ou un nom trop long est REFUSE et non tronque : le kill switch designe l'interface par son nom, et une troncature silencieuse ferait proteger une autre interface. Un **passeur**, pile TCP/IP en espace utilisateur qui traduit chaque flux en un `CONNECT` SOCKS5 vers la facade, avec l'adresse d'origine et le bon `ATYP`. Un **aiguillage** qui envoie le systeme dans le TUN et fait sortir le coeur par **identite** et non par marque - le meme discriminant que celui du kill switch, faute de quoi un coeur autorise par les filtres ressortirait par une porte qui ramene a l'interieur. Et l'**assemblage**, qui n'a demande aucune forme nouvelle a la machine a etats : elle ne parle qu'a un port, `TunnelDevice`, et il suffisait d'une deuxieme implementation.

La recette monte l'interface, fait passer une connexion TCP ordinaire de bout en bout jusqu'a un CONNECT visant la destination d'origine, verifie que le coeur ne se route pas dans son propre TUN, et ne laisse ni interface ni regle derriere elle. Elle se relance dans un espace de noms reseau, parce que ce qu'elle pose est une route par defaut pour toute la machine. Son premier jet a echoue et a appris quelque chose qui depasse la recette : dans un espace de noms sans route par defaut, le coeur retombe dans le TUN - donc **sur une machine qui perd son lien physique, le coeur serait route dans son propre tunnel**. Le kill switch tient a ce moment-la, mais il faut le savoir.

**L'UDP passe aussi**, par une association SOCKS5 dont le lien de controle TCP est garde ouvert et surveille : c'est lui qui tient l'association. Le piege d'interoperabilite y est traite - un mandataire qui ecoute partout annonce son relais en `0.0.0.0`, qui n'est l'adresse de personne, et la regle est d'en garder le port en reprenant l'adresse du mandataire ; la recette l'annonce ainsi deliberement. Un datagramme fragmente est rejete plutot que pris pour entier, et un datagramme dont la source n'est pas la destination visee est ecarte : le relais rend ce qu'il veut, l'application n'a parle qu'a une adresse.

**Et le chemin est desormais entier.** Un client qui envoie un profil de coeur - lu d'un lien de partage `vless://` ou `hysteria2://`, la forme que les panneaux d'administration et les QR codes emettent deja - obtient un tunnel par coeur qui monte pour de vrai : le superviseur met en service le peripherique qui sait le porter, engendre la configuration du coeur depuis le profil, l'ecrit, lance le coeur, attend qu'il reponde, et monte alors seulement l'interface. L'ordre n'est pas negociable et une recette le mesure : le kill switch est arme AVANT que le coeur ne demarre - il trouve donc son exemption deja posee, et il n'existe aucun instant ou il tourne sans elle - et le coeur repond AVANT que l'interface n'envoie la machine vers la facade.

Trois refus gardent ce chemin, et chacun ferme un mode d'echec qui aurait eu l'air de marcher :

- **La decision et le profil doivent s'accorder.** Une demarche par coeur avec un profil WireGuard, ou l'inverse, est refusee en nommant les deux. Un daemon qui monte autre chose que ce que sa couche de decision a retenu est pire qu'un daemon qui refuse.
- **Seul sing-box porte un profil aujourd'hui.** Le generateur de configuration de Xray n'ecrit qu'une sortie directe : le lancer avec un vrai profil ferait sortir le trafic **en clair**, depuis un compte que le kill switch exempte, avec un tunnel qui a l'air monte. Amneziawg, lui, se pilote par UAPI et ne prend pas de fichier au lancement. Les deux sont refuses en le disant.
- **Un coeur qui ne demarre pas ne se retente pas.** Le retenter relancerait le meme binaire avec la meme configuration et le meme secret, ecrits une ligne plus haut : la boucle ne convergerait jamais et couterait un processus par tour. Mesure du 19 aout 2026 sur essai-linux, en falsifiant le secret de l'API : sans cette regle, la connexion rendait `Ok` pendant que rien n'etait monte.

**Le chemin par coeur existe aussi sous Windows.** Les trois etages y sont desormais cables : le TUN Wintun s'ouvre, l'interface recoit son adresse, sa MTU et sa route, et le passeur mene les paquets a la facade. Ce qui change de plateforme n'est pas l'assemblage, c'est **l'echappement du coeur** - le fait qu'il puisse joindre son serveur au lieu de boucler dans son propre tunnel.

Linux le fait par la table de routage, et par **identite** : `ip rule uidrange` envoie ce qui vient du compte du coeur dans la table `main`. Windows ne sait pas router par processus - sa table ne connait que des destinations, et la seule facon d'y router par processus serait un pilote de rappel WFP en mode noyau, que le plan ecarte. L'echappement **demenage** donc : de la table de routage vers la configuration du coeur, ou il devient une liaison de socket, `bind_interface` pour sing-box et `sockopt.interface` pour Xray. Les deux posent `IP_UNICAST_IF`, ce qui fait sortir par l'interface nommee **quelle que soit la table de routage** - verifie dans la source des deux binaires epingles, pas dans leur documentation. La propriete que le plan demandait ne bouge pas : l'echappement se decide sur la **socket** du coeur, pas sur une adresse de destination.

Le moment de la decision fait partie de la reponse. Le nom de l'interface est calcule **avant** que la route par defaut du tunnel n'existe ; la meme question posee apres repondrait le tunnel lui-meme, c'est-a-dire exactement la boucle qu'elle sert a eviter. Une recette le rend visible en posant une route hote vers une adresse temoin : la meme fonction, la meme adresse, deux reponses differentes selon le moment.

Cout assume : le nom est fige au lancement du coeur, donc un changement de lien - Wi-Fi a la place du cable - rend la liaison caduque. C'est un echec **ferme** : rien ne sort par une porte qu'on ne voulait pas, le tunnel cesse simplement de fonctionner.

**Une correction de plan est tombee en chemin.** Poser la route par defaut sur le tunnel ne suffit pas sous Windows : deux routes `/0` coexistent alors, celle du lien physique et la notre, et c'est la somme metrique d'interface plus metrique de route qui departage. Une interface fraiche recoit une metrique calculee sur la vitesse du lien, que rien ne garantit gagnante - le tunnel monterait et le trafic continuerait de sortir en clair a cote. La metrique de l'interface est donc forcee a zero, et **seulement quand le plan prend reellement la route par defaut** de cette famille. Les deux references font exactement cela au meme endroit : WireGuard pour Windows sous `if foundDefault4`, sing-tun sous `if AutoRoute`.

Le chemin par coeur n'existe que si le daemon a ete demarre avec `--coeurs-dans` **et** `--facade`, ses deux moities : avec la facade seule le TUN enverrait tout le trafic vers une ecoute qui ferme les connexions, avec le repertoire seul un coeur tournerait sans que rien ne le rejoigne. Sans l'un des deux, un profil de coeur est refuse en nommant les drapeaux manquants.

**Et un coeur qui meurt est remarque.** L'interface, a elle seule, ne prouve rien : elle tient debout meme quand le coeur qui porte le trafic est mort, et le tunnel paraissait alors vivant alors que plus rien ne passait. L'atelier attend desormais la mort de son coeur au lieu de ne se reveiller qu'a la demande suivante ; quand elle arrive il cesse de le publier, en journalisant son code de sortie **et ce qu'il a dit sur sa sortie d'erreur** - un `exit 1` muet enverrait chercher la panne partout. Le peripherique par coeur lit ce meme signal, celui-la meme que suit la facade, et le tunnel cesse d'etre vivant.

La suite ne demande aucun mecanisme nouveau : la perte du tunnel demonte et reprogramme une tentative, avec le recul qui existait deja, et la tentative relance un coeur. Le kill switch n'est jamais baisse pendant ce trajet, ce qu'une recette mesure a chaque montage. Le signal retenu est la **sortie du processus** et non un sondage de l'API : sing-box n'expose aucun point de vitalite - `/proxies/<tag>/delay` mesure la latence d'une sortie, pas la sante du coeur - et la demande d'un vrai healthcheck est encore ouverte a l'amont ([SagerNet/sing-box#1494](https://github.com/SagerNet/sing-box/issues/1494), verifie le 19 aout 2026). C'est aussi ce que surveillent les lanceurs en circulation.

## Le profil au repos

Un profil porte des secrets d'authentification : une cle privee WireGuard, ou l'UUID et le mot de passe d'un profil de coeur. Deux choses le protegent desormais, et la premiere est un durcissement qui **casse les profils mal ranges**, deliberement.

**Un profil en clair lisible par d'autres est refuse**, la ou il n'y avait qu'un avertissement imprime sur la sortie d'erreur au milieu d'une connexion qui reussissait - ce qui n'a jamais fait changer un mode a personne. Les droits sont verifies **avant** la lecture, et le groupe est refuse au meme titre que le monde : un profil en `0640 root:bifrost` donne la cle privee a tous ceux qui ont le droit de *piloter* le daemon, ce qui n'est pas la meme chose que d'avoir le droit de la lire. Le message nomme le mode fautif et donne la commande.

**Le repertoire compte autant que le fichier.** Un profil parfaitement en `0600` dans un repertoire ou n'importe qui ecrit peut etre **remplace** ; le remplacant designe le serveur de son choix, et le tunnel monte vers lui sans que rien ne le signale. C'est une redirection complete du trafic obtenue sans jamais lire le moindre secret, et c'est une propriete d'INTEGRITE, distincte de celle du fichier - c'est ce que protege le `0700` de `/etc/mullvad-vpn`. La verification porte donc sur l'ECRITURE et non sur la lecture, et elle honore le bit collant : `/tmp` en `1777` passe, parce qu'un repertoire collant ne laisse retirer un fichier qu'a son proprietaire.

**Un profil peut etre scelle**, par `bifrost profil sceller`. Le clair n'est alors plus necessaire, et la commande dit de le supprimer plutot que de le faire elle-meme : c'est la seule copie d'une cle privee, et la detruire n'appartient pas a cet outil. Tant que les deux coexistent, l'ouverture le signale.

### Pourquoi systemd-creds et pas le trousseau

Le plan nommait le keystore du systeme : DPAPI sous Windows, libsecret/Secret Service sous Linux. Cette seconde moitie ne tient pas, pour une raison mecanique : le Secret Service se joint par le bus de **session**. Un daemon systeme n'en a pas, et un `bifrost` lance par `sudo` non plus, `sudo` nettoyant `DBUS_SESSION_BUS_ADDRESS`. L'unite systemd de ce depot va deja plus loin et interdit les appels du trousseau : `SystemCallFilter=~@keyring`.

La reference du domaine est WireGuard lui-meme, et elle est asymetrique : sous Windows il chiffre ses configurations avec DPAPI, sous Linux `wg-quick` s'en remet aux droits du fichier - et [sa page de manuel](https://www.man7.org/linux/man-pages/man8/wg-quick.8.html) nomme deux voies pour aller plus loin, `pass(1)` et **systemd-creds**. C'est celle-la qui est retenue : AES256-GCM, cle maitresse partagee par defaut entre la puce TPM2 et un fichier de `/var/` - il faut les deux - et **le nom du credential est authentifie**, donc un ciphertext ne peut pas etre glisse dans le creneau du profil. Une recette le mesure en essayant precisement cela.

La frontiere retenue est celle que Tailscale trace pour son propre chiffrement d'etat, et elle est plus utile que le raccourci "root peut tout" : cela protege contre qui peut **lire** des fichiers, meme en root, sans executer de code - le vol du disque, la recopie sur une autre machine, un voleur d'informations qui ramasse des fichiers ; cela ne protege pas contre qui peut **executer** du code en root, qui n'a qu'a appeler `systemd-creds` comme nous, ni contre qui lit la memoire du processus. C'est la meme limite que DPAPI en portee machine, et `systemd-creds` la dit lui-meme quand `/var/` n'est pas sur un support chiffre - cet avertissement est laisse visible.

Et il en coute quelque chose que personne ne dit : la cle appartient a **cette** machine. Une reinitialisation du TPM, un changement de carte mere, une reinstallation qui refait `/var/lib/systemd/credential.secret`, et le profil scelle devient illisible, definitivement. Le billet de Tailscale sur le meme mecanisme n'aborde ni la reinitialisation du TPM ni la migration ; le sujet merite mieux que le silence quand le fichier peut etre l'unique copie d'une cle privee, alors `sceller` le dit a haute voix, au moment ou la decision se prend et pas dans une documentation que personne ne relit avant de supprimer le clair.

### Le daemon detient le profil

Le dechiffrement exige le TPM, donc root, et le client ne l'est pas. **C'est desormais le daemon qui ouvre le profil**, et le verbe d'IPC qui le demande ne transporte **aucun chemin** : le daemon tourne en root, et lui faire lire un fichier que l'appelant designe ferait de lui un depute confus. Le profil vient de sa propre ligne de commande, comme le reste de sa configuration.

Le verbe est distinct de `connect` plutot qu'un champ optionnel dedans, parce que les deux ne demandent pas la meme chose : `connect` porte un profil que l'appelant a lu, il en connait donc les secrets ; celui-ci demande au daemon d'ouvrir le sien, que l'appelant peut ne pas savoir lire. La consequence est le point entier - **un membre du groupe gagne le droit de se connecter sans gagner celui de lire la cle**.

**Le plan disait `LoadCredentialEncrypted=` ; la mesure dit non.** Ce mecanisme dechiffre **une fois, au demarrage du service**, dans un tmpfs en lecture seule et non swappable, et il n'existe aucun rechargement a chaud : changer de profil imposerait de redemarrer l'unite, donc de laisser tomber le tunnel et de rearmer le kill switch, pour ce qui est un reglage que l'utilisateur modifie. Les trois references du domaine convergent d'ailleurs ailleurs : `wg-quick` s'en remet aux droits du fichier, Mullvad garde `/etc/mullvad-vpn` en `0700` root avec un `settings.json` en clair que le daemon possede, et Tailscale garde `tailscaled.state` en `0600` possede par le daemon, avec un scellement TPM en option (`--encrypt-state`, alpha en 1.86). Le daemon possede le profil, les droits sont la ligne de base, le chiffrement est une option - et le dechiffrement se fait a la demande, sur un fil bloquant pour ne pas figer la boucle qui sert toutes les connexions IPC.

### La moitie Windows du coffre

Elle passe par DPAPI, comme le plan le demandait - mais **pas en portee machine**, et c'est une correction de fond. La documentation de `CryptProtectData` est explicite sur ce que fait `CRYPTPROTECT_LOCAL_MACHINE` : n'importe quel utilisateur de la machine peut alors dechiffrer. Ce n'est pas un effet de bord, c'est sa raison d'etre - et cela viderait le coffre de sa moitie utile. Sous Linux il faut etre root pour ouvrir un profil scelle ; la portee machine le rendrait ouvrable par le premier compte venu, ce qui protege du vol du disque mais plus de rien contre qui est deja sur la machine, alors que c'est precisement la ou le profil vit.

**La reference que le plan cite lui-meme le contredit.** WireGuard pour Windows n'utilise pas la portee machine : son service chiffre chaque configuration dans son propre contexte - celui de Local System - avec `CRYPTPROTECT_UI_FORBIDDEN` et rien d'autre, puis verifie au dechiffrement le nom qui accompagne le chiffre. C'est ce qui est fait ici, et l'equivalence avec Linux devient exacte : root la-bas, SYSTEM ici. Le nom verifie apporte la meme propriete d'integrite que `systemd-creds` - une recette glisse un chiffre parfaitement valide produit sous un autre nom, et mesure qu'il est refuse.

DPAPI-NG (`NCryptProtectSecret` avec un descripteur `SID=S-1-5-18`) a ete envisage : plus explicite, mais il repose sur le service de distribution de cles, pense pour un domaine, et n'apporte rien sur une machine autonome - le cas d'un poste client VPN.

Et il en coute la meme chose qu'ailleurs, en pire d'un cran : Microsoft documente que la **reinitialisation du mot de passe par un administrateur** rend les donnees DPAPI indechiffrables. Un domaine garde des cles de secours sur ses controleurs ; une machine autonome n'en a aucune. `sceller` le dit, avec les mots de la plateforme.

### Et pendant qu'on y etait : qui possede le repertoire

Le controle qui refuse un repertoire ou d'autres peuvent ecrire etait un `Ok(())` sous Windows, au motif que le durcissement de `C:\ProgramData\Bifrost` appartenait a l'installateur. Il n'y a pas d'installateur, et la mesure du jour donne le prix de cette hypothese : `C:\ProgramData` porte une ACE `CREATOR OWNER` en controle total heritee par ses enfants, si bien qu'un repertoire cree la par un utilisateur **ordinaire**, sans elevation, lui appartient. `C:\ProgramData\Bifrost` n'existait pas : le premier a le creer le possede, attend qu'un administrateur y installe un profil, et le remplace par le sien - le tunnel monte alors vers son serveur, sans qu'aucun secret n'ait jamais ete lu. C'est la mecanique de [CVE-2026-35603](https://cymulate.com/blog/cve-2026-35603-ai-coding-tools-privilege-escalation/), ou quatre outils de developpement chargeaient leur configuration depuis un sous-repertoire de `ProgramData` que personne n'avait cree ni restreint. Le scellement ne rattrape pas cela : le proprietaire peut supprimer le fichier scelle et laisser un clair a la place.

Ce qui est verifie est donc le **proprietaire**, et non la liste de controle - parce que le proprietaire d'un objet detient implicitement `WRITE_DAC` quoi que dise la liste : sur un repertoire possede par un tiers, une liste parfaite ne protege de rien, il la reecrit quand il veut. Comparaison par SID et jamais par nom, la machine de mesure etant en allemand (`VORDEFINIERT\Benutzer`, `NT-AUTORITAT\SYSTEM`) : les noms sont traduits, les SID non.

Reste une chose hors de portee, qu'il vaut mieux dire que taire : un profil **en clair** dans `C:\ProgramData\Bifrost` est lisible par tous les comptes de la machine, par une ACE `Users` heritee. Le refuser serait refuser toute installation par defaut ; la reponse est de le sceller, ce que l'ouverture conseille deja et que ce lot rend enfin possible des deux cotes.

## D'ou vient un profil

Le rangement au repos protege un profil une fois qu'il est la. Reste la question d'avant : **qui l'a emis**.

Elle n'est pas resolue par le transport, et c'est le piege. REALITY verifie la cle publique du serveur, WireGuard verifie son pair - mais ils verifient le serveur **que le profil nomme**. Ils ne disent rien du choix de ce serveur. Un profil fabrique par un tiers monte donc un tunnel parfaitement chiffre vers ce tiers, sans qu'aucune verification n'echoue nulle part. C'est la meme faille que le repertoire trop ouvert, un cran plus tot : la ou celle-la laissait *remplacer* un profil range, celle-ci laisse en *installer* un faux.

Et elle s'aggrave a chaque canal. Le plan en veut trois - subscription CDN, miroir GitHub raw, bot Telegram - donc trois points d'injection. **La signature est ce qui rend un canal hostile acceptable** : sans elle, ajouter des canaux augmente la surface d'attaque ; avec elle, chaque canal supplementaire est gratuit. Elle vient donc avant le multi-canal, et non apres.

```bash
bifrost profil installer profil-recu.toml
```

La commande verifie la signature `profil-recu.toml.minisig` contre la cle publique de confiance rangee a cote de la destination, puis met le profil en place en `0600`. Rien n'est ecrit avant que la signature ne soit acceptee.

### Minisign, et pas TUF ni Sigstore

Le format est **minisign**, en mode prehache uniquement : Ed25519, une specification tenant en une page, et une verification sans aucune dependance (`minisign-verify`, MIT, de l'auteur de libsodium). Le format herite est refuse, comme la specification amont le demande aux nouvelles implementations - et ce refus est **mesure**, pas declare : `minisign -l` produit encore de l'herite, et une recette d'interoperabilite le lui fait produire pour verifier qu'il est rejete. La meme recette verifie que ce que signe le vrai binaire est accepte par notre code, ce que les recettes internes ne peuvent pas dire puisqu'elles signent avec la bibliotheque.

`docs/06` recommandait TUF pour le canal du daemon. TUF resout la delegation de roles et la rotation en ligne dans un depot de paquets ; ici il y a un fichier et une seule autorite, et l'anti-rejeu se reduit alors a un compteur monotone. Son implementation Rust, `tough`, a d'ailleurs porte CVE-2025-2885 : une validation manquante du numero de version des metadonnees racine, c'est-a-dire un defaut sur le point meme que le cadre existe pour proteger. Sigstore se disqualifie autrement : la verification sans reseau exige un bundle et une infrastructure miroir, l'amont deconseille de figer les URL de ses instances Rekor d'une annee sur l'autre, et le mode keyless lie le signataire a un fournisseur OIDC. Un client anti-censure doit pouvoir verifier **hors ligne** un fichier ramasse n'importe ou, et son signataire est souvent pseudonyme.

La reference deployee est **Psiphon**, depuis quinze ans : liste de serveurs signee, cle publique de verification dans la configuration du client, telechargement bascule entre plusieurs URL racines. C'est l'architecture du plan, avec la signature comme fondation. **Tor** a retire son API `moat` en 2024 au profit de Telegram et des reglages geolocalises, et ses bridge lines portent l'empreinte de la cle du bridge : la aussi, ce qui vient d'un canal non fiable porte de quoi etre authentifie hors du canal.

### La cle de confiance est celle de l'utilisateur

Le plan supposait un editeur qui signe pour ses utilisateurs, avec une cle publique codee en dur. Bifrost est **auto-heberge** : l'utilisateur est l'operateur, il signe ses propres serveurs avec sa propre cle. Une cle codee en dur par nous n'aurait rien a authentifier - nous ne signons pas ses serveurs. Elle est donc un fichier, `confiance.pub`, installe une fois a cote du profil :

```bash
minisign -G -p confiance.pub -s signature.key     # sur la machine qui signe
minisign -S -s signature.key -t "serie=1" -m tunnel.toml
```

Cela ne l'affaiblit pas : ce fichier vit dans le repertoire du profil, dont le rangement au repos exige deja qu'il ne soit pas modifiable par d'autres. Qui peut y remplacer la cle peut de toute facon y remplacer le profil. Ce que la signature protege, c'est le trajet **avant** l'installation.

### Le rejeu, et la retrogradation silencieuse

`serie=N` dans le commentaire de confiance - la partie du fichier de signature qui est couverte par la signature - ordonne les profils. Un profil de serie inferieure ou egale a celui qui est installe est refuse : il ne le remplace pas, il le rejoue, et rejouer un profil dont le serveur est brule ou passe a l'adversaire est exactement l'attaque. L'horodatage que minisign ecrit tout seul aurait pu servir de defaut, et il est ecarte : resigner le *meme* profil le change, alors que "ceci remplace cela" est une decision, pas un effet de bord de l'heure de signature.

Le cas qui compte est le second : **retirer `serie=` d'un profil deja numerote est traite comme un recul**. Sans cette regle, l'anti-rejeu se contournerait en omettant un champ, et une protection qu'on desarme en omettant un champ n'en est pas une. La commande dit d'ailleurs a haute voix quand un profil ne declare aucune serie, parce que l'absence est silencieuse autrement, et qu'une protection qu'on croit avoir est pire que pas de protection.

### La ou la signature n'intervient pas

A l'ouverture d'un profil deja installe. Un administrateur qui ecrit ses trois lignes dans un editeur doit rester servi, et exiger une signature a chaque ouverture obligerait tout le monde a signer pour se connecter. Le plan parle du *bootstrap*, c'est-a-dire du moment ou le profil vient d'ailleurs ; une fois installe, c'est le rangement au repos qui prend le relais.

## Les criteres d'echec en cours de session

Un tunnel peut monter parfaitement et cesser de servir dix secondes plus tard. Le document 04 nomme deux facons, et les attribue toutes deux a un censeur : le **gel apres 16-20 Ko** dans une meme connexion TCP, signature du TSPU russe - le "rideau de 16 kilooctets" pose sur Cloudflare en juin 2025 - et l'**effondrement du debit**, throttling plutot que blocage franc, mesure a 2 Kb/s sur SSH. La couche de selection les typait depuis le debut ; personne ne les regardait. Les nommer n'est pas les voir.

**L'etat de l'art a corrige le plan sur un point de fond.** Le plan decrit ces criteres comme des observations d'un flux vivant. Ils ne peuvent pas l'etre entierement : **un tunnel inactif et un tunnel gele sont indiscernables de l'exterieur**. Dans les deux cas plus rien n'arrive, et une session SSH ouverte et silencieuse produit exactement la trace d'une connexion coupee par un DPI. Aucune quantite de comptage ne leve l'ambiguite, parce que l'information manquante n'est pas dans les compteurs : elle est chez le pair, et il faut la lui **demander**.

C'est ce que fait Psiphon, et sa forme est reprise telle quelle plutot que reinventee : une inactivite mesuree **en lecture** et non en echange ; une sonde aller-retour envoyee seulement au-dela de 10 s de silence, de sorte qu'un tunnel qui coule n'est jamais sonde ; une cadence **tiree au sort** entre 1 et 2 minutes, avec en commentaire amont la meme raison que le plan donne en d'autres termes - "ne pas emettre de motif de bascule regulier" ; un budget de 5 s pour la sonde de diagnostic. Ces quatre valeurs viennent d'un client deploye a grande echelle dans les pays qui nous interessent, ce qui vaut mieux qu'un nombre choisi ici.

**Le `urltest` de sing-box ne peut pas repondre**, et pas seulement pour la raison que le plan donnait. Sa cible par defaut est `generate_204`, dont le corps fait **zero octet** : une sonde qui ne transfere rien ne verra jamais un rideau qui tombe a 16 Ko. Et son intervalle est fixe a 3 minutes, donc regulier, donc un motif.

L'observateur est pur et vit avec le reste de la politique ; le superviseur du daemon lui verse les compteurs du tunnel a chaque sondage, au rythme deja en place, sans un reveil de plus. Trois etats se distinguent alors sans ambiguite : le tunnel recoit, et on ne regarde que le debit ; il ne recoit plus et on ne lui a rien demande, et **on ne conclut rien** - c'est le cas ou le plan aurait conclu a tort ; il ne recoit plus et une sonde n'est pas revenue, et le nombre d'octets recus au moment ou il s'est tu dit lequel des trois modes c'etait.

Deux garde-fous que la falsification a valides : un lien lent **depuis toujours** n'est pas un lien etrangle - le condamner ferait changer de technique en boucle sur une 3G faible - et un debit tombe **a zero** est un silence, pas un throttling, donc il passe par la sonde. Et seules les deux signatures que le document 04 attribue a un censeur vont au carnet : une coupure ordinaire, serveur qui redemarre ou Wi-Fi qui saute, ecarterait sinon la technique du prochain essai pour une raison qui n'a rien a voir avec elle.

**Ce qui conclut aujourd'hui, et ce qui attend.** Le critere de debit est vivant : il ne demande rien au pair, il se lit entierement dans les compteurs. Celui de gel attend la sonde, que ce daemon ne sait pas encore emettre - le fil du superviseur est synchrone et n'a pas de handle de runtime, alors que les deux sondes possibles sont asynchrones. La tentation serait de repondre avec `last_handshake`, qui est sous la main : pour WireGuard il dit vrai, mais pour un chemin par coeur il est **fabrique**, faute de poignee de main periodique, et il repondrait toujours "le pair est vivant". Une reponse toujours positive est pire que pas de reponse : elle a l'air d'une mesure.

Restent a ecrire, dans cet ordre :

1. La sonde aller-retour ci-dessus, qui rendra le critere de gel concluant.
2. Les deux sondes manquantes, QUIC et MITM TLS. La seconde ne peut pas se contenter de regarder des tailles : detecter une interception demande de VALIDER une chaine de certificats, donc une vraie pile TLS. Ce point etait bloque sur le fournisseur cryptographique ; il ne l'est plus, la pile etant desormais dans le depot.

## Le TUN sous Windows

Le chemin par coeur a besoin d'un TUN **generique**: une interface qui rend des paquets IP bruts, que le passeur traduit en connexions SOCKS5. WireGuardNT ne fait pas cela - il cree un adaptateur WireGuard, qui chiffre lui-meme avec ses propres cles. Il faut donc `wintun.dll`, une seconde bibliotheque.

### Le depot ne la distribue pas, il va la chercher

```bash
bifrost pilote recuperer
```

Un binaire tiers versionne est un binaire que personne ne relit, que rien ne date, et qui grossit l'historique a chaque mise a jour. L'archive vient donc de l'amont, et **son empreinte SHA-256 est epinglee dans le programme**: le reseau n'a plus a etre digne de confiance, puisqu'un miroir hostile ou une interception ne peuvent pas produire une archive qui corresponde. Une empreinte fausse d'un seul caractere fait refuser l'archive, et rien n'est ecrit.

**C'est le client qui telecharge, jamais le daemon** - et ce n'est pas un choix de confort: une recette le lui interdit deja, en refusant `ureq`, `reqwest`, `rustls` et le reste dans sa fermeture transitive. Le daemon tourne en SYSTEM avec un tube joignable; lui apprendre a parler au reseau ouvert lui ajouterait une surface qu'il n'a aucune raison d'avoir.

**Pas de verification Authenticode en plus, et il vaut mieux le dire que l'ecrire pour l'apparence.** L'empreinte fixe l'identite plus etroitement qu'une signature: elle designe un fichier, la signature en accepte tous ceux que la meme cle a signes. La mesure du jour le confirme d'ailleurs par un autre bout - le certificat de Wintun a **expire le 14 decembre 2021**, et la signature reste `Valid` par le seul effet de son horodatage. Une verification qui aurait regarde les dates aurait refuse le bon fichier.

L'extraction ne coute aucune dependance: `tar.exe`, livre avec Windows depuis 1803, lit un zip et en sort un seul membre. Et le membre est cherche par suffixe plutot que devine par prefixe, pour que la recuperation ne casse pas en silence le jour ou l'amont change la forme de son archive.

### La liaison

Quatorze points d'entree, releves sur la DLL elle-meme plutot que de memoire, tous resolus a la construction: un chargement partiel laisserait le daemon decouvrir un symbole manquant au milieu d'une montee de tunnel, kill switch deja arme. La DLL est chargee par **chemin absolu**, meme regle que `wireguard.dll` - un processus qui tourne en SYSTEM et charge une DLL par nom est un detournement en puissance.

Le mecanisme n'a rien de commun avec Linux. La-bas le TUN est un descripteur et lire un paquet est un `read`; ici c'est une paire d'anneaux en memoire partagee avec le pilote, on obtient un pointeur dedans et on le rend une fois recopie. **Rien ne bloque jamais**: l'anneau vide repond tout de suite, et `lire` rend alors `WouldBlock` - ce que rendrait un descripteur non bloquant sous Linux, ou il faut d'ailleurs le demander explicitement. La distinction porte le reste: une boucle qui prendrait l'anneau vide pour une panne fermerait le tunnel au premier silence du reseau.

Le contrat est le meme des deux cotes pour ce qui compte: un paquet plus grand que le tampon est **refuse et perdu, jamais tronque** - un paquet tronque remis a la pile serait pire qu'un paquet perdu. L'interface disparait avec sa structure. Et le GUID est fixe, comme du cote WireGuardNT: Windows attache le profil reseau, donc les regles du pare-feu, a l'identite de l'interface, et un GUID different a chaque montee ferait redecouvrir un reseau inconnu a chaque fois.

Le nom suit la regle Linux - quinze caracteres - alors que Windows en accepterait plus. La plus stricte gagne: un profil doit pouvoir passer d'une machine a l'autre sans devenir refusable.

### L'enveloppe asynchrone, et pourquoi elle differe

La pile veut lire et ecrire sans bloquer. Sous Linux, `AsyncFd` suffit: le systeme sait signaler la lisibilite d'un descripteur. **Wintun n'en rend aucun** - il rend une paire d'anneaux en memoire partagee et un evenement Windows. Rien dans `tokio` ne surveille un evenement Windows: sa couche d'entrees-sorties y passe par les ports d'achevement, que `mio` n'ouvre qu'aux sockets et aux tubes nommes.

**Un fil dedie, et pas `spawn_blocking`.** La documentation de `spawn_blocking` est explicite: elle est faite pour du travail **borne**, et chaque appel immobilise un fil du bassin pour toute sa duree. Une boucle de lecture de TUN dure autant que le tunnel; l'y mettre reduirait durablement la capacite du bassin au detriment de tout ce que le daemon y fait par ailleurs.

**Un canal plutot qu'un reveil de tache**, et c'est un echange assume. L'alternative fait moins de copies - le fil ne servirait que de sonneur, et la lecture se ferait dans l'anneau depuis la tache, ce qui ne bloque jamais. Mais elle demande une poignee de main entre le fil et la tache, parce que l'evenement reste declenche tant qu'il reste des paquets: sans elle le fil tournerait a vide. Le canal coute une allocation et une recopie par paquet, et rend la concurrence triviale - un fil qui produit, une tache qui consomme, `tokio` qui porte les reveils. Dans un produit de securite l'echange se fait dans ce sens, et c'est le meme raisonnement qui a fait prendre `ipstack` plutot qu'ecrire TCP a la main.

Le canal est **borne**: une pile qui n'avale plus fait remplir l'anneau, et le pilote jette - exactement ce qui arrive sous Linux quand le noyau ne peut plus mettre en file. Un canal sans borne remplacerait une perte de paquets par une consommation de memoire sans fin.

**L'arret est la partie qui compte.** L'amont ne promet nulle part que terminer la session libere un fil bloque dans l'attente, ni qu'il est sur de terminer une session pendant qu'un autre fil est dans `WintunReceivePacket`. On ne batit pas sur un silence: le fil attend **d'un seul appel** l'evenement de lecture et un evenement d'arret qui nous appartient, si bien que la deconnexion le reveille tout de suite; il est ensuite **rejoint**, et la session n'est terminee qu'apres. L'ordre inverse ne planterait pas tout de suite - il planterait un jour, en production, a la deconnexion.

Un seul endroit repasse au lieu d'attendre: l'anneau d'**emission** plein. Wintun ne publie d'evenement que pour la reception, il n'y a donc rien a surveiller; on rend la main a l'ordonnanceur en redemandant a etre repasse, ce qui laisse tourner tout le reste du daemon pendant que le pilote vide.

## Par quels chemins il arrive

Le plan veut trois canaux : subscription CDN, miroir GitHub raw, bot Telegram. La raison affichee est la disponibilite. Mais un multi-canal naif ne fait que **multiplier les points d'injection** - trois endroits d'ou peut venir un faux profil au lieu d'un seul. Ce qui renverse le compte, c'est la signature : elle deplace la confiance du canal vers la cle, et rend alors chaque canal supplementaire gratuit. L'ordre des deux lots n'etait pas interchangeable.

```bash
bifrost profil recuperer \
  --depuis https://cdn.exemple/tunnel.toml \
  --depuis https://raw.githubusercontent.com/exemple/miroir/main/tunnel.toml \
  --depuis /media/usb/tunnel.toml
```

Une adresse `http://`, `https://`, ou un chemin de fichier - une cle USB est un canal, et c'est le seul qui repond encore quand tout le reste est bloque. La commande n'ecrit rien en place : elle depose ce qu'elle a trouve et dit la commande `installer` a lancer ensuite.

### Deux decisions qui la distinguent d'un `telecharger le premier`

**Tous les canaux sont interroges, et la serie la plus haute gagne.** S'arreter au premier qui repond suffirait contre une panne, pas contre un adversaire : qui controle un canal n'aurait qu'a se placer en tete et servir un vieux profil authentique, dont le serveur est brule ou lui appartient desormais. En retenant la serie la plus haute de *tous* les canaux, il lui faut aussi faire taire les autres - c'est ce qui donne sa valeur au multi-canal contre quelqu'un, et pas seulement contre une panne.

**Un canal qui sert une mauvaise signature est ecarte, pas fatal.** Traiter une signature invalide comme une erreur laisserait un seul miroir empoisonne empecher toute mise a jour : un deni de service a un contre trois, sur le mecanisme meme cense y resister.

Le rapport distingue par ailleurs un canal **muet** d'un canal **suspect**, et la distinction n'est pas cosmetique : trois canaux muets, c'est un reseau qui filtre ; un canal suspect, c'est quelqu'un qui publie autre chose que vos profils. Le premier appelle a changer de chemin, le second a s'inquieter. Un canal suspect est signale meme quand la recuperation a reussi par ailleurs.

### Ce que le transport doit refuser

Un canal hostile n'a pas besoin de fabriquer une signature pour nuire. Il peut accepter la connexion et se taire, ou servir un corps sans fin. Sans **delai** ni **plafond de taille**, le premier ferait pendre la commande et le second grossir le processus jusqu'a sa mort - les deux defauts qu'un `telecharger l'adresse` naif laisse ouverts. Un profil de tunnel tient en deux kilo-octets ; soixante-quatre sont acceptes, et les atteindre est en soi le signe que quelque chose ne va pas.

Un canal en `http://` est accepte et **signale** : la signature protege l'authenticite quel que soit le transport, mais pas le secret du contenu - un observateur apprend quels serveurs vous utilisez, donc lesquels bloquer. En situation de censure, le canal en clair est parfois le seul qui passe ; c'est un echange que l'utilisateur doit voir.

### Le HTTP n'entre pas dans le daemon

Le daemon tourne en root, en permanence, avec un socket que d'autres peuvent joindre. La recuperation parle a des serveurs qui ne sont pas les notres. Les reunir ferait qu'un defaut dans un analyseur HTTP ou TLS deviendrait une compromission racine permanente - c'est le raisonnement deja applique au compte `bifrost-coeur`. La recuperation vit donc dans une caisse a part, dont **seul le client depend**, et une recette le mesure : un `bifrost-amorce.workspace = true` ajoute par distraction au manifeste du daemon ne casserait rien et ne se verrait nulle part, alors elle tombe avant la revue. C'est la signature qui rend cette separation tenable : le profil recupere etant authentifie par une cle, son transport n'a besoin d'aucun privilege.

### La pile TLS, et une affirmation du handoff corrigee

`ureq` avec rustls et **aws-lc-rs** - le fournisseur par defaut de rustls depuis que `ring` porte [RUSTSEC-2025-0007](https://rustsec.org/advisories/RUSTSEC-2025-0007.html) (non maintenu, repris par l'equipe rustls pour la seule securite). Le handoff affirmait que `ring` et `aws-lc-rs` exigent `nasm` et `cmake`, absents des machines de dev, et que cela bloquait aussi la sonde MITM TLS. **Mesure le 19 aout 2026 : c'est faux.** aws-lc-rs se construit sur dev-windows, qui n'a ni l'un ni l'autre, en une minute, et une requete HTTPS reelle aboutit sur les deux plateformes. Le blocage etait perime.

Le mimetisme d'empreinte TLS (JA3/JA4) reste un cran au-dessus : `wreq` le fait, au prix de BoringSSL, donc de `cmake` et de Go dans la chaine de construction. Il n'est pas pris. aws-lc-rs porte en revanche les echanges de cles post-quantiques, ce qui en 2026 rapproche notre ClientHello du trafic courant plutot que de l'en eloigner.

### Le canal qui passe par une personne

Le plan veut un bot Telegram et cite Tor en exemple. La citation est exacte, le mecanisme ne l'est pas : **Tor Browser n'interroge jamais Telegram**. Sa documentation decrit quatre gestes, tous humains - ecrire a `@GetBridgesBot` depuis son application, taper `/webtunnel`, copier les adresses, les coller dans le navigateur.

La difference decide de tout. Ce qui fait passer Telegram la ou le reste est bloque, c'est l'application : ses proxys MTProto, et la mise a jour d'avril 2026 qui deguise son trafic en trafic de navigateur. Un programme qui ferait un `GET` sur `api.telegram.org` n'heriterait d'aucun de ces contournements ; il serait aussi bloquable que n'importe quel domaine, et en pire, celui-la etant nommement cible - au 10 avril 2026, [95 % des connexions Telegram echouent en Russie sans VPN](https://www.osw.waw.pl/en/publikacje/analyses/2026-04-17/russia-blocks-telegram-and-cracks-down-vpns). Ecrire ce client aurait ajoute une dependance a une API a jeton pour un canal **moins** resistant qu'un miroir HTTPS quelconque.

Ce qui manquait n'etait donc pas un client d'API, mais le chemin par lequel une personne fait entrer un profil recu n'importe ou :

```bash
bifrost profil partager tunnel.toml          # cote operateur : une chaine a transmettre
bifrost profil recuperer --depuis "bifrost1..."   # cote destinataire
```

Une chaine unique, en base64url sans remplissage - ni `+`, ni `/`, ni `=` que les URL et les messageries transforment - et tout espace blanc est ignore a la lecture, parce qu'une messagerie replie une chaine de huit cents caracteres et que l'utilisateur qui recopie ajoute des espaces. Elle sert Telegram exactement comme Tor s'en sert, et sert aussi Signal, un courriel, un QR code, un SMS. Le prefixe porte un **numero de version** : un format qu'on colle traine dans des messages et des captures d'ecran, et le jour ou il faudra en changer, un lien de l'ancien monde doit etre refuse en le disant plutot que mal interprete.

**Un lien nu est signe, pas chiffre.** La signature protege son authenticite quel que soit le chemin parcouru - c'est tout l'interet. Mais le profil y est en base64, c'est-a-dire *encode et non chiffre* : le base64 a l'apparence du secret sans en avoir l'effet. Et ce qui fuit alors n'est pas d'abord la cle privee, c'est **l'adresse du serveur** - un lien intercepte brule le serveur, ce qui est exactement le dommage que ce produit existe pour eviter. La commande le dit avant d'imprimer le lien, et non apres : ce qui suit un mur de huit cents caracteres ne se lit pas.

### Le lien chiffre

C'est la seconde moitie du "signes **et chiffres**" du plan, qui ne disait pas comment.

```bash
bifrost profil partager tunnel.toml --chiffrer
```

La phrase de passe sort sur la sortie d'erreur, le lien sur la sortie standard - on peut donc rediriger le lien sans emporter la phrase avec lui. Elle est **engendree par le programme, jamais tapee par une personne** : une phrase choisie par un humain, dans un produit ou l'adversaire peut etre un Etat, ne vaut pas le scrypt qui la protege. Vingt-quatre caracteres de base32 Crockford - ni `I`, ni `L`, ni `O`, ni `U`, qui se confondent quand on dicte au telephone - soit 120 bits, bien au-dela de ce que le facteur de travail aurait a rattraper.

La seule consigne qui compte accompagne la phrase : **la transmettre par un autre chemin que le lien**. Dans la meme conversation, elle ne protege de rien. Et la reciproque est signalee aussi : donner une phrase alors qu'aucun canal ne porte de lien chiffre declenche un avertissement, parce que croire avoir recu un lien protege quand il ne l'etait pas est un malentendu qui ne se rattrape plus - le lien est deja parti en clair.

**Signer puis chiffrer, dans cet ordre.** C'est le lien signe entier qui est chiffre. Une signature posee sur du chiffre n'authentifierait que le chiffre et ne dirait rien du profil ; ici, ce qui sort du dechiffrement *est* le lien nu, que le reste de la chaine sait deja verifier et installer sans rien changer. La faiblesse connue de cet ordre - le renvoi subreptice, ou un destinataire rechiffre pour un tiers - ne mene nulle part ici : le profil reste celui du meme operateur, signe par lui.

Le format est `age-encryption.org/v1` avec un destinataire scrypt, donc sans echange prealable de cles. Ce choix garde la porte ouverte : `age` accepte plusieurs types de destinataires dans un meme fichier, donc chiffrer un jour pour une cle publique X25519 du destinataire n'obligera pas a changer le format du lien.

Derouler ce chemin a la main a trouve un defaut que les recettes n'avaient pas vu : replie par une messagerie, le lien arrive avec des espaces en tete, echappait a la reconnaissance de son prefixe, passait pour un chemin de fichier - et le rapport imprimait alors **le lien entier, cle privee encodee comprise**. La reconnaissance ebarbe desormais la designation, et le rapport abrege tout nom de canal au-dela de cent caracteres, pour tous les canaux y compris ceux qui n'existent pas encore.

## Prochaines etapes

La liste tenue a jour est dans [`ETAT.md`](ETAT.md), avec pour chaque chantier ouvert une prochaine action nommee. En resume : du document 03, la couche DNS est livree et il reste ses couches Windows, registre et WFP par service ; puis la suite de l'objectif 2. L'audit de dependances demande par le document 07 est cable.

Signaler une faille de securite : voir [`SECURITY.md`](SECURITY.md). Le `packaging/security.txt` (RFC 9116) est servi par le site de l'editeur.
