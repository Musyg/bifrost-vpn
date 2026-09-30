# Etat de Bifrost

Bifrost est un VPN auto-heberge pour Windows 11 et Linux. Trois objectifs, dans
cet ordre: ne pas fuir (kill switch de niveau noyau, fail-closed), ne pas etre
bloque (resistance active au DPI et a la censure), ne pas laisser le systeme
d'exploitation parler (blocage de la telemetrie avant le tunnel). Le MVP de
l'objectif 1 est implemente; l'objectif 2 avance; l'objectif 3 est au stade de
la conception. Daemon et CLI, pas d'interface graphique.

Cette page tient sur un ecran et se met a jour a chaque tranche. Ce qui est
mesure et ce qui ne l'est pas est detaille dans le README et dans les documents
du plan `docs/01..07` et `docs/09`. La suite de fuite couvre dix vecteurs; le compte des
recettes cargo est pris par `scripts/recettes-strict.sh`, jamais par le compte
de `cargo test`, qui presente comme verte une recette abstenue.

Chaque mesure nomme l'hote qui l'a produite. Les hotes sont designes par leur
role: `dev-windows` (Windows 10 build 19045, ou vit et compile le depot),
`essai-linux` (Ubuntu 24.04, chaine outillee cargo-deny et cargo-audit) et
`essai-windows` (Windows 11, session de mesure sans chaine Rust).

## Comptes de recettes

La CI automatique couvre Linux; Windows est lance uniquement sur demande
(`workflow_dispatch`, option `windows=true`) pour maitriser le quota. Un job
Windows saute n'atteste rien sur cette plateforme. Voir le README pour le
lancement avant une livraison Windows et la revision effectivement mesuree.
Les etapes des jobs `controles` et `fuite` tournent sous `bash -eo pipefail`
depuis le 30/09/2026 (`defaults.run.shell: bash`): avant, le shell implicite
`bash -e` rendait le code du dernier element d'un tube, et
`recettes-strict.sh | tee` restait vert quand une recette rougissait. La recette
`tubes_sous_pipefail.rs` exige `shell: bash` de toute etape qui porte un tube.

Les comptes ci-dessous ont ete pris le 30/09/2026 sur l'arbre qui porte le
portage des corrections du tableau de survie et des abstentions, puis D1b.3b,
l'identite du serveur de D1b.3c, sa verification par toutes les commandes de
la CLI, la correction du permis DNS Windows par famille, la garde des tubes
sous pipefail, la preuve WFP par declaration, le retrait de CAP_SYS_ADMIN du
service, les litteraux abimes par un transport d'antislashs et le trou FF
de la garde des abstentions, la comparaison des objets nft nommes, puis la
garde sans privilege du contrat de `check` sans banc et des drop-ins de l'unite, puis l'isolement des executions concurrentes
d'une meme suite (repertoires temporaires par processus, ports sans personne
tenus), puis la preuve des regles de routage et des routes (D1c.1), puis le refus des tables de routage que le noyau se reserve, puis le demontage exact du routage, puis l'identification du proprietaire des ecoutes de boucle locale du chemin par coeur, puis le rafraichissement du tableau de survie au 30/09/2026, puis la preuve du routage face au daemon (D1c.2), puis la fermeture du :53 du LAN sous `allow_lan`. L'hote qui tient le role `essai-linux` a change le 29/09: ses comptes ne se comparent pas a ceux d'avant cette date.

Compte honnete des recettes cargo, par hote. La colonne `reelles` est ce qui a
verifie quelque chose: `annoncees` moins `abstentions` moins `rouges`.

| Hote | Annoncees | Abstentions | Rouges | Reelles |
|---|---|---|---|---|
| dev-windows | 1470 | 19 | 0 | 1451 |
| essai-linux | 1533 | 25 | 0 | 1508 |

Les deux lignes ont ete prises par `scripts/recettes-strict.sh`, chacune sur son
hote: le portage a ajoute 14 recettes des deux cotes, D1b.3b 11 sur dev-windows et 22
sur `essai-linux`, D1b.3c (identite du serveur de la declaration) 4 sur
dev-windows et 5 sur `essai-linux`, la verification du serveur par les commandes
9 sur dev-windows et 7 sur `essai-linux`, le permis DNS par famille 8 sur
dev-windows et 6 sur `essai-linux` (ses deux recettes de traduction sont devenues pures avec la preuve WFP et
tournent sur les deux hotes), la garde des tubes sous pipefail 6 des deux
cotes, la preuve WFP par declaration 51 sur dev-windows et 48 sur
`essai-linux`, le retrait de CAP_SYS_ADMIN du service 7 sur dev-windows et 13 sur
`essai-linux` (les gardes de l'unite tournent sur les deux hotes; le refus
nomme du harnais et la relecture des captures sont propres a Linux), la garde des antislashs
manges 2 des deux cotes, la
comparaison des objets nft nommes 7 sur dev-windows et 8 sur `essai-linux` (la
recette face au faux daemon est propre a Linux), la garde du contrat de `check`
sans banc et des drop-ins de l'unite 7 sur dev-windows et 10 sur `essai-linux`
(chaque raison reelle de ne pas monter le banc, la lecture du masque effectif et
`linux::run_all()` sous un compte ordinaire sont propres a Linux), l'isolement
des executions concurrentes 4 des deux cotes (la recette du port sans personne
que personne ne peut prendre, et les trois recettes de la garde
`partage_entre_executions.rs`), la preuve des regles de routage et des routes
34 sur dev-windows et 36 sur `essai-linux` (la lecture du noyau et la pose du chemin
par coeur sont propres a Linux, le constat hors Linux a Windows), le refus des tables
de routage reservees au noyau 12 sur dev-windows et 13 sur `essai-linux` (la
comparaison aux constantes de libc est propre a Linux), le demontage exact du routage
19 sur dev-windows et 24 sur `essai-linux` (la lecture du noyau avant la pose, le
proprietaire de l'interface et le refus rendu par `down` sont propres a Linux), l'identification du proprietaire des ecoutes de boucle locale du chemin par coeur 16 sur dev-windows et 38 sur `essai-linux` (la lecture de `/proc`, le chemin par le compte dedie et le refus de `SO_REUSEPORT` par la facade sont propres a Linux, la table des ecoutes et l'ecoute large a cote du coeur a Windows), le rafraichissement du tableau de survie 3 sur chaque hote, la preuve du routage face au daemon 10 sur dev-windows et 20 sur `essai-linux` (le faux daemon sur socket Unix qui eprouve le protocole et l'analyse stricte est propre a Linux), la fermeture du :53 du LAN sous `allow_lan` 1 sur dev-windows et 4 sur `essai-linux` (les recettes du rendu nft sont propres a Linux, celle de la reference de `prove nft` tourne sur les deux hotes). Sur `essai-linux` une recette de plus est ignoree par
construction (elle pose une route et ne tourne qu'en espace de noms reseau).
La ligne `essai-linux` a ete prise dans un clone, ou la garde des modes de
scripts mesure (elle lit l'index); dans une copie sans `.git` elle s'abstient,
d'ou les 26 abstentions des comptes precedents.

## Ce qui est ouvert, document par document

Les documents du plan `docs/01..07` et `docs/09`, leur etat et, pour un chantier ouvert,
la prochaine action. Une cellule vide signalerait une tranche non finie.

| Chantier | Etat et derniere mesure | Prochaine action |
|---|---|---|
| 01 | Architecture technique. Cadre du plan, redige; ce n'est pas un livrable | - |
| 02 | Kill switch WFP et nftables. Specification de reference, a jour. 30/09/2026: le permis DNS Windows ne se pose plus que sur la couche de la famille du resolveur, et la traduction refuse une condition inapplicable a sa couche au lieu de l'ecarter (elle compte les conditions posees). Mesure sur essai-windows avant (filtre sans adresse sur l'autre couche; resolveur `::1`, une requete DNS IPv4 vers un resolveur public obtenait sa reponse, kill switch arme) et apres (un seul permis, l'autre famille refusee par `block-dns`). La fuite IPv6 hors LAN reste inferee: pas d'IPv6 globale sur le site. 30/09/2026 aussi: une `routing_table` que le noyau se reserve (0, 253, 254, 255) est refusee a la validation, et la pose comme le demontage WireGuard la refusent sans rien emettre quand la validation n'a pas eu lieu. Mesure avant, en namespace jetable par `LinuxTunnel::up` et `down`: une tentative de connexion en 254 vidait `main`, en 0 toutes les tables; un demontage en 255 vidait `local`, en 253 `default`. Apres: refus nomme, etat du namespace identique. 30/09/2026 encore: le demontage du routage Linux ne retire plus que ce qui porte l'etiquette du produit et repond a ses propres commandes de pose. Chaque regle et chaque route qu'il pose porte cette etiquette (`protocol 177` sur une regle, `proto 177` sur une route), chaque retrait designe exactement l'une d'elles, et aucune table n'est plus videe; un objet qu'un tiers poserait avec la meme etiquette n'en est pas distingue. Avant la premiere commande, le produit lit les regles et les routes des deux familles et refuse en le nommant, sans rien poser ni retirer, une table ou une marque qu'un tiers sans cette etiquette emploie (les valeurs par defaut, 51820, sont celles de wg-quick), et une interface du nom du profil qui n'est pas la sienne (autre cle, ou autre type). Mesure avant, en namespace jetable par `LinuxTunnel::up` et `down` et par l'aiguillage du coeur: un tiers de la forme de wg-quick dans la meme table perdait sa route et ses regles des la tentative de connexion, un tiers pose apres le produit perdait ses regles a la place de celles du produit, un tiers aux priorites du coeur perdait les siennes, l'interface d'un tiers qui portait le nom du profil etait supprimee. Apres: quatorze cas, deux chemins, deux familles, le tiers intact dans chaque ordre, et l'etat initial exact sur une table libre (`banc-demontage-routage-linux.sh`, aussi en CI). 30/09/2026 enfin: sous `allow_lan`, le :53 vers le LAN hors resolveur declare tombe avant l'acceptation du LAN, dans les deux familles, en UDP comme en TCP, comme sous Windows ou `block-dns` (14) pese plus que `permit-lan` (11). Mesure avant, en namespaces jetables sur essai-linux, rendu du produit, LAN ouvert, resolveur de boucle locale: un repondeur DNS du lien recevait les huit requetes :53 envoyees (IPv4, IPv6 unique-locale, lien local; UDP et TCP). Apres: aucune; le resolveur declare sur le lien toujours servi (IPv4 puis IPv6), un port hors DNS du lien toujours joint, le DNS par le tunnel servi. La reference de `prove nft` porte les memes regles (64 politiques confrontees au rendu applique, dont 32 LAN ouvert), et `dns-leak` mesure aussi le :53 vers le lien sous LAN ouvert, derriere deux temoins. | - |
| 03 | Anti-telemetrie OS. Couche DNS livree; couches Windows registre et WFP par service a finir | Finir les couches Windows registre et WFP par service |
| 04 | Anti-censure DPI. Tableau de survie rafraichi le 30/09/2026 (Hysteria2/Iran Mort -> Incertain, AmneziaWG/Russie redatee 2026-08; aucune source turkmene posterieure a juillet); inerte depuis le 30/09/2026 (`TABLEAU_INERTE_A_PARTIR_DU`, gardee par `selection::planifier`): il n'ecarte plus rien et, a environnement et memoire egaux, son classement est fige: aucun plan ne bouge plus tant qu'aucun statut ne change ni qu'aucune cellule Mort n'est redatee | Chercher des sources, en priorite au Turkmenistan: aucune n'y mesure REALITY, XHTTP-CDN, Hysteria2 ni WireGuard nu depuis leurs cellules; ntc.party n'est lisible que par IPv6 |
| 05 | Anonymat et chainage. Document redige; le chainage Tor et Nym n'est pas commence, et le document lui-meme le place apres les trois objectifs | Chainage Tor ou Nym, apres les objectifs 1 a 3 |
| 06 | Architecture logicielle et packaging. Daemon, IPC authentifie, machine a etats et scripts d'installation faits (Linux et Windows, comptes dedies, ACL). 30/09/2026: l'unite systemd ne donne plus CAP_SYS_ADMIN ni CAP_NET_RAW au service, garde `unite_systemd.rs`; daemon reel sous les seules capacites de l'unite, en namespace jetable (`e2e-linux.sh --unite`): toutes les fonctions VPN passent, `check` par le service rend neuf SKIPPED qui nomment CAP_SYS_ADMIN et `sudo bifrost-daemon --run-checks`, qui conclut hors du service. 30/09/2026 aussi: le chemin par coeur n'envoie le secret de l'API du coeur et le trafic qu'a une ecoute de boucle locale identifiee comme celle du coeur lance, au lancement et a chaque usage en session (sonde, bascule, facade); Windows par le PID de la table des ecoutes, Linux par les inodes quand les descripteurs du coeur sont lisibles, sinon par l'uid du socket contre le compte dedie. Mesure sous les seules capacites de l'unite, en namespace jetable: le coeur sous son compte est reconnu et la facade lui relaie le trafic; un squatteur d'un autre compte est refuse sans recevoir le secret, que le daemon lui envoyait avant. L'unite n'est pas mesuree sous systemd. Le contrat de `check` sans banc (chaque vecteur sauf `doh-bypass` rend SKIPPED avec sa raison, `doh-bypass` rend son verdict, aucun ne rend PASSED) est garde par des recettes sans privilege, `linux::run_all()` compris; les gardes de l'unite lisent aussi ses drop-ins livres, et ce que `install-linux.sh` pose, scripts sources ou lances compris. Ni interface graphique, ni MSI, ni .deb/.rpm, ni mise a jour TUF, ni provisioning; SBOM en CI | Mesurer l'unite sous systemd (`service-systemd-linux.sh`), puis `RestrictNamespaces=yes` et le retrait d'`AF_PACKET`; interface graphique en jalon propre apres J2; paquets signes et mise a jour TUF |
| 07 | Programme de securite produit. fmt, clippy, recettes, suite de fuite, cargo audit, cargo deny et SBOM en CI; politique de divulgation publiee (SECURITY.md, security.txt); inventaire unsafe ferme; cargo vet et fuzz absents, aucune cle PGP | Publier une cle PGP (champ Encryption); ajouter cargo vet et un harnais fuzz |
| 09 | Souverainete verifiable. D1a: `prove binaire`. D1b.1: comparaison nft hors ligne. D1b.2: collecte Linux passive encadree par GETGEN. D1b.3a: `prove nft --politique` engendre la reference produit depuis une intention v1 explicite; 64 combinaisons confrontees au rendu applique en banc jetable. D1b.3b: `prove nft --politique-daemon --actif` prend pour attendu la politique que le daemon declare avoir posee (requete IPC en lecture, relue avant et apres la collecte); daemon reel en banc jetable: correspondance, quatre alterations en ecart, droits retires et daemon arrete non mesures. D1b.3c (identite): le client exige un serveur root (SO_PEERCRED) avant de lire la declaration, sinon UNMEASURED daemon-identity; regle Windows (proprietaire du pipe LocalSystem) livree dans bifrost-ipc et exigee par `prove wfp`. D1b.3c (WFP): `prove wfp --politique-daemon --actif` confronte le moteur WFP a la politique que le daemon declare avoir posee, par le meme lecteur de declaration que `prove nft` (identite, N1, mesure, N2); projection WFP v1 distincte de la nft; reference rendue par la traduction de la pose; enumeration en lecture seule dans une transaction unique; arbitrage des filtres tiers au poids effectif rendu par le moteur; banc jetable Windows avant fusion: MATCH, trois alterations en ecart, verrou non mesure, puis MATCH apres reprise; apres fusion, un daemon en console elevee est refuse par la preuve (UNMEASURED daemon-identity) et admis par `status`. Toutes les commandes de la CLI verifient aussi le serveur avant d'ecrire (root; Windows LocalSystem ou Administrateurs), refus en code 4, rien envoye; un compte ordinaire refuse sans rien recevoir en banc jetable. D1b.3c (objets nft): set, map, flowtable, counter, quota, limit, ct helper, ct timeout, ct expectation et synproxy sont compares, elements de set et peripheriques de flowtable en ensemble, valeurs d'etat (compteurs, consommation des quotas, dernier passage, expiration) ignorees; un objet tiers est un ecart de sa categorie, en `--politique-daemon` aussi; secmark et tunnel restent non mesures. Avant, mesure en namespace jetable a cote du daemon reel: un seul de ces objets, dans n'importe quelle table, rendait les trois modes non mesures. Banc jetable: correspondance apres trafic, onze alterations en ecart de leur seule categorie, objet tiers en ecart face au daemon reel. D1c.1: `prove routes --intention --actif` confronte les regles de routage et les routes du noyau Linux (deux familles, toutes les tables, rtnetlink lu deux fois, sans privilege) au plan que le produit pose, desormais source unique de `netcfg::add_routing` et `aiguillage::poser` (commandes executees dans le meme ordre qu'avant; depuis le 30/09/2026 chacune porte l'etiquette du produit, que la preuve ne compare pas); ordre des regles, regles tierces avant le tunnel, table du tunnel et routes que `suppress_prefixlength 0` laisse passer sont compares, la legitimite par une regle ecrite, la route du tunnel doit etre utilisable (ni morte, ni sans porteuse, ni echue); banc jetable: correspondance des deux chemins en root et sans privilege, trente-six alterations en ecart de leurs seules categories, chaque type de route dans `main` et `local` confronte a un temoin d'emission, deux limites nommees et mesurees (adresse a masque large, multidiffusion IPv6 sur le lien), collecte pendant une bascule non mesuree. D1c.2: `prove routes --politique-daemon --actif` prend pour attendu le plan de routage que le peripherique du tunnel declare avoir pose (commande IPC distincte `declaration-routage`, six cles, meme lecteur que `prove nft`/`prove wfp`: identite, N1, mesure, N2), reconstruit au meme constructeur que le produit et confronte au noyau; le plan declare est une seconde evaluation de la meme fonction pure sur la meme configuration, retenue apres la derniere commande reussie, egale par construction au plan des commandes et non leur capture; l'etiquette du produit (`proto 177`) est exigee sur les objets du plan en mode daemon, ignoree en `--intention`; rien pose est dit sans comparer; sous Windows, non applicable nomme sans lecture, et `source: null` hors Linux; banc a cote d'un daemon reel (`e2e-linux.sh`): MATCH des deux familles, encore apres reprise, aucun plan apres deconnexion, hote inchange. Jumeau Windows (IP Helper) non livre. Ni preuve globale du VPN ni validation Windows | Relever la forme de secmark et tunnel nft (hote a module de securite a contextes, nft plus recent); prove wfp face au service reel sous LocalSystem, en banc; D1c: resolveurs effectifs et exceptions DNS, puis provenance |

## Scripts

Chaque banc et outil du depot, avec sa ligne d'usage. Un banc que personne ne
sait lancer n'est pas un banc.

Sous `scripts/`:

| Script | Usage |
|---|---|
| recettes-strict.sh | Compte honnete des recettes cargo (vertes, abstentions, rouges); `--strict` echoue aussi sur abstention |
| abstentions-budget.sh | Exige que chaque abstention de la CI figure dans la liste attendue du job |
| check-strict.sh | Exige que les dix vecteurs de fuite soient PASSED |
| preuve-nft-linux.sh | Collecte nft passive, ecart, refus de privileges, objets nft nommes (correspondance apres trafic, alterations en ecart de leur categorie) et confrontation a la declaration d'un daemon reel, faux daemon non root refuse, compteur non root que chaque commande refuse sans rien lui ecrire, dans des namespaces jetables (apres cargo build --workspace); sudo bash ./scripts/preuve-nft-linux.sh |
| preuve-routes-linux.sh | Regles de routage et routes: les commandes que le produit pose, appliquees dans un namespace jetable par cas, correspondent (root et sans privilege), chaque alteration donne un ecart de sa seule categorie, un temoin d'emission confirme ce que chaque type de route admis fait du trafic, une regle qui bascule pendant la collecte rend UNMEASURED, le rapport ne porte aucun identifiant (apres cargo build --workspace et cargo build -p bifrost-daemon --example routage_produit); sudo bash ./scripts/preuve-routes-linux.sh |
| banc-demontage-routage-linux.sh | Demontage du routage: par `LinuxTunnel::up` et `down` et par l'aiguillage du coeur, dans un namespace jetable par cas, deux familles, le produit refuse sans rien poser une table, une marque ou une interface qu'un tiers occupe, ne retire rien d'un tiers pose avant ou apres lui, retire le reste d'une session interrompue, et rend l'etat initial exact sur une table libre, `prove routes` en MATCH sur la pose (apres cargo build --workspace et cargo build -p bifrost-daemon --example banc_demontage; module noyau wireguard); sudo bash ./scripts/banc-demontage-routage-linux.sh |
| check-cibles.sh | Construit et verifie les cibles sur l'hote courant |
| e2e-linux.sh | Bout en bout Linux: daemon reel, capture, montee du tunnel et etancheite, hote isole (/etc et /var/lib superposes, resolveur de l'hote masque); `--unite FICHIER` lance le daemon sous les seules capacites de l'unite et exige le contrat de `check` sans CAP_SYS_ADMIN |
| banc-coeur-e2e.sh | Banc bout en bout d'un coeur anti-censure |
| banc-bascule-en-session.sh | Banc de bascule DNS en session, avec temoin de l'etat DNS de l'hote |
| banc-cdn-linux.sh | Banc CDN Linux (httpupgrade, edge) |
| mort-daemon-systemd-linux.sh | Banc de mort brutale du daemon sous systemd, etancheite mesuree |
| resolveur-linux.sh | Banc du resolveur chiffre embarque, Linux |
| resolveur-systemd-linux.sh | Banc du resolveur sous l'unite systemd |
| service-systemd-linux.sh | Banc du service Linux (cycle connect/disconnect par l'unite) |
| service-windows-pair.sh | Pilote la paire de bancs de service Windows depuis Linux |
| quic-chronologie.py | Chronologie des evenements QUIC pour l'analyse d'une capture |
| banc-coeur-windows.ps1 | Banc d'un coeur anti-censure, Windows |
| banc-jeton-filtre-windows.ps1 | Banc du jeton de filtre WFP, Windows |
| jetons-compare-windows.ps1 | Compare les jetons de filtre entre deux mesures Windows |
| service-windows.ps1 | Banc du service Windows |
| packaging-linux.sh | Fabrique les paquets Linux |
| packaging-windows.ps1 | Fabrique le paquet Windows |
| telemetrie-windows.ps1 | Banc de la couche anti-telemetrie Windows |
| telemetrie-reseau-windows.ps1 | Mesure la telemetrie reseau Windows |
| telemetrie-effet-windows.ps1 | Mesure l'effet d'un filtre de telemetrie |
| telemetrie-conditions-windows.ps1 | Etablit les conditions de mesure de telemetrie |
| telemetrie-cibles-windows.ps1 | Enumere les cibles de telemetrie |
| telemetrie-cause-windows.ps1 | Impute une sortie de telemetrie a sa cause |
| telemetrie-cause-binaire-windows.ps1 | Impute une sortie a un binaire precis |
| telemetrie-svchost-windows.ps1 | Analyse les sorties de telemetrie hebergees dans svchost |
| telemetrie-jeton-capture-windows.ps1 | Lit l'utilisateur du jeton capture a la creation de socket |
| telemetrie-w32time-windows.ps1 | Banc temoin sur W32Time, service qui, lui, se laisse bloquer |
| telemetrie-regle-microsoft-windows.ps1 | Rejoue une regle de blocage de Microsoft et mesure son effet |

Sous `packaging/`:

| Script | Usage |
|---|---|
| comptes.sh | Verifie la coherence des comptes systeme declares par le packaging |
| install-linux.sh | Installe le daemon, cree les comptes et l'unite systemd |
| install-windows.ps1 | Installe le service Windows et pose les ACL du resolveur |
| systemd/system-sleep/bifrost-reprise | Hook de reprise apres veille, cote systemd |
