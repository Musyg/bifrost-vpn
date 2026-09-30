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

Les comptes ci-dessous ont ete pris le 30/09/2026 sur l'arbre qui porte le
portage des corrections du tableau de survie et des abstentions, puis D1b.3b,
l'identite du serveur de D1b.3c, sa verification par toutes les commandes de
la CLI et la correction du permis DNS Windows par famille. L'hote qui tient le role `essai-linux` a change le
29/09: ses comptes ne se comparent pas a ceux d'avant cette date.

Compte honnete des recettes cargo, par hote. La colonne `reelles` est ce qui a
verifie quelque chose: `annoncees` moins `abstentions` moins `rouges`.

| Hote | Annoncees | Abstentions | Rouges | Reelles |
|---|---|---|---|---|
| dev-windows | 1291 | 19 | 0 | 1272 |
| essai-linux | 1304 | 26 | 0 | 1278 |

Les deux lignes ont ete prises par `scripts/recettes-strict.sh`, chacune sur son
hote: le portage a ajoute 14 recettes des deux cotes, D1b.3b 11 sur dev-windows et 22
sur `essai-linux`, D1b.3c (identite du serveur de la declaration) 4 sur
dev-windows et 5 sur `essai-linux`, la verification du serveur par les commandes
9 sur dev-windows et 7 sur `essai-linux`, le permis DNS par famille 8 sur
dev-windows et 6 sur `essai-linux` (ses deux recettes de traduction reelle ne
tournent que sous Windows). Sur `essai-linux`
une recette de plus est ignoree par construction
(elle pose une route et ne tourne qu'en espace de noms reseau), et la garde des
modes de scripts s'y abstient parce que la copie mesuree n'a pas de `.git` (elle
lit l'index; dans un clone elle mesure).

## Ce qui est ouvert, document par document

Les documents du plan `docs/01..07` et `docs/09`, leur etat et, pour un chantier ouvert,
la prochaine action. Une cellule vide signalerait une tranche non finie.

| Chantier | Etat et derniere mesure | Prochaine action |
|---|---|---|
| 01 | Architecture technique. Cadre du plan, redige; ce n'est pas un livrable | - |
| 02 | Kill switch WFP et nftables. Specification de reference, a jour. 30/09/2026: le permis DNS Windows ne se pose plus que sur la couche de la famille du resolveur, et la traduction refuse une condition inapplicable a sa couche au lieu de l'ecarter (elle compte les conditions posees). Mesure sur essai-windows avant (filtre sans adresse sur l'autre couche; resolveur `::1`, une requete DNS IPv4 vers un resolveur public obtenait sa reponse, kill switch arme) et apres (un seul permis, l'autre famille refusee par `block-dns`). La fuite IPv6 hors LAN reste inferee: pas d'IPv6 globale sur le site | - |
| 03 | Anti-telemetrie OS. Couche DNS livree; couches Windows registre et WFP par service a finir | Finir les couches Windows registre et WFP par service |
| 04 | Anti-censure DPI. Tableau de survie rafraichi le 20/09/2026 (une cellule); inerte a partir du 30/09/2026 (`TABLEAU_INERTE_A_PARTIR_DU`, gardee par `selection::planifier`): il classe encore, il n'ecarte plus rien | Rafraichir le tableau, en priorite la colonne Turkmenistan, sans source depuis juillet |
| 05 | Anonymat et chainage. Document redige; le chainage Tor et Nym n'est pas commence, et le document lui-meme le place apres les trois objectifs | Chainage Tor ou Nym, apres les objectifs 1 a 3 |
| 06 | Architecture logicielle et packaging. Daemon, IPC authentifie, machine a etats et scripts d'installation faits (Linux et Windows, comptes dedies, ACL); ni interface graphique, ni MSI, ni .deb/.rpm, ni mise a jour TUF, ni provisioning; SBOM en CI | Interface graphique en jalon propre apres J2; paquets signes et mise a jour TUF |
| 07 | Programme de securite produit. fmt, clippy, recettes, suite de fuite, cargo audit, cargo deny et SBOM en CI; politique de divulgation publiee (SECURITY.md, security.txt); inventaire unsafe ferme; cargo vet et fuzz absents, aucune cle PGP | Publier une cle PGP (champ Encryption); ajouter cargo vet et un harnais fuzz |
| 09 | Souverainete verifiable. D1a: `prove binaire`. D1b.1: comparaison nft hors ligne. D1b.2: collecte Linux passive encadree par GETGEN. D1b.3a: `prove nft --politique` engendre la reference produit depuis une intention v1 explicite; 64 combinaisons confrontees au rendu applique en banc jetable. D1b.3b: `prove nft --politique-daemon --actif` prend pour attendu la politique que le daemon declare avoir posee (requete IPC en lecture, relue avant et apres la collecte); daemon reel en banc jetable: correspondance, quatre alterations en ecart, droits retires et daemon arrete non mesures. D1b.3c (identite): le client exige un serveur root (SO_PEERCRED) avant de lire la declaration, sinon UNMEASURED daemon-identity; regle Windows (proprietaire du pipe LocalSystem) livree dans bifrost-ipc, sans preuve Windows qui l'appelle encore. Toutes les commandes de la CLI verifient aussi le serveur avant d'ecrire (root; Windows LocalSystem ou Administrateurs), refus en code 4, rien envoye; un compte ordinaire refuse sans rien recevoir en banc jetable. Ni preuve globale du VPN ni validation Windows | D1b.3c: objets nft hors perimetre, collecte WFP |

## Scripts

Chaque banc et outil du depot, avec sa ligne d'usage. Un banc que personne ne
sait lancer n'est pas un banc.

Sous `scripts/`:

| Script | Usage |
|---|---|
| recettes-strict.sh | Compte honnete des recettes cargo (vertes, abstentions, rouges); `--strict` echoue aussi sur abstention |
| abstentions-budget.sh | Exige que chaque abstention de la CI figure dans la liste attendue du job |
| check-strict.sh | Exige que les dix vecteurs de fuite soient PASSED |
| preuve-nft-linux.sh | Collecte nft passive, ecart, refus de privileges et confrontation a la declaration d'un daemon reel, faux daemon non root refuse, compteur non root que chaque commande refuse sans rien lui ecrire, dans des namespaces jetables (apres cargo build --workspace); sudo bash ./scripts/preuve-nft-linux.sh |
| check-cibles.sh | Construit et verifie les cibles sur l'hote courant |
| e2e-linux.sh | Bout en bout Linux: daemon reel, capture, montee du tunnel et etancheite |
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
