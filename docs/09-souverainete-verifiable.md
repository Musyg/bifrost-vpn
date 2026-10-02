# 09 - Souverainete verifiable

Date: 27 septembre 2026. Specification de produit et criteres de livraison.
Ce document complete 01 a 07, sans promouvoir leurs pistes en fonctions livrees.
Le numero 08 est reserve au chantier d'interface maintenu separement.
L'etat de reference PUBLIC est e983fb9. Voir ETAT.md pour les tranches suivantes.

## Promesse et limites

L'utilisateur choisit son infrastructure, detient ses cles, connait les sorties
reseau de son client et peut confronter ses protections a des observations
locales. Aucun compte, abonnement, serveur de coordination ou cle de l'editeur
ne doit etre necessaire pour utiliser un profil local. L'hebergement peut couter
de l'argent; le logiciel ne promet ni infrastructure gratuite ni anonymat.

Une signature authentifie une declaration, pas sa veracite. Un hash identique
ne prouve pas la surete du programme. Un test de laboratoire ne prouve pas
l'etat du poste. Une mesure ponctuelle ne prouve pas la prochaine seconde.
Le noyau et le compte qui execute le controle restent dans la base de confiance:
un OS compromis peut mentir. Les comptes connectes et le navigateur sont hors
du perimetre de protection du tunnel.

## D1 - Observations locales et commande prove

### Contrat commun

- `prove` est passif par defaut: pas de sonde externe, pas d'appel a `check`,
  pas de changement de route, DNS, pare-feu ou profil, pas d'elevation implicite.
- Chaque rapport porte une version de schema, un perimetre, les attentes, les
  observations, leur source, l'intervalle de collecte et les limites.
- Separer observation du noyau, declaration du daemon et resultat d'un banc.
  Un `kill_switch_engaged=true` du daemon n'est jamais une preuve du noyau.
- Un controle non implemente, refuse, incomplet, perime ou illisible reste
  NON MESURE avec sa raison. Une valeur absente ne devient pas une valeur saine.
- L'export est local et explicite. Aucun envoi automatique. Ne pas exporter
  par defaut cle, profil, IP, nom de poste, nom de fichier, chemin, historique
  DNS ou identifiant stable de session. Une empreinte peut identifier un fichier:
  meme un rapport expurge se relit avant partage.
- Un futur rapport compose n'est conforme que si TOUS les controles obligatoires
  de son perimetre sont mesures et conformes. Un ecart prime sur un inconnu;
  sans ecart, un inconnu rend le resultat incomplet. Pas de note moyenne.

### D1a - Integrite d'un fichier (premiere tranche)

`bifrost-cli --json prove binaire --fichier <fichier> --sha256 <reference>`

Rapport v1, perimetre `file-sha256`: hash des octets lus depuis un descripteur
unique compare au SHA-256 fourni. `MATCH`/code 0, `MISMATCH`/code 1,
`UNMEASURED`/code 2. Une erreur de syntaxe CLI rend aussi 2, avant le rapport.
La reference est declaree `user-supplied`, la provenance `not-verified` et la
securite reseau `not-evaluated`, MEME sur MATCH. `started_at_unix_ms` et
`completed_at_unix_ms` viennent de l'horloge locale non attestee (null si elle
precede Unix); `duration_ms` utilise une horloge monotone. Un rapport sauvegarde
n'est pas une mesure fraiche.

Lecture de fichier regulier uniquement, liens symboliques presents au controle
initial refuses, plafond de
512 Mio, memoire bornee, erreur de lecture sans hash partiel, comparaison des
metadonnees du descripteur avant/apres. Ce controle n'est pas un instantane
atomique contre un ecrivain hostile: une modification de meme taille dont la
date est restauree peut echapper a cette detection. Un chemin peut etre remplace
entre le controle initial et l'ouverture, ou apres; la mesure concerne le
descripteur lu, pas une future execution.
Le fichier doit etre sur un stockage local de confiance et rester immuable
pendant le controle. Le plafond porte sur les octets, pas sur le delai d'I/O.

Acceptation: vecteur SHA-256 connu, un octet modifie, reference mal formee,
fichier absent, repertoire, lien, fichier trop grand, erreur apres lecture
partielle, JSON sans chemin, execution sans daemon, fichier laisse intact.

### D1b - Politique pare-feu effective (en cours)

#### D1b.1 - Comparateur hors ligne livre

`bifrost-cli --json prove nft --attendu reference.json --observe capture.json`

Cette tranche compare deux fichiers au format de sortie `nft -j list ruleset`;
elle ne lance PAS nft, ne lit pas le noyau et n'applique aucune regle. Le
perimetre `nft-json-comparison` porte `source=user-supplied-snapshots`,
`live_kernel=false`, `generation_verified=false`, `network_security=not-evaluated`.
MATCH/0 signifie correspondance structurelle des captures, MISMATCH/1 un ecart,
UNMEASURED/2 une comparaison impossible. Meme une reference permissive peut
correspondre: la commande n'evalue pas sa surete. Les fichiers peuvent etre
anciens, incomplets ou falsifies; leur collecte n'est pas attestee.

Schema nft JSON 1 avec metainfo initiale obligatoire. Tables, chaines, regles
et objets nommes sont compares, y compris familles, priorites, hooks,
politiques, flags, expressions, commentaires, regles et objets
supplementaires et ordre global. Les cles d'un objet JSON peuvent etre
reordonnees, pas les elements d'un tableau, hors les deux ensembles nommes
plus bas. Seuls les handles d'objets et les valeurs d'etat que le noyau change
seul sont ignores: `packets`/`bytes` des compteurs (anonymes, nommes ou
d'element), consommation d'un quota (`used`, et `used_unit` d'un quota
anonyme ou d'element, que nft n'ecrit qu'une fois non nulle), dernier passage
(`last`, nul ou non) et temps restant d'un element (`expires`). L'instruction
ou l'objet qui les porte reste compare, presence et position comprises; la
limite d'un quota et le delai d'un element aussi. Une consommation ou une
valeur de compteur posee a la creation n'est pas comparee davantage.
Les informations de version du producteur dans metainfo ne sont pas comparees.
Les expressions sont comparees structurellement, sans interpreteur nft: ce
controle n'est ni un validateur complet de la grammaire nft, ni un simulateur.

Objets nommes autonomes, depuis D1b.3c: set, map, flowtable, counter, quota,
limit, ct helper, ct timeout, ct expectation et synproxy, dans la forme que nft
1.0.9 leur donne. Identite (type, famille, table, nom), declaration et, pour un
set ou une map, elements sont compares. Les elements d'un set sont une
appartenance: compares sans egard a leur ordre, tries par cle; une cle en
double, ou deux valeurs pour une cle de map, n'est pas une sortie de nft et
rend la capture NON MESUREE. Les peripheriques d'un flowtable sont aussi un
ensemble (nft en ecrit un seul en chaine, plusieurs en liste). Un objet
ajoute, retire ou change est un ecart de sa categorie (`sets`, `set-elements`,
`maps`, `map-elements`, `flowtables`, `counters`, `quotas`, `limits`,
`ct-helpers`, `ct-timeouts`, `ct-expectations`, `synproxies`), comme une
chaine tierce; un element qu'un set dynamique gagne ou perd avec le trafic
aussi. Tout autre type (`secmark`, `tunnel`, `element` hors d'un set...):
UNMEASURED, jamais omis. Meme refus pour un schema inconnu, une cle JSON
dupliquee, une table, une chaine ou un objet nomme duplique, un objet
malforme, un parent absent, un nombre non entier, un fichier tronque ou
inaccessible. Une reference sans chaine de base est refusee; une capture
observee valide mais vide constitue un ecart.

Deux fichiers reguliers immuables, 2 Mio maximum chacun, lecture bornee, liens
detectes au controle initial refuses. Les limites de concurrence et de stockage
de D1a s'appliquent aussi ici. Rapport sans noms, adresses, expressions ni chemins:
seuls les comptes (dont `objects`, le nombre d'objets nommes) et les categories
d'ecart sont exportes; ni element de set ni peripherique. L'intervalle est celui
de la comparaison locale, PAS celui de la collecte des captures.

Acceptation hors ligne: ordre de regles inverse, chaine tierce ajoutee, politique
drop remplacee, priorite/hook/interface/destination/operateur modifies, regle ou
compteur supprime, table dormant, capture vide, invalide et hors perimetre.
Objets nommes, chaque type: correspondance malgre leurs valeurs d'etat, l'ordre
de leurs elements et de leurs peripheriques; element ajoute ou retire, flag,
valeur de map, hook, priorite ou peripheriques de flowtable, counter retire,
limite de quota, objet tiers ajoute, chacun dans sa seule categorie; type
inconnu et objet malforme NON MESURES.
Les fixtures sont synthetiques: elles ne prouvent pas une observation du noyau.

#### D1b.2 - Collecte passive Linux livree

`bifrost-cli --json prove nft --attendu reference.json --actif`

Lire et valider la reference AVANT tout acces noyau. Envoyer uniquement
NFT_MSG_GETGEN sur NETLINK_NETFILTER, lancer le nft systeme avec les arguments
fixes `--json --numeric list ruleset`, puis relire GETGEN. Les generations
doivent etre identiques. La source netlink doit etre le noyau; sequence,
destination, type, longueur et attribut d'identifiant sont controles. Troncature,
generation absente/dupliquee, refus d'acces et changement rendent UNMEASURED.

Pas de shell, pas de recherche dans PATH, pas de sudo, pas d'IPC privilegie.
L'environnement du sous-processus est vide sauf LC_ALL=C. La sortie est bornee
a 2 Mio; lecture et attente de nft sont limitees a 5 secondes apres lancement.
Chaque GETGEN attend au maximum une seconde. En cas d'erreur, seul l'enfant
cree est tue et une seconde est accordee a sa recuperation. Les blocages d'I/O
du stockage ou du noyau ne sont pas couverts par une garantie temps reel.

Perimetre `nft-kernel-comparison`, source `kernel-netlink-and-system-nft`.
`live_kernel` et `generation_verified` ne deviennent vrais qu'apres une collecte
complete avec generation stable. Une capture ensuite hors format peut encore
etre NON MESUREE. Les generations numeriques et le contenu brut ne sont pas
exportes. Aucun resultat Windows n'est revendique; hors Linux le mode est
indisponible. Aucun priviliege ou service persistant n'est installe.

Limites: namespace courant, confiance dans le noyau et le binaire nft systeme,
reference non authentifiee, generation 32 bits, etat ponctuel. Conntrack, eBPF,
iptables legacy, interfaces physiques, routes et DNS ne sont pas prouves par
cette comparaison. Les types d'objets que D1b.1 ne lit pas restent NON MESURES.

Acceptation: frames netlink invalides, generation changee ou seconde lecture
refusee, enfant trop lent/trop bavard/en echec. Le banc `preuve-nft-linux.sh`
cree son propre namespace sans lien externe sur runner Linux jetable: MATCH,
regle ajoutee -> MISMATCH, droits retires -> UNMEASURED, table retiree ->
MISMATCH. La capture avant/apres le controle doit rester identique.

#### D1b.3a - Reference produit depuis une intention versionnee

`bifrost-cli --json prove nft --politique intention.json --actif`

`--politique` et `--attendu` sont exclusifs. La comparaison d'une capture reste
possible avec `--observe`. Le mode politique est Linux uniquement pour cette
tranche. Aucune regle n'est appliquee par ces commandes.

Le fichier porte exactement `schema_version=1`, `tunnel_interface` (chaine ou
null), `fwmark` (entier non nul ou null), `dns_resolver` (IP), `allow_lan` (booleen),
`coeur_uid` et `resolveur_uid` (entiers non nuls ou null). Tous les champs sont
obligatoires. Champs inconnus, cles dupliquees, version inconnue, types invalides,
interface invalide/lo, UID root/partage et DNS non exploitable sont refuses avant
toute collecte. Un resolveur embarque exige une destination DNS de boucle locale.
Les plafonds et controles de lecture D1b.1 s'appliquent au fichier d'intention.

Le module pur `bifrost-firewall::politique_nft` reconstruit une `FirewallPolicy`
et sa reference JSON. Les parametres proviennent de L'APPELANT: ce n'est pas une
lecture du profil actif du daemon. Le rapport conserve `schema_version=1`, ajoute
`expected_source=bifrost-policy-v1-user-declared` et `policy_schema_version=1`
apres validation. Pour une capture de reference, `expected_source` vaut
`user-supplied-snapshot` et `policy_schema_version` est null. Aucun parametre de
l'intention n'est exporte. `network_security` reste `not-evaluated`.

La reference couvre le ruleset produit complet (input/output/forward, DNS,
DHCP, NDP, marque, interface, LAN et exceptions par UID), pas les seules regles
qui portent le nom Bifrost. Une table ou un objet nomme tiers rend MISMATCH;
un type d'objet que le comparateur ne lit pas rend UNMEASURED. Aucun tri global
ni filtre de regles tierces ne peut
masquer un changement. La forme JSON cible est celle de nft avec `--numeric`;
une difference de representation entre versions peut rendre un ecart et doit
etre examinee, pas ignoree automatiquement.

Acceptation: 64 combinaisons interface/marque/LAN/coeur/resolveur/DNS IPv6. Le
banc jetable applique le rendu texte REEL du produit, puis le compare a la
reference pure, hors ligne et via la collecte active. Les captures avant/apres
doivent rester identiques. Table tierce et permis non prevu deviennent MISMATCH.
Les tests sans privileges couvrent aussi l'intention invalide, l'ordre des
restrictions DNS et le changement de chaque parametre attendu.

#### D1b.3b - Politique declaree par le daemon, livree sous Linux

`bifrost-cli --json prove nft --politique-daemon --actif`

L'attendu n'est plus fourni par l'appelant: c'est la politique que le daemon
joint par `--socket` declare avoir remise en dernier a son moteur nftables. Le
superviseur la retient a l'endroit unique ou il appelle le moteur, apres ses
propres retouches (handle du tunnel, exemption du coeur, restriction du
resolveur) et avec la reponse du moteur. Rien n'est recalcule depuis le profil
ni depuis `TunnelStatus`. Chaque appel au moteur, reussi ou non, incremente un
numero d'application; un alea tire au demarrage distingue deux vies du daemon.
Un refus du moteur est declare `echec`, sans politique: la precedente n'est pas
redeclaree.

La requete IPC `declaration-pare-feu` est une lecture sans parametre, classee
non mutante. Elle passe par le controle d'acces existant, inchange: socket 0660
et SO_PEERCRED sous Linux (root et le groupe `--group`), DACL du pipe sous
Windows (SYSTEM et Administrateurs). Qui peut la lire pouvait deja connecter et
deconnecter. Elle ne porte ni cle, ni profil, ni point d'acces: version, alea,
numero, moteur, issue (`aucune`, `posee`, `retiree`, `echec`) et, si posee, la
projection v1 des six champs que le rendu nft lit. Une recette verifie sur le
rendu reel que ces six champs suffisent a le reproduire.

Protocole: lire la declaration (N1), GETGEN, dump nft, GETGEN, relire (N2). N1
et N2 doivent etre identiques en entier. La declaration est servie par le fil
qui applique les politiques: aucune lecture ne tombe entre une pose et sa note.
Declaration ou generation changee, daemon injoignable ou muet (5 s), acces
refuse, reponse tronquee ou hors schema, aucune politique posee, retrait ou
echec du moteur: UNMEASURED avec sa raison. La declaration passe par le meme
lecteur strict que `--politique`; interface `lo`, compte de coeur ou de
resolveur root, compte partage entre les deux, ou moteur autre que nftables
sortent du perimetre de la reference et rendent UNMEASURED, jamais MATCH. Un
noyau different de la declaration rend MISMATCH. La declaration ne porte aucun
objet nft nomme: un objet tiers, dans une table tierce ou dans celle du
produit, rend MISMATCH avec sa categorie, comme une table tierce (voir D1b.3c).

`--politique-daemon` exclut `--attendu`, `--politique` et `--observe`, et exige
donc `--actif`. Le rapport garde `schema_version=1` et `policy_schema_version=1`,
porte `expected_source=daemon-declared-active-policy`, et
`failed_input=daemon-declaration` quand la declaration est en cause. Il
n'exporte ni les parametres de la politique, ni le numero, ni l'alea. Une
correspondance dit que le noyau porte ce que le daemon dit avoir pose;
`network_security` reste `not-evaluated`. Une declaration du daemon n'est jamais une observation du noyau. Depuis D1b.3c,
le client verifie qui la sert (voir D1b.3c).

Etats du daemon sous Linux, qui n'a pas de filtre de demarrage: au demarrage,
rien n'est pose; la connexion pose sans interface puis, interface montee, avec
elle; la reconnexion repose sans interface; l'erreur garde la derniere pose; la
reprise apres veille, dans tout etat sauf deconnecte, repose avec l'interface du
profil; la deconnexion retire. Chaque pose est la politique exacte remise au
moteur.

Acceptation, banc jetable (`scripts/preuve-nft-linux.sh`, job `fuite`): daemon
reel dans un namespace sans veth, profil a coeur dont le binaire manque; le kill
switch est pose, le tunnel ne monte jamais, le DNS de l'hote n'est pas touche.
Daemon neuf: UNMEASURED. Etat erreur: MATCH sans mutation. Regle retiree,
exception elargie, filtre tiers prioritaire, interface remplacee: MISMATCH,
puis MATCH apres reprise. Lecteur sans droit noyau, hors du groupe, ou refuse
par le daemon: UNMEASURED. Trente reprises concurrentes: MATCH ou UNMEASURED
explique, jamais MISMATCH. Deconnexion, daemon arrete avec sa table en place:
UNMEASURED. Aucun processus ne survit aux namespaces. Non mesures en banc:
etat connecte, montee de l'interface, reconnexion, chemin WireGuard (marque),
resolveur embarque reel.

#### D1b.3c - Identite du serveur, preuve WFP et objets nft nommes livres

Identite du serveur de la declaration, livree. Avant d'ecrire le moindre octet,
`prove nft --politique-daemon` et `prove wfp --politique-daemon` exigent du
processus qui sert `--socket` une
identite privilegiee (`IpcClient::connect_verified`). Linux: `SO_PEERCRED` sur
le socket du client rend l'uid effectif du processus qui a appele `listen(2)`,
fige a cet instant et traduit dans l'espace de noms utilisateur du client; il
doit valoir 0 (regle `root-peer-credentials`). Le daemon tourne toujours en
root: il le verifie avant d'ecouter, et l'unite livree n'a pas de `User=`.
Windows: le proprietaire du pipe, lu sur la poignee du client, doit etre
LocalSystem (regle `windows-system-pipe-owner`). Le jeton du processus serveur
n'est pas lisible sans privilege; le proprietaire l'est, et un compte non
privilegie ne peut ni creer un pipe possede par SYSTEM ou les Administrateurs,
ni le lui attribuer apres coup (ERROR_INVALID_OWNER, mesure). Sinon: UNMEASURED,
`failed_input=daemon-identity`, sans rien envoyer au serveur. Le rapport porte
`daemon_identity`: le nom de la regle, ou `null` tant qu'elle n'est pas
etablie; jamais un uid, un pid ou un SID.

Limites: la regle dit qui ecoute, pas que c'est le daemon. Un serveur root, ou un
pipe de LocalSystem, qui n'est pas le daemon est admis (mesure: un rejeu sous
root correspond). Un socket d'ecoute cree par root puis confie a un autre
processus garde les identifiants de root. Un pipe de LocalSystem dont la DACL
laisse d'autres comptes creer des instances peut etre servi par un tiers; celle
du daemon ne l'accorde qu'a SYSTEM et aux Administrateurs, donc a un processus
eleve (un compte non eleve y est refuse, mesure; le cas eleve est infere de la
DACL). Un daemon Windows lance en console eleve cree un pipe possede par les
Administrateurs et n'est pas admis par la preuve.

Les commandes verifient aussi le serveur, livre. `connect` (avec ou sans
`--config`), `disconnect`, `status`, `check`, `inspection-tls --annoncer`, la
sonde d'`emergency-disarm` et `reprise` (le hook de veille) etablissent
l'identite du serveur avant d'ecrire le moindre octet: `bifrost_ipc` n'a plus
de client qui s'en dispense (`IpcClient::connect_verified` est son seul
constructeur). Leur regle exige les droits que le daemon exige de lui-meme pour
demarrer: Linux, uid effectif 0 (`root-peer-credentials`); Windows, un pipe
possede par LocalSystem (`windows-system-pipe-owner`) ou par les Administrateurs
(`windows-administrators-pipe-owner`), ce qui admet le daemon lance en console
elevee. Un compte non privilegie ne peut servir ni l'une ni l'autre (mesure). La
preuve garde la sienne, LocalSystem seul sous Windows: elle exporte un constat
sur ce que le daemon declare. Refus: un message qui nomme le socket et la regle,
jamais un uid, un pid ou un SID, rien d'envoye, code de sortie 4, aucune option
pour s'en passer; `inspection-tls --annoncer` garde le code de sa mesure et dit
le refus sur la sortie d'erreur. Le hook de reprise tourne sous root
(`systemd-sleep` n'a pas de `User=`); face a un serveur d'un autre compte il rend
4 et journalise que la politique n'a pas ete reposee.

Constat avant correction, mesure le 30/09/2026 sur le client de `5baf9f3` face a
un faux serveur du compte courant: `connect --config` lui ecrivait 506 octets,
cle privee du profil comprise; les autres commandes, leur requete; la sonde
d'`emergency-disarm` n'ecrivait rien mais le prenait pour le daemon. Sous
Windows, service arrete, un compte non eleve a cree le pipe au nom par defaut et
recu le profil d'un `connect --config` lance sans `--socket`. Sous Linux, le
chemin par defaut n'est pas prenable par un compte ordinaire; `--socket` pouvait
designer n'importe quel chemin. Acceptation: sans privilege sur les deux
plateformes, un faux serveur du compte courant recoit une connexion et zero
octet de chaque commande, qui rend 4; banc jetable, un compteur root recoit
`connect --config` et la cle jetable du profil de test (temoin), le meme sous un
compte ordinaire ne recoit rien d'aucune commande ni du hook, et le hook, face au
vrai daemon, repose la politique. Non mesures: le service Windows reel sous
LocalSystem, et le pipe des Administrateurs de bout en bout.

Acceptation, banc jetable: un faux daemon qui rejoue la vraie declaration sur un
`--socket` choisi, noyau conforme, rend MATCH sous root et UNMEASURED
`daemon-identity` sous un autre compte, sans recevoir une seule requete.

Politique WFP confrontee a la declaration, livree.
`bifrost-cli --json prove wfp --politique-daemon --actif` est le pendant
Windows de `prove nft --politique-daemon`, et passe par le meme lecteur: meme
exigence d'identite (LocalSystem seul), meme protocole N1, mesure, N2, memes
raisons, memes champs `failed_input` et `daemon_identity`. Quand le moteur est
WFP, la declaration porte une projection distincte (`projection = wfp`,
version 1): les champs que lit le plan WFP, plus ce que le moteur a lu de son
hote pour poser (binaire du daemon, SID de son jeton, LUID de l'interface). Ces
valeurs ne vont qu'a un appelant admis sur le canal du daemon, et la preuve ne
les recopie jamais dans son rapport. La projection nft des autres moteurs est
inchangee; les deux ne se lisent jamais l'une pour l'autre.

La reference est rendue par le plan WFP du produit et par la MEME traduction
que la pose, jamais par une copie ecrite a la main: une condition inapplicable a
sa couche fait echouer la reference comme elle fait echouer la pose. Elle a
besoin de deux valeurs de l'hote qui prouve (identifiant d'application d'un
chemin, identite en liste de controle d'acces), et le dit. L'observe est
enumere en lecture seule, sans elevation implicite, dans une seule transaction
en lecture seule qui tient le role du GETGEN: WFP ne publie pas de numero de
generation. Sous-couches et filtres des quatre couches ALE, desactives compris.
Un appelant sans droit recoit un refus, jamais une liste vide.

Trois controles: les objets de Bifrost (multi-ensemble normalise), la
sous-couche et le fournisseur, l'arbitrage. Un filtre tiers defait un blocage de
Bifrost s'il est evalue avant lui et que son action ne se laisse pas ecraser
(autorisation dure, callout terminal ou inconnu), dans une sous-couche de poids
au moins egal au poids EFFECTIF que le moteur a rendu a celle de Bifrost: le
moteur rebat un poids de sous-couche qui entre en collision, si bien qu'une
valeur demandee maximale peut atterrir sous une sous-couche tierce. Tout ce que
la reference ne sait pas decrire rend UNMEASURED, jamais MATCH. Codes MATCH/0,
MISMATCH/1, UNMEASURED/2; `expected_source=daemon-declared-active-policy`; ni
chemin, ni SID, ni LUID, ni GUID dans le rapport. MATCH dit que le moteur porte
les filtres que le daemon declare avoir poses et qu'aucun filtre tiers lisible
des quatre couches ALE ne peut defaire leurs blocages; les filtres illisibles
par l'appelant et les callouts noyau echappent a la lecture. Ce n'est pas une
preuve d'etancheite du VPN.

Acceptation, banc jetable Windows le 30/09/2026, avant la fusion avec l'identite
du serveur et le permis DNS par famille: daemon reel, kill switch pose avec le
LAN ouvert, sans filtre de demarrage ni redemarrage: MATCH; regle retiree,
exception trop large, filtre tiers prioritaire en ecart puis MATCH apres
reprise; verrou de transaction tenu par un tiers: UNMEASURED puis MATCH. Par
recette: regle desactivee, interface remplacee, action hors reference,
declaration changee entre les deux lectures, acces refuse, donnees tronquees,
serveur non admis a la premiere ou a la seconde lecture. Apres la fusion, banc jetable Windows le 30/09/2026: un daemon
lance en console elevee, kill switch pose, 25 filtres; `status` est admis par
la regle des commandes, la preuve rend UNMEASURED `daemon-identity` et le
daemon ne journalise aucune requete de sa part. Non mesure en banc apres la
fusion: la preuve face au service reel sous LocalSystem, dont le MATCH n'est
etabli que par recette.

Objets nft nommes, livre. Constat avant, mesure le 30/09/2026 sur le client de
`eb325b3`, nft 1.0.9, noyau 7.0, en namespace jetable a cote du ruleset que
pose le daemon reel: un seul set, map, flowtable, counter, quota, limit,
ct helper, ct timeout, ct expectation ou synproxy pose par un tiers, dans une
table tierce ou dans celle du produit, rendait les trois modes UNMEASURED
(`type d'objet nft non pris en charge`), meme face a une reference qui portait
l'objet identique; seule une table tierce vide rendait MISMATCH en
`--politique-daemon`. Sur un hote ou un pare-feu tiers pose un set, la preuve
etait muette. Un quota anonyme et `last` dans une regle rendaient en outre un
faux ecart des que du trafic passait: leur valeur d'etat etait comparee.

Apres: les dix types sont lus et compares (voir D1b.1). `--observe` et
`--actif` correspondent, apres trafic, a une reference qui porte les memes
objets. `--politique-daemon` rend MISMATCH avec la categorie de ce qui est en
plus (`tables` et `sets` pour un set dans une table tierce, `counters` seul
pour un counter ajoute a la table du produit): la declaration n'en porte aucun,
et un objet que le daemon n'a pas pose n'est pas ce qu'il declare, qu'une regle
le reference ou non. Un type que le comparateur ne lit pas reste UNMEASURED,
meme la ou une table tierce suffirait a conclure a un ecart.

Limites: la forme JSON de nft 1.0.9 omet `auto-merge` d'un set (propriete de
l'outil, pas du noyau), rend `typeof` en `type`, et n'ecrit une valeur de
`ct timeout` que si elle differe du defaut de nft: deux captures prises par
des versions de nft aux defauts differents peuvent correspondre sur des
delais differents. Un set rempli par le trafic change d'elements entre deux
captures: c'est un ecart, pas un etat ignore. La forme d'un meter n'a pas ete
relevee. Le noyau de mesure refuse `secmark` (pas de module de securite a
contextes) et nft 1.0.9 ne connait pas `tunnel`: leur forme n'est pas relevee.

Acceptation, banc jetable (`preuve-nft-linux.sh`): une table tierce porte un
objet de chaque type lu. Apres trafic et plus d'une seconde, chacune des six
valeurs d'etat ignorees a change (temoin) et la collecte active correspond.
Element ajoute, element retire, flag de set, valeur de map, priorite et
peripheriques de flowtable, counter retire, limite de quota, debit de limit,
set tiers ajoute, counter ajoute a la table du produit: chacun un ecart de sa
seule categorie, puis correspondance une fois repose. Face au daemon reel, un
set tiers rend `tables` et `sets`, un counter ajoute a sa table `counters`,
puis correspondance une fois retires. Avec le client de `eb325b3`, le banc
echoue sur ces etapes (UNMEASURED). Chaque neutralisation d'une valeur d'etat,
retiree du client et rejouee face au noyau, rend un ecart de sa categorie.

Reste a faire: `secmark` et `tunnel`, que le comparateur ne lit pas faute d'en
avoir releve la forme, restent NON MESURES.

La collecte Linux D1b.2 encadre le dump par la generation nftables (`getgen`/`id`),
pas par deux horodatages. Deux captures identiques seules ne prouvent pas
l'absence d'un changement transitoire. D1b reste incomplet: sous Linux, l'attendu peut venir de la declaration d'un serveur root, que le
client verifie avant de la lire, mais rien n'etablit que ce serveur est le
daemon; sous Windows, la preuve n'admet que le pipe de LocalSystem, sans
etablir non plus que son serveur est le daemon. Deux types d'objets nft
(`secmark`, `tunnel`) ne sont pas lus. Une
intention permissive ou obsolete n'est pas rendue fiable par le fait que le
produit sait la representer, ni par le fait que le daemon la declare.

### D1c - Routes, DNS et provenance (en cours)

Ajouter les routes IPv4/IPv6, regles de routage, resolvers effectifs, exceptions
DNS et empreintes des composants charges. Comparer configuration attendue et
etat OS; conserver les limites propres aux caches et connexions deja ouvertes.
Pour la provenance, une reference de confiance doit venir d'un manifeste signe
verifie contre une racine obtenue independamment, avec cible, version et taille.
Une signature de profil ne couvre pas les executables.

#### D1c.1 - Regles de routage et routes Linux, par intention, livrees

`bifrost-cli --json prove routes --intention intention.json --actif`

L'intention v1 porte exactement `schema_version=1`, `chemin` (`wireguard` ou
`coeur`), `interface`, `fwmark`, `table` et `coeur_uid`, tous obligatoires.
WireGuard exige une marque non nulle et une table hors de celles que le noyau
se reserve (0, 253, 254, 255), sans compte de coeur; le coeur n'a ni marque ni
table (la sienne est fixee par le produit) et un compte non nul ou null. Le nom
d'interface suit la regle du produit, sans `lo`. Champs inconnus ou manquants,
cles dupliquees, nombres non entiers et version inconnue sont refuses avant
toute lecture du noyau, avec les plafonds de lecture de D1b.1. Les deux
familles sont toujours attendues: le produit pose toujours les deux.

L'attendu est le plan que le produit pose, `bifrost_core::routage::Plan`: depuis
D1c.1, `netcfg::add_routing` (WireGuard) et `aiguillage::poser` (coeur) tirent
leurs commandes `ip` de ce plan, au lieu de les ecrire chacun. Les commandes
executees sont celles d'avant, dans le meme ordre, et depuis le 30/09/2026
chacune porte en dernier l'etiquette du produit (`protocol 177` sur une regle,
`proto 177` sur une route; recettes de reference du daemon). L'etiquette ne
change aucune decision de routage et la preuve ne la compare pas: une regle ou
une route tierce identique a celle du plan, sans etiquette, passe donc pour
celle du produit. L'etiquette sert au demontage, qui tire du meme plan le
retrait exact de chaque commande de pose et ne retire rien qui ne la porte pas.
Depuis le 02/10/2026 l'etiquette seule ne designe plus rien: chaque session du
produit s'inscrit, avant sa premiere commande, au journal des sessions du
daemon, et le retrait ne vise que ce qu'une session inscrite a pose, par sa
forme, la priorite que le noyau a donnee a chaque regle et son interface; un
objet a l'etiquette qu'aucune session inscrite n'explique fait refuser le
montage, sans rien retirer. Il n'y a pas de seconde implementation. Les regles de
WireGuard sont posees sans priorite: le plan en deduit l'ordre d'evaluation,
l'inverse de l'ordre de pose (`fib_default_rule_pref` du noyau), et le banc le
mesure.

Collecte: rtnetlink en lecture, sans shell, sans programme externe, sans
elevation. Un compte ordinaire lit ces dumps: mesure sur essai-linux. Le lien du
tunnel est lu par son nom, puis les adresses, les regles et les routes de toutes
les tables, dans les deux familles. Le controle strict des requetes est active
(`NETLINK_GET_STRICT_CHK`), et les routes sont demandees sans leurs exceptions.
Les cas suivants rendent UNMEASURED:
- un attribut, un type, une action ou un drapeau non reconnu;
- un drapeau de route dont l'effet sur l'emission n'a pas ete mesure, comme le
  delestage ou le piegeage materiel;
- une longueur fausse ou un attribut duplique;
- `NLM_F_DUMP_INTR`, une troncature;
- un refus d'acces ou une famille absente du noyau.

Le noyau ne pose pas `NLM_F_DUMP_INTR` sur les dumps de regles et de routes, et
il n'offre aucune generation lisible. La collecte entiere est donc faite deux
fois, et les deux lectures doivent etre identiques, sinon UNMEASURED. Cela ne
prouve pas qu'un instant a porte exactement cet etat: un changement qui
s'annule entre les deux lectures echappe. `ip -j` est ecarte, car iproute2
6.1.0 rend 0 sur un dump interrompu ou tronque.

Comparaison, famille par famille, avec les ecarts dans cet ordre:
- `<famille>-product-rules`: chaque regle du plan est presente une seule fois,
  avec son contenu exact, sa priorite quand le produit la fixe, et dans l'ordre
  d'evaluation du plan.
- `<famille>-rules-before-tunnel`: une regle tierce evaluee avant celle du
  tunnel, qui consulte une autre table ou qui saute. La table `local` est
  l'exception ecrite: c'est son contenu qui est juge. Une regle neutre, une
  regle qui rejette, ou une regle qui consulte la table du tunnel n'est pas un
  ecart.
- `<famille>-tunnel-table`: exactement la route par defaut du plan, vers
  l'interface du tunnel, sans passerelle, utilisable, et rien d'autre. Le
  noyau ignore une route dont le prochain saut est mort (`dead`), ou sans
  porteuse (`linkdown`) des que `ignore_routes_with_linkdown` vaut 1, et une
  route echue alors que le dump la montre encore: le trafic sort alors par le
  lien. Chacune est un ecart, et une route qui porte une echeance aussi.
  `onlink` n'en est pas un: il ne change pas l'emission.
- `<famille>-routes-before-tunnel`: ce que `local`, et `main` au travers de
  `suppress_prefixlength 0`, laissent passer avant le tunnel.

La legitimite de ces routes se decide par une regle, pas par une liste
d'adresses. Chaque cas admis a ete confronte au banc a un temoin d'emission.
Une route est admise dans sept cas:
- elle mene a l'interface du tunnel;
- elle est de type `local`: livree a l'hote, rien n'est emis;
- elle est la route connectee d'une adresse de l'interface, c'est-a-dire
  unicast, sans passerelle ni prefixe source, vers le reseau exact d'une
  adresse portee par la meme interface: elle emet sur le lien, vers ce
  reseau. Pour une adresse point a point, ce reseau est celui de son pair
  (`peer`, lu comme adresse de destination): sa route connectee est admise
  aussi, et emet sur le lien (mesure);
- elle est une route hote `broadcast` (IPv4 seulement) ou `anycast` vers une
  adresse de ce meme reseau exact, comme le noyau en pose: elle emet vers ce
  reseau, ou livre a l'hote;
- elle est `multicast` vers une destination de multidiffusion: elle emet sur
  le lien, c'est une limite nommee;
- elle rejette: `blackhole`, `unreachable` ou `prohibit`;
- elle est `throw`, qui renvoie a la regle suivante.

Tout le reste est un ecart. `broadcast` et `anycast` ne livrent pas a l'hote:
poses par un tiers, ils emettent sur le lien vers toute leur destination, dans
`main` comme dans `local`. Une telle route hors du reseau du lien est donc un
ecart, et `broadcast` en IPv6 aussi, car la famille n'a pas de diffusion et le
noyau traite la route en unicast. Une route par objet de prochain saut,
multichemin ou encapsulee est aussi un ecart: le comparateur ne la resout pas,
et ne l'admet jamais. Les drapeaux d'une route consultee avant le tunnel ne
changent pas son jugement: morte, elle est inerte, mais elle peut revivre a
tout instant.

Deux limites nommees, mesurees au banc, rendent MATCH alors que du trafic sort
par le lien:
- une route connectee est admise quelle que soit la largeur du reseau de son
  adresse. Une adresse a masque large met sur le lien tout ce que son masque
  couvre: un bail DHCP a masque large, un prefixe annonce sur le lien par un
  routeur IPv6, ou une adresse posee a la main;
- la multidiffusion part sur le lien. Le noyau pose `ff00::/8` sur chaque
  interface IPv6, dans `local`, consultee avant le tunnel: une destination de
  multidiffusion IPv6, de toute portee, sort par le lien physique avec la
  seule pose du produit.

Le perimetre est `linux-routing-comparison`, la source
`kernel-rtnetlink-read-twice`, et
`expected_source=bifrost-routing-plan-v1-user-declared`. Le rapport ne porte que
des categories et des comptes: ni interface, ni adresse, ni table, ni marque, ni
compte. `network_security` reste `not-evaluated`.

Limites:
- l'intention est declaree, ce n'est pas le profil actif du daemon;
- seul le namespace courant est lu;
- un changement qui s'annule entre les deux lectures, ou ce qui est pose apres
  la collecte, n'est pas vu;
- ne sont pas prouves: les routes deja en cache dans les sockets, les
  connexions deja ouvertes, les exceptions de route (PMTU, redirections), le
  pare-feu et le DNS;
- les deux limites nommees ci-dessus: masque large et multidiffusion;
- un compte ou une marque que l'intention ne declare pas n'est pas devine.

MATCH n'est pas une preuve d'etancheite du VPN.

Acceptation, banc jetable `scripts/preuve-routes-linux.sh` (un namespace par
cas). Les commandes que le produit rend, appliquees telles quelles,
correspondent pour les deux chemins, en root comme sans privilege, et la preuve
ne change pas l'etat du namespace. Un temoin d'emission accompagne les cas: un
datagramme envoye dans le namespace, diffusion permise, et les compteurs
d'emission de l'interface physique et de celle du tunnel. Chacune des
alterations suivantes donne un ecart de sa seule categorie:
- une regle retiree, l'ordre inverse, la famille IPv6 oubliee;
- une regle tierce ou un saut avant le tunnel;
- une route du tunnel retiree, changee ou en trop;
- la route du tunnel sans porteuse, morte ou qui expire, sur les deux chemins;
- une route plus specifique par une passerelle dans `main` ou dans `local`,
  dont `0.0.0.0/1` et `128.0.0.0/1`;
- une route `unicast`, `broadcast`, `anycast` ou `multicast` vers une
  destination hors du reseau du lien, dans `main` puis dans `local`, dans les
  deux familles, et une route hote de ces types hors de ce reseau;
- la priorite du coeur changee;
- l'interface du tunnel absente.

Pour chaque ecart que le temoin peut montrer, il montre le trafic sorti par le
lien, ou perdu quand le tunnel n'a plus de porteuse. Correspondent, et le
temoin confirme que rien ne sort par le lien hors de son reseau:
- des routes `local`, `blackhole`, `unreachable`, `prohibit` et `throw`, dans
  `main` puis dans `local`;
- une route vers le tunnel, la route connectee d'une seconde adresse du lien;
- les routes hote du reseau du lien, et `onlink` sur la route du tunnel;
- le lien physique sans porteuse ou mort.

Les deux limites nommees sont mesurees: MATCH, et le temoin sort par le lien.
Une regle qui bascule pendant la collecte rend UNMEASURED: le banc exige au
moins une collecte instable en cent essais, et jamais une correspondance.

Mode face au daemon, livre. `prove routes --politique-daemon --actif` prend
pour attendu le plan de routage que le PERIPHERIQUE DU TUNNEL declare avoir
pose, par une commande IPC distincte (`declaration-routage`, six cles, sa
propre version), lue par le meme lecteur que `prove nft` et `prove wfp`
(identite du serveur, N1, mesure encadree, N2), avec la limite de ce lecteur
ecrite en D1b: sous Linux le serveur est un processus root, rien n'etablit
que c'est le daemon. Le plan declare est une seconde
evaluation de la meme fonction pure (`netcfg::plan`, `aiguillage::plan`) sur la
meme configuration, retenue par le peripherique apres la derniere commande
reussie de sa pose: egal par construction au plan dont les commandes sont
tirees, ce n'est pas une capture des commandes elles-memes. Le superviseur le
retient a chaque montage et demontage (`TunnelDevice::routage_pose`), sans rien
recalculer d'un profil, et la preuve le reconstruit au meme constructeur que le
produit. En mode daemon, l'etiquette du produit (`protocol`/`proto 177`) est
EXIGEE sur les regles et la route du plan: un daemon reel pose avec elle, donc
une regle ou une route identique a un autre originateur n'est pas la sienne; le
mode `--intention` l'ignore. Rien pose: le rapport le dit (issue `aucun`), sans
comparer. Sous Windows, la commande et la preuve passent par le jumeau IP Helper
(D1c.3, ci-dessous); sur un autre systeme, ou rien n'est lu, le rapport des
deux modes porte `source: null`. Banc
jetable a cote d'un daemon reel (`e2e-linux.sh`): correspondance des deux
familles tunnel monte, encore apres reprise, et aucun plan a comparer apres
deconnexion, l'hote inchange.

#### D1c.3 - Routes et lignes d'interface Windows (IP Helper), livrees

`bifrost-cli --json prove routes --intention intention.json --actif` et
`bifrost-cli --json prove routes --politique-daemon --actif`, sous Windows.

Ce que le produit pose. Les deux chemins posent par les memes appels IP
Helper, sur le LUID de l'interface du tunnel, dans cet ordre: les adresses du
profil (`CreateUnicastIpAddressEntry`); une ligne d'interface par famille
adressee (`GetIpInterfaceEntry` puis `SetIpInterfaceEntry`: MTU du profil,
`DadTransmits` a zero et, seulement quand le plan prend la route par defaut de
la famille, metrique automatique coupee et metrique a zero); puis les routes
(`CreateIpForwardEntry2`, prochain saut non specifie, metrique zero).
WireGuard pose une route par prefixe autorise, masquee et dedoublonnee; le
chemin par coeur pose la route par defaut de chaque famille adressee sur son
TUN. C'est le produit qui pose ces routes, pas le coeur, dont l'echappement
passe par sa socket liee a l'interface physique. Le plan vit dans
`bifrost_core::routage_windows::PlanWindows`: `wgnt::ipcfg::apply` et `remove`
en tirent chacun de leurs appels, les memes qu'avant, dans le meme ordre et
avec les memes champs (recette du plan, appel pour appel), et la preuve le
reconstruit au meme constructeur. Il n'y a pas de seconde implementation.

L'intention Windows v1 est distincte de celle de Linux, dont `fwmark`,
`table` et `coeur_uid` n'ont pas de sens ici. Elle porte exactement
`schema_version` (1), `plateforme` (`windows`), `chemin` (`wireguard` ou
`coeur`), `interface` (la regle de nom du produit), `mtu` (de 576 a 9000),
`familles` (`ipv4`, `ipv6`, dans cet ordre, sans doublon, au moins une) et
`destinations` (WireGuard: au moins un prefixe, masque, sous sa forme
canonique, sans doublon; coeur: `null`). Champs inconnus ou manquants, cles
dupliquees, nombres non entiers, version inconnue et forme Linux sont refuses
avant toute lecture du systeme, avec les plafonds de lecture de D1b.1.

Collecte: l'alias de l'interface du tunnel resolu en LUID
(`ConvertInterfaceAliasToLuid`), puis les tables des routes
(`GetIpForwardTable2`), des lignes d'interface (`GetIpInterfaceTable`) et des
adresses (`GetUnicastIpAddressTable`), toutes interfaces, deux familles. Un
compte ordinaire les lit: mesure sous un jeton d'integrite moyenne. Aucun appel
qui cree, retire ou change un objet de la pile IP, ni qui emette sur le
reseau: le collecteur ne nomme de l'espace IP Helper que ces quatre fonctions
et la liberation des tables, ce qu'une recette verifie sur son source par des
listes fermees. Les valeurs d'etat qui
changent seules (age d'une route, durees de vie) sont laissees. IP Helper n'a
ni transaction ni generation lisible: la collecte entiere est faite deux fois,
et deux collectes differentes rendent UNMEASURED.

Comment Windows choisit (Microsoft Learn, "Chapter 10 - TCP/IP End-to-End
Delivery" et "MIB_IPFORWARD_ROW2", lus le 01/10/2026): le prefixe le plus
long; a longueur egale, la metrique la plus faible, qui est la somme de la
metrique de la route et de celle de son interface; a metrique egale,
l'interface la premiere dans l'ordre de liaison en IPv4, une route choisie
par la pile en IPv6.

Comparaison, famille par famille, ecarts dans cet ordre:
- `tunnel-interface-missing`: l'alias ne designe aucune interface; rien
  d'autre n'est compare;
- `<famille>-plan-route-missing`: une route du plan n'est pas sur l'interface
  du tunnel, a sa destination exacte, sur le lien;
- `<famille>-route-metric`: elle y est, avec une autre metrique;
- `<famille>-interface-metric`: la famille est capturee, et la ligne du tunnel
  est absente, en metrique automatique, ou d'une autre metrique que zero;
- `<famille>-tunnel-extra-route`: une route du tunnel hors du plan et hors
  des classes admises;
- `<famille>-competing-route`: une route d'une autre interface qui gagne,
  pour une destination du plan, contre la route du plan la plus specifique qui
  la contient: prefixe plus long, ou meme prefixe et metrique effective plus
  faible, ou metrique effective illisible.

A meme prefixe et metrique effective egale, ni l'une ni l'autre ne gagne sur
ce que la preuve lit: l'ordre de liaison ne se lit pas. Une telle route, hors
des classes admises, rend UNMEASURED quand rien d'autre n'est un ecart; un
ecart prime.

La legitimite se decide par une regle de forme, comme sous Linux. Une route
est admise quand elle est:
- une route de l'interface de bouclage, ou la route hote d'une adresse portee
  par son interface;
- une route sur le lien vers le reseau exact (longueur non nulle) d'une
  adresse portee par son interface;
- une route hote sur le lien vers une adresse de ce reseau;
- une route sur le lien vers une destination de multidiffusion, limite
  nommee;
- `255.255.255.255/32` sur le lien, limite nommee;
- sur l'interface du tunnel seulement, la diffusion dirigee d'une route IPv4
  du plan de 1 a 30 bits: la route hote de sa derniere adresse. Que Windows
  la cree avec la route du plan et la retire avec elle est mesure pour un
  `/24`; pour les autres longueurs, la classe suit la definition de la
  diffusion dirigee, sans mesure.
Tout le reste est un ecart, et une route par une passerelle n'est jamais
admise.

Le perimetre est `windows-routing-comparison`, la source
`iphelper-tables-read-twice`, et `expected_source` vaut
`bifrost-windows-routing-plan-v1-user-declared` (intention) ou
`daemon-declared-active-routing-plan` (daemon). Le rapport ne porte que des
categories et des comptes: ni interface, ni adresse, ni prefixe, ni LUID.

Mode face au daemon. Le peripherique du tunnel (WireGuardNT, et le coeur sous
Windows) retient le plan que `ipcfg::apply` vient d'executer, apres son
dernier appel reussi (le coeur, une fois le passage ouvert), et l'oublie des
le debut du demontage. Le superviseur le declare dans une forme distincte,
`declaration-routage-windows` (sa propre version; un plan de cinq cles:
chemin, interface, MTU, familles, destinations), lue par le meme lecteur que
les autres preuves: identite du serveur exigee avant le premier octet
(proprietaire du pipe LocalSystem, jamais les Administrateurs; une seule
exigence pour les trois lectures de preuve, jugee par sa recette avec la
decision meme de `bifrost-ipc`), N1, mesure encadree, N2. L'analyse est
stricte (cles exactes, doublons, entiers, version, instance, coherence de
l'etat, du numero et du plan, graphie canonique; la forme Linux est refusee),
et le plan est reconstruit au meme constructeur. Rien de pose: dit sans
comparer.

Limites:
- l'intention est declaree, ce n'est pas le profil actif du daemon;
- un changement qui s'annule entre les deux collectes, ou ce qui est pose
  apres la collecte, n'est pas vu;
- Windows ne porte aucune etiquette de proprietaire sur une route: une route
  identique a celle du plan, posee par un tiers, passe pour celle du produit;
- une route connectee est admise quelle que soit la largeur du reseau de son
  adresse, et la multidiffusion et la diffusion limitee partent sur le lien;
- l'ordre de liaison n'est pas lu: une egalite rend UNMEASURED;
- ne sont pas compares: la MTU et `DadTransmits` des lignes, l'etat de
  connexion de l'interface, la duree de vie des routes, les adresses du
  tunnel;
- ne sont pas prouves: les routes en cache, les connexions ouvertes, une
  source liee a une interface, le pare-feu et le DNS.

MATCH n'est pas une preuve d'etancheite du VPN.

Acceptation, banc jetable Windows a cote d'un daemon reel sous LocalSystem,
LAN ouvert, plan WireGuard sans route par defaut puis capture des deux
familles. Correspondance des deux familles dans les deux modes. Chaque
categorie de route provoquee donne son ecart dans les deux modes, et pour
chacune `Find-NetRoute` dit l'interface que Windows choisit: route du plan
retiree, route en trop sur le tunnel, route plus longue ou moins chere d'une
autre interface, metrique de route ou d'interface qui fait perdre le tunnel
face a une concurrente. Une metrique de route ou d'interface differente sans
concurrente est un ecart au plan sans changement de choix. Une egalite rend
UNMEASURED, et Windows y a choisi le tunnel. Deux declarations differentes
autour de la collecte rendent UNMEASURED; un daemon qui n'est pas sous
LocalSystem est refuse (`daemon-identity`); rien de pose est dit; une
interface absente est un ecart. L'hote est inchange apres chaque serie.

#### D1c.4 - Resolveurs DNS effectifs Linux, par intention, livres

`bifrost-cli --json prove dns --intention intention.json --actif`

L'intention v1 porte exactement `schema_version` (1), `backend`
(`systemd-resolved` ou `resolv-conf`), `interface` (la regle de nom du
produit, sans `lo`), `local_resolver`, `upstream` (1 a 16 adresses sous leur
forme canonique, sans doublon), `embarque` et `resolveur_uid` (`null`, ou le
compte non nul du resolveur embarque, admis seulement avec lui), tous
obligatoires, et doit passer la regle DNS du produit (`DnsPolicy::validate`).
Le backend est declare: le daemon le choisit a l'execution et ne l'ecrit
nulle part. Champs inconnus ou manquants, cles dupliquees, nombres non
entiers et version inconnue sont refuses avant toute lecture du systeme, avec
les plafonds de lecture de D1b.1.

L'attendu est le plan DNS que le produit pose,
`bifrost_core::plan_dns::PlanDns`: le lien du tunnel et les serveurs a
interroger, le resolveur embarque seul quand il y en a un, sinon les amonts
dans l'ordre du profil. Depuis D1c.4, `bifrost_dns::linux` tire de ce plan
les arguments `resolvectl` (`dns <lien> <serveurs>`, puis `domain <lien> ~.`)
et le contenu de `/etc/resolv.conf`: les recettes de lignes exactes d'avant
passent sans retouche. Il n'y a pas de seconde implementation.

Collecte, sans shell, sans programme externe, sans elevation, sans
ecriture:
- `/etc/nsswitch.conf`: les sources de la ligne `hosts`, et la presence de
  `/etc/mdns.allow` quand un module mDNS non minimal y figure;
- `/proc/net/udp`, et `udp6` pour un resolveur embarque IPv6: les ecoutes
  UDP du port 53 du namespace courant et leur compte;
- le contenu de `/etc/resolv.conf`;
- backend `systemd-resolved`: le mode de `/etc/resolv.conf`, calcule comme
  resolved le calcule (inode compare a ceux de ses fichiers uplink, stub et
  statique), les liens du namespace (rtnetlink), et, sur le bus systeme, le
  proprietaire de `org.freedesktop.resolve1` et son compte, les serveurs
  (`DNSEx`) et les domaines (`Domains`) du Manager, le mode qu'il calcule
  (`ResolvConfMode`), ses delegues DNS (`ListDelegates`), et pour chaque lien
  `DefaultRoute`, `ScopesMask` et ses serveurs (`DNSEx` du lien).

La collecte entiere est faite deux fois; deux lectures differentes rendent
UNMEASURED.

Le bus est lu par un lecteur D-Bus ecrit a la main, sans dependance, d'apres
la specification D-Bus 0.43. Il s'authentifie par EXTERNAL, sans negocier de
descripteur, et n'appelle que `Hello`, `GetNameOwner`,
`GetConnectionUnixUser`, `Properties.Get`, `Manager.ListDelegates` et
`Manager.GetLink`, chacun avec `NO_AUTO_START`: un service absent n'est pas
demarre, il est dit absent. `Properties.GetAll` n'est pas employe: il rendrait
des signatures que la preuve ne lit pas. L'adresse est celle que la
specification fixe au bus systeme; la variable d'environnement qui la
remplacerait n'est pas lue. Il lit les signatures `s`, `u`, `o`, `a(so)`
(la presence d'un element, pas son contenu), et une variante qui porte
`a(iiayqs)`, `a(iayqs)`, `a(isb)`, `s`, `b` ou `t`. Les cas suivants rendent
UNMEASURED:
- une autre signature, un descripteur de fichier passe;
- un message tronque, une longueur hors borne (1 Mio par message, 4096
  elements par tableau), un delai de 2 s depasse;
- un boutisme autre que celui de l'hote, une version de protocole inconnue;
- un remplissage non nul, une chaine hors UTF-8 strict, un booleen hors de 0
  et 1, un champ d'en-tete connu du mauvais type ou en double;
- une reponse a un autre appel ou d'un autre emetteur, un appel recu;
- une erreur que le bus rend lui-meme pour un appel qu'il refuse de
  transmettre.
Un signal ou un message d'un type inconnu est saute en entier, et un champ
d'en-tete inconnu d'un type de base aussi, comme la specification l'exige.

Le Manager rend chaque serveur sous l'index de l'interface par laquelle
resolved l'interroge (`dns_server_ifindex`, systemd 255 et 262), pas sous sa
portee: un serveur de bouclage y porte l'index de `lo` quel que soit le lien
qui le porte. Mesure au banc: le resolveur embarque, pose par le produit sur
le lien du tunnel, figure sous `lo` dans le `DNSEx` du Manager. Chaque serveur
est donc rattache a sa portee par le `DNSEx` de son lien: ceux de chaque lien
sont retires un a un du Manager, sous l'index que le Manager doit leur
donner, et ce qui reste est la portee globale. Un serveur de lien que le
Manager ne rend pas rend UNMEASURED.

Gardes, avant toute comparaison, UNMEASURED sinon:
- le bus repond et `org.freedesktop.resolve1` y a un proprietaire;
- le resolved lu est celui du namespace reseau courant: le bus systeme est
  joignable depuis un autre namespace et y rend d'autres liens. L'ecoute UDP
  du stub (`127.0.0.53:53`) doit etre visible ici sous le compte du
  proprietaire du nom, tout index de lien que resolved cite doit exister ici,
  et resolved doit connaitre chaque lien d'ici. C'est une heuristique: un
  processus de ce compte peut lier cette adresse ailleurs, et
  `DNSStubListener=no` rend la preuve UNMEASURED;
- le mode de `/etc/resolv.conf` que resolved calcule est celui que la preuve
  calcule, sinon resolved juge un autre fichier (autre namespace de montage);
- aucun delegue DNS: ces portees (systemd 258 et suivants) ne figurent ni
  dans `DNSEx` ni dans `Domains`;
- chaque serveur qu'un lien declare figure dans le `DNSEx` du Manager.

Ecarts, dans cet ordre:
- `resolv-conf-path` (resolved): `/etc/resolv.conf` n'est ni le stub ni le
  fichier statique de resolved, ou son contenu, lu comme glibc le lit, a une
  ligne `nameserver` qui ne designe pas le stub, ou n'en a aucune. Le mode
  compare des inodes, et un fichier monte sur celui du stub garde son inode:
  mesure au banc, ou ce montage rend le mode `stub` alors que glibc interroge
  l'adresse du fichier monte;
- `resolv-conf-content` (resolv-conf): le fichier differe du rendu du
  produit, au bit pres;
- `hosts-sources`: un module de la ligne `hosts` qui n'est ni `files`, ni
  `myhostname`, ni `mymachines`, ni `dns`, ni (resolved seulement)
  `resolve`, ni un module mDNS de la limite nommee;
- `tunnel-link-scope` (resolved): le lien du tunnel est absent, ou resolved
  n'y tient pas de portee DNS active; son `~.` est alors inerte;
- `tunnel-link-servers` (resolved): les serveurs du lien du tunnel ne sont
  pas exactement ceux du plan, dans l'ordre, au port 53, sans nom TLS;
- `tunnel-link-domains` (resolved): autre chose qu'exactement `~.`;
- `dns-exceptions` (resolved): une autre portee qui a un serveur porte un
  domaine autre que la racine, de routage ou de recherche: elle bat `~.` pour
  ses noms;
- `competing-default-routes` (resolved): une autre portee qui a un serveur
  porte aussi `~.`: les deux sont interrogees;
- `multicast-resolution` (resolved): une portee LLMNR active, sur n'importe
  quel lien: elle prend les noms a une etiquette;
- `local-resolver-listener` (resolveur embarque): aucune ecoute UDP de
  `local_resolver:53`, ou une qui n'est pas sous le compte declare.

La legitimite des autres portees se decide par une regle, sans liste
d'adresses. Une portee autre que celle du tunnel, un lien ou la portee
globale, est admise si elle n'a ni domaine, ni `~.`, ni portee LLMNR: ses
serveurs ne sont alors consultes que lorsqu'aucun domaine ne correspond, ce
que `~.` bat toujours (`dns_scope_good_domain`, systemd 255 et 262). Une
portee sans serveur ne recoit rien. `DefaultRoute` ne change donc pas le
jugement; il est compte.

Limites nommees, ou du trafic DNS peut sortir hors du tunnel alors que la
preuve rend MATCH:
- `.local` par mDNS: une portee mDNS de resolved, ou un module `mdns*` de
  nsswitch (minimal, ou non minimal sans `/etc/mdns.allow`); comptees;
- la recherche inverse d'une adresse du reseau d'un lien fait jeu egal avec
  `~.` sur ce lien;
- les noms a une etiquette quand `ResolveUnicastSingleLabel=yes`, que le bus
  ne dit pas, et, apres systemd 255, quand l'appelant le demande.

Autres limites:
- l'intention est declaree, ce n'est pas le profil actif du daemon;
- systemd anterieur a 255 ou posterieur a 262 n'est ni mesure ni lu: la
  mesure est faite sur systemd 255, les sources relues sont celles de 255 et
  262;
- Varlink (`io.systemd.Resolve`) n'est pas employe: la preuve lit le bus
  D-Bus, et un resolved joignable par Varlink seulement la rend UNMEASURED;
- un changement qui s'annule entre les deux lectures, ou ce qui change apres
  la collecte, n'est pas vu;
- une graphie de l'adresse du stub autre que `127.0.0.53` dans
  `/etc/resolv.conf` est un ecart, meme si glibc la lit comme le stub;
- ne sont pas prouves: les caches (resolved, nscd, applications), les
  connexions ouvertes, les resolveurs propres aux applications, le pare-feu;
  le mode DNS sur TLS n'est pas compare.

Le perimetre est `linux-dns-comparison`, la source
`resolved-dbus-and-system-files-read-twice` ou
`resolv-conf-and-system-files-read-twice`, et `expected_source` vaut
`bifrost-dns-plan-v1-user-declared`. Le rapport ne porte que des categories et
des comptes: ni adresse, ni domaine, ni interface, ni compte. Hors Linux, la
commande lit l'intention puis rend UNMEASURED, sans source.

MATCH n'est pas une preuve d'etancheite du VPN.

Mode face au daemon, non livre. `--politique-daemon` demanderait que le
daemon declare, par une commande IPC distincte, le plan DNS qu'il a pose et
le backend qu'il a choisi, retenus apres la derniere commande reussie et
oublies au debut du demontage, avec le compte du resolveur embarque; la
declaration serait lue par le lecteur commun (identite du serveur, N1, mesure,
N2) et le plan reconstruit au meme constructeur.

Acceptation, banc jetable (`scripts/preuve-dns-linux.sh`): un systemd-resolved
255 reel, sur un bus D-Bus prive, dans un namespace de montage prive et des
namespaces reseau jetables, sans toucher au resolveur ni au bus de l'hote. La
pose du produit, rendue par le produit et appliquee telle quelle par
`resolvectl`, correspond, en compte ordinaire comme en root, avec les memes
comptes. Chaque categorie provoquee donne son seul ecart, et un temoin
d'emission (un repondeur DNS par lien, et une resolution par glibc) dit par
ou la requete sort. Bus absent, resolved absent du bus, bus qui refuse
l'appel ou la connexion, signature inconnue, delegues DNS, autre namespace
reseau et autre namespace de montage rendent UNMEASURED; un domaine qui
bascule pendant la collecte aussi, jamais MATCH. La preuve ne change pas
l'etat du resolveur, et l'hote est inchange apres chaque passage.

D1c reste incomplet. Ne sont pas livres: la preuve DNS face au daemon, les
resolveurs effectifs sous Windows et la provenance.

## D2 - Distribution reproductible et mises a jour verifiables

Pour chaque cible et artefact nomme, deux constructions isolees depuis le meme
commit, lock, toolchain et environnement documente produisent les memes octets.
Varier chemin, heure et identite du constructeur; conserver les divergences,
ne jamais annoncer la reproductibilite sur la seule presence du lock ou du SBOM.
Definir separement le payload reproductible et l'enveloppe signee/horodatee.

Publier manifeste (commit, cible, taille, SHA-256), SBOM correspondant a la
construction exacte, provenance du workflow et signatures. Une attestation
de CI et deux jobs du meme operateur ne sont pas deux constructeurs independants.
Prevoir verification hors ligne, cle racine hors ligne, rotation/revocation et
TUF pour rollback, gel et metadonnees expirees. Aucun auto-update obligatoire.

Acceptation: modifier un octet, retirer une signature, presenter une ancienne
version, une cible incorrecte, une cle revoquee, des metadonnees expirees ou un
telechargement trop grand doit empecher l'installation, sans repli non verifie.
Des cles jetables de test ne sont jamais annoncees comme signatures de release.

## D3 - Controle des sorties reseau

Inventorier toutes les sorties: tunnel, amorcage DNS, acquisition de profils,
catalogues de resolvers, diagnostics, vitalite, mises a jour et coeurs tiers.
Pour chaque sortie: initiateur, phase avant/dans le tunnel, destination,
necessite, donnees envoyees, plafond (paquets/octets/frequence), configuration
et possibilite de refus. Le budget est applique AVANT l'emission, localement;
son epuisement rend le diagnostic indisponible, jamais une exception au kill switch.

Les cibles Google/Cloudflare/gstatic actuelles doivent devenir remplacables.
Un mode sans diagnostic externe et sans acquisition distante doit permettre
de monter un profil local preconfigure. L'absence de serveur Bifrost ne signifie
pas absence de tiers. Pas d'analytics ni identifiant de suivi.

Acceptation: captures avant connexion, connexion, echec, reconnexion et arret;
chaque paquet emis correspond a une permission inventoriee. Budget epuise,
cible refusee et mode hors ligne: aucune emission de diagnostic non autorisee.

## D4 - Sorties au choix et portabilite

Profils locaux ouverts, exportables et importables hors ligne, cles generees
localement, rotation possible sans editeur. Le provisioning est optionnel et
distinct du client. Documenter installation serveur et migration vers un autre
hebergeur. Aucun echec de licence ou d'API centrale ne bloque un profil valide.

Acceptation: profil local utilise alors que tous les domaines de l'editeur
sont injoignables; migration vers un second serveur sans compte Bifrost.

## D5 - DNS a confiance separee

ODoH est une option distincte du DNS chiffre existant. Choix explicite du proxy
et de la cible, administrateurs independants lorsque ce benefice est annonce,
chemin d'amorcage documente, metadonnees expirees refusees. Pas de repli silencieux
vers du DNS ordinaire ou du DoH direct. Garder visible la limite de collusion
proxy/cible et l'absence de protection contre un observateur global.

Acceptation: proxy arrete, cle cible expiree, reponse invalide, changement de
reseau; aucune requete de secours ne contourne la politique consentie.

## D6 - Multihop a operateurs independants

Choisir entree et sortie separement, avec informations d'operateur declarees et
limites de verification. Deux VPS du meme operateur ne suffisent pas a affirmer
l'independance. Le tunnel d'entree porte celui de sortie; echec d'un maillon,
reconnexion ou changement de profil ne doit jamais sortir au premier saut.
Pare-feu, DNS et routes doivent etre juges sur la chaine entiere.

Acceptation: couper chaque maillon, changer une route, injecter une configuration
partielle et tester IPv6/DNS; zero repli mono-saut. Mesurer latence et debit.
La correlation temporelle, la collusion et les identites applicatives restent
des limites. Tor et Nym ont des contrats distincts, pas un label d'anonymat commun.

## Ordre de livraison

1. D1a: comparaison locale d'empreinte et contrat d'export.
2. D1b puis D1c: preuves OS, et reduction des privileges du collecteur.
3. D2: releases verifiables et reproductibilite effectivement reproduite.
4. D3 puis D4: inventaire applique des sorties et parcours d'auto-hebergement.
5. D5 puis D6: DNS separe, multihop mesure. Aucun raccourci sur l'etancheite.

Les defauts de securite existants restent prioritaires. La reduction de
CAP_SYS_ADMIN du daemon est faite le 30/09/2026: le service ne la detient
plus, et la suite de fuite se lance hors de lui. La couverture Windows n'est
pas effacee par ce plan. Chaque tranche met a jour ETAT.md et ses limites.

## Sources primaires relues le 27 septembre 2026

- [Reproducible Builds: definition](https://reproducible-builds.org/docs/definition/):
  comparaison octet pour octet, environnement et artefacts explicites.
- [TUF, specification 1.0.36](https://theupdateframework.github.io/specification/latest/):
  roles, racines, expiration, resistance au rollback et au gel.
- [RFC 9230](https://www.rfc-editor.org/rfc/rfc9230.html): ODoH et separation
  proxy/cible. Specification experimentale, pas garantie globale d'anonymat.
- [nft, manuel officiel](https://netfilter.org/projects/nftables/manpage.html):
  sorties JSON, compteurs variables, handles, politiques et priorites.
- [Noyau Linux, nftables netlink](https://docs.kernel.org/netlink/specs/nftables.html):
  operation getgen et identifiant de generation pour la collecte D1b.2.

## Sources primaires relues le 30 septembre 2026, pour D1c.1

- [Noyau Linux v7.0, `net/core/fib_rules.c`](https://raw.githubusercontent.com/torvalds/linux/v7.0/net/core/fib_rules.c):
  dump des regles sans `NLM_F_DUMP_INTR`, attributs ecrits, et priorite
  choisie pour une regle posee sans `pref` (`fib_default_rule_pref`).
- [Noyau Linux v7.0, `net/core/rtnetlink.c`](https://raw.githubusercontent.com/torvalds/linux/v7.0/net/core/rtnetlink.c):
  CAP_NET_ADMIN exige seulement hors des lectures.
- [Noyau Linux v7.0, `net/ipv4/fib_trie.c`](https://raw.githubusercontent.com/torvalds/linux/v7.0/net/ipv4/fib_trie.c)
  et [`net/ipv6/ip6_fib.c`](https://raw.githubusercontent.com/torvalds/linux/v7.0/net/ipv6/ip6_fib.c):
  dumps de routes sans `NLM_F_DUMP_INTR`, reprise silencieuse d'un dump IPv6
  dont l'arbre change; `fib_lookup_good_nhc` ignore un prochain saut mort, ou
  sans porteuse quand `ignore_routes_with_linkdown` le demande.
- [Noyau Linux v7.0, `net/ipv4/fib_semantics.c`](https://raw.githubusercontent.com/torvalds/linux/v7.0/net/ipv4/fib_semantics.c):
  `fib_nexthop_info`, les seuls drapeaux de prochain saut qu'un dump porte
  (`dead`, `linkdown`, `onlink`, delestage et piegeage materiels).
- [Noyau Linux v7.0, `net/ipv6/route.c`](https://raw.githubusercontent.com/torvalds/linux/v7.0/net/ipv6/route.c):
  une route `anycast` ou `broadcast` posee par un tiers garde son type dans le
  dump sans livrer a l'hote (`rtm_to_fib6_config`, `ip6_rt_get_dev_rcu`);
  l'echeance d'une route n'est ecrite que dans `RTA_CACHEINFO`
  (`rt6_fill_node`).
- [Noyau Linux v7.0, `net/ipv4/route.c`](https://raw.githubusercontent.com/torvalds/linux/v7.0/net/ipv4/route.c):
  `__mkroute_output`, une route `broadcast` ou `multicast` emet sur son
  interface.
- [Noyau Linux v7.0, `net/netlink/af_netlink.c`](https://raw.githubusercontent.com/torvalds/linux/v7.0/net/netlink/af_netlink.c):
  `NLM_F_DUMP_INTR` sur le message de fin, seulement la ou le dump suit une
  sequence.
- [iproute2 6.1.0, `lib/libnetlink.c`](https://raw.githubusercontent.com/iproute2/iproute2/v6.1.0/lib/libnetlink.c):
  un dump interrompu ou tronque est signale sur la sortie d'erreur, avec un
  code de sortie 0.

## Sources primaires relues le 1er octobre 2026, pour D1c.3

- [Microsoft Learn, Chapter 10 - TCP/IP End-to-End Delivery](https://learn.microsoft.com/en-us/previous-versions/tn-archive/bb727011(v=technet.10)):
  choix de la route par l'hote source, IPv4 et IPv6: prefixe le plus long,
  metrique la plus faible, puis ordre de liaison en IPv4 et choix de la pile
  en IPv6.
- [Microsoft Learn, MIB_IPFORWARD_ROW2](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_ipforward_row2):
  la metrique d'une route est un decalage, ajoute a la metrique de son
  interface.
- [Microsoft Learn, MIB_IPINTERFACE_ROW](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_ipinterface_row):
  `Metric`, `UseAutomaticMetric`, `NlMtu`, `DadTransmits`.
- [Microsoft Learn, CreateIpForwardEntry2](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-createipforwardentry2):
  la pose d'une route que le produit emploie.

## Sources primaires relues le 2 octobre 2026, pour D1c.4

- [D-Bus Specification 0.43](https://dbus.freedesktop.org/doc/dbus-specification.html),
  revision du 29/10/2024: format des messages et marshalling, champs
  d'en-tete et leurs types, remplissage nul, booleens, noms valides,
  authentification EXTERNAL et `BEGIN`, `NO_AUTO_START`, adresse du bus
  systeme, messages et champs inconnus a ignorer, methodes du bus.
- [systemd v255, `src/resolve/resolved-bus.c`](https://raw.githubusercontent.com/systemd/systemd/v255/src/resolve/resolved-bus.c):
  `DNSEx`, `Domains`, `ResolvConfMode` et `GetLink` du Manager;
  `bus_dns_server_append`.
- [systemd v255, `src/resolve/resolved-link-bus.c`](https://raw.githubusercontent.com/systemd/systemd/v255/src/resolve/resolved-link-bus.c):
  `DNSEx` (`a(iayqs)`, sans index), `DefaultRoute` et `ScopesMask` d'un lien.
- [systemd v255, `src/resolve/resolved-dns-server.c`](https://raw.githubusercontent.com/systemd/systemd/v255/src/resolve/resolved-dns-server.c)
  et [v262](https://raw.githubusercontent.com/systemd/systemd/v262/src/resolve/resolved-dns-server.c):
  `dns_server_ifindex`, l'index de `lo` pour une adresse de bouclage, quel que
  soit le lien.
- [systemd v255, `src/basic/in-addr-util.c`](https://raw.githubusercontent.com/systemd/systemd/v255/src/basic/in-addr-util.c):
  `in_addr_is_localhost`, `127.0.0.0/8` et `::1`.
- [systemd v255, `src/resolve/resolved-dns-scope.c`](https://raw.githubusercontent.com/systemd/systemd/v255/src/resolve/resolved-dns-scope.c)
  et [v262](https://raw.githubusercontent.com/systemd/systemd/v262/src/resolve/resolved-dns-scope.c):
  `dns_scope_good_domain`, le routage par domaine que la regle de legitimite
  reprend.
- [systemd v255, `src/resolve/resolved-resolv-conf.c`](https://raw.githubusercontent.com/systemd/systemd/v255/src/resolve/resolved-resolv-conf.c):
  `resolv_conf_mode`, l'ordre uplink, stub, statique, et le stub ecrit.
- [systemd v255, `src/resolve/resolved-def.h`](https://raw.githubusercontent.com/systemd/systemd/v255/src/resolve/resolved-def.h):
  les bits de `ScopesMask`.
- [systemd v255, `man/org.freedesktop.resolve1.xml`](https://raw.githubusercontent.com/systemd/systemd/v255/man/org.freedesktop.resolve1.xml),
  [v259](https://raw.githubusercontent.com/systemd/systemd/v259/man/org.freedesktop.resolve1.xml)
  et [v262](https://raw.githubusercontent.com/systemd/systemd/v262/man/org.freedesktop.resolve1.xml):
  l'interface D-Bus, `ListDelegates` apparu en 258.
- [systemd v255, `man/resolved.conf.xml`](https://raw.githubusercontent.com/systemd/systemd/v255/man/resolved.conf.xml)
  et [`man/systemd-resolved.service.xml`](https://raw.githubusercontent.com/systemd/systemd/v255/man/systemd-resolved.service.xml):
  modes de `/etc/resolv.conf`, stub, LLMNR, mDNS,
  `ResolveUnicastSingleLabel`.
- [glibc 2.39, `resolv/res_init.c`](https://sourceware.org/git/?p=glibc.git;a=blob_plain;f=resolv/res_init.c;hb=refs/tags/glibc-2.39):
  lecture des lignes `nameserver` (mot-cle suivi d'un blanc, commentaires
  `;` et `#`, adresse jusqu'au blanc suivant).
- [man-pages, `nsswitch.conf(5)`](https://git.kernel.org/pub/scm/docs/man-pages/man-pages.git/plain/man/man5/nsswitch.conf.5)
  et [`resolv.conf(5)`](https://git.kernel.org/pub/scm/docs/man-pages/man-pages.git/plain/man/man5/resolv.conf.5).
- [nss-mdns, `README.md`](https://raw.githubusercontent.com/lathiat/nss-mdns/master/README.md):
  modules minimaux et `/etc/mdns.allow`.
- [Noyau Linux v7.0, `net/ipv4/udp.c`](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/net/ipv4/udp.c?h=v7.0),
  [`net/ipv6/datagram.c`](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/net/ipv6/datagram.c?h=v7.0)
  et [`include/net/transp_v6.h`](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/include/net/transp_v6.h?h=v7.0):
  le format de `/proc/net/udp` et `udp6`.
