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

Schema nft JSON 1 avec metainfo initiale obligatoire. Tables, chaines et regles
sont comparees, y compris familles, priorites, hooks, politiques, flags,
expressions, commentaires, regles supplementaires et ordre global. Les cles
d'un objet JSON peuvent etre reordonnees, pas les elements d'un tableau.
Seuls les handles d'objets et les deux valeurs `packets`/`bytes` des compteurs
anonymes sont ignores; la presence et la position du compteur restent comparees.
Les informations de version du producteur dans metainfo ne sont pas comparees.
Les expressions sont comparees structurellement, sans interpreteur nft: ce
controle n'est ni un validateur complet de la grammaire nft, ni un simulateur.

Objets autonomes set/map/flowtable/counter et autres types non pris en charge:
UNMEASURED, jamais omis. Meme refus pour un schema inconnu, une cle JSON
dupliquee, une table/chaine dupliquee, un parent absent, un nombre non entier,
un fichier tronque ou inaccessible. Une reference sans chaine de base est
refusee; une capture observee valide mais vide constitue un ecart.

Deux fichiers reguliers immuables, 2 Mio maximum chacun, lecture bornee, liens
detectes au controle initial refuses. Les limites de concurrence et de stockage
de D1a s'appliquent aussi ici. Rapport sans noms, adresses, expressions ni chemins:
seuls les comptes et les categories d'ecart sont exportes. L'intervalle est celui
de la comparaison locale, PAS celui de la collecte des captures.

Acceptation hors ligne: ordre de regles inverse, chaine tierce ajoutee, politique
drop remplacee, priorite/hook/interface/destination/operateur modifies, regle ou
compteur supprime, table dormant, capture vide, invalide et hors perimetre.
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
cette comparaison. Les objets hors perimetre D1b.1 restent NON MESURES.

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
qui portent le nom Bifrost. Une table tierce rend MISMATCH; un objet hors
perimetre rend UNMEASURED. Aucun tri global ni filtre de regles tierces ne peut
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
noyau different de la declaration rend MISMATCH.

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

#### D1b.3c - Identite du serveur livree; autres objets et WFP (a faire)

Identite du serveur de la declaration, livree. Avant d'ecrire le moindre octet,
`prove nft --politique-daemon` exige du processus qui sert `--socket` une
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
laisse d'autres comptes creer des instances peut etre servi par un tiers; celui
du daemon ne le permet pas. Un daemon Windows lance en console eleve cree un pipe
possede par les Administrateurs et n'est pas admis. Les autres commandes de la
CLI ne verifient pas encore le serveur.

Acceptation, banc jetable: un faux daemon qui rejoue la vraie declaration sur un
`--socket` choisi, noyau conforme, rend MATCH sous root et UNMEASURED
`daemon-identity` sous un autre compte, sans recevoir une seule requete.

Collecteurs dedies en lecture seule: enumeration WFP sur Windows. Comparer
famille, couches/hooks, priorites, filtres, exceptions, interface, destinations
autorisees et persistance a une politique attendue versionnee. Documenter les
effets de composition avec les regles tierces. Lire avant/apres l'identite de
la generation active; si elle change pendant la collecte, rendre NON MESURE. Ne
pas confondre absence de table et acces refuse. Verifier cote client
l'identite du processus qui sert la declaration.

Acceptation: regle retiree, exception trop large, filtre tiers prioritaire,
interface remplacee, donnees tronquees, acces refuse, generation modifiee.
Chaque alteration doit supprimer la conformite, avec le controle en cause.
Eprouver sur machines jetables; ne pas couper le reseau du poste de travail.

La collecte Linux D1b.2 encadre le dump par la generation nftables (`getgen`/`id`),
pas par deux horodatages. Deux captures identiques seules ne prouvent pas
l'absence d'un changement transitoire. D1b reste incomplet: sous Linux, l'attendu peut venir de la declaration d'un serveur root, que le
client verifie avant de la lire, mais rien n'etablit que ce serveur est le
daemon; les objets hors perimetre et la couverture WFP manquent. Une
intention permissive ou obsolete n'est pas rendue fiable par le fait que le
produit sait la representer, ni par le fait que le daemon la declare.

### D1c - Routes, DNS et provenance

Ajouter les routes IPv4/IPv6, regles de routage, resolvers effectifs, exceptions
DNS et empreintes des composants charges. Comparer configuration attendue et
etat OS; conserver les limites propres aux caches et connexions deja ouvertes.
Pour la provenance, une reference de confiance doit venir d'un manifeste signe
verifie contre une racine obtenue independamment, avec cible, version et taille.
Une signature de profil ne couvre pas les executables.

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

Les defauts de securite existants restent prioritaires. En particulier, la
reduction de CAP_SYS_ADMIN du daemon et la couverture Windows ne sont pas
effacees par ce plan. Chaque tranche met a jour ETAT.md et ses limites.

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
