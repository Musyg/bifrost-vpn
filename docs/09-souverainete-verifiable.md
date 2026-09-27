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

#### D1b.2 - Collecte noyau et politique attendue (a faire)

Collecteurs dedies en lecture seule: nftables/netlink sur Linux, enumeration
WFP sur Windows. Comparer famille, couches/hooks, priorites, filtres, exceptions,
interface, destinations autorisees et persistance a une politique attendue
versionnee. Documenter les effets de composition avec les regles tierces.
Lire avant/apres l'identite de la generation active; si elle change pendant
la collecte, rendre NON MESURE. Ne pas confondre absence de table et acces refuse.

Acceptation: regle retiree, exception trop large, filtre tiers prioritaire,
interface remplacee, donnees tronquees, acces refuse, generation modifiee.
Chaque alteration doit supprimer la conformite, avec le controle en cause.
Eprouver sur machines jetables; ne pas couper le reseau du poste de travail.

La collecte Linux devra notamment encadrer le dump par la generation nftables
(`getgen`/`id`), pas par deux horodatages. Deux captures identiques ne prouvent
pas l'absence d'un changement transitoire. La comparaison D1b.1 ne satisfait
donc pas encore le contrat de preuve effective D1b.

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
  operation getgen et identifiant de generation pour la future collecte D1b.2.
