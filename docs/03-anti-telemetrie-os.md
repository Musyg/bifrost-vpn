# Cartographie operationnelle de la telemetrie Windows 11 (24H2/25H2) et Linux pour le module anti-telemetrie de Bifrost

## TL;DR
- Sur Windows 11 Home et Pro, AllowTelemetry=0 est silencieusement traite comme 1 (Required): l'elimination reelle exige une combinaison de couches (service DiagTrack desactive + WFP par service + resolveur DNS local), pas une seule cle de registre.
- Le fichier hosts seul est insuffisant (IP en dur dans diagtrack.dll documentees par le BSI, CDN partages Azure Front Door 13.107.x.x, detection Defender HostsFileHijack): la seule methode qui cible reellement svchost par service est le filtrage WFP (approche simplewall).
- La telemetrie Linux (Ubuntu/Debian) est marginale et opt-out en quelques commandes; le vrai probleme est Windows, plus la telemetrie applicative (VS Code, Docker, JetBrains) commune aux deux OS.

## Releve du 22 aout 2026, avant d'ecrire la couche DNS

Ce document a ete confronte a ses sources primaires avant d'en tirer du code.
Ce qu'il dit tient dans l'ensemble; huit points ont bouge ou manquaient. Ils
sont notes ici plutot que corriges dans le corps, pour qu'on voie ce qui a ete
verifie et quand.

**Ce qui n'a pas bouge.** La page "Connection endpoints for Windows 11
Enterprise" porte toujours `ms.date: 2026-06-16`, comme annonce partie 1.1.
dnscrypt-proxy est toujours en **2.1.18**, publiee le 18 juillet 2026.

**Ce qui manquait, et qui compte.**

1. **`hagezi/dns-blocklists` est sous GPL-3.0** (releve sur le `LICENSE` du
   depot). La partie 3 recommande ses listes et la partie 2.3 prend soin
   d'ecarter simplewall pour cause de GPL: la licence des LISTES n'avait pas
   ete verifiee. Bifrost etant MPL-2.0 avec une frontiere de licence tenue par
   une recette, ces listes ne sont pas embarquables. La liste livree est donc
   ecrite dans le depot, entree par entree, a partir de la page Microsoft et de
   `WindowsSpyBlocker` (MIT).
2. **blocky n'est pas necessaire.** La partie 6 le recommande comme resolveur
   local, mais le produit en embarque deja un - dnscrypt-proxy, livre avec le
   chantier du resolveur chiffre - et il sait refuser des noms nativement
   (`[blocked_names]`). Mesure du 22/08 sur essai-windows: 2.1.18 accepte notre
   configuration avec cette section (`Configuration successfully checked`).
3. **La page Microsoft range `www.microsoft.com` sous Diagnostic Data.** Le
   tableau de la partie 1.1 ne le mentionne pas. Une liste construite en
   recopiant la categorie couperait le site de Microsoft.
4. **`self.events.data.microsoft.com` figure DEUX fois**, sous Diagnostic Data
   et sous Office.
5. **`*.pipe.aria.microsoft.com` est range sous Skype**, ou il sert a
   RECUPERER de la configuration. La partie 1.1 le classe en telemetrie pure
   d'apres WindowsSpyBlocker. Il ne fait donc pas que mesurer.
6. **`settings-win.data.microsoft.com` et `settings.data.microsoft.com`**:
   Microsoft ecrit qu'une application qui s'en sert "might stop working".
   Casse, donc profil Strict et non Equilibre.
7. **`definitionupdates.microsoft.com` est range sous Windows Update**, pas
   sous Defender comme l'ecrit la partie 1.1.
8. **La citation d'`AllowTelemetry` n'est pas verbatim.** La partie 1.4 cite
   "0 - No telemetry data is sent from OS components...". La page Policy CSP
   System (`ms.date: 2026-02-27`) ecrit pour la valeur 0: *"Security.
   Information that's required to help keep Windows more secure... Note: This
   value is only applicable to Windows 10 Enterprise, Windows 10 Education,
   Windows 10 Mobile Enterprise, Windows 10 IoT Core (IoT Core), and Windows
   Server 2016. Using this setting on other devices is equivalent to setting
   the value of 1."* Le fond tient - 0 traite comme 1 hors Enterprise,
   Education et Server - mais les mots et les editions nommees different, et
   les valeurs admises sont 0, 1 et 3, sans 2.

**Une mesure que le document demandait sans la donner.** La reponse d'un
resolveur pour un nom refuse: dnscrypt-proxy 2.1.18 rend **NOERROR avec zero
enregistrement**, et non REFUSED. Mesure du 22/08 sur essai-windows, par
`--resolveur-selftest`, avec `www.msftconnecttest.com` comme question de
controle dans la meme execution.

## Releve du 22 aout 2026, avant d'ecrire la couche 1

Deuxieme confrontation du document a ses sources, cette fois sur la partie
registre, services et taches. Six points ont bouge. Les mesures machine ont ete
faites la meme journee sur les deux hotes, pour que la comparaison ait un sens:
**dev-windows, Windows 10 build 19045**, et **essai-windows, Windows 11 25H2
build 10.0.26200.9168**.

1. **Deux des neuf taches planifiees de la partie 1.3 n'existent pas sur 25H2,
   et l'une a simplement change de nom.** Releve par `Get-ScheduledTask`, dont
   l'etat est une enumeration et non une phrase traduite:

   | Tache nommee par le document | dev-windows, 19045 | essai-windows, 26200 |
   |---|---|---|
   | `Application Experience\Microsoft Compatibility Appraiser` | presente | **absente** |
   | `Application Experience\Microsoft Compatibility Appraiser Exp` | absente | **presente** |
   | `Application Experience\ProgramDataUpdater` | presente | **absente** |
   | Les six autres | presentes | presentes |

   Le catalogue porte donc les DEUX noms d'appraiser plus `ProgramDataUpdater`,
   et sur chaque machine celles qui n'existent pas sont dites SANS OBJET. Un
   moteur qui n'aurait garde qu'un seul nom ne ferait rien sur la moitie du
   parc en annoncant la meme chose des deux cotes.

2. **`TurnOffWindowsCopilot` est deprecie, en portee UTILISATEUR, et hors liste
   depuis 24H2.** Le document 03 le range dans un bloc `.reg` sous
   `HKEY_LOCAL_MACHINE`. La page Policy CSP WindowsAI (`ms.date: 2026-06-22`)
   le donne `Location: User Configuration`, donc sous HKCU, avec la note
   *"This policy is deprecated and may be removed in a future release"*, une
   liste de systemes applicables qui s'arrete a Windows 11 23H2, et une
   remarque disant qu'il ne vise pas le nouveau Copilot. Pose sous HKLM comme
   le document l'ecrit, il ne fait rien. Il n'est pas livre.

3. **`RemoveMicrosoftCopilotApp` existe, mais n'a pas de chemin de registre.**
   C'est la politique de desinstallation dediee que le document disait "a
   verifier au moment de l'implementation". Sa correspondance de politique de
   groupe ne porte aucune ligne `Registry Key Name`: elle n'est atteignable que
   par CSP, donc par une gestion de parc. Et elle exclut Pro. Un produit qui
   ecrit le registre ne peut pas la poser.

4. **La page `manage-recall` porte `ms.date: 2025-12-10`**, plus ancienne que
   la page Policy CSP. C'est cette derniere qui donne les chemins:
   `SOFTWARE\Policies\Microsoft\Windows\WindowsAI`, valeurs
   `AllowRecallEnablement` (0 = indisponible, 1 = disponible par defaut) et
   `DisableAIDataAnalysis` (1 = pas d'instantane). Trois politiques du meme
   groupe que le document ne nomme pas: `DisableClickToDo`,
   `DisableSettingsAgent` et `AllowRecallExport`, les deux premieres en
   Insider Preview.

5. **Les cles de politique visees n'existent pas d'avance.** Sur essai-windows,
   `DataCollection` existe et ses valeurs non, tandis que `WindowsAI`,
   `CloudContent`, `AdvertisingInfo` et `InputPersonalization` n'existent pas
   du tout sous `Policies`. Les poser CREE cinq cles. C'est pourquoi le journal
   distingue "la valeur n'existait pas" de "la cle n'existait pas": sans cette
   distinction, un retour en arriere laisse cinq cles de politique vides
   derriere lui. Mesure du meme jour, apres aller-retour complet: les cinq
   cles ont bien disparu.

6. **Une tache active n'ecrit AUCUN `<Enabled>` dans son XML.** Mesure sur
   `Customer Experience Improvement Program\Consolidator`, lue active, puis
   desactivee, puis rendue a son etat: active, le bloc `<Settings>` ne porte
   pas d'element `<Enabled>`; desactivee, il porte `<Enabled>false</Enabled>`.
   L'absence vaut donc `true`, valeur par defaut du schema que `schtasks`
   n'ecrit pas. Un lecteur qui chercherait `<Enabled>true</Enabled>` ne le
   trouverait jamais et conclurait a une tache desactivee partout. Et
   `<Enabled>` apparait AUSSI dans `<Triggers>`, avec un sens different: la
   lecture est ancree sur `<Settings>`.

**Ce que la couche 1 livree ne couvre pas**, et qui reste au plan: le point de
restauration systeme que la partie 6 demande avant toute modification, le
moteur de detection de derive, et les couches 2 (WFP par service) et 4 (fichier
hosts, que le plan deconseille lui-meme pour les domaines Microsoft).

## Releve du 22 aout 2026, avant d'ecrire le plan de la couche 2

Troisieme confrontation du document a ses sources, cette fois sur le blocage
par service. Quatre points, mesures le meme jour sur **essai-windows, Windows
11 25H2 build 10.0.26200.9168**.

1. **`ALE_USER_ID` ne porte pas un SID mais un DESCRIPTEUR DE SECURITE.** La
   page Microsoft Learn des identifiants de condition (`ms.date: 2024-05-02`)
   donne `FWPM_CONDITION_ALE_USER_ID` avec le type
   `FWP_SECURITY_DESCRIPTOR_TYPE`, la ou `FWPM_CONDITION_ALE_PACKAGE_ID`, lui,
   est bien un `FWP_SID`. La condition n'est donc pas une egalite de SID: WFP
   fait un controle d'acces du jeton contre un descripteur. Le depot construit
   deja le bon: `matching_sddl` rend `D:(A;;0x<FWP_ACTRL_MATCH_FILTER>;;;<SID>)`,
   un DACL qui n'accorde qu'a ce SID le seul droit que WFP consulte.

2. **La derivation du SID a partir du nom du service se verifie.**
   `S-1-5-80-` suivi du SHA-1 du nom en majuscules encode en UTF-16LE, lu en
   cinq `u32` petit-boutistes. Deux temoins releves par `sc showsid` le meme
   jour servent de test dans le code, plutot qu'une valeur reputee correcte:

   | Service | SID releve sur la machine |
   |---|---|
   | `DiagTrack` | `S-1-5-80-2620808479-2171380039-3191355562-2070425692-3097948119` |
   | `wuauserv` | `S-1-5-80-1014140700-3308905587-3330345912-272242898-93311788` |

   `wuauserv` est un temoin choisi: c'est le service qu'il ne faut PAS casser,
   et savoir calculer son SID est ce qui permet de verifier mecaniquement
   qu'aucun filtre ne le porte.

3. **Le piege qui rendrait la couche inoperante en silence: `SERVICE_SID_TYPE`.**
   Un service configure en `NONE` ne porte aucun SID de service dans son jeton,
   et la condition ne mordrait jamais - sans erreur, sans trace, avec un filtre
   pose et un rapport vert. Releve du 22/08/2026 par `sc qsidtype`: `DiagTrack`,
   `dmwappushservice`, `DoSvc`, `WerSvc` et `wuauserv` sont tous `UNRESTRICTED`
   sur 26200, donc le cas ne se presente pas ici. Le depot connaissait deja ce
   piege pour son PROPRE service - `service::spec` porte le test
   `le_service_porte_son_propre_sid`, ecrit le 16 aout 2026 apres avoir mesure
   que passer en service sans ca rendait la garantie plus faible qu'en console.
   Ici il vise les services d'en face, et la regle est la meme qu'a la couche 1:
   une cible dont le jeton ne porte pas son SID est SANS OBJET, jamais posee.

4. **`SvcHostSplitThresholdInKB` vaut `0x380000`**, soit 3,5 Go: au-dessus de ce
   seuil chaque service a son propre processus `svchost.exe`. Ca ne sauve pas le
   blocage par chemin pour autant - les processus separes gardent le meme
   chemin, et `ALE_APP_ID` compare un chemin. Ca condamne aussi l'idee de viser
   le PID, qui change a chaque redemarrage du service. Le SID reste le seul
   discriminant stable, ce qui confirme la partie 2.2 du present document.

5. **Deux des cinq binaires emetteurs de la partie 1.3 n'existent pas sur 25H2.**
   Mesure du 22/08/2026 par la commande d'etat des lieux, la meme journee sur
   les deux hotes: `MusNotification.exe` et `WaaSMedicAgent.exe` sont presents
   sur dev-windows (19045) et **absents** de `System32` sur essai-windows
   (26200). `CompatTelRunner.exe`, `DeviceCensus.exe` et `SIHClient.exe` sont
   presents des deux cotes. Meme famille que les deux taches planifiees de la
   couche 1: la liste du document est d'epoque Windows 10, et chaque entree
   doit pouvoir se dire SANS OBJET plutot que de faire echouer la pose.

**Ce qui est livre:** le plan ET la pose. Les filtres vivent dans leur PROPRE
provider et leur propre sublayer, persistants et distincts de ceux du kill
switch, parce qu'ils doivent valoir aussi quand le tunnel est baisse: quelqu'un
qui coupe son VPN ne demande pas a rallumer la telemetrie de son systeme. Le
retrait que la partie 8 exige rejoue une suite de cles FIXES et supprime
chacune en tolerant les absentes, donc sans rien savoir de la politique posee -
utilisable apres un plantage ou par un desinstalleur.

**Mesure du 22/08/2026 sur essai-windows, build 26200, profil Strict**, par
`scripts/telemetrie-reseau-windows.ps1`. L'instrument est `netsh wfp show
filters`, de Microsoft, et non le binaire eprouve: un filtre WFP peut etre
parfaitement present dans le moteur et ne rien bloquer, donc lui demander
a lui-meme s'il est pose ne prouverait rien. 8 cibles posables sur 10, 16
filtres poses, un filtre portant le SID de DiagTrack, **aucun portant celui de
wuauserv**, et apres retrait plus une seule reference au provider. Test de
mutation: en rendant le balayage de retrait inoperant, le banc rougit sur trois
points, dont << une machine filtree par un logiciel absent >>.

**Ce que cette mesure ne prouve PAS**, et qu'il faut dire: que la connexion de
DiagTrack est effectivement refusee. Elle prouve que la politique voulue est
dans le moteur, pas son effet. De meme, l'etape qui verifie que le kill switch
n'est pas touche se declare SKIPPED quand le tunnel est baisse: un temoin qui
passe de zero a zero ne discrimine rien.

## Mesure d'effet du 22 aout 2026: le filtre ne mord pas

La mesure manquante ci-dessus a ete faite le jour meme, par
`scripts/telemetrie-effet-windows.ps1` sur essai-windows. **Elle est negative**,
et cette section existe pour que personne ne relise la precedente en croyant la
couche acquise.

**Le protocole, et pourquoi il est tordu.** Deux temoins evidents ont ete
elimines par la mesure elle-meme:

| Ce qui semblait evident | Ce que la mesure a montre |
|---|---|
| `CompatTelRunner.exe` est LE processus de telemetrie a bloquer | Audit des connexions AUTORISEES actif, sans aucun filtre: **zero** 5156 le citant. Un temoin muet aurait certifie n'importe quel filtre. **La conclusion tiree de ce zero etait fausse, corrigee le 23/08: voir plus bas** |
| Comparer << sans filtre >> puis << avec filtre >> suffit | DiagTrack n'emet qu'une fois par redemarrage. Dans cet ordre, le second passage est vide meme sans filtre, et on aurait attribue au filtre un epuisement de file |

D'ou trois passages ALTERNES, **commences par le cas filtre**, avec l'audit des
succes (5156) actif: sans lui, << bloque >> et << n'a rien tente >> rendent la
meme mesure, c'est-a-dire aucune.

| Passage | Filtres | Connexions autorisees | Refusees | Imputees a la couche 2 |
|---|---|---|---|---|
| A | **poses, 8 dans le moteur, verifies par netsh** | **1, vers `20.42.73.27:443`** | 0 | 0 |
| B | absents | 0 | 0 | 0 |
| C | poses | 0 | 0 | 0 |

Les filtres du passage A etaient poses AVANT le redemarrage de DiagTrack et
leurs `FilterRTID` releves un par un. **DiagTrack est sorti quand meme.** B et C
a zero confirment au passage que le confondant d'ordre etait reel.

**Conclusion, et elle est genante: le filtre est present, il porte le bon SID de
service, et la connexion passe.** La couche 2 est donc posee et retirable, et
son effet n'est pas acquis. Le depot ne doit pas la presenter autrement.

**Trois hypotheses, aucune tranchee.**

1. Le controle d'acces WFP contre le descripteur `matching_sddl` ne reconnait
   pas un SID de service porte comme **groupe** du jeton. `ALE_USER_ID` prend un
   `FWP_SECURITY_DESCRIPTOR_TYPE`, pas un `FWP_SID`, et effectue un controle
   d'acces; il reste a etablir contre quoi.
2. L'arbitrage entre sous-couches donne la main a une autre. La sous-couche
   telemetrie est posee au meme poids que celle du kill switch.
3. La connexion est autorisee a une couche autre que `ALE_AUTH_CONNECT_V4`.

**L'instrument qui trancherait** est le `FilterRTID` porte par le 5156 lui-meme,
qui nomme le filtre GAGNANT. Il n'a pas pu etre lu ce jour-la: la sonde de suivi
a trouve la fenetre vide, DiagTrack ayant epuise sa file.

## La forme du filtre, elle, mord: mesure du 22 aout 2026

Le declencheur deterministe qui manquait a ete construit le meme jour:
`scripts/telemetrie-cause-windows.ps1` installe un service de test jetable dont
le binaire est le daemon en mode `--connect-probe`, lui donne un
`SERVICE_SID_TYPE` unrestricted comme DiagTrack, lit son SID avec `sc showsid`,
et lui pose un blocage de la MEME forme que ceux du catalogue - meme couches,
meme poids, meme veto, meme condition - par `--telemetrie-sonde-sid`. Une sonde
qui poserait autre chose ne mesurerait pas ce qu'on croit.

| Passage | Sonde | Autorisees | Refusees | Filtre gagnant nomme par l'evenement |
|---|---|---|---|---|
| A | absente | **1236** | 0 | `Default Outbound`, rtid 87276, layer 48 |
| B | **posee sur le SID du service de test** | **0** | **569** | **`bifrost telemetrie sonde S-1-5-80-...` (ALE_AUTH_CONNECT_V4), rtid 89674, a nous** |

**Le mecanisme de la couche 2 est donc mesure efficace.** Un blocage
`ALE_USER_ID` portant un SID de service refuse bien la connexion du service qui
porte ce SID, a `ALE_AUTH_CONNECT_V4`, et l'evenement 5157 nomme notre filtre
comme gagnant. Ce n'est pas une inference: le systeme designe lui-meme le filtre
qui a decide.

**Ce qui reste ouvert est donc PROPRE a DiagTrack, et non a la construction.**
Une observation d'echappement tient toujours, et rien ne l'explique encore. Les
deux hypotheses generales sont d'ailleurs eliminees par cette mesure: le
controle d'acces WFP reconnait bien un SID de service porte comme groupe du
jeton, et l'arbitrage entre sous-couches donne bien la main a la notre. Restent
des explications specifiques - toutes a mesurer, aucune retenue.

**La reprise de la mesure sur DiagTrack se declare d'abord SKIPPED, pas verte.**
Relance du banc d'effet le meme soir: trois passages, zero connexion de
DiagTrack dans les trois, y compris sans aucun filtre. Le temoin ne discriminait
plus, donc le banc a refuse de conclure - le contraire aurait ete un vert par
defaut sur une machine muette.

## L'echec est reproduit, et le filtre gagnant est nomme

Relance apres un redemarrage d'essai-windows, la seule condition qui redonne a
DiagTrack de quoi emettre. Machine demarree a 22:39:59, banc lance a 22:47:07 et
termine a 22:51:29, donc **entierement dans la fenetre qui suit le demarrage**.
Le script deploye a ete verifie identique a celui du depot, empreinte SHA-256
comparee des deux cotes, pour qu'on ne mesure pas une version qui aurait derive.

```
  A FILTRE  pid=13172  filtres=8  autorisees=0 refusees=0 dont nous=0
  B sans    pid=2476   filtres=0  autorisees=0 refusees=0 dont nous=0
  C FILTRE  pid=7628   filtres=8  autorisees=2 refusees=0 dont nous=0  40.79.141.153:443
     autorisee par: rtid=89644 layer=48 a nous=non  << Default Outbound >>
     autorisee par: rtid=89644 layer=48 a nous=non  << Default Outbound >>
```

**Verdict du banc: ECHEC.** Deux connexions autorisees alors que les huit
filtres etaient poses et verifies presents. Nettoyage verifie independamment du
banc, et pas seulement d'apres sa derniere ligne: nouveau releve `netsh`, zero
filtre de la couche 2 restant, politique d'audit revenue a << Echec >> seul.

**Le passage B n'apporte rien cette fois, et il faut le dire.** Il est a zero
comme A: la file de DiagTrack ne s'est remplie qu'au moment du passage C.
L'alternance n'a donc pas joue son role ici. Ce n'est pas un probleme pour la
conclusion, parce qu'une connexion autorisee ALORS QUE le filtre est pose se
suffit a elle-meme: c'est le sens meme d'un blocage qui ne bloque pas.

**Ce que la mesure dit, et ce qu'elle ne dit pas.** Elle dit, et c'est un releve:
le filtre gagnant est `Default Outbound`, il n'est pas a nous, et il a AUTORISE.
Le reste est une lecture, pas une mesure: chez WFP un blocage l'emporte sur une
autorisation, donc si une autorisation gagne, la seule explication coherente est
que **notre filtre n'a pas MATCHE**. Ce n'est donc pas un probleme d'arbitrage
entre filtres - piste deja eliminee par la sonde - mais un **controle d'acces
qui echoue**. `ALE_USER_ID` ne porte pas un SID mais un descripteur de securite,
et WFP controle le jeton contre lui.

Le SID de service de DiagTrack est pourtant bien dans le jeton de son processus.

## Les jetons compares, et l'hypothese qui tombe

`scripts/jetons-compare-windows.ps1` lit et compare deux jetons attribut par
attribut: celui de DiagTrack, et celui d'un service de test que notre filtre
bloque. C'est une tranche de LECTURE: elle ne pose aucun filtre.

**La ligne du SID de service est identique au bit pres.**

```
  DiagTrack        S-1-5-80-2620808479-...-3097948119
                     attributs 0x0000000E = ENABLED_BY_DEFAULT+ENABLED+OWNER
  temoin bloque    S-1-5-80-3195187898-...-2059879559
                     attributs 0x0000000E = ENABLED_BY_DEFAULT+ENABLED+OWNER
```

Aucun `USE_FOR_DENY_ONLY`, `SE_GROUP_ENABLED` des deux cotes, zero SID
restreignant, `IsTokenRestricted` NON des deux cotes, memes onze groupes, meme
niveau d'integrite, meme compte `S-1-5-18`. **Ni le groupe ni sa mise en etat
n'expliquent l'echec du controle d'acces.**

**Le `-p` de `svchost -k utcsvc -p` n'est PAS une protection de processus.**
`PS_PROTECTION = 0x00`, type << aucune >>, `IsProtectedProcess=0`,
`IsSecureProcess=0`, et `OpenProcess(PROCESS_QUERY_INFORMATION)` reussit - ce
qu'un PPL refuse. Une piste qu'on aurait pu suivre longtemps sur la foi d'un
drapeau mal lu.

**Une seule difference subsistait**: `TokenHasRestrictions` vaut 1 pour
DiagTrack et 0 pour le temoin, parce que DiagTrack declare une valeur
`RequiredPrivileges` et que le SCM construit alors son jeton en FILTRANT celui
de LocalSystem, 28 privileges ramenes a 10.

## Le jeton filtre est bloque comme l'autre: la derniere piste Windows tombe

`scripts/banc-jeton-filtre-windows.ps1` fabrique deux services **identiques en
tout sauf cet etat** - meme binaire, memes arguments, meme `sc sidtype
unrestricted`, la liste `RequiredPrivileges` du second etant LUE dans la base de
registre de DiagTrack et non recopiee en dur.

| Service | `TokenHasRestrictions` | Privileges | Sans sonde | Avec sonde | Filtre gagnant avec sonde |
|---|---|---|---|---|---|
| `bifrost-jetonlibre` | 0 | 28 | 1252 autorisees | **0 / 621 refusees** | **le notre**, `ALE_AUTH_CONNECT_V4` |
| `bifrost-jetonfiltre` | 1 | 10 | 1226 autorisees | **0 / 673 refusees** | **le notre**, `ALE_AUTH_CONNECT_V4` |

**Reponse: NON.** Un jeton filtre n'echappe pas au blocage `ALE_USER_ID`.
`TokenHasRestrictions` n'a aucun effet sur ce controle d'acces. Le temoin sort
bien sans sonde dans les deux cas, donc la mesure discrimine.

## Ce qu'il reste, et ce n'est plus une subtilite de Windows

Forme du filtre: mesuree bonne. Layer: le bon - `Default Outbound` gagne contre
DiagTrack au layer 48, et c'est au layer 48 que notre filtre bat ce meme
`Default Outbound` sur les services de test. Arbitrage entre sous-couches:
mesure en notre faveur. Jeton: le SID est present et actif. Etat filtre du
jeton: sans effet.

Restaient deux defauts possibles de notre mesure ou de notre code, tous deux
identifies en relisant nos propres bancs. **Les deux ont ete mesures, et les deux
tombent.**

## Ce que la couche pose reellement, condition par condition

L'instrument qui manquait lit le dump `netsh` en DOM et
selectionne par `//item[filterKey]` - jamais un decoupage sur `<item>`, qui sert
aussi aux drapeaux et aux conditions. Profil `equilibre`, releve du 23 aout 2026:

| filterId | nom | condition portee |
|---|---|---|
| 91934 / 91935 | `service-diagtrack` V4 et V6 | `ALE_USER_ID` = `S-1-5-80-2620808479-...-3097948119` |
| 91936 / 91937 | `service-dmwappushservice` V4 et V6 | `ALE_USER_ID` = `S-1-5-80-3841379657-...-70241904` |
| 91938 / 91939 | `binaire-compattelrunner` V4 et V6 | `ALE_APP_ID` = `\device\harddiskvolume3\windows\system32\compattelrunner.exe` |
| 91940 / 91941 | `binaire-devicecensus` V4 et V6 | `ALE_APP_ID` = `\device\harddiskvolume3\windows\system32\devicecensus.exe` |

Tous en `FWP_ACTION_BLOCK`, poids 10, dans notre provider et notre sublayer,
drapeaux `PERSISTENT` **et `CLEAR_ACTION_RIGHT`**: le veto est bien la.

Le SID porte par les filtres 91934 et 91935 est **exactement** celui que
`sc showsid DiagTrack` rend. Dans le dump il apparait sous la forme
`D:(A;;CC;;;S-1-5-80-...)`, `CC` etant la facon dont `netsh` imprime le droit
`0x1`, c'est-a-dire `FWP_ACTRL_MATCH_FILTER`.

**Aucun ecart entre ce que le produit annonce et ce que le moteur porte.**
`--telemetrie-reseau-etat` dit POSABLE pour les quatre cibles avec le SID ou le
chemin exact, et le moteur porte ces quatre cibles sur deux couches.

**La premiere piste tombe donc: le filtre visant DiagTrack a bien ete pose, avec
le bon SID, aux deux couches, avec le veto.**

## Et la connexion observee etait bien celle de DiagTrack, autant qu'on puisse l'etablir

La ligne d'extraction du PID du banc d'effet a ete **falsifiee correcte** sur cet
hote: rejouee telle quelle sous sa propre temporisation, elle rend le meme PID
que `Get-CimInstance`. Et sur 5515 evenements 5156 de la soiree, **un seul PID
de svchost porte exactement deux connexions** vers un point d'arrivee Microsoft,
aux secondes de la mesure, avec le meme `FilterRTID=89644` et le meme
`LayerRTID=48`: le PID 7628, qui etait celui de DiagTrack.

**Ce qui reste non prouve, et qui doit etre dit**: que le PID 7628 etait DiagTrack
a 22:51:02 precisement. L'audit de creation de processus est desactive sur cette
machine, et ce build ne journalise aucun evenement SCM 7036. L'instant de
creation de ce PID n'est plus recuperable; on sait seulement qu'il etait celui de
DiagTrack environ cinquante-six minutes plus tard.

## Il ne reste qu'une hypothese: l'usurpation d'identite

WFP evalue `ALE_USER_ID` contre le jeton **effectif au moment de la connexion**.
Si le fil qui appelle `connect()` usurpe un jeton qui ne porte pas le SID de
service, le filtre ne matche pas - et cela expliquerait tout ce qu'on observe a
la fois: jeton de processus identique a celui d'un service qu'on bloque, filtre
correct et verifie pose, layer correct, et un permit qui gagne.

Un releve a montre que deux des onze fils de DiagTrack portaient un jeton
d'usurpation, tous deux avec le SID de service `ENABLED`. Mais un instantane ne
voit pas une usurpation qui n'existe que le temps d'un appel, et c'est
precisement celle-la qu'il faudrait attraper.

**Deux defauts de l'instrument, nommes, qui empechaient de trancher.** Le banc
d'effet COMPTAIT les filtres sans jamais lire leur condition, donc sans pouvoir
affirmer qu'il eprouvait bien sa cible. Et il lisait le PID une seule fois, deux
secondes apres le demarrage, sans jamais le relire ni retenir le champ
`Application`. Les deux sont corriges, et un releve d'usurpation echantillonne
PENDANT la fenetre y est ajoute.

## La mesure decisive du 23 aout 2026, et elle ferme l'enquete

Redemarrage d'essai-windows a 00:27:53, banc lance a **boot + 6 minutes**, dans
la fenetre ou DiagTrack a de quoi emettre. Cette fois le banc verifie ce qu'il
eprouve, et il l'imprime:

```
   CONTROLE SID  : 2 filtre(s) pose(s) portent EXACTEMENT le SID de DiagTrack
                   id=91964  service-diagtrack (ALE_AUTH_CONNECT_V4)  FWP_ACTION_BLOCK
                   id=91965  service-diagtrack (ALE_AUTH_CONNECT_V6)  FWP_ACTION_BLOCK
   PID au depart : 7384  cree le 2026-08-23 00:33:58.731
   PID au releve : 7384  cree le 2026-08-23 00:33:58.731  (inchange)
   RESULTAT      autorisees=1  refusees=0  dont par nos filtres=0
      AUTORISEE  rtid=89694 layer=48 a nous=non
         nom du gagnant : Default Outbound
         destination    : 20.184.175.16:443
```

**Verdict: ECHEC.** Une connexion autorisee alors que les filtres etaient poses,
verifies presents, **et verifies porteurs du SID de la cible**, avec un processus
dont la continuite est verifiee du debut a la fin de la fenetre.

**L'usurpation ne sauve pas l'explication non plus.** 24 releves, 428 fils
examines, 48 occurrences de fil portant un jeton d'usurpation - et les 48
portent le SID de service de DiagTrack, `ENABLED`, attributs `0x0000000E`, sans
`USE_FOR_DENY_ONLY`. **Ce n'est pas un jeton qui echapperait au filtre: c'est un
jeton que le filtre devrait mordre exactement comme celui du processus.**

Le lecteur d'usurpation est **falsifie**, et c'etait indispensable: un lecteur
qui serait retombe en silence sur le jeton du PROCESSUS aurait imprime
exactement la meme chose. Eprouve sur un processus dont un fil usurpe une
identite differente de la sienne, il rend l'identite du FIL (`ANONYMOUS LOGON`)
la ou le processus en a une autre, et 22 fils sur 23 rendent `ERROR_NO_TOKEN`.
Un repli aurait rendu l'identite du processus partout, et 23 jetons.

Les trois controles du banc sont falsifies eux aussi. Le controle du SID: en
mutant d'UN caractere le SID attendu, le banc **abandonne avant de redemarrer
quoi que ce soit** et sort en 1. La continuite du PID: en lui faisant croire que
le processus a change, la mesure est **invalidee** avec sa raison, et le verdict
devient SKIPPED - << un passage invalide n'est pas un passage sans connexion >>.
Le lecteur de jeton absent: l'etape se declare SKIPPED trois fois plutot que de
disparaitre en silence.

**Et le banc qui a mesure est bien celui du depot, verifie des DEUX cotes de la
fenetre.** L'empreinte du fichier depose sur essai-windows avait ete comparee a
celle du depot AVANT la mesure; elle l'a ete de nouveau APRES, parce qu'une
tache suspendue trainait et qu'un `Set-Content` mort-ne aurait pu reecrire le
fichier une fois la mesure faite. Meme taille, meme SHA-256, et surtout un
instant d'ecriture reste celui du depot initial et non celui de l'arret de la
tache: le passage complet a donc ete produit par le code exact qui est dans
`scripts/telemetrie-effet-windows.ps1`. Verifier l'instrument avant de mesurer
ne suffit pas quand quelque chose peut encore ecrire apres.

## Ce qu'il faut en conclure, et ce qu'on ne sait toujours pas

**Le mecanisme fonctionne.** Un blocage `ALE_USER_ID` portant un SID de service
refuse la connexion du service qui porte ce SID: mesure sur un service de test
ordinaire, et sur un service de test au jeton filtre, avec le 5157 nommant notre
filtre dans les deux cas.

**DiagTrack y echappe, deux fois, et aucune explication mesurable ne survit.**
Filtre pose et verifie porteur du bon SID, a la bonne couche, avec le veto, dans
notre sous-couche. Jeton du processus portant le SID actif. Jetons d'usurpation
portant le SID actif. Processus continu. Et `Default Outbound` gagne.

**Une seule reserve honnete subsiste, et l'instrument ne peut pas la lever**: un
echantillonnage a 9 secondes d'intervalle ne voit pas une usurpation qui
n'existerait que le temps d'un appel. Ce qui est etabli, c'est que les fils qui
usurpent de facon DURABLE portent le SID actif. Trancher demanderait de capturer
le jeton effectif a l'instant du `connect()` - un ETW sur
`Microsoft-Windows-Kernel-Process`, ou une sonde en mode noyau.

**Consequence pour le produit, et elle est nette: la couche 2 ne doit pas etre
annoncee comme bloquant DiagTrack.** Ce qui eteint DiagTrack, c'est la couche 1,
qui met son service en demarrage 4. Le present document le disait avant toute
cette enquete, dans le catalogue lui-meme: << l'eteindre est plus sur que
d'esperer le filtrer >>. La mesure lui donne raison.

**Et il faut dire aussi ce qui n'a pas ete mesure**: les autres cibles du
catalogue - `dmwappushservice`, `CompatTelRunner`, `DeviceCensus`, et les six du
profil strict - n'ont jamais ete eprouvees. Le mecanisme marche, une cible
mesuree lui echappe, les autres sont inconnues.

## DiagTrack n'est PAS un cas particulier: une deuxieme vraie cible echappe

La phrase ci-dessus a tenu une demi-journee. Les quatre autres services du
catalogue ont ete eprouves le 23 aout, et l'un d'eux a repondu.

**`DoSvc` echappe, avec la signature EXACTE de DiagTrack.** Mesure refaite deux
fois, par l'agent puis par l'orchestrateur separement, sur des redemarrages
differents du service:

```
   filtres portant exactement le SID de DoSvc : 2   (sur 16 filtres de couche 2)
   PID au depart : 7460  demarre a 02:16:45.193
   PID au releve : 7460  demarre a 02:16:45.193   (inchange)
   total pour le PID 7460 : autorisees=26  refusees=0
      AUTORISEE rtid=89694 layer=48 dst=72.153.5.131:443
      AUTORISEE rtid=89694 layer=48 dst=23.212.193.114:443
      AUTORISEE rtid=89694 layer=48 dst=72.145.35.103:443
```

Filtre pose, verifie porteur du SID exact, processus continu, seul dans son
`svchost` - et `Default Outbound` gagne, exactement comme pour DiagTrack.

**Le contraste est etabli dans la MEME session, sur le MEME moteur, a cinq
minutes d'intervalle.** `telemetrie-cause-windows.ps1` fabrique un service de
test et lui applique un blocage de la meme forme: **0 autorisee, 609 refusees**,
le 5157 nommant notre filtre. Le moteur mord donc bien a cette heure-la, sur
cette machine-la, avec ce binaire-la.

### Ce que cette deuxieme cible ELIMINE, et c'est neuf

DiagTrack et DoSvc different sur tout ce qu'on aurait pu soupconner:

| | DiagTrack | DoSvc |
|---|---|---|
| compte | `LocalSystem` | `NT Authority\NetworkService` |
| groupe `svchost` | `-k utcsvc -p` | `-k NetworkService -p` |
| demarrage | automatique | `AUTO_START (DELAYED)` |
| destinations | `20.184.175.16:443` | `72.153.5.x:443`, `23.212.193.114:443` |

**Ni le compte, ni le groupe `svchost`, ni le type de demarrage ne sont le
discriminant.**

### Une piste ouverte puis refermee: les regles de pare-feu du vrai service

L'arbitrage entre sous-couches avait ete ecarte - mais sur un service de TEST,
pour lequel Windows ne pose aucune regle. Un vrai service en a, et le controle
de l'orchestrateur l'a montre par accident: en cherchant le SID de DoSvc dans
TOUT le moteur au lieu de le chercher dans notre seul provider, il en a trouve
**74** au lieu de 2.

Les 72 autres appartiennent a Windows. Verification faite, **ils sont tous
ENTRANTS**: `ALE_AUTH_LISTEN_V4/V6`, `ALE_AUTH_RECV_ACCEPT_V4/V6`,
`ALE_RESOURCE_ASSIGNMENT_V4/V6`, tous nommes << Delivery Optimization (TCP-In) >>
ou << (UDP-In) >>, dans `FWPM_SUBLAYER_MPSSVC_WF` et `FWPM_SUBLAYER_TEREDO`.
**Aucun sur `ALE_AUTH_CONNECT`**, la couche 48 ou se joue la sortie. La piste se
referme: qu'un vrai service ait des regles de pare-feu ne ressuscite pas
l'arbitrage.

### Ce qui survit, et c'est une HYPOTHESE, pas une mesure

> **PERIMEE le 23 aout 2026, quelques heures apres avoir ete ecrite.** W32Time
> est heberge dans `svchost.exe` et il se bloque. L'hebergement n'est pas le
> discriminant. La section est conservee telle quelle: elle dit ce qu'on croyait
> et a quel moment, ce qui est la seule facon de relire une enquete sans se
> mentir. La suite est plus bas, << L'hypothese svchost tombe >>.

Les deux cibles qui echappent sont des services Windows **heberges dans
`svchost.exe`**. Les trois temoins qui sont bloques - `bifrost-jetonlibre`,
`bifrost-jetonfiltre`, `bifrost-temoin` - portent **leur propre binaire**. Avec
DiagTrack seul, << svchost >> et << DiagTrack >> etaient confondus; ils ne le
sont plus.

Trancher demanderait un service de test **heberge dans svchost**: une DLL de
service enregistree sous un groupe `svchost`, avec son propre SID, bloquee par la
meme sonde. Il n'a pas ete construit - cela demande une DLL et des ecritures
registre - et tant qu'il ne l'est pas, ceci reste une hypothese.

### Les trois autres, et pourquoi elles ne disent rien

Aucune n'est un echec du filtre: dans les trois cas **le temoin n'emet pas**, et
un temoin muet ne certifie rien.

- **`dmwappushservice`**: demarre trois fois, seul dans son `svchost`, et zero
  connexion, y compris sur dix minutes d'inactivite. Aucun `omadmclient` ni
  `deviceenroller`. Il faudrait un enrolement MDM, absent de cette machine.
- **`CDPSvc`**: vivant 48 tours sur 48 pendant dix minutes, redemarrages
  compris, et zero evenement. `wlidsvc` est arrete et la machine ne porte que des
  comptes locaux: pas de compte Microsoft, donc rien a synchroniser.
- **`WerSvc`**: le declencheur MARCHE - trois rapports `AppCrash_powershell.exe`
  produits - mais le service lui-meme n'emet rien. Voir juste en dessous.

### Deux defauts du catalogue, trouves en chemin

**`service-wersvc` vise a cote, et c'est structurel.** Le reseau de Windows Error
Reporting n'est pas fait par le service mais par `WerFault.exe`, un processus
distinct portant son propre jeton. Releve, verifie deux fois:

```
  01:49:20.874  id=5156  pid=11136  135.234.160.245:443  rtid=89694 layer=48
      \device\harddiskvolume3\windows\system32\werfault.exe
  01:50:52.730  id=5156  pid=7328   135.234.160.245:443  rtid=89694 layer=48
  01:52:24.948  id=5156  pid=16988  135.233.45.223:443   rtid=89694 layer=48
```

Le premier et le troisieme tombent DANS des passages ou les filtres etaient
poses. Un `ALE_USER_ID` sur le SID de `WerSvc` ne peut pas les matcher **par
construction**: ce n'est pas une defaillance du mecanisme, c'est une cible mal
choisie. Sa place est du cote `ALE_APP_ID`.

> **FAIT le 23 aout 2026**, une fois `ALE_APP_ID` mesure mordant. L'entree est
> devenue `binaire-werfault`, sur `System32\WerFault.exe`, chemin verifie sur
> dev-windows et non suppose. Deux gardes la tiennent, chacune sur une facon
> differente de se tromper: l'une refuse le retour a `Cible::Service`, l'autre
> refuse qu'on perde la cible en croyant la deplacer.
>
> **`SysWOW64\WerFault.exe` existe aussi et n'est PAS vise.** Aucune sortie
> n'en a ete relevee; le poser sans mesure serait annoncer une protection sans
> preuve. Le trou est nomme dans le code, a cote de l'entree, plutot que
> comble a l'aveugle.
>
> Ce qui n'est toujours pas mesure: que ce filtre-la refuse une sortie REELLE
> de `WerFault.exe`. Ce qui est mesure, c'est que le MECANISME mord. La
> difference est exactement celle qui a piege `ALE_USER_ID`, et elle demande
> essai-windows et un plantage provoque.

**`CDPUserSvc` est nomme dans la partie 1.3 de ce document et absent des deux
catalogues.** Il tourne sous `CDPUserSvc_87a25`, et le suffixe est propre a
l'installation: une derivation de SID a partir d'un nom fixe ne peut pas
l'atteindre. C'est un trou de couverture, pas un defaut de mecanisme.

### `ALE_APP_ID` mord, et c'est la premiere bonne nouvelle de l'enquete

Le second mecanisme du catalogue a enfin sa mesure d'effet, le 23 aout, avec un
temoin qu'on commande: une copie jetable du daemon a un chemin a nous.

| Passage | Nos filtres | Code de sortie du temoin | Autorisees | Refusees | Dont nos filtres |
|---|---|---|---|---|---|
| A | 2 | **3 BLOQUE** | 0 | **636** | **636** |
| B, sans filtre | 0 | **5 CONNECTE** | **1225** | 0 | 0 |
| C | 2 | **3 BLOQUE** | 0 | **639** | **639** |

Le 5157 nomme le gagnant: `bifrost telemetrie sonde binaire ...`
(`ALE_AUTH_CONNECT_V4`), couche 48. Au passage sans filtre, c'est
`Default Outbound`. **Les deux signaux independants concordent** - le code de
sortie de `--connect-probe`, qui ne depend d'aucun journal, et le journal, seul
a nommer le gagnant.

Le contexte rend la nouvelle importante: `ALE_USER_ID` mord aussi, mais deux
vraies cibles lui echappent. Ici, le mecanisme mord sur un binaire jetable -
**et aucune vraie cible du catalogue n'a encore ete eprouvee sous filtre.**

`ALE_AUTH_CONNECT_V6` reste **pose seulement**: la cible du temoin est en IPv4,
donc le filtre V6 porte le bon chemin et n'a jamais ete sollicite.

### Correction: `CompatTelRunner.exe` SE CONNECTE

Ce document affirmait le contraire, et cette page le repetait a trois endroits.
**C'etait faux, et la facon dont c'etait faux est exactement le piege que le
document pretendait avoir evite.**

Les quatre taches planifiees qui lancent `compattelrunner.exe` **n'avaient
jamais tourne**: `dernier essai: 30.11.1999 00:00:00`, resultat `267011`, soit
`SCHED_S_TASK_HAS_NOT_RUN`. Demarrees explicitement le 23/08, elles rendent 0 -
et le binaire emet:

```
  02:59:00.005  id=5156  pid=15788  57.153.246.3:443    rtid=89694 layer=48
      \device\harddiskvolume3\windows\system32\compattelrunner.exe
  02:59:00.205  id=5156  pid=15788  213.55.139.105:80   rtid=89694 layer=48
```

Verification independante: `MareBackup` n'a **aucun declencheur** et aucune
prochaine execution; `Microsoft Compatibility Appraiser Exp` a un declencheur
mais aucune prochaine execution non plus. Elles ne partent pas seules sur cette
machine. Et une tache soeur non declenchee porte encore le marqueur
`30.11.1999 / 267011`, ce qui corrobore l'etat d'avant.

**Le zero mesurait le declencheur, pas le binaire.** La lecon du document -
<< un temoin muet certifie n'importe quoi >> - etait juste; la conclusion qu'on
en avait tiree ne l'etait pas. Constater qu'un temoin est muet n'autorise pas a
dire POURQUOI il l'est.

Deuxieme consequence, moins agreable: son emission n'est **pas rejouable a
volonte**. Elle depend d'un etat, le premier passage de l'appraiser. Une mesure
d'effet sur lui demandera une machine dont l'appraiser n'a pas encore tourne.

### Ce que le catalogue `ALE_APP_ID` couvre reellement sur 25H2

Reconnaissance faite sans rien poser, avec l'audit des succes actif et un
controle positif a chaque passage - une copie jetable du daemon sortant en clair,
466 puis 448 evenements la portant, donc le journal enregistrait bien au meme
instant.

| Cible | Etat mesure |
|---|---|
| `CompatTelRunner.exe` | **EMET**, une fois, quand on declenche ses taches |
| `DeviceCensus.exe` | **MUET**: a tourne deux fois, zero evenement les deux fois |
| `MusNotification.exe` | **SANS OBJET**: absent de `System32`. Ses 4 taches rendent `2147942402`, `ERROR_FILE_NOT_FOUND` |
| `WaaSMedicAgent.exe` | **SANS OBJET**: absent. La tache `PerformRemediation` existe mais son action a un `Execute` **vide**, c'est un gestionnaire COM |
| `SIHClient.exe` | **PRESENT, aucun declencheur**: aucune des 274 taches de la machine ne le nomme. Son lanceur est `UsoSvc` |

**Le catalogue `ALE_APP_ID` protege donc, sur ce build, une cible et demie.**
Deux entrees sur cinq sont sans objet, une n'a pas de declencheur, une est
muette. Ce n'est pas un defaut du mecanisme - il mord - c'est un constat de
couverture, et il doit etre dit.

Pourquoi `DeviceCensus` est muet n'est **pas** mesure. Qu'il ecrive dans le
magasin de telemetrie et que DiagTrack televerse est une hypothese.

### Ce que le produit a le droit de dire, revise

**Les quatre cibles `ALE_USER_ID` qui restent au catalogue sont TOUTES des
services heberges dans `svchost.exe`**: `DiagTrack`, `dmwappushservice`,
`DoSvc`, `CDPSvc`. La cinquieme, `WerSvc`, est passee du cote `ALE_APP_ID` le
23/08 sous l'identifiant `binaire-werfault`. Des quatre restantes, deux sont
mesurees echappant et deux n'ont pas pu etre eprouvees faute de temoin qui
emette. **Aucune des quatre ne doit etre annoncee comme bloquee.** Ce qui eteint
la telemetrie, aujourd'hui, c'est la couche 1.

**Arbitrage du 05/09/2026:** la couche 2 reste posee et retirable, et le produit
la presente comme << defense en profondeur, jamais la couche qui porte la
promesse >>, parce que `ALE_USER_ID` fait un controle d'acces contre le jeton
capture a la creation de la socket, que deux cibles (`DiagTrack`, `DoSvc`) y
echappent par usurpation a cet instant, et que la regle de Microsoft
(`New-NetFirewallRule -Service -Action Block`) echoue identiquement (mesure du
23/08/2026, essai-windows).

### L'hypothese << svchost >> tombe, et c'est W32Time qui la tue

`W32Time` est heberge dans `svchost.exe -k LocalService`, il tourne sous
`NT AUTHORITY\LocalService`, son `SERVICE_SID_TYPE` est `UNRESTRICTED` - et
**il se bloque**. Mesure du 23 aout 2026 sur essai-windows, deux series
independantes: **9 refus sur 9 connexions**, le 5157 nommant notre filtre.

L'hebergement dans `svchost.exe` n'est donc pas le discriminant. C'etait la
derniere hypothese structurelle, et elle tombe sur un service du systeme, pas
sur un montage a nous.

Le temoin que la section perimee reclamait - une DLL de service enregistree sous
un groupe `svchost`, avec son propre SID - **a ete construit**
(`crates/bifrost-temoin-svchost`, et son banc `telemetrie-svchost-windows.ps1`).
Il **n'a pas ete lance**, et c'est un choix qui se dit: W32Time repond a la meme
question, plus tot et mieux, parce que c'est un vrai service de Windows et non
un montage dont on pourrait suspecter la representativite. Le crate est livre
comme instrument disponible, pas comme mesure faite.

### DoSvc echappe aussi a la sonde SEULE, et cela ecarte un confondant

Sur toute l'enquete jusque-la, le clivage bloque/echappe etait parfaitement
confondu avec un second clivage que personne n'avait isole: **la sonde seule
(deux filtres) bloquait, quatre fois sur quatre; le catalogue (huit ou seize
filtres) echappait, deux fois sur deux.** Le nombre de filtres poses, ou leur
voisinage dans la sous-couche, restait une explication possible.

Trois passages sur `DoSvc`, la sonde posee SEULE, verifies porteurs du SID exact,
PID continu du debut a la fin:

```
A - SONDE SEULE   nos filtres portant le SID de DoSvc : 2   autorisees=25  refusees=0
B - SANS RIEN     nos filtres portant le SID de DoSvc : 0   autorisees=25  refusees=0
C - SONDE SEULE   nos filtres portant le SID de DoSvc : 2   autorisees=25  refusees=0
```

Le confondant est ecarte: **DoSvc echappe des deux facons.** Au passage, cela
etablit qu'il faut pouvoir sonder une cible DU CATALOGUE - or `plan_sonde_binaire`
refuse par construction les binaires du catalogue, alors que `plan_sonde` autorise
les services. L'asymetrie est notee comme dette, pas corrigee ici.

### La protection de processus ne discrimine pas non plus

Mesure lecture seule, sans lire aucune memoire: un processus protege accorde
`OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` et refuse
`PROCESS_QUERY_INFORMATION` avec l'erreur 5.

```
  W32Time      limited=OK  full=OK        -> non protege   BLOQUE
  DiagTrack    limited=OK  full=OK        -> non protege   ECHAPPE
  DoSvc        limited=OK  full=REFUS 5   -> PROTEGE (PPL) ECHAPPE
  Dnscache     limited=OK  full=OK        -> non protege
```

Un bloque non protege, un echappant non protege, un echappant protege: la
protection ne separe rien.

### CE N'EST PAS NOTRE FILTRE: la regle de Microsoft echoue identiquement

C'est la mesure qui ferme l'enquete, et elle ne construit rien. Elle demande a
Windows de poser LUI-MEME la politique, par `New-NetFirewallRule -Service <nom>
-Direction Outbound -Action Block`, puis lit qui gagne. Meme script, meme
machine, meme session, seul le service change.

| | `W32Time` | `DoSvc` |
|---|---|---|
| compte d'execution | `NT AUTHORITY\LocalService` | `NT Authority\NetworkService` |
| `SERVICE_SID_TYPE` | `UNRESTRICTED` | `UNRESTRICTED` |
| filtres poses par Windows | 6, rtid 92218-92223 | 6, rtid 92224-92229 |
| couches | `ALE_AUTH_CONNECT_V4` x3, `_V6` x3 | identique |
| profils couverts | 1, 2, et un sans condition | identique |
| tous porteurs du SID du service | oui | oui |
| **resultat** | **0 autorisee, 5 refusees** | **25 autorisees, 0 refusee** |
| filtre gagnant | `bifrost-essai-regle-microsoft` (rtid 92220) | `Default Outbound` (rtid 89694) |
| second signal independant | `w32tm /resync` echoue: << aucune donnee de temps >> | - |

La condition posee par Windows, relevee dans le moteur:

```
condition : FWPM_CONDITION_ALE_USER_ID FWP_MATCH_EQUAL
            = O:SYG:SYD:(A;;CCRC;;;S-1-5-80-3055155277-...-2193176987)
action    : FWP_ACTION_BLOCK
couche    : FWPM_LAYER_ALE_AUTH_CONNECT_V4
sous-couche: FWPM_SUBLAYER_MPSSVC_WF   poids 10
```

C'est exactement la forme de nos filtres. **Notre implementation est hors de
cause**: la construction de Microsoft, sur le service de Microsoft, avec le SID
que Microsoft derive lui-meme, echoue de la meme facon.

Un detail releve en passant, et qui corrige une croyance de ce document: sur
25H2, une regle `-Service` produit un filtre a **deux** conditions seulement,
`ALE_USER_ID` et `ORIGINAL_PROFILE_ID`. Pas de `ALE_APP_ID` sur `svchost.exe`,
contrairement a ce que decrivaient les sources de 2019. La politique de Windows
et la notre sont donc structurellement identiques.

### La cause, et elle est documentee, pas devinee

`FWPM_CONDITION_ALE_USER_ID` **n'est pas une comparaison de SID**. C'est un
**controle d'acces**: la condition porte un descripteur de securite, et le moteur
fait un `AccessCheck` contre le jeton **capture a la CREATION DE LA SOCKET**, par
le pilote TCP/IP, au moment ou AFD configure la socket. Si le thread qui cree la
socket **usurpe l'identite d'un client** a cet instant, le jeton capture est
celui du client, et le SID de service n'y figure pas. Le filtre ne MATCHE pas -
et un BLOCK qui ne matche pas ne gagne pas, ce qui explique qu'un PERMIT de poids
inferieur l'emporte.

Microsoft l'ecrit, dans le fil WFP << Filtering by service name >> cite par
l'archive des forums:

> Block by service name uses Service SID as filtering condition. There are cases
> when a service impersonates when it binds to the socket. In such cases, traffic
> is sent in context of user and SID that is being examined by WFP is the user's
> SID and not the service SID. Hence block by service name doesnt work.

Et, dans le meme fil archive: << Since a service can manipulate its token,
perhaps by impersonating a client, I don't think that "service name" rules can be
guaranteed to work (it will depend on how the service is designed/coded). >>

**Sources, relevees le 23 aout 2026** - dates de publication telles qu'affichees
par chaque source, non inferees:

| Source | Nature | Date affichee | Ce qu'elle etablit |
|---|---|---|---|
| Microsoft Learn, archive des forums MSDN/TechNet, << Firewall rule doesn't work >>, `f2bf0f58-6332-44ec-81c9-61e2b42097dd` | fil archive par Microsoft, cite le fil WFP << Filtering by service name >> marque resolu | fil du 16/01/2019, archive mise a jour le 11/01/2024 | l'usurpation au moment du `bind` fait echouer le blocage par nom de service; cas releve sur `CryptSvc` et sur le spouleur |
| Project Zero, J. Forshaw, << Understanding Network Access in Windows AppContainers >> | recherche primaire | aout 2021 | `ALE_USER_ID` porte un descripteur de securite evalue par controle d'acces; le jeton est capture par le pilote TCP/IP **a la creation de la socket** |
| G. Nebbett, << Windows Filtering Platform and Windows Service Hardening rules >> | analyse de trace | avril 2022 | la trace WFP porte un `TOKEN_ACCESS_INFORMATION`, dont les SID sont extractibles; c'est bien un jeton, pas un SID isole |
| `metablaster/WindowsFirewallRuleset`, page << Problematic network traffic >> | jeu de regles maintenu, source secondaire | consultee le 23/08/2026 | nomme `CryptSvc`, `wlidsvc`, `wuauserv` et `BITS` comme non filtrables par SID de service, et recommande de retomber sur `svchost.exe` + comptes |

Ce que ces sources **n'etablissent pas**, et qu'il ne faut pas leur faire dire:
aucune ne nomme `DiagTrack` ni `DoSvc`. Le mecanisme est documente, son
application a nos deux cibles est **inferee** du fait qu'elles presentent la
signature decrite et qu'aucune autre explication n'a survecu aux mesures.

### Et l'usurpation est MESUREE, pas seulement documentee

Les sources disent le mecanisme. Restait a etablir qu'il est bien celui qui joue
ici, sur cette machine, sur ces deux services. Il se mesure, et voici comment.

L'en-tete d'un net event WFP porte un champ `userId`: **l'utilisateur du jeton
capture**, celui-la meme contre lequel le controle d'acces est fait. Il n'est
renseigne que sur un REFUS. On force donc un refus par une regle qui ne depend
d'AUCUNE identite - une adresse ou un port de destination - et on lit le champ.

Mesure du 23 aout 2026 sur essai-windows, banc
`telemetrie-jeton-capture-windows.ps1`:

| | `W32Time` (se bloque) | `DoSvc` (echappe) |
|---|---|---|
| compte d'execution du service | `NT AUTHORITY\LocalService` = `S-1-5-19` | `NT Authority\NetworkService` = `S-1-5-20` |
| refus imputes a la regle | 4 | 10 |
| dont **rattaches au PID du service** | **4 sur 4** | **4 sur 10**; les 6 autres sont d autres processus, ecartes |
| `appId` du jeton capture | `\device\harddiskvolume3\windows\system32\svchost.exe` | identique |
| **`userId` du jeton capture** | **`S-1-5-19`** | **`S-1-5-21-...-1001`** |
| deuxieme serie, quelques minutes plus tot | - | 13 refus, meme `userId` |
| ce jeton est-il celui du service ? | **oui**, c'est son compte | **non**, c'est un compte UTILISATEUR |

`S-1-5-21-...-1001` est un SID de compte local ou de domaine, RID 1001: le premier
compte interactif de la machine. Le service tourne sous `NetworkService` et la
socket a ete creee sous l'identite d'un humain. **C'est exactement la signature
que decrivent les sources**, relevee ici, sur notre cible.

Ce que cette mesure etablit, et ce qu'elle n'etablit pas - la distinction
compte:

- **Etabli**: le jeton capture a la creation de la socket, pour les connexions
  de `DoSvc`, a pour utilisateur un compte humain et non le compte du service.
  Donc le thread usurpait a cet instant.
- **Etabli**: pour `W32Time`, qui se bloque, le meme champ rend son propre
  compte d'execution. Le temoin negatif tient: le banc sait lire un jeton non
  usurpe et le distinguer.
- **NON etabli directement**: que le SID de service soit ABSENT de ce jeton. Le
  champ `userId` rend l'utilisateur, pas la liste des groupes. L'absence se
  DEDUIT du fait que le filtre ne matche pas, ce qui est le sens meme du
  controle d'acces - un jeton portant encore le SID de service aurait matche.

Quatre defauts de lecture ont ete traverses avant d'obtenir ce chiffre, et ils
se ressemblent tous:

1. Le tamis rendait zero, et le banc en concluait << l'instrument est fautif >>.
   Il ne l'etait pas.
2. Sur 25H2 le type est `FWPM_NET_EVENT_TYPE_PUBLIC_CLASSIFY_DROP`, pas
   `FWPM_NET_EVENT_TYPE_CLASSIFY_DROP` comme le montrent les sources de 2019.
   Une egalite stricte ecartait les 100 refus, en silence.
3. `[datetime]::TryParseExact` avec une liste de formats: en PowerShell,
   `@(...)` est un `Object[]` et non un `String[]`, la surcharge se lie mal, et
   **90 horodates sur 90** deviennent illisibles. `TryParse` en culture
   invariante lit l'ISO sans qu'on ait a deviner un format.
4. Le net event ne porte **pas de PID**, et `appId` vaut `svchost.exe`, partage
   par des dizaines de services: attribuer ces jetons a `DoSvc` etait une
   inference. Elle est desormais mesuree, par jointure du triplet port local +
   adresse distante + port distant entre le 5157, qui porte le PID, et le net
   event, qui porte le jeton.

La lecon est une seule, et elle est deja dans ce depot sous un autre nom: **un
tamis qui rend zero au bout n'accuse rien; un tamis qui compte a chaque etage
nomme son propre defaut.** Les deux premieres versions du banc ne comptaient
qu'au bout. La troisieme comptait a chaque etage, et les deux defauts suivants
sont tombes en deux passages.

### Ce que le produit a le droit de dire, revise une seconde fois

La revision precedente disait: aucune des cinq cibles `ALE_USER_ID` ne doit etre
annoncee comme bloquee. Elle tenait pour une limite de nos cibles. **C'est une
limite de la plateforme**, et cela change ce qu'on promet:

1. **Le blocage par SID de service n'est pas une garantie, et ne peut pas en
   etre une.** Ce n'est pas une reserve prudente: c'est ce que Microsoft dit de
   son propre mecanisme, et ce que nous avons mesure avec l'outil de Microsoft.
   Un service qui usurpe au moment ou il lie sa socket y echappe, et rien du
   cote filtre ne peut le rattraper.
2. **Le mecanisme reste utile la ou il mord**, et il mord: `W32Time` et trois
   temoins de test. Il a sa place comme couche de defense en profondeur, jamais
   comme la couche qui porte la promesse.
3. **`ALE_APP_ID`, lui, compare un chemin d'image et ne depend d'aucun jeton.**
   Il mord (636 puis 639 refus). Mais pour un service heberge dans
   `svchost.exe`, le chemin d'image est celui de `svchost.exe`, partage par des
   dizaines de services: il ne discrimine pas.
4. **Ce qui eteint la telemetrie reste la couche 1** - registre, services,
   taches planifiees - et la couche DNS. Les deux sont mesurees efficaces.

## Key Findings

1. La reference officielle est la page Microsoft Learn "Connection endpoints for Windows 11 Enterprise" (derniere mise a jour 2026-06-16), qui liste les endpoints par domaine fonctionnel avec protocole et destination. Il n'existe pas de page "25H2" distincte: la meme page couvre 23H2/24H2/25H2. Une page separee existe pour les editions non-Enterprise.
2. Quatre categories doivent etre distinguees: telemetrie pure (events.data.microsoft.com), telemetrie melangee a un service fonctionnel (Update, Store, NCSI, activation), publicite/experimentation (msn.com, iris.microsoft.com, adnxs), et Copilot/Recall/AI.
3. Le blocage par IP est dangereux car la telemetrie transite par des CDN partages avec des services legitimes; le blocage par hostname (DNS/WFP) est la bonne approche.
4. Recall stocke localement (%LocalAppData%\CoreAIPlatform.00\UKP\) et ne remonte pas de screenshots a Microsoft; le risque est local. Desactivable via AllowRecallEnablement=0.
5. Outils reutilisables comme reference: WindowsSpyBlocker (MIT, listes), simplewall (GPL, architecture WFP), O&O ShutUp10++ (freeware, usage commercial autorise, reference de comportement). Winhance et WinUtil sont des references de comportement mais avec bugs de regression documentes.

## Details

### PARTIE 1 - Endpoints Windows 11 24H2/25H2

#### 1.1 Endpoints officiels (Microsoft Learn, page mise a jour 2026-06-16)

Methodologie Microsoft: VM Windows 11 par defaut, compte local (pas de domaine/Entra), capture IPv4 uniquement pendant une semaine en idle. Tout le diagnostic data est chiffre TLS avec certificate pinning.

| Categorie | Endpoint | Protocole | Ce qui casse si bloque |
|---|---|---|---|
| Diagnostic Data (telemetrie pure) | v10.events.data.microsoft.com | TLSv1.2/HTTPS/HTTP | Rien de fonctionnel; coeur du pipeline Connected User Experiences and Telemetry |
| Diagnostic Data | self.events.data.microsoft.com | TLSv1.2/HTTP | Idem |
| Diagnostic Data | functional.events.data.microsoft.com | TLSv1.2 | Idem |
| Diagnostic Data | browser.events.data.msn.com | HTTP | Telemetrie navigateur/MSN |
| Error Reporting | watson.*.microsoft.com, telecommand.telemetry.microsoft.com, www.telecommandsvc.microsoft.com | TLSv1.2 | Windows Error Reporting (crash dumps). Desactivable via GPO "Disable Windows Error Reporting". A noter: telecommand.telemetry.microsoft.com sert WER, pas la telemetrie pure |
| Settings | settings-win.data.microsoft.com, settings.data.microsoft.com | TLSv1.2/HTTPS/HTTP | Config dynamique d'apps (System Initiated User Feedback, Xbox) |
| Spotlight/pub | arc.msn.com, ris.api.iris.microsoft.com, fd.api.iris.microsoft.com, api.msn.com, assets.msn.com, ntp.msn.com, srtb.msn.com | TLS/HTTP | Windows Spotlight, suggestions, tips, MSN |
| Store | *.wns.windows.com | TLSv1.2/HTTPS | Push notifications (WNS), MDM, sync mail/settings |
| Store | *displaycatalog.mp.microsoft.com, storeedgefd.dsx.mp.microsoft.com, livetileedge.dsx.mp.microsoft.com | TLS/HTTPS/HTTP | Install/MAJ apps Store |
| NCSI | www.msftconnecttest.com, ipv6.msftconnecttest.com | HTTPS/HTTP | Icone reseau affiche "pas d'acces Internet" |
| Update | *.prod.do.dsp.mp.microsoft.com, *.dl.delivery.mp.microsoft.com, *.windowsupdate.com, *.update.microsoft.com, *.delivery.mp.microsoft.com, *.api.cdp.microsoft.com | TLS/HTTPS/HTTP | Windows Update casse |
| Activation | licensing.mp.microsoft.com | TLS/HTTPS/HTTP | Activation en ligne et licences apps |
| Defender | wdcp.microsoft.com, *.smartscreen-prod.microsoft.com, definitionupdates.microsoft.com | TLSv1.2/HTTPS | Cloud protection, SmartScreen, definitions |
| Certificates | ctldl.windowsupdate.com, ocsp.digicert.com | TLS/HTTPS/HTTP | MAJ liste certificats racine (surface d'attaque augmentee si bloque) |

Endpoints publicitaires/telemetrie additionnels issus de WindowsSpyBlocker (data/hosts/spy.txt, MIT, base sur capture reseau QEMU/Proxmox): a.ads1.msn.com, a.ads2.msads.net, a.rad.msn.com, ac3.msn.com, adnxs.com, secure.adnxs.com, ads.msn.com, bingads.microsoft.com, mobile.pipe.aria.microsoft.com, *.pipe.aria.microsoft.com, kmwatson.events.data.microsoft.com, kmwatsonc.events.data.microsoft.com, oca.telemetry.microsoft.com, reports.wes.df.telemetry.microsoft.com, nw-umwatson.events.data.microsoft.com, alpha.telemetry.microsoft.com, nexus.officeapps.live.com, nexusrules.officeapps.live.com.

#### 1.2 IP en dur et contournements

- Source primaire de reference: le rapport du BSI allemand (projet SiSyPHuS Win10, "Work Package 4: Telemetry" v1.0, et "Telemetry Differential Analysis" v1.0) documente que les noms d'hotes du backend telemetrie sont codes en dur dans diagtrack.dll (Table 2 "Information on hosts hardcoded in diagtrack.dll" et Table 5). Le service DiagTrack etablit des connexions TLS avec certificate pinning et lit/envoie des fichiers dont les chemins sont hardcodes dans la section ressource de diagtrack.dll. C'est la justification technique du fait que hosts/DNS ne suffisent pas seuls.
- CDN partages: les endpoints device-graph (DDS/CDP) se cachent derriere des IP Azure Front Door partagees (13.107.x.x) egalement utilisees par Office, Bing et Windows Update; le blocage par IP casse ces services (projet GitHub alohatracker/GDIDie, qui recommande explicitement le blocage par hostname et un backstop pare-feu par SID de service). Le blocage doit etre par hostname, jamais par IP sur ces plages.
- DoH natif Windows: le service Dnscache (resolveur local) supporte le DoH. Cles pertinentes:
  - HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\EnableAutoDoh (DWORD=2 active l'auto-promotion des serveurs connus).
  - HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DoHPolicy (DWORD=3 = Require DoH).
  - Serveurs "bien connus" declares sous Dnscache\Parameters\DohWellKnownServers\<IP>\Template (REG_SZ).
  - Sur 24H2, la GPO "Configure DNS over HTTPS (DoH) name resolution" est sous Computer Configuration\Administrative Templates\Network\DNS Client (peut etre absente/en "Prohibit DoH" selon deploiement). Le netsh equivalent: `netsh dns add encryption server=<IP> dohtemplate=<URI>`.
- Format des uploads: protocole Unified Telemetry Client vers *.events.data.microsoft.com (anciennement vortex.data.microsoft.com). Variantes: kmwatson/umwatson (Watson/WER), mobile.events.data.microsoft.com, teams.events.data.microsoft.com, self.events.data.microsoft.com.

#### 1.3 Services, processus, taches planifiees

Services (desactivation: `sc config <nom> start= disabled`, ou registre `Start`=4 pour contourner les Access Denied du SCM sur DoSvc):

| Service | Nom affichage | Role | Ce qui casse |
|---|---|---|---|
| DiagTrack | Connected User Experiences and Telemetry | Pipeline telemetrie principal | Achievements Xbox/Game Bar, richer diagnostics support |
| dmwappushservice | Device Management WAP Push Routing | Routage WAP push MDM | MDM sur devices geres |
| DoSvc | Delivery Optimization | P2P updates + device graph | MAJ P2P (updates fonctionnent quand meme) |
| CDPUserSvc / CDPSvc | Connected Devices Platform | Device graph / near-share | Continuite entre appareils |
| WerSvc | Windows Error Reporting | Crash reports | Rapports d'erreur |
| WSAIFabricSvc | AI Fabric Service (Copilot+) | Controle WorkloadsSessionHost.exe (inference ONNX) | Fonctions AI locales (25H2 sur Copilot+) |

Taches planifiees (`schtasks /Change /TN "<chemin>" /Disable` ou PowerShell Disable-ScheduledTask):
- \Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser (lance CompatTelRunner.exe)
- \Microsoft\Windows\Application Experience\ProgramDataUpdater
- \Microsoft\Windows\Application Experience\StartupAppTask
- \Microsoft\Windows\Application Experience\PcaPatchDbTask
- \Microsoft\Windows\Customer Experience Improvement Program\Consolidator
- \Microsoft\Windows\Customer Experience Improvement Program\UsbCeip
- \Microsoft\Windows\Autochk\Proxy
- \Microsoft\Windows\Feedback\Siuf\DmClient et \Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload

Note operationnelle (WinUtil issue #4035): CompatTelRunner.exe peut continuer a se lancer a chaque installation/desinstallation malgre la desactivation des taches; le seul moyen 100% fiable reste le blocage WFP par chemin de processus.

Processus emetteurs a cibler en WFP par chemin (ALE_APP_ID): CompatTelRunner.exe, DeviceCensus.exe, MusNotification.exe, SIHClient.exe, WaaSMedicAgent.exe. Pour svchost.exe, ne PAS bloquer globalement mais cibler le service par SID (voir 2.2).

#### 1.4 Cles de registre et politiques

Point critique tranche: sur Home et Pro, AllowTelemetry ne peut pas descendre sous Required(1). La documentation Microsoft Learn le dit explicitement, verbatim: "0 - No telemetry data is sent from OS components. Note: This value is only applicable to enterprise and server devices. Using this setting on other devices is equivalent to setting the value of 1." Cela reste valide en 24H2/25H2. Consequence produit: sur Home/Pro, poser AllowTelemetry=0 desactive l'UI de reglage et reduit la surface, mais n'annule pas la telemetrie Required; le blocage reseau (DNS/WFP) est donc la seule garantie reelle.

```reg
Windows Registry Editor Version 5.00
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection]
"AllowTelemetry"=dword:00000000
"AllowDeviceNameInTelemetry"=dword:00000000
"DoNotShowFeedbackNotifications"=dword:00000001
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsAI]
"AllowRecallEnablement"=dword:00000000
"DisableAIDataAnalysis"=dword:00000001
[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot]
"TurnOffWindowsCopilot"=dword:00000001
```

Cles Copilot/Recall/AI (sources Microsoft Learn: manage-recall et policy-csp-windowsai):
- AllowRecallEnablement=0 sous HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsAI: supprime les bits Recall et supprime les snapshots deja stockes. Supporte Windows 11 24H2 avec KB5055627 (build 10.0.26100.3915) et ulterieur. Editions Pro/Enterprise/Education/IoT.
- DisableAIDataAnalysis=1 sous HKCU/HKLM\...\WindowsAI: empeche la sauvegarde des snapshots (consentement individuel requis de toute facon; par defaut off pour devices geres).
- TurnOffWindowsCopilot=1 sous HKCU/HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot: cible l'ancien Copilot. Le nouveau Copilot livre en app Store (Microsoft.Copilot) n'est PAS fiablement neutralise par cette cle sur builds recents; une politique plus recente WindowsAI/TurnOffWindowsCopilot (HKCU\SOFTWARE\Policies\Microsoft\Windows\WindowsAI) existe et 25H2 a ajoute une politique de desinstallation dediee. A verifier au moment de l'implementation.

Cles publicite/suivi (paths, types et valeurs de desactivation verifies):

| Path | Value name | Type | Valeur (desactive) |
|---|---|---|---|
| HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo | Enabled | DWORD | 0 |
| HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo | DisabledByGroupPolicy | DWORD | 1 |
| HKCU\Software\Microsoft\Windows\CurrentVersion\Privacy | TailoredExperiencesWithDiagnosticDataEnabled | DWORD | 0 |
| HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent | DisableTailoredExperiencesWithDiagnosticData | DWORD | 1 |
| HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent | DisableWindowsConsumerFeatures | DWORD | 1 |
| HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent | DisableSoftLanding | DWORD | 1 (Enterprise/Education) |
| HKCU\Software\Microsoft\InputPersonalization | RestrictImplicitInkCollection | DWORD | 1 |
| HKCU\Software\Microsoft\InputPersonalization | RestrictImplicitTextCollection | DWORD | 1 |
| HKCU\Software\Microsoft\InputPersonalization\TrainedDataStore | HarvestContacts | DWORD | 0 |
| HKCU\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy | HasAccepted | DWORD | 0 |
| HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization | AllowInputPersonalization | DWORD | 0 |
| HKCU\...\ContentDeliveryManager | SubscribedContent-338388Enabled | DWORD | 0 |
| HKCU\...\ContentDeliveryManager | SilentInstalledAppsEnabled | DWORD | 0 |
| HKCU\...\ContentDeliveryManager | SystemPaneSuggestionsEnabled | DWORD | 0 |
| HKCU\...\ContentDeliveryManager | FeatureManagementEnabled | DWORD | 0 |

(ContentDeliveryManager = HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager. Attention: ContentDeliveryAllowed=0 casse la rotation Spotlight de l'ecran de verrouillage.)

Regressions connues:
- Winhance issue #281 (ouverte le 29 dec 2025, Windows 11 Enterprise 24H2, v25.12.12): le toggle "Send Diagnostic Data" active la telemetrie meme en position "Disable". Verbatim du rapporteur m1g0r3ng: "The 'Send Diagnostic Data' toggle seems to have enabled telemetry for Recommended and even enables telemetry (sets it to 1) when using the 'Disable' toggle." Detecte par O&O ShutUp10++. Lecon: valider l'etat effectif apres application, ne pas se fier au toggle.
- Les feature updates reactivent DiagTrack et remettent AllowTelemetry a la valeur par defaut. Detection: comparer periodiquement l'etat effectif aux valeurs cibles et reappliquer (voir Partie 6).
- Fiabilite reduite des cles ContentDeliveryManager sur builds recents (shell durci par Microsoft): privilegier les GPO CloudContent (plus durables).

### PARTIE 2 - Efficacite reelle des methodes

#### 2.1 Pourquoi le fichier hosts ne suffit plus
- IP en dur dans diagtrack.dll (BSI), composants ignorant hosts (domaines hardcodes dans dnsapi documentes), DoH interne du service Dnscache, listes trop larges cassant Windows Update.
- Depuis fin juillet 2020, Defender detecte les entrees telemetrie ajoutees au fichier hosts comme SettingsModifier:Win32/HostsFileHijack. Reference: fiche Microsoft Security Intelligence "SettingsModifier:Win32/HostsFileHijack" (publiee le 14 jan 2020, mise a jour le 7 aout 2020); premiers signalements utilisateurs le 23 juillet 2020, vague de detections fin juillet 2020 (Bleeping Computer/Slashdot). Toujours actif en 2026 (variante Win32/PossibleHostsFileHijack). Contournement propre: ne PAS utiliser hosts pour la telemetrie MS; utiliser un resolveur DNS local + WFP. Si hosts est indispensable, ajouter une exclusion Defender sur le fichier (au prix d'aveugler Defender sur hosts).

#### 2.2 Comparatif des couches

| Couche | Efficacite | Risque de casse | Cible svchost par service |
|---|---|---|---|
| Fichier hosts | Faible (contourne, detecte Defender) | Moyen | Non |
| DNS local (Pi-hole/AdGuard/blocky) | Bonne sur endpoints par hostname | Faible si liste curatee | Non (mais agit AVANT le tunnel) |
| Pare-feu Windows | Moyenne | Regles ecrasees par updates | Difficilement |
| WFP par processus (simplewall) | Elevee | Moyen | Oui (via Services tab / SID) |
| Blocage a la source (services/taches/registre) | Elevee | Eleve (fragile aux updates) | N/A |

WFP est la seule couche qui autorise/refuse par service au sein de svchost.exe: on peut bloquer DiagTrack tout en laissant wuauserv (Windows Update) et BITS. C'est le point technique differenciant. simplewall opere via l'API Windows Filtering Platform (couches ALE, Application Layer Enforcement, classification par connexion), independamment du pare-feu Windows; ses filtres persistent meme l'application fermee.

Ordre de priorite recommande: (1) registre/GPO + services desactives (source, reversible), (2) WFP par service pour svchost/CompatTelRunner (seule methode ciblant svchost), (3) DNS local pour les endpoints par hostname, (4) hosts uniquement pour cas non-MS. Le VPN etant deja en kill switch, la couche DNS locale doit intercepter AVANT le tunnel: c'est la propriete centrale (le trafic telemetrie n'entre jamais dans le tunnel).

#### 2.3 Outils evalues honnetement

| Outil | Version 2026 | Licence | Reutilisable dans le produit | Note |
|---|---|---|---|---|
| O&O ShutUp10++ | 2.2.1024 (4 fev 2026); Free 3.2.1111 (15 juil 2026) | Freeware (usage perso/commercial/educatif gratuit) | Comme outil oui; code proprietaire (non forkable) | Ajoute controles Copilot/Recall/AI. Cree point de restauration. Premium reapplique apres updates. Reference de comportement |
| WindowsSpyBlocker | actif (MIT) | MIT | Oui (listes reutilisables) | Listes spy/update/extra basees sur capture reseau QEMU/Proxmox. Meilleure source de listes |
| simplewall | 3.9.1 (22 juil 2026) | GPL-3.0 | Fork = contamination GPL | Seul a cibler svchost par service via WFP. Reference d'architecture. v3.9 a introduit une regression (boucle notifications svchost), corrigee en v3.9.1 pre-release |
| Winhance | v26.03.x | selon repo | A auditer | Bugs regression documentes (#281 telemetrie, #280 Windows Update) |
| WinUtil (Chris Titus) | actif | MIT | Oui | Recettes de taches telemetrie reutilisables (issue #4035) |
| privacy.sexy | actif | AGPL-3.0 | Attention AGPL (contamine cote serveur) | Genere scripts; excellente source de recettes |
| Sophia Script | actif | MIT | Oui | PowerShell exhaustif |
| Optimizer | actif | GPL-3.0 | Fork GPL | Debloat generaliste |

Conclusion: reference technique = simplewall (logique WFP) + WindowsSpyBlocker (listes MIT) + Sophia/WinUtil (recettes MIT). A ecrire soi-meme: l'orchestrateur reversible (journal, profils, detection de derive) et le moteur WFP-par-service, car aucun outil ne combine WFP-par-service + DNS + reversibilite sous licence permissive.

### PARTIE 3 - Couche DNS et filtrage reseau

Comparatif operationnel 2026:

| Solution | Licence | DoH/DoT/DoQ natif | Filtrage par client | Embarquement produit |
|---|---|---|---|---|
| AdGuard Home | GPL-3.0 | Oui (les trois, natif UI) | Oui (UI) | Bon (binaire Go unique) |
| Pi-hole | EUPL (+ marque) | Non (v6: HTTPS admin seulement; upstream chiffre via cloudflared/unbound) | Oui (groupes) | Moyen (stack dnsmasq+lighttpd+PHP) |
| Technitium | GPL-3.0 | Oui (C#), clustering HA natif (v14) | Oui | Bon si stack .NET |
| blocky | Apache-2.0 (Go) | Oui | Oui | Excellent (leger, embarque, permissive) |

Recommandation d'embarquement dans le produit: blocky (Apache-2.0, permissive, leger, Go) pour eviter la contamination GPL du client MPL-2.0. AdGuard Home si l'on accepte GPL et l'on veut une UI riche + Blocked Services.

Listes de blocage Windows maintenues en 2026:
- hagezi "Windows/Office Tracker DNS Blocklist" (wildcard/native.winoffice.txt). Titre officiel de la liste: "HaGeZi's Windows/Office Tracker DNS Blocklist" (719 entrees dans la version publiee d'octobre 2025). Basee en partie sur la liste BSI SiSyPHuS testee "pour plusieurs mois sans casse" (issue #8071). Faux positifs tres faibles (concu pour). Cible Vortex et Aria (vortex.data.microsoft.com, pipe.aria.microsoft.com).
- WindowsSpyBlocker spy.txt (capture reseau, MIT).
- StevenBlack/hosts (agrege, plus large, donc plus de risque de casser Update; a manier avec whitelist Update).

Impact ECH: RFC 9849 "TLS Encrypted Client Hello" (E. Rescorla, K. Oku, N. Sullivan, C. A. Wood; Standards Track IETF; March 2026; DOI 10.17487/RFC9849; annonce RFC Editor du 3 mars 2026) et RFC 9848 "Bootstrapping TLS Encrypted ClientHello with DNS Service Bindings" (March 2026). ECH chiffre le SNI et l'integralite du ClientHelloInner: le filtrage par SNI en clair devient inefficace. En revanche le filtrage DNS reste efficace car la resolution du nom precede la connexion, et l'ECHConfig lui-meme est publie dans le DNS (records SVCB/HTTPS, type 65). Parade: forcer tout le DNS vers le resolveur local controle et bloquer le DoH tiers. JA4 fingerprinting et IP-reputation restent efficaces (ECH ne les neutralise pas). Signaler la fraicheur: le deploiement ECH cote endpoints Microsoft n'est pas generalise; a re-evaluer.

Forcer TOUT le DNS vers le resolveur local:
- Rediriger/bloquer le port 53 sortant vers tout sauf le resolveur local (nftables/WFP).
- Bloquer les serveurs DoH connus (liste hagezi "DoH/VPN/TOR/Proxy Bypass") au niveau reseau.
- Chrome/Edge: GPO DnsOverHttpsMode="off". Firefox: policies.json avec DNSOverHTTPS Enabled=false (ou network.trr.mode=5). 
- Windows: DoHPolicy=3 pour n'autoriser que le DoH controle, ou EnableAutoDoh maitrise.

### PARTIE 4 - Equivalent Linux

Ubuntu 24.04+ (endpoint et desactivation):

| Composant | Envoie | Endpoint | Desactivation | Casse |
|---|---|---|---|---|
| ubuntu-report | Config materielle/logicielle a l'install (opt-in) | metrics.ubuntu.com | `ubuntu-report -f send no`; `apt purge ubuntu-report` | Rien |
| popularity-contest (popcon) | Paquets installes (opt-in) | popcon.ubuntu.com | `apt purge popularity-contest` | Rien |
| whoopsie | Crash reports | daisy.ubuntu.com | `systemctl disable --now whoopsie`; `apt purge whoopsie` | Rapports crash |
| apport | Capture crashes locale (envoi sur action) | (local) | `systemctl disable apport`; enabled=0 dans /etc/default/apport | Popups crash |
| motd-news | News dans MOTD | motd.ubuntu.com | ENABLED=0 dans /etc/default/motd-news | MOTD dynamique |
| snapd | Refresh/recherche | api.snapcraft.io | Voir ci-dessous | Snaps |

Commande combinee:
```bash
sudo apt purge -y ubuntu-report popularity-contest apport whoopsie apport-symptoms
sudo apt-mark hold ubuntu-report popularity-contest apport whoopsie apport-symptoms
```

Debian 12+: popularity-contest est opt-in explicite a l'install (off par defaut); reportbug est manuel (aucun envoi automatique). Telemetrie quasi nulle par defaut.

Telemetrie applicative (commune Windows/Linux, souvent le vrai probleme chez un developpeur):
- VS Code: `"telemetry.telemetryLevel": "off"` (settings.json) ou politique d'entreprise TelemetryLevel. Envoie vers Azure Monitor / Application Insights (dc.services.visualstudio.com, *.in.applicationinsights.azure.com). Attention: certaines extensions ont leur propre telemetrie (redhat.telemetry.enabled=false, docker-explorer.enableTelemetry=false, julia.enableTelemetry=false, sonarlint.disableTelemetry=true). L'extension vscode-docker a ete signalee (issue #3372) comme continuant a joindre un endpoint telemetrie via Remote SSH malgre l'opt-out. Alternative sans telemetrie: VSCodium.
- Docker Desktop: desactiver "Send usage statistics" dans Settings; endpoint Application Insights.
- JetBrains: Help > Data Sharing > Off (par IDE); endpoint analytics JetBrains.
- Firefox: toolkit.telemetry.enabled=false + datareporting via policies.json (DisableTelemetry=true).
- Chrome/Chromium: politique MetricsReportingEnabled=false.
- Steam / Discord: opt-out partiel dans les parametres.

Snap/Flatpak: snapd communique avec api.snapcraft.io (recherche, refresh, inclut des infos device pour les delta updates). Pas d'opt-out par-app simple; blocage = ne pas utiliser snap, ou bloquer api.snapcraft.io au DNS (casse install/MAJ des snaps). Flatpak/Flathub ne collecte pas de telemetrie utilisateur; les statistiques d'installation sont agregees cote serveur uniquement.

systemd-resolved: point specifique telemetrie seulement, comme demande. Verifier que resolved ne fallback pas vers un DoH/DNS public non controle (FallbackDNS vide, DNSOverTLS maitrise); le forcage DNS global est traite ailleurs.

Ampleur reelle: la telemetrie Linux (Ubuntu) est marginale comparee a Windows. ubuntu-report envoie une seule fois a l'install; popcon est opt-in; Debian est quasi silencieux. Aucun equivalent du flux continu Windows. Point de comparaison Windows: FB Pro GmbH (test aout 2022 avec l'outil SAM du BSI) a mesure, verbatim, "The unhardened Windows 11 system sent 448 data packets to Microsoft in one week." Conclusion honnete: pour un dev sous Linux, l'effort doit porter sur la telemetrie applicative (VS Code, Docker, JetBrains), pas sur l'OS.

### PARTIE 5 - Mesure et verification

Outils de capture:
- pktmon (natif Windows): `pktmon start --etw -m real-time`; filtres par IP/port; export .etl converti en .pcapng. Aucun logiciel tiers a installer.
- Wireshark: capture + filtre `tls.handshake.extensions_server_name` pour identifier les endpoints par SNI (avant generalisation ECH).
- Sysmon Event ID 3 (Network connection): correle processus/connexion/hash; ideal pour attribuer une connexion sortante a svchost + service precis.
- Process Monitor: correlation process/reseau en temps reel.

Tableau de bord produit (metrique avant/apres): nombre de connexions bloquees par destination, volume de donnees non exfiltrees (estime = taille moyenne de payload x connexions bloquees), liste des destinations bloquees avec categorie (telemetrie/pub/AI). Sources de comptage: logs WFP (filtres block) + logs du resolveur DNS local (requetes NXDOMAIN/sinkhole). Baseline "avant" = capture 24-48h sans blocage; "apres" = meme fenetre avec blocage.

Etudes publiques serieuses (2024-2026): la reference methodologique reste le projet BSI SiSyPHuS Win10 ("Work Package 4: Telemetry" + "Telemetry Differential Analysis") - analyse de diagtrack.dll, ETW providers par niveau de telemetrie, implementation registre. Le test FB Pro (aout 2022, methodologie/outil BSI) fournit le chiffre de 448 paquets/semaine sur Win11 non durci. A signaler et eviter: la plupart des "mesures" en ligne (videos YouTube, blogs SEO) sont non methodologiques; ne pas les citer.

Automatisation CI/VM: VM Windows en snapshot -> appliquer profil -> usage scripte ou attente idle -> capture pktmon -> parser les destinations observees vs liste attendue -> assertion (par ex. 0 connexion vers *.events.data.microsoft.com). Reutiliser la methodologie WindowsSpyBlocker (QEMU/Proxmox, dumps quotidiens compares aux regles).

### PARTIE 6 - Implementation dans le produit

Architecture recommandee du module anti-telemetrie:
1. Couche source (registre/GPO + services + taches): appliquee en premier, la plus efficace mais fragile aux updates. Integralement journalisee et reversible.
2. Couche WFP par service: cible DiagTrack/CompatTelRunner par SID/chemin. Persiste meme l'app fermee (prevoir imperativement un "disable filters" au rollback).
3. Couche DNS locale (blocky embarque + listes hagezi/WindowsSpyBlocker): intercepte les endpoints par hostname AVANT le tunnel VPN. Propriete centrale.
4. Couche hosts: uniquement pour des cas non-Microsoft (eviter HostsFileHijack).

Reversibilite (obligatoire):
- Point de restauration systeme avant toute modification (comme O&O ShutUp10++).
- Export .reg des cles avant modification (`reg export`) + journal horodate de chaque changement (cle, ancienne valeur, nouvelle valeur).
- Sauvegarde de l'etat des services (StartupType) et des taches planifiees.
- Commande WFP "disable filters" executee avant toute desinstallation.

Gestion des updates qui reannulent: moteur de detection de derive (tache planifiee du produit) comparant l'etat effectif aux valeurs cibles; reapplication automatique. C'est le mecanisme d'O&O ShutUp10 Premium ("continuously monitors your selected settings and automatically restores them, even after Windows updates"). Winhance issue #281 illustre le risque de mal detecter l'etat (se fier au toggle plutot qu'a la valeur effective).

Profils recommandes:
- Equilibre (rien ne casse): AllowTelemetry=0 + Advertising/Tailored off + DiagTrack disabled + blocage DNS des *.events.data.microsoft.com et endpoints pub. Store/Update/Defender/NCSI intacts.
- Strict (accepte de casser Store/Copilot): + Recall/Copilot off + WFP block large + Spotlight off + WNS coupe (perte des notifications push, sync).
- Parano (machine hors ligne fonctionnelle): + blocage Update/Store/activation/NCSI; machine essentiellement deconnectee des services Microsoft.

Reutilisable tel quel: listes WindowsSpyBlocker (MIT) et hagezi, recettes Sophia/WinUtil (MIT), blocky (Apache-2.0). A forker/reimplementer: la logique WFP de simplewall est en GPL-3.0; pour le client MPL-2.0, reimplementer via l'API native FWPM plutot que forker. A ecrire de zero: orchestrateur reversible, tableau de bord metrique, moteur de detection de derive, integration au client VPN.

Estimation d'effort (jours-homme), calibree sur la taille du code equivalent:
- Couche registre/services/taches + reversibilite: 15-20 j (privacy.sexy compte des centaines de recettes; en reprendre ~80 pertinentes).
- Moteur WFP par service (API FWPM native, sans fork GPL): 25-35 j (le coeur est la classification par SID de service, la partie la plus delicate).
- Integration DNS locale (blocky embarque + listes + auto-update): 10-15 j.
- Tableau de bord metrique + capture pktmon + parsing: 15-20 j.
- Detection de derive + profils + tests VM CI: 15-20 j.
- Total indicatif: 80-110 j-homme.

Risques de support:
- Casser une machine cliente (Update/Store/activation): support couteux; d'ou le profil "Equilibre" par defaut et la reversibilite obligatoire.
- Garantie: modifier services/registre n'invalide pas la garantie materielle, mais peut compliquer un support Microsoft (support demandant des diagnostics riches).
- Conflit MDM/entreprise: sur machines gerees (Intune/GPO), le module ne doit PAS ecraser les politiques d'entreprise; detecter la presence d'un MDM/domaine et basculer en mode avertissement.
- Defender HostsFileHijack: eviter le fichier hosts pour les domaines Microsoft.

## Recommendations
1. Livrer d'abord le profil "Equilibre" avec les 3 couches (registre + WFP-par-service + DNS blocky), reversibilite complete et point de restauration. Benchmark de succes: 0 connexion vers *.events.data.microsoft.com sur 48h de capture pktmon, avec Windows Update et le Store fonctionnels.
2. Embarquer blocky (Apache-2.0) comme resolveur local; sources de listes: hagezi native.winoffice + WindowsSpyBlocker spy.txt. Ne pas embarquer simplewall (GPL): reimplementer la logique WFP par SID via l'API FWPM.
3. Sur Home/Pro, ne jamais promettre "telemetrie a zero" par le registre seul: le blocage reseau (DNS/WFP local, avant le tunnel) est la garantie. Communiquer honnetement le fait que AllowTelemetry=0 est traite comme 1 (documente par Microsoft).
4. Implementer un moteur de detection de derive (tache planifiee) qui reapplique apres chaque feature update; declencheurs: changement de numero de build, ou AllowTelemetry effectif != 0, ou DiagTrack repasse en Automatic.
5. Detecter MDM/domaine et basculer en mode "avertissement seul" pour eviter tout conflit avec les politiques d'entreprise.
6. Seuils qui changeraient la strategie: si ECH devient generalise cote endpoints Microsoft et casse la correlation SNI, s'appuyer davantage sur DNS + WFP par processus; si Microsoft ajoute des endpoints telemetrie en IP en dur, prioriser le WFP par service sur le DNS.

## Caveats
- Fraicheur incertaine 25H2 / build 26200: le comportement Copilot/Recall evolue vite. AllowRecallEnablement est confirme jusqu'a 24H2 KB5055627 (build 10.0.26100.3915). Le nouveau Copilot app (Microsoft.Copilot) n'est pas fiablement neutralise par TurnOffWindowsCopilot sur builds recents; verifier au moment de l'implementation. Les Copilot+ features (Recall, Click to Do, Semantic Search) sont apparues en servicing 24H2 avant activation formelle en 25H2 (enablement package sur 24H2).
- Il n'existe pas de page Microsoft Learn "25H2" distincte pour les endpoints; la page Windows 11 Enterprise (2026-06-16) couvre les versions courantes; une page non-Enterprise existe separement.
- Le chiffre "448 paquets/semaine" (FB Pro, aout 2022, methodologie BSI) porte sur un Win11 initial; a re-mesurer sur 24H2/25H2 pour alimenter le tableau de bord produit.
- La fiabilite des cles ContentDeliveryManager est reduite sur builds recents (shell durci par Microsoft); privilegier les GPO CloudContent.
- simplewall v3.9 a introduit une regression (boucle de notifications svchost), corrigee en v3.9.1 (pre-release); ne pas dependre d'une pre-release en production.
- La telemetrie Edge est collectee separement depuis le 6 mars 2024 (Espace economique europeen) avec ses propres reglages, distincte du diagnostic data Windows.
- Windows 11 24H2 Home/Pro atteint la fin des mises a jour le 13 octobre 2026; 25H2 est la version courante. Tenir compte de ce calendrier pour le support.