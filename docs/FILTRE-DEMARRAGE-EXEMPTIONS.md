# Ce que le filtre de demarrage doit laisser passer

Releve du 17 aout 2026. Sert de specification aux options d'interface, et de
liste de controle a la mise en oeuvre.

Le probleme ouvert 2 a etabli qu'un filtre WFP boot-time pose depuis l'espace
utilisateur ferme la fenetre de fuite au demarrage machine. La recette
`--boot-filtres` ne bloque QU'UNE adresse: c'est un instrument de mesure. En
faire une fonction demande de decider ce qu'un blocage total laisse passer,
faute de quoi la machine redemarre sans reseau du tout.

Le fil directeur: chaque exemption est une fuite potentielle, donc chacune doit
etre justifiee par une panne concrete qu'elle evite, pas par le confort.

## 1. Non negociable, aucune option

Sans ces quatre familles, la machine ne peut pas obtenir d'adresse ni parler a
son propre reseau: elle serait inutilisable et l'utilisateur desactiverait la
fonction, ce qui est le pire resultat. Mullvad les classe pareil, "always
allowed", dans TOUS ses etats y compris l'etat d'erreur.

- **Boucle locale.** Tout le trafic sur les adaptateurs de boucle locale, dans
  les deux sens. Aucun risque: rien ne sort de la machine.
- **DHCPv4.** Sortant UDP `*:68` vers `255.255.255.255:67`; entrant UDP `*:67`
  vers `*:68`. Sans lui, pas d'adresse, donc pas de reseau, y compris pas de
  tunnel.
- **DHCPv6.** Sortant UDP `[fe80::/10]:546` vers `[ff02::1:2]:547` et
  `[ff05::1:3]:547`; entrant UDP `[fe80::/10]:547` vers `[fe80::/10]:546`.
- **NDP**, sous-ensemble strict d'ICMPv6, sans quoi IPv6 ne fonctionne pas du
  tout: sollicitation de routeur (133) vers `ff02::2`, annonce de routeur (134)
  depuis `fe80::/10`, redirection (137) depuis `fe80::/10`, sollicitation de
  voisin (135) vers et depuis `ff02::1:ff00:0/104` et `fe80::/10`, annonce de
  voisin (136) vers et depuis `fe80::/10`.

**Piege a ne pas reproduire.** Si la politique bloque IPv6 en entier parce que
le tunnel ne le transporte pas, alors les exemptions DHCPv6 et NDP n'ont pas
lieu d'etre: les poser quand meme est une contradiction, et c'est un bug
ouvert chez Mullvad (issue 8247, "ipv6 dhcp rules are being added despite ipv6
being off"). La regle: les exemptions IPv6 suivent l'etat d'IPv6, elles ne sont
pas inconditionnelles.

## 2. Options d'interface

### 2.1 Reseau local. Defaut propose: DESACTIVE

Ce que Mullvad appelle "local network sharing", et ce que l'utilisateur veut
quand il a une imprimante ou un NAS. Plages a ouvrir si l'option est active:

- non routables: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`,
  `169.254.0.0/16`, `fe80::/10`, `fc00::/7`
- multicast local: `224.0.0.0/24`, `239.0.0.0/8`, `255.255.255.255/32`,
  `ff01::/16` a `ff05::/16`
- reponses du serveur DHCP: sortant UDP `*:67` vers `*:68`

**Limite a annoncer plutot qu'a decouvrir.** Cela ne marche de facon fiable que
pour le sous-reseau directement attache. Des qu'un equipement est derriere une
passerelle, le trafic emprunte la route par defaut, devenue celle du tunnel, et
echoue. C'est une plainte ancienne et toujours ouverte chez Mullvad (issues
2674 et 6219). Ne pas promettre le multi-sous-reseau.

Defaut desactive parce que c'est une exemption qui expose la machine a son
reseau local, et qu'un reseau local hostile - hotel, coworking, aeroport - est
precisement le cas ou l'on veut un VPN.

### 2.2 Reseau overlay, `100.64.0.0/10`. Defaut propose: DESACTIVE, mais PROPOSE explicitement

C'est la plage CGNAT, celle qu'utilisent Tailscale, et d'autres reseaux
overlay. **Elle n'est PAS dans les plages "reseau local" ci-dessus**, et son
absence est un manque signale chez Mullvad depuis longtemps (issue 6086).

Consequence concrete, qui vaut d'etre ecrite noir sur blanc: une machine
administree a distance par un overlay de ce type, qui redemarre avec un filtre
de demarrage sans cette exemption, devient **injoignable**. C'est exactement le
mode de panne repare sur essai-windows le 17 aout 2026, mais livre a
l'utilisateur et sans acces pour le corriger.

Donc: option separee du reseau local, defaut desactive, mais l'interface doit
la mettre en avant plutot que de l'enterrer, et l'assistant de premiere
configuration devrait detecter la presence d'une interface dans cette plage et
poser la question.

### 2.2 bis Correction: ouvrir la plage CGNAT ne suffit PAS

Etabli le 17 aout 2026, avant d'avoir pose quoi que ce soit, et c'est
precisement ce qui a empeche de rendre une machine d'essai injoignable.

`100.64.0.0/10` porte les adresses INTERNES de l'overlay. Le transport reel,
lui, sort vers des endpoints PUBLICS: de l'UDP vers le pair, ou du 443 vers un
relais quand la traversee de NAT echoue. Un blocage qui n'ouvre que la plage
CGNAT laisse donc passer un trafic interne qui n'a plus de porteur: l'overlay
tombe, et la machine devient injoignable malgre l'exemption. Ouvrir la plage est
necessaire et pas suffisant.

Le bon mecanisme est celui que ce depot applique deja a son propre endpoint:
autoriser une IDENTITE de processus, jamais une destination. On autorise le
demon de l'overlay a sortir, et lui seul; ouvrir ses adresses de serveurs
donnerait un canal de sortie en clair utilisable par n'importe quel programme.

**Consequence structurelle, a ecrire noir sur blanc.** Une condition d'identite
de processus ne vaut rien dans la fenetre pre-BFE, ou aucun processus n'existe.
La couverture est donc necessairement asymetrique:

- filtre BOOT-TIME (de `tcpip.sys` a BFE): l'overlay ne peut pas etre maintenu,
  aucune identite n'est evaluable. La machine est coupee pendant cette fenetre,
  qui dure quelques secondes;
- filtre PERSISTANT (de BFE au daemon Bifrost): le demon de l'overlay tourne,
  son identite est evaluable, et la machine peut rester joignable.

Une interface honnete doit donc annoncer "joignable a partir du demarrage des
services, pas pendant l'amorcage", et non "joignable". L'option CGNAT seule
promettrait quelque chose de faux.

### 2.3 Portail captif. Defaut propose: DESACTIVE, et TEMPORAIRE par construction

Le probleme est structurel et sans solution automatique propre: le portail
exige un acces reseau pour s'authentifier, le filtre l'interdit tant que le
tunnel n'est pas monte, et le tunnel ne peut pas monter avant
l'authentification. La reponse de Mullvad est de dire a l'utilisateur de
desactiver le mode lockdown, ce qui marche mais laisse la machine nue et
compte sur lui pour le reactiver.

Meilleure forme, et c'est un vrai apport possible: un bouton "je dois passer un
portail captif" qui relache la politique pour une duree BORNEE, avec un compte a
rebours visible, et qui la reprend tout seul a l'echeance. Jamais un
interrupteur permanent. Sans bornage, cette option est simplement le bouton
"desactiver la protection" avec un autre nom.

Ne PAS chercher a autoriser les URL de detection de portail par liste
(`msftconnecttest.com` et compagnie): c'est du trafic vers un tiers depuis
l'adresse reelle, donc une fuite, et la liste change selon l'OS et les versions.

### 2.4 Synchronisation de l'heure. Defaut propose: DESACTIVE, a mesurer avant de trancher

A verifier avant d'en faire une option: la poignee de main WireGuard transporte
un horodatage et le pair rejette un horodatage anterieur au dernier vu pour ce
meme pair. Une machine dont l'horloge recule - pile CMOS morte, premier
demarrage - pourrait donc ne plus pouvoir monter son tunnel, et un filtre de
demarrage qui bloque NTP rendrait la panne definitive. **Hypothese, non
mesuree ici.** Si elle se confirme, l'exemption NTP devient necessaire et non
plus optionnelle, avec sa contrepartie: elle revele l'adresse reelle au serveur
de temps. La bonne reponse serait alors de synchroniser DANS le tunnel une fois
monte, et de n'ouvrir NTP au demarrage que le temps d'une resynchronisation.

## 3. Jamais autorise, et pourquoi le dire

- **DNS en clair hors tunnel (port 53).** C'est la fuite classique, et tout
  l'objet du resolveur chiffre embarque.
- **Verification de connectivite de l'OS.** Son blocage fait afficher "pas
  d'acces internet" par Windows alors que le tunnel fonctionne. Effet
  cosmetique, a documenter dans l'interface pour eviter le ticket de support,
  pas a corriger en ouvrant le trafic.
- **Mise a jour, telemetrie, tout le reste.** Par defaut, le filtre de
  demarrage bloque; ce document ne liste que les trous.

## 4. Deux decisions de produit qui ne sont pas des options

**Le filtre de demarrage est OPT-IN.** Mullvad ne pose ses filtres persistants
que si l'utilisateur a active le mode lockdown ou la connexion automatique.
Meme choix ici, et pour une raison simple: le mode de panne d'un defaut sur ce
chemin est une machine sans reseau, chez quelqu'un qui n'a pas les moyens de
diagnostiquer. Une protection qui s'active toute seule et qui peut casser la
machine n'est pas un defaut acceptable.

**La sortie de secours n'est pas negociable et doit etre eprouvee AVANT la
mise en service.** Une commande qui retire les filtres sans reseau, des GUID
fixes connus d'avance, et une procedure ecrite. La demonstration que ce n'est
pas theorique: essai-windows est restee a moitie coupee le 17 aout 2026 parce
que le chemin de retrait avait deux defauts, un filtre boot-time non enumerable
sans GUID fixe et un code d'erreur non tolere. Voir le probleme ouvert 2.

## 5. Hors perimetre pour l'instant

Machines jointes a un domaine: un blocage au demarrage retarde ou casse
l'ouverture de session quand un controleur de domaine n'est pas joignable, et
les strategies de groupe ne s'appliquent pas. Microsoft documente le probleme
pour son propre Always On VPN, ou un filtre de trafic sur le tunnel machine
produit ces symptomes. A traiter le jour ou le produit vise ce public, pas
avant.

## Sources

- `mullvadvpn-app/docs/security.md`, regles de pare-feu par etat
- mullvad/mullvadvpn-app issues 2674, 6086, 6219, 8247
- Mullvad, page "Local Network Access"
- Microsoft Learn, Always On VPN, filtres de trafic sur tunnel machine
- Notes de support NordVPN et retours terrain sur les portails captifs
