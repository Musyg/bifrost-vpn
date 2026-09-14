# Bifrost - Couche "anonymat reel": architecture de sortie, modeles de menace et implementation (etat au 25 juillet 2026)

## TL;DR
- Un VPN auto-heberge mono-utilisateur ne fournit PAS d'anonymat: l'IP de sortie unique est un identifiant stable attribuable a une personne, ce qui le rend inferieur a un pool commercial partage face aux adversaires 1, 2 et 4. Il fournit de la confidentialite et du controle, pas de l'anonymat. Le produit doit refuser le mot "anonymat" pour le mono-saut et le reserver aux modes Tor/Nym.
- La recommandation par defaut pour "anonymat renforce" est l'architecture hybride client -> VPS perso (entree, resistance DPI, controle) -> Mullvad/IVPN (sortie, foule partagee), mais elle viole les CGU de Mullvad et n'echappe pas a la correlation par adversaire global. Le seul mode qui resiste reellement a la correlation de trafic est le mixnet Nym en mode Anonymous (5 sauts) ou Tor, au prix d'une latence multipliee.
- En 2026, l'IP de sortie n'est plus le facteur limitant dominant pour la plupart des utilisateurs: le fingerprinting applicatif (JA4/JA4+, canvas, comptes connectes) domine. Un produit honnete doit dire que sans navigateur durci et sans discipline de compte, aucune architecture reseau ne rend anonyme.

## Key Findings

1. **Le paradoxe de l'IP unique est reel et non contournable par la seule ingenierie reseau.** L'ensemble d'anonymat d'un VPS mono-utilisateur est de taille 1. Un pool commercial partage place l'utilisateur dans une foule de plusieurs milliers d'IP-partageantes par serveur. Le VPS auto-heberge gagne sur le controle et la resistance DPI, jamais sur la taille d'ensemble d'anonymat.

2. **La correlation de trafic assistee par ML est operationnelle et efficace.** DeepCoFFEA (Oh, Yang, Mathews, Holland, Rahman, Hopper, Wright, IEEE S&P 2022, DOI 10.1109/SP46214.2022.9833801) atteint "93% true positive rate versus at most 13% when tuned for high precision, with two orders of magnitude speedup over prior work". DeepCorr (Nasr, Bahramali, Houmansadr, arXiv:1808.07285) atteint 96% de precision avec environ 900 paquets par flux ("compared to 4% by the state-of-the-art system of RAPTOR"). Aucune architecture low-latency (mono-saut, multi-hop, VPN->Mullvad) ne bat un adversaire passif global. Seuls les mixnets (Nym Anonymous) et dans une moindre mesure Tor + DAITA opposent une resistance mesurable.

3. **Nym est le seul mixnet grand public operationnel en 2026, mais lent.** Environ 500 mixnodes actifs, mode Anonymous a 5 sauts (format Sphinx, base Loopix), cout d'environ 1 Mbps de debit stable et quelques dizaines de ms de latence ajoutee par le mixing plus jusqu'a 200 ms par hop en profil High. Navigation utilisable mais penible (chargement de page de plusieurs secondes). Mode Fast (2 sauts, dVPN AmneziaWG) comparable a un VPN classique mais sans mixing donc sans propriete anti-correlation.

4. **DAITA/Maybenot est integrable et sous licence permissive.** Maybenot est en Rust, double licence MIT ou Apache 2.0, disponible sur crates.io avec un wrapper FFI. Le surcout mesure est important (les portages RegulaTor sur Maybenot montrent plus de 100% de surcout de bande passante), ce qui explique pourquoi Mullvad l'applique uniquement au dernier saut client<->serveur.

5. **Le KYC hebergeur se durcit en Europe (NIS2) mais des niches sans KYC subsistent.** IONOS a supprime la confidentialite WHOIS pour tous ses TLD le 6 mars 2026 (transposition allemande de NIS2 de decembre 2025, obligation article 28); Hetzner a mis en place une verification d'identite via iDenfy. A l'oppose, Njalla, SporeStack, 1984 Hosting, AlexHost et Incognet restent sans KYC et acceptent Monero.

6. **Le "no logs" tient a la saisie: cas documentes.** Le raid de la police suedoise (NOA) chez Mullvad le 18 avril 2023 s'est solde par un depart sans rien; la saisie Perfect Privacy a Rotterdam le 24 aout 2016 n'a rien donne. Le RAM-only reduit encore la surface. Mais sur infrastructure louee, netflow datacenter et logs hyperviseur subsistent hors de votre controle.

## Details

### PARTIE 1 - MODELISATION DE LA MENACE ET METRIQUE D'ANONYMAT

#### 1.1 Modeles de menace

| Adversaire | Ce qu'il voit | Ce qu'il peut deduire | Ce qui le bat |
|---|---|---|---|
| A1 FAI local, marketing, traqueurs | IP source, DNS, SNI, volumes | Qui vous etes chez le FAI; profil comportemental cote web via cookies/IP | Tout tunnel chiffre avec DNS local; mono-saut VPS suffit largement |
| A2 Plateforme fingerprinteuse (Google, Meta, Cloudflare, DataDome) | JA4/JA4+, HTTP/2, canvas, comptes connectes, IP de sortie | Vous relie a travers les sessions meme sans cookies; IP secondaire | Navigateur durci (Mullvad/Tor Browser), isolation de comptes, PAS l'IP seule |
| A3 Autorite judiciaire avec requisition sur l'hebergeur | Contenu du serveur saisi, donnees hebergeur (KYC, paiement, netflow) | Attribution du serveur a une identite civile via chaine de paiement/KYC | RAM-only, acquisition Monero sans KYC, juridiction non cooperante, multi-hop inter-juridictions |
| A4 Adversaire passif global (correlation entree/sortie) | Timing et volumes aux deux bouts | Correle flux d'entree et de sortie meme chiffres (DeepCoFFEA 93% TPR) | Mixnet (Nym Anonymous), padding constant + cover traffic; JAMAIS un VPN low-latency |
| A5 Adversaire actif etatique (injection, sondage, saisie) | Tout A4 + capacite de saisie et d'injection active | Deanonymisation par confirmation active, saisie de maillon | Combinaison RAM-only + multi-hop + mixnet + OpSec parfaite; en pratique tres difficile a garantir |

#### 1.2 Metrique d'anonymat

Definitions operationnelles:
- **Taille de l'ensemble d'anonymat (anonymity set)**: nombre d'utilisateurs indistinguables du point de vue de l'adversaire. VPS mono-utilisateur = 1. C'est la metrique qui condamne le mono-saut.
- **Entropie**: log2 de la taille effective de l'ensemble, ponderee par les probabilites. Un pool commercial partage augmente l'entropie cote IP; il ne fait rien pour l'entropie cote fingerprint applicatif.
- **Unlinkability**: incapacite de relier deux actions au meme sujet. C'est la propriete que visent Nym (zk-nyms separant paiement et trafic, credentials a divulgation nulle de connaissance) et Tor (isolation par flux).

**Donnees publiques sur la taille des pools commerciaux:** les fournisseurs ne publient pas de compte d'utilisateurs simultanes par serveur en temps reel. On sait que des centaines a des milliers d'utilisateurs partagent une meme IP de sortie chez les grands fournisseurs, ce qui est structurellement superieur a 1. C'est une information dont la precision est incertaine et qui doit etre presentee comme telle.

**L'IP de sortie est-elle le facteur limitant en 2026 ? Reponse honnete: non, pour la plupart des cas.** Le fingerprinting applicatif domine. En 2026, JA4+ est le standard universel de fingerprinting TLS adopte par Cloudflare, AWS, VirusTotal, Akamai (source: krowdev "How Websites Detect Bots in 2026", proxies.sx guide JA4+ 2026). Le blog Cloudflare "JA4 Signals" indique analyser "over 15 million unique JA4 fingerprints generated from more than 500 million user agents and billions of IP addresses" par jour, et correler JA4 contre le user-agent declare (une incoherence est un signal primaire). La correlation cross-session par canvas, WebGL, polices et surtout comptes connectes rend l'IP presque secondaire. Conclusion pour le produit: sans discipline navigateur et compte, changer d'IP ne rend pas anonyme.

### PARTIE 2 - ARCHITECTURES DE SORTIE COMPAREES

Tableau de synthese (latences ajoutees indicatives, a valider par mesure sur votre parc):

| Architecture | Latence ajoutee | Debit | Cout mensuel | Complexite | Bat A1 | Bat A2 | Bat A3 | Bat A4 |
|---|---|---|---|---|---|---|---|---|
| 2.1 Mono-saut VPS | +5 a +40 ms | ligne du VPS | 3 a 15 EUR | faible | oui | non (IP unique) | partiel | non |
| 2.2 Multi-hop 2 VPS | +30 a +120 ms | min des sauts | 6 a 40 EUR | moyenne | oui | non | oui si juridictions distinctes | non |
| 2.3 VPS -> Mullvad/IVPN | +30 a +90 ms | ~ligne Mullvad | 3 a 15 + 5 EUR | moyenne | oui | partiel (foule) | oui | non |
| 2.4 VPN -> Tor | +centaines de ms | 0.5 a 2 Mbit/s typique | 3 a 15 EUR | moyenne | oui | partiel | oui | partiel |
| 2.5 VPN -> Nym Anonymous | +centaines de ms a s | ~1 Mbit/s | 3 a 15 + ~4 EUR | elevee | oui | oui | oui | oui (mesurable) |
| 2.6 Pools tournants / residentiel | variable | variable | eleve | elevee | oui | detectable/ethiquement problematique | variable | non |

#### 2.1 Mono-saut VPS proprietaire
Suffisant contre A1 (FAI, traqueurs) et pour contourner la censure/geoblocage. Dangereux des que l'adversaire est A2 ou plus: l'IP unique devient un identifiant. A n'exposer dans le produit que comme "confidentialite/controle", jamais comme "anonymat".

#### 2.2 Multi-hop entre VPS de juridictions differentes
Construction par WireGuard chaine. Principe cle (documente par Pro Custodibus "Multi-Hop WireGuard", 2022): `AllowedIPs` definit ce qui est route vers chaque peer; pour tout envoyer via le dernier saut, on met `0.0.0.0/0, ::/0`. Sur le VPS intermediaire, activer le forwarding et le NAT (masquerade).

Exemple minimal sur le VPS 1 (entree, recoit le client, sort vers VPS 2):
```ini
# /etc/wireguard/wg0.conf sur VPS1 (cote client)
[Interface]
Address = 10.10.0.1/24
ListenPort = 51820
PrivateKey = <cle_privee_vps1>
PostUp = sysctl -w net.ipv4.ip_forward=1
PostUp = nft add table ip nat; nft add chain ip nat post { type nat hook postrouting priority 100 \; }; nft add rule ip nat post oifname "wg1" masquerade
[Peer] # le client
PublicKey = <cle_pub_client>
AllowedIPs = 10.10.0.2/32

# /etc/wireguard/wg1.conf sur VPS1 (vers VPS2, saut de sortie)
[Interface]
Address = 10.20.0.2/24
PrivateKey = <cle_privee_vps1_wg1>
[Peer] # VPS2
PublicKey = <cle_pub_vps2>
Endpoint = <ip_vps2>:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
```

Isolation renforcee par network namespaces (empeche les fuites si le processus applicatif est compromis). Reutilisable: le script `wg-netns` (Accelerox/wireguard-namespace sur GitHub) execute un processus dans un namespace WireGuard dedie sans toucher aux regles iptables globales.

**Gain reel:** aide contre A3 (aucun hebergeur unique ne voit entree ET sortie, a condition de juridictions et de fournisseurs distincts). N'aide PAS contre A4 (correlation) ni A2 (IP de sortie toujours unique). **Le chainage chez le meme fournisseur ou dans la meme juridiction annule le benefice A3**: un seul acteur (ou une seule requisition) voit les deux bouts.

**Latence:** chaque saut ajoute la RTT entre datacenters. Comptez +30 a +120 ms selon distances. A noter: le double chiffrement/dechiffrement a chaque saut est peu couteux en CPU avec WireGuard mais le debit tombe au minimum des sauts.

#### 2.3 Sortie via fournisseur commercial en dernier saut (VPS perso -> Mullvad/IVPN)
Architecture: client -> VPS perso (entree, resistance DPI via votre couche sing-box/REALITY, controle total) -> client WireGuard Mullvad/IVPN sur le VPS (sortie dans la foule partagee).

**Faisabilite technique: oui, robuste et automatisable.** On genere une cle sur le VPS et on recupere la configuration via l'API Mullvad (procede documente par la doc OPNsense de Mullvad):
```bash
# Sur le VPS: generer la cle et l'enregistrer via l'API Mullvad
wg genkey | tee privatekey | wg pubkey > publickey
curl -sSL https://api.mullvad.net/app/v1/wireguard-keys \
  -H "Content-Type: application/json" \
  -H "Authorization: Token VOTRE_NUMERO_DE_COMPTE" \
  -d "{\"pubkey\":\"$(cat publickey)\"}"
# La reponse contient l'Allowed IP attribuee. On assemble ensuite wg1.conf
# avec Endpoint = <serveur>.mullvad.net:51820 et PublicKey du serveur choisi.
```
Le routage se fait comme en 2.2 (le peer Mullvad porte `AllowedIPs = 0.0.0.0/0`).

**CGU: c'est un point bloquant pour une integration dans le produit.** Les CGU de Mullvad interdisent explicitement (verbatim): "You are prohibited from utilizing this service to provide a service similar to that provided by Mullvad or other services where VPN constitutes a significant part of the service." Un usage personnel sur son propre VPS n'est pas une revente, mais integrer Mullvad comme saut de sortie dans le produit distribue a des tiers viole ces CGU. **Recommandation: ne pas cabler Mullvad/IVPN en dur dans le produit; laisser l'utilisateur fournir son propre compte.** Note: Mullvad a mis fin a OpenVPN le 15 janvier 2026 (WireGuard only).

**Est-ce le meilleur des deux mondes ? Partiellement, et avec des failles.** Gains: foule partagee cote sortie (bat partiellement A2 sur l'IP), controle et anti-DPI cote entree, protection contre A3 (Mullvad ne voit pas votre client, votre VPS ne voit pas la destination reelle en clair). Failles: (1) l'IP de sortie Mullvad est partagee mais largement bloquee/CAPTCHAee par les plateformes; (2) ne bat pas A4 (correlation globale); (3) viole les CGU; (4) ajoute un point de confiance (Mullvad); (5) l'obfuscation anti-censure de Mullvad est indisponible hors app officielle (WireGuard nu perd cet avantage).

#### 2.4 VPN vers Tor
Architectures:
- **Tor over VPN** (VPN puis Tor): cache l'usage de Tor au FAI et au premier noeud; le fournisseur VPN voit que vous entrez sur Tor mais pas la destination. C'est la configuration a privilegier pour la plupart des cas (position Proton VPN, NordVPN).
- **VPN over Tor** (Tor puis VPN): la destination voit une IP VPN et non une sortie Tor (utile contre le blocage des exit nodes), mais le fournisseur VPN voit le trafic sortant et re-introduit un point de confiance; plus complexe et plus faillible.
- **Tor pour certaines applications seulement**: isolation par flux via SOCKS.

Erreurs classiques: forcer le trafic Tor a travers un client VPN apres coup; se croire anonyme envers un site ou l'on est connecte a un compte (l'IP ne compte plus, le compte vous identifie); melanger flux identifiants et anonymes dans le meme circuit.

**Implementation isolation par flux** (torrc):
```
# Isolation par destination et par identifiants SOCKS
SocksPort 9050 IsolateDestAddr IsolateDestPort
SocksPort 9051 IsolateSOCKSAuth
# Proxy transparent (redirection nftables du trafic TCP vers TransPort)
TransPort 9040
DNSPort 5353
VirtualAddrNetworkIPv4 10.192.0.0/10
AutomapHostsOnResolve 1
```

**Etat mesure du reseau Tor en 2026:** environ 7500 a 9500 relais actifs (dont environ 1500 a 2000 exit relays), capacite advertised de l'ordre de 700 a 900 Gbit/s et consommation de l'ordre de 300 a 500 Gbit/s (source: Tor Metrics, syntheses 99coupons/sqmagazine 2026). Debit par circuit cote client typiquement de l'ordre de 0.5 a 2 Mbit/s pour un usage courant (mesures independantes: distribution centree autour de 1 a 1.5 Mbit/s dans les tests de routeur Tor), avec une RTT applicative souvent citee autour de 400 ms. Ces chiffres varient dans le temps; a valider sur Tor Metrics (onionperf-throughput.html, onionperf-latencies.html) au moment du deploiement. Version stable Tor 0.4.9.8 (7 mai 2026).

**Probleme des exit nodes:** blocage massif par les sites (CAPTCHA, 403), risque de noeud de sortie malveillant sniffant le trafic non chiffre en bout, et exposition legale des operateurs. Le Tor Project explore des relais RAM-only "stateless" (impulsion de l'ONG italienne Osservatorio Nessuno) pour resister aux saisies materielles.

#### 2.5 VPN vers Nym mixnet
**Etat reel au 25 juillet 2026 (fraicheur a signaler):** l'API Nym `/v1/mixnodes/active` renvoyait un compte d'environ 498 mixnodes actifs. NymVPN annonce de l'ordre de 713 serveurs sur environ 149 localisations dans 72 pays (Tom's Guide, 2026). Logiciel Nym en Rust, GPLv3, release stable v2025.2 "Hu" (fevrier 2025). Chief Scientist: Prof. Claudia Diaz (ex-KU Leuven). Le mixnet est base sur Loopix, format de paquet Sphinx. Editeur: Nym Technologies S.A. (Suisse).

**Modes:**
- **Fast (2 sauts, dVPN base AmneziaWG):** debit comparable a un VPN classique, PAS de mixing donc PAS de propriete anti-correlation. Protege l'IP et resiste a la censure, rien de plus.
- **Anonymous (5 sauts: entry gateway + 3 mixnodes + exit gateway, Sphinx):** chaque mixnode retient chaque paquet un delai aleatoire tire d'une loi exponentielle, plus cover traffic constant. C'est le seul mode grand public qui vise l'unlinkability contre A4. Cout (source: blog Nym "Mixnet Tuning"): "about 1 Mbps of steady throughput and a few tens of milliseconds of added latency", cover traffic reglable de 0.7 a 2 Mbps, delai par mixnode reglable jusqu'a 200 ms par hop en profil "High".

**Latence acceptable ?** Pour messagerie et navigation legere, oui mais penible: un testeur (tabswire, 6 semaines d'usage, 2026) rapporte "Mixnet mode is somewhere between 'works for email and chat' and 'watch a YouTube video at 480p if you're patient'... the page took eleven seconds to render". Pour streaming, non. Connexion etablie en 4 a 5 s (kripeshadwani, 2026). Audit Cure53. Prix NymVPN: 14.99 USD/mois, 4.49 USD/mois en annuel, 3.79 USD/mois en 2 ans (Tom's Guide 2026); politique fair-use 2 To/mois.

**Peut-on chainer son propre VPN vers Nym ?** Techniquement, on peut faire tourner le client Nym derriere son VPS d'entree (VPS -> gateway Nym). Le mixnet n'expose pas un simple endpoint WireGuard classique cote mixing; l'integration passe par le client Nym (nym-client / nym-vpn-cli) ou les bibliotheques Rust/TypeScript officielles (MixnetClient::connect_new()). C'est plus lourd qu'un simple peer WireGuard.

**Nym est-il le seul mixnet operationnel en 2026 ? En pratique, oui pour le grand public.** HOPR existe mais oriente messagerie/infrastructure; les derivatifs Loopix (Karst, autres) restent academiques ou non deployes a l'echelle grand public. A signaler comme information dont la fraicheur est incertaine.

#### 2.6 Pools d'IP tournants et sorties multiples
- **Rotation d'IP entre plusieurs VPS:** faisable, mais cree un motif detectable (meme fingerprint applicatif surgissant depuis un jeu d'IP correlees) et n'augmente pas l'ensemble d'anonymat cote fingerprint. Amelioration d'anonymat marginale voire negative.
- **Sortie residentielle (proxies residentiels):** techniquement efficace contre le blocage (hCaptcha, aout 2025: les principaux WAF/CDN detectent "less than 10% of requests in some attacks using residential proxies"), mais **ethiquement et legalement toxique**: une part majeure de l'offre provient de malware et de SDK revendant la bande passante d'utilisateurs a leur insu. Le PSA du FBI de juin 2025 sur BADBOX 2.0 decrit "millions of infected devices" maintenant des backdoors vers des services proxy (>1 million d'appareils selon HUMAN Satori mars 2025, jusqu'a 10 millions d'appareils AOSP selon Google); le botnet apparente mesure par Lumen Black Lotus Labs compte "between 1.5 million and 2.5 million distinct IP addresses each day". Alerte FBI 2026 sur les proxies residentiels. **A proscrire dans un produit qui se veut ethique.**
- **Sortie mobile CGNAT:** meilleure foule theorique (enorme, blocage quasi impossible car IP partagee par des milliers d'abonnes), mais peu praticable et peu stable pour une petite structure (necessite SIM/modems, IP non routable entrante, gestion CGNAT). Interessant en theorie, marginal en pratique pour un produit.

#### 2.7 Decision finale par modele de menace

| Besoin / adversaire principal | Architecture recommandee | Cout latence | Cout mensuel |
|---|---|---|---|
| A1 seul (FAI, pub, geoblocage) | Mono-saut VPS (2.1) | negligeable | 3 a 15 EUR |
| A2 (plateformes) | VPS -> foule commerciale (2.3) + navigateur durci | faible | +5 EUR + compte |
| A3 (justice/hebergeur) | Multi-hop inter-juridictions (2.2) + RAM-only + Monero | moyen | 6 a 40 EUR |
| A4 (correlation globale) | Nym Anonymous (2.5) ou Tor+DAITA | eleve | +4 EUR |
| A5 (etat actif) | Nym/Tor + RAM-only + multi-hop + OS dedie; garanties limitees | tres eleve | variable |

### PARTIE 3 - DEFENSE CONTRE LA CORRELATION DE TRAFIC

**Etat de l'art 2026:** DeepCoFFEA (metric learning + amplification, IEEE S&P 2022) atteint "93% true positive rate versus at most 13% when tuned for high precision, with two orders of magnitude speedup". DeepCorr (arXiv:1808.07285) atteint 96% de precision avec environ 900 paquets par flux. Cote website fingerprinting (adversaire local, un seul bout): plus de 96% en closed-world de 100 sites, plus de 94% en 900 classes (Rimmer et al., "Automated Website Fingerprinting through Deep Learning", NDSS 2018); attaques recentes Holmes (CCS 2024), Laserbeak (IEEE TIFS 2024). En multi-onglets/realiste, la precision chute (Holmes note une precision minimale de 42.86% pour ARES et 54.11% pour DF sous trafic obfusque en multi-tab), ce qui nuance la menace en conditions realistes. Condition realiste cle: l'attaque A4 requiert l'observation des deux bouts, ce qui limite qui peut la monter (etat, grand acteur reseau).

**DAITA de Mullvad et Maybenot:** DAITA = Maybenot + defenses sur-mesure + integration (source: Pulls, "Evaluating using the first eight DAITA servers", 2024). Maybenot (Pulls et al., "Maybenot: A Framework for Traffic Analysis Defenses", arXiv:2304.09510, version 2) est un framework de machines a etats qui injecte du padding et du trafic factice cote client ET cote serveur. Techniques (verbatim Mullvad): "constant packet sizes, random background traffic and data pattern distortion". Versions v1 (2024) et v2 (2025); v2 ajoute une base de defenses evolutive pour invalider periodiquement les modeles d'attaque. Developpe avec l'Universite de Karlstad. Integre dans wireguard-go via le wrapper wireguard-go-rs.

**Surcout mesure:** l'integration de padding a un cout non trivial. L'evaluation "State Machine Frameworks for Website Fingerprinting Defenses: Maybe Not" (arXiv:2310.10789) mesure, pour les portages RegulaTor sur Maybenot: "Maybenot RT-Light incurred 178.18% overhead... and Maybenot RT-Heavy's overhead was 212.96%", avec une latence de l'ordre de 15 a 22%, concluant qu'un surcout d'environ 108% en bande passante "makes Maybenot RegulaTor too costly for implementation in Tor". Mullvad limite donc DAITA au saut client<->serveur avec des defenses calibrees.

**Integration dans un produit tiers: oui.** Maybenot (framework + simulateur) est sur crates.io "dual-licensed under either the MIT or Apache 2.0 license", avec un wrapper FFI (maybenot-ffi) de meme licence. Maturite: bibliotheque en production chez Mullvad. Effort: reutiliser le binding FFI dans votre wireguard-go; l'issue netbird #2366 documente le chemin ("Incorporate maybenot using maybenot's-ffi c binding into wireguard-go. Mullvad has done so with their wireguard-go-rs wrapper, meaning that most of the heavy lifting is done").

**Autres defenses (cout/efficacite):**
- Padding constant a debit fixe: efficace mais gaspilleur (bande passante constante).
- Cover traffic (Nym): efficace contre A4 car mixe plusieurs utilisateurs; cout ~1 Mbps constant.
- Delais aleatoires (mixing): coeur de l'efficacite Nym; cout en latence direct.

**Les mixnets resolvent-ils la correlation ou la deplacent-ils ? Analyse honnete.** Un mixnet resout reellement la correlation timing/volume au sein de sa fenetre de mixing, a condition d'un ensemble d'anonymat suffisant (assez d'utilisateurs simultanes). Le probleme deplace: l'anonymat depend du nombre d'utilisateurs concurrents. Si le trafic reel est faible, le cover traffic doit compenser, et un adversaire qui controle beaucoup de noeuds ou observe globalement avec peu d'utilisateurs reduit le gain. Le mixnet echange donc "correlation deterministe" contre "anonymat probabiliste dependant de la foule et de la latence". Ce compromis est formalise par le trilemme des reseaux d'anonymat (Das, Meiser, Mohammadi, Kate; confirme dans la litterature ACN): anonymat fort, faible latence et faible bande passante ne sont pas simultanement atteignables.

### PARTIE 4 - INFRASTRUCTURE SERVEUR: RAM-ONLY, SANS TRACE

#### 4.1 Noeuds RAM-only sur VPS loue
Le modele de reference est Mullvad System Transparency (blog Mullvad "Diskless infrastructure"): bootloader stboot qui telecharge un OS package signe depuis un serveur de provisioning, en verifie la signature, et boote en RAM sans disque; OS d'environ 200 MB, noyau Linux slimme suivant mainline. Verbatim: "Our VPN servers launch the System Transparency bootloader (stboot) which downloads the OS package from a provisioning server and verifies that it originates from relevant Mullvad VPN staff by checking its signatures." Les serveurs de provisioning ont des disques (images signees + config de base). Migration completee et auditee (2022, 2023).

**Procedure reproductible sur VPS loue (Hetzner/OVH ou autre):**
```bash
# Approche 1: overlayroot en RAM (Debian 12/Ubuntu 24.04)
apt-get install -y overlayroot
# /etc/overlayroot.conf
overlayroot="tmpfs:swap=1,recurse=0"
# Au reboot, le disque devient read-only et toutes les ecritures vont en tmpfs (RAM),
# perdues a l'extinction. Le disque ne contient que l'image de base.

# Approche 2: iPXE + squashfs en RAM (boot reseau)
# 1) Booter le VPS en rescue system (Hetzner: activable au panel/API).
# 2) Recuperer un squashfs immuable signe depuis un serveur de provisioning HTTPS.
# 3) Charger noyau + initramfs qui monte le squashfs en RAM (toram) via un initrd custom.
#    Exemple de ligne de boot: kernel ... boot=live toram fetch=https://prov.example/os.squashfs

# Approche 3: OS immuables
# - Flatcar Container Linux / Talos: root immuable, config declarative (Ignition/machine config).
# - NixOS: generation reproductible; root en tmpfs (fileSystems."/" = { fsType = "tmpfs"; })
#   avec /nix/store monte depuis une image, config 100% declarative et auditable.
```

**Ce qui est reellement gagne:** disparaissent les traces sur disque local (logs, cles a froid, historique) apres coupure d'alimentation. **Ce qui subsiste hors de votre controle:** logs de l'hyperviseur, netflow du datacenter, snapshots eventuels pris par l'hebergeur, metadonnees de facturation/reseau. Le RAM-only ne protege pas contre un adversaire qui observe le lien reseau du datacenter (A4/A5). Rappel Mullvad: "Running the system in RAM does not prevent the possibility of logging. It does however minimise the risk of accidentally storing something that can later be retrieved."

**Non reproductible sur infrastructure louee:** attestation materielle, TPM verifiable de bout en bout, Secure Boot dont vous controlez les cles, et la System Transparency complete facon Mullvad (qui suppose un controle physique/organisationnel du materiel et une chaine de signature auditable). Sur un VPS loue, vous ne pouvez pas prouver a un tiers ce qui tourne reellement sous l'hyperviseur: **residu de confiance = l'hebergeur et son hyperviseur.** C'est irreductible sur du loue.

#### 4.2 Durcissement anti-forensique
```bash
# journald en volatile (RAM uniquement)
mkdir -p /etc/systemd/journald.conf.d
printf '[Journal]\nStorage=volatile\nRuntimeMaxUse=64M\n' > /etc/systemd/journald.conf.d/volatile.conf
systemctl restart systemd-journald
# Desactiver l'historique shell
export HISTFILE=/dev/null; ln -sf /dev/null ~/.bash_history
# Chiffrement du disque si disque persistant (LUKS), cle non stockee sur la machine:
cryptsetup luksFormat /dev/sdX ; # deverrouillage manuel via SSH/dropbear au boot
# Effacement des logs residuels
find /var/log -type f -exec shred -u {} \; 2>/dev/null
```

**Saisie/requisition, cas documentes:**
- **Mullvad, 18 avril 2023 (communique Mullvad du 20 avril 2023):** "at least six police officers from the National Operations Department (NOA) of the Swedish Police visited the Mullvad VPN office in Gothenburg with a search warrant. They intended to seize computers with customer data. In line with our policies such customer data did not exist... they left without taking anything and without any customer information." Le mandat, accorde le 17 fevrier 2023, decoulait d'une demande d'entraide judiciaire allemande. L'Electronic Communications Act suedois (2022:482) ne s'applique pas aux fournisseurs VPN (pas de retention obligatoire).
- **Perfect Privacy, Rotterdam, 24 aout 2016 (blog Perfect Privacy / TorrentFreak):** la police neerlandaise a saisi deux serveurs directement chez l'hebergeur I3D, sans jamais contacter Perfect Privacy. Verbatim: "Since we are not logging any data there is currently no reason to believe that any user data was compromised." Service retabli en moins de 18 heures; serveurs restitues vers le 22 septembre 2016.
- **Contre-exemple (Ennetcom, 2016):** des serveurs de telephones chiffres qui, EUX, conservaient des donnees ont ete copies et exploites en justice. Enseignement: la saisie ne donne "rien" que si rien n'est stocke. Le maillon faible reste la chaine d'attribution (paiement, KYC) et l'observation reseau amont, pas le disque.

#### 4.3 Attribution et paiement
**Acquerir/payer un VPS sans lien avec l'identite civile (2026):** Monero (masque emetteur, recepteur, montant, contrairement a Bitcoin dont le registre est public et liable). Options sans KYC verifiees (sources: kycnot.me, criptovps, nordbastion/0xnull 2026):

| Hebergeur | KYC | Paiement | Notes |
|---|---|---|---|
| Njalla | Aucun (email/XMPP suffit) | Monero, BTC, ETH, LTC, ZEC | Fonde par Peter Sunde; proxy de confidentialite; VPS a partir d'environ 15 EUR/mois; miroir onion. Se reserve de transmettre email/XMPP aux autorites en cas de violation grave |
| SporeStack | Aucun, sans email (token) | Monero, BTC, BCH | API-first, serveurs ephemeres; revend de la capacite (DigitalOcean/Vultr); actif depuis 2017; pas d'exit Tor autorise |
| 1984 Hosting | Aucun pour crypto | BTC, XMR | Islande, energie verte |
| AlexHost | Aucun | Monero | Moldavie, hors UE/Five Eyes, a partir d'environ 2 EUR/mois |
| Incognet | Aucun | XMR, BTC | Hosting oriente confidentialite, Islande/US |

**Etat 2026 du KYC (fraicheur a signaler):** NIS2 durcit l'ecosysteme. IONOS a supprime la confidentialite WHOIS pour tous ses TLD le 6 mars 2026 (transposition allemande de NIS2 de decembre 2025, sans periode de transition; obligation article 28; source webhosting.today, 26 mars 2026); les particuliers restent proteges via RGPD. Hetzner a mis en place une verification d'identite via iDenfy. Les niches sans KYC ci-dessus subsistent mais sont sous pression reglementaire croissante.

**Operationnel sans trace:** email jetable ou XMPP/OTR (Njalla l'accepte), pas de numero de telephone, acces au panel via Tor, cle SSH dediee, jamais depuis l'IP domestique. **Risque de deanonymisation par la chaine de paiement:** un achat en Bitcoin depuis un exchange KYC relie l'identite civile au serveur; c'est le vecteur d'attribution le plus courant (le ledger BTC est public et liable). Utiliser Monero acquis hors KYC, ou du cash par courrier la ou c'est propose (Mullvad accepte le cash par la poste, modele transposable).

### PARTIE 5 - FACTEUR HUMAIN ET POSTE CLIENT

**Poids relatif reel des facteurs (du plus au moins determinant en 2026):**
1. **Comptes connectes** (Google/Meta): identification directe, l'IP ne compte plus.
2. **Fingerprint navigateur** (canvas, WebGL, polices, JA4/JA4+ cote TLS): correlation cross-session massive.
3. **Identifiants materiels / telemetrie OS**.
4. **IP de sortie**: important seulement en l'absence des trois precedents.

**Ce que le produit peut faire au niveau OS vs ce qui exige une VM/OS dedie:**
- Au niveau OS/produit: tunnel, kill switch fail-closed, DNS local, anti-telemetrie (deja fait), routage multi-hop/Tor/Nym.
- Exige une VM ou un OS dedie: isolation reseau anti-fuite meme si l'appli est compromise (**Whonix 18**, base Debian 13, Gateway Tor + Workstation isolee, requiert Qubes 4.3; Kloak anti-fingerprint de frappe reecrit en Wayland; supporte jusqu'en 2026 par Power Up Privacy), amnesie (**Tails**, fusionne avec le Tor Project depuis septembre 2024), compartimentation (**Qubes OS 4.3**, event buffering par defaut), durcissement general sans anonymat force (**Kicksecure**).

**Navigateur durci: recommander, ne pas reinventer.** N'integrez PAS un navigateur maison (vous heriteriez de tout le fardeau anti-fingerprint). Recommandez **Mullvad Browser** (fingerprint uniformise, sans Tor, pour usage VPN) et **Tor Browser** (pour anonymat reseau). C'est la position honnete: le produit gere le reseau, le navigateur gere l'application.

**Risque de fausse securite:** un utilisateur qui se croit anonyme en mono-saut et qui ne l'est pas est en danger accru (il baisse la garde). Le produit doit communiquer le niveau reel par mode (voir Partie 6 UI) et afficher explicitement "ceci ne vous rend pas anonyme envers les sites ou vous etes connecte".

### PARTIE 6 - IMPLEMENTATION DANS LE PRODUIT

**Architecture logicielle.** Vous avez deja sing-box et WireGuard. Modelez le chainage comme une pile d'"outbounds" ordonnee:
- Entree: votre couche anti-DPI (VLESS+REALITY+Vision, XHTTP-CDN, Hysteria2, AmneziaWG) inchangee.
- Sauts intermediaires: WireGuard chaine (2.2) via namespaces, ou outbounds sing-box empiles.
- Sortie speciale: Tor (SOCKS/Trans), Nym (via nym-client/nym-vpn-cli en processus separe, comme vous le faites deja pour sing-box/Xray).
- DAITA: binding FFI Maybenot dans le wireguard-go du dernier saut client<->serveur.

**Gestion des etats et kill switch.** Chaque maillon est un etat surveille (up/down/degraded). Regle: **le kill switch fail-closed (WFP + nftables, deja implemente) doit couper toute la chaine si N'IMPORTE QUEL maillon requis tombe**, jamais laisser le trafic "reflouer" vers un saut de niveau inferieur (sinon fuite silencieuse vers une IP moins protegee). Distinguer maillons "requis" (leur chute coupe tout) et "optionnels" (bascule automatique, deja implementee pour l'anti-censure).

**Interface: modele a trois niveaux, sans mensonge.**

| Niveau | Architecture | Ce qui est reellement protege | Ce qui n'est PAS protege | Cout latence affiche |
|---|---|---|---|---|
| Standard | Mono-saut VPS | FAI, geoblocage, snooping local | Correlation, IP unique attribuable, fingerprint | +5 a 40 ms |
| Renforce | Multi-hop inter-juridictions (+ foule commerciale optionnelle) | Attribution hebergeur (A3), FAI | Correlation globale (A4), fingerprint | +30 a 120 ms |
| Maximum | Nym Anonymous (ou Tor) + RAM-only | Correlation (A4) dans la limite de la foule, attribution | Fingerprint applicatif, comptes connectes | +centaines de ms a plusieurs s |

Afficher a chaque niveau la phrase honnete: "Aucun niveau ne vous rend anonyme si vous vous connectez a un compte ou si votre navigateur n'est pas durci."

**Licences et compatibilite avec le client MPL-2.0:**

| Composant | Licence | Compatible avec le client MPL-2.0 |
|---|---|---|
| Tor | BSD 3-clause | Oui (permissive) |
| Nym (nym) | GPLv3 | Oui mais copyleft: lier en processus separe (IPC), pas en lib statique, pour eviter la contamination |
| Maybenot | MIT ou Apache 2.0 | Oui (permissive, ideal) |
| Client Mullvad/IVPN | apps open source, mais CGU du service interdisent la revente | Non en dur; laisser l'utilisateur fournir son compte |

**Estimation d'effort (jours-homme), justifiee par reference a du code existant:**

| Composant | Effort | Justification / reutilisation |
|---|---|---|
| Multi-hop WireGuard + namespaces | 10 a 15 j | Patterns Pro Custodibus + script wg-netns a forker |
| Sortie Tor (Trans/SOCKS + isolation) | 8 a 12 j | torrc bien documente; wiring kill switch |
| Integration Nym (processus separe) | 15 a 25 j | Reutiliser votre pattern sing-box/Xray; nym-vpn-cli existe mais API mouvante |
| DAITA/Maybenot (FFI) | 15 a 25 j | Binding FFI existant; issue netbird #2366 comme guide; l'essentiel du travail est fait par wireguard-go-rs |
| RAM-only provisioning | 8 a 12 j | overlayroot/NixOS declaratif |
| UI niveaux + machine d'etats kill switch | 12 a 20 j | Etend votre bascule automatique existante |

**Reutilisable tel quel:** torrc, patterns WireGuard, crate Maybenot. **A forker:** wg-netns, wireguard-go-rs de Mullvad (pour DAITA). **A ecrire de zero:** orchestrateur d'etats de chaine, UI honnete des niveaux, provisioning RAM-only specifique a votre hebergeur.

**Pieges connus (issues des projets):** integration Maybenot dans wireguard-go non triviale (netbird #2366); API nym-vpn-cli et modes en evolution rapide (verifier a chaque release); Mullvad a mis fin a OpenVPN le 15 janvier 2026 (WireGuard only), impact si vous vous appuyiez dessus; obfuscation Mullvad indisponible hors app officielle (si vous cablez WireGuard nu vers Mullvad, vous perdez l'anti-censure Mullvad).

### PARTIE 7 - LIMITES, HONNETETE ET RISQUE

**Ce qu'aucune architecture ne protege:** les comptes connectes; le fingerprint applicatif si le navigateur n'est pas durci; la correlation par un adversaire global si le trafic est low-latency; les erreurs d'OpSec (paiement lie a l'identite, connexion depuis l'IP domestique); les metadonnees hors de votre controle (netflow datacenter, hyperviseur).

**Un produit peut-il honnetement promettre l'anonymat ? Non.** Position argumentee: promettre l'anonymat serait mensonger car (1) l'IP de sortie unique d'un auto-heberge est un identifiant, (2) le fingerprint applicatif domine et echappe au reseau, (3) la correlation globale bat toute architecture low-latency, (4) sur infrastructure louee subsiste un residu de confiance irreductible. **Le produit doit promettre confidentialite, controle et resistance a la censure, et parler d'anonymat UNIQUEMENT pour les modes Tor/Nym Anonymous, en explicitant leurs limites.**

**Risque de reputation et d'abus.** Un outil d'anonymat fort attire des usages illicites. Gestion par les projets existants: Tor assume et documente (transparence, recherche ouverte, cooperation limitee aux abus techniques); Mullvad refuse de detenir des donnees (rien a livrer, comme prouve en avril 2023) et communique honnetement ses limites; Njalla agit comme proxy de confidentialite mais se reserve de transmettre l'email/XMPP aux autorites en cas de violation grave de sa politique. **Recommandation produit:** politique d'usage acceptable claire, absence de logs par design (vous ne pouvez pas livrer ce que vous n'avez pas), communication honnete du niveau de protection, et refus explicite des sorties residentielles issues de malware.

## Recommendations

1. **Immediat (semaines 1 a 4):** implementer les niveaux Standard (mono-saut, existant) et Renforce (multi-hop inter-juridictions via WireGuard chaine + namespaces). Cabler le kill switch fail-closed sur toute la chaine. Renommer les libelles UI: bannir "anonymat" pour Standard/Renforce, employer "confidentialite et controle". Benchmark de bascule: si la latence Renforce depasse +150 ms mediane, revoir le choix des datacenters.
2. **Court terme (mois 2 a 3):** integrer la sortie Tor (isolation par flux via IsolateDestAddr/IsolateSOCKSAuth) et le mode Nym Anonymous en processus separe (reutiliser votre pattern sing-box/Xray). Afficher honnetement le cout latence. Recommander Mullvad Browser et Tor Browser plutot que d'integrer un navigateur.
3. **Moyen terme (mois 3 a 5):** integrer DAITA via le binding FFI Maybenot sur le dernier saut, en option activable (surcout bande passante potentiellement superieur a 100% selon la defense; a mesurer et afficher). Mettre en place le provisioning RAM-only (overlayroot ou NixOS declaratif) et documenter les traces residuelles hors de votre controle.
4. **Ne pas faire:** ne pas cabler Mullvad/IVPN en dur (CGU explicite interdisant la revente); ne pas proposer de sorties residentielles (malware/ethique, cf. BADBOX 2.0 et alerte FBI); ne pas promettre l'anonymat.
5. **Seuils qui changent la reco:** si Nym publie un ensemble d'anonymat mesurable et une latence en baisse, promouvoir le mode Maximum; si le nombre d'exit Tor chute sous un seuil operationnel (par ex. moins de 1000 exits), privilegier Nym.

## Caveats
- **Fraicheur incertaine (a revalider au deploiement):** taille exacte du mixnet Nym (environ 498 mixnodes actifs releves via l'API `/v1/mixnodes/active`, environ 713 serveurs NymVPN annonces par Tom's Guide 2026); debits Tor (fourchettes advertised 700-900 Gbit/s / consumed 300-500 Gbit/s et debit par circuit de 0.5-2 Mbit/s varient dans le temps sur Tor Metrics); etat du KYC hebergeur (durcissement NIS2 continu, niches sans KYC sous pression).
- Les tailles de pools commerciaux (utilisateurs simultanes par serveur) ne sont pas publiees precisement; l'affirmation "foule de milliers" est structurelle mais non chiffree par les fournisseurs.
- Les latences des architectures sont indicatives et dependent de la geographie de votre parc; a mesurer.
- Les surcouts DAITA/Maybenot cites (178% a 213%) proviennent de portages de defenses academiques (RegulaTor, arXiv:2310.10789) et non necessairement de la configuration exacte de DAITA v2 en production, qui n'est pas entierement publiee et evolue dans le temps par conception.
- Le cas Windscribe RAM-only (Pays-Bas, ~2025) est largement source par l'editeur et non entierement confirme par les autorites; a traiter comme declaratif.
- Les taux de succes des attaques de correlation/fingerprinting (93-96%) sont obtenus en conditions de laboratoire (closed-world, observation des deux bouts); en conditions realistes (open-world, multi-onglets), la precision chute nettement, ce qui borne la menace reelle a des adversaires disposant d'une visibilite reseau large (etat, grand acteur).