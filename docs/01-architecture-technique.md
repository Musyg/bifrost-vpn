# Bifrost : architecture technique d'un VPN auto-heberge de nouvelle generation

## TL;DR
- Un VPN auto-heberge peut atteindre une etancheite et un blocage de la telemetrie OS de premier plan, et une resistance DPI solide (via AmneziaWG + VLESS/REALITY empruntes a l'ecosysteme Xray/sing-box), mais il ne peut PAS egaler un pool partage sur l'anonymat pur : une IP de sortie unique et non partagee est un identifiant, pas un bouclier.
- La stack recommandee est WireGuard (noyau) + Rosenpass (post-quantique) pour le tunnel de base, avec une couche d'obfuscation sing-box (VLESS+REALITY en TCP/443, Hysteria2 en secours QUIC, AmneziaWG en repli), un kill switch WFP (Windows) / nftables+fwmark (Linux), et un filtrage DNS AdGuard Home ; pour l'anonymat reel, chainer vers Tor ou Nym plutot que de s'appuyer sur une IP VPS unique.

## Key Findings

1. **Le paradoxe de l'anonymat auto-heberge est reel et decisif.** Un VPS proprietaire donne une souverainete apparente mais une IP de sortie non partagee, donc une correlation triviale : tout observateur qui voit une seule personne derriere cette IP peut lui attribuer 100 % du trafic. Un pool commercial partage (Mullvad, IVPN) noie l'utilisateur dans une foule. La recommandation doit donc etre classee par modele de menace, pas par ideologie de souverainete.

2. **La resistance DPI 2026 ne se joue plus au niveau du protocole VPN mais du camouflage TLS/QUIC.** WireGuard nu est detecte et bloque par le TSPU russe et le GFW chinois. Les trois protocoles qui tiennent en 2026 sont VLESS+REALITY (camouflage TLS 1.3), Hysteria2 (QUIC), et AmneziaWG (WireGuard obfusque) ; la strategie gagnante est multi-protocole avec bascule automatique.

3. **Le GFW s'est nettement durci en 2025-2026** : censure SNI sur QUIC deployee depuis janvier 2025, detection des connexions DoH externes, cinq regles heuristiques de detection du trafic entierement chiffre, sondage actif, et "chasse" active aux IP de sortie via achat de services VPN puis coupure par les operateurs. Le 20 aout 2025, selon GFW Report (gfw.report, Mingshi Wu), entre ~00h34 et 01h48 heure de Pekin, le GFW a injecte sans condition des paquets TCP RST+ACK forges pour couper toutes les connexions sur le port TCP 443 pendant environ 74 minutes ; chaque SYN et SYN+ACK declenchait trois RST+ACK injectes (fenetres 1980/1981/1982), sans correspondance avec une empreinte de dispositif GFW connue.

4. **Le kill switch de niveau production exige WFP sur Windows** (la simple table de routage est contournable), et sur Linux un ensemble nftables + fwmark + `Table = off`. Le blocage de la telemetrie Windows par fichier hosts est mort (IP en dur, DoH interne).

5. **Le post-quantique est deja en production** chez Mullvad et reproductible en auto-heberge. Selon le blog officiel Mullvad (9 janvier 2025), la version desktop 2025.2 active par defaut les tunnels quantum-resistant sur Windows, ce qui les rend actifs par defaut sur toutes les plateformes desktop ; "les algorithmes actuellement utilises sont Classic McEliece et ML-KEM. Avec cette nouvelle version, nous sommes passes du standard Kyber anterieur au standard NIST ML-KEM". En auto-heberge, Rosenpass (McEliece + Kyber, PSK WireGuard rafraichie toutes les deux minutes) reproduit ce comportement.

## Details

### AXE 1 - Transport et protocole

**Comparatif des coeurs de tunnel (2026).** WireGuard en module noyau reste la reference de debit : il sature un lien 1 Gbps sur un seul coeur (99,89 % du maximum theorique sur un coeur Atom C3000 a 2,2 GHz d'apres Netgate) et depasse largement les implementations userspace. wireguard-go et boringtun (Rust) paient le cout des changements de contexte user/kernel : 20 a 40 % de debit en moins sur materiel rapide. Mullvad a introduit un nouveau moteur "GotaTun" en Rust optimise pour l'efficacite energetique. OpenVPN, meme avec DCO, est en fin de vie : Mullvad l'a retire en janvier 2026. MASQUE/CONNECT-UDP (RFC 9298) et QUIC natif sont pertinents surtout comme couche d'obfuscation (voir Axe 2), pas comme coeur de performance.

Conclusion operationnelle : coeur = WireGuard noyau sur Linux, WinTun sur Windows ; userspace uniquement en repli quand le noyau n'est pas disponible.

**Cryptographie post-quantique - etat de deploiement reel.** Mullvad a stabilise les tunnels quantum-resistant et les active par defaut sur desktop depuis la version 2025.2 (Windows inclus), via un echange hybride ; les docs officielles Mullvad (mullvad.net/en/help/quantum-resistant-tunnels-with-wireguard) confirment que le flag KEM par defaut est "cme-mlkem" (Classic McEliece + ML-KEM) pour negocier la PSK. IVPN a egalement deploye des tunnels quantum-resistant. Pour l'auto-heberge, Rosenpass (rosenpass.eu, MIT/Apache-2.0, ecrit en Rust) est la voie la plus simple : il tourne en parallele de WireGuard, effectue un echange post-quantique (Classic McEliece pour l'authenticite, Kyber pour la confidentialite) et injecte le secret dans la PSK toutes les deux minutes, sans toucher au binaire WireGuard. NIST a finalise ML-KEM (FIPS 203) en aout 2024. Le deploiement PQ TLS hybride (X25519MLKEM768) est desormais la norme cote navigateurs.

Conclusion operationnelle : WireGuard noyau + Rosenpass en side-car pour la PQ. C'est reproductible, formellement verifie (ProVerif) et gratuit.

**Defense contre l'analyse de trafic.** DAITA de Mullvad (Defense Against AI-guided Traffic Analysis) est la reference. Il repose sur le framework open source Maybenot et combine : (1) taille de paquet constante (padding), (2) injection de paquets factices, (3) distorsion du motif de trafic bidirectionnelle. Selon le blog Mullvad du 28 mars 2025 ("DAITA version 2 now available on all platforms"), en inserant plus soigneusement les paquets factices, "nous utilisons environ moitie moins de ces paquets tout en maintenant le meme niveau de defense", avec des configurations dynamiques par session "selectionnees parmi les milliers de configurations possibles" ; les travaux sont menes par Tobias Pulls (Universite de Karlstad) et DAITA v3 est deja sur la feuille de route. Le surcout est de l'ordre de 5 a 20 % de bande passante. Maybenot etant open source et revu academiquement, il est integrable dans un client auto-heberge.

Conclusion operationnelle : integrer Maybenot cote client et serveur ; c'est le seul moyen credible de resister a la correlation timing/volume, mais uniquement utile face a un adversaire capable d'analyse statistique globale.

**Benchmarks.** Kernel WireGuard : 1542 Mbps sur un seul coeur Xeon D-1541 (implementation noyau) contre 1370 Mbps pour wireguard-go sur le meme appareil (Netgate XG-1541), sature un lien 1 Gbps sur un coeur Atom. MTU par defaut 1420 (overhead 60 octets IPv4 / 80 IPv6). Sur ARM (Raspberry Pi 4, Cortex-A72), le debit chute nettement, ce qui impose du materiel x86 recent ou ARM serveur pour du multi-Gbps. GRO/GSO/TSO et le governor "performance" sont indispensables pour tenir 10 Gbps+ (Tailscale documente le franchissement des 10 Gb/s sur Linux via ces optimisations).

### AXE 2 - Resistance FAI / DPI / censure

**Protocoles SOTA 2026.** Les trois piliers de la resistance a la censure en 2026 :
- **VLESS + REALITY (Xray)** : camouflage TLS 1.3 qui emprunte le certificat d'un site legitime (Microsoft, Apple), en TCP/443. C'est le stack au taux de survie observe le plus eleve en Chine, Russie et Iran, surtout combine a Cloudflare/WARP. Repli obligatoire sur les reseaux qui filtrent QUIC.
- **Hysteria2** : base sur QUIC modifie (controle de congestion Brutal), obfuscation Salamander, se fond dans le trafic HTTP/3. Excellent sur reseaux mobiles a perte, mais attire l'attention des classificateurs QUIC agressifs.
- **AmneziaWG** : WireGuard obfusque (randomisation de la forme du paquet de handshake, phase de junk bytes). Simple, rapide, mais tombe sur les reseaux qui droppent l'UDP non reconnu.

Le consensus 2026 est le multi-protocole avec bascule automatique : le client teste chaque protocole et choisit le vivant. Shadowsocks-2022, Trojan, obfs4, Cloak, phantun, udp2raw restent utiles comme transports/replis mais ne sont plus des choix primaires.

**Sing-box vs Xray-core.** Sing-box (SagerNet, Go) est le choix par defaut recommande pour un nouveau produit multi-plateforme en 2026 : configuration JSON unifiee identique sur toutes les plateformes (iOS et routeurs inclus), support protocolaire le plus large, maintenance active. Xray-core reste la reference REALITY historique et pour XHTTP, avec une maturite superieure sur certains cas. Certaines configs VLESS ne fonctionnent qu'avec l'un ou l'autre backend. Recommandation : sing-box comme coeur client universel, avec Xray-core disponible en option pour XHTTP.

**Etat du blocage etatique 2026.**
- **Chine (GFW)** : censure SNI etendue a QUIC depuis janvier 2025 (le GFW extrait le SNI des connexions QUIC et bloque, d'apres le papier USENIX Security 2025 de GFW Report qui a mesure ~43,8K FQDN bloques par semaine sur la liste Tranco, 58 207 uniques sur trois mois) ; identification des connexions DoH externes ; cinq regles heuristiques (entropie, ratio ASCII) pour le trafic entierement chiffre ; sondage actif ; chasse active aux IP de sortie. L'episode RST+ACK du 20 aout 2025 (voir Key Findings) illustre l'imprevisibilite. WireGuard nu et Shadowsocks original sont morts.
- **Russie (TSPU)** : reconnait la signature WireGuard (0x01/0x02) depuis 2023 au moins ; tout WireGuard nu est droppe au niveau reseau sur quasi tous les FAI russes. AmneziaWG, VLESS Reality, Hysteria2 tiennent selon la tolerance UDP du reseau.
- **Iran** : filternet, blocage Shadowsocks documente ; REALITY + repli tiennent.

Sources primaires a suivre : GFW Report (gfw.report), net4people/bbs (GitHub), OONI, communautes Xray/sing-box (accepter sources en anglais, chinois, russe, farsi).

**ECH (Encrypted Client Hello).** RFC 9849 ratifiee le 3 mars 2026. ECH chiffre l'integralite du ClientHello interne (SNI, ALPN, ciphers) dans un ClientHello externe portant un SNI public de couverture. Cote defense : aveugle l'inspection passive et le filtrage par SNI ; Chrome (117+, defaut 122+), Firefox (118/119+ avec DoH), Safari 17+ le supportent. Cote attaque : ECH echoue "gracieusement" en retombant sur un handshake SNI visible, et le support cote serveur auto-heberge reste limite en 2026 (necessite publication de cles ECH via enregistrements DNS HTTPS/SVCB). Cote defense enterprise, il casse le filtrage NGFW base sur SNI.

Conclusion operationnelle : activer ECH cote client (via DoH) ; ne pas compter dessus comme unique defense car il retombe en clair. Le GFW extrait deja le SNI de QUIC, donc ECH+DoH est un complement, pas une solution.

**Detection heuristique par les FAI europeens/suisses.** Contrairement au GFW, les FAI europeens ne pratiquent pas de blocage protocolaire systematique. Les risques reels sont : throttling de certains ports, fingerprinting de handshake WireGuard (signature fixe), et blocage de ports non standard sur certains reseaux d'entreprise. La parade est de sortir en 443 (TCP via VLESS/REALITY, UDP via Hysteria2/QUIC) pour se fondre dans le HTTPS/HTTP3 legitime.

**Comportement en reseau hostile.** Captive portal : detecter et gerer la fenetre avant kill switch. Proxy d'entreprise avec inspection TLS : seul un L7 proxy qui termine TLS voit le trafic ; REALITY resiste au fingerprinting passif mais pas a un MITM qui reinjecte son propre certificat (a detecter par pinning). Reseau qui n'autorise que 80/443 : VLESS/REALITY en TCP/443 est la seule option fiable ; Hysteria2 tombe si l'UDP est bloque.

### AXE 3 - Architecture et anonymat reel

**Le probleme central, traite frontalement.** Un VPN auto-heberge = une IP unique non partagee. Face a un adversaire qui correle (FAI, autorite judiciaire, plateforme), cette IP est un identifiant stable et attribuable a une seule personne. Un pool commercial partage offre un anonymat de foule superieur. Donc : l'auto-heberge maximise le CONTROLE et la resistance a la telemetrie/censure, pas l'anonymat pur.

**Options comparees, classees par menace :**
- **Menace faible (FAI curieux, telemetrie, marketing)** : VPS proprietaire mono-saut suffit. Le controle et l'etancheite priment.
- **Menace moyenne (correlation, profilage plateforme)** : multi-hop entre VPS de juridictions differentes, ou sortie via un fournisseur commercial partage en dernier saut (le meilleur des deux mondes : controle de l'entree, foule a la sortie). Pools d'IP tournants si disponibles.
- **Menace forte (adversaire etatique, deanonymisation ciblee)** : chainage VPN vers Tor (le VPN cache l'usage de Tor au FAI, Tor fournit l'anonymat de foule) ou VPN vers Nym mixnet.
- **Nym mixnet (statut 2026)** : NymVPN, produit de Nym Technologies (societe suisse), lance en mars 2025. D'apres PRWeb (13 mars 2025) et Nym, le projet est fonde par Harry Halpin (MIT), Ania Piotrowska (UCL), Claudia Diaz (KU Leuven) et Alexis Roussel, avec Chelsea Manning comme conseillere securite. Le mode "Anonymous" est un mixnet a generation de bruit 5 sauts (format de paquet Sphinx) ; le mode "Fast" est un dVPN 2 sauts base sur AmneziaWG. Login via une cle zk-nym de 24 mots, paiement en BTC/XMR. Latence mixnet forte (3-8 s par page) mais c'est le seul produit grand public qui protege reellement les metadonnees contre un adversaire passif global.

Conclusion operationnelle : ne jamais presenter l'auto-heberge comme "anonymat maximal". Pour l'anonymat reel, la recommandation par defaut est VPN auto-heberge (entree, resistance DPI) -> Tor ou Nym (sortie, foule).

**Plan de controle auto-heberge.** Comparatif 2026 :
- **NetBird** (BSD-3/Apache-2.0, full open source client+serveur, SSO/OIDC, ACL, posture checks, ~13K etoiles, tres actif ; binaire serveur unifie depuis v0.65 fevrier 2026) : meilleur choix pour un produit auto-hebergeable de bout en bout.
- **Headscale** (BSD-3) : reimplantation du serveur de coordination Tailscale ; utilise les clients Tailscale officiels ; ne gere pas l'identite.
- **Nebula** (Slack, base certificats, passe a l'echelle).
- **Defguard** (Rust, MFA au niveau protocole, WireGuard).
- **Firezone** (SSO/OIDC, mais Community Edition sous SSPL, non OSI-approved).
- **ZeroTier** (L2).

Conclusion : NetBird comme base du plan de controle (licence permissive, full open source, gouvernance saine), quitte a en forker les parties utiles.

**Noeuds RAM-only facon Mullvad.** Mullvad a acheve sa migration vers une infrastructure RAM-only le 20 septembre 2023 : les serveurs bootent le bootloader System Transparency "stboot", telechargent un "OS Package" signe depuis un serveur de provisioning, en verifient les signatures, puis bootent en RAM (OS d'un peu plus de 200 MB, kernel mainline slimme). Caveat honnete de Mullvad : "tourner en RAM n'empeche pas le logging, cela minimise le risque de stocker accidentellement quelque chose". Le stack System Transparency (system-transparency.org, code sur git.glasklar.is) utilise coreboot, UEFI Secure Boot, TPM 2.0, AMD SEV-SNP, builds reproductibles Debian et le log de transparence Sigsum. Reproductibilite sur VPS loue : le BOOT en RAM est faisable (Hetzner rescue + iPXE, root en tmpfs via overlayroot/squashfs, ou OS immuables type Flatcar/Talos qui bootent root en tmpfs par defaut) ; la partie VERIFIABLE (attestation materielle TPM/SEV-SNP) n'est PAS reproductible sur infrastructure louee car on ne controle ni le firmware, ni l'hyperviseur, ni la racine de confiance materielle. Mullvad a fait auditer sa config diskless deux fois (2022 et 2023, le second par Radically Open Security).

**Fournisseurs.** Suisse : Infomaniak, Exoscale, Init7 (souverainete, mais soumis au droit suisse). UE : Hetzner, OVH (bon marche, mais IP datacenter bien connues et souvent classees). Reputes resistants : Njalla (fondee par Peter Sunde, accepte Monero/BTC, signup XMPP sans email, miroir Tor, VPS Suede uniquement en 2026), FlokiNET, 1984 Hosting (Islande). Contrainte : les IP de datacenter connues sont plus facilement bloquees par le GFW que les IP residentielles.

**Paiement non tracable en 2026.** Monero (XMR) est le standard : il masque emetteur, destinataire et montant, contrairement a BTC (registre public linkable). Hebergeurs acceptant XMR directement sans KYC : Njalla, Incognet, SporeStack (API-first, serveurs jetables), AnubizHost. Bonnes pratiques : XMR achete en P2P, email jetable cree via Tor, acces au panel via Tor.

### AXE 4 - Etancheite absolue

**Kill switch Windows (WFP).** La manipulation de la table de routage seule est insuffisante : une application privilegiee peut la reecrire, et il existe une fenetre de fuite au boot/reconnexion. La Windows Filtering Platform (WFP) est la seule approche production. Deux niveaux : (1) filtres en mode utilisateur via la Base Filtering Engine (BFE, bfe.dll) - suffisant pour bloquer par IP/port/appli, ne necessite que des droits admin ; (2) callout driver en mode noyau pour l'inspection profonde/modification de paquets - necessite signature de driver (attestation ou EV, et pour la distribution large, soumission au portail materiel Microsoft). Un kill switch WFP doit poser des filtres "permit" pour l'interface WinTun et l'endpoint VPN, et un filtre "block" par defaut a haute priorite (weight) couvrant IPv4 et IPv6, persistant meme si le service tombe. WireGuard officiel sur Windows utilise deja WinTun + WFP.

Conclusion : implementer le kill switch en filtres WFP user-mode (BFE) pour le MVP ; ajouter un callout driver signe seulement si l'inspection par processus est requise.

**Kill switch Linux (nftables + fwmark).** Le pattern de reference vient du man page wg-quick(8) : un filtre OUTPUT qui rejette tout paquet qui ne sort pas par l'interface WG et ne porte pas le fwmark de wg-quick (`iptables -I OUTPUT ! -o %i -m mark ! --mark $(wg show %i fwmark) -m addrtype ! --dst-type LOCAL -j REJECT`). En nftables moderne, le mecanisme sous-jacent (documente sur wireguard.com/netns) est : `wg set wg0 fwmark 1234` puis `ip rule add not fwmark 1234 table 2468` + `ip rule add table main suppress_prefixlength 0`, avec `Table = off` dans wg0.conf pour empecher wg-quick d'installer une route clearnet. Sur un routeur, la regle de drop doit etre dans la chaine `forward` (policy drop) et non `output`. Points critiques : IPv6 doit etre bloque en bloc sinon il fuit past un kill switch IPv4 ; garder la policy OUTPUT accept pour que la machine puisse joindre l'endpoint WG (probleme oeuf-poule) ; tester en faisant `wg-quick down` et en verifiant que l'egress expire. Un caveat du man page : DHCP (sockets PF_PACKET) contourne Netfilter et reste autorise.

**Split tunneling par application.**
- Linux : network namespaces (methode officielle wireguard.com/netns) - on deplace wg0 dans un netns via `ip link set wg0 netns <ns>` + `wg setconf` (pas wg-quick, qui ne gere pas les namespaces) et on lance l'appli avec `ip netns exec` ; ou cgroups + fwmark (marquer le trafic d'un cgroup et le policy-router vers la table VPN). Attention : `net_cls` est un controleur cgroup v1, a adapter sur les systemes cgroup v2 (defaut Ubuntu 24.04). Outil : wg-netns.
- Windows : split tunneling par processus via WFP (filtres conditionnes par l'ID de processus).

**Elimination des fuites.** DNS : resolveur local (Unbound ou dnscrypt-proxy) force en DoH/DoT/DoQ, jamais le DNS du FAI ; sur Windows, desactiver le DoH interne qui contourne les regles. IPv6 : desactiver ou router integralement dans le tunnel (sinon fuite garantie). WebRTC : desactiver/forcer via politique navigateur. mDNS/LLMNR/NetBIOS : desactiver. Fuite au reboot et pendant la fenetre de reconnexion : filtres WFP/nftables persistants poses AVANT la montee du tunnel.

**Suite de tests automatisable en CI.** Verifier : absence de fuite DNS, IP de sortie = IP VPN, pas de fuite IPv6, pas de WebRTC leak, comportement du kill switch (couper le tunnel et verifier 0 paquet en egress), fenetre de reconnexion. A integrer en CI avec des conteneurs reseau simulant les fuites.

### AXE 5 - Blocage telemetrie OS et reseau

**Cartographie telemetrie Windows 11 24H2/25H2.** Sur une install propre 24H2 (build 26100.x), DiagTrack (Connected User Experiences and Telemetry) tourne par defaut (Automatic/Running) et est le principal canal sortant vers Microsoft ; sur Home et Pro on ne peut pas descendre sous le niveau par defaut via l'UI. 25H2 (build 26200.6584, enablement package du 1er octobre 2025 par-dessus 24H2) a active les fonctions Copilot+ : Recall (captures d'ecran periodiques dans une base SQLite locale %LocalAppData%\CoreAIPlatform.00\UKP\, traitement on-device), Click to Do, Semantic Search, Copilot. dmwappushsvc est un canal secondaire.

**Pourquoi le fichier hosts ne marche plus.** IP en dur dans certains binaires, DoH interne de Windows 11 qui chiffre les requetes DNS avant qu'elles n'atteignent le fichier hosts (donc bypass silencieux), et bypass applicatifs. Ce qui marche reellement : (1) desactiver DiagTrack (`sc config DiagTrack start= disabled` + `sc stop DiagTrack`) ; (2) politiques de groupe (gpedit : Data Collection > Allow Diagnostic Data > Off, Pro+ seulement) et registre (DisableAIDataAnalysis=1, AllowRecallEnablement=0 sous HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsAI ; TurnOffWindowsCopilot=1) ; (3) filtrage WFP par processus ; (4) filtrage au niveau reseau (DNS + firewall sortant). A noter : un bug rapporte fin 2025 (Winhance issue #281) montre que le toggle "Send Diagnostic Data" peut reactiver la telemetrie - a auditer.

**Outils SOTA, evalues honnetement.**
- **O&O ShutUp10++** : reference pour toggles registre/politiques, reversible, detecte les regressions post-update. Bon defaut.
- **Win11Debloat / Winhance / WinUtil (Chris Titus)** : scripts PowerShell efficaces mais peuvent casser des composants (Store, apps) ; Winhance a eu un bug de reactivation telemetrie.
- **privacy.sexy** : genere des scripts transparents et auditables ; bon pour la reproductibilite.
- **simplewall** : firewall WFP en mode utilisateur, excellent pour bloquer par processus.

Effet de bord general : chaque mise a jour majeure Windows peut reactiver des reglages. La privacy est un processus continu, pas un one-shot.

**Couche DNS/filtrage reseau.** AdGuard Home est le choix par defaut 2026 : DoH/DoT/DoQ integres, filtrage par client, UI mature, plus simple que Pi-hole. Pi-hole reste bon pour le controle modulaire par groupe. Technitium pour le clustering natif haute dispo (v14). Blocky pour un binaire Go leger. Impact ECH : le filtrage par SNI devient aveugle quand ECH est actif (relation un-a-plusieurs derriere un SNI de couverture CDN) ; le filtrage doit donc se faire au niveau DNS (nom de domaine) et non SNI.

**Equivalent Linux.** Ubuntu : desactiver popcon, whoopsie (rapports de crash), apport ; auditer snap (telemetrie Canonical). Firefox : desactiver la telemetrie (ou passer a LibreWolf/Mullvad Browser). Chrome/VS Code : telemetrie Microsoft/Google a bloquer au niveau reseau. Bloquer les endpoints tiers au niveau AdGuard Home/nftables.

### AXE 6 - Anonymisation de la machine

**Empreintes a neutraliser.** MAC (randomisation, native sur Windows/Linux modernes), empreinte DHCP, fingerprint de pile TCP/IP (p0f), TLS (JA3 mort car Chrome randomise l'ordre des extensions ; JA4/JA4+ est le standard 2026, trie les champs et couvre TLS/HTTP/TCP, et inclut desormais l'info de key-share post-quantique), HTTP/2 (empreinte Akamai) et HTTP/3 (JA4H, QUIC), derive d'horloge, MTU, hostname/NetBIOS. Point cle 2026 : les WAF (Cloudflare, Akamai, DataDome) ne bloquent plus sur un hash statique mais sur la COHERENCE croisee (JA4 vs User-Agent vs Client Hints vs H2 settings vs geo-IP). Un mismatch (TLS dit Chrome 134 mais HTTP/3 dit aioquic) declenche le blocage. uTLS (Go) permet d'imiter le ClientHello d'un navigateur reel ; curl-impersonate/curl_cffi pour les clients HTTP.

**Navigateurs.** Comparatif d'efficacite reelle mesuree :
- **Mullvad Browser** (Firefox durci, co-developpe avec Tor Project) : meilleur pari contre un traqueur cible car il vise l'UNIFORMITE (tous les utilisateurs se ressemblent), meme s'il score plus bas sur privacytests.org (108/156) - le score haut mesure la difficulte de fingerprinting par defaut, pas la survie face a un adversaire cible.
- **Tor Browser** : anonymat reseau maximal + anti-fingerprinting, au prix de la latence.
- **Brave** : meilleur score leaderboard (143/156) via "farbling" (randomisation), mais le farbling a ete casse dans une etude peer-reviewed 2025 ; bon pour l'usage quotidien.
- **Camoufox** : controle du fingerprint au niveau moteur, score 70 %+ sur CreepJS, ~200 MB RAM par instance ; specialiste scraping/multi-identite.

Recommandation : Mullvad Browser comme navigateur par defaut de l'utilisateur Bifrost (uniformite = anonymat de foule), Tor Browser pour les besoins d'anonymat reseau.

**OS niveau vs VM.** Au niveau OS on peut : randomiser MAC, durcir la pile, imiter TLS via uTLS pour les clients maison, filtrer la telemetrie. Ce qui EXIGE une VM/OS dedie : compartimentation forte (Qubes OS), isolation reseau forcee (Whonix - tout le trafic force via Tor, impossible de fuiter l'IP reelle), amnesie (Tails - RAM-only, ne laisse rien), durcissement noyau (Kicksecure). Pour un anonymat serieux, Bifrost sur l'hote ne remplace pas Whonix/Qubes.

### AXE 7 - Implementation concrete

**Stack recommandee de bout en bout :**
- Coeur tunnel : WireGuard noyau (Linux) / WinTun (Windows) + Rosenpass (PQ).
- Obfuscation : sing-box comme coeur client universel (VLESS+REALITY TCP/443 primaire, Hysteria2 QUIC secours, AmneziaWG repli), bascule automatique.
- Analyse trafic : Maybenot (DAITA-like) cote client et serveur.
- Plan de controle : NetBird (forke selon besoins).
- Kill switch : WFP (Windows) / nftables+fwmark (Linux).
- DNS : Unbound ou dnscrypt-proxy local + AdGuard Home pour le filtrage.
- Sortie anonyme : chainage optionnel vers Tor/Nym.
- Serveurs : noeuds RAM-only (Flatcar/Talos ou stboot), payes en Monero chez Njalla/Incognet/1984.

**Langage et framework client.** Rust est le choix dominant en 2026 pour ce type de produit (Mullvad GotaTun en Rust, Rosenpass en Rust, Defguard en Rust, boringtun en Rust). Pour l'UI : Tauri (Rust + webview, MSI leger) ou une UI native. Go reste valable (sing-box, NetBird sont en Go) pour la partie reseau. Recommandation : coeur reseau en Go (reutiliser sing-box) OU Rust ; UI en Tauri.

**Packaging et distribution.**
- Windows : MSI + service Windows ; exigences de signature de code (certificat EV pour eviter SmartScreen et pour la signature de driver si callout). WinTun deja signe par WireGuard LLC.
- Linux : .deb/.rpm/AUR, unites systemd, integration systemd-networkd/NetworkManager.
- Mise a jour : mecanisme securise signe (TUF-like) ; ne jamais faire confiance a un canal non signe.

**A reutiliser / forker / ecrire soi-meme :**
- Reutiliser tel quel : WireGuard, Rosenpass, sing-box, Maybenot, AdGuard Home, Unbound, WinTun.
- Forker : NetBird (plan de controle), un client sing-box (UI), scripts privacy.sexy (durcissement Windows).
- Ecrire soi-meme : le kill switch WFP integre, la logique de bascule multi-protocole orientee menace, la suite de tests de fuites en CI, l'orchestration RAM-only, l'UI Tauri.

**Estimation d'effort (jours-homme, ordre de grandeur) :**
- Integration WireGuard + Rosenpass : 10-15 j.
- Integration sing-box + bascule multi-protocole : 20-30 j.
- Kill switch WFP (user-mode) : 15-25 j ; + callout driver signe : +30-40 j.
- Kill switch Linux nftables + netns/cgroup split tunnel : 10-15 j.
- Couche DNS/telemetrie (AdGuard + durcissement Windows/Linux) : 15-20 j.
- Client UI Tauri multi-plateforme : 40-60 j.
- Orchestration RAM-only + provisioning : 20-30 j.
- Suite de tests de fuites CI : 10-15 j.
- Total MVP fonctionnel : ~3-4 mois-homme ; version complete : ~9-12 mois-homme.

**Roadmap par phases :**
- Phase 0 (MVP) : WireGuard + kill switch (WFP user-mode / nftables) + DNS local + client CLI. Objectif : vrai VPN sans fuite.
- Phase 1 : obfuscation sing-box (VLESS/REALITY + Hysteria2) + bascule + UI Tauri. Objectif : resistance DPI.
- Phase 2 : Rosenpass PQ + Maybenot + multi-hop + chainage Tor/Nym. Objectif : anonymat et resistance analyse.
- Phase 3 : blocage telemetrie OS integre + RAM-only. Objectif : blocage complet de la telemetrie OS.

### AXE 8 - Ce qu'un VPN ne protege pas, et limites

**Ce qu'un VPN ne peut PAS proteger, a dire explicitement :**
- La telemetrie chiffree legitime : le trafic Windows/Copilot/Recall chiffre vers Microsoft passe DANS le tunnel ; le VPN ne le voit pas. Seul le blocage OS (Axe 5) l'arrete.
- Les comptes connectes : etre logue a Google/Microsoft/Meta lie l'activite a l'identite quel que soit l'IP.
- Le fingerprinting applicatif et navigateur : JA4/JA4H, canvas, WebGL, fonts. Le VPN change l'IP, pas l'empreinte. Il faut Mullvad/Tor Browser.
- Les hardware IDs : advertising ID Windows, identifiants materiels, MAC si non randomisee.
- La correlation de trafic par adversaire global : seuls DAITA/Maybenot et les mixnets (Nym) attenuent.
- L'IP de sortie unique de l'auto-heberge : identifiant en soi.

## Recommandations

1. **Immediatement (MVP, phase 0)** : construire le vrai VPN sans fuite avant tout le reste. WireGuard noyau + kill switch (WFP user-mode sur Windows, nftables+fwmark+`Table=off` sur Linux) + DNS local (Unbound) + suite de tests de fuites en CI. Benchmark declencheur pour passer a la phase 1 : zero fuite mesuree sur les six vecteurs (DNS, IPv6, WebRTC, mDNS, reboot, reconnexion).

2. **Court terme (phase 1)** : integrer sing-box avec VLESS+REALITY (TCP/443) primaire, Hysteria2 (QUIC) secours, AmneziaWG repli, et bascule automatique orientee reseau. Seuil de succes : connexion stable maintenue derriere un DPI simule bloquant WireGuard nu et l'UDP.

3. **Moyen terme (phase 2)** : ajouter Rosenpass (PQ), Maybenot (anti-analyse), multi-hop, et surtout le chainage optionnel vers Tor/Nym. Communiquer clairement : l'anonymat reel vient du chainage, pas de l'IP VPS.

4. **Seuils qui changent la reco** : si l'adversaire est etatique (GFW/TSPU/Iran), passer obligatoirement en multi-protocole + IP residentielle/CDN (pas datacenter). Si l'adversaire est un traqueur global capable de correlation, imposer Nym mixnet ou Tor + DAITA.

## Caveats
- **Fraicheur incertaine** : plusieurs sources 2026 sur les protocoles anti-censure sont des blogs commerciaux de fournisseurs VPN (codehummus, molehole, lunaire, iplogs, sunsetbrowser) a recouper ; les faits sur le GFW sont corrobores par GFW Report (USENIX Security 2025, et le rapport RST+ACK du 20 aout 2025) et net4people, plus fiables. Les revues "2026" de Mullvad/IVPN (onlineshieldhub, gizmodo) sont commerciales ; les faits techniques (DAITA v2, PQ par defaut McEliece+ML-KEM) sont confirmes par le blog officiel Mullvad.
- **Syntaxe cgroup v2** pour le split tunnel Linux sur Ubuntu 24.04 : a verifier (les exemples trouves melangent cgroup v1 et v2 ; `net_cls` est v1).
- **RAM-only verifiable** : la partie attestation (System Transparency, TPM/SEV-SNP) n'est pas reproductible sur VPS loue ; seul le boot en RAM l'est.
- **ECH** : RFC 9849 ratifiee mars 2026, mais support serveur auto-heberge limite ; ne pas en dependre.
- **Anonymat** : aucune configuration ici ne garantit l'anonymat contre un adversaire etatique determine et cible. La compartimentation (Qubes/Whonix/Tails) reste indispensable au-dela du VPN.