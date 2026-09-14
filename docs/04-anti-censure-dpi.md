# Bifrost - Couche anti-censure / resistance DPI - Document d'implementation (etat au 25 juillet 2026)

## TL;DR
- La pile retenue est: VLESS+REALITY+XTLS-Vision (TCP/443) comme protocole primaire furtif, XHTTP (stream-one) derriere Cloudflare comme repli CDN, Hysteria2 (QUIC/UDP + Salamander + port hopping) pour reseaux a perte et throttling, et AmneziaWG comme repli WireGuard obfusque. La bascule automatique est portee par sing-box (urltest/selector) embarque comme processus separe, avec un superviseur maison ecrit par-dessus.
- Aucun protocole ne survit partout: la Russie (TSPU) et l'Iran sont passes en 2025-2026 a du whitelisting SNI+CIDR qui casse REALITY comme les autres, le GFW chinois dechiffre desormais le SNI QUIC (depuis le 7 avril 2024), et le Turkmenistan banne les IP par volume de trafic. La resistance vient donc de la combinaison protocole + infrastructure (choix d'ASN, rotation d'IP, CDN) et non d'un protocole unique.
- Cout d'ingenierie estime: 90 a 130 jours-homme pour un MVP multi-plateforme (Windows 11 + Ubuntu 24.04/Debian 12), l'essentiel etant la logique de bascule, le bootstrap resistant au blocage, et l'UI Auto/Discret/Rapide. Les coeurs (sing-box GPLv3, Xray MPL-2.0) sont reutilisables tels quels comme processus separes; le piege de licence principal est GPLv3 de sing-box si on le lie statiquement.

## Key Findings

### Etat de la menace (sources primaires)
- **GFW - trafic entierement chiffre**: le GFW exempte le trafic "probablement benin" via 5 heuristiques sur le premier paquet TCP (Wu et al., USENIX Security 2023, gfw.report). Regles exactes: Ex1 popcount/octet <= 3.4 ou >= 4.6 bits/octet; Ex2 les 6+ premiers octets sont ASCII imprimable [0x20-0x7e]; Ex3 >50% d'octets imprimables; Ex4 >20 octets imprimables contigus; Ex5 empreinte TLS/HTTP. Le reste est bloque. Selon le papier: "the inferred detection algorithm would block roughly 0.6% of all connections on our network tap... the GFW strategically only monitors 26% of connections and only to specific IP ranges of popular data centers". Detection purement passive confirmee: sur 33 119 connexions declenchees, seulement 179 sondes actives ("in more than 99% of the tests, the GFW did not send any active probes"). Censure residuelle de 180 s sur le meme 3-tuple apres declenchement. Limite au TCP. Cela condamne Shadowsocks nu, VMess, obfs4 sans camouflage.
- **GFW - QUIC/SNI**: depuis le 7 avril 2024, le GFW dechiffre les paquets QUIC Initial a l'echelle nationale et extrait le SNI (Zohaib, Zao, Sippe et al., "Exposing and Circumventing SNI-based QUIC Censorship of the GFW", USENIX Security 2025, pp. 783-802). Ampleur mesuree: 58 207 FQDN uniques bloques entre le 8 octobre 2024 et le 15 janvier 2025, ~43,8K FQDN/semaine en moyenne. Failles exploitables: (a) le GFW ne reassemble pas un TLS Client Hello fragmente en plusieurs datagrammes UDP ou plusieurs CRYPTO frames (etat janvier 2025); (b) il ignore l'inspection QUIC quand le port source <= port destination (faire tourner le serveur QUIC sur un port de destination haut > ~49152 evade la regle). Le surcout de dechiffrement effondre l'efficacite sous charge.
- **Russie (TSPU)**: nouvelle methode a partir de juin 2025 (net4people #490): "gel" TCP silencieux (sans RST) quand une connexion vers une IP de datacenter etranger (Hetzner, DigitalOcean, OVH...) depasse ~15-20KB recus (mesure affinee par Runnin4ik: 14KB min, ~25KB HTTPS, 32-34KB HTTP). Escalade upd3/upd4: whitelist SNI puis whitelist CIDR. En novembre 2025, blocage en gros de Cloudflare, OVH, Hetzner, DigitalOcean, Oracle, AWS dans les regions Centre et Nord-Ouest (rootk1t, net4people #490). Un utilisateur: "worse than China... they didn't have no whitelists". SSH/sFTP passaient encore (puis throttling a 2Kb/s). zapret (fragmentation/desync cote client) contourne encore.
- **Iran**: whitelisting SNI/CIDR deploye depuis 2024; "Reality is dead in Iran" (dev irgfw); MCCI/IRGFW ont une large "gray list" d'IP (des VPS sans aucun trafic pendant 3 mois ont ete bloques). UDP quasi entierement desactive - rapport Nym (Ania M. Piotrowska, "Nym report on Iran's recent Internet blackouts", 30 juin 2025): "Popular VPS providers commonly used for hosting VPNs - including Hetzner, DigitalOcean, Linode, and others - have had large portions of their IP space blocked... Almost all UDP-based protocols have been disabled... The only notable exception is UDP port 53". DPI qui reassemble les fragments TCP pour extraire le SNI meme derriere CDN (net4people #628, juin 2026). Blackouts quasi-totaux (juin 2025; janvier-mai 2026).
- **Turkmenistan**: le plus brutal. Blocage volumetrique par IP, protocole-agnostique. IP fraiches bannies "after a few days of use, sometimes in a few hours, sometimes in a few weeks, traffic was mostly from 20 to 150gb" (its0ka, net4people #523, 14 sept. 2025). VPS commerciaux "typically blocked within 2-3 days" (GreatFireVPN); seuls les CDN survivent. Un endpoint AmneziaWG a ~500MB/mois a survecu ~2 ans sur la meme IP. Blocages a heure fixe (10h ou 12h UTC).
- **Tor**: en Chine (avril 2025) obfs4/meek/snowflake inutilisables, webtunnel se connecte puis vite bloque. WebTunnel massivement bloque en Russie mi-2025; distribution basculee vers Telegram. Conjure en deploiement 2026 (registration DNS et AMP-cache, transports DTLS/prefix).

### Durees de vie d'IP mesurees (par pays/hebergeur)
- **Turkmenistan**: 2-3 jours (commercial), heures a semaines (individuel), declencheur = volume (20-150GB). Blocages a heure fixe (10h ou 12h UTC).
- **Russie**: ASN entiers bloques (Hetzner AS24940, OVH, DO, Oracle, AWS, Cloudflare). ICMP passe, TCP/UDP non (Tor forum #16134, dec. 2024). IP domestiques (Yandex Cloud, VK Cloud) parfois epargnees (pas de TSPU en amont). Corroboration ntc.party #17013 (9 juin 2025).
- **Iran**: Hetzner "Most IPs are Blocked", Oracle free-tier bloque (awesome-iran-freedom vps-providers.md); hosts moins connus (RackNerd, Contabo, NetCup, AlexHost, Aeza-NL) durent plus longtemps. Divergence par ISP (MCI vs Irancell, LowEndTalk juin 2025). Attribution ASN de TIC variable selon sources.
- **Chine**: cible IP+port des datacenters connus (BandwagonHost); residentiel rarement bloque mais possible (net4people #129); whitelist cote serveur prolonge fortement la survie.

## Details

### PARTIE 1 - Tableau de survie des techniques (etabli au 25 juillet 2026; cinq lignes rafraichies le 20 aout et le 4 septembre 2026, voir SOTA-2026-07.md)

Legende: Fonctionne / Degrade / Incertain / Mort. "Incertain" est la lecture que le code (`crates/bifrost-evasion/src/survie.rs`) fait des cellules ecrites ici "Degrade/Mort" ou "Mort/Degrade": la technique tient ou tombe selon le reseau. Ces lignes sont des observations communautaires (net4people, ntc.party, Tor forum, GFW Report), pas des mesures controlees. Fraicheur en semaines. Pour les cinq techniques candidates du produit (REALITY+Vision, XHTTP-CDN, Hysteria2, AmneziaWG, WireGuard nu), la colonne "Derniere mesure" porte la date par pays quand elle differe; le tableau operatoire est celui du code, qui fait foi en cas d'ecart.

| Technique | Chine (GFW) | Russie (TSPU) | Iran | Turkmenistan | Derniere mesure | Source |
|---|---|---|---|---|---|---|
| WireGuard nu | Mort | Mort (fingerprint) | Mort (UDP off) | Degrade (volume) | 2026-Q2 | net4people #490/#523, Nym |
| OpenVPN | Mort | Mort | Mort | Mort | 2026 | GFW Report, communaute |
| Shadowsocks-2022 | Mort (sans plugin) | Degrade | Degrade | Degrade | 2026 | GFW USENIX23 |
| Trojan | Degrade | Mort (16KB) | Mort | Mort | 2026 | net4people #490 |
| VLESS+REALITY(+Vision) | Fonctionne | Incertain (CIDR; mobile sous liste blanche: passe sur un MTS, coupe sur un autre; TUN degrade sur Beeline) | Mort/Degrade | Mort (IP ban) | 2026-07 (Russie: 2026-09) | net4people #490/#546/#628; Russie 2026-09: net4people #650/#663/#662 |
| VLESS+XTLS-Vision (sans REALITY) | Degrade | Mort | Mort | Mort | 2026 | net4people #546 |
| XHTTP (SplitHTTP) | Fonctionne | Degrade (gel 16-20 Ko hors petite liste blanche sur Cloudflare; l'attribution au prefixe IP a ete retiree par son auteur le 02/09/2026; httpupgrade/xhttp OK Extreme-Orient 2026-06) | Degrade | Mort | 2026-06 (Russie: 2026-09) | net4people #490, Xray #4113; Russie 2026-09: net4people #662 |
| Hysteria2 | Degrade (QUIC SNI) | Degrade (passe par sing-box sur un reseau filtre le 03/09/2026; la TSPU filtre le QUIC v1 par SNI sur tous les ports UDP, v2 non touche; passe sur mobile MTS et Megafon a Ijevsk le 22/08, un temoignage sans mesure) | Mort (UDP off) | Mort | 2026-01 (Russie: 2026-09) | GFW USENIX25, Nym; Russie 2026-09: Xray #6717, net4people #654/#650 |
| TUIC v5 | Degrade | Degrade | Mort | Mort | 2026 | communaute |
| AmneziaWG | Degrade | Degrade (blocage generalise juin-juillet 2026 selon la documentation amont Amnezia, versions 1.5/2.0; IP d'un exploitant bloquees le 04/08/2026; la 3.1, reponse au blocage, est supportee par le client 5.0.1.5 du 21/08/2026) | Degrade | Fonctionne (bas volume) | 2026-07 | net4people #523; Russie: docs.amnezia.org, hub.xeovo.com #208, amnezia-client 5.0.1.5 |
| obfs4 | Mort | Degrade | Degrade | Mort | 2025-04 | Tor forum |
| Cloak | Degrade | Degrade | Degrade | Mort | 2026 | communaute |
| phantun / udp2raw | Degrade | Degrade | Mort (UDP off) | Mort | 2026 | communaute |
| Snowflake | Mort | Fonctionnait puis DTLS-fp 2026-03-30 | Degrade | Mort | 2026-03 | Tor, net4people #603 |
| WebTunnel | Degrade (vite bloque) | Mort (mi-2025) | Degrade | ? | 2025 | Tor blog |
| Conjure | En deploiement | En deploiement | En deploiement | ? | 2026 | Tor blog |
| MASQUE/CONNECT-UDP | Degrade (QUIC) | Degrade | Mort | Mort | 2026 | communaute |
| ShadowTLS v3 | Degrade (Aparecium 2025-06) | Degrade | Degrade | Mort | 2026-03 | tekkix |
| NaiveProxy | Fonctionne | Degrade | Degrade | Mort | 2026 | klzgrad |
| gost | Degrade | Degrade | Degrade | Mort | 2026 | communaute |

Rafraichissements du tableau: 20 aout 2026 (AmneziaWG/Russie, Fonctionne -> Degrade) et 4 septembre 2026 (REALITY, XHTTP-CDN et Hysteria2 en Russie dates 2026-09, statuts confirmes; dix-sept cellules inchangees faute de source posterieure au 20 aout). Le detail, le Source Log et la Claim Map de chaque rafraichissement sont dans `SOTA-2026-07.md`, sections "Rafraichissement du tableau de survie". La regle: une cellule ne change que sur une source primaire datee plus recente que la sienne; sinon elle garde sa date, meme perimee.

### Techniques de detection 2026
- **Entropie/popcount/ASCII**: seuils GFW exacts ci-dessus (Ex1-Ex5). Consequence design: ne jamais exposer un premier paquet a haute entropie sans camouflage TLS/HTTP. Un protocole "looks like nothing" (SS nu) est mort en Chine.
- **Active probing**: le GFW et l'IRGFW envoient des sondes vers les serveurs suspects. REALITY y resiste parce que le serveur transfere toute sonde non authentifiee (mauvais X25519/shortId) vers le vrai site cible (`dest`) et renvoie son vrai certificat; le sondeur voit un site legitime. NaiveProxy/Caddy: `probe_resistance` renvoie une vraie page (`file_server`). ShadowTLS v3 vulnerable: l'outil Aparecium (juin 2025) revele une difference fixe de longueur du ServerFinished et une mauvaise gestion du NewSessionTicket cote OpenSSL.
- **Fingerprint TLS (JA3/JA4)**: reellement utilise cote censeur (Iran a "zoome" sur les proxies TLS, net4people/Xray #3269). Preuve: des IP sans trafic ont ete grillees, indiquant un scan cote censeur. REALITY et les clients modernes utilisent uTLS (fingerprint chrome/firefox) pour ne pas se distinguer.
- **Analyse de flux/timing, ML**: deploye surtout en Chine (classification), moins ailleurs. Peu de seuils publics; a traiter comme une menace de fond, d'ou l'importance du padding (Vision) et du camouflage protocolaire.
- **Blocage QUIC/SNI**: Chine dechiffre l'Initial (voir ci-dessus). Ailleurs surtout blocage UDP franc (Iran, Turkmenistan). Regle d'evasion Chine: port destination haut, fragmentation du Client Hello.
- **Blocage IP / chasse aux IP**: durees de vie mesurees ci-dessus. ASN grilles en Russie: Hetzner, OVH, DO, Oracle, AWS, Cloudflare.
- **Blocage de plages/ASN**: Russie (whitelist CIDR), Turkmenistan (blacklist de /8 entiers de hosting/CDN). ASN qui tiennent: hosts domestiques (Russie), hosts moins abuses (Iran), CDN partout (au prix du cout collateral).
- **Rate limiting/throttling vs blocage**: Russie gele apres 16-20KB dans une meme connexion TCP; SSH throttle a 2Kb/s. Detection = debit qui s'effondre apres N KB/N secondes dans une meme connexion.

### PARTIE 2 - Configurations

#### 2.1 VLESS + REALITY

**Fonctionnement**: REALITY n'imite pas un site, il en emprunte reellement un. Le client envoie un ClientHello (uTLS, SNI = site cible reel) vers votre serveur. Le serveur verifie le shortId dans le champ SessionID et l'echange X25519. Client authentifie -> tunnel VLESS, avec un "certificat de confiance temporaire" signe par la cle d'authentification temporaire. Sonde non authentifiee -> le handshake est relaye vers le vrai `dest` et le vrai certificat est renvoye. Un DPI voit une connexion TLS 1.3 normale vers un grand site. **Limites reelles**: exige TLS 1.3 + HTTP/2 cote cible; casse si le censeur passe en whitelist CIDR (Russie/Iran 2026) car l'IP de sortie n'est pas dans la whitelist; casse si l'IP est deja "grise"; net4people #546 documente un policing de connexion TLS sur certains FAI russes qui casse REALITY+Vision.

**Generation des cles**:
```bash
xray x25519
# Private key: <privateKey>  Public key: <publicKey>
xray uuid
openssl rand -hex 8   # shortId (longueur paire, max 16 hex). "" (vide) autorise si liste cote serveur.
```
Note sing-box: `sing-box generate reality-keypair` et `sing-box generate uuid`.

**Serveur Xray-core** (JSON commente):
```json
{
  "log": { "loglevel": "warning" },
  "inbounds": [{
    "listen": "0.0.0.0",
    "port": 443,
    "protocol": "vless",
    "settings": {
      "clients": [{ "id": "<UUID>", "flow": "xtls-rprx-vision" }],
      "decryption": "none"
    },
    "streamSettings": {
      "network": "raw",
      "security": "reality",
      "realitySettings": {
        "target": "www.microsoft.com:443",
        "xver": 0,
        "serverNames": ["www.microsoft.com"],
        "privateKey": "<privateKey>",
        "shortIds": ["", "0123456789abcdef"]
      }
    },
    "sniffing": { "enabled": true, "destOverride": ["http","tls","quic"] }
  }],
  "outbounds": [
    { "protocol": "freedom", "tag": "direct" },
    { "protocol": "blackhole", "tag": "block" }
  ]
}
```

**Serveur sing-box**:
```json
{
  "inbounds": [{
    "type": "vless",
    "listen": "::",
    "listen_port": 443,
    "users": [{ "uuid": "<UUID>", "flow": "xtls-rprx-vision" }],
    "tls": {
      "enabled": true,
      "server_name": "www.microsoft.com",
      "reality": {
        "enabled": true,
        "handshake": { "server": "www.microsoft.com", "server_port": 443 },
        "private_key": "<privateKey>",
        "short_id": ["0123456789abcdef"]
      }
    }
  }],
  "outbounds": [{ "type": "direct" }]
}
```

**Client sing-box (Windows 11 + Ubuntu/Debian, identique)**:
```json
{
  "outbounds": [{
    "type": "vless",
    "tag": "reality-out",
    "server": "<SERVER_IP>",
    "server_port": 443,
    "uuid": "<UUID>",
    "flow": "xtls-rprx-vision",
    "tls": {
      "enabled": true,
      "server_name": "www.microsoft.com",
      "utls": { "enabled": true, "fingerprint": "chrome" },
      "reality": { "enabled": true, "public_key": "<publicKey>", "short_id": "0123456789abcdef" }
    }
  }]
}
```

**XTLS-Vision (flow xtls-rprx-vision)**: a activer avec REALITY sur TCP. Reduit le double-chiffrement TLS-in-TLS et ajoute du padding pour masquer les longueurs de paquets (empeche le DPI de reperer le tunnel par les tailles). Incompatible avec WebSocket/gRPC/XHTTP. Gain de performance reel sur gros transferts.

**Choix du site de couverture** (dest/serverNames): TLS 1.3 obligatoire, HTTP/2, pas derriere Cloudflare, meme continent que le serveur, non bloque localement, non redirige (l'apex peut rediriger vers www). Bonus: OCSP stapling, IP proche du serveur, messages post-ServerHello chiffres ensemble (ex. dl.google.com). Methode de test automatisable:
```bash
check_dest() {
  d=$1
  ver=$(echo | openssl s_client -connect ${d}:443 -tls1_3 2>/dev/null | grep -c "TLSv1.3")
  h2=$(curl -sI --http2 https://${d} -o /dev/null -w "%{http_version}\n")
  cf=$(curl -sI https://${d} | grep -ci "cloudflare")
  echo "$d tls13=$ver http2=$h2 cloudflare=$cf  (ok si tls13>=1, http2=2, cloudflare=0)"
}
check_dest www.microsoft.com
```
Candidats connus stables: Europe/CH: www.microsoft.com, dl.google.com, www.samsung.com; usage regional Russie 2026: ozon.ru, api.oneme.ru (SNI whitelistes observes dans #490, permettent de passer meme sous whitelist SNI). En pratique, quand le censeur applique la whitelist CIDR, il faut que le dest ET l'IP de sortie soient dans la whitelist (impossible sur un VPS etranger), d'ou le recours au premier-hop domestique.

**REALITY sur QUIC/UDP**: non disponible en 2026 (REALITY est TCP-only). Non pertinent; toute affirmation contraire est fausse.

#### 2.2 XHTTP / SplitHTTP
Statut: SplitHTTP renomme XHTTP dans Xray-core (fin 2024, PR #3994/#4113). Modes: packet-up (upload en paquets discrets, passe tous les middleboxes HTTP), stream-up (upload en flux), stream-one (flux bidirectionnel unique). Recommandation: **stream-one** (ou mode auto) avec REALITY en direct; packet-up seulement derriere certains middleboxes/CDN H3. packet-up est desormais presque aussi rapide que stream-up apres optimisations. Superieur a REALITY seul quand il faut passer un CDN (H2/H3) ou quand REALITY-Vision est detecte par policing de connexion (net4people #546); en Russie Extreme-Orient, httpupgrade/xhttp/gRPC contournaient encore le gel 16KB (#490).

**Serveur Xray XHTTP+REALITY**:
```json
{
  "inbounds": [{
    "port": 443, "protocol": "vless",
    "settings": { "clients": [{ "id": "<UUID>" }], "decryption": "none" },
    "streamSettings": {
      "network": "xhttp",
      "security": "reality",
      "realitySettings": { "target": "www.microsoft.com:443", "serverNames": ["www.microsoft.com"], "privateKey": "<privateKey>", "shortIds": ["0123456789abcdef"] },
      "xhttpSettings": { "host": "www.microsoft.com", "path": "/<random-long-path>", "mode": "auto" }
    }
  }],
  "outbounds": [{ "protocol": "freedom" }]
}
```
**Client (extrait streamSettings)**:
```json
"streamSettings": {
  "network": "xhttp",
  "security": "reality",
  "realitySettings": { "fingerprint": "chrome", "serverName": "www.microsoft.com", "publicKey": "<publicKey>", "shortId": "0123456789abcdef" },
  "xhttpSettings": { "host": "www.microsoft.com", "path": "/<random-long-path>", "mode": "stream-one" }
}
```
**XHTTP derriere CDN (Cloudflare)**: pointer le client sur le domaine CDN, `security: "tls"` (pas reality), `mode: "stream-one"` (Cloudflare supporte parfaitement stream-one). Le serveur XHTTP peut n'ecouter qu'en H1/H2, le client peut utiliser H3 (le CDN convertit H3->H1/H2 vers l'origine). Piege connu: la separation upstream/downstream (deux serveurs) est delicate a configurer (Xray #6042).

#### 2.3 Hysteria2
**Serveur (YAML commente)**:
```yaml
listen: :443
tls:
  cert: /etc/hysteria/fullchain.pem   # vrai cert Let's Encrypt (self-signed detecte via CT logs)
  key: /etc/hysteria/privkey.pem
auth:
  type: password
  password: <AUTH_PASSWORD>
obfs:
  type: salamander
  salamander:
    password: <OBFS_PASSWORD>          # identique client/serveur; mauvais mdp = timeout
bandwidth:
  up: 0                                # 0 = pas de limite serveur (laisser le client dicter)
  down: 0
ignoreClientBandwidth: false           # true si l'admin connait le vrai debit (empeche un client de mentir)
masquerade:
  type: proxy
  proxy:
    url: https://news.ycombinator.com/ # requetes non authentifiees relayees ici (reverse proxy)
    rewriteHost: true
```
**Client (YAML)**:
```yaml
server: <SERVER_IP>:443
auth: <AUTH_PASSWORD>
obfs:
  type: salamander
  salamander:
    password: <OBFS_PASSWORD>
bandwidth:
  up: 40 mbps      # ~80% du debit montant reel mesure
  down: 160 mbps   # ~80% du debit descendant reel mesure
tls:
  sni: <domaine>
quic:
  initStreamReceiveWindow: 16777216
  maxStreamReceiveWindow: 16777216
  initConnReceiveWindow: 33554432
  maxConnReceiveWindow: 33554432
socks5:
  listen: 127.0.0.1:1080
```
**Controle de congestion Brutal**: se declenche des que up/down sont fournis (sinon BBR). Calibrer a ~80% de la bande passante reelle mesuree. Sur-estimer provoque perte de paquets et congestion (l'algo n'ecoute pas la congestion et pousse a debit fixe, compensant meme la perte en accelerant); sous-estimer bride. `disableLossCompensation: true` pour envoyer exactement au debit fixe.
**Salamander**: transforme chaque paquet QUIC en octets aleatoires (utile si le FAI fingerprinte QUIC/H3). Gain reel: rend le flux indistinct d'UDP aleatoire. Gecko (experimental) ajoute la fragmentation du handshake.
**Port hopping**: `server_ports: 20000-20100`, `hop_interval: 30s` cote client; efficace contre le blocage par port; effet de bord NAT: multiplie les entrees de conntrack, peut saturer les petits routeurs domestiques.
**Masquerade**: le serveur repond aux requetes non authentifiees comme un reverse proxy vers un vrai site (defense contre le scan/probe).

**sing-box Hysteria2 outbound (client)**:
```json
{
  "type": "hysteria2",
  "tag": "hy2-out",
  "server": "<SERVER_IP>",
  "server_port": 443,
  "server_ports": ["20000-20100"],
  "hop_interval": "30s",
  "up_mbps": 40,
  "down_mbps": 160,
  "obfs": { "type": "salamander", "password": "<OBFS_PASSWORD>" },
  "password": "<AUTH_PASSWORD>",
  "tls": { "enabled": true, "server_name": "<domaine>" }
}
```
Note: bande passante en entier Mbps dans sing-box (pas de suffixe "mbps"; Xray/mihomo acceptent "100mbps"). **Incompatibilite connue**: la Salamander de Xray-core et celle de Hysteria2 ne s'interoperent pas (Xray #5712) - utiliser le meme coeur des deux cotes.

#### 2.4 AmneziaWG
**Parametres (ce que fait chacun)**:
- **Jc**: nombre de paquets junk envoyes avant la session (1-128; recommande 4-12, souvent 3-4). **Jmin/Jmax**: taille min/max de ces junks (recommande Jmin=8, Jmax=80; alternative 50/1000). Jmin < Jmax <= 1280 (a MTU 1280).
- **S1**: octets junk prefixes au paquet Init handshake -> len(init)=148+S1. **S2**: idem Response -> len(resp)=92+S2. Contrainte: S1+56 != S2. Recommande 15-150. S1<=1132, S2<=1188.
- **S3/S4** (AWG 2.0): junk sur Cookie (64+S3) et Data (payload+S4).
- **H1-H4**: valeurs de remplacement des magic headers (types de message 1-4). Doivent etre uniques entre elles; plage 5 a 2147483647.
**Danger des valeurs par defaut**: si tout le monde laisse H1=1, H2=2, H3=3, H4=4 ou des Jc/S identiques, le fingerprint devient commun et une regle DPI universelle devient possible. Il faut generer des H1-H4 aleatoires non-chevauchants par deploiement (les plages ne doivent pas se chevaucher, ainsi aucun couple de clients n'a des en-tetes identiques). Seuls Jc/Jmin/Jmax peuvent differer entre client et serveur; tout le reste doit etre identique. En AWG 2.0, les 11 parametres (Jc, Jmin, Jmax, S1-S4, H1-H4) sont obligatoires: le serveur refuse la config si l'un manque.

**Config serveur (awg0.conf)**:
```ini
[Interface]
PrivateKey = <SERVER_PRIVATE_KEY>
Address = 10.9.9.1/24
ListenPort = 51820
Jc = 6
Jmin = 55
Jmax = 205
S1 = 72
S2 = 56
S3 = 32
S4 = 16
H1 = 1234567
H2 = 2345678
H3 = 3456789
H4 = 4567890
[Peer]
PublicKey = <CLIENT_PUBLIC_KEY>
AllowedIPs = 10.9.9.2/32
```
**Client**:
```ini
[Interface]
PrivateKey = <CLIENT_PRIVATE_KEY>
Address = 10.9.9.2/24
DNS = 10.9.9.1
Jc = 6
Jmin = 55
Jmax = 205
S1 = 72
S2 = 56
S3 = 32
S4 = 16
H1 = 1234567
H2 = 2345678
H3 = 3456789
H4 = 4567890
[Peer]
PublicKey = <SERVER_PUBLIC_KEY>
Endpoint = <SERVER_IP>:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
```
(Generer H1-H4 aleatoires par deploiement; les valeurs ci-dessus sont des placeholders.)
**Compatibilite WireGuard standard**: si seuls Jc/Jmin/Jmax sont poses (S1=S2=0, H1-H4=1,2,3,4), un serveur WG standard accepte - le client envoie juste des junks avant l'init, sans effet sur le protocole WG. Pour un produit supportant les deux, garder un mode "junk-only" (compatible WG) et un mode "AWG complet" (serveur AWG requis). **Support tiers 2026**: module noyau Linux (amnezia-vpn/amneziawg-linux-kernel-module, DKMS, `apt-get install amneziawg`), WireSock Secure Connect et client Amnezia sur Windows.

#### 2.5 Autres protocoles (config minimale + cas d'usage)
- **ShadowTLS v3 (sing-box)**: chaine ShadowTLS -> Shadowsocks. Le handshake TLS est relaye vers un vrai donneur, le client recoit un vrai certificat (d'ou resistance a l'active probing basique via challenge-response HMAC). Cas d'usage: SNI-blocking simple sans active probing sophistique. A eviter si active probing (detecte par Aparecium juin 2025). SNI = domaine donneur reel, non bloque.
- **NaiveProxy (Caddy + fork forwardproxy)**: meilleur choix "HTTP/2 pur, indistinct de Chrome" (reutilise la pile reseau Chromium). Mitige: fingerprinting TLS (pile Chrome), active probing (application fronting), analyse de longueur (padding). Caddyfile:
```
{ order forward_proxy before file_server }
:443, example.com {
  tls me@example.com
  forward_proxy { basic_auth user pass; hide_ip; hide_via; probe_resistance }
  file_server { root /var/www/html }
}
```
Client: `{ "listen": "socks://127.0.0.1:1080", "proxy": "https://user:pass@example.com" }`. Cas d'usage: Chine (survit encore), reseau avec inspection TLS.
- **TUIC v5 (sing-box, UUID+password sur QUIC, TLS obligatoire)**: repli UDP furtif quand QUIC passe. TLS block requis (QUIC). La v4 (token) n'est pas supportee par sing-box.
- **Shadowsocks-2022 (SIP022, AEAD AES-GCM + anti-rejeu)**: uniquement combine a Cloak/v2ray-plugin (WS+TLS) ou ShadowTLS; nu = mort en Chine (entropie). Cas d'usage: reseaux peu hostiles (UE), setup ultra-simple, latence minimale (+2-3ms vs WG).
- **Tor pluggable (Snowflake/WebTunnel/obfs4/Conjure)**: pertinent seulement comme repli de dernier recours (blackout, tout le reste mort). Snowflake fonctionnait a ~100% en Russie nov. 2025-mars 2026 jusqu'au filtrage par fingerprint DTLS (2026-03-30, net4people #603). A embarquer optionnellement, pas dans le chemin par defaut.

### PARTIE 3 - Bascule automatique

#### 3.1 Detection d'environnement (< 5s)
Sondes paralleles au demarrage (budget ~5s):
- **UDP bloque**: envoyer un paquet STUN vers un serveur STUN connu; timeout 1.5s -> UDP suspect.
- **QUIC bloque specifiquement**: tenter H3 vers un domaine H3-capable; echec mais TCP/443 OK -> QUIC filtre.
- **Seulement 80/443**: tenter TCP connect sur 443, 80, puis un port haut (ex 51820); si seuls 80/443 repondent -> reseau restreint (hotel/aeroport).
- **Inspection TLS (MITM)**: faire un handshake TLS vers un domaine pinne (ex. un domaine dont on connait l'empreinte de chaine) et comparer la chaine/empreinte au pin; mismatch = MITM d'entreprise. On lit seulement le certificat, on ne casse pas la connexion.
- **Captive portal**: requete HTTP vers un endpoint de detection (generate_204); reponse != 204 -> portal a franchir d'abord.
- **DPI actif qui coupe (signature TSPU)**: telecharger un blob > 32KB via une connexion TLS 1.3 vers l'IP datacenter et detecter si le flux gele apres ~16-20KB.
- **Throttling vs blocage**: mesurer le debit sur 10s; effondrement apres N secondes = throttling, echec de handshake immediat = blocage franc.

#### 3.2 Machine a etats
Cle de reseau = (BSSID Wi-Fi ou identifiant d'interface) + passerelle par defaut + ASN de sortie observe. Ordre d'essai (du plus furtif/leger au plus lourd), memorise par reseau:
1. Reseau deja connu -> reutiliser directement le protocole memorise qui a marche (pas de re-sondage).
2. Sinon: (a) VLESS+REALITY+Vision TCP/443; (b) XHTTP stream-one derriere CDN; (c) Hysteria2 UDP/443 + Salamander (si UDP non bloque); (d) AmneziaWG bas-volume; (e) repli Tor (Snowflake/WebTunnel) en dernier.
Criteres de passage au candidat suivant: echec de handshake < 3s, ou gel apres 16-20KB, ou debit < seuil sur 10s.
**Parallelisme**: happy-eyeballs limite (2 candidats max en parallele), jamais 6 d'affilee - un client qui tente 6 protocoles en rafale est lui-meme une signature detectable. Preferer sequentiel avec jitter aleatoire entre tentatives.
**Discretion**: espacer les tentatives (jitter), ne pas re-sonder en boucle, memoriser pour eviter de re-tester a chaque reconnexion, ne pas emettre de motif de bascule regulier.
**Degradation en cours de session**: si le tunnel gele apres 3 min (signature TSPU), basculer vers le candidat suivant en gardant l'etat applicatif - le SOCKS local reste stable, le kill switch WFP/nftables n'est jamais leve pendant la bascule (fail-closed).

#### 3.3 Implementation
**sing-box** supporte nativement `urltest` (selection par latence la plus basse, health check periodique) + `selector` (choix manuel/persiste via Clash API, cache `store_selected`). Limites: urltest teste la latence, pas l'accessibilite reelle de la cible ni le gel apres 16KB; il faut donc un superviseur maison qui pilote le selector via la Clash API et applique les criteres specifiques (gel, throttling, blackhole). `interrupt_exist_connections` controle la coupure des connexions existantes au switch.
```json
{
  "outbounds": [
    { "type": "vless", "tag": "reality", "...": "..." },
    { "type": "hysteria2", "tag": "hy2", "...": "..." },
    { "type": "wireguard", "tag": "awg", "...": "..." },
    { "type": "urltest", "tag": "auto",
      "outbounds": ["reality","hy2","awg"],
      "url": "https://www.gstatic.com/generate_204",
      "interval": "3m", "tolerance": 50, "interrupt_exist_connections": false },
    { "type": "selector", "tag": "select",
      "outbounds": ["auto","reality","hy2","awg"], "default": "auto" }
  ],
  "route": { "final": "select", "auto_detect_interface": true },
  "experimental": { "clash_api": { "external_controller": "127.0.0.1:9090", "store_selected": true } }
}
```
**Xray-core**: `observatory` (sonde les outbounds, probeUrl/probeInterval) + `balancers` (strategy leastPing) + routing rules. Configuration via un balancer reference dans `route`.
**A ecrire soi-meme**: le superviseur (detection d'environnement, criteres gel/throttling, memorisation par reseau, orchestration deux coeurs, coordination du kill switch, degradation en session).
**Bootstrap/distribution des configs**: le canal ne doit pas etre bloquable (probleme d'amorcage). Techniques et statut 2026: domain fronting (degrade, Cloudflare restreint le SNI mismatch), DNS/DoH (Chine identifie precisement les connexions DoH etrangeres), Telegram (utilise par Tor pour distribuer les bridges WebTunnel; fonctionne encore, difficile a scraper en temps reel), GitHub (raw.githubusercontent souvent accessible), subscription links (standard mais bloquable si un seul domaine). **Recommandation**: multi-canal avec fallback - subscription sur domaine CDN + miroir GitHub raw + bot Telegram, profils signes (Ed25519) et chiffres, avec plusieurs domaines de secours codes en dur.

### PARTIE 4 - Infrastructure resistante

#### 4.1 Hebergement
Durees de vie mesurees ci-dessus. Choisir des ASN moins abuses (RackNerd, Contabo, NetCup, AlexHost, Aeza-NL pour cibler l'Iran; hosts domestiques Yandex Cloud/VK Cloud comme premier-hop en Russie car souvent sans TSPU). **IP residentielles/mobiles vs datacenter**: les residentielles/mobiles (CGNAT) sont bien plus resistantes - bloquer une plage carrier casserait l'internet mobile de millions d'usagers, cout collateral qu'aucun etat n'assume; mais cout eleve et legalite douteuse (proxies residentiels souvent en zone grise). **CDN devant le serveur (Cloudflare/Gcore/Fastly)**: supporte par XHTTP/WebSocket/gRPC (pas REALITY ni Vision); gros gain de survie (trop gros pour blacklister), mais Cloudflare est parfois bloque en gros (Russie nov. 2025) et l'Iran reassemble les fragments derriere CDN (#628). **Multi-IP + rotation**: garder les sessions via un **domaine stable** (le client se reconnecte au domaine, pas a l'IP) et faire tourner l'A record; les sessions QUIC survivent au changement d'IP (connection migration). Provisionner un time-to-block par defaut de 2-3 jours pour le Turkmenistan (rotation automatique).

#### 4.2 Durcissement
- **Ne pas etre identifiable par scan (Censys/Shodan/ZMap)**: REALITY rend le serveur indistinct d'un vrai site (toute sonde non authentifiee -> vrai cert du dest). NaiveProxy/Caddy: `probe_resistance` + `file_server` servant une vraie page. Hysteria2: masquerade.
- **Repli correct**: a une requete non authentifiee, renvoyer le contenu d'un vrai site (REALITY relaie vers dest; Caddy sert /var/www/html; Hysteria2 masquerade relaie vers un vrai site). Jamais de page d'erreur revelatrice.
- **nginx/caddy frontal + fallback**: utile pour NaiveProxy/Trojan/WS (coexistence web + proxy sur un port); rendu largement inutile par REALITY qui gere son propre fallback via `dest`/`serverNames`.
- **Detection de scans + bannissement**: fail2ban sur les ports de management (SSH deplace sur port haut, authentification par cle uniquement). La **whitelist cote serveur** (n'accepter les connexions proxy que depuis des IP clientes connues, bloquer l'active probing) prolonge fortement la survie du serveur (observe en Chine). Limiter le debit du fallback pour eviter que le serveur soit detourne en CDN par des tiers (Xray #3318).

### PARTIE 5 - Performance mesuree
Sources: rapports operateurs et tests communautaires 2025-2026 (Lunaire, clashpub, hiddifysales); a valider par vos propres bancs.
- **Reseau stable/fibre**: WireGuard/AmneziaWG le plus efficace (overhead minimal ~32 octets d'en-tete, +2-3ms, ChaCha20 noyau). REALITY+Vision proche du fil sur gros transferts. Hysteria2 legerement plus lourd (overhead QUIC + CPU userspace); sur reseau parfait, la difference avec WG est faible.
- **Reseau a perte (mobile)**: des 5% de perte, Hysteria2 (Brutal) est rapporte 2-5x plus rapide que WireGuard; a 20-30% de perte, 3-10x plus rapide. WireGuard souffre du probleme TCP-in-tunnel (le TCP interne voit la perte reseau et ralentit). Exemple rapporte: RTT 120-180ms, 2-5% perte, TCP nu 2-6 Mbps vs Hysteria2 steady 12-18 Mbps.
- **CPU**: WireGuard (ChaCha20 noyau) < REALITY (TLS) < Hysteria2/TUIC (QUIC userspace).
- **Surcout obfuscation vs WG nu**: AmneziaWG junk = negligeable en debit (+quelques paquets au handshake); Salamander = leger surcout CPU; REALITY = surcout du handshake TLS.
- **Batterie (portable nomade)**: QUIC userspace (Hysteria2/TUIC) consomme plus que WireGuard noyau; privilegier WG/AmneziaWG quand le reseau est propre (mode Rapide). RAM: sing-box ~20MB vs Xray ~60MB pour charge comparable (rapport communautaire).
- **MTU/fragmentation**: WireGuard MTU 1420 (1280 minimal); AmneziaWG reduire selon S1-S4 (junks augmentent la taille); Hysteria2 udp_fragment ~1200 si stalls; derriere CDN reduire le MTU pour eviter la fragmentation IP.

### PARTIE 6 - Implementation produit
- **Architecture**: embarquer sing-box comme **processus separe** (pas en bibliotheque liee, pour eviter le contaminant GPLv3 sur le client proprietaire) pilote par IPC/Clash API. Xray-core en complement (processus separe) pour REALITY+Vision+XHTTP (fonctionnalites que Xray porte en premier et le plus abouti). Gerer deux coeurs via le superviseur maison qui active l'un ou l'autre selon le protocole choisi et expose un **SOCKS local unique stable** vers lequel le systeme (via TUN) est route.
- **Licences**: sing-box GPL-3.0, Xray-core MPL-2.0, Hysteria2 MIT, AmneziaWG GPL-2.0 (fork WireGuard). **Piege**: la GPLv3 de sing-box contamine si liaison statique dans le binaire client -> le tenir en processus separe communiquant par socket evite la contamination (frontiere de processus, pas d'oeuvre derivee). La MPL-2.0 (Xray) est copyleft par-fichier, compatible avec le client MPL-2.0 tant qu'on ne modifie pas les fichiers sources. Les coeurs GPL restent des executables separes non modifies, distribues avec leur source/offre de source.
- **Configs dynamiques**: le client genere ses JSON/YAML a la volee a partir d'un profil (secrets + parametres) recu par subscription, plutot que des fichiers statiques embarques (permet de pousser de nouveaux candidats dest, ASN, ports sans mise a jour du client).
- **Secrets client** (cles publiques REALITY, UUID, mots de passe Hysteria2/obfs): stocker dans le keystore OS - DPAPI/Credential Manager sur Windows 11, libsecret/Secret Service (keyring) sur Linux; jamais en clair sur disque; chiffrer le profil de subscription au repos. Les cles REALITY cote client sont publiques (moins critiques), mais l'UUID et les mots de passe sont des secrets d'authentification.
- **Interface utilisateur**: modele **Auto / Discret / Rapide**. Auto = machine a etats complete (defaut). Discret = force le chemin le plus furtif (REALITY/XHTTP-CDN, jamais UDP brut, jamais WG nu). Rapide = privilegie WireGuard/AmneziaWG/Hysteria2 selon la perte reseau mesuree. L'utilisateur ne choisit jamais "VLESS vs Hysteria2"; il choisit une intention.
- **Effort par composant (jours-homme)**: integration sing-box (processus + IPC/Clash API) 8-12; integration Xray (observatory/balancer) 6-8; superviseur/machine a etats 20-30; detection d'environnement 10-15; bootstrap multi-canal + profils signes 10-15; UI 3 modes 12-18; keystore/secrets 5-8; packaging Windows/Linux + coordination kill switch 10-15; tests terrain (VPN reels par pays) 10+. **Total ~90-130 j-h pour le MVP**. Justification: sing-box et Xray (chacun des dizaines de kloc Go) sont reutilises tels quels comme binaires; le travail net est la colle (IPC, superviseur, UI, bootstrap), estimee par analogie avec la taille des panels existants (reality-ezpz, hiddify) qui font l'orchestration en quelques kloc.
- **Reutilisable tel quel**: sing-box, Xray-core, hysteria, amneziawg (binaires). **A forker**: rien de critique au depart; eventuellement le fork Caddy+forwardproxy si NaiveProxy est integre. **A ecrire de zero**: superviseur, detection d'environnement, bootstrap multi-canal, UI 3 modes, integration keystore, coordination kill switch.
- **Pieges connus (issues GitHub)**: Salamander Xray vs Hysteria2 incompatibles (#5712); XHTTP upstream/downstream separation delicate (#6042); AmneziaWG casse si un des 11 params AWG 2.0 manque; REALITY dest derriere Cloudflare = fuite/abus possible du fallback (#3318); sing-box urltest ne detecte pas le gel 16KB (d'ou le superviseur maison); flow xtls-rprx-vision incompatible avec WS/gRPC/XHTTP.

### PARTIE 7 - Limites et risques
- **Ne protege PAS**: contre la compromission de l'endpoint client, la correlation de trafic par un adversaire global (qui voit les deux bouts), les fuites applicatives hors tunnel, l'analyse comportementale du poste, ni le blocage total (blackout Iran janv.-mai 2026) ou le whitelisting CIDR strict (rien ne passe sauf services domestiques - la seule reponse est un premier-hop domestique ou un service whiteliste detourne, ex. plateformes de visio domestiques VK/Bale Meet).
- **Risque utilisateur en pays a censure forte**: l'usage d'un outil de contournement peut etre illegal ET detectable independamment du trafic (achat/telechargement du client, presence du binaire sur le disque, comportement, achat de VPS). Russie: depuis 2024, publicite/promotion des outils de contournement interdite; providers penalises; brevet de detection VPN depose (CN121691088A, oct. 2025). Iran: seuls les VPN autorises sont legaux. Turkmenistan/Belarus: bans. Le client doit minimiser les traces locales (installation discrete, pas de nom evident, purge possible).
- **Course perpetuelle**: la maintenance est continue (les regles changent en semaines). Structurer: veille automatisee (net4people/bbs, GFW Report, OONI, Censored Planet, ntc.party, issues Xray/sing-box/hysteria/amnezia), pipeline de mise a jour rapide des coeurs et des profils (candidats dest, ASN de sortie, ports), telemetrie du taux de succes par reseau/pays (anonymisee), et capacite a pousser de nouveaux profils sans mise a jour du client.

## Recommendations
1. **MVP (semaines 1-8)**: sing-box + Xray en processus separes; chemin par defaut VLESS+REALITY+Vision TCP/443 (dest = www.microsoft.com ou dl.google.com, teste par le script fourni); repli AmneziaWG (H1-H4 aleatoires par deploiement). Superviseur minimal (detection UDP/QUIC/80-443, gel 16KB) + kill switch coordonne fail-closed. Bootstrap subscription sur domaine CDN + miroir GitHub raw. Keystore OS pour les secrets.
2. **v1 (semaines 9-16)**: ajouter Hysteria2 (Salamander + port hopping, Brutal a 80% du debit mesure) pour reseaux a perte, XHTTP stream-one derriere Cloudflare pour reseaux "80/443 only" et inspection TLS d'entreprise. Detection d'environnement complete (<5s). UI Auto/Discret/Rapide. Memorisation par reseau (BSSID+passerelle+ASN).
3. **v1.1**: repli Tor (Snowflake/WebTunnel) optionnel pour blackout; rotation d'IP par domaine stable (2-3 jours par defaut pour cibles Turkmenistan); whitelist serveur + fail2ban + limitation du fallback.
4. **Seuils qui changent la strategie**: si REALITY tombe dans une region cible (mesure net4people/OONI), promouvoir XHTTP-CDN par defaut la-bas; si UDP est ouvert et perte >5%, promouvoir Hysteria2; si whitelisting CIDR strict (Russie/Iran), basculer sur premier-hop domestique + CDN, car aucun protocole sur VPS etranger ne passe. Reevaluer les candidats dest et les ASN de sortie chaque semaine.
5. **Infrastructure**: eviter Hetzner/OVH/DigitalOcean/Oracle/AWS pour les IP de sortie visant Russie/Iran (ASN grilles); preferer ASN moins abuses + CDN devant; pour la Russie, prevoir un premier-hop domestique (Yandex/VK Cloud) faute de mieux.

## Caveats
- Les durees de vie d'IP et le statut de blocage sont des observations communautaires (net4people/bbs, ntc.party, Tor forum), pas des mesures controlees; fraicheur incertaine, la situation change en semaines. Chaque ligne du tableau de survie est datee de sa derniere mesure fiable connue.
- L'attribution d'ASN pour l'Iran (TIC) varie selon les sources (AS48159 / AS49666 / AS58224).
- Le "gel 16KB" russe a peut-etre ete partiellement remplace par le whitelisting SNI+CIDR courant 2025-2026 (debat dans le fil net4people #490; certains observateurs considerent la methode "gel" discontinuee au profit de la whitelist).
- Les chiffres de performance (2-5x, 3-10x, 12-18 Mbps) proviennent de rapports operateurs et de tests non-academiques; a valider imperativement par vos propres bancs avant toute promesse produit.
- REALITY sur QUIC/UDP n'existe pas en 2026 (REALITY est TCP-only).
- La faille de non-reassemblage QUIC du GFW (fragmentation du Client Hello) est datee de janvier 2025 (USENIX 2025); le GFW peut l'avoir corrigee depuis - a reverifier avant de s'appuyer dessus en Chine.
- Certaines URL de config citees proviennent de tutoriels tiers; toute config doit etre testee sur banc avant deploiement, les schemas sing-box/Xray evoluant a chaque version (sing-box v1.13.x, Xray v26.x en 2026).