#!/usr/bin/env bash
# Banc de la BASCULE EN SESSION, avec mesure de fuite. Entierement local.
#
# # Ce que ce banc etablit
#
# Qu'un tunnel deja monte, dont le candidat courant se degrade, change de
# transport SANS TOMBER, que le trafic repart par le suivant, et que rien de ce
# qu'il porte n'apparait en clair sur le fil pendant l'operation. C'est la
# "degradation en cours de session" du document 04 partie 3.2, mesuree plutot
# que nommee.
#
# Montage, trois espaces de noms, comme `banc-coeur-e2e.sh`:
#
#   client            serveur A (REALITY)        serveur B (Hysteria2)
#   10.79.0.2  <-->   10.79.0.1:8443 tcp
#   10.79.1.2  <-->                              10.79.1.1:8443 udp
#                     banniere 10.99.0.1:7100    banniere 10.99.0.1:7100
#                     cible TLS 127.0.0.1:8444
#
# La banniere porte la MEME adresse dans les deux serveurs, sur une interface
# muette. Le client n'a aucune route vers elle: elle n'est joignable que par le
# tunnel, et ce qu'elle repond - BIFROST-A ou BIFROST-B - dit par OU on est
# passe. Deux serveurs de transports DIFFERENTS parce que `Profils` refuse deux
# profils du meme transport: la selection raisonne en techniques.
#
# # Trois choses que ce banc a apprises, et qu'il faut savoir pour le lire
#
# 1. L'application doit INSISTER. Un banc qui se tait apres le gel fait tomber
#    le tunnel meme quand la bascule reussit: apres dix secondes de silence
#    l'observateur envoie sa sonde de vitalite, laquelle vise generate_204 sur
#    l'internet public, hors d'atteinte ici. Une application qui perd sa
#    connexion, elle, reessaie; ses echecs traversent le coeur, qui ecrit ses
#    refus dans le TUN, donc le silence ne s'installe pas et c'est le critere
#    de DEBIT qui tranche. C'est le seul des deux criteres qu'un banc ferme
#    peut honorer.
#
# 2. Le critere de debit ne s'arme qu'apres une REFERENCE. `effondrement()`
#    exige un debit de reference d'au moins 2 Kio/s, d'ou le telechargement de
#    400 Ko de l'etape 7bis: sans lui, la chute n'a rien a quoi se comparer et
#    rien n'est jamais conclu.
#
# 3. Une capture arretee dans la foulee du dernier echange rendait un zero tres
#    propre pour une raison qui n'a rien a voir avec l'etancheite: libpcap ne
#    reveillait tcpdump qu'au bout d'une seconde, et ce qui dormait dans
#    l'anneau etait perdu. La cause est desormais supprimee a la source: les
#    captures portent `--immediate-mode`, donc le noyau ne retient plus rien, et
#    l'etape 12 compare les deux compteurs de tcpdump pour le dire si le drapeau
#    saute. L'attente avant l'arret n'est plus qu'une marge. Restent les deux
#    captures TEMOINS cote serveur: elles doivent voir la banniere en clair,
#    sans quoi un pcap vide et un tunnel etanche donneraient le meme resultat.
#
# # Ce qu'il arme, contrairement a `banc-coeur-e2e.sh`
#
# Le kill switch, dans l'espace de noms du client, avec son temoin negatif: une
# requete hors tunnel doit etre jetee. Rien n'est pose sur la machine hote, et
# tout dispararait a la sortie, y compris en cas d'erreur.
#
# # A savoir avant de lire les journaux
#
# Les serveurs ecrivent `network: missing default interface` au demarrage.
# C'est attendu: leurs namespaces n'ont pas de route par defaut.
#
# # Usage
#
#   scripts/banc-bascule-en-session.sh
#
# Variables: COEURS (repertoire du binaire sing-box), DEPOT (racine du depot
# construit), BANC (repertoire de travail jetable), GARDER=1 pour le conserver.
set -euo pipefail

NS_C=bifrost-bsc-client
NS_A=bifrost-bsc-reality
NS_B=bifrost-bsc-hysteria2
SNI_A=reality.bifrost.test
SNI_B=hy2.bifrost.test
PORT=8443
PORT_CIBLE=8444
PORT_BANNIERE=7100
# L'entree SOCKS du coeur. Valeur par defaut du daemon, redite ici parce que
# la sonde de l'etape 8ter s'y adresse directement.
PORT_SOCKS_COEUR=1080
# Adresse de la banniere: la MEME dans les deux namespaces serveurs, portee par
# une interface muette. Le client n'a aucune route vers elle: elle n'est
# joignable que par le tunnel, et ce qu'elle repond dit par OU on est passe.
ADR_BANNIERE=10.99.0.1
BANC=${BANC:-$HOME/bifrost-banc-bascule}
COEURS=${COEURS:-$HOME/bifrost-coeurs}
DEPOT=${DEPOT:-$HOME/bifrost-src}
DAEMON=$DEPOT/target/debug/bifrost-daemon
CLI=$DEPOT/target/debug/bifrost-cli
SOCKET=$BANC/daemon.sock

# `ip netns del` supprime le NOM, pas les processus: ceux qui tournent dedans
# survivent dans un espace devenu anonyme, invisibles a `ip netns list` et
# tenant leurs ports sans fin. Mesure du 21 aout 2026 sur la machine d'essai:
# 468 orphelins accumules par les bancs, le plus vieux depuis 25 h, dont un
# triplet laisse a CHAQUE passage. `ip netns pids` rend exactement les PID de
# cet espace: un kill cible, sans motif de nom.
vider_netns() {
  local p
  for p in $(sudo ip netns pids "$1" 2>/dev/null); do sudo kill "$p" 2>/dev/null; done
  # Laisser le temps de sortir proprement avant de trancher: un SIGKILL au bout
  # d'une seconde fixe fait rapporter "Killed" par le shell pour chaque tache de
  # fond, ce qui salit un passage vert et se lit comme un incident alors que le
  # menage s'est bien passe.
  local i
  for i in 1 2 3 4 5 6 7 8 9 10; do
    [ -z "$(sudo ip netns pids "$1" 2>/dev/null)" ] && return
    sleep 0.5
  done
  for p in $(sudo ip netns pids "$1" 2>/dev/null); do sudo kill -9 "$p" 2>/dev/null; done
}

nettoyer() {
  # Deconnecter AVANT de tuer, sur les chemins d'erreur aussi: un daemon tue
  # laisse le resolveur du tunnel sur `/etc/resolv.conf`, qui n'est pas
  # cloisonne par `ip netns` et appartient donc a la machine hote. Le banc qui
  # sort en catastrophe doit rendre la machine comme celui qui sort bien.
  if [ -S "${SOCKET:-}" ]; then
    sudo ip netns exec "$NS_C" "$CLI" --socket "$SOCKET" disconnect >/dev/null 2>&1 || true
  fi
  # Par PID, jamais par motif de nom: un motif emporterait les processus
  # homonymes de la machine hote.
  sudo pkill -F "$BANC/daemon.pid" 2>/dev/null || true
  for p in ${CAPTURES:-}; do sudo kill "$p" 2>/dev/null || true; done
  for ns in "$NS_C" "$NS_A" "$NS_B"; do
    vider_netns "$ns"
    sudo ip netns del "$ns" 2>/dev/null || true
  done
  if [ "${GARDER:-0}" != "1" ]; then
    sudo rm -rf "$BANC"
  else
    echo "banc conserve dans $BANC"
  fi
}
trap nettoyer EXIT

manquant() {
  echo "SKIPPED: $1"
  exit 0
}

[ -x "$COEURS/sing-box" ] || manquant "$COEURS/sing-box absent: ce banc veut un vrai sing-box, que le depot ne distribue pas"
[ -x "$DAEMON" ] || manquant "$DAEMON absent: construire le daemon d'abord (cargo build --bin bifrost-daemon)"
[ -x "$CLI" ] || manquant "$CLI absent: construire le client d'abord (cargo build --bin bifrost-cli)"
command -v openssl >/dev/null || manquant "openssl absent, impossible d'engendrer les certificats du banc"
command -v python3 >/dev/null || manquant "python3 absent, il porte les bannieres et la cible TLS"
command -v tcpdump >/dev/null || manquant "tcpdump absent: sans capture, la fuite ne serait pas mesuree et ce banc ne prouverait que le routage"
command -v nft >/dev/null || manquant "nft absent, le kill switch ne peut pas etre arme"
sudo -n true 2>/dev/null || manquant "creer un espace de noms reseau demande des privileges, et sudo en demande un mot de passe ici"

# L'etat DNS de l'HOTE, releve avant tout et compare a la sortie.
#
# Ce banc lance un daemon qui BASCULE le DNS, et `/etc/resolv.conf` n'est PAS
# cloisonne par `ip netns`: sans le montage pose plus bas, la bascule tombe sur
# la machine hote. C'est arrive le 20 aout 2026 - essai-linux s'est retrouve avec
# `nameserver 10.98.0.1`, adresse qui n'existe que dans ce banc, et le serveur
# REALITY de la machine a cesse de resoudre le site emprunte. Un banc qui
# affirme ne rien laisser derriere lui doit le MESURER.
etat_dns_hote() {
  # Le lien compte autant que le contenu: `/etc/resolv.conf` est un lien vers
  # le stub de systemd-resolved sur une Ubuntu ordinaire, et le remplacer par
  # un fichier ordinaire est deja une modification, meme a contenu egal.
  printf '%s|%s
' "$(readlink /etc/resolv.conf || echo '(pas un lien)')"     "$(sha256sum /etc/resolv.conf 2>/dev/null | cut -d' ' -f1)"
}
DNS_AVANT=$(etat_dns_hote)
# Et la premisse qui rend la comparaison lisible: si le resolveur de l'hote est
# DEJA le notre, ce banc comparerait du casse a du casse et rendrait un
# "inchange" parfaitement vide de sens. C'est arrive le 20 aout 2026. Un banc
# qui ne peut pas mesurer le dit et s'arrete, il ne rend pas un vert.
if grep -q "genere par bifrost" /etc/resolv.conf 2>/dev/null; then
  echo "SKIPPED: /etc/resolv.conf de cette machine porte deja le resolveur d'un tunnel."
  echo "  Un passage precedent est mort sans se deconnecter. Rendre la machine d'abord:"
  echo "    sudo bifrost-daemon --cleanup-firewall"
  echo "  et si la note de forme a disparu, reposer le lien a la main, par exemple"
  echo "    sudo ln -sf ../run/systemd/resolve/stub-resolv.conf /etc/resolv.conf"
  exit 0
fi

echo "== 1. trois namespaces =="
nettoyer
rm -rf "$BANC"; mkdir -p "$BANC"
for ns in "$NS_C" "$NS_A" "$NS_B"; do sudo ip netns add "$ns"; sudo ip -n "$ns" link set lo up; done
# Pas de `/etc/netns/<ns>/resolv.conf` ici, et ce n'est pas un oubli. Le
# mecanisme a ete essaye le 20 aout 2026 et NE PROTEGE PAS: `ip netns exec`
# monte le fichier par-dessus la CIBLE du lien quand `/etc/resolv.conf` en est
# un, tandis que `bifrost-dns` ecrit par `rename`, lequel remplace le lien
# lui-meme - dans le `/etc` de la machine, que le namespace partage. Un espace
# de noms de montage isole des MONTAGES, pas le contenu d'un repertoire. Ce qui
# rend l'hote a son etat, c'est la deconnexion de l'etape 13bis.
for duo in "a $NS_A 10.79.0" "b $NS_B 10.79.1"; do
  set -- $duo
  sudo ip link add "veth-c$1" type veth peer name "veth-s$1"
  sudo ip link set "veth-c$1" netns "$NS_C"
  sudo ip link set "veth-s$1" netns "$2"
  sudo ip -n "$NS_C" addr add "$3.2/24" dev "veth-c$1"
  sudo ip -n "$NS_C" link set "veth-c$1" up
  sudo ip -n "$2" addr add "$3.1/24" dev "veth-s$1"
  sudo ip -n "$2" link set "veth-s$1" up
done
# La banniere, portee par une interface muette dans CHAQUE serveur.
for ns in "$NS_A" "$NS_B"; do
  sudo ip -n "$ns" link add banniere type dummy
  sudo ip -n "$ns" addr add "$ADR_BANNIERE/32" dev banniere
  sudo ip -n "$ns" link set banniere up
done
echo "   client 10.79.0.2 / 10.79.1.2, serveurs .1, banniere $ADR_BANNIERE des deux cotes"
echo "   le client a-t-il une route vers la banniere ?"
sudo ip netns exec "$NS_C" ip route get "$ADR_BANNIERE" 2>&1 | head -1 || true

echo "== 2. secrets =="
PAIRE=$("$COEURS/sing-box" generate reality-keypair)
CLE_PRIVEE=$(echo "$PAIRE" | awk '/PrivateKey/{print $2}')
CLE_PUBLIQUE=$(echo "$PAIRE" | awk '/PublicKey/{print $2}')
UUID=$("$COEURS/sing-box" generate uuid)
SHORT_ID=$("$COEURS/sing-box" generate rand 8 --hex)
MDP=$(head -c 24 /dev/urandom | base64 | tr -d '/+=' | head -c 24)
for duo in "b $SNI_B" "cible $SNI_A"; do
  set -- $duo
  openssl req -x509 -newkey rsa:2048 -sha256 -days 2 -nodes \
    -keyout "$BANC/$1.key" -out "$BANC/$1.crt" -subj "/CN=$2" \
    -addext "subjectAltName=DNS:$2" 2>/dev/null
  chmod 600 "$BANC/$1.key"
done

echo "== 3. serveurs =="
cat > "$BANC/a.json" <<JSON
{ "log": { "level": "info" },
  "inbounds": [{ "type": "vless", "tag": "reality-in", "listen": "10.79.0.1",
    "listen_port": $PORT, "users": [{ "uuid": "$UUID", "flow": "xtls-rprx-vision" }],
    "tls": { "enabled": true, "server_name": "$SNI_A",
      "reality": { "enabled": true,
        "handshake": { "server": "127.0.0.1", "server_port": $PORT_CIBLE },
        "private_key": "$CLE_PRIVEE", "short_id": ["$SHORT_ID"] } } }],
  "outbounds": [{ "type": "direct", "tag": "direct" }] }
JSON
cat > "$BANC/b.json" <<JSON
{ "log": { "level": "info" },
  "inbounds": [{ "type": "hysteria2", "tag": "hy2-in", "listen": "10.79.1.1",
    "listen_port": $PORT, "users": [{ "password": "$MDP" }],
    "tls": { "enabled": true, "server_name": "$SNI_B",
      "certificate_path": "$BANC/b.crt", "key_path": "$BANC/b.key" } }],
  "outbounds": [{ "type": "direct", "tag": "direct" }] }
JSON
cat > "$BANC/banniere.py" <<'PY'
import http.server, socketserver, sys
ADR, PORT, TEXTE = sys.argv[1], int(sys.argv[2]), sys.argv[3].encode()
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        corps = b"X" * 400000 if self.path == "/gros" else TEXTE
        self.send_response(200)
        self.send_header("Content-Length", str(len(corps)))
        self.end_headers()
        self.wfile.write(corps)
    def log_message(self, *a): pass
socketserver.TCPServer.allow_reuse_address = True
with socketserver.TCPServer((ADR, PORT), H) as s:
    s.serve_forever()
PY
cat > "$BANC/cible_tls.py" <<'PY'
import socket, ssl, sys, threading
PORT, CERT, CLE = int(sys.argv[1]), sys.argv[2], sys.argv[3]
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.minimum_version = ssl.TLSVersion.TLSv1_3
ctx.load_cert_chain(CERT, CLE)
ctx.set_alpn_protocols(["h2", "http/1.1"])
e = socket.socket(); e.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
e.bind(("127.0.0.1", PORT)); e.listen(16)
def servir(b):
    try:
        with ctx.wrap_socket(b, server_side=True) as t: t.recv(4096)
    except Exception: pass
    finally:
        try: b.close()
        except Exception: pass
while True:
    b, _ = e.accept(); threading.Thread(target=servir, args=(b,), daemon=True).start()
PY

sudo ip netns exec "$NS_A" runuser -u "$USER" -- \
  python3 "$BANC/cible_tls.py" "$PORT_CIBLE" "$BANC/cible.crt" "$BANC/cible.key" >"$BANC/cible.log" 2>&1 &
sleep 1
for trio in "$NS_A a BIFROST-A" "$NS_B b BIFROST-B"; do
  set -- $trio
  sudo ip netns exec "$1" runuser -u "$USER" -- \
    python3 "$BANC/banniere.py" "$ADR_BANNIERE" "$PORT_BANNIERE" "$3" >"$BANC/$2-banniere.log" 2>&1 &
  sudo ip netns exec "$1" runuser -u "$USER" -- \
    "$COEURS/sing-box" run -c "$BANC/$2.json" >"$BANC/$2-serveur.log" 2>&1 &
done
sleep 2
sudo ip netns exec "$NS_A" ss -lnt | grep -q ":$PORT " || { echo "FAILED: A muet"; tail -3 "$BANC/a-serveur.log"; exit 1; }
sudo ip netns exec "$NS_B" ss -lnu | grep -q ":$PORT " || { echo "FAILED: B muet"; tail -3 "$BANC/b-serveur.log"; exit 1; }
echo "   A (REALITY/tcp) et B (Hysteria2/udp) ecoutent, bannieres BIFROST-A et BIFROST-B posees"
echo "   verification locale des bannieres:"
sudo ip netns exec "$NS_A" curl -s --max-time 3 "http://$ADR_BANNIERE:$PORT_BANNIERE/" && echo " <- dans A"
sudo ip netns exec "$NS_B" curl -s --max-time 3 "http://$ADR_BANNIERE:$PORT_BANNIERE/" && echo " <- dans B"

echo "== 4. profil a deux coeurs =="
cat > "$BANC/profil.toml" <<TOML
interface = "bfbanc"
addresses = ["10.98.0.2/24"]

[[coeurs]]
etiquette = "A-reality"
transport = { transport = "vless-reality", serveur = "10.79.0.1", port = $PORT, uuid = "$UUID", cle_publique = "$CLE_PUBLIQUE", short_id = "$SHORT_ID", nom_de_serveur = "$SNI_A" }

[[coeurs]]
etiquette = "B-hysteria2"
transport = { transport = "hysteria2", serveur = "10.79.1.1", port = $PORT, mot_de_passe = "$MDP", nom_de_serveur = "$SNI_B", certificat = """
$(cat "$BANC/b.crt")""" }

[dns]
local_resolver = "127.0.0.1"
upstream = ["10.98.0.1"]
TOML
chmod 600 "$BANC/profil.toml"
echo "   ecrit"

echo "== 5. daemon dans le namespace client =="
sudo ip netns exec "$NS_C" setsid "$DAEMON" \
  --socket "$SOCKET" \
  --coeurs-dans "$COEURS" \
  --coeurs-configurations "$BANC/configurations" \
  --facade 127.0.0.1:1081 \
  --coeur-utilisateur nobody \
  >"$BANC/daemon.log" 2>&1 &
echo $! > "$BANC/daemon.pid"
for _ in $(seq 1 40); do
  if [ -S "$SOCKET" ]; then
    break
  fi
  sleep 0.25
done
[ -S "$SOCKET" ] || { echo "FAILED: le daemon n'a pas ouvert son socket"; tail -20 "$BANC/daemon.log"; exit 1; }
echo "   socket ouvert"

echo "== 5bis. captures: les deux fils, et les deux temoins =="
# Ce qui distingue un vecteur de fuite d'un test fonctionnel: on ne demande pas
# a la banniere par ou elle a repondu, on REGARDE le fil. Les deux captures des
# serveurs sont le controle qui rend le zero interpretable - un pcap vide donne
# le meme zero qu'un tunnel etanche, et sans temoin on ne saurait pas lequel des
# deux on tient.

# LES DEUX ETAGES D'UNE CAPTURE tcpdump.
#
# En sortant, tcpdump ecrit trois compteurs sur son erreur standard. Ils ne
# mesurent pas la meme chose: `received by filter` vient du noyau, qui compte a
# l'ENTREE de l'anneau sans savoir si l'application lira un jour; `captured`
# est le compteur interne de tcpdump, incremente une fois par paquet
# effectivement remis. Leur difference est ce que le noyau a accepte et que
# personne n'a jamais lu.
#
# Sans cette lecture, un zero ne se distingue pas d'une perte silencieuse.
# Mesure du 23/08/2026 sur la suite de fuite: cinq captures sur vingt-trois
# perdaient des paquets, dont une a 1 vu et 0 remis, et le vecteur concluait
# quand meme a l'etancheite. `--immediate-mode` supprime la cause; ceci est ce
# qui le dit le jour ou le drapeau saute.
compteur_tcpdump() {
  awk -v e="$2" 'index($0, e) && $0 ~ /^[0-9]+ packet/ { n = $1 } END { print n }' \
    "$1" 2>/dev/null
}
CAPTURES=""
capturer() {
  sudo ip netns exec "$1" tcpdump -i "$2" -s 0 --immediate-mode -U -w "$BANC/$3.pcap" >"$BANC/cap-$3.log" 2>&1 &
  CAPTURES="$CAPTURES $!"
  # L invariant des deux compteurs n est pas le meme sur lo que sur un veth.
  echo "$2" >"$BANC/cap-$3.iface"
}
capturer "$NS_C" veth-ca fil-a
capturer "$NS_C" veth-cb fil-b
# Les temoins ecoutent `lo` et non l'interface muette: une adresse posee sur un
# muet est LOCALE, donc le noyau livre par la boucle et rien ne traverse jamais
# le muet. Premiere version de ce banc: deux pcap de 196 octets, soit l'en-tete
# et rien d'autre.
capturer "$NS_A" lo temoin-a
capturer "$NS_B" lo temoin-b
sleep 1
echo "   quatre captures en cours"

echo "== 6. connect =="
set +e
sudo ip netns exec "$NS_C" "$CLI" --socket "$SOCKET" connect --config "$BANC/profil.toml"
CODE=$?
set -e
echo "   code: $CODE"
sudo ip netns exec "$NS_C" "$CLI" --socket "$SOCKET" --json status 2>&1 | grep -E "state|kill_switch" | head -4 || true

echo "== 7. par ou passe le trafic ? =="
banniere() {
  sudo ip netns exec "$NS_C" curl -s --max-time 8 "http://$ADR_BANNIERE:$PORT_BANNIERE/" 2>/dev/null || true
}
VU=$(banniere)
echo "   la banniere repond: '$VU'"
[ "$VU" = "BIFROST-A" ] || { echo "FAILED: attendu BIFROST-A"; tail -20 "$BANC/daemon.log"; exit 1; }

echo "== 7bis. sens des compteurs du TUN, mesure et non suppose =="
RX0=$(sudo ip netns exec "$NS_C" cat /sys/class/net/bfbanc/statistics/rx_bytes)
TX0=$(sudo ip netns exec "$NS_C" cat /sys/class/net/bfbanc/statistics/tx_bytes)
RECU=$(sudo ip netns exec "$NS_C" curl -s --max-time 20 -o /dev/null -w "%{size_download}" "http://$ADR_BANNIERE:$PORT_BANNIERE/gros" || echo 0)
RX1=$(sudo ip netns exec "$NS_C" cat /sys/class/net/bfbanc/statistics/rx_bytes)
TX1=$(sudo ip netns exec "$NS_C" cat /sys/class/net/bfbanc/statistics/tx_bytes)
echo "   telecharge: $RECU octets"
echo "   delta rx_bytes: $(( RX1 - RX0 ))"
echo "   delta tx_bytes: $(( TX1 - TX0 ))"
echo "   -> le compteur qui suit le telechargement est celui des octets RECUS"

echo "== 8. regles du kill switch, avant le gel =="
sudo ip netns exec "$NS_C" nft list ruleset 2>/dev/null | grep -cE "drop" | xargs echo "   regles de rejet:" || true
sudo ip netns exec "$NS_C" nft list ruleset 2>/dev/null | grep -E "skuid|drop" | head -6 || true

echo "== 8bis. temoin negatif: hors du tunnel, rien ne sort =="
# Le kill switch n'exempte que le coeur, par identite (skuid 65534). Une requete
# vers le port de transport du serveur ne passe PAS par le tunnel - la route y
# est directe - donc elle doit etre jetee. Sans ce temoin, "le trafic passe"
# ne dirait pas s'il passe PAR le tunnel ou a cote.
set +e
sudo ip netns exec "$NS_C" curl -s --max-time 4 "http://10.79.1.1:$PORT/" >/dev/null 2>&1
HORS=$?
sudo ip netns exec "$NS_C" runuser -u nobody -- curl -s --max-time 4 "http://10.79.1.1:$PORT/" >/dev/null 2>&1
COEUR=$?
set -e
[ "$HORS" -ne 0 ] || { echo "FAILED: une requete hors tunnel a abouti"; exit 1; }
echo "   hors tunnel, compte non exempte: bloque (code $HORS)"
echo "   meme requete sous l'identite du coeur: code $COEUR (le pare-feu la laisse passer, le serveur la refuse)"

echo "== 8ter. temoin: un tiers local ne sort pas par l'entree du coeur =="
# Le trou mesure ici le 20 aout 2026, et desormais garde: la boucle locale
# n'authentifie personne. Un processus quelconque de la machine - ni le passeur
# ni le coeur - se connectait a l'entree SOCKS du coeur sans rien presenter et
# ressortait par le tunnel, banniere comprise. Meme famille que FlClash #1934.
#
# La sonde parle le protocole plutot que de lire le code de sortie de curl:
# elle distingue les TROIS issues qu'un simple echec confondrait - le coeur
# accepte sans identifiants (le trou), le coeur exige (l'etat voulu), rien
# n'ecoute (une premisse fausse, ou le refus ne prouverait rien).
set +e
SONDE=$(sudo ip netns exec "$NS_C" python3 - "$PORT_SOCKS_COEUR" <<'PROTOCOLE'
import socket
import sys

port = int(sys.argv[1])
try:
    f = socket.create_connection(("127.0.0.1", port), timeout=5)
except OSError as e:
    print(f"MUET {e}")
    sys.exit(0)
with f:
    # Salutation d'un tiers: "je ne propose que sans authentification".
    f.sendall(bytes([0x05, 0x01, 0x00]))
    r = f.recv(2)
if r == bytes([0x05, 0x00]):
    print("OUVERT le coeur accepte un appelant qui ne presente rien")
elif len(r) == 2 and r[0] == 0x05 and r[1] == 0xFF:
    print("EXIGE le coeur refuse la methode sans authentification")
else:
    print(f"INDECIS reponse inattendue: {r.hex() or 'vide'}")
PROTOCOLE
)
set -e
echo "   $SONDE"
case "$SONDE" in
  EXIGE*) ;;
  OUVERT*) echo "FAILED: EXPOSE, tout processus local sort par le tunnel sans identifiants"; exit 1 ;;
  *) echo "FAILED: la sonde n'a rien pu conclure, le refus ne prouverait rien"; exit 1 ;;
esac
# Le temoin qui rend ce refus lisible: le tunnel, lui, porte toujours. Sans
# cette ligne, un coeur mort donnerait exactement le meme EXIGE.
VU_APRES_SONDE=$(banniere)
if [ "$VU_APRES_SONDE" != "BIFROST-A" ]; then
  echo "FAILED: le tunnel ne porte plus apres la sonde ($VU_APRES_SONDE), le refus ne prouve rien"
  exit 1
fi
echo "   et le tunnel porte toujours: $VU_APRES_SONDE"

echo "== 9. GEL de A =="
sudo ip -n "$NS_A" link set veth-sa down
echo "   le lien vers A est coupe"
banniere >/dev/null 2>&1 || true
echo "   la banniere par A: '$(banniere)'"

echo "== 10. l'application insiste, comme une vraie application =="
# Pourquoi insister plutot que se taire. Un banc qui se tait fait tomber le
# tunnel meme quand la bascule reussit, et pour une raison qui n'a rien a voir
# avec elle: apres dix secondes sans trafic l'observateur envoie sa sonde de
# vitalite, laquelle vise generate_204 sur l'internet public - hors d'atteinte
# depuis un espace de noms isole. Le banc mesurerait sa propre cage.
#
# Une application qui perd sa connexion, elle, reessaie. Ses echecs traversent
# le coeur, qui ecrit ses refus DANS le TUN: le silence ne s'installe jamais,
# la sonde ne part pas, et c'est le critere de DEBIT qui tranche - une chute
# sous la reference etablie plus haut. C'est le chemin que le document 04
# partie 3.2 decrit, et le seul des deux qu'un banc ferme peut honorer.
DEBUT=$(date +%s)
VU=""
for i in $(seq 1 30); do
  VU=$(banniere)
  # `grep -c` rend 1 quand le compte est zero. Sans ce garde-fou, `set -e`
  # tuerait le banc au moment precis ou le kill switch n'a plus de regle -
  # c'est-a-dire au seul moment ou l'on voudrait le voir le dire. Meme famille
  # que les `|| true` qui suivent: sous `set -euo pipefail`, tout pipeline dont
  # un maillon peut legitimement ne rien trouver est un arret silencieux.
  RESTE=$(sudo ip netns exec "$NS_C" nft list ruleset 2>/dev/null | grep -cE "drop" || true)
  RX=$(sudo ip netns exec "$NS_C" cat /sys/class/net/bfbanc/statistics/rx_bytes 2>/dev/null || echo NA)
  # Meme regle, et c'est ici qu'elle mordait: si le client ne rend rien a cet
  # instant, `grep` ne trouve rien, `pipefail` fait rendre 1 au pipeline, et la
  # boucle s'arretait au tour suivant sans une ligne de journal.
  ETAT=$(sudo ip netns exec "$NS_C" "$CLI" --socket "$SOCKET" --json status 2>/dev/null | grep -o '"state": *"[a-z]*"' | head -1 || true)
  echo "   t+$(( $(date +%s) - DEBUT ))s: banniere='$VU' drop=$RESTE rx=$RX $ETAT"
  if [ "$VU" = "BIFROST-B" ]; then
    break
  fi
  sleep 2
done

echo "== 11. et maintenant, par ou passe le trafic ? =="
echo "   la banniere repond: '$VU'"
if [ "$VU" = "BIFROST-B" ]; then
  echo "   -> le trafic est reparti par B, sans que le tunnel soit tombe"
else
  echo "   -> ECHEC: le trafic n'est pas reparti par B"
fi
echo "== 12. ce que le fil a porte =="
# Laisser passer les derniers paquets sur le fil, et rien de plus.
#
# Il y avait ici trois secondes. Elles repondaient au delai de lecture de
# libpcap: tcpdump n'etait reveille qu'au bout d'une seconde, donc une capture
# arretee dans la foulee du dernier echange perdait ce qui dormait dans
# l'anneau et rendait un zero tres propre pour une raison qui n'avait rien a
# voir avec l'etancheite. Mesure du 20 aout 2026: le temoin de B annoncait
# "24 paquets vus par le filtre, 0 ecrits", pour un echange qui datait de moins
# d'une seconde.
#
# La cause est traitee: les captures portent `--immediate-mode`, qui fait
# retomber libpcap en TPACKET_V2, ou le noyau ne met rien en attente. Et
# l'echange, lui, est deja fini quand on arrive ici: l'etape 11 a lu la
# banniere de facon synchrone. Il ne reste donc a couvrir que le trajet des
# derniers paquets sur le veth.
#
# Mesure du 23/08/2026 sur la machine d'essai, deux passages a 0,2 s: les
# quatre captures concordantes, et les deux temoins voyant toujours leur
# banniere en clair. Deux chemins rouges independants surveillent cette valeur -
# la comparaison des deux compteurs plus bas, et le contenu attendu des temoins -
# donc une attente trop courte se verrait au lieu de se taire.
sleep 0.2
for p in $CAPTURES; do sudo kill "$p" 2>/dev/null || true; done
sleep 2
sudo chmod 644 "$BANC"/*.pcap 2>/dev/null || true
for l in "$BANC"/cap-*.log; do
  echo "   $(basename "$l" .log): $(awk '{printf "%s ", $0}' "$l")"
done

# Les quatre captures doivent avoir remis tout ce que le noyau leur a donne.
# Sinon le verdict de fuite ci-dessous porte sur des pcap troues, et les deux
# temoins - dont c'est precisement le role de rendre le zero interpretable -
# perdraient leur pouvoir de temoigner.
#
# L'invariant n'est PAS le meme selon l'interface. Sur un veth, un paquet vu
# par le filtre du noyau doit etre un paquet remis. Sur la boucle locale, le
# noyau en compte DEUX pour un: le paquet passe une fois en sortie et une fois
# en entree, et c'est libpcap qui jette la copie sortante, en espace
# utilisateur, apres que le compteur du noyau l'a deja vue. `pcap-linux.c`,
# `linux_check_direction()`: << Outgoing packet. If this is from the loopback
# device, reject it; we'll see the packet as an incoming packet as well, and we
# don't want to see it twice. >>
#
# Mesure du 23/08/2026 sur la machine d'essai: le temoin de A annoncait 164 vus
# pour 82 remis, soit exactement le double, et une egalite stricte le declarait
# incomplet. Une garde qui rougit pour la mauvaise raison apprend a ignorer le
# rouge, donc l'invariant de la boucle locale est ecrit ici plutot que subi.
for l in "$BANC"/cap-*.log; do
  ETAGE_NOM=$(basename "$l" .log)
  ETAGE_IF=$(cat "$BANC/$ETAGE_NOM.iface" 2>/dev/null || echo inconnue)
  ETAGE_VUS=$(compteur_tcpdump "$l" "received by filter")
  ETAGE_REMIS=$(compteur_tcpdump "$l" "captured")
  if [ -z "$ETAGE_VUS" ] || [ -z "$ETAGE_REMIS" ]; then
    echo "FAILED: $ETAGE_NOM n'a pas rendu ses compteurs, son pcap n'est pas verifiable"
    exit 1
  fi
  if [ "$ETAGE_IF" = lo ]; then
    ETAGE_ATTENDU=$((ETAGE_REMIS * 2))
  else
    ETAGE_ATTENDU=$ETAGE_REMIS
  fi
  if [ "$ETAGE_VUS" -gt "$ETAGE_ATTENDU" ]; then
    echo "FAILED: $ETAGE_NOM incomplete sur $ETAGE_IF, $ETAGE_VUS paquet(s) vus par le filtre du noyau pour $ETAGE_REMIS remis"
    exit 1
  fi
  echo "   $ETAGE_NOM ($ETAGE_IF): deux etages concordants, $ETAGE_VUS vus, $ETAGE_REMIS remis"
done
set +e
python3 - "$BANC" <<'LECTURE'
import pathlib
import sys

banc = pathlib.Path(sys.argv[1])
# Les deux fils portent le tunnel: rien de la banniere ne doit y paraitre. Les
# deux temoins ecoutent la boucle des serveurs, en aval du dechiffrement: la
# banniere DOIT y paraitre, sans quoi le zero des fils ne prouverait rien.
attendu = {"fil-a": False, "fil-b": False, "temoin-a": True, "temoin-b": True}
verdict = 0
for nom, doit_paraitre in attendu.items():
    f = banc / f"{nom}.pcap"
    if not f.exists():
        print(f"   {nom}: pas de capture")
        verdict = 1
        continue
    brut = f.read_bytes()
    vus = sorted({brut[i : i + 9].decode() for i in range(len(brut) - 8)
                  if brut[i : i + 8] == b"BIFROST-"})
    if doit_paraitre:
        etat = "OK" if vus else "ECHEC: le temoin ne voit rien, le zero des fils ne prouve donc rien"
    else:
        etat = "OK" if not vus else "FUITE"
    if not etat.startswith("OK"):
        verdict = 1
    print(f"   {nom}: {len(brut)} octets, en clair {vus or 'rien'} -> {etat}")
sys.exit(verdict)
LECTURE
FUITE=$?
set -e

echo "== 13. ce que le daemon a observe =="
grep -aoE 'candidat perdu.*|bascule demandee.*|le coeur sert desormais.*' "$BANC/daemon.log" | sed 's/^/   /' | tail -8 || true

echo "== 13bis. deconnexion, comme un utilisateur =="
# Et non un `kill`. Un daemon tue laisse DELIBEREMENT le systeme ferme, kill
# switch arme et resolveur du tunnel en place: c'est la bonne conduite pour un
# VPN, et c'est pour cela que la voie de retour est une commande et non un
# signal. Deconnecter ici fait donc deux choses a la fois: c'est le nettoyage
# du banc, et c'est la MESURE du chemin de restauration du produit, que
# l'etape suivante juge.
set +e
sudo ip netns exec "$NS_C" "$CLI" --socket "$SOCKET" disconnect
echo "   code: $?"
set -e

echo "== 14. la machine hote a-t-elle ete touchee =="
DNS_APRES=$(etat_dns_hote)
if [ "$DNS_AVANT" = "$DNS_APRES" ]; then
  echo "   /etc/resolv.conf: inchange"
  DNS_INTACT=0
else
  echo "   /etc/resolv.conf: MODIFIE par ce banc"
  echo "     avant: $DNS_AVANT"
  echo "     apres: $DNS_APRES"
  DNS_INTACT=1
fi

echo
if [ "$VU" = "BIFROST-B" ] && [ "$FUITE" -eq 0 ] && [ "$DNS_INTACT" -eq 0 ]; then
  echo "OK: le tunnel a change de transport sans tomber, rien n'a paru en clair sur le fil, et la machine hote est intacte"
  exit 0
fi
echo "FAILED: banniere finale '$VU', verdict des captures $FUITE, DNS de l'hote $DNS_INTACT"
echo "--- fin du journal du daemon ---"
tail -20 "$BANC/daemon.log"
exit 1
