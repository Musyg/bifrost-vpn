#!/usr/bin/env bash
# Banc du repli CDN: les deux transports HTTP, par les deux chemins.
#
# # Ce que ce banc etablit
#
# Que `websocket-cdn` porte du trafic reel A TRAVERS un CDN, et que
# `httpupgrade-front` n'y arrive pas alors qu'il y arrive derriere un front
# ordinaire. Cette ASYMETRIE est le sujet du banc, pas un detail: c'est elle qui
# justifie deux techniques la ou une seule aurait suffi, et c'est une mesure du
# 21 aout 2026 qu'aucune lecture de documentation n'aurait donnee.
#
#   espace de noms client            |            machine hote
#                                    |
#   client sing-box                  |   nginx dedie 8088
#     |                              |     +-- /ws-<alea> --> sing-box 44347 (ws)
#     +-- par le CDN --> 443 --------|-->  +-- /hu-<alea> --> sing-box 44348 (httpupgrade)
#     |   <alea>.trycloudflare.com   |     +-- /          --> une vraie page
#     |     (cloudflared)            |
#     +-- par le front --> 10.78.0.1:8088   banniere 127.0.0.1:7200
#                                    |        (hors de portee du client)
#
# Quatre cellules, dont trois doivent passer et une doit echouer:
#
#   | transport      | par le front | par le CDN |
#   |----------------|--------------|------------|
#   | ws             | passe        | passe      |
#   | httpupgrade    | passe        | ECHOUE     |
#
# La colonne "par le front" n'est pas decorative: sans elle, un echec du cote
# CDN ne distinguerait pas "l'edge refuse ce transport" de "l'origine est
# cassee". C'est le temoin qui donne son sens a la cellule qui echoue.
#
# # Pourquoi un espace de noms pour le client
#
# La banniere vit sur `127.0.0.1:7200` de l'HOTE. Si le client partageait cette
# boucle locale, il l'atteindrait sans tunnel et la mesure ne dirait plus rien.
# Dans un espace de noms, `127.0.0.1` designe une AUTRE boucle locale: la
# banniere n'est joignable que par un CONNECT resolu a la SORTIE du tunnel. Le
# banc le VERIFIE avant de mesurer quoi que ce soit.
#
# Sans privileges, il se rabat sur un client colocalise: les quatre cellules
# gardent leur sens - un CONNECT qui echoue reste un CONNECT qui echoue - mais
# le temoin negatif disparait et le chemin produit devient inmesurable. Le banc
# le DIT plutot que de rendre un vert moins cher.
#
# # Pourquoi httpupgrade echoue, et pourquoi c'est structurel
#
# `transport/v2rayhttpupgrade/client.go` annonce `Upgrade: websocket` mais ecrit
# une requete HTTP/1.1 brute, sans `Sec-WebSocket-Key` ni
# `Sec-WebSocket-Version`. L'edge REFUSE cette poignee incomplete par un 400.
# Le serveur `httpupgrade` de sing-box refuse a l'inverse une poignee COMPLETE:
# "real websocket request received". Les deux exigences s'excluent. Un proxy
# inverse ordinaire, lui, relaie sans valider - d'ou la colonne qui passe.
#
# Si un jour la cellule attendue en echec se met a passer, ce banc le DIT au
# lieu de rougir: ce serait une nouvelle, pas une regression.
#
# # Pourquoi un front devant le coeur
#
# Mesure du meme jour: sing-box seul rend un `404` VIDE, sans meme un en-tete
# `Server`, sur tout chemin autre que le secret. Un sondage actif distingue cela
# d'un site ordinaire, et sing-box n'a pas de `fallback` contrairement a Xray.
# nginx sert une vraie page et ne route que les chemins secrets. Le banc le
# VERIFIE plutot que de le supposer.
#
# # Ce qu'il touche, et ce qu'il n'arme pas
#
# Aucun kill switch, aucune route sur les interfaces existantes. Il mesure qu'un
# transport TRAVERSE, pas qu'il est etanche: c'est l'objet des vecteurs de
# fuite, qui ont leur propre banc.
#
# Il touche en revanche au pare-feu, et il vaut mieux le dire. Sur une machine
# qui fait tourner docker ou ufw, FORWARD et INPUT sont en politique DROP. Le
# banc INSERE trois regles ACCEPT en TETE de chaine - en tete et pas a la fin,
# sinon les chaines de docker et de ufw tranchent avant - et les retire en
# sortant:
#
#   FORWARD, deux regles sur le veth      pour que le client sorte sur Internet
#   INPUT, une regle sur le veth:8088     pour qu'il joigne le front sur l'hote
#
# La distinction n'est pas cosmetique. Un paquet vers `10.78.0.1` n'est PAS
# route: il est livre localement, donc il passe par INPUT et jamais par FORWARD.
# Ouvrir FORWARD seul donne une sortie Internet et un `i/o timeout` sur le
# front, ce qui se lit a tort comme une origine cassee.
#
# Les trois regles portent sur une interface qui n'existe que le temps du banc,
# et `ip_forward` n'est remis a zero que s'il valait zero a l'arrivee.
#
# Il ne touche pas au nginx du systeme - une instance dediee, sans privilege,
# avec sa propre configuration et son propre pid.
#
# # Ce qu'il n'etablit PAS
#
# Que le transport resiste a un censeur. Cloudflare n'est pas un adversaire: il
# route. Ce banc mesure la COMPATIBILITE avec un CDN, condition necessaire et
# rien de plus. Le tableau de survie, lui, se nourrit d'observations de terrain
# datees.
#
# # Usage
#
#   scripts/banc-cdn-linux.sh                    # les quatre cellules
#   scripts/banc-cdn-linux.sh --garder           # laisse la pile debout
#   scripts/banc-cdn-linux.sh --daemon <chemin>  # ajoute le chemin PRODUIT
#
# Sans `--daemon`, le banc mesure les transports avec un client sing-box nu:
# meme question, meme coeur, mais ce n'est pas la configuration que Bifrost
# engendre. Avec, il lance en plus `--coeur-e2e`, qui eprouve le profil, le
# generateur, le superviseur et la bascule.
#
# Variables: BIFROST_COEUR (binaire sing-box), BIFROST_CLOUDFLARED,
# BIFROST_BANC_CDN (repertoire de travail).

set -uo pipefail

BASE="${BIFROST_BANC_CDN:-$HOME/bifrost-banc-cdn}"
COEUR="${BIFROST_COEUR:-$HOME/bifrost-coeurs/sing-box}"
CLOUDFLARED="${BIFROST_CLOUDFLARED:-$BASE/cloudflared}"
DAEMON=""
GARDER=0

NS=bifrost-cdn-client
VETH_H=v-cdn-h
VETH_C=v-cdn-c
RESEAU=10.78.0
PORT_WS=44347
PORT_HU=44348
PORT_FRONT=8088
PORT_BANNIERE=7200
PORT_SOCKS=1090
ATTENDU=BIFROST-BANC-CDN
NAVIGATEUR="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36"

while [ $# -gt 0 ]; do
	case "$1" in
	--garder) GARDER=1 ;;
	--daemon)
		DAEMON="${2:-}"
		shift
		;;
	*)
		echo "option inconnue: $1" >&2
		exit 2
		;;
	esac
	shift
done

echecs=0
sautes=0
NETNS=0
FORWARD_AVANT=""

dire() { printf '%s\n' "$*"; }
passe() { dire "PASSED  $*"; }
casse() {
	dire "FAILED  $*"
	echecs=$((echecs + 1))
}
saute() {
	dire "SKIPPED $*"
	sautes=$((sautes + 1))
}
manquant() {
	dire "SKIPPED $*"
	exit 0
}

# ---------------------------------------------------------------------------
# 0. Premisses. Tout ce qui manque rend SKIPPED en le nommant, jamais PASSED.
# ---------------------------------------------------------------------------
dire "== 0. premisses =="

for outil in nginx curl python3 ss; do
	command -v "$outil" > /dev/null 2>&1 ||
		manquant "premisses: '$outil' est absent du PATH"
done
[ -x "$COEUR" ] || manquant "premisses: aucun sing-box a '$COEUR' (BIFROST_COEUR)"
[ -x "$CLOUDFLARED" ] ||
	manquant "premisses: aucun cloudflared a '$CLOUDFLARED' (BIFROST_CLOUDFLARED)"
if [ -n "$DAEMON" ] && [ ! -x "$DAEMON" ]; then
	manquant "premisses: --daemon '$DAEMON' n'est pas executable"
fi
curl -s --max-time 10 -o /dev/null https://api.cloudflare.com/ ||
	manquant "premisses: api.cloudflare.com injoignable, ce banc a besoin d'Internet"
for p in "$PORT_WS" "$PORT_HU" "$PORT_FRONT" "$PORT_BANNIERE"; do
	if ss -lnt 2> /dev/null | grep -q ":$p "; then
		manquant "premisses: le port $p est deja pris, le banc refuse de se meler a autre chose"
	fi
done

if sudo -n true 2> /dev/null && command -v runuser > /dev/null 2>&1; then
	NETNS=1
	dire "   espace de noms: oui, le temoin negatif sera mesure"
else
	dire "   espace de noms: NON (sudo sans mot de passe indisponible)."
	dire "   Le client partagera la boucle locale de la banniere: les quatre"
	dire "   cellules restent valides, le temoin negatif est perdu."
fi
dire "   sing-box: $("$COEUR" version 2>&1 | head -1)"
dire "   $("$CLOUDFLARED" --version 2>&1 | head -1)"

# ---------------------------------------------------------------------------
# 1. L'etat, hors du depot. Les secrets naissent ici et n'en sortent pas.
# ---------------------------------------------------------------------------
mkdir -p "$BASE/nginx/logs" "$BASE/nginx/temp" "$BASE/site"
chmod 700 "$BASE"
PIDS="$BASE/pids"
: > "$PIDS"

UUID=$(python3 -c "import uuid; print(uuid.uuid4())")
ALEA=$(python3 -c "import secrets; print(secrets.token_hex(6))")
CHEMIN_WS="/ws-$ALEA"
CHEMIN_HU="/hu-$ALEA"

# Le demontage vit ici et pas a la fin: un `exit` premature doit rendre la
# machine aussi, sinon le banc laisse des orphelins qui tiennent les ports et le
# passage suivant rend SKIPPED sans qu'on sache pourquoi.
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

demonter() {
	if [ "$GARDER" = 1 ]; then
		dire
		dire "pile laissee debout (--garder). PID dans $PIDS"
		return
	fi
	nginx -s stop -c "$BASE/nginx/nginx.conf" 2> /dev/null
	# Par PID note, jamais par motif de nom: un motif a deja coupe des services
	# etrangers sur cette flotte.
	while read -r p; do [ -n "$p" ] && kill "$p" 2> /dev/null; done < "$PIDS"
	sleep 1
	while read -r p; do [ -n "$p" ] && kill -9 "$p" 2> /dev/null; done < "$PIDS"
	if [ "$NETNS" = 1 ]; then
		sudo iptables -t nat -D POSTROUTING -s "$RESEAU.0/30" \
			! -o "$VETH_H" -j MASQUERADE 2> /dev/null
		sudo iptables -D FORWARD -i "$VETH_H" -j ACCEPT 2> /dev/null
		sudo iptables -D FORWARD -o "$VETH_H" -m conntrack \
			--ctstate RELATED,ESTABLISHED -j ACCEPT 2> /dev/null
		sudo iptables -D INPUT -i "$VETH_H" -p tcp \
			--dport "$PORT_FRONT" -j ACCEPT 2> /dev/null
		vider_netns "$NS"
		sudo ip netns del "$NS" 2> /dev/null
		sudo rm -rf "/etc/netns/$NS"
		# Ne rendre la machine ni plus ni moins permissive qu'on l'a trouvee.
		[ "$FORWARD_AVANT" = "0" ] && sudo sysctl -qw net.ipv4.ip_forward=0
	fi
}
trap demonter EXIT

# ---------------------------------------------------------------------------
# 2. L'espace de noms du client, s'il est possible
# ---------------------------------------------------------------------------
HOTE_FRONT=127.0.0.1
DANS_NS=()
if [ "$NETNS" = 1 ]; then
	dire
	dire "== 1. l'espace de noms du client =="
	vider_netns "$NS"
	sudo ip netns del "$NS" 2> /dev/null
	sudo ip netns add "$NS" || manquant "espace de noms: 'ip netns add' a echoue"
	sudo ip -n "$NS" link set lo up
	sudo ip link add "$VETH_H" type veth peer name "$VETH_C"
	sudo ip link set "$VETH_C" netns "$NS"
	sudo ip addr add "$RESEAU.1/30" dev "$VETH_H"
	sudo ip link set "$VETH_H" up
	sudo ip -n "$NS" addr add "$RESEAU.2/30" dev "$VETH_C"
	sudo ip -n "$NS" link set "$VETH_C" up
	sudo ip -n "$NS" route add default via "$RESEAU.1"
	sudo mkdir -p "/etc/netns/$NS"
	echo "nameserver 1.1.1.1" | sudo tee "/etc/netns/$NS/resolv.conf" > /dev/null
	FORWARD_AVANT=$(cat /proc/sys/net/ipv4/ip_forward)
	sudo sysctl -qw net.ipv4.ip_forward=1
	sudo iptables -t nat -A POSTROUTING -s "$RESEAU.0/30" \
		! -o "$VETH_H" -j MASQUERADE
	# En TETE de chaine: sur une machine qui porte docker ou ufw, la politique
	# FORWARD est DROP et leurs chaines sont branchees avant. Ajouter a la fin
	# ne servirait a rien.
	sudo iptables -I FORWARD 1 -i "$VETH_H" -j ACCEPT
	sudo iptables -I FORWARD 1 -o "$VETH_H" -m conntrack \
		--ctstate RELATED,ESTABLISHED -j ACCEPT
	# Et INPUT, qui est une autre question: joindre le front sur l'hote n'est pas
	# du routage mais une livraison locale, que FORWARD ne voit jamais passer.
	sudo iptables -I INPUT 1 -i "$VETH_H" -p tcp --dport "$PORT_FRONT" -j ACCEPT
	HOTE_FRONT="$RESEAU.1"
	DANS_NS=(sudo ip netns exec "$NS" runuser -u "$USER" --)
	if "${DANS_NS[@]}" curl -s --max-time 15 -o /dev/null https://api.cloudflare.com/; then
		passe "espace de noms: il sort sur Internet"
	else
		casse "espace de noms: pas de sortie Internet, le NAT n'a pas pris"
		exit 1
	fi
fi

# ---------------------------------------------------------------------------
# 3. La pile
# ---------------------------------------------------------------------------
dire
dire "== 2. la pile =="

cat > "$BASE/banniere.py" << 'PY'
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

port = int(sys.argv[1])
corps = sys.argv[2].encode()


class Main(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(corps)))
        self.end_headers()
        self.wfile.write(corps)

    def log_message(self, *_):
        pass


HTTPServer(("127.0.0.1", port), Main).serve_forever()
PY

cat > "$BASE/client.py" << 'PY'
import io
import json
import sys

fichier, genre, chemin, serveur, port, uuid, socks, tls, agent = sys.argv[1:10]

sortie = {
    "type": "vless",
    "tag": "essai",
    "server": serveur,
    "server_port": int(port),
    "uuid": uuid,
}
if tls == "oui":
    sortie["tls"] = {
        "enabled": True,
        "server_name": serveur,
        "utls": {"enabled": True, "fingerprint": "chrome"},
    }

transport = {"type": genre, "path": chemin}
if genre == "ws":
    # `ws` n'a PAS de champ `host`: le client lit un `Host` dans les en-tetes,
    # le retire, et s'en sert comme hote de la requete. Son agent par defaut est
    # `Go-http-client/1.1`, qu'aucun navigateur n'envoie.
    transport["headers"] = {"Host": serveur, "User-Agent": agent}
else:
    transport["host"] = serveur
sortie["transport"] = transport

io.open(fichier, "w", encoding="utf-8", newline="\n").write(
    json.dumps(
        {
            "log": {"level": "warn"},
            "inbounds": [
                {"type": "socks", "listen": "127.0.0.1", "listen_port": int(socks)}
            ],
            "outbounds": [sortie],
        },
        indent=2,
    )
    + "\n"
)
PY

cat > "$BASE/site/index.html" << 'HTML'
<!doctype html>
<meta charset="utf-8">
<title>Carnet de bord</title>
<style>body{font:16px/1.6 system-ui,sans-serif;max-width:38rem;margin:4rem auto;padding:0 1rem}</style>
<h1>Carnet de bord</h1>
<p>Notes personnelles, publiees au fil de l'eau.</p>
HTML

cat > "$BASE/origine.json" << JSON
{
  "log": { "level": "warn" },
  "inbounds": [
    {
      "type": "vless", "tag": "entree-ws",
      "listen": "127.0.0.1", "listen_port": $PORT_WS,
      "users": [ { "name": "banc", "uuid": "$UUID" } ],
      "transport": { "type": "ws", "path": "$CHEMIN_WS" }
    },
    {
      "type": "vless", "tag": "entree-httpupgrade",
      "listen": "127.0.0.1", "listen_port": $PORT_HU,
      "users": [ { "name": "banc", "uuid": "$UUID" } ],
      "transport": { "type": "httpupgrade", "path": "$CHEMIN_HU" }
    }
  ],
  "outbounds": [ { "type": "direct", "tag": "direct" } ]
}
JSON
chmod 600 "$BASE/origine.json"

ECOUTE_FRONT="listen 127.0.0.1:$PORT_FRONT;"
[ "$NETNS" = 1 ] && ECOUTE_FRONT="$ECOUTE_FRONT
        listen $RESEAU.1:$PORT_FRONT;"

cat > "$BASE/nginx/nginx.conf" << CONF
worker_processes 1;
error_log $BASE/nginx/logs/error.log warn;
pid $BASE/nginx/nginx.pid;
events { worker_connections 256; }
http {
    include /etc/nginx/mime.types;
    access_log $BASE/nginx/logs/access.log;
    client_body_temp_path $BASE/nginx/temp/body;
    proxy_temp_path $BASE/nginx/temp/proxy;
    fastcgi_temp_path $BASE/nginx/temp/fastcgi;
    uwsgi_temp_path $BASE/nginx/temp/uwsgi;
    scgi_temp_path $BASE/nginx/temp/scgi;

    server {
        $ECOUTE_FRONT
        server_name _;
        root $BASE/site;
        index index.html;

        # Les trois en-tetes qui font tenir un Upgrade a travers un proxy
        # inverse. Sans eux nginx tamponne et la bascule ne se produit jamais.
        location $CHEMIN_WS {
            proxy_pass http://127.0.0.1:$PORT_WS;
            proxy_http_version 1.1;
            proxy_set_header Upgrade \$http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host \$host;
            proxy_read_timeout 300s;
            proxy_buffering off;
        }
        location $CHEMIN_HU {
            proxy_pass http://127.0.0.1:$PORT_HU;
            proxy_http_version 1.1;
            proxy_set_header Upgrade \$http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host \$host;
            proxy_read_timeout 300s;
            proxy_buffering off;
        }
        location / { try_files \$uri \$uri/ =404; }
    }
}
CONF

python3 "$BASE/banniere.py" "$PORT_BANNIERE" "$ATTENDU" > "$BASE/banniere.log" 2>&1 &
echo $! >> "$PIDS"

"$COEUR" run -c "$BASE/origine.json" > "$BASE/origine.log" 2>&1 &
echo $! >> "$PIDS"

if ! nginx -t -c "$BASE/nginx/nginx.conf" > "$BASE/nginx/test.log" 2>&1; then
	casse "nginx: configuration refusee"
	sed 's/^/        /' "$BASE/nginx/test.log"
	exit 1
fi
nginx -c "$BASE/nginx/nginx.conf"

for _ in $(seq 1 40); do
	ss -lnt 2> /dev/null | grep -q ":$PORT_FRONT " &&
		ss -lnt 2> /dev/null | grep -q ":$PORT_WS " && break
	sleep 0.25
done
if curl -s --max-time 5 "http://127.0.0.1:$PORT_BANNIERE/" | grep -q "$ATTENDU"; then
	passe "pile: la banniere repond sur la boucle locale de l'hote"
else
	casse "pile: la banniere ne repond pas, rien de ce qui suit n'aurait de sens"
	exit 1
fi
dire "   origine: ws sur $PORT_WS, httpupgrade sur $PORT_HU"
dire "   front nginx sur $HOTE_FRONT:$PORT_FRONT, chemins $CHEMIN_WS et $CHEMIN_HU"

# Le temoin negatif, AVANT toute mesure: si la banniere etait deja joignable
# sans tunnel, les cellules qui suivent ne prouveraient rien.
if [ "$NETNS" = 1 ]; then
	if "${DANS_NS[@]}" curl -s --max-time 5 -o /dev/null \
		"http://127.0.0.1:$PORT_BANNIERE/"; then
		casse "temoin: la banniere est joignable en direct depuis le client"
		exit 1
	else
		passe "temoin: en direct, la banniere est hors d'atteinte du client"
	fi
else
	saute "temoin: sans espace de noms, le client partage la boucle locale de la
        banniere. Elle lui est joignable sans tunnel, donc rien ici ne peut
        etablir qu'un CONNECT a bien traverse."
fi

# ---------------------------------------------------------------------------
# 4. Le tunnel
# ---------------------------------------------------------------------------
dire
dire "== 3. le tunnel rapide =="
"$CLOUDFLARED" tunnel --url "http://127.0.0.1:$PORT_FRONT" --no-autoupdate \
	> "$BASE/tunnel.log" 2>&1 &
echo $! >> "$PIDS"

HOTE=""
for _ in $(seq 1 60); do
	HOTE=$(grep -oE "https://[a-z0-9-]+\.trycloudflare\.com" "$BASE/tunnel.log" 2> /dev/null | head -1)
	[ -n "$HOTE" ] && break
	sleep 1
done
if [ -z "$HOTE" ]; then
	saute "tunnel: aucun hote rendu en 60 s, Cloudflare n'a pas repondu"
	tail -8 "$BASE/tunnel.log" | sed 's/^/        /'
	exit 0
fi
DOMAINE="${HOTE#https://}"
dire "   $HOTE"
sleep 3

# ---------------------------------------------------------------------------
# 5. La facade. Elle est la pour qu'un sondage actif ne trouve pas un coeur nu.
# ---------------------------------------------------------------------------
dire
dire "== 4. ce qu'un sondage actif voit =="
ENTETES=$(curl -s -i --max-time 25 "$HOTE/" 2>&1)
if printf '%s' "$ENTETES" | grep -qi "^server: cloudflare" &&
	printf '%s' "$ENTETES" | grep -q "Carnet de bord"; then
	passe "facade: une vraie page repond a travers le CDN"
else
	casse "facade: le CDN n'a pas rendu la page attendue"
	printf '%s' "$ENTETES" | head -6 | sed 's/^/        /'
fi
CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 25 "$HOTE/robots.txt")
if [ "$CODE" = "404" ]; then
	passe "facade: un chemin inconnu rend 404, comme un site ordinaire"
else
	casse "facade: chemin inconnu -> HTTP $CODE, attendu 404"
fi

# ---------------------------------------------------------------------------
# 6. Les quatre cellules
# ---------------------------------------------------------------------------
essayer_transport() {
	local nom="$1" genre="$2" chemin="$3" serveur="$4" port="$5" tls="$6"
	local conf="$BASE/client-$nom.json"
	python3 "$BASE/client.py" "$conf" "$genre" "$chemin" "$serveur" "$port" \
		"$UUID" "$PORT_SOCKS" "$tls" "$NAVIGATEUR" || return 1
	chmod 600 "$conf"
	"${DANS_NS[@]}" "$COEUR" run -c "$conf" > "$BASE/client-$nom.log" 2>&1 &
	local pid=$!
	echo "$pid" >> "$PIDS"
	local pret=1
	for _ in $(seq 1 40); do
		"${DANS_NS[@]}" ss -lnt 2> /dev/null | grep -q ":$PORT_SOCKS " && {
			pret=0
			break
		}
		sleep 0.25
	done
	local reponse=""
	if [ "$pret" = 0 ]; then
		reponse=$("${DANS_NS[@]}" curl -s --max-time 25 \
			--socks5-hostname "127.0.0.1:$PORT_SOCKS" \
			"http://127.0.0.1:$PORT_BANNIERE/" 2> /dev/null)
	fi
	# Tuer le pere par son PID; sous `ip netns exec`, sing-box est son enfant et
	# part avec lui. Jamais de motif de nom: un motif a deja coupe des services
	# etrangers sur cette flotte.
	kill "$pid" 2> /dev/null
	wait "$pid" 2> /dev/null
	sleep 1
	[ "$reponse" = "$ATTENDU" ]
}

derniere_erreur() {
	sed 's/\x1b\[[0-9;]*m//g' "$BASE/client-$1.log" |
		grep -iE "error|fatal|unexpected" | tail -2 | sed 's/^/        /'
}

dire
dire "== 5. le temoin: les deux transports par le front, en direct =="
if essayer_transport front-ws ws "$CHEMIN_WS" "$HOTE_FRONT" "$PORT_FRONT" non; then
	passe "front + ws: la banniere traverse"
else
	casse "front + ws: la banniere n'a pas traverse, l'origine est en cause"
	derniere_erreur front-ws
fi
if essayer_transport front-hu httpupgrade "$CHEMIN_HU" "$HOTE_FRONT" "$PORT_FRONT" non; then
	passe "front + httpupgrade: la banniere traverse"
else
	casse "front + httpupgrade: la banniere n'a pas traverse, l'origine est en cause"
	derniere_erreur front-hu
fi

dire
dire "== 6. la mesure: les deux transports par le CDN =="
if essayer_transport cdn-ws ws "$CHEMIN_WS" "$DOMAINE" 443 oui; then
	passe "CDN + ws: la banniere traverse un vrai edge"
else
	casse "CDN + ws: le repli CDN du produit ne passe plus"
	derniere_erreur cdn-ws
fi

# La cellule qui doit ECHOUER. Un banc qui la compterait comme un echec
# ordinaire rougirait a chaque passage; un banc qui l'ignorerait ne verrait pas
# le jour ou elle change.
LIGNES_AVANT=$(wc -l < "$BASE/nginx/logs/access.log" 2> /dev/null || echo 0)
if essayer_transport cdn-hu httpupgrade "$CHEMIN_HU" "$DOMAINE" 443 oui; then
	dire "NOTABLE CDN + httpupgrade: il PASSE, contrairement a la mesure du 21/08/2026."
	dire "        Cloudflare a change de comportement, ou l'edge atteint differe."
	dire "        Ce n'est pas une regression: c'est une nouvelle a verifier"
	dire "        avant d'en tirer parti."
else
	MOTIF=$(sed 's/\x1b\[[0-9;]*m//g' "$BASE/client-cdn-hu.log" |
		grep -o "unexpected status: [0-9]*" | head -1)
	passe "CDN + httpupgrade: refuse comme attendu (${MOTIF:-motif non lu})"
	# L'imputation, qui vaut plus que le refus lui-meme: si l'edge a rejete, le
	# front n'a PAS vu la requete. Sans ce controle, une origine cassee se lirait
	# comme un refus de l'edge.
	if sed -n "$((LIGNES_AVANT + 1)),\$p" "$BASE/nginx/logs/access.log" 2> /dev/null |
		grep -q "$CHEMIN_HU"; then
		casse "imputation: le front a VU la requete, le refus ne vient donc pas de l'edge"
	else
		passe "imputation: aucune ligne nouvelle chez le front, l'edge a bien rejete"
	fi
fi

# ---------------------------------------------------------------------------
# 7. Le chemin PRODUIT, si le binaire est la
# ---------------------------------------------------------------------------
dire
dire "== 7. le chemin du produit =="
if [ -z "$DAEMON" ]; then
	saute "produit: --daemon non fourni. Les cellules ci-dessus mesurent le
        transport avec un client sing-box nu, pas la configuration que Bifrost
        engendre: profil, generateur, superviseur et bascule ne sont pas
        eprouves."
elif [ "$NETNS" != 1 ]; then
	saute "produit: --coeur-e2e ouvre par un temoin negatif sur la banniere, et
        sans espace de noms le client la joint sans tunnel. La recette echouerait
        pour une raison qui ne dit rien du transport."
else
	PROFIL="$BASE/profil-cdn.json"
	python3 - "$PROFIL" "$DOMAINE" "$UUID" "$CHEMIN_WS" "$PORT_BANNIERE" "$ATTENDU" << 'PY'
import io
import json
import sys

fichier, domaine, uuid, chemin, port, attendu = sys.argv[1:7]
io.open(fichier, "w", encoding="utf-8", newline="\n").write(
    json.dumps(
        {
            "sorties": [
                {
                    "type": "vless-websocket",
                    "tag": "cdn",
                    "serveur": domaine,
                    "port": 443,
                    "uuid": uuid,
                    "nom_de_serveur": domaine,
                    "hote": domaine,
                    "chemin": chemin,
                }
            ],
            "banniere": {
                "hote": "127.0.0.1",
                "port": int(port),
                "chemin": "/",
                "attendu": attendu,
            },
        },
        indent=2,
    )
    + "\n"
)
PY
	chmod 600 "$PROFIL"
	if "${DANS_NS[@]}" "$DAEMON" --coeur-e2e "$PROFIL" \
		--coeurs-dans "$(dirname "$COEUR")" > "$BASE/produit.log" 2>&1; then
		passe "produit: --coeur-e2e complet a travers le CDN"
	else
		casse "produit: --coeur-e2e a echoue"
	fi
	sed 's/\x1b\[[0-9;]*m//g' "$BASE/produit.log" |
		grep -E "^(PASSED|FAILED|SKIPPED)" | sed 's/^/        /'
fi

# ---------------------------------------------------------------------------
# 8. Verdict
# ---------------------------------------------------------------------------
dire
if [ "$echecs" -eq 0 ]; then
	dire "OK: $sautes saut(s), aucun echec. Le repli CDN traverse, et httpupgrade"
	dire "    echoue la ou la mesure du 21/08/2026 dit qu'il echoue."
	exit 0
fi
dire "ECHEC: $echecs cellule(s) en echec, $sautes saut(s)"
exit 1
