#!/usr/bin/env bash
# Banc de bout en bout pour `--coeur-e2e`, entierement local, DEUX transports.
#
# # Ce que ce banc etablit
#
# Que du trafic reel traverse un tunnel par coeur, par VLESS+REALITY comme par
# Hysteria2, avec sing-box des DEUX cotes - client et serveurs - sur une seule
# machine et sans acces reseau.
#
# `--coeur-e2e` repose sur une banniere placee sur la BOUCLE LOCALE du serveur
# de sortie: elle n'est atteignable que par un CONNECT resolu a la sortie du
# tunnel, donc si elle repond, le trafic a traverse, et il n'y a pas d'autre
# explication. Lancer client et serveur sans separation ruinerait la mesure -
# `127.0.0.1` serait la meme boucle pour les deux, et le temoin negatif
# "injoignable en direct" echouerait.
#
# D'ou TROIS espaces de noms: le client, et un serveur par transport. Deux
# serveurs et non un seul parce que `Profils` refuse deux profils du meme
# transport - la couche de selection raisonne en techniques, pas en serveurs -
# et parce que c'est le montage dont la bascule en session aura besoin.
#
#   client            serveur A (REALITY)        serveur B (Hysteria2)
#   10.79.0.2  <-->   10.79.0.1:8443 tcp
#   10.79.1.2  <-->                              10.79.1.1:8443 udp
#                     banniere 127.0.0.1:7100    banniere 127.0.0.1:7100
#                     cible TLS 127.0.0.1:8444
#
# # La cible TLS de A n'est pas decorative
#
# Mesure du 20 aout 2026, sing-box 1.13.18: REALITY compose avec le site
# emprunte MEME POUR UN CLIENT AUTHENTIFIE. Avec un `handshake.server`
# injoignable, la connexion legitime est refusee - "REALITY: failed to dial
# dest: connect: connection refused" - et le client ne voit qu'un CONNECT rate.
# Le banc porte donc une vraie cible TLS 1.3 sur la boucle locale de A.
#
# La consequence depasse le banc: en exploitation, un site emprunte devenu
# injoignable fait tomber le tunnel pour tout le monde, pas seulement pour les
# sondes du censeur. C'est une dependance de disponibilite a mettre en face du
# choix du `dest`.
#
# # Ce qu'il n'arme pas
#
# Aucun kill switch, aucune regle de pare-feu sur la machine hote, aucune route
# hors des namespaces. La recette mesure le ROUTAGE, pas l'etancheite: c'est
# l'objet des vecteurs de fuite, qui ont leur propre banc.
#
# # A savoir avant de lire les journaux
#
# Les serveurs ecrivent `network: missing default interface` au demarrage.
# C'est attendu: leurs namespaces n'ont pas de route par defaut, et la sortie
# `direct` n'en a pas besoin puisqu'elle mene a la boucle locale.
#
# # Usage
#
#   scripts/banc-coeur-e2e.sh
#
# Variables: COEURS (repertoire du binaire sing-box), DAEMON (binaire du
# daemon), BANC (repertoire de travail jetable), GARDER=1 pour le conserver.
set -euo pipefail

NS_C=bifrost-e2e-client
NS_A=bifrost-e2e-reality
NS_B=bifrost-e2e-hysteria2
SNI_A=reality.bifrost.test
SNI_B=hy2.bifrost.test
PORT=8443
PORT_CIBLE=8444
PORT_BANNIERE=7100
BANNIERE=BIFROST-E2E-OK

DEPOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
BANC=${BANC:-$HOME/bifrost-banc-e2e}
COEURS=${COEURS:-$HOME/bifrost-coeurs}
DAEMON=${DAEMON:-$DEPOT/target/debug/bifrost-daemon}

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
  for ns in "$NS_C" "$NS_A" "$NS_B"; do
    vider_netns "$ns"
    sudo ip netns del "$ns" 2>/dev/null || true
  done
  # Le banc porte des cles privees et des mots de passe, tous engendres pour
  # cette execution. Les laisser trainer n'apporte rien: la prochaine execution
  # en fabrique d'autres. `GARDER=1` les conserve pour un diagnostic.
  if [ "${GARDER:-0}" != "1" ]; then
    rm -rf "$BANC"
  fi
}
trap nettoyer EXIT

manquant() {
  echo "SKIPPED: $1"
  exit 0
}

[ -x "$COEURS/sing-box" ] || manquant "$COEURS/sing-box absent: ce banc veut un vrai sing-box, que le depot ne distribue pas"
[ -x "$DAEMON" ] || manquant "$DAEMON absent: construire le daemon d'abord (cargo build --bin bifrost-daemon)"
command -v openssl >/dev/null || manquant "openssl absent, impossible d'engendrer les certificats du banc"
command -v python3 >/dev/null || manquant "python3 absent, il porte la banniere et la cible TLS"
sudo -n true 2>/dev/null || manquant "creer un espace de noms reseau demande des privileges, et sudo en demande un mot de passe ici"

echo "== 1. trois namespaces, deux liens =="
nettoyer
rm -rf "$BANC"
mkdir -p "$BANC"
sudo ip netns add "$NS_C"
sudo ip netns add "$NS_A"
sudo ip netns add "$NS_B"
sudo ip -n "$NS_C" link set lo up
for duo in "a $NS_A 10.79.0" "b $NS_B 10.79.1"; do
  # shellcheck disable=SC2086
  set -- $duo
  sudo ip link add "veth-c$1" type veth peer name "veth-s$1"
  sudo ip link set "veth-c$1" netns "$NS_C"
  sudo ip link set "veth-s$1" netns "$2"
  sudo ip -n "$NS_C" addr add "$3.2/24" dev "veth-c$1"
  sudo ip -n "$NS_C" link set "veth-c$1" up
  sudo ip -n "$2" link set lo up
  sudo ip -n "$2" addr add "$3.1/24" dev "veth-s$1"
  sudo ip -n "$2" link set "veth-s$1" up
done
sudo ip netns exec "$NS_C" ping -c1 -W2 10.79.0.1 >/dev/null
sudo ip netns exec "$NS_C" ping -c1 -W2 10.79.1.1 >/dev/null
echo "   client -> A (10.79.0.1) et B (10.79.1.1): liens vivants"

echo "== 2. secrets et certificats du banc =="
PAIRE=$("$COEURS/sing-box" generate reality-keypair)
CLE_PRIVEE=$(echo "$PAIRE" | awk '/PrivateKey/{print $2}')
CLE_PUBLIQUE=$(echo "$PAIRE" | awk '/PublicKey/{print $2}')
UUID=$("$COEURS/sing-box" generate uuid)
SHORT_ID=$("$COEURS/sing-box" generate rand 8 --hex)
MDP=$(head -c 24 /dev/urandom | base64 | tr -d '/+=' | head -c 24)
# Le certificat de B est EPINGLE dans le profil, jamais ignore: `Confiance` n'a
# volontairement aucune variante "ne pas verifier". L'admettre ferait passer la
# recette avec un tunnel non authentifie, donc lui ferait prouver le contraire
# de ce qu'elle annonce. Celui de la cible TLS de A, lui, n'est jamais vu par
# le client: REALITY lui sert un certificat temporaire signe par sa cle.
for duo in "b $SNI_B" "cible $SNI_A"; do
  # shellcheck disable=SC2086
  set -- $duo
  openssl req -x509 -newkey rsa:2048 -sha256 -days 2 -nodes \
    -keyout "$BANC/$1.key" -out "$BANC/$1.crt" -subj "/CN=$2" \
    -addext "subjectAltName=DNS:$2" 2>/dev/null
  chmod 600 "$BANC/$1.key"
done
echo "   paire REALITY, uuid, short id, mot de passe hysteria2, deux certificats"

echo "== 3. configurations des serveurs =="
cat > "$BANC/a.json" <<JSON
{
  "log": { "level": "info" },
  "inbounds": [{
    "type": "vless", "tag": "reality-in",
    "listen": "10.79.0.1", "listen_port": $PORT,
    "users": [{ "uuid": "$UUID", "flow": "xtls-rprx-vision" }],
    "tls": {
      "enabled": true, "server_name": "$SNI_A",
      "reality": {
        "enabled": true,
        "handshake": { "server": "127.0.0.1", "server_port": $PORT_CIBLE },
        "private_key": "$CLE_PRIVEE",
        "short_id": ["$SHORT_ID"]
      }
    }
  }],
  "outbounds": [{ "type": "direct", "tag": "direct" }]
}
JSON
cat > "$BANC/b.json" <<JSON
{
  "log": { "level": "info" },
  "inbounds": [{
    "type": "hysteria2", "tag": "hy2-in",
    "listen": "10.79.1.1", "listen_port": $PORT,
    "users": [{ "password": "$MDP" }],
    "tls": {
      "enabled": true, "server_name": "$SNI_B",
      "certificate_path": "$BANC/b.crt", "key_path": "$BANC/b.key"
    }
  }],
  "outbounds": [{ "type": "direct", "tag": "direct" }]
}
JSON
chmod 600 "$BANC/a.json" "$BANC/b.json"

cat > "$BANC/banniere.py" <<'PY'
import http.server
import socketserver
import sys

PORT, TEXTE = int(sys.argv[1]), sys.argv[2].encode()


class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", str(len(TEXTE)))
        self.end_headers()
        self.wfile.write(TEXTE)

    def log_message(self, *a):
        pass


socketserver.TCPServer.allow_reuse_address = True
with socketserver.TCPServer(("127.0.0.1", PORT), H) as s:
    s.serve_forever()
PY

# La cible TLS 1.3 du handshake REALITY. Elle ne parle pas HTTP: REALITY
# n'echange que le handshake avec elle. Voir l'en-tete du script.
cat > "$BANC/cible_tls.py" <<'PY'
import socket
import ssl
import sys
import threading

PORT, CERT, CLE = int(sys.argv[1]), sys.argv[2], sys.argv[3]

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.minimum_version = ssl.TLSVersion.TLSv1_3
ctx.load_cert_chain(CERT, CLE)
ctx.set_alpn_protocols(["h2", "http/1.1"])

ecoute = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ecoute.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
ecoute.bind(("127.0.0.1", PORT))
ecoute.listen(16)


def servir(brut):
    try:
        with ctx.wrap_socket(brut, server_side=True) as tls:
            tls.recv(4096)
    except Exception:
        pass
    finally:
        try:
            brut.close()
        except Exception:
            pass


while True:
    brut, _ = ecoute.accept()
    threading.Thread(target=servir, args=(brut,), daemon=True).start()
PY

echo "== 4. lancement dans les namespaces serveurs =="
sudo ip netns exec "$NS_A" runuser -u "$USER" -- \
  python3 "$BANC/cible_tls.py" "$PORT_CIBLE" "$BANC/cible.crt" "$BANC/cible.key" \
  >"$BANC/cible.log" 2>&1 &
sleep 1
for duo in "$NS_A a" "$NS_B b"; do
  # shellcheck disable=SC2086
  set -- $duo
  sudo ip netns exec "$1" runuser -u "$USER" -- \
    python3 "$BANC/banniere.py" "$PORT_BANNIERE" "$BANNIERE" >"$BANC/$2-banniere.log" 2>&1 &
  sudo ip netns exec "$1" runuser -u "$USER" -- \
    "$COEURS/sing-box" run -c "$BANC/$2.json" >"$BANC/$2-serveur.log" 2>&1 &
done
sleep 2
sudo ip netns exec "$NS_A" ss -lnt 2>/dev/null | grep -q ":$PORT " \
  || { echo "FAILED: le serveur REALITY n'ecoute pas"; tail -5 "$BANC/a-serveur.log"; exit 1; }
sudo ip netns exec "$NS_B" ss -lnu 2>/dev/null | grep -q ":$PORT " \
  || { echo "FAILED: le serveur Hysteria2 n'ecoute pas"; tail -5 "$BANC/b-serveur.log"; exit 1; }
echo "   A ecoute en TCP, B en UDP, les deux bannieres sont posees"

echo "== 5. profil de la recette, deux transports =="
python3 - "$BANC" "$UUID" "$CLE_PUBLIQUE" "$SHORT_ID" "$SNI_A" "$MDP" "$SNI_B" \
  "$PORT" "$PORT_BANNIERE" "$BANNIERE" <<'PY'
import json
import sys

banc, uuid, pub, sid, sni_a, mdp, sni_b, port, port_b, attendu = sys.argv[1:11]
pem = open(f"{banc}/b.crt").read().splitlines()
profil = {
    "sorties": [
        {
            "type": "vless-reality",
            "tag": "vless-reality-vision",
            "serveur": "10.79.0.1",
            "port": int(port),
            "uuid": uuid,
            "cle_publique": pub,
            "short_id": sid,
            "nom_de_serveur": sni_a,
        },
        {
            "type": "hysteria2",
            "tag": "hysteria2",
            "serveur": "10.79.1.1",
            "port": int(port),
            "mot_de_passe": mdp,
            "nom_de_serveur": sni_b,
            "certificat": pem,
        },
    ],
    "banniere": {
        "hote": "127.0.0.1",
        "port": int(port_b),
        "chemin": "/",
        "attendu": attendu,
    },
}
open(f"{banc}/profil.json", "w").write(json.dumps(profil, indent=2))
PY
chmod 600 "$BANC/profil.json"
echo "   ecrit (porte l'uuid et le mot de passe, mode 0600)"

echo "== 6. la recette, depuis le namespace client =="
set +e
sudo ip netns exec "$NS_C" runuser -u "$USER" -- \
  env HOME="$HOME" "$DAEMON" --coeur-e2e "$BANC/profil.json" --coeurs-dans "$COEURS"
CODE=$?
set -e
echo "== code de sortie de la recette: $CODE =="
exit $CODE
