#!/bin/sh
# Le PAIR du banc de service Windows: un serveur WireGuard avec un VRAI acces a
# Internet, monte sur essai-linux et joignable depuis le LAN.
#
# # Pourquoi ce script existe separement
#
# `service-systemd-linux.sh` monte son serveur dans un namespace, sur la meme
# machine que le client. Le pendant Windows ne le peut pas: son client est une
# AUTRE machine. Le serveur vit donc dans le namespace racine d'essai-linux, et
# la moitie Linux du banc tient dans ce fichier.
#
# # Pourquoi un vrai acces a Internet, et pas seulement un pair qui repond
#
# Le pair d'`exit-ip` n'a ni NAT ni routage, et c'etait justifie: ce vecteur
# n'exige pas que les sondes publiques aboutissent. Ici si. dnscrypt-proxy doit
# joindre sa source puis son serveur chiffre; sans Internet il ne demarre pas,
# et le banc ne mesurerait plus rien du resolveur - c'est-a-dire plus rien de ce
# qu'il est venu mesurer.
#
# # Ce qui est touche sur la machine, et comment c'est rendu
#
# Une table nft A NOUS, supprimee en partant: aucune regle existante n'est
# modifiee, et les chaines que Docker gere ne sont pas relues. Deux regles
# FORWARD, retirees une par une en boucle - `-D` n'en retire qu'un exemplaire
# et une execution tuee par un signal en laisse s'accumuler en silence.
# `ip_forward` est releve avant et remis apres.
#
# L'interface `wgsvc` et sa cle privee n'existent qu'en memoire noyau: pas de
# `/etc/wireguard`, pas de `wg-quick` activee. Un redemarrage les emporte, ce
# qui est voulu, mais se voit alors comme une absence de poignee de main cote
# Windows. Le banc client le dit nommement plutot que d'accuser le produit.
#
# # Usage
#
#   sudo ./service-windows-pair.sh            # monte, ecrit le profil client
#   sudo ./service-windows-pair.sh --menage   # rend la machine
#
# Le profil client porte une cle privee: il est ecrit en 600 sous $ATELIER et
# n'est jamais affiche.

set -eu

DAEMON=${DAEMON:-/usr/bin/bifrost-daemon}
ATELIER=${ATELIER:-/root/bifrost-service-windows}
IFACE=wgsvc
WG_PORT=51820
RESEAU=10.98.0.0/24
SRV_ADDR=10.98.0.1
CLI_ADDR=10.98.0.2
BANNIERE_PORT=7100
BANNIERE=BIFROST-SERVICE-OK
TABLE_NAT=bifrost_service_win
PROFIL="$ATELIER/profil-client.toml"
PID_BANNIERE="$ATELIER/banniere.pid"

ECHECS=0
ok()   { echo "  ok    $1"; }
fail() { echo "  ECHEC $1"; ECHECS=$((ECHECS + 1)); }
step() { echo; echo "== $1"; }

[ "$(id -u)" -eq 0 ] || { echo "ce script doit tourner en root"; exit 1; }

menage() {
  # La banniere d'abord, et PAR SON PID: `pkill` sur un motif de nom a deja
  # coupe des services voisins sur cette flotte. Supprimer l'interface ne tue
  # pas le processus qui ecoutait dessus - un `nohup` survit a sa session, et
  # une note de ce depot a affirme le contraire pendant deux jours.
  if [ -f "$PID_BANNIERE" ]; then
    kill "$(cat "$PID_BANNIERE")" 2>/dev/null || true
    rm -f "$PID_BANNIERE"
  fi
  ip link del "$IFACE" 2>/dev/null || true
  nft delete table ip "$TABLE_NAT" 2>/dev/null || true
  for sens in -s -d; do
    n=0
    while [ "$n" -lt 20 ] && iptables -D FORWARD "$sens" "$RESEAU" -j ACCEPT 2>/dev/null; do
      n=$((n + 1))
    done
  done
  n=0
  while [ "$n" -lt 20 ] &&
    iptables -D INPUT -s "$RESEAU" -p tcp --dport "$BANNIERE_PORT" -j ACCEPT 2>/dev/null; do
    n=$((n + 1))
  done
  if [ -n "${FORWARD_AVANT:-}" ]; then
    sysctl -qw net.ipv4.ip_forward="$FORWARD_AVANT"
  fi
  return 0
}

if [ "${1:-}" = --menage ]; then
  FORWARD_AVANT=""
  menage
  # Le controle qui manquait a la note du 18/08/2026: l'ecouteur se verifie par
  # ce qui ECOUTE, jamais en deduisant son sort du demontage de l'interface.
  if ss -lntp 2>/dev/null | grep -q ":$BANNIERE_PORT "; then
    echo "ECHEC: quelque chose ecoute encore sur :$BANNIERE_PORT"
    exit 1
  fi
  if ip link show "$IFACE" >/dev/null 2>&1; then
    echo "ECHEC: $IFACE est toujours la"
    exit 1
  fi
  echo "pair demonte: interface, banniere, NAT et regles FORWARD retires"
  exit 0
fi

[ -x "$DAEMON" ] || { echo "SKIPPED: $DAEMON absent"; exit 3; }
command -v nft >/dev/null 2>&1 || { echo "SKIPPED: nft absent"; exit 3; }
command -v python3 >/dev/null 2>&1 || { echo "SKIPPED: python3 absent"; exit 3; }

umask 077
mkdir -p "$ATELIER"
FORWARD_AVANT=$(sysctl -n net.ipv4.ip_forward)
menage

step "Le pair a-t-il lui-meme Internet"
# En UDP et surtout PAS en `ping`: ufw laisse passer l'ICMP dans sa chaine
# `before-forward` et bloque le reste. Un ping reussi ici serait un faux temoin,
# mesure le 17/08/2026 et paye d'une heure de diagnostic. On interroge dans le
# protocole dont le resolveur a besoin.
if timeout 8 dig +short +time=3 +tries=2 @9.9.9.9 example.com A 2>/dev/null | grep -qE '^[0-9]+\.'; then
  ok "la machine resout par UDP: la voie du resolveur existe"
else
  fail "la machine n'atteint pas Internet en UDP: dnscrypt-proxy ne demarrera pas"
fi

step "Serveur WireGuard sur $IFACE"
SRV=$("$DAEMON" --genkey)
CLI=$("$DAEMON" --genkey)
SRV_PRIV=$(echo "$SRV" | awk '{print $1}')
SRV_PUB=$(echo "$SRV" | awk '{print $2}')
CLI_PRIV=$(echo "$CLI" | awk '{print $1}')
CLI_PUB=$(echo "$CLI" | awk '{print $2}')
ip link add "$IFACE" type wireguard
"$DAEMON" --wg-apply "{\"interface\":\"$IFACE\",\"private_key\":\"$SRV_PRIV\",\"listen_port\":$WG_PORT,\"peers\":[{\"public_key\":\"$CLI_PUB\",\"allowed_ips\":[\"$CLI_ADDR/32\"]}]}"
ip addr add "$SRV_ADDR/24" dev "$IFACE"
ip link set "$IFACE" up
ok "en ecoute sur :$WG_PORT, pair $CLI_ADDR"

step "NAT vers Internet"
sysctl -qw net.ipv4.ip_forward=1
nft add table ip "$TABLE_NAT"
nft add chain ip "$TABLE_NAT" post '{ type nat hook postrouting priority srcnat; }'
nft add rule ip "$TABLE_NAT" post ip saddr "$RESEAU" masquerade
# Le NAT ne suffit pas: sur une machine qui porte ufw, docker ou tailscale, la
# chaine FORWARD est en `policy drop`.
iptables -I FORWARD 1 -s "$RESEAU" -j ACCEPT
iptables -I FORWARD 1 -d "$RESEAU" -j ACCEPT
# Et INPUT non plus. Mesure du 22/08/2026: le premier passage du banc client a
# resolu un vrai nom a travers le tunnel - donc le NAT et le routage
# marchaient - tout en ne lisant jamais la banniere. Elle est servie par la
# machine ELLE-MEME, pas routee au travers: elle releve d'INPUT, que ufw tient
# en `policy drop`. Ce que le FORWARD ouvre ne dit rien de ce qui s'adresse a
# l'hote.
iptables -I INPUT 1 -s "$RESEAU" -p tcp --dport "$BANNIERE_PORT" -j ACCEPT
ok "table $TABLE_NAT, deux regles FORWARD et une INPUT, toutes retirees au --menage"

step "Banniere joignable par le seul tunnel"
# Elle porte une adresse qui n'existe que chez ce pair. Aucune route ne mene la
# depuis le LAN: ce qu'elle repond dit que le trafic est reellement sorti par le
# tunnel. Le banc client verifie qu'elle est MUETTE avant de monter quoi que ce
# soit, sans quoi sa reponse ne dirait rien du chemin emprunte.
#
# Pourquoi une banniere plutot que les compteurs du tunnel: un endpoint MORT
# fait monter `tx_bytes`, ce sont ses tentatives de poignee de main. La lecon
# est datee - `exit-ip` sous Linux concluait au transport sur des paquets
# chiffres - et elle vaut ici aussi.
cat >"$ATELIER/banniere.py" <<'PY'
import socketserver
import sys

ADRESSE = sys.argv[1]
PORT = int(sys.argv[2])
CORPS = (sys.argv[3] + "\n").encode()


class Poignee(socketserver.StreamRequestHandler):
    timeout = 5

    def handle(self):
        try:
            self.rfile.readline()
        except Exception:
            return
        self.wfile.write(
            b"HTTP/1.0 200 OK\r\nContent-Length: %d\r\n\r\n%s" % (len(CORPS), CORPS)
        )


class Serveur(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


Serveur((ADRESSE, PORT), Poignee).serve_forever()
PY
setsid nohup python3 "$ATELIER/banniere.py" "$SRV_ADDR" "$BANNIERE_PORT" "$BANNIERE" \
  >"$ATELIER/banniere.log" 2>&1 &
echo $! >"$PID_BANNIERE"
n=0
while [ "$n" -lt 20 ] && ! ss -lntp 2>/dev/null | grep -q ":$BANNIERE_PORT "; do
  n=$((n + 1))
  sleep 0.25
done
if ss -lntp 2>/dev/null | grep -q ":$BANNIERE_PORT "; then
  ok "'$BANNIERE' servie sur $SRV_ADDR:$BANNIERE_PORT (pid $(cat "$PID_BANNIERE"))"
else
  fail "la banniere n'ecoute pas: le banc client n'aurait aucun temoin de transport"
  cat "$ATELIER/banniere.log" 2>/dev/null
fi

step "Profil client"
# L'adresse du LAN, et jamais celle de Tailscale: le banc client arme un kill
# switch qui coupe tout ce qui ne passe pas par le tunnel, et un endpoint
# joignable par un autre VPN se couperait lui-meme.
LAN=$(ip -4 -o addr show scope global | awk '{print $4}' | cut -d/ -f1 | grep -v '^100\.' | head -1)
if [ -z "$LAN" ]; then
  fail "aucune adresse LAN trouvee pour l'endpoint"
  LAN=0.0.0.0
fi
cat >"$PROFIL" <<TOML
# Profil du banc de service Windows. Cle privee de test, jetable, engendree a
# chaque montage du pair. Ne pas versionner.
interface = "bifrost-svc"
private_key = "$CLI_PRIV"
addresses = ["$CLI_ADDR/32"]
mtu = 1420
allow_lan = false

[peer]
public_key = "$SRV_PUB"
endpoint = { addr = "$LAN:$WG_PORT" }
allowed_ips = ["0.0.0.0/0"]
persistent_keepalive = 15

[dns]
local_resolver = "127.0.0.1"
upstream = ["9.9.9.9"]
embarque = true
TOML
chmod 600 "$PROFIL"
ok "profil en 600 dans $PROFIL: endpoint $LAN:$WG_PORT, route par defaut, embarque = true"

echo
echo "banniere: $BANNIERE sur $SRV_ADDR:$BANNIERE_PORT"
if [ "$ECHECS" -eq 0 ]; then
  echo "pair monte: tout est passe"
else
  echo "pair monte: $ECHECS controle(s) en echec"
  exit 1
fi
