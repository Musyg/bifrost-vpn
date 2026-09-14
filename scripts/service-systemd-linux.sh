#!/usr/bin/env bash
# Un cycle connect/disconnect COMPLET, par le service systemd installe.
#
# Ce que cette recette ajoute a e2e-linux.sh, qui mesure deja les fuites: le
# daemon n'y est pas un processus lance a la main avec les options du banc,
# c'est l'unite REELLE, avec son durcissement, ses capacites et les drapeaux
# qu'elle porte. Et le resolveur n'est pas une doublure: c'est dnscrypt-proxy,
# qui doit joindre sa source puis negocier avec un serveur chiffre. Le banc lui
# donne donc un vrai acces a Internet, par le serveur WireGuard qu'il monte.
#
# POURQUOI DANS UN NAMESPACE. Armer le kill switch coupe tout trafic qui ne
# passe pas par le tunnel, sans exception pour les connexions etablies: sur une
# machine distante cela inclut la session par laquelle on travaille, et il n'y
# a pas de recette qui rende cela sans danger. Le namespace confine la mesure
# sans l'affaiblir: les regles nftables, les routes et le tunnel y sont les
# memes qu'ailleurs, parce qu'ils sont tous relatifs au namespace reseau.
#
# La SEULE chose que la recette change a l'unite installee est
# `NetworkNamespacePath`. L'isolation de /etc n'y touche pas: elle est posee de
# l'exterieur avec `nsenter`, dans le namespace de montage du daemon. Le faire
# depuis l'unite aurait demande de lui ouvrir l'appel systeme `mount`, donc de
# mesurer une unite qui n'est plus celle qu'on installe.
#
# Usage: sudo ./scripts/service-systemd-linux.sh

set -uo pipefail

DAEMON=/usr/bin/bifrost-daemon
CLI=/usr/bin/bifrost-cli
RESOLVEUR=/usr/lib/bifrost/dnscrypt-proxy
UNITE=bifrost-daemon.service
DROPIN=/etc/systemd/system/bifrost-daemon.service.d/zz-essai-namespace.conf
COMPTE_RESOLVEUR=bifrost-resolveur

NS_SRV=bifrost-svc-server
NS_CLI=bifrost-svc-client
# Deux liens: celui du tunnel, et celui par lequel le serveur atteint Internet.
VETH_S=veth-svcs;  VETH_C=veth-svcc
VETH_H=veth-svch;  VETH_U=veth-svcu
SRV_ADDR=10.97.0.1; CLI_ADDR=10.97.0.2
HOTE_ADDR=10.96.0.1; UPLINK_ADDR=10.96.0.2
WG_PORT=51820
TUN_SRV=10.97.9.1; TUN_CLI=10.97.9.2
NOM_REEL=example.com
TABLE_NAT=bifrost_essai

WORK=$(mktemp -d /tmp/bifrost-svc.XXXXXX)
PROFILE="$WORK/tunnel.toml"
FORWARD_AVANT=""

ECHECS=0
ok()   { printf '  OK    %s\n' "$1"; }
fail() { printf '  ECHEC %s\n' "$1"; ECHECS=$((ECHECS + 1)); }
skip() { printf '  SKIP  %s\n' "$1"; }
step() { printf '\n== %s\n' "$1"; }

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

empreinte_resolv() {
  if [ -L /etc/resolv.conf ]; then
    echo "lien $(readlink /etc/resolv.conf)"
  elif [ -e /etc/resolv.conf ]; then
    echo "fichier $(stat -c %a /etc/resolv.conf) $(sha256sum /etc/resolv.conf | cut -d' ' -f1)"
  else
    echo absent
  fi
}

# `ip netns del` supprime le NOM, pas les processus: ceux qui tournent dedans
# survivent dans un espace devenu anonyme, invisibles a `ip netns list` et
# tenant leurs ports sans fin. Mesure du 21 aout 2026 sur la machine d'essai:
# 468 orphelins accumules par les bancs, le plus vieux depuis 25 h, dont un
# triplet laisse a CHAQUE passage. `ip netns pids` rend exactement les PID de
# cet espace: un kill cible, sans motif de nom.
vider_netns() {
  local p
  for p in $(ip netns pids "$1" 2>/dev/null); do kill "$p" 2>/dev/null; done
  # Laisser le temps de sortir proprement avant de trancher: un SIGKILL au bout
  # d'une seconde fixe fait rapporter "Killed" par le shell pour chaque tache de
  # fond, ce qui salit un passage vert et se lit comme un incident alors que le
  # menage s'est bien passe.
  local i
  for i in 1 2 3 4 5 6 7 8 9 10; do
    [ -z "$(ip netns pids "$1" 2>/dev/null)" ] && return
    sleep 0.5
  done
  for p in $(ip netns pids "$1" 2>/dev/null); do kill -9 "$p" 2>/dev/null; done
}

menage() {
  # GARDER=1 laisse le banc debout pour inspection. Reserve au diagnostic: le
  # service reste alors dans le namespace, et le menage est a faire a la main.
  if [ -n "${GARDER:-}" ]; then
    printf '
banc conserve (GARDER=1). Menage: sudo GARDER= %s --menage
' "$0"
    return
  fi
  # L'ordre compte: arreter le service AVANT de defaire le namespace, sinon
  # l'unite reste accrochee a un chemin qui n'existe plus.
  systemctl stop "$UNITE" >/dev/null 2>&1
  rm -f "$DROPIN"
  rmdir /etc/systemd/system/bifrost-daemon.service.d 2>/dev/null
  systemctl daemon-reload >/dev/null 2>&1
  vider_netns "$NS_CLI"
  vider_netns "$NS_SRV"
  ip netns del "$NS_CLI" 2>/dev/null
  ip netns del "$NS_SRV" 2>/dev/null
  ip link del "$VETH_H" 2>/dev/null
  nft delete table ip "$TABLE_NAT" 2>/dev/null
  # Sans condition, et en boucle. Une execution tuee par SIGPIPE - lire la
  # sortie dans un `head` suffit - mourait sans passer par ici, et le `--menage`
  # d'apres, qui demarre avec le drapeau vide, refusait de retirer ce qu'elle
  # avait laisse. Les regles se sont ainsi accumulees en silence. `-D` ne retire
  # qu'un exemplaire a la fois et rend non nul quand il n'y en a plus.
  for sens in -s -d; do
    n=0
    while [ "$n" -lt 20 ] && iptables -D FORWARD "$sens" 10.96.0.0/24 -j ACCEPT 2>/dev/null; do
      n=$((n + 1))
    done
  done
  [ -n "$FORWARD_AVANT" ] && sysctl -qw net.ipv4.ip_forward="$FORWARD_AVANT"
  rm -rf "$WORK"
}
# EXIT seul ne suffit pas: le shell tue par un signal ne l'atteint jamais.
trap menage EXIT
trap 'exit 143' INT TERM HUP PIPE

[ "$(id -u)" -eq 0 ] || { echo "ce script doit tourner en root"; exit 1; }
if [ "${1:-}" = --menage ]; then GARDER=""; menage; echo "banc demonte"; exit 0; fi
for f in "$DAEMON" "$CLI" "$RESOLVEUR"; do
  [ -x "$f" ] || { echo "SKIPPED: $f absent, lancer packaging/install-linux.sh"; exit 3; }
done
systemctl cat "$UNITE" >/dev/null 2>&1 || { echo "SKIPPED: unite $UNITE absente"; exit 3; }
id "$COMPTE_RESOLVEUR" >/dev/null 2>&1 || { echo "SKIPPED: compte $COMPTE_RESOLVEUR absent"; exit 3; }

RESOLV_MACHINE_AVANT=$(empreinte_resolv)

step "Banc: deux namespaces, et un vrai acces a Internet"
# dnscrypt-proxy doit joindre sa source puis son serveur chiffre. Sans Internet
# il ne demarre pas, et la recette ne mesurerait que la doublure que le banc de
# fuite mesure deja.
vider_netns "$NS_CLI"; vider_netns "$NS_SRV"
ip netns del "$NS_CLI" 2>/dev/null; ip netns del "$NS_SRV" 2>/dev/null
ip link del "$VETH_H" 2>/dev/null
ip netns add "$NS_SRV"; ip netns add "$NS_CLI"
ip link add "$VETH_C" type veth peer name "$VETH_S"
ip link set "$VETH_C" netns "$NS_CLI"; ip link set "$VETH_S" netns "$NS_SRV"
ip link add "$VETH_H" type veth peer name "$VETH_U"
ip link set "$VETH_U" netns "$NS_SRV"
ip addr add "$HOTE_ADDR/24" dev "$VETH_H"; ip link set "$VETH_H" up
for p in "$NS_SRV $VETH_S $SRV_ADDR" "$NS_CLI $VETH_C $CLI_ADDR" "$NS_SRV $VETH_U $UPLINK_ADDR"; do
  set -- $p
  ip -n "$1" link set lo up
  ip -n "$1" addr add "$3/24" dev "$2"
  ip -n "$1" link set "$2" up
done
ip -n "$NS_SRV" route add default via "$HOTE_ADDR"
ip -n "$NS_CLI" route add default via "$SRV_ADDR"

FORWARD_AVANT=$(sysctl -n net.ipv4.ip_forward)
sysctl -qw net.ipv4.ip_forward=1
ip netns exec "$NS_SRV" sysctl -qw net.ipv4.ip_forward=1
# Une table a nous, supprimee en partant: on ne touche a aucune regle existante
# de la machine.
nft delete table ip "$TABLE_NAT" 2>/dev/null
nft add table ip "$TABLE_NAT"
nft add chain ip "$TABLE_NAT" post '{ type nat hook postrouting priority srcnat; }'
nft add rule ip "$TABLE_NAT" post ip saddr 10.96.0.0/24 masquerade
ip netns exec "$NS_SRV" nft add table ip "$TABLE_NAT"
ip netns exec "$NS_SRV" nft add chain ip "$TABLE_NAT" post '{ type nat hook postrouting priority srcnat; }'
ip netns exec "$NS_SRV" nft add rule ip "$TABLE_NAT" post oifname "$VETH_U" masquerade

# Le NAT ne suffit pas: sur une machine qui porte ufw, docker ou tailscale, la
# chaine FORWARD est en `policy drop`. Deux regles, aussi etroites que
# possible, retirees en partant.
iptables -I FORWARD 1 -s 10.96.0.0/24 -j ACCEPT
iptables -I FORWARD 1 -d 10.96.0.0/24 -j ACCEPT

# Et surtout PAS `ping` pour verifier: ufw laisse passer l'ICMP dans sa chaine
# `before-forward` et bloque le reste. Un `ping` reussi ici est un faux
# temoin, mesure le 17/08/2026: il passait alors que rien d'autre ne sortait,
# et le diagnostic a coute une heure. On interroge donc en UDP, le protocole
# dont le resolveur a besoin.
if ip netns exec "$NS_SRV" timeout 8 dig +short +time=3 +tries=2 @9.9.9.9 example.com A 2>/dev/null | grep -qE '^[0-9]+\.'; then
  ok "le serveur du banc resout par UDP: la voie du resolveur existe"
else
  fail "le serveur du banc n'atteint pas Internet en UDP: dnscrypt-proxy ne demarrera pas"
fi

step "Serveur WireGuard"
umask 077
read -r SRV_PRIV SRV_PUB <<<"$("$DAEMON" --genkey)"
read -r CLI_PRIV CLI_PUB <<<"$("$DAEMON" --genkey)"
ip -n "$NS_SRV" link add wgsrv type wireguard
ip netns exec "$NS_SRV" "$DAEMON" --wg-apply "$(cat <<JSON
{"interface":"wgsrv","private_key":"$SRV_PRIV","listen_port":$WG_PORT,
 "peers":[{"public_key":"$CLI_PUB","allowed_ips":["$TUN_CLI/32"]}]}
JSON
)"
ip -n "$NS_SRV" addr add "$TUN_SRV/24" dev wgsrv
ip -n "$NS_SRV" link set wgsrv up
ip netns exec "$NS_SRV" nft add rule ip "$TABLE_NAT" post ip saddr "$TUN_CLI/32" masquerade
ok "serveur en ecoute sur $SRV_ADDR:$WG_PORT, sortie NAT vers Internet"

step "Le service systemd, dans ce namespace"
mkdir -p "$(dirname "$DROPIN")"
cat >"$DROPIN" <<CONF
# Pose par scripts/service-systemd-linux.sh, retire en fin de recette.
# SEULE deviation par rapport a l'unite installee.
[Service]
NetworkNamespacePath=/run/netns/$NS_CLI
CONF
systemctl daemon-reload
systemctl restart "$UNITE"
for _ in $(seq 1 40); do [ -S /run/bifrost/daemon.sock ] && break; sleep 0.25; done
PID_DAEMON=$(systemctl show "$UNITE" -p MainPID --value)
if [ "$(systemctl is-active "$UNITE")" = active ] && [ -S /run/bifrost/daemon.sock ]; then
  ok "unite active (pid $PID_DAEMON), socket ouvert"
else
  fail "l'unite n'a pas demarre"; journalctl -u "$UNITE" -n 20 --no-pager -o cat; exit 1
fi

# Isolation de /etc, posee de l'EXTERIEUR dans le namespace de montage du
# daemon. `ip netns` ne change que le reseau: sans cela le daemon reecrit le
# /etc/resolv.conf de la machine, partage avec tous ses services.
# Le mode de `haut` devient celui du /etc superpose. Le poser explicitement et
# non le laisser a l'umask: l'unite fixe `UMask=0077`, ce qui donne un /etc en
# 0700 root:root, intraversable pour le compte du resolveur. Mesure du
# 17/08/2026: dnscrypt-proxy echouait alors sur
# `open /etc/ssl/certs/ca-certificates.crt: permission denied`. Defaut du banc
# et non du produit, qui lit le /etc de la machine, en 0755.
nsenter -t "$PID_DAEMON" -m -- mount -t tmpfs bifrost-essai /mnt \
  && nsenter -t "$PID_DAEMON" -m -- mkdir -p /mnt/haut /mnt/travail \
  && nsenter -t "$PID_DAEMON" -m -- chmod 755 /mnt /mnt/haut \
  && nsenter -t "$PID_DAEMON" -m -- mount -t overlay bifrost-etc \
       -o lowerdir=/etc,upperdir=/mnt/haut,workdir=/mnt/travail /etc \
  && ok "le /etc du daemon est isole de celui de la machine" \
  || fail "isolation de /etc impossible: la recette toucherait la machine"

step "Profil demandant le resolveur chiffre"
cat >"$PROFILE" <<TOML
interface = "wg0"
private_key = "$CLI_PRIV"
addresses = ["$TUN_CLI/32"]
mtu = 1420

[peer]
public_key = "$SRV_PUB"
endpoint = { addr = "$SRV_ADDR:$WG_PORT" }
allowed_ips = ["0.0.0.0/0", "::/0"]
persistent_keepalive = 5

[dns]
local_resolver = "127.0.0.1"
upstream = ["9.9.9.9"]
embarque = true
TOML
chmod 600 "$PROFILE"
ok "profil ecrit en 600, embarque = true"

step "connect"
if "$CLI" connect --config "$PROFILE"; then
  ok "connect a repondu sans erreur"
else
  fail "connect a echoue"; journalctl -u "$UNITE" -n 30 --no-pager -o cat
fi
ETAT=$("$CLI" status --json)
echo "$ETAT" | grep -q '"state": "connected"' \
  && ok "status: connected" \
  || fail "status n'est pas connected: $(echo "$ETAT" | tr -d '\n ')"
echo "$ETAT" | grep -q '"kill_switch_engaged": true' \
  && ok "kill switch arme" \
  || fail "kill switch non arme"
TX=$(echo "$ETAT" | grep -o '"tx_bytes": [0-9]*' | awk '{print $2}')
[ "${TX:-0}" -gt 0 ] && ok "le tunnel transporte ($TX octets emis)" || fail "le tunnel ne transporte rien"

step "Le VRAI resolveur chiffre tourne, sous son compte"
PID_RESOLVEUR=$(pgrep -f "^$RESOLVEUR " | head -1)
if [ -n "$PID_RESOLVEUR" ]; then
  ok "dnscrypt-proxy en service (pid $PID_RESOLVEUR)"
  UID_ATTENDU=$(id -u "$COMPTE_RESOLVEUR")
  UID_REEL=$(awk '/^Uid:/ {print $3}' "/proc/$PID_RESOLVEUR/status")
  [ "$UID_REEL" = "$UID_ATTENDU" ] \
    && ok "il tourne sous $COMPTE_RESOLVEUR (uid $UID_REEL)" \
    || fail "uid $UID_REEL, attendu $UID_ATTENDU"
  PERE=$(awk '/^PPid:/ {print $2}' "/proc/$PID_RESOLVEUR/status")
  [ "$PERE" = "$PID_DAEMON" ] \
    && ok "il est bien l'enfant du daemon (ppid $PERE)" \
    || fail "ppid $PERE, le daemon est $PID_DAEMON"
else
  fail "aucun dnscrypt-proxy: le profil en demandait un"
fi

step "La machine resout par lui"
RESOLV_NS=$(nsenter -t "$PID_DAEMON" -m -- cat /etc/resolv.conf 2>/dev/null)
echo "$RESOLV_NS" | grep -q '^nameserver 127.0.0.1$' \
  && ok "resolv.conf pointe le resolveur local" \
  || fail "resolv.conf ne pointe pas 127.0.0.1: $(echo "$RESOLV_NS" | grep ^nameserver | tr '\n' ' ')"

# La mesure qui compte: un vrai nom, demande EXPLICITEMENT au resolveur local,
# donc par DoH au bout du tunnel. Le banc de fuite ne peut pas la faire, faute
# d'Internet.
# Pas de `getent`: il suit resolv.conf. Un profil sans resolveur embarque
# resolvait quand meme, en clair par l'amont, et le temoin restait vert.
ADRESSE=$(nsenter -t "$PID_DAEMON" -n -- \
  dig +short +time=3 +tries=1 @127.0.0.1 "$NOM_REEL" A 2>/dev/null \
  | grep -E '^[0-9]+\.' | head -1)
[ -n "$ADRESSE" ] \
  && ok "$NOM_REEL resout en $ADRESSE, par le resolveur local" \
  || fail "$NOM_REEL ne resout pas"

step "Rien ne sort en clair sur le :53"
if command -v tcpdump >/dev/null 2>&1; then
  # A la SORTIE du tunnel, la ou la requete redeviendrait du clair si le
  # resolveur ne la chiffrait pas. Le bootstrap a deja eu lieu au demarrage.
  ip netns exec "$NS_SRV" timeout 12 tcpdump -i "$VETH_U" -n --immediate-mode -c 1 'udp port 53' \
    >"$WORK/clair.txt" 2>"$WORK/clair.err" &
  CHASSE=$!
  sleep 1
  nsenter -t "$PID_DAEMON" -m -n -- getent hosts bifrost-essai-unique.example >/dev/null 2>&1
  nsenter -t "$PID_DAEMON" -m -n -- getent hosts www.wikipedia.org >/dev/null 2>&1
  wait $CHASSE 2>/dev/null
  # Compter les PAQUETS et non les octets du fichier: tcpdump y ecrit aussi des
  # lignes qui n'en sont pas, et `[ -s ]` prenait l'une d'elles pour une fuite.
  # Sans `|| echo 0`: `grep -c` ecrit deja 0 quand il ne trouve rien, et sort
  # en erreur. Les deux ensemble donnaient "0\n0", que `[` refuse de comparer.
  CLAIR=$(grep -c '\.53:' "$WORK/clair.txt" 2>/dev/null)
  CLAIR=${CLAIR:-0}
  # La comparaison des deux etages, restreinte au cas ou elle a un sens.
  #
  # Cette capture porte `-c 1`: des qu'un paquet est pris, tcpdump s'arrete, et
  # le noyau peut en avoir compte d'autres entre-temps. Un ecart y est donc
  # normal QUAND un paquet a ete capture. Il ne l'est pas quand aucun ne l'a
  # ete: zero remis alors que le noyau en a vu passer, c'est une requete DNS en
  # clair que la capture a laissee filer, et le << aucune requete en clair >>
  # ci-dessous serait faux.
  #
  # `fail` et non `skip`: un tcpdump absent se voit avant de mesurer et le
  # `skip` du bas le dit honnetement, alors qu'ici la mesure a eu lieu, a rendu
  # un nombre, et ce nombre servirait de preuve. Le taire serait le blanc-seing
  # que ce controle existe pour refuser.
  ETAGE_VUS=$(compteur_tcpdump "$WORK/clair.err" "received by filter")
  ETAGE_REMIS=$(compteur_tcpdump "$WORK/clair.err" "captured")
  if [ "$CLAIR" -gt 0 ]; then
    fail "une requete DNS est sortie en clair: $(grep '\.53:' "$WORK/clair.txt" | head -1)"
  elif [ -n "$ETAGE_VUS" ] && [ "$ETAGE_VUS" -gt 0 ] && [ "${ETAGE_REMIS:-0}" -eq 0 ]; then
    fail "capture incomplete: $ETAGE_VUS paquet(s) ont passe le filtre du noyau et aucun n'a ete remis, le zero ne prouve rien"
  else
    ok "aucune requete en clair a la sortie du tunnel (${ETAGE_VUS:-?} vus par le filtre, ${ETAGE_REMIS:-?} remis)"
  fi
else
  skip "tcpdump absent"
fi

step "Le /etc/resolv.conf de la machine n'a pas bouge"
# PENDANT que le tunnel est monte, et non apres: une restauration fidele
# rendrait le controle muet s'il n'etait fait qu'a la fin.
[ "$(empreinte_resolv)" = "$RESOLV_MACHINE_AVANT" ] \
  && ok "intact pendant la connexion ($RESOLV_MACHINE_AVANT)" \
  || fail "modifie: $RESOLV_MACHINE_AVANT devenu $(empreinte_resolv)"

step "Les regles posees ferment le :53 a tout le monde sauf lui"
REGLES=$(ip netns exec "$NS_CLI" nft list ruleset 2>/dev/null)
UID_R=$(id -u "$COMPTE_RESOLVEUR")
echo "$REGLES" | grep -qE "meta skuid $UID_R .*dport 53 accept" \
  && ok "l'uid $UID_R garde le droit d'emettre du :53" \
  || fail "aucune exception pour le resolveur dans les regles vivantes"
echo "$REGLES" | grep -qE '^[[:space:]]*udp dport 53 drop' \
  && ok "le :53 tombe pour tous les autres" \
  || fail "le :53 circule librement"

step "disconnect"
if "$CLI" disconnect; then
  ok "disconnect a repondu sans erreur"
else
  fail "disconnect a echoue"
fi
sleep 1
# Sans resolveur au depart, "il s'est arrete" ne prouve rien: le temoin restait
# vert dans le cas meme ou le produit n'en avait jamais lance.
if [ -z "$PID_RESOLVEUR" ]; then
  fail "aucun resolveur n'avait demarre: son arret ne peut pas etre constate"
elif pgrep -f "^$RESOLVEUR " >/dev/null; then
  fail "le resolveur survit a la deconnexion"
else
  ok "le resolveur (pid $PID_RESOLVEUR) s'est arrete avec le tunnel"
fi
ip netns exec "$NS_CLI" nft list tables 2>/dev/null | grep -qi bifrost \
  && fail "des filtres restent en place" \
  || ok "le kill switch est retire"

step "Le service a tenu tout du long"
[ "$(systemctl is-active "$UNITE")" = active ] \
  && ok "unite toujours active" \
  || fail "l'unite n'est plus active"
N=$(systemctl show "$UNITE" -p NRestarts --value)
[ "$N" = 0 ] && ok "aucun redemarrage" || fail "$N redemarrage(s): le daemon est tombe"

echo
if [ "$ECHECS" -eq 0 ]; then
  echo "service systemd, cycle complet: tout est passe"
else
  echo "service systemd, cycle complet: $ECHECS controle(s) en echec"
  exit 1
fi
