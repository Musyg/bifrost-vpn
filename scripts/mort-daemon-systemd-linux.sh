#!/usr/bin/env bash
# Le daemon MEURT: le kill switch tient-il, sous l'unite systemd REELLE?
#
# Ce que cette recette ajoute au vecteur `daemon-mort` de la suite de fuite: le
# processus qui meurt n'y est pas un enfant du harnais, c'est l'unite installee,
# avec son durcissement, ses capacites et surtout SON CYCLE DE VIE - `Restart=`,
# `RestartSec=`, et tout `ExecStop*=` qu'elle porterait. C'est cette moitie-la
# qu'aucun test cargo ne peut atteindre: on ne fait pas rejouer un cycle de
# redemarrage a l'init d'une machine sans toucher a cette machine.
#
# Elle est nee d'un defaut mesure le 23/08/2026. L'unite portait
#   ExecStopPost=-/usr/bin/bifrost-daemon --cleanup-firewall
# sous un commentaire qui annoncait l'invariant que cette ligne cassait.
# `man systemd.service` dit que la directive s'execute sur TOUS les chemins
# d'arret, fin inattendue comprise, et qu'un redemarrage est un arret suivi d'un
# demarrage: chaque plantage demontait le pare-feu, puis laissait la machine nue
# pendant `RestartSec`. Premiere mesure, avant correction: 16 paquets sortants
# en clair sur l'interface physique.
#
# TROIS BRAS, dans cet ordre, sur le MEME montage et avec les MEMES sondes.
# Seul l'etat du daemon change entre eux:
#
#   A. temoin   daemon vivant, deconnecte, aucun filtre   -> doit VOIR en clair
#   B. protege  daemon vivant, connecte, kill switch arme -> doit voir zero
#   C. mort     daemon SIGKILL par PID, kill switch arme  -> la mesure
#
# Sans le bras A, un zero au bras C ne prouverait rien: une capture arretee trop
# tot et une sonde qui n'emet pas rendent le meme pcap vide qu'une etancheite
# parfaite. Sans le bras B, on ne saurait pas que le montage protege quand tout
# va bien.
#
# POURQUOI DANS UN NAMESPACE. Armer le kill switch coupe tout trafic qui ne
# passe pas par le tunnel, sans exception pour les connexions etablies: sur une
# machine distante cela inclut la session par laquelle on travaille. Le
# namespace confine la mesure sans l'affaiblir - regles nftables, routes et
# tunnel y sont tous relatifs au namespace reseau. La SEULE deviation par
# rapport a l'unite installee est `NetworkNamespacePath=`.
#
# Ce banc ne demande AUCUN acces a Internet et ne touche ni au routage de la
# machine, ni a son `ip_forward`, ni a ses regles: deux namespaces et un veth.
#
# Usage: sudo ./scripts/mort-daemon-systemd-linux.sh [etiquette]
# Codes: 0 etanche, 1 fuite mesuree, 3 rien de concluant (temoin muet, ou
#        prerequis absent). Jamais 0 par defaut.

set -uo pipefail

DAEMON=/usr/bin/bifrost-daemon
CLI=/usr/bin/bifrost-cli
UNITE=bifrost-daemon.service
UNITE_FICHIER=/etc/systemd/system/bifrost-daemon.service
DROPIN=/etc/systemd/system/bifrost-daemon.service.d/zz-essai-mort.conf

NS_SRV=bifrost-mort-srv
NS_CLI=bifrost-mort-cli
VETH_S=veth-morts
VETH_C=veth-mortc
SRV_ADDR=10.98.0.1
CLI_ADDR=10.98.0.2
WG_PORT=51820
TUN_SRV=10.98.9.1
TUN_CLI=10.98.9.2

ETIQUETTE="${1:-mesure}"
WORK=$(mktemp -d /tmp/bifrost-mort.XXXXXX)
PROFILE="$WORK/tunnel.toml"

# Ce qui ne compte JAMAIS comme du clair: trafic WireGuard vers l'endpoint,
# multicast, broadcast, DHCP, decouverte de voisins IPv6. Meme liste que
# `capture::allowed()` dans crates/bifrost-daemon/src/checks/capture.rs.
PERMIS="(udp port $WG_PORT and host $SRV_ADDR) or (net 224.0.0.0/4) or (host 255.255.255.255) or (udp port 67 or udp port 68) or (udp port 546 or udp port 547) or (dst net ff00::/8) or (icmp6 and icmp6[icmp6type] >= 133 and icmp6[icmp6type] <= 137)"
FUITE="(ip or ip6) and not ($PERMIS)"
# Les destinations de crates/bifrost-daemon/src/checks/probe.rs.
INTERNET="dst host 8.8.8.8 or dst host 203.0.113.9 or dst host 2001:db8::1"
LAN="dst host $SRV_ADDR and not (udp port $WG_PORT)"

step() { printf '\n== %s\n' "$1"; }
ok()   { printf '  OK    %s\n' "$1"; }
fail() { printf '  ECHEC %s\n' "$1"; }
info() { printf '  .     %s\n' "$1"; }

# `ip netns del` supprime le NOM, pas les processus: ceux qui tournent dedans
# survivent dans un espace devenu anonyme, invisibles a `ip netns list`. On
# recense par `ip netns pids`, qui rend exactement les PID de cet espace, et on
# tue par PID - jamais par motif de nom.
vider_netns() {
  local p i
  for p in $(ip netns pids "$1" 2>/dev/null); do kill "$p" 2>/dev/null; done
  for i in 1 2 3 4 5 6 7 8 9 10; do
    [ -z "$(ip netns pids "$1" 2>/dev/null)" ] && return
    sleep 0.5
  done
  for p in $(ip netns pids "$1" 2>/dev/null); do kill -9 "$p" 2>/dev/null; done
}

menage() {
  systemctl stop "$UNITE" >/dev/null 2>&1
  rm -f "$DROPIN"
  rmdir /etc/systemd/system/bifrost-daemon.service.d 2>/dev/null
  systemctl daemon-reload >/dev/null 2>&1
  systemctl reset-failed "$UNITE" >/dev/null 2>&1
  vider_netns "$NS_CLI"
  vider_netns "$NS_SRV"
  ip netns del "$NS_CLI" 2>/dev/null
  ip netns del "$NS_SRV" 2>/dev/null
  ip link del "$VETH_C" 2>/dev/null
}
# EXIT seul ne suffit pas: le shell tue par un signal ne l'atteint jamais.
trap menage EXIT
trap 'exit 143' INT TERM HUP PIPE

[ "$(id -u)" -eq 0 ] || { echo "ce script doit tourner en root"; exit 1; }
for f in "$DAEMON" "$CLI"; do
  [ -x "$f" ] || { echo "SKIPPED: $f absent, lancer packaging/install-linux.sh"; exit 3; }
done
command -v tcpdump >/dev/null || { echo "SKIPPED: tcpdump absent"; exit 3; }
command -v nc >/dev/null || { echo "SKIPPED: nc absent, la sonde du lien en depend"; exit 3; }
systemctl cat "$UNITE" >/dev/null 2>&1 || { echo "SKIPPED: unite $UNITE absente"; exit 3; }

EMPREINTE_RESOLV_AVANT="$(readlink -f /etc/resolv.conf 2>/dev/null || echo absent)|$(stat -c %Y /etc/resolv.conf 2>/dev/null || echo 0)"

echo "### mesure '$ETIQUETTE' -- $(date -Is)"
echo "### $(systemctl --version | head -1)"
echo "### lignes de cycle de vie de l'unite installee:"
grep -n '^ExecStop\|^Restart=\|^RestartSec\|^OnFailure' "$UNITE_FICHIER" | sed 's/^/###   /'

step "Banc: deux namespaces relies par un veth"
vider_netns "$NS_CLI"; vider_netns "$NS_SRV"
ip netns del "$NS_CLI" 2>/dev/null; ip netns del "$NS_SRV" 2>/dev/null
ip link del "$VETH_C" 2>/dev/null
ip netns add "$NS_SRV" || exit 1
ip netns add "$NS_CLI" || exit 1
ip link add "$VETH_C" type veth peer name "$VETH_S" || exit 1
ip link set "$VETH_C" netns "$NS_CLI"
ip link set "$VETH_S" netns "$NS_SRV"
for p in "$NS_SRV $VETH_S $SRV_ADDR" "$NS_CLI $VETH_C $CLI_ADDR"; do
  set -- $p
  ip -n "$1" link set lo up
  ip -n "$1" addr add "$3/24" dev "$2"
  ip -n "$1" link set "$2" up
done
ip -n "$NS_CLI" route add default via "$SRV_ADDR"
ok "client $CLI_ADDR sur $VETH_C, passerelle $SRV_ADDR sur $VETH_S"

step "Serveur WireGuard dans $NS_SRV"
umask 077
read -r SRV_PRIV SRV_PUB <<<"$("$DAEMON" --genkey)"
read -r CLI_PRIV CLI_PUB <<<"$("$DAEMON" --genkey)"
ip -n "$NS_SRV" link add wgsrv type wireguard
ip netns exec "$NS_SRV" "$DAEMON" --wg-apply "$(cat <<JSON
{"interface":"wgsrv","private_key":"$SRV_PRIV","listen_port":$WG_PORT,
 "peers":[{"public_key":"$CLI_PUB","allowed_ips":["$TUN_CLI/32"]}]}
JSON
)" || { fail "wg-apply cote serveur"; exit 1; }
ip -n "$NS_SRV" addr add "$TUN_SRV/24" dev wgsrv
ip -n "$NS_SRV" link set wgsrv up
ok "serveur en ecoute sur $SRV_ADDR:$WG_PORT"

step "L'unite REELLE, confinee dans $NS_CLI"
mkdir -p "$(dirname "$DROPIN")"
cat >"$DROPIN" <<CONF
# Pose par scripts/mort-daemon-systemd-linux.sh, retire en fin de recette.
# SEULE deviation par rapport a l'unite installee.
[Service]
NetworkNamespacePath=/run/netns/$NS_CLI
CONF
systemctl daemon-reload
systemctl reset-failed "$UNITE" >/dev/null 2>&1
systemctl restart "$UNITE" || { fail "l'unite n'a pas demarre"; journalctl -u "$UNITE" -n 20 --no-pager -o cat; exit 1; }
for _ in $(seq 1 40); do [ -S /run/bifrost/daemon.sock ] && break; sleep 0.25; done
PID_DAEMON=$(systemctl show "$UNITE" -p MainPID --value)
if [ "$(systemctl is-active "$UNITE")" = active ] && [ -S /run/bifrost/daemon.sock ]; then
  ok "unite active (pid $PID_DAEMON), socket ouvert"
else
  fail "unite non active"; journalctl -u "$UNITE" -n 20 --no-pager -o cat; exit 1
fi

# Isolation de /etc, posee de l'EXTERIEUR dans le namespace de MONTAGE du
# daemon. `ip netns` ne change que le reseau: sans cela le daemon reecrirait le
# /etc/resolv.conf de la machine, partage avec tous ses services.
nsenter -t "$PID_DAEMON" -m -- mount -t tmpfs bifrost-essai /mnt \
  && nsenter -t "$PID_DAEMON" -m -- mkdir -p /mnt/haut /mnt/travail \
  && nsenter -t "$PID_DAEMON" -m -- chmod 755 /mnt /mnt/haut \
  && nsenter -t "$PID_DAEMON" -m -- mount -t overlay bifrost-etc \
       -o lowerdir=/etc,upperdir=/mnt/haut,workdir=/mnt/travail /etc \
  && ok "le /etc du daemon est isole de celui de la machine" \
  || { fail "isolation de /etc impossible: la recette toucherait la machine"; exit 1; }

# ---------------------------------------------------------------------------
# Les sondes, identiques aux trois bras.
#
# `--probe all` vise des destinations hors lien, dont la route passe par le
# tunnel des qu'il est monte: elles ne fuient pas en clair meme sans filtres.
# Celle qui DISCRIMINE est celle du lien, refusee par `allow_lan = false` tant
# que le kill switch tient, et qui repart en clair des qu'il tombe.
# ---------------------------------------------------------------------------
sonder() {
  ip netns exec "$NS_CLI" "$DAEMON" --probe all >/dev/null 2>&1
  ip netns exec "$NS_CLI" "$DAEMON" --probe-lan "$SRV_ADDR" >/dev/null 2>&1
}

TPID=""
TLOG=""
capture_debut() {
  local nom="$1" i
  PCAP="$WORK/$nom.pcap"
  TLOG="$WORK/$nom.tcpdump"
  rm -f "$PCAP"
  ip netns exec "$NS_SRV" tcpdump -i "$VETH_S" -nn --immediate-mode -U -s 128 -w "$PCAP" \
    >"$TLOG" 2>&1 &
  TPID=$!
  # Attendre la PREUVE que tcpdump vit: l'en-tete pcap fait 24 octets. Un
  # simple `sleep` supposerait un demarrage rapide, et un pcap ouvert trop tard
  # se lirait comme une absence de fuite.
  for i in $(seq 1 100); do
    if [ -e "$PCAP" ] && [ "$(stat -c %s "$PCAP" 2>/dev/null || echo 0)" -ge 24 ]; then
      sleep 0.5
      return 0
    fi
    sleep 0.05
  done
  fail "tcpdump ne s'est pas attache pour $nom"
  return 1
}

capture_fin() {
  sleep 0.8
  kill -TERM "$TPID" 2>/dev/null
  wait "$TPID" 2>/dev/null
  TPID=""
}

compter() {
  if [ -z "${2:-}" ]; then
    tcpdump -r "$1" -nn 2>/dev/null | grep -c . || true
  else
    tcpdump -r "$1" -nn "$2" 2>/dev/null | grep -c . || true
  fi
}

rendre() {
  local nom="$1" pcap="$2" t i l sortant tot vus remis ecart
  t=$(compter "$pcap" "$FUITE")
  sortant=$(compter "$pcap" "($FUITE) and src host $CLI_ADDR")
  i=$(compter "$pcap" "($FUITE) and ($INTERNET)")
  l=$(compter "$pcap" "($FUITE) and ($LAN)")
  tot=$(compter "$pcap" "")
  vus=$(compteur_tcpdump "$TLOG" "received by filter")
  remis=$(compteur_tcpdump "$TLOG" "captured")
  ecart=$(ecart_capture "$TLOG")
  printf '  >> %-12s clair=%-5s sortant=%-5s internet=%-5s lan=%-5s (captures: %s)\n' \
    "$nom" "$t" "$sortant" "$i" "$l" "$tot"
  if [ "$t" -gt 0 ]; then
    tcpdump -r "$pcap" -nn -c 6 "$FUITE" 2>/dev/null | sed 's/^/       | /'
  fi
  echo "$t" >"$WORK/$nom.compte"
  printf '     %-12s deux etages: vus=%s remis=%s ecart=%s\n' \
    "$nom" "${vus:-?}" "${remis:-?}" "$ecart"
  echo "$ecart" >"$WORK/$nom.ecart"
}

# L'ECART ENTRE LES DEUX ETAGES DE LA CAPTURE.
#
# En sortant, tcpdump ecrit trois compteurs sur son erreur standard, deja
# rediriges ici vers "$WORK/<nom>.tcpdump". Ils ne mesurent pas la meme chose:
# `received by filter` vient du noyau, qui compte a l'ENTREE de l'anneau sans
# savoir si l'application lira un jour; `captured` est le compteur interne de
# tcpdump, incremente une fois par paquet effectivement ECRIT. Leur difference
# est donc exactement ce que le noyau a accepte et que personne n'a jamais lu.
#
# Sans cette lecture, un bras qui rend zero ne distingue pas << rien n'est
# sorti >> de << ce qui est sorti n'a pas ete capture >>. Mesure du 23/08/2026
# sur la suite de fuite: cinq captures sur vingt-trois perdaient des paquets,
# dont une a 1 vu par le filtre et 0 remis, et le vecteur concluait quand meme
# a l'etancheite. `--immediate-mode` supprime la cause; ceci est ce qui le dit
# le jour ou le drapeau saute.
compteur_tcpdump() {
  awk -v e="$2" 'index($0, e) && $0 ~ /^[0-9]+ packet/ { n = $1 } END { print n }' \
    "$1" 2>/dev/null
}

ecart_capture() {
  local log="$1" vus remis
  [ -r "$log" ] || { echo ILLISIBLE; return; }
  vus=$(compteur_tcpdump "$log" "received by filter")
  remis=$(compteur_tcpdump "$log" "captured")
  # Un tcpdump acheve par SIGKILL n'imprime aucun compteur: `cleanup()` ne
  # tourne que sur le chemin normal de sortie. Rendre zero ferait passer une
  # capture jamais lue pour une capture vide.
  [ -n "$vus" ] && [ -n "$remis" ] || { echo ILLISIBLE; return; }
  echo "$((vus - remis))"
}

step "BRAS A -- temoin: daemon vivant, deconnecte, aucun filtre"
info "filtres dans $NS_CLI: [$(ip netns exec "$NS_CLI" nft list tables 2>/dev/null | tr '\n' ' ')]"
capture_debut temoin && { sonder; capture_fin; rendre "A-temoin" "$PCAP"; }

step "Profil et connexion"
cat >"$PROFILE" <<TOML
interface = "wg0"
private_key = "$CLI_PRIV"
addresses = ["$TUN_CLI/32"]
mtu = 1420
allow_lan = false

[peer]
public_key = "$SRV_PUB"
endpoint = { addr = "$SRV_ADDR:$WG_PORT" }
allowed_ips = ["0.0.0.0/0", "::/0"]
persistent_keepalive = 5

[dns]
local_resolver = "127.0.0.1"
upstream = ["$TUN_SRV"]
TOML
chmod 600 "$PROFILE"
if "$CLI" connect --config "$PROFILE"; then
  ok "connect a repondu sans erreur"
else
  fail "connect a echoue"; journalctl -u "$UNITE" -n 40 --no-pager -o cat; exit 1
fi
ETAT=$("$CLI" status --json)
echo "$ETAT" | grep -q '"state": "connected"' && ok "status: connected" || fail "status: $(echo "$ETAT" | tr -d '\n ')"
echo "$ETAT" | grep -q '"kill_switch_engaged": true' && ok "kill switch arme" || fail "kill switch NON arme"
TX=$(echo "$ETAT" | grep -o '"tx_bytes": [0-9]*' | awk '{print $2}')
if [ "${TX:-0}" -gt 0 ]; then ok "le tunnel transporte ($TX octets emis)"; else info "tx_bytes=${TX:-0}"; fi

step "BRAS B -- protege: daemon vivant, connecte, kill switch arme"
capture_debut protege && { sonder; capture_fin; rendre "B-protege" "$PCAP"; }

step "BRAS C -- la mesure: SIGKILL du daemon, par PID"
PID_DAEMON=$(systemctl show "$UNITE" -p MainPID --value)
info "MainPID=$PID_DAEMON, NRestarts avant=$(systemctl show "$UNITE" -p NRestarts --value)"
if capture_debut mort; then
  kill -9 "$PID_DAEMON"
  # Sonder pendant TOUTE la fenetre: la mort, ce que systemd execute apres, le
  # `RestartSec`, et le retour du daemon.
  for i in 1 2 3 4 5 6 7 8; do
    sonder
    [ "$i" = 2 ] && ip netns exec "$NS_CLI" nft list tables 2>/dev/null | tr '\n' ' ' >"$WORK/filtres-apres-mort"
    sleep 0.4
  done
  capture_fin
  rendre "C-mort" "$PCAP"
fi
info "filtres ~1 s apres la mort: [$(cat "$WORK/filtres-apres-mort" 2>/dev/null)]"
info "filtres a la fin du bras C : [$(ip netns exec "$NS_CLI" nft list tables 2>/dev/null | tr '\n' ' ')]"
info "NRestarts apres=$(systemctl show "$UNITE" -p NRestarts --value), etat=$(systemctl is-active "$UNITE")"

step "Journal de l'unite, fenetre de la mort"
journalctl -u "$UNITE" -n 20 --no-pager -o short-iso | sed 's/^/  | /'

step "Le /etc/resolv.conf de la machine n'a pas bouge"
EMPREINTE_RESOLV_APRES="$(readlink -f /etc/resolv.conf 2>/dev/null || echo absent)|$(stat -c %Y /etc/resolv.conf 2>/dev/null || echo 0)"
if [ "$EMPREINTE_RESOLV_AVANT" = "$EMPREINTE_RESOLV_APRES" ]; then
  ok "intact ($EMPREINTE_RESOLV_APRES)"
else
  fail "modifie: $EMPREINTE_RESOLV_AVANT devenu $EMPREINTE_RESOLV_APRES"
fi

step "Verdict"
A=$(cat "$WORK/A-temoin.compte" 2>/dev/null || echo 0)
B=$(cat "$WORK/B-protege.compte" 2>/dev/null || echo 0)
C=$(cat "$WORK/C-mort.compte" 2>/dev/null || echo 0)
echo "  A temoin (sans filtre)   : $A paquet(s) en clair"
echo "  B protege (daemon vivant): $B paquet(s) en clair"
echo "  C daemon tue             : $C paquet(s) en clair"
for f in "$WORK"/*.pcap; do
  [ -e "$f" ] && cp "$f" "/tmp/bifrost-mort-$ETIQUETTE-$(basename "$f")" 2>/dev/null
done
echo "  pcap conserves: /tmp/bifrost-mort-$ETIQUETTE-*.pcap"

# Les trois bras concluent sur des pcap, et un pcap incomplet rend un zero qui
# ne se distingue pas d'une etancheite. On refuse donc de conclure, exactement
# comme pour un temoin muet, et avec le meme code de sortie.
EA=$(cat "$WORK/A-temoin.ecart" 2>/dev/null || echo ILLISIBLE)
EB=$(cat "$WORK/B-protege.ecart" 2>/dev/null || echo ILLISIBLE)
EC=$(cat "$WORK/C-mort.ecart" 2>/dev/null || echo ILLISIBLE)
echo "  ecart des deux etages    : A=$EA B=$EB C=$EC"
for e in "$EA" "$EB" "$EC"; do
  if [ "$e" != 0 ]; then
    echo "  INDECIS: une capture est incomplete (ecart=$e). Des paquets ont passe le"
    echo "           filtre du noyau sans etre remis a tcpdump, ou tcpdump n'a pas"
    echo "           rendu ses compteurs. Un zero tire de ce pcap ne prouverait rien."
    echo "           Verifier que --immediate-mode est bien pose sur la capture."
    exit 3
  fi
done
if [ "${A:-0}" -eq 0 ]; then
  echo "  INDECIS: le temoin n'a rien vu. La mesure ne prouve rien."
  exit 3
fi
if [ "${B:-0}" -gt 0 ]; then
  echo "  INDECIS: le montage fuit deja daemon VIVANT. Reparer cela d'abord."
  exit 3
fi
if [ "${C:-0}" -gt 0 ]; then
  echo "  FUITE MESUREE: la mort du daemon a ouvert $C paquet(s) en clair."
  exit 1
fi
echo "  ETANCHE: la mort du daemon n'a produit aucun paquet en clair."
