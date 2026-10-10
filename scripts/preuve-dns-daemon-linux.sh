#!/usr/bin/env bash
# Banc jetable de `prove dns --politique-daemon`: le VRAI daemon pose son plan
# DNS (connect, tunnel WireGuard reel, kill switch) et la preuve compare le
# resolveur effectif au plan que le daemon DECLARE avoir pose (commande IPC
# `declaration-dns`). Cadre de preuve-dns-linux.sh: un systemd-resolved reel,
# sur un bus D-Bus PRIVE, dans un namespace de montage prive et des namespaces
# reseau jetables; lancement du daemon de e2e-linux.sh: /etc et /var/lib
# superposes. Ni le resolved de l'hote, ni son bus systeme, ni son
# /etc/resolv.conf ne sont lus ou touches: le banc prouve qu'il a joint le bus
# prive AVANT de lancer resolved, le daemon ou la moindre commande `resolvectl`.
# Adresses de documentation seulement (RFC 5737 et RFC 3849).
#
# Pourquoi un script a part, hors de l'integration continue: il lui faut un
# daemon root qui monte un vrai tunnel WireGuard et arme son kill switch, le
# cadre de e2e-linux.sh, que l'integration continue n'execute pas (voir la
# raison dans .github/workflows/ci.yml). preuve-dns-linux.sh, lui, ne lance
# aucun daemon.
#
# Deux namespaces reseau, crees ici sous des noms exacts et retires ici par ces
# noms: P (le poste: bus prive, resolved prive, le daemon, la preuve) et S (le
# serveur WireGuard). Une paire veth creee DANS P.
#
# Ce que le banc mesure:
# - daemon 1, lance apres le resolved prive: son gestionnaire en service est
#   systemd-resolved. Aucun plan declare avant connect et apres disconnect, dit
#   sans rien comparer; MATCH sans puis avec resolveur embarque; chaque
#   categorie d'ecart de ce backend, provoquee sous le daemon, donne cet ecart
#   et lui seul, et le daemon declare, a l'octet pres, la meme chose avant et
#   apres chaque cas;
# - daemon 2, lance dans un namespace de montage ou le stub de resolved
#   n'existe pas: son gestionnaire est resolv.conf. MATCH sans puis avec
#   resolveur embarque, resolv-conf-content et hosts-sources;
# - un plan qui change pendant la collecte (connect et disconnect en boucle)
#   rend UNMEASURED, jamais MATCH ni MISMATCH sur un plan change;
# - un serveur non root sur un --socket choisi: refus d'identite, sans une
#   requete recue; une declaration hors schema servie par root: refus de la
#   declaration; le rejeu exact sous root: MATCH (temoin, et limite de la
#   regle d'identite);
# - le rapport ne porte ni adresse, ni interface, ni compte, ni chemin, ni rien
#   de la declaration.
#
# Usage: sudo bash scripts/preuve-dns-daemon-linux.sh [chemin/vers/target/debug]
#   Exige root (namespaces), `cargo build -p bifrost-daemon -p bifrost-cli`,
#   le module noyau wireguard (charge a la creation de la premiere interface),
#   puis ip, jq, setpriv, unshare, nsenter, findmnt, dbus-daemon, busctl,
#   resolvectl, ss, ping, python3 et /usr/lib/systemd/systemd-resolved.
#   BIFROST_BANC_JOURNAL=<repertoire existant>: y copie rapports, declarations,
#   journaux et la liste des processus lances (`pids.txt`: pid, date de
#   demarrage, namespace reseau).
set -euo pipefail
unset DBUS_SYSTEM_BUS_ADDRESS DBUS_SESSION_BUS_ADDRESS NOTIFY_SOCKET WATCHDOG_PID WATCHDOG_USEC

TUN=wg0
PHY=bp0
PAIR=rs0
WGSRV=wgsrv
# Le lien physique: bp0 dans P, rs0 dans S; son serveur DNS est celui qu'un
# DHCP aurait pousse, et S y tient l'endpoint du tunnel.
PHY_P=198.51.100.1
PHY_S=198.51.100.2
DHCP=198.51.100.53
PORT_WG=51820
# Le tunnel: wg0 dans P, wgsrv dans S; ses serveurs sont l'amont du plan.
TUN_P=192.0.2.2
TUN_S=192.0.2.1
AMONT=192.0.2.53
AMONT6=2001:db8::53
LOCAL=127.0.0.1
REPONSE=192.0.2.99
# Comptes: la preuve tourne sous `nobody`; le resolveur embarque factice, que
# le daemon lance, sous un compte numerique que le rapport ne doit jamais dire.
U_PREUVE=65534
U_RESOLVEUR=4243
RESOLVED=/usr/lib/systemd/systemd-resolved
CHEMIN_PATH=/usr/sbin:/usr/bin:/sbin:/bin
AUCUN="aucun plan DNS pose par ce daemon: rien a comparer"
MODIFIEE="declaration du daemon modifiee pendant la collecte"

# --- commun ------------------------------------------------------------------

passe() {
  echo "PASSED: $*" | tee -a "$BAC/passes.txt"
}

temoin() {
  echo "$*" | tee -a "$BAC/temoins.txt"
}

refus() {
  echo "ARRET AVANT ECRITURE: $*" >&2
  exit 3
}

# La date de demarrage d'un processus (champ 22 de /proc/<pid>/stat), lue
# apres le nom, qui peut contenir des blancs. Vide si le processus n'existe
# pas.
debut_de() {
  sed 's/^.*) //' "/proc/$1/stat" 2> /dev/null | awk '{print $20}'
}

# `noter <pid> <inode du namespace reseau>`: chaque processus lance est releve
# avec sa date de demarrage et le namespace ou il doit tourner, pour etre tue
# par son PID, et seulement si c'est encore lui: un PID recycle par un
# processus de l'hote n'est jamais vise. L'inode est donne, pas lu: un
# processus qui vient d'etre lance n'est peut-etre pas encore entre dans son
# namespace.
noter() {
  local debut
  debut=$(debut_de "$1")
  if [ -z "$debut" ]; then debut=mort; fi
  echo "$1 $debut $2" >> "$BAC/pids.txt"
  PIDS+=("$1:$debut:$2")
}

# `vivant <pid> <debut> <inode>`: le meme processus vit, dans ce namespace. Un
# zombie n'a plus de namespace: il compte pour mort.
vivant() {
  [ "$(debut_de "$1")" = "$2" ] && [ "$(stat -L -c %i "/proc/$1/ns/net" 2> /dev/null)" = "$3" ]
}

tuer_releves() {
  local e p d n
  for e in "${PIDS[@]}"; do
    IFS=: read -r p d n <<< "$e"
    if vivant "$p" "$d" "$n"; then kill "$p" 2> /dev/null || true; fi
  done
  for e in "${PIDS[@]}"; do
    IFS=: read -r p d n <<< "$e"
    for _ in $(seq 1 50); do
      if ! vivant "$p" "$d" "$n"; then break; fi
      sleep 0.1
    done
    if vivant "$p" "$d" "$n"; then kill -KILL "$p" 2> /dev/null || true; fi
  done
  PIDS=()
}

# Mort ou zombie: un enfant que personne n'a encore recolte garde son /proc.
mort() {
  [ ! -e "/proc/$1" ] || grep -q '^State:[[:space:]]*Z' "/proc/$1/status" 2> /dev/null
}

DBUS_PERMISSIF='<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>system</type>
  <listen>unix:path=/run/dbus/system_bus_socket</listen>
  <auth>EXTERNAL</auth>
  <policy context="default">
    <allow user="*"/>
    <allow own="*"/>
    <allow send_destination="*"/>
    <allow receive_sender="*"/>
    <allow send_type="method_call"/>
    <allow send_type="signal"/>
    <allow receive_type="method_call"/>
    <allow receive_type="method_return"/>
    <allow receive_type="error"/>
    <allow receive_type="signal"/>
  </policy>
</busconfig>'

# La declaration DNS brute du daemon, lue en root, telle que le daemon l'ecrit:
# le temoin de ce que le daemon dit avoir pose, a cote de la preuve.
LIRE_PY='
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(10)
s.connect(sys.argv[1])
s.sendall(b"{\"version\":1,\"command\":\"declaration-dns\"}\n")
d = b""
while not d.endswith(b"\n"):
    b = s.recv(65536)
    if not b:
        break
    d += b
sys.stdout.buffer.write(d)
'

# Un faux daemon sur un --socket choisi: sert la meme reponse a chaque
# requete et compte les requetes recues, une ligne chacune.
FAUX_PY='
import os, socket, sys
chemin, reponse, journal, pret = sys.argv[1], open(sys.argv[2], "rb").read(), sys.argv[3], sys.argv[4]
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(chemin)
os.chmod(chemin, 0o666)
s.listen(8)
open(pret, "w").close()
while True:
    c, _ = s.accept()
    if c.makefile("rb").readline():
        with open(journal, "a") as j:
            j.write("requete\n")
        c.sendall(reponse)
    c.close()
'

# --- dans P, namespace de montage prive ----------------------------------------

# `bus_prive <configuration>`: un dbus-daemon sur le tmpfs de /run/dbus du
# namespace de montage courant, sans repertoire de services (aucune
# activation). Refuse si le socket n'est pas sur ce tmpfs.
bus_prive() {
  [ -z "$(ls -A /run/dbus)" ] || refus "/run/dbus n'est pas vide avant le bus prive"
  dbus-daemon --config-file="$1" --nofork --nopidfile > "$BAC/dbus.log" 2>&1 &
  noter $! "$NS_P"
  for _ in $(seq 1 50); do
    if [ -S /run/dbus/system_bus_socket ]; then break; fi
    sleep 0.1
  done
  [ -S /run/dbus/system_bus_socket ] || refus "socket du bus prive absent"
  [ "$(stat -c %d /run/dbus/system_bus_socket)" = "$(stat -c %d /run/dbus)" ] ||
    refus "le socket du bus n'est pas sur le tmpfs du banc"
  [ "$(stat -c %d /run/dbus/system_bus_socket)" != "$HOTE_DEV_BUS" ] ||
    refus "le socket du bus est sur le peripherique de celui de l'hote"
  [ "$(readlink -f /var/run/dbus/system_bus_socket)" = /run/dbus/system_bus_socket ] ||
    refus "l'adresse du bus systeme ne mene pas au socket du banc"
}

# LLMNR permis globalement, pour que `multicast-resolution` se provoque par
# lien; coupe sur le lien physique des le depart. wg0 n'a pas IFF_MULTICAST:
# resolved n'y ouvre jamais de portee LLMNR.
resolved_conf() {
  printf '[Resolve]\nDNS=\nDomains=\nLLMNR=yes\nMulticastDNS=no\nDNSSEC=no\nDNSOverTLS=no\nFallbackDNS=\nDNSStubListener=yes\n' \
    > "$BAC/resolved.conf"
}

nsswitch() {
  printf 'passwd: files\ngroup: files\nshadow: files\nhosts: %s\n' "$1" > "$BAC/nsswitch.conf"
}

demarrer_resolved() {
  env -i PATH="$CHEMIN_PATH" SYSTEMD_LOG_LEVEL=info SYSTEMD_LOG_TARGET=console "$RESOLVED" >> "$BAC/resolved.log" 2>&1 &
  noter $! "$NS_P"
  for _ in $(seq 1 100); do
    if busctl --system list --no-legend 2> /dev/null | awk '{print $1}' | grep -x org.freedesktop.resolve1 > /dev/null; then
      break
    fi
    sleep 0.1
  done
  busctl --system list --no-legend | awk '{print $1}' | grep -x org.freedesktop.resolve1 > /dev/null ||
    refus "resolved prive n'a pas pris son nom"
  for _ in $(seq 1 50); do
    if awk 'NR > 1 && $2 == "3500007F:0035"' /proc/net/udp | grep . > /dev/null; then break; fi
    sleep 0.1
  done
}

masque() {
  local i o
  i=$(cat "/sys/class/net/$1/ifindex")
  o=$(busctl --system call org.freedesktop.resolve1 /org/freedesktop/resolve1 \
    org.freedesktop.resolve1.Manager GetLink i "$i" | awk '{print $2}' | tr -d '"')
  busctl --system get-property org.freedesktop.resolve1 "$o" org.freedesktop.resolve1.Link ScopesMask |
    awk '{print $2}'
}

# `attendre_masque <lien> <bits requis> <bits interdits>`.
attendre_masque() {
  local m=0
  for _ in $(seq 1 100); do
    m=$(masque "$1")
    if [ $((m & $2)) = "$2" ] && [ $((m & $3)) = 0 ]; then return 0; fi
    sleep 0.1
  done
  echo "portees de $1 jamais atteintes: $m" >&2
  return 1
}

# `muet <nom>`: le rapport ne porte rien de la declaration ni aucun
# identifiant du banc. Les horodatages sont des nombres quelconques: hors de la
# recherche.
muet() {
  jq -e 'has("application") or has("instance") or has("plan") or has("issue") | not' "$BAC/$1.json" > /dev/null
  if jq 'del(.started_at_unix_ms, .completed_at_unix_ms, .duration_ms)' "$BAC/$1.json" |
    grep -E '192\.0\.2|198\.51\.100|2001:db8|127\.0\.0|wg0|wgsrv|bp0|rs0|bfdnsd|banc|\.test|4243|65534|\.sock' > /dev/null; then
    echo "$1: le rapport exporte un identifiant du banc" >&2
    return 1
  fi
}

# `prouver <nom> <socket> [prefixe...]`: la preuve par declaration, sans
# privilege et sans environnement, dans le namespace courant (ou sous le
# prefixe donne).
prouver() {
  local nom=$1 socket=$2
  shift 2
  CODE=0
  "$@" env -i PATH="$CHEMIN_PATH" setpriv --reuid="$U_PREUVE" --regid="$U_PREUVE" --clear-groups \
    "$CLI" --json --socket "$socket" prove dns --politique-daemon --actif > "$BAC/$nom.json" || CODE=$?
  muet "$nom"
}

# `declaration <socket> <fichier>`.
declaration() {
  python3 -I -c "$LIRE_PY" "$1" > "$2"
  jq -e '.result == "declaration-dns" and .schema_version == 1' "$2" > /dev/null
}

# `attendre_issue <socket> <issue> <fichier>`.
attendre_issue() {
  for _ in $(seq 1 40); do
    declaration "$1" "$3"
    if jq -e --arg i "$2" '.issue == $i' "$3" > /dev/null; then return 0; fi
    sleep 0.25
  done
  echo "le daemon ne declare pas l'issue $2" >&2
  cat "$3" >&2
  return 1
}

# L'etat du resolveur, en une empreinte: le resolved prive par le bus, et les
# fichiers du namespace de montage courant (ou de celui du prefixe).
etat() {
  {
    resolvectl status --no-pager 2>&1 || true
    resolvectl dns 2>&1 || true
    resolvectl domain 2>&1 || true
    "$@" stat -c '%F %d %i' /etc/resolv.conf 2>&1 || true
    "$@" sha256sum /etc/resolv.conf 2>&1 || true
    sha256sum /etc/nsswitch.conf 2>&1 || true
  } | sha256sum
}

# `prouver_cas <nom> <socket> <declaration de reference> [prefixe...]`: une
# preuve qui ne change rien a l'etat du resolveur, apres laquelle le daemon
# declare toujours, a l'octet pres, la declaration de reference: il n'a ni
# repose ni retire son plan pendant le cas.
prouver_cas() {
  local nom=$1 socket=$2 reference=$3 avant apres
  shift 3
  avant=$(etat "$@")
  prouver "$nom" "$socket" "$@"
  apres=$(etat "$@")
  if [ "$avant" != "$apres" ]; then
    echo "$nom: l'etat du resolveur a change pendant la preuve" >&2
    return 1
  fi
  declaration "$socket" "$BAC/$nom-declaration.json"
  if ! cmp -s "$reference" "$BAC/$nom-declaration.json"; then
    echo "$nom: le daemon a change sa declaration pendant le cas" >&2
    return 1
  fi
}

# `attendre <nom> <code> <verdict> <ecarts en JSON>`: le verdict, et
# exactement ces categories d'ecart, dans cet ordre, l'attendu venant du daemon.
attendre() {
  if [ "$CODE" != "$2" ] || ! jq -e --arg v "$3" --argjson d "$4" \
    '.verdict == $v and .differences == $d and .live_system and .collection_verified
     and .schema_version == 1 and .scope == "linux-dns-comparison"
     and .expected_source == "daemon-declared-active-dns-plan"
     and .daemon_identity == "root-peer-credentials" and .intention_schema_version == null
     and .network_security == "not-evaluated" and .failed_input == null' \
    "$BAC/$1.json" > /dev/null; then
    echo "$1: attendu $3 $4 (code $2), rendu code $CODE" >&2
    cat "$BAC/$1.json" >&2
    return 1
  fi
  passe "$1 -> $3 $4"
}

# `ecart <nom> <socket> <reference> <ecarts en JSON> [prefixe...]` et
# `retour <nom> <socket> <reference> [prefixe...]`.
ecart() {
  prouver_cas "$1" "$2" "$3" "${@:5}"
  attendre "$1" 1 MISMATCH "$4"
}

retour() {
  prouver_cas "$1" "$2" "$3" "${@:4}"
  attendre "$1" 0 MATCH '[]'
}

# `rien_de_pose <nom>`: le daemon a repondu, son identite est admise, et il ne
# declare aucun plan: la preuve le dit sans rien lire ni comparer.
rien_de_pose() {
  if [ "$CODE" != 2 ] || ! jq -e --arg r "$AUCUN" \
    '.verdict == "UNMEASURED" and .reason == $r and .differences == []
     and .expected_source == "daemon-declared-active-dns-plan"
     and .daemon_identity == "root-peer-credentials" and .failed_input == "daemon-declaration"
     and (.live_system | not) and (.collection_verified | not)
     and .backend == null and .source == null
     and .expected_counts == null and .observed_counts == null' "$BAC/$1.json" > /dev/null; then
    echo "$1: attendu UNMEASURED ($AUCUN), rendu code $CODE" >&2
    cat "$BAC/$1.json" >&2
    return 1
  fi
  passe "$1 -> UNMEASURED, aucun plan declare, rien compare"
}

# `lancer_daemon <nom> [prefixe...]`: le vrai daemon, root, sans
# environnement, dans le namespace reseau courant et sous le prefixe donne.
# `unshare` sans --fork, `sh -c exec` et `env` font exec: le PID releve EST le
# daemon, ce que /proc confirme. Tout ce qu'il ecrit hors de /etc et /var/lib
# (superposes) est redirige sous le bac.
lancer_daemon() {
  local nom=$1
  shift
  SOCK="$BAC/$nom-ipc/d.sock"
  "$@" env -i PATH="$CHEMIN_PATH" "$DAEMON" --socket "$SOCK" --group "$GROUPE" \
    --coeurs-configurations "$BAC/$nom/coeurs" --journal-routage "$BAC/$nom/routage" \
    --resolveur-utilisateur "$U_RESOLVEUR:$U_RESOLVEUR" --resolveur-binaire "$FAUX_DNSCRYPT" \
    --resolveur-configuration "$BAC/$nom/resolveur/dnscrypt-proxy.toml" \
    --resolveur-etat "$BAC/$nom/resolveur-etat" > "$BAC/$nom.log" 2>&1 &
  PID_D=$!
  noter "$PID_D" "$NS_P"
  for _ in $(seq 1 40); do
    if [ -S "$SOCK" ]; then break; fi
    kill -0 "$PID_D"
    sleep 0.25
  done
  if [ ! -S "$SOCK" ]; then
    cat "$BAC/$nom.log" >&2
    return 1
  fi
  if [ "$(readlink "/proc/$PID_D/exe")" != "$DAEMON" ]; then
    echo "le PID $PID_D n'est pas celui du daemon" >&2
    return 1
  fi
  SOCKETS=("$SOCK")
}

arreter_daemon() {
  kill "$1"
  for _ in $(seq 1 100); do
    if mort "$1"; then break; fi
    sleep 0.1
  done
  mort "$1" || { echo "le daemon $1 ne s'arrete pas" >&2; return 1; }
  wait "$1" 2> /dev/null || true
  SOCKETS=()
}

# Le handshake est declenche par du trafic: le banc envoie un ping par le
# tunnel jusqu'a ce que le daemon se dise connecte, kill switch arme.
attendre_connecte() {
  local s=""
  for _ in $(seq 1 30); do
    ping -c1 -W1 "$TUN_S" > /dev/null 2>&1 || true
    s=$("$CLI" --json --socket "$1" status)
    if jq -e '.state.state == "connected" and .kill_switch_engaged' <<< "$s" > /dev/null; then return 0; fi
    sleep 0.25
  done
  echo "le tunnel ne se connecte pas" >&2
  echo "$s" >&2
  return 1
}

# `connecter <socket> <profil>`.
connecter() {
  "$CLI" --socket "$1" connect --config "$2" > /dev/null
  attendre_connecte "$1"
}

# Le resolveur embarque que le daemon <pid> a lance: l'ecoute de LOCAL:53,
# sous le compte declare, enfant du daemon.
resolveur_de() {
  local p
  p=$(ss -Hlunp 'sport = :53' | grep -F "$LOCAL:53" | sed -n 's/.*pid=\([0-9]*\).*/\1/p' | sed -n 1p || true)
  if [ -z "$p" ]; then
    echo "aucune ecoute sur le resolveur local" >&2
    return 1
  fi
  if [ "$(awk '$1 == "Uid:" {print $2}' "/proc/$p/status")" != "$U_RESOLVEUR" ] ||
    [ "$(awk '$1 == "PPid:" {print $2}' "/proc/$p/status")" != "$1" ]; then
    echo "l'ecoute du resolveur local n'est pas l'enfant du daemon, sous le compte declare" >&2
    return 1
  fi
  echo "$p"
}

# `faux_daemon <nom> <reponse> [prefixe...]`: un faux daemon sous le prefixe
# (vide: root; setpriv: un compte ordinaire), sur un --socket choisi; la preuve
# le joint, puis il est tue par son PID. REQUETES: ce qu'il a recu.
faux_daemon() {
  local nom=$1 reponse=$2 pid
  shift 2
  rm -f "$FAUX" "$BAC/faux/requetes" "$BAC/faux/pret"
  "$@" python3 -I -c "$FAUX_PY" "$FAUX" "$reponse" "$BAC/faux/requetes" "$BAC/faux/pret" > /dev/null 2>&1 &
  pid=$!
  noter "$pid" "$NS_P"
  for _ in $(seq 1 50); do
    if [ -e "$BAC/faux/pret" ]; then break; fi
    sleep 0.1
  done
  [ -e "$BAC/faux/pret" ]
  prouver "$nom" "$FAUX"
  kill "$pid"
  wait "$pid" 2> /dev/null || true
  REQUETES=0
  if [ -f "$BAC/faux/requetes" ]; then REQUETES=$(grep -c . "$BAC/faux/requetes" || true); fi
}

menage_daemons() {
  local s
  for s in "${SOCKETS[@]}"; do
    if [ -S "$s" ]; then timeout 10 "$CLI" --socket "$s" disconnect > /dev/null 2>&1 || true; fi
  done
}

arret_interieur() {
  local code=$?
  menage_daemons
  tuer_releves
  exit "$code"
}

interieur() {
  PIDS=()
  SOCKETS=()
  trap arret_interieur EXIT
  NS_P=$(stat -L -c %i /proc/self/ns/net)
  echo "== isolation du montage =="
  [ "$(findmnt -n -o PROPAGATION /)" = private ] || refus "montage non prive"
  mkdir "$BAC/etc-haut" "$BAC/etc-travail" "$BAC/varlib-haut" "$BAC/varlib-travail"
  mount -t overlay bfdnsd-etc -o "lowerdir=/etc,upperdir=$BAC/etc-haut,workdir=$BAC/etc-travail" /etc ||
    refus "/etc superpose"
  mount -t overlay bfdnsd-varlib -o "lowerdir=/var/lib,upperdir=$BAC/varlib-haut,workdir=$BAC/varlib-travail" /var/lib ||
    refus "/var/lib superpose"
  mount -t tmpfs -o mode=0755 bfdnsd-dbus /run/dbus || refus "tmpfs /run/dbus"
  mount -t tmpfs -o "mode=0755,uid=$(id -u systemd-resolve),gid=$(id -g systemd-resolve)" \
    bfdnsd-resolve /run/systemd/resolve || refus "tmpfs /run/systemd/resolve"
  [ -z "$(ls -A /run/systemd/resolve)" ] || refus "/run/systemd/resolve n'est pas vide"
  # Ni la configuration de l'hote, ni l'etat de ses liens selon networkd (ses
  # numeros d'interface croiseraient ceux du banc).
  local d
  for d in /etc/systemd/resolved.conf.d /run/systemd/resolved.conf.d \
    /usr/local/lib/systemd/resolved.conf.d /usr/lib/systemd/resolved.conf.d /run/systemd/netif; do
    if [ -d "$d" ]; then mount -t tmpfs -o mode=0755 bfdnsd-masque "$d"; fi
  done
  resolved_conf
  nsswitch "files dns"
  chmod 644 "$BAC/resolved.conf" "$BAC/nsswitch.conf"
  mount --bind "$BAC/resolved.conf" /etc/systemd/resolved.conf || refus "resolved.conf prive"
  mount --bind "$BAC/nsswitch.conf" /etc/nsswitch.conf || refus "nsswitch.conf prive"

  echo "== bus prive =="
  bus_prive "$BAC/dbus-permissif.conf"
  if busctl --system list --no-legend | awk '{print $1}' | grep -x org.freedesktop.resolve1 > /dev/null; then
    refus "resolve1 deja present sur le bus joint"
  fi
  if awk 'NR > 1 && $2 == "3500007F:0035"' /proc/net/udp | grep . > /dev/null; then
    refus "un stub ecoute deja dans ce namespace"
  fi
  echo "bus prive prouve: socket sur le tmpfs du banc, resolve1 absent, aucun stub"

  echo "== resolved prive =="
  demarrer_resolved
  temoin "version: $("$RESOLVED" --version | sed -n 1p)"
  resolvectl dns "$PHY" "$DHCP"
  resolvectl llmnr "$PHY" no
  attendre_masque "$PHY" 1 6

  echo "== daemon 1: gestionnaire systemd-resolved =="
  lancer_daemon d1
  local s1=$SOCK p1=$PID_D
  declaration "$s1" "$BAC/d1-neuf.json"
  jq -e '.issue == "aucun" and .application == 0 and .plan == null' "$BAC/d1-neuf.json" > /dev/null
  prouver d1-rien-avant "$s1"
  rien_de_pose d1-rien-avant

  echo "== profil A: plan pose, sans resolveur embarque =="
  connecter "$s1" "$BAC/profil-a.toml"
  attendre_issue "$s1" pose "$BAC/d1-a.json"
  jq -e --arg t "$TUN" --arg a "$AMONT" --arg b "$AMONT6" --arg l "$LOCAL" \
    '.application == 1 and .plan.backend == "systemd-resolved" and .plan.interface == $t
     and .plan.local_resolver == $l and .plan.upstream == [$a, $b]
     and (.plan.embarque | not) and .plan.resolveur_uid == null' "$BAC/d1-a.json" > /dev/null
  temoin "d1: declare pose par systemd-resolved, application 1, sans resolveur embarque"
  retour d1-pose-a "$s1" "$BAC/d1-a.json"
  jq -e '.backend == "systemd-resolved" and .source == "resolved-dbus-and-system-files-read-twice"
    and .expected_counts.servers == 2 and .expected_counts.tunnel_domains == 1
    and .observed_counts.tunnel_servers == 2 and .observed_counts.tunnel_domains == 1
    and .observed_counts.llmnr_links == 0 and .observed_counts.resolv_conf_mode == "stub"
    and .observed_counts.local_resolver_listeners == null' "$BAC/d1-pose-a.json" > /dev/null

  echo "== qui sert la declaration: identite du serveur, schema de la reponse =="
  cp "$BAC/d1-a.json" "$BAC/faux/exacte.json"
  jq -c '.schema_version = 2' "$BAC/d1-a.json" > "$BAC/faux/version.json"
  jq -c --arg b "2001:DB8::53" '.plan.upstream[1] = $b' "$BAC/d1-a.json" > "$BAC/faux/graphie.json"
  chmod 644 "$BAC"/faux/*.json
  faux_daemon faux-exacte "$BAC/faux/exacte.json"
  attendre faux-exacte 0 MATCH '[]'
  [ "$REQUETES" = 2 ] || { echo "faux-exacte: $REQUETES requetes, attendu 2" >&2; exit 1; }
  passe "faux-exacte -> le rejeu exact sous root est admis, N1 et N2 lus (limite de la regle d'identite)"
  faux_daemon faux-non-root "$BAC/faux/exacte.json" setpriv --reuid="$U_PREUVE" --regid="$U_PREUVE" --clear-groups
  if [ "$CODE" != 2 ] || [ "$REQUETES" != 0 ] || ! jq -e '.verdict == "UNMEASURED"
    and .reason == "serveur de la declaration non privilegie" and .failed_input == "daemon-identity"
    and .daemon_identity == null and (.live_system | not) and .backend == null' "$BAC/faux-non-root.json" > /dev/null; then
    echo "faux-non-root: attendu UNMEASURED (daemon-identity) sans requete" >&2
    cat "$BAC/faux-non-root.json" >&2
    exit 1
  fi
  passe "faux-non-root -> UNMEASURED (daemon-identity), aucune requete recue"
  local v
  for v in version graphie; do
    faux_daemon "faux-$v" "$BAC/faux/$v.json"
    if [ "$CODE" != 2 ] || [ "$REQUETES" != 1 ] || ! jq -e '.verdict == "UNMEASURED"
      and .reason == "declaration du daemon hors schema" and .failed_input == "daemon-declaration"
      and (.live_system | not) and .backend == null and .observed_counts == null' "$BAC/faux-$v.json" > /dev/null; then
      echo "faux-$v: attendu UNMEASURED (declaration hors schema) apres une requete" >&2
      cat "$BAC/faux-$v.json" >&2
      exit 1
    fi
    passe "faux-$v -> UNMEASURED (declaration hors schema), une requete recue"
  done

  echo "== resolv-conf-path =="
  mount --bind /run/systemd/resolve/resolv.conf /etc/resolv.conf
  ecart d1-chemin "$s1" "$BAC/d1-a.json" '["resolv-conf-path"]'
  jq -e '.observed_counts.resolv_conf_mode == "uplink"' "$BAC/d1-chemin.json" > /dev/null
  umount /etc/resolv.conf
  retour d1-retour-chemin "$s1" "$BAC/d1-a.json"

  echo "== hosts-sources =="
  nsswitch "files ldap dns"
  ecart d1-sources "$s1" "$BAC/d1-a.json" '["hosts-sources"]'
  nsswitch "files dns"
  retour d1-retour-sources "$s1" "$BAC/d1-a.json"

  echo "== tunnel-link-servers =="
  resolvectl dns "$TUN" "$AMONT6" "$AMONT"
  ecart d1-serveurs "$s1" "$BAC/d1-a.json" '["tunnel-link-servers"]'
  resolvectl dns "$TUN" "$AMONT" "$AMONT6"
  retour d1-retour-serveurs "$s1" "$BAC/d1-a.json"

  echo "== tunnel-link-domains =="
  resolvectl domain "$TUN" '~.' '~banc.test'
  ecart d1-domaines "$s1" "$BAC/d1-a.json" '["tunnel-link-domains"]'
  resolvectl domain "$TUN" '~.'
  retour d1-retour-domaines "$s1" "$BAC/d1-a.json"

  echo "== dns-exceptions =="
  resolvectl domain "$PHY" '~banc.test'
  ecart d1-exception "$s1" "$BAC/d1-a.json" '["dns-exceptions"]'
  resolvectl domain "$PHY" ''
  retour d1-retour-exception "$s1" "$BAC/d1-a.json"

  echo "== competing-default-routes =="
  resolvectl domain "$PHY" '~.'
  ecart d1-concurrente "$s1" "$BAC/d1-a.json" '["competing-default-routes"]'
  resolvectl domain "$PHY" ''
  retour d1-retour-concurrente "$s1" "$BAC/d1-a.json"

  echo "== multicast-resolution =="
  resolvectl llmnr "$PHY" yes
  attendre_masque "$PHY" 2 0
  ecart d1-llmnr "$s1" "$BAC/d1-a.json" '["multicast-resolution"]'
  resolvectl llmnr "$PHY" no
  attendre_masque "$PHY" 1 6
  retour d1-retour-llmnr "$s1" "$BAC/d1-a.json"

  echo "== tunnel-link-scope =="
  ip link set "$TUN" down
  attendre_masque "$TUN" 0 1
  ecart d1-tunnel-eteint "$s1" "$BAC/d1-a.json" '["tunnel-link-scope"]'
  ip link set "$TUN" up
  attendre_masque "$TUN" 1 0
  retour d1-tunnel-rallume "$s1" "$BAC/d1-a.json"

  echo "== disconnect: plan oublie =="
  "$CLI" --socket "$s1" disconnect > /dev/null
  declaration "$s1" "$BAC/d1-apres-a.json"
  jq -e '.issue == "aucun" and .application == 2 and .plan == null' "$BAC/d1-apres-a.json" > /dev/null
  prouver d1-rien-apres-a "$s1"
  rien_de_pose d1-rien-apres-a

  echo "== N1 et N2 differentes: le plan change pendant la collecte =="
  : > "$BAC/course.log"
  bash "$BAC/banc.sh" --course "$s1" > "$BAC/course.log" 2>&1 &
  local course=$!
  noter "$course" "$NS_P"
  # Quarante preuves pendant la boucle, sans s'arreter au premier cas vise:
  # chacune doit tomber dans l'une des quatre issues admises.
  local modifiees=0 instables=0 posees=0 aucuns=0 essais=0
  for _ in $(seq 1 40); do
    essais=$((essais + 1))
    prouver course "$s1"
    if [ "$CODE" = 2 ] && jq -e --arg r "$MODIFIEE" '.verdict == "UNMEASURED" and .reason == $r
      and .failed_input == "daemon-declaration" and .live_system and .collection_verified
      and .differences == [] and .observed_counts == null' "$BAC/course.json" > /dev/null; then
      modifiees=$((modifiees + 1))
      cp "$BAC/course.json" "$BAC/course-modifiee.json"
    elif [ "$CODE" = 2 ] && jq -e '.verdict == "UNMEASURED" and (.reason | startswith("collecte instable"))
      and .differences == [] and .observed_counts == null' "$BAC/course.json" > /dev/null; then
      instables=$((instables + 1))
    elif [ "$CODE" = 2 ] && jq -e --arg r "$AUCUN" '.verdict == "UNMEASURED" and .reason == $r' \
      "$BAC/course.json" > /dev/null; then
      aucuns=$((aucuns + 1))
    elif [ "$CODE" = 0 ] && jq -e '.verdict == "MATCH" and .collection_verified' "$BAC/course.json" > /dev/null; then
      posees=$((posees + 1))
    else
      echo "course: ni plan stable, ni plan absent, ni plan change pendant la collecte" >&2
      cat "$BAC/course.json" >&2
      exit 1
    fi
  done
  touch "$BAC/course-fin"
  wait "$course"
  temoin "course: $modifiees declarations modifiees pendant la collecte, $instables collectes instables, $posees MATCH sur plan stable, $aucuns sans plan, sur $essais preuves"
  [ "$modifiees" -ge 1 ]
  passe "course -> UNMEASURED quand la declaration change pendant la collecte, jamais MISMATCH"
  declaration "$s1" "$BAC/d1-apres-course.json"
  jq -e '.issue == "aucun" and .plan == null' "$BAC/d1-apres-course.json" > /dev/null
  prouver d1-rien-apres-course "$s1"
  rien_de_pose d1-rien-apres-course

  echo "== profil B: plan pose avec resolveur embarque =="
  connecter "$s1" "$BAC/profil-b.toml"
  attendre_issue "$s1" pose "$BAC/d1-b.json"
  jq -e --arg a "$AMONT" --argjson u "$U_RESOLVEUR" \
    '.plan.backend == "systemd-resolved" and .plan.embarque and .plan.resolveur_uid == $u
     and .plan.upstream == [$a]' "$BAC/d1-b.json" > /dev/null
  local res
  res=$(resolveur_de "$p1")
  temoin "d1: resolveur embarque lance par le daemon et declare sous le meme compte"
  retour d1-pose-b "$s1" "$BAC/d1-b.json"
  jq -e '.observed_counts.local_resolver_listeners == 1 and .observed_counts.tunnel_servers == 1
    and .expected_counts.servers == 1' "$BAC/d1-pose-b.json" > /dev/null

  echo "== local-resolver-listener =="
  kill "$res"
  for _ in $(seq 1 50); do
    if ! ss -Hlun 'sport = :53' | grep -F "$LOCAL:53" > /dev/null; then break; fi
    sleep 0.1
  done
  ecart d1-sans-ecoute "$s1" "$BAC/d1-b.json" '["local-resolver-listener"]'
  "$CLI" --socket "$s1" disconnect > /dev/null
  declaration "$s1" "$BAC/d1-apres-b.json"
  jq -e '.issue == "aucun" and .plan == null' "$BAC/d1-apres-b.json" > /dev/null
  prouver d1-rien-apres-b "$s1"
  rien_de_pose d1-rien-apres-b
  arreter_daemon "$p1"

  echo "== daemon 2: gestionnaire resolv.conf (stub de resolved absent de son montage) =="
  # shellcheck disable=SC2016
  lancer_daemon d2 unshare -m --propagation private sh -c \
    'mount -t tmpfs -o mode=0755 bfdnsd-sans-stub /run/systemd/resolve && exec "$@"' sh
  local s2=$SOCK p2=$PID_D
  local dans2=(nsenter -t "$p2" -m --)
  "${dans2[@]}" test ! -e /run/systemd/resolve/stub-resolv.conf
  local lien_avant
  lien_avant=$("${dans2[@]}" stat -c '%F %N' /etc/resolv.conf)
  declaration "$s2" "$BAC/d2-neuf.json"
  jq -e '.issue == "aucun" and .application == 0 and .plan == null' "$BAC/d2-neuf.json" > /dev/null
  prouver d2-rien-avant "$s2" "${dans2[@]}"
  rien_de_pose d2-rien-avant

  connecter "$s2" "$BAC/profil-a.toml"
  attendre_issue "$s2" pose "$BAC/d2-a.json"
  jq -e '.application == 1 and .plan.backend == "resolv.conf" and (.plan.embarque | not)' "$BAC/d2-a.json" > /dev/null
  "${dans2[@]}" grep -q 'genere par bifrost' /etc/resolv.conf
  temoin "d2: declare pose par resolv.conf, application 1; le fichier du namespace du daemon porte sa marque"
  retour d2-pose-a "$s2" "$BAC/d2-a.json" "${dans2[@]}"
  jq -e '.backend == "resolv-conf" and .source == "resolv-conf-and-system-files-read-twice"
    and .expected_counts.servers == 2 and .observed_counts.links == null' "$BAC/d2-pose-a.json" > /dev/null

  echo "== resolv-conf-content =="
  printf 'nameserver %s\nnameserver %s\n' "$DHCP" "$AMONT" > "$BAC/resolv-altere.conf"
  chmod 644 "$BAC/resolv-altere.conf"
  "${dans2[@]}" mount --bind "$BAC/resolv-altere.conf" /etc/resolv.conf
  ecart d2-contenu "$s2" "$BAC/d2-a.json" '["resolv-conf-content"]' "${dans2[@]}"
  "${dans2[@]}" umount /etc/resolv.conf
  retour d2-retour-contenu "$s2" "$BAC/d2-a.json" "${dans2[@]}"

  echo "== hosts-sources (resolv.conf) =="
  nsswitch "files resolve [!UNAVAIL=return] dns"
  ecart d2-sources "$s2" "$BAC/d2-a.json" '["hosts-sources"]' "${dans2[@]}"
  nsswitch "files dns"
  retour d2-retour-sources "$s2" "$BAC/d2-a.json" "${dans2[@]}"

  "$CLI" --socket "$s2" disconnect > /dev/null
  declaration "$s2" "$BAC/d2-apres-a.json"
  jq -e '.issue == "aucun" and .application == 2 and .plan == null' "$BAC/d2-apres-a.json" > /dev/null
  [ "$("${dans2[@]}" stat -c '%F %N' /etc/resolv.conf)" = "$lien_avant" ]
  temoin "d2: apres disconnect, /etc/resolv.conf du namespace du daemon rendu a sa forme d'origine"
  prouver d2-rien-apres-a "$s2" "${dans2[@]}"
  rien_de_pose d2-rien-apres-a

  connecter "$s2" "$BAC/profil-b.toml"
  attendre_issue "$s2" pose "$BAC/d2-b.json"
  jq -e --argjson u "$U_RESOLVEUR" '.plan.backend == "resolv.conf" and .plan.embarque
    and .plan.resolveur_uid == $u' "$BAC/d2-b.json" > /dev/null
  resolveur_de "$p2" > /dev/null
  "${dans2[@]}" grep -qx "nameserver $LOCAL" /etc/resolv.conf
  retour d2-pose-b "$s2" "$BAC/d2-b.json" "${dans2[@]}"
  jq -e '.observed_counts.local_resolver_listeners == 1' "$BAC/d2-pose-b.json" > /dev/null
  "$CLI" --socket "$s2" disconnect > /dev/null
  declaration "$s2" "$BAC/d2-apres-b.json"
  jq -e '.issue == "aucun" and .plan == null' "$BAC/d2-apres-b.json" > /dev/null
  prouver d2-rien-apres-b "$s2" "${dans2[@]}"
  rien_de_pose d2-rien-apres-b
  arreter_daemon "$p2"
}

# --- connect et disconnect en boucle, contre le daemon 1 -----------------------

course() {
  while [ ! -e "$BAC/course-fin" ]; do
    "$CLI" --socket "$1" connect --config "$BAC/profil-a.toml" > /dev/null
    "$CLI" --socket "$1" disconnect > /dev/null
  done
}

# --- dans le namespace de l'hote: namespaces reseau, serveur, retrait ----------

ecrire_outils() {
  printf '%s\n' "$DBUS_PERMISSIF" > "$BAC/dbus-permissif.conf"
  chmod 644 "$BAC/dbus-permissif.conf"
  printf '#!/bin/sh\n# Doublure de dnscrypt-proxy, ecrite par preuve-dns-daemon-linux.sh: le daemon\n# la lance comme le vrai, sous le compte du resolveur; elle ignore ses\n# arguments et sert le :53 de la boucle locale en repondant elle-meme.\nexec %s --faux-resolveur %s:53 --faux-resolveur-adresse %s\n' \
    "$DAEMON" "$LOCAL" "$REPONSE" > "$FAUX_DNSCRYPT"
  chmod 755 "$FAUX_DNSCRYPT"
  mkdir -m 755 "$BAC/faux"
  chown "$U_PREUVE:$GROUPE" "$BAC/faux"
  FAUX="$BAC/faux/d.sock"
}

# `profil <fichier> <amonts TOML> <embarque>`.
profil() {
  printf 'interface = "%s"\nprivate_key = "%s"\naddresses = ["%s/32"]\nmtu = 1420\n\n[peer]\npublic_key = "%s"\nendpoint = { addr = "%s:%s" }\nallowed_ips = ["0.0.0.0/0", "::/0"]\npersistent_keepalive = 5\n\n[dns]\nlocal_resolver = "%s"\nupstream = [%s]\nembarque = %s\n' \
    "$TUN" "$CLI_PRIV" "$TUN_P" "$SRV_PUB" "$PHY_S" "$PORT_WG" "$LOCAL" "$2" "$3" > "$1"
  chmod 600 "$1"
}

empreinte_resolv() {
  local nature corps
  nature=$(stat -c '%F %a' /etc/resolv.conf 2> /dev/null || echo absent)
  if [ -L /etc/resolv.conf ]; then
    corps=$(readlink /etc/resolv.conf)
  else
    corps=$(sha256sum /etc/resolv.conf 2> /dev/null | cut -d' ' -f1)
  fi
  echo "$nature $corps"
}

# `ip netns del` ne tue rien: les processus du banc sont tues par leur PID
# releve au lancement. Ce qui vivrait encore dans le namespace est retrouve par
# son inode, qui survit au nom: compte, nomme, tue par son PID (le namespace a
# ete cree par ce banc, rien d'autre n'y tourne), et le banc echoue.
retirer_netns() {
  local ns=$1 inode reste=0 p
  inode=$(stat -L -c %i "/run/netns/$ns")
  for p in /proc/[0-9]*; do
    if [ "$(stat -L -c %i "$p/ns/net" 2> /dev/null)" = "$inode" ]; then
      echo "SURVIVANT dans $ns: pid ${p#/proc/} ($(cat "$p/comm" 2> /dev/null || true))" >&2
      kill -KILL "${p#/proc/}" 2> /dev/null || true
      reste=$((reste + 1))
    fi
  done
  ip netns del "$ns"
  [ "$reste" = 0 ]
}

nettoyer() {
  local code=$? ns p d n
  tuer_releves
  if [ -f "$BAC/pids.txt" ]; then
    while read -r p d n; do
      if vivant "$p" "$d" "$n"; then
        echo "SURVIVANT: pid $p" >&2
        kill -KILL "$p" 2> /dev/null || true
        code=1
      fi
    done < "$BAC/pids.txt"
  fi
  if [ -n "$JOURNAL" ]; then
    cp "$BAC"/*.json "$BAC"/*.log "$BAC"/*.txt "$JOURNAL"/ 2> /dev/null || true
    if [ -n "${SUDO_UID:-}" ]; then chown -R "$SUDO_UID:${SUDO_GID:-$SUDO_UID}" "$JOURNAL"; fi
  fi
  for ns in "${CREES[@]}"; do retirer_netns "$ns" || code=1; done
  if [ "$(findmnt -n -o TARGET | grep -cE '^/run/dbus$|^/run/systemd/resolve$' || true)" != "$HOTE_MONTAGES" ] ||
    findmnt -n -o SOURCE | grep -E '^bfdnsd' > /dev/null; then
    echo "montages du banc visibles depuis l'hote" >&2
    code=1
  fi
  if [ "$(stat -c '%d %i' /run/dbus/system_bus_socket 2> /dev/null || true)" != "$HOTE_SOCKET" ]; then
    echo "le socket du bus de l'hote a change" >&2
    code=1
  fi
  if [ "$(empreinte_resolv)" != "$HOTE_RESOLV" ]; then
    echo "/etc/resolv.conf de l'hote a change" >&2
    code=1
  fi
  if [ "$(stat -c '%F' /var/lib/bifrost 2> /dev/null || echo absent)" != "$HOTE_VARLIB" ]; then
    echo "/var/lib/bifrost de l'hote a change" >&2
    code=1
  fi
  rm -rf -- "$BAC"
  if [ "$code" = 0 ]; then
    echo "PASSED: $CAS cas, ${#CREES[@]} namespaces jetables, tous retires, en $(($(date +%s) - DEBUT)) s"
  fi
  exit "$code"
}

exterieur() {
  if [ "$(id -u)" != 0 ]; then
    echo 'Ce banc exige root pour creer ses namespaces jetables.' >&2
    exit 2
  fi
  local outil
  for outil in ip jq setpriv unshare nsenter findmnt dbus-daemon busctl resolvectl ss ping \
    python3 stat sha256sum cmp getent timeout install; do
    command -v "$outil" > /dev/null || { echo "outil absent: $outil" >&2; exit 2; }
  done
  RACINE=$(cd "$(dirname "$0")/.." && pwd)
  local bin=${1:-$RACINE/target/debug}
  test -x "$bin/bifrost-daemon"
  test -x "$bin/bifrost-cli"
  test -x "$RESOLVED"
  JOURNAL=${BIFROST_BANC_JOURNAL:-}
  if [ -n "$JOURNAL" ]; then test -d "$JOURNAL"; fi
  DEBUT=$(date +%s)
  CAS=0
  PIDS=()
  CREES=()
  # Ce que l'hote montre avant: compare a la sortie.
  HOTE_MONTAGES=$(findmnt -n -o TARGET | grep -cE '^/run/dbus$|^/run/systemd/resolve$' || true)
  HOTE_SOCKET=$(stat -c '%d %i' /run/dbus/system_bus_socket 2> /dev/null || true)
  HOTE_DEV_BUS=$(stat -c %d /run/dbus/system_bus_socket 2> /dev/null || echo aucun)
  HOTE_RESOLV=$(empreinte_resolv)
  HOTE_VARLIB=$(stat -c '%F' /var/lib/bifrost 2> /dev/null || echo absent)
  BAC=$(mktemp -d /tmp/bfdnsd.XXXXXX)
  # Traversable par tous: la preuve et le resolveur tournent sous leurs comptes.
  chmod 755 "$BAC"
  trap nettoyer EXIT
  : > "$BAC/passes.txt"
  : > "$BAC/temoins.txt"
  : > "$BAC/pids.txt"
  mkdir -m 755 "$BAC/bin"
  DAEMON="$BAC/bin/bifrost-daemon"
  CLI="$BAC/bin/bifrost-cli"
  FAUX_DNSCRYPT="$BAC/bin/faux-dnscrypt-proxy"
  install -m 755 "$bin/bifrost-daemon" "$DAEMON"
  install -m 755 "$bin/bifrost-cli" "$CLI"
  cp "$0" "$BAC/banc.sh"
  GROUPE=$(getent group "$U_PREUVE" | cut -d: -f1)
  [ -n "$GROUPE" ] || { echo "aucun groupe $U_PREUVE sur cette machine" >&2; exit 2; }
  ecrire_outils
  if [ -d /sys/module/wireguard ]; then
    temoin "module wireguard deja charge au lancement du banc"
  else
    temoin "module wireguard absent au lancement du banc: charge par la creation de la premiere interface"
  fi

  local prefixe="bfdnsd-$$" ns
  NP="$prefixe-p"
  NSV="$prefixe-s"
  for ns in "$NP" "$NSV"; do
    if [ -e "/run/netns/$ns" ]; then
      echo "namespace $ns deja present" >&2
      exit 1
    fi
    ip netns add "$ns"
    CREES+=("$ns")
    ip -n "$ns" link set lo up
  done
  ip -n "$NP" link add "$PHY" type veth peer name "$PAIR" netns "$NSV"
  ip -n "$NP" addr add "$PHY_P/24" dev "$PHY"
  ip -n "$NSV" addr add "$PHY_S/24" dev "$PAIR"
  ip -n "$NP" link set "$PHY" up
  ip -n "$NSV" link set "$PAIR" up
  ip -n "$NP" route add default via "$PHY_S"

  # Cles jetables, nees ici et mortes avec le bac.
  read -r SRV_PRIV SRV_PUB <<< "$("$DAEMON" --genkey)"
  read -r CLI_PRIV CLI_PUB <<< "$("$DAEMON" --genkey)"
  ip -n "$NSV" link add "$WGSRV" type wireguard
  ip netns exec "$NSV" "$DAEMON" --wg-apply "$(printf '{"interface":"%s","private_key":"%s","listen_port":%s,"peers":[{"public_key":"%s","allowed_ips":["%s/32"]}]}' \
    "$WGSRV" "$SRV_PRIV" "$PORT_WG" "$CLI_PUB" "$TUN_P")" > /dev/null
  ip -n "$NSV" addr add "$TUN_S/24" dev "$WGSRV"
  ip -n "$NSV" link set "$WGSRV" up
  profil "$BAC/profil-a.toml" "\"$AMONT\", \"$AMONT6\"" false
  profil "$BAC/profil-b.toml" "\"$AMONT\"" true

  export BAC CLI DAEMON FAUX_DNSCRYPT FAUX GROUPE HOTE_DEV_BUS
  ip netns exec "$NP" unshare -m --propagation private bash "$BAC/banc.sh" --interieur
  CAS=$(grep -c '^PASSED' "$BAC/passes.txt")
}

case "${1:-}" in
  --interieur) interieur ;;
  --course) course "$2" ;;
  *) exterieur "$@" ;;
esac
