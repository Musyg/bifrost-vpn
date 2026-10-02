#!/usr/bin/env bash
# Banc jetable de `prove dns` (D1c.4): un systemd-resolved REEL, sur un bus
# D-Bus PRIVE, dans un namespace de montage prive et des namespaces reseau
# jetables. Ni le resolved de l'hote, ni son bus systeme, ni son
# `/etc/resolv.conf` ne sont lus ou touches: le bus prive ecoute sur un tmpfs
# monte sur `/run/dbus` dans le namespace de montage du banc, et le banc prouve
# qu'il l'a joint AVANT de lancer resolved ou la moindre commande `resolvectl`.
# Adresses de documentation seulement (RFC 5737 et RFC 3849).
#
# Quatre namespaces reseau, crees ici sous des noms exacts et retires ici par
# ces noms: P (le poste: bus prive, resolved prive, la preuve), T (le serveur
# DNS du tunnel), H (le serveur DNS du lien physique, celui qu'un DHCP aurait
# pousse) et Q (un namespace vide, pour la garde d'espace de noms). Deux paires
# veth creees DANS P, jamais dans le namespace de l'hote.
#
# Ce que le banc mesure:
# - la pose du produit, rendue par l'exemple `pose-dns` (qui appelle
#   `resolved_apply_commands` et `resolv_conf_contents`) et appliquee telle
#   quelle par `resolvectl` sur le bus prive, donne MATCH, sans privilege;
# - chaque categorie d'ecart, provoquee, donne cet ecart et lui seul; un
#   temoin d'emission (un repondeur DNS dans T et un dans H, qui comptent les
#   questions recues, et une resolution par glibc dans P) dit par ou la
#   requete est vraiment sortie;
# - les limites nommees (mDNS dans resolved et dans nsswitch) donnent MATCH et
#   sont comptees;
# - bus absent, resolved absent, bus qui refuse, signature inconnue, delegues
#   DNS, autre namespace reseau, autre namespace de montage: UNMEASURED;
# - un domaine qui bascule pendant la collecte rend UNMEASURED, jamais MATCH;
# - la preuve ne pose rien: l'etat du resolved prive est le meme avant et apres;
# - le rapport ne porte ni adresse, ni domaine, ni interface, ni compte.
#
# Usage: sudo bash scripts/preuve-dns-linux.sh
#   Exige root (namespaces), `cargo build -p bifrost-cli` et
#   `cargo build -p bifrost-dns --example pose-dns`, puis ip, jq, setpriv,
#   unshare, findmnt, dbus-daemon, dbus-monitor, busctl, resolvectl, getent,
#   python3 avec ses modules dbus et gi (le faux service des cas UNMEASURED),
#   et /usr/lib/systemd/systemd-resolved.
#   BIFROST_BANC_JOURNAL=<repertoire existant>: y copie rapports, journaux et
#   la capture D-Bus du cas `pose` (graines de fuzzing).
set -euo pipefail
unset DBUS_SYSTEM_BUS_ADDRESS DBUS_SESSION_BUS_ADDRESS NOTIFY_SOCKET WATCHDOG_PID WATCHDOG_USEC

TUN=bt0
PHY=bp0
# Le tunnel: bt0 dans P, rt0 dans T; son serveur DNS est l'amont du plan.
TUN_P=192.0.2.1
AMONT=192.0.2.53
AMONT6=2001:db8::53
# Le lien physique: bp0 dans P, rp0 dans H; son serveur est celui du DHCP.
PHY_P=198.51.100.1
DHCP=198.51.100.53
LOCAL=127.0.0.1
# Comptes: la preuve tourne sous `nobody`; le resolveur embarque factice sous
# un compte quelconque, que le rapport ne doit jamais repeter.
U_PREUVE=65534
U_RESOLVEUR=4243
RESOLVED=/usr/lib/systemd/systemd-resolved
CHEMIN_PATH=/usr/sbin:/usr/bin:/sbin:/bin

# --- commun ------------------------------------------------------------------

passe() {
  echo "PASSED: $*" | tee -a "$BAC/passes.txt"
}

# `muet <nom>`: le rapport ne porte aucun identifiant du banc. Les horodatages
# sont des nombres quelconques: hors de la recherche.
muet() {
  if jq 'del(.started_at_unix_ms, .completed_at_unix_ms, .duration_ms)' "$BAC/$1.json" |
    grep -E '192\.0\.2|198\.51\.100|2001:db8|127\.0\.0|bt0|bp0|rt0|rp0|banc|\.test|4243|4244|65534' > /dev/null; then
    echo "$1: le rapport exporte un identifiant du banc" >&2
    return 1
  fi
}

# `lancer_preuve <nom> <intention> [prefixe...]`: la preuve, sans privilege et
# sans environnement, dans le namespace courant (ou sous le prefixe donne).
lancer_preuve() {
  local nom=$1 intention=$2
  shift 2
  DERNIER=$nom
  CODE=0
  "$@" env -i PATH="$CHEMIN_PATH" setpriv --reuid="$U_PREUVE" --regid="$U_PREUVE" --clear-groups \
    "$CLI" --json prove dns --intention "$intention" --actif > "$BAC/$nom.json" || CODE=$?
  muet "$nom"
}

# `attendre <nom> <code> <verdict> <ecarts en JSON>`: le verdict, et
# exactement ces categories d'ecart, dans cet ordre.
attendre() {
  if [ "$CODE" != "$2" ] || ! jq -e --arg v "$3" --argjson d "$4" \
    '.verdict == $v and .differences == $d and .live_system and .collection_verified
     and .schema_version == 1 and .scope == "linux-dns-comparison"
     and .network_security == "not-evaluated" and .failed_input == null' \
    "$BAC/$1.json" > /dev/null; then
    echo "$1: attendu $3 $4 (code $2), rendu code $CODE" >&2
    cat "$BAC/$1.json" >&2
    return 1
  fi
  passe "$1 -> $3 $4"
}

# `non_mesure <nom> <debut de la raison>`.
non_mesure() {
  if [ "$CODE" != 2 ] || ! jq -e --arg r "$2" \
    '.verdict == "UNMEASURED" and (.reason | startswith($r)) and .differences == []
     and .failed_input == "observed" and .observed_counts == null' \
    "$BAC/$1.json" > /dev/null; then
    echo "$1: attendu UNMEASURED ($2), rendu code $CODE" >&2
    cat "$BAC/$1.json" >&2
    return 1
  fi
  passe "$1 -> UNMEASURED ($2)"
}

# L'etat du resolved joint, en une empreinte (bus prive seulement).
etat() {
  {
    resolvectl status --no-pager 2>&1 || true
    resolvectl dns 2>&1 || true
    resolvectl domain 2>&1 || true
    stat -L -c '%d %i' /etc/resolv.conf 2>&1 || true
    sha256sum /etc/nsswitch.conf 2>&1 || true
  } | sha256sum
}

# `prouver <nom> <intention>`: une preuve qui ne doit rien changer.
prouver() {
  local avant apres
  avant=$(etat)
  lancer_preuve "$1" "$2"
  apres=$(etat)
  if [ "$avant" != "$apres" ]; then
    echo "$1: l'etat du resolveur a change pendant la preuve" >&2
    return 1
  fi
}

# `noter <pid> [inode du namespace reseau]`: chaque processus lance est
# releve avec le namespace ou il tourne (par defaut celui du banc courant), pour
# etre tue par son PID, et seulement s'il y tourne encore: un PID recycle par
# un processus de l'hote n'est jamais vise.
noter() {
  local ns=${2:-$(stat -L -c %i /proc/self/ns/net)}
  echo "$1 $ns" >> "$BAC/pids.txt"
  PIDS+=("$1:$ns")
}

# `vivant <pid> <inode>`: le processus vit, dans ce namespace.
vivant() {
  [ "$(stat -L -c %i "/proc/$1/ns/net" 2> /dev/null)" = "$2" ]
}

tuer_releves() {
  local e
  for e in "${PIDS[@]}"; do
    if vivant "${e%%:*}" "${e##*:}"; then kill "${e%%:*}" 2> /dev/null || true; fi
  done
  for e in "${PIDS[@]}"; do
    for _ in $(seq 1 50); do
      if ! vivant "${e%%:*}" "${e##*:}"; then break; fi
      sleep 0.1
    done
    if vivant "${e%%:*}" "${e##*:}"; then kill -KILL "${e%%:*}" 2> /dev/null || true; fi
  done
  PIDS=()
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
    <allow eavesdrop="true"/>
  </policy>
</busconfig>'

# `bus_prive <configuration>`: un dbus-daemon sur le tmpfs de /run/dbus du
# namespace de montage courant, sans repertoire de services (aucune
# activation). Refuse si le socket n'est pas sur ce tmpfs.
bus_prive() {
  [ -z "$(ls -A /run/dbus)" ] || refus "/run/dbus n'est pas vide avant le bus prive"
  dbus-daemon --config-file="$1" --nofork --nopidfile > "$BAC/dbus-$$.log" 2>&1 &
  noter $!
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

refus() {
  echo "ARRET AVANT ECRITURE: $*" >&2
  exit 3
}

# --- le faux service et le repondeur ------------------------------------------

ecrire_outils() {
  cat > "$BAC/repondeur.py" << 'PY'
import os, socket, struct, sys
def nom(p, i):
    e = []
    while True:
        n = p[i]
        if n == 0:
            return ".".join(e), i + 1
        if n & 0xC0:
            raise ValueError
        e.append(p[i + 1:i + 1 + n].decode("ascii", "replace"))
        i += 1 + n
adresse, port, journal = sys.argv[1], int(sys.argv[2]), sys.argv[3]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((adresse, port))
with open(journal, "a", buffering=1) as j:
    j.write("pret %d\n" % os.getpid())
    while True:
        p, d = s.recvfrom(4096)
        try:
            ident, drap, qd = struct.unpack("!HHH", p[:6])
            q, i = nom(p, 12)
            qtype, qclass = struct.unpack("!HH", p[i:i + 4])
        except Exception:
            continue
        if qd != 1 or drap & 0x8000:
            continue
        j.write("question %s %d\n" % (q.lower(), qtype))
        question = p[12:i + 4]
        if qtype == 1:
            r = struct.pack("!HHHHHH", ident, 0x8180, 1, 1, 0, 0) + question
            r += struct.pack("!HHHIH", 0xC00C, 1, 1, 60, 4) + bytes([192, 0, 2, 99])
        else:
            r = struct.pack("!HHHHHH", ident, 0x8180, 1, 0, 0, 0) + question
        s.sendto(r, d)
PY
  # Un faux org.freedesktop.resolve1, pour les cas que resolved ne produit
  # pas: une signature que la preuve ne lit pas, des delegues DNS.
  cat > "$BAC/faux-resolve1.py" << 'PY'
import sys
import dbus, dbus.service, dbus.exceptions
from dbus.mainloop.glib import DBusGMainLoop
from gi.repository import GLib
DBusGMainLoop(set_as_default=True)
mode = sys.argv[1]
bus = dbus.SystemBus()
nom = dbus.service.BusName("org.freedesktop.resolve1", bus)
P = "org.freedesktop.DBus.Properties"
M = "org.freedesktop.resolve1.Manager"
def inconnue():
    return dbus.exceptions.DBusException("inconnue", name="org.freedesktop.DBus.Error.UnknownProperty")
class Manager(dbus.service.Object):
    @dbus.service.method(P, in_signature="ss", out_signature="v")
    def Get(self, interface, propriete):
        if propriete == "DNSEx":
            return dbus.Array([], signature="(iiay)" if mode == "signature" else "(iiayqs)")
        if propriete == "Domains":
            return dbus.Array([], signature="(isb)")
        if propriete == "ResolvConfMode":
            return dbus.String("stub")
        raise inconnue()
    @dbus.service.method(M, in_signature="", out_signature="a(so)")
    def ListDelegates(self):
        if mode == "delegues":
            return dbus.Array([("d", dbus.ObjectPath("/org/freedesktop/resolve1/dns_delegate/d"))], signature="(so)")
        return dbus.Array([], signature="(so)")
    @dbus.service.method(M, in_signature="i", out_signature="o")
    def GetLink(self, index):
        return dbus.ObjectPath("/org/freedesktop/resolve1/link/_3%d" % index)
class Lien(dbus.service.Object):
    @dbus.service.method(P, in_signature="ss", out_signature="v")
    def Get(self, interface, propriete):
        if propriete == "DefaultRoute":
            return dbus.Boolean(True)
        if propriete == "ScopesMask":
            return dbus.UInt64(1)
        if propriete == "DNSEx":
            return dbus.Array([], signature="(iayqs)")
        raise inconnue()
Manager(bus, "/org/freedesktop/resolve1")
liens = [Lien(bus, "/org/freedesktop/resolve1/link/_3%d" % i) for i in range(1, 10)]
print("pret", flush=True)
GLib.MainLoop().run()
PY
  printf '%s\n' "$DBUS_PERMISSIF" > "$BAC/dbus-permissif.conf"
  # La politique refuse a tout autre que root d'appeler resolve1.
  printf '%s\n' "$DBUS_PERMISSIF" |
    sed 's#  </policy>#    <deny send_destination="org.freedesktop.resolve1"/>\n  </policy>\n  <policy user="root">\n    <allow send_destination="org.freedesktop.resolve1"/>\n  </policy>#' \
      > "$BAC/dbus-politique.conf"
  # Seul root peut se connecter.
  printf '%s\n' "$DBUS_PERMISSIF" | sed 's#<allow user="\*"/>#<allow user="root"/>#' > "$BAC/dbus-connexion.conf"
  grep -q 'deny send_destination' "$BAC/dbus-politique.conf"
  grep -q 'allow user="root"' "$BAC/dbus-connexion.conf"
  chmod 644 "$BAC"/*.py "$BAC"/*.conf
}

# --- dans P, namespace de montage prive ----------------------------------------

resolved_conf() {
  printf '[Resolve]\nDNS=%s\nDomains=%s\nLLMNR=%s\nMulticastDNS=%s\nDNSSEC=no\nDNSOverTLS=no\nFallbackDNS=\nDNSStubListener=yes\n' \
    "$1" "$2" "$3" "$4" > "$BAC/resolved.conf"
}

demarrer_resolved() {
  env -i PATH="$CHEMIN_PATH" SYSTEMD_LOG_LEVEL=info SYSTEMD_LOG_TARGET=console "$RESOLVED" >> "$BAC/resolved.log" 2>&1 &
  RES_PID=$!
  noter "$RES_PID"
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

arreter_resolved() {
  kill "$RES_PID"
  for _ in $(seq 1 50); do
    if ! kill -0 "$RES_PID" 2> /dev/null; then break; fi
    sleep 0.1
  done
  ! kill -0 "$RES_PID" 2> /dev/null
}

# `poser <oui|non>`: les commandes du produit, rendues par le produit.
poser() {
  local ligne mots
  "$POSE" resolved "$TUN" "$1" "$LOCAL" "$AMONT" "$AMONT6" > "$BAC/pose-$1.txt"
  while IFS= read -r ligne; do
    read -r -a mots <<< "$ligne"
    resolvectl "${mots[@]}"
  done < "$BAC/pose-$1.txt"
}

nsswitch() {
  printf 'passwd: files\ngroup: files\nshadow: files\nhosts: %s\n' "$1" > "$BAC/nsswitch.conf"
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

# `temoin <nom> <tunnel: 0|+> <physique: 0|+>`: une resolution par glibc, et
# ce que chaque repondeur a recu pour ce nom.
temoin() {
  local t h
  getent ahostsv4 "$1" > /dev/null 2>&1 || true
  sleep 0.5
  t=$(grep -c " $1 " "$BAC/rep-t.log" || true)
  h=$(grep -c " $1 " "$BAC/rep-h.log" || true)
  echo "temoin $1: tunnel=$t physique=$h" | tee -a "$BAC/temoins.txt"
  if { [ "$2" = 0 ] && [ "$t" != 0 ]; } || { [ "$2" = + ] && [ "$t" = 0 ]; } ||
    { [ "$3" = 0 ] && [ "$h" != 0 ]; } || { [ "$3" = + ] && [ "$h" = 0 ]; }; then
    echo "temoin $1: attendu tunnel $2 physique $3" >&2
    return 1
  fi
}

arret_interieur() {
  local code=$?
  tuer_releves
  exit "$code"
}

interieur() {
  PIDS=()
  trap arret_interieur EXIT
  echo "== isolation du montage =="
  [ "$(findmnt -n -o PROPAGATION /)" = private ] || refus "montage non prive"
  mount -t tmpfs -o mode=0755 tmpfs /run/dbus || refus "tmpfs /run/dbus"
  mount -t tmpfs -o "mode=0755,uid=$(id -u systemd-resolve),gid=$(id -g systemd-resolve)" \
    tmpfs /run/systemd/resolve || refus "tmpfs /run/systemd/resolve"
  [ -z "$(ls -A /run/systemd/resolve)" ] || refus "/run/systemd/resolve n'est pas vide"
  # Ni la configuration de l'hote, ni l'etat de ses liens selon networkd (ses
  # numeros d'interface croiseraient ceux du banc).
  for d in /etc/systemd/resolved.conf.d /run/systemd/resolved.conf.d \
    /usr/local/lib/systemd/resolved.conf.d /usr/lib/systemd/resolved.conf.d /run/systemd/netif; do
    if [ -d "$d" ]; then mount -t tmpfs -o mode=0755 tmpfs "$d"; fi
  done
  resolved_conf "" "" no no
  nsswitch "files dns"
  chmod 644 "$BAC/resolved.conf" "$BAC/nsswitch.conf"
  mount --bind "$BAC/resolved.conf" /etc/systemd/resolved.conf || refus "resolved.conf prive"
  mount --bind "$BAC/nsswitch.conf" /etc/nsswitch.conf || refus "nsswitch.conf prive"
  sysctl -q -w net.ipv4.ip_unprivileged_port_start=0

  echo "== bus prive =="
  bus_prive "$BAC/dbus-permissif.conf"
  if busctl --system list --no-legend | awk '{print $1}' | grep -x org.freedesktop.resolve1 > /dev/null; then
    refus "resolve1 deja present sur le bus joint"
  fi
  if awk 'NR > 1 && $2 == "3500007F:0035"' /proc/net/udp | grep . > /dev/null; then
    refus "un stub ecoute deja dans ce namespace"
  fi
  echo "bus prive prouve: socket sur le tmpfs du banc, resolve1 absent, aucun stub"

  echo "== resolved prive, configuration A (ni LLMNR ni mDNS) =="
  demarrer_resolved
  echo "version: $("$RESOLVED" --version | sed -n 1p)"

  echo "== pose du produit =="
  resolvectl dns "$PHY" "$DHCP"
  poser non
  printf 'dns %s %s %s\ndomain %s ~.\n' "$TUN" "$AMONT" "$AMONT6" "$TUN" | cmp - "$BAC/pose-non.txt"
  attendre_masque "$TUN" 1 0
  attendre_masque "$PHY" 1 0

  dbus-monitor --system --binary > "$BAC/capture-dbus.bin" 2> "$BAC/monitor.log" &
  MON=$!
  noter "$MON"
  sleep 1
  prouver pose "$BAC/i-resolved.json"
  attendre pose 0 MATCH '[]'
  kill "$MON"
  jq -e '.expected_counts.servers == 2 and .expected_counts.tunnel_domains == 1
    and .observed_counts.tunnel_servers == 2 and .observed_counts.tunnel_domains == 1
    and .observed_counts.scopes_with_servers == 2 and .observed_counts.other_scopes_with_domains == 0
    and .observed_counts.other_default_route_links == 1 and .observed_counts.llmnr_links == 0
    and .observed_counts.resolv_conf_mode == "stub" and .observed_counts.links == 3
    and .named_limits.mdns_links == 0 and .named_limits.mdns_nss_sources == 0
    and .source == "resolved-dbus-and-system-files-read-twice" and .backend == "systemd-resolved"' \
    "$BAC/pose.json" > /dev/null
  temoin e0.autre.test + 0
  # En root, la meme lecture: la preuve n'a besoin d'aucun privilege.
  CODE=0
  env -i PATH="$CHEMIN_PATH" "$CLI" --json prove dns --intention "$BAC/i-resolved.json" --actif \
    > "$BAC/pose-root.json" || CODE=$?
  jq -e -n --slurpfile a "$BAC/pose.json" --slurpfile b "$BAC/pose-root.json" \
    '$a[0].verdict == $b[0].verdict and $a[0].observed_counts == $b[0].observed_counts
     and $a[0].named_limits == $b[0].named_limits' > /dev/null
  passe "pose-root -> meme verdict et memes comptes qu'en compte ordinaire"

  echo "== resolv-conf-path =="
  mount --bind /run/systemd/resolve/resolv.conf /etc/resolv.conf
  prouver chemin-uplink "$BAC/i-resolved.json"
  attendre chemin-uplink 1 MISMATCH '["resolv-conf-path"]'
  jq -e '.observed_counts.resolv_conf_mode == "uplink"' "$BAC/chemin-uplink.json" > /dev/null
  umount /etc/resolv.conf
  # Un fichier etranger monte sur celui du stub: /etc/resolv.conf mene au stub
  # par un lien symbolique, le montage le suit, et le fichier garde l'inode
  # du stub. Le mode dit `stub`; le contenu dit ou glibc ira.
  printf 'nameserver %s\n' "$DHCP" > "$BAC/etranger.conf"
  chmod 644 "$BAC/etranger.conf"
  mount --bind "$BAC/etranger.conf" /etc/resolv.conf
  prouver chemin-etranger "$BAC/i-resolved.json"
  attendre chemin-etranger 1 MISMATCH '["resolv-conf-path"]'
  echo "chemin-etranger: mode lu $(jq -r .observed_counts.resolv_conf_mode "$BAC/chemin-etranger.json")" |
    tee -a "$BAC/temoins.txt"
  temoin e1.autre.test 0 +
  umount /etc/resolv.conf

  echo "== hosts-sources =="
  nsswitch "files ldap dns"
  prouver sources-hors "$BAC/i-resolved.json"
  attendre sources-hors 1 MISMATCH '["hosts-sources"]'
  nsswitch "files mdns4_minimal [NOTFOUND=return] dns"
  prouver sources-mdns "$BAC/i-resolved.json"
  attendre sources-mdns 0 MATCH '[]'
  jq -e '.named_limits.mdns_nss_sources == 1' "$BAC/sources-mdns.json" > /dev/null
  nsswitch "files myhostname mymachines resolve [!UNAVAIL=return] dns"
  prouver sources-admises "$BAC/i-resolved.json"
  attendre sources-admises 0 MATCH '[]'
  nsswitch "files dns"

  echo "== tunnel-link-scope =="
  ip link set "$TUN" down
  attendre_masque "$TUN" 0 1
  prouver tunnel-eteint "$BAC/i-resolved.json"
  attendre tunnel-eteint 1 MISMATCH '["tunnel-link-scope"]'
  temoin e2.autre.test 0 +
  ip link set "$TUN" up
  attendre_masque "$TUN" 1 0
  prouver tunnel-rallume "$BAC/i-resolved.json"
  attendre tunnel-rallume 0 MATCH '[]'

  echo "== tunnel-link-servers =="
  resolvectl dns "$TUN" "$AMONT6" "$AMONT"
  prouver tunnel-serveurs-ordre "$BAC/i-resolved.json"
  attendre tunnel-serveurs-ordre 1 MISMATCH '["tunnel-link-servers"]'
  resolvectl dns "$TUN" "$AMONT"
  prouver tunnel-serveur-manquant "$BAC/i-resolved.json"
  attendre tunnel-serveur-manquant 1 MISMATCH '["tunnel-link-servers"]'
  poser non

  echo "== tunnel-link-domains =="
  resolvectl domain "$TUN" ''
  prouver tunnel-sans-domaine "$BAC/i-resolved.json"
  attendre tunnel-sans-domaine 1 MISMATCH '["tunnel-link-domains"]'
  temoin e3.autre.test + +
  resolvectl domain "$TUN" '~.' '~banc.test'
  prouver tunnel-domaine-en-trop "$BAC/i-resolved.json"
  attendre tunnel-domaine-en-trop 1 MISMATCH '["tunnel-link-domains"]'
  poser non

  echo "== dns-exceptions, competing-default-routes =="
  resolvectl domain "$PHY" '~banc.test'
  prouver exception-routage "$BAC/i-resolved.json"
  attendre exception-routage 1 MISMATCH '["dns-exceptions"]'
  temoin e4.banc.test 0 +
  temoin e4.autre.test + 0
  resolvectl domain "$PHY" 'banc2.test'
  prouver exception-recherche "$BAC/i-resolved.json"
  attendre exception-recherche 1 MISMATCH '["dns-exceptions"]'
  temoin e5.banc2.test 0 +
  resolvectl domain "$PHY" '~.'
  prouver concurrente "$BAC/i-resolved.json"
  attendre concurrente 1 MISMATCH '["competing-default-routes"]'
  temoin e6.autre.test + +
  resolvectl domain "$PHY" '~.' '~banc.test'
  prouver exception-et-concurrente "$BAC/i-resolved.json"
  attendre exception-et-concurrente 1 MISMATCH '["dns-exceptions","competing-default-routes"]'
  resolvectl domain "$PHY" ''
  resolvectl default-route "$PHY" no
  prouver physique-sans-route-par-defaut "$BAC/i-resolved.json"
  attendre physique-sans-route-par-defaut 0 MATCH '[]'
  jq -e '.observed_counts.other_default_route_links == 0' "$BAC/physique-sans-route-par-defaut.json" > /dev/null
  resolvectl revert "$PHY"
  resolvectl dns "$PHY" "$DHCP"
  # Un domaine sur un lien SANS serveur: il ne recoit rien, la regle l'admet.
  resolvectl revert "$PHY"
  resolvectl domain "$PHY" '~banc.test'
  prouver domaine-sans-serveur "$BAC/i-resolved.json"
  attendre domaine-sans-serveur 0 MATCH '[]'
  temoin e7.banc.test + 0
  resolvectl revert "$PHY"
  resolvectl dns "$PHY" "$DHCP"
  prouver retour-pose "$BAC/i-resolved.json"
  attendre retour-pose 0 MATCH '[]'

  echo "== local-resolver-listener (resolveur embarque) =="
  poser oui
  printf 'dns %s %s\ndomain %s ~.\n' "$TUN" "$LOCAL" "$TUN" | cmp - "$BAC/pose-oui.txt"
  : > "$BAC/rep-local.log"
  chmod 666 "$BAC/rep-local.log"
  setpriv --reuid="$U_RESOLVEUR" --regid="$U_RESOLVEUR" --clear-groups \
    python3 "$BAC/repondeur.py" "$LOCAL" 53 "$BAC/rep-local.log" > /dev/null 2>&1 &
  ECOUTE=$!
  noter "$ECOUTE"
  for _ in $(seq 1 50); do
    if grep -q '^pret' "$BAC/rep-local.log"; then break; fi
    sleep 0.1
  done
  grep -q '^pret' "$BAC/rep-local.log"
  # Le Manager rend le serveur de bouclage du tunnel sous l'index de lo (1);
  # le lien du tunnel le declare.
  local dnsex
  dnsex=$(busctl --system get-property org.freedesktop.resolve1 /org/freedesktop/resolve1 \
    org.freedesktop.resolve1.Manager DNSEx)
  echo "embarque: DNSEx du Manager: $dnsex" | tee -a "$BAC/temoins.txt"
  grep -q ' 1 2 4 127 0 0 1 0 ""' <<< "$dnsex"
  prouver embarque "$BAC/i-embarque.json"
  attendre embarque 0 MATCH '[]'
  jq -e '.observed_counts.local_resolver_listeners == 1 and .observed_counts.tunnel_servers == 1
    and .observed_counts.scopes_with_servers == 2' "$BAC/embarque.json" > /dev/null
  prouver embarque-autre-compte "$BAC/i-embarque-autre.json"
  attendre embarque-autre-compte 1 MISMATCH '["local-resolver-listener"]'
  kill "$ECOUTE"
  wait "$ECOUTE" 2> /dev/null || true
  prouver embarque-sans-ecoute "$BAC/i-embarque.json"
  attendre embarque-sans-ecoute 1 MISMATCH '["local-resolver-listener"]'
  poser non

  echo "== backend resolv.conf =="
  "$POSE" resolv-conf "$TUN" non "$LOCAL" "$AMONT" "$AMONT6" > "$BAC/resolv-produit.conf"
  chmod 644 "$BAC/resolv-produit.conf"
  mount --bind "$BAC/resolv-produit.conf" /etc/resolv.conf
  prouver rc-pose "$BAC/i-resolvconf.json"
  attendre rc-pose 0 MATCH '[]'
  jq -e '.source == "resolv-conf-and-system-files-read-twice" and .backend == "resolv-conf"
    and .observed_counts.links == null' "$BAC/rc-pose.json" > /dev/null
  temoin e8.autre.test + 0
  nsswitch "files resolve [!UNAVAIL=return] dns"
  prouver rc-resolve "$BAC/i-resolvconf.json"
  attendre rc-resolve 1 MISMATCH '["hosts-sources"]'
  nsswitch "files dns"
  umount /etc/resolv.conf
  printf 'nameserver %s\nnameserver %s\n' "$DHCP" "$AMONT" > "$BAC/resolv-altere.conf"
  chmod 644 "$BAC/resolv-altere.conf"
  mount --bind "$BAC/resolv-altere.conf" /etc/resolv.conf
  prouver rc-altere "$BAC/i-resolvconf.json"
  attendre rc-altere 1 MISMATCH '["resolv-conf-content"]'
  temoin e9.autre.test 0 +
  umount /etc/resolv.conf

  echo "== UNMEASURED: autre namespace reseau, autres namespaces de montage =="
  lancer_preuve autre-netns "$BAC/i-resolved.json" ip netns exec "$NQ"
  non_mesure autre-netns "ecoute du stub de systemd-resolved absente"
  for cas in autre-montage sans-bus bus-sans-resolved bus-politique bus-connexion signature delegues; do
    unshare -m --propagation private bash "$BAC/banc.sh" --imbrique "$cas"
  done

  echo "== course: un domaine qui bascule pendant la collecte =="
  cat > "$BAC/basculer.sh" << 'SH'
while :; do
  resolvectl domain "$1" '~a.test' || exit 1
  resolvectl domain "$1" '~b.test' || exit 1
done
SH
  bash "$BAC/basculer.sh" "$PHY" &
  COURSE=$!
  noter "$COURSE"
  local instables=0 coherentes=0 essais=0
  for _ in $(seq 1 100); do
    essais=$((essais + 1))
    lancer_preuve course "$BAC/i-resolved.json"
    if [ "$CODE" = 2 ] && jq -e '.verdict == "UNMEASURED" and (.reason | startswith("collecte instable"))
      and (.collection_verified | not) and .differences == []' "$BAC/course.json" > /dev/null; then
      instables=$((instables + 1))
    elif [ "$CODE" = 1 ] && jq -e '.collection_verified and .verdict == "MISMATCH"
      and .differences == ["dns-exceptions"]' "$BAC/course.json" > /dev/null; then
      coherentes=$((coherentes + 1))
    else
      echo "course: ni etat stable, ni collecte instable" >&2
      cat "$BAC/course.json" >&2
      exit 1
    fi
    if [ "$instables" -ge 10 ]; then break; fi
  done
  kill "$COURSE"
  wait "$COURSE" 2> /dev/null || true
  echo "course: $instables collectes instables et $coherentes coherentes sur $essais" | tee -a "$BAC/temoins.txt"
  [ "$instables" -ge 1 ]
  passe "course -> UNMEASURED sur un domaine qui bascule, jamais MATCH"
  resolvectl domain "$PHY" ''

  echo "== resolved prive, configuration B (LLMNR) =="
  arreter_resolved
  resolved_conf "" "" yes no
  demarrer_resolved
  poser non
  attendre_masque "$PHY" 2 0
  prouver llmnr "$BAC/i-resolved.json"
  attendre llmnr 1 MISMATCH '["multicast-resolution"]'
  jq -e '.observed_counts.llmnr_links >= 2' "$BAC/llmnr.json" > /dev/null
  resolvectl llmnr "$PHY" no
  resolvectl llmnr "$TUN" no
  attendre_masque "$PHY" 1 6
  attendre_masque "$TUN" 1 6
  prouver llmnr-coupe "$BAC/i-resolved.json"
  attendre llmnr-coupe 0 MATCH '[]'

  echo "== resolved prive, configuration C (mDNS) =="
  arreter_resolved
  resolved_conf "" "" no yes
  demarrer_resolved
  poser non
  resolvectl mdns "$PHY" yes
  attendre_masque "$PHY" 8 6
  prouver mdns "$BAC/i-resolved.json"
  attendre mdns 0 MATCH '[]'
  jq -e '.named_limits.mdns_links >= 1' "$BAC/mdns.json" > /dev/null
  resolvectl mdns "$PHY" no

  echo "== resolved prive, configuration D (portee globale) =="
  arreter_resolved
  resolved_conf "$DHCP" "~global.test" no no
  demarrer_resolved
  poser non
  prouver globale-exception "$BAC/i-resolved.json"
  attendre globale-exception 1 MISMATCH '["dns-exceptions"]'
  temoin e10.global.test 0 +
  arreter_resolved
  resolved_conf "$DHCP" "" no no
  demarrer_resolved
  poser non
  prouver globale-sans-domaine "$BAC/i-resolved.json"
  attendre globale-sans-domaine 0 MATCH '[]'
  jq -e '.observed_counts.scopes_with_servers == 3' "$BAC/globale-sans-domaine.json" > /dev/null
  temoin e11.autre.test + 0
  arreter_resolved
}

# --- un namespace de montage de plus, dans P, pour un cas UNMEASURED ------------

imbrique() {
  PIDS=()
  trap arret_interieur EXIT
  [ "$(findmnt -n -o PROPAGATION /)" = private ] || refus "montage imbrique non prive"
  case "$1" in
    autre-montage)
      # Le resolved prive juge le fichier de SON namespace (le stub); la
      # preuve en lit un autre ici (le fichier uplink).
      mount --bind /run/systemd/resolve/resolv.conf /etc/resolv.conf
      lancer_preuve autre-montage "$BAC/i-resolved.json"
      non_mesure autre-montage "systemd-resolved juge un autre /etc/resolv.conf"
      return
      ;;
  esac
  mount -t tmpfs -o mode=0755 tmpfs /run/dbus
  case "$1" in
    sans-bus)
      lancer_preuve sans-bus "$BAC/i-resolved.json"
      non_mesure sans-bus "bus systeme injoignable"
      ;;
    bus-sans-resolved)
      bus_prive "$BAC/dbus-permissif.conf"
      lancer_preuve bus-sans-resolved "$BAC/i-resolved.json"
      non_mesure bus-sans-resolved "systemd-resolved absent du bus systeme"
      ;;
    bus-politique | signature | delegues)
      local conf=permissif mode=normal
      if [ "$1" = bus-politique ]; then conf=politique; fi
      if [ "$1" != bus-politique ]; then mode=$1; fi
      bus_prive "$BAC/dbus-$conf.conf"
      env -i PATH="$CHEMIN_PATH" python3 "$BAC/faux-resolve1.py" "$mode" > "$BAC/faux-$1.log" 2>&1 &
      noter $!
      for _ in $(seq 1 50); do
        if grep -q '^pret' "$BAC/faux-$1.log"; then break; fi
        sleep 0.1
      done
      grep -q '^pret' "$BAC/faux-$1.log"
      lancer_preuve "$1" "$BAC/i-resolved.json"
      case "$1" in
        bus-politique) non_mesure "$1" "bus systeme: appel refuse par sa politique" ;;
        signature) non_mesure "$1" "signature D-Bus non prise en charge" ;;
        delegues) non_mesure "$1" "delegues DNS presents" ;;
      esac
      ;;
    bus-connexion)
      bus_prive "$BAC/dbus-connexion.conf"
      lancer_preuve bus-connexion "$BAC/i-resolved.json"
      if [ "$CODE" != 2 ] || ! jq -e '.verdict == "UNMEASURED" and .failed_input == "observed"
        and .observed_counts == null' "$BAC/bus-connexion.json" > /dev/null; then
        echo "bus-connexion: attendu UNMEASURED" >&2
        cat "$BAC/bus-connexion.json" >&2
        exit 1
      fi
      passe "bus-connexion -> UNMEASURED ($(jq -r .reason "$BAC/bus-connexion.json"))"
      ;;
    *)
      echo "cas inconnu: $1" >&2
      exit 2
      ;;
  esac
}

# --- dans le namespace de l'hote: namespaces reseau, repondeurs, retrait --------

# `ip netns del` ne tue rien: les processus du banc sont tues par leur PID
# releve au lancement; ce qui vivrait encore dans le namespace est compte par
# son inode, qui survit au nom, et fait echouer le banc.
retirer_netns() {
  local ns=$1 inode reste pid
  inode=$(stat -L -c %i "/run/netns/$ns")
  ip netns del "$ns"
  reste=0
  for pid in /proc/[0-9]*; do
    if [ "$(stat -L -c %i "$pid/ns/net" 2> /dev/null)" = "$inode" ]; then
      reste=$((reste + 1))
    fi
  done
  if [ "$reste" != 0 ]; then
    echo "processus encore vivants dans le namespace $ns: $reste" >&2
    return 1
  fi
}

nettoyer() {
  local code=$? ns p inode
  tuer_releves
  if [ -f "$BAC/pids.txt" ]; then
    while read -r p inode; do
      if vivant "$p" "$inode"; then
        echo "SURVIVANT: pid $p" >&2
        kill -KILL "$p" 2> /dev/null || true
        code=1
      fi
    done < "$BAC/pids.txt"
  fi
  if [ -n "$JOURNAL" ]; then
    cp "$BAC"/*.json "$BAC"/*.log "$BAC"/*.txt "$JOURNAL"/ 2> /dev/null || true
    if [ -f "$BAC/capture-dbus.bin" ]; then cp "$BAC/capture-dbus.bin" "$JOURNAL"/; fi
    if [ -n "${SUDO_UID:-}" ]; then chown -R "$SUDO_UID:${SUDO_GID:-$SUDO_UID}" "$JOURNAL"; fi
  fi
  for ns in "${CREES[@]}"; do retirer_netns "$ns" || code=1; done
  if [ "$(findmnt -n -o TARGET | grep -cE '^/run/dbus$|^/run/systemd/resolve$')" != "$HOTE_MONTAGES" ]; then
    echo "montages du banc visibles depuis l'hote" >&2
    code=1
  fi
  if [ "$(stat -c '%d %i' /run/dbus/system_bus_socket 2> /dev/null)" != "$HOTE_SOCKET" ]; then
    echo "le socket du bus de l'hote a change" >&2
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
  for outil in ip jq setpriv unshare findmnt dbus-daemon dbus-monitor busctl resolvectl getent \
    python3 sysctl stat sha256sum cmp; do
    command -v "$outil" > /dev/null || { echo "outil absent: $outil" >&2; exit 2; }
  done
  python3 -c 'import dbus, dbus.service, gi' || { echo 'python3: modules dbus et gi absents' >&2; exit 2; }
  RACINE=$(cd "$(dirname "$0")/.." && pwd)
  test -x "$RACINE/target/debug/bifrost-cli"
  test -x "$RACINE/target/debug/examples/pose-dns"
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
  BAC=$(mktemp -d)
  chmod 755 "$BAC"
  trap nettoyer EXIT
  cp "$RACINE/target/debug/bifrost-cli" "$BAC/bifrost-cli"
  cp "$RACINE/target/debug/examples/pose-dns" "$BAC/pose-dns"
  cp "$0" "$BAC/banc.sh"
  CLI="$BAC/bifrost-cli"
  POSE="$BAC/pose-dns"
  chmod 755 "$CLI" "$POSE"
  ecrire_outils
  : > "$BAC/passes.txt"

  local prefixe="bfdns-$$" ns
  NP="$prefixe-p"
  NT="$prefixe-t"
  NH="$prefixe-h"
  NQ="$prefixe-q"
  for ns in "$NP" "$NT" "$NH" "$NQ"; do
    if ip netns list | awk '{print $1}' | grep -x "$ns" > /dev/null; then
      echo "namespace $ns deja present" >&2
      exit 1
    fi
    ip netns add "$ns"
    CREES+=("$ns")
    ip -n "$ns" link set lo up
  done
  ip -n "$NP" link add "$TUN" type veth peer name rt0 netns "$NT"
  ip -n "$NP" link add "$PHY" type veth peer name rp0 netns "$NH"
  ip -n "$NP" addr add "$TUN_P/24" dev "$TUN"
  ip -n "$NP" addr add "$PHY_P/24" dev "$PHY"
  ip -n "$NT" addr add "$AMONT/24" dev rt0
  ip -n "$NH" addr add "$DHCP/24" dev rp0
  ip -n "$NP" link set "$TUN" up
  ip -n "$NP" link set "$PHY" up
  ip -n "$NT" link set rt0 up
  ip -n "$NH" link set rp0 up

  ip netns exec "$NT" python3 "$BAC/repondeur.py" "$AMONT" 53 "$BAC/rep-t.log" > /dev/null 2>&1 &
  noter $! "$(stat -L -c %i "/run/netns/$NT")"
  ip netns exec "$NH" python3 "$BAC/repondeur.py" "$DHCP" 53 "$BAC/rep-h.log" > /dev/null 2>&1 &
  noter $! "$(stat -L -c %i "/run/netns/$NH")"
  for _ in $(seq 1 50); do
    if grep -q '^pret' "$BAC/rep-t.log" 2> /dev/null && grep -q '^pret' "$BAC/rep-h.log" 2> /dev/null; then
      break
    fi
    sleep 0.1
  done
  grep -q '^pret' "$BAC/rep-t.log"
  grep -q '^pret' "$BAC/rep-h.log"

  # Les intentions que la preuve lit.
  jq -n --arg t "$TUN" --arg l "$LOCAL" --arg a "$AMONT" --arg b "$AMONT6" \
    '{schema_version:1, backend:"systemd-resolved", interface:$t, local_resolver:$l,
      upstream:[$a,$b], embarque:false, resolveur_uid:null}' > "$BAC/i-resolved.json"
  jq '.backend = "resolv-conf"' "$BAC/i-resolved.json" > "$BAC/i-resolvconf.json"
  jq --argjson u "$U_RESOLVEUR" '.embarque = true | .resolveur_uid = $u' "$BAC/i-resolved.json" > "$BAC/i-embarque.json"
  jq --argjson u "$((U_RESOLVEUR + 1))" '.embarque = true | .resolveur_uid = $u' "$BAC/i-resolved.json" > "$BAC/i-embarque-autre.json"
  chmod 644 "$BAC"/i-*.json

  export BAC CLI POSE NQ HOTE_DEV_BUS
  ip netns exec "$NP" unshare -m --propagation private bash "$BAC/banc.sh" --interieur
  CAS=$(grep -c '^PASSED' "$BAC/passes.txt")
}

case "${1:-}" in
  --interieur) interieur ;;
  --imbrique) imbrique "$2" ;;
  *) exterieur ;;
esac
