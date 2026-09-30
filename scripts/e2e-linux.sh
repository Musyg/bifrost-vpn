#!/usr/bin/env bash
# Recette Linux de bout en bout, confinee dans des namespaces reseau.
#
# Pourquoi des namespaces: armer le kill switch dans le namespace initial coupe
# tout le trafic sortant de la machine, y compris la session SSH depuis
# laquelle on lance le test. Le confinement n'est pas une commodite, c'est ce
# qui rend le test rejouable sur une machine distante.
#
# Verifie les points 1, 2 et 3 de la definition of done:
#   1. connect monte le tunnel, status le confirme
#   2. ip link del pendant une connexion active ne produit aucun paquet en clair
#   3. check execute tous les vecteurs et affiche un verdict par vecteur
# et, en chemin, le resolveur embarque lance PAR le daemon, la declaration de
# la politique posee, la reprise apres veille et la deconnexion.
#
# AVEC `--unite`, le daemon est lance avec les seules capacites que l'unite
# designee donne au service: `setpriv` lui pose le CapabilityBoundingSet et les
# AmbientCapabilities LUS dans le fichier, plus NoNewPrivileges. C'est ce que
# systemd fait des capacites d'un service root; le reste du durcissement de
# l'unite (ProtectSystem, SystemCallFilter...) n'est PAS reproduit, et ce banc
# ne remplace pas une mesure sous systemd. Sans CAP_SYS_ADMIN, `check` doit le
# DIRE vecteur par vecteur et nommer la commande qui mesure hors du service; le
# banc lance ensuite cette commande, dans un espace de noms jetable, pour
# prouver qu'elle mesure.
#
# Rien ne touche a l'hote: les interfaces naissent dans les namespaces, le
# daemon voit un /etc et un /var/lib superposes et ne voit pas
# systemd-resolved, et tout processus est termine par le PID releve a son
# lancement, jamais par un motif de nom.
#
# Usage: sudo ./scripts/e2e-linux.sh [chemin/vers/target/debug] [--unite FICHIER]

set -euo pipefail

BIN=""
UNITE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --unite) UNITE="${2:?--unite demande le chemin d une unite systemd}"; shift 2 ;;
    *) BIN="$1"; shift ;;
  esac
done
BIN="${BIN:-$(cd "$(dirname "$0")/.." && pwd)/target/debug}"
if [ -n "$UNITE" ]; then
  [ -f "$UNITE" ] || { echo "unite introuvable: $UNITE"; exit 1; }
  UNITE=$(cd "$(dirname "$UNITE")" && pwd)/$(basename "$UNITE")
fi

# Compte declare comme celui des coeurs. Numerique et non nominal: la recette
# ne cree aucun compte, et 65534 est `nobody` partout ou elle tourne.
COEUR_UID=65534
# Compte du resolveur chiffre. DISTINCT de celui du coeur, et c'est la
# propriete que la recette doit pouvoir observer: le coeur est exempte du kill
# switch, le resolveur ne l'est jamais. `daemon` (uid 1) plutot qu'un compte
# fabrique pour l'occasion, meme raison que `nobody` pour le coeur: il existe
# sur toute distribution et la recette ne cree aucun compte systeme.
RESOLVEUR_UID=1

NS_SRV=bifrost-e2e-server
NS_CLI=bifrost-e2e-client
VETH_S=veth-e2es
VETH_C=veth-e2ec
SRV_ADDR=10.99.0.1
CLI_ADDR=10.99.0.2
WG_PORT=51820
TUN_SRV=10.99.9.1
TUN_CLI=10.99.9.2
NOM_RESOLU=bifrost.test
DNS_ATTENDU=10.99.9.42
# Espace de noms ou le banc lance le harnais HORS du service, en root complet.
NS_HORS=bifrost-e2e-hors
# Noms FIXES des espaces de noms du harnais de fuite (checks/netns.rs). Le
# harnais detruit ce qui porte ces noms avant de monter les siens: si un autre
# banc les tient, lancer `check` le lui retirerait sous les pieds.
NS_HARNAIS="bifrost-check-client bifrost-check-phys"

WORK=$(mktemp -d /tmp/bifrost-e2e.XXXXXX)
# Traversable par tous: le resolveur tourne sous son propre compte et doit
# atteindre son binaire et sa configuration. Le depot, lui, peut vivre sous un
# repertoire personnel ferme aux autres comptes, d'ou la copie des binaires.
chmod 755 "$WORK"
mkdir -m 755 "$WORK/bin"
DAEMON="$WORK/bin/bifrost-daemon"
CLI="$WORK/bin/bifrost-cli"
FAUX_DNSCRYPT="$WORK/bin/faux-dnscrypt-proxy"
SOCKET="$WORK/daemon.sock"
PROFILE="$WORK/tunnel.toml"
PCAP="$WORK/killswitch.pcap"
DAEMON_LOG="$WORK/daemon.log"
PID_DAEMON=""
PID_AMONT=""
PID_CAPTURE=""
PID_RESOLVEUR=""
ORPHELINS=0

ok()   { printf '  OK    %s\n' "$1"; }
fail() { printf '  ECHEC %s\n' "$1"; FAILURES=$((FAILURES + 1)); }
step() { printf '\n== %s\n' "$1"; }
FAILURES=0

# Numeros des capacites, capabilities(7). Le banc calcule lui-meme les masques
# qu'il attend dans /proc au lieu de les recopier d'un autre outil.
NUMEROS="chown:0 dac_override:1 dac_read_search:2 fowner:3 fsetid:4 kill:5
setgid:6 setuid:7 setpcap:8 linux_immutable:9 net_bind_service:10
net_broadcast:11 net_admin:12 net_raw:13 ipc_lock:14 ipc_owner:15
sys_module:16 sys_rawio:17 sys_chroot:18 sys_ptrace:19 sys_pacct:20
sys_admin:21 sys_boot:22 sys_nice:23 sys_resource:24 sys_time:25
sys_tty_config:26 mknod:27 lease:28 audit_write:29 audit_control:30
setfcap:31 mac_override:32 mac_admin:33 syslog:34 wake_alarm:35
block_suspend:36 audit_read:37 perfmon:38 bpf:39 checkpoint_restore:40"

# `CAP_NET_ADMIN` -> `net_admin`, la forme de setpriv.
nom_court() {
  local c
  c=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')
  printf '%s' "${c#cap_}"
}

numero_de() {
  local paire
  for paire in $NUMEROS; do
    if [ "${paire%%:*}" = "$1" ]; then
      printf '%s' "${paire#*:}"
      return 0
    fi
  done
  echo "capacite inconnue du banc: $1" >&2
  return 1
}

# Masque de /proc/<pid>/status pour une liste de noms, sur 16 chiffres hexa.
masque_de() {
  local m=0 c n
  for c in $1; do
    n=$(numero_de "$(nom_court "$c")") || return 1
    m=$(( m | (1 << n) ))
  done
  printf '%016x' "$m"
}

# Liste pour setpriv: tout retirer, puis ajouter ce que l'unite nomme.
liste_setpriv() {
  local s="-all" c
  for c in $1; do s="$s,+$(nom_court "$c")"; done
  printf '%s' "$s"
}

# Lit une directive de capacites dans le [Service] de l'unite.
#
# Le banc n'evalue que la forme que l'unite livree emploie: UNE affectation,
# une liste de noms, sans `~`. Plusieurs lignes qui se cumulent, une inversion
# ou une remise a zero sont REFUSEES plutot que mal lues: un banc qui
# appliquerait d'autres capacites que celles de l'unite mesurerait autre chose
# qu'elle. La garde sans privilege qui evalue toutes ces formes est
# crates/bifrost-daemon/tests/unite_systemd.rs.
capacites_de() {
  local lignes valeur
  lignes=$(sed -n '/^\[Service\]/,/^\[/p' "$UNITE" \
    | sed -e ':a' -e '/\\$/{N; s/\\\n[[:space:]]*/ /; ta}' \
    | grep -E "^[[:space:]]*$1[[:space:]]*=" || true)
  if [ "$(printf '%s\n' "$lignes" | grep -c .)" -ne 1 ]; then
    echo "$1: une seule affectation attendue dans $UNITE" >&2
    return 1
  fi
  valeur=${lignes#*=}
  case "$valeur" in
    *'~'*) echo "$1: inversion non evaluee par le banc: [$valeur]" >&2; return 1 ;;
  esac
  # Sans guillemets: la liste est rendue sur une ligne, blancs normalises.
  # shellcheck disable=SC2086
  echo $valeur
}

# Un processus vivant, pas un zombie: un enfant mort que personne n'a recolte
# garde son /proc et passerait pour vivant.
vivant() {
  [ -n "$1" ] && [ -e "/proc/$1" ] \
    && ! grep -q '^State:[[:space:]]*Z' "/proc/$1/status" 2>/dev/null
}

# Termine un processus par le PID releve a son lancement. JAMAIS par un motif
# de ligne de commande: un motif atteint aussi ce qui n'est pas a nous, la
# session depuis laquelle on lance le banc comprise. SIGTERM, puis SIGKILL
# s'il s'attarde, puis recolte.
terminer() {
  local pid="$1" i
  [ -n "$pid" ] || return 0
  kill "$pid" 2>/dev/null || true
  for i in $(seq 1 20); do
    vivant "$pid" || break
    sleep 0.25
  done
  if vivant "$pid"; then kill -9 "$pid" 2>/dev/null || true; fi
  wait "$pid" 2>/dev/null || true
}

# Champ de /proc/<pid>/status, sans son nom.
champ() {
  awk -v c="$2:" '$1 == c { print $2 }' "/proc/$1/status" 2>/dev/null
}

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

# Retire un espace de noms et compte ce qui lui survit.
#
# L'inode est releve AVANT le retrait: il survit au nom, et c'est par lui
# qu'on retrouve un processus reste dans un espace devenu anonyme. Un
# survivant est un echec du banc, pas un detail de menage.
retirer_netns() {
  local ns="$1" inode p reste=0
  [ -e "/run/netns/$ns" ] || return 0
  inode=$(stat -L -c %i "/run/netns/$ns" 2>/dev/null || true)
  vider_netns "$ns"
  ip netns del "$ns" 2>/dev/null || true
  [ -n "$inode" ] || return 0
  for p in /proc/[0-9]*; do
    if [ "$(stat -L -c %i "$p/ns/net" 2>/dev/null)" = "$inode" ]; then
      reste=$((reste + 1))
    fi
  done
  if [ "$reste" -ne 0 ]; then
    printf '  ECHEC %s processus survivent a l espace de noms %s\n' "$reste" "$ns"
    ORPHELINS=$((ORPHELINS + reste))
  fi
}

# Nettoyage reseau seul: appele aussi AVANT le montage pour repartir d'un banc
# propre, sans toucher au repertoire de travail qui vient d'etre cree.
cleanup_net() {
  terminer "$PID_CAPTURE"
  terminer "$PID_DAEMON"
  terminer "$PID_AMONT"
  PID_CAPTURE=""; PID_DAEMON=""; PID_AMONT=""
  retirer_netns "$NS_CLI"
  retirer_netns "$NS_SRV"
  retirer_netns "$NS_HORS"
}

# Vrai quand les noms du harnais etaient libres au depart: ce qui les porte a
# la sortie a donc ete cree par ce banc, et lui revient a retirer.
HARNAIS_A_NOUS=0

cleanup() {
  local ns
  cleanup_net
  if [ "$HARNAIS_A_NOUS" = 1 ]; then
    for ns in $NS_HARNAIS; do retirer_netns "$ns"; done
  fi
  rm -rf "$WORK"
}

# Etat du resolveur de la MACHINE, nature et contenu.
#
# `stat` sans -L: c'est la nature du chemin lui-meme qui compte, pas celle de
# sa cible. Un lien remplace par un fichier de meme contenu est precisement le
# defaut a detecter, et `-L` les rendrait indiscernables.
empreinte_resolv() {
  local nature corps
  nature=$(stat -c '%F %a' /etc/resolv.conf 2>/dev/null || echo absent)
  if [ -L /etc/resolv.conf ]; then
    corps=$(readlink /etc/resolv.conf)
  else
    corps=$(sha256sum /etc/resolv.conf 2>/dev/null | cut -d' ' -f1)
  fi
  echo "$nature $corps"
}
trap cleanup EXIT

[ "$(id -u)" -eq 0 ] || { echo "ce script doit tourner en root"; exit 1; }
[ -x "$BIN/bifrost-daemon" ] || { echo "binaire introuvable: $BIN/bifrost-daemon"; exit 1; }
[ -x "$BIN/bifrost-cli" ] || { echo "binaire introuvable: $BIN/bifrost-cli"; exit 1; }
for outil in ip nft tcpdump setpriv unshare nsenter jq getent ss; do
  command -v "$outil" >/dev/null 2>&1 || { echo "outil absent: $outil"; exit 1; }
done
for ns in $NS_HARNAIS; do
  if [ -e "/run/netns/$ns" ]; then
    echo "l'espace de noms $ns existe deja: un autre banc fait tourner le harnais, et check le lui retirerait"
    exit 1
  fi
done
HARNAIS_A_NOUS=1
install -m 755 "$BIN/bifrost-daemon" "$DAEMON"
install -m 755 "$BIN/bifrost-cli" "$CLI"
# Ce que la machine porte avant le banc, pour dire apres qu'il n'y a rien laisse.
VARLIB_AVANT=$(stat -c '%F' /var/lib/bifrost 2>/dev/null || echo absent)

# Les capacites que l'unite donne au service, quand on en designe une.
BORNES=""
AMBIANTES=""
LANCEUR=()
if [ -n "$UNITE" ]; then
  step "Capacites lues dans $UNITE"
  BORNES=$(capacites_de CapabilityBoundingSet) || exit 1
  AMBIANTES=$(capacites_de AmbientCapabilities) || exit 1
  MASQUE_BORNES=$(masque_de "$BORNES") || exit 1
  MASQUE_AMBIANTES=$(masque_de "$AMBIANTES") || exit 1
  printf '        bornes:   %s (%s)\n        ambiant:  %s (%s)\n' \
    "$BORNES" "$MASQUE_BORNES" "$AMBIANTES" "$MASQUE_AMBIANTES"
  # L'ordre de setpriv est celui de systemd: bornes, heritables, ambiant.
  # L'ambiant exige que la capacite soit heritable, d'ou les deux listes.
  LANCEUR=(setpriv --no-new-privs
           --bounding-set "$(liste_setpriv "$BORNES")"
           --inh-caps "$(liste_setpriv "$AMBIANTES")"
           --ambient-caps "$(liste_setpriv "$AMBIANTES")" --)
  ok "le daemon sera lance avec ces seules capacites, NoNewPrivileges compris"
fi
SYS_ADMIN=$(numero_de sys_admin)
if [ -z "$UNITE" ] || [ $(( 0x${MASQUE_BORNES} >> SYS_ADMIN & 1 )) -eq 1 ]; then
  DOTE_SYS_ADMIN=1
else
  DOTE_SYS_ADMIN=0
fi

step "Preparation du banc"
cleanup_net
ip netns add "$NS_SRV"
ip netns add "$NS_CLI"
# Le lien nait DANS les namespaces: le creer dans celui de l'hote puis l'y
# deplacer poserait, le temps d'une commande, deux interfaces sur la machine.
ip -n "$NS_CLI" link add "$VETH_C" type veth peer name "$VETH_S" netns "$NS_SRV"
for pair in "$NS_SRV $VETH_S $SRV_ADDR" "$NS_CLI $VETH_C $CLI_ADDR"; do
  set -- $pair
  ip -n "$1" link set lo up
  ip -n "$1" addr add "$3/24" dev "$2"
  ip -n "$1" link set "$2" up
done
ip -n "$NS_CLI" route add default via "$SRV_ADDR"
ok "namespaces $NS_SRV et $NS_CLI relies"

step "Generation des cles"
umask 077
read -r SRV_PRIV SRV_PUB <<<"$("$DAEMON" --genkey)"
read -r CLI_PRIV CLI_PUB <<<"$("$DAEMON" --genkey)"
ok "deux paires de cles generees"

step "Serveur WireGuard dans $NS_SRV"
ip -n "$NS_SRV" link add wgsrv type wireguard
ip netns exec "$NS_SRV" "$DAEMON" --wg-apply "$(cat <<JSON
{"interface":"wgsrv","private_key":"$SRV_PRIV","listen_port":$WG_PORT,
 "peers":[{"public_key":"$CLI_PUB","allowed_ips":["$TUN_CLI/32"]}]}
JSON
)"
ip -n "$NS_SRV" addr add "$TUN_SRV/24" dev wgsrv
ip -n "$NS_SRV" link set wgsrv up
ok "serveur en ecoute sur $SRV_ADDR:$WG_PORT"

step "Resolveur au bout du tunnel"
# Le vecteur dns-leak prouve qu'aucune requete ne SORT. Pris seul il passerait
# a l'identique sur un Bifrost dont la resolution serait entierement cassee:
# zero paquet en clair, zero paquet tout court. Ce resolveur donne au banc de
# quoi mesurer l'autre moitie, que la resolution FONCTIONNE encore.
#
# Il n'ecoute que sur l'adresse du tunnel: une requete qui l'atteint a
# forcement traverse wgc, donc elle etait chiffree sur le fil.
# `ip netns exec` remplace son processus par la commande, sans fork: `$!` est
# donc le PID du resolveur lui-meme, et c'est par lui qu'il sera termine.
ip netns exec "$NS_SRV" "$DAEMON" \
  --faux-resolveur "$TUN_SRV:53" --faux-resolveur-adresse "$DNS_ATTENDU" \
  >"$WORK/resolveur.log" 2>&1 &
PID_AMONT=$!
for _ in $(seq 1 20); do
  ip netns exec "$NS_SRV" ss -lun 2>/dev/null | grep "$TUN_SRV:53" >/dev/null && break
  sleep 0.25
done
if ip netns exec "$NS_SRV" ss -lun 2>/dev/null | grep "$TUN_SRV:53" >/dev/null; then
  ok "faux resolveur en ecoute sur $TUN_SRV:53"
else
  fail "le faux resolveur n'ecoute pas"; cat "$WORK/resolveur.log"
fi

step "Profil client"
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
upstream = ["$TUN_SRV"]
# Un resolveur ecoute reellement sur 127.0.0.1:53 dans ce namespace, lance plus
# bas: resolv.conf doit donc pointer sur LUI et non sur l'amont.
embarque = true
TOML
chmod 600 "$PROFILE"
ok "profil ecrit en 600"

step "Demarrage du daemon dans $NS_CLI"
# `--coeur-utilisateur nobody`: c'est ce qui fait de cette recette le temoin
# du cablage entre le daemon et le coeur. Le compte declare ici doit se
# retrouver dans les regles REELLEMENT posees, et non seulement dans une
# politique en memoire. `nobody` parce qu'il existe partout, y compris sur un
# runner d'integration continue, et parce que la recette n'a pas a fabriquer
# de compte systeme sur la machine qui l'execute.
# `ip netns exec` ne change QUE le namespace reseau: le systeme de fichiers
# reste celui de la machine. Sans l'isolation qui suit, le daemon ecrit dans le
# /etc/resolv.conf REEL de la machine qui execute la recette.
#
# Ce n'est pas une precaution theorique. Mesure du 17/08/2026 sur essai-linux: une
# execution de cette recette a remplace le lien symbolique /etc/resolv.conf par
# un fichier ordinaire en mode 600 root, laissant la machine sans resolution de
# noms pour tout processus non privilegie, bien apres la fin de la recette.
#
# Un `mount --bind` sur le seul fichier ne suffit PAS, mesure aussi: bind SUIT
# les liens symboliques, donc il se pose sur la cible (stub-resolv.conf) et
# laisse /etc/resolv.conf intact, en lien. Le daemon renomme ensuite par-dessus
# ce lien, dans le /etc partage, et la machine est touchee malgre le namespace.
#
# Un overlay sur /etc entier repond a la vraie contrainte: le daemon doit voir
# un /etc complet et inscriptible dont les ecritures n'atteignent pas la
# machine. Ce qu'il modifie atterrit dans etc-haut, sous $WORK, efface avec lui.
#
# Deux fuites de la meme famille, trouvees le 30/09/2026 en preparant ce banc
# pour une machine qui fait tourner systemd-resolved:
#
#   - le daemon choisit resolvectl des que /run/systemd/resolve/stub-resolv.conf
#     existe. Or resolvectl parle au systemd-resolved de l'HOTE, par D-Bus, qu'un
#     namespace reseau n'isole pas, et lui designe l'interface par un index pris
#     dans le namespace du banc: celui d'une interface de la machine, peut-etre.
#     Le banc masque donc ce repertoire, et le daemon ecrit son resolv.conf;
#   - le daemon ecrit sa sauvegarde et son carnet sous /var/lib/bifrost, et le
#     creait sur la machine. /var/lib est superpose comme /etc.
#
# `ip netns exec`, `unshare` sans --fork, `sh -c ... exec` et `setpriv`
# remplacent chacun leur processus par le suivant: `$!` est le PID du daemon,
# ce que le banc verifie ensuite par /proc au lieu de le supposer.
cat >"$FAUX_DNSCRYPT" <<RESOLVEUR
#!/bin/sh
# Doublure de dnscrypt-proxy, ecrite par e2e-linux.sh. Le daemon la lance comme
# le vrai: sous le compte du resolveur, avec -config. Elle ignore ses arguments
# et sert le :53 de la boucle locale en relayant vers l'amont, par le tunnel.
exec "$DAEMON" --faux-resolveur 127.0.0.1:53 --faux-resolveur-amont $TUN_SRV:53
RESOLVEUR
chmod 755 "$FAUX_DNSCRYPT"
GROUPE=$(getent group 65534 | cut -d: -f1)
[ -n "$GROUPE" ] || { echo "aucun groupe 65534 sur cette machine"; exit 1; }
# shellcheck disable=SC2016
ip netns exec "$NS_CLI" unshare --mount --propagation private sh -c '
  set -e
  mkdir -p "$1/etc-haut" "$1/etc-travail" "$1/varlib-haut" "$1/varlib-travail"
  mount -t overlay bifrost-etc -o "lowerdir=/etc,upperdir=$1/etc-haut,workdir=$1/etc-travail" /etc
  mount -t overlay bifrost-varlib -o "lowerdir=/var/lib,upperdir=$1/varlib-haut,workdir=$1/varlib-travail" /var/lib
  if [ -d /run/systemd/resolve ]; then
    mount -t tmpfs -o mode=0755 bifrost-sans-resolved /run/systemd/resolve
  fi
  shift
  exec "$@"' sh "$WORK" "${LANCEUR[@]}" "$DAEMON" \
    --socket "$SOCKET" --group "$GROUPE" \
    --coeur-utilisateur "$COEUR_UID:$COEUR_UID" \
    --resolveur-utilisateur "$RESOLVEUR_UID:$RESOLVEUR_UID" \
    --resolveur-binaire "$FAUX_DNSCRYPT" \
    --resolveur-configuration "$WORK/resolveur/dnscrypt-proxy.toml" \
    --resolveur-etat "$WORK/resolveur-etat" \
  >"$DAEMON_LOG" 2>&1 &
PID_DAEMON=$!
for _ in $(seq 1 40); do [ -S "$SOCKET" ] && break; sleep 0.25; done
[ -S "$SOCKET" ] || { echo "le daemon n'a pas ouvert $SOCKET"; cat "$DAEMON_LOG"; exit 1; }

# Les sondes de resolution entrent dans SON namespace de montage pour voir le
# meme resolv.conf: il faut donc que ce PID soit bien le sien.
if [ "$(readlink "/proc/$PID_DAEMON/exe" 2>/dev/null)" != "$DAEMON" ]; then
  echo "le PID $PID_DAEMON n'est pas celui du daemon: $(readlink "/proc/$PID_DAEMON/exe" 2>&1)"
  cat "$DAEMON_LOG"
  exit 1
fi
DAEMON_REEL=$PID_DAEMON
ok "daemon en ecoute (pid $DAEMON_REEL), resolv.conf et /var/lib isoles de la machine"

if [ -n "$UNITE" ]; then
  step "Le daemon n'a que les capacites de l'unite"
  # Ce que le noyau lui donne, lu dans /proc, et non ce qu'on a demande a
  # setpriv. Pour un service root, systemd rend l'effectif egal aux bornes, et
  # l'ambiant a ce que l'unite y met.
  for attendu in "CapBnd $MASQUE_BORNES" "CapPrm $MASQUE_BORNES" \
                 "CapEff $MASQUE_BORNES" "CapAmb $MASQUE_AMBIANTES" "NoNewPrivs 1"; do
    set -- $attendu
    vu=$(champ "$DAEMON_REEL" "$1")
    if [ "$vu" = "$2" ]; then
      ok "$1 = $vu"
    else
      fail "$1 = ${vu:-illisible}, attendu $2"
    fi
  done
fi

# Temoin de l'isolation elle-meme. Sans lui, une regression qui remettrait le
# daemon dans le namespace de montage de la machine ne se verrait qu'a la
# prochaine fois que quelqu'un remarque que sa resolution de noms est cassee.
RESOLV_AVANT=$(empreinte_resolv)

# --- DoD 1 ---------------------------------------------------------------
step "DoD 1: connect monte le tunnel et status le confirme"
if ip netns exec "$NS_CLI" "$CLI" --socket "$SOCKET" connect --config "$PROFILE"; then
  ok "connect a repondu sans erreur"
else
  fail "connect a echoue"; cat "$DAEMON_LOG"; exit 1
fi

# Le handshake est declenche par du trafic; on laisse le keepalive agir.
for _ in $(seq 1 20); do
  ip netns exec "$NS_CLI" ping -c1 -W1 "$TUN_SRV" >/dev/null 2>&1 || true
  STATUS=$(ip netns exec "$NS_CLI" "$CLI" --socket "$SOCKET" --json status)
  echo "$STATUS" | grep '"connected"' >/dev/null && break
  sleep 0.5
done

echo "$STATUS" | sed 's/^/    /'
echo "$STATUS" | grep '"state": *"connected"' >/dev/null && ok "status = connected" \
  || fail "status n'est pas connected"
echo "$STATUS" | grep '"kill_switch_engaged": *true' >/dev/null && ok "kill switch arme" \
  || fail "kill switch non arme alors que le tunnel est monte"

if ip netns exec "$NS_CLI" ping -c2 -W2 "$TUN_SRV" >/dev/null 2>&1; then
  ok "trafic achemine dans le tunnel ($TUN_CLI -> $TUN_SRV)"
else
  fail "le tunnel ne transporte rien"
fi

# --- Le resolveur embarque ------------------------------------------------
step "Le daemon a lance le resolveur embarque, sous son compte"
# La forme de dnscrypt-proxy, moins le chiffrement: il ecoute sur 127.0.0.1:53
# et relaie vers l'amont, a travers le tunnel. Ce que le banc eprouve n'est pas
# DoH, dont les auteurs de dnscrypt-proxy repondent, mais ce que le DAEMON en
# fait: il ecrit sa configuration et la lui donne (CAP_CHOWN), prend son
# compte avant l'exec (CAP_SETUID, CAP_SETGID), ne lui laisse que de quoi se
# lier au :53 (CAP_NET_BIND_SERVICE), et l'arretera a la deconnexion (CAP_KILL).
PID_RESOLVEUR=$(ip netns exec "$NS_CLI" ss -Hlunp 'sport = :53' 2>/dev/null \
  | grep '127.0.0.1:53' | sed -n 's/.*pid=\([0-9]*\).*/\1/p' | sed -n 1p)
if [ -n "$PID_RESOLVEUR" ] && [ "$(champ "$PID_RESOLVEUR" Uid)" = "$RESOLVEUR_UID" ]; then
  ok "resolveur en ecoute sur 127.0.0.1:53 (pid $PID_RESOLVEUR), sous l'uid $RESOLVEUR_UID"
else
  fail "aucun resolveur sous l'uid $RESOLVEUR_UID sur 127.0.0.1:53 (pid ${PID_RESOLVEUR:-aucun})"
  sed 's/^/        /' "$DAEMON_LOG"
fi
if [ -n "$PID_RESOLVEUR" ]; then
  RESTE=$(printf '%016x' $(( 1 << $(numero_de net_bind_service) )))
  for ensemble in CapEff CapPrm CapAmb; do
    vu=$(champ "$PID_RESOLVEUR" "$ensemble")
    if [ "$vu" = "$RESTE" ]; then
      ok "$ensemble du resolveur reduit a CAP_NET_BIND_SERVICE"
    else
      fail "$ensemble du resolveur = ${vu:-illisible}, attendu $RESTE"
    fi
  done
fi

# --- Le DNS marche encore -------------------------------------------------
step "Kill switch arme, la resolution de noms fonctionne toujours"
# Le complement de dns-leak, et la raison d'etre de toute cette etape: un kill
# switch qui bloque le DNS au lieu de le rerouter passerait dns-leak avec les
# honneurs. Zero requete en clair, zero requete du tout, et un utilisateur qui
# ne peut plus ouvrir une page.
#
# `nsenter -m -n` et non `ip netns exec`: la sonde doit voir le MEME
# resolv.conf que le daemon, celui du montage isole plus haut. Avec
# `ip netns exec` elle lirait celui de la machine et mesurerait la resolution
# de l'hote, ce qui passerait toujours et ne prouverait rien.
RESOLUTION=$(nsenter -t "$DAEMON_REEL" -m -n -- "$DAEMON" --resoudre "$NOM_RESOLU" 2>&1) \
  && RESOLU=oui || RESOLU=non
if [ "$RESOLU" = oui ] && echo "$RESOLUTION" | grep -x "$DNS_ATTENDU" >/dev/null; then
  ok "$NOM_RESOLU resolu en $DNS_ATTENDU a travers le tunnel"
else
  fail "resolution impossible avec le kill switch arme"
  echo "$RESOLUTION" | sed 's/^/        /'
  nsenter -t "$DAEMON_REEL" -m -n -- cat /etc/resolv.conf | sed 's/^/        /'
fi

# Et la reponse doit etre venue du tunnel, pas d'un resolveur de la machine
# qui aurait repondu par hasard. Seul le faux resolveur sert cette adresse.
if grep -q "faux resolveur" "$WORK/resolveur.log" \
   && [ "$(grep -c . "$WORK/resolveur.log")" -ge 1 ]; then
  ok "la reponse vient du resolveur place au bout du tunnel"
fi

# C'est ICI que l'isolation se mesure, tunnel monte, et non a la fin. Le
# gestionnaire DNS rend fidelement l'etat d'origine a la deconnexion: une
# recette qui ne regarde qu'apres coup ne verrait donc RIEN, meme en ecrivant
# dans le resolveur de la machine. Ce qu'elle manquerait: pendant toute la
# duree du tunnel, la machine hote pointerait sur un resolveur joignable
# seulement depuis le banc, et n'aurait plus de resolution du tout.
if [ "$(empreinte_resolv)" = "$RESOLV_AVANT" ]; then
  ok "le resolveur de la machine est intact PENDANT que le tunnel est monte"
else
  fail "le daemon du banc a reconfigure le resolveur de la machine"
  printf '        avant:   %s\n        pendant: %s\n' "$RESOLV_AVANT" "$(empreinte_resolv)"
fi
# Et le temoin que le daemon a pris le chemin du fichier, pas celui de
# resolvectl: le resolv.conf qu'IL voit porte sa marque. Sans cela, un daemon
# qui aurait parle au systemd-resolved de la machine passerait le controle
# ci-dessus, qui ne regarde que le fichier de l'hote.
if nsenter -t "$DAEMON_REEL" -m -- grep -q "genere par bifrost" /etc/resolv.conf 2>/dev/null; then
  ok "le daemon a ecrit SON resolv.conf, dans le /etc superpose"
else
  fail "le resolv.conf du daemon ne porte pas sa marque: a-t-il parle a systemd-resolved?"
fi

# --- Le resolveur embarque ne se contourne pas -----------------------------
step "Aucune application ne peut choisir son propre resolveur"
# Le trou que la restriction ferme, et qu'aucun vecteur ne voyait. `oifname
# <tunnel> accept` accepte tout ce qui sort par le tunnel, requetes DNS
# comprises: une application avec un resolveur en dur l'interrogeait a travers
# le tunnel. Rien ne fuit sur le fil local, donc dns-leak reste vert, mais la
# requete ressort en clair a la sortie du tunnel pendant que l'utilisateur
# croit interroger le resolveur annonce.
#
# La sonde vise l'amont du banc, donc une adresse REELLEMENT joignable par le
# tunnel: viser une adresse morte ferait passer ce controle pour de mauvaises
# raisons.
# Controle POSITIF d'abord. Sans lui, le refus mesure juste apres pourrait
# venir d'un amont muet, d'une route absente ou d'un tunnel casse, et on
# lirait une panne quelconque comme une preuve d'etancheite.
if ip netns exec "$NS_CLI" setpriv --reuid="$RESOLVEUR_UID" --regid="$RESOLVEUR_UID" \
     --clear-groups "$DAEMON" --interroger "$TUN_SRV:53" >/dev/null 2>&1; then
  ok "le resolveur, lui, joint l'amont: la voie existe et repond"
else
  fail "le resolveur ne joint pas l'amont: le refus mesure ensuite ne prouve rien"
fi

# Et le meme geste, depuis un compte ordinaire, doit echouer.
if ip netns exec "$NS_CLI" setpriv --reuid="$COEUR_UID" --regid="$COEUR_UID" \
     --clear-groups "$DAEMON" --interroger "$TUN_SRV:53" >/dev/null 2>&1; then
  fail "une application ordinaire interroge le resolveur de son choix par le tunnel"
else
  ok "une application ordinaire ne peut pas contourner le resolveur embarque"
fi

REGLES_DNS=$(ip netns exec "$NS_CLI" nft list chain inet bifrost output 2>/dev/null || true)
# Le motif est ANCRE en debut de ligne. Sans cela il attraperait aussi le
# `meta skuid <coeur> udp dport 53 drop` du bloc d'exemption, et le controle
# passerait sur une regle qui ne ferme rien pour les applications ordinaires.
# Trouve par mutation le 17/08/2026: sans --resolveur-utilisateur, ce controle
# restait vert.
if echo "$REGLES_DNS" | grep -E "^[[:space:]]*udp dport 53 drop" >/dev/null; then
  ok "les regles vivantes ferment le :53"
else
  fail "aucun drop du :53 dans les regles vivantes"
  echo "$REGLES_DNS" | sed 's/^/        /'
fi
# Et l'ordre, qui est toute la difference entre une regle utile et une regle
# decorative. `nft` rend les regles dans l'ordre d'application.
LIGNE_DROP=$(echo "$REGLES_DNS" | grep -nE "^[[:space:]]*udp dport 53 drop" | sed -n 1p | cut -d: -f1)
LIGNE_TUNNEL=$(echo "$REGLES_DNS" | grep -n "oifname \"wgc\"\|oifname \"wg0\"" | sed -n 1p | cut -d: -f1)
if [ -n "$LIGNE_DROP" ] && [ -n "$LIGNE_TUNNEL" ] && [ "$LIGNE_DROP" -lt "$LIGNE_TUNNEL" ]; then
  ok "le drop du :53 precede l'acceptation du tunnel (lignes $LIGNE_DROP < $LIGNE_TUNNEL)"
else
  fail "le drop du :53 est pose apres l'acceptation du tunnel: sans effet"
  echo "$REGLES_DNS" | sed 's/^/        /'
fi
# L'exception, elle, doit designer le resolveur et lui seul.
if echo "$REGLES_DNS" | grep "meta skuid $RESOLVEUR_UID .*dport 53 accept" >/dev/null; then
  ok "seul l'uid $RESOLVEUR_UID garde le droit d'emettre du :53"
else
  fail "le resolveur n'a pas d'exception: son bootstrap serait bloque"
  echo "$REGLES_DNS" | sed 's/^/        /'
fi

# --- Cablage du coeur -----------------------------------------------------
step "L'identite declaree au daemon se retrouve dans les regles posees"
# Les tests unitaires prouvent que la politique porte l'exemption et que le
# generateur la rend. Ni les uns ni l'autre ne prouvent que le fil entier
# conduit: c'est ici, sur les regles que le noyau applique vraiment, que la
# chaine se verifie de bout en bout.
REGLES=$(ip netns exec "$NS_CLI" nft list table inet bifrost 2>/dev/null || true)
if echo "$REGLES" | grep "meta skuid $COEUR_UID accept" >/dev/null; then
  ok "le compte declare au demarrage est exempte par les regles vivantes"
else
  fail "aucune exemption pour l'uid $COEUR_UID: le daemon ne transmet pas l'identite"
  echo "$REGLES" | sed 's/^/        /'
fi

# L'exemption ne doit pas passer AU-DESSUS de la restriction DNS. Les permits
# DNS sont poses plus haut dans la chaine, donc un skuid nu laisserait le
# coeur interroger n'importe quel resolveur en clair.
if echo "$REGLES" | grep -B2 "meta skuid $COEUR_UID accept" \
     | grep "meta skuid $COEUR_UID .* dport 53 drop" >/dev/null; then
  ok "le :53 du coeur tombe avant son autorisation de sortie"
else
  fail "l'exemption du coeur precede la restriction DNS: fuite DNS rouverte"
fi

# Trois occurrences et pas une de plus: les deux drop sur le :53 et l'accept,
# toutes dans la chaine output. Une quatrieme voudrait dire qu'une exemption
# est apparue en input ou en forward, ou qu'une destination a ete ouverte au
# passage. Compte sur la table ENTIERE, sinon la question ne se poserait pas.
SKUIDS=$(echo "$REGLES" | grep -c "meta skuid $COEUR_UID" || true)
if [ "$SKUIDS" -eq 3 ]; then
  ok "l'exemption ne touche que la sortie ($SKUIDS regles)"
else
  fail "$SKUIDS regles portent l'uid du coeur au lieu de 3"
  echo "$REGLES" | grep "meta skuid" | sed 's/^/        /'
fi

# --- Declaration et reprise -------------------------------------------------
step "La politique que le daemon declare est celle que le noyau porte"
# Lecture seule des deux cotes: la requete de declaration ne change rien au
# daemon, la collecte nft ne pose rien. MATCH veut dire que ce que le daemon
# dit avoir pose est ce qui est pose.
prouver() {
  ip netns exec "$NS_CLI" "$CLI" --socket "$SOCKET" --json prove nft \
    --politique-daemon --actif >"$WORK/preuve.json" 2>"$WORK/preuve.err" || true
  jq -e '.verdict == "MATCH"' "$WORK/preuve.json" >/dev/null 2>&1
}
if prouver; then
  ok "declaration et noyau concordent (MATCH)"
else
  fail "la declaration ne concorde pas avec le noyau"
  sed 's/^/        /' "$WORK/preuve.json" "$WORK/preuve.err"
fi

step "Reprise apres veille: la politique est reposee, l'etat ne bouge pas"
# Le chemin du hook systemd-sleep, sans endormir la machine: la meme commande,
# avec les memes arguments que systemd lui donnerait au reveil.
if ip netns exec "$NS_CLI" "$CLI" --socket "$SOCKET" reprise --phase post --operation suspend \
     >"$WORK/reprise.log" 2>&1; then
  ok "reprise acceptee par le daemon"
else
  fail "reprise refusee"; sed 's/^/        /' "$WORK/reprise.log"
fi
STATUS=$(ip netns exec "$NS_CLI" "$CLI" --socket "$SOCKET" --json status)
if echo "$STATUS" | grep '"state": *"connected"' >/dev/null \
   && echo "$STATUS" | grep '"kill_switch_engaged": *true' >/dev/null; then
  ok "toujours connecte, kill switch arme"
else
  fail "la reprise a change l'etat"; echo "$STATUS" | sed 's/^/        /'
fi
if prouver; then
  ok "apres la reprise, declaration et noyau concordent encore"
else
  fail "apres la reprise, la declaration ne concorde plus"
  sed 's/^/        /' "$WORK/preuve.json" "$WORK/preuve.err"
fi

# --- DoD 2 ---------------------------------------------------------------
step "DoD 2: ip link del wg0 ne produit aucun paquet en clair"
ip netns exec "$NS_SRV" tcpdump -i "$VETH_S" -nn --immediate-mode -U -s 128 -w "$PCAP" >/dev/null 2>"$PCAP.tcpdump" &
PID_CAPTURE=$!
sleep 0.6

ip -n "$NS_CLI" link del wg0
ip netns exec "$NS_CLI" "$DAEMON" --probe all >/dev/null 2>&1 || true
ip netns exec "$NS_CLI" ping -c2 -W1 "$TUN_SRV" >/dev/null 2>&1 || true
ip netns exec "$NS_CLI" ping -c2 -W1 8.8.8.8 >/dev/null 2>&1 || true
sleep 0.6
terminer "$PID_CAPTURE"
PID_CAPTURE=""

# Le pcap est-il complet ? Le zero du controle suivant en depend entierement.
ETAGE_VUS=$(compteur_tcpdump "$PCAP.tcpdump" "received by filter")
ETAGE_REMIS=$(compteur_tcpdump "$PCAP.tcpdump" "captured")
if [ -z "$ETAGE_VUS" ] || [ -z "$ETAGE_REMIS" ]; then
  fail "tcpdump n'a pas rendu ses compteurs: rien ne dit que le pcap est complet"
elif [ "$ETAGE_VUS" -ne "$ETAGE_REMIS" ]; then
  fail "capture incomplete: $ETAGE_VUS paquet(s) vus par le filtre du noyau, $ETAGE_REMIS remis"
else
  ok "capture complete: $ETAGE_VUS vus par le filtre, $ETAGE_REMIS remis"
fi

# Tout ce qui n'est pas du WireGuard chiffre vers l'endpoint, du multicast,
# du broadcast, du DHCP ou du NDP est une fuite.
LEAK_FILTER="(ip or ip6) and not ((udp port $WG_PORT and host $SRV_ADDR) \
 or (net 224.0.0.0/4) or (host 255.255.255.255) \
 or (udp port 67 or udp port 68) or (udp port 546 or udp port 547) \
 or (dst net ff00::/8) \
 or (icmp6 and icmp6[icmp6type] >= 133 and icmp6[icmp6type] <= 137))"

LEAKS=$(tcpdump -r "$PCAP" -nn -c 20 "$LEAK_FILTER" 2>/dev/null | grep -v '^reading' || true)
if [ -z "$LEAKS" ]; then
  ok "zero paquet en clair apres destruction de l'interface"
else
  fail "fuite detectee apres destruction de l'interface"
  echo "$LEAKS" | sed 's/^/        /'
fi

# --- DoD 3 ---------------------------------------------------------------
step "DoD 3: check, par le daemon"
# Le harnais cree ses propres namespaces, depuis celui du daemon, et ne touche
# jamais au pare-feu de l'hote. Le client, lui, n'a besoin que du socket.
#
# doh-bypass juge les politiques des navigateurs INSTALLES sur la machine. Sur
# un hote qui porte un Firefox sans politique, il rend FAILED, et il a raison:
# ce n'est pas le produit qu'il mesure alors, c'est l'hote. Comme la CI avant
# check-strict, le banc pose donc la politique par la commande du produit,
# mais dans le /etc superpose du daemon, jamais sur la machine.
if nsenter -t "$DAEMON_REEL" -m -- "$DAEMON" --doh-policy poser >"$WORK/doh.log" 2>&1; then
  ok "politique DoH posee dans le /etc du daemon"
else
  fail "pose de la politique DoH refusee"; sed 's/^/        /' "$WORK/doh.log"
fi
set +e
"$CLI" --socket "$SOCKET" --json check >"$WORK/check.json"
CHECK_CODE=$?
set -e
jq -r '.outcomes[] | "        \(.verdict)\t\(.vector)\t\(.detail)"' "$WORK/check.json" \
  || { fail "rapport de check illisible"; cat "$WORK/check.json"; }
[ $CHECK_CODE -eq 0 ] && ok "aucun vecteur en echec" || fail "au moins un vecteur en echec"
if [ "$DOTE_SYS_ADMIN" = 0 ]; then
  # Le contrat du service qui n'a pas CAP_SYS_ADMIN: chaque vecteur qui monte
  # un banc le DIT, nomme la capacite qui manque et la commande qui mesure hors
  # du service. Un motif vague, ou un repli qui se tairait, serait rouge ici.
  BANC=$(jq '[.outcomes[] | select(.vector != "doh-bypass")] | length' "$WORK/check.json")
  REFUS=$(jq '[.outcomes[] | select(.vector != "doh-bypass" and .verdict == "SKIPPED"
               and (.detail | contains("CAP_SYS_ADMIN"))
               and (.detail | contains("bifrost-daemon --run-checks")))] | length' "$WORK/check.json")
  if [ "$BANC" -gt 0 ] && [ "$REFUS" = "$BANC" ]; then
    ok "les $BANC vecteurs du banc refusent en nommant CAP_SYS_ADMIN et la commande hors du service"
  else
    fail "$REFUS vecteur(s) sur $BANC disent pourquoi le service ne peut pas les mesurer"
  fi
  # doh-bypass ne monte aucun banc: il lit des fichiers, il conclut encore.
  if jq -e '[.outcomes[] | select(.vector == "doh-bypass" and .verdict != "SKIPPED")] | length == 1' \
       "$WORK/check.json" >/dev/null; then
    ok "doh-bypass conclut quand meme dans le service"
  else
    fail "doh-bypass ne conclut plus dans le service"
  fi
fi

step "Deconnexion"
ip netns exec "$NS_CLI" "$CLI" --socket "$SOCKET" disconnect && ok "disconnect accepte" \
  || fail "disconnect a echoue"
if ip netns exec "$NS_CLI" nft list table inet bifrost >/dev/null 2>&1; then
  fail "la table nftables est encore en place apres disconnect"
else
  ok "kill switch retire"
fi
# Le daemon arrete le resolveur, qui tourne sous un AUTRE compte: sans
# CAP_KILL il le lancerait sans jamais pouvoir l'arreter.
for _ in $(seq 1 20); do vivant "$PID_RESOLVEUR" || break; sleep 0.25; done
if [ -n "$PID_RESOLVEUR" ] && ! vivant "$PID_RESOLVEUR"; then
  ok "le resolveur (pid $PID_RESOLVEUR) est arrete"
else
  fail "le resolveur survit a la deconnexion (pid ${PID_RESOLVEUR:-inconnu})"
fi

if [ "$DOTE_SYS_ADMIN" = 0 ]; then
  step "Le harnais hors du service, comme le message le demande"
  # La commande que `check` vient de nommer, lancee comme elle le dit: en
  # root, hors du service, donc avec toutes les capacites de root. Dans un
  # espace de noms jetable, parce que le banc cree ses interfaces dans celui
  # ou il tourne, et que celui de l'hote n'est pas a nous; et sur un /etc
  # superpose, ou la politique DoH est posee comme pour le daemon.
  ip netns add "$NS_HORS"
  ip -n "$NS_HORS" link set lo up
  set +e
  # shellcheck disable=SC2016
  unshare --mount --propagation private sh -c '
    set -e
    mkdir -p "$1/hors-etc-haut" "$1/hors-etc-travail" "$1/hors-varlib-haut" "$1/hors-varlib-travail"
    mount -t overlay bifrost-etc-hors -o "lowerdir=/etc,upperdir=$1/hors-etc-haut,workdir=$1/hors-etc-travail" /etc
    mount -t overlay bifrost-varlib-hors -o "lowerdir=/var/lib,upperdir=$1/hors-varlib-haut,workdir=$1/hors-varlib-travail" /var/lib
    "$2" --doh-policy poser >"$1/hors-doh.log" 2>&1
    exec ip netns exec "$3" "$2" --run-checks --json' sh "$WORK" "$DAEMON" "$NS_HORS" \
    >"$WORK/hors.json" 2>"$WORK/hors.err"
  HORS_CODE=$?
  set -e
  jq -r '.outcomes[] | "        \(.verdict)\t\(.vector)\t\(.detail)"' "$WORK/hors.json" \
    || { fail "rapport de --run-checks illisible"; sed 's/^/        /' "$WORK/hors.err"; }
  if jq -e '[.outcomes[] | select(.detail | contains("CAP_SYS_ADMIN"))] | length == 0' \
       "$WORK/hors.json" >/dev/null 2>&1 \
     && jq -e '[.outcomes[] | select(.verdict == "PASSED")] | length > 1' \
       "$WORK/hors.json" >/dev/null 2>&1; then
    ok "hors du service, le harnais monte ses bancs et conclut"
  else
    fail "hors du service, le harnais ne mesure toujours pas"
  fi
  [ "$HORS_CODE" -eq 0 ] && ok "aucun vecteur en echec hors du service" \
    || fail "au moins un vecteur en echec hors du service"
fi

step "La recette n'a pas touche au resolveur de la machine"
# La verification que cette recette aurait du avoir depuis le debut. Le 17 aout
# 2026 elle a casse la resolution de noms d'essai-linux, et rien dans sa sortie ne
# l'a signale: elle affichait "tout est passe".
RESOLV_APRES=$(empreinte_resolv)
if [ "$RESOLV_AVANT" = "$RESOLV_APRES" ]; then
  ok "/etc/resolv.conf intact ($RESOLV_APRES)"
else
  fail "/etc/resolv.conf modifie: $RESOLV_AVANT devenu $RESOLV_APRES"
fi

VARLIB_APRES=$(stat -c '%F' /var/lib/bifrost 2>/dev/null || echo absent)
if [ "$VARLIB_AVANT" = "$VARLIB_APRES" ]; then
  ok "/var/lib/bifrost de la machine inchange ($VARLIB_APRES)"
else
  fail "/var/lib/bifrost de la machine: $VARLIB_AVANT devenu $VARLIB_APRES"
fi

step "Absence de processus residuel"
# Un processus root survivant au script bloque le nettoyage de tout appelant
# qui n'est pas root, un runner d'integration continue par exemple. On verifie
# donc explicitement plutot que d'esperer: chaque espace de noms est retire
# apres avoir ete vide par PID, et ce qui vit encore dans son inode est compte.
ORPHELINS=0
cleanup_net
for ns in $NS_HARNAIS; do
  if [ -e "/run/netns/$ns" ]; then
    fail "le harnais a laisse l'espace de noms $ns derriere lui"
    retirer_netns "$ns"
  fi
done
if [ "$ORPHELINS" -eq 0 ]; then
  ok "aucun processus du banc ne survit a ses espaces de noms"
else
  fail "$ORPHELINS processus du banc survivent a leurs espaces de noms"
fi

printf '\n'
if [ "$FAILURES" -eq 0 ]; then
  echo "recette Linux: tout est passe"
else
  echo "recette Linux: $FAILURES echec(s)"
  echo "journal du daemon:"
  sed 's/^/    /' "$DAEMON_LOG"
fi
exit "$FAILURES"
