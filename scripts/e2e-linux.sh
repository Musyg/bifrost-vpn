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
#
# Usage: sudo ./scripts/e2e-linux.sh [chemin/vers/target/debug]

set -euo pipefail

BIN="${1:-$(cd "$(dirname "$0")/.." && pwd)/target/debug}"
DAEMON="$BIN/bifrost-daemon"
CLI="$BIN/bifrost-cli"

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

WORK=$(mktemp -d /tmp/bifrost-e2e.XXXXXX)
SOCKET="$WORK/daemon.sock"
PROFILE="$WORK/tunnel.toml"
PCAP="$WORK/killswitch.pcap"
DAEMON_LOG="$WORK/daemon.log"
DAEMON_PID=""

ok()   { printf '  OK    %s\n' "$1"; }
fail() { printf '  ECHEC %s\n' "$1"; FAILURES=$((FAILURES + 1)); }
step() { printf '\n== %s\n' "$1"; }
FAILURES=0

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

# Nettoyage reseau seul: appele aussi AVANT le montage pour repartir d'un banc
# propre, sans toucher au repertoire de travail qui vient d'etre cree.
# Termine un processus identifie par un motif de ligne de commande. SIGTERM,
# puis SIGKILL s'il s'attarde.
#
# On vise par motif et non par PID: `setsid` fork, donc `$!` designe le setsid
# et pas le programme. Les motifs utilises sont des chemins uniques a cette
# execution, ce qui evite de toucher a un processus etranger.
terminate_pattern() {
  local motif="$1"
  pgrep -f "$motif" >/dev/null 2>&1 || return 0
  pkill -f "$motif" 2>/dev/null || true
  for _ in $(seq 1 20); do
    pgrep -f "$motif" >/dev/null 2>&1 || return 0
    sleep 0.25
  done
  pkill -9 -f "$motif" 2>/dev/null || true
  sleep 0.5
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

cleanup_net() {
  terminate_pattern "$SOCKET"
  terminate_pattern "$PCAP"
  # Le faux resolveur ne porte aucun chemin unique dans sa ligne de commande:
  # on le vise par son drapeau ET par l'adresse du banc, qui n'existe nulle
  # part ailleurs sur une machine ordinaire.
  terminate_pattern "faux-resolveur $TUN_SRV:53"
  terminate_pattern "faux-resolveur-amont $TUN_SRV:53"
  vider_netns "$NS_CLI"
  vider_netns "$NS_SRV"
  ip netns del "$NS_CLI" 2>/dev/null || true
  ip netns del "$NS_SRV" 2>/dev/null || true
  ip link del "$VETH_S" 2>/dev/null || true
  ip link del "$VETH_C" 2>/dev/null || true
}

cleanup() {
  cleanup_net
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
[ -x "$DAEMON" ] || { echo "binaire introuvable: $DAEMON"; exit 1; }
[ -x "$CLI" ] || { echo "binaire introuvable: $CLI"; exit 1; }

step "Preparation du banc"
cleanup_net
ip netns add "$NS_SRV"
ip netns add "$NS_CLI"
ip link add "$VETH_C" type veth peer name "$VETH_S"
ip link set "$VETH_C" netns "$NS_CLI"
ip link set "$VETH_S" netns "$NS_SRV"
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
setsid ip netns exec "$NS_SRV" "$DAEMON" \
  --faux-resolveur "$TUN_SRV:53" --faux-resolveur-adresse "$DNS_ATTENDU" \
  >"$WORK/resolveur.log" 2>&1 &
for _ in $(seq 1 20); do
  ip netns exec "$NS_SRV" ss -lun 2>/dev/null | grep -q "$TUN_SRV:53" && break
  sleep 0.25
done
if ip netns exec "$NS_SRV" ss -lun 2>/dev/null | grep -q "$TUN_SRV:53"; then
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
# setsid detache le daemon de la session du shell appelant. Il reste tue
# explicitement par cleanup_net, mais s'il survivait a une interruption
# brutale, il ne figurerait pas dans l'arbre de processus de l'appelant. Un
# runner d'integration continue attend la disparition de cet arbre avant de
# clore son job, et un processus root qu'il ne peut pas tuer l'y bloque
# indefiniment, meme apres que toutes les etapes ont reussi.
#
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
setsid ip netns exec "$NS_CLI" unshare --mount --propagation private \
  sh -c "mkdir -p '$WORK/etc-haut' '$WORK/etc-travail' \
         && mount -t overlay bifrost-etc -o lowerdir=/etc,upperdir='$WORK/etc-haut',workdir='$WORK/etc-travail' /etc \
         && exec '$DAEMON' --socket '$SOCKET' --coeur-utilisateur '$COEUR_UID:$COEUR_UID' --resolveur-utilisateur '$RESOLVEUR_UID:$RESOLVEUR_UID'" \
  >"$DAEMON_LOG" 2>&1 &
DAEMON_PID=$!
for _ in $(seq 1 40); do [ -S "$SOCKET" ] && break; sleep 0.25; done
[ -S "$SOCKET" ] || { echo "le daemon n'a pas ouvert $SOCKET"; cat "$DAEMON_LOG"; exit 1; }

# Le PID du daemon lui-meme, et non celui de setsid: les sondes de resolution
# doivent entrer dans SON namespace de montage pour voir le meme resolv.conf.
# Le motif est le chemin du socket, unique a cette execution.
DAEMON_REEL=$(pgrep -f "bifrost-daemon --socket $SOCKET" | head -1)
[ -n "$DAEMON_REEL" ] || { echo "daemon introuvable"; cat "$DAEMON_LOG"; exit 1; }
ok "daemon en ecoute (pid $DAEMON_REEL), resolv.conf isole de la machine"

# Temoin de l'isolation elle-meme. Sans lui, une regression qui remettrait le
# daemon dans le namespace de montage de la machine ne se verrait qu'a la
# prochaine fois que quelqu'un remarque que sa resolution de noms est cassee.
RESOLV_AVANT=$(empreinte_resolv)

step "Resolveur embarque sur la boucle locale"
# La forme de dnscrypt-proxy, moins le chiffrement: il ecoute sur 127.0.0.1:53
# et relaie vers l'amont, a travers le tunnel. Ce que le banc doit eprouver
# n'est pas DoH, dont les auteurs de dnscrypt-proxy repondent, mais la
# plomberie autour: les applications passent par la boucle locale, le resolveur
# est le seul a pouvoir emettre du :53, et sa requete part par le tunnel.
#
# Sous le compte du resolveur, avec la capacite de se lier a un port
# privilegie et rien d'autre. C'est ce que fera l'unite systemd de
# dnscrypt-proxy: le :53 exige soit root, soit CAP_NET_BIND_SERVICE, et un
# resolveur qui resterait root perdrait tout l'interet d'un compte dedie.
setsid ip netns exec "$NS_CLI" setpriv \
  --reuid="$RESOLVEUR_UID" --regid="$RESOLVEUR_UID" --clear-groups \
  --inh-caps=+net_bind_service --ambient-caps=+net_bind_service \
  "$DAEMON" --faux-resolveur "127.0.0.1:53" --faux-resolveur-amont "$TUN_SRV:53" \
  >"$WORK/resolveur-local.log" 2>&1 &
for _ in $(seq 1 20); do
  ip netns exec "$NS_CLI" ss -lun 2>/dev/null | grep -q "127.0.0.1:53" && break
  sleep 0.25
done
if ip netns exec "$NS_CLI" ss -lun 2>/dev/null | grep -q "127.0.0.1:53"; then
  ok "resolveur embarque en ecoute sur 127.0.0.1:53 sous l'uid $RESOLVEUR_UID"
else
  fail "le resolveur embarque n'ecoute pas"; cat "$WORK/resolveur-local.log"
fi

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
  echo "$STATUS" | grep -q '"connected"' && break
  sleep 0.5
done

echo "$STATUS" | sed 's/^/    /'
echo "$STATUS" | grep -q '"state": *"connected"' && ok "status = connected" \
  || fail "status n'est pas connected"
echo "$STATUS" | grep -q '"kill_switch_engaged": *true' && ok "kill switch arme" \
  || fail "kill switch non arme alors que le tunnel est monte"

if ip netns exec "$NS_CLI" ping -c2 -W2 "$TUN_SRV" >/dev/null 2>&1; then
  ok "trafic achemine dans le tunnel ($TUN_CLI -> $TUN_SRV)"
else
  fail "le tunnel ne transporte rien"
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
if [ "$RESOLU" = oui ] && echo "$RESOLUTION" | grep -qx "$DNS_ATTENDU"; then
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
if echo "$REGLES_DNS" | grep -qE "^[[:space:]]*udp dport 53 drop"; then
  ok "les regles vivantes ferment le :53"
else
  fail "aucun drop du :53 dans les regles vivantes"
  echo "$REGLES_DNS" | sed 's/^/        /'
fi
# Et l'ordre, qui est toute la difference entre une regle utile et une regle
# decorative. `nft` rend les regles dans l'ordre d'application.
LIGNE_DROP=$(echo "$REGLES_DNS" | grep -nE "^[[:space:]]*udp dport 53 drop" | head -1 | cut -d: -f1)
LIGNE_TUNNEL=$(echo "$REGLES_DNS" | grep -n "oifname \"wgc\"\|oifname \"wg0\"" | head -1 | cut -d: -f1)
if [ -n "$LIGNE_DROP" ] && [ -n "$LIGNE_TUNNEL" ] && [ "$LIGNE_DROP" -lt "$LIGNE_TUNNEL" ]; then
  ok "le drop du :53 precede l'acceptation du tunnel (lignes $LIGNE_DROP < $LIGNE_TUNNEL)"
else
  fail "le drop du :53 est pose apres l'acceptation du tunnel: sans effet"
  echo "$REGLES_DNS" | sed 's/^/        /'
fi
# L'exception, elle, doit designer le resolveur et lui seul.
if echo "$REGLES_DNS" | grep -q "meta skuid $RESOLVEUR_UID .*dport 53 accept"; then
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
if echo "$REGLES" | grep -q "meta skuid $COEUR_UID accept"; then
  ok "le compte declare au demarrage est exempte par les regles vivantes"
else
  fail "aucune exemption pour l'uid $COEUR_UID: le daemon ne transmet pas l'identite"
  echo "$REGLES" | sed 's/^/        /'
fi

# L'exemption ne doit pas passer AU-DESSUS de la restriction DNS. Les permits
# DNS sont poses plus haut dans la chaine, donc un skuid nu laisserait le
# coeur interroger n'importe quel resolveur en clair.
if echo "$REGLES" | grep -B2 "meta skuid $COEUR_UID accept" \
     | grep -q "meta skuid $COEUR_UID .* dport 53 drop"; then
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

# --- DoD 2 ---------------------------------------------------------------
step "DoD 2: ip link del wg0 ne produit aucun paquet en clair"
setsid ip netns exec "$NS_SRV" tcpdump -i "$VETH_S" -nn --immediate-mode -U -s 128 -w "$PCAP" >/dev/null 2>"$PCAP.tcpdump" &
sleep 0.6

ip -n "$NS_CLI" link del wg0
ip netns exec "$NS_CLI" "$DAEMON" --probe all >/dev/null 2>&1 || true
ip netns exec "$NS_CLI" ping -c2 -W1 "$TUN_SRV" >/dev/null 2>&1 || true
ip netns exec "$NS_CLI" ping -c2 -W1 8.8.8.8 >/dev/null 2>&1 || true
sleep 0.6
terminate_pattern "$PCAP"

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
step "DoD 3: check execute tous les vecteurs"
# Le harnais cree ses propres namespaces et ne touche jamais au pare-feu de
# l'hote: il tourne donc en dehors du namespace du test.
set +e
"$CLI" --socket "$SOCKET" check
CHECK_CODE=$?
set -e
[ $CHECK_CODE -eq 0 ] && ok "aucun vecteur en echec" || fail "au moins un vecteur en echec"

step "Deconnexion"
ip netns exec "$NS_CLI" "$CLI" --socket "$SOCKET" disconnect && ok "disconnect accepte" \
  || fail "disconnect a echoue"
if ip netns exec "$NS_CLI" nft list table inet bifrost >/dev/null 2>&1; then
  fail "la table nftables est encore en place apres disconnect"
else
  ok "kill switch retire"
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

step "Absence de processus residuel"
# Un processus root survivant au script bloque le nettoyage de tout appelant
# qui n'est pas root, un runner d'integration continue par exemple. On verifie
# donc explicitement plutot que d'esperer.
cleanup_net
RESIDUELS=$(pgrep -af "$SOCKET|$PCAP" 2>/dev/null || true)
if [ -z "$RESIDUELS" ]; then
  ok "aucun processus du banc ne survit"
else
  fail "processus residuels apres nettoyage"
  echo "$RESIDUELS" | sed 's/^/        /'
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
