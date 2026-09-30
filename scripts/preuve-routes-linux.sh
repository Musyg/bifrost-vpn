#!/usr/bin/env bash
# Banc jetable de `prove routes` (D1c.1): chaque cas vit dans SON namespace
# reseau, cree ici et retire ici. Rien de l'hote n'est lu ni touche: ni regle,
# ni route, ni interface. Adresses de documentation seulement (RFC 5737 et
# RFC 3849), interfaces factices (`dummy`) sans lien vers l'exterieur.
#
# Ce que le banc mesure:
# - les commandes que le produit pose, rendues par l'exemple `routage_produit`
#   (qui appelle `netcfg::add_routing` et `aiguillage::poser`) et appliquees
#   telles quelles, donnent MATCH, en root et sans privilege;
# - chaque alteration donne un ecart dans sa seule categorie;
# - chaque type de route (RTN_*), dans `main` et dans `local`, dans les deux
#   familles, et chaque drapeau que le lecteur admet, est confronte a un
#   TEMOIN D'EMISSION: un datagramme UDP (diffusion permise) envoye dans le
#   namespace, et les compteurs d'emission de l'interface physique et de
#   celle du tunnel. Ce que la preuve admet n'emet pas hors du tunnel, sauf
#   vers le reseau du lien et sauf les deux limites nommees (masque large,
#   multidiffusion), qui sont mesurees ici aussi;
# - la preuve ne pose rien: l'etat du namespace est le meme avant et apres;
# - une regle qui bascule pendant la collecte rend UNMEASURED;
# - le rapport ne porte ni nom, ni adresse, ni table, ni marque, ni compte.
set -euo pipefail
if [ "$(id -u)" != 0 ]; then
  echo 'Ce banc exige root pour creer ses namespaces jetables.' >&2
  exit 2
fi
RACINE=$(cd "$(dirname "$0")/.." && pwd)
CLI="$RACINE/target/debug/bifrost-cli"
RENDU="$RACINE/target/debug/examples/routage_produit"
for outil in ip jq setpriv stat sha256sum seq sed grep wc paste python3 sysctl; do command -v "$outil" >/dev/null; done
test -x "$CLI"
test -x "$RENDU"
BAC=$(mktemp -d)
PREFIXE="bfroute-$$"
N=0
NS=""
TUNNEL=""
COURSE=""
DERNIER=""
CODE=0
CAS=0
# Parametres du banc: une marque, une table et un compte quelconques, que le
# rapport ne doit jamais repeter.
MARQUE=45562
TABLE=30303
COMPTE=4242
# `ip netns del` ne tue rien: il retire le NOM, et ce qui tourne dans le
# namespace continue de vivre, invisible a `ip netns list`. On releve donc les
# PID du namespace AVANT de le retirer, on les tue par PID (jamais par nom: un
# motif de nom atteint les processus de l'hote), puis on compte ce qui vit
# encore dans le namespace par son inode, qui survit au nom.
retirer_netns() {
  local ns=$1 inode pid reste
  inode=$(stat -L -c %i "/run/netns/$ns")
  for pid in $(ip netns pids "$ns"); do kill "$pid" 2>/dev/null || true; done
  for _ in $(seq 1 20); do
    if [ -z "$(ip netns pids "$ns")" ]; then break; fi
    sleep 0.25
  done
  for pid in $(ip netns pids "$ns"); do kill -KILL "$pid" 2>/dev/null || true; done
  ip netns del "$ns"
  reste=0
  for pid in /proc/[0-9]*; do
    if [ "$(stat -L -c %i "$pid/ns/net" 2>/dev/null)" = "$inode" ]; then
      reste=$((reste + 1))
    fi
  done
  if [ "$reste" != 0 ]; then
    echo "orphelins apres retrait du namespace $ns: $reste" >&2
    return 1
  fi
}
nettoyer() {
  local code=$?
  if [ "$code" != 0 ] && [ -n "$DERNIER" ] && [ -f "$BAC/$DERNIER.json" ]; then
    cat "$BAC/$DERNIER.json"
  fi
  if [ -n "$COURSE" ]; then
    kill "$COURSE" 2>/dev/null || true
    wait "$COURSE" 2>/dev/null || true
  fi
  if [ -n "$NS" ]; then retirer_netns "$NS" || code=1; fi
  rm -rf -- "$BAC"
  exit "$code"
}
trap nettoyer EXIT
cp "$CLI" "$BAC/bifrost-cli"
CLI="$BAC/bifrost-cli"
chmod 755 "$BAC" "$CLI"
# Le temoin d'emission: un datagramme vers la destination donnee, diffusion
# permise (SO_BROADCAST), sans interface imposee: c'est la table de routage
# qui choisit. Il dit s'il a ete envoye ou refuse, et par quelle erreur.
cat > "$BAC/temoin.py" <<'PY'
import errno, socket, sys
cible = sys.argv[1]
famille = socket.AF_INET6 if ":" in cible else socket.AF_INET
s = socket.socket(famille, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
try:
    s.sendto(b"x", (cible, 9))
    print("envoye")
except OSError as e:
    print("refuse", errno.errorcode.get(e.errno, e.errno))
PY
chmod 644 "$BAC/temoin.py"

# L'etat de routage du namespace courant, en une empreinte. Le compte a
# rebours d'une route qui expire change seul: il n'en fait pas partie.
etat() {
  {
    ip -n "$NS" -4 rule show
    ip -n "$NS" -6 rule show
    ip -n "$NS" -4 route show table all
    ip -n "$NS" -6 route show table all | sed -E 's/ expires -?[0-9]+sec//'
    ip -n "$NS" -br addr show
  } | sha256sum
}

# Le noyau pose de lui-meme les adresses de lien IPv6 et leurs routes quand une
# interface monte, par une tache differee: attendre que l'etat ne bouge plus
# avant de le comparer a lui-meme.
stabiliser() {
  local a b
  for _ in $(seq 1 50); do
    a=$(etat)
    sleep 0.2
    b=$(etat)
    if [ "$a" = "$b" ]; then return 0; fi
  done
  echo "l'etat du namespace ne se stabilise pas" >&2
  return 1
}

# `nouveau_ns <interface du tunnel>`: le namespace precedent est retire, un
# neuf est cree avec une fausse interface physique (adresse, route par defaut
# par une passerelle, dans les deux familles) et l'interface du tunnel montee
# avec ses adresses, comme le daemon la monte avant de poser son routage.
nouveau_ns() {
  if [ -n "$NS" ]; then
    retirer_netns "$NS"
    NS=""
  fi
  N=$((N + 1))
  ip netns add "$PREFIXE-$N"
  NS="$PREFIXE-$N"
  TUNNEL=$1
  # Pas de sollicitation de routeur: elle ferait bouger les compteurs
  # d'emission que le temoin lit. Reglage du namespace jetable seulement.
  ip netns exec "$NS" sysctl -q -w net.ipv6.conf.all.accept_ra=0 net.ipv6.conf.default.accept_ra=0
  ip -n "$NS" link set lo up
  ip -n "$NS" link add bfphys0 type dummy
  ip -n "$NS" -4 addr add 192.0.2.2/24 dev bfphys0
  ip -n "$NS" -6 addr add 2001:db8:1::2/64 dev bfphys0 nodad
  ip -n "$NS" link set bfphys0 up
  ip -n "$NS" -4 route add default via 192.0.2.1 dev bfphys0
  ip -n "$NS" -6 route add default via 2001:db8:1::1 dev bfphys0
  ip -n "$NS" link add "$1" type dummy
  ip -n "$NS" -4 addr add 198.51.100.2/32 dev "$1"
  ip -n "$NS" -6 addr add 2001:db8:2::2/128 dev "$1" nodad
  ip -n "$NS" link set "$1" up
}

# `appliquer <fichier>`: chaque ligne est un jeu d'arguments d'`ip`, applique
# tel quel dans le namespace courant. Une commande qui echoue arrete le banc,
# comme elle arreterait le daemon.
appliquer() {
  local ligne mots
  while IFS= read -r ligne; do
    read -r -a mots <<< "$ligne"
    ip -n "$NS" "${mots[@]}"
  done < "$1"
}

# Les commandes du produit, rendues par le produit.
"$RENDU" wireguard bfwg0 "$MARQUE" "$TABLE" > "$BAC/pose-wg.txt"
"$RENDU" coeur bftun0 "$COMPTE" > "$BAC/pose-coeur.txt"
"$RENDU" coeur bftun0 > "$BAC/pose-coeur-sans.txt"
test "$(wc -l < "$BAC/pose-wg.txt")" = 6
test "$(wc -l < "$BAC/pose-coeur.txt")" = 8
test "$(wc -l < "$BAC/pose-coeur-sans.txt")" = 6
# Sans IPv6: les lignes IPv4 seules. Dans l'autre ordre: les deux regles IPv4
# de WireGuard echangees (lignes 2 et 3).
grep '^-4 ' "$BAC/pose-wg.txt" > "$BAC/pose-wg-4.txt"
grep '^-4 ' "$BAC/pose-coeur.txt" > "$BAC/pose-coeur-4.txt"
{
  sed -n 1p "$BAC/pose-wg.txt"
  sed -n 3p "$BAC/pose-wg.txt"
  sed -n 2p "$BAC/pose-wg.txt"
  sed -n '4,$p' "$BAC/pose-wg.txt"
} > "$BAC/pose-wg-inverse.txt"

# Les intentions que la preuve lit.
jq -n --argjson m "$MARQUE" --argjson t "$TABLE" \
  '{schema_version:1, chemin:"wireguard", interface:"bfwg0", fwmark:$m, table:$t, coeur_uid:null}' > "$BAC/wg.json"
jq -n --argjson u "$COMPTE" \
  '{schema_version:1, chemin:"coeur", interface:"bftun0", fwmark:null, table:null, coeur_uid:$u}' > "$BAC/coeur.json"
jq -n '{schema_version:1, chemin:"coeur", interface:"bftun0", fwmark:null, table:null, coeur_uid:null}' > "$BAC/coeur-sans.json"
chmod 644 "$BAC"/*.json

# Aucun identifiant du banc dans le rapport.
muet() {
  if jq 'del(.started_at_unix_ms, .completed_at_unix_ms, .duration_ms)' "$BAC/$1.json" \
    | grep -F -e bfwg0 -e bftun0 -e bfphys0 -e 192.0.2 -e 198.51.100 -e 203.0.113 \
      -e 2001:db8 -e "$TABLE" -e "$MARQUE" -e "$COMPTE" >/dev/null; then
    echo "$1: le rapport exporte un identifiant du banc" >&2
    return 1
  fi
}

# `prouver <nom> <intention> [sans-privilege]`: une preuve dans le namespace
# courant, qui ne doit rien y changer.
prouver() {
  local nom=$1 intention=$2 avant apres
  DERNIER=$nom
  stabiliser
  avant=$(etat)
  CODE=0
  if [ "${3:-}" = sans-privilege ]; then
    ip netns exec "$NS" setpriv --reuid=65534 --regid=65534 --clear-groups \
      "$CLI" --json prove routes --intention "$intention" --actif > "$BAC/$nom.json" || CODE=$?
  else
    ip netns exec "$NS" "$CLI" --json prove routes --intention "$intention" --actif > "$BAC/$nom.json" || CODE=$?
  fi
  apres=$(etat)
  if [ "$avant" != "$apres" ]; then
    echo "$nom: l'etat du namespace a change pendant la preuve" >&2
    return 1
  fi
  muet "$nom"
}

# `attendre <nom> <code> <verdict> <ecarts en JSON>`: le verdict, et
# exactement ces categories d'ecart, dans cet ordre.
attendre() {
  if [ "$CODE" != "$2" ] || ! jq -e --arg v "$3" --argjson d "$4" \
    '.verdict == $v and .differences == $d and .live_kernel and .collection_verified
     and .schema_version == 1 and .scope == "linux-routing-comparison"
     and .network_security == "not-evaluated" and .failed_input == null' \
    "$BAC/$1.json" >/dev/null; then
    echo "$1: attendu $3 $4 (code $2), rendu code $CODE" >&2
    return 1
  fi
  CAS=$((CAS + 1))
  echo "PASSED: $1 -> $3 $4"
}

# Compteurs d'emission de l'interface physique et de celle du tunnel.
emis() {
  local i
  for i in bfphys0 "$TUNNEL"; do
    ip -n "$NS" -j -s link show dev "$i" | jq '.[0].stats64.tx.packets'
  done | paste -sd ' '
}
# Les rapports d'abonnement multicast IPv6 d'une interface qui monte partent
# d'eux-memes pendant une ou deux secondes: attendre que les compteurs ne
# bougent plus avant de mesurer.
calme() {
  local a b n=0
  a=$(emis)
  for _ in $(seq 1 60); do
    sleep 0.5
    b=$(emis)
    if [ "$a" = "$b" ]; then
      n=$((n + 1))
      if [ "$n" -ge 3 ]; then return 0; fi
    else
      n=0
    fi
    a=$b
  done
  echo "les compteurs d'emission ne se calment pas" >&2
  return 1
}
# `temoin <destination> <tunnel|lien|aucune>`: un datagramme, et ou il est
# parti. `lien`: sur l'interface physique seule; `tunnel`: sur celle du
# tunnel seule; `aucune`: ni l'une ni l'autre (livre a l'hote ou refuse).
temoin() {
  local p0 t0 p1 t1 dp dt issue ok=0
  calme
  read -r p0 t0 <<< "$(emis)"
  issue=$(ip netns exec "$NS" python3 "$BAC/temoin.py" "$1")
  sleep 0.3
  read -r p1 t1 <<< "$(emis)"
  dp=$((p1 - p0))
  dt=$((t1 - t0))
  case $2 in
    tunnel) [ "$dt" -ge 1 ] && [ "$dp" = 0 ] && ok=1 ;;
    lien) [ "$dp" -ge 1 ] && [ "$dt" = 0 ] && ok=1 ;;
    aucune) [ "$dp" = 0 ] && [ "$dt" = 0 ] && ok=1 ;;
  esac
  if [ "$ok" != 1 ]; then
    echo "temoin vers $1: attendu $2, mesure physique +$dp tunnel +$dt ($issue)" >&2
    return 1
  fi
  echo "  temoin vers $1: $2 (physique +$dp, tunnel +$dt; $issue)"
}

wg_pose() {
  nouveau_ns bfwg0
  appliquer "${1:-$BAC/pose-wg.txt}"
}
coeur_pose() {
  nouveau_ns bftun0
  appliquer "${1:-$BAC/pose-coeur.txt}"
}

# --- Chemin WireGuard -----------------------------------------------------

wg_pose
echo 'Regles posees par le produit, priorites choisies par le noyau:'
ip -n "$NS" -4 rule show
prouver wg-pose "$BAC/wg.json"
attendre wg-pose 0 MATCH '[]'
jq -e '.expected_counts.ipv4.product_rules == 2 and .expected_counts.ipv6.product_rules == 2
  and .observed_counts.ipv4.product_rules_found == 2 and .observed_counts.ipv6.product_rules_found == 2
  and .observed_counts.ipv4.third_party_rules_before_tunnel == 0
  and .observed_counts.ipv4.routes_before_tunnel.other == 0
  and .observed_counts.ipv6.routes_before_tunnel.other == 0
  and .observed_counts.ipv4.routes_before_tunnel.connected >= 1
  and .observed_counts.ipv6.routes_before_tunnel.connected >= 1
  and .observed_counts.ipv4.routes_before_tunnel.own_network_host >= 1
  and .observed_counts.ipv6.routes_before_tunnel.multicast_on_link >= 1
  and .tunnel_interface_present' "$BAC/wg-pose.json" >/dev/null
jq -c '.observed_counts' "$BAC/wg-pose.json"
# Ce que la pose seule fait de chaque destination: Internet au tunnel, le
# reseau du lien et sa diffusion sur le lien, la multidiffusion IPv4 au
# tunnel. LIMITE NOMMEE: la multidiffusion IPv6 part sur le lien, par la
# route ff00::/8 que le noyau pose dans `local`.
temoin 203.0.113.5 tunnel
temoin 2001:db8:9::5 tunnel
temoin 192.0.2.7 lien
temoin 192.0.2.255 lien
temoin 2001:db8:1::7 lien
temoin 239.1.2.3 tunnel
temoin ff0e::1 lien
echo 'LIMITE mesuree: multidiffusion IPv6 emise sur le lien avec la seule pose du produit'
prouver wg-pose-sans-privilege "$BAC/wg.json" sans-privilege
attendre wg-pose-sans-privilege 0 MATCH '[]'
jq -e -n --slurpfile a "$BAC/wg-pose.json" --slurpfile b "$BAC/wg-pose-sans-privilege.json" \
  '$a[0].observed_counts == $b[0].observed_counts' >/dev/null

nouveau_ns bfwg0
prouver wg-rien "$BAC/wg.json"
attendre wg-rien 1 MISMATCH '["ipv4-product-rules","ipv4-tunnel-table","ipv6-product-rules","ipv6-tunnel-table"]'

wg_pose
ip -n "$NS" -4 rule del not fwmark "$MARQUE" table "$TABLE"
prouver wg-regle-retiree "$BAC/wg.json"
attendre wg-regle-retiree 1 MISMATCH '["ipv4-product-rules"]'

wg_pose
ip -n "$NS" -6 rule del table main suppress_prefixlength 0
prouver wg-lan-retiree "$BAC/wg.json"
attendre wg-lan-retiree 1 MISMATCH '["ipv6-product-rules"]'

wg_pose "$BAC/pose-wg-inverse.txt"
prouver wg-ordre-inverse "$BAC/wg.json"
attendre wg-ordre-inverse 1 MISMATCH '["ipv4-product-rules"]'

wg_pose "$BAC/pose-wg-4.txt"
prouver wg-sans-ipv6 "$BAC/wg.json"
attendre wg-sans-ipv6 1 MISMATCH '["ipv6-product-rules","ipv6-tunnel-table"]'

wg_pose
ip -n "$NS" -4 rule add pref 100 table 100
prouver wg-tierce-avant "$BAC/wg.json"
attendre wg-tierce-avant 1 MISMATCH '["ipv4-rules-before-tunnel"]'

wg_pose
ip -n "$NS" -6 rule add pref 100 goto 32766
prouver wg-saut-avant "$BAC/wg.json"
attendre wg-saut-avant 1 MISMATCH '["ipv6-rules-before-tunnel"]'

wg_pose
ip -n "$NS" -4 rule add pref 40000 table 100
ip -n "$NS" -4 rule add pref 100 blackhole
ip -n "$NS" -4 rule add pref 101 table "$TABLE"
prouver wg-tierces-inoffensives "$BAC/wg.json"
attendre wg-tierces-inoffensives 0 MATCH '[]'

wg_pose
ip -n "$NS" -6 route del ::/0 dev bfwg0 table "$TABLE"
prouver wg-route-tunnel-retiree "$BAC/wg.json"
attendre wg-route-tunnel-retiree 1 MISMATCH '["ipv6-tunnel-table"]'

wg_pose
ip -n "$NS" -4 route replace 0.0.0.0/0 via 192.0.2.1 dev bfphys0 table "$TABLE"
prouver wg-route-tunnel-changee "$BAC/wg.json"
attendre wg-route-tunnel-changee 1 MISMATCH '["ipv4-tunnel-table"]'

wg_pose
ip -n "$NS" -4 route add 203.0.113.0/24 dev bfwg0 table "$TABLE"
prouver wg-route-tunnel-en-trop "$BAC/wg.json"
attendre wg-route-tunnel-en-trop 1 MISMATCH '["ipv4-tunnel-table"]'

wg_pose
ip -n "$NS" -4 route add 203.0.113.0/24 via 192.0.2.1 dev bfphys0
prouver wg-main-specifique "$BAC/wg.json"
attendre wg-main-specifique 1 MISMATCH '["ipv4-routes-before-tunnel"]'

wg_pose
ip -n "$NS" -4 route add 0.0.0.0/1 via 192.0.2.1 dev bfphys0
ip -n "$NS" -4 route add 128.0.0.0/1 via 192.0.2.1 dev bfphys0
prouver wg-main-def1 "$BAC/wg.json"
attendre wg-main-def1 1 MISMATCH '["ipv4-routes-before-tunnel"]'

wg_pose
ip -n "$NS" -6 route add 2001:db8:5::/48 via 2001:db8:1::1 dev bfphys0
prouver wg-main-specifique-6 "$BAC/wg.json"
attendre wg-main-specifique-6 1 MISMATCH '["ipv6-routes-before-tunnel"]'

wg_pose
ip -n "$NS" -4 route add 203.0.113.7/32 via 192.0.2.1 dev bfphys0 table local
prouver wg-local-specifique "$BAC/wg.json"
attendre wg-local-specifique 1 MISMATCH '["ipv4-routes-before-tunnel"]'

# Ce que la regle de legitimite admet, mesure: un rejet dans chaque famille,
# une route vers l'interface du tunnel, la route connectee d'une seconde
# adresse du lien.
wg_pose
ip -n "$NS" -4 route add blackhole 203.0.113.0/24
ip -n "$NS" -6 route add unreachable 2001:db8:6::/48
ip -n "$NS" -4 route add 203.0.113.64/26 dev bfwg0
ip -n "$NS" -4 addr add 192.0.2.130/25 dev bfphys0
prouver wg-legitimes "$BAC/wg.json"
attendre wg-legitimes 0 MATCH '[]'
jq -e '.observed_counts.ipv4.routes_before_tunnel.rejecting >= 1
  and .observed_counts.ipv6.routes_before_tunnel.rejecting >= 1
  and .observed_counts.ipv4.routes_before_tunnel.tunnel_interface >= 1
  and .observed_counts.ipv4.routes_before_tunnel.connected >= 2' "$BAC/wg-legitimes.json" >/dev/null
temoin 203.0.113.5 aucune
temoin 203.0.113.70 tunnel
temoin 192.0.2.140 lien
temoin 2001:db8:6::5 aucune

# Chaque type de route, pose par un tiers vers 203.0.113.0/24 et
# 2001:db8:9::/64, dans `main` puis dans `local`, sur le lien physique quand
# le type en a un. Ce qui emet sur le lien hors de son reseau est un ecart;
# ce qui livre a l'hote, rejette ou renvoie a la regle suivante n'en est
# pas un, et le temoin le confirme.
for table in main local; do
  for genre in unicast local broadcast anycast multicast blackhole unreachable prohibit throw; do
    wg_pose
    case $genre in
      blackhole | unreachable | prohibit | throw)
        ip -n "$NS" -4 route add "$genre" 203.0.113.0/24 table "$table"
        ip -n "$NS" -6 route add "$genre" 2001:db8:9::/64 table "$table"
        ;;
      *)
        ip -n "$NS" -4 route add "$genre" 203.0.113.0/24 dev bfphys0 table "$table"
        ip -n "$NS" -6 route add "$genre" 2001:db8:9::/64 dev bfphys0 table "$table"
        ;;
    esac
    prouver "type-$genre-$table" "$BAC/wg.json"
    case $genre in
      unicast | broadcast | anycast | multicast)
        attendre "type-$genre-$table" 1 MISMATCH '["ipv4-routes-before-tunnel","ipv6-routes-before-tunnel"]'
        temoin 203.0.113.5 lien
        temoin 2001:db8:9::5 lien
        ;;
      throw)
        attendre "type-$genre-$table" 0 MATCH '[]'
        temoin 203.0.113.5 tunnel
        temoin 2001:db8:9::5 tunnel
        ;;
      *)
        attendre "type-$genre-$table" 0 MATCH '[]'
        temoin 203.0.113.5 aucune
        temoin 2001:db8:9::5 aucune
        ;;
    esac
  done
done

# Routes hote DANS le reseau du lien: la diffusion IPv4 que le noyau pose,
# un anycast IPv6 pose par un tiers, et l'anycast de routeur de
# sous-reseau que le noyau pose quand l'hote route. Elles emettent vers le
# reseau du lien, ou livrent a l'hote: admises.
wg_pose
ip -n "$NS" -6 route add anycast 2001:db8:1::7/128 dev bfphys0 table local
ip netns exec "$NS" sysctl -q -w net.ipv6.conf.all.forwarding=1
prouver wg-hote-du-reseau "$BAC/wg.json"
attendre wg-hote-du-reseau 0 MATCH '[]'
jq -e '.observed_counts.ipv4.routes_before_tunnel.own_network_host >= 1
  and .observed_counts.ipv6.routes_before_tunnel.own_network_host >= 2' "$BAC/wg-hote-du-reseau.json" >/dev/null
temoin 192.0.2.255 lien
temoin 2001:db8:1::7 lien
temoin 2001:db8:1:: aucune

# Routes hote HORS du reseau du lien: une diffusion et un anycast IPv4, un
# anycast IPv6. Chacune emet sur le lien: un ecart.
wg_pose
ip -n "$NS" -4 route add broadcast 203.0.113.5/32 dev bfphys0 table local
ip -n "$NS" -4 route add anycast 203.0.113.6/32 dev bfphys0 table local
ip -n "$NS" -6 route add anycast 2001:db8:9::5/128 dev bfphys0 table local
prouver wg-hote-hors-reseau "$BAC/wg.json"
attendre wg-hote-hors-reseau 1 MISMATCH '["ipv4-routes-before-tunnel","ipv6-routes-before-tunnel"]'
temoin 203.0.113.5 lien
temoin 203.0.113.6 lien
temoin 2001:db8:9::5 lien

# Une diffusion IPv6, meme vers une adresse du reseau du lien: la famille n'a
# pas de diffusion, ni le noyau ni le produit n'en posent, et le noyau la
# traite en unicast. Un ecart par regle; le temoin montre ou elle emet.
wg_pose
ip -n "$NS" -6 route add broadcast 2001:db8:1::8/128 dev bfphys0 table local
prouver wg-diffusion-6 "$BAC/wg.json"
attendre wg-diffusion-6 1 MISMATCH '["ipv6-routes-before-tunnel"]'
temoin 2001:db8:1::8 lien

# LIMITE NOMMEE: une route de multidiffusion vers une destination de
# multidiffusion est admise, et emet sur le lien.
wg_pose
ip -n "$NS" -4 route add multicast 224.0.0.0/4 dev bfphys0
prouver wg-multidiffusion-4 "$BAC/wg.json"
attendre wg-multidiffusion-4 0 MATCH '[]'
jq -e '.observed_counts.ipv4.routes_before_tunnel.multicast_on_link == 1' "$BAC/wg-multidiffusion-4.json" >/dev/null
temoin 239.1.2.3 lien
echo 'LIMITE mesuree: une route de multidiffusion posee sur le lien est admise et emet sur le lien'

# LIMITE NOMMEE: une adresse a masque large rend une route connectee qui
# couvre ce masque; elle est admise, et tout ce qu'elle couvre part sur le
# lien.
wg_pose
ip -n "$NS" -4 addr add 192.0.2.3/1 dev bfphys0
ip -n "$NS" -6 addr add 2001:db8:1::3/3 dev bfphys0 nodad
prouver wg-masque-large "$BAC/wg.json"
attendre wg-masque-large 0 MATCH '[]'
temoin 203.0.113.5 lien
temoin 2001:db8:9::5 lien
echo 'LIMITE mesuree: une adresse a masque large met sur le lien tout ce que son masque couvre'

# La route du tunnel inutilisable. Sans porteuse, le noyau la marque
# `linkdown` et le trafic se perd; avec `ignore_routes_with_linkdown`, lu a
# chaque recherche, il la marque aussi `dead`, l'ignore, et le trafic sort
# par le lien. Les deux sont des ecarts.
wg_pose
ip -n "$NS" link set bfwg0 carrier off
prouver wg-tunnel-sans-porteuse "$BAC/wg.json"
attendre wg-tunnel-sans-porteuse 1 MISMATCH '["ipv4-tunnel-table","ipv6-tunnel-table"]'
temoin 203.0.113.5 aucune
temoin 2001:db8:9::5 aucune

wg_pose
ip netns exec "$NS" sysctl -q -w net.ipv4.conf.all.ignore_routes_with_linkdown=1 \
  net.ipv6.conf.all.ignore_routes_with_linkdown=1
ip -n "$NS" link set bfwg0 carrier off
prouver wg-tunnel-mort "$BAC/wg.json"
attendre wg-tunnel-mort 1 MISMATCH '["ipv4-tunnel-table","ipv6-tunnel-table"]'
temoin 203.0.113.5 lien
temoin 2001:db8:9::5 lien

# `onlink` sur la route du tunnel (IPv6; IPv4 le refuse sans passerelle):
# l'emission ne change pas, ce n'est pas un ecart.
wg_pose
ip -n "$NS" -6 route replace ::/0 dev bfwg0 onlink table "$TABLE"
prouver wg-tunnel-onlink "$BAC/wg.json"
attendre wg-tunnel-onlink 0 MATCH '[]'
temoin 2001:db8:9::5 tunnel

# Une route du tunnel qui expire: un ecart des qu'elle porte une echeance;
# une fois echue, le noyau ne la consulte plus alors que le dump la montre
# encore, et le trafic sort par le lien.
wg_pose
ip -n "$NS" -6 route replace ::/0 dev bfwg0 table "$TABLE" expires 8
prouver wg-tunnel-expire "$BAC/wg.json"
attendre wg-tunnel-expire 1 MISMATCH '["ipv6-tunnel-table"]'
temoin 2001:db8:9::5 tunnel
sleep 9
temoin 2001:db8:9::5 lien
prouver wg-tunnel-echu "$BAC/wg.json"
attendre wg-tunnel-echu 1 MISMATCH '["ipv6-tunnel-table"]'

# Une route connectee sans porteuse reste admise: marquee morte, le noyau
# l'ignore et le trafic de son reseau passe au tunnel; marquee seulement
# `linkdown`, il se perd. Rien ne sort par le lien.
wg_pose
ip netns exec "$NS" sysctl -q -w net.ipv4.conf.all.ignore_routes_with_linkdown=1 \
  net.ipv6.conf.all.ignore_routes_with_linkdown=1
ip -n "$NS" link set bfphys0 carrier off
prouver wg-lien-mort "$BAC/wg.json"
attendre wg-lien-mort 0 MATCH '[]'
temoin 192.0.2.7 tunnel
temoin 2001:db8:1::7 tunnel
# Une route par une passerelle du lien mort reste un ecart: elle n'emet
# rien tant que le lien est mort, et revit avec sa porteuse.
ip -n "$NS" -4 route add 203.0.113.0/24 via 192.0.2.1 dev bfphys0 onlink
prouver wg-lien-mort-passerelle "$BAC/wg.json"
attendre wg-lien-mort-passerelle 1 MISMATCH '["ipv4-routes-before-tunnel"]'
temoin 203.0.113.5 tunnel
wg_pose
ip -n "$NS" link set bfphys0 carrier off
prouver wg-lien-sans-porteuse "$BAC/wg.json"
attendre wg-lien-sans-porteuse 0 MATCH '[]'
temoin 192.0.2.7 aucune
temoin 2001:db8:1::7 aucune

wg_pose
ip -n "$NS" link del bfwg0
prouver wg-sans-interface "$BAC/wg.json"
attendre wg-sans-interface 1 MISMATCH '["ipv4-tunnel-table","ipv6-tunnel-table"]'
jq -e '.tunnel_interface_present == false' "$BAC/wg-sans-interface.json" >/dev/null

# --- Chemin par coeur -----------------------------------------------------

coeur_pose
prouver coeur-pose "$BAC/coeur.json"
attendre coeur-pose 0 MATCH '[]'
jq -e '.expected_counts.ipv4.product_rules == 3 and .observed_counts.ipv6.product_rules_found == 3' \
  "$BAC/coeur-pose.json" >/dev/null
temoin 203.0.113.5 tunnel
temoin 2001:db8:9::5 tunnel
temoin 192.0.2.7 lien
prouver coeur-pose-sans-privilege "$BAC/coeur.json" sans-privilege
attendre coeur-pose-sans-privilege 0 MATCH '[]'

# L'interface du coeur sans porteuse (un TUN que plus personne ne lit), avec
# `ignore_routes_with_linkdown`: la route du tunnel est morte, un ecart.
coeur_pose
ip netns exec "$NS" sysctl -q -w net.ipv4.conf.all.ignore_routes_with_linkdown=1 \
  net.ipv6.conf.all.ignore_routes_with_linkdown=1
ip -n "$NS" link set bftun0 carrier off
prouver coeur-tunnel-mort "$BAC/coeur.json"
attendre coeur-tunnel-mort 1 MISMATCH '["ipv4-tunnel-table","ipv6-tunnel-table"]'
temoin 203.0.113.5 lien
temoin 2001:db8:9::5 lien

coeur_pose "$BAC/pose-coeur-sans.txt"
prouver coeur-sans-compte "$BAC/coeur-sans.json"
attendre coeur-sans-compte 0 MATCH '[]'
# L'intention dit un compte, la pose n'en a pas.
prouver coeur-compte-absent "$BAC/coeur.json"
attendre coeur-compte-absent 1 MISMATCH '["ipv4-product-rules","ipv6-product-rules"]'

nouveau_ns bftun0
prouver coeur-rien "$BAC/coeur.json"
attendre coeur-rien 1 MISMATCH '["ipv4-product-rules","ipv4-tunnel-table","ipv6-product-rules","ipv6-tunnel-table"]'

coeur_pose
ip -n "$NS" -4 rule del pref 9100
prouver coeur-regle-retiree "$BAC/coeur.json"
attendre coeur-regle-retiree 1 MISMATCH '["ipv4-product-rules"]'

coeur_pose
ip -n "$NS" -4 rule del pref 9120
ip -n "$NS" -4 rule add lookup 2847 pref 9121
prouver coeur-priorite-changee "$BAC/coeur.json"
attendre coeur-priorite-changee 1 MISMATCH '["ipv4-product-rules"]'

coeur_pose
ip -n "$NS" -6 rule add pref 9115 lookup 100
prouver coeur-tierce-avant "$BAC/coeur.json"
attendre coeur-tierce-avant 1 MISMATCH '["ipv6-rules-before-tunnel"]'

coeur_pose
ip -n "$NS" -6 route add 2001:db8:5::/48 via 2001:db8:1::1 dev bfphys0
prouver coeur-main-specifique-6 "$BAC/coeur.json"
attendre coeur-main-specifique-6 1 MISMATCH '["ipv6-routes-before-tunnel"]'

coeur_pose "$BAC/pose-coeur-4.txt"
prouver coeur-sans-ipv6 "$BAC/coeur.json"
attendre coeur-sans-ipv6 1 MISMATCH '["ipv6-product-rules","ipv6-tunnel-table"]'

# --- Collecte pendant qu'une regle bascule ---------------------------------
#
# Un basculeur ajoute et retire sans cesse une regle tierce avant le tunnel.
# Chaque preuve doit rendre soit un etat que deux lectures ont vu identique
# (MATCH sans la regle, l'ecart de sa categorie avec elle), soit UNMEASURED;
# et au moins une fois UNMEASURED, sinon l'encadrement n'a rien ete.
wg_pose
stabiliser
for _ in $(seq 1 200); do
  printf 'rule add pref 100 table 100\nrule del pref 100 table 100\n'
done > "$BAC/bascule.txt"
cat > "$BAC/basculer.sh" <<'SH'
#!/usr/bin/env bash
set -u
while :; do
  ip -n "$1" -4 -batch "$2" || exit 1
done
SH
bash "$BAC/basculer.sh" "$NS" "$BAC/bascule.txt" &
COURSE=$!
instables=0
coherentes=0
essais=0
DERNIER=course
for _ in $(seq 1 100); do
  essais=$((essais + 1))
  CODE=0
  ip netns exec "$NS" "$CLI" --json prove routes --intention "$BAC/wg.json" --actif > "$BAC/course.json" || CODE=$?
  muet course
  if [ "$CODE" = 2 ] && jq -e '.verdict == "UNMEASURED" and (.reason | startswith("collecte instable"))
    and (.collection_verified | not) and .differences == [] and .observed_counts == null' \
    "$BAC/course.json" >/dev/null; then
    instables=$((instables + 1))
  elif jq -e '.collection_verified and ((.verdict == "MATCH" and .differences == [])
    or (.verdict == "MISMATCH" and .differences == ["ipv4-rules-before-tunnel"]))' \
    "$BAC/course.json" >/dev/null; then
    coherentes=$((coherentes + 1))
  else
    echo 'course: ni etat stable, ni collecte instable' >&2
    exit 1
  fi
  if [ "$instables" -ge 10 ]; then break; fi
done
kill "$COURSE"
wait "$COURSE" 2>/dev/null || true
COURSE=""
echo "course: $instables collectes instables et $coherentes coherentes sur $essais"
test "$instables" -ge 1
CAS=$((CAS + 1))
echo 'PASSED: course -> UNMEASURED sur une regle qui bascule pendant la collecte'

retirer_netns "$NS"
NS=""
echo "PASSED: $CAS cas, $N namespaces jetables, tous retires"
