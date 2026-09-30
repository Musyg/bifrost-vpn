#!/usr/bin/env bash
# Banc jetable du demontage du routage: le produit ne retire que ce qu'il a
# pose, et refuse de se poser dans une table ou sur une marque qu'un tiers
# emploie. Chaque cas vit dans SON namespace reseau, cree ici et retire ici.
# Rien de l'hote n'est lu ni touche. Adresses de documentation seulement
# (RFC 5737 et RFC 3849), interfaces factices (`dummy`) sans lien vers
# l'exterieur, et une interface WireGuard sans pair joignable.
#
# Le produit est appele par ses fonctions a lui, rendues par l'exemple
# `banc_demontage`: `LinuxTunnel::up` et `down` pour WireGuard (le module
# noyau `wireguard` est necessaire), et pour le chemin par coeur ce que
# `CoeurTunnel` fait du routage, une interface factice tenant lieu de TUN.
#
# Le tiers est pose a la main, sous la forme de wg-quick (`add_default` de
# wireguard-tools, src/wg-quick/linux.bash: `rule add not fwmark T table T`,
# `rule add table main suppress_prefixlength 0`, `route add ... table T`),
# ou sous la forme de l'aiguillage du coeur (memes priorites).
#
# Pour chaque chemin (WireGuard, coeur), dans les deux familles:
# - libre: monter puis demonter rend l'etat initial exact, et la preuve
#   `prove routes` rend MATCH sur la pose;
# - tiers avant, meme table: refus nomme, rien pose, rien retire, et le
#   demontage qui suit ne retire rien non plus;
# - tiers apres, meme table: le demontage laisse tout ce que le tiers a pose;
# - tiers avant ou apres, autre table (et, pour le coeur, memes priorites):
#   montage accepte, demontage exact;
# - reste d'une session interrompue: le montage suivant le retire et pose un
#   etat identique au premier; le demontage rend l'etat initial.
# Et pour WireGuard seul, dont l'interface porte le nom du profil:
# - tiers avant, meme NOM d'interface (autre table): refus nomme, rien pose,
#   rien retire, et le demontage qui suit laisse l'interface du tiers;
# - session interrompue qui laisse l'interface du produit (sa cle): le
#   montage suivant la reconnait, la retire et pose un etat identique.
#
# Usage: sudo bash ./scripts/banc-demontage-routage-linux.sh
# (apres cargo build --workspace et
# cargo build -p bifrost-daemon --example banc_demontage)
set -euo pipefail
if [ "$(id -u)" != 0 ]; then
  echo 'Ce banc exige root pour creer ses namespaces jetables.' >&2
  exit 2
fi
RACINE=$(cd "$(dirname "$0")/.." && pwd)
OUTIL="$RACINE/target/debug/examples/banc_demontage"
CLI="$RACINE/target/debug/bifrost-cli"
for outil in ip jq stat seq sed grep cmp sysctl; do command -v "$outil" >/dev/null; done
test -x "$OUTIL"
test -x "$CLI"

# Les valeurs par defaut du produit, qui sont celles de wg-quick.
MARQUE=51820
TABLE=51820
# Celles que wg-quick prend quand 51820 est occupee.
AUTRE=51821
COMPTE=4242
COEUR_TABLE=2847

CAS_TOUS="wg-libre wg-avant-meme wg-apres-meme wg-avant-autre wg-apres-autre wg-reste
wg-avant-nom wg-reste-lien
coeur-libre coeur-avant-meme coeur-apres-meme coeur-avant-autre coeur-apres-autre coeur-reste"

# --- le pere: chaque cas dans son propre processus -------------------------
if [ "${1:-}" != --cas ]; then
  rouges=0
  vus=0
  for cas in $CAS_TOUS; do
    vus=$((vus + 1))
    if bash "$0" --cas "$cas"; then
      echo "PASSED: $cas"
    else
      echo "FAILED: $cas"
      rouges=$((rouges + 1))
    fi
  done
  echo "banc du demontage: $vus cas, $rouges rouge(s)"
  test "$rouges" = 0
  exit 0
fi

# --- un cas -----------------------------------------------------------------
CAS=$2
NS="bfdm-$$"
BAC=$(mktemp -d)
ECART=0

# `ip netns del` ne tue rien: il retire le NOM. On releve les PID du
# namespace, on les tue par PID (jamais par motif de nom), puis on compte ce
# qui vit encore dans le namespace par son inode, qui survit au nom.
retirer_netns() {
  local ns=$1 inode pid reste
  inode=$(stat -L -c %i "/run/netns/$ns")
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
  if [ -e "/run/netns/$NS" ]; then retirer_netns "$NS" || code=1; fi
  rm -rf -- "$BAC"
  exit "$code"
}
trap nettoyer EXIT

ecart() {
  echo "  ECART ($CAS): $*" >&2
  ECART=1
}

I() { ip -n "$NS" "$@"; }

# L'etat de routage du namespace, une ligne par objet, prefixee de sa
# section. Le compte a rebours d'une route qui expire n'en fait pas partie.
etat() {
  {
    I -4 rule show | sed 's/^/r4 /'
    I -6 rule show | sed 's/^/r6 /'
    I -4 route show table all | sed 's/^/t4 /'
    I -6 route show table all | sed -E 's/ expires -?[0-9]+sec//' | sed 's/^/t6 /'
    I -br link show | sed 's/^/l /'
    I -br addr show | sed 's/^/a /'
  } > "$1"
}

# Le noyau pose des objets par des taches differees: attendre que l'etat ne
# bouge plus avant de le relever.
releve() {
  local a="$BAC/stab-a" b="$BAC/stab-b"
  for _ in $(seq 1 50); do
    etat "$a"
    sleep 0.2
    etat "$b"
    if cmp -s "$a" "$b"; then
      cp "$b" "$1"
      return 0
    fi
  done
  echo "l'etat du namespace ne se stabilise pas" >&2
  return 1
}

# `moins A B`: les lignes de A absentes de B, dans l'ordre de A.
moins() {
  grep -vxF -f "$2" "$1" || true
}

# `exiger_egal <attendu> <obtenu> <quoi>`: memes lignes, meme ordre; sinon
# l'ecart est dit, ligne par ligne.
exiger_egal() {
  if ! cmp -s "$1" "$2"; then
    ecart "$3"
    moins "$1" "$2" | sed 's/^/    disparu:  /' >&2
    moins "$2" "$1" | sed 's/^/    apparu:   /' >&2
    if [ -z "$(moins "$1" "$2")" ] && [ -z "$(moins "$2" "$1")" ]; then
      echo "    memes lignes, ordre different" >&2
    fi
  fi
}

nouveau_ns() {
  ip netns add "$NS"
  ip netns exec "$NS" sysctl -q -w net.ipv6.conf.all.accept_ra=0 net.ipv6.conf.default.accept_ra=0
  I link set lo up
  I link add bfphys0 type dummy
  I link set bfphys0 addrgenmode none
  I -4 addr add 192.0.2.2/24 dev bfphys0
  I -6 addr add 2001:db8:1::2/64 dev bfphys0 nodad
  I link set bfphys0 up
  I -4 route add default via 192.0.2.1 dev bfphys0
  I -6 route add default via 2001:db8:1::1 dev bfphys0
  # L'interface du tiers.
  I link add tiers0 type dummy
  I link set tiers0 addrgenmode none
  I link set tiers0 up
}

# L'interface factice qui tient lieu de TUN du chemin par coeur, adressee
# comme `configure_link` l'adresse. Son adresse materielle est fixee (plage
# de documentation, RFC 7042): le cas du reste la recree, et une adresse
# tiree au hasard ferait un ecart qui n'est pas celui du produit.
tun_factice() {
  I link add bftun0 address 00:00:5e:00:53:01 type dummy
  I link set bftun0 addrgenmode none
  I -4 addr add 198.51.100.2/32 dev bftun0
  I -6 addr add 2001:db8:2::2/128 dev bftun0 nodad
  I link set bftun0 up
}

# `produit <monter|demonter>`: le code de sortie est rendu dans CODE, la
# sortie d'erreur dans $BAC/produit.err.
produit() {
  CODE=0
  case $CAS in
    wg-*) ip netns exec "$NS" "$OUTIL" wireguard "$1" bfwg0 "$MARQUE" "$TABLE" 2> "$BAC/produit.err" || CODE=$? ;;
    coeur-*) ip netns exec "$NS" "$OUTIL" coeur "$1" bftun0 "$COMPTE" 2> "$BAC/produit.err" || CODE=$? ;;
  esac
}

exiger_monte() {
  produit monter
  if [ "$CODE" != 0 ]; then
    ecart "montage refuse ou en echec (code $CODE): $(cat "$BAC/produit.err")"
  fi
}

exiger_demonte() {
  produit demonter
  if [ "$CODE" != 0 ]; then
    ecart "demontage en echec (code $CODE): $(cat "$BAC/produit.err")"
  fi
}

# Le tiers WireGuard, sous la forme de wg-quick: `tiers_wg <table=marque>
# [metrique]`, deux familles.
tiers_wg() {
  local t=$1 metrique=${2:-}
  for f in -4 -6; do
    I "$f" rule add not fwmark "$t" table "$t"
    I "$f" rule add table main suppress_prefixlength 0
  done
  if [ -n "$metrique" ]; then
    I -4 route add 0.0.0.0/0 dev tiers0 table "$t" metric "$metrique"
    I -6 route add ::/0 dev tiers0 table "$t" metric "$metrique"
  else
    I -4 route add 0.0.0.0/0 dev tiers0 table "$t"
    I -6 route add ::/0 dev tiers0 table "$t"
  fi
}

# Le tiers qui occupe la table du coeur, aux priorites du coeur.
tiers_coeur_meme() {
  for f in -4 -6; do
    I "$f" rule add uidrange "$COMPTE-$COMPTE" lookup main pref 9100
    I "$f" rule add lookup main suppress_prefixlength 0 pref 9110
    I "$f" rule add lookup "$COEUR_TABLE" pref 9120
    I "$f" route add default dev tiers0 table "$COEUR_TABLE"
  done
}

# Le tiers qui rejoint la table du coeur apres lui: une regle vers elle a une
# autre priorite, une route par defaut de metrique 100, et une regle a la
# priorite du tunnel vers une autre table.
tiers_coeur_apres_meme() {
  for f in -4 -6; do
    I "$f" rule add lookup "$COEUR_TABLE" pref 9115
    I "$f" route add default dev tiers0 table "$COEUR_TABLE" metric 100
    I "$f" rule add lookup 100 pref 9120
  done
}

# Le tiers aux MEMES priorites que le coeur, dans une autre table, dont une
# regle plus etroite que celle du LAN du produit.
tiers_coeur_autre() {
  I -4 rule add from 192.0.2.0/24 lookup main suppress_prefixlength 0 pref 9110
  I -6 rule add from 2001:db8:1::/64 lookup main suppress_prefixlength 0 pref 9110
  for f in -4 -6; do
    I "$f" rule add lookup 100 pref 9120
    I "$f" rule add uidrange "$COMPTE-$COMPTE" lookup 100 pref 9100
    I "$f" route add default dev tiers0 table 100
  done
}

# Le tiers WireGuard qui porte le NOM d'interface du produit (sans sa cle),
# sous la forme de wg-quick dans une autre table.
tiers_nom() {
  I link add bfwg0 type wireguard
  I link set bfwg0 up
  for f in -4 -6; do
    I "$f" rule add not fwmark "$AUTRE" table "$AUTRE"
    I "$f" rule add table main suppress_prefixlength 0
  done
  I -4 route add 0.0.0.0/0 dev bfwg0 table "$AUTRE"
  I -6 route add ::/0 dev bfwg0 table "$AUTRE"
}

tiers() {
  case $CAS in
    wg-avant-nom) tiers_nom ;;
    wg-avant-meme) tiers_wg "$TABLE" ;;
    wg-apres-meme) tiers_wg "$TABLE" 100 ;;
    wg-*-autre) tiers_wg "$AUTRE" ;;
    coeur-avant-meme) tiers_coeur_meme ;;
    coeur-apres-meme) tiers_coeur_apres_meme ;;
    coeur-*-autre) tiers_coeur_autre ;;
  esac
}

# La preuve passive sur la pose du produit: MATCH.
prouver() {
  local intention="$BAC/intention.json" code=0
  case $CAS in
    wg-*)
      jq -n --argjson m "$MARQUE" --argjson t "$TABLE" \
        '{schema_version:1, chemin:"wireguard", interface:"bfwg0", fwmark:$m, table:$t, coeur_uid:null}' > "$intention"
      ;;
    coeur-*)
      jq -n --argjson u "$COMPTE" \
        '{schema_version:1, chemin:"coeur", interface:"bftun0", fwmark:null, table:null, coeur_uid:$u}' > "$intention"
      ;;
  esac
  ip netns exec "$NS" "$CLI" --json prove routes --intention "$intention" --actif > "$BAC/preuve.json" || code=$?
  if [ "$code" != 0 ] || ! jq -e '.verdict == "MATCH" and .differences == []' "$BAC/preuve.json" >/dev/null; then
    ecart "prove routes ne rend pas MATCH sur la pose (code $code): $(jq -c '.differences' "$BAC/preuve.json")"
  fi
}

nouveau_ns
case $CAS in coeur-*) tun_factice ;; esac

case $CAS in
  *-libre)
    releve "$BAC/s0"
    exiger_monte
    releve "$BAC/s1"
    if cmp -s "$BAC/s0" "$BAC/s1"; then ecart "le montage n'a rien pose"; fi
    moins "$BAC/s1" "$BAC/s0" > "$BAC/pose"
    prouver
    exiger_demonte
    releve "$BAC/s2"
    exiger_egal "$BAC/s0" "$BAC/s2" "monter puis demonter ne rend pas l'etat initial"
    # Chaque regle et chaque route de la table du tunnel posees portent
    # l'etiquette du produit.
    grep -E '^(r4|r6) ' "$BAC/pose" > "$BAC/pose-regles" || true
    test -s "$BAC/pose-regles" || ecart "aucune regle posee"
    if grep -vE ' proto 177' "$BAC/pose-regles" > "$BAC/sans-etiquette"; then
      ecart "regle posee sans l'etiquette du produit: $(cat "$BAC/sans-etiquette")"
    fi
    ;;
  *-avant-meme)
    releve "$BAC/s0"
    tiers
    releve "$BAC/s1"
    produit monter
    releve "$BAC/s2"
    exiger_egal "$BAC/s1" "$BAC/s2" "le montage refuse a change l'etat"
    exiger_demonte
    releve "$BAC/s3"
    exiger_egal "$BAC/s1" "$BAC/s3" "le demontage apres un refus a retire ce qui n'est pas au produit"
    produit monter
    case $CAS in wg-*) t=$TABLE ;; *) t=$COEUR_TABLE ;; esac
    if [ "$CODE" = 0 ]; then
      ecart "le montage dans une table occupee est accepte"
    elif ! grep -F "montage refuse" "$BAC/produit.err" >/dev/null \
      || ! grep -F "table $t" "$BAC/produit.err" >/dev/null; then
      ecart "le refus ne nomme pas la table $t: $(cat "$BAC/produit.err")"
    else
      echo "  refus: $(cat "$BAC/produit.err")"
    fi
    releve "$BAC/s4"
    exiger_egal "$BAC/s1" "$BAC/s4" "le second montage refuse a change l'etat"
    ;;
  *-apres-meme | *-apres-autre)
    releve "$BAC/s0"
    exiger_monte
    releve "$BAC/s1"
    moins "$BAC/s1" "$BAC/s0" > "$BAC/pose"
    tiers
    releve "$BAC/s2"
    moins "$BAC/s2" "$BAC/s1" > "$BAC/du-tiers"
    test -s "$BAC/du-tiers" || ecart "le tiers n'a rien pose"
    exiger_demonte
    releve "$BAC/s3"
    moins "$BAC/s2" "$BAC/pose" > "$BAC/attendu"
    exiger_egal "$BAC/attendu" "$BAC/s3" "le demontage n'a pas retire exactement ce que le produit a pose"
    ;;
  *-avant-autre)
    releve "$BAC/s0"
    tiers
    releve "$BAC/s1"
    exiger_monte
    releve "$BAC/s2"
    if cmp -s "$BAC/s1" "$BAC/s2"; then ecart "le montage n'a rien pose"; fi
    exiger_demonte
    releve "$BAC/s3"
    exiger_egal "$BAC/s1" "$BAC/s3" "le demontage n'a pas rendu l'etat du tiers"
    ;;
  wg-avant-nom)
    releve "$BAC/s0"
    tiers
    releve "$BAC/s1"
    produit monter
    if [ "$CODE" = 0 ]; then
      ecart "le montage sur l'interface d'un tiers est accepte"
    elif ! grep -F "montage refuse" "$BAC/produit.err" >/dev/null \
      || ! grep -F "interface bfwg0" "$BAC/produit.err" >/dev/null; then
      ecart "le refus ne nomme pas l'interface bfwg0: $(cat "$BAC/produit.err")"
    else
      echo "  refus: $(cat "$BAC/produit.err")"
    fi
    releve "$BAC/s2"
    exiger_egal "$BAC/s1" "$BAC/s2" "le montage refuse a change l'etat"
    exiger_demonte
    releve "$BAC/s3"
    exiger_egal "$BAC/s1" "$BAC/s3" "le demontage apres un refus a retire ce qui n'est pas au produit"
    ;;
  wg-reste-lien)
    releve "$BAC/s0"
    exiger_monte
    releve "$BAC/s1"
    # Une session interrompue sans demontage: tout reste, interface comprise.
    exiger_monte
    releve "$BAC/s2"
    exiger_egal "$BAC/s1" "$BAC/s2" "le montage sur le reste de la session ne rend pas l'etat du premier"
    exiger_demonte
    releve "$BAC/s3"
    exiger_egal "$BAC/s0" "$BAC/s3" "le demontage ne rend pas l'etat initial"
    ;;
  *-reste)
    releve "$BAC/s0"
    exiger_monte
    releve "$BAC/s1"
    # Une session interrompue: l'interface disparait, les regles restent.
    case $CAS in
      wg-*) I link del bfwg0 ;;
      coeur-*)
        I link del bftun0
        tun_factice
        ;;
    esac
    releve "$BAC/s-interrompu"
    exiger_monte
    releve "$BAC/s2"
    exiger_egal "$BAC/s1" "$BAC/s2" "le montage apres une session interrompue ne rend pas l'etat du premier"
    exiger_demonte
    releve "$BAC/s3"
    exiger_egal "$BAC/s0" "$BAC/s3" "le demontage ne rend pas l'etat initial"
    ;;
  *)
    echo "cas inconnu: $CAS" >&2
    exit 2
    ;;
esac
test "$ECART" = 0
