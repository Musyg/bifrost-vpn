#!/usr/bin/env bash
# Banc jetable du routage du produit face aux tiers et a ses propres
# sessions: le produit ne retire que ce qu'une de ses sessions a pose et
# enregistre, et refuse de se poser dans une table ou sur une marque qu'un
# tiers emploie, a cote d'une autre de ses sessions vivante, ou devant un objet
# a son etiquette qu'aucune session n'a enregistre.
#
# Tout se passe dans un espace de montage prive (tmpfs sur /run et /tmp: le
# journal des sessions du produit, /run/bifrost/routage, et les namespaces
# reseau du banc n'existent que la), et chaque cas dans SON namespace reseau,
# cree ici et retire ici. Rien de l'hote n'est lu ni touche. Adresses de
# documentation seulement (RFC 5737 et RFC 3849), interfaces factices
# (`dummy`) sans lien vers l'exterieur, et des interfaces WireGuard sans pair
# joignable.
#
# Le produit est appele par ses fonctions a lui, au travers de l'exemple
# `banc_demontage`, qui tient une session comme le daemon la tient: le meme
# objet monte, puis demonte sur ordre (`LinuxTunnel::up` et `down` pour
# WireGuard, le module noyau `wireguard` est necessaire; pour le chemin par
# coeur ce que `CoeurTunnel` fait du routage, une interface factice tenant
# lieu de TUN). Un porteur tue sans demontage est un daemon tue; un porteur
# qui sort sans demontage est un daemon arrete, qui ne demonte pas son
# tunnel: dans les deux cas ses objets restent, et sa session aussi, au
# journal. Un porteur a ordres (`porter`) garde ses deux peripheriques d'un
# montage a l'autre, comme le superviseur d'une connexion a la suivante.
#
# Les tiers sont poses a la main: sous la forme de wg-quick (`add_default` de
# wireguard-tools, src/wg-quick/linux.bash), sous celle de l'aiguillage du
# coeur, ou avec l'etiquette du produit (177).
#
# Pour chaque chemin (WireGuard, coeur), dans les deux familles:
# - libre: monter puis demonter rend l'etat initial exact, et la preuve
#   `prove routes` rend MATCH sur la pose;
# - tiers avant, meme table: refus nomme, rien pose, rien retire, et le
#   demontage qui suit ne retire rien non plus;
# - tiers apres, meme table: le demontage laisse tout ce que le tiers a pose;
# - tiers avant ou apres, autre table (et, pour le coeur, memes priorites):
#   montage accepte, demontage exact;
# - reste d'une session tuee: le montage suivant le retire et pose un etat
#   identique au premier; le demontage rend l'etat initial;
# - objets a l'etiquette du produit qu'aucune session n'a enregistres, poses
#   avant: refus nomme, rien retire; et le reste d'une session tuee dont le
#   journal a disparu est traite de meme;
# - une autre session du produit vivante dans le namespace: refus nomme, rien
#   retire, et elle se demonte ensuite exactement;
# - une session tuee sous un autre profil, ou par l'autre chemin: le montage
#   suivant retire tout ce qu'elle avait pose, interface comprise, et rien ne
#   reste d'elle;
# - un daemon arrete sans demontage: ce qui reste est compte; le montage
#   suivant le retire et pose un etat identique au premier, et sans le
#   journal il refuse, rien retire;
# - le meme peripherique monte, demonte, puis remonte: le second montage rend
#   l'etat du premier, et chaque demontage l'etat initial.
# Pour le coeur seul: un montage refuse, le demontage qui suit, puis un
# nouveau montage une fois la voie libre. Et sur un meme porteur, le
# peripherique WireGuard monte: un montage par coeur est refuse, rien retire.
# Et pour WireGuard seul:
# - tiers avant, meme NOM d'interface (autre table): refus nomme, rien pose,
#   rien retire, et le demontage qui suit laisse l'interface du tiers;
# - session tuee qui laisse l'interface du produit (sa cle): le montage
#   suivant la reconnait, la retire et pose un etat identique;
# - une regle a l'etiquette du produit posee par un tiers apres le montage: le
#   demontage la laisse et retire la sienne.
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
for outil in ip jq stat seq sed grep cmp sysctl unshare mount mkfifo wc; do
  command -v "$outil" >/dev/null
done
test -x "$OUTIL"
test -x "$CLI"

# Le journal des sessions du produit, sous son repertoire d'execution.
JOURNAL_PRODUIT=/run/bifrost/routage

# Les valeurs par defaut du produit, qui sont celles de wg-quick.
MARQUE=51820
TABLE=51820
# Celles que wg-quick prend quand 51820 est occupee, et un second profil.
AUTRE=51821
COMPTE=4242
COEUR_TABLE=2847

CAS_TOUS="wg-libre wg-avant-meme wg-apres-meme wg-avant-autre wg-apres-autre wg-reste
wg-avant-nom wg-reste-lien
coeur-libre coeur-avant-meme coeur-apres-meme coeur-avant-autre coeur-apres-autre coeur-reste
wg-etiquete-avant-meme wg-etiquete-avant-autre coeur-etiquete-avant wg-etiquete-apres
wg-reste-sans-journal coeur-reste-sans-journal
wg-deux-sessions coeur-deux-sessions
wg-crash-autre-profil wg-crash-meme-table wg-crash-puis-coeur coeur-crash-puis-wg
wg-arret coeur-arret wg-arret-sans-journal coeur-arret-sans-journal
wg-reconnexion coeur-reconnexion coeur-refus-puis-reconnexion wg-tenu-puis-coeur"

# --- l'espace de montage prive ----------------------------------------------
# Le banc se relance une fois dans un espace de montage a lui, ou /run et /tmp
# sont des tmpfs neufs. La garde compare l'espace de montage courant a celui
# de PID 1: s'ils sont les memes, rien n'est monte.
if [ "${BANC_ROUTAGE_ISOLE:-}" != 1 ]; then
  exec unshare --mount --propagation private env BANC_ROUTAGE_ISOLE=1 bash "$0" "$@"
fi
if [ "$(stat -L -c %i /proc/self/ns/mnt)" = "$(stat -L -c %i /proc/1/ns/mnt)" ]; then
  echo "espace de montage partage avec PID 1: arret avant tout montage" >&2
  exit 2
fi

# --- le pere: chaque cas dans son propre processus -------------------------
if [ "${1:-}" != --cas ]; then
  mount -t tmpfs -o mode=0755 bifrost-banc-run /run
  mount -t tmpfs -o mode=1777 bifrost-banc-tmp /tmp
  rouges=0
  vus=0
  for cas in ${BANC_CAS:-$CAS_TOUS}; do
    vus=$((vus + 1))
    if bash "$0" --cas "$cas"; then
      echo "PASSED: $cas"
    else
      echo "FAILED: $cas"
      rouges=$((rouges + 1))
    fi
  done
  echo "banc du routage: $vus cas, $rouges rouge(s)"
  test "$rouges" = 0
  exit 0
fi

# --- un cas -----------------------------------------------------------------
CAS=$2
NS="bfrt-$$"
BAC=$(mktemp -d)
ECART=0
CODE=0
declare -A PID_DE FD_DE LIGNES_DE
# Un ordre ecrit a un porteur deja mort rend une erreur, pas la mort du banc.
trap '' PIPE

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
  local code=$? nom
  for nom in "${!PID_DE[@]}"; do
    kill -KILL "${PID_DE[$nom]}" 2>/dev/null || true
    wait "${PID_DE[$nom]}" 2>/dev/null || true
  done
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

# `aucune_trace <etat> <motif> <quoi>`: aucune ligne de l'etat ne porte le
# motif (expression etendue).
aucune_trace() {
  if grep -E "$2" "$1" > "$BAC/traces"; then
    ecart "$3"
    sed 's/^/    reste:    /' "$BAC/traces" >&2
  fi
}

# `exiger_etiquetes <etat> <nombre> <quoi>`: exactement ce nombre de regles et
# de routes a l'etiquette du produit, ceux d'une seule session.
exiger_etiquetes() {
  local n
  n=$(grep -cE '^(r4|r6|t4|t6) .* proto 177( |$)' "$1" || true)
  if [ "$n" != "$2" ]; then
    ecart "$3: $n objets a l'etiquette du produit au lieu de $2"
    grep -E '^(r4|r6|t4|t6) .* proto 177( |$)' "$1" | sed 's/^/    etiquete: /' >&2 || true
  fi
}

# `compter_etiquetes <etat> <quoi>`: le nombre de regles et de routes a
# l'etiquette du produit, releve pour le rapport.
compter_etiquetes() {
  echo "  objets a l'etiquette du produit $2: $(grep -cE '^(r4|r6|t4|t6) .* proto 177( |$)' "$1" || true)"
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
# de documentation, RFC 7042): un cas la recree, et une adresse tiree au
# hasard ferait un ecart qui n'est pas celui du produit.
tun_factice() {
  local nom=${1:-bftun0} mac=${2:-00:00:5e:00:53:01}
  I link add "$nom" address "$mac" type dummy
  I link set "$nom" addrgenmode none
  I -4 addr add 198.51.100.2/32 dev "$nom"
  I -6 addr add 2001:db8:2::2/128 dev "$nom" nodad
  I link set "$nom" up
}

# --- les porteurs de session ------------------------------------------------
# `demarrer <nom> <arguments de l'outil>`: le porteur part et rend sa premiere
# reponse dans CODE.
demarrer() {
  local nom=$1 fd
  shift
  mkfifo "$BAC/$nom.in"
  : > "$BAC/$nom.out"
  ip netns exec "$NS" "$OUTIL" "$@" < "$BAC/$nom.in" > "$BAC/$nom.out" 2> "$BAC/$nom.err" &
  PID_DE[$nom]=$!
  exec {fd}> "$BAC/$nom.in"
  FD_DE[$nom]=$fd
  LIGNES_DE[$nom]=1
  reponse "$nom"
}

# `lancer <nom> <arguments de tenir>`: un porteur monte et attend ses ordres.
# CODE vaut 0 s'il a monte, 1 s'il a refuse (raison dans $BAC/<nom>.raison).
lancer() {
  local nom=$1
  shift
  demarrer "$nom" tenir "$@"
}

# `porteur <nom>`: un porteur a ordres, rien de monte.
porteur() {
  demarrer "$1" porter
  if [ "$CODE" != 0 ]; then ecart "le porteur $1 n'est pas pret"; fi
}

# Attend la reponse suivante du porteur et la lit dans CODE.
reponse() {
  local nom=$1 n=${LIGNES_DE[$1]} l
  for _ in $(seq 1 200); do
    if [ "$(wc -l < "$BAC/$nom.out")" -ge "$n" ]; then
      l=$(sed -n "${n}p" "$BAC/$nom.out")
      case $l in
        monte | demonte | pret) CODE=0 ;;
        refuse\ * | echec\ *)
          CODE=1
          printf '%s\n' "${l#* }" > "$BAC/$nom.raison"
          ;;
        *)
          CODE=2
          ecart "reponse inattendue du porteur $nom: $l"
          ;;
      esac
      return 0
    fi
    if ! kill -0 "${PID_DE[$nom]}" 2>/dev/null; then
      CODE=3
      ecart "le porteur $nom est mort sans repondre: $(cat "$BAC/$nom.err")"
      return 0
    fi
    sleep 0.1
  done
  CODE=3
  ecart "le porteur $nom ne repond pas"
}

ordre() {
  local nom=$1
  echo "$2" >&"${FD_DE[$nom]}" 2>/dev/null || true
  LIGNES_DE[$nom]=$((LIGNES_DE[$nom] + 1))
  reponse "$nom"
}

# Le porteur meurt sans rien demonter: un daemon tue.
tuer() {
  local nom=$1 fd=${FD_DE[$1]}
  kill -KILL "${PID_DE[$nom]}" 2>/dev/null || true
  wait "${PID_DE[$nom]}" 2>/dev/null || true
  exec {fd}>&-
  unset "PID_DE[$nom]"
}

# Le porteur sort sans rien demonter, comme un daemon arrete.
finir() {
  local nom=$1 fd=${FD_DE[$1]}
  echo fin >&"$fd" 2>/dev/null || true
  wait "${PID_DE[$nom]}" 2>/dev/null || true
  exec {fd}>&-
  unset "PID_DE[$nom]"
}

exiger_monte() {
  local nom=$1
  lancer "$@"
  if [ "$CODE" != 0 ]; then
    ecart "montage de $nom refuse ou en echec: $(cat "$BAC/$nom.raison" 2>/dev/null)"
  fi
}

# `exiger_refus <nom> <ce que le refus nomme> <arguments de tenir>`
exiger_refus() {
  local nom=$1 motif=$2
  shift 2
  lancer "$nom" "$@"
  if [ "$CODE" = 0 ]; then
    ecart "le montage de $nom est accepte"
  elif ! grep -F "montage refuse" "$BAC/$nom.raison" >/dev/null \
    || ! grep -F -- "$motif" "$BAC/$nom.raison" >/dev/null; then
    ecart "le refus de $nom ne nomme pas '$motif': $(cat "$BAC/$nom.raison" 2>/dev/null)"
  else
    echo "  refus ($nom): $(cat "$BAC/$nom.raison")"
  fi
}

exiger_hors_journal() {
  if compgen -G "$JOURNAL_PRODUIT/${PID_DE[$1]}-*" >/dev/null; then
    ecart "la session de $1 reste au journal apres son demontage"
  fi
}

exiger_demonte() {
  local nom=$1
  ordre "$nom" demonter
  if [ "$CODE" != 0 ]; then
    ecart "demontage de $nom en echec: $(cat "$BAC/$nom.raison" 2>/dev/null)"
  fi
  exiger_hors_journal "$nom"
}

# `exiger_ordre <nom> <ordre>`: un ordre au porteur a ordres, qui aboutit.
exiger_ordre() {
  ordre "$1" "$2"
  if [ "$CODE" != 0 ]; then
    ecart "'$2' de $1 refuse ou en echec: $(cat "$BAC/$1.raison" 2>/dev/null)"
  fi
}

# `exiger_ordre_refuse <nom> <ce que le refus nomme> <ordre>`
exiger_ordre_refuse() {
  ordre "$1" "$3"
  if [ "$CODE" = 0 ]; then
    ecart "'$3' de $1 est accepte"
  elif ! grep -F "montage refuse" "$BAC/$1.raison" >/dev/null \
    || ! grep -F -- "$2" "$BAC/$1.raison" >/dev/null; then
    ecart "le refus de '$3' ne nomme pas '$2': $(cat "$BAC/$1.raison" 2>/dev/null)"
  else
    echo "  refus ($1, $3): $(cat "$BAC/$1.raison")"
  fi
}

# Les profils du banc: WireGuard par defaut, un second profil WireGuard (autre
# interface, autre cle, marque et table 51821), et le coeur.
WG_A=(wireguard bfwg0 "$MARQUE" "$TABLE")
WG_B=(wireguard bfwg1 "$AUTRE" "$AUTRE")
WG_B_MEME=(wireguard bfwg1 "$MARQUE" "$TABLE")
COEUR_A=(coeur bftun0 "$COMPTE")
COEUR_B=(coeur bftun1 "$COMPTE")
case $CAS in
  wg-*) PROFIL=("${WG_A[@]}") ;;
  coeur-*) PROFIL=("${COEUR_A[@]}") ;;
esac

# --- les tiers --------------------------------------------------------------
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

# Le meme, a l'etiquette du produit.
tiers_wg_etiquete() {
  local t=$1
  for f in -4 -6; do
    I "$f" rule add not fwmark "$t" table "$t" protocol 177
    I "$f" rule add table main suppress_prefixlength 0 protocol 177
  done
  I -4 route add 0.0.0.0/0 dev tiers0 table "$t" proto 177
  I -6 route add ::/0 dev tiers0 table "$t" proto 177
}

# Une regle de la forme de celle du LAN du produit, a son etiquette.
tiers_lan_etiquete() {
  for f in -4 -6; do
    I "$f" rule add table main suppress_prefixlength 0 protocol 177
  done
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

# Le meme, retire par le banc, objet par objet.
retirer_tiers_coeur_meme() {
  for f in -4 -6; do
    I "$f" route del default dev tiers0 table "$COEUR_TABLE"
    I "$f" rule del lookup "$COEUR_TABLE" pref 9120
    I "$f" rule del lookup main suppress_prefixlength 0 pref 9110
    I "$f" rule del uidrange "$COMPTE-$COMPTE" lookup main pref 9100
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

# Le tiers de la forme de l'aiguillage du coeur, a l'etiquette du produit:
# la regle du LAN a sa priorite, et une autre table.
tiers_coeur_etiquete() {
  for f in -4 -6; do
    I "$f" rule add lookup main suppress_prefixlength 0 pref 9110 protocol 177
    I "$f" rule add lookup 100 pref 9120 protocol 177
    I "$f" route add default dev tiers0 table 100 proto 177
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
    wg-avant-autre | wg-apres-autre) tiers_wg "$AUTRE" ;;
    coeur-avant-meme) tiers_coeur_meme ;;
    coeur-apres-meme) tiers_coeur_apres_meme ;;
    coeur-avant-autre | coeur-apres-autre) tiers_coeur_autre ;;
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

# Le journal disparait, comme sous un superviseur qui vide le repertoire
# d'execution: les sessions qu'il enregistrait ne sont plus connues.
vider_le_journal() {
  rm -rf -- "$JOURNAL_PRODUIT"
}

nouveau_ns
case $CAS in
  coeur-* | wg-crash-puis-coeur | wg-tenu-puis-coeur) tun_factice ;;
esac
case $CAS in coeur-deux-sessions) tun_factice bftun1 00:00:5e:00:53:02 ;; esac

case $CAS in
  wg-libre | coeur-libre)
    releve "$BAC/s0"
    exiger_monte A "${PROFIL[@]}"
    releve "$BAC/s1"
    if cmp -s "$BAC/s0" "$BAC/s1"; then ecart "le montage n'a rien pose"; fi
    moins "$BAC/s1" "$BAC/s0" > "$BAC/pose"
    prouver
    exiger_demonte A
    releve "$BAC/s2"
    exiger_egal "$BAC/s0" "$BAC/s2" "monter puis demonter ne rend pas l'etat initial"
    # Chaque regle et chaque route de la table du tunnel posees portent
    # l'etiquette du produit.
    grep -E '^(r4|r6) ' "$BAC/pose" > "$BAC/pose-regles" || true
    test -s "$BAC/pose-regles" || ecart "aucune regle posee"
    if grep -vE ' proto 177' "$BAC/pose-regles" > "$BAC/sans-etiquette"; then
      ecart "regle posee sans l'etiquette du produit: $(cat "$BAC/sans-etiquette")"
    fi
    finir A
    ;;
  wg-avant-meme | coeur-avant-meme)
    releve "$BAC/s0"
    tiers
    releve "$BAC/s1"
    case $CAS in wg-*) t=$TABLE ;; *) t=$COEUR_TABLE ;; esac
    exiger_refus A "table $t" "${PROFIL[@]}"
    releve "$BAC/s2"
    exiger_egal "$BAC/s1" "$BAC/s2" "le montage refuse a change l'etat"
    exiger_demonte A
    releve "$BAC/s3"
    exiger_egal "$BAC/s1" "$BAC/s3" "le demontage apres un refus a retire ce qui n'est pas au produit"
    finir A
    exiger_refus A2 "table $t" "${PROFIL[@]}"
    releve "$BAC/s4"
    exiger_egal "$BAC/s1" "$BAC/s4" "le second montage refuse a change l'etat"
    finir A2
    ;;
  wg-apres-meme | wg-apres-autre | coeur-apres-meme | coeur-apres-autre)
    releve "$BAC/s0"
    exiger_monte A "${PROFIL[@]}"
    releve "$BAC/s1"
    moins "$BAC/s1" "$BAC/s0" > "$BAC/pose"
    tiers
    releve "$BAC/s2"
    moins "$BAC/s2" "$BAC/s1" > "$BAC/du-tiers"
    test -s "$BAC/du-tiers" || ecart "le tiers n'a rien pose"
    exiger_demonte A
    releve "$BAC/s3"
    moins "$BAC/s2" "$BAC/pose" > "$BAC/attendu"
    exiger_egal "$BAC/attendu" "$BAC/s3" "le demontage n'a pas retire exactement ce que le produit a pose"
    finir A
    ;;
  wg-avant-autre | coeur-avant-autre)
    releve "$BAC/s0"
    tiers
    releve "$BAC/s1"
    exiger_monte A "${PROFIL[@]}"
    releve "$BAC/s2"
    if cmp -s "$BAC/s1" "$BAC/s2"; then ecart "le montage n'a rien pose"; fi
    exiger_demonte A
    releve "$BAC/s3"
    exiger_egal "$BAC/s1" "$BAC/s3" "le demontage n'a pas rendu l'etat du tiers"
    finir A
    ;;
  wg-avant-nom)
    releve "$BAC/s0"
    tiers
    releve "$BAC/s1"
    exiger_refus A "interface bfwg0" "${PROFIL[@]}"
    releve "$BAC/s2"
    exiger_egal "$BAC/s1" "$BAC/s2" "le montage refuse a change l'etat"
    exiger_demonte A
    releve "$BAC/s3"
    exiger_egal "$BAC/s1" "$BAC/s3" "le demontage apres un refus a retire ce qui n'est pas au produit"
    finir A
    ;;
  wg-reste-lien)
    releve "$BAC/s0"
    exiger_monte A "${PROFIL[@]}"
    releve "$BAC/s1"
    # Une session tuee sans demontage: tout reste, interface comprise.
    tuer A
    exiger_monte A2 "${PROFIL[@]}"
    releve "$BAC/s2"
    exiger_egal "$BAC/s1" "$BAC/s2" "le montage sur le reste de la session ne rend pas l'etat du premier"
    exiger_demonte A2
    releve "$BAC/s3"
    exiger_egal "$BAC/s0" "$BAC/s3" "le demontage ne rend pas l'etat initial"
    finir A2
    ;;
  wg-reste | coeur-reste)
    releve "$BAC/s0"
    exiger_monte A "${PROFIL[@]}"
    releve "$BAC/s1"
    # Une session tuee: l'interface disparait, les regles restent.
    tuer A
    case $CAS in
      wg-*) I link del bfwg0 ;;
      coeur-*)
        I link del bftun0
        tun_factice
        ;;
    esac
    exiger_monte A2 "${PROFIL[@]}"
    releve "$BAC/s2"
    exiger_egal "$BAC/s1" "$BAC/s2" "le montage apres une session tuee ne rend pas l'etat du premier"
    exiger_demonte A2
    releve "$BAC/s3"
    exiger_egal "$BAC/s0" "$BAC/s3" "le demontage ne rend pas l'etat initial"
    finir A2
    ;;
  wg-etiquete-avant-meme | wg-etiquete-avant-autre | coeur-etiquete-avant)
    releve "$BAC/s0"
    case $CAS in
      wg-etiquete-avant-meme) tiers_wg_etiquete "$TABLE" ;;
      wg-etiquete-avant-autre) tiers_wg_etiquete "$AUTRE" ;;
      coeur-*) tiers_coeur_etiquete ;;
    esac
    releve "$BAC/s1"
    exiger_refus A "177" "${PROFIL[@]}"
    releve "$BAC/s2"
    exiger_egal "$BAC/s1" "$BAC/s2" "le montage devant des objets a l'etiquette du produit a change l'etat"
    exiger_demonte A
    releve "$BAC/s3"
    exiger_egal "$BAC/s1" "$BAC/s3" "le demontage apres un refus a retire ce qui n'est pas au produit"
    finir A
    ;;
  wg-etiquete-apres)
    releve "$BAC/s0"
    exiger_monte A "${PROFIL[@]}"
    releve "$BAC/s1"
    moins "$BAC/s1" "$BAC/s0" > "$BAC/pose"
    tiers_lan_etiquete
    releve "$BAC/s2"
    exiger_demonte A
    releve "$BAC/s3"
    moins "$BAC/s2" "$BAC/pose" > "$BAC/attendu"
    exiger_egal "$BAC/attendu" "$BAC/s3" "le demontage n'a pas retire exactement ce que le produit a pose"
    finir A
    ;;
  wg-reste-sans-journal | coeur-reste-sans-journal)
    releve "$BAC/s0"
    exiger_monte A "${PROFIL[@]}"
    releve "$BAC/s1"
    tuer A
    case $CAS in
      coeur-*)
        I link del bftun0
        tun_factice
        ;;
    esac
    releve "$BAC/s1b"
    vider_le_journal
    exiger_refus A2 "177" "${PROFIL[@]}"
    releve "$BAC/s2"
    exiger_egal "$BAC/s1b" "$BAC/s2" "le montage devant le reste d'une session inconnue a change l'etat"
    exiger_demonte A2
    releve "$BAC/s3"
    exiger_egal "$BAC/s1b" "$BAC/s3" "le demontage apres un refus a retire ce qui n'est pas au produit"
    finir A2
    ;;
  wg-deux-sessions | coeur-deux-sessions)
    releve "$BAC/s0"
    exiger_monte A "${PROFIL[@]}"
    releve "$BAC/s1"
    case $CAS in
      wg-*) exiger_refus B "autre session du produit" "${WG_B[@]}" ;;
      coeur-*) exiger_refus B "autre session du produit" "${COEUR_B[@]}" ;;
    esac
    releve "$BAC/s2"
    exiger_egal "$BAC/s1" "$BAC/s2" "le montage d'une seconde session a change l'etat de la premiere"
    exiger_demonte B
    releve "$BAC/s3"
    exiger_egal "$BAC/s1" "$BAC/s3" "le demontage de la seconde session a retire ce qu'elle n'a pas pose"
    exiger_demonte A
    releve "$BAC/s4"
    exiger_egal "$BAC/s0" "$BAC/s4" "le demontage de la premiere ne rend pas l'etat initial"
    finir B
    finir A
    ;;
  wg-crash-autre-profil | wg-crash-meme-table)
    releve "$BAC/s0"
    exiger_monte A "${WG_A[@]}"
    releve "$BAC/s1"
    tuer A
    case $CAS in
      wg-crash-autre-profil) exiger_monte B "${WG_B[@]}" ;;
      *) exiger_monte B "${WG_B_MEME[@]}" ;;
    esac
    releve "$BAC/s2"
    aucune_trace "$BAC/s2" 'bfwg0' "il reste des objets de la session tuee"
    exiger_etiquetes "$BAC/s2" 6 "apres le montage de la seconde session"
    exiger_demonte B
    releve "$BAC/s3"
    exiger_egal "$BAC/s0" "$BAC/s3" "le demontage de la seconde session ne rend pas l'etat initial"
    finir B
    ;;
  wg-crash-puis-coeur)
    releve "$BAC/s0"
    exiger_monte A "${WG_A[@]}"
    tuer A
    exiger_monte C "${COEUR_A[@]}"
    releve "$BAC/s2"
    aucune_trace "$BAC/s2" 'bfwg0|lookup 51820' "il reste des objets de la session WireGuard tuee"
    exiger_etiquetes "$BAC/s2" 8 "apres le montage du coeur"
    exiger_demonte C
    releve "$BAC/s3"
    exiger_egal "$BAC/s0" "$BAC/s3" "le demontage du coeur ne rend pas l'etat initial"
    finir C
    ;;
  coeur-crash-puis-wg)
    releve "$BAC/s0"
    exiger_monte C "${COEUR_A[@]}"
    tuer C
    I link del bftun0
    tun_factice
    exiger_monte A "${WG_A[@]}"
    releve "$BAC/s2"
    aucune_trace "$BAC/s2" '^r[46] 91[0-2]0:|lookup 2847' "il reste des objets de la session du coeur tuee"
    exiger_etiquetes "$BAC/s2" 6 "apres le montage de WireGuard"
    exiger_demonte A
    releve "$BAC/s3"
    exiger_egal "$BAC/s0" "$BAC/s3" "le demontage de WireGuard ne rend pas l'etat initial"
    finir A
    ;;
  wg-arret | coeur-arret | wg-arret-sans-journal | coeur-arret-sans-journal)
    releve "$BAC/s0"
    exiger_monte A "${PROFIL[@]}"
    releve "$BAC/s1"
    # Un daemon arrete: il sort sans demonter son tunnel. Le TUN du coeur
    # disparait avec le processus qui le tient, l'interface WireGuard reste.
    finir A
    case $CAS in
      coeur-*)
        I link del bftun0
        tun_factice
        ;;
    esac
    releve "$BAC/s1b"
    compter_etiquetes "$BAC/s1b" "apres l'arret"
    case $CAS in
      *-sans-journal)
        vider_le_journal
        exiger_refus A2 "177" "${PROFIL[@]}"
        releve "$BAC/s2"
        exiger_egal "$BAC/s1b" "$BAC/s2" "le montage devant le reste d'une session inconnue a change l'etat"
        exiger_demonte A2
        releve "$BAC/s3"
        exiger_egal "$BAC/s1b" "$BAC/s3" "le demontage apres un refus a retire ce qui n'est pas au produit"
        ;;
      *)
        exiger_monte A2 "${PROFIL[@]}"
        releve "$BAC/s2"
        exiger_egal "$BAC/s1" "$BAC/s2" "le montage apres un arret ne rend pas l'etat du premier"
        exiger_demonte A2
        releve "$BAC/s3"
        exiger_egal "$BAC/s0" "$BAC/s3" "le demontage ne rend pas l'etat initial"
        ;;
    esac
    finir A2
    ;;
  wg-reconnexion | coeur-reconnexion)
    case $CAS in
      wg-*) moyen="wireguard ${WG_A[*]:1}" ;;
      *) moyen="coeur ${COEUR_A[*]:1}" ;;
    esac
    voie=${moyen%% *}
    releve "$BAC/s0"
    porteur P
    exiger_ordre P "$voie monter ${moyen#* }"
    releve "$BAC/s1"
    if cmp -s "$BAC/s0" "$BAC/s1"; then ecart "le montage n'a rien pose"; fi
    exiger_ordre P "$voie demonter"
    exiger_hors_journal P
    releve "$BAC/s2"
    exiger_egal "$BAC/s0" "$BAC/s2" "la deconnexion ne rend pas l'etat initial"
    exiger_ordre P "$voie monter ${moyen#* }"
    releve "$BAC/s3"
    exiger_egal "$BAC/s1" "$BAC/s3" "le nouveau montage ne rend pas l'etat du premier"
    exiger_ordre P "$voie demonter"
    exiger_hors_journal P
    releve "$BAC/s4"
    exiger_egal "$BAC/s0" "$BAC/s4" "la seconde deconnexion ne rend pas l'etat initial"
    finir P
    ;;
  coeur-refus-puis-reconnexion)
    releve "$BAC/s0"
    tiers_coeur_meme
    releve "$BAC/s1"
    porteur P
    exiger_ordre_refuse P "table $COEUR_TABLE" "coeur monter ${COEUR_A[*]:1}"
    releve "$BAC/s2"
    exiger_egal "$BAC/s1" "$BAC/s2" "le montage refuse a change l'etat"
    # Apres un echec, le superviseur demonte le peripherique, puis reessaie.
    exiger_ordre P "coeur demonter"
    releve "$BAC/s3"
    exiger_egal "$BAC/s1" "$BAC/s3" "le demontage apres un refus a retire ce qui n'est pas au produit"
    retirer_tiers_coeur_meme
    releve "$BAC/s4"
    exiger_egal "$BAC/s0" "$BAC/s4" "le banc n'a pas retire exactement son tiers"
    exiger_ordre P "coeur monter ${COEUR_A[*]:1}"
    releve "$BAC/s5"
    if cmp -s "$BAC/s4" "$BAC/s5"; then ecart "le nouveau montage n'a rien pose"; fi
    exiger_ordre P "coeur demonter"
    exiger_hors_journal P
    releve "$BAC/s6"
    exiger_egal "$BAC/s0" "$BAC/s6" "le demontage ne rend pas l'etat initial"
    finir P
    ;;
  wg-tenu-puis-coeur)
    releve "$BAC/s0"
    porteur P
    exiger_ordre P "wireguard monter ${WG_A[*]:1}"
    releve "$BAC/s1"
    # Le peripherique par coeur n'a rien monte: son demontage ne retire rien.
    exiger_ordre P "coeur demonter"
    releve "$BAC/s2"
    exiger_egal "$BAC/s1" "$BAC/s2" "le demontage d'un peripherique qui n'a rien monte a change l'etat"
    exiger_ordre_refuse P "autre session du produit" "coeur monter ${COEUR_A[*]:1}"
    releve "$BAC/s3"
    exiger_egal "$BAC/s1" "$BAC/s3" "le montage par coeur a change l'etat de la session WireGuard tenue"
    exiger_ordre P "wireguard demonter"
    exiger_hors_journal P
    releve "$BAC/s4"
    exiger_egal "$BAC/s0" "$BAC/s4" "le demontage WireGuard ne rend pas l'etat initial"
    finir P
    ;;
  *)
    echo "cas inconnu: $CAS" >&2
    exit 2
    ;;
esac
test "$ECART" = 0
