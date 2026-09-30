#!/usr/bin/env bash
# Banc jetable: toutes les mutations nft restent dans NOTRE namespace isole.
set -euo pipefail
if [ "$(id -u)" != 0 ]; then
  echo 'Ce banc exige root pour creer son namespace jetable.' >&2
  exit 2
fi
RACINE=$(cd "$(dirname "$0")/.." && pwd)
CLI="$RACINE/target/debug/bifrost-cli"
DAEMON="$RACINE/target/debug/bifrost-daemon"
for outil in ip nft jq setpriv cmp getent stat python3; do command -v "$outil" >/dev/null; done
test -x "$CLI"
test -x "$DAEMON"
BAC=$(mktemp -d)
NS="bfproof-$$"
NSD="bfdecl-$$"
CREE=0
CREE_D=0
PID_DAEMON=""
PID_FAUX=""
COURSE=""
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
  echo "orphelins apres retrait du namespace $ns: $reste"
  [ "$reste" = 0 ]
}
nettoyer() {
  local code=$?
  if [ "$code" != 0 ]; then
    for rapport in match ecart refus vide politique decl faux; do
      if [ -f "$BAC/$rapport.json" ]; then cat "$BAC/$rapport.json"; fi
    done
    for journal in connect.log daemon.log; do
      if [ -f "$BAC/$journal" ]; then tail -n 30 "$BAC/$journal"; fi
    done
  fi
  if [ -n "$COURSE" ]; then kill "$COURSE" 2>/dev/null || true; wait "$COURSE" 2>/dev/null || true; fi
  if [ -n "$PID_FAUX" ]; then
    kill "$PID_FAUX" 2>/dev/null || true
    wait "$PID_FAUX" 2>/dev/null || true
  fi
  if [ -n "$PID_DAEMON" ]; then
    kill "$PID_DAEMON" 2>/dev/null || true
    wait "$PID_DAEMON" 2>/dev/null || true
  fi
  if [ "$CREE_D" = 1 ]; then retirer_netns "$NSD" || code=1; fi
  if [ "$CREE" = 1 ]; then retirer_netns "$NS" || code=1; fi
  rm -rf -- "$BAC"
  exit "$code"
}
trap nettoyer EXIT
cp "$CLI" "$BAC/bifrost-cli"
CLI="$BAC/bifrost-cli"
cp "$DAEMON" "$BAC/bifrost-daemon"
DAEMON="$BAC/bifrost-daemon"
chmod 755 "$BAC" "$CLI" "$DAEMON"
ip netns add "$NS"
CREE=1
# Sans interface physique ni veth: aucun trafic ne peut sortir de ce namespace.
ip netns exec "$NS" nft -f - <<'NFT'
table inet bifrost_preuve {
  chain output {
    type filter hook output priority 0; policy drop;
    oifname "lo" accept
    counter
  }
}
NFT
ip netns exec "$NS" nft --json --numeric list ruleset > "$BAC/reference.json"
chmod 755 "$BAC"
chmod 644 "$BAC/reference.json"
ip netns exec "$NS" "$CLI" --json prove nft --attendu "$BAC/reference.json" --actif > "$BAC/match.json"
jq -e '.verdict == "MATCH" and .scope == "nft-kernel-comparison" and .live_kernel and .generation_verified and .network_security == "not-evaluated"' "$BAC/match.json" >/dev/null
ip netns exec "$NS" nft --json --numeric list ruleset > "$BAC/apres.json"
cmp "$BAC/reference.json" "$BAC/apres.json"
echo 'PASSED: collecte reelle, generation stable, aucune regle modifiee'

ip netns exec "$NS" nft add rule inet bifrost_preuve output accept
CODE=0
ip netns exec "$NS" "$CLI" --json prove nft --attendu "$BAC/reference.json" --actif > "$BAC/ecart.json" || CODE=$?
test "$CODE" = 1
jq -e '.verdict == "MISMATCH" and .generation_verified and (.differences | index("rules") != null)' "$BAC/ecart.json" >/dev/null
echo 'PASSED: une exception ajoutee devient un ecart'

CODE=0
ip netns exec "$NS" setpriv --reuid=65534 --regid=65534 --clear-groups "$CLI" --json prove nft --attendu "$BAC/reference.json" --actif > "$BAC/refus.json" || CODE=$?
test "$CODE" = 2
jq -e '.verdict == "UNMEASURED" and (.generation_verified | not) and .reason == "acces noyau refuse; aucune elevation automatique"' "$BAC/refus.json" >/dev/null
echo 'PASSED: un acces refuse ne devient jamais une absence de regle'

ip netns exec "$NS" nft delete table inet bifrost_preuve
CODE=0
ip netns exec "$NS" "$CLI" --json prove nft --attendu "$BAC/reference.json" --actif > "$BAC/vide.json" || CODE=$?
test "$CODE" = 1
jq -e '.verdict == "MISMATCH" and .observed_counts.tables == 0 and .generation_verified' "$BAC/vide.json" >/dev/null
echo 'PASSED: la disparition du pare-feu devient un ecart'

# Confronter la reference pure au VRAI generateur utilise par le daemon.
# Six dimensions binaires: interface, marque, LAN, coeur, resolveur et DNS v6.
# Le helper ne fait que rendre du texte; seul nft dans NOTRE namespace le pose.
RENDU="$RACINE/target/debug/examples/politique_nft"
test -x "$RENDU"
for ((cas=0; cas<64; cas++)); do
  jq -n --argjson n "$cas" '{schema_version:1,
    tunnel_interface:(if ($n % 2) == 1 then "wg0" else null end),
    fwmark:(if (($n / 2 | floor) % 2) == 1 then 51820 else null end),
    allow_lan:((($n / 4 | floor) % 2) == 1),
    coeur_uid:(if (($n / 8 | floor) % 2) == 1 then 1001 else null end),
    resolveur_uid:(if (($n / 16 | floor) % 2) == 1 then 1002 else null end),
    dns_resolver:(if (($n / 32 | floor) % 2) == 1 then "::1" else "127.0.0.1" end)
  }' > "$BAC/intention.json"
  "$RENDU" "$BAC/intention.json" > "$BAC/produit.nft"
  ip netns exec "$NS" nft -f "$BAC/produit.nft"
  ip netns exec "$NS" nft --json --numeric list ruleset > "$BAC/produit.json"
  if ! "$CLI" --json prove nft --politique "$BAC/intention.json" --observe "$BAC/produit.json" > "$BAC/politique.json"; then
    echo "reference produit en ecart, cas synthetique $cas"
    # Pas de donnees utilisateur dans ce banc: montrer les deux formes utiles.
    "$RENDU" "$BAC/intention.json" json | jq .
    jq . "$BAC/produit.json"
    exit 1
  fi
  jq -e '.verdict == "MATCH" and .expected_source == "bifrost-policy-v1-user-declared" and .policy_schema_version == 1 and (.live_kernel | not)' "$BAC/politique.json" >/dev/null
  ip netns exec "$NS" "$CLI" --json prove nft --politique "$BAC/intention.json" --actif > "$BAC/politique.json"
  jq -e '.verdict == "MATCH" and .generation_verified and .live_kernel and .network_security == "not-evaluated"' "$BAC/politique.json" >/dev/null
  ip netns exec "$NS" nft --json --numeric list ruleset > "$BAC/apres.json"
  cmp "$BAC/produit.json" "$BAC/apres.json"
done
echo 'PASSED: 64 politiques produit, reference hors ligne et collecte reelle, sans mutation'

# Une politique tierce ne doit pas disparaitre de la comparaison.
ip netns exec "$NS" nft add table inet tiers
CODE=0
ip netns exec "$NS" "$CLI" --json prove nft --politique "$BAC/intention.json" --actif > "$BAC/politique.json" || CODE=$?
test "$CODE" = 1
jq -e '.verdict == "MISMATCH" and (.differences | index("tables") != null)' "$BAC/politique.json" >/dev/null
ip netns exec "$NS" nft delete table inet tiers

# Un permis non prevu ne doit jamais devenir conforme au plan produit.
ip netns exec "$NS" nft insert rule inet bifrost output accept
CODE=0
ip netns exec "$NS" "$CLI" --json prove nft --politique "$BAC/intention.json" --actif > "$BAC/politique.json" || CODE=$?
test "$CODE" = 1
jq -e '.verdict == "MISMATCH" and (.differences | index("rules") != null)' "$BAC/politique.json" >/dev/null
echo 'PASSED: table tierce et permis ajoute detectes contre le plan produit'

# --- D1b.3b: l'attendu est ce que le VRAI daemon declare avoir pose ---
#
# Le daemon tourne dans un second namespace jetable, sans veth: rien n'en sort.
# L'etat choisi est le moins cher ou il pose une politique reelle: un profil a
# coeur dont le binaire manque. Le kill switch est arme AVANT le lancement du
# coeur, le lancement echoue sans etre retente, et le daemon reste en erreur,
# kill switch arme. Le tunnel ne monte jamais, donc le DNS de l'hote (partage
# par tous les namespaces via resolvectl ou /etc/resolv.conf) n'est jamais
# touche: c'est la raison de ce choix, et pas seulement son cout.
ip netns add "$NSD"
CREE_D=1
ip netns exec "$NSD" ip link set lo up
SOCKET="$BAC/daemon.sock"
# Le groupe 65534 porte un nom different selon la distribution.
GROUPE=$(getent group 65534 | cut -d: -f1)
test -n "$GROUPE"
mkdir "$BAC/coeurs-vides" "$BAC/configurations"
# Adresses de documentation (RFC 5737): elles ne designent aucune machine.
cat > "$BAC/profil.toml" <<'TOML'
interface = "bfdecl0"
addresses = ["198.51.100.2/32"]

[[coeurs]]
etiquette = "injoignable"
transport = { transport = "vless-websocket", serveur = "192.0.2.10", port = 443, uuid = "00000000-0000-4000-8000-000000000000", nom_de_serveur = "exemple.test", hote = "exemple.test", chemin = "/banc" }

[dns]
local_resolver = "127.0.0.1"
upstream = ["198.51.100.53"]
TOML
# Le client refuse un profil lisible par d'autres: il porte des secrets.
chmod 600 "$BAC/profil.toml"
ip netns exec "$NSD" "$DAEMON" --socket "$SOCKET" --group "$GROUPE" \
  --coeurs-dans "$BAC/coeurs-vides" --coeurs-configurations "$BAC/configurations" \
  --facade 127.0.0.1:1081 --coeur-utilisateur 65534:65534 \
  > "$BAC/daemon.log" 2>&1 &
PID_DAEMON=$!
for _ in $(seq 1 40); do
  if [ -S "$SOCKET" ]; then break; fi
  kill -0 "$PID_DAEMON"
  sleep 0.25
done
test -S "$SOCKET"
# `ip netns exec` fait exec: le PID releve EST le daemon, et il est dans NOTRE
# namespace. Sans cette verification, la suite pourrait tuer un autre processus.
#
# Jamais `grep -q` au bout d'un tube dans ce script: il sort au premier
# resultat, l'ecrivain recoit SIGPIPE, et `pipefail` fait de ce SUCCES un
# echec 141. Mesure du 29/09/2026 sur la machine d'essai: le banc est tombe
# ainsi apres un MATCH, sur la ligne `nft list chain | grep -qF` de l'etape
# de reprise. `grep ... >/dev/null` lit tout et rend le meme verdict.
ip netns pids "$NSD" | grep -x "$PID_DAEMON" >/dev/null

prouver() {
  local sortie=$1
  shift
  CODE=0
  ip netns exec "$NSD" "$@" "$CLI" --json --socket "$SOCKET" prove nft --politique-daemon --actif \
    > "$BAC/$sortie.json" || CODE=$?
}
# Rien de la declaration ne sort: ni UID, ni interface, ni resolveur, ni numero.
# Les horodatages sont retires avant la recherche, ou ils finiraient par
# contenir un de ces nombres par coincidence.
#
# Pas de `! commande` ici ni plus bas: sous `set -e`, une commande inversee
# n'arrete JAMAIS le script, meme quand l'inversion echoue.
muet() {
  jq -e 'has("application") or has("instance") or has("politique") | not' "$BAC/$1.json" >/dev/null
  if jq 'del(.started_at_unix_ms, .completed_at_unix_ms, .duration_ms)' "$BAC/$1.json" \
    | grep -F -e 65534 -e bfdecl0 -e 127.0.0.1 -e 198.51.100 >/dev/null; then
    echo "le rapport exporte un parametre de la declaration" >&2
    return 1
  fi
}
correspond() {
  prouver decl
  test "$CODE" = 0
  jq -e '.verdict == "MATCH" and .schema_version == 1 and .expected_source == "daemon-declared-active-policy" and .daemon_identity == "root-peer-credentials" and .policy_schema_version == 1 and .live_kernel and .generation_verified and .network_security == "not-evaluated" and .failed_input == null' "$BAC/decl.json" >/dev/null
  muet decl
}
ecart() {
  prouver decl
  test "$CODE" = 1
  jq -e --arg d "$1" '.verdict == "MISMATCH" and .expected_source == "daemon-declared-active-policy" and .generation_verified and (.differences | index($d) != null)' "$BAC/decl.json" >/dev/null
  muet decl
}
non_mesure() {
  local raison=$1
  shift
  prouver decl "$@"
  test "$CODE" = 2
  jq -e --arg r "$raison" '.verdict == "UNMEASURED" and .reason == $r and .expected_source == "daemon-declared-active-policy"' "$BAC/decl.json" >/dev/null
  muet decl
}
# Une reprise est asynchrone: le daemon la range et repose plus tard. On attend
# que la table CHANGE (sans compteurs), puis une seule preuve doit correspondre:
# la declaration est servie par le fil qui applique, donc aucune lecture ne
# peut tomber entre la pose et sa note.
reposer() {
  local avant
  avant=$(ip netns exec "$NSD" nft -s list table inet bifrost)
  ip netns exec "$NSD" "$CLI" --socket "$SOCKET" reprise --phase post --operation suspend 2>/dev/null
  for _ in $(seq 1 40); do
    if [ "$(ip netns exec "$NSD" nft -s list table inet bifrost)" != "$avant" ]; then return 0; fi
    sleep 0.25
  done
  echo "le daemon n'a pas repose sa politique apres la reprise" >&2
  return 1
}
# Handle de la premiere regle de la chaine output dont l'expression satisfait
# le filtre jq donne.
handle() {
  ip netns exec "$NSD" nft -j list chain inet bifrost output \
    | jq -r "[.nftables[] | select(.rule) | .rule | select($1) | .handle][0]"
}

non_mesure 'aucune politique posee par ce daemon depuis son demarrage'
# Le serveur a ete admis avant que la declaration ne dise qu'il n'y a rien.
jq -e '.daemon_identity == "root-peer-credentials" and .failed_input == "daemon-declaration"' "$BAC/decl.json" >/dev/null
test -z "$(ip netns exec "$NSD" nft list ruleset)"
echo 'PASSED: daemon neuf, aucune politique declaree, rien de compare'

# L'echec attendu, et pour SA raison: un refus du client (droits du profil,
# lecture) laisserait le daemon deconnecte, et la suite ne mesurerait rien.
CODE=0
ip netns exec "$NSD" "$CLI" --socket "$SOCKET" connect --config "$BAC/profil.toml" > "$BAC/connect.log" 2>&1 || CODE=$?
test "$CODE" != 0
grep -qF 'coeur introuvable' "$BAC/connect.log"
ip netns exec "$NSD" "$CLI" --json --socket "$SOCKET" status \
  | jq -e '.state.state == "error" and .kill_switch_engaged' >/dev/null
ip netns exec "$NSD" nft --json --numeric list ruleset > "$BAC/avant.json"
correspond
ip netns exec "$NSD" nft --json --numeric list ruleset > "$BAC/apres.json"
cmp "$BAC/avant.json" "$BAC/apres.json"
echo 'PASSED: etat erreur, kill switch pose par le daemon, correspondance sans mutation'

# --- D1b.3c: QUI sert la declaration ---
#
# Un faux daemon rejoue, octet pour octet, la declaration que le vrai vient de
# servir, sur un --socket choisi par l'utilisateur. Le noyau porte exactement
# ce qu'elle dit: sans verification d'identite, la preuve dirait MATCH. Sous
# root, elle le dit encore, et c'est la LIMITE de la regle: elle dit qui ecoute,
# pas que c'est le daemon. Sous un compte quelconque, le client refuse AVANT
# d'ecrire: le faux daemon ne recoit aucune requete.
LIRE_PY='
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(sys.argv[1])
s.sendall(b"{\"version\":1,\"command\":\"declaration-pare-feu\"}\n")
d = b""
while not d.endswith(b"\n"):
    b = s.recv(65536)
    if not b:
        break
    d += b
sys.stdout.buffer.write(d)
'
FAUX_PY='
import socket, sys
chemin, reponse, journal = sys.argv[1], open(sys.argv[2], "rb").read(), sys.argv[3]
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(chemin)
s.listen(8)
while True:
    c, _ = s.accept()
    if c.makefile("rb").readline():
        with open(journal, "a") as j:
            j.write("requete\n")
        c.sendall(reponse)
    c.close()
'
ip netns exec "$NSD" python3 -c "$LIRE_PY" "$SOCKET" > "$BAC/declaration.json"
jq -e '.result == "declaration-pare-feu" and .issue == "posee"' "$BAC/declaration.json" >/dev/null
chmod 644 "$BAC/declaration.json"
mkdir "$BAC/faux"
chown 65534:"$GROUPE" "$BAC/faux"
FAUX="$BAC/faux/d.sock"
# Le prefixe (vide, ou setpriv) choisit le compte du faux daemon. `ip netns
# exec` et `setpriv` font exec: le PID releve EST l'interprete, dans NOTRE
# namespace, et c'est lui qu'on tue, par PID.
faux_daemon() {
  rm -f "$FAUX" "$BAC/faux/requetes"
  ip netns exec "$NSD" "$@" python3 -c "$FAUX_PY" "$FAUX" "$BAC/declaration.json" "$BAC/faux/requetes" &
  PID_FAUX=$!
  for _ in $(seq 1 40); do
    if [ -S "$FAUX" ]; then break; fi
    kill -0 "$PID_FAUX"
    sleep 0.25
  done
  test -S "$FAUX"
  ip netns pids "$NSD" | grep -x "$PID_FAUX" >/dev/null
  CODE=0
  ip netns exec "$NSD" "$CLI" --json --socket "$FAUX" prove nft --politique-daemon --actif \
    > "$BAC/faux.json" || CODE=$?
  kill "$PID_FAUX"
  wait "$PID_FAUX" 2>/dev/null || true
  PID_FAUX=""
  muet faux
}
# Temoin: le rejeu sous root passe. Sans lui, le refus qui suit pourrait venir
# d'une declaration mal rejouee plutot que de l'identite du serveur.
faux_daemon
test "$CODE" = 0
jq -e '.verdict == "MATCH" and .daemon_identity == "root-peer-credentials" and .failed_input == null' "$BAC/faux.json" >/dev/null
test "$(wc -l < "$BAC/faux/requetes")" = 2
# La garde: le meme rejeu, servi par un compte non root.
faux_daemon setpriv --reuid=65534 --regid=65534 --clear-groups
test "$CODE" = 2
jq -e '.verdict == "UNMEASURED" and .reason == "serveur de la declaration non privilegie" and .failed_input == "daemon-identity" and .daemon_identity == null and (.live_kernel | not) and (.generation_verified | not)' "$BAC/faux.json" >/dev/null
test ! -e "$BAC/faux/requetes"
echo 'PASSED: faux daemon non root sur un --socket choisi -> non mesure (daemon-identity), sans une requete; le meme rejeu sous root passe (limite de la regle)'

# --- Toutes les commandes verifient leur serveur, pas seulement la preuve ---
#
# Avant, `connect --config` envoyait le profil, cle privee comprise, a
# quiconque tenait le --socket. Un faux serveur COMPTE ici ce qu'il recoit,
# connexion par connexion, et ne repond jamais. Servi par un compte non root,
# chaque commande du client qui parle au daemon doit le joindre (une
# connexion), refuser en 4 et ne lui avoir rien ecrit. Temoin: le meme faux
# serveur sous root recoit `connect --config`, et la cle privee JETABLE du
# profil de test avec; sans lui, le zero de la branche refusee pourrait venir
# d'un compteur aveugle. Le vrai daemon, root, reste admis: `connect` et
# `status` plus haut, le hook de reprise et `disconnect` plus bas.
COMPTE_PY='
import socket, sys
chemin, journal = sys.argv[1], sys.argv[2]
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(chemin)
s.listen(8)
while True:
    c, _ = s.accept()
    c.settimeout(5)
    d = b""
    try:
        while not d.endswith(b"\n"):
            b = c.recv(65536)
            if not b:
                break
            d += b
    except socket.timeout:
        pass
    with open(journal + ".octets", "ab") as j:
        j.write(d)
    with open(journal, "a") as j:
        j.write("%d\n" % len(d))
    c.close()
'
COMPTE="$BAC/faux/c.sock"
JOURNAL="$BAC/faux/compte"
# Une paire JETABLE, tiree par le daemon du banc, pour ce seul passage.
CLE=$("$DAEMON" --genkey | cut -d' ' -f1)
PAIR=$("$DAEMON" --genkey | cut -d' ' -f2)
test -n "$CLE"
test -n "$PAIR"
cat > "$BAC/profil-wg.toml" <<TOML
interface = "bfsecipc0"
private_key = "$CLE"
addresses = ["198.51.100.2/32"]

[peer]
public_key = "$PAIR"
endpoint = { addr = "192.0.2.10:51820" }
allowed_ips = ["0.0.0.0/0", "::/0"]

[dns]
local_resolver = "127.0.0.1"
upstream = ["198.51.100.53"]
TOML
chmod 600 "$BAC/profil-wg.toml"
# Le prefixe (vide, ou setpriv) choisit le compte du compteur. Meme regle que
# faux_daemon: le PID releve EST l'interprete, et il est tue par PID.
compteur() {
  rm -f "$COMPTE" "$JOURNAL" "$JOURNAL.octets"
  ip netns exec "$NSD" "$@" python3 -c "$COMPTE_PY" "$COMPTE" "$JOURNAL" &
  PID_FAUX=$!
  for _ in $(seq 1 40); do
    if [ -S "$COMPTE" ]; then break; fi
    kill -0 "$PID_FAUX"
    sleep 0.25
  done
  test -S "$COMPTE"
  ip netns pids "$NSD" | grep -x "$PID_FAUX" >/dev/null
}
arreter_compteur() {
  kill "$PID_FAUX"
  wait "$PID_FAUX" 2>/dev/null || true
  PID_FAUX=""
}
# Attend la ligne de la connexion, puis rend le nombre d'octets qu'elle a porte.
octets_recus() {
  for _ in $(seq 1 40); do
    if [ -s "$JOURNAL" ]; then break; fi
    sleep 0.25
  done
  test "$(wc -l < "$JOURNAL")" = 1
  cat "$JOURNAL"
}
# `refuse <etiquette> <arguments du client...>`
refuse() {
  local etiquette=$1
  shift
  rm -f "$JOURNAL" "$JOURNAL.octets"
  CODE=0
  ip netns exec "$NSD" "$CLI" --socket "$COMPTE" "$@" > "$BAC/cmd.out" 2> "$BAC/cmd.err" || CODE=$?
  if [ "$CODE" != 4 ] || [ "$(octets_recus)" != 0 ]; then
    echo "$etiquette: code $CODE, octets $(cat "$JOURNAL" 2>/dev/null)" >&2
    return 1
  fi
  grep -F "n'a pas l'identite attendue du daemon" "$BAC/cmd.err" >/dev/null
  test ! -s "$BAC/cmd.out"
  echo "   $etiquette: refuse (4), 1 connexion, 0 octet"
}
compteur
CODE=0
ip netns exec "$NSD" "$CLI" --socket "$COMPTE" connect --config "$BAC/profil-wg.toml" > "$BAC/cmd.out" 2>&1 || CODE=$?
test "$CODE" != 4
test "$(octets_recus)" -gt 0
grep -F "$CLE" "$JOURNAL.octets" >/dev/null
arreter_compteur
echo 'PASSED: temoin, compteur root -> connect --config admis, la cle jetable lui arrive'
compteur setpriv --reuid=65534 --regid=65534 --clear-groups
refuse 'connect --config' connect --config "$BAC/profil-wg.toml"
refuse 'connect' connect
refuse 'disconnect' disconnect
refuse 'status' status
refuse '--json status' --json status
refuse 'check' check
refuse 'reprise' reprise --phase post --operation suspend
# Le hook tel que l'installateur le depose, par son interprete: code 4, rien
# d'ecrit, et le journal dit que rien n'a ete repose.
HOOK="$RACINE/packaging/systemd/system-sleep/bifrost-reprise"
rm -f "$JOURNAL" "$JOURNAL.octets"
CODE=0
ip netns exec "$NSD" env BIFROST_CLI="$CLI" BIFROST_SOCKET="$COMPTE" sh "$HOOK" post suspend 2> "$BAC/cmd.err" || CODE=$?
test "$CODE" = 4
test "$(octets_recus)" = 0
grep -F "n'a PAS ete reposee" "$BAC/cmd.err" >/dev/null
echo '   hook bifrost-reprise: refuse (4), 1 connexion, 0 octet'
# La sonde d'emergency-disarm, avec une copie du client et un daemon LEURRE a
# cote d'elle: le vrai binaire privilegie n'est jamais lance.
mkdir "$BAC/urgence"
cp "$CLI" "$BAC/urgence/bifrost-cli"
printf '#!/bin/sh\nexit 0\n' > "$BAC/urgence/bifrost-daemon"
chmod 755 "$BAC/urgence" "$BAC/urgence/bifrost-cli" "$BAC/urgence/bifrost-daemon"
rm -f "$JOURNAL" "$JOURNAL.octets"
ip netns exec "$NSD" "$BAC/urgence/bifrost-cli" --socket "$COMPTE" emergency-disarm --je-sais-ce-que-je-fais > "$BAC/cmd.out" 2> "$BAC/cmd.err"
test "$(octets_recus)" = 0
grep -F "n'a pas l'identite attendue du daemon" "$BAC/cmd.err" >/dev/null
if grep -F 'un daemon repond encore' "$BAC/cmd.err" >/dev/null; then
  echo "la sonde a pris le compteur non root pour le daemon" >&2
  exit 1
fi
arreter_compteur
echo '   emergency-disarm: la sonde n ecrit rien et ne prend pas le compteur pour le daemon'
ip netns exec "$NSD" "$BAC/urgence/bifrost-cli" --socket "$SOCKET" emergency-disarm --je-sais-ce-que-je-fais > "$BAC/cmd.out" 2> "$BAC/cmd.err"
grep -F 'un daemon repond encore' "$BAC/cmd.err" >/dev/null
echo 'PASSED: compteur non root -> chaque commande refuse en 4 sans lui ecrire un octet; le vrai daemon reste reconnu'
# Le hook, cette fois face au vrai daemon: il passe, et la politique est
# reposee. Meme attente que `reposer`, par le chemin de production.
AVANT=$(ip netns exec "$NSD" nft -s list table inet bifrost)
ip netns exec "$NSD" env BIFROST_CLI="$CLI" BIFROST_SOCKET="$SOCKET" sh "$HOOK" post suspend 2> "$BAC/cmd.err"
grep -F 'signalee au daemon' "$BAC/cmd.err" >/dev/null
REPOSEE=0
for _ in $(seq 1 40); do
  if [ "$(ip netns exec "$NSD" nft -s list table inet bifrost)" != "$AVANT" ]; then REPOSEE=1; break; fi
  sleep 0.25
done
test "$REPOSEE" = 1
correspond
echo 'PASSED: le hook de reprise, sous root face au vrai daemon, repose la politique'

# Regle retiree: le drop du :53 du coeur, celui qui l'empeche de resoudre en clair.
H=$(handle 'any(.expr[]; .match.left.meta.key? == "skuid") and any(.expr[]; has("drop"))')
test "$H" != null
ip netns exec "$NSD" nft delete rule inet bifrost output handle "$H"
ecart rules
reposer
correspond
# La reprise en etat erreur repose une politique qui nomme l'interface du
# profil: la declaration a suivi ce que le daemon a REELLEMENT pose.
ip netns exec "$NSD" nft list chain inet bifrost output | grep -F 'oifname "bfdecl0" accept' >/dev/null
echo 'PASSED: regle retiree -> ecart; reprise -> la declaration suit la nouvelle pose'

# Exception trop large: l'exemption du coeur devient celle de tout non-root.
H=$(handle '(.expr | length) == 2 and .expr[0].match.left.meta.key? == "skuid" and (.expr[1] | has("accept"))')
test "$H" != null
ip netns exec "$NSD" nft replace rule inet bifrost output handle "$H" meta skuid '!=' 0 accept
ecart rules
reposer
correspond
echo 'PASSED: exception elargie -> ecart'

# Filtre tiers prioritaire: une table etrangere accepte tout avant la notre.
ip netns exec "$NSD" nft -f - <<'NFT'
table inet tiers {
  chain sortie {
    type filter hook output priority -10; policy accept;
    accept
  }
}
NFT
ecart tables
ip netns exec "$NSD" nft delete table inet tiers
correspond
echo 'PASSED: filtre tiers prioritaire -> ecart'

# Interface remplacee: le tunnel accepte vers une autre interface.
H=$(handle '.expr[0].match.left.meta.key? == "oifname" and .expr[0].match.right == "bfdecl0"')
test "$H" != null
ip netns exec "$NSD" nft replace rule inet bifrost output handle "$H" oifname '"autre0"' accept
ecart rules
reposer
correspond
echo 'PASSED: interface remplacee -> ecart'

# Droits retires, trois fois. Membre du groupe du daemon mais sans droit noyau:
# la declaration est lue, le noyau ne l'est pas.
non_mesure 'acces noyau refuse; aucune elevation automatique' \
  setpriv --reuid=65534 --regid=65534 --clear-groups
jq -e '.failed_input == "observed" and (.live_kernel | not)' "$BAC/decl.json" >/dev/null
# Hors du groupe: le systeme de fichiers refuse le socket (0660).
non_mesure 'acces au daemon refuse' setpriv --reuid=65533 --regid=65533 --clear-groups
# Socket ouvert a tous le temps d'une preuve: c'est alors le daemon lui-meme
# (SO_PEERCRED) qui refuse, et son journal le dit.
chmod 0666 "$SOCKET"
non_mesure 'acces au daemon refuse' setpriv --reuid=65533 --regid=65533 --clear-groups
chmod 0660 "$SOCKET"
grep -qF 'connexion refusee' "$BAC/daemon.log"
echo 'PASSED: droits retires -> non mesure, cote noyau comme cote daemon'

# Course: trente reprises concurrentes. Chaque preuve rend une correspondance ou
# un non mesure explique; jamais un ecart, puisque rien ne s'ecarte de ce qui
# est declare, seulement un attendu qui bouge pendant la lecture.
(
  for _ in $(seq 1 30); do
    ip netns exec "$NSD" "$CLI" --socket "$SOCKET" reprise --phase post --operation suspend 2>/dev/null
    sleep 0.02
  done
) &
COURSE=$!
VUS_M=0
VUS_U=0
for _ in $(seq 1 15); do
  prouver course
  case "$CODE" in
    0) VUS_M=$((VUS_M + 1)) ;;
    2)
      jq -e '.reason == "declaration du daemon modifiee pendant la collecte" or .reason == "generation nft modifiee pendant la collecte"' "$BAC/course.json" >/dev/null
      VUS_U=$((VUS_U + 1))
      ;;
    *) cat "$BAC/course.json"; exit 1 ;;
  esac
done
wait "$COURSE"
COURSE=""
for _ in $(seq 1 20); do
  prouver decl
  if [ "$CODE" = 0 ]; then break; fi
  sleep 0.25
done
correspond
echo "PASSED: course de reprises -> $VUS_M correspondances, $VUS_U non mesures, aucun ecart"

ip netns exec "$NSD" "$CLI" --socket "$SOCKET" disconnect >/dev/null
if ip netns exec "$NSD" nft list table inet bifrost >/dev/null 2>&1; then
  echo "la table du kill switch a survecu a la deconnexion" >&2
  exit 1
fi
non_mesure 'kill switch retire par le daemon: aucune politique a comparer'
echo 'PASSED: deconnexion -> retrait declare, rien de compare'

CODE=0
ip netns exec "$NSD" "$CLI" --socket "$SOCKET" connect --config "$BAC/profil.toml" > "$BAC/connect.log" 2>&1 || CODE=$?
test "$CODE" != 0
grep -qF 'coeur introuvable' "$BAC/connect.log"
correspond
kill "$PID_DAEMON"
wait "$PID_DAEMON" || true
PID_DAEMON=""
# Le daemon arrete laisse son kill switch en place, et c'est voulu; la preuve,
# elle, n'a plus d'attendu et ne conclut pas.
ip netns exec "$NSD" nft list table inet bifrost >/dev/null
non_mesure 'daemon injoignable'
jq -e '.daemon_identity == null and .failed_input == "daemon-declaration"' "$BAC/decl.json" >/dev/null
echo 'PASSED: daemon arrete -> non mesure, la table restee en place n est pas une correspondance'
