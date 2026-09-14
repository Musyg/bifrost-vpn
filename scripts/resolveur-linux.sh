#!/usr/bin/env bash
# Confronte la configuration engendree au VRAI dnscrypt-proxy.
#
# Les tests du generateur ne prouvent que sa coherence avec lui-meme. C'est
# exactement le genre de recette qui reste verte pendant que le produit refuse
# de demarrer: une cle inconnue de cette version, une valeur hors plage, une
# section renommee entre deux versions, rien de tout cela ne se voit en
# comparant des chaines a d'autres chaines. Seul le binaire tranche.
#
# Le binaire n'est pas cherche dans le PATH, deliberement, comme pour les
# coeurs anti-censure: un tiers qui deposerait son "dnscrypt-proxy" devant le
# notre serait exactement le probleme qu'un resolveur chiffre existe pour
# eviter. Il faut le designer.
#
# Usage: ./scripts/resolveur-linux.sh [chemin/vers/dnscrypt-proxy]
#        RESOLVEUR=/chemin/dnscrypt-proxy ./scripts/resolveur-linux.sh

set -euo pipefail

RACINE_DEPOT="$(cd "$(dirname "$0")/.." && pwd)"
BINAIRE="${1:-${RESOLVEUR:-}}"
TRAVAIL="$(mktemp -d)"

ECHECS=0
ok()   { printf '  OK    %s\n' "$1"; }
fail() { printf '  ECHEC %s\n' "$1"; ECHECS=$((ECHECS + 1)); }
step() { printf '\n== %s\n' "$1"; }
trap 'rm -rf "$TRAVAIL"' EXIT

# Le binaire manquant ne fait pas tout sauter: la generation et les controles
# de propriete n'en ont pas besoin, et une recette qui ne mesure RIEN sur un
# runner sans dnscrypt-proxy laisserait le generateur deriver sans temoin.
# Seule la confrontation au binaire se declare SKIPPED.
AVEC_BINAIRE=oui
if [ -z "$BINAIRE" ] || [ ! -x "$BINAIRE" ]; then
  AVEC_BINAIRE=non
fi

step "Le binaire designe repond"
if [ "$AVEC_BINAIRE" = oui ]; then
  VERSION=$("$BINAIRE" -version 2>&1 | head -1)
  [ -n "$VERSION" ] && ok "dnscrypt-proxy $VERSION" || fail "le binaire ne rend pas sa version"
else
  echo "  SKIP  dnscrypt-proxy introuvable: le designer en argument ou via RESOLVEUR"
fi

step "Le generateur produit une configuration"
# Pas d'outillage Rust, pas de mesure - et surtout pas un echec produit. Lancee
# sous `sudo` sans rustup pour root, la recette accusait le generateur d'avoir
# echoue alors qu'aucun compilateur n'avait ete trouve. Elle n'a pas besoin de
# root; le dire vaut mieux que de mentir sur la cause.
if ! cargo --version >/dev/null 2>&1; then
  echo "SKIPPED: cargo inutilisable ici ($(cargo --version 2>&1 | head -1))."
  echo "         Cette recette n'exige pas root: la relancer en utilisateur ordinaire."
  exit 3
fi
CONFIG="$TRAVAIL/dnscrypt-proxy.toml"
BLOCAGE="$TRAVAIL/blocked-names.txt"

# La liste d'abord: la configuration la DESIGNE, donc l'engendrer ensuite
# laisserait une fenetre ou le fichier soumis a `-check` pointe un absent.
if (cd "$RACINE_DEPOT" && cargo run -q -p bifrost-dns --example liste-telemetrie equilibre) > "$BLOCAGE" 2>"$TRAVAIL/gen.err"; then
  ok "liste anti-telemetrie engendree ($(grep -cv '^#\|^$' "$BLOCAGE") motif(s))"
else
  fail "le generateur de liste a echoue"
  sed 's/^/        /' "$TRAVAIL/gen.err"
  exit 1
fi

if (cd "$RACINE_DEPOT" && cargo run -q -p bifrost-dns --example config-resolveur \
      "127.0.0.1:53" "quad9-dnscrypt-ip4-filter-pri,cloudflare" "9.9.9.9,1.1.1.1" \
      "$BLOCAGE") > "$CONFIG" 2>"$TRAVAIL/gen.err"; then
  ok "configuration engendree ($(wc -l < "$CONFIG") lignes)"
else
  fail "le generateur a echoue"
  sed 's/^/        /' "$TRAVAIL/gen.err"
  exit 1
fi

step "dnscrypt-proxy accepte cette configuration"
# `-check` a besoin du reseau: il resout le nom de la source des resolveurs
# via les bootstrap_resolvers. Un echec de reseau n'est donc pas un echec de
# configuration, et les confondre transformerait une recette de conformite en
# detecteur de coupure Internet. On lit la sortie pour trancher.
#
# Ce que cette etape attrape, mesure sur 2.1.18: une cle inconnue de cette
# version et un type invalide sortent tous deux en FATAL. C'est precisement ce
# que les tests du generateur ne peuvent pas voir.
if [ "$AVEC_BINAIRE" != oui ]; then
  echo "  SKIP  sans binaire, la conformite a dnscrypt-proxy n'est pas jugee"
  echo "        Sous Windows, c'est --resolveur-selftest qui la juge, et il va"
  echo "        plus loin: il INTERROGE le resolveur vivant."
elif (cd "$TRAVAIL" && "$BINAIRE" -check -config "$CONFIG") >"$TRAVAIL/check.log" 2>&1; then
  ok "configuration acceptee: $(grep -c NOTICE "$TRAVAIL/check.log") message(s), code 0"
elif grep -qiE "bootstrap|no such host|timeout|network is unreachable|connection refused" "$TRAVAIL/check.log"; then
  echo "  SKIP  -check n'a pas pu joindre le reseau, la configuration n'est pas jugee"
  sed 's/^/        /' "$TRAVAIL/check.log"
else
  fail "dnscrypt-proxy REFUSE la configuration engendree"
  sed 's/^/        /' "$TRAVAIL/check.log"
fi

step "Les proprietes qui comptent sont dans le fichier lu par le binaire"
# Relues sur le fichier REELLEMENT soumis, et non sur la sortie du generateur
# en memoire: c'est ce fichier-la que dnscrypt-proxy vient de valider.
#
# Et elles ne font double emploi avec `-check` en rien. Mesure du 17/08/2026:
# dnscrypt-proxy 2.1.18 accepte sans un mot une ecoute sur 0.0.0.0:53, donc un
# resolveur ouvert a tout le reseau local. Il juge la syntaxe de sa
# configuration; les proprietes de securite, personne ne les juge a sa place.
for exigence in \
  "ignore_system_dns = true" \
  "require_dnssec = true" \
  "require_nolog = true"
do
  grep -qF "$exigence" "$CONFIG" \
    && ok "$exigence" \
    || fail "absent du fichier soumis: $exigence"
done
if grep -q "fallback_resolver" "$CONFIG"; then
  fail "un repli en clair est declare: il fuirait au pire moment"
else
  ok "aucun repli en clair"
fi

step "La liste anti-telemetrie designee est celle qui a ete soumise"
# Relue sur le fichier, pas sur la sortie du generateur: c'est ce fichier-la
# que dnscrypt-proxy vient de valider.
DESIGNE=$(sed -n "s/^blocked_names_file = '\(.*\)'$/\1/p" "$CONFIG")
# Le CONTENU et non la chaine. Sous git-bash, MSYS traduit un argument qui
# ressemble a un chemin POSIX en chemin Windows avant de le passer au
# programme: `/tmp/x/blocked-names.txt` arrive comme
# `C:/Users/.../Temp/x/blocked-names.txt`. Les deux designent le meme fichier,
# et une egalite de chaines aurait fait echouer la recette sur une machine ou
# rien n'est casse.
if [ -n "$DESIGNE" ] && [ -f "$DESIGNE" ] && cmp -s "$DESIGNE" "$BLOCAGE"; then
  ok "blocked_names_file pointe le fichier engendre ($DESIGNE)"
else
  fail "blocked_names_file designe '$DESIGNE', qui n'est pas la liste engendree"
fi

# Le plancher du produit. Le blocage par ZONE est le geste qui casse une
# machine sans prevenir: un `*.microsoft.com` egare couperait Windows Update,
# le Store, Defender et l'activation. La verification vit aussi en recette Rust
# (`bifrost_dns::telemetrie`), et elle est refaite ICI sur le fichier reel:
# c'est le seul endroit ou l'on tient l'octet que le binaire va lire.
for interdit in \
  "*.microsoft.com" \
  "*.windows.com" \
  "*.msn.com" \
  "microsoft.com" \
  "windowsupdate.com"
do
  if grep -qxF "$interdit" "$BLOCAGE"; then
    fail "motif trop large dans la liste: $interdit"
  else
    ok "absent, et c'est voulu: $interdit"
  fi
done

if grep -qxF "*.events.data.microsoft.com" "$BLOCAGE"; then
  ok "le pipeline de telemetrie est bien refuse"
else
  fail "la liste ne refuse meme pas *.events.data.microsoft.com"
fi

echo
if [ "$ECHECS" -eq 0 ]; then
  echo "resolveur chiffre: tout est passe"
else
  echo "resolveur chiffre: $ECHECS controle(s) en echec"
  exit 1
fi
