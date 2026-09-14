#!/usr/bin/env bash
# Exige que les vecteurs de fuite soient tous PASSED.
#
# `bifrost-cli check` renvoie 0 quand des vecteurs sont SKIPPED, et c'est le
# bon comportement pour un utilisateur: l'absence de mesure n'est pas un echec.
# En integration continue ce serait un blanc-seing, puisqu'un environnement mal
# outille rendrait la CI verte sans avoir rien verifie. Ce script durcit donc le
# critere: tout ce qui n'est pas PASSED fait echouer le build.
#
# Il passe par `bifrost-daemon --run-checks` et non par le couple daemon plus
# client: la suite tourne alors dans un seul processus au premier plan, qui
# rend la main en sortant. Aucun daemon en tache de fond a nettoyer, et donc
# aucun processus root residuel qu'un runner d'integration continue, qui tourne
# en utilisateur ordinaire, serait incapable de tuer.
#
# Usage: sudo ./scripts/check-strict.sh [chemin/vers/target/debug]

set -euo pipefail

BIN="${1:-$(cd "$(dirname "$0")/.." && pwd)/target/debug}"
DAEMON="$BIN/bifrost-daemon"
RAPPORT="${RAPPORT:-rapport-fuite.json}"

[ "$(id -u)" -eq 0 ] || { echo "ce script doit tourner en root"; exit 1; }
[ -x "$DAEMON" ] || { echo "binaire introuvable: $DAEMON"; exit 1; }

# --run-checks sort en 1 s'il y a un echec: on veut analyser le rapport dans
# tous les cas, donc on desarme temporairement l'arret-sur-erreur.
set +e
"$DAEMON" --run-checks --json >"$RAPPORT"
set -e

# Sans ce controle, un rapport illisible produit une erreur d'analyse JSON
# obscure au lieu de dire ce qui ne va pas.
if [ ! -s "$RAPPORT" ]; then
  echo "rapport vide ou non ecrit: $RAPPORT"
  exit 1
fi

if command -v jq >/dev/null 2>&1; then
  jq -r '.outcomes[] | "\(.verdict)\t\(.vector)\t\(.detail)"' "$RAPPORT"
  NON_PASSES=$(jq -r '[.outcomes[] | select(.verdict != "PASSED")] | length' "$RAPPORT")
  TOTAL=$(jq -r '.outcomes | length' "$RAPPORT")
else
  echo "jq absent, analyse textuelle du rapport"
  NON_PASSES=$(grep -c '"verdict": *"\(FAILED\|SKIPPED\)"' "$RAPPORT" || true)
  TOTAL=$(grep -c '"verdict"' "$RAPPORT" || true)
fi

# Le nombre attendu est demande au binaire, pas ecrit ici: un nombre en dur
# devrait etre corrige a chaque vecteur ajoute, et il ne le serait qu'apres
# avoir fait echouer une CI.
ATTENDUS=$("$DAEMON" --list-checks | grep -c .)

echo
if [ "$TOTAL" -ne "$ATTENDUS" ]; then
  echo "rapport incomplet: $TOTAL vecteur(s) au lieu de $ATTENDUS"
  exit 1
fi
if [ "$NON_PASSES" -ne 0 ]; then
  echo "$NON_PASSES vecteur(s) ne sont pas PASSED"
  exit 1
fi
echo "tous les vecteurs sont PASSED"
