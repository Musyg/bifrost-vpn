#!/usr/bin/env bash
# Le budget d'abstention: chaque recette qui s'abstient SUR LE RUNNER doit etre
# attendue, nommement.
#
# # Pourquoi ce script existe
#
# `recettes-strict.sh` rend les abstentions VISIBLES (il relance la suite avec
# --nocapture), mais il ne dit pas si elles sont NORMALES. En integration
# continue, `--strict` refuse toute abstention; c'est le but final, mais tant
# que des outils manquent au runner (Wintun, minisign, dnscrypt-proxy, sing-box)
# ou que des mesures demandent des privileges qu'un runner ordinaire n'a pas, la
# suite en compte quelques-unes qui ne sont pas des defauts. Ce script est le
# palier: il accepte une LISTE d'abstentions attendues et rougit sur tout ce qui
# s'en ecarte. Chaque ligne de la liste est un aveu a faire tomber; le jour ou
# les deux listes sont vides, la CI passe a `recettes-strict.sh --strict` et ce
# script disparait.
#
# # Ce qu'il rend
#
#   - ROUGE si une abstention du journal n'est PAS dans la liste (nouvelle), ou
#     si une ligne de la liste n'a pas une forme stable (garde de forme), ou si
#     la liste est mal formee (en-tete, tri, doublon).
#   - VERT sinon; une ligne de la liste qui n'apparait PLUS dans le journal est
#     signalee comme un progres a retirer, sans rougir.
#
# # La forme stable
#
# Les raisons de SKIPPED des recettes sont des litteraux imprimes par les tests
# (elles ne passent pas par un catalogue comme `windows::motifs`), et plusieurs
# portent du variable: un chemin absolu (le wintun.dll a cote du binaire), un
# uid, un pid. On les compare donc apres normalisation:
#   - tout chemin absolu (Windows `X:\...` ou Unix `/a/b...`) devient <CHEMIN>;
#   - toute suite de chiffres (uid, pid, compteur) devient <N>.
# Une ligne de la liste qui n'est PAS deja sous forme normalisee (chemin ou
# nombre brut) fait rougir la garde de forme: la liste doit etre stable, sinon
# elle depend du runner.
#
# L'artefact d'affichage parallele de `recettes-strict.sh` ("raison perdue a l
# affichage: ...") est non deterministe: c'est le motif d'une AUTRE recette qui
# s'est intercale sous --nocapture. Il est ignore ici (ni nouvelle abstention,
# ni ligne attendue), et se lit avec --test-threads=1.
#
# Usage:
#   ./scripts/abstentions-budget.sh --liste FICHIER [--journal FICHIER]
#   ./scripts/abstentions-budget.sh --verifier-liste FICHIER
#
# --journal absent: le script relance recettes-strict.sh et lit sa sortie.

set -uo pipefail

cd "$(dirname "$0")/.."

MARQUEUR_PERDU='raison perdue a l affichage'

# Remplace ce qui varie d'un run a l'autre par un marqueur stable. Chemins
# d'abord (ils contiennent des chiffres), nombres ensuite.
normaliser() {
  sed -e 's#[A-Za-z]:\\[^[:space:]]*#<CHEMIN>#g' \
    -e 's#/[^[:space:]/][^[:space:]/]*/[^[:space:]]*#<CHEMIN>#g' \
    -e 's/[0-9][0-9]*/<N>/g'
}

# Sort les formes normalisees, uniques, presentes dans un journal. Le meme
# decollage que recettes-strict.sh (deux impressions collees sous --nocapture),
# puis on garde ce qui commence a SKIPPED, on normalise, on retire l'artefact.
extraire_formes() {
  local fichier="$1"
  sed 's/\(.\)SKIPPED/\1\n SKIPPED/g' "$fichier" |
    grep 'SKIPPED' |
    sed 's/^.*\(SKIPPED\)/\1/' |
    normaliser |
    grep -v "$MARQUEUR_PERDU" |
    LC_ALL=C sort -u
}

# Les lignes de corps d'une liste: ni commentaire, ni vide.
lire_corps() {
  grep -v '^[[:space:]]*#' "$1" | grep -v '^[[:space:]]*$'
}

# Vrai si la ligne a une forme connue: elle commence par SKIPPED et la
# normalisation ne la change pas (elle est deja stable).
forme_valide() {
  local ligne="$1"
  case "$ligne" in
  SKIPPED:*) : ;;
  "SKIPPED "*) : ;;
  *) return 1 ;;
  esac
  local norm
  norm=$(printf '%s' "$ligne" | normaliser)
  [ "$norm" = "$ligne" ]
}

# Controle d'hygiene d'une liste: en-tete (date, run, commit), corps trie, sans
# doublon, chaque ligne de forme valide. Rend 0 si tout va bien.
verifier_liste() {
  local liste="$1"
  local souci=0

  if [ ! -f "$liste" ]; then
    echo "ECHEC: liste introuvable: $liste"
    return 1
  fi

  # En-tete: les lignes de commentaire en tete doivent dater le releve et citer
  # le run et le commit PAR LEUR NUMERO. On lit le bloc de commentaires du
  # fichier entier: il est en tete par convention, mais un grep sur tout le
  # fichier suffit a la garde.
  # Le mot seul ne suffit pas: le 14/09/2026, une falsification qui retirait
  # les deux numeros de run de l'en-tete Linux a laisse la garde verte, parce
  # que << runner >> et << runs >> contenaient encore le mot. Une garde qui
  # accepte << runner >> pour un numero de run ne garde rien.
  local entete
  entete=$(grep '^[[:space:]]*#' "$liste" || true)
  if ! printf '%s' "$entete" | grep -Eq '[0-9]{4}-[0-9]{2}-[0-9]{2}'; then
    echo "ECHEC: en-tete sans date (AAAA-MM-JJ) du releve: $liste"
    souci=1
  fi
  if ! printf '%s' "$entete" | grep -Eqi 'run[[:space:]]+[0-9]{6,}'; then
    echo "ECHEC: en-tete qui ne cite aucun run de CI par son numero (<< run NNNNNN >>): $liste"
    souci=1
  fi
  if ! printf '%s' "$entete" | grep -Eqi 'commit[[:space:]]+[0-9a-f]{7,}'; then
    echo "ECHEC: en-tete qui ne cite aucun commit par son SHA (<< commit abcdef0 >>): $liste"
    souci=1
  fi

  local corps
  corps=$(lire_corps "$liste")

  # Chaque ligne de corps: forme valide.
  if [ -n "$corps" ]; then
    while IFS= read -r ligne; do
      [ -z "$ligne" ] && continue
      if ! forme_valide "$ligne"; then
        echo "ECHEC: ligne de forme inconnue (pas normalisee, ou ne commence pas par SKIPPED): $ligne"
        souci=1
      fi
    done <<EOF
$corps
EOF
  fi

  # Trie et sans doublon: le corps doit etre identique a son tri unique.
  local trie
  trie=$(printf '%s\n' "$corps" | grep -v '^$' | LC_ALL=C sort)
  local trie_uniq
  trie_uniq=$(printf '%s\n' "$corps" | grep -v '^$' | LC_ALL=C sort -u)
  local corps_net
  corps_net=$(printf '%s\n' "$corps" | grep -v '^$')
  if [ "$corps_net" != "$trie" ]; then
    echo "ECHEC: corps non trie (LC_ALL=C): $liste"
    souci=1
  fi
  if [ "$trie" != "$trie_uniq" ]; then
    echo "ECHEC: corps avec doublon(s): $liste"
    souci=1
  fi

  return "$souci"
}

usage() {
  echo "usage: $0 --liste FICHIER [--journal FICHIER]"
  echo "       $0 --verifier-liste FICHIER"
}

LISTE=""
JOURNAL=""
VERIFIER_SEUL=0

while [ $# -gt 0 ]; do
  case "$1" in
  --liste)
    LISTE="${2:-}"
    shift 2
    ;;
  --journal)
    JOURNAL="${2:-}"
    shift 2
    ;;
  --verifier-liste)
    LISTE="${2:-}"
    VERIFIER_SEUL=1
    shift 2
    ;;
  -h | --help)
    usage
    exit 0
    ;;
  *)
    echo "argument inconnu: $1"
    usage
    exit 2
    ;;
  esac
done

if [ -z "$LISTE" ]; then
  usage
  exit 2
fi

# L'hygiene de la liste est un prealable dans tous les cas.
if ! verifier_liste "$LISTE"; then
  echo "ECHEC: la liste $LISTE est mal formee."
  exit 1
fi

if [ "$VERIFIER_SEUL" -eq 1 ]; then
  echo "liste bien formee: $LISTE"
  exit 0
fi

# Le journal: fourni, ou produit en relancant recettes-strict.sh.
NETTOYER_JOURNAL=0
if [ -z "$JOURNAL" ]; then
  JOURNAL=$(mktemp)
  NETTOYER_JOURNAL=1
  echo "== pas de --journal: relance de recettes-strict.sh =="
  if ! ./scripts/recettes-strict.sh >"$JOURNAL" 2>&1; then
    echo "ECHEC: recettes-strict.sh a echoue (rouge ou suite non executee). Journal:"
    tail -n 40 "$JOURNAL" | sed 's/^/       /'
    rm -f "$JOURNAL"
    exit 1
  fi
fi

if [ ! -f "$JOURNAL" ]; then
  echo "ECHEC: journal introuvable: $JOURNAL"
  exit 1
fi

PRESENTES=$(mktemp)
ATTENDUES=$(mktemp)
trap 'rm -f "$PRESENTES" "$ATTENDUES"; [ "$NETTOYER_JOURNAL" -eq 1 ] && rm -f "$JOURNAL"' EXIT

extraire_formes "$JOURNAL" >"$PRESENTES"
lire_corps "$LISTE" | grep -v '^$' | LC_ALL=C sort -u >"$ATTENDUES"

NOUVELLES=$(LC_ALL=C comm -13 "$ATTENDUES" "$PRESENTES")
MANQUANTES=$(LC_ALL=C comm -23 "$ATTENDUES" "$PRESENTES")

echo "== budget d'abstention: $LISTE =="
echo "  attendues : $(grep -c . "$ATTENDUES" || true)"
echo "  presentes : $(grep -c . "$PRESENTES" || true)"

CODE=0

if [ -n "$MANQUANTES" ]; then
  echo
  echo "== progres: attendues mais ABSENTES du journal (a retirer de la liste) =="
  printf '%s\n' "$MANQUANTES" | sed 's/^/  - /'
fi

if [ -n "$NOUVELLES" ]; then
  echo
  echo "== ROUGE: abstention(s) NOUVELLE(S), absentes de la liste =="
  printf '%s\n' "$NOUVELLES" | sed 's/^/  + /'
  echo
  echo "  Chacune est une recette qui ne mesure rien sur le runner et que rien"
  echo "  n'attendait. Soit c'est un defaut a corriger, soit c'est un aveu a"
  echo "  ajouter a $LISTE en connaissance de cause."
  CODE=1
fi

if [ "$CODE" -eq 0 ]; then
  echo
  echo "budget tenu: aucune abstention nouvelle."
fi

exit "$CODE"
