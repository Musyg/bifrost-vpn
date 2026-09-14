#!/usr/bin/env bash
# Le compte HONNETE des recettes cargo: combien ont mesure, combien se sont
# abstenues.
#
# Pendant de `check-strict.sh`, qui tient le meme raisonnement pour les vecteurs
# de fuite: rendre 0 quand des mesures sont SKIPPED est le bon comportement pour
# qui developpe, l'absence de mesure n'etant pas un echec. Mais le compte que
# `cargo test` affiche ne distingue pas les deux, et c'est ce compte-la que
# chaque message de commit de ce depot cite comme preuve.
#
# Une recette qui ne peut pas s'executer imprime `SKIPPED` et rend `Ok`, donc
# cargo la compte comme passee. Sans `--nocapture` elle est INVISIBLE. Mesure du
# 21/08/2026 sur dev-windows: 942 vertes annoncees, 23 lignes d'abstention.
#
# La demonstration est arrivee seule le meme jour. Les quatre recettes d'interop
# minisign se declaraient absentes de binaire alors que le binaire etait installe
# et son repertoire dans le PATH utilisateur: c'est le shell qui avait ete
# initialise avant l'ajout. Deux executions de la MEME commande, deux fois `ok`,
# et dans l'une d'elles quatre recettes n'avaient rien verifie.
#
# Usage:
#   ./scripts/recettes-strict.sh            # compte et liste, echoue sur rouge
#   ./scripts/recettes-strict.sh --strict   # echoue AUSSI sur abstention
#
# `--strict` est fait pour l'integration continue, ou une abstention est un
# blanc-seing: un environnement mal outille rendrait le build vert sans avoir
# rien verifie.
#
# Variable d'environnement:
#   RECETTES_JOURNAL_BRUT=<fichier>   garde une copie du journal complet de
#                                     `cargo test` (sinon il est efface a la
#                                     sortie). La CI le depose en artefact quand
#                                     l'etape echoue.
#
# Un journal qui porte du binaire ne doit pas faire mentir le compte. Releve du
# 14/09/2026 sur les huit runs de la CI Windows du 05/09 (b8df9a5) au 13/09
# (4826229): une recette y imprimait des octets nuls (la sortie UTF-16 d'un
# `bash.exe` qui n'etait pas Git Bash), `grep` sans `-a` s'arretait la avec
# << Binary file matches >>, et le script annoncait 207 vertes, 0 rouge, puis
# sortait 101 par le code de cargo sans nommer une seule recette rouge. Depuis:
# `grep -a` partout, les octets nuls sont comptes et dits, et un code de cargo
# non nul que le compte n'explique pas imprime les lignes qui l'expliquent.

set -uo pipefail

cd "$(dirname "$0")/.."

STRICT=0
[ "${1:-}" = "--strict" ] && STRICT=1

JOURNAL=$(mktemp)
DECOLLE=$(mktemp)
trap 'rm -f "$JOURNAL" "$DECOLLE"' EXIT

echo "== execution de la suite, sortie non capturee =="
# --no-fail-fast: sans lui cargo s'arrete au premier binaire rouge et le compte
# sous-estime tout le reste. --nocapture: sans lui les abstentions n'existent
# pas a l'ecran, ce qui est tout l'objet de ce script.
cargo test --workspace --no-fail-fast -- --nocapture > "$JOURNAL" 2>&1
CODE_CARGO=$?

if [ -n "${RECETTES_JOURNAL_BRUT:-}" ]; then
  cp "$JOURNAL" "$RECETTES_JOURNAL_BRUT"
fi

# `-a` sur chaque grep du journal: sans lui, au premier octet nul grep imprime
# << Binary file matches >> et se tait, et tout ce qui suit dans le journal
# echappe au compte (voir l'en-tete). Un octet nul dans la sortie d'une recette
# est en soi un defaut a nommer: on le compte.
NULS=$(tr -cd '\000' < "$JOURNAL" | wc -c | tr -d ' ')

VERTES=$(grep -a '^test result:' "$JOURNAL" | awk '{s += $4} END {print s + 0}')
ROUGES=$(grep -a '^test result:' "$JOURNAL" | awk '{s += $6} END {print s + 0}')
IGNOREES=$(grep -a '^test result:' "$JOURNAL" | awk '{s += $8} END {print s + 0}')
BINAIRES=$(grep -a -c '^test result:' "$JOURNAL")
# Sous `--nocapture`, les binaires de test ecrivent en parallele dans le MEME
# tube et deux impressions peuvent se retrouver collees bout a bout sur une
# ligne. Compter les lignes perd alors une abstention, et le compte bouge d'une
# execution a l'autre sans que rien n'ait change - vu le 22/08/2026, 20 puis 21
# sur essai-linux. On coupe donc avant chaque `SKIPPED` qui n'ouvre pas sa
# ligne, et on compte apres. Le meme fichier sert au regroupement plus bas, qui
# souffrait du meme collage.
sed 's/\(.\)SKIPPED/\1\n SKIPPED/g' "$JOURNAL" > "$DECOLLE"
ABSTENTIONS=$(grep -a -c 'SKIPPED' "$DECOLLE")

# Preuve d'execution. Une suite qui n'a pas tourne - binaire verrouille,
# compilation rouge, orphelin qui retient le tube - rend zero binaire, et zero
# rouge se lit alors comme un succes. C'est arrive.
if [ "$BINAIRES" -eq 0 ]; then
  echo "ECHEC: aucun binaire de test n'a rendu de resultat. La suite n'a pas tourne."
  tail -n 30 "$JOURNAL" | sed 's/^/       /'
  exit 1
fi

echo
echo "== ce que la suite a REELLEMENT mesure =="
printf '  binaires de test : %s\n' "$BINAIRES"
printf '  vertes annoncees : %s\n' "$VERTES"
printf '  abstentions      : %s\n' "$ABSTENTIONS"
printf '  ignorees         : %s\n' "$IGNOREES"
printf '  rouges           : %s\n' "$ROUGES"
printf '  => mesure reelle : %s recette(s) ont verifie quelque chose\n'   "$((VERTES - ABSTENTIONS))"
if [ "$NULS" -gt 0 ]; then
  printf '  octets nuls      : %s dans le journal (une recette a imprime du binaire; le compte est pris avec grep -a)\n' "$NULS"
fi

if [ "$ABSTENTIONS" -gt 0 ]; then
  echo
  echo "== ce qui ne s'est pas execute, et pourquoi =="
  # Regroupe par motif: dix abstentions pour la meme raison manquante sont UN
  # outil a installer, pas dix problemes.
  # Le decollage remet une abstention par ligne, mais il ne peut pas rendre une
  # raison qui a atterri AILLEURS. Mesure du 23/08/2026 sur dev-windows: en
  # parallele, une occurrence sortait en `SKIPPED: ` nue, la ligne de
  # progression d'une AUTRE recette s'etant intercalee entre les deux ecritures.
  # Rejouee en `--test-threads=1`, la meme suite rend 18 abstentions et les 18
  # portent leur raison. Le COMPTE etait donc juste et la LECTURE fausse - une
  # ligne vide se lit comme une abstention sans motif, ce que le depot
  # s'interdit. On la nomme pour ce qu'elle est.
  grep -a 'SKIPPED' "$DECOLLE" | sed 's/^[[:space:]]*//' |
    sed 's/^SKIPPED:\{0,1\}[[:space:]]*$/SKIPPED (raison perdue a l affichage: une autre recette s est intercalee. Rejouer avec --test-threads=1 pour la lire.)/' |
    sort | uniq -c | sort -rn |
    sed 's/^/  /'
  echo
  echo "  Chacune est une mesure qui n'a PAS eu lieu et que le compte de cargo"
  echo "  presente comme verte. Installer ce qui manque, ou accepter en le sachant."
fi

echo

# Le compte des occurrences n'est pas exactement le compte des recettes: rien
# n'interdit a une recette d'imprimer deux fois. C'est une borne, et elle est
# dite comme telle plutot que presentee comme un decompte exact. Aucune raison
# ne contient aujourd'hui le mot lui-meme - verifie sur les sources - donc une
# occurrence vaut une abstention.
echo "note: les abstentions sont comptees en OCCURRENCES du mot, pas en recettes."
echo "      C'est une borne superieure fidele tant qu'une recette n'imprime"
echo "      qu'une fois, ce qui est l'usage actuel du depot."

if [ "$ROUGES" -gt 0 ]; then
  echo
  echo "ECHEC: $ROUGES recette(s) rouge(s)."
  grep -a -E '^test .* FAILED' "$JOURNAL" | sed 's/^/  /' | head -40
  exit 1
fi

if [ "$STRICT" -eq 1 ] && [ "$ABSTENTIONS" -gt 0 ]; then
  echo "ECHEC (--strict): $ABSTENTIONS abstention(s). En integration continue,"
  echo "                  une mesure qui n'a pas eu lieu ne vaut pas un succes."
  exit 1
fi

# Le code de cargo est repris quand rien d'autre n'a echoue: il porte les cas
# que le comptage ne voit pas, comme un binaire qui ne compile pas ou un binaire
# de test qui meurt sans rendre de ligne `test result:`. Un tel code doit etre
# EXPLIQUE a l'ecran: huit runs de CI ont rendu 101 sans qu'une ligne ne dise
# pourquoi, parce que le journal etait efface a la sortie.
if [ "$CODE_CARGO" -ne 0 ]; then
  echo
  echo "ECHEC: cargo a rendu $CODE_CARGO alors que le compte ci-dessus ne voit aucune rouge."
  echo "       Ce que le journal en dit (erreurs, paniques, binaires morts):"
  grep -a -n -E "^error|panicked at|FAILED|process didn't exit successfully|test failed, to rerun|STATUS_|SIGSEGV|SIGABRT" "$JOURNAL" | sed 's/^/         /' | head -60
  echo "       Les 30 dernieres lignes du journal:"
  tail -n 30 "$JOURNAL" | sed 's/^/         /'
  if [ -n "${RECETTES_JOURNAL_BRUT:-}" ]; then
    echo "       Journal complet: $RECETTES_JOURNAL_BRUT"
  fi
fi
exit "$CODE_CARGO"
