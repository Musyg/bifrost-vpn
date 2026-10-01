#!/usr/bin/env bash
# Rejoue les graines de chaque cible de fuzzing, puis fuzze chaque cible un
# temps borne; echoue sur tout plantage, panique, depassement memoire ou delai.
#
# Le harnais (`fuzz/`, cargo-fuzz et libFuzzer) est un espace de travail cargo
# SEPARE du workspace racine: voir `fuzz/Cargo.toml` et la section 2.3 de
# `docs/07-programme-securite-produit.md`, qui recense les parseurs, leur
# frontiere de confiance et les cibles. Il demande une chaine nightly (le
# sanitizer d'adresses de libFuzzer) et cargo-fuzz, et ne tourne que sous
# Linux.
#
# Usage:
#   ./scripts/fuzz-linux.sh                     # rejoue, puis 30 s par cible
#   ./scripts/fuzz-linux.sh --duree 600         # 600 s par cible
#   ./scripts/fuzz-linux.sh --rejouer           # rejoue les graines, rien de plus
#   ./scripts/fuzz-linux.sh --cible lien_profil # une cible (option repetable)
#
# Variables d'environnement:
#   BIFROST_FUZZ_CHAINE   chaine passee a cargo et rustc (defaut: nightly)
#   CARGO_TARGET_DIR      repertoire de construction, comme pour cargo
#                         (defaut: fuzz/target)
#
# Les binaires des cibles sont construits dans CARGO_TARGET_DIR si elle est
# posee, sinon dans `fuzz/target/`, et le script les lit au meme endroit: il
# passe ce repertoire a `cargo fuzz build --target-dir`, qui l'emporte sur toute
# autre configuration de cargo. Le corpus de travail
# (`fuzz/target/corpus-travail/<cible>`) et les entrees qui font tomber une
# cible (`fuzz/target/artefacts/<cible>/`) restent sous `fuzz/target/` dans
# tous les cas. Les graines versionnees (`fuzz/graines/<cible>`) ne sont que
# LUES. C'est voulu: libFuzzer ecrit dans le premier repertoire qu'on lui
# donne, sous des noms sans extension, et un `cargo fuzz run` nu ecrirait dans
# `fuzz/corpus/` et `fuzz/artifacts/`, que la recette
# `caracteres_de_controle.rs` parcourt comme du texte. Elle ne descend jamais
# dans un repertoire `target`.
#
# Les cibles ne joignent aucun reseau. Celle de l'IPC ecoute sur un socket Unix,
# sous le compte qui lance ce script, dans un repertoire par processus qu'elle
# ne retire pas: son banc vit dans une statique, que Rust ne detruit jamais, et
# une cible tombee ne retire rien. Ce script donne donc aux cibles (TMPDIR) un
# repertoire temporaire a lui, et le retire a sa sortie, quelle qu'elle soit.

set -euo pipefail

cd "$(dirname "$0")/.."

DUREE=30
REJOUER_SEULEMENT=0
CIBLES=()
while [ $# -gt 0 ]; do
  case "$1" in
    --duree)
      DUREE="${2:?--duree attend un nombre de secondes}"
      shift 2
      ;;
    --rejouer)
      REJOUER_SEULEMENT=1
      shift
      ;;
    --cible)
      CIBLES+=("${2:?--cible attend un nom de cible}")
      shift 2
      ;;
    *)
      echo "argument inconnu: $1" >&2
      exit 2
      ;;
  esac
done

case "$DUREE" in
  '' | *[!0-9]*)
    echo "--duree attend un entier de secondes, recu: $DUREE" >&2
    exit 2
    ;;
esac

CHAINE="${BIFROST_FUZZ_CHAINE:-nightly}"
TRIPLE="$(uname -m)-unknown-linux-gnu"
# Le repertoire de construction que cargo prendrait: CARGO_TARGET_DIR, relatif
# au repertoire courant comme cargo le lit, sinon celui du harnais. Rendu
# absolu, il est passe tel quel a la construction, puis lu ci-dessous.
CONSTRUCTION="${CARGO_TARGET_DIR:-fuzz/target}"
case "$CONSTRUCTION" in
  /*) ;;
  *) CONSTRUCTION="$PWD/$CONSTRUCTION" ;;
esac
BINAIRES="$CONSTRUCTION/$TRIPLE/release"

# Les cibles sont les fichiers de `fuzz/fuzz_targets`: le nom du binaire est
# celui du fichier, comme `fuzz/Cargo.toml` le declare.
if [ "${#CIBLES[@]}" -eq 0 ]; then
  for source in fuzz/fuzz_targets/*.rs; do
    nom="${source##*/}"
    CIBLES+=("${nom%.rs}")
  done
fi
if [ "${#CIBLES[@]}" -eq 0 ]; then
  echo "ECHEC: aucune cible dans fuzz/fuzz_targets" >&2
  exit 1
fi

# Le verrou d'abord: un `fuzz/Cargo.lock` que la construction voudrait changer
# est une erreur, pas une mise a jour silencieuse.
cargo +"$CHAINE" fetch --locked --manifest-path fuzz/Cargo.toml

echo "== construction des cibles (sanitizer d'adresses, assertions de debogage) =="
echo "   dans $CONSTRUCTION"
cargo +"$CHAINE" fuzz build --fuzz-dir fuzz --debug-assertions --target-dir "$CONSTRUCTION"

# Les memes bornes pour la relecture et pour la campagne. La memoire est
# plafonnee a 2 Gio et une entree a 120 s: au-dela, libFuzzer rend la cible
# tombee, et c'est une trouvaille.
BORNES=(-rss_limit_mb=2048 -timeout=120)

# Le repertoire temporaire des cibles (voir l'en-tete), cree sous celui de
# l'appelant et retire a la sortie: fin normale, echec, Ctrl-C ou SIGTERM.
TEMPORAIRE="$(mktemp -d "${TMPDIR:-/tmp}/bifrost-fuzz.XXXXXX")"
trap 'rm -rf -- "$TEMPORAIRE"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

TOMBEES=()
for cible in "${CIBLES[@]}"; do
  binaire="$BINAIRES/$cible"
  graines="fuzz/graines/$cible"
  if [ ! -x "$binaire" ]; then
    echo "ECHEC: $binaire absent apres la construction" >&2
    exit 1
  fi
  shopt -s nullglob
  fichiers=("$graines"/*)
  shopt -u nullglob
  if [ "${#fichiers[@]}" -eq 0 ]; then
    echo "ECHEC: aucune graine sous $graines" >&2
    exit 1
  fi

  echo
  echo "== $cible: relecture des ${#fichiers[@]} graines =="
  if ! TMPDIR="$TEMPORAIRE" "$binaire" "${BORNES[@]}" "${fichiers[@]}"; then
    echo "TOMBEE: $cible sur une graine (voir la sortie ci-dessus)"
    TOMBEES+=("$cible (graine)")
    continue
  fi
  if [ "$REJOUER_SEULEMENT" -eq 1 ]; then
    continue
  fi

  travail="fuzz/target/corpus-travail/$cible"
  artefacts="fuzz/target/artefacts/$cible"
  mkdir -p "$travail" "$artefacts"
  echo "== $cible: campagne de $DUREE s =="
  if ! TMPDIR="$TEMPORAIRE" "$binaire" "${BORNES[@]}" -max_total_time="$DUREE" \
    -print_final_stats=1 -artifact_prefix="$artefacts/" "$travail" "$graines"; then
    echo "TOMBEE: $cible, entree conservee sous $artefacts/"
    TOMBEES+=("$cible (campagne)")
  fi
done

echo
if [ "${#TOMBEES[@]}" -gt 0 ]; then
  echo "ECHEC: ${#TOMBEES[@]} cible(s) tombee(s):"
  for t in "${TOMBEES[@]}"; do
    echo "  $t"
  done
  exit 1
fi
echo "${#CIBLES[@]} cible(s): aucune n'est tombee."
