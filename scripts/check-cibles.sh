#!/usr/bin/env bash
# Compile le depot pour chaque plateforme visee, pas seulement pour celle-ci.
#
# # Le defaut qu'il attrape
#
# Le 21 aout 2026, `demarrage_cli` a perdu son `#[cfg(windows)]` en meme temps
# que son commentaire, remplaces par ceux d'une fonction inseree au-dessus. Le
# corps est entierement Windows: il appelle `bifrost_firewall::windows` et un
# aide lui-meme gate. Sur Windows, rien ne bronche. Sur Linux, cinq erreurs de
# compilation - et le binaire n'existe simplement plus.
#
# Ce qui l'a laisse passer merite d'etre nomme: `cargo check`, `cargo clippy`,
# `cargo fmt` et 942 recettes vertes, tous sur la seule plateforme de
# developpement. Aucune n'avait la moindre chance de le voir, parce qu'un
# defaut de `cfg` n'est pas un defaut de logique: c'est du code qui n'existe
# pas la ou on regarde. Il a fallu construire ailleurs pour qu'il apparaisse.
#
# # Pourquoi `check` et pas `build`
#
# `cargo check` ne fait pas d'edition de liens: il ne reclame donc pas de linker
# pour la cible, et la bibliotheque standard que `rustup target add` pose suffit
# a verifier du Rust pur.
#
# Elle ne suffit PAS partout, et c'est mesure. Le depot tire `aws-lc-sys`, qui
# compile du C, par `aws-lc-rs` sous `rustls`, `ureq` et `rcgen` - donc par
# `bifrost-amorce` et `bifrost-cli`. Son script de construction tourne meme sous
# `check`. Depuis Linux vers Windows, il invoque le `cc` de l'hote avec les
# defines de la cible et echoue sur `unknown type name 'pthread_rwlock_t'`
# (mesure du 21 aout 2026). Cela ne dit rien de notre code.
#
# Le script classe donc cet echec-la en ABSTENTION, pas en ECHEC, et le nomme.
# Un script de construction qui echoue n'est jamais du Rust qui ne type-checke
# pas: la distinction est nette et vaut mieux qu'un rouge qu'on apprend a
# ignorer.
#
# # Ce qu'il ne fait pas
#
# Il ne construit pas, donc il ne dit rien de l'edition de liens ni de
# l'execution sur la cible. Une plateforme qui compile ici peut encore echouer
# a lier ailleurs. Il repond a une question et une seule: le code existe-t-il,
# et tient-il, sous chaque `cfg`.
#
# Et comme la compilation croisee bute sur une dependance native, une seule
# machine ne peut PAS couvrir les deux plateformes. La couverture reelle demande
# ce script sur chacun des deux hotes - c'est ce que la ligne finale rappelle.
#
# # Abstentions
#
# Une cible non installee, ou dont une dependance native ne se compile pas
# d'ici, rend `ABSTENTION` en nommant la raison, jamais un vert. Et si AUCUNE
# cible n'a pu etre verifiee, le script echoue au lieu de conclure: zero mesure
# n'est pas zero probleme.
#
# Usage:
#   scripts/check-cibles.sh            # abstentions tolerees
#   scripts/check-cibles.sh --strict   # une abstention fait echouer

set -uo pipefail

CIBLES="x86_64-pc-windows-msvc x86_64-unknown-linux-gnu"
STRICT=0
[ "${1:-}" = "--strict" ] && STRICT=1

cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1

INSTALLEES=$(rustup target list --installed 2> /dev/null)
if [ -z "$INSTALLEES" ]; then
    echo "ECHEC: 'rustup target list --installed' n'a rien rendu."
    echo "       Sans rustup, ce script ne sait pas ce qu'il peut verifier."
    exit 1
fi

verifiees=0
abstentions=0
echecs=0

for cible in $CIBLES; do
    if ! printf '%s\n' "$INSTALLEES" | grep -qx "$cible"; then
        echo "ABSTENTION  $cible"
        echo "            non installee. Pour l'activer: rustup target add $cible"
        abstentions=$((abstentions + 1))
        continue
    fi
    if cargo check --workspace --all-targets --target "$cible" \
        > "/tmp/check-$cible.log" 2>&1; then
        echo "OK          $cible"
        verifiees=$((verifiees + 1))
        continue
    fi
    # Un script de construction qui tombe n'est pas du Rust qui ne tient pas:
    # c'est une chaine C absente pour cette cible. Le compter comme un echec
    # apprendrait a ignorer le rouge, ce qui coute plus cher que l'abstention.
    natif=$(grep -oE "failed to run custom build command for .[a-z0-9_-]+" \
        "/tmp/check-$cible.log" | head -1 | sed 's/.*for .//')
    if [ -n "$natif" ]; then
        echo "ABSTENTION  $cible"
        echo "            '$natif' compile du C et son script echoue d'ici."
        echo "            Verifier cette cible depuis un hote qui la porte."
        abstentions=$((abstentions + 1))
        continue
    fi
    echo "ECHEC       $cible"
    grep -E "^error" -A 4 "/tmp/check-$cible.log" | head -30 | sed 's/^/            /'
    echecs=$((echecs + 1))
    verifiees=$((verifiees + 1))
done

echo
echo "  cibles verifiees : $verifiees"
echo "  abstentions      : $abstentions"

# Le meme garde-fou que recettes-strict.sh: un script qui n'a rien mesure doit
# le dire, sinon son silence se lit comme un vert.
if [ "$verifiees" -eq 0 ]; then
    echo
    echo "ECHEC: aucune cible n'a pu etre verifiee, ce resultat ne vaut rien."
    exit 1
fi
if [ "$echecs" -gt 0 ]; then
    echo
    echo "ECHEC: $echecs cible(s) ne compilent pas. Journaux dans /tmp/check-<cible>.log"
    exit 1
fi
if [ "$STRICT" = 1 ] && [ "$abstentions" -gt 0 ]; then
    echo
    echo "ECHEC (--strict): $abstentions cible(s) non verifiee(s)."
    exit 1
fi
echo
echo "OK: $verifiees cible(s) verifiee(s) d'ici."
if [ "$abstentions" -gt 0 ]; then
    echo "    $abstentions non verifiee(s) d'ici, chacune pour la raison donnee"
    echo "    ci-dessus. Leur couverture demande un passage sur leur propre hote."
fi
exit 0
