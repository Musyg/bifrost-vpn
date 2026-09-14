#!/usr/bin/env bash
# Eprouve le resolveur chiffre sous le durcissement REEL de l'unite systemd.
#
# `--resolveur-selftest` lance sous `sudo` ne prouve pas grand-chose sur le
# produit: root y garde toutes ses capacites, tous les repertoires sont
# accessibles en ecriture, et rien ne ressemble a ce que l'unite impose. Trois
# defauts que cette recette a trouves, tous verts sous `sudo`:
#
#   - le daemon chownait le repertoire de travail AVANT d'y ecrire, ce que
#     l'absence de CAP_DAC_OVERRIDE lui interdisait ensuite;
#   - le CapabilityBoundingSet ne contenait ni CAP_SETUID ni
#     CAP_NET_BIND_SERVICE, donc la bascule etait impossible;
#   - et surtout, il ne contenait pas CAP_KILL: le daemon pouvait lancer le
#     resolveur et jamais l'arreter, root n'ayant pas le droit de signaler un
#     processus d'un autre UID sans cette capacite.
#
# Les proprietes ne sont pas recopiees ici: elles sont LUES dans l'unite
# installee. Une recette qui les redit a sa facon mesure sa propre copie, et
# reste verte pendant que l'unite derive.
#
# Usage: sudo ./scripts/resolveur-systemd-linux.sh [chemin/vers/unite]

set -euo pipefail

UNITE="${1:-/etc/systemd/system/bifrost-daemon.service}"
DAEMON=/usr/bin/bifrost-daemon
RESOLVEUR=/usr/lib/bifrost/dnscrypt-proxy
CONFIGURATION=/run/bifrost/resolveur/dnscrypt-proxy.toml
COMPTE=bifrost-resolveur

ok()   { printf '  OK    %s\n' "$1"; }
step() { printf '\n== %s\n' "$1"; }
skip() { printf '  SKIP  %s\n' "$1"; exit 3; }

step "Ce qu'il faut pour mesurer"
command -v systemd-run >/dev/null 2>&1 || skip "systemd-run absent"
[ "$(id -u)" -eq 0 ] || skip "poser un service transitoire et se lier au :53 exigent root"
[ -f "$UNITE" ] || skip "unite absente: $UNITE. Lancer packaging/install-linux.sh"
[ -x "$DAEMON" ] || skip "$DAEMON absent: lancer packaging/install-linux.sh"
[ -x "$RESOLVEUR" ] || skip "$RESOLVEUR absent: RESOLVEUR=... packaging/install-linux.sh"
ok "unite $UNITE, daemon et resolveur en place"

step "Durcissement lu dans l'unite"
# Tout le [Service] SAUF ce qui decrit le processus a lancer: la recette
# remplace la commande, elle ne doit rien changer d'autre. Les continuations
# de ligne sont recollees avant le tri, sinon la suite d'un ExecStart
# multiligne passerait pour une directive.
PROPRIETES=()
while IFS= read -r ligne; do
  case "$ligne" in
    Exec*|Type=*|Restart=*|RestartSec=*|'#'*|'') continue ;;
  esac
  PROPRIETES+=(-p "$ligne")
done < <(
  sed -n '/^\[Service\]/,/^\[/p' "$UNITE" \
    | sed -e ':a' -e '/\\$/{N; s/\\\n[[:space:]]*//; ta}' \
    | grep -E '^[A-Za-z]+='
)
[ ${#PROPRIETES[@]} -gt 0 ] || skip "aucune directive lue dans le [Service] de $UNITE"
ok "$(( ${#PROPRIETES[@]} / 2 )) directive(s) reprises telles quelles"
printf '        %s\n' "${PROPRIETES[@]}" | grep -v '^        -p$' | sed 's/^        /        /'

step "Le resolveur sous ce durcissement"
# Le repertoire de travail est recree a chaque passage: le laisser ferait
# passer pour bon un daemon qui ne sait plus le creer.
rm -rf "$(dirname "$CONFIGURATION")"
systemd-run --wait --collect --quiet --pipe "${PROPRIETES[@]}" \
  "$DAEMON" --resolveur-selftest \
    --resolveur-binaire "$RESOLVEUR" \
    --resolveur-configuration "$CONFIGURATION" \
    --resolveur-utilisateur "$COMPTE"
CODE=$?

step "Ce qui reste apres"
RESIDUS=$(pgrep -f "^$RESOLVEUR " || true)
if [ -n "$RESIDUS" ]; then
  printf '  ECHEC un resolveur survit a la recette: %s\n' "$RESIDUS"
  CODE=1
else
  ok "aucun resolveur residuel"
fi

if [ "$CODE" -eq 0 ]; then
  printf '\nresolveur sous unite systemd: tout est passe\n'
else
  printf '\nresolveur sous unite systemd: echec (code %s)\n' "$CODE"
fi
exit "$CODE"
