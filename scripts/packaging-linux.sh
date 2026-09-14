#!/usr/bin/env bash
# Eprouve l'empaquetage Linux SANS toucher a la machine qui l'execute.
#
# Creer un compte systeme pour verifier qu'on sait creer un compte systeme
# laisserait une trace permanente sur chaque machine de recette, et sur un
# runner d'integration continue cela ne prouverait rien de plus. On applique
# donc le fichier declaratif dans une racine jetable, avec `--root`, et on lit
# les fichiers de comptes qu'il y ecrit. Ce qui est mesure est exactement ce
# qui se produirait a l'installation.
#
# Usage: sudo ./scripts/packaging-linux.sh

set -euo pipefail

RACINE_DEPOT="$(cd "$(dirname "$0")/.." && pwd)"
SYSUSERS="$RACINE_DEPOT/packaging/sysusers.d/bifrost.conf"
UNITE="$RACINE_DEPOT/packaging/systemd/bifrost-daemon.service"
INSTALL="$RACINE_DEPOT/packaging/install-linux.sh"
ESSAI="$(mktemp -d)"

ECHECS=0
ok()   { printf '  OK    %s\n' "$1"; }
fail() { printf '  ECHEC %s\n' "$1"; ECHECS=$((ECHECS + 1)); }
step() { printf '\n== %s\n' "$1"; }
nettoyer() { rm -rf "$ESSAI"; }
trap nettoyer EXIT

[ "$(id -u)" -eq 0 ] || { echo "ce script doit tourner en root"; exit 1; }
for f in "$SYSUSERS" "$UNITE" "$INSTALL"; do
  [ -f "$f" ] || { echo "fichier d'empaquetage introuvable: $f"; exit 1; }
done
command -v systemd-sysusers >/dev/null 2>&1 || {
  echo "SKIPPED: systemd-sysusers absent, le fichier declaratif ne peut pas etre eprouve"
  exit 0
}

# Racine jetable minimale. sysusers a besoin des fichiers de comptes pour
# choisir des identifiants libres.
mkdir -p "$ESSAI/etc"
printf 'root:x:0:0:root:/root:/bin/bash\n' > "$ESSAI/etc/passwd"
printf 'root:x:0:\n'                       > "$ESSAI/etc/group"
printf 'root:!:19000:0:99999:7:::\n'       > "$ESSAI/etc/shadow"

step "Le fichier declaratif cree les comptes"
systemd-sysusers --root="$ESSAI" "$SYSUSERS" >/dev/null 2>&1 \
  && ok "systemd-sysusers a accepte le fichier" \
  || fail "systemd-sysusers a refuse le fichier"

COMPTES=$(grep '^u ' "$SYSUSERS" | awk '{print $2}')
GROUPE=$(grep '^g ' "$SYSUSERS" | awk '{print $2}')
COMPTE=$(echo "$COMPTES" | head -1)   # le coeur, pour les controles qui le visent
# Le resolveur, lu dans le fichier declaratif et non ecrit en dur ici: une
# recette qui recopie le nom qu'elle verifie ne verifie que sa propre copie.
COMPTE_RESOLVEUR=$(echo "$COMPTES" | grep resolveur | head -1)
LIGNE=$(grep "^$COMPTE:" "$ESSAI/etc/passwd" || true)

for c in $COMPTES; do
  grep -q "^$c:" "$ESSAI/etc/passwd" && ok "compte $c cree" || fail "compte $c absent"
done
grep -q "^$GROUPE:" "$ESSAI/etc/group" \
  && ok "groupe de pilotage $GROUPE cree" \
  || fail "groupe $GROUPE absent"

step "Aucun compte de service ne peut ouvrir de session"
# Chacun de ces comptes porte un privilege que personne d'autre n'a: une sortie
# en clair pour le coeur, le droit d'emettre du :53 pour le resolveur.
# Quiconque pourrait se placer sous l'une de ces identites en heriterait.
for c in $COMPTES; do
  L=$(grep "^$c:" "$ESSAI/etc/passwd" || true)
  case "$L" in
    *:/usr/sbin/nologin|*:/sbin/nologin|*:/bin/false)
      ok "$c: shell interdit ($(echo "$L" | awk -F: '{print $7}'))" ;;
    *) fail "$c: shell utilisable ($(echo "$L" | awk -F: '{print $7}'))" ;;
  esac
  if [ "$(echo "$L" | awk -F: '{print $6}')" = "/nonexistent" ]; then
    ok "$c: aucun repertoire personnel"
  else
    fail "$c: repertoire personnel $(echo "$L" | awk -F: '{print $6}')"
  fi
done

step "Le coeur et le resolveur sont deux identites distinctes"
# La propriete que ce fichier existe pour garantir. Les deux roles sont
# OPPOSES: le coeur est exempte du kill switch pour sortir hors du tunnel, le
# resolveur ne l'est pas et ne doit jamais l'etre. Un seul compte pour les deux
# donnerait au resolveur DNS une sortie en clair, c'est-a-dire exactement la
# fuite que le resolveur chiffre existe pour fermer, et le vecteur dns-leak
# resterait vert puisque cette sortie serait autorisee.
NB_COMPTES=$(echo "$COMPTES" | grep -c .)
NB_UID=$(for c in $COMPTES; do grep "^$c:" "$ESSAI/etc/passwd" | awk -F: '{print $3}'; done | sort -u | wc -l)
if [ "$NB_COMPTES" -ge 2 ] && [ "$NB_UID" -eq "$NB_COMPTES" ]; then
  ok "$NB_COMPTES comptes, $NB_UID identifiants distincts"
else
  fail "$NB_COMPTES compte(s) pour $NB_UID identifiant(s): des roles se confondent"
fi

step "Aucun compte de service ne peut piloter le daemon"
# Membre du groupe de pilotage, l'un d'eux pourrait DECONNECTER le VPN: un
# debordement dans un parseur tiers deviendrait une coupure a distance.
MEMBRES=$(grep "^$GROUPE:" "$ESSAI/etc/group" | awk -F: '{print $4}')
GID_PILOTAGE=$(grep "^$GROUPE:" "$ESSAI/etc/group" | awk -F: '{print $3}')
for c in $COMPTES; do
  if echo ",$MEMBRES," | grep -q ",$c,"; then
    fail "$c est membre de $GROUPE: il pourrait couper le tunnel"
  else
    ok "$c n'est pas membre de $GROUPE"
  fi
  # Et son groupe primaire n'est pas celui de pilotage non plus: la ligne
  # passwd porte un GID, que le controle precedent ne regarde pas.
  GID=$(grep "^$c:" "$ESSAI/etc/passwd" | awk -F: '{print $4}')
  if [ "$GID" = "$GID_PILOTAGE" ]; then
    fail "$c a pour groupe primaire celui de pilotage (gid $GID)"
  else
    ok "$c: groupe primaire distinct (gid $GID, pilotage $GID_PILOTAGE)"
  fi
done

step "Rejouer l'installation ne casse rien"
AVANT=$(cat "$ESSAI/etc/passwd" "$ESSAI/etc/group")
systemd-sysusers --root="$ESSAI" "$SYSUSERS" >/dev/null 2>&1 || true
if [ "$AVANT" = "$(cat "$ESSAI/etc/passwd" "$ESSAI/etc/group")" ]; then
  ok "second passage sans effet"
else
  fail "second passage a modifie les comptes: l'installation n'est pas idempotente"
fi

step "L'unite et le fichier de comptes nomment le meme compte"
# Deux fichiers qui doivent s'accorder, et rien dans le systeme ne les relie.
# S'ils divergeaient, le daemon refuserait de demarrer avec un message tres
# clair, sur un fichier que personne ne penserait a relire.
# Depuis la ligne ExecStart et elle seule: les commentaires de l'unite parlent
# aussi de ce drapeau, et les lire donnerait un nom qui n'est pas celui passe
# au daemon.
DECLARE=$(grep '^ExecStart=' "$UNITE" | grep -o -- '--coeur-utilisateur [^ ]*' | awk '{print $2}')
if [ "$DECLARE" = "$COMPTE" ]; then
  ok "l'unite demande $DECLARE, le fichier de comptes cree $COMPTE"
else
  fail "l'unite demande ${DECLARE:-<rien>} mais le fichier de comptes cree $COMPTE"
fi

step "Les deux voies de creation produisent le meme compte"
# L'installateur retombe sur `useradd` quand systemd-sysusers est absent, ce
# qui est le cas d'Alpine, de Devuan, de Void et des CentOS anciens. Cette voie
# n'avait jamais TOURNE nulle part: la recette grepait ses options dans
# l'installateur et les comparait a la declaration. Une comparaison de texte ne
# voit ni ce que `useradd` fait, ni ce qu'il refuse, ni le compte qu'il produit
# - et de fait elle n'avait pas vu que le repli donnait aux DEUX comptes le
# meme commentaire, la ou la declaration en donne un par role.
#
# Elle l'exerce maintenant dans une seconde racine jetable, en appelant la
# fonction que l'installateur appelle lui-meme. Pas une transcription: la meme.
if ! command -v useradd >/dev/null 2>&1 || ! command -v groupadd >/dev/null 2>&1; then
  echo "  SKIP  useradd ou groupadd absent: la voie de repli ne peut pas etre exercee ici"
elif ! useradd --help 2>&1 | grep -q -- '--prefix'; then
  echo "  SKIP  useradd sans --prefix (shadow-utils < 4.6): l'exercer toucherait la vraie machine"
else
  REPLI=$(mktemp -d)
  trap 'nettoyer; rm -rf "$REPLI"' EXIT
  mkdir -p "$REPLI/etc"
  printf 'root:x:0:0:root:/root:/bin/bash\n' > "$REPLI/etc/passwd"
  printf 'root:x:0:\n'                       > "$REPLI/etc/group"
  printf 'root:!:19000:0:99999:7:::\n'       > "$REPLI/etc/shadow"
  # useradd --system lit ces bornes dans le login.defs DU PREFIXE. Sans elles
  # il refuserait, et son refus se lirait comme un defaut du repli.
  printf 'SYS_UID_MIN 100\nSYS_UID_MAX 999\nSYS_GID_MIN 100\nSYS_GID_MAX 999\n' \
    > "$REPLI/etc/login.defs"

  # shellcheck source=../packaging/comptes.sh
  . "$RACINE_DEPOT/packaging/comptes.sh"
  if comptes_creer_a_la_main "$SYSUSERS" "$GROUPE" "$REPLI" $COMPTES >/dev/null 2>&1; then
    ok "la voie de repli s'execute sans erreur"
  else
    fail "la voie de repli echoue a l'execution"
  fi

  # Les deux voies doivent produire le MEME compte. Comparaison champ par
  # champ sur ce que chacune a REELLEMENT ecrit, pas sur ce que l'installateur
  # a l'air de demander. Champs 5, 6, 7: commentaire, repertoire, shell.
  for c in $COMPTES; do
    DECLAREE=$(grep "^$c:" "$ESSAI/etc/passwd" | cut -d: -f5,6,7 || true)
    REPLIEE=$(grep "^$c:" "$REPLI/etc/passwd" | cut -d: -f5,6,7 || true)
    if [ -z "$DECLAREE" ] || [ -z "$REPLIEE" ]; then
      fail "$c manquant dans l'une des deux racines (declaratif: ${DECLAREE:-<absent>}, repli: ${REPLIEE:-<absent>})"
    elif [ "$DECLAREE" = "$REPLIEE" ]; then
      ok "$c identique par les deux voies ($DECLAREE)"
    else
      fail "$c diverge: declaratif [$DECLAREE], repli [$REPLIEE]"
    fi
  done

  # Le groupe primaire doit etre le groupe DEDIE, ce que --no-user-group
  # garantit. Seule propriete que la comparaison ci-dessus ne couvre pas: elle
  # porterait sur le NUMERO de groupe, qui differe legitimement d'une racine a
  # l'autre.
  for c in $COMPTES; do
    GID=$(grep "^$c:" "$REPLI/etc/passwd" | cut -d: -f4)
    NOM_GROUPE=$(awk -F: -v g="$GID" '$3 == g {print $1}' "$REPLI/etc/group")
    [ "$NOM_GROUPE" = "$c" ] \
      && ok "$c a pour groupe primaire son groupe dedie" \
      || fail "$c a pour groupe primaire ${NOM_GROUPE:-<inconnu>}, pas $c"
    if grep "^$GROUPE:" "$REPLI/etc/group" | cut -d: -f4 | tr ',' '\n' | grep -qx "$c"; then
      fail "le repli a mis $c dans le groupe de pilotage $GROUPE"
    fi
  done
  ok "aucun compte de service n'est dans le groupe de pilotage par la voie de repli"
fi

step "L'unite et l'installateur s'accordent sur le resolveur"
# Meme famille de piege que ci-dessus, sur trois valeurs cette fois: le compte
# du resolveur, le chemin ou l'installateur DEPOSE le binaire, et celui que
# l'unite lui DESIGNE. Rien dans le systeme ne relie ces fichiers; s'ils
# divergeaient, tout s'installerait sans un mot et seule une connexion avec un
# profil `embarque` le revelerait, des mois plus tard.
EXEC_START=$(sed -e ':a' -e '/\\$/{N; s/\\\n[[:space:]]*//; ta}' "$UNITE" | grep '^ExecStart=')
DECLARE_RESOLVEUR=$(echo "$EXEC_START" | grep -o -- '--resolveur-utilisateur [^ ]*' | awk '{print $2}')
if [ "$DECLARE_RESOLVEUR" = "$COMPTE_RESOLVEUR" ]; then
  ok "l'unite demande $DECLARE_RESOLVEUR, le fichier de comptes le cree"
else
  fail "l'unite demande ${DECLARE_RESOLVEUR:-<rien>} mais le fichier de comptes cree $COMPTE_RESOLVEUR"
fi

CHEMIN_UNITE=$(echo "$EXEC_START" | grep -o -- '--resolveur-binaire [^ ]*' | awk '{print $2}')
CHEMIN_INSTALL=$(grep '^RESOLVEUR_INSTALLE=' "$INSTALL" | cut -d= -f2)
if [ -n "$CHEMIN_UNITE" ] && [ "$CHEMIN_UNITE" = "$CHEMIN_INSTALL" ]; then
  ok "le binaire est depose et designe au meme endroit ($CHEMIN_UNITE)"
else
  fail "l'unite designe ${CHEMIN_UNITE:-<rien>}, l'installateur depose ${CHEMIN_INSTALL:-<rien>}"
fi

# Un resolveur qui pourrait reecrire son propre programme transformerait
# n'importe quel defaut de dnscrypt-proxy en persistance sur la machine.
if grep -q 'install -D -m 0755 -o root -g root "\$RESOLVEUR" "\$RESOLVEUR_INSTALLE"' "$INSTALL"; then
  ok "le binaire est pose root:root en 0755, hors de portee du compte qui l'execute"
else
  fail "le binaire du resolveur n'est pas pose explicitement en root:root 0755"
fi

step "L'unite peut reellement faire tourner le resolveur"
# Les capacites ne sont pas decoratives, et leur absence ne se voit pas a la
# lecture. Mesure du 17/08/2026: sans CAP_SETUID ni CAP_NET_BIND_SERVICE la
# bascule echoue, et sans CAP_KILL le daemon lance le resolveur sans jamais
# pouvoir l'arreter, root n'ayant pas le droit de signaler un processus d'un
# autre UID. Ce controle-ci ne lit que la declaration; c'est
# scripts/resolveur-systemd-linux.sh qui l'eprouve pour de vrai.
BORNES=$(grep '^CapabilityBoundingSet=' "$UNITE" | cut -d= -f2-)
for capacite in CAP_SETUID CAP_SETGID CAP_NET_BIND_SERVICE CAP_KILL; do
  case " $BORNES " in
    *" $capacite "*) ok "$capacite est dans le CapabilityBoundingSet" ;;
    *) fail "$capacite manque: le daemon ne pourra pas mener le resolveur jusqu'au bout" ;;
  esac
done

# Et son oppose: l'ambiant est HERITE. CAP_KILL n'y a rien a faire, le
# resolveur n'ayant aucune raison de signaler quoi que ce soit.
AMBIANTES=$(grep '^AmbientCapabilities=' "$UNITE" | cut -d= -f2-)
case " $AMBIANTES " in
  *" CAP_KILL "*) fail "CAP_KILL est ambiant, donc transmis au resolveur" ;;
  *) ok "CAP_KILL n'est pas ambiant" ;;
esac

step "L'installateur ne demarre rien tout seul"
# Poser un kill switch coupe la session SSH depuis laquelle on installe. Un
# installateur qui active le service au passage transformerait une installation
# en perte d'acces a la machine.
# Le texte d'aide final CITE la commande a lancer a la main; on le retire avant
# de chercher, sinon la recette confondrait "explique quoi faire" et "le fait".
COMMANDES=$(sed '/<<TEXTE/,/^TEXTE$/d' "$INSTALL" | grep -v '^[[:space:]]*#')
if echo "$COMMANDES" | grep -qE 'systemctl[[:space:]]+(enable|start)'; then
  fail "l'installateur active ou demarre le service"
else
  ok "aucune activation automatique"
fi

echo
if [ "$ECHECS" -eq 0 ]; then
  echo "empaquetage Linux: tout est passe"
else
  echo "empaquetage Linux: $ECHECS controle(s) en echec"
  exit 1
fi
