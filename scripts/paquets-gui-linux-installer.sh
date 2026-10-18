#!/usr/bin/env bash
# Installation, premier lancement et retrait REELS du .deb de la coquille
# graphique de Bifrost. Runner jetable seulement.
#
# Ce script modifie la machine: il installe le paquet et ses dependances, lance
# la coquille, puis la retire. Il refuse de tourner sans
# BIFROST_RUNNER_JETABLE=1, que seul le job paquets-gui-linux de la CI pose,
# sur un runner jetable.
#
# Ce qu'il mesure, dans l'ordre (OK ou ECHEC par controle, sortie au premier
# ECHEC):
#   1. avant: aucun paquet bifrost-gui;
#   2. apt-get install: binaire, entree de bureau, page et icones en place,
#      modes et proprietaires; entree de bureau muette sous
#      desktop-file-validate; ldd sans bibliotheque introuvable, et la
#      bibliotheque chargee par dlopen presente; aucune entree de demarrage de
#      session; aucun compte ni groupe cree par le paquet;
#   3. lancement en root: la coquille refuse et sort en 3, avec son message;
#   4. premier lancement sous l'utilisateur qui a invoque sudo, sur un serveur X
#      virtuel (xvfb-run), sans daemon: elle tient 8 s (timeout rend 124) sans
#      panique;
#   5. apt-get remove: tout est retire, et l'etat dpkg du paquet est relu (sans
#      conffile ni script du mainteneur, dpkg l'oublie des le retrait; une
#      purge n'est faite que s'il reste un etat config-files);
#   6. le .rpm, s'il a ete construit, est lu (fichiers, dependances, scriptlets)
#      mais pas installe: la base du runner est Debian.
#
# Usage: sudo BIFROST_RUNNER_JETABLE=1 ./scripts/paquets-gui-linux-installer.sh [REPERTOIRE_PAQUETS]
set -uo pipefail

RACINE_DEPOT="$(cd "$(dirname "$0")/.." && pwd)"
PAQUETS="${1:-$RACINE_DEPOT/target/paquets-gui}"

if [ "${BIFROST_RUNNER_JETABLE:-}" != "1" ]; then
  echo "REFUS: ce script installe, lance et retire la coquille graphique." >&2
  echo "       Il ne tourne que sur un runner jetable, BIFROST_RUNNER_JETABLE=1 pose." >&2
  exit 1
fi
[ "$(id -u)" -eq 0 ] || { echo "REFUS: ce script doit tourner en root (apt-get)." >&2; exit 1; }
for outil in xvfb-run desktop-file-validate timeout ldd; do
  command -v "$outil" >/dev/null 2>&1 || { echo "outil requis absent: $outil" >&2; exit 1; }
done

export DEBIAN_FRONTEND=noninteractive

ok()   { printf '  OK    %s\n' "$1"; }
step() { printf '\n== %s\n' "$1"; }
echec() {
  printf '  ECHEC %s\n' "$1"
  echo "---- dpkg -s bifrost-gui ----"
  dpkg -s bifrost-gui 2>/dev/null || echo "(paquet non installe)"
  exit 1
}

ID_APP="$(awk -F'"' '/"identifier"[[:space:]]*:/{print $4; exit}' "$RACINE_DEPOT/gui/tauri.conf.json")"
[ -n "$ID_APP" ] || { echo "identifiant illisible dans gui/tauri.conf.json"; exit 1; }
DESKTOP="/usr/share/applications/$ID_APP.desktop"
DEB="$(ls "$PAQUETS"/bifrost-gui_*_amd64.deb 2>/dev/null | sed -n 1p)"
[ -n "$DEB" ] && [ -f "$DEB" ] || { echo "aucun .deb sous $PAQUETS (scripts/paquets-gui-linux.sh d'abord)"; exit 1; }
echo "paquet: $DEB"

# ------------------------------------------------------------------- avant
step "Avant installation"
if dpkg -s bifrost-gui >/dev/null 2>&1; then echec "un paquet bifrost-gui est deja installe"; fi
ok "aucun paquet bifrost-gui"
GROUPES_AVANT="$(getent group | cut -d: -f1 | sort)"
COMPTES_AVANT="$(getent passwd | cut -d: -f1 | sort)"

# ----------------------------------------------------------------- install
step "apt-get install"
# Le .deb par son chemin: apt resout ses Depends. Le Recommends bifrost n'est
# dans aucune source du runner: apt le laisse.
apt-get install -y "$DEB" || echec "apt-get install a echoue"
ok "paquet installe"

step "Fichiers poses"
[ "$(stat -c '%a %U:%G' /usr/bin/bifrost-gui 2>/dev/null)" = "755 root:root" ] \
  && ok "/usr/bin/bifrost-gui 755 root:root" || echec "/usr/bin/bifrost-gui: $(stat -c '%a %U:%G' /usr/bin/bifrost-gui 2>&1)"
for chemin in "$DESKTOP" /usr/share/man/man1/bifrost-gui.1.gz /usr/share/doc/bifrost-gui/copyright; do
  [ "$(stat -c '%a %U:%G' "$chemin" 2>/dev/null)" = "644 root:root" ] && ok "$chemin 644 root:root" \
    || echec "$chemin: $(stat -c '%a %U:%G' "$chemin" 2>&1)"
done
ICONES="$(find /usr/share/icons/hicolor -path "*/apps/$ID_APP.png")"
NB_ICONES="$(grep -c . <<< "$ICONES" || true)"
[ "$NB_ICONES" -ge 1 ] && ok "$NB_ICONES icone(s) hicolor $ID_APP.png" || echec "aucune icone hicolor posee"
cmp -s "$DESKTOP" "$RACINE_DEPOT/packaging/desktop/$ID_APP.desktop" \
  && ok "entree de bureau identique a sa source" || echec "entree de bureau differente de sa source"
DFV="$(desktop-file-validate "$DESKTOP" 2>&1)"
[ -z "$DFV" ] && ok "desktop-file-validate: muet sur l'entree posee" \
  || { sed 's/^/    /' <<< "$DFV"; echec "desktop-file-validate a parle sur l'entree posee"; }

step "Bibliotheques"
LDD="$(ldd /usr/bin/bifrost-gui 2>&1)"
if grep -F 'not found' >/dev/null <<< "$LDD"; then
  sed 's/^/    /' <<< "$LDD"
  echec "ldd: au moins une bibliotheque introuvable"
fi
ok "ldd: aucune bibliotheque introuvable"
if ldconfig -p | grep -F 'libayatana-appindicator3.so.1' >/dev/null; then
  ok "libayatana-appindicator3.so.1 presente (chargee par dlopen pour la zone de notification)"
else
  echec "libayatana-appindicator3.so.1 absente apres installation"
fi

step "Pas de demarrage automatique, aucun compte"
AUTOSTART="$(ls /etc/xdg/autostart 2>/dev/null || true)"
if grep -F -e "$ID_APP" -e bifrost >/dev/null <<< "$AUTOSTART"; then
  echec "une entree de demarrage de session nomme la coquille: $AUTOSTART"
fi
ok "aucune entree sous /etc/xdg/autostart"
LISTE_PAQUET="$(dpkg -L bifrost-gui)"
if grep -F 'autostart' >/dev/null <<< "$LISTE_PAQUET"; then
  echec "le paquet pose un fichier sous un repertoire autostart"
fi
ok "aucun fichier autostart dans la liste du paquet"
[ "$(getent group | cut -d: -f1 | sort)" = "$GROUPES_AVANT" ] && ok "aucun groupe cree" || echec "un groupe a ete cree par le paquet"
[ "$(getent passwd | cut -d: -f1 | sort)" = "$COMPTES_AVANT" ] && ok "aucun compte cree" || echec "un compte a ete cree par le paquet"

# --------------------------------------------------------------- lancements
step "Lancement en root: refus, code 3"
# Le refus est la premiere chose que fait la coquille: aucun affichage requis.
ERREUR_ROOT="$(timeout -k 3 8 /usr/bin/bifrost-gui 2>&1 >/dev/null)"
CODE_ROOT=$?
sed 's/^/    /' <<< "$ERREUR_ROOT"
[ "$CODE_ROOT" -eq 3 ] && ok "code 3" || echec "lancement en root: code $CODE_ROOT au lieu de 3"
grep -F 'ne doit pas etre lance en administrateur' >/dev/null <<< "$ERREUR_ROOT" \
  && ok "message de refus sur stderr" || echec "message de refus absent de stderr"

step "Premier lancement, utilisateur ordinaire, sans daemon"
LANCEUR="${SUDO_USER:-}"
if [ -z "$LANCEUR" ] || [ "$LANCEUR" = "root" ]; then
  echec "aucun utilisateur ordinaire (SUDO_USER) pour lancer la coquille"
fi
# Sans GPU: pas de composition. La coquille est arretee par timeout, jamais
# par un motif de nom.
ERREUR_UTILISATEUR="$(sudo -H -u "$LANCEUR" env WEBKIT_DISABLE_COMPOSITING_MODE=1 \
  xvfb-run -a timeout -k 3 8 /usr/bin/bifrost-gui 2>&1 >/dev/null)"
CODE_UTILISATEUR=$?
if grep -E 'panicked|RUST_BACKTRACE' >/dev/null <<< "$ERREUR_UTILISATEUR"; then
  sed 's/^/    /' <<< "$ERREUR_UTILISATEUR"
  echec "la coquille a panique"
fi
if [ "$CODE_UTILISATEUR" -eq 124 ]; then
  ok "la coquille a tenu 8 s sous $LANCEUR (timeout, code 124), sans panique"
  if [ -n "$ERREUR_UTILISATEUR" ]; then
    echo "  stderr (sans session D-Bus ni hote de zone de notification):"
    sed 's/^/    /' <<< "$ERREUR_UTILISATEUR"
  fi
else
  sed 's/^/    /' <<< "$ERREUR_UTILISATEUR"
  echec "la coquille est sortie en $CODE_UTILISATEUR (attendu 124: vivante au bout du delai)"
fi

# ------------------------------------------------------------------ remove
step "apt-get remove"
apt-get remove -y bifrost-gui || echec "apt-get remove a echoue"
for chemin in /usr/bin/bifrost-gui "$DESKTOP" /usr/share/man/man1/bifrost-gui.1.gz; do
  [ ! -e "$chemin" ] && ok "$chemin retire" || echec "$chemin encore present apres remove"
done
RESTES="$(find /usr/share/icons/hicolor -path "*/apps/$ID_APP.png")"
[ -z "$RESTES" ] && ok "icones retirees" || echec "icones encore presentes: $RESTES"

step "Etat dpkg apres remove"
# ${db:Status-Status}: installed, config-files ou not-installed; rien du tout
# (code non nul) quand dpkg a oublie le paquet.
ETAT="$(dpkg-query -W -f='${db:Status-Status}' bifrost-gui 2>/dev/null)"
ETAT_CODE=$?
echo "  etat: '${ETAT}' (code $ETAT_CODE)"
if [ "$ETAT_CODE" -ne 0 ] || [ -z "$ETAT" ] || [ "$ETAT" = "not-installed" ]; then
  ok "rien a purger: aucun conffile, aucun script du mainteneur"
elif [ "$ETAT" = "config-files" ]; then
  apt-get purge -y bifrost-gui || echec "apt-get purge a echoue"
  ETAT_APRES="$(dpkg-query -W -f='${db:Status-Status}' bifrost-gui 2>/dev/null)"
  [ -z "$ETAT_APRES" ] || [ "$ETAT_APRES" = "not-installed" ] && ok "purge faite" \
    || echec "etat apres purge: '$ETAT_APRES'"
else
  echec "etat dpkg inattendu apres remove: '$ETAT'"
fi

# --------------------------------------------------------------------- rpm
step "Lecture du .rpm (sans installation)"
RPM="$(ls "$PAQUETS"/bifrost-gui-*.rpm 2>/dev/null | sed -n 1p)"
if [ -z "$RPM" ]; then
  echo "  SKIPPED: aucun .rpm sous $PAQUETS (rpmbuild absent a la construction)"
elif ! command -v rpm >/dev/null 2>&1; then
  echo "  SKIPPED: rpm absent, le .rpm n'est pas lu"
else
  LISTE_RPM="$(rpm -qlp "$RPM")"
  sed 's/^/    /' <<< "$LISTE_RPM"
  if grep -F 'autostart' >/dev/null <<< "$LISTE_RPM"; then
    echec "le .rpm pose un fichier sous un repertoire autostart"
  fi
  [ -z "$(rpm -qp --scripts "$RPM")" ] && ok "aucun scriptlet, aucune entree autostart (lu, pas installe)" \
    || echec "le .rpm porte des scriptlets"
fi

echo
echo "installation, lancement et retrait reels de la coquille: tout est passe"
