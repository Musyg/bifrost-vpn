#!/usr/bin/env bash
# Construit et verifie les paquets Linux de la coquille graphique de Bifrost
# (bifrost-gui): le .deb, et le .rpm la ou rpmbuild existe.
#
# Dans l'ordre:
#   1. lit la version du workspace (Cargo.toml, [workspace.package]) et refuse
#      si gui/Cargo.toml ou gui/tauri.conf.json en annoncent une autre; lit
#      l'identifiant de l'application dans gui/tauri.conf.json, qui nomme
#      l'entree de bureau et l'icone;
#   2. exige le binaire de la coquille (gui/target/release/bifrost-gui), qui ne
#      se construit que la ou les paquets -dev de WebKitGTK sont poses, et
#      bifrost-icone (target/release);
#   3. ecrit les icones par bifrost-icone et pose une icone hicolor par PNG
#      bifrost-<cote>.png que le binaire a ecrit: aucune liste de cotes ici;
#   4. assemble l'arbre du .deb avec les fichiers de packaging/ tels quels,
#      strippe la copie du binaire, mesure les dependances (les bibliotheques
#      liees par dpkg-shlibdeps, et celle que la coquille charge a l'execution
#      pour sa zone de notification, retenue si son soname est dans le
#      binaire), les injecte avec la version dans le control, et construit le
#      paquet par fakeroot dpkg-deb, tout en root:root;
#   5. verifie le .deb: champs, modes et proprietaires, aucun fichier
#      inattendu, entree de bureau identique a sa source et muette sous
#      desktop-file-validate, aucun script du mainteneur, aucune entree de
#      demarrage de session; puis man --warnings et lintian s'ils sont la;
#   6. construit le .rpm par rpmbuild s'il est la, sinon le dit (SKIPPED), et
#      en lit les fichiers, les modes et les dependances.
#
# N'installe rien et ne demande pas root: fakeroot suffit. La sortie doit etre
# neuve: ce script refuse un repertoire de sortie qui n'est pas vide. Les arbres
# de travail y restent (icones, arbre-deb, rpmbuild), a cote des paquets.
#
# Usage: ./scripts/paquets-gui-linux.sh [REPERTOIRE_COQUILLE] [REPERTOIRE_BINAIRES] [REPERTOIRE_SORTIE]
#   REPERTOIRE_COQUILLE: defaut gui/target/release (bifrost-gui)
#   REPERTOIRE_BINAIRES: defaut target/release (bifrost-icone)
#   REPERTOIRE_SORTIE:   defaut target/paquets-gui
set -euo pipefail

RACINE_DEPOT="$(cd "$(dirname "$0")/.." && pwd)"
GUI_BIN="${1:-$RACINE_DEPOT/gui/target/release}"
BIN="${2:-$RACINE_DEPOT/target/release}"
SORTIE="${3:-$RACINE_DEPOT/target/paquets-gui}"

PKG="$RACINE_DEPOT/packaging"
CONTROL_SRC="$PKG/deb-gui/control"
COPYRIGHT_SRC="$PKG/deb-gui/copyright"
SPEC_SRC="$PKG/rpm/bifrost-gui.spec"
MAN_SRC="$PKG/man/bifrost-gui.1"
MAINTENEUR="Bifrost <security@inaricom.com>"

ECHECS=0
ok()   { printf '  OK    %s\n' "$1"; }
fail() { printf '  ECHEC %s\n' "$1"; ECHECS=$((ECHECS + 1)); }
step() { printf '\n== %s\n' "$1"; }

for outil in dpkg-deb dpkg-shlibdeps fakeroot strip gzip tar cmp; do
  command -v "$outil" >/dev/null 2>&1 || { echo "outil requis absent: $outil"; exit 1; }
done

# ------------------------------------------------------------------ sources
VERSION="$(awk '/^\[workspace.package\]/{f=1;next} /^\[/{f=0} f&&/^version[[:space:]]*=/{gsub(/[" ]/,"");sub(/version=/,"");print;exit}' "$RACINE_DEPOT/Cargo.toml")"
[ -n "$VERSION" ] || { echo "version du workspace illisible dans Cargo.toml"; exit 1; }
VERSION_GUI="$(awk '/^\[package\]/{f=1;next} /^\[/{f=0} f&&/^version[[:space:]]*=/{gsub(/[" ]/,"");sub(/version=/,"");print;exit}' "$RACINE_DEPOT/gui/Cargo.toml")"
VERSION_TAURI="$(awk -F'"' '/"version"[[:space:]]*:/{print $4; exit}' "$RACINE_DEPOT/gui/tauri.conf.json")"
[ "$VERSION_GUI" = "$VERSION" ] || { echo "REFUS: gui/Cargo.toml annonce $VERSION_GUI, le workspace $VERSION"; exit 1; }
[ "$VERSION_TAURI" = "$VERSION" ] || { echo "REFUS: gui/tauri.conf.json annonce $VERSION_TAURI, le workspace $VERSION"; exit 1; }
echo "version du workspace: $VERSION (gui/Cargo.toml et gui/tauri.conf.json concordent)"
ID_APP="$(awk -F'"' '/"identifier"[[:space:]]*:/{print $4; exit}' "$RACINE_DEPOT/gui/tauri.conf.json")"
[ -n "$ID_APP" ] || { echo "identifiant illisible dans gui/tauri.conf.json"; exit 1; }
DESKTOP_SRC="$PKG/desktop/$ID_APP.desktop"
echo "identifiant de l'application: $ID_APP"

for f in "$CONTROL_SRC" "$COPYRIGHT_SRC" "$SPEC_SRC" "$MAN_SRC" "$DESKTOP_SRC"; do
  [ -f "$f" ] || { echo "fichier de packaging/ introuvable: $f"; exit 1; }
done
[ -x "$GUI_BIN/bifrost-gui" ] || {
  echo "binaire introuvable: $GUI_BIN/bifrost-gui"
  echo "  (cargo build --release --manifest-path gui/Cargo.toml --locked, la ou les paquets -dev de WebKitGTK sont poses)"
  exit 1
}
[ -x "$BIN/bifrost-icone" ] || { echo "binaire introuvable: $BIN/bifrost-icone (cargo build --release --locked -p bifrost-icone)"; exit 1; }
if [ -e "$SORTIE" ] && [ -n "$(ls -A "$SORTIE")" ]; then
  echo "le repertoire de sortie n'est pas vide: $SORTIE (en donner un neuf)"
  exit 1
fi
mkdir -p "$SORTIE"

# ------------------------------------------------------------------ .deb
step "Icones (bifrost-icone)"
# bifrost-icone <repertoire> ecrit bifrost-<cote>.png pour chaque cote de
# COTES_HICOLOR, bifrost.ico et les PNG du tray, et imprime chaque chemin.
ICONES="$SORTIE/icones"
mkdir -p "$ICONES"
ECRITES="$("$BIN/bifrost-icone" "$ICONES")"
sed 's/^/    /' <<< "$ECRITES"

step "Arbre du .deb"
ARBRE="$SORTIE/arbre-deb"
install -D -m 0755 "$GUI_BIN/bifrost-gui" "$ARBRE/usr/bin/bifrost-gui"
install -D -m 0644 "$DESKTOP_SRC" "$ARBRE/usr/share/applications/$ID_APP.desktop"
install -D -m 0644 "$COPYRIGHT_SRC" "$ARBRE/usr/share/doc/bifrost-gui/copyright"
install -D -m 0644 "$MAN_SRC" "$ARBRE/usr/share/man/man1/bifrost-gui.1"
gzip -9n "$ARBRE/usr/share/man/man1/bifrost-gui.1"
# Une icone hicolor par bifrost-<cote>.png ecrit, le cote lu dans le nom; le
# .ico et les PNG du tray n'en sont pas.
ICONES_POSEES=()
while IFS= read -r png; do
  nom="$(basename "$png")"
  cote="${nom#bifrost-}"
  cote="${cote%.png}"
  case "$cote" in ''|*[!0-9]*) continue ;; esac
  install -D -m 0644 "$png" "$ARBRE/usr/share/icons/hicolor/${cote}x${cote}/apps/$ID_APP.png"
  ICONES_POSEES+=("./usr/share/icons/hicolor/${cote}x${cote}/apps/$ID_APP.png")
done <<< "$ECRITES"
[ "${#ICONES_POSEES[@]}" -gt 0 ] || { echo "bifrost-icone n'a ecrit aucun bifrost-<cote>.png"; exit 1; }
# Le changelog est engendre (lintian: no-changelog), date par SOURCE_DATE_EPOCH
# s'il est pose, par l'horloge sinon; gzip -9n, sans horodatage.
if [ -n "${SOURCE_DATE_EPOCH:-}" ]; then
  DATE_CL="$(LC_ALL=C date -u -d "@$SOURCE_DATE_EPOCH" '+%a, %d %b %Y %H:%M:%S +0000')"
else
  DATE_CL="$(LC_ALL=C date -u '+%a, %d %b %Y %H:%M:%S +0000')"
fi
printf 'bifrost-gui (%s) unstable; urgency=medium\n\n  * Paquet de la coquille graphique de Bifrost.\n\n -- %s  %s\n' \
  "$VERSION" "$MAINTENEUR" "$DATE_CL" > "$ARBRE/usr/share/doc/bifrost-gui/changelog"
gzip -9n "$ARBRE/usr/share/doc/bifrost-gui/changelog"
# Aucun script du mainteneur: ni service, ni compte, ni pare-feu. Le cache
# d'icones et la base des entrees de bureau sont mis a jour par les
# declencheurs de leurs propres paquets.
mkdir -p "$ARBRE/DEBIAN"
ok "arbre assemble (${#ICONES_POSEES[@]} icones hicolor)"

step "Strip de la copie du binaire (jamais celui de $GUI_BIN)"
avant="$(stat -c '%s' "$ARBRE/usr/bin/bifrost-gui")"
strip --strip-unneeded "$ARBRE/usr/bin/bifrost-gui"
apres="$(stat -c '%s' "$ARBRE/usr/bin/bifrost-gui")"
ok "bifrost-gui: $avant -> $apres octets"

step "Dependances des bibliotheques liees (dpkg-shlibdeps)"
SHLIBS_REP="$SORTIE/shlibs"
mkdir -p "$SHLIBS_REP/debian"
printf 'Source: bifrost-gui\n\nPackage: bifrost-gui\nArchitecture: amd64\n' > "$SHLIBS_REP/debian/control"
set +e
SHLIBS_SORTIE="$(cd "$SHLIBS_REP" && dpkg-shlibdeps -O "$ARBRE/usr/bin/bifrost-gui")"
SHLIBS_CODE=$?
set -e
[ "$SHLIBS_CODE" -eq 0 ] || { echo "dpkg-shlibdeps a echoue (code $SHLIBS_CODE)"; exit 1; }
SHLIBS="$(sed -n 's/^shlibs:Depends=//p' <<< "$SHLIBS_SORTIE")"
[ -n "$SHLIBS" ] || { echo "dpkg-shlibdeps n'a rendu aucune dependance"; exit 1; }
ok "shlibs:Depends=$SHLIBS"

step "Bibliotheque chargee a l'execution (dlopen)"
# dpkg-shlibdeps ne voit que les bibliotheques liees. La zone de notification
# passe par tray-icon et libappindicator-sys (gui/Cargo.lock), qui ouvre
# libayatana-appindicator3.so.1 par dlopen, a defaut libappindicator3.so.1, et
# panique s'il ne trouve ni l'une ni l'autre. Le paquet est retenu si le soname
# est dans le binaire (une chaine que strip laisse); absent, cette table ne
# correspond plus a la coquille, et le script refuse.
DLOPEN_SONAME="libayatana-appindicator3.so.1"
DLOPEN="libayatana-appindicator3-1"
if grep -a -F "$DLOPEN_SONAME" "$ARBRE/usr/bin/bifrost-gui" >/dev/null; then
  ok "$DLOPEN_SONAME dans le binaire: $DLOPEN retenu"
else
  echo "REFUS: $DLOPEN_SONAME absent du binaire: la table dlopen de ce script ne correspond plus a la coquille"
  exit 1
fi

CONTROL="$(cat "$CONTROL_SRC")"
CONTROL="${CONTROL//@VERSION@/$VERSION}"
CONTROL="${CONTROL//@SHLIBS@/$SHLIBS}"
CONTROL="${CONTROL//@DLOPEN@/$DLOPEN}"
printf '%s\n' "$CONTROL" > "$ARBRE/DEBIAN/control"

step "Construction du .deb (fakeroot dpkg-deb)"
DEB="$SORTIE/bifrost-gui_${VERSION}_amd64.deb"
export ARBRE DEB
fakeroot sh -c 'chown -R root:root "$ARBRE" && dpkg-deb --root-owner-group --build "$ARBRE" "$DEB"'
ok "$DEB"

step "Verification du .deb"
CONTENU="$(dpkg-deb --contents "$DEB")"
echo "-- dpkg-deb --info --"
dpkg-deb --info "$DEB" | sed 's/^/    /'
echo "-- dpkg-deb --contents --"
sed 's/^/    /' <<< "$CONTENU"

champ() {
  local nom="$1" attendu="$2" lu
  lu="$(dpkg-deb -f "$DEB" "$nom")"
  if [ "$lu" = "$attendu" ]; then ok "$nom: $lu"; else fail "$nom: $lu (attendu $attendu)"; fi
}
champ Package bifrost-gui
champ Version "$VERSION"
champ Architecture amd64
champ Maintainer "$MAINTENEUR"
champ Depends "$SHLIBS, $DLOPEN, hicolor-icon-theme"
champ Recommends bifrost

verifier() {
  local chemin="$1" droits="$2" ligne lu proprio
  ligne="$(awk -v c="$chemin" '$NF == c {print}' <<< "$CONTENU")"
  [ -n "$ligne" ] || { fail "$chemin absent du .deb"; return; }
  lu="$(awk '{print $1}' <<< "$ligne")"
  proprio="$(awk '{print $2}' <<< "$ligne")"
  if [ "$lu" = "$droits" ] && [ "$proprio" = "root/root" ]; then
    ok "$chemin: $lu $proprio"
  else
    fail "$chemin: $lu $proprio (attendu $droits root/root)"
  fi
}
verifier ./usr/bin/bifrost-gui -rwxr-xr-x
verifier "./usr/share/applications/$ID_APP.desktop" -rw-r--r--
verifier ./usr/share/doc/bifrost-gui/changelog.gz -rw-r--r--
verifier ./usr/share/doc/bifrost-gui/copyright -rw-r--r--
verifier ./usr/share/man/man1/bifrost-gui.1.gz -rw-r--r--
for icone in "${ICONES_POSEES[@]}"; do
  verifier "$icone" -rw-r--r--
done

DIRS_PROPRIO="$(awk '$1 ~ /^d/ && $2 != "root/root" {print $NF}' <<< "$CONTENU")"
[ -z "$DIRS_PROPRIO" ] && ok "chaque repertoire du .deb est a root/root" \
  || fail "repertoires hors root/root: $DIRS_PROPRIO"

ATTENDUS="$( { printf '%s\n' \
  ./usr/bin/bifrost-gui \
  "./usr/share/applications/$ID_APP.desktop" \
  ./usr/share/doc/bifrost-gui/changelog.gz \
  ./usr/share/doc/bifrost-gui/copyright \
  ./usr/share/man/man1/bifrost-gui.1.gz
  printf '%s\n' "${ICONES_POSEES[@]}"; } | sort)"
REELS="$(awk '$1 !~ /^d/ {print $NF}' <<< "$CONTENU" | sort)"
if [ "$ATTENDUS" = "$REELS" ]; then
  ok "aucun fichier inattendu dans le .deb"
else
  fail "les fichiers du .deb ne sont pas ceux attendus"
  echo "    attendus:"; sed 's/^/      /' <<< "$ATTENDUS"
  echo "    lus:";      sed 's/^/      /' <<< "$REELS"
fi
if grep -F 'autostart' >/dev/null <<< "$REELS"; then
  fail "le .deb pose une entree de demarrage de session (autostart)"
else
  ok "aucune entree de demarrage de session"
fi

EXTRAIT="$SORTIE/extrait"
mkdir -p "$EXTRAIT"
dpkg-deb --fsys-tarfile "$DEB" | tar -xOf - "./usr/share/applications/$ID_APP.desktop" > "$EXTRAIT/$ID_APP.desktop"
if cmp -s "$EXTRAIT/$ID_APP.desktop" "$DESKTOP_SRC"; then
  ok "entree de bureau identique a packaging/desktop/$ID_APP.desktop"
else
  fail "entree de bureau differente de sa source"
fi
dpkg-deb --fsys-tarfile "$DEB" | tar -xOf - ./usr/share/man/man1/bifrost-gui.1.gz > "$EXTRAIT/bifrost-gui.1.gz"
gzip -dc "$EXTRAIT/bifrost-gui.1.gz" > "$EXTRAIT/bifrost-gui.1"
if cmp -s "$EXTRAIT/bifrost-gui.1" "$MAN_SRC"; then
  ok "page bifrost-gui.1 identique a sa source"
else
  fail "page bifrost-gui.1 differe de sa source"
fi
CONTROLE="$(dpkg-deb --ctrl-tarfile "$DEB" | tar -tf -)"
SCRIPTS_MAINTENEUR="$(grep -E '(preinst|postinst|prerm|postrm|conffiles)$' <<< "$CONTROLE" || true)"
[ -z "$SCRIPTS_MAINTENEUR" ] && ok "aucun script du mainteneur, aucun conffile" \
  || fail "fichiers de controle inattendus: $SCRIPTS_MAINTENEUR"

step "Entree de bureau (desktop-file-validate)"
if command -v desktop-file-validate >/dev/null 2>&1; then
  set +e
  DFV="$(desktop-file-validate "$DESKTOP_SRC" 2>&1)"
  DFV_CODE=$?
  set -e
  if [ -z "$DFV" ] && [ "$DFV_CODE" -eq 0 ]; then
    ok "desktop-file-validate: muet, code 0"
  else
    sed 's/^/    /' <<< "$DFV"
    fail "desktop-file-validate: code $DFV_CODE"
  fi
else
  echo "  SKIPPED: desktop-file-validate absent"
fi

step "Page de manuel (man --warnings)"
if command -v man >/dev/null 2>&1; then
  avert="$(LC_ALL=C.UTF-8 MANROFFSEQ='' MANWIDTH=80 man --warnings -E UTF-8 -l -Tutf8 -Z "$MAN_SRC" 2>&1 >/dev/null || true)"
  if [ -n "$avert" ]; then
    fail "man --warnings sur bifrost-gui.1: $avert"
  else
    ok "bifrost-gui.1: aucun avertissement"
  fi
else
  echo "  SKIPPED: man absent, la page n'est pas rendue ici"
fi

step "lintian"
if command -v lintian >/dev/null 2>&1; then
  set +e
  LINTIAN="$(lintian "$DEB" 2>&1)"
  LINTIAN_CODE=$?
  set -e
  sed 's/^/    /' <<< "$LINTIAN"
  if grep '^E:' >/dev/null <<< "$LINTIAN"; then
    fail "lintian: au moins une erreur (E:)"
  elif [ "$LINTIAN_CODE" -ne 0 ]; then
    fail "lintian: code $LINTIAN_CODE sans ligne E:"
  else
    ok "lintian: aucune erreur, code 0"
  fi
else
  echo "  SKIPPED: lintian absent"
fi

# ------------------------------------------------------------------ .rpm
step "Construction du .rpm (rpmbuild)"
if command -v rpmbuild >/dev/null 2>&1; then
  TOP="$SORTIE/rpmbuild"
  mkdir -p "$TOP/SPECS" "$TOP/BUILD" "$TOP/RPMS" "$TOP/BUILDROOT"
  SPEC="$(cat "$SPEC_SRC")"
  printf '%s\n' "${SPEC//@VERSION@/$VERSION}" > "$TOP/SPECS/bifrost-gui.spec"
  # Pas d'extraction de debuginfo sur un binaire deja construit.
  rpmbuild -bb \
    --define "_topdir $TOP" \
    --define "debug_package %{nil}" \
    --define "gui_bindir $GUI_BIN" \
    --define "pkg_source $PKG" \
    --define "icones_source $ICONES" \
    "$TOP/SPECS/bifrost-gui.spec"
  RPM_CONSTRUIT="$(find "$TOP/RPMS" -name '*.rpm' | sed -n 1p)"
  [ -n "$RPM_CONSTRUIT" ] || { echo "rpmbuild n'a produit aucun .rpm"; exit 1; }
  cp "$RPM_CONSTRUIT" "$SORTIE/"
  RPM="$SORTIE/$(basename "$RPM_CONSTRUIT")"
  ok "$RPM"
  echo "-- rpm -qip --"
  rpm -qip "$RPM" | sed 's/^/    /'
  LISTE_RPM="$(rpm -qlvp "$RPM")"
  echo "-- rpm -qlvp --"
  sed 's/^/    /' <<< "$LISTE_RPM"
  for entree in \
    "-rwxr-xr-x /usr/bin/bifrost-gui" \
    "-rw-r--r-- /usr/share/applications/$ID_APP.desktop" \
    "-rw-r--r-- /usr/share/icons/hicolor/16x16/apps/$ID_APP.png" \
    "-rw-r--r-- /usr/share/icons/hicolor/256x256/apps/$ID_APP.png"; do
    droits="${entree%% *}"
    chemin="${entree#* }"
    ligne="$(awk -v c="$chemin" '$NF == c {print $1, $3, $4}' <<< "$LISTE_RPM")"
    if [ "$ligne" = "$droits root root" ]; then
      ok "rpm $chemin: $ligne"
    else
      fail "rpm $chemin: [$ligne] (attendu $droits root root)"
    fi
  done
  REQUIS_RPM="$(rpm -qp --requires "$RPM")"
  echo "-- rpm -qp --requires --"
  sed 's/^/    /' <<< "$REQUIS_RPM"
  if grep -F "$DLOPEN_SONAME" >/dev/null <<< "$REQUIS_RPM"; then
    ok "le .rpm requiert $DLOPEN_SONAME"
  else
    fail "le .rpm ne requiert pas $DLOPEN_SONAME"
  fi
  SCRIPTS_RPM="$(rpm -qp --scripts "$RPM")"
  [ -z "$SCRIPTS_RPM" ] && ok "aucun scriptlet dans le .rpm" || fail "scriptlets dans le .rpm: $SCRIPTS_RPM"
else
  echo "  SKIPPED: rpmbuild absent, le .rpm n'est pas construit ici"
fi

echo
if [ "$ECHECS" -eq 0 ]; then
  echo "paquets Linux de la coquille: tout est passe (sortie: $SORTIE)"
else
  echo "paquets Linux de la coquille: $ECHECS controle(s) en echec"
  exit 1
fi
