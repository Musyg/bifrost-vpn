#!/usr/bin/env bash
# Construit et verifie les paquets Linux de Bifrost: le .deb, et le .rpm la ou
# rpmbuild existe.
#
# Dans l'ordre:
#   1. lit la version du workspace (Cargo.toml, [workspace.package]);
#   2. assemble l'arbre du .deb avec les fichiers de packaging/ tels quels (les
#      memes que pose packaging/install-linux.sh), strippe les copies des
#      binaires, mesure les dependances des bibliotheques liees par
#      dpkg-shlibdeps, injecte version et dependances dans le control, et
#      construit le paquet par fakeroot dpkg-deb, tout en root:root;
#   3. verifie le .deb: champs, modes et proprietaires de chaque fichier, unite,
#      hook et declaration des comptes identiques octet pour octet a leur
#      source, scripts du mainteneur identiques et en 0755, aucun fichier
#      inattendu; puis man --warnings et lintian s'ils sont la;
#   4. construit le .rpm par rpmbuild s'il est la, sinon le dit (SKIPPED), et
#      en lit les fichiers, les modes et les scriptlets.
#
# N'installe rien et ne demande pas root: fakeroot suffit. Aucun depot de
# paquets n'est construit.
#
# La sortie doit etre neuve: ce script refuse un repertoire de sortie qui n'est
# pas vide, plutot que d'y melanger deux constructions. Les arbres de travail y
# restent (arbre-deb, rpmbuild), a cote des paquets.
#
# Usage: ./scripts/paquets-linux.sh [REPERTOIRE_BINAIRES] [REPERTOIRE_SORTIE]
#   REPERTOIRE_BINAIRES: defaut target/release
#   REPERTOIRE_SORTIE:   defaut target/paquets
set -euo pipefail

RACINE_DEPOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${1:-$RACINE_DEPOT/target/release}"
SORTIE="${2:-$RACINE_DEPOT/target/paquets}"

PKG="$RACINE_DEPOT/packaging"
UNITE_SRC="$PKG/systemd/bifrost-daemon.service"
HOOK_SRC="$PKG/systemd/system-sleep/bifrost-reprise"
SYSUSERS_SRC="$PKG/sysusers.d/bifrost.conf"
CONTROL_SRC="$PKG/deb/control"
COPYRIGHT_SRC="$PKG/deb/copyright"
SPEC_SRC="$PKG/rpm/bifrost.spec"
MAN_DAEMON_SRC="$PKG/man/bifrost-daemon.1"
MAN_CLI_SRC="$PKG/man/bifrost-cli.1"
MAINTENEUR="Bifrost <security@inaricom.com>"

ECHECS=0
ok()   { printf '  OK    %s\n' "$1"; }
fail() { printf '  ECHEC %s\n' "$1"; ECHECS=$((ECHECS + 1)); }
info() { printf '  ..    %s\n' "$1"; }
step() { printf '\n== %s\n' "$1"; }

for outil in dpkg-deb dpkg-shlibdeps fakeroot strip gzip tar cmp; do
  command -v "$outil" >/dev/null 2>&1 || { echo "outil requis absent: $outil"; exit 1; }
done
for f in "$UNITE_SRC" "$HOOK_SRC" "$SYSUSERS_SRC" "$CONTROL_SRC" "$COPYRIGHT_SRC" \
         "$SPEC_SRC" "$MAN_DAEMON_SRC" "$MAN_CLI_SRC" \
         "$PKG/deb/postinst" "$PKG/deb/prerm" "$PKG/deb/postrm"; do
  [ -f "$f" ] || { echo "fichier de packaging/ introuvable: $f"; exit 1; }
done
for b in bifrost-daemon bifrost-cli; do
  [ -x "$BIN/$b" ] || { echo "binaire introuvable: $BIN/$b (cargo build --release -p bifrost-daemon -p bifrost-cli --locked)"; exit 1; }
done
if [ -e "$SORTIE" ] && [ -n "$(ls -A "$SORTIE")" ]; then
  echo "le repertoire de sortie n'est pas vide: $SORTIE (en donner un neuf)"
  exit 1
fi
mkdir -p "$SORTIE"

VERSION="$(awk '/^\[workspace.package\]/{f=1;next} /^\[/{f=0} f&&/^version[[:space:]]*=/{gsub(/[" ]/,"");sub(/version=/,"");print;exit}' "$RACINE_DEPOT/Cargo.toml")"
[ -n "$VERSION" ] || { echo "version du workspace illisible dans Cargo.toml"; exit 1; }
echo "version du workspace: $VERSION"

# --------------------------------------------------------------------- .deb
step "Arbre du .deb"
ARBRE="$SORTIE/arbre-deb"
# Memes destinations et memes modes que packaging/install-linux.sh, sauf
# l'unite: un paquet la pose sous /usr/lib/systemd/system, l'installateur sous
# /etc/systemd/system, qui appartient a l'administrateur. Meme fichier.
install -D -m 0755 "$BIN/bifrost-daemon" "$ARBRE/usr/bin/bifrost-daemon"
install -D -m 0755 "$BIN/bifrost-cli" "$ARBRE/usr/bin/bifrost-cli"
install -D -m 0644 "$UNITE_SRC" "$ARBRE/usr/lib/systemd/system/bifrost-daemon.service"
install -D -m 0755 "$HOOK_SRC" "$ARBRE/usr/lib/systemd/system-sleep/bifrost-reprise"
install -D -m 0644 "$SYSUSERS_SRC" "$ARBRE/usr/lib/sysusers.d/bifrost.conf"
install -D -m 0644 "$COPYRIGHT_SRC" "$ARBRE/usr/share/doc/bifrost/copyright"
# Le changelog est engendre (lintian: no-changelog). Paquet natif (version sans
# revision Debian): changelog.gz. La date vient de SOURCE_DATE_EPOCH s'il est
# pose, de l'horloge sinon; gzip -9n: compression maximale, sans horodatage.
if [ -n "${SOURCE_DATE_EPOCH:-}" ]; then
  DATE_CL="$(LC_ALL=C date -u -d "@$SOURCE_DATE_EPOCH" '+%a, %d %b %Y %H:%M:%S +0000')"
else
  DATE_CL="$(LC_ALL=C date -u '+%a, %d %b %Y %H:%M:%S +0000')"
fi
printf 'bifrost (%s) unstable; urgency=medium\n\n  * Paquet du daemon Bifrost et de son client en ligne de commande.\n\n -- %s  %s\n' \
  "$VERSION" "$MAINTENEUR" "$DATE_CL" > "$ARBRE/usr/share/doc/bifrost/changelog"
gzip -9n "$ARBRE/usr/share/doc/bifrost/changelog"
install -D -m 0644 "$MAN_DAEMON_SRC" "$ARBRE/usr/share/man/man1/bifrost-daemon.1"
install -D -m 0644 "$MAN_CLI_SRC" "$ARBRE/usr/share/man/man1/bifrost-cli.1"
gzip -9n "$ARBRE/usr/share/man/man1/bifrost-daemon.1"
gzip -9n "$ARBRE/usr/share/man/man1/bifrost-cli.1"
mkdir -p "$ARBRE/DEBIAN"
for script in postinst prerm postrm; do
  install -m 0755 "$PKG/deb/$script" "$ARBRE/DEBIAN/$script"
done
ok "arbre assemble"

step "Strip des copies des binaires (jamais ceux de $BIN)"
for b in bifrost-daemon bifrost-cli; do
  avant="$(stat -c '%s' "$ARBRE/usr/bin/$b")"
  strip --strip-unneeded "$ARBRE/usr/bin/$b"
  apres="$(stat -c '%s' "$ARBRE/usr/bin/$b")"
  ok "$b: $avant -> $apres octets"
done

step "Dependances des bibliotheques liees (dpkg-shlibdeps)"
# dpkg-shlibdeps lit debian/control dans le repertoire courant: un control
# minimal, dans un repertoire a lui.
SHLIBS_REP="$SORTIE/shlibs"
mkdir -p "$SHLIBS_REP/debian"
printf 'Source: bifrost\n\nPackage: bifrost\nArchitecture: amd64\n' > "$SHLIBS_REP/debian/control"
set +e
SHLIBS_SORTIE="$(cd "$SHLIBS_REP" && dpkg-shlibdeps -O "$ARBRE/usr/bin/bifrost-daemon" "$ARBRE/usr/bin/bifrost-cli")"
SHLIBS_CODE=$?
set -e
[ "$SHLIBS_CODE" -eq 0 ] || { echo "dpkg-shlibdeps a echoue (code $SHLIBS_CODE)"; exit 1; }
SHLIBS="$(sed -n 's/^shlibs:Depends=//p' <<< "$SHLIBS_SORTIE")"
[ -n "$SHLIBS" ] || { echo "dpkg-shlibdeps n'a rendu aucune dependance"; exit 1; }
ok "shlibs:Depends=$SHLIBS"

CONTROL="$(cat "$CONTROL_SRC")"
CONTROL="${CONTROL//@VERSION@/$VERSION}"
CONTROL="${CONTROL//@SHLIBS@/$SHLIBS}"
printf '%s\n' "$CONTROL" > "$ARBRE/DEBIAN/control"

step "Construction du .deb (fakeroot dpkg-deb)"
DEB="$SORTIE/bifrost_${VERSION}_amd64.deb"
export ARBRE DEB
# chown et construction dans la meme session fakeroot: sinon dpkg-deb lirait le
# proprietaire reel des fichiers.
fakeroot sh -c 'chown -R root:root "$ARBRE" && dpkg-deb --root-owner-group --build "$ARBRE" "$DEB"'
ok "$DEB"

step "Verification du .deb"
# --contents capture une fois, relu par here-string: aucun tube ferme tot.
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
champ Package bifrost
champ Version "$VERSION"
champ Architecture amd64
champ Maintainer "$MAINTENEUR"
champ Depends "$SHLIBS, systemd, nftables"

# Une ligne de --contents: <droits> <proprietaire/groupe> <taille> <date> <heure> <chemin>
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
verifier ./usr/bin/bifrost-daemon -rwxr-xr-x
verifier ./usr/bin/bifrost-cli -rwxr-xr-x
verifier ./usr/lib/systemd/system/bifrost-daemon.service -rw-r--r--
verifier ./usr/lib/systemd/system-sleep/bifrost-reprise -rwxr-xr-x
verifier ./usr/lib/sysusers.d/bifrost.conf -rw-r--r--
verifier ./usr/share/doc/bifrost/changelog.gz -rw-r--r--
verifier ./usr/share/doc/bifrost/copyright -rw-r--r--
verifier ./usr/share/man/man1/bifrost-daemon.1.gz -rw-r--r--
verifier ./usr/share/man/man1/bifrost-cli.1.gz -rw-r--r--

DIRS_PROPRIO="$(awk '$1 ~ /^d/ && $2 != "root/root" {print $NF}' <<< "$CONTENU")"
[ -z "$DIRS_PROPRIO" ] && ok "chaque repertoire du .deb est a root/root" \
  || fail "repertoires hors root/root: $DIRS_PROPRIO"

ATTENDUS="$(printf '%s\n' \
  ./usr/bin/bifrost-daemon \
  ./usr/bin/bifrost-cli \
  ./usr/lib/systemd/system/bifrost-daemon.service \
  ./usr/lib/systemd/system-sleep/bifrost-reprise \
  ./usr/lib/sysusers.d/bifrost.conf \
  ./usr/share/doc/bifrost/changelog.gz \
  ./usr/share/doc/bifrost/copyright \
  ./usr/share/man/man1/bifrost-daemon.1.gz \
  ./usr/share/man/man1/bifrost-cli.1.gz | sort)"
REELS="$(awk '$1 !~ /^d/ {print $NF}' <<< "$CONTENU" | sort)"
if [ "$ATTENDUS" = "$REELS" ]; then
  ok "aucun fichier inattendu dans le .deb"
else
  fail "les fichiers du .deb ne sont pas ceux attendus"
  echo "    attendus:"; sed 's/^/      /' <<< "$ATTENDUS"
  echo "    lus:";      sed 's/^/      /' <<< "$REELS"
fi

# Les fichiers que pose aussi install-linux.sh, identiques a leur source.
EXTRAIT="$SORTIE/extrait"
mkdir -p "$EXTRAIT"
identique() {
  local membre="$1" source="$2" nom
  nom="$(basename "$membre")"
  dpkg-deb --fsys-tarfile "$DEB" | tar -xOf - "$membre" > "$EXTRAIT/$nom"
  if cmp -s "$EXTRAIT/$nom" "$source"; then
    ok "$membre identique a ${source#"$RACINE_DEPOT"/}"
  else
    fail "$membre differe de ${source#"$RACINE_DEPOT"/}"
  fi
}
identique ./usr/lib/systemd/system/bifrost-daemon.service "$UNITE_SRC"
identique ./usr/lib/systemd/system-sleep/bifrost-reprise "$HOOK_SRC"
identique ./usr/lib/sysusers.d/bifrost.conf "$SYSUSERS_SRC"
for page in bifrost-daemon bifrost-cli; do
  dpkg-deb --fsys-tarfile "$DEB" | tar -xOf - "./usr/share/man/man1/$page.1.gz" > "$EXTRAIT/$page.1.gz"
  gzip -dc "$EXTRAIT/$page.1.gz" > "$EXTRAIT/$page.1"
  if cmp -s "$EXTRAIT/$page.1" "$PKG/man/$page.1"; then
    ok "page $page.1 identique a sa source"
  else
    fail "page $page.1 differe de sa source"
  fi
done

# Les scripts du mainteneur: 0755, identiques a packaging/deb/.
CONTROLE="$(dpkg-deb --ctrl-tarfile "$DEB" | tar -tvf -)"
for script in postinst prerm postrm; do
  droits="$(awk -v c="./$script" '$NF == c {print $1}' <<< "$CONTROLE")"
  dpkg-deb --ctrl-tarfile "$DEB" | tar -xOf - "./$script" > "$EXTRAIT/$script"
  if [ "$droits" = "-rwxr-xr-x" ] && cmp -s "$EXTRAIT/$script" "$PKG/deb/$script"; then
    ok "$script: $droits, identique a packaging/deb/$script"
  else
    fail "$script: droits [$droits] ou contenu different de packaging/deb/$script"
  fi
done

step "Pages de manuel (man --warnings)"
# La commande que lintian lance pour manpage-has-errors-from-man.
if command -v man >/dev/null 2>&1; then
  for page in "$MAN_DAEMON_SRC" "$MAN_CLI_SRC"; do
    avert="$(LC_ALL=C.UTF-8 MANROFFSEQ='' MANWIDTH=80 man --warnings -E UTF-8 -l -Tutf8 -Z "$page" 2>&1 >/dev/null || true)"
    if [ -n "$avert" ]; then
      fail "man --warnings sur $(basename "$page"): $avert"
    else
      ok "$(basename "$page"): aucun avertissement"
    fi
  done
else
  echo "  SKIPPED: man absent, les pages ne sont pas rendues ici"
fi

step "lintian"
if command -v lintian >/dev/null 2>&1; then
  # Une erreur (E:) ou un code non nul font echouer; les avertissements (W:)
  # sont imprimes.
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

# --------------------------------------------------------------------- .rpm
step "Construction du .rpm (rpmbuild)"
if command -v rpmbuild >/dev/null 2>&1; then
  TOP="$SORTIE/rpmbuild"
  mkdir -p "$TOP/SPECS" "$TOP/BUILD" "$TOP/RPMS" "$TOP/BUILDROOT"
  SPEC="$(cat "$SPEC_SRC")"
  printf '%s\n' "${SPEC//@VERSION@/$VERSION}" > "$TOP/SPECS/bifrost.spec"
  # Pas d'extraction de debuginfo sur des binaires deja construits.
  rpmbuild -bb \
    --define "_topdir $TOP" \
    --define "debug_package %{nil}" \
    --define "bindir_source $BIN" \
    --define "pkg_source $PKG" \
    "$TOP/SPECS/bifrost.spec"
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
    "-rwxr-xr-x /usr/bin/bifrost-daemon" \
    "-rwxr-xr-x /usr/bin/bifrost-cli" \
    "-rw-r--r-- /usr/lib/systemd/system/bifrost-daemon.service" \
    "-rwxr-xr-x /usr/lib/systemd/system-sleep/bifrost-reprise" \
    "-rw-r--r-- /usr/lib/sysusers.d/bifrost.conf"; do
    droits="${entree%% *}"
    chemin="${entree#* }"
    ligne="$(awk -v c="$chemin" '$NF == c {print $1, $3, $4}' <<< "$LISTE_RPM")"
    if [ "$ligne" = "$droits root root" ]; then
      ok "rpm $chemin: $ligne"
    else
      fail "rpm $chemin: [$ligne] (attendu $droits root root)"
    fi
  done
  echo "-- rpm -qp --scripts --"
  rpm -qp --scripts "$RPM" | sed 's/^/    /'
else
  echo "  SKIPPED: rpmbuild absent, le .rpm n'est pas construit ici"
fi

echo
if [ "$ECHECS" -eq 0 ]; then
  echo "paquets Linux: tout est passe (sortie: $SORTIE)"
else
  echo "paquets Linux: $ECHECS controle(s) en echec"
  exit 1
fi
