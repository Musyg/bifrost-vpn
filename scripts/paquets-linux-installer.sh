#!/usr/bin/env bash
# Installation et retrait REELS du .deb de Bifrost. Runner jetable seulement.
#
# Ce script modifie la machine: il installe le paquet, cree ses comptes,
# demarre puis arrete le service, retire et purge le paquet. Il refuse de
# tourner sans BIFROST_RUNNER_JETABLE=1, que seul le job paquets-linux de la CI
# pose, sur un runner jetable.
#
# Ce qu'il mesure, dans l'ordre (OK ou ECHEC par controle, sortie au premier
# ECHEC, journal du service en cas d'echec):
#   1. avant: aucune table nft bifrost, route par defaut relevee;
#   2. apt-get install: le service n'est NI active NI demarre (le parti pris de
#      packaging/install-linux.sh), l'unite, le hook, la declaration et les
#      pages sont en place, les comptes sont ceux de la declaration (groupe
#      bifrost, comptes systeme bifrost-coeur et bifrost-resolveur, sans
#      connexion, hors du groupe, uid distincts);
#   3. le refus de l'installateur, rejoue: un compte de service ajoute au groupe
#      bifrost fait echouer la configuration, retire il la laisse passer;
#   4. l'administrateur active et demarre le service: il tourne, n'arme rien sans
#      profil (aucune table nft, route inchangee);
#   5. apt-get remove: le service est arrete et desactive (aucun lien laisse
#      vers une unite retiree), unite, binaires et pages retires, aucune table
#      nft;
#   6. apt-get purge: /var/lib/bifrost retire s'il est vide, garde et nomme
#      sinon; comptes conserves;
#   7. le .rpm, s'il a ete construit, est lu (fichiers, scriptlets) mais pas
#      installe: la base du runner est Debian.
#
# Usage: sudo BIFROST_RUNNER_JETABLE=1 ./scripts/paquets-linux-installer.sh [REPERTOIRE_PAQUETS]
set -uo pipefail

RACINE_DEPOT="$(cd "$(dirname "$0")/.." && pwd)"
PAQUETS="${1:-$RACINE_DEPOT/target/paquets}"

if [ "${BIFROST_RUNNER_JETABLE:-}" != "1" ]; then
  echo "REFUS: ce script installe et retire un paquet et cree des comptes systeme." >&2
  echo "       Il ne tourne que sur un runner jetable, BIFROST_RUNNER_JETABLE=1 pose." >&2
  exit 1
fi
[ "$(id -u)" -eq 0 ] || { echo "REFUS: ce script doit tourner en root (apt-get, systemctl)." >&2; exit 1; }

export DEBIAN_FRONTEND=noninteractive

ok()   { printf '  OK    %s\n' "$1"; }
step() { printf '\n== %s\n' "$1"; }
journal() {
  echo "---- journalctl -u bifrost-daemon ----"
  journalctl -u bifrost-daemon --no-pager -n 80 2>/dev/null || echo "(journal indisponible)"
}
echec() { printf '  ECHEC %s\n' "$1"; journal; exit 1; }

DEB="$(ls "$PAQUETS"/bifrost_*_amd64.deb 2>/dev/null | sed -n 1p)"
[ -n "$DEB" ] && [ -f "$DEB" ] || { echo "aucun .deb sous $PAQUETS (scripts/paquets-linux.sh d'abord)"; exit 1; }
echo "paquet: $DEB"

table_bifrost() { command -v nft >/dev/null 2>&1 && nft list table inet bifrost >/dev/null 2>&1; }

# ------------------------------------------------------------------- avant
step "Avant installation"
if dpkg -s bifrost >/dev/null 2>&1; then echec "un paquet bifrost est deja installe"; fi
table_bifrost && echec "une table nft inet bifrost existe deja"
ok "aucune table nft bifrost"
ROUTE_AVANT="$(ip route show default 2>/dev/null || true)"
echo "  route par defaut: ${ROUTE_AVANT:-<aucune>}"

# ----------------------------------------------------------------- install
step "apt-get install"
apt-get install -y "$DEB" || echec "apt-get install a echoue"
ok "paquet installe"

step "Apres installation: rien d'active, rien de demarre"
ACTIVE="$(systemctl is-enabled bifrost-daemon.service 2>&1 || true)"
[ "$ACTIVE" = "disabled" ] && ok "service non active (is-enabled: $ACTIVE)" \
  || echec "service active par le paquet (is-enabled: $ACTIVE)"
ETAT="$(systemctl is-active bifrost-daemon.service 2>&1 || true)"
[ "$ETAT" = "inactive" ] && ok "service non demarre (is-active: $ETAT)" \
  || echec "service demarre par le paquet (is-active: $ETAT)"
table_bifrost && echec "une table nft bifrost a ete posee a l'installation"
ok "aucune table nft bifrost"

step "Fichiers poses"
for chemin in /usr/bin/bifrost-daemon /usr/bin/bifrost-cli /usr/lib/systemd/system-sleep/bifrost-reprise; do
  [ "$(stat -c '%a %U:%G' "$chemin" 2>/dev/null)" = "755 root:root" ] && ok "$chemin 755 root:root" \
    || echec "$chemin: $(stat -c '%a %U:%G' "$chemin" 2>&1)"
done
for chemin in /usr/lib/systemd/system/bifrost-daemon.service /usr/lib/sysusers.d/bifrost.conf \
              /usr/share/man/man1/bifrost-daemon.1.gz /usr/share/man/man1/bifrost-cli.1.gz; do
  [ "$(stat -c '%a %U:%G' "$chemin" 2>/dev/null)" = "644 root:root" ] && ok "$chemin 644 root:root" \
    || echec "$chemin: $(stat -c '%a %U:%G' "$chemin" 2>&1)"
done
cmp -s /usr/lib/systemd/system/bifrost-daemon.service "$RACINE_DEPOT/packaging/systemd/bifrost-daemon.service" \
  && ok "unite installee identique a packaging/systemd/bifrost-daemon.service" \
  || echec "unite installee differente de sa source"
/usr/bin/bifrost-cli --version >/dev/null 2>&1 && ok "bifrost-cli --version" || echec "bifrost-cli ne repond pas"

step "Comptes"
getent group bifrost >/dev/null && ok "groupe bifrost" || echec "groupe bifrost absent"
for compte in bifrost-coeur bifrost-resolveur; do
  ligne="$(getent passwd "$compte")" || echec "compte $compte absent"
  uid="$(cut -d: -f3 <<< "$ligne")"
  maison="$(cut -d: -f6 <<< "$ligne")"
  shell="$(cut -d: -f7 <<< "$ligne")"
  [ "$uid" -lt 1000 ] && ok "$compte: compte systeme (uid $uid)" || echec "$compte: uid $uid hors des comptes systeme"
  [ "$maison" = "/nonexistent" ] && [ "$shell" = "/usr/sbin/nologin" ] && ok "$compte: $maison, $shell" \
    || echec "$compte: maison $maison, shell $shell (attendu /nonexistent, /usr/sbin/nologin)"
  if id -nG "$compte" | tr ' ' '\n' | grep -x bifrost >/dev/null; then
    echec "$compte appartient au groupe bifrost"
  fi
  ok "$compte hors du groupe bifrost"
done
[ "$(id -u bifrost-coeur)" != "$(id -u bifrost-resolveur)" ] && ok "uid du coeur et du resolveur distincts" \
  || echec "bifrost-coeur et bifrost-resolveur partagent un uid"

step "Le refus de l'installateur, rejoue par le paquet"
gpasswd -a bifrost-coeur bifrost >/dev/null || echec "gpasswd -a a echoue"
if dpkg-reconfigure bifrost; then
  echec "la configuration est passee avec bifrost-coeur dans le groupe bifrost"
fi
ok "configuration refusee tant que bifrost-coeur est dans le groupe bifrost"
gpasswd -d bifrost-coeur bifrost >/dev/null || echec "gpasswd -d a echoue"
dpkg-reconfigure bifrost || echec "la configuration echoue apres le retrait du compte"
ok "configuration acceptee une fois le compte retire"
[ "$(systemctl is-enabled bifrost-daemon.service 2>&1 || true)" = "disabled" ] \
  || echec "la reconfiguration a active le service"
ok "toujours non active apres reconfiguration"

step "L'administrateur active et demarre le service"
systemctl enable --now bifrost-daemon.service || echec "systemctl enable --now a echoue"
systemctl is-active --quiet bifrost-daemon.service && ok "service actif" || echec "service inactif apres demarrage"
table_bifrost && echec "une table nft bifrost est posee sans profil"
ok "aucune table nft bifrost sans profil"
ROUTE_APRES="$(ip route show default 2>/dev/null || true)"
[ "$ROUTE_APRES" = "$ROUTE_AVANT" ] && ok "route par defaut inchangee" \
  || echec "route par defaut modifiee: [$ROUTE_AVANT] devenue [$ROUTE_APRES]"

# ------------------------------------------------------------------ remove
step "apt-get remove"
JOURNAL_RETRAIT="$(mktemp)"
apt-get remove -y bifrost 2>&1 | tee "$JOURNAL_RETRAIT"
CODE_RETRAIT="${PIPESTATUS[0]}"
rm -f "$JOURNAL_RETRAIT"
[ "$CODE_RETRAIT" -eq 0 ] || echec "apt-get remove a echoue (code $CODE_RETRAIT)"
ETAT="$(systemctl is-active bifrost-daemon.service 2>&1 || true)"
[ "$ETAT" != "active" ] && ok "service arrete (is-active: $ETAT)" || echec "service encore actif apres remove"
[ ! -e /etc/systemd/system/multi-user.target.wants/bifrost-daemon.service ] \
  && [ ! -L /etc/systemd/system/multi-user.target.wants/bifrost-daemon.service ] \
  && ok "aucun lien d'activation laisse" || echec "lien d'activation laisse apres remove"
for chemin in /usr/lib/systemd/system/bifrost-daemon.service /usr/bin/bifrost-daemon /usr/bin/bifrost-cli \
              /usr/lib/systemd/system-sleep/bifrost-reprise /usr/share/man/man1/bifrost-daemon.1.gz \
              /usr/share/man/man1/bifrost-cli.1.gz; do
  [ ! -e "$chemin" ] && ok "$chemin retire" || echec "$chemin encore present apres remove"
done
table_bifrost && echec "une table nft bifrost subsiste apres remove"
ok "aucune table nft bifrost"

# ------------------------------------------------------------------- purge
step "apt-get purge"
apt-get purge -y bifrost || echec "apt-get purge a echoue"
dpkg -s bifrost >/dev/null 2>&1 && echec "le paquet est encore connu de dpkg apres purge"
ok "paquet purge"
if [ -d /var/lib/bifrost ]; then
  if [ -n "$(ls -A /var/lib/bifrost)" ]; then
    ok "/var/lib/bifrost garde, non vide: $(ls -A /var/lib/bifrost | tr '\n' ' ')"
  else
    echec "/var/lib/bifrost vide et garde par purge"
  fi
else
  ok "/var/lib/bifrost retire (vide)"
fi
getent passwd bifrost-coeur >/dev/null && getent passwd bifrost-resolveur >/dev/null \
  && getent group bifrost >/dev/null && ok "comptes conserves" || echec "un compte a ete retire par purge"

# --------------------------------------------------------------------- rpm
step "Lecture du .rpm (sans installation)"
RPM="$(ls "$PAQUETS"/bifrost-*.rpm 2>/dev/null | sed -n 1p)"
if [ -z "$RPM" ]; then
  echo "  SKIPPED: aucun .rpm sous $PAQUETS (rpmbuild absent a la construction)"
elif ! command -v rpm >/dev/null 2>&1; then
  echo "  SKIPPED: rpm absent, le .rpm n'est pas lu"
else
  SCRIPTS_RPM="$(rpm -qp --scripts "$RPM")"
  sed 's/^/    /' <<< "$SCRIPTS_RPM"
  # En tete de ligne seulement: le message de fin cite la commande a taper.
  if grep -E '^[[:space:]]*systemctl (enable|start|restart|try-restart|reload-or-restart)' >/dev/null <<< "$SCRIPTS_RPM"; then
    echec "un scriptlet du .rpm active ou demarre le service"
  fi
  ok "aucun scriptlet du .rpm n'active ni ne demarre le service (lu, pas installe)"
fi

echo
echo "installation et retrait reels: tout est passe"
