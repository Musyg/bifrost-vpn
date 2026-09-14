#!/usr/bin/env bash
# Installe Bifrost sur un systeme systemd: comptes, binaires, unite.
#
# N'ACTIVE NI NE DEMARRE le service. Poser un kill switch sur une machine coupe
# tout trafic qui ne passe pas par le tunnel, y compris la session SSH depuis
# laquelle on installe. Le demarrage reste donc une decision explicite, prise
# par quelqu'un qui sait ou il se trouve.
#
# Idempotent: relancable sur une installation existante sans rien casser.
#
# Usage: sudo ./packaging/install-linux.sh [chemin/vers/target/release]
#
# Le resolveur chiffre (dnscrypt-proxy) n'est pas dans ce depot: c'est un
# binaire tiers, recupere et verifie separement. Le designer par la variable
# RESOLVEUR pour qu'il soit installe:
#
#   sudo RESOLVEUR=/chemin/vers/dnscrypt-proxy ./packaging/install-linux.sh
#
# Sans elle, tout le reste s'installe et l'unite designe quand meme
# l'emplacement attendu: un profil qui demande `embarque` echouera alors avec
# un message clair, plutot que de se rabattre en silence sur du DNS en clair.

set -euo pipefail

ICI="$(cd "$(dirname "$0")" && pwd)"
BIN="${1:-$(cd "$ICI/.." && pwd)/target/release}"
COMPTE_COEUR=bifrost-coeur
COMPTE_RESOLVEUR=bifrost-resolveur
GROUPE_PILOTAGE=bifrost
# Emplacement du resolveur chiffre. /usr/lib et non /usr/bin: ce binaire n'est
# pas destine a etre appele a la main, il est lance par le daemon. Le chemin
# est en dur dans l'unite, jamais cherche dans le PATH, parce qu'un tiers qui y
# deposerait le sien serait exactement ce qu'un resolveur chiffre evite.
RESOLVEUR_INSTALLE=/usr/lib/bifrost/dnscrypt-proxy
# Le hook de reprise apres veille. /usr/lib et non /etc: systemd lit les deux,
# mais /etc appartient a l'administrateur et ce fichier appartient au produit.
# Le nom ne porte pas de point: c'est aussi le cas des hooks livres par les
# autres paquets, et il n'y a aucune raison d'eprouver le filtrage de systemd
# sur ce point.
HOOK_VEILLE_INSTALLE=/usr/lib/systemd/system-sleep/bifrost-reprise
# Deux comptes de service, deux roles opposes: le coeur est exempte du kill
# switch, le resolveur ne l'est jamais. Ils partagent le meme confinement.
COMPTES_SERVICE="$COMPTE_COEUR $COMPTE_RESOLVEUR"
# La source de verite des comptes, lue par les DEUX voies de creation.
DECLARATION="$ICI/sysusers.d/bifrost.conf"
# shellcheck source=comptes.sh
. "$ICI/comptes.sh"

ok()   { printf '  OK    %s\n' "$1"; }
info() { printf '  ..    %s\n' "$1"; }
step() { printf '\n== %s\n' "$1"; }

[ "$(id -u)" -eq 0 ] || { echo "ce script doit tourner en root"; exit 1; }
for f in bifrost-daemon bifrost-cli; do
  [ -x "$BIN/$f" ] || { echo "binaire introuvable: $BIN/$f"; exit 1; }
done
# Verifie AVANT de rien poser: un `install` qui echoue au milieu laisse une
# installation a moitie faite, ce qui est pire qu'un refus. Le hook est le seul
# fichier d'empaquetage designe par un chemin qui n'existe nulle part ailleurs
# dans ce script.
HOOK_VEILLE="$ICI/systemd/system-sleep/bifrost-reprise"
[ -f "$HOOK_VEILLE" ] || { echo "hook de reprise introuvable: $HOOK_VEILLE"; exit 1; }

step "Comptes systeme"
# `systemd-sysusers` quand il est la: le fichier declaratif est la source de
# verite, et il sera rejoue au demarrage si les comptes disparaissent. Sinon on
# retombe sur useradd, en reproduisant les memes proprietes a la main.
if command -v systemd-sysusers >/dev/null 2>&1; then
  install -D -m 0644 "$DECLARATION" /usr/lib/sysusers.d/bifrost.conf
  systemd-sysusers /usr/lib/sysusers.d/bifrost.conf
  ok "comptes appliques depuis /usr/lib/sysusers.d/bifrost.conf"
else
  info "systemd-sysusers absent, creation a la main"
  # Le corps vit dans packaging/comptes.sh: la recette d'empaquetage appelle la
  # MEME fonction dans une racine jetable, ce qu'elle ne pouvait pas faire tant
  # que ces lignes etaient ici. Voir l'en-tete de ce fichier-la.
  comptes_creer_a_la_main "$DECLARATION" "$GROUPE_PILOTAGE" "" $COMPTES_SERVICE
  ok "comptes $GROUPE_PILOTAGE, $COMPTE_COEUR et $COMPTE_RESOLVEUR en place"
fi

# Les controles qui comptent, quelle que soit la voie prise.
for compte in $COMPTES_SERVICE; do
  # Membre du groupe de pilotage, ce compte pourrait DECONNECTER le VPN: un
  # debordement dans un parseur tiers deviendrait une coupure a distance.
  if id -nG "$compte" | tr ' ' '\n' | grep -qx "$GROUPE_PILOTAGE"; then
    echo "REFUS: $compte appartient au groupe $GROUPE_PILOTAGE, donc il" >&2
    echo "       pourrait piloter le daemon. Le retirer avant d'installer." >&2
    exit 1
  fi
done
ok "aucun compte de service ne peut piloter le daemon"

# Et surtout, les deux comptes ne doivent pas etre le meme. Le coeur porte une
# exemption du kill switch; le resolveur qui en heriterait pourrait emettre du
# DNS en clair hors tunnel, ce que le resolveur chiffre existe pour empecher.
UID_COEUR=$(id -u "$COMPTE_COEUR")
UID_RESOLVEUR=$(id -u "$COMPTE_RESOLVEUR")
if [ "$UID_COEUR" = "$UID_RESOLVEUR" ]; then
  echo "REFUS: $COMPTE_COEUR et $COMPTE_RESOLVEUR partagent l'uid $UID_COEUR." >&2
  echo "       Le resolveur heriterait de l'exemption du coeur et pourrait" >&2
  echo "       emettre du DNS en clair hors tunnel." >&2
  exit 1
fi
ok "coeur (uid $UID_COEUR) et resolveur (uid $UID_RESOLVEUR) sont distincts"

step "Binaires"
install -D -m 0755 "$BIN/bifrost-daemon" /usr/bin/bifrost-daemon
install -D -m 0755 "$BIN/bifrost-cli" /usr/bin/bifrost-cli
ok "/usr/bin/bifrost-daemon et /usr/bin/bifrost-cli"

step "Resolveur chiffre"
if [ -n "${RESOLVEUR:-}" ]; then
  [ -x "$RESOLVEUR" ] || { echo "RESOLVEUR=$RESOLVEUR n'est pas executable"; exit 1; }
  # 0755 root:root, comme les autres binaires. Surtout PAS accessible en
  # ecriture au compte qui l'execute: un resolveur qui pourrait reecrire son
  # propre programme transformerait n'importe quel defaut en persistance.
  #
  # Reinstaller en designant la cible elle-meme est la facon naturelle de
  # rejouer l'installateur. `install` refuse de copier un fichier sur lui-meme
  # et faisait echouer tout le reste de la pose. On remet les droits sans
  # copier: le resultat est le meme, et l'operation redevient rejouable.
  if [ "$RESOLVEUR" -ef "$RESOLVEUR_INSTALLE" ]; then
    chown root:root "$RESOLVEUR_INSTALLE"
    chmod 0755 "$RESOLVEUR_INSTALLE"
  else
    install -D -m 0755 -o root -g root "$RESOLVEUR" "$RESOLVEUR_INSTALLE"
  fi
  ok "$RESOLVEUR_INSTALLE ($("$RESOLVEUR_INSTALLE" -version 2>/dev/null || echo 'version illisible'))"
elif [ -x "$RESOLVEUR_INSTALLE" ]; then
  ok "$RESOLVEUR_INSTALLE deja en place, conserve"
else
  info "aucun resolveur chiffre installe (RESOLVEUR non defini)"
  info "un profil demandant \`embarque\` echouera tant qu'il manque"
fi

# Pas de repertoire de travail cree ici: /run est un tmpfs vide a chaque
# demarrage, et ce que l'installation y poserait disparaitrait au premier
# redemarrage. C'est le daemon qui cree /run/bifrost/resolveur et le donne au
# compte, a chaque connexion, dans `ecrire_configuration`.

step "Unite systemd"
install -D -m 0644 "$ICI/systemd/bifrost-daemon.service" \
        /etc/systemd/system/bifrost-daemon.service
systemctl daemon-reload
ok "unite installee et rechargee"

step "Reprise apres veille"
# En 0755 et non 0644: systemd ne lance que les fichiers EXECUTABLES de ce
# repertoire, et un hook non executable y serait ignore sans un mot. C'est
# `install -m` qui fixe le mode, jamais celui du depot - un depot clone depuis
# Windows n'en porte aucun.
#
# Poser ce fichier ne demarre rien et ne change rien au comportement de la
# machine tant qu'aucun daemon n'ecoute: le hook constate alors l'absence de
# canal et rend la main. Il n'entre donc pas dans la reserve de l'en-tete sur
# ce que l'installateur n'active pas.
install -D -m 0755 "$HOOK_VEILLE" "$HOOK_VEILLE_INSTALLE"
ok "$HOOK_VEILLE_INSTALLE"

cat <<TEXTE

Installation terminee. Le service n'est ni active ni demarre.

  usermod -aG $GROUPE_PILOTAGE <utilisateur>   # droit de piloter le daemon
  systemctl enable --now bifrost-daemon

Armer le kill switch coupe tout trafic hors tunnel, session SSH comprise.
TEXTE
