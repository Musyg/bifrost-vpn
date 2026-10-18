#!/usr/bin/env bash
# Installe REELLEMENT le .rpm du daemon, dans des conteneurs Fedora jetables, et
# lit ce que le paquet fait: comptes, fichiers, refus du %pre, reinstallation,
# desinstallation.
#
# Le .rpm est construit par scripts/paquets-linux.sh avec le rpmbuild d'Ubuntu,
# et la base du runner est Debian: sans conteneur, il ne s'installe nulle part.
# Ce script le donne a dnf, le gestionnaire de Fedora, qui resout ses
# dependances (systemd, nftables) depuis les depots de Fedora.
#
# L'image: Fedora 44, la version stable au 18/10/2026 (Fedora 45 etait en gel
# final, sortie visee le 20/10). Elle est tiree par l'empreinte de son
# manifeste linux/amd64, jamais par une etiquette: une etiquette se deplace (la
# 44 est reconstruite chaque jour), une empreinte nomme un contenu. Lue le
# 18/10/2026 a 09:06 UTC au registre de Fedora, par HTTPS anonyme: GET
# /v2/fedora/manifests/44 (Accept: index OCI) rend l'index
# sha256:4a78eff1423dcce55cf68b8fd66e7cdca61c85978283db3ecc3089a8419fbbc0, dont
# l'entree linux/amd64 est le manifeste epingle ici (une couche, configuration
# creee le 18/10/2026 a 06:48 UTC). quay.io/fedora/fedora sert le meme index,
# mais ne servait deja plus celui de la veille: une empreinte n'y survit pas a
# l'etiquette. Le registre de Fedora servait encore, le meme jour, les index de
# la 44 remplaces depuis le 05/10. Si l'empreinte disparait du registre, le
# tirage echoue ici en le disant: relire l'empreinte de la 44 et la remplacer,
# jamais retomber sur l'etiquette.
#
# Fedora 44 n'impose pas la signature d'un paquet installe (rpm 6.0, mode
# historique: le changement qui l'impose est celui de Fedora 45), et dnf ne
# verifie pas celle d'un fichier local (localpkg_gpgcheck faux par defaut): le
# .rpm non signe s'installe tel quel. Le rpmbuild 4.18 d'Ubuntu ne tire aucun
# Provides user() ou group() de la declaration: le rpm de Fedora ne cree donc
# aucun compte de lui-meme, le %pre du paquet est le seul createur.
#
# Le meme rpmbuild ajoute de lui-meme, marques %artifact, un lien
# /usr/lib/.build-id/xx/yyyy vers chaque binaire ELF qui porte un build-id, et
# ses repertoires (%_build_id_links compat, defaut de rpm 4.18). La liste du
# paquet est donc lue sans les artefacts (--noartifact), egale a POSES; les
# artefacts, eux, ne peuvent etre que ces liens, un par binaire, ou aucun.
#
# Cinq cas, chacun dans un conteneur neuf (`docker run --rm`, sans tirage):
#   installation     comptes et groupe crees tels que la declaration les
#                    decrit (relus par getent), fichiers poses a leur mode,
#                    paquet installe, aucun service active ni demarre, le
#                    message du %post relu;
#   refus-membre     bifrost-coeur deja membre du groupe bifrost (compte et
#                    groupe crees avant, dans ce conteneur): installation
#                    refusee, le REFUS du %pre relu, paquet absent, aucun
#                    fichier du paquet pose;
#   refus-uid        bifrost-coeur et bifrost-resolveur deja crees au meme uid:
#                    idem, avec l'autre REFUS;
#   reinstallation   le paquet reinstalle sur lui-meme: accepte, comptes
#                    inchanges; puis, bifrost-coeur mis dans le groupe, la
#                    reinstallation est refusee par le meme REFUS (le %pre
#                    rejoue) et le paquet installe reste en place;
#   desinstallation  comptes conserves; l'etat /var/lib/bifrost retire s'il est
#                    vide, garde et nomme s'il ne l'est pas (le %postun).
# Chaque attente est exacte: le code de dnf, une ligne relue dans son journal,
# une valeur relue. Un ecart arrete le cas en le nommant, et le script echoue.
#
# dnf tourne avec les reglages d'un systeme Fedora ordinaire: l'image pose
# tsflags=nodocs, qui ne poserait pas les pages de manuel; --setopt=tsflags=
# le retire. clean_requirements_on_remove=False: une desinstallation ne retire
# que le paquet, pas systemd ni nftables. keepcache: les paquets telecharges
# restent dans le cache, un volume nomme partage par les cinq conteneurs et
# retire a la fin.
#
# Rien n'est fait hors des conteneurs, sauf par Docker: tirage de l'image,
# creation et retrait du volume. Sous l'utilisateur courant si le socket de
# Docker lui est ouvert, sinon par `sudo -n docker`, et seulement pour Docker.
#
# Usage: ./scripts/paquets-rpm-conteneur.sh [REPERTOIRE_PAQUETS]
#   REPERTOIRE_PAQUETS: defaut target/paquets (sortie de paquets-linux.sh)
# Ce script se relance lui-meme dans chaque conteneur avec `--cas NOM`; cette
# forme refuse de tourner hors d'un conteneur lance par lui.
set -uo pipefail

IMAGE_FEDORA="registry.fedoraproject.org/fedora@sha256:10667e171df877cedd245b7065238143e09eaae7da4656d3e62eb7c094378011"
VERSION_FEDORA=44

# Les lignes que les scriptlets du spec impriment, a la lettre
# (packaging/rpm/bifrost.spec; crates/bifrost-evasion/tests/paquets_linux.rs
# exige qu'elles y soient).
REFUS_MEMBRE="bifrost: REFUS, bifrost-coeur appartient au groupe bifrost et pourrait piloter le daemon"
REFUS_UID="bifrost: REFUS, bifrost-coeur et bifrost-resolveur partagent un uid"
MESSAGE_POST="bifrost: installe. Le service n'est ni active ni demarre."
MESSAGE_COMPTES="bifrost: les comptes systeme bifrost, bifrost-coeur et bifrost-resolveur sont conserves"
MESSAGE_ETAT="bifrost: /var/lib/bifrost n'est pas vide et reste en place (etat du daemon)"

# Ce que le paquet pose, et a quel mode: les poses de %install, lues par la
# meme recette.
POSES=(
  "755 /usr/bin/bifrost-daemon"
  "755 /usr/bin/bifrost-cli"
  "644 /usr/lib/systemd/system/bifrost-daemon.service"
  "755 /usr/lib/systemd/system-sleep/bifrost-reprise"
  "644 /usr/lib/sysusers.d/bifrost.conf"
  "644 /usr/share/licenses/bifrost/copyright"
  "644 /usr/share/man/man1/bifrost-daemon.1.gz"
  "644 /usr/share/man/man1/bifrost-cli.1.gz"
)

# ======================================================== dans le conteneur

CAS=""
JOURNAL=/tmp/bifrost-dnf.journal
DECLARATION=/bifrost/packaging/sysusers.d/bifrost.conf
RPM=""
NVRA=""
VERSION_PAQUET=""

ok()    { printf '  OK    [%s] %s\n' "$CAS" "$1"; }
info()  { printf '  ..    [%s] %s\n' "$CAS" "$1"; }
echec() { printf '  ECHEC [%s] %s\n' "$CAS" "$1"; exit 1; }

# dnf, son code compare a l'attendu, son journal imprime et garde pour relue.
transaction() {
  local attendu="$1" code
  shift
  dnf -y --setopt=tsflags= --setopt=keepcache=True --setopt=clean_requirements_on_remove=False "$@" >"$JOURNAL" 2>&1
  code=$?
  sed 's/^/    | /' "$JOURNAL"
  if [ "$code" -eq "$attendu" ]; then
    ok "dnf $*: code $code"
  else
    echec "dnf $*: code $code, attendu $attendu"
  fi
}

# Une ligne du dernier journal de dnf, a la lettre. dnf imprime la sortie d'un
# scriptlet ligne a ligne, chacune precedee de `>>> `, retire ici.
relue() {
  local attendu="$1" l
  while IFS= read -r l; do
    l="${l#>>> }"
    if [ "$l" = "$attendu" ]; then
      ok "ligne relue: $attendu"
      return 0
    fi
  done < "$JOURNAL"
  echec "ligne absente du journal de dnf: $attendu"
}

absente() {
  local interdite="$1" l
  while IFS= read -r l; do
    l="${l#>>> }"
    if [ "$l" = "$interdite" ]; then
      echec "ligne presente dans le journal de dnf: $interdite"
    fi
  done < "$JOURNAL"
  ok "ligne absente du journal: $interdite"
}

# Un seul REFUS: le %pre sort au premier.
refus_unique() {
  local l n=0
  while IFS= read -r l; do
    l="${l#>>> }"
    case "$l" in
      "bifrost: REFUS"*) n=$((n + 1)) ;;
    esac
  done < "$JOURNAL"
  if [ "$n" -eq 1 ]; then
    ok "une seule ligne REFUS"
  else
    echec "$n ligne(s) REFUS dans le journal, attendu 1"
  fi
}

# Aucun REFUS: l'installation acceptee ne doit pas en porter.
aucun_refus() {
  local l
  while IFS= read -r l; do
    l="${l#>>> }"
    case "$l" in
      "bifrost: REFUS"*) echec "ligne REFUS a une installation acceptee: $l" ;;
    esac
  done < "$JOURNAL"
  ok "aucune ligne REFUS"
}

paquet_installe() {
  local lu verif code
  lu="$(rpm -q bifrost)"
  code=$?
  if [ "$code" -eq 0 ] && [ "$lu" = "$NVRA" ]; then
    ok "rpm -q bifrost: $lu"
  else
    echec "rpm -q bifrost: [$lu] code $code, attendu [$NVRA] code 0"
  fi
  verif="$(rpm -V bifrost 2>&1)"
  code=$?
  if [ "$code" -eq 0 ] && [ -z "$verif" ]; then
    ok "rpm -V bifrost: code 0, aucun ecart"
  else
    echec "rpm -V bifrost: code $code: $verif"
  fi
}

paquet_absent() {
  local lu code
  lu="$(rpm -q bifrost 2>&1)"
  code=$?
  if [ "$code" -eq 1 ]; then
    ok "rpm -q bifrost: code 1 ($lu)"
  else
    echec "rpm -q bifrost: code $code, attendu 1: $lu"
  fi
  lu="$(rpm -qa bifrost)"
  if [ -z "$lu" ]; then
    ok "rpm -qa bifrost: vide"
  else
    echec "rpm -qa bifrost: $lu"
  fi
}

# Les artefacts que rpmbuild peut ajouter: les repertoires du build-id, et un
# lien par binaire ELF. LIENS garde `chemin cible` de chaque lien lu.
RE_REPERTOIRE_ID='^/usr/lib/\.build-id(/[0-9a-f]{2})?$'
RE_LIEN_ID='^/usr/lib/\.build-id/[0-9a-f]{2}/[0-9a-f]{30,126}$'
LIENS=()

# La liste du paquet: les fichiers de POSES, ni plus ni moins, hors artefacts;
# puis les artefacts, qui ne peuvent etre que ceux du build-id.
lire_le_paquet() {
  local attendue lue entree drapeaux droits chemin cible
  attendue="$(for entree in "${POSES[@]}"; do printf '%s\n' "${entree#* }"; done)"
  attendue="$(sort <<< "$attendue")"
  lue="$(rpm -qlp --noartifact "$RPM")" || echec "rpm -qlp --noartifact $RPM a echoue"
  lue="$(sort <<< "$lue")"
  if [ "$lue" = "$attendue" ]; then
    ok "le paquet porte les ${#POSES[@]} fichiers attendus, aucun autre hors artefacts"
  else
    echec "fichiers du paquet: [$lue], attendu [$attendue]"
  fi
  lue="$(rpm -qp --qf '[%{FILEFLAGS} %{FILEMODES:perms} %{FILENAMES} %{FILELINKTOS}\n]' "$RPM")" || echec "rpm -qp --qf $RPM a echoue"
  LIENS=()
  while read -r drapeaux droits chemin cible; do
    # RPMFILE_ARTIFACT, 1 << 12.
    if [ $((drapeaux & 4096)) -eq 0 ]; then
      continue
    fi
    if [[ $droits == d* && -z $cible && $chemin =~ $RE_REPERTOIRE_ID ]]; then
      info "artefact: repertoire $chemin"
    elif [[ $droits == l* && $chemin =~ $RE_LIEN_ID ]] && { [ "$cible" = "../../../../usr/bin/bifrost-daemon" ] || [ "$cible" = "../../../../usr/bin/bifrost-cli" ]; }; then
      LIENS+=("$chemin $cible")
    else
      echec "artefact du paquet que ce script ne sait pas lire: [$drapeaux $droits $chemin $cible]"
    fi
  done <<< "$lue"
  case "${#LIENS[@]}" in
    0) ok "aucun lien build-id dans le paquet" ;;
    2)
      if [ "${LIENS[0]#* }" != "${LIENS[1]#* }" ]; then
        ok "un lien build-id par binaire: ${LIENS[0]}, ${LIENS[1]}"
      else
        echec "deux liens build-id vers le meme binaire: ${LIENS[0]}, ${LIENS[1]}"
      fi
      ;;
    *) echec "${#LIENS[@]} lien(s) build-id, attendu 0 ou 2 (un par binaire ELF)" ;;
  esac
}

fichiers_poses() {
  local entree mode chemin lu paire origine cible
  for entree in "${POSES[@]}"; do
    mode="${entree%% *}"
    chemin="${entree#* }"
    lu="$(stat -c '%a %U:%G' "$chemin" 2>&1)"
    if [ "$lu" = "$mode root:root" ]; then
      ok "$chemin $lu"
    else
      echec "$chemin: [$lu], attendu [$mode root:root]"
    fi
  done
  for entree in "${LIENS[@]}"; do
    chemin="${entree%% *}"
    cible="${entree#* }"
    lu="$(readlink "$chemin" 2>&1)"
    if [ "$lu" = "$cible" ] && [ "$(readlink -f "$chemin")" = "/usr/bin/${cible##*/}" ]; then
      ok "$chemin -> $lu"
    else
      echec "$chemin: lien [$lu], attendu [$cible] vers /usr/bin/${cible##*/}"
    fi
  done
  for paire in systemd/bifrost-daemon.service:/usr/lib/systemd/system/bifrost-daemon.service \
               systemd/system-sleep/bifrost-reprise:/usr/lib/systemd/system-sleep/bifrost-reprise \
               sysusers.d/bifrost.conf:/usr/lib/sysusers.d/bifrost.conf; do
    chemin="${paire#*:}"
    origine="/bifrost/packaging/${paire%%:*}"
    if [ "$(sha256sum < "$chemin")" = "$(sha256sum < "$origine")" ]; then
      ok "$chemin identique a ${origine#/bifrost/}"
    else
      echec "$chemin differe de ${origine#/bifrost/}"
    fi
  done
  lu="$(/usr/bin/bifrost-cli --version 2>&1)"
  if [ "$lu" = "bifrost-cli $VERSION_PAQUET" ]; then
    ok "bifrost-cli --version: $lu"
  else
    echec "bifrost-cli --version: [$lu], attendu [bifrost-cli $VERSION_PAQUET]"
  fi
}

aucun_fichier_pose() {
  local entree chemin
  for entree in "${POSES[@]}"; do
    chemin="${entree#* }"
    if [ -e "$chemin" ] || [ -L "$chemin" ]; then
      echec "$chemin pose alors que le paquet n'est pas installe"
    fi
  done
  for entree in "${LIENS[@]}"; do
    chemin="${entree%% *}"
    if [ -e "$chemin" ] || [ -L "$chemin" ]; then
      echec "$chemin pose alors que le paquet n'est pas installe"
    fi
  done
  ok "aucun des ${#POSES[@]} fichiers du paquet ni de ses ${#LIENS[@]} lien(s) build-id n'est pose"
}

# La declaration, en grammaire fermee: lignes vides, commentaires,
# `g NOM -` et `u NOM - "GECOS" MAISON SHELL`. Toute autre ligne arrete le cas.
GROUPES=()
COMPTES=()
GECOS=()
MAISONS=()
SHELLS=()
RE_G='^g[[:space:]]+([a-z][a-z0-9-]*)[[:space:]]+-[[:space:]]*$'
RE_U='^u[[:space:]]+([a-z][a-z0-9-]*)[[:space:]]+-[[:space:]]+"([^"]*)"[[:space:]]+([^[:space:]]+)[[:space:]]+([^[:space:]]+)[[:space:]]*$'
lire_declaration() {
  local ligne
  while IFS= read -r ligne; do
    case "$ligne" in
      ''|'#'*) continue ;;
    esac
    if [[ $ligne =~ $RE_G ]]; then
      GROUPES+=("${BASH_REMATCH[1]}")
    elif [[ $ligne =~ $RE_U ]]; then
      COMPTES+=("${BASH_REMATCH[1]}")
      GECOS+=("${BASH_REMATCH[2]}")
      MAISONS+=("${BASH_REMATCH[3]}")
      SHELLS+=("${BASH_REMATCH[4]}")
    else
      echec "ligne de la declaration que ce script ne sait pas lire: $ligne"
    fi
  done < "$DECLARATION"
  if [ "${#GROUPES[@]}" -ne 1 ] || [ "${#COMPTES[@]}" -ne 2 ]; then
    echec "la declaration porte ${#GROUPES[@]} groupe(s) et ${#COMPTES[@]} compte(s), attendu 1 et 2"
  fi
}

# Les comptes tels que la declaration les decrit: un groupe systeme sans membre,
# deux comptes systeme avec leur groupe du meme nom, leur description, leur
# maison et leur shell, hors du groupe de pilotage, a des uid distincts.
comptes_de_la_declaration() {
  local g c i ligne nom uid gid gecos maison shell membres gid_c groupes uids=" "
  for g in "${GROUPES[@]}"; do
    ligne="$(getent group "$g")" || echec "groupe $g absent"
    IFS=: read -r nom _ gid membres <<< "$ligne"
    if [ "$nom" = "$g" ] && [ "$gid" -ge 1 ] && [ "$gid" -le 999 ] && [ -z "$membres" ]; then
      ok "groupe $g: gid systeme $gid, aucun membre"
    else
      echec "groupe $g: [$ligne], attendu un gid de 1 a 999 et aucun membre"
    fi
  done
  for i in "${!COMPTES[@]}"; do
    c="${COMPTES[$i]}"
    ligne="$(getent passwd "$c")" || echec "compte $c absent"
    IFS=: read -r nom _ uid gid gecos maison shell <<< "$ligne"
    if [ "$nom" = "$c" ] && [ "$uid" -ge 1 ] && [ "$uid" -le 999 ]; then
      ok "$c: compte systeme, uid $uid"
    else
      echec "$c: [$ligne], attendu un uid de 1 a 999"
    fi
    if [ "$gecos" = "${GECOS[$i]}" ] && [ "$maison" = "${MAISONS[$i]}" ] && [ "$shell" = "${SHELLS[$i]}" ]; then
      ok "$c: [$gecos] $maison $shell, comme la declaration"
    else
      echec "$c: [$gecos] $maison $shell, la declaration dit [${GECOS[$i]}] ${MAISONS[$i]} ${SHELLS[$i]}"
    fi
    ligne="$(getent group "$c")" || echec "groupe $c absent"
    IFS=: read -r _ _ gid_c _ <<< "$ligne"
    if [ "$gid_c" = "$gid" ]; then
      ok "$c: groupe principal $c (gid $gid)"
    else
      echec "$c: gid $gid, le groupe $c a le gid $gid_c"
    fi
    groupes=" $(id -nG "$c") "
    for g in "${GROUPES[@]}"; do
      case "$groupes" in
        *" $g "*) echec "$c appartient au groupe $g" ;;
      esac
    done
    ok "$c: groupes [${groupes# }], hors de ${GROUPES[*]}"
    case "$uids" in
      *" $uid "*) echec "$c partage l'uid $uid avec un autre compte de la declaration" ;;
    esac
    uids="$uids$uid "
  done
  ok "uid distincts:$uids"
}

# L'etat des comptes de la declaration, en une chaine comparable.
comptes() {
  getent passwd "${COMPTES[@]}"
  getent group "${GROUPES[@]}" "${COMPTES[@]}"
}

comptes_inchanges() {
  local avant="$1" apres
  apres="$(comptes)"
  if [ "$apres" = "$avant" ]; then
    ok "comptes inchanges: $(tr '\n' ' ' <<< "$apres")"
  else
    echec "comptes changes: avant [$avant], apres [$apres]"
  fi
}

# Aucune unite activee, aucun processus du daemon. Sans systemd en PID 1,
# systemctl ne demarre rien; ce controle dit que le paquet n'a pose aucun lien
# d'activation et lance aucun daemon.
rien_de_demarre() {
  local unites f nom
  unites="$(find /etc/systemd /usr/lib/systemd /run/systemd -name bifrost-daemon.service 2>/dev/null)"
  if [ "$unites" = "/usr/lib/systemd/system/bifrost-daemon.service" ]; then
    ok "une seule unite, celle du paquet: aucun lien d'activation"
  else
    echec "unites bifrost-daemon.service trouvees: [$unites]"
  fi
  for f in /proc/[0-9]*/comm; do
    nom=""
    read -r nom 2>/dev/null < "$f"
    if [ "$nom" = "bifrost-daemon" ]; then
      echec "un processus bifrost-daemon tourne (${f%/comm})"
    fi
  done
  ok "aucun processus bifrost-daemon"
}

preconditions_vierges() {
  local c
  if rpm -q bifrost >/dev/null 2>&1; then
    echec "bifrost deja installe dans un conteneur neuf"
  fi
  for c in "${GROUPES[@]}" "${COMPTES[@]}"; do
    if getent passwd "$c" >/dev/null || getent group "$c" >/dev/null; then
      echec "$c existe deja dans un conteneur neuf"
    fi
  done
  if [ -e /var/lib/bifrost ]; then
    echec "/var/lib/bifrost existe deja dans un conteneur neuf"
  fi
  ok "conteneur vierge: ni paquet, ni compte, ni etat bifrost"
}

cas_installation() {
  preconditions_vierges
  transaction 0 install "$RPM"
  relue "$MESSAGE_POST"
  aucun_refus
  paquet_installe
  fichiers_poses
  comptes_de_la_declaration
  rien_de_demarre
}

cas_refus_membre() {
  preconditions_vierges
  groupadd -r bifrost || echec "groupadd -r bifrost a echoue"
  useradd -r -M -d /nonexistent -s /usr/sbin/nologin -G bifrost bifrost-coeur || echec "useradd bifrost-coeur a echoue"
  case " $(id -nG bifrost-coeur) " in
    *" bifrost "*) ok "avant: bifrost-coeur membre du groupe bifrost" ;;
    *) echec "avant: bifrost-coeur n'est pas membre du groupe bifrost" ;;
  esac
  transaction 1 install "$RPM"
  relue "$REFUS_MEMBRE"
  refus_unique
  absente "$MESSAGE_POST"
  paquet_absent
  aucun_fichier_pose
}

cas_refus_uid() {
  local uid
  preconditions_vierges
  useradd -r -M -d /nonexistent -s /usr/sbin/nologin bifrost-coeur || echec "useradd bifrost-coeur a echoue"
  uid="$(id -u bifrost-coeur)" || echec "uid de bifrost-coeur illisible"
  useradd -r -o -u "$uid" -M -d /nonexistent -s /usr/sbin/nologin bifrost-resolveur || echec "useradd bifrost-resolveur a echoue"
  if [ "$(id -u bifrost-resolveur)" = "$uid" ]; then
    ok "avant: bifrost-coeur et bifrost-resolveur a l'uid $uid"
  else
    echec "avant: bifrost-resolveur n'a pas l'uid $uid"
  fi
  transaction 1 install "$RPM"
  relue "$REFUS_UID"
  refus_unique
  absente "$MESSAGE_POST"
  paquet_absent
  aucun_fichier_pose
}

cas_reinstallation() {
  local avant
  preconditions_vierges
  transaction 0 install "$RPM"
  paquet_installe
  avant="$(comptes)"
  transaction 0 reinstall "$RPM"
  relue "$MESSAGE_POST"
  aucun_refus
  paquet_installe
  comptes_inchanges "$avant"
  gpasswd -a bifrost-coeur bifrost >/dev/null || echec "gpasswd -a bifrost-coeur bifrost a echoue"
  transaction 1 reinstall "$RPM"
  relue "$REFUS_MEMBRE"
  refus_unique
  paquet_installe
}

cas_desinstallation() {
  local avant
  preconditions_vierges
  transaction 0 install "$RPM"
  avant="$(comptes)"
  mkdir /var/lib/bifrost || echec "mkdir /var/lib/bifrost a echoue"
  transaction 0 remove bifrost
  relue "$MESSAGE_COMPTES"
  absente "$MESSAGE_ETAT"
  paquet_absent
  aucun_fichier_pose
  if [ -e /var/lib/bifrost ]; then
    echec "/var/lib/bifrost vide et garde par la desinstallation"
  fi
  ok "/var/lib/bifrost vide retire"
  comptes_inchanges "$avant"
  transaction 0 install "$RPM"
  mkdir /var/lib/bifrost || echec "mkdir /var/lib/bifrost a echoue"
  printf 'etat\n' > /var/lib/bifrost/etat || echec "ecriture de /var/lib/bifrost/etat"
  transaction 0 remove bifrost
  relue "$MESSAGE_ETAT"
  relue "$MESSAGE_COMPTES"
  paquet_absent
  if [ "$(cat /var/lib/bifrost/etat 2>&1)" = "etat" ]; then
    ok "/var/lib/bifrost non vide garde, contenu intact"
  else
    echec "/var/lib/bifrost/etat perdu par la desinstallation"
  fi
  comptes_inchanges "$avant"
}

dans_le_conteneur() {
  local os version
  CAS="$1"
  if [ ! -f /.dockerenv ] || [ "${BIFROST_CONTENEUR_JETABLE:-}" != "1" ]; then
    echo "REFUS: --cas ne tourne que dans un conteneur jetable lance par ce script." >&2
    return 1
  fi
  os="$(sed -n 's/^ID=//p' /usr/lib/os-release)"
  version="$(sed -n 's/^VERSION_ID=//p' /usr/lib/os-release)"
  if [ "$os" != "fedora" ] || [ "$version" != "$VERSION_FEDORA" ] || [ "$(id -u)" -ne 0 ]; then
    echo "REFUS: --cas attend Fedora $VERSION_FEDORA en root (lu: $os $version, uid $(id -u))." >&2
    return 1
  fi
  RPM="${BIFROST_RPM:-}"
  [ -f "$RPM" ] || echec "paquet introuvable dans le conteneur: [$RPM]"
  NVRA="$(rpm -qp --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}' "$RPM")" || echec "rpm -qp $RPM a echoue"
  VERSION_PAQUET="$(rpm -qp --qf '%{VERSION}' "$RPM")" || echec "rpm -qp $RPM a echoue"
  info "Fedora $version, $(rpm --version), paquet $NVRA"
  lire_declaration
  lire_le_paquet
  case "$CAS" in
    installation) cas_installation ;;
    refus-membre) cas_refus_membre ;;
    refus-uid) cas_refus_uid ;;
    reinstallation) cas_reinstallation ;;
    desinstallation) cas_desinstallation ;;
    *) echec "cas inconnu: $CAS" ;;
  esac
  info "tout est passe"
}

if [ "${1:-}" = "--cas" ]; then
  dans_le_conteneur "${2:-}"
  exit $?
fi

# ================================================================== sur l'hote

RACINE_DEPOT="$(cd "$(dirname "$0")/.." && pwd)"
PAQUETS="${1:-$RACINE_DEPOT/target/paquets}"
SCRIPT="$RACINE_DEPOT/scripts/paquets-rpm-conteneur.sh"

h_ok()   { printf '  OK    %s\n' "$1"; }
h_info() { printf '  ..    %s\n' "$1"; }
h_fin()  { printf '  ECHEC %s\n' "$1"; exit 1; }
step()   { printf '\n== %s\n' "$1"; }

step "Paquet et image"
[ -d "$PAQUETS" ] || h_fin "repertoire des paquets introuvable: $PAQUETS (scripts/paquets-linux.sh d'abord)"
PAQUETS="$(cd "$PAQUETS" && pwd)"
shopt -s nullglob
TROUVES=("$PAQUETS"/bifrost-[0-9]*.x86_64.rpm)
shopt -u nullglob
[ "${#TROUVES[@]}" -eq 1 ] || h_fin "${#TROUVES[@]} .rpm du daemon sous $PAQUETS, attendu 1 (rpmbuild absent a la construction?)"
RPM_HOTE="${TROUVES[0]}"
RPM_NOM="$(basename "$RPM_HOTE")"
h_ok "paquet: $RPM_HOTE"
[ -f "$SCRIPT" ] || h_fin "script introuvable: $SCRIPT"

command -v docker >/dev/null 2>&1 || h_fin "Docker absent: le .rpm ne peut pas etre installe dans un conteneur"
DOCKER=(docker)
if ! "${DOCKER[@]}" info >/dev/null 2>&1; then
  DOCKER=(sudo -n docker)
  "${DOCKER[@]}" info >/dev/null 2>&1 || h_fin "le daemon Docker ne repond ni a $(id -un) ni par sudo -n"
  h_info "le socket de Docker n'est pas ouvert a $(id -un): Docker passe par sudo -n"
fi
h_info "utilisateur: $(id)"
h_info "$("${DOCKER[@]}" version --format 'Docker: client {{.Client.Version}}, serveur {{.Server.Version}}' 2>&1)"

if ! "${DOCKER[@]}" pull "$IMAGE_FEDORA"; then
  h_fin "tirage de $IMAGE_FEDORA refuse: empreinte retiree du registre, ou registre injoignable"
fi
EMPREINTES_LUES="$("${DOCKER[@]}" image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "$IMAGE_FEDORA")"
if grep -Fx "$IMAGE_FEDORA" >/dev/null <<< "$EMPREINTES_LUES"; then
  h_ok "image tiree par son empreinte: $IMAGE_FEDORA"
else
  h_fin "l'image locale ne porte pas l'empreinte epinglee: [$EMPREINTES_LUES]"
fi
PLATEFORME="$("${DOCKER[@]}" image inspect --format '{{.Os}}/{{.Architecture}}' "$IMAGE_FEDORA")"
[ "$PLATEFORME" = "linux/amd64" ] || h_fin "plateforme de l'image: $PLATEFORME, attendu linux/amd64"
h_ok "plateforme: $PLATEFORME"

VOLUME="bifrost-rpm-cache-$$"
"${DOCKER[@]}" volume create "$VOLUME" >/dev/null || h_fin "creation du volume $VOLUME refusee"
trap '"${DOCKER[@]}" volume rm -f "$VOLUME" >/dev/null 2>&1' EXIT
h_ok "volume du cache de dnf: $VOLUME"

ECHECS=0
for cas in installation refus-membre refus-uid reinstallation desinstallation; do
  step "Cas $cas, dans un conteneur neuf"
  "${DOCKER[@]}" run --rm --pull=never \
    --env BIFROST_CONTENEUR_JETABLE=1 \
    --env "BIFROST_RPM=/bifrost/$RPM_NOM" \
    --mount "type=bind,src=$RPM_HOTE,dst=/bifrost/$RPM_NOM,readonly" \
    --mount "type=bind,src=$SCRIPT,dst=/bifrost/paquets-rpm-conteneur.sh,readonly" \
    --mount "type=bind,src=$RACINE_DEPOT/packaging,dst=/bifrost/packaging,readonly" \
    --mount "type=volume,src=$VOLUME,dst=/var/cache/libdnf5" \
    "$IMAGE_FEDORA" bash /bifrost/paquets-rpm-conteneur.sh --cas "$cas"
  code=$?
  if [ "$code" -eq 0 ]; then
    h_ok "cas $cas"
  else
    printf '  ECHEC cas %s: code %s\n' "$cas" "$code"
    ECHECS=$((ECHECS + 1))
  fi
done

echo
if [ "$ECHECS" -eq 0 ]; then
  echo "installation du .rpm dans des conteneurs Fedora: tout est passe"
else
  echo "installation du .rpm dans des conteneurs Fedora: $ECHECS cas en echec"
  exit 1
fi
