## Gabarit RPM du paquet Bifrost (Fedora, RHEL).
##
## @VERSION@ est remplace a la construction par la version du workspace
## (Cargo.toml, [workspace.package]), par scripts/paquets-linux.sh: la meme
## source que le control du .deb, jamais recopiee a la main.
##
## Les binaires ne sont pas compiles par rpmbuild: ils sont deja construits
## (cargo build --release --locked) et copies dans le BUILDROOT par %%install,
## depuis les chemins passes en --define par le script. Il n'y a donc ni %%prep
## ni %%build.
##
## Ce paquet fait ce que fait le .deb, avec les memes fichiers de packaging/ et
## des scriptlets qui reproduisent postinst, prerm et postrm, donc ce que fait
## packaging/install-linux.sh: memes comptes, memes binaires et memes modes, la
## meme unite, le meme hook. Il N'ACTIVE NI NE DEMARRE le service.
## Une difference d'ordre avec le .deb, voulue: les comptes et leurs refus
## passent en %%pre, avant la pose des fichiers, parce que rpm arrete
## l'installation d'un paquet dont le %%pre echoue et pas celle d'un paquet
## dont le %%post echoue.
## crates/bifrost-evasion/tests/paquets_linux.rs garde cette parite.

Name:           bifrost
Version:        @VERSION@
Release:        1%{?dist}
Summary:        Daemon Bifrost: tunnel WireGuard et kill switch

License:        MPL-2.0
URL:            https://github.com/Musyg/bifrost-vpn
Packager:       Bifrost <security@inaricom.com>
Vendor:         Bifrost
BuildArch:      x86_64

# Les memes dependances que le Depends du control. Celles des bibliotheques
# liees y sont mesurees par dpkg-shlibdeps (libc6, libgcc-s1); ici glibc et
# libgcc, que rpmbuild complete des versions de symboles qu'il lit dans les
# binaires. systemd (unite, systemd-sysusers, systemctl) et nftables (le
# daemon appelle nft) gardent leur nom.
Requires:       glibc
Requires:       libgcc
Requires:       systemd
Requires:       nftables
# Ce que le %%pre appelle avant que le paquet soit pose: systemd-sysusers, id
# et tr (coreutils), grep. Requires(pre) les fait installer avant lui dans
# une meme transaction, une image construite d'un coup comprise.
Requires(pre):  systemd
Requires(pre):  coreutils
Requires(pre):  grep
Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd

%description
Bifrost est un VPN auto-heberge. Ce paquet pose le daemon privilegie et
son client en ligne de commande, l'unite systemd du daemon, le hook de reprise
apres veille et la declaration des comptes systeme, comme
packaging/install-linux.sh. Il n'active ni ne demarre le service: armer le kill
switch coupe tout trafic hors tunnel, session SSH comprise.

Le groupe bifrost ouvre trois commandes du daemon: l'etat, la connexion au
profil qu'il detient et la deconnexion. root a tout le canal.

Le resolveur chiffre (dnscrypt-proxy) n'est pas distribue: c'est un binaire
tiers, a recuperer et verifier separement, que le daemon attend au chemin
/usr/lib/bifrost/dnscrypt-proxy.

%install
# bindir_source: le repertoire des binaires construits; pkg_source: le
# repertoire packaging/ du depot. Passes par le script, jamais devines.
install -D -m 0755 %{bindir_source}/bifrost-daemon %{buildroot}/usr/bin/bifrost-daemon
install -D -m 0755 %{bindir_source}/bifrost-cli %{buildroot}/usr/bin/bifrost-cli
install -D -m 0644 %{pkg_source}/systemd/bifrost-daemon.service %{buildroot}/usr/lib/systemd/system/bifrost-daemon.service
install -D -m 0755 %{pkg_source}/systemd/system-sleep/bifrost-reprise %{buildroot}/usr/lib/systemd/system-sleep/bifrost-reprise
install -D -m 0644 %{pkg_source}/sysusers.d/bifrost.conf %{buildroot}/usr/lib/sysusers.d/bifrost.conf
install -D -m 0644 %{pkg_source}/deb/copyright %{buildroot}/usr/share/licenses/bifrost/copyright
# Poses non compressees: brp-compress les recomprime (voir %%files).
install -D -m 0644 %{pkg_source}/man/bifrost-daemon.1 %{buildroot}/usr/share/man/man1/bifrost-daemon.1
install -D -m 0644 %{pkg_source}/man/bifrost-cli.1 %{buildroot}/usr/share/man/man1/bifrost-cli.1

%files
%license /usr/share/licenses/bifrost/copyright
/usr/bin/bifrost-daemon
/usr/bin/bifrost-cli
/usr/lib/systemd/system/bifrost-daemon.service
%attr(0755,root,root) /usr/lib/systemd/system-sleep/bifrost-reprise
/usr/lib/sysusers.d/bifrost.conf
/usr/share/man/man1/bifrost-daemon.1.gz
/usr/share/man/man1/bifrost-cli.1.gz

# Miroir de la partie comptes de postinst, AVANT la pose des fichiers: comptes
# depuis la declaration, memes refus que l'installateur. $1 = 1 a
# l'installation, 2 a la mise a jour: meme traitement.
#
# rpm n'installe pas un paquet dont le %%pre rend un code non nul: rien n'est
# pose, et une mise a jour laisse la version precedente en place. Un %%post qui
# echoue laisse au contraire le paquet installe, avec un avertissement
# (rpm-scriptlets(7), EXIT STATUS).
#
# La declaration n'est pas encore sur le disque. rpmbuild lit a la construction
# le fichier que %%install pose, par %%(cat ...), et le scriptlet le passe a
# systemd-sysusers sur son entree; --replace le tient pour
# /usr/lib/sysusers.d/bifrost.conf, si bien qu'une surcharge de
# l'administrateur sous /etc/sysusers.d garde la priorite. C'est la forme de
# %%sysusers_create_package de systemd, sans son `|| :`: ici un echec refuse.
# Le delimiteur est entre apostrophes parce que les commentaires de la
# declaration portent des mots entre accents graves, que le shell executerait.
#
# rpm 4.19 et suivants creent aussi les comptes de lui-meme juste avant ce
# %%pre, depuis les Provides user() et group() que rpmbuild 4.19 tire d'un
# fichier sysusers.d. Le .rpm de la CI est construit par le rpmbuild 4.18
# d'Ubuntu 24.04, qui n'en tire aucun: ce %%pre est donc le seul createur, et
# la ou rpm cree deja, il ne refait rien.
%pre
if ! command -v systemd-sysusers >/dev/null 2>&1; then
  echo "bifrost: systemd-sysusers absent, les comptes ne peuvent pas etre crees depuis /usr/lib/sysusers.d/bifrost.conf" >&2
  exit 1
fi
if ! systemd-sysusers --replace=/usr/lib/sysusers.d/bifrost.conf - <<'DECLARATION_BIFROST'
%(cat %{pkg_source}/sysusers.d/bifrost.conf)
DECLARATION_BIFROST
then
  echo "bifrost: systemd-sysusers a echoue, les comptes ne sont pas crees" >&2
  exit 1
fi
for compte in bifrost-coeur bifrost-resolveur; do
  if id -nG "$compte" | tr ' ' '\n' | grep -x bifrost >/dev/null; then
    echo "bifrost: REFUS, $compte appartient au groupe bifrost et pourrait piloter le daemon" >&2
    exit 1
  fi
done
if [ "$(id -u bifrost-coeur)" = "$(id -u bifrost-resolveur)" ]; then
  echo "bifrost: REFUS, bifrost-coeur et bifrost-resolveur partagent un uid" >&2
  exit 1
fi

# Miroir du reste de postinst: daemon-reload et le message de fin. Ni enable
# ni start, et plus aucun compte: ils sont crees et controles en %%pre.
%post
if [ -d /run/systemd/system ]; then
  systemctl daemon-reload
fi
echo "bifrost: installe. Le service n'est ni active ni demarre."
echo "  usermod -aG bifrost <utilisateur>   # l'etat, connect-stored et disconnect"
echo "  systemctl enable --now bifrost-daemon"
echo "Armer le kill switch coupe tout trafic hors tunnel, session SSH comprise."
echo "Apres une mise a jour, un service deja demarre garde l'ancien binaire jusqu'a son redemarrage."

# Miroir de prerm: a la desinstallation finale seulement ($1 = 0).
%preun
if [ "$1" = 0 ]; then
  if [ -d /run/systemd/system ]; then
    systemctl stop bifrost-daemon.service >/dev/null 2>&1 || :
  fi
  systemctl disable bifrost-daemon.service >/dev/null 2>&1 || :
  if command -v bifrost-daemon >/dev/null 2>&1; then
    bifrost-daemon --cleanup-firewall \
      || echo "bifrost: --cleanup-firewall a rendu un code non nul, verifier les filtres a la main" >&2
  fi
fi

# Miroir de postrm: daemon-reload; a la desinstallation finale, l'etat du
# daemon n'est retire que s'il est vide, les comptes sont conserves.
%postun
if [ -d /run/systemd/system ]; then
  systemctl daemon-reload >/dev/null 2>&1 || :
fi
if [ "$1" = 0 ]; then
  if [ -d /var/lib/bifrost ]; then
    rmdir --ignore-fail-on-non-empty /var/lib/bifrost
  fi
  if [ -d /var/lib/bifrost ]; then
    echo "bifrost: /var/lib/bifrost n'est pas vide et reste en place (etat du daemon)"
  fi
  echo "bifrost: les comptes systeme bifrost, bifrost-coeur et bifrost-resolveur sont conserves"
fi

%changelog
* Sat Oct 17 2026 Bifrost <security@inaricom.com> - @VERSION@-1
- Paquet du daemon Bifrost et de son client en ligne de commande.
