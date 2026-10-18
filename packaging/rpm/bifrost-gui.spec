## Gabarit RPM du paquet de la coquille graphique de Bifrost (Fedora, RHEL).
##
## @VERSION@ est remplace a la construction par la version du workspace
## (Cargo.toml, [workspace.package]), par scripts/paquets-gui-linux.sh: la meme
## source que le control du .deb de la coquille et que le paquet du daemon.
##
## Le binaire n'est pas compile par rpmbuild: la coquille est deja construite
## (cargo build --release --manifest-path gui/Cargo.toml --locked) et copiee
## dans le BUILDROOT par %%install, depuis les chemins passes en --define par le
## script, comme les icones, ecrites par bifrost-icone. Il n'y a donc ni %%prep
## ni %%build.
##
## Ce paquet pose ce que pose le .deb de la coquille, aux memes modes, a son
## fichier de copyright pres (/usr/share/licenses au lieu de /usr/share/doc).
## crates/bifrost-evasion/tests/paquets_linux.rs garde cette parite.

Name:           bifrost-gui
Version:        @VERSION@
Release:        1%{?dist}
Summary:        Coquille graphique de Bifrost, sans privilege

License:        MPL-2.0
URL:            https://github.com/Musyg/bifrost-vpn
Packager:       Bifrost <security@inaricom.com>
Vendor:         Bifrost
BuildArch:      x86_64

# Les bibliotheques liees (WebKitGTK, GTK, GLib...): rpmbuild en engendre les
# Requires par soname en lisant le binaire, l'equivalent de dpkg-shlibdeps.
# La bibliotheque de la zone de notification est chargee a l'execution
# (dlopen), donc invisible a ce calcul: elle est declaree par son soname, celui
# que le .deb retient. Le theme d'icones n'est pas une bibliotheque. Le daemon
# (paquet bifrost) est recommande: sans lui, la coquille dit qu'il est
# injoignable.
Requires:       libayatana-appindicator3.so.1()(64bit)
Requires:       hicolor-icon-theme
Recommends:     bifrost

%description
Bifrost est un VPN auto-heberge. Ce paquet pose sa coquille graphique: une
fenetre et une icone de zone de notification qui montrent l'etat du tunnel et
du kill switch, connectent au profil que le daemon detient et deconnectent.
Elle refuse de demarrer en root et ne parle au daemon que par son socket, dont
elle verifie qu'il est tenu par root avant d'y ecrire.

Le groupe bifrost, que cree le paquet bifrost, n'a que trois commandes du canal
du daemon: l'etat, connect-stored et disconnect, ce que la coquille offre. root
garde tout le canal.

Pas de demarrage automatique: le paquet pose une entree de menu, aucune entree
de demarrage de session.

%install
# gui_bindir: le repertoire du binaire de la coquille; pkg_source: le
# repertoire packaging/ du depot; icones_source: le repertoire ou bifrost-icone
# a ecrit ses PNG. Passes par le script, jamais devines.
install -D -m 0755 %{gui_bindir}/bifrost-gui %{buildroot}/usr/bin/bifrost-gui
install -D -m 0644 %{pkg_source}/desktop/io.github.musyg.bifrost-vpn.desktop %{buildroot}/usr/share/applications/io.github.musyg.bifrost-vpn.desktop
install -D -m 0644 %{pkg_source}/deb-gui/copyright %{buildroot}/usr/share/licenses/bifrost-gui/copyright
# Pose non compressee: brp-compress la recomprime (voir %%files).
install -D -m 0644 %{pkg_source}/man/bifrost-gui.1 %{buildroot}/usr/share/man/man1/bifrost-gui.1
# Une icone par cote de COTES_HICOLOR (crates/bifrost-icone), sous le nom de
# l'identifiant de l'application (gui/tauri.conf.json). rpm exige une liste
# explicite; la recette du depot l'aligne sur COTES_HICOLOR.
install -D -m 0644 %{icones_source}/bifrost-16.png %{buildroot}/usr/share/icons/hicolor/16x16/apps/io.github.musyg.bifrost-vpn.png
install -D -m 0644 %{icones_source}/bifrost-24.png %{buildroot}/usr/share/icons/hicolor/24x24/apps/io.github.musyg.bifrost-vpn.png
install -D -m 0644 %{icones_source}/bifrost-32.png %{buildroot}/usr/share/icons/hicolor/32x32/apps/io.github.musyg.bifrost-vpn.png
install -D -m 0644 %{icones_source}/bifrost-48.png %{buildroot}/usr/share/icons/hicolor/48x48/apps/io.github.musyg.bifrost-vpn.png
install -D -m 0644 %{icones_source}/bifrost-64.png %{buildroot}/usr/share/icons/hicolor/64x64/apps/io.github.musyg.bifrost-vpn.png
install -D -m 0644 %{icones_source}/bifrost-128.png %{buildroot}/usr/share/icons/hicolor/128x128/apps/io.github.musyg.bifrost-vpn.png
install -D -m 0644 %{icones_source}/bifrost-256.png %{buildroot}/usr/share/icons/hicolor/256x256/apps/io.github.musyg.bifrost-vpn.png

%files
%license /usr/share/licenses/bifrost-gui/copyright
/usr/bin/bifrost-gui
/usr/share/applications/io.github.musyg.bifrost-vpn.desktop
/usr/share/icons/hicolor/16x16/apps/io.github.musyg.bifrost-vpn.png
/usr/share/icons/hicolor/24x24/apps/io.github.musyg.bifrost-vpn.png
/usr/share/icons/hicolor/32x32/apps/io.github.musyg.bifrost-vpn.png
/usr/share/icons/hicolor/48x48/apps/io.github.musyg.bifrost-vpn.png
/usr/share/icons/hicolor/64x64/apps/io.github.musyg.bifrost-vpn.png
/usr/share/icons/hicolor/128x128/apps/io.github.musyg.bifrost-vpn.png
/usr/share/icons/hicolor/256x256/apps/io.github.musyg.bifrost-vpn.png
/usr/share/man/man1/bifrost-gui.1.gz

# Aucun scriptlet: ni service, ni compte, ni pare-feu. Le cache d'icones et la
# base des entrees de bureau sont mis a jour par les declencheurs de leurs
# propres paquets.

%changelog
* Sun Oct 18 2026 Bifrost <security@inaricom.com> - @VERSION@-1
- Paquet de la coquille graphique de Bifrost.
