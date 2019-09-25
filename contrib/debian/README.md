
Debian
====================
This directory contains files used to package playervsplayercoind/playervsplayercoin-qt
for Debian-based Linux systems. If you compile playervsplayercoind/playervsplayercoin-qt yourself, there are some useful files here.

## playervsplayercoin: URI support ##


playervsplayercoin-qt.desktop  (Gnome / Open Desktop)
To install:

	sudo desktop-file-install playervsplayercoin-qt.desktop
	sudo update-desktop-database

If you build yourself, you will either need to modify the paths in
the .desktop file or copy or symlink your playervsplayercoin-qt binary to `/usr/bin`
and the `../../share/pixmaps/playervsplayercoin128.png` to `/usr/share/pixmaps`

playervsplayercoin-qt.protocol (KDE)

