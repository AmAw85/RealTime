#!/bin/sh
# Installe les raccourcis fwmon : Bureau + menu Applications.
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$(readlink -f -- "$0")")" && pwd)
apps="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
desktop_dir=$(xdg-user-dir DESKTOP 2>/dev/null || echo "$HOME/Desktop")

chmod +x "$here/fwmonctl" "$here/fwmon.sh"
mkdir -p "$apps" "$desktop_dir"

make_entry() {  # $1=slug  $2=nom  $3=action  $4=icone
    slug=$1 name=$2 action=$3 icon=$4
    cat > "$apps/fwmon-$slug.desktop" <<EOF
[Desktop Entry]
Type=Application
Version=1.0
Name=$name
Comment=Surveillance reseau par application (fwmon)
Exec=$here/fwmonctl $action
Icon=$icon
Terminal=false
Categories=System;Monitor;
Keywords=reseau;network;fwmon;
StartupNotify=false
EOF
    desktop-file-validate "$apps/fwmon-$slug.desktop" 2>/dev/null || true
    cp -f "$apps/fwmon-$slug.desktop" "$desktop_dir/fwmon-$slug.desktop"
    chmod +x "$desktop_dir/fwmon-$slug.desktop"
}

make_entry lancer   "fwmon — Lancer la surveillance" start network-transmit-receive-symbolic
make_entry afficher "fwmon — Afficher"               show  view-restore-symbolic
make_entry fermer   "fwmon — Fermer"                 stop  application-exit-symbolic

if command -v gio >/dev/null 2>&1; then
    for f in "$desktop_dir"/fwmon-*.desktop; do
        gio set "$f" metadata::trusted true 2>/dev/null || true
    done
fi
command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database "$apps" 2>/dev/null || true

echo "Raccourcis installes :"
echo "  menu    : $apps/fwmon-{lancer,afficher,fermer}.desktop"
echo "  bureau  : $desktop_dir/fwmon-{lancer,afficher,fermer}.desktop"
echo "  commande: $here/fwmonctl start|show|stop|status"
