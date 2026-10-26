#!/bin/sh
# Installe fwmon dans ~/.local/bin (lien symbolique vers le lanceur du depot).
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
dest="${1:-$HOME/.local/bin}"

if [ ! -f "$here/fwmon/app.py" ]; then
    echo "install.sh : lancez ce script depuis le dossier fwmon" >&2
    exit 1
fi

mkdir -p "$dest"
chmod +x "$here/fwmon.sh"
ln -sf "$here/fwmon.sh" "$dest/fwmon"

echo "fwmon installe : $dest/fwmon"
echo "lancement      : fwmon"

if command -v sudox >/dev/null 2>&1; then
    echo "sudox          : $(command -v sudox)"
elif [ -x "$HOME/.local/bin/sudox" ]; then
    echo "sudox          : $HOME/.local/bin/sudox"
else
    echo "attention      : sudox introuvable — la collecte sera limitee a votre utilisateur"
fi
