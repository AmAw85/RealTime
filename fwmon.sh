#!/bin/sh
# Lanceur fwmon — necessite sudox pour la collecte privilegiee.
# Resout le lien symbolique (~/.local/bin/fwmon) avant de chercher le depot.
self=$0
if command -v readlink >/dev/null 2>&1; then
    resolved=$(readlink -f -- "$0" 2>/dev/null) && [ -n "$resolved" ] && self=$resolved
fi
here=$(CDPATH= cd -- "$(dirname -- "$self")" && pwd)
exec python3 "$here/fwmon/app.py" "$@"
