#!/usr/bin/env bash
# Installs v2rm with pipx (installing pipx first if it isn't already
# present) and runs `pipx ensurepath` so the `v2rm` command is on PATH
# afterward -- no manual `export PATH=...` step required.
#
# Usage: ./install.sh   (from a clone of this repo)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

have() { command -v "$1" >/dev/null 2>&1; }

if ! have pipx; then
    echo "pipx not found -- installing it..."
    if have apt-get; then
        if [ "$(id -u)" -eq 0 ]; then
            apt-get update -qq && apt-get install -y -qq pipx
        elif have sudo; then
            sudo apt-get update -qq && sudo apt-get install -y -qq pipx
        else
            python3 -m pip install --user --quiet pipx
        fi
    else
        python3 -m pip install --user --quiet pipx
    fi
fi

if ! have pipx; then
    # A --user pip install of pipx just now won't be on PATH in *this*
    # shell yet -- bootstrap it for the rest of this script only.
    export PATH="$HOME/.local/bin:$PATH"
fi

if ! have pipx; then
    echo "Could not find or install pipx. Install it manually, then re-run this script," >&2
    echo "or fall back to: pip install --user ." >&2
    exit 1
fi

echo "Installing v2rm..."
pipx install --force "$SCRIPT_DIR"

echo "Making sure v2rm is on PATH..."
pipx ensurepath

echo
if have v2rm; then
    echo "v2rm is installed and ready -- run: v2rm --help"
else
    echo "v2rm is installed. Open a new terminal (or run: source ~/.bashrc) so the"
    echo "updated PATH takes effect, then run: v2rm --help"
fi
