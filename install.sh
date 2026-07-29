#!/usr/bin/env bash
# opslint installer. Clones the suite and symlinks opslint onto your PATH.
#
#   curl -fsSL https://raw.githubusercontent.com/vtino17/opslint/main/install.sh | sudo bash
#
# Overrides: OPSLINT_REPO, OPSLINT_DEST (default /opt/opslint), OPSLINT_BIN (/usr/local/bin)
set -euo pipefail
REPO="${OPSLINT_REPO:-https://github.com/vtino17/opslint}"
DEST="${OPSLINT_DEST:-/opt/opslint}"
BIN="${OPSLINT_BIN:-/usr/local/bin}"

echo "installing opslint into $DEST ..."
if command -v git >/dev/null 2>&1; then
    if [[ -d "$DEST/.git" ]]; then git -C "$DEST" pull --ff-only
    else git clone --depth 1 "$REPO" "$DEST"; fi
else
    tmp="$(mktemp -d)"
    curl -fsSL "$REPO/archive/refs/heads/main.tar.gz" -o "$tmp/o.tgz"
    tar -C "$tmp" -xzf "$tmp/o.tgz"; rm -rf "$DEST"; mv "$tmp"/opslint-* "$DEST"; rm -rf "$tmp"
fi
chmod +x "$DEST/opslint.py" "$DEST"/tools/*.py 2>/dev/null || true
ln -sf "$DEST/opslint.py" "$BIN/opslint"
echo "done. try:  opslint audit"
