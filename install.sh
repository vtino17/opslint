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

die() { printf 'opslint installer: %s\n' "$*" >&2; exit 1; }

[[ "$DEST" == /* && "${DEST##*/}" == "opslint" && "$DEST" != *$'\n'* && "$DEST" != *$'\r'* ]] \
    || die "OPSLINT_DEST must be an absolute path whose final component is 'opslint'"
[[ "$BIN" == /* && "$BIN" != *$'\n'* && "$BIN" != *$'\r'* ]] \
    || die "OPSLINT_BIN must be an absolute path on one line"

echo "installing opslint into $DEST ..."
if command -v git >/dev/null 2>&1; then
    if [[ -d "$DEST/.git" ]]; then git -C "$DEST" pull --ff-only
    else git clone --depth 1 "$REPO" "$DEST"; fi
else
    tmp="$(mktemp -d)"; trap 'rm -rf -- "$tmp"' EXIT
    curl -fsSL "$REPO/archive/refs/heads/main.tar.gz" -o "$tmp/o.tgz"
    mkdir "$tmp/source"
    tar -C "$tmp/source" --strip-components=1 -xzf "$tmp/o.tgz"
    [[ -f "$tmp/source/opslint.py" && -d "$tmp/source/tools" ]] \
        || die "downloaded archive does not contain a valid OpsLint tree"
    mkdir -p "$(dirname "$DEST")"
    rm -rf -- "$DEST"
    mv "$tmp/source" "$DEST"
    trap - EXIT; rm -rf -- "$tmp"
fi
mkdir -p "$BIN"
chmod +x "$DEST/opslint.py" "$DEST"/tools/*.py 2>/dev/null || true
ln -sf "$DEST/opslint.py" "$BIN/opslint"
echo "done. try:  opslint audit"
