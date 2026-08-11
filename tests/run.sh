#!/usr/bin/env bash
# opslint tests. Read-only; builds a fixture config dir in a temp location.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
OL="python3 opslint.py"
pass=0; fail=0
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT

assert() {   # <desc> <expect> -- <cmd...>
    local desc="$1" expect="$2"; shift 2; [[ "$1" == "--" ]] && shift
    local out; out="$("$@" 2>&1)"
    if grep -qF -- "$expect" <<<"$out"; then printf '  PASS  %s\n' "$desc"; pass=$((pass+1))
    else printf '  FAIL  %s\n        wanted: %s\n        got: %s\n' "$desc" "$expect" "$out"; fail=$((fail+1)); fi
}
assert_exit() {  # <desc> <code> -- <cmd...>
    local desc="$1" want="$2"; shift 2; [[ "$1" == "--" ]] && shift
    "$@" >/dev/null 2>&1; local rc=$?
    if [[ "$rc" == "$want" ]]; then printf '  PASS  %s\n' "$desc"; pass=$((pass+1))
    else printf '  FAIL  %s (exit %s want %s)\n' "$desc" "$rc" "$want"; fail=$((fail+1)); fi
}

echo "== syntax & bundled tools =="
if python3 -c "import ast; ast.parse(open('opslint.py').read())"; then
    echo "  PASS  opslint.py parses"; pass=$((pass+1))
else echo "  FAIL  syntax"; fail=$((fail+1)); fi
for t in sshaudit sudoerslint fstablint cronlint envlint nginxdoctor sysctlaudit unitcheck; do
    if [[ -f "tools/$t.py" ]]; then printf '  PASS  bundled %s\n' "$t"; pass=$((pass+1))
    else printf '  FAIL  missing bundled %s\n' "$t"; fail=$((fail+1)); fi
done

echo "== installer path safety =="
assert "installer rejects root destination" "final component is 'opslint'" -- env OPSLINT_DEST=/ bash install.sh
assert_exit "installer rejects root destination with non-zero exit" 1 -- env OPSLINT_DEST=/ bash install.sh
assert "installer rejects unrelated destination" "final component is 'opslint'" -- env OPSLINT_DEST=/opt/other-tool bash install.sh
assert "installer rejects relative bin path" "OPSLINT_BIN must be an absolute path" -- env OPSLINT_BIN=bin bash install.sh

# a fixture directory with one problem per tool
F="$T/cfg"; mkdir -p "$F/sudoers.d"
printf 'PermitRootLogin yes\n'            > "$F/sshd_config"
printf 'alice ALL=(ALL) NOPASSWD: ALL\n'  > "$F/sudoers.d/ops"
printf 'tmpfs /tmp tmpfs defaults 0 0\n'  > "$F/fstab"
printf 'DB_PASSWORD=changeme\n'           > "$F/.env"
printf 'http { server { listen 443 ssl; ssl_protocols TLSv1; } }\n' > "$F/nginx.conf"
printf 'net.ipv4.tcp_syncookies = 0\n' > "$F/sysctl.conf"
printf '[Service]\nExecStart=/usr/bin/app\n' > "$F/app.service"

echo "== aggregate audit =="
assert "runs ssh check"       "PermitRootLogin"            -- $OL audit --dir "$F" --no-color
assert "runs sudo check"      "passwordless full sudo"     -- $OL audit --dir "$F" --no-color
assert "runs fstab check"     "/tmp is missing"            -- $OL audit --dir "$F" --no-color
assert "runs env check"       "weak/default value"         -- $OL audit --dir "$F" --no-color
assert "runs nginx check"     "obsolete TLSv1"             -- $OL audit --dir "$F" --no-color
assert "runs sysctl check"    "tcp_syncookies"             -- $OL audit --dir "$F" --no-color
assert "runs unit check"      "runs as root"               -- $OL audit --dir "$F" --no-color
assert "prints a rolled-up score" "opslint score:"        -- $OL audit --dir "$F" --no-color
assert "aggregates critical"  "critical"                   -- $OL audit --dir "$F" --no-color
assert_exit "findings -> non-zero exit" 1 -- $OL audit --dir "$F" --no-color

echo "== clean config scores 100 =="
C="$T/clean"; mkdir -p "$C"
printf 'UUID=r / ext4 defaults 0 1\n' > "$C/fstab"
printf 'DEBUG=true\n' > "$C/.env"
assert "clean scores 100"     "score: 100/100"             -- $OL audit --dir "$C" --no-color
assert_exit "clean exits zero" 0 -- $OL audit --dir "$C" --no-color

echo "== empty dir is handled =="
E="$T/empty"; mkdir -p "$E"
assert "empty dir is graceful" "nothing to audit"          -- $OL audit --dir "$E" --no-color
assert_exit "empty dir exits zero" 0 -- $OL audit --dir "$E" --no-color
assert "missing audit target is rejected" "not a readable directory" -- $OL audit --dir "$T/missing" --no-color
assert_exit "missing audit target exits two" 2 -- $OL audit --dir "$T/missing" --no-color

echo "== passthrough to a single tool =="
printf 'bob ALL=(ALL) NOPASSWD: /usr/bin/vim\n' > "$T/sudoers"
assert "passthrough runs sudoerslint" "shell escape" -- $OL sudo "$T/sudoers" --no-color

echo "== JSON output for CI =="
# capture the JSON first: opslint intentionally exits non-zero on findings, and
# with 'set -o pipefail' that would mask the parser's own result.
_json="$($OL audit --dir "$F" --json || true)"
if printf '%s' "$_json" | python3 -c "import json,sys; d=json.load(sys.stdin); assert 'score' in d and 'findings' in d and d['failed'] is True and len(d['findings'])>0"; then
    printf '  PASS  %s\n' "audit --json is valid, well-shaped JSON"; pass=$((pass+1))
else printf '  FAIL  %s\n' "audit --json JSON shape"; fail=$((fail+1)); fi
assert "json findings carry tool+level" '"level": "CRITICAL"' -- $OL audit --dir "$F" --json

echo "== bundled tool failures fail closed =="
_broken="$(python3 - "$F" <<'PY' || true
import opslint
import sys

opslint.TOOLS = sys.argv[1]  # fixture has targets, but deliberately no tool scripts
raise SystemExit(opslint.main(["audit", "--dir", sys.argv[1], "--json"]))
PY
)"
if printf '%s' "$_broken" | python3 -c "import json,sys; d=json.load(sys.stdin); assert d['failed'] is True and d['counts']['ERROR'] > 0"; then
    printf '  PASS  %s\n' "a missing bundled tool produces a failing ERROR finding"; pass=$((pass+1))
else printf '  FAIL  %s\n' "bundled tool failure was ignored"; fail=$((fail+1)); fi

echo
echo "== $pass passed, $fail failed =="
[[ $fail -eq 0 ]]
