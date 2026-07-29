#!/usr/bin/env bash
# opslint tests. Read-only; builds a fixture config dir in a temp location.
set -uo pipefail
cd "$(dirname "$0")/.."
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
for t in sshaudit sudoerslint fstablint cronlint envlint nginxdoctor; do
    if [[ -f "tools/$t.py" ]]; then printf '  PASS  bundled %s\n' "$t"; pass=$((pass+1))
    else printf '  FAIL  missing bundled %s\n' "$t"; fail=$((fail+1)); fi
done

# a fixture directory with one problem per tool
F="$T/cfg"; mkdir -p "$F/sudoers.d"
printf 'PermitRootLogin yes\n'            > "$F/sshd_config"
printf 'alice ALL=(ALL) NOPASSWD: ALL\n'  > "$F/sudoers.d/ops"
printf 'tmpfs /tmp tmpfs defaults 0 0\n'  > "$F/fstab"
printf 'DB_PASSWORD=changeme\n'           > "$F/.env"
printf 'http { server { listen 443 ssl; ssl_protocols TLSv1; } }\n' > "$F/nginx.conf"

echo "== aggregate audit =="
assert "runs ssh check"       "PermitRootLogin"            -- $OL audit --dir "$F" --no-color
assert "runs sudo check"      "passwordless full sudo"     -- $OL audit --dir "$F" --no-color
assert "runs fstab check"     "/tmp is missing"            -- $OL audit --dir "$F" --no-color
assert "runs env check"       "weak/default value"         -- $OL audit --dir "$F" --no-color
assert "runs nginx check"     "obsolete TLSv1"             -- $OL audit --dir "$F" --no-color
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

echo "== passthrough to a single tool =="
printf 'bob ALL=(ALL) NOPASSWD: /usr/bin/vim\n' > "$T/sudoers"
assert "passthrough runs sudoerslint" "shell escape" -- $OL sudo "$T/sudoers" --no-color

echo
echo "== $pass passed, $fail failed =="
[[ $fail -eq 0 ]]
