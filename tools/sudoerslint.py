#!/usr/bin/env python3
"""sudoerslint - flag dangerous rules in sudoers files.

`visudo -c` tells you a sudoers file *parses*. It does not tell you that the rule
you just added lets a user become root. sudoerslint reads sudoers files and
reports the risky patterns:

  * passwordless full sudo (``NOPASSWD: ALL``);
  * a sudo grant to a binary that can spawn a shell - vim, less, find, tar,
    python and friends (a GTFOBins-style privilege escalation): being allowed to
    run ``sudo vim`` is being allowed to run ``sudo`` anything;
  * ``Defaults !authenticate`` / ``!env_reset`` and ``env_keep`` entries that
    preserve ``LD_PRELOAD`` and similar;
  * wildcards in a command path, which are routinely abused to run unintended
    commands.

It reads files only and changes nothing.

    sudoerslint /etc/sudoers
    sudoerslint /etc/sudoers.d/*

Exit status is non-zero on any HIGH or CRITICAL finding.
"""
from __future__ import annotations

import argparse
import os
import re
import sys

# Binaries that can break out to a shell when run under sudo (GTFOBins-informed).
# name -> how it escapes
SHELL_ESCAPE = {
    "vi": "`:!sh`", "vim": "`:!sh`", "view": "`:!sh`", "rvim": "shell", "nano": "^R^X",
    "less": "`!sh`", "more": "`!sh`", "man": "`!sh`", "pager": "shell",
    "find": "-exec /bin/sh", "awk": "system()", "gawk": "system()", "sed": "e command",
    "ed": "!sh", "vimdiff": "shell",
    "python": "os.system", "python2": "os.system", "python3": "os.system",
    "perl": "exec", "ruby": "exec", "node": "child_process", "php": "system",
    "lua": "os.execute", "gdb": "!sh", "nmap": "--interactive / NSE",
    "env": "env /bin/sh", "tar": "--checkpoint-action=exec", "zip": "-T -TT",
    "ftp": "!sh", "smbclient": "!sh", "socat": "exec", "expect": "spawn sh",
    "screen": "shell", "tmux": "shell", "git": "PAGER / hooks", "ssh": "ProxyCommand",
    "make": "recipe", "cpan": "! sh", "bundle": "exec", "busybox": "sh",
    "systemctl": "pager -> !sh", "journalctl": "pager -> !sh", "crontab": "-e editor",
    "mount": "shell via helper", "docker": "run -v / mounts host root",
    "apt": "APT::Update::Pre-Invoke", "apt-get": "APT::Update::Pre-Invoke",
    "dpkg": "hooks", "puppet": "apply", "cpulimit": "-f",
    "sh": "is a shell", "bash": "is a shell", "dash": "is a shell",
    "zsh": "is a shell", "ksh": "is a shell", "fish": "is a shell",
}

# env vars that let a preserved value hijack a privileged process
DANGEROUS_ENV = {"LD_PRELOAD", "LD_LIBRARY_PATH", "PYTHONPATH", "PERL5LIB",
                 "RUBYLIB", "BASH_ENV", "ENV", "IFS", "PATH"}


class Finding:
    def __init__(self, level: str, where: str, msg: str):
        self.level, self.where, self.msg = level, where, msg


def _basename(cmd: str) -> str:
    cmd = cmd.strip().strip('"')
    first = cmd.split()[0] if cmd.split() else cmd
    return os.path.basename(first)


def _parse_commands(spec: str) -> list[tuple[bool, str]]:
    """Return (nopasswd, command) for each command in the spec after 'host='."""
    # drop a leading runas group like (ALL:ALL) or (root)
    spec = spec.strip()
    spec = re.sub(r"^\([^)]*\)\s*", "", spec)
    result: list[tuple[bool, str]] = []
    nopasswd = False
    for item in spec.split(","):
        item = item.strip()
        if not item:
            continue
        # tags before the command; NOPASSWD:/PASSWD: toggle, others we strip
        while True:
            m = re.match(r"([A-Z_]+):\s*(.*)$", item)
            if not m:
                break
            tag, item = m.group(1), m.group(2).strip()
            if tag == "NOPASSWD":
                nopasswd = True
            elif tag == "PASSWD":
                nopasswd = False
            # NOEXEC/SETENV/LOG_INPUT/etc: ignore, keep scanning
        if item:
            result.append((nopasswd, item))
    return result


def audit_file(path: str) -> list[Finding]:
    out: list[Finding] = []
    base = os.path.basename(path)
    cmnd_alias: dict[str, list[str]] = {}

    with open(path, encoding="utf-8", errors="replace") as fh:
        raw_lines = fh.readlines()

    # join line continuations (backslash-newline)
    lines: list[tuple[int, str]] = []
    buf = ""
    start = 0
    for i, raw in enumerate(raw_lines, 1):
        s = raw.rstrip("\n")
        if not buf:
            start = i
        if s.endswith("\\"):
            buf += s[:-1]
            continue
        buf += s
        lines.append((start, buf))
        buf = ""
    if buf:
        lines.append((start, buf))

    # first pass: collect Cmnd_Alias so we can resolve them
    for _ln, line in lines:
        m = re.match(r"\s*Cmnd_Alias\s+([A-Z0-9_]+)\s*=\s*(.+)$", line)
        if m:
            cmnd_alias[m.group(1)] = [c.strip() for c in m.group(2).split(",")]

    for ln, line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        where = f"{base}:{ln}"

        # Defaults lines
        if stripped.startswith("Defaults"):
            body = stripped
            if re.search(r"!\s*authenticate", body):
                out.append(Finding("HIGH", where, "Defaults !authenticate disables the sudo password prompt"))
            if re.search(r"!\s*env_reset", body):
                out.append(Finding("HIGH", where, "Defaults !env_reset keeps the caller's environment (privesc risk)"))
            mk = re.search(r"env_keep\s*[+]?=\s*\"?([^\"]+)\"?", body)
            if mk:
                kept = set(re.split(r"[\s,]+", mk.group(1)))
                bad = sorted(kept & DANGEROUS_ENV)
                if bad:
                    out.append(Finding("HIGH", where, f"env_keep preserves dangerous variable(s): {', '.join(bad)}"))
            if re.search(r"\btargetpw\b|\brootpw\b", body):
                pass  # informational only; not flagged
            continue

        # alias / other definitions we don't treat as user specs
        if re.match(r"\s*(User_Alias|Runas_Alias|Host_Alias|Cmnd_Alias)\b", stripped):
            continue

        # user spec: who host = spec
        if "=" not in stripped:
            continue
        lhs, _, spec = stripped.partition("=")
        # the left side is "user host [host...]"; the rule subject is the first token
        who = lhs.split()[0] if lhs.split() else lhs.strip()

        for nopasswd, cmd in _parse_commands(spec):
            # resolve a command alias
            targets = cmnd_alias.get(cmd, [cmd])
            for target in targets:
                tclean = target.strip()
                is_all = tclean == "ALL"
                name = _basename(tclean)

                if is_all and nopasswd:
                    out.append(Finding("CRITICAL", where,
                        f"{who}: passwordless full sudo (NOPASSWD: ALL) - complete root access, no password"))
                elif is_all and who.upper() != "ROOT":
                    out.append(Finding("MEDIUM", where, f"{who}: unrestricted sudo (ALL commands)"))

                if not is_all and name in SHELL_ESCAPE:
                    sev = "HIGH" if nopasswd else "MEDIUM"
                    tag = "NOPASSWD " if nopasswd else ""
                    out.append(Finding(sev, where,
                        f"{who}: {tag}sudo to '{name}' allows a shell escape ({SHELL_ESCAPE[name]}) = root shell"))

                if not is_all and "*" in tclean:
                    out.append(Finding("MEDIUM", where,
                        f"{who}: wildcard in command '{tclean}' can be abused to run unintended commands"))

    if not out:
        out.append(Finding("OK", base, "no risky rules found"))
    return out


RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "OK": 0}
COLOR = {"CRITICAL": "\033[1;31m", "HIGH": "\033[31m", "MEDIUM": "\033[33m",
         "LOW": "\033[36m", "OK": "\033[32m"}
RESET = "\033[0m"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="sudoerslint", description="flag dangerous sudoers rules")
    p.add_argument("files", nargs="+")
    p.add_argument("--no-color", action="store_true")
    a = p.parse_args(argv)
    use_color = sys.stdout.isatty() and not a.no_color

    worst = 0
    for path in a.files:
        findings = audit_file(path)
        print(f"== {path} ==")
        for f in sorted(findings, key=lambda x: -RANK[x.level]):
            worst = max(worst, RANK[f.level])
            tag = f"{COLOR[f.level]}{f.level:<8}{RESET}" if use_color else f"{f.level:<8}"
            print(f"  {tag} {f.where}: {f.msg}")
    return 1 if worst >= RANK["HIGH"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
