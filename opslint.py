#!/usr/bin/env python3
"""opslint - one command to audit a Linux host's configuration hygiene.

opslint bundles six focused linters and runs them together, then rolls their
findings up into a single severity summary, a 0-100 score, and one exit code:

  * sshaudit    - sshd_config and authorized_keys (weak crypto, risky auth)
  * sudoerslint - dangerous sudoers rules (NOPASSWD ALL, shell-escape grants)
  * fstablint   - /etc/fstab hardening and boot safety
  * cronlint    - crontab footguns
  * envlint     - secrets and exposure in .env / docker-compose
  * nginxdoctor - nginx security config

Usage:
    opslint audit                 # audit this host at the standard /etc paths
    opslint audit --dir ./config  # audit a directory of config files instead
    opslint ssh|sudo|fstab|cron|env|nginx [args...]   # run one tool directly

It reads files only and changes nothing. Exit status is non-zero if the audit
finds anything HIGH or CRITICAL, so it drops into CI or a cron check.
"""
from __future__ import annotations

import argparse
import glob
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TOOLS = os.path.join(HERE, "tools")

# subcommand -> vendored script
SCRIPTS = {
    "ssh": "sshaudit.py",
    "sudo": "sudoerslint.py",
    "fstab": "fstablint.py",
    "cron": "cronlint.py",
    "env": "envlint.py",
    "nginx": "nginxdoctor.py",
    "sysctl": "sysctlaudit.py",
    "unit": "unitcheck.py",
}

# severity token -> (score weight, is-failing)
WEIGHT = {
    "CRITICAL": (25, True), "ERROR": (10, True), "HIGH": (10, True),
    "MEDIUM": (4, False), "WARN": (4, False), "LOW": (1, False),
    "INFO": (0, False),
}
LEVEL_RE = re.compile(r"^\s*(?:\[)?(CRITICAL|ERROR|HIGH|MEDIUM|WARN|LOW|INFO)\b")
COLOR = {"CRITICAL": "\033[1;31m", "ERROR": "\033[1;31m", "HIGH": "\033[31m",
         "MEDIUM": "\033[33m", "WARN": "\033[33m", "LOW": "\033[36m", "OK": "\033[32m"}
RESET = "\033[0m"
TOOL_TIMEOUT_SECONDS = 30


def run_script(name: str, args: list[str]) -> tuple[int, str]:
    path = os.path.join(TOOLS, name)
    try:
        proc = subprocess.run(
            [sys.executable, path, *args],
            capture_output=True,
            text=True,
            timeout=TOOL_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return 124, f"{name} timed out after {TOOL_TIMEOUT_SECONDS} seconds\n"
    except OSError as exc:
        return 126, f"unable to run {name}: {exc}\n"
    return proc.returncode, proc.stdout + proc.stderr


def parse_findings(output: str) -> list[tuple[str, str]]:
    """Return (level, detail) for each finding line the tool printed."""
    found: list[tuple[str, str]] = []
    for line in output.splitlines():
        m = LEVEL_RE.match(line)
        if m:
            detail = line[m.end():].strip().lstrip("]").strip()
            found.append((m.group(1), detail))
    return found


# ---- target discovery -----------------------------------------------------

def _first_existing(*paths: str) -> list[str]:
    return [p for p in paths if os.path.exists(p)]


def discover(base: str | None) -> list[tuple[str, str, list[str]]]:
    """Return (label, script, args) jobs for whichever targets exist."""
    jobs: list[tuple[str, str, list[str]]] = []

    def add(label: str, script: str, args: list[str]):
        jobs.append((label, script, args))

    if base:
        b = base
        # ssh
        for p in _first_existing(os.path.join(b, "sshd_config")):
            add("ssh", "sshaudit.py", ["sshd", "--config", p, "--no-color"])
        for p in _first_existing(os.path.join(b, "authorized_keys")):
            add("ssh-keys", "sshaudit.py", ["keys", "--file", p, "--no-color"])
        # sudoers
        sud = _first_existing(os.path.join(b, "sudoers")) + sorted(glob.glob(os.path.join(b, "sudoers.d", "*")))
        if sud:
            add("sudo", "sudoerslint.py", sud + ["--no-color"])
        # fstab
        for p in _first_existing(os.path.join(b, "fstab")):
            add("fstab", "fstablint.py", [p, "--no-color"])
        # cron
        crons = sorted(glob.glob(os.path.join(b, "crontab*"))) + sorted(glob.glob(os.path.join(b, "cron.d", "*")))
        for p in crons:
            add("cron", "cronlint.py", [p, "--no-color"])
        # env / compose
        envs = (sorted(glob.glob(os.path.join(b, ".env*"))) +
                sorted(glob.glob(os.path.join(b, "*compose*.y*ml"))))
        if envs:
            add("env", "envlint.py", envs + ["--no-color"])
        # nginx
        ngx = (sorted(glob.glob(os.path.join(b, "nginx.conf"))) +
               sorted(glob.glob(os.path.join(b, "*.conf"))) +
               sorted(glob.glob(os.path.join(b, "sites-enabled", "*"))))
        ngx = [p for p in dict.fromkeys(ngx) if os.path.isfile(p)]
        # exclude sysctl .conf files misfiled as nginx (they get their own job)
        ngx = [p for p in ngx if os.path.basename(p) != "sysctl.conf"]
        if ngx:
            add("nginx", "nginxdoctor.py", ngx + ["--no-color"])
        # sysctl
        sysctl = _first_existing(os.path.join(b, "sysctl.conf"))
        if os.path.isdir(os.path.join(b, "sysctl.d")):
            sysctl.append(os.path.join(b, "sysctl.d"))
        if sysctl:
            add("sysctl", "sysctlaudit.py", sysctl + ["--no-color"])
        # systemd units (a repo's own .service files)
        units = sorted(glob.glob(os.path.join(b, "*.service")))
        for u in units:
            add("unit", "unitcheck.py", [u, "--no-color"])
    else:
        # system defaults
        for p in _first_existing("/etc/ssh/sshd_config"):
            add("ssh", "sshaudit.py", ["sshd", "--config", p, "--no-color"])
        sud = _first_existing("/etc/sudoers") + sorted(glob.glob("/etc/sudoers.d/*"))
        if sud:
            add("sudo", "sudoerslint.py", sud + ["--no-color"])
        for p in _first_existing("/etc/fstab"):
            add("fstab", "fstablint.py", [p, "--no-color"])
        crons = _first_existing("/etc/crontab") + sorted(glob.glob("/etc/cron.d/*"))
        crons = [p for p in crons if os.path.isfile(p)]
        for p in crons:
            add("cron", "cronlint.py", [p, "--system", "--no-color"])
        ngx = _first_existing("/etc/nginx/nginx.conf") + sorted(glob.glob("/etc/nginx/sites-enabled/*"))
        ngx = [p for p in ngx if os.path.isfile(p)]
        if ngx:
            add("nginx", "nginxdoctor.py", ngx + ["--no-color"])
        # sysctl config (files only; the running kernel is a separate concern)
        sysctl = _first_existing("/etc/sysctl.conf")
        if os.path.isdir("/etc/sysctl.d"):
            sysctl.append("/etc/sysctl.d")
        if sysctl:
            add("sysctl", "sysctlaudit.py", sysctl + ["--no-color"])
        # note: system .service units are deliberately not swept here - most are
        # vendor units that legitimately need privileges. Use 'opslint unit <f>'
        # or 'opslint audit --dir' on a repo of your own units.
    return jobs


def cmd_audit(a: argparse.Namespace) -> int:
    if a.dir and not os.path.isdir(a.dir):
        print(f"opslint: audit target is not a readable directory: {a.dir}", file=sys.stderr)
        return 2
    use_color = sys.stdout.isatty() and not a.no_color
    jobs = discover(a.dir)
    if not jobs:
        where = a.dir or "the standard /etc paths"
        print(f"opslint: nothing to audit under {where}")
        print("  (point --dir at a folder with sshd_config, sudoers, fstab, .env, *.conf, ...)")
        return 0

    total: dict[str, int] = {}
    score = 100
    records: list[dict[str, str]] = []
    for label, script, args in jobs:
        rc, output = run_script(script, args)
        findings = parse_findings(output)
        if rc not in (0, 1):
            detail = next(
                (line.strip() for line in output.splitlines() if line.strip()),
                f"{script} exited with status {rc}",
            )
            findings.append(("ERROR", f"tool execution failed (exit {rc}): {detail}"))
        if not a.json:
            print(f"\n### {label} ({script})")
            body = output.strip("\n")
            if body:
                print(body)
            if rc not in (0, 1):
                print(f"ERROR tool execution failed with exit status {rc}")
        for lvl, detail in findings:
            total[lvl] = total.get(lvl, 0) + 1
            score -= WEIGHT.get(lvl, (0, False))[0]
            records.append({"tool": label, "level": lvl, "detail": detail})

    score = max(0, score)
    failing = any(WEIGHT.get(l, (0, False))[1] for l in total)
    band = "good" if score >= 85 else "needs work" if score >= 60 else "poor"

    if a.json:
        import json
        print(json.dumps({
            "score": score,
            "band": band,
            "failed": failing,
            "counts": total,
            "findings": records,
        }, indent=2))
        return 1 if failing else 0

    print("\n" + "=" * 60)
    summary = (", ".join(f"{n} {lvl.lower()}" for lvl, n in
               sorted(total.items(), key=lambda kv: -WEIGHT.get(kv[0], (0,))[0]))
               if total else "no findings")
    line = f"opslint score: {score}/100 ({band}) - {summary}"
    if use_color:
        col = COLOR["OK"] if score >= 85 else COLOR["WARN"] if score >= 60 else COLOR["HIGH"]
        line = f"{col}{line}{RESET}"
    print(line)
    return 1 if failing else 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="opslint", description="audit a host's config hygiene with one command")
    p.add_argument("--no-color", action="store_true")
    sub = p.add_subparsers(dest="command", required=True)

    au = sub.add_parser("audit", help="run every applicable linter and roll up a score")
    au.add_argument("--dir", help="audit config files under this directory instead of /etc")
    au.add_argument("--json", action="store_true", help="emit machine-readable JSON (score + findings) for CI")
    au.add_argument("--no-color", action="store_true")

    for name in SCRIPTS:
        sp = sub.add_parser(name, help=f"run {SCRIPTS[name]} directly")
        sp.add_argument("args", nargs=argparse.REMAINDER)

    a = p.parse_args(argv)
    if a.command == "audit":
        return cmd_audit(a)
    rc, output = run_script(SCRIPTS[a.command], a.args)
    print(output, end="")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
