#!/usr/bin/env python3
"""envlint - catch secrets and exposure mistakes in .env and compose files.

Two files leak more than their share of production incidents: a ``.env`` with a
real secret that ends up committed, and a ``docker-compose.yml`` that publishes a
database port to every interface or runs a container ``privileged``. envlint
scans both before you commit them.

    envlint .env docker-compose.yml
    envlint .                      # scan a directory for both

It is a single Python file with no dependencies - the scanning is pattern-based,
so it needs no YAML parser and runs anywhere. It reads files only and exits
non-zero on any HIGH or CRITICAL finding, which makes it a natural pre-commit
hook.
"""
from __future__ import annotations

import argparse
import math
import os
import re
import sys

# ---- secret detectors that fire regardless of the surrounding key ----
SECRET_PATTERNS = [
    ("CRITICAL", "AWS access key id",   re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("CRITICAL", "private key block",   re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("CRITICAL", "Google API key",      re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("CRITICAL", "Slack token",         re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}")),
    ("HIGH",     "GitHub token",        re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b")),
    ("HIGH",     "Stripe live key",     re.compile(r"\bsk_live_[0-9A-Za-z]{16,}\b")),
    ("HIGH",     "JWT",                 re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}")),
]

# key names that should hold a secret (so a real-looking value is a leak)
SECRET_KEY = re.compile(r"(?i)(pass(word|wd)?|secret|token|api[_-]?key|access[_-]?key|"
                        r"private[_-]?key|credential|auth[_-]?key)")

# obvious weak / placeholder values
WEAK_VALUES = {
    "password", "passwd", "changeme", "change_me", "admin", "root", "secret",
    "123456", "12345678", "test", "example", "guest", "default", "postgres",
}
PLACEHOLDERISH = re.compile(r"(?i)(change.?me|your[_-]|placeholder|example|xxxx|<[^>]+>|\.\.\.)")

# container ports that should not be published to the world
SENSITIVE_PORTS = {
    "5432": "PostgreSQL", "3306": "MySQL/MariaDB", "6379": "Redis",
    "27017": "MongoDB", "9200": "Elasticsearch", "5672": "RabbitMQ",
    "15672": "RabbitMQ admin", "2375": "Docker API", "2376": "Docker API",
    "9092": "Kafka", "11211": "memcached", "5601": "Kibana", "8086": "InfluxDB",
}


class Finding:
    def __init__(self, level: str, where: str, msg: str):
        self.level, self.where, self.msg = level, where, msg


def entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {c: s.count(c) for c in set(s)}
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _strip_quotes(v: str) -> str:
    v = v.strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
        return v[1:-1]
    return v


def scan_secret_patterns(line: str, where: str, out: list[Finding]) -> bool:
    hit = False
    for level, name, rx in SECRET_PATTERNS:
        if rx.search(line):
            out.append(Finding(level, where, f"{name} detected"))
            hit = True
    return hit


def lint_env(path: str, lines: list[str]) -> list[Finding]:
    out: list[Finding] = []
    base = os.path.basename(path)
    for i, raw in enumerate(lines, 1):
        line = raw.rstrip("\n")
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        where = f"{base}:{i}"
        if stripped.startswith("export "):
            stripped = stripped[len("export "):]
        if "=" not in stripped:
            continue
        key, _, rawval = stripped.partition("=")
        key = key.strip()
        val = _strip_quotes(rawval)

        scan_secret_patterns(line, where, out)

        if not SECRET_KEY.search(key):
            continue
        if val.lower() in WEAK_VALUES:
            out.append(Finding("WARN", where, f"{key} uses a weak/default value {val!r}"))
        elif val == "" or PLACEHOLDERISH.search(val):
            out.append(Finding("INFO", where, f"{key} is empty/placeholder (fine for a template)"))
        elif len(val) >= 8 and (entropy(val) >= 3.0 or any(c.isdigit() for c in val) and any(c.isalpha() for c in val)):
            out.append(Finding("WARN", where,
                f"{key} holds what looks like a real secret; ensure this file is gitignored"))
    _check_gitignore(path, out)
    return out


def _check_gitignore(path: str, out: list[Finding]) -> None:
    d = os.path.dirname(os.path.abspath(path))
    gi = os.path.join(d, ".gitignore")
    if not os.path.exists(gi):
        return
    with open(gi, encoding="utf-8", errors="replace") as fh:
        patterns = {ln.strip() for ln in fh}
    name = os.path.basename(path)
    covered = any(p in patterns for p in (name, ".env", "*.env", ".env*", "env"))
    if not covered:
        out.append(Finding("HIGH", name, "not covered by .gitignore in its directory; risk of committing it"))


PORT_RE = re.compile(r"""["']?(?:(?P<ip>\d{1,3}(?:\.\d{1,3}){3}):)?(?P<host>\d{1,5}):(?P<cont>\d{1,5})(?:/\w+)?["']?""")


def lint_compose(path: str, lines: list[str]) -> list[Finding]:
    out: list[Finding] = []
    base = os.path.basename(path)
    for i, raw in enumerate(lines, 1):
        line = raw.rstrip("\n")
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        where = f"{base}:{i}"

        scan_secret_patterns(line, where, out)

        if re.search(r"privileged:\s*true", stripped):
            out.append(Finding("HIGH", where, "privileged: true gives the container near-root on the host"))
        if "/var/run/docker.sock" in stripped:
            out.append(Finding("HIGH", where, "mounts the docker socket; equivalent to host root"))
        if re.search(r"network_mode:\s*['\"]?host", stripped):
            out.append(Finding("WARN", where, "network_mode: host removes network isolation"))

        # published ports
        m = PORT_RE.search(stripped)
        if m and ("- " in line or line.lstrip().startswith("-") or ":" in (m.group("host") or "")):
            host, cont, ip = m.group("host"), m.group("cont"), m.group("ip")
            svc = SENSITIVE_PORTS.get(cont)
            if svc:
                if ip in (None, "0.0.0.0"):
                    out.append(Finding("HIGH", where,
                        f"{svc} port {cont} is published to ALL interfaces; bind to 127.0.0.1 or drop it"))
                elif ip.startswith("127.") :
                    out.append(Finding("INFO", where, f"{svc} port {cont} published on loopback only (ok)"))
            elif ip in (None,) and host:
                out.append(Finding("INFO", where, f"port {host}->{cont} published to all interfaces"))

        # inline secret in environment
        env_kv = re.match(r"-?\s*([A-Za-z0-9_]+)\s*[:=]\s*(.+)$", stripped)
        if env_kv and SECRET_KEY.search(env_kv.group(1)):
            val = _strip_quotes(env_kv.group(2))
            if val and not PLACEHOLDERISH.search(val) and not val.startswith("$"):
                lvl = "HIGH" if val.lower() in WEAK_VALUES else "WARN"
                out.append(Finding(lvl, where,
                    f"{env_kv.group(1)} set inline in compose; move it to a secret/.env"))
    return out


def _classify(path: str, text: str) -> str:
    name = os.path.basename(path).lower()
    if "compose" in name or name in ("docker-compose.yml", "docker-compose.yaml"):
        return "compose"
    if name.startswith(".env") or name.endswith(".env"):
        return "env"
    if re.search(r"^\s*services:\s*$", text, re.MULTILINE):
        return "compose"
    return "env"


def lint_path(path: str) -> list[tuple[str, list[Finding]]]:
    results = []
    if os.path.isdir(path):
        for name in (".env", ".env.local", "docker-compose.yml", "docker-compose.yaml", "compose.yml"):
            p = os.path.join(path, name)
            if os.path.exists(p):
                results += lint_path(p)
        return results
    with open(path, encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    lines = text.splitlines()
    kind = _classify(path, text)
    findings = lint_compose(path, lines) if kind == "compose" else lint_env(path, lines)
    return [(path, findings)]


RANK = {"CRITICAL": 4, "HIGH": 3, "WARN": 2, "INFO": 1}
COLOR = {"CRITICAL": "\033[1;31m", "HIGH": "\033[31m", "WARN": "\033[33m", "INFO": "\033[90m"}
RESET = "\033[0m"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="envlint", description="scan .env and compose files for leaks and exposure")
    p.add_argument("paths", nargs="+", help="files or directories to scan")
    p.add_argument("--no-color", action="store_true")
    a = p.parse_args(argv)
    use_color = sys.stdout.isatty() and not a.no_color

    worst = 0
    for path in a.paths:
        for fpath, findings in lint_path(path):
            print(f"== {fpath} ==")
            if not findings:
                print("  ok: nothing flagged")
                continue
            for f in sorted(findings, key=lambda x: -RANK[x.level]):
                worst = max(worst, RANK[f.level])
                tag = f"{COLOR[f.level]}{f.level:<8}{RESET}" if use_color else f"{f.level:<8}"
                print(f"  {tag} {f.where}: {f.msg}")
    return 1 if worst >= RANK["HIGH"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
