#!/usr/bin/env python3
"""unitcheck - statically score the sandboxing of a systemd service unit.

`systemd-analyze security` grades a unit, but only one that is installed on a
running systemd host. unitcheck reads a ``.service`` *file* and reports the same
kind of thing with no systemd and no dependencies - so it runs in CI, on the
unit files you keep in a repo, on any machine.

It reports the missing and dangerous directives and a 0-100 hardening score.
It is the audit counterpart to unitforge, which generates hardened units.

    unitcheck myapp.service
    unitcheck /etc/systemd/system/*.service

Exit status is non-zero if a unit has any HIGH finding or scores below the
threshold (default 50, tune with --min-score).
"""
from __future__ import annotations

import argparse
import sys

# ---- hardening directives we expect, with how to judge them ----
# (key, predicate(value)->ok, severity_if_missing_or_bad, weight, human label)
def _yes(v: str) -> bool:
    return v.strip().lower() in ("yes", "true", "on", "1")


CHECKS = [
    ("NoNewPrivileges", _yes, "HIGH", 3, "processes can gain privileges"),
    ("ProtectSystem", lambda v: v.strip().lower() in ("strict", "full"), "HIGH", 3,
     "filesystem is writable (ProtectSystem not strict/full)"),
    ("ProtectHome", lambda v: v.strip().lower() in ("yes", "read-only", "tmpfs"), "MEDIUM", 2,
     "home directories are accessible"),
    ("PrivateTmp", _yes, "MEDIUM", 2, "shares /tmp with the rest of the system"),
    ("PrivateDevices", _yes, "MEDIUM", 2, "has access to physical devices"),
    ("ProtectKernelTunables", _yes, "MEDIUM", 1, "can write kernel tunables (/proc/sys)"),
    ("ProtectKernelModules", _yes, "MEDIUM", 1, "can load kernel modules"),
    ("ProtectKernelLogs", _yes, "LOW", 1, "can read the kernel log"),
    ("ProtectControlGroups", _yes, "LOW", 1, "can write the cgroup hierarchy"),
    ("ProtectClock", _yes, "LOW", 1, "can change the system clock"),
    ("ProtectHostname", _yes, "LOW", 1, "can change the hostname"),
    ("RestrictNamespaces", _yes, "MEDIUM", 2, "can create namespaces (sandbox escape)"),
    ("RestrictRealtime", _yes, "LOW", 1, "can use realtime scheduling"),
    ("RestrictSUIDSGID", _yes, "MEDIUM", 1, "can create setuid/setgid files"),
    ("LockPersonality", _yes, "LOW", 1, "execution personality is not locked"),
    ("MemoryDenyWriteExecute", _yes, "MEDIUM", 2, "memory can be writable+executable (W^X off)"),
    ("SystemCallFilter", lambda v: bool(v.strip()), "HIGH", 3, "no syscall filter"),
    ("SystemCallArchitectures", lambda v: v.strip().lower() == "native", "LOW", 1,
     "non-native syscall ABIs are allowed"),
    ("RestrictAddressFamilies", lambda v: bool(v.strip()), "MEDIUM", 2,
     "all socket address families are allowed"),
    ("CapabilityBoundingSet", lambda v: True, "MEDIUM", 2,
     "no CapabilityBoundingSet: the service keeps all Linux capabilities"),
]


class Finding:
    def __init__(self, level: str, msg: str):
        self.level, self.msg = level, msg


def parse_service(text: str) -> dict[str, list[str]]:
    """Collect [Service] directives as key -> list of values (units allow repeats)."""
    directives: dict[str, list[str]] = {}
    section = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip().lower()
            continue
        if section != "service" or "=" not in line:
            continue
        key, _, val = line.partition("=")
        directives.setdefault(key.strip(), []).append(val.strip())
    return directives


DANGER_CAPS = {"CAP_SYS_ADMIN", "CAP_SYS_MODULE", "CAP_SYS_PTRACE", "CAP_DAC_READ_SEARCH"}


def audit_unit(text: str) -> tuple[list[Finding], int]:
    d = parse_service(text)
    out: list[Finding] = []
    got = 0
    total = 0

    for key, ok, sev, weight, label in CHECKS:
        total += weight
        vals = d.get(key)
        if vals is None:
            out.append(Finding(sev, f"missing {key}: {label}"))
        elif not ok(vals[-1]):
            out.append(Finding(sev, f"{key}={vals[-1]}: {label}"))
        else:
            got += weight

    # runs as root?
    users = d.get("User")
    if not users:
        out.append(Finding("HIGH", "no User= set: the service runs as root"))
    elif users[-1].strip() in ("root", "0"):
        out.append(Finding("HIGH", "User=root: the service runs as root"))

    # explicitly dangerous capabilities kept or granted
    for key in ("CapabilityBoundingSet", "AmbientCapabilities"):
        for v in d.get(key, []):
            kept = {c.strip() for c in v.replace(",", " ").split()} & DANGER_CAPS
            if kept:
                out.append(Finding("HIGH", f"{key} includes dangerous capability: {', '.join(sorted(kept))}"))

    score = round(100 * got / total) if total else 0
    return out, score


RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
COLOR = {"CRITICAL": "\033[1;31m", "HIGH": "\033[31m", "MEDIUM": "\033[33m",
         "LOW": "\033[36m", "OK": "\033[32m"}
RESET = "\033[0m"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="unitcheck", description="statically score systemd unit hardening")
    p.add_argument("files", nargs="+")
    p.add_argument("--min-score", type=int, default=50, help="fail below this score (default 50)")
    p.add_argument("--no-color", action="store_true")
    a = p.parse_args(argv)
    use_color = sys.stdout.isatty() and not a.no_color

    failed = False
    for path in a.files:
        with open(path, encoding="utf-8", errors="replace") as fh:
            findings, score = audit_unit(fh.read())
        print(f"== {path} ==")
        for f in sorted(findings, key=lambda x: -RANK[x.level]):
            tag = f"{COLOR[f.level]}{f.level:<8}{RESET}" if use_color else f"{f.level:<8}"
            print(f"  {tag} {f.msg}")
        band = "hardened" if score >= 85 else "partial" if score >= 50 else "weak"
        line = f"  score: {score}/100 ({band})"
        if use_color:
            col = COLOR["OK"] if score >= 85 else COLOR["MEDIUM"] if score >= 50 else COLOR["HIGH"]
            line = f"{col}{line}{RESET}"
        print(line)
        if score < a.min_score or any(f.level in ("HIGH", "CRITICAL") for f in findings):
            failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
