#!/usr/bin/env python3
"""sysctlaudit - check sysctl config against a kernel-hardening baseline.

Servers set kernel security knobs in /etc/sysctl.conf and /etc/sysctl.d/*.conf,
and then nobody checks them again. sysctlaudit reads those files (or any file you
point it at), compares each setting to a CIS-style hardening baseline, and
reports what is wrong or missing. It is the audit counterpart to a tool that
*applies* the hardening.

    sysctlaudit                       # /etc/sysctl.conf + /etc/sysctl.d/*.conf
    sysctlaudit ./99-hardening.conf   # a specific file (or directory)

It reads files only and changes nothing. Exit status is non-zero on any HIGH
finding or a wrong value.
"""
from __future__ import annotations

import argparse
import glob
import os
import sys

# (key, expected, comparator, severity, why)
#   eq  -> must equal expected
#   gte -> numeric value must be >= expected
BASELINE = [
    ("net.ipv4.tcp_syncookies", "1", "eq", "HIGH", "SYN-flood protection"),
    ("net.ipv4.conf.all.rp_filter", "1", "eq", "MEDIUM", "reverse-path filtering (anti-spoofing)"),
    ("net.ipv4.conf.all.accept_redirects", "0", "eq", "MEDIUM", "ignore ICMP redirects"),
    ("net.ipv4.conf.all.send_redirects", "0", "eq", "MEDIUM", "do not send ICMP redirects"),
    ("net.ipv4.conf.all.accept_source_route", "0", "eq", "MEDIUM", "reject source-routed packets"),
    ("net.ipv4.conf.all.log_martians", "1", "eq", "LOW", "log spoofed/martian packets"),
    ("net.ipv4.icmp_echo_ignore_broadcasts", "1", "eq", "LOW", "ignore broadcast pings (smurf)"),
    ("net.ipv6.conf.all.accept_redirects", "0", "eq", "MEDIUM", "ignore IPv6 redirects"),
    ("net.ipv6.conf.all.accept_source_route", "0", "eq", "MEDIUM", "reject IPv6 source routing"),
    ("kernel.randomize_va_space", "2", "gte", "HIGH", "full address-space layout randomization"),
    ("kernel.kptr_restrict", "1", "gte", "MEDIUM", "hide kernel pointers from userspace"),
    ("kernel.dmesg_restrict", "1", "eq", "MEDIUM", "restrict dmesg to root"),
    ("kernel.yama.ptrace_scope", "1", "gte", "MEDIUM", "restrict ptrace of other processes"),
    ("kernel.sysrq", "0", "eq", "LOW", "disable the magic SysRq key"),
    ("fs.protected_hardlinks", "1", "eq", "MEDIUM", "hardlink protection"),
    ("fs.protected_symlinks", "1", "eq", "MEDIUM", "symlink protection"),
    ("fs.suid_dumpable", "0", "eq", "MEDIUM", "no core dumps from setuid programs"),
]


class Finding:
    def __init__(self, level: str, key: str, msg: str):
        self.level, self.key, self.msg = level, key, msg


def parse_sysctl(paths: list[str]) -> dict[str, str]:
    """Merge sysctl settings; a later file/line wins, matching sysctl ordering."""
    values: dict[str, str] = {}
    for path in paths:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith(("#", ";")):
                    continue
                if line.startswith("-"):
                    line = line[1:]            # '-key = val' means ignore errors
                if "=" not in line:
                    continue
                key, _, val = line.partition("=")
                values[key.strip()] = val.strip()
    return values


def _compare(actual: str, expected: str, how: str) -> bool:
    if how == "eq":
        return actual == expected
    if how == "gte":
        try:
            return int(actual) >= int(expected)
        except ValueError:
            return False
    return False


def audit(values: dict[str, str]) -> tuple[list[Finding], int]:
    out: list[Finding] = []
    ok = 0
    for key, expected, how, sev, why in BASELINE:
        actual = values.get(key)
        if actual is None:
            out.append(Finding("WARN", key, f"not set - relies on the kernel default ({why})"))
        elif _compare(actual, expected, how):
            ok += 1
        else:
            want = f">= {expected}" if how == "gte" else expected
            out.append(Finding(sev, key, f"is {actual}, should be {want} ({why})"))

    # context-dependent: IP forwarding
    fwd = values.get("net.ipv4.ip_forward")
    if fwd == "1":
        out.append(Finding("LOW", "net.ipv4.ip_forward",
                           "IP forwarding is on - correct only if this host is a router/NAT/VPN"))

    score = round(100 * ok / len(BASELINE))
    return out, score


RANK = {"HIGH": 3, "MEDIUM": 2, "WARN": 1, "LOW": 1}
COLOR = {"HIGH": "\033[31m", "MEDIUM": "\033[33m", "WARN": "\033[33m",
         "LOW": "\033[36m", "OK": "\033[32m"}
RESET = "\033[0m"


def _resolve_targets(args_paths: list[str]) -> list[str]:
    if args_paths:
        files: list[str] = []
        for p in args_paths:
            if os.path.isdir(p):
                files += sorted(glob.glob(os.path.join(p, "*.conf")))
            elif os.path.exists(p):
                files.append(p)
        return files
    # system defaults, in sysctl's own precedence order (later wins)
    defaults = ["/etc/sysctl.conf"] + sorted(glob.glob("/etc/sysctl.d/*.conf")) + \
               sorted(glob.glob("/run/sysctl.d/*.conf")) + sorted(glob.glob("/usr/lib/sysctl.d/*.conf"))
    return [p for p in defaults if os.path.exists(p)]


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="sysctlaudit", description="audit sysctl config against a hardening baseline")
    p.add_argument("paths", nargs="*", help="sysctl file(s) or directory; default: system sysctl config")
    p.add_argument("--no-color", action="store_true")
    a = p.parse_args(argv)
    use_color = sys.stdout.isatty() and not a.no_color

    targets = _resolve_targets(a.paths)
    if not targets:
        print("sysctlaudit: no sysctl config found to audit")
        return 0

    values = parse_sysctl(targets)
    findings, score = audit(values)
    print(f"== sysctl ({len(targets)} file(s)) ==")
    for f in sorted(findings, key=lambda x: -RANK[x.level]):
        tag = f"{COLOR[f.level]}{f.level:<7}{RESET}" if use_color else f"{f.level:<7}"
        print(f"  {tag} {f.key}: {f.msg}")
    band = "hardened" if score >= 85 else "partial" if score >= 50 else "weak"
    line = f"  hardening score: {score}/100 ({band}) - {len(BASELINE)} baseline keys"
    if use_color:
        col = COLOR["OK"] if score >= 85 else COLOR["MEDIUM"] if score >= 50 else COLOR["HIGH"]
        line = f"{col}{line}{RESET}"
    print(line)
    failing = any(f.level == "HIGH" for f in findings) or any(
        f.level in ("MEDIUM",) and "should be" in f.msg for f in findings)
    return 1 if failing else 0


if __name__ == "__main__":
    raise SystemExit(main())
