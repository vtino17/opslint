#!/usr/bin/env python3
"""fstablint - validate /etc/fstab for the hardening and reliability mistakes.

An fstab that parses can still hang the boot when an NFS server is down, mount
/tmp so that anyone can drop an executable setuid binary there, or refer to
/dev/sda2 that becomes /dev/sdb2 after you add a disk. fstablint checks for the
things `mount -a` will not warn you about until it is too late:

  * /tmp, /var/tmp and /dev/shm without nodev,nosuid,noexec (CIS hardening);
  * network filesystems without _netdev / nofail (a down server hangs the boot);
  * mounts by device name instead of UUID= / LABEL= (device order is not stable);
  * the wrong field count, and duplicate mount points.

It reads files only and changes nothing.

    fstablint /etc/fstab

Exit status is non-zero on any HIGH or CRITICAL finding.
"""
from __future__ import annotations

import argparse
import sys

# mount point -> options it should carry (CIS-style hardening)
HARDEN = {
    "/tmp": {"nodev", "nosuid", "noexec"},
    "/var/tmp": {"nodev", "nosuid", "noexec"},
    "/dev/shm": {"nodev", "nosuid", "noexec"},
    "/home": {"nodev", "nosuid"},
}
NETWORK_FS = {"nfs", "nfs4", "cifs", "smbfs", "smb3", "glusterfs", "ceph", "fuse.sshfs"}
PSEUDO_FS = {"proc", "sysfs", "tmpfs", "devpts", "devtmpfs", "swap", "cgroup",
             "cgroup2", "mqueue", "hugetlbfs", "debugfs", "securityfs", "overlay"}


class Finding:
    def __init__(self, level: str, line: int, msg: str):
        self.level, self.line, self.msg = level, line, msg


def audit(text: str) -> list[Finding]:
    out: list[Finding] = []
    seen_mounts: dict[str, int] = {}

    for i, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        spec = fields[0]
        mount = fields[1] if len(fields) > 1 else "?"
        fstype = fields[2].lower() if len(fields) > 2 else "?"
        opts = set(fields[3].split(",")) if len(fields) > 3 else set()

        # field count
        if len(fields) < 4:
            out.append(Finding("ERROR", i, f"only {len(fields)} fields; need at least 4 (spec mount fstype options)"))
            continue
        if len(fields) < 6 and fstype not in ("swap",) and spec.lower() != "none":
            out.append(Finding("LOW", i, f"missing dump/pass fields ({len(fields)}/6); fsck order is undefined"))

        # duplicate mount point (ignore swap/none)
        if mount not in ("none", "swap", "?"):
            if mount in seen_mounts:
                out.append(Finding("HIGH", i, f"mount point {mount} already defined on line {seen_mounts[mount]}"))
            else:
                seen_mounts[mount] = i

        # hardening options on sensitive mounts
        if mount in HARDEN:
            missing = HARDEN[mount] - opts
            if missing:
                out.append(Finding("HIGH", i,
                    f"{mount} is missing {','.join(sorted(missing))} (CIS: sensitive mounts should carry these)"))

        # network filesystems and boot safety
        if fstype in NETWORK_FS:
            if "_netdev" not in opts:
                out.append(Finding("MEDIUM", i, f"{mount}: network fs without _netdev; it may mount before the network is up"))
            if "nofail" not in opts:
                out.append(Finding("HIGH", i, f"{mount}: network fs without nofail; a down server will hang the boot"))

        # device-name spec instead of a stable identifier
        if spec.startswith("/dev/") and not spec.startswith("/dev/mapper/") and fstype not in PSEUDO_FS:
            out.append(Finding("LOW", i,
                f"{mount}: mounted by device name {spec}; use UUID= or LABEL= (device order is not stable)"))

        # passno on a real filesystem
        if len(fields) >= 6 and fstype not in PSEUDO_FS and fstype not in NETWORK_FS:
            passno = fields[5]
            if passno == "0":
                out.append(Finding("LOW", i, f"{mount}: fsck pass is 0; this filesystem will never be checked"))
            if mount == "/" and passno != "1":
                out.append(Finding("MEDIUM", i, "/ should have fsck pass 1"))

    if not out:
        out.append(Finding("OK", 0, "no issues found"))
    return out


RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "ERROR": 3, "LOW": 1, "OK": 0}
COLOR = {"CRITICAL": "\033[1;31m", "ERROR": "\033[1;31m", "HIGH": "\033[31m",
         "MEDIUM": "\033[33m", "LOW": "\033[36m", "OK": "\033[32m"}
RESET = "\033[0m"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="fstablint", description="validate /etc/fstab")
    p.add_argument("files", nargs="+")
    p.add_argument("--no-color", action="store_true")
    a = p.parse_args(argv)
    use_color = sys.stdout.isatty() and not a.no_color

    worst = 0
    for path in a.files:
        with open(path, encoding="utf-8", errors="replace") as fh:
            findings = audit(fh.read())
        print(f"== {path} ==")
        for f in sorted(findings, key=lambda x: (-RANK[x.level], x.line)):
            worst = max(worst, RANK[f.level])
            loc = f"line {f.line}" if f.line else "fstab"
            tag = f"{COLOR[f.level]}{f.level:<8}{RESET}" if use_color else f"{f.level:<8}"
            print(f"  {tag} {loc}: {f.msg}")
    return 1 if worst >= 3 else 0


if __name__ == "__main__":
    raise SystemExit(main())
