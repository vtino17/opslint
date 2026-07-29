#!/usr/bin/env python3
"""cronlint - validate crontab files and catch the classic cron footguns.

Cron has a handful of traps that bite people repeatedly and that a plain "does
it parse" check misses:

  * the last line is ignored if the file has no trailing newline;
  * an unescaped ``%`` in the command is turned into a newline (the rest becomes
    stdin), so ``date +%Y`` silently breaks;
  * restricting BOTH day-of-month and day-of-week makes cron run when EITHER
    matches (an OR, not the AND most people expect);
  * a bare command name relies on cron's minimal ``PATH`` and often "works on my
    shell" but not under cron.

cronlint checks the schedule fields for real and flags all of the above. It
reads files only and changes nothing.

    cronlint crontab.txt
    crontab -l | cronlint -            # read from stdin
    cronlint --system /etc/cron.d/*    # files with a user field

Exit status is non-zero if there is any ERROR-level finding.
"""
from __future__ import annotations

import argparse
import sys

MONTHS = ["jan", "feb", "mar", "apr", "may", "jun",
          "jul", "aug", "sep", "oct", "nov", "dec"]
DAYS = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"]

MACROS = {"@reboot", "@yearly", "@annually", "@monthly", "@weekly",
          "@daily", "@midnight", "@hourly"}

# field name, (min, max), name->number map
FIELDS = [
    ("minute", (0, 59), {}),
    ("hour", (0, 23), {}),
    ("day-of-month", (1, 31), {}),
    ("month", (1, 12), {m: i + 1 for i, m in enumerate(MONTHS)}),
    ("day-of-week", (0, 7), {d: i for i, d in enumerate(DAYS)}),
]


class Finding:
    def __init__(self, level: str, line: int, msg: str):
        self.level, self.line, self.msg = level, line, msg


def _resolve(tok: str, names: dict[str, int]) -> int | None:
    tok = tok.lower()
    if tok in names:
        return names[tok]
    try:
        return int(tok)
    except ValueError:
        return None


def check_field(spec: str, bounds: tuple[int, int], names: dict[str, int]) -> str | None:
    """Return an error string if the field is invalid, else None."""
    lo, hi = bounds
    for item in spec.split(","):
        if item == "":
            return f"empty element in {spec!r}"
        step = None
        base = item
        if "/" in item:
            base, _, step_s = item.partition("/")
            if not step_s.isdigit() or int(step_s) == 0:
                return f"invalid step in {item!r}"
            step = int(step_s)
        if base == "*":
            continue
        if "-" in base.lstrip("-") and not base.lstrip().startswith("-"):
            a_s, _, b_s = base.partition("-")
            a, b = _resolve(a_s, names), _resolve(b_s, names)
            if a is None or b is None:
                return f"non-numeric range {base!r}"
            if not (lo <= a <= hi and lo <= b <= hi):
                return f"range {base!r} outside {lo}-{hi}"
            if a > b:
                return f"reversed range {base!r} (start > end)"
        else:
            v = _resolve(base, names)
            if v is None:
                return f"non-numeric value {base!r}"
            if not (lo <= v <= hi):
                return f"value {v} outside {lo}-{hi}"
        if step is not None and base == "*":
            continue
    return None


def _field_is_restricted(spec: str) -> bool:
    """True if the field is not a wildcard (constrains the schedule)."""
    return spec != "*" and not spec.startswith("*/")


def lint_lines(lines: list[str], system: bool, had_final_newline: bool) -> list[Finding]:
    out: list[Finding] = []
    seen_schedules: dict[str, int] = {}
    ncmd = 0

    for idx, raw in enumerate(lines, 1):
        line = raw.rstrip("\n")
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        # environment assignment: NAME = value
        if "=" in stripped.split()[0] or (len(stripped.split()) >= 2 and stripped.split()[1] == "="):
            continue

        toks = stripped.split()
        # schedule portion
        if toks[0] in MACROS:
            time_fields: list[str] = []
            rest = toks[1:]
            sched_key = toks[0]
        elif toks[0].startswith("@"):
            out.append(Finding("ERROR", idx, f"unknown time macro {toks[0]!r}"))
            continue
        else:
            need = 5
            if len(toks) < need + 1:
                out.append(Finding("ERROR", idx, f"only {len(toks)} tokens; need 5 time fields + command"))
                continue
            time_fields = toks[:5]
            rest = toks[5:]
            sched_key = " ".join(time_fields)

        # system crontab has a user field before the command
        if system and rest:
            rest = rest[1:]
        command = " ".join(rest)
        if not command:
            out.append(Finding("ERROR", idx, "schedule has no command"))
            continue
        ncmd += 1

        # validate each time field
        for (name, bounds, names), spec in zip(FIELDS, time_fields):
            err = check_field(spec, bounds, names)
            if err:
                out.append(Finding("ERROR", idx, f"{name}: {err}"))

        # footgun: dom AND dow both restricted -> cron ORs them
        if len(time_fields) == 5:
            dom, dow = time_fields[2], time_fields[4]
            if _field_is_restricted(dom) and _field_is_restricted(dow):
                out.append(Finding("WARN", idx,
                    "both day-of-month and day-of-week are set; cron runs when EITHER matches (OR, not AND)"))

        # footgun: unescaped % in the command
        pct = command.replace("\\%", "")
        if "%" in pct:
            out.append(Finding("ERROR", idx,
                "unescaped '%' in command; cron turns it into a newline. Use '\\%'"))

        # footgun: relative command path
        first = rest[0] if rest else ""
        if first and not first.startswith(("/", "@")) and "=" not in first:
            out.append(Finding("WARN", idx,
                f"command {first!r} is not an absolute path; cron's PATH is minimal"))

        # every-minute jobs and duplicate schedules
        if sched_key == "* * * * *":
            out.append(Finding("INFO", idx, "runs every minute; make sure it cannot overlap itself"))
        if sched_key in seen_schedules:
            out.append(Finding("WARN", idx,
                f"same schedule as line {seen_schedules[sched_key]}; jobs may contend"))
        else:
            seen_schedules[sched_key] = idx

    if ncmd and not had_final_newline:
        out.append(Finding("ERROR", len(lines),
            "file has no trailing newline; cron silently ignores the last line"))
    return out


LEVEL_RANK = {"ERROR": 3, "WARN": 2, "INFO": 1}
COLOR = {"ERROR": "\033[31m", "WARN": "\033[33m", "INFO": "\033[90m"}
RESET = "\033[0m"


def lint_file(path: str, system: bool) -> tuple[list[Finding], str]:
    if path == "-":
        text = sys.stdin.read()
        label = "(stdin)"
    else:
        with open(path, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
        label = path
    had_nl = text.endswith("\n") or text == ""
    lines = text.splitlines()
    return lint_lines(lines, system, had_nl), label


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="cronlint", description="validate crontab files")
    p.add_argument("files", nargs="+", help="crontab file(s), or - for stdin")
    p.add_argument("--system", action="store_true",
                   help="files have a user field (e.g. /etc/crontab, /etc/cron.d/*)")
    p.add_argument("--no-color", action="store_true")
    a = p.parse_args(argv)
    use_color = sys.stdout.isatty() and not a.no_color

    worst = 0
    total = 0
    for path in a.files:
        findings, label = lint_file(path, a.system)
        if len(a.files) > 1:
            print(f"== {label} ==")
        for f in findings:
            total += 1
            worst = max(worst, LEVEL_RANK.get(f.level, 0))
            tag = f"{COLOR.get(f.level,'')}{f.level:<5}{RESET}" if use_color else f"{f.level:<5}"
            print(f"  {tag} line {f.line}: {f.msg}")
        if not findings:
            print(f"  ok: no issues in {label}")
    return 1 if worst >= LEVEL_RANK["ERROR"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
