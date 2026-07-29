#!/usr/bin/env python3
"""nginxdoctor - find security mistakes in nginx configuration.

nginx is easy to misconfigure in ways that never show up until someone looks:
a leaked version banner, TLSv1.0 still enabled, a missing HSTS header, and the
infamous ``add_header`` inheritance trap where adding one header inside a
``location`` silently drops every header set by the parent block.

nginxdoctor parses the config with a brace-aware parser (so it understands the
http / server / location nesting the inheritance rule depends on), reports
findings by severity, and changes nothing.

    nginxdoctor /etc/nginx/nginx.conf
    nginxdoctor sites-enabled/*.conf

It has no dependencies and exits non-zero on any HIGH or CRITICAL finding.
"""
from __future__ import annotations

import argparse
import re
import sys

# ---- security headers we expect on a TLS server, and how to recognise them ----
EXPECTED_HEADERS = {
    "strict-transport-security": ("HIGH", "HSTS (Strict-Transport-Security)"),
    "x-content-type-options": ("MEDIUM", "X-Content-Type-Options: nosniff"),
    "x-frame-options": ("MEDIUM", "X-Frame-Options / CSP frame-ancestors"),
    "referrer-policy": ("LOW", "Referrer-Policy"),
}
WEAK_PROTOCOLS = {"sslv2", "sslv3", "tlsv1", "tlsv1.0", "tlsv1.1"}
WEAK_CIPHER = re.compile(r"(?i)\b(RC4|3DES|DES|MD5|EXPORT|NULL|aNULL|eNULL|PSK|ADH)\b")


class Block:
    def __init__(self, header: str, parent: "Block | None", line: int):
        parts = header.split()
        self.header = header
        self.name = parts[0].lower() if parts else ""
        self.args = parts[1:]
        self.parent = parent
        self.line = line
        self.directives: list[tuple[str, list[str], int]] = []
        self.children: list[Block] = []

    def directive(self, name: str) -> tuple[str, list[str], int] | None:
        for d in self.directives:
            if d[0] == name:
                return d
        return None

    def header_names(self) -> set[str]:
        return {d[1][0].lower().strip('"') for d in self.directives
                if d[0] == "add_header" and d[1]}


class Finding:
    def __init__(self, level: str, line: int, msg: str):
        self.level, self.line, self.msg = level, line, msg


def parse(text: str) -> Block:
    # strip comments (to end of line)
    text = re.sub(r"#[^\n]*", "", text)
    tokens: list[tuple[str, int]] = []
    buf = ""
    line = 1
    for ch in text:
        if ch == "\n":
            line += 1
        if ch in "{};":
            if buf.strip():
                tokens.append((buf.strip(), line))
            tokens.append((ch, line))
            buf = ""
        else:
            buf += ch

    root = Block("", None, 0)
    stack = [root]
    pending = ""
    for tok, ln in tokens:
        if tok == "{":
            b = Block(pending, stack[-1], ln)
            stack[-1].children.append(b)
            stack.append(b)
            pending = ""
        elif tok == "}":
            if len(stack) > 1:
                stack.pop()
            pending = ""
        elif tok == ";":
            if pending.strip():
                parts = pending.split()
                stack[-1].directives.append((parts[0].lower(), parts[1:], ln))
            pending = ""
        else:
            pending = tok
    return root


def walk(block: Block):
    yield block
    for c in block.children:
        yield from walk(c)


def _is_tls_server(server: Block) -> bool:
    for name, args, _ in server.directives:
        if name == "listen" and any("ssl" in a or a == "443" or a.endswith(":443") for a in args):
            return True
        if name == "ssl_certificate" or (name == "ssl" and args[:1] == ["on"]):
            return True
    return False


def _collect_header_names(block: Block | None) -> set[str]:
    names: set[str] = set()
    while block is not None:
        names |= block.header_names()
        block = block.parent
    return names


def audit(root: Block) -> list[Finding]:
    out: list[Finding] = []

    # server_tokens
    tokens_set = False
    for b in walk(root):
        d = b.directive("server_tokens")
        if d:
            tokens_set = True
            if d[1][:1] == ["on"]:
                out.append(Finding("MEDIUM", d[2], "server_tokens on leaks the nginx version; set it off"))
    if not tokens_set:
        out.append(Finding("LOW", 0, "server_tokens is not set (defaults to on, leaking the version); set it off"))

    # TLS protocol / cipher strength (anywhere)
    for b in walk(root):
        for name, args, ln in b.directives:
            if name == "ssl_protocols":
                bad = sorted({a for a in args if a.lower() in WEAK_PROTOCOLS})
                if bad:
                    out.append(Finding("HIGH", ln, f"ssl_protocols enables obsolete {', '.join(bad)}"))
            if name == "ssl_ciphers":
                # ':' separates ciphers; a leading '!' is an *exclusion* (good), skip those
                cipher_str = " ".join(args).strip('"\'')
                weak = set()
                for tok in cipher_str.split(":"):
                    tok = tok.strip()
                    if not tok or tok.startswith("!"):
                        continue
                    m = WEAK_CIPHER.findall(tok)
                    weak.update(x.upper() for x in m)
                if weak:
                    out.append(Finding("HIGH", ln, f"ssl_ciphers allows weak {', '.join(sorted(weak))}"))
            if name == "autoindex" and args[:1] == ["on"]:
                out.append(Finding("MEDIUM", ln, "autoindex on exposes a directory listing"))

    # per-server-block checks
    for server in (b for b in walk(root) if b.name == "server"):
        tls = _is_tls_server(server)
        if tls and not any(b.directive("ssl_protocols") for b in [server] + _ancestors(server)):
            out.append(Finding("MEDIUM", server.line,
                "TLS server without an explicit ssl_protocols; old nginx defaults may allow TLSv1"))
        if tls:
            present = _collect_header_names(server)
            for hdr, (lvl, label) in EXPECTED_HEADERS.items():
                if hdr not in present:
                    out.append(Finding(lvl, server.line, f"TLS server is missing {label}"))

        # add_header inheritance trap
        parent_headers = _collect_header_names(server.parent) | server.header_names()
        for loc in (c for c in server.children if c.name == "location"):
            loc_headers = loc.header_names()
            if loc_headers:
                dropped = parent_headers - loc_headers
                if dropped:
                    out.append(Finding("HIGH", loc.line,
                        f"location {' '.join(loc.args)}: its add_header drops inherited header(s) "
                        f"{', '.join(sorted(dropped))} (nginx resets add_header per block)"))

    return out


def _ancestors(b: Block) -> list[Block]:
    out = []
    p = b.parent
    while p is not None:
        out.append(p)
        p = p.parent
    return out


RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
COLOR = {"CRITICAL": "\033[1;31m", "HIGH": "\033[31m", "MEDIUM": "\033[33m", "LOW": "\033[36m"}
RESET = "\033[0m"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="nginxdoctor", description="find security mistakes in nginx config")
    p.add_argument("files", nargs="+")
    p.add_argument("--no-color", action="store_true")
    a = p.parse_args(argv)
    use_color = sys.stdout.isatty() and not a.no_color

    worst = 0
    for path in a.files:
        with open(path, encoding="utf-8", errors="replace") as fh:
            findings = audit(parse(fh.read()))
        print(f"== {path} ==")
        if not findings:
            print("  ok: nothing flagged")
            continue
        for f in sorted(findings, key=lambda x: (-RANK[x.level], x.line)):
            worst = max(worst, RANK[f.level])
            loc = f"line {f.line}" if f.line else "config"
            tag = f"{COLOR[f.level]}{f.level:<8}{RESET}" if use_color else f"{f.level:<8}"
            print(f"  {tag} {loc}: {f.msg}")
    return 1 if worst >= RANK["HIGH"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
