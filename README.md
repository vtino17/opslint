# opslint

One command to audit a Linux host's configuration hygiene.

opslint bundles six focused linters and runs them together, then rolls their
findings up into a single severity summary, a **0-100 score**, and one exit code:

| Tool | Checks |
|------|--------|
| **sshaudit**    | `sshd_config` and `authorized_keys` - weak crypto, risky auth, small RSA keys |
| **sudoerslint** | dangerous sudoers rules - `NOPASSWD: ALL`, shell-escape (GTFOBins) grants |
| **fstablint**   | `/etc/fstab` - CIS mount hardening, network-mount boot safety |
| **cronlint**    | crontab footguns - missing final newline, unescaped `%`, dom+dow trap |
| **envlint**     | `.env` / `docker-compose` - hardcoded secrets, exposed ports |
| **nginxdoctor** | nginx - weak TLS, missing headers, the `add_header` inheritance trap |
| **sysctlaudit** | sysctl config vs a CIS kernel-hardening baseline |
| **unitcheck**   | systemd `.service` sandboxing score (in `--dir` mode / `opslint unit`) |

Everything is bundled in `tools/`, so opslint is self-contained: one Python 3,
no dependencies, reads files only, changes nothing.

Bundled linters run with a 30-second timeout. If a linter cannot start, crashes,
or returns an invalid execution status, the aggregate audit fails closed with
an `ERROR` finding instead of silently reporting a clean score.

## Usage

```sh
opslint audit                 # audit this host at the standard /etc paths
opslint audit --dir ./config  # audit a directory of config files instead
```

```
$ opslint audit --dir ./config

### sudo (sudoerslint.py)
  CRITICAL ops:1: alice: passwordless full sudo (NOPASSWD: ALL) - complete root access, no password
### fstab (fstablint.py)
  HIGH     line 1: /tmp is missing nodev,noexec,nosuid (CIS: sensitive mounts should carry these)
### nginx (nginxdoctor.py)
  HIGH     line 1: ssl_protocols enables obsolete TLSv1
...
============================================================
opslint score: 13/100 (poor) - 1 critical, 4 high, 3 medium, 2 warn, 2 low
```

The exit status is non-zero if anything is HIGH or CRITICAL, so `opslint audit`
drops straight into CI or a nightly cron check.

### Machine-readable output

`--json` emits the score and every finding as JSON, for a pipeline, a dashboard,
or `jq`:

```sh
$ opslint audit --dir ./config --json
{
  "score": 65,
  "band": "needs work",
  "failed": true,
  "counts": { "CRITICAL": 1, "HIGH": 1 },
  "findings": [
    { "tool": "sudo", "level": "CRITICAL", "detail": "sudoers:1: alice: passwordless full sudo ..." },
    { "tool": "fstab", "level": "HIGH", "detail": "line 1: /tmp is missing nodev,noexec,nosuid ..." }
  ]
}
```

Run any bundled tool directly and pass it your own arguments:

```sh
opslint ssh    sshd --config /etc/ssh/sshd_config
opslint sudo   /etc/sudoers.d/*
opslint nginx  /etc/nginx/nginx.conf
opslint env    .
```

## The score

Starts at 100 and subtracts per finding (CRITICAL −25, HIGH/ERROR −10, MEDIUM/WARN
−4, LOW −1, floored at 0). It is a relative hygiene signal to trend over time and
gate on, not an absolute compliance rating.

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/vtino17/opslint/main/install.sh | sudo bash
opslint audit
```

Or clone and run `python3 opslint.py audit` in place.

## Caveat

opslint is a fast configuration lint that reads the files it is pointed at. It is
not a substitute for a full CIS benchmark, `nginx -t`, `visudo -c`, or a live TLS
scan — pair it with those. Each bundled tool documents its own limits.

## Tests

```sh
./tests/run.sh
```

Builds a fixture config directory with one problem per tool, asserts the
aggregate audit finds them, checks that a clean config scores 100, and cleans up.

## License

MIT. See `LICENSE`. Bundles sshaudit, sudoerslint, fstablint, cronlint, envlint
and nginxdoctor, all MIT and also available as standalone repos.
