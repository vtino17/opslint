# Contributing to OpsLint

OpsLint is a security signal used in CI and host audits. False negatives are
more dangerous than a visible tool failure, so aggregate behavior must fail
closed when a bundled linter cannot produce a valid result.

## Workflow

1. Create a focused branch from `main`.
2. Add a regression test for every behavior or severity change.
3. Run the local gates:

   ```sh
   ./tests/run.sh
   shellcheck --severity=warning install.sh tests/run.sh
   ruff check --select E9,F63,F7,F82 opslint.py tools
   ```

4. Open a pull request in English that describes affected inputs, expected exit
   codes, and any compatibility risk.

Keep the suite dependency-free at runtime. Do not hide parse errors, crashes,
timeouts, permission errors, or missing bundled tools behind a clean score.
Never include real `.env` files, credentials, private hostnames, or customer
configuration in tests or issues.

Report suspected vulnerabilities privately according to `SECURITY.md`.
