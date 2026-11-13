# LinScope

**Linux security configuration checker with evidence-based reports.**

LinScope reviews local configuration without changing it. Each finding includes a
stable ID, status, severity, collected evidence, and a recommendation. It is a
learning and infrastructure-security project, not a compliance certification or
a guarantee that a host is secure.

## Quick start

Requires **Linux and Python 3.10+**. No third-party runtime dependencies.

```bash
git clone https://github.com/nomatterwhathappns/LinScope.git
cd LinScope
python3 -m linscope --help
python3 -m linscope
python3 -m linscope --category ssh --category permissions
mkdir -p reports
python3 -m linscope --format json --output reports/baseline.json
```

Run without elevation first. Unavailable evidence is reported as `UNKNOWN`;
LinScope never invokes sudo. Additional read permissions can improve coverage,
but are not needed to inspect the source or use the CLI. Shadow contents,
password hashes, and private-key contents are never collected.

An optional console command can be installed in a virtual environment:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
linscope --version
```

## Coverage through v1.1

* **SSH:** effective default configuration via `sshd -T`, including normal
  `Include` expansion; root/password/empty-password login, key authentication,
  attempt limit, X11 and forwarded-port scope. Connection-specific `Match`
  contexts and live daemon flags require separate review.
* **Accounts:** UID 0, duplicate UIDs, interactive system accounts, selected
  privileged groups, and sudo rule inventory. Local files do not cover remote
  identity providers; sudo text matches are not an effective-privilege engine.
* **Permissions:** protected system files, SSH host-key metadata, temporary
  directory sticky bits, and optional scoped SUID/SGID/world-write searches.
* **Authentication:** password-creation defaults, PAM quality/lockout module
  references, and existing-account password status/aging metadata without hashes.
* **Network:** TCP/UDP listeners, binding scope, plaintext-service port hints,
  UFW state, and separate IPv4/IPv6 base INPUT policy snapshots. These are not
  remote-reachability tests or complete firewall-rule simulations.
* **Services:** running/enabled services and sockets, selected legacy-service
  names, and failed service inventory on systemd hosts.

The primary target is Ubuntu/Debian. Other distributions and containers may
produce `UNKNOWN` or `SKIP`; support must be verified before relying on results.
Use `--profile server|desktop|router|container` to state the intended host role.

## Reading results

| Status | Meaning |
| --- | --- |
| PASS | Available evidence meets this check's stated baseline. |
| WARN | Review is needed; context may justify this configuration. |
| FAIL | A specific checked baseline is violated; not proof of compromise. |
| UNKNOWN | Evidence is inaccessible, unavailable, malformed, or incomplete. |
| SKIP | Not applicable at the checked location, or an optional check is disabled. |
| INFO | Inventory/context that is not a security verdict. |

Severity describes potential impact, independently of status. Review evidence
before applying a recommendation. Some changes can disrupt authentication or
applications; LinScope applies none automatically.

`--deep` enables filesystem searches under `/usr/bin`, `/usr/sbin`, `/etc`,
and `/usr/local/bin`, without crossing mount boundaries. Commands have timeouts
and output limits. A failed/partial collection is not reported as clean.

Report files are created with mode 0600 and cannot overwrite existing files.
They may include hostnames, usernames, paths, and listening addresses. The
`reports/` directory is ignored by Git; committed examples use synthetic data.

## Exit codes

* `0`: collection completed; findings may still require review.
* `1`: `--fail-on low|medium|high|critical` found WARN/FAIL at or above the threshold.
* `2`: CLI/output error, or incomplete coverage with `--fail-on-unknown`.

Without `--fail-on-unknown`, UNKNOWN findings remain visible but do not fail the
process. This is useful in restricted environments but should be intentional in CI.

## Development

```bash
python3 -m unittest discover -v
```

Tests use synthetic configuration and command results. They do not change host
security settings or require root. See [CHANGELOG.md](CHANGELOG.md) for checkpoints.

## Checkpoint workflow

All checkpoints are on `main`: `v1.0`, `v1.1`, `v1.2`, `v1.3`, `v1.4`.
To study a completed version without moving main:

```bash
git switch --detach v1.0
# Return to the latest version:
git switch main
```
