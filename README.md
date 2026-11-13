# LinScope

**Linux security configuration checker with evidence-based reports.**

LinScope reviews local configuration without changing it. Each finding includes a
stable ID, status, severity, collected evidence, and a recommendation. It is a
learning and infrastructure-security project, not a compliance certification or
a guarantee that a host is secure.

[Learning guide (Bahasa Indonesia)](docs/BELAJAR.md) ·
[Check catalog](docs/CHECKS.md) · [Architecture](docs/ARCHITECTURE.md) ·
[Synthetic example](examples/report.json) · [Changelog](CHANGELOG.md)

## Quick start

Requires **Linux and Python 3.10+**. No third-party runtime dependencies.
Install once with `pipx` (which creates an isolated environment), then run
`linscope` directly. If pipx reports that its command directory is absent from
PATH, run `pipx ensurepath` and open a new terminal.

```bash
git clone https://github.com/nomatterwhathappns/LinScope.git
cd LinScope
pipx install .
linscope --help
linscope
linscope --category ssh --category permissions
mkdir -p reports
linscope --format json --output reports/baseline.json
linscope --format html --output reports/review.html
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

## Coverage through v1.5

* **SSH:** effective default configuration via `sshd -T`, including normal
  `Include` expansion; root/password/empty-password login, key authentication,
  attempt limit, X11 and forwarded-port scope. Connection-specific `Match`
  contexts can be selected explicitly; live daemon flags and unselected contexts
  require separate review.
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
* **Kernel:** live forwarding/redirect sysctls, ASLR, kernel log/pointer access,
  protected links, and ptrace restrictions. Router and container roles matter.
* **Packages:** installed count, local APT metadata age, cached upgrade simulation,
  and reboot-marker hints. No metadata is downloaded and no CVEs are inferred.
* **Logging:** common logging services, journald storage/retention configuration,
  log-directory/rotation configuration permissions, auditd, and reported time sync.
* **Scheduled tasks:** system cron/task metadata and direct root executable
  paths, plus system timer/service unit metadata; includes resolved ancestors.
* **Filesystem:** effective backing mount options for temporary directories,
  ownership/sticky bits, and fstab permissions; handles directory symlinks.
* **Mandatory access control:** available LSMs, AppArmor profile modes, SELinux
  enforcement, and persistent SELinux configuration. Both are not required.

The primary target is Ubuntu/Debian. Other distributions and containers may
produce `UNKNOWN` or `SKIP`; support must be verified before relying on results.
Use `--profile server|desktop|router|container` to state the intended host role.

* **POSIX ACLs:** effective named/group access under the ACL mask on protected
  targets, plus directory default-inheritance review.
* **Effective sudo:** noninteractive evaluated policy listings for selected
  users; passwordless and broad-command review without running any grant or
  collecting raw permitted command arguments.

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

## Policy and accepted-risk exceptions

Start with [examples/policy.json](examples/policy.json). `profile` and `checks`
select a host role and category scope; command-line selections override them.
Unknown keys, duplicate keys, invalid dates, and empty scopes are rejected.

```bash
linscope --policy examples/policy.json
linscope --profile router --category kernel
```

An exception documents a specific accepted risk and must have a reason and an
expiry date. It never removes a finding or changes its original status/severity:

```json
{
  "exceptions": {
    "SSH-002": {
      "reason": "Temporary password access during a controlled migration",
      "expires": "2030-01-01"
    }
  }
}
```

Choose the real review deadline; the date above is illustrative. Expiry is
inclusive through that UTC date. Expired exceptions stay visible as inactive.
Exception IDs absent from a report produce visible policy warnings, including
when a category is excluded or its evidence cannot be collected.

By default `--fail-on` still counts findings with active exceptions. To explicitly
honor accepted risks for that threshold, use both `--policy` and
`--honor-exceptions`. UNKNOWN coverage is never excused by this option.

```bash
linscope --policy examples/policy.json --fail-on high --fail-on-unknown
```

## Deeper checks and custom baselines

```bash
linscope --category ssh --ssh-context user=alice,addr=192.0.2.10,host=client.example
linscope --category acl --category sudo --sudo-user alice
linscope --policy examples/policy-custom.json
```

SSH context keys are `user`, `addr` (numeric IP), and `host`; optional `laddr`
and `lport` allow local-address/port Match conditions. Contexts do not connect to
those addresses. Each target has a stable hashed ID usable in exceptions.

Custom `baseline` supports `SSH-001.allowed` (valid PermitRootLogin modes),
`SSH-005.max_attempts` (integer 1..100), and `PACKAGES-002.max_age_days`
(integer 1..365). The same SSH baseline applies to default and selected Match
contexts; the package threshold also governs whether a zero-upgrade result can
be trusted. `ssh_contexts` and `sudo_users` can be supplied in policy. CLI target
selections override the respective policy selections. Different nondefault
parameters are recorded in scope and cannot be compared as equivalent scans.

Effective sudo listings use `sudo -n -ll -U USER`, never command execution or
interactive elevation. Sudo may consult its configured policy backends; listing
failure remains UNKNOWN. Without explicit selection only the real-UID account
is queried. Listings describe sudo policy, not every possible escalation path.

## Compare reports

```bash
linscope --compare examples/report.json examples/report-after.json
linscope --compare reports/baseline.json reports/after.json --format json
```

Comparison is offline and supports text/JSON output. Host name, OS, profile,
selected categories, and deep-search scope must match. A kernel/version update
is allowed. Only WARN/FAIL changing to PASS is counted as resolved. Missing checks
or a transition to UNKNOWN/SKIP never counts as a fix. Changes in evidence,
severity, or exception metadata remain visible. It is a snapshot comparison,
not a continuously running monitor.

## Development

```bash
python3 -m unittest discover -v
```

Tests use synthetic configuration and command results. They do not change host
security settings or require root. See [CHANGELOG.md](CHANGELOG.md) for checkpoints.
GitHub Actions runs unit tests on Python 3.10, 3.12, and 3.13, validates a package
installation, and checks offline report comparison. Live smoke checks in this
project's cloud container do not establish full behavior on every Ubuntu/Debian
release; validate on your target VM before operational use.

## Checkpoint workflow

All checkpoints are on `main`: `v1.0`, `v1.1`, `v1.2`, `v1.3`, `v1.4`.
To study a completed version without moving main:

```bash
git switch --detach v1.0
# Return to the latest version:
git switch main
```
