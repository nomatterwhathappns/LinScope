# Terminal usage

Install once from the repository using `pipx install .`, then use `linscope`.
No GUI, browser, desktop session, server, or Python command is needed to run
checks. A browser is optional for opening generated HTML reports.

## Inspect collection capabilities

```bash
linscope --preflight
linscope --preflight --category ssh --category sudo --format json
linscope --list-categories
```

Preflight discovers executables and samples metadata/read-access hints. It does
not run audit commands, attempt elevation, open credential contents, or guarantee
that a command will succeed. Missing tools and read permissions explain some
UNKNOWN findings. Container detection is a hint, not proof of host type.

## Collect and choose a display

```bash
linscope --progress
linscope --status WARN --status FAIL --sort severity
linscope --min-severity high --view-category ssh
linscope --summary
linscope --category kernel --profile router
```

`--category` chooses what is collected. `--view-category`, `--status`,
`--min-severity`, `--sort`, and `--summary` only change the text/HTML view. Full
counts and coverage remain visible. Priority summaries rank WARN/FAIL findings;
they are not an overall numerical security score.

`--fail-on` and `--fail-on-unknown` always evaluate the complete collected report,
even if a display filter hides details. JSON is always complete, so combining
JSON output with display options is rejected rather than silently dropping data.
Progress goes to stderr and cannot pollute machine-readable stdout.

## Save reports

```bash
mkdir -p reports
linscope --format json --output reports/baseline.json
linscope --format html --output reports/review.html
linscope --format html --status FAIL --output reports/priority-view.html
```

Output paths must not already exist. JSON stores full evidence. HTML retains all
findings and supports local search, category/status/severity filters, sorting,
summary, and details controls. Requested CLI filters initialize its view, and
Show all/reset restores the full report. With JavaScript disabled all findings
and evidence remain visible. No remote scripts, fonts, or services are loaded.

Text output with filters contains only the requested detailed view. Use JSON or
opt-in history if you also want to persist the complete report.

## Keep private local history

```bash
linscope --history-dir reports/history --summary
linscope --history-dir reports/history --compare-latest --summary
linscope --history-dir reports/history --history-list
linscope --history-dir reports/history --history-list --format json
```

History is off by default. Its directory must be owned by the effective user
and have mode 0700; a new directory is created privately. Saved reports use mode
0600 and unique filenames. Do not mix root and non-root histories. Stored JSON
always contains all findings, including evidence hidden by display filters.

`--compare-latest` selects the latest compatible snapshot before saving the
current scan. The first compatible scan establishes a baseline. Other hosts,
profiles, selected categories, deep-search modes, or baseline/target parameters
are not treated as equivalent. A transition to UNKNOWN or SKIP is never resolved.
Assessment-rule fingerprints must match too. A new verified scan will not select
an older snapshot without rule metadata; the first matching scan establishes a
new baseline. Legacy-only offline comparisons carry an explicit unverified label.

History listing is offline and performs no audit commands. Corrupt/unsafe history
files fail visibly instead of silently disappearing. At most 500 report files
and 10,000 directory entries are inspected; archive older files yourself when
the limit is reached. No reports are automatically deleted or uploaded.

The primary text/JSON/HTML output is written before saving history. If history
storage fails, the command returns 2 and reports the failure on stderr; a primary
output may already exist. Finding threshold exits can still save valid snapshots.

History data is written and synced under a hidden temporary name, then published
atomically without replacing any existing pathname. This uses Linux
`renameat2(RENAME_NOREPLACE)` on supporting libc/kernel/filesystems. Unsupported
publication returns 2 explicitly. A kill before publication can leave an ignored
hidden temporary file, but cannot publish a half-written report. A directory-sync
failure after publication leaves a complete visible file and reports that its
power-loss durability could not be confirmed. No history is silently deleted.

## Update an installed local checkout

```bash
git pull --ff-only
pipx install --force .
linscope --version
```

Source changes do not automatically update a normal non-editable pipx
installation. Reinstall after switching checkpoints if you want to run that
version. Development tests still use Python's unittest runner; that is separate
from the installed command used to operate the tool.

## Select service and user-file targets

```bash
linscope --category systemd --service-unit nginx.service --service-unit ssh.service
linscope --category docker
linscope --category userfiles
linscope --category userfiles --user-path /home/alice/.ssh/id_ed25519
```

Choose a real path/account for your host; the absolute path above is illustrative.
The user-file owner baseline stays the invoking real UID/root, so selecting
another user's paths does not silently change the trusted identity. `user_paths`
and `service_units` are also accepted in policy, with CLI selections overriding
the corresponding policy list. Up to 50 absolute paths and 30 units are allowed.
No shell expansion or executable commands are accepted in policy.

Docker checks are optional by category and require access to the conventional
local rootful socket; rootless/custom/remote Docker contexts are not used.
They do not start/build/modify containers. Missing tooling or daemon access stays
visible. Systemd checks inspect configured hardening properties, not application
compatibility or runtime enforcement. No GUI is needed for these categories.

## Review file capabilities and expanded ACLs

```bash
linscope --category capabilities
linscope --category capabilities --deep --sort severity
linscope --category acl --service-unit nginx.service
linscope --category acl --user-path /home/alice/.aws/credentials
```

Capability checks need `getcap` from libcap tooling and `find`. They inspect
metadata without opening or executing target programs. Default roots are
`/usr/bin`, `/usr/sbin`, `/usr/local/bin`, and `/usr/local/sbin`; direct files by
default and recursive, no-cross-mount discovery with `--deep`. A grant such as
`cap_setuid` warrants review, but does not establish a working escalation path.
Permission failures, malformed output, diagnostics and limits remain visible.

ACL scope now includes conventional host private keys, invoking-user credential
paths, Docker socket, cron entries, system service/timer fragments/drop-ins,
and lexical/resolved parent directories. Default/inherited ACLs and effective
ACL masks are treated separately. Directory read/traversal is allowed by the
parent baseline; untrusted effective write needs review. Root-system target
roles cannot be weakened by selecting an overlapping path as a user credential.
Current-user scope includes the real UID even when only ACL is selected.

Command capture uses bounded memory instead of temporary output files. Exceeding
1 MiB on either output stream stops that invocation; timeout/overflow/interruption
cleans up the direct child and descendants retaining its process group. Processes
that deliberately detach into another group/session are outside that boundary.
