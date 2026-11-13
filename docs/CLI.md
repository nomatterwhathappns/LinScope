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

History listing is offline and performs no audit commands. Corrupt/unsafe history
files fail visibly instead of silently disappearing. At most 500 report files
and 10,000 directory entries are inspected; archive older files yourself when
the limit is reached. No reports are automatically deleted or uploaded.

The primary text/JSON/HTML output is written before saving history. If history
storage fails, the command returns 2 and reports the failure on stderr; a primary
output may already exist. Finding threshold exits can still save valid snapshots.

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
