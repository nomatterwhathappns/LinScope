# Changelog

## 1.8

* Stream command output with a live 1 MiB limit per channel, a monotonic deadline,
  and process-group cleanup on overflow/timeout/interruption. No output capture
  files are written, and malformed UTF-8 remains incomplete evidence.
* Write history under private hidden names, fsync data, and atomically publish
  with Linux renameat2 NOREPLACE. Preserve complete published reports on a later
  directory-sync failure and report unsupported atomic-publication platforms.
* Expand POSIX ACL review to host keys, user credentials, Docker socket,
  scheduled/system service paths and lexical/resolved parent directories.
* Record rule revision, effective default/custom configurable baselines, and
  source fingerprints for the full built-in rule pack. Prevent incompatible
  rule identities from being treated as comparable remediation evidence.
* Add bounded file-capability inventory with permitted/effective/inheritable
  sets, namespace root IDs, and explicit incomplete-collection coverage.
* Retain legacy report reading/comparison with a visible unverified-rules label;
  verified snapshots never mix with legacy or incomplete identities.

## 1.7

* Expand to 17 categories with systemd service-hardening properties, conventional
  local Docker socket/running-container configuration, and user credential-file metadata.
* Support explicit service-unit and absolute user-path selections in CLI/policy.
  Record target selections and current-account UID where identity affects scope.
* Bound automatic service/container discovery and keep missing properties,
  unsupported tools, permissions and namespace ambiguity visible.
* Project only selected Docker fields; never capture full inspect/environment
  data. User-file checks inspect metadata and ancestry without opening contents.
* Include regressions for numeric root UID variants, normalized bind paths,
  explicit-path baseline preservation, and strict projected JSON validation.

## 1.6

* Add display-only status/severity/category filtering, deterministic sorting,
  priority summaries, and optional stderr progress. Canonical JSON, history,
  evidence, and exit gates remain complete.
* Add advisory preflight command/access discovery without running audit commands.
* Add private opt-in local history, offline listing, and latest-compatible
  comparison; require matching host, profile, parameters and collection scope.
* Add offline HTML search/filter/sort and collapsible details with hashed static
  script CSP; all evidence is available when JavaScript is disabled.

## 1.5

* Evaluate explicit SSH user/address/host Match contexts with stable target IDs.
* Add mask-aware POSIX ACL checks and noninteractive effective sudo listings.
* Configure root-login acceptance, authentication attempt limits, and APT cache
  age with strictly validated baseline settings; record parameters in report scope.
* Keep different parameter/baseline scopes incomparable, retain collection
  uncertainty, and avoid collecting raw sudo command arguments or credential contents.
* Make the installed `linscope` command the primary documented entry point.

## 1.4

* Add standalone HTML reports, declarative profile/category policy, expiring
  visible exceptions, and conservative offline JSON report comparison.
* Preserve original finding status; active exceptions affect exit thresholds
  only with an explicit --honor-exceptions flag. Warn about unmatched IDs.
* Validate malformed identity records and UID_MIN rather than producing clean
  account findings from incomplete evidence.
* Reject FIFOs/special files and invalid UTF-8 during bounded file collection;
  preserve JSON evidence exactly even when redirected through stdout.
* Add integration/regression tests, package-install CI, synthetic reports, a
  check catalog, architecture notes, and an Indonesian learning guide.

## 1.3

* Complete 12-category scope with scheduled tasks, filesystem and MAC modules.
* Check lexical and resolved task/unit-file ancestors; select mount options
  using resolved paths so symlink targets cannot inherit the wrong verdict.
* Scope AppArmor/SELinux findings to available controls, and preserve container
  namespace/UID-mapping uncertainty.

## 1.2

* Add live kernel/sysctl, Debian/Ubuntu package-cache, and logging/audit checks.
* Treat stale/missing package metadata as incomplete coverage rather than
  declaring a host current. Never download metadata or apply upgrades.
* Review effective journald scalar settings and runtime time-sync reports.

## 1.1

* Add authentication, network/firewall, and systemd service checks.
* Keep PAM presence distinct from enforcement, and network bindings distinct
  from external reachability. Inspect both IPv4 and IPv6.
* Correct system-account shell handling: an empty shell defaults to an
  interactive shell; do not classify it as disabled.
* Refine sudo inventory handling for comments and root-prefixed usernames.

## 1.0

* Add a standard-library Python CLI and explicit evidence-based finding model.
* Review SSH defaults, local accounts/privileges, and file permissions.
* Add text/JSON reporting, scoped deep checks, exit policies, and private report files.
* Include fixture-based tests and document collection limitations.
