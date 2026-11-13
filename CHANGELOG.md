# Changelog

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
