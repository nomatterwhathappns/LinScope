"""Read Debian/Ubuntu package state without refreshing or downloading metadata.

Upgrade results are conditional on the local APT cache. No package/version-to-CVE
mapping is performed, and neither a fresh cache nor zero upgrades proves a
vulnerability-free host. Reboot markers are distribution-specific hints.
"""
from __future__ import annotations

import re
import time

from linscope.core import Finding, unavailable

CACHE_MAX_AGE = 7 * 86400


def _supported(ctx):
    try:
        text = ctx.read("/etc/os-release")
    except OSError as exc:
        return None, str(exc)
    values = {}
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if sep and key in ("ID", "ID_LIKE"):
            values[key] = value.strip().strip('"\'')
    identifiers = set((values.get("ID", "") + " " + values.get("ID_LIKE", "")).lower().split())
    if identifiers & {"debian", "ubuntu"}:
        return True, "Debian/Ubuntu package family"
    return False, "This module currently supports Debian/Ubuntu package tooling only"


def _cache(ctx):
    baseline = getattr(ctx, "baseline", {})
    if not isinstance(baseline, dict):
        return None, "Package baseline must be an object"
    config = baseline.get("PACKAGES-002", {"max_age_days": 7})
    if (not isinstance(config, dict) or set(config) != {"max_age_days"}
            or type(config["max_age_days"]) is not int or not 1 <= config["max_age_days"] <= 365):
        return None, "PACKAGES-002 max_age_days must be an integer in 1..365"
    max_age_days = config["max_age_days"]
    try:
        paths = sorted(set(ctx.glob("/var/lib/apt/lists/*_InRelease") +
                           ctx.glob("/var/lib/apt/lists/*_Release")))
        if not paths:
            return None, "No local APT Release/InRelease metadata was found"
        ages = [time.time() - ctx.stat(path).st_mtime for path in paths]
    except OSError as exc:
        return None, f"APT cache metadata could not be inspected: {exc}"
    if any(age < -300 for age in ages):
        return None, "APT metadata has a future timestamp; check system time"
    oldest = max(ages)
    evidence = (f"Inspected {len(paths)} Release/InRelease files; oldest local timestamp is "
                f"{max(oldest, 0) / 86400:.1f} days old; threshold is {max_age_days} days. "
                "Filesystem timestamps do not verify repository authenticity or a successful refresh.")
    return oldest <= max_age_days * 86400, evidence


def run(ctx):
    supported, detail = _supported(ctx)
    titles = [("PACKAGES-001", "Installed package inventory"),
              ("PACKAGES-002", "Local APT metadata freshness"),
              ("PACKAGES-003", "Pending package upgrades"),
              ("PACKAGES-004", "Distribution reboot-required hint")]
    if supported is not True:
        status = "UNKNOWN" if supported is None else "SKIP"
        return [Finding(check_id, "packages", title, status, "info", detail,
                        "Use Debian/Ubuntu for these package checks or inspect the native package manager separately.")
                for check_id, title in titles]
    findings = []
    inventory = ctx.command(["dpkg-query", "-W", "-f=${db:Status-Abbrev}\\n"])
    if not inventory.ok:
        findings.append(unavailable("PACKAGES-001", "packages", titles[0][1],
                                    inventory.error or "dpkg-query failed"))
    else:
        states = inventory.stdout.splitlines()
        count = sum(state.startswith("ii ") for state in states)
        if not states or any(len(state) < 3 for state in states):
            findings.append(unavailable("PACKAGES-001", "packages", titles[0][1],
                                        "Unrecognized or empty dpkg status output"))
        else:
            findings.append(Finding("PACKAGES-001", "packages", titles[0][1], "INFO", "info",
                                    f"{count} packages have dpkg status 'ii'; package names are omitted.",
                                    "Review installed packages for business need; this count is not a vulnerability scan."))
    fresh, cache_evidence = _cache(ctx)
    findings.append(Finding("PACKAGES-002", "packages", titles[1][1],
                            "UNKNOWN" if fresh is None else ("PASS" if fresh else "WARN"),
                            "medium", cache_evidence,
                            "Refresh package metadata through your normal maintenance process and rerun. "
                            "LinScope never refreshes or downloads package metadata."))
    upgrades = ctx.command(["apt-get", "-s", "--no-download", "-o", "Debug::NoLocking=1", "upgrade"], timeout=15)
    if not upgrades.ok:
        findings.append(unavailable("PACKAGES-003", "packages", titles[2][1],
                                    upgrades.error or "APT upgrade simulation failed"))
    else:
        installs = [line for line in upgrades.stdout.splitlines() if line.startswith("Inst ")]
        summary = re.search(r"(?m)^(\d+) upgraded, (\d+) newly installed, (\d+) to remove and (\d+) not upgraded\.",
                            upgrades.stdout)
        if not summary:
            findings.append(unavailable("PACKAGES-003", "packages", titles[2][1],
                                        "APT simulation did not provide a recognized complete summary"))
        else:
            upgraded, new, removed, held = map(int, summary.groups())
            # Inconsistency means the simulation cannot safely support a clean result.
            if len(installs) != upgraded + new:
                findings.append(unavailable("PACKAGES-003", "packages", titles[2][1],
                                            "APT simulation package lines and summary are inconsistent"))
            else:
                pending = upgraded + new + held + removed
                status = "WARN" if pending else ("PASS" if fresh is True else "UNKNOWN")
                evidence = (f"Cached simulation: {upgraded} upgrades, {new} new dependencies, "
                            f"{held} held/not upgraded, {removed} removals. No downloads or changes performed.")
                if fresh is not True:
                    evidence += " Cache freshness is unverified or stale; zero candidates cannot establish currency."
                findings.append(Finding("PACKAGES-003", "packages", titles[2][1], status, "medium",
                                        evidence,
                                        "Review available updates and held packages using your patch process. "
                                        "This does not identify CVEs or guarantee security-update coverage."))
    try:
        ctx.stat("/run/reboot-required")
    except FileNotFoundError:
        findings.append(Finding("PACKAGES-004", "packages", titles[3][1], "INFO", "info",
                                "No /run/reboot-required marker is present. Absence does not prove reboot is unnecessary.",
                                "Review kernel/library update history and your distribution's restart guidance."))
    except OSError as exc:
        findings.append(unavailable("PACKAGES-004", "packages", titles[3][1], exc))
    else:
        findings.append(Finding("PACKAGES-004", "packages", titles[3][1], "WARN", "medium",
                                "/run/reboot-required exists; this is a distribution hint, not an impact assessment.",
                                "Plan a restart according to change-management requirements. In a container, "
                                "coordinate host and container lifecycle separately."))
    return findings
