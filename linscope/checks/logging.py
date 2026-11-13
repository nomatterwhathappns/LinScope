"""Inspect common systemd logging/audit facilities with explicit scope.

Custom logging agents, remote delivery, rotation success and actual audit-rule
coverage are not proven by these configuration/runtime checks. Non-systemd
hosts yield UNKNOWN for systemd-dependent checks.
"""
from __future__ import annotations

import stat

from linscope.core import Finding, unavailable


def _properties(text):
    values = {}
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if sep:
            values[key.strip()] = value.strip()
    return values


def _unit(ctx, name):
    result = ctx.command(["systemctl", "show", name, "--property=LoadState", "--property=ActiveState"])
    if not result.ok:
        return None
    props = _properties(result.stdout)
    if not props.get("LoadState") or not props.get("ActiveState"):
        return None
    return props


def _journal_settings(ctx):
    result = ctx.command(["systemd-analyze", "cat-config", "systemd/journald.conf"])
    if not result.ok:
        return None, result.error or "Effective journald configuration could not be collected"
    values = {}
    section = ""
    for raw in result.stdout.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            continue
        key, sep, value = line.partition("=")
        if section == "Journal" and sep:
            values[key.strip()] = value.strip()
    # cat-config reports main file and ordered drop-ins; the last scalar setting wins.
    return values, ""


def run(ctx):
    findings = []
    units = {name: _unit(ctx, name) for name in (
        "systemd-journald.service", "rsyslog.service", "syslog-ng.service")}
    known = {name: props for name, props in units.items() if props is not None}
    active = [name for name, props in known.items()
              if props["LoadState"] == "loaded" and props["ActiveState"] == "active"]
    if active:
        findings.append(Finding("LOGGING-001", "logging", "Common logging service activity",
                                "PASS", "medium", "Active: " + ", ".join(active) +
                                ". Activity does not verify ingestion, retention or remote delivery.",
                                "Test expected log generation and delivery; monitor the logging pipeline."))
    elif len(known) == len(units):
        findings.append(Finding("LOGGING-001", "logging", "Common logging service activity",
                                "WARN", "medium", "None of journald, rsyslog or syslog-ng is active. "
                                "Custom agents and container logging drivers were not assessed.",
                                "Confirm that a suitable logging pipeline collects and retains system events."))
    else:
        findings.append(unavailable("LOGGING-001", "logging", "Common logging service activity",
                                    "Could not determine all candidate service states; no confirmed active service"))

    journal, error = _journal_settings(ctx)
    title = "Journald persistent-storage configuration"
    if journal is None:
        findings.append(unavailable("LOGGING-002", "logging", title, error))
    else:
        storage = journal.get("Storage", "auto") or "auto"
        if storage == "persistent":
            status, evidence = "PASS", "Effective Storage=persistent requests persistent storage. Runtime writes were not tested."
        elif storage == "auto":
            try:
                directory = ctx.stat("/var/log/journal")
            except FileNotFoundError:
                status, evidence = "WARN", "Storage=auto and /var/log/journal is absent; journal defaults to volatile storage."
            except OSError as exc:
                status, evidence = "UNKNOWN", f"Storage=auto but journal directory cannot be inspected: {exc}"
            else:
                if stat.S_ISDIR(directory.st_mode):
                    status, evidence = "PASS", "Storage=auto and /var/log/journal is a directory; persistent storage is configured. Runtime writes were not tested."
                else:
                    status, evidence = "WARN", "Storage=auto but /var/log/journal is not a directory."
        elif storage in ("volatile", "none"):
            status, evidence = "WARN", f"Effective Storage={storage}; local journal persistence is not requested."
        else:
            status, evidence = "UNKNOWN", "Unrecognized effective journald Storage value."
        findings.append(Finding("LOGGING-002", "logging", title, status, "medium", evidence,
                                "Choose retention appropriate for incident investigation. Containers may use "
                                "a host-side logging driver; document that exception and verify delivery."))

    title = "System log directory ownership and permissions"
    try:
        item = ctx.stat("/var/log")
    except OSError as exc:
        findings.append(unavailable("LOGGING-003", "logging", title, exc))
    else:
        mode = stat.S_IMODE(item.st_mode)
        good = stat.S_ISDIR(item.st_mode) and item.st_uid == 0 and not mode & 0o002
        findings.append(Finding("LOGGING-003", "logging", title, "PASS" if good else "WARN", "medium",
                                f"/var/log uid={item.st_uid}, mode={mode:04o}; checks root ownership and no world write. "
                                "Individual log files and ACLs are outside this check.",
                                "Keep the directory root-owned and prevent untrusted writes; review service-specific permissions."))

    title = "Text-log rotation configuration permissions"
    try:
        item = ctx.stat("/etc/logrotate.conf")
    except FileNotFoundError:
        findings.append(unavailable("LOGGING-004", "logging", title,
                                    "No /etc/logrotate.conf found; journald or other rotation mechanisms may be used.",
                                    "Verify retention for text logs or document an alternative rotation mechanism."))
    except OSError as exc:
        findings.append(unavailable("LOGGING-004", "logging", title, exc))
    else:
        mode = stat.S_IMODE(item.st_mode)
        good = stat.S_ISREG(item.st_mode) and item.st_uid == 0 and not mode & 0o022
        findings.append(Finding("LOGGING-004", "logging", title, "PASS" if good else "WARN", "medium",
                                f"/etc/logrotate.conf uid={item.st_uid}, mode={mode:04o}; rotation execution and included files were not tested.",
                                "Keep rotation configuration root-owned and not group/world writable. "
                                "Verify timer/cron execution and included service configurations separately."))

    title = "Audit daemon service activity"
    audit = _unit(ctx, "auditd.service")
    if audit is None:
        findings.append(unavailable("LOGGING-005", "logging", title, "Audit daemon systemd state could not be collected"))
    else:
        active = audit["LoadState"] == "loaded" and audit["ActiveState"] == "active"
        status = "PASS" if active else ("INFO" if ctx.profile in ("desktop", "container") else "WARN")
        findings.append(Finding("LOGGING-005", "logging", title, status, "medium",
                                f"auditd LoadState={audit['LoadState']}, ActiveState={audit['ActiveState']}; "
                                "kernel audit enablement, alternative tooling and rule coverage are not established.",
                                "For hosts requiring audit trails, verify auditd or an approved alternative and test required rules. "
                                "Container auditing is generally coordinated with the host."))

    title = "Reported network time synchronization"
    clock = ctx.command(["timedatectl", "show", "--property=NTPSynchronized", "--property=NTP"])
    props = _properties(clock.stdout) if clock.ok else {}
    synced = props.get("NTPSynchronized")
    if synced not in ("yes", "no", "true", "false"):
        findings.append(unavailable("LOGGING-006", "logging", title,
                                    clock.error or "No recognized NTPSynchronized property; time may be managed externally"))
    else:
        good = synced in ("yes", "true")
        findings.append(Finding("LOGGING-006", "logging", title, "PASS" if good else "WARN", "medium",
                                f"timedatectl reports NTPSynchronized={synced}; NTP={props.get('NTP', 'unknown')}. "
                                "This is a runtime service report, not an independent clock comparison.",
                                "Use a trusted time source and investigate synchronization failures. "
                                "Containers may inherit the host clock."))

    title = "Journald retention settings inventory"
    if journal is None:
        findings.append(unavailable("LOGGING-007", "logging", title, error))
    else:
        keys = ("SystemMaxUse", "SystemKeepFree", "RuntimeMaxUse", "RuntimeKeepFree", "MaxRetentionSec")
        explicit = [key for key in keys if journal.get(key)]
        findings.append(Finding("LOGGING-007", "logging", title, "INFO", "info",
                                "Explicit retention keys: " + (", ".join(explicit) if explicit else "none; systemd defaults apply") +
                                ". Values and actual retained history need operational review.",
                                "Set and test retention according to storage capacity and investigation needs. "
                                "Default retention limits are not automatically insecure."))
    return findings
