"""Review selected system-service hardening properties without changing units.

The default scope is at most 30 currently running system services in the current
systemd manager/namespace. Explicit service names may also inspect inactive
loaded units. Properties describe configured restrictions, not demonstrated
process isolation: executable privilege prefixes, service-specific exceptions,
actual syscall behavior, and all workloads are outside this review. Root is a
legitimate identity for many services and is therefore inventory, not a failure.
"""
from __future__ import annotations

import hashlib
import re

from linscope.core import Finding, unavailable

CATEGORY = "systemd"
MAX_UNITS = 30
LIST_COMMAND = ["systemctl", "list-units", "--type=service", "--state=running",
                "--no-legend", "--no-pager", "--plain"]
PROPERTIES = ("Id", "LoadState", "ActiveState", "User", "DynamicUser",
              "NoNewPrivileges", "ProtectSystem", "ProtectHome", "PrivateTmp",
              "CapabilityBoundingSet", "RestrictSUIDSGID")
_UNIT = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.@:\\-]*\.service", re.ASCII)
_USER = re.compile(r"(?:[A-Za-z_][A-Za-z0-9_.-]*\$?|[0-9]+)", re.ASCII)
_CAPABILITY = re.compile(r"cap_[a-z0-9_]+", re.ASCII)
_ACTIVE_STATES = {"active", "reloading", "inactive", "failed", "activating",
                  "deactivating", "maintenance", "refreshing"}
_HIGH_IMPACT_CAPS = {"cap_sys_admin", "cap_sys_module", "cap_sys_rawio",
                     "cap_sys_ptrace", "cap_dac_override", "cap_dac_read_search",
                     "cap_setuid", "cap_setgid", "cap_net_admin", "cap_sys_boot",
                     "cap_sys_time", "cap_mac_admin", "cap_mac_override"}
_TITLES = (
    "Service execution identity review",
    "NoNewPrivileges configuration",
    "ProtectSystem configuration",
    "ProtectHome configuration",
    "PrivateTmp configuration",
    "Capability bounding-set review",
    "RestrictSUIDSGID configuration",
)


def valid_unit(name):
    return isinstance(name, str) and len(name) <= 255 and bool(_UNIT.fullmatch(name))


def unit_id(unit, number):
    digest = hashlib.sha256(unit.encode("utf-8")).hexdigest()[:12].upper()
    return f"SYSTEMD-{digest}-{number:03d}"


def show_command(unit):
    return ["systemctl", "show", "--property=" + ",".join(PROPERTIES), "--", unit]


def _boolean(value):
    if value in {"yes", "true", "1"}:
        return True
    if value in {"no", "false", "0"}:
        return False
    return None


def _discovery(ctx):
    selected = getattr(ctx, "service_units", [])
    errors = []
    if selected:
        if not isinstance(selected, (list, tuple)):
            return [], ["service_units must be a list of system service names"], "explicit selection"
        names = set()
        for name in selected:
            if not valid_unit(name):
                errors.append("An explicitly selected service name is invalid; it was not queried")
            else:
                names.add(name)
        scope = "explicit selection"
    else:
        result = ctx.command(LIST_COMMAND)
        if not result.ok:
            return [], [result.error or "Running system service inventory is unavailable"], "running services"
        names = set()
        for line in result.stdout.splitlines():
            fields = line.split()
            if fields and fields[0] == "●":
                fields = fields[1:]
            if not fields:
                continue
            if (len(fields) < 4 or not valid_unit(fields[0])
                    or fields[1:4] != ["loaded", "active", "running"]):
                errors.append("Running-service inventory contains an unsupported or contradictory row")
                continue
            names.add(fields[0])
        scope = "currently running system services"
    if len(names) > MAX_UNITS:
        errors.append(f"Inventory contains {len(names)} services; only the first {MAX_UNITS} sorted names are inspected")
    return sorted(names)[:MAX_UNITS], errors, scope


def _properties(text):
    values = {}
    for raw in text.splitlines():
        if not raw:
            continue
        key, separator, value = raw.partition("=")
        if not separator or key not in PROPERTIES or key in values:
            raise ValueError("Malformed, unexpected, or duplicate systemctl property")
        values[key] = value
    if values.get("LoadState") != "loaded":
        raise ValueError("Service is not confirmed loaded; default-looking properties cannot establish its configuration")
    if not valid_unit(values.get("Id")):
        raise ValueError("Resolved service identity is missing or unsupported")
    if values.get("ActiveState") not in _ACTIVE_STATES:
        raise ValueError("Service activity state is missing or unsupported")
    return values


def _finding(unit, number, status, severity, evidence, recommendation):
    return Finding(unit_id(unit, number), CATEGORY, f"{unit}: {_TITLES[number - 1]}",
                   status, severity, evidence, recommendation)


def _unknown(unit, number, evidence):
    return unavailable(unit_id(unit, number), CATEGORY, f"{unit}: {_TITLES[number - 1]}",
                       evidence, "Verify that the unit is loaded and the installed systemd supports the reported property; inspect the service's intended requirements.")


def _unit_findings(ctx, unit):
    result = ctx.command(show_command(unit))
    if not result.ok:
        reason = result.error or f"Read-only systemctl show failed (exit {result.returncode}); no service properties were evaluated"
        return [_unknown(unit, number, reason) for number in range(1, 8)]
    try:
        values = _properties(result.stdout)
    except ValueError as exc:
        return [_unknown(unit, number, str(exc)) for number in range(1, 8)]
    prefix = f"Requested={unit}; resolved={values['Id']}; ActiveState={values['ActiveState']}. "
    if getattr(ctx, "profile", "server") == "container":
        prefix += "Properties describe this manager/namespace, not the container host. "
    findings = []
    user, dynamic = values.get("User"), _boolean(values.get("DynamicUser"))
    if user is None or dynamic is None or (user and not _USER.fullmatch(user)):
        findings.append(_unknown(unit, 1, prefix + "User or DynamicUser is unavailable or unrecognized"))
    else:
        # User= empty is system manager's root default; it is not a missing field.
        root = not user or user == "root" or (user.isascii() and user.isdigit() and int(user) == 0)
        identity = ("dynamic-user handling requested; existing-account resolution was not inspected" if dynamic
                    else "root/default identity" if root else "explicit identity configured; actual UID and process credentials were not resolved")
        findings.append(_finding(unit, 1, "INFO", "info", prefix + f"User={user or '(default root)'}; DynamicUser={values['DynamicUser']}; {identity}.",
                                 "Confirm the required privilege level and use a dedicated identity where practical. Root execution alone is not a vulnerability; these properties do not inspect command-specific privilege prefixes."))

    for number, key, recommendation in (
        (2, "NoNewPrivileges", "Consider NoNewPrivileges=yes when compatible; it prevents gaining privileges through execve, not every privileged operation."),
        (7, "RestrictSUIDSGID", "Consider RestrictSUIDSGID=yes for services that do not need to create SUID/SGID files; verify application compatibility."),
    ):
        flag = _boolean(values.get(key))
        if flag is None:
            findings.append(_unknown(unit, number, prefix + f"{key} is unavailable or unrecognized"))
        else:
            findings.append(_finding(unit, number, "PASS" if flag else "WARN", "medium",
                                     prefix + f"{key}={values[key]}; configured service property, not a runtime isolation test.", recommendation))

    for number, key, expected, recognized, recommendation in (
        (3, "ProtectSystem", {"full", "strict"}, {"no", "yes", "full", "strict"},
         "Consider ProtectSystem=full or strict where compatible, with narrowly scoped writable paths for required state. Review executable privilege prefixes and namespace support."),
        (4, "ProtectHome", {"yes", "read-only", "tmpfs"}, {"no", "yes", "read-only", "tmpfs"},
         "Restrict access to home directories when the service does not require it; select yes, read-only, or tmpfs according to the workload."),
        (5, "PrivateTmp", {"yes", "disconnected"}, {"no", "yes", "disconnected"},
         "Consider a private temporary directory when compatible; verify sharing requirements and the installed systemd version."),
    ):
        value = values.get(key)
        if value not in recognized:
            findings.append(_unknown(unit, number, prefix + f"{key} is unavailable or unrecognized"))
        else:
            findings.append(_finding(unit, number, "PASS" if value in expected else "WARN", "medium",
                                     prefix + f"{key}={value}; checked configuration only; per-command exceptions and runtime enforcement are not established.", recommendation))

    capabilities = values.get("CapabilityBoundingSet")
    if capabilities is None:
        findings.append(_unknown(unit, 6, prefix + "CapabilityBoundingSet is unavailable"))
    else:
        parts = capabilities.lower().split()
        if any(not _CAPABILITY.fullmatch(part) for part in parts):
            findings.append(_unknown(unit, 6, prefix + "CapabilityBoundingSet uses an unsupported representation"))
        else:
            observed = set(parts)
            high_impact = sorted(observed & _HIGH_IMPACT_CAPS)
            status = "WARN" if high_impact else "INFO" if observed else "PASS"
            findings.append(_finding(unit, 6, status, "high" if high_impact else "info",
                                     prefix + f"Bounding set contains {len(observed)} capabilities; selected high-impact capabilities: {', '.join(high_impact) or 'none'}. "
                                     "A bounding set limits possible capabilities; it does not prove which capabilities a process holds.",
                                     "Review every retained capability against service requirements. An empty bounding set is the restrictive baseline; root-level services may legitimately require selected capabilities."))
    return sorted(findings, key=lambda finding: finding.id)


def run(ctx):
    units, errors, scope = _discovery(ctx)
    evidence = f"Scope: {scope}; inspecting {len(units)} service(s), maximum {MAX_UNITS}. "
    evidence += " ".join(dict.fromkeys(errors)) if errors else "Selected inventory was collected without detected discovery errors."
    evidence += " Configuration properties do not prove process isolation or cover all system services and user managers."
    findings = [Finding("SYSTEMD-000", CATEGORY, "System service hardening inspection scope",
                        "UNKNOWN" if errors else "INFO", "info", evidence,
                        "Use explicit service selections to cover important inactive units. Review required privileges, systemd support, command-specific overrides, and runtime behavior separately.")]
    for unit in units:
        findings.extend(_unit_findings(ctx, unit))
    return findings
