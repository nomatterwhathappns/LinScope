"""AppArmor/SELinux observations; neither mechanism is required alongside the other.

Loaded profiles are not proof that every service is confined. aa-status JSON is
used when available; unsupported output and insufficient privilege stay UNKNOWN.
"""
from __future__ import annotations

import json

from linscope.core import Finding, unavailable


def _lsms(ctx):
    try:
        values = {v.strip() for v in ctx.read("/sys/kernel/security/lsm").strip().split(",") if v.strip()}
        return values or None
    except OSError:
        return None


def _apparmor(ctx, lsms):
    if lsms is not None and "apparmor" not in lsms:
        return False, "AppArmor is absent from the active LSM list."
    try:
        raw = ctx.read("/sys/module/apparmor/parameters/enabled").strip().lower()
        if raw in ("y", "yes", "1"):
            return True, "AppArmor kernel parameter is enabled."
        if raw in ("n", "no", "0"):
            return False, "AppArmor kernel parameter is disabled."
        return None, "Unrecognized AppArmor kernel parameter."
    except FileNotFoundError:
        if lsms is not None and "apparmor" not in lsms:
            return False, "AppArmor is absent from the active LSM list."
        return None, "AppArmor kernel parameter is unavailable."
    except OSError as exc:
        return None, f"AppArmor state unreadable: {exc}"


def _selinux(ctx, lsms):
    command = ctx.command(["getenforce"])
    if command.ok:
        state = command.stdout.strip().lower()
        if state in ("enforcing", "permissive", "disabled"):
            return state, f"getenforce reports {state}."
        return None, "getenforce returned an unrecognized state."
    try:
        raw = ctx.read("/sys/fs/selinux/enforce").strip()
        if raw in ("0", "1"):
            state = "enforcing" if raw == "1" else "permissive"
            return state, f"SELinux runtime enforcement value is {raw}."
        return None, "Unrecognized SELinux enforcement value."
    except FileNotFoundError:
        if lsms is not None and "selinux" not in lsms:
            return "disabled", "SELinux is absent from the active LSM list."
        return None, "SELinux runtime state is unavailable; missing tooling is not proof of disablement."
    except OSError as exc:
        return None, f"SELinux runtime state unreadable: {exc}"


def run(ctx):
    lsms = _lsms(ctx)
    aa_enabled, aa_evidence = _apparmor(ctx, lsms)
    se_state, se_evidence = _selinux(ctx, lsms)
    active = aa_enabled is True or se_state in ("enforcing", "permissive")
    known_inactive = aa_enabled is False and se_state == "disabled"
    results = [Finding(
        "MAC-001", "mac", "Mandatory access control runtime availability",
        "INFO" if active else "WARN" if known_inactive else "UNKNOWN",
        "medium" if known_inactive else "info",
        aa_evidence + " " + se_evidence +
        (" Container observations do not establish host-wide policy." if ctx.profile == "container" else ""),
        "Use the distribution-supported AppArmor or SELinux policy and inspect workload coverage; "
        "kernel availability alone does not prove effective confinement.")]
    if aa_enabled is False:
        results.append(Finding("MAC-002", "mac", "AppArmor profile enforcement", "SKIP", "info",
                               aa_evidence, "AppArmor need not be installed alongside SELinux; review MAC-001 and MAC-003."))
    elif aa_enabled is None:
        results.append(unavailable("MAC-002", "mac", "AppArmor profile enforcement", aa_evidence))
    else:
        command = ctx.command(["aa-status", "--json"])
        if not command.ok:
            results.append(unavailable("MAC-002", "mac", "AppArmor profile enforcement",
                                       command.error or f"aa-status returned {command.returncode}; profile data could not be collected."))
        else:
            try:
                payload = json.loads(command.stdout)
                profiles = payload["profiles"]
                if not isinstance(profiles, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in profiles.items()):
                    raise ValueError("Unsupported AppArmor profile data")
                allowed = {"enforce", "complain", "kill", "unconfined", "prompt", "special-unconfined"}
                if any(mode not in allowed for mode in profiles.values()):
                    raise ValueError("Unrecognized AppArmor profile mode")
                enforce = sum(mode in ("enforce", "kill") for mode in profiles.values())
                relaxed = len(profiles) - enforce
                warn = not profiles or bool(relaxed)
                results.append(Finding("MAC-002", "mac", "AppArmor profile enforcement", "WARN" if warn else "PASS",
                                       "medium" if warn else "info",
                                       f"Loaded profiles={len(profiles)}; enforcing/kill={enforce}; other modes={relaxed}. "
                                       "This count does not establish coverage of every process.",
                                       "Review profiles in non-enforcing modes and verify important workloads have appropriate profiles."))
            except (ValueError, KeyError, TypeError) as exc:
                results.append(unavailable("MAC-002", "mac", "AppArmor profile enforcement", str(exc)))
    if se_state is None:
        results.append(unavailable("MAC-003", "mac", "SELinux runtime enforcement", se_evidence))
    elif se_state == "disabled":
        results.append(Finding("MAC-003", "mac", "SELinux runtime enforcement", "SKIP", "info", se_evidence,
                               "SELinux is not active; AppArmor may provide the host's confinement instead."))
    else:
        results.append(Finding("MAC-003", "mac", "SELinux runtime enforcement",
                               "PASS" if se_state == "enforcing" else "WARN",
                               "info" if se_state == "enforcing" else "medium", se_evidence,
                               "Use enforcing mode after validating workload policy; review labels and policy coverage separately."))
    try:
        text = ctx.read("/etc/selinux/config")
        states = []
        for raw in text.splitlines():
            line = raw.split("#", 1)[0].strip()
            key, sep, value = line.partition("=")
            if sep and key.strip() == "SELINUX":
                states.append(value.strip().strip("\"'").lower())
        if len(states) != 1 or states[0] not in ("enforcing", "permissive", "disabled"):
            raise ValueError("SELINUX setting is absent, duplicated, or unsupported")
        configured = states[0]
        mismatch = se_state in ("enforcing", "permissive") and configured != se_state
        results.append(Finding("MAC-004", "mac", "SELinux persistent configuration", "WARN" if mismatch else "INFO",
                               "medium" if mismatch else "info",
                               f"SELINUX={configured}; runtime={se_state or 'unknown'}. Boot parameters can override this file.",
                               "Keep persistent configuration consistent with the intended boot policy; inspect kernel command-line overrides."))
    except FileNotFoundError:
        results.append(Finding("MAC-004", "mac", "SELinux persistent configuration",
                               "SKIP" if se_state == "disabled" else "UNKNOWN", "info",
                               "/etc/selinux/config does not exist.", "Review the distribution-specific SELinux policy if SELinux is intended."))
    except (OSError, ValueError) as exc:
        results.append(unavailable("MAC-004", "mac", "SELinux persistent configuration", exc))
    return results
