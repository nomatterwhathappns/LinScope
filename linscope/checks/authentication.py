"""Local authentication review for Debian-style PAM and passwd metadata.

Presence of a PAM module is inventory, not proof that its control-flow enforces
policy. login.defs applies to account creation; it does not describe every user.
Password hashes are never read or reported. External identity stores are out of
scope, and fixed password rotation is not treated as universally beneficial.
"""
from __future__ import annotations

import re

from linscope.core import Context, Finding, unavailable

CATEGORY = "authentication"


def _finding(number, title, status, severity, evidence, recommendation):
    return Finding(f"AUTHENTICATION-{number:03d}", CATEGORY, title, status,
                   severity, evidence, recommendation)


def _active_lines(text):
    return [line.split("#", 1)[0].strip() for line in text.splitlines()
            if line.split("#", 1)[0].strip()]


def _defaults(ctx):
    try:
        text = ctx.read("/etc/login.defs")
    except OSError as exc:
        return [unavailable(f"AUTHENTICATION-{i:03d}", CATEGORY, title, exc)
                for i, title in [(1, "Password aging defaults"), (2, "Password expiry warning default")]]
    values = {}
    duplicates = set()
    for line in _active_lines(text):
        fields = line.split()
        if len(fields) >= 2 and fields[0] in {"PASS_MAX_DAYS", "PASS_MIN_DAYS", "PASS_WARN_AGE"}:
            if fields[0] in values:
                duplicates.add(fields[0])
            values[fields[0]] = fields[1]
    results = []
    keys = ("PASS_MAX_DAYS", "PASS_MIN_DAYS")
    if any(key not in values or not re.fullmatch(r"-?\d+", values[key]) or key in duplicates for key in keys):
        results.append(_finding(1, "Password aging defaults", "UNKNOWN", "info",
                                "Required login.defs aging settings are absent, duplicated, or not numeric.",
                                "Review login.defs; inspect existing account metadata separately."))
    else:
        results.append(_finding(1, "Password aging defaults", "INFO", "info",
                                "; ".join(f"{key}={values[key]}" for key in keys) +
                                ". These are creation defaults, not existing-user policy.",
                                "Choose aging policy for your environment; do not impose periodic rotation without a policy need."))
    key = "PASS_WARN_AGE"
    if key not in values or not re.fullmatch(r"-?\d+", values[key]) or key in duplicates:
        results.append(_finding(2, "Password expiry warning default", "UNKNOWN", "info",
                                "PASS_WARN_AGE is absent, duplicated, or not numeric.",
                                "Inspect the effective warning period where password expiration is used."))
    else:
        warning = int(values[key])
        results.append(_finding(2, "Password expiry warning default", "WARN" if warning < 7 else "PASS",
                                "low", f"PASS_WARN_AGE={warning}; applies to newly created local accounts.",
                                "If password expiry is required, provide enough warning (baseline: at least 7 days)."))
    return results


def _pam(ctx):
    results = []
    try:
        lines = _active_lines(ctx.read("/etc/pam.d/common-password"))
        quality = any(re.search(r"(?:^|\s)(?:\S*/)?pam_(?:pwquality|passwdqc)\.so(?:\s|$)", line)
                      for line in lines)
        results.append(_finding(3, "PAM password quality module review", "INFO" if quality else "WARN",
                                "medium", "A quality module is referenced in common-password." if quality else
                                "No pam_pwquality or pam_passwdqc reference found in common-password.",
                                "Review PAM control flow, module options and external identity policy; module presence alone does not prove enforcement."))
    except OSError as exc:
        results.append(unavailable("AUTHENTICATION-003", CATEGORY, "PAM password quality module review", exc))
    auth_lines = []
    errors = []
    for path in ("/etc/pam.d/common-auth", "/etc/pam.d/common-account"):
        try:
            auth_lines.extend(_active_lines(ctx.read(path)))
        except OSError as exc:
            errors.append(str(exc))
    lockout = any(re.search(r"(?:^|\s)(?:\S*/)?pam_(?:faillock|tally2)\.so(?:\s|$)", line)
                  for line in auth_lines)
    if lockout:
        results.append(_finding(4, "PAM failed-login controls review", "INFO", "info",
                                "A faillock/tally2 module reference was found in the inspected PAM files." +
                                (" Some PAM files could not be inspected." if errors else ""),
                                "Verify the complete PAM sequence and lockout settings; consider denial-of-service impact and external identity controls."))
    elif errors:
        results.append(unavailable("AUTHENTICATION-004", CATEGORY, "PAM failed-login controls review",
                                   "Could not inspect all expected PAM files: " + "; ".join(errors)))
    else:
        results.append(_finding(4, "PAM failed-login controls review", "WARN", "medium",
                                "No faillock/tally2 reference found in common-auth or common-account.",
                                "Review whether local or external controls limit repeated authentication failures; absence here is not proof that no protection exists."))
    return results


def _account_metadata(ctx):
    titles = [(5, "Interactive local accounts without a password"), (6, "Existing-account password aging inventory")]
    try:
        passwd = ctx.read("/etc/passwd")
        interactive = set()
        for line in passwd.splitlines():
            if not line.strip() or line.startswith("#"):
                continue
            fields = line.split(":")
            if len(fields) != 7:
                raise ValueError("Malformed passwd entry")
            if not fields[0] or not fields[2].isdigit() or not fields[3].isdigit():
                raise ValueError("Malformed passwd account name or numeric UID/GID")
            if fields[0] == "root" or fields[6].rsplit("/", 1)[-1] not in {"nologin", "false", "sync", "shutdown", "halt"}:
                interactive.add(fields[0])
        if not interactive:
            raise ValueError("No local interactive-account metadata available")
    except (OSError, ValueError) as exc:
        return [unavailable(f"AUTHENTICATION-{i:03d}", CATEGORY, title, exc) for i, title in titles]
    cmd = ctx.command(["passwd", "-S", "-a"])
    if not cmd.ok:
        return [unavailable(f"AUTHENTICATION-{i:03d}", CATEGORY, title,
                            cmd.error or "passwd metadata unavailable; sufficient read permission is required.")
                for i, title in titles]
    metadata = {}
    malformed = False
    for line in cmd.stdout.splitlines():
        fields = line.split()
        if not fields:
            continue
        if len(fields) != 7 or fields[1] not in {"P", "L", "NP", "PS", "LK"}:
            malformed = True
            continue
        try:
            for index in (3, 4, 5, 6):
                int(fields[index])
        except ValueError:
            malformed = True
            continue
        if fields[0] in metadata:
            malformed = True
        metadata[fields[0]] = fields
    missing = interactive - metadata.keys()
    if malformed or missing:
        return [unavailable(f"AUTHENTICATION-{i:03d}", CATEGORY, title,
                            "passwd metadata is malformed or incomplete for the local interactive-account inventory.")
                for i, title in titles]
    empty = sorted(name for name in interactive if metadata[name][1] == "NP")
    empty_finding = _finding(5, titles[0][1], "FAIL" if empty else "PASS", "high",
                             "No password is set for: " + ", ".join(empty) if empty else
                             f"No NP (no-password) status among {len(interactive)} inspected interactive local accounts.",
                             "Lock unused accounts or set an appropriate credential; review PAM and SSH empty-password handling. NP status alone does not prove login is allowed.")
    enabled = [metadata[name] for name in interactive if metadata[name][1] in {"P", "PS"}]
    no_expiry = sum(int(row[4]) < 0 or int(row[4]) >= 99999 for row in enabled)
    inventory = _finding(6, titles[1][1], "INFO", "info",
                         f"{len(enabled)} password-set interactive local accounts; {no_expiry} have unlimited or >=99999-day maximum age. No hashes collected.",
                         "Compare actual account aging with your policy; local metadata does not cover remote identity providers or establish credential strength.")
    return [empty_finding, inventory]


def run(ctx: Context):
    return _defaults(ctx) + _pam(ctx) + _account_metadata(ctx)
