"""Declarative report exceptions; policies cannot run commands or hide findings."""
from __future__ import annotations

from copy import deepcopy
from datetime import date
import json
import os
from pathlib import Path
from pathlib import PurePosixPath
import re
import stat

PROFILES = ("server", "desktop", "router", "container")
CATEGORIES = ("ssh", "accounts", "permissions", "authentication", "network",
              "services", "kernel", "packages", "logging", "scheduled",
              "filesystem", "mac", "acl", "sudo", "systemd", "docker", "userfiles", "capabilities")
_CHECK_ID = re.compile(r"^[A-Z][A-Z0-9_]*(?:-[A-F0-9]{12})?-[0-9]{3,}$")
_USER = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}\$?")


def validate_users(users):
    if not isinstance(users, list) or len(users) > 20 or any(not isinstance(user, str) or not _USER.fullmatch(user) for user in users):
        raise ValueError("sudo_users must contain at most 20 simple local usernames")
    if len(users) != len(set(users)):
        raise ValueError("sudo_users must not contain duplicates")
    return sorted(users)


def validate_paths(paths):
    if not isinstance(paths, list) or len(paths) > 50:
        raise ValueError("user_paths must be a list of at most 50 absolute metadata paths")
    result = []
    for path in paths:
        if (not isinstance(path, str) or not path.startswith("/") or len(path) > 4096
                or ".." in PurePosixPath(path).parts or any(ord(c) < 32 or 127 <= ord(c) < 160 for c in path)):
            raise ValueError("user_paths require bounded absolute paths without traversal or control characters")
        result.append(str(PurePosixPath(path)))
    if len(result) != len(set(result)):
        raise ValueError("user_paths must not contain duplicate normalized paths")
    return sorted(result)


def validate_service_units(units):
    pattern = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.@:\\-]*\.service", re.ASCII)
    if not isinstance(units, list) or len(units) > 30:
        raise ValueError("service_units must be a list of at most 30 system service names")
    if any(not isinstance(unit, str) or len(unit) > 255 or not pattern.fullmatch(unit) for unit in units):
        raise ValueError("service_units must contain valid .service unit names without paths/options")
    if len(units) != len(set(units)):
        raise ValueError("service_units must not contain duplicates")
    return sorted(units)


def validate_baseline(baseline):
    if not isinstance(baseline, dict):
        raise ValueError("baseline must be an object keyed by supported check IDs")
    result = deepcopy(baseline)
    for check_id, value in result.items():
        if not isinstance(value, dict):
            raise ValueError(f"{check_id}: baseline must be an object")
        if check_id == "SSH-001":
            allowed = value.get("allowed")
            choices = {"no", "yes", "prohibit-password", "without-password", "forced-commands-only"}
            if set(value) != {"allowed"} or not isinstance(allowed, list) or not allowed or any(not isinstance(v, str) or v not in choices for v in allowed):
                raise ValueError("SSH-001 baseline requires a nonempty allowed list of PermitRootLogin values")
            normalized = ["prohibit-password" if v == "without-password" else v for v in allowed]
            if len(normalized) != len(set(normalized)):
                raise ValueError("SSH-001 allowed values must be unique (including aliases)")
            value["allowed"] = sorted(normalized)
        elif check_id in ("SSH-005", "PACKAGES-002"):
            key, upper = ("max_attempts", 100) if check_id == "SSH-005" else ("max_age_days", 365)
            if set(value) != {key} or type(value.get(key)) is not int or not 1 <= value[key] <= upper:
                raise ValueError(f"{check_id} baseline requires integer {key} in 1..{upper}")
        else:
            raise ValueError(f"Unsupported baseline check ID: {check_id}")
    return result


def validate_ssh_contexts(contexts):
    from linscope.checks.ssh import normalize_connection_context
    if not isinstance(contexts, list) or len(contexts) > 20:
        raise ValueError("ssh_contexts must be a list of at most 20 connection contexts")
    normalized = [normalize_connection_context(item) for item in contexts]
    keys = [json.dumps(item, sort_keys=True) for item in normalized]
    if len(keys) != len(set(keys)):
        raise ValueError("ssh_contexts must not contain duplicate contexts")
    return [item for _, item in sorted(zip(keys, normalized), key=lambda pair: pair[0])]


def parse_ssh_context(value):
    context = {}
    for part in value.split(","):
        key, sep, item = part.partition("=")
        if not sep or not key or key in context:
            raise ValueError("SSH context requires unique comma-separated key=value fields")
        context[key] = item
    if "lport" in context:
        if not re.fullmatch(r"[0-9]+", context["lport"]):
            raise ValueError("SSH lport must be an integer")
        context["lport"] = int(context["lport"])
    return validate_ssh_contexts([context])[0]


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate policy key: {key}")
        result[key] = value
    return result


def validate_policy(policy: dict) -> dict:
    """Validate a policy and return a detached copy, without changing its meaning."""
    if not isinstance(policy, dict):
        raise ValueError("Policy must be a JSON object")
    unknown = set(policy) - {"profile", "checks", "exceptions", "baseline", "ssh_contexts", "sudo_users", "user_paths", "service_units"}
    if unknown:
        raise ValueError("Unknown policy keys: " + ", ".join(sorted(unknown)))
    if "profile" in policy and policy["profile"] not in PROFILES:
        raise ValueError("profile must be server, desktop, router, or container")
    if "checks" in policy:
        checks = policy["checks"]
        if not isinstance(checks, list) or not checks:
            raise ValueError("checks must be a non-empty list of category names")
        if any(not isinstance(item, str) or item not in CATEGORIES for item in checks):
            raise ValueError("checks contains an unsupported category")
        if len(checks) != len(set(checks)):
            raise ValueError("checks must not contain duplicates")
    exceptions = policy.get("exceptions", {})
    if not isinstance(exceptions, dict):
        raise ValueError("exceptions must be an object keyed by stable check IDs")
    for check_id, exception in exceptions.items():
        if not isinstance(check_id, str) or not _CHECK_ID.fullmatch(check_id):
            raise ValueError(f"Invalid exception check ID: {check_id}")
        if not isinstance(exception, dict) or set(exception) != {"reason", "expires"}:
            raise ValueError(f"{check_id}: exception requires only reason and expires")
        reason = exception["reason"]
        if not isinstance(reason, str) or not reason.strip() or len(reason) > 2000:
            raise ValueError(f"{check_id}: reason must contain 1-2000 characters")
        expires = exception["expires"]
        if not isinstance(expires, str) or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", expires):
            raise ValueError(f"{check_id}: expires must be an ISO date (YYYY-MM-DD)")
        try:
            date.fromisoformat(expires)
        except ValueError as exc:
            raise ValueError(f"{check_id}: invalid expiry date") from exc
    result = deepcopy(policy)
    if "baseline" in policy:
        result["baseline"] = validate_baseline(policy["baseline"])
    if "ssh_contexts" in policy:
        result["ssh_contexts"] = validate_ssh_contexts(policy["ssh_contexts"])
    if "sudo_users" in policy:
        result["sudo_users"] = validate_users(policy["sudo_users"])
    if "user_paths" in policy:
        result["user_paths"] = validate_paths(policy["user_paths"])
    if "service_units" in policy:
        result["service_units"] = validate_service_units(policy["service_units"])
    return result


def load_policy(path: str | Path) -> dict:
    """Load a bounded UTF-8 JSON policy; duplicate and unknown keys are errors."""
    fd = os.open(Path(path), os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise OSError("Policy must be a regular file")
        raw = stream.read(262_145)
    if len(raw) > 262_144:
        raise ValueError("Policy exceeds the 256 KiB size limit")
    try:
        policy = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid policy JSON at line {exc.lineno}: {exc.msg}") from exc
    return validate_policy(policy)


def apply_exceptions(findings: list[dict], policy: dict, today: date | None = None) -> list[dict]:
    """Annotate findings without suppressing them or changing status/severity.

    Expiry is inclusive in UTC when today is not supplied. Expired exceptions
    stay visible as active=False, so stale policy never silently accepts risk.
    """
    if today is None:
        from datetime import datetime, timezone
        today = datetime.now(timezone.utc).date()
    validated = validate_policy(policy)
    result = deepcopy(findings)
    for finding in result:
        # Never trust exception metadata already attached to input findings.
        finding.pop("exception", None)
        exception = validated.get("exceptions", {}).get(finding["id"])
        if exception:
            finding["exception"] = {
                "reason": exception["reason"], "expires": exception["expires"],
                "active": date.fromisoformat(exception["expires"]) >= today,
            }
    return result
