"""Declarative report exceptions; policies cannot run commands or hide findings."""
from __future__ import annotations

from copy import deepcopy
from datetime import date
import json
import os
from pathlib import Path
import re
import stat

PROFILES = ("server", "desktop", "router", "container")
CATEGORIES = ("ssh", "accounts", "permissions", "authentication", "network",
              "services", "kernel", "packages", "logging", "scheduled",
              "filesystem", "mac")
_CHECK_ID = re.compile(r"^[A-Z][A-Z0-9_]*-[0-9]{3,}$")


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
    unknown = set(policy) - {"profile", "checks", "exceptions"}
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
    return deepcopy(policy)


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
