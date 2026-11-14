"""Deterministic identities for the rules used to assess a snapshot.

Fingerprints identify selected code and configuration, not authenticity or a
signature. Source hashes deliberately make comparison conservative: even a
format-only rule edit can require a new baseline.
"""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import re

RULESET_REVISION = "1.8.0"
DEFAULT_BASELINES = {
    "SSH-001": {"allowed": ["no"]},
    "SSH-005": {"max_attempts": 4},
    "PACKAGES-002": {"max_age_days": 7},
}
_BASELINE_CATEGORIES = {"SSH-001": "ssh", "SSH-005": "ssh", "PACKAGES-002": "packages"}
_SHA256 = re.compile(r"[0-9a-f]{64}", re.ASCII)
_CATEGORY = re.compile(r"[a-z][a-z0-9_]*", re.ASCII)
_ENGINE_SOURCES = ("core.py", "cli.py", "policy.py", "rules.py", "reporting.py",
                   "history.py", "registry.py", "checks/__init__.py")


def _digest(manifest):
    encoded = json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()
    return sha256(encoded).hexdigest()


def build_rules_snapshot(ctx, categories):
    """Record selected source identities and fully resolved configurable values."""
    selected = sorted(set(categories))
    if any(not isinstance(category, str) or not _CATEGORY.fullmatch(category) for category in selected):
        raise ValueError("Rule categories must be simple built-in names")
    from linscope.policy import validate_baseline
    overrides = validate_baseline(getattr(ctx, "baseline", {}))
    effective = {check_id: deepcopy(overrides.get(check_id, default))
                 for check_id, default in DEFAULT_BASELINES.items()
                 if _BASELINE_CATEGORIES[check_id] in selected}
    from linscope.policy import CATEGORIES
    # Include the full built-in pack: categories can import shared assessment
    # helpers from each other (for example authentication -> accounts).
    builtin_categories = sorted(set(CATEGORIES) | set(selected))
    source_files = list(_ENGINE_SOURCES)
    source_files += [f"checks/{category}.py" for category in builtin_categories]
    package = Path(__file__).resolve().parent
    hashes, unavailable = {}, []
    for name in sorted(source_files):
        path = package / name
        try:
            # Read installed package source only, never host credential/config data.
            with path.open("rb") as stream:
                data = stream.read(1_048_577)
            if len(data) > 1_048_576:
                raise OSError("Rule source exceeds identity collection limit")
        except OSError:
            unavailable.append(name)
        else:
            hashes[name] = sha256(data).hexdigest()
    manifest = {
        "revision": RULESET_REVISION,
        "profile": ctx.profile,
        "categories": selected,
        "builtin_categories": builtin_categories,
        "effective_baselines": effective,
        "source_sha256": hashes,
        "unavailable_sources": unavailable,
        "stable": True,
        "complete": not unavailable,
    }
    return {**manifest, "fingerprint": _digest(manifest)}


def validate_rules_snapshot(rules):
    """Reject malformed or inconsistent identities instead of trusting a label."""
    required = {"revision", "profile", "categories", "builtin_categories", "effective_baselines", "source_sha256", "stable",
                "unavailable_sources", "complete", "fingerprint"}
    if not isinstance(rules, dict) or set(rules) != required:
        raise ValueError("Rules metadata has an unsupported shape")
    for field in ("revision", "profile"):
        if not isinstance(rules[field], str) or not rules[field] or len(rules[field]) > 128:
            raise ValueError(f"Rules {field} must be nonempty bounded text")
    categories = rules["categories"]
    if (not isinstance(categories, list) or any(not isinstance(item, str) or not _CATEGORY.fullmatch(item) for item in categories)
            or len(categories) != len(set(categories)) or categories != sorted(categories)):
        raise ValueError("Rules categories must be unique sorted built-in names")
    builtin = rules["builtin_categories"]
    if (not isinstance(builtin, list) or any(not isinstance(item, str) or not _CATEGORY.fullmatch(item) for item in builtin)
            or builtin != sorted(set(builtin)) or not set(categories) <= set(builtin)):
        raise ValueError("Rules built-in category coverage is inconsistent")
    from linscope.policy import validate_baseline
    effective = validate_baseline(rules["effective_baselines"])
    expected = {check_id for check_id, category in _BASELINE_CATEGORIES.items() if category in categories}
    if set(effective) != expected or effective != rules["effective_baselines"]:
        raise ValueError("Rules effective baselines are incomplete or not canonical")
    source = rules["source_sha256"]
    missing = rules["unavailable_sources"]
    expected_sources = set(_ENGINE_SOURCES) | {f"checks/{category}.py" for category in builtin}
    if not isinstance(source, dict) or any(not isinstance(key, str) or not isinstance(value, str) or not _SHA256.fullmatch(value) for key, value in source.items()):
        raise ValueError("Rules source hashes must be SHA256 strings")
    if (not isinstance(missing, list) or any(not isinstance(item, str) for item in missing)
            or missing != sorted(set(missing)) or set(source) & set(missing)
            or set(source) | set(missing) != expected_sources):
        raise ValueError("Rules source coverage is inconsistent")
    if type(rules["stable"]) is not bool:
        raise ValueError("Rules stability must be a boolean")
    if type(rules["complete"]) is not bool or rules["complete"] != (not missing and rules["stable"]):
        raise ValueError("Rules completeness is inconsistent")
    fingerprint = rules["fingerprint"]
    manifest = {key: value for key, value in rules.items() if key != "fingerprint"}
    if not isinstance(fingerprint, str) or not _SHA256.fullmatch(fingerprint) or fingerprint != _digest(manifest):
        raise ValueError("Rules fingerprint does not match the recorded manifest")


def mark_rules_unstable(rules):
    """Preserve the recorded end-state but make mid-scan source edits explicit."""
    result = deepcopy(rules)
    result["stable"], result["complete"] = False, False
    manifest = {key: value for key, value in result.items() if key != "fingerprint"}
    result["fingerprint"] = _digest(manifest)
    return result


def rules_compatible(old, new):
    """Legacy pairs remain readable; verified and unverified snapshots cannot mix."""
    first, second = old.get("rules"), new.get("rules")
    for report in (old, new):
        if "rules" in report:
            validate_rules_snapshot(report["rules"])
    if "rules" not in old and "rules" not in new:
        return True
    if first is None or second is None:
        return False
    return first["complete"] and second["complete"] and first["fingerprint"] == second["fingerprint"]
