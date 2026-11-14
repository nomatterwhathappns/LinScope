"""Inventory file capabilities in bounded conventional executable directories.

Only file metadata is queried; no discovered file is executed or opened for its
contents. The default visits direct regular files; --deep recurses without
crossing mount boundaries and without following descendant symlinks. This is
not a complete filesystem, runtime-capability, provenance or exploitability
assessment. Namespaced root IDs and execution conditions need separate review.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import PurePosixPath
import re
import stat

from linscope.core import Finding, unavailable

CATEGORY = "capabilities"
ROOTS = ("/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin")
MAX_FILES = 10_000
MAX_FINDINGS = 200
BATCH_FILES = 128
MAX_ARGUMENT_BYTES = 32_768
PROBE_COMMAND = ["getcap", "-h"]

# Linux capability numbers 0..40. Future names/numbers are deliberately UNKNOWN
# until their semantics are reviewed; an unfamiliar grant is never called safe.
CAPABILITIES = tuple("cap_" + name for name in (
    "chown dac_override dac_read_search fowner fsetid kill setgid setuid setpcap "
    "linux_immutable net_bind_service net_broadcast net_admin net_raw ipc_lock "
    "ipc_owner sys_module sys_rawio sys_chroot sys_ptrace sys_pacct sys_admin "
    "sys_boot sys_nice sys_resource sys_time sys_tty_config mknod lease "
    "audit_write audit_control setfcap mac_override mac_admin syslog wake_alarm "
    "block_suspend audit_read perfmon bpf checkpoint_restore"
).split())
HIGH_IMPACT = frozenset({
    "cap_setuid", "cap_setgid", "cap_setpcap", "cap_setfcap", "cap_dac_override",
    "cap_dac_read_search", "cap_sys_admin", "cap_sys_module", "cap_sys_rawio",
    "cap_sys_ptrace", "cap_sys_boot", "cap_sys_time", "cap_net_admin",
    "cap_linux_immutable", "cap_audit_control", "cap_mac_override", "cap_mac_admin",
    "cap_syslog", "cap_perfmon", "cap_bpf", "cap_checkpoint_restore",
})
_NAME = r"(?:cap_[a-z0-9_]+|[0-9]+|all)"
_CLAUSE = re.compile(rf"(?P<names>{_NAME}(?:,{_NAME})*)?(?P<ops>(?:[=+\-][eip]*)+)", re.ASCII)
_OPERATION = re.compile(r"([=+\-])([eip]*)", re.ASCII)


@dataclass(frozen=True)
class CapabilityRecord:
    path: str
    permitted: frozenset[str]
    effective: frozenset[str]
    inheritable: frozenset[str]
    rootid: int | None


def path_id(path):
    return "CAPS-" + sha256(path.encode("utf-8")).hexdigest()[:12].upper() + "-001"


def _valid_path(value):
    if (not isinstance(value, str) or not value.startswith("/") or len(value) > 4096
            or ".." in PurePosixPath(value).parts
            or any(ord(char) < 32 or 127 <= ord(char) < 160 for char in value)):
        raise ValueError("Unsupported executable pathname in metadata output")
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise ValueError("Executable pathname is not valid UTF-8") from exc
    if str(PurePosixPath(value)) != value:
        raise ValueError("Executable pathname is not normalized")
    return value


def discovery_command(roots, deep=False):
    command = ["find", "-H", *roots, "-xdev"]
    if not deep:
        command += ["-maxdepth", "1"]
    return command + ["-type", "f", "-print0"]


def parse_discovery(text, roots, deep=False):
    if not text:
        return []
    if not text.endswith("\0"):
        raise ValueError("Executable discovery lacks a complete NUL-delimited record")
    paths = []
    for value in text[:-1].split("\0"):
        path = _valid_path(value)
        target = PurePosixPath(path)
        if not any(PurePosixPath(root) in target.parents for root in roots):
            raise ValueError("Executable discovery returned a path outside its selected roots")
        if not deep and str(target.parent) not in roots:
            raise ValueError("Executable discovery exceeded the selected direct-file depth")
        paths.append(path)
    if len(paths) != len(set(paths)):
        raise ValueError("Executable discovery returned duplicate paths")
    return sorted(paths)


def _capability_name(value):
    if value in CAPABILITIES:
        return value
    if re.fullmatch(r"[0-9]+", value, re.ASCII) and len(value) <= 2:
        number = int(value)
        if number < len(CAPABILITIES):
            return CAPABILITIES[number]
    raise ValueError("File metadata contains an unsupported capability name/number")


def parse_capability_text(text):
    """Interpret libcap text assignments, additions, removals and rootid suffix.

    A leading standalone '=' is libcap's empty base set, used by older output.
    Omitted names (e.g. '=ep') or 'all' select every currently supported Linux
    capability. Permissions remain distinct rather than treating an effective
    bit as proof of an exploitable program.
    """
    if not isinstance(text, str) or not text.strip() or len(text) > 8192:
        raise ValueError("Missing or oversized file-capability text")
    if any((ord(char) < 32 and char not in "\t") or 127 <= ord(char) < 160 for char in text):
        raise ValueError("Capability expression contains unexpected control characters")
    text = text.strip()
    rootid = None
    suffix = re.search(r"\s*\[rootid=([0-9]+)\]$", text, re.ASCII)
    if suffix:
        digits = suffix[1]
        if len(digits) > 10 or not 0 <= int(digits) < 2**32 - 1:
            raise ValueError("File capability namespace root ID is outside the usable UID range")
        rootid = int(digits)
        text = text[:suffix.start()].rstrip()
    if not text:
        raise ValueError("Capability root ID is not a capability-set expression")
    sets = {flag: set() for flag in "pei"}
    for clause in text.split():
        match = _CLAUSE.fullmatch(clause)
        if not match:
            raise ValueError("Unrecognized file-capability expression")
        raw_names = match["names"]
        if raw_names is None or raw_names == "all":
            names = set(CAPABILITIES)
        else:
            pieces = raw_names.split(",")
            if "all" in pieces:
                raise ValueError("Ambiguous all-capability list")
            normalized = [_capability_name(name) for name in pieces]
            if len(normalized) != len(set(normalized)):
                raise ValueError("Duplicate capability name in a clause")
            names = set(normalized)
        for operation, flags in _OPERATION.findall(match["ops"]):
            if len(flags) != len(set(flags)) or (not flags and operation != "="):
                raise ValueError("Invalid capability flag operation")
            if operation == "=":
                for current in sets.values():
                    current.difference_update(names)
            for flag in flags:
                if operation == "-":
                    sets[flag].difference_update(names)
                else:
                    sets[flag].update(names)
    return frozenset(sets["p"]), frozenset(sets["e"]), frozenset(sets["i"]), rootid


def parse_output(text, expected_paths):
    """Associate output with exact queried paths, preserving spaces safely.

    Legacy separators and filenames containing capability-looking text can be
    ambiguous. Such rows are rejected rather than attributed to the wrong file.
    """
    records = []
    seen = set()
    expected = set(expected_paths)
    for line in text.splitlines():
        if not line:
            continue
        candidates = []
        for separator in re.finditer(r"[ \t]+", line):
            path = line[:separator.start()]
            if path not in expected:
                continue
            try:
                values = parse_capability_text(line[separator.end():])
            except ValueError:
                continue
            candidates.append((path, values))
        if len(candidates) != 1:
            raise ValueError("Capability output row is malformed, unqueried, or ambiguous")
        path, values = candidates[0]
        if path in seen:
            raise ValueError("Capability output contains duplicate file records")
        seen.add(path)
        records.append(CapabilityRecord(path, *values))
    return records


def _batches(paths):
    batch, size = [], 32
    for path in paths:
        required = len(path.encode("utf-8")) + 9  # NUL and argv-pointer allowance.
        if batch and (len(batch) >= BATCH_FILES or size + required > MAX_ARGUMENT_BYTES):
            yield batch
            batch, size = [], 32
        batch.append(path)
        size += required
    if batch:
        yield batch


def _record_finding(record):
    all_grants = record.permitted | record.effective | record.inheritable
    high = sorted(all_grants & HIGH_IMPACT)
    namespace = "not explicitly reported" if record.rootid is None else str(record.rootid)
    evidence = (f"permitted={','.join(sorted(record.permitted)) or 'none'}; "
                f"effective={','.join(sorted(record.effective)) or 'none'}; "
                f"inheritable={','.join(sorted(record.inheritable)) or 'none'}; "
                f"namespace rootid={namespace}. "
                + ("Selected high-impact grants: " + ", ".join(high) + ". " if high else "")
                + "File metadata only; runtime credentials, namespace applicability and exploitability were not tested.")
    return Finding(path_id(record.path), CATEGORY, f"File capability metadata: {record.path}",
                   "WARN" if high else "INFO", "high" if high else "low" if all_grants else "info",
                   evidence,
                   "Confirm the program needs these grants, review its ownership/permissions and package provenance, "
                   "and understand permitted/effective/inheritable and namespace behavior. A capability alone is not proof of a vulnerability.")


def run(ctx):
    probe = ctx.command(PROBE_COMMAND)
    if not probe.ok:
        return [unavailable("CAPS-000", CATEGORY, "File capability inventory scope",
                            probe.error or "getcap availability could not be established.",
                            "Install or provide supported libcap getcap tooling; no executable contents are needed.")]
    roots, errors, absent = [], [], []
    for root in ROOTS:
        try:
            metadata = ctx.stat(root)
            if not stat.S_ISDIR(metadata.st_mode):
                errors.append(f"Conventional executable root is not a directory: {root}")
                continue
            roots.append(root)
        except FileNotFoundError:
            absent.append(root)
        except OSError:
            errors.append(f"Conventional executable root metadata is inaccessible: {root}")
    if not roots:
        return [Finding("CAPS-000", CATEGORY, "File capability inventory scope", "UNKNOWN" if errors else "SKIP", "info",
                        "; ".join(errors) or "None of the selected conventional executable directories exists.",
                        "Review the host's executable locations. This module does not scan arbitrary paths or the entire filesystem.")]
    deep = bool(getattr(ctx, "deep", False))
    discovery = ctx.command(discovery_command(roots, deep), timeout=15)
    if not discovery.ok:
        return [unavailable("CAPS-000", CATEGORY, "File capability inventory scope",
                            discovery.error or "Executable discovery failed or was incomplete; no clean capability inventory was inferred.",
                            "Review directory access and collection limits, then rerun the selected conventional scope.")]
    try:
        paths = parse_discovery(discovery.stdout, roots, deep)
    except ValueError as exc:
        return [unavailable("CAPS-000", CATEGORY, "File capability inventory scope", str(exc))]
    if len(paths) > MAX_FILES:
        errors.append(f"Executable candidate count exceeds {MAX_FILES}; only the first sorted candidates were queried")
        paths = paths[:MAX_FILES]
    if discovery.stderr.strip():
        errors.append("Executable discovery reported diagnostics; selected coverage cannot be established completely")
    records = []
    for batch in _batches(paths):
        result = ctx.command(["getcap", "-n", "--", *batch], timeout=15)
        if not result.ok:
            errors.append(result.error or "A getcap batch failed; some file capability metadata is unavailable")
            continue
        # libcap getcap can exit zero for per-file errors (including EACCES or
        # disappearance). Treat diagnostics as incomplete evidence, preserving
        # any successfully parsed positive rows rather than inferring absence.
        if result.stderr.strip():
            errors.append("getcap reported per-file diagnostics despite a successful exit; some metadata may be unavailable")
        try:
            records.extend(parse_output(result.stdout, batch))
        except ValueError as exc:
            errors.append(str(exc))
    if len(records) > MAX_FINDINGS:
        errors.append(f"Capability record count exceeds {MAX_FINDINGS}; additional findings were omitted")
    records = sorted(records, key=lambda record: record.path)[:MAX_FINDINGS]
    evidence = (f"Roots={','.join(roots)}; traversal={'recursive' if deep else 'direct files'}; "
                f"queried candidates={len(paths)}; reported capability records={len(records)}. "
                "No mount-boundary crossing or descendant symlink following; command-line directory symlinks may be followed. ")
    if absent:
        evidence += "Absent conventional roots=" + ",".join(absent) + ". "
    if errors:
        evidence += "Incomplete collection: " + "; ".join(errors[:10]) + ("; additional errors omitted" if len(errors) > 10 else "") + ". "
    if not records:
        evidence += "No capability-bearing metadata was returned in the available selected evidence; this does not establish host-wide safety."
    scope = Finding("CAPS-000", CATEGORY, "File capability inventory scope", "UNKNOWN" if errors else "INFO", "info",
                    evidence,
                    "Review file-capability grants alongside SUID/SGID, permissions, ACLs and provenance. "
                    "Use --deep for bounded recursive conventional-directory coverage; other paths and runtime privilege behavior require separate review.")
    return [scope, *(_record_finding(record) for record in records)]
