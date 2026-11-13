"""Review POSIX ACL access on conventional protected files, without contents.

The ACL mask limits named users and all group entries, not the owner or other
entry. Default ACLs describe possible inheritance, not access to existing files.
These checks do not resolve NSS group membership, ACLs on every parent directory,
NFSv4 ACLs, or another namespace's access controls.
"""
from __future__ import annotations

from hashlib import sha256
import re
import stat

from linscope.core import Finding, unavailable

TARGETS = ("/etc/passwd", "/etc/group", "/etc/shadow", "/etc/gshadow",
           "/etc/sudoers", "/etc/ssh/sshd_config", "/etc/ssh")
OPTIONAL = {"/etc/sudoers", "/etc/ssh/sshd_config", "/etc/ssh"}
SECRET_FILES = {"/etc/shadow", "/etc/gshadow", "/etc/sudoers"}


def _id(path, number=1):
    return f"ACL-{sha256(path.encode()).hexdigest()[:12].upper()}-{number:03d}"


def _bits(value):
    if not re.fullmatch(r"[r-][w-][x-]", value):
        raise ValueError("Invalid ACL permission field")
    return (4 if value[0] == "r" else 0) | (2 if value[1] == "w" else 0) | (1 if value[2] == "x" else 0)


def parse_acl(text):
    """Parse one getfacl -cpn record and reject ambiguous/incomplete evidence."""
    access, defaults = {}, {}
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        fields = line.split(":")
        target = access
        if fields[0] == "default":
            target, fields = defaults, fields[1:]
        if len(fields) != 3:
            raise ValueError("Unrecognized POSIX ACL entry")
        kind, qualifier, permissions = fields
        if kind not in {"user", "group", "mask", "other"}:
            raise ValueError("Unsupported ACL entry type")
        if kind in {"mask", "other"} and qualifier:
            raise ValueError("Unexpected ACL qualifier")
        if qualifier and (not re.fullmatch(r"[0-9]+", qualifier) or not 0 <= int(qualifier) < 2**32 - 1):
            raise ValueError("ACL must contain usable numeric user/group IDs")
        if qualifier:
            qualifier = str(int(qualifier))
        key = (kind, qualifier)
        if key in target:
            raise ValueError("Duplicate ACL entry")
        target[key] = _bits(permissions)
    for entries in (access, defaults):
        if not entries and entries is defaults:
            continue
        if any(key not in entries for key in (("user", ""), ("group", ""), ("other", ""))):
            raise ValueError("Incomplete base ACL")
        if any(qualifier for _, qualifier in entries) and ("mask", "") not in entries:
            raise ValueError("Named ACL entries lack a mask")
    return access, defaults


def _shadow_gid(ctx):
    entries = []
    for line in ctx.read("/etc/group").splitlines():
        fields = line.split(":")
        if fields[0] == "shadow":
            entries.append(fields)
    if len(entries) != 1:
        raise ValueError("Cannot establish one local shadow group")
    fields = entries[0]
    if len(fields) != 4 or not re.fullmatch(r"[0-9]+", fields[2]) or not 0 <= int(fields[2]) < 2**32 - 1:
        raise ValueError("Invalid local shadow group")
    return int(fields[2])


def _issues(ctx, path, metadata, entries):
    mask = entries.get(("mask", ""), 7)
    problems, uncertainties = [], []
    directory = stat.S_ISDIR(metadata.st_mode)
    if metadata.st_uid != 0:
        if getattr(ctx, "profile", "server") == "container":
            uncertainties.append("nonzero owner UID may reflect namespace mapping")
        else:
            problems.append("protected target is not root-owned")
    for (kind, qualifier), permissions in entries.items():
        if kind == "mask" or (kind == "user" and not qualifier):
            continue
        effective = permissions & mask if kind == "group" or (kind == "user" and qualifier) else permissions
        if kind == "user" and qualifier == "0":
            continue  # UID 0 is already privileged independently of this ACL.
        allowed = 5 if directory else 4
        if path in SECRET_FILES:
            allowed = 0
            if kind == "group":
                gid = int(qualifier) if qualifier else metadata.st_gid
                if gid == 0:
                    allowed = 4
                elif path in {"/etc/shadow", "/etc/gshadow"} and effective & 4:
                    try:
                        allowed = 4 if gid == _shadow_gid(ctx) else 0
                    except (OSError, ValueError):
                        uncertainties.append("group-read trust could not be established")
                        # Other unsafe bits remain findings even with unknown read trust.
                        allowed = 4
        if effective & ~allowed:
            actor = kind + (":" + qualifier if qualifier else " (base)")
            problems.append(f"{actor} effective permission bits={effective:o}, allowed={allowed:o}")
    return problems, uncertainties


def run(ctx):
    results = []
    for path in TARGETS:
        check_id = _id(path)
        title = f"Effective POSIX ACL: {path}"
        try:
            metadata = ctx.stat(path)
        except FileNotFoundError:
            results.append(Finding(check_id, "acl", title, "SKIP" if path in OPTIONAL else "UNKNOWN", "info",
                                   f"{path} is absent at its conventional location.",
                                   "Review custom locations if this component is configured elsewhere."))
            continue
        except OSError:
            results.append(unavailable(check_id, "acl", title, "Target metadata is inaccessible."))
            continue
        if not (stat.S_ISREG(metadata.st_mode) or stat.S_ISDIR(metadata.st_mode)):
            results.append(unavailable(check_id, "acl", title, "Target is not a regular file or directory."))
            continue
        command = ctx.command(["getfacl", "-cpn", "--", path])
        if not command.ok:
            results.append(unavailable(check_id, "acl", title,
                                       command.error or "ACL tool could not inspect this target; no ACL verdict was inferred."))
            continue
        try:
            access, defaults = parse_acl(command.stdout)
            mode = stat.S_IMODE(metadata.st_mode)
            expected = ((mode >> 6) & 7, (mode >> 3) & 7, mode & 7)
            observed = (access[("user", "")], access.get(("mask", ""), access[("group", "")]), access[("other", "")])
            if expected != observed:
                raise ValueError("ACL and mode snapshots disagree; target may have changed during collection")
            if defaults and not stat.S_ISDIR(metadata.st_mode):
                raise ValueError("Default ACL returned for a non-directory")
            problems, uncertainties = _issues(ctx, path, metadata, access)
        except (ValueError, TypeError) as exc:
            results.append(unavailable(check_id, "acl", title, str(exc)))
            continue
        named = sum(bool(qualifier) for _, qualifier in access)
        status = "WARN" if problems else "UNKNOWN" if uncertainties else "PASS"
        evidence = (f"uid={metadata.st_uid}, gid={metadata.st_gid}; named entries={named}; mask={access.get(('mask', ''), 7):o}. "
                    + ("; ".join(problems + uncertainties) or "Inspected ACL grants fit the stated protected-target baseline.")
                    + " Only the resolved target ACL is evaluated; parent traversal and group membership are outside this check.")
        results.append(Finding(check_id, "acl", title, status, "high" if path in SECRET_FILES else "medium", evidence,
                               "Review effective named/group grants and their ACL mask. Preserve required service access; do not rely on chmod output alone."))
        if stat.S_ISDIR(metadata.st_mode):
            default_problems, default_unknown = _issues(ctx, path, metadata, defaults) if defaults else ([], [])
            results.append(Finding(_id(path, 2), "acl", f"Default ACL inheritance: {path}",
                                   "WARN" if default_problems else "UNKNOWN" if default_unknown else "INFO", "medium" if default_problems else "info",
                                   f"Default ACL entries={len(defaults)}. " + ("; ".join(default_problems + default_unknown) or
                                   "Inheritance grants require review against the file creation mode; existing-file access is not inferred."),
                                   "Review default ACLs alongside application creation modes, especially for directories that hold both public configuration and private keys."))
    return results
