"""Review bounded POSIX ACL targets and lexical/resolved parent directories.

The ACL mask limits named users and all group entries, not the owner or other
entry. Default ACLs describe possible inheritance, not access to existing files.
Targets include conventional protected files, SSH host keys, invoking-user
credential paths, the conventional Docker socket, system cron entries, and
selected/discovered systemd fragments/drop-ins. No credential or task contents
are read. Discovery and parent collection are bounded and omissions are UNKNOWN.
NSS group membership, NFSv4 ACLs, all possible task dependencies, alternate Docker
sockets, and other namespaces are outside this review.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import os
from pathlib import Path, PurePosixPath
import pwd
import re
import stat

from linscope.core import Finding, unavailable

TARGETS = ("/etc/passwd", "/etc/group", "/etc/shadow", "/etc/gshadow",
           "/etc/sudoers", "/etc/ssh/sshd_config", "/etc/ssh")
OPTIONAL = {"/etc/sudoers", "/etc/ssh/sshd_config", "/etc/ssh"}
SECRET_FILES = {"/etc/shadow", "/etc/gshadow", "/etc/sudoers"}
MAX_TARGETS = 200
MAX_ANCESTORS = 256
MAX_UNIT_FILES = 200
MAX_ACL_ENTRIES = 2048
CRON_DIRS = ("/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily",
             "/etc/cron.weekly", "/etc/cron.monthly")
_UNIT = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.@:\\-]*\.(?:service|timer)", re.ASCII)


@dataclass(frozen=True)
class Target:
    path: str
    policy: str = "public"
    user_uid: int | None = None
    optional: bool = True
    expected_type: str = "file"


def _safe_path(value):
    if (not isinstance(value, str) or not value.startswith("/") or len(value) > 4096
            or ".." in PurePosixPath(value).parts
            or any(ord(c) < 32 or 127 <= ord(c) < 160 for c in value)):
        raise ValueError("Unsupported absolute metadata path")
    return str(PurePosixPath(value))


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
        if len(access) + len(defaults) > MAX_ACL_ENTRIES:
            raise ValueError("POSIX ACL exceeds the bounded entry limit")
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


def _issues(ctx, path, metadata, entries, target=None, ancestor=False):
    """Compare effective entries with one target's stated identity baseline."""
    target = target or Target(path, "shadow" if path in {"/etc/shadow", "/etc/gshadow"}
                              else "rootgroup" if path == "/etc/sudoers" else "public")
    mask = entries.get(("mask", ""), 7)
    problems, uncertainties = [], []
    directory = stat.S_ISDIR(metadata.st_mode)
    shadow_resolved, shadow_gid, shadow_error = False, None, False
    trusted_uids = {0}
    if target.user_uid is not None:
        trusted_uids.add(target.user_uid)
    if metadata.st_uid not in trusted_uids:
        if getattr(ctx, "profile", "server") == "container":
            uncertainties.append("nonzero owner UID may reflect namespace mapping")
        else:
            problems.append("owner UID is outside the target's trusted root/invoking-user baseline")
    for (kind, qualifier), permissions in entries.items():
        if kind == "mask" or (kind == "user" and not qualifier):
            continue
        effective = permissions & mask if kind == "group" or (kind == "user" and qualifier) else permissions
        if kind == "user" and qualifier and int(qualifier) in trusted_uids:
            continue
        allowed = 5 if directory or target.policy == "task" else 4
        if not ancestor and target.policy in {"private", "userprivate", "shadow", "rootgroup"}:
            allowed = 0
            if kind == "group" and target.policy in {"shadow", "rootgroup"}:
                gid = int(qualifier) if qualifier else metadata.st_gid
                if gid == 0:
                    allowed = 4
                elif target.policy == "shadow" and effective & 4:
                    if not shadow_resolved:
                        try:
                            shadow_gid = _shadow_gid(ctx)
                        except (OSError, ValueError):
                            shadow_error = True
                        shadow_resolved = True
                    if shadow_error:
                        if "group-read trust could not be established" not in uncertainties:
                            uncertainties.append("group-read trust could not be established")
                        allowed = 4
                    else:
                        allowed = 4 if gid == shadow_gid else 0
        elif not ancestor and target.policy == "socket":
            # Connecting to a UNIX socket needs write permission. Group read
            # alone is not daemon control; non-root group write needs review.
            allowed = 6 if kind == "group" and (int(qualifier) if qualifier else metadata.st_gid) == 0 else 4
        if effective & ~allowed:
            actor = kind + (":" + qualifier if qualifier else " (base)")
            problems.append(f"{actor} effective permission bits={effective:o}, allowed={allowed:o}")
    return problems, uncertainties


def _conventional_user_targets(ctx):
    uid = os.getuid()
    targets, errors = {}, []
    try:
        home = _safe_path(pwd.getpwuid(uid).pw_dir).rstrip("/")
    except (KeyError, OSError, ValueError) as exc:
        home = None
        errors.append("Invoking-user conventional home scope could not be established: " + str(exc))
    if home is not None:
        targets = {
            home + "/.ssh": Target(home + "/.ssh", "userprivate", uid, expected_type="directory"),
            home + "/.ssh/authorized_keys": Target(home + "/.ssh/authorized_keys", "public", uid),
        }
        for suffix in ("/.aws/credentials", "/.kube/config", "/.docker/config.json",
                       "/.config/gcloud/application_default_credentials.json"):
            path = home + suffix
            targets[path] = Target(path, "userprivate", uid)
        try:
            for path in ctx.glob(home + "/.ssh/id_*"):
                path = _safe_path(path)
                if not path.endswith(".pub"):
                    targets[path] = Target(path, "userprivate", uid)
        except (OSError, ValueError) as exc:
            errors.append("Invoking-user private-key path discovery is incomplete: " + str(exc))
    explicit = getattr(ctx, "user_paths", [])
    if not isinstance(explicit, list) or len(explicit) > 50:
        raise ValueError("At most 50 explicit user metadata paths are supported")
    for raw in explicit:
        path = _safe_path(raw)
        original = targets.get(path)
        targets[path] = (Target(path, original.policy, uid, False, original.expected_type)
                         if original else Target(path, "userprivate", uid, False, "any"))
    return list(targets.values()), errors


def _unit_properties(ctx, unit):
    timer = unit.endswith(".timer")
    properties = "LoadState,FragmentPath,DropInPaths" + (",Unit" if timer else "")
    result = ctx.command(["systemctl", "show", "--property=" + properties, "--", unit])
    if not result.ok:
        raise ValueError("Unit fragment/drop-in metadata could not be collected")
    values = {}
    allowed = set(properties.split(","))
    for line in result.stdout.splitlines():
        key, sep, value = line.partition("=")
        if not sep or key not in allowed or key in values:
            raise ValueError("Unit fragment metadata is malformed or duplicated")
        values[key] = value
    if set(values) != allowed or values["LoadState"] != "loaded" or not values["FragmentPath"]:
        raise ValueError("Unit is not confirmed loaded with a named fragment")
    # systemctl may escape paths containing spaces. Do not guess how such an
    # ambiguous list should be split or inspect a fabricated partial path.
    raw_paths = [values["FragmentPath"], *values["DropInPaths"].split()]
    if len(raw_paths) > MAX_UNIT_FILES or any("\\" in path for path in raw_paths):
        raise ValueError("Unit file metadata exceeds scope or uses escaped paths")
    paths = [_safe_path(path) for path in raw_paths]
    linked = values.get("Unit")
    if timer and (not _UNIT.fullmatch(linked) or not linked.endswith(".service")):
        raise ValueError("Timer's activated system service could not be resolved")
    return paths, linked


def _systemd_targets(ctx):
    from linscope.checks.scheduled import _timer_units
    from linscope.checks.systemd import _discovery
    services, errors, _ = _discovery(ctx)
    timers, timer_error = _timer_units(ctx)
    if timer_error:
        errors.append("System timer discovery is incomplete: " + timer_error)
    queue = list(services) + (timers or [])
    visited, paths = set(), set()
    while queue:
        unit = queue.pop(0)
        if unit in visited:
            continue
        if len(visited) >= 130:
            errors.append("System unit collection limit reached")
            break
        visited.add(unit)
        if not isinstance(unit, str) or len(unit) > 255 or not _UNIT.fullmatch(unit):
            errors.append("Invalid system unit name was not queried")
            continue
        try:
            discovered, linked = _unit_properties(ctx, unit)
        except ValueError as exc:
            errors.append(f"{unit}: {exc}")
            continue
        paths.update(discovered)
        if len(paths) > MAX_UNIT_FILES:
            errors.append("System unit fragment/drop-in path limit reached")
            paths = set(sorted(paths)[:MAX_UNIT_FILES])
            break
        if linked and linked not in visited:
            queue.append(linked)
    return [Target(path, "task") for path in sorted(paths)], errors


def _discover(ctx):
    targets = {}
    errors = []
    def add(target):
        # Explicit user credentials may overlap conventional root config. Keep
        # the established root policy rather than weakening it through a flag.
        if target.path in targets:
            old = targets[target.path]
            # Root service/cron/socket discovery happens after user discovery.
            # Its identity baseline must also win over an earlier user flag.
            chosen = target if old.user_uid is not None and target.user_uid is None else old
            targets[target.path] = Target(chosen.path, chosen.policy, chosen.user_uid,
                                          old.optional and target.optional, chosen.expected_type)
            return
        if len(targets) >= MAX_TARGETS:
            errors.append(f"Target limit {MAX_TARGETS} reached; additional ACL paths were omitted")
            return
        targets[target.path] = target
    for path in TARGETS:
        add(Target(path, "shadow" if path in {"/etc/shadow", "/etc/gshadow"}
                   else "rootgroup" if path == "/etc/sudoers" else "public",
                   optional=path in OPTIONAL, expected_type="directory" if path == "/etc/ssh" else "file"))
    if not callable(getattr(ctx, "glob", None)):
        errors.append("Extended target discovery is unavailable in this collector context")
        return list(targets.values()), errors
    try:
        for path in ctx.glob("/etc/ssh/ssh_host_*_key"):
            add(Target(_safe_path(path), "private"))
    except (OSError, ValueError) as exc:
        errors.append("SSH host private-key path discovery is incomplete: " + str(exc))
    try:
        user_targets, user_errors = _conventional_user_targets(ctx)
        for target in user_targets:
            add(target)
        errors.extend(user_errors)
    except (KeyError, OSError, ValueError) as exc:
        errors.append("Invoking-user credential path discovery is incomplete: " + str(exc))
    add(Target("/var/run/docker.sock", "socket", expected_type="socket"))
    for path in ("/etc/crontab", "/etc/anacrontab"):
        add(Target(path, "task"))
    for directory in CRON_DIRS:
        add(Target(directory, "task", expected_type="directory"))
        try:
            for path in ctx.glob(directory + "/*"):
                add(Target(_safe_path(path), "task"))
        except (OSError, ValueError) as exc:
            errors.append(f"Cron path discovery for {directory} is incomplete: {exc}")
    unit_targets, unit_errors = _systemd_targets(ctx)
    for target in unit_targets:
        add(target)
    errors.extend(unit_errors)
    return list(targets.values()), errors


def _signature(metadata):
    fields = tuple(getattr(metadata, key, None) for key in ("st_mode", "st_uid", "st_gid", "st_dev", "st_ino"))
    # Named grants can change without changing mode bits, ownership or inode.
    # ctime is the available filesystem change marker for that detectable race.
    changed = getattr(metadata, "st_ctime_ns", getattr(metadata, "st_ctime", None))
    return fields + (changed,)


class _Collection:
    def __init__(self, ctx):
        self.ctx, self.cache, self.parents = ctx, {}, set()
        self.limit_reached = False

    def get(self, path, parent=False):
        if parent and path not in self.parents:
            if len(self.parents) >= MAX_ANCESTORS:
                self.limit_reached = True
                raise OSError("Ancestor ACL path limit reached; coverage is incomplete")
            self.parents.add(path)
        if path in self.cache:
            value = self.cache[path]
            if isinstance(value, Exception):
                raise value
            return value
        try:
            metadata = self.ctx.stat(path)
            if not (stat.S_ISREG(metadata.st_mode) or stat.S_ISDIR(metadata.st_mode) or stat.S_ISSOCK(metadata.st_mode)):
                raise OSError("Target is not a regular file, directory, or UNIX socket")
            command = self.ctx.command(["getfacl", "-cpn", "--", path])
            if not command.ok:
                raise OSError(command.error or "ACL tool could not inspect this target; no ACL verdict was inferred")
            access, defaults = parse_acl(command.stdout)
            mode = stat.S_IMODE(metadata.st_mode)
            expected = ((mode >> 6) & 7, (mode >> 3) & 7, mode & 7)
            observed = (access[("user", "")], access.get(("mask", ""), access[("group", "")]), access[("other", "")])
            if expected != observed or _signature(metadata) != _signature(self.ctx.stat(path)):
                raise OSError("ACL and metadata snapshots disagree; target may have changed during collection")
            if defaults and not stat.S_ISDIR(metadata.st_mode):
                raise OSError("Default ACL returned for a non-directory")
            value = metadata, access, defaults
        except (OSError, ValueError, TypeError) as exc:
            self.cache[path] = exc
            raise
        self.cache[path] = value
        return value


def _ancestor_paths(ctx, path):
    parents, errors = set(), []
    def add_parents(value):
        for parent in PurePosixPath(value).parents:
            if str(parent) in parents:
                continue
            if len(parents) >= MAX_ANCESTORS:
                errors.append("Target ancestry exceeds the bounded parent inspection limit")
                break
            parents.add(str(parent))
    add_parents(path)
    try:
        if not callable(getattr(ctx, "path", None)):
            raise ValueError("Resolved filesystem paths unavailable in this collector context")
        root = getattr(ctx, "root", Path("/")).resolve(strict=True)
        resolved = ctx.path(path).resolve(strict=True)
        relative = resolved.relative_to(root)
        target = "/" + str(relative) if str(relative) != "." else "/"
        add_parents(target)
    except (OSError, ValueError, RuntimeError) as exc:
        errors.append(f"Resolved target ancestry could not be established ({type(exc).__name__})")
    return sorted(parents), errors


def _ancestor_finding(ctx, collection, target):
    paths, errors = _ancestor_paths(ctx, target.path)
    problems, inspected = [], 0
    for path in paths:
        try:
            metadata, access, _ = collection.get(path, parent=True)
            if not stat.S_ISDIR(metadata.st_mode):
                raise OSError("Ancestor is not a directory")
            bad, unknown = _issues(ctx, path, metadata, access, target, ancestor=True)
            problems.extend(f"{path}: {item}" for item in bad)
            errors.extend(f"{path}: {item}" for item in unknown)
            inspected += 1
        except (OSError, ValueError, TypeError) as exc:
            errors.append(f"{path}: {exc}")
    status = "WARN" if problems else "UNKNOWN" if errors else "PASS"
    detail = "; ".join(problems[:8] + errors[:5]) or "Inspected lexical/resolved parent ACLs have no untrusted effective write grants."
    return Finding(_id(target.path, 3), "acl", f"Parent-directory ACL protection: {target.path}", status,
                   "high" if problems else "info",
                   f"Inspected {inspected} unique parent directories. {detail}"
                   + (" Additional parent concerns omitted." if len(problems) > 8 or len(errors) > 5 else "")
                   + " Group membership, remote ACL models and other namespaces were not evaluated.",
                   "Review effective write grants and trusted ownership on both lexical and resolved target parents; directory read/traversal alone is allowed by this baseline.")


def run(ctx):
    targets, discovery_errors = _discover(ctx)
    collection, results = _Collection(ctx), []
    for target in targets:
        path = target.path
        title = f"Effective POSIX ACL: {path}"
        try:
            metadata, access, defaults = collection.get(path)
        except FileNotFoundError:
            absent = True
            if callable(getattr(ctx, "path", None)):
                try:
                    ctx.path(path).lstat()
                    absent = False
                except FileNotFoundError:
                    pass
                except (OSError, ValueError):
                    absent = False
            results.append(Finding(_id(path), "acl", title, "SKIP" if target.optional and absent else "UNKNOWN", "info",
                                   f"{path} is absent at the selected/conventional location." if absent else
                                   f"{path} exists or could not be resolved safely; absence was not established.",
                                   "Review custom locations if this component is configured elsewhere."))
            if not absent:
                results.append(_ancestor_finding(ctx, collection, target))
            continue
        except (OSError, ValueError, TypeError) as exc:
            results.append(unavailable(_id(path), "acl", title, str(exc)))
            results.append(_ancestor_finding(ctx, collection, target))
            continue
        matches = {"file": stat.S_ISREG, "directory": stat.S_ISDIR, "socket": stat.S_ISSOCK}
        if target.expected_type != "any" and not matches[target.expected_type](metadata.st_mode):
            results.append(unavailable(_id(path), "acl", title, "Target has an unexpected file type for the stated baseline"))
            results.append(_ancestor_finding(ctx, collection, target))
            continue
        problems, uncertainties = _issues(ctx, path, metadata, access, target)
        named = sum(bool(qualifier) for _, qualifier in access)
        status = "WARN" if problems else "UNKNOWN" if uncertainties else "PASS"
        private = target.policy in {"private", "userprivate", "shadow", "rootgroup", "socket"}
        evidence = (f"uid={metadata.st_uid}, gid={metadata.st_gid}; named entries={named}; mask={access.get(('mask', ''), 7):o}; policy={target.policy}. "
                    + ("; ".join(problems[:20] + uncertainties[:5]) or "Inspected ACL grants fit the stated protected-target baseline.")
                    + (f" Additional concerns omitted: issues={len(problems)}, unknowns={len(uncertainties)}." if len(problems) > 20 or len(uncertainties) > 5 else "")
                    + " Target access and parent protection are separate findings; group membership and runtime credential use are not established.")
        results.append(Finding(_id(path), "acl", title, status, "high" if private else "medium", evidence,
                               "Review effective named/group grants and their ACL mask. Preserve required service access; ACLs do not establish actual credential validity."))
        if stat.S_ISDIR(metadata.st_mode):
            default_problems, default_unknown = _issues(ctx, path, metadata, defaults, target) if defaults else ([], [])
            results.append(Finding(_id(path, 2), "acl", f"Default ACL inheritance: {path}",
                                   "WARN" if default_problems else "UNKNOWN" if default_unknown else "INFO", "medium" if default_problems else "info",
                                   f"Default ACL entries={len(defaults)}. " + ("; ".join(default_problems[:20] + default_unknown[:5]) or
                                   "Inheritance grants require review against file creation modes; existing-file access is not inferred."),
                                   "Review default ACLs alongside application creation modes, especially for directories holding credentials."))
        results.append(_ancestor_finding(ctx, collection, target))
    if collection.limit_reached:
        discovery_errors.append(f"Ancestor ACL collection exceeded {MAX_ANCESTORS} unique directories")
    results.insert(0, Finding("ACL-000", "acl", "Expanded ACL collection scope", "UNKNOWN" if discovery_errors else "INFO", "info",
                             f"Selected {len(targets)} targets (limit {MAX_TARGETS}); parent limit {MAX_ANCESTORS}. "
                             + ("; ".join(dict.fromkeys(discovery_errors))[:2000] if discovery_errors else
                                "Bounded conventional/explicit discovery completed without a detected discovery failure.")
                             + " Only discovered/selected paths and inspected ancestors are covered; custom paths and all task dependencies are not inferred.",
                             "Review unavailable discovery sources and add explicit user/service selections where appropriate; no file contents or scheduled commands are collected."))
    return results
