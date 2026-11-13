"""Mount and filesystem metadata checks, scoped to the current mount namespace.

These checks do not establish disk encryption, scan file contents, or establish
that a mount option is compatible with every application. Container results
describe the container namespace, not its host.
"""
from __future__ import annotations

from pathlib import PurePosixPath
import re
import stat

from linscope.core import Finding, unavailable


def parse_mountinfo(text):
    """Return (mountpoint, options) pairs or reject malformed partial evidence."""
    mounts = []
    for line in text.splitlines():
        if not line.strip():
            continue
        before, sep, after = line.partition(" - ")
        fields, tail = before.split(), after.split()
        if not sep or len(fields) < 6 or len(tail) < 3:
            raise ValueError("Malformed /proc/self/mountinfo entry")
        mountpoint = re.sub(r"\\([0-7]{3})", lambda m: chr(int(m[1], 8)), fields[4])
        if not mountpoint.startswith("/"):
            raise ValueError("Non-absolute mount point")
        mounts.append((mountpoint, set(fields[5].split(","))))
    if not mounts:
        raise ValueError("Mount table is empty")
    return mounts


def effective_mount(mounts, path):
    target = PurePosixPath(path)
    candidates = [(point, options) for point, options in mounts
                  if target == PurePosixPath(point) or PurePosixPath(point) in target.parents]
    if not candidates:
        raise ValueError(f"No mount covers {path}")
    longest = max(len(PurePosixPath(point).parts) for point, _ in candidates)
    matches = [(point, options) for point, options in candidates
               if len(PurePosixPath(point).parts) == longest]
    if len(matches) != 1:
        raise ValueError(f"Stacked mounts at {matches[0][0]}; effective mount is ambiguous")
    return matches[0]


def resolved_namespace_path(ctx, path):
    """Resolve directory symlinks without escaping the test filesystem root."""
    root = ctx.root.resolve(strict=True)
    resolved = ctx.path(path).resolve(strict=True)
    relative = resolved.relative_to(root)
    return "/" + str(relative) if str(relative) != "." else "/"


def run(ctx):
    results = []
    try:
        mounts = parse_mountinfo(ctx.read("/proc/self/mountinfo"))
        mount_error = None
    except (OSError, ValueError) as exc:
        mounts, mount_error = [], exc
    targets = (("/tmp", {"nodev", "nosuid"}),
               ("/var/tmp", {"nodev", "nosuid"}),
               ("/dev/shm", {"nodev", "nosuid", "noexec"}))
    for index, (path, wanted) in enumerate(targets, 1):
        check_id = f"FILESYSTEM-{index:03d}"
        title = f"Mount restrictions for {path}"
        try:
            ctx.stat(path)
        except FileNotFoundError:
            results.append(Finding(check_id, "filesystem", title, "SKIP", "info",
                                   f"{path} does not exist in this namespace.",
                                   "Re-evaluate if applications create or use this location."))
            continue
        except OSError as exc:
            results.append(unavailable(check_id, "filesystem", title, exc))
            continue
        if mount_error:
            results.append(unavailable(check_id, "filesystem", title, mount_error))
            continue
        try:
            actual_path = resolved_namespace_path(ctx, path)
            point, options = effective_mount(mounts, actual_path)
        except (OSError, ValueError, RuntimeError) as exc:
            results.append(unavailable(check_id, "filesystem", title, exc))
            continue
        missing = sorted(wanted - options)
        note = " Container results cover this mount namespace only." if ctx.profile == "container" else ""
        results.append(Finding(
            check_id, "filesystem", title, "WARN" if missing else "PASS",
            "medium" if missing else "info",
            f"{path} resolves to {actual_path}; uses mount {point}; options={','.join(sorted(options))}; "
            f"missing recommended restrictions={','.join(missing) or 'none'}.{note}",
            "Review application compatibility before enabling nodev/nosuid; use noexec on shared memory "
            "where practical. Mount flags reduce exposure but do not prevent all code execution."))
    bad, errors, checked = [], [], []
    for path in ("/tmp", "/var/tmp", "/dev/shm"):
        try:
            meta = ctx.stat(path)
        except FileNotFoundError:
            continue
        except OSError as exc:
            errors.append(f"{path}: {exc}")
            continue
        mode = stat.S_IMODE(meta.st_mode)
        checked.append(path)
        if meta.st_uid != 0 and ctx.profile == "container":
            errors.append(f"{path}: uid={meta.st_uid} in container namespace; host ownership mapping is unknown")
        if not stat.S_ISDIR(meta.st_mode) or (meta.st_uid != 0 and ctx.profile != "container") or (mode & 0o002 and not mode & stat.S_ISVTX):
            bad.append(f"{path}: uid={meta.st_uid}, mode={mode:04o}")
    status = "FAIL" if bad else "UNKNOWN" if errors else "PASS" if checked else "SKIP"
    results.append(Finding("FILESYSTEM-004", "filesystem", "Temporary directory ownership and sticky bit",
                           status, "high" if bad else "info",
                           "; ".join(bad + errors) or ("Checked: " + ", ".join(checked) if checked else "No target directories exist."),
                           "Use root-owned temporary directories; world-writable directories need the sticky bit. "
                           "Review nonstandard ownership against the intended application model."))
    try:
        meta = ctx.stat("/etc/fstab")
        mode = stat.S_IMODE(meta.st_mode)
        ownership_unknown = meta.st_uid != 0 and ctx.profile == "container"
        bad_fstab = (meta.st_uid != 0 and not ownership_unknown) or bool(mode & 0o022) or not stat.S_ISREG(meta.st_mode)
        results.append(Finding("FILESYSTEM-005", "filesystem", "Persistent mount configuration permissions",
                               "FAIL" if bad_fstab else "UNKNOWN" if ownership_unknown else "PASS", "high" if bad_fstab else "info",
                               f"/etc/fstab: uid={meta.st_uid}, mode={mode:04o}; contents were not collected." +
                               (" Host ownership mapping is unknown in this container namespace." if ownership_unknown else ""),
                               "Keep /etc/fstab root-owned and prevent group/other writes."))
    except FileNotFoundError:
        results.append(Finding("FILESYSTEM-005", "filesystem", "Persistent mount configuration permissions",
                               "SKIP", "info", "/etc/fstab is absent; mounts may be managed elsewhere.",
                               "Review the mechanism that manages persistent mounts on this host."))
    except OSError as exc:
        results.append(unavailable("FILESYSTEM-005", "filesystem", "Persistent mount configuration permissions", exc))
    return results
