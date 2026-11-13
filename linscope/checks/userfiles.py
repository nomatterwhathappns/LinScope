"""Metadata-only review of the invoking user's conventional credential paths.

No key, authorized_keys, credential, token, or configuration content is opened.
Current-user identity comes from the real UID's local account record, not HOME
or USER environment variables. Explicit paths share that identity baseline.
ACLs, remote identity stores and application-specific alternate paths need
separate review. Symlink targets and their parents are checked within namespace.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path, PurePosixPath
import pwd
import stat

from linscope.core import Finding, unavailable


def path_id(path):
    return "USERFILE-" + hashlib.sha256(path.encode()).hexdigest()[:12].upper() + "-001"


def _identity():
    uid = os.getuid()
    account = pwd.getpwuid(uid)
    if not account.pw_dir.startswith("/") or ".." in PurePosixPath(account.pw_dir).parts:
        raise ValueError("Current account home path is not a supported absolute path")
    return uid, account.pw_dir.rstrip("/") or "/"


def _valid_path(path):
    if (not isinstance(path, str) or not path.startswith("/") or ".." in PurePosixPath(path).parts
            or any(ord(c) < 32 or ord(c) == 127 for c in path) or len(path) > 4096):
        raise ValueError("User metadata paths must be absolute, bounded, and contain no traversal/control characters")
    return str(PurePosixPath(path))


def _ancestors(ctx, path):
    """Return lexical and resolved parents; failure prevents a clean verdict."""
    parents = {str(p) for p in PurePosixPath(path).parents}
    root = getattr(ctx, "root", Path("/")).resolve(strict=True)
    resolved = ctx.path(path).resolve(strict=True)
    relative = resolved.relative_to(root)
    target = "/" + str(relative) if str(relative) != "." else "/"
    parents.update(str(p) for p in PurePosixPath(target).parents)
    return sorted(parents)


def inspect_path(ctx, path, uid, allowed_mode, expected_directory=None, optional=True):
    check_id = path_id(path)
    title = f"User security-file metadata: {path}"
    try:
        meta = ctx.stat(path)
    except FileNotFoundError:
        # A dangling symlink is not ordinary absence. lstat is metadata only.
        try:
            item = ctx.path(path).lstat()
        except FileNotFoundError:
            item = None
        except (OSError, ValueError) as exc:
            return unavailable(check_id, "userfiles", title, exc)
        if item is not None:
            return unavailable(check_id, "userfiles", title, "The path exists but its target cannot be resolved.")
        return Finding(check_id, "userfiles", title, "SKIP" if optional else "UNKNOWN", "info",
                       "Optional conventional path is absent." if optional else "Explicitly selected path is absent; metadata could not be evaluated.",
                       "Re-evaluate if this credential/configuration location is introduced or uses an alternate path.")
    except (OSError, ValueError) as exc:
        return unavailable(check_id, "userfiles", title, exc)
    mode = stat.S_IMODE(meta.st_mode)
    if expected_directory is None and stat.S_ISDIR(meta.st_mode):
        allowed_mode |= 0o100
    bad, errors = [], []
    if not stat.S_ISREG(meta.st_mode) and not stat.S_ISDIR(meta.st_mode):
        bad.append("unsupported file type")
    if expected_directory is True and not stat.S_ISDIR(meta.st_mode):
        bad.append("expected a directory")
    if expected_directory is False and not stat.S_ISREG(meta.st_mode):
        bad.append("expected a regular file")
    allowed = {0, uid}
    if meta.st_uid not in allowed:
        bad.append(f"owner uid={meta.st_uid} differs from invoking user/root baseline")
    if mode & ~allowed_mode:
        bad.append(f"mode={mode:04o} exceeds baseline maximum={allowed_mode:04o}")
    try:
        parents = _ancestors(ctx, path)
    except (OSError, ValueError, RuntimeError) as exc:
        parents = []
        errors.append(f"target ancestry could not be established ({type(exc).__name__})")
    for parent in parents:
        try:
            item = ctx.stat(parent)
        except OSError:
            errors.append(f"parent metadata unavailable: {parent}")
            continue
        if not stat.S_ISDIR(item.st_mode):
            errors.append(f"parent is not a directory: {parent}")
        if item.st_uid not in allowed or stat.S_IMODE(item.st_mode) & 0o022:
            bad.append(f"parent requires review: {parent} (uid={item.st_uid}, mode={stat.S_IMODE(item.st_mode):04o})")
    status = "WARN" if bad else "UNKNOWN" if errors else "PASS"
    return Finding(check_id, "userfiles", title, status, "high" if bad else "info",
                   f"uid={meta.st_uid}, gid={meta.st_gid}, mode={mode:04o}; no contents read. "
                   + ("; ".join(bad[:10] + errors[:5]) or "File and resolved ancestor metadata meet the stated invoking-user/root baseline.")
                   + (" Additional metadata concerns omitted." if len(bad) > 10 or len(errors) > 5 else ""),
                   "Restrict private credential/configuration access, protect parent directories, and verify intended ownership. "
                   "Review ACLs and namespace UID mappings separately; do not blindly change permissions.")


def run(ctx):
    try:
        uid, home = _identity()
        explicit = [_valid_path(path) for path in getattr(ctx, "user_paths", [])]
        if len(explicit) > 50:
            raise ValueError("At most 50 explicit user metadata paths are supported")
    except (KeyError, OSError, ValueError, TypeError) as exc:
        return [unavailable("USERFILE-000", "userfiles", "Invoking-user security-file scope", str(exc),
                            "Use a local account with a known home directory and supported explicit paths.")]
    base = home.rstrip("/")
    candidates = {
        base + "/.ssh": (0o700, True, True),
        base + "/.ssh/authorized_keys": (0o644, False, True),
        base + "/.aws/credentials": (0o600, False, True),
        base + "/.kube/config": (0o600, False, True),
        base + "/.docker/config.json": (0o600, False, True),
        base + "/.config/gcloud/application_default_credentials.json": (0o600, False, True),
    }
    errors = []
    try:
        # Public key/certificate files are not private-key candidates.
        for path in ctx.glob(base + "/.ssh/id_*"):
            if not path.endswith(".pub"):
                candidates[path] = (0o600, False, True)
    except (OSError, ValueError) as exc:
        errors.append(unavailable("USERFILE-001", "userfiles", "Conventional SSH private-key discovery", str(exc),
                                  "Grant sufficient metadata access or explicitly select key paths; key contents are never read."))
    for path in explicit:
        if path in candidates:
            allowed_mode, expected_directory, _ = candidates[path]
            candidates[path] = (allowed_mode, expected_directory, False)
        else:
            candidates[path] = (0o600, None, False)
    results = [inspect_path(ctx, path, uid, *spec) for path, spec in sorted(candidates.items())]
    results.extend(errors)
    return results
