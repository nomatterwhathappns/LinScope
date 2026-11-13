"""Bounded cron/systemd timer metadata checks.

Only system cron and system timers are inspected. User crontabs, transient units,
shell expansion, script contents, interpreters' arguments, and arbitrary task
dependencies are not evaluated. No scheduled command is executed or reported.
"""
from __future__ import annotations

from pathlib import PurePosixPath
import re
import shlex
import stat

from linscope.core import Finding, unavailable

CRON_DIRS = ("/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly")


def _metadata(ctx, paths, check_ancestors=True):
    """Return insecure metadata, unreadable paths, and number inspected."""
    bad, errors, inspected = [], [], set()
    for original in paths:
        candidates = [original]
        if check_ancestors:
            candidates += [str(p) for p in PurePosixPath(original).parents]
            try:
                # stat() follows a symlink but checking only lexical ancestors
                # misses a writable target parent, including parent symlinks.
                root = ctx.root.resolve(strict=True)
                resolved = ctx.path(original).resolve(strict=True)
                relative = resolved.relative_to(root)
                target = "/" + str(relative) if str(relative) != "." else "/"
                candidates += [target] + [str(p) for p in PurePosixPath(target).parents]
            except (OSError, ValueError, RuntimeError) as exc:
                errors.append(f"{original}: target ancestry could not be resolved ({type(exc).__name__})")
        for path in candidates:
            if path in inspected:
                continue
            inspected.add(path)
            try:
                meta = ctx.stat(path)
            except OSError as exc:
                errors.append(f"{path}: {exc}")
                continue
            mode = stat.S_IMODE(meta.st_mode)
            if not (stat.S_ISDIR(meta.st_mode) or stat.S_ISREG(meta.st_mode)):
                errors.append(f"{path}: unsupported file type")
            if meta.st_uid != 0 and ctx.profile == "container":
                errors.append(f"{path}: uid={meta.st_uid} in container namespace; host ownership mapping is unknown")
            if (meta.st_uid != 0 and ctx.profile != "container") or mode & 0o022:
                bad.append(f"{path}: uid={meta.st_uid}, mode={mode:04o}")
    return bad, errors, len(inspected)


def _finding(check_id, title, bad, errors, count, recommendation):
    status = "FAIL" if bad else "UNKNOWN" if errors else "PASS" if count else "SKIP"
    evidence = "; ".join(bad[:20] + errors[:10]) or (
        f"Inspected {count} paths; no non-root ownership or group/other write bits found."
        if count else "No applicable paths were discovered within the documented scope.")
    if len(bad) > 20 or len(errors) > 10:
        evidence += f" Summary truncated: insecure={len(bad)}, unreadable={len(errors)}."
    return Finding(check_id, "scheduled", title, status, "high" if bad else "info", evidence, recommendation)


def root_cron_executables(text):
    """Extract direct absolute executables, recording entries we cannot resolve.

    This accepts system crontab format only. It never treats cron text as code.
    """
    paths, unresolved = [], 0
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or re.match(r"^[A-Za-z_][A-Za-z0-9_]*\s*=", line):
            continue
        fields = line.split(None, 2 if line.startswith("@") else 6)
        user_index, command_index = (1, 2) if line.startswith("@") else (5, 6)
        if len(fields) <= command_index:
            unresolved += 1
            continue
        if fields[user_index] != "root":
            continue
        try:
            words = shlex.split(fields[command_index], comments=False)
        except ValueError:
            unresolved += 1
            continue
        if not words or not words[0].startswith("/") or ".." in PurePosixPath(words[0]).parts:
            unresolved += 1
            continue
        # Shell evaluation, cron percent-newline syntax, and expansion need a parser
        # beyond metadata inspection. Do not claim to resolve these entries.
        if any(char in fields[command_index] for char in ("$", "`", "%", "|", ";", "&", "<", ">", "\n")):
            unresolved += 1
        paths.append(words[0])
    return sorted(set(paths)), unresolved


def _timer_units(ctx):
    listing = ctx.command(["systemctl", "list-timers", "--all", "--no-legend", "--no-pager"])
    if not listing.ok:
        return None, listing.error or f"systemctl list-timers returned {listing.returncode}; timer inventory unavailable."
    names = set()
    for line in listing.stdout.splitlines():
        tokens = [token for token in line.split() if token.endswith(".timer")]
        if len(tokens) != 1:
            if line.strip():
                return None, "Timer listing contains an unsupported row; inventory cannot be evaluated completely."
            continue
        if not re.fullmatch(r"[A-Za-z0-9_.@:\\-]+\.timer", tokens[0]):
            return None, "Timer listing contains an unsupported unit name."
        names.add(tokens[0])
    if len(names) > 50:
        return None, "Timer inventory exceeds the bounded inspection limit of 50 units."
    return sorted(names), None


def _unit_files(ctx, timers):
    paths, errors = set(), []
    for timer in timers:
        info = ctx.command(["systemctl", "show", "--property=FragmentPath,DropInPaths,Unit", "--", timer])
        if not info.ok:
            errors.append(f"{timer}: unit metadata unavailable")
            continue
        props = dict(line.split("=", 1) for line in info.stdout.splitlines() if "=" in line)
        service = props.get("Unit", "")
        if not service or not re.fullmatch(r"[A-Za-z0-9_.@:\\-]+\.service", service):
            errors.append(f"{timer}: activated service could not be resolved")
        else:
            info_service = ctx.command(["systemctl", "show", "--property=FragmentPath,DropInPaths", "--", service])
            if not info_service.ok:
                errors.append(f"{service}: unit metadata unavailable")
            else:
                service_props = dict(line.split("=", 1) for line in info_service.stdout.splitlines() if "=" in line)
                for key in ("FragmentPath", "DropInPaths"):
                    if key not in service_props:
                        errors.append(f"{service}: {key} unavailable")
                    else:
                        for path in service_props[key].split():
                            if not path.startswith("/") or "\\" in path or ".." in PurePosixPath(path).parts:
                                errors.append(f"{service}: unsupported unit file path")
                            else:
                                paths.add(path)
                if not service_props.get("FragmentPath"):
                    errors.append(f"{service}: transient or unresolved fragment")
        for key in ("FragmentPath", "DropInPaths"):
            if key not in props:
                errors.append(f"{timer}: {key} unavailable")
            else:
                for path in props[key].split():
                    if not path.startswith("/") or "\\" in path or ".." in PurePosixPath(path).parts:
                        errors.append(f"{timer}: unsupported unit file path")
                    else:
                        paths.add(path)
        if not props.get("FragmentPath"):
            errors.append(f"{timer}: transient or unresolved fragment")
    return sorted(paths), errors


def run(ctx):
    results, system_files, cron_files, discovery_errors = [], [], [], []
    for path in ("/etc/crontab", "/etc/anacrontab"):
        try:
            meta = ctx.stat(path)
            if not stat.S_ISREG(meta.st_mode):
                discovery_errors.append(f"{path}: expected a regular file")
                continue
            system_files.append(path)
        except FileNotFoundError:
            pass
        except OSError as exc:
            discovery_errors.append(f"{path}: {exc}")
    bad, errors, count = _metadata(ctx, system_files)
    results.append(_finding("SCHEDULED-001", "System crontab configuration permissions", bad,
                            errors + discovery_errors, count,
                            "Keep system crontab files and their resolved ancestors root-owned without group/other write permissions."))
    dirs, directory_errors = [], []
    for directory in CRON_DIRS:
        try:
            meta = ctx.stat(directory)
        except FileNotFoundError:
            continue
        except OSError as exc:
            directory_errors.append(f"{directory}: {exc}")
            continue
        if not stat.S_ISDIR(meta.st_mode):
            directory_errors.append(f"{directory}: expected a directory")
            continue
        dirs.append(directory)
        try:
            cron_files.extend(ctx.glob(directory + "/*"))
        except OSError as exc:
            directory_errors.append(str(exc))
    bad, errors, count = _metadata(ctx, dirs + cron_files)
    results.append(_finding("SCHEDULED-002", "System cron directory and task permissions", bad,
                            errors + directory_errors, count,
                            "Protect system cron directories and tasks from modification by non-root users. "
                            "Only direct entries in standard cron directories are inspected."))
    executable_paths, unresolved, parse_errors = set(), 0, []
    # /etc/anacrontab has different syntax; it is covered by metadata checks only.
    to_parse = (["/etc/crontab"] if "/etc/crontab" in system_files else []) + [p for p in cron_files if PurePosixPath(p).parent == PurePosixPath("/etc/cron.d")]
    for path in to_parse:
        try:
            if not stat.S_ISREG(ctx.stat(path).st_mode):
                parse_errors.append(f"{path}: expected a regular task file; contents were not read")
                continue
            text = ctx.read(path)
        except OSError as exc:
            parse_errors.append(f"{path}: {exc}")
            continue
        paths, count_unresolved = root_cron_executables(text)
        executable_paths.update(paths)
        unresolved += count_unresolved
    bad, errors, count = _metadata(ctx, sorted(executable_paths), check_ancestors=True)
    if unresolved:
        errors.append(f"{unresolved} cron entries could not be fully resolved by the direct-executable parser.")
    results.append(_finding("SCHEDULED-003", "Direct root cron executable metadata", bad,
                            errors + parse_errors + discovery_errors + directory_errors, count,
                            "Keep directly referenced root executables and their parent directories root-controlled. "
                            "Review shell expressions, interpreter arguments, script dependencies, anacron commands, "
                            "and user crontabs separately; task contents are never executed."))
    timers, timer_error = _timer_units(ctx)
    if timer_error:
        results.append(unavailable("SCHEDULED-004", "scheduled", "System timer inventory", timer_error))
        results.append(unavailable("SCHEDULED-005", "scheduled", "Timer and activated service unit permissions", timer_error))
    else:
        results.append(Finding("SCHEDULED-004", "scheduled", "System timer inventory", "INFO", "info",
                               f"Listed {len(timers)} system timers; user timers are outside this check.",
                               "Review whether each enabled timer is needed; an installed timer is not itself a security defect."))
        paths, errors = _unit_files(ctx, timers)
        bad, metadata_errors, count = _metadata(ctx, paths, check_ancestors=True)
        results.append(_finding("SCHEDULED-005", "Timer and activated service unit permissions", bad,
                                errors + metadata_errors, count,
                                "Keep timer/service fragments, drop-ins, and their parent directories root-controlled. "
                                "This check does not evaluate ExecStart dependencies or user timers."))
    return results
