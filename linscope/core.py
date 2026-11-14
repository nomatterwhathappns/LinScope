"""Small shared data model and read-only Linux collectors."""
from __future__ import annotations

from dataclasses import asdict, dataclass
import fnmatch
import math
from pathlib import Path
import os
import selectors
import shutil
import signal
import stat
import subprocess
import time
from typing import Sequence

STATUSES = ("PASS", "WARN", "FAIL", "UNKNOWN", "SKIP", "INFO")
SEVERITIES = ("info", "low", "medium", "high", "critical")
COMMAND_OUTPUT_LIMIT = 1_048_576
_READ_CHUNK = 65_536


@dataclass(frozen=True)
class Finding:
    id: str
    category: str
    title: str
    status: str
    severity: str
    evidence: str
    recommendation: str

    def __post_init__(self):
        if self.status not in STATUSES or self.severity not in SEVERITIES:
            raise ValueError("Invalid finding status or severity")

    def to_dict(self):
        return asdict(self)


@dataclass(frozen=True)
class CommandResult:
    argv: tuple[str, ...]
    returncode: int | None
    stdout: str = ""
    stderr: str = ""
    error: str = ""

    @property
    def ok(self):
        return self.returncode == 0 and not self.error


def _terminate_command(proc):
    """Kill this invocation's process group and reap its direct child.

    start_new_session reserves a group for this invocation. Ordinary descendants
    that retain that group are terminated too; descendants deliberately creating
    another session/group are outside this collector's process-group boundary.
    Grandchildren are reaped by their parent or the system's child reaper.
    """
    error = ""
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError as exc:
        error = f"Process-group termination failed ({type(exc).__name__})"
        try:
            proc.kill()
        except ProcessLookupError:
            pass
        except OSError:
            pass
    try:
        proc.wait(timeout=1)
    except subprocess.TimeoutExpired:
        error = (error + "; " if error else "") + "Direct child could not be reaped within cleanup timeout"
    except OSError as exc:
        error = (error + "; " if error else "") + f"Direct child wait failed ({type(exc).__name__})"
    return error


def _run_bounded(command, argv, env, timeout):
    """Drain two pipes fairly with bounded memory and a single elapsed deadline.

    No command output is written to disk. One byte beyond either channel's
    limit is sufficient to stop collection and terminate the process group.
    A parent exiting while descendants hold a pipe open cannot defeat timeout.
    """
    output = {"stdout": bytearray(), "stderr": bytearray()}
    proc, failure, returncode, completed = None, "", None, False
    deadline = time.monotonic() + timeout
    try:
        proc = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                bufsize=0, env=env, start_new_session=True,
                                close_fds=True)
        with selectors.DefaultSelector() as selector:
            for channel in output:
                stream = getattr(proc, channel)
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, channel)
            while selector.get_map() and not failure:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    failure = f"Command timed out after {timeout:g}s"
                    break
                for key, _ in selector.select(min(remaining, 1.0)):
                    channel, stream = key.data, key.fileobj
                    available = COMMAND_OUTPUT_LIMIT - len(output[channel])
                    try:
                        data = os.read(stream.fileno(), min(_READ_CHUNK, available + 1))
                    except BlockingIOError:
                        continue
                    if not data:
                        selector.unregister(stream)
                        stream.close()
                        continue
                    output[channel].extend(data[:available])
                    if len(data) > available:
                        failure = f"Command {channel} exceeded collection limit ({COMMAND_OUTPUT_LIMIT} bytes)"
                        break
            if not failure:
                try:
                    returncode = proc.wait(timeout=max(0, deadline - time.monotonic()))
                    completed = True
                except subprocess.TimeoutExpired:
                    failure = f"Command timed out after {timeout:g}s"
    except (OSError, ValueError) as exc:
        failure = f"Command collection failed ({type(exc).__name__}): {exc}"
    finally:
        if proc is not None:
            if not completed:
                cleanup_error = _terminate_command(proc)
                if cleanup_error:
                    failure = (failure + "; " if failure else "") + cleanup_error
            for channel in output:
                stream = getattr(proc, channel)
                if stream is not None:
                    stream.close()
    decoded = {}
    for channel, raw in output.items():
        try:
            decoded[channel] = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            decoded[channel] = ""
            if not failure:
                failure = f"Command {channel} is not valid UTF-8; evidence was not evaluated"
    return CommandResult(argv, returncode, decoded["stdout"], decoded["stderr"], failure)


class Context:
    """Collectors never change host configuration or request elevation.

    root exists for fixture testing only; the CLI always audits the live host.
    Commands are fixed argument lists supplied by built-in checks, never policy.
    """
    def __init__(self, profile="server", deep=False, root=Path("/"), *,
                 baseline=None, ssh_contexts=None, sudo_users=None,
                 user_paths=None, service_units=None):
        self.profile = profile
        self.deep = deep
        self.root = Path(root)
        self.baseline = baseline or {}
        self.ssh_contexts = ssh_contexts or []
        self.sudo_users = sudo_users or []
        self.user_paths = user_paths or []
        self.service_units = service_units or []
        self._commands: dict[tuple[tuple[str, ...], float], CommandResult] = {}

    def path(self, path: str):
        relative = Path(path.lstrip("/"))
        if ".." in relative.parts:
            raise ValueError("Parent traversal is not supported")
        candidate = self.root / relative
        if self.root != Path("/") and not candidate.resolve().is_relative_to(self.root.resolve()):
            raise OSError("Fixture symlink escapes collection root")
        return candidate

    def read(self, path: str, limit=1_048_576) -> str:
        fd = os.open(self.path(path), os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
        with os.fdopen(fd, "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise OSError(f"{path}: not a regular configuration/pseudo-file")
            raw = stream.read(limit + 1)
        if len(raw) > limit:
            raise OSError(f"{path}: exceeds collection size limit")
        try:
            return raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise OSError(f"{path}: not valid UTF-8; evidence was not evaluated") from exc

    def stat(self, path: str):
        return self.path(path).stat()

    def glob(self, pattern: str, limit=500):
        # pathlib.glob can suppress directory permission errors. Enumerate
        # explicitly so inaccessible evidence never masquerades as no matches.
        parts = Path(pattern.lstrip("/")).parts
        if ".." in parts or "**" in parts:
            raise OSError("Recursive or parent-traversing glob is unsupported")
        current = [""]
        inspected = 0
        for part in parts:
            following = []
            for relative in current:
                parent = self.path(relative)
                try:
                    with os.scandir(parent) as entries:
                        for entry in entries:
                            inspected += 1
                            if inspected > 20_000:
                                raise OSError("Glob exceeded directory-entry collection limit")
                            if fnmatch.fnmatchcase(entry.name, part):
                                following.append((relative + "/" + entry.name).lstrip("/"))
                                if len(following) > limit:
                                    raise OSError(f"{pattern}: exceeds collection file limit ({limit})")
                except (FileNotFoundError, NotADirectoryError):
                    continue
            current = following
        return sorted("/" + path for path in current)

    def command(self, argv: Sequence[str], timeout=8) -> CommandResult:
        if isinstance(argv, (str, bytes)):
            return CommandResult((), None, error="Command arguments must be a nonempty sequence of strings")
        try:
            key = tuple(argv)
        except TypeError:
            return CommandResult((), None, error="Command arguments must be a nonempty sequence of strings")
        if not key or any(not isinstance(arg, str) or "\x00" in arg for arg in key) or not key[0]:
            return CommandResult((), None, error="Command executable must be nonempty; arguments must be strings without NUL bytes")
        try:
            valid_timeout = type(timeout) in (int, float) and math.isfinite(timeout) and timeout > 0
        except OverflowError:
            valid_timeout = False
        if not valid_timeout:
            return CommandResult(key, None, error="Command timeout must be a finite positive number")
        cache_key = (key, float(timeout))
        if cache_key in self._commands:
            return self._commands[cache_key]
        # A test filesystem must never fall through to commands on the host.
        if self.root != Path("/"):
            return CommandResult(key, None, error="Commands disabled for fixture filesystem")
        search_path = "/usr/sbin:/usr/bin:/sbin:/bin"
        binary = shutil.which(key[0], path=search_path)
        if binary is None:
            result = CommandResult(key, None, error=f"Command unavailable: {key[0]}")
        else:
            env = {"PATH": search_path, "LC_ALL": "C", "LANG": "C",
                   "SYSTEMD_PAGER": "cat", "SYSTEMD_COLORS": "0"}
            result = _run_bounded([binary, *key[1:]], key, env, float(timeout))
        self._commands[cache_key] = result
        return result


def unavailable(check_id, category, title, exc, recommendation="Run on a supported host with sufficient read permissions."):
    return Finding(check_id, category, title, "UNKNOWN", "info", str(exc), recommendation)
