"""Small shared data model and read-only Linux collectors."""
from __future__ import annotations

from dataclasses import asdict, dataclass
import fnmatch
from pathlib import Path
import os
import shutil
import stat
import subprocess
import tempfile
from typing import Sequence

STATUSES = ("PASS", "WARN", "FAIL", "UNKNOWN", "SKIP", "INFO")
SEVERITIES = ("info", "low", "medium", "high", "critical")


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


class Context:
    """Collectors never change host configuration or request elevation.

    root exists for fixture testing only; the CLI always audits the live host.
    Commands are fixed argument lists supplied by built-in checks, never policy.
    """
    def __init__(self, profile="server", deep=False, root=Path("/")):
        self.profile = profile
        self.deep = deep
        self.root = Path(root)
        self._commands: dict[tuple[str, ...], CommandResult] = {}

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
        return raw.decode("utf-8", errors="replace")

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
        key = tuple(argv)
        if key in self._commands:
            return self._commands[key]
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
            try:
                # Files bound RAM usage; report truncation rather than evaluate partial output.
                with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
                    proc = subprocess.run([binary, *key[1:]], stdin=subprocess.DEVNULL,
                                          stdout=out, stderr=err, timeout=timeout,
                                          env=env, check=False)
                    out.seek(0)
                    err.seek(0)
                    raw_out, raw_err = out.read(1_048_577), err.read(1_048_577)
                too_large = len(raw_out) > 1_048_576 or len(raw_err) > 1_048_576
                result = CommandResult(key, proc.returncode,
                                       raw_out[:1_048_576].decode(errors="replace"),
                                       raw_err[:1_048_576].decode(errors="replace"),
                                       "Command output exceeded collection limit" if too_large else "")
            except subprocess.TimeoutExpired:
                result = CommandResult(key, None, error=f"Command timed out after {timeout}s")
            except OSError as exc:
                result = CommandResult(key, None, error=f"Command failed: {exc}")
        self._commands[key] = result
        return result


def unavailable(check_id, category, title, exc, recommendation="Run on a supported host with sufficient read permissions."):
    return Finding(check_id, category, title, "UNKNOWN", "info", str(exc), recommendation)
