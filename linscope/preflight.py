"""Advisory collection capabilities without executing checks or opening secrets.

Executable discovery does not prove a command will succeed. Filesystem access
is a point-in-time, effective-identity hint, not an evaluation of category health.
"""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import stat


TRUSTED_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
CATEGORY_TOOLS = {
    "ssh": ("sshd",),
    "accounts": (),
    "permissions": ("find",),
    "authentication": ("passwd",),
    "network": ("ss", "ufw", "nft", "iptables", "ip6tables"),
    "services": ("systemctl",),
    "kernel": (),
    "packages": ("dpkg-query", "apt-get"),
    "logging": ("systemctl", "systemd-analyze", "timedatectl"),
    "scheduled": ("systemctl",),
    "filesystem": (),
    "mac": ("getenforce", "aa-status"),
    "acl": ("getfacl",),
    "sudo": ("sudo",),
    "systemd": ("systemctl",),
    "docker": ("docker",),
    "userfiles": (),
}

# category, path, access required by collectors: content, directory, or metadata.
# This is a representative capability sample, not every path a category uses.
PATH_REQUIREMENTS = (
    ("ssh", "/etc/ssh/sshd_config", "content"),
    ("accounts", "/etc/passwd", "content"),
    ("accounts", "/etc/group", "content"),
    ("accounts", "/etc/sudoers", "content"),
    ("permissions", "/etc/shadow", "metadata"),
    ("permissions", "/etc/gshadow", "metadata"),
    ("authentication", "/etc/login.defs", "content"),
    ("authentication", "/etc/pam.d/common-password", "content"),
    ("authentication", "/etc/pam.d/common-auth", "content"),
    ("kernel", "/proc/sys/kernel/randomize_va_space", "content"),
    ("kernel", "/proc/sys/net/ipv4/ip_forward", "content"),
    ("packages", "/etc/os-release", "content"),
    ("packages", "/var/lib/apt/lists", "directory"),
    ("logging", "/var/log", "metadata"),
    ("logging", "/etc/logrotate.conf", "metadata"),
    ("scheduled", "/etc/crontab", "content"),
    ("filesystem", "/proc/self/mountinfo", "content"),
    ("filesystem", "/etc/fstab", "metadata"),
    ("mac", "/sys/kernel/security/lsm", "content"),
    ("docker", "/var/run/docker.sock", "metadata"),
)


def _access(ctx, category, path, required):
    result = {"path": path, "categories": [category], "state": "unknown",
              "read_access": None, "detail": ""}
    try:
        metadata = ctx.stat(path)
    except FileNotFoundError:
        result.update(state="absent", detail="Not present at the conventional path; custom locations may exist.")
        return result
    except OSError:
        result.update(state="unreadable", detail="Metadata cannot be inspected with the current effective identity.")
        return result
    if required == "metadata":
        result.update(state="metadata-available", detail="Metadata is available; file contents were not opened or tested.")
        return result
    expected = stat.S_ISDIR(metadata.st_mode) if required == "directory" else stat.S_ISREG(metadata.st_mode)
    if not expected:
        result.update(detail="Conventional path has an unexpected file type; collection requires separate review.")
        return result
    try:
        resolved = ctx.path(path)
        mode = os.R_OK | (os.X_OK if required == "directory" else 0)
        readable = os.access(resolved, mode, effective_ids=True)
    except (OSError, ValueError, NotImplementedError, TypeError):
        result.update(detail="Effective-identity access could not be established on this platform.")
        return result
    result.update(state="readable" if readable else "unreadable", read_access=readable,
                  detail="Advisory effective-identity access check only; contents were not opened.")
    return result


def _container_hint(ctx):
    markers, inaccessible = [], False
    for path in ("/.dockerenv", "/run/.containerenv"):
        try:
            ctx.stat(path)
            markers.append(path)
        except FileNotFoundError:
            pass
        except OSError:
            inaccessible = True
    if markers:
        state = "hint-present"
        evidence = "Container marker metadata found: " + ", ".join(markers) + "."
    elif inaccessible:
        state = "unknown"
        evidence = "Container marker metadata could not be fully inspected."
    else:
        state = "not-detected"
        evidence = "No conventional container marker found; this does not establish a bare-metal or VM environment."
    return {"state": state, "evidence": evidence}


def inspect_capabilities(ctx, categories):
    """Return a JSON-serializable capability snapshot without running commands.

    Paths are sampled only for selected built-in categories. Private file
    contents, environment variables and command output are never collected.
    """
    categories = list(dict.fromkeys(categories))
    if not all(isinstance(category, str) and category in CATEGORY_TOOLS for category in categories):
        raise ValueError("Unsupported preflight category")
    tools = {}
    for category in categories:
        for command in CATEGORY_TOOLS[category]:
            tools.setdefault(command, []).append(category)
    discovered = []
    fixture = Path(getattr(ctx, "root", "/")) != Path("/")
    for command, owners in sorted(tools.items()):
        # A fixture filesystem must not accidentally inspect the host toolchain.
        if fixture:
            path = None
            available = None
            detail = "Tool discovery is disabled for a fixture filesystem."
        else:
            path = shutil.which(command, path=TRUSTED_PATH)
            available = path is not None
            detail = "Executable discovery only; permissions, supported options and runtime success are unverified."
        discovered.append({"name": command, "categories": owners,
                           "available": available, "path": path,
                           "execution_verified": False, "detail": detail})
    uid = os.getuid() if hasattr(os, "getuid") else None
    euid = os.geteuid() if hasattr(os, "geteuid") else None
    paths = [_access(ctx, category, path, required)
             for category, path, required in PATH_REQUIREMENTS if category in categories]
    return {
        "kind": "preflight", "schema_version": 1,
        "profile": getattr(ctx, "profile", "server"),
        "identity": {"uid": uid, "euid": euid, "is_root": euid == 0 if euid is not None else None},
        "categories": categories,
        "container": _container_hint(ctx), "tools": discovered, "paths": paths,
        "notes": [
            "No check commands were executed and no credential/key/hash contents were opened.",
            "Binary presence does not establish successful or privileged collection. Missing tools may affect only part of a category.",
            "Path access is a representative point-in-time hint; namespace, OS version, ACLs and live service state can still limit collection.",
            "Profile selection expresses intended role; a container profile cannot establish host-wide controls.",
        ],
    }


def _plain(value):
    return "".join(c for c in str(value) if c in "\n\t" or (ord(c) >= 32 and not 127 <= ord(c) <= 159))


def render_preflight_text(data):
    """Render the capability snapshot without claiming audit success."""
    identity = data["identity"]
    lines = ["LinScope / Collection preflight",
             f"Profile: {data['profile']} | UID: {identity['uid']} | EUID: {identity['euid']}",
             "Categories: " + ", ".join(data["categories"]),
             "Container hint: " + data["container"]["evidence"], "", "TOOLS (not executed)"]
    for tool in data["tools"]:
        state = "AVAILABLE" if tool["available"] is True else "MISSING" if tool["available"] is False else "UNKNOWN"
        lines.append(f"  [{state}] {tool['name']}: {tool['path'] or 'no discovered executable'} ({', '.join(tool['categories'])})")
    if not data["tools"]:
        lines.append("  No external commands in the selected category map.")
    lines.append("\nREPRESENTATIVE PATH ACCESS (contents not opened)")
    for path in data["paths"]:
        lines.append(f"  [{path['state'].upper()}] {path['path']}: {path['detail']}")
    if not data["paths"]:
        lines.append("  No fixed path samples for the selected categories.")
    lines.append("")
    lines.extend("Note: " + note for note in data["notes"])
    return _plain("\n".join(lines)) + "\n"
