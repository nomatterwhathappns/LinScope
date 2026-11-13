"""Read-only review of the conventional local rootful Docker endpoint.

Only running containers in the local socket's namespace are inspected, at most
25 per snapshot. Rootless/custom sockets, remote contexts, images, stopped
containers, actual process credentials, orchestration policy and effective
capability sets are outside this module. Container inspect is a whitelist
projection: environment variables and arbitrary inspect fields are never read.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import PurePosixPath
import re
import stat

from linscope.core import Finding, unavailable

SOCKET = "/var/run/docker.sock"
ENDPOINT = "unix://" + SOCKET
PREFIX = ["docker", "--host", ENDPOINT]
LIMIT = 25
LIST_ARGS = [*PREFIX, "container", "ls", "--no-trunc", "--format", "{{.ID}}"]
PROJECTION = ('{"Privileged":{{json .HostConfig.Privileged}},'
              '"NetworkMode":{{json .HostConfig.NetworkMode}},'
              '"ReadonlyRootfs":{{json .HostConfig.ReadonlyRootfs}},'
              '"CapAdd":{{json .HostConfig.CapAdd}},'
              '"User":{{json .Config.User}},'
              '"Mounts":[{{range $i,$m := .Mounts}}{{if $i}},{{end}}'
              '{"Type":{{json $m.Type}},"Source":{{json $m.Source}},'
              '"Destination":{{json $m.Destination}},"RW":{{json $m.RW}}}{{end}}]}')
HIGH_CAPS = {"ALL", "SYS_ADMIN", "SYS_MODULE", "SYS_PTRACE", "SYS_RAWIO",
             "SYS_BOOT", "NET_ADMIN", "DAC_READ_SEARCH", "BPF", "PERFMON",
             "CHECKPOINT_RESTORE", "MAC_ADMIN", "MAC_OVERRIDE"}
CAPS = set(("CHOWN DAC_OVERRIDE DAC_READ_SEARCH FOWNER FSETID KILL SETGID SETUID "
            "SETPCAP LINUX_IMMUTABLE NET_BIND_SERVICE NET_BROADCAST NET_ADMIN "
            "NET_RAW IPC_LOCK IPC_OWNER SYS_MODULE SYS_RAWIO SYS_CHROOT SYS_PTRACE "
            "SYS_PACCT SYS_ADMIN SYS_BOOT SYS_NICE SYS_RESOURCE SYS_TIME SYS_TTY_CONFIG "
            "MKNOD LEASE AUDIT_WRITE AUDIT_CONTROL SETFCAP MAC_OVERRIDE MAC_ADMIN "
            "SYSLOG WAKE_ALARM BLOCK_SUSPEND AUDIT_READ PERFMON BPF CHECKPOINT_RESTORE ALL").split())


def container_prefix(container_id):
    return "DOCKER-" + hashlib.sha256(container_id.encode()).hexdigest()[:12].upper()


def _finding(prefix, number, title, status, severity, evidence, recommendation):
    return Finding(f"{prefix}-{number:03d}", "docker", title, status, severity,
                   evidence, recommendation)


def _unknown(prefix, number, title, detail):
    return unavailable(f"{prefix}-{number:03d}", "docker", title, detail,
                       "Inspect this field using the local Docker daemon with sufficient read access; no changes are applied.")


def parse_inventory(text):
    values = [line.strip() for line in text.splitlines() if line.strip()]
    if any(not re.fullmatch(r"[0-9a-f]{64}", value) for value in values):
        raise ValueError("Docker container inventory contains an invalid full container ID")
    if len(set(values)) != len(values):
        raise ValueError("Docker container inventory contains duplicate IDs")
    return sorted(values)


def _sensitive_source(source):
    """Identify selected host-control/credential locations, not arbitrary binds."""
    source = str(PurePosixPath("/" + source.lstrip("/")))
    target = PurePosixPath(source)
    exact = {"/", "/etc", "/run", "/var/run"}
    roots = ("/etc/shadow", "/etc/gshadow", "/etc/sudoers", "/etc/sudoers.d",
             "/etc/ssh", "/etc/pam.d", "/root", "/home", "/proc", "/sys",
             "/dev", "/var/lib/docker", "/run/docker.sock", "/var/run/docker.sock")
    return source in exact or any(target == PurePosixPath(root) or PurePosixPath(root) in target.parents
                                  for root in roots)


def inspect_container(ctx, container_id):
    prefix = container_prefix(container_id)
    label = container_id[:12]
    result = ctx.command([*PREFIX, "container", "inspect", "--format", PROJECTION, "--", container_id])
    if not result.ok:
        return [_unknown(prefix, 0, f"Container {label} projected configuration",
                         result.error or "Docker configuration unavailable; the container may have exited or access was denied.")]
    try:
        def unique(pairs):
            value = {}
            for key, item in pairs:
                if key in value:
                    raise ValueError("Duplicate field in projected Docker JSON")
                value[key] = item
            return value
        def invalid_constant(value):
            raise ValueError("Non-finite value in projected Docker JSON")
        data = json.loads(result.stdout, object_pairs_hook=unique, parse_constant=invalid_constant)
        if not isinstance(data, dict):
            raise ValueError("Expected one projected Docker configuration object")
    except (ValueError, TypeError) as exc:
        return [_unknown(prefix, 0, f"Container {label} projected configuration", str(exc))]
    findings = []
    for number, key, title, expected, severity, recommendation in (
        (1, "Privileged", "privileged mode", False, "high",
         "Avoid privileged containers unless the workload explicitly requires broad host access; assess host controls separately."),
        (3, "ReadonlyRootfs", "root filesystem mutability", True, "medium",
         "Use a read-only container root filesystem where compatible, with explicit writable storage for application data."),
    ):
        value = data.get(key)
        if type(value) is not bool:
            findings.append(_unknown(prefix, number, f"Container {label} {title}", f"Projected {key} is missing or is not a boolean."))
        else:
            findings.append(_finding(prefix, number, f"Container {label} {title}",
                                     "PASS" if value == expected else "WARN", severity,
                                     f"Configured {key}={value}; snapshot of the local daemon, not proof of host isolation.", recommendation))
    network = data.get("NetworkMode")
    if not isinstance(network, str) or len(network) > 256 or not re.fullmatch(r"[A-Za-z0-9_.:-]+", network):
        findings.append(_unknown(prefix, 2, f"Container {label} network namespace", "Projected NetworkMode is missing or malformed."))
    else:
        findings.append(_finding(prefix, 2, f"Container {label} network namespace",
                                 "WARN" if network == "host" else "INFO", "medium" if network == "host" else "info",
                                 "Host networking is configured." if network == "host" else "A non-host network mode is configured; other namespace sharing and network access require review.",
                                 "Review whether sharing the host network namespace is necessary; use suitable network separation for the workload."))
    additions = data.get("CapAdd", "missing")
    if additions is None:
        additions = []
    if (not isinstance(additions, list) or len(additions) > 100 or
            any(not isinstance(value, str) or value.removeprefix("CAP_") not in CAPS for value in additions)):
        findings.append(_unknown(prefix, 4, f"Container {label} added capabilities", "Projected CapAdd is missing, malformed, or contains an unknown capability."))
    else:
        normalized = {value.removeprefix("CAP_") for value in additions}
        elevated = normalized & HIGH_CAPS
        findings.append(_finding(prefix, 4, f"Container {label} added capabilities",
                                 "WARN" if elevated else ("INFO" if additions else "PASS"), "high" if elevated else "info",
                                 f"Explicit additions={len(additions)}; high-impact additions=" + (", ".join(sorted(elevated)) or "none")
                                 + ". This does not enumerate Docker's default or the process's effective capabilities.",
                                 "Grant only capabilities required by the workload, and verify effective process capabilities and namespace controls separately."))
    mounts = data.get("Mounts")
    valid = isinstance(mounts, list) and len(mounts) <= 500
    selected, writable = [], 0
    if valid:
        for mount in mounts:
            if (not isinstance(mount, dict) or not all(isinstance(mount.get(k), str) for k in ("Type", "Source", "Destination"))
                    or type(mount.get("RW")) is not bool):
                valid = False
                break
            if mount["Type"] not in {"bind", "volume", "tmpfs", "npipe"}:
                valid = False
                break
            if mount["Type"] == "bind":
                source = mount["Source"]
                if not source.startswith("/") or ".." in PurePosixPath(source).parts:
                    valid = False
                    break
                if _sensitive_source(source):
                    selected.append(source)
                    writable += int(mount["RW"])
    if not valid:
        findings.append(_unknown(prefix, 5, f"Container {label} sensitive bind mounts", "Projected mount metadata is missing, malformed or exceeds the limit."))
    else:
        findings.append(_finding(prefix, 5, f"Container {label} sensitive bind mounts",
                                 "WARN" if selected else "PASS", "high" if writable else "medium",
                                 f"Selected sensitive host bind mounts={len(selected)}; writable={writable}. "
                                 "Only selected conventional host-control/credential locations are classified; no file contents collected.",
                                 "Review host filesystem and daemon-socket exposure. Read-only mounts can still disclose sensitive data; ordinary application binds are not automatically flagged."))
    user = data.get("User")
    if not isinstance(user, str) or len(user) > 256:
        findings.append(_unknown(prefix, 6, f"Container {label} configured user", "Projected User is missing or malformed."))
    else:
        username = user.split(":", 1)[0]
        if username in ("", "root") or (re.fullmatch(r"[0-9]+", username) and int(username) == 0):
            status, evidence = "WARN", "Container configuration uses root or the default user. User namespaces can alter the host UID mapping."
        elif re.fullmatch(r"[0-9]+", username):
            if int(username) < 2**32 - 1:
                status, evidence = "PASS", "Container configuration names a nonzero numeric UID; runtime process credentials were not checked."
            else:
                status, evidence = "UNKNOWN", "Container configuration contains a numeric UID outside the usable Linux range."
        else:
            status, evidence = "INFO", "Container configuration names a user; its numeric UID and runtime process credentials were not resolved."
        findings.append(_finding(prefix, 6, f"Container {label} configured user", status, "medium",
                                 evidence, "Prefer a suitable non-root runtime user and verify application, user-namespace and process-credential requirements."))
    return findings


def run(ctx):
    try:
        meta = ctx.stat(SOCKET)
    except FileNotFoundError:
        return [Finding("DOCKER-001", "docker", "Conventional local Docker socket", "SKIP", "info",
                        f"{SOCKET} is absent. Rootless/custom sockets and remote daemons are outside this module.",
                        "Select this module on hosts using the conventional rootful local Docker socket.")]
    except OSError as exc:
        return [unavailable("DOCKER-001", "docker", "Local Docker socket metadata", exc)]
    mode = stat.S_IMODE(meta.st_mode)
    if not stat.S_ISSOCK(meta.st_mode):
        return [Finding("DOCKER-001", "docker", "Local Docker socket metadata", "FAIL", "high",
                        f"{SOCKET} is not a UNIX socket; daemon queries were not attempted.",
                        "Investigate the unexpected socket-path file type and intended local daemon configuration.")]
    if mode & 0o002:
        status, severity = "FAIL", "high"
    elif meta.st_uid != 0:
        status, severity = ("UNKNOWN", "info") if getattr(ctx, "profile", "server") == "container" else ("WARN", "high")
    elif mode & 0o020 and meta.st_gid != 0:
        status, severity = "WARN", "medium"
    else:
        status, severity = "PASS", "medium"
    results = [Finding("DOCKER-001", "docker", "Local Docker socket metadata", status, severity,
                       f"uid={meta.st_uid}, gid={meta.st_gid}, mode={mode:04o}; local conventional rootful endpoint only. "
                       "Non-root group write grants extensive daemon control; ACLs and namespace mappings are not established here.",
                       "Restrict daemon-socket access to trusted administrators and review Docker-group membership and ACLs.")]
    inventory = ctx.command(LIST_ARGS)
    if not inventory.ok:
        results.append(unavailable("DOCKER-002", "docker", "Running local Docker container inventory",
                                   inventory.error or "Local daemon inventory failed or access was denied; no containers were evaluated."))
        return results
    try:
        ids = parse_inventory(inventory.stdout)
    except ValueError as exc:
        results.append(unavailable("DOCKER-002", "docker", "Running local Docker container inventory", exc))
        return results
    truncated = len(ids) > LIMIT
    results.append(Finding("DOCKER-002", "docker", "Running local Docker container inventory",
                           "UNKNOWN" if truncated else "INFO", "info",
                           f"Observed {len(ids)} running container(s); inspecting {min(len(ids), LIMIT)}. "
                           + ("Inspection limit exceeded; coverage is incomplete. " if truncated else "")
                           + "Stopped containers, rootless/custom sockets, remote daemons and other namespaces are not evaluated.",
                           "Review all relevant daemon/container scopes; this snapshot does not establish complete Docker security."))
    for container_id in ids[:LIMIT]:
        results.extend(inspect_container(ctx, container_id))
    return results
