"""Metadata-only checks; shadow and private-key contents are never read."""
import stat
import re
from linscope.core import Finding, unavailable


def run(ctx):
    specs = [
        ("PERM-001", "/etc/passwd", 0o644),
        ("PERM-002", "/etc/group", 0o644),
        ("PERM-003", "/etc/shadow", 0o640),
        ("PERM-004", "/etc/gshadow", 0o640),
        ("PERM-005", "/etc/sudoers", 0o440),
        ("PERM-006", "/etc/ssh/sshd_config", 0o644),
    ]
    findings = []
    for check_id, path, allowed in specs:
        try:
            metadata = ctx.stat(path)
            mode = stat.S_IMODE(metadata.st_mode)
            issue = metadata.st_uid != 0 or bool(mode & ~allowed) or not stat.S_ISREG(metadata.st_mode)
            group_unknown = False
            if path in ("/etc/shadow", "/etc/gshadow") and mode & 0o040 and metadata.st_gid != 0:
                try:
                    allowed_groups = {0}
                    shadow_entries = []
                    for line in ctx.read("/etc/group").splitlines():
                        fields = line.split(":")
                        if fields[0] == "shadow":
                            shadow_entries.append(fields)
                    if len(shadow_entries) > 1:
                        raise ValueError("Ambiguous duplicate shadow group")
                    if shadow_entries:
                        fields = shadow_entries[0]
                        if len(fields) != 4 or not re.fullmatch(r"[0-9]+", fields[2]) or not 0 <= int(fields[2]) < 2**32 - 1:
                            raise ValueError("Invalid shadow group GID")
                        allowed_groups.add(int(fields[2]))
                    issue = issue or metadata.st_gid not in allowed_groups
                except (OSError, ValueError):
                    group_unknown = True
            status = "WARN" if issue else ("UNKNOWN" if group_unknown else "PASS")
            findings.append(Finding(check_id, "permissions", f"Protected file: {path}", status,
                                    "high" if "shadow" in path else "medium",
                                    f"uid={metadata.st_uid}, gid={metadata.st_gid}, mode={mode:04o}; baseline maximum={allowed:04o}, owner=root."
                                    + (" Group-read trust could not be established." if group_unknown else ""),
                                    "Review ownership and least-privilege permissions. For shadow files, group-read access is allowed only to root/shadow; do not change blindly."))
        except FileNotFoundError:
            optional = path in ("/etc/sudoers", "/etc/ssh/sshd_config")
            findings.append(Finding(check_id, "permissions", f"Protected file: {path}", "SKIP" if optional else "UNKNOWN", "info",
                                    f"{path} is absent.", "Confirm whether the corresponding component is installed and whether it uses a custom location."))
        except OSError as exc:
            findings.append(unavailable(check_id, "permissions", f"Protected file: {path}", exc))
    try:
        paths = ctx.glob("/etc/ssh/ssh_host_*_key")
        exposed = []
        for path in paths:
            item = ctx.stat(path)
            if item.st_uid != 0 or stat.S_IMODE(item.st_mode) & ~0o600 or not stat.S_ISREG(item.st_mode):
                exposed.append(f"{path} (uid={item.st_uid}, mode={stat.S_IMODE(item.st_mode):04o})")
        findings.append(Finding("PERM-007", "permissions", "SSH host private-key metadata",
                                "WARN" if exposed else ("PASS" if paths else "SKIP"), "high",
                                "; ".join(exposed) or (f"{len(paths)} key file(s) meet root-only baseline." if paths else "No keys at conventional host-key paths."),
                                "Restrict private-key read access. Review intentional group-based key access separately; key contents are never collected."))
    except OSError as exc:
        findings.append(unavailable("PERM-007", "permissions", "SSH host private-key metadata", exc))
    for check_id, path in (("PERM-008", "/tmp"), ("PERM-009", "/var/tmp")):
        try:
            item = ctx.stat(path)
            writable = bool(item.st_mode & stat.S_IWOTH)
            sticky = bool(item.st_mode & stat.S_ISVTX)
            status = "FAIL" if (writable and not sticky) or not stat.S_ISDIR(item.st_mode) else ("WARN" if item.st_uid != 0 else "PASS")
            findings.append(Finding(check_id, "permissions", f"Shared temporary directory: {path}",
                                    status, "high",
                                    f"uid={item.st_uid}, mode={stat.S_IMODE(item.st_mode):04o}; world-writable={writable}, sticky={sticky}.",
                                    "Shared temporary directories should be root-owned and use the sticky bit when world-writable; the owner can delete others' entries despite sticky. Review UID mappings in containers."))
        except OSError as exc:
            findings.append(unavailable(check_id, "permissions", f"Shared temporary directory: {path}", exc))
    for check_id, title, args in [
        ("PERM-010", "SUID/SGID executable inventory", ["find", "/usr/bin", "/usr/sbin", "-xdev", "-type", "f", "-perm", "/6000", "-print"]),
        ("PERM-011", "World-writable configuration/executables", ["find", "/etc", "/usr/local/bin", "-xdev", "-type", "f", "-perm", "-0002", "-print"]),
    ]:
        if not ctx.deep:
            findings.append(Finding(check_id, "permissions", title, "SKIP", "info", "Optional bounded-scope filesystem search disabled.", "Use --deep to inspect the documented directories; this is not a full-disk scan."))
            continue
        result = ctx.command(args, timeout=15)
        if not result.ok:
            findings.append(unavailable(check_id, "permissions", title, result.error or result.stderr or "Search failed; results incomplete."))
        else:
            paths = result.stdout.splitlines()
            status = ("WARN" if paths else "PASS") if check_id == "PERM-011" else "INFO"
            findings.append(Finding(check_id, "permissions", title, status, "medium" if check_id == "PERM-011" else "info",
                                    "Scope: " + ", ".join(args[1:3]) + "; matches: " + (", ".join(paths) or "none"),
                                    "Review ownership and expected package provenance. SUID/SGID alone does not prove vulnerability; mounted sub-filesystems are excluded."))
    return findings
