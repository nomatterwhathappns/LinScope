"""Local account and privilege inventory. Does not query remote identity stores."""
import re
from linscope.core import Finding, unavailable


def parse_passwd(text):
    rows = []
    names = set()
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        fields = line.split(":")
        if len(fields) != 7:
            raise ValueError("Malformed local passwd record; account assessment is incomplete")
        if not fields[0] or fields[0] in names or any(c.isspace() for c in fields[0]):
            raise ValueError("Invalid or duplicate local account name")
        if not all(re.fullmatch(r"[0-9]+", fields[index]) for index in (2, 3)):
            raise ValueError("Local account UID/GID must be unsigned decimal integers")
        uid, gid = int(fields[2]), int(fields[3])
        if not (0 <= uid < 2**32 - 1 and 0 <= gid < 2**32 - 1):
            raise ValueError("Local account UID/GID outside usable Linux range")
        names.add(fields[0])
        rows.append((fields[0], uid, gid, fields[6]))
    if not rows:
        raise ValueError("No local passwd records")
    return rows


def run(ctx):
    findings = []
    try:
        users = parse_passwd(ctx.read("/etc/passwd"))
        roots = [name for name, uid, _, _ in users if uid == 0]
        findings.append(Finding("ACCT-001", "accounts", "UID zero accounts",
                                "PASS" if roots == ["root"] else "FAIL", "critical",
                                "UID 0 accounts: " + (", ".join(roots) or "none"),
                                "Investigate any UID 0 account other than the expected root account; do not remove accounts without checking dependencies."))
        mapping = {}
        for name, uid, _, _ in users:
            mapping.setdefault(uid, []).append(name)
        duplicates = [f"UID {uid}: {', '.join(names)}" for uid, names in mapping.items() if len(names) > 1]
        findings.append(Finding("ACCT-002", "accounts", "Duplicate local user IDs",
                                "WARN" if duplicates else "PASS", "medium",
                                "; ".join(duplicates) or "No duplicate UIDs in /etc/passwd.",
                                "Review shared UIDs, which share file ownership and permissions; document intentional cases."))
        try:
            defs = ctx.read("/etc/login.defs")
            entries = [line.split("#", 1)[0].split() for line in defs.splitlines()]
            entries = [entry for entry in entries if entry and entry[0] == "UID_MIN"]
            valid = len(entries) == 1 and len(entries[0]) == 2 and re.fullmatch(r"[0-9]+", entries[0][1])
            uid_min = int(entries[0][1]) if valid else None
            if uid_min is not None and not 1 <= uid_min < 2**32 - 1:
                uid_min = None
        except OSError:
            uid_min = None
        if uid_min is None:
            findings.append(unavailable("ACCT-003", "accounts", "Interactive system accounts", "UID_MIN could not be established from /etc/login.defs"))
        else:
            interactive = [name for name, uid, _, shell in users if 0 < uid < uid_min and shell not in
                           ("/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false")]
            findings.append(Finding("ACCT-003", "accounts", "Interactive system accounts",
                                    "WARN" if interactive else "PASS", "medium",
                                    f"UID_MIN={uid_min}; system accounts with interactive shells: " + (", ".join(interactive) or "none"),
                                    "Review whether service accounts require interactive shells; coordinate changes with service owners."))
    except (OSError, ValueError) as exc:
        findings.append(unavailable("ACCT-001", "accounts", "Local account inventory", exc))
    try:
        groups = []
        for line in ctx.read("/etc/group").splitlines():
            fields = line.split(":")
            if len(fields) == 4 and fields[0] in ("sudo", "wheel", "docker", "lxd", "incus-admin"):
                groups.append(f"{fields[0]}: {fields[3] or '(no supplementary members)'}")
        findings.append(Finding("ACCT-004", "accounts", "Privileged group membership", "INFO", "info",
                                "; ".join(groups) or "No selected administrative groups found.",
                                "Review primary and supplementary group assignments; membership alone does not prove misuse. Container-management groups can grant extensive host access."))
    except OSError as exc:
        findings.append(unavailable("ACCT-004", "accounts", "Privileged group membership", exc))
    try:
        paths = ["/etc/sudoers"] + [p for p in ctx.glob("/etc/sudoers.d/*") if "." not in p.rsplit("/", 1)[-1] and not p.endswith("~")]
        nopasswd, broad, custom_include = [], [], False
        for path in paths:
            for number, line in enumerate(ctx.read(path).splitlines(), 1):
                # Include paths are not assumed covered by the conventional directory.
                clean = line.strip()
                if clean.startswith(("#include", "@include")):
                    custom_include = True
                if not clean or clean.startswith(("#", "@")):
                    continue
                # Conventional inline comments are not policy tokens. This
                # remains an inventory, not a complete sudoers grammar parser.
                clean = re.split(r"\s+#(?!\d)", clean, maxsplit=1)[0]
                if re.search(r"\bNOPASSWD\s*:", clean):
                    nopasswd.append(f"{path}:{number}")
                if re.search(r"=\s*\([^)]*ALL[^)]*\).*\bALL\s*(?:#.*)?$", clean) and clean.split()[0] != "root":
                    broad.append(f"{path}:{number}")
        findings.append(Finding("ACCT-005", "accounts", "Passwordless sudo rule review",
                                "WARN" if nopasswd else "INFO", "medium",
                                "NOPASSWD rule locations: " + (", ".join(nopasswd) or "none in conventional sudoers files")
                                + ". Text inventory does not resolve aliases, rule order, or arbitrary includes.",
                                "Review command scope and business need for each passwordless rule; validate effective privileges with sudo tooling."))
        findings.append(Finding("ACCT-006", "accounts", "Broad sudo rule inventory", "INFO", "info",
                                "Potential broad rules: " + (", ".join(broad) or "none matched")
                                + f". Include directives present: {custom_include}; this is not an effective privilege calculation.",
                                "Review effective per-user sudo permissions, aliases, and included policy files."))
    except FileNotFoundError as exc:
        findings.append(unavailable("ACCT-005", "accounts", "Sudo policy inventory", exc,
                                    "Confirm whether sudo is installed or an alternative privilege manager is used."))
    except OSError as exc:
        findings.append(unavailable("ACCT-005", "accounts", "Sudo policy inventory", exc))
    return findings
