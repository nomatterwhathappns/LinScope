"""Inventory sudo's evaluated listing for explicit local account contexts.

Only `sudo -n -ll -U USER` is used: noninteractive listing, never execution of a
permitted command or elevation of a task. The output is summarized without raw
commands, which may contain sensitive arguments. This is not a shell-escape or
all-command privilege-escalation analysis. Backend policy lookups may occur in
sudo itself; unavailable or unrecognized policy evidence stays UNKNOWN.
"""
from __future__ import annotations

from hashlib import sha256
import os
import pwd
import re

from linscope.core import Finding, unavailable

MAX_USERS = 20
_USER = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}\$?")


def _id(user, number):
    return f"SUDO-{sha256(user.encode()).hexdigest()[:12].upper()}-{number:03d}"


def _entries(text):
    """Parse the verbose listing shape, rejecting unknown entry structures."""
    result, current, in_commands = [], None, False
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line == "Sudoers entry:":
            if current is not None:
                result.append(current)
            current, in_commands = {}, False
            continue
        if current is None:
            # Defaults/policy headers are not evidence of an executable grant.
            continue
        matched = re.fullmatch(r"(RunAsUsers|RunAsGroups|Options|Commands|Cwd|Chroot):\s*(.*)", line)
        if matched:
            key, value = matched.groups()
            if key in current:
                raise ValueError("Duplicate sudo entry field")
            current[key] = [] if key == "Commands" else value
            in_commands = key == "Commands"
            if key == "Commands" and value:
                current[key].append(value)
            continue
        if in_commands and raw[:1].isspace():
            current["Commands"].append(line)
        else:
            raise ValueError("Unrecognized verbose sudo entry")
    if current is not None:
        result.append(current)
    if not result:
        raise ValueError("No recognizable verbose sudo policy entries")
    for entry in result:
        if not entry.get("RunAsUsers") or not entry.get("Commands"):
            raise ValueError("Incomplete verbose sudo entry")
    return result


def _root_hint(runas):
    result = None
    for token in runas.split(","):
        token = token.strip()
        if token in {"ALL", "root", "#0"}:
            result = True
        elif token in {"!ALL", "!root", "!#0"}:
            result = False
        elif re.fullmatch(r"[A-Z_][A-Z0-9_]*", token):
            result = None  # Unexpanded aliases require separate review.
    return result


def _authentication(options):
    state = None
    for option in options.split(","):
        if option.strip() == "!authenticate":
            state = False
        elif option.strip() == "authenticate":
            state = True
    return state


def _no_privileges(user, text):
    if "Sudoers entry:" in text or re.search(r"(?:a password is required|unable to initialize|policy plugin error)", text, re.I):
        return False
    patterns = [
        rf"(?:User|user) {re.escape(user)} is not allowed to run sudo on [^\n]+\.?",
        rf"Sorry, user {re.escape(user)} may not run sudo on [^\n]+\.?",
        rf"(?:sudo:\s*)?{re.escape(user)} is not in the sudoers file\..*",
    ]
    return any(re.fullmatch(pattern, line.strip()) for pattern in patterns for line in text.splitlines())


def run(ctx):
    selected = getattr(ctx, "sudo_users", [])
    try:
        if not isinstance(selected, list) or len(selected) > MAX_USERS:
            raise ValueError("Sudo account selection must be a list of at most 20 local names")
        users = selected or [pwd.getpwuid(os.getuid()).pw_name]
        if any(not isinstance(user, str) or not _USER.fullmatch(user) for user in users):
            raise ValueError("Unsupported local sudo account name")
        users = sorted(set(users))
    except (ValueError, KeyError, OSError) as exc:
        return [unavailable("SUDO-000", "sudo", "Sudo evaluation scope", str(exc))]
    results = []
    for user in users:
        command = ctx.command(["sudo", "-n", "-ll", "-U", user])
        title = f"Effective sudo policy listing: {user}"
        if not command.ok:
            if not command.error and _no_privileges(user, command.stdout + "\n" + command.stderr):
                results.append(Finding(_id(user, 1), "sudo", title, "INFO", "info",
                                       f"Sudo explicitly reports that {user} may not run sudo under the evaluated policy.",
                                       "This does not exclude privileges via other tools, groups, or another policy context."))
            else:
                results.append(unavailable(_id(user, 1), "sudo", title,
                                           command.error or "Noninteractive sudo listing was unavailable; password prompts, denied listing access, and policy errors do not prove absence of privileges."))
            continue
        try:
            entries = _entries(command.stdout)
        except ValueError as exc:
            results.append(unavailable(_id(user, 1), "sudo", title, str(exc)))
            continue
        command_lines = sum(len(entry["Commands"]) for entry in entries)
        results.append(Finding(_id(user, 1), "sudo", title, "INFO", "info",
                               f"Evaluated account={user}; entries={len(entries)}, command records={command_lines}. Raw command contents are omitted.",
                               "Review the effective sudo listing in the intended environment; this inventory does not execute any granted command."))
        passwordless = [entry for entry in entries if _authentication(entry.get("Options", "")) is False]
        root_passwordless = sum(_root_hint(entry["RunAsUsers"]) is True for entry in passwordless)
        results.append(Finding(_id(user, 2), "sudo", f"Effective passwordless sudo review: {user}",
                               "WARN" if passwordless else "INFO", "high" if root_passwordless else "medium" if passwordless else "info",
                               f"Entries explicitly reporting !authenticate={len(passwordless)}; explicit root/ALL run-as hints={root_passwordless}. "
                               "No matching tag does not prove authentication is required; defaults, exemptions, ordering, and command context need review.",
                               "Review accepted passwordless grants and permitted command behavior. Listing does not test authentication or exploitability."))
        broad = []
        for entry in entries:
            if any(re.search(r"(?:^|,)\s*ALL\s*(?:,|$)", line) for line in entry["Commands"]):
                broad.append(entry)
        root_broad = sum(_root_hint(entry["RunAsUsers"]) is True for entry in broad)
        results.append(Finding(_id(user, 3), "sudo", f"Effective broad-command sudo review: {user}",
                               "WARN" if broad else "INFO", "high" if root_broad else "medium" if broad else "info",
                               f"Entries containing an ALL command grant={len(broad)}; explicit root/ALL run-as hints={root_broad}. "
                               "Negations and ordering may restrict grants; non-ALL commands can also convey extensive privileges.",
                               "Review broad grants, exclusions, run-as identities and command capabilities. This is not a complete privilege-escalation verdict."))
    return results
