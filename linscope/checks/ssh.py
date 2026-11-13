"""Review default and explicitly selected OpenSSH connection contexts.

Only sshd's effective output is evaluated. Explicit connection contexts exercise
Match blocks via ``sshd -T -C``; they do not cover every possible connection or
establish the running daemon's alternate configuration path/startup flags.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re

from linscope.core import Finding, unavailable

_USER = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]*\$?", re.ASCII)
_HOST = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,252}", re.ASCII)
_ROOT_VALUES = {"no", "yes", "prohibit-password", "without-password", "forced-commands-only"}
_MONITORED = {"permitrootlogin", "passwordauthentication", "permitemptypasswords",
              "pubkeyauthentication", "maxauthtries", "x11forwarding", "gatewayports"}


def normalize_connection_context(value):
    """Validate a finite sshd -C parameter set without accepting arbitrary options."""
    if not isinstance(value, dict) or not {"user", "addr", "host"} <= set(value) or set(value) - {"user", "addr", "host", "laddr", "lport"}:
        raise ValueError("SSH context requires user, addr and host; optional keys are laddr and lport")
    if not isinstance(value["user"], str) or len(value["user"]) > 256 or not _USER.fullmatch(value["user"]):
        raise ValueError("SSH context user must be a simple local account name")
    if not isinstance(value["host"], str) or not _HOST.fullmatch(value["host"]):
        raise ValueError("SSH context host must be a nonempty hostname or numeric address without separators")
    normalized = {"user": value["user"], "host": value["host"].lower()}
    for key in ("addr", "laddr"):
        if key in value:
            if not isinstance(value[key], str) or "%" in value[key]:
                raise ValueError(f"SSH context {key} must be an unscoped IP address")
            try:
                normalized[key] = str(ipaddress.ip_address(value[key]))
            except ValueError as exc:
                raise ValueError(f"SSH context {key} must be an IP address") from exc
    if "lport" in value:
        if type(value["lport"]) is not int or not 1 <= value["lport"] <= 65535:
            raise ValueError("SSH context lport must be an integer in 1..65535")
        normalized["lport"] = value["lport"]
    return normalized


def connection_context_id(value):
    """An order-independent stable target prefix suitable for policy exceptions."""
    canonical = json.dumps(normalize_connection_context(value), sort_keys=True, separators=(",", ":"))
    return "SSHCTX-" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:12].upper()


def _parse_settings(output):
    settings = {}
    for line in output.splitlines():
        if not line.strip():
            continue
        fields = line.split(None, 1)
        if len(fields) != 2 or not re.fullmatch(r"[a-z][a-z0-9]*", fields[0], re.ASCII):
            raise ValueError("Malformed sshd effective-configuration output")
        key, value = fields[0], fields[1].strip().lower()
        # Repeated hostkey/listenaddress/acceptenv rows are legitimate. A
        # monitored scalar appearing twice is ambiguous, not last-one-wins.
        if key in _MONITORED:
            if key in settings or not value:
                raise ValueError(f"Ambiguous or empty sshd scalar: {key}")
            settings[key] = value
    return settings


def _root_alias(value):
    return "prohibit-password" if value == "without-password" else value


def _baseline(ctx):
    raw = getattr(ctx, "baseline", {})
    if not isinstance(raw, dict):
        raise ValueError("Baseline must be an object")
    root = raw.get("SSH-001", {"allowed": ["no"]})
    attempts = raw.get("SSH-005", {"max_attempts": 4})
    if (not isinstance(root, dict) or set(root) != {"allowed"}
            or not isinstance(root["allowed"], list) or not root["allowed"]
            or any(not isinstance(v, str) or v not in _ROOT_VALUES for v in root["allowed"])):
        raise ValueError("SSH-001 baseline requires a nonempty list of valid allowed root-login modes")
    if (not isinstance(attempts, dict) or set(attempts) != {"max_attempts"}
            or type(attempts["max_attempts"]) is not int or not 1 <= attempts["max_attempts"] <= 100):
        raise ValueError("SSH-005 max_attempts must be an integer in 1..100")
    return {_root_alias(v) for v in root["allowed"]}, attempts["max_attempts"]


def _evaluate(settings, ctx, prefix, label, baseline):
    root_allowed, max_attempts = baseline
    specs = [
        ("001", "Root SSH login", "permitrootlogin", root_allowed,
         {_root_alias(v) for v in _ROOT_VALUES}, "high",
         "Prefer named accounts with controlled sudo access; verify recovery access before restricting root login."),
        ("002", "SSH password authentication", "passwordauthentication", {"no"}, {"yes", "no"}, "medium",
         "For a key-only baseline, verify working key access before disabling password authentication; review PAM/MFA separately."),
        ("003", "Empty SSH passwords", "permitemptypasswords", {"no"}, {"yes", "no"}, "high",
         "Keep PermitEmptyPasswords disabled and review account authentication policy."),
        ("004", "SSH public-key authentication", "pubkeyauthentication", {"yes", "host-bound", "unbound"},
         {"yes", "no", "host-bound", "unbound"}, "low",
         "Enable public-key authentication if adopting the key-based baseline; consider the intended authentication design."),
        ("006", "SSH X11 forwarding", "x11forwarding", {"no"}, {"yes", "no"}, "low",
         "Disable X11 forwarding on servers that do not need it; document legitimate desktop use."),
        ("007", "SSH forwarded-port bind scope", "gatewayports", {"no"}, {"yes", "no", "clientspecified"}, "medium",
         "Prefer GatewayPorts no unless non-loopback remote forwarding is explicitly required."),
    ]
    findings = []
    for number, title, key, expected, valid, severity, recommendation in specs:
        value = settings.get(key)
        actual = _root_alias(value) if key == "permitrootlogin" else value
        status = "UNKNOWN" if actual not in valid else ("PASS" if actual in expected else "WARN")
        if key == "x11forwarding" and ctx.profile == "desktop" and value == "yes":
            status = "INFO"
        findings.append(Finding(f"{prefix}-{number}", "ssh", title, status, severity,
                                f"{label}: {key}={value or 'not reported'}; expected={','.join(sorted(expected))}.", recommendation))
    raw = settings.get("maxauthtries")
    if raw is not None and re.fullmatch(r"[0-9]+", raw, re.ASCII) and len(raw) <= 10:
        tries = int(raw)
        status = "UNKNOWN" if tries > 2**31 - 1 else ("PASS" if 1 <= tries <= max_attempts else "WARN")
    else:
        status = "UNKNOWN"
    findings.append(Finding(f"{prefix}-005", "ssh", "SSH authentication attempt limit", status, "low",
                            f"{label}: maxauthtries={raw or 'not reported'}; expected=1..{max_attempts}.",
                            f"Consider MaxAuthTries {max_attempts} or less, accounting for clients offering multiple keys."))
    return findings


def _collect(ctx, command, prefix, label, baseline):
    result = ctx.command(command)
    if not result.ok:
        return [unavailable(f"{prefix}-000", "ssh", "Effective SSH configuration",
                            label + ": " + (result.error or result.stderr.strip() or f"sshd -T exited {result.returncode}"),
                            "Check sshd configuration validity and read permissions. LinScope does not elevate privileges.")]
    try:
        settings = _parse_settings(result.stdout)
    except ValueError as exc:
        return [unavailable(f"{prefix}-000", "ssh", "Effective SSH configuration", label + ": " + str(exc))]
    return _evaluate(settings, ctx, prefix, label, baseline)


def run(ctx):
    try:
        main = ctx.read("/etc/ssh/sshd_config")
    except FileNotFoundError:
        return [Finding("SSH-000", "ssh", "Default SSH server configuration", "SKIP", "info",
                        "/etc/ssh/sshd_config is absent; custom-path SSH daemons are not evaluated.",
                        "If SSH uses a custom configuration, inspect that daemon separately.")]
    except OSError as exc:
        return [unavailable("SSH-000", "ssh", "SSH configuration access", exc)]
    try:
        baseline = _baseline(ctx)
        contexts = getattr(ctx, "ssh_contexts", [])
        if not isinstance(contexts, list) or len(contexts) > 32:
            raise ValueError("SSH contexts must be a list with at most 32 entries")
        normalized = [normalize_connection_context(value) for value in contexts]
    except ValueError as exc:
        return [unavailable("SSH-000", "ssh", "SSH evaluation parameters", exc)]
    findings = _collect(ctx, ["sshd", "-T"], "SSH", "sshd -T default context", baseline)
    seen = set()
    for context in normalized:
        prefix = connection_context_id(context)
        if prefix in seen:
            continue
        seen.add(prefix)
        # Fixed keys and validated values, one argv element: no shell evaluation
        # or user-supplied options can enter the command.
        parameter = ",".join(f"{key}={context[key]}" for key in ("user", "addr", "host", "laddr", "lport") if key in context)
        findings.extend(_collect(ctx, ["sshd", "-T", "-C", parameter], prefix,
                                 "sshd -T connection context " + parameter, baseline))
    match = any(line.strip().lower().startswith("match ") for line in main.splitlines())
    findings.append(Finding("SSH-008", "ssh", "SSH evaluation scope", "INFO", "info",
                            "sshd -T expands Includes for the default context. "
                            + ("Main file contains Match blocks. " if match else "")
                            + f"Explicit connection contexts evaluated: {len(seen)}. "
                            + "Other Match contexts (including included files), alternate config paths, and live daemon flags are not verified.",
                            "Select relevant user/host/address contexts and inspect the running daemon's launch configuration separately."))
    return findings
