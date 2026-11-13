"""Evaluate OpenSSH's effective default configuration, not ad-hoc text parsing.

sshd -T does not establish the live daemon's startup flags or every Match
context. The scope finding makes this limitation explicit.
"""
from linscope.core import Finding, unavailable


def run(ctx):
    category = "ssh"
    try:
        main = ctx.read("/etc/ssh/sshd_config")
    except FileNotFoundError:
        return [Finding("SSH-000", category, "Default SSH server configuration", "SKIP", "info",
                        "/etc/ssh/sshd_config is absent; custom-path SSH daemons are not evaluated.",
                        "If SSH uses a custom configuration, inspect that daemon separately.")]
    except OSError as exc:
        return [unavailable("SSH-000", category, "SSH configuration access", exc)]
    result = ctx.command(["sshd", "-T"])
    if not result.ok:
        return [unavailable("SSH-000", category, "Effective SSH configuration",
                            result.error or result.stderr.strip() or f"sshd -T exited {result.returncode}",
                            "Check sshd configuration validity and read permissions. LinScope does not elevate privileges.")]
    settings = {}
    for line in result.stdout.splitlines():
        fields = line.split(None, 1)
        if len(fields) == 2:
            settings[fields[0].lower()] = fields[1].strip().lower()
    specs = [
        ("SSH-001", "Root SSH login", "permitrootlogin", {"no"}, "high",
         "Prefer named accounts with controlled sudo access; verify recovery access before restricting root login."),
        ("SSH-002", "SSH password authentication", "passwordauthentication", {"no"}, "medium",
         "For a key-only baseline, verify working key access before disabling password authentication; review PAM/MFA separately."),
        ("SSH-003", "Empty SSH passwords", "permitemptypasswords", {"no"}, "high",
         "Keep PermitEmptyPasswords disabled and review account authentication policy."),
        ("SSH-004", "SSH public-key authentication", "pubkeyauthentication", {"yes"}, "low",
         "Enable public-key authentication if adopting the key-based baseline; consider the intended authentication design."),
        ("SSH-006", "SSH X11 forwarding", "x11forwarding", {"no"}, "low",
         "Disable X11 forwarding on servers that do not need it; document legitimate desktop use."),
        ("SSH-007", "SSH forwarded-port bind scope", "gatewayports", {"no"}, "medium",
         "Prefer GatewayPorts no unless non-loopback remote forwarding is explicitly required."),
    ]
    findings = []
    for check_id, title, key, expected, severity, recommendation in specs:
        value = settings.get(key)
        status = "UNKNOWN" if value is None else ("PASS" if value in expected else "WARN")
        if key == "x11forwarding" and ctx.profile == "desktop" and value == "yes":
            status = "INFO"
        findings.append(Finding(check_id, category, title, status, severity,
                                f"sshd -T default context: {key}={value or 'not reported'}.", recommendation))
    raw = settings.get("maxauthtries")
    try:
        tries = int(raw)
        status = "PASS" if 1 <= tries <= 4 else "WARN"
    except (TypeError, ValueError):
        status = "UNKNOWN"
    findings.append(Finding("SSH-005", category, "SSH authentication attempt limit", status, "low",
                            f"sshd -T default context: maxauthtries={raw or 'not reported'}.",
                            "Consider MaxAuthTries 4 or less, accounting for clients offering multiple keys."))
    match = any(line.strip().lower().startswith("match ") for line in main.splitlines())
    findings.append(Finding("SSH-008", category, "SSH evaluation scope", "INFO", "info",
                            "sshd -T expands Includes for the default context. "
                            + ("Main file contains Match blocks. " if match else "")
                            + "Connection-specific Match blocks (including included files), alternate config paths, and live daemon flags are not verified.",
                            "Use sshd -T -C with relevant user/host/address contexts and inspect the running daemon's launch configuration separately."))
    return findings
