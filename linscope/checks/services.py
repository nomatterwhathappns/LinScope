"""systemd service inventory and narrowly scoped legacy-service review.

Inventories do not cover non-systemd supervisors or every activation mechanism.
Named FTP services may support TLS; findings request review, not a vulnerability
claim. A service that is enabled need not currently be running, and vice versa.
"""
from __future__ import annotations

from linscope.core import Context, Finding, unavailable

CATEGORY = "services"
LEGACY = {"telnet", "telnetd", "inetutils-telnetd", "rsh", "rsh-server", "rlogin",
          "rexec", "vsftpd", "proftpd", "pure-ftpd", "tftp", "tftpd", "tftpd-hpa"}


def _finding(number, title, status, severity, evidence, recommendation):
    return Finding(f"SERVICES-{number:03d}", CATEGORY, title, status, severity,
                   evidence, recommendation)


def _units(text, suffix, mode):
    units = set()
    for line in text.splitlines():
        fields = line.split()
        if not fields:
            continue
        if fields[0] == "●":
            fields = fields[1:]
        if not fields or not fields[0].endswith(suffix):
            raise ValueError("Unrecognized systemd unit listing")
        if mode == "files":
            if len(fields) < 2 or fields[1] not in {"enabled", "enabled-runtime"}:
                raise ValueError("Unrecognized enabled unit state")
        elif len(fields) < 4:
            raise ValueError("Incomplete systemd unit listing")
        units.add(fields[0])
    return units


def _collect(ctx, argv, suffix, mode):
    result = ctx.command(argv)
    if not result.ok:
        return None, result.error or "systemd query failed; systemd may not manage this host."
    try:
        units = _units(result.stdout, suffix, mode)
        if mode == "units":
            requested = next((arg.partition("=")[2] for arg in argv if arg.startswith("--state=")), None)
            for line in result.stdout.splitlines():
                fields = line.split()
                if fields and fields[0] == "●":
                    fields = fields[1:]
                if fields and requested not in fields[2:4]:
                    raise ValueError("Unit state contradicts requested systemd inventory")
        return units, ""
    except ValueError as exc:
        return None, str(exc)


def _summarize(units):
    names = sorted(units)
    return ", ".join(names[:50]) + ("; additional names omitted" if len(names) > 50 else "")


def run(ctx: Context):
    running, running_error = _collect(ctx, ["systemctl", "list-units", "--type=service", "--state=running",
                                           "--no-legend", "--no-pager", "--plain"], ".service", "units")
    enabled, enabled_error = _collect(ctx, ["systemctl", "list-unit-files", "--type=service",
                                           "--state=enabled,enabled-runtime", "--no-legend", "--no-pager"], ".service", "files")
    sockets, socket_error = _collect(ctx, ["systemctl", "list-units", "--type=socket", "--state=listening",
                                           "--no-legend", "--no-pager", "--plain"], ".socket", "units")
    enabled_sockets, enabled_socket_error = _collect(ctx, ["systemctl", "list-unit-files", "--type=socket",
                                                           "--state=enabled,enabled-runtime", "--no-legend", "--no-pager"], ".socket", "files")
    failed, failed_error = _collect(ctx, ["systemctl", "list-units", "--type=service", "--state=failed",
                                         "--no-legend", "--no-pager", "--plain"], ".service", "units")
    results = []
    for number, title, units, error, meaning in [
        (1, "Running service inventory", running, running_error, "currently running"),
        (2, "Enabled service inventory", enabled, enabled_error, "enabled or runtime-enabled")
    ]:
        if units is None:
            results.append(unavailable(f"SERVICES-{number:03d}", CATEGORY, title, error))
        else:
            results.append(_finding(number, title, "INFO", "info",
                                    f"{len(units)} {meaning} systemd services: " + (_summarize(units) or "none"),
                                    "Review each service against the intended host role. This inventory does not cover all socket, timer, dependency, or non-systemd activation."))
    observed = (running or set()) | (enabled or set()) | (sockets or set()) | (enabled_sockets or set())
    legacy = {name for name in observed if name.rsplit(".", 1)[0].split("@", 1)[0] in LEGACY}
    if legacy:
        results.append(_finding(3, "Legacy remote-service review", "WARN", "medium",
                                "Running/enabled/listening units requiring review: " + _summarize(legacy),
                                "Confirm whether each service is required and encrypted; prefer secure alternatives. Names alone do not prove plaintext traffic or remote exposure."))
    elif any(units is None for units in (running, enabled, sockets, enabled_sockets)):
        results.append(unavailable("SERVICES-003", CATEGORY, "Legacy remote-service review",
                                   "No matches in available data, but service/socket inventory is incomplete. " +
                                   "; ".join(error for error in (running_error, enabled_error, socket_error, enabled_socket_error) if error)))
    else:
        results.append(_finding(3, "Legacy remote-service review", "PASS", "medium",
                                "No matches in the limited legacy-unit name list among inspected systemd service/socket inventories.",
                                "Review custom services and other supervisors separately; this is not protocol detection."))
    if failed is None:
        results.append(unavailable("SERVICES-004", CATEGORY, "Failed service inventory", failed_error))
    else:
        results.append(_finding(4, "Failed service inventory", "WARN" if failed else "PASS", "low",
                                f"{len(failed)} failed systemd services: " + (_summarize(failed) or "none"),
                                "Investigate failed units, especially security and logging controls; do not assume every failure is a security incident."))
    return results
