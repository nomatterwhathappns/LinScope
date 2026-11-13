"""Inspect live sysctls, not merely files that may never have been applied.

These checks describe the current namespace. They do not prove host-wide state
from a container or establish that a kernel is free of vulnerabilities.
"""
from __future__ import annotations

from linscope.core import Finding, unavailable


def _values(ctx, check_id, title, paths, acceptable, expected, recommendation):
    observed = {}
    for path in paths:
        try:
            raw = ctx.read(path).strip()
            value = int(raw)
        except (OSError, ValueError) as exc:
            return unavailable(check_id, "kernel", title,
                               f"Cannot evaluate {path}: {exc}")
        observed[path.removeprefix("/proc/sys/").replace("/", ".")] = value
    evidence = "; ".join(f"{name}={value}" for name, value in observed.items())
    if ctx.profile == "container":
        evidence += "; values describe the accessible namespace, not necessarily the host"
    good = all(acceptable(value) for value in observed.values())
    return Finding(check_id, "kernel", title, "PASS" if good else "WARN", "medium",
                   evidence + f"; expected {expected}", recommendation)


def run(ctx):
    findings = []
    forwarding = 1 if ctx.profile == "router" else 0
    findings.append(_values(
        ctx, "KERNEL-001", "IPv4 packet forwarding",
        ["/proc/sys/net/ipv4/ip_forward"], lambda v: v == forwarding,
        str(forwarding) + f" for profile {ctx.profile}",
        "Keep forwarding disabled unless this system routes traffic. Use the router profile "
        "when routing is intended, and review forwarding firewall rules separately."))
    checks = [
        ("KERNEL-002", "IPv4 ICMP redirect acceptance (all/default)",
         ["/proc/sys/net/ipv4/conf/all/accept_redirects",
          "/proc/sys/net/ipv4/conf/default/accept_redirects"], lambda v: v == 0, "0",
         "Disable ICMP redirect acceptance for all/default interfaces unless explicitly needed. "
         "Review existing interface-specific settings too."),
        ("KERNEL-003", "IPv4 ICMP redirect sending (all/default)",
         ["/proc/sys/net/ipv4/conf/all/send_redirects",
          "/proc/sys/net/ipv4/conf/default/send_redirects"], lambda v: v == 0, "0",
         "Review whether redirect sending is needed; normally disable it, including on routers "
         "that do not rely on ICMP redirects. Check interface-specific settings."),
        ("KERNEL-004", "IPv6 ICMP redirect acceptance (all/default)",
         ["/proc/sys/net/ipv6/conf/all/accept_redirects",
          "/proc/sys/net/ipv6/conf/default/accept_redirects"], lambda v: v == 0, "0",
         "Disable IPv6 ICMP redirect acceptance unless required by the network design. "
         "Missing IPv6 sysctls require review rather than proving IPv6 is disabled."),
        ("KERNEL-005", "Address-space layout randomization",
         ["/proc/sys/kernel/randomize_va_space"], lambda v: v == 2, "2",
         "Use full ASLR (randomize_va_space=2) after checking compatibility. "
         "Individual applications may still disable or lack ASLR support."),
        ("KERNEL-006", "Kernel log access restriction",
         ["/proc/sys/kernel/dmesg_restrict"], lambda v: v == 1, "1",
         "Restrict unprivileged kernel log access with kernel.dmesg_restrict=1."),
        ("KERNEL-007", "Kernel pointer exposure restriction",
         ["/proc/sys/kernel/kptr_restrict"], lambda v: v in (1, 2), "1 or 2",
         "Restrict kernel pointer exposure with kernel.kptr_restrict=1 or 2; "
         "choose the value appropriate for debugging requirements."),
        ("KERNEL-008", "Protected symlinks and hardlinks",
         ["/proc/sys/fs/protected_symlinks", "/proc/sys/fs/protected_hardlinks"],
         lambda v: v == 1, "1",
         "Enable fs.protected_symlinks and fs.protected_hardlinks to limit unsafe "
         "link-following behavior in shared locations."),
        ("KERNEL-009", "Unprivileged ptrace restriction",
         ["/proc/sys/kernel/yama/ptrace_scope"], lambda v: v in (1, 2, 3), "1, 2, or 3",
         "Review kernel.yama.ptrace_scope and application debugging needs. "
         "Values 1 through 3 apply progressively stronger restrictions; 3 cannot be lowered until reboot."),
    ]
    for check_id, title, paths, acceptable, expected, recommendation in checks:
        findings.append(_values(ctx, check_id, title, paths, acceptable, expected, recommendation))
    return findings
