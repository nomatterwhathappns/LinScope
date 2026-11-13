"""Socket and firewall snapshots, without remote probes or reachability claims.

Listening addresses are not proof of Internet exposure. Firewall checks inspect
base INPUT policies only; they do not simulate rule ordering, routing, namespaces,
container orchestration, or controls outside the host. Port-based protocol labels
are review hints, never protocol identification.
"""
from __future__ import annotations

import ipaddress
import json

from linscope.core import Context, Finding, unavailable

CATEGORY = "network"


def _finding(number, title, status, severity, evidence, recommendation):
    return Finding(f"NETWORK-{number:03d}", CATEGORY, title, status, severity,
                   evidence, recommendation)


def _parse_listeners(text):
    sockets = []
    for line in text.splitlines():
        fields = line.split()
        if not fields:
            continue
        if len(fields) < 6 or fields[0] not in {"tcp", "udp"}:
            raise ValueError("Unexpected ss output format")
        endpoint = fields[4]
        address, separator, port = endpoint.rpartition(":")
        if not separator or not port.isdigit() or not 0 <= int(port) <= 65535:
            raise ValueError("Unexpected local listener endpoint")
        address = address.strip("[]")
        numeric = address.split("%", 1)[0]
        if numeric == "*":
            scope = "wildcard"
        else:
            parsed = ipaddress.ip_address(numeric)
            scope = "loopback" if parsed.is_loopback else "wildcard" if parsed.is_unspecified else "non-loopback"
        sockets.append((fields[0], address, int(port), scope))
    return sockets


def _listeners(ctx):
    titles = [(1, "TCP/UDP listener inventory"), (2, "Non-loopback bindings review"),
              (3, "Ports commonly associated with plaintext services")]
    result = ctx.command(["ss", "-H", "-lntu"])
    if not result.ok:
        return [unavailable(f"NETWORK-{i:03d}", CATEGORY, title,
                            result.error or "ss could not collect listener information.") for i, title in titles]
    try:
        sockets = _parse_listeners(result.stdout)
    except ValueError as exc:
        return [unavailable(f"NETWORK-{i:03d}", CATEGORY, title, exc) for i, title in titles]
    summary = sorted({f"{proto} {address}:{port} ({scope})" for proto, address, port, scope in sockets})
    outside_loopback = [row for row in sockets if row[3] != "loopback"]
    risky = sorted({f"{proto}/{port}" for proto, _, port, scope in sockets
                    if scope != "loopback" and ((proto == "tcp" and port in {21, 23, 512, 513, 514}) or
                                                (proto == "udp" and port == 69))})
    return [
        _finding(1, titles[0][1], "INFO", "info",
                 f"{len(sockets)} listener rows. " + ("; ".join(summary[:50]) or "No listeners in this snapshot.") +
                 (" Additional rows omitted from display." if len(summary) > 50 else ""),
                 "Compare listeners with the intended service inventory. Snapshot covers only the current network namespace."),
        _finding(2, titles[1][1], "INFO", "info",
                 f"{len(outside_loopback)} listener rows bind wildcard or non-loopback addresses. This does not prove remote or Internet reachability.",
                 "Confirm intended interfaces and firewall policy; bind internal-only services to appropriate local/private interfaces."),
        _finding(3, titles[2][1], "WARN" if risky else "PASS", "medium",
                 "Non-loopback port hints: " + ", ".join(risky) + ". Actual protocols/encryption were not identified." if risky else
                 "No non-loopback listeners matched the small plaintext-service port hint list.",
                 "Identify the actual service and verify encryption requirements. Port numbers alone cannot establish protocol or security.")
    ]


def _ufw(ctx):
    result = ctx.command(["ufw", "status", "verbose"])
    if not result.ok:
        return unavailable("NETWORK-004", CATEGORY, "UFW manager state",
                           result.error or "UFW state unavailable; this does not establish whether other firewall controls exist.")
    lines = [line.strip() for line in result.stdout.splitlines()]
    state = next((line for line in lines if line in {"Status: active", "Status: inactive"}), None)
    if state is None:
        return unavailable("NETWORK-004", CATEGORY, "UFW manager state", "Unrecognized UFW status output.")
    return _finding(4, "UFW manager state", "INFO", "info", state + ". Other firewall backends are assessed separately.",
                    "Use a consistent firewall management approach; inactive UFW does not imply that the host has no firewall.")


def _nft_policies(ctx):
    result = ctx.command(["nft", "-j", "list", "ruleset"])
    if not result.ok:
        return None, result.error or "nft ruleset could not be inspected."
    try:
        body = json.loads(result.stdout)
        objects = body["nftables"]
        if not isinstance(objects, list):
            raise ValueError("Invalid nftables object list")
        policies = []
        for item in objects:
            if not isinstance(item, dict):
                raise ValueError("Invalid nftables entry")
            chain = item.get("chain")
            if chain is None:
                continue
            if not isinstance(chain, dict):
                raise ValueError("Invalid nftables chain")
            if chain.get("hook") == "input":
                if chain.get("family") not in {"inet", "ip", "ip6", "bridge", "arp", "netdev"}:
                    raise ValueError("Unknown nftables chain family")
                if chain.get("policy") not in {"accept", "drop"}:
                    raise ValueError("Missing or unknown nftables input-chain policy")
                policies.append((chain["family"], chain["policy"]))
        return policies, ""
    except (ValueError, TypeError, KeyError) as exc:
        return None, f"Cannot parse nftables ruleset: {exc}"


def _family_policy(ctx, family, nft_policies, nft_error):
    number, tool, nft_family = (5, "iptables", "ip") if family == "IPv4" else (6, "ip6tables", "ip6")
    title = f"{family} host INPUT default-policy review"
    applicable = [] if nft_policies is None else [policy for nft_fam, policy in nft_policies
                                                 if nft_fam in {"inet", nft_family}]
    # Still inspect iptables: legacy and nft backends may coexist.
    result = ctx.command([tool, "-S"])
    legacy = None
    if result.ok:
        for line in result.stdout.splitlines():
            fields = line.split()
            if fields[:2] == ["-P", "INPUT"]:
                if len(fields) != 3 or fields[2] not in {"ACCEPT", "DROP"} or legacy is not None:
                    return unavailable(f"NETWORK-{number:03d}", CATEGORY, title,
                                       "Ambiguous or malformed iptables INPUT policy.")
                legacy = fields[2].lower()
        if legacy is None:
            return unavailable(f"NETWORK-{number:03d}", CATEGORY, title,
                               "Successful iptables query did not include a recognizable INPUT policy.")
    observed = applicable + ([legacy] if legacy else [])
    if "drop" in observed:
        return _finding(number, title, "PASS", "medium",
                        f"At least one inspected {family} base INPUT chain has a default drop policy. nft={applicable}; {tool}={legacy or 'unavailable'}.",
                        "Review complete rules and required exceptions. This check does not prove effective isolation or assess external firewalls.")
    if observed:
        return _finding(number, title, "INFO" if ctx.profile == "container" else "WARN", "medium",
                        f"Inspected {family} INPUT defaults are accept. Explicit deny rules or external controls may still restrict access.",
                        "Review full rule ordering and required access; use a restrictive host baseline where appropriate. Container host policy may be outside this namespace.")
    details = nft_error or "No applicable nft input base chain was observed."
    return unavailable(f"NETWORK-{number:03d}", CATEGORY, title,
                       details + " " + (result.error or f"{tool} INPUT policy unavailable."))


def run(ctx: Context):
    nft_policies, nft_error = _nft_policies(ctx)
    return _listeners(ctx) + [_ufw(ctx), _family_policy(ctx, "IPv4", nft_policies, nft_error),
                              _family_policy(ctx, "IPv6", nft_policies, nft_error)]
