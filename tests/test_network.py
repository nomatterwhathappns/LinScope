import json
import unittest

from linscope.core import CommandResult
from linscope.checks import network


class FakeContext:
    def __init__(self, commands=None, profile="server"):
        self.commands = commands or {}
        self.profile = profile

    def command(self, args):
        value = self.commands.get(tuple(args))
        if value is None:
            return CommandResult(tuple(args), None, error="command unavailable")
        if isinstance(value, CommandResult):
            return value
        return CommandResult(tuple(args), 0, value)


def commands():
    return {
        ("ss", "-H", "-lntu"): "tcp LISTEN 0 128 127.0.0.1:5432 0.0.0.0:*\ntcp LISTEN 0 128 [::]:22 [::]:*\nudp UNCONN 0 0 0.0.0.0:53 0.0.0.0:*\n",
        ("ufw", "status", "verbose"): "Status: inactive\n",
        ("nft", "-j", "list", "ruleset"): json.dumps({"nftables": []}),
        ("iptables", "-S"): "-P INPUT DROP\n-P FORWARD DROP\n-P OUTPUT ACCEPT\n",
        ("ip6tables", "-S"): "-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n",
    }


class NetworkTests(unittest.TestCase):
    def check(self, values=None, profile="server"):
        return {item.id: item for item in network.run(FakeContext(commands() if values is None else values, profile))}

    def test_listener_scope_and_inventory(self):
        findings = self.check()
        self.assertEqual(findings["NETWORK-001"].status, "INFO")
        self.assertIn("3 listener rows", findings["NETWORK-001"].evidence)
        self.assertIn("2 listener rows", findings["NETWORK-002"].evidence)
        self.assertIn("does not prove", findings["NETWORK-002"].evidence)

    def test_ipv6_and_scoped_addresses(self):
        rows = network._parse_listeners("tcp LISTEN 0 1 [::1]:22 [::]:*\nudp UNCONN 0 1 [fe80::1%eth0]:53 [::]:*\n")
        self.assertEqual(rows[0][3], "loopback")
        self.assertEqual(rows[1][3], "non-loopback")

    def test_plaintext_port_hints_are_not_vulnerability_claims(self):
        values = commands()
        values[("ss", "-H", "-lntu")] = "tcp LISTEN 0 10 0.0.0.0:21 0.0.0.0:*\n"
        result = self.check(values)["NETWORK-003"]
        self.assertEqual(result.status, "WARN")
        self.assertIn("not identified", result.evidence)

    def test_loopback_plaintext_hint_does_not_flag_external_binding(self):
        values = commands()
        values[("ss", "-H", "-lntu")] = "tcp LISTEN 0 10 127.0.0.1:23 0.0.0.0:*\n"
        self.assertEqual(self.check(values)["NETWORK-003"].status, "PASS")

    def test_unavailable_or_malformed_ss_never_passes(self):
        for output in ("garbage", "tcp LISTEN 0 1 malformed 0.0.0.0:*", "tcp LISTEN 0 1 0.0.0.0:99999 0.0.0.0:*"):
            values = commands()
            values[("ss", "-H", "-lntu")] = output
            findings = self.check(values)
            self.assertEqual(findings["NETWORK-001"].status, "UNKNOWN")
            self.assertEqual(findings["NETWORK-003"].status, "UNKNOWN")

    def test_ipv4_and_ipv6_are_evaluated_separately(self):
        findings = self.check()
        self.assertEqual(findings["NETWORK-005"].status, "PASS")
        self.assertEqual(findings["NETWORK-006"].status, "WARN")

    def test_inactive_ufw_does_not_mean_absent_firewall(self):
        findings = self.check()
        self.assertEqual(findings["NETWORK-004"].status, "INFO")
        self.assertEqual(findings["NETWORK-005"].status, "PASS")

    def test_nft_inet_default_drop_applies_to_both_families(self):
        values = commands()
        values[("nft", "-j", "list", "ruleset")] = json.dumps({"nftables": [{"chain": {
            "family": "inet", "table": "filter", "name": "custom", "hook": "input", "policy": "drop"}}]})
        findings = self.check(values)
        self.assertEqual(findings["NETWORK-005"].status, "PASS")
        self.assertEqual(findings["NETWORK-006"].status, "PASS")

    def test_nft_forward_policy_does_not_substitute_for_input_policy(self):
        values = commands()
        values[("iptables", "-S")] = "-P INPUT ACCEPT\n"
        values[("nft", "-j", "list", "ruleset")] = json.dumps({"nftables": [{"chain": {
            "family": "inet", "hook": "forward", "policy": "drop"}}]})
        self.assertEqual(self.check(values)["NETWORK-005"].status, "WARN")

    def test_malformed_nft_does_not_crash_or_hide_working_iptables(self):
        values = commands()
        values[("nft", "-j", "list", "ruleset")] = "not json"
        self.assertEqual(self.check(values)["NETWORK-005"].status, "PASS")

    def test_missing_all_collectors_is_unknown(self):
        self.assertTrue(all(item.status == "UNKNOWN" for item in self.check({}).values()))

    def test_container_accept_policy_is_contextual_inventory(self):
        self.assertEqual(self.check(profile="container")["NETWORK-006"].status, "INFO")

    def test_malformed_input_policy_is_unknown(self):
        values = commands()
        values[("iptables", "-S")] = "-P INPUT NOT_A_POLICY\n"
        self.assertEqual(self.check(values)["NETWORK-005"].status, "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
