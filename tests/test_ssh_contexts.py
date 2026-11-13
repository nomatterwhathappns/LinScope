"""Explicit sshd contexts and baselines are fixtures, never live SSH sessions."""
import unittest
from linscope.checks import ssh
from linscope.core import CommandResult


BASE = ("permitrootlogin no\npasswordauthentication no\npermitemptypasswords no\n"
        "pubkeyauthentication yes\nmaxauthtries 4\nx11forwarding no\ngatewayports no\n")
CONNECTION = {"user": "alice", "addr": "192.0.2.10", "host": "client.example"}


class Context:
    profile = "server"
    def __init__(self, contexts=None, outputs=None, baseline=None):
        self.ssh_contexts = contexts or []
        self.outputs = outputs or {}
        self.baseline = baseline or {}
        self.commands = []
    def read(self, path):
        return "Include /etc/ssh/sshd_config.d/*.conf\nMatch User alice\n PasswordAuthentication yes\n"
    def command(self, argv):
        self.commands.append(argv)
        value = self.outputs.get(tuple(argv), BASE)
        if isinstance(value, CommandResult):
            return value
        return CommandResult(tuple(argv), 0, value)


class SSHContextTests(unittest.TestCase):
    def find(self, ctx, check_id):
        return next(f for f in ssh.run(ctx) if f.id == check_id)

    def test_context_command_uses_validated_single_parameter(self):
        ctx = Context([CONNECTION])
        results = ssh.run(ctx)
        self.assertIn(["sshd", "-T", "-C", "user=alice,addr=192.0.2.10,host=client.example"], ctx.commands)
        self.assertEqual(sum(f.id.startswith("SSHCTX-") for f in results), 7)
        self.assertIn("Explicit connection contexts evaluated: 1", results[-1].evidence)

    def test_context_specific_failure_does_not_erase_default(self):
        command = ("sshd", "-T", "-C", "user=alice,addr=192.0.2.10,host=client.example")
        ctx = Context([CONNECTION], {command: CommandResult(command, 1, "", "permission denied")})
        results = {f.id: f for f in ssh.run(ctx)}
        self.assertEqual(results["SSH-001"].status, "PASS")
        self.assertEqual(results[ssh.connection_context_id(CONNECTION) + "-000"].status, "UNKNOWN")

    def test_match_changes_actual_result_for_selected_user(self):
        command = ("sshd", "-T", "-C", "user=alice,addr=192.0.2.10,host=client.example")
        ctx = Context([CONNECTION], {command: BASE.replace("passwordauthentication no", "passwordauthentication yes")})
        results = {f.id: f for f in ssh.run(ctx)}
        self.assertEqual(results["SSH-002"].status, "PASS")
        self.assertEqual(results[ssh.connection_context_id(CONNECTION) + "-002"].status, "WARN")

    def test_default_failure_still_allows_valid_selected_context(self):
        ctx = Context([CONNECTION], {("sshd", "-T"): CommandResult((), 1, "", "default unavailable")})
        results = {f.id: f for f in ssh.run(ctx)}
        self.assertEqual(results["SSH-000"].status, "UNKNOWN")
        self.assertEqual(results[ssh.connection_context_id(CONNECTION) + "-001"].status, "PASS")

    def test_context_id_ignores_mapping_order_and_ipv6_spelling(self):
        first = {"host": "CLIENT.example", "addr": "2001:0db8:0:0:0:0:0:1", "user": "alice"}
        second = {"user": "alice", "addr": "2001:db8::1", "host": "client.example"}
        self.assertEqual(ssh.connection_context_id(first), ssh.connection_context_id(second))
        self.assertRegex(ssh.connection_context_id(first), r"^SSHCTX-[0-9A-F]{12}$")

    def test_ids_do_not_depend_on_target_order(self):
        other = dict(CONNECTION, user="bob")
        first = {f.id for f in ssh.run(Context([CONNECTION, other]))}
        second = {f.id for f in ssh.run(Context([other, CONNECTION]))}
        self.assertEqual(first, second)

    def test_normalized_duplicate_context_only_collected_once(self):
        ctx = Context([CONNECTION, dict(CONNECTION, host="CLIENT.EXAMPLE")])
        results = ssh.run(ctx)
        self.assertEqual(sum(f.id.startswith("SSHCTX-") for f in results), 7)
        self.assertEqual(len(ctx.commands), 2)

    def test_optional_local_address_and_port(self):
        value = dict(CONNECTION, laddr="2001:db8::2", lport=2222)
        ctx = Context([value])
        ssh.run(ctx)
        self.assertEqual(ctx.commands[-1][-1], "user=alice,addr=192.0.2.10,host=client.example,laddr=2001:db8::2,lport=2222")

    def test_invalid_context_values_do_not_execute_sshd(self):
        invalid = [None, {}, {"user": "alice", "addr": "192.0.2.1"},
                   dict(CONNECTION, extra="option"), dict(CONNECTION, user="-oForceCommand=evil"),
                   dict(CONNECTION, user="alice,host=other"), dict(CONNECTION, host="bad\nname"),
                   dict(CONNECTION, addr="example.org"), dict(CONNECTION, addr="fe80::1%eth0"),
                   dict(CONNECTION, lport=True), dict(CONNECTION, lport=0), dict(CONNECTION, lport=65536),
                   dict(CONNECTION, lport="22"), dict(CONNECTION, laddr="not-an-ip")]
        for value in invalid:
            with self.subTest(value=value):
                ctx = Context([value])
                self.assertEqual(ssh.run(ctx)[0].status, "UNKNOWN")
                self.assertEqual(ctx.commands, [])

    def test_context_count_bounded_before_commands(self):
        ctx = Context([dict(CONNECTION, user=f"user{i}") for i in range(33)])
        self.assertEqual(ssh.run(ctx)[0].status, "UNKNOWN")
        self.assertEqual(ctx.commands, [])

    def test_known_scalar_duplicates_are_not_last_wins(self):
        ctx = Context(outputs={("sshd", "-T"): BASE + "permitrootlogin yes\n"})
        findings = ssh.run(ctx)
        self.assertEqual(findings[0].id, "SSH-000")
        self.assertEqual(findings[0].status, "UNKNOWN")

    def test_repeated_multivalued_ssh_keys_are_valid(self):
        ctx = Context(outputs={("sshd", "-T"): BASE + "hostkey /etc/ssh/a\nhostkey /etc/ssh/b\n"})
        self.assertEqual(self.find(ctx, "SSH-001").status, "PASS")

    def test_malformed_nonempty_output_is_unknown(self):
        ctx = Context(outputs={("sshd", "-T"): BASE + "garbage\n"})
        self.assertEqual(ssh.run(ctx)[0].status, "UNKNOWN")

    def test_unrecognized_monitored_value_is_unknown(self):
        ctx = Context(outputs={("sshd", "-T"): BASE.replace("permitrootlogin no", "permitrootlogin perhaps")})
        self.assertEqual(self.find(ctx, "SSH-001").status, "UNKNOWN")

    def test_missing_value_in_context_never_passes(self):
        command = ("sshd", "-T", "-C", "user=alice,addr=192.0.2.10,host=client.example")
        ctx = Context([CONNECTION], {command: ""})
        self.assertEqual(self.find(ctx, ssh.connection_context_id(CONNECTION) + "-001").status, "UNKNOWN")

    def test_root_mode_baseline_changes_default_and_selected_context(self):
        output = BASE.replace("permitrootlogin no", "permitrootlogin prohibit-password")
        ctx = Context([CONNECTION], baseline={"SSH-001": {"allowed": ["no", "prohibit-password"]}})
        ctx.outputs = {("sshd", "-T"): output, ("sshd", "-T", "-C", "user=alice,addr=192.0.2.10,host=client.example"): output}
        findings = {f.id: f for f in ssh.run(ctx)}
        self.assertEqual(findings["SSH-001"].status, "PASS")
        self.assertEqual(findings[ssh.connection_context_id(CONNECTION) + "-001"].status, "PASS")
        self.assertIn("expected=no,prohibit-password", findings["SSH-001"].evidence)

    def test_deprecated_root_mode_alias_has_same_meaning(self):
        ctx = Context(outputs={("sshd", "-T"): BASE.replace("permitrootlogin no", "permitrootlogin without-password")},
                      baseline={"SSH-001": {"allowed": ["prohibit-password"]}})
        self.assertEqual(self.find(ctx, "SSH-001").status, "PASS")

    def test_auth_attempts_baseline_changes_verdict(self):
        ctx = Context(baseline={"SSH-005": {"max_attempts": 3}})
        finding = self.find(ctx, "SSH-005")
        self.assertEqual(finding.status, "WARN")
        self.assertIn("expected=1..3", finding.evidence)
        ctx.baseline = {"SSH-005": {"max_attempts": 6}}
        self.assertEqual(self.find(ctx, "SSH-005").status, "PASS")

    def test_invalid_direct_baseline_never_falls_back_to_pass(self):
        for baseline in ({"SSH-001": {"allowed": ["perhaps"]}}, {"SSH-001": {"allowed": []}},
                         {"SSH-005": {"max_attempts": True}}, {"SSH-005": {"max_attempts": 0}},
                         {"SSH-005": {"max_attempts": 101}}, {"SSH-005": {"extra": 4}}):
            with self.subTest(baseline=baseline):
                ctx = Context(baseline=baseline)
                self.assertEqual(ssh.run(ctx)[0].status, "UNKNOWN")
                self.assertEqual(ctx.commands, [])

    def test_overflowing_attempt_limit_is_unknown_without_conversion_error(self):
        for value in ("9" * 5000, "2147483648", "-1", "4.0"):
            with self.subTest(value=value[:20]):
                ctx = Context(outputs={("sshd", "-T"): BASE.replace("maxauthtries 4", f"maxauthtries {value}")})
                self.assertEqual(self.find(ctx, "SSH-005").status, "UNKNOWN")

    def test_bound_public_key_modes_are_valid_authentication(self):
        for value in ("host-bound", "unbound"):
            with self.subTest(value=value):
                ctx = Context(outputs={("sshd", "-T"): BASE.replace("pubkeyauthentication yes", f"pubkeyauthentication {value}")})
                self.assertEqual(self.find(ctx, "SSH-004").status, "PASS")


if __name__ == "__main__":
    unittest.main()
