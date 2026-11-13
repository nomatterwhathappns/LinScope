from copy import deepcopy
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from linscope import cli
from linscope.core import Context, Finding
from linscope.policy import parse_ssh_context, validate_policy
from linscope.reporting import compare_reports


class ExtendedPolicyTests(unittest.TestCase):
    def test_baselines_are_strict_and_normalized(self):
        policy = {"baseline": {"SSH-001": {"allowed": ["without-password", "no"]},
                               "SSH-005": {"max_attempts": 6}, "PACKAGES-002": {"max_age_days": 3}}}
        original = deepcopy(policy)
        result = validate_policy(policy)
        self.assertEqual(result["baseline"]["SSH-001"]["allowed"], ["no", "prohibit-password"])
        self.assertEqual(policy, original)

    def test_invalid_baselines_rejected(self):
        invalid = [[], {"UNKNOWN-001": {}}, {"SSH-005": {"max_attempts": True}},
                   {"SSH-005": {"max_attempts": 0}}, {"SSH-005": {"max_attempts": 101}},
                   {"PACKAGES-002": {"max_age_days": 1.5}}, {"PACKAGES-002": {"max_age_days": 366}},
                   {"SSH-001": {"allowed": []}}, {"SSH-001": {"allowed": ["invalid"]}},
                   {"SSH-001": {"allowed": ["prohibit-password", "without-password"]}},
                   {"SSH-005": {"max_attempts": 4, "command": "anything"}}]
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_policy({"baseline": value})

    def test_connection_context_cli_parsing(self):
        value = parse_ssh_context("host=CLIENT.EXAMPLE,addr=2001:0db8::1,user=alice,laddr=192.0.2.1,lport=22")
        self.assertEqual(value["host"], "client.example")
        self.assertEqual(value["addr"], "2001:db8::1")
        self.assertEqual(value["lport"], 22)

    def test_context_duplicate_fields_options_and_injection_rejected(self):
        for value in ("user=a,user=b,addr=192.0.2.1,host=x", "user=-o,addr=192.0.2.1,host=x",
                      "user=a,addr=192.0.2.1,host=x,command=evil", "user=a,addr=example.com,host=x",
                      "user=a,addr=192.0.2.1,host=x,lport=true", "user=a,addr=192.0.2.1,host=x,lport=0"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                parse_ssh_context(value)

    def test_duplicate_contexts_rejected_after_normalization(self):
        contexts = [{"user": "alice", "addr": "2001:db8::1", "host": "X"},
                    {"user": "alice", "addr": "2001:0db8::1", "host": "x"}]
        with self.assertRaises(ValueError):
            validate_policy({"ssh_contexts": contexts})

    def test_selected_users_strict_and_canonical(self):
        self.assertEqual(validate_policy({"sudo_users": ["bob", "alice"]})["sudo_users"], ["alice", "bob"])
        for users in (["-root"], ["a,b"], ["a\nb"], ["root", "root"], "root", ["x"] * 21):
            with self.subTest(users=users), self.assertRaises(ValueError):
                validate_policy({"sudo_users": users})

    def test_dynamic_target_exception_id_supported(self):
        policy = {"exceptions": {"SSHCTX-012345ABCDEF-001": {"reason": "Reviewed context", "expires": "2030-01-01"}}}
        self.assertEqual(validate_policy(policy), policy)

    def test_collect_records_nondefault_parameters(self):
        context = Context(baseline={"SSH-005": {"max_attempts": 6}}, sudo_users=["alice"])
        finding = Finding("TEST-001", "test", "Test", "INFO", "info", "fixture", "review")
        with patch("linscope.cli.CHECKS", {"test": lambda _: [finding]}):
            report = cli.collect(context, ["test"])
        self.assertEqual(report["scope"]["parameters"]["baseline"], context.baseline)
        self.assertEqual(report["scope"]["parameters"]["sudo_users"], ["alice"])

    def test_invalid_cli_context_does_not_collect(self):
        with patch("linscope.cli.collect") as collector, contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(["--ssh-context", "user=-o,addr=192.0.2.1,host=x"]), 2)
        collector.assert_not_called()

    def test_changed_baseline_is_not_a_comparable_scope(self):
        finding = Finding("TEST-001", "test", "Test", "INFO", "info", "fixture", "review")
        with patch("linscope.cli.CHECKS", {"test": lambda _: [finding]}):
            first = cli.collect(Context(baseline={"SSH-005": {"max_attempts": 4}}), ["test"])
            second = cli.collect(Context(baseline={"SSH-005": {"max_attempts": 6}}), ["test"])
        with self.assertRaisesRegex(ValueError, "scopes"):
            compare_reports(first, second)


if __name__ == "__main__":
    unittest.main()
