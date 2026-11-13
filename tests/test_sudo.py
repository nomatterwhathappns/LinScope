from types import SimpleNamespace
import unittest
from unittest.mock import patch

from linscope.checks import sudo
from linscope.core import CommandResult


def listing(user="alice", options="!authenticate", commands="ALL", runas="ALL"):
    return (f"Matching Defaults entries for {user} on demo-host:\n"
            "    env_reset, mail_badpass, secure_path=/usr/sbin:/usr/bin\n\n"
            f"User {user} may run the following commands on demo-host:\n\n"
            "Sudoers entry:\n"
            f"    RunAsUsers: {runas}\n"
            "    RunAsGroups: ALL\n"
            f"    Options: {options}\n"
            "    Commands:\n"
            f"        {commands}\n")


class FakeContext:
    def __init__(self, users=None, outputs=None):
        self.sudo_users = ["alice"] if users is None else users
        self.outputs = outputs or {}
        self.calls = []

    def command(self, argv):
        self.calls.append(argv)
        user = argv[-1]
        result = self.outputs.get(user, listing(user))
        return result if isinstance(result, CommandResult) else CommandResult(tuple(argv), 0, result)


class SudoTests(unittest.TestCase):
    def findings(self, ctx=None):
        return {item.id: item for item in sudo.run(ctx or FakeContext())}

    def test_listing_only_noninteractive_fixed_arguments(self):
        ctx = FakeContext()
        results = self.findings(ctx)
        self.assertEqual(ctx.calls, [["sudo", "-n", "-ll", "-U", "alice"]])
        self.assertEqual(results[sudo._id("alice", 1)].status, "INFO")
        self.assertEqual(results[sudo._id("alice", 2)].status, "WARN")
        self.assertEqual(results[sudo._id("alice", 3)].status, "WARN")
        self.assertEqual(results[sudo._id("alice", 2)].severity, "high")

    def test_current_real_uid_name_not_environment_default(self):
        ctx = FakeContext(users=[])
        with patch("linscope.checks.sudo.os.getuid", return_value=123), patch("linscope.checks.sudo.pwd.getpwuid", return_value=SimpleNamespace(pw_name="realuser")) as lookup:
            self.findings(ctx)
        lookup.assert_called_once_with(123)
        self.assertEqual(ctx.calls[0][-1], "realuser")

    def test_unmapped_real_uid_is_unknown(self):
        with patch("linscope.checks.sudo.pwd.getpwuid", side_effect=KeyError("not mapped")):
            results = self.findings(FakeContext(users=[]))
        self.assertEqual(results["SUDO-000"].status, "UNKNOWN")

    def test_raw_command_arguments_never_in_report(self):
        output = listing(commands="/opt/tool --password SUPER_SECRET_ARGUMENT")
        findings = self.findings(FakeContext(outputs={"alice": output}))
        for item in findings.values():
            self.assertNotIn("SUPER_SECRET_ARGUMENT", item.evidence)
            self.assertNotIn("/opt/tool", item.evidence)

    def test_absent_auth_tag_not_claimed_enforced(self):
        findings = self.findings(FakeContext(outputs={"alice": listing(options="env_reset", commands="/usr/bin/id")}))
        self.assertEqual(findings[sudo._id("alice", 2)].status, "INFO")
        self.assertEqual(findings[sudo._id("alice", 3)].status, "INFO")

    def test_last_authentication_option_wins(self):
        ctx = FakeContext(outputs={"alice": listing(options="!authenticate, authenticate")})
        self.assertEqual(self.findings(ctx)[sudo._id("alice", 2)].status, "INFO")
        ctx.outputs["alice"] = listing(options="authenticate, !authenticate")
        self.assertEqual(self.findings(ctx)[sudo._id("alice", 2)].status, "WARN")

    def test_root_exclusion_does_not_claim_root_capability(self):
        ctx = FakeContext(outputs={"alice": listing(runas="ALL, !root")})
        result = self.findings(ctx)[sudo._id("alice", 2)]
        self.assertEqual(result.severity, "medium")
        self.assertIn("hints=0", result.evidence)

    def test_all_negations_keep_review_scope_explicit(self):
        ctx = FakeContext(outputs={"alice": listing(commands="ALL, !/usr/bin/passwd")})
        result = self.findings(ctx)[sudo._id("alice", 3)]
        self.assertEqual(result.status, "WARN")
        self.assertIn("Negations", result.evidence)

    def test_negated_all_is_not_positive_all_grant(self):
        ctx = FakeContext(outputs={"alice": listing(commands="!ALL")})
        self.assertEqual(self.findings(ctx)[sudo._id("alice", 3)].status, "INFO")

    def test_multiple_user_order_and_duplicates_do_not_change_ids(self):
        first = self.findings(FakeContext(users=["alice", "bob", "alice"]))
        second = self.findings(FakeContext(users=["bob", "alice"]))
        self.assertEqual(first.keys(), second.keys())
        self.assertEqual(len(first), 6)

    def test_multiple_entries_retained(self):
        output = listing() + "\nSudoers entry:\n    RunAsUsers: root\n    Options: authenticate\n    Commands:\n        /usr/bin/id\n"
        result = self.findings(FakeContext(outputs={"alice": output}))[sudo._id("alice", 1)]
        self.assertIn("entries=2", result.evidence)

    def test_authoritative_no_privilege_listing_is_inventory(self):
        for message in ("User alice is not allowed to run sudo on demo-host.",
                        "Sorry, user alice may not run sudo on demo-host.",
                        "alice is not in the sudoers file. This incident will be reported."):
            with self.subTest(message=message):
                result = CommandResult((), 1, "", message)
                items = self.findings(FakeContext(outputs={"alice": result}))
                self.assertEqual(items[sudo._id("alice", 1)].status, "INFO")
                self.assertEqual(len(items), 1)

    def test_wrong_username_denial_not_authoritative(self):
        result = CommandResult((), 1, "", "User bob is not allowed to run sudo on demo-host.")
        self.assertEqual(self.findings(FakeContext(outputs={"alice": result}))[sudo._id("alice", 1)].status, "UNKNOWN")

    def test_contradictory_denial_or_authentication_failure_is_unknown(self):
        denial = "User alice is not allowed to run sudo on demo-host."
        for output, error in ((listing(), denial), ("", denial + "\nsudo: a password is required")):
            with self.subTest(output=output):
                result = CommandResult((), 1, output, error)
                self.assertEqual(self.findings(FakeContext(outputs={"alice": result}))[sudo._id("alice", 1)].status, "UNKNOWN")

    def test_password_required_or_permission_error_unknown(self):
        for message in ("sudo: a password is required", "sudo: unable to initialize policy plugin", "permission denied"):
            with self.subTest(message=message):
                result = CommandResult((), 1, "", message)
                self.assertEqual(self.findings(FakeContext(outputs={"alice": result}))[sudo._id("alice", 1)].status, "UNKNOWN")

    def test_failed_or_truncated_command_not_evaluated(self):
        for result in (CommandResult((), None, error="unavailable"), CommandResult((), 1, listing()),
                       CommandResult((), 0, listing(), error="truncated")):
            with self.subTest(result=result):
                self.assertEqual(self.findings(FakeContext(outputs={"alice": result}))[sudo._id("alice", 1)].status, "UNKNOWN")

    def test_invalid_user_context_never_executes(self):
        for users in (["-root"], ["alice\nroot"], ["alice,bob"], ["root;id"], [42], "alice", ["u"] * 21, ["u" * 65]):
            with self.subTest(users=users):
                ctx = FakeContext(users=users)
                self.assertEqual(self.findings(ctx)["SUDO-000"].status, "UNKNOWN")
                self.assertEqual(ctx.calls, [])

    def test_username_grammar_matches_policy_including_digit_leading(self):
        for user in ("123service", "_service", "machine$", "u" * 64):
            with self.subTest(user=user):
                ctx = FakeContext(users=[user])
                self.assertIn(sudo._id(user, 1), self.findings(ctx))
                self.assertEqual(ctx.calls[0][-1], user)

    def test_unrecognized_or_incomplete_policy_unknown(self):
        outputs = ("", "(ALL) NOPASSWD: ALL", listing().replace("Sudoers entry:", "Unrecognized entry:"),
                   listing().replace("    RunAsUsers: ALL\n", ""), listing().replace("        ALL\n", ""),
                   listing().replace("    Options: !authenticate", "    RunAsUsers: root"))
        for output in outputs:
            with self.subTest(output=output):
                self.assertEqual(self.findings(FakeContext(outputs={"alice": output}))[sudo._id("alice", 1)].status, "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
