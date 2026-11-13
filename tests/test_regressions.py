"""Independent regressions for malformed identity data and collector limits."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from linscope.checks import accounts
from linscope.core import Context
from linscope.policy import load_policy
from tests.test_accounts import AccountContext


ROOT = "root:x:0:0:root:/root:/bin/bash\n"


class AccountBoundsRegressions(unittest.TestCase):
    def test_invalid_uid_and_gid_never_produce_clean_account_inventory(self):
        invalid = ("-1", "4294967295", "4294967296", "999999999999999999999",
                   "1000x", "+1000", " 1000", "1.0", "0x3e8", "", "١٠٠٠")
        for field in ("uid", "gid"):
            for value in invalid:
                with self.subTest(field=field, value=value):
                    uid, gid = (value, "1000") if field == "uid" else ("1000", value)
                    data = ROOT + f"alice:x:{uid}:{gid}::/home/alice:/bin/bash\n"
                    with self.assertRaises(ValueError):
                        accounts.parse_passwd(data)
                    findings = accounts.run(AccountContext(passwd=data))
                    account = next(item for item in findings if item.id == "ACCT-001")
                    self.assertEqual(account.status, "UNKNOWN")

    def test_highest_usable_linux_uid_and_gid_remain_valid(self):
        parsed = accounts.parse_passwd(ROOT + "alice:x:4294967294:4294967294::/home/alice:/bin/bash\n")
        self.assertEqual(parsed[-1][1:3], (4294967294, 4294967294))

    def test_duplicate_or_empty_usernames_are_malformed(self):
        cases = (
            ROOT + "alice:x:1000:1000::/home/alice:/bin/bash\nalice:x:1001:1001::/home/other:/bin/bash\n",
            ROOT + ":x:1000:1000::/home/empty:/bin/bash\n",
        )
        for data in cases:
            with self.subTest(data=data):
                with self.assertRaises(ValueError):
                    accounts.parse_passwd(data)

    def test_uid_min_missing_duplicate_malformed_or_out_of_bounds_is_unknown(self):
        values = ("", "UID_MIN 0\n", "UID_MIN -1\n", "UID_MIN 4294967295\n",
                  "UID_MIN 999999999999999999999\n", "UID_MIN invalid\n",
                  "UID_MIN 1.5\n", "UID_MIN 1000\nUID_MIN 2000\n",
                  "UID_MIN 1000\nUID_MIN 1000\n", "UID_MIN 1000\nUID_MIN invalid\n")
        for value in values:
            with self.subTest(value=value):
                ctx = AccountContext()
                ctx.data["/etc/login.defs"] = value
                findings = accounts.run(ctx)
                result = next(item for item in findings if item.id == "ACCT-003")
                self.assertEqual(result.status, "UNKNOWN")

    def test_valid_uid_min_with_inline_comment_is_accepted(self):
        ctx = AccountContext()
        ctx.data["/etc/login.defs"] = "# UID_MIN 500\nUID_MIN 1000 # normal local accounts\n"
        result = next(item for item in accounts.run(ctx) if item.id == "ACCT-003")
        self.assertEqual(result.status, "PASS")


class CommandLimitsRegressions(unittest.TestCase):
    def test_timeout_is_incomplete_evidence_even_when_partial_output_exists(self):
        timeout = subprocess.TimeoutExpired(["fixture-tool"], 0.1, output=b"PASS", stderr=b"partial")
        with patch("linscope.core.shutil.which", return_value="/usr/bin/fixture-tool"), \
                patch("linscope.core.subprocess.run", side_effect=timeout) as runner:
            result = Context().command(["fixture-tool", "--read-only"], timeout=0.1)
        self.assertFalse(result.ok)
        self.assertIsNone(result.returncode)
        self.assertEqual(result.stdout, "")
        self.assertIn("timed out", result.error)
        self.assertEqual(runner.call_args.kwargs["timeout"], 0.1)
        self.assertFalse(runner.call_args.kwargs.get("shell", False))

    def test_oversized_stdout_or_stderr_is_not_clean_evidence(self):
        for channel in ("stdout", "stderr"):
            with self.subTest(channel=channel):
                def fake_run(argv, **kwargs):
                    kwargs[channel].write(b"x" * 1_048_577)
                    return subprocess.CompletedProcess(argv, 0)
                with patch("linscope.core.shutil.which", return_value="/usr/bin/fixture-tool"), \
                        patch("linscope.core.subprocess.run", side_effect=fake_run):
                    result = Context().command(["fixture-tool"])
                self.assertEqual(result.returncode, 0)
                self.assertFalse(result.ok)
                self.assertIn("exceeded", result.error)
                self.assertEqual(len(getattr(result, channel)), 1_048_576)

    def test_exact_output_limit_is_valid_and_command_result_is_cached(self):
        def fake_run(argv, **kwargs):
            kwargs["stdout"].write(b"x" * 1_048_576)
            return subprocess.CompletedProcess(argv, 0)
        with patch("linscope.core.shutil.which", return_value="/usr/bin/fixture-tool"), \
                patch("linscope.core.subprocess.run", side_effect=fake_run) as runner:
            ctx = Context()
            first = ctx.command(["fixture-tool"])
            second = ctx.command(["fixture-tool"])
        self.assertTrue(first.ok)
        self.assertIs(first, second)
        self.assertEqual(runner.call_count, 1)

    def test_nonzero_exit_cannot_be_clean_despite_positive_stdout(self):
        def fake_run(argv, **kwargs):
            kwargs["stdout"].write(b"PASS")
            return subprocess.CompletedProcess(argv, 1)
        with patch("linscope.core.shutil.which", return_value="/usr/bin/fixture-tool"), \
                patch("linscope.core.subprocess.run", side_effect=fake_run):
            result = Context().command(["fixture-tool"])
        self.assertFalse(result.ok)
        self.assertEqual(result.returncode, 1)


class PolicyInputRegressions(unittest.TestCase):
    def test_fifo_policy_fails_promptly_without_waiting_for_a_writer(self):
        with tempfile.TemporaryDirectory() as tmp:
            fifo = Path(tmp, "policy.fifo")
            os.mkfifo(fifo)
            result = subprocess.run([sys.executable, "-m", "linscope", "--policy", str(fifo)],
                                    capture_output=True, text=True, timeout=3, check=False)
        self.assertEqual(result.returncode, 2)
        self.assertIn("regular file", result.stderr)
        self.assertEqual(result.stdout, "")

    def test_policy_invalid_utf8_is_rejected_instead_of_replacement_decoding(self):
        with tempfile.TemporaryDirectory() as tmp:
            policy = Path(tmp, "policy.json")
            policy.write_bytes(b'{"profile":"serv\xffer"}')
            with self.assertRaises(ValueError):
                load_policy(policy)


if __name__ == "__main__":
    unittest.main()
