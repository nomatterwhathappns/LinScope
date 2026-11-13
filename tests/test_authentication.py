import unittest

from linscope.core import CommandResult
from linscope.checks import authentication


class FakeContext:
    profile = "server"
    deep = False

    def __init__(self, files=None, metadata=None, code=0):
        self.files = files or {}
        self.metadata = metadata
        self.code = code
        self.reads = []

    def read(self, path):
        self.reads.append(path)
        value = self.files.get(path, FileNotFoundError(path))
        if isinstance(value, Exception):
            raise value
        return value

    def command(self, args):
        if self.metadata is None:
            return CommandResult(tuple(args), None, error="unavailable")
        return CommandResult(tuple(args), self.code, self.metadata)


def normal_files():
    return {
        "/etc/login.defs": "PASS_MAX_DAYS 99999\nPASS_MIN_DAYS 0\nPASS_WARN_AGE 7\n",
        "/etc/pam.d/common-password": "password requisite pam_pwquality.so retry=3\n",
        "/etc/pam.d/common-auth": "auth required pam_faillock.so preauth\n",
        "/etc/pam.d/common-account": "account required pam_unix.so\n",
        "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\ndaemon:x:1:1::/:/usr/sbin/nologin\n",
    }


class AuthenticationTests(unittest.TestCase):
    def run_checks(self, files=None, metadata="root L 2025-01-01 0 99999 7 -1\nalice P 2025-01-01 0 90 7 -1\ndaemon L 2025-01-01 0 99999 7 -1\n"):
        ctx = FakeContext(normal_files() if files is None else files, metadata)
        return ctx, {item.id: item for item in authentication.run(ctx)}

    def test_valid_metadata_has_seven_fields_and_never_reads_hashes(self):
        ctx, results = self.run_checks()
        self.assertEqual(results["AUTHENTICATION-005"].status, "PASS")
        self.assertEqual(results["AUTHENTICATION-006"].status, "INFO")
        self.assertNotIn("/etc/shadow", ctx.reads)
        self.assertNotIn("/etc/gshadow", ctx.reads)

    def test_login_defaults_not_claimed_as_account_enforcement(self):
        _, results = self.run_checks()
        self.assertEqual(results["AUTHENTICATION-001"].status, "INFO")
        self.assertIn("creation defaults", results["AUTHENTICATION-001"].evidence)

    def test_empty_password_for_interactive_user_is_reported(self):
        _, results = self.run_checks(metadata="root L 2025-01-01 0 99999 7 -1\nalice NP 2025-01-01 0 90 7 -1\n")
        self.assertEqual(results["AUTHENTICATION-005"].status, "FAIL")
        self.assertIn("alice", results["AUTHENTICATION-005"].evidence)

    def test_empty_password_for_nologin_user_not_misclassified(self):
        _, results = self.run_checks(metadata="root L 2025-01-01 0 99999 7 -1\nalice P 2025-01-01 0 90 7 -1\ndaemon NP 2025-01-01 0 99999 7 -1\n")
        self.assertEqual(results["AUTHENTICATION-005"].status, "PASS")

    def test_missing_or_malformed_account_metadata_is_unknown(self):
        for metadata in ("", "root P date 0 90 7 -1\n", "root P date zero 90 7 -1\nalice P date 0 90 7 -1"):
            with self.subTest(metadata=metadata):
                _, results = self.run_checks(metadata=metadata)
                self.assertEqual(results["AUTHENTICATION-005"].status, "UNKNOWN")

    def test_command_permission_failure_is_unknown(self):
        ctx = FakeContext(normal_files(), "permission denied", code=1)
        results = {item.id: item for item in authentication.run(ctx)}
        self.assertEqual(results["AUTHENTICATION-005"].status, "UNKNOWN")

    def test_commented_pam_module_does_not_count(self):
        files = normal_files()
        files["/etc/pam.d/common-password"] = "# password required pam_pwquality.so\npassword required pam_unix.so\n"
        _, results = self.run_checks(files)
        self.assertEqual(results["AUTHENTICATION-003"].status, "WARN")

    def test_pam_reference_is_inventory_not_enforcement_pass(self):
        _, results = self.run_checks()
        self.assertEqual(results["AUTHENTICATION-003"].status, "INFO")
        self.assertEqual(results["AUTHENTICATION-004"].status, "INFO")

    def test_partial_pam_collection_does_not_claim_no_lockout(self):
        files = normal_files()
        files["/etc/pam.d/common-auth"] = "auth required pam_unix.so\n"
        files["/etc/pam.d/common-account"] = PermissionError("denied")
        _, results = self.run_checks(files)
        self.assertEqual(results["AUTHENTICATION-004"].status, "UNKNOWN")

    def test_duplicate_login_definitions_are_unknown(self):
        files = normal_files()
        files["/etc/login.defs"] += "PASS_MAX_DAYS 30\nPASS_WARN_AGE 4\n"
        _, results = self.run_checks(files)
        self.assertEqual(results["AUTHENTICATION-001"].status, "UNKNOWN")
        self.assertEqual(results["AUTHENTICATION-002"].status, "UNKNOWN")

    def test_low_expiry_warning_requests_review(self):
        files = normal_files()
        files["/etc/login.defs"] = "PASS_MAX_DAYS 90\nPASS_MIN_DAYS 0\nPASS_WARN_AGE 0\n"
        _, results = self.run_checks(files)
        self.assertEqual(results["AUTHENTICATION-002"].status, "WARN")

    def test_missing_files_are_unknown_and_no_crash(self):
        _, results = self.run_checks({})
        self.assertTrue(all(item.status == "UNKNOWN" for item in results.values()))

    def test_invalid_account_identifiers_are_unknown(self):
        files = normal_files()
        files["/etc/passwd"] = "root:x:invalid:0::/root:/bin/bash\n"
        _, results = self.run_checks(files)
        self.assertEqual(results["AUTHENTICATION-005"].status, "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
