import unittest
from linscope.checks import accounts


class AccountContext:
    def __init__(self, passwd="root:x:0:0:root:/root:/bin/bash\n", sudoers="root ALL=(ALL:ALL) ALL\n", group="root:x:0:\n"):
        self.data = {"/etc/passwd": passwd, "/etc/login.defs": "UID_MIN 1000\n", "/etc/group": group, "/etc/sudoers": sudoers}
    def read(self, path):
        item = self.data.get(path, FileNotFoundError(path))
        if isinstance(item, Exception):
            raise item
        return item
    def glob(self, pattern):
        return []


class AccountsTests(unittest.TestCase):
    def test_extra_uid_zero_is_failure(self):
        results = accounts.run(AccountContext(passwd="root:x:0:0::/root:/bin/bash\nbackdoor:x:0:0::/:/bin/bash\n"))
        self.assertEqual(next(f.status for f in results if f.id == "ACCT-001"), "FAIL")

    def test_duplicate_nonroot_uid_requires_review(self):
        results = accounts.run(AccountContext(passwd="root:x:0:0::/root:/bin/bash\na:x:1000:1000::/home/a:/bin/bash\nb:x:1000:1000::/home/b:/bin/bash\n"))
        self.assertEqual(next(f.status for f in results if f.id == "ACCT-002"), "WARN")

    def test_malformed_inventory_not_clean(self):
        results = accounts.run(AccountContext(passwd="bad-record"))
        self.assertEqual(results[0].status, "UNKNOWN")

    def test_no_passwordless_rule_is_inventory_not_effective_privilege_pass(self):
        results = accounts.run(AccountContext())
        self.assertEqual(next(f.status for f in results if f.id == "ACCT-005"), "INFO")

    def test_passwordless_rule_does_not_leak_full_rule(self):
        results = accounts.run(AccountContext(sudoers="operator ALL=(root) NOPASSWD: /opt/private/customer-tool\n"))
        result = next(f for f in results if f.id == "ACCT-005")
        self.assertEqual(result.status, "WARN")
        self.assertNotIn("customer-tool", result.evidence)

    def test_unreadable_sudoers_is_unknown(self):
        results = accounts.run(AccountContext(sudoers=PermissionError("denied")))
        self.assertEqual(next(f.status for f in results if f.id == "ACCT-005"), "UNKNOWN")

    def test_blank_shell_defaults_to_interactive_shell(self):
        results = accounts.run(AccountContext(passwd="root:x:0:0::/root:/bin/bash\nsvc:x:100:100::/srv/svc:\n"))
        self.assertEqual(next(f.status for f in results if f.id == "ACCT-003"), "WARN")

    def test_username_beginning_with_root_is_not_root(self):
        results = accounts.run(AccountContext(sudoers="rootops ALL=(ALL:ALL) ALL\n"))
        self.assertIn("/etc/sudoers:1", next(f.evidence for f in results if f.id == "ACCT-006"))

    def test_inline_comment_not_passwordless_policy(self):
        results = accounts.run(AccountContext(sudoers="operator ALL=(ALL) ALL # avoid NOPASSWD: here\n"))
        self.assertEqual(next(f.status for f in results if f.id == "ACCT-005"), "INFO")


if __name__ == "__main__":
    unittest.main()
