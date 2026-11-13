import unittest
from linscope.core import CommandResult
from linscope.checks import ssh


class SSHContext:
    profile = "server"
    def __init__(self, output="", error=None, config="Include /etc/ssh/sshd_config.d/*.conf\n"):
        self.output, self.error, self.config = output, error, config
    def read(self, path):
        if isinstance(self.config, Exception):
            raise self.config
        return self.config
    def command(self, argv):
        return CommandResult(tuple(argv), 1 if self.error else 0, self.output, self.error or "")


class SSHTests(unittest.TestCase):
    def test_effective_config_not_first_text_value(self):
        ctx = SSHContext("permitrootlogin yes\npasswordauthentication no\n", config="PermitRootLogin no\nInclude /etc/ssh/example.conf\n")
        results = {f.id: f for f in ssh.run(ctx)}
        self.assertEqual(results["SSH-001"].status, "WARN")
        self.assertEqual(results["SSH-002"].status, "PASS")

    def test_command_failure_not_pass(self):
        self.assertEqual(ssh.run(SSHContext(error="permission denied"))[0].status, "UNKNOWN")

    def test_missing_default_config_is_explicitly_scoped(self):
        results = ssh.run(SSHContext(config=FileNotFoundError("absent")))
        self.assertEqual(results[0].status, "SKIP")
        self.assertIn("custom", results[0].evidence)

    def test_unreported_values_are_unknown(self):
        results = ssh.run(SSHContext(""))
        self.assertTrue(all(f.status == "UNKNOWN" for f in results if f.id != "SSH-008"))

    def test_match_scope_is_disclosed(self):
        results = ssh.run(SSHContext("maxauthtries 4\n", config="Match User example\n PasswordAuthentication yes\n"))
        evidence = next(f.evidence for f in results if f.id == "SSH-008")
        self.assertIn("Match", evidence)
        self.assertEqual(next(f.status for f in results if f.id == "SSH-005"), "PASS")

    def test_invalid_attempt_limit_unknown(self):
        results = ssh.run(SSHContext("maxauthtries invalid\n"))
        self.assertEqual(next(f.status for f in results if f.id == "SSH-005"), "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
