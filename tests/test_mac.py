import json
from pathlib import Path
import tempfile
import unittest

from linscope.core import CommandResult, Context
from linscope.checks import mac


class FixtureContext(Context):
    def __init__(self, root):
        super().__init__(root=root)
        self.commands = {}

    def command(self, argv, timeout=8):
        return self.commands.get(tuple(argv), CommandResult(tuple(argv), None, error="fixture command unavailable"))


class MacTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.ctx = FixtureContext(self.root)

    def write(self, path, text):
        path = self.root / path.lstrip("/")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def command(self, argv, text, code=0):
        self.ctx.commands[tuple(argv)] = CommandResult(tuple(argv), code, stdout=text)

    def findings(self):
        return {finding.id: finding for finding in mac.run(self.ctx)}

    def apparmor(self, profiles=None):
        self.write("/sys/module/apparmor/parameters/enabled", "Y\n")
        self.command(["aa-status", "--json"], json.dumps({"profiles": profiles or {"test": "enforce"}}))

    def test_apparmor_does_not_require_selinux(self):
        self.apparmor()
        self.write("/sys/kernel/security/lsm", "lockdown,yama,apparmor\n")
        findings = self.findings()
        self.assertEqual(findings["MAC-002"].status, "PASS")
        self.assertEqual(findings["MAC-003"].status, "SKIP")
        self.assertEqual(findings["MAC-004"].status, "SKIP")

    def test_selinux_does_not_require_apparmor(self):
        self.write("/sys/kernel/security/lsm", "lockdown,yama,selinux\n")
        self.command(["getenforce"], "Enforcing\n")
        findings = self.findings()
        self.assertEqual(findings["MAC-002"].status, "SKIP")
        self.assertEqual(findings["MAC-003"].status, "PASS")

    def test_lsm_runtime_list_takes_precedence_over_module_parameter(self):
        self.apparmor()
        self.write("/sys/kernel/security/lsm", "lockdown,yama,selinux\n")
        self.command(["getenforce"], "Enforcing\n")
        self.assertEqual(self.findings()["MAC-002"].status, "SKIP")

    def test_unavailable_tools_not_proof_of_disable(self):
        findings = self.findings()
        self.assertEqual(findings["MAC-001"].status, "UNKNOWN")
        self.assertEqual(findings["MAC-002"].status, "UNKNOWN")
        self.assertEqual(findings["MAC-003"].status, "UNKNOWN")

    def test_known_no_framework_warns_once(self):
        self.write("/sys/kernel/security/lsm", "lockdown,yama,bpf\n")
        findings = self.findings()
        self.assertEqual(findings["MAC-001"].status, "WARN")
        self.assertEqual(findings["MAC-002"].status, "SKIP")
        self.assertEqual(findings["MAC-003"].status, "SKIP")

    def test_permissive_runtime_warns(self):
        self.command(["getenforce"], "Permissive\n")
        self.assertEqual(self.findings()["MAC-003"].status, "WARN")

    def test_enforcement_file_fallback(self):
        self.write("/sys/fs/selinux/enforce", "1\n")
        self.assertEqual(self.findings()["MAC-003"].status, "PASS")

    def test_complain_profiles_warn_and_do_not_report_names(self):
        self.apparmor({"private-path": "complain", "other": "enforce"})
        finding = self.findings()["MAC-002"]
        self.assertEqual(finding.status, "WARN")
        self.assertNotIn("private-path", finding.evidence)

    def test_empty_profiles_warn(self):
        self.apparmor()
        self.command(["aa-status", "--json"], '{"profiles":{}}')
        self.assertEqual(self.findings()["MAC-002"].status, "WARN")

    def test_malformed_profiles_unknown(self):
        self.apparmor()
        self.command(["aa-status", "--json"], '{"profiles":[]}')
        self.assertEqual(self.findings()["MAC-002"].status, "UNKNOWN")
        self.command(["aa-status", "--json"], '[]')
        self.assertEqual(self.findings()["MAC-002"].status, "UNKNOWN")

    def test_permission_error_unknown(self):
        self.apparmor()
        self.command(["aa-status", "--json"], "", code=4)
        self.assertEqual(self.findings()["MAC-002"].status, "UNKNOWN")

    def test_persistent_mismatch_warns_and_duplicate_unknown(self):
        self.command(["getenforce"], "Enforcing\n")
        self.write("/etc/selinux/config", "SELINUX=permissive\n")
        self.assertEqual(self.findings()["MAC-004"].status, "WARN")
        self.write("/etc/selinux/config", "SELINUX=permissive\nSELINUX=enforcing\n")
        self.assertEqual(self.findings()["MAC-004"].status, "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
