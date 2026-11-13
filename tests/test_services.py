import unittest

from linscope.core import CommandResult
from linscope.checks import services


RUNNING = ("systemctl", "list-units", "--type=service", "--state=running", "--no-legend", "--no-pager", "--plain")
ENABLED = ("systemctl", "list-unit-files", "--type=service", "--state=enabled,enabled-runtime", "--no-legend", "--no-pager")
SOCKETS = ("systemctl", "list-units", "--type=socket", "--state=listening", "--no-legend", "--no-pager", "--plain")
ENABLED_SOCKETS = ("systemctl", "list-unit-files", "--type=socket", "--state=enabled,enabled-runtime", "--no-legend", "--no-pager")
FAILED = ("systemctl", "list-units", "--type=service", "--state=failed", "--no-legend", "--no-pager", "--plain")


class FakeContext:
    def __init__(self, outputs=None):
        self.outputs = outputs or {}

    def command(self, args):
        output = self.outputs.get(tuple(args))
        if isinstance(output, CommandResult):
            return output
        if output is None:
            return CommandResult(tuple(args), None, error="not available")
        return CommandResult(tuple(args), 0, output)


def outputs():
    return {RUNNING: "ssh.service loaded active running OpenBSD Secure Shell server\n",
            ENABLED: "ssh.service enabled enabled\n", SOCKETS: "", ENABLED_SOCKETS: "", FAILED: ""}


class ServiceTests(unittest.TestCase):
    def checks(self, values=None):
        return {item.id: item for item in services.run(FakeContext(outputs() if values is None else values))}

    def test_complete_inventory_and_no_failed_units(self):
        findings = self.checks()
        self.assertEqual(findings["SERVICES-001"].status, "INFO")
        self.assertEqual(findings["SERVICES-002"].status, "INFO")
        self.assertEqual(findings["SERVICES-003"].status, "PASS")
        self.assertEqual(findings["SERVICES-004"].status, "PASS")

    def test_enabled_but_not_running_legacy_service_is_reviewed(self):
        values = outputs()
        values[ENABLED] += "telnet.service enabled disabled\n"
        self.assertEqual(self.checks(values)["SERVICES-003"].status, "WARN")

    def test_socket_activated_legacy_service_is_reviewed(self):
        values = outputs()
        values[SOCKETS] = "telnet.socket loaded active listening Telnet Server Activation Socket\n"
        finding = self.checks(values)["SERVICES-003"]
        self.assertEqual(finding.status, "WARN")
        self.assertIn("telnet.socket", finding.evidence)

    def test_missing_socket_inventory_never_produces_false_pass(self):
        values = outputs()
        del values[SOCKETS]
        self.assertEqual(self.checks(values)["SERVICES-003"].status, "UNKNOWN")

    def test_enabled_inactive_legacy_socket_is_reviewed(self):
        values = outputs()
        values[ENABLED_SOCKETS] = "telnet.socket enabled disabled\n"
        self.assertEqual(self.checks(values)["SERVICES-003"].status, "WARN")

    def test_positive_legacy_evidence_survives_other_collection_failure(self):
        values = outputs()
        values[RUNNING] = "vsftpd.service loaded active running FTP server\n"
        del values[SOCKETS]
        self.assertEqual(self.checks(values)["SERVICES-003"].status, "WARN")

    def test_failed_unit_bullet_and_description_are_handled(self):
        values = outputs()
        values[FAILED] = "● auditd.service loaded failed failed Security Auditing Service\n"
        finding = self.checks(values)["SERVICES-004"]
        self.assertEqual(finding.status, "WARN")
        self.assertIn("auditd.service", finding.evidence)

    def test_command_errors_are_unknown(self):
        values = {key: CommandResult(key, 1, "", "System has not been booted with systemd") for key in outputs()}
        self.assertTrue(all(item.status == "UNKNOWN" for item in self.checks(values).values()))

    def test_malformed_listing_is_unknown(self):
        values = outputs()
        values[RUNNING] = "not a valid listing\n"
        self.assertEqual(self.checks(values)["SERVICES-001"].status, "UNKNOWN")

    def test_runtime_enabled_units_and_template_instances(self):
        values = outputs()
        values[ENABLED] = "telnet@tty1.service enabled-runtime -\n"
        self.assertEqual(self.checks(values)["SERVICES-003"].status, "WARN")

    def test_contradictory_inventory_state_is_unknown(self):
        values = outputs()
        values[RUNNING] = "ssh.service loaded inactive dead SSH\n"
        self.assertEqual(self.checks(values)["SERVICES-001"].status, "UNKNOWN")
        self.assertEqual(self.checks(values)["SERVICES-003"].status, "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
