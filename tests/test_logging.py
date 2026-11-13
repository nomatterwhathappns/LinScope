import stat
import unittest
from types import SimpleNamespace

from linscope.checks import logging
from linscope.core import CommandResult


class FakeContext:
    profile = "server"

    def __init__(self):
        self.journal = CommandResult((), 0, "# /etc/systemd/journald.conf\n[Journal]\nStorage=persistent\n")
        self.clock = CommandResult((), 0, "NTP=yes\nNTPSynchronized=yes\n")
        self.unit_states = {
            "systemd-journald.service": "LoadState=loaded\nActiveState=active\n",
            "rsyslog.service": "LoadState=not-found\nActiveState=inactive\n",
            "syslog-ng.service": "LoadState=not-found\nActiveState=inactive\n",
            "auditd.service": "LoadState=loaded\nActiveState=active\n",
        }
        self.files = {
            "/var/log": SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0),
            "/var/log/journal": SimpleNamespace(st_mode=stat.S_IFDIR | 0o2755, st_uid=0),
            "/etc/logrotate.conf": SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_uid=0),
        }

    def stat(self, path):
        result = self.files.get(path, FileNotFoundError(path))
        if isinstance(result, Exception):
            raise result
        return result

    def command(self, argv, **kwargs):
        if argv[0] == "systemd-analyze":
            return self.journal
        if argv[0] == "timedatectl":
            return self.clock
        state = self.unit_states.get(argv[2])
        if state is None:
            return CommandResult(tuple(argv), 1, stderr="not systemd")
        return CommandResult(tuple(argv), 0, state)


class LoggingTests(unittest.TestCase):
    def findings(self, ctx):
        return {f.id: f for f in logging.run(ctx)}

    def test_supported_configuration(self):
        result = self.findings(FakeContext())
        self.assertEqual(7, len(result))
        self.assertTrue(all(f.status == "PASS" for id, f in result.items() if id != "LOGGING-007"))
        self.assertEqual("INFO", result["LOGGING-007"].status)

    def test_last_storage_override_wins(self):
        ctx = FakeContext()
        ctx.journal = CommandResult((), 0,
            "[Journal]\nStorage=persistent\n# drop-in\n[Journal]\nStorage=volatile\n")
        self.assertEqual("WARN", self.findings(ctx)["LOGGING-002"].status)

    def test_unrelated_section_does_not_override(self):
        ctx = FakeContext()
        ctx.journal = CommandResult((), 0, "[Journal]\nStorage=persistent\n[Other]\nStorage=none\n")
        self.assertEqual("PASS", self.findings(ctx)["LOGGING-002"].status)

    def test_auto_requires_real_directory(self):
        ctx = FakeContext()
        ctx.journal = CommandResult((), 0, "[Journal]\nStorage=auto\n")
        self.assertEqual("PASS", self.findings(ctx)["LOGGING-002"].status)
        ctx.files["/var/log/journal"] = FileNotFoundError("missing")
        self.assertEqual("WARN", self.findings(ctx)["LOGGING-002"].status)
        ctx.files["/var/log/journal"] = PermissionError("denied")
        self.assertEqual("UNKNOWN", self.findings(ctx)["LOGGING-002"].status)
        ctx.files["/var/log/journal"] = SimpleNamespace(st_mode=stat.S_IFREG | 0o600)
        self.assertEqual("WARN", self.findings(ctx)["LOGGING-002"].status)

    def test_malformed_unknown_or_missing_commands_never_pass(self):
        ctx = FakeContext()
        ctx.journal = CommandResult((), None, error="command unavailable")
        ctx.clock = CommandResult((), 1, stderr="not systemd")
        ctx.unit_states = {}
        result = self.findings(ctx)
        for id in ("LOGGING-001", "LOGGING-002", "LOGGING-005", "LOGGING-006", "LOGGING-007"):
            self.assertEqual("UNKNOWN", result[id].status)

    def test_inactive_audit_profile_context(self):
        ctx = FakeContext()
        ctx.unit_states["auditd.service"] = "LoadState=not-found\nActiveState=inactive\n"
        self.assertEqual("WARN", self.findings(ctx)["LOGGING-005"].status)
        ctx.profile = "container"
        self.assertEqual("INFO", self.findings(ctx)["LOGGING-005"].status)

    def test_unknown_candidate_service_prevents_clean_negative_conclusion(self):
        ctx = FakeContext()
        ctx.unit_states["systemd-journald.service"] = "LoadState=loaded\nActiveState=inactive\n"
        del ctx.unit_states["rsyslog.service"]
        self.assertEqual("UNKNOWN", self.findings(ctx)["LOGGING-001"].status)

    def test_unsafe_configuration_permissions_warn(self):
        ctx = FakeContext()
        ctx.files["/var/log"] = SimpleNamespace(st_mode=stat.S_IFDIR | 0o777, st_uid=0)
        ctx.files["/etc/logrotate.conf"] = SimpleNamespace(st_mode=stat.S_IFREG | 0o664, st_uid=0)
        result = self.findings(ctx)
        self.assertEqual("WARN", result["LOGGING-003"].status)
        self.assertEqual("WARN", result["LOGGING-004"].status)

    def test_unsynchronized_clock_warns(self):
        ctx = FakeContext()
        ctx.clock = CommandResult((), 0, "NTP=yes\nNTPSynchronized=no\n")
        self.assertEqual("WARN", self.findings(ctx)["LOGGING-006"].status)


if __name__ == "__main__":
    unittest.main()
