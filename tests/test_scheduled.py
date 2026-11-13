from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

from linscope.core import CommandResult, Context
from linscope.checks import scheduled


class FixtureContext(Context):
    def __init__(self, root):
        super().__init__(root=root)
        self.commands = {}

    def stat(self, path):
        result = super().stat(path)
        return SimpleNamespace(st_mode=result.st_mode, st_uid=0, st_gid=0)

    def command(self, argv, timeout=8):
        return self.commands.get(tuple(argv), CommandResult(tuple(argv), None, error="fixture command unavailable"))


class ScheduledTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.root.chmod(0o755)
        self.ctx = FixtureContext(self.root)

    def write(self, path, text="", mode=0o644):
        path = self.root / path.lstrip("/")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        path.chmod(mode)

    def command(self, argv, text="", code=0):
        self.ctx.commands[tuple(argv)] = CommandResult(tuple(argv), code, stdout=text)

    def findings(self):
        return {finding.id: finding for finding in scheduled.run(self.ctx)}

    def test_crontab_permissions(self):
        self.write("/etc/crontab", "# fixture\n")
        self.assertEqual(self.findings()["SCHEDULED-001"].status, "PASS")
        (self.root / "etc/crontab").chmod(0o666)
        self.assertEqual(self.findings()["SCHEDULED-001"].status, "FAIL")

    def test_cron_d_file_permissions(self):
        self.write("/etc/cron.d/task", "# fixture\n", mode=0o664)
        self.assertEqual(self.findings()["SCHEDULED-002"].status, "FAIL")

    def test_empty_cron_directories_proven_absent_skip(self):
        findings = self.findings()
        self.assertEqual(findings["SCHEDULED-001"].status, "SKIP")
        self.assertEqual(findings["SCHEDULED-002"].status, "SKIP")

    def test_directory_in_place_of_crontab_is_unknown(self):
        (self.root / "etc/crontab").mkdir(parents=True)
        self.assertEqual(self.findings()["SCHEDULED-001"].status, "UNKNOWN")

    def test_special_task_file_is_not_read(self):
        import os
        (self.root / "etc/cron.d").mkdir(parents=True)
        os.mkfifo(self.root / "etc/cron.d/pipe")
        self.assertEqual(self.findings()["SCHEDULED-003"].status, "UNKNOWN")

    def test_root_executable_and_ancestors_checked(self):
        self.write("/etc/crontab", "* * * * * root /opt/jobs/task --secret=fixture\n")
        self.write("/opt/jobs/task", "# fixture", mode=0o755)
        self.assertEqual(self.findings()["SCHEDULED-003"].status, "PASS")
        (self.root / "opt/jobs").chmod(0o777)
        finding = self.findings()["SCHEDULED-003"]
        self.assertEqual(finding.status, "FAIL")
        self.assertNotIn("secret", finding.evidence)

    def test_container_unmapped_owner_unknown_not_fail(self):
        self.write("/etc/crontab", "# fixture\n")
        self.ctx.profile = "container"
        original = self.ctx.stat
        self.ctx.stat = lambda path: SimpleNamespace(st_mode=original(path).st_mode, st_uid=65534, st_gid=65534)
        self.assertEqual(self.findings()["SCHEDULED-001"].status, "UNKNOWN")
        (self.root / "etc/crontab").chmod(0o666)
        self.assertEqual(self.findings()["SCHEDULED-001"].status, "FAIL")

    def test_unresolved_shell_never_false_pass(self):
        self.write("/etc/crontab", "* * * * * root test -x /opt/task && /opt/task\n")
        self.assertEqual(self.findings()["SCHEDULED-003"].status, "UNKNOWN")

    def test_executable_symlink_target_ancestor_is_checked(self):
        self.write("/etc/crontab", "* * * * * root /opt/task\n")
        self.write("/unsafe/task", "# fixture", mode=0o755)
        (self.root / "unsafe").chmod(0o777)
        (self.root / "opt").mkdir()
        (self.root / "opt/task").symlink_to("../unsafe/task")
        self.assertEqual(self.findings()["SCHEDULED-003"].status, "FAIL")

    def test_executable_parent_symlink_target_ancestor_is_checked(self):
        self.write("/etc/crontab", "* * * * * root /opt/task\n")
        self.write("/unsafe/task", "# fixture", mode=0o755)
        (self.root / "unsafe").chmod(0o777)
        (self.root / "opt").symlink_to("unsafe", target_is_directory=True)
        self.assertEqual(self.findings()["SCHEDULED-003"].status, "FAIL")

    def test_fixture_symlink_escape_is_unknown(self):
        self.write("/etc/crontab", "* * * * * root /opt/task\n")
        (self.root / "opt").mkdir()
        (self.root / "opt/task").symlink_to("/usr/bin/true")
        self.assertEqual(self.findings()["SCHEDULED-003"].status, "UNKNOWN")

    def test_parser_handles_environment_comments_macro_and_nonroot(self):
        paths, unresolved = scheduled.root_cron_executables(
            "# text\nPATH=/usr/bin\n@reboot root /opt/task --flag\n"
            "* * * * * alice /opt/other\n")
        self.assertEqual(paths, ["/opt/task"])
        self.assertEqual(unresolved, 0)

    def test_shell_expansion_partial_result_is_unknown(self):
        paths, unresolved = scheduled.root_cron_executables("* * * * * root /opt/task $TOKEN\n")
        self.assertEqual(paths, ["/opt/task"])
        self.assertEqual(unresolved, 1)

    def test_missing_executable_unknown(self):
        self.write("/etc/crontab", "* * * * * root /missing/task\n")
        self.assertEqual(self.findings()["SCHEDULED-003"].status, "UNKNOWN")

    def test_timer_unavailable_unknown(self):
        findings = self.findings()
        self.assertEqual(findings["SCHEDULED-004"].status, "UNKNOWN")
        self.assertEqual(findings["SCHEDULED-005"].status, "UNKNOWN")

    def test_no_timers_proven_empty_skips_metadata_check(self):
        self.command(["systemctl", "list-timers", "--all", "--no-legend", "--no-pager"])
        findings = self.findings()
        self.assertEqual(findings["SCHEDULED-004"].status, "INFO")
        self.assertEqual(findings["SCHEDULED-005"].status, "SKIP")

    def timer(self):
        self.command(["systemctl", "list-timers", "--all", "--no-legend", "--no-pager"],
                     "- - - - fixture.timer fixture.service\n")
        self.command(["systemctl", "show", "--property=FragmentPath,DropInPaths,Unit", "--", "fixture.timer"],
                     "FragmentPath=/etc/systemd/system/fixture.timer\nDropInPaths=\nUnit=fixture.service\n")
        self.command(["systemctl", "show", "--property=FragmentPath,DropInPaths", "--", "fixture.service"],
                     "FragmentPath=/etc/systemd/system/fixture.service\nDropInPaths=\n")
        self.write("/etc/systemd/system/fixture.timer")
        self.write("/etc/systemd/system/fixture.service")

    def test_timer_and_activated_service_permissions_checked(self):
        self.timer()
        self.assertEqual(self.findings()["SCHEDULED-005"].status, "PASS")
        (self.root / "etc/systemd/system/fixture.service").chmod(0o666)
        self.assertEqual(self.findings()["SCHEDULED-005"].status, "FAIL")

    def test_timer_service_fragment_symlink_target_ancestor_checked(self):
        self.timer()
        self.write("/unsafe/fixture.service", mode=0o644)
        (self.root / "unsafe").chmod(0o777)
        (self.root / "etc/systemd/system/fixture.service").unlink()
        (self.root / "etc/systemd/system/fixture.service").symlink_to("../../../unsafe/fixture.service")
        self.assertEqual(self.findings()["SCHEDULED-005"].status, "FAIL")

    def test_incomplete_service_metadata_unknown(self):
        self.timer()
        self.command(["systemctl", "show", "--property=FragmentPath,DropInPaths", "--", "fixture.service"],
                     "FragmentPath=\nDropInPaths=\n")
        self.assertEqual(self.findings()["SCHEDULED-005"].status, "UNKNOWN")

    def test_unrecognized_timer_listing_unknown(self):
        self.command(["systemctl", "list-timers", "--all", "--no-legend", "--no-pager"], "unexpected format\n")
        self.assertEqual(self.findings()["SCHEDULED-004"].status, "UNKNOWN")

    def test_large_inventory_unknown(self):
        self.command(["systemctl", "list-timers", "--all", "--no-legend", "--no-pager"],
                     "\n".join(f"- - - - fixture{i}.timer fixture{i}.service" for i in range(51)))
        self.assertEqual(self.findings()["SCHEDULED-004"].status, "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
