import unittest
from types import SimpleNamespace
from unittest.mock import patch

from linscope.checks import packages
from linscope.core import CommandResult

NOW = 1_750_000_000


class FakeContext:
    profile = "server"

    def __init__(self):
        self.os_release = 'ID=ubuntu\nID_LIKE=debian\n'
        self.cache_paths = ["/var/lib/apt/lists/example_InRelease"]
        self.mtime = NOW - 3600
        self.reboot = FileNotFoundError("missing")
        self.inventory = CommandResult((), 0, "ii \nii \nrc \n")
        self.simulation = CommandResult((), 0,
            "Reading package lists... Done\n0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n")

    def read(self, path):
        if isinstance(self.os_release, Exception):
            raise self.os_release
        return self.os_release

    def glob(self, pattern):
        return self.cache_paths if pattern.endswith("_InRelease") else []

    def stat(self, path):
        if path == "/run/reboot-required":
            if isinstance(self.reboot, Exception):
                raise self.reboot
            return self.reboot
        if isinstance(self.mtime, Exception):
            raise self.mtime
        return SimpleNamespace(st_mtime=self.mtime)

    def command(self, argv, **kwargs):
        return self.inventory if argv[0] == "dpkg-query" else self.simulation


class PackageTests(unittest.TestCase):
    def findings(self, ctx):
        with patch("linscope.checks.packages.time.time", return_value=NOW):
            return {f.id: f for f in packages.run(ctx)}

    def test_fresh_zero_candidates_is_scoped_pass(self):
        result = self.findings(FakeContext())
        self.assertEqual("PASS", result["PACKAGES-002"].status)
        self.assertEqual("PASS", result["PACKAGES-003"].status)
        self.assertEqual("INFO", result["PACKAGES-004"].status)
        self.assertIn("2 packages", result["PACKAGES-001"].evidence)

    def test_stale_cache_cannot_produce_clean_upgrade_result(self):
        ctx = FakeContext()
        ctx.mtime = NOW - 8 * 86400
        result = self.findings(ctx)
        self.assertEqual("WARN", result["PACKAGES-002"].status)
        self.assertEqual("UNKNOWN", result["PACKAGES-003"].status)

    def test_no_metadata_cannot_produce_clean_upgrade_result(self):
        ctx = FakeContext()
        ctx.cache_paths = []
        self.assertEqual("UNKNOWN", self.findings(ctx)["PACKAGES-003"].status)

    def test_future_cache_and_unreadable_cache_unknown(self):
        for timestamp in (NOW + 3600, PermissionError("denied")):
            with self.subTest(timestamp=timestamp):
                ctx = FakeContext()
                ctx.mtime = timestamp
                self.assertEqual("UNKNOWN", self.findings(ctx)["PACKAGES-002"].status)

    def test_candidates_and_held_packages_reported(self):
        ctx = FakeContext()
        ctx.simulation = CommandResult((), 0,
            "Inst example [1.0] (1.1 example:stable [amd64])\n"
            "1 upgraded, 0 newly installed, 0 to remove and 2 not upgraded.\n")
        result = self.findings(ctx)["PACKAGES-003"]
        self.assertEqual("WARN", result.status)
        self.assertIn("2 held/not upgraded", result.evidence)

    def test_unrecognized_or_inconsistent_apt_output_unknown(self):
        for text in ("", "0 upgraded, 1 newly installed, 0 to remove and 0 not upgraded.\n"):
            with self.subTest(text=text):
                ctx = FakeContext()
                ctx.simulation = CommandResult((), 0, text)
                self.assertEqual("UNKNOWN", self.findings(ctx)["PACKAGES-003"].status)

    def test_failed_command_never_passes(self):
        ctx = FakeContext()
        ctx.simulation = CommandResult((), 100, "", "permission denied")
        ctx.inventory = CommandResult((), None, error="Missing")
        result = self.findings(ctx)
        self.assertEqual("UNKNOWN", result["PACKAGES-001"].status)
        self.assertEqual("UNKNOWN", result["PACKAGES-003"].status)

    def test_other_distribution_skipped_but_unreadable_os_unknown(self):
        ctx = FakeContext()
        ctx.os_release = "ID=fedora\n"
        self.assertTrue(all(f.status == "SKIP" for f in self.findings(ctx).values()))
        ctx.os_release = PermissionError("denied")
        self.assertTrue(all(f.status == "UNKNOWN" for f in self.findings(ctx).values()))

    def test_reboot_marker_honest_about_absence(self):
        ctx = FakeContext()
        absent = self.findings(ctx)["PACKAGES-004"]
        self.assertEqual("INFO", absent.status)
        self.assertIn("does not prove", absent.evidence)
        ctx.reboot = SimpleNamespace()
        self.assertEqual("WARN", self.findings(ctx)["PACKAGES-004"].status)


if __name__ == "__main__":
    unittest.main()
