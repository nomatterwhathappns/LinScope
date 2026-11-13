import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

from linscope.core import Context
from linscope.checks import filesystem


class FixtureContext(Context):
    def stat(self, path):
        result = super().stat(path)
        return SimpleNamespace(st_mode=result.st_mode, st_uid=0, st_gid=0)


class FilesystemTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.ctx = FixtureContext(root=self.root)
        for path in ("tmp", "var/tmp", "dev/shm", "proc/self", "etc"):
            (self.root / path).mkdir(parents=True, exist_ok=True)
        for path in ("tmp", "var/tmp", "dev/shm"):
            (self.root / path).chmod(0o1777)
        self.write("etc/fstab", "# fixture\n")

    def write(self, path, text):
        (self.root / path).write_text(text)

    def findings(self):
        return {finding.id: finding for finding in filesystem.run(self.ctx)}

    def test_effective_inherited_mount_not_separate_mount_assumption(self):
        self.write("proc/self/mountinfo", "1 0 0:1 / / rw,nosuid,nodev,noexec - overlay overlay rw\n")
        findings = self.findings()
        for check_id in ("FILESYSTEM-001", "FILESYSTEM-002", "FILESYSTEM-003"):
            self.assertEqual(findings[check_id].status, "PASS")
            self.assertIn("uses mount /;", findings[check_id].evidence)

    def test_specific_mount_overrides_root_options(self):
        self.write("proc/self/mountinfo", "1 0 0:1 / / rw,nodev,nosuid,noexec - ext4 /dev/x rw\n"
                   "2 1 0:2 / /tmp rw - tmpfs tmpfs rw\n")
        self.assertEqual(self.findings()["FILESYSTEM-001"].status, "WARN")
        self.assertEqual(self.findings()["FILESYSTEM-002"].status, "PASS")

    def test_mount_prefix_must_be_path_component(self):
        mounts = filesystem.parse_mountinfo("1 0 0:1 / / rw - ext4 /dev/x rw\n"
                                            "2 1 0:2 / /tmp-other rw,nodev - tmpfs tmpfs rw\n")
        self.assertEqual(filesystem.effective_mount(mounts, "/tmp")[0], "/")

    def test_stacked_mount_ambiguous_unknown(self):
        self.write("proc/self/mountinfo", "1 0 0:1 / / rw,nodev,nosuid,noexec - ext4 /dev/x rw\n"
                   "2 1 0:2 / /tmp rw,nodev,nosuid - tmpfs tmpfs rw\n"
                   "3 2 0:3 / /tmp rw - tmpfs tmpfs rw\n")
        self.assertEqual(self.findings()["FILESYSTEM-001"].status, "UNKNOWN")

    def test_symlink_target_mount_restrictions_used(self):
        (self.root / "tmp").rmdir()
        (self.root / "unsafe/temp").mkdir(parents=True)
        (self.root / "tmp").symlink_to("unsafe/temp", target_is_directory=True)
        self.write("proc/self/mountinfo", "1 0 0:1 / / rw,nodev,nosuid,noexec - ext4 /dev/x rw\n"
                   "2 1 0:2 / /unsafe rw - tmpfs tmpfs rw\n")
        finding = self.findings()["FILESYSTEM-001"]
        self.assertEqual(finding.status, "WARN")
        self.assertIn("uses mount /unsafe;", finding.evidence)

    def test_dev_shm_symlink_to_run_shm(self):
        (self.root / "dev/shm").rmdir()
        (self.root / "run/shm").mkdir(parents=True)
        (self.root / "dev/shm").symlink_to("../run/shm", target_is_directory=True)
        self.write("proc/self/mountinfo", "1 0 0:1 / / rw - ext4 /dev/x rw\n"
                   "2 1 0:2 / /run/shm rw,nodev,nosuid,noexec - tmpfs tmpfs rw\n")
        finding = self.findings()["FILESYSTEM-003"]
        self.assertEqual(finding.status, "PASS")
        self.assertIn("uses mount /run/shm;", finding.evidence)

    def test_symlink_outside_fixture_root_is_unknown(self):
        (self.root / "tmp").rmdir()
        (self.root / "tmp").symlink_to("/tmp", target_is_directory=True)
        self.write("proc/self/mountinfo", "1 0 0:1 / / rw,nodev,nosuid,noexec - ext4 /dev/x rw\n")
        self.assertEqual(self.findings()["FILESYSTEM-001"].status, "UNKNOWN")

    def test_malformed_table_never_passes(self):
        self.write("proc/self/mountinfo", "garbage\n")
        self.assertEqual(self.findings()["FILESYSTEM-001"].status, "UNKNOWN")

    def test_missing_table_unknown(self):
        self.assertEqual(self.findings()["FILESYSTEM-001"].status, "UNKNOWN")

    def test_missing_target_is_skipped(self):
        (self.root / "dev/shm").rmdir()
        self.assertEqual(self.findings()["FILESYSTEM-003"].status, "SKIP")

    def test_world_writable_temp_requires_sticky_bit(self):
        (self.root / "tmp").chmod(0o777)
        self.assertEqual(self.findings()["FILESYSTEM-004"].status, "FAIL")
        (self.root / "tmp").chmod(0o1777)
        self.assertEqual(self.findings()["FILESYSTEM-004"].status, "PASS")

    def test_fstab_group_write_flagged_without_reading_contents(self):
        (self.root / "etc/fstab").chmod(0o664)
        finding = self.findings()["FILESYSTEM-005"]
        self.assertEqual(finding.status, "FAIL")
        self.assertNotIn("fixture", finding.evidence)

    def test_container_unmapped_owner_unknown(self):
        self.ctx.profile = "container"
        original = self.ctx.stat
        self.ctx.stat = lambda path: SimpleNamespace(st_mode=original(path).st_mode, st_uid=65534, st_gid=65534)
        findings = self.findings()
        self.assertEqual(findings["FILESYSTEM-004"].status, "UNKNOWN")
        self.assertEqual(findings["FILESYSTEM-005"].status, "UNKNOWN")
        (self.root / "tmp").chmod(0o777)
        self.assertEqual(self.findings()["FILESYSTEM-004"].status, "FAIL")

    def test_mount_escape_decoding(self):
        mounts = filesystem.parse_mountinfo("1 0 0:1 / /space\\040dir rw,nodev - tmpfs tmpfs rw\n")
        self.assertEqual(mounts[0][0], "/space dir")


if __name__ == "__main__":
    unittest.main()
