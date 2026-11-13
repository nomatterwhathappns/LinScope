import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from linscope.checks import userfiles
from linscope.core import Context


class MetadataContext(Context):
    def read(self, path, *args, **kwargs):
        raise AssertionError("Credential contents must never be read")
    def command(self, argv, *args, **kwargs):
        raise AssertionError("User-file metadata checks need no commands")


class UserfilesTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.ctx = MetadataContext(root=self.root)
        self.ctx.user_paths = []
        self.uid = os.getuid()
        self.home = "/home/example"
        self.home_path = self.root / "home/example"
        self.home_path.mkdir(parents=True)
        self.identity_patch = patch("linscope.checks.userfiles._identity", return_value=(self.uid, self.home))
        self.identity_patch.start()
        self.addCleanup(self.identity_patch.stop)

    def file(self, path, mode=0o600):
        file = self.root / path.lstrip("/")
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text("synthetic content that must never be opened")
        file.chmod(mode)
        return file

    def values(self):
        return {finding.id: finding for finding in userfiles.run(self.ctx)}

    def finding(self, path):
        return self.values()[userfiles.path_id(path)]

    def test_absent_conventional_paths_skip(self):
        values = self.values()
        self.assertEqual(len(values), 6)
        self.assertTrue(all(finding.status == "SKIP" for finding in values.values()))

    def test_private_key_metadata_only_and_public_keys_excluded(self):
        self.file(self.home + "/.ssh/id_ed25519", 0o600)
        self.file(self.home + "/.ssh/id_ed25519.pub", 0o644)
        self.root.joinpath("home/example/.ssh").chmod(0o700)
        values = self.values()
        self.assertEqual(values[userfiles.path_id(self.home + "/.ssh/id_ed25519")].status, "PASS")
        self.assertNotIn(userfiles.path_id(self.home + "/.ssh/id_ed25519.pub"), values)

    def test_readable_private_key_warns(self):
        self.file(self.home + "/.ssh/id_ed25519", 0o644)
        self.assertEqual(self.finding(self.home + "/.ssh/id_ed25519").status, "WARN")

    def test_authorized_keys_can_be_publicly_readable_but_not_writable(self):
        path = self.home + "/.ssh/authorized_keys"
        item = self.file(path, 0o644)
        self.assertEqual(self.finding(path).status, "PASS")
        item.chmod(0o666)
        self.assertEqual(self.finding(path).status, "WARN")

    def test_explicit_selection_preserves_known_path_baseline_and_type(self):
        path = self.home + "/.ssh/authorized_keys"
        self.file(path, 0o644)
        self.ctx.user_paths = [path]
        self.assertEqual(self.finding(path).status, "PASS")
        self.ctx.user_paths = [self.home + "/.ssh"]
        item = self.home_path / ".ssh"
        item.joinpath("authorized_keys").unlink()
        item.rmdir()
        self.file(self.home + "/.ssh", 0o700)
        self.assertEqual(self.finding(self.home + "/.ssh").status, "WARN")

    def test_credential_files_and_parent_permissions(self):
        path = self.home + "/.aws/credentials"
        item = self.file(path)
        self.assertEqual(self.finding(path).status, "PASS")
        item.parent.chmod(0o777)
        self.assertEqual(self.finding(path).status, "WARN")

    def test_wrong_expected_type_never_passes(self):
        self.file(self.home + "/.ssh")
        self.assertEqual(self.finding(self.home + "/.ssh").status, "WARN")

    def test_explicit_missing_path_unknown(self):
        self.ctx.user_paths = ["/srv/credentials"]
        self.assertEqual(self.finding("/srv/credentials").status, "UNKNOWN")

    def test_explicit_directory_accepts_owner_execute(self):
        self.ctx.user_paths = ["/srv/private"]
        directory = self.root / "srv/private"
        directory.mkdir(parents=True)
        directory.chmod(0o700)
        self.assertEqual(self.finding("/srv/private").status, "PASS")

    def test_unsupported_explicit_paths_are_not_followed(self):
        for path in ("relative", "/home/../private", "/bad\x00path"):
            with self.subTest(path=path):
                self.ctx.user_paths = [path]
                results = userfiles.run(self.ctx)
                self.assertEqual(results[0].id, "USERFILE-000")
                self.assertEqual(results[0].status, "UNKNOWN")

    def test_too_many_explicit_paths_rejected(self):
        self.ctx.user_paths = [f"/file{number}" for number in range(51)]
        self.assertEqual(userfiles.run(self.ctx)[0].status, "UNKNOWN")

    def test_writable_symlink_target_parent_is_checked(self):
        target = self.file("/unsafe/credentials")
        target.parent.chmod(0o777)
        link = self.home_path / ".aws/credentials"
        link.parent.mkdir(parents=True)
        link.symlink_to("../../../unsafe/credentials")
        self.assertEqual(self.finding(self.home + "/.aws/credentials").status, "WARN")

    def test_dangling_symlink_is_unknown_not_absent(self):
        link = self.home_path / ".aws/credentials"
        link.parent.mkdir(parents=True)
        link.symlink_to("missing")
        self.assertEqual(self.finding(self.home + "/.aws/credentials").status, "UNKNOWN")

    def test_symlink_escape_is_unknown(self):
        link = self.home_path / ".aws/credentials"
        link.parent.mkdir(parents=True)
        link.symlink_to("/etc/passwd")
        self.assertEqual(self.finding(self.home + "/.aws/credentials").status, "UNKNOWN")

    def test_metadata_permission_error_unknown(self):
        original = self.ctx.stat
        def denied(path):
            if path == self.home + "/.aws/credentials":
                raise PermissionError("denied")
            return original(path)
        self.ctx.stat = denied
        self.assertEqual(self.finding(self.home + "/.aws/credentials").status, "UNKNOWN")

    def test_private_key_discovery_error_visible(self):
        with patch.object(self.ctx, "glob", side_effect=PermissionError("denied")):
            values = self.values()
        self.assertEqual(values["USERFILE-001"].status, "UNKNOWN")

    def test_home_identity_comes_from_real_uid_account_not_environment(self):
        self.identity_patch.stop()
        account = SimpleNamespace(pw_dir="/srv/actual")
        with patch("linscope.checks.userfiles.os.getuid", return_value=1234), patch("linscope.checks.userfiles.pwd.getpwuid", return_value=account) as getpw, patch.dict(os.environ, {"HOME": "/evil", "USER": "fake"}):
            self.assertEqual(userfiles._identity(), (1234, "/srv/actual"))
            getpw.assert_called_once_with(1234)

    def test_stable_path_ids(self):
        self.assertEqual(userfiles.path_id("/some/path"), userfiles.path_id("/some/path"))
        self.assertNotEqual(userfiles.path_id("/some/path"), userfiles.path_id("/other/path"))


if __name__ == "__main__":
    unittest.main()
