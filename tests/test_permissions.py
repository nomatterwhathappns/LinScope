import stat
from types import SimpleNamespace
import unittest
from linscope.checks import permissions


class PermissionContext:
    deep = False
    def __init__(self, overrides=None, group="root:x:0:\nshadow:x:42:\n"):
        self.overrides = overrides or {}
        self.group = group
    def stat(self, path):
        if path in self.overrides:
            item = self.overrides[path]
            if isinstance(item, Exception):
                raise item
            return item
        raise FileNotFoundError(path)
    def glob(self, pattern):
        return []
    def read(self, path):
        if path != "/etc/group":
            raise AssertionError("Must not read private file contents")
        return self.group


def metadata(mode, uid=0, gid=0, directory=False):
    return SimpleNamespace(st_mode=(stat.S_IFDIR if directory else stat.S_IFREG) | mode, st_uid=uid, st_gid=gid)


class PermissionsTests(unittest.TestCase):
    def finding(self, ctx, check_id):
        return next(f for f in permissions.run(ctx) if f.id == check_id)

    def test_shadow_group_read_only_for_trusted_group(self):
        self.assertEqual(self.finding(PermissionContext({"/etc/shadow": metadata(0o640, gid=42)}), "PERM-003").status, "PASS")
        self.assertEqual(self.finding(PermissionContext({"/etc/shadow": metadata(0o640, gid=1000)}), "PERM-003").status, "WARN")

    def test_world_readable_shadow_warns(self):
        self.assertEqual(self.finding(PermissionContext({"/etc/shadow": metadata(0o644)}), "PERM-003").status, "WARN")

    def test_nonroot_owner_warns(self):
        self.assertEqual(self.finding(PermissionContext({"/etc/passwd": metadata(0o644, uid=1000)}), "PERM-001").status, "WARN")

    def test_world_writable_temp_without_sticky_fails(self):
        self.assertEqual(self.finding(PermissionContext({"/tmp": metadata(0o777, directory=True)}), "PERM-008").status, "FAIL")
        self.assertEqual(self.finding(PermissionContext({"/tmp": metadata(0o1777, directory=True)}), "PERM-008").status, "PASS")

    def test_permission_denied_is_unknown(self):
        self.assertEqual(self.finding(PermissionContext({"/etc/shadow": PermissionError("denied")}), "PERM-003").status, "UNKNOWN")

    def test_temp_path_must_be_directory(self):
        self.assertEqual(self.finding(PermissionContext({"/tmp": metadata(0o1777)}), "PERM-008").status, "FAIL")

    def test_sticky_bit_does_not_protect_against_directory_owner(self):
        self.assertEqual(self.finding(PermissionContext({"/tmp": metadata(0o1777, uid=1000, directory=True)}), "PERM-008").status, "WARN")


if __name__ == "__main__":
    unittest.main()
