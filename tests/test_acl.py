import stat
from types import SimpleNamespace
import unittest

from linscope.checks import acl
from linscope.core import CommandResult


def meta(mode=0o644, uid=0, gid=0, directory=False):
    return SimpleNamespace(st_mode=(stat.S_IFDIR if directory else stat.S_IFREG) | mode,
                           st_uid=uid, st_gid=gid)


class FakeContext:
    profile = "server"
    def __init__(self, path="/etc/passwd", output="user::rw-\ngroup::r--\nother::r--\n", metadata=None,
                 result=None, group="root:x:0:\nshadow:x:42:\n"):
        self.path = path
        self.output = output
        self.metadata = metadata or meta()
        self.result = result
        self.group = group
        self.calls = []
        self.reads = []

    def stat(self, path):
        if path != self.path:
            raise FileNotFoundError(path)
        if isinstance(self.metadata, Exception):
            raise self.metadata
        return self.metadata

    def read(self, path):
        self.reads.append(path)
        if path != "/etc/group":
            raise AssertionError("ACL checks must not read protected file contents")
        if isinstance(self.group, Exception):
            raise self.group
        return self.group

    def command(self, argv):
        self.calls.append(argv)
        return self.result or CommandResult(tuple(argv), 0, self.output)


class ACLTests(unittest.TestCase):
    def result(self, ctx, number=1):
        return next(item for item in acl.run(ctx) if item.id == acl._id(ctx.path, number))

    def test_basic_protected_public_file_passes(self):
        ctx = FakeContext()
        self.assertEqual(self.result(ctx).status, "PASS")
        self.assertEqual(ctx.calls, [["getfacl", "-cpn", "--", "/etc/passwd"]])
        self.assertEqual(ctx.reads, [])

    def test_named_write_masked_off_does_not_warn(self):
        ctx = FakeContext(output="user::rw-\nuser:1000:rw-\ngroup::r--\nmask::r--\nother::r--\n")
        self.assertEqual(self.result(ctx).status, "PASS")

    def test_named_write_effective_is_reported(self):
        ctx = FakeContext(output="user::rw-\nuser:1000:rw-\ngroup::r--\nmask::rw-\nother::r--\n", metadata=meta(0o664))
        self.assertEqual(self.result(ctx).status, "WARN")

    def test_other_entry_not_limited_by_mask(self):
        ctx = FakeContext(output="user::rw-\ngroup::rw-\nmask::---\nother::rw-\n", metadata=meta(0o606))
        self.assertEqual(self.result(ctx).status, "WARN")

    def test_root_named_entry_is_already_privileged(self):
        ctx = FakeContext(output="user::rw-\nuser:0:rwx\ngroup::r--\nmask::rwx\nother::r--\n", metadata=meta(0o674))
        self.assertEqual(self.result(ctx).status, "PASS")

    def test_shadow_named_user_read_is_reviewed(self):
        ctx = FakeContext(path="/etc/shadow", output="user::rw-\nuser:1000:r--\ngroup::r--\nmask::r--\nother::---\n", metadata=meta(0o640, gid=42))
        self.assertEqual(self.result(ctx).status, "WARN")
        self.assertEqual(set(ctx.reads), {"/etc/group"})

    def test_shadow_group_mask_controls_read(self):
        ctx = FakeContext(path="/etc/shadow", output="user::rw-\ngroup::r--\ngroup:1000:r--\nmask::---\nother::---\n", metadata=meta(0o600, gid=42))
        self.assertEqual(self.result(ctx).status, "PASS")

    def test_shadow_read_trusted_only_for_root_or_unique_shadow_gid(self):
        for gid, expected in ((0, "PASS"), (42, "PASS"), (1000, "WARN")):
            with self.subTest(gid=gid):
                ctx = FakeContext(path="/etc/shadow", output="user::rw-\ngroup::r--\nother::---\n", metadata=meta(0o640, gid=gid))
                self.assertEqual(self.result(ctx).status, expected)

    def test_duplicate_shadow_group_trust_is_unknown(self):
        ctx = FakeContext(path="/etc/shadow", output="user::rw-\ngroup::r--\nother::---\n", metadata=meta(0o640, gid=1000),
                          group="shadow:x:42:\nshadow:x:1000:someone\n")
        self.assertEqual(self.result(ctx).status, "UNKNOWN")

    def test_unknown_read_trust_does_not_hide_write(self):
        ctx = FakeContext(path="/etc/shadow", output="user::rw-\ngroup::rw-\nother::---\n", metadata=meta(0o660, gid=1000),
                          group=PermissionError("denied"))
        self.assertEqual(self.result(ctx).status, "WARN")

    def test_sudoers_named_read_requires_review(self):
        ctx = FakeContext(path="/etc/sudoers", output="user::r--\nuser:1000:r--\ngroup::r--\nmask::r--\nother::---\n", metadata=meta(0o440))
        self.assertEqual(self.result(ctx).status, "WARN")

    def test_missing_mask_with_named_entry_is_unknown(self):
        ctx = FakeContext(output="user::rw-\nuser:1000:r--\ngroup::r--\nother::r--\n")
        self.assertEqual(self.result(ctx).status, "UNKNOWN")

    def test_mode_and_acl_snapshot_disagreement_is_unknown(self):
        ctx = FakeContext(output="user::rw-\ngroup::rw-\nother::r--\n", metadata=meta(0o644))
        self.assertEqual(self.result(ctx).status, "UNKNOWN")

    def test_default_acl_is_inventory_unless_dangerous(self):
        base = "user::rwx\ngroup::r-x\nother::r-x\n"
        defaults = "default:user::rwx\ndefault:group::r-x\ndefault:other::r-x\n"
        ctx = FakeContext(path="/etc/ssh", output=base + defaults, metadata=meta(0o755, directory=True))
        self.assertEqual(self.result(ctx, 2).status, "INFO")
        ctx.output = base + defaults.replace("default:group::r-x", "default:group::rwx")
        self.assertEqual(self.result(ctx, 2).status, "WARN")

    def test_default_acl_on_regular_file_is_unknown(self):
        ctx = FakeContext(output="user::rw-\ngroup::r--\nother::r--\ndefault:user::rwx\ndefault:group::r-x\ndefault:other::r-x\n")
        self.assertEqual(self.result(ctx).status, "UNKNOWN")

    def test_missing_tool_and_partial_command_are_unknown(self):
        for result in (CommandResult((), None, error="getfacl unavailable"),
                       CommandResult((), 1, "user::rw-\ngroup::r--\nother::r--\n", "denied"),
                       CommandResult((), 0, "user::rw-\ngroup::r--\nother::r--\n", error="truncated")):
            with self.subTest(result=result):
                self.assertEqual(self.result(FakeContext(result=result)).status, "UNKNOWN")

    def test_unreadable_metadata_is_unknown_without_command(self):
        ctx = FakeContext(metadata=PermissionError("denied"))
        self.assertEqual(self.result(ctx).status, "UNKNOWN")
        self.assertEqual(ctx.calls, [])

    def test_optional_missing_target_skip_core_missing_unknown(self):
        results = {item.id: item for item in acl.run(FakeContext())}
        self.assertEqual(results[acl._id("/etc/sudoers")].status, "SKIP")
        self.assertEqual(results[acl._id("/etc/shadow")].status, "UNKNOWN")

    def test_malformed_acl_rejected(self):
        invalid = ("", "user::rw-\n", "user::rwx\nuser::rw-\ngroup::r--\nother::r--\n",
                   "user::rw-\ngroup::r--\nother::r--\nmask:100:r--", "user::rw-\nuser:alice:r--\ngroup::r--\nmask::r--\nother::r--",
                   "user::rw-\ngroup::r--\nother::rx-", "user::rw-\ngroup::r--\nother::r--\ngroup:4294967295:r--\nmask::r--")
        for output in invalid:
            with self.subTest(output=output), self.assertRaises(ValueError):
                acl.parse_acl(output)

    def test_effective_comments_are_not_trusted_instead_of_mask(self):
        ctx = FakeContext(output="user::rw-\nuser:1000:rw- #effective:rw-\ngroup::r--\nmask::r--\nother::r--\n")
        self.assertEqual(self.result(ctx).status, "PASS")

    def test_ids_stable_and_distinct(self):
        self.assertEqual(acl._id("/etc/passwd"), acl._id("/etc/passwd"))
        self.assertNotEqual(acl._id("/etc/passwd"), acl._id("/etc/group"))
        self.assertNotEqual(acl._id("/etc/ssh"), acl._id("/etc/ssh", 2))

    def test_numeric_qualifiers_are_canonical_and_cannot_duplicate(self):
        access, _ = acl.parse_acl("user::rw-\nuser:000:r--\ngroup::r--\nmask::r--\nother::r--\n")
        self.assertIn(("user", "0"), access)
        with self.assertRaises(ValueError):
            acl.parse_acl("user::rw-\nuser:001:r--\nuser:1:rw-\ngroup::r--\nmask::r--\nother::r--\n")


if __name__ == "__main__":
    unittest.main()
