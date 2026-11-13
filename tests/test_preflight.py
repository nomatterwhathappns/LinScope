import json
from pathlib import Path
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from linscope.preflight import inspect_capabilities, render_preflight_text, TRUSTED_PATH


class FakeContext:
    profile = "server"
    root = Path("/")

    def __init__(self, paths=None):
        self.paths = paths or {}
        self.accessed = []

    def path(self, path):
        return Path(path)

    def stat(self, path):
        self.accessed.append(path)
        result = self.paths.get(path, FileNotFoundError(path))
        if isinstance(result, Exception):
            raise result
        return result

    def read(self, path):
        raise AssertionError("Preflight must not open file contents")

    def command(self, *args, **kwargs):
        raise AssertionError("Preflight must not run commands")


def regular():
    return SimpleNamespace(st_mode=stat.S_IFREG | 0o600)


class PreflightTests(unittest.TestCase):
    def inspect(self, ctx=None, categories=("ssh",), which=None, accessible=True):
        with patch("linscope.preflight.shutil.which", side_effect=which or (lambda command, path: "/usr/bin/" + command)), patch("linscope.preflight.os.access", return_value=accessible):
            return inspect_capabilities(ctx or FakeContext(), categories)

    def test_discovers_selected_tools_without_executing_them(self):
        data = self.inspect(categories=("sudo", "docker", "network"))
        self.assertEqual({t["name"] for t in data["tools"]}, {"sudo", "docker", "ss", "ufw", "nft", "iptables", "ip6tables"})
        self.assertTrue(all(t["execution_verified"] is False for t in data["tools"]))
        self.assertIn("does not establish", " ".join(data["notes"]))

    def test_uses_fixed_trusted_executable_search_path(self):
        with patch("linscope.preflight.shutil.which", return_value=None) as which:
            inspect_capabilities(FakeContext(), ["ssh"])
        which.assert_called_once_with("sshd", path=TRUSTED_PATH)

    def test_shared_tools_are_deduplicated_with_category_mapping(self):
        data = self.inspect(categories=("services", "systemd", "logging"))
        systemctl = [tool for tool in data["tools"] if tool["name"] == "systemctl"]
        self.assertEqual(len(systemctl), 1)
        self.assertEqual(systemctl[0]["categories"], ["services", "systemd", "logging"])

    def test_fixture_filesystem_never_discovers_host_commands(self):
        ctx = FakeContext()
        ctx.root = Path("/fixture")
        with patch("linscope.preflight.shutil.which", side_effect=AssertionError("host discovery")):
            data = inspect_capabilities(ctx, ["ssh"])
        self.assertIsNone(data["tools"][0]["available"])

    def test_missing_tool_is_not_proof_of_security_state(self):
        data = self.inspect(which=lambda command, path: None)
        self.assertFalse(data["tools"][0]["available"])
        self.assertFalse(data["tools"][0]["execution_verified"])
        self.assertIn("unverified", data["tools"][0]["detail"])

    def test_content_read_access_is_advisory_effective_identity_only(self):
        ctx = FakeContext({"/etc/ssh/sshd_config": regular()})
        with patch("linscope.preflight.shutil.which", return_value=None), patch("linscope.preflight.os.access", return_value=False) as access:
            data = inspect_capabilities(ctx, ["ssh"])
        access.assert_called_once_with(Path("/etc/ssh/sshd_config"), 4, effective_ids=True)
        self.assertEqual(data["paths"][0]["state"], "unreadable")
        self.assertFalse(data["paths"][0]["read_access"])

    def test_shadow_paths_are_metadata_only(self):
        ctx = FakeContext({"/etc/shadow": regular(), "/etc/gshadow": regular()})
        with patch("linscope.preflight.shutil.which", return_value=None), patch("linscope.preflight.os.access", side_effect=AssertionError("No shadow content-access test")):
            data = inspect_capabilities(ctx, ["permissions"])
        self.assertTrue(all(p["state"] == "metadata-available" for p in data["paths"]))
        self.assertTrue(all(p["read_access"] is None for p in data["paths"]))

    def test_absent_and_permission_denied_are_distinct(self):
        ctx = FakeContext({"/etc/ssh/sshd_config": PermissionError("denied")})
        self.assertEqual(self.inspect(ctx)["paths"][0]["state"], "unreadable")
        self.assertEqual(self.inspect()["paths"][0]["state"], "absent")

    def test_special_file_is_not_marked_readable(self):
        ctx = FakeContext({"/etc/ssh/sshd_config": SimpleNamespace(st_mode=stat.S_IFIFO | 0o600)})
        data = self.inspect(ctx)
        self.assertEqual(data["paths"][0]["state"], "unknown")
        self.assertIsNone(data["paths"][0]["read_access"])

    def test_unsupported_effective_id_access_is_unknown(self):
        ctx = FakeContext({"/etc/ssh/sshd_config": regular()})
        with patch("linscope.preflight.shutil.which", return_value=None), patch("linscope.preflight.os.access", side_effect=NotImplementedError):
            data = inspect_capabilities(ctx, ["ssh"])
        self.assertEqual(data["paths"][0]["state"], "unknown")

    def test_directory_access_requires_read_and_search(self):
        ctx = FakeContext({"/var/lib/apt/lists": SimpleNamespace(st_mode=stat.S_IFDIR | 0o755)})
        with patch("linscope.preflight.shutil.which", return_value=None), patch("linscope.preflight.os.access", return_value=True) as access:
            data = inspect_capabilities(ctx, ["packages"])
        access.assert_called_once_with(Path("/var/lib/apt/lists"), 5, effective_ids=True)
        self.assertEqual(next(p for p in data["paths"] if p["path"].endswith("lists"))["state"], "readable")

    def test_container_markers_are_hints_not_host_verification(self):
        ctx = FakeContext({"/.dockerenv": regular()})
        self.assertEqual(self.inspect(ctx)["container"]["state"], "hint-present")
        self.assertEqual(self.inspect()["container"]["state"], "not-detected")
        ctx = FakeContext({"/.dockerenv": PermissionError("denied")})
        self.assertEqual(self.inspect(ctx)["container"]["state"], "unknown")

    def test_identity_uses_real_and_effective_ids(self):
        with patch("linscope.preflight.os.getuid", return_value=1000), patch("linscope.preflight.os.geteuid", return_value=0):
            data = self.inspect()
        self.assertEqual(data["identity"], {"uid": 1000, "euid": 0, "is_root": True})

    def test_result_serializes_and_rendering_is_explicit(self):
        data = self.inspect(categories=("ssh", "sudo"))
        self.assertEqual(json.loads(json.dumps(data)), data)
        text = render_preflight_text(data)
        self.assertIn("TOOLS (not executed)", text)
        self.assertIn("contents not opened", text)
        self.assertIn("[ABSENT]", text)
        self.assertIn("No check commands were executed", text)

    def test_rendering_strips_terminal_controls(self):
        data = self.inspect()
        data["profile"] = "server\x1b[31m\r"
        self.assertNotIn("\x1b", render_preflight_text(data))
        self.assertNotIn("\r", render_preflight_text(data))

    def test_invalid_categories_rejected_without_inspection(self):
        with self.assertRaises(ValueError):
            self.inspect(categories=("not-a-category",))

    def test_category_selection_is_deduplicated(self):
        data = self.inspect(categories=("ssh", "ssh"))
        self.assertEqual(data["categories"], ["ssh"])
        self.assertEqual(len(data["tools"]), 1)


if __name__ == "__main__":
    unittest.main()
