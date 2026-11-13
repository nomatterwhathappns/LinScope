import contextlib
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from linscope.core import Context, Finding
from linscope.cli import collect, main, write_output


class CoreTests(unittest.TestCase):
    def test_invalid_finding_rejected(self):
        with self.assertRaises(ValueError):
            Finding("X-1", "x", "test", "SAFE", "high", "", "")

    def test_fixture_command_does_not_run_on_host(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = Context(root=Path(tmp)).command(["id"])
            self.assertFalse(result.ok)
            self.assertIn("disabled", result.error)

    def test_large_file_is_not_partially_evaluated(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "test").write_text("abcdef")
            with self.assertRaises(OSError):
                Context(root=Path(tmp)).read("/test", limit=3)

    def test_fifo_is_rejected_without_waiting_for_writer(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.mkfifo(Path(tmp, "fifo"))
            with self.assertRaises(OSError):
                Context(root=Path(tmp)).read("/fifo")

    def test_path_traversal_rejected(self):
        with self.assertRaises(ValueError):
            Context().path("/etc/../shadow")

    def test_missing_command_is_unknown_evidence(self):
        result = Context().command(["linscope-command-that-does-not-exist"])
        self.assertIsNone(result.returncode)
        self.assertFalse(result.ok)

    def test_glob_permission_denied_propagates(self):
        with patch("linscope.core.os.scandir", side_effect=PermissionError("denied")):
            with self.assertRaises(PermissionError):
                Context().glob("/etc/*")

    def test_glob_missing_directory_and_bounded_matches(self):
        with tempfile.TemporaryDirectory() as tmp:
            ctx = Context(root=Path(tmp))
            self.assertEqual(ctx.glob("/missing/*"), [])
            Path(tmp, "one.conf").touch()
            Path(tmp, "two.conf").touch()
            self.assertEqual(ctx.glob("/*.conf"), ["/one.conf", "/two.conf"])
            with self.assertRaises(OSError):
                ctx.glob("/*.conf", limit=1)

    def test_fixture_symlink_escape_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "escape").symlink_to("/etc")
            with self.assertRaises(OSError):
                Context(root=Path(tmp)).read("/escape/passwd")

    def test_collector_exception_is_visible_and_other_collectors_continue(self):
        good = Finding("OK-001", "good", "Works", "PASS", "info", "evidence", "review")
        def broken(ctx):
            raise RuntimeError("fixture error")
        with patch("linscope.cli.CHECKS", {"bad": broken, "good": lambda _: [good]}):
            report = collect(Context(), ["bad", "good"])
        self.assertEqual([f["status"] for f in report["findings"]], ["UNKNOWN", "PASS"])

    def test_output_is_private_and_never_overwrites(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "report.json")
            write_output("first", path)
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                write_output("second", path)
            self.assertEqual(Path(path).read_text(), "first")

    def test_output_does_not_follow_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp, "target")
            target.write_text("keep")
            link = Path(tmp, "link")
            link.symlink_to(target)
            with self.assertRaises(FileExistsError):
                write_output("changed", str(link))
            self.assertEqual(target.read_text(), "keep")

    def test_terminal_control_codes_removed(self):
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            write_output("test\x1b[31m\x00\n", None)
        self.assertNotIn("\x1b", stream.getvalue())
        self.assertNotIn("\x00", stream.getvalue())

    def test_fail_on_does_not_treat_info_as_vulnerability(self):
        report = {"findings": [{"status": "INFO", "severity": "critical"}]}
        with patch("linscope.cli.collect", return_value=report), patch("linscope.cli.render_text", return_value=""), patch("linscope.cli.platform.system", return_value="Linux"), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["--fail-on", "low"]), 0)

    def test_unknown_exit_policy(self):
        report = {"findings": [{"status": "UNKNOWN", "severity": "info"}]}
        with patch("linscope.cli.collect", return_value=report), patch("linscope.cli.render_text", return_value=""), patch("linscope.cli.platform.system", return_value="Linux"), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["--fail-on-unknown"]), 2)


if __name__ == "__main__":
    unittest.main()
