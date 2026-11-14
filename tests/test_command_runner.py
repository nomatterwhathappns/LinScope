"""Real synthetic subprocesses test streaming bounds and process-group cleanup."""
import os
from pathlib import Path
import signal
import selectors
import subprocess
import sys
import time
import unittest
from unittest.mock import patch

from linscope.core import COMMAND_OUTPUT_LIMIT, Context


def is_running(pid):
    """Killed orphan grandchildren may remain zombies until the init reaper runs."""
    try:
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    except (FileNotFoundError, ProcessLookupError):
        return False
    return fields[0] != "Z"


class CommandRunnerTests(unittest.TestCase):
    def run_code(self, code, timeout=3, context=None):
        return (context or Context()).command([sys.executable, "-c", code], timeout=timeout)

    def assert_stopped(self, pid):
        deadline = time.monotonic() + 2
        while is_running(pid) and time.monotonic() < deadline:
            time.sleep(0.01)
        if is_running(pid):
            # Keep failed tests from leaving their own synthetic child running.
            os.kill(pid, signal.SIGKILL)
            self.fail(f"Synthetic child {pid} remained running after collector cleanup")

    def test_success_captures_both_channels_and_preserves_unicode(self):
        result = self.run_code("import os; os.write(1,'café\\n'.encode()); os.write(2,b'diagnostic\\n')")
        self.assertTrue(result.ok, result.error)
        self.assertEqual(result.stdout, "café\n")
        self.assertEqual(result.stderr, "diagnostic\n")

    def test_nonzero_exit_preserves_output_without_claiming_success(self):
        result = self.run_code("import sys; print('PASS'); print('diagnostic',file=sys.stderr); sys.exit(7)")
        self.assertEqual(result.returncode, 7)
        self.assertFalse(result.ok)
        self.assertEqual(result.error, "")

    def test_dual_stream_output_does_not_deadlock_or_discard_evidence(self):
        result = self.run_code("import os\nfor _ in range(128):\n os.write(1,b'x'*4096); os.write(2,b'y'*4096)")
        self.assertTrue(result.ok, result.error)
        self.assertEqual(len(result.stdout), 524288)
        self.assertEqual(len(result.stderr), 524288)

    def test_exact_limit_on_both_channels_remains_valid(self):
        result = self.run_code(f"import sys; sys.stdout.buffer.write(b'x'*{COMMAND_OUTPUT_LIMIT}); sys.stderr.buffer.write(b'y'*{COMMAND_OUTPUT_LIMIT})")
        self.assertTrue(result.ok, result.error)
        self.assertEqual(len(result.stdout), COMMAND_OUTPUT_LIMIT)
        self.assertEqual(len(result.stderr), COMMAND_OUTPUT_LIMIT)

    def test_live_stdout_flood_is_stopped_at_limit(self):
        result = self.run_code("import os\nwhile True: os.write(1,b'x'*65536)", timeout=3)
        self.assertFalse(result.ok)
        self.assertIn("stdout exceeded", result.error)
        self.assertEqual(len(result.stdout), COMMAND_OUTPUT_LIMIT)

    def test_live_stderr_flood_is_stopped_at_limit(self):
        result = self.run_code("import os\nwhile True: os.write(2,b'y'*65536)", timeout=3)
        self.assertFalse(result.ok)
        self.assertIn("stderr exceeded", result.error)
        self.assertEqual(len(result.stderr), COMMAND_OUTPUT_LIMIT)

    def test_no_output_command_is_terminated_by_deadline(self):
        started = time.monotonic()
        result = self.run_code("import time; time.sleep(30)", timeout=0.2)
        self.assertFalse(result.ok)
        self.assertIn("timed out", result.error)
        self.assertLess(time.monotonic() - started, 3)

    def test_closed_pipes_do_not_allow_a_running_process_to_escape_timeout(self):
        result = self.run_code("import os,time; os.close(1); os.close(2); time.sleep(30)", timeout=0.2)
        self.assertFalse(result.ok)
        self.assertIn("timed out", result.error)

    def test_timeout_kills_child_holding_pipes_after_parent_exit(self):
        code = ("import subprocess,sys\n"
                "child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)'])\n"
                "print(child.pid,flush=True)\n")
        result = self.run_code(code, timeout=0.6)
        self.assertFalse(result.ok)
        self.assertIn("timed out", result.error)
        self.assert_stopped(int(result.stdout.strip()))

    def test_overflow_kills_child_writer_after_parent_exit(self):
        child = "import os,time; time.sleep(0.1)\nwhile True: os.write(1,b'x'*65536)"
        code = ("import subprocess,sys\n"
                f"child=subprocess.Popen([sys.executable,'-c',{child!r}])\n"
                "print(child.pid,flush=True)\n")
        result = self.run_code(code)
        self.assertFalse(result.ok)
        self.assertIn("stdout exceeded", result.error)
        self.assert_stopped(int(result.stdout.splitlines()[0]))

    def test_invalid_utf8_never_becomes_clean_evidence(self):
        for descriptor, channel in ((1, "stdout"), (2, "stderr")):
            with self.subTest(channel=channel):
                result = self.run_code(f"import os; os.write({descriptor},b'good\\xff')")
                self.assertFalse(result.ok)
                self.assertIn("not valid UTF-8", result.error)
                self.assertEqual(getattr(result, channel), "")

    def test_timeout_is_part_of_cache_identity(self):
        context = Context()
        args = [sys.executable, "-c", "print('fixture')"]
        with patch("linscope.core.subprocess.Popen", wraps=subprocess.Popen) as launch:
            first = context.command(args, timeout=2)
            again = context.command(args, timeout=2.0)
            other_budget = context.command(args, timeout=3)
        self.assertIs(first, again)
        self.assertIsNot(first, other_budget)
        self.assertEqual(launch.call_count, 2)

    def test_no_tempfile_capture_and_safe_launch_settings(self):
        with patch("tempfile.TemporaryFile", side_effect=AssertionError("Disk capture is forbidden")), \
                patch("linscope.core.subprocess.Popen", wraps=subprocess.Popen) as launch:
            result = self.run_code("print('fixture')")
        self.assertTrue(result.ok, result.error)
        settings = launch.call_args.kwargs
        self.assertTrue(settings["start_new_session"])
        self.assertTrue(settings["close_fds"])
        self.assertFalse(settings.get("shell", False))
        self.assertEqual(settings["stdin"], subprocess.DEVNULL)
        self.assertEqual(settings["env"]["PATH"], "/usr/sbin:/usr/bin:/sbin:/bin")
        self.assertNotIn("HOME", settings["env"])

    def test_launch_failure_is_visible(self):
        with patch("linscope.core.shutil.which", return_value="/nonexistent/tool"):
            result = Context().command(["fixture-tool"])
        self.assertFalse(result.ok)
        self.assertIn("FileNotFoundError", result.error)

    def test_selector_failure_terminates_and_reaps_direct_child(self):
        original_launch = subprocess.Popen
        launched = []
        def launch(*args, **kwargs):
            proc = original_launch(*args, **kwargs)
            launched.append(proc)
            return proc
        selector = selectors.DefaultSelector()
        with patch("linscope.core.selectors.DefaultSelector", return_value=selector), \
                patch.object(selector, "select", side_effect=OSError("synthetic collection failure")), \
                patch("linscope.core.subprocess.Popen", side_effect=launch):
            result = self.run_code("import time; time.sleep(30)")
        self.assertFalse(result.ok)
        self.assertIn("collection failed", result.error)
        self.assertEqual(len(launched), 1)
        self.assertIsNotNone(launched[0].returncode)
        self.assertTrue(launched[0].stdout.closed)
        self.assertTrue(launched[0].stderr.closed)
        with self.assertRaises(ChildProcessError):
            os.waitpid(launched[0].pid, os.WNOHANG)

    def test_user_interrupt_cleans_up_before_propagating(self):
        original_launch = subprocess.Popen
        launched = []
        def launch(*args, **kwargs):
            proc = original_launch(*args, **kwargs)
            launched.append(proc)
            return proc
        selector = selectors.DefaultSelector()
        with patch("linscope.core.selectors.DefaultSelector", return_value=selector), \
                patch.object(selector, "select", side_effect=KeyboardInterrupt), \
                patch("linscope.core.subprocess.Popen", side_effect=launch), \
                self.assertRaises(KeyboardInterrupt):
            self.run_code("import time; time.sleep(30)")
        self.assertIsNotNone(launched[0].returncode)
        self.assertTrue(launched[0].stdout.closed)
        self.assertTrue(launched[0].stderr.closed)

    def test_invalid_arguments_and_timeouts_do_not_launch(self):
        with patch("linscope.core.subprocess.Popen") as launch:
            for args in ([], "echo", [""], [None], ["a\x00b"], None):
                with self.subTest(args=args):
                    self.assertFalse(Context().command(args).ok)
            for timeout in (0, -1, True, None, float("inf"), float("nan"), "1", 10**1000):
                with self.subTest(timeout=timeout):
                    self.assertFalse(Context().command(["echo"], timeout=timeout).ok)
        launch.assert_not_called()


if __name__ == "__main__":
    unittest.main()
