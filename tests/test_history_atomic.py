"""Fault injection and real process interruption around atomic publication."""
import ctypes
import errno
import multiprocessing
import os
from pathlib import Path
import signal
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from linscope import history
from linscope.core import Context
from linscope.rules import build_rules_snapshot
from tests.test_history import sample


def _pause_writer(directory, phase, ready):
    """Forked child deliberately pauses at an exact durability boundary."""
    original_fchmod = history.os.fchmod
    original_fsync = history.os.fsync
    original_publish = history._rename_noreplace

    def pause():
        ready.send(phase)
        ready.recv()  # Parent kills this process rather than releasing it.

    def fchmod(fd, mode):
        original_fchmod(fd, mode)
        if phase == "before-write":
            pause()

    def publish(*args):
        if phase == "before-publish":
            pause()
        return original_publish(*args)

    def fsync(fd):
        if phase == "after-publish" and stat.S_ISDIR(os.fstat(fd).st_mode):
            pause()
        return original_fsync(fd)

    with patch("linscope.history.os.fchmod", side_effect=fchmod), \
            patch("linscope.history.os.fsync", side_effect=fsync), \
            patch("linscope.history._rename_noreplace", side_effect=publish):
        history.save_report(directory, sample(status="PASS"))


class AtomicHistoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name, "history")
        self.previous = history.save_report(self.directory, sample())
        self.previous_bytes = self.previous.read_bytes()

    def assert_old_history_intact(self, count=1):
        self.assertEqual(self.previous.read_bytes(), self.previous_bytes)
        self.assertEqual(len(history.list_history(self.directory)), count)
        for path in self.directory.iterdir():
            if history._NAME.fullmatch(path.name):
                self.assertEqual(path.stat().st_nlink, 1)
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_data_sync_precedes_publication_and_directory_sync(self):
        original_sync = os.fsync
        original_publish = history._rename_noreplace
        events = []

        def fsync(fd):
            events.append("directory-sync" if stat.S_ISDIR(os.fstat(fd).st_mode) else "data-sync")
            return original_sync(fd)

        def publish(directory_fd, temporary_name, final_name):
            self.assertFalse(history._NAME.fullmatch(temporary_name))
            self.assertTrue(temporary_name.startswith(".linscope-pending-"))
            metadata = os.stat(temporary_name, dir_fd=directory_fd, follow_symlinks=False)
            self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o600)
            self.assertEqual(metadata.st_nlink, 1)
            events.append("publish")
            return original_publish(directory_fd, temporary_name, final_name)

        with patch("linscope.history.os.fsync", side_effect=fsync), \
                patch("linscope.history._rename_noreplace", side_effect=publish):
            result = history.save_report(self.directory, sample(status="PASS"))
        self.assertEqual(events, ["data-sync", "publish", "directory-sync"])
        self.assertEqual(result.stat().st_nlink, 1)
        self.assertEqual(len(list(self.directory.iterdir())), 2)
        self.assert_old_history_intact(count=2)

    def test_partial_write_failure_never_publishes_report(self):
        original_fdopen = os.fdopen

        class FailingWriter:
            def __init__(self, stream):
                self.stream = stream
            def __enter__(self):
                return self
            def __exit__(self, *args):
                self.stream.close()
            def fileno(self):
                return self.stream.fileno()
            def write(self, encoded):
                self.stream.write(encoded[:17])
                self.stream.flush()
                raise OSError(errno.ENOSPC, "Synthetic partial write")

        def fdopen(fd, mode):
            stream = original_fdopen(fd, mode)
            return FailingWriter(stream) if mode == "wb" else stream

        with patch("linscope.history.os.fdopen", side_effect=fdopen):
            with self.assertRaises(OSError):
                history.save_report(self.directory, sample(status="PASS"))
        self.assertEqual(list(self.directory.iterdir()), [self.previous])
        self.assert_old_history_intact()

    def test_file_wrapper_failure_does_not_leak_raw_descriptor(self):
        original_fdopen = os.fdopen
        captured = []
        def fdopen(fd, mode):
            if mode == "wb":
                captured.append(fd)
                raise OSError(errno.ENOMEM, "Synthetic file wrapper failure")
            return original_fdopen(fd, mode)
        with patch("linscope.history.os.fdopen", side_effect=fdopen):
            with self.assertRaises(OSError):
                history.save_report(self.directory, sample(status="PASS"))
        self.assertEqual(len(captured), 1)
        with self.assertRaises(OSError) as failure:
            os.fstat(captured[0])
        self.assertEqual(failure.exception.errno, errno.EBADF)
        self.assert_old_history_intact()

    def test_data_fsync_failure_cleans_unpublished_temporary_file(self):
        with patch("linscope.history.os.fsync", side_effect=OSError(errno.EIO, "Synthetic data sync error")):
            with self.assertRaises(OSError):
                history.save_report(self.directory, sample(status="PASS"))
        self.assertEqual(list(self.directory.iterdir()), [self.previous])
        self.assert_old_history_intact()

    def test_publication_error_cleans_temporary_and_preserves_old_reports(self):
        with patch("linscope.history._rename_noreplace", side_effect=OSError(errno.EPERM, "Synthetic publication error")):
            with self.assertRaises(OSError):
                history.save_report(self.directory, sample(status="PASS"))
        self.assertEqual(list(self.directory.iterdir()), [self.previous])
        self.assert_old_history_intact()

    def test_directory_sync_failure_keeps_complete_published_report(self):
        original_fsync = os.fsync
        def fsync(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError(errno.EIO, "Synthetic directory sync error")
            return original_fsync(fd)
        with patch("linscope.history.os.fsync", side_effect=fsync):
            with self.assertRaisesRegex(OSError, "published.*durability"):
                history.save_report(self.directory, sample(status="PASS"))
        self.assert_old_history_intact(count=2)
        self.assertEqual(history.latest_compatible(self.directory, sample())["findings"][0]["status"], "PASS")

    def test_missing_libc_primitive_has_no_overwriting_fallback(self):
        with patch("linscope.history.ctypes.CDLL", return_value=SimpleNamespace()):
            with self.assertRaisesRegex(OSError, "unavailable.*libc"):
                history.save_report(self.directory, sample(status="PASS"))
        self.assertEqual(list(self.directory.iterdir()), [self.previous])
        self.assert_old_history_intact()

    def test_kernel_or_filesystem_unsupported_is_explicit(self):
        class FailedRename:
            def __call__(self, *args):
                ctypes.set_errno(errno.ENOSYS)
                return -1
        with patch("linscope.history.ctypes.CDLL", return_value=SimpleNamespace(renameat2=FailedRename())):
            with self.assertRaisesRegex(OSError, "unsupported.*kernel/filesystem"):
                history.save_report(self.directory, sample(status="PASS"))
        self.assert_old_history_intact()
        self.assertEqual(list(self.directory.iterdir()), [self.previous])

    def test_atomic_primitive_refuses_existing_file_symlink_and_directory(self):
        directory_fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, directory_fd)
        for kind in ("file", "symlink", "directory"):
            with self.subTest(kind=kind):
                source = self.directory / (".pending-" + kind)
                target = self.directory / ("target-" + kind)
                source.write_bytes(b"new data")
                if kind == "file":
                    target.write_bytes(b"existing data")
                elif kind == "symlink":
                    target.symlink_to("does-not-exist")
                else:
                    target.mkdir()
                with self.assertRaises(FileExistsError):
                    history._rename_noreplace(directory_fd, source.name, target.name)
                self.assertEqual(source.read_bytes(), b"new data")
                if kind == "file":
                    self.assertEqual(target.read_bytes(), b"existing data")
                elif kind == "symlink":
                    self.assertTrue(target.is_symlink())
                else:
                    self.assertTrue(target.is_dir())

    def test_abandoned_hidden_temporary_is_ignored_and_does_not_block_saves(self):
        abandoned = self.directory / ".linscope-pending-abandoned.tmp"
        abandoned.write_bytes(b"half a report")
        abandoned.chmod(0o600)
        self.assert_old_history_intact()
        history.save_report(self.directory, sample(status="PASS"))
        self.assert_old_history_intact(count=2)
        self.assertEqual(abandoned.read_bytes(), b"half a report")

    def _kill_at_boundary(self, phase, expected_reports):
        context = multiprocessing.get_context("fork")
        parent, child = context.Pipe()
        process = context.Process(target=_pause_writer, args=(str(self.directory), phase, child))
        process.start()
        child.close()
        try:
            self.assertTrue(parent.poll(5), f"Writer did not reach {phase}")
            self.assertEqual(parent.recv(), phase)
            os.kill(process.pid, signal.SIGKILL)
            process.join(5)
            self.assertFalse(process.is_alive())
            self.assertEqual(process.exitcode, -signal.SIGKILL)
        finally:
            if process.is_alive():
                process.kill()
                process.join(5)
            parent.close()
            process.close()
        self.assert_old_history_intact(count=expected_reports)
        if phase != "after-publish":
            hidden = [path for path in self.directory.iterdir() if path.name.startswith(".linscope-pending-")]
            self.assertEqual(len(hidden), 1)

    def test_sigkill_during_temporary_write_keeps_old_history_listable(self):
        self._kill_at_boundary("before-write", 1)

    def test_sigkill_after_data_sync_but_before_publication_is_not_a_partial_report(self):
        self._kill_at_boundary("before-publish", 1)

    def test_sigkill_after_atomic_publication_leaves_a_complete_single_link_report(self):
        self._kill_at_boundary("after-publish", 2)

    def test_legacy_and_verified_rules_never_form_a_matching_baseline(self):
        verified = sample()
        verified["rules"] = build_rules_snapshot(Context(), ["ssh"])
        self.assertIsNone(history.latest_compatible(self.directory, verified))
        history.save_report(self.directory, verified)
        self.assertEqual(history.latest_compatible(self.directory, sample()), sample())

    def test_latest_compatible_skips_newer_different_rules(self):
        verified = sample()
        verified["rules"] = build_rules_snapshot(Context(), ["ssh"])
        history.save_report(self.directory, verified)
        changed = sample(status="PASS")
        changed["rules"] = build_rules_snapshot(Context(baseline={"SSH-005": {"max_attempts": 6}}), ["ssh"])
        history.save_report(self.directory, changed)
        self.assertEqual(history.latest_compatible(self.directory, verified), verified)
        self.assertEqual(history.latest_compatible(self.directory, changed), changed)

    def test_incomplete_rules_are_not_a_verified_comparison_baseline(self):
        original_open = Path.open
        def missing_source(path, *args, **kwargs):
            if path.name == "ssh.py":
                raise OSError("Synthetic missing rule source")
            return original_open(path, *args, **kwargs)
        incomplete = sample()
        with patch.object(Path, "open", missing_source):
            incomplete["rules"] = build_rules_snapshot(Context(), ["ssh"])
        self.assertFalse(incomplete["rules"]["complete"])
        history.save_report(self.directory, incomplete)
        self.assertIsNone(history.latest_compatible(self.directory, incomplete))


if __name__ == "__main__":
    unittest.main()
