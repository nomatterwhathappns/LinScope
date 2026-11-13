from copy import deepcopy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import stat
import tempfile
import threading
import unittest
from unittest.mock import patch

from linscope import history


def sample(host="example-host", status="WARN"):
    return {"schema_version": 1, "tool": {"name": "LinScope", "version": "1.6"},
            "generated_at": "2026-11-14T00:00:00+00:00",
            "host": {"name": host, "system": "Linux", "release": "example", "profile": "server"},
            "scope": {"checks": ["ssh"], "deep": False},
            "findings": [{"id": "SSH-001", "category": "ssh", "title": "Root login",
                          "status": status, "severity": "high", "evidence": "permitrootlogin yes",
                          "recommendation": "Review root access policy."}]}


class HistoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name, "history")

    def save(self, report=None):
        return history.save_report(self.directory, sample() if report is None else report)

    def corrupt(self, path, text):
        path.write_text(text, encoding="utf-8")
        path.chmod(0o600)

    def test_save_private_file_and_directory_without_mutation(self):
        report = sample()
        original = deepcopy(report)
        path = self.save(report)
        self.assertEqual(report, original)
        self.assertRegex(path.name, r"^linscope-[0-9]{8}T[0-9]{12}Z-[0-9a-f]{32}\.json$")
        self.assertEqual(stat.S_IMODE(self.directory.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(json.loads(path.read_text()), report)

    def test_missing_directory_lists_empty_without_creating(self):
        self.assertEqual(history.list_history(self.directory), [])
        self.assertIsNone(history.latest_compatible(self.directory, sample()))
        self.assertFalse(self.directory.exists())

    def test_directory_group_or_world_access_is_rejected_without_chmod(self):
        for mode in (0o755, 0o750, 0o770, 0o1777):
            with self.subTest(mode=mode):
                self.directory.mkdir(exist_ok=True)
                self.directory.chmod(mode)
                with self.assertRaises(ValueError):
                    history.list_history(self.directory)
                with self.assertRaises(ValueError):
                    self.save()
                self.assertEqual(stat.S_IMODE(self.directory.stat().st_mode), mode)

    def test_wrong_owner_directory_rejected(self):
        self.directory.mkdir(mode=0o700)
        with patch("linscope.history.os.geteuid", return_value=os.geteuid() + 1):
            with self.assertRaises(ValueError):
                history.list_history(self.directory)

    def test_final_directory_symlink_rejected_for_save_and_read(self):
        target = Path(self.temp.name, "target")
        target.mkdir(mode=0o700)
        self.directory.symlink_to(target, target_is_directory=True)
        for action in (lambda: self.save(), lambda: history.list_history(self.directory),
                       lambda: history.latest_compatible(self.directory, sample())):
            with self.subTest(action=action), self.assertRaises((OSError, ValueError)):
                action()
        self.assertEqual(list(target.iterdir()), [])

    def test_only_owned_filename_pattern_is_listed(self):
        path = self.save()
        (self.directory / "other.json").write_text("invalid")
        (self.directory / "report.json").symlink_to("/etc/shadow")
        os.mkfifo(self.directory / "unrelated-fifo")
        rows = history.list_history(self.directory)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["name"], path.name)
        self.assertEqual(rows[0]["host"], "example-host")
        self.assertEqual(rows[0]["profile"], "server")
        self.assertEqual(rows[0]["version"], "1.6")
        self.assertEqual(rows[0]["findings_count"], 1)
        self.assertEqual(rows[0]["path"], str(path))

    def test_file_permissions_or_hardlinks_are_rejected(self):
        path = self.save()
        path.chmod(0o644)
        with self.assertRaisesRegex(ValueError, path.name):
            history.list_history(self.directory)
        path.chmod(0o600)
        os.link(path, Path(self.temp.name, "second-link"))
        with self.assertRaisesRegex(ValueError, path.name):
            history.list_history(self.directory)

    def test_wrong_owner_report_rejected(self):
        path = self.save()
        original_fstat = os.fstat
        def owner_difference(fd):
            metadata = original_fstat(fd)
            if stat.S_ISREG(metadata.st_mode):
                values = list(metadata)
                values[4] = os.geteuid() + 1
                return os.stat_result(values)
            return metadata
        with patch("linscope.history.os.fstat", side_effect=owner_difference):
            with self.assertRaisesRegex(ValueError, path.name):
                history.list_history(self.directory)

    def test_owned_name_symlink_and_fifo_rejected_without_reading(self):
        path = self.save()
        path.unlink()
        path.symlink_to("/etc/shadow")
        with self.assertRaisesRegex(ValueError, path.name):
            history.list_history(self.directory)
        path.unlink()
        os.mkfifo(path, 0o600)
        with self.assertRaisesRegex(ValueError, path.name):
            history.list_history(self.directory)

    def test_corruption_not_hidden_by_limit_or_other_host(self):
        bad = self.save(sample("other-host"))
        self.save()
        self.corrupt(bad, "not json")
        with self.assertRaisesRegex(ValueError, bad.name):
            history.list_history(self.directory, limit=1)
        with self.assertRaisesRegex(ValueError, bad.name):
            history.latest_compatible(self.directory, sample())

    def test_save_rejects_corrupt_owned_history_before_adding_new_report(self):
        bad = self.save()
        self.corrupt(bad, "not json")
        before = list(self.directory.iterdir())
        with self.assertRaisesRegex(ValueError, bad.name):
            self.save()
        self.assertEqual(list(self.directory.iterdir()), before)

    def test_strict_json_rejects_duplicate_nonfinite_and_invalid_utf8(self):
        path = self.save()
        invalid = ['{"schema_version":1,"schema_version":1}',
                   json.dumps(sample()).replace('"version": "1.6"', '"version": NaN'),
                   json.dumps(dict(sample(), unused=1.0)).replace('"unused": 1.0', '"unused": 1e999')]
        for value in invalid:
            with self.subTest(value=value[:60]):
                self.corrupt(path, value)
                with self.assertRaisesRegex(ValueError, path.name):
                    history.list_history(self.directory)
        path.write_bytes(b"\xff")
        with self.assertRaisesRegex(ValueError, path.name):
            history.list_history(self.directory)

    def test_malformed_report_rejected_before_creating_history(self):
        invalid = [None, {}, dict(sample(), generated_at="wrong"),
                   dict(sample(), generated_at="2026-11-14T00:00:00"),
                   dict(sample(), tool={"name": "LinScope"}),
                   dict(sample(), unused=float("nan"))]
        for report in invalid:
            with self.subTest(report=report), self.assertRaises(ValueError):
                history.save_report(self.directory, report)
        self.assertFalse(self.directory.exists())

    def test_filename_save_time_determines_order(self):
        first = self.save(sample("first"))
        last = self.save(sample("last"))
        rows = history.list_history(self.directory, limit=1)
        self.assertEqual(rows[0]["name"], last.name)
        self.assertNotEqual(first.name, last.name)

    def test_same_timestamp_still_allocates_unique_paths(self):
        fixed = datetime(2026, 11, 14, tzinfo=timezone.utc)
        with patch("linscope.history.datetime") as mock_time:
            mock_time.fromisoformat.side_effect = datetime.fromisoformat
            mock_time.now.return_value = fixed
            paths = [self.save() for _ in range(3)]
        self.assertEqual(len(set(paths)), 3)
        self.assertEqual(len(history.list_history(self.directory)), 3)

    def test_filename_collision_never_overwrites(self):
        fixed = datetime(2026, 11, 14, tzinfo=timezone.utc)
        from types import SimpleNamespace
        with patch("linscope.history.datetime") as mock_time, patch("linscope.history.uuid.uuid4", return_value=SimpleNamespace(hex="a" * 32)):
            mock_time.fromisoformat.side_effect = datetime.fromisoformat
            mock_time.now.return_value = fixed
            path = self.save()
            before = path.read_bytes()
            with self.assertRaises(FileExistsError):
                self.save(sample(status="PASS"))
        self.assertEqual(path.read_bytes(), before)

    def test_candidate_and_size_limits(self):
        path = self.save()
        with patch("linscope.history.MAX_REPORT_BYTES", 50):
            with self.assertRaises(ValueError):
                history.list_history(self.directory)
            with self.assertRaises(ValueError):
                self.save()
        with patch("linscope.history.MAX_CANDIDATES", 1):
            with self.assertRaises(ValueError):
                self.save()
            second = self.directory / path.name.replace(path.name[-37:-5], "b" * 32)
            second.write_bytes(path.read_bytes())
            second.chmod(0o600)
            with self.assertRaises(ValueError):
                history.list_history(self.directory)

    def test_limit_validation(self):
        for limit in (0, -1, True, 501, "20"):
            with self.subTest(limit=limit), self.assertRaises(ValueError):
                history.list_history(self.directory, limit=limit)

    def test_latest_matching_ignores_other_hosts_profiles_and_scopes(self):
        expected = sample(status="PASS")
        self.save(expected)
        self.save(sample("different-host"))
        for key, value in (("profile", "router"), ("system", "OtherOS")):
            changed = sample()
            changed["host"][key] = value
            self.save(changed)
        changed = sample()
        changed["scope"]["deep"] = True
        self.save(changed)
        changed = sample()
        changed["scope"]["parameters"] = {"baseline": {"SSH-005": {"max_attempts": 6}}}
        self.save(changed)
        original = sample()
        self.assertEqual(history.latest_compatible(self.directory, original), expected)
        self.assertEqual(original, sample())
        self.assertIsNone(history.latest_compatible(self.directory, sample("no-match")))

    def test_no_scope_category_fallback_and_missing_check_are_distinct(self):
        report = sample()
        report.pop("scope")
        self.save(report)
        matching = deepcopy(report)
        matching["findings"][0]["status"] = "PASS"
        self.assertEqual(history.latest_compatible(self.directory, matching), report)
        matching["findings"][0]["category"] = "accounts"
        self.assertIsNone(history.latest_compatible(self.directory, matching))

    def test_foreign_tool_rejected_before_creating_directory_and_on_read(self):
        foreign = sample()
        foreign["tool"]["name"] = "OtherTool"
        with self.assertRaisesRegex(ValueError, "LinScope"):
            history.save_report(self.directory, foreign)
        self.assertFalse(self.directory.exists())
        path = self.save()
        self.corrupt(path, json.dumps(foreign))
        with self.assertRaisesRegex(ValueError, path.name):
            history.list_history(self.directory)
        with self.assertRaisesRegex(ValueError, "LinScope"):
            history.latest_compatible(self.directory, foreign)

    def test_concurrent_readers_wait_until_partial_writer_finishes(self):
        writing, release = threading.Event(), threading.Event()
        list_attempt, latest_attempt = threading.Event(), threading.Event()
        list_done, latest_done = threading.Event(), threading.Event()
        failures, results = [], {}
        actual_fchmod, actual_flock = os.fchmod, history.fcntl.flock

        def hold_partial_file(fd, mode):
            writing.set()
            if not release.wait(3):
                raise RuntimeError("test writer release timed out")
            actual_fchmod(fd, mode)

        def observed_flock(fd, operation):
            if operation == history.fcntl.LOCK_SH:
                if threading.current_thread().name == "history-list":
                    list_attempt.set()
                else:
                    latest_attempt.set()
            return actual_flock(fd, operation)

        def writer():
            try:
                results["path"] = self.save()
            except BaseException as exc:
                failures.append(exc)

        def reader(kind, done):
            try:
                results[kind] = (history.list_history(self.directory) if kind == "list" else
                                 history.latest_compatible(self.directory, sample()))
            except BaseException as exc:
                failures.append(exc)
            finally:
                done.set()

        threads = [threading.Thread(target=writer, name="history-writer", daemon=True),
                   threading.Thread(target=reader, args=("list", list_done), name="history-list", daemon=True),
                   threading.Thread(target=reader, args=("latest", latest_done), name="history-latest", daemon=True)]
        with patch("linscope.history.os.fchmod", side_effect=hold_partial_file), patch("linscope.history.fcntl.flock", side_effect=observed_flock):
            try:
                threads[0].start()
                self.assertTrue(writing.wait(2), "writer did not reach the partial file")
                threads[1].start()
                threads[2].start()
                self.assertTrue(list_attempt.wait(2))
                self.assertTrue(latest_attempt.wait(2))
                self.assertFalse(list_done.wait(0.05), "list read an in-progress report")
                self.assertFalse(latest_done.wait(0.05), "latest read an in-progress report")
            finally:
                release.set()
                for thread in threads:
                    if thread.ident is not None:
                        thread.join(3)
        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual(failures, [])
        self.assertEqual(results["list"][0]["name"], results["path"].name)
        self.assertEqual(results["latest"], sample())

    def test_concurrent_saves_respect_candidate_limit(self):
        # Both writers begin together with separately opened directory handles;
        # the exclusive lock covers enumeration as well as report publication.
        self.directory.mkdir(mode=0o700)
        start = threading.Barrier(3)
        saved, errors = [], []
        def writer():
            try:
                start.wait(2)
                saved.append(self.save())
            except BaseException as exc:
                errors.append(exc)
        threads = [threading.Thread(target=writer, daemon=True) for _ in range(2)]
        with patch("linscope.history.MAX_CANDIDATES", 1):
            for thread in threads:
                thread.start()
            start.wait(2)
            for thread in threads:
                thread.join(3)
            self.assertTrue(all(not thread.is_alive() for thread in threads))
            self.assertEqual(len(saved), 1)
            self.assertEqual(len(errors), 1)
            self.assertIsInstance(errors[0], ValueError)
            self.assertEqual(len(history.list_history(self.directory, limit=1)), 1)

    def test_unicode_and_control_evidence_roundtrips_without_mutation(self):
        report = sample()
        report["findings"][0]["evidence"] = "unicode é \x9b \x1b"
        self.save(report)
        self.assertEqual(history.latest_compatible(self.directory, report), report)


if __name__ == "__main__":
    unittest.main()
