"""CLI views and convenience modes must preserve canonical audit evidence."""
from copy import deepcopy
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from linscope import cli, history
from linscope.core import Context, Finding
from tests.test_cli_integration import sample


def mixed_report():
    report = sample()
    report["scope"]["checks"] = ["kernel", "logging", "permissions", "ssh"]
    extra = [
        ("PERM-003", "permissions", "FAIL", "critical", "protected mode fixture"),
        ("KERNEL-001", "kernel", "PASS", "medium", "kernel value fixture"),
        ("LOGGING-002", "logging", "UNKNOWN", "info", "unavailable fixture"),
    ]
    for check_id, category, status, severity, evidence in extra:
        report["findings"].append({
            "id": check_id, "category": category, "title": f"Fixture {check_id}",
            "status": status, "severity": severity, "evidence": evidence,
            "recommendation": "Review fixture configuration.",
        })
    return report


class CLIUsabilityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)

    def scan(self, arguments, report=None):
        report = deepcopy(mixed_report() if report is None else report)
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch("linscope.cli.collect", return_value=report) as collect, \
                patch("linscope.cli.platform.system", return_value="Linux"), \
                patch("linscope.core.Context.command", side_effect=AssertionError("No live commands in CLI fixture tests")), \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = cli.main(arguments)
        return code, stdout.getvalue(), stderr.getvalue(), collect

    def test_status_filter_changes_view_without_hiding_full_counts(self):
        code, output, _, _ = self.scan(["--status", "PASS"])
        self.assertEqual(code, 0)
        self.assertIn("Full report: 4 findings | Current view: 1", output)
        self.assertIn("FAIL: 1", output)
        self.assertIn("UNKNOWN: 1", output)
        self.assertIn("Evidence: kernel value fixture", output)
        self.assertNotIn("Evidence: protected mode fixture", output)

    def test_repeated_statuses_select_combined_view(self):
        code, output, _, _ = self.scan(["--status", "WARN", "--status", "FAIL"])
        self.assertEqual(code, 0)
        self.assertIn("Current view: 2", output)
        self.assertIn("Evidence: protected mode fixture", output)
        self.assertIn("Evidence: permitrootlogin=yes", output)
        self.assertNotIn("Evidence: kernel value fixture", output)

    def test_minimum_severity_filters_only_display(self):
        code, output, _, _ = self.scan(["--min-severity", "critical"])
        self.assertEqual(code, 0)
        self.assertIn("Current view: 1", output)
        self.assertIn("Evidence: protected mode fixture", output)
        self.assertNotIn("Evidence: permitrootlogin=yes", output)
        self.assertIn("Coverage warning: 1 UNKNOWN", output)

    def test_category_view_does_not_change_collection_selection(self):
        code, output, _, collect = self.scan(["--view-category", "ssh"])
        self.assertEqual(code, 0)
        self.assertEqual(collect.call_args.args[1], list(cli.CHECKS))
        self.assertIn("Full report: 4 findings | Current view: 1", output)
        self.assertIn("Evidence: permitrootlogin=yes", output)
        self.assertNotIn("Evidence: protected mode fixture", output)

    def test_display_filters_never_bypass_severity_exit_gate(self):
        views = (["--status", "PASS"], ["--min-severity", "critical", "--status", "PASS"],
                 ["--view-category", "kernel"], ["--summary"], ["--sort", "severity"])
        for view in views:
            with self.subTest(view=view):
                code, _, _, _ = self.scan([*view, "--fail-on", "high"])
                self.assertEqual(code, 1)

    def test_display_filters_never_bypass_unknown_exit_gate(self):
        views = (["--status", "PASS"], ["--min-severity", "critical"],
                 ["--view-category", "kernel"], ["--summary"], ["--sort", "status"])
        for view in views:
            with self.subTest(view=view):
                code, _, _, _ = self.scan([*view, "--fail-on-unknown"])
                self.assertEqual(code, 2)

    def test_severity_sort_orders_details_by_impact(self):
        code, output, _, _ = self.scan(["--sort", "severity"])
        self.assertEqual(code, 0)
        self.assertLess(output.index("[FAIL] PERM-003"), output.index("[WARN] SSH-001"))
        self.assertLess(output.index("[WARN] SSH-001"), output.index("[PASS] KERNEL-001"))

    def test_summary_omits_detailed_evidence_and_keeps_risk_counts(self):
        code, output, _, _ = self.scan(["--summary"])
        self.assertEqual(code, 0)
        self.assertIn("Priority review", output)
        self.assertIn("FAIL: 1", output)
        self.assertIn("Coverage warning: 1 UNKNOWN", output)
        self.assertIn("canonical JSON/history remains complete", output)
        self.assertNotIn("Evidence:", output)

    def test_json_display_options_rejected_before_collection(self):
        views = (["--status", "PASS"], ["--min-severity", "low"], ["--view-category", "ssh"],
                 ["--sort", "id"], ["--summary"])
        for view in views:
            with self.subTest(view=view), patch("linscope.cli.collect") as collect, \
                    contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
                cli.main(["--format", "json", *view])
            self.assertEqual(raised.exception.code, 2)
            collect.assert_not_called()

    def test_filtered_display_saves_every_finding_to_history(self):
        directory = self.directory / "history"
        original = mixed_report()
        code, output, error, _ = self.scan(["--history-dir", str(directory), "--status", "PASS"], original)
        self.assertEqual(code, 0)
        self.assertIn("Current view: 1", output)
        self.assertIn("History saved:", error)
        rows = history.list_history(directory)
        saved = json.loads(Path(rows[0]["path"]).read_text())
        self.assertEqual(saved["findings"], original["findings"])
        self.assertEqual(len(saved["findings"]), 4)
        self.assertEqual(saved["scope"], original["scope"])

    def test_summary_saves_complete_history_without_mutating_input(self):
        directory = self.directory / "history"
        original = mixed_report()
        before = deepcopy(original)
        code, output, _, _ = self.scan(["--history-dir", str(directory), "--summary"], original)
        self.assertEqual(code, 0)
        self.assertNotIn("Evidence:", output)
        self.assertEqual(original, before)
        saved = history.latest_compatible(directory, original)
        self.assertEqual(saved["findings"], original["findings"])

    def test_html_filtering_does_not_change_history_or_exit_thresholds(self):
        directory = self.directory / "history"
        report = mixed_report()
        code, output, _, _ = self.scan([
            "--format", "html", "--status", "PASS", "--history-dir", str(directory), "--fail-on", "high"], report)
        self.assertEqual(code, 1)
        self.assertIn("<!doctype html>", output)
        self.assertEqual(history.latest_compatible(directory, report)["findings"], report["findings"])

    def test_preflight_json_never_collects_or_executes_commands(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        fixture = Context(root=self.directory)
        with patch("linscope.cli.Context", return_value=fixture), \
                patch("linscope.cli.collect", side_effect=AssertionError("No audit during preflight")) as collect, \
                patch("linscope.core.Context.command", side_effect=AssertionError("No commands during preflight")), \
                patch("linscope.cli.platform.system", return_value="Linux"), \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = cli.main(["--preflight", "--category", "ssh", "--format", "json", "--progress"])
        self.assertEqual(code, 0)
        collect.assert_not_called()
        self.assertEqual(stderr.getvalue(), "")
        result = json.loads(stdout.getvalue())
        self.assertEqual(result["kind"], "preflight")
        self.assertEqual(result["categories"], ["ssh"])
        self.assertTrue(all(tool["execution_verified"] is False for tool in result["tools"]))

    def test_preflight_scan_gates_history_html_and_views_rejected(self):
        options = (["--fail-on", "high"], ["--fail-on-unknown"], ["--history-dir", "unused"],
                   ["--format", "html"], ["--status", "PASS"], ["--summary"])
        for extra in options:
            with self.subTest(extra=extra), patch("linscope.cli.collect") as collect, \
                    contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
                cli.main(["--preflight", *extra])
            self.assertEqual(raised.exception.code, 2)
            collect.assert_not_called()

    def test_history_list_is_offline_and_keeps_json_stdout_clean(self):
        directory = self.directory / "history"
        history.save_report(directory, sample())
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch("linscope.cli.collect", side_effect=AssertionError("No scan for history listing")) as collect, \
                patch("linscope.cli.platform.system", return_value="Darwin"), \
                patch("linscope.core.Context.command", side_effect=AssertionError("No commands for history listing")), \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = cli.main(["--history-list", "--history-dir", str(directory), "--format", "json"])
        self.assertEqual(code, 0)
        collect.assert_not_called()
        self.assertEqual(stderr.getvalue(), "")
        result = json.loads(stdout.getvalue())
        self.assertEqual(result["kind"], "history")
        self.assertEqual(len(result["entries"]), 1)
        self.assertEqual(result["entries"][0]["host"], "test-host")

    def test_history_list_missing_directory_does_not_create_it(self):
        directory = self.directory / "missing"
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout), patch("linscope.cli.collect") as collect:
            code = cli.main(["--history-list", "--history-dir", str(directory)])
        self.assertEqual(code, 0)
        self.assertIn("No saved snapshots", stdout.getvalue())
        self.assertFalse(directory.exists())
        collect.assert_not_called()

    def test_compare_latest_first_scan_sets_baseline_and_saves_full_json(self):
        directory = self.directory / "history"
        code, output, error, _ = self.scan([
            "--history-dir", str(directory), "--compare-latest", "--format", "json"], sample())
        self.assertEqual(code, 0)
        result = json.loads(output)
        self.assertIn("baseline", result["history_note"])
        self.assertNotIn("comparison", result)
        self.assertIn("History saved:", error)
        self.assertEqual(history.latest_compatible(directory, sample())["findings"], sample()["findings"])

    def test_compare_latest_uses_compatible_baseline_despite_newer_other_host(self):
        directory = self.directory / "history"
        history.save_report(directory, sample("WARN"))
        other = sample("FAIL")
        other["host"]["name"] = "another-host"
        history.save_report(directory, other)
        code, output, _, _ = self.scan([
            "--history-dir", str(directory), "--compare-latest", "--format", "json"], sample("PASS"))
        self.assertEqual(code, 0)
        comparison = json.loads(output)["comparison"]
        self.assertEqual(comparison["summary"]["resolved"], 1)
        self.assertEqual(comparison["resolved"][0]["before"]["status"], "WARN")

    def test_compare_latest_does_not_count_hidden_transition_as_missing(self):
        directory = self.directory / "history"
        history.save_report(directory, sample("WARN"))
        code, output, _, _ = self.scan([
            "--history-dir", str(directory), "--compare-latest", "--status", "FAIL"], sample("PASS"))
        self.assertEqual(code, 0)
        self.assertIn("Current view: 0", output)
        self.assertIn("resolved: 1", output)
        saved = history.latest_compatible(directory, sample())
        self.assertEqual(saved["comparison"]["summary"]["resolved"], 1)
        self.assertEqual(saved["findings"][0]["status"], "PASS")

    def test_compare_latest_rejects_changed_baseline_as_incompatible(self):
        directory = self.directory / "history"
        history.save_report(directory, sample("WARN"))
        changed = sample("PASS")
        changed["scope"]["parameters"] = {"baseline": {"SSH-005": {"max_attempts": 6}}}
        code, output, _, _ = self.scan([
            "--history-dir", str(directory), "--compare-latest", "--format", "json"], changed)
        self.assertEqual(code, 0)
        result = json.loads(output)
        self.assertIn("history_note", result)
        self.assertNotIn("comparison", result)

    def test_history_flags_require_explicit_directory_before_collection(self):
        for flag in ("--history-list", "--compare-latest"):
            with self.subTest(flag=flag), patch("linscope.cli.collect") as collect, \
                    contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
                cli.main([flag])
            self.assertEqual(raised.exception.code, 2)
            collect.assert_not_called()

    def test_progress_is_stderr_and_json_stdout_remains_machine_readable(self):
        findings = {
            "ssh": [Finding("SSH-001", "ssh", "Root fixture", "WARN", "high", "fixture", "Review fixture")],
            "permissions": [Finding("PERM-001", "permissions", "Mode fixture", "PASS", "medium", "fixture", "Review fixture")],
        }
        collectors = {name: (lambda _ctx, rows=rows: rows) for name, rows in findings.items()}
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch("linscope.cli.CHECKS", collectors), \
                patch("linscope.cli.platform.system", return_value="Linux"), \
                patch("linscope.cli.platform.node", return_value="synthetic-host"), \
                patch("linscope.cli.platform.release", return_value="synthetic-kernel"), \
                patch("linscope.core.Context.command", side_effect=AssertionError("No live fixture commands")), \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = cli.main(["--category", "ssh", "--category", "permissions", "--progress", "--format", "json"])
        self.assertEqual(code, 0)
        result = json.loads(stdout.getvalue())
        self.assertEqual(len(result["findings"]), 2)
        self.assertIn("[1/2] Checking ssh", stderr.getvalue())
        self.assertIn("[2/2] Checking permissions", stderr.getvalue())
        self.assertNotIn("Checking", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
