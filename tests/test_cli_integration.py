"""CLI integration tests use synthetic reports and never audit the live host."""
from copy import deepcopy
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from linscope import cli


def sample(status="WARN", severity="high"):
    return {
        "schema_version": 1,
        "tool": {"name": "LinScope", "version": "1.4"},
        "generated_at": "2030-01-01T00:00:00+00:00",
        "host": {"name": "test-host", "system": "Linux", "release": "test", "profile": "server"},
        "scope": {"checks": ["ssh"], "deep": False},
        "findings": [{"id": "SSH-001", "category": "ssh", "title": "Root login",
                      "status": status, "severity": severity, "evidence": "permitrootlogin=yes",
                      "recommendation": "Review named-account access."}],
    }


class CLIIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def json_file(self, name, value):
        path = self.root / name
        path.write_text(json.dumps(value), encoding="utf-8")
        return str(path)

    def policy(self, expires="2999-01-01", **values):
        value = {"exceptions": {"SSH-001": {"reason": "Approved temporary test exception", "expires": expires}}}
        value.update(values)
        return self.json_file("policy.json", value)

    def scan(self, arguments, report=None):
        stdout, stderr = io.StringIO(), io.StringIO()
        report = deepcopy(sample() if report is None else report)
        with patch("linscope.cli.collect", return_value=report) as collect, \
                patch("linscope.cli.Context") as context, \
                patch("linscope.cli.platform.system", return_value="Linux"), \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = cli.main(arguments)
        return code, stdout.getvalue(), stderr.getvalue(), collect, context

    def compare(self, before, after, extra=()):
        before_path = self.json_file("before.json", before)
        after_path = self.json_file("after.json", after)
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch("linscope.cli.collect", side_effect=AssertionError("Offline compare must not collect")) as collect, \
                patch("linscope.cli.platform.system", return_value="Darwin"), \
                patch("linscope.core.Context.command", side_effect=AssertionError("Offline compare must not run commands")), \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = cli.main(["--compare", before_path, after_path, *extra])
        collect.assert_not_called()
        return code, stdout.getvalue(), stderr.getvalue()

    def test_policy_profile_and_category_selection_are_applied(self):
        policy = self.json_file("policy.json", {"profile": "router", "checks": ["network", "kernel"]})
        code, _, _, collect, context = self.scan(["--policy", policy])
        self.assertEqual(code, 0)
        context.assert_called_once_with(profile="router", deep=False)
        self.assertEqual(collect.call_args.args[1], ["network", "kernel"])

    def test_cli_overrides_policy_and_deduplicates_categories(self):
        policy = self.json_file("policy.json", {"profile": "router", "checks": ["network"]})
        code, _, _, collect, context = self.scan([
            "--policy", policy, "--profile", "desktop", "--deep",
            "--category", "permissions", "--category", "permissions", "--category", "ssh"])
        self.assertEqual(code, 0)
        context.assert_called_once_with(profile="desktop", deep=True)
        self.assertEqual(collect.call_args.args[1], ["permissions", "ssh"])

    def test_default_profile_and_all_registered_categories(self):
        code, _, _, collect, context = self.scan([])
        self.assertEqual(code, 0)
        context.assert_called_once_with(profile="server", deep=False)
        self.assertEqual(collect.call_args.args[1], list(cli.CHECKS))

    def test_invalid_policy_stops_before_collection(self):
        for value in ([], {"checks": []}, {"profile": "unknown"}, {"command": "unsafe"}):
            with self.subTest(value=value):
                path = self.json_file("policy.json", value)
                code, _, error, collect, _ = self.scan(["--policy", path])
                self.assertEqual(code, 2)
                self.assertIn("linscope:", error)
                collect.assert_not_called()

    def test_duplicate_policy_keys_stop_before_collection(self):
        path = self.root / "policy.json"
        path.write_text('{"profile":"server","profile":"router"}', encoding="utf-8")
        code, _, error, collect, _ = self.scan(["--policy", str(path)])
        self.assertEqual(code, 2)
        self.assertIn("Duplicate", error)
        collect.assert_not_called()

    def test_policy_fifo_is_rejected_without_waiting_for_writer(self):
        path = self.root / "policy.fifo"
        os.mkfifo(path)
        code, _, error, collect, _ = self.scan(["--policy", str(path)])
        self.assertEqual(code, 2)
        self.assertIn("regular", error.lower())
        collect.assert_not_called()

    def test_invalid_policy_encoding_stops_before_collection(self):
        path = self.root / "policy.json"
        path.write_bytes(b'{"profile":"\xff"}')
        code, _, _, collect, _ = self.scan(["--policy", str(path)])
        self.assertEqual(code, 2)
        collect.assert_not_called()

    def test_active_exception_does_not_bypass_threshold_without_opt_in(self):
        code, output, _, _, _ = self.scan([
            "--policy", self.policy(), "--fail-on", "high", "--format", "json"], sample("FAIL"))
        self.assertEqual(code, 1)
        finding = json.loads(output)["findings"][0]
        self.assertEqual(finding["status"], "FAIL")
        self.assertTrue(finding["exception"]["active"])

    def test_honored_exception_preserves_visible_failure_and_evidence(self):
        original = sample("FAIL")
        code, output, _, _, _ = self.scan([
            "--policy", self.policy(), "--honor-exceptions", "--fail-on", "high", "--format", "json"], original)
        self.assertEqual(code, 0)
        finding = json.loads(output)["findings"][0]
        self.assertEqual(finding["status"], "FAIL")
        self.assertEqual(finding["evidence"], original["findings"][0]["evidence"])

    def test_expired_exception_never_bypasses_threshold(self):
        code, output, _, _, _ = self.scan([
            "--policy", self.policy(expires="2000-01-01"), "--honor-exceptions",
            "--fail-on", "high", "--format", "json"], sample("FAIL"))
        self.assertEqual(code, 1)
        self.assertFalse(json.loads(output)["findings"][0]["exception"]["active"])

    def test_exception_cannot_bypass_unknown_coverage_gate(self):
        code, output, _, _, _ = self.scan([
            "--policy", self.policy(), "--honor-exceptions", "--fail-on", "low",
            "--fail-on-unknown", "--format", "json"], sample("UNKNOWN", "info"))
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(output)["findings"][0]["status"], "UNKNOWN")

    def test_severity_gate_only_counts_warn_and_fail(self):
        for status, severity, threshold, expected in (
            ("WARN", "low", "high", 0), ("FAIL", "high", "high", 1),
            ("INFO", "critical", "low", 0), ("PASS", "critical", "low", 0),
            ("SKIP", "critical", "low", 0), ("UNKNOWN", "critical", "low", 0)):
            with self.subTest(status=status, severity=severity, threshold=threshold):
                code, _, _, _, _ = self.scan(["--fail-on", threshold], sample(status, severity))
                self.assertEqual(code, expected)

    def test_unmatched_policy_exception_stays_visible(self):
        policy = self.json_file("policy.json", {"exceptions": {
            "SSH-999": {"reason": "Possibly a typo", "expires": "2999-01-01"}}})
        code, output, _, _, _ = self.scan(["--policy", policy, "--format", "json"])
        self.assertEqual(code, 0)
        self.assertIn("SSH-999", json.loads(output)["policy_warnings"][0])

    def test_json_stdout_roundtrip_preserves_control_character_evidence(self):
        report = sample()
        report["findings"][0]["evidence"] = "Unicode evidence: café, C1 control: \u009b and ESC: \x1b"
        code, output, _, _, _ = self.scan(["--format", "json"], report)
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output), report)

    def test_html_output_escapes_host_controlled_values(self):
        report = sample()
        report["findings"][0]["evidence"] = '<img src=x onerror="alert(1)">'
        code, output, _, _, _ = self.scan(["--format", "html"], report)
        self.assertEqual(code, 0)
        self.assertIn("&lt;img", output)
        self.assertNotIn('<img src=x', output)

    def test_existing_output_is_not_overwritten(self):
        path = self.root / "report.json"
        path.write_text("keep", encoding="utf-8")
        code, _, error, _, _ = self.scan(["--format", "json", "--output", str(path)])
        self.assertEqual(code, 2)
        self.assertIn("linscope:", error)
        self.assertEqual(path.read_text(), "keep")

    def test_private_json_output_matches_report(self):
        path = self.root / "report.json"
        code, output, error, _, _ = self.scan(["--format", "json", "--output", str(path)])
        self.assertEqual((code, output, error), (0, "", ""))
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(json.loads(path.read_text()), sample())

    def test_compare_runs_offline_on_non_linux_host(self):
        code, output, error = self.compare(sample("FAIL"), sample("PASS"), ["--format", "json"])
        self.assertEqual((code, error), (0, ""))
        result = json.loads(output)
        self.assertEqual(result["summary"]["resolved"], 1)

    def test_compare_unknown_transition_is_not_resolved(self):
        code, output, _ = self.compare(sample("FAIL"), sample("UNKNOWN"), ["--format", "json"])
        self.assertEqual(code, 0)
        result = json.loads(output)
        self.assertEqual(result["summary"]["resolved"], 0)
        self.assertEqual(result["summary"]["changed"], 1)

    def test_compare_rejects_host_and_scope_mismatch(self):
        for field, value in (("name", "other-host"), ("profile", "router")):
            with self.subTest(field=field):
                after = sample()
                after["host"][field] = value
                code, _, error = self.compare(sample(), after)
                self.assertEqual(code, 2)
                self.assertIn("Cannot compare", error)
        after = sample()
        after["scope"]["deep"] = True
        self.assertEqual(self.compare(sample(), after)[0], 2)

    def test_compare_rejects_malformed_report(self):
        for value in ([], None, {"schema_version": True}, {"schema_version": 1, "host": []}):
            with self.subTest(value=value):
                code, _, error = self.compare(value, sample())
                self.assertEqual(code, 2)
                self.assertIn("linscope:", error)

    def test_compare_rejects_duplicate_keys_and_nonfinite_json(self):
        after = self.json_file("after.json", sample())
        for raw in ('{"schema_version":1,"schema_version":1}', '{"schema_version":NaN}'):
            with self.subTest(raw=raw):
                before = self.root / "before.json"
                before.write_text(raw, encoding="utf-8")
                stderr = io.StringIO()
                with patch("linscope.cli.collect", side_effect=AssertionError("No collection")), \
                        contextlib.redirect_stderr(stderr):
                    self.assertEqual(cli.main(["--compare", str(before), after]), 2)

    def test_compare_rejects_scan_options_and_unsupported_html(self):
        before = self.json_file("before.json", sample())
        after = self.json_file("after.json", sample())
        for extra in (["--profile", "server"], ["--category", "ssh"], ["--deep"],
                      ["--fail-on", "high"], ["--fail-on-unknown"], ["--honor-exceptions"],
                      ["--list-categories"], ["--format", "html"], ["--policy", "unused.json"]):
            with self.subTest(extra=extra), contextlib.redirect_stderr(io.StringIO()), \
                    self.assertRaises(SystemExit) as raised:
                cli.main(["--compare", before, after, *extra])
            self.assertEqual(raised.exception.code, 2)

    def test_honor_exceptions_requires_explicit_policy_and_threshold(self):
        for args in (["--honor-exceptions"], ["--honor-exceptions", "--fail-on", "high"],
                     ["--honor-exceptions", "--policy", "unused.json"]):
            with self.subTest(args=args), contextlib.redirect_stderr(io.StringIO()), \
                    self.assertRaises(SystemExit) as raised:
                cli.main(args)
            self.assertEqual(raised.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
