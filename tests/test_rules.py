from copy import deepcopy
import contextlib
import io
from hashlib import sha256
import json
import unittest
from unittest.mock import patch

from linscope import cli
from linscope.checks import ssh
from linscope.core import Context, Finding
from linscope.rules import (DEFAULT_BASELINES, build_rules_snapshot, rules_compatible,
                            validate_rules_snapshot)
from linscope.reporting import compare_reports, render_html, render_json, render_text
from tests.test_reporting import sample
from tests.test_ssh import SSHContext


def report_with_rules(status="WARN"):
    report = sample(status)
    report["rules"] = build_rules_snapshot(Context(), ["ssh"])
    return report


def resign(rules):
    manifest = {key: value for key, value in rules.items() if key != "fingerprint"}
    rules["fingerprint"] = sha256(json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()).hexdigest()
    return rules


class RuleIdentityTests(unittest.TestCase):
    def test_defaults_are_resolved_and_overrides_are_canonical(self):
        ctx = Context(baseline={"SSH-005": {"max_attempts": 6}})
        rules = build_rules_snapshot(ctx, ["packages", "ssh"])
        self.assertEqual(rules["effective_baselines"], {"SSH-001": {"allowed": ["no"]}, "SSH-005": {"max_attempts": 6}, "PACKAGES-002": {"max_age_days": 7}})
        validate_rules_snapshot(rules)
        self.assertTrue(rules["complete"])

    def test_snapshot_does_not_mutate_or_expose_shared_defaults(self):
        baseline = deepcopy(DEFAULT_BASELINES)
        rules = build_rules_snapshot(Context(), ["ssh"])
        rules["effective_baselines"]["SSH-001"]["allowed"].append("yes")
        self.assertEqual(DEFAULT_BASELINES, baseline)

    def test_order_does_not_change_identity(self):
        first = build_rules_snapshot(Context(), ["packages", "ssh"])
        second = build_rules_snapshot(Context(), ["ssh", "packages"])
        self.assertEqual(first, second)

    def test_changed_default_cannot_look_like_machine_remediation(self):
        before = report_with_rules("WARN")
        context = SSHContext("maxauthtries 5\n")
        first = next(f for f in ssh.run(context) if f.id == "SSH-005")
        self.assertEqual(first.status, "WARN")
        with patch.dict(DEFAULT_BASELINES, {"SSH-005": {"max_attempts": 6}}):
            after = report_with_rules("PASS")
            second = next(f for f in ssh.run(context) if f.id == "SSH-005")
        self.assertEqual(second.status, "PASS")
        self.assertNotEqual(before["rules"]["fingerprint"], after["rules"]["fingerprint"])
        with self.assertRaisesRegex(ValueError, "assessment rules"):
            compare_reports(before, after)

    def test_real_status_improvement_under_same_rules_is_resolved(self):
        first = report_with_rules("WARN")
        after = deepcopy(first)
        after["findings"][0]["status"] = "PASS"
        diff = compare_reports(first, after)
        self.assertEqual(diff["summary"]["resolved"], 1)
        self.assertTrue(diff["rules_verified"])

    def test_code_change_with_same_revision_requires_new_baseline(self):
        first = report_with_rules()
        after = deepcopy(first)
        after["rules"]["source_sha256"]["checks/ssh.py"] = "0" * 64
        resign(after["rules"])
        with self.assertRaisesRegex(ValueError, "assessment rules"):
            compare_reports(first, after)

    def test_cross_category_helpers_are_part_of_rule_identity(self):
        rules = build_rules_snapshot(Context(), ["authentication"])
        self.assertIn("checks/accounts.py", rules["source_sha256"])
        self.assertIn("checks/__init__.py", rules["source_sha256"])
        validate_rules_snapshot(rules)

    def test_mid_scan_rule_change_is_recorded_as_unstable(self):
        first = build_rules_snapshot(Context(), ["ssh"])
        second = deepcopy(first)
        second["source_sha256"]["checks/ssh.py"] = "0" * 64
        resign(second)
        finding = Finding("SSH-001", "ssh", "Fixture", "PASS", "info", "fixture", "review")
        with patch("linscope.cli.CHECKS", {"ssh": lambda _: [finding]}), patch("linscope.cli.build_rules_snapshot", side_effect=[first, second]):
            report = cli.collect(Context(), ["ssh"])
        self.assertFalse(report["rules"]["stable"])
        self.assertFalse(report["rules"]["complete"])
        validate_rules_snapshot(report["rules"])
        self.assertIn("changed during", report["policy_warnings"][0])

    def test_scoped_override_must_agree_with_recorded_baseline(self):
        report = report_with_rules()
        report["scope"]["parameters"] = {"baseline": {"SSH-005": {"max_attempts": 6}}}
        with self.assertRaisesRegex(ValueError, "contradict"):
            render_json(report)

    def test_legacy_and_verified_cannot_mix(self):
        for first, second in ((sample(), report_with_rules()), (report_with_rules(), sample())):
            with self.subTest(first=first.get("rules") is None), self.assertRaisesRegex(ValueError, "assessment rules"):
                compare_reports(first, second)
        diff = compare_reports(sample(), sample("PASS"))
        self.assertFalse(diff["rules_verified"])
        self.assertIn("unverified", cli.render_comparison(diff))

    def test_incomplete_source_identity_is_never_comparable(self):
        first = report_with_rules()
        missing = "checks/ssh.py"
        first["rules"]["source_sha256"].pop(missing)
        first["rules"]["unavailable_sources"] = [missing]
        first["rules"]["complete"] = False
        resign(first["rules"])
        validate_rules_snapshot(first["rules"])
        self.assertFalse(rules_compatible(first, deepcopy(first)))

    def test_incomplete_rule_identity_triggers_unknown_exit_gate(self):
        report = report_with_rules("PASS")
        name = "checks/ssh.py"
        report["rules"]["source_sha256"].pop(name)
        report["rules"]["unavailable_sources"] = [name]
        report["rules"]["complete"] = False
        resign(report["rules"])
        with patch("linscope.cli.collect", return_value=report), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(["--fail-on-unknown"]), 2)

    def test_malformed_or_tampered_manifest_is_rejected(self):
        mutations = [lambda x: x.update(fingerprint="0" * 64),
                     lambda x: x["effective_baselines"]["SSH-005"].update(max_attempts=6),
                     lambda x: x.update(complete=True, unavailable_sources=["checks/ssh.py"]),
                     lambda x: x.update(source_sha256={}), lambda x: x.update(categories=["ssh", "ssh"]),
                     lambda x: x.update(complete=1), lambda x: x.update(effective_baselines={})]
        for mutate in mutations:
            data = build_rules_snapshot(Context(), ["ssh"])
            mutate(data)
            with self.subTest(data=data), self.assertRaises(ValueError):
                validate_rules_snapshot(data)

    def test_rule_scope_and_report_scope_must_agree(self):
        first = report_with_rules()
        for key, value in (("host", []), ("scope", []), ("host", {"name": "x", "system": "Linux", "profile": "router"}), ("scope", {"checks": ["kernel"], "deep": False})):
            report = deepcopy(first)
            report[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                render_json(report)

    def test_terminal_html_and_json_show_rules_without_executable_content(self):
        report = report_with_rules()
        report["rules"]["revision"] = '<img src=x onerror="alert(1)">'
        resign(report["rules"])
        self.assertIn("Assessment rules", render_text(report))
        self.assertIn("Effective configurable baselines", render_text(report))
        html = render_html(report)
        self.assertNotIn('<img src=x', html)
        self.assertIn("&lt;img", html)
        self.assertEqual(json.loads(render_json(report))["rules"], report["rules"])


if __name__ == "__main__":
    unittest.main()
