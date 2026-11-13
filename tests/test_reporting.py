from copy import deepcopy
import json
import unittest

from linscope.reporting import compare_reports, render_html, render_json, render_text


def sample(status="WARN"):
    return {"schema_version": 1, "tool": {"name": "LinScope", "version": "1.4"},
            "generated_at": "2030-01-01T00:00:00+00:00",
            "host": {"name": "example-host", "system": "Linux", "release": "example", "profile": "server"},
            "scope": {"checks": ["ssh"], "deep": False},
            "findings": [{"id": "SSH-001", "category": "ssh", "title": "Root login",
                          "status": status, "severity": "high", "evidence": "permitrootlogin yes",
                          "recommendation": "Review root access policy."}]}


class ReportingTests(unittest.TestCase):
    def test_json_round_trip_and_no_mutation(self):
        report = sample()
        original = deepcopy(report)
        self.assertEqual(json.loads(render_json(report)), original)
        render_text(report)
        render_html(report)
        self.assertEqual(report, original)

    def test_html_escapes_all_untrusted_dynamic_values(self):
        report = sample()
        payload = '<script>alert("host")</script><img src=x onerror=alert(1)>'
        report["host"] = dict.fromkeys(("name", "system", "release", "profile"), payload)
        report["generated_at"] = payload
        report["tool"]["version"] = payload
        for field in ("id", "category", "title", "evidence", "recommendation"):
            report["findings"][0][field] = payload
        report["findings"][0]["exception"] = {"reason": payload, "expires": payload, "active": False}
        rendered = render_html(report)
        self.assertNotIn(payload, rendered)
        self.assertNotIn("<script>", rendered)
        self.assertNotIn("<img ", rendered)
        self.assertIn("&lt;script&gt;", rendered)
        self.assertIn("Expired exception", rendered)
        self.assertIn("Content-Security-Policy", rendered)
        self.assertIn("@media print", rendered)

    def test_html_status_cannot_be_used_as_attribute_injection(self):
        report = sample()
        report["findings"][0]["status"] = 'WARN" onclick="alert(1)'
        with self.assertRaises(ValueError):
            render_html(report)

    def test_terminal_control_sequences_are_removed(self):
        report = sample()
        report["findings"][0]["evidence"] = "\x1b[31mred\x1b[0m\x1b]0;evil\x07\r\x9b2Jnormal"
        text = render_text(report)
        self.assertNotIn("\x1b", text)
        self.assertNotIn("\x07", text)
        self.assertNotIn("\r", text)
        self.assertNotIn("\x9b", text)
        self.assertIn("red", text)

    def test_unknown_skip_and_exceptions_visible(self):
        report = sample("UNKNOWN")
        report["findings"][0]["exception"] = {"reason": "Approved", "expires": "2030-01-02", "active": True}
        text = render_text(report)
        self.assertIn("UNKNOWN: 1", text)
        self.assertIn("Exception (ACTIVE", text)
        self.assertIn("do not establish safety", text)
        self.assertIn("Original status and severity remain unchanged", render_html(report))

    def test_malformed_reports_raise_value_error(self):
        invalid = [None, [], {}, {"schema_version": 2}, {"schema_version": True}]
        mutations = [lambda x: x.pop("host"), lambda x: x.update(host=[]),
                     lambda x: x["host"].pop("name"), lambda x: x.update(findings={}),
                     lambda x: x.update(findings=[None]), lambda x: x.update(tool="not object"),
                     lambda x: x["findings"][0].pop("id"),
                     lambda x: x["findings"][0].update(evidence=[]),
                     lambda x: x["findings"][0].update(severity="urgent"),
                     lambda x: x.update(scope=[]),
                     lambda x: x.update(scope={"checks": ["ssh", "ssh"], "deep": False}),
                     lambda x: x.update(scope={"checks": [None], "deep": False}),
                     lambda x: x.update(scope={"checks": ["ssh"], "deep": "false"}),
                     lambda x: x.update(policy_warnings="not a list"),
                     lambda x: x.update(policy_warnings=[{"warning": "not a string"}]),
                     lambda x: x.update(policy_warnings=None),
                     lambda x: x["findings"].append(deepcopy(x["findings"][0])),
                     lambda x: x["findings"][0].update(exception=True)]
        for mutate in mutations:
            report = sample()
            mutate(report)
            invalid.append(report)
        for report in invalid:
            for function in (render_text, render_json, render_html):
                with self.subTest(report=report, renderer=function.__name__), self.assertRaises(ValueError):
                    function(report)

    def test_diff_resolution_requires_positive_pass(self):
        for status in ("UNKNOWN", "SKIP", "INFO", "WARN", "FAIL"):
            with self.subTest(status=status):
                diff = compare_reports(sample("FAIL"), sample(status))
                self.assertEqual(diff["resolved"], [])
        diff = compare_reports(sample("FAIL"), sample("PASS"))
        self.assertEqual(diff["summary"]["resolved"], 1)
        self.assertEqual(diff["changed"], [])

    def test_diff_changed_new_missing_and_exception_changes(self):
        old, new = sample(), sample()
        new["findings"][0]["evidence"] = "Different evidence"
        new["findings"][0]["exception"] = {"active": True, "reason": "Approved", "expires": "2030-01-01"}
        added = deepcopy(new["findings"][0])
        added["id"] = "SSH-002"
        new["findings"].append(added)
        diff = compare_reports(old, new)
        self.assertEqual(diff["summary"], {"new": 1, "resolved": 0, "changed": 1, "missing": 0})
        missing = compare_reports(new, old)
        self.assertEqual(missing["summary"]["missing"], 1)
        self.assertEqual(missing["resolved"], [])

    def test_diff_rejects_incompatible_reports(self):
        mutations = [lambda x: x["host"].update(name="other"),
                     lambda x: x["host"].update(system="OtherOS"),
                     lambda x: x["host"].update(profile="router"),
                     lambda x: x["scope"].update(deep=True),
                     lambda x: x["scope"].update(checks=["network"])]
        for mutate in mutations:
            old, new = sample(), sample()
            mutate(new)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                compare_reports(old, new)

    def test_diff_unchanged_and_version_upgrade(self):
        old, new = sample(), sample()
        new["tool"]["version"] = "1.5"
        new["host"]["release"] = "new-kernel"
        self.assertEqual(compare_reports(old, new)["summary"], {"new": 0, "resolved": 0, "changed": 0, "missing": 0})

    def test_diff_rejects_reused_id_in_another_category(self):
        old, new = sample(), sample()
        new["findings"][0]["category"] = "network"
        with self.assertRaisesRegex(ValueError, "changed categories"):
            compare_reports(old, new)

    def test_policy_warnings_are_visible_and_escaped(self):
        report = sample()
        payload = '<img src=x onerror="alert(1)">'
        report["policy_warnings"] = ["SSH-099 was not emitted; check for a typo.", payload,
                                     "Terminal \x1b[31mescape\x1b[0m"]
        html = render_html(report)
        text = render_text(report)
        self.assertIn("Policy warnings", html)
        self.assertIn("SSH-099 was not emitted", html)
        self.assertNotIn(payload, html)
        self.assertIn("&lt;img", html)
        self.assertIn("Policy warning: SSH-099 was not emitted", text)
        self.assertNotIn("\x1b", text)
        self.assertEqual(json.loads(render_json(report))["policy_warnings"], report["policy_warnings"])

    def test_diff_without_scope_rejects_changed_category(self):
        old, new = sample(), sample()
        old.pop("scope")
        new.pop("scope")
        new["findings"][0]["category"] = "network"
        with self.assertRaises(ValueError):
            compare_reports(old, new)


if __name__ == "__main__":
    unittest.main()
