"""Display helpers cannot change stored evidence, policy input, or coverage."""
from copy import deepcopy
import base64
import hashlib
from html.parser import HTMLParser
import json
import unittest

from linscope.reporting import (compare_reports, render_html, render_json,
                                render_text, select_findings)


def sample():
    rows = [
        ("Z-001", "ssh", "WARN", "medium"),
        ("A-001", "accounts", "PASS", "critical"),
        ("B-001", "accounts", "FAIL", "high"),
        ("C-001", "ssh", "UNKNOWN", "info"),
        ("D-001", "kernel", "WARN", "high"),
        ("E-001", "kernel", "INFO", "low"),
        ("F-001", "kernel", "SKIP", "medium"),
    ]
    return {"schema_version": 1, "tool": {"name": "LinScope", "version": "1.6"},
            "generated_at": "2030-01-01T00:00:00+00:00",
            "host": {"name": "example-host", "system": "Linux", "release": "example", "profile": "server"},
            "scope": {"checks": ["accounts", "kernel", "ssh"], "deep": False},
            "findings": [{"id": check_id, "category": category, "title": f"Title {check_id}",
                          "status": status, "severity": severity, "evidence": f"Evidence {check_id}",
                          "recommendation": f"Review {check_id}."}
                         for check_id, category, status, severity in rows]}


class ReportParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.articles = []
        self.details = []
        self.scripts = []
        self.script_attributes = []
        self.csp = None
        self.inside_script = False

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == "article":
            self.articles.append(values)
        if tag == "details":
            self.details.append(values)
        if tag == "script":
            self.inside_script = True
            self.scripts.append("")
            self.script_attributes.append(values)
        if tag == "meta" and values.get("http-equiv") == "Content-Security-Policy":
            self.csp = values["content"]

    def handle_endtag(self, tag):
        if tag == "script":
            self.inside_script = False

    def handle_data(self, data):
        if self.inside_script:
            self.scripts[-1] += data


class ReportViewTests(unittest.TestCase):
    def test_default_id_sort_returns_independent_copy(self):
        report = sample()
        original = deepcopy(report)
        findings = select_findings(report)
        self.assertEqual([f["id"] for f in findings], sorted(f["id"] for f in report["findings"]))
        findings[0]["evidence"] = "Changed view"
        self.assertEqual(report, original)

    def test_filter_combines_status_and_minimum_severity(self):
        findings = select_findings(sample(), statuses=["WARN", "FAIL"], min_severity="high", sort_by="severity")
        self.assertEqual([f["id"] for f in findings], ["B-001", "D-001"])

    def test_category_selection_combines_filters_without_changing_collection_scope(self):
        report = sample()
        original = deepcopy(report)
        self.assertEqual([f["id"] for f in select_findings(report, categories="ssh", statuses="WARN")], ["Z-001"])
        self.assertEqual([f["id"] for f in select_findings(report, categories=["kernel", "accounts"], min_severity="high")], ["A-001", "B-001", "D-001"])
        self.assertEqual(select_findings(report, categories=[]), [])
        self.assertEqual(select_findings(report, categories="not-collected"), [])
        self.assertEqual(report, original)

    def test_text_category_filter_keeps_full_counts(self):
        text = render_text(sample(), categories="accounts")
        self.assertIn("Full report: 7 findings | Current view: 2", text)
        self.assertIn("Evidence A-001", text)
        self.assertNotIn("Evidence C-001", text)
        self.assertIn("Coverage warning: 1 UNKNOWN", text)

    def test_single_status_string_and_list_input(self):
        self.assertEqual([f["id"] for f in select_findings(sample()["findings"], statuses="UNKNOWN")], ["C-001"])
        self.assertEqual(select_findings(sample(), statuses=[]), [])

    def test_severity_and_status_sort_are_deterministic(self):
        self.assertEqual([f["id"] for f in select_findings(sample(), sort_by="severity")],
                         ["A-001", "B-001", "D-001", "Z-001", "F-001", "E-001", "C-001"])
        self.assertEqual([f["status"] for f in select_findings(sample(), sort_by="status")],
                         ["FAIL", "WARN", "WARN", "UNKNOWN", "INFO", "SKIP", "PASS"])
        categories = [f["category"] for f in select_findings(sample(), sort_by="category")]
        self.assertEqual(categories, sorted(categories))

    def test_invalid_view_options_are_rejected(self):
        for options in ({"statuses": ["SAFE"]}, {"statuses": 1}, {"statuses": {"WARN": True}},
                        {"categories": 1}, {"categories": ""}, {"categories": [None]},
                        {"min_severity": "urgent"}, {"sort_by": "unsafe"}):
            for function in (select_findings, render_text, render_html):
                with self.subTest(options=options, function=function.__name__), self.assertRaises(ValueError):
                    function(sample(), **options)

    def test_filtered_text_preserves_canonical_counts_and_unknown_warning(self):
        text = render_text(sample(), statuses=["FAIL"], min_severity="high")
        self.assertIn("Full report: 7 findings | Current view: 1", text)
        self.assertIn("UNKNOWN: 1", text)
        self.assertIn("Coverage warning: 1 UNKNOWN", text)
        self.assertIn("Evidence B-001", text)
        self.assertNotIn("Evidence A-001", text)
        self.assertNotIn("Evidence Z-001", text)

    def test_summary_only_omits_detailed_evidence_but_not_counts(self):
        text = render_text(sample(), summary_only=True)
        self.assertIn("Summary only", text)
        self.assertIn("Priority review", text)
        self.assertIn("B-001 / HIGH / FAIL", text)
        self.assertNotIn("Evidence B-001", text)
        self.assertIn("Full report: 7 findings", text)

    def test_priority_is_limited_to_five_warning_failure_findings(self):
        report = sample()
        for number in range(10):
            report["findings"].append({"id": f"EXTRA-{number:03d}", "category": "ssh", "title": "Priority extra",
                                       "status": "FAIL", "severity": "critical", "evidence": "extra", "recommendation": "Review"})
        text = render_text(report, summary_only=True)
        priority_lines = [line for line in text.splitlines() if line.startswith("  EXTRA-")]
        self.assertEqual(len(priority_lines), 5)

    def test_html_keeps_all_cards_even_for_empty_or_summary_view(self):
        report = sample()
        for options in ({"statuses": []}, {"statuses": ["FAIL"], "summary_only": True}):
            with self.subTest(options=options):
                html = render_html(report, **options)
                parser = ReportParser()
                parser.feed(html)
                self.assertEqual(len(parser.articles), len(report["findings"]))
                self.assertEqual({card["data-check-id"] for card in parser.articles}, {f["id"] for f in report["findings"]})
                self.assertTrue(all("hidden" not in card for card in parser.articles))
                self.assertTrue(all("open" in detail for detail in parser.details))
                for finding in report["findings"]:
                    self.assertIn(finding["evidence"], html)

    def test_html_initial_category_selection_is_data_not_executable_code(self):
        for categories in (None, "ssh", ["accounts", "kernel"], [], ["not-collected"]):
            with self.subTest(categories=categories):
                html = render_html(sample(), categories=categories)
                parser = ReportParser()
                parser.feed(html)
                self.assertEqual(len(parser.articles), 7)
                expected = None if categories is None else [categories] if isinstance(categories, str) else sorted(categories)
                class MainParser(HTMLParser):
                    data = None
                    def handle_starttag(self, tag, attrs):
                        if tag == "main":
                            self.data = dict(attrs)
                main = MainParser()
                main.feed(html)
                self.assertEqual(json.loads(main.data["data-initial-categories"]), expected)

    def test_comparison_and_history_notes_are_visible_and_safe(self):
        report = sample()
        note = '<script>alert("history")</script>\x1b[31m unsafe'
        report["history_note"] = note
        report["comparison"] = {"summary": {"new": 2, "resolved": 1, "changed": 3, "missing": 0},
                                "new": [], "resolved": [], "changed": [], "missing": []}
        original = deepcopy(report)
        text = render_text(report)
        html = render_html(report)
        self.assertIn("History:", text)
        self.assertIn("Previous compatible report: new: 2 | resolved: 1", text)
        self.assertNotIn("\x1b", text)
        self.assertIn("&lt;script&gt;", html)
        self.assertNotIn('<script>alert("history")', html)
        self.assertIn("Previous compatible report", html)
        self.assertEqual(json.loads(render_json(report)), original)

    def test_invalid_comparison_or_history_metadata_is_rejected(self):
        values = [{"history_note": None}, {"history_note": []}, {"comparison": None},
                  {"comparison": {"summary": []}},
                  {"comparison": {"summary": {"new": 0}}},
                  {"comparison": {"summary": {"new": 0, "resolved": 0, "changed": -1, "missing": 0}}},
                  {"comparison": {"summary": {"new": False, "resolved": 0, "changed": 0, "missing": 0}}},
                  {"comparison": {"summary": {"new": "<script>", "resolved": 0, "changed": 0, "missing": 0}}}]
        for extra in values:
            report = sample()
            report.update(extra)
            for function in (render_text, render_html, render_json):
                with self.subTest(extra=extra, function=function.__name__), self.assertRaises(ValueError):
                    function(report)

    def test_html_script_hash_matches_exact_inline_bytes(self):
        parser = ReportParser()
        parser.feed(render_html(sample()))
        self.assertEqual(len(parser.scripts), 1)
        digest = base64.b64encode(hashlib.sha256(parser.scripts[0].encode()).digest()).decode()
        script_policy = next(part.strip() for part in parser.csp.split(";") if part.strip().startswith("script-src"))
        self.assertEqual(script_policy, f"script-src 'sha256-{digest}'")
        self.assertNotIn("src", parser.script_attributes[0])
        self.assertNotIn("unsafe-inline", script_policy)

    def test_dynamic_values_never_enter_executable_script(self):
        report = sample()
        payload = '</script><script>alert("injected")</script>'
        for field in ("id", "category", "title", "evidence", "recommendation"):
            report["findings"][0][field] = payload
        parser = ReportParser()
        html = render_html(report)
        parser.feed(html)
        self.assertEqual(len(parser.scripts), 1)
        self.assertNotIn("injected", parser.scripts[0])
        self.assertIn("&lt;/script&gt;", html)
        self.assertIn(payload, {card["data-check-id"] for card in parser.articles})

    def test_all_renderers_leave_report_and_json_unchanged(self):
        report = sample()
        original = deepcopy(report)
        render_text(report, statuses=["PASS"], sort_by="severity", summary_only=True)
        render_html(report, statuses=["PASS"], sort_by="status", summary_only=True)
        self.assertEqual(report, original)
        self.assertEqual(json.loads(render_json(report)), original)

    def test_scope_parameters_allow_json_data_and_reject_invalid_types(self):
        report = sample()
        report["scope"]["parameters"] = {"baseline": {"SSH-005": {"max_attempts": 3}},
                                           "ssh_contexts": [{"user": "alice", "addr": "192.0.2.1", "host": "example"}]}
        self.assertEqual(json.loads(render_json(report)), report)
        for value in ([], None, "invalid", {"unexpected": object()}, {"nonfinite": float("nan")}):
            report["scope"]["parameters"] = value
            for function in (render_text, render_html, render_json):
                with self.subTest(value=value, function=function.__name__), self.assertRaises(ValueError):
                    function(report)

    def test_scope_parameters_changes_cannot_be_counted_as_fixes(self):
        old, new = sample(), sample()
        old["scope"]["parameters"] = {"baseline": {"SSH-005": {"max_attempts": 3}}}
        new["scope"]["parameters"] = {"baseline": {"SSH-005": {"max_attempts": 5}}}
        with self.assertRaisesRegex(ValueError, "different collection scopes"):
            compare_reports(old, new)
        new["scope"]["parameters"] = deepcopy(old["scope"]["parameters"])
        self.assertEqual(compare_reports(old, new)["summary"], {"new": 0, "resolved": 0, "changed": 0, "missing": 0})

    def test_unknown_scope_key_cannot_silently_change_interpretation(self):
        report = sample()
        report["scope"]["ignored_baseline"] = True
        with self.assertRaises(ValueError):
            render_json(report)

    def test_different_explicit_tool_names_cannot_be_compared(self):
        old, new = sample(), sample()
        new["tool"]["name"] = "OtherTool"
        with self.assertRaisesRegex(ValueError, "different tools"):
            compare_reports(old, new)
        old.pop("tool")
        self.assertEqual(compare_reports(old, new)["summary"], {"new": 0, "resolved": 0, "changed": 0, "missing": 0})

    def test_explicit_tool_name_requires_a_nonempty_string(self):
        for name in ("", None, [], 0):
            report = sample()
            report["tool"]["name"] = name
            with self.subTest(name=name), self.assertRaises(ValueError):
                render_json(report)


if __name__ == "__main__":
    unittest.main()
