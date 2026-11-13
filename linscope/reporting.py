"""Portable terminal, JSON, HTML reports and conservative baseline comparison."""
from __future__ import annotations

from collections import Counter
from copy import deepcopy
from html import escape
import json
import re

from linscope.core import SEVERITIES, STATUSES


def _findings(report: dict) -> list[dict]:
    if (not isinstance(report, dict) or type(report.get("schema_version")) is not int
            or report["schema_version"] != 1):
        raise ValueError("Unsupported report schema; expected schema_version 1")
    if not isinstance(report.get("tool", {}), dict):
        raise ValueError("Report tool metadata must be an object")
    warnings = report.get("policy_warnings", [])
    if not isinstance(warnings, list) or not all(isinstance(warning, str) for warning in warnings):
        raise ValueError("Report policy_warnings must be a list of strings")
    if "scope" in report:
        scope = report["scope"]
        if (not isinstance(scope, dict) or not {"checks", "deep"} <= set(scope)
                or set(scope) - {"checks", "deep", "parameters"}
                or type(scope["deep"]) is not bool or not isinstance(scope["checks"], list)
                or not all(isinstance(category, str) and category for category in scope["checks"])
                or len(scope["checks"]) != len(set(scope["checks"]))):
            raise ValueError("Report scope requires unique checks and a boolean deep flag")
        if "parameters" in scope:
            if not isinstance(scope["parameters"], dict):
                raise ValueError("Report scope parameters must be an object")
            try:
                json.dumps(scope["parameters"], allow_nan=False)
            except (TypeError, ValueError, RecursionError) as exc:
                raise ValueError("Report scope parameters must contain finite JSON data") from exc
    host = report.get("host")
    if not isinstance(host, dict) or not all(isinstance(host.get(k), str) and host[k]
                                              for k in ("name", "system", "profile")):
        raise ValueError("Report host requires name, system, and profile strings")
    findings = report.get("findings")
    if not isinstance(findings, list):
        raise ValueError("Report findings must be a list")
    ids = set()
    for finding in findings:
        if not isinstance(finding, dict):
            raise ValueError("Invalid finding object")
        fields = ("id", "category", "title", "status", "severity", "evidence", "recommendation")
        if not all(isinstance(finding.get(key), str) for key in fields):
            raise ValueError("Finding requires string id/category/title/status/severity/evidence/recommendation")
        if not finding["id"] or finding["id"] in ids:
            raise ValueError("Finding IDs must be non-empty and unique")
        ids.add(finding["id"])
        if finding["status"] not in STATUSES or finding["severity"] not in SEVERITIES:
            raise ValueError("Unknown finding status or severity")
        if "exception" in finding:
            exception = finding["exception"]
            if (not isinstance(exception, dict)
                    or not isinstance(exception.get("reason"), str)
                    or not isinstance(exception.get("expires"), str)
                    or type(exception.get("active")) is not bool):
                raise ValueError("Invalid finding exception metadata")
    return findings


def _plain(value) -> str:
    """Keep untrusted evidence from emitting terminal escape/control sequences."""
    text = str(value)
    text = re.sub(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)", "", text)
    text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
    return "".join(c for c in text if c in "\n\t" or (ord(c) >= 32 and not 127 <= ord(c) <= 159))


def render_text(report: dict) -> str:
    findings = _findings(report)
    host = report["host"]
    counts = Counter(f["status"] for f in findings)
    tool = report.get("tool", {})
    lines = [f"LinScope {tool.get('version', '')} | Linux security configuration report",
             f"Host: {host['name']} | Profile: {host['profile']} | Generated: {report.get('generated_at', 'unknown')}",
             " | ".join(f"{status}: {counts[status]}" for status in STATUSES), ""]
    for warning in report.get("policy_warnings", []):
        lines.append(f"Policy warning: {warning}")
    if report.get("policy_warnings"):
        lines.append("")
    for finding in findings:
        lines.extend([f"[{finding['status']}] {finding['id']} / {finding['severity'].upper()} — {finding['title']}",
                      f"  Evidence: {finding['evidence']}",
                      f"  Recommendation: {finding['recommendation']}"])
        if "exception" in finding:
            exception = finding["exception"]
            state = "ACTIVE" if exception["active"] else "EXPIRED"
            lines.append(f"  Exception ({state}, expires {exception['expires']}): {exception['reason']}")
        lines.append("")
    lines.append("Results describe collected evidence. UNKNOWN and SKIP do not establish safety.")
    lines.append("Exceptions document accepted risk; they do not change finding status.")
    return _plain("\n".join(lines)) + "\n"


def render_json(report: dict) -> str:
    _findings(report)
    return json.dumps(report, indent=2, ensure_ascii=True, sort_keys=True, allow_nan=False) + "\n"


def render_html(report: dict) -> str:
    findings = _findings(report)
    esc = lambda value: escape(str(value), quote=True)
    host = report["host"]
    counts = Counter(f["status"] for f in findings)
    tiles = "".join(f'<div class="metric {s.lower()}"><strong>{counts[s]}</strong><span>{s}</span></div>'
                    for s in STATUSES)
    cards = []
    warnings_html = ""
    if report.get("policy_warnings"):
        warnings_html = ('<aside class="policy-warnings"><strong>Policy warnings</strong><ul>'
                         + "".join(f"<li>{esc(warning)}</li>" for warning in report["policy_warnings"])
                         + "</ul></aside>")
    for index, finding in enumerate(findings, 1):
        exception_html = ""
        if "exception" in finding:
            exception = finding["exception"]
            state = "Active" if exception["active"] else "Expired"
            exception_html = (f'<aside class="exception"><strong>{state} exception</strong> · expires '
                              f'{esc(exception["expires"])}<p>{esc(exception["reason"])}</p>'
                              '<small>Original status and severity remain unchanged.</small></aside>')
        cards.append(f'''<article id="finding-{index}" class="finding">
<div class="finding-top"><span class="badge {finding['status'].lower()}">{esc(finding['status'])}</span>
<span class="eyebrow">{esc(finding['id'])} · {esc(finding['category'])} · {esc(finding['severity'])}</span></div>
<h2>{esc(finding['title'])}</h2>
<dl><dt>Evidence</dt><dd>{esc(finding['evidence'])}</dd>
<dt>Recommendation</dt><dd>{esc(finding['recommendation'])}</dd></dl>{exception_html}</article>''')
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; base-uri 'none'; form-action 'none'">
<title>LinScope report · {esc(host['name'])}</title>
<style>
:root{{color-scheme:light;--ink:#142536;--muted:#53677a;--line:#dce5ec;--paper:#fff;--wash:#f2f6fa}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--wash);color:var(--ink);font:15px/1.65 system-ui,-apple-system,sans-serif}}
main{{max-width:1120px;margin:auto;padding:48px 28px}}header{{border-bottom:1px solid var(--line);padding-bottom:30px}}
.brand{{font-size:13px;text-transform:uppercase;letter-spacing:.17em;font-weight:750;color:#136b72}}h1{{font-size:42px;line-height:1.15;letter-spacing:-.04em;margin:12px 0}}
.sub{{color:var(--muted);max-width:760px}}.metadata{{display:flex;gap:10px 28px;flex-wrap:wrap;font-size:13px;color:var(--muted)}}
.metrics{{display:grid;grid-template-columns:repeat(6,1fr);gap:12px;margin:28px 0}}.metric{{background:var(--paper);border:1px solid var(--line);border-top:3px solid currentColor;border-radius:10px;padding:16px}}
.metric strong{{display:block;font-size:30px;line-height:1.2}}.metric span{{font-size:11px;letter-spacing:.08em;font-weight:700}}
.pass{{color:#176244}}.warn{{color:#91550b}}.fail{{color:#b22e3b}}.unknown{{color:#6952a0}}.skip{{color:#5b6976}}.info{{color:#1d6394}}
.notice{{border-left:3px solid #136b72;background:#e7f1f2;padding:15px 19px;margin-bottom:28px;color:#264e55}}
.policy-warnings{{border-left:3px solid #a76910;background:#fff5df;padding:15px 19px;margin-bottom:28px;color:#73521a}}.policy-warnings ul{{margin:6px 0 0;padding-left:20px;overflow-wrap:anywhere}}
.finding{{border:1px solid var(--line);background:var(--paper);border-radius:12px;margin:16px 0;padding:24px;break-inside:avoid}}
.finding-top{{display:flex;gap:12px;align-items:center;flex-wrap:wrap}}.badge{{border:1px solid currentColor;border-radius:5px;padding:2px 8px;font-size:11px;font-weight:750;letter-spacing:.05em}}
.eyebrow{{color:var(--muted);font-size:12px;overflow-wrap:anywhere}}h2{{font-size:20px;margin:14px 0 18px;line-height:1.35}}
dl{{margin:0}}dt{{font-size:11px;font-weight:750;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);margin-top:14px}}dd{{margin:5px 0;white-space:pre-wrap;overflow-wrap:anywhere}}
.exception{{background:#fff5df;border:1px solid #e8d8b2;border-radius:6px;margin-top:18px;padding:12px 15px;color:#73521a}}.exception p{{margin:4px 0}}
footer{{margin-top:32px;font-size:12px;color:var(--muted)}}@media(max-width:700px){{main{{padding:26px 16px}}h1{{font-size:32px}}.metrics{{grid-template-columns:repeat(3,1fr)}}.finding{{padding:18px}}}}
@media print{{body{{background:white}}main{{padding:0;max-width:none}}h1{{font-size:30px}}.metric,.finding{{box-shadow:none}}.finding{{border-radius:0}}}}
</style></head><body><main><header><div class="brand">LinScope / Security configuration</div>
<h1>Host security review</h1><p class="sub">Read-only checks, observable evidence, and actionable recommendations.</p>
<div class="metadata"><span><strong>Host</strong> {esc(host['name'])}</span><span><strong>Profile</strong> {esc(host['profile'])}</span>
<span><strong>System</strong> {esc(host['system'])} {esc(host.get('release', ''))}</span>
<span><strong>Generated</strong> {esc(report.get('generated_at', 'unknown'))}</span>
<span><strong>Version</strong> {esc(report.get('tool', {}).get('version', 'unknown'))}</span></div></header>
<section class="metrics" aria-label="Finding summary">{tiles}</section>
<aside class="notice">UNKNOWN means evidence could not be established. SKIP means a check does not apply.
Neither establishes safety. An exception records accepted risk without changing the original result.</aside>
{warnings_html}
<section aria-label="Findings">{''.join(cards) if cards else '<p>No findings were produced for the selected scope.</p>'}</section>
<footer>Generated by LinScope. This report reflects collected configuration evidence and does not certify that a host is free of vulnerabilities.</footer>
</main></body></html>\n'''


def compare_reports(old: dict, new: dict) -> dict:
    """Compare compatible reports; only WARN/FAIL -> PASS is a resolution.

    Missing checks and transitions to UNKNOWN/SKIP are never resolutions. Scope
    changes are rejected instead of manufacturing improvements in the report.
    """
    old_findings, new_findings = _findings(old), _findings(new)
    for key in ("name", "system", "profile"):
        if old["host"][key] != new["host"][key]:
            raise ValueError(f"Cannot compare different host {key} values")
    if old.get("scope") != new.get("scope"):
        raise ValueError("Cannot compare reports with different collection scopes")
    # Reports predating explicit scope still need comparable category selections.
    if "scope" not in old and {f["category"] for f in old_findings} != {f["category"] for f in new_findings}:
        raise ValueError("Cannot compare reports with different category selections")
    before = {f["id"]: f for f in old_findings}
    after = {f["id"]: f for f in new_findings}
    result = {"new": [], "resolved": [], "changed": [], "missing": []}
    for check_id in sorted(after.keys() - before.keys()):
        result["new"].append(deepcopy(after[check_id]))
    for check_id in sorted(before.keys() - after.keys()):
        result["missing"].append(deepcopy(before[check_id]))
    compare_keys = ("title", "status", "severity", "evidence", "recommendation", "exception")
    for check_id in sorted(before.keys() & after.keys()):
        first, second = before[check_id], after[check_id]
        if first["category"] != second["category"]:
            raise ValueError(f"Check ID {check_id} changed categories between reports")
        if not any(first.get(k) != second.get(k) for k in compare_keys):
            continue
        change = {"id": check_id, "before": deepcopy(first), "after": deepcopy(second)}
        if first["status"] in {"WARN", "FAIL"} and second["status"] == "PASS":
            result["resolved"].append(change)
        else:
            result["changed"].append(change)
    result["summary"] = {key: len(value) for key, value in result.items()}
    return result
